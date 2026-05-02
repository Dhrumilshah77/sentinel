"""FastAPI server. Streams real-data scored events to the dashboard, with
optional injection of labeled malicious flows from NSL-KDD / CTU-13 / ThreatFox.

Run:
    uvicorn api.server:app --reload --port 8000
"""
from __future__ import annotations
import asyncio
import json
import random
from datetime import datetime
from itertools import islice
from pathlib import Path

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, JSONResponse

from core.schema  import Event
from core.scorer  import Scorer
from core.enrich  import Enricher
from core.explain import heuristic, LLMExplainer
from core.intel     import IntelFusion
from core.sanctions import SanctionsIndex, WANTED, FUNDING_LINKS
from core.exposure  import ExposureIndex
from core.live      import scan as live_scan, nvd_recent, classify
from core.chat      import Chat
from core.loaders import (
    load_nsl_kdd, load_ctu13, load_threatfox_recent,
    load_cicids, load_cert,
)

ROOT = Path(__file__).resolve().parent.parent
UI   = ROOT / "ui"

app = FastAPI(title="SENTINEL")

# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------

class Engine:
    def __init__(self) -> None:
        self.scorer    = Scorer(contamination=0.05)
        self.enricher  = Enricher()
        self.llm       = LLMExplainer()
        self.subscribers: set[asyncio.Queue] = set()
        self.queue: asyncio.Queue[Event] = asyncio.Queue(maxsize=8_000)
        self.alerts_seen = 0
        self.events_seen = 0
        self.sources_used: list[str] = []
        self.malicious_pool: list[Event] = []   # real labeled-bad events for inject
        self._fitted = False

    def fit_baseline_real(self) -> int:
        """Bootstrap on REAL NSL-KDD: IForest on benign + supervised XGBoost
        on labeled benign+malicious. Both heads share the unified feature
        space — that's the technical core of the pitch."""
        normal: list[Event] = []
        malicious: list[Event] = []
        for ev in load_nsl_kdd():
            if ev.label is None:
                normal.append(ev)
            else:
                malicious.append(ev)
            if len(normal) >= 30_000 and len(malicious) >= 12_000:
                break
        if not normal:
            raise RuntimeError(
                "No NSL-KDD data found. Run datasets/download.sh first.")
        self.malicious_pool = malicious
        # 1. Unsupervised baseline on benign only
        self.scorer.fit_baseline(normal)
        # 2. Supervised head on labeled mix
        labeled = [(e, 0) for e in normal] + [(e, 1) for e in malicious]
        info = self.scorer.fit_supervised(labeled)
        self._fitted = True
        self.sources_used.append(
            f"NSL-KDD: {len(normal):,} benign + {len(malicious):,} malicious "
            f"(supervised: {info})"
        )
        return len(normal)

    async def score_event(self, ev: Event) -> dict:
        s = self.scorer.score(ev)
        self.enricher.enrich(s)
        s.rationale = heuristic(s, self.enricher)
        self.events_seen += 1
        if s.score >= 0.6:
            self.alerts_seen += 1
        return s.as_dict()

    async def broadcast(self, payload: dict) -> None:
        dead: list[asyncio.Queue] = []
        for q in self.subscribers:
            try:
                q.put_nowait(payload)
            except asyncio.QueueFull:
                dead.append(q)
        for q in dead:
            self.subscribers.discard(q)

ENGINE     = Engine()
INTEL      = IntelFusion()
SANCTIONS  = SanctionsIndex()
EXPOSURE   = ExposureIndex(INTEL.kev.entries)
CHATBOT    = Chat()

# ---------------------------------------------------------------------------
# Background producers — REAL DATA ONLY
# ---------------------------------------------------------------------------

async def _drain_iter(it, eps: float = 25.0) -> None:
    """Push events from an iterator into the queue at ~eps events/sec."""
    delay = 1.0 / max(eps, 0.1)
    for ev in it:
        # Re-stamp to wall-clock so windowed features track demo time, not
        # the dataset's frozen 2017/1999 timestamps.
        ev.ts = datetime.now()
        try:
            ENGINE.queue.put_nowait(ev)
        except asyncio.QueueFull:
            await asyncio.sleep(0.05)
            try: ENGINE.queue.put_nowait(ev)
            except asyncio.QueueFull: pass
        await asyncio.sleep(delay)

async def producer_nslkdd_normal() -> None:
    """Continuous benign traffic from NSL-KDD test set (real connection records)."""
    while True:
        emitted = 0
        for ev in load_nsl_kdd(ROOT / "data" / "datasets" / "nsl_kdd_test.csv"):
            if ev.label is not None: continue   # only normal traffic
            ev.ts = datetime.now()
            try: ENGINE.queue.put_nowait(ev)
            except asyncio.QueueFull: pass
            emitted += 1
            await asyncio.sleep(0.04)            # ~25/s
        if emitted == 0:
            # No NSL-KDD on disk → wait and retry. No synthetic fallback.
            await asyncio.sleep(5)

async def producer_threatfox() -> None:
    """Replay real malware IOCs from ThreatFox as connect events.

    Every event from this stream is something a REAL attacker did within the
    past few days — perfect for showing the engine catching live threats.
    """
    while True:
        any_event = False
        for ev in load_threatfox_recent():
            any_event = True
            ev.ts = datetime.now()
            try: ENGINE.queue.put_nowait(ev)
            except asyncio.QueueFull: pass
            await asyncio.sleep(2.0)            # one every 2s — sparse, attention-grabbing
        if not any_event:
            await asyncio.sleep(30)

async def producer_ctu13() -> None:
    """CTU-13 binetflow. Mix of botnet + benign — both are real."""
    while True:
        any_event = False
        for ev in load_ctu13():
            any_event = True
            ev.ts = datetime.now()
            try: ENGINE.queue.put_nowait(ev)
            except asyncio.QueueFull: pass
            await asyncio.sleep(0.10)           # ~10/s
        if not any_event:
            await asyncio.sleep(15)

async def producer_cert() -> None:
    """Insider activity from CERT (if user has dropped it into data/datasets/cert/)."""
    while True:
        any_event = False
        for ev in load_cert():
            any_event = True
            ev.ts = datetime.now()
            try: ENGINE.queue.put_nowait(ev)
            except asyncio.QueueFull: pass
            await asyncio.sleep(0.20)           # ~5/s
        if not any_event:
            await asyncio.sleep(20)

async def producer_cicids() -> None:
    """CIC-IDS-2017 flow records (if user has dropped them into data/datasets/cicids/)."""
    while True:
        any_event = False
        for ev in load_cicids():
            any_event = True
            ev.ts = datetime.now()
            try: ENGINE.queue.put_nowait(ev)
            except asyncio.QueueFull: pass
            await asyncio.sleep(0.05)
        if not any_event:
            await asyncio.sleep(20)

async def consumer() -> None:
    while True:
        ev = await ENGINE.queue.get()
        scored = await ENGINE.score_event(ev)
        await ENGINE.broadcast({"kind": "scored", "data": scored})

async def stats_pulse() -> None:
    while True:
        await ENGINE.broadcast({
            "kind": "stats",
            "data": {
                "events": ENGINE.events_seen,
                "alerts": ENGINE.alerts_seen,
                "sources": ENGINE.sources_used,
                "ts": datetime.now().isoformat(),
            },
        })
        await asyncio.sleep(1.0)

# ---------------------------------------------------------------------------
# Lifecycle
# ---------------------------------------------------------------------------

@app.on_event("startup")
async def _startup() -> None:
    # The intel-fusion UI is click-driven. The behavioral engine still loads
    # so the /inject and /explain endpoints work in the live-ops sub-tab,
    # but nothing auto-streams — that was the prior UX issue.
    try:
        n = ENGINE.fit_baseline_real()
        print(f"[engine] baseline fit on {n:,} REAL events; pool="
              f"{len(ENGINE.malicious_pool):,}")
    except Exception as e:
        print(f"[engine] baseline fit skipped: {e}")
    print(f"[intel] CISA KEV: {len(INTEL.kev.entries):,} actively-exploited CVEs"
          f" · MITRE: {len(INTEL.mitre.groups)} APT groups"
          f", {len(INTEL.mitre.techniques)} techniques"
          f", {len(INTEL.mitre.malware)} malware"
          f", {len(INTEL.mitre.campaigns)} campaigns"
          f" · ThreatFox: {len(INTEL.ioc.live_iocs):,} live IOCs")
    asyncio.create_task(consumer())   # keep for /inject
    asyncio.create_task(stats_pulse())

# ---------------------------------------------------------------------------
# HTTP
# ---------------------------------------------------------------------------

@app.get("/")
async def index():
    return FileResponse(UI / "index.html")

@app.get("/health")
async def health():
    return {
        "ok": True, "fitted": ENGINE._fitted,
        "events": ENGINE.events_seen, "alerts": ENGINE.alerts_seen,
        "sources": ENGINE.sources_used,
        "malicious_pool": len(ENGINE.malicious_pool),
    }

@app.post("/inject/{kind}")
async def inject(kind: str):
    """Inject a burst of REAL labeled-malicious events from NSL-KDD's attack
    rows. `kind` selects the attack family — these are real attacks, not
    synthesized."""
    families = {
        "scan":     {"ipsweep", "portsweep", "nmap", "satan", "mscan", "saint"},
        "dos":      {"neptune", "smurf", "back", "teardrop", "land", "pod",
                     "apache2", "udpstorm", "processtable", "mailbomb"},
        "r2l":      {"guess_passwd", "ftp_write", "imap", "phf", "multihop",
                     "warezmaster", "warezclient", "spy", "xlock", "xsnoop",
                     "snmpguess", "snmpgetattack", "httptunnel", "sendmail",
                     "named"},
        "u2r":      {"buffer_overflow", "loadmodule", "rootkit", "perl",
                     "sqlattack", "xterm", "ps"},
        "ioc":      None,   # special: pull from ThreatFox live IOCs
        "insider":  None,   # special: pull from CERT if available
    }
    if kind not in families:
        return JSONResponse({"error": f"unknown kind {kind}",
                             "options": list(families)}, status_code=400)

    pulled: list[Event] = []

    if kind == "ioc":
        for ev in load_threatfox_recent():
            pulled.append(ev)
            if len(pulled) >= 30: break
    elif kind == "insider":
        # Use CERT if present, else find file/login events in malicious pool
        for ev in load_cert():
            pulled.append(ev)
            if len(pulled) >= 60: break
    else:
        target_labels = families[kind]
        # Filter the pre-loaded malicious pool by attack family
        candidates = [e for e in ENGINE.malicious_pool
                      if e.label and e.label.lower() in target_labels]
        random.shuffle(candidates)
        pulled = candidates[:60]

    if not pulled:
        return JSONResponse({"error": f"no real events available for '{kind}' "
                                       "— check that the dataset is downloaded"},
                            status_code=404)

    for ev in pulled:
        try:
            ENGINE.queue.put_nowait(ev)
        except asyncio.QueueFull:
            pass
    return {"injected": len(pulled), "kind": kind, "source": "real-labeled-data"}

# ---------------------------------------------------------------------------
# Multi-agency intel fusion endpoints
# ---------------------------------------------------------------------------

@app.get("/intel/summary")
async def intel_summary():
    return INTEL.summary()

@app.get("/intel/map")
async def intel_map():
    return {"markers": INTEL.attribution_map()}

@app.get("/intel/group/{gid}")
async def intel_group(gid: str):
    res = INTEL.group(gid)
    if not res: return JSONResponse({"error": "not found"}, status_code=404)
    return res

@app.get("/intel/search")
async def intel_search(q: str = ""):
    return INTEL.search(q)

# ---------------------------------------------------------------------------
# Sanctions / wanted / funding linkages
# ---------------------------------------------------------------------------

@app.get("/sanctions/summary")
async def sanctions_summary():
    s = SANCTIONS.summary()
    s["wanted"] = WANTED
    s["funding_links"] = FUNDING_LINKS
    return s

@app.get("/sanctions/search")
async def sanctions_search(q: str = ""):
    return {"query": q, "ofac": SANCTIONS.search(q, limit=30),
            "wanted": [w for w in WANTED if (q or "").lower() in
                       (w["name"] + " " + w["country"] + " " +
                        " ".join(w.get("linked_apts", []))).lower()]}

# ---------------------------------------------------------------------------
# Defensive posture — what WE need to harden
# ---------------------------------------------------------------------------

@app.get("/exposure")
async def exposure():
    return EXPOSURE.report()

# ---------------------------------------------------------------------------
# Globe arcs — for the 3D globe attack-flow layer
# ---------------------------------------------------------------------------

# US "blue" target locations (curated DoD/Army-relevant). Real coordinates of
# real US strategic / industrial / agency hubs that show up in adversary
# targeting (per public DoJ indictments + CISA advisories).
US_TARGETS = [
    {"name":"Pentagon (DoD HQ)",        "lat":38.871, "lng":-77.056},
    {"name":"NSA Fort Meade",            "lat":39.108, "lng":-76.769},
    {"name":"CIA Langley",               "lat":38.951, "lng":-77.146},
    {"name":"FBI HQ DC",                 "lat":38.895, "lng":-77.025},
    {"name":"USCYBERCOM",                "lat":39.108, "lng":-76.769},
    {"name":"INDOPACOM (Honolulu)",      "lat":21.355, "lng":-157.964},
    {"name":"EUCOM (Stuttgart proxy)",   "lat":38.880, "lng":-77.106},
    {"name":"CENTCOM (Tampa)",           "lat":27.844, "lng":-82.519},
    {"name":"Silicon Valley (defense industrial base)","lat":37.387, "lng":-122.060},
    {"name":"NYC financial sector",      "lat":40.706, "lng":-74.009},
]

@app.get("/globe/arcs")
async def globe_arcs():
    """Returns arc lines from each attributed APT origin to plausible US
    targets, for the 3D globe attack-flow visualization. Adversaries that
    have multiple groups get more arcs."""
    import random
    random.seed(7)
    arcs = []
    markers = INTEL.attribution_map()
    color_for = {"China":"#ef4444","Russia":"#ef4444","North Korea":"#ef4444",
                 "Iran":"#ef4444","Vietnam":"#f59e0b","Brazil/UK":"#f59e0b",
                 "USA/UK":"#5fb4ff"}
    for m in markers:
        for g in m["groups"][:6]:
            tgt = random.choice(US_TARGETS)
            arcs.append({
                "from_lat": m["lat"], "from_lng": m["lng"],
                "to_lat":   tgt["lat"], "to_lng":  tgt["lng"],
                "country":  m["country"],
                "group":    g["name"],
                "actor":    g.get("actor"),
                "target":   tgt["name"],
                "color":    color_for.get(m["country"], "#5fb4ff"),
            })
    return {
        "arcs":    arcs,
        "origins": [{"lat":m["lat"],"lng":m["lng"],"country":m["country"],
                     "groups":len(m["groups"])} for m in markers],
        "targets": US_TARGETS,
    }

# ---------------------------------------------------------------------------
# Live external scan — real APIs, real-time
# ---------------------------------------------------------------------------

@app.get("/live/scan")
async def live_scan_endpoint(q: str = ""):
    if not q.strip():
        return {"error": "missing query"}
    res = await live_scan(q.strip())
    # Pivot through CISA KEV if a CVE was searched
    if res["kind"] == "cve":
        kev = INTEL.kev.by_cve.get(q.strip().upper())
        if kev:
            res["results"]["cisa_kev"] = kev
    return res

@app.get("/live/cve/recent")
async def live_cve_recent(days: int = 14, limit: int = 30):
    return {"days": days, "items": nvd_recent(days=days, limit=limit)}

@app.get("/live/iocs/refresh")
async def live_iocs_refresh():
    """Force a re-pull of live abuse.ch ThreatFox IOCs (real-time)."""
    import requests
    p = ROOT / "data" / "feeds" / "threatfox.json"
    try:
        r = requests.get("https://threatfox.abuse.ch/export/json/recent/",
                         headers={"User-Agent":"sentinel/1.0"}, timeout=20)
        r.raise_for_status()
        p.write_bytes(r.content)
        # Reload IOC index in-place
        from core.intel import IocIndex
        INTEL.ioc = IocIndex()
        return {"refreshed": True, "live_iocs": len(INTEL.ioc.live_iocs),
                "fetched_at": datetime.utcnow().isoformat() + "Z"}
    except Exception as e:
        return {"refreshed": False, "error": str(e)}

# ---------------------------------------------------------------------------
# Chatbot
# ---------------------------------------------------------------------------

@app.post("/chat")
async def chat(payload: dict):
    q = (payload or {}).get("q", "")
    history = (payload or {}).get("history") or []
    text = CHATBOT.reply(history, INTEL, SANCTIONS, EXPOSURE, q)
    return {"answer": text, "query": q}

@app.post("/intel/briefing")
async def intel_briefing(payload: dict | None = None):
    """LLM-synthesized intel briefing across all agency feeds."""
    q = (payload or {}).get("q") or ""
    ctx = INTEL.briefing_context(q)

    # Build a compact prompt — only what the LLM truly needs.
    groups_block = "\n".join(
        f"- {g['name']} ({g.get('country') or 'unattributed'}; "
        f"{g.get('actor') or '—'})"
        for g in (ctx["hits"].get("groups") or [])[:8]
    ) or "- none matched"
    kev_block = "\n".join(
        f"- {v['cve']}: {v['vendor']} {v['product']} — {v['name']}"
        f" {'[RANSOMWARE]' if v.get('ransomware')=='Known' else ''}"
        for v in (ctx["hits"].get("kev") or [])[:8]
    ) or "- none matched"
    iocs_block = "\n".join(
        f"- {i['type']} {i['ioc']} (malware: {i.get('malware')})"
        for i in (ctx["hits"].get("iocs") or [])[:6]
    ) or "- none"
    src_block = "\n".join(f"- {s}" for s in ctx["sources"])

    prompt = (
        "You are a US Army intelligence analyst writing an UNCLASSIFIED//FOUO "
        "Cyber Threat Briefing for a battalion commander. The briefing must be "
        "concise, action-focused, and cite agency sources.\n\n"
        f"COMMANDER QUERY: {ctx['query']}\n\n"
        f"OPEN-SOURCE FEEDS INGESTED:\n{src_block}\n\n"
        f"RELEVANT APT/THREAT ACTORS (MITRE ATT&CK):\n{groups_block}\n\n"
        f"ACTIVELY EXPLOITED VULNERABILITIES (CISA KEV):\n{kev_block}\n\n"
        f"LIVE MALWARE IOCS (abuse.ch ThreatFox, last 7 days):\n{iocs_block}\n\n"
        "Output the briefing in this exact format:\n"
        "===BLUF===\n"
        "<2 sentences. Bottom-line up front: who, what, mission impact.>\n"
        "===KEY THREATS===\n"
        "<3-5 bullets. Each: ACTOR — TECHNIQUE — TARGET — SEVERITY (LOW/MED/HIGH/CRITICAL).>\n"
        "===RECOMMENDED ACTIONS===\n"
        "<3-5 imperative bullets. Patch X, block Y, query Z. Each cites the agency.>\n"
        "===INTEL GAPS===\n"
        "<1-2 bullets on what we DON'T know yet.>\n"
    )

    llm = ENGINE.llm
    if not llm.client:
        # Even without an LLM key, build a useful briefing from the structured
        # sources so the demo isn't blank. Pull the freshest CISA KEV + most
        # relevant attributed APT groups when the query didn't match anything.
        groups = ctx["hits"].get("groups") or [g for g in INTEL.mitre.groups if g.get("country")][:8]
        kev = ctx["hits"].get("kev") or sorted(
            INTEL.kev.entries, key=lambda v: v.get("date_added") or "", reverse=True
        )[:8]
        ransomware_total = sum(1 for v in INTEL.kev.entries if v.get("ransomware") == "Known")
        bluf = (f"Open-source feeds report {len(INTEL.kev.entries)} actively-exploited "
                f"CVEs (CISA KEV, {INTEL.kev.released[:10]}), with {len(groups)} relevant "
                f"APT groups under MITRE ATT&CK tracking and "
                f"{len(INTEL.ioc.live_iocs):,} live malware IOCs from abuse.ch. "
                f"Query: {ctx['query']}.")
        threats = "\n".join(
            f"- {g['name']} ({g.get('country') or 'unattributed'}) — "
            f"{g.get('actor') or 'multi-source'} — "
            f"techniques: {len(INTEL.mitre.uses_by_group.get(g['id'], []))} mapped — "
            f"SEVERITY: {'CRITICAL' if g.get('country') in ('Russia','China','North Korea','Iran') else 'HIGH'}"
            for g in groups[:5]
        ) or "- (no groups matched query)"
        actions = "\n".join(
            f"- Patch {v['cve']} ({v['vendor']} {v['product']}) — due {v.get('due_date','?')}"
            f" {'· RANSOMWARE-USED' if v.get('ransomware')=='Known' else ''} — CISA KEV"
            for v in kev[:5]
        ) or "- No CVE matches; query broadened to top 5 newest CISA KEV entries."
        gaps = (
            f"- AI synthesis offline (set ANTHROPIC_API_KEY in .env). Direct-match enrichment only.\n"
            f"- {ransomware_total} of {len(INTEL.kev.entries)} CISA KEV entries are ransomware-linked."
        )
        return {
            "briefing": (
                f"===BLUF===\n{bluf}\n"
                f"===KEY THREATS===\n{threats}\n"
                f"===RECOMMENDED ACTIONS===\n{actions}\n"
                f"===INTEL GAPS===\n{gaps}\n"
            ),
            "sources": ctx["sources"],
            "query": ctx["query"],
            "context": {
                "groups": [g["name"] for g in groups[:8]],
                "cves":   [v["cve"]  for v in kev[:8]],
            },
        }
    try:
        msg = llm.client.messages.create(
            model="claude-haiku-4-5-20251001",
            max_tokens=900,
            messages=[{"role": "user", "content": prompt}],
        )
        text = "".join(b.text for b in msg.content if hasattr(b, "text")).strip()
    except Exception as e:
        text = f"(LLM error: {e})"
    return {
        "briefing": text,
        "sources": ctx["sources"],
        "query": ctx["query"],
        "context": {
            "groups": [g["name"] for g in (ctx["hits"].get("groups") or [])[:8]],
            "cves":   [v["cve"]  for v in (ctx["hits"].get("kev")    or [])[:8]],
        },
    }

@app.post("/explain")
async def explain_with_llm(payload: dict):
    from core.schema import Score
    ev_dict = payload.get("event", {})
    ev_dict["ts"] = datetime.fromisoformat(ev_dict["ts"])
    ev = Event(**{k: v for k, v in ev_dict.items() if k in Event.__dataclass_fields__})
    s = Score(
        event=ev,
        score=payload.get("score", 0),
        baseline_z=payload.get("baseline_z", 0),
        isolation_score=payload.get("isolation_score", 0),
        top_features=[tuple(t) for t in payload.get("top_features", [])],
        techniques=payload.get("techniques", []),
        iocs_hit=payload.get("iocs_hit", []),
    )
    text = ENGINE.llm.explain(s, ENGINE.enricher) or "(LLM disabled — set ANTHROPIC_API_KEY)"
    return {"rationale": text}

# ---------------------------------------------------------------------------
# WebSocket
# ---------------------------------------------------------------------------

@app.websocket("/ws")
async def ws(ws: WebSocket):
    await ws.accept()
    q: asyncio.Queue = asyncio.Queue(maxsize=4_000)
    ENGINE.subscribers.add(q)
    try:
        while True:
            payload = await q.get()
            await ws.send_text(json.dumps(payload, default=str))
    except WebSocketDisconnect:
        pass
    finally:
        ENGINE.subscribers.discard(q)
