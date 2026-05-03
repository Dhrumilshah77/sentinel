"""Vercel entrypoint for the SENTINEL dashboard.

The local demo uses api/server.py, which also starts the streaming anomaly
engine. Vercel only needs the click-driven dashboard endpoints, so this file
keeps the hosted preview lightweight and free-tier friendly.
"""
from __future__ import annotations

import random
from datetime import datetime
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse, JSONResponse

from core.chat import Chat
from core.exposure import ExposureIndex
from core.intel import IntelFusion
from core.live import nvd_recent, scan as live_scan
from core.mission import mission_hotspot, mission_module, mission_summary
from core.monitor import global_monitor, geo_dossier, imagery_analysis, satellite_monitor
from core.sanctions import FUNDING_LINKS, WANTED, SanctionsIndex

ROOT = Path(__file__).resolve().parent
UI = ROOT / "ui"

app = FastAPI(title="SENTINEL Vercel")

INTEL = IntelFusion()
SANCTIONS = SanctionsIndex()
EXPOSURE = ExposureIndex(INTEL.kev.entries)
CHATBOT = Chat()

US_TARGETS = [
    {"name": "Pentagon (DoD HQ)", "lat": 38.871, "lng": -77.056},
    {"name": "NSA Fort Meade", "lat": 39.108, "lng": -76.769},
    {"name": "CIA Langley", "lat": 38.951, "lng": -77.146},
    {"name": "FBI HQ DC", "lat": 38.895, "lng": -77.025},
    {"name": "USCYBERCOM", "lat": 39.108, "lng": -76.769},
    {"name": "INDOPACOM (Honolulu)", "lat": 21.355, "lng": -157.964},
    {"name": "EUCOM (Stuttgart proxy)", "lat": 38.880, "lng": -77.106},
    {"name": "CENTCOM (Tampa)", "lat": 27.844, "lng": -82.519},
    {"name": "Silicon Valley (defense industrial base)", "lat": 37.387, "lng": -122.060},
    {"name": "NYC financial sector", "lat": 40.706, "lng": -74.009},
]


@app.get("/")
async def index():
    return FileResponse(UI / "index.html")


@app.get("/health")
async def health():
    return {
        "ok": True,
        "runtime": "vercel-lightweight",
        "kev": len(INTEL.kev.entries),
        "apt_groups": len(INTEL.mitre.groups),
        "iocs": len(INTEL.ioc.live_iocs),
    }


@app.get("/mission/summary")
async def mission_summary_endpoint():
    return mission_summary(INTEL, SANCTIONS, EXPOSURE)


@app.get("/mission/module/{module_id}")
async def mission_module_endpoint(module_id: str):
    res = mission_module(module_id, INTEL, SANCTIONS, EXPOSURE)
    if not res:
        return JSONResponse({"error": "unknown mission module"}, status_code=404)
    return res


@app.get("/mission/hotspot/{hotspot_id}")
async def mission_hotspot_endpoint(hotspot_id: str):
    res = mission_hotspot(hotspot_id, INTEL, SANCTIONS, EXPOSURE)
    if not res:
        return JSONResponse({"error": "unknown hotspot"}, status_code=404)
    return res


@app.get("/monitor/global")
def monitor_global_endpoint(live: bool = True):
    return global_monitor(INTEL, SANCTIONS, EXPOSURE, include_live=live)


@app.get("/monitor/satellite")
def monitor_satellite_endpoint():
    return satellite_monitor()


@app.get("/monitor/geo")
def monitor_geo_endpoint(lat: float, lng: float):
    return geo_dossier(lat, lng, INTEL, SANCTIONS, EXPOSURE)


@app.get("/monitor/imagery/analyze")
def monitor_imagery_analyze_endpoint(lat: float, lng: float):
    return imagery_analysis(lat, lng, INTEL, SANCTIONS, EXPOSURE)


@app.get("/intel/summary")
async def intel_summary():
    return INTEL.summary()


@app.get("/intel/map")
async def intel_map():
    return {"markers": INTEL.attribution_map()}


@app.get("/intel/group/{gid}")
async def intel_group(gid: str):
    res = INTEL.group(gid)
    if not res:
        return JSONResponse({"error": "not found"}, status_code=404)
    return res


@app.get("/intel/search")
async def intel_search(q: str = ""):
    return INTEL.search(q)


@app.get("/sanctions/summary")
async def sanctions_summary():
    s = SANCTIONS.summary()
    s["wanted"] = WANTED
    s["funding_links"] = FUNDING_LINKS
    return s


@app.get("/sanctions/search")
async def sanctions_search(q: str = ""):
    ql = (q or "").lower()
    return {
        "query": q,
        "ofac": SANCTIONS.search(q, limit=30),
        "wanted": [
            w for w in WANTED
            if ql in (w["name"] + " " + w["country"] + " " + " ".join(w.get("linked_apts", []))).lower()
        ],
    }


@app.get("/exposure")
async def exposure():
    return EXPOSURE.report()


@app.get("/globe/arcs")
async def globe_arcs():
    random.seed(7)
    arcs = []
    markers = INTEL.attribution_map()
    color_for = {
        "China": "#ef4444",
        "Russia": "#ef4444",
        "North Korea": "#ef4444",
        "Iran": "#ef4444",
        "Vietnam": "#f59e0b",
        "Brazil/UK": "#f59e0b",
        "USA/UK": "#5fb4ff",
    }
    for m in markers:
        for g in m["groups"][:6]:
            tgt = random.choice(US_TARGETS)
            arcs.append({
                "from_lat": m["lat"],
                "from_lng": m["lng"],
                "to_lat": tgt["lat"],
                "to_lng": tgt["lng"],
                "country": m["country"],
                "group": g["name"],
                "actor": g.get("actor"),
                "target": tgt["name"],
                "color": color_for.get(m["country"], "#5fb4ff"),
            })
    return {
        "arcs": arcs,
        "origins": [
            {"lat": m["lat"], "lng": m["lng"], "country": m["country"], "groups": len(m["groups"])}
            for m in markers
        ],
        "targets": US_TARGETS,
    }


@app.get("/live/scan")
async def live_scan_endpoint(q: str = ""):
    if not q.strip():
        return {"error": "missing query"}
    res = await live_scan(q.strip())
    if res["kind"] == "cve":
        kev = INTEL.kev.by_cve.get(q.strip().upper())
        if kev:
            res["results"]["cisa_kev"] = kev
    return res


@app.get("/live/cve/recent")
async def live_cve_recent(days: int = 14, limit: int = 30):
    return {"days": days, "items": nvd_recent(days=days, limit=limit)}


@app.post("/chat")
async def chat(payload: dict):
    q = (payload or {}).get("q", "")
    history = (payload or {}).get("history") or []
    text = CHATBOT.reply(history, INTEL, SANCTIONS, EXPOSURE, q)
    return {"answer": text, "query": q}


@app.post("/intel/briefing")
async def intel_briefing(payload: dict | None = None):
    q = (payload or {}).get("q") or ""
    ctx = INTEL.briefing_context(q)
    groups = ctx["hits"].get("groups") or [g for g in INTEL.mitre.groups if g.get("country")][:8]
    kev = ctx["hits"].get("kev") or sorted(
        INTEL.kev.entries, key=lambda v: v.get("date_added") or "", reverse=True
    )[:8]
    ransomware_total = sum(1 for v in INTEL.kev.entries if v.get("ransomware") == "Known")
    threats = "\n".join(
        f"- {g['name']} ({g.get('country') or 'unattributed'}) — "
        f"{g.get('actor') or 'multi-source'} — "
        f"techniques: {len(INTEL.mitre.uses_by_group.get(g['id'], []))} mapped — "
        f"SEVERITY: {'CRITICAL' if g.get('country') in ('Russia', 'China', 'North Korea', 'Iran') else 'HIGH'}"
        for g in groups[:5]
    ) or "- No groups matched query."
    actions = "\n".join(
        f"- Patch {v['cve']} ({v['vendor']} {v['product']}) — due {v.get('due_date', '?')}"
        f" {'· RANSOMWARE-USED' if v.get('ransomware') == 'Known' else ''} — CISA KEV"
        for v in kev[:5]
    ) or "- No CVE matches; query broadened to newest CISA KEV entries."
    bluf = (
        f"Open-source feeds report {len(INTEL.kev.entries)} actively-exploited CVEs, "
        f"{len(groups)} relevant MITRE-tracked APT groups, and {len(INTEL.ioc.live_iocs):,} live malware IOCs. "
        f"Query: {ctx['query']}."
    )
    return {
        "briefing": (
            f"===BLUF===\n{bluf}\n"
            f"===KEY THREATS===\n{threats}\n"
            f"===RECOMMENDED ACTIONS===\n{actions}\n"
            f"===INTEL GAPS===\n"
            f"- Hosted preview uses structured OSINT synthesis only.\n"
            f"- {ransomware_total} of {len(INTEL.kev.entries)} CISA KEV entries are ransomware-linked.\n"
        ),
        "sources": ctx["sources"],
        "query": ctx["query"],
        "context": {
            "groups": [g["name"] for g in groups[:8]],
            "cves": [v["cve"] for v in kev[:8]],
        },
    }


@app.post("/inject/{kind}")
async def inject(kind: str):
    return {
        "injected": 0,
        "kind": kind,
        "source": "vercel-preview",
        "note": "The hosted preview disables local dataset replay. Use the local FastAPI server for live event injection.",
    }


@app.get("/{path:path}")
async def spa_fallback(path: str):
    if "." in path:
        return JSONResponse({"error": "not found"}, status_code=404)
    return FileResponse(UI / "index.html")
