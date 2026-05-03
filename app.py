"""Vercel entrypoint for the SENTINEL dashboard.

The local demo uses api/server.py, which also starts the streaming anomaly
engine. Vercel only needs the click-driven dashboard endpoints, so this file
keeps the hosted preview lightweight and free-tier friendly.
"""
from __future__ import annotations

from html import escape
import random
from datetime import datetime
from pathlib import Path
from typing import Any

from fastapi import FastAPI
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse

from core.chat import Chat
from core.exposure import ExposureIndex
from core.intel import IntelFusion
from core.live import nvd_recent, scan as live_scan
from core.mission import mission_hotspot, mission_module, mission_summary
from core.monitor import _imagery_preview_url, global_monitor, geo_dossier, imagery_analysis, satellite_monitor
from core.page_details import MODULE_SLUGS, PAGE_EXPANSIONS, SATELLITE_TARGETS, SLUG_MODULES
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


def _e(value: Any) -> str:
    return escape(str(value or ""), quote=True)


def _metric_html(metrics: list[dict[str, Any]]) -> str:
    return "".join(
        f"<div class='metric { _e(m.get('tone')) }'><b>{_e(m.get('value'))}</b><span>{_e(m.get('label'))}</span></div>"
        for m in metrics
    )


def _decision_html(decision: dict[str, Any]) -> str:
    comps = decision.get("components") or {}
    bars = "".join(
        f"<div class='barrow'><span>{_e(k).replace('_', ' ')}</span><b>{_e(v)}</b><i><em style='width:{max(0, min(100, int(v or 0)))}%'></em></i></div>"
        for k, v in comps.items()
    )
    evidence = "".join(f"<li>{_e(x)}</li>" for x in decision.get("evidence") or [])
    return f"""
    <section class="decision">
      <div>
        <p class="eyebrow">Decision Score</p>
        <h2>{_e(decision.get('title'))}</h2>
        <p>{_e(decision.get('score_reason'))}</p>
        <ul>{evidence}</ul>
      </div>
      <aside>
        <div class="score">{_e(decision.get('score'))}</div>
        <div class="band">{_e(decision.get('band'))}</div>
        <p><strong>Action:</strong> {_e(decision.get('recommended_action'))}</p>
        <p><strong>Owner:</strong> {_e(decision.get('owner'))} · {_e(decision.get('time_to_action'))}</p>
        {bars}
      </aside>
    </section>
    """


def _cards(items: list[str]) -> str:
    return "".join(f"<div class='chip'>{_e(x)}</div>" for x in items)


def _minute_checks(items: list[dict[str, Any]]) -> str:
    return "".join(
        f"""
        <tr>
          <td><strong>{_e(row.get('check'))}</strong></td>
          <td>{_e(row.get('fields'))}</td>
          <td>{_e(row.get('decision'))}</td>
        </tr>
        """
        for row in items
    )


def _typology_cards(module: dict[str, Any]) -> str:
    typologies = (module.get("deep_dive") or {}).get("typologies") or []
    return "".join(
        f"""
        <article class="typology">
          <div><strong>{_e(t.get('name'))}</strong><span class="risk">{_e(t.get('risk'))}</span></div>
          <p>{_e(t.get('decision'))}</p>
          <div class="signals">{''.join(f"<span>{_e(s)}</span>" for s in (t.get('signals') or []))}</div>
        </article>
        """
        for t in typologies
    )


def _source_rows(module: dict[str, Any]) -> str:
    return "".join(
        f"<tr><td>{_e(s.get('name'))}</td><td>{_e(s.get('agency'))}</td><td>{_e(s.get('domain'))}</td><td>{_e(s.get('access'))}</td></tr>"
        for s in module.get("sources_detail") or []
    )


def _hotspot_cards(module: dict[str, Any]) -> str:
    return "".join(
        f"""
        <a class="hotspot" href="/monitor/imagery/analyze?lat={_e(h.get('lat'))}&lng={_e(h.get('lng'))}">
          <strong>{_e(h.get('name'))}</strong>
          <span>{_e(h.get('severity'))} · {_e(h.get('country'))} · {_e(h.get('kind'))}</span>
          <p>{_e(h.get('why'))}</p>
        </a>
        """
        for h in module.get("hotspots") or []
    )


def _flow_html(module: dict[str, Any]) -> str:
    edges = (module.get("deep_dive") or {}).get("flow_edges") or []
    if not edges:
        return ""
    return "<section><p class='eyebrow'>Money / Signal Flow</p><div class='flow'>" + "".join(
        f"<div><b>{_e(a)}</b><span>to</span><b>{_e(b)}</b><small>{_e(c)}</small></div>"
        for a, b, c in edges
    ) + "</div></section>"


def _detail_rows(module_id: str, module: dict[str, Any]) -> str:
    detail = module.get("detail") or {}
    if module_id == "cyber_defense":
        kev = "".join(
            f"<tr><td>{_e(v.get('cve'))}</td><td>{_e(v.get('vendor'))} {_e(v.get('product'))}</td><td>{_e(v.get('due_date'))}</td><td>{_e(v.get('ransomware'))}</td></tr>"
            for v in (detail.get("recent_kev") or [])[:12]
        )
        iocs = "".join(
            f"<tr><td>{_e(i.get('ioc'))}</td><td>{_e(i.get('type'))}</td><td>{_e(i.get('malware'))}</td><td>{_e(i.get('first_seen'))}</td></tr>"
            for i in (detail.get("iocs") or [])[:12]
        )
        return f"""
        <section><p class="eyebrow">Concrete Cyber Data</p><h2>Recent KEV + IOC Drilldown</h2>
          <div class="split"><table><thead><tr><th>CVE</th><th>Product</th><th>Due</th><th>Ransomware</th></tr></thead><tbody>{kev}</tbody></table>
          <table><thead><tr><th>IOC</th><th>Type</th><th>Malware</th><th>First Seen</th></tr></thead><tbody>{iocs}</tbody></table></div>
        </section>"""
    if module_id in ("aml_finance", "sanctions"):
        countries = "".join(f"<tr><td>{_e(c)}</td><td>{_e(n)}</td></tr>" for c, n in list((detail.get("top_countries") or {}).items())[:15])
        wanted = "".join(
            f"<tr><td>{_e(w.get('name'))}</td><td>{_e(w.get('country'))}</td><td>${int(w.get('bounty_usd') or 0):,}</td><td>{_e(', '.join(w.get('linked_apts') or []))}</td></tr>"
            for w in (detail.get("wanted") or [])[:12]
        )
        return f"""
        <section><p class="eyebrow">Concrete Financial Data</p><h2>Sanctions + Wanted Actor Drilldown</h2>
          <div class="split"><table><thead><tr><th>Country</th><th>OFAC Records</th></tr></thead><tbody>{countries}</tbody></table>
          <table><thead><tr><th>Actor</th><th>Country</th><th>Bounty</th><th>APT Links</th></tr></thead><tbody>{wanted}</tbody></table></div>
        </section>"""
    if module_id == "supply_chain":
        vendors = "".join(
            f"<tr><td>{_e(v.get('vendor'))}</td><td>{_e(v.get('risk'))}</td><td>{_e(v.get('kev_count'))}</td><td>{_e(v.get('ransom_count'))}</td></tr>"
            for v in (detail.get("vendors") or [])[:15]
        )
        return f"<section><p class='eyebrow'>Concrete Vendor Data</p><h2>Defense Vendor Exposure</h2><table><thead><tr><th>Vendor</th><th>Risk</th><th>KEV</th><th>Ransomware</th></tr></thead><tbody>{vendors}</tbody></table></section>"
    return ""


def _satellite_gallery() -> str:
    cards = []
    for t in SATELLITE_TARGETS:
        true_color = _imagery_preview_url(float(t["lat"]), float(t["lng"]))
        thermal = _imagery_preview_url(float(t["lat"]), float(t["lng"]), "VIIRS_SNPP_Thermal_Anomalies_375m_All")
        precip = _imagery_preview_url(float(t["lat"]), float(t["lng"]), "IMERG_Precipitation_Rate")
        cards.append(f"""
        <article class="image-card">
          <img src="{_e(true_color)}" alt="{_e(t['name'])} public satellite preview" loading="lazy">
          <div>
            <h3>{_e(t['name'])}</h3>
            <div class="scoreline"><b>{_e(t['score'])}</b><span>prediction / triage score</span></div>
            <p>{_e(t['prediction'])}</p>
            <p class="links"><a href="{_e(thermal)}" target="_blank">Thermal layer</a><a href="{_e(precip)}" target="_blank">Precipitation layer</a><a href="/monitor/imagery/analyze?lat={_e(t['lat'])}&lng={_e(t['lng'])}" target="_blank">JSON analysis</a></p>
          </div>
        </article>
        """)
    return "<section><p class='eyebrow'>Visible Satellite Imagery + Prediction Cards</p><h2>Public Image Layers with Tracking/Triage Scores</h2><div class='image-grid'>" + "".join(cards) + "</div><p class='caveat'>These are public NASA GIBS imagery previews and OSINT triage scores. They cue human review; they do not claim classified object recognition or prove military activity by themselves.</p></section>"


def _module_page_html(module_id: str) -> str:
    module = mission_module(module_id, INTEL, SANCTIONS, EXPOSURE)
    if not module:
        return ""
    expansion = PAGE_EXPANSIONS[module_id]
    slug = MODULE_SLUGS[module_id]
    nav = "".join(
        f"<a class='{ 'active' if mid == module_id else '' }' href='/{_e(s)}'>{_e(PAGE_EXPANSIONS[mid]['title'].replace(' Page', ''))}</a>"
        for mid, s in MODULE_SLUGS.items()
    )
    fields = "".join(f"<span>{_e(f)}</span>" for f in (module.get("deep_dive") or {}).get("detection_fields") or [])
    rubric = "".join(f"<li>{_e(x)}</li>" for x in expansion.get("score_rubric") or [])
    outputs = "".join(f"<li>{_e(x)}</li>" for x in expansion.get("operator_outputs") or [])
    satellite = _satellite_gallery() if module_id == "satellite_imagery" else ""
    html = f"""<!doctype html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>SENTINEL · {_e(expansion['title'])}</title>
<style>
:root {{ --bg:#05080c; --panel:#0a0f15; --line:#1c2735; --fg:#e6edf3; --muted:#93a4b5; --accent:#5fb4ff; --gold:#d4af37; --crit:#ff5577; --ok:#7aff95; }}
* {{ box-sizing:border-box; }} body {{ margin:0; background:var(--bg); color:var(--fg); font-family:IBM Plex Mono, ui-monospace, SFMono-Regular, Menlo, monospace; }}
a {{ color:inherit; }} header {{ position:sticky; top:0; z-index:5; background:#070b10; border-bottom:1px solid var(--line); padding:14px 18px; display:flex; align-items:center; justify-content:space-between; gap:16px; }}
.brand b {{ color:var(--accent); font-size:22px; letter-spacing:2px; }} .brand span {{ display:block; color:var(--muted); font-size:10px; letter-spacing:2px; margin-top:3px; }}
.nav {{ display:flex; gap:7px; flex-wrap:wrap; justify-content:flex-end; }} .nav a {{ text-decoration:none; border:1px solid var(--line); padding:7px 9px; border-radius:4px; color:var(--muted); font-size:10px; text-transform:uppercase; }}
.nav a.active,.nav a:hover {{ border-color:var(--accent); color:var(--accent); background:#101824; }}
main {{ max-width:1500px; margin:0 auto; padding:22px; }} .hero {{ display:grid; grid-template-columns:1.35fr .65fr; gap:18px; align-items:stretch; border-bottom:1px solid var(--line); padding-bottom:18px; }}
.hero h1 {{ margin:0; color:var(--accent); font-size:38px; line-height:1.05; letter-spacing:0; }} .hero p {{ color:var(--muted); line-height:1.55; }}
.metrics {{ display:grid; grid-template-columns:repeat(4,1fr); gap:1px; background:var(--line); }} .metric {{ background:var(--panel); padding:14px; }} .metric b {{ color:var(--gold); font-size:30px; display:block; }} .metric span {{ color:var(--muted); font-size:11px; text-transform:uppercase; }}
section {{ margin-top:22px; border-top:1px solid var(--line); padding-top:18px; }} .eyebrow {{ color:var(--gold); text-transform:uppercase; letter-spacing:1.5px; font-size:11px; margin:0 0 8px; }} h2 {{ margin:0 0 12px; color:var(--fg); font-size:22px; }}
.decision {{ display:grid; grid-template-columns:1fr 380px; gap:18px; border:1px solid var(--line); background:#070b10; padding:18px; }} .decision ul {{ color:var(--muted); line-height:1.6; }} .decision aside {{ border-left:2px solid var(--accent); padding-left:16px; }}
.score {{ color:var(--crit); font-size:72px; line-height:.9; }} .band {{ color:var(--gold); font-weight:bold; letter-spacing:2px; margin:7px 0 14px; }}
.barrow {{ margin:9px 0; color:var(--muted); font-size:11px; }} .barrow span {{ text-transform:uppercase; }} .barrow b {{ float:right; color:var(--fg); }} .barrow i {{ display:block; height:6px; background:#121a24; border-radius:20px; overflow:hidden; clear:both; margin-top:5px; }} .barrow em {{ display:block; height:100%; background:linear-gradient(90deg,var(--accent),var(--crit)); }}
.chips {{ display:grid; grid-template-columns:repeat(4,1fr); gap:8px; }} .chip {{ border:1px solid var(--line); background:var(--panel); padding:10px; color:var(--muted); }}
table {{ width:100%; border-collapse:collapse; background:var(--panel); }} th,td {{ text-align:left; border:1px solid var(--line); padding:10px; vertical-align:top; }} th {{ color:var(--gold); font-size:11px; text-transform:uppercase; }} td {{ color:#cbd5df; line-height:1.45; }}
.typologies {{ display:grid; grid-template-columns:repeat(3,1fr); gap:10px; }} .typology {{ border:1px solid var(--line); background:var(--panel); padding:12px; min-height:150px; }} .typology div:first-child {{ display:flex; justify-content:space-between; gap:8px; }} .risk {{ color:var(--crit); font-size:11px; }} .typology p {{ color:var(--muted); line-height:1.45; }} .signals span,.fields span {{ display:inline-block; border:1px solid #263344; padding:4px 6px; margin:3px; color:#b8c6d4; font-size:10px; }}
.split {{ display:grid; grid-template-columns:1fr 1fr; gap:12px; }} .flow {{ display:grid; grid-template-columns:repeat(4,1fr); gap:8px; }} .flow div {{ border:1px solid var(--line); background:var(--panel); padding:12px; }} .flow span,.flow small {{ display:block; color:var(--muted); margin:5px 0; }}
.hotspots,.image-grid {{ display:grid; grid-template-columns:repeat(3,1fr); gap:12px; }} .hotspot,.image-card {{ text-decoration:none; border:1px solid var(--line); background:var(--panel); padding:12px; color:var(--fg); }} .hotspot span,.hotspot p {{ color:var(--muted); }} .hotspot:hover {{ border-color:var(--accent); }}
.image-card {{ padding:0; overflow:hidden; }} .image-card img {{ width:100%; aspect-ratio:16/10; object-fit:cover; display:block; background:#020306; }} .image-card div {{ padding:12px; }} .image-card h3 {{ margin:0 0 8px; color:var(--accent); }} .scoreline b {{ color:var(--crit); font-size:34px; }} .scoreline span {{ color:var(--muted); margin-left:8px; text-transform:uppercase; font-size:10px; }} .links a {{ display:inline-block; margin:4px 6px 0 0; color:var(--gold); font-size:11px; }} .caveat {{ color:var(--muted); border:1px dashed #304052; padding:12px; }}
@media(max-width:1000px) {{ .hero,.decision,.split {{ grid-template-columns:1fr; }} .metrics,.chips,.typologies,.hotspots,.image-grid,.flow {{ grid-template-columns:1fr; }} header {{ align-items:flex-start; flex-direction:column; }} }}
</style></head>
<body><header><a class="brand" href="/" style="text-decoration:none"><b>SENTINEL</b><span>MULTI-PAGE COMMAND INTELLIGENCE</span></a><nav class="nav">{nav}</nav></header>
<main>
  <section class="hero">
    <div><p class="eyebrow">/{_e(slug)}</p><h1>{_e(expansion['title'])}</h1><p>{_e(expansion['mission_question'])}</p><p>{_e(module.get('problem'))}</p></div>
    <div class="metrics">{_metric_html(module.get('metrics') or [])}</div>
  </section>
  {_decision_html(module.get('decision') or {})}
  <section><p class="eyebrow">Minute Detail Coverage</p><h2>Sub-Problems This Page Handles</h2><div class="chips">{_cards(expansion.get('subdomains') or [])}</div></section>
  <section><p class="eyebrow">Detection Logic</p><h2>Field-Level Checks and Operational Decisions</h2><table><thead><tr><th>Check</th><th>Fields / Signals</th><th>Decision</th></tr></thead><tbody>{_minute_checks(expansion.get('minute_checks') or [])}</tbody></table></section>
  <section><p class="eyebrow">Scoring</p><h2>Why the Score Moves</h2><div class="split"><div><ul>{rubric}</ul></div><div><h2>Operator Outputs</h2><ul>{outputs}</ul></div></div></section>
  {_detail_rows(module_id, module)}
  {satellite}
  {_flow_html(module)}
  <section><p class="eyebrow">Typology Library</p><h2>Detailed Typologies Rendered on This Page</h2><div class="typologies">{_typology_cards(module)}</div></section>
  <section><p class="eyebrow">Detection Fields</p><h2>Data Model</h2><div class="fields">{fields}</div></section>
  <section><p class="eyebrow">Trusted Sources</p><h2>Public Military-Grade / Government / OSINT Feeds</h2><table><thead><tr><th>Source</th><th>Agency</th><th>Domain</th><th>Access</th></tr></thead><tbody>{_source_rows(module)}</tbody></table></section>
  <section><p class="eyebrow">Geo Drilldowns</p><h2>Map Hotspots for This Page</h2><div class="hotspots">{_hotspot_cards(module) or '<p class="caveat">No dedicated hotspots yet; source and scoring systems still active.</p>'}</div></section>
</main></body></html>"""
    return html


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
    clean = path.strip("/")
    if clean in SLUG_MODULES:
        html = _module_page_html(SLUG_MODULES[clean])
        if html:
            return HTMLResponse(html)
    if clean.startswith("module/"):
        module_id = clean.split("/", 1)[1]
        html = _module_page_html(module_id)
        if html:
            return HTMLResponse(html)
    if "." in path:
        return JSONResponse({"error": "not found"}, status_code=404)
    return FileResponse(UI / "index.html")
