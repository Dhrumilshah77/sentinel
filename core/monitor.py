"""WorldMonitor-style global situational awareness for SENTINEL.

The point is a fast first screen: live public signals, top metrics, map
hotspots, and drilldowns without dragging in an entire second codebase.
"""
from __future__ import annotations

import json
import math
from datetime import datetime
from typing import Any

import requests

UA = {"User-Agent": "sentinel-natsec-monitor/1.0"}
T = 7

SATELLITE_LAYERS: list[dict[str, Any]] = [
    {
        "id": "viirs_true_color",
        "name": "VIIRS SNPP True Color",
        "provider": "NASA GIBS",
        "cadence": "Daily",
        "use": "Rapid visual context for smoke, dust, weather, and terrain.",
        "url": "https://gibs.earthdata.nasa.gov/wmts/epsg3857/best/wmts.cgi",
        "layer": "VIIRS_SNPP_CorrectedReflectance_TrueColor",
    },
    {
        "id": "modis_thermal",
        "name": "MODIS Thermal Anomalies",
        "provider": "NASA FIRMS/GIBS",
        "cadence": "Near real-time",
        "use": "Wildfire and heat-source detection for infrastructure risk.",
        "url": "https://gibs.earthdata.nasa.gov/wmts/epsg3857/best/wmts.cgi",
        "layer": "MODIS_Terra_Thermal_Anomalies_All",
    },
    {
        "id": "landsatlook",
        "name": "LandsatLook Imagery",
        "provider": "USGS",
        "cadence": "Scene-based",
        "use": "High-resolution open imagery for before/after assessment.",
        "url": "https://landsatlook.usgs.gov/",
        "layer": "Landsat Collection 2",
    },
    {
        "id": "sentinel_browser",
        "name": "Sentinel-2 Optical",
        "provider": "Copernicus Browser",
        "cadence": "5-day revisit",
        "use": "Open optical imagery for ports, airfields, flooding, and burn scars.",
        "url": "https://browser.dataspace.copernicus.eu/",
        "layer": "Sentinel-2 L2A",
    },
]

STRATEGIC_HOTSPOTS: list[dict[str, Any]] = [
    {"id": "taiwan-strait", "name": "Taiwan Strait", "lat": 24.0, "lng": 121.0, "kind": "conflict", "severity": "HIGH", "module": "geo_conflict", "why": "Military, cyber, shipping, and semiconductor supply-chain convergence."},
    {"id": "south-china-sea", "name": "South China Sea", "lat": 12.5, "lng": 114.0, "kind": "maritime", "severity": "HIGH", "module": "aviation_maritime", "why": "Disputed maritime region with trade, naval, and ISR relevance."},
    {"id": "red-sea", "name": "Red Sea / Bab el-Mandeb", "lat": 12.6, "lng": 43.3, "kind": "maritime", "severity": "CRITICAL", "module": "aviation_maritime", "why": "Strategic shipping disruption and regional escalation pressure."},
    {"id": "black-sea", "name": "Black Sea", "lat": 44.0, "lng": 34.0, "kind": "conflict", "severity": "CRITICAL", "module": "geo_conflict", "why": "Kinetic conflict, port disruption, cyber operations, and GPS interference."},
    {"id": "hormuz-monitor", "name": "Strait of Hormuz", "lat": 26.56, "lng": 56.25, "kind": "energy", "severity": "CRITICAL", "module": "geo_conflict", "why": "Energy chokepoint and escalation-sensitive maritime corridor."},
    {"id": "suez-monitor", "name": "Suez Canal", "lat": 30.04, "lng": 32.55, "kind": "supply", "severity": "HIGH", "module": "supply_chain", "why": "Global trade chokepoint with fast supply-chain cascade potential."},
    {"id": "malacca-monitor", "name": "Strait of Malacca", "lat": 1.35, "lng": 103.82, "kind": "supply", "severity": "HIGH", "module": "supply_chain", "why": "Indo-Pacific logistics and energy shipping dependency."},
    {"id": "ukraine-monitor", "name": "Ukraine Theater", "lat": 50.45, "lng": 30.52, "kind": "conflict", "severity": "CRITICAL", "module": "geo_conflict", "why": "Cyber, sanctions, disaster, infrastructure, and military signals converge."},
]

MISSION_ASSETS: list[dict[str, Any]] = [
    {"id": "pentagon", "name": "Pentagon / DoD HQ", "lat": 38.871, "lng": -77.056, "type": "Command", "criticality": 98},
    {"id": "fort-meade", "name": "NSA / USCYBERCOM", "lat": 39.108, "lng": -76.769, "type": "Cyber Command", "criticality": 99},
    {"id": "langley", "name": "CIA Langley", "lat": 38.951, "lng": -77.146, "type": "Intelligence", "criticality": 94},
    {"id": "indopacom", "name": "INDOPACOM / Honolulu", "lat": 21.355, "lng": -157.964, "type": "Combatant Command", "criticality": 92},
    {"id": "centcom", "name": "CENTCOM / Tampa", "lat": 27.844, "lng": -82.519, "type": "Combatant Command", "criticality": 90},
    {"id": "nyc-finance", "name": "NYC Financial Sector", "lat": 40.706, "lng": -74.009, "type": "Financial Infrastructure", "criticality": 86},
    {"id": "silicon-valley", "name": "Defense AI / Cloud Supply Base", "lat": 37.387, "lng": -122.060, "type": "Defense Industrial Base", "criticality": 88},
]


def _get_json(url: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
    try:
        r = requests.get(url, headers=UA, params=params, timeout=T)
        if not r.ok:
            return {"_status": r.status_code, "_url": r.url}
        return r.json()
    except Exception as e:
        return {"_error": str(e)[:180], "_url": url}


def _point_from_geo(geo: dict[str, Any] | None) -> tuple[float | None, float | None]:
    if not geo:
        return None, None
    coords = geo.get("coordinates")
    typ = geo.get("type")
    if not coords:
        return None, None
    if typ == "Point" and len(coords) >= 2:
        return float(coords[1]), float(coords[0])
    if typ in ("Polygon", "MultiPolygon"):
        try:
            ring = coords[0][0] if typ == "MultiPolygon" else coords[0]
            lng = sum(p[0] for p in ring) / max(len(ring), 1)
            lat = sum(p[1] for p in ring) / max(len(ring), 1)
            return float(lat), float(lng)
        except Exception:
            return None, None
    return None, None


def live_public_signals() -> dict[str, Any]:
    """Fetch no-auth public feeds. Each failure is isolated so the dashboard
    still works during venue Wi-Fi weirdness."""
    eonet = _get_json("https://eonet.gsfc.nasa.gov/api/v3/events", {"status": "open", "days": 30, "limit": 30})
    quakes = _get_json("https://earthquake.usgs.gov/earthquakes/feed/v1.0/summary/4.5_day.geojson")
    noaa = _get_json("https://api.weather.gov/alerts/active", {"status": "actual", "message_type": "alert"})
    opensky = _get_json(
        "https://opensky-network.org/api/states/all",
        {"lamin": 24.0, "lomin": -125.0, "lamax": 50.0, "lomax": -66.0},
    )

    disaster_events: list[dict[str, Any]] = []
    for ev in (eonet.get("events") or [])[:20]:
        geo = (ev.get("geometry") or [{}])[-1]
        lat, lng = _point_from_geo(geo)
        disaster_events.append({
            "id": ev.get("id"),
            "name": ev.get("title"),
            "kind": (ev.get("categories") or [{}])[0].get("title", "EONET"),
            "source": "NASA EONET",
            "lat": lat,
            "lng": lng,
            "severity": "HIGH" if (ev.get("categories") or [{}])[0].get("title") in ("Wildfires", "Severe Storms") else "MEDIUM",
            "time": geo.get("date"),
        })

    quake_events: list[dict[str, Any]] = []
    for f in (quakes.get("features") or [])[:20]:
        props = f.get("properties") or {}
        coords = ((f.get("geometry") or {}).get("coordinates") or [None, None])
        quake_events.append({
            "id": f.get("id"),
            "name": props.get("title"),
            "kind": "Earthquake",
            "source": "USGS",
            "lat": coords[1],
            "lng": coords[0],
            "severity": "HIGH" if (props.get("mag") or 0) >= 6 else "MEDIUM",
            "magnitude": props.get("mag"),
            "time": props.get("time"),
        })

    weather_alerts: list[dict[str, Any]] = []
    for f in (noaa.get("features") or [])[:20]:
        props = f.get("properties") or {}
        lat, lng = _point_from_geo(f.get("geometry"))
        weather_alerts.append({
            "id": props.get("id"),
            "name": props.get("headline") or props.get("event"),
            "kind": props.get("event") or "Weather Alert",
            "source": "NOAA/NWS",
            "lat": lat,
            "lng": lng,
            "severity": props.get("severity") or "Unknown",
            "area": props.get("areaDesc"),
            "time": props.get("sent"),
        })

    aircraft = []
    for row in (opensky.get("states") or [])[:80]:
        if len(row) < 8:
            continue
        aircraft.append({
            "icao24": row[0],
            "callsign": (row[1] or "").strip(),
            "origin_country": row[2],
            "lng": row[5],
            "lat": row[6],
            "altitude_m": row[7],
            "velocity_mps": row[9] if len(row) > 9 else None,
        })

    all_events = [e for e in disaster_events + quake_events + weather_alerts if e.get("lat") is not None and e.get("lng") is not None]
    return {
        "signals": {
            "nasa_eonet": {"count": len(disaster_events), "items": disaster_events, "status": _status(eonet)},
            "usgs_earthquakes": {"count": len(quake_events), "items": quake_events, "status": _status(quakes)},
            "noaa_alerts": {"count": len(weather_alerts), "items": weather_alerts, "status": _status(noaa)},
            "opensky_aircraft": {"count": len(aircraft), "items": aircraft[:30], "status": _status(opensky)},
        },
        "map_events": all_events[:45],
        "fetched_at": datetime.utcnow().isoformat() + "Z",
    }


def _status(payload: dict[str, Any]) -> str:
    if "_error" in payload:
        return "error"
    if "_status" in payload:
        return f"http_{payload['_status']}"
    return "ok"


def _score_band(score: int) -> str:
    if score >= 90:
        return "ACT NOW"
    if score >= 75:
        return "PRIORITIZE"
    if score >= 55:
        return "WATCH"
    return "MONITOR"


def _distance_km(a_lat: float, a_lng: float, b_lat: float, b_lng: float) -> float:
    r = 6371.0
    p1, p2 = math.radians(a_lat), math.radians(b_lat)
    dp = math.radians(b_lat - a_lat)
    dl = math.radians(b_lng - a_lng)
    x = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return 2 * r * math.atan2(math.sqrt(x), math.sqrt(1 - x))


def _decision(
    title: str,
    score: int,
    confidence: int,
    impact: int,
    urgency: int,
    actionability: int,
    action: str,
    owner: str,
    evidence: list[str],
    sources: list[str],
    time_to_action: str,
    lat: float | None = None,
    lng: float | None = None,
    domain: str = "global",
) -> dict[str, Any]:
    return {
        "title": title,
        "score": max(0, min(100, int(score))),
        "band": _score_band(score),
        "confidence": confidence,
        "components": {
            "mission_impact": impact,
            "urgency": urgency,
            "actionability": actionability,
        },
        "recommended_action": action,
        "owner": owner,
        "time_to_action": time_to_action,
        "evidence": evidence,
        "sources": sources,
        "domain": domain,
        "lat": lat,
        "lng": lng,
    }


def decision_products(intel: Any, sanctions: Any, exposure: Any, live: dict[str, Any]) -> list[dict[str, Any]]:
    intel_summary = intel.summary()
    exp = exposure.report()
    sanc = sanctions.summary()
    top_vendor = (exp.get("vendors") or [{}])[0]
    live_events = live.get("map_events") or []
    severe_geo = next((e for e in live_events if e.get("severity") in ("HIGH", "Extreme", "Severe")), None)
    decisions = [
        _decision(
            title=f"Patch {top_vendor.get('vendor', 'top exposed vendor')} before next mission window",
            score=min(99, 72 + int(top_vendor.get("ransom_count") or 0) // 2),
            confidence=93,
            impact=96,
            urgency=90,
            actionability=92,
            action="Generate patch/change ticket for the top 5 CISA KEV items, then verify exposed management interfaces are not internet reachable.",
            owner="G-6 / Cyber Protection Team",
            evidence=[
                f"{top_vendor.get('kev_count', 0)} actively exploited CVEs on {top_vendor.get('vendor', 'vendor')}",
                f"{top_vendor.get('ransom_count', 0)} ransomware-used CVEs",
                f"{intel_summary['kev_count']} total CISA KEV records loaded",
            ],
            sources=["CISA KEV", "NIST NVD", "DoD vendor stack model"],
            time_to_action="0-24h",
            lat=39.108,
            lng=-76.769,
            domain="cyber_defense",
        ),
        _decision(
            title="Prioritize DPRK crypto-theft and sanctions watch",
            score=91,
            confidence=88,
            impact=90,
            urgency=84,
            actionability=86,
            action="Search OFAC aliases and wanted actors for Lazarus/BlueNoroff, then flag related wallet/domain/IOC pivots for finance-sector partners.",
            owner="J2 / Financial Intelligence Cell",
            evidence=[
                f"{sanc['ofac_total']:,} OFAC entities indexed",
                f"${sanc['wanted_bounty_usd'] // 1_000_000}M in public cyber bounties represented",
                "DPRK funding links are curated from public Treasury/FBI/DoJ attribution",
            ],
            sources=["US Treasury OFAC", "FBI Cyber Most Wanted", "State Dept RFJ", "DoJ"],
            time_to_action="0-48h",
            lat=39.0392,
            lng=125.7625,
            domain="aml_finance",
        ),
        _decision(
            title="Watch Black Sea / Ukraine convergence for cyber spillover",
            score=96,
            confidence=82,
            impact=94,
            urgency=88,
            actionability=78,
            action="Increase monitoring of logistics, satellite comms, ports, and regional supplier dependencies; generate regional BLUF before commander update.",
            owner="J2 / J6 Fusion",
            evidence=[
                "Critical conflict hotspot",
                "Known Russian APT attribution in MITRE ATT&CK",
                "Sanctions, cyber, GPS, and infrastructure signals converge",
            ],
            sources=["MITRE ATT&CK", "OFAC SDN", "NASA/USGS/NOAA overlays"],
            time_to_action="Today",
            lat=50.45,
            lng=30.52,
            domain="geo_conflict",
        ),
        _decision(
            title="Protect Suez / Red Sea logistics assumptions",
            score=94,
            confidence=79,
            impact=92,
            urgency=87,
            actionability=80,
            action="Open Air/Sea page, review chokepoints, and prepare alternate routing impact note for supply-chain and sustainment leads.",
            owner="G-4 / Sustainment",
            evidence=[
                "Critical maritime chokepoint",
                "Global supply route dependency",
                "Cross-stream risk: regional conflict, shipping, energy, cyber",
            ],
            sources=["Strategic hotspot model", "OpenSky", "GDACS/GDELT-ready feed plan"],
            time_to_action="24-72h",
            lat=12.6,
            lng=43.3,
            domain="aviation_maritime",
        ),
    ]
    if severe_geo:
        decisions.append(_decision(
            title=f"Imagery tasking cue: {severe_geo.get('name')}",
            score=84 if severe_geo.get("severity") == "HIGH" else 70,
            confidence=76,
            impact=78,
            urgency=82,
            actionability=74,
            action="Open Satellite page, compare NASA event geometry with GIBS/Landsat/Copernicus imagery, and check nearby mission assets or logistics routes.",
            owner="Geospatial / Common Operating Picture",
            evidence=[
                f"{severe_geo.get('source')} live event",
                f"Category: {severe_geo.get('kind')}",
                f"Coordinates: {severe_geo.get('lat')}, {severe_geo.get('lng')}",
            ],
            sources=[severe_geo.get("source", "Public geospatial feed"), "NASA GIBS", "USGS LandsatLook"],
            time_to_action="Today",
            lat=severe_geo.get("lat"),
            lng=severe_geo.get("lng"),
            domain="satellite_imagery",
        ))
    return sorted(decisions, key=lambda d: -d["score"])


def global_monitor(intel: Any, sanctions: Any, exposure: Any, include_live: bool = True) -> dict[str, Any]:
    intel_summary = intel.summary()
    sanction_summary = sanctions.summary()
    exposure_report = exposure.report()
    live = live_public_signals() if include_live else {"signals": {}, "map_events": [], "fetched_at": None}

    metrics = [
        {"label": "Active Cyber CVEs", "value": intel_summary["kev_count"], "tone": "crit", "source": "CISA KEV"},
        {"label": "Live Malware IOCs", "value": intel_summary["live_iocs"], "tone": "bad", "source": "abuse.ch"},
        {"label": "Sanctioned Entities", "value": sanction_summary["ofac_total"], "tone": "gold", "source": "OFAC SDN"},
        {"label": "Exposed Vendors", "value": exposure_report["totals"]["vendors_with_active_exploits"], "tone": "warn", "source": "CISA KEV x DoD stack"},
        {"label": "Open Disaster Signals", "value": live["signals"].get("nasa_eonet", {}).get("count", "live"), "tone": "ok", "source": "NASA EONET"},
        {"label": "USGS M4.5+ Quakes", "value": live["signals"].get("usgs_earthquakes", {}).get("count", "live"), "tone": "warn", "source": "USGS"},
        {"label": "US Weather Alerts", "value": live["signals"].get("noaa_alerts", {}).get("count", "live"), "tone": "ok", "source": "NOAA"},
        {"label": "Air Tracks", "value": live["signals"].get("opensky_aircraft", {}).get("count", "live"), "tone": "ok", "source": "OpenSky"},
    ]

    convergence = []
    for h in STRATEGIC_HOTSPOTS:
        score = {"CRITICAL": 92, "HIGH": 78, "MEDIUM": 55}.get(h["severity"], 40)
        if h["kind"] in ("conflict", "maritime", "energy"):
            score += 4
        convergence.append({**h, "score": min(score, 99)})

    return {
        "title": "Global Situation Monitor",
        "subtitle": "WorldMonitor-inspired, stripped down for military digital defense.",
        "metrics": metrics,
        "decision_deck": decision_products(intel, sanctions, exposure, live),
        "koala_metrics": [
            {"label": "Layer Model", "value": 8, "tone": "ok", "source": "Koala-inspired map layers"},
            {"label": "Signal Categories", "value": 12, "tone": "gold", "source": "Cyber + AML + geospatial + infrastructure"},
            {"label": "Risk Hotspots", "value": len(STRATEGIC_HOTSPOTS), "tone": "warn", "source": "Cross-stream convergence"},
            {"label": "Country Risk Index", "value": len(intel_summary["apt_by_country"]), "tone": "bad", "source": "MITRE attribution + OFAC"},
            {"label": "Trusted Source Families", "value": 9, "tone": "ok", "source": "Military-grade public datasets"},
            {"label": "Source Health", "value": "LIVE", "tone": "ok", "source": "No-auth public APIs + cached feeds"},
        ],
        "convergence": sorted(convergence, key=lambda x: -x["score"]),
        "live": live,
        "satellite_layers": SATELLITE_LAYERS,
        "cyber": {
            "recent_kev": intel_summary["kev_recent"],
            "ioc_sample": intel_summary["ioc_sample"],
            "apt_by_country": intel_summary["apt_by_country"],
        },
        "aml": {
            "top_sanctioned_countries": sanction_summary["top_countries"],
            "wanted_bounty_usd": sanction_summary["wanted_bounty_usd"],
        },
        "exposure": exposure_report["vendors"][:8],
        "updated_at": datetime.utcnow().isoformat() + "Z",
    }


def satellite_monitor() -> dict[str, Any]:
    live = live_public_signals()
    imagery_events = [
        e for e in live["map_events"]
        if e.get("source") in ("NASA EONET", "USGS", "NOAA/NWS")
    ][:30]
    return {
        "label": "Satellite & Imagery",
        "problem": "Use public orbital and geospatial feeds for disaster, infrastructure, airfield, port, and route awareness.",
        "metrics": [
            {"label": "Imagery Layers", "value": len(SATELLITE_LAYERS), "tone": "ok"},
            {"label": "NASA Events", "value": live["signals"].get("nasa_eonet", {}).get("count", 0), "tone": "warn"},
            {"label": "USGS Quakes", "value": live["signals"].get("usgs_earthquakes", {}).get("count", 0), "tone": "warn"},
            {"label": "NOAA Alerts", "value": live["signals"].get("noaa_alerts", {}).get("count", 0), "tone": "ok"},
        ],
        "sources_detail": [
            {"name": "NASA EONET", "agency": "NASA", "domain": "Open earth observation events", "access": "No-auth API"},
            {"name": "NASA GIBS", "agency": "NASA", "domain": "Global imagery tile services", "access": "Public WMTS"},
            {"name": "USGS Earthquake Hazards", "agency": "USGS", "domain": "Seismic GeoJSON", "access": "No-auth API"},
            {"name": "LandsatLook", "agency": "USGS", "domain": "Open satellite imagery", "access": "Public viewer"},
            {"name": "Copernicus Browser", "agency": "EU Copernicus", "domain": "Sentinel imagery", "access": "Public viewer"},
            {"name": "NOAA/NWS Alerts", "agency": "NOAA", "domain": "Weather warning polygons", "access": "No-auth API"},
        ],
        "actions": [
            "Open NASA/USGS event geometry on the globe.",
            "Use imagery layer cards for before/after visual assessment.",
            "Correlate disasters with ports, bases, vendors, and communications risk.",
            "Treat imagery as context; commanders still approve operational action.",
        ],
        "layers": SATELLITE_LAYERS,
        "events": imagery_events,
        "imagery_decisions": [
            _decision(
                title=f"Review imagery for {e.get('name')}",
                score=82 if e.get("severity") == "HIGH" else 64,
                confidence=74,
                impact=76,
                urgency=80 if e.get("severity") == "HIGH" else 58,
                actionability=78,
                action="Open NASA GIBS or LandsatLook and compare event geometry with nearby infrastructure, routes, ports, or command assets.",
                owner="Geospatial / Mission Planning",
                evidence=[
                    f"{e.get('source')} event",
                    f"{e.get('kind')} at {e.get('lat')}, {e.get('lng')}",
                    f"Event time: {e.get('time')}",
                ],
                sources=[e.get("source", "Public feed"), "NASA GIBS", "USGS LandsatLook"],
                time_to_action="Today",
                lat=e.get("lat"),
                lng=e.get("lng"),
                domain="satellite_imagery",
            )
            for e in imagery_events[:6]
        ],
        "updated_at": datetime.utcnow().isoformat() + "Z",
    }


def geo_dossier(lat: float, lng: float, intel: Any, sanctions: Any, exposure: Any) -> dict[str, Any]:
    """Decision dossier for a clicked globe coordinate."""
    nearest_hotspots = sorted(
        [
            {**h, "distance_km": round(_distance_km(lat, lng, h["lat"], h["lng"]), 1)}
            for h in STRATEGIC_HOTSPOTS
        ],
        key=lambda h: h["distance_km"],
    )[:5]
    nearest_assets = sorted(
        [
            {**a, "distance_km": round(_distance_km(lat, lng, a["lat"], a["lng"]), 1)}
            for a in MISSION_ASSETS
        ],
        key=lambda a: a["distance_km"],
    )[:5]
    closest = nearest_hotspots[0] if nearest_hotspots else None
    distance_factor = 25 if closest and closest["distance_km"] < 500 else 10 if closest and closest["distance_km"] < 1500 else 0
    severity_factor = {"CRITICAL": 35, "HIGH": 25, "MEDIUM": 12}.get((closest or {}).get("severity"), 5)
    asset_factor = max(0, 20 - int((nearest_assets[0]["distance_km"] if nearest_assets else 9999) / 300))
    score = min(99, 35 + distance_factor + severity_factor + asset_factor)
    decision = _decision(
        title=f"Coordinate assessment {lat:.2f}, {lng:.2f}",
        score=score,
        confidence=72 if closest else 55,
        impact=min(99, 55 + severity_factor + asset_factor),
        urgency=60 + distance_factor,
        actionability=70,
        action="Review nearest hotspot, mission assets, imagery layers, and relevant cyber/AML overlays before briefing commander.",
        owner="Watch Officer / Fusion Cell",
        evidence=[
            f"Nearest hotspot: {closest['name']} ({closest['distance_km']} km)" if closest else "No hotspot within model",
            f"Nearest mission asset: {nearest_assets[0]['name']} ({nearest_assets[0]['distance_km']} km)" if nearest_assets else "No mission asset match",
            "Coordinate can pivot to satellite imagery, cyber attribution, and sanctions overlays",
        ],
        sources=["SENTINEL strategic hotspot model", "NASA/USGS imagery catalog", "MITRE/OFAC overlays"],
        time_to_action="Immediate triage",
        lat=lat,
        lng=lng,
        domain=(closest or {}).get("module", "global"),
    )
    return {
        "coordinate": {"lat": lat, "lng": lng},
        "decision": decision,
        "nearest_hotspots": nearest_hotspots,
        "nearest_assets": nearest_assets,
        "imagery_layers": SATELLITE_LAYERS,
        "recommended_pivots": [
            "Open Satellite + Imagery for visual context.",
            "Open Threat if nearest hotspot is conflict/geopolitical.",
            "Open Supply Chain if nearest hotspot is chokepoint/logistics.",
            "Open Cyber Security if nearby command asset or cyber actor origin matters.",
        ],
    }
