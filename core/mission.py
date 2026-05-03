"""Mission-domain fusion layer for the SENTINEL dashboard.

This module keeps the hackathon surface huge but simple: each mission button
returns one operational panel with trusted sources, map hotspots, indicators,
and recommended defensive actions.
"""
from __future__ import annotations

from collections import Counter
from datetime import datetime
from typing import Any

from .sanctions import FUNDING_LINKS, WANTED

TRUSTED_SOURCES: list[dict[str, str]] = [
    {"name": "CISA KEV", "agency": "DHS/CISA", "domain": "Cyber", "access": "Free public JSON"},
    {"name": "NIST NVD", "agency": "NIST", "domain": "Cyber", "access": "Free public API"},
    {"name": "MITRE ATT&CK", "agency": "MITRE", "domain": "Cyber", "access": "Free STIX/TAXII data"},
    {"name": "FIRST EPSS", "agency": "FIRST", "domain": "Cyber", "access": "Free public API"},
    {"name": "FBI Cyber Most Wanted", "agency": "FBI", "domain": "Cyber/Attribution", "access": "Public page"},
    {"name": "DoJ Cyber Indictments", "agency": "Department of Justice", "domain": "Attribution", "access": "Public releases"},
    {"name": "OFAC SDN", "agency": "US Treasury", "domain": "Sanctions/AML", "access": "Free CSV"},
    {"name": "Rewards for Justice", "agency": "US State Department", "domain": "Bounties", "access": "Public page"},
    {"name": "NSA Advisories", "agency": "NSA", "domain": "Cyber defense", "access": "Public advisories"},
    {"name": "DC3", "agency": "DoD Cyber Crime Center", "domain": "DoD cyber", "access": "Public advisories"},
    {"name": "abuse.ch", "agency": "abuse.ch", "domain": "Threat intel", "access": "Free exports"},
    {"name": "Spamhaus DROP/EDROP", "agency": "Spamhaus", "domain": "Threat intel", "access": "Free lists"},
    {"name": "SANS DShield", "agency": "SANS ISC", "domain": "Threat intel", "access": "Free list"},
    {"name": "PhishTank", "agency": "OpenDNS community", "domain": "Phishing", "access": "Free export"},
    {"name": "CIA World Factbook", "agency": "CIA", "domain": "Country context", "access": "Public reference"},
    {"name": "USGS Earthquake Hazards", "agency": "USGS", "domain": "Disasters", "access": "Free GeoJSON"},
    {"name": "NASA EONET", "agency": "NASA", "domain": "Disasters", "access": "Free API"},
    {"name": "GDACS", "agency": "UN/EU GDACS", "domain": "Disasters", "access": "Free RSS/API"},
    {"name": "NOAA/NWS Alerts", "agency": "NOAA", "domain": "Weather/disasters", "access": "Free API"},
    {"name": "FAA NAS Status", "agency": "FAA", "domain": "Aviation", "access": "Free XML"},
    {"name": "OpenSky Network", "agency": "OpenSky", "domain": "Aviation", "access": "Free API"},
    {"name": "GDELT 2.1", "agency": "GDELT Project", "domain": "Geopolitical events", "access": "Free API"},
    {"name": "Open-Meteo", "agency": "Open-Meteo", "domain": "Climate stress", "access": "Free API"},
    {"name": "UN OCHA HAPI", "agency": "UN OCHA", "domain": "Humanitarian", "access": "Free API"},
    {"name": "NASA GIBS", "agency": "NASA", "domain": "Satellite imagery", "access": "Public WMTS"},
    {"name": "USGS LandsatLook", "agency": "USGS", "domain": "Satellite imagery", "access": "Public viewer"},
    {"name": "Copernicus Sentinel", "agency": "EU Copernicus", "domain": "Satellite imagery", "access": "Public browser"},
]

MISSION_MODULES: list[dict[str, Any]] = [
    {
        "id": "cyber_defense",
        "label": "Cyber Defense",
        "short": "Detect active intrusion, exposure, malware IOCs, and likely actor playbooks.",
        "problem": "Mission networks and AI systems need a single view of active exploitation, adversary TTPs, and patch priority.",
        "sources": ["CISA KEV", "NIST NVD", "MITRE ATT&CK", "FIRST EPSS", "abuse.ch", "Spamhaus DROP/EDROP", "SANS DShield", "PhishTank", "NSA Advisories", "DC3"],
        "actions": [
            "Validate only owned or authorized assets with live OSINT scan.",
            "Patch CISA KEV entries first, prioritizing ransomware-used CVEs.",
            "Block recent IOCs at DNS, proxy, EDR, and perimeter controls.",
            "Map alert behavior to MITRE ATT&CK techniques before response.",
            "Generate a commander BLUF with mitigations and remaining intel gaps.",
        ],
    },
    {
        "id": "aml_finance",
        "label": "Money Laundering",
        "short": "Trace sanctioned actors, cyber bounties, funding links, and criminal-finance pressure.",
        "problem": "Cyber operations often intersect with sanctions evasion, ransomware cashout, and state funding pipelines.",
        "sources": ["OFAC SDN", "FBI Cyber Most Wanted", "DoJ Cyber Indictments", "Rewards for Justice", "CIA World Factbook"],
        "actions": [
            "Search OFAC names, aliases, programs, countries, and linked locations.",
            "Pivot from wanted actors to APT groups and funding flows.",
            "Flag DPRK, Russia, Iran, and PRC-linked public attribution.",
            "Separate public evidence from analytic inference in the dossier.",
        ],
    },
    {
        "id": "sanctions",
        "label": "Sanctions Intel",
        "short": "Country and entity pressure map from Treasury OFAC plus wanted cyber operators.",
        "problem": "Command staff need fast entity checks without leaving the operational picture.",
        "sources": ["OFAC SDN", "Rewards for Justice", "FBI Cyber Most Wanted", "DoJ Cyber Indictments"],
        "actions": [
            "Query name, alias, country, vessel, or program across OFAC.",
            "Surface top designated countries and nearby cyber actors.",
            "Attach public bounty and indictment context to the same dossier.",
        ],
    },
    {
        "id": "supply_chain",
        "label": "Supply Chain",
        "short": "Defense vendor exposure, chokepoints, ports, and infrastructure cascade risk.",
        "problem": "A patched tactical unit still depends on vulnerable vendors, ports, logistics nodes, and cloud providers.",
        "sources": ["CISA KEV", "NIST NVD", "MITRE ATT&CK", "GDELT 2.1", "USGS Earthquake Hazards", "NASA EONET"],
        "actions": [
            "Rank DoD-stack vendors by active exploitation and ransomware use.",
            "Watch strategic chokepoints and logistics hubs for disruption.",
            "Tie infrastructure events to vulnerable software and mission impact.",
        ],
    },
    {
        "id": "geo_conflict",
        "label": "Geopolitical Risk",
        "short": "Country hotspots, public advisories, conflict signals, and attributed cyber pressure.",
        "problem": "Cyber risk is amplified by regional conflict, sanctions pressure, and adversary intent.",
        "sources": ["CIA World Factbook", "GDELT 2.1", "US State Department", "MITRE ATT&CK", "OFAC SDN"],
        "actions": [
            "Click a country or hotspot for actors, sanctions, and likely mission impact.",
            "Use signal convergence: conflict + cyber + sanctions + infrastructure.",
            "Generate a regional BLUF for commander review.",
        ],
    },
    {
        "id": "aviation_maritime",
        "label": "Air & Maritime",
        "short": "Aviation status, maritime chokepoints, GPS interference, and logistics exposure.",
        "problem": "Digital defense depends on physical movement, airspace, ports, and navigation integrity.",
        "sources": ["FAA NAS Status", "OpenSky Network", "GDACS", "GDELT 2.1", "gpsjam.org"],
        "actions": [
            "Track airports, chokepoints, naval-relevant ports, and route disruption.",
            "Correlate cyber alerts with logistics chokepoints.",
            "Surface GPS/GNSS interference as an electronic-warfare indicator.",
        ],
    },
    {
        "id": "disasters",
        "label": "Disasters",
        "short": "Earthquakes, wildfires, storms, floods, climate stress, and infrastructure cascade triggers.",
        "problem": "Natural events can degrade comms, logistics, power, and cyber response capacity.",
        "sources": ["USGS Earthquake Hazards", "NASA EONET", "GDACS", "NOAA/NWS Alerts", "Open-Meteo"],
        "actions": [
            "Overlay disaster signals on cyber and supply-chain hotspots.",
            "Prioritize exposed facilities and vendor dependencies in affected regions.",
            "Use population and infrastructure exposure as response multipliers.",
        ],
    },
    {
        "id": "insider_ai",
        "label": "Insider & AI",
        "short": "Behavioral anomaly scoring plus AI/model deployment hardening.",
        "problem": "Modern mission systems need one risk engine for network behavior, insider activity, and AI supply chain changes.",
        "sources": ["NSL-KDD", "CERT Insider Threat", "CISA KEV", "MITRE ATT&CK", "ModelScan-compatible workflow"],
        "actions": [
            "Inject real labeled NSL-KDD attack families for live detection demo.",
            "Score behavior with IsolationForest, per-entity z-score, and supervised XGBoost.",
            "Validate model/container artifacts against known-good baselines before deployment.",
            "Keep human-in-the-loop mitigation decisions explicit.",
        ],
    },
    {
        "id": "satellite_imagery",
        "label": "Satellite & Imagery",
        "short": "Public orbital imagery and geospatial event feeds for visual situational awareness.",
        "problem": "Cyber, logistics, and national-security decisions need visual context for disasters, ports, airfields, routes, and infrastructure.",
        "sources": ["NASA EONET", "NASA GIBS", "USGS Earthquake Hazards", "USGS LandsatLook", "Copernicus Sentinel", "NOAA/NWS Alerts"],
        "actions": [
            "Use NASA EONET and USGS event geometry as globe overlays.",
            "Open NASA GIBS, LandsatLook, or Copernicus imagery for visual confirmation.",
            "Correlate satellite-visible events with cyber exposure and logistics risk.",
            "Keep imagery as decision support; do not automate irreversible actions.",
        ],
    },
]

HOTSPOTS: list[dict[str, Any]] = [
    {"id": "pentagon", "name": "Pentagon / DoD HQ", "lat": 38.871, "lng": -77.056, "kind": "command", "module": "cyber_defense", "severity": "CRITICAL", "country": "United States", "why": "Mission command target; anchor for cyber defense and incident response."},
    {"id": "fort-meade", "name": "NSA / USCYBERCOM Fort Meade", "lat": 39.108, "lng": -76.769, "kind": "command", "module": "cyber_defense", "severity": "CRITICAL", "country": "United States", "why": "Cyber command and intelligence hub; high-value target in public adversary doctrine."},
    {"id": "langley", "name": "CIA Langley", "lat": 38.951, "lng": -77.146, "kind": "intel", "module": "geo_conflict", "severity": "HIGH", "country": "United States", "why": "Country context, threat attribution, and national intelligence coordination."},
    {"id": "nyc-finance", "name": "NYC Financial Sector", "lat": 40.706, "lng": -74.009, "kind": "finance", "module": "aml_finance", "severity": "HIGH", "country": "United States", "why": "Ransomware, sanctions evasion, and illicit finance blast radius."},
    {"id": "silicon-valley", "name": "Defense AI / Cloud Supply Base", "lat": 37.387, "lng": -122.060, "kind": "supply", "module": "supply_chain", "severity": "HIGH", "country": "United States", "why": "Vendor and AI model supply-chain dependency concentration."},
    {"id": "beijing", "name": "PRC Cyber Actor Origin", "lat": 39.9042, "lng": 116.4074, "kind": "actor", "module": "cyber_defense", "severity": "CRITICAL", "country": "China", "why": "Public attribution includes PLA/MSS-linked APT activity."},
    {"id": "moscow", "name": "Russian Cyber Actor Origin", "lat": 55.7558, "lng": 37.6176, "kind": "actor", "module": "cyber_defense", "severity": "CRITICAL", "country": "Russia", "why": "Public attribution includes GRU/SVR/FSB and ransomware-linked actors."},
    {"id": "pyongyang", "name": "DPRK Cyber + Crypto Theft", "lat": 39.0392, "lng": 125.7625, "kind": "finance", "module": "aml_finance", "severity": "CRITICAL", "country": "North Korea", "why": "Lazarus/BlueNoroff public linkage to crypto theft and weapons-program funding."},
    {"id": "tehran", "name": "Iran Cyber Actor Origin", "lat": 35.6892, "lng": 51.3890, "kind": "actor", "module": "geo_conflict", "severity": "HIGH", "country": "Iran", "why": "Public attribution includes IRGC/MOIS-linked intrusion activity."},
    {"id": "suez", "name": "Suez Canal Chokepoint", "lat": 30.0444, "lng": 32.5498, "kind": "chokepoint", "module": "aviation_maritime", "severity": "HIGH", "country": "Egypt", "why": "Strategic maritime trade and military logistics chokepoint."},
    {"id": "malacca", "name": "Strait of Malacca", "lat": 1.3521, "lng": 103.8198, "kind": "chokepoint", "module": "aviation_maritime", "severity": "HIGH", "country": "Singapore/Malaysia/Indonesia", "why": "Global shipping, fuel, and Indo-Pacific logistics dependency."},
    {"id": "panama", "name": "Panama Canal", "lat": 9.0800, "lng": -79.6800, "kind": "chokepoint", "module": "supply_chain", "severity": "MEDIUM", "country": "Panama", "why": "Strategic shipping disruption can cascade into supply pressure."},
    {"id": "hormuz", "name": "Strait of Hormuz", "lat": 26.5667, "lng": 56.2500, "kind": "chokepoint", "module": "geo_conflict", "severity": "CRITICAL", "country": "Iran/Oman", "why": "Energy shipping chokepoint with conflict escalation sensitivity."},
    {"id": "ukraine", "name": "Ukraine Conflict / Cyber Convergence", "lat": 50.4501, "lng": 30.5234, "kind": "conflict", "module": "geo_conflict", "severity": "CRITICAL", "country": "Ukraine", "why": "Conflict, cyber operations, sanctions, GPS interference, and infrastructure risk converge."},
    {"id": "tokyo", "name": "Indo-Pacific Logistics Hub", "lat": 35.6762, "lng": 139.6503, "kind": "supply", "module": "aviation_maritime", "severity": "MEDIUM", "country": "Japan", "why": "Regional logistics and allied basing relevance."},
    {"id": "california-wildfire", "name": "Western US Disaster Stress", "lat": 36.7783, "lng": -119.4179, "kind": "disaster", "module": "disasters", "severity": "MEDIUM", "country": "United States", "why": "Wildfire, power, and comms disruption can degrade cyber response."},
    {"id": "gibs-global", "name": "NASA GIBS Global Imagery", "lat": 0.0, "lng": -30.0, "kind": "satellite", "module": "satellite_imagery", "severity": "HIGH", "country": "Global", "why": "Daily public imagery layers for smoke, cloud, thermal anomalies, and surface context."},
    {"id": "landsat-global", "name": "USGS LandsatLook", "lat": 34.0, "lng": -98.0, "kind": "satellite", "module": "satellite_imagery", "severity": "MEDIUM", "country": "Global", "why": "Open scene-based imagery for infrastructure and before/after assessment."},
]


def _source_details(names: list[str]) -> list[dict[str, str]]:
    wanted = set(names)
    return [s for s in TRUSTED_SOURCES if s["name"] in wanted]


def _module_metrics(module_id: str, intel: Any, sanctions: Any, exposure: Any) -> list[dict[str, Any]]:
    summary = intel.summary()
    sanc = sanctions.summary()
    exp = exposure.report()
    if module_id == "cyber_defense":
        return [
            {"label": "CISA KEV", "value": summary["kev_count"], "tone": "bad"},
            {"label": "Ransomware CVEs", "value": summary["kev_ransomware"], "tone": "crit"},
            {"label": "APT Groups", "value": summary["apt_groups_total"], "tone": "warn"},
            {"label": "Live IOCs", "value": summary["live_iocs"], "tone": "ok"},
        ]
    if module_id == "aml_finance":
        return [
            {"label": "OFAC Entities", "value": sanc["ofac_total"], "tone": "gold"},
            {"label": "Wanted Actors", "value": sanc["wanted_count"], "tone": "warn"},
            {"label": "Public Bounties", "value": f"${sanc['wanted_bounty_usd'] // 1_000_000}M", "tone": "gold"},
            {"label": "Funding Links", "value": len(FUNDING_LINKS), "tone": "crit"},
        ]
    if module_id == "sanctions":
        return [
            {"label": "SDN Entities", "value": sanc["ofac_total"], "tone": "gold"},
            {"label": "Addresses", "value": sanc["ofac_addresses"], "tone": "warn"},
            {"label": "Aliases", "value": sanc["ofac_aliases"], "tone": "ok"},
            {"label": "Top Countries", "value": len(sanc["top_countries"]), "tone": "bad"},
        ]
    if module_id == "supply_chain":
        return [
            {"label": "Exposed Vendors", "value": exp["totals"]["vendors_with_active_exploits"], "tone": "bad"},
            {"label": "Active Exploits", "value": exp["totals"]["total_active_exploits"], "tone": "crit"},
            {"label": "Ransomware Used", "value": exp["totals"]["total_ransomware_used"], "tone": "crit"},
            {"label": "Chokepoints", "value": 4, "tone": "warn"},
        ]
    if module_id == "insider_ai":
        return [
            {"label": "Behavior Sources", "value": "NSL/CERT/CIC", "tone": "ok"},
            {"label": "Model Heads", "value": 3, "tone": "ok"},
            {"label": "Attack Families", "value": 5, "tone": "warn"},
            {"label": "Human Approval", "value": "ON", "tone": "gold"},
        ]
    if module_id == "satellite_imagery":
        return [
            {"label": "Imagery Sources", "value": 4, "tone": "ok"},
            {"label": "Event Feeds", "value": 3, "tone": "warn"},
            {"label": "Open Access", "value": "YES", "tone": "gold"},
            {"label": "Map Layers", "value": "LIVE", "tone": "ok"},
        ]
    return [
        {"label": "Trusted Sources", "value": len(TRUSTED_SOURCES), "tone": "ok"},
        {"label": "Hotspots", "value": len([h for h in HOTSPOTS if h["module"] == module_id]), "tone": "warn"},
        {"label": "Signals", "value": "Multi", "tone": "gold"},
        {"label": "Action Mode", "value": "BLUF", "tone": "ok"},
    ]


def _module_payload(module: dict[str, Any], intel: Any, sanctions: Any, exposure: Any) -> dict[str, Any]:
    module_id = module["id"]
    hotspots = [h for h in HOTSPOTS if h["module"] == module_id]
    if module_id == "cyber_defense":
        detail = {
            "top_exposure": exposure.report()["vendors"][:6],
            "recent_kev": intel.summary()["kev_recent"],
            "iocs": intel.summary()["ioc_sample"],
        }
    elif module_id in ("aml_finance", "sanctions"):
        detail = {
            "top_countries": sanctions.summary()["top_countries"],
            "wanted": WANTED,
            "funding_links": FUNDING_LINKS,
        }
    elif module_id == "supply_chain":
        detail = {"vendors": exposure.report()["vendors"][:10], "chokepoints": [h for h in HOTSPOTS if h["kind"] == "chokepoint"]}
    else:
        detail = {"hotspots": hotspots, "source_catalog": _source_details(module["sources"])}
    return {
        **module,
        "metrics": _module_metrics(module_id, intel, sanctions, exposure),
        "sources_detail": _source_details(module["sources"]),
        "hotspots": hotspots,
        "detail": detail,
        "updated_at": datetime.utcnow().isoformat() + "Z",
    }


def mission_summary(intel: Any, sanctions: Any, exposure: Any) -> dict[str, Any]:
    modules = []
    for m in MISSION_MODULES:
        modules.append({
            "id": m["id"],
            "label": m["label"],
            "short": m["short"],
            "metrics": _module_metrics(m["id"], intel, sanctions, exposure),
            "hotspots": len([h for h in HOTSPOTS if h["module"] == m["id"]]),
            "sources": len(m["sources"]),
        })
    return {
        "modules": modules,
        "hotspots": HOTSPOTS,
        "sources": TRUSTED_SOURCES,
        "source_domains": dict(Counter(s["domain"] for s in TRUSTED_SOURCES)),
        "updated_at": datetime.utcnow().isoformat() + "Z",
    }


def mission_module(module_id: str, intel: Any, sanctions: Any, exposure: Any) -> dict[str, Any] | None:
    module = next((m for m in MISSION_MODULES if m["id"] == module_id), None)
    if not module:
        return None
    return _module_payload(module, intel, sanctions, exposure)


def mission_hotspot(hotspot_id: str, intel: Any, sanctions: Any, exposure: Any) -> dict[str, Any] | None:
    hotspot = next((h for h in HOTSPOTS if h["id"] == hotspot_id), None)
    if not hotspot:
        return None
    module = mission_module(hotspot["module"], intel, sanctions, exposure)
    related_groups = [
        g for g in intel.mitre.groups
        if (hotspot["country"].split("/")[0].lower() in (g.get("country") or "").lower())
    ][:8]
    return {
        "hotspot": hotspot,
        "module": module,
        "related_groups": related_groups,
        "country_sanctions": sanctions.search(hotspot["country"].split("/")[0], limit=8),
        "recommended_next": [
            "Open the mission module for full source context.",
            "Generate a briefing for this hotspot.",
            "Run live scan only on owned/authorized indicators connected to this location.",
        ],
    }
