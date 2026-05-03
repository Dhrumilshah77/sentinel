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
    {"name": "FinCEN Advisories", "agency": "US Treasury FinCEN", "domain": "AML/Fraud", "access": "Public advisories"},
    {"name": "FATF Typologies", "agency": "FATF", "domain": "AML/Fraud", "access": "Public reports"},
    {"name": "Federal Reserve FraudClassifier", "agency": "Federal Reserve", "domain": "Payments fraud", "access": "Public taxonomy"},
    {"name": "FBI IC3", "agency": "FBI", "domain": "Internet crime", "access": "Public annual reports"},
    {"name": "SEC Investor Alerts", "agency": "SEC", "domain": "Investor/crypto fraud", "access": "Public alerts"},
    {"name": "CFTC Customer Advisories", "agency": "CFTC", "domain": "Commodity/crypto fraud", "access": "Public alerts"},
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
    {"name": "NOAA SWPC", "agency": "NOAA", "domain": "Space weather", "access": "Free public JSON"},
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
        "sources": ["OFAC SDN", "FinCEN Advisories", "FATF Typologies", "Federal Reserve FraudClassifier", "FBI IC3", "SEC Investor Alerts", "CFTC Customer Advisories", "FBI Cyber Most Wanted", "DoJ Cyber Indictments", "Rewards for Justice", "CIA World Factbook"],
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
        "sources": ["NASA EONET", "NASA GIBS", "USGS Earthquake Hazards", "USGS LandsatLook", "Copernicus Sentinel", "NOAA/NWS Alerts", "GDACS", "GDELT 2.1", "NOAA SWPC"],
        "actions": [
            "Use NASA EONET and USGS event geometry as globe overlays.",
            "Open NASA GIBS, LandsatLook, or Copernicus imagery for visual confirmation.",
            "Run OSINT imagery triage on any clicked coordinate for thermal, weather, mobility, and military-relevance cues.",
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


DETAILED_MODULES: dict[str, dict[str, Any]] = {
    "cyber_defense": {
        "commander_view": "Prioritize defensive action by exploitability, mission asset exposure, actor intent, and time-to-patch.",
        "typologies": [
            {"name": "Initial access exploitation", "risk": "CRITICAL", "signals": ["CISA KEV present", "EPSS high", "internet-facing product", "ransomware-known flag"], "decision": "Patch or isolate before routine change window."},
            {"name": "Credential and identity attack", "risk": "HIGH", "signals": ["impossible travel", "MFA fatigue", "new OAuth consent", "admin role change"], "decision": "Revoke sessions, rotate credentials, inspect privilege paths."},
            {"name": "Command and control", "risk": "HIGH", "signals": ["ThreatFox IOC hit", "new DNS beacon", "rare ASN", "JA3 or user-agent outlier"], "decision": "Block indicator, hunt peer hosts, preserve packet/log evidence."},
            {"name": "Supply-chain package compromise", "risk": "HIGH", "signals": ["new dependency", "unexpected maintainer", "install script change", "SBOM drift"], "decision": "Freeze release, compare hashes, rebuild from trusted source."},
            {"name": "AI/model deployment tampering", "risk": "HIGH", "signals": ["model hash drift", "unexpected pickle/joblib artifact", "new container layer", "baseline eval change"], "decision": "Quarantine artifact and require human approval before inference use."},
        ],
        "detection_fields": ["asset_owner", "mission_system", "vendor", "product", "cve", "kev_date_added", "epss", "known_ransomware", "internet_exposed", "ttp_id", "ioc", "first_seen", "last_seen", "control_gap"],
        "scoring_formula": "0.30 mission criticality + 0.25 active exploitation + 0.20 actor intent + 0.15 exposure + 0.10 control gap.",
        "history": [
            {"period": "2017", "case": "WannaCry / NotPetya pattern", "lesson": "Known vulnerabilities plus flat networks create operational disruption beyond IT."},
            {"period": "2020", "case": "SolarWinds supply-chain compromise", "lesson": "Trusted software updates can become the intrusion path."},
            {"period": "2021-2026", "case": "VPN, edge appliance, and identity-provider exploitation", "lesson": "Patch internet-facing control planes first, not just highest CVSS."},
        ],
        "live_sources": ["CISA KEV JSON", "NIST NVD CVE 2.0", "FIRST EPSS", "MITRE ATT&CK STIX", "abuse.ch ThreatFox", "Spamhaus DROP/EDROP", "SANS DShield"],
        "workflows": ["Asset -> CVE -> KEV/EPSS -> exposed service -> actor TTP -> recommended control", "IOC -> malware family -> ATT&CK technique -> block/hunt query", "Vendor -> mission system -> open CVEs -> patch sequence"],
    },
    "aml_finance": {
        "commander_view": "Connect fraud, sanctions, cybercrime, and crypto movement into one explainable financial-threat picture.",
        "typologies": [
            {"name": "Crypto fraud and investment scams", "risk": "HIGH", "signals": ["new wallet cluster", "rapid inbound deposits", "exchange hop", "mixer exposure", "victim complaints"], "decision": "Freeze/flag exposed wallets and create SAR-style evidence packet."},
            {"name": "Ransomware cashout", "risk": "CRITICAL", "signals": ["ThreatFox malware family", "OFAC-linked actor", "mixing service", "nested exchange", "peel chain"], "decision": "Prioritize sanctions and law-enforcement notification workflow."},
            {"name": "First-party fraud", "risk": "MEDIUM", "signals": ["synthetic identity traits", "no normal income pattern", "rapid credit seeking", "device reuse"], "decision": "Step-up KYC and restrict high-risk movement."},
            {"name": "Third-party fraud", "risk": "HIGH", "signals": ["victim account takeover", "new beneficiary", "new device", "SIM swap", "velocity spike"], "decision": "Hold transfer, contact verified owner, preserve session telemetry."},
            {"name": "Account takeover", "risk": "HIGH", "signals": ["impossible travel", "credential stuffing", "new device fingerprint", "password reset then transfer"], "decision": "Lock account, revoke tokens, route to fraud ops."},
            {"name": "PEP and sanctions screening", "risk": "HIGH", "signals": ["OFAC alias hit", "country/program match", "close associate", "state-owned entity"], "decision": "Escalate enhanced due diligence and sanctions counsel review."},
            {"name": "Layering / peeling chains", "risk": "CRITICAL", "signals": ["many small outputs", "round-dollar transfers", "rapid chain hops", "bridge/mixer exposure"], "decision": "Graph funds movement and flag convergence wallets."},
            {"name": "Trade-based laundering", "risk": "HIGH", "signals": ["invoice mismatch", "dual-use goods", "shell entity", "high-risk port"], "decision": "Link sanctions, supply-chain, and shipping pages before release."},
        ],
        "detection_fields": ["customer_id", "beneficial_owner", "pep_flag", "sanctions_program", "wallet", "counterparty", "device_id", "ip_geo", "transaction_amount", "velocity_1h", "velocity_24h", "mixer_exposure", "exchange_hops", "chargeback_history", "kyc_age_days"],
        "scoring_formula": "0.25 sanctions/PEP exposure + 0.20 velocity anomaly + 0.20 account/device anomaly + 0.20 graph-risk proximity + 0.15 source-of-funds uncertainty.",
        "history": [
            {"period": "2019", "case": "Convertible virtual currency typologies", "lesson": "FinCEN highlighted darknet markets, P2P exchangers, kiosks, and unregistered MSBs as key risks."},
            {"period": "2020", "case": "FATF virtual asset red flags", "lesson": "Anonymity features, weak jurisdictions, unusual transaction patterns, and source-of-funds gaps are primary indicators."},
            {"period": "2020-2026", "case": "DPRK crypto theft and ransomware monetization", "lesson": "Cyber and AML cannot be separated; proceeds movement often funds strategic programs."},
        ],
        "live_sources": ["OFAC SDN", "FinCEN advisories", "FATF red-flag typologies", "Federal Reserve FraudClassifier", "FBI IC3", "SEC investor alerts", "CFTC customer advisories", "FBI Cyber Most Wanted", "State Rewards for Justice", "DoJ public indictments", "GDELT financial-crime watch"],
        "workflows": ["Identity -> device -> account -> transaction -> counterparty -> sanctions/PEP", "Wallet -> peel chain -> mixer/bridge -> exchange -> withdrawal entity", "Threat actor -> malware -> wallet/alias -> OFAC/FBI/DoJ evidence"],
        "flow_edges": [
            ["Victim funds", "Compromised account", "ATO / social engineering"],
            ["Compromised account", "Mule account", "third-party fraud"],
            ["Mule account", "Crypto exchange", "conversion"],
            ["Crypto exchange", "Peel chain wallets", "layering"],
            ["Peel chain wallets", "Mixer / bridge", "obfuscation"],
            ["Mixer / bridge", "Nested exchange", "cashout"],
            ["Nested exchange", "Sanctioned actor", "attribution / investigation"],
        ],
    },
    "sanctions": {
        "commander_view": "Screen people, entities, vessels, programs, aliases, and countries against public sanctions and cyber attribution.",
        "typologies": [
            {"name": "Alias and transliteration match", "risk": "HIGH", "signals": ["name similarity", "known alias", "date/place overlap"], "decision": "Route to entity-resolution review."},
            {"name": "Beneficial ownership concealment", "risk": "HIGH", "signals": ["shell company", "shared address", "nominee director", "high-risk jurisdiction"], "decision": "Escalate ownership graph."},
            {"name": "Vessel / maritime sanctions evasion", "risk": "HIGH", "signals": ["AIS gaps", "ship-to-ship transfer", "flag hopping", "dark port call"], "decision": "Pivot to Air/Sea and supply-chain pages."},
            {"name": "Cyber actor designation", "risk": "CRITICAL", "signals": ["linked APT", "ransomware wallet", "DoJ indictment", "RFJ bounty"], "decision": "Attach actor dossier and blocklist pivots."},
        ],
        "detection_fields": ["name", "alias", "program", "country", "address", "vessel_imo", "ownership_edge", "linked_apt", "bounty_usd", "indictment_ref"],
        "scoring_formula": "0.30 direct list match + 0.25 ownership proximity + 0.20 cyber attribution + 0.15 jurisdiction risk + 0.10 confidence.",
        "history": [
            {"period": "2014-2026", "case": "Russia sanctions expansion", "lesson": "Entity networks and procurement fronts shift over time."},
            {"period": "2018-2026", "case": "DPRK cyber and crypto designations", "lesson": "Sanctions, cyber theft, and weapons-program funding are linked in public reporting."},
        ],
        "live_sources": ["OFAC SDN", "FBI Cyber Most Wanted", "Rewards for Justice", "DoJ releases", "GDELT sanctions watch"],
        "workflows": ["Entity -> alias -> address -> program -> ownership graph", "APT -> wanted actor -> sanctions program -> public bounty", "Vessel/entity -> port/chokepoint -> supply-chain risk"],
    },
    "supply_chain": {
        "commander_view": "Rank mission dependency risk across software vendors, chokepoints, ports, cloud, and logistics nodes.",
        "typologies": [
            {"name": "Exposed vendor stack", "risk": "CRITICAL", "signals": ["DoD-stack vendor", "CISA KEV", "ransomware known", "critical mission use"], "decision": "Patch/isolate vendor technology first."},
            {"name": "Port and chokepoint disruption", "risk": "HIGH", "signals": ["GDACS event", "GDELT route disruption", "weather/quake nearby", "strategic chokepoint"], "decision": "Prepare alternate route impact note."},
            {"name": "Software dependency drift", "risk": "HIGH", "signals": ["new dependency", "SBOM mismatch", "unexpected maintainer", "build hash change"], "decision": "Freeze release and rebuild from known-good source."},
            {"name": "Dual-use procurement risk", "risk": "HIGH", "signals": ["sanctioned country", "front company", "sensitive commodity", "unusual route"], "decision": "Pivot sanctions and AML pages."},
        ],
        "detection_fields": ["vendor", "product", "mission_use", "kev_count", "ransom_count", "sbom_package", "port", "route", "country", "weather_event", "supplier_tier", "alternate_supplier"],
        "scoring_formula": "0.30 mission criticality + 0.25 active exploit exposure + 0.20 route/chokepoint risk + 0.15 supplier concentration + 0.10 recovery time.",
        "history": [
            {"period": "2020", "case": "Trusted software update compromise", "lesson": "Assume supplier trust requires continuous verification."},
            {"period": "2021-2026", "case": "Edge appliance mass exploitation", "lesson": "Internet-facing vendor products can become operational choke points."},
            {"period": "2023-2026", "case": "Canal/Red Sea/logistics disruption", "lesson": "Physical route stress changes cyber and sustainment priorities."},
        ],
        "live_sources": ["CISA KEV", "NIST NVD", "NASA EONET", "USGS", "GDACS", "GDELT", "OpenSky"],
        "workflows": ["Vendor -> product -> active exploit -> mission system -> mitigation", "Route -> chokepoint -> live event -> sustainment impact", "Supplier -> country -> sanctions -> procurement risk"],
    },
    "geo_conflict": {
        "commander_view": "Fuse public conflict, sanctions, cyber attribution, disaster, and media signals into regional risk.",
        "typologies": [
            {"name": "Cyber spillover from kinetic conflict", "risk": "CRITICAL", "signals": ["regional conflict", "APT attribution", "infrastructure targeting", "wiper/ransomware history"], "decision": "Increase monitoring on logistics, satellite comms, and suppliers."},
            {"name": "Sanctions pressure and retaliation", "risk": "HIGH", "signals": ["new sanctions narratives", "state media attention", "cyber actor activity"], "decision": "Brief likely cyber/economic retaliation paths."},
            {"name": "Chokepoint escalation", "risk": "HIGH", "signals": ["Red Sea/Hormuz/Suez/Malacca proximity", "shipping disruption", "military rhetoric"], "decision": "Pivot Air/Sea and Supply Chain."},
            {"name": "Information environment shift", "risk": "MEDIUM", "signals": ["GDELT volume spike", "negative tone", "bot-like repetition"], "decision": "Separate public reporting from verified operational evidence."},
        ],
        "detection_fields": ["region", "actor_country", "apt_groups", "sanctions_count", "gdelt_volume", "gdelt_tone", "hotspot_distance", "disaster_overlap", "mission_asset_distance"],
        "scoring_formula": "0.25 conflict severity + 0.20 cyber actor capability + 0.20 mission proximity + 0.20 sanctions/economic pressure + 0.15 live event convergence.",
        "history": [
            {"period": "2014-2026", "case": "Ukraine / Black Sea", "lesson": "Kinetic, cyber, sanctions, GPS, and infrastructure risk converge."},
            {"period": "2020-2026", "case": "Taiwan Strait / South China Sea", "lesson": "Military signaling affects cyber, shipping, semiconductor, and alliance risk."},
            {"period": "2023-2026", "case": "Red Sea disruption", "lesson": "Regional conflict quickly changes global logistics assumptions."},
        ],
        "live_sources": ["GDELT 2.1", "CIA World Factbook", "MITRE ATT&CK", "OFAC SDN", "NASA/USGS/NOAA/GDACS"],
        "workflows": ["Hotspot -> actor country -> APTs -> sanctions -> mission impact", "Media signal -> live event -> chokepoint -> logistics/cyber priority"],
    },
    "aviation_maritime": {
        "commander_view": "Track airspace, maritime chokepoints, ports, GPS/GNSS interference, and logistics confidence.",
        "typologies": [
            {"name": "Air track anomaly", "risk": "MEDIUM", "signals": ["OpenSky state vector", "unexpected altitude", "route deviation", "origin mismatch"], "decision": "Use as cue for watch officer, not attribution."},
            {"name": "Port/chokepoint disruption", "risk": "HIGH", "signals": ["GDACS/GDELT alert", "weather event", "conflict hotspot", "route dependency"], "decision": "Open supply-chain alternate-route workflow."},
            {"name": "GNSS interference cue", "risk": "HIGH", "signals": ["regional conflict", "reported GPS jamming", "aviation/maritime route impact"], "decision": "Flag navigation integrity risk."},
            {"name": "Sanctioned vessel / dark shipping", "risk": "HIGH", "signals": ["AIS gap", "flag change", "ship-to-ship transfer", "OFAC relation"], "decision": "Pivot sanctions and AML entity graph."},
        ],
        "detection_fields": ["callsign", "icao24", "origin_country", "altitude_m", "velocity_mps", "port", "chokepoint", "route", "weather_alert", "gdacs_event", "sanctions_relation"],
        "scoring_formula": "0.25 chokepoint criticality + 0.20 live disruption + 0.20 route dependency + 0.20 conflict proximity + 0.15 navigation integrity.",
        "history": [
            {"period": "2021-2026", "case": "Suez / Red Sea route stress", "lesson": "A single corridor can alter global sustainment timelines."},
            {"period": "2022-2026", "case": "Black Sea aviation/maritime risk", "lesson": "Conflict zones create cascading air, sea, cyber, and insurance effects."},
        ],
        "live_sources": ["OpenSky Network", "GDACS", "GDELT", "NOAA/NWS", "NASA EONET", "OFAC SDN"],
        "workflows": ["Aircraft -> state vector -> airspace region -> mission relevance", "Port -> chokepoint -> live event -> alternate route", "Vessel/entity -> sanctions -> AML graph"],
    },
    "disasters": {
        "commander_view": "Detect natural-event impact on communications, logistics, power, cyber-response capacity, and mission assets.",
        "typologies": [
            {"name": "Earthquake infrastructure stress", "risk": "HIGH", "signals": ["USGS magnitude", "depth", "PAGER alert", "asset proximity"], "decision": "Assess facilities, routes, and comms fallback."},
            {"name": "Wildfire / thermal anomaly", "risk": "HIGH", "signals": ["NASA EONET wildfire", "VIIRS thermal layer", "smoke/aerosol", "power grid proximity"], "decision": "Open imagery triage and logistics impact."},
            {"name": "Storm / flood mobility degradation", "risk": "HIGH", "signals": ["NOAA warning", "IMERG precipitation", "GDACS flood/cyclone", "route overlap"], "decision": "Prepare sustainment and evacuation options."},
            {"name": "Space weather communications risk", "risk": "MEDIUM", "signals": ["NOAA Kp index", "HF radio/GPS/satellite comms concern"], "decision": "Flag comms degradation risk to signal staff."},
        ],
        "detection_fields": ["event_id", "source", "category", "magnitude", "severity", "lat", "lng", "distance_to_asset", "distance_to_chokepoint", "imagery_layer", "estimated_start", "confidence"],
        "scoring_formula": "0.25 event severity + 0.25 mission proximity + 0.20 infrastructure dependence + 0.15 duration + 0.15 confidence.",
        "history": [
            {"period": "Real time", "case": "USGS GeoJSON feeds", "lesson": "Earthquake feeds update continuously and can trigger fast location-based triage."},
            {"period": "Real time", "case": "NASA EONET events", "lesson": "Wildfires, storms, ice, volcanoes, dust, and floods can be paired with imagery."},
        ],
        "live_sources": ["USGS GeoJSON", "NASA EONET", "NOAA/NWS alerts", "GDACS RSS", "NASA GIBS", "NOAA SWPC"],
        "workflows": ["Event -> coordinates -> nearest mission asset -> imagery -> response priority", "Weather alert -> route/chokepoint -> supply-chain impact"],
    },
    "satellite_imagery": {
        "commander_view": "Use public imagery as decision support: cue human review, compare layers, and explain why a coordinate deserves attention.",
        "typologies": [
            {"name": "Thermal anomaly review", "risk": "HIGH", "signals": ["VIIRS/MODIS thermal layer", "NASA EONET wildfire", "industrial heat cue"], "decision": "Compare thermal and true-color imagery."},
            {"name": "Airfield / port activity cue", "risk": "MEDIUM", "signals": ["strategic hotspot proximity", "OpenSky/GDELT overlap", "route/chokepoint relevance"], "decision": "Human analyst compares current and historical imagery."},
            {"name": "Flood / route degradation", "risk": "HIGH", "signals": ["IMERG precipitation", "NOAA alert", "GDACS flood/cyclone", "near route"], "decision": "Overlay logistics routes and alternatives."},
            {"name": "Smoke/dust/obscuration", "risk": "MEDIUM", "signals": ["aerosol index", "EONET event", "weather alert"], "decision": "Flag ISR visibility and air/ground movement risk."},
        ],
        "detection_fields": ["lat", "lng", "bbox", "layer_id", "time", "nearest_hotspot", "nearest_asset", "thermal_score", "weather_score", "mobility_score", "military_relevance_score"],
        "scoring_formula": "0.25 live event proximity + 0.25 hotspot proximity + 0.20 mission asset proximity + 0.20 imagery-layer availability + 0.10 confidence.",
        "history": [
            {"period": "Daily", "case": "NASA GIBS true-color / thermal / precipitation layers", "lesson": "Public imagery can support rapid before/after context."},
            {"period": "Scene based", "case": "USGS LandsatLook and Copernicus Sentinel", "lesson": "Higher-detail open imagery supports manual confirmation."},
        ],
        "live_sources": ["NASA GIBS WMS/WMTS", "NASA EONET", "USGS LandsatLook", "Copernicus Browser", "NOAA/NWS", "GDACS", "GDELT"],
        "workflows": ["Click coordinate -> imagery analysis -> preview image -> indicators -> recommended pivots", "Event -> imagery layer -> nearest asset -> mission note"],
    },
    "insider_ai": {
        "commander_view": "Score anomalous user, network, and model-deployment behavior while keeping human approval in the loop.",
        "typologies": [
            {"name": "Insider data staging", "risk": "HIGH", "signals": ["unusual file access", "bulk download", "off-hours activity", "new external destination"], "decision": "Preserve logs, step-up review, limit data movement."},
            {"name": "Account misuse after compromise", "risk": "HIGH", "signals": ["new device", "privilege change", "impossible travel", "rare command sequence"], "decision": "Revoke session and inspect peer activity."},
            {"name": "Model/container tampering", "risk": "HIGH", "signals": ["hash drift", "unexpected package", "new base image", "eval regression"], "decision": "Block deployment until artifact verification passes."},
            {"name": "Prompt/data exfiltration path", "risk": "MEDIUM", "signals": ["sensitive prompt", "unapproved connector", "large context export"], "decision": "Route to AI governance and DLP review."},
        ],
        "detection_fields": ["user_id", "role", "device_id", "file_count", "bytes_out", "time_of_day", "geo_velocity", "model_hash", "container_layer", "baseline_z", "isolation_score", "human_approval"],
        "scoring_formula": "0.30 behavior anomaly + 0.25 data sensitivity + 0.20 privilege level + 0.15 model/artifact drift + 0.10 repeat history.",
        "history": [
            {"period": "CERT dataset pattern", "case": "Behavioral insider activity", "lesson": "User/entity baselines are more useful than one-off static rules."},
            {"period": "Modern AI deployments", "case": "Model supply-chain drift", "lesson": "AI artifacts must be treated like deployable software with provenance."},
        ],
        "live_sources": ["NSL-KDD", "CERT Insider Threat", "CIC-IDS-2017", "CISA KEV", "MITRE ATT&CK", "local model/container manifest"],
        "workflows": ["User -> behavior baseline -> sensitive data -> approval gate", "Model artifact -> hash/SBOM -> eval delta -> deployment decision"],
    },
}


EXTRA_TYPOLOGIES: dict[str, list[dict[str, Any]]] = {
    "cyber_defense": [
        {"name": "Phishing and BEC intrusion", "risk": "HIGH", "signals": ["lookalike domain", "new mail rule", "invoice language", "OAuth grant", "credential replay"], "decision": "Disable mail rules, revoke tokens, inspect mailbox and finance pivots."},
        {"name": "Ransomware pre-positioning", "risk": "CRITICAL", "signals": ["remote admin tool", "backup deletion", "mass file enumeration", "domain admin use", "known ransomware CVE"], "decision": "Isolate affected segment and preserve identity/log evidence."},
        {"name": "DDoS against sensor/comms edge", "risk": "HIGH", "signals": ["traffic spike", "single service saturation", "botnet ASN mix", "availability SLO breach"], "decision": "Shift to protected endpoint/CDN, rate-limit, and activate continuity plan."},
        {"name": "Cloud control-plane abuse", "risk": "HIGH", "signals": ["new access key", "rare region", "security group opened", "snapshot export", "console login anomaly"], "decision": "Revoke keys, lock region, inspect IAM and storage access."},
        {"name": "SaaS OAuth consent abuse", "risk": "HIGH", "signals": ["new app consent", "mail/read scopes", "unverified publisher", "cross-tenant token use"], "decision": "Remove app, revoke refresh tokens, review tenant-wide consents."},
        {"name": "Data exfiltration", "risk": "CRITICAL", "signals": ["large egress", "rare destination", "encrypted archive", "DLP hit", "off-hours transfer"], "decision": "Stop transfer, snapshot logs, and scope affected data."},
        {"name": "OT/ICS targeting", "risk": "CRITICAL", "signals": ["engineering workstation access", "Modbus/OPC anomaly", "new PLC logic", "flat IT/OT path"], "decision": "Segment OT, require manual validation, and shift to safety procedures."},
        {"name": "Edge appliance exploitation", "risk": "CRITICAL", "signals": ["VPN/admin portal", "KEV match", "webshell indicator", "config export", "unusual child process"], "decision": "Reimage edge device and rotate all credentials crossing that boundary."},
    ],
    "aml_finance": [
        {"name": "Card-not-present fraud", "risk": "HIGH", "signals": ["new card/device pair", "AVS/CVV mismatch", "high order velocity", "reshipper address", "BIN attack"], "decision": "Step-up authentication and hold fulfillment."},
        {"name": "Card-present skimming", "risk": "MEDIUM", "signals": ["same merchant cluster", "fallback swipe", "geographic burst", "low-ticket testing"], "decision": "Alert acquiring/merchant team and monitor exposed card range."},
        {"name": "Synthetic identity", "risk": "HIGH", "signals": ["thin file", "SSN/name mismatch", "device reuse", "rapid credit build", "address cluster"], "decision": "Require enhanced KYC and restrict credit/withdrawal limits."},
        {"name": "Mule network recruitment", "risk": "HIGH", "signals": ["many inbound victims", "fast outbound wires", "same device/IP cluster", "student/elder segment"], "decision": "Freeze mule hub and produce graph packet for investigators."},
        {"name": "Check fraud", "risk": "MEDIUM", "signals": ["mobile deposit anomaly", "new payee", "duplicate image", "high-risk routing number"], "decision": "Delay funds availability and verify maker institution."},
        {"name": "ACH and wire fraud", "risk": "HIGH", "signals": ["new beneficiary", "template change", "large first transfer", "IP/device anomaly"], "decision": "Hold transfer and call back using verified contact channel."},
        {"name": "BEC invoice diversion", "risk": "HIGH", "signals": ["vendor bank change", "invoice language drift", "mailbox rule", "lookalike domain"], "decision": "Verify vendor out-of-band and pivot to cyber investigation."},
        {"name": "Pig-butchering / romance scam", "risk": "HIGH", "signals": ["victim narrative", "crypto ramp", "repeated wires", "foreign exchange", "social platform link"], "decision": "Trigger victim-safety workflow and block high-risk crypto outbound."},
        {"name": "Refund and chargeback abuse", "risk": "MEDIUM", "signals": ["repeat disputes", "friendly-fraud pattern", "delivery confirmed", "shared device"], "decision": "Score account trust and require stronger purchase proof."},
        {"name": "Promo and bonus abuse", "risk": "MEDIUM", "signals": ["many new accounts", "same device", "same funding source", "rapid withdrawal"], "decision": "Link identities and delay bonus payout."},
        {"name": "Merchant fraud", "risk": "HIGH", "signals": ["rapid volume spike", "same customer cards", "refund loop", "high chargeback rate"], "decision": "Hold settlement and inspect merchant ownership."},
        {"name": "Bust-out fraud", "risk": "HIGH", "signals": ["credit line growth", "sudden utilization", "many cash-like purchases", "no repayment"], "decision": "Lower exposure and block cash-equivalent channels."},
        {"name": "Elder financial exploitation", "risk": "HIGH", "signals": ["new caregiver payee", "unusual withdrawal", "branch concern", "romance/BEC indicator"], "decision": "Escalate vulnerable-customer protocol and pause suspicious transfer."},
        {"name": "Tax/refund fraud", "risk": "MEDIUM", "signals": ["same bank account across refunds", "synthetic identity", "filing velocity", "address reuse"], "decision": "Link entities and route to public-benefits fraud workflow."},
        {"name": "Payroll diversion", "risk": "MEDIUM", "signals": ["direct deposit change", "new account", "employee mailbox compromise", "HR self-service anomaly"], "decision": "Verify with employee and reset compromised credentials."},
        {"name": "SIM-swap enabled ATO", "risk": "HIGH", "signals": ["phone port-out", "password reset", "new device", "transfer within minutes"], "decision": "Lock account and require secure recovery."},
        {"name": "Loan stacking", "risk": "HIGH", "signals": ["many applications", "short window", "shared device/address", "thin-file borrower"], "decision": "Query consortium-style signals and tighten underwriting."},
    ],
    "sanctions": [
        {"name": "Export-control procurement evasion", "risk": "HIGH", "signals": ["dual-use commodity", "front company", "transshipment route", "end-user mismatch"], "decision": "Escalate trade-compliance review and block shipment release."},
        {"name": "Front-company network", "risk": "HIGH", "signals": ["shared address", "nominee director", "rapid incorporation", "sanctioned-country nexus"], "decision": "Build ownership graph and mark indirect exposure."},
        {"name": "Dual-use goods diversion", "risk": "HIGH", "signals": ["electronics/aerospace part", "unusual buyer", "rerouted logistics", "military end-use risk"], "decision": "Require end-use validation and legal review."},
        {"name": "PEP screening", "risk": "MEDIUM", "signals": ["official role", "family/close associate", "state-owned enterprise", "adverse media"], "decision": "Apply enhanced due diligence and ongoing monitoring."},
        {"name": "Adverse media escalation", "risk": "MEDIUM", "signals": ["corruption terms", "sanctions reporting", "indictment mention", "state-media linkage"], "decision": "Attach public evidence and require analyst disposition."},
    ],
    "supply_chain": [
        {"name": "SBOM drift", "risk": "HIGH", "signals": ["new package", "version mismatch", "unknown license", "hash mismatch"], "decision": "Block release until SBOM and artifact hashes reconcile."},
        {"name": "Vendor compromise", "risk": "CRITICAL", "signals": ["vendor KEV spike", "remote admin exposure", "incident disclosure", "trusted update path"], "decision": "Treat vendor channel as hostile until verification passes."},
        {"name": "Counterfeit component risk", "risk": "HIGH", "signals": ["unusual broker", "obsolete part", "price anomaly", "country risk"], "decision": "Require provenance and independent inspection."},
        {"name": "Single-source supplier", "risk": "MEDIUM", "signals": ["one supplier", "long lead time", "regional disaster", "no alternate contract"], "decision": "Prepare alternate sourcing and mission impact note."},
        {"name": "Cloud region outage", "risk": "HIGH", "signals": ["regional service event", "single-region deployment", "identity/provider dependency"], "decision": "Fail over critical workloads and test recovery plan."},
        {"name": "Route disruption", "risk": "HIGH", "signals": ["port closure", "canal delay", "storm track", "conflict route overlap"], "decision": "Recompute sustainment route and adjust inventory posture."},
        {"name": "Dependency confusion", "risk": "HIGH", "signals": ["public package name collision", "new registry source", "install script", "build egress"], "decision": "Pin private registry and quarantine suspicious packages."},
    ],
    "geo_conflict": [
        {"name": "Military mobilization cue", "risk": "HIGH", "signals": ["regional reporting spike", "air/sea activity", "border movement", "official rhetoric"], "decision": "Raise regional watch posture and update commander BLUF."},
        {"name": "Election interference / influence ops", "risk": "HIGH", "signals": ["coordinated narratives", "bot-like repetition", "foreign state media", "phishing against civic orgs"], "decision": "Separate influence signal from verified intrusion evidence."},
        {"name": "Energy chokepoint pressure", "risk": "HIGH", "signals": ["Hormuz/Suez/Red Sea proximity", "tanker reroute", "sanctions pressure", "oil/gas news spike"], "decision": "Notify logistics and supply-chain leads."},
        {"name": "Refugee/humanitarian pressure", "risk": "MEDIUM", "signals": ["conflict escalation", "border reports", "OCHA/GDELT terms", "infrastructure damage"], "decision": "Assess aid route and civilian infrastructure implications."},
        {"name": "EW/GPS interference", "risk": "HIGH", "signals": ["conflict theater", "aviation anomaly", "maritime spoofing", "reported jamming"], "decision": "Flag navigation confidence and switch to alternate PNT procedures."},
    ],
    "aviation_maritime": [
        {"name": "AIS gap / dark shipping", "risk": "HIGH", "signals": ["transponder silence", "high-risk zone", "flag change", "port-call mismatch"], "decision": "Review vessel history and sanctions proximity."},
        {"name": "Ship-to-ship transfer", "risk": "HIGH", "signals": ["loitering pair", "AIS proximity", "sanctioned cargo route", "night operation"], "decision": "Pivot sanctions/AML graph and port-state watch."},
        {"name": "Spoofed vessel identity", "risk": "HIGH", "signals": ["IMO/name mismatch", "impossible speed", "duplicate MMSI", "track jump"], "decision": "Treat track as low confidence and require independent confirmation."},
        {"name": "Port congestion", "risk": "MEDIUM", "signals": ["queue length", "weather alert", "labor/security event", "route concentration"], "decision": "Estimate sustainment delay and alternate port options."},
        {"name": "Airspace closure", "risk": "HIGH", "signals": ["NOTAM/news alert", "conflict proximity", "route deviation", "military exercise"], "decision": "Notify air mobility and adjust routing assumptions."},
        {"name": "ADS-B anomaly", "risk": "MEDIUM", "signals": ["identity change", "altitude jump", "track dropout", "unexpected origin"], "decision": "Use as cue for human watch, not final attribution."},
        {"name": "Drone/UAS corridor risk", "risk": "HIGH", "signals": ["critical facility", "airspace restriction", "recent incident", "low-altitude pattern"], "decision": "Coordinate counter-UAS and local security posture."},
    ],
    "disasters": [
        {"name": "Cyclone / hurricane impact", "risk": "HIGH", "signals": ["GDACS/NOAA alert", "coastal facility", "port route", "storm surge"], "decision": "Stage continuity, power, and route fallback."},
        {"name": "Extreme heat", "risk": "MEDIUM", "signals": ["heat warning", "power demand", "outdoor operations", "cooling dependency"], "decision": "Protect personnel and critical infrastructure cooling."},
        {"name": "Drought / water stress", "risk": "MEDIUM", "signals": ["long-duration alert", "reservoir/river context", "agriculture/logistics impact"], "decision": "Monitor sustainment and host-nation stability effects."},
        {"name": "Volcano / ash cloud", "risk": "HIGH", "signals": ["EONET volcano", "aviation route", "ash advisory", "wind direction"], "decision": "Assess air mobility and visibility limits."},
        {"name": "Infrastructure cascade", "risk": "HIGH", "signals": ["power outage reports", "telecom disruption", "hospital/port proximity", "cyber response overlap"], "decision": "Prioritize comms and power restoration dependencies."},
    ],
    "satellite_imagery": [
        {"name": "Convoy / logistics pattern cue", "risk": "MEDIUM", "signals": ["road chokepoint", "conflict hotspot", "OpenSky/GDELT overlap", "before/after need"], "decision": "Task human imagery comparison; do not infer intent from one frame."},
        {"name": "Burn-scar change detection", "risk": "HIGH", "signals": ["wildfire event", "thermal anomaly", "true-color contrast", "route proximity"], "decision": "Compare current imagery to previous scene and route map."},
        {"name": "Flood extent cue", "risk": "HIGH", "signals": ["IMERG precipitation", "NOAA flood alert", "river/coastal proximity", "road/port overlap"], "decision": "Mark mobility degradation and alternate routes."},
        {"name": "Shipyard / port change", "risk": "MEDIUM", "signals": ["strategic port", "AIS/port disruption", "GDELT article", "cloud-free imagery"], "decision": "Queue port-focused before/after review."},
        {"name": "Construction / emplacement change", "risk": "MEDIUM", "signals": ["persistent hotspot", "new surface pattern", "road access", "conflict proximity"], "decision": "Require historical imagery and second-source confirmation."},
        {"name": "Night-lights / power anomaly", "risk": "MEDIUM", "signals": ["disaster/conflict overlap", "urban area", "power-grid concern", "VIIRS night cue"], "decision": "Use as outage cue and corroborate with public utility/reporting."},
    ],
    "insider_ai": [
        {"name": "Privilege misuse", "risk": "HIGH", "signals": ["admin action outlier", "new service account", "policy change", "sensitive repo access"], "decision": "Require peer review and revoke unnecessary privilege."},
        {"name": "Impossible travel", "risk": "HIGH", "signals": ["geo velocity", "new ASN", "new device", "MFA prompt burst"], "decision": "Revoke sessions and force secure recovery."},
        {"name": "Anomalous model artifact", "risk": "HIGH", "signals": ["hash drift", "unexpected pickle", "new dependency", "eval regression"], "decision": "Quarantine artifact and rebuild from trusted source."},
        {"name": "Shadow AI connector", "risk": "MEDIUM", "signals": ["unapproved app", "sensitive scopes", "large prompt/context export", "unknown vendor"], "decision": "Remove connector and inspect data accessed."},
        {"name": "Secret leakage", "risk": "HIGH", "signals": ["API key pattern", "public repo", "chat export", "CI log exposure"], "decision": "Revoke secret, rotate credentials, and scan dependent systems."},
        {"name": "Malicious package/model supply chain", "risk": "HIGH", "signals": ["new package source", "obfuscated install", "model repo change", "unexpected network call"], "decision": "Block install, verify provenance, and isolate build runner."},
    ],
}


def _deep_dive(module_id: str) -> dict[str, Any]:
    base = DETAILED_MODULES.get(module_id, {})
    if not base:
        return {}
    deep = {**base}
    deep["typologies"] = [
        *(base.get("typologies") or []),
        *EXTRA_TYPOLOGIES.get(module_id, []),
    ]
    return deep


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
            {"label": "Imagery Sources", "value": 6, "tone": "ok"},
            {"label": "Event Feeds", "value": 6, "tone": "warn"},
            {"label": "Open Access", "value": "YES", "tone": "gold"},
            {"label": "OSINT CV Cues", "value": 4, "tone": "ok"},
        ]
    return [
        {"label": "Trusted Sources", "value": len(TRUSTED_SOURCES), "tone": "ok"},
        {"label": "Hotspots", "value": len([h for h in HOTSPOTS if h["module"] == module_id]), "tone": "warn"},
        {"label": "Signals", "value": "Multi", "tone": "gold"},
        {"label": "Action Mode", "value": "BLUF", "tone": "ok"},
    ]


def _module_decision(module_id: str, module: dict[str, Any], intel: Any, sanctions: Any, exposure: Any) -> dict[str, Any]:
    metrics = _module_metrics(module_id, intel, sanctions, exposure)
    hotspots = [h for h in HOTSPOTS if h["module"] == module_id]
    severe = sum(1 for h in hotspots if h["severity"] in ("HIGH", "CRITICAL"))
    source_count = len(module["sources"])
    base = {
        "cyber_defense": 92,
        "aml_finance": 88,
        "sanctions": 84,
        "supply_chain": 86,
        "geo_conflict": 89,
        "aviation_maritime": 82,
        "disasters": 78,
        "satellite_imagery": 87,
        "insider_ai": 80,
    }.get(module_id, 70)
    score = min(98, base + min(6, severe * 2) + min(4, source_count // 3))
    band = "ACT NOW" if score >= 90 else "PRIORITIZE" if score >= 75 else "WATCH" if score >= 55 else "MONITOR"
    evidence = [
        f"{source_count} trusted public sources wired into this module",
        f"{len(hotspots)} map hotspots, {severe} high/critical",
        f"Top metric: {metrics[0]['label']} = {metrics[0]['value']}",
    ]
    return {
        "title": f"{module['label']} decision score",
        "score": score,
        "band": band,
        "confidence": 78 + min(15, source_count),
        "components": {
            "mission_impact": min(98, base + severe),
            "urgency": min(96, 62 + severe * 7),
            "actionability": min(95, 70 + source_count),
        },
        "recommended_action": module["actions"][0],
        "owner": "Fusion Cell / Watch Officer",
        "time_to_action": "Immediate triage",
        "evidence": evidence,
        "score_reason": (
            f"Score {score} is based on module baseline risk ({base}), "
            f"{severe} high/critical hotspots, {source_count} trusted sources, "
            f"and the leading metric {metrics[0]['label']}={metrics[0]['value']}."
        ),
        "sources": module["sources"][:6],
        "domain": module_id,
    }


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
        "decision": _module_decision(module_id, module, intel, sanctions, exposure),
        "sources_detail": _source_details(module["sources"]),
        "hotspots": hotspots,
        "detail": detail,
        "deep_dive": _deep_dive(module_id),
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
