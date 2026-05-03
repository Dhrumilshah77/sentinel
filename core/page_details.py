"""Rich page-level details for SENTINEL mission pages."""
from __future__ import annotations

from typing import Any


MODULE_SLUGS: dict[str, str] = {
    "cyber_defense": "cyber-security",
    "geo_conflict": "threat-intelligence",
    "aml_finance": "fraud-aml",
    "sanctions": "sanctions-screening",
    "supply_chain": "supply-chain",
    "aviation_maritime": "air-maritime",
    "disasters": "disaster-response",
    "satellite_imagery": "satellite-imagery",
    "insider_ai": "insider-ai",
}

SLUG_MODULES = {v: k for k, v in MODULE_SLUGS.items()}


PAGE_EXPANSIONS: dict[str, dict[str, Any]] = {
    "cyber_defense": {
        "title": "Cyber Security Command Page",
        "mission_question": "Which mission systems are most likely to be exploited next, why, and what defensive action should be taken first?",
        "subdomains": [
            "External attack surface", "CISA KEV patch priority", "Ransomware pre-positioning", "Identity compromise",
            "Cloud control-plane abuse", "SaaS OAuth abuse", "Phishing/BEC", "DDoS continuity",
            "OT/ICS exposure", "AI/model deployment hardening", "Supply-chain package compromise", "Data exfiltration",
            "Edge appliance exploitation", "Threat hunting", "Evidence preservation",
        ],
        "minute_checks": [
            {"check": "Internet-facing KEV", "fields": "asset, product, CVE, KEV date, EPSS, ransomware flag, owner", "decision": "Patch/isolate before ordinary change window."},
            {"check": "Identity blast radius", "fields": "new device, MFA events, impossible travel, privilege delta, OAuth scopes", "decision": "Revoke sessions and inspect admin paths."},
            {"check": "IOC-to-host hunt", "fields": "domain/IP/hash, malware family, first_seen, host count, DNS/proxy hits", "decision": "Block, hunt peer hosts, preserve logs."},
            {"check": "Cloud exfil path", "fields": "new key, storage read volume, snapshot export, rare region, security group", "decision": "Rotate keys, lock storage, review IAM."},
            {"check": "AI artifact drift", "fields": "model hash, base image, package delta, eval delta, signer", "decision": "Quarantine model/container until rebuilt from trusted baseline."},
            {"check": "Ransomware staging", "fields": "backup deletion, remote admin tool, mass enumeration, domain admin use", "decision": "Segment, disable compromised accounts, activate continuity."},
        ],
        "score_rubric": [
            "30% mission criticality: command, sensor, comms, logistics, or AI deployment dependency.",
            "25% active exploitation: KEV, EPSS, ransomware-used, and live IOC overlap.",
            "20% actor intent: MITRE-linked country/sector targeting and public attribution.",
            "15% exposure: internet reachability, identity path, or vendor blast radius.",
            "10% control gap: missing MFA, weak segmentation, stale patch, weak logging.",
        ],
        "operator_outputs": [
            "Commander BLUF: act/watch/monitor score with reason.",
            "Patch list: CVE, product, owner, due date, ransomware flag.",
            "Hunt packet: IOC, malware, ATT&CK technique, affected hosts.",
            "Containment checklist: isolate, revoke, rotate, preserve, verify.",
        ],
    },
    "aml_finance": {
        "title": "Fraud + AML Intelligence Page",
        "mission_question": "Which transaction, identity, wallet, counterparty, or entity pattern looks like fraud, laundering, sanctions evasion, or cybercrime funding?",
        "subdomains": [
            "First-party fraud", "Third-party fraud", "Account takeover", "Card-not-present fraud",
            "Card-present/skimming", "ACH fraud", "Wire fraud", "Check fraud", "Synthetic identity",
            "Mule networks", "BEC invoice diversion", "Payroll diversion", "SIM-swap ATO",
            "Pig-butchering and romance scams", "Crypto investment fraud", "Ransomware cashout",
            "Mixer and bridge exposure", "Peeling/layering chains", "Merchant fraud",
            "Refund/chargeback abuse", "Promo abuse", "Bust-out fraud", "Loan stacking",
            "Elder exploitation", "PEP screening", "OFAC sanctions", "Trade-based laundering",
            "Beneficial ownership concealment",
        ],
        "minute_checks": [
            {"check": "CNP fraud", "fields": "card, BIN, AVS/CVV, device, IP geo, shipping, velocity, chargeback history", "decision": "Step-up auth or hold fulfillment."},
            {"check": "ATO transfer", "fields": "password reset, new device, beneficiary age, SIM swap, impossible travel, amount velocity", "decision": "Hold transfer and contact verified owner."},
            {"check": "Mule cluster", "fields": "inbound victims, outbound wires, shared device/IP, account age, rapid cashout", "decision": "Freeze hub accounts and create graph evidence packet."},
            {"check": "Crypto laundering", "fields": "wallet, exchange hops, bridge/mixer exposure, peel chain depth, sanctions proximity", "decision": "Flag wallet/counterparty and escalate SAR-style review."},
            {"check": "BEC diversion", "fields": "vendor bank change, lookalike domain, mailbox rule, invoice language drift", "decision": "Verify out-of-band and pivot to cyber."},
            {"check": "PEP/sanctions", "fields": "name, alias, program, country, ownership edge, adverse media, official role", "decision": "Enhanced due diligence or block/review."},
            {"check": "Trade-based laundering", "fields": "invoice mismatch, dual-use goods, transshipment, shell entity, port risk", "decision": "Link to sanctions and supply-chain pages before release."},
        ],
        "score_rubric": [
            "25% sanctions/PEP exposure: direct hit, alias, ownership proximity, country/program risk.",
            "20% velocity anomaly: sudden transfer, many small payments, rapid cashout, unusual timing.",
            "20% device/account anomaly: new device, SIM swap, impossible travel, credential reset.",
            "20% graph proximity: mule hubs, mixers, nested exchanges, sanctioned actors, known fraud rings.",
            "15% source-of-funds uncertainty: thin KYC, shell entity, trade mismatch, unexplained crypto ramp.",
        ],
        "operator_outputs": [
            "Fraud disposition: approve, step-up, hold, freeze, or escalate.",
            "AML packet: identity, counterparty, typology, graph path, evidence, source list.",
            "Money-flow diagram: victim -> mule -> exchange -> peel chain -> mixer/bridge -> cashout.",
            "Reason code: the exact fields that moved the score.",
        ],
    },
    "sanctions": {
        "title": "Sanctions + Entity Screening Page",
        "mission_question": "Is this person, company, vessel, wallet, or procurement path directly or indirectly exposed to sanctioned actors?",
        "subdomains": ["OFAC SDN", "aliases", "transliteration", "beneficial ownership", "front companies", "vessel evasion", "PEPs", "adverse media", "dual-use goods", "cyber actor designations"],
        "minute_checks": [
            {"check": "Direct entity match", "fields": "name, alias, DOB, address, country, program", "decision": "Block or legal review depending on confidence."},
            {"check": "Ownership proximity", "fields": "parent, director, nominee, address reuse, shell company", "decision": "Escalate indirect exposure review."},
            {"check": "Vessel evasion", "fields": "IMO, MMSI, AIS gap, flag change, STS transfer, port call", "decision": "Pivot to Air/Sea and AML."},
            {"check": "Procurement evasion", "fields": "dual-use part, end user, transshipment, broker, destination", "decision": "Hold shipment and validate end use."},
        ],
        "score_rubric": ["30% direct list match", "25% ownership proximity", "20% cyber/public attribution", "15% jurisdiction risk", "10% analyst confidence"],
        "operator_outputs": ["Entity-resolution packet", "Ownership graph", "Vessel/procurement watch note", "Block/review recommendation"],
    },
    "supply_chain": {
        "title": "Supply Chain Risk Page",
        "mission_question": "Which vendor, route, port, package, cloud region, or supplier dependency can break mission continuity?",
        "subdomains": ["vendor KEV exposure", "SBOM drift", "dependency confusion", "counterfeit components", "single-source suppliers", "cloud region outage", "ports", "canals", "weather disruption", "sanctions-linked procurement"],
        "minute_checks": [
            {"check": "Vendor exposure", "fields": "vendor, product, KEV count, ransomware count, mission owner", "decision": "Patch/isolate the highest mission dependency first."},
            {"check": "SBOM drift", "fields": "package, registry, version, hash, maintainer, install script", "decision": "Freeze release and rebuild from known-good source."},
            {"check": "Route disruption", "fields": "port, canal, storm, conflict zone, lead time, alternate route", "decision": "Update sustainment ETA and alternate routing."},
            {"check": "Supplier concentration", "fields": "tier, geography, replacement time, contract status, inventory", "decision": "Stage buffer or alternate supplier."},
        ],
        "score_rubric": ["30% mission criticality", "25% active exploit exposure", "20% route/chokepoint risk", "15% supplier concentration", "10% recovery time"],
        "operator_outputs": ["Top vendor list", "SBOM drift report", "Route impact note", "Alternate supplier/port recommendation"],
    },
    "geo_conflict": {
        "title": "Threat + Geopolitical Intelligence Page",
        "mission_question": "Where do conflict, cyber, sanctions, logistics, disasters, and media signals converge into a decision risk?",
        "subdomains": ["regional conflict", "cyber spillover", "sanctions retaliation", "military mobilization", "influence operations", "energy chokepoints", "EW/GPS interference", "humanitarian pressure", "critical infrastructure"],
        "minute_checks": [
            {"check": "Conflict-cyber convergence", "fields": "region, actor country, APT groups, sectors, sanctions, infrastructure", "decision": "Raise monitoring on logistics, comms, suppliers."},
            {"check": "Chokepoint escalation", "fields": "route, port, energy flow, conflict proximity, media spike", "decision": "Pivot Air/Sea and Supply Chain."},
            {"check": "Influence operation", "fields": "narrative, source country, repetition, timing, phishing overlap", "decision": "Separate influence signal from confirmed intrusion."},
        ],
        "score_rubric": ["25% conflict severity", "20% actor cyber capability", "20% mission proximity", "20% sanctions/economic pressure", "15% live signal convergence"],
        "operator_outputs": ["Regional BLUF", "Actor/country map", "Chokepoint warning", "Cross-domain risk explanation"],
    },
    "aviation_maritime": {
        "title": "Air + Maritime Tracking Page",
        "mission_question": "Which public air, maritime, port, chokepoint, or navigation signal affects mission movement and logistics?",
        "subdomains": ["OpenSky aircraft", "AIS/dark shipping", "ship-to-ship transfer", "port congestion", "airspace closure", "ADS-B anomalies", "GNSS jamming", "drone/UAS corridors", "sanctioned vessels", "route disruption"],
        "minute_checks": [
            {"check": "Air track anomaly", "fields": "callsign, icao24, altitude, velocity, origin, route, dropout", "decision": "Use as watch cue; corroborate before attribution."},
            {"check": "Dark vessel", "fields": "IMO/MMSI, AIS gap, flag, port calls, STS proximity, sanctions", "decision": "Pivot sanctions and AML entity graph."},
            {"check": "Port/chokepoint disruption", "fields": "queue, event, weather, conflict, route dependency", "decision": "Prepare alternate-route impact note."},
        ],
        "score_rubric": ["25% chokepoint criticality", "20% live disruption", "20% route dependency", "20% conflict proximity", "15% navigation integrity"],
        "operator_outputs": ["Track cue list", "Port/chokepoint status", "Navigation confidence note", "Sanctions/vessel pivot"],
    },
    "disasters": {
        "title": "Disaster + Infrastructure Response Page",
        "mission_question": "Which natural event can degrade power, comms, logistics, cyber response, or mission assets?",
        "subdomains": ["earthquake", "wildfire", "flood", "cyclone", "heat", "drought", "volcano/ash", "space weather", "infrastructure cascade", "route degradation"],
        "minute_checks": [
            {"check": "Earthquake impact", "fields": "magnitude, depth, PAGER, distance to asset, route overlap", "decision": "Assess facilities, routes, comms fallback."},
            {"check": "Wildfire/thermal", "fields": "EONET, VIIRS thermal, smoke, power proximity, evacuation route", "decision": "Open imagery triage and logistics impact."},
            {"check": "Storm/flood", "fields": "NOAA alert, IMERG, GDACS, port/road overlap", "decision": "Prepare sustainment and mobility options."},
        ],
        "score_rubric": ["25% event severity", "25% mission proximity", "20% infrastructure dependence", "15% duration", "15% confidence"],
        "operator_outputs": ["Facility impact list", "Imagery cue", "Route degradation note", "Continuity action"],
    },
    "satellite_imagery": {
        "title": "Satellite Imagery + Geo Prediction Page",
        "mission_question": "What does public imagery and geospatial event data suggest about activity, damage, mobility, visibility, and military/logistics relevance?",
        "subdomains": ["NASA GIBS true color", "VIIRS thermal", "IMERG precipitation", "smoke/aerosol", "USGS LandsatLook", "Copernicus Sentinel-2", "airfield/port activity cue", "convoy/logistics cue", "burn scar", "flood extent", "construction/change detection", "night-lights power anomaly"],
        "minute_checks": [
            {"check": "Thermal anomaly", "fields": "VIIRS/MODIS layer, EONET event, industrial/route proximity, smoke", "decision": "Compare thermal and true-color imagery."},
            {"check": "Flood/mobility", "fields": "IMERG, NOAA/GDACS alert, river/coast, road/port overlap", "decision": "Mark route degradation and alternate paths."},
            {"check": "Military/logistics relevance", "fields": "hotspot distance, asset distance, port/airfield proximity, live events", "decision": "Human imagery review before any operational conclusion."},
            {"check": "Change cue", "fields": "current preview, historical source, construction/yard pattern, cloud cover", "decision": "Queue before/after review in NASA/USGS/Copernicus."},
        ],
        "score_rubric": ["25% live event proximity", "25% strategic hotspot proximity", "20% mission asset proximity", "20% imagery-layer availability", "10% confidence"],
        "operator_outputs": ["Imagery preview", "Prediction score", "Nearby event list", "Human review caveat", "Pivot to route/asset/hotspot"],
    },
    "insider_ai": {
        "title": "Insider Threat + AI Security Page",
        "mission_question": "Which user, device, data movement, model artifact, or AI connector creates unacceptable insider or AI deployment risk?",
        "subdomains": ["UEBA", "data staging", "privilege misuse", "impossible travel", "secret leakage", "shadow AI connectors", "prompt/data exfil", "model hash drift", "container tampering", "malicious package/model supply chain"],
        "minute_checks": [
            {"check": "Data staging", "fields": "file count, bytes out, time, sensitivity, destination", "decision": "Preserve logs and restrict movement."},
            {"check": "Privilege misuse", "fields": "admin action, service account, repo/model access, policy change", "decision": "Require peer review and revoke excess privilege."},
            {"check": "Model tampering", "fields": "hash, dependency, base image, eval delta, signer", "decision": "Quarantine artifact and rebuild."},
            {"check": "Secret leakage", "fields": "key pattern, repo/chat/CI exposure, service dependency", "decision": "Revoke, rotate, and scan dependent systems."},
        ],
        "score_rubric": ["30% behavior anomaly", "25% data sensitivity", "20% privilege level", "15% model/artifact drift", "10% repeat history"],
        "operator_outputs": ["User/entity score", "Artifact verification result", "DLP/secret action", "Human approval gate"],
    },
}


SATELLITE_TARGETS: list[dict[str, Any]] = [
    {"name": "Taiwan Strait", "lat": 24.0, "lng": 121.0, "score": 91, "prediction": "Strategic activity relevance high: maritime, air, cyber, and semiconductor supply-chain signals converge."},
    {"name": "Black Sea / Ukraine", "lat": 46.5, "lng": 32.2, "score": 94, "prediction": "Conflict + port + cyber spillover relevance high; compare true-color, smoke, and weather layers."},
    {"name": "Red Sea / Bab el-Mandeb", "lat": 12.6, "lng": 43.3, "score": 92, "prediction": "Chokepoint and shipping disruption likelihood high; track port, route, and AIS/dark-shipping cues."},
    {"name": "Pentagon / DC Region", "lat": 38.871, "lng": -77.056, "score": 86, "prediction": "Mission asset proximity high; use imagery for disaster/weather/infrastructure context, not classified surveillance."},
    {"name": "Strait of Hormuz", "lat": 26.56, "lng": 56.25, "score": 93, "prediction": "Energy chokepoint relevance high; monitor maritime, weather, and geopolitical escalation signals."},
    {"name": "Suez Canal", "lat": 30.04, "lng": 32.55, "score": 88, "prediction": "Supply-chain chokepoint risk high; imagery supports route and congestion context."},
]
