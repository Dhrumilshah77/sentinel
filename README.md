# SENTINEL

**Mission decision intelligence for digital defense.**

SENTINEL is a multi-domain command console built for the 3rd Annual National
Security Hackathon. It fuses public, trusted national-security data into a
single 3D operational picture that helps a commander answer:

> What is happening, where is it happening, how confident are we, what is the
> mission impact, and what action should we take first?

The system started as a cyber threat fusion dashboard and now includes
decision scoring, 3D map layers, satellite/imagery cues, sanctions and
anti-money-laundering intelligence, supply-chain risk, aviation/maritime
chokepoints, disaster overlays, insider/AI risk, and a grounded analyst chat.

```
UNCLASSIFIED // FOR OFFICIAL USE ONLY // HACKATHON DEMO
All data is public open-source intelligence. No classified data is used.
```

## Why It Matters

Military digital defense is not only a CVE problem. A real command staff has
to reason across cyber exploitation, adversary attribution, sanctions,
financial flows, logistics chokepoints, disasters, air and maritime movement,
and visual geospatial context.

SENTINEL compresses those separate workflows into one place:

- **Global monitor**: WorldMonitor-style 3D globe with operational layers.
- **Decision deck**: scored, ranked courses of action with evidence.
- **Cyber security**: CISA KEV, MITRE ATT&CK, abuse.ch IOCs, NVD, EPSS.
- **Fraud + AML**: OFAC sanctions, FBI/State wanted actors, public funding links.
- **Satellite + imagery**: NASA EONET, NASA GIBS, USGS, NOAA, Copernicus pivots.
- **Supply chain**: DoD/Army vendor stack ranked against exploited CVEs.
- **Air/sea**: chokepoints, route disruption, and public air-track context.
- **Insider + AI**: behavioral risk scoring over real labeled datasets.

## Command Decision Model

The dashboard does not only show random feeds. It produces decision products.
Each decision card includes:

- **Score**: 0-100 operational priority.
- **Band**: `ACT NOW`, `PRIORITIZE`, `WATCH`, or `MONITOR`.
- **Confidence**: how strongly the public evidence supports the assessment.
- **Components**: mission impact, urgency, and actionability.
- **Recommended COA**: a concrete next action.
- **Owner**: the staff section or team that should act.
- **Time to action**: immediate, today, 24-72h, etc.
- **Evidence**: source-backed facts used in the score.
- **Sources**: CISA, MITRE, OFAC, FBI, NASA, USGS, NOAA, and others.

Example decision products:

- Patch Microsoft before next mission window.
- Prioritize DPRK crypto-theft and sanctions watch.
- Watch Black Sea / Ukraine convergence for cyber spillover.
- Protect Suez / Red Sea logistics assumptions.
- Review imagery for live NASA/USGS/NOAA geospatial events.

## 3D Map Experience

The first screen is a 3D globe with operational layers:

- Cyber arcs
- Strategic hotspots
- Disasters
- Satellite/imagery events
- Air tracks
- AML/sanctions
- Command targets
- Labels

Map behavior:

- `+` and `-` zoom the globe.
- Manual drag/orbit or zoom stops auto-rotation.
- Hovering over map elements shows values: score, severity, source, magnitude,
  altitude, group count, and rationale.
- Clicking any marker opens the right-side dossier.
- Clicking empty globe coordinates opens a coordinate decision dossier with
  nearest hotspots, nearest mission assets, imagery pivots, and score.

## Satellite And Imagery

The satellite page uses public geospatial feeds and imagery sources:

- **NASA EONET**: live natural event geometry such as wildfires and storms.
- **NASA GIBS**: public global imagery layers such as true color and thermal anomalies.
- **USGS Earthquake Hazards**: live M4.5+ earthquake GeoJSON.
- **USGS LandsatLook**: open high-resolution imagery viewer.
- **Copernicus Browser**: Sentinel-2 imagery for ports, routes, burn scars, floods.
- **NOAA/NWS Alerts**: live weather warning polygons.

Imagery appears in three places:

- The 3D map satellite/disaster layers.
- The Satellite + Imagery page metrics and live event list.
- Imagery decision cards that recommend when to review NASA GIBS, LandsatLook,
  or Copernicus around a live event or mission area.

## Trusted Data Sources

| Domain | Sources |
|---|---|
| Cyber exploitation | CISA Known Exploited Vulnerabilities, NIST NVD, FIRST EPSS |
| Threat actors | MITRE ATT&CK Enterprise, public CISA/FBI/DoJ attribution |
| Malware IOCs | abuse.ch ThreatFox, URLhaus, Feodo, SSLBL, Spamhaus, DShield, PhishTank |
| Sanctions / AML | US Treasury OFAC SDN, FBI Cyber Most Wanted, State Dept Rewards for Justice, DoJ press releases |
| Satellite / imagery | NASA EONET, NASA GIBS, USGS Earthquake Hazards, USGS LandsatLook, Copernicus Browser, NOAA/NWS |
| Behavioral risk | NSL-KDD, CTU-13, optional CIC-IDS and CERT Insider Threat datasets |
| Live scan enrichment | GreyNoise, AbuseIPDB, Shodan, VirusTotal, AlienVault OTX, IPinfo, Pulsedive, NVD, EPSS |

All sources are public or free-tier. API-key sources are optional; the demo
still works with cached/public feeds.

## Demo Flow

Open:

```bash
http://127.0.0.1:8000/
```

Suggested 3-minute judge flow:

1. **Global Monitor**
   - Show the command decision deck.
   - Explain that SENTINEL ranks actions instead of dumping feeds.

2. **3D Map Layers**
   - Toggle Cyber, Strategic Hotspots, Satellite/Imagery, AML/Sanctions.
   - Hover a marker to show score/severity/source.
   - Click an empty coordinate to generate a coordinate dossier.

3. **Cyber Security**
   - Show top decision score.
   - Open exposure: Microsoft, Cisco, VMware, Palo Alto, Ivanti ranked by CISA KEV.
   - Show recent CVEs and live IOC sample.

4. **Fraud + AML**
   - Show OFAC totals, wanted actors, bounty totals, and public funding links.
   - Pivot to DPRK / Lazarus crypto-theft risk.

5. **Satellite + Imagery**
   - Show NASA/USGS/NOAA live geospatial events.
   - Open imagery layer cards for NASA GIBS, USGS LandsatLook, Copernicus.
   - Explain how imagery becomes a decision cue, not decoration.

6. **Analyst Chat / Briefing**
   - Ask: `what should we prioritize first?`
   - Generate BLUF-style commander briefing.

## Architecture

```text
SENTINEL UI
  3D globe, layer controls, decision deck, dossiers, analyst chat
       |
       | REST + WebSocket
       v
FastAPI server
  /monitor/global       global decision deck and map layers
  /monitor/satellite    satellite/imagery events and decision cues
  /monitor/geo          clicked-coordinate decision dossier
  /mission/*            mission pages and hotspots
  /intel/*              MITRE, CISA, IOC search and actor dossiers
  /sanctions/*          OFAC, wanted actors, funding links
  /exposure             DoD-stack vendor exposure
  /live/scan            defensive OSINT enrichment
  /chat                 grounded analyst assistant
       |
       v
Core engines
  monitor.py            command decision model and geo scoring
  mission.py            mission-domain catalog and page payloads
  intel.py              CISA KEV + MITRE ATT&CK + IOCs
  sanctions.py          OFAC + FBI/State/DoJ curated public intelligence
  exposure.py           DoD vendor stack x CISA KEV
  scorer.py             behavioral anomaly and supervised risk engine
```

## Repository Layout

```text
sentinel/
├── api/server.py             FastAPI application and endpoints
├── core/
│   ├── monitor.py            global monitor, decision deck, geo scoring, imagery cues
│   ├── mission.py            mission pages, trusted sources, hotspots
│   ├── intel.py              CISA KEV + MITRE ATT&CK + IOC fusion
│   ├── sanctions.py          OFAC SDN + wanted actors + funding links
│   ├── exposure.py           DoD/Army vendor stack exposure scoring
│   ├── live.py               live defensive OSINT scan fan-out
│   ├── scorer.py             behavioral risk scoring
│   ├── loaders.py            NSL-KDD, CTU-13, CIC-IDS, CERT loaders
│   └── chat.py               grounded analyst chat
├── ui/index.html             no-build frontend with globe.gl / Three.js
├── feeds/pull_open_feeds.py  abuse.ch, Spamhaus, DShield, PhishTank pullers
├── mitre/pull_attack.py      MITRE ATT&CK STIX puller
├── datasets/download.sh      NSL-KDD, CTU-13, CISA KEV downloader
├── bootstrap.sh              optional project bootstrap
├── requirements.txt
└── README.md
```

## Quickstart

```bash
git clone https://github.com/Dhrumilshah77/sentinel.git
cd sentinel

python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# Pull public feeds and datasets if they are not already present.
python feeds/pull_open_feeds.py
python mitre/pull_attack.py
./datasets/download.sh

uvicorn api.server:app --host 127.0.0.1 --port 8000
```

Then open:

```text
http://127.0.0.1:8000/
```

Notes:

- The first server boot fits the local behavioral model and can take about a minute.
- Optional API keys can be placed in `.env` for Shodan, VirusTotal, OTX, etc.
- Never commit `.env` or API keys.

## Key Endpoints

```text
GET  /monitor/global?live=true        Decision deck + global map layers
GET  /monitor/satellite               Satellite/imagery decision cues
GET  /monitor/geo?lat=...&lng=...     Clicked-coordinate decision dossier
GET  /mission/summary                 Mission pages and source catalog
GET  /mission/module/{id}             Cyber, AML, sanctions, supply chain, etc.
GET  /mission/hotspot/{id}            Hotspot dossier
GET  /intel/summary                   Cyber source summary
GET  /intel/search?q=...              Search CISA/MITRE/IOCs
GET  /sanctions/search?q=...          Search OFAC/wanted actors
GET  /exposure                        DoD vendor exposure ranking
GET  /live/scan?q=...                 Defensive OSINT enrichment
POST /intel/briefing                  Commander BLUF
POST /chat                            Analyst chat
```

## Safety Boundaries

SENTINEL is defensive and analytical:

- It enriches indicators through public OSINT.
- It ranks exposure and recommends hardening actions.
- It does not automate intrusion, exploitation, credential theft, malware,
  persistence, or access to third-party systems.
- Live scan should be used only for owned or authorized indicators.

## Judging Alignment

| Criterion | SENTINEL Evidence |
|---|---|
| Technical Demo | Real data ingestion, 3D globe layers, decision deck, coordinate scoring, live public APIs, analyst chat |
| Military Impact | Compresses cyber, sanctions, imagery, logistics, and disaster awareness into command decisions |
| Creativity | Blends WorldMonitor-style global monitoring with cyber fusion and mission scoring |
| Presentation | Click-driven flow: global score, map layer, hotspot, coordinate dossier, action |

## Current Limitations

- This is a hackathon prototype, not an accredited DoD system.
- Imagery sources are public viewers/tile services, not classified imagery.
- Some live APIs are best-effort and may fail on venue Wi-Fi.
- External paid/free-tier API keys improve enrichment but are optional.

## License

MIT.

## Credits

Built by Dhrumil Shah for the 3rd Annual National Security Hackathon, San
Francisco, May 2026, sponsored by the United States Army.

Public-source feeds remain the property of their original agencies and
maintainers. SENTINEL is a fusion, scoring, and decision-support layer.
