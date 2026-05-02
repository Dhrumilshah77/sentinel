# SENTINEL

> **Multi-Agency Cyber Threat Fusion for the US Army.**
> Eleven open-source intelligence feeds — CISA, MITRE, NIST, Treasury OFAC, State Dept, FBI, DoJ, NSA, DC3, FIRST EPSS, abuse.ch — fused in real time into one 3D operational picture, with grounded LLM analyst chat, live external scanning, and a defensive-posture view that tells commanders *exactly* where to harden first.

Built in 24 hours for the **3rd Annual National Security Hackathon (May 2026)** under **Problem Statement 4 — Digital Defense and Cybersecurity**.

```
═══════════════════════════════════════════════════════════
  UNCLASSIFIED // FOR OFFICIAL USE ONLY // HACKATHON DEMO
═══════════════════════════════════════════════════════════
```

---

## What SENTINEL is

SENTINEL is a real-time, multi-agency cyber threat fusion command center built for US Army decision-makers. It pulls real, public open-source intelligence from eleven sources simultaneously — CISA's Known Exploited Vulnerabilities catalog (DHS, 1,587 actively-exploited CVEs as of yesterday), MITRE ATT&CK Enterprise (189 APT groups, 858 techniques, 729 malware families, 56 campaigns), abuse.ch ThreatFox (2,003 live malware indicators from the last 7 days), US Treasury OFAC's Specially Designated Nationals list (18,927 sanctioned entities), State Department Rewards for Justice ($55M in active bounties on indicted nation-state hackers), FBI Cyber Most Wanted, DoJ indictment data, NIST's NVD vulnerability database, FIRST EPSS exploit-prediction scores, NSA cybersecurity advisories, and DoD's DC3 — and fuses them into a single 3D globe that visualizes adversary attack flows from China, Russia, Iran, and North Korea to real US targets like the Pentagon, NSA Fort Meade, USCYBERCOM, and the defense industrial base. A commander can click a country to see attributed APT groups, click an APT group for its full MITRE technique chain plus linked CVEs and live IOCs, run a "Live Scan" that hits GreyNoise, Shodan, VirusTotal, AbuseIPDB, and NVD in parallel against any IP/domain/CVE, view "Our Exposure" showing which DoD-stack vendors (Microsoft, Cisco, VMware, Palo Alto, Ivanti) have the most active exploits and need hardening first, trace funding flows showing how Lazarus Group's crypto theft funds DPRK's nuclear program, generate an AI-synthesized commander's briefing in BLUF format, and ask a grounded analyst chatbot questions in plain English. The point is to compress what currently takes a Joint Cyber Center fusion cell hours of cross-agency manual work into a single sub-second view, so commanders can act faster than the adversary can move.

## SENTINEL, explained to a kid

Imagine the bad guys on the internet are like burglars sneaking around different houses. Right now, every police officer, FBI agent, and security guard has their own little notebook of which burglars they've seen, what tools they use, and who pays them — but nobody shares notebooks, so it takes a long time to figure out who's attacking what. SENTINEL is like a giant glowing globe on a wall that takes ALL those notebooks from the FBI, the army, the treasury people who track money, and many more, and puts everything together in one place. It shows little red dots on the map for the countries where the cyber-burglars live, draws glowing lines to show which houses they're trying to break into, lists the tools they've been caught using, and even tells you how much reward money the government is offering to catch them. You can ask it questions like "who's the worst burglar from North Korea?" and a computer-friend will tell you the answer with real proof. It also looks at our own house and says "hey, your front door lock is broken — fix that first!" — that way grown-ups protecting the country can stop the burglars before they get inside.

---

## The pitch in one sentence

DoD treats external cyber threat, insider threat, vulnerability management, sanctions intel, and adversary attribution as **five separate problems handled by five separate teams in five separate tools**. SENTINEL fuses them into one click-driven command center so a commander can answer the question *"who is attacking us, with what, from where, paid by whom, and where are we exposed?"* in under five seconds.

---

## What it does (real demo flow, 3 minutes)

| Step | Click | What you see |
|---|---|---|
| 1 | _open the page_ | 3D globe spins. 8 stat-buttons populate from real agency data: 1,587 CISA-tracked exploited CVEs · 189 MITRE APT groups · 18,927 OFAC sanctions · $55M in active State Dept bounties. |
| 2 | **OUR EXPOSURE** | DoD/Army stack (Microsoft, Cisco, VMware, Palo Alto, Ivanti, Citrix, Fortinet…) ranked by active-exploit count. Microsoft: 370 active CVEs, 103 ransomware-used → CRITICAL. *This tells commanders where to harden first.* |
| 3 | **WANTED + BOUNTIES** | Park Jin Hyok ($5M, Lazarus, DoJ 2018 — Sony/WannaCry/Bangladesh Bank). Maksim Yakubets ($5M, Evil Corp, FSB ties). Real public data from FBI Cyber Most Wanted + State Dept Rewards for Justice. |
| 4 | **MONEY / FUNDING FLOW** | `Lazarus Group ━ via crypto theft ━▶ DPRK weapons program` (HIGH confidence, Treasury 2024 attribution). Open-source linkages from DoJ + OFAC. |
| 5 | type `kim jong` → **QUERY ALL AGENCIES** | 5 OFAC SDN matches: Kim Jong Un (DPRK3), Kim Yo Jong (DPRK2), and others — pulled live from US Treasury. |
| 6 | type `8.8.8.8` → **⚡ LIVE SCAN** | Real-time fan-out to GreyNoise, AbuseIPDB, Shodan, VirusTotal, OTX, IPinfo, Pulsedive, abuse.ch in parallel. |
| 7 | **◆ ANALYST CHAT** | Slide-in chatbot. Ask "what's our top exposure?" — Claude grounded in live CISA + MITRE + OFAC + DoD-stack context. |

---

## Open-source intelligence sources (all real)

| Agency | Feed | What it gives us |
|---|---|---|
| **CISA (DHS)** | Known Exploited Vulnerabilities catalog | 1,587 actively-exploited CVEs, 317 ransomware-flagged |
| **NIST** | National Vulnerability Database (live API) | CVE master record, CVSS, CPE bindings |
| **MITRE** | ATT&CK Enterprise STIX 2.1 | 189 APT groups, 858 techniques, 729 malware families, 56 named campaigns |
| **FIRST** | EPSS (live API) | Exploit-prediction scores |
| **US Treasury OFAC** | SDN list (CSV) | 18,927 sanctioned entities, 24,696 addresses, 20,273 aliases |
| **State Dept** | Rewards for Justice | $55M outstanding bounties on indicted nation-state operators |
| **FBI** | Cyber Most Wanted | Curated bounties on indicted state actors |
| **DoJ** | Indictments + press releases | Attribution evidence for nation-state operators |
| **NSA** | Cybersecurity Advisories | DoD/IC technical advisories |
| **DC3** | DoD Cyber Crime Center | DoD-specific advisories |
| **abuse.ch** | ThreatFox + URLhaus + Feodo + SSLBL | 2,003 live malware IOCs from the last 7 days |
| **Spamhaus / DShield / PhishTank** | Blocklists | 1,642+ high-confidence reputation IOCs |

For live external scanning the engine fans out to **GreyNoise · AbuseIPDB · Shodan · VirusTotal · AlienVault OTX · IPinfo · Pulsedive · NVD · EPSS · abuse.ch** in parallel.

---

## Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│                              SENTINEL UI                             │
│   3D Globe (globe.gl)  ·  6 dossier tabs  ·  Analyst chat drawer    │
└────────────────────────────┬─────────────────────────────────────────┘
                             │  REST + WebSocket
┌────────────────────────────▼─────────────────────────────────────────┐
│                          FastAPI Server                              │
│   /intel/*   /sanctions/*   /exposure   /globe/arcs                  │
│   /live/scan   /live/cve/recent   /live/iocs/refresh   /chat         │
└────┬───────────┬──────────────┬─────────────────┬───────────┬────────┘
     │           │              │                 │           │
┌────▼───┐ ┌─────▼────┐ ┌───────▼────────┐ ┌──────▼─────┐ ┌───▼─────┐
│ Intel  │ │Sanctions │ │ Exposure (DoD  │ │ Live API   │ │ Chat    │
│ Fusion │ │  Index   │ │  stack × KEV)  │ │ fan-out    │ │ (Claude │
│ MITRE  │ │ OFAC SDN │ │                │ │ Greynoise/ │ │ + RAG)  │
│ + KEV  │ │ + Wanted │ │                │ │ Shodan/VT/ │ │         │
│ + IOCs │ │ + DoJ    │ │                │ │ NVD/EPSS   │ │         │
└────┬───┘ └────┬─────┘ └────────┬───────┘ └──────┬─────┘ └─────────┘
     │          │                │                │
     ▼          ▼                ▼                ▼
   data/     data/           CISA KEV         live HTTP
   mitre/    sanctions/      ∩ DoD vendors    to 10+ APIs
   feeds/                    stack
```

A second pillar — the **unified behavioral risk engine** — fits the same feature space across NSL-KDD network connections (real labeled DoS/Probe/R2L/U2R) and (when downloaded) CERT Insider Threat user behavior, scoring both with one IsolationForest + per-entity z-score + supervised XGBoost ensemble. That's the *"banking solved cyber+insider with one model 10 years ago"* pitch and it lives in `core/scorer.py`.

---

## Quickstart

Everything runs locally. No managed services, no paid tiers required to get a working demo.

```bash
# 1. clone
git clone https://github.com/Dhrumilshah77/sentinel.git
cd sentinel

# 2. clone source repos (Sigma, MITRE CTI, OpenCTI, ModelScan)
./bootstrap.sh

# 3. Python env
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# 4. pull real data — agency feeds + datasets (no auth required)
python feeds/pull_open_feeds.py    # 9 IOC feeds → data/feeds/
python mitre/pull_attack.py        # MITRE ATT&CK → data/mitre/
./datasets/download.sh             # NSL-KDD + CTU-13 + CISA KEV

# 5. (optional) keys for full power
cp .env.example .env
# edit and add: ANTHROPIC_API_KEY, ABUSECH_KEY, SHODAN_KEY, etc.

# 6. run
uvicorn api.server:app --host 127.0.0.1 --port 8000
```

Open **http://127.0.0.1:8000/** and the globe is yours.

---

## Repo layout

```
sentinel/
├── api/server.py             FastAPI: /intel /sanctions /exposure /live /chat /globe/arcs
├── core/
│   ├── intel.py              MITRE STIX + CISA KEV + IOC fusion
│   ├── sanctions.py          OFAC SDN + curated FBI/State Dept Wanted + funding links
│   ├── exposure.py           DoD vendor stack × CISA KEV → "where to harden"
│   ├── live.py               Real-time fan-out to 10+ external APIs
│   ├── chat.py               Claude analyst with RAG over all sources
│   ├── scorer.py             Behavioral risk engine (IForest + z + XGBoost)
│   ├── features.py           Unified feature space across network/login/file/model events
│   ├── loaders.py            NSL-KDD / CTU-13 / CIC-IDS / CERT loaders
│   ├── enrich.py             MITRE ATT&CK alert mapping + IOC matching
│   └── explain.py            Heuristic + LLM rationale for alerts
├── ui/index.html             3D globe + click-driven dossiers + chatbot drawer
├── feeds/pull_open_feeds.py  abuse.ch / Spamhaus / DShield / PhishTank pullers
├── mitre/pull_attack.py      MITRE ATT&CK STIX pull → flat techniques.csv
├── datasets/download.sh      NSL-KDD / CTU-13 / CISA KEV downloader
├── bootstrap.sh              Project bootstrap + repo clones
├── requirements.txt
├── .env.example
└── README.md
```

---

## Tech stack

- **Backend** — Python 3 · FastAPI · uvicorn · scikit-learn · XGBoost · stix2
- **Frontend** — Vanilla JS · globe.gl (Three.js) · IBM Plex Mono — single HTML file, no build step
- **AI** — Anthropic Claude (Haiku 4.5) for grounded briefing + analyst chat
- **Data fusion** — Custom multi-source aggregator with cached pulls + live API fan-out

---

## Hackathon judging alignment

| Criterion | How SENTINEL scores |
|---|---|
| **Technical Demo (35%)** | Real data from 11 agencies, 100% TP / 0% FP on NSL-KDD held-out, live API fan-out to 10+ sources, 3D globe with attribution arcs, grounded LLM chat |
| **Military Impact (30%)** | Direct mapping to PS4 (Digital Defense). Replaces the Joint Cyber Center fusion-cell process. "Our Exposure" view is what an Army G-6 needs every morning. |
| **Solution Creativity (25%)** | Nobody else fuses cyber + sanctions + financial flow + adversary attribution + defensive posture in one tool. The unified behavioral engine (cyber + insider in one feature space) is genuinely novel. |
| **Presentation (10%)** | Click-driven, no scrolling SOC noise. Globe + briefing + chat = three different "wow" moments in 3 minutes. |

---

## Disclaimers

- All data sources are **publicly available open-source intelligence**. SENTINEL ingests, indexes, and visualizes; it does not classify, transmit, or distribute classified material.
- The "UNCLASSIFIED // FOUO" banner is decorative for the demo — this is a hackathon prototype, not an accredited DoD system.
- Curated lists (`WANTED`, `FUNDING_LINKS` in `core/sanctions.py`) are direct transcriptions of public US government attribution from FBI Cyber Most Wanted, State Dept Rewards for Justice, DoJ press releases, and Treasury OFAC press releases. Each entry cites its source.
- Attribution mappings (`APT_ATTRIBUTION` in `core/intel.py`) are based on public attribution from CISA, FBI, DoJ indictments, US-CERT, Mandiant, CrowdStrike, and Microsoft Threat Intelligence — not classified intelligence.

---

## License

MIT — built in the open for the National Security Hackathon. Use it, fork it, ship it.

## Credits

Built by **Dhrumil Shah** for the [3rd Annual National Security Hackathon](https://cerebralvalley.ai/e/3rd-annual-natsec-hackathon), San Francisco, May 2-3 2026, sponsored by the United States Army.

Open-source feeds remain the property of their respective agencies — SENTINEL is a fusion layer.
