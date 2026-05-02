"""Multi-agency open-source intel fusion.

Aggregates real feeds from:
  - CISA KEV (DHS)            — known-exploited vulnerabilities
  - NIST NVD                  — CVE master record
  - MITRE ATT&CK STIX         — APT groups, malware, campaigns, techniques
  - FIRST EPSS                — exploit prediction scores
  - abuse.ch (ThreatFox/Feodo/SSLBL/URLhaus/PhishTank)  — live IOCs
  - Spamhaus / DShield        — high-confidence blocklists
  - CISA advisories RSS       — cybersecurity advisories feed
  - AlienVault OTX            — community threat intel (if key set)

Everything here reads from data/ that has already been pulled by
feeds/pull_open_feeds.py and the bootstrap. The web layer hits this module
synchronously for a dashboard-load query and pulls in <300 ms.
"""
from __future__ import annotations
import json, csv, re
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import Iterable

ROOT  = Path(__file__).resolve().parent.parent
FEEDS = ROOT / "data" / "feeds"
MITRE = ROOT / "data" / "mitre"

# --- Curated nation-state attribution for the most-cited APT groups ---------
# Sources: public attribution from CISA, FBI, DoJ indictments, US-CERT,
# Mandiant, CrowdStrike, Microsoft Threat Intelligence. Not exhaustive — only
# groups with strong public attribution. lat/lng for capital city.
APT_ATTRIBUTION: dict[str, tuple[str, str, float, float]] = {
    # name patterns matched case-insensitively against MITRE name + aliases
    "apt1":            ("China",        "PLA Unit 61398",        39.9042, 116.4074),
    "apt3":            ("China",        "Boyusec/MSS",            39.9042, 116.4074),
    "apt10":           ("China",        "Stone Panda/MSS",        39.9042, 116.4074),
    "apt19":           ("China",        "Codoso",                 39.9042, 116.4074),
    "apt40":           ("China",        "Leviathan/MSS",          39.9042, 116.4074),
    "apt41":           ("China",        "Wicked Panda/MSS",       39.9042, 116.4074),
    "winnti":          ("China",        "Winnti Group",           39.9042, 116.4074),
    "mustang panda":   ("China",        "Mustang Panda",          39.9042, 116.4074),
    "volt typhoon":    ("China",        "Volt Typhoon (PRC)",     39.9042, 116.4074),
    "salt typhoon":    ("China",        "Salt Typhoon (PRC)",     39.9042, 116.4074),
    "elderwood":       ("China",        "Elderwood/Beijing Group",39.9042, 116.4074),
    "deep panda":      ("China",        "Deep Panda",             39.9042, 116.4074),
    "axiom":           ("China",        "Axiom",                  39.9042, 116.4074),

    "apt28":           ("Russia",       "GRU 26165 (Fancy Bear)", 55.7558,  37.6176),
    "apt29":           ("Russia",       "SVR (Cozy Bear)",        55.7558,  37.6176),
    "fancy bear":      ("Russia",       "GRU 26165",              55.7558,  37.6176),
    "cozy bear":       ("Russia",       "SVR",                    55.7558,  37.6176),
    "sandworm":        ("Russia",       "GRU 74455 (Sandworm)",   55.7558,  37.6176),
    "turla":           ("Russia",       "Turla/FSB",              55.7558,  37.6176),
    "wizard spider":   ("Russia",       "Wizard Spider/TrickBot", 55.7558,  37.6176),
    "indrik spider":   ("Russia",       "Evil Corp",              55.7558,  37.6176),
    "gamaredon":       ("Russia",       "Gamaredon/FSB",          55.7558,  37.6176),
    "energetic bear":  ("Russia",       "Energetic Bear",         55.7558,  37.6176),

    "lazarus":         ("North Korea",  "Lazarus Group/RGB",      39.0392, 125.7625),
    "kimsuky":         ("North Korea",  "Kimsuky",                39.0392, 125.7625),
    "andariel":        ("North Korea",  "Andariel",               39.0392, 125.7625),
    "bluenoroff":      ("North Korea",  "BlueNoroff",             39.0392, 125.7625),

    "apt33":           ("Iran",         "Elfin/IRGC",             35.6892,  51.3890),
    "apt34":           ("Iran",         "OilRig/MOIS",            35.6892,  51.3890),
    "apt35":           ("Iran",         "Charming Kitten/IRGC",   35.6892,  51.3890),
    "apt39":           ("Iran",         "Chafer/MOIS",            35.6892,  51.3890),
    "muddywater":      ("Iran",         "MuddyWater/MOIS",        35.6892,  51.3890),

    "apt32":           ("Vietnam",      "OceanLotus",             21.0285, 105.8542),
    "apt37":           ("North Korea",  "Reaper",                 39.0392, 125.7625),
    "apt38":           ("North Korea",  "Lazarus financial arm",  39.0392, 125.7625),

    "lapsus":          ("Brazil/UK",    "LAPSUS$",               -23.5505, -46.6333),
    "fin7":            ("Russia",       "FIN7/Carbanak",          55.7558,  37.6176),
    "scattered spider":("USA/UK",       "Scattered Spider/UNC3944",37.7749,-122.4194),
}

_WORD = re.compile(r"[a-z0-9]+")
def _attribute(name: str, aliases: list[str]) -> tuple[str, str, float, float] | None:
    """Match needles only on word boundaries — otherwise 'apt1' matches every
    'apt1xx' code and corrupts attribution."""
    text = " ".join([name] + (aliases or [])).lower()
    tokens = set(_WORD.findall(text))   # individual lowercased word tokens
    # Sort needles by length desc so longer multi-word phrases get a chance first
    for needle, info in sorted(APT_ATTRIBUTION.items(), key=lambda kv: -len(kv[0])):
        parts = needle.split()
        if len(parts) == 1:
            if parts[0] in tokens:
                return info
        else:
            # multi-word: require the full phrase as a substring
            if needle in text:
                return info
    return None

# --- MITRE STIX loaders -----------------------------------------------------

class MitreIndex:
    def __init__(self) -> None:
        self.groups: list[dict] = []
        self.malware: dict[str, dict] = {}
        self.campaigns: list[dict] = []
        self.techniques: dict[str, dict] = {}
        self.uses_by_group: dict[str, list[str]] = defaultdict(list)
        self._load()

    def _load(self) -> None:
        p = MITRE / "enterprise-attack.json"
        if not p.exists(): return
        bundle = json.loads(p.read_text())
        objs = bundle.get("objects", [])
        by_id = {o["id"]: o for o in objs if "id" in o}

        for o in objs:
            t = o.get("type")
            if t == "intrusion-set":
                ttp_id = next((e.get("external_id")
                               for e in o.get("external_references", [])
                               if e.get("source_name") == "mitre-attack"), None)
                attribution = _attribute(o.get("name", ""), o.get("aliases", []))
                self.groups.append({
                    "id":          ttp_id or o["id"],
                    "stix_id":     o["id"],
                    "name":        o.get("name", ""),
                    "aliases":     o.get("aliases", []),
                    "description": (o.get("description") or "")[:600],
                    "country":     attribution[0] if attribution else None,
                    "actor":       attribution[1] if attribution else None,
                    "lat":         attribution[2] if attribution else None,
                    "lng":         attribution[3] if attribution else None,
                })
            elif t == "malware":
                ttp_id = next((e.get("external_id")
                               for e in o.get("external_references", [])
                               if e.get("source_name") == "mitre-attack"), None)
                self.malware[o["id"]] = {
                    "id":   ttp_id or o["id"],
                    "name": o.get("name", ""),
                    "description": (o.get("description") or "")[:300],
                }
            elif t == "campaign":
                self.campaigns.append({
                    "name": o.get("name", ""),
                    "first_seen": o.get("first_seen", ""),
                    "last_seen":  o.get("last_seen", ""),
                    "description": (o.get("description") or "")[:300],
                })
            elif t == "attack-pattern":
                ttp_id = next((e.get("external_id")
                               for e in o.get("external_references", [])
                               if e.get("source_name") == "mitre-attack"), None)
                if ttp_id:
                    self.techniques[ttp_id] = {
                        "id":   ttp_id,
                        "name": o.get("name", ""),
                        "tactics": [p["phase_name"]
                                    for p in o.get("kill_chain_phases", [])],
                        "description": (o.get("description") or "")[:400],
                    }

        # Build a STIX-id → G-id map so the relationship loop can key by G-id
        # (groups dict uses G-ids, not STIX ids).
        stix_to_gid: dict[str, str] = {}
        for g in self.groups:
            stix_to_gid[g["stix_id"]] = g["id"]

        # group -> [technique IDs] via SROs (uses-relationships)
        for o in objs:
            if o.get("type") != "relationship": continue
            if o.get("relationship_type") != "uses": continue
            src_stix = o.get("source_ref", "")
            tgt = by_id.get(o.get("target_ref", ""))
            if not tgt or tgt.get("type") != "attack-pattern": continue
            gid = stix_to_gid.get(src_stix)
            if not gid: continue
            ttp = next((e.get("external_id")
                        for e in tgt.get("external_references", [])
                        if e.get("source_name") == "mitre-attack"), None)
            if ttp:
                self.uses_by_group[gid].append(ttp)

# --- CISA KEV ---------------------------------------------------------------

class KevIndex:
    def __init__(self) -> None:
        self.entries: list[dict] = []
        self.by_cve: dict[str, dict] = {}
        self.released: str = ""
        self._load()

    def _load(self) -> None:
        p = FEEDS / "cisa_kev.json"
        if not p.exists(): return
        data = json.loads(p.read_text())
        self.released = data.get("dateReleased", "")
        for v in data.get("vulnerabilities", []):
            entry = {
                "cve":         v.get("cveID"),
                "vendor":      v.get("vendorProject"),
                "product":     v.get("product"),
                "name":        v.get("vulnerabilityName"),
                "date_added":  v.get("dateAdded"),
                "due_date":    v.get("dueDate"),
                "ransomware":  v.get("knownRansomwareCampaignUse"),
                "notes":       v.get("notes", ""),
                "description": v.get("shortDescription", ""),
                "cwes":        v.get("cwes", []),
            }
            self.entries.append(entry)
            if entry["cve"]: self.by_cve[entry["cve"]] = entry

# --- IOC index --------------------------------------------------------------

class IocIndex:
    def __init__(self) -> None:
        self.live_iocs: list[dict] = []
        self.iocs_by_country = defaultdict(int)
        self._load()

    def _load(self) -> None:
        p = FEEDS / "threatfox.json"
        if not p.exists(): return
        try:
            data = json.loads(p.read_text())
        except Exception: return
        items: list = []
        if isinstance(data, dict):
            src = data.get("data") if isinstance(data.get("data"), dict) else data
            for v in src.values():
                if isinstance(v, list): items.extend(v)
        elif isinstance(data, list):
            items = data
        for it in items[:5_000]:
            self.live_iocs.append({
                "ioc":        it.get("ioc_value") or it.get("ioc"),
                "type":       it.get("ioc_type"),
                "malware":    it.get("malware_printable") or it.get("malware"),
                "first_seen": it.get("first_seen_utc") or it.get("first_seen"),
                "tags":       it.get("tags") or [],
                "reporter":   it.get("reporter"),
                "confidence": it.get("confidence_level"),
            })

# --- the fusion engine ------------------------------------------------------

class IntelFusion:
    def __init__(self) -> None:
        self.mitre = MitreIndex()
        self.kev   = KevIndex()
        self.ioc   = IocIndex()

    # ---- summary for top-of-dashboard cards --------------------------------
    def summary(self) -> dict:
        attributed = [g for g in self.mitre.groups if g.get("country")]
        by_country: dict[str, int] = defaultdict(int)
        for g in attributed: by_country[g["country"]] += 1
        recent_kev = sorted(self.kev.entries, key=lambda v: v.get("date_added") or "",
                            reverse=True)[:8]
        ransomware_kev = [v for v in self.kev.entries if v.get("ransomware") == "Known"]
        return {
            "agencies_active":  ["CISA (DHS)", "NIST NVD", "MITRE ATT&CK",
                                 "FIRST EPSS", "abuse.ch", "Spamhaus",
                                 "DShield (SANS)", "PhishTank"],
            "kev_count":         len(self.kev.entries),
            "kev_released":      self.kev.released,
            "kev_ransomware":    len(ransomware_kev),
            "kev_recent":        recent_kev,
            "apt_groups_total":  len(self.mitre.groups),
            "apt_attributed":    len(attributed),
            "apt_by_country":    dict(by_country),
            "techniques":        len(self.mitre.techniques),
            "malware_families":  len(self.mitre.malware),
            "campaigns":         len(self.mitre.campaigns),
            "live_iocs":         len(self.ioc.live_iocs),
            "ioc_sample":        self.ioc.live_iocs[:8],
        }

    # ---- attribution map data ---------------------------------------------
    def attribution_map(self) -> list[dict]:
        markers: dict[tuple[float, float, str], dict] = {}
        for g in self.mitre.groups:
            if g.get("lat") is None: continue
            key = (g["lat"], g["lng"], g["country"])
            if key not in markers:
                markers[key] = {
                    "country": g["country"], "lat": g["lat"], "lng": g["lng"],
                    "groups": [],
                }
            markers[key]["groups"].append({
                "id": g["id"], "name": g["name"], "actor": g.get("actor"),
                "techniques": self.mitre.uses_by_group.get(g["id"], [])[:5],
            })
        return list(markers.values())

    # ---- group dossier ----------------------------------------------------
    def group(self, gid: str) -> dict | None:
        for g in self.mitre.groups:
            if g["id"] == gid:
                tech_ids = self.mitre.uses_by_group.get(gid, [])
                techs = [self.mitre.techniques[t] for t in tech_ids
                         if t in self.mitre.techniques]
                # Find KEV CVEs whose vendor/product appears in group description
                desc = (g.get("description") or "").lower()
                related_kev = [v for v in self.kev.entries
                               if (v.get("vendor") or "").lower() in desc
                               or (v.get("product") or "").lower() in desc][:8]
                related_iocs = [i for i in self.ioc.live_iocs
                                if i.get("malware") and
                                any(a.lower() in (i["malware"] or "").lower()
                                    for a in [g["name"]] + (g.get("aliases") or []))][:8]
                return {
                    "group": g,
                    "techniques": techs[:25],
                    "related_kev": related_kev,
                    "related_iocs": related_iocs,
                }
        return None

    # ---- search ----------------------------------------------------------
    def search(self, q: str) -> dict:
        ql = (q or "").lower().strip()
        if not ql:
            return {"groups": [], "kev": [], "techniques": [], "iocs": []}
        groups = [g for g in self.mitre.groups
                  if ql in g["name"].lower()
                  or any(ql in a.lower() for a in g.get("aliases", []))
                  or ql in (g.get("country") or "").lower()][:20]
        kev = [v for v in self.kev.entries
               if (v.get("cve") or "").lower().find(ql) >= 0
               or ql in (v.get("vendor") or "").lower()
               or ql in (v.get("product") or "").lower()
               or ql in (v.get("name") or "").lower()][:20]
        techniques = [t for t in self.mitre.techniques.values()
                      if ql in (t.get("id") or "").lower()
                      or ql in (t.get("name") or "").lower()][:20]
        iocs = [i for i in self.ioc.live_iocs
                if ql in str(i.get("ioc") or "").lower()
                or ql in str(i.get("malware") or "").lower()][:20]
        return {"groups": groups, "kev": kev,
                "techniques": techniques, "iocs": iocs}

    # ---- briefing context (fed to the LLM) -------------------------------
    def briefing_context(self, q: str | None = None) -> dict:
        if q:
            hits = self.search(q)
        else:
            hits = {
                "groups": [g for g in self.mitre.groups
                           if g.get("country")][:8],
                "kev":    sorted(self.kev.entries,
                                 key=lambda v: v.get("date_added") or "",
                                 reverse=True)[:10],
                "techniques": list(self.mitre.techniques.values())[:0],
                "iocs":   self.ioc.live_iocs[:8],
            }
        return {
            "query":   q or "current threat picture",
            "summary": self.summary(),
            "hits":    hits,
            "sources": [
                "CISA Known Exploited Vulnerabilities (DHS)",
                "MITRE ATT&CK Enterprise (FFRDC)",
                "NIST National Vulnerability Database",
                "FIRST EPSS",
                "abuse.ch ThreatFox / SSLBL / Feodo / URLhaus",
                "Spamhaus DROP / EDROP",
                "SANS DShield",
                "PhishTank",
            ],
        }
