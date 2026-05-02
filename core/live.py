"""Live external-API fan-out for the SCAN button.

Hits multiple real, free-tier OSINT/threat-intel APIs in parallel and merges
results. Where a key is missing, that source is gracefully skipped — the rest
still return real live data.

Endpoints used (all real, all free):
  - GreyNoise community     no-key
  - URLhaus / ThreatFox      no-key
  - abuse.ch SSLBL/Feodo     no-key (cached locally)
  - NVD CVE 2.0              no-key (NIST)
  - FIRST EPSS               no-key
  - AbuseIPDB                key
  - Shodan                   key
  - VirusTotal               key
  - AlienVault OTX           key
  - IPinfo                   token
  - Pulsedive                key
"""
from __future__ import annotations
import asyncio
import os, re, json
from datetime import datetime, timedelta
from pathlib import Path
from urllib.parse import quote_plus

import requests
from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parent.parent
load_dotenv(ROOT / ".env")

UA = {"User-Agent": "sentinel-natsec/1.0"}
T  = 8

CVE_RE    = re.compile(r"^CVE-\d{4}-\d{3,7}$", re.I)
IP_RE     = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
DOMAIN_RE = re.compile(r"^[a-z0-9][a-z0-9.\-]*\.[a-z]{2,}$", re.I)
HASH_RE   = re.compile(r"^[a-f0-9]{32}$|^[a-f0-9]{40}$|^[a-f0-9]{64}$", re.I)

def classify(q: str) -> str:
    q = (q or "").strip()
    if CVE_RE.match(q):    return "cve"
    if IP_RE.match(q):     return "ip"
    if HASH_RE.match(q):   return "hash"
    if DOMAIN_RE.match(q): return "domain"
    if q.startswith(("http://", "https://")): return "url"
    return "keyword"

def _get(url, headers=None, params=None, timeout=T):
    h = dict(UA)
    if headers: h.update(headers)
    try:
        r = requests.get(url, headers=h, params=params, timeout=timeout)
        if not r.ok: return {"_status": r.status_code}
        return r.json()
    except Exception as e:
        return {"_error": str(e)[:160]}

def _post(url, json_body=None, data=None, headers=None, timeout=T):
    h = dict(UA)
    if headers: h.update(headers)
    try:
        r = requests.post(url, json=json_body, data=data, headers=h, timeout=timeout)
        if not r.ok: return {"_status": r.status_code}
        return r.json()
    except Exception as e:
        return {"_error": str(e)[:160]}

# === Per-source callers (all real APIs) =====================================

def src_greynoise(ip: str) -> dict:
    return _get(f"https://api.greynoise.io/v3/community/{ip}")

def _abuse_headers() -> dict | None:
    """abuse.ch added Auth-Key requirements in 2024. Header is optional but
    if you have one set it via ABUSECH_KEY in .env."""
    k = os.getenv("ABUSECH_KEY")
    return {"Auth-Key": k} if k else None

def src_urlhaus(target: str) -> dict:
    h = _abuse_headers()
    if h is None:
        return {"_skip": "no ABUSECH_KEY (free at https://auth.abuse.ch/)"}
    if target.startswith("http"):
        return _post("https://urlhaus-api.abuse.ch/v1/url/",
                     data={"url": target}, headers=h)
    return _post("https://urlhaus-api.abuse.ch/v1/host/",
                 data={"host": target}, headers=h)

def src_threatfox(target: str) -> dict:
    h = _abuse_headers()
    if h is None:
        return {"_skip": "no ABUSECH_KEY (free at https://auth.abuse.ch/)"}
    return _post("https://threatfox-api.abuse.ch/api/v1/",
                 json_body={"query": "search_ioc", "search_term": target},
                 headers=h)

def src_nvd_cve(cve: str) -> dict:
    return _get("https://services.nvd.nist.gov/rest/json/cves/2.0",
                params={"cveId": cve.upper()}, timeout=15)

def src_epss(cve: str) -> dict:
    return _get("https://api.first.org/data/v1/epss",
                params={"cve": cve.upper()})

def src_abuseipdb(ip: str) -> dict:
    k = os.getenv("ABUSEIPDB_KEY")
    if not k: return {"_skip": "no ABUSEIPDB_KEY"}
    return _get("https://api.abuseipdb.com/api/v2/check",
                headers={"Key": k, "Accept": "application/json"},
                params={"ipAddress": ip, "maxAgeInDays": 90})

def src_shodan(ip: str) -> dict:
    k = os.getenv("SHODAN_KEY")
    if not k: return {"_skip": "no SHODAN_KEY"}
    return _get(f"https://api.shodan.io/shodan/host/{ip}",
                params={"key": k}, timeout=15)

def src_virustotal(target: str, kind: str) -> dict:
    k = os.getenv("VT_KEY")
    if not k: return {"_skip": "no VT_KEY"}
    if kind == "ip":
        path = f"ip_addresses/{target}"
    elif kind == "domain":
        path = f"domains/{target}"
    elif kind == "hash":
        path = f"files/{target}"
    elif kind == "url":
        import base64
        b = base64.urlsafe_b64encode(target.encode()).rstrip(b"=").decode()
        path = f"urls/{b}"
    else:
        return {"_skip": "unsupported"}
    return _get(f"https://www.virustotal.com/api/v3/{path}",
                headers={"x-apikey": k})

def src_otx(target: str, kind: str) -> dict:
    k = os.getenv("OTX_KEY")
    if not k: return {"_skip": "no OTX_KEY"}
    paths = {"ip": f"IPv4/{target}", "domain": f"domain/{target}",
             "hash": f"file/{target}", "url": f"url/{target}"}
    if kind not in paths: return {"_skip": "unsupported"}
    return _get(f"https://otx.alienvault.com/api/v1/indicators/{paths[kind]}/general",
                headers={"X-OTX-API-KEY": k})

def src_ipinfo(ip: str) -> dict:
    t = os.getenv("IPINFO_TOKEN")
    if not t: return {"_skip": "no IPINFO_TOKEN"}
    return _get(f"https://ipinfo.io/{ip}", params={"token": t})

def src_pulsedive(target: str) -> dict:
    k = os.getenv("PULSEDIVE_KEY")
    if not k: return {"_skip": "no PULSEDIVE_KEY"}
    return _get("https://pulsedive.com/api/info.php",
                params={"indicator": target, "key": k, "pretty": 1})

# === NVD recent (for the live CVE feed) =====================================

def nvd_recent(days: int = 14, limit: int = 30) -> list[dict]:
    end = datetime.utcnow()
    start = end - timedelta(days=days)
    fmt = "%Y-%m-%dT%H:%M:%S.000"
    res = _get("https://services.nvd.nist.gov/rest/json/cves/2.0",
               params={"pubStartDate": start.strftime(fmt),
                       "pubEndDate":   end.strftime(fmt),
                       "resultsPerPage": min(limit, 100)},
               timeout=20)
    out: list[dict] = []
    for v in (res.get("vulnerabilities") or [])[:limit]:
        c = v.get("cve") or {}
        metrics = c.get("metrics") or {}
        cvss_v3 = (metrics.get("cvssMetricV31")
                   or metrics.get("cvssMetricV30")
                   or [{}])[0].get("cvssData", {}) if metrics else {}
        out.append({
            "cve":       c.get("id"),
            "published": c.get("published"),
            "modified":  c.get("lastModified"),
            "score":     cvss_v3.get("baseScore"),
            "severity":  cvss_v3.get("baseSeverity"),
            "summary":   ((c.get("descriptions") or [{}])[0].get("value") or "")[:280],
        })
    return out

# === Fan-out scan ==========================================================

async def scan(q: str) -> dict:
    kind = classify(q)
    loop = asyncio.get_event_loop()
    tasks: dict[str, asyncio.Future] = {}

    def schedule(name, fn, *args):
        tasks[name] = loop.run_in_executor(None, fn, *args)

    if kind == "ip":
        schedule("greynoise",  src_greynoise, q)
        schedule("abuseipdb",  src_abuseipdb, q)
        schedule("shodan",     src_shodan,    q)
        schedule("virustotal", src_virustotal, q, "ip")
        schedule("otx",        src_otx, q, "ip")
        schedule("ipinfo",     src_ipinfo, q)
        schedule("pulsedive",  src_pulsedive, q)
        schedule("threatfox",  src_threatfox, q)
        schedule("urlhaus",    src_urlhaus, q)
    elif kind == "domain":
        schedule("urlhaus",    src_urlhaus, q)
        schedule("threatfox",  src_threatfox, q)
        schedule("virustotal", src_virustotal, q, "domain")
        schedule("otx",        src_otx, q, "domain")
        schedule("pulsedive",  src_pulsedive, q)
    elif kind == "url":
        schedule("urlhaus",    src_urlhaus, q)
        schedule("virustotal", src_virustotal, q, "url")
    elif kind == "hash":
        schedule("virustotal", src_virustotal, q, "hash")
        schedule("otx",        src_otx, q, "hash")
        schedule("threatfox",  src_threatfox, q)
    elif kind == "cve":
        schedule("nvd",        src_nvd_cve, q)
        schedule("epss",       src_epss, q)
    else:
        schedule("threatfox",  src_threatfox, q)

    results = {}
    for name, fut in tasks.items():
        try:
            results[name] = await asyncio.wait_for(fut, timeout=T+2)
        except Exception as e:
            results[name] = {"_error": str(e)[:160]}
    return {
        "query": q, "kind": kind,
        "sources": list(tasks.keys()),
        "results": results,
        "fetched_at": datetime.utcnow().isoformat() + "Z",
    }
