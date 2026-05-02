"""Wraps every keyed free-tier API from the SENTINEL dump in one CLI.

Usage:
    python apis/enrichers.py <ip_or_domain_or_url>
    python apis/enrichers.py --cve CVE-2024-12345
    python apis/enrichers.py --epss CVE-2024-12345

Reads keys from .env (see .env.example). Missing keys -> source skipped.
"""
from __future__ import annotations
import argparse, json, os, sys
from pathlib import Path
import requests
from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parent.parent
load_dotenv(ROOT / ".env")

T = 30
UA = {"User-Agent": "sentinel-hackathon/1.0"}

def _get(url, headers=None, params=None):
    h = dict(UA)
    if headers: h.update(headers)
    r = requests.get(url, headers=h, params=params, timeout=T)
    if not r.ok:
        return {"_status": r.status_code, "_body": r.text[:300]}
    try:
        return r.json()
    except Exception:
        return {"_text": r.text[:500]}

# === IP / domain / URL reputation ===
def abuseipdb(ip):
    k = os.getenv("ABUSEIPDB_KEY")
    if not k: return {"_skip": "no ABUSEIPDB_KEY"}
    return _get("https://api.abuseipdb.com/api/v2/check",
                headers={"Key": k, "Accept": "application/json"},
                params={"ipAddress": ip, "maxAgeInDays": 90})

def otx_ip(ip):
    k = os.getenv("OTX_KEY")
    if not k: return {"_skip": "no OTX_KEY"}
    return _get(f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general",
                headers={"X-OTX-API-KEY": k})

def virustotal_ip(ip):
    k = os.getenv("VT_KEY")
    if not k: return {"_skip": "no VT_KEY"}
    return _get(f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
                headers={"x-apikey": k})

def greynoise(ip):
    k = os.getenv("GREYNOISE_KEY")
    if not k: return {"_skip": "no GREYNOISE_KEY"}
    return _get(f"https://api.greynoise.io/v3/community/{ip}",
                headers={"key": k})

def shodan(ip):
    k = os.getenv("SHODAN_KEY")
    if not k: return {"_skip": "no SHODAN_KEY"}
    return _get(f"https://api.shodan.io/shodan/host/{ip}", params={"key": k})

def ipinfo(ip):
    t = os.getenv("IPINFO_TOKEN")
    if not t: return {"_skip": "no IPINFO_TOKEN"}
    return _get(f"https://ipinfo.io/{ip}", params={"token": t})

def pulsedive(ind):
    k = os.getenv("PULSEDIVE_KEY")
    if not k: return {"_skip": "no PULSEDIVE_KEY"}
    return _get("https://pulsedive.com/api/info.php",
                params={"indicator": ind, "key": k, "pretty": 1})

# === No-auth ===
def urlhaus_url(u):
    r = requests.post("https://urlhaus-api.abuse.ch/v1/url/", data={"url": u}, timeout=T)
    try: return r.json()
    except Exception: return {"_text": r.text[:500]}

def threatfox(ind):
    r = requests.post("https://threatfox-api.abuse.ch/api/v1/",
                      json={"query": "search_ioc", "search_term": ind}, timeout=T)
    try: return r.json()
    except Exception: return {"_text": r.text[:500]}

# === CVE / vuln ===
def nvd(cve):
    return _get("https://services.nvd.nist.gov/rest/json/cves/2.0",
                params={"cveId": cve})

def osv(pkg=None, cve=None):
    body = {}
    if cve: body = {"vulnerability": {"id": cve}}
    elif pkg: body = {"package": {"name": pkg}}
    r = requests.post("https://api.osv.dev/v1/query", json=body, timeout=T)
    try: return r.json()
    except Exception: return {"_text": r.text[:500]}

def epss(cve):
    return _get("https://api.first.org/data/v1/epss", params={"cve": cve})

def enrich_ip(ip):
    return {
        "ip": ip,
        "abuseipdb": abuseipdb(ip),
        "otx":       otx_ip(ip),
        "virustotal": virustotal_ip(ip),
        "greynoise": greynoise(ip),
        "shodan":    shodan(ip),
        "ipinfo":    ipinfo(ip),
        "pulsedive": pulsedive(ip),
        "threatfox": threatfox(ip),
    }

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("indicator", nargs="?", help="IP / domain / URL")
    ap.add_argument("--cve", help="Look up a CVE in NVD/OSV/EPSS")
    ap.add_argument("--epss", help="EPSS score for a CVE")
    args = ap.parse_args()
    out = {}
    if args.cve:
        out = {"cve": args.cve, "nvd": nvd(args.cve), "osv": osv(cve=args.cve),
               "epss": epss(args.cve)}
    elif args.epss:
        out = {"cve": args.epss, "epss": epss(args.epss)}
    elif args.indicator:
        ind = args.indicator
        if ind.startswith("http"):
            out = {"url": ind, "urlhaus": urlhaus_url(ind),
                   "threatfox": threatfox(ind)}
        else:
            out = enrich_ip(ind)
    else:
        ap.print_help(); return 2
    json.dump(out, sys.stdout, indent=2, default=str)
    print()
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
