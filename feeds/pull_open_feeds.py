"""Pulls every no-auth threat-intel feed from the SENTINEL dump.

Output: data/feeds/<source>.<ext> + a unified data/feeds/iocs.csv with
(indicator, type, source, first_seen) for fast lookup at demo time.

Run: python feeds/pull_open_feeds.py
"""
from __future__ import annotations
import csv, json, os, sys, time
from pathlib import Path
import requests

OUT = Path(__file__).resolve().parent.parent / "data" / "feeds"
OUT.mkdir(parents=True, exist_ok=True)

FEEDS = [
    # name, url, kind (json|csv|txt)
    ("feodotracker_ips",  "https://feodotracker.abuse.ch/downloads/ipblocklist.json", "json"),
    ("threatfox",         "https://threatfox.abuse.ch/export/json/recent/",           "json"),
    ("sslbl_ips",         "https://sslbl.abuse.ch/blacklist/sslipblacklist.csv",      "csv"),
    ("urlhaus",           "https://urlhaus.abuse.ch/downloads/csv_recent/",           "csv"),
    ("dshield_top20",     "https://isc.sans.edu/block.txt",                           "txt"),
    ("spamhaus_drop",     "https://www.spamhaus.org/drop/drop.txt",                   "txt"),
    ("spamhaus_edrop",    "https://www.spamhaus.org/drop/edrop.txt",                  "txt"),
    ("phishtank",         "https://data.phishtank.com/data/online-valid.csv",         "csv"),
    ("emerging_threats",  "https://rules.emergingthreats.net/open/suricata/emerging.rules.tar.gz", "bin"),
]

UA = {"User-Agent": "sentinel-hackathon/1.0 (+https://github.com/)"}

def fetch(name: str, url: str, kind: str) -> Path:
    ext = {"json": "json", "csv": "csv", "txt": "txt", "bin": "bin"}[kind]
    dest = OUT / f"{name}.{ext}"
    print(f"[+] {name}  <-  {url}")
    r = requests.get(url, headers=UA, timeout=60)
    r.raise_for_status()
    dest.write_bytes(r.content)
    return dest

def parse_ips_from_text(p: Path) -> list[str]:
    ips = []
    for line in p.read_text(errors="ignore").splitlines():
        line = line.strip()
        if not line or line.startswith(("#", ";")):
            continue
        token = line.split()[0].split(",")[0]
        ips.append(token)
    return ips

def to_unified_csv(rows: list[tuple[str, str, str]]) -> Path:
    out = OUT / "iocs.csv"
    with out.open("w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["indicator", "type", "source"])
        w.writerows(rows)
    return out

def main() -> int:
    rows: list[tuple[str, str, str]] = []
    for name, url, kind in FEEDS:
        try:
            p = fetch(name, url, kind)
        except Exception as e:
            print(f"    ! {name}: {e}", file=sys.stderr)
            continue
        # Quick unified-IOC extraction for the obvious feeds
        if name in ("dshield_top20", "spamhaus_drop", "spamhaus_edrop"):
            for ip in parse_ips_from_text(p):
                rows.append((ip, "ip", name))
        elif name == "feodotracker_ips":
            try:
                data = json.loads(p.read_text())
                for entry in data:
                    if "ip_address" in entry:
                        rows.append((entry["ip_address"], "ip", name))
            except Exception:
                pass
        elif name == "sslbl_ips":
            for line in p.read_text(errors="ignore").splitlines():
                if line and not line.startswith("#"):
                    parts = line.split(",")
                    if len(parts) >= 2:
                        rows.append((parts[1].strip(), "ip", name))
        time.sleep(0.5)
    csv_path = to_unified_csv(rows)
    print(f"\n[ok] {len(rows):,} IOCs -> {csv_path}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
