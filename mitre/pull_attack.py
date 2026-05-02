"""Pulls MITRE ATT&CK Enterprise STIX 2.1 bundle for the alert -> TTP mapping
that judges expect. Saves a flat techniques.csv for fast lookup at demo time.
"""
from __future__ import annotations
import csv, json
from pathlib import Path
import requests

OUT = Path(__file__).resolve().parent.parent / "data" / "mitre"
OUT.mkdir(parents=True, exist_ok=True)

URL = ("https://raw.githubusercontent.com/mitre/cti/master/"
       "enterprise-attack/enterprise-attack.json")

def main():
    print(f"[+] fetching {URL}")
    r = requests.get(URL, timeout=120); r.raise_for_status()
    bundle = r.json()
    (OUT / "enterprise-attack.json").write_text(json.dumps(bundle))

    rows = []
    for obj in bundle.get("objects", []):
        if obj.get("type") != "attack-pattern": continue
        ext = obj.get("external_references") or []
        ttp = next((e.get("external_id") for e in ext
                    if e.get("source_name") == "mitre-attack"), None)
        if not ttp: continue
        tactics = ",".join(p["phase_name"] for p in obj.get("kill_chain_phases", []))
        rows.append({
            "id": ttp,
            "name": obj.get("name", ""),
            "tactics": tactics,
            "description": (obj.get("description") or "").replace("\n", " ")[:500],
        })
    with (OUT / "techniques.csv").open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["id","name","tactics","description"])
        w.writeheader(); w.writerows(rows)
    print(f"[ok] {len(rows)} techniques -> data/mitre/techniques.csv")

if __name__ == "__main__":
    main()
