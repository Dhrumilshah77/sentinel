#!/usr/bin/env bash
# Datasets that have DIRECT downloads (no auth, no form). Real data only.
# Form-gated datasets are listed at the bottom — fill those forms NOW so the
# data lands while the engine is running on what we have.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
OUT="$ROOT/data/datasets"
FEEDS="$ROOT/data/feeds"
mkdir -p "$OUT" "$FEEDS"

dl() {  # url, filename
  local url="$1" name="$2"
  if [ -f "$OUT/$name" ]; then echo "skip $name (exists)"; return; fi
  echo "[+] $name"
  curl -L --fail --retry 3 -o "$OUT/$name" "$url"
}
dlf() { # url, filename in feeds dir
  local url="$1" name="$2"
  if [ -f "$FEEDS/$name" ]; then echo "skip $name (exists)"; return; fi
  echo "[+] $name"
  curl -L --fail --retry 3 -o "$FEEDS/$name" "$url"
}

# === REAL DATA, DIRECT DOWNLOAD ============================================

# NSL-KDD — clean KDD'99 with labeled DoS / Probe / R2L / U2R attacks.
dl "https://raw.githubusercontent.com/Mamcose/NSL-KDD-Network-Intrusion-Detection/master/NSL_KDD_Train.csv" "nsl_kdd_train.csv"
dl "https://raw.githubusercontent.com/Mamcose/NSL-KDD-Network-Intrusion-Detection/master/NSL_KDD_Test.csv"  "nsl_kdd_test.csv"

# CTU-13 — real botnet binetflow captures (13 scenarios, ~2GB compressed).
dl "https://mcfp.felk.cvut.cz/publicDatasets/CTU-13-Dataset/CTU-13-Dataset.tar.bz2" "ctu13.tar.bz2"
if [ -f "$OUT/ctu13.tar.bz2" ] && [ ! -d "$OUT/ctu13_unpacked" ]; then
  echo "[+] unpacking CTU-13 (this takes ~30s)…"
  mkdir -p "$OUT/ctu13_unpacked"
  tar -xjf "$OUT/ctu13.tar.bz2" -C "$OUT/ctu13_unpacked"
fi

# MITRE ATT&CK Enterprise STIX — real adversary technique catalog.
dl "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json" "enterprise-attack.json"

# CISA KEV — actively exploited vulnerabilities (US gov, daily-updated).
dlf "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json" "cisa_kev.json"

# === REAL LIVE INTEL (also pulled by feeds/pull_open_feeds.py) =============
# These are continuously updated — re-run periodically during the hackathon.
echo
echo "[i] also run:  python feeds/pull_open_feeds.py   to refresh live IOC feeds"

cat <<'NOTE'

[ FORM-GATED — fill out NOW; data arrives in <30 min for most ]

  CIC-IDS-2017          UNB form: https://www.unb.ca/cic/datasets/ids-2017.html
                        Drop the per-day CSVs into  data/datasets/cicids/
                        Loader: core.loaders.load_cicids() handles the standard schema.

  CIC-IDS-2018          https://www.unb.ca/cic/datasets/ids-2018.html
                        Same target dir as above.

  UNSW-NB15             https://research.unsw.edu.au/projects/unsw-nb15-dataset

  CERT Insider Threat   *** Critical for the unified-engine pitch ***
                        https://insights.sei.cmu.edu/library/insider-threat-test-dataset/
                        Use r4.2 (small) or r6.2 (full).
                        Drop logon.csv / device.csv / file.csv / http.csv / email.csv
                        into  data/datasets/cert/
                        Loader: core.loaders.load_cert() reads them all.

NOTE
echo "[ok] direct downloads -> $OUT"
echo "[ok] feed snapshots   -> $FEEDS"
