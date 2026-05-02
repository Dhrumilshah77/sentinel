#!/usr/bin/env bash
# SENTINEL — Option E bootstrap. Clones only repos relevant to unified
# behavioral risk engine. Skips RF/container/network-IDS bloat from the
# original SENTINEL dump.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
cd "$HERE"

mkdir -p repos data/feeds data/datasets data/mitre

clone() {
  local url="$1" dir="repos/$(basename "$1" .git)"
  if [ -d "$dir" ]; then echo "skip $dir (exists)"; return; fi
  git clone --depth=1 "$url" "$dir"
}

# === CORE for Option E ===
# Sigma — vendor-agnostic detection rules. Use to map alerts to MITRE ATT&CK.
clone https://github.com/SigmaHQ/sigma.git
# MITRE CTI — official ATT&CK STIX 2.0 (TTPs, techniques, software, groups).
clone https://github.com/mitre/cti.git
# OpenCTI — knowledge graph for entity linking + alert correlation.
clone https://github.com/OpenCTI-Platform/opencti.git
# ModelScan — detect tampered ML model files (covers the AI-supply-chain leg of the pitch).
clone https://github.com/protectai/modelscan.git
# Awesome AI Security — curated index, useful as reference during build.
clone https://github.com/ottosulin/awesome-ai-security.git

# === OPTIONAL — only if you need full XDR/SIEM stack on demo machine ===
# clone https://github.com/wazuh/wazuh.git              # heavy, skip unless using
# clone https://github.com/TheHive-Project/TheHive.git  # case management UI
# clone https://github.com/Shuffle/Shuffle.git          # SOAR playbooks

echo
echo "Repos cloned. Next:"
echo "  cp .env.example .env  &&  edit keys"
echo "  python -m venv .venv && source .venv/bin/activate && pip install -r requirements.txt"
echo "  python feeds/pull_open_feeds.py        # no-auth threat intel"
echo "  python apis/enrichers.py 8.8.8.8       # smoke-test keyed APIs"
echo "  python mitre/pull_attack.py            # MITRE ATT&CK STIX"
echo "  bash datasets/download.sh              # CIC-IDS / UNSW-NB15 / CTU-13"
