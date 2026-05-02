"""Real-data loaders. Each yields normalized Event objects.

Sources (direct-download / no-auth tier):
  - NSL-KDD          → labeled connection records (DoS, Probe, R2L, U2R)
  - CTU-13           → real botnet binetflow (Argus output)
  - abuse.ch ThreatFox → live IOCs (last ~N days) replayed as connect events
  - CICIDS-2017 mirror → flow records (if downloaded; uses standard column names)
  - CERT Insider Threat r4.2/r6.2 → user logon/file/email logs (if downloaded)

For datasets behind a form, the loader simply skips with a note instead of
failing; the running engine just gets fewer streams.
"""
from __future__ import annotations
import csv, json, os, random
from datetime import datetime, timedelta
from pathlib import Path
from typing import Iterable

from .schema import Event

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "data" / "datasets"

# --- NSL-KDD ----------------------------------------------------------------
# Columns from the canonical schema (43 incl. label).
_NSL_COLS = [
    "duration","protocol_type","service","flag","src_bytes","dst_bytes",
    "land","wrong_fragment","urgent","hot","num_failed_logins","logged_in",
    "num_compromised","root_shell","su_attempted","num_root","num_file_creations",
    "num_shells","num_access_files","num_outbound_cmds","is_host_login",
    "is_guest_login","count","srv_count","serror_rate","srv_serror_rate",
    "rerror_rate","srv_rerror_rate","same_srv_rate","diff_srv_rate",
    "srv_diff_host_rate","dst_host_count","dst_host_srv_count",
    "dst_host_same_srv_rate","dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate","dst_host_srv_diff_host_rate",
    "dst_host_serror_rate","dst_host_srv_serror_rate",
    "dst_host_rerror_rate","dst_host_srv_rerror_rate","label","difficulty",
]

def load_nsl_kdd(path: Path | None = None, start: datetime | None = None,
                 step_seconds: float = 0.05) -> Iterable[Event]:
    """Yield Events from NSL-KDD test/train CSVs (one row = one connection).

    The dataset has no real timestamps; we synthesize a monotonically
    increasing wall-clock so windowed features behave correctly. Labels are
    preserved on the Event for evaluation.
    """
    paths = [path] if path else [
        DATA / "nsl_kdd_train.csv",
        DATA / "nsl_kdd_test.csv",
    ]
    t = start or datetime(2026, 5, 2, 8, 0, 0)
    for p in paths:
        if p is None or not p.exists():
            continue
        with p.open() as f:
            r = csv.reader(f)
            for row in r:
                if len(row) < len(_NSL_COLS) - 1:
                    continue
                rec = dict(zip(_NSL_COLS, row + [""] * (len(_NSL_COLS) - len(row))))
                try:
                    duration = float(rec["duration"] or 0)
                    src_b = float(rec["src_bytes"] or 0)
                    dst_b = float(rec["dst_bytes"] or 0)
                except ValueError:
                    continue
                proto = rec["protocol_type"] or "tcp"
                service = rec["service"] or "other"
                label = rec["label"] or "normal"
                # NSL-KDD doesn't carry IPs; synthesize stable pseudo-IPs from
                # service/proto so per-entity baselines still mean something.
                actor  = f"10.42.{abs(hash(service))%200}.{abs(hash(proto))%250}"
                target = f"10.99.{abs(hash(service+proto))%250}.{abs(hash(label))%250}"
                # Pass NSL-KDD's pre-engineered numeric features through `raw`
                # under `dom_*` keys so the feature extractor can consume them
                # in the unified feature space.
                dom = {}
                for col in ("count","srv_count","serror_rate","srv_serror_rate",
                            "rerror_rate","srv_rerror_rate","same_srv_rate",
                            "diff_srv_rate","srv_diff_host_rate",
                            "dst_host_count","dst_host_srv_count",
                            "dst_host_same_srv_rate","dst_host_diff_srv_rate",
                            "dst_host_serror_rate","dst_host_rerror_rate",
                            "logged_in","num_failed_logins","num_compromised",
                            "root_shell","num_root","num_file_creations"):
                    try: dom[f"dom_{col}"] = float(rec.get(col) or 0)
                    except ValueError: dom[f"dom_{col}"] = 0.0
                yield Event(
                    ts=t, type="network", actor=actor, target=target,
                    action="connect", bytes=src_b + dst_b, duration=duration,
                    success=(rec["flag"] == "SF"),
                    asset=f"sensor-nslkdd-{service[:8]}",
                    label=None if label == "normal" else label,
                    raw={"service": service, "proto": proto,
                         "src_b": src_b, "dst_b": dst_b, **dom},
                )
                t += timedelta(seconds=step_seconds)

# --- CTU-13 -----------------------------------------------------------------

def load_ctu13(scenario_dir: Path | None = None) -> Iterable[Event]:
    """CTU-13 ships per-scenario directories with `.binetflow` files.

    Argus binetflow header (CSV):
      StartTime,Dur,Proto,SrcAddr,Sport,Dir,DstAddr,Dport,State,sTos,dTos,
      TotPkts,TotBytes,SrcBytes,Label
    """
    if scenario_dir is None:
        scenario_dir = DATA / "ctu13_unpacked"
    if not scenario_dir.exists():
        return
    for binet in sorted(scenario_dir.rglob("*.binetflow")):
        with binet.open() as f:
            r = csv.DictReader(f)
            for row in r:
                try:
                    ts = datetime.strptime(row["StartTime"][:19], "%Y/%m/%d %H:%M:%S")
                except Exception:
                    continue
                src = row.get("SrcAddr", "?")
                dst = row.get("DstAddr", "?")
                lbl = row.get("Label", "")
                # CTU-13 marks botnet flows with 'Botnet' in the Label column.
                ground = "BOTNET" if "botnet" in lbl.lower() else None
                try:
                    tot_b = float(row.get("TotBytes") or 0)
                    dur   = float(row.get("Dur") or 0)
                except ValueError:
                    tot_b, dur = 0.0, 0.0
                yield Event(
                    ts=ts, type="network", actor=src, target=dst,
                    action="connect", bytes=tot_b, duration=dur,
                    success=row.get("State", "").startswith("S"),
                    asset=f"sensor-ctu-{binet.stem[:10]}",
                    label=ground,
                    raw={"proto": row.get("Proto"), "sport": row.get("Sport"),
                         "dport": row.get("Dport"), "ctu_label": lbl},
                )

# --- ThreatFox (live malware IOCs) ------------------------------------------

def load_threatfox_recent() -> Iterable[Event]:
    """Replays the most recent ThreatFox export as 'connect' Events.

    These are *real malicious indicators* observed in the wild within the past
    days — every event here is something a real attacker actually did.
    """
    p = ROOT / "data" / "feeds" / "threatfox.json"
    if not p.exists():
        return
    try:
        data = json.loads(p.read_text())
    except Exception:
        return
    # ThreatFox export is a dict { "<id>": [item, ...], ... }; the API form
    # wraps in {"data": {...}}. Handle both, and the legacy list form.
    items = []
    if isinstance(data, dict):
        src = data.get("data") if "data" in data and isinstance(data["data"], dict) else data
        for v in src.values():
            if isinstance(v, list): items.extend(v)
            elif isinstance(v, dict): items.append(v)
    elif isinstance(data, list):
        items = data
    for it in items:
        ind = it.get("ioc_value") or it.get("ioc")
        if not ind: continue
        ts_raw = it.get("first_seen_utc") or it.get("first_seen") or ""
        try:
            ts = datetime.strptime(ts_raw[:19], "%Y-%m-%d %H:%M:%S")
        except Exception:
            ts = datetime.utcnow()
        # IOC type → event shape
        kind = (it.get("ioc_type") or "").lower()
        if kind in ("ip:port", "ip"):
            host = ind.split(":")[0]
            yield Event(
                ts=ts, type="network", actor="local-egress", target=host,
                action="connect", bytes=0, duration=0,
                asset="threatfox-replay",
                label=f"REAL_IOC:{it.get('malware', it.get('threat_type', 'unknown'))}",
                raw=it,
            )
        elif kind in ("domain", "url"):
            yield Event(
                ts=ts, type="network", actor="local-egress", target=ind,
                action="resolve", bytes=0,
                asset="threatfox-replay",
                label=f"REAL_IOC:{it.get('malware', it.get('threat_type', 'unknown'))}",
                raw=it,
            )

# --- CIC-IDS-2017 (form-gated, but standard CSV format) ---------------------

_CICIDS_LABEL_COL_CANDIDATES = (" Label", "Label")

def load_cicids(dir_path: Path | None = None) -> Iterable[Event]:
    """Reads any CIC-IDS-2017/2018 CSVs placed in data/datasets/cicids/."""
    base = dir_path or (DATA / "cicids")
    if not base.exists(): return
    for p in sorted(base.rglob("*.csv")):
        with p.open() as f:
            r = csv.DictReader(f)
            label_col = next((c for c in _CICIDS_LABEL_COL_CANDIDATES
                              if c in (r.fieldnames or [])), None)
            for row in r:
                try:
                    flow_dur = float(row.get(" Flow Duration") or row.get("Flow Duration") or 0)
                    fwd_b    = float(row.get(" Total Length of Fwd Packets")
                                     or row.get("Total Length of Fwd Packets") or 0)
                    bwd_b    = float(row.get(" Total Length of Bwd Packets")
                                     or row.get("Total Length of Bwd Packets") or 0)
                except ValueError:
                    continue
                src = row.get(" Source IP") or row.get("Source IP") or "?"
                dst = row.get(" Destination IP") or row.get("Destination IP") or "?"
                ts_raw = row.get(" Timestamp") or row.get("Timestamp") or ""
                try:
                    ts = datetime.strptime(ts_raw[:19], "%d/%m/%Y %H:%M:%S")
                except Exception:
                    ts = datetime.utcnow()
                lbl = (row.get(label_col) or "").strip() if label_col else ""
                yield Event(
                    ts=ts, type="network", actor=src, target=dst,
                    action="connect", bytes=fwd_b + bwd_b,
                    duration=flow_dur / 1e6,    # µs → s
                    asset=f"sensor-cicids-{p.stem[:14]}",
                    label=None if lbl.upper() == "BENIGN" else (lbl or None),
                )

# --- CERT Insider Threat (form-gated) ---------------------------------------

def load_cert(dir_path: Path | None = None) -> Iterable[Event]:
    """Reads CERT r4.2/r6.2 logs if present. Each subfile maps to an event type:
        logon.csv  → login events
        device.csv → file (USB) events
        file.csv   → file events
        http.csv   → network events
        email.csv  → file events (proxy)
    """
    base = dir_path or (DATA / "cert")
    if not base.exists(): return
    mapping = {
        "logon.csv":  ("login",   "login"),
        "device.csv": ("file",    "usb"),
        "file.csv":   ("file",    "read"),
        "http.csv":   ("network", "http"),
        "email.csv":  ("file",    "email"),
    }
    for fname, (etype, action) in mapping.items():
        p = base / fname
        if not p.exists(): continue
        with p.open() as f:
            r = csv.DictReader(f)
            for row in r:
                try:
                    ts = datetime.strptime(row["date"], "%m/%d/%Y %H:%M:%S")
                except Exception:
                    continue
                actor = row.get("user") or "?"
                target = row.get("pc") or row.get("url") or row.get("filename") or "?"
                yield Event(
                    ts=ts, type=etype, actor=actor, target=target,
                    action=action, bytes=0, asset=row.get("pc", ""),
                    raw=row,
                )
