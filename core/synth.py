"""Synthetic data generator. Two purposes:

  1. Train the baseline immediately, before CIC-IDS / CERT downloads finish.
  2. Be the "ground truth" demo: the attacks we inject are *known-bad* so we
     can show the same engine catching both an external network attack and
     an insider exfil with no model retraining in between.

Three personas, three normal patterns, three attack scenarios.
"""
from __future__ import annotations
import random
from datetime import datetime, timedelta
from typing import Iterable

from .schema import Event

USERS  = [f"u_{i:03d}" for i in range(40)]
HOSTS  = [f"host-{i:02d}" for i in range(15)]
INTRA_IPS = [f"10.0.{i//255}.{i%255}" for i in range(80)]
EXT_IPS   = [f"203.0.113.{i}" for i in range(50)]   # TEST-NET-3
MODELS = ["intel-rag-v3", "imint-classifier-v2", "comms-summarizer-v1"]
PATHS  = [f"/share/intel/report-{i:04d}.pdf" for i in range(120)]

random.seed(7)

def _hour_weight(h: int) -> float:
    # daytime activity peak
    if 8 <= h < 18: return 1.0
    if 6 <= h < 22: return 0.4
    return 0.05

def benign(start: datetime, hours: float = 12.0, eps: int = 30) -> Iterable[Event]:
    """Yield benign events at ~eps events/sec until `hours` of sim time pass."""
    t = start
    end = start + timedelta(hours=hours)
    user_paths: dict[str, list[str]] = {u: random.sample(PATHS, 8) for u in USERS}
    while t < end:
        # decide event type by hour
        if random.random() < _hour_weight(t.hour):
            roll = random.random()
            if roll < 0.55:                 # network
                yield Event(t, "network", random.choice(INTRA_IPS),
                            random.choice(INTRA_IPS), "connect",
                            bytes=random.expovariate(1/2_000),
                            duration=random.expovariate(1/0.2),
                            asset=random.choice(HOSTS))
            elif roll < 0.75:               # file access (insider baseline)
                u = random.choice(USERS)
                yield Event(t, "file", u, random.choice(user_paths[u]),
                            "read", bytes=random.expovariate(1/50_000),
                            asset=random.choice(HOSTS))
            elif roll < 0.90:               # logins
                u = random.choice(USERS)
                yield Event(t, "login", u, random.choice(HOSTS), "login",
                            success=random.random() > 0.05,
                            asset=random.choice(HOSTS))
            else:                            # model query
                yield Event(t, "model_query", random.choice(USERS),
                            random.choice(MODELS), "query",
                            bytes=random.expovariate(1/4_000))
        t += timedelta(seconds=1.0 / max(eps, 1))

# --- Attack injectors -------------------------------------------------------

def attack_external_scan(t: datetime, src: str = "203.0.113.66") -> Iterable[Event]:
    """Port-scan style: one external IP hits 60 internal targets in <30s."""
    targets = random.sample(INTRA_IPS, 60)
    for i, tgt in enumerate(targets):
        yield Event(t + timedelta(seconds=i * 0.4), "network", src, tgt,
                    "connect", bytes=64, duration=0.05,
                    asset="perimeter", success=random.random() > 0.7,
                    label="EXT_SCAN")

def attack_insider_exfil(t: datetime, user: str = "u_017") -> Iterable[Event]:
    """At 02:00 the user reads 80 files from /share/intel and uploads
    a large blob to an unfamiliar host. Same engine should catch this."""
    night = t.replace(hour=2, minute=14, second=0, microsecond=0)
    targets = random.sample(PATHS, 80)
    for i, p in enumerate(targets):
        yield Event(night + timedelta(seconds=i * 0.6), "file", user, p,
                    "read", bytes=random.uniform(80_000, 400_000),
                    asset="laptop-23", label="INSIDER_EXFIL")
    yield Event(night + timedelta(seconds=60), "network", user,
                "203.0.113.9", "upload", bytes=80_000_000,
                duration=120.0, asset="laptop-23", label="INSIDER_EXFIL")

def attack_model_tamper(t: datetime, who: str = "u_031") -> Iterable[Event]:
    """Unusual user pulls weights for a sensitive model + queries with
    suspicious volume — proxy for model-supply-chain abuse."""
    yield Event(t, "file", who, "/models/imint-classifier-v2/weights.bin",
                "read", bytes=420_000_000, label="MODEL_TAMPER",
                asset="ml-bench-01")
    for i in range(40):
        yield Event(t + timedelta(seconds=i * 0.5), "model_query", who,
                    "imint-classifier-v2", "query",
                    bytes=120_000, label="MODEL_TAMPER",
                    asset="ml-bench-01")
