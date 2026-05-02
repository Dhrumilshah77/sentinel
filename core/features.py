"""Per-entity rolling-window feature extraction.

Features are deliberately event-type-agnostic — that's the whole point.
A login burst, a TCP scan, and a file-exfil episode all light up the
same axes (volume, target diversity, novelty, off-hours, failure rate).
"""
from __future__ import annotations
from collections import defaultdict, deque
from datetime import datetime, timedelta
from typing import Deque

from .schema import Event

# Window sizes — short enough to react inside a 3-min demo, long enough
# to be meaningful. Tune live during build if needed.
SHORT = timedelta(minutes=5)
LONG  = timedelta(hours=1)

# Universal behavioral features — work for ANY event type (network, login,
# file, model_query, process). This is the unified-engine pitch.
BEHAVIORAL_FEATURES = [
    "rate_5m", "rate_1h",
    "bytes_5m", "bytes_1h",
    "distinct_targets_5m", "distinct_targets_1h",
    "novel_target",       # 1 if target unseen before for this actor
    "off_hours",          # outside 08-18 local
    "weekend",
    "failure_rate_1h",
    "type_entropy_1h",    # 0 = always same event type, higher = mixed
    "duration",
    "log_bytes",
]

# Domain-specific numeric signals carried via Event.raw under the dom_ prefix.
# Defaults to 0.0 when an event type doesn't supply them — that's the trick
# that keeps the feature space unified across cyber + insider + model.
DOMAIN_FEATURES = [
    "dom_count", "dom_srv_count",
    "dom_serror_rate", "dom_srv_serror_rate",
    "dom_rerror_rate", "dom_srv_rerror_rate",
    "dom_same_srv_rate", "dom_diff_srv_rate", "dom_srv_diff_host_rate",
    "dom_dst_host_count", "dom_dst_host_srv_count",
    "dom_dst_host_same_srv_rate", "dom_dst_host_diff_srv_rate",
    "dom_dst_host_serror_rate", "dom_dst_host_rerror_rate",
    "dom_logged_in", "dom_num_failed_logins", "dom_num_compromised",
    "dom_root_shell", "dom_num_root", "dom_num_file_creations",
]

FEATURE_NAMES = BEHAVIORAL_FEATURES + DOMAIN_FEATURES

class FeatureExtractor:
    """Stateful — feed events in time order. Returns per-event feature dict."""

    def __init__(self) -> None:
        self.events: dict[str, Deque[Event]] = defaultdict(lambda: deque(maxlen=10_000))
        self.targets_seen: dict[str, set[str]] = defaultdict(set)

    def _evict(self, q: Deque[Event], now: datetime) -> None:
        cutoff = now - LONG
        while q and q[0].ts < cutoff:
            q.popleft()

    def extract(self, ev: Event) -> dict[str, float]:
        q = self.events[ev.actor]
        self._evict(q, ev.ts)

        in_short = [e for e in q if e.ts >= ev.ts - SHORT]
        in_long  = list(q)  # already evicted to LONG

        rate_5m = len(in_short) / 5.0
        rate_1h = len(in_long) / 60.0
        bytes_5m = sum(e.bytes for e in in_short)
        bytes_1h = sum(e.bytes for e in in_long)
        distinct_5m = len({e.target for e in in_short})
        distinct_1h = len({e.target for e in in_long})

        seen = self.targets_seen[ev.actor]
        novel = 0.0 if ev.target in seen else 1.0

        hour = ev.ts.hour
        off_hours = 1.0 if hour < 8 or hour >= 18 else 0.0
        weekend = 1.0 if ev.ts.weekday() >= 5 else 0.0

        if in_long:
            failures = sum(1 for e in in_long if not e.success)
            failure_rate = failures / len(in_long)
        else:
            failure_rate = 0.0

        # Type entropy: how mixed are this actor's recent activities?
        # An attacker frequently shifts modes (login, then network, then file).
        # Computed via Gini-like 1 - sum(p_i^2) for speed.
        if in_long:
            counts: dict[str, int] = {}
            for e in in_long:
                counts[e.type] = counts.get(e.type, 0) + 1
            total = len(in_long)
            type_entropy = 1.0 - sum((c / total) ** 2 for c in counts.values())
        else:
            type_entropy = 0.0

        feats: dict[str, float] = {
            "rate_5m": rate_5m,
            "rate_1h": rate_1h,
            "bytes_5m": float(bytes_5m),
            "bytes_1h": float(bytes_1h),
            "distinct_targets_5m": float(distinct_5m),
            "distinct_targets_1h": float(distinct_1h),
            "novel_target": novel,
            "off_hours": off_hours,
            "weekend": weekend,
            "failure_rate_1h": failure_rate,
            "type_entropy_1h": type_entropy,
            "duration": float(ev.duration),
            "log_bytes": float(_log1p(ev.bytes)),
        }
        # Domain features default to 0.0 unless the source loader put them in
        # Event.raw under the dom_ prefix. This is what keeps the feature
        # space unified across cyber + insider + model events.
        for k in DOMAIN_FEATURES:
            try:    feats[k] = float(ev.raw.get(k, 0.0) or 0.0)
            except (TypeError, ValueError): feats[k] = 0.0

        q.append(ev)
        seen.add(ev.target)
        return feats

def _log1p(x: float) -> float:
    import math
    return math.log1p(max(x, 0.0))
