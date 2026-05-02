"""Unified event schema. Network packets, user logins, file accesses, and
model queries all collapse to the same shape so one feature pipeline scores
them all. This is the technical heart of the unified-engine pitch.
"""
from __future__ import annotations
from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Literal, Optional

EventType = Literal["network", "login", "file", "model_query", "process"]

@dataclass
class Event:
    ts: datetime
    type: EventType
    actor: str          # who/what initiated: user_id or src_ip
    target: str         # what was touched: dst_ip / path / model_id
    action: str         # connect | read | write | login | query | exec | ...
    bytes: float = 0.0
    duration: float = 0.0
    success: bool = True
    asset: str = ""     # host / device / segment
    label: Optional[str] = None   # ground truth (for eval only)
    raw: dict = field(default_factory=dict)

    def as_dict(self) -> dict:
        d = asdict(self)
        d["ts"] = self.ts.isoformat()
        return d

@dataclass
class Score:
    event: Event
    score: float                # 0..1, higher = more anomalous
    baseline_z: float           # how far from this entity's baseline
    isolation_score: float      # IsolationForest decision_function (negated)
    top_features: list[tuple[str, float]] = field(default_factory=list)
    techniques: list[str] = field(default_factory=list)   # MITRE T-IDs
    iocs_hit: list[str] = field(default_factory=list)
    rationale: str = ""

    def as_dict(self) -> dict:
        return {
            "event": self.event.as_dict(),
            "score": round(self.score, 4),
            "baseline_z": round(self.baseline_z, 3),
            "isolation_score": round(self.isolation_score, 3),
            "top_features": [(n, round(v, 3)) for n, v in self.top_features],
            "techniques": self.techniques,
            "iocs_hit": self.iocs_hit,
            "rationale": self.rationale,
        }
