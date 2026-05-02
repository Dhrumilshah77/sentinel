"""Anomaly scorer: ensemble of three signals on the unified feature space.

  (a) IsolationForest — globally weird events.
  (b) Per-entity z-score — this user/IP has changed behavior (insider angle).
  (c) Optional supervised XGBoost head — when labeled cyber data is available
      (NSL-KDD / CIC-IDS), learn the bad/good boundary directly.

The fusion is intentional: (a)+(b) are the unsupervised core that works on
anything (insider threat, novel attacks). (c) lifts precision on known cyber
attack families. Toggling (c) on/off in the demo shows the unsupervised core
catches things even without labels — that's the unified-engine story.
"""
from __future__ import annotations
from collections import defaultdict
from typing import Iterable

import numpy as np
from sklearn.ensemble import IsolationForest

from .features import FEATURE_NAMES, FeatureExtractor
from .schema import Event, Score

class _RunningStats:
    __slots__ = ("n", "mean", "M2")
    def __init__(self) -> None:
        self.n = 0
        self.mean = np.zeros(len(FEATURE_NAMES))
        self.M2   = np.zeros(len(FEATURE_NAMES))

    def update(self, x: np.ndarray) -> None:
        self.n += 1
        delta = x - self.mean
        self.mean += delta / self.n
        self.M2   += delta * (x - self.mean)

    def std(self) -> np.ndarray:
        if self.n < 2: return np.ones_like(self.mean)
        return np.sqrt(self.M2 / (self.n - 1)) + 1e-6

class Scorer:
    def __init__(self, contamination: float = 0.05) -> None:
        self.fx = FeatureExtractor()
        self.iforest = IsolationForest(
            n_estimators=150, contamination=contamination, random_state=0,
        )
        self.fitted = False
        self.entity_stats: dict[str, _RunningStats] = defaultdict(_RunningStats)
        self.xgb = None     # set by fit_supervised()

    # --- training -----------------------------------------------------------

    def fit_baseline(self, events: Iterable[Event]) -> None:
        X = []
        for ev in events:
            f = self.fx.extract(ev)
            x = np.array([f[k] for k in FEATURE_NAMES], dtype=float)
            self.entity_stats[ev.actor].update(x)
            X.append(x)
        if not X:
            raise RuntimeError("fit_baseline got 0 events")
        self.iforest.fit(np.asarray(X))
        self.fitted = True

    def fit_supervised(self, events: Iterable[tuple[Event, int]]) -> dict:
        """Fit XGBoost on (event, is_malicious) pairs. is_malicious in {0, 1}."""
        try:
            from xgboost import XGBClassifier
        except ImportError:
            return {"trained": False, "error": "xgboost not installed"}
        # Use a fresh feature extractor for training so live state isn't tainted.
        fx_train = FeatureExtractor()
        X, y = [], []
        for ev, label in events:
            f = fx_train.extract(ev)
            X.append([f[k] for k in FEATURE_NAMES]); y.append(int(label))
        X = np.asarray(X); y = np.asarray(y)
        if len(np.unique(y)) < 2:
            return {"trained": False, "error": "need both classes"}
        clf = XGBClassifier(
            n_estimators=120, max_depth=6, learning_rate=0.15,
            objective="binary:logistic", eval_metric="logloss",
            tree_method="hist", n_jobs=2,
        )
        clf.fit(X, y)
        self.xgb = clf
        return {"trained": True, "n": int(len(y)),
                "pos_rate": float((y == 1).mean())}

    # --- scoring ------------------------------------------------------------

    def score(self, ev: Event) -> Score:
        if not self.fitted:
            raise RuntimeError("call fit_baseline() first")
        f = self.fx.extract(ev)
        x = np.array([f[k] for k in FEATURE_NAMES], dtype=float)

        # IsolationForest -> [0,1] anomaly
        df = float(self.iforest.decision_function(x.reshape(1, -1))[0])
        iforest_score = float(np.clip(0.5 - df, 0.0, 1.0))

        # Per-entity z-score
        stats = self.entity_stats[ev.actor]
        if stats.n < 5:
            z_vec = np.zeros_like(x)
        else:
            z_vec = (x - stats.mean) / stats.std()
        z_max = float(np.max(np.abs(z_vec))) if stats.n >= 5 else 0.0
        z_norm = float(np.clip(z_max / 6.0, 0.0, 1.0))
        stats.update(x)

        # Supervised head (optional, lifts precision on known cyber attacks)
        if self.xgb is not None:
            sup = float(self.xgb.predict_proba(x.reshape(1, -1))[0, 1])
        else:
            sup = None

        # Fuse: unsupervised first; if supervised available, weighted blend.
        unsup = 0.5 * iforest_score + 0.5 * z_norm
        if sup is None:
            combined = unsup
        else:
            combined = 0.4 * unsup + 0.6 * sup

        # Top contributing features
        if stats.n >= 5:
            order = np.argsort(-np.abs(z_vec))[:4]
            top = [(FEATURE_NAMES[i], float(z_vec[i])) for i in order]
        else:
            order = np.argsort(-x)[:4]
            top = [(FEATURE_NAMES[i], float(x[i])) for i in order]

        s = Score(
            event=ev, score=combined,
            baseline_z=z_max, isolation_score=iforest_score,
            top_features=top,
        )
        if sup is not None:
            s.rationale = f"sup_proba={sup:.2f}"
        return s
