"""Explainability layer.

Two paths:
  1. Always-on heuristic rationale (template-built from features + ATT&CK).
  2. Optional LLM rationale via Anthropic Claude — used when ANTHROPIC_API_KEY
     is set. Adds a paragraph an operator can read in <5 seconds.

The heuristic path is what runs in the live demo; the LLM path is what makes
the "explainable kill-chain" pitch concrete in Q&A.
"""
from __future__ import annotations
import os
from pathlib import Path
from dotenv import load_dotenv

from .schema import Score
from .enrich import Enricher

load_dotenv(Path(__file__).resolve().parent.parent / ".env")

_TEMPLATE = (
    "{actor} performed {action} on {target} at {when}. "
    "Score {score:.2f} (baseline z={z:.1f}). "
    "Drivers: {drivers}. "
    "{ioc_line}"
    "ATT&CK: {ttps}."
)

def heuristic(score: Score, enricher: Enricher) -> str:
    ev = score.event
    drivers = ", ".join(f"{n} ({v:+.1f})" for n, v in score.top_features[:3])
    ttps = ", ".join(f"{t} {enricher.technique_name(t)}" for t in score.techniques) or "none mapped"
    ioc_line = f"IOC match: {', '.join(score.iocs_hit)}. " if score.iocs_hit else ""
    when = ev.ts.strftime("%H:%M:%S")
    return _TEMPLATE.format(
        actor=ev.actor, action=ev.action, target=ev.target, when=when,
        score=score.score, z=score.baseline_z, drivers=drivers,
        ioc_line=ioc_line, ttps=ttps,
    )

# --- Optional LLM rationale --------------------------------------------------

class LLMExplainer:
    def __init__(self) -> None:
        self.key = os.getenv("ANTHROPIC_API_KEY")
        self.client = None
        if self.key:
            try:
                from anthropic import Anthropic
                self.client = Anthropic(api_key=self.key)
            except Exception:
                self.client = None

    def explain(self, score: Score, enricher: Enricher) -> str:
        if not self.client:
            return ""
        ev = score.event
        ttp_block = "\n".join(
            f"- {t}: {enricher.technique_name(t)}" for t in score.techniques
        ) or "- none"
        feat_block = "\n".join(f"- {n}: {v:+.2f}" for n, v in score.top_features)
        prompt = (
            "You are a SOC analyst writing a 2-sentence explanation for a commander "
            "who has 5 seconds to read it. Be concrete; do not hedge.\n\n"
            f"Event: actor={ev.actor} action={ev.action} target={ev.target} "
            f"type={ev.type} bytes={ev.bytes:.0f} success={ev.success} "
            f"ts={ev.ts.isoformat()}\n"
            f"Anomaly score: {score.score:.2f} (z={score.baseline_z:.1f})\n"
            f"Top behavioral drivers (z-scores):\n{feat_block}\n"
            f"MITRE ATT&CK techniques flagged:\n{ttp_block}\n"
            f"IOC matches: {', '.join(score.iocs_hit) or 'none'}\n\n"
            "Output exactly two sentences. Sentence 1: what likely happened. "
            "Sentence 2: recommended immediate action."
        )
        try:
            msg = self.client.messages.create(
                model="claude-haiku-4-5-20251001",
                max_tokens=200,
                messages=[{"role": "user", "content": prompt}],
            )
            return "".join(b.text for b in msg.content if hasattr(b, "text")).strip()
        except Exception as e:
            return f"(llm error: {e})"
