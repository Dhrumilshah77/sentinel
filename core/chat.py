"""Conversational analyst — Claude with intel sources as RAG context.

The chatbot is grounded: every turn is given a fresh slice of the relevant
agency data so it cites real CVEs, real APT groups, real OFAC entries,
real IOCs. Without grounding it would hallucinate.
"""
from __future__ import annotations
import os
from pathlib import Path
from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parent.parent / ".env")

SYSTEM = (
    "You are SENTINEL, a US Army cyber intelligence analyst assistant. "
    "Answer the commander's question CONCISELY and ACTIONABLY. Always cite "
    "the agency source for any specific claim (CISA KEV, MITRE ATT&CK, OFAC, "
    "FBI Cyber Most Wanted, abuse.ch, NVD, FIRST EPSS). If you don't have "
    "the data in your context, say so — never invent CVE IDs, APT names, or "
    "bounties. Use plain language. Avoid jargon when possible. Respond in "
    "≤180 words unless asked for detail. When recommending actions, format "
    "them as imperative bullets the commander can execute."
)

class Chat:
    def __init__(self) -> None:
        self.key = os.getenv("ANTHROPIC_API_KEY")
        self.client = None
        if self.key:
            try:
                from anthropic import Anthropic
                self.client = Anthropic(api_key=self.key)
            except Exception:
                self.client = None

    def _build_context(self, intel, sanctions, exposure, q: str) -> str:
        ql = (q or "").lower()
        # Search every source for relevance to the question
        hits = intel.search(q) if q else {"groups": [], "kev": [], "techniques": [], "iocs": []}
        groups = hits.get("groups") or [g for g in intel.mitre.groups if g.get("country")][:6]
        kev = hits.get("kev") or sorted(
            intel.kev.entries, key=lambda v: v.get("date_added") or "", reverse=True
        )[:6]
        techs = hits.get("techniques") or []
        iocs = hits.get("iocs") or intel.ioc.live_iocs[:5]
        sdn_hits = sanctions.search(q, limit=5) if q else []

        # Wanted matches
        from .sanctions import WANTED, FUNDING_LINKS
        wanted_hits = [w for w in WANTED if ql and (
            ql in w["name"].lower()
            or ql in w.get("country", "").lower()
            or any(ql in a.lower() for a in w.get("linked_apts", []))
        )][:4]
        funding_hits = [f for f in FUNDING_LINKS if ql and (
            ql in f["src"].lower() or ql in f["dst"].lower() or ql in f["evidence"].lower()
        )][:4]

        # Exposure context — just top vendors with critical risk
        report = exposure.report() if exposure else {"vendors": []}
        critical_exposure = [v for v in report.get("vendors", [])
                             if v["risk"] in ("CRITICAL", "HIGH")][:6]

        parts = ["=== RELEVANT INTEL CONTEXT ==="]
        if groups:
            parts.append("APT GROUPS (MITRE ATT&CK):")
            for g in groups[:6]:
                parts.append(f"  - {g['name']} | country={g.get('country') or '?'} | actor={g.get('actor') or '—'}")
        if kev:
            parts.append("ACTIVELY EXPLOITED CVES (CISA KEV):")
            for v in kev[:6]:
                rs = " RANSOMWARE" if v.get("ransomware") == "Known" else ""
                parts.append(f"  - {v['cve']} {v['vendor']} {v['product']} — {v['name']}{rs}")
        if iocs:
            parts.append("LIVE MALWARE IOCS (abuse.ch ThreatFox, last 7d):")
            for i in iocs[:4]:
                parts.append(f"  - {i.get('type')} {i.get('ioc')} | malware={i.get('malware')}")
        if sdn_hits:
            parts.append("OFAC SANCTIONS (US Treasury SDN matches):")
            for e in sdn_hits[:4]:
                parts.append(f"  - {e['name']} | program={e['program']} | type={e['type']}")
        if wanted_hits:
            parts.append("FBI/STATE DEPT WANTED (with bounties):")
            for w in wanted_hits:
                parts.append(f"  - {w['name']} | {w['unit']} ({w['country']}) | bounty=${w['bounty_usd']:,} | {w['indictment']}")
        if funding_hits:
            parts.append("FUNDING / CRIMINAL LINKAGES (DoJ + Treasury attribution):")
            for f in funding_hits:
                parts.append(f"  - {f['src']} → {f['dst']} via {f['via']} | {f['evidence']}")
        if critical_exposure:
            parts.append("OUR EXPOSURE (DoD stack × CISA KEV):")
            for v in critical_exposure:
                parts.append(f"  - {v['vendor']} ({v['use']}) | {v['kev_count']} active CVEs, {v['ransom_count']} ransomware-used | risk={v['risk']}")
        if techs:
            parts.append("MITRE TECHNIQUES MATCHED:")
            for t in techs[:6]:
                parts.append(f"  - {t['id']} {t['name']}")
        return "\n".join(parts)

    def reply(self, history: list[dict], intel, sanctions, exposure, q: str) -> str:
        if not self.client:
            # Even without an LLM, return a real, useful synthesis from the
            # structured sources so the demo is never empty.
            ctx = self._build_context(intel, sanctions, exposure, q)
            return (
                "[ANALYST OFFLINE — direct lookup, no LLM synthesis]\n"
                "Set ANTHROPIC_API_KEY in .env for conversational answers.\n"
                "----\n"
                + ctx
            )
        ctx = self._build_context(intel, sanctions, exposure, q)
        msgs = []
        for m in history[-6:]:   # keep last few turns
            if m.get("role") in ("user","assistant") and m.get("content"):
                msgs.append({"role": m["role"], "content": m["content"]})
        msgs.append({
            "role": "user",
            "content": f"{ctx}\n\n=== COMMANDER QUESTION ===\n{q}",
        })
        try:
            resp = self.client.messages.create(
                model="claude-haiku-4-5-20251001",
                max_tokens=600,
                system=SYSTEM,
                messages=msgs,
            )
            return "".join(b.text for b in resp.content if hasattr(b, "text")).strip()
        except Exception as e:
            return f"(LLM error: {e})"
