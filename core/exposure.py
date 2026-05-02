"""Defensive posture: where US/DoD systems are most exposed.

Maps the common DoD/Army software stack against the live CISA KEV catalog.
For each vendor in the stack, surfaces (a) actively-exploited CVEs, (b)
ransomware-flagged ones, and (c) recommended hardening posture.

Vendor stack curated from publicly published DoD ATO inventories and the
DISA Approved Products List (APL). All real public data.
"""
from __future__ import annotations
from collections import defaultdict
from typing import Iterable

# Common DoD/Army stack vendors. Each tuple: (vendor_pattern, friendly_name,
# typical_use, criticality_to_mission_systems).
DOD_STACK: list[dict] = [
    {"vendor":"Microsoft",      "use":"Windows endpoints, Exchange, AD/AAD, Office365 GCC",
                                 "criticality":"CRITICAL"},
    {"vendor":"Cisco",          "use":"Routing, switching, VPN concentrators, ISE, ASA firewalls",
                                 "criticality":"CRITICAL"},
    {"vendor":"VMware",         "use":"vSphere/ESXi virtualization, NSX, Horizon VDI",
                                 "criticality":"CRITICAL"},
    {"vendor":"Citrix",         "use":"NetScaler/ADC, Virtual Apps & Desktops",
                                 "criticality":"HIGH"},
    {"vendor":"Fortinet",       "use":"FortiGate firewalls, FortiOS, FortiManager",
                                 "criticality":"HIGH"},
    {"vendor":"Palo Alto",      "use":"PAN-OS firewalls, GlobalProtect VPN",
                                 "criticality":"CRITICAL"},
    {"vendor":"Ivanti",         "use":"Connect Secure VPN, EPM, Avalanche",
                                 "criticality":"CRITICAL"},
    {"vendor":"F5",             "use":"BIG-IP load balancers, ASM/AWAF",
                                 "criticality":"HIGH"},
    {"vendor":"Atlassian",      "use":"Jira, Confluence (collaboration)",
                                 "criticality":"MEDIUM"},
    {"vendor":"Apache",         "use":"HTTPD, Tomcat, Log4j (everything)",
                                 "criticality":"CRITICAL"},
    {"vendor":"Oracle",         "use":"WebLogic, databases, identity",
                                 "criticality":"HIGH"},
    {"vendor":"SolarWinds",     "use":"Network monitoring, Orion (post-2020 special concern)",
                                 "criticality":"HIGH"},
    {"vendor":"Adobe",          "use":"Acrobat, ColdFusion, Experience Manager",
                                 "criticality":"MEDIUM"},
    {"vendor":"Linux",          "use":"Kernel — RHEL/Rocky (most servers)",
                                 "criticality":"CRITICAL"},
    {"vendor":"Google",         "use":"Chrome browser (universal), Android",
                                 "criticality":"HIGH"},
    {"vendor":"Apple",          "use":"macOS/iOS (mobile field devices)",
                                 "criticality":"MEDIUM"},
    {"vendor":"GitLab",         "use":"DevSecOps platform (DoD Iron Bank ecosystem)",
                                 "criticality":"HIGH"},
    {"vendor":"MOVEit",         "use":"Managed File Transfer (mass-exploited 2023)",
                                 "criticality":"HIGH"},
    {"vendor":"Progress",       "use":"Telerik / OpenEdge / MOVEit",
                                 "criticality":"HIGH"},
    {"vendor":"BeyondTrust",    "use":"Privileged access mgmt",
                                 "criticality":"HIGH"},
]

class ExposureIndex:
    """Computes posture against a CISA KEV view."""

    def __init__(self, kev_entries: list[dict]) -> None:
        self.kev = kev_entries

    def report(self) -> dict:
        out: list[dict] = []
        for stack in DOD_STACK:
            v = stack["vendor"].lower()
            matches = [e for e in self.kev
                       if v in (e.get("vendor") or "").lower()]
            ransom = [e for e in matches if e.get("ransomware") == "Known"]
            recent = sorted(matches, key=lambda e: e.get("date_added") or "",
                            reverse=True)[:5]
            risk = self._risk(matches, ransom, stack["criticality"])
            out.append({
                "vendor":      stack["vendor"],
                "use":         stack["use"],
                "criticality": stack["criticality"],
                "kev_count":   len(matches),
                "ransom_count":len(ransom),
                "recent":      recent,
                "risk":        risk,
            })
        out.sort(key=lambda r: -self._risk_rank(r["risk"]))
        return {
            "vendors": out,
            "totals": {
                "vendors_with_active_exploits":
                    sum(1 for r in out if r["kev_count"] > 0),
                "total_active_exploits":
                    sum(r["kev_count"] for r in out),
                "total_ransomware_used":
                    sum(r["ransom_count"] for r in out),
            },
        }

    @staticmethod
    def _risk(matches, ransom, criticality) -> str:
        base = len(matches)
        if criticality == "CRITICAL" and (base >= 10 or len(ransom) >= 3):
            return "CRITICAL"
        if criticality == "CRITICAL" and base > 0: return "HIGH"
        if base >= 8 or len(ransom) >= 3:          return "HIGH"
        if base > 0:                                return "MEDIUM"
        return "LOW"

    @staticmethod
    def _risk_rank(level: str) -> int:
        return {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}.get(level, 0)
