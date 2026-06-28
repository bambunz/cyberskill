"""Data models shared across cyberskill."""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import StrEnum
from typing import Any


class OWASPCategory(StrEnum):
    A01 = "A01"
    A02 = "A02"
    A03 = "A03"
    A04 = "A04"
    A05 = "A05"
    A06 = "A06"
    A07 = "A07"
    A08 = "A08"
    A09 = "A09"
    A10 = "A10"

    @property
    def label(self) -> str:
        return _LABELS[self]

    @property
    def description(self) -> str:
        return _DESCRIPTIONS[self]


_LABELS: dict[OWASPCategory, str] = {
    OWASPCategory.A01: "A01:2021 – Broken Access Control",
    OWASPCategory.A02: "A02:2021 – Cryptographic Failures",
    OWASPCategory.A03: "A03:2021 – Injection",
    OWASPCategory.A04: "A04:2021 – Insecure Design",
    OWASPCategory.A05: "A05:2021 – Security Misconfiguration",
    OWASPCategory.A06: "A06:2021 – Vulnerable and Outdated Components",
    OWASPCategory.A07: "A07:2021 – Identification and Authentication Failures",
    OWASPCategory.A08: "A08:2021 – Software and Data Integrity Failures",
    OWASPCategory.A09: "A09:2021 – Security Logging and Monitoring Failures",
    OWASPCategory.A10: "A10:2021 – Server-Side Request Forgery (SSRF)",
}

_DESCRIPTIONS: dict[OWASPCategory, str] = {
    OWASPCategory.A01: (
        "Access control enforces policy such that users cannot act outside of their "
        "intended permissions. Failures lead to unauthorised information disclosure, "
        "modification, or destruction of all data, or performing a business function "
        "outside the user's limits."
    ),
    OWASPCategory.A02: (
        "Previously known as Sensitive Data Exposure. The focus is on failures related "
        "to cryptography (or lack thereof) which often lead to exposure of sensitive "
        "data including passwords, credit card numbers, health records, and PII."
    ),
    OWASPCategory.A03: (
        "An application is vulnerable when user-supplied data is not validated, filtered, "
        "or sanitised by the application. Includes SQL, NoSQL, OS, LDAP injection, "
        "XSS, and template injection."
    ),
    OWASPCategory.A04: (
        "Insecure design is a broad category representing different weaknesses expressed "
        "as missing or ineffective control design. Moving from detection to prevention "
        "requires threat modelling integrated into development."
    ),
    OWASPCategory.A05: (
        "Security misconfiguration is the most commonly seen issue. Without a concerted "
        "repeatable hardening process, systems are at higher risk. Includes unnecessary "
        "features, default accounts, overly permissive cloud storage, and missing security headers."
    ),
    OWASPCategory.A06: (
        "Components such as libraries, frameworks, and software modules run with the same "
        "privileges as the application. If a vulnerable component is exploited, such an "
        "attack can facilitate serious data loss or server takeover."
    ),
    OWASPCategory.A07: (
        "Confirmation of the user's identity, authentication, and session management is "
        "critical. Weaknesses may allow attackers to assume other users' identities "
        "temporarily or permanently via credential stuffing, brute force, and stolen sessions."
    ),
    OWASPCategory.A08: (
        "Software and data integrity failures relate to code and infrastructure that does "
        "not protect against integrity violations. Includes insecure deserialisation, "
        "unsigned auto-updates, and CI/CD pipeline compromises."
    ),
    OWASPCategory.A09: (
        "Without logging and monitoring breaches cannot be detected. Insufficient logging, "
        "monitoring, and alerting occurs at any time. Attackers rely on the lack of monitoring "
        "to achieve their goals before detection."
    ),
    OWASPCategory.A10: (
        "SSRF flaws occur whenever a web application fetches a remote resource without "
        "validating the user-supplied URL. An attacker can coerce the application to send "
        "a crafted request to an unexpected destination, even behind firewalls or VPNs."
    ),
}


@dataclass(slots=True)
class ToolResult:
    tool_name: str
    target: str
    command: str
    stdout: str
    stderr: str
    returncode: int
    duration_seconds: float
    owasp_categories: frozenset[OWASPCategory]
    structured: dict[str, Any] = field(default_factory=dict)
    error: str | None = None

    @property
    def success(self) -> bool:
        return self.returncode == 0 and self.error is None

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": self.tool_name,
            "target": self.target,
            "command": self.command,
            "success": self.success,
            "returncode": self.returncode,
            "duration_seconds": round(self.duration_seconds, 3),
            "owasp_categories": [c.label for c in sorted(self.owasp_categories)],
            "structured": self.structured,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "error": self.error,
        }


@dataclass(slots=True)
class ScanReport:
    target: str
    results: list[ToolResult]
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "timestamp": self.timestamp.isoformat(),
            "total_tools": len(self.results),
            "successful_tools": sum(1 for r in self.results if r.success),
            "results": [r.to_dict() for r in self.results],
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)
