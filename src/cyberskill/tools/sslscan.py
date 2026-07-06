"""sslscan — SSL/TLS configuration analyser."""
from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from typing import Any
from urllib.parse import urlparse

from cyberskill.base import BaseTool
from cyberskill.models import OWASPCategory
from cyberskill.registry import registry


def _host_port(target: str) -> str:
    """Convert a URL to host:port format that sslscan expects."""
    p = urlparse(target)
    if p.scheme in ("http", "https"):
        host = p.hostname or target
        port = p.port or (443 if p.scheme == "https" else 80)
        return f"{host}:{port}"
    return target

_WEAK_CIPHERS = frozenset({"rc4", "des", "3des", "export", "null", "anon"})
_WEAK_PROTOCOLS = frozenset({"sslv2", "sslv3", "tlsv1.0", "tlsv1.1"})


class SslscanTool(BaseTool):
    name = "sslscan"
    binary = "sslscan"
    description = (
        "SSL/TLS analyser: weak protocols (SSLv2/3, TLS 1.0/1.1), weak ciphers, "
        "certificate validity and chain trust (A02)"
    )
    owasp_categories = frozenset({OWASPCategory.A02})

    def build_command(
        self,
        target: str,
        *,
        xml_output: bool = True,
        starttls: str = "",
        ipv4_only: bool = False,
        **_: Any,
    ) -> list[str]:
        """
        starttls: protocol for STARTTLS negotiation ('smtp', 'ftp', 'imap', etc.)
        """
        cmd = ["sslscan"]
        if xml_output:
            cmd.append("--xml=-")   # XML to stdout
        if starttls:
            cmd.append(f"--starttls-{starttls}")
        if ipv4_only:
            cmd.append("--ipv4")
        cmd.append(_host_port(target))
        return cmd

    def _parse(self, stdout: str, stderr: str, returncode: int) -> dict[str, Any]:
        # Try XML first; fall back to text parsing
        try:
            return _parse_xml(stdout)
        except ET.ParseError:
            return _parse_text(stdout)


def _parse_xml(raw: str) -> dict[str, Any]:
    root = ET.fromstring(raw)

    ciphers_accepted: list[dict[str, str]] = []
    ciphers_rejected: list[dict[str, str]] = []
    protocols: dict[str, bool] = {}
    cert_info: dict[str, str] = {}

    for cipher in root.findall(".//cipher"):
        status = cipher.get("status", "")
        entry = {
            "cipher": cipher.get("cipher", ""),
            "protocol": cipher.get("sslversion", ""),
            "bits": cipher.get("bits", ""),
            "kex": cipher.get("kex", ""),
        }
        if status == "accepted":
            ciphers_accepted.append(entry)
        else:
            ciphers_rejected.append(entry)

    for proto in root.findall(".//protocol"):
        key = proto.get("type", "") + proto.get("version", "")
        protocols[key] = proto.get("enabled", "0") == "1"

    cert_el = root.find(".//certificate")
    if cert_el is not None:
        cert_info = {
            "subject": cert_el.findtext("subject", ""),
            "issuer": cert_el.findtext("issuer", ""),
            "not_before": cert_el.findtext("not-valid-before", ""),
            "not_after": cert_el.findtext("not-valid-after", ""),
            "signature_algorithm": cert_el.findtext("signature-algorithm", ""),
            "pk_bits": cert_el.findtext("pk[@bits]", ""),
        }

    weak_ciphers = [
        c for c in ciphers_accepted
        if any(w in c["cipher"].lower() for w in _WEAK_CIPHERS)
    ]
    weak_protocols = [
        proto for proto, enabled in protocols.items()
        if enabled and proto.lower() in _WEAK_PROTOCOLS
    ]

    issues: list[str] = []
    for c in weak_ciphers:
        issues.append(f"Weak cipher accepted: {c['cipher']} ({c['protocol']})")
    for p in weak_protocols:
        issues.append(f"Weak protocol enabled: {p}")

    return {
        "protocols": protocols,
        "ciphers_accepted": ciphers_accepted,
        "ciphers_rejected": ciphers_rejected,
        "certificate": cert_info,
        "weak_ciphers": weak_ciphers,
        "weak_protocols": weak_protocols,
        "issues": issues,
        "issue_count": len(issues),
    }


def _parse_text(stdout: str) -> dict[str, Any]:
    """Fallback text parser when XML output is unavailable."""
    issues: list[str] = []
    for line in stdout.splitlines():
        low = line.lower()
        if any(w in low for w in ("rc4", "sslv2", "sslv3", "export", "null cipher", "tls 1.0", "tls 1.1")):
            issues.append(line.strip())
    return {"issues": issues, "raw": stdout, "parse_mode": "text_fallback"}


registry.register(SslscanTool)
