"""nuclei — template-based vulnerability scanner with CVE and misconfiguration coverage."""
from __future__ import annotations

import json as _json
from typing import Any

from cyberskill.base import BaseTool
from cyberskill.models import OWASPCategory
from cyberskill.registry import registry


class NucleiTool(BaseTool):
    name = "nuclei"
    binary = "nuclei"
    description = (
        "Template-based scanner: CVEs, misconfigs, exposed panels, SSRF, "
        "integrity checks, log/monitor gaps (broadest OWASP coverage)"
    )
    owasp_categories = frozenset({
        OWASPCategory.A04,
        OWASPCategory.A05,
        OWASPCategory.A06,
        OWASPCategory.A08,
        OWASPCategory.A09,
        OWASPCategory.A10,
    })

    def build_command(
        self,
        target: str,
        *,
        severity: str = "low,medium,high,critical",
        tags: str = "",
        templates: str = "",
        exclude_tags: str = "dos",
        rate_limit: int = 150,
        concurrency: int = 25,
        **_: Any,
    ) -> list[str]:
        """
        severity:     comma-separated (info,low,medium,high,critical)
        tags:         comma-separated template tags to filter (e.g. "cve,ssrf,lfi")
        templates:    path to template file/dir; default uses nuclei's community templates
        exclude_tags: always exclude these (default: dos — avoids disruption)
        """
        cmd = [
            "nuclei",
            "-u", target,
            "-j",                       # JSON output, one object per line
            "-severity", severity,
            "-rate-limit", str(rate_limit),
            "-c", str(concurrency),
            "-silent",
            "-no-color",
        ]
        if tags:
            cmd += ["-tags", tags]
        if templates:
            cmd += ["-t", templates]
        if exclude_tags:
            cmd += ["-etags", exclude_tags]
        return cmd

    def _parse(self, stdout: str, stderr: str, returncode: int) -> dict[str, Any]:
        findings: list[dict[str, Any]] = []
        by_severity: dict[str, int] = {}
        by_type: dict[str, int] = {}

        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = _json.loads(line)
            except _json.JSONDecodeError:
                continue

            info = obj.get("info", {})
            severity = info.get("severity", "unknown").lower()
            finding_type = obj.get("type", "unknown")

            findings.append(
                {
                    "template_id": obj.get("template-id", ""),
                    "name": info.get("name", ""),
                    "severity": severity,
                    "type": finding_type,
                    "matched_at": obj.get("matched-at", ""),
                    "tags": info.get("tags", []),
                    "description": info.get("description", ""),
                    "reference": info.get("reference", []),
                    "curl_command": obj.get("curl-command", ""),
                }
            )
            by_severity[severity] = by_severity.get(severity, 0) + 1
            by_type[finding_type] = by_type.get(finding_type, 0) + 1

        return {
            "findings": findings,
            "total": len(findings),
            "by_severity": by_severity,
            "by_type": by_type,
        }


registry.register(NucleiTool)
