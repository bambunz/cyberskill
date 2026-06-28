"""nikto — web server vulnerability and misconfiguration scanner."""
from __future__ import annotations

import re
from typing import Any

from cyberskill.base import BaseTool
from cyberskill.models import OWASPCategory
from cyberskill.registry import registry


class NiktoTool(BaseTool):
    name = "nikto"
    binary = "nikto"
    description = "Web server scanner: exposed files, misconfigs, outdated software, headers"
    owasp_categories = frozenset({
        OWASPCategory.A01,
        OWASPCategory.A05,
    })

    def build_command(
        self,
        target: str,
        *,
        port: int = 0,
        ssl: bool = False,
        plugins: str = "",
        tuning: str = "",
        max_time: str = "",
        **_: Any,
    ) -> list[str]:
        """
        tuning: nikto tuning options (e.g. '1' for interesting files,
                '2' for misconfigurations, '4' for XSS, '9' for SQL injection)
        """
        cmd = ["nikto", "-h", target, "-nointeractive", "-Format", "txt"]
        if port:
            cmd += ["-p", str(port)]
        if ssl:
            cmd.append("-ssl")
        if plugins:
            cmd += ["-Plugins", plugins]
        if tuning:
            cmd += ["-Tuning", tuning]
        if max_time:
            cmd += ["-maxtime", max_time]
        return cmd

    def _parse(self, stdout: str, stderr: str, returncode: int) -> dict[str, Any]:
        findings: list[dict[str, str]] = []
        server = ""
        osvdb_refs: list[str] = []
        target_ip = ""
        target_port = ""

        for line in stdout.splitlines():
            line = line.strip()

            m_server = re.search(r"Server:\s+(.+)", line)
            if m_server:
                server = m_server.group(1).strip()

            m_target = re.search(r"Target IP:\s+(\S+)", line)
            if m_target:
                target_ip = m_target.group(1)

            m_port = re.search(r"Target Port:\s+(\d+)", line)
            if m_port:
                target_port = m_port.group(1)

            # Finding lines start with + or -
            if line.startswith("+ ") or line.startswith("- "):
                content = line[2:].strip()
                refs = re.findall(r"OSVDB-(\d+)", content)
                osvdb_refs.extend(refs)
                if content:
                    severity = "medium"
                    if any(w in content.lower() for w in ("xss", "sql", "inject", "exec")):
                        severity = "high"
                    elif any(w in content.lower() for w in ("info", "header", "cookie")):
                        severity = "low"
                    findings.append({"finding": content, "severity": severity})

        return {
            "server": server,
            "target_ip": target_ip,
            "target_port": target_port,
            "findings": findings,
            "total_findings": len(findings),
            "osvdb_refs": sorted(set(osvdb_refs)),
        }


registry.register(NiktoTool)
