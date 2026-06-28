"""sqlmap — automated SQL injection detection and exploitation."""
from __future__ import annotations

import re
from typing import Any

from cyberskill.base import BaseTool
from cyberskill.models import OWASPCategory
from cyberskill.registry import registry


class SqlmapTool(BaseTool):
    name = "sqlmap"
    binary = "sqlmap"
    description = "SQL injection scanner: boolean/time-based blind, error-based, UNION, stacked"
    owasp_categories = frozenset({OWASPCategory.A03})

    def build_command(
        self,
        target: str,
        *,
        data: str = "",
        cookie: str = "",
        level: int = 1,
        risk: int = 1,
        dbms: str = "",
        enumerate_dbs: bool = True,
        enumerate_tables: bool = False,
        dump: bool = False,
        technique: str = "",
        **_: Any,
    ) -> list[str]:
        cmd = [
            "sqlmap",
            "-u", target,
            "--batch",
            "--level", str(level),
            "--risk", str(risk),
            "--output-dir", "/tmp/sqlmap_out",
        ]
        if data:
            cmd += ["--data", data]
        if cookie:
            cmd += ["--cookie", cookie]
        if dbms:
            cmd += ["--dbms", dbms]
        if technique:
            cmd += ["--technique", technique]
        if enumerate_dbs:
            cmd.append("--dbs")
        if enumerate_tables:
            cmd.append("--tables")
        if dump:
            cmd.append("--dump")
        return cmd

    def _parse(self, stdout: str, stderr: str, returncode: int) -> dict[str, Any]:
        vulnerable_params: list[str] = []
        databases: list[str] = []
        tables: list[str] = []
        injection_types: list[str] = []

        for line in stdout.splitlines():
            # "Parameter: id (GET)" / "Parameter: username (POST)"
            m = re.search(r"Parameter:\s+(\S+)\s+\(", line)
            if m:
                vulnerable_params.append(m.group(1))

            # "Type: boolean-based blind"
            m2 = re.search(r"^\s+Type:\s+(.+)", line)
            if m2:
                injection_types.append(m2.group(1).strip())

            # "[*] information_schema"
            m3 = re.match(r"\[\*\]\s+(\S+)", line)
            if m3 and "available databases" not in line.lower():
                val = m3.group(1)
                if "." in val:
                    tables.append(val)
                else:
                    databases.append(val)

        return {
            "vulnerable": bool(vulnerable_params),
            "vulnerable_parameters": sorted(set(vulnerable_params)),
            "injection_types": sorted(set(injection_types)),
            "databases": databases,
            "tables": tables,
        }


registry.register(SqlmapTool)
