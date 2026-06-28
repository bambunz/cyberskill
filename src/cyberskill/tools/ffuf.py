"""ffuf — fast web fuzzer for directory and endpoint discovery."""
from __future__ import annotations

import re
from typing import Any

from cyberskill.base import BaseTool
from cyberskill.models import OWASPCategory
from cyberskill.registry import registry

_DEFAULT_WORDLIST = "/usr/share/wordlists/dirb/common.txt"


class FfufTool(BaseTool):
    name = "ffuf"
    binary = "ffuf"
    description = "Fast web fuzzer: directories, vhosts, parameter names, backup files"
    owasp_categories = frozenset({OWASPCategory.A01})

    def build_command(
        self,
        target: str,
        *,
        wordlist: str = _DEFAULT_WORDLIST,
        extensions: str = "php,html,js,txt,bak,zip,old",
        threads: int = 40,
        filter_code: str = "404",
        filter_size: str = "",
        method: str = "GET",
        header: str = "",
        match_code: str = "",
        vhost_mode: bool = False,
        **_: Any,
    ) -> list[str]:
        """
        vhost_mode: fuzz virtual hostnames via Host header instead of URL paths.
        filter_code: comma-separated HTTP status codes to hide from results.
        filter_size: hide responses with this byte length (useful to drop default pages).
        """
        if vhost_mode:
            url = target
            header = f"Host: FUZZ.{target.split('://')[-1].rstrip('/')}"
        else:
            url = target.rstrip("/") + "/FUZZ" if "FUZZ" not in target else target

        cmd = [
            "ffuf",
            "-u", url,
            "-w", wordlist,
            "-t", str(threads),
            "-X", method,
            "-s",             # silent mode (no banner/progress)
        ]

        # Extensions prepend a dot separator automatically
        if extensions and not vhost_mode:
            dot_exts = ",".join(
                e if e.startswith(".") else f".{e}" for e in extensions.split(",")
            )
            cmd += ["-e", dot_exts]

        if filter_code:
            cmd += ["-fc", filter_code]
        if filter_size:
            cmd += ["-fs", filter_size]
        if match_code:
            cmd += ["-mc", match_code]
        if header:
            cmd += ["-H", header]

        return cmd

    def _parse(self, stdout: str, stderr: str, returncode: int) -> dict[str, Any]:
        results: list[dict[str, Any]] = []
        # ffuf default text output (silent mode):
        # /admin                  [Status: 200, Size: 1234, Words: 100, Lines: 50, Duration: 12ms]
        pattern = re.compile(
            r"^(/\S*)\s+\[Status:\s*(\d+),\s*Size:\s*(\d+),\s*Words:\s*(\d+),\s*Lines:\s*(\d+)"
        )
        for line in stdout.splitlines():
            m = pattern.match(line.strip())
            if m:
                results.append(
                    {
                        "path": m.group(1),
                        "status": int(m.group(2)),
                        "size": int(m.group(3)),
                        "words": int(m.group(4)),
                        "lines": int(m.group(5)),
                    }
                )
        return {"results": results, "total": len(results)}


registry.register(FfufTool)
