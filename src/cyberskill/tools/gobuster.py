"""gobuster — directory and subdomain brute-forcer."""
from __future__ import annotations

import re
from typing import Any

from cyberskill.base import BaseTool
from cyberskill.models import OWASPCategory
from cyberskill.registry import registry

_DEFAULT_WORDLIST = "/usr/share/wordlists/dirb/common.txt"


class GobusterTool(BaseTool):
    name = "gobuster"
    binary = "gobuster"
    description = "Directory/subdomain brute-forcer — discovers unprotected paths and vhosts"
    owasp_categories = frozenset({OWASPCategory.A01})

    def build_command(
        self,
        target: str,
        *,
        mode: str = "dir",
        wordlist: str = _DEFAULT_WORDLIST,
        extensions: str = "php,html,js,txt,bak,zip",
        threads: int = 20,
        status_codes: str = "200,204,301,302,307,401,403",
        follow_redirect: bool = False,
        **_: Any,
    ) -> list[str]:
        """
        mode: 'dir' (directory enum), 'dns' (subdomain enum), 'vhost' (virtual-host enum)
        """
        cmd = [
            "gobuster", mode,
            "-u" if mode != "dns" else "-d", target,
            "-w", wordlist,
            "-t", str(threads),
            "--no-progress",
            "--no-error",
        ]
        if mode == "dir":
            cmd += ["-s", status_codes]
            if extensions:
                cmd += ["-x", extensions]
            if follow_redirect:
                cmd.append("-r")
        return cmd

    def _parse(self, stdout: str, stderr: str, returncode: int) -> dict[str, Any]:
        found: list[dict[str, str]] = []
        # gobuster dir output: "/admin   (Status: 200) [Size: 1234] [--> /admin/]"
        pattern = re.compile(
            r"^(/\S+)\s+\(Status:\s*(\d+)\)(?:\s+\[Size:\s*(\d+)\])?(?:\s+\[-->\s*(.+?)\])?",
        )
        for line in stdout.splitlines():
            m = pattern.match(line.strip())
            if m:
                found.append(
                    {
                        "path": m.group(1),
                        "status": m.group(2),
                        "size": m.group(3) or "",
                        "redirect": m.group(4) or "",
                    }
                )
        return {"found": found, "total": len(found)}


registry.register(GobusterTool)
