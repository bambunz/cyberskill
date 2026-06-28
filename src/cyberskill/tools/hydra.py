"""hydra — online password brute-force tool."""
from __future__ import annotations

import re
from typing import Any

from cyberskill.base import BaseTool
from cyberskill.models import OWASPCategory
from cyberskill.registry import registry

_DEFAULT_PASS_LIST = "/usr/share/wordlists/rockyou.txt"


class HydraTool(BaseTool):
    name = "hydra"
    binary = "hydra"
    description = "Online credential brute-forcer: SSH, FTP, HTTP-form, RDP, SMB, and more"
    owasp_categories = frozenset({OWASPCategory.A07})

    def build_command(
        self,
        target: str,
        *,
        service: str = "ssh",
        username: str = "admin",
        userlist: str = "",
        password: str = "",
        passlist: str = _DEFAULT_PASS_LIST,
        port: int = 0,
        tasks: int = 16,
        stop_on_first: bool = True,
        http_form_path: str = "/login",
        http_form_params: str = "user=^USER^&pass=^PASS^:Invalid",
        **_: Any,
    ) -> list[str]:
        """
        service: 'ssh', 'ftp', 'rdp', 'smb', 'http-post-form', 'http-get-form', 'telnet', etc.
        For HTTP form auth set service='http-post-form' and provide http_form_path/params.
        http_form_params format: "<fields>:<invalid-response-indicator>"
        """
        cmd = ["hydra", "-t", str(tasks)]
        if stop_on_first:
            cmd.append("-f")

        if userlist:
            cmd += ["-L", userlist]
        else:
            cmd += ["-l", username]

        if password:
            cmd += ["-p", password]
        else:
            cmd += ["-P", passlist]

        if port:
            cmd += ["-s", str(port)]

        if service in ("http-post-form", "http-get-form"):
            cmd += [target, service, f"{http_form_path}:{http_form_params}"]
        else:
            cmd.append(f"{service}://{target}")

        return cmd

    def _parse(self, stdout: str, stderr: str, returncode: int) -> dict[str, Any]:
        credentials: list[dict[str, str]] = []
        attempts = 0

        for line in stdout.splitlines():
            # "[22][ssh] host: 10.0.0.1  login: admin  password: secret123"
            m = re.search(
                r"\[(\d+)\]\[([^\]]+)\]\s+host:\s+(\S+)\s+login:\s+(\S+)\s+password:\s+(\S+)",
                line,
            )
            if m:
                credentials.append(
                    {
                        "port": m.group(1),
                        "service": m.group(2),
                        "host": m.group(3),
                        "username": m.group(4),
                        "password": m.group(5),
                    }
                )
            m2 = re.search(r"(\d+) valid passwords? found", line)
            if m2:
                attempts = int(m2.group(1))

        return {
            "credentials_found": credentials,
            "total_found": len(credentials),
            "attempts": attempts,
        }


registry.register(HydraTool)
