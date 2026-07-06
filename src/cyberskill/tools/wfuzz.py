"""wfuzz — web fuzzer for directories, path traversal, injection, auth bypass."""
from __future__ import annotations

import re
from typing import Any

from cyberskill.base import BaseTool
from cyberskill.models import OWASPCategory
from cyberskill.registry import registry

_DIR_WORDLIST       = "/usr/share/wordlists/dirb/common.txt"
_TRAVERSAL_WORDLIST = "/usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt"
_SQLI_WORDLIST      = "/usr/share/seclists/Fuzzing/SQLi/Generic-SQLi.txt"
_SSRF_WORDLIST      = "/usr/share/seclists/Fuzzing/SSRF/SSRF-targets.txt"
_AUTH_WORDLIST      = "/usr/share/seclists/Passwords/probable-v2-top1575.txt"
_XSS_WORDLIST       = "/usr/share/seclists/Fuzzing/XSS/XSS-Jhaddix.txt"
_RFI_WORDLIST       = "/usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt"


class WfuzzTool(BaseTool):
    name = "wfuzz"
    binary = "wfuzz"
    description = (
        "Web fuzzer: directory enum, path traversal (A01), injection payloads (A03), "
        "auth bypass (A07), SSRF probing (A10)"
    )
    owasp_categories = frozenset({
        OWASPCategory.A01,
        OWASPCategory.A03,
        OWASPCategory.A07,
        OWASPCategory.A10,
    })

    # Wordlist presets keyed by mode
    _WORDLISTS: dict[str, str] = {
        "dir":       _DIR_WORDLIST,
        "traversal": _TRAVERSAL_WORDLIST,
        "sqli":      _SQLI_WORDLIST,
        "ssrf":      _SSRF_WORDLIST,
        "auth":      _AUTH_WORDLIST,
        "xss":       _XSS_WORDLIST,
        "rfi":       _RFI_WORDLIST,
    }

    def build_command(
        self,
        target: str,
        *,
        mode: str = "dir",
        wordlist: str = "",
        hide_code: str = "404",
        hide_lines: str = "",
        threads: int = 10,
        post_data: str = "",
        header: str = "",
        **_: Any,
    ) -> list[str]:
        """
        mode options:
          dir        — directory enumeration; FUZZ appended to target URL
          traversal  — LFI/path-traversal payloads; FUZZ appended to target URL
          sqli       — SQL injection payloads; target must contain FUZZ or has ?param=
          xss        — reflected XSS payloads; target must contain FUZZ or has ?param=
          rfi        — remote file inclusion payloads; target must contain FUZZ
          ssrf       — SSRF probe URLs; target must contain FUZZ
          auth       — password fuzzing; target must contain FUZZ
          param      — generic param fuzzing; target must contain FUZZ
        """
        wl = wordlist or self._WORDLISTS.get(mode, _DIR_WORDLIST)

        if "FUZZ" not in target:
            if mode in ("sqli", "xss", "rfi", "ssrf", "auth", "param") and "?" in target and "=" in target:
                # Replace the first parameter value with FUZZ for injection modes
                import re as _re
                url = _re.sub(r"(=[^&]*)", "=FUZZ", target, count=1)
            else:
                url = target.rstrip("/") + "/FUZZ"
        else:
            url = target

        cmd = [
            "wfuzz",
            "-c",
            "--hc", hide_code,
            "-t", str(threads),
            "-w", wl,
        ]
        if hide_lines:
            cmd += ["--hl", hide_lines]
        if post_data:
            cmd += ["-d", post_data]
        if header:
            cmd += ["-H", header]
        cmd.append(url)
        return cmd

    def _parse(self, stdout: str, stderr: str, returncode: int) -> dict[str, Any]:
        hits: list[dict[str, str]] = []
        # wfuzz line: "000000001: 200   1 L   7 W   45 Ch  '/admin'"
        pattern = re.compile(
            r"(\d+):\s+(\d+)\s+\d+\s+L\s+\d+\s+W\s+\d+\s+Ch\s+\"(.+?)\""
        )
        for line in stdout.splitlines():
            m = pattern.search(line)
            if m:
                hits.append(
                    {
                        "id": m.group(1),
                        "status": m.group(2),
                        "payload": m.group(3),
                    }
                )
        return {"hits": hits, "total": len(hits)}


registry.register(WfuzzTool)
