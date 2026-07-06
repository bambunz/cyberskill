"""Chained scan orchestrator — each phase feeds intelligence into the next."""
from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

from cyberskill.intel import (
    AuthService,
    DBService,
    WebIntel,
    WebTarget,
    extract_from_nmap,
    extract_from_nikto,
    extract_paths_from_ffuf,
    extract_paths_from_gobuster,
    is_url_target,
    merge_paths_into_intel,
    target_has_params,
)
from cyberskill.models import ToolResult


# ---------------------------------------------------------------------------
# Result container
# ---------------------------------------------------------------------------

@dataclass
class ChainedScanResult:
    target: str
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    phases: dict[str, list[ToolResult]] = field(default_factory=dict)
    web_targets: list[WebTarget] = field(default_factory=list)
    auth_services: list[AuthService] = field(default_factory=list)
    db_services: list[DBService] = field(default_factory=list)
    web_intel: list[WebIntel] = field(default_factory=list)

    def all_results(self) -> list[ToolResult]:
        out: list[ToolResult] = []
        for results in self.phases.values():
            out.extend(results)
        return out


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------

class ChainingOrchestrator:
    """Runs tools in dependency order, passing each phase's findings forward.

    Phase 1 — Network recon:   nmap
    Phase 2 — Web fingerprint: nikto · sslscan · ffuf  (per web target found)
    Phase 3 — Vuln scanning:   nuclei (CMS/tech tags) · gobuster (extra paths)
    Phase 4 — Injection:       sqlmap · wfuzz (sqli/traversal/xss/rfi) · commix
    Phase 5 — Auth testing:    hydra (SSH/FTP network + HTTP form login pages)

    Each phase is skipped gracefully if no relevant targets were found or if the
    required binary is not installed.
    """

    def __init__(self, timeout: int = 300, concurrency: int = 3) -> None:
        self._timeout = timeout
        self._sem = asyncio.Semaphore(concurrency)

    # ------------------------------------------------------------------ #
    # Public entry point
    # ------------------------------------------------------------------ #

    async def run(self, target: str) -> ChainedScanResult:
        result = ChainedScanResult(target=target)
        url_mode = is_url_target(target)

        # ---- Phase 1: Network recon (nmap) — skip if target is already a URL ----
        if not url_mode:
            p1 = await self._phase1_recon(target)
            result.phases["phase1_recon"] = p1
            for r in p1:
                if r.tool_name == "nmap" and r.success:
                    web, auth, dbs = extract_from_nmap(r)
                    result.web_targets.extend(web)
                    result.auth_services.extend(auth)
                    result.db_services.extend(dbs)
        else:
            # Treat the URL itself as a single web target
            parsed = urlparse(target)
            ssl = parsed.scheme == "https"
            port = parsed.port or (443 if ssl else 80)
            result.web_targets.append(
                WebTarget(url=target, host=parsed.hostname or target, port=port, ssl=ssl)
            )

        # ---- Phase 2: Web fingerprinting (nikto, sslscan, ffuf) ----
        if result.web_targets:
            p2 = await self._phase2_web_fingerprint(result.web_targets)
            result.phases["phase2_web_fingerprint"] = p2
            for wt in result.web_targets:
                intel = WebIntel(base_url=wt.url)
                for r in p2:
                    if r.tool_name == "nikto" and r.target == wt.host and r.success:
                        intel = extract_from_nikto(r, base_url=wt.url)
                    elif r.tool_name == "ffuf" and wt.url in r.target and r.success:
                        merge_paths_into_intel(intel, extract_paths_from_ffuf(r))
                    elif r.tool_name == "gobuster" and wt.url in r.target and r.success:
                        merge_paths_into_intel(intel, extract_paths_from_gobuster(r))
                # If original target has params, add it to param_urls
                if target_has_params(target) and target not in intel.param_urls:
                    intel.param_urls.append(target)
                result.web_intel.append(intel)

        # ---- Phase 3: Targeted vulnerability scanning (nuclei, gobuster) ----
        if result.web_targets and result.web_intel:
            p3 = await self._phase3_vuln_scan(result.web_targets, result.web_intel)
            result.phases["phase3_vuln_scan"] = p3

        # ---- Phase 4: Injection testing (sqlmap, wfuzz, commix) ----
        injection_urls = _collect_injection_targets(result)
        if injection_urls:
            p4 = await self._phase4_injection(injection_urls)
            result.phases["phase4_injection"] = p4

        # ---- Phase 5: Auth / credential testing (hydra) ----
        login_targets = _collect_auth_targets(result)
        if login_targets:
            p5 = await self._phase5_auth(login_targets)
            result.phases["phase5_auth"] = p5

        return result

    # ------------------------------------------------------------------ #
    # Phase implementations
    # ------------------------------------------------------------------ #

    async def _phase1_recon(self, target: str) -> list[ToolResult]:
        from cyberskill.tools.nmap import NmapTool
        return [await self._run(NmapTool(), target, os_detect=True, ports="1-65535")]

    async def _phase2_web_fingerprint(self, web_targets: list[WebTarget]) -> list[ToolResult]:
        from cyberskill.tools.nikto import NiktoTool
        from cyberskill.tools.sslscan import SslscanTool
        from cyberskill.tools.ffuf import FfufTool

        tasks: list[asyncio.Task] = []

        async def _run_task(tool, tgt, **kw) -> ToolResult:
            return await self._run(tool, tgt, **kw)

        async with asyncio.TaskGroup() as tg:
            for wt in web_targets:
                tasks.append(tg.create_task(_run_task(NiktoTool(), wt.host, port=wt.port, ssl=wt.ssl)))
                tasks.append(tg.create_task(_run_task(FfufTool(), wt.url)))
                if wt.ssl:
                    tasks.append(tg.create_task(_run_task(SslscanTool(), wt.host)))

        return [t.result() for t in tasks]

    async def _phase3_vuln_scan(
        self, web_targets: list[WebTarget], web_intel: list[WebIntel]
    ) -> list[ToolResult]:
        from cyberskill.tools.nuclei import NucleiTool
        from cyberskill.tools.gobuster import GobusterTool

        tasks: list[asyncio.Task] = []

        async def _run_task(tool, tgt, **kw) -> ToolResult:
            return await self._run(tool, tgt, **kw)

        async with asyncio.TaskGroup() as tg:
            for wt, intel in zip(web_targets, web_intel):
                tags = ",".join(intel.nuclei_tags) if intel.nuclei_tags else ""
                # Run nuclei per web target — include severity info and matched tags
                tasks.append(tg.create_task(_run_task(
                    NucleiTool(), wt.url,
                    tags=tags,
                    severity="low,medium,high,critical",
                )))
                # Extra directory brute-force — gobuster is faster on large sets
                tasks.append(tg.create_task(_run_task(GobusterTool(), wt.url)))

        return [t.result() for t in tasks]

    async def _phase4_injection(self, urls: list[str]) -> list[ToolResult]:
        from cyberskill.tools.sqlmap import SqlmapTool
        from cyberskill.tools.wfuzz import WfuzzTool
        from cyberskill.tools.commix import CommixTool

        tasks: list[asyncio.Task] = []

        async def _run_task(tool, tgt, **kw) -> ToolResult:
            return await self._run(tool, tgt, **kw)

        async with asyncio.TaskGroup() as tg:
            for url in urls:
                # SQL injection
                tasks.append(tg.create_task(_run_task(SqlmapTool(), url, level=2, risk=2)))
                # Command injection
                tasks.append(tg.create_task(_run_task(CommixTool(), url)))
                # Wfuzz — sqli payloads on each param
                tasks.append(tg.create_task(_run_task(WfuzzTool(), url, mode="sqli")))
                # Path traversal / LFI on the base path
                base = url.split("?")[0]
                tasks.append(tg.create_task(_run_task(WfuzzTool(), base, mode="traversal")))
                # XSS probing
                tasks.append(tg.create_task(_run_task(WfuzzTool(), url, mode="xss")))
                # RFI probing
                tasks.append(tg.create_task(_run_task(WfuzzTool(), url, mode="rfi")))

        return [t.result() for t in tasks]

    async def _phase5_auth(
        self, targets: list[dict[str, Any]]
    ) -> list[ToolResult]:
        from cyberskill.tools.hydra import HydraTool

        tasks: list[asyncio.Task] = []

        async def _run_task(tool, tgt, **kw) -> ToolResult:
            return await self._run(tool, tgt, **kw)

        async with asyncio.TaskGroup() as tg:
            for t in targets:
                kw = {k: v for k, v in t.items() if k != "target"}
                tasks.append(tg.create_task(_run_task(HydraTool(), t["target"], **kw)))

        return [t.result() for t in tasks]

    # ------------------------------------------------------------------ #
    # Internal helpers
    # ------------------------------------------------------------------ #

    async def _run(self, tool, target: str, **options) -> ToolResult:
        async with self._sem:
            return await tool.run(target, timeout=self._timeout, **options)


# ---------------------------------------------------------------------------
# Target collection helpers
# ---------------------------------------------------------------------------

def _collect_injection_targets(result: ChainedScanResult) -> list[str]:
    """Return URLs that have query parameters and should undergo injection testing."""
    urls: list[str] = []
    for intel in result.web_intel:
        for url in intel.param_urls:
            if url not in urls:
                urls.append(url)
    # Also check the original target
    if target_has_params(result.target) and result.target not in urls:
        urls.append(result.target)
    return urls


def _collect_auth_targets(result: ChainedScanResult) -> list[dict[str, Any]]:
    """Build hydra target dicts from network services and discovered login paths."""
    targets: list[dict[str, Any]] = []

    # Network-layer services (SSH, FTP, RDP, SMB)
    for svc in result.auth_services:
        if svc.service in ("ssh", "ftp", "telnet", "rdp", "smb"):
            targets.append({
                "target": svc.host,
                "service": svc.service,
                "port": svc.port,
            })

    # HTTP form login pages discovered by nikto / ffuf
    for wt, intel in zip(result.web_targets, result.web_intel):
        for path in intel.login_paths:
            url = wt.host
            port = wt.port
            service = "https-form" if wt.ssl else "http-post-form"
            targets.append({
                "target": url,
                "service": service,
                "port": port,
                "http_form_path": path,
                "http_form_params": "username=^USER^&password=^PASS^:Invalid",
            })

    return targets
