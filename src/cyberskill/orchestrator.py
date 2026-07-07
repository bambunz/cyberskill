"""Chained scan orchestrator — each phase feeds intelligence into the next."""
from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable
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

    Phase 1 — Network recon:   nmap (all 65535 ports; always runs even for URLs)
    Phase 2 — Web fingerprint: nikto · sslscan · ffuf  (per web target found)
    Phase 3 — Vuln scanning:   nuclei (CMS/tech tags) · gobuster (extra paths)
    Phase 4 — Injection:       sqlmap · wfuzz (sqli/traversal/xss/rfi) · commix
    Phase 5 — Auth testing:    hydra (SSH/FTP network + HTTP form login pages)

    Each phase is skipped gracefully if no relevant targets were found or if the
    required binary is not installed.
    """

    def __init__(
        self,
        timeout: int = 300,
        concurrency: int = 3,
        progress_cb: Callable[[str], None] | None = None,
    ) -> None:
        self._timeout = timeout
        self._sem = asyncio.Semaphore(concurrency)
        self._emit = progress_cb or (lambda _: None)

    # ------------------------------------------------------------------ #
    # Public entry point
    # ------------------------------------------------------------------ #

    async def run(self, target: str) -> ChainedScanResult:
        result = ChainedScanResult(target=target)
        url_mode = is_url_target(target)

        # Derive the hostname to give nmap (nmap needs a bare host, not a URL)
        if url_mode:
            parsed = urlparse(target)
            nmap_host = parsed.hostname or target
            ssl = parsed.scheme == "https"
            port = parsed.port or (443 if ssl else 80)
            # Pre-seed the primary URL as a web target so phase 2 always runs it
            result.web_targets.append(
                WebTarget(url=target, host=nmap_host, port=port, ssl=ssl)
            )
        else:
            nmap_host = target

        # ---- Phase 1: Full-port network recon (nmap) — always runs ----
        self._emit(f"\n[Phase 1] Network recon — scanning all ports on {nmap_host}")
        p1 = await self._phase1_recon(nmap_host)
        result.phases["phase1_recon"] = p1
        for r in p1:
            if r.tool_name == "nmap" and r.success:
                web, auth, dbs = extract_from_nmap(r)
                self._emit(
                    f"  → found {len(web)} web target(s), "
                    f"{len(auth)} auth service(s), {len(dbs)} DB service(s)"
                )
                # Merge nmap-discovered web targets (skip the pre-seeded primary if already there)
                for wt in web:
                    if not _url_in_list(wt.url, result.web_targets):
                        result.web_targets.append(wt)
                result.auth_services.extend(auth)
                result.db_services.extend(dbs)

        # ---- Phase 2: Web fingerprinting (nikto, sslscan, ffuf) ----
        if result.web_targets:
            self._emit(
                f"\n[Phase 2] Web fingerprinting — {len(result.web_targets)} target(s): "
                + ", ".join(wt.url for wt in result.web_targets)
            )
            p2 = await self._phase2_web_fingerprint(result.web_targets)
            result.phases["phase2_web_fingerprint"] = p2

            for wt in result.web_targets:
                intel = WebIntel(base_url=wt.url)
                for r in p2:
                    if r.tool_name == "nikto" and wt.host in r.target and r.success:
                        intel = extract_from_nikto(r, base_url=wt.url)
                    elif r.tool_name in ("ffuf", "gobuster") and wt.url in r.target and r.success:
                        paths = (
                            extract_paths_from_ffuf(r)
                            if r.tool_name == "ffuf"
                            else extract_paths_from_gobuster(r)
                        )
                        merge_paths_into_intel(intel, paths)
                if target_has_params(target) and target not in intel.param_urls:
                    intel.param_urls.append(target)
                result.web_intel.append(intel)
                if intel.cms:
                    self._emit(f"  → CMS detected: {intel.cms} on {wt.url}")
                if intel.technologies:
                    self._emit(f"  → Technologies: {', '.join(intel.technologies)} on {wt.url}")

        # ---- Phase 3: Targeted vulnerability scanning (nuclei, gobuster) ----
        if result.web_targets and result.web_intel:
            self._emit(
                f"\n[Phase 3] Vulnerability scanning — nuclei + gobuster on "
                f"{len(result.web_targets)} target(s)"
            )
            p3 = await self._phase3_vuln_scan(result.web_targets, result.web_intel)
            result.phases["phase3_vuln_scan"] = p3
            # Absorb any new paths discovered by gobuster into intel
            for wt, intel in zip(result.web_targets, result.web_intel):
                for r in p3:
                    if r.tool_name == "gobuster" and wt.url in r.target and r.success:
                        merge_paths_into_intel(intel, extract_paths_from_gobuster(r))

        # ---- Phase 4: Injection testing (sqlmap, wfuzz, commix) ----
        injection_urls = _collect_injection_targets(result)
        if injection_urls:
            self._emit(
                f"\n[Phase 4] Injection testing — sqlmap + wfuzz + commix on "
                f"{len(injection_urls)} URL(s) with parameters"
            )
            p4 = await self._phase4_injection(injection_urls)
            result.phases["phase4_injection"] = p4
        else:
            self._emit("\n[Phase 4] Injection testing — skipped (no parameterised URLs found)")

        # ---- Phase 5: Auth / credential testing (hydra) ----
        login_targets = _collect_auth_targets(result)
        if login_targets:
            self._emit(
                f"\n[Phase 5] Auth brute-force — hydra on {len(login_targets)} target(s)"
            )
            p5 = await self._phase5_auth(login_targets)
            result.phases["phase5_auth"] = p5
        else:
            self._emit("\n[Phase 5] Auth brute-force — skipped (no auth targets found)")

        self._emit("\n[Done] All phases complete.\n")
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

        async def _task(tool, tgt, **kw) -> ToolResult:
            return await self._run(tool, tgt, **kw)

        async with asyncio.TaskGroup() as tg:
            for wt in web_targets:
                tasks.append(tg.create_task(_task(NiktoTool(), wt.host, port=wt.port, ssl=wt.ssl)))
                tasks.append(tg.create_task(_task(FfufTool(), wt.url)))
                if wt.ssl:
                    tasks.append(tg.create_task(_task(SslscanTool(), wt.host)))

        return [t.result() for t in tasks]

    async def _phase3_vuln_scan(
        self, web_targets: list[WebTarget], web_intel: list[WebIntel]
    ) -> list[ToolResult]:
        from cyberskill.tools.nuclei import NucleiTool
        from cyberskill.tools.gobuster import GobusterTool

        tasks: list[asyncio.Task] = []

        async def _task(tool, tgt, **kw) -> ToolResult:
            return await self._run(tool, tgt, **kw)

        async with asyncio.TaskGroup() as tg:
            for wt, intel in zip(web_targets, web_intel):
                tags = ",".join(intel.nuclei_tags) if intel.nuclei_tags else ""
                tasks.append(tg.create_task(_task(
                    NucleiTool(), wt.url,
                    tags=tags,
                    severity="low,medium,high,critical",
                )))
                tasks.append(tg.create_task(_task(GobusterTool(), wt.url)))

        return [t.result() for t in tasks]

    async def _phase4_injection(self, urls: list[str]) -> list[ToolResult]:
        from cyberskill.tools.sqlmap import SqlmapTool
        from cyberskill.tools.wfuzz import WfuzzTool
        from cyberskill.tools.commix import CommixTool

        tasks: list[asyncio.Task] = []

        async def _task(tool, tgt, **kw) -> ToolResult:
            return await self._run(tool, tgt, **kw)

        async with asyncio.TaskGroup() as tg:
            for url in urls:
                tasks.append(tg.create_task(_task(SqlmapTool(), url, level=2, risk=2)))
                tasks.append(tg.create_task(_task(CommixTool(), url)))
                tasks.append(tg.create_task(_task(WfuzzTool(), url, mode="sqli")))
                base = url.split("?")[0]
                tasks.append(tg.create_task(_task(WfuzzTool(), base, mode="traversal")))
                tasks.append(tg.create_task(_task(WfuzzTool(), url, mode="xss")))
                tasks.append(tg.create_task(_task(WfuzzTool(), url, mode="rfi")))

        return [t.result() for t in tasks]

    async def _phase5_auth(self, targets: list[dict[str, Any]]) -> list[ToolResult]:
        from cyberskill.tools.hydra import HydraTool

        tasks: list[asyncio.Task] = []

        async def _task(tool, tgt, **kw) -> ToolResult:
            return await self._run(tool, tgt, **kw)

        async with asyncio.TaskGroup() as tg:
            for t in targets:
                kw = {k: v for k, v in t.items() if k != "target"}
                tasks.append(tg.create_task(_task(HydraTool(), t["target"], **kw)))

        return [t.result() for t in tasks]

    # ------------------------------------------------------------------ #
    # Internal helpers
    # ------------------------------------------------------------------ #

    async def _run(self, tool, target: str, **options) -> ToolResult:
        self._emit(f"  ▶ {tool.name:<12} starting on {target}")
        async with self._sem:
            result = await tool.run(target, timeout=self._timeout, **options)
        if result.error:
            self._emit(f"  ✗ {tool.name:<12} ERROR: {result.error}")
        else:
            n = _count_findings(result)
            self._emit(
                f"  ✓ {tool.name:<12} {n} finding(s)  [{result.duration_seconds:.1f}s]"
            )
        return result


# ---------------------------------------------------------------------------
# Target collection helpers
# ---------------------------------------------------------------------------

def _collect_injection_targets(result: ChainedScanResult) -> list[str]:
    urls: list[str] = []
    for intel in result.web_intel:
        for url in intel.param_urls:
            if url not in urls:
                urls.append(url)
    if target_has_params(result.target) and result.target not in urls:
        urls.append(result.target)
    return urls


def _collect_auth_targets(result: ChainedScanResult) -> list[dict[str, Any]]:
    targets: list[dict[str, Any]] = []

    for svc in result.auth_services:
        if svc.service in ("ssh", "ftp", "telnet", "rdp", "smb"):
            targets.append({
                "target": svc.host,
                "service": svc.service,
                "port": svc.port,
            })

    for wt, intel in zip(result.web_targets, result.web_intel):
        for path in intel.login_paths:
            service = "https-post-form" if wt.ssl else "http-post-form"
            targets.append({
                "target": wt.host,
                "service": service,
                "port": wt.port,
                "http_form_path": path,
                "http_form_params": "username=^USER^&password=^PASS^:Invalid",
            })

    return targets


def _count_findings(result: ToolResult) -> int:
    s = result.structured or {}
    for key in ("issue_count", "total_findings", "total_found", "total"):
        if key in s:
            return int(s[key])
    for key in ("issues", "findings", "credentials_found", "found", "hosts", "results"):
        val = s.get(key)
        if isinstance(val, list):
            return len(val)
    return 0


def _url_in_list(url: str, targets: list[WebTarget]) -> bool:
    return any(wt.url == url for wt in targets)
