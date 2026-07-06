"""Report synthesis — aggregates all phase results into a prioritised finding list."""
from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field
from typing import Any

from cyberskill.models import OWASPCategory, ToolResult
from cyberskill.orchestrator import ChainedScanResult

# Severity ordering (higher index = higher priority)
_SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0, "unknown": 0}


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class ExploitHint:
    title: str
    description: str
    command: str = ""
    reference: str = ""


@dataclass
class Finding:
    severity: str
    owasp: str
    tool: str
    target: str
    title: str
    detail: str
    evidence: str = ""
    exploit_hints: list[ExploitHint] = field(default_factory=list)

    @property
    def rank(self) -> int:
        return _SEVERITY_RANK.get(self.severity.lower(), 0)


@dataclass
class ChainedReport:
    target: str
    timestamp: str
    phases_run: list[str]
    attack_surface: dict[str, Any]
    findings: list[Finding]
    summary: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "timestamp": self.timestamp,
            "phases_run": self.phases_run,
            "attack_surface": self.attack_surface,
            "summary": self.summary,
            "findings": [_finding_to_dict(f) for f in self.findings],
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    def to_markdown(self) -> str:
        return _render_markdown(self)


# ---------------------------------------------------------------------------
# Builder
# ---------------------------------------------------------------------------

def build_report(scan: ChainedScanResult) -> ChainedReport:
    findings: list[Finding] = []

    for phase_name, results in scan.phases.items():
        for result in results:
            findings.extend(_extract_findings(result))

    # Sort: critical → high → medium → low → info
    findings.sort(key=lambda f: f.rank, reverse=True)

    # Build attack surface summary
    attack_surface: dict[str, Any] = {
        "web_targets": [
            {"url": wt.url, "port": wt.port, "ssl": wt.ssl,
             "product": wt.product, "version": wt.version}
            for wt in scan.web_targets
        ],
        "auth_services": [
            {"host": s.host, "port": s.port, "service": s.service}
            for s in scan.auth_services
        ],
        "db_services": [
            {"host": s.host, "port": s.port, "service": s.service}
            for s in scan.db_services
        ],
        "cms": next((i.cms for i in scan.web_intel if i.cms), ""),
        "technologies": list({t for i in scan.web_intel for t in i.technologies}),
        "login_paths": list({p for i in scan.web_intel for p in i.login_paths}),
        "admin_paths": list({p for i in scan.web_intel for p in i.admin_paths}),
    }

    by_severity: dict[str, int] = {}
    by_owasp: dict[str, int] = {}
    for f in findings:
        by_severity[f.severity] = by_severity.get(f.severity, 0) + 1
        by_owasp[f.owasp] = by_owasp.get(f.owasp, 0) + 1

    summary = {
        "total_findings": len(findings),
        "by_severity": by_severity,
        "by_owasp": by_owasp,
        "tools_run": sorted({r.tool_name for results in scan.phases.values() for r in results}),
        "tools_succeeded": sorted({
            r.tool_name for results in scan.phases.values() for r in results if r.success
        }),
    }

    return ChainedReport(
        target=scan.target,
        timestamp=scan.timestamp,
        phases_run=list(scan.phases.keys()),
        attack_surface=attack_surface,
        findings=findings,
        summary=summary,
    )


# ---------------------------------------------------------------------------
# Per-tool finding extractors
# ---------------------------------------------------------------------------

def _extract_findings(result: ToolResult) -> list[Finding]:
    name = result.tool_name
    if name == "nmap":
        return _from_nmap(result)
    if name == "nikto":
        return _from_nikto(result)
    if name == "nuclei":
        return _from_nuclei(result)
    if name == "sqlmap":
        return _from_sqlmap(result)
    if name == "commix":
        return _from_commix(result)
    if name == "wfuzz":
        return _from_wfuzz(result)
    if name == "sslscan":
        return _from_sslscan(result)
    if name == "hydra":
        return _from_hydra(result)
    if name in ("gobuster", "ffuf"):
        return _from_dir_enum(result)
    return []


def _from_nmap(r: ToolResult) -> list[Finding]:
    findings: list[Finding] = []
    for host in r.structured.get("hosts", []):
        addr = host.get("address", r.target)
        for port in host.get("open_ports", []):
            portnum = port.get("port", "?")
            svc     = port.get("service", "")
            product = port.get("product", "")
            version = port.get("version", "")

            # Outdated component hint
            if product and version:
                findings.append(Finding(
                    severity="info",
                    owasp=OWASPCategory.A06.label,
                    tool="nmap",
                    target=f"{addr}:{portnum}",
                    title=f"Service detected: {product} {version}",
                    detail=f"Port {portnum}/{port.get('protocol','tcp')} running {product} {version}.",
                    evidence=f"{product} {version}",
                    exploit_hints=[ExploitHint(
                        title="Check for known CVEs",
                        description=f"Search NVD/CVEDetails for {product} {version}.",
                        reference="https://nvd.nist.gov/vuln/search",
                    )],
                ))
            # Dangerous services exposed
            if svc in ("telnet", "ftp") or (svc == "ssh" and portnum not in (22,)):
                findings.append(Finding(
                    severity="medium",
                    owasp=OWASPCategory.A02.label,
                    tool="nmap",
                    target=f"{addr}:{portnum}",
                    title=f"Insecure service exposed: {svc.upper()} on port {portnum}",
                    detail=f"{svc.upper()} transmits credentials in cleartext.",
                    evidence=f"Port {portnum} open ({svc})",
                    exploit_hints=[ExploitHint(
                        title="Credential capture / MITM",
                        description=f"Intercept {svc.upper()} traffic with Wireshark or arpspoof.",
                        command=f"hydra -L users.txt -P passwords.txt {svc}://{addr} -s {portnum}",
                    )],
                ))
    return findings


def _from_nikto(r: ToolResult) -> list[Finding]:
    findings: list[Finding] = []
    sev_map = {"high": "high", "medium": "medium", "low": "low"}
    for f in r.structured.get("findings", []):
        text = f.get("finding", "")
        sev  = sev_map.get(f.get("severity", "low"), "low")
        hints = _nikto_hints(text, r.target)
        findings.append(Finding(
            severity=sev,
            owasp=_guess_owasp_from_text(text),
            tool="nikto",
            target=r.target,
            title=text[:100],
            detail=text,
            evidence=text,
            exploit_hints=hints,
        ))
    return findings


def _from_nuclei(r: ToolResult) -> list[Finding]:
    findings: list[Finding] = []
    for f in r.structured.get("findings", []):
        sev = f.get("severity", "info")
        hints: list[ExploitHint] = []
        refs = f.get("reference", [])
        if refs:
            hints.append(ExploitHint(
                title="References",
                description="See linked advisories for PoC and patch guidance.",
                reference=refs[0] if isinstance(refs, list) else str(refs),
            ))
        curl = f.get("curl_command", "")
        if curl:
            hints.append(ExploitHint(
                title="Reproduce with curl",
                description="Reproduce the finding with the command below.",
                command=curl,
            ))
        owasp = _nuclei_tag_to_owasp(f.get("tags", []))
        findings.append(Finding(
            severity=sev,
            owasp=owasp,
            tool="nuclei",
            target=f.get("matched_at", r.target),
            title=f.get("name", f.get("template_id", "nuclei finding")),
            detail=f.get("description", ""),
            evidence=f.get("matched_at", ""),
            exploit_hints=hints,
        ))
    return findings


def _from_sqlmap(r: ToolResult) -> list[Finding]:
    if not r.structured.get("vulnerable"):
        return []
    params = r.structured.get("vulnerable_parameters", [])
    types  = r.structured.get("injection_types", [])
    dbs    = r.structured.get("databases", [])
    hints = [
        ExploitHint(
            title="Dump database with sqlmap",
            description="Enumerate and dump accessible databases.",
            command=(
                f"sqlmap -u \"{r.target}\" --batch --dbs"
                + (f" --dbms={dbs[0]}" if dbs else "")
            ),
        ),
        ExploitHint(
            title="Attempt OS shell",
            description="Escalate SQL injection to OS command execution.",
            command=f"sqlmap -u \"{r.target}\" --batch --os-shell",
        ),
    ]
    return [Finding(
        severity="critical",
        owasp=OWASPCategory.A03.label,
        tool="sqlmap",
        target=r.target,
        title=f"SQL injection in parameter(s): {', '.join(params)}",
        detail=(
            f"Vulnerable parameters: {', '.join(params)}\n"
            f"Injection types: {', '.join(types)}\n"
            f"Databases: {', '.join(dbs)}"
        ),
        evidence=r.stdout[:500],
        exploit_hints=hints,
    )]


def _from_commix(r: ToolResult) -> list[Finding]:
    if not r.structured.get("vulnerable"):
        return []
    points  = r.structured.get("injection_points", [])
    outputs = r.structured.get("command_output", [])
    return [Finding(
        severity="critical",
        owasp=OWASPCategory.A03.label,
        tool="commix",
        target=r.target,
        title=f"OS command injection in parameter(s): {', '.join(points)}",
        detail=f"Command output: {' | '.join(outputs)}",
        evidence=r.stdout[:500],
        exploit_hints=[ExploitHint(
            title="Open interactive OS shell",
            description="Leverage command injection for interactive shell access.",
            command=f'commix --url "{r.target}" --batch --os-shell',
        )],
    )]


def _from_wfuzz(r: ToolResult) -> list[Finding]:
    hits = r.structured.get("hits", [])
    if not hits:
        return []
    payloads = [h.get("payload", "") for h in hits[:5]]
    return [Finding(
        severity="medium",
        owasp=OWASPCategory.A01.label,
        tool="wfuzz",
        target=r.target,
        title=f"wfuzz: {len(hits)} hits — possible injection/traversal/discovery",
        detail=f"Sample payloads: {', '.join(payloads)}",
        evidence="\n".join(
            f"{h['status']}  {h['payload']}" for h in hits[:10]
        ),
        exploit_hints=[ExploitHint(
            title="Manually verify hits",
            description="Review each payload in a browser or with curl to confirm exploitability.",
        )],
    )]


def _from_sslscan(r: ToolResult) -> list[Finding]:
    findings: list[Finding] = []
    s = r.structured

    if s.get("expired"):
        findings.append(Finding(
            severity="high",
            owasp=OWASPCategory.A02.label,
            tool="sslscan",
            target=r.target,
            title="SSL certificate is expired",
            detail="An expired certificate may allow MITM attacks.",
            exploit_hints=[ExploitHint(
                title="MITM with expired cert",
                description="Use mitmproxy or SSLstrip to intercept traffic.",
                command=f"mitmproxy --mode transparent",
            )],
        ))

    for cipher in s.get("weak_ciphers", []):
        findings.append(Finding(
            severity="medium",
            owasp=OWASPCategory.A02.label,
            tool="sslscan",
            target=r.target,
            title=f"Weak cipher accepted: {cipher}",
            detail=f"The server accepts the weak cipher suite {cipher}.",
            exploit_hints=[ExploitHint(
                title="BEAST/POODLE/SWEET32 exploitation",
                description="Weak ciphers may be exploitable with known SSL attacks.",
                reference="https://testssl.sh/",
            )],
        ))

    for proto in s.get("weak_protocols", []):
        findings.append(Finding(
            severity="high",
            owasp=OWASPCategory.A02.label,
            tool="sslscan",
            target=r.target,
            title=f"Insecure protocol enabled: {proto.upper()}",
            detail=f"The server supports {proto.upper()} which is deprecated.",
            exploit_hints=[ExploitHint(
                title=f"POODLE/DROWN attack against {proto.upper()}",
                description=f"Downgrade attacks may be possible since {proto.upper()} is enabled.",
                command=f"testssl.sh --poodle {r.target}",
            )],
        ))
    return findings


def _from_hydra(r: ToolResult) -> list[Finding]:
    creds = r.structured.get("credentials_found", [])
    if not creds:
        return []
    lines = [f"{c['username']}:{c['password']} ({c['service']}:{c['port']})" for c in creds]
    return [Finding(
        severity="critical",
        owasp=OWASPCategory.A07.label,
        tool="hydra",
        target=r.target,
        title=f"Weak/default credentials found: {len(creds)} pair(s)",
        detail="\n".join(lines),
        evidence="\n".join(lines),
        exploit_hints=[ExploitHint(
            title="Log in with found credentials",
            description="Use the discovered credentials to authenticate to the service.",
        )],
    )]


def _from_dir_enum(r: ToolResult) -> list[Finding]:
    items = r.structured.get("results", r.structured.get("found", []))
    interesting = [
        i for i in items
        if isinstance(i, dict) and i.get("status", i.get("status_code", 200)) not in (404,)
        and any(kw in str(i).lower() for kw in ("admin", "backup", "config", "login", "db", ".bak", ".sql", ".env"))
    ]
    if not interesting:
        return []
    paths = [i.get("path", i.get("payload", "")) for i in interesting[:10]]
    return [Finding(
        severity="medium",
        owasp=OWASPCategory.A01.label,
        tool=r.tool_name,
        target=r.target,
        title=f"Sensitive paths discovered ({len(interesting)} items)",
        detail="\n".join(paths),
        evidence="\n".join(paths),
        exploit_hints=[ExploitHint(
            title="Access sensitive endpoints",
            description="Manually visit discovered paths — check for unauthenticated access.",
        )],
    )]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _guess_owasp_from_text(text: str) -> str:
    t = text.lower()
    if any(w in t for w in ("sql", "inject", "xss", "csrf", "rfi", "lfi", "command")):
        return OWASPCategory.A03.label
    if any(w in t for w in ("ssl", "tls", "cipher", "encrypt", "cert")):
        return OWASPCategory.A02.label
    if any(w in t for w in ("login", "password", "auth", "brute")):
        return OWASPCategory.A07.label
    if any(w in t for w in ("cve", "outdated", "version", "component")):
        return OWASPCategory.A06.label
    if any(w in t for w in ("header", "config", "default", "exposed")):
        return OWASPCategory.A05.label
    if any(w in t for w in ("admin", "directory", "path", "traversal", "access")):
        return OWASPCategory.A01.label
    return OWASPCategory.A05.label


def _nikto_hints(text: str, target: str) -> list[ExploitHint]:
    hints: list[ExploitHint] = []
    t = text.lower()
    if "xss" in t:
        hints.append(ExploitHint(
            title="Cross-Site Scripting (XSS)",
            description="Inject a script payload in the identified parameter.",
            command=f"wfuzz -c -w /usr/share/seclists/Fuzzing/XSS/XSS-Jhaddix.txt -u \"{target}FUZZ\"",
        ))
    if "sql" in t or "inject" in t:
        hints.append(ExploitHint(
            title="SQL Injection",
            description="Test with sqlmap for automated exploitation.",
            command=f"sqlmap -u \"{target}\" --batch --dbs",
        ))
    if "admin" in t or "login" in t:
        hints.append(ExploitHint(
            title="Default credentials",
            description="Attempt default/common credentials on the admin panel.",
            command=f"hydra -L users.txt -P /usr/share/wordlists/rockyou.txt http-post-form \"{target}:username=^USER^&password=^PASS^:Invalid\"",
        ))
    return hints


_NUCLEI_OWASP: dict[str, str] = {
    "sqli":         OWASPCategory.A03.label,
    "xss":          OWASPCategory.A03.label,
    "rce":          OWASPCategory.A03.label,
    "lfi":          OWASPCategory.A03.label,
    "rfi":          OWASPCategory.A03.label,
    "ssrf":         OWASPCategory.A10.label,
    "csrf":         OWASPCategory.A01.label,
    "misconfig":    OWASPCategory.A05.label,
    "exposure":     OWASPCategory.A05.label,
    "cve":          OWASPCategory.A06.label,
    "default-login":OWASPCategory.A07.label,
    "panel":        OWASPCategory.A05.label,
}


def _nuclei_tag_to_owasp(tags: list[str]) -> str:
    for tag in tags:
        if tag in _NUCLEI_OWASP:
            return _NUCLEI_OWASP[tag]
    return OWASPCategory.A05.label


def _finding_to_dict(f: Finding) -> dict[str, Any]:
    return {
        "severity": f.severity,
        "owasp": f.owasp,
        "tool": f.tool,
        "target": f.target,
        "title": f.title,
        "detail": f.detail,
        "evidence": f.evidence,
        "exploit_hints": [
            {
                "title": h.title,
                "description": h.description,
                "command": h.command,
                "reference": h.reference,
            }
            for h in f.exploit_hints
        ],
    }


# ---------------------------------------------------------------------------
# Markdown renderer
# ---------------------------------------------------------------------------

_SEV_ICON = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪"}


def _render_markdown(report: ChainedReport) -> str:
    lines: list[str] = []
    a = lines.append

    a(f"# Cyberskill Chained Scan Report")
    a(f"")
    a(f"**Target:** `{report.target}`")
    a(f"**Timestamp:** {report.timestamp}")
    a(f"**Phases run:** {', '.join(report.phases_run)}")
    a(f"")

    # Summary
    a("## Summary")
    s = report.summary
    a(f"- Total findings: **{s['total_findings']}**")
    for sev in ("critical", "high", "medium", "low", "info"):
        count = s["by_severity"].get(sev, 0)
        if count:
            icon = _SEV_ICON.get(sev, "")
            a(f"  - {icon} {sev.capitalize()}: {count}")
    a(f"- Tools run: {', '.join(s['tools_run'])}")
    a(f"")

    # Attack surface
    a("## Attack Surface")
    surf = report.attack_surface
    if surf["web_targets"]:
        a("### Web endpoints")
        for wt in surf["web_targets"]:
            ssl_label = " (HTTPS)" if wt["ssl"] else ""
            ver = f" — {wt['product']} {wt['version']}" if wt.get("product") else ""
            a(f"- `{wt['url']}`{ssl_label}{ver}")
    if surf["auth_services"]:
        a("### Network services")
        for s in surf["auth_services"]:
            a(f"- `{s['host']}:{s['port']}` — {s['service'].upper()}")
    if surf["db_services"]:
        a("### Database services")
        for d in surf["db_services"]:
            a(f"- `{d['host']}:{d['port']}` — {d['service'].upper()}")
    if surf["cms"]:
        a(f"### CMS detected: **{surf['cms'].title()}**")
    if surf["technologies"]:
        a(f"### Technologies: {', '.join(surf['technologies'])}")
    if surf["login_paths"]:
        a("### Login pages")
        for p in surf["login_paths"]:
            a(f"- `{p}`")
    if surf["admin_paths"]:
        a("### Admin panels")
        for p in surf["admin_paths"]:
            a(f"- `{p}`")
    a("")

    # Findings
    a("## Findings")
    if not report.findings:
        a("_No findings recorded._")
    for i, f in enumerate(report.findings, 1):
        icon = _SEV_ICON.get(f.severity.lower(), "")
        a(f"### {i}. {icon} [{f.severity.upper()}] {f.title}")
        a(f"")
        a(f"| Field | Value |")
        a(f"|-------|-------|")
        a(f"| Tool | `{f.tool}` |")
        a(f"| Target | `{f.target}` |")
        a(f"| OWASP | {f.owasp} |")
        a(f"| Severity | {f.severity.upper()} |")
        a(f"")
        if f.detail:
            a(f"**Detail:** {f.detail}")
            a(f"")
        if f.evidence:
            a(f"**Evidence:**")
            a(f"```")
            a(f.evidence[:400])
            a(f"```")
            a(f"")
        if f.exploit_hints:
            a(f"**Exploit hints:**")
            for h in f.exploit_hints:
                a(f"- **{h.title}** — {h.description}")
                if h.command:
                    a(f"  ```bash")
                    a(f"  {h.command}")
                    a(f"  ```")
                if h.reference:
                    a(f"  Reference: {h.reference}")
            a(f"")

    return "\n".join(lines)
