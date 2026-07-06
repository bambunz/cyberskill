# cyberskill

An AI-powered cybersecurity skill that wraps industry-standard security tools behind a clean Python API, covers all ten OWASP Top 10 (2021) categories, and integrates natively with Claude AI via the Anthropic API and the Model Context Protocol (MCP).

> **Authorisation reminder** — only scan systems you own or have explicit written permission to test.

---

## Contents

- [Features](#features)
- [Architecture](#architecture)
- [Tools](#tools)
- [OWASP Top 10 coverage](#owasp-top-10-coverage)
- [Installation](#installation)
- [CLI usage](#cli-usage)
- [Python API](#python-api)
- [Chained scanning](#chained-scanning)
  - [How the phases work](#how-the-phases-work)
  - [Python API](#chained-scan-python-api)
  - [Report format](#report-format)
- [Claude AI integration](#claude-ai-integration)
  - [Approach 1 — Claude API agent](#approach-1--claude-api-agent)
  - [Approach 2 — MCP server](#approach-2--mcp-server)
- [Extending with custom tools](#extending-with-custom-tools)
- [Development](#development)

---

## Features

- **10 built-in tools** covering every OWASP Top 10 category
- **Chained scanning** — each phase's findings automatically configure the next tool (nmap → nikto/ffuf → nuclei → sqlmap/wfuzz/commix → hydra)
- **Async execution** with configurable concurrency (`asyncio` + `Semaphore`)
- **Structured output** — each tool parses its own stdout into a typed dict
- **Plugin system** — third-party packages can register tools via Python entry-points
- **AI-ready facade** (`CyberskillAI`) — synchronous, JSON-serialisable interface
- **Two Claude integrations** — direct API agent and MCP server

---

## Architecture

```
┌─────────────────────────────────────────────────┐
│                  Claude AI                      │
│  (API tool use or MCP client)                   │
└─────────────┬──────────────────┬───────────────┘
              │                  │
      claude_agent.py      mcp_server.py
              │                  │
┌─────────────▼──────────────────▼───────────────┐
│            CyberskillAI  (skill.py)             │
│  list_tools · list_categories · scan · ...      │
└─────────────────────┬───────────────────────────┘
                      │
          ┌───────────▼───────────┐
          │     ScanRunner        │  asyncio concurrency
          │  run_tools / full_    │  Semaphore
          │  assessment           │
          └───────────┬───────────┘
                      │
          ┌───────────▼───────────┐
          │    ToolRegistry       │  built-ins + entry-points
          └───────────┬───────────┘
                      │
     ┌────────────────┼────────────────┐
     ▼                ▼                ▼
 BaseTool          BaseTool        BaseTool  ...
 (nmap)          (sqlmap)        (nuclei)
 build_command    build_command   build_command
 _parse           _parse          _parse
```

Each tool wrapper:
1. declares `name`, `binary`, `description`, and `owasp_categories`
2. implements `build_command(target, **options) → list[str]`
3. optionally overrides `_parse(stdout, stderr, returncode) → dict` to produce structured results

The `BaseTool.run()` coroutine handles subprocess execution, timeout enforcement, and `ToolResult` construction.

---

## Tools

| Tool | Binary | Description | OWASP |
|------|--------|-------------|-------|
| **nmap** | `nmap` | Port/service/OS scanner with NSE script support (SSL, HTTP headers, CVEs) | A02 A05 A06 |
| **gobuster** | `gobuster` | Directory/subdomain brute-forcer — discovers unprotected paths and vhosts | A01 |
| **wfuzz** | `wfuzz` | Web fuzzer with mode presets: dir, traversal, sqli, ssrf, auth | A01 A03 A07 A10 |
| **sqlmap** | `sqlmap` | SQL injection scanner: boolean/time-based blind, error-based, UNION, stacked | A03 |
| **nikto** | `nikto` | Web server scanner: exposed files, misconfigs, outdated software, headers | A01 A05 |
| **nuclei** | `nuclei` | Template-based vuln scanner with JSON output and severity grouping | A04 A05 A06 A08 A09 A10 |
| **hydra** | `hydra` | Online credential brute-forcer: SSH, FTP, HTTP-form, RDP, SMB and more | A07 |
| **sslscan** | `sslscan` | SSL/TLS configuration analyser — weak ciphers, expired certs, protocol versions | A02 |
| **commix** | `commix` | Command injection scanner: classic, blind time-based, file-based techniques | A03 |
| **ffuf** | `ffuf` | Fast web fuzzer: directories, vhosts, parameter names, backup files | A01 |

---

## OWASP Top 10 coverage

| # | Category | Tools |
|---|----------|-------|
| A01 | Broken Access Control | gobuster, wfuzz, nikto, ffuf |
| A02 | Cryptographic Failures | nmap, sslscan |
| A03 | Injection | wfuzz, sqlmap, commix |
| A04 | Insecure Design | nuclei |
| A05 | Security Misconfiguration | nmap, nikto, nuclei |
| A06 | Vulnerable and Outdated Components | nmap, nuclei |
| A07 | Identification and Authentication Failures | wfuzz, hydra |
| A08 | Software and Data Integrity Failures | nuclei |
| A09 | Security Logging and Monitoring Failures | nuclei |
| A10 | Server-Side Request Forgery (SSRF) | wfuzz, nuclei |

---

## Installation

```bash
# Core package only (no AI dependencies)
pip install -e .

# With Claude API agent support
pip install -e ".[claude]"

# With MCP server support
pip install -e ".[mcp]"

# Everything
pip install -e ".[all]"
```

**Prerequisites** — the tool binaries must be installed separately and available on `PATH`. Install them via your OS package manager or from their official sources:

```bash
# Debian / Ubuntu
sudo apt install nmap gobuster wfuzz sqlmap nikto hydra sslscan commix ffuf

# macOS (Homebrew)
brew install nmap gobuster wfuzz sqlmap nikto hydra sslscan
```

Nuclei, commix, and ffuf may need manual installation — see their upstream repos.

---

## CLI usage

```bash
# List all registered tools and check which binaries are installed
cyberskill list-tools

# List OWASP Top 10 categories with mapped tools
cyberskill list-categories

# Detailed info on a single tool
cyberskill tool-info nmap

# Full assessment (all tools, all categories) — writes JSON to stdout
cyberskill scan 192.168.1.1

# Scan targeting specific OWASP categories only
cyberskill scan https://target.local -c A03 -c A05

# Scan with specific tools
cyberskill scan https://target.local -t nmap -t sqlmap

# Save report to file; tune concurrency and per-tool timeout
cyberskill scan 10.0.0.1 --concurrency 3 --timeout 120 --output report.json
```

### Sample output

```json
{
  "target": "192.168.1.1",
  "timestamp": "2025-01-01T12:00:00+00:00",
  "total_tools": 10,
  "successful_tools": 8,
  "results": [
    {
      "tool": "nmap",
      "target": "192.168.1.1",
      "command": "nmap -sV --open -oX - -p 1-1000 ...",
      "success": true,
      "returncode": 0,
      "duration_seconds": 4.21,
      "owasp_categories": [
        "A02:2021 – Cryptographic Failures",
        "A05:2021 – Security Misconfiguration",
        "A06:2021 – Vulnerable and Outdated Components"
      ],
      "structured": {
        "hosts": [
          {
            "address": "192.168.1.1",
            "hostname": "router.local",
            "open_ports": [
              {"port": "22", "protocol": "tcp", "service": "ssh", "product": "OpenSSH", "version": "8.9"},
              {"port": "80", "protocol": "tcp", "service": "http", "product": "nginx", "version": "1.18.0"}
            ],
            "os_matches": ["Linux 5.x (95%)"]
          }
        ],
        "total_hosts": 1
      }
    }
  ]
}
```

---

## Python API

```python
from cyberskill.skill import CyberskillAI

skill = CyberskillAI()           # discovers + loads all built-in tools

# Discovery
tools = skill.list_tools()       # list[dict] — name, binary, available, owasp_categories
cats  = skill.list_categories()  # list[dict] — id, label, description, tools
info  = skill.tool_info("nmap")  # dict

# Scan — returns a JSON-serialisable dict
report = skill.scan("192.168.1.1")

# Targeted scan by tool names
report = skill.scan("https://target.local", tools=["sqlmap", "nikto"])

# Targeted scan by OWASP category
report = skill.scan("https://target.local", categories=["A03", "A05"])

# Async variant (call from an existing event loop)
report = await skill.async_scan("192.168.1.1", categories=["A02"])
```

### Data models

```python
from cyberskill.models import OWASPCategory, ScanReport, ToolResult

# OWASPCategory is a StrEnum — usable as a string "A03" or via enum member
OWASPCategory.A03          # → "A03"
OWASPCategory.A03.label    # → "A03:2021 – Injection"
OWASPCategory.A03.description  # → long description string

# ToolResult fields
result.tool_name           # "sqlmap"
result.target              # "http://target/page?id=1"
result.command             # full argv string
result.success             # bool (returncode 0 and no error)
result.returncode          # int
result.duration_seconds    # float
result.owasp_categories    # frozenset[OWASPCategory]
result.structured          # parsed dict from _parse()
result.stdout / .stderr    # raw subprocess output
result.error               # None or error string (e.g. binary not found)

# ScanReport
report.target              # str
report.timestamp           # datetime (UTC)
report.results             # list[ToolResult]
report.to_dict()           # JSON-serialisable dict
report.to_json(indent=2)   # JSON string
```

---

## Chained scanning

`chained_scan` is an intelligent multi-phase orchestrator. Rather than running all tools blindly in parallel, it runs them in dependency order and feeds each phase's findings into the next as precise configuration — so nuclei runs only WordPress templates when WordPress is detected, sqlmap only tests parameters that actually exist, and hydra targets only the login forms that nikto found.

### How the phases work

```
Target (IP / hostname / URL)
        │
        ▼
┌───────────────────────────────────────────────────────────────┐
│ Phase 1 — Network recon                                       │
│   nmap (-sV, all ports, OS detection)                         │
│   Extracts → web targets · SSH/FTP/RDP services · DB ports   │
└───────────────────────┬───────────────────────────────────────┘
                        │ web targets
                        ▼
┌───────────────────────────────────────────────────────────────┐
│ Phase 2 — Web fingerprinting  (per web target, in parallel)  │
│   nikto   → CMS (WordPress/Joomla/Drupal), server header,    │
│             login paths (/wp-login.php), admin paths          │
│   ffuf    → directory brute-force, additional paths           │
│   sslscan → weak ciphers, expired certs  (HTTPS targets only) │
│   Extracts → cms · technologies · login_paths · nuclei_tags  │
└───────────────────────┬───────────────────────────────────────┘
                        │ cms + tech tags + paths
                        ▼
┌───────────────────────────────────────────────────────────────┐
│ Phase 3 — Targeted vulnerability scan                         │
│   nuclei   → runs ONLY templates matching detected tags       │
│              e.g. -tags wordpress,apache,php,default-login    │
│   gobuster → deeper path discovery                            │
└───────────────────────┬───────────────────────────────────────┘
                        │ param URLs (from target or nikto)
                        ▼
┌───────────────────────────────────────────────────────────────┐
│ Phase 4 — Injection testing  (only if param URLs found)       │
│   sqlmap  → SQL injection (level 2, risk 2)                   │
│   commix  → OS command injection                              │
│   wfuzz   → SQLi payloads     (?id=FUZZ)                      │
│             XSS payloads      (?q=FUZZ)                       │
│             RFI payloads      (?page=FUZZ)                    │
│             LFI/traversal     (/path/FUZZ)                    │
└───────────────────────┬───────────────────────────────────────┘
                        │ services + login pages
                        ▼
┌───────────────────────────────────────────────────────────────┐
│ Phase 5 — Auth / credential testing                           │
│   hydra  → SSH, FTP, RDP, SMB  (from Phase 1 services)       │
│            HTTP form brute-force (from Phase 2 login paths)   │
└───────────────────────────────────────────────────────────────┘
                        │
                        ▼
              Prioritised finding report
        (critical → high → medium → low → info)
              with per-finding exploit hints
```

Phases are skipped gracefully when no relevant targets are found (e.g. if nmap finds no web ports, phases 2–4 are skipped). Missing tool binaries are also silently skipped.

### Chained scan Python API

```python
from cyberskill.skill import CyberskillAI

skill = CyberskillAI()

# Scan a host — starts with nmap, chains through all phases
report = skill.chained_scan("192.168.1.1")

# Scan a URL directly — skips nmap, starts at Phase 2
report = skill.chained_scan("http://192.168.1.1/app?id=1")

# Get a human-readable Markdown report
md = skill.chained_scan("192.168.1.1", output="markdown")
print(md)

# Async variant
report = await skill.async_chained_scan("192.168.1.1", timeout=120)
```

### Report format

```json
{
  "target": "192.168.1.1",
  "timestamp": "2025-01-01T12:00:00+00:00",
  "phases_run": ["phase1_recon", "phase2_web_fingerprint", "phase3_vuln_scan"],
  "attack_surface": {
    "web_targets": [{"url": "http://192.168.1.1", "port": 80, "ssl": false, "product": "nginx"}],
    "auth_services": [{"host": "192.168.1.1", "port": 22, "service": "ssh"}],
    "db_services":   [{"host": "192.168.1.1", "port": 3306, "service": "mysql"}],
    "cms": "wordpress",
    "technologies": ["apache", "php"],
    "login_paths": ["/wp-login.php"],
    "admin_paths":  ["/wp-admin/"]
  },
  "summary": {
    "total_findings": 7,
    "by_severity": {"critical": 1, "high": 2, "medium": 3, "low": 1},
    "tools_run": ["commix", "ffuf", "nikto", "nmap", "nuclei", "sqlmap", "wfuzz"]
  },
  "findings": [
    {
      "severity": "critical",
      "owasp": "A03:2021 – Injection",
      "tool": "sqlmap",
      "target": "http://192.168.1.1/app?id=1",
      "title": "SQL injection in parameter(s): id",
      "detail": "Injection types: boolean-based blind, time-based blind\nDatabases: dvwa, mysql",
      "exploit_hints": [
        {
          "title": "Dump database with sqlmap",
          "command": "sqlmap -u \"http://192.168.1.1/app?id=1\" --batch --dbs",
          "reference": ""
        },
        {
          "title": "Attempt OS shell",
          "command": "sqlmap -u \"http://192.168.1.1/app?id=1\" --batch --os-shell",
          "reference": ""
        }
      ]
    }
  ]
}
```

The Markdown output (`output="markdown"`) renders the same data as a human-readable report with severity icons, tables, and fenced exploit command blocks — suitable for copy-paste into a pentest report.

---

## Claude AI integration

The package ships two ready-to-use Claude integrations in `examples/`. Both expose the same five operations as callable tools:

| Tool | Description |
|------|-------------|
| `list_tools` | List all registered tools and their OWASP coverage |
| `list_categories` | List all OWASP Top 10 categories and their mapped tools |
| `tool_info` | Get metadata for a single tool by name |
| `scan` | Run specific tools or categories against a target |
| `chained_scan` | Full 5-phase chained assessment with per-finding exploit hints |

---

### Approach 1 — Claude API agent

`examples/claude_agent.py` runs a local Python agentic loop. Claude decides which cyberskill tools to call and with what parameters, executes them, and synthesises the findings into a natural-language answer.

**Install**

```bash
pip install -e ".[claude]"
export ANTHROPIC_API_KEY="sk-ant-..."
```

**One-shot mode**

```bash
python examples/claude_agent.py "What ports and services are running on 192.168.1.1?"

python examples/claude_agent.py "Test http://testphp.vulnweb.com for SQL injection"

python examples/claude_agent.py "Run a full OWASP A02 and A05 assessment on 10.0.0.1"
```

**Interactive mode** (no arguments)

```bash
python examples/claude_agent.py
# Cyberskill AI — Claude-powered security assessment agent
# Type your request and press Enter (Ctrl-C to quit).
#
# You: list available tools
# [tool] list_tools({})
# Here are the registered tools ...
```

**How it works**

1. Defines four JSON schema tool definitions and passes them to `client.messages.create()`
2. Uses `claude-opus-4-8` with `thinking: {type: "adaptive"}` for deep reasoning over scan results
3. Runs a manual agentic loop — calls Claude, dispatches tool calls to `CyberskillAI`, feeds results back — until `stop_reason == "end_turn"`
4. Handles tool errors gracefully via `is_error: true` tool results

**Embed in your own app**

```python
from examples.claude_agent import run_agent

answer = run_agent("What does nmap find on 192.168.1.100?", verbose=False)
print(answer)
```

---

### Approach 2 — MCP server

`examples/mcp_server.py` exposes cyberskill as an MCP server (stdio transport). Any MCP-compatible client — Claude Desktop, Claude Code, or the Claude API `mcp_servers` parameter — can discover and call the tools without any additional code.

**Install**

```bash
pip install -e ".[mcp]"
```

#### Connect to Claude Desktop

Edit your Claude Desktop config file:

- **macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Linux**: `~/.config/claude/claude_desktop_config.json`
- **Windows**: `%APPDATA%\Claude\claude_desktop_config.json`

```json
{
  "mcpServers": {
    "cyberskill": {
      "command": "python",
      "args": ["/absolute/path/to/examples/mcp_server.py"]
    }
  }
}
```

Restart Claude Desktop. You will see `cyberskill` appear in the tool list.

#### Connect to Claude Code

Create or update `.mcp.json` in your project root:

```json
{
  "mcpServers": {
    "cyberskill": {
      "command": "python",
      "args": ["examples/mcp_server.py"]
    }
  }
}
```

Or pass it on the command line:

```bash
claude --mcp-config .mcp.json
```

#### Connect via the Claude API

```python
import anthropic

client = anthropic.Anthropic()

response = client.messages.create(
    model="claude-opus-4-8",
    max_tokens=16000,
    mcp_servers=[
        {
            "type": "stdio",
            "command": "python",
            "args": ["examples/mcp_server.py"],
        }
    ],
    messages=[{"role": "user", "content": "Scan 192.168.1.1 for open ports and services"}],
)
print(response.content[0].text)
```

#### MCP resources

The server also exposes two static resources that Claude can read without calling a tool:

| URI | Contents |
|-----|----------|
| `cyberskill://owasp/top10` | All ten OWASP categories with descriptions and mapped tools |
| `cyberskill://tools/available` | All registered tools including installation status |

---

### Choosing an approach

| | Claude API agent | MCP server |
|-|-----------------|------------|
| **Setup** | `pip install anthropic` + API key | `pip install mcp` |
| **Use case** | Standalone script or embedded in your app | Claude Desktop / Claude Code / any MCP client |
| **Control** | Full — you own the loop and can add logging, approval gates, etc. | Handled by the client |
| **Streaming** | Add `.stream()` in the loop | Transparent |
| **Multi-turn** | Extend the `messages` list between calls | Client manages history |

Both approaches give Claude identical capabilities over cyberskill.

---

## Extending with custom tools

Third-party packages can add new tools to the registry without modifying this package.

**1. Implement `BaseTool`**

```python
# mypackage/tools/mytool.py
from cyberskill.base import BaseTool
from cyberskill.models import OWASPCategory

class MyTool(BaseTool):
    name = "mytool"
    binary = "mytool"
    description = "A custom security tool"
    owasp_categories = frozenset({OWASPCategory.A01})

    def build_command(self, target: str, **options) -> list[str]:
        return ["mytool", "--target", target]

    def _parse(self, stdout: str, stderr: str, returncode: int) -> dict:
        return {"raw": stdout, "findings": []}
```

**2. Register the entry-point in `pyproject.toml`**

```toml
[project.entry-points."cyberskill.tools"]
mytool = "mypackage.tools.mytool:MyTool"
```

**3. Install the package**

```bash
pip install -e .
```

`CyberskillAI` calls `registry.discover()` on init and will pick up your tool automatically.

**Register programmatically** (without entry-points):

```python
from cyberskill.registry import registry
from mypackage.tools.mytool import MyTool

registry.register(MyTool)
```

---

## Development

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Run tests with coverage
pytest --cov=cyberskill --cov-report=term-missing

# Type-check (optional)
mypy src/
```

### Project structure

```
cyberskill/
├── examples/
│   ├── claude_agent.py      # Claude API agentic loop integration
│   └── mcp_server.py        # MCP server (Claude Desktop / Claude Code)
├── src/cyberskill/
│   ├── __init__.py
│   ├── base.py              # BaseTool ABC + async execution
│   ├── cli.py               # Click CLI (cyberskill scan / list-tools / ...)
│   ├── intel.py             # Intelligence extractors (nmap→WebTarget, nikto→WebIntel …)
│   ├── models.py            # OWASPCategory, ToolResult, ScanReport
│   ├── orchestrator.py      # ChainingOrchestrator — 5-phase chained runner
│   ├── registry.py          # ToolRegistry + plugin discovery
│   ├── report.py            # ChainedReport builder + Markdown renderer + ExploitHints
│   ├── runner.py            # ScanRunner (async concurrency)
│   ├── skill.py             # CyberskillAI facade (scan + chained_scan)
│   └── tools/
│       ├── commix.py
│       ├── ffuf.py
│       ├── gobuster.py
│       ├── hydra.py
│       ├── nikto.py
│       ├── nmap.py
│       ├── nuclei.py
│       ├── sqlmap.py
│       ├── sslscan.py
│       └── wfuzz.py
├── tests/
│   ├── test_base.py
│   ├── test_cli.py
│   ├── test_models.py
│   ├── test_registry.py
│   ├── test_skill.py
│   └── tools/
│       ├── test_nmap.py
│       ├── test_nuclei.py
│       ├── test_sqlmap.py
│       └── test_wfuzz.py
└── pyproject.toml
```
