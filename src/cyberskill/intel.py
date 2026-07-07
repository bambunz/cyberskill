"""Intelligence extraction — pulls actionable data from tool results to drive chained scans."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import urlparse

from cyberskill.models import ToolResult

# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class WebTarget:
    url: str
    host: str
    port: int
    ssl: bool
    product: str = ""
    version: str = ""


@dataclass
class AuthService:
    host: str
    port: int
    service: str   # ssh, ftp, rdp, smb, telnet …


@dataclass
class DBService:
    host: str
    port: int
    service: str   # mysql, postgresql, mssql, oracle …


@dataclass
class WebIntel:
    """Aggregated intelligence from nikto + directory-enumeration tools."""
    base_url: str = ""
    cms: str = ""                                          # wordpress, joomla, drupal …
    server: str = ""                                       # Apache/2.4.41, nginx/1.18.0 …
    technologies: list[str] = field(default_factory=list)
    login_paths: list[str] = field(default_factory=list)  # /wp-login.php, /administrator …
    admin_paths: list[str] = field(default_factory=list)  # /admin, /dashboard …
    interesting_paths: list[str] = field(default_factory=list)
    param_urls: list[str] = field(default_factory=list)   # URLs with ?param=value
    nuclei_tags: list[str] = field(default_factory=list)  # computed for Phase 3


# ---------------------------------------------------------------------------
# Service classification sets
# ---------------------------------------------------------------------------

_HTTP_SVCS  = {"http", "http-alt", "http-proxy", "www", "webcache", "http-mgmt",
               "http?", "ajp13", "jetty", "gunicorn"}
_HTTPS_SVCS = {"https", "https-alt", "ssl/http", "ssl/https", "ssl/http-proxy",
               "https?", "ssl/http?"}
_AUTH_SVCS  = {"ssh", "ftp", "rdp", "smb", "microsoft-ds", "telnet", "vnc"}
_DB_SVCS    = {"mysql", "postgresql", "ms-sql-s", "mssql", "oracle",
               "mongodb", "redis", "memcache", "cassandra"}

# Ports commonly used for web even if nmap labels the service as unknown/tcpwrapped
_COMMON_WEB_PORTS: frozenset[int] = frozenset({
    80, 443, 8080, 8443, 8000, 8001, 8008, 8888,
    9090, 9000, 9001, 3000, 3001, 4000, 4200, 5000,
    7080, 7443, 8180, 8181, 8280, 8300, 10443,
    3128, 6080, 8009, 8444, 8765, 9200, 9300,
})

# ---------------------------------------------------------------------------
# nmap extraction
# ---------------------------------------------------------------------------

def extract_from_nmap(
    result: ToolResult,
) -> tuple[list[WebTarget], list[AuthService], list[DBService]]:
    """Parse nmap structured output into typed intel."""
    web: list[WebTarget] = []
    auth: list[AuthService] = []
    dbs: list[DBService] = []

    for host in result.structured.get("hosts", []):
        addr = host.get("address", "")
        if not addr:
            continue
        for p in host.get("open_ports", []):
            if p.get("protocol", "tcp") != "tcp":
                continue
            svc     = p.get("service", "").lower()
            portnum = int(p.get("port", 0))
            product = p.get("product", "").lower()
            version = p.get("version", "")
            scripts = p.get("scripts", {})

            # Detect SSL: explicit HTTPS service names, high-SSL ports, or ssl-cert script ran
            is_ssl = (
                svc in _HTTPS_SVCS
                or portnum in (443, 8443, 4443, 10443, 7443)
                or "ssl-cert" in scripts
            )

            # Classify as web if: known HTTP/HTTPS service name, common web port number,
            # http-headers/http-title script ran, or product contains http/nginx/apache
            is_web = (
                svc in _HTTP_SVCS
                or svc in _HTTPS_SVCS
                or portnum in _COMMON_WEB_PORTS
                or "http-headers" in scripts
                or "http-title" in scripts
                or any(w in product for w in ("http", "nginx", "apache", "iis", "lighttpd",
                                               "tomcat", "jetty", "node", "gunicorn", "flask",
                                               "django", "spring", "express"))
            )

            if is_web:
                scheme = "https" if is_ssl else "http"
                default_port = 443 if is_ssl else 80
                url = (
                    f"{scheme}://{addr}"
                    if portnum == default_port
                    else f"{scheme}://{addr}:{portnum}"
                )
                web.append(WebTarget(
                    url=url, host=addr, port=portnum, ssl=is_ssl,
                    product=p.get("product", ""), version=version,
                ))

            if svc in _AUTH_SVCS:
                auth.append(AuthService(host=addr, port=portnum, service=svc))
            if svc in _DB_SVCS:
                dbs.append(DBService(host=addr, port=portnum, service=svc))

    return web, auth, dbs

# ---------------------------------------------------------------------------
# nikto extraction
# ---------------------------------------------------------------------------

_CMS_PATTERNS = [
    (r"wordpress|wp-content|wp-login|wp-admin|wp-json", "wordpress"),
    (r"joomla|/administrator|com_content",              "joomla"),
    (r"drupal|sites/default|core/misc",                 "drupal"),
    (r"magento|mage/",                                  "magento"),
    (r"typo3",                                          "typo3"),
]

_TECH_PATTERNS = [
    (r"php[/ ][\d.]",           "php"),
    (r"asp\.net|aspx",          "asp"),
    (r"nginx[/ ][\d.]",         "nginx"),
    (r"apache[/ ][\d.]",        "apache"),
    (r"tomcat[/ ][\d.]",        "tomcat"),
    (r"iis[/ ][\d.]",           "iis"),
    (r"\bjenkins\b",            "jenkins"),
    (r"phpmyadmin",             "phpmyadmin"),
    (r"\bgrafana\b",            "grafana"),
    (r"kibana|elastic",         "elastic"),
    (r"\bstruts\b",             "struts"),
    (r"\bspring\b",             "spring"),
]

_LOGIN_RE = re.compile(r"login|signin|auth|logon|wp-login|admin/login", re.I)
_ADMIN_RE = re.compile(r"/admin|/administrator|/manager|/dashboard|/wp-admin|/cpanel|/panel", re.I)
_PATH_RE  = re.compile(r"'(/[^\s'\"<>]{2,})'")


def extract_from_nikto(result: ToolResult, base_url: str = "") -> WebIntel:
    """Build WebIntel from a nikto ToolResult."""
    intel = WebIntel(base_url=base_url)
    s = result.structured

    intel.server = s.get("server", "")

    # Detect technologies from server header
    for pattern, tag in _TECH_PATTERNS:
        if re.search(pattern, intel.server, re.I):
            _add_unique(intel.technologies, tag)

    all_text = " ".join(f.get("finding", "") for f in s.get("findings", []))

    # CMS
    for pattern, cms_name in _CMS_PATTERNS:
        if re.search(pattern, all_text, re.I):
            intel.cms = cms_name
            _add_unique(intel.nuclei_tags, cms_name)
            break

    # Technologies from findings
    for pattern, tag in _TECH_PATTERNS:
        if re.search(pattern, all_text, re.I):
            _add_unique(intel.technologies, tag)

    # Paths from findings
    for path in _PATH_RE.findall(all_text):
        path = path.rstrip(".").rstrip(",")
        if _LOGIN_RE.search(path):
            _add_unique(intel.login_paths, path)
        elif _ADMIN_RE.search(path):
            _add_unique(intel.admin_paths, path)
        else:
            _add_unique(intel.interesting_paths, path)

    # Nuclei tags from technologies
    for t in intel.technologies:
        _add_unique(intel.nuclei_tags, t)

    # Broad tags always added
    for tag in ("misconfig", "exposure", "vulns"):
        _add_unique(intel.nuclei_tags, tag)

    if intel.login_paths or intel.admin_paths:
        for tag in ("panel", "default-login"):
            _add_unique(intel.nuclei_tags, tag)

    # XSS / CSRF / RFI if nikto flagged these attack classes
    for keyword, tag in (("xss", "xss"), ("csrf", "csrf"), ("rfi", "rfi"), ("lfi", "lfi")):
        if keyword in all_text.lower():
            _add_unique(intel.nuclei_tags, tag)

    return intel


# ---------------------------------------------------------------------------
# ffuf / gobuster extraction
# ---------------------------------------------------------------------------

def extract_paths_from_ffuf(result: ToolResult) -> list[str]:
    return [
        r["path"]
        for r in result.structured.get("results", [])
        if r.get("status", 0) not in (404, 400)
    ]


def extract_paths_from_gobuster(result: ToolResult) -> list[str]:
    return [f["path"] for f in result.structured.get("found", [])]


def merge_paths_into_intel(intel: WebIntel, paths: list[str]) -> None:
    """Classify newly discovered paths into the correct intel buckets."""
    for path in paths:
        if _LOGIN_RE.search(path):
            _add_unique(intel.login_paths, path)
        elif _ADMIN_RE.search(path):
            _add_unique(intel.admin_paths, path)
        else:
            _add_unique(intel.interesting_paths, path)

        if intel.base_url and "=" in path:
            _add_unique(intel.param_urls, intel.base_url.rstrip("/") + path)


# ---------------------------------------------------------------------------
# Target classification
# ---------------------------------------------------------------------------

def is_url_target(target: str) -> bool:
    return urlparse(target).scheme in ("http", "https")


def target_has_params(target: str) -> bool:
    return "?" in target and "=" in target


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _add_unique(lst: list, item: str) -> None:
    if item and item not in lst:
        lst.append(item)
