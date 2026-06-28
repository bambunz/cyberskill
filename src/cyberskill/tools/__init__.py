"""Import all built-in tools — each module-level call registers the tool."""
from cyberskill.tools import (
    commix,
    ffuf,
    gobuster,
    hydra,
    nikto,
    nmap,
    nuclei,
    sslscan,
    sqlmap,
    wfuzz,
)

__all__ = [
    "commix",
    "ffuf",
    "gobuster",
    "hydra",
    "nikto",
    "nmap",
    "nuclei",
    "sslscan",
    "sqlmap",
    "wfuzz",
]
