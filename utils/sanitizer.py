"""
Input sanitization and target validation.
Prevents command injection and enforces allowed-target policies.
"""

import re
import ipaddress
import logging
from typing import Optional

logger = logging.getLogger("mcp-security.sanitizer")

_ALLOWED_TARGETS: list[str] = []
_ALLOWED_CIDRS: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []

# Characters that could enable shell injection
_DANGEROUS_CHARS = re.compile(r"[;&|`$(){}!\n\r\\\"']")

# Valid hostname pattern
_HOSTNAME_RE = re.compile(
    r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})*\.?$"
)

# Valid URL pattern (http/https only)
_URL_RE = re.compile(
    r"^https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%{}-]+$"
)


def configure_allowed_targets(targets_csv: str) -> None:
    """Parse the MCP_ALLOWED_TARGETS env var."""
    global _ALLOWED_TARGETS, _ALLOWED_CIDRS
    _ALLOWED_TARGETS = []
    _ALLOWED_CIDRS = []

    if not targets_csv.strip():
        logger.warning("No target restrictions configured — all targets allowed")
        return

    for entry in targets_csv.split(","):
        entry = entry.strip()
        if not entry:
            continue
        try:
            network = ipaddress.ip_network(entry, strict=False)
            _ALLOWED_CIDRS.append(network)
        except ValueError:
            _ALLOWED_TARGETS.append(entry.lower())

    logger.info(
        f"Allowed targets: {len(_ALLOWED_TARGETS)} domains, "
        f"{len(_ALLOWED_CIDRS)} CIDRs"
    )


def sanitize_target(target: str) -> str:
    """
    Validate and sanitize a target string (IP, hostname, or URL).
    Raises ValueError on dangerous input.
    """
    target = target.strip()

    if not target:
        raise ValueError("Target cannot be empty")

    if len(target) > 2048:
        raise ValueError("Target string too long (max 2048 chars)")

    if _DANGEROUS_CHARS.search(target):
        raise ValueError(
            f"Target contains forbidden characters: {target!r}"
        )

    return target


def validate_target_allowed(target: str) -> None:
    """Check target against the allow-list. No-op if allow-list is empty."""
    if not _ALLOWED_TARGETS and not _ALLOWED_CIDRS:
        return  # No restrictions

    # Extract hostname from URL
    hostname = target
    if "://" in hostname:
        hostname = hostname.split("://", 1)[1].split("/", 0)[0].split(":")[0]

    # Check domain allow-list
    hostname_lower = hostname.lower()
    for allowed in _ALLOWED_TARGETS:
        if hostname_lower == allowed or hostname_lower.endswith(f".{allowed}"):
            return

    # Check CIDR allow-list — handle both single IPs and network targets
    try:
        addr = ipaddress.ip_address(hostname)
        for cidr in _ALLOWED_CIDRS:
            if addr in cidr:
                return
    except ValueError:
        try:
            net = ipaddress.ip_network(hostname, strict=False)
            for cidr in _ALLOWED_CIDRS:
                if net.subnet_of(cidr):
                    return
        except ValueError:
            pass  # Not an IP or network

    raise ValueError(
        f"Target '{target}' is not in the allowed targets list. "
        f"Configure MCP_ALLOWED_TARGETS to add it."
    )


def sanitize_ports(ports: str) -> str:
    """Validate a port specification string (e.g., '80,443', '1-1024')."""
    ports = ports.strip()
    if not re.match(r"^[0-9,\- ]+$", ports):
        raise ValueError(f"Invalid port specification: {ports!r}")
    return ports


def sanitize_wordlist_path(path: str) -> str:
    """Validate wordlist path — must be under /usr/share."""
    path = path.strip()
    if _DANGEROUS_CHARS.search(path):
        raise ValueError(f"Path contains forbidden characters: {path!r}")
    if not path.startswith("/usr/share/"):
        raise ValueError("Wordlists must be under /usr/share/")
    if ".." in path:
        raise ValueError("Path traversal not allowed")
    return path


def sanitize_search_term(term: str) -> str:
    """Sanitize a searchsploit query term."""
    term = term.strip()
    if not term:
        raise ValueError("Search term cannot be empty")
    if len(term) > 256:
        raise ValueError("Search term too long (max 256 chars)")
    if _DANGEROUS_CHARS.search(term):
        raise ValueError(f"Search term contains forbidden characters")
    return term