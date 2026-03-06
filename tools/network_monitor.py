"""
Network monitoring utilities — ping, DNS lookup, whois, quick port check.
Lightweight tools for ongoing network health monitoring.
"""

from typing import Optional
from fastmcp import FastMCP
from utils.sanitizer import sanitize_target, validate_target_allowed, sanitize_ports
from utils.runner import run_tool
from utils.formatter import format_header, format_footer, format_error, truncate_output
from utils.rate_limiter import RateLimiter


def register(mcp: FastMCP, limiter: RateLimiter) -> None:

    @mcp.tool()
    async def ping_host(target: str, count: int = 4) -> str:
        """
        Ping a host to check if it's reachable.

        Args:
            target: IP address or hostname.
            count: Number of pings (1-20, default 4).

        Returns:
            Ping results with latency statistics.
        """
        limiter.check("ping")
        try:
            target = sanitize_target(target)
            validate_target_allowed(target)
        except ValueError as e:
            return format_error("ping", str(e))

        count = max(1, min(20, count))
        cmd = ["ping", "-c", str(count), "-W", "3", target]

        header = format_header("ping", target, f"count={count}")
        rc, stdout, stderr = await run_tool(cmd, timeout=60, tool_name="ping")
        output = truncate_output(stdout)
        footer = format_footer(rc)
        return f"{header}\n\n{output}\n\n{footer}"

    @mcp.tool()
    async def dns_lookup(target: str, record_type: str = "A") -> str:
        """
        Perform DNS lookup on a domain.

        Args:
            target: Domain name to look up.
            record_type: DNS record type (A, AAAA, MX, NS, TXT, CNAME, SOA, ANY).

        Returns:
            DNS query results.
        """
        limiter.check("dns")
        try:
            target = sanitize_target(target)
        except ValueError as e:
            return format_error("dns", str(e))

        valid_types = {"A","AAAA","MX","NS","TXT","CNAME","SOA","ANY"}
        record_type = record_type.upper()
        if record_type not in valid_types:
            return format_error("dns", f"Invalid record type: {record_type}")

        cmd = ["dig", target, record_type, "+noall", "+answer", "+stats"]

        header = format_header("dns lookup", target, f"type={record_type}")
        rc, stdout, stderr = await run_tool(cmd, timeout=30, tool_name="dns")
        output = truncate_output(stdout)
        footer = format_footer(rc)
        return f"{header}\n\n{output}\n\n{footer}"

    @mcp.tool()
    async def whois_lookup(target: str) -> str:
        """
        Perform a WHOIS lookup on a domain or IP address.

        Args:
            target: Domain name or IP address.

        Returns:
            WHOIS registration information.
        """
        limiter.check("whois")
        try:
            target = sanitize_target(target)
        except ValueError as e:
            return format_error("whois", str(e))

        cmd = ["whois", target]

        header = format_header("whois", target)
        rc, stdout, stderr = await run_tool(cmd, timeout=30, tool_name="whois")
        output = truncate_output(stdout, max_lines=100)
        footer = format_footer(rc)
        return f"{header}\n\n{output}\n\n{footer}"

    @mcp.tool()
    async def quick_port_check(target: str, ports: str = "22,80,443,3306,5432,8080,8443") -> str:
        """
        Quick TCP connect scan on specific ports — faster than a full nmap scan.

        Args:
            target: IP address or hostname.
            ports: Comma-separated port list (default: common service ports).

        Returns:
            Open/closed status for each specified port.
        """
        limiter.check("quick_port_check")
        try:
            target = sanitize_target(target)
            validate_target_allowed(target)
            ports = sanitize_ports(ports)
        except ValueError as e:
            return format_error("port_check", str(e))

        cmd = ["nmap", "-sT", "-p", ports, "--open", "-oN", "-", target]

        header = format_header("quick port check", target, f"ports={ports}")
        rc, stdout, stderr = await run_tool(cmd, timeout=120, tool_name="port_check")
        output = truncate_output(stdout)
        footer = format_footer(rc)
        return f"{header}\n\n{output}\n\n{footer}"
