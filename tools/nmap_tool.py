"""Nmap network scanner MCP tool."""

from typing import Optional
from fastmcp import FastMCP
from utils.sanitizer import sanitize_target, validate_target_allowed, sanitize_ports
from utils.runner import run_tool
from utils.formatter import format_header, format_footer, format_error, truncate_output
from utils.rate_limiter import RateLimiter


def register(mcp: FastMCP, limiter: RateLimiter) -> None:

    @mcp.tool()
    async def nmap_scan(
        target: str,
        scan_type: str = "quick",
        ports: Optional[str] = None,
        scripts: Optional[str] = None,
        timeout: int = 600,
    ) -> str:
        """
        Run an nmap network scan against a target host or subnet.

        Args:
            target: IP address, hostname, or CIDR range to scan.
            scan_type: One of 'quick', 'full', 'service', 'vuln', 'stealth', 'udp'.
                - quick: Top 1000 ports, service detection (-sV --top-ports 1000)
                - full: All 65535 ports (-p-)
                - service: Service + OS detection (-sV -O)
                - vuln: NSE vuln scripts (--script=vuln)
                - stealth: SYN scan (-sS)
                - udp: UDP scan (-sU --top-ports 100)
            ports: Optional port specification (e.g., '80,443' or '1-1024').
            scripts: Optional comma-separated NSE scripts to run.
            timeout: Max seconds (default 600).

        Returns:
            Formatted nmap scan results as text.
        """
        limiter.check("nmap")

        try:
            target = sanitize_target(target)
            validate_target_allowed(target)
        except ValueError as e:
            return format_error("nmap", str(e))

        # Build command
        cmd = ["nmap", "-oN", "-"]

        scan_flags = {
            "quick":   ["-sV", "--top-ports", "1000"],
            "full":    ["-sV", "-p-"],
            "service": ["-sV", "-O"],
            "vuln":    ["-sV", "--script=vuln"],
            "stealth": ["-sS", "--top-ports", "1000"],
            "udp":     ["-sU", "--top-ports", "100"],
        }

        if scan_type not in scan_flags:
            return format_error(
                "nmap",
                f"Unknown scan_type '{scan_type}'. "
                f"Choose from: {', '.join(scan_flags.keys())}"
            )

        cmd.extend(scan_flags[scan_type])

        if ports:
            try:
                ports = sanitize_ports(ports)
                cmd.extend(["-p", ports])
            except ValueError as e:
                return format_error("nmap", str(e))

        if scripts:
            scripts = scripts.replace(" ", "")
            if not all(c.isalnum() or c in "-_," for c in scripts):
                return format_error("nmap", "Invalid script name characters")
            cmd.extend(["--script", scripts])

        cmd.append(target)

        header = format_header("nmap", target, f"type={scan_type}")
        rc, stdout, stderr = await run_tool(cmd, timeout=timeout, tool_name="nmap")

        if rc == -1:
            return header + "\n" + format_error("nmap", stderr)

        output = truncate_output(stdout)
        footer = format_footer(rc)
        return f"{header}\n\n{output}\n\n{footer}"