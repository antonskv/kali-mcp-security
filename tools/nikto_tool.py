"""Nikto web server scanner MCP tool."""

from typing import Optional
from fastmcp import FastMCP
from utils.sanitizer import sanitize_target, validate_target_allowed
from utils.runner import run_tool
from utils.formatter import format_header, format_footer, format_error, truncate_output
from utils.rate_limiter import RateLimiter


def register(mcp: FastMCP, limiter: RateLimiter) -> None:

    @mcp.tool()
    async def nikto_scan(
        target: str,
        port: int = 80,
        ssl: bool = False,
        tuning: Optional[str] = None,
        timeout: int = 900,
    ) -> str:
        """
        Run a Nikto web vulnerability scan against a target web server.

        Args:
            target: URL or hostname of the web server.
            port: Target port (default 80).
            ssl: Use SSL/TLS (default False).
            tuning: Nikto tuning options string. Categories:
                0 = File Upload
                1 = Interesting File / Seen in logs
                2 = Misconfiguration / Default File
                3 = Information Disclosure
                4 = Injection (XSS/Script/HTML)
                5 = Remote File Retrieval — Inside Web Root
                6 = Denial of Service
                7 = Remote File Retrieval — Server Wide
                8 = Command Execution / Remote Shell
                9 = SQL Injection
                a = Authentication Bypass
                b = Software Identification
                c = Remote Source Inclusion
            timeout: Max seconds (default 900).

        Returns:
            Formatted Nikto scan results.
        """
        limiter.check("nikto")

        try:
            target = sanitize_target(target)
            validate_target_allowed(target)
        except ValueError as e:
            return format_error("nikto", str(e))

        if not (1 <= port <= 65535):
            return format_error("nikto", f"Invalid port: {port}")

        cmd = ["nikto", "-h", target, "-p", str(port), "-Format", "txt"]

        if ssl:
            cmd.append("-ssl")

        if tuning:
            if not all(c in "0123456789abc" for c in tuning):
                return format_error("nikto", f"Invalid tuning string: {tuning}")
            cmd.extend(["-Tuning", tuning])

        header = format_header("nikto", f"{target}:{port}", f"ssl={ssl}")
        rc, stdout, stderr = await run_tool(cmd, timeout=timeout, tool_name="nikto")

        if rc == -1:
            return header + "\n" + format_error("nikto", stderr)

        output = truncate_output(stdout)
        footer = format_footer(rc)
        return f"{header}\n\n{output}\n\n{footer}"