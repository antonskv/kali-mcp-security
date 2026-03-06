"""SQLMap SQL injection scanner MCP tool."""

from typing import Optional
from fastmcp import FastMCP
from utils.sanitizer import sanitize_target, validate_target_allowed
from utils.runner import run_tool
from utils.formatter import format_header, format_footer, format_error, truncate_output
from utils.rate_limiter import RateLimiter


def register(mcp: FastMCP, limiter: RateLimiter) -> None:

    @mcp.tool()
    async def sqlmap_scan(
        url: str,
        method: str = "GET",
        data: Optional[str] = None,
        level: int = 1,
        risk: int = 1,
        dbs: bool = False,
        tables: Optional[str] = None,
        timeout: int = 600,
    ) -> str:
        """
        Run sqlmap to test a URL for SQL injection vulnerabilities.

        Args:
            url: Target URL with parameter(s) to test (e.g.,
                 'http://example.com/page?id=1').
            method: HTTP method — 'GET' or 'POST'.
            data: POST data string (required if method=POST).
            level: Test level 1-5 (higher = more tests, slower).
            risk: Risk level 1-3 (higher = more aggressive payloads).
            dbs: If True, enumerate databases after finding injection.
            tables: Database name to enumerate tables from.
            timeout: Max seconds (default 600).

        Returns:
            Formatted sqlmap results.
        """
        limiter.check("sqlmap")

        try:
            url = sanitize_target(url)
            validate_target_allowed(url)
        except ValueError as e:
            return format_error("sqlmap", str(e))

        if method.upper() not in ("GET", "POST"):
            return format_error("sqlmap", f"Invalid method: {method}")
        if not (1 <= level <= 5):
            return format_error("sqlmap", f"Level must be 1-5, got {level}")
        if not (1 <= risk <= 3):
            return format_error("sqlmap", f"Risk must be 1-3, got {risk}")

        cmd = [
            "sqlmap", "-u", url,
            "--batch",            # Non-interactive
            "--level", str(level),
            "--risk", str(risk),
            "--output-dir=/tmp/sqlmap-output",
            "--disable-coloring",
        ]

        if method.upper() == "POST" and data:
            cmd.extend(["--method", "POST", "--data", data])

        if dbs:
            cmd.append("--dbs")

        if tables:
            if not all(c.isalnum() or c in "_-" for c in tables):
                return format_error("sqlmap", "Invalid database name")
            cmd.extend(["-D", tables, "--tables"])

        header = format_header("sqlmap", url, f"level={level} risk={risk}")
        rc, stdout, stderr = await run_tool(cmd, timeout=timeout, tool_name="sqlmap")

        if rc == -1:
            return header + "\n" + format_error("sqlmap", stderr)

        output = truncate_output(stdout)
        footer = format_footer(rc)
        return f"{header}\n\n{output}\n\n{footer}"