"""WPScan WordPress vulnerability scanner MCP tool."""

import os
from typing import Optional
from fastmcp import FastMCP
from utils.sanitizer import sanitize_target, validate_target_allowed
from utils.runner import run_tool
from utils.formatter import format_header, format_footer, format_error, truncate_output
from utils.rate_limiter import RateLimiter


def register(mcp: FastMCP, limiter: RateLimiter) -> None:

    @mcp.tool()
    async def wpscan_scan(
        url: str,
        enumerate: Optional[str] = None,
        plugins_detection: str = "mixed",
        timeout: int = 600,
    ) -> str:
        """
        Scan a WordPress site for vulnerabilities using WPScan.

        Args:
            url: WordPress site URL (e.g., 'http://example.com').
            enumerate: Comma-separated enumeration options:
                vp  = Vulnerable plugins
                ap  = All plugins
                p   = Popular plugins
                vt  = Vulnerable themes
                at  = All themes
                t   = Popular themes
                u   = Users (1-30)
                m   = Media (timthumbs)
                cb  = Config backups
                dbe = DB exports
            plugins_detection: 'mixed', 'passive', or 'aggressive'.
            timeout: Max seconds (default 600).

        Returns:
            Formatted WPScan results.
        """
        limiter.check("wpscan")

        try:
            url = sanitize_target(url)
            validate_target_allowed(url)
        except ValueError as e:
            return format_error("wpscan", str(e))

        if plugins_detection not in ("mixed", "passive", "aggressive"):
            return format_error(
                "wpscan",
                f"Invalid plugins_detection: {plugins_detection}"
            )

        cmd = [
            "wpscan", "--url", url,
            "--no-banner",
            "--format", "cli",
            "--plugins-detection", plugins_detection,
        ]

        token = os.getenv("WPSCAN_API_TOKEN", "")
        if token:
            cmd.extend(["--api-token", token])

        if enumerate:
            valid_opts = {"vp","ap","p","vt","at","t","u","m","cb","dbe"}
            parts = [e.strip() for e in enumerate.split(",")]
            for p in parts:
                if p not in valid_opts:
                    return format_error("wpscan", f"Invalid enum option: {p}")
            cmd.extend(["-e", ",".join(parts)])

        header = format_header("wpscan", url, f"detect={plugins_detection}")
        rc, stdout, stderr = await run_tool(cmd, timeout=timeout, tool_name="wpscan")

        if rc == -1:
            return header + "\n" + format_error("wpscan", stderr)

        output = truncate_output(stdout)
        footer = format_footer(rc)
        return f"{header}\n\n{output}\n\n{footer}"