"""Dirb directory/file brute forcer MCP tool."""

from typing import Optional
from fastmcp import FastMCP
from utils.sanitizer import (
    sanitize_target, validate_target_allowed, sanitize_wordlist_path,
)
from utils.runner import run_tool
from utils.formatter import format_header, format_footer, format_error, truncate_output
from utils.rate_limiter import RateLimiter


def register(mcp: FastMCP, limiter: RateLimiter) -> None:

    @mcp.tool()
    async def dirb_scan(
        url: str,
        wordlist: str = "/usr/share/dirb/wordlists/common.txt",
        extensions: Optional[str] = None,
        user_agent: Optional[str] = None,
        timeout: int = 600,
    ) -> str:
        """
        Brute-force directories and files on a web server using dirb.

        Args:
            url: Target base URL (e.g., 'http://example.com/').
            wordlist: Path to wordlist file (must be under /usr/share/).
                Defaults to the standard common.txt wordlist.
            extensions: Comma-separated file extensions to test
                (e.g., 'php,html,txt').
            user_agent: Custom User-Agent header string.
            timeout: Max seconds (default 600).

        Returns:
            Formatted dirb scan results showing discovered paths.
        """
        limiter.check("dirb")

        try:
            url = sanitize_target(url)
            validate_target_allowed(url)
            wordlist = sanitize_wordlist_path(wordlist)
        except ValueError as e:
            return format_error("dirb", str(e))

        cmd = ["dirb", url, wordlist, "-S"]  # -S = silent (no banner)

        if extensions:
            if not all(c.isalnum() or c in ",." for c in extensions):
                return format_error("dirb", f"Invalid extensions: {extensions}")
            cmd.extend(["-X", f".{extensions.replace(',', ',.')}"])

        if user_agent:
            if len(user_agent) > 256:
                return format_error("dirb", "User-Agent too long")
            cmd.extend(["-a", user_agent])

        header = format_header("dirb", url, f"wordlist={wordlist.split('/')[-1]}")
        rc, stdout, stderr = await run_tool(cmd, timeout=timeout, tool_name="dirb")

        if rc == -1:
            return header + "\n" + format_error("dirb", stderr)

        output = truncate_output(stdout)
        footer = format_footer(rc)
        return f"{header}\n\n{output}\n\n{footer}"