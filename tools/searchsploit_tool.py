"""SearchSploit (Exploit-DB) offline search MCP tool."""

from typing import Optional
from fastmcp import FastMCP
from utils.sanitizer import sanitize_search_term
from utils.runner import run_tool
from utils.formatter import format_header, format_footer, format_error, truncate_output
from utils.rate_limiter import RateLimiter


def register(mcp: FastMCP, limiter: RateLimiter) -> None:

    @mcp.tool()
    async def searchsploit(
        query: str,
        exact: bool = False,
        json_output: bool = False,
        exclude: Optional[str] = None,
    ) -> str:
        """
        Search the local Exploit-DB database for known exploits.

        Args:
            query: Search term (e.g., 'apache 2.4', 'wordpress 6.0',
                   'OpenSSH 8.x').
            exact: If True, perform exact match instead of fuzzy.
            json_output: Return raw JSON instead of formatted table.
            exclude: Terms to exclude from results (e.g., 'dos').

        Returns:
            Formatted searchsploit results listing matching exploits.
        """
        limiter.check("searchsploit")

        try:
            query = sanitize_search_term(query)
        except ValueError as e:
            return format_error("searchsploit", str(e))

        cmd = ["searchsploit"]

        if exact:
            cmd.append("--exact")
        if json_output:
            cmd.append("--json")
        if exclude:
            try:
                exclude = sanitize_search_term(exclude)
                cmd.extend(["--exclude", exclude])
            except ValueError as e:
                return format_error("searchsploit", str(e))

        cmd.extend(query.split())

        header = format_header("searchsploit", query, f"exact={exact}")
        rc, stdout, stderr = await run_tool(
            cmd, timeout=60, tool_name="searchsploit"
        )

        if rc == -1:
            return header + "\n" + format_error("searchsploit", stderr)

        output = truncate_output(stdout, max_lines=200)
        footer = format_footer(rc)
        return f"{header}\n\n{output}\n\n{footer}"