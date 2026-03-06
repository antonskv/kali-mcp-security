"""Safe async subprocess execution with timeout."""

import asyncio
import os
import logging
from typing import Optional

logger = logging.getLogger("mcp-security.runner")

DEFAULT_TIMEOUT = int(os.getenv("MCP_MAX_SCAN_TIMEOUT", "3600"))


async def run_tool(
    cmd: list[str],
    timeout: Optional[int] = None,
    tool_name: str = "unknown",
) -> tuple[int, str, str]:
    """
    Execute a command asynchronously with timeout.
    Returns (return_code, stdout, stderr).
    """
    timeout = timeout or DEFAULT_TIMEOUT
    cmd_display = " ".join(cmd[:4]) + ("..." if len(cmd) > 4 else "")
    logger.info(f"[{tool_name}] Running: {cmd_display} (timeout={timeout}s)")

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            # Drop all inherited env except PATH and tool-specific vars
            env={
                "PATH": os.environ.get("PATH", "/usr/bin:/usr/sbin"),
                "HOME": os.environ.get("HOME", "/home/mcpuser"),
                "TERM": "xterm",
            },
        )
        stdout, stderr = await asyncio.wait_for(
            proc.communicate(), timeout=timeout
        )
        rc = proc.returncode or 0
        logger.info(f"[{tool_name}] Finished with exit code {rc}")
        return rc, stdout.decode("utf-8", errors="replace"), stderr.decode("utf-8", errors="replace")

    except asyncio.TimeoutError:
        logger.warning(f"[{tool_name}] Timed out after {timeout}s — killing")
        proc.kill()
        await proc.wait()
        return -1, "", f"TIMEOUT: Scan exceeded {timeout}s and was terminated."

    except Exception as e:
        logger.error(f"[{tool_name}] Execution error: {e}")
        return -1, "", f"ERROR: {str(e)}"