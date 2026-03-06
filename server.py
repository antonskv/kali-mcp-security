#!/usr/bin/env python3
import sys
sys.path.insert(0, "/opt/mcp-server")

import os
import logging
from dotenv import load_dotenv
from fastmcp import FastMCP

load_dotenv()

from tools.nmap_tool import register as register_nmap
from tools.nikto_tool import register as register_nikto
from tools.sqlmap_tool import register as register_sqlmap
from tools.wpscan_tool import register as register_wpscan
from tools.dirb_tool import register as register_dirb
from tools.searchsploit_tool import register as register_searchsploit
from tools.network_monitor import register as register_netmon
from utils.sanitizer import configure_allowed_targets
from utils.rate_limiter import RateLimiter

# ── Logging ─────────────────────────────────────────────────────────────────
log_level = os.getenv("MCP_LOG_LEVEL", "INFO").upper()
logging.basicConfig(
    level=getattr(logging, log_level, logging.INFO),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[
        logging.StreamHandler(),
        #logging.FileHandler("logs/mcp-server.log", mode="a"),
    ],
)
logger = logging.getLogger("mcp-security")

# ── Initialize FastMCP ──────────────────────────────────────────────────────
mcp = FastMCP("Kali Security MCP Server")

# ── Configure security constraints ──────────────────────────────────────────
allowed = os.getenv("MCP_ALLOWED_TARGETS", "")
configure_allowed_targets(allowed)

rate_limiter = RateLimiter(
    max_per_minute=int(os.getenv("MCP_RATE_LIMIT_PER_MIN", "30"))
)

# ── Register all tools ──────────────────────────────────────────────────────
register_nmap(mcp, rate_limiter)
register_nikto(mcp, rate_limiter)
register_sqlmap(mcp, rate_limiter)
register_wpscan(mcp, rate_limiter)
register_dirb(mcp, rate_limiter)
register_searchsploit(mcp, rate_limiter)
register_netmon(mcp, rate_limiter)

logger.info("All security tools registered successfully")

# ── Run ─────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    transport = os.getenv("MCP_TRANSPORT", "stdio")
    host = os.getenv("MCP_HOST", "0.0.0.0")
    port = int(os.getenv("MCP_PORT", "8083"))
    logger.info(f"Starting MCP Security Server — transport={transport}")
    if transport == "sse":
        mcp.run(transport="sse", host=host, port=port)
    else:
        mcp.run(transport="stdio")