# Kali Linux MCP Security Server — Claude Guide

## Project Overview

An MCP (Model Context Protocol) server that exposes Kali Linux security tools to LLMs for web pentesting and network vulnerability monitoring. Built with FastMCP (Python), runs non-root inside Docker.

## Architecture

```
LLM (Claude, etc.)
    │
    ▼  MCP Protocol (SSE)
┌─────────────────────────────┐
│  FastMCP Server (Python)    │
│  ┌────────┐ ┌────────────┐  │
│  │Sanitize│→│ Rate Limit │  │
│  └────────┘ └─────┬──────┘  │
│               ┌───▼────┐    │
│               │ Runner │    │  ← async subprocess
│               └───┬────┘    │
│          ┌────────┼────────┐│
│          ▼        ▼        ▼│
│       [nmap]  [nikto] [sqlmap] ...
│          │        │        │ │
│          └────────┼────────┘│
│               ┌───▼─────┐   │
│               │Formatter│   │
│               └─────────┘   │
└─────────────────────────────┘
  Running as: mcpuser (non-root)
  Capabilities: NET_RAW, NET_BIND_SERVICE
```

## File Structure

```
kali-mcp-security/
├── Dockerfile                 # Kali-based image, non-root mcpuser
├── docker-compose.yml         # Service definition, port mapping, resource limits
├── requirements.txt           # Python deps (fastmcp, python-dotenv, etc.)
├── .env                       # Runtime config (MCP_ALLOWED_TARGETS, ports, etc.)
├── server.py                  # FastMCP entrypoint — registers all tools, starts SSE server
└── tools/
    ├── nmap_tool.py           # Network port/service/vuln scanning
    ├── nikto_tool.py          # Web server vulnerability assessment
    ├── sqlmap_tool.py         # SQL injection detection & exploitation
    ├── wpscan_tool.py         # WordPress-specific vulnerability scan
    ├── dirb_tool.py           # Directory & file brute-forcing
    ├── searchsploit_tool.py   # Offline Exploit-DB search
    ├── network_monitor.py     # ping, dns, whois, quick port check
    ├── formatter.py           # Structured output formatting
    ├── rate_limiter.py        # Sliding window rate limiter
    ├── runner.py              # Async subprocess execution
    └── sanitizer.py           # Input validation & allow-list enforcement
```

## Key Configuration (`.env`)

| Variable | Default | Description |
|---|---|---|
| `MCP_PORT` | `8083` | Port the SSE server listens on |
| `MCP_HOST` | `0.0.0.0` | Bind address |
| `MCP_ALLOWED_TARGETS` | _(empty = block all)_ | CIDR/IP allow-list for scan targets |
| `MCP_RATE_LIMIT_PER_MIN` | `30` | Max tool calls per minute |
| `MCP_MAX_SCAN_TIMEOUT` | `3600` | Max seconds a scan may run |
| `MCP_LOG_LEVEL` | `INFO` | Logging verbosity |

**Always set `MCP_ALLOWED_TARGETS` before running.** An empty value blocks all scans.

## Quick Start

```bash
# Configure
cp .env.example .env
# Edit .env — set MCP_ALLOWED_TARGETS to authorized networks

# Build and run
docker compose up --build -d

# Verify
curl http://localhost:8083/health
```

## Connecting to Claude Desktop

Add to `claude_desktop_config.json`:
```json
{
  "mcpServers": {
    "kali-security": {
      "url": "http://localhost:8083/sse"
    }
  }
}
```

## Available Tools

| Tool | Description |
|---|---|
| `nmap_scan` | Network port/service/vuln scanning |
| `nikto_scan` | Web server vulnerability assessment |
| `sqlmap_scan` | SQL injection detection & exploitation |
| `wpscan_scan` | WordPress-specific vulnerability scan |
| `dirb_scan` | Directory & file brute-forcing |
| `searchsploit` | Offline Exploit-DB search |
| `ping_host` | ICMP reachability check |
| `dns_lookup` | DNS record queries |
| `whois_lookup` | Domain/IP registration info |
| `quick_port_check` | Fast TCP connect scan on specific ports |

## Security Features

- **Non-root execution** — runs as `mcpuser` with minimal Linux capabilities
- **Input sanitization** — blocks shell injection characters (`sanitizer.py`)
- **Target allow-list** — restrict scanning to authorized networks via `MCP_ALLOWED_TARGETS`
- **Rate limiting** — sliding-window cap via `MCP_RATE_LIMIT_PER_MIN` (`rate_limiter.py`)
- **Timeout enforcement** — kills runaway scans after `MCP_MAX_SCAN_TIMEOUT` seconds
- **Output truncation** — prevents context window overflow (`formatter.py`)
- **Capability-based permissions** — only `NET_RAW` + `NET_BIND_SERVICE`
- **Read-only containers** with tmpfs for scratch space

## Development Notes

- All tools follow a `register(mcp, rate_limiter)` pattern — see any `tools/*.py` for reference.
- Tool output is structured text (header / body / footer) via `tools/formatter.py`.
- Subprocess execution is handled by `tools/runner.py` with configurable timeouts.
- `tools/sanitizer.py` is the security boundary — all target inputs pass through here.
- Port is `8083` everywhere (Dockerfile `ENV`, docker-compose port mapping, server.py fallback).
