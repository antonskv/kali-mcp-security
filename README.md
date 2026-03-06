# Kali Linux MCP Security Server

An MCP (Model Context Protocol) server that exposes Kali Linux security
tools to LLMs for web pentesting and network vulnerability monitoring.

## Architecture
```
LLM (Claude, OpenAI...)
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

## Quick Start
```bash
# Clone and configure
cp .env.example .env
# Edit .env — set MCP_ALLOWED_TARGETS for safety

# Build and run
docker compose up --build -d

# Verify, it should respond with code 200 and show "event: endpoint" on first line
curl http://localhost:8083/sse

```

## Connecting to Claude Desktop

Add to `claude_desktop_config.json`:
```json
{
  "mcpServers": {
    "kali-security": {
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--cap-add=NET_RAW",
        "--cap-add=NET_BIND_SERVICE",
        "--cap-add=NET_ADMIN",
        "-e",
        "MCP_ALLOWED_TARGETS=",
        "-e",
        "MCP_RATE_LIMIT_PER_MIN=30",
        "-e",
        "MCP_LOG_LEVEL=INFO",
        "kali-mcp-security:latest"
      ]
    }
  }
}
```

## Available Tools

| Tool               | Description                              |
|--------------------|------------------------------------------|
| `nmap_scan`        | Network port/service/vuln scanning       |
| `nikto_scan`       | Web server vulnerability assessment      |
| `sqlmap_scan`      | SQL injection detection & exploitation   |
| `wpscan_scan`      | WordPress-specific vulnerability scan    |
| `dirb_scan`        | Directory & file brute-forcing           |
| `searchsploit`     | Offline Exploit-DB search                |
| `ping_host`        | ICMP reachability check                  |
| `dns_lookup`       | DNS record queries                       |
| `whois_lookup`     | Domain/IP registration info              |
| `quick_port_check` | Fast TCP connect scan on specific ports  |

## Security Features

- **Non-root execution** — runs as `mcpuser` with minimal capabilities
- **Input sanitization** — blocks shell injection characters
- **Target allow-list** — restrict scanning to authorized networks
- **Rate limiting** — configurable per-minute cap
- **Timeout enforcement** — kills runaway scans
- **Output truncation** — prevents context window overflow
- **Capability-based permissions** — only NET_RAW + NET_BIND_SERVICE
- **Read-only containers** with tmpfs for scratch space
