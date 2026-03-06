# =============================================================================
# Kali Linux MCP Security Server
# Non-root container with pentest tools exposed via FastMCP
# =============================================================================
FROM kalilinux/kali-rolling:latest

LABEL maintainer="secops-mcp"
LABEL description="MCP Security Server with pentesting tools on Kali Linux"

# ── Environment configuration ────────────────────────────────────────────────
ENV DEBIAN_FRONTEND=noninteractive \
    MCP_HOST=0.0.0.0 \
    MCP_PORT=8083 \
    MCP_LOG_LEVEL=INFO \
    MCP_MAX_SCAN_TIMEOUT=3600 \
    MCP_ALLOWED_TARGETS="" \
    MCP_RATE_LIMIT_PER_MIN=30 \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# ── Install security tools & Python ──────────────────────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    nikto \
    sqlmap \
    wpscan \
    dirb \
    exploitdb \
    python3 \
    python3-pip \
    python3-venv \
    libcap2-bin \
    iputils-ping \
    net-tools \
    curl \
    dnsutils \
    whois \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# ── Create non-root user ────────────────────────────────────────────────────
RUN groupadd -r mcpuser && useradd -r -g mcpuser -m -s /bin/bash mcpuser

# ── Set capabilities for network tools (instead of running as root) ──────────
# /usr/bin/nmap is a wrapper script; real binary is /usr/lib/nmap/nmap
# Kali sets cap_net_admin on nmap by default — we strip it to only what we need,
# otherwise exec fails when cap_net_admin is not in the container bounding set.
RUN setcap cap_net_raw,cap_net_bind_service+eip /usr/lib/nmap/nmap \
    && setcap cap_net_raw+eip /usr/bin/ping

# ── Python environment ──────────────────────────────────────────────────────
RUN python3 -m venv /opt/mcp-venv
ENV PATH="/opt/mcp-venv/bin:$PATH"

COPY requirements.txt /opt/mcp-server/requirements.txt
RUN pip install --no-cache-dir -r /opt/mcp-server/requirements.txt

# ── Copy application code ───────────────────────────────────────────────────
COPY --chown=mcpuser:mcpuser . /opt/mcp-server
WORKDIR /opt/mcp-server

# ── Create working directories ──────────────────────────────────────────────
RUN mkdir -p /opt/mcp-server/logs /opt/mcp-server/reports \
    && chown -R mcpuser:mcpuser /opt/mcp-server

ENV PYTHONPATH="/opt/mcp-server"

# ── Switch to non-root ──────────────────────────────────────────────────────
USER mcpuser

EXPOSE ${MCP_PORT}

HEALTHCHECK --interval=30s --timeout=10s --retries=3 \
    CMD curl -f http://localhost:${MCP_PORT}/health || exit 1

ENTRYPOINT ["python3", "server.py"]