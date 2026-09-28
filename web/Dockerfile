# ============================================================================
# Security Orchestrator – Web container  (Node backend + React UI + Py brain)
# ============================================================================
# This is the FRONTEND + BRAIN container. It runs:
#   * the React SPA (built here, served statically by the Node server), and
#   * the Node/Express backend (web/server) which owns all HTTP/SSE/uploads/DB.
# The Node server invokes the Python orchestrator *brain* as a CLI
# (plan / postprocess / env-detect / auto-plan) and launches the ephemeral
# *scanner-runner* container (security-orchestrator) via the Docker socket.
# It holds NO scanners.
#
# Build (from project root):
#   docker build -f web/Dockerfile -t security-orchestrator-web .
#
# Run (Docker socket required so it can start runner containers):
#   docker run -p 5000:5000 \
#     -v /var/run/docker.sock:/var/run/docker.sock \
#     -v /data/scans:/data/scans -e SCANS_DIR=/data/scans \
#     security-orchestrator-web
# ============================================================================

# ── Stage 1: build the React client ─────────────────────────────────────────
FROM node:20-bookworm-slim AS client
WORKDIR /client
COPY web/client/package*.json ./
RUN npm ci
COPY web/client/ ./
RUN npm run build      # → /client/dist

# ── Stage 2: runtime (Node + Python + docker CLI) ───────────────────────────
FROM node:20-bookworm-slim

LABEL maintainer="Security Orchestrator"
LABEL description="Security scanning orchestrator – Node backend + React UI"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Docker CLI (to launch runner containers) + Python (orchestrator brain)
RUN apt-get update -qq && \
    apt-get install -y --no-install-recommends \
      ca-certificates curl gnupg git python3 python3-pip && \
    install -m 0755 -d /etc/apt/keyrings && \
    curl -fsSL https://download.docker.com/linux/debian/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg && \
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
      https://download.docker.com/linux/debian $(. /etc/os-release && echo $VERSION_CODENAME) stable" \
      > /etc/apt/sources.list.d/docker.list && \
    apt-get update -qq && \
    apt-get install -y --no-install-recommends docker-ce-cli && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Python brain dependencies (pydantic + pyyaml only – no scanners, no Flask)
COPY web/requirements.txt ./web/requirements.txt
RUN pip3 install --no-cache-dir --break-system-packages -r web/requirements.txt

# Node backend dependencies
COPY web/server/package*.json ./web/server/
RUN cd web/server && npm ci --omit=dev

# Application code
COPY orchestrator/ ./orchestrator/
COPY web/server/   ./web/server/
COPY examples/     ./examples/
COPY tools_registry.yaml ./
# Built SPA from stage 1
COPY --from=client /client/dist ./web/client/dist

# Runtime directories (scans/ is expected to be a shared volume)
RUN mkdir -p /app/scans /app/uploads /app/configs

# Environment defaults
ENV SCANNER_IMAGE="security-orchestrator" \
    LLM_BASE_URL="http://host.docker.internal:1234" \
    PROJECT_ROOT="/app" \
    SCANS_DIR="scans" \
    CLIENT_DIST="/app/web/client/dist" \
    PYTHON_BIN="python3" \
    PORT="5000"

EXPOSE 5000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD node -e "require('http').get('http://localhost:'+(process.env.PORT||5000)+'/api/ignore-patterns',r=>process.exit(r.statusCode===200?0:1)).on('error',()=>process.exit(1))"

WORKDIR /app/web/server
CMD ["node", "index.js"]
