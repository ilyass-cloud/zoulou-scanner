# ============================================================================
# Security Orchestrator – Scanner Runner Image
# ============================================================================
# This is the BACKEND *executor* container. It is ephemeral: the web /
# orchestrator container spins one up per scan, mounts the target read-only,
# passes a deterministic plan (plan.json), and the runner only *executes* the
# planned scanner tools – it does NOT plan, normalise, score or call the LLM.
# All of that lives in the lightweight web image (see web/Dockerfile).
#
# Build:
#   docker build -t security-orchestrator .
#
# Run (normally invoked automatically by the web container):
#   docker run --rm \
#     -v /path/to/target:/scan/target:ro \
#     -v scans-data:/app/scans \
#     security-orchestrator \
#     python -m orchestrator.main run-plan --plan /app/scans/<run_id>/plan.json --verbose
# ============================================================================

FROM python:3.12-slim AS base

LABEL maintainer="Security Orchestrator"
LABEL description="Ephemeral scanner-runner: executes a deterministic scan plan"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# ── 1. System dependencies + scanners ────────────────────────────────────────
# Install all external scanning tools (cached layer if the script is unchanged).
COPY scripts/install_scanners.sh /tmp/install_scanners.sh
RUN chmod +x /tmp/install_scanners.sh && \
    /tmp/install_scanners.sh && \
    rm -f /tmp/install_scanners.sh

# ── 2. Python dependencies (includes pip-installable scanners) ───────────────
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# ── 3. Orchestrator code only ────────────────────────────────────────────────
# The runner needs the orchestrator package (models, planner rebuild, plugins).
# It does NOT serve the web UI, so web/ and examples/ are intentionally omitted.
COPY orchestrator/ ./orchestrator/
COPY tools_registry.yaml .

# Mount points: target repo (read-only) and shared scans volume (plan + results)
RUN mkdir -p /scan/target /app/scans /app/out

# ── 4. Default command ───────────────────────────────────────────────────────
# The web container overrides this with an explicit `run-plan` invocation.
# Showing help by default makes a bare `docker run` self-documenting.
CMD ["python", "-m", "orchestrator.main", "run-plan", "--help"]