#!/bin/bash

# ============================================================================
# Security Orchestrator – Scanner Installer
# ============================================================================
# Installs all external scanning tools used by the orchestrator.
# Run this script inside the Docker build or on any Debian/Ubuntu host.
#
# Each tool is installed independently so a single failure doesn't block
# the rest. The script prints a summary at the end.
# ============================================================================

# Do NOT use set -e: individual install failures are handled per-tool
set -uo pipefail

INSTALLED=()
FAILED=()

log()  { echo -e "\n\033[1;34m[INSTALL]\033[0m $*"; }
ok()   { echo -e "  \033[1;32m✔\033[0m $*"; INSTALLED+=("$1"); }
fail() { echo -e "  \033[1;31m✘\033[0m $*"; FAILED+=("$1"); }

# ── System packages (apt) ────────────────────────────────────────────────────
log "Installing system dependencies..."
apt-get update -qq
apt-get install -y --no-install-recommends \
    curl wget git unzip ca-certificates gnupg \
    nmap \
    npm \
    > /dev/null 2>&1
ok "system-packages" "apt packages (curl, git, nmap, npm)"

# ── Python-based scanners (pip) ──────────────────────────────────────────────
log "Installing Python-based scanners..."

# Semgrep – multi-language SAST
if pip install --no-cache-dir semgrep 2>/dev/null; then
    ok "semgrep" "$(semgrep --version 2>/dev/null || echo 'installed')"
else
    fail "semgrep" "pip install semgrep failed"
fi

# Bandit – Python SAST
if pip install --no-cache-dir bandit 2>/dev/null; then
    ok "bandit" "$(bandit --version 2>/dev/null || echo 'installed')"
else
    fail "bandit" "pip install bandit failed"
fi

# pip-audit – Python dependency auditing
if pip install --no-cache-dir pip-audit 2>/dev/null; then
    ok "pip-audit" "$(pip-audit --version 2>/dev/null || echo 'installed')"
else
    fail "pip-audit" "pip install pip-audit failed"
fi

# Safety – Python dependency checking
if pip install --no-cache-dir safety 2>/dev/null; then
    ok "safety" "$(safety --version 2>/dev/null || echo 'installed')"
else
    fail "safety" "pip install safety failed"
fi

# ── Go-based scanners (binary downloads) ─────────────────────────────────────
log "Installing Go-based scanners..."

# Gitleaks – secret detection
GITLEAKS_VERSION="8.30.0"
if curl -sSfL "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz" \
    | tar -xz -C /usr/local/bin gitleaks 2>/dev/null; then
    chmod +x /usr/local/bin/gitleaks
    ok "gitleaks" "v${GITLEAKS_VERSION}"
else
    fail "gitleaks" "download failed"
fi

# TruffleHog – secret detection
TRUFFLEHOG_VERSION="3.93.7"
if curl -sSfL "https://github.com/trufflesecurity/trufflehog/releases/download/v${TRUFFLEHOG_VERSION}/trufflehog_${TRUFFLEHOG_VERSION}_linux_amd64.tar.gz" \
    | tar -xz -C /usr/local/bin trufflehog 2>/dev/null; then
    chmod +x /usr/local/bin/trufflehog
    ok "trufflehog" "v${TRUFFLEHOG_VERSION}"
else
    fail "trufflehog" "download failed"
fi

# Trivy – container/filesystem/IaC scanner
log "Installing Trivy..."
if curl -sSfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin 2>/dev/null; then
    ok "trivy" "$(trivy --version 2>/dev/null | head -1 || echo 'installed')"
else
    fail "trivy" "install script failed"
fi

# Grype – container vulnerability scanner
log "Installing Grype..."
if curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin 2>/dev/null; then
    ok "grype" "$(grype version 2>/dev/null | head -1 || echo 'installed')"
else
    fail "grype" "install script failed"
fi

# ── Nmap (already installed via apt above) ───────────────────────────────────
if command -v nmap &>/dev/null; then
    ok "nmap" "$(nmap --version 2>/dev/null | head -1 || echo 'installed')"
else
    fail "nmap" "not found after apt install"
fi

# ── npm audit (comes with npm, already installed via apt) ────────────────────
if command -v npm &>/dev/null; then
    ok "npm-audit" "npm $(npm --version 2>/dev/null)"
else
    fail "npm-audit" "npm not found"
fi

# ── Cleanup ──────────────────────────────────────────────────────────────────
log "Cleaning up..."
apt-get clean
rm -rf /var/lib/apt/lists/* /tmp/* /root/.cache

# ── Summary ──────────────────────────────────────────────────────────────────
echo ""
echo "============================================"
echo " Scanner Installation Summary"
echo "============================================"
echo ""
echo " Installed (${#INSTALLED[@]}):"
for t in "${INSTALLED[@]}"; do
    echo "   ✔ $t"
done
echo ""
if [ ${#FAILED[@]} -gt 0 ]; then
    echo " Failed (${#FAILED[@]}):"
    for t in "${FAILED[@]}"; do
        echo "   ✘ $t"
    done
    echo ""
    echo " Some scanners failed to install."
    echo " They can be installed later or disabled in the Tools Registry."
else
    echo " All scanners installed successfully!"
fi
echo "============================================"

