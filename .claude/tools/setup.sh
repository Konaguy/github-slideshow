#!/usr/bin/env bash
# Bug bounty toolchain installer.
# Idempotent: skips anything already on PATH. Safe to run at session start.
# Installs recon + scanning tools used by the recon-scout, web-vuln-hunter,
# api-hunter, mobile-recon and code-auditor agents.
set -uo pipefail

log() { printf '\033[1;34m[setup]\033[0m %s\n' "$*"; }
have() { command -v "$1" >/dev/null 2>&1; }

# --- Go (needed for ProjectDiscovery tools + ffuf) --------------------------
if ! have go; then
  log "Go not found; installing Go toolchain..."
  GO_VER="1.22.5"
  ARCH="$(uname -m)"; case "$ARCH" in x86_64) GARCH=amd64;; aarch64|arm64) GARCH=arm64;; *) GARCH=amd64;; esac
  curl -fsSL "https://go.dev/dl/go${GO_VER}.linux-${GARCH}.tar.gz" -o /tmp/go.tgz \
    && rm -rf /usr/local/go && tar -C /usr/local -xzf /tmp/go.tgz && rm -f /tmp/go.tgz
fi
export PATH="$PATH:/usr/local/go/bin:${HOME}/go/bin"
export GOBIN="${HOME}/go/bin"; mkdir -p "$GOBIN"

# --- Go-based tools ---------------------------------------------------------
go_install() { # name  module@version
  if have "$1"; then log "$1 present, skipping"; return; fi
  log "installing $1..."
  GOFLAGS=-mod=mod go install "$2" 2>/dev/null && log "$1 installed" || log "WARN: $1 failed"
}
go_install subfinder github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go_install httpx     github.com/projectdiscovery/httpx/cmd/httpx@latest
go_install nuclei    github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go_install katana    github.com/projectdiscovery/katana/cmd/katana@latest
go_install dnsx      github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go_install ffuf      github.com/ffuf/ffuf/v2@latest
go_install gau       github.com/lc/gau/v2/cmd/gau@latest

# --- Python-based tools -----------------------------------------------------
if have pipx; then PIPX="pipx install"; elif have pip3; then PIPX="pip3 install --quiet"; else PIPX=""; fi
if [ -n "$PIPX" ]; then
  have semgrep || { log "installing semgrep..."; $PIPX semgrep >/dev/null 2>&1 && log "semgrep installed" || log "WARN: semgrep failed"; }
else
  log "WARN: no pip/pipx; skipping semgrep"
fi

# --- gitleaks (secret scanner) ---------------------------------------------
if ! have gitleaks; then
  log "installing gitleaks..."
  GL_VER="8.18.4"; ARCH="$(uname -m)"; case "$ARCH" in x86_64) GLA=x64;; aarch64|arm64) GLA=arm64;; *) GLA=x64;; esac
  curl -fsSL "https://github.com/gitleaks/gitleaks/releases/download/v${GL_VER}/gitleaks_${GL_VER}_linux_${GLA}.tar.gz" -o /tmp/gl.tgz \
    && tar -C "$GOBIN" -xzf /tmp/gl.tgz gitleaks 2>/dev/null && rm -f /tmp/gl.tgz && log "gitleaks installed" || log "WARN: gitleaks failed"
fi

# --- SecLists wordlists (for ffuf content/param discovery) -------------------
SECLISTS_DIR="${SECLISTS_DIR:-$HOME/.local/share/seclists}"
if [ ! -d "$SECLISTS_DIR/Discovery" ]; then
  log "fetching SecLists (shallow) into $SECLISTS_DIR..."
  mkdir -p "$SECLISTS_DIR"
  git clone --depth 1 https://github.com/danielmiessler/SecLists.git "$SECLISTS_DIR" >/dev/null 2>&1 \
    && log "SecLists installed" || log "WARN: SecLists clone failed (fetch manually if needed)"
else
  log "SecLists present at $SECLISTS_DIR, skipping"
fi
export SECLISTS_DIR

# --- nuclei templates -------------------------------------------------------
have nuclei && { log "updating nuclei templates..."; nuclei -update-templates -silent >/dev/null 2>&1 || true; }

log "done. Ensure PATH includes: /usr/local/go/bin and ${HOME}/go/bin"
log "SecLists: $SECLISTS_DIR (set \$SECLISTS_DIR to override)"
log "installed tools:"; for t in subfinder httpx nuclei katana dnsx ffuf gau semgrep gitleaks; do
  if have "$t"; then printf '  \033[1;32m✓\033[0m %s\n' "$t"; else printf '  \033[1;31m✗\033[0m %s\n' "$t"; fi; done
