#!/usr/bin/env bash
# bin/install_browser.sh — Idempotent browser binary installer.
#
# Installs:
#   1. Playwright Chromium (required by src/agents/browser/*)
#   2. agent-browser (optional — Vercel Rust CLI; gracefully degrades when absent)
#
# Usage:
#   bin/install_browser.sh              # install both
#   bin/install_browser.sh --playwright  # playwright only
#   bin/install_browser.sh --agent-browser # agent-browser only
#   bin/install_browser.sh --verify     # verify only, no install
#
# Idempotent: re-running on an already-installed environment is a fast no-op.

set -uo pipefail

# Resolve repo root from this script's location (works from any CWD)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

# Locate the Python interpreter (prefer .venv)
if [[ -x "$REPO_ROOT/.venv/bin/python" ]]; then
    PYTHON="$REPO_ROOT/.venv/bin/python"
elif command -v python3 >/dev/null 2>&1; then
    PYTHON="$(command -v python3)"
else
    echo "[install_browser] FATAL: no python3 found on PATH" >&2
    exit 1
fi

# ----------------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------------
log()  { echo "[install_browser] $*"; }
warn() { echo "[install_browser] WARN: $*" >&2; }
err()  { echo "[install_browser] ERROR: $*" >&2; }

# ----------------------------------------------------------------------------
# Playwright Chromium
# ----------------------------------------------------------------------------
install_playwright() {
    log "Installing Playwright Chromium..."

    if ! "$PYTHON" -c "import playwright" 2>/dev/null; then
        warn "playwright python package not installed; attempting pip install"
        "$PYTHON" -m pip install --quiet playwright || {
            err "pip install playwright failed. Activate your venv and try again."
            return 1
        }
    fi

    # `playwright install chromium` is idempotent — re-running skips already-installed
    if "$PYTHON" -m playwright install chromium 2>&1 | tee /tmp/pw-install.log; then
        log "Playwright install command completed"
    else
        err "Playwright install failed; see /tmp/pw-install.log"
        return 1
    fi

    # Verify the chromium binary is on disk
    local pw_cache="${PLAYWRIGHT_BROWSERS_PATH:-$HOME/Library/Caches/ms-playwright}"
    local chromium_dir
    chromium_dir=$(find "$pw_cache" -maxdepth 2 -type d -name "chromium-*" 2>/dev/null | head -1)
    if [[ -z "$chromium_dir" ]]; then
        # Linux path
        pw_cache="${PLAYWRIGHT_BROWSERS_PATH:-$HOME/.cache/ms-playwright}"
        chromium_dir=$(find "$pw_cache" -maxdepth 2 -type d -name "chromium-*" 2>/dev/null | head -1)
    fi

    if [[ -n "$chromium_dir" && -x "$chromium_dir/chrome-linux/chrome" ]]; then
        log "Playwright Chromium verified at: $chromium_dir/chrome-linux/chrome"
        return 0
    elif [[ -n "$chromium_dir" && -x "$chromium_dir/chrome-mac/Chromium.app/Contents/MacOS/Chromium" ]]; then
        log "Playwright Chromium verified at: $chromium_dir/chrome-mac/Chromium.app/Contents/MacOS/Chromium"
        return 0
    fi

    warn "Could not verify Playwright Chromium binary on disk"
    warn "Set PLAYWRIGHT_BROWSERS_PATH or re-run 'python -m playwright install chromium'"
    return 1
}

# ----------------------------------------------------------------------------
# agent-browser (Vercel Rust CLI)
# ----------------------------------------------------------------------------
# Optional: if absent, the operator module logs a warning and falls back to
# HTTPX-only recon. We do NOT fail the install on a missing agent-browser.
install_agent_browser() {
    if command -v agent-browser >/dev/null 2>&1; then
        log "agent-browser already on PATH: $(command -v agent-browser)"
        return 0
    fi

    log "agent-browser not on PATH — attempting install"

    # Homebrew path (macOS / Linuxbrew)
    if command -v brew >/dev/null 2>&1; then
        if brew install agent-browser 2>/dev/null; then
            log "Installed agent-browser via Homebrew"
            return 0
        fi
        warn "brew install agent-browser failed; skipping"
    fi

    # Cargo path (if user has Rust toolchain)
    if command -v cargo >/dev/null 2>&1; then
        if cargo install agent-browser 2>/dev/null; then
            log "Installed agent-browser via cargo"
            return 0
        fi
        warn "cargo install agent-browser failed; skipping"
    fi

    # npm path (last resort — official Vercel pkg)
    if command -v npm >/dev/null 2>&1; then
        if npm install -g agent-browser 2>/dev/null; then
            log "Installed agent-browser via npm"
            return 0
        fi
        warn "npm install -g agent-browser failed; skipping"
    fi

    warn "agent-browser install skipped — browser operator will fall back to HTTPX-only recon"
    warn "Install manually from https://github.com/vercel-labs/agent-browser and re-run"
    return 0
}

verify_only() {
    log "Verifying browser binaries (no install)..."

    local ok=0
    if command -v agent-browser >/dev/null 2>&1; then
        log "OK: agent-browser at $(command -v agent-browser)"
    else
        warn "MISSING: agent-browser (HTTPX-only recon will be used)"
        ok=1
    fi

    local pw_cache="${PLAYWRIGHT_BROWSERS_PATH:-$HOME/Library/Caches/ms-playwright}"
    local chromium_dir
    chromium_dir=$(find "$pw_cache" -maxdepth 2 -type d -name "chromium-*" 2>/dev/null | head -1)
    if [[ -z "$chromium_dir" ]]; then
        pw_cache="${PLAYWRIGHT_BROWSERS_PATH:-$HOME/.cache/ms-playwright}"
        chromium_dir=$(find "$pw_cache" -maxdepth 2 -type d -name "chromium-*" 2>/dev/null | head -1)
    fi

    if [[ -n "$chromium_dir" ]]; then
        log "OK: Playwright Chromium at $chromium_dir"
    else
        warn "MISSING: Playwright Chromium"
        ok=1
    fi

    if [[ $ok -eq 0 ]]; then
        log "All browser binaries verified"
        return 0
    else
        warn "One or more browser binaries missing — run without --verify to install"
        return 1
    fi
}

# ----------------------------------------------------------------------------
# Entry point
# ----------------------------------------------------------------------------
case "${1:-all}" in
    --playwright)
        install_playwright
        ;;
    --agent-browser)
        install_agent_browser
        ;;
    --verify)
        verify_only
        ;;
    --help|-h)
        cat <<'EOF'
install_browser.sh — Idempotent browser binary installer

Usage:
  install_browser.sh                  Install Playwright + agent-browser
  install_browser.sh --playwright     Install Playwright Chromium only
  install_browser.sh --agent-browser  Install agent-browser only (best-effort)
  install_browser.sh --verify         Verify binaries (no install)
  install_browser.sh --help           Show this help

Environment:
  PLAYWRIGHT_BROWSERS_PATH   Override Playwright browser cache directory
EOF
        ;;
    all|"")
        install_playwright || warn "Playwright install had errors (continuing)"
        install_agent_browser
        log "Done. Run with --verify to confirm install."
        ;;
    *)
        err "Unknown option: $1 (use --help)"
        exit 2
        ;;
esac
