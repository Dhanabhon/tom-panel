#!/bin/sh
# TomPanel quick install: build from a freshly cloned repository, install,
# and print everything needed to open the browser wizard.
#
# Run from the repository root on a fresh Ubuntu Server 24.04 LTS VPS:
#   git clone https://github.com/Dhanabhon/tom-panel.git
#   cd tomlpanel
#   sudo sh scripts/quick-install.sh
#
# Requires: root, Docker, 900+ MB RAM, 10+ GB disk, no existing /etc/tompanel.
# Optional: PANEL_DOMAIN=panel.example.com PANEL_PORT=4884 for domain guidance.
set -eu

fail() { echo "✗ $1" >&2; exit 1; }
step() { printf "→ %s…\n" "$1"; }
ok()   { printf "  ✓ %s\n" "$1"; }

cd "$(dirname -- "$0")/.."

# ── Preflight ─────────────────────────────────────────────
step "Checking prerequisites"
[ "$(id -u)" = "0" ] || fail "run as root"
[ "$(uname -m)" = "x86_64" ] || fail "only AMD64 is supported"
# shellcheck source=/dev/null
. /etc/os-release
[ "$ID" = "ubuntu" ] && [ "$VERSION_ID" = "24.04" ] || fail "only Ubuntu 24.04 LTS"
[ ! -d /etc/tompanel ] || fail "/etc/tompanel already exists — uninstall first"
command -v docker >/dev/null 2>&1 || fail "Docker is required (apt-get install docker.io)"
docker info >/dev/null 2>&1 || fail "Docker daemon is not running"
MEMORY_MB=$(awk '/MemTotal/ {print int($2/1024)}' /proc/meminfo)
[ "$MEMORY_MB" -ge 900 ] || fail "at least 900 MB RAM required (found ${MEMORY_MB} MB)"
ROOT_GB=$(df -BG / | awk 'NR==2 {gsub("G",""); print $4}')
[ "$ROOT_GB" -ge 10 ] || fail "at least 10 GB disk required"
ok "Ubuntu 24.04 / ${MEMORY_MB} MB RAM / ${ROOT_GB} GB disk"

# ── Build ─────────────────────────────────────────────────
step "Building reproducible .deb (Docker)"
VERSION=$(cat VERSION 2>/dev/null || echo 0.1.1)
./scripts/build-deb.sh "$VERSION" > /tmp/tp-build.log 2>&1 || {
    tail -5 /tmp/tp-build.log >&2
    fail "build failed — check /tmp/tp-build.log"
}
DEB="dist/tompanel_${VERSION}_amd64.deb"
[ -f "$DEB" ] || fail "build produced no .deb"
ok "Built $DEB ($(du -h "$DEB" | cut -f1))"

# ── Install ───────────────────────────────────────────────
step "Installing TomPanel"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y curl ca-certificates openssh-server unattended-upgrades > /dev/null 2>&1
ufw allow OpenSSH > /dev/null 2>&1
ufw --force enable > /dev/null 2>&1
ok "OpenSSH allowed before UFW enabled"
apt-get install -y "$DEB" > /dev/null 2>&1 || {
    apt-get install -y ./"$DEB" 2>&1 | tail -3 >&2
    fail "package installation failed"
}
ok "Package installed"

# ── Wait for health ───────────────────────────────────────
step "Waiting for panel to start"
HEALTHY=""
for _ in $(seq 1 15); do
    if curl -fsS http://127.0.0.1:8080/healthz > /dev/null 2>&1; then
        HEALTHY=1
        break
    fi
    sleep 2
done
[ -n "$HEALTHY" ] || fail "panel did not become healthy (check: journalctl -u tompanel)"
ok "Panel is healthy"

# ── Generate setup URL ────────────────────────────────────
step "Generating one-time setup URL"
SERVER_IP=$(curl -fsS --max-time 5 https://api.ipify.org 2>/dev/null || hostname -I | awk '{print $1}')
SETUP_URL=$(runuser -u tompanel -- /usr/lib/tompanel/tompanel -config /etc/tompanel/config.toml setup-url 2>/dev/null | grep -o 'http://[^ ]*' || true)

# ── Ready card ────────────────────────────────────────────
echo
echo "═══════════════════════════════════════════════════════════"
echo "  ✓ TomPanel $VERSION is installed and running"
echo "═══════════════════════════════════════════════════════════"
echo
echo "  FROM YOUR COMPUTER, open the SSH tunnel:"
echo
echo "    ssh -L 8080:127.0.0.1:8080 root@${SERVER_IP}"
echo
echo "  THEN open this URL in your browser:"
echo
if [ -n "$SETUP_URL" ]; then
    # Rewrite loopback URL so it works through the tunnel
    SETUP_URL="${SETUP_URL#http://127.0.0.1:8080}"
    echo "    http://127.0.0.1:8080${SETUP_URL}"
else
    echo "    http://127.0.0.1:8080"
    echo
    echo "  (if the setup page doesn't load, run this on the server:)"
    echo "    runuser -u tompanel -- /usr/lib/tompanel/tompanel -config /etc/tompanel/config.toml setup-url"
fi
echo
echo "  The browser wizard will guide you through:"
echo "    1. Create your administrator account"
echo "    2. Save your TOTP secret + recovery codes"
if [ -n "${PANEL_DOMAIN:-}" ]; then
    echo "    3. Connect your domain: ${PANEL_DOMAIN} (port ${PANEL_PORT:-4884})"
    echo
    echo "  DNS: Create an A record pointing ${PANEL_DOMAIN} → ${SERVER_IP}"
    echo "  After setup, go to Settings → Panel endpoint to enable HTTPS."
fi
echo
echo "  Docs: https://dhanabhon.github.io/tom-panel/"
echo "═══════════════════════════════════════════════════════════"
