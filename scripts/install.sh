#!/bin/sh
# TomPanel guided installer for Ubuntu Server 24.04 LTS (AMD64).
# Stops on stack conflicts, never turns an existing host into a managed host
# by inference, and enables private access only.
set -eu

fail() { echo "ERROR: $1" >&2; exit 1; }
note() { echo "==> $1"; }

[ "$(id -u)" = "0" ] || fail "run as root"
[ "$(uname -m)" = "x86_64" ] || fail "only AMD64 is supported"
# shellcheck source=/dev/null
. /etc/os-release
[ "$ID" = "ubuntu" ] && [ "$VERSION_ID" = "24.04" ] || fail "only Ubuntu Server 24.04 LTS is supported"

# Conflict checks: an existing panel or foreign web stack stops the install.
[ -d /etc/tompanel ] && fail "/etc/tompanel already exists; this host is not fresh"
systemctl is-active --quiet tompanel.service 2>/dev/null && fail "tompanel is already installed"
if [ -f /etc/nginx/sites-enabled/default ] && grep -q "default_server" /etc/nginx/sites-enabled/default 2>/dev/null; then
    note "disabling the stock Nginx default site"
    rm -f /etc/nginx/sites-enabled/default
fi

MEMORY_MB=$(awk '/MemTotal/ {print int($2/1024)}' /proc/meminfo)
[ "$MEMORY_MB" -ge 1024 ] || fail "at least 1 GB of memory is required"
ROOT_GB=$(df -BG / | awk 'NR==2 {gsub("G",""); print $4}')
[ "$ROOT_GB" -ge 10 ] || fail "at least 10 GB of free disk is required"

# Public IPv4 reachability is reported but never required.
if command -v curl >/dev/null 2>&1; then
    PUBLIC_IP=$(curl -fsS --max-time 5 https://api.ipify.org 2>/dev/null || echo "unavailable")
    note "public IPv4: $PUBLIC_IP"
fi

# Swap: create 2 GB only when none exists.
if [ "$(swapon --show | wc -l)" = "0" ]; then
    note "creating a 2 GB swapfile"
    fallocate -l 2G /swapfile
    chmod 0600 /swapfile
    mkswap /swapfile
    swapon /swapfile
    grep -q '^/swapfile' /etc/fstab || echo '/swapfile none swap sw 0 0' >> /etc/fstab
else
    note "existing swap detected; keeping it"
fi

export DEBIAN_FRONTEND=noninteractive
note "installing base packages"
apt-get update
apt-get install -y --no-install-recommends curl ca-certificates openssh-server unattended-upgrades

# OpenSSH is allowed before the firewall turns on so the session survives.
note "allowing OpenSSH before enabling UFW"
ufw allow OpenSSH
ufw --force enable

# PHP PPA is optional and requires explicit consent.
if [ "${TOMPANEL_PHP_PPA:-}" = "consent" ]; then
    note "adding the PHP PPA (explicit consent recorded)"
    apt-get install -y --no-install-recommends software-properties-common
    add-apt-repository -y ppa:ondrej/php
    apt-get update
else
    note "PHP PPA skipped; using the distribution PHP"
fi

PACKAGE="${1:-./tompanel.deb}"
[ -f "$PACKAGE" ] || fail "package $PACKAGE not found (pass the path to the signed .deb)"
note "installing $PACKAGE"
apt-get install -y "$PACKAGE"

SETUP_URL=$(sudo -u tompanel /usr/lib/tompanel/tompanel -config /etc/tompanel/config.toml setup-url 2>/dev/null || true)

echo
echo "TomPanel installed and running in private mode."
echo "Open an SSH tunnel:   ssh -L 8080:127.0.0.1:8080 user@this-server"
echo "Then visit:           http://127.0.0.1:8080"
if [ -n "$SETUP_URL" ]; then
    echo "One-time setup URL (valid 15 minutes, run on the server):"
    echo "  $SETUP_URL"
fi
