#!/bin/sh
# Remove TomPanel while preserving sites and backups unless the administrator
# confirms their exact paths.
set -eu

fail() { echo "ERROR: $1" >&2; exit 1; }

[ "$(id -u)" = "0" ] || fail "run as root"

systemctl stop tompanel.service tompanel-agent.service 2>/dev/null || true
apt-get remove -y tompanel 2>/dev/null || true

# Ledger-owned resources only: users remain until data removal is confirmed.
if [ "${TOMPANEL_PURGE_SITES:-}" = "/srv/tompanel" ] && [ "${TOMPANEL_PURGE_BACKUPS:-}" = "/var/backups/tompanel" ]; then
    echo "Removing confirmed data paths"
    rm -rf /srv/tompanel /var/backups/tompanel /var/lib/tompanel /etc/tompanel
    if getent passwd tompanel >/dev/null; then deluser --system tompanel; fi
else
    echo "Preserved (pass TOMPANEL_PURGE_SITES=/srv/tompanel and TOMPANEL_PURGE_BACKUPS=/var/backups/tompanel to remove):"
    echo "  /srv/tompanel /var/backups/tompanel /var/lib/tompanel /etc/tompanel"
fi
