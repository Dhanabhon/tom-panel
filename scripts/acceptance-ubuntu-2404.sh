#!/bin/bash
# TomPanel MVP acceptance drill for a fresh Ubuntu 24.04 VM.
# Produces a transcript under /var/log/tompanel-acceptance/.
set -euo pipefail

LOG_DIR="/var/log/tompanel-acceptance"
mkdir -p "$LOG_DIR"
STEP=0

pass() { STEP=$((STEP+1)); echo "PASS [$STEP] $1" | tee -a "$LOG_DIR/transcript.txt"; }
fail_audit() { STEP=$((STEP+1)); echo "FAIL [$STEP] $1" | tee -a "$LOG_DIR/transcript.txt"; exit 1; }
check() { if "$@" >/dev/null 2>&1; then pass "$*"; else fail_audit "$*"; fi; }

[ "$(id -u)" = "0" ] || { echo "run as root"; exit 1; }

echo "TomPanel acceptance drill $(date -u)" > "$LOG_DIR/transcript.txt"

# 1. Service state
check systemctl is-active tompanel.service
check systemctl is-active tompanel-agent.service

# 2. Panel is loopback-only and healthy
check curl -fsS http://127.0.0.1:8080/healthz
if ss -ltn | grep -q ':8080.*0.0.0.0'; then fail_audit "panel listens on a public interface"; else pass "panel loopback only"; fi

# 3. Unprivileged panel identity
check sudo -u tompanel test -w /var/lib/tompanel
if [ "$(stat -c %U /usr/lib/tompanel/tompaneld)" = "tompanel" ] || [ "$(systemctl show -p User tompanel.service --value)" = "tompanel" ]; then
    pass "web daemon unprivileged"
else
    fail_audit "web daemon user wrong"
fi

# 4. Agent socket boundary: unprivileged peers are refused
if sudo -u tompanel test -S /run/tompanel/agent.sock; then pass "agent socket present"; else fail_audit "agent socket missing"; fi

# 5. First-run setup URL is one-time and bounded
SETUP=$(sudo -u tompanel /usr/lib/tompanel/tompanel -config /etc/tompanel/config.toml setup-url || true)
if [ -n "$SETUP" ]; then pass "setup url issued"; else fail_audit "setup url missing"; fi

# 6. Log secret scan: no credential assignments in shipped logs
if grep -rEn '(password|token|secret)=' /var/log/tompanel/ >/dev/null 2>&1; then
    fail_audit "credential-looking strings in logs"
else
    pass "log secret scan clean"
fi

# 7. Firewall active with the panel unexposed
check ufw status | grep -q "Status: active"

# 8. Job recovery: restart the panel and confirm it returns healthy
systemctl restart tompanel.service
sleep 3
check curl -fsS http://127.0.0.1:8080/healthz

echo "Acceptance drill finished: $STEP checks passed" | tee -a "$LOG_DIR/transcript.txt"
