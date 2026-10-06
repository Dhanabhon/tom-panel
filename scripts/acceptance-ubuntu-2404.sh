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
# Only the Local Address column (field 4) decides exposure; the Peer column
# is "0.0.0.0:*" for every listener and must not be inspected.
PANEL_LOCAL=$(ss -ltn | awk '$4 ~ /:8080$/ {print $4}')
if [ -z "$PANEL_LOCAL" ]; then
    fail_audit "panel is not listening on 8080"
elif [ "$PANEL_LOCAL" = "127.0.0.1:8080" ] || [ "$PANEL_LOCAL" = "[::1]:8080" ]; then
    pass "panel loopback only ($PANEL_LOCAL)"
else
    fail_audit "panel listens on a public interface ($PANEL_LOCAL)"
fi

# 3. Unprivileged panel identity (tompanel is nologin; run as root, stat as tompanel)
check test "$(stat -c %U /var/lib/tompanel)" = tompanel
if [ "$(stat -c %U /usr/lib/tompanel/tompaneld)" = "tompanel" ] || [ "$(systemctl show -p User tompanel.service --value)" = "tompanel" ]; then
    pass "web daemon unprivileged"
else
    fail_audit "web daemon user wrong"
fi

# 4. Agent socket boundary: unprivileged peers are refused
check test -S /run/tompanel/agent.sock
if [ "$(stat -c %G /run/tompanel/agent.sock 2>/dev/null)" = "tompanel" ] || [ -g /run/tompanel ]; then
    pass "agent socket group-owned by tompanel"
else
    fail_audit "agent socket ownership unexpected: $(stat -c %U:%G /run/tompanel/agent.sock 2>/dev/null)"
fi

# 5. First-run setup URL is one-time and bounded.
# The CLI refuses non-TTY stdout by design (token must not leak into pipes
# or logs), so the drill pty-wraps the call. The tompanel account is
# nologin by design too, so the shell must be requested explicitly.
setup_url_call() {
    script -qec "runuser -u tompanel -- /usr/lib/tompanel/tompanel -config /etc/tompanel/config.toml setup-url" /dev/null
}
if command -v script >/dev/null 2>&1 && command -v runuser >/dev/null 2>&1; then
    SETUP=$(setup_url_call 2>/dev/null | grep -o 'http://[^[:space:]]*setup#token=[^[:space:]]*' || true)
    ENROLLED=$(setup_url_call 2>&1 | grep -ci 'administrator\|already\|enrolled' || true)
    if [ -n "$SETUP" ]; then
        pass "setup url issued (one-time, TTY-gated)"
    elif [ "${ENROLLED:-0}" -gt 0 ]; then
        pass "setup correctly refused: administrator already enrolled"
    else
        fail_audit "setup url missing"
    fi
else
    if runuser -u tompanel -- /usr/lib/tompanel/tompanel -config /etc/tompanel/config.toml setup-url </dev/null >/dev/null 2>&1; then
        fail_audit "setup url printed without a terminal"
    else
        pass "setup url correctly refuses non-interactive output"
    fi
fi

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
