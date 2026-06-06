#!/bin/bash
# E2E Test: Full Session
# Runs a complete session in an isolated manner
# REQUIRES ROOT + isolated environment (VM/container preferred)
# This test modifies system state.

set -euo pipefail

FELLA="${1:-./zig-out/bin/fella}"

echo "[TEST] E2E: Full session lifecycle"

# Verify we're in a safe environment
if [[ -f /.dockerenv ]]; then
    echo "      INFO: Running in Docker container"
elif [[ -f /run/.containerenv ]]; then
    echo "      INFO: Running in Podman container"
elif systemd-detect-virt 2>/dev/null | grep -q "lxc"; then
    echo "      INFO: Running in LXC container"
else
    echo "      WARN: Not in a container. This test modifies system state."
    echo "      SKIPPED: Run in container for safety"
    exit 0
fi

# Save original state
ORIG_HOST=$(hostname)
ORIG_MID=$(cat /etc/machine-id 2>/dev/null || echo "NONE")

echo "      Original: host=$ORIG_HOST machine-id=$ORIG_MID"

# Clean state
sudo pkill -9 tor 2>/dev/null || true
sudo rm -f /var/lib/fella/tor.pid
sleep 1

# Step 1: Init
$FELLA init > /dev/null 2>&1
echo "      Step 1: init ✓"

# Step 2: Start (identity + tor + basic killswitch)
$FELLA start > /dev/null 2>&1
echo "      Step 2: start ✓"

# Step 3: Verify traffic goes through Tor
IP=$(proxychains4 curl -s --max-time 15 https://checkip.amazonaws.com 2>/dev/null || echo "TIMEOUT")
TOR_CHECK=$(proxychains4 curl -s --max-time 15 https://check.torproject.org/api/ip 2>/dev/null || echo "TIMEOUT")
if echo "$TOR_CHECK" | grep -q 'IsTor.*true'; then
    echo "      Step 3: tor routing verified ✓ (IP: $IP)"
else
    echo "      Step 3: FAIL - not routing through Tor (response: $TOR_CHECK)"
    $FELLA stop > /dev/null 2>&1 || true
    exit 1
fi

# Step 4: Rotate
$FELLA rotate > /dev/null 2>&1
NEW_HOST=$(hostname)
if [[ "$ORIG_HOST" != "$NEW_HOST" ]]; then
    echo "      Step 4: rotation verified ✓ (new host: $NEW_HOST)"
else
    echo "      Step 4: FAIL - hostname did not change"
    $FELLA stop > /dev/null 2>&1 || true
    exit 1
fi

# Step 5: Stop
$FELLA stop > /dev/null 2>&1
echo "      Step 5: stop ✓"

# Step 6: Verify restoration
FINAL_HOST=$(hostname)
if [[ "$ORIG_HOST" == "$FINAL_HOST" ]]; then
    echo "      Step 6: restoration verified ✓"
else
    echo "      Step 6: FAIL - hostname not restored"
    exit 1
fi

echo "      All E2E checks passed"
