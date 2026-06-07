#!/bin/bash
# Integration Test: Netns Shell
# Verifies that fella shell routes traffic through Tor
# REQUIRES ROOT

set -euo pipefail

FELLA="${1:-./zig-out/bin/fella}"

echo "[TEST] Netns shell routes through Tor"

# Clean state
sudo rm -rf /var/lib/fella
sudo pkill -9 tor 2>/dev/null || true
sleep 1

$FELLA init > /dev/null 2>&1
$FELLA start > /dev/null 2>&1

# Run curl inside fella shell and capture output
OUT=$(echo 'curl -s --max-time 15 https://check.torproject.org/api/ip' | $FELLA shell 2>&1 | grep -o '{.*}' || echo "FAIL")

if echo "$OUT" | grep -q 'IsTor.*true'; then
    echo "      PASS: Traffic routed through Tor in shell"
else
    echo "      FAIL: Not routing through Tor (got: $OUT)"
    $FELLA stop > /dev/null 2>&1 || true
    exit 1
fi

$FELLA stop > /dev/null 2>&1
echo "      All netns shell checks passed"
