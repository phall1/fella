#!/bin/bash
# Integration Test: Tor Backend
# Verifies that Tor daemon starts, is reachable, and stops cleanly
# REQUIRES ROOT + tor package installed

set -euo pipefail

FELLA="${1:-./zig-out/bin/fella}"

echo "[TEST] Tor backend lifecycle"

# Check tor binary exists
if ! command -v tor > /dev/null 2>&1; then
    echo "      SKIPPED: tor binary not installed"
    exit 0
fi

# Clean state
sudo pkill -9 tor 2>/dev/null || true
sudo rm -f /var/lib/fella/tor.pid
sleep 1

# Start fella (which starts Tor)
$FELLA init > /dev/null 2>&1
$FELLA start > /dev/null 2>&1

# Check 127.0.0.1:9050 is listening
if ss -tlnp | grep -q ':9050'; then
    echo "      PASS: Tor SOCKS port listening"
else
    echo "      FAIL: Tor SOCKS port not listening"
    $FELLA stop > /dev/null 2>&1 || true
    exit 1
fi

# Check via fella status
STATUS_OUT=$($FELLA status 2>&1)
if echo "$STATUS_OUT" | grep -q 'Tor:.*running'; then
    echo "      PASS: fella status reports Tor running"
else
    echo "      FAIL: fella status does not report Tor running"
    echo "      Output was: $STATUS_OUT"
    $FELLA stop > /dev/null 2>&1 || true
    exit 1
fi

# Stop fella (which stops Tor)
$FELLA stop > /dev/null 2>&1

# Verify no tor on 9050
if ss -tlnp | grep -q ':9050'; then
    echo "      FAIL: Tor still listening after stop"
    exit 1
else
    echo "      PASS: Tor stopped cleanly"
fi

echo "      All Tor backend checks passed"
