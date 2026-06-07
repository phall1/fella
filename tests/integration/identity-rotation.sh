#!/bin/bash
# Integration Test: Identity Rotation
# Verifies that fella rotate actually changes hostname
# REQUIRES ROOT

set -euo pipefail

FELLA="${1:-./zig-out/bin/fella}"

echo "[TEST] Identity rotation changes hostname"

# Save original
ORIG_HOST=$(hostname)
echo "      Original hostname: $ORIG_HOST"

# Clean state
sudo rm -rf /var/lib/fella
sudo pkill -9 tor 2>/dev/null || true

$FELLA init > /dev/null 2>&1
$FELLA start > /dev/null 2>&1
NEW_HOST=$(hostname)
echo "      New hostname: $NEW_HOST"

if [[ "$ORIG_HOST" == "$NEW_HOST" ]]; then
    echo "      FAIL: Hostname did not change"
    $FELLA stop > /dev/null 2>&1 || true
    exit 1
fi

$FELLA stop > /dev/null 2>&1
RESTORED_HOST=$(hostname)

if [[ "$ORIG_HOST" != "$RESTORED_HOST" ]]; then
    echo "      FAIL: Hostname not restored (got $RESTORED_HOST, expected $ORIG_HOST)"
    exit 1
fi

echo "      PASS: Hostname rotated and restored"
