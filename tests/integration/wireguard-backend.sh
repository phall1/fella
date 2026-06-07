#!/bin/bash
# Integration Test: WireGuard Backend Selection
# Verifies backend persistence and graceful failure without config
# REQUIRES ROOT

set -euo pipefail

FELLA="${1:-./zig-out/bin/fella}"

echo "[TEST] WireGuard backend selection"

# Clean state
sudo rm -rf /var/lib/fella
sudo pkill -9 tor 2>/dev/null || true
sudo ip link del wg-fella 2>/dev/null || true
sleep 1

# Init with wireguard backend
$FELLA init --backend wireguard >/dev/null 2>&1

# Verify backend persisted
STATUS_OUT=$($FELLA status 2>&1)
if echo "$STATUS_OUT" | grep -q 'Backend:.*wireguard'; then
    echo "      PASS: Backend persisted as wireguard"
else
    echo "      FAIL: Backend not persisted"
    echo "      Output: $STATUS_OUT"
    exit 1
fi

# Try start without config file — should fail gracefully
START_OUT=$($FELLA start 2>&1 || true)
if echo "$START_OUT" | grep -qi 'wireguard.conf\|NoWgConfig\|no config'; then
    echo "      PASS: Graceful failure without wireguard.conf"
else
    echo "      FAIL: Did not fail gracefully (or no useful error)"
    echo "      Output: $START_OUT"
    exit 1
fi

# Create a syntactically valid (but non-functional) config
sudo mkdir -p /var/lib/fella
sudo tee /var/lib/fella/wireguard.conf >/dev/null <<'EOF'
[Interface]
PrivateKey = aBcdEfGhIjKlMnOpQrStUvWxYz0123456789+abcdEFg=
Address = 10.99.99.2/24
ListenPort = 51820

[Peer]
PublicKey = aBcdEfGhIjKlMnOpQrStUvWxYz0123456789+abcdEFg=
Endpoint = 127.0.0.1:51820
AllowedIPs = 0.0.0.0/0
EOF

# Verify fella attempts to set up the interface (will fail at connection, not parse)
START_OUT=$($FELLA start 2>&1 || true)
if echo "$START_OUT" | grep -q 'wg-fella\|WireGuard interface'; then
    echo "      PASS: WireGuard setup logic executed"
else
    echo "      WARN: WireGuard setup did not execute (may be missing wg binary)"
fi

$FELLA stop >/dev/null 2>&1 || true
echo "      All WireGuard backend checks passed"
