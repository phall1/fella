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

# This test is a stub until Tor backend is implemented
# When implemented:
# 1. fella start (starts Tor)
# 2. Check 127.0.0.1:9050 is listening
# 3. proxychains4 curl through it
# 4. fella stop (stops Tor)
# 5. Verify no tor processes owned by debian-tor

echo "      SKIPPED: Tor backend not yet implemented"
