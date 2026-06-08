#!/bin/bash
# Integration Test: Doctor command
# Verifies fella doctor detects environment and dependencies
# REQUIRES ROOT

set -euo pipefail

FELLA="${1:-./zig-out/bin/fella}"

echo "[TEST] Doctor command"

# Run doctor and capture JSON output
OUT=$($FELLA doctor --json 2>/dev/null)

if echo "$OUT" | grep -q '"virtualization"'; then
    echo "      PASS: Doctor outputs JSON with virtualization field"
else
    echo "      FAIL: Doctor JSON missing virtualization field"
    echo "      Output: $OUT"
    exit 1
fi

if echo "$OUT" | grep -q '"sys_admin":true'; then
    echo "      PASS: SYS_ADMIN detected as true"
else
    echo "      FAIL: SYS_ADMIN not detected correctly"
    echo "      Output: $OUT"
    exit 1
fi

if echo "$OUT" | grep -q '"net_admin":true'; then
    echo "      PASS: NET_ADMIN detected as true"
else
    echo "      FAIL: NET_ADMIN not detected correctly"
    echo "      Output: $OUT"
    exit 1
fi

# Also test human-readable mode
OUT_HUMAN=$($FELLA doctor 2>/dev/null)
if echo "$OUT_HUMAN" | grep -q 'fella Doctor'; then
    echo "      PASS: Human-readable doctor works"
else
    echo "      FAIL: Human-readable doctor missing header"
    exit 1
fi

echo "      All doctor checks passed"
