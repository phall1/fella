#!/bin/bash
# Integration Test: Platform Probe
# Verifies that `fella doctor` correctly detects the environment

set -euo pipefail

FELLA="${1:-./zig-out/bin/fella}"

echo "[TEST] Platform probe detects virtualization"

# Run doctor and capture output
OUTPUT=$($FELLA doctor 2>&1)

# Check that virtualization is reported
if echo "$OUTPUT" | grep -q "Virtualization:"; then
    echo "      PASS: Virtualization field present"
else
    echo "      FAIL: Virtualization field missing"
    exit 1
fi

# Check that interface is reported
if echo "$OUTPUT" | grep -q "Interface:"; then
    echo "      PASS: Interface field present"
else
    echo "      FAIL: Interface field missing"
    exit 1
fi

# Check that capabilities are reported
if echo "$OUTPUT" | grep -q "SYS_ADMIN:"; then
    echo "      PASS: SYS_ADMIN field present"
else
    echo "      FAIL: SYS_ADMIN field missing"
    exit 1
fi

echo "      All platform probe checks passed"
