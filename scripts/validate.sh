#!/bin/bash
#
# fella Validation Gate Script
# Runs the appropriate test suite based on environment and flags
#

set -euo pipefail

FELLA_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
FELLA_BIN="${FELLA_ROOT}/zig-out/bin/fella"
RED='\033[0;31m'
GRN='\033[0;32m'
YEL='\033[1;33m'
BLU='\033[0;34m'
RST='\033[0m'

usage() {
    echo "Usage: $(basename "$0") [options]"
    echo ""
    echo "Options:"
    echo "  --unit         Run unit tests only (default, no root needed)"
    echo "  --integration  Run integration tests (needs root)"
    echo "  --e2e          Run end-to-end tests (needs root + isolated env)"
    echo "  --all          Run all test levels"
    echo "  --ci           CI mode (same as --all, with JSON output)"
    echo "  --build        Build before testing"
    echo "  --help         Show this message"
    echo ""
}

# Defaults
RUN_UNIT=true
RUN_INTEG=false
RUN_E2E=false
DO_BUILD=false
CI_MODE=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        --unit)        RUN_UNIT=true; RUN_INTEG=false; RUN_E2E=false ;;
        --integration) RUN_UNIT=true; RUN_INTEG=true;  RUN_E2E=false ;;
        --e2e)         RUN_UNIT=true; RUN_INTEG=true;  RUN_E2E=true  ;;
        --all)         RUN_UNIT=true; RUN_INTEG=true;  RUN_E2E=true  ;;
        --ci)          RUN_UNIT=true; RUN_INTEG=true;  RUN_E2E=true; CI_MODE=true ;;
        --build)       DO_BUILD=true ;;
        --help)        usage; exit 0 ;;
        *)             echo "Unknown option: $1"; usage; exit 1 ;;
    esac
    shift
done

check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}[!] This test level requires root${RST}"
        exit 1
    fi
}

run_unit_tests() {
    echo -e "${BLU}=== Unit Tests ===${RST}"
    cd "$FELLA_ROOT"
    zig build test 2>&1 | tee /tmp/fella-unit-tests.log
    local exit_code=${PIPESTATUS[0]}
    if [[ $exit_code -eq 0 ]]; then
        echo -e "${GRN}[+] Unit tests passed${RST}"
    else
        echo -e "${RED}[-] Unit tests failed${RST}"
    fi
    return $exit_code
}

run_integration_tests() {
    echo -e "${BLU}=== Integration Tests ===${RST}"
    check_root

    local failed=0
    local total=0

    for test_script in "$FELLA_ROOT/tests/integration/"*.sh; do
        if [[ -f "$test_script" ]]; then
            total=$((total + 1))
            echo "    Running: $(basename "$test_script")"
            if bash "$test_script" "$FELLA_BIN" 2>&1 | sed 's/^/      /'; then
                echo -e "      ${GRN}PASS${RST}"
            else
                echo -e "      ${RED}FAIL${RST}"
                failed=$((failed + 1))
            fi
        fi
    done

    if [[ $total -eq 0 ]]; then
        echo -e "${YEL}[*] No integration tests found${RST}"
        return 0
    fi

    echo ""
    echo -e "${BLU}Integration: $((total - failed))/$total passed${RST}"
    if [[ $failed -gt 0 ]]; then
        return 1
    fi
}

run_e2e_tests() {
    echo -e "${BLU}=== E2E Tests ===${RST}"
    check_root

    local failed=0
    local total=0

    for test_script in "$FELLA_ROOT/tests/e2e/"*.sh; do
        if [[ -f "$test_script" ]]; then
            total=$((total + 1))
            echo "    Running: $(basename "$test_script")"
            if bash "$test_script" "$FELLA_BIN" 2>&1 | sed 's/^/      /'; then
                echo -e "      ${GRN}PASS${RST}"
            else
                echo -e "      ${RED}FAIL${RST}"
                failed=$((failed + 1))
            fi
        fi
    done

    if [[ $total -eq 0 ]]; then
        echo -e "${YEL}[*] No E2E tests found${RST}"
        return 0
    fi

    echo ""
    echo -e "${BLU}E2E: $((total - failed))/$total passed${RST}"
    if [[ $failed -gt 0 ]]; then
        return 1
    fi
}

# Build if requested
if [[ "$DO_BUILD" == true ]]; then
    echo -e "${BLU}=== Building fella ===${RST}"
    cd "$FELLA_ROOT"
    zig build
fi

# Check binary exists
if [[ ! -x "$FELLA_BIN" ]]; then
    echo -e "${BLU}=== Building fella ===${RST}"
    cd "$FELLA_ROOT"
    zig build
fi

if [[ ! -x "$FELLA_BIN" ]]; then
    echo -e "${RED}[-] fella binary not found at $FELLA_BIN${RST}"
    exit 1
fi

echo -e "${BLU}=== fella Validation ===${RST}"
echo "Binary: $FELLA_BIN"
echo ""

# Run selected suites
OVERALL_EXIT=0

if [[ "$RUN_UNIT" == true ]]; then
    run_unit_tests || OVERALL_EXIT=1
    echo ""
fi

if [[ "$RUN_INTEG" == true ]]; then
    run_integration_tests || OVERALL_EXIT=1
    echo ""
fi

if [[ "$RUN_E2E" == true ]]; then
    run_e2e_tests || OVERALL_EXIT=1
    echo ""
fi

if [[ $OVERALL_EXIT -eq 0 ]]; then
    echo -e "${GRN}[+] ALL VALIDATION PASSED${RST}"
else
    echo -e "${RED}[-] SOME VALIDATION FAILED${RST}"
fi

exit $OVERALL_EXIT
