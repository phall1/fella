#!/usr/bin/env bash
# Never replace an existing VM checkout, or install packages implicitly.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
MACHINE="${1:-fella-test}"
# Avoid copying macOS extended attributes into the Linux test tree.
export COPYFILE_DISABLE=1
# shellcheck disable=SC2016
tar --no-xattrs -cf - -C "$ROOT" \
    --exclude='.git' --exclude='.zig-cache' --exclude='zig-out' --exclude='__pycache__' . |
    orb -m "$MACHINE" bash -c '
        set -euo pipefail
        stage="$(mktemp -d "${TMPDIR:-/tmp}/fella-source.XXXXXXXX")"
        trap '\''rm -rf "$stage"'\'' EXIT
        tar -xf - -C "$stage"
        cd "$stage"
        bash scripts/zig.sh fmt --check build.zig build.zig.zon src
        bash scripts/zig.sh build test --summary all
        bash scripts/zig.sh build -Doptimize=ReleaseSafe
        python3 tests/integration.py zig-out/bin/fella
    '
