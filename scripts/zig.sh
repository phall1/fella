#!/usr/bin/env bash
# Use the pinned compiler without replacing any system installation.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VERSION="$(sed -n 's/^zig = "\([^"]*\)"/\1/p' "$ROOT/.mise.toml")"
if [[ -z "$VERSION" ]]; then
    echo "Cannot read pinned Zig version from .mise.toml" >&2
    exit 1
fi
if [[ -n "${FELLA_ZIG:-}" ]]; then
    ZIG="$FELLA_ZIG"
elif command -v zig >/dev/null && [[ "$(zig version)" == "$VERSION" ]]; then
    ZIG="$(command -v zig)"
else
    ARCH="$(uname -m)"
    case "$(uname -s)" in
        Linux) OS=linux ;;
        Darwin) OS=macos ;;
        *) echo "Unsupported build host; install Zig $VERSION yourself." >&2; exit 1 ;;
    esac
    case "$ARCH-$OS" in
        aarch64-linux) SHA=a1546d5646eb184437918d6635ca6b762a0e889eac09cef720ee7a1ed3fe7795 ;;
        x86_64-linux) SHA=3581863e3cbcfd0fce0efc682ce7e9e93da96668a977791d356a26d2a7e9b17a ;;
        arm64-macos|aarch64-macos) ARCH=aarch64; SHA=75f1bc7a1e9852f17ec9a0c1895f767c4ec56d46bc8a834920eece1d0359dd8d ;;
        x86_64-macos) SHA=9af07b20319fbd0c92ee46ad23e81d6a782b1aaea2cfb8dcbff35f1d2c7ddbb7 ;;
        *) echo "Unsupported architecture; install Zig $VERSION yourself." >&2; exit 1 ;;
    esac
    CACHE="${FELLA_TOOLCHAIN_CACHE:-$HOME/.cache/fella-toolchains}"
    mkdir -p "$CACHE"
    PACKAGE="zig-$ARCH-$OS-$VERSION"
    ZIG="$CACHE/$PACKAGE/zig"
    if [[ ! -x "$ZIG" ]]; then
        STAGE="$(mktemp -d "$CACHE/download.XXXXXXXX")"
        trap 'rm -rf "$STAGE"' EXIT
        curl -fL "https://ziglang.org/download/$VERSION/$PACKAGE.tar.xz" -o "$STAGE/zig.tar.xz" >&2
        if command -v sha256sum >/dev/null; then
            printf '%s  %s\n' "$SHA" "$STAGE/zig.tar.xz" | sha256sum -c - >&2
        else
            printf '%s  %s\n' "$SHA" "$STAGE/zig.tar.xz" | shasum -a 256 -c - >&2
        fi
        tar -xf "$STAGE/zig.tar.xz" -C "$STAGE"
        mv "$STAGE/$PACKAGE" "$CACHE/"
        rm -rf "$STAGE"
        trap - EXIT
    fi
fi
if [[ "$("$ZIG" version)" != "$VERSION" ]]; then
    echo "Expected Zig $VERSION; check FELLA_ZIG or the toolchain cache." >&2
    exit 1
fi
exec "$ZIG" "$@"
