#!/bin/bash
#
# fella Install Script
# Installs the fella binary and runtime directories.
#
# Usage:
#   sudo ./scripts/install.sh
#   curl -sL https://raw.githubusercontent.com/phall1/fella/main/scripts/install.sh | sudo bash
#

set -euo pipefail

REPO="https://github.com/phall1/fella.git"
SRC_DIR="/opt/fella"
PREFIX="${PREFIX:-/usr/local}"
BINDIR="${PREFIX}/bin"
LIBDIR="/var/lib/fella"

need_root() {
    if [[ $EUID -ne 0 ]]; then
        echo "[!] This script must be run as root (try: sudo $0)" >&2
        exit 1
    fi
}

need_cmd() {
    if ! command -v "$1" >/dev/null 2>&1; then
        echo "[!] Required command not found: $1" >&2
        exit 1
    fi
}

install_deps() {
    echo "[*] Checking runtime dependencies..."
    local missing=""
    for cmd in iptables ip6tables ip tor torsocks wg; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            missing="$missing $cmd"
        fi
    done
    if [[ -n "$missing" ]]; then
        echo "[!] Optional/missing packages:$missing"
        echo "    Install with your package manager, e.g.:"
        echo "      apt install iptables iproute2 tor torsocks wireguard-tools"
    fi
}

clone_or_update() {
    if [[ -d "$SRC_DIR/.git" ]]; then
        echo "[*] Updating existing source in $SRC_DIR"
        cd "$SRC_DIR"
        git pull --ff-only
    else
        echo "[*] Cloning $REPO into $SRC_DIR"
        rm -rf "$SRC_DIR"
        git clone --depth 1 "$REPO" "$SRC_DIR"
        cd "$SRC_DIR"
    fi
}

build() {
    echo "[*] Building fella..."
    if ! command -v zig >/dev/null 2>&1; then
        echo "[!] Zig not found in PATH. Install Zig 0.16.0 first:" >&2
        echo "    https://ziglang.org/download/" >&2
        exit 1
    fi
    zig build
}

install_files() {
    echo "[*] Installing binary to $BINDIR/fella"
    install -Dm755 zig-out/bin/fella "$BINDIR/fella"

    echo "[*] Creating runtime directories in $LIBDIR"
    install -d -m700 "$LIBDIR"
    install -d -m700 "$LIBDIR/original"
    install -d -m700 "$LIBDIR/tor"
}

print_done() {
    echo ""
    echo "[+] fella installed successfully."
    echo ""
    echo "    Quick start:"
    echo "      sudo fella init"
    echo "      sudo fella start"
    echo "      sudo fella shell"
    echo "      sudo fella stop"
    echo ""
    echo "    Encrypted state:"
    echo "      export FELLA_PASSPHRASE='...'"
    echo "      sudo fella init --encrypt"
    echo ""
    echo "    WireGuard backend:"
    echo "      sudo fella init --backend wireguard"
    echo "      # place config at /var/lib/fella/wireguard.conf"
    echo "      sudo fella start"
    echo ""
}

main() {
    need_root
    need_cmd git
    need_cmd make

    install_deps

    if [[ "${1:-}" == "--local" ]] || [[ "${1:-}" == "-l" ]]; then
        cd "$(dirname "$0")/.."
    else
        clone_or_update
    fi

    build
    install_files
    print_done
}

main "$@"
