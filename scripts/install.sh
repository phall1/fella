#!/bin/bash
#
# fella Install Script
# Installs the fella binary, runtime directories, and optionally all dependencies.
#
# Usage:
#   sudo ./scripts/install.sh
#   curl -sL https://raw.githubusercontent.com/phall1/fella/main/scripts/install.sh | sudo bash
#   curl -sL ... | sudo bash -s -- --auto
#

set -euo pipefail

REPO="https://github.com/phall1/fella.git"
SRC_DIR="/opt/fella"
PREFIX="${PREFIX:-/usr/local}"
BINDIR="${PREFIX}/bin"
LIBDIR="/var/lib/fella"
ZIG_VERSION="0.16.0"
ARCH="$(uname -m)"
AUTO=false
LOCAL=false

# Parse our own flags before we do anything else
for arg in "$@"; do
    case "$arg" in
        --auto) AUTO=true ;;
        --local|-l) LOCAL=true ;;
    esac
done

need_root() {
    if [[ $EUID -ne 0 ]]; then
        echo "[!] This script must be run as root (try: sudo $0)" >&2
        exit 1
    fi
}

detect_pkg_manager() {
    if command -v apt-get >/dev/null 2>&1; then
        echo "apt"
    elif command -v dnf >/dev/null 2>&1; then
        echo "dnf"
    elif command -v pacman >/dev/null 2>&1; then
        echo "pacman"
    elif command -v apk >/dev/null 2>&1; then
        echo "apk"
    else
        echo "unknown"
    fi
}

install_system_deps() {
    local pkg_manager
    pkg_manager="$(detect_pkg_manager)"

    local needed=()
    for cmd in iptables ip6tables ip tor torsocks wg; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            needed+=("$cmd")
        fi
    done

    if [[ ${#needed[@]} -eq 0 ]]; then
        echo "[*] All runtime dependencies already installed"
        return
    fi

    echo "[!] Missing commands: ${needed[*]}"

    if [[ "$AUTO" != true ]]; then
        echo "[*] Re-run with --auto to install system packages automatically, or run:"
        case "$pkg_manager" in
            apt) echo "    apt update && apt install -y iptables iproute2 tor torsocks wireguard-tools" ;;
            dnf) echo "    dnf install -y iptables iproute tor torsocks wireguard-tools" ;;
            pacman) echo "    pacman -S --noconfirm iptables iproute2 tor torsocks wireguard-tools" ;;
            apk) echo "    apk add iptables iproute2 tor torsocks wireguard-tools" ;;
            *) echo "    Install iptables, iproute2, tor, torsocks, and wireguard-tools manually" ;;
        esac
        exit 1
    fi

    echo "[*] Auto-installing system dependencies via $pkg_manager..."
    case "$pkg_manager" in
        apt)
            export DEBIAN_FRONTEND=noninteractive
            export DEBIAN_FRONTEND=noninteractive
            apt-get update -qq
            apt-get install -y -qq iptables iproute2 tor torsocks wireguard-tools curl git gcc
            ;;
        dnf)
            dnf install -y iptables iproute tor torsocks wireguard-tools curl git gcc
            ;;
        pacman)
            pacman -S --noconfirm iptables iproute2 tor torsocks wireguard-tools curl git gcc
            ;;
        apk)
            apk add iptables iproute2 tor torsocks wireguard-tools curl git gcc
            ;;
        *)
            echo "[!] Unknown package manager. Install deps manually." >&2
            exit 1
            ;;
    esac
}

install_zig() {
    if command -v zig >/dev/null 2>&1; then
        local ver
        ver="$(zig version 2>/dev/null || echo unknown)"
        if [[ "$ver" == "$ZIG_VERSION"* ]]; then
            echo "[*] Zig $ver already available"
            return
        fi
        echo "[!] Found zig $ver but need $ZIG_VERSION"
    fi

    local zig_arch
    case "$ARCH" in
        x86_64) zig_arch="x86_64" ;;
        aarch64|arm64) zig_arch="aarch64" ;;
        *)
            echo "[!] Unsupported architecture: $ARCH" >&2
            exit 1
            ;;
    esac

    local zig_tar="zig-${zig_arch}-linux-${ZIG_VERSION}.tar.xz"
    local zig_url="https://ziglang.org/download/${ZIG_VERSION}/${zig_tar}"
    local zig_dir="/opt/zig-${ZIG_VERSION}"
    local zig_link="/usr/local/bin/zig"

    echo "[*] Downloading Zig ${ZIG_VERSION} for ${zig_arch}..."
    rm -rf "$zig_dir"
    mkdir -p /opt
    curl -fsSL "$zig_url" -o "/tmp/${zig_tar}"
    tar -xf "/tmp/${zig_tar}" -C /opt
    mv "/opt/zig-${zig_arch}-linux-${ZIG_VERSION}" "$zig_dir"
    ln -sf "${zig_dir}/zig" "$zig_link"
    rm -f "/tmp/${zig_tar}"

    export PATH="${zig_link%/*}:$PATH"
    echo "[*] Zig installed to $zig_link"
}

clone_or_update() {
    if [[ "$LOCAL" == true ]]; then
        cd "$(dirname "$0")/.."
        return
    fi

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
        echo "[!] Zig still not in PATH after install attempt" >&2
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
    echo "      exit"
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
    echo "    Chain (VPN -> Tor):"
    echo "      sudo cp your-wireguard.conf /var/lib/fella/wireguard.conf"
    echo "      sudo fella init --backend chain"
    echo "      sudo fella start"
    echo ""
    echo "    Cover traffic padding:"
    echo "      sudo fella start --cover"
    echo ""
}

main() {
    need_root

    install_system_deps
    install_zig

    if [[ "$LOCAL" != true ]]; then
        need_cmd git
        need_cmd curl
    fi

    clone_or_update
    build
    install_files
    print_done
}

need_cmd() {
    if ! command -v "$1" >/dev/null 2>&1; then
        echo "[!] Required command not found: $1" >&2
        exit 1
    fi
}

main "$@"
