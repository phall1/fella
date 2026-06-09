#!/bin/bash
set -euo pipefail

# fella VM-based integration test harness
# Uses QEMU + cloud-init + Ubuntu cloud image for fully isolated testing.
#
# Usage:
#   ./scripts/vm-test.sh launch    # Download image, create VM, start
#   ./scripts/vm-test.sh snapshot  # Snapshot current disk state
#   ./scripts/vm-test.sh restore   # Restore to last snapshot
#   ./scripts/vm-test.sh test      # Build fella in VM, run integration suite
#   ./scripts/vm-test.sh ssh       # SSH into the VM
#   ./scripts/vm-test.sh destroy   # Destroy VM and disk

VM_NAME="fella-test"
VM_DIR="$HOME/.local/share/fella-vm"
DISK="$VM_DIR/${VM_NAME}.qcow2"
DISK_SIZE="20G"
MEM="2048"
CPUS="2"
SSH_PORT="2222"
CLOUD_IMG_URL="https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.img"
CLOUD_IMG="$VM_DIR/noble-server-cloudimg-amd64.img"
SSH_KEY="$VM_DIR/id_fella_vm"

check_deps() {
    for cmd in qemu-system-x86_64 qemu-img ssh-keygen ssh curl; do
        if ! command -v "$cmd" &>/dev/null; then
            echo "[!] Missing: $cmd"
            echo "    Install: sudo apt install qemu-system-x86 qemu-utils openssh-client curl"
            exit 1
        fi
    done
}

ensure_image() {
    mkdir -p "$VM_DIR"
    if [[ ! -f "$CLOUD_IMG" ]]; then
        echo "[+] Downloading Ubuntu cloud image..."
        curl -L -o "$CLOUD_IMG" "$CLOUD_IMG_URL"
    fi
    if [[ ! -f "$SSH_KEY" ]]; then
        echo "[+] Generating SSH key..."
        ssh-keygen -t ed25519 -f "$SSH_KEY" -N "" -C "fella-vm"
    fi
}

launch() {
    check_deps
    ensure_image

    if [[ -f "$DISK" ]]; then
        echo "[*] VM disk already exists. Use 'destroy' first if you want a fresh VM."
    else
        echo "[+] Creating VM disk..."
        qemu-img create -f qcow2 -F qcow2 -b "$CLOUD_IMG" "$DISK" "$DISK_SIZE"
    fi

    # cloud-init user-data
    cat > "$VM_DIR/user-data" <<EOF
#cloud-config
users:
  - name: fella
    sudo: ALL=(ALL) NOPASSWD:ALL
    ssh_authorized_keys:
      - $(cat "${SSH_KEY}.pub")
    shell: /bin/bash
packages:
  - tor
  - torsocks
  - wireguard-tools
  - iptables
  - iproute2
  - curl
  - git
  - gcc
  - make
  - firefox
runcmd:
  - systemctl enable --now tor
EOF

    cat > "$VM_DIR/meta-data" <<EOF
instance-id: fella-test-01
local-hostname: fella-test
EOF

    # Create cloud-init ISO
    if command -v cloud-localds &>/dev/null; then
        cloud-localds "$VM_DIR/cidata.iso" "$VM_DIR/user-data" "$VM_DIR/meta-data"
    else
        # Fallback: create ISO manually
        mkdir -p "$VM_DIR/cidata"
        cp "$VM_DIR/user-data" "$VM_DIR/cidata/"
        cp "$VM_DIR/meta-data" "$VM_DIR/cidata/"
        mkisofs -output "$VM_DIR/cidata.iso" -volid cidata -joliet -rock "$VM_DIR/cidata" 2>/dev/null || \
        genisoimage -output "$VM_DIR/cidata.iso" -volid cidata -joliet -rock "$VM_DIR/cidata" 2>/dev/null || {
            echo "[!] cloud-localds, mkisofs, or genisoimage required for cloud-init"
            exit 1
        }
    fi

    echo "[+] Starting VM..."
    nohup qemu-system-x86_64 \
        -name "$VM_NAME" \
        -m "$MEM" \
        -smp "$CPUS" \
        -cpu host \
        -enable-kvm \
        -drive file="$DISK",format=qcow2,if=virtio \
        -drive file="$VM_DIR/cidata.iso",format=raw,if=virtio,media=cdrom,readonly=on \
        -netdev user,id=net0,hostfwd=tcp::${SSH_PORT}-:22 \
        -device virtio-net-pci,netdev=net0 \
        -nographic \
        -serial mon:stdio \
        -display none \
        > "$VM_DIR/vm.log" 2>&1 &

    echo "[*] VM launching in background (PID $!)"
    echo "[*] Waiting for SSH..."

    for i in {1..60}; do
        if ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
                -o ConnectTimeout=2 -p "$SSH_PORT" -i "$SSH_KEY" fella@localhost true 2>/dev/null; then
            echo "[+] VM ready. SSH: ssh -p $SSH_PORT -i $SSH_KEY fella@localhost"
            return 0
        fi
        sleep 1
    done
    echo "[!] VM did not come up in time. Check $VM_DIR/vm.log"
    return 1
}

snapshot() {
    if [[ ! -f "$DISK" ]]; then
        echo "[!] No VM disk found. Run 'launch' first."
        exit 1
    fi
    echo "[+] Creating snapshot..."
    qemu-img snapshot -c "pre-test-$(date +%s)" "$DISK"
    echo "[+] Snapshot created"
}

restore() {
    if [[ ! -f "$DISK" ]]; then
        echo "[!] No VM disk found. Run 'launch' first."
        exit 1
    fi
    echo "[+] Restoring last snapshot..."
    qemu-img snapshot -a "$(qemu-img snapshot -l "$DISK" | tail -n 1 | awk '{print $2}')" "$DISK"
    echo "[+] Restored"
}

test_suite() {
    if ! ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
            -p "$SSH_PORT" -i "$SSH_KEY" fella@localhost true 2>/dev/null; then
        echo "[!] VM not running or SSH not ready."
        exit 1
    fi

    echo "[+] Copying fella source to VM..."
    rsync -az -e "ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -p $SSH_PORT -i $SSH_KEY" \
        --exclude='.git' --exclude='.zig-cache' --exclude='zig-out' \
        . fella@localhost:/home/fella/fella/

    echo "[+] Building in VM..."
    ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
        -p "$SSH_PORT" -i "$SSH_KEY" fella@localhost \
        "cd /home/fella/fella && zig build"

    echo "[+] Running unit tests..."
    ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
        -p "$SSH_PORT" -i "$SSH_KEY" fella@localhost \
        "cd /home/fella/fella && zig build test"

    echo "[+] Running integration tests (needs root in VM)..."
    ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
        -p "$SSH_PORT" -i "$SSH_KEY" fella@localhost \
        "cd /home/fella/fella && sudo ./zig-out/bin/fella init && sudo ./zig-out/bin/fella start && sudo ./zig-out/bin/fella verify && sudo ./zig-out/bin/fella stop"

    echo "[+] All tests passed in VM"
}

ssh_vm() {
    ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
        -p "$SSH_PORT" -i "$SSH_KEY" fella@localhost
}

destroy() {
    echo "[+] Stopping VM..."
    pkill -f "qemu-system-x86_64.*name $VM_NAME" || true
    sleep 1
    if [[ -f "$DISK" ]]; then
        echo "[+] Removing VM disk..."
        rm -f "$DISK"
    fi
    rm -f "$VM_DIR/cidata.iso"
    echo "[+] VM destroyed"
}

case "${1:-}" in
    launch) launch ;;
    snapshot) snapshot ;;
    restore) restore ;;
    test) test_suite ;;
    ssh) ssh_vm ;;
    destroy) destroy ;;
    *)
        echo "Usage: $0 {launch|snapshot|restore|test|ssh|destroy}"
        echo ""
        echo "  launch   - Create and start a fresh Ubuntu VM with dependencies"
        echo "  snapshot - Snapshot the VM disk before testing"
        echo "  restore  - Restore VM to last snapshot"
        echo "  test     - Build fella in VM and run integration suite"
        echo "  ssh      - SSH into the VM"
        echo "  destroy  - Stop and delete the VM"
        exit 1
        ;;
esac
