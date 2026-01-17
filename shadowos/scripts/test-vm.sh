#!/bin/bash
# ShadowOS VM Testing Script
# Test the ShadowOS ISO in QEMU/KVM virtual machine
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
ISO_PATH="${1:-$PROJECT_ROOT/shadowos-6.19.0-custom.iso}"
RAM="${2:-2G}"
CPUS="${3:-2}"

# Check if ISO exists
if [[ ! -f "$ISO_PATH" ]]; then
    echo "❌ ISO not found: $ISO_PATH"
    echo ""
    echo "Usage: $0 [path/to/iso] [RAM] [CPUs]"
    echo "  Example: $0 shadowos.iso 4G 4"
    exit 1
fi

echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║          🖥️  ShadowOS VM Testing Environment 🖥️               ║"
echo "╠═══════════════════════════════════════════════════════════════╣"
echo "║  ISO:  $(basename "$ISO_PATH")"
echo "║  RAM:  $RAM"  
echo "║  CPUs: $CPUS"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo ""

# Check for QEMU
if ! command -v qemu-system-x86_64 &> /dev/null; then
    echo "❌ QEMU not installed. Install with:"
    echo "   sudo apt install qemu-system-x86 qemu-kvm"
    exit 1
fi

# Check KVM availability
KVM_OPTS=""
if [[ -c /dev/kvm ]] && [[ -w /dev/kvm ]]; then
    echo "✅ KVM acceleration available"
    KVM_OPTS="-enable-kvm"
else
    echo "⚠️  KVM not available, using software emulation (slower)"
fi

echo ""
echo "🚀 Starting ShadowOS VM..."
echo "   Press Ctrl+Alt+G to release mouse"
echo "   Press Ctrl+C to terminate"
echo ""

# Run QEMU
qemu-system-x86_64 \
    $KVM_OPTS \
    -m "$RAM" \
    -smp "$CPUS" \
    -cdrom "$ISO_PATH" \
    -boot d \
    -vga virtio \
    -display gtk,show-cursor=on \
    -usb \
    -device usb-tablet \
    -netdev user,id=net0,hostfwd=tcp::2222-:22 \
    -device virtio-net-pci,netdev=net0 \
    -serial mon:stdio \
    "$@"

echo ""
echo "VM terminated."
