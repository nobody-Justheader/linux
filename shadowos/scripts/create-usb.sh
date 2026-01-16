#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# create-usb.sh - Create ShadowOS USB (called from kernel Makefile)
# Part of kernel build: make shadowos-usb DEVICE=/dev/sdX
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SHADOWOS_DIR="$(dirname "$SCRIPT_DIR")"
DEVICE="${1:-}"

[[ -z "$DEVICE" ]] && { echo "Usage: $0 /dev/sdX"; exit 1; }
[[ ! -b "$DEVICE" ]] && { echo "Not a block device: $DEVICE"; exit 1; }
[[ $EUID -ne 0 ]] && { echo "Run as root"; exit 1; }

log() { echo "[shadowos] $*"; }

get_part() {
    [[ "$DEVICE" == *nvme* || "$DEVICE" == *mmcblk* ]] && echo "${DEVICE}p$1" || echo "${DEVICE}$1"
}

log "Creating ShadowOS USB on $DEVICE"
echo "⚠️  ALL DATA WILL BE ERASED!"
read -p "Continue? [y/N] " -n 1 -r
echo
[[ ! $REPLY =~ ^[Yy]$ ]] && exit 0

# Unmount
for i in {1..9}; do umount "$(get_part $i)" 2>/dev/null || true; done
cryptsetup close shadow_root 2>/dev/null || true

# Partition
log "Partitioning..."
wipefs -a "$DEVICE"
parted -s "$DEVICE" mklabel gpt
parted -s "$DEVICE" mkpart ESP fat32 1MiB 513MiB
parted -s "$DEVICE" set 1 esp on
parted -s "$DEVICE" mkpart primary fat32 513MiB 4609MiB
parted -s "$DEVICE" mkpart primary 4609MiB 100%
partprobe "$DEVICE"; sleep 3

# Format
log "Formatting..."
mkfs.vfat -F 32 -n EFI "$(get_part 1)"
mkfs.vfat -F 32 -n PUBLIC "$(get_part 2)"

# Encryption
log "Setting up encryption..."
TMP=$(mktemp -d)
mount "$(get_part 2)" "$TMP"
mkdir -p "$TMP/.shadow"

dd if=/dev/urandom of="$(get_part 3)" bs=1M status=progress 2>&1 || true

echo "Enter password for hidden volume:"
cryptsetup luksFormat --type luks2 --cipher aes-xts-plain64 --key-size 512 \
    --hash sha512 --pbkdf argon2id --header "$TMP/.shadow/header.bin" "$(get_part 3)"

echo "Re-enter password to open:"
cryptsetup open --header "$TMP/.shadow/header.bin" "$(get_part 3)" shadow_root

mkfs.ext4 -L SHADOWOS /dev/mapper/shadow_root

# Install
log "Installing ShadowOS..."
ROOT=$(mktemp -d)
mount /dev/mapper/shadow_root "$ROOT"

# Download Alpine
curl -sL "https://dl-cdn.alpinelinux.org/alpine/v3.19/releases/x86_64/alpine-minirootfs-3.19.0-x86_64.tar.gz" | tar xz -C "$ROOT"

# Copy ShadowOS
cp -r "$SHADOWOS_DIR/usr" "$ROOT/"
cp -r "$SHADOWOS_DIR/etc" "$ROOT/"
chmod +x "$ROOT/usr/bin/"* 2>/dev/null || true

umount "$ROOT"; rmdir "$ROOT"
cryptsetup close shadow_root
umount "$TMP"; rmdir "$TMP"

# Bootloader
log "Installing bootloader..."
ESP=$(mktemp -d)
mount "$(get_part 1)" "$ESP"
mkdir -p "$ESP"/{EFI/BOOT,boot/grub}

cat > "$ESP/boot/grub/grub.cfg" << 'EOF'
set timeout=0
set default=0

menuentry "ShadowOS" {
    linux /boot/vmlinuz shadowboot quiet loglevel=0 noswap
    initrd /boot/initramfs.img
}
EOF

grub-install --target=x86_64-efi --efi-directory="$ESP" --boot-directory="$ESP/boot" --removable --no-nvram "$DEVICE" 2>/dev/null || true
umount "$ESP"; rmdir "$ESP"

log "Done! Boot from USB and press 'h' at GRUB."
