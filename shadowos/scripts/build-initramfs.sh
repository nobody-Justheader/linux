#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# build-initramfs.sh - Build custom ShadowOS initramfs
# Creates a minimal initramfs with busybox and our custom init
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SHADOWOS_DIR="$(dirname "$SCRIPT_DIR")"
BUILD_DIR="${BUILD_DIR:-/tmp/shadowos-build}"
INITRAMFS_DIR="$BUILD_DIR/initramfs-root"
OUTPUT="${1:-$BUILD_DIR/iso/boot/initramfs.img}"

ALPINE_VERSION="${ALPINE_VERSION:-3.19}"
ALPINE_MIRROR="https://dl-cdn.alpinelinux.org/alpine"

log() { echo "[initramfs] $*"; }
warn() { echo "[warning] $*"; }
error() { echo "[ERROR] $*" >&2; exit 1; }

# =============================================================================
# SETUP INITRAMFS STRUCTURE
# =============================================================================

setup_structure() {
    log "Creating initramfs structure..."
    
    rm -rf "$INITRAMFS_DIR"
    mkdir -p "$INITRAMFS_DIR"/{bin,sbin,lib,lib64,dev,proc,sys,mnt,run,tmp,etc}
    mkdir -p "$INITRAMFS_DIR"/mnt/{boot,lower,upper,work,root,probe,toram}
    
    # Essential device nodes
    sudo mknod -m 600 "$INITRAMFS_DIR/dev/console" c 5 1
    sudo mknod -m 666 "$INITRAMFS_DIR/dev/null" c 1 3
    sudo mknod -m 666 "$INITRAMFS_DIR/dev/zero" c 1 5
    sudo mknod -m 666 "$INITRAMFS_DIR/dev/tty" c 5 0
    sudo mknod -m 660 "$INITRAMFS_DIR/dev/tty0" c 4 0
    sudo mknod -m 660 "$INITRAMFS_DIR/dev/tty1" c 4 1
    sudo mknod -m 666 "$INITRAMFS_DIR/dev/random" c 1 8
    sudo mknod -m 666 "$INITRAMFS_DIR/dev/urandom" c 1 9
    sudo mknod -m 660 "$INITRAMFS_DIR/dev/loop0" b 7 0
    sudo mknod -m 660 "$INITRAMFS_DIR/dev/loop1" b 7 1
    sudo mknod -m 660 "$INITRAMFS_DIR/dev/loop2" b 7 2
    sudo mknod -m 660 "$INITRAMFS_DIR/dev/loop3" b 7 3
    
    log "Structure created"
}

# =============================================================================
# INSTALL BUSYBOX
# =============================================================================

install_busybox() {
    log "Installing busybox..."
    
    local busybox_apk="$BUILD_DIR/busybox-static.apk"
    
    if [[ ! -f "$busybox_apk" ]]; then
        log "Downloading busybox-static..."
        curl -fSL "$ALPINE_MIRROR/v$ALPINE_VERSION/main/x86_64/busybox-static-1.36.1-r15.apk" \
            -o "$busybox_apk" 2>/dev/null || \
        curl -fSL "$ALPINE_MIRROR/v$ALPINE_VERSION/main/x86_64/busybox-static-1.36.1-r19.apk" \
            -o "$busybox_apk" 2>/dev/null || \
        # Fallback: find latest version
        curl -fSL "$(curl -s "$ALPINE_MIRROR/v$ALPINE_VERSION/main/x86_64/" | \
            grep -oP 'busybox-static-[^"]+\.apk' | head -1 | \
            xargs -I{} echo "$ALPINE_MIRROR/v$ALPINE_VERSION/main/x86_64/{}")" \
            -o "$busybox_apk"
    fi
    
    # Extract busybox
    tar -xzf "$busybox_apk" -C "$INITRAMFS_DIR" ./bin/busybox.static 2>/dev/null || \
        tar -xzf "$busybox_apk" -C "$BUILD_DIR" 2>/dev/null
    
    # Find and install busybox
    local busybox_bin
    busybox_bin=$(find "$BUILD_DIR" "$INITRAMFS_DIR" -name "busybox.static" -o -name "busybox" 2>/dev/null | head -1)
    
    if [[ -z "$busybox_bin" ]]; then
        # Try system busybox as fallback
        if command -v busybox &>/dev/null; then
            busybox_bin=$(command -v busybox)
            log "Using system busybox: $busybox_bin"
        else
            error "Could not find busybox binary"
        fi
    fi
    
    cp "$busybox_bin" "$INITRAMFS_DIR/bin/busybox"
    chmod 755 "$INITRAMFS_DIR/bin/busybox"
    
    # Create busybox symlinks
    log "Creating busybox symlinks..."
    local applets=(
        # Core
        sh ash
        # File operations
        cat cp mv rm mkdir rmdir ls ln readlink stat find
        # Mount operations
        mount umount losetup switch_root pivot_root
        # Device handling
        mknod mdev
        # Process
        sleep kill
        # Text
        echo printf grep sed awk cut head tail
        # System info
        dmesg uname
        # Block devices
        blkid
        # Module loading
        modprobe insmod lsmod
        # Misc
        clear true false test "[" expr
    )
    
    for applet in "${applets[@]}"; do
        ln -sf busybox "$INITRAMFS_DIR/bin/$applet"
    done
    
    # Also link to /sbin for init expectations
    ln -sf ../bin/busybox "$INITRAMFS_DIR/sbin/modprobe"
    ln -sf ../bin/busybox "$INITRAMFS_DIR/sbin/mdev"
    
    log "Busybox installed with $(echo ${#applets[@]}) applets"
}

# =============================================================================
# INSTALL KERNEL MODULES
# =============================================================================

install_modules() {
    log "Installing kernel modules..."
    
    local modloop="$BUILD_DIR/iso/boot/modloop-lts"
    
    if [[ ! -f "$modloop" ]]; then
        log "Downloading modloop..."
        curl -fSL "$ALPINE_MIRROR/v$ALPINE_VERSION/releases/x86_64/netboot/modloop-lts" \
            -o "$modloop"
    fi
    
    # Extract essential modules from modloop
    local modloop_mount="$BUILD_DIR/modloop-mount"
    mkdir -p "$modloop_mount"
    
    log "Extracting modules from modloop..."
    sudo mount -o loop,ro "$modloop" "$modloop_mount" 2>/dev/null || {
        warn "Could not mount modloop, skipping module extraction"
        return 0
    }
    
    # Find kernel version
    local kver
    kver=$(ls "$modloop_mount/modules/" 2>/dev/null | head -1)
    
    if [[ -n "$kver" ]]; then
        mkdir -p "$INITRAMFS_DIR/lib/modules/$kver/kernel"
        
        # Copy essential modules
        local essential_modules=(
            "kernel/fs/squashfs"
            "kernel/fs/overlayfs"
            "kernel/fs/isofs"
            "kernel/drivers/cdrom"
            "kernel/drivers/scsi"
            "kernel/drivers/ata"
            "kernel/drivers/usb/storage"
            "kernel/drivers/usb/host"
            "kernel/drivers/block/loop.ko"
            "kernel/drivers/virtio"
        )
        
        for modpath in "${essential_modules[@]}"; do
            if [[ -e "$modloop_mount/modules/$kver/$modpath" ]]; then
                local destdir="$INITRAMFS_DIR/lib/modules/$kver/$(dirname "$modpath")"
                mkdir -p "$destdir"
                cp -a "$modloop_mount/modules/$kver/$modpath" "$destdir/" 2>/dev/null || true
            fi
        done
        
        # Copy modules.dep and related
        cp "$modloop_mount/modules/$kver/modules."* "$INITRAMFS_DIR/lib/modules/$kver/" 2>/dev/null || true
        
        log "Modules for kernel $kver installed"
    fi
    
    sudo umount "$modloop_mount" 2>/dev/null || true
}

# =============================================================================
# INSTALL INIT SCRIPT
# =============================================================================

install_init() {
    log "Installing init script..."
    
    local init_src="$SHADOWOS_DIR/initramfs/init"
    
    if [[ ! -f "$init_src" ]]; then
        error "Init script not found: $init_src"
    fi
    
    cp "$init_src" "$INITRAMFS_DIR/init"
    chmod 755 "$INITRAMFS_DIR/init"
    
    # Also create /sbin/init symlink
    ln -sf ../init "$INITRAMFS_DIR/sbin/init"
    
    log "Init script installed"
}

# =============================================================================
# CREATE CPIO ARCHIVE
# =============================================================================

create_cpio() {
    log "Creating initramfs cpio archive..."
    
    mkdir -p "$(dirname "$OUTPUT")"
    
    # Create cpio archive
    (
        cd "$INITRAMFS_DIR"
        find . -print0 | cpio --null -o -H newc --quiet
    ) | gzip -9 > "$OUTPUT"
    
    local size
    size=$(du -h "$OUTPUT" | cut -f1)
    log "Initramfs created: $OUTPUT ($size)"
}

# =============================================================================
# MAIN
# =============================================================================

main() {
    log "Building ShadowOS initramfs..."
    
    mkdir -p "$BUILD_DIR"
    
    setup_structure
    install_busybox
    install_modules
    install_init
    create_cpio
    
    log "Initramfs build complete!"
}

main "$@"
