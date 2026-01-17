#!/bin/bash
# ShadowOS Complete Build in Docker Container
# This builds the kernel AND the ISO entirely in a container
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
IMAGE_NAME="shadowos-builder"
KERNEL_SRC="/home/deadlock/Documents/linux"

cd "$PROJECT_ROOT"

echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║       🔥 ShadowOS Containerized Build System 🔥                ║"
echo "╠═══════════════════════════════════════════════════════════════╣"
echo "║  Building kernel and ISO safely inside Docker container       ║"
echo "╚═══════════════════════════════════════════════════════════════╝"

# Build container image if needed
if [[ "$(docker images -q $IMAGE_NAME 2> /dev/null)" == "" ]] || [[ "${1:-}" == "--rebuild" ]]; then
    echo "[shadowos] 🐳 Building Docker builder image..."
    docker build \
        --build-arg USER_ID="$(id -u)" \
        --build-arg GROUP_ID="$(id -g)" \
        -t "$IMAGE_NAME" \
        -f "$SCRIPT_DIR/Dockerfile" .
fi

if [[ "${1:-}" == "--rebuild" ]]; then shift; fi

echo "[shadowos] 🐳 Running build in container..."
echo "[shadowos] Kernel source: $KERNEL_SRC"
echo "[shadowos] ShadowOS dir: $PROJECT_ROOT"

# Run container with both kernel source and shadowos mounted
docker run --rm --privileged \
    -v "$KERNEL_SRC:/kernel:ro" \
    -v "$PROJECT_ROOT:/app" \
    -v "$PROJECT_ROOT/build:/app/build" \
    -e KERNEL_SRC=/kernel \
    -e BUILD_DIR=/app/build \
    --user root \
    -w /app \
    "$IMAGE_NAME" \
    /bin/bash -c '
        set -e
        echo "📦 Installing kernel to rootfs..."
        
        # Create directories
        mkdir -p /app/build/rootfs/boot
        mkdir -p /app/build/rootfs/lib/modules
        
        # Copy kernel
        cp /kernel/arch/x86/boot/bzImage /app/build/rootfs/boot/vmlinuz-6.19.0-shadowos
        cp /kernel/.config /app/build/rootfs/boot/config-6.19.0-shadowos
        
        # Install modules
        cd /kernel
        KERNEL_VER=$(make kernelrelease)
        echo "📦 Installing modules for $KERNEL_VER..."
        make modules_install INSTALL_MOD_PATH=/app/build/rootfs 2>/dev/null || true
        
        # Copy kernel and config with correct names
        cp /kernel/arch/x86/boot/bzImage /app/build/rootfs/boot/vmlinuz-$KERNEL_VER
        cp /kernel/.config /app/build/rootfs/boot/config-$KERNEL_VER
        
        # Generate initramfs
        echo "📦 Generating initramfs..."
        chroot /app/build/rootfs update-initramfs -c -k $KERNEL_VER 2>/dev/null || true
        
        # Build squashfs
        echo "📦 Creating squashfs..."
        mkdir -p /app/build/iso/live /app/build/iso/boot/grub
        mksquashfs /app/build/rootfs /app/build/iso/live/filesystem.squashfs \
            -comp zstd -Xcompression-level 10 -noappend -quiet
        
        # Copy kernel
        cp /app/build/rootfs/boot/vmlinuz-$KERNEL_VER /app/build/iso/live/vmlinuz
        
        # Copy initrd (find the actual file generated)
        INITRD_FILE=$(find /app/build/rootfs/boot -name "initrd.img-*" | head -n 1)
        if [ -n "$INITRD_FILE" ]; then
            echo "📦 Found initrd: $INITRD_FILE"
            cp "$INITRD_FILE" /app/build/iso/live/initrd.img
        else
            echo "❌ Error: No initrd.img found in /boot!"
            ls -la /app/build/rootfs/boot/
            exit 1
        fi
        
        # Create GRUB config
        cat > /app/build/iso/boot/grub/grub.cfg << EOF
set timeout=5
set default=0
# Search for the ISO root
search --no-floppy --set=root --file /live/vmlinuz

menuentry "ShadowOS 6.19.0 - Kernel-Level Security" {
    linux /live/vmlinuz boot=live quiet splash
    initrd /live/initrd.img
}

menuentry "ShadowOS (Reflex Mode)" {
    linux /live/vmlinuz boot=live toram
    initrd /live/initrd.img
}

menuentry "ShadowOS (Debug Mode)" {
    linux /live/vmlinuz boot=live debug earlyprintk=vga
    initrd /live/initrd.img
}
EOF
        
        # Generate ISO
        echo "📀 Generating ISO..."
        grub-mkrescue -o /app/shadowos-bleeding.iso /app/build/iso 2>/dev/null
        
        echo ""
        echo "✅ Build complete!"
        ls -lh /app/shadowos-bleeding.iso
    '

echo ""
echo "[shadowos] ✅ Container build finished!"
echo "[shadowos] ISO: $PROJECT_ROOT/shadowos-6.19.0-shadowos.iso"
