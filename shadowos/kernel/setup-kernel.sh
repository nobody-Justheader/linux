#!/bin/bash
# ShadowOS Kernel Setup Script
# Links ShadowOS sources into the generic Linux kernel tree

KERNEL_DIR="${KERNEL_DIR:-..}"

echo ">>> ShadowOS Setup targeting: $KERNEL_DIR"

if [ ! -d "$KERNEL_DIR" ]; then
    echo "Error: Kernel directory $KERNEL_DIR not found."
    echo "Please set KERNEL_DIR to your Linux source tree."
    exit 1
fi

# 1. Link Include Files
echo "[+] Linking headers..."
if [ ! -d "$KERNEL_DIR/include/shadowos" ]; then
    ln -sf "$(pwd)/src/include/shadowos" "$KERNEL_DIR/include/shadowos"
fi

# 2. Link Net Modules
echo "[+] Linking network modules..."
if [ ! -d "$KERNEL_DIR/net/shadowos" ]; then
    ln -sf "$(pwd)/src/net/shadowos" "$KERNEL_DIR/net/shadowos"
fi

# 3. Patch Kconfig/Makefiles (Non-destructive check)
if ! grep -q "config SHADOWOS" "$KERNEL_DIR/net/Kconfig" 2>/dev/null; then
    echo "[!] Warning: You need to add 'source \"net/shadowos/Kconfig\"' to $KERNEL_DIR/net/Kconfig"
fi

if ! grep -q "obj-\$(CONFIG_SHADOWOS)" "$KERNEL_DIR/net/Makefile" 2>/dev/null; then
    echo "[!] Warning: You need to add 'obj-\$(CONFIG_SHADOWOS) += shadowos/' to $KERNEL_DIR/net/Makefile"
fi

echo ">>> Setup complete."
