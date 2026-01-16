#!/bin/sh
#
# Dracut pre-mount hook for ShadowOS hidden boot
# /usr/lib/dracut/modules.d/99shadow/shadow-pre-mount.sh
#

type getarg >/dev/null 2>&1 || . /lib/dracut-lib.sh

# Check for shadow boot flag
if ! getarg shadowboot >/dev/null 2>&1; then
    return 0
fi

info "ShadowOS: Hidden boot initiated"

# Find encrypted partition
find_shadow_partition() {
    for dev in /dev/sd?3 /dev/sd?2 /dev/nvme?n1p3 /dev/nvme?n1p2; do
        [ -b "$dev" ] || continue
        if cryptsetup isLuks "$dev" 2>/dev/null; then
            echo "$dev"
            return 0
        fi
    done
    return 1
}

# Find header on mounted partitions
find_shadow_header() {
    for mp in /run/media/* /mnt/*; do
        [ -d "$mp" ] || continue
        [ -f "$mp/.shadow/header.bin" ] && echo "$mp/.shadow/header.bin" && return 0
    done
    
    # Try mounting USB partitions
    for dev in /dev/sd?1 /dev/sd?2 /dev/nvme?n1p1 /dev/nvme?n1p2; do
        [ -b "$dev" ] || continue
        mkdir -p /tmp/header_search
        if mount -t vfat -o ro "$dev" /tmp/header_search 2>/dev/null; then
            if [ -f /tmp/header_search/.shadow/header.bin ]; then
                cp /tmp/header_search/.shadow/header.bin /tmp/shadow_header.bin
                umount /tmp/header_search
                echo "/tmp/shadow_header.bin"
                return 0
            fi
            umount /tmp/header_search
        fi
    done
    return 1
}

# Main decryption
shadow_device=$(find_shadow_partition)
[ -z "$shadow_device" ] && { warn "ShadowOS: No encrypted partition found"; return 1; }

shadow_header=$(find_shadow_header)

echo ""
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║                    ShadowOS Boot                          ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""

tries=3
while [ $tries -gt 0 ]; do
    echo -n "Password: "
    read -s password
    echo ""
    
    if [ -n "$shadow_header" ]; then
        echo "$password" | cryptsetup open --header "$shadow_header" "$shadow_device" shadow_root 2>/dev/null
    else
        echo "$password" | cryptsetup open "$shadow_device" shadow_root 2>/dev/null
    fi
    
    [ $? -eq 0 ] && break
    
    tries=$((tries - 1))
    [ $tries -gt 0 ] && echo "[!] Invalid. $tries attempts left."
done

[ -b /dev/mapper/shadow_root ] || { warn "Decryption failed"; return 1; }

info "ShadowOS: Volume decrypted"

# Set root for dracut
export root=/dev/mapper/shadow_root
echo "/dev/mapper/shadow_root / auto defaults 0 1" > /etc/fstab
