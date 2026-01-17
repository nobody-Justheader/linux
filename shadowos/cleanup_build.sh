#!/bin/bash
set -x
# Force unmount everything in build/rootfs
if [ -d "build/rootfs" ]; then
    mount | grep $(pwd)/build/rootfs | awk '{print $3}' | sort -r | xargs -r umount -f
fi

# Try to remove again
rm -rf build output
