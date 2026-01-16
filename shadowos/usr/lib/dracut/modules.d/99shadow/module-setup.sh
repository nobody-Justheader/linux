#!/bin/bash
#
# Dracut module for ShadowOS hidden boot
# /usr/lib/dracut/modules.d/99shadow/module-setup.sh
#

check() {
    require_binaries cryptsetup || return 1
    return 0
}

depends() {
    echo crypt dm
}

install() {
    inst_multiple cryptsetup blkid
    
    # Install shadow decrypt script
    inst_script "$moddir/shadow-decrypt.sh" /usr/bin/shadow-decrypt
    
    # Install config hook
    inst_hook pre-mount 99 "$moddir/shadow-pre-mount.sh"
    
    # Copy crypto modules
    instmods dm_crypt xts aes serpent twofish sha256 sha512
}

installkernel() {
    instmods dm_crypt dm_mod xts aes aes_generic sha256_generic sha512_generic
    instmods usb_storage ehci_hcd xhci_hcd
}
