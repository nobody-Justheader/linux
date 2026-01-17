# ShadowOS Security Modules Makefile

# Phase 4: Hardware Control
obj-$(CONFIG_SHADOWOS_USB) += shadow_usb.o
obj-$(CONFIG_SHADOWOS_AV) += shadow_av.o
obj-$(CONFIG_SHADOWOS_BT) += shadow_bt.o
obj-$(CONFIG_SHADOWOS_DMA) += shadow_dma.o

# Phase 5: Storage Security
obj-$(CONFIG_SHADOWOS_SHRED) += shadow_shred.o
obj-$(CONFIG_SHADOWOS_RAM) += shadow_ram.o

# Phase 6: Anti-Forensics
obj-$(CONFIG_SHADOWOS_PANIC) += shadow_panic.o
obj-$(CONFIG_SHADOWOS_CLOAK) += shadow_cloak.o
obj-$(CONFIG_SHADOWOS_META) += shadow_meta.o
obj-$(CONFIG_SHADOWOS_HONEY) += shadow_honey.o

# Phase 7: Detection & Protection
obj-$(CONFIG_SHADOWOS_ROOTKIT) += shadow_rootkit.o
obj-$(CONFIG_SHADOWOS_BEACON) += shadow_beacon.o
obj-$(CONFIG_SHADOWOS_EXFIL) += shadow_exfil.o
obj-$(CONFIG_SHADOWOS_COLDBOOT) += shadow_coldboot.o
obj-$(CONFIG_SHADOWOS_TAMPER) += shadow_tamper.o
obj-$(CONFIG_SHADOWOS_SIGN) += shadow_sign.o
obj-$(CONFIG_SHADOWOS_DEFCON) += shadow_defcon.o
obj-$(CONFIG_SHADOWOS_EVIDENCE) += shadow_evidence.o

# Phase 8: Research Features
obj-$(CONFIG_SHADOWOS_INFINITE) += shadow_infinite.o
obj-$(CONFIG_SHADOWOS_DEADMAN) += shadow_deadman.o
obj-$(CONFIG_SHADOWOS_TIMELOCK) += shadow_timelock.o

