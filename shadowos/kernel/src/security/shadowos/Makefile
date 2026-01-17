# ShadowOS Security Modules Makefile

# Phase 4: Hardware Control
obj-$(CONFIG_SHADOWOS_USB) += shadow_usb.o
obj-$(CONFIG_SHADOWOS_AV) += shadow_av.o

# Phase 5: Storage Security
obj-$(CONFIG_SHADOWOS_SHRED) += shadow_shred.o
obj-$(CONFIG_SHADOWOS_RAM) += shadow_ram.o

# Phase 6: Anti-Forensics
obj-$(CONFIG_SHADOWOS_PANIC) += shadow_panic.o
obj-$(CONFIG_SHADOWOS_CLOAK) += shadow_cloak.o
obj-$(CONFIG_SHADOWOS_META) += shadow_meta.o
obj-$(CONFIG_SHADOWOS_HONEY) += shadow_honey.o

# Phase 8: Research Features
obj-$(CONFIG_SHADOWOS_INFINITE) += shadow_infinite.o
obj-$(CONFIG_SHADOWOS_DEADMAN) += shadow_deadman.o
obj-$(CONFIG_SHADOWOS_TIMELOCK) += shadow_timelock.o
