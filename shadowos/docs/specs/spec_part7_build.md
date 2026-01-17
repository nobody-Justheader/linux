# ShadowOS Specification - Part 7

## Build System & Project Structure

---

# PROJECT DIRECTORY STRUCTURE

```
shadowos/
├── README.md                        # Project overview
├── LICENSE                          # GPL-2.0
├── Makefile                         # Master build system
├── Kconfig                          # Build configuration
│
├── kernel/                          # Custom kernel
│   ├── Makefile                     # Kernel build
│   ├── download-kernel.sh           # Fetch Linux source
│   ├── apply-patches.sh             # Apply patches
│   ├── config/
│   │   └── shadowos_defconfig       # Kernel config
│   ├── patches/
│   │   ├── 0001-shadowos-kconfig.patch
│   │   ├── 0002-shadowos-core.patch
│   │   ├── 0003-shadowos-detect.patch
│   │   └── ...
│   └── src/
│       ├── net/shadowos/            # Network modules
│       │   ├── Kconfig
│       │   ├── Makefile
│       │   ├── shadow_core.c
│       │   ├── shadow_detect.c
│       │   ├── shadow_chaos.c
│       │   ├── shadow_phantom.c
│       │   ├── shadow_flux.c
│       │   ├── shadow_dns.c
│       │   └── shadow_geo.c
│       ├── security/shadowos/       # Security modules
│       │   ├── Kconfig
│       │   ├── Makefile
│       │   ├── shadow_usb.c
│       │   ├── shadow_av.c
│       │   ├── shadow_shred.c
│       │   ├── shadow_ram.c
│       │   ├── shadow_panic.c
│       │   └── shadow_cloak.c
│       └── include/shadowos/         # Headers
│           ├── shadow_types.h
│           ├── shadow_netlink.h
│           └── shadow_config.h
│
├── userspace/                       # Userspace components
│   ├── libshadow/                   # C library
│   │   ├── Makefile
│   │   ├── shadow.c
│   │   ├── shadow.h
│   │   ├── netlink.c
│   │   └── sysfs.c
│   ├── shadow-alertd/               # Alert daemon
│   │   ├── Makefile
│   │   ├── shadow_alertd.c
│   │   ├── shadow_alertd.py
│   │   └── shadow-alertd.service
│   └── shadow-control-center/       # GTK UI
│       ├── setup.py
│       ├── shadow_control.py
│       ├── shadow_control.glade
│       ├── tabs/
│       └── assets/
│
├── scripts/                         # Build scripts
│   ├── build-iso.sh                 # ISO builder
│   ├── build-kernel.sh              # Kernel builder
│   ├── build-in-docker.sh           # Docker build
│   └── install-modules.sh           # Module installer
│
├── configs/                         # System configs
│   ├── sysctl.d/
│   ├── systemd/
│   └── profile.d/
│
├── docs/                            # Documentation
│   ├── BUILD.md
│   ├── INSTALL.md
│   ├── USAGE.md
│   └── specs/                       # Technical specs
│       ├── README.md
│       ├── spec_part1_overview.md
│       ├── spec_part2_defense.md
│       ├── spec_part3_hardware.md
│       ├── spec_part4_forensics.md
│       ├── spec_part5_research.md
│       └── spec_part6_ui.md
│
└── tests/                           # Test suites
    ├── kernel/
    ├── userspace/
    └── integration/
```

---

# KERNEL BUILD SYSTEM

Since the ShadowOS project is located at `root/shadowos` inside the kernel source tree (`root`):

## Kernel Location
* **Kernel Source:** `../../` (relative to `shadowos/kernel/`)
* **Project Root:** `shadowos/`

## setup-kernel.sh (Replaces download-kernel.sh)

```bash
#!/bin/bash
# Link ShadowOS modules into kernel tree

KERNEL_DIR="../.."
SHADOW_SRC="src"

echo "[shadowos] Linking modules into kernel tree..."

# Link net/shadowos
if [ ! -L "$KERNEL_DIR/net/shadowos" ]; then
    ln -sf "$PWD/$SHADOW_SRC/net/shadowos" "$KERNEL_DIR/net/"
    echo "Linked net/shadowos"
fi

# Link security/shadowos
if [ ! -L "$KERNEL_DIR/security/shadowos" ]; then
    ln -sf "$PWD/$SHADOW_SRC/security/shadowos" "$KERNEL_DIR/security/"
    echo "Linked security/shadowos"
fi

# Link include/shadowos
if [ ! -L "$KERNEL_DIR/include/shadowos" ]; then
    ln -sf "$PWD/$SHADOW_SRC/include/shadowos" "$KERNEL_DIR/include/"
    echo "Linked include/shadowos"
fi

# Patch Kconfig/Makefiles if not already done
if ! grep -q "shadowos" "$KERNEL_DIR/net/Kconfig"; then
    echo "[shadowos] Patching net/Kconfig..."
    # Insert before 'endmenu'
    sed -i '/endmenu/i source "net/shadowos/Kconfig"' "$KERNEL_DIR/net/Kconfig"
fi

if ! grep -q "shadowos" "$KERNEL_DIR/net/Makefile"; then
    echo "[shadowos] Patching net/Makefile..."
    echo "obj-\$(CONFIG_SHADOWOS) += shadowos/" >> "$KERNEL_DIR/net/Makefile"
fi

echo "[shadowos] Kernel tree setup complete"
```

## kernel/Makefile

```makefile
# In-tree Kernel Build

KERNEL_DIR := ../..
JOBS := $(shell nproc)

.PHONY: all setup config build package clean

all: setup config build package

setup:
	./setup-kernel.sh

config: setup
	# Merge our config fragment
	./scripts/kconfig/merge_config.sh -m $(KERNEL_DIR)/.config config/shadowos_defconfig
	$(MAKE) -C $(KERNEL_DIR) olddefconfig

build: config
	$(MAKE) -C $(KERNEL_DIR) -j$(JOBS)

package: build
	$(MAKE) -C $(KERNEL_DIR) -j$(JOBS) bindeb-pkg
	mv $(KERNEL_DIR)/../linux-image-*.deb .
	mv $(KERNEL_DIR)/../linux-headers-*.deb .

clean:
	# Don't clean the whole kernel, just our stuff?
	# Or let the user handle kernel cleaning
	@echo "Run 'make -C ../.. clean' to clean kernel"
```

---

# KERNEL MODULE MAKEFILE

## kernel/src/net/shadowos/Makefile

```makefile
# ShadowOS Network Modules

obj-$(CONFIG_SHADOWOS_CORE) += shadow_core.o
obj-$(CONFIG_SHADOWOS_DETECT) += shadow_detect.o
obj-$(CONFIG_SHADOWOS_CHAOS) += shadow_chaos.o
obj-$(CONFIG_SHADOWOS_PHANTOM) += shadow_phantom.o
obj-$(CONFIG_SHADOWOS_FLUX) += shadow_flux.o
obj-$(CONFIG_SHADOWOS_DNS) += shadow_dns.o
obj-$(CONFIG_SHADOWOS_GEO) += shadow_geo.o

# Multi-file modules
shadow_core-objs := core_main.o core_netlink.o core_sysfs.o core_stats.o
shadow_phantom-objs := phantom_main.o phantom_banners.o phantom_tarpit.o
```

## kernel/src/net/shadowos/Kconfig

```kconfig
# ShadowOS Security Modules

menuconfig SHADOWOS
	bool "ShadowOS Security Framework"
	depends on NETFILTER
	help
	  Enable ShadowOS kernel security modules for active defense,
	  network deception, and anti-forensics capabilities.

if SHADOWOS

config SHADOWOS_CORE
	tristate "ShadowOS Core Framework"
	default y
	help
	  Core infrastructure for ShadowOS modules. Required for all
	  other ShadowOS features.

config SHADOWOS_DETECT
	tristate "Scan Detection"
	depends on SHADOWOS_CORE
	default y
	help
	  Detect network reconnaissance and port scanning.

config SHADOWOS_CHAOS
	tristate "Protocol Chaos"
	depends on SHADOWOS_CORE
	default y
	help
	  Randomize TCP/IP stack behavior to defeat fingerprinting.

config SHADOWOS_PHANTOM
	tristate "Phantom Services"
	depends on SHADOWOS_CORE
	default y
	help
	  Fake service responses on closed ports.

config SHADOWOS_FLUX
	tristate "Identity Flux"
	depends on SHADOWOS_CORE
	default y
	help
	  Per-connection OS identity changes.

config SHADOWOS_DNS
	tristate "DNS Sinkhole"
	depends on SHADOWOS_CORE
	default y
	help
	  Kernel-level DNS filtering.

config SHADOWOS_GEO
	tristate "Geo-Fencing"
	depends on SHADOWOS_CORE
	default m
	help
	  Block/allow traffic by country.

endif # SHADOWOS
```

---

# MASTER MAKEFILE

```makefile
# ShadowOS Master Build System

.PHONY: all kernel userspace iso clean help

# Configuration
BUILD_DIR ?= $(PWD)/build
KERNEL_DIR := kernel
USERSPACE_DIR := userspace

all: kernel userspace iso

# Build custom kernel
kernel:
	$(MAKE) -C $(KERNEL_DIR)

# Build userspace components
userspace: libshadow alertd control-center

libshadow:
	$(MAKE) -C $(USERSPACE_DIR)/libshadow

alertd: libshadow
	$(MAKE) -C $(USERSPACE_DIR)/shadow-alertd

control-center:
	cd $(USERSPACE_DIR)/shadow-control-center && pip install -e .

# Build complete ISO
iso: kernel userspace
	BUILD_DIR=$(BUILD_DIR) ./scripts/build-iso.sh

# Docker build (recommended)
docker-build:
	./scripts/build-in-docker.sh

# Install kernel modules (for development)
install-modules:
	sudo ./scripts/install-modules.sh

# Run tests
test:
	$(MAKE) -C tests

# Clean everything
clean:
	$(MAKE) -C $(KERNEL_DIR) clean
	$(MAKE) -C $(USERSPACE_DIR)/libshadow clean
	$(MAKE) -C $(USERSPACE_DIR)/shadow-alertd clean
	rm -rf $(BUILD_DIR)

help:
	@echo "ShadowOS Build System"
	@echo ""
	@echo "Targets:"
	@echo "  all           - Build everything"
	@echo "  kernel        - Build custom kernel"
	@echo "  userspace     - Build userspace components"
	@echo "  iso           - Build complete ISO"
	@echo "  docker-build  - Build in Docker (recommended)"
	@echo "  test          - Run tests"
	@echo "  clean         - Clean build artifacts"
```

---

# INTEGRATION WITH EXISTING BUILD

The existing `build-iso.sh` will be modified to:

1. Check for custom kernel packages
2. Install custom kernel if available
3. Load ShadowOS modules on boot
4. Configure systemd services

```bash
# In build-iso.sh, add kernel install step:

if [ -f "kernel/linux-image-*.deb" ]; then
    log "Installing custom ShadowOS kernel..."
    sudo cp kernel/linux-image-*.deb "$ROOTFS/tmp/"
    sudo cp kernel/linux-headers-*.deb "$ROOTFS/tmp/"
    sudo chroot "$ROOTFS" dpkg -i /tmp/linux-*.deb
    sudo rm "$ROOTFS/tmp/linux-*.deb"
fi
```

---

# CONTINUOUS INTEGRATION

## .github/workflows/build.yml

```yaml
name: Build ShadowOS

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  build-kernel:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Install dependencies
        run: |
          sudo apt-get update
          sudo apt-get install -y build-essential bc libncurses-dev \
            flex bison libssl-dev libelf-dev
      
      - name: Build kernel
        run: make kernel
      
      - name: Upload kernel packages
        uses: actions/upload-artifact@v3
        with:
          name: kernel-packages
          path: kernel/*.deb

  build-iso:
    needs: build-kernel
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Download kernel packages
        uses: actions/download-artifact@v3
        with:
          name: kernel-packages
          path: kernel/
      
      - name: Build ISO
        run: make docker-build
      
      - name: Upload ISO
        uses: actions/upload-artifact@v3
        with:
          name: shadowos-iso
          path: shadowos.iso
```

# FUTURE IMPROVEMENTS

## Initramfs

The current initramfs implementation is based on a minimal BusyBox environment. For better debugging and tool availability, this should be migrated.

*   **Requirement:** Migrate initramfs from minimal Busybox to full Debian/Alpine environment.
*   **Goal:** Ensure standard tools like `ip` (iproute2), `ifconfig` (net-tools), and `udev` are available during early boot and in the rescue shell.
*   **Benefit:** Easier troubleshooting of network configuration, module loading, and boot failures.

## Build Process

*   **Reproducible Builds:** Ensure deterministic build output for security auditing.
*   **SBOM Generation:** Automatically generate Software Bill of Materials for each ISO build.
