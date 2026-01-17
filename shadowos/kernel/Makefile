# ShadowOS In-Tree Kernel Build
# This Makefile assumes we are at root/shadowos/kernel
# and the kernel source is at root/

KERNEL_DIR ?= ..
JOBS := $(shell nproc)

.PHONY: all setup config build package clean help

all: setup config build package

setup:
	@echo ">>> Setting up in-tree modules"
	chmod +x setup-kernel.sh
	./setup-kernel.sh

config: setup
	@echo ">>> Configuring kernel"
	# Ensure merge_config exists in kernel tree? It usually does in scripts/kconfig
	$(KERNEL_DIR)/scripts/kconfig/merge_config.sh -m -O $(KERNEL_DIR) $(KERNEL_DIR)/.config config/shadowos_defconfig
	$(MAKE) -C $(KERNEL_DIR) olddefconfig

build: config
	@echo ">>> Building kernel (j$(JOBS))"
	@if [ ! -f $(KERNEL_DIR)/.config ]; then echo "Error: No .config found"; exit 1; fi
	$(MAKE) -C $(KERNEL_DIR) -j$(JOBS)

package: build
	@echo ">>> Packaging kernel"
	$(MAKE) -C $(KERNEL_DIR) -j$(JOBS) bindeb-pkg LOCALVERSION=-shadowos

clean:
	@echo "To clean the kernel, run: make -C ../.. clean"
	@echo "To remove links, you may need to manually revert setup-kernel.sh changes"

help:
	@echo "ShadowOS Kernel Build System"
	@echo "  setup   - Link modules to kernel tree"
	@echo "  config  - Apply ShadowOS configuration"
	@echo "  build   - Build kernel image"
	@echo "  package - Build deb packages"
