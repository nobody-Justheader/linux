# SPDX-License-Identifier: GPL-2.0
#
# Makefile for ShadowOS
#

obj-$(CONFIG_SHADOWOS) += shadowos/

# Installation targets
SHADOWOS_DESTDIR ?= $(INSTALL_MOD_PATH)/shadowos
SHADOWOS_SRC := $(srctree)/shadowos

.PHONY: shadowos-install shadowos-iso shadowos-usb shadowos-clean

shadowos-install:
	@echo "  INSTALL ShadowOS to $(SHADOWOS_DESTDIR)"
	$(Q)mkdir -p $(SHADOWOS_DESTDIR)/usr/bin
	$(Q)mkdir -p $(SHADOWOS_DESTDIR)/etc
	$(Q)install -m 755 $(SHADOWOS_SRC)/usr/bin/* $(SHADOWOS_DESTDIR)/usr/bin/
	$(Q)cp -r $(SHADOWOS_SRC)/etc/* $(SHADOWOS_DESTDIR)/etc/
	@echo "  ShadowOS installed"

shadowos-iso: vmlinux
	@echo "  BUILD  ShadowOS ISO"
	$(Q)$(SHADOWOS_SRC)/scripts/build-iso.sh \
		--kernel $(objtree)/arch/$(SRCARCH)/boot/bzImage \
		--output $(objtree)/shadowos.iso
	@echo "  ISO    $(objtree)/shadowos.iso"

shadowos-usb:
	@echo "  BUILD  ShadowOS USB"
	@echo "  Usage: make shadowos-usb DEVICE=/dev/sdX"
ifndef DEVICE
	$(error DEVICE not set. Use: make shadowos-usb DEVICE=/dev/sdX)
endif
	$(Q)$(SHADOWOS_SRC)/scripts/create-usb.sh $(DEVICE)

shadowos-clean:
	@echo "  CLEAN  ShadowOS"
	$(Q)rm -rf $(objtree)/shadowos.iso
	$(Q)rm -rf $(objtree)/shadowos-build

help-shadowos:
	@echo  ''
	@echo  'ShadowOS targets:'
	@echo  '  shadowos-install  - Install ShadowOS to INSTALL_MOD_PATH'
	@echo  '  shadowos-iso      - Build bootable ISO'
	@echo  '  shadowos-usb      - Create USB (DEVICE=/dev/sdX required)'
	@echo  '  shadowos-clean    - Clean ShadowOS build files'
	@echo  ''
