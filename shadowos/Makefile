# ShadowOS Makefile
# Incremental build system to avoid redownloading packages

BUILD_DIR = /app/build
ROOTFS = $(BUILD_DIR)/rootfs
OUTPUT_DIR = output
ISO_NAME = shadowos.iso

.PHONY: all clean rootfs packages config iso help

all: iso

help:
	@echo "ShadowOS Build System"
	@echo "  make rootfs    - Bootstrap Debian base (Cached)"
	@echo "  make packages  - Install packages (Cached)"
	@echo "  make config    - Apply configuration (Always runs)"
	@echo "  make iso       - Generate ISO image"
	@echo "  make clean     - Remove all build artifacts"

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

# 1. Base System (Debootstrap)
# specific marker file to check if done
$(BUILD_DIR)/.rootfs_done: 
	@echo "[Makefile] Bootstrapping rootfs..."
	BUILD_DIR=$(BUILD_DIR) ./scripts/build-iso.sh --stage-rootfs
	touch $(BUILD_DIR)/.rootfs_done

rootfs: $(BUILD_DIR)/.rootfs_done

# 2. Packages (Apt)
# Depends on rootfs
$(BUILD_DIR)/.packages_done: $(BUILD_DIR)/.rootfs_done
	@echo "[Makefile] Installing packages..."
	BUILD_DIR=$(BUILD_DIR) ./scripts/build-iso.sh --stage-packages
	touch $(BUILD_DIR)/.packages_done

packages: $(BUILD_DIR)/.packages_done

# 3. Configuration (Copy files)
# Always run to pick up script changes
config: $(BUILD_DIR)/.packages_done
	@echo "[Makefile] Applying configuration..."
	BUILD_DIR=$(BUILD_DIR) ./scripts/build-iso.sh --stage-config

# 4. ISO Generation
iso: config
	@echo "[Makefile] Generating ISO..."
	BUILD_DIR=$(BUILD_DIR) ./scripts/build-iso.sh --stage-iso

clean:
	rm -rf $(BUILD_DIR) $(OUTPUT_DIR)/$(ISO_NAME)
