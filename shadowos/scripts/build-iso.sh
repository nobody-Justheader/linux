#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# build-iso.sh - Build ShadowOS ISO (Debian + systemd based)
# Creates a Kali-like live ISO with systemd, glibc, and full compatibility
# MUST BE RUN INSIDE DOCKER CONTAINER via build-in-docker.sh
#

# Check if running inside a container (Docker safety check)
if [ ! -f /.dockerenv ] && [ -z "${SHADOWOS_ALLOW_HOST_BUILD:-}" ]; then
    echo "[ERROR] This script must be run inside a Docker container."
    echo "        Use: ./scripts/build-in-docker.sh --clean"
    echo ""
    echo "        To override (DANGEROUS): export SHADOWOS_ALLOW_HOST_BUILD=1"
    exit 1
fi

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SHADOWOS_DIR="$(dirname "$SCRIPT_DIR")"
BUILD_DIR="$(realpath -m "${BUILD_DIR:-/tmp/shadowos-build}")"
OUTPUT="${OUTPUT:-shadowos.iso}"

# Debian configuration
DEBIAN_RELEASE="bookworm"
DEBIAN_MIRROR="http://deb.debian.org/debian"

# Build options
CLEAN_BUILD=0
DEBUG_BUILD=0

log() { echo "[shadowos] $*"; }
warn() { echo "[warning] $*"; }
error() { echo "[ERROR] $*" >&2; exit 1; }

cleanup() {
    # Explicitly unmount known targets in reverse order of mounting
    if [ -d "$BUILD_DIR/rootfs" ]; then
        local rootfs="$BUILD_DIR/rootfs"
        # Unmount in reverse order: dev/pts -> dev -> sys -> proc
        # We check mountpoint -q to avoid errors on already unmounted dirs
        mountpoint -q "$rootfs/dev/pts" && sudo umount "$rootfs/dev/pts"
        mountpoint -q "$rootfs/dev"     && sudo umount "$rootfs/dev"
        mountpoint -q "$rootfs/sys"     && sudo umount "$rootfs/sys"
        mountpoint -q "$rootfs/proc"    && sudo umount "$rootfs/proc"
    fi
}
trap cleanup EXIT

# =============================================================================
# PARSE ARGUMENTS
# =============================================================================

while [[ $# -gt 0 ]]; do
    case "$1" in
        --output)  OUTPUT="$2"; shift 2 ;;
        --clean)   CLEAN_BUILD=1; shift ;;
        --debug)   DEBUG_BUILD=1; shift ;;
        --help)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --output PATH   Output ISO path (default: shadowos.iso)"
            echo "  --clean         Clean build directory before building"
            echo "  --debug         Build with debug boot options"
            echo "  --help          Show this help"
            exit 0
            ;;
        *) shift ;;
    esac
done

# =============================================================================
# CHECK DEPENDENCIES
# =============================================================================

check_deps() {
    local missing=()
    
    for cmd in debootstrap mksquashfs xorriso grub-mkrescue; do
        if ! command -v "$cmd" &>/dev/null; then
            missing+=("$cmd")
        fi
    done
    
    if [[ ${#missing[@]} -gt 0 ]]; then
        error "Missing dependencies: ${missing[*]}
Install with: sudo apt install debootstrap squashfs-tools xorriso grub-pc-bin grub-efi-amd64-bin mtools"
    fi
}

check_deps

# =============================================================================
# SETUP
# =============================================================================

log "Building ShadowOS ISO (Debian + systemd)..."
log "Output: $OUTPUT"
log "Build dir: $BUILD_DIR"

if [[ $CLEAN_BUILD -eq 1 ]]; then
    log "Cleaning build directory..."
    
    # Run safe cleanup first
    cleanup

    # FINAL SAFETY CHECK: Ensure critical paths are NOT mounted before rm
    # This prevents the "host deletion" bug if unmount failed
    if mountpoint -q "$BUILD_DIR/rootfs/dev"; then
        error "CRITICAL: $BUILD_DIR/rootfs/dev is still mounted! Aborting clean."
    fi

    # Remove with --one-file-system to physically prevent crossing into host /dev
    sudo rm -rf --one-file-system "$BUILD_DIR"
fi

mkdir -p "$BUILD_DIR"/{rootfs,iso/boot/grub,iso/live}

# =============================================================================
# CREATE DEBIAN ROOTFS
# =============================================================================

ROOTFS="$BUILD_DIR/rootfs"
# Create rootfs
if [ ! -d "$ROOTFS/bin" ]; then
    echo "[shadowos] Creating Debian rootfs with debootstrap..."
    # Only install absolute minimum in debootstrap to avoid polkitd/dbus config errors
    sudo debootstrap \
        --arch=amd64 \
        --variant=minbase \
        --include=sudo,locales,console-setup,linux-image-amd64,live-boot,systemd-sysv \
        bookworm "$ROOTFS" http://deb.debian.org/debian/
    
    log "Debian base installed"
else
    log "Using existing rootfs"
fi

# =============================================================================
# CONFIGURE SYSTEM
# =============================================================================

log "Configuring system..."

# Set hostname
echo "shadowos" | sudo tee "$ROOTFS/etc/hostname" > /dev/null

# Set OS identity
sudo tee "$ROOTFS/etc/os-release" > /dev/null << 'OSRELEASE'
PRETTY_NAME="ShadowOS 1.0 (Based on Debian Bookworm)"
NAME="ShadowOS"
VERSION_ID="1.0"
VERSION="1.0"
VERSION_CODENAME="shadow"
ID=shadowos
ID_LIKE=debian
HOME_URL="https://shadowos.io"
SUPPORT_URL="https://shadowos.io/support"
BUG_REPORT_URL="https://shadowos.io/bugs"
OSRELEASE

# Protect os-release from being overwritten by base-files upgrades
sudo chroot "$ROOTFS" dpkg-divert --add --rename --divert /etc/os-release.debian /etc/os-release 2>/dev/null || true
sudo tee "$ROOTFS/etc/os-release" > /dev/null << 'OSRELEASE2'
PRETTY_NAME="ShadowOS 1.0 (Based on Debian Bookworm)"
NAME="ShadowOS"
VERSION_ID="1.0"
VERSION="1.0"
VERSION_CODENAME="shadow"
ID=shadowos
ID_LIKE=debian
HOME_URL="https://shadowos.io"
SUPPORT_URL="https://shadowos.io/support"
BUG_REPORT_URL="https://shadowos.io/bugs"
OSRELEASE2

# Configure hosts
sudo tee "$ROOTFS/etc/hosts" > /dev/null << 'EOF'
127.0.0.1   localhost
127.0.1.1   shadowos

::1         localhost ip6-localhost ip6-loopback
EOF

# Configure locales
sudo chroot "$ROOTFS" bash -c "echo 'en_US.UTF-8 UTF-8' > /etc/locale.gen && locale-gen"

# Set root password (empty for auto-login)
sudo chroot "$ROOTFS" bash -c "echo 'root:' | chpasswd -e"

# Configure repositories (Debian + Kali)
sudo tee "$ROOTFS/etc/apt/sources.list" > /dev/null << 'EOF'
# Debian Bookworm (base)
deb http://deb.debian.org/debian bookworm main contrib non-free non-free-firmware
deb http://deb.debian.org/debian bookworm-updates main contrib non-free non-free-firmware
deb http://security.debian.org/debian-security bookworm-security main contrib non-free non-free-firmware
EOF

# Create Kali setup script (run post-install to enable Kali repos)
log "Creating Kali repository setup script..."
sudo tee "$ROOTFS/usr/bin/shadowos-kali-setup" > /dev/null << 'KALISETUP'
#!/bin/bash
# ShadowOS - Enable Kali Repositories
# Run this after first boot to add Kali repos for security tools

set -e

echo "=============================================="
echo "    ShadowOS - Kali Repository Setup"
echo "=============================================="
echo ""

# Download and install Kali GPG key
echo "[shadowos] Downloading Kali GPG key..."
sudo mkdir -p /usr/share/keyrings

# Download key to temp file first
TMPKEY=$(mktemp)
if curl -fsSL https://archive.kali.org/archive-key.asc -o "$TMPKEY"; then
    echo "[shadowos] Key downloaded, dearmoring..."
    sudo gpg --batch --yes --dearmor -o /usr/share/keyrings/kali-archive-keyring.gpg "$TMPKEY"
    rm -f "$TMPKEY"
    echo "[shadowos] GPG key installed successfully"
else
    echo "[error] Failed to download Kali GPG key"
    rm -f "$TMPKEY"
    exit 1
fi

# Add Kali repository
echo "[shadowos] Adding Kali repository..."
echo "# Kali Rolling (security tools) - pinned to low priority" | sudo tee /etc/apt/sources.list.d/kali.list > /dev/null
echo "deb [signed-by=/usr/share/keyrings/kali-archive-keyring.gpg] http://http.kali.org/kali kali-rolling main contrib non-free non-free-firmware" | sudo tee -a /etc/apt/sources.list.d/kali.list > /dev/null

# Pin Kali packages to lower priority
echo "[shadowos] Configuring apt pinning..."
sudo tee /etc/apt/preferences.d/kali-priority > /dev/null << 'PINNING'
Package: *
Pin: release o=Kali
Pin-Priority: 100
PINNING

echo ""
echo "[shadowos] Updating package lists..."
sudo apt-get update

echo ""
echo "[shadowos] Kali repository enabled!"
echo "           Install tools with: apt install <package-name>"
echo "           Debian packages take priority (PIN 100 for Kali)"
KALISETUP
sudo chmod +x "$ROOTFS/usr/bin/shadowos-kali-setup"

# =============================================================================
# INSTALL ADDITIONAL PACKAGES
# =============================================================================



log "Installing additional packages..."

# Mount required filesystems for chroot
sudo mount --bind /dev "$ROOTFS/dev" || true
sudo mount --bind /dev/pts "$ROOTFS/dev/pts" || true
sudo mount -t proc proc "$ROOTFS/proc" || true
sudo mount -t sysfs sysfs "$ROOTFS/sys" || true

# Prevent services from starting in chroot
echo "exit 101" | sudo tee "$ROOTFS/usr/sbin/policy-rc.d" > /dev/null
sudo chmod +x "$ROOTFS/usr/sbin/policy-rc.d"

# Install GUI and tools
    sudo chroot "$ROOTFS" apt-get update
    # Install packages (split into groups to avoid total failure)
    # 1. Core GUI & Drivers (XFCE + LightDM)
    sudo chroot "$ROOTFS" apt-get install -y --no-install-recommends \
        xfce4 xfce4-goodies \
        lightdm lightdm-gtk-greeter \
        firefox-esr thunar \
        xorg xinit \
        dbus-x11 \
        network-manager-gnome \
        xserver-xorg-video-vmware xserver-xorg-video-qxl xserver-xorg-video-all \
        pciutils usbutils \
        firmware-linux-nonfree firmware-misc-nonfree firmware-realtek \
        || error "GUI Package installation failed!"

    # 2. Tools & Network
    sudo chroot "$ROOTFS" apt-get install -y --no-install-recommends \
        grub-pc-bin grub-efi-amd64-bin \
        iproute2 iputils-ping nano curl wget net-tools git \
        gnupg ca-certificates \
        fonts-dejavu ttf-bitstream-vera fonts-noto \
        network-manager wpasupplicant \
        nmap tcpdump iptables macchanger tor \
        zsh mousepad xfce4-terminal \
        arc-theme papirus-icon-theme adwaita-icon-theme \
        xfce4-whiskermenu-plugin 

# Configure XFCE Autostart (nm-applet, etc.)
# XFCE handles most things automatically, just ensure nm-applet starts
sudo mkdir -p "$ROOTFS/home/shadow/.config/autostart"
sudo tee "$ROOTFS/home/shadow/.config/autostart/nm-applet.desktop" > /dev/null << 'NMAPPLET'
[Desktop Entry]
Type=Application
Name=Network Manager Applet
Exec=nm-applet
Hidden=false
X-GNOME-Autostart-enabled=true
NMAPPLET

# Create wallpaper setup autostart (ensures wallpaper is set at login)
sudo tee "$ROOTFS/home/shadow/.config/autostart/shadowos-wallpaper.desktop" > /dev/null << 'WALLPAPER'
[Desktop Entry]
Type=Application
Name=ShadowOS Wallpaper
Exec=/bin/bash -c "sleep 2 && xfconf-query -c xfce4-desktop -p /backdrop/screen0/monitorVirtual1/workspace0/last-image -s /usr/share/backgrounds/shadowos/wallpaper.png 2>/dev/null; xfconf-query -c xfce4-desktop -p /backdrop/screen0/monitor0/workspace0/last-image -s /usr/share/backgrounds/shadowos/wallpaper.png 2>/dev/null; true"
Hidden=false
X-GNOME-Autostart-enabled=true
WALLPAPER

# Create .zshrc for shadow user
sudo touch "$ROOTFS/home/shadow/.zshrc"
sudo tee "$ROOTFS/home/shadow/.zshrc" > /dev/null << 'ZSHRC'
# ShadowOS zsh configuration
export PATH="$HOME/.local/bin:$PATH"
alias ll='ls -la'
alias la='ls -A'
alias l='ls -CF'
# Prompt
PS1='%F{cyan}%n@%m%f:%F{blue}%~%f$ '
ZSHRC

# Install ShadowOS branding
log "Installing ShadowOS branding..."
# Desktop wallpaper
sudo mkdir -p "$ROOTFS/usr/share/backgrounds/shadowos"
if [ -f "$SHADOWOS_DIR/assets/wallpaper.png" ]; then
    sudo cp "$SHADOWOS_DIR/assets/wallpaper.png" "$ROOTFS/usr/share/backgrounds/shadowos/wallpaper.png"
fi

# XFCE default wallpaper config (using monitor0 which is more universal)
sudo mkdir -p "$ROOTFS/home/shadow/.config/xfce4/xfconf/xfce-perchannel-xml"
sudo tee "$ROOTFS/home/shadow/.config/xfce4/xfconf/xfce-perchannel-xml/xfce4-desktop.xml" > /dev/null << 'XFCEDESK'
<?xml version="1.0" encoding="UTF-8"?>
<channel name="xfce4-desktop" version="1.0">
  <property name="backdrop" type="empty">
    <property name="screen0" type="empty">
      <property name="monitor0" type="empty">
        <property name="workspace0" type="empty">
          <property name="last-image" type="string" value="/usr/share/backgrounds/shadowos/wallpaper.png"/>
          <property name="image-style" type="int" value="5"/>
        </property>
      </property>
      <property name="monitorVirtual1" type="empty">
        <property name="workspace0" type="empty">
          <property name="last-image" type="string" value="/usr/share/backgrounds/shadowos/wallpaper.png"/>
          <property name="image-style" type="int" value="5"/>
        </property>
      </property>
    </property>
  </property>
</channel>
XFCEDESK

# Boot logo will be copied later to ISO directory (not rootfs)
# See GRUB configuration section

# Configure XFCE theme - Arc-Dark with Papirus icons
log "Configuring XFCE modern theme..."
sudo mkdir -p "$ROOTFS/home/shadow/.config/xfce4/xfconf/xfce-perchannel-xml"

# xsettings - GTK theme and icons
sudo tee "$ROOTFS/home/shadow/.config/xfce4/xfconf/xfce-perchannel-xml/xsettings.xml" > /dev/null << 'XSETTINGS'
<?xml version="1.0" encoding="UTF-8"?>
<channel name="xsettings" version="1.0">
  <property name="Net" type="empty">
    <property name="ThemeName" type="string" value="Arc-Dark"/>
    <property name="IconThemeName" type="string" value="Papirus-Dark"/>
  </property>
  <property name="Gtk" type="empty">
    <property name="CursorThemeName" type="string" value="Adwaita"/>
    <property name="FontName" type="string" value="DejaVu Sans 10"/>
  </property>
</channel>
XSETTINGS

# xfwm4 - Window manager with compositor
sudo tee "$ROOTFS/home/shadow/.config/xfce4/xfconf/xfce-perchannel-xml/xfwm4.xml" > /dev/null << 'XFWM4'
<?xml version="1.0" encoding="UTF-8"?>
<channel name="xfwm4" version="1.0">
  <property name="general" type="empty">
    <property name="theme" type="string" value="Arc-Dark"/>
    <property name="use_compositing" type="bool" value="true"/>
    <property name="frame_opacity" type="int" value="100"/>
    <property name="inactive_opacity" type="int" value="90"/>
    <property name="popup_opacity" type="int" value="100"/>
    <property name="show_frame_shadow" type="bool" value="true"/>
  </property>
</channel>
XFWM4

# xfce4-panel - Modern dark panel with Whisker Menu
sudo tee "$ROOTFS/home/shadow/.config/xfce4/xfconf/xfce-perchannel-xml/xfce4-panel.xml" > /dev/null << 'XFCEPANEL'
<?xml version="1.0" encoding="UTF-8"?>
<channel name="xfce4-panel" version="1.0">
  <property name="configver" type="int" value="2"/>
  <property name="panels" type="array">
    <value type="int" value="1"/>
  </property>
  <property name="panel-1" type="empty">
    <!-- p=12: Bottom Locked. mode=0: Horizontal. length=100%: Full Width -->
    <property name="position" type="string" value="p=12;x=0;y=0"/>
    <property name="position-locked" type="bool" value="true"/>
    <property name="length" type="uint" value="100"/>
    <property name="length-adjust" type="uint" value="1"/>
    <property name="size" type="uint" value="32"/>
    <property name="mode" type="uint" value="0"/>
    <property name="nrows" type="uint" value="1"/>
    <property name="plugin-ids" type="array">
      <value type="int" value="1"/>
      <value type="int" value="2"/>
      <value type="int" value="3"/>
      <value type="int" value="4"/>
      <value type="int" value="5"/>
      <value type="int" value="6"/>
      <value type="int" value="7"/>
    </property>
    <property name="background-style" type="uint" value="1"/>
    <property name="background-rgba" type="array">
      <value type="double" value="0.12"/>
      <value type="double" value="0.12"/>
      <value type="double" value="0.15"/>
      <value type="double" value="0.95"/>
    </property>
  </property>
  <property name="plugins" type="empty">
    <property name="plugin-1" type="string" value="whiskermenu"/>
    <property name="plugin-2" type="string" value="separator">
       <property name="style" type="uint" value="0"/>
    </property>
    <property name="plugin-3" type="string" value="tasklist">
       <property name="grouping" type="bool" value="true"/>
    </property>
    <property name="plugin-4" type="string" value="separator">
       <property name="expand" type="bool" value="true"/>
       <property name="style" type="uint" value="0"/>
    </property>
    <property name="plugin-5" type="string" value="pager"/>
    <property name="plugin-6" type="string" value="systray">
       <property name="show-frame" type="bool" value="false"/>
    </property>
    <property name="plugin-7" type="string" value="clock"/>
  </property>
</channel>
XFCEPANEL

# Force panel geometry script (fix for floating panel)
log "Creating panel fix script..."
sudo tee "$ROOTFS/usr/bin/shadowos-fix-panel" > /dev/null << 'FIXPANEL'
#!/bin/bash
# Force XFCE panel to correct geometry
sleep 3
xfconf-query -c xfce4-panel -p /panels/panel-1/position-locked -n -t bool -s true
xfconf-query -c xfce4-panel -p /panels/panel-1/length -n -t uint -s 100
xfconf-query -c xfce4-panel -p /panels/panel-1/length-adjust -n -t uint -s 1
xfconf-query -c xfce4-panel -p /panels/panel-1/size -n -t uint -s 32
xfconf-query -c xfce4-panel -p /panels/panel-1/position -n -t string -s "p=12;x=0;y=0"
xfconf-query -c xfce4-panel -p /panels/panel-1/mode -n -t uint -s 0
FIXPANEL
sudo chmod +x "$ROOTFS/usr/bin/shadowos-fix-panel"

# Autostart for panel fix
sudo mkdir -p "$ROOTFS/etc/xdg/autostart"
sudo tee "$ROOTFS/etc/xdg/autostart/shadowos-fix-panel.desktop" > /dev/null << 'AUTOSTART'
[Desktop Entry]
Type=Application
Name=Fix Panel Geometry
Exec=/usr/bin/shadowos-fix-panel
Terminal=false
StartupNotify=false
Hidden=false
AUTOSTART

# Set ownership

sudo chown -R 1000:1000 "$ROOTFS/home/shadow/.config"
sudo chown 1000:1000 "$ROOTFS/home/shadow/.zshrc"

# Configure LightDM to allow manual login (or auto if preferred, but manual requested)
# We ensure the greeter is set
sudo mkdir -p "$ROOTFS/etc/lightdm"
echo "[Seat:*]" | sudo tee "$ROOTFS/etc/lightdm/lightdm.conf" > /dev/null
echo "greeter-session=lightdm-gtk-greeter" | sudo tee -a "$ROOTFS/etc/lightdm/lightdm.conf" > /dev/null
echo "user-session=xfce" | sudo tee -a "$ROOTFS/etc/lightdm/lightdm.conf" > /dev/null

# Update .bash_profile (Optional now since LightDM handles login)
sudo tee "$ROOTFS/home/shadow/.bash_profile" > /dev/null << 'PROFILE'
# ShadowOS
if [ -z "$DISPLAY" ] && [ "$(tty)" = "/dev/tty1" ]; then
    echo "Welcome to ShadowOS."
    echo "Logs are being dumped to serial console."
fi
# Dump Log to Serial (Bidirectional Friendly)
if [ -e /dev/ttyS0 ] && [ -w /dev/ttyS0 ]; then
    {
        echo "=== [ShadowOS Debug Dump] ==="
        lspci -nnk | grep -A3 VGA
        lsmod | grep -E "drm|vbox|vmw"
        echo "=== [End Dump] ==="
    } > /dev/ttyS0 2>/dev/null
fi
PROFILE
sudo chown 1000:1000 "$ROOTFS/home/shadow/.bash_profile"

log "Creating 'shadow' user (post-package install)..."
# Create shadow user
echo "[shadowos] Creating 'shadow' user..."
# We use -g shadow (GID 42) which exists in base. Other groups (dialout, netdev) exist after package install.
# Switch to Zsh default
sudo chroot "$ROOTFS" useradd -m -s /usr/bin/zsh -g shadow -G sudo,video,input,plugdev,dialout,audio,netdev shadow || true
sudo chroot "$ROOTFS" sh -c 'echo "shadow:shadow" | chpasswd'
echo "shadow ALL=(ALL) NOPASSWD: ALL" | sudo tee "$ROOTFS/etc/sudoers.d/shadow" > /dev/null
sudo chmod 0440 "$ROOTFS/etc/sudoers.d/shadow"

# Clean apt cache
sudo chroot "$ROOTFS" apt-get clean
sudo rm -rf "$ROOTFS/var/lib/apt/lists/"*

# Unmount
sudo umount "$ROOTFS/sys" 2>/dev/null || true
sudo umount "$ROOTFS/proc" 2>/dev/null || true
sudo umount "$ROOTFS/dev/pts" 2>/dev/null || true
sudo umount "$ROOTFS/dev" 2>/dev/null || true

log "Packages installed"

# =============================================================================
# CONFIGURE SYSTEMD
# =============================================================================

log "Configuring systemd..."

# Auto-login on tty1
sudo mkdir -p "$ROOTFS/etc/systemd/system/getty@tty1.service.d"
# Auto-login config - DISABLED to fix flashing loop
# cat > "$ROOTFS/etc/systemd/system/getty@tty1.service.d/autologin.conf" << 'SERVICE'
# [Service]
# ExecStart=
# ExecStart=-/sbin/agetty --autologin shadow --noclear %I $TERM
# SERVICEOF

# Create ShadowOS security service
sudo tee "$ROOTFS/etc/systemd/system/shadowos.service" > /dev/null << 'EOF'
[Unit]
Description=ShadowOS Security Hardening
After=network.target

[Service]
Type=oneshot
ExecStart=/usr/bin/shadow-harden full
RemainAfterExit=yes
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

# Enable services
sudo chroot "$ROOTFS" systemctl enable shadowos.service 2>/dev/null || true
sudo chroot "$ROOTFS" systemctl enable NetworkManager.service 2>/dev/null || true

# LXDE config is handled automatically by task-lxde-desktop

# Configure .xinitrc for LXDE
sudo tee "$ROOTFS/home/shadow/.xinitrc" > /dev/null << 'XINIT'
#!/bin/sh
exec openbox-session
XINIT
sudo chmod +x "$ROOTFS/home/shadow/.xinitrc"

# Configure .bash_profile (Manual start)
sudo tee "$ROOTFS/home/shadow/.bash_profile" > /dev/null << 'PROFILE'
if [ -z "$DISPLAY" ] && [ "$(tty)" = "/dev/tty1" ]; then
    clear
    cat /etc/motd
    echo ""
    echo "Welcome to ShadowOS (LXDE Edition)!"
    echo "Type 'startx' to launch the desktop."
    echo ""
    
    # Auto-dump debug info to serial console (if available)
    if [ -e /dev/ttyS0 ]; then
        echo "Dumping debug info to COM1..."
        echo "=== [ShadowOS Debug Start] ===" > /dev/ttyS0
        echo "--- lspci -nnk (Video) ---" > /dev/ttyS0
        lspci -nnk | grep -A3 VGA >> /dev/ttyS0
        echo "--- Kernel DRM Modules ---" > /dev/ttyS0
        lsmod | grep -E "drm|vbox|vmw" >> /dev/ttyS0
        echo "--- Xorg Log (tail) ---" >> /dev/ttyS0
        tail -n 50 /var/log/Xorg.0.log 2>/dev/null >> /dev/ttyS0
        echo "=== [ShadowOS Debug End] ===" > /dev/ttyS0
    fi
fi
PROFILE

# Fix permissions
sudo chroot "$ROOTFS" chown -R shadow:shadow /home/shadow

log "systemd configured"

# =============================================================================
# INSTALL SHADOWOS COMPONENTS
# =============================================================================

log "Installing ShadowOS components..."

# Copy ShadowOS tools
sudo cp -r "$SHADOWOS_DIR/usr" "$ROOTFS/" 2>/dev/null || true

# Set permissions
sudo chmod +x "$ROOTFS/usr/bin/"* 2>/dev/null || true

# Create shadow-harden script if not exists
if [[ ! -f "$ROOTFS/usr/bin/shadow-harden" ]]; then
    sudo tee "$ROOTFS/usr/bin/shadow-harden" > /dev/null << 'HARDEN'
#!/bin/bash
# ShadowOS Security Hardening & Network Deception
# For physical penetration testing - evade network detection and EDRs

MODE="${1:-full}"

echo "=============================================="
echo "   ShadowOS Security Hardening & Stealth"
echo "=============================================="
echo ""

case "$MODE" in
    full|all)
        # Run all hardening
        $0 kernel
        $0 network
        $0 stealth
        ;;
    kernel)
        echo "[shadowos] Applying kernel hardening..."
        # Core dumps
        echo "|/bin/false" > /proc/sys/kernel/core_pattern 2>/dev/null
        echo 0 > /proc/sys/fs/suid_dumpable 2>/dev/null
        # Restrict kernel info
        echo 1 > /proc/sys/kernel/dmesg_restrict 2>/dev/null
        echo 2 > /proc/sys/kernel/kptr_restrict 2>/dev/null
        # ASLR
        echo 2 > /proc/sys/kernel/randomize_va_space 2>/dev/null
        # Disable swap
        swapoff -a 2>/dev/null
        echo "[shadowos] Kernel hardening complete."
        ;;
    network)
        echo "[shadowos] Applying network hardening..."
        echo 1 > /proc/sys/net/ipv4/conf/all/rp_filter 2>/dev/null
        echo 0 > /proc/sys/net/ipv4/conf/all/accept_redirects 2>/dev/null
        echo 0 > /proc/sys/net/ipv6/conf/all/accept_redirects 2>/dev/null
        echo 0 > /proc/sys/net/ipv4/conf/all/send_redirects 2>/dev/null
        echo "[shadowos] Network hardening complete."
        ;;
    stealth)
        echo "[shadowos] Activating network stealth mode..."
        
        # === TTL MANIPULATION ===
        # Mimic Windows default TTL (128) to evade OS fingerprinting
        echo 128 > /proc/sys/net/ipv4/ip_default_ttl 2>/dev/null
        echo "[stealth] TTL set to 128 (Windows-like)"
        
        # === TCP TIMESTAMPS ===
        # Disable TCP timestamps to prevent uptime fingerprinting
        echo 0 > /proc/sys/net/ipv4/tcp_timestamps 2>/dev/null
        echo "[stealth] TCP timestamps disabled"
        
        # === ICMP STEALTH ===
        # Ignore ICMP echo (ping) requests
        echo 1 > /proc/sys/net/ipv4/icmp_echo_ignore_all 2>/dev/null
        # Ignore broadcast pings (smurf attack protection + stealth)
        echo 1 > /proc/sys/net/ipv4/icmp_echo_ignore_broadcasts 2>/dev/null
        echo "[stealth] ICMP responses disabled"
        
        # === MAC ADDRESS RANDOMIZATION ===
        for iface in /sys/class/net/*; do
            iface=$(basename "$iface")
            [[ "$iface" == "lo" ]] && continue
            # Use macchanger to randomize MAC
            macchanger -r "$iface" 2>/dev/null && echo "[stealth] Randomized MAC for $iface" || true
        done
        
        # === TCP FINGERPRINT MASKING ===
        echo 1 > /proc/sys/net/ipv4/tcp_syncookies 2>/dev/null
        echo 0 > /proc/sys/net/ipv4/tcp_sack 2>/dev/null
        echo 0 > /proc/sys/net/ipv4/tcp_window_scaling 2>/dev/null
        echo "[stealth] TCP fingerprint masking enabled"
        
        # Trigger initial rotation
        $0 rotate
        
        echo ""
        echo "[shadowos] Stealth mode activated - device now looks like Windows with Polymorph active"
        ;;
    rotate)
        # === POLYMORPHIC IDENTITY ROTATION ===
        # Randomly rotate /etc/issue and /etc/os-release to confuse scanners
        
        # Pre-defined identities
        IDENTITIES=("ubuntu" "fedora" "arch" "windows" "shadow" "freebsd" "cisco")
        CHOSEN_ID=${IDENTITIES[$RANDOM % ${#IDENTITIES[@]}]}
        
        # echo "[polymorph] Rotating identity to: $CHOSEN_ID"
        
        case "$CHOSEN_ID" in
            ubuntu)
                echo "Ubuntu 22.04 LTS \n \l" > /etc/issue
                cat > /etc/os-release <<EOF
PRETTY_NAME="Ubuntu 22.04.3 LTS"
NAME="Ubuntu"
VERSION_ID="22.04"
VERSION="22.04.3 LTS (Jammy Jellyfish)"
ID=ubuntu
ID_LIKE=debian
HOME_URL="https://www.ubuntu.com/"
EOF
                ;;
            fedora)
                echo "Fedora Linux 38 (Workstation Edition) \n \l" > /etc/issue
                cat > /etc/os-release <<EOF
NAME="Fedora Linux"
VERSION="38"
ID=fedora
PRETTY_NAME="Fedora Linux 38"
CPE_NAME="cpe:/o:fedoraproject:fedora:38"
EOF
                ;;
            arch)
                echo "Arch Linux \r (\l)" > /etc/issue
                cat > /etc/os-release <<EOF
NAME="Arch Linux"
PRETTY_NAME="Arch Linux"
ID=arch
BUILD_ID=rolling
EOF
                ;;
            windows)
                echo "Microsoft Windows [Version 10.0.19045.3693]" > /etc/issue
                echo "(c) Microsoft Corporation. All rights reserved." >> /etc/issue
                cat > /etc/os-release <<EOF
NAME="Microsoft Windows"
VERSION="10"
ID=windows
PRETTY_NAME="Windows 10 Pro"
EOF
                ;;
            freebsd)
                echo "FreeBSD 13.2-RELEASE" > /etc/issue
                cat > /etc/os-release <<EOF
NAME="FreeBSD"
VERSION="13.2-RELEASE"
ID=freebsd
PRETTY_NAME="FreeBSD 13.2-RELEASE"
EOF
                ;;
            cisco)
                echo "User Access Verification" > /etc/issue
                echo "" >> /etc/issue
                echo "Password:" >> /etc/issue
                cat > /etc/os-release <<EOF
NAME="Cisco IOS"
ID=cisco
PRETTY_NAME="Cisco IOS Software"
EOF
                ;;
            shadow)
                echo "ShadowOS 1.0 \n \l" > /etc/issue
                cat > /etc/os-release <<EOF
PRETTY_NAME="ShadowOS 1.0"
NAME="ShadowOS"
ID=shadowos
EOF
                ;;
        esac
        ;;
    daemon)
        echo "[polymorph] Starting Active Polymorphic Defense (Interval: 60s)..."
        while true; do
            $0 rotate
            # Future: Add active port fuzzing/honeyports here
            sleep 60
        done
        ;;
    windows)
        # Preset: Look like Windows
        echo "[shadowos] Windows disguise mode..."
        echo 128 > /proc/sys/net/ipv4/ip_default_ttl 2>/dev/null
        echo 0 > /proc/sys/net/ipv4/tcp_timestamps 2>/dev/null
        # Windows Banner
        echo "Microsoft Windows [Version 10.0.19045.3693]" > /etc/issue
        echo "(c) Microsoft Corporation. All rights reserved." >> /etc/issue
        echo "[shadowos] Now appearing as Windows system (TTL=128 + Banner)"
        ;;
    linux)
        # Preset: Default Linux TTL
        echo "[shadowos] Reverting to Linux defaults..."
        echo 64 > /proc/sys/net/ipv4/ip_default_ttl 2>/dev/null
        echo 1 > /proc/sys/net/ipv4/tcp_timestamps 2>/dev/null
        # Restore ShadowOS Banner
        echo "ShadowOS 1.0 \n \l" > /etc/issue
        echo "[shadowos] Linux defaults restored (TTL=64)"
        ;;
    *)
        echo "Usage: shadow-harden [full|stealth|rotate|daemon|windows|linux]"
        exit 1
        ;;
esac

echo ""
HARDEN
    sudo chmod +x "$ROOTFS/usr/bin/shadow-harden"
    
    # Create Polymorph Service (Autostart Daemon)
    sudo tee "$ROOTFS/etc/systemd/system/shadow-polymorph.service" > /dev/null << 'POLYMORPH'
[Unit]
Description=ShadowOS Active Polymorphic Defense
After=network.target shadowos.service

[Service]
ExecStart=/usr/bin/shadow-harden daemon
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
POLYMORPH
    sudo chroot "$ROOTFS" systemctl enable shadow-polymorph.service 2>/dev/null || true
fi

# Create RAM workspace
sudo mkdir -p "$ROOTFS/shadow"

log "ShadowOS components installed"

# Create shadowos-update script
log "Creating shadowos-update script..."
sudo tee "$ROOTFS/usr/bin/shadowos-update" > /dev/null << 'UPDATE'
#!/bin/bash
# ShadowOS Update Script
# Wraps apt update/upgrade and provides GitHub-based ShadowOS updates

SHADOWOS_REPO="${SHADOWOS_REPO:-https://github.com/shadowos/shadowos}"
SHADOWOS_BRANCH="${SHADOWOS_BRANCH:-main}"

echo "=============================================="
echo "         ShadowOS System Update"
echo "=============================================="
echo ""

case "${1:-full}" in
    system|apt)
        echo "[shadowos] Updating system packages..."
        sudo apt-get update
        sudo apt-get upgrade -y
        sudo apt-get dist-upgrade -y
        sudo apt-get autoremove -y
        echo "[shadowos] System packages updated."
        ;;
    core|github)
        echo "[shadowos] Checking for ShadowOS core updates from GitHub..."
        if command -v git &> /dev/null; then
            TMPDIR=$(mktemp -d)
            if git clone --depth 1 -b "$SHADOWOS_BRANCH" "$SHADOWOS_REPO" "$TMPDIR" 2>/dev/null; then
                echo "[shadowos] Updating ShadowOS components..."
                sudo cp -r "$TMPDIR/usr/"* /usr/ 2>/dev/null || true
                sudo cp -r "$TMPDIR/etc/"* /etc/ 2>/dev/null || true
                rm -rf "$TMPDIR"
                echo "[shadowos] ShadowOS core updated from GitHub."
            else
                echo "[shadowos] No GitHub repo configured or network unavailable."
            fi
        else
            echo "[warning] git not installed, cannot fetch GitHub updates."
        fi
        ;;
    full|"")
        $0 system
        $0 core
        ;;
    *)
        echo "Usage: shadowos-update [system|core|full]"
        echo ""
        echo "  system  - Update system packages via apt"
        echo "  core    - Update ShadowOS from GitHub"
        echo "  full    - Both (default)"
        exit 1
        ;;
esac

echo ""
echo "[shadowos] Update complete."
UPDATE
sudo chmod +x "$ROOTFS/usr/bin/shadowos-update"

# Create apt update hook to show ShadowOS branding
sudo mkdir -p "$ROOTFS/etc/apt/apt.conf.d"
sudo tee "$ROOTFS/etc/apt/apt.conf.d/99shadowos" > /dev/null << 'APTHOOK'
// ShadowOS apt configuration
APT::Update::Pre-Invoke { "echo '[ShadowOS] Starting package database update...'"; };
APT::Update::Post-Invoke { "echo '[ShadowOS] Package database updated.'"; };
APTHOOK

# =============================================================================
# GENERATE INITRAMFS
# =============================================================================

log "Generating initramfs..."

# Mount for chroot
sudo mount --bind /dev "$ROOTFS/dev" || true
sudo mount --bind /dev/pts "$ROOTFS/dev/pts" || true
sudo mount -t proc proc "$ROOTFS/proc" || true
sudo mount -t sysfs sysfs "$ROOTFS/sys" || true

# Update initramfs with live-boot (Critical step)
log "Regenerating initramfs..."
sudo chroot "$ROOTFS" update-initramfs -u -k all || error "Failed to regenerate initramfs"

# Copy kernel and initramfs to ISO
KERNEL_VER=$(ls "$ROOTFS/lib/modules/" | sort -V | tail -1)
if [[ -n "$KERNEL_VER" ]]; then
    log "Using kernel $KERNEL_VER"
    sudo cp "$ROOTFS/boot/vmlinuz-$KERNEL_VER" "$BUILD_DIR/iso/boot/vmlinuz"
    sudo cp "$ROOTFS/boot/initrd.img-$KERNEL_VER" "$BUILD_DIR/iso/boot/initrd.img"
else
    error "No kernel found in rootfs"
fi

# Unmount
sudo umount "$ROOTFS/sys" 2>/dev/null || true
sudo umount "$ROOTFS/proc" 2>/dev/null || true
sudo umount "$ROOTFS/dev/pts" 2>/dev/null || true
sudo umount "$ROOTFS/dev" 2>/dev/null || true

# =============================================================================
# CREATE SQUASHFS
# =============================================================================

log "Creating SquashFS (this takes a while)..."

sudo rm -f "$BUILD_DIR/iso/live/filesystem.squashfs"
sudo mksquashfs "$ROOTFS" "$BUILD_DIR/iso/live/filesystem.squashfs" \
    -comp gzip -b 1M -noappend

# Create live-boot metadata
log "Creating live-boot metadata..."
echo "filesystem.squashfs" | sudo tee "$BUILD_DIR/iso/live/filesystem.module" > /dev/null
sudo du -sb "$ROOTFS" | cut -f1 | sudo tee "$BUILD_DIR/iso/live/filesystem.size" > /dev/null

# Create .disk info
sudo mkdir -p "$BUILD_DIR/iso/.disk"
echo "ShadowOS 1.0" | sudo tee "$BUILD_DIR/iso/.disk/info" > /dev/null
echo "live" | sudo tee "$BUILD_DIR/iso/.disk/cd_type" > /dev/null

log "SquashFS created"

# =============================================================================
# GRUB CONFIGURATION
# =============================================================================

log "Configuring GRUB..."

if [[ $DEBUG_BUILD -eq 1 ]]; then
    QUIET_OPTS=""
else
    QUIET_OPTS="quiet splash"
fi

# Copy boot logo to ISO GRUB directory
if [ -f "$SHADOWOS_DIR/assets/boot_logo.png" ]; then
    log "Copying boot logo to ISO..."
    sudo cp "$SHADOWOS_DIR/assets/boot_logo.png" "$BUILD_DIR/iso/boot/grub/shadowos-logo.png"
fi

sudo tee "$BUILD_DIR/iso/boot/grub/grub.cfg" > /dev/null << EOF
# Load graphics modules first
insmod all_video
insmod gfxterm
insmod png
insmod jpeg

# Set graphics mode
set gfxmode=1024x768,auto
set gfxpayload=keep

# Try to load font
if loadfont /boot/grub/fonts/unicode.pf2; then
    set have_font=true
fi

# Initialize graphics terminal
terminal_output gfxterm

# Load background image
if [ -f /boot/grub/shadowos-logo.png ]; then
    background_image -m stretch /boot/grub/shadowos-logo.png
fi

# Serial console for debugging (optional)
insmod serial
serial --speed=115200 --unit=0 --word=8 --parity=no --stop=1

set timeout=5
set default=0

menuentry "ShadowOS Live" {
    linux /boot/vmlinuz boot=live $QUIET_OPTS console=tty0 console=ttyS0,115200n8
    initrd /boot/initrd.img
}

menuentry "ShadowOS Live (Safe Graphics - nomodeset)" {
    linux /boot/vmlinuz boot=live nomodeset $QUIET_OPTS console=tty0 console=ttyS0,115200n8
    initrd /boot/initrd.img
}

menuentry "ShadowOS Live (Debug)" {
    linux /boot/vmlinuz boot=live debug console=tty0 console=ttyS0,115200n8
    initrd /boot/initrd.img
}
EOF

# Update shadow user profile for robust X11 start
sudo tee "$ROOTFS/home/shadow/.bash_profile" > /dev/null << 'PROFILE'
# ShadowOS - Auto-start X11
if [ -z "$DISPLAY" ] && [ "$(tty)" = "/dev/tty1" ]; then
    
    # Custom branding
    clear
    cat /etc/motd
    echo ""
    echo "Welcome to ShadowOS!"
    echo "---------------------------------------------------"
    echo "Type 'startx' to launch the desktop."
    echo "Type 'shadow-harden' to apply security settings."
    echo "---------------------------------------------------"
    echo ""

    # Auto-dump debug info to serial console (if available)
    if [ -e /dev/ttyS0 ] && [ -w /dev/ttyS0 ]; then
        echo "Dumping debug info to COM1..."
        {
            echo "=== [ShadowOS Debug Start] ==="
            echo "--- Date ---"
            date
            echo "--- Disk Usage ---"
            df -h
            echo "--- lspci -nnk (Video) ---"
            lspci -nnk | grep -A3 VGA
            echo "--- Kernel DRM Modules ---"
            lsmod | grep -E "drm|vbox|vmw"
            echo "--- Xorg Log (tail) ---"
            tail -n 50 /var/log/Xorg.0.log 2>/dev/null
            echo "--- LightDM Log (tail) ---"
            tail -n 50 /var/log/lightdm/lightdm.log 2>/dev/null
            echo "--- LightDM X-0 Log (tail) ---"
            tail -n 50 /var/log/lightdm/x-0.log 2>/dev/null
            echo "=== [ShadowOS Debug End] ==="
        } > /dev/ttyS0 2>/dev/null
    fi
fi
PROFILE
sudo chown 1000:1000 "$ROOTFS/home/shadow/.bash_profile"

log "GRUB configured"

# =============================================================================
# CREATE ISO
# =============================================================================

log "Creating ISO..."

sudo grub-mkrescue -o "$OUTPUT" "$BUILD_DIR/iso" -- -volid SHADOWOS 2>/dev/null || \
    error "grub-mkrescue failed"

[[ -f "$OUTPUT" ]] || error "ISO not created"

SIZE=$(du -h "$OUTPUT" | cut -f1)

log ""
log "=============================================="
log " ShadowOS ISO Build Complete (Debian + systemd)"
log "=============================================="
log ""
log " Output: $OUTPUT ($SIZE)"
log ""
log " Boot modes:"
log "   - ShadowOS Live        Standard live boot"
log "   - RAM Mode             Copy to RAM, eject media"
log "   - Forensic             Read-only, no changes"
log "   - Debug                Verbose boot output"
log ""
log " Test with:"
log "   qemu-system-x86_64 -m 4G -cdrom $OUTPUT -enable-kvm"
log "=============================================="
