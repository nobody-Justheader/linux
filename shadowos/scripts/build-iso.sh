#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# build-iso.sh - Build ShadowOS ISO (Debian + systemd based)
# Creates a Kali-like live ISO with systemd, glibc, and full compatibility
# MUST BE RUN INSIDE DOCKER CONTAINER via build-in-docker.sh
#

# Arguments
STAGE="${1:-all}"

# If running from Makefile, we might get specific flags
case "$STAGE" in
    --stage-rootfs)
        STAGE="rootfs"
        ;;
    --stage-packages)
        STAGE="packages"
        ;;
    --stage-config)
        STAGE="config"
        ;;
    --stage-iso)
        STAGE="iso"
        ;;
    *)
        STAGE="all"
        ;;
esac

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
DEBIAN_RELEASE="trixie"
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
        mountpoint -q "$rootfs/dev/pts" && sudo umount "$rootfs/dev/pts" || true
        mountpoint -q "$rootfs/dev"     && sudo umount "$rootfs/dev" || true
        mountpoint -q "$rootfs/sys"     && sudo umount "$rootfs/sys" || true
        mountpoint -q "$rootfs/proc"    && sudo umount "$rootfs/proc" || true
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
# BOOTSTRAP ROOTFS
# =============================================================================

ROOTFS="$BUILD_DIR/rootfs"

if [[ "$STAGE" == "rootfs" || "$STAGE" == "all" ]]; then
    # Create rootfs
    if [ ! -d "$ROOTFS/bin" ]; then
        echo "[shadowos] Creating Debian rootfs with debootstrap..."
        # Only install absolute minimum in debootstrap to avoid polkitd/dbus config errors
        sudo debootstrap \
            --arch=amd64 \
            --variant=minbase \
            --include=sudo,locales,console-setup,linux-image-amd64,linux-headers-amd64,build-essential,live-boot,systemd-sysv \
            trixie "$ROOTFS" http://deb.debian.org/debian/
        
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
PRETTY_NAME="ShadowOS 1.0 (Based on Debian Trixie)"
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
PRETTY_NAME="ShadowOS 1.0 (Based on Debian Trixie)"
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
# Debian Trixie (base)
deb http://deb.debian.org/debian trixie main contrib non-free non-free-firmware
deb http://deb.debian.org/debian trixie-updates main contrib non-free non-free-firmware
deb http://security.debian.org/debian-security trixie-security main contrib non-free non-free-firmware
EOF

    # Create Kali setup script (run post-install to enable Kali repos)
    log "Creating Kali repository setup script..."
    cat > "$ROOTFS/usr/bin/shadowos-kali-setup" << 'KALISETUP'
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
    chmod +x "$ROOTFS/usr/bin/shadowos-kali-setup"
    log "Kali script created successfully."
fi # End rootfs stage

if [[ "$STAGE" == "rootfs" ]]; then exit 0; fi

if [[ "$STAGE" == "packages" || "$STAGE" == "all" ]]; then
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

    # First install ca-certificates and gnupg (needed for repo setup)
    sudo chroot "$ROOTFS" apt-get update
    sudo chroot "$ROOTFS" apt-get install -y ca-certificates gnupg curl wget

    # Now add VSCodium Repository (requires ca-certificates)
    log "Adding VSCodium repo..."
    curl -fsSL https://gitlab.com/paulcarroty/vscodium-deb-rpm-repo/raw/master/pub.gpg | \
        sudo tee "$ROOTFS/usr/share/keyrings/vscodium-archive-keyring.gpg.asc" > /dev/null
    sudo chroot "$ROOTFS" gpg --batch --yes --dearmor -o /usr/share/keyrings/vscodium-archive-keyring.gpg /usr/share/keyrings/vscodium-archive-keyring.gpg.asc
    echo 'deb [signed-by=/usr/share/keyrings/vscodium-archive-keyring.gpg] https://download.vscodium.com/debs vscodium main' | \
        sudo tee "$ROOTFS/etc/apt/sources.list.d/vscodium.list" > /dev/null

    # Update with new repo
    sudo chroot "$ROOTFS" apt-get update

    # Install GUI and tools (MATE Desktop + LightDM + Kali-style themes)
    # MATE is more reliable than XFCE for panel configuration
    log "Installing MATE desktop and tools..."
    sudo chroot "$ROOTFS" apt-get install -y --no-install-recommends \
        mate-desktop-environment-core \
        mate-desktop-environment-extras \
        mate-tweak \
        lightdm lightdm-gtk-greeter lightdm-gtk-greeter-settings \
        firefox-esr caja caja-open-terminal \
        xorg xinit \
        dbus-x11 \
        network-manager-gnome \
        xserver-xorg-video-vmware xserver-xorg-video-qxl xserver-xorg-video-all \
        pciutils usbutils \
        firmware-linux firmware-linux-nonfree firmware-misc-nonfree firmware-realtek \
        git \
        pluma atril engrampa eom \
        arc-theme papirus-icon-theme \
        xtables-addons-dkms xtables-addons-common linux-headers-amd64 dkms \
        mate-terminal zsh zsh-syntax-highlighting zsh-autosuggestions \
        tor torsocks \
        python3-gi python3-gi-cairo gir1.2-gtk-3.0 python3-psutil \
        calamares calamares-settings-debian \
        live-boot live-config live-config-systemd \
        || error "GUI Package installation failed!"

    # Install VSCodium separately (from external repo)
    log "Installing VSCodium..."
    sudo chroot "$ROOTFS" apt-get install -y codium || log "Warning: VSCodium install failed, continuing..."

    # (Redundant package installation block removed)

    # Configure XFCE Autostart in SKEL (so useradd copies to user's home)
    # NOTE: All user configs go to /etc/skel first, NOT /home/shadow directly
    log "Setting up skeleton directory for new users..."
    sudo mkdir -p "$ROOTFS/etc/skel/.config/autostart"
    sudo tee "$ROOTFS/etc/skel/.config/autostart/nm-applet.desktop" > /dev/null << 'NMAPPLET'
[Desktop Entry]
Type=Application
Name=Network Manager Applet
Exec=nm-applet
Hidden=false
X-GNOME-Autostart-enabled=true
NMAPPLET

    # Create wallpaper setup autostart (MATE uses gsettings)
    sudo tee "$ROOTFS/etc/skel/.config/autostart/shadowos-wallpaper.desktop" > /dev/null << 'WALLPAPER'
[Desktop Entry]
Type=Application
Name=ShadowOS Wallpaper
Exec=/bin/bash -c "sleep 2 && gsettings set org.mate.background picture-filename '/usr/share/backgrounds/shadowos/wallpaper.png' 2>/dev/null; true"
Hidden=false
X-GNOME-Autostart-enabled=true
WALLPAPER

    # Set default shell to ZSH for future users
    log "Setting default shell to ZSH..."
    sudo chroot "$ROOTFS" sed -i 's|^SHELL=.*|SHELL=/bin/zsh|' /etc/default/useradd
    sudo chroot "$ROOTFS" sed -i 's|^DSHELL=.*|DSHELL=/bin/zsh|' /etc/adduser.conf

    # Create .zshrc in skel (will be copied to new users)
    sudo tee "$ROOTFS/etc/skel/.zshrc" > /dev/null << 'ZSHRC'
# ShadowOS .zshrc
export PATH="$HOME/.local/bin:$PATH"

# Enable Powerlevel10k-like simplified prompt
autoload -Uz promptinit
promptinit
PROMPT='%F{red}┌──(%F{cyan}%n@%m%F{red})-[%F{white}%~%F{red}]
└─%F{red}$%f '

# History
HISTFILE=~/.zsh_history
HISTSIZE=1000
SAVEHIST=1000
setopt SHARE_HISTORY

# Aliases
alias ll='ls -la'
alias la='ls -A'
alias l='ls -CF'
alias update='sudo shadowos-update'
alias tor-on='shadow-control-center --tor-on'
alias tor-off='shadow-control-center --tor-off'
alias chaos-on='shadow-control-center --chaos-on'

# Plugins (Syntax Highlighting & Autosuggestions)
source /usr/share/zsh-syntax-highlighting/zsh-syntax-highlighting.zsh 2>/dev/null || true
source /usr/share/zsh-autosuggestions/zsh-autosuggestions.zsh 2>/dev/null || true
ZSHRC

    # Install ShadowOS branding
    log "Installing ShadowOS branding..."
    sudo mkdir -p "$ROOTFS/usr/share/backgrounds/shadowos"
    if [ -f "$SHADOWOS_DIR/assets/wallpaper.png" ]; then
        sudo cp "$SHADOWOS_DIR/assets/wallpaper.png" "$ROOTFS/usr/share/backgrounds/shadowos/wallpaper.png"
    fi

    # MATE theme configuration - Arc-Dark with Papirus icons
    # MATE uses dconf/gsettings, which is more reliable than XFCE's xfconf
    log "Configuring MATE theme..."
    
    # Create dconf profile for system defaults
    sudo mkdir -p "$ROOTFS/etc/dconf/profile"
    sudo tee "$ROOTFS/etc/dconf/profile/user" > /dev/null << 'DCONFPROFILE'
user-db:user
system-db:local
DCONFPROFILE

    # Create system-wide MATE defaults
    sudo mkdir -p "$ROOTFS/etc/dconf/db/local.d"
    sudo tee "$ROOTFS/etc/dconf/db/local.d/00-shadowos" > /dev/null << 'DCONFMATE'
# ShadowOS MATE Desktop Configuration
# Arc-Dark theme with Papirus icons

[org/mate/desktop/interface]
gtk-theme='Arc-Dark'
icon-theme='Papirus-Dark'
cursor-theme='Adwaita'
font-name='DejaVu Sans 10'

[org/mate/marco/general]
theme='Arc-Dark'
compositing-manager=true

[org/mate/desktop/background]
picture-filename='/usr/share/backgrounds/shadowos/wallpaper.png'
picture-options='zoom'
primary-color='#1e1e2e'
secondary-color='#1e1e2e'

[org/mate/panel/general]
object-id-list=['menu-bar', 'window-list', 'notification-area', 'clock']
toplevel-id-list=['top']

[org/mate/panel/toplevels/top]
expand=true
orientation='bottom'
size=28
screen=0

[org/mate/terminal/profiles/default]
background-color='#1E1E2EFF'
foreground-color='#CDD6F4FF'
palette='#45475A:#F38BA8:#A6E3A1:#F9E2AF:#89B4FA:#F5C2E7:#94E2D5:#BAC2DE:#585B70:#F38BA8:#A6E3A1:#F9E2AF:#89B4FA:#F5C2E7:#94E2D5:#A6ADC8'
use-theme-colors=false
bold-color='#CDD6F4FF'
DCONFMATE

    # Compile dconf database
    log "Compiling dconf database..."
    sudo chroot "$ROOTFS" dconf update 2>/dev/null || true

    # Configure NetworkManager for Anonymity (MAC Randomization & Hostname)
    sudo tee "$ROOTFS/etc/NetworkManager/NetworkManager.conf" > /dev/null << 'NMCONF'
[main]
plugins=ifupdown,keyfile
dhcp=internal
# Anonymity: Send generic hostname
hostname-mode=none

[ifupdown]
managed=false

[device]
# Anonymity: Randomize MAC address for Wi-Fi and Ethernet
wifi.scan-rand-mac-address=yes

[connection]
# Randomize MAC for every new connection
wifi.cloned-mac-address=random
ethernet.cloned-mac-address=random
NMCONF
    sudo chmod 644 "$ROOTFS/etc/NetworkManager/NetworkManager.conf"

    # Remove duplicate apt install block (Cleanup)
    # The previous redundant block (Tools & Network) is removed/merged.

    # =============================================================================
    # REMOVE BUSYBOX (Debian Mode)
    # =============================================================================
    log "Removing BusyBox to enforce Debian Mode..."
    
    # Configure initramfs to NOT use BusyBox (Debian Mode)
    if [ -f "$ROOTFS/etc/initramfs-tools/initramfs.conf" ]; then
        sudo sed -i 's/^BUSYBOX=.*/BUSYBOX=n/' "$ROOTFS/etc/initramfs-tools/initramfs.conf"
    else
        echo "BUSYBOX=n" | sudo tee -a "$ROOTFS/etc/initramfs-tools/initramfs.conf" > /dev/null
    fi

    # NOTE: We cannot purge busybox package because live-boot depends on it.
    # Setting BUSYBOX=n ensures initramfs uses klibc-utils instead of busybox,
    # satisfying the 'Debian Mode' requirement functionally.

    # Clean apt cache
    sudo chroot "$ROOTFS" apt-get clean
    sudo rm -rf "$ROOTFS/var/lib/apt/lists/"*

    # Unmount
    sudo umount "$ROOTFS/sys" 2>/dev/null || true
    sudo umount "$ROOTFS/proc" 2>/dev/null || true
    sudo umount "$ROOTFS/dev/pts" 2>/dev/null || true
    sudo umount "$ROOTFS/dev" 2>/dev/null || true
fi # End packages stage

if [[ "$STAGE" == "config" || "$STAGE" == "all" ]]; then
    # =============================================================================
    # CONFIGURATION
    # =============================================================================

    # =============================================================================
    # PLYMOUTH THEME (Boot Logo)
    # =============================================================================
    log "Configuring Plymouth theme..."
    
    PLYMOUTH_DIR="$ROOTFS/usr/share/plymouth/themes/shadowos"
    sudo mkdir -p "$PLYMOUTH_DIR"
    
    if [ -f "$SHADOWOS_DIR/assets/boot_logo.png" ]; then
        sudo cp "$SHADOWOS_DIR/assets/boot_logo.png" "$PLYMOUTH_DIR/boot_logo.png"
    fi

    # Create .plymouth file
    sudo tee "$PLYMOUTH_DIR/shadowos.plymouth" > /dev/null << 'PLYMOUTHCONF'
[Plymouth Theme]
Name=ShadowOS
Description=ShadowOS Stealth Boot Theme
ModuleName=script

[script]
ImageDir=/usr/share/plymouth/themes/shadowos
ScriptFile=/usr/share/plymouth/themes/shadowos/shadowos.script
PLYMOUTHCONF

    # Create .script file
    sudo tee "$PLYMOUTH_DIR/shadowos.script" > /dev/null << 'PLYMOUTHSCRIPT'
Window.SetBackgroundTopColor(0.0, 0.0, 0.0);
Window.SetBackgroundBottomColor(0.0, 0.0, 0.0);

logo.image = Image("boot_logo.png");
logo.sprite = Sprite(logo.image);

logo.sprite.SetX(Window.GetWidth() / 2 - logo.image.GetWidth() / 2);
logo.sprite.SetY(Window.GetHeight() / 2 - logo.image.GetHeight() / 2);
logo.sprite.SetZ(100);
PLYMOUTHSCRIPT

    # Set as default theme
    # Note: We use chroot to run plymouth-set-default-theme
    if [ -x "$ROOTFS/usr/sbin/plymouth-set-default-theme" ]; then
        sudo chroot "$ROOTFS" plymouth-set-default-theme -R shadowos
    fi

    # MATE theme setup script (runs on first login to apply gsettings)
    log "Creating MATE theme setup script..."
    sudo tee "$ROOTFS/usr/bin/shadowos-theme-setup" > /dev/null << 'THEMESETUP'
#!/bin/bash
# ShadowOS MATE Theme Setup
# Applies Arc-Dark theme and Papirus icons on first login

MARKER="$HOME/.config/shadowos-theme-configured"

if [ -f "$MARKER" ]; then
    exit 0
fi

echo "[shadowos] Applying MATE theme configuration..."

# Wait for MATE session to be ready
sleep 3

# Apply GTK theme
gsettings set org.mate.interface gtk-theme 'Arc-Dark'
gsettings set org.mate.interface icon-theme 'Papirus-Dark'
gsettings set org.mate.interface cursor-theme 'Adwaita'
gsettings set org.mate.interface font-name 'DejaVu Sans 10'

# Apply Marco (window manager) theme
gsettings set org.mate.Marco.general theme 'Arc-Dark'
gsettings set org.mate.Marco.general compositing-manager true

# Apply wallpaper
gsettings set org.mate.background picture-filename '/usr/share/backgrounds/shadowos/wallpaper.png'
gsettings set org.mate.background picture-options 'zoom'
gsettings set org.mate.background primary-color '#1e1e2e'

# Apply MATE terminal colors (Catppuccin-inspired)
gsettings set org.mate.terminal.profile:/org/mate/terminal/profiles/default/ background-color '#1E1E2E'
gsettings set org.mate.terminal.profile:/org/mate/terminal/profiles/default/ foreground-color '#CDD6F4'
gsettings set org.mate.terminal.profile:/org/mate/terminal/profiles/default/ use-theme-colors false

# Reset MATE panel to default layout (fixes blank panel on first boot)
echo "[shadowos] Resetting MATE panel to default layout..."
mate-panel --reset &
sleep 2

# Mark as configured
mkdir -p "$(dirname "$MARKER")"
touch "$MARKER"

echo "[shadowos] MATE theme applied successfully!"
THEMESETUP
    sudo chmod +x "$ROOTFS/usr/bin/shadowos-theme-setup"

    # Create Autostart Entry for the theme setup script
    sudo mkdir -p "$ROOTFS/etc/xdg/autostart"
    sudo tee "$ROOTFS/etc/xdg/autostart/shadowos-theme-setup.desktop" > /dev/null << 'AUTOSTART'
[Desktop Entry]
Type=Application
Name=ShadowOS Theme Setup
Exec=/usr/bin/shadowos-theme-setup
Terminal=false
StartupNotify=false
Hidden=false
OnlyShowIn=MATE;
AUTOSTART

    # Configure LightDM to use MATE session
    sudo mkdir -p "$ROOTFS/etc/lightdm"
    sudo tee "$ROOTFS/etc/lightdm/lightdm.conf" > /dev/null << 'LIGHTDM'
[Seat:*]
greeter-session=lightdm-gtk-greeter
user-session=mate
LIGHTDM

    # Create .bash_profile in skel (for non-zsh fallback)
    sudo tee "$ROOTFS/etc/skel/.bash_profile" > /dev/null << 'PROFILE'
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

    # Configure GRUB with Persistence and Custom Theme
    log "Configuring GRUB..."

    # 1. Create Theme Directory
    sudo mkdir -p "$ROOTFS/boot/grub/themes/shadowos"

    # 2. Add Persistence to GRUB
    # We modify the grub.cfg generation or add a custom entry
    # For live-build/Debian ISOs, usually in boot/grub/grub.cfg or loopback.cfg
    # We'll create a robust grub.cfg that includes Persistence

    sudo tee "$ROOTFS/boot/grub/grub.cfg" > /dev/null << 'GRUBCFG'
set default=0
set timeout=10

insmod efi_gop
insmod efi_uga
insmod video_bochs
insmod video_cirrus
insmod gfxterm
insmod png

loadfont /boot/grub/themes/shadowos/terminus-16.pf2
terminal_output gfxterm

set theme=/boot/grub/themes/shadowos/theme.txt
export theme

menuentry "ShadowOS Live (Forensic Mode)" {
    linux /live/vmlinuz boot=live components quiet splash
    initrd /live/initrd.img
}

menuentry "ShadowOS Live (Persistence)" {
    linux /live/vmlinuz boot=live components quiet splash persistence
    initrd /live/initrd.img
}

menuentry "Install ShadowOS (Graphical)" {
    linux /live/vmlinuz boot=live components quiet splash
    initrd /live/initrd.img
    # In live session, user runs Calamares
}
GRUBCFG

    # Configure Calamares Installer
    log "Configuring Calamares..."
    sudo mkdir -p "$ROOTFS/etc/calamares/modules"
    sudo mkdir -p "$ROOTFS/etc/calamares/branding/shadowos"

    # Minimal branding/settings needed for functional install
    sudo tee "$ROOTFS/etc/calamares/settings.conf" > /dev/null << 'CALAMARES'
modules-search: [ local ]

instances:
- id:       user
  module:   users
  config:   users.conf

sequence:
- show:
  - welcome
  - location
  - keyboard
  - partition
  - users
  - summary
- exec:
  - partition
  - mount
  - unpackfs
  - machineid
  - fstab
  - locale
  - keyboard
  - localecfg
  - users
  - networkcfg
  - hwclock
  - services-systemd
  - grubcfg
  - bootloader
  - umount
- show:
  - finished

branding: shadowos
prompt-install: true
dont-chroot: false
oem-setup: false
disable-cancel: false
disable-cancel-during-exec: true
quit-at-end: false
CALAMARES

    # Create Desktop shortcut for installer
    sudo mkdir -p "$ROOTFS/home/shadow/Desktop"
    sudo chown 1000:1000 "$ROOTFS/home/shadow/Desktop"
    sudo tee "$ROOTFS/home/shadow/Desktop/install-shadowos.desktop" > /dev/null << 'INSTDESK'
[Desktop Entry]
Type=Application
Name=Install ShadowOS
Exec=sudo calamares
Icon=calamares
Terminal=false
INSTDESK
    sudo chmod +x "$ROOTFS/home/shadow/Desktop/install-shadowos.desktop"
    sudo chown 1000:1000 "$ROOTFS/home/shadow/Desktop/install-shadowos.desktop"

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

    # Create shadow-api (Backend for Control Center)
    sudo tee "$ROOTFS/usr/bin/shadow-api" > /dev/null << 'SHADOWAPI'
#!/usr/bin/env python3
import sys
import subprocess
import json
import os

# ShadowOS Kernel API
# Manages iptables (Netfilter), sysctl, and systemd services

def run_cmd(cmd):
    try:
        subprocess.run(cmd, shell=True, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return True
    except:
        return False

def check_service(service):
    return run_cmd(f"systemctl is-active --quiet {service}")

def check_process(name):
    return run_cmd(f"pgrep -f {name}")

def get_status():
    status = {
        "chaos_mode": False,
        "stealth_mode": False,
        "tor_mode": False,
        "polymorph": check_service("shadow-polymorph"),
        "identity": "unknown"
    }
    
    # Check Chaos Mode (iptables rule)
    if run_cmd("iptables -C INPUT -p tcp -m statistic --mode random --probability 0.33 -j DROP 2>/dev/null") or \
       run_cmd("iptables -C INPUT -j CHAOS 2>/dev/null"): # Future CHAOS check
        status["chaos_mode"] = True
        
    # Check Stealth (sysctl)
    try:
        with open("/proc/sys/net/ipv4/icmp_echo_ignore_all", "r") as f:
            if f.read().strip() == "1":
                status["stealth_mode"] = True
    except:
        pass

    # Check Identity
    try:
        with open("/etc/issue", "r") as f:
            issue = f.read().lower()
            if "windows" in issue: status["identity"] = "Windows"
            elif "ubuntu" in issue: status["identity"] = "Ubuntu"
            elif "fedora" in issue: status["identity"] = "Fedora"
            elif "arch" in issue: status["identity"] = "Arch"
            elif "cisco" in issue: status["identity"] = "Cisco"
            else: status["identity"] = "ShadowOS"
    except:
        pass

    return json.dumps(status)

def f_chaos(enable):
    if enable:
        # Use shadow-harden fuzz mode (which we will update to use CHAOS if avail)
        # For now, falls back to userspace-like netfilter rules if CHAOS module missing
        run_cmd("/usr/bin/shadow-harden fuzz")
    else:
        # Flush fuzz/chaos rules
        # Simple flush for now (Production: specific chain delete)
        run_cmd("iptables -D INPUT -p tcp -m multiport --dports 21,23,25,80,443,445,3389,8080 -m statistic --mode random --probability 0.33 -j DROP")
        run_cmd("iptables -D INPUT -p tcp -m multiport --dports 21,23,25,80,443,445,3389,8080 -m statistic --mode random --probability 0.5 -j REJECT --reject-with tcp-reset")
        run_cmd("iptables -D INPUT -p tcp -m multiport --dports 21,23,25,80,443,445,3389,8080 -j REJECT --reject-with icmp-host-prohibited")
        # Try removing CHAOS target if used
        run_cmd("iptables -D INPUT -p tcp -j CHAOS --tarpit 2>/dev/null")

def f_stealth(enable):
    if enable:
        run_cmd("/usr/bin/shadow-harden stealth")
    else:
        # Revert to standard
        run_cmd("sysctl -w net.ipv4.icmp_echo_ignore_all=0")
        run_cmd("sysctl -w net.ipv4.tcp_timestamps=1")
        run_cmd("sysctl -w net.ipv4.ip_default_ttl=64")

def f_tor(enable):
    if enable:
        # Transparent Proxy (TCP -> 9040, DNS -> 5353)
        # 1. TCP
        run_cmd("iptables -t nat -A OUTPUT -m owner --uid-owner debian-tor -j RETURN")
        run_cmd("iptables -t nat -A OUTPUT -p tcp --syn -j REDIRECT --to-ports 9040")
        # 2. DNS (UDP/TCP)
        run_cmd("iptables -t nat -A OUTPUT -m owner --uid-owner debian-tor -j RETURN")
        run_cmd("iptables -t nat -A OUTPUT -p udp --dport 53 -j REDIRECT --to-ports 5353")
        run_cmd("iptables -t nat -A OUTPUT -p tcp --dport 53 -j REDIRECT --to-ports 5353")
        # 3. Block other UDP (Leak protection)
        run_cmd("iptables -A OUTPUT -m owner --uid-owner debian-tor -j ACCEPT")
        run_cmd("iptables -A OUTPUT -p udp --dport 53 -j DROP") # Allow redirected only
        
        # Configure Tor (Ensure TransPort/DNSPort are set)
        if not os.path.exists("/etc/tor/torrc.d/shadowos.conf"):
             with open("/etc/tor/torrc.d/shadowos.conf", "w") as f:
                 f.write("TransPort 0.0.0.0:9040\nDNSPort 0.0.0.0:5353\nAutomapHostsOnResolve 1\n")
        run_cmd("systemctl restart tor")
    else:
        # Flush Tor NAT rules
        run_cmd("iptables -t nat -F OUTPUT")
        # Allow UDP again
        run_cmd("iptables -D OUTPUT -p udp --dport 53 -j DROP 2>/dev/null")

def f_polymorph(enable):
    if enable:
        run_cmd("systemctl start shadow-polymorph")
        run_cmd("systemctl enable shadow-polymorph")
    else:
        run_cmd("systemctl stop shadow-polymorph")
        run_cmd("systemctl disable shadow-polymorph")

def f_rotate(identity):
    # Manual rotation wrapper around shadow-harden logic
    # We can invoke specific rotation via env var or arg in future
    # For now, just trigger random rotation
    run_cmd("/usr/bin/shadow-harden rotate")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(get_status())
        sys.exit(0)
    
    cmd = sys.argv[1]
    
    if cmd == "status":
        print(get_status())
    elif cmd == "chaos":
        f_chaos(sys.argv[2] == "on")
    elif cmd == "stealth":
        f_stealth(sys.argv[2] == "on")
    elif cmd == "tor":
        f_tor(sys.argv[2] == "on")
    elif cmd == "polymorph":
        f_polymorph(sys.argv[2] == "on")
    elif cmd == "rotate":
        f_rotate(sys.argv[2] if len(sys.argv) > 2 else None)
    else:
        print("Unknown command")
SHADOWAPI
    sudo chmod +x "$ROOTFS/usr/bin/shadow-api"
    # =============================================================================
    # INSTALL REPOSITORY TOOLS (shadow-toolkit, shadow-recon, etc.)
    # =============================================================================
    echo "[shadowos] Installing repository tools..."
    if [ -d "usr/bin" ]; then
        sudo cp -r usr/bin/* "$ROOTFS/usr/bin/"
        # Use find to only chmod files that exist, avoiding dangling symlink errors
        sudo find "$ROOTFS/usr/bin" -type f -exec chmod +x {} +
    fi

    # =============================================================================
    # COMPILE & INSTALL SHADOWOS KERNEL MODULES
    # =============================================================================
    if [ -d "kernel/src" ]; then
        echo "[shadowos] Preparing ShadowOS kernel modules..."
        # Copy kernel source to rootfs
        sudo mkdir -p "$ROOTFS/usr/src/shadowos-modules"
        sudo cp -r kernel/src/* "$ROOTFS/usr/src/shadowos-modules/"
        
        # Create a build script to run inside chroot
        sudo tee "$ROOTFS/usr/src/shadowos-modules/build-modules.sh" > /dev/null << 'BUILDSCRIPT'
#!/bin/bash
set -e

# Find kernel headers
KVER=$(ls /lib/modules | sort -V | tail -n1)
KDIR="/lib/modules/$KVER/build"

echo "[shadowos-build] compiling modules for kernel $KVER"

# Create top-level Makefile
cat > Makefile << 'EOF'
obj-m += net/shadowos/
obj-m += security/shadowos/

ccflags-y := -I$(src)/include

all:
	make -C KERNEL_DIR M=$(PWD) modules

install:
	make -C KERNEL_DIR M=$(PWD) modules_install
EOF

# Fix KDIR in Makefile
sed -i "s|KERNEL_DIR|$KDIR|g" Makefile

# Create subdirectory Makefiles to include all object files
for dir in net/shadowos security/shadowos; do
    echo "[shadowos-build] Generating Makefile for $dir"
    # Create Makefile that adds all .c files as objects
    # We use wildcard to find them, then convert .c to .o
    # Note: This runs in make, so we use make syntax
    cat > "$dir/Makefile" << 'SUBMAKE'
# Force build all files in this directory as a single module or individual modules?
# We want individual modules for granular control

# Convert all .c files to .o
src_files := $(wildcard $(src)/*.c)
obj_files := $(src_files:$(src)/%.c=%.o)

# define modules
obj-m := $(obj_files)

ccflags-y := -I$(src)/../../include
SUBMAKE
done

# Compile
echo "[shadowos-build] Starting compilation..."
make

# Install
echo "[shadowos-build] Installing modules..."
make install
depmod -a "$KVER"

echo "[shadowos-build] Module build complete."
BUILDSCRIPT

        sudo chmod +x "$ROOTFS/usr/src/shadowos-modules/build-modules.sh"
        
        # Run compilation in chroot
        echo "[shadowos] Running module compilation in rootfs..."
        # We need to bind mount /dev /sys /proc for some build tools? usually not needed for pure make but good practice
        # build-iso.sh might already have them mounted? No, early cleanup.
        # But we are inside the main build loop, so mounts might be active if we are careful.
        # Actually build-iso.sh doesn't mount them for the main phase? 
        # Let's just run chroot. debootstrap doesn't leave mounts active.
        
        sudo chroot "$ROOTFS" /bin/bash -c "cd /usr/src/shadowos-modules && ./build-modules.sh"
        
        # Create modules-load.d configuration to auto-load modules at boot
        echo "[shadowos] Creating module auto-load configuration..."
        sudo mkdir -p "$ROOTFS/etc/modules-load.d"
        sudo tee "$ROOTFS/etc/modules-load.d/shadowos.conf" > /dev/null << 'MODCONF'
# ShadowOS Security Modules - Auto-load at boot
# Core modules
shadow_core

# Network defense modules
shadow_detect
shadow_chaos
shadow_frustrate
shadow_dns
shadow_geo
shadow_fprint
shadow_mac
shadow_promisc
shadow_inject
shadow_mtd
shadow_flux
shadow_phantom
shadow_decoy

# Security modules
shadow_cloak
shadow_debug
shadow_defcon
shadow_deny
shadow_duress
shadow_escalate
shadow_honey
shadow_keylog
shadow_layers
shadow_lsm
shadow_memcrypt
shadow_osint
shadow_panic
shadow_persona
shadow_phish
shadow_profile
shadow_proto
shadow_ram
shadow_rootkit
shadow_shred
shadow_sign
shadow_stego
shadow_synth
shadow_syscall
shadow_tamper
shadow_timelock

# Hardware protection
shadow_usb
shadow_av
shadow_dma
shadow_bt

# Anti-forensics
shadow_deadman
shadow_coldboot
shadow_meta
shadow_attrib
shadow_classify
shadow_evidence
shadow_exfil
shadow_infinite
shadow_beacon
shadow_lookalike
MODCONF

        # Create systemd service for loading modules (in case modules-load.d doesn't work)
        sudo tee "$ROOTFS/etc/systemd/system/shadowos-modules.service" > /dev/null << 'SVCFILE'
[Unit]
Description=ShadowOS Kernel Modules Loader
After=systemd-modules-load.service
Before=network.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/bash -c 'for mod in /lib/modules/$(uname -r)/updates/*/shadowos/*.ko.xz; do modprobe $(basename "$mod" .ko.xz) 2>/dev/null || true; done'

[Install]
WantedBy=multi-user.target
SVCFILE

        sudo chroot "$ROOTFS" systemctl enable shadowos-modules.service 2>/dev/null || true
    else
        echo "[warning] kernel/src not found! Skipping module build."
    fi

    # =============================================================================
    # COMPILE & INSTALL LIBSHADOW (REQUIRED DEPENDENCY)
    # =============================================================================
    echo "[shadowos] Compiling libshadow..."
    if [ -d "userspace/libshadow" ]; then
        # Copy sources to chroot and compile there (gcc is in chroot, not in container)
        sudo mkdir -p "$ROOTFS/tmp/libshadow"
        sudo cp userspace/libshadow/* "$ROOTFS/tmp/libshadow/"
        
        sudo chroot "$ROOTFS" /bin/bash -c "
            cd /tmp/libshadow
            make clean 2>/dev/null || true
            make
        "
        
        # Install library
        sudo cp "$ROOTFS/tmp/libshadow/libshadow.so" "$ROOTFS/usr/lib/"
        sudo cp "$ROOTFS/tmp/libshadow/shadow.h" "$ROOTFS/usr/include/"
        sudo rm -rf "$ROOTFS/tmp/libshadow"
        sudo ldconfig -r "$ROOTFS" || true
    else
        echo "[warning] userspace/libshadow not found!"
    fi

    # =============================================================================
    # INSTALL SHADOW DASHBOARD
    # =============================================================================
    echo "[shadowos] Installing Shadow Dashboard..."
    if [ -d "userspace/shadow-dashboard" ]; then
        sudo mkdir -p "$ROOTFS/usr/share/shadow-dashboard"
        sudo cp -r userspace/shadow-dashboard/* "$ROOTFS/usr/share/shadow-dashboard/"
        
        # Wrapper
        sudo tee "$ROOTFS/usr/bin/shadow-dashboard" > /dev/null << 'WRAPPER'
#!/bin/sh
cd /usr/share/shadow-dashboard
exec python3 shadow_dashboard.py "$@"
WRAPPER
        sudo chmod +x "$ROOTFS/usr/bin/shadow-dashboard"
        
        # Desktop Entry
        sudo tee "$ROOTFS/usr/share/applications/shadow-dashboard.desktop" > /dev/null << 'DESKTOP'
[Desktop Entry]
Version=1.0
Type=Application
Name=Shadow Dashboard
Comment=Threat Intelligence Dashboard
Exec=shadow-dashboard
Icon=utilities-system-monitor
Categories=ShadowOS;System;Monitor;
Terminal=false
DESKTOP
    fi

    # =============================================================================
    # INSTALL SHADOW ALERT DAEMON
    # =============================================================================
    echo "[shadowos] Installing Shadow Alert Daemon..."
    if [ -d "userspace/shadow-alertd" ]; then
        sudo mkdir -p "$ROOTFS/usr/share/shadow-alertd"
        sudo cp -r userspace/shadow-alertd/* "$ROOTFS/usr/share/shadow-alertd/"
        
        # Service wrapper or just binary
        sudo tee "$ROOTFS/usr/bin/shadow-alertd" > /dev/null << 'WRAPPER'
#!/bin/sh
cd /usr/share/shadow-alertd
exec python3 shadow_alertd.py "$@"
WRAPPER
        sudo chmod +x "$ROOTFS/usr/bin/shadow-alertd"
    fi

    # =============================================================================
    # INSTALL SHADOW CONTROL CENTER
    # =============================================================================
    # Install Shadow Control Center from userspace
    echo "[shadowos] Installing Shadow Control Center..."
    sudo mkdir -p "$ROOTFS/usr/share/shadow-control-center"
    sudo cp -r userspace/shadow-control-center/* "$ROOTFS/usr/share/shadow-control-center/"
    
    # Create executable wrapper
    sudo tee "$ROOTFS/usr/bin/shadow-control-center" > /dev/null << 'WRAPPER'
#!/bin/sh
cd /usr/share/shadow-control-center
exec python3 shadow_control.py "$@"
WRAPPER
    sudo chmod +x "$ROOTFS/usr/bin/shadow-control-center"

    # Create Desktop Entry for Control Center
    sudo tee "$ROOTFS/usr/share/applications/shadow-control.desktop" > /dev/null << 'DESKTOP'
[Desktop Entry]
Version=1.0
Type=Application
Name=Shadow Control Center
Comment=Manage Active Defense and Anonymity
Exec=sudo shadow-control-center
Icon=security-high
Categories=ShadowOS;System;Security;
Terminal=false
DESKTOP
    sudo chmod +x "$ROOTFS/usr/share/applications/shadow-control.desktop"

    # Create Desktop Entries for ShadowOS Utilities
    log "Creating ShadowOS menu entries..."

    # Create ShadowOS menu category
    sudo mkdir -p "$ROOTFS/usr/share/desktop-directories"
    sudo tee "$ROOTFS/usr/share/desktop-directories/shadowos.directory" > /dev/null << 'MENUDIR'
[Desktop Entry]
Version=1.0
Type=Directory
Name=ShadowOS
Comment=ShadowOS Security Tools
Icon=security-high
MENUDIR

    # Shadow Harden
    sudo tee "$ROOTFS/usr/share/applications/shadow-harden.desktop" > /dev/null << 'HARDENDESK'
[Desktop Entry]
Version=1.0
Type=Application
Name=Shadow Harden
Comment=Security Hardening & Stealth Mode
Exec=mate-terminal -e "sudo shadow-harden"
Icon=security-high
Categories=ShadowOS;System;Security;
Terminal=false
HARDENDESK

    # Shadow Stealth
    sudo tee "$ROOTFS/usr/share/applications/shadow-stealth.desktop" > /dev/null << 'STEALTHDESK'
[Desktop Entry]
Version=1.0
Type=Application
Name=Shadow Stealth
Comment=MAC & Hostname Spoofing
Exec=mate-terminal -e "sudo shadow-stealth"
Icon=network-wireless
Categories=ShadowOS;Network;Security;
Terminal=false
STEALTHDESK

    # Shadow Tor
    sudo tee "$ROOTFS/usr/share/applications/shadow-tor.desktop" > /dev/null << 'TORDESK'
[Desktop Entry]
Version=1.0
Type=Application
Name=Shadow Tor
Comment=Tor Network Management
Exec=mate-terminal -e "sudo shadow-tor"
Icon=preferences-system-network
Categories=ShadowOS;Network;Security;
Terminal=false
TORDESK

    # Shadow Recon
    sudo tee "$ROOTFS/usr/share/applications/shadow-recon.desktop" > /dev/null << 'RECONDESK'
[Desktop Entry]
Version=1.0
Type=Application
Name=Shadow Recon
Comment=Network Reconnaissance
Exec=mate-terminal -e "shadow-recon"
Icon=network-server
Categories=ShadowOS;Network;Security;
Terminal=false
RECONDESK

    # Shadow Scan
    sudo tee "$ROOTFS/usr/share/applications/shadow-scan.desktop" > /dev/null << 'SCANDESK'
[Desktop Entry]
Version=1.0
Type=Application
Name=Shadow Scan
Comment=Network Scanner
Exec=mate-terminal -e "shadow-scan"
Icon=network-workgroup
Categories=ShadowOS;Network;Security;
Terminal=false
SCANDESK

    # Shadow WiFi
    sudo tee "$ROOTFS/usr/share/applications/shadow-wifi.desktop" > /dev/null << 'WIFIDESK'
[Desktop Entry]
Version=1.0
Type=Application
Name=Shadow WiFi
Comment=WiFi Attack Tools
Exec=mate-terminal -e "sudo shadow-wifi"
Icon=network-wireless
Categories=ShadowOS;Network;Security;
Terminal=false
WIFIDESK

    # Shadow Toolkit
    sudo tee "$ROOTFS/usr/share/applications/shadow-toolkit.desktop" > /dev/null << 'TOOLKITDESK'
[Desktop Entry]
Version=1.0
Type=Application
Name=Shadow Toolkit
Comment=Security Toolkit Manager
Exec=mate-terminal -e "shadow-toolkit"
Icon=applications-system
Categories=ShadowOS;System;Security;
Terminal=false
TOOLKITDESK

    # Secure Delete
    sudo tee "$ROOTFS/usr/share/applications/sdelete.desktop" > /dev/null << 'SDELETEDESK'
[Desktop Entry]
Version=1.0
Type=Application
Name=Secure Delete
Comment=Anti-forensic File Deletion
Exec=mate-terminal -e "sdelete --help"
Icon=edit-delete
Categories=ShadowOS;System;Security;
Terminal=false
SDELETEDESK

    # Update desktop and icon caches (like Kali/modern distros)
    log "Updating desktop and icon caches..."
    sudo chroot "$ROOTFS" update-desktop-database /usr/share/applications 2>/dev/null || true
    sudo chroot "$ROOTFS" gtk-update-icon-cache -f /usr/share/icons/hicolor 2>/dev/null || true
    sudo chroot "$ROOTFS" gtk-update-icon-cache -f /usr/share/icons/Papirus-Dark 2>/dev/null || true

    # Remove Debian branding from menu
    log "Removing Debian branding..."
    sudo rm -f "$ROOTFS/usr/share/applications/debian-*" 2>/dev/null || true
    sudo rm -f "$ROOTFS/usr/share/desktop-directories/Debian*.directory" 2>/dev/null || true
    sudo tee "$ROOTFS/usr/bin/shadow-harden" > /dev/null << 'HARDEN'
#!/bin/bash
# ShadowOS Security Hardening & Network Deception
# For physical penetration testing - evade network detection and EDRs

MODE="${1:-full}"

echo "=============================================="
echo "   ShadowOS Security Hardening & Stealth"
echo "=============================================="
echo ""

# Helper to check if rule exists
iptables_exists() {
    iptables -C "$@" 2>/dev/null
}

case "$MODE" in
    full|all)
        # Run all hardening
        $0 kernel
        $0 network
        $0 stealth
        $0 fuzz
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
    fuzz)
        echo "[shadowos] Activating Kernel-Level Network Fuzzing (CHAOS)..."
        
        # Load xt_CHAOS module if available
        modprobe xt_CHAOS 2>/dev/null || true
        
        PORTS="21,23,25,80,443,445,3389,8080"
        
        # Check if CHAOS target is supported
        if iptables -m chaos --help >/dev/null 2>&1; then
            echo "[fuzz] Using xt_CHAOS kernel module (Tarpit/Delude)"
            if ! iptables_exists -A INPUT -p tcp -m multiport --dports $PORTS -j CHAOS --tarpit; then
                iptables -A INPUT -p tcp -m multiport --dports $PORTS -j CHAOS --tarpit
            fi
        else
            echo "[fuzz] xt_CHAOS not found/loaded. Falling back to statistic-based fuzzing."
            # Fallback: Statistic Based
            if ! iptables_exists -A INPUT -p tcp -m multiport --dports $PORTS -m statistic --mode random --probability 0.33 -j DROP; then
                iptables -A INPUT -p tcp -m multiport --dports $PORTS -m statistic --mode random --probability 0.33 -j DROP
            fi
            if ! iptables_exists -A INPUT -p tcp -m multiport --dports $PORTS -m statistic --mode random --probability 0.5 -j REJECT --reject-with tcp-reset; then
                iptables -A INPUT -p tcp -m multiport --dports $PORTS -m statistic --mode random --probability 0.5 -j REJECT --reject-with tcp-reset
            fi
            if ! iptables_exists -A INPUT -p tcp -m multiport --dports $PORTS -j REJECT --reject-with icmp-host-prohibited; then
                 iptables -A INPUT -p tcp -m multiport --dports $PORTS -j REJECT --reject-with icmp-host-prohibited
            fi
        fi

        echo "[shadowos] Network Fuzzing Active on ports: $PORTS"
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
        # Ensure fuzzer is running initially
        $0 fuzz
        
        while true; do
            $0 rotate
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
fi # End config stage

if [[ "$STAGE" == "iso" || "$STAGE" == "all" ]]; then
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

// Automatically refresh menu and icon caches after package installs (like Kali)
DPkg::Post-Invoke { "if [ -x /usr/bin/update-desktop-database ]; then update-desktop-database -q /usr/share/applications 2>/dev/null || true; fi"; };
DPkg::Post-Invoke { "if [ -x /usr/bin/gtk-update-icon-cache ]; then gtk-update-icon-cache -f -q /usr/share/icons/hicolor 2>/dev/null || true; fi"; };
APTHOOK

    # =============================================================================
    # GENERATE INITRAMFS
    # =============================================================================

    log "Generating initramfs..."

    # Create initramfs hook to ensure busybox utilities are available
    # Live-boot requires sed, tr, grep, etc. for filesystem detection
    sudo mkdir -p "$ROOTFS/etc/initramfs-tools/hooks"
    sudo tee "$ROOTFS/etc/initramfs-tools/hooks/live-busybox" > /dev/null << 'BUSYBOX_HOOK'
#!/bin/sh
PREREQ=""
prereqs() { echo "$PREREQ"; }
case "$1" in
    prereqs) prereqs; exit 0;;
esac

. /usr/share/initramfs-tools/hook-functions

# Ensure busybox is copied first
copy_exec /bin/busybox /bin

# Copy coreutils and essential utilities that live-boot needs
for bin in /bin/sed /usr/bin/tr /bin/grep /bin/egrep /bin/fgrep \
           /bin/cat /bin/ls /bin/mount /bin/umount /bin/mkdir /bin/rmdir \
           /bin/cp /bin/mv /bin/rm /bin/ln /bin/chmod /bin/chown \
           /bin/dd /bin/df /bin/touch /bin/date /bin/sleep /bin/sync \
           /usr/bin/find /usr/bin/basename /usr/bin/dirname /usr/bin/id \
           /usr/bin/cut /usr/bin/head /usr/bin/tail /usr/bin/wc \
           /usr/bin/sort /usr/bin/uniq /usr/bin/tee /usr/bin/xargs \
           /usr/bin/expr /usr/bin/test /usr/bin/stat /usr/bin/readlink \
           /usr/bin/realpath /usr/bin/env /usr/bin/printf /usr/bin/seq \
           /sbin/losetup /sbin/blkid /sbin/blockdev; do
    if [ -e "$bin" ]; then
        copy_exec "$bin" "$(dirname $bin)" 2>/dev/null || true
    fi
done

# Create busybox symlinks for all common utilities
# This ensures utilities are available even if copy_exec fails
for util in sed tr grep egrep fgrep cat ls mount umount mkdir rmdir \
            cp mv rm ln chmod chown dd df touch date sleep sync \
            find basename dirname id cut head tail wc sort uniq tee \
            xargs expr test stat readlink realpath env printf seq \
            awk sh ash echo true false yes pwd whoami uname hostname \
            losetup blkid blockdev modprobe insmod depmod; do
    if [ ! -e "${DESTDIR}/bin/$util" ]; then
        ln -sf busybox "${DESTDIR}/bin/$util" 2>/dev/null || true
    fi
    if [ ! -e "${DESTDIR}/sbin/$util" ]; then
        ln -sf ../bin/busybox "${DESTDIR}/sbin/$util" 2>/dev/null || true
    fi
done
BUSYBOX_HOOK
    sudo chmod +x "$ROOTFS/etc/initramfs-tools/hooks/live-busybox"

    # Mount for chroot
    sudo mount --bind /dev "$ROOTFS/dev" || true
    sudo mount --bind /dev/pts "$ROOTFS/dev/pts" || true
    sudo mount -t proc proc "$ROOTFS/proc" || true
    sudo mount -t sysfs sysfs "$ROOTFS/sys" || true

    # Update initramfs with live-boot (Critical step)
    log "Regenerating initramfs..."
    sudo chroot "$ROOTFS" update-initramfs -u -k all || error "Failed to regenerate initramfs"

    # Copy kernel and initramfs to ISO
    # Copy kernel and initramfs to ISO
    # Filter for kernels that actually exist in /boot (ignoring host kernel artifacts in /lib/modules)
    KERNEL_VER=""
    for kver in $(ls "$ROOTFS/lib/modules/" | sort -V -r); do
        if [ -f "$ROOTFS/boot/vmlinuz-$kver" ]; then
            KERNEL_VER="$kver"
            break
        fi
    done

    if [[ -n "$KERNEL_VER" ]]; then
        log "Using kernel $KERNEL_VER"
        if [[ ! -d "$BUILD_DIR/iso/boot" ]]; then mkdir -p "$BUILD_DIR/iso/boot"; fi
        sudo cp "$ROOTFS/boot/vmlinuz-$KERNEL_VER" "$BUILD_DIR/iso/boot/vmlinuz"
        sudo cp "$ROOTFS/boot/initrd.img-$KERNEL_VER" "$BUILD_DIR/iso/boot/initrd.img"
    else
        error "No valid kernel found in rootfs (checked /lib/modules against /boot/vmlinuz-*)"
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
# Serial console for debugging - initialize FIRST
insmod serial
serial --speed=115200 --unit=0 --word=8 --parity=no --stop=1

# Start with console terminal (guaranteed to work in BIOS mode)
terminal_input console serial
terminal_output console serial

set timeout=5
set default=0

# Try to load graphics modules (optional, non-fatal)
insmod all_video
insmod gfxterm
insmod png
insmod jpeg

# Try graphics mode only on EFI (more reliable there)
if [ "\$grub_platform" = "efi" ]; then
    set gfxmode=1024x768,auto
    set gfxpayload=keep
    if loadfont /boot/grub/fonts/unicode.pf2; then
        terminal_output gfxterm
    fi
fi

# Load background image if in graphics mode
if [ -f /boot/grub/shadowos-logo.png ]; then
    background_image -m stretch /boot/grub/shadowos-logo.png
fi

menuentry "ShadowOS Live" {
    linux /boot/vmlinuz boot=live components $QUIET_OPTS console=tty0 console=ttyS0,115200n8
    initrd /boot/initrd.img
}

menuentry "ShadowOS Live (Safe Graphics - nomodeset)" {
    linux /boot/vmlinuz boot=live components nomodeset $QUIET_OPTS console=tty0 console=ttyS0,115200n8
    initrd /boot/initrd.img
}

menuentry "ShadowOS Live (Debug)" {
    linux /boot/vmlinuz boot=live components debug console=tty0 console=ttyS0,115200n8
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
fi
