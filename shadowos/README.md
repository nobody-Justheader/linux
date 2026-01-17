# ShadowOS

A privacy-focused, security-hardened Linux distribution built on Debian Bookworm, designed for penetration testing and anonymous operations.

## Features

### 🛡️ Active Defense System
- **Chaos Fuzzing** - Kernel-level iptables rules that randomly DROP/REJECT/TARPIT traffic
- **Stealth Mode** - TTL=128 (Windows-like), disabled TCP timestamps, ICMP blocking
- **Polymorphic Identity** - Rotates `/etc/os-release` and `/etc/issue` every 60s to appear as Ubuntu, Fedora, Windows, Cisco, etc.

### 🔒 Privacy & Security
- Hidden encrypted boot partition support
- Anti-forensic file operations (secure deletion, metadata scrubbing)
- MAC address and hostname randomization
- Automatic kernel hardening at boot
- RAM-only workspace option

### 🖥️ Desktop Environment
- XFCE4 with LightDM display manager
- Arc-Dark theme + Papirus-Dark icons (Kali-inspired)
- Whisker Menu with custom panel layout
- Terminator terminal + ZSH with syntax highlighting

### 🛠️ Included Tools

| Tool | Description |
|------|-------------|
| `shadow-harden` | Kernel hardening, TTL spoofing, ICMP blocking |
| `shadow-stealth` | MAC/hostname spoofing with 50+ device profiles |
| `shadow-tor` | Transparent Tor proxy setup |
| `shadow-wifi` | WiFi attack utilities |
| `shadow-recon` | Network reconnaissance |
| `shadow-scan` | Network scanning |
| `shadow-crack` | Password cracking utilities |
| `shadow-exploit` | Exploitation framework integration |
| `sdelete` / `sscrub` | Anti-forensic secure deletion |
| `scopy` / `smove` | Secure file operations |
| `shadow-control-center` | GTK3 GUI for managing all features |

### 🔧 Kali Integration
After first boot, run `shadowos-kali-setup` to add Kali repositories for additional security tools.

---

## Building

### Prerequisites
- Docker
- 4GB+ free disk space
- Linux host (tested on Ubuntu/Debian)

### Quick Build
```bash
cd shadowos
./scripts/build-in-docker.sh
```

This will:
1. Build a Docker container with build dependencies
2. Run the build inside the container
3. Output `shadowos.iso` in the `output/` directory

### Incremental Builds
The Makefile supports incremental builds:

```bash
# Full build
make iso

# Individual stages
make rootfs     # Bootstrap Debian base (cached)
make packages   # Install packages (cached)
make config     # Apply configuration (always runs)
make iso        # Generate ISO

# Clean build
make clean
```

### Build Options
```bash
./scripts/build-iso.sh --help

Options:
  --output PATH   Output ISO path (default: shadowos.iso)
  --clean         Clean build directory before building
  --debug         Build with debug boot options
```

---

## Testing

### QEMU
```bash
qemu-system-x86_64 -m 4G -cdrom shadowos.iso -enable-kvm
```

### VirtualBox
1. Create new VM (Debian 64-bit)
2. Attach `shadowos.iso` as optical drive
3. Enable EFI if needed
4. Boot

### VMware
1. Create new VM
2. Use "Other Linux 5.x kernel 64-bit"
3. Attach ISO and boot

---

## Boot Modes

| Mode | Description |
|------|-------------|
| **ShadowOS Live** | Standard live boot |
| **Safe Graphics** | Use `nomodeset` for compatibility |
| **Debug** | Verbose boot output + serial console |

---

## Usage

### Control Center
Launch the GUI control panel:
```bash
shadow-control-center
```

### Stealth Mode
Disguise your system as different devices:
```bash
# Random device identity
sudo shadow-stealth randomize wlan0

# Appear as specific device
sudo shadow-stealth device hp_printer
sudo shadow-stealth device apple_iphone
sudo shadow-stealth device cisco

# Restore original
sudo shadow-stealth restore
```

### Security Hardening
```bash
# Full hardening
sudo shadow-harden full

# Individual modes
sudo shadow-harden kernel    # Kernel hardening
sudo shadow-harden network   # Network hardening
sudo shadow-harden stealth   # Stealth mode (TTL=128, no ICMP)
sudo shadow-harden fuzz      # Chaos traffic fuzzing
sudo shadow-harden rotate    # Rotate identity
sudo shadow-harden daemon    # Start polymorphic daemon

# OS Presets
sudo shadow-harden windows   # Look like Windows
sudo shadow-harden linux     # Revert to Linux
```

---

## Configuration

### Kconfig Options
Edit `Kconfig` to customize the build:

| Option | Description |
|--------|-------------|
| `SHADOWOS_HIDDEN_BOOT` | Hidden encrypted boot partition |
| `SHADOWOS_ANTI_FORENSIC` | Secure deletion, no journals |
| `SHADOWOS_STEALTH_NETWORK` | MAC randomization, hostname spoofing |
| `SHADOWOS_HARDENING` | Mandatory security hardening |
| `SHADOWOS_DESKTOP` | XFCE desktop environment |
| `SHADOWOS_KALI_TOOLS` | Kali repository integration |
| `SHADOWOS_RAM_ONLY` | Boot entirely to RAM |

### Sysctl Hardening
Default hardening is applied via `/etc/sysctl.d/99-shadowos.conf`:
- Core dump protection
- Kernel info restriction
- Full ASLR
- ICMP stealth
- Network hardening
- Memory protection

---

## License

GPL-2.0 - See [COPYING](../COPYING)

---

## Credits

Built with ❤️ for the security community.
