ShadowOS - Privacy-Focused Penetration Testing Distribution
===========================================================

ShadowOS is a security-hardened Linux distribution integrated into the
kernel build system. It provides hidden boot, anti-forensic features,
network stealth, and penetration testing capabilities.

Building ShadowOS
-----------------

1. Configure the kernel with ShadowOS support:

   make menuconfig
   # Enable: ShadowOS Privacy Distribution
   # Or use the defconfig:
   make shadowos_defconfig

2. Build the kernel:

   make -j$(nproc)

3. Build a bootable ISO:

   make shadowos-iso

4. Create a USB drive:

   make shadowos-usb DEVICE=/dev/sdX

Configuration Options
---------------------

CONFIG_SHADOWOS
  Enable ShadowOS privacy distribution features.

CONFIG_SHADOWOS_HIDDEN_BOOT
  Support for hidden encrypted boot partitions with detached LUKS headers.
  At boot, press 'h' at GRUB to access the hidden system.

CONFIG_SHADOWOS_ANTI_FORENSIC
  Anti-forensic features including:
  - scopy: Secure copy (strips metadata, no timestamps)
  - smove: Secure move (securely deletes source)
  - sdelete: 7-pass secure deletion
  - sscrub: Metadata scrubbing
  - smount/sumount: Journal-free mounting

CONFIG_SHADOWOS_STEALTH_NETWORK
  Network stealth features:
  - Automatic MAC address randomization
  - Hostname spoofing with 40+ device profiles
  - Appear as printers, phones, gaming consoles, etc.

CONFIG_SHADOWOS_HARDENING
  Mandatory privacy hardening applied at boot:
  - Kernel sysctl hardening
  - Swap disabled (cold boot prevention)
  - Core dumps disabled
  - Shell history disabled
  - Firewall default deny

CONFIG_SHADOWOS_KALI_TOOLS
  Integration with Kali Linux repositories for security tools.
  Select preset: MINIMAL (~500MB), STANDARD (~2GB), or FULL (~15GB).

Runtime Commands
----------------

After booting ShadowOS, the following commands are available:

Network Stealth:
  shadow-stealth randomize   - Randomize MAC and hostname
  shadow-stealth profile HP  - Appear as HP printer

WiFi:
  shadow-wifi scan           - Scan networks
  shadow-wifi status         - Show connection status

TOR:
  shadow-tor start           - Start TOR
  shadow-tor newid           - New identity

VPN:
  shadow-vpn up              - Connect WireGuard VPN

Pentesting:
  shadow-scan fast <target>  - Quick port scan
  shadow-capture start       - Start packet capture
  shadow-crack wifi <file>   - Crack WiFi capture
  shadow-recon domain <dom>  - Domain reconnaissance

System:
  shadow-workspace create    - Create RAM workspace
  shadow-harden all          - Apply privacy hardening
  shadow-toolkit install     - Install tool categories

Boot Behavior
-------------

ShadowOS automatically detects the installation media and boots in the
most secure mode:

USB Drive with encryption:
  - Prompts for hidden volume password
  - Boots fully encrypted system
  - All privacy hardening applied

ISO/Live media:
  - RAM-only mode (toram)
  - Nothing written to disk
  - All data lost on shutdown

No manual mode selection - security is mandatory.

File Aliases
------------

Standard commands are aliased to secure versions:
  cp  -> scopy (strips metadata)
  mv  -> smove (secure source deletion)
  rm  -> sdelete (7-pass overwrite)

Use backslash to access originals: \cp, \mv, \rm

Files
-----

shadowos/
├── Kconfig              - Kernel configuration options
├── Makefile             - Build rules (iso, usb, install)
├── scripts/
│   ├── build-iso.sh     - ISO builder
│   └── create-usb.sh    - USB creator
├── usr/bin/             - Runtime tools
└── etc/                 - Configuration files

kernel/configs/
├── privacy.config       - x86_64 privacy kernel config
├── privacy_arm64.config - ARM64 privacy kernel config
└── privacy_riscv.config - RISC-V privacy kernel config

arch/x86/configs/
└── shadowos_defconfig   - Complete ShadowOS kernel config
