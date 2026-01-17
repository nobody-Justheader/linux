---
description: How to build the ShadowOS ISO image
---

# Building ShadowOS

This workflow describes how to build the ShadowOS ISO image.

## Prerequisites

- Docker installed and running
- At least 4GB free disk space
- Linux host system

## Build Steps

### 1. Navigate to ShadowOS directory

```bash
cd /home/deadlock/Documents/linux/shadowos
```

### 2. Run the Docker build (recommended)

```bash
./scripts/build-in-docker.sh
```

This will:
- Build the Docker builder image (if not exists)
- Run the full build inside the container
- Output `shadowos.iso` to the current directory

### 3. Alternative: Incremental build with Make

If you need to rebuild specific stages:

```bash
# Rebuild only config and ISO (reuses cached rootfs and packages)
make config iso

# Full clean rebuild
make clean
make iso
```

### 4. Test the ISO

```bash
qemu-system-x86_64 -m 4G -cdrom shadowos.iso -enable-kvm
```

## Build Stages

| Stage | Command | Description | Cached? |
|-------|---------|-------------|---------|
| rootfs | `make rootfs` | Bootstrap Debian base | Yes |
| packages | `make packages` | Install XFCE, tools | Yes |
| config | `make config` | Apply ShadowOS configs | No |
| iso | `make iso` | Generate ISO | No |

## Troubleshooting

### Docker permission denied
```bash
sudo usermod -aG docker $USER
# Then log out and back in
```

### Out of disk space
```bash
make clean
docker system prune -a
```

### Build fails at packages stage
Check network connectivity - the build downloads packages from Debian and VSCodium repos.
