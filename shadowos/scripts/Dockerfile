# SPDX-License-Identifier: GPL-2.0
FROM debian:bookworm

ENV DEBIAN_FRONTEND=noninteractive

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    debootstrap \
    squashfs-tools \
    xorriso \
    grub-pc-bin \
    grub-efi-amd64-bin \
    mtools \
    dosfstools \
    sudo \
    curl \
    wget \
    ca-certificates \
    git \
    make \
    bc \
    kmod \
    cpio \
    fakeroot \
    && rm -rf /var/lib/apt/lists/*

# Create builder user to avoid root-owned files on host
# We'll allow the UID/GID to be passed at build time, default to 1000
ARG USER_ID=1000
ARG GROUP_ID=1000

RUN groupadd -g ${GROUP_ID} builder && \
    useradd -u ${USER_ID} -g builder -m builder && \
    echo "builder ALL=(ALL) NOPASSWD: ALL" > /etc/sudoers.d/builder

# Set workdir
WORKDIR /work

# Default to running the build via sudo inside container (since build script needs root privileges for debootstrap/mount)
# But we start as regular user to keep environment sane
USER builder

CMD ["./scripts/build-iso.sh"]
