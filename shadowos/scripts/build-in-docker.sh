#!/bin/bash
# Wrapper to run build-iso.sh inside Docker
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
IMAGE_NAME="shadowos-builder"

# Go to project root
cd "$PROJECT_ROOT"

# Build container image if needed
if [[ "$(docker images -q $IMAGE_NAME 2> /dev/null)" == "" ]] || [[ "${1:-}" == "--rebuild" ]]; then
    echo "[shadowos] Building Docker builder image..."
    USER_ID=$(id -u)
    GROUP_ID=$(id -g)
    docker build \
        --build-arg USER_ID="$USER_ID" \
        --build-arg GROUP_ID="$GROUP_ID" \
        -t "$IMAGE_NAME" \
        -f "$SCRIPT_DIR/Dockerfile" .
fi

if [[ "${1:-}" == "--rebuild" ]]; then
    shift
fi

echo "[shadowos] Running build in container..."
# Run container
# --privileged is required for mount/chroot operations inside
# --rm removes container after exit
# Run the build inside the container
# Handle --clean argument
ARGS="$@"
if [[ "$*" == *"--clean"* ]]; then
    echo "[shadowos] Cleaning build artifacts..."
    docker run --rm --privileged \
        -v "$(pwd):/app" \
        -e SHADOWOS_DIR=/app \
        --user root \
        -w /app \
        shadowos-builder \
        make clean
    
    # Remove --clean from args to avoid passing it to make iso
    ARGS="${ARGS/--clean/}"
fi

docker run --rm --privileged \
    -v "$(pwd):/app" \
    -v "$(pwd)/output:/app/output" \
    -e SHADOWOS_DIR=/app \
    --user root \
    -w /app \
    shadowos-builder \
    make -j$(nproc) iso $ARGS

echo "[shadowos] Container build finished."
