# ShadowOS Robust Build Guidelines

To ensure the stability and security of ShadowOS builds, all developers must adhere to the following **Robust Build Rules**.

## Rule 1: Always Use Containerized Builds
**NEVER** build the ISO directly on your host machine. Host contamination is the #1 cause of "it works on my machine" bugs and potential security risks.

*   **Correct:** `./scripts/build-shadowos-docker.sh`
*   **Incorrect:** `./scripts/build-iso.sh` (when not in Docker)

The `build-shadowos-docker.sh` script sets up a pristine environment with the exact required dependencies.

## Rule 2: Incremental Builds via Makefile
Use the `Makefile` for standard operations. It wraps the docker script and handles caching smarts.
- `make iso` -> Runs the docker build.
- `make clean` -> Safely removes artifacts.

## Rule 3: Safe Cleaning Protocols
Before running `rm -rf` on any build directory, **ALWAYS** verify that `debootstrap` chroots have been unmounted.
The build scripts attempt to handle this, but if a build cancels or crashes mid-way, `rootfs/dev` might still be mounted.
- Check with: `mount | grep shadowos`

## Rule 4: Verify Your Build
After a build completes, verify the output:
1.  Check that `shadowos-bleeding.iso` exists in the root directory.
2.  Ensure it is larger than 1GB (a typical size).
3.  Test it using `./scripts/test-vm.sh`.

## Troubleshooting
If the build fails with "permissions denied" or odd file errors:
1.  Run `make clean` (or `./scripts/build-shadowos-docker.sh --rebuild` to force a docker image rebuild).
2.  Check Docker disk space (`docker system df`).
3.  Ensure you are not running `sudo make` outside of the container context (files created as root on host).
