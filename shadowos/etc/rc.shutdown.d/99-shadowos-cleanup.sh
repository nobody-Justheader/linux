#!/bin/sh
#
# 99-shadowos-cleanup.sh - ShadowOS Shutdown Cleanup
# /etc/rc.shutdown.d/99-shadowos-cleanup.sh
#
# Runs at shutdown to wipe all traces
#

log() {
    echo "[ShadowOS Cleanup] $*"
}

log "Starting shutdown cleanup..."

# -----------------------------------------------------------------------------
# WIPE SHELL HISTORIES
# -----------------------------------------------------------------------------
log "Wiping shell histories..."

for hist in /home/*/.bash_history /home/*/.zsh_history /root/.bash_history /root/.zsh_history; do
    [ -f "$hist" ] && shred -fzun 3 "$hist" 2>/dev/null
done

# Clear bash/zsh history in memory for all users
for user_home in /home/* /root; do
    [ -d "$user_home" ] || continue
    rm -f "$user_home/.bash_history" "$user_home/.zsh_history" \
          "$user_home/.lesshst" "$user_home/.viminfo" \
          "$user_home/.python_history" "$user_home/.node_repl_history" 2>/dev/null
done

# -----------------------------------------------------------------------------
# WIPE TEMPORARY FILES
# -----------------------------------------------------------------------------
log "Wiping temporary files..."

rm -rf /tmp/* /tmp/.* 2>/dev/null || true
rm -rf /var/tmp/* /var/tmp/.* 2>/dev/null || true

# -----------------------------------------------------------------------------
# WIPE LOGS
# -----------------------------------------------------------------------------
log "Wiping system logs..."

# Wipe log files
for logfile in /var/log/*.log /var/log/**/*.log; do
    [ -f "$logfile" ] && shred -fzun 1 "$logfile" 2>/dev/null
done

# Clear journal if using systemd
if command -v journalctl >/dev/null 2>&1; then
    journalctl --flush --rotate 2>/dev/null
    journalctl --vacuum-time=1s 2>/dev/null
fi

# Clear traditional logs
for log in /var/log/messages /var/log/syslog /var/log/auth.log /var/log/kern.log; do
    [ -f "$log" ] && shred -fzun 1 "$log" 2>/dev/null
done

# Clear wtmp/btmp (login records)
shred -fzun 1 /var/log/wtmp 2>/dev/null
shred -fzun 1 /var/log/btmp 2>/dev/null
shred -fzun 1 /var/log/lastlog 2>/dev/null

# -----------------------------------------------------------------------------
# WIPE RAM WORKSPACE
# -----------------------------------------------------------------------------
if mountpoint -q /shadow 2>/dev/null; then
    log "Wiping RAM workspace..."
    find /shadow -type f -exec shred -fzun 1 {} \; 2>/dev/null
    umount -l /shadow 2>/dev/null
fi

# -----------------------------------------------------------------------------
# WIPE SWAP
# -----------------------------------------------------------------------------
log "Wiping swap space..."

# Get swap devices
for swap in $(swapon --show=NAME --noheadings 2>/dev/null); do
    swapoff "$swap" 2>/dev/null
    # Overwrite with random data
    dd if=/dev/urandom of="$swap" bs=1M 2>/dev/null || true
    mkswap "$swap" 2>/dev/null
done

# For swap files
if [ -f /swapfile ]; then
    swapoff /swapfile 2>/dev/null
    shred -fzun 1 /swapfile 2>/dev/null
fi

# -----------------------------------------------------------------------------
# CLEAR CLIPBOARD
# -----------------------------------------------------------------------------
log "Clearing clipboard..."

if command -v wl-copy >/dev/null 2>&1; then
    echo -n "" | wl-copy 2>/dev/null
fi

if command -v xclip >/dev/null 2>&1; then
    echo -n "" | xclip -selection clipboard 2>/dev/null
fi

# -----------------------------------------------------------------------------
# WIPE BROWSER DATA
# -----------------------------------------------------------------------------
log "Wiping browser data..."

for user_home in /home/* /root; do
    [ -d "$user_home" ] || continue
    
    # Firefox
    rm -rf "$user_home/.mozilla/firefox/"*"/cookies.sqlite" \
           "$user_home/.mozilla/firefox/"*"/places.sqlite" \
           "$user_home/.mozilla/firefox/"*"/formhistory.sqlite" \
           "$user_home/.mozilla/firefox/"*"/webappsstore.sqlite" 2>/dev/null
    
    # Chromium
    rm -rf "$user_home/.config/chromium/Default/Cookies" \
           "$user_home/.config/chromium/Default/History" \
           "$user_home/.config/chromium/Default/Login Data" 2>/dev/null
           
    # Chrome
    rm -rf "$user_home/.config/google-chrome/Default/Cookies" \
           "$user_home/.config/google-chrome/Default/History" 2>/dev/null
done

# -----------------------------------------------------------------------------
# WIPE NETWORK TRACES
# -----------------------------------------------------------------------------
log "Wiping network traces..."

# Clear ARP cache
ip neigh flush all 2>/dev/null

# Clear routing cache
ip route flush cache 2>/dev/null

# Clear DNS cache if using systemd-resolved
if command -v resolvectl >/dev/null 2>&1; then
    resolvectl flush-caches 2>/dev/null
fi

# Clear WiFi saved networks (optional - be careful with this)
# rm -rf /var/lib/shadowos/wifi-credentials.db 2>/dev/null

# -----------------------------------------------------------------------------
# WIPE RAM (if sdmem is available)
# -----------------------------------------------------------------------------
if command -v sdmem >/dev/null 2>&1; then
    log "Wiping unused RAM (this may take a while)..."
    # Quick wipe - single pass with zeros
    sdmem -fll 2>/dev/null &
    sleep 5  # Give it a few seconds, don't wait forever
    kill %1 2>/dev/null || true
fi

# -----------------------------------------------------------------------------
# SYNC AND DONE
# -----------------------------------------------------------------------------
log "Syncing filesystems..."
sync

log "Cleanup complete. Safe to power off."
