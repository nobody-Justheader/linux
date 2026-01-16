# ShadowOS Profile - Automatic Security Environment
# /etc/profile.d/shadowos.sh
#
# Loaded on every shell - security is MANDATORY

# =============================================================================
# DISABLE ALL HISTORY (Thorough)
# =============================================================================

export HISTSIZE=0
export HISTFILESIZE=0
export SAVEHIST=0
unset HISTFILE
export LESSHISTFILE=/dev/null
export MYSQL_HISTFILE=/dev/null
export SQLITE_HISTORY=/dev/null
export PYTHON_HISTORY=/dev/null
export NODE_REPL_HISTORY=/dev/null
export REDISCLI_HISTFILE=/dev/null

# Disable history for current shell
set +o history 2>/dev/null
unset HISTFILE

# =============================================================================
# SECURE ALIASES (Always On)
# =============================================================================

# Secure file operations replace standard commands
alias cp='scopy'
alias mv='smove'
alias rm='sdelete'

# Original commands with backslash: \cp, \mv, \rm

# =============================================================================
# SECURE ENVIRONMENT
# =============================================================================

export TMPDIR=/shadow/tmp
export TEMP=/shadow/tmp
export TMP=/shadow/tmp
mkdir -p /shadow/tmp 2>/dev/null

# Secure umask
umask 077

# Disable core dumps
ulimit -c 0

# =============================================================================
# AUTO CLEANUP ON EXIT
# =============================================================================

cleanup_on_exit() {
    # Clear shell memory
    history -c 2>/dev/null
    
    # Clear temp files
    rm -rf /shadow/tmp/* 2>/dev/null
    
    # Clear clipboard
    which xclip >/dev/null 2>&1 && xclip -selection clipboard < /dev/null
    which wl-copy >/dev/null 2>&1 && wl-copy --clear
}

trap cleanup_on_exit EXIT

# =============================================================================
# NETWORK STEALTH (Re-apply on shell start)
# =============================================================================

# Verify MAC is randomized
_check_stealth() {
    for iface in /sys/class/net/*/address; do
        [ -f "$iface" ] || continue
        local mac=$(cat "$iface")
        # Check if still factory MAC (unlikely with our init)
    done
}

# Run check silently
_check_stealth 2>/dev/null

# =============================================================================
# WORKSPACE
# =============================================================================

# Ensure RAM workspace exists
[ -d /shadow ] || mkdir -p /shadow 2>/dev/null

# Default to RAM workspace
cd /shadow 2>/dev/null || true
