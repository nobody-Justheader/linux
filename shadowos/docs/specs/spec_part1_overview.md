# ShadowOS Complete Technical Specification

## Document Overview

This specification is split into multiple parts:
- **Part 1** (this file): Overview + Phase 1 (Core Infrastructure)
- **Part 2**: Phase 2-3 (Active Defense + Network Security)
- **Part 3**: Phase 4-5 (Hardware + Storage)
- **Part 4**: Phase 6-7 (Anti-Forensics + Offensive)
- **Part 5**: Phase 8 (Research/Experimental)

---

## Project Summary

| Metric | Value |
|--------|-------|
| Total Features | ~180 implementable |
| Total Phases | 8 |
| Estimated Duration | 6-12 months |
| Kernel Version | Linux 6.1 LTS |
| Language | C (kernel), Python/C (userspace) |

---

## Feature Tiers

| Tier | Features | Description |
|------|----------|-------------|
| Core | 30 | Essential, enabled by default |
| Professional | 50 | For security professionals |
| Expert | 60 | Advanced defense capabilities |
| Research | 40 | Cutting-edge, experimental |

---

# PHASE 1: CORE INFRASTRUCTURE

**Duration:** 2-3 weeks  
**Features:** 30  
**Goal:** Working custom kernel with basic framework

## 1.1 Kernel Build System

### Specification

```
Directory Structure:
shadowos/
├── kernel/
│   ├── Makefile                    # Master kernel build
│   ├── download-kernel.sh          # Fetch Linux 6.1.x
│   ├── apply-patches.sh            # Apply ShadowOS patches
│   ├── config/
│   │   └── shadowos_defconfig      # Kernel configuration
│   ├── patches/
│   │   └── *.patch                 # Kernel patches
│   └── src/
│       ├── net/shadowos/           # Network modules
│       ├── security/shadowos/      # Security modules
│       └── include/shadowos/       # Headers
```

### Build Commands

```bash
make kernel-download    # Download Linux 6.1.x source
make kernel-patch       # Apply ShadowOS patches
make kernel-config      # Configure with shadowos_defconfig
make kernel-build       # Compile (30-60 min)
make kernel-package     # Create .deb package
```

---

## 1.2 shadow_core Module

### Purpose
Central framework for all ShadowOS kernel modules.

### Technical Specification

```c
// File: kernel/src/net/shadowos/shadow_core.c

/* Module Information */
MODULE_LICENSE("GPL");
MODULE_AUTHOR("ShadowOS Project");
MODULE_DESCRIPTION("ShadowOS Core Framework");
MODULE_VERSION("1.0.0");

/* Core Components */
struct shadow_core {
    bool enabled;                    // Master enable
    u32 log_level;                   // 0=none, 1=error, 2=warn, 3=info, 4=debug
    struct kobject *kobj;            // sysfs kobject
    struct genl_family genl_family;  // Netlink family
    spinlock_t lock;                 // Core lock
    struct shadow_stats stats;       // Statistics
};

/* Statistics Structure */
struct shadow_stats {
    atomic64_t alerts_sent;
    atomic64_t packets_inspected;
    atomic64_t scans_detected;
    atomic64_t connections_diverted;
    atomic64_t phantom_responses;
};
```

### sysfs Interface

```
/sys/kernel/shadowos/
├── core/
│   ├── enabled          # 0/1 (rw)
│   ├── version          # "1.0.0" (ro)
│   ├── log_level        # 0-4 (rw)
│   └── stats            # JSON stats (ro)
```

### Netlink Protocol

```c
/* Netlink Family */
#define SHADOW_GENL_NAME "shadowos"
#define SHADOW_GENL_VERSION 1

/* Commands */
enum shadow_nl_cmd {
    SHADOW_CMD_UNSPEC,
    SHADOW_CMD_ALERT,        // Kernel → User: Alert
    SHADOW_CMD_CONFIG_GET,   // User → Kernel: Get config
    SHADOW_CMD_CONFIG_SET,   // User → Kernel: Set config
    SHADOW_CMD_STATS,        // User ↔ Kernel: Statistics
    __SHADOW_CMD_MAX,
};

/* Attributes */
enum shadow_nl_attr {
    SHADOW_ATTR_UNSPEC,
    SHADOW_ATTR_ALERT_TYPE,
    SHADOW_ATTR_ALERT_SEVERITY,
    SHADOW_ATTR_SRC_IP,
    SHADOW_ATTR_DST_IP,
    SHADOW_ATTR_SRC_PORT,
    SHADOW_ATTR_DST_PORT,
    SHADOW_ATTR_MESSAGE,
    SHADOW_ATTR_TIMESTAMP,
    __SHADOW_ATTR_MAX,
};
```

---

## 1.3 shadow_detect Module

### Purpose
Detect network reconnaissance and scanning.

### Detection Algorithms

```c
/* Scan Detection Thresholds */
struct scan_thresholds {
    u32 syn_ports_per_sec;      // Default: 5
    u32 syn_window_ms;          // Default: 10000
    u32 connect_per_sec;        // Default: 10
    u32 udp_ports_per_sec;      // Default: 10
    u32 flood_pps;              // Default: 100
};

/* Per-Source Tracking */
struct source_tracker {
    __be32 src_ip;
    u64 first_seen;
    u64 last_seen;
    u32 ports_targeted[65536/32];  // Bitmap
    u32 port_count;
    u32 packet_count;
    u8 flags_seen;
    struct hlist_node node;
};
```

### Detection Types

| Type | Detection Method | Threshold |
|------|-----------------|-----------|
| SYN Scan | Multiple SYN to different ports | 5 ports/10s |
| Connect Scan | Multiple full connections | 10 conn/10s |
| FIN Scan | FIN without prior connection | Any |
| NULL Scan | No TCP flags set | Any |
| XMAS Scan | FIN+PSH+URG flags | Any |
| UDP Scan | UDP to multiple ports | 10 ports/10s |
| OS Fingerprint | Unusual TCP options | Pattern match |

### sysfs Interface

```
/sys/kernel/shadowos/detect/
├── enabled              # 0/1
├── syn_threshold        # Ports to trigger
├── window_ms            # Detection window
├── action               # alert/divert/block
└── tracked_sources      # Current tracked IPs (ro)
```

---

## 1.4 Userspace Components

### shadow-alertd Daemon

```python
# File: userspace/shadow-alertd/shadow_alertd.py

"""
ShadowOS Alert Daemon
- Listens on netlink for kernel alerts
- Displays desktop notifications
- Logs to file/syslog
"""

import socket
from gi.repository import Notify

class ShadowAlertd:
    def __init__(self):
        self.nl_socket = self.create_netlink_socket()
        Notify.init("ShadowOS")
    
    def create_netlink_socket(self):
        # Create generic netlink socket
        sock = socket.socket(socket.AF_NETLINK, 
                            socket.SOCK_DGRAM, 
                            NETLINK_GENERIC)
        sock.bind((os.getpid(), 0))
        return sock
    
    def handle_alert(self, alert):
        notification = Notify.Notification.new(
            f"⚠️ {alert.type}",
            f"Source: {alert.src_ip}\n"
            f"Target: {alert.dst_port}\n"
            f"Action: {alert.action}",
            "security-high"
        )
        notification.show()
```

### libshadow Library

```c
// File: userspace/libshadow/shadow.h

/* Public API */
int shadow_init(void);
void shadow_cleanup(void);

/* Configuration */
int shadow_get_enabled(const char *module);
int shadow_set_enabled(const char *module, bool enabled);

/* Alerts */
typedef void (*shadow_alert_cb)(struct shadow_alert *alert);
int shadow_register_alert_callback(shadow_alert_cb cb);

/* Statistics */
struct shadow_stats *shadow_get_stats(void);
```

---

## 1.5 Phase 1 Feature List

| # | Feature | Module | Priority |
|---|---------|--------|----------|
| 1 | Kernel module framework | shadow_core | P0 |
| 2 | sysfs interface | shadow_core | P0 |
| 3 | Netlink communication | shadow_core | P0 |
| 4 | Logging framework | shadow_core | P0 |
| 5 | Statistics collection | shadow_core | P0 |
| 6 | SYN scan detection | shadow_detect | P0 |
| 7 | Connect scan detection | shadow_detect | P0 |
| 8 | UDP scan detection | shadow_detect | P1 |
| 9 | FIN/NULL/XMAS detection | shadow_detect | P1 |
| 10 | OS fingerprint detection | shadow_detect | P1 |
| 11 | Alert daemon | shadow-alertd | P0 |
| 12 | Desktop notifications | shadow-alertd | P0 |
| 13 | libshadow library | libshadow | P0 |
| 14 | Basic Control Center | shadow-control | P1 |
| 15 | Custom kernel build | build system | P0 |
| 16 | Kernel packaging | build system | P0 |
| 17 | Module auto-load | systemd | P1 |
| 18 | Log rotation | logrotate | P2 |
| 19 | Man pages | documentation | P2 |
| 20 | Unit tests | testing | P1 |

---

## 1.6 Testing Strategy

### Kernel Module Tests

```bash
# Load modules
sudo modprobe shadow_core
sudo modprobe shadow_detect

# Verify loaded
lsmod | grep shadow

# Check sysfs
cat /sys/kernel/shadowos/core/version
echo 1 > /sys/kernel/shadowos/detect/enabled

# Test detection (from another machine)
nmap -sS <target_ip>

# Check alerts
journalctl -f | grep SHADOW
```

### Integration Tests

```bash
# Run test suite
make test

# Coverage report
make coverage
```

---

## Next Document

Continue to **Part 2: Phase 2-3 Specification** for:
- Active Defense modules (shadow_chaos, shadow_phantom, shadow_flux)
- Network Security modules (shadow_dns, shadow_geo)
