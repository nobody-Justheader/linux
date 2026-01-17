/* SPDX-License-Identifier: GPL-2.0 */
/*
 * ShadowOS Kernel Framework - Type Definitions
 * 
 * Copyright (C) 2024 ShadowOS Project
 */

#ifndef _SHADOWOS_TYPES_H
#define _SHADOWOS_TYPES_H

#include <linux/types.h>

/* Module version */
#define SHADOWOS_VERSION_MAJOR  1
#define SHADOWOS_VERSION_MINOR  0
#define SHADOWOS_VERSION_PATCH  0
#define SHADOWOS_VERSION        "1.0.0"

/* Log levels */
enum shadow_log_level {
    SHADOW_LOG_NONE = 0,
    SHADOW_LOG_ERROR = 1,
    SHADOW_LOG_WARN = 2,
    SHADOW_LOG_INFO = 3,
    SHADOW_LOG_DEBUG = 4,
};

/* Alert types */
enum shadow_alert_type {
    SHADOW_ALERT_SCAN_SYN = 1,
    SHADOW_ALERT_SCAN_CONNECT,
    SHADOW_ALERT_SCAN_UDP,
    SHADOW_ALERT_SCAN_FIN,
    SHADOW_ALERT_SCAN_NULL,
    SHADOW_ALERT_SCAN_XMAS,
    SHADOW_ALERT_SCAN_OS_FINGERPRINT,
    SHADOW_ALERT_SCAN_MASSCAN,
    SHADOW_ALERT_USB_CONNECTED,
    SHADOW_ALERT_USB_BLOCKED,
    SHADOW_ALERT_HONEY_TRIGGERED,
    SHADOW_ALERT_MAC_ROTATED,
    SHADOW_ALERT_PANIC_TRIGGERED,
    SHADOW_ALERT_TAMPER_DETECTED,
};

/* Alert severity levels */
enum shadow_severity {
    SHADOW_SEV_INFO = 1,
    SHADOW_SEV_LOW = 2,
    SHADOW_SEV_MEDIUM = 3,
    SHADOW_SEV_HIGH = 4,
    SHADOW_SEV_CRITICAL = 5,
};

/* Scan detection action */
enum shadow_action {
    SHADOW_ACTION_ALERT = 0,    /* Just alert */
    SHADOW_ACTION_DIVERT = 1,   /* Alert + divert response */
    SHADOW_ACTION_BLOCK = 2,    /* Alert + block */
};

/* Alert structure sent to userspace */
struct shadow_alert {
    __u32 id;                   /* Unique alert ID */
    __u64 timestamp;            /* Kernel timestamp (ns) */
    __u8 type;                  /* Alert type */
    __u8 severity;              /* Severity level */
    __be32 src_ip;              /* Source IP */
    __be32 dst_ip;              /* Destination IP */
    __be16 src_port;            /* Source port */
    __be16 dst_port;            /* Destination port */
    __u32 packet_count;         /* Packets in this event */
    __u32 ports_targeted;       /* Number of ports targeted */
    char scan_type[32];         /* Human readable scan type */
    char action_taken[64];      /* Action description */
    char details[256];          /* Additional details */
} __attribute__((packed));

/* Statistics structure */
struct shadow_stats {
    __u64 alerts_sent;
    __u64 packets_inspected;
    __u64 scans_detected;
    __u64 scans_diverted;
    __u64 connections_blocked;
    __u64 phantom_responses;
    __u64 dns_blocked;
    __u64 usb_blocked;
};

/* Per-source tracking for scan detection */
struct shadow_source_track {
    __be32 src_ip;              /* Source IP */
    __u64 first_seen;           /* First packet timestamp */
    __u64 last_seen;            /* Last packet timestamp */
    __u32 port_bitmap[2048];    /* 65536 bits for port tracking */
    __u32 port_count;           /* Number of unique ports */
    __u32 packet_count;         /* Total packets from this source */
    __u8 flags_seen;            /* TCP flags observed */
    struct hlist_node node;     /* Hash table node */
};

/* Phantom service definition */
struct shadow_phantom_svc {
    __u16 port;
    const char *banner;
    __u16 banner_len;
    __u32 delay_ms;
    bool tarpit;
};

/* OS identity profile for flux */
struct shadow_os_profile {
    char name[32];
    __u8 ttl;
    __u16 window;
    __u16 mss;
    __u8 df_bit;
    __u8 sack_ok;
    __u8 timestamps;
    __u8 window_scale;
};

#endif /* _SHADOWOS_TYPES_H */
