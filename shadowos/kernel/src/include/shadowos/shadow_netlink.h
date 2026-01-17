/* SPDX-License-Identifier: GPL-2.0 */
/*
 * ShadowOS Kernel Framework - Netlink Protocol Definitions
 * 
 * Copyright (C) 2024 ShadowOS Project
 */

#ifndef _SHADOWOS_NETLINK_H
#define _SHADOWOS_NETLINK_H

#include <linux/genetlink.h>

/* Netlink family name */
#define SHADOW_GENL_NAME        "shadowos"
#define SHADOW_GENL_VERSION     1
#define SHADOW_GENL_MCGRP_NAME  "shadow_events"

/* Netlink commands */
enum shadow_nl_commands {
    SHADOW_CMD_UNSPEC,
    SHADOW_CMD_ALERT,           /* Kernel → User: Alert event */
    SHADOW_CMD_CONFIG_GET,      /* User → Kernel: Get config */
    SHADOW_CMD_CONFIG_SET,      /* User → Kernel: Set config */
    SHADOW_CMD_STATS_GET,       /* User → Kernel: Get stats */
    SHADOW_CMD_STATS_RESET,     /* User → Kernel: Reset stats */
    SHADOW_CMD_LOG,             /* Kernel → User: Log message */
    __SHADOW_CMD_MAX,
};
#define SHADOW_CMD_MAX (__SHADOW_CMD_MAX - 1)

/* Netlink attributes */
enum shadow_nl_attrs {
    SHADOW_ATTR_UNSPEC,
    
    /* Alert attributes */
    SHADOW_ATTR_ALERT_ID,       /* u32: Alert ID */
    SHADOW_ATTR_ALERT_TYPE,     /* u8: Alert type */
    SHADOW_ATTR_ALERT_SEVERITY, /* u8: Severity */
    SHADOW_ATTR_TIMESTAMP,      /* u64: Timestamp */
    SHADOW_ATTR_SRC_IP,         /* u32: Source IP */
    SHADOW_ATTR_DST_IP,         /* u32: Destination IP */
    SHADOW_ATTR_SRC_PORT,       /* u16: Source port */
    SHADOW_ATTR_DST_PORT,       /* u16: Destination port */
    SHADOW_ATTR_PACKET_COUNT,   /* u32: Packet count */
    SHADOW_ATTR_PORTS_COUNT,    /* u32: Ports targeted */
    SHADOW_ATTR_SCAN_TYPE,      /* string: Scan type */
    SHADOW_ATTR_ACTION,         /* string: Action taken */
    SHADOW_ATTR_DETAILS,        /* string: Details */
    
    /* Config attributes */
    SHADOW_ATTR_MODULE,         /* string: Module name */
    SHADOW_ATTR_ENABLED,        /* u8: 0/1 */
    SHADOW_ATTR_CONFIG_KEY,     /* string: Config key */
    SHADOW_ATTR_CONFIG_VALUE,   /* string: Config value */
    
    /* Stats attributes */
    SHADOW_ATTR_STATS,          /* nested: Statistics */
    
    __SHADOW_ATTR_MAX,
};
#define SHADOW_ATTR_MAX (__SHADOW_ATTR_MAX - 1)

/* Multicast group for events */
enum shadow_nl_mcgrps {
    SHADOW_MCGRP_EVENTS,
};

/* Function prototypes (implemented in shadow_core) */
int shadow_netlink_init(void);
void shadow_netlink_exit(void);
int shadow_send_alert(struct shadow_alert *alert);
int shadow_send_log(int level, const char *fmt, ...);

#endif /* _SHADOWOS_NETLINK_H */
