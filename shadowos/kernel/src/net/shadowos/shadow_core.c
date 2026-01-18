/* SPDX-License-Identifier: GPL-2.0 */
/*
 * ShadowOS Core Framework
 *
 * Copyright (C) 2026 ShadowOS Project
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <net/genetlink.h>
#include <linux/sysfs.h>
#include <linux/kobject.h>
#include <linux/spinlock.h>
#include <shadowos/shadow_types.h>
#include <shadowos/shadow_netlink.h>

/* Module Info */
MODULE_LICENSE("GPL");
MODULE_AUTHOR("ShadowOS Team");
MODULE_DESCRIPTION("ShadowOS Security Framework Core");
MODULE_VERSION(SHADOWOS_VERSION);

/* Core Components */
struct shadow_core {
    bool enabled;
    u32 log_level;
    struct kobject *kobj;
    spinlock_t lock;
    struct shadow_stats stats;
};

static struct shadow_core shadow_state;
static struct kobject *shadow_kobj_root;

/* Forward Declaration */
struct kobject *shadow_get_kobj(void);

struct kobject *shadow_get_kobj(void)
{
    return shadow_kobj_root;
}
EXPORT_SYMBOL(shadow_get_kobj);

/* Sysfs Attributes */
static ssize_t shadow_enabled_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
    return sprintf(buf, "%d\n", shadow_state.enabled);
}

static ssize_t shadow_enabled_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count)
{
    bool enabled;
    int ret;

    ret = kstrtobool(buf, &enabled);
    if (ret)
        return ret;

    shadow_state.enabled = enabled;
    return count;
}

static ssize_t shadow_log_level_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
    return sprintf(buf, "%u\n", shadow_state.log_level);
}

static ssize_t shadow_log_level_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count)
{
    unsigned int val;
    int ret;

    ret = kstrtouint(buf, 10, &val);
    if (ret)
        return ret;

    if (val > SHADOW_LOG_DEBUG)
        return -EINVAL;

    shadow_state.log_level = val;
    return count;
}

static ssize_t shadow_version_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
    return sprintf(buf, "%s\n", SHADOWOS_VERSION);
}

static ssize_t shadow_stats_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
    struct shadow_stats *s = &shadow_state.stats;
    
    spin_lock_bh(&shadow_state.lock);
    // Simple text format for now: "alerts_sent packets_inspected ..."
    // Or JSON-like for easier parsing:
    int len = sprintf(buf, 
        "alerts_sent: %llu\n"
        "packets_inspected: %llu\n"
        "scans_detected: %llu\n"
        "scans_diverted: %llu\n",
        s->alerts_sent,
        s->packets_inspected,
        s->scans_detected,
        s->scans_diverted
    );
    spin_unlock_bh(&shadow_state.lock);
    
    return len;
}

static struct kobj_attribute shadow_attr_enabled = __ATTR(enabled, 0644, shadow_enabled_show, shadow_enabled_store);
static struct kobj_attribute shadow_attr_loglevel = __ATTR(log_level, 0644, shadow_log_level_show, shadow_log_level_store);
static struct kobj_attribute shadow_attr_version = __ATTR(version, 0444, shadow_version_show, NULL);
static struct kobj_attribute shadow_attr_stats = __ATTR(stats, 0444, shadow_stats_show, NULL);

static struct attribute *shadow_attrs[] = {
    &shadow_attr_enabled.attr,
    &shadow_attr_loglevel.attr,
    &shadow_attr_version.attr,
    &shadow_attr_stats.attr,
    NULL,
};

static struct attribute_group shadow_attr_group = {
    .attrs = shadow_attrs,
};

/* Netlink Family */
static struct genl_family shadow_genl_family;

static const struct genl_multicast_group shadow_mcgrps[] = {
    [SHADOW_MCGRP_EVENTS] = { .name = SHADOW_GENL_MCGRP_NAME },
};

/* Send alert to userspace */
int shadow_send_alert(struct shadow_alert *alert)
{
    struct sk_buff *skb;
    void *msg_head;
    int rc;

    skb = genlmsg_new(NLMSG_GOODSIZE, GFP_ATOMIC);
    if (!skb)
        return -ENOMEM;

    msg_head = genlmsg_put(skb, 0, 0, &shadow_genl_family, 0, SHADOW_CMD_ALERT);
    if (!msg_head) {
        nlmsg_free(skb);
        return -EMSGSIZE;
    }

    if (nla_put_u32(skb, SHADOW_ATTR_ALERT_ID, alert->id) ||
        nla_put_u8(skb, SHADOW_ATTR_ALERT_TYPE, alert->type) ||
        nla_put_u8(skb, SHADOW_ATTR_ALERT_SEVERITY, alert->severity) ||
        nla_put_u64_64bit(skb, SHADOW_ATTR_TIMESTAMP, alert->timestamp, SHADOW_ATTR_UNSPEC) ||
        nla_put_be32(skb, SHADOW_ATTR_SRC_IP, alert->src_ip) ||
        nla_put_be32(skb, SHADOW_ATTR_DST_IP, alert->dst_ip) ||
        nla_put_be16(skb, SHADOW_ATTR_SRC_PORT, alert->src_port) ||
        nla_put_be16(skb, SHADOW_ATTR_DST_PORT, alert->dst_port) ||
        nla_put_string(skb, SHADOW_ATTR_SCAN_TYPE, alert->scan_type) ||
        nla_put_string(skb, SHADOW_ATTR_ACTION, alert->action_taken) ||
        nla_put_string(skb, SHADOW_ATTR_DETAILS, alert->details)) {
        nlmsg_free(skb);
        return -EMSGSIZE;
    }

    genlmsg_end(skb, msg_head);

    rc = genlmsg_multicast(&shadow_genl_family, skb, 0, SHADOW_MCGRP_EVENTS, GFP_ATOMIC);
    
    /* Update stats */
    spin_lock_bh(&shadow_state.lock);
    shadow_state.stats.alerts_sent++;
    spin_unlock_bh(&shadow_state.lock);

    return rc;
}
EXPORT_SYMBOL(shadow_send_alert);

/* Send log to userspace */
int shadow_send_log(int level, const char *fmt, ...)
{
    struct shadow_alert alert = {0};
    va_list args;
    
    if (level < SHADOW_LOG_INFO)
        return 0; // Filter low level logs

    alert.type = 0; // Log type
    alert.severity = level;
    alert.timestamp = ktime_get_real_ns();
    
    va_start(args, fmt);
    vsnprintf(alert.details, sizeof(alert.details), fmt, args);
    va_end(args);
    
    strncpy(alert.scan_type, "KERNEL_LOG", sizeof(alert.scan_type));
    
    return shadow_send_alert(&alert);
}
EXPORT_SYMBOL(shadow_send_log);

/* Netlink handler: Get config */
static int shadow_nl_config_get(struct sk_buff *skb, struct genl_info *info)
{
    struct sk_buff *msg;
    void *hdr;
    
    msg = genlmsg_new(NLMSG_GOODSIZE, GFP_KERNEL);
    if (!msg)
        return -ENOMEM;
    
    hdr = genlmsg_put(msg, info->snd_portid, info->snd_seq,
                      &shadow_genl_family, 0, SHADOW_CMD_CONFIG_GET);
    if (!hdr) {
        nlmsg_free(msg);
        return -EMSGSIZE;
    }
    
    if (nla_put_u8(msg, SHADOW_ATTR_ENABLED, shadow_state.enabled) ||
        nla_put_string(msg, SHADOW_ATTR_CONFIG_VALUE, SHADOWOS_VERSION)) {
        genlmsg_cancel(msg, hdr);
        nlmsg_free(msg);
        return -EMSGSIZE;
    }
    
    genlmsg_end(msg, hdr);
    return genlmsg_reply(msg, info);
}

/* Netlink handler: Get stats */
static int shadow_nl_stats_get(struct sk_buff *skb, struct genl_info *info)
{
    struct sk_buff *msg;
    void *hdr;
    
    msg = genlmsg_new(NLMSG_GOODSIZE, GFP_KERNEL);
    if (!msg)
        return -ENOMEM;
    
    hdr = genlmsg_put(msg, info->snd_portid, info->snd_seq,
                      &shadow_genl_family, 0, SHADOW_CMD_STATS_GET);
    if (!hdr) {
        nlmsg_free(msg);
        return -EMSGSIZE;
    }
    
    spin_lock_bh(&shadow_state.lock);
    if (nla_put_u64_64bit(msg, SHADOW_ATTR_STATS, shadow_state.stats.alerts_sent, SHADOW_ATTR_UNSPEC)) {
        spin_unlock_bh(&shadow_state.lock);
        genlmsg_cancel(msg, hdr);
        nlmsg_free(msg);
        return -EMSGSIZE;
    }
    spin_unlock_bh(&shadow_state.lock);
    
    genlmsg_end(msg, hdr);
    return genlmsg_reply(msg, info);
}

/* Netlink Ops */
static const struct genl_ops shadow_genl_ops[] = {
    {
        .cmd = SHADOW_CMD_CONFIG_GET,
        .doit = shadow_nl_config_get,
        .flags = 0,
    },
    {
        .cmd = SHADOW_CMD_STATS_GET,
        .doit = shadow_nl_stats_get,
        .flags = 0,
    },
};

/* Netlink Attribute Policy */
static const struct nla_policy shadow_genl_policy[SHADOW_ATTR_MAX + 1] = {
    [SHADOW_ATTR_ALERT_ID]       = { .type = NLA_U32 },
    [SHADOW_ATTR_ALERT_TYPE]     = { .type = NLA_U8 },
    [SHADOW_ATTR_ALERT_SEVERITY] = { .type = NLA_U8 },
    [SHADOW_ATTR_TIMESTAMP]      = { .type = NLA_U64 },
    [SHADOW_ATTR_SRC_IP]         = { .type = NLA_U32 },
    [SHADOW_ATTR_DST_IP]         = { .type = NLA_U32 },
    [SHADOW_ATTR_SRC_PORT]       = { .type = NLA_U16 },
    [SHADOW_ATTR_DST_PORT]       = { .type = NLA_U16 },
    [SHADOW_ATTR_PACKET_COUNT]   = { .type = NLA_U32 },
    [SHADOW_ATTR_PORTS_COUNT]    = { .type = NLA_U32 },
    [SHADOW_ATTR_SCAN_TYPE]      = { .type = NLA_NUL_STRING, .len = 32 },
    [SHADOW_ATTR_ACTION]         = { .type = NLA_NUL_STRING, .len = 64 },
    [SHADOW_ATTR_DETAILS]        = { .type = NLA_NUL_STRING, .len = 256 },
    [SHADOW_ATTR_MODULE]         = { .type = NLA_NUL_STRING, .len = 32 },
    [SHADOW_ATTR_ENABLED]        = { .type = NLA_U8 },
    [SHADOW_ATTR_CONFIG_KEY]     = { .type = NLA_NUL_STRING, .len = 64 },
    [SHADOW_ATTR_CONFIG_VALUE]   = { .type = NLA_NUL_STRING, .len = 256 },
    [SHADOW_ATTR_STATS]          = { .type = NLA_U64 },
};

static struct genl_family shadow_genl_family __ro_after_init = {
    .name = SHADOW_GENL_NAME,
    .version = SHADOW_GENL_VERSION,
    .maxattr = SHADOW_ATTR_MAX,
    .policy = shadow_genl_policy,
    .module = THIS_MODULE,
    .ops = shadow_genl_ops,
    .n_ops = ARRAY_SIZE(shadow_genl_ops),
    .mcgrps = shadow_mcgrps,
    .n_mcgrps = ARRAY_SIZE(shadow_mcgrps),
};

static int __init shadow_core_init(void)
{
    int rc;

    pr_info("ShadowOS: Initializing Core Framework %s\n", SHADOWOS_VERSION);

    /* Initialize core state */
    spin_lock_init(&shadow_state.lock);
    shadow_state.enabled = true;
    shadow_state.log_level = SHADOW_LOG_INFO;

    /* Create sysfs root /sys/kernel/shadowos/ */
    shadow_kobj_root = kobject_create_and_add("shadowos", kernel_kobj);
    if (!shadow_kobj_root)
        return -ENOMEM;

    /* Create core directory /sys/kernel/shadowos/core/ */
    shadow_state.kobj = kobject_create_and_add("core", shadow_kobj_root);
    if (!shadow_state.kobj) {
        kobject_put(shadow_kobj_root);
        return -ENOMEM;
    }

    rc = sysfs_create_group(shadow_state.kobj, &shadow_attr_group);
    if (rc) {
        kobject_put(shadow_state.kobj);
        kobject_put(shadow_kobj_root);
        return rc;
    }

    rc = genl_register_family(&shadow_genl_family);
    if (rc) {
        pr_err("ShadowOS: Failed to register netlink family (err=%d)\n", rc);
        sysfs_remove_group(shadow_state.kobj, &shadow_attr_group);
        kobject_put(shadow_state.kobj);
        kobject_put(shadow_kobj_root);
        return rc;
    }

    pr_info("ShadowOS: Core initialized successfully\n");
    return 0;
}

static void __exit shadow_core_exit(void)
{
    genl_unregister_family(&shadow_genl_family);
    sysfs_remove_group(shadow_state.kobj, &shadow_attr_group);
    kobject_put(shadow_state.kobj);
    kobject_put(shadow_kobj_root);
    pr_info("ShadowOS: Core unloaded\n");
}

module_init(shadow_core_init);
module_exit(shadow_core_exit);
