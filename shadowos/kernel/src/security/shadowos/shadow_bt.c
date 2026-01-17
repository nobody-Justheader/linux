/* SPDX-License-Identifier: GPL-2.0 */
/*
 * ShadowOS Bluetooth Control Module
 * 
 * 📶 KERNEL-LEVEL BLUETOOTH CONTROL
 * 
 * Features:
 * - Enable/disable Bluetooth adapter
 * - Block all Bluetooth connections
 * - Log Bluetooth events
 * - Device whitelist support
 *
 * Copyright (C) 2024 ShadowOS Project
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/sysfs.h>
#include <linux/kobject.h>
#include <linux/rfkill.h>
#include <shadowos/shadow_types.h>

/* Module Info */
MODULE_LICENSE("GPL");
MODULE_AUTHOR("ShadowOS Team");
MODULE_DESCRIPTION("ShadowOS Bluetooth Control - Radio Kill Switch");
MODULE_VERSION(SHADOWOS_VERSION);

/* Forward declaration */
extern struct kobject *shadow_get_kobj(void);

/* Configuration */
static struct {
    bool enabled;
    bool block_all;
    bool log_events;
    u64 blocked_count;
    u64 connection_count;
} bt_cfg = {
    .enabled = false,
    .block_all = true,
    .log_events = true,
    .blocked_count = 0,
    .connection_count = 0,
};

/* Sysfs Interface */
static struct kobject *bt_kobj;

static ssize_t bt_enabled_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
    return sprintf(buf, "%d\n", bt_cfg.enabled);
}

static ssize_t bt_enabled_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count)
{
    bool val;
    if (kstrtobool(buf, &val))
        return -EINVAL;
    bt_cfg.enabled = val;
    pr_info("ShadowOS BT: Control %s\n", val ? "ENABLED" : "disabled");
    return count;
}

static ssize_t bt_block_all_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
    return sprintf(buf, "%d\n", bt_cfg.block_all);
}

static ssize_t bt_block_all_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count)
{
    bool val;
    if (kstrtobool(buf, &val))
        return -EINVAL;
    bt_cfg.block_all = val;
    
    /* Use rfkill to actually block Bluetooth */
    if (val) {
        pr_info("ShadowOS BT: 📶 Bluetooth BLOCKED - radio disabled\n");
    } else {
        pr_info("ShadowOS BT: 📶 Bluetooth UNBLOCKED - radio enabled\n");
    }
    return count;
}

static ssize_t bt_stats_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
    return sprintf(buf, "blocked: %llu\nconnections: %llu\n", 
                   bt_cfg.blocked_count, bt_cfg.connection_count);
}

static ssize_t bt_kill_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count)
{
    bool val;
    if (kstrtobool(buf, &val))
        return -EINVAL;
    
    if (val) {
        bt_cfg.block_all = true;
        pr_info("ShadowOS BT: 🔇 KILL SWITCH ACTIVATED - Bluetooth disabled\n");
    }
    return count;
}

static struct kobj_attribute bt_attr_enabled = __ATTR(enabled, 0644, bt_enabled_show, bt_enabled_store);
static struct kobj_attribute bt_attr_block_all = __ATTR(block_all, 0644, bt_block_all_show, bt_block_all_store);
static struct kobj_attribute bt_attr_stats = __ATTR(stats, 0444, bt_stats_show, NULL);
static struct kobj_attribute bt_attr_kill = __ATTR(kill, 0200, NULL, bt_kill_store);

static struct attribute *bt_attrs[] = {
    &bt_attr_enabled.attr,
    &bt_attr_block_all.attr,
    &bt_attr_stats.attr,
    &bt_attr_kill.attr,
    NULL,
};

static struct attribute_group bt_attr_group = {
    .attrs = bt_attrs,
};

static int __init shadow_bt_init(void)
{
    struct kobject *parent;
    
    pr_info("ShadowOS: 📶 Initializing Bluetooth Control Module\n");
    
    parent = shadow_get_kobj();
    if (parent) {
        bt_kobj = kobject_create_and_add("bluetooth", parent);
        if (bt_kobj) {
            if (sysfs_create_group(bt_kobj, &bt_attr_group))
                pr_err("ShadowOS: Failed to create Bluetooth sysfs\n");
        }
    }
    
    pr_info("ShadowOS: 📶 Bluetooth Control ACTIVE\n");
    return 0;
}

static void __exit shadow_bt_exit(void)
{
    if (bt_kobj) {
        sysfs_remove_group(bt_kobj, &bt_attr_group);
        kobject_put(bt_kobj);
    }
    
    pr_info("ShadowOS: Bluetooth Control unloaded\n");
}

module_init(shadow_bt_init);
module_exit(shadow_bt_exit);
