/* SPDX-License-Identifier: GPL-2.0 */
/*
 * ShadowOS Time-Locked Secrets (shadow_timelock)
 * 
 * DATA ACCESSIBLE ONLY AT CERTAIN TIMES
 * 
 * Features:
 * - Time-based file access control
 * - Configurable allowed hours/days
 * - Automatic lock/unlock based on time
 *
 * Copyright (C) 2024 ShadowOS Project
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/time.h>
#include <linux/sysfs.h>
#include <linux/kobject.h>
#include <linux/list.h>
#include <shadowos/shadow_types.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("ShadowOS Team");
MODULE_DESCRIPTION("ShadowOS Time-Locked Secrets - Time-Based Access Control");
MODULE_VERSION(SHADOWOS_VERSION);

extern struct kobject *shadow_get_kobj(void);

/* Time-lock rule */
struct timelock_rule {
    char path[256];
    u8 start_hour;      /* 0-23 */
    u8 end_hour;        /* 0-23 */
    u8 allowed_days;    /* Bitmask: Sun=1, Mon=2, Tue=4, ... */
    u64 access_denied;
    u64 access_granted;
    struct list_head list;
};

/* Configuration */
static struct {
    bool enabled;
    struct list_head rules;
    spinlock_t lock;
} timelock_cfg;

static struct kobject *timelock_kobj;

/* Check if current time permits access */
static bool time_permits_access(struct timelock_rule *rule)
{
    struct tm now_tm;
    time64_t now = ktime_get_real_seconds();
    
    time64_to_tm(now, 0, &now_tm);
    
    /* Check hour range */
    if (now_tm.tm_hour < rule->start_hour || now_tm.tm_hour > rule->end_hour)
        return false;
    
    /* Check day */
    if (!(rule->allowed_days & (1 << now_tm.tm_wday)))
        return false;
    
    return true;
}

/* Check if path is time-locked */
bool shadow_timelock_check(const char *path)
{
    struct timelock_rule *rule;
    bool permitted = true;
    
    if (!timelock_cfg.enabled)
        return true;
    
    spin_lock(&timelock_cfg.lock);
    list_for_each_entry(rule, &timelock_cfg.rules, list) {
        if (strstr(path, rule->path)) {
            if (time_permits_access(rule)) {
                rule->access_granted++;
            } else {
                rule->access_denied++;
                permitted = false;
                pr_info("ShadowOS TIMELOCK: Access denied to %s (time restriction)\n", 
                        path);
            }
            break;
        }
    }
    spin_unlock(&timelock_cfg.lock);
    
    return permitted;
}
EXPORT_SYMBOL(shadow_timelock_check);

/* Sysfs Interface */
static ssize_t timelock_enabled_show(struct kobject *kobj,
                                     struct kobj_attribute *attr, char *buf)
{
    return sprintf(buf, "%d\n", timelock_cfg.enabled);
}

static ssize_t timelock_enabled_store(struct kobject *kobj,
                                      struct kobj_attribute *attr,
                                      const char *buf, size_t count)
{
    return kstrtobool(buf, &timelock_cfg.enabled) ? : count;
}

/* Add rule: path:start_hour-end_hour:days_bitmask */
static ssize_t timelock_add_store(struct kobject *kobj,
                                  struct kobj_attribute *attr,
                                  const char *buf, size_t count)
{
    struct timelock_rule *rule;
    char path[256];
    u8 start, end, days;
    
    if (sscanf(buf, "%255[^:]:%hhu-%hhu:%hhu", path, &start, &end, &days) != 4) {
        pr_err("ShadowOS TIMELOCK: Format: path:start_hour-end_hour:days_bitmask\n");
        return -EINVAL;
    }
    
    rule = kzalloc(sizeof(*rule), GFP_KERNEL);
    if (!rule)
        return -ENOMEM;
    
    strncpy(rule->path, path, sizeof(rule->path) - 1);
    rule->start_hour = start;
    rule->end_hour = end;
    rule->allowed_days = days;
    
    spin_lock(&timelock_cfg.lock);
    list_add(&rule->list, &timelock_cfg.rules);
    spin_unlock(&timelock_cfg.lock);
    
    pr_info("ShadowOS TIMELOCK: Added rule for %s (%u:00-%u:00, days=%u)\n",
            path, start, end, days);
    
    return count;
}

static ssize_t timelock_list_show(struct kobject *kobj,
                                  struct kobj_attribute *attr, char *buf)
{
    struct timelock_rule *rule;
    int len = 0;
    
    spin_lock(&timelock_cfg.lock);
    list_for_each_entry(rule, &timelock_cfg.rules, list) {
        len += snprintf(buf + len, PAGE_SIZE - len,
                       "%s: %02u:00-%02u:00 days=0x%02x (granted=%llu denied=%llu)\n",
                       rule->path, rule->start_hour, rule->end_hour,
                       rule->allowed_days, rule->access_granted, rule->access_denied);
    }
    spin_unlock(&timelock_cfg.lock);
    
    if (len == 0)
        len = sprintf(buf, "No time-lock rules configured\n");
    
    return len;
}

static ssize_t timelock_time_show(struct kobject *kobj,
                                  struct kobj_attribute *attr, char *buf)
{
    struct tm now_tm;
    time64_t now = ktime_get_real_seconds();
    static const char *days[] = {"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"};
    
    time64_to_tm(now, 0, &now_tm);
    
    return sprintf(buf, "%s %02d:%02d:%02d UTC\n",
                   days[now_tm.tm_wday],
                   now_tm.tm_hour, now_tm.tm_min, now_tm.tm_sec);
}

static struct kobj_attribute timelock_attr_enabled =
    __ATTR(enabled, 0644, timelock_enabled_show, timelock_enabled_store);
static struct kobj_attribute timelock_attr_add =
    __ATTR(add, 0200, NULL, timelock_add_store);
static struct kobj_attribute timelock_attr_list =
    __ATTR(list, 0444, timelock_list_show, NULL);
static struct kobj_attribute timelock_attr_time =
    __ATTR(current_time, 0444, timelock_time_show, NULL);

static struct attribute *timelock_attrs[] = {
    &timelock_attr_enabled.attr,
    &timelock_attr_add.attr,
    &timelock_attr_list.attr,
    &timelock_attr_time.attr,
    NULL,
};

static struct attribute_group timelock_attr_group = {
    .attrs = timelock_attrs,
};

static int __init shadow_timelock_init(void)
{
    struct kobject *parent;
    
    pr_info("ShadowOS: ⏰ Initializing Time-Locked Secrets\n");
    
    INIT_LIST_HEAD(&timelock_cfg.rules);
    spin_lock_init(&timelock_cfg.lock);
    timelock_cfg.enabled = false;
    
    parent = shadow_get_kobj();
    if (parent) {
        timelock_kobj = kobject_create_and_add("timelock", parent);
        if (timelock_kobj) {
            if (sysfs_create_group(timelock_kobj, &timelock_attr_group))
                pr_err("ShadowOS: Failed to create timelock sysfs\n");
        }
    }
    
    pr_info("ShadowOS: ⏰ Time-Locked Secrets ready\n");
    return 0;
}

static void __exit shadow_timelock_exit(void)
{
    struct timelock_rule *rule, *tmp;
    
    if (timelock_kobj) {
        sysfs_remove_group(timelock_kobj, &timelock_attr_group);
        kobject_put(timelock_kobj);
    }
    
    list_for_each_entry_safe(rule, tmp, &timelock_cfg.rules, list) {
        list_del(&rule->list);
        kfree(rule);
    }
    
    pr_info("ShadowOS: Time-Locked Secrets unloaded\n");
}

module_init(shadow_timelock_init);
module_exit(shadow_timelock_exit);
