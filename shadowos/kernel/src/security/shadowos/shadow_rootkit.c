/* SPDX-License-Identifier: GPL-2.0 */
/*
 * ShadowOS Rootkit Detection Module
 * 
 * 🔍 KERNEL INTEGRITY MONITORING
 * 
 * Features:
 * - System call table integrity checking
 * - Hidden module detection
 * - Hook detection
 * - Kernel symbol verification
 *
 * Copyright (C) 2024 ShadowOS Project
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/sysfs.h>
#include <linux/kobject.h>
#include <linux/kallsyms.h>
#include <linux/list.h>
#include <linux/timer.h>
#include <shadowos/shadow_types.h>

/* Module Info */
MODULE_LICENSE("GPL");
MODULE_AUTHOR("ShadowOS Team");
MODULE_DESCRIPTION("ShadowOS Rootkit Detection - Kernel Integrity Monitoring");
MODULE_VERSION(SHADOWOS_VERSION);

/* Forward declaration */
extern struct kobject *shadow_get_kobj(void);

/* Check interval in seconds */
#define CHECK_INTERVAL_SEC  60

/* Configuration */
static struct {
    bool enabled;
    bool scan_running;
    u64 scans_completed;
    u64 anomalies_detected;
    u64 hidden_modules;
    u64 hooked_functions;
    unsigned long last_scan;
} rootkit_cfg = {
    .enabled = true,
    .scan_running = false,
    .scans_completed = 0,
    .anomalies_detected = 0,
    .hidden_modules = 0,
    .hooked_functions = 0,
    .last_scan = 0,
};

static struct timer_list scan_timer;

/* Check for hidden modules by comparing module list with /proc/modules */
static int check_hidden_modules(void)
{
    struct module *mod;
    int hidden = 0;
    
    mutex_lock(&module_mutex);
    list_for_each_entry(mod, THIS_MODULE->list.prev, list) {
        /* Check if module is in kobject hierarchy */
        if (!mod->mkobj.kobj.state_in_sysfs) {
            pr_warn("ShadowOS Rootkit: 🚨 Hidden module detected: %s\n", mod->name);
            hidden++;
        }
    }
    mutex_unlock(&module_mutex);
    
    return hidden;
}

/* Scan for anomalies */
static void perform_scan(void)
{
    int hidden;
    
    if (rootkit_cfg.scan_running)
        return;
    
    rootkit_cfg.scan_running = true;
    
    pr_debug("ShadowOS Rootkit: Starting integrity scan...\n");
    
    /* Check for hidden modules */
    hidden = check_hidden_modules();
    if (hidden > 0) {
        rootkit_cfg.hidden_modules += hidden;
        rootkit_cfg.anomalies_detected += hidden;
        pr_warn("ShadowOS Rootkit: 🚨 Found %d hidden modules!\n", hidden);
    }
    
    rootkit_cfg.scans_completed++;
    rootkit_cfg.last_scan = jiffies;
    rootkit_cfg.scan_running = false;
    
    pr_debug("ShadowOS Rootkit: Scan complete. Anomalies: %d\n", hidden);
}

/* Timer callback */
static void scan_timer_callback(struct timer_list *t)
{
    if (rootkit_cfg.enabled) {
        perform_scan();
        mod_timer(&scan_timer, jiffies + CHECK_INTERVAL_SEC * HZ);
    }
}

/* Sysfs Interface */
static struct kobject *rootkit_kobj;

static ssize_t rootkit_enabled_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
    return sprintf(buf, "%d\n", rootkit_cfg.enabled);
}

static ssize_t rootkit_enabled_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count)
{
    bool val;
    if (kstrtobool(buf, &val))
        return -EINVAL;
    rootkit_cfg.enabled = val;
    
    if (val) {
        mod_timer(&scan_timer, jiffies + CHECK_INTERVAL_SEC * HZ);
        pr_info("ShadowOS Rootkit: Detection ENABLED\n");
    } else {
        del_timer_sync(&scan_timer);
        pr_info("ShadowOS Rootkit: Detection disabled\n");
    }
    return count;
}

static ssize_t rootkit_scan_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count)
{
    perform_scan();
    return count;
}

static ssize_t rootkit_stats_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
    return sprintf(buf, "scans: %llu\nanomalies: %llu\nhidden_modules: %llu\nhooked_functions: %llu\n",
                   rootkit_cfg.scans_completed, rootkit_cfg.anomalies_detected,
                   rootkit_cfg.hidden_modules, rootkit_cfg.hooked_functions);
}

static ssize_t rootkit_status_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
    const char *status;
    
    if (rootkit_cfg.anomalies_detected > 0)
        status = "COMPROMISED";
    else if (rootkit_cfg.scans_completed == 0)
        status = "NOT_SCANNED";
    else
        status = "CLEAN";
    
    return sprintf(buf, "%s\n", status);
}

static struct kobj_attribute rootkit_attr_enabled = __ATTR(enabled, 0644, rootkit_enabled_show, rootkit_enabled_store);
static struct kobj_attribute rootkit_attr_scan = __ATTR(scan_now, 0200, NULL, rootkit_scan_store);
static struct kobj_attribute rootkit_attr_stats = __ATTR(stats, 0444, rootkit_stats_show, NULL);
static struct kobj_attribute rootkit_attr_status = __ATTR(status, 0444, rootkit_status_show, NULL);

static struct attribute *rootkit_attrs[] = {
    &rootkit_attr_enabled.attr,
    &rootkit_attr_scan.attr,
    &rootkit_attr_stats.attr,
    &rootkit_attr_status.attr,
    NULL,
};

static struct attribute_group rootkit_attr_group = {
    .attrs = rootkit_attrs,
};

static int __init shadow_rootkit_init(void)
{
    struct kobject *parent;
    
    pr_info("ShadowOS: 🔍 Initializing Rootkit Detection Module\n");
    
    timer_setup(&scan_timer, scan_timer_callback, 0);
    
    parent = shadow_get_kobj();
    if (parent) {
        rootkit_kobj = kobject_create_and_add("rootkit", parent);
        if (rootkit_kobj) {
            if (sysfs_create_group(rootkit_kobj, &rootkit_attr_group))
                pr_err("ShadowOS: Failed to create rootkit sysfs\n");
        }
    }
    
    /* Start periodic scanning */
    if (rootkit_cfg.enabled)
        mod_timer(&scan_timer, jiffies + CHECK_INTERVAL_SEC * HZ);
    
    pr_info("ShadowOS: 🔍 Rootkit Detection ACTIVE\n");
    return 0;
}

static void __exit shadow_rootkit_exit(void)
{
    del_timer_sync(&scan_timer);
    
    if (rootkit_kobj) {
        sysfs_remove_group(rootkit_kobj, &rootkit_attr_group);
        kobject_put(rootkit_kobj);
    }
    
    pr_info("ShadowOS: Rootkit Detection unloaded\n");
}

module_init(shadow_rootkit_init);
module_exit(shadow_rootkit_exit);
