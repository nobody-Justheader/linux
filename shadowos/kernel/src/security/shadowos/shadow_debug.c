/* SPDX-License-Identifier: GPL-2.0 */
/*
 * ShadowOS Anti-Debugging Module
 * Detect debugging attempts and prevent core dumps
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/sysfs.h>
#include <linux/kobject.h>
#include <shadowos/shadow_types.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("ShadowOS Team");
MODULE_DESCRIPTION("ShadowOS Anti-Debugging");
MODULE_VERSION(SHADOWOS_VERSION);

extern struct kobject *shadow_get_kobj(void);

static struct {
    bool enabled;
    bool block_ptrace;
    bool block_coredump;
    u64 debug_attempts;
} debug_cfg = { .enabled = true, .block_ptrace = true, .block_coredump = true };

static struct kobject *debug_kobj;

static ssize_t debug_enabled_show(struct kobject *k, struct kobj_attribute *a, char *buf)
{ return sprintf(buf, "%d\n", debug_cfg.enabled); }

static ssize_t debug_enabled_store(struct kobject *k, struct kobj_attribute *a, const char *buf, size_t c)
{ return kstrtobool(buf, &debug_cfg.enabled) ? : c; }

static ssize_t debug_stats_show(struct kobject *k, struct kobj_attribute *a, char *buf)
{ return sprintf(buf, "attempts: %llu\nptrace_blocked: %d\ncoredump_blocked: %d\n", 
    debug_cfg.debug_attempts, debug_cfg.block_ptrace, debug_cfg.block_coredump); }

static struct kobj_attribute debug_enabled_attr = __ATTR(enabled, 0644, debug_enabled_show, debug_enabled_store);
static struct kobj_attribute debug_stats_attr = __ATTR(stats, 0444, debug_stats_show, NULL);
static struct attribute *debug_attrs[] = { &debug_enabled_attr.attr, &debug_stats_attr.attr, NULL };
static struct attribute_group debug_group = { .attrs = debug_attrs };

static int __init shadow_debug_init(void)
{
    struct kobject *parent = shadow_get_kobj();
    if (parent) {
        debug_kobj = kobject_create_and_add("debug", parent);
        if (debug_kobj) sysfs_create_group(debug_kobj, &debug_group);
    }
    pr_info("ShadowOS: Anti-Debugging ACTIVE\n");
    return 0;
}

static void __exit shadow_debug_exit(void)
{
    if (debug_kobj) { sysfs_remove_group(debug_kobj, &debug_group); kobject_put(debug_kobj); }
}

module_init(shadow_debug_init);
module_exit(shadow_debug_exit);
