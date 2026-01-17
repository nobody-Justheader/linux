/* SPDX-License-Identifier: GPL-2.0 */
/*
 * ShadowOS Attacker Profiling Module
 * Track attack patterns and build fingerprints
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/sysfs.h>
#include <linux/kobject.h>
#include <shadowos/shadow_types.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("ShadowOS Team");
MODULE_DESCRIPTION("ShadowOS Attacker Profiling");
MODULE_VERSION(SHADOWOS_VERSION);

extern struct kobject *shadow_get_kobj(void);

static struct {
    bool enabled;
    u64 attackers_profiled;
    u64 patterns_matched;
} profile_cfg = { .enabled = true };

static struct kobject *profile_kobj;

static ssize_t profile_enabled_show(struct kobject *k, struct kobj_attribute *a, char *buf)
{ return sprintf(buf, "%d\n", profile_cfg.enabled); }

static ssize_t profile_enabled_store(struct kobject *k, struct kobj_attribute *a, const char *buf, size_t c)
{ return kstrtobool(buf, &profile_cfg.enabled) ? : c; }

static ssize_t profile_stats_show(struct kobject *k, struct kobj_attribute *a, char *buf)
{ return sprintf(buf, "profiled: %llu\npatterns: %llu\n", profile_cfg.attackers_profiled, profile_cfg.patterns_matched); }

static struct kobj_attribute profile_enabled_attr = __ATTR(enabled, 0644, profile_enabled_show, profile_enabled_store);
static struct kobj_attribute profile_stats_attr = __ATTR(stats, 0444, profile_stats_show, NULL);
static struct attribute *profile_attrs[] = { &profile_enabled_attr.attr, &profile_stats_attr.attr, NULL };
static struct attribute_group profile_group = { .attrs = profile_attrs };

static int __init shadow_profile_init(void)
{
    struct kobject *parent = shadow_get_kobj();
    if (parent) {
        profile_kobj = kobject_create_and_add("profile", parent);
        if (profile_kobj) sysfs_create_group(profile_kobj, &profile_group);
    }
    pr_info("ShadowOS: Attacker Profiling ACTIVE\n");
    return 0;
}

static void __exit shadow_profile_exit(void)
{
    if (profile_kobj) { sysfs_remove_group(profile_kobj, &profile_group); kobject_put(profile_kobj); }
}

module_init(shadow_profile_init);
module_exit(shadow_profile_exit);
