/* SPDX-License-Identifier: GPL-2.0 */
/*
 * ShadowOS Lookalike Detection Module
 * Domain typosquatting and visual similarity analysis
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/sysfs.h>
#include <linux/kobject.h>
#include <shadowos/shadow_types.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("ShadowOS Team");
MODULE_DESCRIPTION("ShadowOS Lookalike Detection");
MODULE_VERSION(SHADOWOS_VERSION);

extern struct kobject *shadow_get_kobj(void);

static struct {
    bool enabled;
    u64 domains_checked;
    u64 lookalikes_detected;
} lookalike_cfg = { .enabled = true };

static struct kobject *lookalike_kobj;

static ssize_t lookalike_enabled_show(struct kobject *k, struct kobj_attribute *a, char *buf)
{ return sprintf(buf, "%d\n", lookalike_cfg.enabled); }

static ssize_t lookalike_enabled_store(struct kobject *k, struct kobj_attribute *a, const char *buf, size_t c)
{ return kstrtobool(buf, &lookalike_cfg.enabled) ? : c; }

static ssize_t lookalike_stats_show(struct kobject *k, struct kobj_attribute *a, char *buf)
{ return sprintf(buf, "checked: %llu\ndetected: %llu\n", lookalike_cfg.domains_checked, lookalike_cfg.lookalikes_detected); }

static struct kobj_attribute lookalike_enabled_attr = __ATTR(enabled, 0644, lookalike_enabled_show, lookalike_enabled_store);
static struct kobj_attribute lookalike_stats_attr = __ATTR(stats, 0444, lookalike_stats_show, NULL);
static struct attribute *lookalike_attrs[] = { &lookalike_enabled_attr.attr, &lookalike_stats_attr.attr, NULL };
static struct attribute_group lookalike_group = { .attrs = lookalike_attrs };

static int __init shadow_lookalike_init(void)
{
    struct kobject *parent = shadow_get_kobj();
    if (parent) {
        lookalike_kobj = kobject_create_and_add("lookalike", parent);
        if (lookalike_kobj) sysfs_create_group(lookalike_kobj, &lookalike_group);
    }
    pr_info("ShadowOS: Lookalike Detection ACTIVE\n");
    return 0;
}

static void __exit shadow_lookalike_exit(void)
{
    if (lookalike_kobj) { sysfs_remove_group(lookalike_kobj, &lookalike_group); kobject_put(lookalike_kobj); }
}

module_init(shadow_lookalike_init);
module_exit(shadow_lookalike_exit);
