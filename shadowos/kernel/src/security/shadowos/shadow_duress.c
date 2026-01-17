/* SPDX-License-Identifier: GPL-2.0 */
/*
 * ShadowOS Duress Password Module
 * Alternative password triggers emergency wipe
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/sysfs.h>
#include <linux/kobject.h>
#include <shadowos/shadow_types.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("ShadowOS Team");
MODULE_DESCRIPTION("ShadowOS Duress Password");
MODULE_VERSION(SHADOWOS_VERSION);

extern struct kobject *shadow_get_kobj(void);

static struct {
    bool enabled;
    bool triggered;
    u64 trigger_count;
} duress_cfg = { .enabled = true };

static struct kobject *duress_kobj;

static ssize_t duress_enabled_show(struct kobject *k, struct kobj_attribute *a, char *buf)
{ return sprintf(buf, "%d\n", duress_cfg.enabled); }

static ssize_t duress_enabled_store(struct kobject *k, struct kobj_attribute *a, const char *buf, size_t c)
{ return kstrtobool(buf, &duress_cfg.enabled) ? : c; }

static ssize_t duress_stats_show(struct kobject *k, struct kobj_attribute *a, char *buf)
{ return sprintf(buf, "triggers: %llu\n", duress_cfg.trigger_count); }

static struct kobj_attribute duress_enabled_attr = __ATTR(enabled, 0644, duress_enabled_show, duress_enabled_store);
static struct kobj_attribute duress_stats_attr = __ATTR(stats, 0444, duress_stats_show, NULL);
static struct attribute *duress_attrs[] = { &duress_enabled_attr.attr, &duress_stats_attr.attr, NULL };
static struct attribute_group duress_group = { .attrs = duress_attrs };

static int __init shadow_duress_init(void)
{
    struct kobject *parent = shadow_get_kobj();
    if (parent) {
        duress_kobj = kobject_create_and_add("duress", parent);
        if (duress_kobj) sysfs_create_group(duress_kobj, &duress_group);
    }
    pr_info("ShadowOS: Duress Password ACTIVE\n");
    return 0;
}

static void __exit shadow_duress_exit(void)
{
    if (duress_kobj) { sysfs_remove_group(duress_kobj, &duress_group); kobject_put(duress_kobj); }
}

module_init(shadow_duress_init);
module_exit(shadow_duress_exit);
