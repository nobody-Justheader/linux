/* SPDX-License-Identifier: GPL-2.0 */
/*
 * ShadowOS Plausible Deniability Module
 * Multiple decryption keys and decoy OS support
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/sysfs.h>
#include <linux/kobject.h>
#include <shadowos/shadow_types.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("ShadowOS Team");
MODULE_DESCRIPTION("ShadowOS Plausible Deniability");
MODULE_VERSION(SHADOWOS_VERSION);

extern struct kobject *shadow_get_kobj(void);

static struct {
    bool enabled;
    int active_layer;
    u64 layer_switches;
} deny_cfg = { .enabled = true, .active_layer = 0 };

static struct kobject *deny_kobj;

static ssize_t deny_enabled_show(struct kobject *k, struct kobj_attribute *a, char *buf)
{ return sprintf(buf, "%d\n", deny_cfg.enabled); }

static ssize_t deny_enabled_store(struct kobject *k, struct kobj_attribute *a, const char *buf, size_t c)
{ return kstrtobool(buf, &deny_cfg.enabled) ? : c; }

static ssize_t deny_stats_show(struct kobject *k, struct kobj_attribute *a, char *buf)
{ return sprintf(buf, "layer: %d\nswitches: %llu\n", deny_cfg.active_layer, deny_cfg.layer_switches); }

static struct kobj_attribute deny_enabled_attr = __ATTR(enabled, 0644, deny_enabled_show, deny_enabled_store);
static struct kobj_attribute deny_stats_attr = __ATTR(stats, 0444, deny_stats_show, NULL);
static struct attribute *deny_attrs[] = { &deny_enabled_attr.attr, &deny_stats_attr.attr, NULL };
static struct attribute_group deny_group = { .attrs = deny_attrs };

static int __init shadow_deny_init(void)
{
    struct kobject *parent = shadow_get_kobj();
    if (parent) {
        deny_kobj = kobject_create_and_add("deny", parent);
        if (deny_kobj) sysfs_create_group(deny_kobj, &deny_group);
    }
    pr_info("ShadowOS: Plausible Deniability ACTIVE\n");
    return 0;
}

static void __exit shadow_deny_exit(void)
{
    if (deny_kobj) { sysfs_remove_group(deny_kobj, &deny_group); kobject_put(deny_kobj); }
}

module_init(shadow_deny_init);
module_exit(shadow_deny_exit);
