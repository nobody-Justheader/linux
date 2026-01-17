/* SPDX-License-Identifier: GPL-2.0 */
/*
 * ShadowOS Hidden Partition (Steganographic) Module
 * Hidden volumes and decoy filesystems
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/sysfs.h>
#include <linux/kobject.h>
#include <shadowos/shadow_types.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("ShadowOS Team");
MODULE_DESCRIPTION("ShadowOS Hidden Partition");
MODULE_VERSION(SHADOWOS_VERSION);

extern struct kobject *shadow_get_kobj(void);

static struct {
    bool enabled;
    int hidden_volumes;
    u64 bytes_hidden;
} stego_cfg = { .enabled = false };

static struct kobject *stego_kobj;

static ssize_t stego_enabled_show(struct kobject *k, struct kobj_attribute *a, char *buf)
{ return sprintf(buf, "%d\n", stego_cfg.enabled); }

static ssize_t stego_enabled_store(struct kobject *k, struct kobj_attribute *a, const char *buf, size_t c)
{ return kstrtobool(buf, &stego_cfg.enabled) ? : c; }

static ssize_t stego_stats_show(struct kobject *k, struct kobj_attribute *a, char *buf)
{ return sprintf(buf, "volumes: %d\nbytes: %llu\n", stego_cfg.hidden_volumes, stego_cfg.bytes_hidden); }

static struct kobj_attribute stego_enabled_attr = __ATTR(enabled, 0644, stego_enabled_show, stego_enabled_store);
static struct kobj_attribute stego_stats_attr = __ATTR(stats, 0444, stego_stats_show, NULL);
static struct attribute *stego_attrs[] = { &stego_enabled_attr.attr, &stego_stats_attr.attr, NULL };
static struct attribute_group stego_group = { .attrs = stego_attrs };

static int __init shadow_stego_init(void)
{
    struct kobject *parent = shadow_get_kobj();
    if (parent) {
        stego_kobj = kobject_create_and_add("stego", parent);
        if (stego_kobj) sysfs_create_group(stego_kobj, &stego_group);
    }
    pr_info("ShadowOS: Hidden Partition ACTIVE\n");
    return 0;
}

static void __exit shadow_stego_exit(void)
{
    if (stego_kobj) { sysfs_remove_group(stego_kobj, &stego_group); kobject_put(stego_kobj); }
}

module_init(shadow_stego_init);
module_exit(shadow_stego_exit);
