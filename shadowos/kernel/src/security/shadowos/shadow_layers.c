/* SPDX-License-Identifier: GPL-2.0 */
/*
 * ShadowOS Reality Layers Module
 * Virtual filesystem layers showing different content to different users
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/sysfs.h>
#include <linux/kobject.h>
#include <shadowos/shadow_types.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("ShadowOS Team");
MODULE_DESCRIPTION("ShadowOS Reality Layers");
MODULE_VERSION(SHADOWOS_VERSION);

extern struct kobject *shadow_get_kobj(void);

static struct {
    bool enabled;
    int active_layer;
    int total_layers;
} layers_cfg = { .enabled = false, .active_layer = 0, .total_layers = 2 };

static struct kobject *layers_kobj;

static ssize_t layers_enabled_show(struct kobject *k, struct kobj_attribute *a, char *buf)
{ return sprintf(buf, "%d\n", layers_cfg.enabled); }

static ssize_t layers_enabled_store(struct kobject *k, struct kobj_attribute *a, const char *buf, size_t c)
{ return kstrtobool(buf, &layers_cfg.enabled) ? : c; }

static ssize_t layers_stats_show(struct kobject *k, struct kobj_attribute *a, char *buf)
{ return sprintf(buf, "active: %d\ntotal: %d\n", layers_cfg.active_layer, layers_cfg.total_layers); }

static struct kobj_attribute layers_enabled_attr = __ATTR(enabled, 0644, layers_enabled_show, layers_enabled_store);
static struct kobj_attribute layers_stats_attr = __ATTR(stats, 0444, layers_stats_show, NULL);
static struct attribute *layers_attrs[] = { &layers_enabled_attr.attr, &layers_stats_attr.attr, NULL };
static struct attribute_group layers_group = { .attrs = layers_attrs };

static int __init shadow_layers_init(void)
{
    struct kobject *parent = shadow_get_kobj();
    if (parent) {
        layers_kobj = kobject_create_and_add("layers", parent);
        if (layers_kobj) sysfs_create_group(layers_kobj, &layers_group);
    }
    pr_info("ShadowOS: Reality Layers ACTIVE\n");
    return 0;
}

static void __exit shadow_layers_exit(void)
{
    if (layers_kobj) { sysfs_remove_group(layers_kobj, &layers_group); kobject_put(layers_kobj); }
}

module_init(shadow_layers_init);
module_exit(shadow_layers_exit);
