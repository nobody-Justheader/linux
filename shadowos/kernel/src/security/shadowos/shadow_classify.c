/* SPDX-License-Identifier: GPL-2.0 */
/*
 * ShadowOS Traffic Classification Module
 * Application protocol detection and anomaly scoring
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/sysfs.h>
#include <linux/kobject.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <shadowos/shadow_types.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("ShadowOS Team");
MODULE_DESCRIPTION("ShadowOS Traffic Classification");
MODULE_VERSION(SHADOWOS_VERSION);

extern struct kobject *shadow_get_kobj(void);

static struct {
    bool enabled;
    u64 packets_classified;
    u64 anomalies_detected;
} classify_cfg = { .enabled = true };

static struct kobject *classify_kobj;

static ssize_t classify_enabled_show(struct kobject *k, struct kobj_attribute *a, char *buf)
{ return sprintf(buf, "%d\n", classify_cfg.enabled); }

static ssize_t classify_enabled_store(struct kobject *k, struct kobj_attribute *a, const char *buf, size_t c)
{ return kstrtobool(buf, &classify_cfg.enabled) ? : c; }

static ssize_t classify_stats_show(struct kobject *k, struct kobj_attribute *a, char *buf)
{ return sprintf(buf, "classified: %llu\nanomalies: %llu\n", classify_cfg.packets_classified, classify_cfg.anomalies_detected); }

static struct kobj_attribute classify_enabled_attr = __ATTR(enabled, 0644, classify_enabled_show, classify_enabled_store);
static struct kobj_attribute classify_stats_attr = __ATTR(stats, 0444, classify_stats_show, NULL);
static struct attribute *classify_attrs[] = { &classify_enabled_attr.attr, &classify_stats_attr.attr, NULL };
static struct attribute_group classify_group = { .attrs = classify_attrs };

static int __init shadow_classify_init(void)
{
    struct kobject *parent = shadow_get_kobj();
    if (parent) {
        classify_kobj = kobject_create_and_add("classify", parent);
        if (classify_kobj) sysfs_create_group(classify_kobj, &classify_group);
    }
    pr_info("ShadowOS: Traffic Classification ACTIVE\n");
    return 0;
}

static void __exit shadow_classify_exit(void)
{
    if (classify_kobj) { sysfs_remove_group(classify_kobj, &classify_group); kobject_put(classify_kobj); }
}

module_init(shadow_classify_init);
module_exit(shadow_classify_exit);
