/* SPDX-License-Identifier: GPL-2.0 */
/*
 * ShadowOS Auto-Escalation Module
 * Automatic DEFCON level changes based on threat detection
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/sysfs.h>
#include <linux/kobject.h>
#include <shadowos/shadow_types.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("ShadowOS Team");
MODULE_DESCRIPTION("ShadowOS Auto-Escalation");
MODULE_VERSION(SHADOWOS_VERSION);

extern struct kobject *shadow_get_kobj(void);
extern int shadow_defcon_escalate(void);

static struct {
    bool enabled;
    int threat_threshold;
    u64 auto_escalations;
} escalate_cfg = { .enabled = true, .threat_threshold = 5 };

static struct kobject *escalate_kobj;

static ssize_t escalate_enabled_show(struct kobject *k, struct kobj_attribute *a, char *buf)
{ return sprintf(buf, "%d\n", escalate_cfg.enabled); }

static ssize_t escalate_enabled_store(struct kobject *k, struct kobj_attribute *a, const char *buf, size_t c)
{ return kstrtobool(buf, &escalate_cfg.enabled) ? : c; }

static ssize_t escalate_stats_show(struct kobject *k, struct kobj_attribute *a, char *buf)
{ return sprintf(buf, "auto_escalations: %llu\nthreshold: %d\n", escalate_cfg.auto_escalations, escalate_cfg.threat_threshold); }

static struct kobj_attribute escalate_enabled_attr = __ATTR(enabled, 0644, escalate_enabled_show, escalate_enabled_store);
static struct kobj_attribute escalate_stats_attr = __ATTR(stats, 0444, escalate_stats_show, NULL);
static struct attribute *escalate_attrs[] = { &escalate_enabled_attr.attr, &escalate_stats_attr.attr, NULL };
static struct attribute_group escalate_group = { .attrs = escalate_attrs };

static int __init shadow_escalate_init(void)
{
    struct kobject *parent = shadow_get_kobj();
    if (parent) {
        escalate_kobj = kobject_create_and_add("escalate", parent);
        if (escalate_kobj) sysfs_create_group(escalate_kobj, &escalate_group);
    }
    pr_info("ShadowOS: Auto-Escalation ACTIVE\n");
    return 0;
}

static void __exit shadow_escalate_exit(void)
{
    if (escalate_kobj) { sysfs_remove_group(escalate_kobj, &escalate_group); kobject_put(escalate_kobj); }
}

module_init(shadow_escalate_init);
module_exit(shadow_escalate_exit);
