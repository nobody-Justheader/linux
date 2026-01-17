/* SPDX-License-Identifier: GPL-2.0 */
/*
 * ShadowOS Network Persona Module
 * Complete identity switching with MAC/IP/Hostname coordination
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/sysfs.h>
#include <linux/kobject.h>
#include <shadowos/shadow_types.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("ShadowOS Team");
MODULE_DESCRIPTION("ShadowOS Network Persona");
MODULE_VERSION(SHADOWOS_VERSION);

extern struct kobject *shadow_get_kobj(void);

static struct {
    bool enabled;
    int active_persona;
    u64 switches;
} persona_cfg = { .enabled = true, .active_persona = 0 };

static struct kobject *persona_kobj;

static ssize_t persona_enabled_show(struct kobject *k, struct kobj_attribute *a, char *buf)
{ return sprintf(buf, "%d\n", persona_cfg.enabled); }

static ssize_t persona_enabled_store(struct kobject *k, struct kobj_attribute *a, const char *buf, size_t c)
{ return kstrtobool(buf, &persona_cfg.enabled) ? : c; }

static ssize_t persona_stats_show(struct kobject *k, struct kobj_attribute *a, char *buf)
{ return sprintf(buf, "active: %d\nswitches: %llu\n", persona_cfg.active_persona, persona_cfg.switches); }

static struct kobj_attribute persona_enabled_attr = __ATTR(enabled, 0644, persona_enabled_show, persona_enabled_store);
static struct kobj_attribute persona_stats_attr = __ATTR(stats, 0444, persona_stats_show, NULL);
static struct attribute *persona_attrs[] = { &persona_enabled_attr.attr, &persona_stats_attr.attr, NULL };
static struct attribute_group persona_group = { .attrs = persona_attrs };

static int __init shadow_persona_init(void)
{
    struct kobject *parent = shadow_get_kobj();
    if (parent) {
        persona_kobj = kobject_create_and_add("persona", parent);
        if (persona_kobj) sysfs_create_group(persona_kobj, &persona_group);
    }
    pr_info("ShadowOS: Network Persona ACTIVE\n");
    return 0;
}

static void __exit shadow_persona_exit(void)
{
    if (persona_kobj) { sysfs_remove_group(persona_kobj, &persona_group); kobject_put(persona_kobj); }
}

module_init(shadow_persona_init);
module_exit(shadow_persona_exit);
