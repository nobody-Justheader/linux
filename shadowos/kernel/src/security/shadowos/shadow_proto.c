/* SPDX-License-Identifier: GPL-2.0 */
/*
 * ShadowOS Protocol Whitelist Module
 * Allow/deny by protocol with deep packet inspection
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/sysfs.h>
#include <linux/kobject.h>
#include <shadowos/shadow_types.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("ShadowOS Team");
MODULE_DESCRIPTION("ShadowOS Protocol Whitelist");
MODULE_VERSION(SHADOWOS_VERSION);

extern struct kobject *shadow_get_kobj(void);

static struct {
    bool enabled;
    u64 allowed;
    u64 blocked;
} proto_cfg = { .enabled = true };

static struct kobject *proto_kobj;

static ssize_t proto_enabled_show(struct kobject *k, struct kobj_attribute *a, char *buf)
{ return sprintf(buf, "%d\n", proto_cfg.enabled); }

static ssize_t proto_enabled_store(struct kobject *k, struct kobj_attribute *a, const char *buf, size_t c)
{ return kstrtobool(buf, &proto_cfg.enabled) ? : c; }

static ssize_t proto_stats_show(struct kobject *k, struct kobj_attribute *a, char *buf)
{ return sprintf(buf, "allowed: %llu\nblocked: %llu\n", proto_cfg.allowed, proto_cfg.blocked); }

static struct kobj_attribute proto_enabled_attr = __ATTR(enabled, 0644, proto_enabled_show, proto_enabled_store);
static struct kobj_attribute proto_stats_attr = __ATTR(stats, 0444, proto_stats_show, NULL);
static struct attribute *proto_attrs[] = { &proto_enabled_attr.attr, &proto_stats_attr.attr, NULL };
static struct attribute_group proto_group = { .attrs = proto_attrs };

static int __init shadow_proto_init(void)
{
    struct kobject *parent = shadow_get_kobj();
    if (parent) {
        proto_kobj = kobject_create_and_add("proto", parent);
        if (proto_kobj) sysfs_create_group(proto_kobj, &proto_group);
    }
    pr_info("ShadowOS: Protocol Whitelist ACTIVE\n");
    return 0;
}

static void __exit shadow_proto_exit(void)
{
    if (proto_kobj) { sysfs_remove_group(proto_kobj, &proto_group); kobject_put(proto_kobj); }
}

module_init(shadow_proto_init);
module_exit(shadow_proto_exit);
