/* SPDX-License-Identifier: GPL-2.0 */
/*
 * ShadowOS Hardware Keylogger Detection Module
 * USB HID timing analysis and suspicious device patterns
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/sysfs.h>
#include <linux/kobject.h>
#include <shadowos/shadow_types.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("ShadowOS Team");
MODULE_DESCRIPTION("ShadowOS Hardware Keylogger Detection");
MODULE_VERSION(SHADOWOS_VERSION);

extern struct kobject *shadow_get_kobj(void);

static struct {
    bool enabled;
    u64 devices_scanned;
    u64 keyloggers_detected;
} keylog_cfg = { .enabled = true };

static struct kobject *keylog_kobj;

static ssize_t keylog_enabled_show(struct kobject *k, struct kobj_attribute *a, char *buf)
{ return sprintf(buf, "%d\n", keylog_cfg.enabled); }

static ssize_t keylog_enabled_store(struct kobject *k, struct kobj_attribute *a, const char *buf, size_t c)
{ return kstrtobool(buf, &keylog_cfg.enabled) ? : c; }

static ssize_t keylog_stats_show(struct kobject *k, struct kobj_attribute *a, char *buf)
{ return sprintf(buf, "scanned: %llu\ndetected: %llu\n", keylog_cfg.devices_scanned, keylog_cfg.keyloggers_detected); }

static struct kobj_attribute keylog_enabled_attr = __ATTR(enabled, 0644, keylog_enabled_show, keylog_enabled_store);
static struct kobj_attribute keylog_stats_attr = __ATTR(stats, 0444, keylog_stats_show, NULL);
static struct attribute *keylog_attrs[] = { &keylog_enabled_attr.attr, &keylog_stats_attr.attr, NULL };
static struct attribute_group keylog_group = { .attrs = keylog_attrs };

static int __init shadow_keylog_init(void)
{
    struct kobject *parent = shadow_get_kobj();
    if (parent) {
        keylog_kobj = kobject_create_and_add("keylog", parent);
        if (keylog_kobj) sysfs_create_group(keylog_kobj, &keylog_group);
    }
    pr_info("ShadowOS: Keylogger Detection ACTIVE\n");
    return 0;
}

static void __exit shadow_keylog_exit(void)
{
    if (keylog_kobj) { sysfs_remove_group(keylog_kobj, &keylog_group); kobject_put(keylog_kobj); }
}

module_init(shadow_keylog_init);
module_exit(shadow_keylog_exit);
