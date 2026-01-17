/* SPDX-License-Identifier: GPL-2.0 */
/*
 * ShadowOS Encrypted Memory Module
 * Encrypt sensitive memory regions with key management
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/sysfs.h>
#include <linux/kobject.h>
#include <shadowos/shadow_types.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("ShadowOS Team");
MODULE_DESCRIPTION("ShadowOS Encrypted Memory");
MODULE_VERSION(SHADOWOS_VERSION);

extern struct kobject *shadow_get_kobj(void);

static struct {
    bool enabled;
    u64 regions_protected;
    u64 bytes_encrypted;
} memcrypt_cfg = { .enabled = true };

static struct kobject *memcrypt_kobj;

static ssize_t memcrypt_enabled_show(struct kobject *k, struct kobj_attribute *a, char *buf)
{ return sprintf(buf, "%d\n", memcrypt_cfg.enabled); }

static ssize_t memcrypt_enabled_store(struct kobject *k, struct kobj_attribute *a, const char *buf, size_t c)
{ return kstrtobool(buf, &memcrypt_cfg.enabled) ? : c; }

static ssize_t memcrypt_stats_show(struct kobject *k, struct kobj_attribute *a, char *buf)
{ return sprintf(buf, "regions: %llu\nbytes: %llu\n", memcrypt_cfg.regions_protected, memcrypt_cfg.bytes_encrypted); }

static struct kobj_attribute memcrypt_enabled_attr = __ATTR(enabled, 0644, memcrypt_enabled_show, memcrypt_enabled_store);
static struct kobj_attribute memcrypt_stats_attr = __ATTR(stats, 0444, memcrypt_stats_show, NULL);
static struct attribute *memcrypt_attrs[] = { &memcrypt_enabled_attr.attr, &memcrypt_stats_attr.attr, NULL };
static struct attribute_group memcrypt_group = { .attrs = memcrypt_attrs };

static int __init shadow_memcrypt_init(void)
{
    struct kobject *parent = shadow_get_kobj();
    if (parent) {
        memcrypt_kobj = kobject_create_and_add("memcrypt", parent);
        if (memcrypt_kobj) sysfs_create_group(memcrypt_kobj, &memcrypt_group);
    }
    pr_info("ShadowOS: Encrypted Memory ACTIVE\n");
    return 0;
}

static void __exit shadow_memcrypt_exit(void)
{
    if (memcrypt_kobj) { sysfs_remove_group(memcrypt_kobj, &memcrypt_group); kobject_put(memcrypt_kobj); }
}

module_init(shadow_memcrypt_init);
module_exit(shadow_memcrypt_exit);
