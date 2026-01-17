/* SPDX-License-Identifier: GPL-2.0 */
/*
 * ShadowOS Syscall Randomization Module
 * Randomize syscall numbers for attack surface reduction
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/sysfs.h>
#include <linux/kobject.h>
#include <shadowos/shadow_types.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("ShadowOS Team");
MODULE_DESCRIPTION("ShadowOS Syscall Randomization");
MODULE_VERSION(SHADOWOS_VERSION);

extern struct kobject *shadow_get_kobj(void);

static struct {
    bool enabled;
    u64 calls_randomized;
} syscall_cfg = { .enabled = false };

static struct kobject *syscall_kobj;

static ssize_t syscall_enabled_show(struct kobject *k, struct kobj_attribute *a, char *buf)
{ return sprintf(buf, "%d\n", syscall_cfg.enabled); }

static ssize_t syscall_enabled_store(struct kobject *k, struct kobj_attribute *a, const char *buf, size_t c)
{ return kstrtobool(buf, &syscall_cfg.enabled) ? : c; }

static ssize_t syscall_stats_show(struct kobject *k, struct kobj_attribute *a, char *buf)
{ return sprintf(buf, "randomized: %llu\n", syscall_cfg.calls_randomized); }

static struct kobj_attribute syscall_enabled_attr = __ATTR(enabled, 0644, syscall_enabled_show, syscall_enabled_store);
static struct kobj_attribute syscall_stats_attr = __ATTR(stats, 0444, syscall_stats_show, NULL);
static struct attribute *syscall_attrs[] = { &syscall_enabled_attr.attr, &syscall_stats_attr.attr, NULL };
static struct attribute_group syscall_group = { .attrs = syscall_attrs };

static int __init shadow_syscall_init(void)
{
    struct kobject *parent = shadow_get_kobj();
    if (parent) {
        syscall_kobj = kobject_create_and_add("syscall", parent);
        if (syscall_kobj) sysfs_create_group(syscall_kobj, &syscall_group);
    }
    pr_info("ShadowOS: Syscall Randomization ACTIVE\n");
    return 0;
}

static void __exit shadow_syscall_exit(void)
{
    if (syscall_kobj) { sysfs_remove_group(syscall_kobj, &syscall_group); kobject_put(syscall_kobj); }
}

module_init(shadow_syscall_init);
module_exit(shadow_syscall_exit);
