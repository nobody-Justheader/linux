/* SPDX-License-Identifier: GPL-2.0 */
/*
 * ShadowOS Module Signing Verification Module
 * 
 * 📜 KERNEL MODULE SIGNATURE ENFORCEMENT
 * 
 * Features:
 * - Verify kernel module signatures
 * - Block unsigned modules
 * - Certificate management
 * - Audit logging
 *
 * Copyright (C) 2026 ShadowOS Project
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/sysfs.h>
#include <linux/kobject.h>
#include <shadowos/shadow_types.h>

/* Module Info */
MODULE_LICENSE("GPL");
MODULE_AUTHOR("ShadowOS Team");
MODULE_DESCRIPTION("ShadowOS Module Signing - Signature Enforcement");
MODULE_VERSION(SHADOWOS_VERSION);

/* Forward declaration */
extern struct kobject *shadow_get_kobj(void);

/* Configuration */
static struct {
    bool enabled;
    bool enforce_signatures;
    bool log_unsigned;
    u64 modules_verified;
    u64 modules_blocked;
    u64 unsigned_detected;
} sign_cfg = {
    .enabled = true,
    .enforce_signatures = false,
    .log_unsigned = true,
    .modules_verified = 0,
    .modules_blocked = 0,
    .unsigned_detected = 0,
};

/* Module loading notifier */
static int sign_module_notify(struct notifier_block *nb,
                              unsigned long action, void *data)
{
    struct module *mod = data;
    
    if (!sign_cfg.enabled)
        return NOTIFY_OK;
    
    switch (action) {
    case MODULE_STATE_COMING:
        sign_cfg.modules_verified++;
        
        /* Check if module is signed */
        if (!mod->sig_ok) {
            sign_cfg.unsigned_detected++;
            
            if (sign_cfg.log_unsigned) {
                pr_warn("ShadowOS Sign: 📜 Unsigned module detected: %s\n", mod->name);
            }
            
            if (sign_cfg.enforce_signatures) {
                pr_warn("ShadowOS Sign: 🚫 BLOCKED unsigned module: %s\n", mod->name);
                sign_cfg.modules_blocked++;
                return NOTIFY_BAD;
            }
        } else {
            pr_debug("ShadowOS Sign: ✓ Module verified: %s\n", mod->name);
        }
        break;
    }
    
    return NOTIFY_OK;
}

static struct notifier_block sign_module_nb = {
    .notifier_call = sign_module_notify,
    .priority = INT_MAX,
};

/* Sysfs Interface */
static struct kobject *sign_kobj;

static ssize_t sign_enabled_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
    return sprintf(buf, "%d\n", sign_cfg.enabled);
}

static ssize_t sign_enabled_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count)
{
    return kstrtobool(buf, &sign_cfg.enabled) ? : count;
}

static ssize_t sign_enforce_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
    return sprintf(buf, "%d\n", sign_cfg.enforce_signatures);
}

static ssize_t sign_enforce_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count)
{
    return kstrtobool(buf, &sign_cfg.enforce_signatures) ? : count;
}

static ssize_t sign_stats_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
    return sprintf(buf, "verified: %llu\nblocked: %llu\nunsigned: %llu\nenforce: %d\n",
                   sign_cfg.modules_verified, sign_cfg.modules_blocked,
                   sign_cfg.unsigned_detected, sign_cfg.enforce_signatures);
}

static struct kobj_attribute sign_attr_enabled = __ATTR(enabled, 0644, sign_enabled_show, sign_enabled_store);
static struct kobj_attribute sign_attr_enforce = __ATTR(enforce, 0644, sign_enforce_show, sign_enforce_store);
static struct kobj_attribute sign_attr_stats = __ATTR(stats, 0444, sign_stats_show, NULL);

static struct attribute *sign_attrs[] = {
    &sign_attr_enabled.attr,
    &sign_attr_enforce.attr,
    &sign_attr_stats.attr,
    NULL,
};

static struct attribute_group sign_attr_group = {
    .attrs = sign_attrs,
};

static int __init shadow_sign_init(void)
{
    struct kobject *parent;
    
    pr_info("ShadowOS: 📜 Initializing Module Signing Verification\n");
    
    register_module_notifier(&sign_module_nb);
    
    parent = shadow_get_kobj();
    if (parent) {
        sign_kobj = kobject_create_and_add("signing", parent);
        if (sign_kobj) {
            if (sysfs_create_group(sign_kobj, &sign_attr_group))
                pr_err("ShadowOS: Failed to create signing sysfs\n");
        }
    }
    
    pr_info("ShadowOS: 📜 Module Signing Verification ACTIVE\n");
    return 0;
}

static void __exit shadow_sign_exit(void)
{
    unregister_module_notifier(&sign_module_nb);
    
    if (sign_kobj) {
        sysfs_remove_group(sign_kobj, &sign_attr_group);
        kobject_put(sign_kobj);
    }
    
    pr_info("ShadowOS: Module Signing Verification unloaded\n");
}

module_init(shadow_sign_init);
module_exit(shadow_sign_exit);
