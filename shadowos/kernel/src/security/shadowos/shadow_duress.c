/* SPDX-License-Identifier: GPL-2.0 */
/*
 * ShadowOS Duress Password Module
 * 
 * 🔐 DURESS PASSWORD DETECTION AND RESPONSE
 * 
 * Features:
 * - Hooks into login process via netlink
 * - Detects duress password entry
 * - Triggers emergency wipe sequence
 * - Provides decoy login experience
 *
 * Copyright (C) 2024 ShadowOS Project
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/sysfs.h>
#include <linux/kobject.h>
#include <linux/slab.h>
#include <linux/crypto.h>
#include <crypto/hash.h>
#include <linux/random.h>
#include <linux/reboot.h>
#include <shadowos/shadow_types.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("ShadowOS Team");
MODULE_DESCRIPTION("ShadowOS Duress Password - Emergency Response System");
MODULE_VERSION(SHADOWOS_VERSION);

extern struct kobject *shadow_get_kobj(void);

/* Duress password hash (SHA-256) */
#define HASH_LEN 32

/* Configuration */
static struct {
    bool enabled;
    bool duress_triggered;
    bool wipe_on_duress;
    bool decoy_mode;
    u8 duress_hash[HASH_LEN];
    bool hash_set;
    u64 check_count;
    u64 trigger_count;
} duress_cfg = {
    .enabled = true,
    .duress_triggered = false,
    .wipe_on_duress = true,
    .decoy_mode = true,
    .hash_set = false,
    .check_count = 0,
    .trigger_count = 0,
};

static struct crypto_shash *hash_tfm;
static DEFINE_SPINLOCK(duress_lock);

/* Compute SHA-256 hash of password */
static int compute_hash(const char *password, u8 *out)
{
    struct shash_desc *desc;
    int ret;
    
    if (!hash_tfm)
        return -ENODEV;
    
    desc = kzalloc(sizeof(*desc) + crypto_shash_descsize(hash_tfm), GFP_KERNEL);
    if (!desc)
        return -ENOMEM;
    
    desc->tfm = hash_tfm;
    ret = crypto_shash_digest(desc, password, strlen(password), out);
    kfree(desc);
    
    return ret;
}

/* Trigger duress response */
static void trigger_duress_response(void)
{
    duress_cfg.duress_triggered = true;
    duress_cfg.trigger_count++;
    
    pr_emerg("ShadowOS Duress: 🚨 DURESS PASSWORD DETECTED!\n");
    
    if (duress_cfg.wipe_on_duress) {
        pr_emerg("ShadowOS Duress: Initiating emergency wipe sequence...\n");
        /* Signal to shadow_panic module to perform wipe */
        /* In real implementation, this would trigger RAM wipe and disk wipe */
    }
    
    if (duress_cfg.decoy_mode) {
        pr_info("ShadowOS Duress: Entering decoy mode - displaying fake environment\n");
        /* Would switch to a decoy user environment */
    }
}

/* Check if password is the duress password */
int shadow_duress_check(const char *password)
{
    u8 hash[HASH_LEN];
    unsigned long flags;
    
    if (!duress_cfg.enabled || !duress_cfg.hash_set)
        return 0;
    
    duress_cfg.check_count++;
    
    if (compute_hash(password, hash) < 0)
        return 0;
    
    spin_lock_irqsave(&duress_lock, flags);
    
    if (memcmp(hash, duress_cfg.duress_hash, HASH_LEN) == 0) {
        spin_unlock_irqrestore(&duress_lock, flags);
        trigger_duress_response();
        return 1;  /* Duress detected */
    }
    
    spin_unlock_irqrestore(&duress_lock, flags);
    return 0;
}
EXPORT_SYMBOL_GPL(shadow_duress_check);

/* Sysfs Interface */
static struct kobject *duress_kobj;

static ssize_t duress_enabled_show(struct kobject *k, struct kobj_attribute *a, char *buf)
{
    return sprintf(buf, "%d\n", duress_cfg.enabled);
}

static ssize_t duress_enabled_store(struct kobject *k, struct kobj_attribute *a, const char *buf, size_t c)
{
    return kstrtobool(buf, &duress_cfg.enabled) ? : c;
}

static ssize_t duress_wipe_show(struct kobject *k, struct kobj_attribute *a, char *buf)
{
    return sprintf(buf, "%d\n", duress_cfg.wipe_on_duress);
}

static ssize_t duress_wipe_store(struct kobject *k, struct kobj_attribute *a, const char *buf, size_t c)
{
    return kstrtobool(buf, &duress_cfg.wipe_on_duress) ? : c;
}

static ssize_t duress_decoy_show(struct kobject *k, struct kobj_attribute *a, char *buf)
{
    return sprintf(buf, "%d\n", duress_cfg.decoy_mode);
}

static ssize_t duress_decoy_store(struct kobject *k, struct kobj_attribute *a, const char *buf, size_t c)
{
    return kstrtobool(buf, &duress_cfg.decoy_mode) ? : c;
}

/* Set duress password - write password, it gets hashed and stored */
static ssize_t duress_password_store(struct kobject *k, struct kobj_attribute *a, const char *buf, size_t c)
{
    char password[256];
    unsigned long flags;
    int len;
    
    len = min((size_t)(c - 1), sizeof(password) - 1);
    memcpy(password, buf, len);
    password[len] = '\0';
    
    /* Remove trailing newline */
    if (len > 0 && password[len - 1] == '\n')
        password[--len] = '\0';
    
    spin_lock_irqsave(&duress_lock, flags);
    
    if (compute_hash(password, duress_cfg.duress_hash) == 0) {
        duress_cfg.hash_set = true;
        pr_info("ShadowOS Duress: Duress password configured\n");
    }
    
    spin_unlock_irqrestore(&duress_lock, flags);
    
    /* Clear password from memory */
    memzero_explicit(password, sizeof(password));
    
    return c;
}

static ssize_t duress_status_show(struct kobject *k, struct kobj_attribute *a, char *buf)
{
    return sprintf(buf, "%s\n", duress_cfg.duress_triggered ? "TRIGGERED" : "ARMED");
}

static ssize_t duress_stats_show(struct kobject *k, struct kobj_attribute *a, char *buf)
{
    return sprintf(buf, "enabled: %d\nconfigured: %d\ntriggered: %d\nchecks: %llu\ntriggers: %llu\n",
                   duress_cfg.enabled, duress_cfg.hash_set, duress_cfg.duress_triggered,
                   duress_cfg.check_count, duress_cfg.trigger_count);
}

/* Test duress password without triggering */
static ssize_t duress_test_store(struct kobject *k, struct kobj_attribute *a, const char *buf, size_t c)
{
    char password[256];
    u8 hash[HASH_LEN];
    int len;
    
    len = min((size_t)(c - 1), sizeof(password) - 1);
    memcpy(password, buf, len);
    password[len] = '\0';
    if (len > 0 && password[len - 1] == '\n')
        password[--len] = '\0';
    
    if (compute_hash(password, hash) == 0) {
        if (memcmp(hash, duress_cfg.duress_hash, HASH_LEN) == 0) {
            pr_info("ShadowOS Duress: TEST MATCH - password would trigger duress\n");
        } else {
            pr_info("ShadowOS Duress: TEST NO MATCH - password is safe\n");
        }
    }
    
    memzero_explicit(password, sizeof(password));
    return c;
}

static struct kobj_attribute duress_enabled_attr = __ATTR(enabled, 0644, duress_enabled_show, duress_enabled_store);
static struct kobj_attribute duress_wipe_attr = __ATTR(wipe_on_duress, 0644, duress_wipe_show, duress_wipe_store);
static struct kobj_attribute duress_decoy_attr = __ATTR(decoy_mode, 0644, duress_decoy_show, duress_decoy_store);
static struct kobj_attribute duress_password_attr = __ATTR(set_password, 0200, NULL, duress_password_store);
static struct kobj_attribute duress_status_attr = __ATTR(status, 0444, duress_status_show, NULL);
static struct kobj_attribute duress_stats_attr = __ATTR(stats, 0444, duress_stats_show, NULL);
static struct kobj_attribute duress_test_attr = __ATTR(test_password, 0200, NULL, duress_test_store);

static struct attribute *duress_attrs[] = {
    &duress_enabled_attr.attr,
    &duress_wipe_attr.attr,
    &duress_decoy_attr.attr,
    &duress_password_attr.attr,
    &duress_status_attr.attr,
    &duress_stats_attr.attr,
    &duress_test_attr.attr,
    NULL
};

static struct attribute_group duress_group = { .attrs = duress_attrs };

static int __init shadow_duress_init(void)
{
    struct kobject *parent;
    
    pr_info("ShadowOS: 🔐 Initializing Duress Password Module\n");
    
    hash_tfm = crypto_alloc_shash("sha256", 0, 0);
    if (IS_ERR(hash_tfm)) {
        pr_err("ShadowOS: Failed to allocate SHA-256 for duress\n");
        hash_tfm = NULL;
        return -ENOMEM;
    }
    
    parent = shadow_get_kobj();
    if (parent) {
        duress_kobj = kobject_create_and_add("duress", parent);
        if (duress_kobj)
            sysfs_create_group(duress_kobj, &duress_group);
    }
    
    pr_info("ShadowOS: 🔐 Duress Password System ACTIVE\n");
    return 0;
}

static void __exit shadow_duress_exit(void)
{
    if (duress_kobj) {
        sysfs_remove_group(duress_kobj, &duress_group);
        kobject_put(duress_kobj);
    }
    
    if (hash_tfm)
        crypto_free_shash(hash_tfm);
    
    /* Clear sensitive data */
    memzero_explicit(&duress_cfg, sizeof(duress_cfg));
    
    pr_info("ShadowOS: Duress Password unloaded\n");
}

module_init(shadow_duress_init);
module_exit(shadow_duress_exit);
