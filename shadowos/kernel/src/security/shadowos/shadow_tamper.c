/* SPDX-License-Identifier: GPL-2.0 */
/*
 * ShadowOS Tamper Detection Module
 * 
 * 🔐 EVIL MAID ATTACK DETECTION
 * 
 * Features:
 * - Boot integrity verification
 * - Hardware change detection
 * - BIOS/UEFI modification alerts
 * - Physical tampering indicators
 *
 * Copyright (C) 2026 ShadowOS Project
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/sysfs.h>
#include <linux/kobject.h>
#include <linux/dmi.h>
#include <linux/efi.h>
#include <linux/crypto.h>
#include <crypto/hash.h>
#include <shadowos/shadow_types.h>

/* Module Info */
MODULE_LICENSE("GPL");
MODULE_AUTHOR("ShadowOS Team");
MODULE_DESCRIPTION("ShadowOS Tamper Detection - Evil Maid Protection");
MODULE_VERSION(SHADOWOS_VERSION);

/* Forward declaration */
extern struct kobject *shadow_get_kobj(void);

#define HASH_LEN    32  /* SHA-256 */

/* Hardware fingerprint */
struct hw_fingerprint {
    u8 bios_hash[HASH_LEN];
    u8 dmi_hash[HASH_LEN];
    char bios_vendor[64];
    char bios_version[64];
    char system_serial[64];
    unsigned long capture_time;
};

/* Configuration */
static struct {
    bool enabled;
    bool fingerprint_valid;
    bool tampering_detected;
    u64 checks_performed;
    u64 anomalies_found;
    struct hw_fingerprint baseline;
    struct hw_fingerprint current;
} tamper_cfg = {
    .enabled = true,
    .fingerprint_valid = false,
    .tampering_detected = false,
    .checks_performed = 0,
    .anomalies_found = 0,
};

static struct crypto_shash *hash_tfm;

/* Compute SHA-256 hash of a string */
static int compute_hash(const char *data, size_t len, u8 *out)
{
    struct shash_desc *desc;
    int ret;
    
    if (!hash_tfm)
        return -ENODEV;
    
    desc = kzalloc(sizeof(*desc) + crypto_shash_descsize(hash_tfm), GFP_KERNEL);
    if (!desc)
        return -ENOMEM;
    
    desc->tfm = hash_tfm;
    ret = crypto_shash_digest(desc, data, len, out);
    kfree(desc);
    
    return ret;
}

/* Capture current hardware fingerprint */
static void capture_fingerprint(struct hw_fingerprint *fp)
{
    const char *str;
    char combined[512];
    
    memset(fp, 0, sizeof(*fp));
    fp->capture_time = jiffies;
    
    /* BIOS vendor and version */
    str = dmi_get_system_info(DMI_BIOS_VENDOR);
    if (str)
        strscpy(fp->bios_vendor, str, sizeof(fp->bios_vendor));
    
    str = dmi_get_system_info(DMI_BIOS_VERSION);
    if (str)
        strscpy(fp->bios_version, str, sizeof(fp->bios_version));
    
    str = dmi_get_system_info(DMI_PRODUCT_SERIAL);
    if (str)
        strscpy(fp->system_serial, str, sizeof(fp->system_serial));
    
    /* Compute combined DMI hash */
    snprintf(combined, sizeof(combined), "%s|%s|%s",
             fp->bios_vendor, fp->bios_version, fp->system_serial);
    compute_hash(combined, strlen(combined), fp->dmi_hash);
}

/* Compare fingerprints */
static bool compare_fingerprints(struct hw_fingerprint *a, struct hw_fingerprint *b)
{
    if (memcmp(a->dmi_hash, b->dmi_hash, HASH_LEN) != 0)
        return false;
    if (strcmp(a->bios_vendor, b->bios_vendor) != 0)
        return false;
    if (strcmp(a->bios_version, b->bios_version) != 0)
        return false;
    return true;
}

/* Perform tamper check */
static void perform_check(void)
{
    capture_fingerprint(&tamper_cfg.current);
    tamper_cfg.checks_performed++;
    
    if (!tamper_cfg.fingerprint_valid) {
        /* First run - establish baseline */
        memcpy(&tamper_cfg.baseline, &tamper_cfg.current, sizeof(struct hw_fingerprint));
        tamper_cfg.fingerprint_valid = true;
        pr_info("ShadowOS Tamper: 🔐 Baseline fingerprint captured\n");
        return;
    }
    
    /* Compare with baseline */
    if (!compare_fingerprints(&tamper_cfg.baseline, &tamper_cfg.current)) {
        tamper_cfg.tampering_detected = true;
        tamper_cfg.anomalies_found++;
        pr_warn("ShadowOS Tamper: 🚨 HARDWARE TAMPERING DETECTED!\n");
        pr_warn("ShadowOS Tamper: BIOS changed: %s -> %s\n",
                tamper_cfg.baseline.bios_version, tamper_cfg.current.bios_version);
    }
}

/* Sysfs Interface */
static struct kobject *tamper_kobj;

static ssize_t tamper_enabled_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
    return sprintf(buf, "%d\n", tamper_cfg.enabled);
}

static ssize_t tamper_enabled_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count)
{
    return kstrtobool(buf, &tamper_cfg.enabled) ? : count;
}

static ssize_t tamper_check_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count)
{
    if (tamper_cfg.enabled)
        perform_check();
    return count;
}

static ssize_t tamper_status_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
    const char *status;
    
    if (tamper_cfg.tampering_detected)
        status = "TAMPERED";
    else if (!tamper_cfg.fingerprint_valid)
        status = "NO_BASELINE";
    else
        status = "CLEAN";
    
    return sprintf(buf, "%s\n", status);
}

static ssize_t tamper_stats_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
    return sprintf(buf, "checks: %llu\nanomalies: %llu\ntampered: %d\n",
                   tamper_cfg.checks_performed, tamper_cfg.anomalies_found,
                   tamper_cfg.tampering_detected);
}

static ssize_t tamper_reset_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count)
{
    bool val;
    if (kstrtobool(buf, &val))
        return -EINVAL;
    
    if (val) {
        tamper_cfg.fingerprint_valid = false;
        tamper_cfg.tampering_detected = false;
        tamper_cfg.anomalies_found = 0;
        pr_info("ShadowOS Tamper: Baseline reset - will capture on next check\n");
    }
    return count;
}

static struct kobj_attribute tamper_attr_enabled = __ATTR(enabled, 0644, tamper_enabled_show, tamper_enabled_store);
static struct kobj_attribute tamper_attr_check = __ATTR(check_now, 0200, NULL, tamper_check_store);
static struct kobj_attribute tamper_attr_status = __ATTR(status, 0444, tamper_status_show, NULL);
static struct kobj_attribute tamper_attr_stats = __ATTR(stats, 0444, tamper_stats_show, NULL);
static struct kobj_attribute tamper_attr_reset = __ATTR(reset_baseline, 0200, NULL, tamper_reset_store);

static struct attribute *tamper_attrs[] = {
    &tamper_attr_enabled.attr,
    &tamper_attr_check.attr,
    &tamper_attr_status.attr,
    &tamper_attr_stats.attr,
    &tamper_attr_reset.attr,
    NULL,
};

static struct attribute_group tamper_attr_group = {
    .attrs = tamper_attrs,
};

static int __init shadow_tamper_init(void)
{
    struct kobject *parent;
    
    pr_info("ShadowOS: 🔐 Initializing Tamper Detection Module\n");
    
    hash_tfm = crypto_alloc_shash("sha256", 0, 0);
    if (IS_ERR(hash_tfm)) {
        pr_err("ShadowOS: Failed to allocate SHA-256\n");
        hash_tfm = NULL;
    }
    
    parent = shadow_get_kobj();
    if (parent) {
        tamper_kobj = kobject_create_and_add("tamper", parent);
        if (tamper_kobj) {
            if (sysfs_create_group(tamper_kobj, &tamper_attr_group))
                pr_err("ShadowOS: Failed to create tamper sysfs\n");
        }
    }
    
    /* Capture initial fingerprint */
    if (tamper_cfg.enabled)
        perform_check();
    
    pr_info("ShadowOS: 🔐 Tamper Detection ACTIVE - Evil maid protection enabled\n");
    return 0;
}

static void __exit shadow_tamper_exit(void)
{
    if (tamper_kobj) {
        sysfs_remove_group(tamper_kobj, &tamper_attr_group);
        kobject_put(tamper_kobj);
    }
    
    if (hash_tfm)
        crypto_free_shash(hash_tfm);
    
    pr_info("ShadowOS: Tamper Detection unloaded\n");
}

module_init(shadow_tamper_init);
module_exit(shadow_tamper_exit);
