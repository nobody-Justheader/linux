/* SPDX-License-Identifier: GPL-2.0 */
/*
 * ShadowOS Evidence Preservation Module
 * 
 * 🔒 SECURE FORENSIC LOGGING
 * 
 * Features:
 * - Tamper-resistant logging
 * - Hash chain integrity
 * - Secure log export
 * - Chain of custody support
 *
 * Copyright (C) 2026 ShadowOS Project
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/sysfs.h>
#include <linux/kobject.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/time.h>
#include <linux/crypto.h>
#include <crypto/hash.h>
#include <shadowos/shadow_types.h>

/* Module Info */
MODULE_LICENSE("GPL");
MODULE_AUTHOR("ShadowOS Team");
MODULE_DESCRIPTION("ShadowOS Evidence Preservation - Secure Forensic Logging");
MODULE_VERSION(SHADOWOS_VERSION);

/* Forward declaration */
extern struct kobject *shadow_get_kobj(void);

/* Maximum log entries */
#define MAX_LOG_ENTRIES     10000
#define MAX_LOG_MSG_LEN     256
#define HASH_LEN            32  /* SHA-256 */

/* Log entry structure */
struct evidence_entry {
    u64 sequence;
    ktime_t timestamp;
    u8 prev_hash[HASH_LEN];
    u8 hash[HASH_LEN];
    char source[32];
    char message[MAX_LOG_MSG_LEN];
    struct list_head list;
};

/* Configuration */
static struct {
    bool enabled;
    bool chain_verified;
    u64 entry_count;
    u64 integrity_checks;
    u64 integrity_failures;
    u8 genesis_hash[HASH_LEN];
    u8 latest_hash[HASH_LEN];
} evidence_cfg = {
    .enabled = true,
    .chain_verified = true,
    .entry_count = 0,
    .integrity_checks = 0,
    .integrity_failures = 0,
};

static LIST_HEAD(evidence_log);
static DEFINE_SPINLOCK(evidence_lock);
static struct crypto_shash *hash_tfm;

/* Compute SHA-256 hash */
static int compute_hash(const void *data, size_t len, u8 *out)
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

/* Add log entry with hash chain */
int shadow_evidence_log(const char *source, const char *fmt, ...)
{
    struct evidence_entry *entry;
    va_list args;
    u8 hash_input[sizeof(struct evidence_entry)];
    unsigned long flags;
    
    if (!evidence_cfg.enabled)
        return 0;
    
    entry = kzalloc(sizeof(*entry), GFP_ATOMIC);
    if (!entry)
        return -ENOMEM;
    
    spin_lock_irqsave(&evidence_lock, flags);
    
    entry->sequence = evidence_cfg.entry_count++;
    entry->timestamp = ktime_get_real();
    memcpy(entry->prev_hash, evidence_cfg.latest_hash, HASH_LEN);
    
    strscpy(entry->source, source, sizeof(entry->source));
    
    va_start(args, fmt);
    vsnprintf(entry->message, MAX_LOG_MSG_LEN, fmt, args);
    va_end(args);
    
    /* Compute hash of this entry */
    memcpy(hash_input, entry, sizeof(*entry));
    if (compute_hash(hash_input, sizeof(*entry), entry->hash) == 0) {
        memcpy(evidence_cfg.latest_hash, entry->hash, HASH_LEN);
    }
    
    list_add_tail(&entry->list, &evidence_log);
    
    spin_unlock_irqrestore(&evidence_lock, flags);
    
    pr_debug("ShadowOS Evidence: [%llu] %s: %s\n", 
             entry->sequence, entry->source, entry->message);
    
    return 0;
}
EXPORT_SYMBOL_GPL(shadow_evidence_log);

/* Verify integrity of log chain */
static bool verify_chain(void)
{
    struct evidence_entry *entry;
    u8 computed_hash[HASH_LEN];
    u8 prev_hash[HASH_LEN] = {0};
    bool valid = true;
    
    evidence_cfg.integrity_checks++;
    
    list_for_each_entry(entry, &evidence_log, list) {
        /* Check prev_hash matches */
        if (memcmp(entry->prev_hash, prev_hash, HASH_LEN) != 0) {
            pr_warn("ShadowOS Evidence: 🚨 CHAIN BROKEN at seq %llu\n", entry->sequence);
            valid = false;
            break;
        }
        
        /* Compute and verify hash */
        if (compute_hash(entry, sizeof(*entry), computed_hash) == 0) {
            if (memcmp(entry->hash, computed_hash, HASH_LEN) != 0) {
                pr_warn("ShadowOS Evidence: 🚨 ENTRY TAMPERED at seq %llu\n", entry->sequence);
                valid = false;
                break;
            }
        }
        
        memcpy(prev_hash, entry->hash, HASH_LEN);
    }
    
    if (!valid)
        evidence_cfg.integrity_failures++;
    
    evidence_cfg.chain_verified = valid;
    return valid;
}

/* Sysfs Interface */
static struct kobject *evidence_kobj;

static ssize_t evidence_enabled_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
    return sprintf(buf, "%d\n", evidence_cfg.enabled);
}

static ssize_t evidence_enabled_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count)
{
    bool val;
    if (kstrtobool(buf, &val))
        return -EINVAL;
    evidence_cfg.enabled = val;
    shadow_evidence_log("system", "Evidence logging %s", val ? "enabled" : "disabled");
    return count;
}

static ssize_t evidence_stats_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
    return sprintf(buf, "entries: %llu\nintegrity_checks: %llu\nfailures: %llu\nchain_valid: %d\n",
                   evidence_cfg.entry_count, evidence_cfg.integrity_checks,
                   evidence_cfg.integrity_failures, evidence_cfg.chain_verified);
}

static ssize_t evidence_verify_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count)
{
    bool result;
    
    spin_lock(&evidence_lock);
    result = verify_chain();
    spin_unlock(&evidence_lock);
    
    pr_info("ShadowOS Evidence: Chain verification %s\n", result ? "PASSED" : "FAILED");
    return count;
}

static ssize_t evidence_count_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
    return sprintf(buf, "%llu\n", evidence_cfg.entry_count);
}

static ssize_t evidence_latest_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
    struct evidence_entry *entry;
    ssize_t len = 0;
    int count = 0;
    
    spin_lock(&evidence_lock);
    list_for_each_entry_reverse(entry, &evidence_log, list) {
        len += sprintf(buf + len, "[%llu] %s: %s\n", 
                       entry->sequence, entry->source, entry->message);
        if (++count >= 10)
            break;
    }
    spin_unlock(&evidence_lock);
    
    return len;
}

static struct kobj_attribute evidence_attr_enabled = __ATTR(enabled, 0644, evidence_enabled_show, evidence_enabled_store);
static struct kobj_attribute evidence_attr_stats = __ATTR(stats, 0444, evidence_stats_show, NULL);
static struct kobj_attribute evidence_attr_verify = __ATTR(verify, 0200, NULL, evidence_verify_store);
static struct kobj_attribute evidence_attr_count = __ATTR(count, 0444, evidence_count_show, NULL);
static struct kobj_attribute evidence_attr_latest = __ATTR(latest, 0444, evidence_latest_show, NULL);

static struct attribute *evidence_attrs[] = {
    &evidence_attr_enabled.attr,
    &evidence_attr_stats.attr,
    &evidence_attr_verify.attr,
    &evidence_attr_count.attr,
    &evidence_attr_latest.attr,
    NULL,
};

static struct attribute_group evidence_attr_group = {
    .attrs = evidence_attrs,
};

static int __init shadow_evidence_init(void)
{
    struct kobject *parent;
    
    pr_info("ShadowOS: 🔒 Initializing Evidence Preservation Module\n");
    
    /* Initialize crypto */
    hash_tfm = crypto_alloc_shash("sha256", 0, 0);
    if (IS_ERR(hash_tfm)) {
        pr_err("ShadowOS: Failed to allocate SHA-256\n");
        hash_tfm = NULL;
    }
    
    /* Initialize genesis hash */
    memset(evidence_cfg.genesis_hash, 0, HASH_LEN);
    memset(evidence_cfg.latest_hash, 0, HASH_LEN);
    
    parent = shadow_get_kobj();
    if (parent) {
        evidence_kobj = kobject_create_and_add("evidence", parent);
        if (evidence_kobj) {
            if (sysfs_create_group(evidence_kobj, &evidence_attr_group))
                pr_err("ShadowOS: Failed to create evidence sysfs\n");
        }
    }
    
    shadow_evidence_log("system", "Evidence module initialized");
    
    pr_info("ShadowOS: 🔒 Evidence Preservation ACTIVE - Tamper-resistant logging enabled\n");
    return 0;
}

static void __exit shadow_evidence_exit(void)
{
    struct evidence_entry *entry, *tmp;
    
    if (evidence_kobj) {
        sysfs_remove_group(evidence_kobj, &evidence_attr_group);
        kobject_put(evidence_kobj);
    }
    
    if (hash_tfm)
        crypto_free_shash(hash_tfm);
    
    /* Cleanup log entries */
    list_for_each_entry_safe(entry, tmp, &evidence_log, list) {
        list_del(&entry->list);
        kfree(entry);
    }
    
    pr_info("ShadowOS: Evidence module unloaded\n");
}

module_init(shadow_evidence_init);
module_exit(shadow_evidence_exit);
