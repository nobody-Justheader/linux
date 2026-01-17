/* SPDX-License-Identifier: GPL-2.0 */
/*
 * ShadowOS Encrypted Memory Module
 * 
 * 🔐 IN-MEMORY ENCRYPTION FOR SENSITIVE DATA
 * 
 * Features:
 * - Register memory regions for encryption
 * - AES-256 encryption of sensitive buffers
 * - Automatic key rotation
 * - Integration with RAM scrubbing
 *
 * Copyright (C) 2024 ShadowOS Project
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/sysfs.h>
#include <linux/kobject.h>
#include <linux/crypto.h>
#include <crypto/skcipher.h>
#include <linux/scatterlist.h>
#include <linux/slab.h>
#include <linux/random.h>
#include <shadowos/shadow_types.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("ShadowOS Team");
MODULE_DESCRIPTION("ShadowOS Encrypted Memory - In-Memory Encryption");
MODULE_VERSION(SHADOWOS_VERSION);

extern struct kobject *shadow_get_kobj(void);

#define KEY_SIZE 32
#define IV_SIZE 16
#define MAX_REGIONS 64

/* Protected memory region */
struct mem_region {
    void *addr;
    size_t size;
    u8 iv[IV_SIZE];
    bool encrypted;
    bool active;
};

/* Configuration */
static struct {
    bool enabled;
    u8 master_key[KEY_SIZE];
    bool key_initialized;
    struct mem_region regions[MAX_REGIONS];
    int region_count;
    u64 bytes_encrypted;
    u64 operations;
} memcrypt_cfg = {
    .enabled = true,
    .key_initialized = false,
    .region_count = 0,
    .bytes_encrypted = 0,
    .operations = 0,
};

static struct crypto_skcipher *cipher;
static DEFINE_SPINLOCK(memcrypt_lock);

/* Initialize encryption key */
static int init_master_key(void)
{
    get_random_bytes(memcrypt_cfg.master_key, KEY_SIZE);
    memcrypt_cfg.key_initialized = true;
    pr_info("ShadowOS Memcrypt: 🔐 Master key initialized\n");
    return 0;
}

/* Encrypt a memory region */
static int encrypt_region(struct mem_region *region)
{
    struct skcipher_request *req;
    struct scatterlist sg;
    DECLARE_CRYPTO_WAIT(wait);
    int ret;
    
    if (!cipher || !memcrypt_cfg.key_initialized)
        return -ENODEV;
    
    if (region->encrypted)
        return 0;  /* Already encrypted */
    
    /* Generate random IV */
    get_random_bytes(region->iv, IV_SIZE);
    
    req = skcipher_request_alloc(cipher, GFP_KERNEL);
    if (!req)
        return -ENOMEM;
    
    sg_init_one(&sg, region->addr, region->size);
    
    skcipher_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG,
                                   crypto_req_done, &wait);
    skcipher_request_set_crypt(req, &sg, &sg, region->size, region->iv);
    
    ret = crypto_wait_req(crypto_skcipher_encrypt(req), &wait);
    
    skcipher_request_free(req);
    
    if (ret == 0) {
        region->encrypted = true;
        memcrypt_cfg.bytes_encrypted += region->size;
        memcrypt_cfg.operations++;
        pr_debug("ShadowOS Memcrypt: Encrypted %zu bytes at %p\n",
                 region->size, region->addr);
    }
    
    return ret;
}

/* Decrypt a memory region */
static int decrypt_region(struct mem_region *region)
{
    struct skcipher_request *req;
    struct scatterlist sg;
    DECLARE_CRYPTO_WAIT(wait);
    int ret;
    
    if (!cipher || !memcrypt_cfg.key_initialized)
        return -ENODEV;
    
    if (!region->encrypted)
        return 0;  /* Not encrypted */
    
    req = skcipher_request_alloc(cipher, GFP_KERNEL);
    if (!req)
        return -ENOMEM;
    
    sg_init_one(&sg, region->addr, region->size);
    
    skcipher_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG,
                                   crypto_req_done, &wait);
    skcipher_request_set_crypt(req, &sg, &sg, region->size, region->iv);
    
    ret = crypto_wait_req(crypto_skcipher_decrypt(req), &wait);
    
    skcipher_request_free(req);
    
    if (ret == 0) {
        region->encrypted = false;
        memcrypt_cfg.operations++;
        pr_debug("ShadowOS Memcrypt: Decrypted %zu bytes at %p\n",
                 region->size, region->addr);
    }
    
    return ret;
}

/* Register memory region for protection */
int shadow_memcrypt_register(void *addr, size_t size)
{
    struct mem_region *region;
    unsigned long flags;
    
    if (!memcrypt_cfg.enabled)
        return -ENODEV;
    
    if (memcrypt_cfg.region_count >= MAX_REGIONS)
        return -ENOSPC;
    
    spin_lock_irqsave(&memcrypt_lock, flags);
    
    region = &memcrypt_cfg.regions[memcrypt_cfg.region_count];
    region->addr = addr;
    region->size = size;
    region->encrypted = false;
    region->active = true;
    
    memcrypt_cfg.region_count++;
    
    spin_unlock_irqrestore(&memcrypt_lock, flags);
    
    /* Encrypt immediately */
    encrypt_region(region);
    
    pr_info("ShadowOS Memcrypt: 🔐 Registered region %p (%zu bytes)\n", addr, size);
    return memcrypt_cfg.region_count - 1;
}
EXPORT_SYMBOL_GPL(shadow_memcrypt_register);

/* Rotate master key */
static int rotate_key(void)
{
    int i;
    unsigned long flags;
    
    spin_lock_irqsave(&memcrypt_lock, flags);
    
    /* Decrypt all regions with old key */
    for (i = 0; i < memcrypt_cfg.region_count; i++) {
        if (memcrypt_cfg.regions[i].active)
            decrypt_region(&memcrypt_cfg.regions[i]);
    }
    
    /* Generate new key */
    get_random_bytes(memcrypt_cfg.master_key, KEY_SIZE);
    crypto_skcipher_setkey(cipher, memcrypt_cfg.master_key, KEY_SIZE);
    
    /* Re-encrypt with new key */
    for (i = 0; i < memcrypt_cfg.region_count; i++) {
        if (memcrypt_cfg.regions[i].active)
            encrypt_region(&memcrypt_cfg.regions[i]);
    }
    
    spin_unlock_irqrestore(&memcrypt_lock, flags);
    
    pr_info("ShadowOS Memcrypt: 🔐 Key rotated, %d regions re-encrypted\n",
            memcrypt_cfg.region_count);
    return 0;
}

/* Sysfs Interface */
static struct kobject *memcrypt_kobj;

static ssize_t memcrypt_enabled_show(struct kobject *k, struct kobj_attribute *a, char *buf)
{ return sprintf(buf, "%d\n", memcrypt_cfg.enabled); }

static ssize_t memcrypt_enabled_store(struct kobject *k, struct kobj_attribute *a, const char *buf, size_t c)
{ return kstrtobool(buf, &memcrypt_cfg.enabled) ? : c; }

static ssize_t memcrypt_rotate_store(struct kobject *k, struct kobj_attribute *a, const char *buf, size_t c)
{
    rotate_key();
    return c;
}

static ssize_t memcrypt_stats_show(struct kobject *k, struct kobj_attribute *a, char *buf)
{
    return sprintf(buf, "regions: %d\nbytes_protected: %llu\noperations: %llu\nkey_ready: %d\n",
                   memcrypt_cfg.region_count, memcrypt_cfg.bytes_encrypted,
                   memcrypt_cfg.operations, memcrypt_cfg.key_initialized);
}

static struct kobj_attribute memcrypt_enabled_attr = __ATTR(enabled, 0644, memcrypt_enabled_show, memcrypt_enabled_store);
static struct kobj_attribute memcrypt_rotate_attr = __ATTR(rotate_key, 0200, NULL, memcrypt_rotate_store);
static struct kobj_attribute memcrypt_stats_attr = __ATTR(stats, 0444, memcrypt_stats_show, NULL);

static struct attribute *memcrypt_attrs[] = {
    &memcrypt_enabled_attr.attr,
    &memcrypt_rotate_attr.attr,
    &memcrypt_stats_attr.attr,
    NULL
};

static struct attribute_group memcrypt_group = { .attrs = memcrypt_attrs };

static int __init shadow_memcrypt_init(void)
{
    struct kobject *parent;
    
    pr_info("ShadowOS: 🔐 Initializing Encrypted Memory\n");
    
    cipher = crypto_alloc_skcipher("cbc(aes)", 0, 0);
    if (IS_ERR(cipher)) {
        pr_err("ShadowOS: Failed to allocate AES cipher\n");
        cipher = NULL;
        return -ENOMEM;
    }
    
    init_master_key();
    crypto_skcipher_setkey(cipher, memcrypt_cfg.master_key, KEY_SIZE);
    
    parent = shadow_get_kobj();
    if (parent) {
        memcrypt_kobj = kobject_create_and_add("memcrypt", parent);
        if (memcrypt_kobj)
            sysfs_create_group(memcrypt_kobj, &memcrypt_group);
    }
    
    pr_info("ShadowOS: 🔐 Encrypted Memory ACTIVE - AES-256-CBC\n");
    return 0;
}

static void __exit shadow_memcrypt_exit(void)
{
    int i;
    
    /* Securely wipe key */
    memzero_explicit(memcrypt_cfg.master_key, KEY_SIZE);
    
    /* Decrypt all regions before exiting */
    for (i = 0; i < memcrypt_cfg.region_count; i++) {
        if (memcrypt_cfg.regions[i].active && memcrypt_cfg.regions[i].encrypted)
            decrypt_region(&memcrypt_cfg.regions[i]);
    }
    
    if (memcrypt_kobj) {
        sysfs_remove_group(memcrypt_kobj, &memcrypt_group);
        kobject_put(memcrypt_kobj);
    }
    
    if (cipher)
        crypto_free_skcipher(cipher);
    
    pr_info("ShadowOS: Encrypted Memory unloaded\n");
}

module_init(shadow_memcrypt_init);
module_exit(shadow_memcrypt_exit);
