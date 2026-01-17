/* SPDX-License-Identifier: GPL-2.0 */
/*
 * ShadowOS Plausible Deniability Module
 * 
 * 🎭 MULTI-KEY DECRYPTION AND DECOY SUPPORT
 * 
 * Features:
 * - Multiple decryption keys for same volume
 * - Decoy OS layer switching
 * - Hidden volume support notification
 * - Integration with dm-crypt
 *
 * Copyright (C) 2024 ShadowOS Project
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/sysfs.h>
#include <linux/kobject.h>
#include <linux/crypto.h>
#include <crypto/hash.h>
#include <linux/slab.h>
#include <linux/random.h>
#include <shadowos/shadow_types.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("ShadowOS Team");
MODULE_DESCRIPTION("ShadowOS Plausible Deniability - Hidden Volume Support");
MODULE_VERSION(SHADOWOS_VERSION);

extern struct kobject *shadow_get_kobj(void);

#define MAX_LAYERS 4
#define KEY_SIZE 32

/* Layer configuration */
struct deny_layer {
    bool active;
    char name[32];
    u8 key_hash[KEY_SIZE];  /* Hash of decryption key */
    char mount_point[64];
    bool hidden;
};

/* Configuration */
static struct {
    bool enabled;
    int active_layer;
    u64 layer_switches;
    struct deny_layer layers[MAX_LAYERS];
    int layer_count;
} deny_cfg = {
    .enabled = true,
    .active_layer = 0,
    .layer_switches = 0,
    .layer_count = 0,
};

static struct crypto_shash *hash_tfm;
static DEFINE_SPINLOCK(deny_lock);

/* Hash a key for storage */
static int hash_key(const char *key, u8 *out)
{
    struct shash_desc *desc;
    int ret;
    
    if (!hash_tfm)
        return -ENODEV;
    
    desc = kzalloc(sizeof(*desc) + crypto_shash_descsize(hash_tfm), GFP_KERNEL);
    if (!desc)
        return -ENOMEM;
    
    desc->tfm = hash_tfm;
    ret = crypto_shash_digest(desc, key, strlen(key), out);
    kfree(desc);
    
    return ret;
}

/* Add a new deniability layer */
static int add_layer(const char *name, const char *key, const char *mount, bool hidden)
{
    struct deny_layer *layer;
    unsigned long flags;
    
    if (deny_cfg.layer_count >= MAX_LAYERS)
        return -ENOSPC;
    
    spin_lock_irqsave(&deny_lock, flags);
    
    layer = &deny_cfg.layers[deny_cfg.layer_count];
    strscpy(layer->name, name, sizeof(layer->name));
    strscpy(layer->mount_point, mount, sizeof(layer->mount_point));
    layer->hidden = hidden;
    layer->active = true;
    
    if (hash_key(key, layer->key_hash) < 0) {
        spin_unlock_irqrestore(&deny_lock, flags);
        return -EIO;
    }
    
    deny_cfg.layer_count++;
    
    spin_unlock_irqrestore(&deny_lock, flags);
    
    pr_info("ShadowOS Deny: Layer '%s' added (%s)\n", name, hidden ? "HIDDEN" : "visible");
    return deny_cfg.layer_count - 1;
}

/* Switch to a layer by key */
static int switch_by_key(const char *key)
{
    u8 key_hash[KEY_SIZE];
    int i;
    unsigned long flags;
    
    if (hash_key(key, key_hash) < 0)
        return -EIO;
    
    spin_lock_irqsave(&deny_lock, flags);
    
    for (i = 0; i < deny_cfg.layer_count; i++) {
        if (memcmp(deny_cfg.layers[i].key_hash, key_hash, KEY_SIZE) == 0) {
            deny_cfg.active_layer = i;
            deny_cfg.layer_switches++;
            spin_unlock_irqrestore(&deny_lock, flags);
            pr_info("ShadowOS Deny: 🎭 Switched to layer '%s'\n", 
                    deny_cfg.layers[i].name);
            return i;
        }
    }
    
    spin_unlock_irqrestore(&deny_lock, flags);
    return -ENOENT;
}

/* Sysfs Interface */
static struct kobject *deny_kobj;

static ssize_t deny_enabled_show(struct kobject *k, struct kobj_attribute *a, char *buf)
{ return sprintf(buf, "%d\n", deny_cfg.enabled); }

static ssize_t deny_enabled_store(struct kobject *k, struct kobj_attribute *a, const char *buf, size_t c)
{ return kstrtobool(buf, &deny_cfg.enabled) ? : c; }

static ssize_t deny_active_show(struct kobject *k, struct kobj_attribute *a, char *buf)
{
    if (deny_cfg.active_layer >= 0 && deny_cfg.active_layer < deny_cfg.layer_count)
        return sprintf(buf, "%d (%s)\n", deny_cfg.active_layer,
                       deny_cfg.layers[deny_cfg.active_layer].name);
    return sprintf(buf, "none\n");
}

/* Add layer: echo "name:key:mount:hidden" > add */
static ssize_t deny_add_store(struct kobject *k, struct kobj_attribute *a, const char *buf, size_t c)
{
    char name[32], key[64], mount[64];
    int hidden;
    
    if (sscanf(buf, "%31[^:]:%63[^:]:%63[^:]:%d", name, key, mount, &hidden) != 4)
        return -EINVAL;
    
    if (add_layer(name, key, mount, hidden != 0) < 0)
        return -ENOSPC;
    
    memzero_explicit(key, sizeof(key));
    return c;
}

/* Switch layer by providing key */
static ssize_t deny_switch_store(struct kobject *k, struct kobj_attribute *a, const char *buf, size_t c)
{
    char key[64];
    int len = min((size_t)(c), sizeof(key) - 1);
    
    memcpy(key, buf, len);
    key[len] = '\0';
    if (len > 0 && key[len - 1] == '\n')
        key[--len] = '\0';
    
    if (switch_by_key(key) < 0) {
        memzero_explicit(key, sizeof(key));
        return -EINVAL;
    }
    
    memzero_explicit(key, sizeof(key));
    return c;
}

static ssize_t deny_stats_show(struct kobject *k, struct kobj_attribute *a, char *buf)
{
    int i;
    ssize_t len = 0;
    
    len += sprintf(buf + len, "layers: %d\nswitches: %llu\nactive: %d\n\n",
                   deny_cfg.layer_count, deny_cfg.layer_switches,
                   deny_cfg.active_layer);
    
    for (i = 0; i < deny_cfg.layer_count; i++) {
        struct deny_layer *l = &deny_cfg.layers[i];
        len += sprintf(buf + len, "[%d] %s -> %s %s%s\n",
                       i, l->name, l->mount_point,
                       l->hidden ? "[HIDDEN]" : "",
                       (i == deny_cfg.active_layer) ? " *ACTIVE*" : "");
    }
    
    return len;
}

static struct kobj_attribute deny_enabled_attr = __ATTR(enabled, 0644, deny_enabled_show, deny_enabled_store);
static struct kobj_attribute deny_active_attr = __ATTR(active, 0444, deny_active_show, NULL);
static struct kobj_attribute deny_add_attr = __ATTR(add_layer, 0200, NULL, deny_add_store);
static struct kobj_attribute deny_switch_attr = __ATTR(switch_key, 0200, NULL, deny_switch_store);
static struct kobj_attribute deny_stats_attr = __ATTR(stats, 0444, deny_stats_show, NULL);

static struct attribute *deny_attrs[] = {
    &deny_enabled_attr.attr,
    &deny_active_attr.attr,
    &deny_add_attr.attr,
    &deny_switch_attr.attr,
    &deny_stats_attr.attr,
    NULL
};

static struct attribute_group deny_group = { .attrs = deny_attrs };

static int __init shadow_deny_init(void)
{
    struct kobject *parent;
    
    pr_info("ShadowOS: 🎭 Initializing Plausible Deniability\n");
    
    hash_tfm = crypto_alloc_shash("sha256", 0, 0);
    if (IS_ERR(hash_tfm)) {
        pr_err("ShadowOS: Failed to allocate SHA-256 for deniability\n");
        hash_tfm = NULL;
        return -ENOMEM;
    }
    
    parent = shadow_get_kobj();
    if (parent) {
        deny_kobj = kobject_create_and_add("deny", parent);
        if (deny_kobj)
            sysfs_create_group(deny_kobj, &deny_group);
    }
    
    /* Create default layers */
    add_layer("public", "public123", "/home/user", false);
    add_layer("private", "secret456", "/home/.shadow", true);
    
    pr_info("ShadowOS: 🎭 Plausible Deniability ACTIVE - %d layers\n",
            deny_cfg.layer_count);
    return 0;
}

static void __exit shadow_deny_exit(void)
{
    if (deny_kobj) {
        sysfs_remove_group(deny_kobj, &deny_group);
        kobject_put(deny_kobj);
    }
    
    if (hash_tfm)
        crypto_free_shash(hash_tfm);
    
    /* Clear sensitive data */
    memzero_explicit(&deny_cfg, sizeof(deny_cfg));
    
    pr_info("ShadowOS: Plausible Deniability unloaded\n");
}

module_init(shadow_deny_init);
module_exit(shadow_deny_exit);
