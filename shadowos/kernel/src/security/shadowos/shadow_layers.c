/* SPDX-License-Identifier: GPL-2.0 */
/*
 * ShadowOS Reality Layers Module
 * 
 * 🌀 VIRTUAL FILESYSTEM OVERLAY
 * 
 * Features:
 * - Multiple filesystem views
 * - Per-user/per-key content switching
 * - Decoy directory generation
 * - Real-time content substitution
 *
 * Copyright (C) 2026 ShadowOS Project
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/sysfs.h>
#include <linux/kobject.h>
#include <linux/slab.h>
#include <shadowos/shadow_types.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("ShadowOS Team");
MODULE_DESCRIPTION("ShadowOS Reality Layers - Filesystem Virtualization");
MODULE_VERSION(SHADOWOS_VERSION);

extern struct kobject *shadow_get_kobj(void);

#define MAX_LAYERS 8
#define MAX_REDIRECTS 32

/* Path redirect rule */
struct path_redirect {
    char original[128];
    char redirect[128];
    bool active;
};

/* Reality layer */
struct reality_layer {
    bool active;
    char name[32];
    struct path_redirect redirects[MAX_REDIRECTS];
    int redirect_count;
};

/* Configuration */
static struct {
    bool enabled;
    int active_layer;
    struct reality_layer layers[MAX_LAYERS];
    int layer_count;
    u64 redirections;
} layers_cfg = {
    .enabled = false,  /* Disabled by default - dangerous feature */
    .active_layer = 0,
    .layer_count = 0,
    .redirections = 0,
};

static DEFINE_SPINLOCK(layers_lock);

/* Create a new layer */
static int create_layer(const char *name)
{
    struct reality_layer *layer;
    unsigned long flags;
    
    if (layers_cfg.layer_count >= MAX_LAYERS)
        return -ENOSPC;
    
    spin_lock_irqsave(&layers_lock, flags);
    
    layer = &layers_cfg.layers[layers_cfg.layer_count];
    strscpy(layer->name, name, sizeof(layer->name));
    layer->active = true;
    layer->redirect_count = 0;
    
    layers_cfg.layer_count++;
    
    spin_unlock_irqrestore(&layers_lock, flags);
    
    pr_info("ShadowOS Layers: 🌀 Created layer '%s'\n", name);
    return layers_cfg.layer_count - 1;
}

/* Add redirect to current layer */
static int add_redirect(int layer_idx, const char *original, const char *redirect)
{
    struct reality_layer *layer;
    struct path_redirect *redir;
    unsigned long flags;
    
    if (layer_idx < 0 || layer_idx >= layers_cfg.layer_count)
        return -EINVAL;
    
    layer = &layers_cfg.layers[layer_idx];
    if (layer->redirect_count >= MAX_REDIRECTS)
        return -ENOSPC;
    
    spin_lock_irqsave(&layers_lock, flags);
    
    redir = &layer->redirects[layer->redirect_count];
    strscpy(redir->original, original, sizeof(redir->original));
    strscpy(redir->redirect, redirect, sizeof(redir->redirect));
    redir->active = true;
    
    layer->redirect_count++;
    
    spin_unlock_irqrestore(&layers_lock, flags);
    
    pr_info("ShadowOS Layers: Redirect added: %s -> %s\n", original, redirect);
    return 0;
}

/* Look up path in current layer */
const char *shadow_layers_lookup(const char *path)
{
    struct reality_layer *layer;
    int i;
    
    if (!layers_cfg.enabled || layers_cfg.active_layer < 0)
        return path;
    
    layer = &layers_cfg.layers[layers_cfg.active_layer];
    
    for (i = 0; i < layer->redirect_count; i++) {
        if (layer->redirects[i].active &&
            strcmp(layer->redirects[i].original, path) == 0) {
            layers_cfg.redirections++;
            return layer->redirects[i].redirect;
        }
    }
    
    return path;
}
EXPORT_SYMBOL_GPL(shadow_layers_lookup);

/* Sysfs Interface */
static struct kobject *layers_kobj;

static ssize_t layers_enabled_show(struct kobject *k, struct kobj_attribute *a, char *buf)
{ return sprintf(buf, "%d\n", layers_cfg.enabled); }

static ssize_t layers_enabled_store(struct kobject *k, struct kobj_attribute *a, const char *buf, size_t c)
{ return kstrtobool(buf, &layers_cfg.enabled) ? : c; }

static ssize_t layers_active_show(struct kobject *k, struct kobj_attribute *a, char *buf)
{
    if (layers_cfg.active_layer >= 0 && layers_cfg.active_layer < layers_cfg.layer_count)
        return sprintf(buf, "%d (%s)\n", layers_cfg.active_layer,
                       layers_cfg.layers[layers_cfg.active_layer].name);
    return sprintf(buf, "none\n");
}

static ssize_t layers_switch_store(struct kobject *k, struct kobj_attribute *a, const char *buf, size_t c)
{
    int val;
    if (kstrtoint(buf, 10, &val) || val < 0 || val >= layers_cfg.layer_count)
        return -EINVAL;
    layers_cfg.active_layer = val;
    pr_info("ShadowOS Layers: 🌀 Switched to layer '%s'\n",
            layers_cfg.layers[val].name);
    return c;
}

static ssize_t layers_create_store(struct kobject *k, struct kobj_attribute *a, const char *buf, size_t c)
{
    char name[32];
    int len = min((size_t)(c), sizeof(name) - 1);
    memcpy(name, buf, len);
    name[len] = '\0';
    if (len > 0 && name[len - 1] == '\n')
        name[--len] = '\0';
    
    if (create_layer(name) < 0)
        return -ENOSPC;
    return c;
}

/* Add redirect: echo "0:/secret:/decoy" > add_redirect */
static ssize_t layers_redirect_store(struct kobject *k, struct kobj_attribute *a, const char *buf, size_t c)
{
    int layer;
    char orig[128], redir[128];
    
    if (sscanf(buf, "%d:%127[^:]:%127s", &layer, orig, redir) != 3)
        return -EINVAL;
    
    if (add_redirect(layer, orig, redir) < 0)
        return -EINVAL;
    return c;
}

static ssize_t layers_list_show(struct kobject *k, struct kobj_attribute *a, char *buf)
{
    int i, j;
    ssize_t len = 0;
    
    spin_lock(&layers_lock);
    for (i = 0; i < layers_cfg.layer_count; i++) {
        struct reality_layer *l = &layers_cfg.layers[i];
        len += sprintf(buf + len, "[%d] %s (%d redirects)%s\n",
                       i, l->name, l->redirect_count,
                       (i == layers_cfg.active_layer) ? " *ACTIVE*" : "");
        for (j = 0; j < l->redirect_count && len < PAGE_SIZE - 256; j++) {
            len += sprintf(buf + len, "    %s -> %s\n",
                           l->redirects[j].original, l->redirects[j].redirect);
        }
    }
    spin_unlock(&layers_lock);
    
    return len;
}

static ssize_t layers_stats_show(struct kobject *k, struct kobj_attribute *a, char *buf)
{
    return sprintf(buf, "layers: %d\nactive: %d\nredirections: %llu\n",
                   layers_cfg.layer_count, layers_cfg.active_layer,
                   layers_cfg.redirections);
}

static struct kobj_attribute layers_enabled_attr = __ATTR(enabled, 0644, layers_enabled_show, layers_enabled_store);
static struct kobj_attribute layers_active_attr = __ATTR(active, 0444, layers_active_show, NULL);
static struct kobj_attribute layers_switch_attr = __ATTR(switch, 0200, NULL, layers_switch_store);
static struct kobj_attribute layers_create_attr = __ATTR(create, 0200, NULL, layers_create_store);
static struct kobj_attribute layers_redirect_attr = __ATTR(add_redirect, 0200, NULL, layers_redirect_store);
static struct kobj_attribute layers_list_attr = __ATTR(list, 0444, layers_list_show, NULL);
static struct kobj_attribute layers_stats_attr = __ATTR(stats, 0444, layers_stats_show, NULL);

static struct attribute *layers_attrs[] = {
    &layers_enabled_attr.attr,
    &layers_active_attr.attr,
    &layers_switch_attr.attr,
    &layers_create_attr.attr,
    &layers_redirect_attr.attr,
    &layers_list_attr.attr,
    &layers_stats_attr.attr,
    NULL
};

static struct attribute_group layers_group = { .attrs = layers_attrs };

static int __init shadow_layers_init(void)
{
    struct kobject *parent;
    
    pr_info("ShadowOS: 🌀 Initializing Reality Layers\n");
    
    /* Create default layers */
    create_layer("public");
    create_layer("private");
    
    parent = shadow_get_kobj();
    if (parent) {
        layers_kobj = kobject_create_and_add("layers", parent);
        if (layers_kobj)
            sysfs_create_group(layers_kobj, &layers_group);
    }
    
    pr_info("ShadowOS: 🌀 Reality Layers ACTIVE - %d layers configured\n",
            layers_cfg.layer_count);
    return 0;
}

static void __exit shadow_layers_exit(void)
{
    if (layers_kobj) {
        sysfs_remove_group(layers_kobj, &layers_group);
        kobject_put(layers_kobj);
    }
    
    pr_info("ShadowOS: Reality Layers unloaded\n");
}

module_init(shadow_layers_init);
module_exit(shadow_layers_exit);
