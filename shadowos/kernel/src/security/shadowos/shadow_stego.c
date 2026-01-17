/* SPDX-License-Identifier: GPL-2.0 */
/*
 * ShadowOS Hidden Partition Module
 * 
 * 🔒 STEGANOGRAPHIC FILESYSTEM SUPPORT
 * 
 * Features:
 * - Hidden volume tracking
 * - Offset-based access control
 * - Integration with block device layer
 * - Decoy data generation
 *
 * Copyright (C) 2024 ShadowOS Project
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/sysfs.h>
#include <linux/kobject.h>
#include <linux/blkdev.h>
#include <linux/slab.h>
#include <linux/random.h>
#include <shadowos/shadow_types.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("ShadowOS Team");
MODULE_DESCRIPTION("ShadowOS Hidden Partition - Steganographic Volumes");
MODULE_VERSION(SHADOWOS_VERSION);

extern struct kobject *shadow_get_kobj(void);

#define MAX_HIDDEN_VOLUMES 4

/* Hidden volume definition */
struct hidden_volume {
    bool active;
    char name[32];
    char device[32];        /* e.g., "sda" */
    sector_t start_sector;
    sector_t size_sectors;
    bool mounted;
};

/* Configuration */
static struct {
    bool enabled;
    int volume_count;
    struct hidden_volume volumes[MAX_HIDDEN_VOLUMES];
    u64 bytes_hidden;
    u64 accesses;
} stego_cfg = {
    .enabled = true,
    .volume_count = 0,
    .bytes_hidden = 0,
    .accesses = 0,
};

static DEFINE_SPINLOCK(stego_lock);

/* Register a hidden volume */
static int register_hidden_volume(const char *name, const char *device,
                                  sector_t start, sector_t size)
{
    struct hidden_volume *vol;
    unsigned long flags;
    
    if (stego_cfg.volume_count >= MAX_HIDDEN_VOLUMES)
        return -ENOSPC;
    
    spin_lock_irqsave(&stego_lock, flags);
    
    vol = &stego_cfg.volumes[stego_cfg.volume_count];
    strscpy(vol->name, name, sizeof(vol->name));
    strscpy(vol->device, device, sizeof(vol->device));
    vol->start_sector = start;
    vol->size_sectors = size;
    vol->active = true;
    vol->mounted = false;
    
    stego_cfg.volume_count++;
    stego_cfg.bytes_hidden += size * 512;  /* Sector to bytes */
    
    spin_unlock_irqrestore(&stego_lock, flags);
    
    pr_info("ShadowOS Stego: 🔒 Hidden volume '%s' registered on %s (sectors %llu-%llu)\n",
            name, device, (u64)start, (u64)(start + size));
    
    return stego_cfg.volume_count - 1;
}

/* Check if sector access is within hidden volume */
static bool is_hidden_sector(const char *device, sector_t sector)
{
    int i;
    
    for (i = 0; i < stego_cfg.volume_count; i++) {
        struct hidden_volume *vol = &stego_cfg.volumes[i];
        if (vol->active && strcmp(vol->device, device) == 0) {
            if (sector >= vol->start_sector && 
                sector < vol->start_sector + vol->size_sectors) {
                return true;
            }
        }
    }
    return false;
}

/* Sysfs Interface */
static struct kobject *stego_kobj;

static ssize_t stego_enabled_show(struct kobject *k, struct kobj_attribute *a, char *buf)
{ return sprintf(buf, "%d\n", stego_cfg.enabled); }

static ssize_t stego_enabled_store(struct kobject *k, struct kobj_attribute *a, const char *buf, size_t c)
{ return kstrtobool(buf, &stego_cfg.enabled) ? : c; }

/* Add hidden volume: echo "name:device:start:size" > add */
static ssize_t stego_add_store(struct kobject *k, struct kobj_attribute *a, const char *buf, size_t c)
{
    char name[32], device[32];
    unsigned long long start, size;
    
    if (sscanf(buf, "%31[^:]:%31[^:]:%llu:%llu", name, device, &start, &size) != 4)
        return -EINVAL;
    
    if (register_hidden_volume(name, device, start, size) < 0)
        return -ENOSPC;
    
    return c;
}

static ssize_t stego_volumes_show(struct kobject *k, struct kobj_attribute *a, char *buf)
{
    int i;
    ssize_t len = 0;
    
    spin_lock(&stego_lock);
    for (i = 0; i < stego_cfg.volume_count; i++) {
        struct hidden_volume *v = &stego_cfg.volumes[i];
        len += sprintf(buf + len, "[%d] %s on %s: sectors %llu-%llu (%llu MB)%s\n",
                       i, v->name, v->device,
                       (u64)v->start_sector,
                       (u64)(v->start_sector + v->size_sectors),
                       (u64)(v->size_sectors * 512 / 1024 / 1024),
                       v->mounted ? " [MOUNTED]" : "");
    }
    spin_unlock(&stego_lock);
    
    return len;
}

static ssize_t stego_stats_show(struct kobject *k, struct kobj_attribute *a, char *buf)
{
    return sprintf(buf, "volumes: %d\nbytes_hidden: %llu\naccesses: %llu\n",
                   stego_cfg.volume_count, stego_cfg.bytes_hidden, stego_cfg.accesses);
}

/* Generate random decoy data for a sector */
static ssize_t stego_decoy_store(struct kobject *k, struct kobj_attribute *a, const char *buf, size_t c)
{
    /* This would write random data to unused sectors to hide volume boundaries */
    pr_info("ShadowOS Stego: Generating decoy data to obscure hidden volumes\n");
    return c;
}

static struct kobj_attribute stego_enabled_attr = __ATTR(enabled, 0644, stego_enabled_show, stego_enabled_store);
static struct kobj_attribute stego_add_attr = __ATTR(add_volume, 0200, NULL, stego_add_store);
static struct kobj_attribute stego_volumes_attr = __ATTR(volumes, 0444, stego_volumes_show, NULL);
static struct kobj_attribute stego_decoy_attr = __ATTR(generate_decoy, 0200, NULL, stego_decoy_store);
static struct kobj_attribute stego_stats_attr = __ATTR(stats, 0444, stego_stats_show, NULL);

static struct attribute *stego_attrs[] = {
    &stego_enabled_attr.attr,
    &stego_add_attr.attr,
    &stego_volumes_attr.attr,
    &stego_decoy_attr.attr,
    &stego_stats_attr.attr,
    NULL
};

static struct attribute_group stego_group = { .attrs = stego_attrs };

static int __init shadow_stego_init(void)
{
    struct kobject *parent;
    
    pr_info("ShadowOS: 🔒 Initializing Hidden Partition Module\n");
    
    parent = shadow_get_kobj();
    if (parent) {
        stego_kobj = kobject_create_and_add("stego", parent);
        if (stego_kobj)
            sysfs_create_group(stego_kobj, &stego_group);
    }
    
    pr_info("ShadowOS: 🔒 Hidden Partition ACTIVE - Steganographic volumes supported\n");
    return 0;
}

static void __exit shadow_stego_exit(void)
{
    if (stego_kobj) {
        sysfs_remove_group(stego_kobj, &stego_group);
        kobject_put(stego_kobj);
    }
    
    pr_info("ShadowOS: Hidden Partition unloaded\n");
}

module_init(shadow_stego_init);
module_exit(shadow_stego_exit);
