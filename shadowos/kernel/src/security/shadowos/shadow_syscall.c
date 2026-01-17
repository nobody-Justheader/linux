/* SPDX-License-Identifier: GPL-2.0 */
/*
 * ShadowOS Syscall Obfuscation Module
 * 
 * 🔀 SYSCALL NUMBER RANDOMIZATION
 * 
 * Features:
 * - Per-process syscall mapping
 * - Randomized syscall table offsets
 * - Compatible userspace library
 * - Attack surface reduction
 *
 * Note: This is a security research module. Full syscall randomization
 * requires deep kernel changes. This module provides the infrastructure
 * for future implementation.
 *
 * Copyright (C) 2024 ShadowOS Project
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/sysfs.h>
#include <linux/kobject.h>
#include <linux/random.h>
#include <linux/slab.h>
#include <linux/hashtable.h>
#include <linux/sched.h>
#include <shadowos/shadow_types.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("ShadowOS Team");
MODULE_DESCRIPTION("ShadowOS Syscall Obfuscation - Attack Surface Reduction");
MODULE_VERSION(SHADOWOS_VERSION);

extern struct kobject *shadow_get_kobj(void);

#define MAP_HASH_BITS 8
#define NUM_SYSCALLS 450  /* Approximate number of syscalls */

/* Per-process syscall mapping */
struct syscall_map {
    pid_t pid;
    u16 forward[NUM_SYSCALLS];   /* Original -> Randomized */
    u16 reverse[NUM_SYSCALLS];   /* Randomized -> Original */
    unsigned long created;
    struct hlist_node node;
};

DEFINE_HASHTABLE(syscall_maps, MAP_HASH_BITS);
static DEFINE_SPINLOCK(syscall_lock);

/* Configuration */
static struct {
    bool enabled;
    bool per_process;          /* Create unique map per process */
    u64 processes_protected;
    u64 syscalls_translated;
} syscall_cfg = {
    .enabled = false,  /* Disabled by default - experimental */
    .per_process = true,
    .processes_protected = 0,
    .syscalls_translated = 0,
};

/* Generate randomized syscall mapping */
static void generate_mapping(struct syscall_map *map)
{
    int i;
    u16 temp, swap_idx;
    u8 rand_bytes[2];
    
    /* Initialize with identity mapping */
    for (i = 0; i < NUM_SYSCALLS; i++) {
        map->forward[i] = i;
    }
    
    /* Fisher-Yates shuffle */
    for (i = NUM_SYSCALLS - 1; i > 0; i--) {
        get_random_bytes(rand_bytes, sizeof(rand_bytes));
        swap_idx = (rand_bytes[0] | (rand_bytes[1] << 8)) % (i + 1);
        
        temp = map->forward[i];
        map->forward[i] = map->forward[swap_idx];
        map->forward[swap_idx] = temp;
    }
    
    /* Build reverse mapping */
    for (i = 0; i < NUM_SYSCALLS; i++) {
        map->reverse[map->forward[i]] = i;
    }
}

/* Get or create syscall map for process */
static struct syscall_map *get_syscall_map(pid_t pid)
{
    struct syscall_map *map;
    u32 hash = hash_32(pid, MAP_HASH_BITS);
    
    /* Look for existing map */
    hash_for_each_possible(syscall_maps, map, node, hash) {
        if (map->pid == pid)
            return map;
    }
    
    /* Create new map */
    map = kzalloc(sizeof(*map), GFP_ATOMIC);
    if (!map)
        return NULL;
    
    map->pid = pid;
    map->created = jiffies;
    generate_mapping(map);
    
    hash_add(syscall_maps, &map->node, hash);
    syscall_cfg.processes_protected++;
    
    pr_debug("ShadowOS Syscall: Created mapping for PID %d\n", pid);
    
    return map;
}

/* Translate syscall number (would be called from syscall entry) */
int shadow_syscall_translate(int syscall_nr)
{
    struct syscall_map *map;
    unsigned long flags;
    int result;
    
    if (!syscall_cfg.enabled)
        return syscall_nr;
    
    if (syscall_nr < 0 || syscall_nr >= NUM_SYSCALLS)
        return syscall_nr;
    
    spin_lock_irqsave(&syscall_lock, flags);
    
    if (syscall_cfg.per_process) {
        map = get_syscall_map(current->pid);
    } else {
        map = get_syscall_map(0);  /* Global map */
    }
    
    if (map) {
        result = map->reverse[syscall_nr];
        syscall_cfg.syscalls_translated++;
    } else {
        result = syscall_nr;
    }
    
    spin_unlock_irqrestore(&syscall_lock, flags);
    
    return result;
}
EXPORT_SYMBOL_GPL(shadow_syscall_translate);

/* Get mapping for userspace (so compatible loader can translate) */
static ssize_t syscall_mapping_show(struct kobject *k, struct kobj_attribute *a, char *buf)
{
    struct syscall_map *map;
    ssize_t len = 0;
    int i;
    
    spin_lock(&syscall_lock);
    map = get_syscall_map(current->pid);
    if (map) {
        /* Output first 20 mappings as example */
        for (i = 0; i < 20 && len < PAGE_SIZE - 32; i++) {
            len += sprintf(buf + len, "%d->%d\n", i, map->forward[i]);
        }
    }
    spin_unlock(&syscall_lock);
    
    return len;
}

/* Sysfs Interface */
static struct kobject *syscall_kobj;

static ssize_t syscall_enabled_show(struct kobject *k, struct kobj_attribute *a, char *buf)
{ return sprintf(buf, "%d\n", syscall_cfg.enabled); }

static ssize_t syscall_enabled_store(struct kobject *k, struct kobj_attribute *a, const char *buf, size_t c)
{
    bool val;
    if (kstrtobool(buf, &val))
        return -EINVAL;
    
    if (val && !syscall_cfg.enabled) {
        pr_warn("ShadowOS Syscall: ⚠️ Enabling syscall randomization - this is EXPERIMENTAL!\n");
    }
    syscall_cfg.enabled = val;
    return c;
}

static ssize_t syscall_stats_show(struct kobject *k, struct kobj_attribute *a, char *buf)
{
    return sprintf(buf, "enabled: %d\nper_process: %d\nprocesses: %llu\ntranslations: %llu\n",
                   syscall_cfg.enabled, syscall_cfg.per_process,
                   syscall_cfg.processes_protected, syscall_cfg.syscalls_translated);
}

static struct kobj_attribute syscall_enabled_attr = __ATTR(enabled, 0644, syscall_enabled_show, syscall_enabled_store);
static struct kobj_attribute syscall_mapping_attr = __ATTR(mapping, 0400, syscall_mapping_show, NULL);
static struct kobj_attribute syscall_stats_attr = __ATTR(stats, 0444, syscall_stats_show, NULL);

static struct attribute *syscall_attrs[] = {
    &syscall_enabled_attr.attr,
    &syscall_mapping_attr.attr,
    &syscall_stats_attr.attr,
    NULL
};

static struct attribute_group syscall_group = { .attrs = syscall_attrs };

static int __init shadow_syscall_init(void)
{
    struct kobject *parent;
    
    pr_info("ShadowOS: 🔀 Initializing Syscall Obfuscation\n");
    
    hash_init(syscall_maps);
    
    parent = shadow_get_kobj();
    if (parent) {
        syscall_kobj = kobject_create_and_add("syscall", parent);
        if (syscall_kobj)
            sysfs_create_group(syscall_kobj, &syscall_group);
    }
    
    pr_info("ShadowOS: 🔀 Syscall Obfuscation ready (disabled by default)\n");
    return 0;
}

static void __exit shadow_syscall_exit(void)
{
    struct syscall_map *map;
    struct hlist_node *tmp;
    int bkt;
    
    if (syscall_kobj) {
        sysfs_remove_group(syscall_kobj, &syscall_group);
        kobject_put(syscall_kobj);
    }
    
    spin_lock(&syscall_lock);
    hash_for_each_safe(syscall_maps, bkt, tmp, map, node) {
        hash_del(&map->node);
        kfree(map);
    }
    spin_unlock(&syscall_lock);
    
    pr_info("ShadowOS: Syscall Obfuscation unloaded\n");
}

module_init(shadow_syscall_init);
module_exit(shadow_syscall_exit);
