/* SPDX-License-Identifier: GPL-2.0 */
/*
 * ShadowOS Attacker Profiling Module
 * 
 * 🎯 ATTACKER BEHAVIOR ANALYSIS AND FINGERPRINTING
 * 
 * Features:
 * - Track attack patterns per source IP
 * - Calculate threat scores
 * - Identify known attack signatures
 * - Build attacker fingerprints
 *
 * Copyright (C) 2024 ShadowOS Project
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/sysfs.h>
#include <linux/kobject.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/hashtable.h>
#include <linux/jhash.h>
#include <shadowos/shadow_types.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("ShadowOS Team");
MODULE_DESCRIPTION("ShadowOS Attacker Profiling - Threat Intelligence");
MODULE_VERSION(SHADOWOS_VERSION);

extern struct kobject *shadow_get_kobj(void);

#define PROFILE_HASH_BITS 10
#define MAX_ATTACK_TYPES 8

/* Attack types */
enum attack_type {
    ATTACK_SCAN = 0,
    ATTACK_BRUTE_FORCE,
    ATTACK_INJECTION,
    ATTACK_BEACON,
    ATTACK_EXFIL,
    ATTACK_OVERFLOW,
    ATTACK_DOS,
    ATTACK_OTHER
};

static const char *attack_names[] = {
    "scan", "brute_force", "injection", "beacon", 
    "exfil", "overflow", "dos", "other"
};

/* Attacker profile entry */
struct attacker_profile {
    __be32 ip_addr;
    unsigned long first_seen;
    unsigned long last_seen;
    u32 attack_counts[MAX_ATTACK_TYPES];
    u32 total_attacks;
    int threat_score;
    struct hlist_node node;
};

DEFINE_HASHTABLE(profile_table, PROFILE_HASH_BITS);
static DEFINE_SPINLOCK(profile_lock);

/* Configuration */
static struct {
    bool enabled;
    u64 attackers_tracked;
    u64 total_events;
} profile_cfg = {
    .enabled = true,
    .attackers_tracked = 0,
    .total_events = 0,
};

/* Get or create attacker profile */
static struct attacker_profile *get_profile(__be32 ip)
{
    struct attacker_profile *prof;
    u32 hash = jhash_1word(ip, 0);
    
    hash_for_each_possible(profile_table, prof, node, hash) {
        if (prof->ip_addr == ip) {
            prof->last_seen = jiffies;
            return prof;
        }
    }
    
    /* Create new profile */
    prof = kzalloc(sizeof(*prof), GFP_ATOMIC);
    if (!prof)
        return NULL;
    
    prof->ip_addr = ip;
    prof->first_seen = jiffies;
    prof->last_seen = jiffies;
    
    hash_add(profile_table, &prof->node, hash);
    profile_cfg.attackers_tracked++;
    
    return prof;
}

/* Calculate threat score for profile */
static int calculate_threat_score(struct attacker_profile *prof)
{
    int score = 0;
    int i;
    
    /* Weight different attack types */
    static const int weights[] = { 5, 10, 20, 15, 25, 30, 8, 5 };
    
    for (i = 0; i < MAX_ATTACK_TYPES; i++) {
        score += prof->attack_counts[i] * weights[i];
    }
    
    /* Recency bonus */
    if (time_before(jiffies, prof->last_seen + 60 * HZ))
        score *= 2;
    
    return min(score, 1000);  /* Cap at 1000 */
}

/* Record attack event from IP */
int shadow_profile_attack(__be32 ip, int attack_type)
{
    struct attacker_profile *prof;
    unsigned long flags;
    
    if (!profile_cfg.enabled)
        return 0;
    
    if (attack_type < 0 || attack_type >= MAX_ATTACK_TYPES)
        attack_type = ATTACK_OTHER;
    
    spin_lock_irqsave(&profile_lock, flags);
    
    prof = get_profile(ip);
    if (prof) {
        prof->attack_counts[attack_type]++;
        prof->total_attacks++;
        prof->threat_score = calculate_threat_score(prof);
        profile_cfg.total_events++;
        
        if (prof->threat_score >= 100) {
            pr_warn("ShadowOS Profile: 🎯 High-threat attacker %pI4 (score: %d)\n",
                    &ip, prof->threat_score);
        }
    }
    
    spin_unlock_irqrestore(&profile_lock, flags);
    return 0;
}
EXPORT_SYMBOL_GPL(shadow_profile_attack);

/* Sysfs Interface */
static struct kobject *profile_kobj;

static ssize_t profile_enabled_show(struct kobject *k, struct kobj_attribute *a, char *buf)
{ return sprintf(buf, "%d\n", profile_cfg.enabled); }

static ssize_t profile_enabled_store(struct kobject *k, struct kobj_attribute *a, const char *buf, size_t c)
{ return kstrtobool(buf, &profile_cfg.enabled) ? : c; }

static ssize_t profile_top_show(struct kobject *k, struct kobj_attribute *a, char *buf)
{
    struct attacker_profile *prof;
    ssize_t len = 0;
    int bkt;
    int count = 0;
    
    spin_lock(&profile_lock);
    hash_for_each(profile_table, bkt, prof, node) {
        if (count++ >= 10) break;  /* Top 10 only */
        len += sprintf(buf + len, "%pI4: score=%d attacks=%u\n",
                       &prof->ip_addr, prof->threat_score, prof->total_attacks);
    }
    spin_unlock(&profile_lock);
    
    return len;
}

static ssize_t profile_stats_show(struct kobject *k, struct kobj_attribute *a, char *buf)
{
    return sprintf(buf, "tracked: %llu\nevents: %llu\n",
                   profile_cfg.attackers_tracked, profile_cfg.total_events);
}

static struct kobj_attribute profile_enabled_attr = __ATTR(enabled, 0644, profile_enabled_show, profile_enabled_store);
static struct kobj_attribute profile_top_attr = __ATTR(top_attackers, 0444, profile_top_show, NULL);
static struct kobj_attribute profile_stats_attr = __ATTR(stats, 0444, profile_stats_show, NULL);

static struct attribute *profile_attrs[] = {
    &profile_enabled_attr.attr,
    &profile_top_attr.attr,
    &profile_stats_attr.attr,
    NULL
};

static struct attribute_group profile_group = { .attrs = profile_attrs };

static int __init shadow_profile_init(void)
{
    struct kobject *parent;
    
    pr_info("ShadowOS: 🎯 Initializing Attacker Profiling\n");
    
    hash_init(profile_table);
    
    parent = shadow_get_kobj();
    if (parent) {
        profile_kobj = kobject_create_and_add("profile", parent);
        if (profile_kobj)
            sysfs_create_group(profile_kobj, &profile_group);
    }
    
    pr_info("ShadowOS: 🎯 Attacker Profiling ACTIVE\n");
    return 0;
}

static void __exit shadow_profile_exit(void)
{
    struct attacker_profile *prof;
    struct hlist_node *tmp;
    int bkt;
    
    if (profile_kobj) {
        sysfs_remove_group(profile_kobj, &profile_group);
        kobject_put(profile_kobj);
    }
    
    spin_lock(&profile_lock);
    hash_for_each_safe(profile_table, bkt, tmp, prof, node) {
        hash_del(&prof->node);
        kfree(prof);
    }
    spin_unlock(&profile_lock);
    
    pr_info("ShadowOS: Attacker Profiling unloaded\n");
}

module_init(shadow_profile_init);
module_exit(shadow_profile_exit);
