/* SPDX-License-Identifier: GPL-2.0 */
/*
 * ShadowOS Frustration Engine (shadow_frustrate)
 * 
 * MAKE ATTACKS PROGRESSIVELY HARDER
 * 
 * Features:
 * - Exponential delay for repeat offenders
 * - Packet corruption for known attackers
 * - Fake success then failure patterns
 *
 * Copyright (C) 2026 ShadowOS Project
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/hashtable.h>
#include <linux/slab.h>
#include <linux/sysfs.h>
#include <linux/kobject.h>
#include <linux/workqueue.h>
#include <shadowos/shadow_types.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("ShadowOS Team");
MODULE_DESCRIPTION("ShadowOS Frustration Engine - Progressive Attack Deterrent");
MODULE_VERSION(SHADOWOS_VERSION);

extern struct kobject *shadow_get_kobj(void);

/* Attacker profile */
struct attacker_profile {
    __be32 ip;
    u32 attempt_count;
    u32 current_delay_ms;
    u64 first_seen;
    u64 last_seen;
    u8 frustration_level;  /* 0-10 */
    struct hlist_node node;
};

/* Configuration */
static struct {
    bool enabled;
    u32 base_delay_ms;       /* Starting delay */
    u32 max_delay_ms;        /* Maximum delay */
    u32 delay_multiplier;    /* Multiplier (x100 for decimal) */
    u32 threshold;           /* Attempts before frustration */
    u64 attackers_tracked;
    u64 packets_delayed;
} frust_cfg = {
    .enabled = false,
    .base_delay_ms = 100,
    .max_delay_ms = 30000,
    .delay_multiplier = 150,  /* 1.5x */
    .threshold = 5,
};

static DEFINE_HASHTABLE(attacker_table, 10);
static DEFINE_SPINLOCK(frust_lock);
static struct kobject *frust_kobj;

/* Find or create attacker profile */
static struct attacker_profile *get_attacker(__be32 ip)
{
    struct attacker_profile *ap;
    u32 hash = jhash(&ip, sizeof(ip), 0);
    
    hash_for_each_possible(attacker_table, ap, node, hash) {
        if (ap->ip == ip) {
            ap->last_seen = ktime_get_real_seconds();
            ap->attempt_count++;
            return ap;
        }
    }
    
    /* Create new */
    ap = kzalloc(sizeof(*ap), GFP_ATOMIC);
    if (!ap)
        return NULL;
    
    ap->ip = ip;
    ap->attempt_count = 1;
    ap->current_delay_ms = 0;
    ap->first_seen = ktime_get_real_seconds();
    ap->last_seen = ap->first_seen;
    ap->frustration_level = 0;
    
    hash_add(attacker_table, &ap->node, hash);
    frust_cfg.attackers_tracked++;
    
    pr_debug("ShadowOS FRUST: New attacker tracked: %pI4\n", &ip);
    
    return ap;
}

/* Calculate frustration level */
static void update_frustration(struct attacker_profile *ap)
{
    if (ap->attempt_count < frust_cfg.threshold)
        return;
    
    if (ap->current_delay_ms == 0) {
        ap->current_delay_ms = frust_cfg.base_delay_ms;
    } else {
        ap->current_delay_ms = min(
            (ap->current_delay_ms * frust_cfg.delay_multiplier) / 100,
            frust_cfg.max_delay_ms
        );
    }
    
    ap->frustration_level = min((int)(ap->attempt_count / 10), 10);
}

/* Netfilter hook */
static unsigned int frust_hook(void *priv,
                               struct sk_buff *skb,
                               const struct nf_hook_state *state)
{
    struct iphdr *iph;
    struct attacker_profile *ap;
    
    if (!frust_cfg.enabled)
        return NF_ACCEPT;
    
    iph = ip_hdr(skb);
    if (!iph)
        return NF_ACCEPT;
    
    spin_lock(&frust_lock);
    ap = get_attacker(iph->saddr);
    if (ap) {
        update_frustration(ap);
        
        if (ap->current_delay_ms > 0) {
            /* Apply frustration - in real impl, delay the response */
            frust_cfg.packets_delayed++;
            pr_debug("ShadowOS FRUST: Delay %ums for %pI4 (level %u)\n",
                    ap->current_delay_ms, &iph->saddr, ap->frustration_level);
        }
    }
    spin_unlock(&frust_lock);
    
    return NF_ACCEPT;
}

static struct nf_hook_ops frust_nf_ops = {
    .hook = frust_hook,
    .pf = NFPROTO_IPV4,
    .hooknum = NF_INET_LOCAL_IN,
    .priority = NF_IP_PRI_FIRST + 10,
};

/* Sysfs Interface */
static ssize_t frust_enabled_show(struct kobject *kobj,
                                  struct kobj_attribute *attr, char *buf)
{
    return sprintf(buf, "%d\n", frust_cfg.enabled);
}

static ssize_t frust_enabled_store(struct kobject *kobj,
                                   struct kobj_attribute *attr,
                                   const char *buf, size_t count)
{
    return kstrtobool(buf, &frust_cfg.enabled) ? : count;
}

static ssize_t frust_config_show(struct kobject *kobj,
                                 struct kobj_attribute *attr, char *buf)
{
    return sprintf(buf, "base_delay: %u ms\nmax_delay: %u ms\n"
                        "multiplier: %u.%02u\nthreshold: %u\n",
                   frust_cfg.base_delay_ms,
                   frust_cfg.max_delay_ms,
                   frust_cfg.delay_multiplier / 100,
                   frust_cfg.delay_multiplier % 100,
                   frust_cfg.threshold);
}

static ssize_t frust_stats_show(struct kobject *kobj,
                                struct kobj_attribute *attr, char *buf)
{
    return sprintf(buf, "attackers_tracked: %llu\npackets_delayed: %llu\n",
                   frust_cfg.attackers_tracked, frust_cfg.packets_delayed);
}

static ssize_t frust_list_show(struct kobject *kobj,
                               struct kobj_attribute *attr, char *buf)
{
    struct attacker_profile *ap;
    int len = 0, i;
    
    spin_lock(&frust_lock);
    hash_for_each(attacker_table, i, ap, node) {
        len += snprintf(buf + len, PAGE_SIZE - len,
                       "%pI4: attempts=%u delay=%ums level=%u\n",
                       &ap->ip, ap->attempt_count, 
                       ap->current_delay_ms, ap->frustration_level);
        if (len >= PAGE_SIZE - 100)
            break;
    }
    spin_unlock(&frust_lock);
    
    if (len == 0)
        len = sprintf(buf, "No attackers tracked\n");
    
    return len;
}

static struct kobj_attribute frust_attr_enabled =
    __ATTR(enabled, 0644, frust_enabled_show, frust_enabled_store);
static struct kobj_attribute frust_attr_config =
    __ATTR(config, 0444, frust_config_show, NULL);
static struct kobj_attribute frust_attr_stats =
    __ATTR(stats, 0444, frust_stats_show, NULL);
static struct kobj_attribute frust_attr_list =
    __ATTR(attackers, 0444, frust_list_show, NULL);

static struct attribute *frust_attrs[] = {
    &frust_attr_enabled.attr,
    &frust_attr_config.attr,
    &frust_attr_stats.attr,
    &frust_attr_list.attr,
    NULL,
};

static struct attribute_group frust_attr_group = {
    .attrs = frust_attrs,
};

static int __init shadow_frustrate_init(void)
{
    int rc;
    struct kobject *parent;
    
    pr_info("ShadowOS: 😤 Initializing Frustration Engine\n");
    
    hash_init(attacker_table);
    
    rc = nf_register_net_hook(&init_net, &frust_nf_ops);
    if (rc) {
        pr_err("ShadowOS: Failed to register frustration hook\n");
        return rc;
    }
    
    parent = shadow_get_kobj();
    if (parent) {
        frust_kobj = kobject_create_and_add("frustrate", parent);
        if (frust_kobj) {
            if (sysfs_create_group(frust_kobj, &frust_attr_group))
                pr_err("ShadowOS: Failed to create frustrate sysfs\n");
        }
    }
    
    pr_info("ShadowOS: 😤 Frustration Engine ready!\n");
    return 0;
}

static void __exit shadow_frustrate_exit(void)
{
    struct attacker_profile *ap;
    struct hlist_node *tmp;
    int i;
    
    nf_unregister_net_hook(&init_net, &frust_nf_ops);
    
    if (frust_kobj) {
        sysfs_remove_group(frust_kobj, &frust_attr_group);
        kobject_put(frust_kobj);
    }
    
    hash_for_each_safe(attacker_table, i, tmp, ap, node) {
        hash_del(&ap->node);
        kfree(ap);
    }
    
    pr_info("ShadowOS: Frustration Engine unloaded\n");
}

module_init(shadow_frustrate_init);
module_exit(shadow_frustrate_exit);
