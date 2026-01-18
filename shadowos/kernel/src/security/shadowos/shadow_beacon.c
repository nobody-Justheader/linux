/* SPDX-License-Identifier: GPL-2.0 */
/*
 * ShadowOS Beacon Detection Module
 * 
 * 📡 C2 BEACON PATTERN DETECTION
 * 
 * Features:
 * - Detect periodic connection patterns
 * - Identify C2 beacon behavior
 * - Jitter analysis
 * - Suspicious IP logging
 *
 * Copyright (C) 2026 ShadowOS Project
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/sysfs.h>
#include <linux/kobject.h>
#include <linux/hashtable.h>
#include <linux/jhash.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <shadowos/shadow_types.h>

/* Module Info */
MODULE_LICENSE("GPL");
MODULE_AUTHOR("ShadowOS Team");
MODULE_DESCRIPTION("ShadowOS Beacon Detection - C2 Communication Detection");
MODULE_VERSION(SHADOWOS_VERSION);

/* Forward declaration */
extern struct kobject *shadow_get_kobj(void);

/* Hash table size */
#define CONN_HASH_BITS  10
#define MAX_HISTORY     10
#define BEACON_THRESHOLD_MS  5000   /* Connections within 5s are suspicious */
#define MIN_BEACONS     3           /* Minimum beacons to detect pattern */

/* Connection tracking entry */
struct conn_entry {
    __be32 daddr;
    __be16 dport;
    unsigned long timestamps[MAX_HISTORY];
    int ts_count;
    int beacon_score;
    struct hlist_node node;
};

DEFINE_HASHTABLE(conn_table, CONN_HASH_BITS);
static DEFINE_SPINLOCK(conn_lock);

/* Configuration */
static struct {
    bool enabled;
    u64 connections_tracked;
    u64 beacons_detected;
    u64 patterns_identified;
    int sensitivity;    /* 1-10, higher = more sensitive */
} beacon_cfg = {
    .enabled = true,
    .connections_tracked = 0,
    .beacons_detected = 0,
    .patterns_identified = 0,
    .sensitivity = 5,
};

/* Calculate beacon score based on timing regularity */
static int calculate_beacon_score(struct conn_entry *entry)
{
    int i;
    unsigned long intervals[MAX_HISTORY - 1];
    unsigned long avg_interval = 0;
    unsigned long variance = 0;
    
    if (entry->ts_count < MIN_BEACONS)
        return 0;
    
    /* Calculate intervals */
    for (i = 1; i < entry->ts_count; i++) {
        intervals[i-1] = entry->timestamps[i] - entry->timestamps[i-1];
        avg_interval += intervals[i-1];
    }
    avg_interval /= (entry->ts_count - 1);
    
    /* Calculate variance */
    for (i = 0; i < entry->ts_count - 1; i++) {
        long diff = intervals[i] - avg_interval;
        variance += diff * diff;
    }
    variance /= (entry->ts_count - 1);
    
    /* Low variance = regular pattern = high beacon score */
    /* Score 0-100, higher = more likely beacon */
    if (avg_interval > 0) {
        int regularity = 100 - (variance * 100 / (avg_interval * avg_interval));
        return (regularity > 0) ? regularity : 0;
    }
    
    return 0;
}

/* Netfilter hook for outbound connections */
static unsigned int beacon_hook(void *priv, struct sk_buff *skb,
                                const struct nf_hook_state *state)
{
    struct iphdr *iph;
    struct tcphdr *tcph;
    struct conn_entry *entry;
    u32 hash;
    unsigned long now = jiffies;
    bool found = false;
    
    if (!beacon_cfg.enabled)
        return NF_ACCEPT;
    
    iph = ip_hdr(skb);
    if (iph->protocol != IPPROTO_TCP)
        return NF_ACCEPT;
    
    tcph = tcp_hdr(skb);
    
    /* Only track SYN packets (new connections) */
    if (!tcph->syn || tcph->ack)
        return NF_ACCEPT;
    
    hash = jhash_2words(iph->daddr, tcph->dest, 0);
    
    spin_lock(&conn_lock);
    
    /* Look for existing entry */
    hash_for_each_possible(conn_table, entry, node, hash) {
        if (entry->daddr == iph->daddr && entry->dport == tcph->dest) {
            found = true;
            
            /* Shift timestamps and add new one */
            if (entry->ts_count >= MAX_HISTORY) {
                memmove(entry->timestamps, entry->timestamps + 1,
                        (MAX_HISTORY - 1) * sizeof(unsigned long));
                entry->ts_count = MAX_HISTORY - 1;
            }
            entry->timestamps[entry->ts_count++] = now;
            
            /* Calculate beacon score */
            entry->beacon_score = calculate_beacon_score(entry);
            
            if (entry->beacon_score > (100 - beacon_cfg.sensitivity * 10)) {
                beacon_cfg.beacons_detected++;
                pr_warn("ShadowOS Beacon: 📡 Suspicious beacon detected to %pI4:%d (score: %d)\n",
                        &entry->daddr, ntohs(entry->dport), entry->beacon_score);
            }
            break;
        }
    }
    
    /* Create new entry */
    if (!found) {
        entry = kzalloc(sizeof(*entry), GFP_ATOMIC);
        if (entry) {
            entry->daddr = iph->daddr;
            entry->dport = tcph->dest;
            entry->timestamps[0] = now;
            entry->ts_count = 1;
            entry->beacon_score = 0;
            hash_add(conn_table, &entry->node, hash);
            beacon_cfg.connections_tracked++;
        }
    }
    
    spin_unlock(&conn_lock);
    
    return NF_ACCEPT;
}

static struct nf_hook_ops beacon_nfho = {
    .hook = beacon_hook,
    .pf = NFPROTO_IPV4,
    .hooknum = NF_INET_LOCAL_OUT,
    .priority = NF_IP_PRI_MANGLE,
};

/* Sysfs Interface */
static struct kobject *beacon_kobj;

static ssize_t beacon_enabled_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
    return sprintf(buf, "%d\n", beacon_cfg.enabled);
}

static ssize_t beacon_enabled_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count)
{
    return kstrtobool(buf, &beacon_cfg.enabled) ? : count;
}

static ssize_t beacon_sensitivity_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
    return sprintf(buf, "%d\n", beacon_cfg.sensitivity);
}

static ssize_t beacon_sensitivity_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count)
{
    int val;
    if (kstrtoint(buf, 10, &val) || val < 1 || val > 10)
        return -EINVAL;
    beacon_cfg.sensitivity = val;
    return count;
}

static ssize_t beacon_stats_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
    return sprintf(buf, "tracked: %llu\nbeacons: %llu\npatterns: %llu\nsensitivity: %d\n",
                   beacon_cfg.connections_tracked, beacon_cfg.beacons_detected,
                   beacon_cfg.patterns_identified, beacon_cfg.sensitivity);
}

static struct kobj_attribute beacon_attr_enabled = __ATTR(enabled, 0644, beacon_enabled_show, beacon_enabled_store);
static struct kobj_attribute beacon_attr_sensitivity = __ATTR(sensitivity, 0644, beacon_sensitivity_show, beacon_sensitivity_store);
static struct kobj_attribute beacon_attr_stats = __ATTR(stats, 0444, beacon_stats_show, NULL);

static struct attribute *beacon_attrs[] = {
    &beacon_attr_enabled.attr,
    &beacon_attr_sensitivity.attr,
    &beacon_attr_stats.attr,
    NULL,
};

static struct attribute_group beacon_attr_group = {
    .attrs = beacon_attrs,
};

static int __init shadow_beacon_init(void)
{
    struct kobject *parent;
    int ret;
    
    pr_info("ShadowOS: 📡 Initializing Beacon Detection Module\n");
    
    hash_init(conn_table);
    
    ret = nf_register_net_hook(&init_net, &beacon_nfho);
    if (ret) {
        pr_err("ShadowOS: Failed to register beacon hook\n");
        return ret;
    }
    
    parent = shadow_get_kobj();
    if (parent) {
        beacon_kobj = kobject_create_and_add("beacon", parent);
        if (beacon_kobj) {
            if (sysfs_create_group(beacon_kobj, &beacon_attr_group))
                pr_err("ShadowOS: Failed to create beacon sysfs\n");
        }
    }
    
    pr_info("ShadowOS: 📡 Beacon Detection ACTIVE - Monitoring for C2 patterns\n");
    return 0;
}

static void __exit shadow_beacon_exit(void)
{
    struct conn_entry *entry;
    struct hlist_node *tmp;
    int bkt;
    
    nf_unregister_net_hook(&init_net, &beacon_nfho);
    
    if (beacon_kobj) {
        sysfs_remove_group(beacon_kobj, &beacon_attr_group);
        kobject_put(beacon_kobj);
    }
    
    /* Cleanup hash table */
    hash_for_each_safe(conn_table, bkt, tmp, entry, node) {
        hash_del(&entry->node);
        kfree(entry);
    }
    
    pr_info("ShadowOS: Beacon Detection unloaded\n");
}

module_init(shadow_beacon_init);
module_exit(shadow_beacon_exit);
