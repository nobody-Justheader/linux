/* SPDX-License-Identifier: GPL-2.0 */
/*
 * ShadowOS Network Scan Detection Module
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
#include <linux/udp.h>
#include <linux/hashtable.h>
#include <linux/spinlock.h>
#include <linux/jiffies.h>
#include <linux/slab.h>
#include <shadowos/shadow_types.h>

/* Validated symbol from shadow_core */
extern int shadow_send_alert(struct shadow_alert *alert);
extern int shadow_send_log(int level, const char *fmt, ...);
extern struct kobject *shadow_get_kobj(void);

/* Module Info */
MODULE_LICENSE("GPL");
MODULE_AUTHOR("ShadowOS Team");
MODULE_DESCRIPTION("ShadowOS Scan Detection");
MODULE_VERSION(SHADOWOS_VERSION);

/* Globals */
static bool detect_enabled = true;
static DEFINE_HASHTABLE(shadow_src_ht, 10); // 1024 buckets
static DEFINE_SPINLOCK(detect_lock);

/* Scan thresholds */
static struct {
    u32 syn_ports_per_sec;
    u32 syn_window_ms;
    u32 connect_per_sec;
    u32 udp_ports_per_sec;
} thresholds = {
    .syn_ports_per_sec = 5,
    .syn_window_ms = 10000,
    .connect_per_sec = 10,
    .udp_ports_per_sec = 10,
};

static struct shadow_source_track *get_source_track(__be32 src_ip)
{
    struct shadow_source_track *t;
    
    hash_for_each_possible(shadow_src_ht, t, node, src_ip) {
        if (t->src_ip == src_ip)
            return t;
    }
    return NULL;
}

static void update_source_track(struct shadow_source_track *t, struct sk_buff *skb, u16 dest_port, u8 flags)
{
    u64 now = ktime_get_real_ns();
    
    t->last_seen = now;
    t->packet_count++;
    t->flags_seen |= flags;
    
    // Check if port bit is set
    // Simplified port tracking for this phase
    if (!(t->port_bitmap[dest_port / 32] & (1 << (dest_port % 32)))) {
        t->port_bitmap[dest_port / 32] |= (1 << (dest_port % 32));
        t->port_count++;
    }
}

/* Sysfs */
static struct kobject *detect_kobj;

static ssize_t detect_enabled_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
    return sprintf(buf, "%d\n", detect_enabled);
}

static ssize_t detect_enabled_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count)
{
    return kstrtobool(buf, &detect_enabled) ? : count;
}

static ssize_t syn_threshold_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
    return sprintf(buf, "%u\n", thresholds.syn_ports_per_sec);
}

static ssize_t syn_threshold_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count)
{
    return kstrtouint(buf, 10, &thresholds.syn_ports_per_sec) ? : count;
}

static struct kobj_attribute detect_attr_enabled = __ATTR(enabled, 0644, detect_enabled_show, detect_enabled_store);
static struct kobj_attribute detect_attr_syn = __ATTR(syn_threshold, 0644, syn_threshold_show, syn_threshold_store);

static struct attribute *detect_attrs[] = {
    &detect_attr_enabled.attr,
    &detect_attr_syn.attr,
    NULL,
};

static struct attribute_group detect_attr_group = {
    .attrs = detect_attrs,
};

/* Netfilter Hook */
static unsigned int shadow_detect_hook(void *priv,
                                     struct sk_buff *skb,
                                     const struct nf_hook_state *state)
{
    struct iphdr *iph;
    struct tcphdr _tcph, *tcph = NULL;
    struct udphdr _udph, *udph = NULL;
    struct shadow_source_track *t;
    unsigned long flags;
    __be32 src_ip;
    u16 dest_port = 0;
    u8 tcp_flags = 0;
    unsigned int iph_len;
    
    if (!detect_enabled)
        return NF_ACCEPT;
    
    /* In PRE_ROUTING, need to check if we have enough data */
    if (!pskb_may_pull(skb, sizeof(struct iphdr)))
        return NF_ACCEPT;
        
    iph = ip_hdr(skb);
    if (!iph)
        return NF_ACCEPT;
    
    iph_len = iph->ihl * 4;
    if (iph_len < sizeof(struct iphdr))
        return NF_ACCEPT;
        
    src_ip = iph->saddr;
    
    if (iph->protocol == IPPROTO_TCP) {
        /* Use skb_header_pointer for safe access in PRE_ROUTING */
        tcph = skb_header_pointer(skb, iph_len, sizeof(_tcph), &_tcph);
        if (!tcph) return NF_ACCEPT;
        dest_port = ntohs(tcph->dest);
        
        // Extract flags (basic)
        if (tcph->syn) tcp_flags |= 0x02;
        if (tcph->ack) tcp_flags |= 0x10;
        if (tcph->fin) tcp_flags |= 0x01;
        
    } else if (iph->protocol == IPPROTO_UDP) {
        udph = skb_header_pointer(skb, iph_len, sizeof(_udph), &_udph);
        if (!udph) return NF_ACCEPT;
        dest_port = ntohs(udph->dest);
    } else {
        return NF_ACCEPT;
    }

    spin_lock_irqsave(&detect_lock, flags);
    
    t = get_source_track(src_ip);
    if (!t) {
        t = kzalloc(sizeof(*t), GFP_ATOMIC);
        if (t) {
            t->src_ip = src_ip;
            t->first_seen = ktime_get_real_ns();
            hash_add(shadow_src_ht, &t->node, src_ip);
        }
    }
    
    if (t) {
        update_source_track(t, skb, dest_port, tcp_flags);
        
        // Simple Threshold Check (Example for SYN Scan)
        // If SYN only and port count > threshold
        if (tcph && tcph->syn && !tcph->ack && t->port_count > thresholds.syn_ports_per_sec) {
            // Rate limit alerts logic would go here
            // Trigger Alert
            struct shadow_alert alert = {0};
            alert.type = SHADOW_ALERT_SCAN_SYN;
            alert.severity = SHADOW_SEV_HIGH;
            alert.src_ip = src_ip;
            alert.dst_port = htons(dest_port);
            alert.timestamp = ktime_get_real_ns();
            strncpy(alert.scan_type, "SYN_SCAN", sizeof(alert.scan_type));
            
            /* Log to dmesg for visibility */
            pr_alert("ShadowOS: 🚨 SCAN DETECTED: %s from %pI4 targeting port %d\n",
                     alert.scan_type, &src_ip, dest_port);
            
            spin_unlock_irqrestore(&detect_lock, flags);
            shadow_send_alert(&alert);
            return NF_ACCEPT;
        }
    }
    
    spin_unlock_irqrestore(&detect_lock, flags);
    
    return NF_ACCEPT;
}

static struct nf_hook_ops shadow_nf_ops[] = {
    {
        .hook = shadow_detect_hook,
        .pf = NFPROTO_IPV4,
        .hooknum = NF_INET_PRE_ROUTING,
        .priority = NF_IP_PRI_MANGLE + 1,
    },
};

static int __init shadow_detect_init(void)
{
    int rc;
    struct kobject *core_kobj;
    
    pr_info("ShadowOS: Initializing Scan Detection\n");
    
    /* Register Netfilter Hooks */
    rc = nf_register_net_hooks(&init_net, shadow_nf_ops, ARRAY_SIZE(shadow_nf_ops));
    if (rc) {
        pr_err("ShadowOS: Failed to register netfilter hooks\n");
        return rc;
    }
    
    /* Register Sysfs */
    core_kobj = shadow_get_kobj();
    if (core_kobj) {
        detect_kobj = kobject_create_and_add("detect", core_kobj);
        if (detect_kobj) {
            if (sysfs_create_group(detect_kobj, &detect_attr_group))
                pr_err("ShadowOS: Failed to create detect sysfs group\n");
        }
    }
    
    return 0;
}

static void __exit shadow_detect_exit(void)
{
    struct shadow_source_track *t;
    struct hlist_node *tmp;
    int i;
    
    nf_unregister_net_hooks(&init_net, shadow_nf_ops, ARRAY_SIZE(shadow_nf_ops));
    
    if (detect_kobj) {
        sysfs_remove_group(detect_kobj, &detect_attr_group);
        kobject_put(detect_kobj);
    }
    
    /* Cleanup hashtable */
    hash_for_each_safe(shadow_src_ht, i, tmp, t, node) {
        hash_del(&t->node);
        kfree(t);
    }
    
    pr_info("ShadowOS: Scan Detection unloaded\n");
}

module_init(shadow_detect_init);
module_exit(shadow_detect_exit);
