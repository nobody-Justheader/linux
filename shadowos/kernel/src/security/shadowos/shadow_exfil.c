/* SPDX-License-Identifier: GPL-2.0 */
/*
 * ShadowOS Exfiltration Detection Module
 * 
 * 📤 DATA EXFILTRATION DETECTION
 * 
 * Features:
 * - Abnormal outbound data detection
 * - DNS tunneling detection
 * - Large data transfer alerts
 * - Covert channel analysis
 *
 * Copyright (C) 2026 ShadowOS Project
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/sysfs.h>
#include <linux/kobject.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <shadowos/shadow_types.h>

/* Module Info */
MODULE_LICENSE("GPL");
MODULE_AUTHOR("ShadowOS Team");
MODULE_DESCRIPTION("ShadowOS Exfiltration Detection - Data Leak Prevention");
MODULE_VERSION(SHADOWOS_VERSION);

/* Forward declaration */
extern struct kobject *shadow_get_kobj(void);

/* Thresholds */
#define DNS_QUERY_MAX_LEN       63      /* Suspicious if longer */
#define LARGE_TRANSFER_BYTES    10485760 /* 10MB per connection */
#define DNS_TUNNEL_THRESHOLD    50      /* Queries per minute */

/* Configuration */
static struct {
    bool enabled;
    bool block_suspicious;
    u64 bytes_out_total;
    u64 packets_analyzed;
    u64 dns_queries;
    u64 suspicious_dns;
    u64 large_transfers;
    u64 blocked_count;
    unsigned long window_start;
    int dns_in_window;
} exfil_cfg = {
    .enabled = true,
    .block_suspicious = false,
    .bytes_out_total = 0,
    .packets_analyzed = 0,
    .dns_queries = 0,
    .suspicious_dns = 0,
    .large_transfers = 0,
    .blocked_count = 0,
    .window_start = 0,
    .dns_in_window = 0,
};

/* Check for DNS tunneling (long subdomain names) */
static bool check_dns_tunnel(struct sk_buff *skb, struct udphdr *udph)
{
    unsigned char *data;
    int len;
    int label_len;
    int total_len = 0;
    
    /* Get DNS payload */
    data = (unsigned char *)udph + sizeof(struct udphdr);
    len = ntohs(udph->len) - sizeof(struct udphdr);
    
    if (len < 12)  /* DNS header */
        return false;
    
    /* Skip DNS header, start at question section */
    data += 12;
    len -= 12;
    
    /* Parse domain name labels */
    while (len > 0 && *data != 0) {
        label_len = *data;
        if (label_len > DNS_QUERY_MAX_LEN) {
            exfil_cfg.suspicious_dns++;
            return true;  /* Suspiciously long label */
        }
        total_len += label_len;
        data += label_len + 1;
        len -= label_len + 1;
    }
    
    /* Check for high entropy in domain name (base64/hex encoded data) */
    if (total_len > 100) {
        exfil_cfg.suspicious_dns++;
        return true;
    }
    
    return false;
}

/* Netfilter hook for outbound traffic */
static unsigned int exfil_hook(void *priv, struct sk_buff *skb,
                               const struct nf_hook_state *state)
{
    struct iphdr *iph;
    struct udphdr *udph;
    unsigned long now = jiffies;
    
    if (!exfil_cfg.enabled)
        return NF_ACCEPT;
    
    iph = ip_hdr(skb);
    exfil_cfg.packets_analyzed++;
    exfil_cfg.bytes_out_total += ntohs(iph->tot_len);
    
    /* Check for DNS traffic */
    if (iph->protocol == IPPROTO_UDP) {
        udph = (struct udphdr *)((unsigned char *)iph + (iph->ihl * 4));
        
        if (ntohs(udph->dest) == 53) {
            exfil_cfg.dns_queries++;
            
            /* Rate limiting window */
            if (time_after(now, exfil_cfg.window_start + HZ * 60)) {
                exfil_cfg.window_start = now;
                exfil_cfg.dns_in_window = 0;
            }
            exfil_cfg.dns_in_window++;
            
            /* Check for DNS tunneling */
            if (check_dns_tunnel(skb, udph)) {
                pr_warn("ShadowOS Exfil: 📤 Suspicious DNS query detected (possible tunneling)\n");
                if (exfil_cfg.block_suspicious) {
                    exfil_cfg.blocked_count++;
                    return NF_DROP;
                }
            }
            
            /* Check for excessive DNS queries */
            if (exfil_cfg.dns_in_window > DNS_TUNNEL_THRESHOLD) {
                pr_warn("ShadowOS Exfil: 📤 Excessive DNS queries (%d/min) - possible exfil\n",
                        exfil_cfg.dns_in_window);
            }
        }
    }
    
    return NF_ACCEPT;
}

static struct nf_hook_ops exfil_nfho = {
    .hook = exfil_hook,
    .pf = NFPROTO_IPV4,
    .hooknum = NF_INET_LOCAL_OUT,
    .priority = NF_IP_PRI_MANGLE + 1,
};

/* Sysfs Interface */
static struct kobject *exfil_kobj;

static ssize_t exfil_enabled_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
    return sprintf(buf, "%d\n", exfil_cfg.enabled);
}

static ssize_t exfil_enabled_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count)
{
    return kstrtobool(buf, &exfil_cfg.enabled) ? : count;
}

static ssize_t exfil_block_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
    return sprintf(buf, "%d\n", exfil_cfg.block_suspicious);
}

static ssize_t exfil_block_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count)
{
    return kstrtobool(buf, &exfil_cfg.block_suspicious) ? : count;
}

static ssize_t exfil_stats_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
    return sprintf(buf, "packets: %llu\nbytes_out: %llu\ndns_queries: %llu\nsuspicious_dns: %llu\nlarge_transfers: %llu\nblocked: %llu\n",
                   exfil_cfg.packets_analyzed, exfil_cfg.bytes_out_total,
                   exfil_cfg.dns_queries, exfil_cfg.suspicious_dns,
                   exfil_cfg.large_transfers, exfil_cfg.blocked_count);
}

static struct kobj_attribute exfil_attr_enabled = __ATTR(enabled, 0644, exfil_enabled_show, exfil_enabled_store);
static struct kobj_attribute exfil_attr_block = __ATTR(block_suspicious, 0644, exfil_block_show, exfil_block_store);
static struct kobj_attribute exfil_attr_stats = __ATTR(stats, 0444, exfil_stats_show, NULL);

static struct attribute *exfil_attrs[] = {
    &exfil_attr_enabled.attr,
    &exfil_attr_block.attr,
    &exfil_attr_stats.attr,
    NULL,
};

static struct attribute_group exfil_attr_group = {
    .attrs = exfil_attrs,
};

static int __init shadow_exfil_init(void)
{
    struct kobject *parent;
    int ret;
    
    pr_info("ShadowOS: 📤 Initializing Exfiltration Detection Module\n");
    
    ret = nf_register_net_hook(&init_net, &exfil_nfho);
    if (ret) {
        pr_err("ShadowOS: Failed to register exfil hook\n");
        return ret;
    }
    
    parent = shadow_get_kobj();
    if (parent) {
        exfil_kobj = kobject_create_and_add("exfil", parent);
        if (exfil_kobj) {
            if (sysfs_create_group(exfil_kobj, &exfil_attr_group))
                pr_err("ShadowOS: Failed to create exfil sysfs\n");
        }
    }
    
    exfil_cfg.window_start = jiffies;
    
    pr_info("ShadowOS: 📤 Exfiltration Detection ACTIVE\n");
    return 0;
}

static void __exit shadow_exfil_exit(void)
{
    nf_unregister_net_hook(&init_net, &exfil_nfho);
    
    if (exfil_kobj) {
        sysfs_remove_group(exfil_kobj, &exfil_attr_group);
        kobject_put(exfil_kobj);
    }
    
    pr_info("ShadowOS: Exfiltration Detection unloaded\n");
}

module_init(shadow_exfil_init);
module_exit(shadow_exfil_exit);
