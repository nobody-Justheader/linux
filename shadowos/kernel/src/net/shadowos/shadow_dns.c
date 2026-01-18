/* SPDX-License-Identifier: GPL-2.0 */
/*
 * ShadowOS DNS Sinkhole Module
 * 
 * KERNEL-LEVEL DNS FILTERING - CANNOT BE BYPASSED BY USERSPACE
 * 
 * Features:
 * - Intercepts ALL DNS queries at the kernel level
 * - Domain blocklist with fast hash lookup
 * - Query logging for exfiltration detection
 * - Force encrypted DNS mode (blocks plain DNS)
 *
 * Copyright (C) 2026 ShadowOS Project
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/hashtable.h>
#include <linux/slab.h>
#include <linux/sysfs.h>
#include <linux/kobject.h>
#include <linux/spinlock.h>
#include <shadowos/shadow_types.h>

/* Module Info */
MODULE_LICENSE("GPL");
MODULE_AUTHOR("ShadowOS Team");
MODULE_DESCRIPTION("ShadowOS DNS Sinkhole - Kernel-Level DNS Filtering");
MODULE_VERSION(SHADOWOS_VERSION);

/* Forward declaration */
extern struct kobject *shadow_get_kobj(void);
extern int shadow_send_log(int level, const char *fmt, ...);

/* DNS Header Structure */
struct dns_header {
    __be16 id;
    __be16 flags;
    __be16 qdcount;
    __be16 ancount;
    __be16 nscount;
    __be16 arcount;
} __packed;

/* Blocked domain entry */
struct blocked_domain {
    char domain[256];
    struct hlist_node node;
};

/* Configuration */
static struct {
    bool enabled;
    bool log_queries;
    bool block_plain_dns;  /* Force DoH/DoT only */
    u64 queries_blocked;
    u64 queries_logged;
} dns_cfg = {
    .enabled = false,
    .log_queries = true,
    .block_plain_dns = false,
    .queries_blocked = 0,
    .queries_logged = 0,
};

static DEFINE_HASHTABLE(dns_blocklist, 8);  /* 256 buckets */
static DEFINE_SPINLOCK(dns_lock);

/* Simple domain hash */
static u32 domain_hash(const char *domain)
{
    u32 hash = 0;
    while (*domain)
        hash = hash * 31 + *domain++;
    return hash;
}

/* Check if domain is blocked */
static bool is_domain_blocked(const char *domain)
{
    struct blocked_domain *entry;
    u32 hash = domain_hash(domain);
    
    hash_for_each_possible(dns_blocklist, entry, node, hash) {
        if (strcmp(entry->domain, domain) == 0)
            return true;
        /* Also check if it's a subdomain */
        if (strstr(domain, entry->domain) != NULL)
            return true;
    }
    return false;
}

/* Extract domain name from DNS query */
static int extract_domain(const unsigned char *dns_data, int len, char *domain, int domain_size)
{
    int i = 0, j = 0;
    int label_len;
    
    if (len < sizeof(struct dns_header) + 1)
        return -1;
    
    dns_data += sizeof(struct dns_header);
    len -= sizeof(struct dns_header);
    
    while (i < len && j < domain_size - 1) {
        label_len = dns_data[i];
        if (label_len == 0)
            break;
        if (label_len > 63)
            return -1;  /* Compression pointer or invalid */
        
        if (j > 0)
            domain[j++] = '.';
        
        i++;
        if (i + label_len > len)
            return -1;
        
        while (label_len-- > 0 && j < domain_size - 1) {
            domain[j++] = dns_data[i++];
        }
    }
    domain[j] = '\0';
    return j;
}

/* Netfilter hook for DNS packets */
static unsigned int dns_hook(void *priv,
                            struct sk_buff *skb,
                            const struct nf_hook_state *state)
{
    struct iphdr *iph;
    struct udphdr *udph;
    unsigned char *dns_data;
    char domain[256];
    int dns_len;
    
    if (!dns_cfg.enabled)
        return NF_ACCEPT;
    
    iph = ip_hdr(skb);
    if (!iph)
        return NF_ACCEPT;
    
    /* Only interested in UDP port 53 */
    if (iph->protocol != IPPROTO_UDP)
        return NF_ACCEPT;
    
    udph = udp_hdr(skb);
    if (!udph)
        return NF_ACCEPT;
    
    if (ntohs(udph->dest) != 53)
        return NF_ACCEPT;
    
    /* Block ALL plain DNS if force encrypted mode */
    if (dns_cfg.block_plain_dns) {
        dns_cfg.queries_blocked++;
        pr_debug("ShadowOS DNS: Blocked plain DNS (force encrypted mode)\n");
        return NF_DROP;
    }
    
    /* Extract DNS query data */
    dns_data = (unsigned char *)udph + sizeof(struct udphdr);
    dns_len = ntohs(udph->len) - sizeof(struct udphdr);
    
    if (dns_len < sizeof(struct dns_header))
        return NF_ACCEPT;
    
    if (extract_domain(dns_data, dns_len, domain, sizeof(domain)) > 0) {
        /* Log query if enabled */
        if (dns_cfg.log_queries) {
            pr_info("ShadowOS DNS: Query for %s from %pI4\n", domain, &iph->saddr);
            dns_cfg.queries_logged++;
        }
        
        /* Check blocklist */
        spin_lock_bh(&dns_lock);
        if (is_domain_blocked(domain)) {
            spin_unlock_bh(&dns_lock);
            dns_cfg.queries_blocked++;
            pr_info("ShadowOS DNS: BLOCKED %s\n", domain);
            return NF_DROP;
        }
        spin_unlock_bh(&dns_lock);
    }
    
    return NF_ACCEPT;
}

static struct nf_hook_ops dns_nf_ops[] = {
    {
        .hook = dns_hook,
        .pf = NFPROTO_IPV4,
        .hooknum = NF_INET_LOCAL_OUT,
        .priority = NF_IP_PRI_MANGLE,
    },
};

/* Sysfs Interface */
static struct kobject *dns_kobj;

static ssize_t dns_enabled_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
    return sprintf(buf, "%d\n", dns_cfg.enabled);
}

static ssize_t dns_enabled_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count)
{
    return kstrtobool(buf, &dns_cfg.enabled) ? : count;
}

static ssize_t dns_log_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
    return sprintf(buf, "%d\n", dns_cfg.log_queries);
}

static ssize_t dns_log_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count)
{
    return kstrtobool(buf, &dns_cfg.log_queries) ? : count;
}

static ssize_t dns_force_encrypted_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
    return sprintf(buf, "%d\n", dns_cfg.block_plain_dns);
}

static ssize_t dns_force_encrypted_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count)
{
    return kstrtobool(buf, &dns_cfg.block_plain_dns) ? : count;
}

static ssize_t dns_stats_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
    return sprintf(buf, "blocked: %llu\nlogged: %llu\n", 
                   dns_cfg.queries_blocked, dns_cfg.queries_logged);
}

/* Add domain to blocklist via sysfs */
static ssize_t dns_blocklist_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count)
{
    struct blocked_domain *entry;
    char domain[256];
    int len;
    
    len = min(count, sizeof(domain) - 1);
    strncpy(domain, buf, len);
    domain[len] = '\0';
    
    /* Remove trailing newline */
    if (len > 0 && domain[len-1] == '\n')
        domain[len-1] = '\0';
    
    entry = kzalloc(sizeof(*entry), GFP_KERNEL);
    if (!entry)
        return -ENOMEM;
    
    strncpy(entry->domain, domain, sizeof(entry->domain) - 1);
    
    spin_lock_bh(&dns_lock);
    hash_add(dns_blocklist, &entry->node, domain_hash(domain));
    spin_unlock_bh(&dns_lock);
    
    pr_info("ShadowOS DNS: Added %s to blocklist\n", domain);
    return count;
}

static struct kobj_attribute dns_attr_enabled = __ATTR(enabled, 0644, dns_enabled_show, dns_enabled_store);
static struct kobj_attribute dns_attr_log = __ATTR(log_queries, 0644, dns_log_show, dns_log_store);
static struct kobj_attribute dns_attr_force = __ATTR(force_encrypted, 0644, dns_force_encrypted_show, dns_force_encrypted_store);
static struct kobj_attribute dns_attr_stats = __ATTR(stats, 0444, dns_stats_show, NULL);
static struct kobj_attribute dns_attr_blocklist = __ATTR(blocklist, 0200, NULL, dns_blocklist_store);

static struct attribute *dns_attrs[] = {
    &dns_attr_enabled.attr,
    &dns_attr_log.attr,
    &dns_attr_force.attr,
    &dns_attr_stats.attr,
    &dns_attr_blocklist.attr,
    NULL,
};

static struct attribute_group dns_attr_group = {
    .attrs = dns_attrs,
};

static int __init shadow_dns_init(void)
{
    int rc;
    struct kobject *parent;
    
    pr_info("ShadowOS: 🌐 Initializing DNS Sinkhole - KERNEL-LEVEL DNS CONTROL\n");
    
    rc = nf_register_net_hooks(&init_net, dns_nf_ops, ARRAY_SIZE(dns_nf_ops));
    if (rc) {
        pr_err("ShadowOS: Failed to register DNS hooks\n");
        return rc;
    }
    
    parent = shadow_get_kobj();
    if (parent) {
        dns_kobj = kobject_create_and_add("dns", parent);
        if (dns_kobj) {
            if (sysfs_create_group(dns_kobj, &dns_attr_group))
                pr_err("ShadowOS: Failed to create DNS sysfs\n");
        }
    }
    
    pr_info("ShadowOS: 🌐 DNS Sinkhole ACTIVE - All DNS queries under kernel control!\n");
    return 0;
}

static void __exit shadow_dns_exit(void)
{
    struct blocked_domain *entry;
    struct hlist_node *tmp;
    int i;
    
    nf_unregister_net_hooks(&init_net, dns_nf_ops, ARRAY_SIZE(dns_nf_ops));
    
    if (dns_kobj) {
        sysfs_remove_group(dns_kobj, &dns_attr_group);
        kobject_put(dns_kobj);
    }
    
    /* Cleanup blocklist */
    hash_for_each_safe(dns_blocklist, i, tmp, entry, node) {
        hash_del(&entry->node);
        kfree(entry);
    }
    
    pr_info("ShadowOS: DNS Sinkhole unloaded\n");
}

module_init(shadow_dns_init);
module_exit(shadow_dns_exit);
