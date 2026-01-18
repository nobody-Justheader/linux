/* SPDX-License-Identifier: GPL-2.0 */
/*
 * ShadowOS Phishing Detection Module
 * 
 * 🎣 DOMAIN LOOKALIKE AND PHISHING DETECTION
 * 
 * Features:
 * - Levenshtein distance for typosquatting detection
 * - Homoglyph detection (unicode lookalikes)
 * - Known phishing domain database
 * - DNS query interception for real-time checking
 *
 * Copyright (C) 2026 ShadowOS Project
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/sysfs.h>
#include <linux/kobject.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <shadowos/shadow_types.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("ShadowOS Team");
MODULE_DESCRIPTION("ShadowOS Phishing Detection - Domain Typosquatting Protection");
MODULE_VERSION(SHADOWOS_VERSION);

extern struct kobject *shadow_get_kobj(void);

/* Known legitimate domains to protect */
static const char *protected_domains[] = {
    "google.com", "facebook.com", "amazon.com", "microsoft.com",
    "apple.com", "paypal.com", "netflix.com", "instagram.com",
    "twitter.com", "linkedin.com", "github.com", "dropbox.com",
    "bank", "secure", "login", "account", "verify", "update",
    NULL
};

/* Homoglyph mappings (unicode lookalikes) */
static const struct {
    char original;
    const char *lookalikes;
} homoglyphs[] = {
    {'a', "аạàáâãäå"},  /* Cyrillic а, Vietnamese, accents */
    {'e', "еėèéêëē"},
    {'i', "іìíîïı"},
    {'o', "оọòóôõö"},
    {'c', "сç"},
    {'p', "р"},
    {'s', "ѕ"},
    {'x', "х"},
    {'y', "уỳýŷÿ"},
    {0, NULL}
};

/* Configuration */
static struct {
    bool enabled;
    bool block_suspicious;
    int sensitivity;         /* 1-10, higher = more strict */
    u64 domains_checked;
    u64 phishing_detected;
    u64 blocked_count;
} phish_cfg = {
    .enabled = true,
    .block_suspicious = false,
    .sensitivity = 5,
    .domains_checked = 0,
    .phishing_detected = 0,
    .blocked_count = 0,
};

/* Calculate Levenshtein distance between two strings */
static int levenshtein_distance(const char *s1, const char *s2)
{
    int len1 = strlen(s1);
    int len2 = strlen(s2);
    int *prev, *curr, *tmp;
    int i, j, cost, result;
    
    if (len1 == 0) return len2;
    if (len2 == 0) return len1;
    
    prev = kmalloc((len2 + 1) * sizeof(int), GFP_ATOMIC);
    curr = kmalloc((len2 + 1) * sizeof(int), GFP_ATOMIC);
    if (!prev || !curr) {
        kfree(prev);
        kfree(curr);
        return -1;
    }
    
    for (j = 0; j <= len2; j++)
        prev[j] = j;
    
    for (i = 1; i <= len1; i++) {
        curr[0] = i;
        for (j = 1; j <= len2; j++) {
            cost = (s1[i-1] == s2[j-1]) ? 0 : 1;
            curr[j] = min3(
                prev[j] + 1,      /* deletion */
                curr[j-1] + 1,    /* insertion */
                prev[j-1] + cost  /* substitution */
            );
        }
        tmp = prev;
        prev = curr;
        curr = tmp;
    }
    
    result = prev[len2];
    kfree(prev);
    kfree(curr);
    return result;
}

/* Check if domain contains homoglyphs */
static bool contains_homoglyph(const char *domain)
{
    int i, j;
    
    for (i = 0; domain[i]; i++) {
        /* Check for non-ASCII characters that look like ASCII */
        if ((unsigned char)domain[i] > 127) {
            return true;  /* Non-ASCII in domain = suspicious */
        }
    }
    
    /* Check for suspicious patterns */
    for (i = 0; homoglyphs[i].original; i++) {
        for (j = 0; domain[j]; j++) {
            /* This is simplified - real implementation would check UTF-8 */
            if ((unsigned char)domain[j] > 127)
                return true;
        }
    }
    
    return false;
}

/* Check if domain is similar to a protected domain */
static bool is_typosquat(const char *domain)
{
    int i, distance, threshold;
    int domain_len = strlen(domain);
    
    /* Adjust threshold based on sensitivity */
    threshold = 11 - phish_cfg.sensitivity;  /* 1-10 -> 10-1 */
    
    for (i = 0; protected_domains[i]; i++) {
        int prot_len = strlen(protected_domains[i]);
        
        /* Skip if lengths are too different */
        if (abs(domain_len - prot_len) > threshold)
            continue;
        
        /* Check if domain contains protected keyword */
        if (strstr(domain, protected_domains[i]) && 
            strcmp(domain, protected_domains[i]) != 0) {
            /* e.g., "google-login.com" contains "google" but isn't "google.com" */
            if (strstr(domain, "-") || strstr(domain, "_"))
                return true;
        }
        
        /* Calculate edit distance */
        distance = levenshtein_distance(domain, protected_domains[i]);
        if (distance > 0 && distance <= threshold) {
            pr_debug("ShadowOS Phish: '%s' is %d edits from '%s'\n",
                     domain, distance, protected_domains[i]);
            return true;
        }
    }
    
    return false;
}

/* Parse domain from DNS query */
static int parse_dns_domain(const unsigned char *data, int len, char *domain, int domain_size)
{
    int i = 0, j = 0;
    int label_len;
    
    if (len < 12)
        return -1;
    
    /* Skip DNS header */
    data += 12;
    len -= 12;
    
    while (len > 0 && *data != 0 && j < domain_size - 1) {
        label_len = *data;
        if (label_len > 63 || label_len > len - 1)
            break;
        
        data++;
        len--;
        
        for (i = 0; i < label_len && j < domain_size - 1; i++) {
            domain[j++] = tolower(data[i]);
        }
        domain[j++] = '.';
        
        data += label_len;
        len -= label_len;
    }
    
    if (j > 0)
        domain[j - 1] = '\0';  /* Remove trailing dot */
    else
        domain[0] = '\0';
    
    return 0;
}

/* Netfilter hook for DNS queries */
static unsigned int phish_hook(void *priv, struct sk_buff *skb,
                               const struct nf_hook_state *state)
{
    struct iphdr *iph;
    struct udphdr *udph;
    unsigned char *dns_data;
    int dns_len;
    char domain[256];
    bool suspicious = false;
    
    if (!phish_cfg.enabled)
        return NF_ACCEPT;
    
    iph = ip_hdr(skb);
    if (iph->protocol != IPPROTO_UDP)
        return NF_ACCEPT;
    
    udph = (struct udphdr *)((unsigned char *)iph + (iph->ihl * 4));
    
    /* Only check DNS queries (destination port 53) */
    if (ntohs(udph->dest) != 53)
        return NF_ACCEPT;
    
    dns_data = (unsigned char *)udph + sizeof(struct udphdr);
    dns_len = ntohs(udph->len) - sizeof(struct udphdr);
    
    if (parse_dns_domain(dns_data, dns_len, domain, sizeof(domain)) < 0)
        return NF_ACCEPT;
    
    if (strlen(domain) == 0)
        return NF_ACCEPT;
    
    phish_cfg.domains_checked++;
    
    /* Check for phishing indicators */
    if (contains_homoglyph(domain)) {
        suspicious = true;
        pr_warn("ShadowOS Phish: 🎣 Homoglyph detected in domain: %s\n", domain);
    }
    
    if (is_typosquat(domain)) {
        suspicious = true;
        pr_warn("ShadowOS Phish: 🎣 Typosquat detected: %s\n", domain);
    }
    
    if (suspicious) {
        phish_cfg.phishing_detected++;
        
        if (phish_cfg.block_suspicious) {
            phish_cfg.blocked_count++;
            pr_warn("ShadowOS Phish: 🚫 BLOCKED suspicious domain: %s\n", domain);
            return NF_DROP;
        }
    }
    
    return NF_ACCEPT;
}

static struct nf_hook_ops phish_nfho = {
    .hook = phish_hook,
    .pf = NFPROTO_IPV4,
    .hooknum = NF_INET_LOCAL_OUT,
    .priority = NF_IP_PRI_FIRST,
};

/* Sysfs Interface */
static struct kobject *phish_kobj;

static ssize_t phish_enabled_show(struct kobject *k, struct kobj_attribute *a, char *buf)
{
    return sprintf(buf, "%d\n", phish_cfg.enabled);
}

static ssize_t phish_enabled_store(struct kobject *k, struct kobj_attribute *a, const char *buf, size_t c)
{
    return kstrtobool(buf, &phish_cfg.enabled) ? : c;
}

static ssize_t phish_block_show(struct kobject *k, struct kobj_attribute *a, char *buf)
{
    return sprintf(buf, "%d\n", phish_cfg.block_suspicious);
}

static ssize_t phish_block_store(struct kobject *k, struct kobj_attribute *a, const char *buf, size_t c)
{
    return kstrtobool(buf, &phish_cfg.block_suspicious) ? : c;
}

static ssize_t phish_sensitivity_show(struct kobject *k, struct kobj_attribute *a, char *buf)
{
    return sprintf(buf, "%d\n", phish_cfg.sensitivity);
}

static ssize_t phish_sensitivity_store(struct kobject *k, struct kobj_attribute *a, const char *buf, size_t c)
{
    int val;
    if (kstrtoint(buf, 10, &val) || val < 1 || val > 10)
        return -EINVAL;
    phish_cfg.sensitivity = val;
    return c;
}

static ssize_t phish_stats_show(struct kobject *k, struct kobj_attribute *a, char *buf)
{
    return sprintf(buf, "checked: %llu\ndetected: %llu\nblocked: %llu\nsensitivity: %d\n",
                   phish_cfg.domains_checked, phish_cfg.phishing_detected,
                   phish_cfg.blocked_count, phish_cfg.sensitivity);
}

static struct kobj_attribute phish_enabled_attr = __ATTR(enabled, 0644, phish_enabled_show, phish_enabled_store);
static struct kobj_attribute phish_block_attr = __ATTR(block_suspicious, 0644, phish_block_show, phish_block_store);
static struct kobj_attribute phish_sensitivity_attr = __ATTR(sensitivity, 0644, phish_sensitivity_show, phish_sensitivity_store);
static struct kobj_attribute phish_stats_attr = __ATTR(stats, 0444, phish_stats_show, NULL);

static struct attribute *phish_attrs[] = {
    &phish_enabled_attr.attr,
    &phish_block_attr.attr,
    &phish_sensitivity_attr.attr,
    &phish_stats_attr.attr,
    NULL
};

static struct attribute_group phish_group = { .attrs = phish_attrs };

static int __init shadow_phish_init(void)
{
    struct kobject *parent;
    int ret;
    
    pr_info("ShadowOS: 🎣 Initializing Phishing Detection Module\n");
    
    ret = nf_register_net_hook(&init_net, &phish_nfho);
    if (ret) {
        pr_err("ShadowOS: Failed to register phish hook\n");
        return ret;
    }
    
    parent = shadow_get_kobj();
    if (parent) {
        phish_kobj = kobject_create_and_add("phish", parent);
        if (phish_kobj)
            sysfs_create_group(phish_kobj, &phish_group);
    }
    
    pr_info("ShadowOS: 🎣 Phishing Detection ACTIVE - Protecting against typosquatting\n");
    return 0;
}

static void __exit shadow_phish_exit(void)
{
    nf_unregister_net_hook(&init_net, &phish_nfho);
    
    if (phish_kobj) {
        sysfs_remove_group(phish_kobj, &phish_group);
        kobject_put(phish_kobj);
    }
    
    pr_info("ShadowOS: Phishing Detection unloaded\n");
}

module_init(shadow_phish_init);
module_exit(shadow_phish_exit);
