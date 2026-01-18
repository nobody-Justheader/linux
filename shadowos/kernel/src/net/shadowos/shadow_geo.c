/* SPDX-License-Identifier: GPL-2.0 */
/*
 * ShadowOS Geo-Blocking Module
 * 
 * KERNEL-LEVEL GEOGRAPHIC TRAFFIC CONTROL
 * 
 * Features:
 * - IP-to-country lookup with binary search
 * - Country blocklist/allowlist modes
 * - Connection logging by country
 * - Blocks traffic BEFORE it reaches any application
 *
 * Copyright (C) 2026 ShadowOS Project
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/sysfs.h>
#include <linux/kobject.h>
#include <shadowos/shadow_types.h>

/* Module Info */
MODULE_LICENSE("GPL");
MODULE_AUTHOR("ShadowOS Team");
MODULE_DESCRIPTION("ShadowOS Geo-Blocking - Block Traffic by Country");
MODULE_VERSION(SHADOWOS_VERSION);

/* Forward declaration */
extern struct kobject *shadow_get_kobj(void);

/* Geo Mode */
enum geo_mode {
    GEO_MODE_OFF = 0,
    GEO_MODE_BLOCK,     /* Block listed countries */
    GEO_MODE_ALLOW,     /* Only allow listed countries */
};

/* IP Range with country code */
struct geo_range {
    __be32 start;
    __be32 end;
    char country[3];  /* ISO 3166-1 alpha-2 + null */
};

/* Sample IP ranges (would be loaded from userspace in production) */
static struct geo_range sample_ranges[] = {
    /* Russia - sample ranges */
    {.start = 0x05000000, .end = 0x050FFFFF, .country = "RU"},
    {.start = 0x25000000, .end = 0x250FFFFF, .country = "RU"},
    /* China - sample ranges */
    {.start = 0x01000000, .end = 0x010FFFFF, .country = "CN"},
    {.start = 0x24000000, .end = 0x240FFFFF, .country = "CN"},
    /* North Korea - sample range */
    {.start = 0xAB000000, .end = 0xAB00FFFF, .country = "KP"},
    /* Iran - sample range */
    {.start = 0x02BC0000, .end = 0x02BCFFFF, .country = "IR"},
};

#define GEO_RANGE_COUNT ARRAY_SIZE(sample_ranges)

/* Configuration */
static struct {
    enum geo_mode mode;
    char countries[64];     /* Comma-separated country codes */
    u64 connections_blocked;
    u64 connections_logged;
    bool log_enabled;
} geo_cfg = {
    .mode = GEO_MODE_OFF,
    .countries = "",
    .connections_blocked = 0,
    .connections_logged = 0,
    .log_enabled = true,
};

/* Binary search for IP lookup */
static const char *geo_lookup(__be32 ip)
{
    int lo = 0, hi = GEO_RANGE_COUNT - 1;
    u32 ip_host = ntohl(ip);
    
    while (lo <= hi) {
        int mid = (lo + hi) / 2;
        u32 start = ntohl(sample_ranges[mid].start);
        u32 end = ntohl(sample_ranges[mid].end);
        
        if (ip_host < start)
            hi = mid - 1;
        else if (ip_host > end)
            lo = mid + 1;
        else
            return sample_ranges[mid].country;
    }
    return "??";
}

/* Check if country is in the configured list */
static bool country_in_list(const char *country)
{
    char *p;
    char countries_copy[64];
    char *token;
    
    if (strlen(geo_cfg.countries) == 0)
        return false;
    
    strncpy(countries_copy, geo_cfg.countries, sizeof(countries_copy) - 1);
    countries_copy[sizeof(countries_copy) - 1] = '\0';
    
    p = countries_copy;
    while ((token = strsep(&p, ",")) != NULL) {
        if (strcmp(token, country) == 0)
            return true;
    }
    return false;
}

/* Netfilter hook for incoming connections */
static unsigned int geo_hook_in(void *priv,
                                struct sk_buff *skb,
                                const struct nf_hook_state *state)
{
    struct iphdr *iph;
    const char *country;
    bool should_block = false;
    
    if (geo_cfg.mode == GEO_MODE_OFF)
        return NF_ACCEPT;
    
    iph = ip_hdr(skb);
    if (!iph)
        return NF_ACCEPT;
    
    country = geo_lookup(iph->saddr);
    
    if (geo_cfg.log_enabled && strcmp(country, "??") != 0) {
        pr_debug("ShadowOS Geo: Connection from %pI4 (%s)\n", &iph->saddr, country);
        geo_cfg.connections_logged++;
    }
    
    switch (geo_cfg.mode) {
    case GEO_MODE_BLOCK:
        if (country_in_list(country))
            should_block = true;
        break;
    case GEO_MODE_ALLOW:
        if (!country_in_list(country) && strcmp(country, "??") != 0)
            should_block = true;
        break;
    default:
        break;
    }
    
    if (should_block) {
        geo_cfg.connections_blocked++;
        pr_info("ShadowOS Geo: 🚫 BLOCKED connection from %s (%pI4)\n", country, &iph->saddr);
        return NF_DROP;
    }
    
    return NF_ACCEPT;
}

/* Also hook outgoing to prevent connections TO blocked countries */
static unsigned int geo_hook_out(void *priv,
                                 struct sk_buff *skb,
                                 const struct nf_hook_state *state)
{
    struct iphdr *iph;
    const char *country;
    bool should_block = false;
    
    if (geo_cfg.mode == GEO_MODE_OFF)
        return NF_ACCEPT;
    
    iph = ip_hdr(skb);
    if (!iph)
        return NF_ACCEPT;
    
    country = geo_lookup(iph->daddr);
    
    switch (geo_cfg.mode) {
    case GEO_MODE_BLOCK:
        if (country_in_list(country))
            should_block = true;
        break;
    case GEO_MODE_ALLOW:
        if (!country_in_list(country) && strcmp(country, "??") != 0)
            should_block = true;
        break;
    default:
        break;
    }
    
    if (should_block) {
        geo_cfg.connections_blocked++;
        pr_info("ShadowOS Geo: 🚫 BLOCKED outgoing to %s (%pI4)\n", country, &iph->daddr);
        return NF_DROP;
    }
    
    return NF_ACCEPT;
}

static struct nf_hook_ops geo_nf_ops[] = {
    {
        .hook = geo_hook_in,
        .pf = NFPROTO_IPV4,
        .hooknum = NF_INET_LOCAL_IN,
        .priority = NF_IP_PRI_FIRST,
    },
    {
        .hook = geo_hook_out,
        .pf = NFPROTO_IPV4,
        .hooknum = NF_INET_LOCAL_OUT,
        .priority = NF_IP_PRI_FIRST,
    },
};

/* Sysfs Interface */
static struct kobject *geo_kobj;

static ssize_t geo_mode_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
    const char *modes[] = {"off", "block", "allow"};
    return sprintf(buf, "%s\n", modes[geo_cfg.mode]);
}

static ssize_t geo_mode_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count)
{
    if (sysfs_streq(buf, "off"))
        geo_cfg.mode = GEO_MODE_OFF;
    else if (sysfs_streq(buf, "block"))
        geo_cfg.mode = GEO_MODE_BLOCK;
    else if (sysfs_streq(buf, "allow"))
        geo_cfg.mode = GEO_MODE_ALLOW;
    else
        return -EINVAL;
    
    pr_info("ShadowOS Geo: Mode set to %s\n", 
            geo_cfg.mode == GEO_MODE_OFF ? "off" : 
            geo_cfg.mode == GEO_MODE_BLOCK ? "block" : "allow");
    return count;
}

static ssize_t geo_countries_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
    return sprintf(buf, "%s\n", geo_cfg.countries);
}

static ssize_t geo_countries_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count)
{
    int len = min(count, sizeof(geo_cfg.countries) - 1);
    strncpy(geo_cfg.countries, buf, len);
    geo_cfg.countries[len] = '\0';
    
    /* Remove trailing newline */
    if (len > 0 && geo_cfg.countries[len-1] == '\n')
        geo_cfg.countries[len-1] = '\0';
    
    pr_info("ShadowOS Geo: Countries set to [%s]\n", geo_cfg.countries);
    return count;
}

static ssize_t geo_stats_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
    return sprintf(buf, "blocked: %llu\nlogged: %llu\n", 
                   geo_cfg.connections_blocked, geo_cfg.connections_logged);
}

static struct kobj_attribute geo_attr_mode = __ATTR(mode, 0644, geo_mode_show, geo_mode_store);
static struct kobj_attribute geo_attr_countries = __ATTR(countries, 0644, geo_countries_show, geo_countries_store);
static struct kobj_attribute geo_attr_stats = __ATTR(stats, 0444, geo_stats_show, NULL);

static struct attribute *geo_attrs[] = {
    &geo_attr_mode.attr,
    &geo_attr_countries.attr,
    &geo_attr_stats.attr,
    NULL,
};

static struct attribute_group geo_attr_group = {
    .attrs = geo_attrs,
};

static int __init shadow_geo_init(void)
{
    int rc;
    struct kobject *parent;
    
    pr_info("ShadowOS: 🌍 Initializing Geo-Blocking - COUNTRY-LEVEL TRAFFIC CONTROL\n");
    
    rc = nf_register_net_hooks(&init_net, geo_nf_ops, ARRAY_SIZE(geo_nf_ops));
    if (rc) {
        pr_err("ShadowOS: Failed to register geo hooks\n");
        return rc;
    }
    
    parent = shadow_get_kobj();
    if (parent) {
        geo_kobj = kobject_create_and_add("geo", parent);
        if (geo_kobj) {
            if (sysfs_create_group(geo_kobj, &geo_attr_group))
                pr_err("ShadowOS: Failed to create geo sysfs\n");
        }
    }
    
    pr_info("ShadowOS: 🌍 Geo-Blocking ACTIVE - Block entire countries at the kernel level!\n");
    return 0;
}

static void __exit shadow_geo_exit(void)
{
    nf_unregister_net_hooks(&init_net, geo_nf_ops, ARRAY_SIZE(geo_nf_ops));
    
    if (geo_kobj) {
        sysfs_remove_group(geo_kobj, &geo_attr_group);
        kobject_put(geo_kobj);
    }
    
    pr_info("ShadowOS: Geo-Blocking unloaded\n");
}

module_init(shadow_geo_init);
module_exit(shadow_geo_exit);
