/* SPDX-License-Identifier: GPL-2.0 */
/*
 * ShadowOS Protocol Chaos Module
 * Confuses fingerprinting tools by randomizing network parameters
 *
 * Copyright (C) 2024 ShadowOS Project
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/random.h>
#include <linux/sysfs.h>
#include <linux/kobject.h>
#include <net/tcp.h>
#include <shadowos/shadow_types.h>

/* Module Info */
MODULE_LICENSE("GPL");
MODULE_AUTHOR("ShadowOS Team");
MODULE_DESCRIPTION("ShadowOS Protocol Chaos");
MODULE_VERSION(SHADOWOS_VERSION);

/* Forward declaration */
extern struct kobject *shadow_get_kobj(void);

/* Configuration */
static struct {
    bool enabled;
    bool ttl_chaos;
    bool window_chaos;
    bool timestamp_chaos;
    bool options_chaos;
    u32 jitter_min_ms;
    u32 jitter_max_ms;
} chaos_cfg = {
    .enabled = false,
    .ttl_chaos = true,
    .window_chaos = true,
    .timestamp_chaos = false,
    .options_chaos = false,
    .jitter_min_ms = 0,
    .jitter_max_ms = 50,
};

/* TTL values to mimic various OS */
static const u8 ttl_values[] = {32, 64, 128, 255};

/* Window sizes from various OS */
static const u16 window_values[] = {
    5840,   /* Linux default */
    8192,   /* BSD */
    16384,  /* Older Windows */
    65535,  /* Windows 10 */
    29200,  /* Linux modern */
};

static u8 chaos_get_ttl(void)
{
    return ttl_values[get_random_u32() % ARRAY_SIZE(ttl_values)];
}

static u16 chaos_get_window(void)
{
    return window_values[get_random_u32() % ARRAY_SIZE(window_values)];
}

/* Netfilter hook for outgoing packets */
static unsigned int chaos_hook_out(void *priv,
                                   struct sk_buff *skb,
                                   const struct nf_hook_state *state)
{
    struct iphdr *iph;
    struct tcphdr *tcph;
    
    if (!chaos_cfg.enabled)
        return NF_ACCEPT;
    
    iph = ip_hdr(skb);
    if (!iph || iph->protocol != IPPROTO_TCP)
        return NF_ACCEPT;
    
    tcph = tcp_hdr(skb);
    if (!tcph)
        return NF_ACCEPT;
    
    /* Make packet writable */
    if (skb_ensure_writable(skb, skb->len))
        return NF_ACCEPT;
    
    /* Refresh pointers after possible reallocation */
    iph = ip_hdr(skb);
    tcph = tcp_hdr(skb);
    
    if (chaos_cfg.ttl_chaos) {
        iph->ttl = chaos_get_ttl();
    }
    
    if (chaos_cfg.window_chaos) {
        tcph->window = htons(chaos_get_window());
    }
    
    /* Recalculate checksums */
    iph->check = 0;
    iph->check = ip_fast_csum((unsigned char *)iph, iph->ihl);
    
    /* TCP checksum needs recalculation too */
    tcph->check = 0;
    skb->csum = 0;
    
    return NF_ACCEPT;
}

static struct nf_hook_ops chaos_nf_ops[] = {
    {
        .hook = chaos_hook_out,
        .pf = NFPROTO_IPV4,
        .hooknum = NF_INET_LOCAL_OUT,
        .priority = NF_IP_PRI_MANGLE,
    },
};

/* Sysfs */
static struct kobject *chaos_kobj;

#define CHAOS_ATTR_RW(_name, _field) \
static ssize_t _name##_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf) \
{ return sprintf(buf, "%d\n", chaos_cfg._field); } \
static ssize_t _name##_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count) \
{ return kstrtobool(buf, &chaos_cfg._field) ? : count; } \
static struct kobj_attribute chaos_attr_##_name = __ATTR(_name, 0644, _name##_show, _name##_store)

CHAOS_ATTR_RW(enabled, enabled);
CHAOS_ATTR_RW(ttl, ttl_chaos);
CHAOS_ATTR_RW(window, window_chaos);
CHAOS_ATTR_RW(timestamps, timestamp_chaos);

static struct attribute *chaos_attrs[] = {
    &chaos_attr_enabled.attr,
    &chaos_attr_ttl.attr,
    &chaos_attr_window.attr,
    &chaos_attr_timestamps.attr,
    NULL,
};

static struct attribute_group chaos_attr_group = {
    .attrs = chaos_attrs,
};

static int __init shadow_chaos_init(void)
{
    int rc;
    struct kobject *parent;
    
    pr_info("ShadowOS: Initializing Protocol Chaos\n");
    
    rc = nf_register_net_hooks(&init_net, chaos_nf_ops, ARRAY_SIZE(chaos_nf_ops));
    if (rc) {
        pr_err("ShadowOS: Failed to register chaos hooks\n");
        return rc;
    }
    
    parent = shadow_get_kobj();
    if (parent) {
        chaos_kobj = kobject_create_and_add("chaos", parent);
        if (chaos_kobj) {
            if (sysfs_create_group(chaos_kobj, &chaos_attr_group))
                pr_err("ShadowOS: Failed to create chaos sysfs\n");
        }
    }
    
    pr_info("ShadowOS: Protocol Chaos initialized\n");
    return 0;
}

static void __exit shadow_chaos_exit(void)
{
    nf_unregister_net_hooks(&init_net, chaos_nf_ops, ARRAY_SIZE(chaos_nf_ops));
    
    if (chaos_kobj) {
        sysfs_remove_group(chaos_kobj, &chaos_attr_group);
        kobject_put(chaos_kobj);
    }
    
    pr_info("ShadowOS: Protocol Chaos unloaded\n");
}

module_init(shadow_chaos_init);
module_exit(shadow_chaos_exit);
