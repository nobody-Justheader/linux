/* SPDX-License-Identifier: GPL-2.0 */
/*
 * ShadowOS Identity Flux Module
 * Per-connection OS identity spoofing
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
#include <linux/random.h>
#include <linux/sysfs.h>
#include <linux/kobject.h>
#include <uapi/linux/ip.h>
#include <shadowos/shadow_types.h>

/* Module Info */
MODULE_LICENSE("GPL");
MODULE_AUTHOR("ShadowOS Team");
MODULE_DESCRIPTION("ShadowOS Identity Flux");
MODULE_VERSION(SHADOWOS_VERSION);

/* Forward declaration */
extern struct kobject *shadow_get_kobj(void);

/* Flux modes */
enum flux_mode {
    FLUX_MODE_OFF = 0,
    FLUX_MODE_RANDOM,
    FLUX_MODE_STICKY,
    FLUX_MODE_PROFILE,
};

/* OS Profiles */
static struct shadow_os_profile profiles[] = {
    {"windows_10",     128, 65535, 1460, 1, 1, 1, 8},
    {"windows_server", 128, 65535, 1460, 1, 1, 1, 8},
    {"linux_5",        64,  29200, 1460, 1, 1, 1, 7},
    {"linux_4",        64,  29200, 1460, 1, 1, 1, 7},
    {"macos_13",       64,  65535, 1460, 1, 1, 1, 6},
    {"freebsd_13",     64,  65535, 1460, 1, 1, 1, 6},
    {"cisco_ios",      255, 4128,  536,  0, 0, 0, 0},
    {"printer",        64,  8192,  1460, 0, 0, 0, 0},
    {"iot_device",     64,  5840,  1460, 0, 0, 0, 0},
};

/* Configuration */
static struct {
    enum flux_mode mode;
    int profile_index;
} flux_cfg = {
    .mode = FLUX_MODE_OFF,
    .profile_index = 0,
};

/* Connection tracking */
struct flux_connection {
    __be32 src_ip;
    __be32 dst_ip;
    __be16 src_port;
    __be16 dst_port;
    int profile_idx;
    struct hlist_node node;
};

static DEFINE_HASHTABLE(flux_conn_ht, 10);
static DEFINE_SPINLOCK(flux_lock);

static u32 flux_hash(__be32 src, __be32 dst, __be16 sport, __be16 dport)
{
    return src ^ dst ^ sport ^ dport;
}

static struct flux_connection *flux_find_conn(__be32 src, __be32 dst, __be16 sport, __be16 dport)
{
    struct flux_connection *c;
    u32 hash = flux_hash(src, dst, sport, dport);
    
    hash_for_each_possible(flux_conn_ht, c, node, hash) {
        if (c->src_ip == src && c->dst_ip == dst &&
            c->src_port == sport && c->dst_port == dport)
            return c;
    }
    return NULL;
}

static int flux_get_profile(struct sk_buff *skb)
{
    struct iphdr *iph = ip_hdr(skb);
    struct tcphdr *tcph = tcp_hdr(skb);
    struct flux_connection *conn;
    unsigned long flags;
    int idx;
    
    spin_lock_irqsave(&flux_lock, flags);
    
    conn = flux_find_conn(iph->saddr, iph->daddr, tcph->source, tcph->dest);
    
    if (!conn) {
        conn = kzalloc(sizeof(*conn), GFP_ATOMIC);
        if (conn) {
            conn->src_ip = iph->saddr;
            conn->dst_ip = iph->daddr;
            conn->src_port = tcph->source;
            conn->dst_port = tcph->dest;
            
            switch (flux_cfg.mode) {
            case FLUX_MODE_RANDOM:
                conn->profile_idx = get_random_u32() % ARRAY_SIZE(profiles);
                break;
            case FLUX_MODE_PROFILE:
                conn->profile_idx = flux_cfg.profile_index;
                break;
            default:
                conn->profile_idx = 0;
            }
            
            hash_add(flux_conn_ht, &conn->node, 
                     flux_hash(conn->src_ip, conn->dst_ip, conn->src_port, conn->dst_port));
        }
    }
    
    idx = conn ? conn->profile_idx : 0;
    spin_unlock_irqrestore(&flux_lock, flags);
    
    return idx;
}

/* Apply OS profile to outgoing packet */
static unsigned int flux_hook_out(void *priv,
                                  struct sk_buff *skb,
                                  const struct nf_hook_state *state)
{
    struct iphdr *iph;
    struct tcphdr *tcph;
    struct shadow_os_profile *prof;
    int idx;
    
    if (flux_cfg.mode == FLUX_MODE_OFF)
        return NF_ACCEPT;
    
    iph = ip_hdr(skb);
    if (!iph || iph->protocol != IPPROTO_TCP)
        return NF_ACCEPT;
    
    tcph = tcp_hdr(skb);
    if (!tcph)
        return NF_ACCEPT;
    
    idx = flux_get_profile(skb);
    prof = &profiles[idx];
    
    if (skb_ensure_writable(skb, skb->len))
        return NF_ACCEPT;
    
    iph = ip_hdr(skb);
    tcph = tcp_hdr(skb);
    
    /* Apply profile */
    iph->ttl = prof->ttl;
    tcph->window = htons(prof->window);
    
    if (prof->df_bit)
        iph->frag_off |= htons(0x4000); /* IP_DF */
    else
        iph->frag_off &= ~htons(0x4000);
    
    /* Recalculate checksums */
    iph->check = 0;
    iph->check = ip_fast_csum((unsigned char *)iph, iph->ihl);
    
    return NF_ACCEPT;
}

static struct nf_hook_ops flux_nf_ops[] = {
    {
        .hook = flux_hook_out,
        .pf = NFPROTO_IPV4,
        .hooknum = NF_INET_LOCAL_OUT,
        .priority = NF_IP_PRI_MANGLE + 1,
    },
};

/* Sysfs */
static struct kobject *flux_kobj;

static ssize_t flux_mode_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
    const char *modes[] = {"off", "random", "sticky", "profile"};
    return sprintf(buf, "%s\n", modes[flux_cfg.mode]);
}

static ssize_t flux_mode_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count)
{
    if (sysfs_streq(buf, "off"))
        flux_cfg.mode = FLUX_MODE_OFF;
    else if (sysfs_streq(buf, "random"))
        flux_cfg.mode = FLUX_MODE_RANDOM;
    else if (sysfs_streq(buf, "sticky"))
        flux_cfg.mode = FLUX_MODE_STICKY;
    else if (sysfs_streq(buf, "profile"))
        flux_cfg.mode = FLUX_MODE_PROFILE;
    else
        return -EINVAL;
    return count;
}

static ssize_t flux_profile_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
    return sprintf(buf, "%s\n", profiles[flux_cfg.profile_index].name);
}

static ssize_t flux_profiles_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
    int i, len = 0;
    for (i = 0; i < ARRAY_SIZE(profiles); i++) {
        len += sprintf(buf + len, "%s ", profiles[i].name);
    }
    if (len > 0)
        buf[len - 1] = '\n';
    return len;
}

static struct kobj_attribute flux_attr_mode = __ATTR(mode, 0644, flux_mode_show, flux_mode_store);
static struct kobj_attribute flux_attr_profile = __ATTR(profile, 0444, flux_profile_show, NULL);
static struct kobj_attribute flux_attr_profiles = __ATTR(profiles, 0444, flux_profiles_show, NULL);

static struct attribute *flux_attrs[] = {
    &flux_attr_mode.attr,
    &flux_attr_profile.attr,
    &flux_attr_profiles.attr,
    NULL,
};

static struct attribute_group flux_attr_group = {
    .attrs = flux_attrs,
};

static int __init shadow_flux_init(void)
{
    int rc;
    struct kobject *parent;
    
    pr_info("ShadowOS: Initializing Identity Flux\n");
    
    rc = nf_register_net_hooks(&init_net, flux_nf_ops, ARRAY_SIZE(flux_nf_ops));
    if (rc) {
        pr_err("ShadowOS: Failed to register flux hooks\n");
        return rc;
    }
    
    parent = shadow_get_kobj();
    if (parent) {
        flux_kobj = kobject_create_and_add("flux", parent);
        if (flux_kobj) {
            if (sysfs_create_group(flux_kobj, &flux_attr_group))
                pr_err("ShadowOS: Failed to create flux sysfs\n");
        }
    }
    
    pr_info("ShadowOS: Identity Flux initialized\n");
    return 0;
}

static void __exit shadow_flux_exit(void)
{
    struct flux_connection *conn;
    struct hlist_node *tmp;
    int i;
    
    nf_unregister_net_hooks(&init_net, flux_nf_ops, ARRAY_SIZE(flux_nf_ops));
    
    if (flux_kobj) {
        sysfs_remove_group(flux_kobj, &flux_attr_group);
        kobject_put(flux_kobj);
    }
    
    /* Cleanup connection table */
    hash_for_each_safe(flux_conn_ht, i, tmp, conn, node) {
        hash_del(&conn->node);
        kfree(conn);
    }
    
    pr_info("ShadowOS: Identity Flux unloaded\n");
}

module_init(shadow_flux_init);
module_exit(shadow_flux_exit);
