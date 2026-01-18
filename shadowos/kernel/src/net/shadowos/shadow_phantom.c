/* SPDX-License-Identifier: GPL-2.0 */
/*
 * ShadowOS Phantom Services Module
 * Responds to closed ports with fake service banners and tarpit connections
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
#include <linux/skbuff.h>
#include <linux/sysfs.h>
#include <linux/kobject.h>
#include <linux/random.h>
#include <net/ip.h>
#include <net/tcp.h>
#include <shadowos/shadow_types.h>

/* Module Info */
MODULE_LICENSE("GPL");
MODULE_AUTHOR("ShadowOS Team");
MODULE_DESCRIPTION("ShadowOS Phantom Services - Tarpit & Fake Banners");
MODULE_VERSION(SHADOWOS_VERSION);

/* Forward declaration */
extern struct kobject *shadow_get_kobj(void);

/* Phantom service definition */
struct phantom_service {
    u16 port;
    const char *banner;
    u16 banner_len;
    u32 delay_ms;
    bool tarpit;
    bool enabled;
    u64 connections;
};

/* Default phantom services */
static struct phantom_service phantoms[] = {
    /* SSH */
    {22, "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3\r\n", 33, 100, false, false, 0},
    /* HTTP */
    {80, "HTTP/1.1 200 OK\r\nServer: Apache/2.4.52\r\n\r\n", 43, 50, false, false, 0},
    /* Telnet (tarpit) */
    {23, "\r\nCisco IOS\r\nUser Access Verification\r\nUsername: ", 48, 500, true, false, 0},
    /* SMB (tarpit - slow responses) */
    {445, NULL, 0, 200, true, false, 0},
    /* RDP (tarpit) */
    {3389, NULL, 0, 300, true, false, 0},
    /* MySQL */
    {3306, "5.7.38-log", 10, 100, false, false, 0},
    /* FTP */
    {21, "220 ProFTPD 1.3.7 Server ready\r\n", 32, 100, false, false, 0},
};

static bool phantom_enabled = false;
static u64 total_tarpits = 0;
static u64 total_synacks = 0;

/* Find phantom service for port */
static struct phantom_service *find_phantom(u16 port)
{
    int i;
    for (i = 0; i < ARRAY_SIZE(phantoms); i++) {
        if (phantoms[i].port == port && phantoms[i].enabled)
            return &phantoms[i];
    }
    return NULL;
}

/* Craft and send SYN-ACK for tarpit */
static int send_tarpit_synack(struct sk_buff *skb, struct iphdr *iph, struct tcphdr *tcph)
{
    struct sk_buff *nskb;
    struct iphdr *niph;
    struct tcphdr *ntcph;
    int total_len = sizeof(struct iphdr) + sizeof(struct tcphdr);
    u32 seq;
    
    nskb = alloc_skb(total_len + LL_MAX_HEADER + 32, GFP_ATOMIC);
    if (!nskb)
        return -ENOMEM;
    
    skb_reserve(nskb, LL_MAX_HEADER + 16);
    skb_reset_network_header(nskb);
    
    /* Build IP header */
    niph = (struct iphdr *)skb_put(nskb, sizeof(struct iphdr));
    niph->version = 4;
    niph->ihl = 5;
    niph->tos = 0;
    niph->tot_len = htons(total_len);
    niph->id = htons(get_random_u32() & 0xFFFF);
    niph->frag_off = 0;
    niph->ttl = 64;
    niph->protocol = IPPROTO_TCP;
    niph->check = 0;
    niph->saddr = iph->daddr;  /* Swap src/dst */
    niph->daddr = iph->saddr;
    niph->check = ip_fast_csum(niph, niph->ihl);
    
    /* Build TCP header */
    skb_set_transport_header(nskb, sizeof(struct iphdr));
    ntcph = (struct tcphdr *)skb_put(nskb, sizeof(struct tcphdr));
    memset(ntcph, 0, sizeof(struct tcphdr));
    
    ntcph->source = tcph->dest;  /* Swap ports */
    ntcph->dest = tcph->source;
    
    get_random_bytes(&seq, sizeof(seq));
    ntcph->seq = htonl(seq);
    ntcph->ack_seq = htonl(ntohl(tcph->seq) + 1);
    ntcph->doff = 5;
    ntcph->syn = 1;
    ntcph->ack = 1;
    ntcph->window = htons(1);  /* Tiny window for tarpit */
    ntcph->check = 0;
    ntcph->urg_ptr = 0;
    
    /* TCP checksum */
    ntcph->check = csum_tcpudp_magic(niph->saddr, niph->daddr,
                                      sizeof(struct tcphdr), IPPROTO_TCP,
                                      csum_partial(ntcph, sizeof(struct tcphdr), 0));
    
    nskb->protocol = htons(ETH_P_IP);
    
    /* Route and send */
    if (ip_route_me_harder(dev_net(skb->dev), skb->sk, nskb, RTN_UNSPEC) == 0) {
        ip_local_out(dev_net(skb->dev), nskb->sk, nskb);
        total_synacks++;
        return 0;
    }
    
    kfree_skb(nskb);
    return -EINVAL;
}

/* Netfilter hook - intercept incoming SYN to phantom ports */
static unsigned int phantom_hook_in(void *priv,
                                    struct sk_buff *skb,
                                    const struct nf_hook_state *state)
{
    struct iphdr *iph;
    struct tcphdr *tcph;
    struct phantom_service *svc;
    u16 dport;
    
    if (!phantom_enabled)
        return NF_ACCEPT;
    
    iph = ip_hdr(skb);
    if (!iph || iph->protocol != IPPROTO_TCP)
        return NF_ACCEPT;
    
    tcph = tcp_hdr(skb);
    if (!tcph)
        return NF_ACCEPT;
    
    /* Only interested in SYN packets */
    if (!tcph->syn || tcph->ack)
        return NF_ACCEPT;
    
    dport = ntohs(tcph->dest);
    svc = find_phantom(dport);
    
    if (svc) {
        svc->connections++;
        
        pr_info("ShadowOS PHANTOM: 👻 Connection to port %u from %pI4 (%s)\n",
                dport, &iph->saddr, svc->tarpit ? "TARPIT" : "phantom");
        
        if (svc->tarpit) {
            /* Send SYN-ACK with tiny window to slow down attacker */
            if (send_tarpit_synack(skb, iph, tcph) == 0) {
                total_tarpits++;
                return NF_DROP;  /* Don't let it proceed normally */
            }
        }
    }
    
    return NF_ACCEPT;
}

static struct nf_hook_ops phantom_nf_ops[] = {
    {
        .hook = phantom_hook_in,
        .pf = NFPROTO_IPV4,
        .hooknum = NF_INET_LOCAL_IN,
        .priority = NF_IP_PRI_FILTER - 1,
    },
};

/* Sysfs */
static struct kobject *phantom_kobj;

static ssize_t phantom_enabled_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
    return sprintf(buf, "%d\n", phantom_enabled);
}

static ssize_t phantom_enabled_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count)
{
    return kstrtobool(buf, &phantom_enabled) ? : count;
}

static ssize_t phantom_ports_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
    int i, len = 0;
    for (i = 0; i < ARRAY_SIZE(phantoms); i++) {
        len += sprintf(buf + len, "[%s] %u: %s (%llu conns)\n",
                       phantoms[i].enabled ? "ON" : "off",
                       phantoms[i].port,
                       phantoms[i].tarpit ? "TARPIT" : "banner",
                       phantoms[i].connections);
    }
    return len;
}

/* Enable port: echo "22 1" > enable_port */
static ssize_t phantom_enable_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count)
{
    u16 port;
    int enable, i;
    
    if (sscanf(buf, "%hu %d", &port, &enable) != 2)
        return -EINVAL;
    
    for (i = 0; i < ARRAY_SIZE(phantoms); i++) {
        if (phantoms[i].port == port) {
            phantoms[i].enabled = enable;
            pr_info("ShadowOS PHANTOM: Port %u %s\n", port, enable ? "ENABLED" : "disabled");
            return count;
        }
    }
    
    return -EINVAL;
}

static ssize_t phantom_stats_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
    return sprintf(buf, "synacks: %llu\ntarpits: %llu\n", total_synacks, total_tarpits);
}

static struct kobj_attribute phantom_attr_enabled = __ATTR(enabled, 0644, phantom_enabled_show, phantom_enabled_store);
static struct kobj_attribute phantom_attr_ports = __ATTR(ports, 0444, phantom_ports_show, NULL);
static struct kobj_attribute phantom_attr_enable = __ATTR(enable_port, 0200, NULL, phantom_enable_store);
static struct kobj_attribute phantom_attr_stats = __ATTR(stats, 0444, phantom_stats_show, NULL);

static struct attribute *phantom_attrs[] = {
    &phantom_attr_enabled.attr,
    &phantom_attr_ports.attr,
    &phantom_attr_enable.attr,
    &phantom_attr_stats.attr,
    NULL,
};

static struct attribute_group phantom_attr_group = {
    .attrs = phantom_attrs,
};

static int __init shadow_phantom_init(void)
{
    int rc;
    struct kobject *parent;
    
    pr_info("ShadowOS: 👻 Initializing Phantom Services\n");
    
    rc = nf_register_net_hooks(&init_net, phantom_nf_ops, ARRAY_SIZE(phantom_nf_ops));
    if (rc) {
        pr_err("ShadowOS: Failed to register phantom hooks\n");
        return rc;
    }
    
    parent = shadow_get_kobj();
    if (parent) {
        phantom_kobj = kobject_create_and_add("phantom", parent);
        if (phantom_kobj) {
            if (sysfs_create_group(phantom_kobj, &phantom_attr_group))
                pr_err("ShadowOS: Failed to create phantom sysfs\n");
        }
    }
    
    pr_info("ShadowOS: 👻 Phantom Services ACTIVE - tarpit & fake banners ready!\n");
    return 0;
}

static void __exit shadow_phantom_exit(void)
{
    nf_unregister_net_hooks(&init_net, phantom_nf_ops, ARRAY_SIZE(phantom_nf_ops));
    
    if (phantom_kobj) {
        sysfs_remove_group(phantom_kobj, &phantom_attr_group);
        kobject_put(phantom_kobj);
    }
    
    pr_info("ShadowOS: Phantom Services unloaded\n");
}

module_init(shadow_phantom_init);
module_exit(shadow_phantom_exit);
