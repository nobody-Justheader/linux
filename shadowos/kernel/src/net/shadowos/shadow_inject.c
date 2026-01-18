/* SPDX-License-Identifier: GPL-2.0 */
/*
 * ShadowOS Raw Packet Injection Module (shadow_inject)
 * 
 * KERNEL-LEVEL PACKET CRAFTING AND INJECTION
 * 
 * Features:
 * - Inject raw packets directly into network stack
 * - Bypass userspace restrictions
 * - Support for custom headers
 *
 * Copyright (C) 2026 ShadowOS Project
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/sysfs.h>
#include <linux/kobject.h>
#include <net/ip.h>
#include <net/checksum.h>
#include <shadowos/shadow_types.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("ShadowOS Team");
MODULE_DESCRIPTION("ShadowOS Packet Injection - Raw Packet Crafting");
MODULE_VERSION(SHADOWOS_VERSION);

extern struct kobject *shadow_get_kobj(void);

/* Configuration */
static struct {
    bool enabled;
    u64 packets_injected;
    u64 bytes_injected;
} inject_cfg = {
    .enabled = false,
    .packets_injected = 0,
    .bytes_injected = 0,
};

static struct kobject *inject_kobj;

/* Inject raw packet */
int shadow_inject_packet(struct net_device *dev, void *data, 
                         size_t len, int protocol)
{
    struct sk_buff *skb;
    int rc;
    
    if (!inject_cfg.enabled) {
        pr_debug("ShadowOS INJECT: Injection disabled\n");
        return -EPERM;
    }
    
    if (!dev || !data || len == 0) {
        return -EINVAL;
    }
    
    /* Allocate SKB */
    skb = alloc_skb(len + NET_IP_ALIGN + LL_MAX_HEADER, GFP_KERNEL);
    if (!skb)
        return -ENOMEM;
    
    skb_reserve(skb, NET_IP_ALIGN + LL_MAX_HEADER);
    skb_put_data(skb, data, len);
    
    skb->dev = dev;
    skb->protocol = htons(protocol);
    skb->pkt_type = PACKET_OUTGOING;
    
    /* Set network header */
    skb_reset_network_header(skb);
    
    rc = dev_queue_xmit(skb);
    if (rc == NET_XMIT_SUCCESS) {
        inject_cfg.packets_injected++;
        inject_cfg.bytes_injected += len;
        pr_debug("ShadowOS INJECT: Sent %zu bytes on %s\n", len, dev->name);
    }
    
    return rc;
}
EXPORT_SYMBOL(shadow_inject_packet);

/* Build and inject TCP RST packet */
int shadow_inject_tcp_rst(__be32 saddr, __be32 daddr,
                          __be16 sport, __be16 dport, __be32 seq)
{
    struct net_device *dev;
    struct sk_buff *skb;
    struct iphdr *iph;
    struct tcphdr *tcph;
    int total_len;
    
    if (!inject_cfg.enabled)
        return -EPERM;
    
    /* Find output device */
    dev = ip_dev_find(&init_net, saddr);
    if (!dev) {
        /* Use default route */
        dev = dev_get_by_name(&init_net, "eth0");
        if (!dev)
            return -ENODEV;
    }
    
    total_len = sizeof(struct iphdr) + sizeof(struct tcphdr);
    
    skb = alloc_skb(total_len + LL_MAX_HEADER, GFP_KERNEL);
    if (!skb) {
        dev_put(dev);
        return -ENOMEM;
    }
    
    skb_reserve(skb, LL_MAX_HEADER);
    skb_reset_network_header(skb);
    
    /* Build IP header */
    iph = skb_put(skb, sizeof(struct iphdr));
    iph->version = 4;
    iph->ihl = 5;
    iph->tos = 0;
    iph->tot_len = htons(total_len);
    iph->id = htons(prandom_u32() & 0xFFFF);
    iph->frag_off = 0;
    iph->ttl = 64;
    iph->protocol = IPPROTO_TCP;
    iph->check = 0;
    iph->saddr = saddr;
    iph->daddr = daddr;
    iph->check = ip_fast_csum(iph, iph->ihl);
    
    /* Build TCP header */
    skb_set_transport_header(skb, sizeof(struct iphdr));
    tcph = skb_put(skb, sizeof(struct tcphdr));
    memset(tcph, 0, sizeof(struct tcphdr));
    tcph->source = sport;
    tcph->dest = dport;
    tcph->seq = seq;
    tcph->ack_seq = 0;
    tcph->doff = 5;
    tcph->rst = 1;
    tcph->window = 0;
    tcph->check = 0;
    tcph->urg_ptr = 0;
    
    /* TCP checksum */
    tcph->check = csum_tcpudp_magic(saddr, daddr, sizeof(struct tcphdr),
                                    IPPROTO_TCP, 
                                    csum_partial(tcph, sizeof(struct tcphdr), 0));
    
    skb->dev = dev;
    skb->protocol = htons(ETH_P_IP);
    skb->pkt_type = PACKET_OUTGOING;
    
    dev_queue_xmit(skb);
    dev_put(dev);
    
    inject_cfg.packets_injected++;
    pr_debug("ShadowOS INJECT: RST sent to %pI4:%u\n", &daddr, ntohs(dport));
    
    return 0;
}
EXPORT_SYMBOL(shadow_inject_tcp_rst);

/* Sysfs Interface */
static ssize_t inject_enabled_show(struct kobject *kobj,
                                   struct kobj_attribute *attr, char *buf)
{
    return sprintf(buf, "%d\n", inject_cfg.enabled);
}

static ssize_t inject_enabled_store(struct kobject *kobj,
                                    struct kobj_attribute *attr,
                                    const char *buf, size_t count)
{
    return kstrtobool(buf, &inject_cfg.enabled) ? : count;
}

static ssize_t inject_stats_show(struct kobject *kobj,
                                 struct kobj_attribute *attr, char *buf)
{
    return sprintf(buf, "packets: %llu\nbytes: %llu\n",
                   inject_cfg.packets_injected, inject_cfg.bytes_injected);
}

static struct kobj_attribute inject_attr_enabled =
    __ATTR(enabled, 0644, inject_enabled_show, inject_enabled_store);
static struct kobj_attribute inject_attr_stats =
    __ATTR(stats, 0444, inject_stats_show, NULL);

static struct attribute *inject_attrs[] = {
    &inject_attr_enabled.attr,
    &inject_attr_stats.attr,
    NULL,
};

static struct attribute_group inject_attr_group = {
    .attrs = inject_attrs,
};

static int __init shadow_inject_init(void)
{
    struct kobject *parent;
    
    pr_info("ShadowOS: 💉 Initializing Packet Injection Module\n");
    
    parent = shadow_get_kobj();
    if (parent) {
        inject_kobj = kobject_create_and_add("inject", parent);
        if (inject_kobj) {
            if (sysfs_create_group(inject_kobj, &inject_attr_group))
                pr_err("ShadowOS: Failed to create inject sysfs\n");
        }
    }
    
    pr_info("ShadowOS: 💉 Packet Injection ready (disabled by default)\n");
    return 0;
}

static void __exit shadow_inject_exit(void)
{
    if (inject_kobj) {
        sysfs_remove_group(inject_kobj, &inject_attr_group);
        kobject_put(inject_kobj);
    }
    
    pr_info("ShadowOS: Packet Injection unloaded\n");
}

module_init(shadow_inject_init);
module_exit(shadow_inject_exit);
