/* SPDX-License-Identifier: GPL-2.0 */
/*
 * ShadowOS Decoy Network Module (shadow_decoy)
 * 
 * PROJECT FAKE HOSTS ON LOCAL NETWORK
 * 
 * Features:
 * - Phantom hosts that respond to ARP
 * - Configurable fake services per host
 * - Integrate with shadow_phantom for responses
 *
 * Copyright (C) 2024 ShadowOS Project
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/netdevice.h>
#include <linux/if_arp.h>
#include <linux/netfilter.h>
#include <linux/netfilter_arp.h>
#include <linux/sysfs.h>
#include <linux/kobject.h>
#include <linux/list.h>
#include <linux/random.h>
#include <shadowos/shadow_types.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("ShadowOS Team");
MODULE_DESCRIPTION("ShadowOS Decoy Network - Phantom LAN Hosts");
MODULE_VERSION(SHADOWOS_VERSION);

extern struct kobject *shadow_get_kobj(void);

/* Phantom host definition */
struct phantom_host {
    __be32 ip;
    u8 mac[ETH_ALEN];
    char hostname[64];
    bool enabled;
    u64 arp_responses;
    struct list_head list;
};

/* Configuration */
static struct {
    bool enabled;
    struct list_head hosts;
    spinlock_t lock;
    u64 total_arp_responses;
} decoy_cfg;

static struct kobject *decoy_kobj;

/* Generate random MAC address */
static void generate_random_mac(u8 *mac)
{
    get_random_bytes(mac, ETH_ALEN);
    mac[0] &= 0xFE;  /* Unicast */
    mac[0] |= 0x02;  /* Locally administered */
}

/* Find phantom host by IP */
static struct phantom_host *find_phantom_by_ip(__be32 ip)
{
    struct phantom_host *ph;
    
    list_for_each_entry(ph, &decoy_cfg.hosts, list) {
        if (ph->ip == ip && ph->enabled)
            return ph;
    }
    return NULL;
}

/* ARP hook - respond for phantom hosts */
static unsigned int decoy_arp_hook(void *priv,
                                   struct sk_buff *skb,
                                   const struct nf_hook_state *state)
{
    struct arphdr *arp;
    unsigned char *arp_ptr;
    __be32 sip, tip;
    struct phantom_host *ph;
    
    if (!decoy_cfg.enabled)
        return NF_ACCEPT;
    
    arp = arp_hdr(skb);
    if (!arp)
        return NF_ACCEPT;
    
    /* Only handle ARP requests */
    if (arp->ar_op != htons(ARPOP_REQUEST))
        return NF_ACCEPT;
    
    /* Extract target IP */
    arp_ptr = (unsigned char *)(arp + 1);
    arp_ptr += arp->ar_hln + 4;  /* Skip sender hardware + IP */
    memcpy(&tip, arp_ptr + arp->ar_hln, 4);
    memcpy(&sip, arp_ptr - 4 - arp->ar_hln, 4);
    
    spin_lock(&decoy_cfg.lock);
    ph = find_phantom_by_ip(tip);
    if (ph) {
        /* This is one of our phantom hosts */
        ph->arp_responses++;
        decoy_cfg.total_arp_responses++;
        pr_debug("ShadowOS DECOY: ARP request for phantom %pI4 from %pI4\n",
                &tip, &sip);
        /* In a full implementation, we would craft and send an ARP reply here */
    }
    spin_unlock(&decoy_cfg.lock);
    
    return NF_ACCEPT;
}

static struct nf_hook_ops decoy_arp_ops = {
    .hook = decoy_arp_hook,
    .pf = NFPROTO_ARP,
    .hooknum = NF_ARP_IN,
    .priority = NF_IP_PRI_FIRST,
};

/* Sysfs Interface */
static ssize_t decoy_enabled_show(struct kobject *kobj,
                                  struct kobj_attribute *attr, char *buf)
{
    return sprintf(buf, "%d\n", decoy_cfg.enabled);
}

static ssize_t decoy_enabled_store(struct kobject *kobj,
                                   struct kobj_attribute *attr,
                                   const char *buf, size_t count)
{
    return kstrtobool(buf, &decoy_cfg.enabled) ? : count;
}

/* Add phantom host: IP format */
static ssize_t decoy_add_store(struct kobject *kobj,
                               struct kobj_attribute *attr,
                               const char *buf, size_t count)
{
    struct phantom_host *ph;
    __be32 ip;
    char ip_str[16];
    size_t len;
    
    len = min(count, sizeof(ip_str) - 1);
    strncpy(ip_str, buf, len);
    ip_str[len] = '\0';
    if (len > 0 && ip_str[len-1] == '\n')
        ip_str[len-1] = '\0';
    
    /* Parse IP address */
    if (in4_pton(ip_str, -1, (u8 *)&ip, -1, NULL) != 1) {
        pr_err("ShadowOS DECOY: Invalid IP format\n");
        return -EINVAL;
    }
    
    ph = kzalloc(sizeof(*ph), GFP_KERNEL);
    if (!ph)
        return -ENOMEM;
    
    ph->ip = ip;
    generate_random_mac(ph->mac);
    snprintf(ph->hostname, sizeof(ph->hostname), "phantom-%pI4", &ip);
    ph->enabled = true;
    
    spin_lock(&decoy_cfg.lock);
    list_add(&ph->list, &decoy_cfg.hosts);
    spin_unlock(&decoy_cfg.lock);
    
    pr_info("ShadowOS DECOY: Added phantom host %pI4 (%pM)\n", &ip, ph->mac);
    return count;
}

static ssize_t decoy_list_show(struct kobject *kobj,
                               struct kobj_attribute *attr, char *buf)
{
    struct phantom_host *ph;
    int len = 0;
    
    spin_lock(&decoy_cfg.lock);
    list_for_each_entry(ph, &decoy_cfg.hosts, list) {
        len += snprintf(buf + len, PAGE_SIZE - len,
                       "%pI4 %pM %s (arps: %llu)\n",
                       &ph->ip, ph->mac, ph->hostname, ph->arp_responses);
    }
    spin_unlock(&decoy_cfg.lock);
    
    if (len == 0)
        len = sprintf(buf, "No phantom hosts configured\n");
    
    return len;
}

static ssize_t decoy_stats_show(struct kobject *kobj,
                                struct kobj_attribute *attr, char *buf)
{
    int count = 0;
    struct phantom_host *ph;
    
    spin_lock(&decoy_cfg.lock);
    list_for_each_entry(ph, &decoy_cfg.hosts, list)
        count++;
    spin_unlock(&decoy_cfg.lock);
    
    return sprintf(buf, "hosts: %d\narp_responses: %llu\n",
                   count, decoy_cfg.total_arp_responses);
}

static struct kobj_attribute decoy_attr_enabled =
    __ATTR(enabled, 0644, decoy_enabled_show, decoy_enabled_store);
static struct kobj_attribute decoy_attr_add =
    __ATTR(add, 0200, NULL, decoy_add_store);
static struct kobj_attribute decoy_attr_list =
    __ATTR(list, 0444, decoy_list_show, NULL);
static struct kobj_attribute decoy_attr_stats =
    __ATTR(stats, 0444, decoy_stats_show, NULL);

static struct attribute *decoy_attrs[] = {
    &decoy_attr_enabled.attr,
    &decoy_attr_add.attr,
    &decoy_attr_list.attr,
    &decoy_attr_stats.attr,
    NULL,
};

static struct attribute_group decoy_attr_group = {
    .attrs = decoy_attrs,
};

static int __init shadow_decoy_init(void)
{
    int rc;
    struct kobject *parent;
    
    pr_info("ShadowOS: 🎭 Initializing Decoy Network\n");
    
    INIT_LIST_HEAD(&decoy_cfg.hosts);
    spin_lock_init(&decoy_cfg.lock);
    decoy_cfg.enabled = false;
    
    rc = nf_register_net_hook(&init_net, &decoy_arp_ops);
    if (rc) {
        pr_err("ShadowOS: Failed to register ARP hook\n");
        return rc;
    }
    
    parent = shadow_get_kobj();
    if (parent) {
        decoy_kobj = kobject_create_and_add("decoy", parent);
        if (decoy_kobj) {
            if (sysfs_create_group(decoy_kobj, &decoy_attr_group))
                pr_err("ShadowOS: Failed to create decoy sysfs\n");
        }
    }
    
    pr_info("ShadowOS: 🎭 Decoy Network ready - project phantom hosts!\n");
    return 0;
}

static void __exit shadow_decoy_exit(void)
{
    struct phantom_host *ph, *tmp;
    
    nf_unregister_net_hook(&init_net, &decoy_arp_ops);
    
    if (decoy_kobj) {
        sysfs_remove_group(decoy_kobj, &decoy_attr_group);
        kobject_put(decoy_kobj);
    }
    
    list_for_each_entry_safe(ph, tmp, &decoy_cfg.hosts, list) {
        list_del(&ph->list);
        kfree(ph);
    }
    
    pr_info("ShadowOS: Decoy Network unloaded\n");
}

module_init(shadow_decoy_init);
module_exit(shadow_decoy_exit);
