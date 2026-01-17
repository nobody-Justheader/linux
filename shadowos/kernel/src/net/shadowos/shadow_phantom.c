/* SPDX-License-Identifier: GPL-2.0 */
/*
 * ShadowOS Phantom Services Module
 * Responds to closed ports with fake service banners
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
#include <linux/sysfs.h>
#include <linux/kobject.h>
#include <shadowos/shadow_types.h>

/* Module Info */
MODULE_LICENSE("GPL");
MODULE_AUTHOR("ShadowOS Team");
MODULE_DESCRIPTION("ShadowOS Phantom Services");
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
};

/* Default phantom services */
static struct phantom_service phantoms[] = {
    /* SSH */
    {22, "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3\r\n", 33, 100, false, false},
    /* HTTP */
    {80, "HTTP/1.1 200 OK\r\nServer: Apache/2.4.52\r\n\r\n", 43, 50, false, false},
    /* Telnet (tarpit) */
    {23, "\r\nCisco IOS\r\nUser Access Verification\r\nUsername: ", 48, 500, true, false},
    /* SMB (tarpit - never responds) */
    {445, NULL, 0, 200, true, false},
    /* RDP (tarpit) */
    {3389, NULL, 0, 300, true, false},
    /* MySQL */
    {3306, "5.7.38-log", 10, 100, false, false},
    /* FTP */
    {21, "220 ProFTPD 1.3.7 Server ready\r\n", 32, 100, false, false},
};

static bool phantom_enabled = false;

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
        /* Log phantom activation */
        pr_debug("ShadowOS: Phantom triggered on port %u from %pI4\n",
                 dport, &iph->saddr);
        
        if (svc->tarpit) {
            /* Tarpit: would send SYN-ACK but never complete */
            /* For now, just accept and let connection timeout */
            return NF_ACCEPT;
        }
        /* Non-tarpit phantom services need userspace helper */
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
        if (phantoms[i].enabled)
            len += sprintf(buf + len, "%u ", phantoms[i].port);
    }
    if (len > 0)
        buf[len - 1] = '\n';
    return len;
}

static struct kobj_attribute phantom_attr_enabled = __ATTR(enabled, 0644, phantom_enabled_show, phantom_enabled_store);
static struct kobj_attribute phantom_attr_ports = __ATTR(ports, 0444, phantom_ports_show, NULL);

static struct attribute *phantom_attrs[] = {
    &phantom_attr_enabled.attr,
    &phantom_attr_ports.attr,
    NULL,
};

static struct attribute_group phantom_attr_group = {
    .attrs = phantom_attrs,
};

static int __init shadow_phantom_init(void)
{
    int rc;
    struct kobject *parent;
    
    pr_info("ShadowOS: Initializing Phantom Services\n");
    
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
    
    pr_info("ShadowOS: Phantom Services initialized\n");
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
