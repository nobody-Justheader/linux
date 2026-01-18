/* SPDX-License-Identifier: GPL-2.0 */
/*
 * ShadowOS Moving Target Defense (shadow_mtd)
 * 
 * SERVICES THAT MOVE BETWEEN PORTS
 * 
 * Features:
 * - Dynamic port remapping
 * - NAT-based service hopping
 * - Configurable move intervals
 *
 * Copyright (C) 2026 ShadowOS Project
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/timer.h>
#include <linux/random.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/sysfs.h>
#include <linux/kobject.h>
#include <linux/list.h>
#include <shadowos/shadow_types.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("ShadowOS Team");
MODULE_DESCRIPTION("ShadowOS Moving Target Defense - Dynamic Port Hopping");
MODULE_VERSION(SHADOWOS_VERSION);

extern struct kobject *shadow_get_kobj(void);

/* MTD service definition */
struct mtd_service {
    u16 real_port;          /* Actual service port */
    u16 current_port;       /* Currently exposed port */
    u16 port_range_start;
    u16 port_range_end;
    u32 move_interval_sec;
    u64 last_move;
    u64 connections;
    bool enabled;
    struct list_head list;
};

/* Configuration */
static struct {
    bool enabled;
    struct list_head services;
    spinlock_t lock;
    struct timer_list move_timer;
    u64 total_moves;
} mtd_cfg;

static struct kobject *mtd_kobj;

/* Generate new random port */
static u16 get_random_port(struct mtd_service *svc)
{
    u32 range = svc->port_range_end - svc->port_range_start;
    return svc->port_range_start + (get_random_u32() % range);
}

/* Move service to new port */
static void mtd_move_service(struct mtd_service *svc)
{
    u16 old_port = svc->current_port;
    u16 new_port;
    
    do {
        new_port = get_random_port(svc);
    } while (new_port == old_port);
    
    svc->current_port = new_port;
    svc->last_move = ktime_get_real_seconds();
    mtd_cfg.total_moves++;
    
    pr_info("ShadowOS MTD: Service %u moved: %u -> %u\n",
            svc->real_port, old_port, new_port);
}

/* Timer callback - check for moves */
static void mtd_timer_callback(struct timer_list *t)
{
    struct mtd_service *svc;
    u64 now = ktime_get_real_seconds();
    
    if (!mtd_cfg.enabled)
        goto reschedule;
    
    spin_lock(&mtd_cfg.lock);
    list_for_each_entry(svc, &mtd_cfg.services, list) {
        if (!svc->enabled)
            continue;
        
        if (now - svc->last_move >= svc->move_interval_sec) {
            mtd_move_service(svc);
        }
    }
    spin_unlock(&mtd_cfg.lock);
    
reschedule:
    mod_timer(&mtd_cfg.move_timer, jiffies + HZ * 10);  /* Check every 10s */
}

/* Netfilter hook for port translation */
static unsigned int mtd_hook(void *priv,
                            struct sk_buff *skb,
                            const struct nf_hook_state *state)
{
    struct iphdr *iph;
    struct tcphdr *tcph;
    struct mtd_service *svc;
    
    if (!mtd_cfg.enabled)
        return NF_ACCEPT;
    
    iph = ip_hdr(skb);
    if (!iph || iph->protocol != IPPROTO_TCP)
        return NF_ACCEPT;
    
    tcph = tcp_hdr(skb);
    if (!tcph)
        return NF_ACCEPT;
    
    spin_lock(&mtd_cfg.lock);
    list_for_each_entry(svc, &mtd_cfg.services, list) {
        if (!svc->enabled)
            continue;
        
        /* Incoming: translate exposed port to real port */
        if (ntohs(tcph->dest) == svc->current_port) {
            tcph->dest = htons(svc->real_port);
            svc->connections++;
            pr_debug("ShadowOS MTD: Translated %u -> %u\n",
                    svc->current_port, svc->real_port);
            break;
        }
    }
    spin_unlock(&mtd_cfg.lock);
    
    return NF_ACCEPT;
}

static struct nf_hook_ops mtd_nf_ops = {
    .hook = mtd_hook,
    .pf = NFPROTO_IPV4,
    .hooknum = NF_INET_PRE_ROUTING,
    .priority = NF_IP_PRI_NAT_DST - 1,
};

/* Sysfs Interface */
static ssize_t mtd_enabled_show(struct kobject *kobj,
                                struct kobj_attribute *attr, char *buf)
{
    return sprintf(buf, "%d\n", mtd_cfg.enabled);
}

static ssize_t mtd_enabled_store(struct kobject *kobj,
                                 struct kobj_attribute *attr,
                                 const char *buf, size_t count)
{
    return kstrtobool(buf, &mtd_cfg.enabled) ? : count;
}

/* Add service: real_port:range_start-range_end:interval */
static ssize_t mtd_add_store(struct kobject *kobj,
                             struct kobj_attribute *attr,
                             const char *buf, size_t count)
{
    struct mtd_service *svc;
    u16 real_port, range_start, range_end;
    u32 interval;
    
    if (sscanf(buf, "%hu:%hu-%hu:%u", &real_port, &range_start, 
               &range_end, &interval) != 4) {
        pr_err("ShadowOS MTD: Format: real_port:range_start-range_end:interval\n");
        return -EINVAL;
    }
    
    svc = kzalloc(sizeof(*svc), GFP_KERNEL);
    if (!svc)
        return -ENOMEM;
    
    svc->real_port = real_port;
    svc->port_range_start = range_start;
    svc->port_range_end = range_end;
    svc->move_interval_sec = interval;
    svc->current_port = get_random_port(svc);
    svc->last_move = ktime_get_real_seconds();
    svc->enabled = true;
    
    spin_lock(&mtd_cfg.lock);
    list_add(&svc->list, &mtd_cfg.services);
    spin_unlock(&mtd_cfg.lock);
    
    pr_info("ShadowOS MTD: Added service %u -> %u (range %u-%u, interval %us)\n",
            real_port, svc->current_port, range_start, range_end, interval);
    
    return count;
}

static ssize_t mtd_list_show(struct kobject *kobj,
                             struct kobj_attribute *attr, char *buf)
{
    struct mtd_service *svc;
    int len = 0;
    
    spin_lock(&mtd_cfg.lock);
    list_for_each_entry(svc, &mtd_cfg.services, list) {
        len += snprintf(buf + len, PAGE_SIZE - len,
                       "port %u -> %u (range %u-%u, conns: %llu)\n",
                       svc->real_port, svc->current_port,
                       svc->port_range_start, svc->port_range_end,
                       svc->connections);
    }
    spin_unlock(&mtd_cfg.lock);
    
    if (len == 0)
        len = sprintf(buf, "No MTD services configured\n");
    
    return len;
}

static ssize_t mtd_stats_show(struct kobject *kobj,
                              struct kobj_attribute *attr, char *buf)
{
    return sprintf(buf, "total_moves: %llu\n", mtd_cfg.total_moves);
}

static struct kobj_attribute mtd_attr_enabled =
    __ATTR(enabled, 0644, mtd_enabled_show, mtd_enabled_store);
static struct kobj_attribute mtd_attr_add =
    __ATTR(add, 0200, NULL, mtd_add_store);
static struct kobj_attribute mtd_attr_list =
    __ATTR(list, 0444, mtd_list_show, NULL);
static struct kobj_attribute mtd_attr_stats =
    __ATTR(stats, 0444, mtd_stats_show, NULL);

static struct attribute *mtd_attrs[] = {
    &mtd_attr_enabled.attr,
    &mtd_attr_add.attr,
    &mtd_attr_list.attr,
    &mtd_attr_stats.attr,
    NULL,
};

static struct attribute_group mtd_attr_group = {
    .attrs = mtd_attrs,
};

static int __init shadow_mtd_init(void)
{
    int rc;
    struct kobject *parent;
    
    pr_info("ShadowOS: 🎯 Initializing Moving Target Defense\n");
    
    INIT_LIST_HEAD(&mtd_cfg.services);
    spin_lock_init(&mtd_cfg.lock);
    mtd_cfg.enabled = false;
    
    timer_setup(&mtd_cfg.move_timer, mtd_timer_callback, 0);
    mod_timer(&mtd_cfg.move_timer, jiffies + HZ * 10);
    
    rc = nf_register_net_hook(&init_net, &mtd_nf_ops);
    if (rc) {
        pr_err("ShadowOS: Failed to register MTD hook\n");
        del_timer(&mtd_cfg.move_timer);
        return rc;
    }
    
    parent = shadow_get_kobj();
    if (parent) {
        mtd_kobj = kobject_create_and_add("mtd", parent);
        if (mtd_kobj) {
            if (sysfs_create_group(mtd_kobj, &mtd_attr_group))
                pr_err("ShadowOS: Failed to create mtd sysfs\n");
        }
    }
    
    pr_info("ShadowOS: 🎯 MTD ready - services will hop between ports!\n");
    return 0;
}

static void __exit shadow_mtd_exit(void)
{
    struct mtd_service *svc, *tmp;
    
    del_timer_sync(&mtd_cfg.move_timer);
    nf_unregister_net_hook(&init_net, &mtd_nf_ops);
    
    if (mtd_kobj) {
        sysfs_remove_group(mtd_kobj, &mtd_attr_group);
        kobject_put(mtd_kobj);
    }
    
    list_for_each_entry_safe(svc, tmp, &mtd_cfg.services, list) {
        list_del(&svc->list);
        kfree(svc);
    }
    
    pr_info("ShadowOS: MTD unloaded\n");
}

module_init(shadow_mtd_init);
module_exit(shadow_mtd_exit);
