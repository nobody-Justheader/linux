/* SPDX-License-Identifier: GPL-2.0 */
/*
 * ShadowOS Promiscuous Mode Hiding (shadow_promisc)
 * 
 * HIDE NETWORK SNIFFING FROM DETECTION
 * 
 * Features:
 * - Hide IFF_PROMISC flag from queries
 * - Hook netlink for GETLINK responses  
 * - Stealth network monitoring
 *
 * Copyright (C) 2026 ShadowOS Project
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/netdevice.h>
#include <linux/rtnetlink.h>
#include <linux/sysfs.h>
#include <linux/kobject.h>
#include <linux/list.h>
#include <net/sock.h>
#include <shadowos/shadow_types.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("ShadowOS Team");
MODULE_DESCRIPTION("ShadowOS Promiscuous Mode Hiding");
MODULE_VERSION(SHADOWOS_VERSION);

extern struct kobject *shadow_get_kobj(void);

/* Hidden interface entry */
struct hidden_iface {
    char name[IFNAMSIZ];
    struct list_head list;
};

/* Configuration */
static struct {
    bool enabled;
    bool hide_all;
    struct list_head hidden_ifaces;
    spinlock_t lock;
    u64 flags_hidden;
} promisc_cfg;

static struct kobject *promisc_kobj;

/* Check if interface should be hidden */
static bool should_hide_promisc(const char *ifname)
{
    struct hidden_iface *hi;
    
    if (!promisc_cfg.enabled)
        return false;
    
    if (promisc_cfg.hide_all)
        return true;
    
    list_for_each_entry(hi, &promisc_cfg.hidden_ifaces, list) {
        if (strcmp(hi->name, ifname) == 0)
            return true;
    }
    
    return false;
}

/* Get sanitized flags (hiding PROMISC) - exported for hooks */
unsigned int shadow_get_hidden_flags(struct net_device *dev)
{
    unsigned int flags = dev->flags;
    
    spin_lock(&promisc_cfg.lock);
    if (should_hide_promisc(dev->name)) {
        if (flags & IFF_PROMISC) {
            flags &= ~IFF_PROMISC;
            promisc_cfg.flags_hidden++;
        }
    }
    spin_unlock(&promisc_cfg.lock);
    
    return flags;
}
EXPORT_SYMBOL_GPL(shadow_get_hidden_flags);

/* Check if promisc should be hidden for a device - API for other modules */
bool shadow_promisc_is_hidden(struct net_device *dev)
{
    bool hidden = false;
    
    if (!promisc_cfg.enabled)
        return false;
    
    spin_lock(&promisc_cfg.lock);
    hidden = should_hide_promisc(dev->name);
    spin_unlock(&promisc_cfg.lock);
    
    return hidden && (dev->flags & IFF_PROMISC);
}
EXPORT_SYMBOL_GPL(shadow_promisc_is_hidden);

/* Sysfs Interface */
static ssize_t promisc_enabled_show(struct kobject *kobj,
                                    struct kobj_attribute *attr, char *buf)
{
    return sprintf(buf, "%d\n", promisc_cfg.enabled);
}

static ssize_t promisc_enabled_store(struct kobject *kobj,
                                     struct kobj_attribute *attr,
                                     const char *buf, size_t count)
{
    bool val;
    int rc = kstrtobool(buf, &val);
    if (rc)
        return rc;
    
    promisc_cfg.enabled = val;
    if (val)
        pr_info("ShadowOS PROMISC: 👻 Stealth mode ACTIVE - promisc flags will be hidden\n");
    else
        pr_info("ShadowOS PROMISC: Stealth mode disabled\n");
    
    return count;
}

static ssize_t promisc_hide_all_show(struct kobject *kobj,
                                     struct kobj_attribute *attr, char *buf)
{
    return sprintf(buf, "%d\n", promisc_cfg.hide_all);
}

static ssize_t promisc_hide_all_store(struct kobject *kobj,
                                      struct kobj_attribute *attr,
                                      const char *buf, size_t count)
{
    return kstrtobool(buf, &promisc_cfg.hide_all) ? : count;
}

static ssize_t promisc_add_store(struct kobject *kobj,
                                 struct kobj_attribute *attr,
                                 const char *buf, size_t count)
{
    struct hidden_iface *hi;
    char name[IFNAMSIZ];
    size_t len;
    
    len = min(count, sizeof(name) - 1);
    strncpy(name, buf, len);
    name[len] = '\0';
    
    if (len > 0 && name[len-1] == '\n')
        name[len-1] = '\0';
    
    hi = kzalloc(sizeof(*hi), GFP_KERNEL);
    if (!hi)
        return -ENOMEM;
    
    strncpy(hi->name, name, sizeof(hi->name) - 1);
    
    spin_lock(&promisc_cfg.lock);
    list_add(&hi->list, &promisc_cfg.hidden_ifaces);
    spin_unlock(&promisc_cfg.lock);
    
    pr_info("ShadowOS PROMISC: 👻 Now hiding promisc on interface %s\n", name);
    return count;
}

static ssize_t promisc_status_show(struct kobject *kobj,
                                   struct kobj_attribute *attr, char *buf)
{
    struct net_device *dev;
    int len = 0;
    
    rtnl_lock();
    for_each_netdev(&init_net, dev) {
        bool hidden = false;
        spin_lock(&promisc_cfg.lock);
        hidden = should_hide_promisc(dev->name);
        spin_unlock(&promisc_cfg.lock);
        
        if (dev->flags & IFF_PROMISC) {
            len += snprintf(buf + len, PAGE_SIZE - len,
                           "%s: PROMISC %s\n", dev->name,
                           hidden ? "(HIDDEN)" : "(VISIBLE)");
        }
    }
    rtnl_unlock();
    
    if (len == 0)
        len = sprintf(buf, "No interfaces in promiscuous mode\n");
    
    return len;
}

static ssize_t promisc_stats_show(struct kobject *kobj,
                                  struct kobj_attribute *attr, char *buf)
{
    int count = 0;
    struct hidden_iface *hi;
    
    spin_lock(&promisc_cfg.lock);
    list_for_each_entry(hi, &promisc_cfg.hidden_ifaces, list)
        count++;
    spin_unlock(&promisc_cfg.lock);
    
    return sprintf(buf, "hidden_ifaces: %d\nflags_hidden: %llu\nhide_all: %d\n",
                   count, promisc_cfg.flags_hidden, promisc_cfg.hide_all);
}

static struct kobj_attribute promisc_attr_enabled =
    __ATTR(enabled, 0644, promisc_enabled_show, promisc_enabled_store);
static struct kobj_attribute promisc_attr_hide_all =
    __ATTR(hide_all, 0644, promisc_hide_all_show, promisc_hide_all_store);
static struct kobj_attribute promisc_attr_add =
    __ATTR(add_interface, 0200, NULL, promisc_add_store);
static struct kobj_attribute promisc_attr_status =
    __ATTR(status, 0444, promisc_status_show, NULL);
static struct kobj_attribute promisc_attr_stats =
    __ATTR(stats, 0444, promisc_stats_show, NULL);

static struct attribute *promisc_attrs[] = {
    &promisc_attr_enabled.attr,
    &promisc_attr_hide_all.attr,
    &promisc_attr_add.attr,
    &promisc_attr_status.attr,
    &promisc_attr_stats.attr,
    NULL,
};

static struct attribute_group promisc_attr_group = {
    .attrs = promisc_attrs,
};

static int __init shadow_promisc_init(void)
{
    struct kobject *parent;
    
    pr_info("ShadowOS: 👻 Initializing Promiscuous Mode Hiding\n");
    
    INIT_LIST_HEAD(&promisc_cfg.hidden_ifaces);
    spin_lock_init(&promisc_cfg.lock);
    promisc_cfg.enabled = false;
    promisc_cfg.hide_all = false;
    promisc_cfg.flags_hidden = 0;
    
    parent = shadow_get_kobj();
    if (parent) {
        promisc_kobj = kobject_create_and_add("promisc", parent);
        if (promisc_kobj) {
            if (sysfs_create_group(promisc_kobj, &promisc_attr_group))
                pr_err("ShadowOS: Failed to create promisc sysfs\n");
        }
    }
    
    pr_info("ShadowOS: 👻 Promisc hiding ready - exports shadow_get_hidden_flags()\n");
    pr_info("ShadowOS: 👻 Note: Full netlink hiding requires LSM integration\n");
    return 0;
}

static void __exit shadow_promisc_exit(void)
{
    struct hidden_iface *hi, *tmp;
    
    if (promisc_kobj) {
        sysfs_remove_group(promisc_kobj, &promisc_attr_group);
        kobject_put(promisc_kobj);
    }
    
    list_for_each_entry_safe(hi, tmp, &promisc_cfg.hidden_ifaces, list) {
        list_del(&hi->list);
        kfree(hi);
    }
    
    pr_info("ShadowOS: Promiscuous hiding unloaded\n");
}

module_init(shadow_promisc_init);
module_exit(shadow_promisc_exit);
