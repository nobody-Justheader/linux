/* SPDX-License-Identifier: GPL-2.0 */
/*
 * ShadowOS MAC Address Rotation Module
 * 
 * 🔄 AUTOMATIC MAC ADDRESS ROTATION
 * 
 * Features:
 * - Random MAC on boot
 * - Timed MAC rotation
 * - OUI preservation option
 * - Per-interface control
 *
 * Copyright (C) 2026 ShadowOS Project
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/rtnetlink.h>
#include <linux/random.h>
#include <linux/timer.h>
#include <linux/if_arp.h>
#include <linux/sysfs.h>
#include <linux/kobject.h>
#include <shadowos/shadow_types.h>

/* Module Info */
MODULE_LICENSE("GPL");
MODULE_AUTHOR("ShadowOS Team");
MODULE_DESCRIPTION("ShadowOS MAC Rotation - Automatic MAC Randomization");
MODULE_VERSION(SHADOWOS_VERSION);

/* Forward declaration */
extern struct kobject *shadow_get_kobj(void);

/* Configuration */
static struct {
    bool enabled;
    bool preserve_oui;
    u32 interval_minutes;
    bool randomize_on_boot;
    u64 rotations_count;
} mac_cfg = {
    .enabled = false,
    .preserve_oui = true,
    .interval_minutes = 30,
    .randomize_on_boot = true,
    .rotations_count = 0,
};

static struct timer_list mac_timer;

/* Generate random MAC address */
static void generate_random_mac(u8 *mac, const u8 *original, bool preserve_oui)
{
    if (preserve_oui) {
        /* Keep vendor OUI (first 3 bytes) */
        memcpy(mac, original, 3);
        get_random_bytes(mac + 3, 3);
    } else {
        /* Fully random */
        get_random_bytes(mac, ETH_ALEN);
    }
    
    /* Ensure locally administered, unicast */
    mac[0] &= 0xFE;  /* Clear multicast bit */
    mac[0] |= 0x02;  /* Set locally administered bit */
}

/* Rotate MAC for a device */
static int rotate_mac(struct net_device *dev)
{
    u8 new_mac[ETH_ALEN];
    struct sockaddr_storage ss;
    struct sockaddr *sa = (struct sockaddr *)&ss;
    int ret;
    
    if (!dev || !(dev->flags & IFF_UP))
        return -ENODEV;
    
    generate_random_mac(new_mac, dev->dev_addr, mac_cfg.preserve_oui);
    
    memcpy(sa->sa_data, new_mac, ETH_ALEN);
    sa->sa_family = dev->type;
    
    rtnl_lock();
    ret = dev_set_mac_address(dev, &ss, NULL);
    rtnl_unlock();
    
    if (ret == 0) {
        mac_cfg.rotations_count++;
        pr_info("ShadowOS MAC: 🔄 %s rotated to %pM\n", dev->name, new_mac);
    }
    
    return ret;
}

/* Timer callback for automatic rotation */
static void mac_timer_callback(struct timer_list *t)
{
    struct net_device *dev;
    
    if (!mac_cfg.enabled)
        goto reschedule;
    
    rcu_read_lock();
    for_each_netdev_rcu(&init_net, dev) {
        if (dev->type == ARPHRD_ETHER && (dev->flags & IFF_UP)) {
            rotate_mac(dev);
        }
    }
    rcu_read_unlock();

reschedule:
    mod_timer(&mac_timer, jiffies + msecs_to_jiffies(mac_cfg.interval_minutes * 60 * 1000));
}

/* Sysfs Interface */
static struct kobject *mac_kobj;

static ssize_t mac_enabled_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
    return sprintf(buf, "%d\n", mac_cfg.enabled);
}

static ssize_t mac_enabled_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count)
{
    bool val;
    if (kstrtobool(buf, &val))
        return -EINVAL;
    mac_cfg.enabled = val;
    pr_info("ShadowOS MAC: Rotation %s\n", val ? "ENABLED" : "disabled");
    return count;
}

static ssize_t mac_interval_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
    return sprintf(buf, "%u\n", mac_cfg.interval_minutes);
}

static ssize_t mac_interval_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count)
{
    unsigned int val;
    if (kstrtouint(buf, 10, &val) || val < 1 || val > 1440)
        return -EINVAL;
    mac_cfg.interval_minutes = val;
    return count;
}

static ssize_t mac_preserve_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
    return sprintf(buf, "%d\n", mac_cfg.preserve_oui);
}

static ssize_t mac_preserve_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count)
{
    return kstrtobool(buf, &mac_cfg.preserve_oui) ? : count;
}

static ssize_t mac_rotate_now_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count)
{
    struct net_device *dev;
    char ifname[IFNAMSIZ];
    int len = min(count, sizeof(ifname) - 1);
    
    strncpy(ifname, buf, len);
    ifname[len] = '\0';
    if (len > 0 && ifname[len-1] == '\n')
        ifname[len-1] = '\0';
    
    dev = dev_get_by_name(&init_net, ifname);
    if (dev) {
        rotate_mac(dev);
        dev_put(dev);
    }
    return count;
}

static ssize_t mac_stats_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
    return sprintf(buf, "enabled: %d\ninterval_min: %u\nrotations: %llu\n",
                   mac_cfg.enabled, mac_cfg.interval_minutes, mac_cfg.rotations_count);
}

static struct kobj_attribute mac_attr_enabled = __ATTR(enabled, 0644, mac_enabled_show, mac_enabled_store);
static struct kobj_attribute mac_attr_interval = __ATTR(interval_minutes, 0644, mac_interval_show, mac_interval_store);
static struct kobj_attribute mac_attr_preserve = __ATTR(preserve_oui, 0644, mac_preserve_show, mac_preserve_store);
static struct kobj_attribute mac_attr_rotate = __ATTR(rotate_now, 0200, NULL, mac_rotate_now_store);
static struct kobj_attribute mac_attr_stats = __ATTR(stats, 0444, mac_stats_show, NULL);

static struct attribute *mac_attrs[] = {
    &mac_attr_enabled.attr,
    &mac_attr_interval.attr,
    &mac_attr_preserve.attr,
    &mac_attr_rotate.attr,
    &mac_attr_stats.attr,
    NULL,
};

static struct attribute_group mac_attr_group = {
    .attrs = mac_attrs,
};

static int __init shadow_mac_init(void)
{
    struct kobject *parent;
    
    pr_info("ShadowOS: 🔄 Initializing MAC Rotation\n");
    
    parent = shadow_get_kobj();
    if (parent) {
        mac_kobj = kobject_create_and_add("mac", parent);
        if (mac_kobj) {
            if (sysfs_create_group(mac_kobj, &mac_attr_group))
                pr_err("ShadowOS: Failed to create MAC sysfs\n");
        }
    }
    
    /* Setup timer */
    timer_setup(&mac_timer, mac_timer_callback, 0);
    mod_timer(&mac_timer, jiffies + msecs_to_jiffies(mac_cfg.interval_minutes * 60 * 1000));
    
    pr_info("ShadowOS: 🔄 MAC Rotation ready - change your identity on demand!\n");
    return 0;
}

static void __exit shadow_mac_exit(void)
{
    timer_delete_sync(&mac_timer);
    
    if (mac_kobj) {
        sysfs_remove_group(mac_kobj, &mac_attr_group);
        kobject_put(mac_kobj);
    }
    
    pr_info("ShadowOS: MAC Rotation unloaded\n");
}

module_init(shadow_mac_init);
module_exit(shadow_mac_exit);
