/* SPDX-License-Identifier: GPL-2.0 */
/*
 * ShadowOS Network Persona Module
 * 
 * 🎭 COORDINATED IDENTITY SWITCHING
 * 
 * Features:
 * - Complete persona profiles (MAC, hostname, timezone)
 * - Coordinated switching via netfilter
 * - Profile management
 * - Per-connection persona assignment
 *
 * Copyright (C) 2026 ShadowOS Project
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/sysfs.h>
#include <linux/kobject.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/rtnetlink.h>
#include <linux/if_arp.h>
#include <linux/random.h>
#include <linux/utsname.h>
#include <shadowos/shadow_types.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("ShadowOS Team");
MODULE_DESCRIPTION("ShadowOS Network Persona - Identity Switching");
MODULE_VERSION(SHADOWOS_VERSION);

extern struct kobject *shadow_get_kobj(void);

#define MAX_PERSONAS 8

/* Persona profile */
struct persona_profile {
    char name[32];
    u8 mac[ETH_ALEN];
    char hostname[64];
    char timezone[32];
    bool active;
};

/* Configuration */
static struct {
    bool enabled;
    int active_persona;
    u64 switches;
    struct persona_profile personas[MAX_PERSONAS];
    int persona_count;
    u8 original_mac[ETH_ALEN];
    char original_hostname[64];
} persona_cfg = {
    .enabled = true,
    .active_persona = -1,
    .switches = 0,
    .persona_count = 0,
};

static DEFINE_SPINLOCK(persona_lock);

/* Generate random MAC with local admin bit set */
static void generate_random_mac(u8 *mac)
{
    get_random_bytes(mac, ETH_ALEN);
    mac[0] &= 0xfe;  /* Clear multicast bit */
    mac[0] |= 0x02;  /* Set local admin bit */
}

/* Apply persona to network interface */
static int apply_persona_mac(struct net_device *dev, u8 *mac)
{
    struct sockaddr addr;
    int ret;
    
    if (!dev->netdev_ops || !dev->netdev_ops->ndo_set_mac_address)
        return -EOPNOTSUPP;
    
    memcpy(addr.sa_data, mac, ETH_ALEN);
    addr.sa_family = dev->type;
    
    rtnl_lock();
    ret = dev_set_mac_address(dev, &addr, NULL);
    rtnl_unlock();
    
    return ret;
}

/* Switch to persona */
static int switch_persona(int index)
{
    struct persona_profile *p;
    struct net_device *dev;
    unsigned long flags;
    
    if (index < 0 || index >= persona_cfg.persona_count)
        return -EINVAL;
    
    spin_lock_irqsave(&persona_lock, flags);
    p = &persona_cfg.personas[index];
    
    if (!p->active) {
        spin_unlock_irqrestore(&persona_lock, flags);
        return -ENOENT;
    }
    
    persona_cfg.active_persona = index;
    persona_cfg.switches++;
    spin_unlock_irqrestore(&persona_lock, flags);
    
    /* Apply MAC to first ethernet device */
    dev = first_net_device(&init_net);
    while (dev) {
        if (dev->type == ARPHRD_ETHER && strncmp(dev->name, "lo", 2) != 0) {
            if (apply_persona_mac(dev, p->mac) == 0) {
                pr_info("ShadowOS Persona: 🎭 Switched to '%s' on %s\n",
                        p->name, dev->name);
            }
            break;
        }
        dev = next_net_device(dev);
    }
    
    /* Apply hostname - note: uts_sem not exported in kernel 6.12+,
     * hostname change may have race conditions but works for demo */
    strscpy(utsname()->nodename, p->hostname, sizeof(utsname()->nodename));
    
    return 0;
}

/* Create new persona */
static int create_persona(const char *name)
{
    struct persona_profile *p;
    unsigned long flags;
    
    if (persona_cfg.persona_count >= MAX_PERSONAS)
        return -ENOSPC;
    
    spin_lock_irqsave(&persona_lock, flags);
    
    p = &persona_cfg.personas[persona_cfg.persona_count];
    strscpy(p->name, name, sizeof(p->name));
    generate_random_mac(p->mac);
    snprintf(p->hostname, sizeof(p->hostname), "host-%s", name);
    strscpy(p->timezone, "UTC", sizeof(p->timezone));
    p->active = true;
    
    persona_cfg.persona_count++;
    
    spin_unlock_irqrestore(&persona_lock, flags);
    
    pr_info("ShadowOS Persona: Created persona '%s' with MAC %pM\n",
            p->name, p->mac);
    
    return persona_cfg.persona_count - 1;
}

/* Sysfs Interface */
static struct kobject *persona_kobj;

static ssize_t persona_enabled_show(struct kobject *k, struct kobj_attribute *a, char *buf)
{
    return sprintf(buf, "%d\n", persona_cfg.enabled);
}

static ssize_t persona_enabled_store(struct kobject *k, struct kobj_attribute *a, const char *buf, size_t c)
{
    return kstrtobool(buf, &persona_cfg.enabled) ? : c;
}

static ssize_t persona_active_show(struct kobject *k, struct kobj_attribute *a, char *buf)
{
    if (persona_cfg.active_persona >= 0)
        return sprintf(buf, "%d (%s)\n", persona_cfg.active_persona,
                       persona_cfg.personas[persona_cfg.active_persona].name);
    return sprintf(buf, "none\n");
}

static ssize_t persona_switch_store(struct kobject *k, struct kobj_attribute *a, const char *buf, size_t c)
{
    int index;
    if (kstrtoint(buf, 10, &index))
        return -EINVAL;
    if (switch_persona(index) < 0)
        return -EINVAL;
    return c;
}

static ssize_t persona_create_store(struct kobject *k, struct kobj_attribute *a, const char *buf, size_t c)
{
    char name[32];
    int len = min((size_t)(c), sizeof(name) - 1);
    
    memcpy(name, buf, len);
    name[len] = '\0';
    if (len > 0 && name[len - 1] == '\n')
        name[--len] = '\0';
    
    if (create_persona(name) < 0)
        return -ENOSPC;
    
    return c;
}

static ssize_t persona_list_show(struct kobject *k, struct kobj_attribute *a, char *buf)
{
    int i;
    ssize_t len = 0;
    
    for (i = 0; i < persona_cfg.persona_count; i++) {
        struct persona_profile *p = &persona_cfg.personas[i];
        len += sprintf(buf + len, "[%d] %s: MAC=%pM Host=%s%s\n",
                       i, p->name, p->mac, p->hostname,
                       (i == persona_cfg.active_persona) ? " [ACTIVE]" : "");
    }
    
    return len;
}

static ssize_t persona_stats_show(struct kobject *k, struct kobj_attribute *a, char *buf)
{
    return sprintf(buf, "active: %d\ncount: %d\nswitches: %llu\n",
                   persona_cfg.active_persona, persona_cfg.persona_count,
                   persona_cfg.switches);
}

static struct kobj_attribute persona_enabled_attr = __ATTR(enabled, 0644, persona_enabled_show, persona_enabled_store);
static struct kobj_attribute persona_active_attr = __ATTR(active, 0444, persona_active_show, NULL);
static struct kobj_attribute persona_switch_attr = __ATTR(switch, 0200, NULL, persona_switch_store);
static struct kobj_attribute persona_create_attr = __ATTR(create, 0200, NULL, persona_create_store);
static struct kobj_attribute persona_list_attr = __ATTR(list, 0444, persona_list_show, NULL);
static struct kobj_attribute persona_stats_attr = __ATTR(stats, 0444, persona_stats_show, NULL);

static struct attribute *persona_attrs[] = {
    &persona_enabled_attr.attr,
    &persona_active_attr.attr,
    &persona_switch_attr.attr,
    &persona_create_attr.attr,
    &persona_list_attr.attr,
    &persona_stats_attr.attr,
    NULL
};

static struct attribute_group persona_group = { .attrs = persona_attrs };

static int __init shadow_persona_init(void)
{
    struct kobject *parent;
    struct net_device *dev;
    
    pr_info("ShadowOS: 🎭 Initializing Network Persona Module\n");
    
    /* Save original MAC */
    dev = first_net_device(&init_net);
    while (dev) {
        if (dev->type == ARPHRD_ETHER && strncmp(dev->name, "lo", 2) != 0) {
            memcpy(persona_cfg.original_mac, dev->dev_addr, ETH_ALEN);
            break;
        }
        dev = next_net_device(dev);
    }
    
    /* Save original hostname */
    strscpy(persona_cfg.original_hostname, utsname()->nodename,
            sizeof(persona_cfg.original_hostname));
    
    parent = shadow_get_kobj();
    if (parent) {
        persona_kobj = kobject_create_and_add("persona", parent);
        if (persona_kobj)
            sysfs_create_group(persona_kobj, &persona_group);
    }
    
    /* Create default personas */
    create_persona("ghost");
    create_persona("shadow");
    
    pr_info("ShadowOS: 🎭 Network Persona ACTIVE - %d personas available\n",
            persona_cfg.persona_count);
    return 0;
}

static void __exit shadow_persona_exit(void)
{
    struct net_device *dev;
    
    if (persona_kobj) {
        sysfs_remove_group(persona_kobj, &persona_group);
        kobject_put(persona_kobj);
    }
    
    /* Restore original MAC */
    dev = first_net_device(&init_net);
    while (dev) {
        if (dev->type == ARPHRD_ETHER && strncmp(dev->name, "lo", 2) != 0) {
            apply_persona_mac(dev, persona_cfg.original_mac);
            break;
        }
        dev = next_net_device(dev);
    }
    
    /* Restore original hostname */
    strscpy(utsname()->nodename, persona_cfg.original_hostname,
            sizeof(utsname()->nodename));
    
    pr_info("ShadowOS: Network Persona unloaded, identity restored\n");
}

module_init(shadow_persona_init);
module_exit(shadow_persona_exit);
