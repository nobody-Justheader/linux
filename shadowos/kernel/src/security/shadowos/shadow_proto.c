/* SPDX-License-Identifier: GPL-2.0 */
/*
 * ShadowOS Protocol Whitelist Module
 * 
 * 🔒 APPLICATION LAYER PROTOCOL FILTERING
 * 
 * Features:
 * - Allow/deny by protocol and port
 * - Deep packet inspection for protocol verification
 * - Block port-jumping attacks
 * - Configurable whitelist/blacklist
 *
 * Copyright (C) 2026 ShadowOS Project
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/sysfs.h>
#include <linux/kobject.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <shadowos/shadow_types.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("ShadowOS Team");
MODULE_DESCRIPTION("ShadowOS Protocol Whitelist - Application Layer Firewall");
MODULE_VERSION(SHADOWOS_VERSION);

extern struct kobject *shadow_get_kobj(void);

/* Protocol rule */
struct proto_rule {
    u16 port;
    u8 expected_proto;  /* 0=any, 1=HTTP, 2=TLS, 3=SSH, etc */
    bool allow;
    struct list_head list;
};

/* Configuration */
static struct {
    bool enabled;
    bool default_allow;     /* Allow or deny by default */
    bool verify_protocol;   /* Check if traffic matches expected protocol */
    u64 allowed;
    u64 blocked;
    u64 mismatches;
} proto_cfg = {
    .enabled = true,
    .default_allow = true,
    .verify_protocol = true,
    .allowed = 0,
    .blocked = 0,
    .mismatches = 0,
};

static LIST_HEAD(proto_rules);
static DEFINE_SPINLOCK(proto_lock);

/* Check if payload matches expected HTTP */
static bool is_http(const unsigned char *data, int len)
{
    if (len < 4) return false;
    return (memcmp(data, "GET ", 4) == 0 ||
            memcmp(data, "POST", 4) == 0 ||
            memcmp(data, "HEAD", 4) == 0 ||
            memcmp(data, "PUT ", 4) == 0 ||
            memcmp(data, "HTTP", 4) == 0);
}

/* Check if payload matches TLS */
static bool is_tls(const unsigned char *data, int len)
{
    if (len < 3) return false;
    return (data[0] == 0x16 && data[1] == 0x03);  /* TLS handshake */
}

/* Check if payload matches SSH */
static bool is_ssh(const unsigned char *data, int len)
{
    if (len < 4) return false;
    return (memcmp(data, "SSH-", 4) == 0);
}

/* Verify protocol matches expected */
static bool verify_expected_protocol(u16 port, const unsigned char *data, int len)
{
    switch (port) {
    case 80:
    case 8080:
        return is_http(data, len);
    case 443:
    case 8443:
        return is_tls(data, len);
    case 22:
        return is_ssh(data, len);
    default:
        return true;  /* Unknown port, allow */
    }
}

/* Netfilter hook */
static unsigned int proto_hook(void *priv, struct sk_buff *skb,
                                const struct nf_hook_state *state)
{
    struct iphdr *iph;
    struct tcphdr *tcph;
    unsigned char *payload;
    int payload_len;
    u16 dport;
    struct proto_rule *rule;
    bool found = false;
    bool allow = proto_cfg.default_allow;
    
    if (!proto_cfg.enabled)
        return NF_ACCEPT;
    
    iph = ip_hdr(skb);
    if (iph->protocol != IPPROTO_TCP)
        return NF_ACCEPT;
    
    tcph = tcp_hdr(skb);
    dport = ntohs(tcph->dest);
    
    /* Get payload */
    payload = (unsigned char *)tcph + (tcph->doff * 4);
    payload_len = ntohs(iph->tot_len) - (iph->ihl * 4) - (tcph->doff * 4);
    
    /* Check rules */
    spin_lock(&proto_lock);
    list_for_each_entry(rule, &proto_rules, list) {
        if (rule->port == dport) {
            found = true;
            allow = rule->allow;
            break;
        }
    }
    spin_unlock(&proto_lock);
    
    /* Verify protocol if enabled */
    if (allow && proto_cfg.verify_protocol && payload_len > 0) {
        if (!verify_expected_protocol(dport, payload, payload_len)) {
            proto_cfg.mismatches++;
            pr_warn("ShadowOS Proto: 🔒 Protocol mismatch on port %d - BLOCKED\n", dport);
            proto_cfg.blocked++;
            return NF_DROP;
        }
    }
    
    if (allow) {
        proto_cfg.allowed++;
        return NF_ACCEPT;
    } else {
        proto_cfg.blocked++;
        pr_debug("ShadowOS Proto: Blocked port %d\n", dport);
        return NF_DROP;
    }
}

static struct nf_hook_ops proto_nfho = {
    .hook = proto_hook,
    .pf = NFPROTO_IPV4,
    .hooknum = NF_INET_LOCAL_OUT,
    .priority = NF_IP_PRI_MANGLE + 20,
};

/* Add rule: echo "80:allow" or "22:deny" > add_rule */
static ssize_t proto_add_rule_store(struct kobject *k, struct kobj_attribute *a, const char *buf, size_t c)
{
    struct proto_rule *rule;
    unsigned int port;
    char action[16];
    
    if (sscanf(buf, "%u:%15s", &port, action) != 2)
        return -EINVAL;
    
    rule = kzalloc(sizeof(*rule), GFP_KERNEL);
    if (!rule)
        return -ENOMEM;
    
    rule->port = port;
    rule->allow = (strcmp(action, "allow") == 0);
    
    spin_lock(&proto_lock);
    list_add(&rule->list, &proto_rules);
    spin_unlock(&proto_lock);
    
    pr_info("ShadowOS Proto: Rule added - port %d: %s\n", port, rule->allow ? "ALLOW" : "DENY");
    return c;
}

/* Sysfs Interface */
static struct kobject *proto_kobj;

static ssize_t proto_enabled_show(struct kobject *k, struct kobj_attribute *a, char *buf)
{ return sprintf(buf, "%d\n", proto_cfg.enabled); }

static ssize_t proto_enabled_store(struct kobject *k, struct kobj_attribute *a, const char *buf, size_t c)
{ return kstrtobool(buf, &proto_cfg.enabled) ? : c; }

static ssize_t proto_verify_show(struct kobject *k, struct kobj_attribute *a, char *buf)
{ return sprintf(buf, "%d\n", proto_cfg.verify_protocol); }

static ssize_t proto_verify_store(struct kobject *k, struct kobj_attribute *a, const char *buf, size_t c)
{ return kstrtobool(buf, &proto_cfg.verify_protocol) ? : c; }

static ssize_t proto_stats_show(struct kobject *k, struct kobj_attribute *a, char *buf)
{
    return sprintf(buf, "allowed: %llu\nblocked: %llu\nmismatches: %llu\nverify: %d\n",
                   proto_cfg.allowed, proto_cfg.blocked, proto_cfg.mismatches,
                   proto_cfg.verify_protocol);
}

static struct kobj_attribute proto_enabled_attr = __ATTR(enabled, 0644, proto_enabled_show, proto_enabled_store);
static struct kobj_attribute proto_verify_attr = __ATTR(verify_protocol, 0644, proto_verify_show, proto_verify_store);
static struct kobj_attribute proto_add_rule_attr = __ATTR(add_rule, 0200, NULL, proto_add_rule_store);
static struct kobj_attribute proto_stats_attr = __ATTR(stats, 0444, proto_stats_show, NULL);

static struct attribute *proto_attrs[] = {
    &proto_enabled_attr.attr,
    &proto_verify_attr.attr,
    &proto_add_rule_attr.attr,
    &proto_stats_attr.attr,
    NULL
};

static struct attribute_group proto_group = { .attrs = proto_attrs };

static int __init shadow_proto_init(void)
{
    struct kobject *parent;
    int ret;
    
    pr_info("ShadowOS: 🔒 Initializing Protocol Whitelist\n");
    
    ret = nf_register_net_hook(&init_net, &proto_nfho);
    if (ret) {
        pr_err("ShadowOS: Failed to register proto hook\n");
        return ret;
    }
    
    parent = shadow_get_kobj();
    if (parent) {
        proto_kobj = kobject_create_and_add("proto", parent);
        if (proto_kobj)
            sysfs_create_group(proto_kobj, &proto_group);
    }
    
    pr_info("ShadowOS: 🔒 Protocol Whitelist ACTIVE - DPI enabled\n");
    return 0;
}

static void __exit shadow_proto_exit(void)
{
    struct proto_rule *rule, *tmp;
    
    nf_unregister_net_hook(&init_net, &proto_nfho);
    
    if (proto_kobj) {
        sysfs_remove_group(proto_kobj, &proto_group);
        kobject_put(proto_kobj);
    }
    
    spin_lock(&proto_lock);
    list_for_each_entry_safe(rule, tmp, &proto_rules, list) {
        list_del(&rule->list);
        kfree(rule);
    }
    spin_unlock(&proto_lock);
    
    pr_info("ShadowOS: Protocol Whitelist unloaded\n");
}

module_init(shadow_proto_init);
module_exit(shadow_proto_exit);
