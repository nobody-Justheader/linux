/* SPDX-License-Identifier: GPL-2.0 */
/*
 * ShadowOS Traffic Classification Module
 * 
 * 📊 DEEP PACKET INSPECTION AND TRAFFIC CLASSIFICATION
 * 
 * Features:
 * - Protocol detection (HTTP, TLS, SSH, DNS, etc.)
 * - Application fingerprinting
 * - Anomaly scoring based on traffic patterns
 * - Per-connection classification
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
#include <shadowos/shadow_types.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("ShadowOS Team");
MODULE_DESCRIPTION("ShadowOS Traffic Classification - DPI and Protocol Detection");
MODULE_VERSION(SHADOWOS_VERSION);

extern struct kobject *shadow_get_kobj(void);

/* Protocol identifiers */
enum traffic_proto {
    PROTO_UNKNOWN = 0,
    PROTO_HTTP,
    PROTO_HTTPS,
    PROTO_TLS,
    PROTO_SSH,
    PROTO_DNS,
    PROTO_SMTP,
    PROTO_FTP,
    PROTO_IMAP,
    PROTO_POP3,
    PROTO_TELNET,
    PROTO_TORRENT,
    PROTO_VPN,
    PROTO_MAX
};

static const char *proto_names[] = {
    [PROTO_UNKNOWN] = "unknown",
    [PROTO_HTTP] = "http",
    [PROTO_HTTPS] = "https",
    [PROTO_TLS] = "tls",
    [PROTO_SSH] = "ssh",
    [PROTO_DNS] = "dns",
    [PROTO_SMTP] = "smtp",
    [PROTO_FTP] = "ftp",
    [PROTO_IMAP] = "imap",
    [PROTO_POP3] = "pop3",
    [PROTO_TELNET] = "telnet",
    [PROTO_TORRENT] = "torrent",
    [PROTO_VPN] = "vpn",
};

/* Configuration */
static struct {
    bool enabled;
    bool log_all;
    u64 packets_analyzed;
    u64 proto_counts[PROTO_MAX];
    u64 anomalies_detected;
    int anomaly_threshold;
} classify_cfg = {
    .enabled = true,
    .log_all = false,
    .packets_analyzed = 0,
    .anomalies_detected = 0,
    .anomaly_threshold = 50,
};

/* Detect protocol from payload */
static enum traffic_proto detect_protocol(const unsigned char *data, int len, __be16 sport, __be16 dport)
{
    u16 src = ntohs(sport);
    u16 dst = ntohs(dport);
    
    /* Port-based detection first */
    if (dst == 80 || src == 80) {
        if (len >= 4 && (memcmp(data, "GET ", 4) == 0 || 
                         memcmp(data, "POST", 4) == 0 ||
                         memcmp(data, "HTTP", 4) == 0))
            return PROTO_HTTP;
    }
    
    if (dst == 443 || src == 443) {
        /* TLS handshake starts with 0x16 0x03 */
        if (len >= 2 && data[0] == 0x16 && data[1] == 0x03)
            return PROTO_TLS;
        return PROTO_HTTPS;
    }
    
    if (dst == 22 || src == 22) {
        if (len >= 4 && memcmp(data, "SSH-", 4) == 0)
            return PROTO_SSH;
    }
    
    if (dst == 53 || src == 53)
        return PROTO_DNS;
    
    if (dst == 25 || src == 25 || dst == 587 || src == 587)
        return PROTO_SMTP;
    
    if (dst == 21 || src == 21)
        return PROTO_FTP;
    
    if (dst == 143 || src == 143 || dst == 993 || src == 993)
        return PROTO_IMAP;
    
    if (dst == 110 || src == 110 || dst == 995 || src == 995)
        return PROTO_POP3;
    
    if (dst == 23 || src == 23)
        return PROTO_TELNET;
    
    /* BitTorrent detection */
    if (len >= 20 && data[0] == 19 && memcmp(data + 1, "BitTorrent protocol", 19) == 0)
        return PROTO_TORRENT;
    
    /* VPN detection (OpenVPN starts with 0x38) */
    if (len >= 1 && (data[0] == 0x38 || dst == 1194 || src == 1194))
        return PROTO_VPN;
    
    /* Payload-based detection */
    if (len >= 4) {
        if (memcmp(data, "GET ", 4) == 0 || memcmp(data, "POST", 4) == 0 ||
            memcmp(data, "HEAD", 4) == 0 || memcmp(data, "PUT ", 4) == 0)
            return PROTO_HTTP;
    }
    
    return PROTO_UNKNOWN;
}

/* Calculate anomaly score for connection */
static int calculate_anomaly_score(struct sk_buff *skb, enum traffic_proto proto)
{
    struct iphdr *iph = ip_hdr(skb);
    int score = 0;
    
    /* Suspicious: non-standard ports for known protocols */
    if (proto == PROTO_HTTP) {
        struct tcphdr *tcph = tcp_hdr(skb);
        u16 dst = ntohs(tcph->dest);
        if (dst != 80 && dst != 8080 && dst != 8000)
            score += 20;  /* HTTP on unusual port */
    }
    
    /* Suspicious: TLS on non-443 port */
    if (proto == PROTO_TLS) {
        struct tcphdr *tcph = tcp_hdr(skb);
        u16 dst = ntohs(tcph->dest);
        if (dst != 443 && dst != 8443)
            score += 25;
    }
    
    /* Suspicious: Telnet is insecure */
    if (proto == PROTO_TELNET)
        score += 40;
    
    /* Suspicious: FTP is insecure */
    if (proto == PROTO_FTP)
        score += 30;
    
    /* Suspicious: Unknown protocol on high port */
    if (proto == PROTO_UNKNOWN) {
        struct tcphdr *tcph = tcp_hdr(skb);
        if (ntohs(tcph->dest) > 10000)
            score += 15;
    }
    
    /* Suspicious: Very small TTL (might be probe) */
    if (iph->ttl < 10)
        score += 20;
    
    return score;
}

/* Netfilter hook */
static unsigned int classify_hook(void *priv, struct sk_buff *skb,
                                   const struct nf_hook_state *state)
{
    struct iphdr *iph;
    struct tcphdr *tcph;
    unsigned char *payload;
    int payload_len;
    enum traffic_proto proto;
    int anomaly_score;
    
    if (!classify_cfg.enabled)
        return NF_ACCEPT;
    
    iph = ip_hdr(skb);
    if (iph->protocol != IPPROTO_TCP)
        return NF_ACCEPT;
    
    tcph = tcp_hdr(skb);
    
    /* Get payload */
    payload = (unsigned char *)tcph + (tcph->doff * 4);
    payload_len = ntohs(iph->tot_len) - (iph->ihl * 4) - (tcph->doff * 4);
    
    if (payload_len <= 0)
        return NF_ACCEPT;
    
    classify_cfg.packets_analyzed++;
    
    /* Detect protocol */
    proto = detect_protocol(payload, payload_len, tcph->source, tcph->dest);
    classify_cfg.proto_counts[proto]++;
    
    /* Calculate anomaly score */
    anomaly_score = calculate_anomaly_score(skb, proto);
    
    if (anomaly_score >= classify_cfg.anomaly_threshold) {
        classify_cfg.anomalies_detected++;
        pr_warn("ShadowOS Classify: 📊 Anomaly detected: %s traffic, score=%d, %pI4:%d -> %pI4:%d\n",
                proto_names[proto], anomaly_score,
                &iph->saddr, ntohs(tcph->source),
                &iph->daddr, ntohs(tcph->dest));
    } else if (classify_cfg.log_all) {
        pr_debug("ShadowOS Classify: %s traffic %pI4:%d -> %pI4:%d\n",
                 proto_names[proto],
                 &iph->saddr, ntohs(tcph->source),
                 &iph->daddr, ntohs(tcph->dest));
    }
    
    return NF_ACCEPT;
}

static struct nf_hook_ops classify_nfho = {
    .hook = classify_hook,
    .pf = NFPROTO_IPV4,
    .hooknum = NF_INET_LOCAL_OUT,
    .priority = NF_IP_PRI_FIRST + 10,
};

/* Sysfs Interface */
static struct kobject *classify_kobj;

static ssize_t classify_enabled_show(struct kobject *k, struct kobj_attribute *a, char *buf)
{
    return sprintf(buf, "%d\n", classify_cfg.enabled);
}

static ssize_t classify_enabled_store(struct kobject *k, struct kobj_attribute *a, const char *buf, size_t c)
{
    return kstrtobool(buf, &classify_cfg.enabled) ? : c;
}

static ssize_t classify_threshold_show(struct kobject *k, struct kobj_attribute *a, char *buf)
{
    return sprintf(buf, "%d\n", classify_cfg.anomaly_threshold);
}

static ssize_t classify_threshold_store(struct kobject *k, struct kobj_attribute *a, const char *buf, size_t c)
{
    int val;
    if (kstrtoint(buf, 10, &val) || val < 0 || val > 100)
        return -EINVAL;
    classify_cfg.anomaly_threshold = val;
    return c;
}

static ssize_t classify_stats_show(struct kobject *k, struct kobj_attribute *a, char *buf)
{
    int i;
    ssize_t len = 0;
    
    len += sprintf(buf + len, "packets: %llu\nanomalies: %llu\n",
                   classify_cfg.packets_analyzed, classify_cfg.anomalies_detected);
    
    for (i = 0; i < PROTO_MAX; i++) {
        if (classify_cfg.proto_counts[i] > 0)
            len += sprintf(buf + len, "%s: %llu\n", proto_names[i], classify_cfg.proto_counts[i]);
    }
    
    return len;
}

static struct kobj_attribute classify_enabled_attr = __ATTR(enabled, 0644, classify_enabled_show, classify_enabled_store);
static struct kobj_attribute classify_threshold_attr = __ATTR(threshold, 0644, classify_threshold_show, classify_threshold_store);
static struct kobj_attribute classify_stats_attr = __ATTR(stats, 0444, classify_stats_show, NULL);

static struct attribute *classify_attrs[] = {
    &classify_enabled_attr.attr,
    &classify_threshold_attr.attr,
    &classify_stats_attr.attr,
    NULL
};

static struct attribute_group classify_group = { .attrs = classify_attrs };

static int __init shadow_classify_init(void)
{
    struct kobject *parent;
    int ret;
    
    pr_info("ShadowOS: 📊 Initializing Traffic Classification Module\n");
    
    ret = nf_register_net_hook(&init_net, &classify_nfho);
    if (ret) {
        pr_err("ShadowOS: Failed to register classify hook\n");
        return ret;
    }
    
    parent = shadow_get_kobj();
    if (parent) {
        classify_kobj = kobject_create_and_add("classify", parent);
        if (classify_kobj)
            sysfs_create_group(classify_kobj, &classify_group);
    }
    
    pr_info("ShadowOS: 📊 Traffic Classification ACTIVE - DPI enabled\n");
    return 0;
}

static void __exit shadow_classify_exit(void)
{
    nf_unregister_net_hook(&init_net, &classify_nfho);
    
    if (classify_kobj) {
        sysfs_remove_group(classify_kobj, &classify_group);
        kobject_put(classify_kobj);
    }
    
    pr_info("ShadowOS: Traffic Classification unloaded\n");
}

module_init(shadow_classify_init);
module_exit(shadow_classify_exit);
