/* SPDX-License-Identifier: GPL-2.0 */
/*
 * ShadowOS Auto-Escalation Module
 * 
 * 🚨 AUTOMATIC DEFCON LEVEL ESCALATION
 * 
 * Features:
 * - Monitors threat indicators from other modules
 * - Automatically escalates DEFCON level based on threat score
 * - Configurable thresholds and cooldown periods
 * - Integration with DEFCON notifier chain
 *
 * Copyright (C) 2026 ShadowOS Project
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/sysfs.h>
#include <linux/kobject.h>
#include <linux/timer.h>
#include <linux/workqueue.h>
#include <shadowos/shadow_types.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("ShadowOS Team");
MODULE_DESCRIPTION("ShadowOS Auto-Escalation - Threat-Based DEFCON Management");
MODULE_VERSION(SHADOWOS_VERSION);

extern struct kobject *shadow_get_kobj(void);
extern int shadow_defcon_escalate(void);
extern int shadow_defcon_deescalate(void);
extern int shadow_defcon_get_level(void);

/* Threat indicators */
struct threat_indicator {
    const char *name;
    int weight;
    u64 count;
    unsigned long last_seen;
};

static struct threat_indicator threats[] = {
    { "scan_detected", 10, 0, 0 },
    { "beacon_detected", 25, 0, 0 },
    { "exfil_detected", 30, 0, 0 },
    { "rootkit_detected", 50, 0, 0 },
    { "phishing_detected", 15, 0, 0 },
    { "tamper_detected", 40, 0, 0 },
    { "brute_force", 20, 0, 0 },
    { "malware_detected", 45, 0, 0 },
    { NULL, 0, 0, 0 }
};

/* Configuration */
static struct {
    bool enabled;
    int threat_score;
    int escalate_threshold;     /* Score needed to escalate */
    int deescalate_threshold;   /* Score to deescalate */
    int cooldown_seconds;       /* Time between escalations */
    unsigned long last_escalation;
    u64 auto_escalations;
    u64 auto_deescalations;
} escalate_cfg = {
    .enabled = true,
    .threat_score = 0,
    .escalate_threshold = 50,
    .deescalate_threshold = 10,
    .cooldown_seconds = 60,
    .last_escalation = 0,
    .auto_escalations = 0,
    .auto_deescalations = 0,
};

static struct timer_list assess_timer;
static struct workqueue_struct *escalate_wq;
static struct work_struct assess_work;

/* Calculate current threat score */
static int calculate_threat_score(void)
{
    int i;
    int score = 0;
    unsigned long now = jiffies;
    unsigned long decay_time = 5 * 60 * HZ;  /* 5 minute decay */
    
    for (i = 0; threats[i].name; i++) {
        if (threats[i].count > 0) {
            /* Apply time decay */
            if (time_after(now, threats[i].last_seen + decay_time)) {
                threats[i].count = 0;  /* Fully decayed */
            } else {
                /* Weighted contribution */
                score += threats[i].weight * min((u64)5, threats[i].count);
            }
        }
    }
    
    return score;
}

/* Report threat from other modules */
int shadow_escalate_threat(const char *threat_type)
{
    int i;
    
    if (!escalate_cfg.enabled)
        return 0;
    
    for (i = 0; threats[i].name; i++) {
        if (strcmp(threats[i].name, threat_type) == 0) {
            threats[i].count++;
            threats[i].last_seen = jiffies;
            pr_debug("ShadowOS Escalate: Threat '%s' reported (count: %llu)\n",
                     threat_type, threats[i].count);
            return 0;
        }
    }
    
    return -EINVAL;
}
EXPORT_SYMBOL_GPL(shadow_escalate_threat);

/* Assessment work function */
static void assess_threats(struct work_struct *work)
{
    int score;
    int current_level;
    unsigned long now = jiffies;
    
    if (!escalate_cfg.enabled)
        return;
    
    score = calculate_threat_score();
    escalate_cfg.threat_score = score;
    
    current_level = shadow_defcon_get_level();
    
    /* Check cooldown */
    if (time_before(now, escalate_cfg.last_escalation + escalate_cfg.cooldown_seconds * HZ))
        return;
    
    /* Escalate if score exceeds threshold */
    if (score >= escalate_cfg.escalate_threshold && current_level > 1) {
        pr_warn("ShadowOS Escalate: 🚨 Threat score %d >= %d, ESCALATING DEFCON\n",
                score, escalate_cfg.escalate_threshold);
        shadow_defcon_escalate();
        escalate_cfg.auto_escalations++;
        escalate_cfg.last_escalation = now;
    }
    /* Deescalate if score is low enough */
    else if (score <= escalate_cfg.deescalate_threshold && current_level < 5) {
        if (time_after(now, escalate_cfg.last_escalation + 10 * 60 * HZ)) {
            /* Only deescalate after 10 minutes of calm */
            pr_info("ShadowOS Escalate: Threat score %d <= %d, deescalating DEFCON\n",
                    score, escalate_cfg.deescalate_threshold);
            shadow_defcon_deescalate();
            escalate_cfg.auto_deescalations++;
        }
    }
}

/* Timer callback */
static void assess_timer_callback(struct timer_list *t)
{
    /* Queue assessment work */
    queue_work(escalate_wq, &assess_work);
    
    /* Reschedule timer for every 30 seconds */
    mod_timer(&assess_timer, jiffies + 30 * HZ);
}

/* Sysfs Interface */
static struct kobject *escalate_kobj;

static ssize_t escalate_enabled_show(struct kobject *k, struct kobj_attribute *a, char *buf)
{
    return sprintf(buf, "%d\n", escalate_cfg.enabled);
}

static ssize_t escalate_enabled_store(struct kobject *k, struct kobj_attribute *a, const char *buf, size_t c)
{
    return kstrtobool(buf, &escalate_cfg.enabled) ? : c;
}

static ssize_t escalate_threshold_show(struct kobject *k, struct kobj_attribute *a, char *buf)
{
    return sprintf(buf, "%d\n", escalate_cfg.escalate_threshold);
}

static ssize_t escalate_threshold_store(struct kobject *k, struct kobj_attribute *a, const char *buf, size_t c)
{
    int val;
    if (kstrtoint(buf, 10, &val) || val < 0 || val > 500)
        return -EINVAL;
    escalate_cfg.escalate_threshold = val;
    return c;
}

static ssize_t escalate_score_show(struct kobject *k, struct kobj_attribute *a, char *buf)
{
    return sprintf(buf, "%d\n", calculate_threat_score());
}

/* Report threat manually for testing */
static ssize_t escalate_report_store(struct kobject *k, struct kobj_attribute *a, const char *buf, size_t c)
{
    char threat[64];
    int len = min((size_t)(c), sizeof(threat) - 1);
    
    memcpy(threat, buf, len);
    threat[len] = '\0';
    if (len > 0 && threat[len - 1] == '\n')
        threat[--len] = '\0';
    
    shadow_escalate_threat(threat);
    return c;
}

static ssize_t escalate_stats_show(struct kobject *k, struct kobj_attribute *a, char *buf)
{
    int i;
    ssize_t len = 0;
    
    len += sprintf(buf + len, "threat_score: %d\nescalate_threshold: %d\ndeescalate_threshold: %d\n",
                   calculate_threat_score(), escalate_cfg.escalate_threshold, 
                   escalate_cfg.deescalate_threshold);
    len += sprintf(buf + len, "auto_escalations: %llu\nauto_deescalations: %llu\n",
                   escalate_cfg.auto_escalations, escalate_cfg.auto_deescalations);
    
    len += sprintf(buf + len, "\nThreat indicators:\n");
    for (i = 0; threats[i].name; i++) {
        if (threats[i].count > 0)
            len += sprintf(buf + len, "  %s: %llu (weight: %d)\n",
                           threats[i].name, threats[i].count, threats[i].weight);
    }
    
    return len;
}

static struct kobj_attribute escalate_enabled_attr = __ATTR(enabled, 0644, escalate_enabled_show, escalate_enabled_store);
static struct kobj_attribute escalate_threshold_attr = __ATTR(threshold, 0644, escalate_threshold_show, escalate_threshold_store);
static struct kobj_attribute escalate_score_attr = __ATTR(score, 0444, escalate_score_show, NULL);
static struct kobj_attribute escalate_report_attr = __ATTR(report_threat, 0200, NULL, escalate_report_store);
static struct kobj_attribute escalate_stats_attr = __ATTR(stats, 0444, escalate_stats_show, NULL);

static struct attribute *escalate_attrs[] = {
    &escalate_enabled_attr.attr,
    &escalate_threshold_attr.attr,
    &escalate_score_attr.attr,
    &escalate_report_attr.attr,
    &escalate_stats_attr.attr,
    NULL
};

static struct attribute_group escalate_group = { .attrs = escalate_attrs };

static int __init shadow_escalate_init(void)
{
    struct kobject *parent;
    
    pr_info("ShadowOS: 🚨 Initializing Auto-Escalation Module\n");
    
    /* Create workqueue */
    escalate_wq = create_singlethread_workqueue("shadow_escalate");
    if (!escalate_wq) {
        pr_err("ShadowOS: Failed to create escalate workqueue\n");
        return -ENOMEM;
    }
    
    INIT_WORK(&assess_work, assess_threats);
    timer_setup(&assess_timer, assess_timer_callback, 0);
    
    parent = shadow_get_kobj();
    if (parent) {
        escalate_kobj = kobject_create_and_add("escalate", parent);
        if (escalate_kobj)
            sysfs_create_group(escalate_kobj, &escalate_group);
    }
    
    /* Start assessment timer */
    mod_timer(&assess_timer, jiffies + 30 * HZ);
    
    pr_info("ShadowOS: 🚨 Auto-Escalation ACTIVE - Monitoring threat indicators\n");
    return 0;
}

static void __exit shadow_escalate_exit(void)
{
    del_timer_sync(&assess_timer);
    
    if (escalate_wq) {
        cancel_work_sync(&assess_work);
        destroy_workqueue(escalate_wq);
    }
    
    if (escalate_kobj) {
        sysfs_remove_group(escalate_kobj, &escalate_group);
        kobject_put(escalate_kobj);
    }
    
    pr_info("ShadowOS: Auto-Escalation unloaded\n");
}

module_init(shadow_escalate_init);
module_exit(shadow_escalate_exit);
