/* SPDX-License-Identifier: GPL-2.0 */
/*
 * ShadowOS DEFCON Levels Module
 * 
 * 🚨 SECURITY POSTURE MANAGEMENT
 * 
 * Features:
 * - 5 security levels (DEFCON 5 = peaceful, DEFCON 1 = maximum)
 * - Auto-apply security settings per level
 * - Escalation triggers
 * - Integration with other ShadowOS modules
 *
 * Copyright (C) 2024 ShadowOS Project
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/sysfs.h>
#include <linux/kobject.h>
#include <linux/notifier.h>
#include <shadowos/shadow_types.h>

/* Module Info */
MODULE_LICENSE("GPL");
MODULE_AUTHOR("ShadowOS Team");
MODULE_DESCRIPTION("ShadowOS DEFCON Levels - Security Posture Management");
MODULE_VERSION(SHADOWOS_VERSION);

/* Forward declaration */
extern struct kobject *shadow_get_kobj(void);

/* DEFCON Levels */
#define DEFCON_5    5   /* Peaceful - minimal security */
#define DEFCON_4    4   /* Normal - standard security */
#define DEFCON_3    3   /* Elevated - enhanced monitoring */
#define DEFCON_2    2   /* High - active defense */
#define DEFCON_1    1   /* Maximum - lockdown mode */

/* Configuration */
static struct {
    int current_level;
    int previous_level;
    bool auto_escalate;
    u64 escalation_count;
    u64 level_changes;
    unsigned long last_change;     /* jiffies */
} defcon_cfg = {
    .current_level = DEFCON_4,
    .previous_level = DEFCON_4,
    .auto_escalate = true,
    .escalation_count = 0,
    .level_changes = 0,
    .last_change = 0,
};

/* Level descriptions */
static const char *defcon_desc[] = {
    [0] = "Invalid",
    [DEFCON_1] = "MAXIMUM - Full lockdown, all defenses active",
    [DEFCON_2] = "HIGH - Active defense, aggressive blocking",
    [DEFCON_3] = "ELEVATED - Enhanced monitoring, suspicious blocking",
    [DEFCON_4] = "NORMAL - Standard security posture",
    [DEFCON_5] = "PEACEFUL - Minimal security, monitoring only",
};

/* Notifier chain for level changes */
static BLOCKING_NOTIFIER_HEAD(defcon_chain);

int shadow_defcon_register(struct notifier_block *nb)
{
    return blocking_notifier_chain_register(&defcon_chain, nb);
}
EXPORT_SYMBOL_GPL(shadow_defcon_register);

int shadow_defcon_unregister(struct notifier_block *nb)
{
    return blocking_notifier_chain_unregister(&defcon_chain, nb);
}
EXPORT_SYMBOL_GPL(shadow_defcon_unregister);

int shadow_defcon_get_level(void)
{
    return defcon_cfg.current_level;
}
EXPORT_SYMBOL_GPL(shadow_defcon_get_level);

/* Set DEFCON level and notify all modules */
static int set_defcon_level(int level)
{
    if (level < DEFCON_1 || level > DEFCON_5)
        return -EINVAL;
    
    if (level == defcon_cfg.current_level)
        return 0;
    
    defcon_cfg.previous_level = defcon_cfg.current_level;
    defcon_cfg.current_level = level;
    defcon_cfg.level_changes++;
    defcon_cfg.last_change = jiffies;
    
    if (level < defcon_cfg.previous_level)
        defcon_cfg.escalation_count++;
    
    pr_warn("ShadowOS DEFCON: 🚨 Level changed: %d -> %d (%s)\n",
            defcon_cfg.previous_level, level, defcon_desc[level]);
    
    /* Notify all registered modules */
    blocking_notifier_call_chain(&defcon_chain, level, NULL);
    
    return 0;
}

/* Escalate by one level */
int shadow_defcon_escalate(void)
{
    if (defcon_cfg.current_level > DEFCON_1)
        return set_defcon_level(defcon_cfg.current_level - 1);
    return 0;
}
EXPORT_SYMBOL_GPL(shadow_defcon_escalate);

/* De-escalate by one level */
int shadow_defcon_deescalate(void)
{
    if (defcon_cfg.current_level < DEFCON_5)
        return set_defcon_level(defcon_cfg.current_level + 1);
    return 0;
}
EXPORT_SYMBOL_GPL(shadow_defcon_deescalate);

/* Sysfs Interface */
static struct kobject *defcon_kobj;

static ssize_t defcon_level_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
    return sprintf(buf, "%d\n", defcon_cfg.current_level);
}

static ssize_t defcon_level_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count)
{
    int level;
    if (kstrtoint(buf, 10, &level))
        return -EINVAL;
    if (set_defcon_level(level))
        return -EINVAL;
    return count;
}

static ssize_t defcon_desc_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
    return sprintf(buf, "%s\n", defcon_desc[defcon_cfg.current_level]);
}

static ssize_t defcon_auto_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
    return sprintf(buf, "%d\n", defcon_cfg.auto_escalate);
}

static ssize_t defcon_auto_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count)
{
    return kstrtobool(buf, &defcon_cfg.auto_escalate) ? : count;
}

static ssize_t defcon_stats_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
    return sprintf(buf, "current: %d\nprevious: %d\nescalations: %llu\nchanges: %llu\n",
                   defcon_cfg.current_level, defcon_cfg.previous_level,
                   defcon_cfg.escalation_count, defcon_cfg.level_changes);
}

static ssize_t defcon_escalate_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count)
{
    shadow_defcon_escalate();
    return count;
}

static ssize_t defcon_deescalate_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count)
{
    shadow_defcon_deescalate();
    return count;
}

static struct kobj_attribute defcon_attr_level = __ATTR(level, 0644, defcon_level_show, defcon_level_store);
static struct kobj_attribute defcon_attr_desc = __ATTR(description, 0444, defcon_desc_show, NULL);
static struct kobj_attribute defcon_attr_auto = __ATTR(auto_escalate, 0644, defcon_auto_show, defcon_auto_store);
static struct kobj_attribute defcon_attr_stats = __ATTR(stats, 0444, defcon_stats_show, NULL);
static struct kobj_attribute defcon_attr_escalate = __ATTR(escalate, 0200, NULL, defcon_escalate_store);
static struct kobj_attribute defcon_attr_deescalate = __ATTR(deescalate, 0200, NULL, defcon_deescalate_store);

static struct attribute *defcon_attrs[] = {
    &defcon_attr_level.attr,
    &defcon_attr_desc.attr,
    &defcon_attr_auto.attr,
    &defcon_attr_stats.attr,
    &defcon_attr_escalate.attr,
    &defcon_attr_deescalate.attr,
    NULL,
};

static struct attribute_group defcon_attr_group = {
    .attrs = defcon_attrs,
};

static int __init shadow_defcon_init(void)
{
    struct kobject *parent;
    
    pr_info("ShadowOS: 🚨 Initializing DEFCON Levels Module\n");
    
    parent = shadow_get_kobj();
    if (parent) {
        defcon_kobj = kobject_create_and_add("defcon", parent);
        if (defcon_kobj) {
            if (sysfs_create_group(defcon_kobj, &defcon_attr_group))
                pr_err("ShadowOS: Failed to create DEFCON sysfs\n");
        }
    }
    
    pr_info("ShadowOS: 🚨 DEFCON System ACTIVE - Current Level: %d (%s)\n",
            defcon_cfg.current_level, defcon_desc[defcon_cfg.current_level]);
    return 0;
}

static void __exit shadow_defcon_exit(void)
{
    if (defcon_kobj) {
        sysfs_remove_group(defcon_kobj, &defcon_attr_group);
        kobject_put(defcon_kobj);
    }
    
    pr_info("ShadowOS: DEFCON module unloaded\n");
}

module_init(shadow_defcon_init);
module_exit(shadow_defcon_exit);
