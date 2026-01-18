/* SPDX-License-Identifier: GPL-2.0 */
/*
 * ShadowOS Dead Man's Switch (shadow_deadman)
 * 
 * REQUIRE PERIODIC CHECK-INS OR TRIGGER ACTION
 * 
 * Features:
 * - Configurable check-in interval
 * - Trigger actions: wipe, lock, alert
 * - Userspace notification support
 *
 * Copyright (C) 2026 ShadowOS Project
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/timer.h>
#include <linux/sysfs.h>
#include <linux/kobject.h>
#include <shadowos/shadow_types.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("ShadowOS Team");
MODULE_DESCRIPTION("ShadowOS Dead Man's Switch - Periodic Check-in Required");
MODULE_VERSION(SHADOWOS_VERSION);

extern struct kobject *shadow_get_kobj(void);

/* Possible actions */
enum deadman_action {
    DEADMAN_ACTION_ALERT = 0,
    DEADMAN_ACTION_LOCK,
    DEADMAN_ACTION_WIPE,
};

/* Configuration */
static struct {
    bool armed;
    u32 interval_hours;
    u64 last_checkin;
    enum deadman_action action;
    bool triggered;
    u64 checkin_count;
} deadman_cfg = {
    .armed = false,
    .interval_hours = 24,
    .last_checkin = 0,
    .action = DEADMAN_ACTION_ALERT,
    .triggered = false,
    .checkin_count = 0,
};

static struct timer_list deadman_timer;
static struct kobject *deadman_kobj;

/* Check if triggered */
static void deadman_check(struct timer_list *t)
{
    u64 now = ktime_get_real_seconds();
    u64 elapsed_hours;
    
    if (!deadman_cfg.armed || deadman_cfg.triggered)
        goto reschedule;
    
    if (deadman_cfg.last_checkin == 0) {
        deadman_cfg.last_checkin = now;
        goto reschedule;
    }
    
    elapsed_hours = (now - deadman_cfg.last_checkin) / 3600;
    
    if (elapsed_hours >= deadman_cfg.interval_hours) {
        deadman_cfg.triggered = true;
        
        pr_crit("ShadowOS DEADMAN: ⚠️ SWITCH TRIGGERED - No check-in for %llu hours!\n",
                elapsed_hours);
        
        switch (deadman_cfg.action) {
            case DEADMAN_ACTION_ALERT:
                pr_alert("ShadowOS DEADMAN: Action = ALERT\n");
                break;
            case DEADMAN_ACTION_LOCK:
                pr_alert("ShadowOS DEADMAN: Action = LOCK (requires userspace)\n");
                break;
            case DEADMAN_ACTION_WIPE:
                pr_alert("ShadowOS DEADMAN: Action = WIPE (requires confirmation)\n");
                break;
        }
    }
    
reschedule:
    mod_timer(&deadman_timer, jiffies + HZ * 60);  /* Check every minute */
}

/* Sysfs Interface */
static ssize_t deadman_armed_show(struct kobject *kobj,
                                  struct kobj_attribute *attr, char *buf)
{
    return sprintf(buf, "%d\n", deadman_cfg.armed);
}

static ssize_t deadman_armed_store(struct kobject *kobj,
                                   struct kobj_attribute *attr,
                                   const char *buf, size_t count)
{
    bool armed;
    int rc = kstrtobool(buf, &armed);
    if (rc)
        return rc;
    
    if (armed && !deadman_cfg.armed) {
        deadman_cfg.last_checkin = ktime_get_real_seconds();
        deadman_cfg.triggered = false;
        pr_info("ShadowOS DEADMAN: Armed! Check-in required every %u hours\n",
                deadman_cfg.interval_hours);
    }
    
    deadman_cfg.armed = armed;
    return count;
}

static ssize_t deadman_interval_show(struct kobject *kobj,
                                     struct kobj_attribute *attr, char *buf)
{
    return sprintf(buf, "%u\n", deadman_cfg.interval_hours);
}

static ssize_t deadman_interval_store(struct kobject *kobj,
                                      struct kobj_attribute *attr,
                                      const char *buf, size_t count)
{
    return kstrtou32(buf, 10, &deadman_cfg.interval_hours) ? : count;
}

static ssize_t deadman_checkin_store(struct kobject *kobj,
                                     struct kobj_attribute *attr,
                                     const char *buf, size_t count)
{
    deadman_cfg.last_checkin = ktime_get_real_seconds();
    deadman_cfg.checkin_count++;
    deadman_cfg.triggered = false;
    
    pr_info("ShadowOS DEADMAN: Check-in received (#%llu)\n", 
            deadman_cfg.checkin_count);
    
    return count;
}

static ssize_t deadman_status_show(struct kobject *kobj,
                                   struct kobj_attribute *attr, char *buf)
{
    u64 now = ktime_get_real_seconds();
    u64 elapsed = 0;
    u64 remaining = 0;
    
    if (deadman_cfg.last_checkin > 0) {
        elapsed = (now - deadman_cfg.last_checkin) / 3600;
        if (deadman_cfg.interval_hours > elapsed)
            remaining = deadman_cfg.interval_hours - elapsed;
    }
    
    return sprintf(buf, 
                   "armed: %s\n"
                   "triggered: %s\n"
                   "interval: %u hours\n"
                   "elapsed: %llu hours\n"
                   "remaining: %llu hours\n"
                   "checkins: %llu\n"
                   "action: %s\n",
                   deadman_cfg.armed ? "yes" : "no",
                   deadman_cfg.triggered ? "YES!" : "no",
                   deadman_cfg.interval_hours,
                   elapsed,
                   remaining,
                   deadman_cfg.checkin_count,
                   deadman_cfg.action == DEADMAN_ACTION_ALERT ? "alert" :
                   deadman_cfg.action == DEADMAN_ACTION_LOCK ? "lock" : "wipe");
}

static ssize_t deadman_action_show(struct kobject *kobj,
                                   struct kobj_attribute *attr, char *buf)
{
    return sprintf(buf, "%s\n",
                   deadman_cfg.action == DEADMAN_ACTION_ALERT ? "alert" :
                   deadman_cfg.action == DEADMAN_ACTION_LOCK ? "lock" : "wipe");
}

static ssize_t deadman_action_store(struct kobject *kobj,
                                    struct kobj_attribute *attr,
                                    const char *buf, size_t count)
{
    if (strncmp(buf, "alert", 5) == 0)
        deadman_cfg.action = DEADMAN_ACTION_ALERT;
    else if (strncmp(buf, "lock", 4) == 0)
        deadman_cfg.action = DEADMAN_ACTION_LOCK;
    else if (strncmp(buf, "wipe", 4) == 0)
        deadman_cfg.action = DEADMAN_ACTION_WIPE;
    else
        return -EINVAL;
    
    return count;
}

static struct kobj_attribute deadman_attr_armed =
    __ATTR(armed, 0644, deadman_armed_show, deadman_armed_store);
static struct kobj_attribute deadman_attr_interval =
    __ATTR(interval_hours, 0644, deadman_interval_show, deadman_interval_store);
static struct kobj_attribute deadman_attr_checkin =
    __ATTR(checkin, 0200, NULL, deadman_checkin_store);
static struct kobj_attribute deadman_attr_status =
    __ATTR(status, 0444, deadman_status_show, NULL);
static struct kobj_attribute deadman_attr_action =
    __ATTR(action, 0644, deadman_action_show, deadman_action_store);

static struct attribute *deadman_attrs[] = {
    &deadman_attr_armed.attr,
    &deadman_attr_interval.attr,
    &deadman_attr_checkin.attr,
    &deadman_attr_status.attr,
    &deadman_attr_action.attr,
    NULL,
};

static struct attribute_group deadman_attr_group = {
    .attrs = deadman_attrs,
};

static int __init shadow_deadman_init(void)
{
    struct kobject *parent;
    
    pr_info("ShadowOS: 💀 Initializing Dead Man's Switch\n");
    
    timer_setup(&deadman_timer, deadman_check, 0);
    mod_timer(&deadman_timer, jiffies + HZ * 60);
    
    parent = shadow_get_kobj();
    if (parent) {
        deadman_kobj = kobject_create_and_add("deadman", parent);
        if (deadman_kobj) {
            if (sysfs_create_group(deadman_kobj, &deadman_attr_group))
                pr_err("ShadowOS: Failed to create deadman sysfs\n");
        }
    }
    
    pr_info("ShadowOS: 💀 Dead Man's Switch ready\n");
    return 0;
}

static void __exit shadow_deadman_exit(void)
{
    del_timer_sync(&deadman_timer);
    
    if (deadman_kobj) {
        sysfs_remove_group(deadman_kobj, &deadman_attr_group);
        kobject_put(deadman_kobj);
    }
    
    pr_info("ShadowOS: Dead Man's Switch unloaded\n");
}

module_init(shadow_deadman_init);
module_exit(shadow_deadman_exit);
