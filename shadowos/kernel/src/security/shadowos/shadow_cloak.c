/* SPDX-License-Identifier: GPL-2.0 */
/*
 * ShadowOS Process Cloaking Module
 * 
 * 👻 HIDE PROCESSES FROM /proc AND ps
 * 
 * Features:
 * - Hide processes by PID
 * - Hide processes by name pattern
 * - Invisible to ps, top, htop
 * - Self-protection capability
 *
 * Copyright (C) 2026 ShadowOS Project
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/sched.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/sysfs.h>
#include <linux/kobject.h>
#include <linux/spinlock.h>
#include <shadowos/shadow_types.h>

/* Module Info */
MODULE_LICENSE("GPL");
MODULE_AUTHOR("ShadowOS Team");
MODULE_DESCRIPTION("ShadowOS Process Cloaking - Hide from /proc");
MODULE_VERSION(SHADOWOS_VERSION);

/* Forward declaration */
extern struct kobject *shadow_get_kobj(void);

/* Hidden PID entry */
struct hidden_pid {
    pid_t pid;
    struct list_head list;
};

/* Hidden name pattern */
struct hidden_name {
    char pattern[64];
    struct list_head list;
};

/* Configuration */
static struct {
    bool enabled;
    u32 hidden_count;
} cloak_cfg = {
    .enabled = false,
    .hidden_count = 0,
};

static LIST_HEAD(hidden_pids);
static LIST_HEAD(hidden_names);
static DEFINE_SPINLOCK(cloak_lock);

/* Check if PID is hidden - exported for LSM integration */
bool shadow_cloak_is_hidden(pid_t pid)
{
    struct hidden_pid *hp;
    struct task_struct *task;
    struct hidden_name *hn;
    
    if (!cloak_cfg.enabled)
        return false;
    
    spin_lock(&cloak_lock);
    
    /* Check explicit PIDs */
    list_for_each_entry(hp, &hidden_pids, list) {
        if (hp->pid == pid) {
            spin_unlock(&cloak_lock);
            return true;
        }
    }
    
    /* Check by name pattern */
    rcu_read_lock();
    task = find_task_by_vpid(pid);
    if (task) {
        list_for_each_entry(hn, &hidden_names, list) {
            if (strstr(task->comm, hn->pattern)) {
                rcu_read_unlock();
                spin_unlock(&cloak_lock);
                return true;
            }
        }
    }
    rcu_read_unlock();
    
    spin_unlock(&cloak_lock);
    return false;
}
EXPORT_SYMBOL_GPL(shadow_cloak_is_hidden);

/* Add PID to hidden list */
static int cloak_hide_pid(pid_t pid)
{
    struct hidden_pid *hp;
    
    hp = kzalloc(sizeof(*hp), GFP_KERNEL);
    if (!hp)
        return -ENOMEM;
    
    hp->pid = pid;
    
    spin_lock(&cloak_lock);
    list_add(&hp->list, &hidden_pids);
    cloak_cfg.hidden_count++;
    spin_unlock(&cloak_lock);
    
    pr_info("ShadowOS Cloak: 👻 PID %d is now INVISIBLE\n", pid);
    return 0;
}

/* Remove PID from hidden list */
static int cloak_unhide_pid(pid_t pid)
{
    struct hidden_pid *hp, *tmp;
    
    spin_lock(&cloak_lock);
    list_for_each_entry_safe(hp, tmp, &hidden_pids, list) {
        if (hp->pid == pid) {
            list_del(&hp->list);
            kfree(hp);
            cloak_cfg.hidden_count--;
            spin_unlock(&cloak_lock);
            pr_info("ShadowOS Cloak: PID %d is now visible\n", pid);
            return 0;
        }
    }
    spin_unlock(&cloak_lock);
    return -ENOENT;
}

/* Hide by name pattern */
static int cloak_hide_name(const char *pattern)
{
    struct hidden_name *hn;
    
    hn = kzalloc(sizeof(*hn), GFP_KERNEL);
    if (!hn)
        return -ENOMEM;
    
    strncpy(hn->pattern, pattern, sizeof(hn->pattern) - 1);
    
    spin_lock(&cloak_lock);
    list_add(&hn->list, &hidden_names);
    spin_unlock(&cloak_lock);
    
    pr_info("ShadowOS Cloak: 👻 Pattern '%s' is now hidden\n", pattern);
    return 0;
}

/* Sysfs Interface */
static struct kobject *cloak_kobj;

static ssize_t cloak_enabled_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
    return sprintf(buf, "%d\n", cloak_cfg.enabled);
}

static ssize_t cloak_enabled_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count)
{
    return kstrtobool(buf, &cloak_cfg.enabled) ? : count;
}

static ssize_t cloak_hide_pid_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count)
{
    pid_t pid;
    if (kstrtoint(buf, 10, &pid))
        return -EINVAL;
    cloak_hide_pid(pid);
    return count;
}

static ssize_t cloak_unhide_pid_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count)
{
    pid_t pid;
    if (kstrtoint(buf, 10, &pid))
        return -EINVAL;
    cloak_unhide_pid(pid);
    return count;
}

static ssize_t cloak_hide_name_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count)
{
    char pattern[64];
    int len = min(count, sizeof(pattern) - 1);
    strncpy(pattern, buf, len);
    pattern[len] = '\0';
    if (len > 0 && pattern[len-1] == '\n')
        pattern[len-1] = '\0';
    cloak_hide_name(pattern);
    return count;
}

static ssize_t cloak_stats_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
    return sprintf(buf, "enabled: %d\nhidden_count: %u\n",
                   cloak_cfg.enabled, cloak_cfg.hidden_count);
}

static struct kobj_attribute cloak_attr_enabled = __ATTR(enabled, 0644, cloak_enabled_show, cloak_enabled_store);
static struct kobj_attribute cloak_attr_hide_pid = __ATTR(hide_pid, 0200, NULL, cloak_hide_pid_store);
static struct kobj_attribute cloak_attr_unhide_pid = __ATTR(unhide_pid, 0200, NULL, cloak_unhide_pid_store);
static struct kobj_attribute cloak_attr_hide_name = __ATTR(hide_name, 0200, NULL, cloak_hide_name_store);
static struct kobj_attribute cloak_attr_stats = __ATTR(stats, 0444, cloak_stats_show, NULL);

static struct attribute *cloak_attrs[] = {
    &cloak_attr_enabled.attr,
    &cloak_attr_hide_pid.attr,
    &cloak_attr_unhide_pid.attr,
    &cloak_attr_hide_name.attr,
    &cloak_attr_stats.attr,
    NULL,
};

static struct attribute_group cloak_attr_group = {
    .attrs = cloak_attrs,
};

static int __init shadow_cloak_init(void)
{
    struct kobject *parent;
    
    pr_info("ShadowOS: 👻 Initializing Process Cloaking\n");
    
    parent = shadow_get_kobj();
    if (parent) {
        cloak_kobj = kobject_create_and_add("cloak", parent);
        if (cloak_kobj) {
            if (sysfs_create_group(cloak_kobj, &cloak_attr_group))
                pr_err("ShadowOS: Failed to create cloak sysfs\n");
        }
    }
    
    pr_info("ShadowOS: 👻 Process Cloaking ready - hide any process!\n");
    return 0;
}

static void __exit shadow_cloak_exit(void)
{
    struct hidden_pid *hp, *tmp_hp;
    struct hidden_name *hn, *tmp_hn;
    
    if (cloak_kobj) {
        sysfs_remove_group(cloak_kobj, &cloak_attr_group);
        kobject_put(cloak_kobj);
    }
    
    /* Cleanup lists */
    list_for_each_entry_safe(hp, tmp_hp, &hidden_pids, list) {
        list_del(&hp->list);
        kfree(hp);
    }
    list_for_each_entry_safe(hn, tmp_hn, &hidden_names, list) {
        list_del(&hn->list);
        kfree(hn);
    }
    
    pr_info("ShadowOS: Process Cloaking unloaded\n");
}

module_init(shadow_cloak_init);
module_exit(shadow_cloak_exit);
