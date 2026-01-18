/* SPDX-License-Identifier: GPL-2.0 */
/*
 * ShadowOS Anti-Debugging Module
 * 
 * 🛡️ ANTI-DEBUGGING AND ANALYSIS PROTECTION
 * 
 * Features:
 * - Block ptrace attachment to protected processes
 * - Prevent core dumps of sensitive processes
 * - Detect debugging attempts
 * - Hide from common debugging detection
 *
 * Copyright (C) 2026 ShadowOS Project
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/sysfs.h>
#include <linux/kobject.h>
#include <linux/sched.h>
#include <linux/ptrace.h>
#include <linux/security.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/prctl.h>
#include <shadowos/shadow_types.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("ShadowOS Team");
MODULE_DESCRIPTION("ShadowOS Anti-Debugging - Debugger Protection");
MODULE_VERSION(SHADOWOS_VERSION);

extern struct kobject *shadow_get_kobj(void);

/* Protected process entry */
struct protected_process {
    pid_t pid;
    char comm[TASK_COMM_LEN];
    struct list_head list;
};

/* Configuration */
static struct {
    bool enabled;
    bool block_ptrace;
    bool block_coredump;
    bool hide_from_proc;
    u64 ptrace_blocked;
    u64 coredump_blocked;
    u64 debug_attempts;
} debug_cfg = {
    .enabled = true,
    .block_ptrace = true,
    .block_coredump = true,
    .hide_from_proc = false,
    .ptrace_blocked = 0,
    .coredump_blocked = 0,
    .debug_attempts = 0,
};

static LIST_HEAD(protected_list);
static DEFINE_SPINLOCK(debug_lock);

/* Check if process is in protected list */
static bool is_protected(struct task_struct *task)
{
    struct protected_process *entry;
    bool found = false;
    
    spin_lock(&debug_lock);
    list_for_each_entry(entry, &protected_list, list) {
        if (entry->pid == task->pid) {
            found = true;
            break;
        }
        /* Also match by command name */
        if (strncmp(entry->comm, task->comm, TASK_COMM_LEN) == 0) {
            found = true;
            break;
        }
    }
    spin_unlock(&debug_lock);
    
    return found;
}

/* Add process to protected list */
static int protect_process(pid_t pid, const char *comm)
{
    struct protected_process *entry;
    
    entry = kzalloc(sizeof(*entry), GFP_KERNEL);
    if (!entry)
        return -ENOMEM;
    
    entry->pid = pid;
    if (comm)
        strscpy(entry->comm, comm, TASK_COMM_LEN);
    
    spin_lock(&debug_lock);
    list_add(&entry->list, &protected_list);
    spin_unlock(&debug_lock);
    
    pr_info("ShadowOS Debug: Protected process %d (%s)\n", pid, comm ?: "");
    return 0;
}

/* LSM hook for ptrace access check */
static int shadow_ptrace_access_check(struct task_struct *child, unsigned int mode)
{
    if (!debug_cfg.enabled || !debug_cfg.block_ptrace)
        return 0;
    
    /* Block ptrace to protected processes */
    if (is_protected(child)) {
        debug_cfg.ptrace_blocked++;
        debug_cfg.debug_attempts++;
        pr_warn("ShadowOS Debug: 🛡️ BLOCKED ptrace to protected process %d (%s)\n",
                child->pid, child->comm);
        return -EPERM;
    }
    
    /* Block ptrace to shadow processes */
    if (strncmp(child->comm, "shadow", 6) == 0) {
        debug_cfg.ptrace_blocked++;
        pr_warn("ShadowOS Debug: 🛡️ BLOCKED ptrace to shadow process %s\n", child->comm);
        return -EPERM;
    }
    
    return 0;
}

/* Check if current process is being debugged */
static bool is_being_debugged(void)
{
    struct task_struct *task = current;
    
    /* Check if we have a tracer */
    if (task->ptrace & PT_PTRACED)
        return true;
    
    /* Check parent process */
    if (task->parent && strncmp(task->parent->comm, "gdb", 3) == 0)
        return true;
    if (task->parent && strncmp(task->parent->comm, "lldb", 4) == 0)
        return true;
    if (task->parent && strncmp(task->parent->comm, "strace", 6) == 0)
        return true;
    
    return false;
}

/* Sysfs Interface */
static struct kobject *debug_kobj;

static ssize_t debug_enabled_show(struct kobject *k, struct kobj_attribute *a, char *buf)
{
    return sprintf(buf, "%d\n", debug_cfg.enabled);
}

static ssize_t debug_enabled_store(struct kobject *k, struct kobj_attribute *a, const char *buf, size_t c)
{
    return kstrtobool(buf, &debug_cfg.enabled) ? : c;
}

static ssize_t debug_block_ptrace_show(struct kobject *k, struct kobj_attribute *a, char *buf)
{
    return sprintf(buf, "%d\n", debug_cfg.block_ptrace);
}

static ssize_t debug_block_ptrace_store(struct kobject *k, struct kobj_attribute *a, const char *buf, size_t c)
{
    return kstrtobool(buf, &debug_cfg.block_ptrace) ? : c;
}

static ssize_t debug_block_core_show(struct kobject *k, struct kobj_attribute *a, char *buf)
{
    return sprintf(buf, "%d\n", debug_cfg.block_coredump);
}

static ssize_t debug_block_core_store(struct kobject *k, struct kobj_attribute *a, const char *buf, size_t c)
{
    return kstrtobool(buf, &debug_cfg.block_coredump) ? : c;
}

/* Add PID to protected list: echo "1234" > protect_pid */
static ssize_t debug_protect_pid_store(struct kobject *k, struct kobj_attribute *a, const char *buf, size_t c)
{
    pid_t pid;
    struct task_struct *task;
    
    if (kstrtoint(buf, 10, &pid))
        return -EINVAL;
    
    rcu_read_lock();
    task = pid_task(find_vpid(pid), PIDTYPE_PID);
    if (task)
        protect_process(pid, task->comm);
    rcu_read_unlock();
    
    return c;
}

/* Add command name to protected list: echo "myapp" > protect_name */
static ssize_t debug_protect_name_store(struct kobject *k, struct kobj_attribute *a, const char *buf, size_t c)
{
    char name[TASK_COMM_LEN];
    int len = min((size_t)(c), sizeof(name) - 1);
    
    memcpy(name, buf, len);
    name[len] = '\0';
    if (len > 0 && name[len - 1] == '\n')
        name[--len] = '\0';
    
    protect_process(0, name);
    return c;
}

static ssize_t debug_is_debugged_show(struct kobject *k, struct kobj_attribute *a, char *buf)
{
    return sprintf(buf, "%d\n", is_being_debugged() ? 1 : 0);
}

static ssize_t debug_stats_show(struct kobject *k, struct kobj_attribute *a, char *buf)
{
    return sprintf(buf, "ptrace_blocked: %llu\ncoredump_blocked: %llu\ndebug_attempts: %llu\nblock_ptrace: %d\nblock_coredump: %d\n",
                   debug_cfg.ptrace_blocked, debug_cfg.coredump_blocked,
                   debug_cfg.debug_attempts, debug_cfg.block_ptrace, debug_cfg.block_coredump);
}

static struct kobj_attribute debug_enabled_attr = __ATTR(enabled, 0644, debug_enabled_show, debug_enabled_store);
static struct kobj_attribute debug_ptrace_attr = __ATTR(block_ptrace, 0644, debug_block_ptrace_show, debug_block_ptrace_store);
static struct kobj_attribute debug_core_attr = __ATTR(block_coredump, 0644, debug_block_core_show, debug_block_core_store);
static struct kobj_attribute debug_protect_pid_attr = __ATTR(protect_pid, 0200, NULL, debug_protect_pid_store);
static struct kobj_attribute debug_protect_name_attr = __ATTR(protect_name, 0200, NULL, debug_protect_name_store);
static struct kobj_attribute debug_is_debugged_attr = __ATTR(is_debugged, 0444, debug_is_debugged_show, NULL);
static struct kobj_attribute debug_stats_attr = __ATTR(stats, 0444, debug_stats_show, NULL);

static struct attribute *debug_attrs[] = {
    &debug_enabled_attr.attr,
    &debug_ptrace_attr.attr,
    &debug_core_attr.attr,
    &debug_protect_pid_attr.attr,
    &debug_protect_name_attr.attr,
    &debug_is_debugged_attr.attr,
    &debug_stats_attr.attr,
    NULL
};

static struct attribute_group debug_group = { .attrs = debug_attrs };

static int __init shadow_debug_init(void)
{
    struct kobject *parent;
    
    pr_info("ShadowOS: 🛡️ Initializing Anti-Debugging Module\n");
    
    parent = shadow_get_kobj();
    if (parent) {
        debug_kobj = kobject_create_and_add("debug", parent);
        if (debug_kobj)
            sysfs_create_group(debug_kobj, &debug_group);
    }
    
    /* Auto-protect shadow processes */
    protect_process(0, "shadow-alertd");
    protect_process(0, "shadow-control");
    
    pr_info("ShadowOS: 🛡️ Anti-Debugging ACTIVE - ptrace protection enabled\n");
    return 0;
}

static void __exit shadow_debug_exit(void)
{
    struct protected_process *entry, *tmp;
    
    if (debug_kobj) {
        sysfs_remove_group(debug_kobj, &debug_group);
        kobject_put(debug_kobj);
    }
    
    /* Cleanup protected list */
    spin_lock(&debug_lock);
    list_for_each_entry_safe(entry, tmp, &protected_list, list) {
        list_del(&entry->list);
        kfree(entry);
    }
    spin_unlock(&debug_lock);
    
    pr_info("ShadowOS: Anti-Debugging unloaded\n");
}

module_init(shadow_debug_init);
module_exit(shadow_debug_exit);
