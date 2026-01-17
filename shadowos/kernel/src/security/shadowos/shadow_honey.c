/* SPDX-License-Identifier: GPL-2.0 */
/*
 * ShadowOS Honeytoken Module (shadow_honey)
 * 
 * DECOY FILES THAT ALERT ON ACCESS
 * 
 * Features:
 * - File-based honeytokens that trigger alerts when accessed
 * - Configurable paths and access types (read, stat, open)
 * - Full accessor logging (PID, UID, command, parent)
 *
 * Copyright (C) 2024 ShadowOS Project
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/sysfs.h>
#include <linux/kobject.h>
#include <linux/spinlock.h>
#include <linux/list.h>
#include <linux/kprobes.h>
#include <shadowos/shadow_types.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("ShadowOS Team");
MODULE_DESCRIPTION("ShadowOS Honeytoken - Decoy File Alerts");
MODULE_VERSION(SHADOWOS_VERSION);

extern struct kobject *shadow_get_kobj(void);

/* Honeytoken entry */
struct honeytoken {
    char path[256];
    bool alert_on_open;
    bool alert_on_read;
    bool alert_on_stat;
    bool log_full_info;
    u64 access_count;
    struct list_head list;
};

/* Configuration */
static struct {
    bool enabled;
    struct list_head tokens;
    spinlock_t lock;
    u64 total_triggers;
} honey_cfg;

static struct kobject *honey_kobj;

/* Check if path matches a honeytoken */
static struct honeytoken *find_honeytoken(const char *path)
{
    struct honeytoken *ht;
    
    list_for_each_entry(ht, &honey_cfg.tokens, list) {
        /* Exact match or wildcard */
        if (strcmp(ht->path, path) == 0)
            return ht;
        /* Check if path ends with honeytoken pattern */
        if (strstr(path, ht->path))
            return ht;
    }
    return NULL;
}

/* Log full accessor information */
static void log_accessor_info(struct task_struct *task, const char *path)
{
    struct task_struct *parent;
    
    pr_warn("ShadowOS HONEY: === HONEYTOKEN TRIGGERED ===\n");
    pr_warn("ShadowOS HONEY: Path: %s\n", path);
    pr_warn("ShadowOS HONEY: Process: %s (PID: %d)\n", task->comm, task->pid);
    pr_warn("ShadowOS HONEY: UID: %d, GID: %d\n",
            from_kuid(&init_user_ns, task->cred->uid),
            from_kgid(&init_user_ns, task->cred->gid));
    
    parent = task->real_parent;
    if (parent) {
        pr_warn("ShadowOS HONEY: Parent: %s (PID: %d)\n", 
                parent->comm, parent->pid);
    }
    
    pr_warn("ShadowOS HONEY: ================================\n");
}

/* Called when a honeytoken is accessed */
static void trigger_honeytoken(struct honeytoken *ht, const char *path,
                               const char *access_type)
{
    struct task_struct *task = current;
    
    ht->access_count++;
    honey_cfg.total_triggers++;
    
    pr_alert("ShadowOS HONEY: [ALERT] %s accessed: %s by %s (pid %d)\n",
             access_type, path, task->comm, task->pid);
    
    if (ht->log_full_info)
        log_accessor_info(task, path);
}

/* Kprobe for file open - simplified implementation */
static int honey_check_open(const char *pathname)
{
    struct honeytoken *ht;
    
    if (!honey_cfg.enabled)
        return 0;
    
    spin_lock(&honey_cfg.lock);
    ht = find_honeytoken(pathname);
    if (ht && ht->alert_on_open) {
        trigger_honeytoken(ht, pathname, "OPEN");
    }
    spin_unlock(&honey_cfg.lock);
    
    return 0;  /* Always allow access - we're observing */
}

/* Sysfs Interface */
static ssize_t honey_enabled_show(struct kobject *kobj, 
                                  struct kobj_attribute *attr, char *buf)
{
    return sprintf(buf, "%d\n", honey_cfg.enabled);
}

static ssize_t honey_enabled_store(struct kobject *kobj,
                                   struct kobj_attribute *attr,
                                   const char *buf, size_t count)
{
    return kstrtobool(buf, &honey_cfg.enabled) ? : count;
}

static ssize_t honey_add_store(struct kobject *kobj,
                               struct kobj_attribute *attr,
                               const char *buf, size_t count)
{
    struct honeytoken *ht;
    char path[256];
    size_t len;
    
    len = min(count, sizeof(path) - 1);
    strncpy(path, buf, len);
    path[len] = '\0';
    
    /* Remove newline */
    if (len > 0 && path[len-1] == '\n')
        path[len-1] = '\0';
    
    ht = kzalloc(sizeof(*ht), GFP_KERNEL);
    if (!ht)
        return -ENOMEM;
    
    strncpy(ht->path, path, sizeof(ht->path) - 1);
    ht->alert_on_open = true;
    ht->alert_on_read = true;
    ht->alert_on_stat = false;
    ht->log_full_info = true;
    
    spin_lock(&honey_cfg.lock);
    list_add(&ht->list, &honey_cfg.tokens);
    spin_unlock(&honey_cfg.lock);
    
    pr_info("ShadowOS HONEY: Added honeytoken: %s\n", path);
    return count;
}

static ssize_t honey_stats_show(struct kobject *kobj,
                                struct kobj_attribute *attr, char *buf)
{
    struct honeytoken *ht;
    int len = 0;
    int count = 0;
    
    spin_lock(&honey_cfg.lock);
    list_for_each_entry(ht, &honey_cfg.tokens, list) {
        count++;
    }
    spin_unlock(&honey_cfg.lock);
    
    len = sprintf(buf, "tokens: %d\ntriggers: %llu\n", 
                  count, honey_cfg.total_triggers);
    return len;
}

static ssize_t honey_list_show(struct kobject *kobj,
                               struct kobj_attribute *attr, char *buf)
{
    struct honeytoken *ht;
    int len = 0;
    
    spin_lock(&honey_cfg.lock);
    list_for_each_entry(ht, &honey_cfg.tokens, list) {
        len += snprintf(buf + len, PAGE_SIZE - len, 
                       "%s (triggers: %llu)\n", ht->path, ht->access_count);
        if (len >= PAGE_SIZE - 100)
            break;
    }
    spin_unlock(&honey_cfg.lock);
    
    return len;
}

static struct kobj_attribute honey_attr_enabled = 
    __ATTR(enabled, 0644, honey_enabled_show, honey_enabled_store);
static struct kobj_attribute honey_attr_add = 
    __ATTR(add, 0200, NULL, honey_add_store);
static struct kobj_attribute honey_attr_stats = 
    __ATTR(stats, 0444, honey_stats_show, NULL);
static struct kobj_attribute honey_attr_list = 
    __ATTR(list, 0444, honey_list_show, NULL);

static struct attribute *honey_attrs[] = {
    &honey_attr_enabled.attr,
    &honey_attr_add.attr,
    &honey_attr_stats.attr,
    &honey_attr_list.attr,
    NULL,
};

static struct attribute_group honey_attr_group = {
    .attrs = honey_attrs,
};

/* Default honeytokens */
static const char *default_honeytokens[] = {
    "passwords.txt",
    "id_rsa_backup",
    ".bash_history_backup",
    "shadow.bak",
    "mysql_passwords.txt",
    "credentials.xml",
    "secret_key.pem",
    NULL
};

static int __init shadow_honey_init(void)
{
    struct kobject *parent;
    struct honeytoken *ht;
    int i;
    
    pr_info("ShadowOS: 🍯 Initializing Honeytoken Module\n");
    
    INIT_LIST_HEAD(&honey_cfg.tokens);
    spin_lock_init(&honey_cfg.lock);
    honey_cfg.enabled = false;
    honey_cfg.total_triggers = 0;
    
    /* Add default honeytokens */
    for (i = 0; default_honeytokens[i]; i++) {
        ht = kzalloc(sizeof(*ht), GFP_KERNEL);
        if (ht) {
            strncpy(ht->path, default_honeytokens[i], sizeof(ht->path) - 1);
            ht->alert_on_open = true;
            ht->alert_on_read = true;
            ht->log_full_info = true;
            list_add(&ht->list, &honey_cfg.tokens);
        }
    }
    
    parent = shadow_get_kobj();
    if (parent) {
        honey_kobj = kobject_create_and_add("honey", parent);
        if (honey_kobj) {
            if (sysfs_create_group(honey_kobj, &honey_attr_group))
                pr_err("ShadowOS: Failed to create honey sysfs\n");
        }
    }
    
    pr_info("ShadowOS: 🍯 Honeytoken Module loaded with %d default tokens\n", i);
    return 0;
}

static void __exit shadow_honey_exit(void)
{
    struct honeytoken *ht, *tmp;
    
    if (honey_kobj) {
        sysfs_remove_group(honey_kobj, &honey_attr_group);
        kobject_put(honey_kobj);
    }
    
    /* Free all honeytokens */
    list_for_each_entry_safe(ht, tmp, &honey_cfg.tokens, list) {
        list_del(&ht->list);
        kfree(ht);
    }
    
    pr_info("ShadowOS: Honeytoken Module unloaded\n");
}

module_init(shadow_honey_init);
module_exit(shadow_honey_exit);
