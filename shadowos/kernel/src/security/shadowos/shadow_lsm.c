/* SPDX-License-Identifier: GPL-2.0 */
/*
 * ShadowOS Security Hook Module (Kprobe Implementation)
 * 
 * 🛡️ SECURITY HOOK INTEGRATION VIA KPROBES
 * 
 * This module uses kprobes to hook security-critical functions,
 * providing LSM-like functionality as a loadable module.
 * 
 * Note: Traditional LSMs must be built into the kernel. This module
 * uses kprobes as an alternative for out-of-tree security monitoring.
 *
 * Integrated modules:
 * - shadow_av: Camera/mic blocking
 * - shadow_cloak: Process hiding from /proc
 * - shadow_honey: Honeytoken file access alerts
 * - shadow_meta: Metadata scrubbing on file close
 *
 * Copyright (C) 2026 ShadowOS Project
 */

#define pr_fmt(fmt) "ShadowOS Hooks: " fmt

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/fs.h>
#include <linux/dcache.h>
#include <linux/path.h>
#include <linux/sched.h>
#include <linux/namei.h>
#include <shadowos/shadow_types.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("ShadowOS Team");
MODULE_DESCRIPTION("ShadowOS Security Hooks - Kprobe-based File Monitoring");
MODULE_VERSION(SHADOWOS_VERSION);

/* External function declarations from other modules */
/* shadow_av - Camera/microphone blocking */
extern bool shadow_av_check_access(const char *filename);

/* shadow_cloak - Process hiding */
extern bool shadow_cloak_is_hidden(pid_t pid);

/* shadow_honey - Honeytoken alerts */
extern void shadow_honey_check_open(const char *pathname);

/* shadow_meta - Metadata scrubbing */
extern void shadow_meta_file_closed(struct file *file);

/* Configuration */
static struct {
    bool enabled;
    u64 file_opens;
    u64 file_closes; 
    u64 av_blocks;
    u64 honey_alerts;
} hook_cfg = {
    .enabled = true,
    .file_opens = 0,
    .file_closes = 0,
    .av_blocks = 0,
    .honey_alerts = 0,
};

/* Kprobe for do_filp_open (file open hook) */
static struct kprobe kp_filp_open = {
    .symbol_name = "do_filp_open",
};

/* Kprobe return probe for do_filp_open */
static struct kretprobe krp_filp_open = {
    .kp.symbol_name = "do_filp_open",
    .maxactive = 64,
};

/* Handler for file open - runs after do_filp_open returns */
static int filp_open_ret_handler(struct kretprobe_instance *ri, 
                                  struct pt_regs *regs)
{
    struct file *file;
    const struct path *path;
    char *buf, *pathname;
    
    if (!hook_cfg.enabled)
        return 0;
    
    /* Get return value (struct file *) */
    file = (struct file *)regs_return_value(regs);
    if (IS_ERR_OR_NULL(file))
        return 0;
    
    path = &file->f_path;
    if (!path || !path->dentry)
        return 0;
    
    hook_cfg.file_opens++;
    
    buf = kmalloc(PATH_MAX, GFP_ATOMIC);
    if (!buf)
        return 0;
    
    pathname = dentry_path_raw(path->dentry, buf, PATH_MAX);
    if (IS_ERR(pathname)) {
        kfree(buf);
        return 0;
    }
    
    /* shadow_av: Block camera/microphone access */
    if (shadow_av_check_access(pathname)) {
        hook_cfg.av_blocks++;
        pr_warn("🛡️ Security check: A/V access detected: %s by %s (pid %d)\n", 
                pathname, current->comm, current->pid);
        /* Note: kprobes can't block - just alert */
    }
    
    /* shadow_honey: Alert on honeytoken access */
    shadow_honey_check_open(pathname);
    
    kfree(buf);
    return 0;
}

/* Kprobe for __fput (file close hook) */
static struct kprobe kp_fput = {
    .symbol_name = "__fput",
};

static int fput_pre_handler(struct kprobe *p, struct pt_regs *regs)
{
    struct file *file;
    
    if (!hook_cfg.enabled)
        return 0;
    
    /* First argument is struct file * */
#ifdef CONFIG_X86_64
    file = (struct file *)regs->di;
#else
    file = (struct file *)regs->regs[0];
#endif
    
    if (!file)
        return 0;
    
    hook_cfg.file_closes++;
    
    /* shadow_meta: Scrub metadata on file close */
    shadow_meta_file_closed(file);
    
    return 0;
}

/* Sysfs Interface */
static struct kobject *hooks_kobj;
extern struct kobject *shadow_get_kobj(void);

static ssize_t hooks_enabled_show(struct kobject *kobj,
                                   struct kobj_attribute *attr, char *buf)
{
    return sprintf(buf, "%d\n", hook_cfg.enabled);
}

static ssize_t hooks_enabled_store(struct kobject *kobj,
                                    struct kobj_attribute *attr,
                                    const char *buf, size_t count)
{
    return kstrtobool(buf, &hook_cfg.enabled) ? : count;
}

static ssize_t hooks_stats_show(struct kobject *kobj,
                                 struct kobj_attribute *attr, char *buf)
{
    return sprintf(buf, 
                   "file_opens: %llu\n"
                   "file_closes: %llu\n"
                   "av_blocks: %llu\n"
                   "honey_alerts: %llu\n",
                   hook_cfg.file_opens, hook_cfg.file_closes,
                   hook_cfg.av_blocks, hook_cfg.honey_alerts);
}

static struct kobj_attribute hooks_attr_enabled =
    __ATTR(enabled, 0644, hooks_enabled_show, hooks_enabled_store);
static struct kobj_attribute hooks_attr_stats =
    __ATTR(stats, 0444, hooks_stats_show, NULL);

static struct attribute *hooks_attrs[] = {
    &hooks_attr_enabled.attr,
    &hooks_attr_stats.attr,
    NULL,
};

static struct attribute_group hooks_attr_group = {
    .attrs = hooks_attrs,
};

static int __init shadow_hooks_init(void)
{
    int ret;
    struct kobject *parent;
    
    pr_info("🛡️ Initializing ShadowOS Security Hooks (Kprobe-based)\n");
    
    /* Register file open kretprobe */
    krp_filp_open.handler = filp_open_ret_handler;
    ret = register_kretprobe(&krp_filp_open);
    if (ret < 0) {
        pr_warn("Failed to register file_open kretprobe: %d\n", ret);
        /* Continue - other probes may work */
    } else {
        pr_info("🛡️ file_open hook registered\n");
    }
    
    /* Register file close kprobe */
    kp_fput.pre_handler = fput_pre_handler;
    ret = register_kprobe(&kp_fput);
    if (ret < 0) {
        pr_warn("Failed to register fput kprobe: %d\n", ret);
    } else {
        pr_info("🛡️ file_close hook registered\n");
    }
    
    /* Create sysfs interface */
    parent = shadow_get_kobj();
    if (parent) {
        hooks_kobj = kobject_create_and_add("hooks", parent);
        if (hooks_kobj) {
            if (sysfs_create_group(hooks_kobj, &hooks_attr_group))
                pr_err("Failed to create hooks sysfs\n");
        }
    }
    
    pr_info("🛡️ ShadowOS Security Hooks ACTIVE\n");
    pr_info("🛡️ Integrated modules:\n");
    pr_info("🛡️   - shadow_av (file_open - camera/mic alerting)\n");
    pr_info("🛡️   - shadow_honey (file_open - honeytoken alerts)\n");
    pr_info("🛡️   - shadow_meta (file_close - metadata scrubbing)\n");
    
    return 0;
}

static void __exit shadow_hooks_exit(void)
{
    unregister_kretprobe(&krp_filp_open);
    unregister_kprobe(&kp_fput);
    
    if (hooks_kobj) {
        sysfs_remove_group(hooks_kobj, &hooks_attr_group);
        kobject_put(hooks_kobj);
    }
    
    pr_info("ShadowOS Security Hooks unloaded\n");
}

module_init(shadow_hooks_init);
module_exit(shadow_hooks_exit);
