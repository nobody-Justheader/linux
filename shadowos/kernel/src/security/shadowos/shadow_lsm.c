/* SPDX-License-Identifier: GPL-2.0 */
/*
 * ShadowOS Linux Security Module
 * 
 * 🛡️ CENTRAL LSM HOOK INTEGRATION
 * 
 * This module hooks into Linux security framework to enable
 * automatic interception for ShadowOS security modules.
 *
 * Integrated modules:
 * - shadow_av: Camera/mic blocking
 * - shadow_cloak: Process hiding from /proc
 * - shadow_honey: Honeytoken file access alerts
 * - shadow_meta: Metadata scrubbing on file close
 *
 * Copyright (C) 2026 ShadowOS Project
 */

#define pr_fmt(fmt) "ShadowOS LSM: " fmt

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/security.h>
#include <linux/lsm_hooks.h>
#include <linux/binfmts.h>
#include <linux/fs.h>
#include <linux/dcache.h>
#include <linux/path.h>
#include <linux/sched.h>
#include <linux/cred.h>
#include <linux/magic.h>
#include <shadowos/shadow_types.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("ShadowOS Team");
MODULE_DESCRIPTION("ShadowOS LSM - Central Security Hook Integration");
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

/* LSM ID */
static struct lsm_id shadowos_lsmid __lsm_ro_after_init = {
    .lsm = "shadowos",
    .id = 0,
};

/* Statistics */
static struct {
    u64 file_opens;
    u64 file_closes;
    u64 av_blocks;
    u64 cloak_hides;
    u64 honey_alerts;
    u64 meta_scrubs;
} lsm_stats = { 0 };

/*
 * file_open hook - intercept all file opens
 * Used by: shadow_av, shadow_honey
 */
static int shadowos_file_open(struct file *file)
{
    const struct path *path = &file->f_path;
    char *buf, *pathname;
    
    if (!path || !path->dentry)
        return 0;
    
    lsm_stats.file_opens++;
    
    buf = kmalloc(PATH_MAX, GFP_KERNEL);
    if (!buf)
        return 0;
    
    pathname = dentry_path_raw(path->dentry, buf, PATH_MAX);
    if (IS_ERR(pathname)) {
        kfree(buf);
        return 0;
    }
    
    /* shadow_av: Block camera/microphone access */
    if (shadow_av_check_access(pathname)) {
        lsm_stats.av_blocks++;
        pr_warn("🛡️ BLOCKED A/V access: %s by %s (pid %d)\n", 
                pathname, current->comm, current->pid);
        kfree(buf);
        return -EACCES;
    }
    
    /* shadow_honey: Alert on honeytoken access */
    shadow_honey_check_open(pathname);
    
    kfree(buf);
    return 0;
}

/*
 * file_free_security hook - intercept file closes
 * Used by: shadow_meta
 */
static void shadowos_file_free_security(struct file *file)
{
    lsm_stats.file_closes++;
    
    /* shadow_meta: Scrub metadata on file close */
    shadow_meta_file_closed(file);
}

/*
 * inode_getattr hook - hide processes from stat
 * Used by: shadow_cloak
 */
static int shadowos_inode_getattr(const struct path *path)
{
    struct inode *inode;
    const char *name;
    pid_t pid;
    
    if (!path || !path->dentry)
        return 0;
    
    inode = d_inode(path->dentry);
    if (!inode)
        return 0;
    
    /* Check if this is a /proc/<pid> directory */
    if (path->dentry->d_sb->s_magic == PROC_SUPER_MAGIC) {
        name = path->dentry->d_name.name;
        
        if (kstrtoint(name, 10, &pid) == 0) {
            if (shadow_cloak_is_hidden(pid)) {
                lsm_stats.cloak_hides++;
                pr_debug("🛡️ Hiding PID %d from stat\n", pid);
                return -ENOENT;
            }
        }
    }
    
    return 0;
}

/*
 * task_alloc hook - track new processes
 */
static int shadowos_task_alloc(struct task_struct *task, unsigned long clone_flags)
{
    /* Future: Initialize per-task security state */
    return 0;
}

/* LSM hook definitions */
static struct security_hook_list shadowos_hooks[] __lsm_ro_after_init = {
    LSM_HOOK_INIT(file_open, shadowos_file_open),
    LSM_HOOK_INIT(file_free_security, shadowos_file_free_security),
    LSM_HOOK_INIT(inode_getattr, shadowos_inode_getattr),
    LSM_HOOK_INIT(task_alloc, shadowos_task_alloc),
};

/* Initialize LSM */
static int __init shadowos_lsm_init(void)
{
    pr_info("🛡️ Initializing ShadowOS LSM\n");
    
    security_add_hooks(shadowos_hooks, ARRAY_SIZE(shadowos_hooks),
                       &shadowos_lsmid);
    
    pr_info("🛡️ ShadowOS LSM ACTIVE - %zu hooks registered\n",
            ARRAY_SIZE(shadowos_hooks));
    pr_info("🛡️ Integrated modules:\n");
    pr_info("🛡️   - shadow_av (file_open - camera/mic blocking)\n");
    pr_info("🛡️   - shadow_honey (file_open - honeytoken alerts)\n");
    pr_info("🛡️   - shadow_meta (file_close - metadata scrubbing)\n");
    pr_info("🛡️   - shadow_cloak (inode_getattr - process hiding)\n");
    
    return 0;
}

/* Register as LSM */
DEFINE_LSM(shadowos) = {
    .name = "shadowos",
    .init = shadowos_lsm_init,
};
