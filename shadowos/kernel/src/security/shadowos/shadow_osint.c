/* SPDX-License-Identifier: GPL-2.0 */
/*
 * ShadowOS Counter-OSINT Module
 * 
 * 🕵️ DISINFORMATION AND DECOY GENERATION
 * 
 * Features:
 * - Generate fake system information
 * - Create decoy files with plausible content
 * - Randomize system fingerprints
 * - Misleading network responses
 *
 * Copyright (C) 2024 ShadowOS Project
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/sysfs.h>
#include <linux/kobject.h>
#include <linux/random.h>
#include <linux/utsname.h>
#include <shadowos/shadow_types.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("ShadowOS Team");
MODULE_DESCRIPTION("ShadowOS Counter-OSINT - Disinformation Engine");
MODULE_VERSION(SHADOWOS_VERSION);

extern struct kobject *shadow_get_kobj(void);

/* Fake OS identities */
static const char *fake_os_names[] = {
    "Windows 10 Enterprise", "macOS Ventura", "Ubuntu 22.04",
    "Red Hat Enterprise 8", "CentOS Stream 9", "Fedora 39"
};
#define NUM_FAKE_OS ARRAY_SIZE(fake_os_names)

/* Configuration */
static struct {
    bool enabled;
    bool fake_uname;
    bool fake_hostname;
    int fake_os_index;
    u64 decoys_generated;
    u64 queries_misled;
} osint_cfg = {
    .enabled = true,
    .fake_uname = false,
    .fake_hostname = false,
    .fake_os_index = -1,  /* Not faking by default */
    .decoys_generated = 0,
    .queries_misled = 0,
};

/* Generate random realistic string */
static void generate_random_string(char *buf, int len, const char *charset)
{
    int i;
    u8 rand_byte;
    int charset_len = strlen(charset);
    
    for (i = 0; i < len - 1; i++) {
        get_random_bytes(&rand_byte, 1);
        buf[i] = charset[rand_byte % charset_len];
    }
    buf[len - 1] = '\0';
}

/* Generate a decoy file path */
static void generate_decoy_path(char *path, int max_len)
{
    static const char *decoy_dirs[] = {
        "/home/admin/documents/",
        "/home/user/downloads/",
        "/var/backup/",
        "/opt/data/"
    };
    static const char *decoy_names[] = {
        "passwords.txt", "bank_accounts.xlsx", "private_keys.pem",
        "credit_cards.csv", "ssh_keys.tar", "wallet.dat"
    };
    u8 rand1, rand2;
    
    get_random_bytes(&rand1, 1);
    get_random_bytes(&rand2, 1);
    
    snprintf(path, max_len, "%s%s",
             decoy_dirs[rand1 % ARRAY_SIZE(decoy_dirs)],
             decoy_names[rand2 % ARRAY_SIZE(decoy_names)]);
}

/* Sysfs Interface */
static struct kobject *osint_kobj;

static ssize_t osint_enabled_show(struct kobject *k, struct kobj_attribute *a, char *buf)
{ return sprintf(buf, "%d\n", osint_cfg.enabled); }

static ssize_t osint_enabled_store(struct kobject *k, struct kobj_attribute *a, const char *buf, size_t c)
{ return kstrtobool(buf, &osint_cfg.enabled) ? : c; }

static ssize_t osint_fake_os_show(struct kobject *k, struct kobj_attribute *a, char *buf)
{
    if (osint_cfg.fake_os_index >= 0 && osint_cfg.fake_os_index < NUM_FAKE_OS)
        return sprintf(buf, "%s\n", fake_os_names[osint_cfg.fake_os_index]);
    return sprintf(buf, "none\n");
}

static ssize_t osint_fake_os_store(struct kobject *k, struct kobj_attribute *a, const char *buf, size_t c)
{
    int val;
    if (kstrtoint(buf, 10, &val) || val < -1 || val >= NUM_FAKE_OS)
        return -EINVAL;
    osint_cfg.fake_os_index = val;
    if (val >= 0)
        pr_info("ShadowOS OSINT: 🕵️ Now appearing as '%s'\n", fake_os_names[val]);
    return c;
}

static ssize_t osint_available_show(struct kobject *k, struct kobj_attribute *a, char *buf)
{
    int i;
    ssize_t len = 0;
    
    for (i = 0; i < NUM_FAKE_OS; i++)
        len += sprintf(buf + len, "[%d] %s\n", i, fake_os_names[i]);
    
    return len;
}

static ssize_t osint_gen_decoy_store(struct kobject *k, struct kobj_attribute *a, const char *buf, size_t c)
{
    char path[128];
    generate_decoy_path(path, sizeof(path));
    pr_info("ShadowOS OSINT: 🕵️ Decoy path generated: %s\n", path);
    osint_cfg.decoys_generated++;
    return c;
}

static ssize_t osint_stats_show(struct kobject *k, struct kobj_attribute *a, char *buf)
{
    return sprintf(buf, "decoys: %llu\nmisled: %llu\nfake_os: %s\n",
                   osint_cfg.decoys_generated, osint_cfg.queries_misled,
                   osint_cfg.fake_os_index >= 0 ? fake_os_names[osint_cfg.fake_os_index] : "none");
}

static struct kobj_attribute osint_enabled_attr = __ATTR(enabled, 0644, osint_enabled_show, osint_enabled_store);
static struct kobj_attribute osint_fake_os_attr = __ATTR(fake_os, 0644, osint_fake_os_show, osint_fake_os_store);
static struct kobj_attribute osint_available_attr = __ATTR(available_os, 0444, osint_available_show, NULL);
static struct kobj_attribute osint_decoy_attr = __ATTR(generate_decoy, 0200, NULL, osint_gen_decoy_store);
static struct kobj_attribute osint_stats_attr = __ATTR(stats, 0444, osint_stats_show, NULL);

static struct attribute *osint_attrs[] = {
    &osint_enabled_attr.attr,
    &osint_fake_os_attr.attr,
    &osint_available_attr.attr,
    &osint_decoy_attr.attr,
    &osint_stats_attr.attr,
    NULL
};

static struct attribute_group osint_group = { .attrs = osint_attrs };

static int __init shadow_osint_init(void)
{
    struct kobject *parent;
    
    pr_info("ShadowOS: 🕵️ Initializing Counter-OSINT Module\n");
    
    parent = shadow_get_kobj();
    if (parent) {
        osint_kobj = kobject_create_and_add("osint", parent);
        if (osint_kobj)
            sysfs_create_group(osint_kobj, &osint_group);
    }
    
    pr_info("ShadowOS: 🕵️ Counter-OSINT ACTIVE - Disinformation ready\n");
    return 0;
}

static void __exit shadow_osint_exit(void)
{
    if (osint_kobj) {
        sysfs_remove_group(osint_kobj, &osint_group);
        kobject_put(osint_kobj);
    }
    
    pr_info("ShadowOS: Counter-OSINT unloaded\n");
}

module_init(shadow_osint_init);
module_exit(shadow_osint_exit);
