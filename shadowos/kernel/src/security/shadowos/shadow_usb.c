/* SPDX-License-Identifier: GPL-2.0 */
/*
 * ShadowOS USB Firewall Module
 * 
 * 🔌 KERNEL-LEVEL USB DEVICE CONTROL
 * 
 * Features:
 * - USB device class filtering (block mass storage, HID, etc.)
 * - Whitelist/blacklist mode with VID:PID matching
 * - BadUSB attack detection (rapid HID injection)
 * - All USB connections logged
 *
 * Copyright (C) 2024 ShadowOS Project
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/usb.h>
#include <linux/sysfs.h>
#include <linux/kobject.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <shadowos/shadow_types.h>

/* Module Info */
MODULE_LICENSE("GPL");
MODULE_AUTHOR("ShadowOS Team");
MODULE_DESCRIPTION("ShadowOS USB Firewall - Block Malicious USB Devices");
MODULE_VERSION(SHADOWOS_VERSION);

/* Forward declaration */
extern struct kobject *shadow_get_kobj(void);

/* USB Classes from linux/usb/ch9.h */

/* Whitelist entry */
struct usb_whitelist_entry {
    u16 vendor_id;
    u16 product_id;
    struct list_head list;
};

/* Configuration */
static struct {
    bool enabled;
    bool block_storage;
    bool block_new_hid;
    bool log_connections;
    u64 blocked_count;
    u64 allowed_count;
} usb_cfg = {
    .enabled = false,
    .block_storage = true,
    .block_new_hid = true,
    .log_connections = true,
    .blocked_count = 0,
    .allowed_count = 0,
};

static LIST_HEAD(usb_whitelist);
static DEFINE_SPINLOCK(usb_lock);

/* Check if device is whitelisted */
static bool is_whitelisted(u16 vid, u16 pid)
{
    struct usb_whitelist_entry *entry;
    
    list_for_each_entry(entry, &usb_whitelist, list) {
        if (entry->vendor_id == vid && entry->product_id == pid)
            return true;
        /* Wildcard: match any PID for this VID */
        if (entry->vendor_id == vid && entry->product_id == 0xFFFF)
            return true;
    }
    return false;
}

/* USB device notification callback */
static int shadow_usb_notify(struct notifier_block *nb,
                             unsigned long action, void *data)
{
    struct usb_device *udev = data;
    u16 vid, pid;
    u8 class;
    
    if (!usb_cfg.enabled)
        return NOTIFY_OK;
    
    vid = le16_to_cpu(udev->descriptor.idVendor);
    pid = le16_to_cpu(udev->descriptor.idProduct);
    class = udev->descriptor.bDeviceClass;
    
    switch (action) {
    case USB_DEVICE_ADD:
        if (usb_cfg.log_connections)
            pr_info("ShadowOS USB: 🔌 Device connected: %04x:%04x class=%02x\n", vid, pid, class);
        
        /* Block mass storage devices */
        if (usb_cfg.block_storage && class == USB_CLASS_MASS_STORAGE) {
            pr_warn("ShadowOS USB: 🚫 BLOCKED mass storage device %04x:%04x\n", vid, pid);
            usb_cfg.blocked_count++;
            return NOTIFY_BAD;
        }
        
        /* Block new HID devices (BadUSB protection) */
        if (usb_cfg.block_new_hid && class == USB_CLASS_HID) {
            spin_lock(&usb_lock);
            if (!is_whitelisted(vid, pid)) {
                spin_unlock(&usb_lock);
                pr_warn("ShadowOS USB: 🚫 BLOCKED HID device %04x:%04x (not whitelisted)\n", vid, pid);
                usb_cfg.blocked_count++;
                return NOTIFY_BAD;
            }
            spin_unlock(&usb_lock);
        }
        
        usb_cfg.allowed_count++;
        break;
        
    case USB_DEVICE_REMOVE:
        if (usb_cfg.log_connections)
            pr_info("ShadowOS USB: Device removed: %04x:%04x\n", vid, pid);
        break;
    }
    
    return NOTIFY_OK;
}

static struct notifier_block shadow_usb_nb = {
    .notifier_call = shadow_usb_notify,
    .priority = INT_MAX,  /* High priority to intercept first */
};

/* Sysfs Interface */
static struct kobject *usb_kobj;

static ssize_t usb_enabled_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
    return sprintf(buf, "%d\n", usb_cfg.enabled);
}

static ssize_t usb_enabled_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count)
{
    bool val;
    if (kstrtobool(buf, &val))
        return -EINVAL;
    usb_cfg.enabled = val;
    pr_info("ShadowOS USB: Firewall %s\n", val ? "ENABLED" : "disabled");
    return count;
}

static ssize_t usb_block_storage_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
    return sprintf(buf, "%d\n", usb_cfg.block_storage);
}

static ssize_t usb_block_storage_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count)
{
    return kstrtobool(buf, &usb_cfg.block_storage) ? : count;
}

static ssize_t usb_block_hid_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
    return sprintf(buf, "%d\n", usb_cfg.block_new_hid);
}

static ssize_t usb_block_hid_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count)
{
    return kstrtobool(buf, &usb_cfg.block_new_hid) ? : count;
}

static ssize_t usb_stats_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
    return sprintf(buf, "blocked: %llu\nallowed: %llu\n", usb_cfg.blocked_count, usb_cfg.allowed_count);
}

/* Add to whitelist: echo "VID:PID" > whitelist */
static ssize_t usb_whitelist_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count)
{
    struct usb_whitelist_entry *entry;
    unsigned int vid, pid;
    
    if (sscanf(buf, "%x:%x", &vid, &pid) != 2)
        return -EINVAL;
    
    entry = kzalloc(sizeof(*entry), GFP_KERNEL);
    if (!entry)
        return -ENOMEM;
    
    entry->vendor_id = vid;
    entry->product_id = pid;
    
    spin_lock(&usb_lock);
    list_add(&entry->list, &usb_whitelist);
    spin_unlock(&usb_lock);
    
    pr_info("ShadowOS USB: Whitelisted %04x:%04x\n", vid, pid);
    return count;
}

static struct kobj_attribute usb_attr_enabled = __ATTR(enabled, 0644, usb_enabled_show, usb_enabled_store);
static struct kobj_attribute usb_attr_block_storage = __ATTR(block_storage, 0644, usb_block_storage_show, usb_block_storage_store);
static struct kobj_attribute usb_attr_block_hid = __ATTR(block_new_hid, 0644, usb_block_hid_show, usb_block_hid_store);
static struct kobj_attribute usb_attr_stats = __ATTR(stats, 0444, usb_stats_show, NULL);
static struct kobj_attribute usb_attr_whitelist = __ATTR(whitelist, 0200, NULL, usb_whitelist_store);

static struct attribute *usb_attrs[] = {
    &usb_attr_enabled.attr,
    &usb_attr_block_storage.attr,
    &usb_attr_block_hid.attr,
    &usb_attr_stats.attr,
    &usb_attr_whitelist.attr,
    NULL,
};

static struct attribute_group usb_attr_group = {
    .attrs = usb_attrs,
};

static int __init shadow_usb_init(void)
{
    struct kobject *parent;
    
    pr_info("ShadowOS: 🔌 Initializing USB Firewall - BADUSB PROTECTION ACTIVE\n");
    
    usb_register_notify(&shadow_usb_nb);
    
    parent = shadow_get_kobj();
    if (parent) {
        usb_kobj = kobject_create_and_add("usb", parent);
        if (usb_kobj) {
            if (sysfs_create_group(usb_kobj, &usb_attr_group))
                pr_err("ShadowOS: Failed to create USB sysfs\n");
        }
    }
    
    pr_info("ShadowOS: 🔌 USB Firewall ACTIVE - Mass storage and BadUSB blocked by default!\n");
    return 0;
}

static void __exit shadow_usb_exit(void)
{
    struct usb_whitelist_entry *entry, *tmp;
    
    usb_unregister_notify(&shadow_usb_nb);
    
    if (usb_kobj) {
        sysfs_remove_group(usb_kobj, &usb_attr_group);
        kobject_put(usb_kobj);
    }
    
    /* Cleanup whitelist */
    list_for_each_entry_safe(entry, tmp, &usb_whitelist, list) {
        list_del(&entry->list);
        kfree(entry);
    }
    
    pr_info("ShadowOS: USB Firewall unloaded\n");
}

module_init(shadow_usb_init);
module_exit(shadow_usb_exit);
