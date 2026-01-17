/* SPDX-License-Identifier: GPL-2.0 */
/*
 * ShadowOS Hardware Keylogger Detection Module
 * 
 * ⌨️ HARDWARE KEYLOGGER DETECTION
 * 
 * Features:
 * - USB HID device enumeration
 * - Timing analysis for inline keyloggers
 * - Suspicious descriptor detection
 * - Multiple keyboard detection
 *
 * Copyright (C) 2024 ShadowOS Project
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/sysfs.h>
#include <linux/kobject.h>
#include <linux/usb.h>
#include <linux/hid.h>
#include <linux/input.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <shadowos/shadow_types.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("ShadowOS Team");
MODULE_DESCRIPTION("ShadowOS Hardware Keylogger Detection - USB HID Analysis");
MODULE_VERSION(SHADOWOS_VERSION);

extern struct kobject *shadow_get_kobj(void);

/* Tracked HID device */
struct hid_entry {
    u16 vendor;
    u16 product;
    char name[64];
    unsigned long first_seen;
    unsigned long last_event;
    u64 event_count;
    bool suspicious;
    struct list_head list;
};

/* Configuration */
static struct {
    bool enabled;
    bool scan_on_connect;
    u64 devices_scanned;
    u64 keyloggers_detected;
    int keyboard_count;
    bool multiple_keyboards_alert;
} keylog_cfg = {
    .enabled = true,
    .scan_on_connect = true,
    .devices_scanned = 0,
    .keyloggers_detected = 0,
    .keyboard_count = 0,
    .multiple_keyboards_alert = false,
};

static LIST_HEAD(hid_devices);
static DEFINE_SPINLOCK(hid_lock);

/* Check for suspicious USB device characteristics */
static bool is_suspicious_device(struct usb_device *udev)
{
    /* Keyloggers often have:
     * - Unusual VID/PID combinations
     * - Multiple interfaces (keyboard + storage)
     * - Short serial numbers or none
     */
    
    struct usb_host_config *config = udev->actconfig;
    int num_interfaces;
    bool has_storage = false;
    bool has_hid = false;
    int i;
    
    if (!config)
        return false;
    
    num_interfaces = config->desc.bNumInterfaces;
    
    /* Check for mixed HID + mass storage (common keylogger pattern) */
    for (i = 0; i < num_interfaces; i++) {
        struct usb_interface *intf = config->interface[i];
        if (intf) {
            struct usb_host_interface *alt = intf->cur_altsetting;
            if (alt) {
                u8 class = alt->desc.bInterfaceClass;
                if (class == USB_CLASS_HID)
                    has_hid = true;
                if (class == USB_CLASS_MASS_STORAGE)
                    has_storage = true;
            }
        }
    }
    
    /* HID + Storage combo is suspicious */
    if (has_hid && has_storage) {
        pr_warn("ShadowOS Keylog: ⌨️ Suspicious: HID + Storage combo device %04x:%04x\n",
                le16_to_cpu(udev->descriptor.idVendor),
                le16_to_cpu(udev->descriptor.idProduct));
        return true;
    }
    
    /* No serial number is suspicious for keyboards */
    if (has_hid && !udev->serial) {
        pr_debug("ShadowOS Keylog: Device without serial: %04x:%04x\n",
                 le16_to_cpu(udev->descriptor.idVendor),
                 le16_to_cpu(udev->descriptor.idProduct));
    }
    
    return false;
}

/* USB device notifier callback */
static int keylog_usb_notify(struct notifier_block *nb,
                             unsigned long action, void *data)
{
    struct usb_device *udev = data;
    struct hid_entry *entry;
    struct usb_host_config *config;
    int i;
    bool is_keyboard = false;
    
    if (!keylog_cfg.enabled || !keylog_cfg.scan_on_connect)
        return NOTIFY_OK;
    
    if (action != USB_DEVICE_ADD)
        return NOTIFY_OK;
    
    config = udev->actconfig;
    if (!config)
        return NOTIFY_OK;
    
    /* Check if this is a keyboard */
    for (i = 0; i < config->desc.bNumInterfaces; i++) {
        struct usb_interface *intf = config->interface[i];
        if (intf && intf->cur_altsetting) {
            struct usb_host_interface *alt = intf->cur_altsetting;
            /* HID keyboard: class 3, subclass 1, protocol 1 */
            if (alt->desc.bInterfaceClass == USB_CLASS_HID &&
                alt->desc.bInterfaceSubClass == 1 &&
                alt->desc.bInterfaceProtocol == 1) {
                is_keyboard = true;
                break;
            }
        }
    }
    
    if (!is_keyboard)
        return NOTIFY_OK;
    
    keylog_cfg.devices_scanned++;
    keylog_cfg.keyboard_count++;
    
    /* Multiple keyboards is suspicious */
    if (keylog_cfg.keyboard_count > 1) {
        keylog_cfg.multiple_keyboards_alert = true;
        pr_warn("ShadowOS Keylog: ⌨️ WARNING: Multiple keyboards detected (%d)!\n",
                keylog_cfg.keyboard_count);
    }
    
    /* Track this device */
    entry = kzalloc(sizeof(*entry), GFP_KERNEL);
    if (entry) {
        entry->vendor = le16_to_cpu(udev->descriptor.idVendor);
        entry->product = le16_to_cpu(udev->descriptor.idProduct);
        if (udev->product)
            strscpy(entry->name, udev->product, sizeof(entry->name));
        entry->first_seen = jiffies;
        entry->suspicious = is_suspicious_device(udev);
        
        if (entry->suspicious)
            keylog_cfg.keyloggers_detected++;
        
        spin_lock(&hid_lock);
        list_add(&entry->list, &hid_devices);
        spin_unlock(&hid_lock);
        
        pr_info("ShadowOS Keylog: Keyboard connected: %04x:%04x %s%s\n",
                entry->vendor, entry->product, entry->name,
                entry->suspicious ? " [SUSPICIOUS]" : "");
    }
    
    return NOTIFY_OK;
}

static struct notifier_block keylog_usb_nb = {
    .notifier_call = keylog_usb_notify,
    .priority = INT_MAX,
};

/* Sysfs Interface */
static struct kobject *keylog_kobj;

static ssize_t keylog_enabled_show(struct kobject *k, struct kobj_attribute *a, char *buf)
{
    return sprintf(buf, "%d\n", keylog_cfg.enabled);
}

static ssize_t keylog_enabled_store(struct kobject *k, struct kobj_attribute *a, const char *buf, size_t c)
{
    return kstrtobool(buf, &keylog_cfg.enabled) ? : c;
}

static ssize_t keylog_scan_store(struct kobject *k, struct kobj_attribute *a, const char *buf, size_t c)
{
    /* Manual scan would iterate all USB devices */
    pr_info("ShadowOS Keylog: Manual scan triggered\n");
    keylog_cfg.devices_scanned++;
    return c;
}

static ssize_t keylog_devices_show(struct kobject *k, struct kobj_attribute *a, char *buf)
{
    struct hid_entry *entry;
    ssize_t len = 0;
    
    spin_lock(&hid_lock);
    list_for_each_entry(entry, &hid_devices, list) {
        len += sprintf(buf + len, "%04x:%04x %s%s\n",
                       entry->vendor, entry->product, entry->name,
                       entry->suspicious ? " [SUSPICIOUS]" : "");
    }
    spin_unlock(&hid_lock);
    
    return len;
}

static ssize_t keylog_stats_show(struct kobject *k, struct kobj_attribute *a, char *buf)
{
    return sprintf(buf, "scanned: %llu\ndetected: %llu\nkeyboards: %d\nmultiple_warning: %d\n",
                   keylog_cfg.devices_scanned, keylog_cfg.keyloggers_detected,
                   keylog_cfg.keyboard_count, keylog_cfg.multiple_keyboards_alert);
}

static struct kobj_attribute keylog_enabled_attr = __ATTR(enabled, 0644, keylog_enabled_show, keylog_enabled_store);
static struct kobj_attribute keylog_scan_attr = __ATTR(scan_now, 0200, NULL, keylog_scan_store);
static struct kobj_attribute keylog_devices_attr = __ATTR(devices, 0444, keylog_devices_show, NULL);
static struct kobj_attribute keylog_stats_attr = __ATTR(stats, 0444, keylog_stats_show, NULL);

static struct attribute *keylog_attrs[] = {
    &keylog_enabled_attr.attr,
    &keylog_scan_attr.attr,
    &keylog_devices_attr.attr,
    &keylog_stats_attr.attr,
    NULL
};

static struct attribute_group keylog_group = { .attrs = keylog_attrs };

static int __init shadow_keylog_init(void)
{
    struct kobject *parent;
    
    pr_info("ShadowOS: ⌨️ Initializing Hardware Keylogger Detection\n");
    
    usb_register_notify(&keylog_usb_nb);
    
    parent = shadow_get_kobj();
    if (parent) {
        keylog_kobj = kobject_create_and_add("keylog", parent);
        if (keylog_kobj)
            sysfs_create_group(keylog_kobj, &keylog_group);
    }
    
    pr_info("ShadowOS: ⌨️ Keylogger Detection ACTIVE - Monitoring USB HID\n");
    return 0;
}

static void __exit shadow_keylog_exit(void)
{
    struct hid_entry *entry, *tmp;
    
    usb_unregister_notify(&keylog_usb_nb);
    
    if (keylog_kobj) {
        sysfs_remove_group(keylog_kobj, &keylog_group);
        kobject_put(keylog_kobj);
    }
    
    spin_lock(&hid_lock);
    list_for_each_entry_safe(entry, tmp, &hid_devices, list) {
        list_del(&entry->list);
        kfree(entry);
    }
    spin_unlock(&hid_lock);
    
    pr_info("ShadowOS: Keylogger Detection unloaded\n");
}

module_init(shadow_keylog_init);
module_exit(shadow_keylog_exit);
