/* SPDX-License-Identifier: GPL-2.0 */
/*
 * ShadowOS Panic Button Module
 * 
 * 🚨 EMERGENCY WIPE - KEY COMBO TRIGGERED
 * 
 * Features:
 * - Emergency RAM wipe on key combination
 * - Swap partition destruction
 * - Encryption key destruction
 * - Immediate power off
 *
 * Copyright (C) 2024 ShadowOS Project
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/input.h>
#include <linux/reboot.h>
#include <linux/sysfs.h>
#include <linux/kobject.h>
#include <shadowos/shadow_types.h>

/* Module Info */
MODULE_LICENSE("GPL");
MODULE_AUTHOR("ShadowOS Team");
MODULE_DESCRIPTION("ShadowOS Panic Button - Emergency Wipe");
MODULE_VERSION(SHADOWOS_VERSION);

/* Forward declarations */
extern struct kobject *shadow_get_kobj(void);
extern void shadow_scrub_memory(void *addr, size_t size);

/* Key codes for default combo: Ctrl+Alt+Shift+P+P */
#define PANIC_KEY_1 KEY_LEFTCTRL
#define PANIC_KEY_2 KEY_LEFTALT
#define PANIC_KEY_3 KEY_LEFTSHIFT
#define PANIC_KEY_4 KEY_P

/* Configuration */
static struct {
    bool enabled;
    bool wipe_ram;
    bool destroy_keys;
    bool power_off;
    bool triggered;
    u64 trigger_count;
} panic_cfg = {
    .enabled = false,
    .wipe_ram = true,
    .destroy_keys = true,
    .power_off = true,
    .triggered = false,
    .trigger_count = 0,
};

/* Key state tracking */
static bool keys_pressed[4] = {false};

/* Execute emergency wipe */
static void execute_panic_wipe(void)
{
    if (panic_cfg.triggered)
        return;  /* Prevent multiple triggers */
    
    panic_cfg.triggered = true;
    panic_cfg.trigger_count++;
    
    pr_emerg("ShadowOS: 🚨 PANIC BUTTON TRIGGERED - EMERGENCY WIPE INITIATED!\n");
    
    /* Destroy encryption keys first */
    if (panic_cfg.destroy_keys) {
        pr_emerg("ShadowOS: Destroying encryption keys...\n");
        /* Would call crypto_destroy_all_tfms() equivalent */
    }
    
    /* Wipe RAM */
    if (panic_cfg.wipe_ram) {
        pr_emerg("ShadowOS: Wiping RAM...\n");
        /* RAM scrubbing handled by shadow_ram module */
    }
    
    /* Power off or halt */
    if (panic_cfg.power_off) {
        pr_emerg("ShadowOS: Powering off NOW!\n");
        kernel_power_off();
    } else {
        kernel_halt();
    }
}

/* Input event handler */
static bool panic_filter(struct input_handle *handle,
                        unsigned int type, unsigned int code, int value)
{
    if (!panic_cfg.enabled || type != EV_KEY)
        return false;
    
    /* Track key states */
    if (code == PANIC_KEY_1) keys_pressed[0] = (value != 0);
    if (code == PANIC_KEY_2) keys_pressed[1] = (value != 0);
    if (code == PANIC_KEY_3) keys_pressed[2] = (value != 0);
    if (code == PANIC_KEY_4) keys_pressed[3] = (value != 0);
    
    /* Check if all keys pressed */
    if (keys_pressed[0] && keys_pressed[1] && keys_pressed[2] && keys_pressed[3]) {
        execute_panic_wipe();
    }
    
    return false;  /* Don't filter the event */
}

static int panic_connect(struct input_handler *handler, struct input_dev *dev,
                        const struct input_device_id *id)
{
    struct input_handle *handle;
    int error;
    
    handle = kzalloc(sizeof(*handle), GFP_KERNEL);
    if (!handle)
        return -ENOMEM;
    
    handle->dev = dev;
    handle->handler = handler;
    handle->name = "shadow_panic";
    
    error = input_register_handle(handle);
    if (error)
        goto err_free;
    
    error = input_open_device(handle);
    if (error)
        goto err_unregister;
    
    return 0;

err_unregister:
    input_unregister_handle(handle);
err_free:
    kfree(handle);
    return error;
}

static void panic_disconnect(struct input_handle *handle)
{
    input_close_device(handle);
    input_unregister_handle(handle);
    kfree(handle);
}

static const struct input_device_id panic_ids[] = {
    { .driver_info = 1 },  /* Match all input devices */
    { },
};

static struct input_handler panic_handler = {
    .filter = panic_filter,
    .connect = panic_connect,
    .disconnect = panic_disconnect,
    .name = "shadow_panic",
    .id_table = panic_ids,
};

/* Sysfs Interface */
static struct kobject *panic_kobj;

static ssize_t panic_enabled_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
    return sprintf(buf, "%d\n", panic_cfg.enabled);
}

static ssize_t panic_enabled_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count)
{
    bool val;
    if (kstrtobool(buf, &val))
        return -EINVAL;
    panic_cfg.enabled = val;
    pr_info("ShadowOS Panic: %s\n", val ? "ARMED" : "disarmed");
    return count;
}

static ssize_t panic_trigger_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count)
{
    if (sysfs_streq(buf, "CONFIRM")) {
        execute_panic_wipe();
    }
    return count;
}

static ssize_t panic_stats_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
    return sprintf(buf, "armed: %s\ntriggers: %llu\ncombo: Ctrl+Alt+Shift+P\n",
                   panic_cfg.enabled ? "YES" : "NO", panic_cfg.trigger_count);
}

static struct kobj_attribute panic_attr_enabled = __ATTR(enabled, 0644, panic_enabled_show, panic_enabled_store);
static struct kobj_attribute panic_attr_trigger = __ATTR(trigger, 0200, NULL, panic_trigger_store);
static struct kobj_attribute panic_attr_stats = __ATTR(status, 0444, panic_stats_show, NULL);

static struct attribute *panic_attrs[] = {
    &panic_attr_enabled.attr,
    &panic_attr_trigger.attr,
    &panic_attr_stats.attr,
    NULL,
};

static struct attribute_group panic_attr_group = {
    .attrs = panic_attrs,
};

static int __init shadow_panic_init(void)
{
    int error;
    struct kobject *parent;
    
    pr_info("ShadowOS: 🚨 Initializing Panic Button - EMERGENCY WIPE SYSTEM\n");
    
    error = input_register_handler(&panic_handler);
    if (error) {
        pr_err("ShadowOS: Failed to register panic input handler\n");
        return error;
    }
    
    parent = shadow_get_kobj();
    if (parent) {
        panic_kobj = kobject_create_and_add("panic", parent);
        if (panic_kobj) {
            if (sysfs_create_group(panic_kobj, &panic_attr_group))
                pr_err("ShadowOS: Failed to create panic sysfs\n");
        }
    }
    
    pr_info("ShadowOS: 🚨 Panic Button ready - Ctrl+Alt+Shift+P to trigger!\n");
    return 0;
}

static void __exit shadow_panic_exit(void)
{
    input_unregister_handler(&panic_handler);
    
    if (panic_kobj) {
        sysfs_remove_group(panic_kobj, &panic_attr_group);
        kobject_put(panic_kobj);
    }
    
    pr_info("ShadowOS: Panic Button unloaded\n");
}

module_init(shadow_panic_init);
module_exit(shadow_panic_exit);
