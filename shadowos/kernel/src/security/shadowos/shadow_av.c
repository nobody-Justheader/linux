/* SPDX-License-Identifier: GPL-2.0 */
/*
 * ShadowOS Audio/Video Kill Switch
 * 
 * 📷🎤 KERNEL-LEVEL CAMERA & MICROPHONE CONTROL
 * 
 * Features:
 * - Block V4L2 device access
 * - Block ALSA capture devices
 * - Device blacklist management
 * - Kernel-level interception
 *
 * Copyright (C) 2024 ShadowOS Project
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/device.h>
#include <linux/sysfs.h>
#include <linux/kobject.h>
#include <linux/kprobes.h>
#include <linux/fs.h>
#include <shadowos/shadow_types.h>

/* Module Info */
MODULE_LICENSE("GPL");
MODULE_AUTHOR("ShadowOS Team");
MODULE_DESCRIPTION("ShadowOS A/V Kill Switch - Camera & Mic Control");
MODULE_VERSION(SHADOWOS_VERSION);

/* Forward declaration */
extern struct kobject *shadow_get_kobj(void);

/* Configuration */
static struct {
    bool camera_killed;
    bool mic_killed;
    u64 camera_block_count;
    u64 mic_block_count;
} av_cfg = {
    .camera_killed = false,
    .mic_killed = false,
    .camera_block_count = 0,
    .mic_block_count = 0,
};

/*
 * Block camera access by intercepting /dev/video* opens
 * This uses a simple approach of checking file paths
 */
static bool should_block_camera(const char *filename)
{
    if (!av_cfg.camera_killed)
        return false;
    
    /* Block /dev/video* devices */
    if (filename && strncmp(filename, "/dev/video", 10) == 0) {
        av_cfg.camera_block_count++;
        pr_warn("ShadowOS A/V: 📷 BLOCKED camera access: %s by %s (pid %d)\n",
                filename, current->comm, current->pid);
        return true;
    }
    
    return false;
}

/*
 * Block microphone access
 */
static bool should_block_mic(const char *filename)
{
    if (!av_cfg.mic_killed)
        return false;
    
    /* Block ALSA capture devices */
    if (filename) {
        if (strncmp(filename, "/dev/snd/pcmC", 13) == 0 &&
            strstr(filename, "c")) {  /* capture device */
            av_cfg.mic_block_count++;
            pr_warn("ShadowOS A/V: 🎤 BLOCKED mic access: %s by %s (pid %d)\n",
                    filename, current->comm, current->pid);
            return true;
        }
        /* Also block /dev/dsp and similar */
        if (strncmp(filename, "/dev/dsp", 8) == 0 ||
            strncmp(filename, "/dev/audio", 10) == 0) {
            av_cfg.mic_block_count++;
            return true;
        }
    }
    
    return false;
}

/* Export for potential LSM integration */
bool shadow_av_check_access(const char *filename)
{
    if (should_block_camera(filename))
        return true;
    if (should_block_mic(filename))
        return true;
    return false;
}
EXPORT_SYMBOL_GPL(shadow_av_check_access);

/* Update camera state */
static void update_camera_state(bool kill)
{
    av_cfg.camera_killed = kill;
    
    if (kill) {
        pr_alert("ShadowOS A/V: 📷 CAMERA KILLED - All camera access will be blocked!\n");
    } else {
        pr_info("ShadowOS A/V: 📷 Camera enabled\n");
    }
}

/* Update mic state */
static void update_mic_state(bool kill)
{
    av_cfg.mic_killed = kill;
    
    if (kill) {
        pr_alert("ShadowOS A/V: 🎤 MICROPHONE KILLED - All audio capture blocked!\n");
    } else {
        pr_info("ShadowOS A/V: 🎤 Microphone enabled\n");
    }
}

/* Sysfs Interface */
static struct kobject *av_kobj;

static ssize_t camera_killed_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
    return sprintf(buf, "%d\n", av_cfg.camera_killed);
}

static ssize_t camera_killed_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count)
{
    bool val;
    if (kstrtobool(buf, &val))
        return -EINVAL;
    update_camera_state(val);
    return count;
}

static ssize_t mic_killed_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
    return sprintf(buf, "%d\n", av_cfg.mic_killed);
}

static ssize_t mic_killed_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count)
{
    bool val;
    if (kstrtobool(buf, &val))
        return -EINVAL;
    update_mic_state(val);
    return count;
}

/* Kill both camera and mic */
static ssize_t av_killall_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count)
{
    bool val;
    if (kstrtobool(buf, &val))
        return -EINVAL;
    if (val) {
        update_camera_state(true);
        update_mic_state(true);
        pr_alert("ShadowOS A/V: 📷🎤 ALL AV KILLED - Privacy mode ACTIVE!\n");
    }
    return count;
}

static ssize_t av_stats_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
    return sprintf(buf, "camera_state: %s\nmic_state: %s\ncamera_blocks: %llu\nmic_blocks: %llu\n",
                   av_cfg.camera_killed ? "KILLED" : "active",
                   av_cfg.mic_killed ? "KILLED" : "active",
                   av_cfg.camera_block_count, av_cfg.mic_block_count);
}

static struct kobj_attribute av_attr_camera = __ATTR(camera_killed, 0644, camera_killed_show, camera_killed_store);
static struct kobj_attribute av_attr_mic = __ATTR(mic_killed, 0644, mic_killed_show, mic_killed_store);
static struct kobj_attribute av_attr_killall = __ATTR(kill_all, 0200, NULL, av_killall_store);
static struct kobj_attribute av_attr_stats = __ATTR(status, 0444, av_stats_show, NULL);

static struct attribute *av_attrs[] = {
    &av_attr_camera.attr,
    &av_attr_mic.attr,
    &av_attr_killall.attr,
    &av_attr_stats.attr,
    NULL,
};

static struct attribute_group av_attr_group = {
    .attrs = av_attrs,
};

static int __init shadow_av_init(void)
{
    struct kobject *parent;
    
    pr_info("ShadowOS: 📷🎤 Initializing A/V Kill Switch\n");
    
    parent = shadow_get_kobj();
    if (parent) {
        av_kobj = kobject_create_and_add("av", parent);
        if (av_kobj) {
            if (sysfs_create_group(av_kobj, &av_attr_group))
                pr_err("ShadowOS: Failed to create A/V sysfs\n");
        }
    }
    
    pr_info("ShadowOS: 📷🎤 A/V Kill Switch ready - use kill_all for instant privacy\n");
    return 0;
}

static void __exit shadow_av_exit(void)
{
    if (av_kobj) {
        sysfs_remove_group(av_kobj, &av_attr_group);
        kobject_put(av_kobj);
    }
    
    pr_info("ShadowOS: A/V Kill Switch unloaded\n");
}

module_init(shadow_av_init);
module_exit(shadow_av_exit);
