# ShadowOS Specification - Part 3

## Phase 4-5: Hardware Control & Storage Security

---

# PHASE 4: HARDWARE CONTROL

**Duration:** 2-3 weeks  
**Features:** 25

---

## 4.1 shadow_usb Module

### Purpose
USB device firewall with whitelist.

### Technical Specification

```c
// File: kernel/src/security/shadowos/shadow_usb.c

struct usb_rule {
    u16 vendor_id;
    u16 product_id;
    u8 device_class;
    char serial[64];
    bool allow;
    struct list_head list;
};

struct usb_config {
    bool enabled;
    bool block_storage;     /* Block mass storage class */
    bool block_hid_new;     /* Block new HID devices */
    bool log_connections;
    struct list_head whitelist;
};

/* USB Notification Callback */
static int shadow_usb_notify(struct notifier_block *nb,
                            unsigned long action, void *data)
{
    struct usb_device *udev = data;
    
    switch (action) {
        case USB_DEVICE_ADD:
            return shadow_usb_check_device(udev);
        case USB_DEVICE_REMOVE:
            shadow_log(LOG_INFO, "USB removed: %04x:%04x",
                      udev->descriptor.idVendor,
                      udev->descriptor.idProduct);
            break;
    }
    return NOTIFY_OK;
}

/* Check if device is allowed */
static int shadow_usb_check_device(struct usb_device *udev)
{
    u16 vid = udev->descriptor.idVendor;
    u16 pid = udev->descriptor.idProduct;
    u8 class = udev->descriptor.bDeviceClass;
    
    /* Block mass storage if configured */
    if (usb_cfg.block_storage && class == USB_CLASS_MASS_STORAGE) {
        shadow_alert(ALERT_USB_BLOCKED, "Mass storage blocked: %04x:%04x", vid, pid);
        return NOTIFY_BAD;  /* Reject device */
    }
    
    /* Check whitelist */
    if (!is_whitelisted(vid, pid)) {
        shadow_alert(ALERT_USB_BLOCKED, "Unknown device blocked: %04x:%04x", vid, pid);
        return NOTIFY_BAD;
    }
    
    shadow_log(LOG_INFO, "USB allowed: %04x:%04x", vid, pid);
    return NOTIFY_OK;
}
```

### BadUSB Detection

```c
/* Detect suspicious USB behavior */
struct badusb_indicators {
    bool keyboard_after_storage;  /* Storage device registers as keyboard */
    bool rapid_hid_injection;     /* Fast keyboard events on connect */
    bool vid_pid_clone;           /* Known cloned device IDs */
};

static bool detect_badusb(struct usb_device *udev)
{
    /* Check for known BadUSB signatures */
    if (is_known_badusb_signature(udev))
        return true;
    
    /* Check for suspicious timing */
    if (is_rapid_hid_injection(udev))
        return true;
    
    return false;
}
```

### sysfs Interface

```
/sys/kernel/shadowos/usb/
├── enabled          # 0/1
├── block_storage    # 0/1
├── block_new_hid    # 0/1
├── whitelist        # "VID:PID\n" format (rw)
├── connected        # Currently connected devices (ro)
└── log              # Connection log (ro)
```

---

## 4.2 shadow_av Module

### Purpose
Kernel-level camera/microphone kill switch.

### Implementation

```c
// File: kernel/src/security/shadowos/shadow_av.c

struct av_config {
    bool camera_killed;
    bool mic_killed;
};

/* Camera Kill - Unbind from driver */
static int kill_camera(bool kill)
{
    struct device *dev;
    
    /* Find all video devices */
    class_for_each_device(video_class, NULL, NULL, kill_video_device);
    
    if (kill) {
        /* Block V4L2 access at syscall level */
        shadow_syscall_filter_add(SYS_open, "/dev/video*", DENY);
        shadow_log(LOG_INFO, "Camera killed");
    } else {
        shadow_syscall_filter_remove(SYS_open, "/dev/video*");
        shadow_log(LOG_INFO, "Camera enabled");
    }
    return 0;
}

/* Microphone Kill */
static int kill_microphone(bool kill)
{
    if (kill) {
        /* Mute ALSA capture */
        snd_ctl_elem_mute_all_capture();
        /* Block /dev/snd access for capture */
        shadow_syscall_filter_add(SYS_open, "/dev/snd/pcmC*c", DENY);
        shadow_log(LOG_INFO, "Microphone killed");
    } else {
        snd_ctl_elem_unmute_all_capture();
        shadow_syscall_filter_remove(SYS_open, "/dev/snd/pcmC*c");
        shadow_log(LOG_INFO, "Microphone enabled");
    }
    return 0;
}
```

### sysfs Interface

```
/sys/kernel/shadowos/av/
├── camera_killed    # 0/1 (rw)
├── mic_killed       # 0/1 (rw)
├── camera_devices   # List of camera devices (ro)
└── audio_devices    # List of audio capture devices (ro)
```

---

## 4.3 shadow_bt Module

### Purpose
Bluetooth stack control.

```c
struct bt_config {
    bool enabled;           /* Bluetooth stack enabled */
    bool discoverable;      /* Allow discovery */
    bool pairing;           /* Allow new pairings */
    struct list_head paired_devices;
};

static int bt_set_enabled(bool enable)
{
    if (!enable) {
        /* Disable Bluetooth at HCI level */
        hci_dev_close_all();
        shadow_log(LOG_INFO, "Bluetooth disabled");
    } else {
        hci_dev_open_all();
        shadow_log(LOG_INFO, "Bluetooth enabled");
    }
    return 0;
}
```

---

# PHASE 5: STORAGE SECURITY

**Duration:** 3-4 weeks  
**Features:** 30

---

## 5.1 shadow_shred Module

### Purpose
Secure file deletion with overwrite.

### Implementation

```c
// File: kernel/src/security/shadowos/shadow_shred.c

struct shred_config {
    bool enabled;
    u8 passes;           /* Number of overwrite passes */
    bool obfuscate_name; /* Rename before delete */
};

/* Patterns for overwrite */
static const u8 shred_patterns[] = {
    0x00,  /* Pass 1: Zeros */
    0xFF,  /* Pass 2: Ones */
    0x55,  /* Pass 3: 01010101 */
    0xAA,  /* Pass 4: 10101010 */
    0x92,  /* Pass 5: Random-ish */
    0x49,  /* Pass 6: Random-ish */
    0x24,  /* Pass 7: Random-ish */
};

/* Hook into unlink syscall */
static int shadow_shred_unlink(struct path *path)
{
    struct file *file;
    struct inode *inode;
    loff_t size;
    
    if (!shred_cfg.enabled)
        return 0;  /* Pass to normal unlink */
    
    inode = path->dentry->d_inode;
    if (!S_ISREG(inode->i_mode))
        return 0;  /* Only regular files */
    
    size = i_size_read(inode);
    
    /* Open file for writing */
    file = dentry_open(path, O_WRONLY, current_cred());
    if (IS_ERR(file))
        return 0;
    
    /* Overwrite with patterns */
    for (int pass = 0; pass < shred_cfg.passes; pass++) {
        shred_overwrite(file, size, shred_patterns[pass % 7]);
        vfs_fsync(file, 0);
    }
    
    /* Final random pass */
    shred_overwrite_random(file, size);
    vfs_fsync(file, 0);
    
    filp_close(file, NULL);
    
    /* Obfuscate filename */
    if (shred_cfg.obfuscate_name)
        shred_rename_random(path);
    
    shadow_log(LOG_DEBUG, "Shredded: %s (%lld bytes, %d passes)",
              path->dentry->d_name.name, size, shred_cfg.passes);
    
    return 0;  /* Continue with normal unlink */
}
```

### sysfs Interface

```
/sys/kernel/shadowos/shred/
├── enabled          # 0/1
├── passes           # 1-7
├── obfuscate_name   # 0/1
└── stats            # Files shredded count (ro)
```

---

## 5.2 shadow_stego Module

### Purpose
Hidden filesystem within unused disk space.

### Concept

```
Normal Disk View:
┌────────────────────────────────────────────────────────────┐
│ Partition 1 (/)  │ Partition 2 (/home) │   Unallocated    │
└────────────────────────────────────────────────────────────┘

Reality:
┌────────────────────────────────────────────────────────────┐
│ Partition 1 (/)  │ Partition 2 (/home) │ HIDDEN ENCRYPTED │
└────────────────────────────────────────────────────────────┘
                                         ↑
                                  Not visible in fdisk/lsblk
                                  Requires special unlock
```

### Implementation

```c
struct stego_config {
    bool unlocked;
    sector_t hidden_start;
    sector_t hidden_size;
    u8 key_hash[32];
};

/* Hide partition from block device enumeration */
static void stego_hide_partition(void)
{
    /* Remove from partition table in memory */
    /* Device still accessible via direct sector access */
}

/* Unlock with password */
static int stego_unlock(const char *password)
{
    u8 hash[32];
    
    sha256(password, strlen(password), hash);
    
    if (memcmp(hash, stego_cfg.key_hash, 32) != 0)
        return -EACCES;
    
    /* Create device mapper target for hidden partition */
    dm_create_target("shadow_hidden", stego_cfg.hidden_start,
                    stego_cfg.hidden_size);
    
    stego_cfg.unlocked = true;
    shadow_log(LOG_INFO, "Hidden partition unlocked");
    
    return 0;
}
```

---

## 5.3 shadow_meta Module

### Purpose
Automatic metadata scrubbing.

### Implementation

```c
/* Metadata types to scrub */
struct meta_scrub_rules {
    bool exif;          /* Image EXIF data */
    bool pdf_metadata;  /* PDF author, timestamps */
    bool office_meta;   /* Office document metadata */
    bool audio_tags;    /* MP3/FLAC tags */
    bool file_times;    /* Randomize atime/mtime */
};

/* Scrub on file close */
static int meta_scrub_release(struct inode *inode, struct file *file)
{
    const char *mime = get_mime_type(file);
    
    if (strstr(mime, "image/")) {
        scrub_exif(file);
    } else if (strstr(mime, "application/pdf")) {
        scrub_pdf_metadata(file);
    } else if (strstr(mime, "audio/")) {
        scrub_audio_tags(file);
    }
    
    if (meta_cfg.file_times)
        randomize_timestamps(inode);
    
    return 0;
}
```

---

## Phase 4-5 Feature Summary

| # | Feature | Module | Status |
|---|---------|--------|--------|
| 41 | USB whitelist | shadow_usb | Spec ✓ |
| 42 | Block mass storage | shadow_usb | Spec ✓ |
| 43 | BadUSB detection | shadow_usb | Spec ✓ |
| 44 | USB logging | shadow_usb | Spec ✓ |
| 45 | Camera kill | shadow_av | Spec ✓ |
| 46 | Microphone kill | shadow_av | Spec ✓ |
| 47 | Bluetooth disable | shadow_bt | Spec ✓ |
| 48 | BT pairing control | shadow_bt | Spec ✓ |
| 49 | Secure delete | shadow_shred | Spec ✓ |
| 50 | Multi-pass overwrite | shadow_shred | Spec ✓ |
| 51 | Filename obfuscation | shadow_shred | Spec ✓ |
| 52 | Hidden partition | shadow_stego | Spec ✓ |
| 53 | Partition unlock | shadow_stego | Spec ✓ |
| 54 | EXIF scrubbing | shadow_meta | Spec ✓ |
| 55 | PDF metadata scrub | shadow_meta | Spec ✓ |
| 56 | Timestamp randomize | shadow_meta | Spec ✓ |
