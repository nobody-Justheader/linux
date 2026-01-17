# ShadowOS Specification - Part 4

## Phase 6-7: Anti-Forensics & Offensive Tools

---

# PHASE 6: ANTI-FORENSICS

**Duration:** 3-4 weeks  
**Features:** 35

---

## 6.1 shadow_ram Module

### Purpose
Secure memory wiping on shutdown/trigger.

### Implementation

```c
// File: kernel/src/security/shadowos/shadow_ram.c

struct ram_config {
    bool scrub_on_shutdown;
    bool scrub_on_reboot;
    bool scrub_on_panic;
};

/* Memory scrubbing function */
static void shadow_ram_scrub(void)
{
    struct page *page;
    unsigned long pfn;
    void *addr;
    
    shadow_log(LOG_WARN, "RAM SCRUB INITIATED");
    
    /* Iterate all memory pages */
    for (pfn = 0; pfn < max_pfn; pfn++) {
        if (!pfn_valid(pfn))
            continue;
        
        page = pfn_to_page(pfn);
        
        /* Skip kernel text/data */
        if (PageReserved(page))
            continue;
        
        addr = kmap_atomic(page);
        memset(addr, 0, PAGE_SIZE);
        kunmap_atomic(addr);
    }
    
    shadow_log(LOG_WARN, "RAM SCRUB COMPLETE");
}

/* Hook into reboot/shutdown */
static int shadow_ram_reboot_notify(struct notifier_block *nb,
                                   unsigned long action, void *data)
{
    switch (action) {
        case SYS_RESTART:
            if (ram_cfg.scrub_on_reboot)
                shadow_ram_scrub();
            break;
        case SYS_HALT:
        case SYS_POWER_OFF:
            if (ram_cfg.scrub_on_shutdown)
                shadow_ram_scrub();
            break;
    }
    return NOTIFY_OK;
}
```

### sysfs Interface

```
/sys/kernel/shadowos/ram/
├── scrub_on_shutdown    # 0/1
├── scrub_on_reboot      # 0/1
├── scrub_now            # Write 1 to trigger (wo)
└── status               # "idle" or "scrubbing" (ro)
```

---

## 6.2 shadow_panic Module

### Purpose
Emergency wipe triggered by key combination.

### Implementation

```c
// File: kernel/src/security/shadowos/shadow_panic.c

struct panic_config {
    bool enabled;
    u16 key_combo[4];    /* Key codes for combo */
    bool wipe_ram;
    bool wipe_swap;
    bool destroy_keys;
    bool power_off;
};

/* Default: Alt + SysRq + X + X */
static u16 default_combo[] = {KEY_LEFTALT, KEY_SYSRQ, KEY_X, KEY_X};

/* Key state tracking */
static bool key_pressed[KEY_MAX];
static int combo_progress = 0;

/* Input event handler */
static void panic_input_event(struct input_handle *handle,
                             unsigned int type,
                             unsigned int code,
                             int value)
{
    if (type != EV_KEY)
        return;
    
    key_pressed[code] = (value != 0);
    
    /* Check combo progress */
    if (check_combo_complete()) {
        shadow_log(LOG_CRIT, "PANIC COMBO TRIGGERED");
        execute_panic_wipe();
    }
}

/* Execute emergency wipe */
static void execute_panic_wipe(void)
{
    /* 1. Wipe RAM */
    if (panic_cfg.wipe_ram)
        shadow_ram_scrub();
    
    /* 2. Wipe Swap */
    if (panic_cfg.wipe_swap)
        shadow_swap_wipe();
    
    /* 3. Destroy encryption keys */
    if (panic_cfg.destroy_keys)
        shadow_destroy_all_keys();
    
    /* 4. Power off or halt */
    if (panic_cfg.power_off)
        kernel_power_off();
    else
        kernel_halt();
}
```

### sysfs Interface

```
/sys/kernel/shadowos/panic/
├── enabled          # 0/1
├── key_combo        # "alt+sysrq+x+x" format (rw)
├── wipe_ram         # 0/1
├── wipe_swap        # 0/1
├── destroy_keys     # 0/1
├── power_off        # 0/1
└── trigger          # Write "CONFIRM" to trigger (wo)
```

---

## 6.3 shadow_cloak Module

### Purpose
Hide processes from /proc.

### Implementation

```c
// File: kernel/src/security/shadowos/shadow_cloak.c

struct cloak_config {
    bool enabled;
    struct list_head hidden_pids;
    struct list_head hidden_names;
};

/* Override proc readdir */
static int cloak_proc_readdir(struct file *file,
                             struct dir_context *ctx)
{
    /* Filter out hidden processes */
    struct cloaked_readdir_context cctx = {
        .real_ctx = ctx,
        .hidden_pids = &cloak_cfg.hidden_pids,
    };
    
    return original_proc_readdir(file, &cctx.ctx);
}

/* Check if PID should be hidden */
static bool is_pid_hidden(pid_t pid)
{
    struct hidden_pid *hp;
    
    list_for_each_entry(hp, &cloak_cfg.hidden_pids, list) {
        if (hp->pid == pid)
            return true;
    }
    
    /* Check by name */
    struct task_struct *task = find_task_by_vpid(pid);
    if (task) {
        struct hidden_name *hn;
        list_for_each_entry(hn, &cloak_cfg.hidden_names, list) {
            if (strstr(task->comm, hn->pattern))
                return true;
        }
    }
    
    return false;
}

/* Override /proc/[pid] access */
static struct dentry *cloak_proc_lookup(struct inode *dir,
                                       struct dentry *dentry,
                                       unsigned int flags)
{
    pid_t pid;
    
    if (kstrtoint(dentry->d_name.name, 10, &pid) == 0) {
        if (is_pid_hidden(pid))
            return ERR_PTR(-ENOENT);
    }
    
    return original_proc_lookup(dir, dentry, flags);
}
```

### sysfs Interface

```
/sys/kernel/shadowos/cloak/
├── enabled          # 0/1
├── hide_pid         # Write PID to hide (wo)
├── unhide_pid       # Write PID to unhide (wo)
├── hide_name        # Pattern to hide (wo)
├── hidden_count     # Number hidden (ro)
└── list             # List of hidden (ro, requires auth)
```

---

## 6.4 shadow_honey Module

### Purpose
Honeytokens and decoy files.

### Implementation

```c
// File: kernel/src/security/shadowos/shadow_honey.c

struct honeytoken {
    char path[256];
    bool alert_on_read;
    bool alert_on_stat;
    bool log_accessor;
    struct list_head list;
};

/* Hook file open */
static int honey_open_check(struct file *file)
{
    const char *path = file->f_path.dentry->d_name.name;
    struct honeytoken *ht;
    
    list_for_each_entry(ht, &honey_cfg.tokens, list) {
        if (path_matches(path, ht->path)) {
            /* ALERT! Honeytoken accessed! */
            struct task_struct *task = current;
            
            shadow_alert(ALERT_HONEY_TRIGGERED,
                        "Honeytoken accessed: %s by %s (pid %d, uid %d)",
                        path, task->comm, task->pid, 
                        from_kuid(&init_user_ns, task->cred->uid));
            
            if (ht->log_accessor)
                log_full_process_info(task);
            
            break;
        }
    }
    
    return 0;  /* Allow access (we want to observe) */
}

/* Pre-created honeytokens */
static const char *default_honeytokens[] = {
    "/home/*/passwords.txt",
    "/home/*/.ssh/id_rsa_backup",
    "/root/.bash_history_backup",
    "/etc/shadow.bak",
    "/var/backups/mysql_passwords.txt",
};
```

---

# PHASE 7: OFFENSIVE TOOLS

**Duration:** 2-3 weeks  
**Features:** 25

---

## 7.1 shadow_inject Module

### Purpose
Kernel-level raw packet injection.

### Implementation

```c
// File: kernel/src/net/shadowos/shadow_inject.c

/* Inject raw packet */
int shadow_inject_packet(struct net_device *dev,
                        void *data, size_t len,
                        int protocol)
{
    struct sk_buff *skb;
    
    skb = alloc_skb(len + NET_IP_ALIGN, GFP_KERNEL);
    if (!skb)
        return -ENOMEM;
    
    skb_reserve(skb, NET_IP_ALIGN);
    skb_put_data(skb, data, len);
    
    skb->dev = dev;
    skb->protocol = htons(protocol);
    
    return dev_queue_xmit(skb);
}

/* Userspace interface via netlink */
static int inject_nl_cmd(struct sk_buff *skb, struct genl_info *info)
{
    struct net_device *dev;
    void *data;
    size_t len;
    
    /* Extract parameters from netlink message */
    dev = dev_get_by_name(&init_net, 
                         nla_data(info->attrs[INJECT_ATTR_IFACE]));
    data = nla_data(info->attrs[INJECT_ATTR_DATA]);
    len = nla_len(info->attrs[INJECT_ATTR_DATA]);
    
    shadow_inject_packet(dev, data, len, ETH_P_IP);
    
    dev_put(dev);
    return 0;
}
```

---

## 7.2 shadow_promisc Module

### Purpose
Hide promiscuous mode from detection.

### Implementation

```c
// File: kernel/src/net/shadowos/shadow_promisc.c

/* Override interface flags reading */
static unsigned int promisc_hide_flags(struct net_device *dev)
{
    unsigned int flags = dev->flags;
    
    if (promisc_cfg.hide_enabled)
        flags &= ~IFF_PROMISC;  /* Remove PROMISC flag */
    
    return flags;
}

/* Hook /proc/net/dev reading */
static int promisc_proc_show(struct seq_file *m, void *v)
{
    /* Show device without PROMISC flag */
    struct net_device *dev = v;
    unsigned int flags = promisc_hide_flags(dev);
    
    /* Original output but with modified flags */
    seq_printf(m, "%6s: ...", dev->name);
    
    return 0;
}
```

---

## 7.3 shadow_mac Module

### Purpose
Automatic MAC address rotation.

### Implementation

```c
// File: kernel/src/net/shadowos/shadow_mac.c

struct mac_config {
    bool rotation_enabled;
    u32 interval_minutes;
    bool preserve_oui;       /* Keep first 3 bytes */
    bool randomize_on_boot;
};

/* Rotate MAC address */
static int rotate_mac(struct net_device *dev)
{
    u8 new_mac[ETH_ALEN];
    
    if (mac_cfg.preserve_oui) {
        /* Keep vendor prefix */
        memcpy(new_mac, dev->dev_addr, 3);
        get_random_bytes(new_mac + 3, 3);
    } else {
        /* Fully random (locally administered) */
        get_random_bytes(new_mac, ETH_ALEN);
        new_mac[0] &= 0xFE;  /* Unicast */
        new_mac[0] |= 0x02;  /* Locally administered */
    }
    
    dev_set_mac_address(dev, new_mac);
    
    shadow_log(LOG_INFO, "%s: MAC rotated to %pM", dev->name, new_mac);
    shadow_alert(ALERT_MAC_ROTATED, "%s: %pM", dev->name, new_mac);
    
    return 0;
}

/* Timer for automatic rotation */
static void mac_rotation_timer(struct timer_list *t)
{
    struct net_device *dev;
    
    for_each_netdev(&init_net, dev) {
        if (is_rotation_enabled(dev))
            rotate_mac(dev);
    }
    
    mod_timer(t, jiffies + msecs_to_jiffies(mac_cfg.interval_minutes * 60000));
}
```

---

## Phase 6-7 Feature Summary

| # | Feature | Module | Status |
|---|---------|--------|--------|
| 57 | RAM scrub shutdown | shadow_ram | Spec ✓ |
| 58 | RAM scrub reboot | shadow_ram | Spec ✓ |
| 59 | Manual RAM scrub | shadow_ram | Spec ✓ |
| 60 | Panic key combo | shadow_panic | Spec ✓ |
| 61 | Panic RAM wipe | shadow_panic | Spec ✓ |
| 62 | Panic swap wipe | shadow_panic | Spec ✓ |
| 63 | Panic key destroy | shadow_panic | Spec ✓ |
| 64 | PID hiding | shadow_cloak | Spec ✓ |
| 65 | Process name hiding | shadow_cloak | Spec ✓ |
| 66 | Honeytoken files | shadow_honey | Spec ✓ |
| 67 | Honeytoken alerts | shadow_honey | Spec ✓ |
| 68 | Raw packet inject | shadow_inject | Spec ✓ |
| 69 | Promisc hiding | shadow_promisc | Spec ✓ |
| 70 | MAC rotation | shadow_mac | Spec ✓ |
| 71 | Rotation scheduling | shadow_mac | Spec ✓ |
| 72 | OUI preservation | shadow_mac | Spec ✓ |
