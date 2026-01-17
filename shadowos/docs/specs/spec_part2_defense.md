# ShadowOS Specification - Part 2

## Phase 2-3: Active Defense & Network Security

---

# PHASE 2: ACTIVE DEFENSE

**Duration:** 3-4 weeks  
**Features:** 40  
**Goal:** Kernel-level deception and counterattack

---

## 2.1 shadow_chaos Module

### Purpose
Protocol-level chaos to confuse fingerprinting tools.

### Technical Specification

```c
// File: kernel/src/net/shadowos/shadow_chaos.c

struct chaos_config {
    bool enabled;
    bool ttl_chaos;          // Random TTL per connection
    bool window_chaos;       // Random window size
    bool timestamp_chaos;    // Manipulate TCP timestamps
    bool options_chaos;      // Random TCP options
    bool rst_chaos;          // Random RST behavior
    u32 jitter_min_ms;       // Minimum response delay
    u32 jitter_max_ms;       // Maximum response delay
};

/* TTL Randomization */
static u8 chaos_get_ttl(void) {
    static const u8 ttls[] = {32, 64, 128, 255};
    return ttls[prandom_u32() % ARRAY_SIZE(ttls)];
}

/* Window Size Chaos */
static u16 chaos_get_window(void) {
    static const u16 windows[] = {
        5840,   // Linux default
        8192,   // BSD
        16384,  // Older Windows
        65535,  // Windows 10
        29200,  // Linux modern
    };
    return windows[prandom_u32() % ARRAY_SIZE(windows)];
}
```

### Netfilter Hooks

```c
/* Hook into outgoing packets */
static unsigned int chaos_hook_out(void *priv,
                                   struct sk_buff *skb,
                                   const struct nf_hook_state *state)
{
    struct iphdr *iph = ip_hdr(skb);
    struct tcphdr *tcph;
    
    if (iph->protocol != IPPROTO_TCP)
        return NF_ACCEPT;
    
    tcph = tcp_hdr(skb);
    
    if (chaos_cfg.ttl_chaos)
        iph->ttl = chaos_get_ttl();
    
    if (chaos_cfg.window_chaos)
        tcph->window = htons(chaos_get_window());
    
    /* Recalculate checksums */
    iph->check = 0;
    iph->check = ip_fast_csum(iph, iph->ihl);
    
    return NF_ACCEPT;
}
```

### sysfs Interface

```
/sys/kernel/shadowos/chaos/
├── enabled          # 0/1
├── ttl              # 0/1
├── window           # 0/1
├── timestamps       # 0/1
├── options          # 0/1
├── rst_random       # 0/1
├── jitter_min_ms    # 0-1000
└── jitter_max_ms    # 0-1000
```

---

## 2.2 shadow_phantom Module

### Purpose
Fake services on closed ports.

### Banner Database

```c
// File: kernel/src/net/shadowos/shadow_phantom.c

struct phantom_service {
    u16 port;
    const char *banner;
    u16 banner_len;
    u32 delay_ms;
    bool tarpit;
};

static struct phantom_service phantoms[] = {
    /* SSH */
    {22, "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3\r\n", 33, 100, false},
    {22, "SSH-2.0-dropbear_2022.83\r\n", 27, 80, false},
    
    /* HTTP */
    {80, "HTTP/1.1 200 OK\r\nServer: Apache/2.4.52\r\n\r\n", 43, 50, false},
    {80, "HTTP/1.1 200 OK\r\nServer: nginx/1.22.0\r\n\r\n", 42, 50, false},
    {80, "HTTP/1.1 200 OK\r\nServer: Microsoft-IIS/10.0\r\n\r\n", 47, 100, false},
    
    /* Telnet Tarpits */
    {23, "\r\nCisco IOS\r\nUser Access Verification\r\nUsername: ", 48, 500, true},
    {23, "\r\nMikroTik v6.49\r\nLogin: ", 25, 500, true},
    
    /* Windows Services - Tarpits */
    {445, NULL, 0, 200, true},   /* SMB - never respond */
    {3389, NULL, 0, 300, true},  /* RDP - never respond */
    {135, NULL, 0, 200, true},   /* RPC - never respond */
    
    /* Databases */
    {3306, "J\x00\x00\x00\x0a" "5.7.38-log\x00", 15, 100, false},
    {5432, "PostgreSQL 14.5\x00", 16, 100, false},
    {27017, "MongoDB 5.0\x00", 12, 100, false},
    
    /* Mail */
    {25, "220 mail.example.com ESMTP ready\r\n", 34, 150, false},
    {110, "+OK POP3 ready\r\n", 16, 100, false},
    
    /* FTP */
    {21, "220 ProFTPD 1.3.7 Server ready\r\n", 32, 100, false},
};
```

### Connection Handling

```c
/* Handle incoming SYN to closed port */
static void phantom_handle_syn(struct sk_buff *skb, 
                               struct phantom_service *svc)
{
    if (svc->tarpit) {
        /* Send SYN-ACK but never complete handshake */
        phantom_send_synack(skb);
        /* Connection will hang forever */
    } else {
        /* Normal phantom: complete handshake, send banner */
        phantom_send_synack(skb);
        schedule_delayed_work(&banner_work, 
                             msecs_to_jiffies(svc->delay_ms));
    }
}
```

---

## 2.3 shadow_flux Module

### Purpose
Per-connection identity changes.

### OS Profiles

```c
struct os_profile {
    char name[32];
    u8 ttl;
    u16 window;
    u16 mss;
    u8 df_bit;
    u8 sack_ok;
    u8 timestamps;
    u8 window_scale;
    u8 nop_pattern[8];
};

static struct os_profile profiles[] = {
    {"windows_10", 128, 65535, 1460, 1, 1, 1, 8, {1,1,1,1}},
    {"windows_server", 128, 65535, 1460, 1, 1, 1, 8, {1,1,1,1}},
    {"linux_5", 64, 29200, 1460, 1, 1, 1, 7, {1,1,1}},
    {"linux_4", 64, 29200, 1460, 1, 1, 1, 7, {1,1,1}},
    {"macos_13", 64, 65535, 1460, 1, 1, 1, 6, {1,1}},
    {"freebsd_13", 64, 65535, 1460, 1, 1, 1, 6, {1}},
    {"cisco_ios", 255, 4128, 536, 0, 0, 0, 0, {}},
    {"juniper", 64, 16384, 1460, 1, 0, 0, 0, {}},
    {"printer", 64, 8192, 1460, 0, 0, 0, 0, {}},
    {"iot_device", 64, 5840, 1460, 0, 0, 0, 0, {}},
};
```

### Connection Tracking

```c
/* Per-connection identity */
struct flux_connection {
    __be32 src_ip;
    __be32 dst_ip;
    __be16 src_port;
    __be16 dst_port;
    struct os_profile *identity;
    struct hlist_node node;
};

/* Assign identity to new connection */
static struct os_profile *flux_assign_identity(struct flux_connection *conn)
{
    switch (flux_cfg.mode) {
        case FLUX_MODE_RANDOM:
            return &profiles[prandom_u32() % ARRAY_SIZE(profiles)];
        case FLUX_MODE_STICKY:
            return flux_get_sticky_identity(conn->src_ip);
        case FLUX_MODE_PROFILE:
            return &profiles[flux_cfg.profile_index];
    }
}
```

---

# PHASE 3: NETWORK SECURITY

**Duration:** 2-3 weeks  
**Features:** 30

---

## 3.1 shadow_dns Module

### Purpose
Kernel-level DNS filtering and sinkhole.

### Implementation

```c
struct dns_config {
    bool sinkhole_enabled;
    bool log_queries;
    bool force_encrypted;
    struct list_head blocklist;
    struct list_head allowlist;
};

/* DNS Query Interception */
static unsigned int dns_hook(void *priv,
                            struct sk_buff *skb,
                            const struct nf_hook_state *state)
{
    struct udphdr *udph;
    struct dns_header *dnsh;
    char domain[256];
    
    if (!is_dns_query(skb))
        return NF_ACCEPT;
    
    extract_domain(skb, domain, sizeof(domain));
    
    if (is_blocked(domain)) {
        shadow_log(LOG_INFO, "DNS blocked: %s", domain);
        return NF_DROP;
    }
    
    if (dns_cfg.log_queries)
        shadow_log(LOG_DEBUG, "DNS query: %s", domain);
    
    return NF_ACCEPT;
}
```

### Blocklist Management

```
/sys/kernel/shadowos/dns/
├── enabled          # 0/1
├── blocklist        # Write domain to add
├── allowlist        # Override blocks
├── log_queries      # 0/1
├── force_doh        # 0/1 (block plain DNS)
└── stats            # Queries blocked (ro)
```

---

## 3.2 shadow_geo Module

### Purpose
Block/allow traffic by country.

### IP Database

```c
/* Compact IP range storage */
struct geo_range {
    __be32 start;
    __be32 end;
    u8 country_code[2];  /* ISO 3166-1 alpha-2 */
};

/* Binary search for IP lookup */
static const char *geo_lookup(__be32 ip)
{
    int lo = 0, hi = geo_range_count - 1;
    
    while (lo <= hi) {
        int mid = (lo + hi) / 2;
        if (ip < geo_ranges[mid].start)
            hi = mid - 1;
        else if (ip > geo_ranges[mid].end)
            lo = mid + 1;
        else
            return geo_ranges[mid].country_code;
    }
    return "??";
}
```

### Configuration

```
/sys/kernel/shadowos/geo/
├── enabled          # 0/1
├── mode             # "block" or "allow"
├── countries        # "RU,CN,KP,IR" (comma-separated)
└── log              # Blocked connections (ro)
```

---

## 3.3 shadow_fprint Module

### Purpose
Fingerprint connections (JA3, HASSH).

### JA3 Implementation

```c
/* JA3 = MD5(SSLVersion,Ciphers,Extensions,EllipticCurves,EllipticCurveFormats) */
static void calculate_ja3(struct tls_client_hello *hello, char *ja3_hash)
{
    char ja3_string[1024];
    int len = 0;
    
    len += snprintf(ja3_string + len, sizeof(ja3_string) - len,
                   "%d,", hello->version);
    
    /* Add cipher suites */
    for (int i = 0; i < hello->cipher_count; i++) {
        if (!is_grease(hello->ciphers[i]))
            len += snprintf(ja3_string + len, sizeof(ja3_string) - len,
                           "%d-", hello->ciphers[i]);
    }
    /* ... extensions, curves, formats ... */
    
    md5_hash(ja3_string, len, ja3_hash);
}
```

---

## Phase 2-3 Feature Summary

| # | Feature | Module | Status |
|---|---------|--------|--------|
| 21 | TTL randomization | shadow_chaos | Spec ✓ |
| 22 | Window chaos | shadow_chaos | Spec ✓ |
| 23 | Timestamp manipulation | shadow_chaos | Spec ✓ |
| 24 | Response jitter | shadow_chaos | Spec ✓ |
| 25 | RST randomization | shadow_chaos | Spec ✓ |
| 26 | TCP options chaos | shadow_chaos | Spec ✓ |
| 27 | Phantom SSH banners | shadow_phantom | Spec ✓ |
| 28 | Phantom HTTP banners | shadow_phantom | Spec ✓ |
| 29 | Phantom DB banners | shadow_phantom | Spec ✓ |
| 30 | Tarpit connections | shadow_phantom | Spec ✓ |
| 31 | Per-conn identity | shadow_flux | Spec ✓ |
| 32 | OS profile mimicry | shadow_flux | Spec ✓ |
| 33 | Identity modes | shadow_flux | Spec ✓ |
| 34 | DNS sinkhole | shadow_dns | Spec ✓ |
| 35 | DNS logging | shadow_dns | Spec ✓ |
| 36 | Force encrypted DNS | shadow_dns | Spec ✓ |
| 37 | Geo-blocking | shadow_geo | Spec ✓ |
| 38 | Country allowlist | shadow_geo | Spec ✓ |
| 39 | JA3 fingerprinting | shadow_fprint | Spec ✓ |
| 40 | HASSH fingerprinting | shadow_fprint | Spec ✓ |
