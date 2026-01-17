/*
 * ShadowOS Userspace Library
 * Public API
 */

#ifndef _LIBSHADOW_H
#define _LIBSHADOW_H

#include <stdint.h>
#include <stdbool.h>

/* Alert Structure matching kernel */
struct shadow_alert {
    uint32_t id;
    uint64_t timestamp;
    uint8_t type;
    uint8_t severity;
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t packet_count;
    uint32_t ports_targeted;
    char scan_type[32];
    char action_taken[64];
    char details[256];
};

/* Core API */
int shadow_init(void);
void shadow_cleanup(void);

/* Config API */
int shadow_get_enabled(const char *module);
int shadow_set_enabled(const char *module, int enabled);

/* Stats API */
struct shadow_stats {
    uint64_t alerts_sent;
    uint64_t packets_inspected;
    uint64_t scans_detected;
    uint64_t scans_diverted;
};

int shadow_get_stats(struct shadow_stats *stats);

#endif /* _LIBSHADOW_H */
