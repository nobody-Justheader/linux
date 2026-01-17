/*
 * ShadowOS Userspace Library Implementation
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include "shadow.h"

#define SYSFS_ROOT "/sys/kernel/shadowos"

int shadow_init(void)
{
    // Check if module is loaded
    if (access(SYSFS_ROOT, F_OK) != 0) {
        return -1;
    }
    return 0;
}

void shadow_cleanup(void)
{
    // Nothing to cleanup yet
}

int shadow_get_enabled(const char *module)
{
    char path[256];
    char buf[16];
    int fd;
    
    snprintf(path, sizeof(path), "%s/%s/enabled", SYSFS_ROOT, module);
    
    fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    
    if (read(fd, buf, sizeof(buf)) < 0) {
        close(fd);
        return -1;
    }
    close(fd);
    
    return atoi(buf);
}

int shadow_set_enabled(const char *module, int enabled)
{
    char path[256];
    char buf[16];
    int fd, len;
    
    snprintf(path, sizeof(path), "%s/%s/enabled", SYSFS_ROOT, module);
    
    fd = open(path, O_WRONLY);
    if (fd < 0) return -1;
    
    len = snprintf(buf, sizeof(buf), "%d", enabled);
    if (write(fd, buf, len) < 0) {
        close(fd);
        return -1;
    }
    close(fd);
    
    return 0;
}

int shadow_get_stats(struct shadow_stats *stats)
{
    // TODO: Implement parsing of /sys/kernel/shadowos/core/stats
    return 0;
}
