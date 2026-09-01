#ifndef OZAYN_PLATFORM_INFO_H
#define OZAYN_PLATFORM_INFO_H

#include "platform.h"
#include "ozayn.h"
#include <stdint.h>

/*
 * platform_info.h — System information & hardware identification.
 *
 * Provides a cross-platform API to query OS, architecture, CPU,
 * memory, hostname, and username. No dynamic allocation.
 *
 * Memory values are in bytes.
 */

#define OZAYN_PLATFORM_INFO_STR_LEN 256

typedef struct {
    char operating_system[64];   /* "Linux", "Windows", "macOS" */
    char architecture[64];       /* "x86_64", "aarch64", etc. */
    char hostname[OZAYN_PLATFORM_INFO_STR_LEN];
    char username[OZAYN_PLATFORM_INFO_STR_LEN];

    uint32_t cpu_count;          /* logical processors */

    uint64_t memory_total;       /* total physical memory in bytes */
    uint64_t memory_available;   /* available physical memory in bytes */
} OzaynPlatformInfo;

/* Query system information. Returns OZAYN_OK on success. */
ozayn_result_t ozayn_platform_get_info(OzaynPlatformInfo *info);

#endif
