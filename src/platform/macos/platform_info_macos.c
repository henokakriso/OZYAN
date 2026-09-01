#include "platform_info.h"
#include "platform.h"
#include "platform_detect.h"

#ifdef OZAYN_OS_MACOS

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/utsname.h>
#include <sys/sysctl.h>
#include <pwd.h>

/*
 * platform_info_macos.c — macOS system information implementation.
 */

ozayn_result_t ozayn_platform_get_info(OzaynPlatformInfo *info) {
    if (!info) return OZAYN_ERR_NULL;
    memset(info, 0, sizeof(OzaynPlatformInfo));

    /* Operating system */
    strncpy(info->operating_system, "macOS", sizeof(info->operating_system) - 1);

    /* Architecture */
    char arch[64];
    size_t arch_len = sizeof(arch);
    if (sysctlbyname("hw.machine", arch, &arch_len, NULL, 0) == 0) {
        strncpy(info->architecture, arch, sizeof(info->architecture) - 1);
    } else {
        strncpy(info->architecture, OZAYN_ARCH_NAME, sizeof(info->architecture) - 1);
    }

    /* Hostname */
    if (gethostname(info->hostname, OZAYN_PLATFORM_INFO_STR_LEN - 1) != 0) {
        strncpy(info->hostname, "Unknown", OZAYN_PLATFORM_INFO_STR_LEN - 1);
    }

    /* Username */
    uid_t uid = getuid();
    struct passwd *pw = getpwuid(uid);
    if (pw && pw->pw_name) {
        strncpy(info->username, pw->pw_name, OZAYN_PLATFORM_INFO_STR_LEN - 1);
    } else {
        strncpy(info->username, "Unknown", OZAYN_PLATFORM_INFO_STR_LEN - 1);
    }

    /* CPU count */
    int ncpu = 0;
    size_t ncpu_len = sizeof(ncpu);
    if (sysctlbyname("hw.ncpu", &ncpu, &ncpu_len, NULL, 0) == 0) {
        info->cpu_count = (uint32_t)ncpu;
    }

    /* Memory */
    uint64_t memsize = 0;
    size_t memsize_len = sizeof(memsize);
    if (sysctlbyname("hw.memsize", &memsize, &memsize_len, NULL, 0) == 0) {
        info->memory_total = memsize;
    }

    /* Available memory: use sysctl for pagesize * free pages */
    uint64_t pagesize = 0;
    size_t pagesize_len = sizeof(pagesize);
    uint64_t free_pages = 0;
    size_t free_len = sizeof(free_pages);

    if (sysctlbyname("hw.pagesize", &pagesize, &pagesize_len, NULL, 0) == 0 &&
        sysctlbyname("vm.pageins_free", &free_pages, &free_len, NULL, 0) == 0) {
        info->memory_available = pagesize * free_pages;
    } else {
        /* Fallback: report 0 if unavailable */
        info->memory_available = 0;
    }

    return OZAYN_OK;
}

#endif /* OZAYN_OS_MACOS */
