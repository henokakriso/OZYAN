#include "platform_info.h"
#include "platform.h"
#include "platform_detect.h"

#ifdef OZAYN_OS_WINDOWS

#include <windows.h>
#include <stdio.h>
#include <string.h>

/*
 * platform_info_windows.c — Windows system information implementation.
 */

ozayn_result_t ozayn_platform_get_info(OzaynPlatformInfo *info) {
    if (!info) return OZAYN_ERR_NULL;
    memset(info, 0, sizeof(OzaynPlatformInfo));

    /* Operating system */
    strncpy(info->operating_system, "Windows", sizeof(info->operating_system) - 1);

    /* Architecture */
#ifdef _M_X64
    strncpy(info->architecture, "x86_64", sizeof(info->architecture) - 1);
#elif defined(_M_IX86)
    strncpy(info->architecture, "x86", sizeof(info->architecture) - 1);
#elif defined(_M_ARM64)
    strncpy(info->architecture, "aarch64", sizeof(info->architecture) - 1);
#else
    strncpy(info->architecture, "unknown", sizeof(info->architecture) - 1);
#endif

    /* Hostname */
    DWORD name_len = OZAYN_PLATFORM_INFO_STR_LEN;
    if (!GetComputerNameA(info->hostname, &name_len)) {
        strncpy(info->hostname, "Unknown", OZAYN_PLATFORM_INFO_STR_LEN - 1);
    }

    /* Username */
    DWORD user_len = OZAYN_PLATFORM_INFO_STR_LEN;
    if (!GetUserNameA(info->username, &user_len)) {
        strncpy(info->username, "Unknown", OZAYN_PLATFORM_INFO_STR_LEN - 1);
    }

    /* CPU count */
    SYSTEM_INFO sysinfo;
    GetSystemInfo(&sysinfo);
    info->cpu_count = sysinfo.dwNumberOfProcessors;

    /* Memory */
    MEMORYSTATUSEX stat;
    stat.dwLength = sizeof(stat);
    if (GlobalMemoryStatusEx(&stat)) {
        info->memory_total = stat.ullTotalPhys;
        info->memory_available = stat.ullAvailPhys;
    }

    return OZAYN_OK;
}

#endif /* OZAYN_OS_WINDOWS */
