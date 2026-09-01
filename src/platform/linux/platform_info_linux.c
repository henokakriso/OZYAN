#define _DEFAULT_SOURCE
#include "platform_info.h"
#include "platform.h"
#include "platform_detect.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/utsname.h>
#include <sys/sysinfo.h>
#include <pwd.h>

/*
 * platform_info_linux.c — Linux system information implementation.
 */

ozayn_result_t ozayn_platform_get_info(OzaynPlatformInfo *info) {
    if (!info) return OZAYN_ERR_NULL;
    memset(info, 0, sizeof(OzaynPlatformInfo));

    /* Operating system */
    strncpy(info->operating_system, "Linux", sizeof(info->operating_system) - 1);

    /* Architecture */
    struct utsname uts;
    if (uname(&uts) == 0) {
        strncpy(info->architecture, uts.machine, sizeof(info->architecture) - 1);
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
    long cores = sysconf(_SC_NPROCESSORS_ONLN);
    if (cores > 0) {
        info->cpu_count = (uint32_t)cores;
    }

    /* Memory */
    struct sysinfo si;
    if (sysinfo(&si) == 0) {
        info->memory_total = (uint64_t)si.totalram * si.mem_unit;
        info->memory_available = (uint64_t)si.freeram * si.mem_unit;
    }

    return OZAYN_OK;
}
