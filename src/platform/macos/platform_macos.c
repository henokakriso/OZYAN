#include "platform.h"

#ifdef OZAYN_OS_MACOS

/*
 * platform_macos.c — macOS platform implementation.
 *
 * Implements the common platform API using macOS/BSD APIs.
 * Only compiles on macOS targets.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/utsname.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/param.h>
#include <sys/mount.h>
#include <dirent.h>
#include <signal.h>
#include <errno.h>
#include <mach/mach.h>
#include <net/if.h>
#include <ifaddrs.h>
#include <arpa/inet.h>

/* ================================================================
 * A. System Information
 * ================================================================ */

ozayn_result_t ozayn_system_info(ozayn_system_info_t *info) {
    if (!info) return OZAYN_ERR_NULL;
    memset(info, 0, sizeof(ozayn_system_info_t));

    strncpy(info->os_name, "macOS", OZAYN_MAX_SYSTEM_STR - 1);

    /* OS version via sysctl */
    char osversion[256];
    size_t osversion_len = sizeof(osversion);
    if (sysctlbyname("kern.osrelease", osversion, &osversion_len, NULL, 0) == 0) {
        strncpy(info->os_version, osversion, OZAYN_MAX_SYSTEM_STR - 1);
    }

    /* Architecture */
    char arch[256];
    size_t arch_len = sizeof(arch);
    if (sysctlbyname("hw.machine", arch, &arch_len, NULL, 0) == 0) {
        strncpy(info->arch, arch, sizeof(info->arch) - 1);
    } else {
        struct utsname uts;
        if (uname(&uts) == 0) {
            strncpy(info->arch, uts.machine, sizeof(info->arch) - 1);
        }
    }

    /* Hostname */
    if (gethostname(info->hostname, OZAYN_MAX_SYSTEM_STR - 1) != 0) {
        strncpy(info->hostname, "unknown", OZAYN_MAX_SYSTEM_STR - 1);
    }

    /* Memory (in bytes, convert to MB) */
    uint64_t memsize = 0;
    size_t memsize_len = sizeof(memsize);
    if (sysctlbyname("hw.memsize", &memsize, &memsize_len, NULL, 0) == 0) {
        info->total_memory_mb = memsize / (1024 * 1024);
    }

    /* CPU cores */
    int ncpu = 0;
    size_t ncpu_len = sizeof(ncpu);
    if (sysctlbyname("hw.ncpu", &ncpu, &ncpu_len, NULL, 0) == 0) {
        info->cpu_cores = (uint32_t)ncpu;
    }

    /* Uptime */
    struct timeval boottime;
    size_t bt_len = sizeof(boottime);
    int mib[2] = { CTL_KERN, KERN_BOOTTIME };
    if (sysctl(mib, 2, &boottime, &bt_len, NULL, 0) == 0) {
        time_t now = time(NULL);
        info->uptime_seconds = (uint64_t)(now - boottime.tv_sec);
    }

    return OZAYN_OK;
}

uint64_t ozayn_system_time(void) {
    return (uint64_t)time(NULL);
}

void ozayn_system_sleep_ms(uint32_t ms) {
    struct timespec ts;
    ts.tv_sec = ms / 1000;
    ts.tv_nsec = (ms % 1000) * 1000000L;
    nanosleep(&ts, NULL);
}

/* ================================================================
 * B. Process Operations
 * ================================================================ */

uint32_t ozayn_process_self(void) {
    return (uint32_t)getpid();
}

ozayn_result_t ozayn_process_info(uint32_t pid, ozayn_process_info_t *info) {
    if (!info) return OZAYN_ERR_NULL;

    char path[64];
    snprintf(path, sizeof(path), "/proc/%u/cmdline", pid);

    FILE *f = fopen(path, "r");
    if (!f) {
        info->pid = pid;
        info->running = 0;
        return OZAYN_ERR;
    }

    info->pid = pid;
    info->running = 1;

    size_t n = fread(info->executable, 1, OZAYN_MAX_PATH - 1, f);
    fclose(f);

    if (n > 0) {
        info->executable[n] = '\0';
        const char *base = strrchr(info->executable, '/');
        strncpy(info->name, base ? base + 1 : info->executable, OZAYN_MAX_PROCESS_NAME - 1);
    } else {
        strncpy(info->name, "unknown", OZAYN_MAX_PROCESS_NAME - 1);
    }

    return OZAYN_OK;
}

ozayn_result_t ozayn_process_signal(uint32_t pid, int signal) {
    if (pid == 0) return OZAYN_ERR;
    if (kill((pid_t)pid, signal) == 0) return OZAYN_OK;
    return OZAYN_ERR;
}

/* ================================================================
 * C. File System / Storage
 * ================================================================ */

int ozayn_fs_exists(const char *path) {
    if (!path) return 0;
    struct stat st;
    return stat(path, &st) == 0;
}

int ozayn_fs_is_dir(const char *path) {
    if (!path) return 0;
    struct stat st;
    if (stat(path, &st) != 0) return 0;
    return S_ISDIR(st.st_mode);
}

static int mkdirs_recursive(const char *path, mode_t mode) {
    char tmp[OZAYN_MAX_PATH];
    char *p = NULL;

    snprintf(tmp, sizeof(tmp), "%s", path);
    for (p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            if (mkdir(tmp, mode) != 0 && errno != EEXIST) return -1;
            *p = '/';
        }
    }
    if (mkdir(tmp, mode) != 0 && errno != EEXIST) return -1;
    return 0;
}

ozayn_result_t ozayn_fs_mkdir(const char *path) {
    if (!path) return OZAYN_ERR_NULL;
    if (mkdirs_recursive(path, 0755) == 0) return OZAYN_OK;
    return OZAYN_ERR;
}

ozayn_result_t ozayn_fs_remove(const char *path) {
    if (!path) return OZAYN_ERR_NULL;
    if (unlink(path) == 0) return OZAYN_OK;
    return OZAYN_ERR;
}

int64_t ozayn_fs_size(const char *path) {
    if (!path) return -1;
    struct stat st;
    if (stat(path, &st) != 0) return -1;
    return (int64_t)st.st_size;
}

int64_t ozayn_fs_read(const char *path, void *buf, uint64_t buf_size) {
    if (!path || !buf) return -1;
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    size_t n = fread(buf, 1, (size_t)buf_size, f);
    fclose(f);
    return (int64_t)n;
}

int64_t ozayn_fs_write(const char *path, const void *data, uint64_t size) {
    if (!path || !data) return -1;
    FILE *f = fopen(path, "wb");
    if (!f) return -1;
    size_t n = fwrite(data, 1, (size_t)size, f);
    fclose(f);
    return (int64_t)n;
}

static char home_buf[OZAYN_MAX_PATH];
static char config_buf[OZAYN_MAX_PATH];

const char *ozayn_fs_home(void) {
    const char *home = getenv("HOME");
    if (home) {
        strncpy(home_buf, home, OZAYN_MAX_PATH - 1);
    } else {
        strncpy(home_buf, "/tmp", OZAYN_MAX_PATH - 1);
    }
    return home_buf;
}

const char *ozayn_fs_config_dir(void) {
    const char *home = ozayn_fs_home();
    snprintf(config_buf, OZAYN_MAX_PATH, "%s/Library/Application Support/OZAYN", home);
    return config_buf;
}

/* ================================================================
 * D. Display / Monitor
 * ================================================================ */

ozayn_result_t ozayn_display_info(ozayn_display_info_t *info) {
    if (!info) return OZAYN_ERR_NULL;
    memset(info, 0, sizeof(ozayn_display_info_t));

    /* macOS: use CoreGraphics via popen or fallback */
    FILE *f = popen("system_profiler SPDisplaysDataType 2>/dev/null | grep Resolution | head -1", "r");
    if (f) {
        char line[256];
        if (fgets(line, sizeof(line), f)) {
            info->count = 1;
            int w = 0, h = 0;
            if (sscanf(line, "Resolution: %d x %d", &w, &h) == 2) {
                info->modes[0].width = (uint32_t)w;
                info->modes[0].height = (uint32_t)h;
                info->modes[0].refresh_hz = 60;
                strncpy(info->modes[0].name, "Default", OZAYN_MAX_DISPLAY_NAME - 1);
            }
        }
        pclose(f);
    }

    if (info->count == 0) {
        info->count = 1;
        info->modes[0].width = 2560;
        info->modes[0].height = 1440;
        info->modes[0].refresh_hz = 60;
        strncpy(info->modes[0].name, "Default", OZAYN_MAX_DISPLAY_NAME - 1);
    }

    return OZAYN_OK;
}

/* ================================================================
 * E. Network
 * ================================================================ */

ozayn_result_t ozayn_network_info(ozayn_network_info_t *info) {
    if (!info) return OZAYN_ERR_NULL;
    memset(info, 0, sizeof(ozayn_network_info_t));

    struct ifaddrs *ifaddr, *ifa;
    if (getifaddrs(&ifaddr) == -1) return OZAYN_ERR;

    for (ifa = ifaddr; ifa != NULL && info->count < 16; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL) continue;

        ozayn_network_iface_t *iface = &info->ifaces[info->count];
        strncpy(iface->name, ifa->ifa_name, OZAYN_MAX_IFACE_NAME - 1);
        iface->is_up = (ifa->ifa_flags & IFF_UP) ? 1 : 0;
        iface->is_loopback = (ifa->ifa_flags & IFF_LOOPBACK) ? 1 : 0;

        if (ifa->ifa_addr->sa_family == AF_INET) {
            struct sockaddr_in *sa = (struct sockaddr_in *)ifa->ifa_addr;
            inet_ntop(AF_INET, &sa->sin_addr, iface->ip, OZAYN_MAX_IP_STR);
        } else if (ifa->ifa_addr->sa_family == AF_INET6) {
            struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *)ifa->ifa_addr;
            inet_ntop(AF_INET6, &sa6->sin6_addr, iface->ip, OZAYN_MAX_IP_STR);
        }

        info->count++;
    }

    freeifaddrs(ifaddr);
    return OZAYN_OK;
}

int ozayn_network_ping(const char *host) {
    if (!host) return 0;
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "ping -c 1 -W 2000 %s >/dev/null 2>&1", host);
    return system(cmd) == 0;
}

/* ================================================================
 * F. Camera (stub)
 * ================================================================ */

ozayn_result_t ozayn_camera_info(ozayn_camera_info_t *info) {
    if (!info) return OZAYN_ERR_NULL;
    memset(info, 0, sizeof(ozayn_camera_info_t));
    info->available = 0;
    return OZAYN_OK;
}

/* ================================================================
 * G. Audio (stub)
 * ================================================================ */

ozayn_result_t ozayn_audio_info(ozayn_audio_info_t *info) {
    if (!info) return OZAYN_ERR_NULL;
    memset(info, 0, sizeof(ozayn_audio_info_t));
    info->available = 0;
    return OZAYN_OK;
}

/* ================================================================
 * H. Input (stub)
 * ================================================================ */

ozayn_result_t ozayn_input_info(ozayn_input_info_t *info) {
    if (!info) return OZAYN_ERR_NULL;
    memset(info, 0, sizeof(ozayn_input_info_t));
    info->has_keyboard = 1;
    info->has_mouse = 1;
    info->has_touch = 0;
    info->has_microphone = 0;
    info->has_camera = 0;
    return OZAYN_OK;
}

/* ================================================================
 * Platform Detection & Initialization
 * ================================================================ */

static OzaynPlatform _ozayn_current_platform = OZAYN_PLATFORM_UNKNOWN;

ozayn_result_t ozayn_platform_detect_init(void) {
#if defined(OZAYN_OS_LINUX)
    _ozayn_current_platform = OZAYN_PLATFORM_LINUX;
#elif defined(OZAYN_OS_WINDOWS)
    _ozayn_current_platform = OZAYN_PLATFORM_WINDOWS;
#elif defined(OZAYN_OS_MACOS)
    _ozayn_current_platform = OZAYN_PLATFORM_MACOS;
#else
    _ozayn_current_platform = OZAYN_PLATFORM_UNKNOWN;
    return OZAYN_ERR;
#endif
    LOG_INFO("PLATFORM", "Platform detected: %s", ozayn_platform_name());
    return OZAYN_OK;
}

void ozayn_platform_detect_shutdown(void) {
    _ozayn_current_platform = OZAYN_PLATFORM_UNKNOWN;
}

OzaynPlatform ozayn_platform_get(void) {
    return _ozayn_current_platform;
}

const char *ozayn_platform_name(void) {
    switch (_ozayn_current_platform) {
        case OZAYN_PLATFORM_LINUX:   return "Linux";
        case OZAYN_PLATFORM_WINDOWS: return "Windows";
        case OZAYN_PLATFORM_MACOS:   return "macOS";
        default:                     return "Unknown";
    }
}

/* ================================================================
 * Platform Lifecycle
 * ================================================================ */

ozayn_result_t ozayn_platform_init(void) {
    ozayn_result_t r = ozayn_platform_detect_init();
    if (r == OZAYN_OK) {
        LOG_INFO("PLATFORM", "Platform layer initialized (%s/%s)", OZAYN_OS_NAME, OZAYN_ARCH_NAME);
    }
    return r;
}

void ozayn_platform_shutdown(void) {
    LOG_INFO("PLATFORM", "Platform layer shut down");
    ozayn_platform_detect_shutdown();
}

#endif /* OZAYN_OS_MACOS */
