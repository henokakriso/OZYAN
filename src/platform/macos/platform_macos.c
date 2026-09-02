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
#include <sys/wait.h>
#include <fcntl.h>
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
 * B2. Cross-Platform Process Management
 * ================================================================ */

ozayn_result_t ozayn_process_start(const char *program, const char *const argv[], OzaynProcess *proc) {
    if (!program || !proc) return OZAYN_ERR_NULL;
    if (strlen(program) == 0) return OZAYN_ERR;

    memset(proc, 0, sizeof(OzaynProcess));
    proc->running = 0;

    int err_pipe[2];
    if (pipe(err_pipe) < 0) return OZAYN_ERR;

    pid_t pid = fork();
    if (pid < 0) {
        close(err_pipe[0]);
        close(err_pipe[1]);
        return OZAYN_ERR;
    } else if (pid == 0) {
        close(err_pipe[0]);
        fcntl(err_pipe[1], F_SETFD, FD_CLOEXEC);

        const char *args[OZAYN_PROCESS_MAX_ARGS + 1];
        args[0] = program;
        int argc = 1;

        if (argv) {
            for (int i = 0; i < OZAYN_PROCESS_MAX_ARGS && argv[i]; i++) {
                args[argc++] = argv[i];
            }
        }
        args[argc] = NULL;

        execvp(program, (char *const *)args);

        unsigned char err_byte = 1;
        write(err_pipe[1], &err_byte, 1);
        close(err_pipe[1]);
        _exit(127);
    } else {
        close(err_pipe[1]);

        unsigned char err_byte = 0;
        int n = read(err_pipe[0], &err_byte, 1);
        close(err_pipe[0]);

        if (n > 0 && err_byte == 1) {
            int status;
            waitpid(pid, &status, 0);
            return OZAYN_ERR;
        }

        proc->pid = (uint32_t)pid;
        proc->running = 1;
        return OZAYN_OK;
    }
    return OZAYN_ERR;
}

int ozayn_process_is_running(OzaynProcess *proc) {
    if (!proc || proc->pid == 0) return 0;
    if (!proc->running) return 0;

    int status;
    pid_t result = waitpid((pid_t)proc->pid, &status, WNOHANG);
    if (result == 0) {
        return 1;
    } else if (result > 0) {
        proc->running = 0;
        return 0;
    }
    return 0;
}

ozayn_result_t ozayn_proc_get_info(OzaynProcess *proc, OzaynProcessInfo *info) {
    if (!proc || !info) return OZAYN_ERR_NULL;
    memset(info, 0, sizeof(OzaynProcessInfo));

    info->pid = proc->pid;

    if (proc->pid == 0) {
        info->state = OZAYN_PROC_STATE_UNKNOWN;
        return OZAYN_OK;
    }

    int alive = kill((pid_t)proc->pid, 0) == 0;
    if (alive) {
        info->state = OZAYN_PROC_STATE_RUNNING;
        strncpy(info->name, "running", OZAYN_MAX_PROCESS_NAME - 1);
    } else {
        info->state = OZAYN_PROC_STATE_EXITED;
        strncpy(info->name, "exited", OZAYN_MAX_PROCESS_NAME - 1);
    }

    return OZAYN_OK;
}

ozayn_result_t ozayn_process_terminate(OzaynProcess *proc) {
    if (!proc) return OZAYN_ERR_NULL;
    if (proc->pid == 0 || !proc->running) return OZAYN_ERR;

    if (kill((pid_t)proc->pid, SIGTERM) == 0) {
        return OZAYN_OK;
    }
    return OZAYN_ERR;
}

ozayn_result_t ozayn_process_wait(OzaynProcess *proc, uint32_t timeout_ms) {
    if (!proc) return OZAYN_ERR_NULL;
    if (proc->pid == 0) return OZAYN_ERR;
    if (!proc->running) return OZAYN_OK;

    if (timeout_ms == 0) {
        int status;
        waitpid((pid_t)proc->pid, &status, 0);
        proc->running = 0;
        return OZAYN_OK;
    }

    uint32_t elapsed = 0;
    while (elapsed < timeout_ms) {
        int status;
        pid_t result = waitpid((pid_t)proc->pid, &status, WNOHANG);
        if (result > 0) {
            proc->running = 0;
            return OZAYN_OK;
        }
        ozayn_system_sleep_ms(10);
        elapsed += 10;
    }
    return OZAYN_ERR;
}

void ozayn_process_close(OzaynProcess *proc) {
    if (!proc) return;
    if (proc->running && proc->pid > 0) {
        ozayn_process_terminate(proc);
    }
    memset(proc, 0, sizeof(OzaynProcess));
}

/* ================================================================
 * C. File System / Storage
 * ================================================================ */

int ozayn_fs_exists(const char *path) {
    if (!path) return 0;
    struct stat st;
    return stat(path, &st) == 0;
}

int ozayn_fs_is_file(const char *path) {
    if (!path) return 0;
    struct stat st;
    if (stat(path, &st) != 0) return 0;
    return S_ISREG(st.st_mode);
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

ozayn_result_t ozayn_fs_rmdir(const char *path) {
    if (!path) return OZAYN_ERR_NULL;
    if (rmdir(path) == 0) return OZAYN_OK;
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

int64_t ozayn_fs_append(const char *path, const void *data, uint64_t size) {
    if (!path || !data) return -1;
    FILE *f = fopen(path, "ab");
    if (!f) return -1;
    size_t n = fwrite(data, 1, (size_t)size, f);
    fclose(f);
    return (int64_t)n;
}

ozayn_result_t ozayn_fs_copy(const char *source, const char *dest) {
    if (!source || !dest) return OZAYN_ERR_NULL;
    if (!ozayn_fs_is_file(source)) return OZAYN_ERR;

    FILE *fin = fopen(source, "rb");
    if (!fin) return OZAYN_ERR;

    FILE *fout = fopen(dest, "wb");
    if (!fout) { fclose(fin); return OZAYN_ERR; }

    char buf[8192];
    size_t n;
    int success = 1;
    while ((n = fread(buf, 1, sizeof(buf), fin)) > 0) {
        if (fwrite(buf, 1, n, fout) != n) { success = 0; break; }
    }

    fclose(fin);
    fclose(fout);
    return success ? OZAYN_OK : OZAYN_ERR;
}

ozayn_result_t ozayn_fs_move(const char *source, const char *dest) {
    if (!source || !dest) return OZAYN_ERR_NULL;
    if (rename(source, dest) == 0) return OZAYN_OK;
    return OZAYN_ERR;
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
 * D2. Cross-Platform Display Management
 * ================================================================ */

static OzaynDisplayState _ozayn_display = {0};

static int _ozayn_display_discover(void) {
    /* macOS: use system_profiler to get display info */
    FILE *f = popen("system_profiler SPDisplaysDataType 2>/dev/null", "r");
    if (!f) {
        /* Fallback: assume one display */
        OzaynDisplayInfo *d = &_ozayn_display.displays[0];
        memset(d, 0, sizeof(OzaynDisplayInfo));
        d->index = 0;
        d->is_primary = 1;
        d->width = 2560;
        d->height = 1440;
        d->refresh_hz = 60;
        d->x = 0;
        d->y = 0;
        strncpy(d->name, "Built-in Display", OZAYN_MAX_DISPLAY_NAME - 1);
        _ozayn_display.count = 1;
        _ozayn_display.primary_index = 0;
        _ozayn_display.available = 1;
        return 1;
    }

    char line[512];
    uint32_t count = 0;
    int current_display = -1;

    while (fgets(line, sizeof(line), f) && count < OZAYN_MAX_DISPLAYS) {
        /* Look for display type headers */
        if (strstr(line, "Display Type:") || strstr(line, "Chipset Model:")) {
            count++;
            current_display = count - 1;

            OzaynDisplayInfo *d = &_ozayn_display.displays[current_display];
            memset(d, 0, sizeof(OzaynDisplayInfo));
            d->index = (uint32_t)current_display;
            d->is_primary = (current_display == 0) ? 1 : 0;
            d->refresh_hz = 60;
            d->x = 0;
            d->y = 0;
            strncpy(d->name, "Display", OZAYN_MAX_DISPLAY_NAME - 1);

            /* Extract display type name */
            char *colon = strchr(line, ':');
            if (colon) {
                colon++;
                while (*colon == ' ') colon++;
                size_t len = strlen(colon);
                while (len > 0 && (colon[len-1] == '\n' || colon[len-1] == '\r')) len--;
                if (len >= OZAYN_MAX_DISPLAY_NAME) len = OZAYN_MAX_DISPLAY_NAME - 1;
                strncpy(d->name, colon, len);
                d->name[len] = '\0';
            }
        }

        /* Parse resolution */
        if (current_display >= 0 && strstr(line, "Resolution:")) {
            OzaynDisplayInfo *d = &_ozayn_display.displays[current_display];
            int w = 0, h = 0;
            if (sscanf(line, "Resolution: %d x %d", &w, &h) == 2) {
                d->width = (uint32_t)w;
                d->height = (uint32_t)h;
            }
        }
    }

    pclose(f);

    /* Set defaults for displays without resolution */
    for (uint32_t i = 0; i < count; i++) {
        if (_ozayn_display.displays[i].width == 0) {
            _ozayn_display.displays[i].width = 2560;
            _ozayn_display.displays[i].height = 1440;
        }
    }

    /* Fallback if nothing found */
    if (count == 0) {
        OzaynDisplayInfo *d = &_ozayn_display.displays[0];
        memset(d, 0, sizeof(OzaynDisplayInfo));
        d->index = 0;
        d->is_primary = 1;
        d->width = 2560;
        d->height = 1440;
        d->refresh_hz = 60;
        d->x = 0;
        d->y = 0;
        strncpy(d->name, "Built-in Display", OZAYN_MAX_DISPLAY_NAME - 1);
        count = 1;
        _ozayn_display.primary_index = 0;
    }

    _ozayn_display.count = count;
    _ozayn_display.available = (count > 0) ? 1 : 0;
    if (_ozayn_display.primary_index < 0) _ozayn_display.primary_index = 0;

    return (int)count;
}

ozayn_result_t ozayn_display_init(void) {
    if (_ozayn_display.initialized) return OZAYN_OK;

    memset(&_ozayn_display, 0, sizeof(OzaynDisplayState));
    _ozayn_display.primary_index = -1;

    _ozayn_display_discover();
    _ozayn_display.initialized = 1;

    return OZAYN_OK;
}

void ozayn_display_shutdown(void) {
    if (!_ozayn_display.initialized) return;
    memset(&_ozayn_display, 0, sizeof(OzaynDisplayState));
    _ozayn_display.primary_index = -1;
}

int ozayn_display_is_available(void) {
    return _ozayn_display.available;
}

uint32_t ozayn_display_count(void) {
    if (!_ozayn_display.initialized) return 0;
    return _ozayn_display.count;
}

ozayn_result_t ozayn_display_get(uint32_t index, OzaynDisplayInfo *info) {
    if (!info) return OZAYN_ERR_NULL;
    if (!_ozayn_display.initialized) return OZAYN_ERR;
    if (index >= _ozayn_display.count) return OZAYN_ERR;
    memcpy(info, &_ozayn_display.displays[index], sizeof(OzaynDisplayInfo));
    return OZAYN_OK;
}

ozayn_result_t ozayn_display_get_primary(OzaynDisplayInfo *info) {
    if (!info) return OZAYN_ERR_NULL;
    if (!_ozayn_display.initialized) return OZAYN_ERR;
    if (_ozayn_display.primary_index < 0) return OZAYN_ERR;
    memcpy(info, &_ozayn_display.displays[_ozayn_display.primary_index], sizeof(OzaynDisplayInfo));
    return OZAYN_OK;
}

ozayn_result_t ozayn_display_refresh(void) {
    if (!_ozayn_display.initialized) return OZAYN_ERR;
    _ozayn_display_discover();
    return OZAYN_OK;
}

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
 * E. Window Management (stub — needs Objective-C runtime)
 * ================================================================ */

static OzaynWindowState _ozayn_window = {0};

ozayn_result_t ozayn_window_init(void) {
    if (_ozayn_window.initialized) return OZAYN_OK;
    memset(&_ozayn_window, 0, sizeof(OzaynWindowState));
    _ozayn_window.initialized = 1;
    _ozayn_window.available = 0;
    LOG_INFO("WINDOW", "Window subsystem initialized (macOS stub — not yet implemented)");
    return OZAYN_OK;
}

void ozayn_window_shutdown(void) {
    if (!_ozayn_window.initialized) return;
    memset(&_ozayn_window, 0, sizeof(OzaynWindowState));
    LOG_INFO("WINDOW", "Window subsystem shut down");
}

int ozayn_window_is_available(void) { return _ozayn_window.available; }
uint32_t ozayn_window_get_count(void) { return _ozayn_window.initialized ? _ozayn_window.count : 0; }

ozayn_result_t ozayn_window_get_info(uint32_t index, OzaynWindowInfo *info) {
    if (!info) return OZAYN_ERR_NULL;
    if (!_ozayn_window.initialized) return OZAYN_ERR;
    if (index >= _ozayn_window.count) return OZAYN_ERR;
    memcpy(info, &_ozayn_window.windows[index], sizeof(OzaynWindowInfo));
    return OZAYN_OK;
}

ozayn_result_t ozayn_window_get_active(OzaynWindowInfo *info) {
    if (!info) return OZAYN_ERR_NULL;
    if (!_ozayn_window.initialized) return OZAYN_ERR;
    return OZAYN_ERR;
}

ozayn_result_t ozayn_window_move(unsigned long long window_id, int32_t x, int32_t y) {
    (void)window_id; (void)x; (void)y;
    return OZAYN_ERR;
}

ozayn_result_t ozayn_window_resize(unsigned long long window_id, uint32_t width, uint32_t height) {
    (void)window_id; (void)width; (void)height;
    return OZAYN_ERR;
}

ozayn_result_t ozayn_window_minimize(unsigned long long window_id) {
    (void)window_id;
    return OZAYN_ERR;
}

ozayn_result_t ozayn_window_maximize(unsigned long long window_id) {
    (void)window_id;
    return OZAYN_ERR;
}

ozayn_result_t ozayn_window_restore(unsigned long long window_id) {
    (void)window_id;
    return OZAYN_ERR;
}

ozayn_result_t ozayn_window_close(unsigned long long window_id) {
    (void)window_id;
    return OZAYN_ERR;
}

ozayn_result_t ozayn_window_refresh(void) {
    if (!_ozayn_window.initialized) return OZAYN_ERR;
    return OZAYN_OK;
}

/* ================================================================
 * G. Camera Device Abstraction (Step 09)
 * ================================================================
 *
 * macOS stub — requires AVFoundation framework for full implementation.
 * Camera privacy permissions are required.
 */

static OzaynCameraState _ozayn_camera = {0};

ozayn_result_t ozayn_camera_init(void) {
    if (_ozayn_camera.initialized) return OZAYN_OK;
    memset(&_ozayn_camera, 0, sizeof(OzaynCameraState));
    /* TODO: AVCaptureDevice discovery via AVFoundation */
    _ozayn_camera.initialized = 1;
    return OZAYN_OK;
}

void ozayn_camera_shutdown(void) {
    if (!_ozayn_camera.initialized) return;
    memset(&_ozayn_camera, 0, sizeof(OzaynCameraState));
}

int ozayn_camera_is_available(void) {
    return _ozayn_camera.available;
}

unsigned int ozayn_camera_get_count(void) {
    if (!_ozayn_camera.initialized) return 0;
    return _ozayn_camera.count;
}

ozayn_result_t ozayn_camera_get_info(unsigned int index, OzaynCameraInfo *info) {
    if (!info) return OZAYN_ERR_NULL;
    if (!_ozayn_camera.initialized) return OZAYN_ERR;
    if (index >= _ozayn_camera.count) return OZAYN_ERR;
    memset(info, 0, sizeof(OzaynCameraInfo));
    return OZAYN_OK;
}

ozayn_result_t ozayn_camera_open(unsigned int index) {
    (void)index;
    if (!_ozayn_camera.initialized) return OZAYN_ERR;
    return OZAYN_ERR;
}

ozayn_result_t ozayn_camera_close(void) {
    if (!_ozayn_camera.initialized) return OZAYN_ERR;
    return OZAYN_ERR;
}

ozayn_result_t ozayn_camera_start(void) {
    if (!_ozayn_camera.initialized) return OZAYN_ERR;
    return OZAYN_ERR;
}

ozayn_result_t ozayn_camera_stop(void) {
    if (!_ozayn_camera.initialized) return OZAYN_ERR;
    return OZAYN_ERR;
}

ozayn_result_t ozayn_camera_capture(OzaynCameraFrame *frame) {
    if (!frame) return OZAYN_ERR_NULL;
    if (!_ozayn_camera.initialized) return OZAYN_ERR;
    memset(frame, 0, sizeof(OzaynCameraFrame));
    return OZAYN_ERR;
}

ozayn_result_t ozayn_camera_set_resolution(unsigned int width, unsigned int height) {
    (void)width; (void)height;
    if (!_ozayn_camera.initialized) return OZAYN_ERR;
    return OZAYN_ERR;
}

ozayn_result_t ozayn_camera_set_fps(unsigned int fps) {
    (void)fps;
    if (!_ozayn_camera.initialized) return OZAYN_ERR;
    return OZAYN_ERR;
}

void ozayn_camera_frame_release(OzaynCameraFrame *frame) {
    if (!frame) return;
    frame->data = NULL;
    frame->data_size = 0;
    frame->width = 0;
    frame->height = 0;
    frame->stride = 0;
    frame->format = OZAYN_PIXEL_FORMAT_UNKNOWN;
}

/* ================================================================
 * H. Audio (stub)
 * ================================================================ */

ozayn_result_t ozayn_audio_info(ozayn_audio_info_t *info) {
    if (!info) return OZAYN_ERR_NULL;
    memset(info, 0, sizeof(ozayn_audio_info_t));
    info->available = 0;
    return OZAYN_OK;
}

/* ================================================================
 * I. Input & Mouse Abstraction (Step 07)
 * ================================================================
 *
 * Uses Core Graphics APIs for mouse position and button control.
 * Coordinate convention: (0,0) = top-left of primary display.
 * X increases rightward, Y increases downward.
 *
 * macOS Permission Note:
 *   Accessibility permissions are required for mouse movement/control.
 *   If permission is denied, the subsystem reports unavailable.
 */

#include <ApplicationServices/ApplicationServices.h>

static OzaynInputState _ozayn_input = {0};

static int _ozayn_input_check_accessibility(void) {
    /* Check if accessibility permissions are granted */
    CFDictionaryRef options = CFDictionaryCreate(
        kCFAllocatorDefault,
        (const void **)&kAXTrustedCheckOptionPrompt,
        (const void **)&kCFBooleanTrue,
        1,
        &kCFTypeDictionaryKeyCallBacks,
        &kCFTypeDictionaryValueCallBacks
    );
    int trusted = AXIsProcessTrustedWithOptions(options);
    CFRelease(options);
    return trusted;
}

ozayn_result_t ozayn_input_init(void) {
    if (_ozayn_input.initialized) return OZAYN_OK;

    memset(&_ozayn_input, 0, sizeof(OzaynInputState));

    /* Check accessibility permissions */
    if (_ozayn_input_check_accessibility()) {
        _ozayn_input.available = 1;
        _ozayn_input.device_info.has_mouse = 1;
        _ozayn_input.device_info.has_keyboard = 1;
    }

    _ozayn_input.initialized = 1;

    LOG_INFO("INPUT", "Input subsystem initialized (available=%s, accessibility=%s)",
             _ozayn_input.available ? "yes" : "no",
             _ozayn_input_check_accessibility() ? "granted" : "denied");

    return OZAYN_OK;
}

void ozayn_input_shutdown(void) {
    if (!_ozayn_input.initialized) return;

    memset(&_ozayn_input, 0, sizeof(OzaynInputState));
    LOG_INFO("INPUT", "Input subsystem shut down");
}

int ozayn_input_is_available(void) {
    return _ozayn_input.available;
}

ozayn_result_t ozayn_input_device_info(OzaynInputDeviceInfo *info) {
    if (!info) return OZAYN_ERR_NULL;
    if (!_ozayn_input.initialized) return OZAYN_ERR;

    memcpy(info, &_ozayn_input.device_info, sizeof(OzaynInputDeviceInfo));
    return OZAYN_OK;
}

ozayn_result_t ozayn_input_get_mouse_position(int32_t *x, int32_t *y) {
    if (!x || !y) return OZAYN_ERR_NULL;
    if (!_ozayn_input.initialized) return OZAYN_ERR;

    CGEventRef event = CGEventCreate(NULL);
    if (!event) return OZAYN_ERR;

    CGPoint cursor = CGEventGetLocation(event);
    CFRelease(event);

    *x = (int32_t)cursor.x;
    *y = (int32_t)cursor.y;
    return OZAYN_OK;
}

ozayn_result_t ozayn_input_get_mouse_state(OzaynMouseState *state) {
    if (!state) return OZAYN_ERR_NULL;
    if (!_ozayn_input.initialized) return OZAYN_ERR;

    memset(state, 0, sizeof(OzaynMouseState));

    CGEventRef event = CGEventCreate(NULL);
    if (!event) return OZAYN_ERR;

    CGPoint cursor = CGEventGetLocation(event);
    CGEventFlags flags = CGEventGetFlags(event);
    CFRelease(event);

    state->x = (int32_t)cursor.x;
    state->y = (int32_t)cursor.y;
    state->left_button = (flags & kCGEventFlagMaskLeftCluster) ? 1 : 0;
    state->right_button = (flags & kCGEventFlagMaskRightCluster) ? 1 : 0;
    state->available = 1;
    return OZAYN_OK;
}

ozayn_result_t ozayn_input_move_mouse(int32_t x, int32_t y) {
    if (!_ozayn_input.initialized) return OZAYN_ERR;

    CGEventRef move = CGEventCreateMouseEvent(NULL, kCGEventMouseMoved, CGPointMake(x, y), 0);
    if (!move) return OZAYN_ERR;

    CGEventPost(kCGHIDEventTap, move);
    CFRelease(move);
    return OZAYN_OK;
}

static ozayn_result_t _ozayn_input_button_event(CGEventType type, CGMouseButton button) {
    if (!_ozayn_input.initialized) return OZAYN_ERR;

    CGPoint current;
    CGEventRef event = CGEventCreate(NULL);
    if (!event) return OZAYN_ERR;
    current = CGEventGetLocation(event);
    CFRelease(event);

    CGEventRef btn = CGEventCreateMouseEvent(NULL, type, current, button);
    if (!btn) return OZAYN_ERR;

    CGEventPost(kCGHIDEventTap, btn);
    CFRelease(btn);
    return OZAYN_OK;
}

ozayn_result_t ozayn_input_mouse_left_down(void) {
    return _ozayn_input_button_event(kCGEventLeftMouseDown, kCGMouseButtonLeft);
}

ozayn_result_t ozayn_input_mouse_left_up(void) {
    return _ozayn_input_button_event(kCGEventLeftMouseUp, kCGMouseButtonLeft);
}

ozayn_result_t ozayn_input_mouse_right_down(void) {
    return _ozayn_input_button_event(kCGEventRightMouseDown, kCGMouseButtonRight);
}

ozayn_result_t ozayn_input_mouse_right_up(void) {
    return _ozayn_input_button_event(kCGEventRightMouseUp, kCGMouseButtonRight);
}

ozayn_result_t ozayn_input_mouse_middle_down(void) {
    return _ozayn_input_button_event(kCGEventOtherMouseDown, kCGMouseButtonCenter);
}

ozayn_result_t ozayn_input_mouse_middle_up(void) {
    return _ozayn_input_button_event(kCGEventOtherMouseUp, kCGMouseButtonCenter);
}

/* Legacy API compatibility */
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
 * J. Keyboard & Basic Input Event Abstraction (Step 08)
 * ================================================================
 *
 * macOS stub — requires Core Graphics event tap for full implementation.
 * Key state queries return -1 (unsupported) when accessibility
 * permissions are not granted.
 */

static OzaynKeyboardState _ozayn_keyboard = {0};

static const char *_ozayn_key_name_table_mac[OZAYN_KEY_COUNT] = {
    [OZAYN_KEY_UNKNOWN] = "Unknown",
    [OZAYN_KEY_A] = "A", [OZAYN_KEY_B] = "B", [OZAYN_KEY_C] = "C",
    [OZAYN_KEY_D] = "D", [OZAYN_KEY_E] = "E", [OZAYN_KEY_F] = "F",
    [OZAYN_KEY_G] = "G", [OZAYN_KEY_H] = "H", [OZAYN_KEY_I] = "I",
    [OZAYN_KEY_J] = "J", [OZAYN_KEY_K] = "K", [OZAYN_KEY_L] = "L",
    [OZAYN_KEY_M] = "M", [OZAYN_KEY_N] = "N", [OZAYN_KEY_O] = "O",
    [OZAYN_KEY_P] = "P", [OZAYN_KEY_Q] = "Q", [OZAYN_KEY_R] = "R",
    [OZAYN_KEY_S] = "S", [OZAYN_KEY_T] = "T", [OZAYN_KEY_U] = "U",
    [OZAYN_KEY_V] = "V", [OZAYN_KEY_W] = "W", [OZAYN_KEY_X] = "X",
    [OZAYN_KEY_Y] = "Y", [OZAYN_KEY_Z] = "Z",
    [OZAYN_KEY_0] = "0", [OZAYN_KEY_1] = "1", [OZAYN_KEY_2] = "2",
    [OZAYN_KEY_3] = "3", [OZAYN_KEY_4] = "4", [OZAYN_KEY_5] = "5",
    [OZAYN_KEY_6] = "6", [OZAYN_KEY_7] = "7", [OZAYN_KEY_8] = "8",
    [OZAYN_KEY_9] = "9",
    [OZAYN_KEY_ESCAPE] = "Escape", [OZAYN_KEY_ENTER] = "Enter",
    [OZAYN_KEY_TAB] = "Tab", [OZAYN_KEY_SPACE] = "Space",
    [OZAYN_KEY_BACKSPACE] = "Backspace",
    [OZAYN_KEY_SHIFT] = "Shift", [OZAYN_KEY_CTRL] = "Ctrl",
    [OZAYN_KEY_ALT] = "Alt",
    [OZAYN_KEY_UP] = "Up", [OZAYN_KEY_DOWN] = "Down",
    [OZAYN_KEY_LEFT] = "Left", [OZAYN_KEY_RIGHT] = "Right",
    [OZAYN_KEY_HOME] = "Home", [OZAYN_KEY_END] = "End",
    [OZAYN_KEY_PAGE_UP] = "PageUp", [OZAYN_KEY_PAGE_DOWN] = "PageDown",
    [OZAYN_KEY_INSERT] = "Insert", [OZAYN_KEY_DELETE] = "Delete",
    [OZAYN_KEY_F1] = "F1", [OZAYN_KEY_F2] = "F2", [OZAYN_KEY_F3] = "F3",
    [OZAYN_KEY_F4] = "F4", [OZAYN_KEY_F5] = "F5", [OZAYN_KEY_F6] = "F6",
    [OZAYN_KEY_F7] = "F7", [OZAYN_KEY_F8] = "F8", [OZAYN_KEY_F9] = "F9",
    [OZAYN_KEY_F10] = "F10", [OZAYN_KEY_F11] = "F11", [OZAYN_KEY_F12] = "F12",
};

ozayn_result_t ozayn_keyboard_init(void) {
    if (_ozayn_keyboard.initialized) return OZAYN_OK;
    memset(&_ozayn_keyboard, 0, sizeof(OzaynKeyboardState));
    /* macOS requires accessibility permissions for key state queries */
    _ozayn_keyboard.available = _ozayn_input.available;
    _ozayn_keyboard.initialized = 1;
    return OZAYN_OK;
}

void ozayn_keyboard_shutdown(void) {
    if (!_ozayn_keyboard.initialized) return;
    memset(&_ozayn_keyboard, 0, sizeof(OzaynKeyboardState));
}

int ozayn_keyboard_is_available(void) {
    return _ozayn_keyboard.available;
}

int ozayn_keyboard_is_key_down(OzaynKey key) {
    (void)key;
    if (!_ozayn_keyboard.initialized || !_ozayn_keyboard.available) return -1;
    /* TODO: CGEventGetFlags / CGEventSource flags */
    return -1;
}

ozayn_result_t ozayn_keyboard_poll_event(OzaynInputEvent *event) {
    if (!event) return OZAYN_ERR_NULL;
    if (!_ozayn_keyboard.initialized) return OZAYN_ERR;
    event->type = OZAYN_INPUT_EVENT_NONE;
    event->key = OZAYN_KEY_UNKNOWN;
    event->modifiers = 0;
    return OZAYN_ERR;
}

const char *ozayn_key_name(OzaynKey key) {
    if (key <= OZAYN_KEY_UNKNOWN || key >= OZAYN_KEY_COUNT) return "Unknown";
    const char *name = _ozayn_key_name_table_mac[key];
    return name ? name : "Unknown";
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
