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
 * H. Microphone Device Abstraction (Step 10)
 * ================================================================
 *
 * macOS stub — requires Core Audio / AVFoundation for full implementation.
 * Microphone privacy permissions are required.
 */

static OzaynMicrophoneState _ozayn_mic = {0};

ozayn_result_t ozayn_microphone_init(void) {
    if (_ozayn_mic.initialized) return OZAYN_OK;
    memset(&_ozayn_mic, 0, sizeof(OzaynMicrophoneState));
    /* TODO: AVAudioSession / Core Audio device enumeration */
    _ozayn_mic.initialized = 1;
    return OZAYN_OK;
}

void ozayn_microphone_shutdown(void) {
    if (!_ozayn_mic.initialized) return;
    memset(&_ozayn_mic, 0, sizeof(OzaynMicrophoneState));
}

int ozayn_microphone_is_available(void) {
    return _ozayn_mic.available;
}

unsigned int ozayn_microphone_get_count(void) {
    if (!_ozayn_mic.initialized) return 0;
    return _ozayn_mic.count;
}

ozayn_result_t ozayn_microphone_get_info(unsigned int index, OzaynMicrophoneInfo *info) {
    if (!info) return OZAYN_ERR_NULL;
    if (!_ozayn_mic.initialized) return OZAYN_ERR;
    if (index >= _ozayn_mic.count) return OZAYN_ERR;
    memset(info, 0, sizeof(OzaynMicrophoneInfo));
    return OZAYN_OK;
}

ozayn_result_t ozayn_microphone_open(unsigned int index) {
    (void)index;
    if (!_ozayn_mic.initialized) return OZAYN_ERR;
    return OZAYN_ERR;
}

ozayn_result_t ozayn_microphone_close(void) {
    if (!_ozayn_mic.initialized) return OZAYN_ERR;
    return OZAYN_ERR;
}

ozayn_result_t ozayn_microphone_start(void) {
    if (!_ozayn_mic.initialized) return OZAYN_ERR;
    return OZAYN_ERR;
}

ozayn_result_t ozayn_microphone_stop(void) {
    if (!_ozayn_mic.initialized) return OZAYN_ERR;
    return OZAYN_ERR;
}

ozayn_result_t ozayn_microphone_capture(OzaynAudioBuffer *buffer) {
    if (!buffer) return OZAYN_ERR_NULL;
    if (!_ozayn_mic.initialized) return OZAYN_ERR;
    memset(buffer, 0, sizeof(OzaynAudioBuffer));
    return OZAYN_ERR;
}

void ozayn_microphone_buffer_release(OzaynAudioBuffer *buffer) {
    if (!buffer) return;
    if (buffer->data) {
        free(buffer->data);
    }
    buffer->data = NULL;
    buffer->data_size = 0;
    buffer->frame_count = 0;
    buffer->sample_rate = 0;
    buffer->channels = 0;
    buffer->format = OZAYN_AUDIO_FORMAT_UNKNOWN;
}

/* ================================================================
 * K. Audio Output / Speaker Abstraction (Step 11)
 * ================================================================
 *
 * macOS stub — requires Core Audio / AVFoundation for full
 * implementation.
 */

static OzaynAudioOutputState _ozayn_speaker = {0};

ozayn_result_t ozayn_audio_output_init(void) {
    if (_ozayn_speaker.initialized) return OZAYN_OK;
    memset(&_ozayn_speaker, 0, sizeof(OzaynAudioOutputState));
    _ozayn_speaker.initialized = 1;
    LOG_INFO("SPEAKER", "Audio output subsystem initialized (stub, available=no)");
    return OZAYN_OK;
}

void ozayn_audio_output_shutdown(void) {
    if (!_ozayn_speaker.initialized) return;
    memset(&_ozayn_speaker, 0, sizeof(OzaynAudioOutputState));
    LOG_INFO("SPEAKER", "Audio output subsystem shut down");
}

int ozayn_audio_output_is_available(void) {
    return _ozayn_speaker.available;
}

unsigned int ozayn_audio_output_get_count(void) {
    if (!_ozayn_speaker.initialized) return 0;
    return _ozayn_speaker.count;
}

ozayn_result_t ozayn_audio_output_get_info(unsigned int index, OzaynAudioOutputInfo *info) {
    if (!info) return OZAYN_ERR_NULL;
    if (!_ozayn_speaker.initialized) return OZAYN_ERR;
    if (index >= _ozayn_speaker.count) return OZAYN_ERR;
    memset(info, 0, sizeof(OzaynAudioOutputInfo));
    return OZAYN_OK;
}

ozayn_result_t ozayn_audio_output_open(unsigned int index) {
    (void)index;
    return OZAYN_ERR;
}

ozayn_result_t ozayn_audio_output_close(void) {
    return OZAYN_ERR;
}

ozayn_result_t ozayn_audio_output_start(void) {
    return OZAYN_ERR;
}

ozayn_result_t ozayn_audio_output_write(const OzaynAudioOutputBuffer *buffer) {
    (void)buffer;
    return OZAYN_ERR;
}

ozayn_result_t ozayn_audio_output_stop(void) {
    return OZAYN_ERR;
}

/* ================================================================
 * L. Network Information & Connectivity Abstraction (Step 12)
 * ================================================================
 *
 * macOS stub — requires SystemConfiguration / IOKit for full
 * implementation.
 */

static OzaynNetworkState _ozayn_net = {0};

ozayn_result_t ozayn_network_init(void) {
    if (_ozayn_net.initialized) return OZAYN_OK;
    memset(&_ozayn_net, 0, sizeof(OzaynNetworkState));
    _ozayn_net.initialized = 1;
    LOG_INFO("NETWORK", "Network subsystem initialized (stub, available=no)");
    return OZAYN_OK;
}

void ozayn_network_shutdown(void) {
    if (!_ozayn_net.initialized) return;
    memset(&_ozayn_net, 0, sizeof(OzaynNetworkState));
    LOG_INFO("NETWORK", "Network subsystem shut down");
}

int ozayn_network_is_available(void) {
    return _ozayn_net.available;
}

unsigned int ozayn_network_get_interface_count(void) {
    if (!_ozayn_net.initialized) return 0;
    return _ozayn_net.count;
}

ozayn_result_t ozayn_network_get_interface_info(unsigned int index, OzaynNetworkInterfaceInfo *info) {
    if (!info) return OZAYN_ERR_NULL;
    if (!_ozayn_net.initialized) return OZAYN_ERR;
    if (index >= _ozayn_net.count) return OZAYN_ERR;
    memset(info, 0, sizeof(OzaynNetworkInterfaceInfo));
    return OZAYN_OK;
}

int ozayn_network_get_default_interface(void) {
    if (!_ozayn_net.initialized) return -1;
    return _ozayn_net.has_default ? _ozayn_net.default_index : -1;
}

OzaynConnectivityState ozayn_network_is_connected(void) {
    return OZAYN_CONNECTIVITY_UNKNOWN;
}

/* ================================================================
 * M. Power & Battery Information Abstraction (Step 13)
 * ================================================================
 *
 * macOS stub — requires IOKit / Core Foundation for full
 * implementation.
 */

static OzaynPowerInfo _ozayn_power = {0};

ozayn_result_t ozayn_power_init(void) {
    if (_ozayn_power.available) return OZAYN_OK;
    memset(&_ozayn_power, 0, sizeof(OzaynPowerInfo));
    _ozayn_power.available = 1;
    LOG_INFO("POWER", "Power subsystem initialized (stub, battery=unknown)");
    return OZAYN_OK;
}

void ozayn_power_shutdown(void) {
    if (!_ozayn_power.available) return;
    memset(&_ozayn_power, 0, sizeof(OzaynPowerInfo));
    LOG_INFO("POWER", "Power subsystem shut down");
}

int ozayn_power_is_available(void) {
    return _ozayn_power.available;
}

ozayn_result_t ozayn_power_get_info(OzaynPowerInfo *info) {
    if (!info) return OZAYN_ERR_NULL;
    if (!_ozayn_power.available) return OZAYN_ERR;
    memcpy(info, &_ozayn_power, sizeof(OzaynPowerInfo));
    return OZAYN_OK;
}

int ozayn_power_has_battery(void) {
    return _ozayn_power.has_battery;
}

int ozayn_power_get_battery_percent(void) {
    return _ozayn_power.battery_percent;
}

int ozayn_power_is_charging(void) {
    return _ozayn_power.charging;
}

int ozayn_power_is_plugged_in(void) {
    return _ozayn_power.plugged_in;
}

/* ================================================================
 * N. Notification System Abstraction (Step 14)
 * ================================================================
 *
 * macOS stub — requires UserNotifications framework for full
 * implementation.
 */

static int _ozayn_notif_initialized = 0;
static int _ozayn_notif_available = 0;

ozayn_result_t ozayn_notification_init(void) {
    if (_ozayn_notif_initialized) return OZAYN_OK;
    _ozayn_notif_initialized = 1;
    _ozayn_notif_available = 0;
    LOG_INFO("NOTIFY", "Notification subsystem initialized (stub, available=no)");
    return OZAYN_OK;
}

void ozayn_notification_shutdown(void) {
    if (!_ozayn_notif_initialized) return;
    _ozayn_notif_initialized = 0;
    _ozayn_notif_available = 0;
    LOG_INFO("NOTIFY", "Notification subsystem shut down");
}

int ozayn_notification_is_available(void) {
    return _ozayn_notif_available;
}

ozayn_result_t ozayn_notification_send(const OzaynNotification *notification) {
    (void)notification;
    return OZAYN_ERR;
}

/* ================================================================
 * O. Clipboard Abstraction (Step 15)
 * ================================================================
 *
 * macOS stub — requires Pasteboard framework for full implementation.
 */

static int _ozayn_clip_initialized = 0;
static int _ozayn_clip_available = 0;

ozayn_result_t ozayn_clipboard_init(void) {
    if (_ozayn_clip_initialized) return OZAYN_OK;
    _ozayn_clip_initialized = 1;
    _ozayn_clip_available = 0;
    LOG_INFO("CLIPBOARD", "Clipboard subsystem initialized (stub, available=no)");
    return OZAYN_OK;
}

void ozayn_clipboard_shutdown(void) {
    if (!_ozayn_clip_initialized) return;
    _ozayn_clip_initialized = 0;
    _ozayn_clip_available = 0;
    LOG_INFO("CLIPBOARD", "Clipboard subsystem shut down");
}

int ozayn_clipboard_is_available(void) {
    return _ozayn_clip_available;
}

int ozayn_clipboard_has_text(void) {
    return 0;
}

ozayn_result_t ozayn_clipboard_get_text(char *buffer, size_t buffer_size, size_t *required_size) {
    (void)buffer;
    (void)buffer_size;
    if (required_size) *required_size = 0;
    return OZAYN_ERR;
}

ozayn_result_t ozayn_clipboard_set_text(const char *text) {
    (void)text;
    return OZAYN_ERR;
}

ozayn_result_t ozayn_clipboard_clear(void) {
    return OZAYN_ERR;
}

/* ================================================================
 * P. Environment & User Session Abstraction (Step 16)
 * ================================================================
 *
 * macOS stub — requires NSProcessInfo / NSFileManager for full
 * implementation. Uses POSIX fallbacks where possible.
 */

#include <unistd.h>
#include <limits.h>
#include <pwd.h>

static int _ozayn_env_initialized = 0;

ozayn_result_t ozayn_environment_init(void) {
    if (_ozayn_env_initialized) return OZAYN_OK;
    _ozayn_env_initialized = 1;
    LOG_INFO("ENV", "Environment subsystem initialized");
    return OZAYN_OK;
}

void ozayn_environment_shutdown(void) {
    if (!_ozayn_env_initialized) return;
    _ozayn_env_initialized = 0;
    LOG_INFO("ENV", "Environment subsystem shut down");
}

int ozayn_environment_is_available(void) {
    return _ozayn_env_initialized;
}

ozayn_result_t ozayn_environment_get_variable(const char *name,
                                               char *buffer,
                                               size_t buffer_size,
                                               size_t *required_size) {
    if (!name || name[0] == '\0') return OZAYN_ERR_NULL;
    if (!_ozayn_env_initialized) return OZAYN_ERR;

    const char *value = getenv(name);
    if (!value) {
        if (buffer && buffer_size > 0) buffer[0] = '\0';
        if (required_size) *required_size = 0;
        return OZAYN_OK;
    }

    size_t len = strlen(value);
    if (required_size) *required_size = len + 1;

    if (!buffer || buffer_size == 0) return OZAYN_OK;

    size_t copy_len = (len < buffer_size - 1) ? len : buffer_size - 1;
    memcpy(buffer, value, copy_len);
    buffer[copy_len] = '\0';

    return OZAYN_OK;
}

ozayn_result_t ozayn_environment_get_home_directory(char *buffer, size_t buffer_size) {
    if (!buffer || buffer_size == 0) return OZAYN_ERR_NULL;
    if (!_ozayn_env_initialized) return OZAYN_ERR;

    const char *home = getenv("HOME");
    if (!home) {
        struct passwd *pw = getpwuid(getuid());
        if (pw) home = pw->pw_dir;
    }

    if (!home) {
        buffer[0] = '\0';
        return OZAYN_ERR;
    }

    size_t len = strlen(home);
    size_t copy_len = (len < buffer_size - 1) ? len : buffer_size - 1;
    memcpy(buffer, home, copy_len);
    buffer[copy_len] = '\0';

    return OZAYN_OK;
}

ozayn_result_t ozayn_environment_get_temp_directory(char *buffer, size_t buffer_size) {
    if (!buffer || buffer_size == 0) return OZAYN_ERR_NULL;
    if (!_ozayn_env_initialized) return OZAYN_ERR;

    const char *tmp = getenv("TMPDIR");
    if (!tmp) tmp = "/tmp";

    size_t len = strlen(tmp);
    size_t copy_len = (len < buffer_size - 1) ? len : buffer_size - 1;
    memcpy(buffer, tmp, copy_len);
    buffer[copy_len] = '\0';

    return OZAYN_OK;
}

ozayn_result_t ozayn_environment_get_current_directory(char *buffer, size_t buffer_size) {
    if (!buffer || buffer_size == 0) return OZAYN_ERR_NULL;
    if (!_ozayn_env_initialized) return OZAYN_ERR;

    char cwd[PATH_MAX];
    if (getcwd(cwd, sizeof(cwd)) == NULL) {
        buffer[0] = '\0';
        return OZAYN_ERR;
    }

    size_t len = strlen(cwd);
    size_t copy_len = (len < buffer_size - 1) ? len : buffer_size - 1;
    memcpy(buffer, cwd, copy_len);
    buffer[copy_len] = '\0';

    return OZAYN_OK;
}

ozayn_result_t ozayn_environment_get_username(char *buffer, size_t buffer_size) {
    if (!buffer || buffer_size == 0) return OZAYN_ERR_NULL;
    if (!_ozayn_env_initialized) return OZAYN_ERR;

    const char *user = getenv("USER");
    if (!user) {
        struct passwd *pw = getpwuid(getuid());
        if (pw) user = pw->pw_name;
    }

    if (!user) {
        buffer[0] = '\0';
        return OZAYN_ERR;
    }

    size_t len = strlen(user);
    size_t copy_len = (len < buffer_size - 1) ? len : buffer_size - 1;
    memcpy(buffer, user, copy_len);
    buffer[copy_len] = '\0';

    return OZAYN_OK;
}

ozayn_result_t ozayn_environment_get_hostname(char *buffer, size_t buffer_size) {
    if (!buffer || buffer_size == 0) return OZAYN_ERR_NULL;
    if (!_ozayn_env_initialized) return OZAYN_ERR;

    char host[256];
    if (gethostname(host, sizeof(host)) != 0) {
        buffer[0] = '\0';
        return OZAYN_ERR;
    }
    host[255] = '\0';

    size_t len = strlen(host);
    size_t copy_len = (len < buffer_size - 1) ? len : buffer_size - 1;
    memcpy(buffer, host, copy_len);
    buffer[copy_len] = '\0';

    return OZAYN_OK;
}

/* ================================================================
 * Q. System Time & Date Abstraction (Step 17)
 * ================================================================
 *
 * macOS implementation using POSIX time APIs.
 * Read-only — no clock modification, no timezone changes.
 */

#include <time.h>
#include <unistd.h>
#include <sys/time.h>

static int _ozayn_time_initialized = 0;

ozayn_result_t ozayn_time_init(void) {
    if (_ozayn_time_initialized) return OZAYN_OK;
    _ozayn_time_initialized = 1;
    LOG_INFO("TIME", "Time subsystem initialized");
    return OZAYN_OK;
}

void ozayn_time_shutdown(void) {
    if (!_ozayn_time_initialized) return;
    _ozayn_time_initialized = 0;
    LOG_INFO("TIME", "Time subsystem shut down");
}

int ozayn_time_is_available(void) {
    return _ozayn_time_initialized;
}

int64_t ozayn_time_unix_seconds(void) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (int64_t)ts.tv_sec;
}

int64_t ozayn_time_unix_milliseconds(void) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (int64_t)ts.tv_sec * 1000 + (int64_t)ts.tv_nsec / 1000000;
}

int64_t ozayn_time_unix_microseconds(void) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (int64_t)ts.tv_sec * 1000000 + (int64_t)ts.tv_nsec / 1000;
}

static void _ozayn_time_fill_local(struct tm *tm_info, OzaynDateTime *dt) {
    dt->year = tm_info->tm_year + 1900;
    dt->month = tm_info->tm_mon + 1;
    dt->day = tm_info->tm_mday;
    dt->hour = tm_info->tm_hour;
    dt->minute = tm_info->tm_min;
    dt->second = tm_info->tm_sec;
    dt->millisecond = 0;

    /* Calculate UTC offset in minutes */
    struct tm local_tm = *tm_info;
    struct tm utc_tm;
    time_t raw = mktime(tm_info);
    gmtime_r(&raw, &utc_tm);
    dt->utc_offset_minutes = (int)difftime(mktime(&local_tm), mktime(&utc_tm)) / 60;
}

ozayn_result_t ozayn_time_get_local(OzaynDateTime *datetime) {
    if (!datetime) return OZAYN_ERR_NULL;
    if (!_ozayn_time_initialized) return OZAYN_ERR;

    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);

    struct tm tm_info;
    localtime_r(&ts.tv_sec, &tm_info);

    _ozayn_time_fill_local(&tm_info, datetime);
    datetime->millisecond = (int)(ts.tv_nsec / 1000000);

    return OZAYN_OK;
}

ozayn_result_t ozayn_time_get_utc(OzaynDateTime *datetime) {
    if (!datetime) return OZAYN_ERR_NULL;
    if (!_ozayn_time_initialized) return OZAYN_ERR;

    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);

    struct tm tm_info;
    gmtime_r(&ts.tv_sec, &tm_info);

    datetime->year = tm_info.tm_year + 1900;
    datetime->month = tm_info.tm_mon + 1;
    datetime->day = tm_info.tm_mday;
    datetime->hour = tm_info.tm_hour;
    datetime->minute = tm_info.tm_min;
    datetime->second = tm_info.tm_sec;
    datetime->millisecond = (int)(ts.tv_nsec / 1000000);
    datetime->utc_offset_minutes = 0;

    return OZAYN_OK;
}

ozayn_result_t ozayn_time_sleep_ms(uint64_t milliseconds) {
    if (!_ozayn_time_initialized) return OZAYN_ERR;

    if (milliseconds == 0) {
        sched_yield();
        return OZAYN_OK;
    }

    struct timespec ts;
    ts.tv_sec = (time_t)(milliseconds / 1000);
    ts.tv_nsec = (long)((milliseconds % 1000) * 1000000);

    nanosleep(&ts, NULL);

    return OZAYN_OK;
}

/* ================================================================
 * R. Application Launch & Discovery Abstraction (Step 18)
 * ================================================================
 *
 * macOS stub — requires NSWorkspace/AppleScript for full implementation.
 * Uses POSIX fork()+execvp() with fallbacks.
 */

#include <libgen.h>
#include <ctype.h>

static int _ozayn_application_initialized = 0;

/* Internal helper: check if a file is executable at the given path */
static int _ozayn_app_is_executable(const char *path) {
    if (!path || !*path) return 0;
    struct stat st;
    if (stat(path, &st) != 0) return 0;
    return S_ISREG(st.st_mode) && (st.st_mode & (S_IXUSR | S_IXGRP | S_IXOTH));
}

/* Internal helper: search for application in PATH directories */
static int _ozayn_app_search_path(const char *app) {
    if (!app || !*app) return 0;

    if (strchr(app, '/') != NULL) {
        return _ozayn_app_is_executable(app);
    }

    const char *path_env = getenv("PATH");
    if (!path_env) return 0;

    char path_buf[4096];
    size_t path_len = strlen(path_env);
    if (path_len >= sizeof(path_buf)) path_len = sizeof(path_buf) - 1;
    memcpy(path_buf, path_env, path_len);
    path_buf[path_len] = '\0';

    char *saveptr = NULL;
    char *dir = strtok_r(path_buf, ":", &saveptr);

    while (dir) {
        if (*dir) {
            char fullpath[4096];
            snprintf(fullpath, sizeof(fullpath), "%s/%s", dir, app);
            if (_ozayn_app_is_executable(fullpath)) {
                return 1;
            }
        }
        dir = strtok_r(NULL, ":", &saveptr);
    }

    return 0;
}

/* Internal helper: find URL opener */
static const char* _ozayn_find_url_opener(void) {
    const char *openers[] = { "open", "xdg-open", NULL };
    for (int i = 0; openers[i]; i++) {
        if (_ozayn_app_search_path(openers[i])) {
            return openers[i];
        }
    }
    return NULL;
}

/* Internal helper: check URL scheme */
static int _ozayn_is_valid_url_scheme(const char *url) {
    if (!url) return 0;
    const char *valid[] = { "http://", "https://", "ftp://", "mailto:", NULL };
    for (int i = 0; valid[i]; i++) {
        size_t len = strlen(valid[i]);
        if (strncmp(url, valid[i], len) == 0) return 1;
    }
    return 0;
}

/* Internal helper: find default browser */
static ozayn_result_t _ozayn_get_default_browser_xdg(char *buffer, size_t buffer_size) {
    if (!buffer || buffer_size == 0) return OZAYN_ERR_NULL;

    /* Try xdg-settings */
    if (_ozayn_app_search_path("xdg-settings")) {
        int pipefd[2];
        if (pipe(pipefd) == 0) {
            pid_t pid = fork();
            if (pid == 0) {
                close(pipefd[0]);
                dup2(pipefd[1], STDOUT_FILENO);
                close(pipefd[1]);
                execlp("xdg-settings", "xdg-settings", "get", "default-web-browser", (char *)NULL);
                _exit(127);
            } else if (pid > 0) {
                close(pipefd[1]);
                char result[1024] = {0};
                ssize_t total = 0;
                ssize_t n;
                while ((n = read(pipefd[0], result + total, sizeof(result) - total - 1)) > 0) {
                    total += n;
                }
                close(pipefd[0]);
                int status;
                waitpid(pid, &status, 0);
                if (WIFEXITED(status) && WEXITSTATUS(status) == 0 && total > 0) {
                    while (total > 0 && (result[total-1] == '\n' || result[total-1] == '\r')) {
                        result[--total] = '\0';
                    }
                    size_t copy_len = strlen(result);
                    if (copy_len >= buffer_size) copy_len = buffer_size - 1;
                    memcpy(buffer, result, copy_len);
                    buffer[copy_len] = '\0';
                    return OZAYN_OK;
                }
            }
        }
    }

    /* Fallback: find common browsers */
    const char *browsers[] = {
        "safari", "firefox", "google-chrome", "chromium", "opera",
        "brave-browser", "vivaldi", "lynx", NULL
    };
    for (int i = 0; browsers[i]; i++) {
        if (_ozayn_app_search_path(browsers[i])) {
            size_t len = strlen(browsers[i]);
            if (len >= buffer_size) len = buffer_size - 1;
            memcpy(buffer, browsers[i], len);
            buffer[len] = '\0';
            return OZAYN_OK;
        }
    }

    return OZAYN_ERR;
}

ozayn_result_t ozayn_application_init(void) {
    if (_ozayn_application_initialized) return OZAYN_OK;
    _ozayn_application_initialized = 1;
    LOG_INFO("APP", "Application subsystem initialized");
    return OZAYN_OK;
}

void ozayn_application_shutdown(void) {
    if (!_ozayn_application_initialized) return;
    _ozayn_application_initialized = 0;
    LOG_INFO("APP", "Application subsystem shut down");
}

int ozayn_application_is_available(void) {
    return _ozayn_application_initialized;
}

ozayn_result_t ozayn_application_launch(const char *application) {
    if (!application) return OZAYN_ERR_NULL;
    if (!*application) return OZAYN_ERR;
    if (!_ozayn_application_initialized) return OZAYN_ERR;

    char fullpath[4096] = {0};
    int found = 0;

    if (strchr(application, '/') != NULL) {
        if (_ozayn_app_is_executable(application)) {
            size_t len = strlen(application);
            if (len >= sizeof(fullpath)) len = sizeof(fullpath) - 1;
            memcpy(fullpath, application, len);
            fullpath[len] = '\0';
            found = 1;
        }
    } else {
        const char *path_env = getenv("PATH");
        if (path_env) {
            char path_buf[4096];
            size_t path_len = strlen(path_env);
            if (path_len >= sizeof(path_buf)) path_len = sizeof(path_buf) - 1;
            memcpy(path_buf, path_env, path_len);
            path_buf[path_len] = '\0';
            char *saveptr = NULL;
            char *dir = strtok_r(path_buf, ":", &saveptr);
            while (dir && !found) {
                if (*dir) {
                    snprintf(fullpath, sizeof(fullpath), "%s/%s", dir, application);
                    if (_ozayn_app_is_executable(fullpath)) found = 1;
                }
                dir = strtok_r(NULL, ":", &saveptr);
            }
        }
    }

    if (!found) return OZAYN_ERR;

    pid_t pid = fork();
    if (pid == 0) {
        setsid();
        execl(fullpath, application, (char *)NULL);
        _exit(127);
    } else if (pid > 0) {
        int status;
        int wait_result = waitpid(pid, &status, WNOHANG);
        if (wait_result > 0 && WIFEXITED(status) && WEXITSTATUS(status) == 127) {
            return OZAYN_ERR;
        }
        return OZAYN_OK;
    }

    return OZAYN_ERR;
}

int ozayn_application_exists(const char *application) {
    if (!application) return 0;
    if (!*application) return 0;
    if (!_ozayn_application_initialized) return 0;
    return _ozayn_app_search_path(application);
}

ozayn_result_t ozayn_application_get_default_browser(char *buffer, size_t buffer_size) {
    if (!buffer || buffer_size == 0) return OZAYN_ERR_NULL;
    if (!_ozayn_application_initialized) return OZAYN_ERR;
    return _ozayn_get_default_browser_xdg(buffer, buffer_size);
}

ozayn_result_t ozayn_application_open_url(const char *url) {
    if (!url) return OZAYN_ERR_NULL;
    if (!*url) return OZAYN_ERR;
    if (!_ozayn_application_initialized) return OZAYN_ERR;
    if (!_ozayn_is_valid_url_scheme(url)) return OZAYN_ERR;

    const char *opener = _ozayn_find_url_opener();
    if (!opener) return OZAYN_ERR;

    pid_t pid = fork();
    if (pid == 0) {
        setsid();
        execlp(opener, opener, url, (char *)NULL);
        _exit(127);
    } else if (pid > 0) {
        int status;
        int wait_result = waitpid(pid, &status, WNOHANG);
        if (wait_result > 0 && WIFEXITED(status) && WEXITSTATUS(status) == 127) {
            return OZAYN_ERR;
        }
        return OZAYN_OK;
    }

    return OZAYN_ERR;
}

/* ================================================================
 * S. System Permissions & Capability Access Abstraction (Step 19)
 * ================================================================
 *
 * macOS stub — requires CoreFoundation/Security framework for full implementation.
 * Reports UNKNOWN for most capabilities on macOS without proper API access.
 */

static int _ozayn_permissions_initialized = 0;

ozayn_result_t ozayn_permissions_init(void) {
    if (_ozayn_permissions_initialized) return OZAYN_OK;
    _ozayn_permissions_initialized = 1;
    LOG_INFO("PERM", "Permissions subsystem initialized");
    return OZAYN_OK;
}

void ozayn_permissions_shutdown(void) {
    if (!_ozayn_permissions_initialized) return;
    _ozayn_permissions_initialized = 0;
    LOG_INFO("PERM", "Permissions subsystem shut down");
}

int ozayn_permissions_is_available(void) {
    return _ozayn_permissions_initialized;
}

OzaynPermissionState ozayn_permissions_get_state(OzaynCapability capability) {
    if (!_ozayn_permissions_initialized) return OZAYN_PERMISSION_UNKNOWN;

    switch (capability) {
        case OZAYN_CAP_FILESYSTEM:
            return OZAYN_PERMISSION_AVAILABLE;
        case OZAYN_CAP_NETWORK:
            return OZAYN_PERMISSION_AVAILABLE;
        case OZAYN_CAP_CAMERA:
        case OZAYN_CAP_MICROPHONE:
        case OZAYN_CAP_NOTIFICATIONS:
        case OZAYN_CAP_ACCESSIBILITY:
            return OZAYN_PERMISSION_UNKNOWN;
        default:
            return OZAYN_PERMISSION_UNKNOWN;
    }
}

const char *ozayn_capability_get_name(OzaynCapability capability) {
    switch (capability) {
        case OZAYN_CAP_UNKNOWN:        return "Unknown";
        case OZAYN_CAP_CAMERA:         return "Camera";
        case OZAYN_CAP_MICROPHONE:     return "Microphone";
        case OZAYN_CAP_NOTIFICATIONS:  return "Notifications";
        case OZAYN_CAP_ACCESSIBILITY:  return "Accessibility";
        case OZAYN_CAP_FILESYSTEM:     return "Filesystem";
        case OZAYN_CAP_NETWORK:        return "Network";
        default:                       return "Invalid";
    }
}

const char *ozayn_permission_state_name(OzaynPermissionState state) {
    switch (state) {
        case OZAYN_PERMISSION_UNKNOWN:     return "Unknown";
        case OZAYN_PERMISSION_AVAILABLE:   return "Available";
        case OZAYN_PERMISSION_GRANTED:     return "Granted";
        case OZAYN_PERMISSION_DENIED:      return "Denied";
        case OZAYN_PERMISSION_RESTRICTED:  return "Restricted";
        case OZAYN_PERMISSION_UNAVAILABLE: return "Unavailable";
        default:                           return "Invalid";
    }
}

/* ================================================================
 * T. System Audio Volume & Mute Abstraction (Step 20)
 * ================================================================
 *
 * macOS stub — requires Core Audio for full implementation.
 * Reports unavailable without proper API access.
 */

static int _ozayn_audio_volume_initialized = 0;

ozayn_result_t ozayn_audio_volume_init(void) {
    if (_ozayn_audio_volume_initialized) return OZAYN_OK;
    _ozayn_audio_volume_initialized = 1;
    LOG_INFO("VOL", "Audio volume subsystem initialized");
    return OZAYN_OK;
}

void ozayn_audio_volume_shutdown(void) {
    if (!_ozayn_audio_volume_initialized) return;
    _ozayn_audio_volume_initialized = 0;
    LOG_INFO("VOL", "Audio volume subsystem shut down");
}

int ozayn_audio_volume_is_available(void) {
    if (!_ozayn_audio_volume_initialized) return 0;
    return 0;
}

ozayn_result_t ozayn_audio_volume_get(int *volume) {
    if (!volume) return OZAYN_ERR_NULL;
    if (!_ozayn_audio_volume_initialized) return OZAYN_ERR;
    *volume = 0;
    return OZAYN_ERR;
}

ozayn_result_t ozayn_audio_volume_set(int volume) {
    if (volume < 0 || volume > 100) return OZAYN_ERR;
    if (!_ozayn_audio_volume_initialized) return OZAYN_ERR;
    return OZAYN_ERR;
}

ozayn_result_t ozayn_audio_volume_is_muted(int *muted) {
    if (!muted) return OZAYN_ERR_NULL;
    if (!_ozayn_audio_volume_initialized) return OZAYN_ERR;
    *muted = 0;
    return OZAYN_ERR;
}

ozayn_result_t ozayn_audio_volume_set_muted(int muted) {
    (void)muted;
    if (!_ozayn_audio_volume_initialized) return OZAYN_ERR;
    return OZAYN_ERR;
}

ozayn_result_t ozayn_audio_volume_toggle_mute(void) {
    if (!_ozayn_audio_volume_initialized) return OZAYN_ERR;
    return OZAYN_ERR;
}

/* ================================================================
 * U. System Lock State & Session Control Abstraction (Step 21)
 * ================================================================
 *
 * macOS stub — requires CoreGraphics for session state detection.
 * Reports unavailable without proper API access.
 */

static int _ozayn_session_initialized = 0;

ozayn_result_t ozayn_session_init(void) {
    if (_ozayn_session_initialized) return OZAYN_OK;
    _ozayn_session_initialized = 1;
    LOG_INFO("SESSION", "Session subsystem initialized");
    return OZAYN_OK;
}

void ozayn_session_shutdown(void) {
    if (!_ozayn_session_initialized) return;
    _ozayn_session_initialized = 0;
    LOG_INFO("SESSION", "Session subsystem shut down");
}

int ozayn_session_is_available(void) {
    if (!_ozayn_session_initialized) return 0;
    return 0;
}

OzaynSessionState ozayn_session_get_state(void) {
    if (!_ozayn_session_initialized) return OZAYN_SESSION_UNKNOWN;
    return OZAYN_SESSION_UNAVAILABLE;
}

int ozayn_session_is_locked(void) {
    if (!_ozayn_session_initialized) return 0;
    return 0;
}

const char *ozayn_session_state_name(OzaynSessionState state) {
    switch (state) {
        case OZAYN_SESSION_UNKNOWN:     return "Unknown";
        case OZAYN_SESSION_ACTIVE:      return "Active";
        case OZAYN_SESSION_LOCKED:      return "Locked";
        case OZAYN_SESSION_INACTIVE:    return "Inactive";
        case OZAYN_SESSION_UNAVAILABLE: return "Unavailable";
        default:                        return "Invalid";
    }
}

ozayn_result_t ozayn_session_lock(void) {
    if (!_ozayn_session_initialized) return OZAYN_ERR;
    return OZAYN_ERR;
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
