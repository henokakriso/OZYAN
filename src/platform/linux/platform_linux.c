#define _DEFAULT_SOURCE
#include "platform.h"
#include "logger.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/utsname.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/sysinfo.h>
#include <dirent.h>
#include <signal.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <net/if.h>
#include <ifaddrs.h>
#include <arpa/inet.h>

/* X11 headers for input abstraction */
#ifdef OZAYN_OS_LINUX
#include <X11/Xlib.h>
#include <X11/Xutil.h>
#include <X11/extensions/XTest.h>
#include <X11/keysym.h>
#include <X11/extensions/scrnsaver.h>
#endif

/* V4L2 headers for camera abstraction */
#ifdef OZAYN_OS_LINUX
#include <linux/videodev2.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#endif

/* ALSA headers for microphone abstraction */
#ifdef OZAYN_OS_LINUX
#include <alsa/asoundlib.h>
#endif

/*
 * platform_linux.c — Linux platform implementation.
 *
 * Implements the common platform API using Linux-specific syscalls.
 */

/* ================================================================
 * A. System Information
 * ================================================================ */

ozayn_result_t ozayn_system_info(ozayn_system_info_t *info) {
    if (!info) return OZAYN_ERR_NULL;
    memset(info, 0, sizeof(ozayn_system_info_t));

    /* OS name and version */
    struct utsname uts;
    if (uname(&uts) == 0) {
        strncpy(info->os_name, uts.sysname, OZAYN_MAX_SYSTEM_STR - 1);
        strncpy(info->os_version, uts.release, OZAYN_MAX_SYSTEM_STR - 1);
        strncpy(info->arch, uts.machine, sizeof(info->arch) - 1);
    } else {
        strncpy(info->os_name, "Linux", OZAYN_MAX_SYSTEM_STR - 1);
        strncpy(info->arch, OZAYN_ARCH_NAME, sizeof(info->arch) - 1);
    }

    /* Hostname */
    if (gethostname(info->hostname, OZAYN_MAX_SYSTEM_STR - 1) != 0) {
        strncpy(info->hostname, "unknown", OZAYN_MAX_SYSTEM_STR - 1);
    }

    /* Memory */
    struct sysinfo si;
    if (sysinfo(&si) == 0) {
        info->total_memory_mb = (si.totalram * si.mem_unit) / (1024 * 1024);
        info->uptime_seconds = si.uptime;
    }

    /* CPU cores */
    long cores = sysconf(_SC_NPROCESSORS_ONLN);
    if (cores > 0) info->cpu_cores = (uint32_t)cores;

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

    /* Read command line (first argument is the executable) */
    size_t n = fread(info->executable, 1, OZAYN_MAX_PATH - 1, f);
    fclose(f);

    if (n > 0) {
        info->executable[n] = '\0';
        /* Extract basename */
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

    /* Pipe for child error reporting */
    int err_pipe[2];
    if (pipe(err_pipe) < 0) return OZAYN_ERR;

    pid_t pid = fork();
    if (pid < 0) {
        close(err_pipe[0]);
        close(err_pipe[1]);
        return OZAYN_ERR;
    } else if (pid == 0) {
        /* Child process */
        close(err_pipe[0]);
        /* Set close-on-exec so pipe auto-closes if execvp succeeds */
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

        /* exec failed — notify parent via pipe */
        unsigned char err_byte = 1;
        write(err_pipe[1], &err_byte, 1);
        close(err_pipe[1]);
        _exit(127);
    } else {
        /* Parent process */
        close(err_pipe[1]);

        /* Check if child exec failed */
        unsigned char err_byte = 0;
        int n = read(err_pipe[0], &err_byte, 1);
        close(err_pipe[0]);

        if (n > 0 && err_byte == 1) {
            /* Child reported exec failure — wait to reap it */
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

    /* Check if process is alive */
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
        /* Infinite wait */
        int status;
        waitpid((pid_t)proc->pid, &status, 0);
        proc->running = 0;
        return OZAYN_OK;
    }

    /* Polling with sleep */
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
    snprintf(config_buf, OZAYN_MAX_PATH, "%s/.config/ozayn", home);
    return config_buf;
}

/* ================================================================
 * D. Display / Monitor
 * ================================================================ */

ozayn_result_t ozayn_display_info(ozayn_display_info_t *info) {
    if (!info) return OZAYN_ERR_NULL;
    memset(info, 0, sizeof(ozayn_display_info_t));

    /* Try to read from /sys/class/drm or fallback to single display */
    FILE *f = popen("xrandr --query 2>/dev/null | grep ' connected' | head -1", "r");
    if (f) {
        char line[256];
        if (fgets(line, sizeof(line), f)) {
            info->count = 1;
            /* Parse resolution if present */
            char *res = strchr(line, ' ');
            if (res) {
                res = strchr(res + 1, ' ');
                if (res) {
                    int w = 0, h = 0;
                    if (sscanf(res, "%dx%d", &w, &h) == 2) {
                        info->modes[0].width = (uint32_t)w;
                        info->modes[0].height = (uint32_t)h;
                        info->modes[0].refresh_hz = 60;
                        strncpy(info->modes[0].name, "Default", OZAYN_MAX_DISPLAY_NAME - 1);
                    }
                }
            }
        }
        pclose(f);
    }

    /* Fallback if xrandr not available */
    if (info->count == 0) {
        info->count = 1;
        info->modes[0].width = 1920;
        info->modes[0].height = 1080;
        info->modes[0].refresh_hz = 60;
        strncpy(info->modes[0].name, "Default", OZAYN_MAX_DISPLAY_NAME - 1);
    }

    return OZAYN_OK;
}

/* ================================================================
 * D2. Cross-Platform Display Management
 * ================================================================ */

static OzaynDisplayState _ozayn_display = {0};

static int _ozayn_display_parse_xrandr(void) {
    FILE *f = popen("xrandr --query 2>/dev/null", "r");
    if (!f) return 0;

    char line[512];
    uint32_t count = 0;
    int primary_done = 0;

    while (fgets(line, sizeof(line), f) && count < OZAYN_MAX_DISPLAYS) {
        /* Look for lines with " connected" */
        char *conn = strstr(line, " connected");
        if (!conn) continue;

        /* Check if primary */
        int is_primary = 0;
        if (strstr(line, " primary")) {
            is_primary = 1;
            primary_done = 1;
        }

        /* Extract name (everything before " connected") */
        char *name_end = strstr(line, " connected");
        if (!name_end) continue;

        size_t name_len = (size_t)(name_end - line);
        if (name_len >= OZAYN_MAX_DISPLAY_NAME) name_len = OZAYN_MAX_DISPLAY_NAME - 1;

        OzaynDisplayInfo *d = &_ozayn_display.displays[count];
        memset(d, 0, sizeof(OzaynDisplayInfo));
        d->index = count;
        d->is_primary = is_primary;
        strncpy(d->name, line, name_len);
        d->name[name_len] = '\0';

        /* Try to parse resolution from the same line or next part */
        /* Format: "HDMI-1 connected primary 1920x1080+0+0" */
        char *res_start = strchr(conn, ' ');
        if (res_start) {
            int w = 0, h = 0, x = 0, y = 0;
            if (sscanf(res_start, " %dx%d+%d+%d", &w, &h, &x, &y) == 4) {
                d->width = (uint32_t)w;
                d->height = (uint32_t)h;
                d->x = (int32_t)x;
                d->y = (int32_t)y;
            }
        }

        /* Default values if not parsed */
        if (d->width == 0) d->width = 1920;
        if (d->height == 0) d->height = 1080;
        d->refresh_hz = 60;

        count++;
    }

    pclose(f);

    /* If no primary found, mark first display as primary */
    if (!primary_done && count > 0) {
        _ozayn_display.displays[0].is_primary = 1;
        _ozayn_display.primary_index = 0;
    }

    return (int)count;
}

static int _ozayn_display_discover(void) {
    int count = _ozayn_display_parse_xrandr();

    /* Fallback if xrandr not available */
    if (count == 0) {
        OzaynDisplayInfo *d = &_ozayn_display.displays[0];
        memset(d, 0, sizeof(OzaynDisplayInfo));
        d->index = 0;
        d->is_primary = 1;
        d->width = 1920;
        d->height = 1080;
        d->refresh_hz = 60;
        d->x = 0;
        d->y = 0;
        strncpy(d->name, "Default", OZAYN_MAX_DISPLAY_NAME - 1);
        count = 1;
        _ozayn_display.primary_index = 0;
    }

    _ozayn_display.count = (uint32_t)count;
    _ozayn_display.available = (count > 0) ? 1 : 0;

    return count;
}

ozayn_result_t ozayn_display_init(void) {
    if (_ozayn_display.initialized) return OZAYN_OK;

    memset(&_ozayn_display, 0, sizeof(OzaynDisplayState));
    _ozayn_display.primary_index = -1;

    _ozayn_display_discover();
    _ozayn_display.initialized = 1;

    LOG_INFO("DISPLAY", "Display subsystem initialized (count=%u, available=%s)",
             _ozayn_display.count, _ozayn_display.available ? "yes" : "no");

    return OZAYN_OK;
}

void ozayn_display_shutdown(void) {
    if (!_ozayn_display.initialized) return;

    memset(&_ozayn_display, 0, sizeof(OzaynDisplayState));
    _ozayn_display.primary_index = -1;

    LOG_INFO("DISPLAY", "Display subsystem shut down");
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

/* ================================================================
 * E. Window Management
 * ================================================================ */

static OzaynWindowState _ozayn_window = {0};

static int _ozayn_window_check_xdotool(void) {
    int ret = system("which xdotool >/dev/null 2>&1");
    return ret == 0;
}

static void _ozayn_window_discover(void) {
    _ozayn_window.count = 0;

    if (!_ozayn_window_check_xdotool()) {
        _ozayn_window.available = 0;
        return;
    }

    /* Check if X display is available */
    if (!getenv("DISPLAY") && !getenv("WAYLAND_DISPLAY")) {
        _ozayn_window.available = 0;
        return;
    }

    /* Get active window ID */
    unsigned long long active_id = 0;
    {
        FILE *f = popen("xdotool getactivewindow 2>/dev/null", "r");
        if (f) {
            char buf[64];
            if (fgets(buf, sizeof(buf), f)) {
                active_id = strtoull(buf, NULL, 10);
            }
            pclose(f);
        }
    }

    /* Discover all windows */
    FILE *f = popen("xdotool search --name \"\" 2>/dev/null", "r");
    if (!f) {
        _ozayn_window.available = 0;
        return;
    }

    char line[64];
    while (fgets(line, sizeof(line), f) && _ozayn_window.count < OZAYN_MAX_WINDOWS) {
        /* Trim newline */
        size_t len = strlen(line);
        while (len > 0 && (line[len-1] == '\n' || line[len-1] == '\r')) line[--len] = '\0';
        if (len == 0) continue;

        unsigned long long wid = strtoull(line, NULL, 10);
        if (wid == 0) continue;

        OzaynWindowInfo *w = &_ozayn_window.windows[_ozayn_window.count];
        memset(w, 0, sizeof(OzaynWindowInfo));
        w->id = wid;
        w->active = (wid == active_id) ? 1 : 0;

        /* Get window title */
        {
            char cmd[128];
            snprintf(cmd, sizeof(cmd), "xdotool getwindowname %llu 2>/dev/null", wid);
            FILE *ft = popen(cmd, "r");
            if (ft) {
                char title_buf[OZAYN_MAX_WINDOW_TITLE];
                if (fgets(title_buf, sizeof(title_buf), ft)) {
                    size_t tlen = strlen(title_buf);
                    while (tlen > 0 && (title_buf[tlen-1] == '\n' || title_buf[tlen-1] == '\r')) title_buf[--tlen] = '\0';
                    strncpy(w->title, title_buf, OZAYN_MAX_WINDOW_TITLE - 1);
                }
                pclose(ft);
            }
        }

        /* Get window geometry */
        {
            char cmd[128];
            snprintf(cmd, sizeof(cmd), "xdotool getwindowgeometry --shell %llu 2>/dev/null", wid);
            FILE *fg = popen(cmd, "r");
            if (fg) {
                char gline[128];
                int gx = 0, gy = 0, gw = 0, gh = 0;
                while (fgets(gline, sizeof(gline), fg)) {
                    if (sscanf(gline, "X=%d", &gx) == 1) continue;
                    if (sscanf(gline, "Y=%d", &gy) == 1) continue;
                    if (sscanf(gline, "WIDTH=%d", &gw) == 1) continue;
                    if (sscanf(gline, "HEIGHT=%d", &gh) == 1) continue;
                }
                pclose(fg);
                w->x = gx;
                w->y = gy;
                w->width = (uint32_t)gw;
                w->height = (uint32_t)gh;
            }
        }

        /* Get window state (minimized, maximized, visible) */
        {
            char cmd[128];
            snprintf(cmd, sizeof(cmd), "xprop -id %llu _NET_WM_STATE 2>/dev/null", wid);
            FILE *fs = popen(cmd, "r");
            if (fs) {
                char sline[512];
                w->visible = 1;
                while (fgets(sline, sizeof(sline), fs)) {
                    if (strstr(sline, "_NET_WM_STATE_HIDDEN")) {
                        w->minimized = 1;
                        w->visible = 0;
                    }
                    if (strstr(sline, "_NET_WM_STATE_MAXIMIZED_VERT") ||
                        strstr(sline, "_NET_WM_STATE_MAXIMIZED_HORZ")) {
                        w->maximized = 1;
                    }
                }
                pclose(fs);
            } else {
                /* Cannot determine state — assume visible */
                w->visible = 1;
            }
        }

        _ozayn_window.count++;
    }

    pclose(f);
    _ozayn_window.available = (_ozayn_window.count > 0) ? 1 : 0;
}

ozayn_result_t ozayn_window_init(void) {
    if (_ozayn_window.initialized) return OZAYN_OK;

    memset(&_ozayn_window, 0, sizeof(OzaynWindowState));
    _ozayn_window_discover();
    _ozayn_window.initialized = 1;

    LOG_INFO("WINDOW", "Window subsystem initialized (count=%u, available=%s)",
             _ozayn_window.count, _ozayn_window.available ? "yes" : "no");

    return OZAYN_OK;
}

void ozayn_window_shutdown(void) {
    if (!_ozayn_window.initialized) return;

    memset(&_ozayn_window, 0, sizeof(OzaynWindowState));
    LOG_INFO("WINDOW", "Window subsystem shut down");
}

int ozayn_window_is_available(void) {
    return _ozayn_window.available;
}

uint32_t ozayn_window_get_count(void) {
    if (!_ozayn_window.initialized) return 0;
    return _ozayn_window.count;
}

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

    for (uint32_t i = 0; i < _ozayn_window.count; i++) {
        if (_ozayn_window.windows[i].active) {
            memcpy(info, &_ozayn_window.windows[i], sizeof(OzaynWindowInfo));
            return OZAYN_OK;
        }
    }

    return OZAYN_ERR;
}

static int _ozayn_window_id_exists(unsigned long long window_id) {
    if (window_id == 0) return 0;
    for (uint32_t i = 0; i < _ozayn_window.count; i++) {
        if (_ozayn_window.windows[i].id == window_id) return 1;
    }
    return 0;
}

ozayn_result_t ozayn_window_move(unsigned long long window_id, int32_t x, int32_t y) {
    if (window_id == 0) return OZAYN_ERR;
    if (!_ozayn_window.initialized) return OZAYN_ERR;
    if (!_ozayn_window_id_exists(window_id)) return OZAYN_ERR;

    char cmd[128];
    snprintf(cmd, sizeof(cmd), "xdotool windowmove %llu %d %d 2>/dev/null", window_id, x, y);
    if (system(cmd) == 0) return OZAYN_OK;
    return OZAYN_ERR;
}

ozayn_result_t ozayn_window_resize(unsigned long long window_id, uint32_t width, uint32_t height) {
    if (window_id == 0) return OZAYN_ERR;
    if (width == 0 || height == 0) return OZAYN_ERR;
    if (!_ozayn_window.initialized) return OZAYN_ERR;
    if (!_ozayn_window_id_exists(window_id)) return OZAYN_ERR;

    char cmd[128];
    snprintf(cmd, sizeof(cmd), "xdotool windowsize %llu %u %u 2>/dev/null", window_id, width, height);
    if (system(cmd) == 0) return OZAYN_OK;
    return OZAYN_ERR;
}

ozayn_result_t ozayn_window_minimize(unsigned long long window_id) {
    if (window_id == 0) return OZAYN_ERR;
    if (!_ozayn_window.initialized) return OZAYN_ERR;
    if (!_ozayn_window_id_exists(window_id)) return OZAYN_ERR;

    char cmd[128];
    snprintf(cmd, sizeof(cmd), "xdotool windowminimize %llu 2>/dev/null", window_id);
    if (system(cmd) == 0) return OZAYN_OK;
    return OZAYN_ERR;
}

ozayn_result_t ozayn_window_maximize(unsigned long long window_id) {
    if (window_id == 0) return OZAYN_ERR;
    if (!_ozayn_window.initialized) return OZAYN_ERR;
    if (!_ozayn_window_id_exists(window_id)) return OZAYN_ERR;

    char cmd[256];
    snprintf(cmd, sizeof(cmd),
        "xdotool windowactivate %llu && "
        "xdotool key --window %llu super+Up 2>/dev/null",
        window_id, window_id);
    if (system(cmd) == 0) return OZAYN_OK;

    snprintf(cmd, sizeof(cmd), "wmctrl -i -r %llu -b add,maximized_vert,maximized_horz 2>/dev/null", window_id);
    if (system(cmd) == 0) return OZAYN_OK;
    return OZAYN_ERR;
}

ozayn_result_t ozayn_window_restore(unsigned long long window_id) {
    if (window_id == 0) return OZAYN_ERR;
    if (!_ozayn_window.initialized) return OZAYN_ERR;
    if (!_ozayn_window_id_exists(window_id)) return OZAYN_ERR;

    char cmd[256];
    snprintf(cmd, sizeof(cmd), "wmctrl -i -r %llu -b remove,maximized_vert,maximized_horz 2>/dev/null", window_id);
    system(cmd);

    snprintf(cmd, sizeof(cmd), "xdotool windowactivate %llu 2>/dev/null", window_id);
    if (system(cmd) == 0) return OZAYN_OK;
    return OZAYN_ERR;
}

ozayn_result_t ozayn_window_close(unsigned long long window_id) {
    if (window_id == 0) return OZAYN_ERR;
    if (!_ozayn_window.initialized) return OZAYN_ERR;
    if (!_ozayn_window_id_exists(window_id)) return OZAYN_ERR;

    char cmd[128];
    snprintf(cmd, sizeof(cmd), "xdotool windowclose %llu 2>/dev/null", window_id);
    if (system(cmd) == 0) return OZAYN_OK;
    return OZAYN_ERR;
}

ozayn_result_t ozayn_window_refresh(void) {
    if (!_ozayn_window.initialized) return OZAYN_ERR;

    _ozayn_window_discover();
    return OZAYN_OK;
}

/* ================================================================
 * F. Network
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
    snprintf(cmd, sizeof(cmd), "ping -c 1 -W 2 %s >/dev/null 2>&1", host);
    return system(cmd) == 0;
}

/* ================================================================
 * G. Camera Device Abstraction (Step 09)
 * ================================================================
 *
 * Uses V4L2 (Video4Linux2) for camera enumeration and capture.
 * Handles missing devices, permission errors, and headless systems.
 */

static OzaynCameraState _ozayn_camera = {0};
static int _ozayn_camera_fd = -1;
static unsigned int _ozayn_camera_open_index = 0;
static struct {
    void *start;
    size_t length;
} _ozayn_camera_buffers[4];
static unsigned int _ozayn_camera_buf_count = 0;
static OzaynCameraInfo _ozayn_camera_infos[OZAYN_MAX_CAMERAS];

static void _ozayn_camera_enumerate(void) {
    _ozayn_camera.count = 0;
    for (unsigned int i = 0; i < OZAYN_MAX_CAMERAS; i++) {
        char dev_path[64];
        snprintf(dev_path, sizeof(dev_path), "/dev/video%u", i);

        int fd = open(dev_path, O_RDWR | O_NONBLOCK);
        if (fd < 0) continue;

        struct v4l2_capability cap;
        memset(&cap, 0, sizeof(cap));
        if (ioctl(fd, VIDIOC_QUERYCAP, &cap) < 0) {
            close(fd);
            continue;
        }

        /* Skip devices that don't support video capture */
        if (!(cap.device_caps & V4L2_CAP_VIDEO_CAPTURE)) {
            close(fd);
            continue;
        }

        OzaynCameraInfo *info = &_ozayn_camera_infos[_ozayn_camera.count];
        memset(info, 0, sizeof(OzaynCameraInfo));
        info->index = _ozayn_camera.count;
        info->available = 1;

        /* Device ID */
        snprintf(info->id, OZAYN_MAX_CAMERA_ID, "/dev/video%u", i);

        /* Device name */
        strncpy(info->name, (const char *)cap.card, OZAYN_MAX_CAMERA_NAME - 1);

        /* Query default format */
        struct v4l2_format fmt;
        memset(&fmt, 0, sizeof(fmt));
        fmt.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
        if (ioctl(fd, VIDIOC_G_FMT, &fmt) == 0) {
            info->width = fmt.fmt.pix.width;
            info->height = fmt.fmt.pix.height;
        }

        /* Query frame rate */
        struct v4l2_streamparm parm;
        memset(&parm, 0, sizeof(parm));
        parm.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
        if (ioctl(fd, VIDIOC_G_PARM, &parm) == 0) {
            if (parm.parm.capture.timeperframe.numerator > 0) {
                info->fps = parm.parm.capture.timeperframe.denominator /
                           parm.parm.capture.timeperframe.numerator;
            }
        }

        close(fd);
        _ozayn_camera.count++;
    }
}

ozayn_result_t ozayn_camera_init(void) {
    if (_ozayn_camera.initialized) return OZAYN_OK;

    memset(&_ozayn_camera, 0, sizeof(OzaynCameraState));
    memset(_ozayn_camera_infos, 0, sizeof(_ozayn_camera_infos));
    _ozayn_camera_fd = -1;

    _ozayn_camera_enumerate();
    _ozayn_camera.available = (_ozayn_camera.count > 0) ? 1 : 0;
    _ozayn_camera.initialized = 1;

    LOG_INFO("CAMERA", "Camera subsystem initialized (count=%u, available=%s)",
             _ozayn_camera.count, _ozayn_camera.available ? "yes" : "no");

    return OZAYN_OK;
}

void ozayn_camera_shutdown(void) {
    if (!_ozayn_camera.initialized) return;

    /* Auto-close if open */
    if (_ozayn_camera.open) {
        ozayn_camera_stop();
        ozayn_camera_close();
    }

    memset(&_ozayn_camera, 0, sizeof(OzaynCameraState));
    _ozayn_camera_fd = -1;
    LOG_INFO("CAMERA", "Camera subsystem shut down");
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

    memcpy(info, &_ozayn_camera_infos[index], sizeof(OzaynCameraInfo));
    return OZAYN_OK;
}

ozayn_result_t ozayn_camera_open(unsigned int index) {
    if (!_ozayn_camera.initialized) return OZAYN_ERR;
    if (_ozayn_camera.open) return OZAYN_ERR_STATE;
    if (index >= _ozayn_camera.count) return OZAYN_ERR;

    char dev_path[64];
    snprintf(dev_path, sizeof(dev_path), "/dev/video%u", index);

    _ozayn_camera_fd = open(dev_path, O_RDWR | O_NONBLOCK);
    if (_ozayn_camera_fd < 0) {
        LOG_WARN("CAMERA", "Failed to open %s: %s", dev_path, strerror(errno));
        return OZAYN_ERR;
    }

    _ozayn_camera_open_index = index;
    _ozayn_camera.open = 1;

    LOG_INFO("CAMERA", "Camera opened: %s", _ozayn_camera_infos[index].name);
    return OZAYN_OK;
}

ozayn_result_t ozayn_camera_close(void) {
    if (!_ozayn_camera.initialized) return OZAYN_ERR;
    if (!_ozayn_camera.open) return OZAYN_ERR_STATE;

    if (_ozayn_camera.streaming) {
        ozayn_camera_stop();
    }

    if (_ozayn_camera_fd >= 0) {
        close(_ozayn_camera_fd);
        _ozayn_camera_fd = -1;
    }

    _ozayn_camera.open = 0;
    _ozayn_camera_open_index = 0;

    LOG_INFO("CAMERA", "Camera closed");
    return OZAYN_OK;
}

ozayn_result_t ozayn_camera_start(void) {
    if (!_ozayn_camera.initialized) return OZAYN_ERR;
    if (!_ozayn_camera.open) return OZAYN_ERR_STATE;
    if (_ozayn_camera.streaming) return OZAYN_ERR_STATE;
    if (_ozayn_camera_fd < 0) return OZAYN_ERR;

    /* Request buffers */
    struct v4l2_requestbuffers req;
    memset(&req, 0, sizeof(req));
    req.count = 4;
    req.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
    req.memory = V4L2_MEMORY_MMAP;

    if (ioctl(_ozayn_camera_fd, VIDIOC_REQBUFS, &req) < 0) {
        LOG_WARN("CAMERA", "VIDIOC_REQBUFS failed: %s", strerror(errno));
        return OZAYN_ERR;
    }

    _ozayn_camera_buf_count = req.count;

    /* Map buffers */
    for (unsigned int i = 0; i < _ozayn_camera_buf_count; i++) {
        struct v4l2_buffer buf;
        memset(&buf, 0, sizeof(buf));
        buf.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
        buf.memory = V4L2_MEMORY_MMAP;
        buf.index = i;

        if (ioctl(_ozayn_camera_fd, VIDIOC_QUERYBUF, &buf) < 0) {
            LOG_WARN("CAMERA", "VIDIOC_QUERYBUF failed: %s", strerror(errno));
            ozayn_camera_stop();
            return OZAYN_ERR;
        }

        _ozayn_camera_buffers[i].length = buf.length;
        _ozayn_camera_buffers[i].start = mmap(NULL, buf.length,
            PROT_READ | PROT_WRITE, MAP_SHARED, _ozayn_camera_fd, buf.m.offset);

        if (_ozayn_camera_buffers[i].start == MAP_FAILED) {
            LOG_WARN("CAMERA", "mmap failed: %s", strerror(errno));
            _ozayn_camera_buffers[i].start = NULL;
            ozayn_camera_stop();
            return OZAYN_ERR;
        }
    }

    /* Queue all buffers */
    for (unsigned int i = 0; i < _ozayn_camera_buf_count; i++) {
        struct v4l2_buffer buf;
        memset(&buf, 0, sizeof(buf));
        buf.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
        buf.memory = V4L2_MEMORY_MMAP;
        buf.index = i;

        if (ioctl(_ozayn_camera_fd, VIDIOC_QBUF, &buf) < 0) {
            LOG_WARN("CAMERA", "VIDIOC_QBUF failed: %s", strerror(errno));
            ozayn_camera_stop();
            return OZAYN_ERR;
        }
    }

    /* Start streaming */
    enum v4l2_buf_type type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
    if (ioctl(_ozayn_camera_fd, VIDIOC_STREAMON, &type) < 0) {
        LOG_WARN("CAMERA", "VIDIOC_STREAMON failed: %s", strerror(errno));
        ozayn_camera_stop();
        return OZAYN_ERR;
    }

    _ozayn_camera.streaming = 1;
    LOG_INFO("CAMERA", "Capture started");
    return OZAYN_OK;
}

ozayn_result_t ozayn_camera_stop(void) {
    if (!_ozayn_camera.initialized) return OZAYN_ERR;
    if (!_ozayn_camera.streaming) return OZAYN_ERR_STATE;

    /* Stop streaming */
    if (_ozayn_camera_fd >= 0) {
        enum v4l2_buf_type type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
        ioctl(_ozayn_camera_fd, VIDIOC_STREAMOFF, &type);
    }

    /* Unmap buffers */
    for (unsigned int i = 0; i < _ozayn_camera_buf_count; i++) {
        if (_ozayn_camera_buffers[i].start && _ozayn_camera_buffers[i].start != MAP_FAILED) {
            munmap(_ozayn_camera_buffers[i].start, _ozayn_camera_buffers[i].length);
            _ozayn_camera_buffers[i].start = NULL;
            _ozayn_camera_buffers[i].length = 0;
        }
    }
    _ozayn_camera_buf_count = 0;

    _ozayn_camera.streaming = 0;
    LOG_INFO("CAMERA", "Capture stopped");
    return OZAYN_OK;
}

ozayn_result_t ozayn_camera_capture(OzaynCameraFrame *frame) {
    if (!frame) return OZAYN_ERR_NULL;
    if (!_ozayn_camera.initialized) return OZAYN_ERR;
    if (!_ozayn_camera.open || !_ozayn_camera.streaming) return OZAYN_ERR_STATE;
    if (_ozayn_camera_fd < 0) return OZAYN_ERR;

    memset(frame, 0, sizeof(OzaynCameraFrame));

    /* Dequeue a buffer */
    struct v4l2_buffer buf;
    memset(&buf, 0, sizeof(buf));
    buf.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
    buf.memory = V4L2_MEMORY_MMAP;

    if (ioctl(_ozayn_camera_fd, VIDIOC_DQBUF, &buf) < 0) {
        return OZAYN_ERR;
    }

    /* Fill frame info from current format */
    struct v4l2_format fmt;
    memset(&fmt, 0, sizeof(fmt));
    fmt.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
    ioctl(_ozayn_camera_fd, VIDIOC_G_FMT, &fmt);

    frame->width = fmt.fmt.pix.width;
    frame->height = fmt.fmt.pix.height;
    frame->stride = fmt.fmt.pix.bytesperline;
    frame->data = (unsigned char *)_ozayn_camera_buffers[buf.index].start;
    frame->data_size = buf.bytesused;

    /* Map pixel format */
    switch (fmt.fmt.pix.pixelformat) {
        case V4L2_PIX_FMT_RGB24:  frame->format = OZAYN_PIXEL_FORMAT_RGB24; break;
        case V4L2_PIX_FMT_BGR24:  frame->format = OZAYN_PIXEL_FORMAT_BGR24; break;
        case V4L2_PIX_FMT_GREY:   frame->format = OZAYN_PIXEL_FORMAT_GRAY8; break;
        case V4L2_PIX_FMT_YUYV:   frame->format = OZAYN_PIXEL_FORMAT_YUYV; break;
        case V4L2_PIX_FMT_MJPEG:  frame->format = OZAYN_PIXEL_FORMAT_MJPEG; break;
        default:                  frame->format = OZAYN_PIXEL_FORMAT_UNKNOWN; break;
    }

    /* Re-queue the buffer */
    ioctl(_ozayn_camera_fd, VIDIOC_QBUF, &buf);

    return OZAYN_OK;
}

ozayn_result_t ozayn_camera_set_resolution(unsigned int width, unsigned int height) {
    if (!_ozayn_camera.initialized) return OZAYN_ERR;
    if (!_ozayn_camera.open) return OZAYN_ERR_STATE;
    if (_ozayn_camera_fd < 0) return OZAYN_ERR;
    if (width == 0 || height == 0) return OZAYN_ERR;

    struct v4l2_format fmt;
    memset(&fmt, 0, sizeof(fmt));
    fmt.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
    fmt.fmt.pix.width = width;
    fmt.fmt.pix.height = height;

    /* Try to set the format — driver may adjust to nearest supported */
    if (ioctl(_ozayn_camera_fd, VIDIOC_S_FMT, &fmt) < 0) {
        LOG_WARN("CAMERA", "Failed to set resolution %ux%u: %s", width, height, strerror(errno));
        return OZAYN_ERR;
    }

    LOG_INFO("CAMERA", "Resolution set to %ux%u", fmt.fmt.pix.width, fmt.fmt.pix.height);
    return OZAYN_OK;
}

ozayn_result_t ozayn_camera_set_fps(unsigned int fps) {
    if (!_ozayn_camera.initialized) return OZAYN_ERR;
    if (!_ozayn_camera.open) return OZAYN_ERR_STATE;
    if (_ozayn_camera_fd < 0) return OZAYN_ERR;
    if (fps == 0) return OZAYN_ERR;

    struct v4l2_streamparm parm;
    memset(&parm, 0, sizeof(parm));
    parm.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
    parm.parm.capture.timeperframe.numerator = 1;
    parm.parm.capture.timeperframe.denominator = fps;

    if (ioctl(_ozayn_camera_fd, VIDIOC_S_PARM, &parm) < 0) {
        LOG_WARN("CAMERA", "Failed to set FPS to %u: %s", fps, strerror(errno));
        return OZAYN_ERR;
    }

    LOG_INFO("CAMERA", "FPS set to %u", fps);
    return OZAYN_OK;
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
 * Uses ALSA for microphone enumeration and PCM capture.
 * Handles missing devices, permission errors, and headless systems.
 */

static OzaynMicrophoneState _ozayn_mic = {0};
static snd_pcm_t *_ozayn_mic_handle = NULL;
static unsigned int _ozayn_mic_open_index = 0;
static OzaynMicrophoneInfo _ozayn_mic_infos[OZAYN_MAX_MICROPHONES];

static void _ozayn_mic_enumerate(void) {
    _ozayn_mic.count = 0;
    void **hints = NULL;

    if (snd_device_name_hint(-1, "pcm", &hints) < 0 || !hints) {
        return;
    }

    for (unsigned int i = 0; hints[i] && _ozayn_mic.count < OZAYN_MAX_MICROPHONES; i++) {
        char *name = snd_device_name_get_hint(hints[i], "NAME");
        char *desc = snd_device_name_get_hint(hints[i], "DESC");

        if (!name || strcmp(name, "null") == 0) {
            free(name);
            free(desc);
            continue;
        }

        /* Try to open the device in capture mode to verify it works */
        snd_pcm_t *test_handle = NULL;
        int open_result = snd_pcm_open(&test_handle, name, SND_PCM_STREAM_CAPTURE, SND_PCM_NONBLOCK);

        OzaynMicrophoneInfo *info = &_ozayn_mic_infos[_ozayn_mic.count];
        memset(info, 0, sizeof(OzaynMicrophoneInfo));
        info->index = (int)_ozayn_mic.count;
        info->available = (open_result == 0) ? 1 : 0;

        /* Device ID */
        snprintf(info->id, OZAYN_MAX_MIC_ID, "%s", name ? name : "unknown");

        /* Device name */
        if (desc) {
            /* desc format is often "name (direction)" — take the first part */
            strncpy(info->name, desc, OZAYN_MAX_MIC_NAME - 1);
        } else if (name) {
            strncpy(info->name, name, OZAYN_MAX_MIC_NAME - 1);
        } else {
            snprintf(info->name, OZAYN_MAX_MIC_NAME, "Microphone %u", _ozayn_mic.count);
        }

        /* Query channels and sample rate if device opened successfully */
        if (open_result == 0 && test_handle) {
            snd_pcm_hw_params_t *hw_params;
            snd_pcm_hw_params_alloca(&hw_params);
            if (snd_pcm_hw_params_any(test_handle, hw_params) == 0) {
                unsigned int channels = 0;
                if (snd_pcm_hw_params_get_channels(hw_params, &channels) == 0) {
                    info->channels = (int)channels;
                }
                unsigned int rate = 0;
                if (snd_pcm_hw_params_get_rate(hw_params, &rate, NULL) == 0) {
                    info->sample_rate = (int)rate;
                }
            }
            snd_pcm_close(test_handle);
        } else {
            /* Safe defaults */
            info->channels = 1;
            info->sample_rate = 44100;
        }

        free(name);
        free(desc);

        _ozayn_mic.count++;
    }

    snd_device_name_free_hint(hints);
}

ozayn_result_t ozayn_microphone_init(void) {
    if (_ozayn_mic.initialized) return OZAYN_OK;

    memset(&_ozayn_mic, 0, sizeof(OzaynMicrophoneState));
    memset(_ozayn_mic_infos, 0, sizeof(_ozayn_mic_infos));
    _ozayn_mic_handle = NULL;

    _ozayn_mic_enumerate();
    _ozayn_mic.available = (_ozayn_mic.count > 0) ? 1 : 0;
    _ozayn_mic.initialized = 1;

    LOG_INFO("MICROPHONE", "Microphone subsystem initialized (count=%u, available=%s)",
             _ozayn_mic.count, _ozayn_mic.available ? "yes" : "no");

    return OZAYN_OK;
}

void ozayn_microphone_shutdown(void) {
    if (!_ozayn_mic.initialized) return;

    if (_ozayn_mic.open) {
        ozayn_microphone_stop();
        ozayn_microphone_close();
    }

    memset(&_ozayn_mic, 0, sizeof(OzaynMicrophoneState));
    _ozayn_mic_handle = NULL;
    LOG_INFO("MICROPHONE", "Microphone subsystem shut down");
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

    memcpy(info, &_ozayn_mic_infos[index], sizeof(OzaynMicrophoneInfo));
    return OZAYN_OK;
}

ozayn_result_t ozayn_microphone_open(unsigned int index) {
    if (!_ozayn_mic.initialized) return OZAYN_ERR;
    if (_ozayn_mic.open) return OZAYN_ERR_STATE;
    if (index >= _ozayn_mic.count) return OZAYN_ERR;

    const char *dev_name = _ozayn_mic_infos[index].id;
    int err = snd_pcm_open(&_ozayn_mic_handle, dev_name, SND_PCM_STREAM_CAPTURE, SND_PCM_NONBLOCK);
    if (err < 0) {
        LOG_WARN("MICROPHONE", "Failed to open %s: %s", dev_name, snd_strerror(err));
        return OZAYN_ERR;
    }

    /* Configure hardware params */
    snd_pcm_hw_params_t *hw_params;
    snd_pcm_hw_params_alloca(&hw_params);
    snd_pcm_hw_params_any(_ozayn_mic_handle, hw_params);

    /* Set access type */
    snd_pcm_hw_params_set_access(_ozayn_mic_handle, hw_params, SND_PCM_ACCESS_RW_INTERLEAVED);

    /* Set format: signed 16-bit little-endian */
    snd_pcm_hw_params_set_format(_ozayn_mic_handle, hw_params, SND_PCM_FORMAT_S16_LE);

    /* Set channels */
    unsigned int channels = (unsigned int)_ozayn_mic_infos[index].channels;
    if (channels == 0) channels = 1;
    snd_pcm_hw_params_set_channels(_ozayn_mic_handle, hw_params, channels);

    /* Set sample rate */
    unsigned int rate = (unsigned int)_ozayn_mic_infos[index].sample_rate;
    if (rate == 0) rate = 44100;
    snd_pcm_hw_params_set_rate_near(_ozayn_mic_handle, hw_params, &rate, NULL);

    err = snd_pcm_hw_params(_ozayn_mic_handle, hw_params);
    if (err < 0) {
        LOG_WARN("MICROPHONE", "Failed to set hw params: %s", snd_strerror(err));
        snd_pcm_close(_ozayn_mic_handle);
        _ozayn_mic_handle = NULL;
        return OZAYN_ERR;
    }

    _ozayn_mic_open_index = index;
    _ozayn_mic.open = 1;

    LOG_INFO("MICROPHONE", "Microphone opened: %s", _ozayn_mic_infos[index].name);
    return OZAYN_OK;
}

ozayn_result_t ozayn_microphone_close(void) {
    if (!_ozayn_mic.initialized) return OZAYN_ERR;
    if (!_ozayn_mic.open) return OZAYN_ERR_STATE;

    if (_ozayn_mic.streaming) {
        ozayn_microphone_stop();
    }

    if (_ozayn_mic_handle) {
        snd_pcm_close(_ozayn_mic_handle);
        _ozayn_mic_handle = NULL;
    }

    _ozayn_mic.open = 0;
    _ozayn_mic_open_index = 0;

    LOG_INFO("MICROPHONE", "Microphone closed");
    return OZAYN_OK;
}

ozayn_result_t ozayn_microphone_start(void) {
    if (!_ozayn_mic.initialized) return OZAYN_ERR;
    if (!_ozayn_mic.open) return OZAYN_ERR_STATE;
    if (_ozayn_mic.streaming) return OZAYN_ERR_STATE;
    if (!_ozayn_mic_handle) return OZAYN_ERR;

    /* Prepare the PCM device */
    int err = snd_pcm_prepare(_ozayn_mic_handle);
    if (err < 0) {
        LOG_WARN("MICROPHONE", "snd_pcm_prepare failed: %s", snd_strerror(err));
        return OZAYN_ERR;
    }

    _ozayn_mic.streaming = 1;
    LOG_INFO("MICROPHONE", "Capture started");
    return OZAYN_OK;
}

ozayn_result_t ozayn_microphone_stop(void) {
    if (!_ozayn_mic.initialized) return OZAYN_ERR;
    if (!_ozayn_mic.streaming) return OZAYN_ERR_STATE;

    if (_ozayn_mic_handle) {
        snd_pcm_drop(_ozayn_mic_handle);
    }

    _ozayn_mic.streaming = 0;
    LOG_INFO("MICROPHONE", "Capture stopped");
    return OZAYN_OK;
}

ozayn_result_t ozayn_microphone_capture(OzaynAudioBuffer *buffer) {
    if (!buffer) return OZAYN_ERR_NULL;
    if (!_ozayn_mic.initialized) return OZAYN_ERR;
    if (!_ozayn_mic.open || !_ozayn_mic.streaming) return OZAYN_ERR_STATE;
    if (!_ozayn_mic_handle) return OZAYN_ERR;

    memset(buffer, 0, sizeof(OzaynAudioBuffer));

    /* Get current hw params to know channels and rate */
    snd_pcm_hw_params_t *hw_params;
    snd_pcm_hw_params_alloca(&hw_params);
    snd_pcm_hw_params_any(_ozayn_mic_handle, hw_params);

    unsigned int channels = 1;
    unsigned int rate = 44100;
    snd_pcm_hw_params_get_channels(hw_params, &channels);
    snd_pcm_hw_params_get_rate(hw_params, &rate, NULL);

    buffer->sample_rate = rate;
    buffer->channels = channels;
    buffer->format = OZAYN_AUDIO_FORMAT_S16;
    buffer->frame_count = 1024;

    /* Allocate buffer: frames * channels * 2 bytes (S16) */
    size_t buf_size = buffer->frame_count * channels * sizeof(int16_t);
    buffer->data = (unsigned char *)malloc(buf_size);
    if (!buffer->data) return OZAYN_ERR;

    /* Read interleaved samples */
    snd_pcm_sframes_t frames = snd_pcm_readi(_ozayn_mic_handle, buffer->data, buffer->frame_count);
    if (frames < 0) {
        /* Try to recover from overrun */
        frames = snd_pcm_recover(_ozayn_mic_handle, (int)frames, 0);
        if (frames < 0) {
            free(buffer->data);
            buffer->data = NULL;
            return OZAYN_ERR;
        }
        frames = snd_pcm_readi(_ozayn_mic_handle, buffer->data, buffer->frame_count);
        if (frames < 0) {
            free(buffer->data);
            buffer->data = NULL;
            return OZAYN_ERR;
        }
    }

    buffer->frame_count = (size_t)frames;
    buffer->data_size = frames * channels * sizeof(int16_t);

    return OZAYN_OK;
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
 * Cross-platform audio output enumeration, configuration, and PCM
 * playback. Uses ALSA on Linux.
 */

#define OZAYN_MAX_SPEAKER_DEFAULT 44100

static OzaynAudioOutputState _ozayn_speaker = {0};
static OzaynAudioOutputInfo _ozayn_speaker_infos[OZAYN_MAX_SPEAKERS];
static snd_pcm_t *_ozayn_speaker_handle = NULL;
static unsigned int _ozayn_speaker_open_index = 0;

static void _ozayn_speaker_enumerate(void) {
    void **hints = NULL;
    _ozayn_speaker.count = 0;

    int ret = snd_device_name_hint(-1, "pcm", &hints);
    if (ret < 0 || !hints) return;

    for (unsigned int i = 0; hints[i] && _ozayn_speaker.count < OZAYN_MAX_SPEAKERS; i++) {
        char *name = snd_device_name_get_hint(hints[i], "NAME");
        char *desc = snd_device_name_get_hint(hints[i], "DESC");

        if (!name || strcmp(name, "null") == 0) {
            free(name);
            free(desc);
            continue;
        }

        /* Try to open the device in playback mode to verify it works */
        snd_pcm_t *test_handle = NULL;
        int open_result = snd_pcm_open(&test_handle, name, SND_PCM_STREAM_PLAYBACK, SND_PCM_NONBLOCK);

        OzaynAudioOutputInfo *info = &_ozayn_speaker_infos[_ozayn_speaker.count];
        memset(info, 0, sizeof(OzaynAudioOutputInfo));
        info->index = (int)_ozayn_speaker.count;
        info->available = (open_result == 0) ? 1 : 0;

        /* Copy name (device ID) */
        if (name) {
            size_t len = strlen(name);
            if (len >= OZAYN_MAX_SPEAKER_ID) len = OZAYN_MAX_SPEAKER_ID - 1;
            memcpy(info->id, name, len);
            info->id[len] = '\0';
        }

        /* Copy description (human-readable name) */
        if (desc) {
            /* desc may contain newlines; use first line */
            const char *first_line = desc;
            const char *nl = strchr(desc, '\n');
            size_t len = nl ? (size_t)(nl - desc) : strlen(desc);
            if (len >= OZAYN_MAX_SPEAKER_NAME) len = OZAYN_MAX_SPEAKER_NAME - 1;
            memcpy(info->name, first_line, len);
            info->name[len] = '\0';
        } else {
            strncpy(info->name, info->id, OZAYN_MAX_SPEAKER_NAME - 1);
        }

        /* Defaults */
        info->channels = 2;
        info->sample_rate = OZAYN_MAX_SPEAKER_DEFAULT;

        /* Close test handle */
        if (open_result == 0 && test_handle) {
            snd_pcm_close(test_handle);
        }

        _ozayn_speaker.count++;
        free(name);
        free(desc);
    }

    snd_device_name_free_hint(hints);
}

ozayn_result_t ozayn_audio_output_init(void) {
    if (_ozayn_speaker.initialized) return OZAYN_OK;

    memset(&_ozayn_speaker, 0, sizeof(OzaynAudioOutputState));
    memset(_ozayn_speaker_infos, 0, sizeof(_ozayn_speaker_infos));
    _ozayn_speaker_handle = NULL;

    _ozayn_speaker_enumerate();
    _ozayn_speaker.available = (_ozayn_speaker.count > 0) ? 1 : 0;
    _ozayn_speaker.initialized = 1;

    LOG_INFO("SPEAKER", "Audio output subsystem initialized (count=%u, available=%s)",
             _ozayn_speaker.count, _ozayn_speaker.available ? "yes" : "no");

    return OZAYN_OK;
}

void ozayn_audio_output_shutdown(void) {
    if (!_ozayn_speaker.initialized) return;

    if (_ozayn_speaker.open) {
        ozayn_audio_output_stop();
        ozayn_audio_output_close();
    }

    memset(&_ozayn_speaker, 0, sizeof(OzaynAudioOutputState));
    _ozayn_speaker_handle = NULL;
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

    memcpy(info, &_ozayn_speaker_infos[index], sizeof(OzaynAudioOutputInfo));
    return OZAYN_OK;
}

ozayn_result_t ozayn_audio_output_open(unsigned int index) {
    if (!_ozayn_speaker.initialized) return OZAYN_ERR;
    if (_ozayn_speaker.open) return OZAYN_ERR_STATE;
    if (index >= _ozayn_speaker.count) return OZAYN_ERR;

    const char *dev_name = _ozayn_speaker_infos[index].id;
    int err = snd_pcm_open(&_ozayn_speaker_handle, dev_name, SND_PCM_STREAM_PLAYBACK, SND_PCM_NONBLOCK);
    if (err < 0) {
        LOG_WARN("SPEAKER", "Failed to open %s: %s", dev_name, snd_strerror(err));
        return OZAYN_ERR;
    }

    /* Configure hardware params */
    snd_pcm_hw_params_t *hw_params;
    snd_pcm_hw_params_alloca(&hw_params);
    snd_pcm_hw_params_any(_ozayn_speaker_handle, hw_params);

    /* Set access type */
    snd_pcm_hw_params_set_access(_ozayn_speaker_handle, hw_params, SND_PCM_ACCESS_RW_INTERLEAVED);

    /* Set format: signed 16-bit little-endian */
    snd_pcm_hw_params_set_format(_ozayn_speaker_handle, hw_params, SND_PCM_FORMAT_S16_LE);

    /* Set channels */
    unsigned int channels = (unsigned int)_ozayn_speaker_infos[index].channels;
    if (channels == 0) channels = 2;
    snd_pcm_hw_params_set_channels(_ozayn_speaker_handle, hw_params, channels);

    /* Set sample rate */
    unsigned int rate = (unsigned int)_ozayn_speaker_infos[index].sample_rate;
    if (rate == 0) rate = 44100;
    snd_pcm_hw_params_set_rate_near(_ozayn_speaker_handle, hw_params, &rate, NULL);

    err = snd_pcm_hw_params(_ozayn_speaker_handle, hw_params);
    if (err < 0) {
        LOG_WARN("SPEAKER", "Failed to set hw params: %s", snd_strerror(err));
        snd_pcm_close(_ozayn_speaker_handle);
        _ozayn_speaker_handle = NULL;
        return OZAYN_ERR;
    }

    _ozayn_speaker_open_index = index;
    _ozayn_speaker.open = 1;

    LOG_INFO("SPEAKER", "Audio output opened: %s", _ozayn_speaker_infos[index].name);
    return OZAYN_OK;
}

ozayn_result_t ozayn_audio_output_close(void) {
    if (!_ozayn_speaker.initialized) return OZAYN_ERR;
    if (!_ozayn_speaker.open) return OZAYN_ERR_STATE;

    if (_ozayn_speaker.streaming) {
        ozayn_audio_output_stop();
    }

    if (_ozayn_speaker_handle) {
        snd_pcm_close(_ozayn_speaker_handle);
        _ozayn_speaker_handle = NULL;
    }

    _ozayn_speaker.open = 0;
    _ozayn_speaker_open_index = 0;

    LOG_INFO("SPEAKER", "Audio output closed");
    return OZAYN_OK;
}

ozayn_result_t ozayn_audio_output_start(void) {
    if (!_ozayn_speaker.initialized) return OZAYN_ERR;
    if (!_ozayn_speaker.open) return OZAYN_ERR_STATE;
    if (_ozayn_speaker.streaming) return OZAYN_ERR_STATE;
    if (!_ozayn_speaker_handle) return OZAYN_ERR;

    /* Prepare the PCM device */
    int err = snd_pcm_prepare(_ozayn_speaker_handle);
    if (err < 0) {
        LOG_WARN("SPEAKER", "snd_pcm_prepare failed: %s", snd_strerror(err));
        return OZAYN_ERR;
    }

    _ozayn_speaker.streaming = 1;
    LOG_INFO("SPEAKER", "Playback started");
    return OZAYN_OK;
}

ozayn_result_t ozayn_audio_output_write(const OzaynAudioOutputBuffer *buffer) {
    if (!buffer) return OZAYN_ERR_NULL;
    if (!_ozayn_speaker.initialized) return OZAYN_ERR;
    if (!_ozayn_speaker.open || !_ozayn_speaker.streaming) return OZAYN_ERR_STATE;
    if (!_ozayn_speaker_handle) return OZAYN_ERR;

    /* Validate buffer */
    if (!buffer->data || buffer->data_size == 0) return OZAYN_ERR;
    if (buffer->frame_count == 0) return OZAYN_ERR;
    if (buffer->channels == 0) return OZAYN_ERR;

    /* Check format: only S16 supported currently */
    if (buffer->format != OZAYN_AUDIO_FORMAT_S16) return OZAYN_ERR;

    /* Validate data_size: frame_count * channels * sizeof(int16_t) */
    size_t expected_size = buffer->frame_count * buffer->channels * sizeof(int16_t);
    if (buffer->data_size < expected_size) return OZAYN_ERR;

    /* Write interleaved samples */
    snd_pcm_sframes_t frames = snd_pcm_writei(_ozayn_speaker_handle, buffer->data, buffer->frame_count);
    if (frames < 0) {
        /* Try to recover from underrun */
        frames = snd_pcm_recover(_ozayn_speaker_handle, (int)frames, 0);
        if (frames < 0) {
            LOG_WARN("SPEAKER", "snd_pcm_writei failed: %s", snd_strerror((int)frames));
            return OZAYN_ERR;
        }
        frames = snd_pcm_writei(_ozayn_speaker_handle, buffer->data, buffer->frame_count);
        if (frames < 0) {
            LOG_WARN("SPEAKER", "snd_pcm_writei retry failed: %s", snd_strerror((int)frames));
            return OZAYN_ERR;
        }
    }

    return OZAYN_OK;
}

ozayn_result_t ozayn_audio_output_stop(void) {
    if (!_ozayn_speaker.initialized) return OZAYN_ERR;
    if (!_ozayn_speaker.streaming) return OZAYN_ERR_STATE;

    if (_ozayn_speaker_handle) {
        snd_pcm_drop(_ozayn_speaker_handle);
    }

    _ozayn_speaker.streaming = 0;
    LOG_INFO("SPEAKER", "Playback stopped");
    return OZAYN_OK;
}

/* ================================================================
 * L. Network Information & Connectivity Abstraction (Step 12)
 * ================================================================
 *
 * Cross-platform network interface enumeration, address discovery,
 * and basic connectivity checking. Uses getifaddrs + ioctl on Linux.
 * This is information only — no packet capture or port scanning.
 */

#include <sys/ioctl.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <ifaddrs.h>
#include <netdb.h>
#include <linux/if_packet.h>

static OzaynNetworkState _ozayn_net = {0};
static OzaynNetworkInterfaceInfo _ozayn_net_ifaces[OZAYN_MAX_NETWORK_IFACES];

static void _ozayn_net_enumerate(void) {
    struct ifaddrs *ifaddr, *ifa;
    _ozayn_net.count = 0;
    _ozayn_net.has_default = 0;
    _ozayn_net.default_index = -1;

    if (getifaddrs(&ifaddr) == -1) return;

    int sock = socket(AF_INET, SOCK_DGRAM, 0);

    for (ifa = ifaddr; ifa != NULL && _ozayn_net.count < OZAYN_MAX_NETWORK_IFACES; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL) continue;

        OzaynNetworkInterfaceInfo *info = &_ozayn_net_ifaces[_ozayn_net.count];
        memset(info, 0, sizeof(OzaynNetworkInterfaceInfo));
        info->index = (int)_ozayn_net.count;

        /* Copy name */
        strncpy(info->name, ifa->ifa_name, OZAYN_MAX_IFACE_NAME_LEN - 1);

        /* Flags */
        info->is_up = (ifa->ifa_flags & IFF_UP) ? 1 : 0;
        info->is_loopback = (ifa->ifa_flags & IFF_LOOPBACK) ? 1 : 0;

        /* IPv4 */
        if (ifa->ifa_addr->sa_family == AF_INET) {
            struct sockaddr_in *sa = (struct sockaddr_in *)ifa->ifa_addr;
            inet_ntop(AF_INET, &sa->sin_addr, info->ipv4, OZAYN_MAX_IPV4_LEN);
        }
        /* IPv6 */
        else if (ifa->ifa_addr->sa_family == AF_INET6) {
            struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *)ifa->ifa_addr;
            inet_ntop(AF_INET6, &sa6->sin6_addr, info->ipv6, OZAYN_MAX_IPV6_LEN);
        }

        /* MAC address via ioctl */
        if (sock >= 0 && ifa->ifa_addr && ifa->ifa_addr->sa_family == AF_PACKET) {
            struct sockaddr_ll *sll = (struct sockaddr_ll *)ifa->ifa_addr;
            if (sll->sll_halen == 6) {
                snprintf(info->mac, OZAYN_MAX_MAC_LEN, "%02x:%02x:%02x:%02x:%02x:%02x",
                         sll->sll_addr[0], sll->sll_addr[1], sll->sll_addr[2],
                         sll->sll_addr[3], sll->sll_addr[4], sll->sll_addr[5]);
            }
        }

        /* Track first non-loopback UP interface as default */
        if (!_ozayn_net.has_default && info->is_up && !info->is_loopback && info->ipv4[0]) {
            _ozayn_net.has_default = 1;
            _ozayn_net.default_index = info->index;
        }

        _ozayn_net.count++;
    }

    if (sock >= 0) close(sock);
    freeifaddrs(ifaddr);
}

ozayn_result_t ozayn_network_init(void) {
    if (_ozayn_net.initialized) return OZAYN_OK;

    memset(&_ozayn_net, 0, sizeof(OzaynNetworkState));
    memset(_ozayn_net_ifaces, 0, sizeof(_ozayn_net_ifaces));

    _ozayn_net_enumerate();
    _ozayn_net.available = (_ozayn_net.count > 0) ? 1 : 0;
    _ozayn_net.initialized = 1;

    LOG_INFO("NETWORK", "Network subsystem initialized (interfaces=%u, available=%s)",
             _ozayn_net.count, _ozayn_net.available ? "yes" : "no");

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

    memcpy(info, &_ozayn_net_ifaces[index], sizeof(OzaynNetworkInterfaceInfo));
    return OZAYN_OK;
}

int ozayn_network_get_default_interface(void) {
    if (!_ozayn_net.initialized) return -1;
    return _ozayn_net.default_index;
}

OzaynConnectivityState ozayn_network_is_connected(void) {
    if (!_ozayn_net.initialized) return OZAYN_CONNECTIVITY_UNKNOWN;

    /* Check if any non-loopback interface is UP with an IPv4 address */
    for (unsigned int i = 0; i < _ozayn_net.count; i++) {
        if (_ozayn_net_ifaces[i].is_up && !_ozayn_net_ifaces[i].is_loopback && _ozayn_net_ifaces[i].ipv4[0]) {
            return OZAYN_CONNECTIVITY_CONNECTED;
        }
    }

    /* Check if any non-loopback interface is UP with IPv6 */
    for (unsigned int i = 0; i < _ozayn_net.count; i++) {
        if (_ozayn_net_ifaces[i].is_up && !_ozayn_net_ifaces[i].is_loopback && _ozayn_net_ifaces[i].ipv6[0]) {
            return OZAYN_CONNECTIVITY_CONNECTED;
        }
    }

    /* Interfaces exist but none are up/connected */
    if (_ozayn_net.count > 0) {
        return OZAYN_CONNECTIVITY_DISCONNECTED;
    }

    return OZAYN_CONNECTIVITY_UNKNOWN;
}

/* ================================================================
 * M. Power & Battery Information Abstraction (Step 13)
 * ================================================================
 *
 * Cross-platform power source information and battery status.
 * Uses sysfs on Linux (/sys/class/power_supply/).
 * Read-only — no power management or control.
 */

#include <dirent.h>

static OzaynPowerInfo _ozayn_power = {0};

static void _ozayn_power_read_sysfs(void) {
    memset(&_ozayn_power, 0, sizeof(OzaynPowerInfo));
    _ozayn_power.available = 0;
    _ozayn_power.has_battery = 0;
    _ozayn_power.battery_percent = -1;
    _ozayn_power.charging = 0;
    _ozayn_power.plugged_in = 0;
    _ozayn_power.battery_remaining_seconds = -1;
    _ozayn_power.battery_full_seconds = -1;

    /* Scan /sys/class/power_supply/ for battery devices */
    DIR *dir = opendir("/sys/class/power_supply");
    if (!dir) return;

    struct dirent *entry;
    char battery_path[512] = {0};
    int found_battery = 0;

    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_name[0] == '.') continue;

        char type_path[512];
        char status_path[512];
        snprintf(type_path, sizeof(type_path), "/sys/class/power_supply/%s/type", entry->d_name);
        snprintf(status_path, sizeof(status_path), "/sys/class/power_supply/%s/status", entry->d_name);

        /* Check if this is a Battery type */
        FILE *f = fopen(type_path, "r");
        if (f) {
            char type[64] = {0};
            if (fgets(type, sizeof(type), f)) {
                /* Remove trailing newline */
                size_t len = strlen(type);
                if (len > 0 && type[len-1] == '\n') type[len-1] = '\0';

                if (strcmp(type, "Battery") == 0) {
                    found_battery =1;
                    snprintf(battery_path, sizeof(battery_path), "/sys/class/power_supply/%s", entry->d_name);
                }
            }
            fclose(f);
        }

        /* Check if this is an AC adapter */
        if (!found_battery) {
            f = fopen(type_path, "r");
            if (f) {
                char type[64] = {0};
                if (fgets(type, sizeof(type), f)) {
                    size_t len = strlen(type);
                    if (len > 0 && type[len-1] == '\n') type[len-1] = '\0';
                    if (strcmp(type, "Mains") == 0 || strcmp(type, "USB") == 0) {
                        _ozayn_power.plugged_in = 1;
                    }
                }
                fclose(f);
            }
        }
    }
    closedir(dir);

    if (found_battery && battery_path[0]) {
        _ozayn_power.has_battery = 1;
        _ozayn_power.available = 1;

        /* Read capacity (percentage) */
        char cap_path[512];
        snprintf(cap_path, sizeof(cap_path), "%s/capacity", battery_path);
        FILE *f = fopen(cap_path, "r");
        if (f) {
            int percent = -1;
            if (fscanf(f, "%d", &percent) == 1) {
                if (percent >= 0 && percent <= 100) {
                    _ozayn_power.battery_percent = percent;
                }
            }
            fclose(f);
        }

        /* Read status (Charging/Discharging/Full/Not charging) */
        char status_file[512];
        snprintf(status_file, sizeof(status_file), "%s/status", battery_path);
        f = fopen(status_file, "r");
        if (f) {
            char status[64] = {0};
            if (fgets(status, sizeof(status), f)) {
                size_t len = strlen(status);
                if (len > 0 && status[len-1] == '\n') status[len-1] = '\0';

                if (strcmp(status, "Charging") == 0 || strcmp(status, "Full") == 0) {
                    _ozayn_power.charging = 1;
                }
            }
            fclose(f);
        }

        /* If we found a battery, we're plugged in if charging or full */
        if (_ozayn_power.charging) {
            _ozayn_power.plugged_in = 1;
        }

        /* Read time to full/empty if available */
        char energy_path[512];
        snprintf(energy_path, sizeof(energy_path), "%s/energy_now", battery_path);
        f = fopen(energy_path, "r");
        if (f) {
            long long energy_now = 0;
            if (fscanf(f, "%lld", &energy_now) == 1) {
                /* energy is in microwatt-hours */
                /* We don't compute time here — would need power_now */
            }
            fclose(f);
        }
    } else {
        /* No battery found */
        _ozayn_power.available = 1;
        _ozayn_power.has_battery = 0;
    }
}

ozayn_result_t ozayn_power_init(void) {
    if (_ozayn_power.available) return OZAYN_OK;

    _ozayn_power_read_sysfs();

    LOG_INFO("POWER", "Power subsystem initialized (battery=%s, percent=%d, charging=%s)",
             _ozayn_power.has_battery ? "yes" : "no",
             _ozayn_power.battery_percent,
             _ozayn_power.charging ? "yes" : "no");

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
 * Cross-platform native desktop notification display.
 * Uses notify-send on Linux for desktop notification delivery.
 * No notification history, no GUI windows, no remote notifications.
 */

static int _ozayn_notif_initialized = 0;
static int _ozayn_notif_available = 0;

static int _ozayn_notif_check_available(void) {
    /* Check if notify-send is available */
    int ret = system("which notify-send >/dev/null 2>&1");
    return (ret == 0) ? 1 : 0;
}

ozayn_result_t ozayn_notification_init(void) {
    if (_ozayn_notif_initialized) return OZAYN_OK;

    _ozayn_notif_available = _ozayn_notif_check_available();
    _ozayn_notif_initialized = 1;

    LOG_INFO("NOTIFY", "Notification subsystem initialized (available=%s)",
             _ozayn_notif_available ? "yes" : "no");

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
    if (!notification) return OZAYN_ERR_NULL;
    if (!_ozayn_notif_initialized) return OZAYN_ERR;
    if (!_ozayn_notif_available) return OZAYN_ERR;

    /* Validate title is not empty */
    if (notification->title[0] == '\0') return OZAYN_ERR;

    /* Build command: notify-send "title" "message" */
    char cmd[2048];
    snprintf(cmd, sizeof(cmd), "notify-send \"%s\" \"%s\" 2>/dev/null",
             notification->title, notification->message);

    int ret = system(cmd);
    if (ret != 0) {
        LOG_WARN("NOTIFY", "Failed to send notification");
        return OZAYN_ERR;
    }

    return OZAYN_OK;
}

/* ================================================================
 * O. Clipboard Abstraction (Step 15)
 * ================================================================
 *
 * Cross-platform plain-text clipboard read/write.
 * Uses X11 XSelection mechanism on Linux.
 * No clipboard monitoring, no history, no remote access.
 * Plain text only.
 */

#include <X11/Xatom.h>
#include <X11/Xlib.h>

static Display *_ozayn_clip_display = NULL;
static Window _ozayn_clip_window = None;
static Atom _ozayn_clip_atom = None;
static Atom _ozayn_clip_targets = None;
static Atom _ozayn_clip_text = None;
static int _ozayn_clip_available = 0;

static int _ozayn_clip_check_x11(void) {
    if (!getenv("DISPLAY") && !getenv("WAYLAND_DISPLAY")) {
        return 0;
    }
    Display *d = XOpenDisplay(NULL);
    if (d) {
        XCloseDisplay(d);
        return 1;
    }
    return 0;
}

ozayn_result_t ozayn_clipboard_init(void) {
    if (_ozayn_clip_display) return OZAYN_OK;

    if (!_ozayn_clip_check_x11()) {
        _ozayn_clip_available = 0;
        LOG_INFO("CLIPBOARD", "Clipboard subsystem initialized (available=no, no X11)");
        return OZAYN_OK;
    }

    _ozayn_clip_display = XOpenDisplay(NULL);
    if (!_ozayn_clip_display) {
        _ozayn_clip_available = 0;
        LOG_INFO("CLIPBOARD", "Clipboard subsystem initialized (available=no, XOpenDisplay failed)");
        return OZAYN_OK;
    }

    /* Create a window for clipboard operations */
    _ozayn_clip_window = XCreateSimpleWindow(_ozayn_clip_display,
                                              DefaultRootWindow(_ozayn_clip_display),
                                              0, 0, 1, 1, 0, 0, 0);

    /* Atoms */
    _ozayn_clip_atom = XInternAtom(_ozayn_clip_display, "CLIPBOARD", False);
    _ozayn_clip_targets = XInternAtom(_ozayn_clip_display, "TARGETS", False);
    _ozayn_clip_text = XInternAtom(_ozayn_clip_display, "UTF8_STRING", False);

    _ozayn_clip_available = 1;

    LOG_INFO("CLIPBOARD", "Clipboard subsystem initialized (available=yes)");
    return OZAYN_OK;
}

void ozayn_clipboard_shutdown(void) {
    if (!_ozayn_clip_display) return;

    if (_ozayn_clip_window != None) {
        XDestroyWindow(_ozayn_clip_display, _ozayn_clip_window);
        _ozayn_clip_window = None;
    }

    XCloseDisplay(_ozayn_clip_display);
    _ozayn_clip_display = NULL;
    _ozayn_clip_available = 0;

    LOG_INFO("CLIPBOARD", "Clipboard subsystem shut down");
}

int ozayn_clipboard_is_available(void) {
    return _ozayn_clip_available;
}

int ozayn_clipboard_has_text(void) {
    if (!_ozayn_clip_display || !_ozayn_clip_available) return 0;

    Atom actual;
    int format;
    unsigned long nitems, bytes_after;
    unsigned char *data = NULL;

    int status = XGetWindowProperty(_ozayn_clip_display, _ozayn_clip_window,
                                    _ozayn_clip_atom, 0, 0, False,
                                    XA_ATOM, &actual, &format, &nitems, &bytes_after, &data);

    if (data) XFree(data);

    if (status != Success) return 0;

    /* Check if UTF8_STRING target exists */
    data = NULL;
    status = XGetWindowProperty(_ozayn_clip_display, _ozayn_clip_window,
                                _ozayn_clip_targets, 0, 1024, False,
                                XA_ATOM, &actual, &format, &nitems, &bytes_after, &data);

    if (status != Success || !data) return 0;

    int has_utf8 = 0;
    Atom *atoms = (Atom *)data;
    for (unsigned long i = 0; i < nitems; i++) {
        if (atoms[i] == _ozayn_clip_text) {
            has_utf8 = 1;
            break;
        }
    }

    XFree(data);
    return has_utf8;
}

ozayn_result_t ozayn_clipboard_get_text(char *buffer, size_t buffer_size, size_t *required_size) {
    if (!buffer && required_size) {
        *required_size = 0;
    }

    if (!_ozayn_clip_display || !_ozayn_clip_available) return OZAYN_ERR;

    /* Request clipboard ownership */
    XSetSelectionOwner(_ozayn_clip_display, _ozayn_clip_atom, _ozayn_clip_window, CurrentTime);

    /* Read property */
    Atom actual;
    int format;
    unsigned long nitems, bytes_after;
    unsigned char *data = NULL;

    int status = XGetWindowProperty(_ozayn_clip_display, _ozayn_clip_window,
                                    _ozayn_clip_atom, 0, 1024 * 1024, False,
                                    _ozayn_clip_text, &actual, &format,
                                    &nitems, &bytes_after, &data);

    if (status != Success || !data || nitems == 0) {
        if (data) XFree(data);
        if (buffer && buffer_size > 0) buffer[0] = '\0';
        if (required_size) *required_size = 0;
        return OZAYN_OK;
    }

    size_t text_len = (size_t)nitems;

    if (required_size) *required_size = text_len + 1;

    if (!buffer || buffer_size == 0) {
        XFree(data);
        return OZAYN_OK;
    }

    size_t copy_len = (text_len < buffer_size - 1) ? text_len : buffer_size - 1;
    memcpy(buffer, data, copy_len);
    buffer[copy_len] = '\0';

    XFree(data);
    return OZAYN_OK;
}

ozayn_result_t ozayn_clipboard_set_text(const char *text) {
    if (!text) return OZAYN_ERR_NULL;
    if (!_ozayn_clip_display || !_ozayn_clip_available) return OZAYN_ERR;

    /* Store text in the clipboard window property */
    XChangeProperty(_ozayn_clip_display, _ozayn_clip_window,
                    _ozayn_clip_atom, _ozayn_clip_text, 8,
                    PropModeReplace, (unsigned char *)text, (int)strlen(text));

    XFlush(_ozayn_clip_display);

    return OZAYN_OK;
}

ozayn_result_t ozayn_clipboard_clear(void) {
    if (!_ozayn_clip_display || !_ozayn_clip_available) return OZAYN_ERR;

    /* Delete the clipboard property */
    XDeleteProperty(_ozayn_clip_display, _ozayn_clip_window, _ozayn_clip_atom);
    XFlush(_ozayn_clip_display);

    return OZAYN_OK;
}

/* ================================================================
 * P. Environment & User Session Abstraction (Step 16)
 * ================================================================
 *
 * Cross-platform environment variable access and user-session
 * information. Uses POSIX APIs on Linux.
 * Read-only — no modification of environment or system state.
 * No credential or secret extraction.
 */

#include <pwd.h>
#include <unistd.h>
#include <limits.h>

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
        /* Fallback to passwd */
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
    if (!tmp) tmp = getenv("TMP");
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

    char host[HOST_NAME_MAX + 1];
    if (gethostname(host, sizeof(host)) != 0) {
        buffer[0] = '\0';
        return OZAYN_ERR;
    }
    host[HOST_NAME_MAX] = '\0';

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
 * Cross-platform system time and date information.
 * Uses POSIX clock_gettime on Linux.
 * Read-only — no clock modification, no timezone changes.
 * Basic sleep primitive only — no scheduling.
 */

#include <time.h>
#include <unistd.h>
#include <sys/time.h>
#include <sched.h>

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
    if (tm_info->tm_gmtoff != 0) {
        dt->utc_offset_minutes = (int)(tm_info->tm_gmtoff / 60);
    } else {
        /* Fallback: compute offset */
        struct tm local_tm = *tm_info;
        struct tm utc_tm;
        time_t raw = mktime(tm_info);
        gmtime_r(&raw, &utc_tm);
        dt->utc_offset_minutes = (int)difftime(mktime(&local_tm), mktime(&utc_tm)) / 60;
    }
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
        /* Zero sleep — yield the CPU briefly */
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
 * Cross-platform application discovery, launching, and URL opening.
 * Uses fork()+execvp() for launching, access()/which for existence.
 * No shell execution — uses native OS mechanisms only.
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

    /* Skip if it contains path separators — not a simple app name */
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

/* Internal helper: try to find a desktop URL opener */
static const char* _ozayn_find_url_opener(void) {
    /* Check for common URL openers */
    static const char *openers[] = {
        "xdg-open",
        "gnome-open",
        "kde-open",
        "kfmclient",
        "gio",
        NULL
    };

    for (int i = 0; openers[i]; i++) {
        if (_ozayn_app_search_path(openers[i])) {
            return openers[i];
        }
    }

    return NULL;
}

/* Internal helper: get default browser via xdg-settings or similar */
static ozayn_result_t _ozayn_get_default_browser_xdg(char *buffer, size_t buffer_size) {
    if (!buffer || buffer_size == 0) return OZAYN_ERR_NULL;

    const char *xdg_settings = NULL;
    const char *openers[] = { "xdg-settings", "xdg-mime", NULL };

    for (int i = 0; openers[i]; i++) {
        if (_ozayn_app_search_path(openers[i])) {
            xdg_settings = openers[i];
            break;
        }
    }

    if (!xdg_settings) {
        return OZAYN_ERR;
    }

    /* Try xdg-settings get default-web-browser */
    if (strcmp(xdg_settings, "xdg-settings") == 0) {
        int pipefd[2];
        if (pipe(pipefd) != 0) return OZAYN_ERR;

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
                /* Trim trailing newlines */
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

    /* Fallback: try to find common browser executables */
    const char *browsers[] = {
        "firefox", "google-chrome", "chromium", "chromium-browser",
        "opera", "brave-browser", "vivaldi", "epiphany", "midori",
        "lynx", "w3m", "links", NULL
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

    /* Find the executable path */
    char fullpath[4096] = {0};
    int found = 0;

    if (strchr(application, '/') != NULL) {
        /* Absolute or relative path — check directly */
        if (_ozayn_app_is_executable(application)) {
            size_t len = strlen(application);
            if (len >= sizeof(fullpath)) len = sizeof(fullpath) - 1;
            memcpy(fullpath, application, len);
            fullpath[len] = '\0';
            found = 1;
        }
    } else {
        /* Search PATH */
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
                    if (_ozayn_app_is_executable(fullpath)) {
                        found = 1;
                    }
                }
                dir = strtok_r(NULL, ":", &saveptr);
            }
        }
    }

    if (!found) return OZAYN_ERR;

    /* Fork and exec — no shell */
    pid_t pid = fork();
    if (pid == 0) {
        /* Child process */
        setsid();
        execl(fullpath, application, (char *)NULL);
        /* If exec fails, exit immediately */
        _exit(127);
    } else if (pid > 0) {
        /* Parent — wait briefly to detect immediate failures */
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

static int _ozayn_is_valid_url_scheme(const char *url) {
    if (!url) return 0;

    /* Check for valid schemes */
    const char *valid[] = { "http://", "https://", "ftp://", "mailto:", NULL };

    for (int i = 0; valid[i]; i++) {
        size_t len = strlen(valid[i]);
        if (strncmp(url, valid[i], len) == 0) {
            return 1;
        }
    }

    return 0;
}

ozayn_result_t ozayn_application_open_url(const char *url) {
    if (!url) return OZAYN_ERR_NULL;
    if (!*url) return OZAYN_ERR;
    if (!_ozayn_application_initialized) return OZAYN_ERR;

    /* Validate URL scheme */
    if (!_ozayn_is_valid_url_scheme(url)) return OZAYN_ERR;

    /* Find URL opener */
    const char *opener = _ozayn_find_url_opener();
    if (!opener) return OZAYN_ERR;

    /* Fork and exec — no shell, pass URL as argument */
    pid_t pid = fork();
    if (pid == 0) {
        /* Child process */
        setsid();
        execlp(opener, opener, url, (char *)NULL);
        _exit(127);
    } else if (pid > 0) {
        /* Parent — wait briefly to detect immediate failures */
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
 * Cross-platform capability/permission inspection.
 * Read-only — no permission modification, no bypass, no elevation.
 * Linux: checks device files, command availability, X11 extensions.
 */

static int _ozayn_permissions_initialized = 0;

/* Internal helper: check if V4L2 camera devices exist */
static int _ozayn_check_camera(void) {
    DIR *dir = opendir("/dev");
    if (!dir) return 0;
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (strncmp(entry->d_name, "video", 5) == 0) {
            closedir(dir);
            return 1;
        }
    }
    closedir(dir);
    return 0;
}

/* Internal helper: check if ALSA capture devices exist */
static int _ozayn_check_microphone(void) {
    void **hints = NULL;
    int err = snd_device_name_hint(-1, "pcm", &hints);
    if (err < 0 || !hints) return 0;

    int found = 0;
    for (int i = 0; hints[i] && !found; i++) {
        char *name = snd_device_name_get_hint(hints[i], "NAME");
        char *desc = snd_device_name_get_hint(hints[i], "DESC");
        char *io = snd_device_name_get_hint(hints[i], "IOID");

        /* Check if it's a capture device (no IOID or IOID=INPUT) */
        int is_capture = (!io || strstr(io, "INPUT"));

        if (is_capture && name && strstr(name, "hw:") != NULL) {
            /* Try to open it to confirm it works */
            snd_pcm_t *pcm;
            if (snd_pcm_open(&pcm, name, SND_PCM_STREAM_CAPTURE, 0) == 0) {
                snd_pcm_close(pcm);
                found = 1;
            }
        }

        free(name);
        free(desc);
        free(io);
    }

    snd_device_name_free_hint(hints);
    return found;
}

/* Internal helper: check if notification tool is available */
static int _ozayn_check_notifications(void) {
    /* Check for notify-send in PATH */
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
            snprintf(fullpath, sizeof(fullpath), "%s/notify-send", dir);
            struct stat st;
            if (stat(fullpath, &st) == 0 && S_ISREG(st.st_mode) &&
                (st.st_mode & (S_IXUSR | S_IXGRP | S_IXOTH))) {
                return 1;
            }
        }
        dir = strtok_r(NULL, ":", &saveptr);
    }
    return 0;
}

/* Internal helper: check X11 accessibility extensions */
static int _ozayn_check_accessibility(void) {
#ifdef OZAYN_OS_LINUX
    const char *display_env = getenv("DISPLAY");
    if (!display_env || !*display_env) return 0;

    Display *dpy = XOpenDisplay(NULL);
    if (!dpy) return 0;

    int has_xtest = 0;
    int dummy1, dummy2;
    has_xtest = XQueryExtension(dpy, "TEST", &dummy1, &dummy2, &dummy2);

    XCloseDisplay(dpy);
    return has_xtest;
#else
    return 0;
#endif
}

/* Internal helper: check filesystem basic access */
static int _ozayn_check_filesystem(void) {
    /* Check if we can access /tmp */
    return (access("/tmp", R_OK | W_OK) == 0);
}

/* Internal helper: check network interfaces */
static int _ozayn_check_network(void) {
    struct ifaddrs *ifaddr;
    if (getifaddrs(&ifaddr) == -1) return 0;

    int found = 0;
    for (struct ifaddrs *ifa = ifaddr; ifa != NULL && !found; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL) continue;
        if (ifa->ifa_flags & IFF_UP) found = 1;
    }

    freeifaddrs(ifaddr);
    return found;
}

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
        case OZAYN_CAP_CAMERA:
            return _ozayn_check_camera() ? OZAYN_PERMISSION_AVAILABLE : OZAYN_PERMISSION_UNAVAILABLE;
        case OZAYN_CAP_MICROPHONE:
            return _ozayn_check_microphone() ? OZAYN_PERMISSION_AVAILABLE : OZAYN_PERMISSION_UNAVAILABLE;
        case OZAYN_CAP_NOTIFICATIONS:
            return _ozayn_check_notifications() ? OZAYN_PERMISSION_AVAILABLE : OZAYN_PERMISSION_UNAVAILABLE;
        case OZAYN_CAP_ACCESSIBILITY:
            return _ozayn_check_accessibility() ? OZAYN_PERMISSION_AVAILABLE : OZAYN_PERMISSION_UNAVAILABLE;
        case OZAYN_CAP_FILESYSTEM:
            return _ozayn_check_filesystem() ? OZAYN_PERMISSION_AVAILABLE : OZAYN_PERMISSION_UNAVAILABLE;
        case OZAYN_CAP_NETWORK:
            return _ozayn_check_network() ? OZAYN_PERMISSION_AVAILABLE : OZAYN_PERMISSION_UNAVAILABLE;
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
 * Cross-platform system audio output volume and mute state control.
 * Uses ALSA mixer API on Linux for the default output device.
 * Volume range: 0–100. Mute: 0 or 1.
 */

static int _ozayn_audio_volume_initialized = 0;

/* Internal helper: open default ALSA mixer for playback */
static snd_mixer_t *_ozayn_open_default_mixer(void) {
    snd_mixer_t *mixer;
    int err = snd_mixer_open(&mixer, 0);
    if (err < 0 || !mixer) return NULL;

    /* Attach to default card */
    err = snd_mixer_attach(mixer, "default");
    if (err < 0) {
        /* Try "hw:0" as fallback */
        err = snd_mixer_attach(mixer, "hw:0");
        if (err < 0) {
            snd_mixer_close(mixer);
            return NULL;
        }
    }

    err = snd_mixer_selem_register(mixer, NULL, NULL);
    if (err < 0) {
        snd_mixer_close(mixer);
        return NULL;
    }

    snd_mixer_load(mixer);
    return mixer;
}

/* Internal helper: find the first playback element */
static snd_mixer_elem_t *_ozayn_find_playback_elem(snd_mixer_t *mixer) {
    snd_mixer_elem_t *elem = snd_mixer_first_elem(mixer);
    while (elem) {
        if (snd_mixer_elem_get_type(elem) == SND_MIXER_ELEM_SIMPLE) {
            snd_mixer_selem_id_t *sid;
            snd_mixer_selem_id_alloca(&sid);
            snd_mixer_selem_get_id(elem, sid);

            /* Look for Master, PCM, or Speaker */
            const char *name = snd_mixer_selem_id_get_name(sid);
            if (strstr(name, "Master") || strstr(name, "PCM") || strstr(name, "Speaker")) {
                /* Check if it has playback volume */
                if (snd_mixer_selem_has_playback_volume(elem)) {
                    return elem;
                }
            }
        }
        elem = snd_mixer_elem_next(elem);
    }

    /* Fallback: find any element with playback volume */
    elem = snd_mixer_first_elem(mixer);
    while (elem) {
        if (snd_mixer_elem_get_type(elem) == SND_MIXER_ELEM_SIMPLE) {
            if (snd_mixer_selem_has_playback_volume(elem)) {
                return elem;
            }
        }
        elem = snd_mixer_elem_next(elem);
    }

    return NULL;
}

/* Internal helper: convert ALSA volume (long) to 0-100 */
static int _ozayn_alsa_to_percent(long alsa_vol, long min, long max) {
    if (max <= min) return 0;
    int percent = (int)((alsa_vol - min) * 100 / (max - min));
    if (percent < 0) percent = 0;
    if (percent > 100) percent = 100;
    return percent;
}

/* Internal helper: convert 0-100 to ALSA volume (long) */
static long _ozayn_percent_to_alsa(int percent, long min, long max) {
    if (percent < 0) percent = 0;
    if (percent > 100) percent = 100;
    if (max <= min) return min;
    return min + (long)percent * (max - min) / 100;
}

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

    snd_mixer_t *mixer = _ozayn_open_default_mixer();
    if (!mixer) return 0;

    snd_mixer_elem_t *elem = _ozayn_find_playback_elem(mixer);
    snd_mixer_close(mixer);
    return elem != NULL;
}

ozayn_result_t ozayn_audio_volume_get(int *volume) {
    if (!volume) return OZAYN_ERR_NULL;
    if (!_ozayn_audio_volume_initialized) return OZAYN_ERR;

    snd_mixer_t *mixer = _ozayn_open_default_mixer();
    if (!mixer) return OZAYN_ERR;

    snd_mixer_elem_t *elem = _ozayn_find_playback_elem(mixer);
    if (!elem) {
        snd_mixer_close(mixer);
        return OZAYN_ERR;
    }

    long min, max;
    snd_mixer_selem_get_playback_volume_range(elem, &min, &max);

    long alsa_vol;
    int err = snd_mixer_selem_get_playback_volume(elem, SND_MIXER_SCHN_FRONT_LEFT, &alsa_vol);
    if (err < 0) {
        snd_mixer_close(mixer);
        return OZAYN_ERR;
    }

    *volume = _ozayn_alsa_to_percent(alsa_vol, min, max);
    snd_mixer_close(mixer);
    return OZAYN_OK;
}

ozayn_result_t ozayn_audio_volume_set(int volume) {
    if (volume < 0 || volume > 100) return OZAYN_ERR;
    if (!_ozayn_audio_volume_initialized) return OZAYN_ERR;

    snd_mixer_t *mixer = _ozayn_open_default_mixer();
    if (!mixer) return OZAYN_ERR;

    snd_mixer_elem_t *elem = _ozayn_find_playback_elem(mixer);
    if (!elem) {
        snd_mixer_close(mixer);
        return OZAYN_ERR;
    }

    long min, max;
    snd_mixer_selem_get_playback_volume_range(elem, &min, &max);
    long alsa_vol = _ozayn_percent_to_alsa(volume, min, max);

    /* Set both channels */
    snd_mixer_selem_set_playback_volume_all(elem, alsa_vol);

    snd_mixer_close(mixer);
    return OZAYN_OK;
}

ozayn_result_t ozayn_audio_volume_is_muted(int *muted) {
    if (!muted) return OZAYN_ERR_NULL;
    if (!_ozayn_audio_volume_initialized) return OZAYN_ERR;

    snd_mixer_t *mixer = _ozayn_open_default_mixer();
    if (!mixer) return OZAYN_ERR;

    snd_mixer_elem_t *elem = _ozayn_find_playback_elem(mixer);
    if (!elem) {
        snd_mixer_close(mixer);
        return OZAYN_ERR;
    }

    int sw;
    int err = snd_mixer_selem_get_playback_switch(elem, SND_MIXER_SCHN_FRONT_LEFT, &sw);
    if (err < 0) {
        snd_mixer_close(mixer);
        return OZAYN_ERR;
    }

    /* ALSA: switch=0 means muted, switch=1 means unmuted */
    *muted = sw ? 0 : 1;
    snd_mixer_close(mixer);
    return OZAYN_OK;
}

ozayn_result_t ozayn_audio_volume_set_muted(int muted) {
    if (!_ozayn_audio_volume_initialized) return OZAYN_ERR;

    snd_mixer_t *mixer = _ozayn_open_default_mixer();
    if (!mixer) return OZAYN_ERR;

    snd_mixer_elem_t *elem = _ozayn_find_playback_elem(mixer);
    if (!elem) {
        snd_mixer_close(mixer);
        return OZAYN_ERR;
    }

    /* ALSA: switch=0 means muted, switch=1 means unmuted */
    snd_mixer_selem_set_playback_switch_all(elem, muted ? 0 : 1);

    snd_mixer_close(mixer);
    return OZAYN_OK;
}

ozayn_result_t ozayn_audio_volume_toggle_mute(void) {
    if (!_ozayn_audio_volume_initialized) return OZAYN_ERR;

    int muted;
    ozayn_result_t r = ozayn_audio_volume_is_muted(&muted);
    if (r != OZAYN_OK) return r;

    return ozayn_audio_volume_set_muted(muted ? 0 : 1);
}

/* ================================================================
 * U. System Lock State & Session Control Abstraction (Step 21)
 * ================================================================
 *
 * Cross-platform session state detection and lock control.
 * Uses XScreenSaver extension on Linux for lock detection.
 * Read-only detection + safe lock action only.
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
#ifdef OZAYN_OS_LINUX
    const char *display_env = getenv("DISPLAY");
    if (display_env && *display_env) return 1;
#endif
    return 0;
}

OzaynSessionState ozayn_session_get_state(void) {
    if (!_ozayn_session_initialized) return OZAYN_SESSION_UNKNOWN;

#ifdef OZAYN_OS_LINUX
    const char *display_env = getenv("DISPLAY");
    if (!display_env || !*display_env) return OZAYN_SESSION_UNAVAILABLE;

    Display *dpy = XOpenDisplay(NULL);
    if (!dpy) return OZAYN_SESSION_UNAVAILABLE;

    int event_base, error_base;
    if (!XScreenSaverQueryExtension(dpy, &event_base, &error_base)) {
        XCloseDisplay(dpy);
        return OZAYN_SESSION_UNAVAILABLE;
    }

    XScreenSaverInfo *info = XScreenSaverAllocInfo();
    if (!info) {
        XCloseDisplay(dpy);
        return OZAYN_SESSION_UNKNOWN;
    }

    XScreenSaverQueryInfo(dpy, DefaultRootWindow(dpy), info);

    OzaynSessionState state;
    if (info->window != None && info->window != 0) {
        state = OZAYN_SESSION_LOCKED;
    } else if (info->idle > 300000) {
        /* More than 5 minutes idle */
        state = OZAYN_SESSION_INACTIVE;
    } else {
        state = OZAYN_SESSION_ACTIVE;
    }

    XFree(info);
    XCloseDisplay(dpy);
    return state;
#else
    return OZAYN_SESSION_UNAVAILABLE;
#endif
}

int ozayn_session_is_locked(void) {
    if (!_ozayn_session_initialized) return 0;
    return ozayn_session_get_state() == OZAYN_SESSION_LOCKED;
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

#ifdef OZAYN_OS_LINUX
    const char *display_env = getenv("DISPLAY");
    if (!display_env || !*display_env) return OZAYN_ERR;

    Display *dpy = XOpenDisplay(NULL);
    if (!dpy) return OZAYN_ERR;

    int event_base, error_base;
    if (!XScreenSaverQueryExtension(dpy, &event_base, &error_base)) {
        XCloseDisplay(dpy);
        return OZAYN_ERR;
    }

    /* Force screen saver activation (lock) */
    XForceScreenSaver(dpy, ScreenSaverActive);
    XSync(dpy, False);
    XCloseDisplay(dpy);
    return OZAYN_OK;
#else
    return OZAYN_ERR;
#endif
}

/* ================================================================
 * V. System Brightness & Display Power Abstraction (Step 22)
 * ================================================================
 *
 * Cross-platform display brightness query and control.
 * Uses /sys/class/backlight/ interface on Linux.
 * Brightness range: 0–100 (normalized from native range).
 */

static int _ozayn_brightness_initialized = 0;
static char _ozayn_brightness_path[256] = {0};
static int _ozayn_brightness_max = 0;

/* Internal helper: find backlight device path */
static int _ozayn_find_backlight(void) {
    DIR *dir = opendir("/sys/class/backlight");
    if (!dir) return 0;

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_name[0] == '.') continue;

        char path[256];
        snprintf(path, sizeof(path), "/sys/class/backlight/%s/brightness", entry->d_name);

        struct stat st;
        if (stat(path, &st) == 0 && S_ISREG(st.st_mode)) {
            /* Check if we can read it */
            FILE *f = fopen(path, "r");
            if (f) {
                fclose(f);
                snprintf(_ozayn_brightness_path, sizeof(_ozayn_brightness_path),
                         "/sys/class/backlight/%s", entry->d_name);

                /* Read max brightness */
                char max_path[256];
                snprintf(max_path, sizeof(max_path), "%s/max_brightness", _ozayn_brightness_path);
                FILE *mf = fopen(max_path, "r");
                if (mf) {
                    if (fscanf(mf, "%d", &_ozayn_brightness_max) != 1) {
                        _ozayn_brightness_max = 100;
                    }
                    fclose(mf);
                } else {
                    _ozayn_brightness_max = 100;
                }

                closedir(dir);
                return 1;
            }
        }
    }

    closedir(dir);
    return 0;
}

/* Internal helper: convert native brightness to 0-100 */
static int _ozayn_native_to_percent(int native_val, int max_val) {
    if (max_val <= 0) return 0;
    int percent = (native_val * 100) / max_val;
    if (percent < 0) percent = 0;
    if (percent > 100) percent = 100;
    return percent;
}

/* Internal helper: convert 0-100 to native brightness */
static int _ozayn_percent_to_native(int percent, int max_val) {
    if (percent < 0) percent = 0;
    if (percent > 100) percent = 100;
    if (max_val <= 0) return 0;
    return (percent * max_val) / 100;
}

ozayn_result_t ozayn_brightness_init(void) {
    if (_ozayn_brightness_initialized) return OZAYN_OK;
    _ozayn_brightness_path[0] = '\0';
    _ozayn_brightness_max = 0;
    _ozayn_brightness_initialized = 1;
    LOG_INFO("BRIGHT", "Brightness subsystem initialized");
    return OZAYN_OK;
}

void ozayn_brightness_shutdown(void) {
    if (!_ozayn_brightness_initialized) return;
    _ozayn_brightness_path[0] = '\0';
    _ozayn_brightness_max = 0;
    _ozayn_brightness_initialized = 0;
    LOG_INFO("BRIGHT", "Brightness subsystem shut down");
}

int ozayn_brightness_is_available(void) {
    if (!_ozayn_brightness_initialized) return 0;
    return _ozayn_find_backlight();
}

ozayn_result_t ozayn_brightness_get(int *brightness) {
    if (!brightness) return OZAYN_ERR_NULL;
    if (!_ozayn_brightness_initialized) return OZAYN_ERR;

    if (!_ozayn_find_backlight()) return OZAYN_ERR;

    char path[256];
    snprintf(path, sizeof(path), "%s/brightness", _ozayn_brightness_path);

    FILE *f = fopen(path, "r");
    if (!f) return OZAYN_ERR;

    int native_val;
    if (fscanf(f, "%d", &native_val) != 1) {
        fclose(f);
        return OZAYN_ERR;
    }
    fclose(f);

    *brightness = _ozayn_native_to_percent(native_val, _ozayn_brightness_max);
    return OZAYN_OK;
}

ozayn_result_t ozayn_brightness_set(int brightness) {
    if (brightness < 0 || brightness > 100) return OZAYN_ERR;
    if (!_ozayn_brightness_initialized) return OZAYN_ERR;

    if (!_ozayn_find_backlight()) return OZAYN_ERR;

    char path[256];
    snprintf(path, sizeof(path), "%s/brightness", _ozayn_brightness_path);

    FILE *f = fopen(path, "w");
    if (!f) return OZAYN_ERR;

    int native_val = _ozayn_percent_to_native(brightness, _ozayn_brightness_max);
    if (fprintf(f, "%d", native_val) < 0) {
        fclose(f);
        return OZAYN_ERR;
    }
    fclose(f);

    return OZAYN_OK;
}

ozayn_result_t ozayn_brightness_get_supported(int *supported) {
    if (!supported) return OZAYN_ERR_NULL;
    if (!_ozayn_brightness_initialized) return OZAYN_ERR;

    *supported = _ozayn_find_backlight() ? 1 : 0;
    return OZAYN_OK;
}

/* ================================================================
 * I. Input & Mouse Abstraction (Step 07)
 * ================================================================
 *
 * Uses X11 native APIs for mouse position and button control.
 * Coordinate convention: (0,0) = top-left of primary display.
 * X increases rightward, Y increases downward.
 */

static OzaynInputState _ozayn_input = {0};

/* X11 display connection for input operations */
static Display *_ozayn_input_display = NULL;

static int _ozayn_input_check_x11(void) {
    if (!getenv("DISPLAY") && !getenv("WAYLAND_DISPLAY")) {
        return 0;
    }
    /* Try to open X display */
    Display *d = XOpenDisplay(NULL);
    if (d) {
        XCloseDisplay(d);
        return 1;
    }
    return 0;
}

ozayn_result_t ozayn_input_init(void) {
    if (_ozayn_input.initialized) return OZAYN_OK;

    memset(&_ozayn_input, 0, sizeof(OzaynInputState));

    /* Check if X11 is available */
    if (_ozayn_input_check_x11()) {
        _ozayn_input_display = XOpenDisplay(NULL);
        if (_ozayn_input_display) {
            _ozayn_input.available = 1;
            _ozayn_input.device_info.has_mouse = 1;
            _ozayn_input.device_info.has_keyboard = 1;
        }
    }

    _ozayn_input.initialized = 1;

    LOG_INFO("INPUT", "Input subsystem initialized (available=%s)",
             _ozayn_input.available ? "yes" : "no");

    return OZAYN_OK;
}

void ozayn_input_shutdown(void) {
    if (!_ozayn_input.initialized) return;

    if (_ozayn_input_display) {
        XCloseDisplay(_ozayn_input_display);
        _ozayn_input_display = NULL;
    }

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
    if (!_ozayn_input_display) return OZAYN_ERR;

    Window root, child;
    int root_x, root_y;
    unsigned int mask;

    if (XQueryPointer(_ozayn_input_display, DefaultRootWindow(_ozayn_input_display),
                      &root, &child, &root_x, &root_y, &root_x, &root_y, &mask)) {
        *x = (int32_t)root_x;
        *y = (int32_t)root_y;
        return OZAYN_OK;
    }

    return OZAYN_ERR;
}

ozayn_result_t ozayn_input_get_mouse_state(OzaynMouseState *state) {
    if (!state) return OZAYN_ERR_NULL;
    if (!_ozayn_input.initialized) return OZAYN_ERR;
    if (!_ozayn_input_display) return OZAYN_ERR;

    memset(state, 0, sizeof(OzaynMouseState));

    Window root, child;
    int root_x, root_y;
    unsigned int mask;

    if (XQueryPointer(_ozayn_input_display, DefaultRootWindow(_ozayn_input_display),
                      &root, &child, &root_x, &root_y, &root_x, &root_y, &mask)) {
        state->x = (int32_t)root_x;
        state->y = (int32_t)root_y;
        state->left_button = (mask & Button1Mask) ? 1 : 0;
        state->middle_button = (mask & Button2Mask) ? 1 : 0;
        state->right_button = (mask & Button3Mask) ? 1 : 0;
        state->available = 1;
        return OZAYN_OK;
    }

    return OZAYN_ERR;
}

ozayn_result_t ozayn_input_move_mouse(int32_t x, int32_t y) {
    if (!_ozayn_input.initialized) return OZAYN_ERR;
    if (!_ozayn_input_display) return OZAYN_ERR;

    XWarpPointer(_ozayn_input_display, None, DefaultRootWindow(_ozayn_input_display),
                 0, 0, 0, 0, (int)x, (int)y);
    XFlush(_ozayn_input_display);
    return OZAYN_OK;
}

static ozayn_result_t _ozayn_input_button_event(unsigned int button, int press) {
    if (!_ozayn_input.initialized) return OZAYN_ERR;
    if (!_ozayn_input_display) return OZAYN_ERR;

    XTestFakeButtonEvent(_ozayn_input_display, button, press, CurrentTime);
    XFlush(_ozayn_input_display);
    return OZAYN_OK;
}

ozayn_result_t ozayn_input_mouse_left_down(void) {
    return _ozayn_input_button_event(Button1, True);
}

ozayn_result_t ozayn_input_mouse_left_up(void) {
    return _ozayn_input_button_event(Button1, False);
}

ozayn_result_t ozayn_input_mouse_right_down(void) {
    return _ozayn_input_button_event(Button3, True);
}

ozayn_result_t ozayn_input_mouse_right_up(void) {
    return _ozayn_input_button_event(Button3, False);
}

ozayn_result_t ozayn_input_mouse_middle_down(void) {
    return _ozayn_input_button_event(Button2, True);
}

ozayn_result_t ozayn_input_mouse_middle_up(void) {
    return _ozayn_input_button_event(Button2, False);
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
 * Uses X11 XQueryKeymap for key state queries and XCheckWindowEvent
 * for non-blocking event polling. Key mapping translates OzaynKey
 * to X11 KeySym via a static lookup table.
 */

static OzaynKeyboardState _ozayn_keyboard = {0};

/* OzaynKey -> X11 KeySym mapping table */
static KeySym _ozayn_key_to_keysym_table[OZAYN_KEY_COUNT] = {
    [OZAYN_KEY_UNKNOWN] = 0,

    /* Letters */
    [OZAYN_KEY_A] = XK_a, [OZAYN_KEY_B] = XK_b, [OZAYN_KEY_C] = XK_c,
    [OZAYN_KEY_D] = XK_d, [OZAYN_KEY_E] = XK_e, [OZAYN_KEY_F] = XK_f,
    [OZAYN_KEY_G] = XK_g, [OZAYN_KEY_H] = XK_h, [OZAYN_KEY_I] = XK_i,
    [OZAYN_KEY_J] = XK_j, [OZAYN_KEY_K] = XK_k, [OZAYN_KEY_L] = XK_l,
    [OZAYN_KEY_M] = XK_m, [OZAYN_KEY_N] = XK_n, [OZAYN_KEY_O] = XK_o,
    [OZAYN_KEY_P] = XK_p, [OZAYN_KEY_Q] = XK_q, [OZAYN_KEY_R] = XK_r,
    [OZAYN_KEY_S] = XK_s, [OZAYN_KEY_T] = XK_t, [OZAYN_KEY_U] = XK_u,
    [OZAYN_KEY_V] = XK_v, [OZAYN_KEY_W] = XK_w, [OZAYN_KEY_X] = XK_x,
    [OZAYN_KEY_Y] = XK_y, [OZAYN_KEY_Z] = XK_z,

    /* Digits */
    [OZAYN_KEY_0] = XK_0, [OZAYN_KEY_1] = XK_1, [OZAYN_KEY_2] = XK_2,
    [OZAYN_KEY_3] = XK_3, [OZAYN_KEY_4] = XK_4, [OZAYN_KEY_5] = XK_5,
    [OZAYN_KEY_6] = XK_6, [OZAYN_KEY_7] = XK_7, [OZAYN_KEY_8] = XK_8,
    [OZAYN_KEY_9] = XK_9,

    /* Control keys */
    [OZAYN_KEY_ESCAPE] = XK_Escape, [OZAYN_KEY_ENTER] = XK_Return,
    [OZAYN_KEY_TAB] = XK_Tab, [OZAYN_KEY_SPACE] = XK_space,
    [OZAYN_KEY_BACKSPACE] = XK_BackSpace,

    /* Modifier keys */
    [OZAYN_KEY_SHIFT] = XK_Shift_L, [OZAYN_KEY_CTRL] = XK_Control_L,
    [OZAYN_KEY_ALT] = XK_Alt_L,

    /* Arrow keys */
    [OZAYN_KEY_UP] = XK_Up, [OZAYN_KEY_DOWN] = XK_Down,
    [OZAYN_KEY_LEFT] = XK_Left, [OZAYN_KEY_RIGHT] = XK_Right,

    /* Navigation */
    [OZAYN_KEY_HOME] = XK_Home, [OZAYN_KEY_END] = XK_End,
    [OZAYN_KEY_PAGE_UP] = XK_Page_Up, [OZAYN_KEY_PAGE_DOWN] = XK_Page_Down,
    [OZAYN_KEY_INSERT] = XK_Insert, [OZAYN_KEY_DELETE] = XK_Delete,

    /* Function keys */
    [OZAYN_KEY_F1] = XK_F1, [OZAYN_KEY_F2] = XK_F2, [OZAYN_KEY_F3] = XK_F3,
    [OZAYN_KEY_F4] = XK_F4, [OZAYN_KEY_F5] = XK_F5, [OZAYN_KEY_F6] = XK_F6,
    [OZAYN_KEY_F7] = XK_F7, [OZAYN_KEY_F8] = XK_F8, [OZAYN_KEY_F9] = XK_F9,
    [OZAYN_KEY_F10] = XK_F10, [OZAYN_KEY_F11] = XK_F11, [OZAYN_KEY_F12] = XK_F12,
};

/* OzaynKey -> human-readable name table */
static const char *_ozayn_key_name_table[OZAYN_KEY_COUNT] = {
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

static KeyCode _ozayn_key_to_x11(OzaynKey key) {
    if (key <= OZAYN_KEY_UNKNOWN || key >= OZAYN_KEY_COUNT) return 0;
    KeySym sym = _ozayn_key_to_keysym_table[key];
    if (sym == 0) return 0;
    return XKeysymToKeycode(_ozayn_input_display, sym);
}

ozayn_result_t ozayn_keyboard_init(void) {
    if (_ozayn_keyboard.initialized) return OZAYN_OK;

    memset(&_ozayn_keyboard, 0, sizeof(OzaynKeyboardState));

    if (_ozayn_input_display) {
        _ozayn_keyboard.available = 1;
    }

    _ozayn_keyboard.initialized = 1;

    LOG_INFO("KEYBOARD", "Keyboard subsystem initialized (available=%s)",
             _ozayn_keyboard.available ? "yes" : "no");

    return OZAYN_OK;
}

void ozayn_keyboard_shutdown(void) {
    if (!_ozayn_keyboard.initialized) return;
    memset(&_ozayn_keyboard, 0, sizeof(OzaynKeyboardState));
    LOG_INFO("KEYBOARD", "Keyboard subsystem shut down");
}

int ozayn_keyboard_is_available(void) {
    return _ozayn_keyboard.available;
}

int ozayn_keyboard_is_key_down(OzaynKey key) {
    if (!_ozayn_keyboard.initialized) return -1;
    if (!_ozayn_keyboard.available) return -1;
    if (key <= OZAYN_KEY_UNKNOWN || key >= OZAYN_KEY_COUNT) return -1;

    KeyCode xcode = _ozayn_key_to_x11(key);
    if (xcode == 0) return -1;

    char keys_return[32];
    XQueryKeymap(_ozayn_input_display, keys_return);

    return (keys_return[xcode >> 3] & (1 << (xcode & 7))) ? 1 : 0;
}

ozayn_result_t ozayn_keyboard_poll_event(OzaynInputEvent *event) {
    if (!event) return OZAYN_ERR_NULL;
    if (!_ozayn_keyboard.initialized) return OZAYN_ERR;

    event->type = OZAYN_INPUT_EVENT_NONE;
    event->key = OZAYN_KEY_UNKNOWN;
    event->modifiers = 0;

    if (!_ozayn_keyboard.available || !_ozayn_input_display) return OZAYN_ERR;

    /* Non-blocking check for pending X11 events */
    if (!XPending(_ozayn_input_display)) return OZAYN_ERR;

    XEvent xev;
    XNextEvent(_ozayn_input_display, &xev);

    if (xev.type == KeyPress || xev.type == KeyRelease) {
        KeySym sym = XLookupKeysym(&xev.xkey, 0);

        /* Map KeySym to OzaynKey */
        OzaynKey oz_key = OZAYN_KEY_UNKNOWN;
        for (int i = 1; i < OZAYN_KEY_COUNT; i++) {
            if (_ozayn_key_to_keysym_table[i] == sym) {
                oz_key = (OzaynKey)i;
                break;
            }
        }

        event->type = (xev.type == KeyPress) ? OZAYN_INPUT_EVENT_KEY_DOWN : OZAYN_INPUT_EVENT_KEY_UP;
        event->key = oz_key;

        /* Determine modifier state */
        event->modifiers = 0;
        if (xev.xkey.state & ShiftMask)   event->modifiers |= OZAYN_MOD_SHIFT;
        if (xev.xkey.state & ControlMask) event->modifiers |= OZAYN_MOD_CTRL;
        if (xev.xkey.state & Mod1Mask)    event->modifiers |= OZAYN_MOD_ALT;

        return OZAYN_OK;
    }

    return OZAYN_ERR;
}

const char *ozayn_key_name(OzaynKey key) {
    if (key <= OZAYN_KEY_UNKNOWN || key >= OZAYN_KEY_COUNT) return "Unknown";
    const char *name = _ozayn_key_name_table[key];
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
