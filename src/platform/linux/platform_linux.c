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
 * F. Camera (stub)
 * ================================================================ */

ozayn_result_t ozayn_camera_info(ozayn_camera_info_t *info) {
    if (!info) return OZAYN_ERR_NULL;
    memset(info, 0, sizeof(ozayn_camera_info_t));
    /* TODO: Section 05 — enumerate /dev/video* devices */
    info->available = 0;
    return OZAYN_OK;
}

/* ================================================================
 * G. Audio (stub)
 * ================================================================ */

ozayn_result_t ozayn_audio_info(ozayn_audio_info_t *info) {
    if (!info) return OZAYN_ERR_NULL;
    memset(info, 0, sizeof(ozayn_audio_info_t));
    /* TODO: Section 06 — enumerate ALSA/PulseAudio devices */
    info->available = 0;
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
