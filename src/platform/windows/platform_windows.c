#include "platform.h"

#ifdef OZAYN_OS_WINDOWS

/*
 * platform_windows.c — Windows platform implementation.
 *
 * Implements the common platform API using Win32 API.
 * Only compiles on Windows targets.
 */

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <stdio.h>
#include <string.h>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

/* ================================================================
 * A. System Information
 * ================================================================ */

ozayn_result_t ozayn_system_info(ozayn_system_info_t *info) {
    if (!info) return OZAYN_ERR_NULL;
    memset(info, 0, sizeof(ozayn_system_info_t));

    strncpy(info->os_name, "Windows", OZAYN_MAX_SYSTEM_STR - 1);

    /* OS version */
    OSVERSIONINFOA osvi;
    ZeroMemory(&osvi, sizeof(osvi));
    osvi.dwOSVersionInfoSize = sizeof(osvi);
    /* Note: GetVersionEx is deprecated but still functional */
    if (GetVersionExA(&osvi)) {
        snprintf(info->os_version, OZAYN_MAX_SYSTEM_STR, "%d.%d.%d",
                 osvi.dwMajorVersion, osvi.dwMinorVersion, osvi.dwBuildNumber);
    }

    /* Architecture */
#ifdef _M_X64
    strncpy(info->arch, "x86_64", sizeof(info->arch) - 1);
#elif defined(_M_IX86)
    strncpy(info->arch, "x86", sizeof(info->arch) - 1);
#elif defined(_M_ARM64)
    strncpy(info->arch, "aarch64", sizeof(info->arch) - 1);
#else
    strncpy(info->arch, "unknown", sizeof(info->arch) - 1);
#endif

    /* Hostname */
    DWORD name_len = OZAYN_MAX_SYSTEM_STR;
    GetComputerNameA(info->hostname, &name_len);

    /* Memory */
    MEMORYSTATUSEX stat;
    stat.dwLength = sizeof(stat);
    if (GlobalMemoryStatusEx(&stat)) {
        info->total_memory_mb = stat.ullTotalPhys / (1024 * 1024);
    }

    /* CPU cores */
    SYSTEM_INFO sysinfo;
    GetSystemInfo(&sysinfo);
    info->cpu_cores = sysinfo.dwNumberOfProcessors;

    /* Uptime */
    ULONGLONG ticks = GetTickCount64();
    info->uptime_seconds = ticks / 1000;

    return OZAYN_OK;
}

uint64_t ozayn_system_time(void) {
    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);
    ULARGE_INTEGER li;
    li.LowPart = ft.dwLowDateTime;
    li.HighPart = ft.dwHighDateTime;
    /* Convert from 100-nanosecond intervals to seconds */
    return (li.QuadPart / 10000000ULL) - 11644473600ULL; /* epoch offset */
}

void ozayn_system_sleep_ms(uint32_t ms) {
    Sleep(ms);
}

/* ================================================================
 * B. Process Operations
 * ================================================================ */

uint32_t ozayn_process_self(void) {
    return (uint32_t)GetCurrentProcessId();
}

ozayn_result_t ozayn_process_info(uint32_t pid, ozayn_process_info_t *info) {
    if (!info) return OZAYN_ERR_NULL;

    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProcess) {
        info->pid = pid;
        info->running = 0;
        return OZAYN_ERR;
    }

    info->pid = pid;
    info->running = 1;

    /* Get process name from executable path */
    char exe_path[OZAYN_MAX_PATH];
    DWORD path_len = OZAYN_MAX_PATH;
    if (QueryFullProcessImageNameA(hProcess, 0, exe_path, &path_len)) {
        strncpy(info->executable, exe_path, OZAYN_MAX_PATH - 1);
        const char *base = strrchr(exe_path, '\\');
        strncpy(info->name, base ? base + 1 : exe_path, OZAYN_MAX_PROCESS_NAME - 1);
    } else {
        strncpy(info->name, "unknown", OZAYN_MAX_PROCESS_NAME - 1);
    }

    CloseHandle(hProcess);
    return OZAYN_OK;
}

ozayn_result_t ozayn_process_signal(uint32_t pid, int signal) {
    HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
    if (!hProcess) return OZAYN_ERR;

    ozayn_result_t result = OZAYN_OK;
    if (signal == 9 || signal == 15) {
        /* SIGKILL / SIGTERM → TerminateProcess */
        if (!TerminateProcess(hProcess, 1)) result = OZAYN_ERR;
    } else {
        /* GenerateConsoleCtrlEvent for other signals */
        if (!GenerateConsoleCtrlEvent(signal, pid)) result = OZAYN_ERR;
    }

    CloseHandle(hProcess);
    return result;
}

/* ================================================================
 * B2. Cross-Platform Process Management
 * ================================================================ */

ozayn_result_t ozayn_process_start(const char *program, const char *const argv[], OzaynProcess *proc) {
    if (!program || !proc) return OZAYN_ERR_NULL;
    if (strlen(program) == 0) return OZAYN_ERR;

    memset(proc, 0, sizeof(OzaynProcess));
    proc->running = 0;

    /* Build command line */
    char cmd_line[2048];
    snprintf(cmd_line, sizeof(cmd_line), "\"%s\"", program);
    if (argv) {
        for (int i = 0; argv[i] && i < OZAYN_PROCESS_MAX_ARGS; i++) {
            size_t len = strlen(cmd_line);
            snprintf(cmd_line + len, sizeof(cmd_line) - len, " \"%s\"", argv[i]);
        }
    }

    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));

    if (!CreateProcessA(NULL, cmd_line, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        return OZAYN_ERR;
    }

    proc->pid = (uint32_t)pi.dwProcessId;
    proc->running = 1;
    /* Store handles in _internal: [0]=process, [1]=thread */
    HANDLE *handles = (HANDLE *)proc->_internal;
    handles[0] = pi.hProcess;
    handles[1] = pi.hThread;

    return OZAYN_OK;
}

int ozayn_process_is_running(OzaynProcess *proc) {
    if (!proc || proc->pid == 0) return 0;
    if (!proc->running) return 0;

    HANDLE *handles = (HANDLE *)proc->_internal;
    if (!handles[0]) return 0;

    DWORD exit_code;
    if (GetExitCodeProcess(handles[0], &exit_code)) {
        if (exit_code == STILL_ACTIVE) {
            return 1;
        }
    }
    proc->running = 0;
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

    if (proc->running) {
        HANDLE *handles = (HANDLE *)proc->_internal;
        DWORD exit_code;
        if (handles[0] && GetExitCodeProcess(handles[0], &exit_code)) {
            if (exit_code == STILL_ACTIVE) {
                info->state = OZAYN_PROC_STATE_RUNNING;
            } else {
                info->state = OZAYN_PROC_STATE_EXITED;
                info->exit_code = (int)exit_code;
            }
        } else {
            info->state = OZAYN_PROC_STATE_UNKNOWN;
        }
    } else {
        info->state = OZAYN_PROC_STATE_EXITED;
    }

    strncpy(info->name, "process", OZAYN_MAX_PROCESS_NAME - 1);
    return OZAYN_OK;
}

ozayn_result_t ozayn_process_terminate(OzaynProcess *proc) {
    if (!proc) return OZAYN_ERR_NULL;
    if (proc->pid == 0 || !proc->running) return OZAYN_ERR;

    HANDLE *handles = (HANDLE *)proc->_internal;
    if (!handles[0]) return OZAYN_ERR;

    if (TerminateProcess(handles[0], 1)) {
        return OZAYN_OK;
    }
    return OZAYN_ERR;
}

ozayn_result_t ozayn_process_wait(OzaynProcess *proc, uint32_t timeout_ms) {
    if (!proc) return OZAYN_ERR_NULL;
    if (proc->pid == 0) return OZAYN_ERR;
    if (!proc->running) return OZAYN_OK;

    HANDLE *handles = (HANDLE *)proc->_internal;
    if (!handles[0]) return OZAYN_ERR;

    DWORD t = (timeout_ms == 0) ? INFINITE : (DWORD)timeout_ms;
    DWORD result = WaitForSingleObject(handles[0], t);
    if (result == WAIT_OBJECT_0 || result == WAIT_TIMEOUT) {
        proc->running = 0;
        return OZAYN_OK;
    }
    return OZAYN_ERR;
}

void ozayn_process_close(OzaynProcess *proc) {
    if (!proc) return;
    HANDLE *handles = (HANDLE *)proc->_internal;
    if (handles[0]) {
        if (proc->running) {
            ozayn_process_terminate(proc);
        }
        CloseHandle(handles[0]);
        handles[0] = NULL;
    }
    if (handles[1]) {
        CloseHandle(handles[1]);
        handles[1] = NULL;
    }
    memset(proc, 0, sizeof(OzaynProcess));
}

/* ================================================================
 * C. File System / Storage
 * ================================================================ */

int ozayn_fs_exists(const char *path) {
    if (!path) return 0;
    DWORD attr = GetFileAttributesA(path);
    return attr != INVALID_FILE_ATTRIBUTES;
}

int ozayn_fs_is_file(const char *path) {
    if (!path) return 0;
    DWORD attr = GetFileAttributesA(path);
    if (attr == INVALID_FILE_ATTRIBUTES) return 0;
    return (attr & FILE_ATTRIBUTE_DIRECTORY) == 0;
}

int ozayn_fs_is_dir(const char *path) {
    if (!path) return 0;
    DWORD attr = GetFileAttributesA(path);
    if (attr == INVALID_FILE_ATTRIBUTES) return 0;
    return (attr & FILE_ATTRIBUTE_DIRECTORY) != 0;
}

ozayn_result_t ozayn_fs_mkdir(const char *path) {
    if (!path) return OZAYN_ERR_NULL;
    if (CreateDirectoryA(path, NULL)) return OZAYN_OK;
    if (GetLastError() == ERROR_ALREADY_EXISTS) return OZAYN_OK;
    return OZAYN_ERR;
}

ozayn_result_t ozayn_fs_rmdir(const char *path) {
    if (!path) return OZAYN_ERR_NULL;
    if (RemoveDirectoryA(path)) return OZAYN_OK;
    return OZAYN_ERR;
}

ozayn_result_t ozayn_fs_remove(const char *path) {
    if (!path) return OZAYN_ERR_NULL;
    if (DeleteFileA(path)) return OZAYN_OK;
    return OZAYN_ERR;
}

int64_t ozayn_fs_size(const char *path) {
    if (!path) return -1;
    HANDLE h = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return -1;
    LARGE_INTEGER size;
    int64_t result = GetFileSizeEx(h, &size) ? size.QuadPart : -1;
    CloseHandle(h);
    return result;
}

int64_t ozayn_fs_read(const char *path, void *buf, uint64_t buf_size) {
    if (!path || !buf) return -1;
    HANDLE h = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return -1;
    DWORD bytes_read = 0;
    BOOL ok = ReadFile(h, buf, (DWORD)buf_size, &bytes_read, NULL);
    CloseHandle(h);
    return ok ? (int64_t)bytes_read : -1;
}

int64_t ozayn_fs_write(const char *path, const void *data, uint64_t size) {
    if (!path || !data) return -1;
    HANDLE h = CreateFileA(path, GENERIC_WRITE, 0, NULL,
                           CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return -1;
    DWORD written = 0;
    BOOL ok = WriteFile(h, data, (DWORD)size, &written, NULL);
    CloseHandle(h);
    return ok ? (int64_t)written : -1;
}

int64_t ozayn_fs_append(const char *path, const void *data, uint64_t size) {
    if (!path || !data) return -1;
    HANDLE h = CreateFileA(path, GENERIC_WRITE, 0, NULL,
                           OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return -1;
    DWORD written = 0;
    SetFilePointer(h, 0, NULL, FILE_END);
    BOOL ok = WriteFile(h, data, (DWORD)size, &written, NULL);
    CloseHandle(h);
    return ok ? (int64_t)written : -1;
}

ozayn_result_t ozayn_fs_copy(const char *source, const char *dest) {
    if (!source || !dest) return OZAYN_ERR_NULL;
    if (!ozayn_fs_is_file(source)) return OZAYN_ERR;
    if (CopyFileA(source, dest, FALSE)) return OZAYN_OK;
    return OZAYN_ERR;
}

ozayn_result_t ozayn_fs_move(const char *source, const char *dest) {
    if (!source || !dest) return OZAYN_ERR_NULL;
    if (MoveFileA(source, dest)) return OZAYN_OK;
    return OZAYN_ERR;
}

static char home_buf[OZAYN_MAX_PATH];
static char config_buf[OZAYN_MAX_PATH];

const char *ozayn_fs_home(void) {
    const char *home = getenv("USERPROFILE");
    if (!home) home = getenv("HOMEDRIVE");
    if (home) {
        strncpy(home_buf, home, OZAYN_MAX_PATH - 1);
    } else {
        strncpy(home_buf, "C:\\", OZAYN_MAX_PATH - 1);
    }
    return home_buf;
}

const char *ozayn_fs_config_dir(void) {
    const char *appdata = getenv("APPDATA");
    if (appdata) {
        snprintf(config_buf, OZAYN_MAX_PATH, "%s\\OZAYN", appdata);
    } else {
        snprintf(config_buf, OZAYN_MAX_PATH, "C:\\OZAYN");
    }
    return config_buf;
}

/* ================================================================
 * D. Display / Monitor
 * ================================================================ */

ozayn_result_t ozayn_display_info(ozayn_display_info_t *info) {
    if (!info) return OZAYN_ERR_NULL;
    memset(info, 0, sizeof(ozayn_display_info_t));

    /* EnumDisplayDevices + EnumDisplaySettings */
    DISPLAY_DEVICEA dd;
    dd.cb = sizeof(dd);
    DEVMODEA dm;

    for (DWORD i = 0; EnumDisplayDevicesA(NULL, i, &dd, 0) && info->count < 8; i++) {
        if (!(dd.StateFlags & DISPLAY_DEVICE_ACTIVE)) continue;

        ozayn_display_mode_t *mode = &info->modes[info->count];
        strncpy(mode->name, dd.DeviceName, OZAYN_MAX_DISPLAY_NAME - 1);

        ZeroMemory(&dm, sizeof(dm));
        dm.dmSize = sizeof(dm);
        if (EnumDisplaySettingsA(dd.DeviceName, ENUM_CURRENT_SETTINGS, &dm)) {
            mode->width = dm.dmPelsWidth;
            mode->height = dm.dmPelsHeight;
            mode->refresh_hz = dm.dmDisplayFrequency;
        }

        info->count++;
    }

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

static int _ozayn_display_discover(void) {
    DISPLAY_DEVICEA dd;
    dd.cb = sizeof(dd);
    DEVMODEA dm;
    uint32_t count = 0;
    int primary_done = 0;

    for (DWORD i = 0; EnumDisplayDevicesA(NULL, i, &dd, 0) && count < OZAYN_MAX_DISPLAYS; i++) {
        if (!(dd.StateFlags & DISPLAY_DEVICE_ACTIVE)) continue;

        /* Check if primary */
        int is_primary = (dd.StateFlags & DISPLAY_DEVICE_PRIMARY_DEVICE) ? 1 : 0;
        if (is_primary) primary_done = 1;

        OzaynDisplayInfo *d = &_ozayn_display.displays[count];
        memset(d, 0, sizeof(OzaynDisplayInfo));
        d->index = count;
        d->is_primary = is_primary;

        /* Extract device name */
        strncpy(d->name, dd.DeviceName, OZAYN_MAX_DISPLAY_NAME - 1);

        /* Get display settings */
        ZeroMemory(&dm, sizeof(dm));
        dm.dmSize = sizeof(dm);
        if (EnumDisplaySettingsA(dd.DeviceName, ENUM_CURRENT_SETTINGS, &dm)) {
            d->width = dm.dmPelsWidth;
            d->height = dm.dmPelsHeight;
            d->refresh_hz = dm.dmDisplayFrequency;
            d->x = (int32_t)dm.dmPosition.x;
            d->y = (int32_t)dm.dmPosition.y;
        } else {
            d->width = 1920;
            d->height = 1080;
            d->refresh_hz = 60;
        }

        count++;
    }

    /* Fallback if no displays found */
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
        primary_done = 1;
        _ozayn_display.primary_index = 0;
    }

    /* If no primary found, mark first as primary */
    if (!primary_done && count > 0) {
        _ozayn_display.displays[0].is_primary = 1;
        _ozayn_display.primary_index = 0;
    }

    _ozayn_display.count = count;
    _ozayn_display.available = (count > 0) ? 1 : 0;

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

    ULONG buf_len = 15000;
    PIP_ADAPTER_ADDRESSES adapters = (PIP_ADAPTER_ADDRESSES)malloc(buf_len);
    if (!adapters) return OZAYN_ERR;

    DWORD result = GetAdaptersAddresses(AF_UNSPEC, 0, NULL, adapters, &buf_len);
    if (result == NO_ERROR) {
        PIP_ADAPTER_ADDRESSES adapter;
        for (adapter = adapters; adapter && info->count < 16; adapter = adapter->Next) {
            if (adapter->OperStatus != IfOperStatusUp) continue;

            ozayn_network_iface_t *iface = &info->ifaces[info->count];
            /* Convert wide string to narrow */
            WideCharToMultiByte(CP_UTF8, 0, adapter->FriendlyName, -1,
                                iface->name, OZAYN_MAX_IFACE_NAME, NULL, NULL);
            iface->is_up = 1;
            iface->is_loopback = (adapter->IfType == IF_TYPE_LOOPBACK) ? 1 : 0;

            /* Get first IPv4 address */
            PIP_ADAPTER_UNICAST_ADDRESS unicast;
            for (unicast = adapter->FirstUnicastAddress; unicast; unicast = unicast->Next) {
                if (unicast->Address.lpSockaddr->sa_family == AF_INET) {
                    struct sockaddr_in *sa = (struct sockaddr_in *)unicast->Address.lpSockaddr;
                    inet_ntop(AF_INET, &sa->sin_addr, iface->ip, OZAYN_MAX_IP_STR);
                    break;
                }
            }

            info->count++;
        }
    }

    free(adapters);
    return OZAYN_OK;
}

int ozayn_network_ping(const char *host) {
    if (!host) return 0;
    /* Windows: use ping command */
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "ping -n 1 -w 2000 %s >nul 2>&1", host);
    return system(cmd) == 0;
}

/* ================================================================
 * E. Window Management (stub — needs Win32 enum)
 * ================================================================ */

static OzaynWindowState _ozayn_window = {0};

ozayn_result_t ozayn_window_init(void) {
    if (_ozayn_window.initialized) return OZAYN_OK;
    memset(&_ozayn_window, 0, sizeof(OzaynWindowState));
    _ozayn_window.initialized = 1;
    _ozayn_window.available = 0;
    return OZAYN_OK;
}

void ozayn_window_shutdown(void) {
    if (!_ozayn_window.initialized) return;
    memset(&_ozayn_window, 0, sizeof(OzaynWindowState));
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
 * Windows stub — requires Media Foundation for full implementation.
 */

static OzaynCameraState _ozayn_camera = {0};

ozayn_result_t ozayn_camera_init(void) {
    if (_ozayn_camera.initialized) return OZAYN_OK;
    memset(&_ozayn_camera, 0, sizeof(OzaynCameraState));
    /* TODO: IMFActivate device enumeration */
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
 * Uses Win32 APIs for mouse position and button control.
 * Coordinate convention: (0,0) = top-left of primary display.
 * X increases rightward, Y increases downward.
 */

static OzaynInputState _ozayn_input = {0};

ozayn_result_t ozayn_input_init(void) {
    if (_ozayn_input.initialized) return OZAYN_OK;

    memset(&_ozayn_input, 0, sizeof(OzaynInputState));

    /* Mouse is always available on Windows */
    _ozayn_input.available = 1;
    _ozayn_input.device_info.has_mouse = 1;
    _ozayn_input.device_info.has_keyboard = 1;

    _ozayn_input.initialized = 1;

    LOG_INFO("INPUT", "Input subsystem initialized (available=%s)",
             _ozayn_input.available ? "yes" : "no");

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

    POINT pt;
    if (GetCursorPos(&pt)) {
        *x = (int32_t)pt.x;
        *y = (int32_t)pt.y;
        return OZAYN_OK;
    }

    return OZAYN_ERR;
}

ozayn_result_t ozayn_input_get_mouse_state(OzaynMouseState *state) {
    if (!state) return OZAYN_ERR_NULL;
    if (!_ozayn_input.initialized) return OZAYN_ERR;

    memset(state, 0, sizeof(OzaynMouseState));

    POINT pt;
    if (GetCursorPos(&pt)) {
        state->x = (int32_t)pt.x;
        state->y = (int32_t)pt.y;
        state->left_button = (GetAsyncKeyState(VK_LBUTTON) & 0x8000) ? 1 : 0;
        state->middle_button = (GetAsyncKeyState(VK_MBUTTON) & 0x8000) ? 1 : 0;
        state->right_button = (GetAsyncKeyState(VK_RBUTTON) & 0x8000) ? 1 : 0;
        state->available = 1;
        return OZAYN_OK;
    }

    return OZAYN_ERR;
}

ozayn_result_t ozayn_input_move_mouse(int32_t x, int32_t y) {
    if (!_ozayn_input.initialized) return OZAYN_ERR;

    if (SetCursorPos((int)x, (int)y)) {
        return OZAYN_OK;
    }

    return OZAYN_ERR;
}

static ozayn_result_t _ozayn_input_button_event(DWORD vk, int press) {
    if (!_ozayn_input.initialized) return OZAYN_ERR;

    INPUT input = {0};
    input.type = INPUT_MOUSE;
    input.mi.dwFlags = press ? MOUSEEVENTF_LEFTDOWN : MOUSEEVENTF_LEFTUP;

    if (vk == VK_RBUTTON) {
        input.mi.dwFlags = press ? MOUSEEVENTF_RIGHTDOWN : MOUSEEVENTF_RIGHTUP;
    } else if (vk == VK_MBUTTON) {
        input.mi.dwFlags = press ? MOUSEEVENTF_MIDDLEDOWN : MOUSEEVENTF_MIDDLEUP;
    }

    if (SendInput(1, &input, sizeof(INPUT))) {
        return OZAYN_OK;
    }

    return OZAYN_ERR;
}

ozayn_result_t ozayn_input_mouse_left_down(void) {
    return _ozayn_input_button_event(VK_LBUTTON, 1);
}

ozayn_result_t ozayn_input_mouse_left_up(void) {
    return _ozayn_input_button_event(VK_LBUTTON, 0);
}

ozayn_result_t ozayn_input_mouse_right_down(void) {
    return _ozayn_input_button_event(VK_RBUTTON, 1);
}

ozayn_result_t ozayn_input_mouse_right_up(void) {
    return _ozayn_input_button_event(VK_RBUTTON, 0);
}

ozayn_result_t ozayn_input_mouse_middle_down(void) {
    return _ozayn_input_button_event(VK_MBUTTON, 1);
}

ozayn_result_t ozayn_input_mouse_middle_up(void) {
    return _ozayn_input_button_event(VK_MBUTTON, 0);
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
 * Windows stub — uses GetAsyncKeyState for key state queries.
 * Event polling is not yet implemented.
 */

static OzaynKeyboardState _ozayn_keyboard = {0};

static const char *_ozayn_key_name_table_win[OZAYN_KEY_COUNT] = {
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
    _ozayn_keyboard.available = 1;
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
    /* TODO: GetAsyncKeyState mapping */
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
    const char *name = _ozayn_key_name_table_win[key];
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
    /* Initialize Winsock */
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
    ozayn_result_t r = ozayn_platform_detect_init();
    if (r == OZAYN_OK) {
        LOG_INFO("PLATFORM", "Platform layer initialized (%s/%s)", OZAYN_OS_NAME, OZAYN_ARCH_NAME);
    }
    return r;
}

void ozayn_platform_shutdown(void) {
    LOG_INFO("PLATFORM", "Platform layer shut down");
    ozayn_platform_detect_shutdown();
    WSACleanup();
}

#endif /* OZAYN_OS_WINDOWS */
