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
 * E. Network
 * ================================================================ */

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
