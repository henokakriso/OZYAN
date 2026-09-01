#ifndef OZAYN_PLATFORM_H
#define OZAYN_PLATFORM_H

#include "platform_detect.h"
#include "ozayn.h"
#include <stdint.h>
#include <time.h>

/*
 * platform.h — Cross-platform system abstraction layer.
 *
 * Provides a common API for OS-level operations.
 * Each platform (Linux, Windows, macOS) implements these functions
 * behind a unified interface. The Core communicates with the
 * abstraction layer rather than directly with OS-specific APIs.
 *
 * Sections:
 *   0. Platform Detection & Initialization
 *   A. System Information
 *   B. Process Operations
 *   C. File System / Storage
 *   D. Display / Monitor
 *   E. Network
 *   F. Camera (stubs for Section 05)
 *   G. Audio (stubs for Section 06)
 *   H. Input (stubs for Section 07)
 */

/* ================================================================
 * 0. Platform Detection & Initialization
 * ================================================================ */

typedef enum {
    OZAYN_PLATFORM_UNKNOWN = 0,
    OZAYN_PLATFORM_LINUX,
    OZAYN_PLATFORM_WINDOWS,
    OZAYN_PLATFORM_MACOS
} OzaynPlatform;

/* Initialize platform detection. Returns OZAYN_OK on supported OS, OZAYN_ERR on unknown. */
ozayn_result_t ozayn_platform_detect_init(void);

/* Shutdown platform layer. Returns to UNKNOWN state. */
void ozayn_platform_detect_shutdown(void);

/* Get detected platform. Returns OZAYN_PLATFORM_UNKNOWN if not initialized. */
OzaynPlatform ozayn_platform_get(void);

/* Get platform name string. Never returns NULL. */
const char *ozayn_platform_name(void);

/* ================================================================
 * A. System Information
 * ================================================================ */

#define OZAYN_MAX_SYSTEM_STR 256

typedef struct {
    char os_name[OZAYN_MAX_SYSTEM_STR];
    char os_version[OZAYN_MAX_SYSTEM_STR];
    char arch[64];
    char hostname[OZAYN_MAX_SYSTEM_STR];
    uint64_t total_memory_mb;
    uint32_t cpu_cores;
    uint64_t uptime_seconds;
} ozayn_system_info_t;

/* Query system information. Returns OZAYN_OK on success. */
ozayn_result_t ozayn_system_info(ozayn_system_info_t *info);

/* Get current timestamp as epoch seconds */
uint64_t ozayn_system_time(void);

/* Sleep for given milliseconds */
void ozayn_system_sleep_ms(uint32_t ms);

/* ================================================================
 * B. Process Operations
 * ================================================================ */

#define OZAYN_MAX_PROCESS_NAME 128
#define OZAYN_MAX_PATH         512

typedef struct {
    uint32_t pid;
    char     name[OZAYN_MAX_PROCESS_NAME];
    char     executable[OZAYN_MAX_PATH];
    int      running;
    uint32_t exit_code;
} ozayn_process_info_t;

/* Get current process PID */
uint32_t ozayn_process_self(void);

/* Get process name by PID. Returns OZAYN_OK or OZAYN_ERR. */
ozayn_result_t ozayn_process_info(uint32_t pid, ozayn_process_info_t *info);

/* Send signal to process. 0 = success. */
ozayn_result_t ozayn_process_signal(uint32_t pid, int signal);

/* ================================================================
 * C. File System / Storage
 * ================================================================ */

/* Check if path exists. Returns 1 if exists, 0 otherwise. */
int ozayn_fs_exists(const char *path);

/* Check if path is a directory. Returns 1 if directory, 0 otherwise. */
int ozayn_fs_is_dir(const char *path);

/* Create directory (recursive). Returns 0 on success. */
ozayn_result_t ozayn_fs_mkdir(const char *path);

/* Remove file. Returns 0 on success. */
ozayn_result_t ozayn_fs_remove(const char *path);

/* Get file size in bytes. Returns -1 on error. */
int64_t ozayn_fs_size(const char *path);

/* Read file contents into buffer. Returns bytes read or -1. */
int64_t ozayn_fs_read(const char *path, void *buf, uint64_t buf_size);

/* Write buffer to file. Returns bytes written or -1. */
int64_t ozayn_fs_write(const char *path, const void *data, uint64_t size);

/* Get home directory. Returns pointer to internal buffer. */
const char *ozayn_fs_home(void);

/* Get config directory (~/.config/ozayn or platform equivalent). Returns pointer to internal buffer. */
const char *ozayn_fs_config_dir(void);

/* ================================================================
 * D. Display / Monitor
 * ================================================================ */

#define OZAYN_MAX_DISPLAY_NAME 128

typedef struct {
    uint32_t x;
    uint32_t y;
    uint32_t width;
    uint32_t height;
    uint32_t refresh_hz;
    char     name[OZAYN_MAX_DISPLAY_NAME];
} ozayn_display_mode_t;

typedef struct {
    uint32_t count;
    ozayn_display_mode_t modes[8]; /* max 8 displays */
} ozayn_display_info_t;

/* Query display information. Returns OZAYN_OK on success. */
ozayn_result_t ozayn_display_info(ozayn_display_info_t *info);

/* ================================================================
 * E. Network
 * ================================================================ */

#define OZAYN_MAX_IFACE_NAME 64
#define OZAYN_MAX_IP_STR     46

typedef struct {
    char name[OZAYN_MAX_IFACE_NAME];
    char ip[OZAYN_MAX_IP_STR];
    int  is_up;
    int  is_loopback;
} ozayn_network_iface_t;

typedef struct {
    uint32_t count;
    ozayn_network_iface_t ifaces[16]; /* max 16 interfaces */
} ozayn_network_info_t;

/* Query network interfaces. Returns OZAYN_OK on success. */
ozayn_result_t ozayn_network_info(ozayn_network_info_t *info);

/* Check if host is reachable. Returns 1 if reachable, 0 otherwise. */
int ozayn_network_ping(const char *host);

/* ================================================================
 * F. Camera (stubs — implemented in Section 05)
 * ================================================================ */

typedef struct {
    int      available;
    uint32_t width;
    uint32_t height;
    uint32_t fps;
} ozayn_camera_info_t;

/* Query camera info. Stub returns available=0. */
ozayn_result_t ozayn_camera_info(ozayn_camera_info_t *info);

/* ================================================================
 * G. Audio (stubs — implemented in Section 06)
 * ================================================================ */

typedef struct {
    int      available;
    uint32_t sample_rate;
    uint32_t channels;
} ozayn_audio_info_t;

/* Query audio info. Stub returns available=0. */
ozayn_result_t ozayn_audio_info(ozayn_audio_info_t *info);

/* ================================================================
 * H. Input (stubs — implemented in Section 07)
 * ================================================================ */

typedef struct {
    int has_keyboard;
    int has_mouse;
    int has_touch;
    int has_microphone;
    int has_camera;
} ozayn_input_info_t;

/* Query input device availability. */
ozayn_result_t ozayn_input_info(ozayn_input_info_t *info);

/* ================================================================
 * Platform Lifecycle
 * ================================================================ */

/* Initialize platform layer. Call once at startup. */
ozayn_result_t ozayn_platform_init(void);

/* Shutdown platform layer. Call once at shutdown. */
void ozayn_platform_shutdown(void);

#endif
