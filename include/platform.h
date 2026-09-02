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
 *   E. Window Management (Step 06)
 *   F. Network
 *   G. Camera (stubs for Section 05)
 *   H. Audio (stubs for Section 06)
 *   I. Input (stubs for Section 07)
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

/* ---- Cross-platform process management ---- */

#define OZAYN_PROCESS_MAX_ARGS 32

typedef enum {
    OZAYN_PROC_STATE_UNKNOWN = 0,
    OZAYN_PROC_STATE_RUNNING,
    OZAYN_PROC_STATE_STOPPED,
    OZAYN_PROC_STATE_EXITED,
    OZAYN_PROC_STATE_FAILED
} OzaynProcessState;

typedef struct {
    uint32_t           pid;        /* OS process ID */
    OzaynProcessState  state;      /* current state */
    int                exit_code;  /* exit code (valid when state=EXITED) */
    char               name[OZAYN_MAX_PROCESS_NAME];
} OzaynProcessInfo;

typedef struct {
    uint32_t pid;                  /* OS process ID, 0 if not started */
    int      running;              /* 1 if currently running */
    int      _internal[16];        /* platform-specific handle storage */
} OzaynProcess;

/* Start a new process. Returns OZAYN_OK on success. */
ozayn_result_t ozayn_process_start(const char *program, const char *const argv[], OzaynProcess *proc);

/* Check if process is running. Returns 1 if running, 0 otherwise. */
int ozayn_process_is_running(OzaynProcess *proc);

/* Get process information. Returns OZAYN_OK on success. */
ozayn_result_t ozayn_proc_get_info(OzaynProcess *proc, OzaynProcessInfo *info);

/* Terminate process. Returns OZAYN_OK on success. */
ozayn_result_t ozayn_process_terminate(OzaynProcess *proc);

/* Wait for process to exit. Blocks until exit or timeout_ms (0=infinite). Returns OZAYN_OK. */
ozayn_result_t ozayn_process_wait(OzaynProcess *proc, uint32_t timeout_ms);

/* Release process resources. Safe to call multiple times. */
void ozayn_process_close(OzaynProcess *proc);

/* ================================================================
 * C. File System / Storage
 * ================================================================ */

/* Check if path exists (file or directory). Returns 1 if exists, 0 otherwise. */
int ozayn_fs_exists(const char *path);

/* Check if path is a regular file. Returns 1 if file, 0 otherwise. */
int ozayn_fs_is_file(const char *path);

/* Check if path is a directory. Returns 1 if directory, 0 otherwise. */
int ozayn_fs_is_dir(const char *path);

/* Create directory (recursive). Returns OZAYN_OK on success. */
ozayn_result_t ozayn_fs_mkdir(const char *path);

/* Remove empty directory. Returns OZAYN_OK on success. */
ozayn_result_t ozayn_fs_rmdir(const char *path);

/* Remove file. Returns OZAYN_OK on success. */
ozayn_result_t ozayn_fs_remove(const char *path);

/* Get file size in bytes. Returns -1 on error. */
int64_t ozayn_fs_size(const char *path);

/* Read file contents into buffer. Returns bytes read or -1. */
int64_t ozayn_fs_read(const char *path, void *buf, uint64_t buf_size);

/* Write buffer to file (creates or overwrites). Returns bytes written or -1. */
int64_t ozayn_fs_write(const char *path, const void *data, uint64_t size);

/* Append data to file (creates if not exists). Returns bytes appended or -1. */
int64_t ozayn_fs_append(const char *path, const void *data, uint64_t size);

/* Copy file from source to destination. Returns OZAYN_OK on success. */
ozayn_result_t ozayn_fs_copy(const char *source, const char *dest);

/* Move/rename file. Returns OZAYN_OK on success. */
ozayn_result_t ozayn_fs_move(const char *source, const char *dest);

/* Get home directory. Returns pointer to internal buffer. */
const char *ozayn_fs_home(void);

/* Get config directory (~/.config/ozayn or platform equivalent). Returns pointer to internal buffer. */
const char *ozayn_fs_config_dir(void);

/* ================================================================
 * D. Display / Monitor
 * ================================================================ */

#define OZAYN_MAX_DISPLAY_NAME 128
#define OZAYN_MAX_DISPLAYS     16

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

/* ---- Cross-platform display management ---- */

typedef struct {
    uint32_t index;
    char     name[OZAYN_MAX_DISPLAY_NAME];
    int32_t  x;
    int32_t  y;
    uint32_t width;
    uint32_t height;
    uint32_t refresh_hz;
    int      is_primary;
} OzaynDisplayInfo;

typedef struct {
    int              initialized;
    int              available;
    uint32_t         count;
    OzaynDisplayInfo displays[OZAYN_MAX_DISPLAYS];
    int              primary_index;
} OzaynDisplayState;

/* Initialize display subsystem. Returns OZAYN_OK on success. */
ozayn_result_t ozayn_display_init(void);

/* Shutdown display subsystem. Safe to call multiple times. */
void ozayn_display_shutdown(void);

/* Check if display subsystem is available. Returns 1 if available, 0 otherwise. */
int ozayn_display_is_available(void);

/* Get number of connected displays. Returns count or 0 if unavailable. */
uint32_t ozayn_display_count(void);

/* Get display info by index. Returns OZAYN_OK on success. */
ozayn_result_t ozayn_display_get(uint32_t index, OzaynDisplayInfo *info);

/* Get primary display info. Returns OZAYN_OK on success. */
ozayn_result_t ozayn_display_get_primary(OzaynDisplayInfo *info);

/* Refresh display list. Returns OZAYN_OK on success. */
ozayn_result_t ozayn_display_refresh(void);

/* ================================================================
 * E. Window Management
 * ================================================================ */

#define OZAYN_MAX_WINDOW_TITLE 256
#define OZAYN_MAX_WINDOWS      256

typedef struct {
    unsigned long long id;
    char     title[OZAYN_MAX_WINDOW_TITLE];
    int32_t  x;
    int32_t  y;
    uint32_t width;
    uint32_t height;
    int      visible;
    int      minimized;
    int      maximized;
    int      active;
} OzaynWindowInfo;

typedef struct {
    int              initialized;
    int              available;
    uint32_t         count;
    OzaynWindowInfo  windows[OZAYN_MAX_WINDOWS];
} OzaynWindowState;

/* Initialize window subsystem. Returns OZAYN_OK on success. */
ozayn_result_t ozayn_window_init(void);

/* Shutdown window subsystem. Safe to call multiple times. */
void ozayn_window_shutdown(void);

/* Check if window subsystem is available. Returns 1 if available, 0 otherwise. */
int ozayn_window_is_available(void);

/* Get number of discovered windows. Returns count or 0 if unavailable. */
uint32_t ozayn_window_get_count(void);

/* Get window info by index. Returns OZAYN_OK on success. */
ozayn_result_t ozayn_window_get_info(uint32_t index, OzaynWindowInfo *info);

/* Get active/foreground window. Returns OZAYN_OK on success. */
ozayn_result_t ozayn_window_get_active(OzaynWindowInfo *info);

/* Move window to position. Returns OZAYN_OK on success. */
ozayn_result_t ozayn_window_move(unsigned long long window_id, int32_t x, int32_t y);

/* Resize window. Returns OZAYN_OK on success. */
ozayn_result_t ozayn_window_resize(unsigned long long window_id, uint32_t width, uint32_t height);

/* Minimize window. Returns OZAYN_OK on success. */
ozayn_result_t ozayn_window_minimize(unsigned long long window_id);

/* Maximize window. Returns OZAYN_OK on success. */
ozayn_result_t ozayn_window_maximize(unsigned long long window_id);

/* Restore minimized/maximized window. Returns OZAYN_OK on success. */
ozayn_result_t ozayn_window_restore(unsigned long long window_id);

/* Close window. Returns OZAYN_OK on success. */
ozayn_result_t ozayn_window_close(unsigned long long window_id);

/* Refresh window list. Returns OZAYN_OK on success. */
ozayn_result_t ozayn_window_refresh(void);

/* ================================================================
 * F. Network
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
 * G. Camera (stubs — implemented in Section 05)
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
 * H. Audio (stubs — implemented in Section 06)
 * ================================================================ */

typedef struct {
    int      available;
    uint32_t sample_rate;
    uint32_t channels;
} ozayn_audio_info_t;

/* Query audio info. Stub returns available=0. */
ozayn_result_t ozayn_audio_info(ozayn_audio_info_t *info);

/* ================================================================
 * I. Input & Mouse Abstraction (Step 07)
 * ================================================================
 *
 * Coordinate convention:
 *   (0,0) = top-left of primary display.
 *   X increases rightward, Y increases downward.
 *   Negative coordinates possible with multi-display setups.
 *   Coordinates match Step 05 Display Abstraction convention.
 */

#define OZAYN_MAX_INPUT_DEVICES 32

/* ---- Input Device Info ---- */

typedef struct {
    int has_keyboard;
    int has_mouse;
    int has_touch;
    int has_microphone;
    int has_camera;
} OzaynInputDeviceInfo;

/* ---- Mouse State ---- */

typedef struct {
    int32_t  x;            /* pointer X position */
    int32_t  y;            /* pointer Y position */
    int      left_button;  /* 1 if pressed, 0 otherwise */
    int      middle_button;
    int      right_button;
    int      available;    /* 1 if mouse input is available */
} OzaynMouseState;

/* ---- Input Subsystem State ---- */

typedef struct {
    int              initialized;
    int              available;
    OzaynInputDeviceInfo device_info;
} OzaynInputState;

/* ---- Input Lifecycle ---- */

/* Initialize input subsystem. Returns OZAYN_OK on success. */
ozayn_result_t ozayn_input_init(void);

/* Shutdown input subsystem. Safe to call multiple times. */
void ozayn_input_shutdown(void);

/* Check if input subsystem is available. Returns 1 if available, 0 otherwise. */
int ozayn_input_is_available(void);

/* ---- Input Device Query ---- */

/* Query input device availability. */
ozayn_result_t ozayn_input_device_info(OzaynInputDeviceInfo *info);

/* ---- Mouse Position ---- */

/* Get current mouse position. Returns OZAYN_OK on success. */
ozayn_result_t ozayn_input_get_mouse_position(int32_t *x, int32_t *y);

/* Get full mouse state including button states. Returns OZAYN_OK on success. */
ozayn_result_t ozayn_input_get_mouse_state(OzaynMouseState *state);

/* Move mouse to specified position. Returns OZAYN_OK on success. */
ozayn_result_t ozayn_input_move_mouse(int32_t x, int32_t y);

/* ---- Mouse Buttons (press/release) ---- */

/* Press left mouse button. Returns OZAYN_OK on success. */
ozayn_result_t ozayn_input_mouse_left_down(void);

/* Release left mouse button. Returns OZAYN_OK on success. */
ozayn_result_t ozayn_input_mouse_left_up(void);

/* Press right mouse button. Returns OZAYN_OK on success. */
ozayn_result_t ozayn_input_mouse_right_down(void);

/* Release right mouse button. Returns OZAYN_OK on success. */
ozayn_result_t ozayn_input_mouse_right_up(void);

/* Press middle mouse button. Returns OZAYN_OK on success. */
ozayn_result_t ozayn_input_mouse_middle_down(void);

/* Release middle mouse button. Returns OZAYN_OK on success. */
ozayn_result_t ozayn_input_mouse_middle_up(void);

/* ---- Legacy API (compatibility) ---- */

typedef OzaynInputDeviceInfo ozayn_input_info_t;

/* Query input device availability (legacy). */
ozayn_result_t ozayn_input_info(ozayn_input_info_t *info);

/* ================================================================
 * Platform Lifecycle
 * ================================================================ */

/* Initialize platform layer. Call once at startup. */
ozayn_result_t ozayn_platform_init(void);

/* Shutdown platform layer. Call once at shutdown. */
void ozayn_platform_shutdown(void);

#endif
