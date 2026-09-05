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
 *   G. Camera Device Abstraction (Step 09)
 *   H. Microphone Device Abstraction (Step 10)
 *   I. Input (Step 07)
 *   J. Keyboard & Input Event Abstraction (Step 08)
 *   K. Audio Output / Speaker Abstraction (Step 11)
 *   L. Network Information & Connectivity Abstraction (Step 12)
 *   M. Power & Battery Information Abstraction (Step 13)
 *   N. Notification System Abstraction (Step 14)
 *   O. Clipboard Abstraction (Step 15)
 *   P. Environment & User Session Abstraction (Step 16)
 *   Q. System Time & Date Abstraction (Step 17)
 *   R. Application Launch & Discovery Abstraction (Step 18)
 *   S. System Permissions & Capability Access Abstraction (Step 19)
 *   T. System Audio Volume & Mute Abstraction (Step 20)
 *   U. System Lock State & Session Control Abstraction (Step 21)
 *   V. System Brightness & Display Power Abstraction (Step 22)
 *   W. System Theme & Appearance Abstraction (Step 23)
 *   X. System Font & Text Rendering Information Abstraction (Step 24)
 *   Y. System Hardware Sensors Abstraction (Step 25)
 *   Z. System Storage & Disk Information Abstraction (Step 26)
 *   AA. USB & Peripheral Device Enumeration Abstraction (Step 27)
 *   AB. Bluetooth & Wireless Peripheral Discovery Abstraction (Step 28)
 *   AC. System Event & Hardware Change Notification Abstraction (Step 29)
 *   AD. System Resource Monitoring Abstraction (Step 30)
 *   AE. Network Configuration & Routing Information Abstraction (Step 31)
 *   AF. System Service & Background Process Information Abstraction (Step 32)
 *   AG. System Security & Firewall State Abstraction (Step 33)
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
 * G. Camera Device Abstraction (Step 09)
 * ================================================================
 *
 * Cross-platform camera enumeration, configuration, and frame capture.
 * This is the hardware/device abstraction layer only — no computer
 * vision, face recognition, or AI processing.
 */

#define OZAYN_MAX_CAMERAS 16
#define OZAYN_MAX_CAMERA_NAME 256
#define OZAYN_MAX_CAMERA_ID 256

/* ---- Pixel Formats ---- */

typedef enum {
    OZAYN_PIXEL_FORMAT_UNKNOWN = 0,
    OZAYN_PIXEL_FORMAT_RGB24,
    OZAYN_PIXEL_FORMAT_BGR24,
    OZAYN_PIXEL_FORMAT_GRAY8,
    OZAYN_PIXEL_FORMAT_YUYV,
    OZAYN_PIXEL_FORMAT_MJPEG
} OzaynPixelFormat;

/* ---- Camera Info ---- */

typedef struct {
    unsigned int index;
    char id[OZAYN_MAX_CAMERA_ID];
    char name[OZAYN_MAX_CAMERA_NAME];
    int available;
    unsigned int width;
    unsigned int height;
    unsigned int fps;
} OzaynCameraInfo;

/* ---- Camera Frame ---- */

typedef struct {
    unsigned int width;
    unsigned int height;
    unsigned int stride;
    OzaynPixelFormat format;
    unsigned char *data;
    size_t data_size;
} OzaynCameraFrame;

/* ---- Camera State ---- */

typedef struct {
    int initialized;
    int available;
    int open;
    int streaming;
    unsigned int count;
} OzaynCameraState;

/* ---- Camera Lifecycle ---- */

/* Initialize camera subsystem. Returns OZAYN_OK on success. */
ozayn_result_t ozayn_camera_init(void);

/* Shutdown camera subsystem. Safe to call multiple times. */
void ozayn_camera_shutdown(void);

/* Check if camera subsystem is available. Returns 1 if available, 0 otherwise. */
int ozayn_camera_is_available(void);

/* ---- Device Enumeration ---- */

/* Get number of cameras. Returns count or 0 if unavailable. */
unsigned int ozayn_camera_get_count(void);

/* Get camera info by index. Returns OZAYN_OK on success. */
ozayn_result_t ozayn_camera_get_info(unsigned int index, OzaynCameraInfo *info);

/* ---- Device Control ---- */

/* Open camera by index. Returns OZAYN_OK on success. */
ozayn_result_t ozayn_camera_open(unsigned int index);

/* Close currently open camera. Returns OZAYN_OK on success. */
ozayn_result_t ozayn_camera_close(void);

/* ---- Capture Control ---- */

/* Start video capture. Returns OZAYN_OK on success. */
ozayn_result_t ozayn_camera_start(void);

/* Stop video capture. Returns OZAYN_OK on success. */
ozayn_result_t ozayn_camera_stop(void);

/* Capture a single frame. Returns OZAYN_OK on success. */
ozayn_result_t ozayn_camera_capture(OzaynCameraFrame *frame);

/* ---- Configuration ---- */

/* Set capture resolution. Returns OZAYN_OK on success. */
ozayn_result_t ozayn_camera_set_resolution(unsigned int width, unsigned int height);

/* Set capture frame rate. Returns OZAYN_OK on success. */
ozayn_result_t ozayn_camera_set_fps(unsigned int fps);

/* ---- Frame Management ---- */

/* Release frame data. Safe to call with NULL or already released frames. */
void ozayn_camera_frame_release(OzaynCameraFrame *frame);

/* ================================================================
 * H. Microphone Device Abstraction (Step 10)
 * ================================================================
 *
 * Cross-platform microphone enumeration, configuration, and PCM audio
 * capture. This is the hardware/device abstraction layer only — no
 * speech recognition, voice commands, or audio processing.
 */

#define OZAYN_MAX_MICROPHONES 16
#define OZAYN_MAX_MIC_NAME 256
#define OZAYN_MAX_MIC_ID 256

/* ---- Audio Sample Format ---- */

typedef enum {
    OZAYN_AUDIO_FORMAT_UNKNOWN = 0,
    OZAYN_AUDIO_FORMAT_S16,      /* signed 16-bit PCM */
    OZAYN_AUDIO_FORMAT_F32       /* 32-bit float */
} OzaynAudioFormat;

/* ---- Microphone Info ---- */

typedef struct {
    int index;
    char id[OZAYN_MAX_MIC_ID];
    char name[OZAYN_MAX_MIC_NAME];
    int available;
    int channels;
    int sample_rate;
} OzaynMicrophoneInfo;

/* ---- Audio Buffer ---- */

typedef struct {
    unsigned int sample_rate;
    unsigned int channels;
    OzaynAudioFormat format;
    size_t frame_count;
    unsigned char *data;
    size_t data_size;
} OzaynAudioBuffer;

/* ---- Microphone State ---- */

typedef struct {
    int initialized;
    int available;
    int open;
    int streaming;
    unsigned int count;
} OzaynMicrophoneState;

/* ---- Microphone Lifecycle ---- */

/* Initialize microphone subsystem. Returns OZAYN_OK on success. */
ozayn_result_t ozayn_microphone_init(void);

/* Shutdown microphone subsystem. Safe to call multiple times. */
void ozayn_microphone_shutdown(void);

/* Check if microphone subsystem is available. Returns 1 if available, 0 otherwise. */
int ozayn_microphone_is_available(void);

/* ---- Device Enumeration ---- */

/* Get number of microphones. Returns count or 0 if unavailable. */
unsigned int ozayn_microphone_get_count(void);

/* Get microphone info by index. Returns OZAYN_OK on success. */
ozayn_result_t ozayn_microphone_get_info(unsigned int index, OzaynMicrophoneInfo *info);

/* ---- Device Control ---- */

/* Open microphone by index. Returns OZAYN_OK on success. */
ozayn_result_t ozayn_microphone_open(unsigned int index);

/* Close currently open microphone. Returns OZAYN_OK on success. */
ozayn_result_t ozayn_microphone_close(void);

/* ---- Capture Control ---- */

/* Start audio capture. Returns OZAYN_OK on success. */
ozayn_result_t ozayn_microphone_start(void);

/* Stop audio capture. Returns OZAYN_OK on success. */
ozayn_result_t ozayn_microphone_stop(void);

/* Capture audio samples. Returns OZAYN_OK on success. */
ozayn_result_t ozayn_microphone_capture(OzaynAudioBuffer *buffer);

/* ---- Buffer Management ---- */

/* Release audio buffer data. Safe to call with NULL or already released buffers. */
void ozayn_microphone_buffer_release(OzaynAudioBuffer *buffer);

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
 * J. Keyboard & Basic Input Event Abstraction (Step 08)
 * ================================================================
 *
 * Platform-independent keyboard state and input event representation.
 * Keyboard state queries are non-blocking and do not create a
 * background keylogger.
 */

/* Modifier flags (bitmask) */
#define OZAYN_MOD_SHIFT    (1 << 0)
#define OZAYN_MOD_CTRL     (1 << 1)
#define OZAYN_MOD_ALT      (1 << 2)

/* Key enumeration — platform-independent */
typedef enum {
    OZAYN_KEY_UNKNOWN = 0,

    /* Letters */
    OZAYN_KEY_A, OZAYN_KEY_B, OZAYN_KEY_C, OZAYN_KEY_D, OZAYN_KEY_E,
    OZAYN_KEY_F, OZAYN_KEY_G, OZAYN_KEY_H, OZAYN_KEY_I, OZAYN_KEY_J,
    OZAYN_KEY_K, OZAYN_KEY_L, OZAYN_KEY_M, OZAYN_KEY_N, OZAYN_KEY_O,
    OZAYN_KEY_P, OZAYN_KEY_Q, OZAYN_KEY_R, OZAYN_KEY_S, OZAYN_KEY_T,
    OZAYN_KEY_U, OZAYN_KEY_V, OZAYN_KEY_W, OZAYN_KEY_X, OZAYN_KEY_Y,
    OZAYN_KEY_Z,

    /* Digits */
    OZAYN_KEY_0, OZAYN_KEY_1, OZAYN_KEY_2, OZAYN_KEY_3, OZAYN_KEY_4,
    OZAYN_KEY_5, OZAYN_KEY_6, OZAYN_KEY_7, OZAYN_KEY_8, OZAYN_KEY_9,

    /* Control keys */
    OZAYN_KEY_ESCAPE, OZAYN_KEY_ENTER, OZAYN_KEY_TAB, OZAYN_KEY_SPACE,
    OZAYN_KEY_BACKSPACE,

    /* Modifier keys */
    OZAYN_KEY_SHIFT, OZAYN_KEY_CTRL, OZAYN_KEY_ALT,

    /* Arrow keys */
    OZAYN_KEY_UP, OZAYN_KEY_DOWN, OZAYN_KEY_LEFT, OZAYN_KEY_RIGHT,

    /* Navigation */
    OZAYN_KEY_HOME, OZAYN_KEY_END, OZAYN_KEY_PAGE_UP, OZAYN_KEY_PAGE_DOWN,
    OZAYN_KEY_INSERT, OZAYN_KEY_DELETE,

    /* Function keys */
    OZAYN_KEY_F1, OZAYN_KEY_F2, OZAYN_KEY_F3, OZAYN_KEY_F4,
    OZAYN_KEY_F5, OZAYN_KEY_F6, OZAYN_KEY_F7, OZAYN_KEY_F8,
    OZAYN_KEY_F9, OZAYN_KEY_F10, OZAYN_KEY_F11, OZAYN_KEY_F12,

    OZAYN_KEY_COUNT
} OzaynKey;

/* Input event type */
typedef enum {
    OZAYN_INPUT_EVENT_NONE = 0,
    OZAYN_INPUT_EVENT_KEY_DOWN,
    OZAYN_INPUT_EVENT_KEY_UP
} OzaynInputEventType;

/* Input event structure */
typedef struct {
    OzaynInputEventType type;
    OzaynKey key;
    unsigned int modifiers;
} OzaynInputEvent;

/* Keyboard state */
typedef struct {
    int initialized;
    int available;
} OzaynKeyboardState;

/* ---- Keyboard Lifecycle ---- */

/* Initialize keyboard subsystem. Returns OZAYN_OK on success. */
ozayn_result_t ozayn_keyboard_init(void);

/* Shutdown keyboard subsystem. Safe to call multiple times. */
void ozayn_keyboard_shutdown(void);

/* Check if keyboard subsystem is available. Returns 1 if available, 0 otherwise. */
int ozayn_keyboard_is_available(void);

/* ---- Key State ---- */

/* Check if a specific key is currently pressed. Returns 1 if pressed, 0 if not,
 * -1 if query is unsupported. */
int ozayn_keyboard_is_key_down(OzaynKey key);

/* ---- Event Polling ---- */

/* Poll for the next keyboard event (non-blocking). Returns OZAYN_OK if an event
 * was retrieved, OZAYN_ERR if no event is available or polling is unsupported. */
ozayn_result_t ozayn_keyboard_poll_event(OzaynInputEvent *event);

/* ---- Key Name ---- */

/* Get human-readable name for a key. Never returns NULL. */
const char *ozayn_key_name(OzaynKey key);

/* ================================================================
 * K. Audio Output / Speaker Abstraction (Step 11)
 * ================================================================
 *
 * Cross-platform audio output enumeration, configuration, and PCM
 * audio playback. This is the hardware/device abstraction layer only.
 * Uses OzaynAudioFormat from Section H for sample format.
 */

#define OZAYN_MAX_SPEAKERS 16
#define OZAYN_MAX_SPEAKER_NAME 256
#define OZAYN_MAX_SPEAKER_ID 256

/* ---- Audio Output Info ---- */

typedef struct {
    int index;
    char id[OZAYN_MAX_SPEAKER_ID];
    char name[OZAYN_MAX_SPEAKER_NAME];
    int available;
    int channels;
    int sample_rate;
} OzaynAudioOutputInfo;

/* ---- Audio Output Buffer (caller-owned data) ---- */

typedef struct {
    unsigned int sample_rate;
    unsigned int channels;
    OzaynAudioFormat format;
    size_t frame_count;
    const unsigned char *data;
    size_t data_size;
} OzaynAudioOutputBuffer;

/* ---- Audio Output State ---- */

typedef struct {
    int initialized;
    int available;
    int open;
    int streaming;
    unsigned int count;
} OzaynAudioOutputState;

/* ---- Audio Output Lifecycle ---- */

ozayn_result_t ozayn_audio_output_init(void);
void           ozayn_audio_output_shutdown(void);

/* ---- Audio Output Queries ---- */

int            ozayn_audio_output_is_available(void);
unsigned int   ozayn_audio_output_get_count(void);
ozayn_result_t ozayn_audio_output_get_info(unsigned int index, OzaynAudioOutputInfo *info);

/* ---- Audio Output Control ---- */

ozayn_result_t ozayn_audio_output_open(unsigned int index);
ozayn_result_t ozayn_audio_output_close(void);

/* ---- Audio Output Streaming ---- */

ozayn_result_t ozayn_audio_output_start(void);
ozayn_result_t ozayn_audio_output_write(const OzaynAudioOutputBuffer *buffer);
ozayn_result_t ozayn_audio_output_stop(void);

/* ================================================================
 * L. Network Information & Connectivity Abstraction (Step 12)
 * ================================================================
 *
 * Cross-platform network interface enumeration, address discovery,
 * and basic connectivity checking. This is the information
 * abstraction layer only — no packet capture, no port scanning,
 * no traffic monitoring.
 */

#define OZAYN_MAX_NETWORK_IFACES 16
#define OZAYN_MAX_IFACE_NAME_LEN 64
#define OZAYN_MAX_IPV4_LEN 64
#define OZAYN_MAX_IPV6_LEN 128
#define OZAYN_MAX_MAC_LEN 32

/* ---- Network Interface Info ---- */

typedef struct {
    int index;
    char name[OZAYN_MAX_IFACE_NAME_LEN];
    char ipv4[OZAYN_MAX_IPV4_LEN];
    char ipv6[OZAYN_MAX_IPV6_LEN];
    char mac[OZAYN_MAX_MAC_LEN];
    int is_up;
    int is_loopback;
} OzaynNetworkInterfaceInfo;

/* ---- Connectivity State ---- */

typedef enum {
    OZAYN_CONNECTIVITY_UNKNOWN = 0,
    OZAYN_CONNECTIVITY_DISCONNECTED,
    OZAYN_CONNECTIVITY_CONNECTED
} OzaynConnectivityState;

/* ---- Network State ---- */

typedef struct {
    int initialized;
    int available;
    unsigned int count;
    int has_default;
    int default_index;
} OzaynNetworkState;

/* ---- Network Lifecycle ---- */

ozayn_result_t ozayn_network_init(void);
void           ozayn_network_shutdown(void);

/* ---- Network Queries ---- */

int            ozayn_network_is_available(void);
unsigned int   ozayn_network_get_interface_count(void);
ozayn_result_t ozayn_network_get_interface_info(unsigned int index, OzaynNetworkInterfaceInfo *info);
int            ozayn_network_get_default_interface(void);

/* ---- Connectivity Check ---- */

OzaynConnectivityState ozayn_network_is_connected(void);

/* ================================================================
 * M. Power & Battery Information Abstraction (Step 13)
 * ================================================================
 *
 * Cross-platform power source information and battery status.
 * Read-only — no power management, no shutdown, no sleep control.
 */

/* ---- Power State ---- */

typedef enum {
    OZAYN_POWER_UNKNOWN = 0,
    OZAYN_POWER_BATTERY,
    OZAYN_POWER_CHARGING,
    OZAYN_POWER_AC_POWER,
    OZAYN_POWER_NO_BATTERY
} OzaynPowerState;

/* ---- Power Info ---- */

typedef struct {
    int available;
    int has_battery;
    int battery_percent;      /* 0–100, or -1 if unknown */
    int charging;
    int plugged_in;
    long long battery_remaining_seconds;  /* -1 if unknown */
    long long battery_full_seconds;       /* -1 if unknown */
} OzaynPowerInfo;

/* ---- Power Lifecycle ---- */

ozayn_result_t ozayn_power_init(void);
void           ozayn_power_shutdown(void);

/* ---- Power Queries ---- */

int            ozayn_power_is_available(void);
ozayn_result_t ozayn_power_get_info(OzaynPowerInfo *info);
int            ozayn_power_has_battery(void);
int            ozayn_power_get_battery_percent(void);
int            ozayn_power_is_charging(void);
int            ozayn_power_is_plugged_in(void);

/* ================================================================
 * N. Notification System Abstraction (Step 14)
 * ================================================================
 *
 * Cross-platform native desktop notification display.
 * Uses the operating system's native notification mechanism.
 * No notification history, no GUI windows, no remote notifications.
 */

#define OZAYN_MAX_NOTIF_TITLE    256
#define OZAYN_MAX_NOTIF_MESSAGE  1024
#define OZAYN_MAX_NOTIF_APP_NAME 256

/* ---- Notification ---- */

typedef struct {
    char title[OZAYN_MAX_NOTIF_TITLE];
    char message[OZAYN_MAX_NOTIF_MESSAGE];
    char application_name[OZAYN_MAX_NOTIF_APP_NAME];
} OzaynNotification;

/* ---- Notification Lifecycle ---- */

ozayn_result_t ozayn_notification_init(void);
void           ozayn_notification_shutdown(void);

/* ---- Notification Queries ---- */

int            ozayn_notification_is_available(void);

/* ---- Notification Send ---- */

ozayn_result_t ozayn_notification_send(const OzaynNotification *notification);

/* ================================================================
 * O. Clipboard Abstraction (Step 15)
 * ================================================================
 *
 * Cross-platform plain-text clipboard read/write.
 * No clipboard monitoring, no history, no remote access.
 * Plain text only — no images, files, or rich text.
 */

#define OZAYN_MAX_CLIPBOARD_TEXT 65536

/* ---- Clipboard Lifecycle ---- */

ozayn_result_t ozayn_clipboard_init(void);
void           ozayn_clipboard_shutdown(void);

/* ---- Clipboard Queries ---- */

int            ozayn_clipboard_is_available(void);
int            ozayn_clipboard_has_text(void);

/* ---- Clipboard Read ---- */

ozayn_result_t ozayn_clipboard_get_text(char *buffer, size_t buffer_size, size_t *required_size);

/* ---- Clipboard Write ---- */

ozayn_result_t ozayn_clipboard_set_text(const char *text);

/* ---- Clipboard Clear ---- */

ozayn_result_t ozayn_clipboard_clear(void);

/* ================================================================
 * P. Environment & User Session Abstraction (Step 16)
 * ================================================================
 *
 * Cross-platform environment variable access and user-session
 * information. Read-only — no modification of environment or
 * system state. No credential or secret extraction.
 */

#define OZAYN_MAX_ENV_VAR_NAME  256
#define OZAYN_MAX_ENV_VAR_VALUE 4096
#define OZAYN_MAX_ENV_PATH     1024
#define OZAYN_MAX_USERNAME      256
#define OZAYN_MAX_HOSTNAME      256

/* ---- Environment Lifecycle ---- */

ozayn_result_t ozayn_environment_init(void);
void           ozayn_environment_shutdown(void);

/* ---- Environment Queries ---- */

int            ozayn_environment_is_available(void);

/* ---- Environment Variable Access ---- */

ozayn_result_t ozayn_environment_get_variable(const char *name,
                                               char *buffer,
                                               size_t buffer_size,
                                               size_t *required_size);

/* ---- Directory Queries ---- */

ozayn_result_t ozayn_environment_get_home_directory(char *buffer, size_t buffer_size);
ozayn_result_t ozayn_environment_get_temp_directory(char *buffer, size_t buffer_size);
ozayn_result_t ozayn_environment_get_current_directory(char *buffer, size_t buffer_size);

/* ---- User/Host Information ---- */

ozayn_result_t ozayn_environment_get_username(char *buffer, size_t buffer_size);
ozayn_result_t ozayn_environment_get_hostname(char *buffer, size_t buffer_size);

/* ================================================================
 * Q. System Time & Date Abstraction (Step 17)
 * ================================================================
 *
 * Cross-platform system time and date information.
 * Read-only — no clock modification, no timezone changes.
 * Basic sleep primitive only — no scheduling.
 */

/* ---- Date/Time Structure ---- */

typedef struct {
    int year;
    int month;          /* 1–12 */
    int day;            /* 1–31 */
    int hour;           /* 0–23 */
    int minute;         /* 0–59 */
    int second;         /* 0–59 */
    int millisecond;    /* 0–999 */
    int utc_offset_minutes;
} OzaynDateTime;

/* ---- Time Lifecycle ---- */

ozayn_result_t ozayn_time_init(void);
void           ozayn_time_shutdown(void);

/* ---- Time Queries ---- */

int            ozayn_time_is_available(void);

/* ---- Unix Timestamps ---- */

int64_t        ozayn_time_unix_seconds(void);
int64_t        ozayn_time_unix_milliseconds(void);
int64_t        ozayn_time_unix_microseconds(void);

/* ---- Date/Time Retrieval ---- */

ozayn_result_t ozayn_time_get_local(OzaynDateTime *datetime);
ozayn_result_t ozayn_time_get_utc(OzaynDateTime *datetime);

/* ---- Sleep ---- */

ozayn_result_t ozayn_time_sleep_ms(uint64_t milliseconds);

/* ================================================================
 * R. Application Launch & Discovery Abstraction (Step 18)
 * ================================================================
 *
 * Cross-platform application discovery, launching, and URL opening.
 * Read-only access to application state — no installation, no modification.
 * No shell execution — uses native OS mechanisms only.
 */

/* ---- Application Lifecycle ---- */

ozayn_result_t ozayn_application_init(void);
void           ozayn_application_shutdown(void);

/* ---- Application Queries ---- */

int            ozayn_application_is_available(void);

/* ---- Application Launch ---- */

ozayn_result_t ozayn_application_launch(const char *application);

/* ---- Application Existence ---- */

int            ozayn_application_exists(const char *application);

/* ---- Default Browser ---- */

ozayn_result_t ozayn_application_get_default_browser(char *buffer, size_t buffer_size);

/* ---- URL Opening ---- */

ozayn_result_t ozayn_application_open_url(const char *url);

/* ================================================================
 * S. System Permissions & Capability Access Abstraction (Step 19)
 * ================================================================
 *
 * Cross-platform capability/permission inspection.
 * Read-only — no permission modification, no bypass, no elevation.
 * Determines whether OS capabilities are available, granted, denied,
 * restricted, or unknown.
 */

/* ---- Capability Types ---- */

typedef enum {
    OZAYN_CAP_UNKNOWN = 0,
    OZAYN_CAP_CAMERA = 1,
    OZAYN_CAP_MICROPHONE = 2,
    OZAYN_CAP_NOTIFICATIONS = 3,
    OZAYN_CAP_ACCESSIBILITY = 4,
    OZAYN_CAP_FILESYSTEM = 5,
    OZAYN_CAP_NETWORK = 6
} OzaynCapability;

/* ---- Permission States ---- */

typedef enum {
    OZAYN_PERMISSION_UNKNOWN = 0,
    OZAYN_PERMISSION_AVAILABLE,
    OZAYN_PERMISSION_GRANTED,
    OZAYN_PERMISSION_DENIED,
    OZAYN_PERMISSION_RESTRICTED,
    OZAYN_PERMISSION_UNAVAILABLE
} OzaynPermissionState;

/* ---- Permissions Lifecycle ---- */

ozayn_result_t ozayn_permissions_init(void);
void           ozayn_permissions_shutdown(void);

/* ---- Permission Queries ---- */

int                  ozayn_permissions_is_available(void);
OzaynPermissionState ozayn_permissions_get_state(OzaynCapability capability);

/* ---- Name Helpers ---- */

const char *ozayn_capability_get_name(OzaynCapability capability);
const char *ozayn_permission_state_name(OzaynPermissionState state);

/* ================================================================
 * T. System Audio Volume & Mute Abstraction (Step 20)
 * ================================================================
 *
 * Cross-platform system audio output volume and mute state control.
 * Operates on the default output device only.
 * Volume range: 0–100. Mute: 0 or 1.
 */

/* ---- Audio Volume Lifecycle ---- */

ozayn_result_t ozayn_audio_volume_init(void);
void           ozayn_audio_volume_shutdown(void);

/* ---- Audio Volume Queries ---- */

int  ozayn_audio_volume_is_available(void);
ozayn_result_t ozayn_audio_volume_get(int *volume);

/* ---- Audio Volume Control ---- */

ozayn_result_t ozayn_audio_volume_set(int volume);

/* ---- Mute Control ---- */

ozayn_result_t ozayn_audio_volume_is_muted(int *muted);
ozayn_result_t ozayn_audio_volume_set_muted(int muted);
ozayn_result_t ozayn_audio_volume_toggle_mute(void);

/* ================================================================
 * U. System Lock State & Session Control Abstraction (Step 21)
 * ================================================================
 *
 * Cross-platform session state detection and lock control.
 * Read-only detection + safe lock action only.
 * No shutdown, reboot, logout, or privilege escalation.
 */

/* ---- Session State ---- */

typedef enum {
    OZAYN_SESSION_UNKNOWN = 0,
    OZAYN_SESSION_ACTIVE,
    OZAYN_SESSION_LOCKED,
    OZAYN_SESSION_INACTIVE,
    OZAYN_SESSION_UNAVAILABLE
} OzaynSessionState;

/* ---- Session Lifecycle ---- */

ozayn_result_t ozayn_session_init(void);
void           ozayn_session_shutdown(void);

/* ---- Session Queries ---- */

int               ozayn_session_is_available(void);
OzaynSessionState ozayn_session_get_state(void);
int               ozayn_session_is_locked(void);
const char       *ozayn_session_state_name(OzaynSessionState state);

/* ---- Session Actions ---- */

ozayn_result_t ozayn_session_lock(void);

/* ================================================================
 * V. System Brightness & Display Power Abstraction (Step 22)
 * ================================================================
 *
 * Cross-platform display brightness query and control.
 * Operates on the primary display only.
 * Brightness range: 0–100 (normalized from native range).
 */

/* ---- Brightness Lifecycle ---- */

ozayn_result_t ozayn_brightness_init(void);
void           ozayn_brightness_shutdown(void);

/* ---- Brightness Queries ---- */

int  ozayn_brightness_is_available(void);
ozayn_result_t ozayn_brightness_get(int *brightness);
ozayn_result_t ozayn_brightness_get_supported(int *supported);

/* ---- Brightness Control ---- */

ozayn_result_t ozayn_brightness_set(int brightness);

/* ================================================================
 * W. System Theme & Appearance Abstraction (Step 23)
 * ================================================================
 *
 * Cross-platform system theme/appearance detection.
 * Read-only — no theme modification, no color changes.
 * Detects light/dark mode from OS settings.
 */

/* ---- Appearance Types ---- */

typedef enum {
    OZAYN_APPEARANCE_UNKNOWN = 0,
    OZAYN_APPEARANCE_LIGHT,
    OZAYN_APPEARANCE_DARK
} OzaynAppearance;

/* ---- Appearance Lifecycle ---- */

ozayn_result_t ozayn_appearance_init(void);
void           ozayn_appearance_shutdown(void);

/* ---- Appearance Queries ---- */

int             ozayn_appearance_is_available(void);
OzaynAppearance ozayn_appearance_get(void);
const char     *ozayn_appearance_name(OzaynAppearance appearance);

/* ================================================================
 * X. System Font & Text Rendering Information Abstraction (Step 24)
 * ================================================================
 *
 * Cross-platform system font discovery and information.
 * Read-only — no font installation, removal, or modification.
 * Provides font count, family/style info, and default font.
 */

/* ---- Font Information ---- */

typedef struct {
    int index;
    char family[256];
    char style[128];
    int available;
} OzaynFontInfo;

/* ---- Font Lifecycle ---- */

ozayn_result_t ozayn_font_init(void);
void           ozayn_font_shutdown(void);

/* ---- Font Queries ---- */

int  ozayn_font_is_available(void);
int  ozayn_font_get_count(void);
ozayn_result_t ozayn_font_get_info(int index, OzaynFontInfo *info);
ozayn_result_t ozayn_font_get_default(char *family, size_t family_size);

/* ================================================================
 * Y. System Hardware Sensors Abstraction (Step 25)
 * ================================================================
 *
 * Cross-platform hardware sensor discovery and reading.
 * Read-only — no hardware control, no fan speed control.
 * Discovers temperature, fan, voltage, current, power sensors.
 */

/* ---- Sensor Types ---- */

typedef enum {
    OZAYN_SENSOR_UNKNOWN = 0,
    OZAYN_SENSOR_TEMPERATURE,
    OZAYN_SENSOR_FAN,
    OZAYN_SENSOR_VOLTAGE,
    OZAYN_SENSOR_CURRENT,
    OZAYN_SENSOR_POWER
} OzaynSensorType;

/* ---- Sensor Information ---- */

typedef struct {
    int index;
    OzaynSensorType type;
    char id[128];
    char name[256];
    double value;
    char unit[32];
    int available;
} OzaynSensorInfo;

/* ---- Sensor Lifecycle ---- */

ozayn_result_t ozayn_sensors_init(void);
void           ozayn_sensors_shutdown(void);

/* ---- Sensor Queries ---- */

int  ozayn_sensors_is_available(void);
int  ozayn_sensors_get_count(void);
ozayn_result_t ozayn_sensors_get_info(int index, OzaynSensorInfo *info);

/* ---- Sensor Type Names ---- */

const char *ozayn_sensor_type_name(OzaynSensorType type);

/* ================================================================
 * Z. System Storage & Disk Information Abstraction (Step 26)
 * ================================================================
 *
 * Cross-platform mounted volume discovery and storage information.
 * Read-only — no formatting, partitioning, mounting, or unmounting.
 * Discovers mounted volumes with capacity and filesystem info.
 */

/* ---- Storage Information ---- */

#include <stdint.h>

typedef struct {
    int index;
    char id[128];
    char name[256];
    char mount_point[512];
    char filesystem[128];

    uint64_t total_bytes;
    uint64_t free_bytes;
    uint64_t available_bytes;

    int removable;
    int read_only;
    int available;
} OzaynStorageInfo;

/* ---- Storage Lifecycle ---- */

ozayn_result_t ozayn_storage_init(void);
void           ozayn_storage_shutdown(void);

/* ---- Storage Queries ---- */

int  ozayn_storage_is_available(void);
int  ozayn_storage_get_count(void);
ozayn_result_t ozayn_storage_get_info(int index, OzaynStorageInfo *info);
ozayn_result_t ozayn_storage_get_system_volume(OzaynStorageInfo *info);

/* ================================================================
 * AA. USB & Peripheral Device Enumeration Abstraction (Step 27)
 * ================================================================
 *
 * Cross-platform USB and peripheral device discovery and enumeration.
 * Read-only — no device control, no driver installation, no ejection.
 * Discovers connected devices with type, name, and vendor/product info.
 */

/* ---- Peripheral Types ---- */

typedef enum {
    OZAYN_PERIPHERAL_UNKNOWN = 0,
    OZAYN_PERIPHERAL_USB,
    OZAYN_PERIPHERAL_CAMERA,
    OZAYN_PERIPHERAL_MICROPHONE,
    OZAYN_PERIPHERAL_AUDIO_OUTPUT,
    OZAYN_PERIPHERAL_KEYBOARD,
    OZAYN_PERIPHERAL_MOUSE,
    OZAYN_PERIPHERAL_STORAGE,
    OZAYN_PERIPHERAL_DISPLAY,
    OZAYN_PERIPHERAL_OTHER
} OzaynPeripheralType;

/* ---- Peripheral Information ---- */

typedef struct {
    size_t index;

    OzaynPeripheralType type;

    char id[256];
    char name[256];
    char manufacturer[256];
    char description[512];

    char connection[64];

    int vendor_id;
    int product_id;

    int available;
} OzaynPeripheralInfo;

/* ---- Peripheral Lifecycle ---- */

ozayn_result_t ozayn_peripheral_init(void);
void           ozayn_peripheral_shutdown(void);

/* ---- Peripheral Queries ---- */

int  ozayn_peripheral_is_available(void);
size_t ozayn_peripheral_get_count(void);
ozayn_result_t ozayn_peripheral_get_info(size_t index, OzaynPeripheralInfo *info);

/* ---- Peripheral Type Names ---- */

const char *ozayn_peripheral_type_name(OzaynPeripheralType type);

/* ================================================================
 * AB. Bluetooth & Wireless Peripheral Discovery Abstraction (Step 28)
 * ================================================================
 *
 * Cross-platform Bluetooth device discovery and basic information.
 * Read-only — no pairing, connection, data transfer, or device control.
 * Discovers nearby Bluetooth devices with type, name, and signal info.
 */

/* ---- Bluetooth Types ---- */

typedef enum {
    OZAYN_BLUETOOTH_UNKNOWN = 0,
    OZAYN_BLUETOOTH_CLASSIC,
    OZAYN_BLUETOOTH_LOW_ENERGY
} OzaynBluetoothType;

/* ---- Bluetooth Device Information ---- */

typedef struct {
    size_t index;

    OzaynBluetoothType type;

    char id[256];
    char name[256];
    char address[64];
    char description[512];

    int signal_strength;
    int signal_strength_available;

    int paired;
    int connected;
    int available;
} OzaynBluetoothDeviceInfo;

/* ---- Bluetooth Lifecycle ---- */

ozayn_result_t ozayn_bluetooth_init(void);
void           ozayn_bluetooth_shutdown(void);

/* ---- Bluetooth Queries ---- */

int  ozayn_bluetooth_is_available(void);

/* ---- Bluetooth Discovery ---- */

ozayn_result_t ozayn_bluetooth_start_discovery(void);
ozayn_result_t ozayn_bluetooth_stop_discovery(void);
int  ozayn_bluetooth_is_discovering(void);

/* ---- Bluetooth Device Enumeration ---- */

size_t ozayn_bluetooth_get_device_count(void);
ozayn_result_t ozayn_bluetooth_get_device_info(size_t index, OzaynBluetoothDeviceInfo *info);

/* ---- Bluetooth Type Names ---- */

const char *ozayn_bluetooth_type_name(OzaynBluetoothType type);

/* ================================================================
 * AC. System Event & Hardware Change Notification Abstraction (Step 29)
 * ================================================================
 *
 * Cross-platform system event detection and hardware change notifications.
 * Read-only — no system modification, no persistent history.
 * Detects device, display, network, power, audio, session, bluetooth changes.
 */

/* ---- System Event Types ---- */

typedef enum {
    OZAYN_SYSTEM_EVENT_NONE = 0,

    OZAYN_SYSTEM_EVENT_DEVICE_CONNECTED,
    OZAYN_SYSTEM_EVENT_DEVICE_DISCONNECTED,

    OZAYN_SYSTEM_EVENT_DISPLAY_CHANGED,

    OZAYN_SYSTEM_EVENT_NETWORK_CHANGED,

    OZAYN_SYSTEM_EVENT_POWER_CHANGED,

    OZAYN_SYSTEM_EVENT_AUDIO_CHANGED,

    OZAYN_SYSTEM_EVENT_SESSION_CHANGED,

    OZAYN_SYSTEM_EVENT_BLUETOOTH_CHANGED
} OzaynSystemEventType;

/* ---- System Event Information ---- */

typedef struct {
    OzaynSystemEventType type;

    char source[128];
    char description[512];

    uint64_t timestamp_ms;

    int available;
} OzaynSystemEvent;

/* ---- System Event Lifecycle ---- */

ozayn_result_t ozayn_system_event_init(void);
void           ozayn_system_event_shutdown(void);

/* ---- System Event Control ---- */

int  ozayn_system_event_is_available(void);
ozayn_result_t ozayn_system_event_start(void);
ozayn_result_t ozayn_system_event_stop(void);
int  ozayn_system_event_is_running(void);

/* ---- System Event Polling ---- */

ozayn_result_t ozayn_system_event_poll(OzaynSystemEvent *event);

/* ---- System Event Type Names ---- */

const char *ozayn_system_event_type_name(OzaynSystemEventType type);

/* ================================================================
 * AD. System Resource Monitoring Abstraction (Step 30)
 * ================================================================
 *
 * Cross-platform read-only system resource monitoring.
 * Provides current CPU usage, memory usage, process count,
 * and load average where supported by the operating system.
 * No background monitoring — caller explicitly queries resources.
 */

/* ---- Resource Information Structure ---- */

typedef struct {
    int available;                    /* 1 if the resource monitoring system is available */

    double cpu_usage_percent;         /* System-wide CPU usage: 0.0–100.0 */
    int cpu_usage_available;          /* 1 if cpu_usage_percent is valid */

    uint64_t memory_total_bytes;      /* Total physical memory in bytes */
    uint64_t memory_used_bytes;       /* Used physical memory in bytes */
    uint64_t memory_available_bytes;  /* Available physical memory in bytes */
    int memory_usage_available;       /* 1 if memory values are valid */

    size_t process_count;             /* Approximate number of running processes */
    int process_count_available;      /* 1 if process_count is valid */

    double load_average_1m;           /* 1-minute load average */
    double load_average_5m;           /* 5-minute load average */
    double load_average_15m;          /* 15-minute load average */
    int load_average_available;       /* 1 if load averages are valid */
} OzaynResourceInfo;

/* ---- Resource Monitoring Lifecycle ---- */

ozayn_result_t ozayn_resources_init(void);
void           ozayn_resources_shutdown(void);

/* ---- Resource Monitoring Queries ---- */

int  ozayn_resources_is_available(void);
ozayn_result_t ozayn_resources_get_info(OzaynResourceInfo *info);
ozayn_result_t ozayn_resources_get_cpu_usage(double *usage_percent);
ozayn_result_t ozayn_resources_get_memory_usage(uint64_t *total_bytes, uint64_t *used_bytes, uint64_t *available_bytes);
ozayn_result_t ozayn_resources_get_process_count(size_t *count);
ozayn_result_t ozayn_resources_get_load_average(double *load_1m, double *load_5m, double *load_15m);

/* ================================================================
 * AE. Network Configuration & Routing Information Abstraction (Step 31)
 * ================================================================
 *
 * Cross-platform read-only network configuration and routing information.
 * Extends Step 12 with subnet, gateway, and DNS details.
 * No network modification, no packet capture, no credential access.
 */

#define OZAYN_MAX_NETCFG_IFACE  128
#define OZAYN_MAX_NETCFG_ADDR   64
#define OZAYN_MAX_NETCFG_V6    128
#define OZAYN_MAX_NETCFG_DNS   128
#define OZAYN_MAX_NETCFG_IFACES 16

/* ---- Network Configuration ---- */

typedef struct {
    int index;

    char interface_name[OZAYN_MAX_NETCFG_IFACE];

    char ipv4_address[OZAYN_MAX_NETCFG_ADDR];
    char ipv6_address[OZAYN_MAX_NETCFG_V6];

    char subnet_mask[OZAYN_MAX_NETCFG_ADDR];

    char gateway_ipv4[OZAYN_MAX_NETCFG_ADDR];
    char gateway_ipv6[OZAYN_MAX_NETCFG_V6];

    char dns_primary[OZAYN_MAX_NETCFG_DNS];
    char dns_secondary[OZAYN_MAX_NETCFG_DNS];

    int has_ipv4;
    int has_ipv6;
    int has_gateway;
    int has_dns;

    int available;
} OzaynNetworkConfig;

/* ---- Network Configuration Lifecycle ---- */

ozayn_result_t ozayn_network_config_init(void);
void           ozayn_network_config_shutdown(void);

/* ---- Network Configuration Queries ---- */

int  ozayn_network_config_is_available(void);
int  ozayn_network_config_get_count(void);
ozayn_result_t ozayn_network_config_get(int index, OzaynNetworkConfig *config);
ozayn_result_t ozayn_network_config_get_default(OzaynNetworkConfig *config);

/* ================================================================
 * AF. System Service & Background Process Information Abstraction (Step 32)
 * ================================================================
 *
 * Cross-platform read-only system service and background process discovery.
 * Extends Process Management (Step 04) with service-specific metadata.
 * No service control, no start/stop, no installation, no modification.
 */

/* ---- Service Types ---- */

typedef enum {
    OZAYN_SERVICE_UNKNOWN = 0,
    OZAYN_SERVICE_SYSTEM,
    OZAYN_SERVICE_USER,
    OZAYN_SERVICE_OTHER
} OzaynServiceType;

/* ---- Service States ---- */

typedef enum {
    OZAYN_SERVICE_STATE_UNKNOWN = 0,
    OZAYN_SERVICE_STATE_RUNNING,
    OZAYN_SERVICE_STATE_STOPPED,
    OZAYN_SERVICE_STATE_PAUSED,
    OZAYN_SERVICE_STATE_DISABLED,
    OZAYN_SERVICE_STATE_OTHER
} OzaynServiceState;

/* ---- Service Information ---- */

#define OZAYN_MAX_SERVICE_ID 256
#define OZAYN_MAX_SERVICE_NAME 256
#define OZAYN_MAX_SERVICE_DESC 512
#define OZAYN_MAX_SERVICES 256

typedef struct {
    int index;

    OzaynServiceType type;
    OzaynServiceState state;

    char id[OZAYN_MAX_SERVICE_ID];
    char name[OZAYN_MAX_SERVICE_NAME];
    char description[OZAYN_MAX_SERVICE_DESC];

    int available;
} OzaynServiceInfo;

/* ---- Service Lifecycle ---- */

ozayn_result_t ozayn_service_init(void);
void           ozayn_service_shutdown(void);

/* ---- Service Queries ---- */

int  ozayn_service_is_available(void);
int  ozayn_service_get_count(void);
ozayn_result_t ozayn_service_get_info(int index, OzaynServiceInfo *info);
ozayn_result_t ozayn_service_find(const char *name, OzaynServiceInfo *info);

/* ---- Service Type/State Names ---- */

const char *ozayn_sys_service_type_name(OzaynServiceType type);
const char *ozayn_sys_service_state_name(OzaynServiceState state);

/* ================================================================
 * AG. System Security & Firewall State Abstraction (Step 33)
 * ================================================================
 *
 * Cross-platform read-only system security and firewall state detection.
 * Diagnostic only — no security modification, no rule changes, no control.
 * Detects whether firewall/antivirus protection appears enabled or disabled.
 */

/* ---- Security States ---- */

typedef enum {
    OZAYN_SECURITY_UNKNOWN = 0,
    OZAYN_SECURITY_ENABLED,
    OZAYN_SECURITY_DISABLED,
    OZAYN_SECURITY_UNAVAILABLE
} OzaynSecurityState;

/* ---- Security Information ---- */

#define OZAYN_MAX_SECURITY_NAME 256

typedef struct {
    int available;

    OzaynSecurityState firewall_state;
    char firewall_name[OZAYN_MAX_SECURITY_NAME];
    int firewall_state_available;

    OzaynSecurityState antivirus_state;
    int antivirus_state_available;
} OzaynSecurityInfo;

/* ---- Security Lifecycle ---- */

ozayn_result_t ozayn_sys_security_init(void);
void           ozayn_sys_security_shutdown(void);

/* ---- Security Queries ---- */

int  ozayn_sys_security_is_available(void);
ozayn_result_t ozayn_sys_security_get_info(OzaynSecurityInfo *info);
OzaynSecurityState ozayn_sys_security_get_firewall_state(void);

/* ---- Security State Names ---- */

const char *ozayn_sys_security_state_name(OzaynSecurityState state);

/* ================================================================
 * Platform Lifecycle
 * ================================================================ */

/* Initialize platform layer. Call once at startup. */
ozayn_result_t ozayn_platform_init(void);

/* Shutdown platform layer. Call once at shutdown. */
void ozayn_platform_shutdown(void);

#endif
