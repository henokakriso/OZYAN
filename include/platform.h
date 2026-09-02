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
 * Platform Lifecycle
 * ================================================================ */

/* Initialize platform layer. Call once at startup. */
ozayn_result_t ozayn_platform_init(void);

/* Shutdown platform layer. Call once at shutdown. */
void ozayn_platform_shutdown(void);

#endif
