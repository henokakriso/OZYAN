# Section 02 — Cross-Platform System Layer

## Purpose

Provides platform abstraction so OZAYN Core can identify and interact with the operating system without OS-specific code in the core logic.

```
OZAYN CORE
    ↓
PLATFORM API
    ↓
Operating System
```

## Step 01 — Platform Detection & Initialization

Detects the host OS at compile time and provides runtime query functions.

### Supported Platforms

| Platform | Macro | Enum Value |
|----------|-------|------------|
| Linux | `OZAYN_OS_LINUX` | `OZAYN_PLATFORM_LINUX` |
| Windows | `OZAYN_OS_WINDOWS` | `OZAYN_PLATFORM_WINDOWS` |
| macOS | `OZAYN_OS_MACOS` | `OZAYN_PLATFORM_MACOS` |
| Unknown | `OZAYN_OS_UNKNOWN` | `OZAYN_PLATFORM_UNKNOWN` |

### Public API

```c
ozayn_result_t ozayn_platform_detect_init(void);   /* detect and set platform */
void           ozayn_platform_detect_shutdown(void); /* reset to UNKNOWN */
OzaynPlatform  ozayn_platform_get(void);            /* get detected platform */
const char    *ozayn_platform_name(void);           /* "Linux", "Windows", "macOS", or "Unknown" */
```

## Step 02 — System Information & Hardware Identification

Provides cross-platform access to OS, architecture, CPU, memory, hostname, and username.

### Public API

```c
ozayn_result_t ozayn_platform_get_info(OzaynPlatformInfo *info);
```

## Step 03 — Filesystem Abstraction

Cross-platform filesystem operations for files and directories.

### Public API

```c
int ozayn_fs_exists(const char *path);        /* 1 if exists, 0 otherwise */
int ozayn_fs_is_file(const char *path);       /* 1 if regular file, 0 otherwise */
int ozayn_fs_is_dir(const char *path);        /* 1 if directory, 0 otherwise */

ozayn_result_t ozayn_fs_mkdir(const char *path);     /* create directory (recursive) */
ozayn_result_t ozayn_fs_rmdir(const char *path);     /* remove empty directory */
ozayn_result_t ozayn_fs_remove(const char *path);    /* remove file */

int64_t ozayn_fs_size(const char *path);             /* file size in bytes, -1 on error */
int64_t ozayn_fs_read(const char *path, void *buf, uint64_t buf_size);   /* bytes read or -1 */
int64_t ozayn_fs_write(const char *path, const void *data, uint64_t size); /* bytes written or -1 */
int64_t ozayn_fs_append(const char *path, const void *data, uint64_t size); /* bytes appended or -1 */

ozayn_result_t ozayn_fs_copy(const char *source, const char *dest);  /* copy file */
ozayn_result_t ozayn_fs_move(const char *source, const char *dest);  /* move/rename file */

const char *ozayn_fs_home(void);        /* user home directory */
const char *ozayn_fs_config_dir(void);  /* platform config directory */
```

### Safety

- All functions handle NULL paths safely (return error/0)
- Empty paths are rejected
- Binary-safe (works with any data)
- Uses `int64_t` for file sizes (supports >2GB files)
- No recursive directory deletion

### Platform Implementations

- Linux/macOS: POSIX (`stat`, `mkdir`, `fopen`, `rename`, `rmdir`)
- Windows: Win32 (`GetFileAttributes`, `CreateFile`, `CopyFile`, `MoveFile`, `RemoveDirectory`)

## Step 04 — Process Management Abstraction

Cross-platform process lifecycle: start, query, terminate, wait, and close.

### Public API

```c
typedef enum {
    OZAYN_PROC_STATE_UNKNOWN = 0,
    OZAYN_PROC_STATE_RUNNING,
    OZAYN_PROC_STATE_STOPPED,
    OZAYN_PROC_STATE_EXITED,
    OZAYN_PROC_STATE_FAILED
} OzaynProcessState;

typedef struct {
    uint32_t           pid;
    OzaynProcessState  state;
    int                exit_code;
    char               name[OZAYN_MAX_PROCESS_NAME];
} OzaynProcessInfo;

typedef struct {
    uint32_t pid;
    int      running;
    int      _internal[16];
} OzaynProcess;

ozayn_result_t ozayn_process_start(const char *program, const char *const argv[], OzaynProcess *proc);
int            ozayn_process_is_running(OzaynProcess *proc);
ozayn_result_t ozayn_proc_get_info(OzaynProcess *proc, OzaynProcessInfo *info);
ozayn_result_t ozayn_process_terminate(OzaynProcess *proc);
ozayn_result_t ozayn_process_wait(OzaynProcess *proc, uint32_t timeout_ms);
void           ozayn_process_close(OzaynProcess *proc);
```

### Safety

- All functions handle NULL parameters safely
- `ozayn_process_close()` is idempotent and safe to call multiple times
- `ozayn_process_wait()` supports both blocking (timeout=0) and timed waits
- Exec failure detection via pipe + FD_CLOEXEC (POSIX) or CreateProcess error code (Windows)
- No `system()` calls — uses `fork/execvp` (POSIX) or `CreateProcess` (Windows)

### Platform Implementations

- Linux/macOS: POSIX (`fork`, `execvp`, `waitpid`, `kill`, pipes)
- Windows: Win32 (`CreateProcess`, `WaitForSingleObject`, `TerminateProcess`)

## Step 05 — Display Abstraction

Cross-platform display discovery and information retrieval.

### Public API

```c
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

ozayn_result_t ozayn_display_init(void);
void           ozayn_display_shutdown(void);
int            ozayn_display_is_available(void);
uint32_t       ozayn_display_count(void);
ozayn_result_t ozayn_display_get(uint32_t index, OzaynDisplayInfo *info);
ozayn_result_t ozayn_display_get_primary(OzaynDisplayInfo *info);
ozayn_result_t ozayn_display_refresh(void);
```

### Safety

- All functions handle NULL parameters safely
- `ozayn_display_shutdown()` is idempotent and safe to call multiple times
- Works in headless environments (returns count=0, available=0)
- No screen capture, no display modification
- Informational only — no side effects

### Platform Implementations

- Linux: xrandr parsing with fallback to single display
- macOS: system_profiler parsing with fallback to built-in display
- Windows: Win32 (`EnumDisplayDevices`, `EnumDisplaySettings`)

### Headless Behavior

- Display subsystem gracefully reports unavailable when no displays exist
- Display count returns 0 in headless environments
- No crashes or errors in headless mode

## Step 06 — Window Management

Cross-platform window discovery, information retrieval, and manipulation.

### Public API

```c
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

ozayn_result_t ozayn_window_init(void);
void           ozayn_window_shutdown(void);
int            ozayn_window_is_available(void);
uint32_t       ozayn_window_get_count(void);
ozayn_result_t ozayn_window_get_info(uint32_t index, OzaynWindowInfo *info);
ozayn_result_t ozayn_window_get_active(OzaynWindowInfo *info);
ozayn_result_t ozayn_window_move(unsigned long long window_id, int32_t x, int32_t y);
ozayn_result_t ozayn_window_resize(unsigned long long window_id, uint32_t width, uint32_t height);
ozayn_result_t ozayn_window_minimize(unsigned long long window_id);
ozayn_result_t ozayn_window_maximize(unsigned long long window_id);
ozayn_result_t ozayn_window_restore(unsigned long long window_id);
ozayn_result_t ozayn_window_close(unsigned long long window_id);
ozayn_result_t ozayn_window_refresh(void);
```

### Safety

- All functions handle NULL parameters safely
- `ozayn_window_shutdown()` is idempotent and safe to call multiple times
- Invalid window IDs are rejected without calling OS APIs
- Zero width/height rejected for resize
- Works in headless environments (returns available=0, count=0)
- No hidden surveillance, no keylogging, no stealth monitoring

### Platform Implementations

- Linux: xdotool + xprop for discovery and manipulation, wmctrl fallback for maximize/restore
- macOS: Stub (requires Objective-C runtime — future implementation)
- Windows: Stub (requires Win32 EnumWindows — future implementation)

### Linux Limitations

- Requires `xdotool` to be installed
- Requires X11 display (or `DISPLAY`/`WAYLAND_DISPLAY` environment variable)
- Maximize uses `super+Up` key combination via xdotool
- Restore uses wmctrl to remove maximized state
- Headless environments report unavailable

### Headless Behavior

- Window subsystem gracefully reports unavailable when no display server is present
- Window count returns 0 in headless environments
- No crashes or errors in headless mode

## Step 07 — Input & Mouse Abstraction

Cross-platform input abstraction for mouse/pointer state and control.

### Coordinate Convention

```
(0,0) = top-left of primary display
X increases rightward
Y increases downward
Negative coordinates possible with multi-display setups
```

Coordinates match Step 05 Display Abstraction convention.

### Public API

```c
/* Input Lifecycle */
ozayn_result_t ozayn_input_init(void);
void           ozayn_input_shutdown(void);
int            ozayn_input_is_available(void);

/* Device Info */
ozayn_result_t ozayn_input_device_info(OzaynInputDeviceInfo *info);

/* Mouse Position */
ozayn_result_t ozayn_input_get_mouse_position(int32_t *x, int32_t *y);
ozayn_result_t ozayn_input_get_mouse_state(OzaynMouseState *state);
ozayn_result_t ozayn_input_move_mouse(int32_t x, int32_t y);

/* Mouse Buttons */
ozayn_result_t ozayn_input_mouse_left_down(void);
ozayn_result_t ozayn_input_mouse_left_up(void);
ozayn_result_t ozayn_input_mouse_right_down(void);
ozayn_result_t ozayn_input_mouse_right_up(void);
ozayn_result_t ozayn_input_mouse_middle_down(void);
ozayn_result_t ozayn_input_mouse_middle_up(void);
```

### Data Structures

```c
typedef struct {
    int32_t  x;            /* pointer X position */
    int32_t  y;            /* pointer Y position */
    int      left_button;  /* 1 if pressed, 0 otherwise */
    int      middle_button;
    int      right_button;
    int      available;    /* 1 if mouse input is available */
} OzaynMouseState;

typedef struct {
    int has_keyboard;
    int has_mouse;
    int has_touch;
    int has_microphone;
    int has_camera;
} OzaynInputDeviceInfo;
```

### Safety

- All functions handle NULL parameters safely
- `ozayn_input_shutdown()` is idempotent and safe to call multiple times
- Works in headless environments (returns available=0)
- No keylogging, no hidden input recording, no stealth surveillance
- No credential harvesting, no persistence, no privilege escalation
- Button operations do not simulate clicks on arbitrary applications

### Platform Implementations

- Linux: X11 native APIs (XQueryPointer, XWarpPointer, XTestFakeButtonEvent)
- macOS: Core Graphics APIs (CGEventCreate, CGEventPost) with accessibility permission check
- Windows: Win32 APIs (GetCursorPos, SetCursorPos, SendInput)

### Linux Limitations

- Requires X11 display server (or `DISPLAY`/`WAYLAND_DISPLAY` environment variable)
- Requires `libX11` and `libXtst` libraries
- Headless environments report unavailable
- Wayland: Limited support — coordinate system may differ

### macOS Permissions

- Accessibility permissions required for mouse movement/control
- If permission is denied, subsystem reports unavailable
- Use `AXIsProcessTrusted()` to check permission status

### Windows Behavior

- Mouse input always available on Windows
- Uses `GetCursorPos`/`SetCursorPos` for position
- Uses `SendInput` for button events
- Uses `GetAsyncKeyState` for button state queries

### Headless Behavior

- Input subsystem gracefully reports unavailable when no display/input session exists
- No crashes or errors in headless mode
- Button operations return OZAYN_ERR when unavailable

### Testing

```bash
make test
```

Tests verify:
- Initialization and shutdown (basic + idempotent)
- Availability detection (before/after init)
- Device info query
- Mouse position retrieval
- Mouse state retrieval (position + button states)
- Mouse movement (safe test coordinates with position restore)
- Button API availability (no actual clicks in tests)
- NULL parameter handling
- Pre-init error handling
- Legacy API compatibility

## Step 08 — Keyboard & Basic Input Event Abstraction

Cross-platform keyboard state queries and input event representation.

### Supported Keys

| Category | Keys |
|----------|------|
| Letters | A-Z |
| Digits | 0-9 |
| Control | Escape, Enter, Tab, Space, Backspace |
| Modifiers | Shift, Ctrl, Alt |
| Navigation | Up, Down, Left, Right, Home, End, PageUp, PageDown, Insert, Delete |
| Function | F1-F12 |

### Public API

```c
/* Keyboard Lifecycle */
ozayn_result_t ozayn_keyboard_init(void);
void           ozayn_keyboard_shutdown(void);
int            ozayn_keyboard_is_available(void);

/* Key State — returns 1 if pressed, 0 if not, -1 if unsupported */
int            ozayn_keyboard_is_key_down(OzaynKey key);

/* Event Polling (non-blocking) */
ozayn_result_t ozayn_keyboard_poll_event(OzaynInputEvent *event);

/* Key Name */
const char    *ozayn_key_name(OzaynKey key);
```

### Data Structures

```c
typedef enum {
    OZAYN_KEY_UNKNOWN = 0,
    OZAYN_KEY_A, /* ... OZAYN_KEY_Z */
    OZAYN_KEY_0, /* ... OZAYN_KEY_9 */
    OZAYN_KEY_ESCAPE, OZAYN_KEY_ENTER, OZAYN_KEY_TAB, OZAYN_KEY_SPACE, OZAYN_KEY_BACKSPACE,
    OZAYN_KEY_SHIFT, OZAYN_KEY_CTRL, OZAYN_KEY_ALT,
    OZAYN_KEY_UP, OZAYN_KEY_DOWN, OZAYN_KEY_LEFT, OZAYN_KEY_RIGHT,
    OZAYN_KEY_HOME, OZAYN_KEY_END, OZAYN_KEY_PAGE_UP, OZAYN_KEY_PAGE_DOWN,
    OZAYN_KEY_INSERT, OZAYN_KEY_DELETE,
    OZAYN_KEY_F1, /* ... OZAYN_KEY_F12 */
    OZAYN_KEY_COUNT
} OzaynKey;

typedef enum {
    OZAYN_INPUT_EVENT_NONE = 0,
    OZAYN_INPUT_EVENT_KEY_DOWN,
    OZAYN_INPUT_EVENT_KEY_UP
} OzaynInputEventType;

typedef struct {
    OzaynInputEventType type;
    OzaynKey key;
    unsigned int modifiers;
} OzaynInputEvent;

/* Modifier flags (bitmask) */
#define OZAYN_MOD_SHIFT    (1 << 0)
#define OZAYN_MOD_CTRL     (1 << 1)
#define OZAYN_MOD_ALT      (1 << 2)
```

### Safety

- All functions handle NULL parameters safely
- `ozayn_keyboard_shutdown()` is idempotent and safe to call multiple times
- Works in headless environments (returns available=0, key state -1)
- No keylogging, no hidden input recording, no stealth surveillance
- No credential harvesting, no persistence, no privilege escalation
- No background thread recording keyboard events
- Event polling is non-blocking — does not freeze runtime
- Keyboard input is never written to disk

### Platform Implementations

- Linux: X11 XQueryKeymap for key state, XLookupString for event polling
- macOS: Stub (requires Core Graphics event tap + accessibility permissions)
- Windows: Stub (requires GetAsyncKeyState mapping)

### Linux Limitations

- Requires X11 display server (or `DISPLAY`/`WAYLAND_DISPLAY` environment variable)
- Requires `libX11` and `libXtst` libraries
- Key state queries require X11 connection
- Event polling requires pending X11 events (non-blocking)
- Headless environments report unavailable

### macOS Permissions

- Accessibility permissions required for key state queries
- If permission is unavailable, subsystem reports unavailable
- Full implementation requires CGEventTap (future step)

### Windows Behavior

- Keyboard subsystem always available on Windows
- Key state queries not yet implemented (returns -1)
- Event polling not yet implemented (returns error)

### Headless Behavior

- Keyboard subsystem gracefully reports unavailable when no display/input session exists
- No crashes or errors in headless mode
- Key state queries return -1 (unsupported)

### Testing

```bash
make test
```

Tests verify:
- Initialization and shutdown (basic + idempotent)
- Availability detection (before/after init)
- Key state queries (before init, unknown key, letters, digits, function keys, modifier keys)
- Key name mapping (known keys, unknown key, never NULL)
- Event polling (null, before init, no event available, field reset)
- Modifier constants
- Key enumeration range

## Step 09 — Camera Device Abstraction

Cross-platform camera enumeration, configuration, and frame capture.

### Camera Lifecycle

```
ozayn_camera_init()
        ↓
enumerate devices
        ↓
ozayn_camera_open(index)
        ↓
configure camera
        ↓
ozayn_camera_start()
        ↓
capture frames
        ↓
ozayn_camera_stop()
        ↓
ozayn_camera_close()
        ↓
ozayn_camera_shutdown()
```

### Public API

```c
/* Camera Lifecycle */
ozayn_result_t ozayn_camera_init(void);
void           ozayn_camera_shutdown(void);
int            ozayn_camera_is_available(void);

/* Device Enumeration */
unsigned int   ozayn_camera_get_count(void);
ozayn_result_t ozayn_camera_get_info(unsigned int index, OzaynCameraInfo *info);

/* Device Control */
ozayn_result_t ozayn_camera_open(unsigned int index);
ozayn_result_t ozayn_camera_close(void);

/* Capture Control */
ozayn_result_t ozayn_camera_start(void);
ozayn_result_t ozayn_camera_stop(void);
ozayn_result_t ozayn_camera_capture(OzaynCameraFrame *frame);

/* Configuration */
ozayn_result_t ozayn_camera_set_resolution(unsigned int width, unsigned int height);
ozayn_result_t ozayn_camera_set_fps(unsigned int fps);

/* Frame Management */
void           ozayn_camera_frame_release(OzaynCameraFrame *frame);
```

### Data Structures

```c
typedef struct {
    unsigned int index;
    char id[256];
    char name[256];
    int available;
    unsigned int width;
    unsigned int height;
    unsigned int fps;
} OzaynCameraInfo;

typedef struct {
    unsigned int width;
    unsigned int height;
    unsigned int stride;
    OzaynPixelFormat format;
    unsigned char *data;
    size_t data_size;
} OzaynCameraFrame;

typedef enum {
    OZAYN_PIXEL_FORMAT_UNKNOWN = 0,
    OZAYN_PIXEL_FORMAT_RGB24,
    OZAYN_PIXEL_FORMAT_BGR24,
    OZAYN_PIXEL_FORMAT_GRAY8,
    OZAYN_PIXEL_FORMAT_YUYV,
    OZAYN_PIXEL_FORMAT_MJPEG
} OzaynPixelFormat;
```

### Safety

- All functions handle NULL parameters safely
- `ozayn_camera_shutdown()` is idempotent and safe to call multiple times
- `ozayn_camera_frame_release()` is safe to call with NULL or already released frames
- Invalid lifecycle transitions are rejected (capture before open, start twice, etc.)
- Works in headless/no-camera environments (count=0, available=0)
- No hidden camera activation, no covert recording
- No frame data written to disk or transmitted over network
- Camera only accessed through explicit OZAYN operations

### Platform Implementations

- Linux: V4L2 (Video4Linux2) for device enumeration, format queries, mmap buffer capture
- macOS: Stub (requires AVFoundation framework + camera privacy permissions)
- Windows: Stub (requires Media Foundation API)

### Linux Implementation

- Enumerates `/dev/video*` devices via V4L2
- Uses `VIDIOC_QUERYCAP` to verify capture capability
- Uses `VIDIOC_G_FMT` to query default resolution
- Uses `VIDIOC_G_PARM` to query frame rate
- MMAP buffer allocation for zero-copy capture
- Non-blocking device open

### Linux Limitations

- Requires V4L2 kernel support
- Requires read access to `/dev/video*` devices
- Headless systems report unavailable
- Some devices may not support all pixel formats

### macOS Permissions

- Camera privacy permissions required (NSCameraUsageDescription)
- If permission is denied, subsystem reports unavailable
- Full implementation requires AVFoundation (future step)

### Windows Behavior

- Camera subsystem stub returns unavailable
- Full implementation requires Media Foundation (future step)

### Headless Behavior

- Camera subsystem gracefully reports unavailable when no camera devices exist
- Camera count returns 0 in headless environments
- No crashes or errors in headless mode

### Testing

```bash
make test
```

Tests verify:
- Initialization and shutdown (basic + idempotent)
- Availability detection (before/after init)
- Device enumeration (count before/after init, get info valid/invalid/null/before init)
- Lifecycle transitions (open invalid, start before open, stop before start, capture before open/null/before init, close before open/before init)
- Configuration safety (set resolution/fps before init, zero values)
- Frame release (null, clears fields)
- Pixel format constants

## Step 10 — Microphone Device Abstraction

Cross-platform microphone enumeration, configuration, and PCM audio capture.

### Microphone Lifecycle

```
ozayn_microphone_init()
        ↓
enumerate devices
        ↓
ozayn_microphone_open(index)
        ↓
ozayn_microphone_start()
        ↓
capture audio
        ↓
ozayn_microphone_stop()
        ↓
ozayn_microphone_close()
        ↓
ozayn_microphone_shutdown()
```

### Public API

```c
/* Microphone Lifecycle */
ozayn_result_t ozayn_microphone_init(void);
void           ozayn_microphone_shutdown(void);
int            ozayn_microphone_is_available(void);

/* Device Enumeration */
unsigned int   ozayn_microphone_get_count(void);
ozayn_result_t ozayn_microphone_get_info(unsigned int index, OzaynMicrophoneInfo *info);

/* Device Control */
ozayn_result_t ozayn_microphone_open(unsigned int index);
ozayn_result_t ozayn_microphone_close(void);

/* Capture Control */
ozayn_result_t ozayn_microphone_start(void);
ozayn_result_t ozayn_microphone_stop(void);
ozayn_result_t ozayn_microphone_capture(OzaynAudioBuffer *buffer);

/* Buffer Management */
void           ozayn_microphone_buffer_release(OzaynAudioBuffer *buffer);
```

### Data Structures

```c
typedef struct {
    int index;
    char id[256];
    char name[256];
    int available;
    int channels;
    int sample_rate;
} OzaynMicrophoneInfo;

typedef struct {
    unsigned int sample_rate;
    unsigned int channels;
    OzaynAudioFormat format;
    size_t frame_count;
    unsigned char *data;
    size_t data_size;
} OzaynAudioBuffer;

typedef enum {
    OZAYN_AUDIO_FORMAT_UNKNOWN = 0,
    OZAYN_AUDIO_FORMAT_S16,
    OZAYN_AUDIO_FORMAT_F32
} OzaynAudioFormat;
```

### Safety

- All functions handle NULL parameters safely
- `ozayn_microphone_shutdown()` is idempotent and safe to call multiple times
- `ozayn_microphone_buffer_release()` is safe to call with NULL or already released buffers
- Invalid lifecycle transitions are rejected (capture before open, start twice, etc.)
- Works in headless/no-microphone environments (count=0, available=0)
- No hidden microphone activation, no covert recording
- Audio data never written to disk or transmitted over network
- Microphone only accessed through explicit OZAYN operations

### Platform Implementations

- Linux: ALSA for device enumeration and PCM capture
- macOS: Stub (requires Core Audio / AVFoundation + microphone privacy permissions)
- Windows: Stub (requires WASAPI)

### Linux Implementation

- Enumerates capture devices via `snd_device_name_hint`
- Opens devices with `snd_pcm_open` in non-blocking mode
- Configures S16_LE format, channels, and sample rate
- Uses `snd_pcm_readi` for interleaved PCM capture
- Handles overrun recovery via `snd_pcm_recover`

### Linux Limitations

- Requires ALSA development libraries (`alsa-lib-dev`)
- Requires read access to ALSA capture devices
- Headless systems may report no microphones
- Some devices may not support S16 format

### macOS Permissions

- Microphone privacy permissions required (NSMicrophoneUsageDescription)
- If permission is denied, subsystem reports unavailable
- Full implementation requires Core Audio (future step)

### Windows Behavior

- Microphone subsystem stub returns unavailable
- Full implementation requires WASAPI (future step)

### Headless Behavior

- Microphone subsystem gracefully reports unavailable when no devices exist
- Microphone count returns 0 in headless environments
- No crashes or errors in headless mode

### Testing

```bash
make test
```

Tests verify:
- Initialization and shutdown (basic + idempotent)
- Availability detection (before/after init)
- Device enumeration (count before/after init, get info valid/invalid/null/before init)
- Lifecycle transitions (open invalid index, open before init, start before open, stop before start, capture before open/null/before init, close before open/before init)
- Buffer release (null, clears fields, empty buffer)
- Audio format constants

## Directory Structure

```
02_PLATFORM/
├── common/           # Platform-independent API (include/platform.h)
├── linux/            # Linux-specific implementations
├── windows/          # Windows-specific implementations
├── macos/            # macOS-specific implementations
├── tests/            # Platform tests
└── README.md         # This file
```

Platform implementations live in `src/platform/{linux,macos,windows}/` and are compiled based on the host OS.

## Testing

```bash
make test
```

### Step 01 Tests (8 tests)
- Platform detection init/shutdown
- Platform name matching
- Idempotent init/shutdown cycles

### Step 02 Tests (10 tests)
- System information API
- OS, architecture, hostname, username
- CPU count and memory

### Step 03 Tests (40 tests)
- Directory creation, detection, removal
- File write, read, existence, size
- File append (new and existing)
- Binary data write/read
- File copy and move
- NULL/empty/invalid path handling

### Step 04 Tests (26 tests)
- Process start, PID, running flag
- Process is_running (running and terminated)
- Process info (running and exited states)
- Process terminate and wait (exits + timeout)
- Process close (cleanup + idempotent)
- Error handling: NULL, empty, invalid exec, zero pid
- Multiple concurrent processes

### Step 05 Tests (26 tests)
- Display init/shutdown (basic + idempotent)
- Display availability (before/after init)
- Display count (before/after init, matches availability)
- Display get by index (valid, invalid, before init)
- Primary display (get, null, before init)
- Display info fields (name, dimensions, index, primary flag)
- Display refresh (basic + before init)
- Multiple displays query
- Legacy display API compatibility

### Step 06 Tests (26 tests)
- Window init/shutdown (basic + idempotent)
- Window availability (before/after init)
- Window count (before/after init)
- Window get info (by index, null, invalid index, before init)
- Active window (returns result, null, before init)
- Window manipulation safety (move/resize/minimize/maximize/restore/close with invalid IDs)
- Window resize zero dimensions
- Window refresh (basic + before init)
- Window shutdown (basic + idempotent + before init)
- Window enumeration (query all windows)

### Step 07 Tests (23 tests)
- Input init/shutdown (basic + idempotent)
- Input availability (before/after init)
- Input device info (after init, null, before init)
- Mouse position (returns result, null, before init)
- Mouse state (returns result, null, before init, button fields)
- Mouse movement (returns result, before init)
- Mouse buttons (before init, after init)
- Input shutdown (basic + idempotent + before init)
- Legacy API (returns result, null)

### Step 08 Tests (23 tests)
- Keyboard init/shutdown (basic + idempotent)
- Keyboard availability (before/after init)
- Key state (before init, unknown key, valid key, letters, digits, function keys, modifier keys)
- Key names (known keys, unknown, never NULL)
- Event polling (null, before init, no event, field reset)
- Keyboard shutdown (basic + idempotent + before init)
- Modifier constants
- Key enumeration range

### Step 09 Tests (29 tests)
- Camera init/shutdown (basic + idempotent)
- Camera availability (before/after init)
- Camera count (before/after init)
- Camera get info (valid index, invalid index, null, before init)
- Lifecycle transitions (open invalid index, open before init, start before open, stop before start, capture before open, capture null, capture before init, close before open, close before init)
- Configuration (set resolution/fps before init, zero values)
- Frame release (null, clears fields)
- Camera shutdown (basic + idempotent + before init)
- Pixel format constants

### Step 10 Tests (26 tests)
- Microphone init/shutdown (basic + idempotent)
- Microphone availability (before/after init)
- Microphone count (before/after init)
- Microphone get info (valid index, invalid index, null, before init)
- Lifecycle transitions (open invalid index, open before init, start before open, stop before start, capture before open, capture null, capture before init, close before open, close before init)
- Buffer release (null, clears fields, empty buffer)
- Microphone shutdown (basic + idempotent + before init)
- Audio format constants

## Step 11 — Audio Output / Speaker Abstraction

Cross-platform audio output enumeration, configuration, and PCM audio playback.

### Audio Output Lifecycle

```
ozayn_audio_output_init()
        ↓
enumerate devices
        ↓
ozayn_audio_output_open(index)
        ↓
ozayn_audio_output_start()
        ↓
write audio
        ↓
ozayn_audio_output_stop()
        ↓
ozayn_audio_output_close()
        ↓
ozayn_audio_output_shutdown()
```

### Public API

```c
/* Audio Output Lifecycle */
ozayn_result_t ozayn_audio_output_init(void);
void           ozayn_audio_output_shutdown(void);

/* Device Queries */
int            ozayn_audio_output_is_available(void);
unsigned int   ozayn_audio_output_get_count(void);
ozayn_result_t ozayn_audio_output_get_info(unsigned int index, OzaynAudioOutputInfo *info);

/* Device Control */
ozayn_result_t ozayn_audio_output_open(unsigned int index);
ozayn_result_t ozayn_audio_output_close(void);

/* Streaming Control */
ozayn_result_t ozayn_audio_output_start(void);
ozayn_result_t ozayn_audio_output_write(const OzaynAudioOutputBuffer *buffer);
ozayn_result_t ozayn_audio_output_stop(void);
```

### Data Structures

```c
typedef struct {
    int index;
    char id[256];
    char name[256];
    int available;
    int channels;
    int sample_rate;
} OzaynAudioOutputInfo;

typedef struct {
    unsigned int sample_rate;
    unsigned int channels;
    OzaynAudioFormat format;
    size_t frame_count;
    const unsigned char *data;
    size_t data_size;
} OzaynAudioOutputBuffer;
```

### Safety

- All functions handle NULL parameters safely
- `ozayn_audio_output_shutdown()` is idempotent and safe to call multiple times
- Invalid lifecycle transitions are rejected (write before open, start twice, etc.)
- Works in headless/no-audio environments (count=0, available=0)
- No hidden audio playback, no persistent audio, no network streaming
- Only explicitly requested audio output is performed

### Platform Implementations

- Linux: ALSA for device enumeration and PCM output
- macOS: Stub (requires Core Audio / AVFoundation)
- Windows: Stub (requires WASAPI)

### Linux Implementation

- Enumerates playback devices via `snd_device_name_hint`
- Opens devices with `snd_pcm_open` in non-blocking mode
- Configures S16_LE format, channels, and sample rate
- Uses `snd_pcm_writei` for interleaved PCM output
- Handles underrun recovery via `snd_pcm_recover`

### Testing

```bash
make test
```

Tests verify:
- Initialization and shutdown (basic + idempotent)
- Availability detection (before/after init)
- Device enumeration (count before/after init, get info valid/invalid/null/before init)
- Lifecycle transitions (open invalid index, open before init, start before open, stop before start, write before open/null/before init, close before open/before init)
- Buffer validation (empty, no data, unknown format, insufficient data)
- Audio format constants

## Step 12 — Network Information & Connectivity Abstraction

Cross-platform network interface enumeration, address discovery, and basic connectivity checking.

### Network Lifecycle

```
ozayn_network_init()
        ↓
enumerate interfaces
        ↓
query interfaces
        ↓
ozayn_network_shutdown()
```

### Public API

```c
/* Network Lifecycle */
ozayn_result_t ozayn_network_init(void);
void           ozayn_network_shutdown(void);

/* Network Queries */
int            ozayn_network_is_available(void);
unsigned int   ozayn_network_get_interface_count(void);
ozayn_result_t ozayn_network_get_interface_info(unsigned int index, OzaynNetworkInterfaceInfo *info);
int            ozayn_network_get_default_interface(void);

/* Connectivity Check */
OzaynConnectivityState ozayn_network_is_connected(void);
```

### Data Structures

```c
typedef struct {
    int index;
    char name[64];
    char ipv4[64];
    char ipv6[128];
    char mac[32];
    int is_up;
    int is_loopback;
} OzaynNetworkInterfaceInfo;

typedef enum {
    OZAYN_CONNECTIVITY_UNKNOWN = 0,
    OZAYN_CONNECTIVITY_DISCONNECTED,
    OZAYN_CONNECTIVITY_CONNECTED
} OzaynConnectivityState;
```

### Safety

- All functions handle NULL parameters safely
- `ozayn_network_shutdown()` is idempotent and safe to call multiple times
- Invalid interface indexes are rejected
- Works in headless/no-network environments (count=0, available=0)
- No packet sniffing, no port scanning, no traffic monitoring
- No network configuration modification

### Platform Implementations

- Linux: `getifaddrs` + `ioctl` for interface enumeration and MAC discovery
- macOS: Stub (requires SystemConfiguration / IOKit)
- Windows: Stub (requires IP Helper API)

### Linux Implementation

- Enumerates interfaces via `getifaddrs`
- Extracts IPv4/IPv6 addresses via `inet_ntop`
- Detects UP/loopback flags via `ifa_flags`
- Gets MAC address via `AF_PACKET` / `sockaddr_ll`
- Default interface: first non-loopback UP interface with IPv4

### Connectivity Detection

- Checks for any non-loopback UP interface with an IPv4 or IPv6 address
- Returns CONNECTED if found, DISCONNECTED if interfaces exist but none connected
- Returns UNKNOWN if not initialized or no interfaces exist

### Testing

```bash
make test
```

Tests verify:
- Initialization and shutdown (basic + idempotent)
- Availability detection (before/after init)
- Interface enumeration (count before/after init, get info valid/invalid/null/before init)
- IPv4/IPv6 format validation
- Loopback detection
- Interface state (UP/loopback flags)
- Connectivity status (UNKNOWN/DISCONNECTED/CONNECTED)
- Default interface detection
- MAC address format
- Connectivity state constants

## Step 13 — Power & Battery Information Abstraction

Cross-platform power source information and battery status. Read-only — no power management.

### Power Lifecycle

```
ozayn_power_init()
        ↓
query power info
        ↓
ozayn_power_shutdown()
```

### Public API

```c
/* Power Lifecycle */
ozayn_result_t ozayn_power_init(void);
void           ozayn_power_shutdown(void);

/* Power Queries */
int            ozayn_power_is_available(void);
ozayn_result_t ozayn_power_get_info(OzaynPowerInfo *info);
int            ozayn_power_has_battery(void);
int            ozayn_power_get_battery_percent(void);
int            ozayn_power_is_charging(void);
int            ozayn_power_is_plugged_in(void);
```

### Data Structures

```c
typedef struct {
    int available;
    int has_battery;
    int battery_percent;      /* 0–100, or -1 if unknown */
    int charging;
    int plugged_in;
    long long battery_remaining_seconds;  /* -1 if unknown */
    long long battery_full_seconds;       /* -1 if unknown */
} OzaynPowerInfo;

typedef enum {
    OZAYN_POWER_UNKNOWN = 0,
    OZAYN_POWER_BATTERY,
    OZAYN_POWER_CHARGING,
    OZAYN_POWER_AC_POWER,
    OZAYN_POWER_NO_BATTERY
} OzaynPowerState;
```

### Safety

- All functions handle NULL parameters safely
- `ozayn_power_shutdown()` is idempotent and safe to call multiple times
- Battery percentage validated to 0–100 range
- Unknown values use -1 sentinel
- Desktop systems without batteries handled gracefully
- No power modification, no shutdown, no sleep control

### Platform Implementations

- Linux: sysfs (`/sys/class/power_supply/`) for battery enumeration and status
- macOS: Stub (requires IOKit / Core Foundation)
- Windows: Stub (requires GetSystemPowerStatus)

### Linux Implementation

- Scans `/sys/class/power_supply/` directory
- Identifies Battery type devices
- Reads `capacity` for percentage
- Reads `status` for charging state (Charging/Discharging/Full)
- Detects Mains/USB adapters for AC power

### Desktop/Laptop Handling

- Desktop systems: `has_battery=0`, `battery_percent=-1`, `charging=0`
- Laptop on battery: `has_battery=1`, `battery_percent=0-100`, `charging=0`, `plugged_in=0`
- Laptop charging: `has_battery=1`, `battery_percent=0-100`, `charging=1`, `plugged_in=1`
- Laptop full: `has_battery=1`, `battery_percent=100`, `charging=1`, `plugged_in=1`

### Testing

```bash
make test
```

Tests verify:
- Initialization and shutdown (basic + idempotent)
- Availability detection (before/after init)
- Power information retrieval (get info, null, before init)
- Battery presence detection
- Battery percentage range (0–100 or -1)
- Charging and plugged-in state
- Power state constants
- Desktop/no-battery handling

## Step 14 — Notification System Abstraction

Cross-platform native desktop notification display using the operating system's native notification mechanism.

### Notification Lifecycle

```
ozayn_notification_init()
        ↓
check availability
        ↓
ozayn_notification_send()
        ↓
ozayn_notification_shutdown()
```

### Public API

```c
/* Notification Lifecycle */
ozayn_result_t ozayn_notification_init(void);
void           ozayn_notification_shutdown(void);

/* Notification Queries */
int            ozayn_notification_is_available(void);

/* Notification Send */
ozayn_result_t ozayn_notification_send(const OzaynNotification *notification);
```

### Data Structures

```c
typedef struct {
    char title[256];
    char message[1024];
    char application_name[256];
} OzaynNotification;
```

### Safety

- All functions handle NULL parameters safely
- `ozayn_notification_shutdown()` is idempotent and safe to call multiple times
- Empty title is rejected
- Empty message is allowed (some notifications show title only)
- Oversized strings handled gracefully (truncation)
- No notification history, no GUI windows, no remote notifications
- No command injection — never uses `system()` with user content

### Platform Implementations

- Linux: `notify-send` command-line tool (standard on most desktop environments)
- macOS: Stub (requires UserNotifications framework)
- Windows: Stub (requires Toast Notification API)

### Linux Implementation

- Checks for `notify-send` availability via `which`
- Sends notifications via `notify-send "title" "message"`
- Works across GNOME, KDE, XFCE, and other desktop environments
- Headless systems: notification unavailable (graceful)

### Headless Behavior

- Notification subsystem reports unavailable on headless systems
- `send()` returns error when unavailable
- No crashes or errors in headless mode

### Security

- Title and message treated as ordinary text
- No shell command construction from notification content
- No `system()` calls with user-provided strings
- No credential exposure in notifications

### Testing

```bash
make test
```

Tests verify:
- Initialization and shutdown (basic + idempotent)
- Availability detection (before/after init)
- Valid notification send (accepts failure on headless)
- Empty title rejection
- Empty message handling
- NULL notification rejection
- Oversized title/message handling
- Send after shutdown rejection
- Shutdown before init

## Step 15 — Clipboard Abstraction

Cross-platform plain-text clipboard read/write. No clipboard monitoring, no history, no remote access.

### Clipboard Lifecycle

```
ozayn_clipboard_init()
        ↓
check availability
        ↓
read/write clipboard
        ↓
ozayn_clipboard_shutdown()
```

### Public API

```c
/* Clipboard Lifecycle */
ozayn_result_t ozayn_clipboard_init(void);
void           ozayn_clipboard_shutdown(void);

/* Clipboard Queries */
int            ozayn_clipboard_is_available(void);
int            ozayn_clipboard_has_text(void);

/* Clipboard Read */
ozayn_result_t ozayn_clipboard_get_text(char *buffer, size_t buffer_size, size_t *required_size);

/* Clipboard Write */
ozayn_result_t ozayn_clipboard_set_text(const char *text);

/* Clipboard Clear */
ozayn_result_t ozayn_clipboard_clear(void);
```

### Safety

- All functions handle NULL parameters safely
- `ozayn_clipboard_shutdown()` is idempotent and safe to call multiple times
- Empty clipboard content handled gracefully
- Buffer overflow prevention: never writes beyond `buffer_size`
- NUL-termination guaranteed when buffer is large enough
- Required size querying supported (pass NULL buffer)
- UTF-8 text supported
- No clipboard monitoring, no history, no remote access
- No command execution from clipboard content

### Platform Implementations

- Linux: X11 XSelection mechanism (UTF8_STRING target)
- macOS: Stub (requires Pasteboard framework)
- Windows: Stub (requires Win32 Clipboard API)

### Linux Implementation

- Uses X11 `XSetSelectionOwner` / `XGetWindowProperty` for clipboard access
- Supports UTF8_STRING text format
- Creates a hidden window for clipboard operations
- Checks for X11 availability (DISPLAY or WAYLAND_DISPLAY)
- No external tools (xclip, xsel, wl-copy) — native X11 only

### Headless Behavior

- Clipboard subsystem reports unavailable on headless systems
- All operations return error when unavailable
- No crashes or errors in headless mode

### Security

- Clipboard data never written to logs, database, or network
- No clipboard monitoring or surveillance
- No automatic command execution
- No password or credential harvesting
- Plain text only — no images, files, or rich text

### Testing

```bash
make test
```

Tests verify:
- Initialization and shutdown (basic + idempotent)
- Availability detection (before/after init)
- Has text detection
- Set/get basic text
- Set/get Unicode/UTF-8 text
- Set/get empty string
- NULL buffer handling
- Zero buffer size
- Small buffer truncation
- Required size reporting
- Clear operation
- Operations after shutdown
- NULL text rejection
- Shutdown before init

## Step 16 — Environment & User Session Abstraction

Cross-platform environment variable access and user-session information. Read-only — no modification of environment or system state.

### Environment Lifecycle

```
ozayn_environment_init()
        ↓
query environment
        ↓
ozayn_environment_shutdown()
```

### Public API

```c
/* Environment Lifecycle */
ozayn_result_t ozayn_environment_init(void);
void           ozayn_environment_shutdown(void);

/* Environment Queries */
int            ozayn_environment_is_available(void);

/* Environment Variable Access */
ozayn_result_t ozayn_environment_get_variable(const char *name,
                                               char *buffer,
                                               size_t buffer_size,
                                               size_t *required_size);

/* Directory Queries */
ozayn_result_t ozayn_environment_get_home_directory(char *buffer, size_t buffer_size);
ozayn_result_t ozayn_environment_get_temp_directory(char *buffer, size_t buffer_size);
ozayn_result_t ozayn_environment_get_current_directory(char *buffer, size_t buffer_size);

/* User/Host Information */
ozayn_result_t ozayn_environment_get_username(char *buffer, size_t buffer_size);
ozayn_result_t ozayn_environment_get_hostname(char *buffer, size_t buffer_size);
```

### Safety

- All functions handle NULL parameters safely
- `ozayn_environment_shutdown()` is idempotent and safe to call multiple times
- Missing environment variables return empty string, not error
- Empty names rejected
- Buffer overflow prevention: never writes beyond `buffer_size`
- NUL-termination guaranteed when buffer is large enough
- Required size querying supported (pass NULL buffer)
- No environment modification, no credential extraction
- No environment variables logged or dumped

### Platform Implementations

- Linux: POSIX APIs (`getenv`, `getpwuid`, `gethostname`, `getcwd`)
- macOS: POSIX APIs with NSFileManager fallbacks
- Windows: `getenv` with Win32 fallbacks (`USERPROFILE`, `COMPUTERNAME`)

### Linux Implementation

- `getenv()` for environment variables
- `getpwuid(getuid())` for home directory and username fallback
- `gethostname()` for hostname
- `getcwd()` for current working directory
- `TMPDIR` / `TMP` / `/tmp` for temp directory

### Directory Behavior

- Home: `$HOME` → `/home/user`
- Temp: `$TMPDIR` → `/tmp`
- Current: `getcwd()` → actual working directory
- Username: `$USER` → `getpwuid` fallback
- Hostname: `gethostname()` → local machine name

### Security

- No environment variable logging
- No credential or secret extraction
- No password retrieval
- No token extraction
- No network discovery
- Read-only access to environment

### Testing

```bash
make test
```

Tests verify:
- Initialization and shutdown (basic + idempotent)
- Availability detection (before/after init)
- Existing variable retrieval (PATH)
- Missing variable handling
- Empty/null name rejection
- Required size reporting
- Small buffer truncation
- Home/temp/current directory retrieval
- Username and hostname retrieval
- NULL parameter handling
- Small buffer handling for directories
- Shutdown before init

## Step 17 — System Time & Date Abstraction

Cross-platform system time and date information. Read-only — no clock modification, no timezone changes.

### Time Lifecycle

```
ozayn_time_init()
        ↓
query time
        ↓
ozayn_time_shutdown()
```

### Public API

```c
/* Time Lifecycle */
ozayn_result_t ozayn_time_init(void);
void           ozayn_time_shutdown(void);

/* Time Queries */
int            ozayn_time_is_available(void);

/* Unix Timestamps */
int64_t        ozayn_time_unix_seconds(void);
int64_t        ozayn_time_unix_milliseconds(void);
int64_t        ozayn_time_unix_microseconds(void);

/* Date/Time Retrieval */
ozayn_result_t ozayn_time_get_local(OzaynDateTime *datetime);
ozayn_result_t ozayn_time_get_utc(OzaynDateTime *datetime);

/* Sleep */
ozayn_result_t ozayn_time_sleep_ms(uint64_t milliseconds);
```

### Data Structures

```c
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
```

### Safety

- All functions handle NULL parameters safely
- `ozayn_time_shutdown()` is idempotent and safe to call multiple times
- No clock modification, no timezone changes
- No NTP synchronization
- No system time modification
- Read-only access to system time

### Platform Implementations

- Linux: POSIX `clock_gettime(CLOCK_REALTIME)`, `localtime_r`, `gmtime_r`, `nanosleep`
- macOS: POSIX APIs (same as Linux)
- Windows: `time()`, `localtime_s`, `gmtime_s`, `Sleep`, `GetSystemTimeAsFileTime`

### Unix Timestamps

- `unix_seconds`: `time()` — epoch seconds
- `unix_milliseconds`: `clock_gettime` — epoch ms with nanosecond precision
- `unix_microseconds`: `clock_gettime` — epoch us with nanosecond precision

### Local vs UTC

- Local: includes timezone offset via `tm_gmtoff`
- UTC: always `utc_offset_minutes = 0`
- Offset range: -720 to +720 minutes

### Sleep

- Uses `nanosleep()` on POSIX, `Sleep()` on Windows
- Zero sleep yields CPU via `sched_yield()` / `SwitchToThread()`
- No busy-waiting

### Testing

```bash
make test
```

Tests verify:
- Initialization and shutdown (basic + idempotent)
- Availability detection (before/after init)
- Unix seconds, milliseconds, microseconds
- Timestamp consistency
- Local date/time with valid ranges
- UTC date/time with valid ranges
- Local vs UTC offset validation
- Sleep basic, zero, before init
- NULL parameter handling

## Step 18 — Application Launch & Discovery Abstraction

Cross-platform application discovery, launching, and URL opening. Read-only access to application state — no installation, no modification. No shell execution — uses native OS mechanisms only.

### Application Lifecycle

```
ozayn_application_init()
        ↓
query/launch applications
        ↓
ozayn_application_shutdown()
```

### Public API

```c
/* Application Lifecycle */
ozayn_result_t ozayn_application_init(void);
void           ozayn_application_shutdown(void);

/* Application Queries */
int            ozayn_application_is_available(void);

/* Application Launch */
ozayn_result_t ozayn_application_launch(const char *application);

/* Application Existence */
int            ozayn_application_exists(const char *application);

/* Default Browser */
ozayn_result_t ozayn_application_get_default_browser(char *buffer, size_t buffer_size);

/* URL Opening */
ozayn_result_t ozayn_application_open_url(const char *url);
```

### Safety

- No shell execution — uses `fork()`+`execvp()` on POSIX, `ShellExecute` on Windows
- No `system()` calls — ever
- No command injection possible
- No privilege escalation
- No application installation
- No browser data extraction
- NULL parameters handled safely
- Empty strings rejected

### Platform Implementations

- Linux: POSIX `fork()`+`execvp()`, PATH search, `xdg-open` for URLs
- macOS: POSIX `fork()`+`execvp()`, `open` command for URLs
- Windows: `ShellExecuteA`, `SearchPathA` for discovery

### Application Discovery

- Searches `PATH` environment variable directories
- Checks file executable permissions
- Supports absolute/relative paths
- No recursive filesystem scanning

### Application Launching

- Forks child process, executes via `execvp()` (POSIX) or `ShellExecute` (Windows)
- No shell involved — direct binary execution
- Setsid for process isolation
- Detects immediate exec failures

### URL Opening

- Validates URL scheme (http, https, ftp, mailto)
- Finds desktop URL opener (xdg-open, gnome-open, open)
- Passes URL as argument — no shell interpretation
- Rejects invalid schemes

### Default Browser Detection

- Linux: `xdg-settings get default-web-browser` with fallback to common browsers
- Windows: Registry lookup for `UserChoice` ProgId
- macOS: `xdg-settings` with fallback to common browsers

### Testing

```bash
make test
```

Tests verify:
- Initialization and shutdown (basic + idempotent)
- Availability detection (before/after init)
- Application existence (valid, nonexistent, null, empty, path)
- Application launch (null, empty, before init, nonexistent, valid)
- Default browser (null, zero size, before init, valid)
- URL opening (null, empty, before init, invalid scheme, no scheme, valid, ftp, mailto, oversized)

## Step 19 — System Permissions & Capability Access Abstraction

Cross-platform capability/permission inspection. Read-only — no permission modification, no bypass, no elevation. Determines whether OS capabilities are available, granted, denied, restricted, or unknown.

### Permissions Lifecycle

```
ozayn_permissions_init()
        ↓
query capabilities
        ↓
ozayn_permissions_shutdown()
```

### Public API

```c
/* Permissions Lifecycle */
ozayn_result_t ozayn_permissions_init(void);
void           ozayn_permissions_shutdown(void);

/* Permission Queries */
int                  ozayn_permissions_is_available(void);
OzaynPermissionState ozayn_permissions_get_state(OzaynCapability capability);

/* Name Helpers */
const char *ozayn_capability_get_name(OzaynCapability capability);
const char *ozayn_permission_state_name(OzaynPermissionState state);
```

### Capability Types

```c
OZAYN_CAP_UNKNOWN        — Unknown capability
OZAYN_CAP_CAMERA         — Camera/video capture
OZAYN_CAP_MICROPHONE     — Audio capture
OZAYN_CAP_NOTIFICATIONS  — Desktop notifications
OZAYN_CAP_ACCESSIBILITY  — OS accessibility features
OZAYN_CAP_FILESYSTEM     — Basic filesystem access
OZAYN_CAP_NETWORK        — Network connectivity
```

### Permission States

```c
OZAYN_PERMISSION_UNKNOWN     — Cannot determine
OZAYN_PERMISSION_AVAILABLE   — Capability present
OZAYN_PERMISSION_GRANTED     — Permission granted
OZAYN_PERMISSION_DENIED      — Permission denied
OZAYN_PERMISSION_RESTRICTED  — Restricted by OS
OZAYN_PERMISSION_UNAVAILABLE — Not available
```

### Safety

- Read-only inspection — no permission modification
- No bypass of OS security controls
- No privilege elevation
- No secret/credential access
- NULL parameters handled safely

### Platform Implementations

- Linux: V4L2 camera check, ALSA mic check, notify-send check, X11 extension check, filesystem/network access
- macOS: Basic filesystem/network checks (privacy APIs require framework)
- Windows: Basic filesystem/network checks (WinRT APIs require framework)

### Testing

```bash
make test
```

Tests verify:
- Initialization and shutdown (basic + idempotent)
- Availability detection (before/after init)
- Capability names (all valid + invalid)
- Permission state names (all valid + invalid)
- Capability queries (camera, microphone, notifications, accessibility, filesystem, network)
- Invalid input handling

## Step 20 — System Audio Volume & Mute Abstraction

Cross-platform system audio output volume and mute state control. Complements Step 11 (raw PCM output) with system-level volume control.

### Audio Volume Lifecycle

```
ozayn_audio_volume_init()
        ↓
query/control volume
        ↓
ozayn_audio_volume_shutdown()
```

### Public API

```c
/* Audio Volume Lifecycle */
ozayn_result_t ozayn_audio_volume_init(void);
void           ozayn_audio_volume_shutdown(void);

/* Audio Volume Queries */
int  ozayn_audio_volume_is_available(void);
ozayn_result_t ozayn_audio_volume_get(int *volume);

/* Audio Volume Control */
ozayn_result_t ozayn_audio_volume_set(int volume);

/* Mute Control */
ozayn_result_t ozayn_audio_volume_is_muted(int *muted);
ozayn_result_t ozayn_audio_volume_set_muted(int muted);
ozayn_result_t ozayn_audio_volume_toggle_mute(void);
```

### Volume Range

- Minimum: 0 (silence)
- Maximum: 100 (full volume)
- Invalid values (-1, 101, INT_MIN, INT_MAX) rejected safely

### Mute State

- `muted = 0` — unmuted
- `muted = 1` — muted
- Toggle flips between muted/unmuted

### Safety

- Operates on default output device only
- No multi-device routing, no per-application volume
- No microphone control
- No audio capture
- No remote control
- Tests restore original volume/mute state
- Headless systems report unavailable gracefully

### Platform Implementations

- Linux: ALSA mixer API (Master/PCM/Speaker playback volume)
- macOS: Stub (requires Core Audio framework)
- Windows: Stub (requires IAudioEndpointVolume)

### Testing

```bash
make test
```

Tests verify:
- Initialization and shutdown (basic + idempotent)
- Availability detection (before/after init)
- Volume query (null, before init, valid range)
- Volume set (negative, over 101, before init, set+restore)
- Mute control (null, before init, mute+verify, unmute+verify)
- Toggle (before init, toggle+verify, toggle back)
- Original state restoration

## Step 21 — System Lock State & Session Control Abstraction

Cross-platform session state detection and lock control. Read-only detection + safe lock action only. No shutdown, reboot, logout, or privilege escalation.

### Session Lifecycle

```
ozayn_session_init()
        ↓
query state / lock
        ↓
ozayn_session_shutdown()
```

### Public API

```c
/* Session Lifecycle */
ozayn_result_t ozayn_session_init(void);
void           ozayn_session_shutdown(void);

/* Session Queries */
int               ozayn_session_is_available(void);
OzaynSessionState ozayn_session_get_state(void);
int               ozayn_session_is_locked(void);
const char       *ozayn_session_state_name(OzaynSessionState state);

/* Session Actions */
ozayn_result_t ozayn_session_lock(void);
```

### Session States

```c
OZAYN_SESSION_UNKNOWN     — Cannot determine
OZAYN_SESSION_ACTIVE      — Session active
OZAYN_SESSION_LOCKED      — Session locked
OZAYN_SESSION_INACTIVE    — Session idle
OZAYN_SESSION_UNAVAILABLE — No session control
```

### Safety

- Lock only — no logout, shutdown, reboot, or privilege escalation
- No automated lock in tests — would lock developer's workstation
- No persistent session monitoring
- No background polling
- NULL parameters handled safely

### Platform Implementations

- Linux: XScreenSaver extension (`XScreenSaverQueryInfo`, `XForceScreenSaver`)
- macOS: Stub (requires CoreGraphics framework)
- Windows: `LockWorkStation` API

### Testing

```bash
make test
```

Tests verify:
- Initialization and shutdown (basic + idempotent)
- Availability detection (before/after init)
- State queries (before/after init)
- Lock queries (before/after init)
- State names (all valid + invalid)
- Lock safety (before init, safe call)
- Lock does NOT actually lock in automated tests

## Step 22 — System Brightness & Display Power Abstraction

Cross-platform display brightness query and control. Operates on the primary display only. Brightness range: 0–100 (normalized from native range).

### Brightness Lifecycle

```
ozayn_brightness_init()
        ↓
query/control brightness
        ↓
ozayn_brightness_shutdown()
```

### Public API

```c
/* Brightness Lifecycle */
ozayn_result_t ozayn_brightness_init(void);
void           ozayn_brightness_shutdown(void);

/* Brightness Queries */
int  ozayn_brightness_is_available(void);
ozayn_result_t ozayn_brightness_get(int *brightness);
ozayn_result_t ozayn_brightness_get_supported(int *supported);

/* Brightness Control */
ozayn_result_t ozayn_brightness_set(int brightness);
```

### Brightness Range

- Minimum: 0 (minimum supported brightness)
- Maximum: 100 (maximum supported brightness)
- Invalid values (-1, 101, INT_MIN, INT_MAX) rejected safely

### Safety

- Primary display only — no multi-monitor, no color profiles
- No resolution changes, no refresh rate changes
- No display power control, no screen capture
- Tests restore original brightness after testing
- Systems without controllable brightness report unavailable

### Platform Implementations

- Linux: `/sys/class/backlight/` interface (kernel backlight)
- macOS: Stub (requires CoreDisplay framework)
- Windows: Stub (requires WmiMonitorBrightness)

### Testing

```bash
make test
```

Tests verify:
- Initialization and shutdown (basic + idempotent)
- Availability detection (before/after init)
- Supported query (null, before init, value)
- Brightness query (null, before init, valid range)
- Brightness set (negative, over 101, before init, set+restore)
- Original brightness restoration

## Step 23 — System Theme & Appearance Abstraction

Cross-platform system theme/appearance detection. Read-only — no theme modification, no color changes. Detects light/dark mode from OS settings.

### Appearance Lifecycle

```
ozayn_appearance_init()
        ↓
detect theme
        ↓
ozayn_appearance_shutdown()
```

### Public API

```c
/* Appearance Lifecycle */
ozayn_result_t ozayn_appearance_init(void);
void           ozayn_appearance_shutdown(void);

/* Appearance Queries */
int             ozayn_appearance_is_available(void);
OzaynAppearance ozayn_appearance_get(void);
const char     *ozayn_appearance_name(OzaynAppearance appearance);
```

### Appearance Types

```c
OZAYN_APPEARANCE_UNKNOWN — Cannot determine
OZAYN_APPEARANCE_LIGHT   — Light theme
OZAYN_APPEARANCE_DARK    — Dark theme
```

### Safety

- Read-only detection — no theme modification
- No wallpaper changes, no color changes
- No registry/modification of settings
- NULL parameters handled safely
- Headless systems return UNKNOWN

### Platform Implementations

- Linux: Environment variables (GTK_THEME, COLOR_SCHEME, QT_THEME, KDE_SESSION_THEME)
- macOS: Stub (requires NSAppearance framework)
- Windows: Stub (requires UxTheme/registry)

### Theme Detection Sources (Linux)

- `GTK_THEME` — GTK-based desktops (GNOME, XFCE)
- `COLOR_SCHEME` — freedesktop.org portal settings
- `QT_THEME` — Qt-based desktops (KDE)
- `KDE_SESSION_THEME` — KDE Plasma
- `DARKMODE` — generic dark mode flag

### Testing

```bash
make test
```

Tests verify:
- Initialization and shutdown (basic + idempotent)
- Availability detection (before/after init)
- Appearance query (before/after init, valid states)
- Name conversion (all valid + invalid)
- Unknown/Light/Dark name strings
- Invalid enum value handling

## Status

- [x] Step 01: Platform Detection & Initialization
- [x] Step 02: System Information & Hardware Identification
- [x] Step 03: Filesystem Abstraction
- [x] Step 04: Process Management Abstraction
- [x] Step 05: Display Abstraction
- [x] Step 06: Window Management
- [x] Step 07: Input & Mouse Abstraction
- [x] Step 08: Keyboard & Input Event Abstraction
- [x] Step 09: Camera Device Abstraction
- [x] Step 10: Microphone Device Abstraction
- [x] Step 11: Audio Output / Speaker Abstraction
- [x] Step 12: Network Information & Connectivity Abstraction
- [x] Step 13: Power & Battery Information Abstraction
- [x] Step 14: Notification System Abstraction
- [x] Step 15: Clipboard Abstraction
- [x] Step 16: Environment & User Session Abstraction
- [x] Step 17: System Time & Date Abstraction
- [x] Step 18: Application Launch & Discovery Abstraction
- [x] Step 19: System Permissions & Capability Access Abstraction
- [x] Step 20: System Audio Volume & Mute Abstraction
- [x] Step 21: System Lock State & Session Control Abstraction
- [x] Step 22: System Brightness & Display Power Abstraction
- [x] Step 23: System Theme & Appearance Abstraction
- [ ] Steps 24-35: (future)
