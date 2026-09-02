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

## Status

- [x] Step 01: Platform Detection & Initialization
- [x] Step 02: System Information & Hardware Identification
- [x] Step 03: Filesystem Abstraction
- [x] Step 04: Process Management Abstraction
- [x] Step 05: Display Abstraction
- [x] Step 06: Window Management
- [x] Step 07: Input & Mouse Abstraction
- [ ] Steps 08-35: (future)
