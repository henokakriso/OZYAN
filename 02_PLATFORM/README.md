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

## Status

- [x] Step 01: Platform Detection & Initialization
- [x] Step 02: System Information & Hardware Identification
- [x] Step 03: Filesystem Abstraction
- [x] Step 04: Process Management Abstraction
- [ ] Steps 05-35: (future)
