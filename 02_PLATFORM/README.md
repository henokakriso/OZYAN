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

### Directory Structure

```
02_PLATFORM/
├── common/           # Platform-independent API (see include/platform.h)
├── linux/            # Linux-specific implementations
├── windows/          # Windows-specific implementations
├── macos/            # macOS-specific implementations
├── tests/            # Platform detection tests
└── README.md         # This file
```

Platform implementations live in `src/platform/{linux,macos,windows}/` and are compiled based on the host OS.

## Testing

```bash
make test
```

8 platform detection tests verify:
- Init succeeds on supported OS
- Platform is detected correctly
- Name matches platform
- State resets to UNKNOWN on shutdown
- Init/shutdown cycles are safe

## Status

- [x] Step 01: Platform Detection & Initialization
- [ ] Step 02: System Information
- [ ] Steps 03-35: (future)
