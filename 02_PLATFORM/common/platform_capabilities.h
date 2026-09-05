#ifndef OZAYN_PLATFORM_CAPABILITIES_H
#define OZAYN_PLATFORM_CAPABILITIES_H

#ifdef __cplusplus
extern "C" {
#endif

/* ================================================================
 * Platform Capability Registry — Section 02 Step 35
 * ================================================================
 *
 * Unified integration layer exposing all Section 02 platform
 * subsystems through a single, queryable registry.
 *
 * This is the final public API of Section 02 — Cross-Platform
 * System Layer. Future OZAYN modules should use this registry
 * instead of directly including platform-specific headers.
 *
 * Architecture:
 *
 *     OZAYN CORE
 *         │
 *         ▼
 *     Platform Capability Registry  (this file)
 *         │
 *         ├── Platform
 *         ├── Filesystem
 *         ├── Process
 *         ├── Display
 *         ├── Window
 *         ├── Input
 *         ├── Keyboard
 *         ├── Camera
 *         ├── Microphone
 *         ├── Audio Output
 *         ├── Network
 *         ├── Power
 *         ├── Notification
 *         ├── Clipboard
 *         ├── Environment
 *         ├── Time
 *         ├── Application
 *         ├── Permissions
 *         ├── Audio Volume
 *         ├── Session
 *         ├── Brightness
 *         ├── Appearance
 *         ├── Font
 *         ├── Sensors
 *         ├── Storage
 *         ├── Peripheral
 *         ├── Bluetooth
 *         ├── System Events
 *         ├── Resources
 *         ├── Network Configuration
 *         ├── Services
 *         ├── Security
 *         └── Diagnostics
 */

/* ---- Capability Enumeration ---- */

typedef enum
{
    OZAYN_CAPABILITY_PLATFORM = 0,
    OZAYN_CAPABILITY_FILESYSTEM,
    OZAYN_CAPABILITY_PROCESS,
    OZAYN_CAPABILITY_DISPLAY,
    OZAYN_CAPABILITY_WINDOW,
    OZAYN_CAPABILITY_INPUT,
    OZAYN_CAPABILITY_KEYBOARD,
    OZAYN_CAPABILITY_CAMERA,
    OZAYN_CAPABILITY_MICROPHONE,
    OZAYN_CAPABILITY_AUDIO_OUTPUT,
    OZAYN_CAPABILITY_NETWORK,
    OZAYN_CAPABILITY_POWER,
    OZAYN_CAPABILITY_NOTIFICATION,
    OZAYN_CAPABILITY_CLIPBOARD,
    OZAYN_CAPABILITY_ENVIRONMENT,
    OZAYN_CAPABILITY_TIME,
    OZAYN_CAPABILITY_APPLICATION,
    OZAYN_CAPABILITY_PERMISSIONS,
    OZAYN_CAPABILITY_AUDIO_VOLUME,
    OZAYN_CAPABILITY_SESSION,
    OZAYN_CAPABILITY_BRIGHTNESS,
    OZAYN_CAPABILITY_APPEARANCE,
    OZAYN_CAPABILITY_FONT,
    OZAYN_CAPABILITY_SENSORS,
    OZAYN_CAPABILITY_STORAGE,
    OZAYN_CAPABILITY_PERIPHERAL,
    OZAYN_CAPABILITY_BLUETOOTH,
    OZAYN_CAPABILITY_SYSTEM_EVENT,
    OZAYN_CAPABILITY_RESOURCES,
    OZAYN_CAPABILITY_NETWORK_CONFIG,
    OZAYN_CAPABILITY_SERVICE,
    OZAYN_CAPABILITY_SECURITY,
    OZAYN_CAPABILITY_DIAGNOSTICS,
    OZAYN_CAPABILITY_COUNT
} OzaynPlatformCapability;

/* ---- Capability State ---- */

typedef enum
{
    OZAYN_CAPABILITY_UNKNOWN = 0,
    OZAYN_CAPABILITY_AVAILABLE,
    OZAYN_CAPABILITY_UNAVAILABLE
} OzaynCapabilityState;

/* ---- Capability Information ---- */

typedef struct
{
    OzaynPlatformCapability capability;
    OzaynCapabilityState state;
    char name[128];
    char description[256];
} OzaynPlatformCapabilityInfo;

/* ---- Registry Lifecycle ---- */

int  ozayn_platform_capabilities_init(void);
void ozayn_platform_capabilities_shutdown(void);
int  ozayn_platform_capabilities_is_available(void);

/* ---- Queries ---- */

int  ozayn_platform_capabilities_get_count(void);
int  ozayn_platform_capabilities_get(OzaynPlatformCapability capability,
                                     OzaynPlatformCapabilityInfo *info);
int  ozayn_platform_capabilities_is_capability_available(OzaynPlatformCapability capability);

/* ---- Names ---- */

const char *ozayn_platform_capability_name(OzaynPlatformCapability capability);
const char *ozayn_platform_capability_state_name(OzaynCapabilityState state);

#ifdef __cplusplus
}
#endif

#endif /* OZAYN_PLATFORM_CAPABILITIES_H */
