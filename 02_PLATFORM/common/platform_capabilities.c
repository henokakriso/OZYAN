#include "platform_capabilities.h"
#include "platform.h"
#include <string.h>
#include <stdio.h>

/* ================================================================
 * Platform Capability Registry — Section 02 Step 35
 * ================================================================
 *
 * Integration layer calling existing Section 02 public APIs
 * to populate a static registry of capability states.
 *
 * Not a new implementation — purely an orchestrator.
 */

static int _cap_initialized = 0;
static OzaynPlatformCapabilityInfo _cap_registry[OZAYN_CAPABILITY_COUNT];
static int _cap_count = 0;

/* ---- Capability name table ---- */

static const char *_cap_names[OZAYN_CAPABILITY_COUNT] = {
    "platform",
    "filesystem",
    "process",
    "display",
    "window",
    "input",
    "keyboard",
    "camera",
    "microphone",
    "audio_output",
    "network",
    "power",
    "notification",
    "clipboard",
    "environment",
    "time",
    "application",
    "permissions",
    "audio_volume",
    "session",
    "brightness",
    "appearance",
    "font",
    "sensors",
    "storage",
    "peripheral",
    "bluetooth",
    "system_event",
    "resources",
    "network_config",
    "service",
    "security",
    "diagnostics"
};

/* ---- Capability description table ---- */

static const char *_cap_descriptions[OZAYN_CAPABILITY_COUNT] = {
    "Platform detection and identification",
    "Filesystem and system information",
    "Process management and lifecycle",
    "Display enumeration and information",
    "Window management and decoration",
    "Input device abstraction (mouse, touch)",
    "Keyboard and key event abstraction",
    "Camera device enumeration and access",
    "Microphone device enumeration and access",
    "Audio output device enumeration and control",
    "Network interface enumeration and state",
    "Power source and battery status",
    "Desktop notification system",
    "Clipboard read/write abstraction",
    "Environment variable access",
    "System time and monotonic clock",
    "Application lifecycle management",
    "Permission queries and access control",
    "Audio volume and mute control",
    "Session lock/unlock and idle detection",
    "Display brightness control",
    "Desktop theme and appearance",
    "Font enumeration and metrics",
    "Hardware sensor access (temperature, etc.)",
    "Storage device enumeration",
    "Peripheral device enumeration (USB, etc.)",
    "Bluetooth adapter and device discovery",
    "System event monitoring (hotplug, etc.)",
    "System resource monitoring (CPU, memory)",
    "Network configuration and routing",
    "System service enumeration and management",
    "Security state and firewall detection",
    "Diagnostics and health information"
};

/* ---- Internal: initialize a capability entry ---- */

static void _cap_set(int idx, OzaynPlatformCapability cap,
                      OzaynCapabilityState state) {
    if (idx < 0 || idx >= OZAYN_CAPABILITY_COUNT) return;
    OzaynPlatformCapabilityInfo *info = &_cap_registry[idx];
    memset(info, 0, sizeof(OzaynPlatformCapabilityInfo));
    info->capability = cap;
    info->state = state;
    if (_cap_names[idx]) strncpy(info->name, _cap_names[idx], sizeof(info->name) - 1);
    if (_cap_descriptions[idx]) strncpy(info->description, _cap_descriptions[idx], sizeof(info->description) - 1);
}

/* ---- Internal: probe a subsystem via init + is_available ---- */

static OzaynCapabilityState _cap_probe_init_avail(
    ozayn_result_t (*init_fn)(void),
    int (*avail_fn)(void),
    void (*shutdown_fn)(void))
{
    if (!init_fn) return OZAYN_CAPABILITY_UNAVAILABLE;
    ozayn_result_t r = init_fn();
    if (r != OZAYN_OK) return OZAYN_CAPABILITY_UNAVAILABLE;
    int avail = 0;
    if (avail_fn) avail = avail_fn();
    if (shutdown_fn) shutdown_fn();
    return avail ? OZAYN_CAPABILITY_AVAILABLE : OZAYN_CAPABILITY_UNAVAILABLE;
}

/* ---- Internal: probe filesystem via system_info ---- */

static OzaynCapabilityState _cap_probe_filesystem(void) {
    ozayn_system_info_t info;
    return (ozayn_system_info(&info) == OZAYN_OK)
        ? OZAYN_CAPABILITY_AVAILABLE
        : OZAYN_CAPABILITY_UNAVAILABLE;
}

/* ---- Internal: probe process via self PID ---- */

static OzaynCapabilityState _cap_probe_process(void) {
    uint32_t pid = ozayn_process_self();
    return (pid > 0) ? OZAYN_CAPABILITY_AVAILABLE : OZAYN_CAPABILITY_UNAVAILABLE;
}

/* ---- Internal: probe platform via detect_init ---- */

static OzaynCapabilityState _cap_probe_platform(void) {
    return (ozayn_platform_detect_init() == OZAYN_OK)
        ? OZAYN_CAPABILITY_AVAILABLE
        : OZAYN_CAPABILITY_UNAVAILABLE;
}

/* ---- Internal: build the full registry ---- */

static void _cap_build_registry(void) {
    _cap_count = 0;

    /* PLATFORM — uses detect_init directly */
    _cap_set(_cap_count++, OZAYN_CAPABILITY_PLATFORM,
             _cap_probe_platform());

    /* FILESYSTEM — uses system_info */
    _cap_set(_cap_count++, OZAYN_CAPABILITY_FILESYSTEM,
             _cap_probe_filesystem());

    /* PROCESS — uses process_self */
    _cap_set(_cap_count++, OZAYN_CAPABILITY_PROCESS,
             _cap_probe_process());

    /* DISPLAY — init + is_available */
    _cap_set(_cap_count++, OZAYN_CAPABILITY_DISPLAY,
             _cap_probe_init_avail(ozayn_display_init,
                                   ozayn_display_is_available,
                                   ozayn_display_shutdown));

    /* WINDOW — init + is_available */
    _cap_set(_cap_count++, OZAYN_CAPABILITY_WINDOW,
             _cap_probe_init_avail(ozayn_window_init,
                                   ozayn_window_is_available,
                                   ozayn_window_shutdown));

    /* INPUT — init + is_available */
    _cap_set(_cap_count++, OZAYN_CAPABILITY_INPUT,
             _cap_probe_init_avail(ozayn_input_init,
                                   ozayn_input_is_available,
                                   ozayn_input_shutdown));

    /* KEYBOARD — init + is_available */
    _cap_set(_cap_count++, OZAYN_CAPABILITY_KEYBOARD,
             _cap_probe_init_avail(ozayn_keyboard_init,
                                   ozayn_keyboard_is_available,
                                   ozayn_keyboard_shutdown));

    /* CAMERA — init + is_available */
    _cap_set(_cap_count++, OZAYN_CAPABILITY_CAMERA,
             _cap_probe_init_avail(ozayn_camera_init,
                                   ozayn_camera_is_available,
                                   ozayn_camera_shutdown));

    /* MICROPHONE — init + is_available */
    _cap_set(_cap_count++, OZAYN_CAPABILITY_MICROPHONE,
             _cap_probe_init_avail(ozayn_microphone_init,
                                   ozayn_microphone_is_available,
                                   ozayn_microphone_shutdown));

    /* AUDIO_OUTPUT — init + is_available */
    _cap_set(_cap_count++, OZAYN_CAPABILITY_AUDIO_OUTPUT,
             _cap_probe_init_avail(ozayn_audio_output_init,
                                   ozayn_audio_output_is_available,
                                   ozayn_audio_output_shutdown));

    /* NETWORK — init + is_available */
    _cap_set(_cap_count++, OZAYN_CAPABILITY_NETWORK,
             _cap_probe_init_avail(ozayn_network_init,
                                   ozayn_network_is_available,
                                   ozayn_network_shutdown));

    /* POWER — init + is_available */
    _cap_set(_cap_count++, OZAYN_CAPABILITY_POWER,
             _cap_probe_init_avail(ozayn_power_init,
                                   ozayn_power_is_available,
                                   ozayn_power_shutdown));

    /* NOTIFICATION — init + is_available */
    _cap_set(_cap_count++, OZAYN_CAPABILITY_NOTIFICATION,
             _cap_probe_init_avail(ozayn_notification_init,
                                   ozayn_notification_is_available,
                                   ozayn_notification_shutdown));

    /* CLIPBOARD — init + is_available */
    _cap_set(_cap_count++, OZAYN_CAPABILITY_CLIPBOARD,
             _cap_probe_init_avail(ozayn_clipboard_init,
                                   ozayn_clipboard_is_available,
                                   ozayn_clipboard_shutdown));

    /* ENVIRONMENT — init + is_available */
    _cap_set(_cap_count++, OZAYN_CAPABILITY_ENVIRONMENT,
             _cap_probe_init_avail(ozayn_environment_init,
                                   ozayn_environment_is_available,
                                   ozayn_environment_shutdown));

    /* TIME — init + is_available */
    _cap_set(_cap_count++, OZAYN_CAPABILITY_TIME,
             _cap_probe_init_avail(ozayn_time_init,
                                   ozayn_time_is_available,
                                   ozayn_time_shutdown));

    /* APPLICATION — init + is_available */
    _cap_set(_cap_count++, OZAYN_CAPABILITY_APPLICATION,
             _cap_probe_init_avail(ozayn_application_init,
                                   ozayn_application_is_available,
                                   ozayn_application_shutdown));

    /* PERMISSIONS — init + is_available */
    _cap_set(_cap_count++, OZAYN_CAPABILITY_PERMISSIONS,
             _cap_probe_init_avail(ozayn_permissions_init,
                                   ozayn_permissions_is_available,
                                   ozayn_permissions_shutdown));

    /* AUDIO_VOLUME — init + is_available */
    _cap_set(_cap_count++, OZAYN_CAPABILITY_AUDIO_VOLUME,
             _cap_probe_init_avail(ozayn_audio_volume_init,
                                   ozayn_audio_volume_is_available,
                                   ozayn_audio_volume_shutdown));

    /* SESSION — init + is_available */
    _cap_set(_cap_count++, OZAYN_CAPABILITY_SESSION,
             _cap_probe_init_avail(ozayn_session_init,
                                   ozayn_session_is_available,
                                   ozayn_session_shutdown));

    /* BRIGHTNESS — init + is_available */
    _cap_set(_cap_count++, OZAYN_CAPABILITY_BRIGHTNESS,
             _cap_probe_init_avail(ozayn_brightness_init,
                                   ozayn_brightness_is_available,
                                   ozayn_brightness_shutdown));

    /* APPEARANCE — init + is_available */
    _cap_set(_cap_count++, OZAYN_CAPABILITY_APPEARANCE,
             _cap_probe_init_avail(ozayn_appearance_init,
                                   ozayn_appearance_is_available,
                                   ozayn_appearance_shutdown));

    /* FONT — init + is_available */
    _cap_set(_cap_count++, OZAYN_CAPABILITY_FONT,
             _cap_probe_init_avail(ozayn_font_init,
                                   ozayn_font_is_available,
                                   ozayn_font_shutdown));

    /* SENSORS — init + is_available */
    _cap_set(_cap_count++, OZAYN_CAPABILITY_SENSORS,
             _cap_probe_init_avail(ozayn_sensors_init,
                                   ozayn_sensors_is_available,
                                   ozayn_sensors_shutdown));

    /* STORAGE — init + is_available */
    _cap_set(_cap_count++, OZAYN_CAPABILITY_STORAGE,
             _cap_probe_init_avail(ozayn_storage_init,
                                   ozayn_storage_is_available,
                                   ozayn_storage_shutdown));

    /* PERIPHERAL — init + is_available */
    _cap_set(_cap_count++, OZAYN_CAPABILITY_PERIPHERAL,
             _cap_probe_init_avail(ozayn_peripheral_init,
                                   ozayn_peripheral_is_available,
                                   ozayn_peripheral_shutdown));

    /* BLUETOOTH — init + is_available */
    _cap_set(_cap_count++, OZAYN_CAPABILITY_BLUETOOTH,
             _cap_probe_init_avail(ozayn_bluetooth_init,
                                   ozayn_bluetooth_is_available,
                                   ozayn_bluetooth_shutdown));

    /* SYSTEM_EVENT — init + is_available */
    _cap_set(_cap_count++, OZAYN_CAPABILITY_SYSTEM_EVENT,
             _cap_probe_init_avail(ozayn_system_event_init,
                                   ozayn_system_event_is_available,
                                   ozayn_system_event_shutdown));

    /* RESOURCES — init + is_available */
    _cap_set(_cap_count++, OZAYN_CAPABILITY_RESOURCES,
             _cap_probe_init_avail(ozayn_resources_init,
                                   ozayn_resources_is_available,
                                   ozayn_resources_shutdown));

    /* NETWORK_CONFIG — init + is_available */
    _cap_set(_cap_count++, OZAYN_CAPABILITY_NETWORK_CONFIG,
             _cap_probe_init_avail(ozayn_network_config_init,
                                   ozayn_network_config_is_available,
                                   ozayn_network_config_shutdown));

    /* SERVICE — init + is_available */
    _cap_set(_cap_count++, OZAYN_CAPABILITY_SERVICE,
             _cap_probe_init_avail(ozayn_service_init,
                                   ozayn_service_is_available,
                                   ozayn_service_shutdown));

    /* SECURITY — init + is_available */
    _cap_set(_cap_count++, OZAYN_CAPABILITY_SECURITY,
             _cap_probe_init_avail(ozayn_sys_security_init,
                                   ozayn_sys_security_is_available,
                                   ozayn_sys_security_shutdown));

    /* DIAGNOSTICS — init + is_available */
    _cap_set(_cap_count++, OZAYN_CAPABILITY_DIAGNOSTICS,
             _cap_probe_init_avail(ozayn_sys_diag_init,
                                   ozayn_sys_diag_is_available,
                                   ozayn_sys_diag_shutdown));
}

/* ================================================================
 * Public API
 * ================================================================ */

int ozayn_platform_capabilities_init(void) {
    if (_cap_initialized) return 1;

    memset(_cap_registry, 0, sizeof(_cap_registry));
    _cap_count = 0;

    _cap_build_registry();
    _cap_initialized = 1;

    return 1;
}

void ozayn_platform_capabilities_shutdown(void) {
    _cap_initialized = 0;
    _cap_count = 0;
}

int ozayn_platform_capabilities_is_available(void) {
    return _cap_initialized;
}

int ozayn_platform_capabilities_get_count(void) {
    if (!_cap_initialized) return 0;
    return _cap_count;
}

int ozayn_platform_capabilities_get(OzaynPlatformCapability capability,
                                    OzaynPlatformCapabilityInfo *info) {
    if (!info) return 0;
    memset(info, 0, sizeof(OzaynPlatformCapabilityInfo));

    if (!_cap_initialized) return 0;
    if (capability < 0 || capability >= OZAYN_CAPABILITY_COUNT) return 0;

    *info = _cap_registry[capability];
    return 1;
}

int ozayn_platform_capabilities_is_capability_available(OzaynPlatformCapability capability) {
    if (!_cap_initialized) return 0;
    if (capability < 0 || capability >= OZAYN_CAPABILITY_COUNT) return 0;
    return _cap_registry[capability].state == OZAYN_CAPABILITY_AVAILABLE;
}

const char *ozayn_platform_capability_name(OzaynPlatformCapability capability) {
    if (capability < 0 || capability >= OZAYN_CAPABILITY_COUNT) return "unknown";
    return _cap_names[capability];
}

const char *ozayn_platform_capability_state_name(OzaynCapabilityState state) {
    switch (state) {
        case OZAYN_CAPABILITY_UNKNOWN:     return "unknown";
        case OZAYN_CAPABILITY_AVAILABLE:   return "available";
        case OZAYN_CAPABILITY_UNAVAILABLE: return "unavailable";
        default:                           return "unknown";
    }
}
