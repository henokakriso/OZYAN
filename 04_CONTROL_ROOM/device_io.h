#ifndef OZAYN_DEVICE_IO_H
#define OZAYN_DEVICE_IO_H

#include <stdint.h>
#include <time.h>

/* ============================================================
 * SECTION 1 — ERROR CODES
 * ============================================================ */

typedef enum {
    OZAYN_DIO_OK                    =   0,
    OZAYN_DIO_ERR_NULL              =  -1,
    OZAYN_DIO_ERR_NOT_INITIALIZED   =  -2,
    OZAYN_DIO_ERR_ALREADY_INIT      =  -3,
    OZAYN_DIO_ERR_INVALID_PARAM     =  -4,
    OZAYN_DIO_ERR_LIMIT_REACHED     =  -5,
    OZAYN_DIO_ERR_NOT_FOUND         =  -6,
    OZAYN_DIO_ERR_DUPLICATE         =  -7,
    OZAYN_DIO_ERR_UNAVAILABLE       =  -8,
    OZAYN_DIO_ERR_UNSUPPORTED       =  -9,
    OZAYN_DIO_ERR_STATE_INVALID     = -10,
    OZAYN_DIO_ERR_RESERVATION_FAILED= -11,
    OZAYN_DIO_ERR_RESERVATION_CONFLICT = -12,
    OZAYN_DIO_ERR_RESERVATION_EXPIRED  = -13,
    OZAYN_DIO_ERR_RESERVATION_NOT_FOUND= -14,
    OZAYN_DIO_ERR_ACTIVATION_FAILED = -15,
    OZAYN_DIO_ERR_RELEASE_FAILED    = -16,
    OZAYN_DIO_ERR_DISCOVERY_FAILED  = -17,
    OZAYN_DIO_ERR_DISCOVERY_TIMEOUT = -18,
    OZAYN_DIO_ERR_PROVIDER_ERROR    = -19,
    OZAYN_DIO_ERR_PERMISSION_DENIED = -20,
    OZAYN_DIO_ERR_AUTH_FAILED       = -21,
    OZAYN_DIO_ERR_SAFETY_FAILED     = -22,
    OZAYN_DIO_ERR_RESOURCE_FAILED   = -23,
    OZAYN_DIO_ERR_TIMEOUT           = -24,
    OZAYN_DIO_ERR_CONCURRENCY       = -25,
    OZAYN_DIO_ERR_DEVICE_DISCONNECTED = -26
} ozayn_dio_err_t;

/* ============================================================
 * SECTION 2 — DEVICE TYPES
 * ============================================================ */

typedef enum {
    OZAYN_DIO_DEV_CAMERA = 0,
    OZAYN_DIO_DEV_MICROPHONE,
    OZAYN_DIO_DEV_AUDIO_INPUT,
    OZAYN_DIO_DEV_AUDIO_OUTPUT,
    OZAYN_DIO_DEV_DISPLAY,
    OZAYN_DIO_DEV_KEYBOARD,
    OZAYN_DIO_DEV_MOUSE,
    OZAYN_DIO_DEV_POINTER,
    OZAYN_DIO_DEV_INPUT_DEVICE,
    OZAYN_DIO_DEV_GPU,
    OZAYN_DIO_DEV_NETWORK_DEVICE,
    OZAYN_DIO_DEV_STORAGE_DEVICE,
    OZAYN_DIO_DEV_OTHER,
    OZAYN_DIO_DEV_TYPE_COUNT
} ozayn_dio_device_type_t;

/* ============================================================
 * SECTION 3 — DEVICE STATES
 * ============================================================ */

typedef enum {
    OZAYN_DIO_STATE_UNKNOWN = 0,
    OZAYN_DIO_STATE_DISCOVERING,
    OZAYN_DIO_STATE_AVAILABLE,
    OZAYN_DIO_STATE_RESERVED,
    OZAYN_DIO_STATE_OPENING,
    OZAYN_DIO_STATE_ACTIVE,
    OZAYN_DIO_STATE_BUSY,
    OZAYN_DIO_STATE_DISABLED,
    OZAYN_DIO_STATE_UNAVAILABLE,
    OZAYN_DIO_STATE_ERROR,
    OZAYN_DIO_STATE_UNSUPPORTED,
    OZAYN_DIO_STATE_RELEASING,
    OZAYN_DIO_STATE_COUNT
} ozayn_dio_device_state_t;

/* ============================================================
 * SECTION 4 — DEVICE AVAILABILITY
 * ============================================================ */

typedef enum {
    OZAYN_DIO_AVAIL_UNKNOWN = 0,
    OZAYN_DIO_AVAIL_AVAILABLE,
    OZAYN_DIO_AVAIL_UNAVAILABLE,
    OZAYN_DIO_AVAIL_LIMITED,
    OZAYN_DIO_AVAIL_COUNT
} ozayn_dio_availability_t;

/* ============================================================
 * SECTION 5 — DEVICE HEALTH
 * ============================================================ */

typedef enum {
    OZAYN_DIO_HEALTH_UNKNOWN = 0,
    OZAYN_DIO_HEALTH_HEALTHY,
    OZAYN_DIO_HEALTH_DEGRADED,
    OZAYN_DIO_HEALTH_UNHEALTHY,
    OZAYN_DIO_HEALTH_FAILED,
    OZAYN_DIO_HEALTH_COUNT
} ozayn_dio_health_t;

/* ============================================================
 * SECTION 6 — DEVICE CAPABILITY TYPES
 * ============================================================ */

typedef enum {
    OZAYN_DIO_CAP_CAMERA_CAPTURE = 0,
    OZAYN_DIO_CAP_MICROPHONE_INPUT,
    OZAYN_DIO_CAP_AUDIO_PLAYBACK,
    OZAYN_DIO_CAP_DISPLAY_OUTPUT,
    OZAYN_DIO_CAP_KEYBOARD_INPUT,
    OZAYN_DIO_CAP_MOUSE_INPUT,
    OZAYN_DIO_CAP_POINTER_CONTROL,
    OZAYN_DIO_CAP_GPU_COMPUTE,
    OZAYN_DIO_CAP_GPU_RENDERING,
    OZAYN_DIO_CAP_NETWORK_ACCESS,
    OZAYN_DIO_CAP_STORAGE_ACCESS,
    OZAYN_DIO_CAP_COUNT
} ozayn_dio_capability_type_t;

/* ============================================================
 * SECTION 7 — CAPABILITY STATES
 * ============================================================ */

typedef enum {
    OZAYN_DIO_CAP_STATE_IMPLEMENTED = 0,
    OZAYN_DIO_CAP_STATE_PLANNED,
    OZAYN_DIO_CAP_STATE_UNAVAILABLE,
    OZAYN_DIO_CAP_STATE_UNSUPPORTED,
    OZAYN_DIO_CAP_STATE_DISABLED,
    OZAYN_DIO_CAP_STATE_ERROR,
    OZAYN_DIO_CAP_STATE_COUNT
} ozayn_dio_cap_state_t;

/* ============================================================
 * SECTION 8 — ACCESS MODE
 * ============================================================ */

typedef enum {
    OZAYN_DIO_ACCESS_SHARED = 0,
    OZAYN_DIO_ACCESS_EXCLUSIVE,
    OZAYN_DIO_ACCESS_COUNT
} ozayn_dio_access_mode_t;

/* ============================================================
 * SECTION 9 — RESERVATION STATES
 * ============================================================ */

typedef enum {
    OZAYN_DIO_RES_STATE_REQUESTED = 0,
    OZAYN_DIO_RES_STATE_RESERVED,
    OZAYN_DIO_RES_STATE_ACTIVE,
    OZAYN_DIO_RES_STATE_RELEASED,
    OZAYN_DIO_RES_STATE_EXPIRED,
    OZAYN_DIO_RES_STATE_CANCELLED,
    OZAYN_DIO_RES_STATE_FAILED,
    OZAYN_DIO_RES_STATE_COUNT
} ozayn_dio_reservation_state_t;

/* ============================================================
 * SECTION 10 — EVENT TYPES
 * ============================================================ */

typedef enum {
    OZAYN_DIO_EVENT_DISCOVERED = 0,
    OZAYN_DIO_EVENT_REGISTERED,
    OZAYN_DIO_EVENT_UPDATED,
    OZAYN_DIO_EVENT_AVAILABLE,
    OZAYN_DIO_EVENT_UNAVAILABLE,
    OZAYN_DIO_EVENT_DEGRADED,
    OZAYN_DIO_EVENT_RESERVED,
    OZAYN_DIO_EVENT_RESERVATION_CREATED,
    OZAYN_DIO_EVENT_RESERVATION_FAILED,
    OZAYN_DIO_EVENT_RESERVATION_EXPIRED,
    OZAYN_DIO_EVENT_ACTIVATED,
    OZAYN_DIO_EVENT_RELEASED,
    OZAYN_DIO_EVENT_DISABLED,
    OZAYN_DIO_EVENT_ERROR,
    OZAYN_DIO_EVENT_CAPABILITY_CHANGED,
    OZAYN_DIO_EVENT_DISCONNECTED,
    OZAYN_DIO_EVENT_RECONNECTED,
    OZAYN_DIO_EVENT_COUNT
} ozayn_dio_event_type_t;

/* ============================================================
 * SECTION 11 — LIMITS
 * ============================================================ */

#define OZAYN_DIO_MAX_DEVICES              64
#define OZAYN_DIO_MAX_CAPABILITIES          8
#define OZAYN_DIO_MAX_RESERVATIONS         32
#define OZAYN_DIO_MAX_EVENTS               64
#define OZAYN_DIO_MAX_ID_LEN               64
#define OZAYN_DIO_MAX_NAME_LEN            128
#define OZAYN_DIO_MAX_PROVIDER_LEN         64
#define OZAYN_DIO_MAX_VERSION_LEN          32
#define OZAYN_DIO_MAX_DESCRIPTION_LEN     256
#define OZAYN_DIO_MAX_METADATA_LEN        256
#define OZAYN_DIO_MAX_PERMISSION_LEN       64
#define OZAYN_DIO_DEFAULT_RESERVATION_TTL_MS 60000

/* ============================================================
 * SECTION 12 — CAPABILITY DESCRIPTOR
 * ============================================================ */

typedef struct {
    ozayn_dio_capability_type_t type;
    ozayn_dio_cap_state_t state;
    char description[OZAYN_DIO_MAX_DESCRIPTION_LEN];
    char required_permission[OZAYN_DIO_MAX_PERMISSION_LEN];
    int active;
} ozayn_dio_capability_t;

/* ============================================================
 * SECTION 13 — DEVICE DESCRIPTOR
 * ============================================================ */

typedef struct {
    char device_id[OZAYN_DIO_MAX_ID_LEN];
    ozayn_dio_device_type_t type;
    char name[OZAYN_DIO_MAX_NAME_LEN];
    char provider[OZAYN_DIO_MAX_PROVIDER_LEN];
    char platform[OZAYN_DIO_MAX_PROVIDER_LEN];
    char version[OZAYN_DIO_MAX_VERSION_LEN];
    ozayn_dio_device_state_t state;
    ozayn_dio_availability_t availability;
    ozayn_dio_health_t health;
    ozayn_dio_access_mode_t access_mode;
    ozayn_dio_capability_t capabilities[OZAYN_DIO_MAX_CAPABILITIES];
    int capability_count;
    char required_permission[OZAYN_DIO_MAX_PERMISSION_LEN];
    char resource_ref[OZAYN_DIO_MAX_ID_LEN];
    time_t registration_time;
    time_t last_update_time;
    int active;
    char metadata[OZAYN_DIO_MAX_METADATA_LEN];
} ozayn_dio_device_desc_t;

/* ============================================================
 * SECTION 14 — DEVICE RESERVATION
 * ============================================================ */

typedef struct {
    char reservation_id[OZAYN_DIO_MAX_ID_LEN];
    char device_id[OZAYN_DIO_MAX_ID_LEN];
    char requester_ref[OZAYN_DIO_MAX_ID_LEN];
    char session_ref[OZAYN_DIO_MAX_ID_LEN];
    ozayn_dio_capability_type_t requested_capability;
    time_t created_time;
    time_t expiry_time;
    ozayn_dio_reservation_state_t state;
    int active;
    char metadata[OZAYN_DIO_MAX_METADATA_LEN];
} ozayn_dio_reservation_t;

/* ============================================================
 * SECTION 15 — DEVICE EVENT
 * ============================================================ */

typedef struct {
    ozayn_dio_event_type_t type;
    char device_id[OZAYN_DIO_MAX_ID_LEN];
    char message[OZAYN_DIO_MAX_DESCRIPTION_LEN];
    time_t timestamp;
} ozayn_dio_event_t;

/* ============================================================
 * SECTION 16 — DISCOVERY RESULT
 * ============================================================ */

typedef struct {
    char provider[OZAYN_DIO_MAX_PROVIDER_LEN];
    int devices_found;
    int devices_registered;
    int errors;
    time_t discovery_time;
    int success;
} ozayn_dio_discovery_result_t;

/* ============================================================
 * SECTION 17 — STATISTICS
 * ============================================================ */

typedef struct {
    uint64_t total_discoveries;
    uint64_t total_devices_registered;
    uint64_t total_devices_unregistered;
    uint64_t total_devices_updated;
    uint64_t total_capabilities_added;
    uint64_t total_capabilities_removed;
    uint64_t total_reservations_created;
    uint64_t total_reservations_activated;
    uint64_t total_reservations_released;
    uint64_t total_reservations_cancelled;
    uint64_t total_reservations_expired;
    uint64_t total_reservations_failed;
    uint64_t total_activations;
    uint64_t total_releases;
    uint64_t total_state_changes;
    uint64_t total_events_emitted;
    uint64_t total_validation_failures;
    uint64_t total_errors;
    int current_active_devices;
    int current_active_reservations;
    int current_discoveries_in_progress;
} ozayn_dio_stats_t;

/* ============================================================
 * SECTION 18 — SERVICE CONFIGURATION
 * ============================================================ */

typedef struct {
    void *component_registry;
    void *resource_manager;
    void *safety_engine;
    void *diagnostics;
    void *audit;
    int max_devices;
    int max_reservations;
    int max_events;
    int reservation_ttl_ms;
} ozayn_dio_service_config_t;

/* ============================================================
 * SECTION 19 — SERVICE STATE
 * ============================================================ */

typedef struct {
    int initialized;
    ozayn_dio_device_desc_t devices[OZAYN_DIO_MAX_DEVICES];
    int device_count;
    uint32_t device_sequence;

    ozayn_dio_reservation_t reservations[OZAYN_DIO_MAX_RESERVATIONS];
    int reservation_count;
    uint32_t reservation_sequence;

    ozayn_dio_event_t events[OZAYN_DIO_MAX_EVENTS];
    int event_head;
    int event_count;
    uint32_t event_sequence;

    ozayn_dio_discovery_result_t last_discovery;
    int discovery_in_progress;

    ozayn_dio_stats_t stats;
    ozayn_dio_service_config_t config;
} ozayn_dio_service_t;

/* ============================================================
 * SECTION 20 — LIFECYCLE
 * ============================================================ */

ozayn_dio_err_t ozayn_dio_service_init(ozayn_dio_service_t *svc,
                                        const ozayn_dio_service_config_t *cfg);
void ozayn_dio_service_shutdown(ozayn_dio_service_t *svc);
int ozayn_dio_service_is_initialized(const ozayn_dio_service_t *svc);
ozayn_dio_service_t *ozayn_dio_get_global(void);

/* ============================================================
 * SECTION 21 — DEVICE REGISTRY
 * ============================================================ */

ozayn_dio_err_t ozayn_dio_device_register(ozayn_dio_service_t *svc,
                                           const ozayn_dio_device_desc_t *desc,
                                           ozayn_dio_device_desc_t **out_device);
ozayn_dio_err_t ozayn_dio_device_unregister(ozayn_dio_service_t *svc,
                                             const char *device_id);
const ozayn_dio_device_desc_t *ozayn_dio_device_get(
    const ozayn_dio_service_t *svc,
    const char *device_id);
const ozayn_dio_device_desc_t *ozayn_dio_device_get_by_type(
    const ozayn_dio_service_t *svc,
    ozayn_dio_device_type_t type);
int ozayn_dio_device_exists(const ozayn_dio_service_t *svc,
                            const char *device_id);
int ozayn_dio_device_count(const ozayn_dio_service_t *svc);
int ozayn_dio_device_full(const ozayn_dio_service_t *svc);

/* ============================================================
 * SECTION 22 — DEVICE STATE MANAGEMENT
 * ============================================================ */

ozayn_dio_err_t ozayn_dio_device_update_state(ozayn_dio_service_t *svc,
                                               const char *device_id,
                                               ozayn_dio_device_state_t state);
ozayn_dio_err_t ozayn_dio_device_update_availability(
    ozayn_dio_service_t *svc,
    const char *device_id,
    ozayn_dio_availability_t availability);
ozayn_dio_err_t ozayn_dio_device_update_health(ozayn_dio_service_t *svc,
                                                const char *device_id,
                                                ozayn_dio_health_t health);

/* ============================================================
 * SECTION 23 — DEVICE CAPABILITIES
 * ============================================================ */

ozayn_dio_err_t ozayn_dio_capability_add(ozayn_dio_service_t *svc,
                                          const char *device_id,
                                          const ozayn_dio_capability_t *cap);
ozayn_dio_err_t ozayn_dio_capability_remove(ozayn_dio_service_t *svc,
                                             const char *device_id,
                                             ozayn_dio_capability_type_t type);
const ozayn_dio_capability_t *ozayn_dio_capability_get(
    const ozayn_dio_service_t *svc,
    const char *device_id,
    ozayn_dio_capability_type_t type);
int ozayn_dio_capability_count(const ozayn_dio_service_t *svc,
                               const char *device_id);
int ozayn_dio_capability_is_available(const ozayn_dio_service_t *svc,
                                      const char *device_id,
                                      ozayn_dio_capability_type_t type);

/* ============================================================
 * SECTION 24 — DEVICE RESERVATIONS
 * ============================================================ */

ozayn_dio_err_t ozayn_dio_reservation_create(ozayn_dio_service_t *svc,
                                              const char *device_id,
                                              const char *requester_ref,
                                              const char *session_ref,
                                              ozayn_dio_capability_type_t capability,
                                              ozayn_dio_reservation_t **out_reservation);
ozayn_dio_err_t ozayn_dio_reservation_activate(ozayn_dio_service_t *svc,
                                                const char *reservation_id);
ozayn_dio_err_t ozayn_dio_reservation_release(ozayn_dio_service_t *svc,
                                               const char *reservation_id);
ozayn_dio_err_t ozayn_dio_reservation_cancel(ozayn_dio_service_t *svc,
                                              const char *reservation_id);
const ozayn_dio_reservation_t *ozayn_dio_reservation_get(
    const ozayn_dio_service_t *svc,
    const char *reservation_id);
int ozayn_dio_reservation_count(const ozayn_dio_service_t *svc);
int ozayn_dio_reservation_count_by_device(const ozayn_dio_service_t *svc,
                                          const char *device_id);

/* ============================================================
 * SECTION 25 — DEVICE DISCOVERY
 * ============================================================ */

typedef void (*ozayn_dio_discover_cb_t)(const char *device_name,
                                        ozayn_dio_device_type_t type,
                                        const char *provider,
                                        void *context);

ozayn_dio_err_t ozayn_dio_discover(ozayn_dio_service_t *svc,
                                    ozayn_dio_discover_cb_t callback,
                                    void *context,
                                    int timeout_ms,
                                    ozayn_dio_discovery_result_t *out_result);

/* ============================================================
 * SECTION 26 — DEVICE ACCESS LIFECYCLE
 * ============================================================ */

ozayn_dio_err_t ozayn_dio_device_reserve(ozayn_dio_service_t *svc,
                                          const char *device_id,
                                          const char *requester_ref,
                                          const char *session_ref,
                                          ozayn_dio_capability_type_t capability,
                                          ozayn_dio_reservation_t **out_reservation);
ozayn_dio_err_t ozayn_dio_device_activate(ozayn_dio_service_t *svc,
                                           const char *device_id,
                                           const char *reservation_id);
ozayn_dio_err_t ozayn_dio_device_release(ozayn_dio_service_t *svc,
                                          const char *device_id,
                                          const char *reservation_id);

/* ============================================================
 * SECTION 27 — DEVICE DISCONNECT / RECONNECT
 * ============================================================ */

ozayn_dio_err_t ozayn_dio_device_disconnect(ozayn_dio_service_t *svc,
                                             const char *device_id);
ozayn_dio_err_t ozayn_dio_device_reconnect(ozayn_dio_service_t *svc,
                                            const char *device_id,
                                            const ozayn_dio_device_desc_t *desc);

/* ============================================================
 * SECTION 28 — EVENTS
 * ============================================================ */

ozayn_dio_err_t ozayn_dio_emit_event(ozayn_dio_service_t *svc,
                                      ozayn_dio_event_type_t type,
                                      const char *device_id,
                                      const char *message);
const ozayn_dio_event_t *ozayn_dio_event_get(const ozayn_dio_service_t *svc,
                                              int index);
int ozayn_dio_event_count(const ozayn_dio_service_t *svc);

/* ============================================================
 * SECTION 29 — CLEANUP
 * ============================================================ */

int ozayn_dio_cleanup_expired_reservations(ozayn_dio_service_t *svc);
int ozayn_dio_cleanup_all(ozayn_dio_service_t *svc);

/* ============================================================
 * SECTION 30 — STATISTICS
 * ============================================================ */

ozayn_dio_err_t ozayn_dio_get_stats(const ozayn_dio_service_t *svc,
                                     ozayn_dio_stats_t *out_stats);

/* ============================================================
 * SECTION 31 — VALIDATION
 * ============================================================ */

int ozayn_dio_device_validate(const ozayn_dio_device_desc_t *desc);
int ozayn_dio_capability_validate(const ozayn_dio_capability_t *cap);
int ozayn_dio_reservation_validate(const ozayn_dio_reservation_t *res);

/* ============================================================
 * SECTION 32 — NAME HELPERS
 * ============================================================ */

const char *ozayn_dio_device_type_name(ozayn_dio_device_type_t type);
const char *ozayn_dio_device_state_name(ozayn_dio_device_state_t state);
const char *ozayn_dio_availability_name(ozayn_dio_availability_t avail);
const char *ozayn_dio_health_name(ozayn_dio_health_t health);
const char *ozayn_dio_capability_type_name(ozayn_dio_capability_type_t cap);
const char *ozayn_dio_cap_state_name(ozayn_dio_cap_state_t state);
const char *ozayn_dio_access_mode_name(ozayn_dio_access_mode_t mode);
const char *ozayn_dio_reservation_state_name(ozayn_dio_reservation_state_t state);
const char *ozayn_dio_event_type_name(ozayn_dio_event_type_t type);
const char *ozayn_dio_err_name(ozayn_dio_err_t err);

#endif /* OZAYN_DEVICE_IO_H */
