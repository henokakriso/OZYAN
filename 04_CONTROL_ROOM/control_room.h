/*
 * control_room.h — Control Room Foundation (Step 01).
 *
 * The Control Room is the operational center of OZAYN. It provides a
 * unified environment for monitoring and controlling OZAYN capabilities:
 *
 *   Monitoring    Control     Event Observation
 *      |              |              |
 *      +--------+-----+------+------+
 *               |            |
 *          CONTROL ROOM CORE
 *               |
 *          CONTROL ROOM API
 *               |
 *   +-----------+-----------+
 *   |           |           |
 * FUTURE GUI FUTURE INPUT FUTURE OUTPUT
 *
 * The Control Room is NOT the GUI. It is the operational backend
 * that a future GUI consumes. It coordinates existing systems rather
 * than replacing them.
 *
 * No AI/ML, no arbitrary command execution, no security bypass,
 * no autonomous control, no GUI, no voice, no gesture, no face
 * recognition, no ARWE integration.
 */

#ifndef OZAYN_CONTROL_ROOM_H
#define OZAYN_CONTROL_ROOM_H

#include <stdint.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================
 * SECTION 1 — ERROR CODES
 * ============================================================ */

typedef enum {
    OZAYN_CR_OK                              =   0,
    OZAYN_CR_ERR_NULL                        =  -1,
    OZAYN_CR_ERR_NOT_INITIALIZED             =  -2,
    OZAYN_CR_ERR_ALREADY_INITIALIZED         =  -3,
    OZAYN_CR_ERR_INVALID_PARAM               =  -4,
    OZAYN_CR_ERR_LIMIT_REACHED               =  -5,
    OZAYN_CR_ERR_NOT_FOUND                   =  -6,
    OZAYN_CR_ERR_STATE_INVALID               =  -7,
    OZAYN_CR_ERR_STATE_TRANSITION            =  -8,
    OZAYN_CR_ERR_POLICY_REJECTED             =  -9,
    OZAYN_CR_ERR_REQUEST_INVALID             = -10,
    OZAYN_CR_ERR_REQUEST_NOT_FOUND           = -11,
    OZAYN_CR_ERR_REQUEST_UNSUPPORTED         = -12,
    OZAYN_CR_ERR_TARGET_INVALID              = -13,
    OZAYN_CR_ERR_TARGET_NOT_FOUND            = -14,
    OZAYN_CR_ERR_ACTION_INVALID              = -15,
    OZAYN_CR_ERR_ACTION_UNSUPPORTED          = -16,
    OZAYN_CR_ERR_OPERATION_FAILED            = -17,
    OZAYN_CR_ERR_OPERATION_TIMEOUT           = -18,
    OZAYN_CR_ERR_CAPABILITY_INVALID          = -19,
    OZAYN_CR_ERR_CAPABILITY_UNAVAILABLE      = -20,
    OZAYN_CR_ERR_CAPABILITY_NOT_SUPPORTED    = -21,
    OZAYN_CR_ERR_EVENT_INVALID               = -22,
    OZAYN_CR_ERR_MONITOR_INVALID             = -23,
    OZAYN_CR_ERR_MONITOR_UNAVAILABLE         = -24,
    OZAYN_CR_ERR_UNAVAILABLE                 = -25
} ozayn_cr_err_t;

/* ============================================================
 * SECTION 2 — LIFECYCLE STATES
 * ============================================================ */

typedef enum {
    OZAYN_CR_LC_UNINITIALIZED                = 0,
    OZAYN_CR_LC_INITIALIZING                 = 1,
    OZAYN_CR_LC_READY                        = 2,
    OZAYN_CR_LC_ACTIVE                       = 3,
    OZAYN_CR_LC_STOPPING                     = 4,
    OZAYN_CR_LC_STOPPED                      = 5,
    OZAYN_CR_LC_ERROR                        = 6
} ozayn_cr_lifecycle_t;

/* ============================================================
 * SECTION 3 — COMPONENT STATES (for monitoring)
 * ============================================================ */

typedef enum {
    OZAYN_CR_COMP_UNKNOWN                    = 0,
    OZAYN_CR_COMP_INITIALIZING               = 1,
    OZAYN_CR_COMP_READY                      = 2,
    OZAYN_CR_COMP_ACTIVE                     = 3,
    OZAYN_CR_COMP_PAUSED                     = 4,
    OZAYN_CR_COMP_STOPPING                   = 5,
    OZAYN_CR_COMP_STOPPED                    = 6,
    OZAYN_CR_COMP_DEGRADED                   = 7,
    OZAYN_CR_COMP_ERROR                      = 8,
    OZAYN_CR_COMP_UNAVAILABLE                = 9
} ozayn_cr_comp_state_t;

/* ============================================================
 * SECTION 4 — COMPONENT TYPES
 * ============================================================ */

typedef enum {
    OZAYN_CR_COMP_TYPE_CORE                  = 0,
    OZAYN_CR_COMP_TYPE_MODULE                = 1,
    OZAYN_CR_COMP_TYPE_TASK                  = 2,
    OZAYN_CR_COMP_TYPE_PROCESS               = 3,
    OZAYN_CR_COMP_TYPE_SECURITY              = 4,
    OZAYN_CR_COMP_TYPE_DEVICE                = 5,
    OZAYN_CR_COMP_TYPE_INPUT                 = 6,
    OZAYN_CR_COMP_TYPE_OUTPUT                = 7,
    OZAYN_CR_COMP_TYPE_VISION                = 8,
    OZAYN_CR_COMP_TYPE_AI                    = 9,
    OZAYN_CR_COMP_TYPE_ARWE                  = 10,
    OZAYN_CR_COMP_TYPE_CUSTOM                = 11
} ozayn_cr_comp_type_t;

/* ============================================================
 * SECTION 5 — CAPABILITY TYPES
 * ============================================================ */

typedef enum {
    OZAYN_CR_CAP_CORE_MONITORING             = 0,
    OZAYN_CR_CAP_MODULE_MONITORING           = 1,
    OZAYN_CR_CAP_TASK_MONITORING             = 2,
    OZAYN_CR_CAP_PROCESS_MONITORING          = 3,
    OZAYN_CR_CAP_MODULE_CONTROL              = 4,
    OZAYN_CR_CAP_TASK_CONTROL                = 5,
    OZAYN_CR_CAP_PROCESS_CONTROL             = 6,
    OZAYN_CR_CAP_DEVICE_MONITORING           = 7,
    OZAYN_CR_CAP_DEVICE_CONTROL              = 8,
    OZAYN_CR_CAP_CAMERA_INPUT                = 9,
    OZAYN_CR_CAP_MICROPHONE_INPUT            = 10,
    OZAYN_CR_CAP_VOICE_INPUT                 = 11,
    OZAYN_CR_CAP_GESTURE_INPUT               = 12,
    OZAYN_CR_CAP_FACE_INPUT                  = 13,
    OZAYN_CR_CAP_VISION_PROCESSING           = 14,
    OZAYN_CR_CAP_3D_RENDERING                = 15,
    OZAYN_CR_CAP_AI_PROCESSING               = 16,
    OZAYN_CR_CAP_MEMORY_ACCESS               = 17,
    OZAYN_CR_CAP_ARWE_INTEGRATION            = 18,
    OZAYN_CR_CAP_WEB_INTELLIGENCE            = 19,
    OZAYN_CR_CAP_SECURITY_MONITORING         = 20,
    OZAYN_CR_CAP_SECURITY_CONTROL            = 21,
    OZAYN_CR_CAP_COUNT
} ozayn_cr_cap_type_t;

/* ============================================================
 * SECTION 6 — CONTROL ACTIONS
 * ============================================================ */

typedef enum {
    OZAYN_CR_ACTION_START                    = 0,
    OZAYN_CR_ACTION_STOP                     = 1,
    OZAYN_CR_ACTION_PAUSE                    = 2,
    OZAYN_CR_ACTION_RESUME                   = 3,
    OZAYN_CR_ACTION_QUERY                    = 4,
    OZAYN_CR_ACTION_RESTART                  = 5,
    OZAYN_CR_ACTION_ENABLE                   = 6,
    OZAYN_CR_ACTION_DISABLE                  = 7,
    OZAYN_CR_ACTION_DIAGNOSTIC               = 8,
    OZAYN_CR_ACTION_COUNT
} ozayn_cr_action_t;

/* ============================================================
 * SECTION 7 — CONTROL REQUEST STATES
 * ============================================================ */

typedef enum {
    OZAYN_CR_REQ_STATE_CREATED               = 0,
    OZAYN_CR_REQ_STATE_VALIDATED             = 1,
    OZAYN_CR_REQ_STATE_AUTHORIZED            = 2,
    OZAYN_CR_REQ_STATE_ACCEPTED              = 3,
    OZAYN_CR_REQ_STATE_RUNNING               = 4,
    OZAYN_CR_REQ_STATE_SUCCEEDED             = 5,
    OZAYN_CR_REQ_STATE_FAILED                = 6,
    OZAYN_CR_REQ_STATE_CANCELLED             = 7,
    OZAYN_CR_REQ_STATE_TIMEOUT               = 8,
    OZAYN_CR_REQ_STATE_REJECTED              = 9,
    OZAYN_CR_REQ_STATE_UNAVAILABLE           = 10,
    OZAYN_CR_REQ_STATE_UNSUPPORTED           = 11
} ozayn_cr_req_state_t;

/* ============================================================
 * SECTION 8 — CONTROL RESULT STATES
 * ============================================================ */

typedef enum {
    OZAYN_CR_RESULT_ACCEPTED                 = 0,
    OZAYN_CR_RESULT_REJECTED                 = 1,
    OZAYN_CR_RESULT_PENDING                  = 2,
    OZAYN_CR_RESULT_RUNNING                  = 3,
    OZAYN_CR_RESULT_SUCCEEDED                = 4,
    OZAYN_CR_RESULT_FAILED                   = 5,
    OZAYN_CR_RESULT_CANCELLED                = 6,
    OZAYN_CR_RESULT_TIMEOUT                  = 7,
    OZAYN_CR_RESULT_UNAVAILABLE              = 8,
    OZAYN_CR_RESULT_UNSUPPORTED              = 9
} ozayn_cr_result_state_t;

/* ============================================================
 * SECTION 9 — CONTROL ROOM CORE STATE
 * ============================================================ */

typedef enum {
    OZAYN_CR_CORE_STATE_UNKNOWN              = 0,
    OZAYN_CR_CORE_STATE_STARTING             = 1,
    OZAYN_CR_CORE_STATE_ONLINE               = 2,
    OZAYN_CR_CORE_STATE_DEGRADED             = 3,
    OZAYN_CR_CORE_STATE_SHUTTING_DOWN        = 4,
    OZAYN_CR_CORE_STATE_OFFLINE              = 5,
    OZAYN_CR_CORE_STATE_ERROR                = 6
} ozayn_cr_core_state_t;

/* ============================================================
 * SECTION 10 — LIMITS
 * ============================================================ */

#define OZAYN_CR_MAX_ID_LEN                  64
#define OZAYN_CR_MAX_TARGET_LEN              64
#define OZAYN_CR_MAX_META_LEN               256
#define OZAYN_CR_MAX_COMPONENTS              64
#define OZAYN_CR_MAX_CAPABILITIES            64
#define OZAYN_CR_MAX_REQUESTS               128
#define OZAYN_CR_MAX_EVENTS                 256
#define OZAYN_CR_MAX_MONITORS                64

/* ============================================================
 * SECTION 11 — CONTROL REQUEST
 * ============================================================ */

typedef struct {
    char                    request_id[OZAYN_CR_MAX_ID_LEN];
    uint32_t                request_version;
    ozayn_cr_action_t       action;
    char                    target[OZAYN_CR_MAX_TARGET_LEN];
    char                    context[OZAYN_CR_MAX_META_LEN];
    ozayn_cr_req_state_t    state;
    ozayn_cr_result_state_t result_state;
    int                     result_code;
    time_t                  request_time;
    time_t                  completion_time;
    char                    metadata[OZAYN_CR_MAX_META_LEN];
} ozayn_cr_request_t;

/* ============================================================
 * SECTION 12 — CONTROL RESULT
 * ============================================================ */

typedef struct {
    char                    request_id[OZAYN_CR_MAX_ID_LEN];
    ozayn_cr_result_state_t result_state;
    char                    target[OZAYN_CR_MAX_TARGET_LEN];
    ozayn_cr_action_t       action;
    int                     result_code;
    time_t                  completion_time;
    char                    safe_metadata[OZAYN_CR_MAX_META_LEN];
} ozayn_cr_result_t;

/* ============================================================
 * SECTION 13 — COMPONENT MONITOR
 * ============================================================ */

typedef struct {
    char                    component_id[OZAYN_CR_MAX_ID_LEN];
    ozayn_cr_comp_type_t    component_type;
    ozayn_cr_comp_state_t   state;
    int                     availability;
    int                     health;
    time_t                  last_update;
    char                    metadata[OZAYN_CR_MAX_META_LEN];
} ozayn_cr_monitor_t;

/* ============================================================
 * SECTION 14 — CAPABILITY ENTRY
 * ============================================================ */

typedef struct {
    ozayn_cr_cap_type_t     type;
    int                     enabled;
    int                     available;
    char                    description[OZAYN_CR_MAX_META_LEN];
} ozayn_cr_capability_t;

/* ============================================================
 * SECTION 15 — CONTROL ROOM STATE SNAPSHOT
 * ============================================================ */

typedef struct {
    ozayn_cr_lifecycle_t    lifecycle;
    ozayn_cr_core_state_t   core_state;
    uint32_t                version;
    time_t                  start_time;
    time_t                  last_update;
    int                     component_count;
    int                     active_requests;
    int                     event_count;
    int                     capability_count;
    char                    safe_status[OZAYN_CR_MAX_META_LEN];
} ozayn_cr_state_t;

/* ============================================================
 * SECTION 16 — CONTROL ROOM EVENT
 * ============================================================ */

typedef struct {
    int                     event_type;
    char                    source[OZAYN_CR_MAX_ID_LEN];
    time_t                  timestamp;
    char                    detail[OZAYN_CR_MAX_META_LEN];
} ozayn_cr_event_entry_t;

/* ============================================================
 * SECTION 17 — POLICY
 * ============================================================ */

typedef struct {
    int                     enabled;
    int                     max_components;
    int                     max_capabilities;
    int                     max_requests;
    int                     max_events;
    int                     max_monitors;
    int                     require_authorization;
    int                     require_approval;
} ozayn_cr_policy_t;

/* ============================================================
 * SECTION 18 — SERVICE CONFIGURATION
 * ============================================================ */

typedef struct {
    void                   *audit;
} ozayn_cr_service_config_t;

/* ============================================================
 * SECTION 19 — SERVICE STATE
 * ============================================================ */

typedef struct {
    int                     initialized;
    ozayn_cr_lifecycle_t    lifecycle;
    ozayn_cr_core_state_t   core_state;
    uint32_t                version;
    time_t                  start_time;
    time_t                  last_update;

    /* Components */
    ozayn_cr_monitor_t      components[OZAYN_CR_MAX_COMPONENTS];
    int                     component_count;

    /* Capabilities */
    ozayn_cr_capability_t   capabilities[OZAYN_CR_MAX_CAPABILITIES];
    int                     capability_count;

    /* Requests */
    ozayn_cr_request_t      requests[OZAYN_CR_MAX_REQUESTS];
    int                     request_head;
    int                     request_count;
    uint32_t                request_sequence;

    /* Event observation */
    ozayn_cr_event_entry_t  events[OZAYN_CR_MAX_EVENTS];
    int                     event_head;
    int                     event_count;

    /* Monitors */
    ozayn_cr_monitor_t      monitors[OZAYN_CR_MAX_MONITORS];
    int                     monitor_count;

    /* Policy */
    ozayn_cr_policy_t       policy;

    /* Dependencies (not owned) */
    void                   *audit;

    /* Statistics */
    uint64_t                total_requests_created;
    uint64_t                total_requests_succeeded;
    uint64_t                total_requests_failed;
    uint64_t                total_requests_rejected;
    uint64_t                total_events_observed;
    uint64_t                total_components_registered;
    uint64_t                total_capabilities_registered;
    uint64_t                total_state_queries;
} ozayn_cr_service_t;

/* ============================================================
 * SECTION 20 — NAME HELPERS — ERRORS
 * ============================================================ */

const char *ozayn_cr_err_name(ozayn_cr_err_t err);

/* ============================================================
 * SECTION 21 — NAME HELPERS — LIFECYCLE
 * ============================================================ */

const char *ozayn_cr_lifecycle_name(ozayn_cr_lifecycle_t lc);

/* ============================================================
 * SECTION 22 — NAME HELPERS — COMPONENT STATE
 * ============================================================ */

const char *ozayn_cr_comp_state_name(ozayn_cr_comp_state_t s);

/* ============================================================
 * SECTION 23 — NAME HELPERS — COMPONENT TYPE
 * ============================================================ */

const char *ozayn_cr_comp_type_name(ozayn_cr_comp_type_t t);

/* ============================================================
 * SECTION 24 — NAME HELPERS — CAPABILITY TYPE
 * ============================================================ */

const char *ozayn_cr_cap_type_name(ozayn_cr_cap_type_t t);

/* ============================================================
 * SECTION 25 — NAME HELPERS — ACTION
 * ============================================================ */

const char *ozayn_cr_action_name(ozayn_cr_action_t a);

/* ============================================================
 * SECTION 26 — NAME HELPERS — REQUEST STATE
 * ============================================================ */

const char *ozayn_cr_req_state_name(ozayn_cr_req_state_t s);

/* ============================================================
 * SECTION 27 — NAME HELPERS — RESULT STATE
 * ============================================================ */

const char *ozayn_cr_result_state_name(ozayn_cr_result_state_t s);

/* ============================================================
 * SECTION 28 — NAME HELPERS — CORE STATE
 * ============================================================ */

const char *ozayn_cr_core_state_name(ozayn_cr_core_state_t s);

/* ============================================================
 * SECTION 29 — LIFECYCLE
 * ============================================================ */

ozayn_cr_err_t ozayn_cr_service_init(
    ozayn_cr_service_t *svc,
    const ozayn_cr_service_config_t *cfg);

void ozayn_cr_service_shutdown(ozayn_cr_service_t *svc);

int ozayn_cr_service_is_initialized(const ozayn_cr_service_t *svc);

/* ============================================================
 * SECTION 30 — STATE QUERY
 * ============================================================ */

ozayn_cr_err_t ozayn_cr_get_state(
    const ozayn_cr_service_t *svc,
    ozayn_cr_state_t *out_state);

/* ============================================================
 * SECTION 31 — LIFECYCLE TRANSITIONS
 * ============================================================ */

ozayn_cr_err_t ozayn_cr_activate(ozayn_cr_service_t *svc);
ozayn_cr_err_t ozayn_cr_deactivate(ozayn_cr_service_t *svc);
ozayn_cr_err_t ozayn_cr_set_error(ozayn_cr_service_t *svc);

/* ============================================================
 * SECTION 32 — COMPONENT REGISTRATION
 * ============================================================ */

ozayn_cr_err_t ozayn_cr_register_component(
    ozayn_cr_service_t *svc,
    const char *component_id,
    ozayn_cr_comp_type_t type,
    ozayn_cr_comp_state_t initial_state);

ozayn_cr_monitor_t *ozayn_cr_get_component(
    ozayn_cr_service_t *svc,
    const char *component_id);

int ozayn_cr_component_count(const ozayn_cr_service_t *svc);

ozayn_cr_err_t ozayn_cr_update_component_state(
    ozayn_cr_service_t *svc,
    const char *component_id,
    ozayn_cr_comp_state_t new_state);

/* ============================================================
 * SECTION 33 — CAPABILITY REGISTRATION
 * ============================================================ */

ozayn_cr_err_t ozayn_cr_register_capability(
    ozayn_cr_service_t *svc,
    ozayn_cr_cap_type_t type,
    int available,
    const char *description);

ozayn_cr_capability_t *ozayn_cr_get_capability(
    ozayn_cr_service_t *svc,
    ozayn_cr_cap_type_t type);

int ozayn_cr_capability_count(const ozayn_cr_service_t *svc);

int ozayn_cr_capability_available(
    const ozayn_cr_service_t *svc,
    ozayn_cr_cap_type_t type);

/* ============================================================
 * SECTION 34 — CONTROL REQUESTS
 * ============================================================ */

ozayn_cr_err_t ozayn_cr_create_request(
    ozayn_cr_service_t *svc,
    ozayn_cr_action_t action,
    const char *target,
    const char *context,
    ozayn_cr_request_t **out_request);

ozayn_cr_request_t *ozayn_cr_get_request(
    ozayn_cr_service_t *svc,
    const char *request_id);

int ozayn_cr_request_count(const ozayn_cr_service_t *svc);

/* ============================================================
 * SECTION 35 — CONTROL EXECUTION
 * ============================================================ */

ozayn_cr_err_t ozayn_cr_validate_request(
    const ozayn_cr_service_t *svc,
    const ozayn_cr_request_t *request);

ozayn_cr_err_t ozayn_cr_execute_request(
    ozayn_cr_service_t *svc,
    ozayn_cr_request_t *request,
    ozayn_cr_result_t *out_result);

/* ============================================================
 * SECTION 36 — EVENT OBSERVATION
 * ============================================================ */

ozayn_cr_err_t ozayn_cr_observe_event(
    ozayn_cr_service_t *svc,
    int event_type,
    const char *source,
    const char *detail);

int ozayn_cr_event_count(const ozayn_cr_service_t *svc);

/* ============================================================
 * SECTION 37 — MONITOR MANAGEMENT
 * ============================================================ */

ozayn_cr_err_t ozayn_cr_create_monitor(
    ozayn_cr_service_t *svc,
    const char *component_id,
    ozayn_cr_comp_type_t type,
    ozayn_cr_monitor_t **out_monitor);

ozayn_cr_monitor_t *ozayn_cr_get_monitor(
    ozayn_cr_service_t *svc,
    const char *component_id);

int ozayn_cr_monitor_count(const ozayn_cr_service_t *svc);

ozayn_cr_err_t ozayn_cr_update_monitor(
    ozayn_cr_service_t *svc,
    const char *component_id,
    ozayn_cr_comp_state_t state,
    int availability,
    int health);

/* ============================================================
 * SECTION 38 — POLICY
 * ============================================================ */

ozayn_cr_policy_t ozayn_cr_default_policy(void);

ozayn_cr_err_t ozayn_cr_set_policy(
    ozayn_cr_service_t *svc,
    const ozayn_cr_policy_t *policy);

const ozayn_cr_policy_t *ozayn_cr_get_policy(const ozayn_cr_service_t *svc);

/* ============================================================
 * SECTION 39 — AUDIT INTEGRATION
 * ============================================================ */

ozayn_cr_err_t ozayn_cr_audit_event(
    ozayn_cr_service_t *svc,
    const char *event_type,
    const char *detail);

/* ============================================================
 * SECTION 40 — RESOURCE SAFETY
 * ============================================================ */

int ozayn_cr_components_full(const ozayn_cr_service_t *svc);
int ozayn_cr_capabilities_full(const ozayn_cr_service_t *svc);
int ozayn_cr_requests_full(const ozayn_cr_service_t *svc);
int ozayn_cr_events_full(const ozayn_cr_service_t *svc);

/* ============================================================
 * SECTION 41 — STATISTICS
 * ============================================================ */

uint64_t ozayn_cr_total_requests(const ozayn_cr_service_t *svc);
uint64_t ozayn_cr_total_events(const ozayn_cr_service_t *svc);

/* ============================================================
 * SECTION 42 — CLEANUP
 * ============================================================ */

int ozayn_cr_cleanup_expired_requests(ozayn_cr_service_t *svc);
int ozayn_cr_cleanup_expired_events(ozayn_cr_service_t *svc);

/* ============================================================
 * SECTION 43 — GLOBAL ACCESSOR
 * ============================================================ */

ozayn_cr_service_t *ozayn_cr_get_global(void);

#ifdef __cplusplus
}
#endif

#endif /* OZAYN_CONTROL_ROOM_H */
