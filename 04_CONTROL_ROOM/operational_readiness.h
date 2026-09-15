#ifndef OZAYN_OPERATIONAL_READINESS_H
#define OZAYN_OPERATIONAL_READINESS_H

#include <stdint.h>

/* ============================================================
 * SECTION 1 — ERRORS
 * ============================================================ */

typedef enum {
    OZAYN_ORD_OK                        =   0,
    OZAYN_ORD_ERR_NULL                  =  -1,
    OZAYN_ORD_ERR_NOT_INITIALIZED       =  -2,
    OZAYN_ORD_ERR_ALREADY_INITIALIZED   =  -3,
    OZAYN_ORD_ERR_INVALID_PARAM         =  -4,
    OZAYN_ORD_ERR_STATE_INVALID         =  -5,
    OZAYN_ORD_ERR_MODE_TRANSITION_INVALID = -6,
    OZAYN_ORD_ERR_MODE_TRANSITION_REJECTED = -7,
    OZAYN_ORD_ERR_MODE_TRANSITION_FAILED = -8,
    OZAYN_ORD_ERR_ASSESSMENT_FAILED     =  -9,
    OZAYN_ORD_ERR_OPERATION_GATED       = -10,
    OZAYN_ORD_ERR_CONCURRENCY_ERROR     = -11,
    OZAYN_ORD_ERR_LIMIT_REACHED         = -12,
    OZAYN_ORD_ERR_CONFIGURATION_ERROR   = -13,
    OZAYN_ORD_ERR_UNAVAILABLE           = -14,
    OZAYN_ORD_ERR_NOT_FOUND             = -15
} ozayn_ord_err_t;

/* ============================================================
 * SECTION 2 — RUNTIME MODES
 * ============================================================ */

typedef enum {
    OZAYN_ORD_MODE_UNKNOWN = 0,
    OZAYN_ORD_MODE_INITIALIZING,
    OZAYN_ORD_MODE_READY,
    OZAYN_ORD_MODE_READY_DEGRADED,
    OZAYN_ORD_MODE_RECOVERY,
    OZAYN_ORD_MODE_MAINTENANCE,
    OZAYN_ORD_MODE_SAFE_HOLD,
    OZAYN_ORD_MODE_BLOCKED,
    OZAYN_ORD_MODE_SHUTTING_DOWN,
    OZAYN_ORD_MODE_FAILED,
    OZAYN_ORD_MODE_COUNT
} ozayn_ord_mode_t;

/* ============================================================
 * SECTION 3 — OPERATION CLASSES
 * ============================================================ */

typedef enum {
    OZAYN_ORD_OPCLASS_NORMAL = 0,
    OZAYN_ORD_OPCLASS_DIAGNOSTIC,
    OZAYN_ORD_OPCLASS_RECOVERY,
    OZAYN_ORD_OPCLASS_SHUTDOWN,
    OZAYN_ORD_OPCLASS_MAINTENANCE,
    OZAYN_ORD_OPCLASS_COUNT
} ozayn_ord_opclass_t;

/* ============================================================
 * SECTION 4 — GATING DECISIONS
 * ============================================================ */

typedef enum {
    OZAYN_ORD_GATE_ALLOWED = 0,
    OZAYN_ORD_GATE_RESTRICTED,
    OZAYN_ORD_GATE_BLOCKED,
    OZAYN_ORD_GATE_UNAVAILABLE
} ozayn_ord_gate_decision_t;

/* ============================================================
 * SECTION 5 — TRANSITION TRIGGERS
 * ============================================================ */

typedef enum {
    OZAYN_ORD_TRIGGER_NONE = 0,
    OZAYN_ORD_TRIGGER_MANUAL,
    OZAYN_ORD_TRIGGER_ASSESSMENT,
    OZAYN_ORD_TRIGGER_EVENT,
    OZAYN_ORD_TRIGGER_SAFETY,
    OZAYN_ORD_TRIGGER_SECURITY,
    OZAYN_ORD_TRIGGER_RESOURCE,
    OZAYN_ORD_TRIGGER_DEVICE,
    OZAYN_ORD_TRIGGER_RECOVERY,
    OZAYN_ORD_TRIGGER_STARTUP,
    OZAYN_ORD_TRIGGER_SHUTDOWN,
    OZAYN_ORD_TRIGGER_FAILURE,
    OZAYN_ORD_TRIGGER_MAINTENANCE_REQUEST,
    OZAYN_ORD_TRIGGER_COUNT
} ozayn_ord_trigger_t;

/* ============================================================
 * SECTION 6 — ASSESSMENT DECISIONS
 * ============================================================ */

typedef enum {
    OZAYN_ORD_ASSESS_NO_CHANGE = 0,
    OZAYN_ORD_ASSESS_MAINTAIN_MODE,
    OZAYN_ORD_ASSESS_TRANSITION_RECOMMENDED,
    OZAYN_ORD_ASSESS_TRANSITION_REQUIRED,
    OZAYN_ORD_ASSESS_UNAVAILABLE
} ozayn_ord_assess_decision_t;

/* ============================================================
 * SECTION 7 — CONDITION STATUS
 * ============================================================ */

typedef enum {
    OZAYN_ORD_CONDITION_UNSATISFIED = 0,
    OZAYN_ORD_CONDITION_SATISFIED,
    OZAYN_ORD_CONDITION_FAILED,
    OZAYN_ORD_CONDITION_UNKNOWN,
    OZAYN_ORD_CONDITION_WARNING
} ozayn_ord_condition_status_t;

/* ============================================================
 * SECTION 8 — SUBSYSTEM STATUS
 * ============================================================ */

typedef enum {
    OZAYN_ORD_SUBSYS_UNKNOWN = 0,
    OZAYN_ORD_SUBSYS_OK,
    OZAYN_ORD_SUBSYS_DEGRADED,
    OZAYN_ORD_SUBSYS_FAILED,
    OZAYN_ORD_SUBSYS_UNAVAILABLE
} ozayn_ord_subsys_status_t;

/* ============================================================
 * SECTION 9 — TRANSITION RESULTS
 * ============================================================ */

typedef enum {
    OZAYN_ORD_TRANSITION_ACCEPTED = 0,
    OZAYN_ORD_TRANSITION_REJECTED,
    OZAYN_ORD_TRANSITION_FAILED,
    OZAYN_ORD_TRANSITION_SKIPPED
} ozayn_ord_transition_result_t;

/* ============================================================
 * SECTION 10 — EVENT TYPES
 * ============================================================ */

typedef enum {
    OZAYN_ORD_EVENT_ASSESSMENT_STARTED = 0,
    OZAYN_ORD_EVENT_ASSESSMENT_COMPLETED,
    OZAYN_ORD_EVENT_MODE_CHANGED,
    OZAYN_ORD_EVENT_TRANSITION_REQUESTED,
    OZAYN_ORD_EVENT_TRANSITION_STARTED,
    OZAYN_ORD_EVENT_TRANSITION_COMPLETED,
    OZAYN_ORD_EVENT_TRANSITION_REJECTED,
    OZAYN_ORD_EVENT_SYSTEM_READY,
    OZAYN_ORD_EVENT_SYSTEM_DEGRADED,
    OZAYN_ORD_EVENT_SYSTEM_RECOVERY,
    OZAYN_ORD_EVENT_SYSTEM_SAFE_HOLD,
    OZAYN_ORD_EVENT_SYSTEM_BLOCKED,
    OZAYN_ORD_EVENT_MAINTENANCE_ENTERED,
    OZAYN_ORD_EVENT_MAINTENANCE_EXITED,
    OZAYN_ORD_EVENT_OPERATION_GATED,
    OZAYN_ORD_EVENT_OPERATION_RELEASED,
    OZAYN_ORD_EVENT_FLAPPING_DETECTED,
    OZAYN_ORD_EVENT_COUNT
} ozayn_ord_event_type_t;

/* ============================================================
 * SECTION 11 — BOUNDED LIMITS
 * ============================================================ */

#define OZAYN_ORD_MAX_ASSESSMENTS       32
#define OZAYN_ORD_MAX_TRANSITIONS       64
#define OZAYN_ORD_MAX_EVENTS            256
#define OZAYN_ORD_MAX_CONDITIONS        16
#define OZAYN_ORD_MAX_WARNINGS          16
#define OZAYN_ORD_MAX_BLOCKING          16
#define OZAYN_ORD_MAX_NAME_LEN          64
#define OZAYN_ORD_MAX_DESC_LEN          128
#define OZAYN_ORD_MAX_ID_LEN            48
#define OZAYN_ORD_FLAP_MIN_MS           500
#define OZAYN_ORD_FLAP_WINDOW_MS        5000
#define OZAYN_ORD_FLAP_THRESHOLD        3
#define OZAYN_ORD_FLAP_COOLDOWN_MS      2000
#define OZAYN_ORD_TRANSITION_HISTORY    16

/* ============================================================
 * SECTION 12 — CONDITION ENTRY
 * ============================================================ */

typedef struct {
    char name[OZAYN_ORD_MAX_NAME_LEN];
    char description[OZAYN_ORD_MAX_DESC_LEN];
    ozayn_ord_condition_status_t status;
    int active;
} ozayn_ord_condition_t;

/* ============================================================
 * SECTION 13 — EVENT ENTRY
 * ============================================================ */

typedef struct {
    ozayn_ord_event_type_t type;
    char id[OZAYN_ORD_MAX_ID_LEN];
    char source[OZAYN_ORD_MAX_NAME_LEN];
    char message[OZAYN_ORD_MAX_DESC_LEN];
    int64_t timestamp_ms;
    int64_t sequence;
} ozayn_ord_event_t;

/* ============================================================
 * SECTION 14 — ASSESSMENT
 * ============================================================ */

typedef struct {
    char id[OZAYN_ORD_MAX_ID_LEN];
    int64_t timestamp_ms;
    ozayn_ord_mode_t current_mode;
    ozayn_ord_mode_t proposed_mode;

    /* Subsystem statuses */
    ozayn_ord_subsys_status_t core_status;
    ozayn_ord_subsys_status_t component_status;
    ozayn_ord_subsys_status_t dependency_status;
    ozayn_ord_subsys_status_t health_status;
    ozayn_ord_subsys_status_t resource_status;
    ozayn_ord_subsys_status_t device_status;
    ozayn_ord_subsys_status_t security_status;
    ozayn_ord_subsys_status_t safety_status;
    ozayn_ord_subsys_status_t recovery_status;
    ozayn_ord_subsys_status_t configuration_status;

    /* Conditions */
    ozayn_ord_condition_t conditions[OZAYN_ORD_MAX_CONDITIONS];
    int condition_count;

    /* Blocking and warnings */
    char blocking[OZAYN_ORD_MAX_BLOCKING][OZAYN_ORD_MAX_DESC_LEN];
    int blocking_count;
    char warnings[OZAYN_ORD_MAX_WARNINGS][OZAYN_ORD_MAX_DESC_LEN];
    int warning_count;

    /* Decision */
    ozayn_ord_assess_decision_t decision;
    ozayn_ord_mode_t recommended_mode;

    int active;
} ozayn_ord_assessment_t;

/* ============================================================
 * SECTION 15 — TRANSITION RECORD
 * ============================================================ */

typedef struct {
    char id[OZAYN_ORD_MAX_ID_LEN];
    ozayn_ord_mode_t previous_mode;
    ozayn_ord_mode_t requested_mode;
    ozayn_ord_mode_t final_mode;
    ozayn_ord_trigger_t trigger;
    char reason[OZAYN_ORD_MAX_DESC_LEN];
    char source[OZAYN_ORD_MAX_NAME_LEN];
    char assessment_id[OZAYN_ORD_MAX_ID_LEN];
    int64_t timestamp_ms;
    ozayn_ord_transition_result_t result;
    int active;
} ozayn_ord_transition_t;

/* ============================================================
 * SECTION 16 — STATS
 * ============================================================ */

typedef struct {
    int total_assessments;
    int total_transitions;
    int total_transition_rejections;
    int total_operations_gated;
    int total_operations_allowed;
    int total_operations_restricted;
    int total_operations_blocked;
    int total_flapping_detections;
    int64_t current_mode_entered_ms;
} ozayn_ord_stats_t;

/* ============================================================
 * SECTION 17 — SERVICE CONFIG
 * ============================================================ */

typedef struct {
    void *component_registry;
    void *resource_manager;
    void *device_session;
    void *safety;
    void *diagnostics;
    void *startup_recovery;
    void *workflow_recovery;
    void *workflow_checkpoint;
    void *audit;
} ozayn_ord_service_config_t;

/* ============================================================
 * SECTION 18 — SERVICE
 * ============================================================ */

typedef struct {
    int initialized;
    int assessment_in_progress;

    /* Current state */
    ozayn_ord_mode_t current_mode;
    ozayn_ord_mode_t previous_mode;

    /* Assessments */
    ozayn_ord_assessment_t assessments[OZAYN_ORD_MAX_ASSESSMENTS];
    int assessment_count;
    int assessment_head;

    /* Transitions */
    ozayn_ord_transition_t transitions[OZAYN_ORD_MAX_TRANSITIONS];
    int transition_count;
    int transition_head;
    int64_t last_transition_ms;

    /* Flapping */
    int64_t flap_timestamps[OZAYN_ORD_FLAP_THRESHOLD];
    int flap_index;
    int flap_count;
    int flapping;
    int64_t flap_cooldown_ms;

    /* Events */
    ozayn_ord_event_t events[OZAYN_ORD_MAX_EVENTS];
    int event_count;
    int event_head;
    int64_t event_sequence;

    /* Blocking conditions */
    char blocking[OZAYN_ORD_MAX_BLOCKING][OZAYN_ORD_MAX_DESC_LEN];
    int blocking_count;

    /* Warnings */
    char warnings[OZAYN_ORD_MAX_WARNINGS][OZAYN_ORD_MAX_DESC_LEN];
    int warning_count;

    /* Subsystem pointers (void* for flexibility) */
    void *component_registry;
    void *resource_manager;
    void *device_session;
    void *safety;
    void *diagnostics;
    void *startup_recovery;
    void *workflow_recovery;
    void *workflow_checkpoint;
    void *audit;

    /* Stats */
    ozayn_ord_stats_t stats;
} ozayn_ord_service_t;

/* ============================================================
 * SECTION 19 — FUNCTION DECLARATIONS
 * ============================================================ */

/* Lifecycle */
ozayn_ord_err_t ozayn_ord_service_init(ozayn_ord_service_t *svc,
    const ozayn_ord_service_config_t *cfg);
ozayn_ord_err_t ozayn_ord_service_shutdown(ozayn_ord_service_t *svc);

/* Global */
ozayn_ord_service_t *ozayn_ord_get_global(void);

/* Subsystem binding */
ozayn_ord_err_t ozayn_ord_set_component_registry(ozayn_ord_service_t *svc, void *ptr);
ozayn_ord_err_t ozayn_ord_set_resource_manager(ozayn_ord_service_t *svc, void *ptr);
ozayn_ord_err_t ozayn_ord_set_device_session(ozayn_ord_service_t *svc, void *ptr);
ozayn_ord_err_t ozayn_ord_set_safety(ozayn_ord_service_t *svc, void *ptr);
ozayn_ord_err_t ozayn_ord_set_diagnostics(ozayn_ord_service_t *svc, void *ptr);
ozayn_ord_err_t ozayn_ord_set_startup_recovery(ozayn_ord_service_t *svc, void *ptr);
ozayn_ord_err_t ozayn_ord_set_workflow_recovery(ozayn_ord_service_t *svc, void *ptr);
ozayn_ord_err_t ozayn_ord_set_workflow_checkpoint(ozayn_ord_service_t *svc, void *ptr);

/* Mode queries */
ozayn_ord_mode_t ozayn_ord_get_mode(const ozayn_ord_service_t *svc);
ozayn_ord_mode_t ozayn_ord_get_previous_mode(const ozayn_ord_service_t *svc);
int ozayn_ord_is_running(const ozayn_ord_service_t *svc);

/* Readiness assessment */
ozayn_ord_err_t ozayn_ord_assess(ozayn_ord_service_t *svc,
    ozayn_ord_assessment_t *out_assessment);
ozayn_ord_err_t ozayn_ord_get_latest_assessment(const ozayn_ord_service_t *svc,
    ozayn_ord_assessment_t *out_assessment);
int ozayn_ord_assessment_count(const ozayn_ord_service_t *svc);

/* Mode transitions */
ozayn_ord_err_t ozayn_ord_transition(ozayn_ord_service_t *svc,
    ozayn_ord_mode_t target_mode, ozayn_ord_trigger_t trigger,
    const char *reason, const char *source);
ozayn_ord_err_t ozayn_ord_transition_force(ozayn_ord_service_t *svc,
    ozayn_ord_mode_t target_mode, ozayn_ord_trigger_t trigger,
    const char *reason, const char *source);
ozayn_ord_err_t ozayn_ord_get_latest_transition(const ozayn_ord_service_t *svc,
    ozayn_ord_transition_t *out_transition);
int ozayn_ord_transition_count(const ozayn_ord_service_t *svc);
int ozayn_ord_is_transition_valid(ozayn_ord_mode_t from, ozayn_ord_mode_t to);

/* Operation gating */
ozayn_ord_gate_decision_t ozayn_ord_check_operation(const ozayn_ord_service_t *svc,
    ozayn_ord_opclass_t opclass);
ozayn_ord_err_t ozayn_ord_gate_operation(ozayn_ord_service_t *svc,
    ozayn_ord_opclass_t opclass, const char *operation_id);

/* Blocking and warnings */
ozayn_ord_err_t ozayn_ord_add_blocking(ozayn_ord_service_t *svc,
    const char *description);
ozayn_ord_err_t ozayn_ord_add_warning(ozayn_ord_service_t *svc,
    const char *description);
int ozayn_ord_blocking_count(const ozayn_ord_service_t *svc);
int ozayn_ord_warning_count(const ozayn_ord_service_t *svc);

/* Events */
ozayn_ord_err_t ozayn_ord_emit_event(ozayn_ord_service_t *svc,
    ozayn_ord_event_type_t type, const char *source,
    const char *message);
ozayn_ord_err_t ozayn_ord_get_event(const ozayn_ord_service_t *svc,
    int index, ozayn_ord_event_t *out_event);
int ozayn_ord_event_count(const ozayn_ord_service_t *svc);

/* Stats */
const ozayn_ord_stats_t *ozayn_ord_get_stats(const ozayn_ord_service_t *svc);
ozayn_ord_err_t ozayn_ord_reset_stats(ozayn_ord_service_t *svc);

/* Flapping */
int ozayn_ord_is_flapping(const ozayn_ord_service_t *svc);

/* Name helpers */
const char *ozayn_ord_err_name(ozayn_ord_err_t err);
const char *ozayn_ord_mode_name(ozayn_ord_mode_t mode);
const char *ozayn_ord_opclass_name(ozayn_ord_opclass_t opclass);
const char *ozayn_ord_gate_name(ozayn_ord_gate_decision_t gate);
const char *ozayn_ord_trigger_name(ozayn_ord_trigger_t trigger);
const char *ozayn_ord_assess_name(ozayn_ord_assess_decision_t assess);
const char *ozayn_ord_condition_name(ozayn_ord_condition_status_t status);
const char *ozayn_ord_subsys_name(ozayn_ord_subsys_status_t status);
const char *ozayn_ord_transition_result_name(ozayn_ord_transition_result_t result);
const char *ozayn_ord_event_type_name(ozayn_ord_event_type_t type);

#endif /* OZAYN_OPERATIONAL_READINESS_H */
