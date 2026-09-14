/*
 * startup_recovery.h — Startup Recovery & System Reconciliation Orchestration
 *
 * Step 19/35 — Control Room
 *
 * Coordinates controlled startup lifecycle, subsystem discovery,
 * state/resource/device/security reconciliation, and recovery assessment.
 *
 * Does NOT perform automatic workflow resume.
 */

#ifndef OZAYN_SRC_STARTUP_RECOVERY_H
#define OZAYN_SRC_STARTUP_RECOVERY_H

#include <stdint.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================
 * CONSTANTS
 * ============================================================ */

#define OZAYN_SRC_MAX_ID_LEN          64
#define OZAYN_SRC_MAX_NAME_LEN        64
#define OZAYN_SRC_MAX_VERSION_LEN     32
#define OZAYN_SRC_MAX_DESC_LEN        256
#define OZAYN_SRC_MAX_METADATA_LEN    256
#define OZAYN_SRC_MAX_COMPONENTS      64
#define OZAYN_SRC_MAX_CAPABILITIES    128
#define OZAYN_SRC_MAX_RECOVERY_ITEMS  32
#define OZAYN_SRC_MAX_PHASE_RESULTS   16
#define OZAYN_SRC_MAX_EVENTS          128
#define OZAYN_SRC_MAX_WARNINGS        32
#define OZAYN_SRC_MAX_BLOCKING        16
#define OZAYN_SRC_MAX_AFFECTED        32
#define OZAYN_SRC_DEFAULT_PHASE_TIMEOUT_MS  30000
#define OZAYN_SRC_DEFAULT_TOTAL_TIMEOUT_MS  120000

/* ============================================================
 * ERROR CODES
 * ============================================================ */

typedef enum {
    OZAYN_SRC_OK                          =   0,
    OZAYN_SRC_ERR_NULL                    =  -1,
    OZAYN_SRC_ERR_NOT_INITIALIZED         =  -2,
    OZAYN_SRC_ERR_ALREADY_INITIALIZED     =  -3,
    OZAYN_SRC_ERR_INVALID_PARAM           =  -4,
    OZAYN_SRC_ERR_STATE_INVALID           =  -5,
    OZAYN_SRC_ERR_PHASE_FAILED            =  -6,
    OZAYN_SRC_ERR_PHASE_TIMEOUT           =  -7,
    OZAYN_SRC_ERR_DEPENDENCY_FAILED       =  -8,
    OZAYN_SRC_ERR_DEPENDENCY_CYCLE        =  -9,
    OZAYN_SRC_ERR_COMPONENT_UNAVAILABLE   = -10,
    OZAYN_SRC_ERR_COMPONENT_INVALID       = -11,
    OZAYN_SRC_ERR_CAPABILITY_UNAVAILABLE  = -12,
    OZAYN_SRC_ERR_STATE_RECONCILE_FAILED  = -13,
    OZAYN_SRC_ERR_RESOURCE_RECONCILE_FAILED = -14,
    OZAYN_SRC_ERR_DEVICE_RECONCILE_FAILED = -15,
    OZAYN_SRC_ERR_SECURITY_REVALIDATE_FAILED = -16,
    OZAYN_SRC_ERR_SAFETY_VALIDATION_FAILED = -17,
    OZAYN_SRC_ERR_RECOVERY_STATE_INVALID  = -18,
    OZAYN_SRC_ERR_RECOVERY_REQUIRED       = -19,
    OZAYN_SRC_ERR_MANUAL_REVIEW_REQUIRED  = -20,
    OZAYN_SRC_ERR_BLOCKED                 = -21,
    OZAYN_SRC_ERR_CONFIGURATION_ERROR     = -22,
    OZAYN_SRC_ERR_CONCURRENCY_ERROR       = -23,
    OZAYN_SRC_ERR_STORAGE_ERROR           = -24,
    OZAYN_SRC_ERR_LIMIT_REACHED           = -25,
    OZAYN_SRC_ERR_NOT_FOUND               = -26,
    OZAYN_SRC_ERR_FAILED                  = -27
} ozayn_src_err_t;

/* ============================================================
 * STARTUP PHASES
 * ============================================================ */

typedef enum {
    OZAYN_SRC_PHASE_NOT_STARTED = 0,
    OZAYN_SRC_PHASE_BOOTSTRAP,
    OZAYN_SRC_PHASE_CORE,
    OZAYN_SRC_PHASE_INFRASTRUCTURE,
    OZAYN_SRC_PHASE_DISCOVERY,
    OZAYN_SRC_PHASE_DEPENDENCY_VALIDATION,
    OZAYN_SRC_PHASE_STATE_RECONCILIATION,
    OZAYN_SRC_PHASE_RESOURCE_RECONCILIATION,
    OZAYN_SRC_PHASE_DEVICE_RECONCILIATION,
    OZAYN_SRC_PHASE_SECURITY_REVALIDATION,
    OZAYN_SRC_PHASE_RECOVERY_ASSESSMENT,
    OZAYN_SRC_PHASE_READY,
    OZAYN_SRC_PHASE_DEGRADED,
    OZAYN_SRC_PHASE_BLOCKED,
    OZAYN_SRC_PHASE_FAILED,
    OZAYN_SRC_PHASE_STOPPING,
    OZAYN_SRC_PHASE_STOPPED,
    OZAYN_SRC_PHASE_COUNT
} ozayn_src_startup_phase_t;

/* ============================================================
 * STARTUP STATE
 * ============================================================ */

typedef enum {
    OZAYN_SRC_STATE_IDLE = 0,
    OZAYN_SRC_STATE_STARTING,
    OZAYN_SRC_STATE_RUNNING,
    OZAYN_SRC_STATE_STOPPING,
    OZAYN_SRC_STATE_STOPPED,
    OZAYN_SRC_STATE_FAILED
} ozayn_src_startup_state_t;

/* ============================================================
 * STARTUP CAUSE
 * ============================================================ */

typedef enum {
    OZAYN_SRC_CAUSE_UNKNOWN = 0,
    OZAYN_SRC_CAUSE_NORMAL_START,
    OZAYN_SRC_CAUSE_NORMAL_RESTART,
    OZAYN_SRC_CAUSE_CRASH_RECOVERY,
    OZAYN_SRC_CAUSE_FORCED_TERMINATION_RECOVERY,
    OZAYN_SRC_CAUSE_POWER_LOSS_RECOVERY
} ozayn_src_startup_cause_t;

/* ============================================================
 * PREVIOUS SHUTDOWN STATE
 * ============================================================ */

typedef enum {
    OZAYN_SRC_SHUTDOWN_UNKNOWN = 0,
    OZAYN_SRC_SHUTDOWN_CLEAN,
    OZAYN_SRC_SHUTDOWN_UNCLEAN,
    OZAYN_SRC_SHUTDOWN_FORCED,
    OZAYN_SRC_SHUTDOWN_CRASH
} ozayn_src_previous_shutdown_t;

/* ============================================================
 * COMPONENT RECONCILIATION STATUS
 * ============================================================ */

typedef enum {
    OZAYN_SRC_RECON_UNKNOWN = 0,
    OZAYN_SRC_RECON_CONSISTENT,
    OZAYN_SRC_RECON_CHANGED,
    OZAYN_SRC_RECON_MISSING,
    OZAYN_SRC_RECON_UNAVAILABLE,
    OZAYN_SRC_RECON_DEGRADED,
    OZAYN_SRC_RECON_FAILED,
    OZAYN_SRC_RECON_NEW
} ozayn_src_component_recon_status_t;

/* ============================================================
 * CAPABILITY RECONCILIATION STATUS
 * ============================================================ */

typedef enum {
    OZAYN_SRC_CAP_RECON_UNKNOWN = 0,
    OZAYN_SRC_CAP_RECON_AVAILABLE,
    OZAYN_SRC_CAP_RECON_UNAVAILABLE,
    OZAYN_SRC_CAP_RECON_DEGRADED,
    OZAYN_SRC_CAP_RECON_UNSUPPORTED,
    OZAYN_SRC_CAP_RECON_INVALID
} ozayn_src_capability_recon_status_t;

/* ============================================================
 * RESOURCE RECONCILIATION STATUS
 * ============================================================ */

typedef enum {
    OZAYN_SRC_RES_RECON_UNKNOWN = 0,
    OZAYN_SRC_RES_RECON_AVAILABLE,
    OZAYN_SRC_RES_RECON_UNAVAILABLE,
    OZAYN_SRC_RES_RECON_CHANGED,
    OZAYN_SRC_RES_RECON_DEGRADED
} ozayn_src_resource_recon_status_t;

/* ============================================================
 * DEVICE RECONCILIATION STATUS
 * ============================================================ */

typedef enum {
    OZAYN_SRC_DEV_RECON_UNKNOWN = 0,
    OZAYN_SRC_DEV_RECON_PRESENT,
    OZAYN_SRC_DEV_RECON_ABSENT,
    OZAYN_SRC_DEV_RECON_CHANGED,
    OZAYN_SRC_DEV_RECON_UNAVAILABLE,
    OZAYN_SRC_DEV_RECON_DEGRADED,
    OZAYN_SRC_DEV_RECON_UNSUPPORTED
} ozayn_src_device_recon_status_t;

/* ============================================================
 * SECURITY RECONCILIATION STATUS
 * ============================================================ */

typedef enum {
    OZAYN_SRC_SEC_RECON_UNKNOWN = 0,
    OZAYN_SRC_SEC_RECON_VALID,
    OZAYN_SRC_SEC_RECON_EXPIRED,
    OZAYN_SRC_SEC_RECON_INVALID,
    OZAYN_SRC_SEC_RECON_UNAVAILABLE
} ozayn_src_security_recon_status_t;

/* ============================================================
 * RECOVERY ASSESSMENT
 * ============================================================ */

typedef enum {
    OZAYN_SRC_RECOVERY_NONE = 0,
    OZAYN_SRC_RECOVERY_REQUIRED,
    OZAYN_SRC_RECOVERY_MANUAL_REVIEW,
    OZAYN_SRC_RECOVERY_BLOCKED,
    OZAYN_SRC_RECOVERY_EXPIRED,
    OZAYN_SRC_RECOVERY_CORRUPTED
} ozayn_src_recovery_assessment_t;

/* ============================================================
 * STARTUP DECISION
 * ============================================================ */

typedef enum {
    OZAYN_SRC_DECISION_UNKNOWN = 0,
    OZAYN_SRC_DECISION_READY,
    OZAYN_SRC_DECISION_READY_DEGRADED,
    OZAYN_SRC_DECISION_RECOVERY_REQUIRED,
    OZAYN_SRC_DECISION_MANUAL_REVIEW_REQUIRED,
    OZAYN_SRC_DECISION_BLOCKED,
    OZAYN_SRC_DECISION_FAILED
} ozayn_src_startup_decision_t;

/* ============================================================
 * FAILURE CLASSIFICATION
 * ============================================================ */

typedef enum {
    OZAYN_SRC_FAIL_NON_CRITICAL = 0,
    OZAYN_SRC_FAIL_DEGRADED,
    OZAYN_SRC_FAIL_CRITICAL,
    OZAYN_SRC_FAIL_BLOCKING
} ozayn_src_failure_class_t;

/* ============================================================
 * RECOVERY PRIORITY
 * ============================================================ */

typedef enum {
    OZAYN_SRC_PRIORITY_LOW = 0,
    OZAYN_SRC_PRIORITY_NORMAL,
    OZAYN_SRC_PRIORITY_HIGH,
    OZAYN_SRC_PRIORITY_CRITICAL
} ozayn_src_recovery_priority_t;

/* ============================================================
 * EVENT TYPES
 * ============================================================ */

typedef enum {
    OZAYN_SRC_EVENT_STARTUP_STARTED = 0,
    OZAYN_SRC_EVENT_PHASE_STARTED,
    OZAYN_SRC_EVENT_PHASE_COMPLETED,
    OZAYN_SRC_EVENT_PHASE_FAILED,
    OZAYN_SRC_EVENT_PHASE_TIMEOUT,
    OZAYN_SRC_EVENT_DEPENDENCY_FAILED,
    OZAYN_SRC_EVENT_DEPENDENCY_CYCLE,
    OZAYN_SRC_EVENT_STATE_RECONCILIATION_STARTED,
    OZAYN_SRC_EVENT_STATE_RECONCILIATION_COMPLETED,
    OZAYN_SRC_EVENT_RESOURCE_RECONCILIATION_COMPLETED,
    OZAYN_SRC_EVENT_DEVICE_RECONCILIATION_COMPLETED,
    OZAYN_SRC_EVENT_SECURITY_REVALIDATION_COMPLETED,
    OZAYN_SRC_EVENT_RECOVERY_ASSESSMENT_STARTED,
    OZAYN_SRC_EVENT_RECOVERY_REQUIRED,
    OZAYN_SRC_EVENT_MANUAL_REVIEW_REQUIRED,
    OZAYN_SRC_EVENT_READY,
    OZAYN_SRC_EVENT_DEGRADED,
    OZAYN_SRC_EVENT_BLOCKED,
    OZAYN_SRC_EVENT_FAILED,
    OZAYN_SRC_EVENT_STARTUP_COMPLETED,
    OZAYN_SRC_EVENT_SHUTDOWN_STARTED,
    OZAYN_SRC_EVENT_SHUTDOWN_COMPLETED,
    OZAYN_SRC_EVENT_COUNT
} ozayn_src_event_type_t;

/* ============================================================
 * PHASE RESULT STATUS
 * ============================================================ */

typedef enum {
    OZAYN_SRC_PHASE_RESULT_PENDING = 0,
    OZAYN_SRC_PHASE_RESULT_SUCCESS,
    OZAYN_SRC_PHASE_RESULT_DEGRADED,
    OZAYN_SRC_PHASE_RESULT_FAILED,
    OZAYN_SRC_PHASE_RESULT_TIMEOUT,
    OZAYN_SRC_PHASE_RESULT_SKIPPED
} ozayn_src_phase_result_status_t;

/* ============================================================
 * STARTUP CONTEXT
 * ============================================================ */

typedef struct {
    char startup_id[OZAYN_SRC_MAX_ID_LEN];
    char startup_version[OZAYN_SRC_MAX_VERSION_LEN];
    char build_version[OZAYN_SRC_MAX_VERSION_LEN];
    char config_version[OZAYN_SRC_MAX_VERSION_LEN];
    char platform[OZAYN_SRC_MAX_NAME_LEN];

    int64_t start_time_ms;
    int64_t completion_time_ms;

    ozayn_src_startup_cause_t startup_cause;
    ozayn_src_previous_shutdown_t previous_shutdown;
    ozayn_src_startup_state_t runtime_state;

    ozayn_src_startup_phase_t current_phase;
    ozayn_src_startup_phase_t highest_completed_phase;
    ozayn_src_startup_decision_t decision;

    char recovery_state_ref[OZAYN_SRC_MAX_ID_LEN];
    char failure_ref[OZAYN_SRC_MAX_ID_LEN];
    char safe_metadata[OZAYN_SRC_MAX_METADATA_LEN];

    int phase_count;
    int64_t phase_timeouts_ms[OZAYN_SRC_PHASE_COUNT];
} ozayn_src_startup_context_t;

/* ============================================================
 * STARTUP MANIFEST
 * ============================================================ */

typedef struct {
    char component_names[OZAYN_SRC_MAX_COMPONENTS][OZAYN_SRC_MAX_NAME_LEN];
    int  component_required[OZAYN_SRC_MAX_COMPONENTS];
    int  component_count;

    char dependency_names[OZAYN_SRC_MAX_COMPONENTS][OZAYN_SRC_MAX_NAME_LEN];
    int  dependency_required[OZAYN_SRC_MAX_COMPONENTS];
    int  dependency_count;

    char capability_names[OZAYN_SRC_MAX_CAPABILITIES][OZAYN_SRC_MAX_NAME_LEN];
    int  capability_required[OZAYN_SRC_MAX_CAPABILITIES];
    int  capability_count;

    int  required_resource_count;
    int  required_security_services;
    int  required_config_valid;

    int64_t phase_timeout_ms[OZAYN_SRC_PHASE_COUNT];
    int64_t total_timeout_ms;

    int failure_policy;  /* 0 = stop on critical, 1 = degrade on non-critical */
} ozayn_src_startup_manifest_t;

/* ============================================================
 * COMPONENT RECONCILIATION ENTRY
 * ============================================================ */

typedef struct {
    char component_name[OZAYN_SRC_MAX_NAME_LEN];
    int  persisted_state;
    int  current_state;
    ozayn_src_component_recon_status_t status;
    int  is_required;
    char description[OZAYN_SRC_MAX_DESC_LEN];
    int  active;
} ozayn_src_component_recon_entry_t;

/* ============================================================
 * CAPABILITY RECONCILIATION ENTRY
 * ============================================================ */

typedef struct {
    char capability_name[OZAYN_SRC_MAX_NAME_LEN];
    char component_name[OZAYN_SRC_MAX_NAME_LEN];
    ozayn_src_capability_recon_status_t status;
    int  is_required;
    char description[OZAYN_SRC_MAX_DESC_LEN];
    int  active;
} ozayn_src_capability_recon_entry_t;

/* ============================================================
 * RESOURCE RECONCILIATION ENTRY
 * ============================================================ */

typedef struct {
    int  resource_type;
    char resource_name[OZAYN_SRC_MAX_NAME_LEN];
    ozayn_src_resource_recon_status_t status;
    int  available_capacity;
    int  required_capacity;
    char description[OZAYN_SRC_MAX_DESC_LEN];
    int  active;
} ozayn_src_resource_recon_entry_t;

/* ============================================================
 * DEVICE RECONCILIATION ENTRY
 * ============================================================ */

typedef struct {
    char device_id[OZAYN_SRC_MAX_ID_LEN];
    char device_name[OZAYN_SRC_MAX_NAME_LEN];
    ozayn_src_device_recon_status_t status;
    int  was_active_session;
    char description[OZAYN_SRC_MAX_DESC_LEN];
    int  active;
} ozayn_src_device_recon_entry_t;

/* ============================================================
 * RECOVERY ITEM
 * ============================================================ */

typedef struct {
    char item_id[OZAYN_SRC_MAX_ID_LEN];
    char workflow_id[OZAYN_SRC_MAX_ID_LEN];
    char checkpoint_id[OZAYN_SRC_MAX_ID_LEN];
    ozayn_src_recovery_priority_t priority;
    ozayn_src_recovery_assessment_t assessment;
    int  requires_authorization;
    int  requires_safety_check;
    int  requires_resource_check;
    int  requires_device_check;
    int  duplicate_risk;
    char description[OZAYN_SRC_MAX_DESC_LEN];
    int  active;
} ozayn_src_recovery_item_t;

/* ============================================================
 * PHASE RESULT
 * ============================================================ */

typedef struct {
    ozayn_src_startup_phase_t phase;
    ozayn_src_phase_result_status_t status;
    int64_t start_time_ms;
    int64_t end_time_ms;
    int64_t duration_ms;
    int components_checked;
    int components_ok;
    int components_failed;
    int components_degraded;
    char failure_ref[OZAYN_SRC_MAX_ID_LEN];
    char description[OZAYN_SRC_MAX_DESC_LEN];
    int  active;
} ozayn_src_phase_result_t;

/* ============================================================
 * EVENT
 * ============================================================ */

typedef struct {
    ozayn_src_event_type_t event_type;
    char event_id[OZAYN_SRC_MAX_ID_LEN];
    char source[OZAYN_SRC_MAX_NAME_LEN];
    char description[OZAYN_SRC_MAX_DESC_LEN];
    char safe_metadata[OZAYN_SRC_MAX_METADATA_LEN];
    int64_t timestamp_ms;
    int  active;
} ozayn_src_event_t;

/* ============================================================
 * STATISTICS
 * ============================================================ */

typedef struct {
    int total_startups;
    int total_restarts;
    int total_crash_recoveries;
    int total_phases_completed;
    int total_phases_failed;
    int total_phases_timeout;
    int total_components_checked;
    int total_components_reconciled;
    int total_capabilities_checked;
    int total_resources_reconciled;
    int total_devices_reconciled;
    int total_security_revalidated;
    int total_recovery_items_loaded;
    int total_recovery_items_eligible;
    int total_recovery_items_blocked;
    int total_recovery_items_manual;
    int total_events;
    int total_warnings;
    int total_blocking_conditions;
} ozayn_src_stats_t;

/* ============================================================
 * SERVICE STATE
 * ============================================================ */

typedef struct {
    int initialized;
    int running;
    int starting;
    int shutting_down;

    /* Context */
    ozayn_src_startup_context_t context;

    /* Manifest */
    ozayn_src_startup_manifest_t manifest;

    /* Phase results */
    ozayn_src_phase_result_t phase_results[OZAYN_SRC_MAX_PHASE_RESULTS];
    int phase_result_count;

    /* Component reconciliation */
    ozayn_src_component_recon_entry_t component_recon[OZAYN_SRC_MAX_COMPONENTS];
    int component_recon_count;

    /* Capability reconciliation */
    ozayn_src_capability_recon_entry_t capability_recon[OZAYN_SRC_MAX_CAPABILITIES];
    int capability_recon_count;

    /* Resource reconciliation */
    ozayn_src_resource_recon_entry_t resource_recon[OZAYN_SRC_MAX_COMPONENTS];
    int resource_recon_count;

    /* Device reconciliation */
    ozayn_src_device_recon_entry_t device_recon[OZAYN_SRC_MAX_COMPONENTS];
    int device_recon_count;

    /* Security reconciliation */
    ozayn_src_security_recon_status_t security_status;
    char security_description[OZAYN_SRC_MAX_DESC_LEN];

    /* Recovery items */
    ozayn_src_recovery_item_t recovery_items[OZAYN_SRC_MAX_RECOVERY_ITEMS];
    int recovery_item_count;

    /* Events */
    ozayn_src_event_t events[OZAYN_SRC_MAX_EVENTS];
    int event_count;
    int event_head;

    /* Warnings */
    char warnings[OZAYN_SRC_MAX_WARNINGS][OZAYN_SRC_MAX_DESC_LEN];
    int warning_count;

    /* Blocking conditions */
    char blocking[OZAYN_SRC_MAX_BLOCKING][OZAYN_SRC_MAX_DESC_LEN];
    int blocking_count;

    /* Affected components */
    char affected[OZAYN_SRC_MAX_AFFECTED][OZAYN_SRC_MAX_NAME_LEN];
    int affected_count;

    /* Statistics */
    ozayn_src_stats_t stats;

    /* Concurrency protection */
    int startup_in_progress;
    int reconciliation_in_progress;

    /* External dependencies (void* to avoid circular includes) */
    void *lifecycle;
    void *dependency;
    void *component_registry;
    void *resource_manager;
    void *device_session;
    void *safety;
    void *diagnostics;
    void *workflow_recovery;
    void *workflow_checkpoint;
    void *state_manager;
    void *events_engine;
} ozayn_src_service_t;

/* ============================================================
 * PUBLIC API — LIFECYCLE
 * ============================================================ */

ozayn_src_err_t ozayn_src_service_init(ozayn_src_service_t *svc);
ozayn_src_err_t ozayn_src_service_shutdown(ozayn_src_service_t *svc);
int ozayn_src_is_initialized(const ozayn_src_service_t *svc);
ozayn_src_service_t *ozayn_src_get_global(void);

/* ============================================================
 * PUBLIC API — EXTERNAL DEPENDENCY BINDING
 * ============================================================ */

ozayn_src_err_t ozayn_src_set_lifecycle(ozayn_src_service_t *svc, void *lifecycle);
ozayn_src_err_t ozayn_src_set_dependency(ozayn_src_service_t *svc, void *dependency);
ozayn_src_err_t ozayn_src_set_component_registry(ozayn_src_service_t *svc, void *registry);
ozayn_src_err_t ozayn_src_set_resource_manager(ozayn_src_service_t *svc, void *resource);
ozayn_src_err_t ozayn_src_set_device_session(ozayn_src_service_t *svc, void *device);
ozayn_src_err_t ozayn_src_set_safety(ozayn_src_service_t *svc, void *safety);
ozayn_src_err_t ozayn_src_set_diagnostics(ozayn_src_service_t *svc, void *diagnostics);
ozayn_src_err_t ozayn_src_set_workflow_recovery(ozayn_src_service_t *svc, void *recovery);
ozayn_src_err_t ozayn_src_set_workflow_checkpoint(ozayn_src_service_t *svc, void *checkpoint);
ozayn_src_err_t ozayn_src_set_state_manager(ozayn_src_service_t *svc, void *state);
ozayn_src_err_t ozayn_src_set_events_engine(ozayn_src_service_t *svc, void *events);

/* ============================================================
 * PUBLIC API — STARTUP CAUSE DETECTION
 * ============================================================ */

ozayn_src_err_t ozayn_src_detect_startup_cause(ozayn_src_service_t *svc,
    ozayn_src_startup_cause_t *out_cause,
    ozayn_src_previous_shutdown_t *out_shutdown);

/* ============================================================
 * PUBLIC API — MANIFEST
 * ============================================================ */

ozayn_src_err_t ozayn_src_manifest_reset(ozayn_src_service_t *svc);
ozayn_src_err_t ozayn_src_manifest_add_component(ozayn_src_service_t *svc,
    const char *name, int required);
ozayn_src_err_t ozayn_src_manifest_add_dependency(ozayn_src_service_t *svc,
    const char *name, int required);
ozayn_src_err_t ozayn_src_manifest_add_capability(ozayn_src_service_t *svc,
    const char *name, int required);
ozayn_src_err_t ozayn_src_manifest_set_phase_timeout(ozayn_src_service_t *svc,
    ozayn_src_startup_phase_t phase, int64_t timeout_ms);
ozayn_src_err_t ozayn_src_manifest_set_total_timeout(ozayn_src_service_t *svc,
    int64_t timeout_ms);
const ozayn_src_startup_manifest_t *ozayn_src_manifest_get(
    const ozayn_src_service_t *svc);

/* ============================================================
 * PUBLIC API — STARTUP EXECUTION
 * ============================================================ */

ozayn_src_err_t ozayn_src_startup(ozayn_src_service_t *svc);
ozayn_src_err_t ozayn_src_startup_phase(ozayn_src_service_t *svc,
    ozayn_src_startup_phase_t phase);
ozayn_src_err_t ozayn_src_shutdown(ozayn_src_service_t *svc);

/* ============================================================
 * PUBLIC API — PHASE QUERY
 * ============================================================ */

ozayn_src_startup_phase_t ozayn_src_get_phase(const ozayn_src_service_t *svc);
ozayn_src_startup_state_t ozayn_src_get_state(const ozayn_src_service_t *svc);
ozayn_src_startup_decision_t ozayn_src_get_decision(const ozayn_src_service_t *svc);
int ozayn_src_is_running(const ozayn_src_service_t *svc);

/* ============================================================
 * PUBLIC API — CONTEXT
 * ============================================================ */

const ozayn_src_startup_context_t *ozayn_src_get_context(
    const ozayn_src_service_t *svc);
ozayn_src_err_t ozayn_src_context_set_startup_cause(ozayn_src_service_t *svc,
    ozayn_src_startup_cause_t cause);
ozayn_src_err_t ozayn_src_context_set_previous_shutdown(ozayn_src_service_t *svc,
    ozayn_src_previous_shutdown_t shutdown);

/* ============================================================
 * PUBLIC API — COMPONENT RECONCILIATION
 * ============================================================ */

ozayn_src_err_t ozayn_src_reconcile_components(ozayn_src_service_t *svc);
int ozayn_src_component_recon_count(const ozayn_src_service_t *svc);
const ozayn_src_component_recon_entry_t *ozayn_src_component_recon_get(
    const ozayn_src_service_t *svc, int index);
int ozayn_src_component_recon_inconsistencies(const ozayn_src_service_t *svc);

/* ============================================================
 * PUBLIC API — CAPABILITY RECONCILIATION
 * ============================================================ */

ozayn_src_err_t ozayn_src_reconcile_capabilities(ozayn_src_service_t *svc);
int ozayn_src_capability_recon_count(const ozayn_src_service_t *svc);
const ozayn_src_capability_recon_entry_t *ozayn_src_capability_recon_get(
    const ozayn_src_service_t *svc, int index);
int ozayn_src_capability_recon_unavailable(const ozayn_src_service_t *svc);

/* ============================================================
 * PUBLIC API — RESOURCE RECONCILIATION
 * ============================================================ */

ozayn_src_err_t ozayn_src_reconcile_resources(ozayn_src_service_t *svc);
int ozayn_src_resource_recon_count(const ozayn_src_service_t *svc);
const ozayn_src_resource_recon_entry_t *ozayn_src_resource_recon_get(
    const ozayn_src_service_t *svc, int index);
int ozayn_src_resource_recon_unavailable(const ozayn_src_service_t *svc);

/* ============================================================
 * PUBLIC API — DEVICE RECONCILIATION
 * ============================================================ */

ozayn_src_err_t ozayn_src_reconcile_devices(ozayn_src_service_t *svc);
int ozayn_src_device_recon_count(const ozayn_src_service_t *svc);
const ozayn_src_device_recon_entry_t *ozayn_src_device_recon_get(
    const ozayn_src_service_t *svc, int index);
int ozayn_src_device_recon_stale_sessions(const ozayn_src_service_t *svc);

/* ============================================================
 * PUBLIC API — SECURITY REVALIDATION
 * ============================================================ */

ozayn_src_err_t ozayn_src_revalidate_security(ozayn_src_service_t *svc);
ozayn_src_security_recon_status_t ozayn_src_security_status(
    const ozayn_src_service_t *svc);

/* ============================================================
 * PUBLIC API — RECOVERY ASSESSMENT
 * ============================================================ */

ozayn_src_err_t ozayn_src_assess_recovery(ozayn_src_service_t *svc);
int ozayn_src_recovery_item_count(const ozayn_src_service_t *svc);
const ozayn_src_recovery_item_t *ozayn_src_recovery_item_get(
    const ozayn_src_service_t *svc, int index);
ozayn_src_recovery_assessment_t ozayn_src_recovery_overall_assessment(
    const ozayn_src_service_t *svc);

/* ============================================================
 * PUBLIC API — STARTUP DECISION
 * ============================================================ */

ozayn_src_err_t ozayn_src_determine_decision(ozayn_src_service_t *svc);
ozayn_src_startup_decision_t ozayn_src_decision_get(
    const ozayn_src_service_t *svc);
const char *ozayn_src_decision_description(const ozayn_src_service_t *svc);

/* ============================================================
 * PUBLIC API — WARNINGS & BLOCKING
 * ============================================================ */

int ozayn_src_warning_count(const ozayn_src_service_t *svc);
const char *ozayn_src_warning_get(const ozayn_src_service_t *svc, int index);
ozayn_src_err_t ozayn_src_add_warning(ozayn_src_service_t *svc,
    const char *description);
int ozayn_src_blocking_count(const ozayn_src_service_t *svc);
const char *ozayn_src_blocking_get(const ozayn_src_service_t *svc, int index);
ozayn_src_err_t ozayn_src_add_blocking(ozayn_src_service_t *svc,
    const char *description);

/* ============================================================
 * PUBLIC API — EVENTS
 * ============================================================ */

ozayn_src_err_t ozayn_src_emit_event(ozayn_src_service_t *svc,
    ozayn_src_event_type_t type, const char *source,
    const char *description, const char *metadata);
int ozayn_src_event_count(const ozayn_src_service_t *svc);
const ozayn_src_event_t *ozayn_src_get_event(const ozayn_src_service_t *svc,
    int index);

/* ============================================================
 * PUBLIC API — STATISTICS
 * ============================================================ */

const ozayn_src_stats_t *ozayn_src_get_stats(const ozayn_src_service_t *svc);
ozayn_src_err_t ozayn_src_reset_stats(ozayn_src_service_t *svc);

/* ============================================================
 * PUBLIC API — VALIDATION
 * ============================================================ */

int ozayn_src_validate_context(const ozayn_src_startup_context_t *ctx);
int ozayn_src_validate_manifest(const ozayn_src_startup_manifest_t *manifest);
int ozayn_src_validate_phase(ozayn_src_startup_phase_t phase);
int ozayn_src_is_phase_terminal(ozayn_src_startup_phase_t phase);
int ozayn_src_is_decision_terminal(ozayn_src_startup_decision_t decision);

/* ============================================================
 * PUBLIC API — PHASE RESULT
 * ============================================================ */

int ozayn_src_phase_result_count(const ozayn_src_service_t *svc);
const ozayn_src_phase_result_t *ozayn_src_phase_result_get(
    const ozayn_src_service_t *svc, int index);
const ozayn_src_phase_result_t *ozayn_src_phase_result_get_by_phase(
    const ozayn_src_service_t *svc, ozayn_src_startup_phase_t phase);

/* ============================================================
 * PUBLIC API — NAME HELPERS
 * ============================================================ */

const char *ozayn_src_err_name(ozayn_src_err_t err);
const char *ozayn_src_phase_name(ozayn_src_startup_phase_t phase);
const char *ozayn_src_state_name(ozayn_src_startup_state_t state);
const char *ozayn_src_cause_name(ozayn_src_startup_cause_t cause);
const char *ozayn_src_shutdown_name(ozayn_src_previous_shutdown_t shutdown);
const char *ozayn_src_component_recon_name(ozayn_src_component_recon_status_t s);
const char *ozayn_src_capability_recon_name(ozayn_src_capability_recon_status_t s);
const char *ozayn_src_resource_recon_name(ozayn_src_resource_recon_status_t s);
const char *ozayn_src_device_recon_name(ozayn_src_device_recon_status_t s);
const char *ozayn_src_security_recon_name(ozayn_src_security_recon_status_t s);
const char *ozayn_src_recovery_assessment_name(ozayn_src_recovery_assessment_t a);
const char *ozayn_src_decision_name(ozayn_src_startup_decision_t decision);
const char *ozayn_src_failure_class_name(ozayn_src_failure_class_t cls);
const char *ozayn_src_priority_name(ozayn_src_recovery_priority_t priority);
const char *ozayn_src_event_type_name(ozayn_src_event_type_t type);
const char *ozayn_src_phase_result_status_name(ozayn_src_phase_result_status_t s);

#ifdef __cplusplus
}
#endif

#endif /* OZAYN_SRC_STARTUP_RECOVERY_H */
