#ifndef OZAYN_WORKFLOW_ORCHESTRATOR_H
#define OZAYN_WORKFLOW_ORCHESTRATOR_H

#include <stdint.h>
#include <time.h>

/* ============================================================
 * SECTION 1 — ERROR CODES
 * ============================================================ */

typedef enum {
    OZAYN_WOF_OK                            =   0,
    OZAYN_WOF_ERR_NULL                      =  -1,
    OZAYN_WOF_ERR_NOT_INITIALIZED           =  -2,
    OZAYN_WOF_ERR_ALREADY_INIT              =  -3,
    OZAYN_WOF_ERR_INVALID_PARAM             =  -4,
    OZAYN_WOF_ERR_LIMIT_REACHED             =  -5,
    OZAYN_WOF_ERR_NOT_FOUND                 =  -6,
    OZAYN_WOF_ERR_DUPLICATE                 =  -7,
    OZAYN_WOF_ERR_STATE_INVALID             =  -8,
    OZAYN_WOF_ERR_DEPENDENCY_INVALID        =  -9,
    OZAYN_WOF_ERR_DEPENDENCY_NOT_FOUND      = -10,
    OZAYN_WOF_ERR_DEPENDENCY_CYCLE          = -11,
    OZAYN_WOF_ERR_DEPENDENCY_FAILED         = -12,
    OZAYN_WOF_ERR_DEPENDENCY_TIMEOUT        = -13,
    OZAYN_WOF_ERR_AUTH_FAILED               = -14,
    OZAYN_WOF_ERR_PERMISSION_DENIED         = -15,
    OZAYN_WOF_ERR_SESSION_INVALID           = -16,
    OZAYN_WOF_ERR_POLICY_DENIED             = -17,
    OZAYN_WOF_ERR_SAFETY_CHECK_FAILED       = -18,
    OZAYN_WOF_ERR_SAFETY_RECHECK_FAILED     = -19,
    OZAYN_WOF_ERR_RESOURCE_UNAVAILABLE      = -20,
    OZAYN_WOF_ERR_RESOURCE_LIMIT            = -21,
    OZAYN_WOF_ERR_RESERVATION_FAILED        = -22,
    OZAYN_WOF_ERR_PIPELINE_INVALID          = -23,
    OZAYN_WOF_ERR_PIPELINE_NOT_FOUND        = -24,
    OZAYN_WOF_ERR_PIPELINE_UNAVAILABLE      = -25,
    OZAYN_WOF_ERR_PIPELINE_CONFLICT         = -26,
    OZAYN_WOF_ERR_TIMEOUT                   = -27,
    OZAYN_WOF_ERR_CANCELLED                 = -28,
    OZAYN_WOF_ERR_EXPIRED                   = -29,
    OZAYN_WOF_ERR_CONCURRENCY               = -30,
    OZAYN_WOF_ERR_CONFIGURATION             = -31,
    OZAYN_WOF_ERR_EVENT_ERROR               = -32,
    OZAYN_WOF_ERR_HISTORY_ERROR             = -33,
    OZAYN_WOF_ERR_DIAGNOSTIC_ERROR          = -34,
    OZAYN_WOF_ERR_ORCHESTRATION_ERROR       = -35,
    OZAYN_WOF_ERR_REJECTED                  = -36,
    OZAYN_WOF_ERR_UNAVAILABLE               = -37,
    OZAYN_WOF_ERR_STAGE_INVALID             = -38,
    OZAYN_WOF_ERR_STAGE_NOT_FOUND           = -39,
    OZAYN_WOF_ERR_STAGE_CONFLICT            = -40,
    OZAYN_WOF_ERR_STAGE_UNAVAILABLE         = -41,
    OZAYN_WOF_ERR_COMPENSATION_FAILED       = -42,
    OZAYN_WOF_ERR_PARTIALLY_SUCCEEDED       = -43
} ozayn_wof_err_t;

/* ============================================================
 * SECTION 2 — WORKFLOW STATES
 * ============================================================ */

typedef enum {
    OZAYN_WOF_WF_CREATED = 0,
    OZAYN_WOF_WF_VALIDATING,
    OZAYN_WOF_WF_AUTHORIZED,
    OZAYN_WOF_WF_WAITING,
    OZAYN_WOF_WF_READY,
    OZAYN_WOF_WF_SCHEDULED,
    OZAYN_WOF_WF_STARTING,
    OZAYN_WOF_WF_ACTIVE,
    OZAYN_WOF_WF_PAUSING,
    OZAYN_WOF_WF_PAUSED,
    OZAYN_WOF_WF_RESUMING,
    OZAYN_WOF_WF_DRAINING,
    OZAYN_WOF_WF_STOPPING,
    OZAYN_WOF_WF_SUCCEEDED,
    OZAYN_WOF_WF_FAILED,
    OZAYN_WOF_WF_PARTIALLY_SUCCEEDED,
    OZAYN_WOF_WF_CANCELLED,
    OZAYN_WOF_WF_TIMEOUT,
    OZAYN_WOF_WF_EXPIRED,
    OZAYN_WOF_WF_REVOKED,
    OZAYN_WOF_WF_REJECTED,
    OZAYN_WOF_WF_UNAVAILABLE,
    OZAYN_WOF_WF_STATE_COUNT
} ozayn_wof_workflow_state_t;

/* ============================================================
 * SECTION 3 — WORKFLOW TYPES
 * ============================================================ */

typedef enum {
    OZAYN_WOF_TYPE_SEQUENTIAL = 0,
    OZAYN_WOF_TYPE_PARALLEL,
    OZAYN_WOF_TYPE_BOUNDED_PARALLEL,
    OZAYN_WOF_TYPE_COUNT
} ozayn_wof_workflow_type_t;

/* ============================================================
 * SECTION 4 — WORKFLOW STAGE TYPES
 * ============================================================ */

typedef enum {
    OZAYN_WOF_STAGE_PIPELINE = 0,
    OZAYN_WOF_STAGE_OPERATION,
    OZAYN_WOF_STAGE_WAIT,
    OZAYN_WOF_STAGE_CONDITION,
    OZAYN_WOF_STAGE_GROUP,
    OZAYN_WOF_STAGE_COUNT
} ozayn_wof_stage_type_t;

/* ============================================================
 * SECTION 5 — WORKFLOW STAGE STATES
 * ============================================================ */

typedef enum {
    OZAYN_WOF_STG_CREATED = 0,
    OZAYN_WOF_STG_WAITING_DEPS,
    OZAYN_WOF_STG_DEPS_SATISFIED,
    OZAYN_WOF_STG_ELIGIBLE,
    OZAYN_WOF_STG_SUBMITTED,
    OZAYN_WOF_STG_SCHEDULED,
    OZAYN_WOF_STG_RUNNING,
    OZAYN_WOF_STG_PAUSED,
    OZAYN_WOF_STG_COMPLETED,
    OZAYN_WOF_STG_FAILED,
    OZAYN_WOF_STG_SKIPPED,
    OZAYN_WOF_STG_CANCELLED,
    OZAYN_WOF_STG_TIMED_OUT,
    OZAYN_WOF_STG_BLOCKED,
    OZAYN_WOF_STG_STATE_COUNT
} ozayn_wof_stage_state_t;

/* ============================================================
 * SECTION 6 — CONDITION TYPES (for CONDITION stages)
 * ============================================================ */

typedef enum {
    OZAYN_WOF_COND_RESOURCE_AVAILABLE = 0,
    OZAYN_WOF_COND_DEVICE_AVAILABLE,
    OZAYN_WOF_COND_PIPELINE_COMPLETED,
    OZAYN_WOF_COND_PIPELINE_FAILED,
    OZAYN_WOF_COND_HEALTH_STATE,
    OZAYN_WOF_COND_CAPABILITY_STATE,
    OZAYN_WOF_COND_OPERATION_RESULT,
    OZAYN_WOF_COND_COUNT
} ozayn_wof_condition_type_t;

/* ============================================================
 * SECTION 7 — FAILURE POLICIES
 * ============================================================ */

typedef enum {
    OZAYN_WOF_FAIL_FAIL_WORKFLOW = 0,
    OZAYN_WOF_FAIL_SKIP_DEPENDENTS,
    OZAYN_WOF_FAIL_CONTINUE_INDEPENDENT,
    OZAYN_WOF_FAIL_MARK_PARTIAL,
    OZAYN_WOF_FAIL_COUNT
} ozayn_wof_failure_policy_t;

/* ============================================================
 * SECTION 8 — COMPENSATION ACTIONS
 * ============================================================ */

typedef enum {
    OZAYN_WOF_COMP_NONE = 0,
    OZAYN_WOF_COMP_NOTIFY,
    OZAYN_WOF_COMP_REVERSE_OPERATION,
    OZAYN_WOF_COMP_RUN_COMPENSATION_PIPELINE,
    OZAYN_WOF_COMP_COUNT
} ozayn_wof_compensation_action_t;

/* ============================================================
 * SECTION 9 — CONCURRENCY POLICIES
 * ============================================================ */

typedef enum {
    OZAYN_WOF_CONC_SEQUENTIAL = 0,
    OZAYN_WOF_CONC_PARALLEL,
    OZAYN_WOF_CONC_BOUNDED,
    OZAYN_WOF_CONC_COUNT
} ozayn_wof_concurrency_policy_t;

/* ============================================================
 * SECTION 10 — EVENT TYPES
 * ============================================================ */

typedef enum {
    OZAYN_WOF_EVENT_CREATED = 0,
    OZAYN_WOF_EVENT_VALIDATING,
    OZAYN_WOF_EVENT_AUTHORIZED,
    OZAYN_WOF_EVENT_REJECTED,
    OZAYN_WOF_EVENT_READY,
    OZAYN_WOF_EVENT_SCHEDULED,
    OZAYN_WOF_EVENT_STARTED,
    OZAYN_WOF_EVENT_STAGE_READY,
    OZAYN_WOF_EVENT_STAGE_STARTED,
    OZAYN_WOF_EVENT_STAGE_COMPLETED,
    OZAYN_WOF_EVENT_STAGE_FAILED,
    OZAYN_WOF_EVENT_STAGE_BLOCKED,
    OZAYN_WOF_EVENT_STAGE_SKIPPED,
    OZAYN_WOF_EVENT_PAUSED,
    OZAYN_WOF_EVENT_RESUMED,
    OZAYN_WOF_EVENT_DRAINING,
    OZAYN_WOF_EVENT_CANCELLED,
    OZAYN_WOF_EVENT_TIMEOUT,
    OZAYN_WOF_EVENT_EXPIRED,
    OZAYN_WOF_EVENT_FAILED,
    OZAYN_WOF_EVENT_PARTIAL,
    OZAYN_WOF_EVENT_SUCCEEDED,
    OZAYN_WOF_EVENT_COMPENSATION_STARTED,
    OZAYN_WOF_EVENT_COMPENSATION_COMPLETED,
    OZAYN_WOF_EVENT_COMPENSATION_FAILED,
    OZAYN_WOF_EVENT_ORCHESTRATOR_STARTED,
    OZAYN_WOF_EVENT_ORCHESTRATOR_STOPPED,
    OZAYN_WOF_EVENT_COUNT
} ozayn_wof_event_type_t;

/* ============================================================
 * SECTION 11 — CLOSE REASONS
 * ============================================================ */

typedef enum {
    OZAYN_WOF_CLOSE_MANUAL_CANCEL = 0,
    OZAYN_WOF_CLOSE_DEPENDENCY_FAILED,
    OZAYN_WOF_CLOSE_PIPELINE_FAILED,
    OZAYN_WOF_CLOSE_RESOURCE_EXHAUSTED,
    OZAYN_WOF_CLOSE_DEVICE_UNAVAILABLE,
    OZAYN_WOF_CLOSE_AUTH_REVOKED,
    OZAYN_WOF_CLOSE_SAFETY_DENIED,
    OZAYN_WOF_CLOSE_POLICY_DENIED,
    OZAYN_WOF_CLOSE_TIMEOUT,
    OZAYN_WOF_CLOSE_DEADLINE_EXPIRED,
    OZAYN_WOF_CLOSE_CONFLICT,
    OZAYN_WOF_CLOSE_CONCURRENCY_LIMIT,
    OZAYN_WOF_CLOSE_SESSION_EXPIRED,
    OZAYN_WOF_CLOSE_SHUTDOWN,
    OZAYN_WOF_CLOSE_ORCHESTRATION_ERROR,
    OZAYN_WOF_CLOSE_PARTIAL_COMPLETION,
    OZAYN_WOF_CLOSE_COUNT
} ozayn_wof_close_reason_t;

/* ============================================================
 * SECTION 12 — CONSTANTS
 * ============================================================ */

#define OZAYN_WOF_MAX_WORKFLOWS             32
#define OZAYN_WOF_MAX_STAGES_PER_WORKFLOW   16
#define OZAYN_WOF_MAX_DEPENDENCIES          32
#define OZAYN_WOF_MAX_STAGE_DEPENDENCIES    8
#define OZAYN_WOF_MAX_DEPENDENCY_DEPTH      8
#define OZAYN_WOF_MAX_CONCURRENT_WORKFLOWS  8
#define OZAYN_WOF_MAX_CONCURRENT_STAGES     4
#define OZAYN_WOF_MAX_EVENTS                64
#define OZAYN_WOF_MAX_ID_LEN                64
#define OZAYN_WOF_MAX_NAME_LEN              64
#define OZAYN_WOF_MAX_DESC_LEN             128
#define OZAYN_WOF_MAX_METADATA_LEN         256
#define OZAYN_WOF_MAX_VERSION_LEN           32

#define OZAYN_WOF_DEFAULT_WORKFLOW_TIMEOUT_MS    600000
#define OZAYN_WOF_DEFAULT_STAGE_TIMEOUT_MS       300000
#define OZAYN_WOF_DEFAULT_DRAIN_TIMEOUT_MS       30000
#define OZAYN_WOF_DEFAULT_TICK_INTERVAL_MS       100
#define OZAYN_WOF_DEFAULT_MAX_RETRIES           3
#define OZAYN_WOF_DEFAULT_MAX_DEPTH             8

/* ============================================================
 * SECTION 13 — WORKFLOW STAGE STRUCTURE
 * ============================================================ */

typedef struct {
    char    stage_id[OZAYN_WOF_MAX_ID_LEN];
    char    workflow_id[OZAYN_WOF_MAX_ID_LEN];
    char    name[OZAYN_WOF_MAX_NAME_LEN];
    char    description[OZAYN_WOF_MAX_DESC_LEN];
    char    pipeline_id[OZAYN_WOF_MAX_ID_LEN];
    char    operation_id[OZAYN_WOF_MAX_ID_LEN];
    char    dependencies[OZAYN_WOF_MAX_STAGE_DEPENDENCIES][OZAYN_WOF_MAX_ID_LEN];
    int     dependency_count;
    char    required_capability[OZAYN_WOF_MAX_ID_LEN];
    char    required_resources[4][OZAYN_WOF_MAX_ID_LEN];
    int     required_resource_count;
    char    required_permission[OZAYN_WOF_MAX_ID_LEN];
    char    security_session_ref[OZAYN_WOF_MAX_ID_LEN];
    char    authorization_ref[OZAYN_WOF_MAX_ID_LEN];
    char    safety_decision_ref[OZAYN_WOF_MAX_ID_LEN];
    char    scheduler_entry_id[OZAYN_WOF_MAX_ID_LEN];
    char    compensation_pipeline_id[OZAYN_WOF_MAX_ID_LEN];
    int     order;
    int     is_optional;
    int     is_critical;
    ozayn_wof_stage_type_t          stage_type;
    ozayn_wof_stage_state_t         state;
    ozayn_wof_condition_type_t      condition_type;
    ozayn_wof_failure_policy_t      failure_policy;
    ozayn_wof_compensation_action_t compensation_action;
    int64_t  timeout_ms;
    int      max_retries;
    int      retry_count;
    uint64_t result_code;
    int64_t  created_time;
    int64_t  started_time;
    int64_t  completed_time;
    int      active;
} ozayn_wof_stage_t;

/* ============================================================
 * SECTION 14 — WORKFLOW STRUCTURE
 * ============================================================ */

typedef struct {
    char    workflow_id[OZAYN_WOF_MAX_ID_LEN];
    char    version[OZAYN_WOF_MAX_VERSION_LEN];
    char    name[OZAYN_WOF_MAX_NAME_LEN];
    char    description[OZAYN_WOF_MAX_DESC_LEN];
    char    owner_ref[OZAYN_WOF_MAX_ID_LEN];
    char    requester_ref[OZAYN_WOF_MAX_ID_LEN];
    char    operation_id[OZAYN_WOF_MAX_ID_LEN];
    char    security_session_ref[OZAYN_WOF_MAX_ID_LEN];
    char    authorization_ref[OZAYN_WOF_MAX_ID_LEN];
    char    safety_decision_ref[OZAYN_WOF_MAX_ID_LEN];
    char    close_reason_detail[OZAYN_WOF_MAX_DESC_LEN];
    char    safe_metadata[OZAYN_WOF_MAX_METADATA_LEN];
    int     active;
    int     version_number;
    ozayn_wof_workflow_type_t       workflow_type;
    ozayn_wof_workflow_state_t      state;
    ozayn_wof_failure_policy_t      failure_policy;
    ozayn_wof_concurrency_policy_t  concurrency_policy;
    ozayn_wof_close_reason_t        close_reason;
    int     stage_count;
    int     completed_stage_count;
    int     failed_stage_count;
    int     cancelled_stage_count;
    int     skipped_stage_count;
    int     blocked_stage_count;
    int     max_concurrent_stages;
    int     current_active_stages;
    int64_t  timeout_ms;
    int64_t  stage_timeout_ms;
    int64_t  created_time;
    int64_t  start_time;
    int64_t  completion_time;
    int64_t  last_tick_time;
    int64_t  start_deadline_ms;
    int64_t  execution_deadline_ms;
    uint64_t result_code;
    uint64_t depth;
} ozayn_wof_workflow_t;

/* ============================================================
 * SECTION 15 — DEPENDENCY STRUCTURE
 * ============================================================ */

typedef struct {
    char    dependency_id[OZAYN_WOF_MAX_ID_LEN];
    char    workflow_id[OZAYN_WOF_MAX_ID_LEN];
    char    source_stage_id[OZAYN_WOF_MAX_ID_LEN];
    char    target_stage_id[OZAYN_WOF_MAX_ID_LEN];
    int     active;
} ozayn_wof_dependency_t;

/* ============================================================
 * SECTION 16 — EVENT STRUCTURE
 * ============================================================ */

typedef struct {
    char    event_id[OZAYN_WOF_MAX_ID_LEN];
    char    workflow_id[OZAYN_WOF_MAX_ID_LEN];
    char    stage_id[OZAYN_WOF_MAX_ID_LEN];
    char    pipeline_id[OZAYN_WOF_MAX_ID_LEN];
    char    operation_id[OZAYN_WOF_MAX_ID_LEN];
    char    request_id[OZAYN_WOF_MAX_ID_LEN];
    char    message[OZAYN_WOF_MAX_DESC_LEN];
    ozayn_wof_event_type_t  event_type;
    int64_t  timestamp;
    uint64_t sequence;
    int      active;
} ozayn_wof_event_t;

/* ============================================================
 * SECTION 17 — STATISTICS STRUCTURE
 * ============================================================ */

typedef struct {
    uint64_t  total_workflows_created;
    uint64_t  total_workflows_validated;
    uint64_t  total_workflows_authorized;
    uint64_t  total_workflows_rejected;
    uint64_t  total_workflows_ready;
    uint64_t  total_workflows_scheduled;
    uint64_t  total_workflows_started;
    uint64_t  total_workflows_succeeded;
    uint64_t  total_workflows_failed;
    uint64_t  total_workflows_cancelled;
    uint64_t  total_workflows_expired;
    uint64_t  total_workflows_timeout;
    uint64_t  total_workflows_partial;
    uint64_t  total_stages_created;
    uint64_t  total_stages_completed;
    uint64_t  total_stages_failed;
    uint64_t  total_stages_skipped;
    uint64_t  total_stages_blocked;
    uint64_t  total_dependencies_added;
    uint64_t  total_dependency_cycles_detected;
    uint64_t  total_state_transitions;
    uint64_t  total_events_emitted;
    uint64_t  total_retries;
    uint64_t  total_fairness_adjustments;
    uint64_t  active_workflows;
    uint64_t  active_stages;
    uint64_t  peak_workflows;
    uint64_t  peak_stages;
} ozayn_wof_stats_t;

/* ============================================================
 * SECTION 18 — SERVICE CONFIGURATION
 * ============================================================ */

typedef struct {
    void *component_registry;
    void *safety_engine;
    void *resource_manager;
    void *operation_queue;
    void *pipeline_coordinator;
    void *pipeline_scheduler;
    void *diagnostics;
    void *operation_history;
    void *audit;
} ozayn_wof_service_config_t;

/* ============================================================
 * SECTION 19 — SERVICE STATE
 * ============================================================ */

typedef struct {
    int                        initialized;
    ozayn_wof_service_config_t config;
    ozayn_wof_workflow_t       workflows[OZAYN_WOF_MAX_WORKFLOWS];
    ozayn_wof_stage_t          stages[OZAYN_WOF_MAX_WORKFLOWS * OZAYN_WOF_MAX_STAGES_PER_WORKFLOW];
    ozayn_wof_dependency_t     dependencies[OZAYN_WOF_MAX_DEPENDENCIES];
    ozayn_wof_event_t          events[OZAYN_WOF_MAX_EVENTS];
    ozayn_wof_stats_t          stats;
    uint64_t                   event_sequence;
    int64_t                    last_tick_time;
    int64_t                    init_time;
    void                      *audit;
} ozayn_wof_service_t;

/* ============================================================
 * SECTION 20 — LIFECYCLE FUNCTIONS
 * ============================================================ */

ozayn_wof_err_t ozayn_wof_service_init(ozayn_wof_service_t *svc,
                                        const ozayn_wof_service_config_t *config);
ozayn_wof_err_t ozayn_wof_service_shutdown(ozayn_wof_service_t *svc);
int             ozayn_wof_is_initialized(const ozayn_wof_service_t *svc);
ozayn_wof_service_t *ozayn_wof_get_global(void);

/* ============================================================
 * SECTION 21 — WORKFLOW LIFECYCLE FUNCTIONS
 * ============================================================ */

ozayn_wof_err_t ozayn_wof_create(ozayn_wof_service_t *svc,
                                  const char *name,
                                  const char *description,
                                  const char *version,
                                  ozayn_wof_workflow_type_t wf_type,
                                  const char *owner_ref,
                                  const char *requester_ref,
                                  const char *session_ref,
                                  const char *safe_metadata,
                                  char *out_workflow_id,
                                  int out_id_len);

ozayn_wof_err_t ozayn_wof_validate(ozayn_wof_service_t *svc,
                                    const char *workflow_id);

ozayn_wof_err_t ozayn_wof_authorize(ozayn_wof_service_t *svc,
                                     const char *workflow_id,
                                     const char *authorization_ref,
                                     const char *safety_ref);

ozayn_wof_err_t ozayn_wof_reject(ozayn_wof_service_t *svc,
                                  const char *workflow_id,
                                  ozayn_wof_close_reason_t reason,
                                  const char *detail);

ozayn_wof_err_t ozayn_wof_ready(ozayn_wof_service_t *svc,
                                 const char *workflow_id);

ozayn_wof_err_t ozayn_wof_schedule(ozayn_wof_service_t *svc,
                                    const char *workflow_id);

ozayn_wof_err_t ozayn_wof_start(ozayn_wof_service_t *svc,
                                 const char *workflow_id);

ozayn_wof_err_t ozayn_wof_pause(ozayn_wof_service_t *svc,
                                 const char *workflow_id);

ozayn_wof_err_t ozayn_wof_resume(ozayn_wof_service_t *svc,
                                  const char *workflow_id);

ozayn_wof_err_t ozayn_wof_cancel(ozayn_wof_service_t *svc,
                                  const char *workflow_id,
                                  ozayn_wof_close_reason_t reason);

ozayn_wof_err_t ozayn_wof_drain(ozayn_wof_service_t *svc,
                                 const char *workflow_id);

ozayn_wof_err_t ozayn_wof_stop(ozayn_wof_service_t *svc,
                                const char *workflow_id);

ozayn_wof_err_t ozayn_wof_remove(ozayn_wof_service_t *svc,
                                  const char *workflow_id);

/* ============================================================
 * SECTION 22 — STAGE MANAGEMENT FUNCTIONS
 * ============================================================ */

ozayn_wof_err_t ozayn_wof_stage_add(ozayn_wof_service_t *svc,
                                     const char *workflow_id,
                                     const char *name,
                                     const char *description,
                                     ozayn_wof_stage_type_t stage_type,
                                     const char *pipeline_id,
                                     const char *operation_id,
                                     const char *required_capability,
                                     const char *required_permission,
                                     const char *session_ref,
                                     int timeout_ms,
                                     int is_optional,
                                     int is_critical,
                                     ozayn_wof_failure_policy_t failure_policy,
                                     ozayn_wof_compensation_action_t comp_action,
                                     const char *comp_pipeline_id,
                                     char *out_stage_id,
                                     int out_id_len);

ozayn_wof_err_t ozayn_wof_stage_remove(ozayn_wof_service_t *svc,
                                        const char *workflow_id,
                                        const char *stage_id);

ozayn_wof_err_t ozayn_wof_stage_set_state(ozayn_wof_service_t *svc,
                                           const char *workflow_id,
                                           const char *stage_id,
                                           ozayn_wof_stage_state_t new_state);

/* ============================================================
 * SECTION 23 — DEPENDENCY MANAGEMENT FUNCTIONS
 * ============================================================ */

ozayn_wof_err_t ozayn_wof_add_dependency(ozayn_wof_service_t *svc,
                                          const char *workflow_id,
                                          const char *source_stage_id,
                                          const char *target_stage_id);

ozayn_wof_err_t ozayn_wof_remove_dependency(ozayn_wof_service_t *svc,
                                             const char *workflow_id,
                                             const char *dependency_id);

/* ============================================================
 * SECTION 24 — READINESS AND ORCHESTRATION FUNCTIONS
 * ============================================================ */

ozayn_wof_err_t ozayn_wof_tick(ozayn_wof_service_t *svc, int64_t now_ms);

/* ============================================================
 * SECTION 25 — QUERY FUNCTIONS
 * ============================================================ */

const ozayn_wof_workflow_t *ozayn_wof_get_workflow(
    const ozayn_wof_service_t *svc, const char *workflow_id);

const ozayn_wof_stage_t *ozayn_wof_get_stage(
    const ozayn_wof_service_t *svc, const char *workflow_id,
    const char *stage_id);

int ozayn_wof_workflow_count(const ozayn_wof_service_t *svc);

int ozayn_wof_workflow_count_by_state(const ozayn_wof_service_t *svc,
                                      ozayn_wof_workflow_state_t state);

int ozayn_wof_stage_count(const ozayn_wof_service_t *svc,
                           const char *workflow_id);

int ozayn_wof_dependency_count(const ozayn_wof_service_t *svc,
                                const char *workflow_id);

int ozayn_wof_is_terminal(ozayn_wof_workflow_state_t state);

int ozayn_wof_is_stage_terminal(ozayn_wof_stage_state_t state);

int ozayn_wof_concurrent_workflows(const ozayn_wof_service_t *svc);

int ozayn_wof_concurrent_stages(const ozayn_wof_service_t *svc,
                                 const char *workflow_id);

/* ============================================================
 * SECTION 26 — EVENT FUNCTIONS
 * ============================================================ */

ozayn_wof_err_t ozayn_wof_emit_event(ozayn_wof_service_t *svc,
                                      ozayn_wof_event_type_t event_type,
                                      const char *workflow_id,
                                      const char *stage_id,
                                      const char *pipeline_id,
                                      const char *operation_id,
                                      const char *message);

const ozayn_wof_event_t *ozayn_wof_get_event(
    const ozayn_wof_service_t *svc, int index);

int ozayn_wof_event_count(const ozayn_wof_service_t *svc);

/* ============================================================
 * SECTION 27 — CLEANUP FUNCTIONS
 * ============================================================ */

ozayn_wof_err_t ozayn_wof_cleanup_terminal(ozayn_wof_service_t *svc);
ozayn_wof_err_t ozayn_wof_cleanup_expired(ozayn_wof_service_t *svc, int64_t now_ms);
ozayn_wof_err_t ozayn_wof_cleanup_all(ozayn_wof_service_t *svc);

/* ============================================================
 * SECTION 28 — STATISTICS FUNCTIONS
 * ============================================================ */

const ozayn_wof_stats_t *ozayn_wof_get_stats(const ozayn_wof_service_t *svc);
ozayn_wof_err_t ozayn_wof_reset_stats(ozayn_wof_service_t *svc);

/* ============================================================
 * SECTION 29 — VALIDATION FUNCTIONS
 * ============================================================ */

int ozayn_wof_validate_workflow(const ozayn_wof_service_t *svc,
                                 const char *workflow_id);

int ozayn_wof_validate_stage(const ozayn_wof_service_t *svc,
                              const char *workflow_id,
                              const char *stage_id);

int ozayn_wof_validate_config(const ozayn_wof_service_config_t *config);

int ozayn_wof_is_valid_transition(ozayn_wof_workflow_state_t from,
                                   ozayn_wof_workflow_state_t to);

int ozayn_wof_is_valid_stage_transition(ozayn_wof_stage_state_t from,
                                         ozayn_wof_stage_state_t to);

/* ============================================================
 * SECTION 30 — NAME HELPER FUNCTIONS
 * ============================================================ */

const char *ozayn_wof_err_name(ozayn_wof_err_t err);
const char *ozayn_wof_workflow_state_name(ozayn_wof_workflow_state_t state);
const char *ozayn_wof_workflow_type_name(ozayn_wof_workflow_type_t type);
const char *ozayn_wof_stage_type_name(ozayn_wof_stage_type_t type);
const char *ozayn_wof_stage_state_name(ozayn_wof_stage_state_t state);
const char *ozayn_wof_condition_type_name(ozayn_wof_condition_type_t cond);
const char *ozayn_wof_failure_policy_name(ozayn_wof_failure_policy_t policy);
const char *ozayn_wof_compensation_action_name(ozayn_wof_compensation_action_t action);
const char *ozayn_wof_concurrency_policy_name(ozayn_wof_concurrency_policy_t policy);
const char *ozayn_wof_event_type_name(ozayn_wof_event_type_t type);
const char *ozayn_wof_close_reason_name(ozayn_wof_close_reason_t reason);

#endif /* OZAYN_WORKFLOW_ORCHESTRATOR_H */
