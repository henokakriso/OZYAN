#ifndef OZAYN_WORKFLOW_RECOVERY_H
#define OZAYN_WORKFLOW_RECOVERY_H

#include <stdint.h>
#include <time.h>

/* ============================================================
 * SECTION 1 — ERROR CODES
 * ============================================================ */

typedef enum {
    OZAYN_WFR_OK                            =   0,
    OZAYN_WFR_ERR_NULL                      =  -1,
    OZAYN_WFR_ERR_NOT_INITIALIZED           =  -2,
    OZAYN_WFR_ERR_ALREADY_INIT              =  -3,
    OZAYN_WFR_ERR_INVALID_PARAM             =  -4,
    OZAYN_WFR_ERR_LIMIT_REACHED             =  -5,
    OZAYN_WFR_ERR_NOT_FOUND                 =  -6,
    OZAYN_WFR_ERR_DUPLICATE                 =  -7,
    OZAYN_WFR_ERR_STATE_INVALID             =  -8,
    OZAYN_WFR_ERR_AUTH_FAILED               =  -9,
    OZAYN_WFR_ERR_SAFETY_CHECK_FAILED       = -10,
    OZAYN_WFR_ERR_RESOURCE_UNAVAILABLE      = -11,
    OZAYN_WFR_ERR_DEPENDENCY_FAILED         = -12,
    OZAYN_WFR_ERR_PIPELINE_INVALID          = -13,
    OZAYN_WFR_ERR_TIMEOUT                   = -14,
    OZAYN_WFR_ERR_CANCELLED                 = -15,
    OZAYN_WFR_ERR_EXPIRED                   = -16,
    OZAYN_WFR_ERR_UNRECOVERABLE             = -17,
    OZAYN_WFR_ERR_RETRY_NOT_ALLOWED         = -18,
    OZAYN_WFR_ERR_RETRY_LIMIT_EXCEEDED      = -19,
    OZAYN_WFR_ERR_COMPENSATION_FAILED       = -20,
    OZAYN_WFR_ERR_COMPENSATION_DENIED       = -21,
    OZAYN_WFR_ERR_EVENT_ERROR               = -22,
    OZAYN_WFR_ERR_HISTORY_ERROR             = -23,
    OZAYN_WFR_ERR_CONFIGURATION             = -24,
    OZAYN_WFR_ERR_UNAVAILABLE               = -25,
    OZAYN_WFR_ERR_REJECTED                  = -26,
    OZAYN_WFR_ERR_RECOVERY_TIMEOUT          = -27,
    OZAYN_WFR_ERR_RECOVERY_FAILED           = -28,
    OZAYN_WFR_ERR_ESCALATION_FAILED         = -29
} ozayn_wfr_err_t;

/* ============================================================
 * SECTION 2 — FAILURE CATEGORIES
 * ============================================================ */

typedef enum {
    OZAYN_WFR_CAT_VALIDATION = 0,
    OZAYN_WFR_CAT_AUTHORIZATION,
    OZAYN_WFR_CAT_SECURITY,
    OZAYN_WFR_CAT_SAFETY,
    OZAYN_WFR_CAT_RESOURCE,
    OZAYN_WFR_CAT_DEVICE,
    OZAYN_WFR_CAT_CAPABILITY,
    OZAYN_WFR_CAT_DEPENDENCY,
    OZAYN_WFR_CAT_PIPELINE,
    OZAYN_WFR_CAT_OPERATION,
    OZAYN_WFR_CAT_TIMEOUT,
    OZAYN_WFR_CAT_CANCELLATION,
    OZAYN_WFR_CAT_CONFIGURATION,
    OZAYN_WFR_CAT_STORAGE,
    OZAYN_WFR_CAT_EVENT,
    OZAYN_WFR_CAT_CONCURRENCY,
    OZAYN_WFR_CAT_PLATFORM,
    OZAYN_WFR_CAT_INTERNAL,
    OZAYN_WFR_CAT_UNKNOWN,
    OZAYN_WFR_CAT_COUNT
} ozayn_wfr_failure_category_t;

/* ============================================================
 * SECTION 3 — FAILURE SEVERITY
 * ============================================================ */

typedef enum {
    OZAYN_WFR_SEV_INFO = 0,
    OZAYN_WFR_SEV_LOW,
    OZAYN_WFR_SEV_MEDIUM,
    OZAYN_WFR_SEV_HIGH,
    OZAYN_WFR_SEV_CRITICAL,
    OZAYN_WFR_SEV_COUNT
} ozayn_wfr_failure_severity_t;

/* ============================================================
 * SECTION 4 — FAILURE STATES
 * ============================================================ */

typedef enum {
    OZAYN_WFR_FS_DETECTED = 0,
    OZAYN_WFR_FS_CLASSIFIED,
    OZAYN_WFR_FS_ASSESSING,
    OZAYN_WFR_FS_CONTAINING,
    OZAYN_WFR_FS_RECOVERING,
    OZAYN_WFR_FS_RECOVERED,
    OZAYN_WFR_FS_PARTIALLY_RECOVERED,
    OZAYN_WFR_FS_UNRECOVERABLE,
    OZAYN_WFR_FS_ESCALATED,
    OZAYN_WFR_FS_ACKNOWLEDGED,
    OZAYN_WFR_FS_CLOSED,
    OZAYN_WFR_FS_STATE_COUNT
} ozayn_wfr_failure_state_t;

/* ============================================================
 * SECTION 5 — RECOVERY DECISIONS
 * ============================================================ */

typedef enum {
    OZAYN_WFR_DEC_CONTINUE = 0,
    OZAYN_WFR_DEC_RETRY,
    OZAYN_WFR_DEC_PAUSE,
    OZAYN_WFR_DEC_CANCEL,
    OZAYN_WFR_DEC_FAIL_WORKFLOW,
    OZAYN_WFR_DEC_PARTIAL_CONTINUE,
    OZAYN_WFR_DEC_COMPENSATE,
    OZAYN_WFR_DEC_ESCALATE,
    OZAYN_WFR_DEC_UNAVAILABLE,
    OZAYN_WFR_DEC_COUNT
} ozayn_wfr_decision_type_t;

/* ============================================================
 * SECTION 6 — IMPACT LEVELS
 * ============================================================ */

typedef enum {
    OZAYN_WFR_IMPACT_STAGE_ONLY = 0,
    OZAYN_WFR_IMPACT_DEPENDENT_STAGES,
    OZAYN_WFR_IMPACT_WORKFLOW,
    OZAYN_WFR_IMPACT_RELATED_RESOURCE,
    OZAYN_WFR_IMPACT_RELATED_DEVICE,
    OZAYN_WFR_IMPACT_RELATED_PIPELINES,
    OZAYN_WFR_IMPACT_COUNT
} ozayn_wfr_impact_level_t;

/* ============================================================
 * SECTION 7 — CONTAINMENT ACTIONS
 * ============================================================ */

typedef enum {
    OZAYN_WFR_CONTAIN_STOP_DISPATCH = 0,
    OZAYN_WFR_CONTAIN_BLOCK_DEPENDENTS,
    OZAYN_WFR_CONTAIN_CANCEL_PENDING,
    OZAYN_WFR_CONTAIN_PAUSE_WORKFLOW,
    OZAYN_WFR_CONTAIN_DRAIN_PIPELINE,
    OZAYN_WFR_CONTAIN_CANCEL_PIPELINE,
    OZAYN_WFR_CONTAIN_RELEASE_RESOURCES,
    OZAYN_WFR_CONTAIN_CLOSE_DEVICE_SESSION,
    OZAYN_WFR_CONTAIN_DISCONNECT_ROUTE,
    OZAYN_WFR_CONTAIN_CLOSE_STREAM,
    OZAYN_WFR_CONTAIN_COUNT
} ozayn_wfr_containment_action_t;

/* ============================================================
 * SECTION 8 — IDEMPOTENCY
 * ============================================================ */

typedef enum {
    OZAYN_WFR_IDEMP_IDEMPOTENT = 0,
    OZAYN_WFR_IDEMP_SAFE_REPEAT,
    OZAYN_WFR_IDEMP_NON_IDEMPOTENT,
    OZAYN_WFR_IDEMP_UNKNOWN,
    OZAYN_WFR_IDEMP_COUNT
} ozayn_wfr_idempotency_t;

/* ============================================================
 * SECTION 9 — BACKOFF STRATEGIES
 * ============================================================ */

typedef enum {
    OZAYN_WFR_BACKOFF_IMMEDIATE = 0,
    OZAYN_WFR_BACKOFF_FIXED_DELAY,
    OZAYN_WFR_BACKOFF_BOUNDED_EXPONENTIAL,
    OZAYN_WFR_BACKOFF_COUNT
} ozayn_wfr_backoff_strategy_t;

/* ============================================================
 * SECTION 10 — RECOVERY STATES (on workflow)
 * ============================================================ */

typedef enum {
    OZAYN_WFR_RECOVERY_NONE = 0,
    OZAYN_WFR_RECOVERY_RECOVERING,
    OZAYN_WFR_RECOVERY_COMPENSATING,
    OZAYN_WFR_RECOVERY_RETRYING,
    OZAYN_WFR_RECOVERY_ESCALATED,
    OZAYN_WFR_RECOVERY_COUNT
} ozayn_wfr_recovery_state_t;

/* ============================================================
 * SECTION 11 — EVENT TYPES
 * ============================================================ */

typedef enum {
    OZAYN_WFR_EVENT_FAILURE_DETECTED = 0,
    OZAYN_WFR_EVENT_FAILURE_CLASSIFIED,
    OZAYN_WFR_EVENT_FAILURE_ASSESSING,
    OZAYN_WFR_EVENT_FAILURE_CONTAINING,
    OZAYN_WFR_EVENT_FAILURE_CONTAINED,
    OZAYN_WFR_EVENT_RECOVERY_STARTED,
    OZAYN_WFR_EVENT_RECOVERY_RETRYING,
    OZAYN_WFR_EVENT_RECOVERY_COMPLETED,
    OZAYN_WFR_EVENT_RECOVERY_PARTIAL,
    OZAYN_WFR_EVENT_RECOVERY_FAILED,
    OZAYN_WFR_EVENT_RECOVERY_TIMEOUT,
    OZAYN_WFR_EVENT_RECOVERY_ESCALATED,
    OZAYN_WFR_EVENT_WORKFLOW_DEGRADED,
    OZAYN_WFR_EVENT_WORKFLOW_RECOVERING,
    OZAYN_WFR_EVENT_WORKFLOW_UNRECOVERABLE,
    OZAYN_WFR_EVENT_COMPENSATION_STARTED,
    OZAYN_WFR_EVENT_COMPENSATION_COMPLETED,
    OZAYN_WFR_EVENT_COMPENSATION_FAILED,
    OZAYN_WFR_EVENT_COUNT
} ozayn_wfr_event_type_t;

/* ============================================================
 * SECTION 12 — RECOVERY HISTORY RESULT
 * ============================================================ */

typedef enum {
    OZAYN_WFR_HIST_SUCCESS = 0,
    OZAYN_WFR_HIST_FAILURE,
    OZAYN_WFR_HIST_TIMEOUT,
    OZAYN_WFR_HIST_DENIED,
    OZAYN_WFR_HIST_ESCALATED,
    OZAYN_WFR_HIST_COUNT
} ozayn_wfr_history_result_t;

/* ============================================================
 * SECTION 13 — CONSTANTS
 * ============================================================ */

#define OZAYN_WFR_MAX_FAILURES              32
#define OZAYN_WFR_MAX_RECOVERY_RECORDS      64
#define OZAYN_WFR_MAX_RECOVERY_HISTORY      32
#define OZAYN_WFR_MAX_CONTAINMENT_ACTIONS   16
#define OZAYN_WFR_MAX_EVENTS                64
#define OZAYN_WFR_MAX_ID_LEN                64
#define OZAYN_WFR_MAX_DESC_LEN             128
#define OZAYN_WFR_MAX_METADATA_LEN         256
#define OZAYN_WFR_MAX_AFFECTED_COMPONENTS   8
#define OZAYN_WFR_MAX_EVIDENCE_REFS         4
#define OZAYN_WFR_MAX_RECOVERY_PRECONDITIONS 4

#define OZAYN_WFR_DEFAULT_RECOVERY_TIMEOUT_MS   30000
#define OZAYN_WFR_DEFAULT_MAX_RETRIES            3
#define OZAYN_WFR_DEFAULT_FIXED_DELAY_MS      1000
#define OZAYN_WFR_DEFAULT_EXPONENTIAL_BASE_MS 1000
#define OZAYN_WFR_DEFAULT_EXPONENTIAL_MAX_MS  30000

/* ============================================================
 * SECTION 14 — FAILURE RECORD STRUCTURE
 * ============================================================ */

typedef struct {
    char    failure_id[OZAYN_WFR_MAX_ID_LEN];
    char    workflow_id[OZAYN_WFR_MAX_ID_LEN];
    char    stage_id[OZAYN_WFR_MAX_ID_LEN];
    char    operation_id[OZAYN_WFR_MAX_ID_LEN];
    char    pipeline_id[OZAYN_WFR_MAX_ID_LEN];
    char    request_id[OZAYN_WFR_MAX_ID_LEN];
    char    source_component[OZAYN_WFR_MAX_ID_LEN];
    char    affected_components[OZAYN_WFR_MAX_AFFECTED_COMPONENTS][OZAYN_WFR_MAX_ID_LEN];
    int     affected_component_count;
    char    evidence_refs[OZAYN_WFR_MAX_EVIDENCE_REFS][OZAYN_WFR_MAX_ID_LEN];
    int     evidence_ref_count;
    char    description[OZAYN_WFR_MAX_DESC_LEN];
    char    safe_metadata[OZAYN_WFR_MAX_METADATA_LEN];
    ozayn_wfr_failure_category_t  category;
    ozayn_wfr_failure_severity_t  severity;
    ozayn_wfr_failure_state_t     state;
    ozayn_wfr_impact_level_t      impact_level;
    int      error_code;
    int      active;
    int64_t  detected_time;
    int64_t  failure_time;
    int64_t  classified_time;
    int64_t  contained_time;
    int64_t  resolved_time;
} ozayn_wfr_failure_record_t;

/* ============================================================
 * SECTION 15 — RECOVERY DECISION STRUCTURE
 * ============================================================ */

typedef struct {
    char    decision_id[OZAYN_WFR_MAX_ID_LEN];
    char    failure_id[OZAYN_WFR_MAX_ID_LEN];
    char    workflow_id[OZAYN_WFR_MAX_ID_LEN];
    char    stage_id[OZAYN_WFR_MAX_ID_LEN];
    char    preconditions[OZAYN_WFR_MAX_RECOVERY_PRECONDITIONS][OZAYN_WFR_MAX_DESC_LEN];
    int     precondition_count;
    char    authorization_ref[OZAYN_WFR_MAX_ID_LEN];
    char    safety_ref[OZAYN_WFR_MAX_ID_LEN];
    char    reason[OZAYN_WFR_MAX_DESC_LEN];
    char    safe_metadata[OZAYN_WFR_MAX_METADATA_LEN];
    ozayn_wfr_decision_type_t  decision;
    int      authorized;
    int      safety_ok;
    int      resources_ok;
    int      active;
    int64_t  decision_time;
    int64_t  expiration_time;
} ozayn_wfr_recovery_decision_t;

/* ============================================================
 * SECTION 16 — RECOVERY HISTORY ENTRY
 * ============================================================ */

typedef struct {
    char    history_id[OZAYN_WFR_MAX_ID_LEN];
    char    failure_id[OZAYN_WFR_MAX_ID_LEN];
    char    decision_id[OZAYN_WFR_MAX_ID_LEN];
    char    workflow_id[OZAYN_WFR_MAX_ID_LEN];
    char    stage_id[OZAYN_WFR_MAX_ID_LEN];
    char    operation_id[OZAYN_WFR_MAX_ID_LEN];
    char    pipeline_id[OZAYN_WFR_MAX_ID_LEN];
    ozayn_wfr_decision_type_t     decision;
    ozayn_wfr_history_result_t     result;
    int      attempt_number;
    int      active;
    int64_t  attempt_time;
    int64_t  result_time;
    int64_t  recovery_duration_ms;
} ozayn_wfr_recovery_history_t;

/* ============================================================
 * SECTION 17 — EVENT STRUCTURE
 * ============================================================ */

typedef struct {
    char    event_id[OZAYN_WFR_MAX_ID_LEN];
    char    failure_id[OZAYN_WFR_MAX_ID_LEN];
    char    workflow_id[OZAYN_WFR_MAX_ID_LEN];
    char    stage_id[OZAYN_WFR_MAX_ID_LEN];
    char    message[OZAYN_WFR_MAX_DESC_LEN];
    ozayn_wfr_event_type_t  event_type;
    int64_t  timestamp;
    uint64_t sequence;
    int      active;
} ozayn_wfr_event_t;

/* ============================================================
 * SECTION 18 — STATISTICS STRUCTURE
 * ============================================================ */

typedef struct {
    uint64_t  total_failures_detected;
    uint64_t  total_failures_classified;
    uint64_t  total_failures_contained;
    uint64_t  total_failures_recovered;
    uint64_t  total_failures_partially_recovered;
    uint64_t  total_failures_unrecoverable;
    uint64_t  total_failures_escalated;
    uint64_t  total_recovery_attempts;
    uint64_t  total_recovery_successes;
    uint64_t  total_recovery_failures;
    uint64_t  total_recovery_timeouts;
    uint64_t  total_compensation_attempts;
    uint64_t  total_compensation_successes;
    uint64_t  total_compensation_failures;
    uint64_t  total_retries;
    uint64_t  total_retries_exhausted;
    uint64_t  total_containment_actions;
    uint64_t  total_events_emitted;
    uint64_t  active_failures;
    uint64_t  active_recoveries;
    uint64_t  peak_failures;
    uint64_t  peak_recoveries;
} ozayn_wfr_stats_t;

/* ============================================================
 * SECTION 19 — SERVICE CONFIGURATION
 * ============================================================ */

typedef struct {
    void *workflow_orchestrator;
    void *pipeline_scheduler;
    void *pipeline_coordinator;
    void *resource_manager;
    void *safety_engine;
    void *operation_queue;
    void *diagnostics;
    void *component_registry;
    void *operation_history;
    void *audit;
} ozayn_wfr_service_config_t;

/* ============================================================
 * SECTION 20 — SERVICE STATE
 * ============================================================ */

typedef struct {
    int                          initialized;
    ozayn_wfr_service_config_t   config;
    ozayn_wfr_failure_record_t   failures[OZAYN_WFR_MAX_FAILURES];
    ozayn_wfr_recovery_decision_t decisions[OZAYN_WFR_MAX_RECOVERY_RECORDS];
    ozayn_wfr_recovery_history_t history[OZAYN_WFR_MAX_RECOVERY_HISTORY];
    ozayn_wfr_event_t            events[OZAYN_WFR_MAX_EVENTS];
    ozayn_wfr_stats_t            stats;
    uint64_t                     event_sequence;
    int64_t                      last_tick_time;
    int64_t                      init_time;
    void                        *audit;
} ozayn_wfr_service_t;

/* ============================================================
 * SECTION 21 — LIFECYCLE FUNCTIONS
 * ============================================================ */

ozayn_wfr_err_t ozayn_wfr_service_init(ozayn_wfr_service_t *svc,
                                        const ozayn_wfr_service_config_t *config);
ozayn_wfr_err_t ozayn_wfr_service_shutdown(ozayn_wfr_service_t *svc);
int             ozayn_wfr_is_initialized(const ozayn_wfr_service_t *svc);
ozayn_wfr_service_t *ozayn_wfr_get_global(void);

/* ============================================================
 * SECTION 22 — FAILURE RECORD FUNCTIONS
 * ============================================================ */

ozayn_wfr_err_t ozayn_wfr_record_failure(ozayn_wfr_service_t *svc,
                                          const char *workflow_id,
                                          const char *stage_id,
                                          const char *operation_id,
                                          const char *pipeline_id,
                                          const char *request_id,
                                          const char *source_component,
                                          ozayn_wfr_failure_category_t category,
                                          ozayn_wfr_failure_severity_t severity,
                                          int error_code,
                                          const char *description,
                                          char *out_failure_id,
                                          int out_id_len);

ozayn_wfr_err_t ozayn_wfr_classify_failure(ozayn_wfr_service_t *svc,
                                            const char *failure_id,
                                            ozayn_wfr_failure_category_t category,
                                            ozayn_wfr_failure_severity_t severity,
                                            ozayn_wfr_impact_level_t impact);

ozayn_wfr_err_t ozayn_wfr_close_failure(ozayn_wfr_service_t *svc,
                                         const char *failure_id);

ozayn_wfr_err_t ozayn_wfr_acknowledge_failure(ozayn_wfr_service_t *svc,
                                               const char *failure_id);

/* ============================================================
 * SECTION 23 — CONTAINMENT FUNCTIONS
 * ============================================================ */

ozayn_wfr_err_t ozayn_wfr_contain_failure(ozayn_wfr_service_t *svc,
                                           const char *failure_id,
                                           ozayn_wfr_containment_action_t action);

/* ============================================================
 * SECTION 24 — RECOVERY DECISION FUNCTIONS
 * ============================================================ */

ozayn_wfr_err_t ozayn_wfr_make_recovery_decision(
    ozayn_wfr_service_t *svc,
    const char *failure_id,
    ozayn_wfr_recovery_decision_t *decision_template,
    char *out_decision_id,
    int out_id_len);

ozayn_wfr_err_t ozayn_wfr_authorize_recovery(ozayn_wfr_service_t *svc,
                                              const char *decision_id,
                                              const char *authorization_ref,
                                              const char *safety_ref);

ozayn_wfr_err_t ozayn_wfr_execute_recovery(ozayn_wfr_service_t *svc,
                                            const char *decision_id);

/* ============================================================
 * SECTION 25 — RETRY FUNCTIONS
 * ============================================================ */

ozayn_wfr_err_t ozayn_wfr_evaluate_retry(ozayn_wfr_service_t *svc,
                                          const char *failure_id,
                                          ozayn_wfr_idempotency_t idempotency,
                                          ozayn_wfr_backoff_strategy_t backoff,
                                          int64_t backoff_delay_ms,
                                          int *out_retryable);

ozayn_wfr_err_t ozayn_wfr_execute_retry(ozayn_wfr_service_t *svc,
                                         const char *failure_id,
                                         const char *decision_id);

/* ============================================================
 * SECTION 26 — COMPENSATION FUNCTIONS
 * ============================================================ */

ozayn_wfr_err_t ozayn_wfr_evaluate_compensation(ozayn_wfr_service_t *svc,
                                                 const char *failure_id,
                                                 int *out_compensable);

ozayn_wfr_err_t ozayn_wfr_execute_compensation(ozayn_wfr_service_t *svc,
                                                const char *failure_id,
                                                const char *decision_id);

/* ============================================================
 * SECTION 27 — TICK / ORCHESTRATION FUNCTIONS
 * ============================================================ */

ozayn_wfr_err_t ozayn_wfr_tick(ozayn_wfr_service_t *svc, int64_t now_ms);

/* ============================================================
 * SECTION 28 — QUERY FUNCTIONS
 * ============================================================ */

const ozayn_wfr_failure_record_t *ozayn_wfr_get_failure(
    const ozayn_wfr_service_t *svc, const char *failure_id);

const ozayn_wfr_recovery_decision_t *ozayn_wfr_get_decision(
    const ozayn_wfr_service_t *svc, const char *decision_id);

const ozayn_wfr_recovery_history_t *ozayn_wfr_get_history_entry(
    const ozayn_wfr_service_t *svc, int index);

int ozayn_wfr_failure_count(const ozayn_wfr_service_t *svc);

int ozayn_wfr_failure_count_by_state(const ozayn_wfr_service_t *svc,
                                      ozayn_wfr_failure_state_t state);

int ozayn_wfr_failure_count_by_category(const ozayn_wfr_service_t *svc,
                                         ozayn_wfr_failure_category_t category);

int ozayn_wfr_decision_count(const ozayn_wfr_service_t *svc);

int ozayn_wfr_history_count(const ozayn_wfr_service_t *svc);

int ozayn_wfr_active_failures(const ozayn_wfr_service_t *svc);

int ozayn_wfr_active_recoveries(const ozayn_wfr_service_t *svc);

int ozayn_wfr_is_failure_terminal(ozayn_wfr_failure_state_t state);

/* ============================================================
 * SECTION 29 — EVENT FUNCTIONS
 * ============================================================ */

ozayn_wfr_err_t ozayn_wfr_emit_event(ozayn_wfr_service_t *svc,
                                      ozayn_wfr_event_type_t event_type,
                                      const char *failure_id,
                                      const char *workflow_id,
                                      const char *stage_id,
                                      const char *message);

const ozayn_wfr_event_t *ozayn_wfr_get_event(
    const ozayn_wfr_service_t *svc, int index);

int ozayn_wfr_event_count(const ozayn_wfr_service_t *svc);

/* ============================================================
 * SECTION 30 — CLEANUP FUNCTIONS
 * ============================================================ */

ozayn_wfr_err_t ozayn_wfr_cleanup_closed(ozayn_wfr_service_t *svc);
ozayn_wfr_err_t ozayn_wfr_cleanup_all(ozayn_wfr_service_t *svc);

/* ============================================================
 * SECTION 31 — STATISTICS FUNCTIONS
 * ============================================================ */

const ozayn_wfr_stats_t *ozayn_wfr_get_stats(const ozayn_wfr_service_t *svc);
ozayn_wfr_err_t ozayn_wfr_reset_stats(ozayn_wfr_service_t *svc);

/* ============================================================
 * SECTION 32 — VALIDATION FUNCTIONS
 * ============================================================ */

int ozayn_wfr_validate_failure_record(const ozayn_wfr_service_t *svc,
                                       const char *failure_id);

int ozayn_wfr_validate_decision(const ozayn_wfr_service_t *svc,
                                 const char *decision_id);

int ozayn_wfr_validate_config(const ozayn_wfr_service_config_t *config);

int ozayn_wfr_is_valid_failure_transition(ozayn_wfr_failure_state_t from,
                                           ozayn_wfr_failure_state_t to);

/* ============================================================
 * SECTION 33 — NAME HELPER FUNCTIONS
 * ============================================================ */

const char *ozayn_wfr_err_name(ozayn_wfr_err_t err);
const char *ozayn_wfr_failure_category_name(ozayn_wfr_failure_category_t cat);
const char *ozayn_wfr_failure_severity_name(ozayn_wfr_failure_severity_t sev);
const char *ozayn_wfr_failure_state_name(ozayn_wfr_failure_state_t state);
const char *ozayn_wfr_recovery_decision_name(ozayn_wfr_decision_type_t dec);
const char *ozayn_wfr_impact_level_name(ozayn_wfr_impact_level_t impact);
const char *ozayn_wfr_containment_action_name(ozayn_wfr_containment_action_t act);
const char *ozayn_wfr_idempotency_name(ozayn_wfr_idempotency_t idemp);
const char *ozayn_wfr_backoff_strategy_name(ozayn_wfr_backoff_strategy_t backoff);
const char *ozayn_wfr_recovery_state_name(ozayn_wfr_recovery_state_t state);
const char *ozayn_wfr_event_type_name(ozayn_wfr_event_type_t type);
const char *ozayn_wfr_history_result_name(ozayn_wfr_history_result_t result);

#endif /* OZAYN_WORKFLOW_RECOVERY_H */
