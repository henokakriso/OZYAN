/*
 * operation_history.h — Operation History & Execution Records
 *
 * Provides a persistent, immutable historical record of completed
 * operations in the OZAYN Control Room. Separate from the live queue.
 *
 * Architecture:
 *   CONTROL OPERATION → EXECUTION RECORD → ATTEMPTS → RESULT → HISTORY STORE → QUERY
 *
 * This module does NOT:
 *   - Create a second authorization system
 *   - Execute arbitrary commands
 *   - Bypass existing Section 03 security
 *   - Replace the security audit system
 *
 * Step 06/35 — Control Room
 */

#ifndef OZAYN_OPERATION_HISTORY_H
#define OZAYN_OPERATION_HISTORY_H

#include <stdint.h>
#include <time.h>

/* ============================================================
 * SECTION 1 — LIMITS
 * ============================================================ */

#define OZAYN_OH_MAX_ID_LEN         64
#define OZAYN_OH_MAX_TARGET_LEN     64
#define OZAYN_OH_MAX_CAP_LEN        64
#define OZAYN_OH_MAX_META_LEN       256
#define OZAYN_OH_MAX_SESSION_LEN    64
#define OZAYN_OH_MAX_IDENTITY_LEN   64
#define OZAYN_OH_MAX_ERROR_LEN      256
#define OZAYN_OH_MAX_PERMISSION_LEN 64
#define OZAYN_OH_MAX_RECORDS        1024
#define OZAYN_OH_MAX_ATTEMPTS       16
#define OZAYN_OH_MAX_QUERY_RESULTS  64

/* ============================================================
 * SECTION 2 — ERROR CODES
 * ============================================================ */

typedef enum {
    OZAYN_OH_OK                        =   0,
    OZAYN_OH_ERR_NULL                  =  -1,
    OZAYN_OH_ERR_NOT_INITIALIZED       =  -2,
    OZAYN_OH_ERR_ALREADY_INITIALIZED   =  -3,
    OZAYN_OH_ERR_INVALID_PARAM         =  -4,
    OZAYN_OH_ERR_NOT_FOUND             =  -5,
    OZAYN_OH_ERR_DUPLICATE_RECORD      =  -6,
    OZAYN_OH_ERR_IMMUTABLE             =  -7,
    OZAYN_OH_ERR_STORAGE_FULL          =  -8,
    OZAYN_OH_ERR_STATE_INVALID         =  -9,
    OZAYN_OH_ERR_STATE_TRANSITION      = -10,
    OZAYN_OH_ERR_RETRY_EXHAUSTED       = -11,
    OZAYN_OH_ERR_NOT_TERMINAL          = -12,
    OZAYN_OH_ERR_STORAGE_FAILURE       = -13
} ozayn_oh_err_t;

/* ============================================================
 * SECTION 3 — TERMINAL STATES (historical record)
 * ============================================================ */

typedef enum {
    OZAYN_OH_STATE_SUCCEEDED     = 0,
    OZAYN_OH_STATE_FAILED        = 1,
    OZAYN_OH_STATE_CANCELLED     = 2,
    OZAYN_OH_STATE_TIMEOUT       = 3,
    OZAYN_OH_STATE_REJECTED      = 4,
    OZAYN_OH_STATE_EXPIRED       = 5,
    OZAYN_OH_STATE_UNAVAILABLE   = 6,
    OZAYN_OH_STATE_UNSUPPORTED   = 7,
    OZAYN_OH_STATE_COUNT
} ozayn_oh_state_t;

/* ============================================================
 * SECTION 4 — RESULT CATEGORIES
 * ============================================================ */

typedef enum {
    OZAYN_OH_RESULT_SUCCESS              = 0,
    OZAYN_OH_RESULT_TARGET_UNAVAILABLE   = 1,
    OZAYN_OH_RESULT_CAPABILITY_UNAVAILABLE = 2,
    OZAYN_OH_RESULT_AUTHORIZATION_FAILED = 3,
    OZAYN_OH_RESULT_PRECONDITION_FAILED  = 4,
    OZAYN_OH_RESULT_TIMEOUT              = 5,
    OZAYN_OH_RESULT_CANCELLED            = 6,
    OZAYN_OH_RESULT_DISPATCH_FAILED      = 7,
    OZAYN_OH_RESULT_RESOURCE_LIMIT       = 8,
    OZAYN_OH_RESULT_INTERNAL_ERROR       = 9,
    OZAYN_OH_RESULT_REJECTED             = 10,
    OZAYN_OH_RESULT_EXPIRED              = 11,
    OZAYN_OH_RESULT_UNAVAILABLE          = 12,
    OZAYN_OH_RESULT_UNSUPPORTED          = 13,
    OZAYN_OH_RESULT_COUNT
} ozayn_oh_result_t;

/* ============================================================
 * SECTION 5 — FAILURE CATEGORIES
 * ============================================================ */

typedef enum {
    OZAYN_OH_FAILURE_NONE               = 0,
    OZAYN_OH_FAILURE_COMPONENT_DOWN     = 1,
    OZAYN_OH_FAILURE_COMPONENT_BUSY     = 2,
    OZAYN_OH_FAILURE_COMPONENT_MISSING  = 3,
    OZAYN_OH_FAILURE_CAPABILITY_MISSING = 4,
    OZAYN_OH_FAILURE_CAPABILITY_MISSING_PROVIDER = 5,
    OZAYN_OH_FAILURE_AUTH_DENIED        = 6,
    OZAYN_OH_FAILURE_AUTH_UNAVAILABLE   = 7,
    OZAYN_OH_FAILURE_PRECONDITION_UNMET = 8,
    OZAYN_OH_FAILURE_DEPENDENCY_MISSING = 9,
    OZAYN_OH_FAILURE_TIMEOUT_EXCEEDED   = 10,
    OZAYN_OH_FAILURE_USER_CANCEL        = 11,
    OZAYN_OH_FAILURE_DISPATCH_ERROR     = 12,
    OZAYN_OH_FAILURE_INTERNAL           = 13,
    OZAYN_OH_FAILURE_STORAGE            = 14,
    OZAYN_OH_FAILURE_RESOURCE_EXHAUSTED = 15,
    OZAYN_OH_FAILURE_COUNT
} ozayn_oh_failure_t;

/* ============================================================
 * SECTION 6 — ACTION ENUM (mirrors queue)
 * ============================================================ */

typedef enum {
    OZAYN_OH_ACTION_START        = 0,
    OZAYN_OH_ACTION_STOP         = 1,
    OZAYN_OH_ACTION_PAUSE        = 2,
    OZAYN_OH_ACTION_RESUME       = 3,
    OZAYN_OH_ACTION_QUERY        = 4,
    OZAYN_OH_ACTION_RESTART      = 5,
    OZAYN_OH_ACTION_ENABLE       = 6,
    OZAYN_OH_ACTION_DISABLE      = 7,
    OZAYN_OH_ACTION_DIAGNOSTIC   = 8,
    OZAYN_OH_ACTION_COUNT
} ozayn_oh_action_t;

/* ============================================================
 * SECTION 7 — HISTORY EVENT TYPES
 * ============================================================ */

typedef enum {
    OZAYN_OH_EVENT_CREATED           = 0,
    OZAYN_OH_EVENT_ATTEMPT_STARTED   = 1,
    OZAYN_OH_EVENT_ATTEMPT_COMPLETED = 2,
    OZAYN_OH_EVENT_ATTEMPT_FAILED    = 3,
    OZAYN_OH_EVENT_ATTEMPT_CANCELLED = 4,
    OZAYN_OH_EVENT_ATTEMPT_TIMEOUT   = 5,
    OZAYN_OH_EVENT_RECORD_FINALIZED  = 6,
    OZAYN_OH_EVENT_RECORD_EXPIRED    = 7,
    OZAYN_OH_EVENT_COUNT
} ozayn_oh_event_type_t;

/* ============================================================
 * SECTION 8 — QUERY FILTER FLAGS
 * ============================================================ */

#define OZAYN_OH_FILTER_TARGET      (1 << 0)
#define OZAYN_OH_FILTER_CAPABILITY  (1 << 1)
#define OZAYN_OH_FILTER_ACTION      (1 << 2)
#define OZAYN_OH_FILTER_STATE       (1 << 3)
#define OZAYN_OH_FILTER_RESULT      (1 << 4)
#define OZAYN_OH_FILTER_REQUESTER   (1 << 5)
#define OZAYN_OH_FILTER_TIME_START  (1 << 6)
#define OZAYN_OH_FILTER_TIME_END    (1 << 7)
#define OZAYN_OH_FILTER_REQUEST_ID  (1 << 8)

/* ============================================================
 * SECTION 9 — STRUCTURES
 * ============================================================ */

/* Execution Attempt — one attempt within an operation's lifetime */
typedef struct {
    char                    attempt_id[OZAYN_OH_MAX_ID_LEN];
    int                     attempt_number;
    ozayn_oh_state_t        attempt_state;
    ozayn_oh_result_t       attempt_result;
    ozayn_oh_failure_t      failure_category;
    int                     result_code;
    char                    error_detail[OZAYN_OH_MAX_ERROR_LEN];
    time_t                  started_time;
    time_t                  completed_time;
    int                     duration_ms;
} ozayn_oh_attempt_t;

/* Execution Record — immutable historical record of a completed operation */
typedef struct {
    /* Core identification */
    char                    record_id[OZAYN_OH_MAX_ID_LEN];
    char                    operation_id[OZAYN_OH_MAX_ID_LEN];
    char                    request_id[OZAYN_OH_MAX_ID_LEN];

    /* Target and capability */
    char                    target[OZAYN_OH_MAX_TARGET_LEN];
    char                    capability[OZAYN_OH_MAX_CAP_LEN];
    ozayn_oh_action_t       action;
    char                    required_permission[OZAYN_OH_MAX_PERMISSION_LEN];

    /* Requester context */
    char                    requester_identity[OZAYN_OH_MAX_IDENTITY_LEN];
    char                    session_id[OZAYN_OH_MAX_SESSION_LEN];

    /* Authorization result */
    int                     authorized;
    int                     authorization_result_code;

    /* Final state and result */
    ozayn_oh_state_t        final_state;
    ozayn_oh_result_t       result_category;
    int                     result_code;

    /* Failure information */
    ozayn_oh_failure_t      failure_category;
    char                    failure_detail[OZAYN_OH_MAX_ERROR_LEN];

    /* Timing */
    time_t                  created_time;
    time_t                  queued_time;
    time_t                  started_time;
    time_t                  completed_time;
    int                     queue_duration_ms;
    int                     execution_duration_ms;
    int                     total_duration_ms;

    /* Retry tracking */
    int                     retry_count;
    int                     max_retries;

    /* Attempts */
    int                     attempt_count;
    ozayn_oh_attempt_t      attempts[OZAYN_OH_MAX_ATTEMPTS];

    /* Safe metadata (no secrets) */
    char                    safe_metadata[OZAYN_OH_MAX_META_LEN];

    /* Audit correlation */
    char                    audit_event_id[OZAYN_OH_MAX_ID_LEN];

    /* Immutability guard */
    int                     finalized;

    /* Active flag */
    int                     active;
} ozayn_oh_record_t;

/* Query Filter — bounds queries */
typedef struct {
    uint32_t                filter_flags;
    char                    target[OZAYN_OH_MAX_TARGET_LEN];
    char                    capability[OZAYN_OH_MAX_CAP_LEN];
    ozayn_oh_action_t       action;
    ozayn_oh_state_t        state;
    ozayn_oh_result_t       result;
    char                    requester_identity[OZAYN_OH_MAX_IDENTITY_LEN];
    char                    request_id[OZAYN_OH_MAX_ID_LEN];
    time_t                  time_start;
    time_t                  time_end;
    int                     limit;
    int                     offset;
} ozayn_oh_query_t;

/* Query Results — bounded result set */
typedef struct {
    const ozayn_oh_record_t *results[OZAYN_OH_MAX_QUERY_RESULTS];
    int                     result_count;
    int                     total_count;
    int                     has_more;
} ozayn_oh_query_results_t;

/* Retention Policy */
typedef struct {
    int                     max_records;
    int                     max_age_seconds;
    int                     max_storage_bytes;
    int                     retain_security_records;
} ozayn_oh_retention_t;

/* History Statistics */
typedef struct {
    uint64_t                total_recorded;
    uint64_t                total_succeeded;
    uint64_t                total_failed;
    uint64_t                total_cancelled;
    uint64_t                total_timeout;
    uint64_t                total_rejected;
    uint64_t                total_expired;
    uint64_t                total_unavailable;
    uint64_t                total_unsupported;
    uint64_t                total_retries;
    uint64_t                total_expired_by_retention;
    int                     current_count;
    int                     storage_capacity;
} ozayn_oh_stats_t;

/* Service Configuration */
typedef struct {
    void                   *audit;
    void                   *event_engine;
    ozayn_oh_retention_t    retention;
} ozayn_oh_service_config_t;

/* Service State */
typedef struct {
    int                     initialized;

    /* History records (static array) */
    ozayn_oh_record_t       records[OZAYN_OH_MAX_RECORDS];
    int                     head;
    int                     count;
    uint32_t                sequence;

    /* Retention policy */
    ozayn_oh_retention_t    retention;

    /* Dependencies (not owned) */
    void                   *audit;
    void                   *event_engine;

    /* Statistics */
    ozayn_oh_stats_t        stats;
} ozayn_oh_service_t;

/* ============================================================
 * SECTION 10 — NAME HELPERS
 * ============================================================ */

const char *ozayn_oh_err_name(ozayn_oh_err_t err);
const char *ozayn_oh_state_name(ozayn_oh_state_t state);
const char *ozayn_oh_result_name(ozayn_oh_result_t result);
const char *ozayn_oh_failure_name(ozayn_oh_failure_t failure);
const char *ozayn_oh_action_name(ozayn_oh_action_t action);
const char *ozayn_oh_event_type_name(ozayn_oh_event_type_t type);

/* ============================================================
 * SECTION 11 — LIFECYCLE
 * ============================================================ */

ozayn_oh_err_t ozayn_oh_service_init(
    ozayn_oh_service_t *svc,
    const ozayn_oh_service_config_t *cfg);

void ozayn_oh_service_shutdown(ozayn_oh_service_t *svc);
int  ozayn_oh_service_is_initialized(const ozayn_oh_service_t *svc);

/* ============================================================
 * SECTION 12 — RECORD CREATION
 * ============================================================ */

ozayn_oh_err_t ozayn_oh_record_create(
    ozayn_oh_service_t *svc,
    const char *operation_id,
    const char *request_id,
    const char *target,
    const char *capability,
    ozayn_oh_action_t action,
    const char *required_permission,
    const char *requester_identity,
    const char *session_id,
    int max_retries,
    ozayn_oh_record_t **out_record);

ozayn_oh_err_t ozayn_oh_record_finalize(
    ozayn_oh_service_t *svc,
    const char *record_id,
    ozayn_oh_state_t final_state,
    ozayn_oh_result_t result_category,
    int result_code,
    const char *failure_detail);

/* ============================================================
 * SECTION 13 — ATTEMPT MANAGEMENT
 * ============================================================ */

ozayn_oh_err_t ozayn_oh_attempt_start(
    ozayn_oh_service_t *svc,
    const char *record_id,
    ozayn_oh_attempt_t **out_attempt);

ozayn_oh_err_t ozayn_oh_attempt_complete(
    ozayn_oh_service_t *svc,
    const char *record_id,
    const char *attempt_id,
    ozayn_oh_state_t attempt_state,
    ozayn_oh_result_t result_category,
    int result_code,
    const char *error_detail);

/* ============================================================
 * SECTION 14 — IMMUTABILITY
 * ============================================================ */

int ozayn_oh_record_is_finalized(
    const ozayn_oh_service_t *svc,
    const char *record_id);

/* ============================================================
 * SECTION 15 — QUERY
 * ============================================================ */

const ozayn_oh_record_t *ozayn_oh_record_get(
    const ozayn_oh_service_t *svc,
    const char *record_id);

const ozayn_oh_record_t *ozayn_oh_record_get_by_operation(
    const ozayn_oh_service_t *svc,
    const char *operation_id);

const ozayn_oh_record_t *ozayn_oh_record_get_by_request(
    const ozayn_oh_service_t *svc,
    const char *request_id);

ozayn_oh_err_t ozayn_oh_query(
    const ozayn_oh_service_t *svc,
    const ozayn_oh_query_t *filter,
    ozayn_oh_query_results_t *results);

int ozayn_oh_record_count(
    const ozayn_oh_service_t *svc);

int ozayn_oh_total_recorded(
    const ozayn_oh_service_t *svc);

/* ============================================================
 * SECTION 16 — RETENTION
 * ============================================================ */

int ozayn_oh_retention_check(
    ozayn_oh_service_t *svc);

ozayn_oh_err_t ozayn_oh_retention_set(
    ozayn_oh_service_t *svc,
    const ozayn_oh_retention_t *retention);

const ozayn_oh_retention_t *ozayn_oh_retention_get(
    const ozayn_oh_service_t *svc);

/* ============================================================
 * SECTION 17 — STATISTICS
 * ============================================================ */

ozayn_oh_err_t ozayn_oh_get_stats(
    const ozayn_oh_service_t *svc,
    ozayn_oh_stats_t *out_stats);

/* ============================================================
 * SECTION 18 — EVENT INTEGRATION
 * ============================================================ */

ozayn_oh_err_t ozayn_oh_emit_event(
    ozayn_oh_service_t *svc,
    ozayn_oh_event_type_t event_type,
    const char *record_id,
    const char *detail);

/* ============================================================
 * SECTION 19 — AUDIT INTEGRATION
 * ============================================================ */

ozayn_oh_err_t ozayn_oh_audit_record(
    ozayn_oh_service_t *svc,
    const char *record_id,
    const char *event_type,
    const char *detail);

/* ============================================================
 * SECTION 20 — VALIDATION
 * ============================================================ */

int ozayn_oh_record_validate(
    const ozayn_oh_record_t *record);

int ozayn_oh_record_is_terminal(
    ozayn_oh_state_t state);

/* ============================================================
 * SECTION 21 — CLEANUP
 * ============================================================ */

int ozayn_oh_cleanup_expired(
    ozayn_oh_service_t *svc);

int ozayn_oh_cleanup_all(
    ozayn_oh_service_t *svc);

/* ============================================================
 * SECTION 22 — GLOBAL ACCESSOR
 * ============================================================ */

ozayn_oh_service_t *ozayn_oh_get_global(void);

#endif /* OZAYN_OPERATION_HISTORY_H */
