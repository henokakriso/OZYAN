/*
 * operation_queue.h — Controlled Operation Queue & Execution Lifecycle
 *
 * Provides bounded, observable, deterministic, and security-aware
 * operation queuing for the OZAYN Control Room.
 *
 * Lifecycle:
 *   CREATED → QUEUED → WAITING → DISPATCHING → RUNNING → SUCCEEDED/FAILED
 *   or: REJECTED, CANCELLED, TIMEOUT, EXPIRED, UNAVAILABLE
 *
 * This module does NOT:
 *   - Create a second authorization system
 *   - Execute arbitrary commands
 *   - Bypass existing Section 03 security
 *
 * Step 05/35 — Control Room
 */

#ifndef OZAYN_OPERATION_QUEUE_H
#define OZAYN_OPERATION_QUEUE_H

#include <stdint.h>
#include <time.h>

/* ============================================================
 * SECTION 1 — LIMITS
 * ============================================================ */

#define OZAYN_OQ_MAX_ID_LEN           64
#define OZAYN_OQ_MAX_TARGET_LEN       64
#define OZAYN_OQ_MAX_CAP_LEN          64
#define OZAYN_OQ_MAX_META_LEN        256
#define OZAYN_OQ_MAX_SESSION_LEN      64
#define OZAYN_OQ_MAX_IDENTITY_LEN     64
#define OZAYN_OQ_MAX_ERROR_LEN        256
#define OZAYN_OQ_MAX_ENTRIES         256

/* ============================================================
 * SECTION 2 — ERRORS
 * ============================================================ */

typedef enum {
    OZAYN_OQ_OK                        =   0,
    OZAYN_OQ_ERR_NULL                  =  -1,
    OZAYN_OQ_ERR_NOT_INITIALIZED       =  -2,
    OZAYN_OQ_ERR_ALREADY_INITIALIZED   =  -3,
    OZAYN_OQ_ERR_INVALID_PARAM         =  -4,
    OZAYN_OQ_ERR_QUEUE_FULL            =  -5,
    OZAYN_OQ_ERR_NOT_FOUND             =  -6,
    OZAYN_OQ_ERR_STATE_INVALID         =  -7,
    OZAYN_OQ_ERR_STATE_TRANSITION      =  -8,
    OZAYN_OQ_ERR_CANCELLATION_UNSUPPORTED = -9,
    OZAYN_OQ_ERR_DUPLICATE_REQUEST     = -10,
    OZAYN_OQ_ERR_TIMEOUT               = -11,
    OZAYN_OQ_ERR_PRECONDITION_FAILED   = -12,
    OZAYN_OQ_ERR_UNAVAILABLE           = -13,
    OZAYN_OQ_ERR_RESOURCE_LIMIT        = -14,
    OZAYN_OQ_ERR_DISPATCH_FAILED       = -15,
    OZAYN_OQ_ERR_RETRY_EXHAUSTED       = -16
} ozayn_oq_err_t;

/* ============================================================
 * SECTION 3 — QUEUE ENTRY STATES
 * ============================================================ */

typedef enum {
    OZAYN_OQ_STATE_CREATED       = 0,
    OZAYN_OQ_STATE_QUEUED        = 1,
    OZAYN_OQ_STATE_WAITING       = 2,
    OZAYN_OQ_STATE_DISPATCHING   = 3,
    OZAYN_OQ_STATE_RUNNING       = 4,
    OZAYN_OQ_STATE_SUCCEEDED     = 5,
    OZAYN_OQ_STATE_FAILED        = 6,
    OZAYN_OQ_STATE_REJECTED      = 7,
    OZAYN_OQ_STATE_CANCELLED     = 8,
    OZAYN_OQ_STATE_TIMEOUT       = 9,
    OZAYN_OQ_STATE_EXPIRED       = 10,
    OZAYN_OQ_STATE_UNAVAILABLE   = 11,
    OZAYN_OQ_STATE_COUNT
} ozayn_oq_state_t;

/* ============================================================
 * SECTION 4 — PRIORITY LEVELS
 * ============================================================ */

typedef enum {
    OZAYN_OQ_PRIORITY_LOW        = 0,
    OZAYN_OQ_PRIORITY_NORMAL     = 1,
    OZAYN_OQ_PRIORITY_HIGH       = 2,
    OZAYN_OQ_PRIORITY_CRITICAL   = 3,
    OZAYN_OQ_PRIORITY_COUNT
} ozayn_oq_priority_t;

/* ============================================================
 * SECTION 5 — OPERATION ACTIONS (synced with router)
 * ============================================================ */

typedef enum {
    OZAYN_OQ_ACTION_START        = 0,
    OZAYN_OQ_ACTION_STOP         = 1,
    OZAYN_OQ_ACTION_PAUSE        = 2,
    OZAYN_OQ_ACTION_RESUME       = 3,
    OZAYN_OQ_ACTION_QUERY        = 4,
    OZAYN_OQ_ACTION_RESTART      = 5,
    OZAYN_OQ_ACTION_ENABLE       = 6,
    OZAYN_OQ_ACTION_DISABLE      = 7,
    OZAYN_OQ_ACTION_DIAGNOSTIC   = 8,
    OZAYN_OQ_ACTION_COUNT
} ozayn_oq_action_t;

/* ============================================================
 * SECTION 6 — QUEUE EVENT TYPES
 * ============================================================ */

typedef enum {
    OZAYN_OQ_EVENT_CREATED        = 0,
    OZAYN_OQ_EVENT_QUEUED         = 1,
    OZAYN_OQ_EVENT_WAITING        = 2,
    OZAYN_OQ_EVENT_DISPATCHING    = 3,
    OZAYN_OQ_EVENT_STARTED        = 4,
    OZAYN_OQ_EVENT_SUCCEEDED      = 5,
    OZAYN_OQ_EVENT_FAILED         = 6,
    OZAYN_OQ_EVENT_CANCELLED      = 7,
    OZAYN_OQ_EVENT_TIMEOUT        = 8,
    OZAYN_OQ_EVENT_EXPIRED        = 9,
    OZAYN_OQ_EVENT_REJECTED       = 10,
    OZAYN_OQ_EVENT_RETRYING       = 11,
    OZAYN_OQ_EVENT_PRECONDITION_FAILED = 12,
    OZAYN_OQ_EVENT_DUPLICATE_DETECTED  = 13,
    OZAYN_OQ_EVENT_RESOURCE_LIMIT_HIT  = 14,
    OZAYN_OQ_EVENT_AUTHORIZATION_FAILED = 15,
    OZAYN_OQ_EVENT_CONFLICT_DETECTED   = 16,
    OZAYN_OQ_EVENT_COUNT
} ozayn_oq_event_type_t;

/* ============================================================
 * SECTION 7 — CONFLICT MODES
 * ============================================================ */

typedef enum {
    OZAYN_OQ_CONFLICT_REJECT     = 0,
    OZAYN_OQ_CONFLICT_WAIT       = 1,
    OZAYN_OQ_CONFLICT_ALLOW      = 2,
    OZAYN_OQ_CONFLICT_COUNT
} ozayn_oq_conflict_mode_t;

/* ============================================================
 * SECTION 8 — STRUCTURES
 * ============================================================ */

/* Queue Entry — represents one operation in the queue */
typedef struct {
    char                    entry_id[OZAYN_OQ_MAX_ID_LEN];
    char                    request_id[OZAYN_OQ_MAX_ID_LEN];
    ozayn_oq_action_t       action;
    char                    target[OZAYN_OQ_MAX_TARGET_LEN];
    char                    capability[OZAYN_OQ_MAX_CAP_LEN];
    char                    context[OZAYN_OQ_MAX_META_LEN];
    char                    requester_identity[OZAYN_OQ_MAX_IDENTITY_LEN];
    char                    session_id[OZAYN_OQ_MAX_SESSION_LEN];
    char                    required_permission[OZAYN_OQ_MAX_ID_LEN];
    int                     priority;
    int                     idempotent;
    int                     cancellable;

    /* State tracking */
    ozayn_oq_state_t        state;
    int                     result_code;
    char                    error_detail[OZAYN_OQ_MAX_ERROR_LEN];

    /* Timing */
    time_t                  created_time;
    time_t                  queued_time;
    time_t                  dispatch_time;
    time_t                  start_time;
    time_t                  completion_time;
    int                     queue_timeout_ms;
    int                     execution_timeout_ms;

    /* Retry */
    int                     retry_count;
    int                     max_retries;

    /* Conflict */
    int                     conflicts_with_running;

    /* Active flag */
    int                     active;
} ozayn_oq_entry_t;

/* Queue Result — returned after completion */
typedef struct {
    char                    entry_id[OZAYN_OQ_MAX_ID_LEN];
    char                    request_id[OZAYN_OQ_MAX_ID_LEN];
    ozayn_oq_state_t        final_state;
    int                     result_code;
    char                    target[OZAYN_OQ_MAX_TARGET_LEN];
    ozayn_oq_action_t       action;
    time_t                  start_time;
    time_t                  completion_time;
    int                     duration_ms;
    char                    safe_metadata[OZAYN_OQ_MAX_META_LEN];
    char                    error_detail[OZAYN_OQ_MAX_ERROR_LEN];
} ozayn_oq_result_t;

/* Policy */
typedef struct {
    int                     enabled;
    int                     max_entries;
    int                     max_running;
    int                     max_per_component;
    int                     max_per_requester;
    int                     max_retries;
    int                     queue_timeout_ms;
    int                     execution_timeout_ms;
    int                     global_timeout_ms;
    int                     require_authorization;
    int                     require_capability;
    int                     allow_idempotent_replay;
    ozayn_oq_conflict_mode_t default_conflict_mode;
} ozayn_oq_policy_t;

/* Service Configuration */
typedef struct {
    void                   *component_registry;
    void                   *authorization;
    void                   *audit;
    void                   *event_engine;
} ozayn_oq_service_config_t;

/* Service State */
typedef struct {
    int                     initialized;

    /* Queue entries (ring buffer) */
    ozayn_oq_entry_t        entries[OZAYN_OQ_MAX_ENTRIES];
    int                     head;
    int                     count;
    uint32_t                sequence;

    /* Active tracking */
    int                     running_count;
    int                     queued_count;

    /* Policy */
    ozayn_oq_policy_t       policy;

    /* Dependencies (not owned) */
    void                   *component_registry;
    void                   *authorization;
    void                   *audit;
    void                   *event_engine;

    /* Statistics */
    uint64_t                total_submitted;
    uint64_t                total_succeeded;
    uint64_t                total_failed;
    uint64_t                total_rejected;
    uint64_t                total_cancelled;
    uint64_t                total_timeouts;
    uint64_t                total_expired;
    uint64_t                total_duplicates;
    uint64_t                total_retries;
    uint64_t                total_precondition_failures;
    uint64_t                total_authorization_denials;
    uint64_t                total_conflicts;
} ozayn_oq_service_t;

/* ============================================================
 * SECTION 9 — NAME HELPERS
 * ============================================================ */

const char *ozayn_oq_err_name(ozayn_oq_err_t err);
const char *ozayn_oq_state_name(ozayn_oq_state_t state);
const char *ozayn_oq_priority_name(ozayn_oq_priority_t priority);
const char *ozayn_oq_action_name(ozayn_oq_action_t action);
const char *ozayn_oq_event_type_name(ozayn_oq_event_type_t type);
const char *ozayn_oq_conflict_mode_name(ozayn_oq_conflict_mode_t mode);

/* ============================================================
 * SECTION 10 — LIFECYCLE
 * ============================================================ */

ozayn_oq_err_t ozayn_oq_service_init(
    ozayn_oq_service_t *svc,
    const ozayn_oq_service_config_t *cfg);

void ozayn_oq_service_shutdown(ozayn_oq_service_t *svc);
int  ozayn_oq_service_is_initialized(const ozayn_oq_service_t *svc);

/* ============================================================
 * SECTION 11 — ENQUEUE
 * ============================================================ */

ozayn_oq_err_t ozayn_oq_enqueue(
    ozayn_oq_service_t *svc,
    const char *request_id,
    ozayn_oq_action_t action,
    const char *target,
    const char *capability,
    const char *context,
    const char *requester_identity,
    const char *session_id,
    const char *required_permission,
    int priority,
    int idempotent,
    int queue_timeout_ms,
    int execution_timeout_ms,
    int max_retries,
    ozayn_oq_entry_t **out_entry);

/* ============================================================
 * SECTION 12 — DEQUEUE / DISPATCH
 * ============================================================ */

ozayn_oq_err_t ozayn_oq_dequeue_next(
    ozayn_oq_service_t *svc,
    ozayn_oq_entry_t **out_entry);

ozayn_oq_err_t ozayn_oq_complete(
    ozayn_oq_service_t *svc,
    const char *entry_id,
    int result_code,
    const char *error_detail);

ozayn_oq_err_t ozayn_oq_fail(
    ozayn_oq_service_t *svc,
    const char *entry_id,
    int result_code,
    const char *error_detail);

/* ============================================================
 * SECTION 13 — CANCELLATION
 * ============================================================ */

ozayn_oq_err_t ozayn_oq_cancel(
    ozayn_oq_service_t *svc,
    const char *entry_id);

int ozayn_oq_entry_cancellable(
    const ozayn_oq_service_t *svc,
    const char *entry_id);

/* ============================================================
 * SECTION 14 — TIMEOUT / EXPIRATION
 * ============================================================ */

int ozayn_oq_check_timeouts(
    ozayn_oq_service_t *svc);

int ozayn_oq_check_expired(
    ozayn_oq_service_t *svc);

/* ============================================================
 * SECTION 15 — PRECONDITION / AUTHORIZATION RECHECK
 * ============================================================ */

ozayn_oq_err_t ozayn_oq_recheck_preconditions(
    ozayn_oq_service_t *svc,
    const char *entry_id);

ozayn_oq_err_t ozayn_oq_recheck_authorization(
    ozayn_oq_service_t *svc,
    const char *entry_id);

/* ============================================================
 * SECTION 16 — RETRY
 * ============================================================ */

ozayn_oq_err_t ozayn_oq_retry(
    ozayn_oq_service_t *svc,
    const char *entry_id);

int ozayn_oq_entry_retryable(
    const ozayn_oq_service_t *svc,
    const char *entry_id);

/* ============================================================
 * SECTION 17 — CONFLICT DETECTION
 * ============================================================ */

int ozayn_oq_has_conflict(
    const ozayn_oq_service_t *svc,
    const char *target,
    ozayn_oq_action_t action);

/* ============================================================
 * SECTION 18 — QUERY
 * ============================================================ */

ozayn_oq_entry_t *ozayn_oq_get_entry(
    ozayn_oq_service_t *svc,
    const char *entry_id);

int ozayn_oq_entry_count(
    const ozayn_oq_service_t *svc);

int ozayn_oq_running_count(
    const ozayn_oq_service_t *svc);

int ozayn_oq_queued_count(
    const ozayn_oq_service_t *svc);

int ozayn_oq_queue_full(
    const ozayn_oq_service_t *svc);

int ozayn_oq_running_limit(
    const ozayn_oq_service_t *svc);

/* ============================================================
 * SECTION 19 — EVENT OBSERVATION
 * ============================================================ */

ozayn_oq_err_t ozayn_oq_emit_event(
    ozayn_oq_service_t *svc,
    ozayn_oq_event_type_t event_type,
    const char *entry_id,
    const char *detail);

/* ============================================================
 * SECTION 20 — AUDIT
 * ============================================================ */

ozayn_oq_err_t ozayn_oq_audit_operation(
    ozayn_oq_service_t *svc,
    const char *entry_id,
    const char *event_type,
    const char *detail);

/* ============================================================
 * SECTION 21 — POLICY
 * ============================================================ */

ozayn_oq_policy_t ozayn_oq_default_policy(void);
ozayn_oq_err_t ozayn_oq_set_policy(
    ozayn_oq_service_t *svc,
    const ozayn_oq_policy_t *policy);
const ozayn_oq_policy_t *ozayn_oq_get_policy(
    const ozayn_oq_service_t *svc);

/* ============================================================
 * SECTION 22 — STATISTICS
 * ============================================================ */

uint64_t ozayn_oq_total_submitted(const ozayn_oq_service_t *svc);
uint64_t ozayn_oq_total_succeeded(const ozayn_oq_service_t *svc);
uint64_t ozayn_oq_total_failed(const ozayn_oq_service_t *svc);
uint64_t ozayn_oq_total_rejected(const ozayn_oq_service_t *svc);
uint64_t ozayn_oq_total_cancelled(const ozayn_oq_service_t *svc);
uint64_t ozayn_oq_total_timeouts(const ozayn_oq_service_t *svc);
uint64_t ozayn_oq_total_expired(const ozayn_oq_service_t *svc);
uint64_t ozayn_oq_total_duplicates(const ozayn_oq_service_t *svc);
uint64_t ozayn_oq_total_retries(const ozayn_oq_service_t *svc);

/* ============================================================
 * SECTION 23 — CLEANUP
 * ============================================================ */

int ozayn_oq_cleanup_completed(ozayn_oq_service_t *svc);
int ozayn_oq_cleanup_all(ozayn_oq_service_t *svc);

/* ============================================================
 * SECTION 24 — GLOBAL ACCESSOR
 * ============================================================ */

ozayn_oq_service_t *ozayn_oq_get_global(void);

#endif /* OZAYN_OPERATION_QUEUE_H */
