/*
 * command_router.h — Safe Command Routing & Operation Request Foundation
 *
 * Provides structured operation routing through the Control Room:
 *   Request → Validate → Resolve Target → Check Capability →
 *   Preconditions → Authorize → Route → Dispatch → Result → Audit
 *
 * This module does NOT:
 *   - Create a second authorization system
 *   - Execute arbitrary commands
 *   - Execute arbitrary scripts or shell commands
 *   - Bypass existing Section 03 security
 *
 * Step 04/35 — Control Room
 */

#ifndef OZAYN_COMMAND_ROUTER_H
#define OZAYN_COMMAND_ROUTER_H

#include <stdint.h>
#include <time.h>

/* ============================================================
 * FORWARD DECLARATIONS
 * ============================================================ */

/* Dependencies are opaque pointers — no header conflicts */

/* ============================================================
 * SECTION 1 — LIMITS
 * ============================================================ */

#define OZAYN_ROUTER_MAX_ID_LEN          64
#define OZAYN_ROUTER_MAX_TARGET_LEN      64
#define OZAYN_ROUTER_MAX_CAP_LEN         64
#define OZAYN_ROUTER_MAX_META_LEN       256
#define OZAYN_ROUTER_MAX_SESSION_LEN     64
#define OZAYN_ROUTER_MAX_IDENTITY_LEN    64
#define OZAYN_ROUTER_MAX_DESCRIPTION_LEN 256
#define OZAYN_ROUTER_MAX_ERROR_LEN       256
#define OZAYN_ROUTER_MAX_OPERATIONS     256
#define OZAYN_ROUTER_MAX_QUEUE          128

/* ============================================================
 * SECTION 2 — ERRORS
 * ============================================================ */

typedef enum {
    OZAYN_ROUTER_OK                        =   0,
    OZAYN_ROUTER_ERR_NULL                  =  -1,
    OZAYN_ROUTER_ERR_NOT_INITIALIZED       =  -2,
    OZAYN_ROUTER_ERR_ALREADY_INITIALIZED   =  -3,
    OZAYN_ROUTER_ERR_INVALID_PARAM         =  -4,
    OZAYN_ROUTER_ERR_REQUEST_INVALID       =  -5,
    OZAYN_ROUTER_ERR_REQUEST_MISSING_ID    =  -6,
    OZAYN_ROUTER_ERR_REQUEST_MISSING_TARGET = -7,
    OZAYN_ROUTER_ERR_REQUEST_MISSING_ACTION = -8,
    OZAYN_ROUTER_ERR_REQUEST_UNSUPPORTED_VERSION = -9,
    OZAYN_ROUTER_ERR_REQUEST_METADATA_TOO_LARGE = -10,
    OZAYN_ROUTER_ERR_TARGET_NOT_FOUND      = -11,
    OZAYN_ROUTER_ERR_TARGET_UNAVAILABLE    = -12,
    OZAYN_ROUTER_ERR_TARGET_UNREGISTERED   = -13,
    OZAYN_ROUTER_ERR_CAPABILITY_NOT_FOUND  = -14,
    OZAYN_ROUTER_ERR_CAPABILITY_UNAVAILABLE = -15,
    OZAYN_ROUTER_ERR_CAPABILITY_UNSUPPORTED = -16,
    OZAYN_ROUTER_ERR_CAPABILITY_PROVIDER_MISSING = -17,
    OZAYN_ROUTER_ERR_CAPABILITY_DEPENDENCY_MISSING = -18,
    OZAYN_ROUTER_ERR_PRECONDITION_FAILED   = -19,
    OZAYN_ROUTER_ERR_AUTHORIZATION_FAILED  = -20,
    OZAYN_ROUTER_ERR_AUTHORIZATION_UNAVAILABLE = -21,
    OZAYN_ROUTER_ERR_OPERATION_REJECTED    = -22,
    OZAYN_ROUTER_ERR_OPERATION_FAILED      = -23,
    OZAYN_ROUTER_ERR_OPERATION_TIMEOUT     = -24,
    OZAYN_ROUTER_ERR_OPERATION_CANCELLED   = -25,
    OZAYN_ROUTER_ERR_CANCELLATION_UNSUPPORTED = -26,
    OZAYN_ROUTER_ERR_DUPLICATE_REQUEST     = -27,
    OZAYN_ROUTER_ERR_QUEUE_FULL            = -28,
    OZAYN_ROUTER_ERR_CONCURRENCY_LIMIT     = -29,
    OZAYN_ROUTER_ERR_RESOURCE_LIMIT        = -30,
    OZAYN_ROUTER_ERR_DISPATCH_FAILED       = -31,
    OZAYN_ROUTER_ERR_STATE_INVALID         = -32,
    OZAYN_ROUTER_ERR_NOT_FOUND             = -33,
    OZAYN_ROUTER_ERR_UNAVAILABLE           = -34
} ozayn_router_err_t;

/* ============================================================
 * SECTION 3 — OPERATION STATES
 * ============================================================ */

typedef enum {
    OZAYN_ROUTER_OP_RECEIVED       = 0,
    OZAYN_ROUTER_OP_VALIDATING     = 1,
    OZAYN_ROUTER_OP_VALIDATED      = 2,
    OZAYN_ROUTER_OP_RESOLVING      = 3,
    OZAYN_ROUTER_OP_RESOLVED       = 4,
    OZAYN_ROUTER_OP_CAPABILITY_CHECK = 5,
    OZAYN_ROUTER_OP_CAPABILITY_VERIFIED = 6,
    OZAYN_ROUTER_OP_PRECONDITION_CHECK = 7,
    OZAYN_ROUTER_OP_PRECONDITION_PASSED = 8,
    OZAYN_ROUTER_OP_AUTHORIZING    = 9,
    OZAYN_ROUTER_OP_AUTHORIZED     = 10,
    OZAYN_ROUTER_OP_QUEUED         = 11,
    OZAYN_ROUTER_OP_DISPATCHING    = 12,
    OZAYN_ROUTER_OP_RUNNING        = 13,
    OZAYN_ROUTER_OP_SUCCEEDED      = 14,
    OZAYN_ROUTER_OP_FAILED         = 15,
    OZAYN_ROUTER_OP_REJECTED       = 16,
    OZAYN_ROUTER_OP_CANCELLED      = 17,
    OZAYN_ROUTER_OP_TIMEOUT        = 18,
    OZAYN_ROUTER_OP_UNAVAILABLE    = 19,
    OZAYN_ROUTER_OP_UNSUPPORTED    = 20,
    OZAYN_ROUTER_OP_COUNT
} ozayn_router_op_state_t;

/* ============================================================
 * SECTION 4 — PRECONDITION FAILURE REASONS
 * ============================================================ */

typedef enum {
    OZAYN_ROUTER_PRECOND_NONE               = 0,
    OZAYN_ROUTER_PRECOND_TARGET_MISSING     = 1,
    OZAYN_ROUTER_PRECOND_TARGET_UNAVAILABLE = 2,
    OZAYN_ROUTER_PRECOND_TARGET_ERROR       = 3,
    OZAYN_ROUTER_PRECOND_CAP_MISSING        = 4,
    OZAYN_ROUTER_PRECOND_CAP_UNAVAILABLE    = 5,
    OZAYN_ROUTER_PRECOND_CAP_DISABLED       = 6,
    OZAYN_ROUTER_PRECOND_DEP_MISSING        = 7,
    OZAYN_ROUTER_PRECOND_STATE_INVALID      = 8,
    OZAYN_ROUTER_PRECOND_SECURITY_BLOCKED   = 9,
    OZAYN_ROUTER_PRECOND_SYSTEM_BUSY        = 10
} ozayn_router_precond_t;

/* ============================================================
 * SECTION 5 — RESULT STATES
 * ============================================================ */

typedef enum {
    OZAYN_ROUTER_RESULT_PENDING       = 0,
    OZAYN_ROUTER_RESULT_ACCEPTED      = 1,
    OZAYN_ROUTER_RESULT_SUCCEEDED     = 2,
    OZAYN_ROUTER_RESULT_FAILED        = 3,
    OZAYN_ROUTER_RESULT_REJECTED      = 4,
    OZAYN_ROUTER_RESULT_CANCELLED     = 5,
    OZAYN_ROUTER_RESULT_TIMEOUT       = 6,
    OZAYN_ROUTER_RESULT_UNAVAILABLE   = 7,
    OZAYN_ROUTER_RESULT_UNSUPPORTED   = 8
} ozayn_router_result_state_t;

/* ============================================================
 * SECTION 6 — SUPPORTED ACTIONS
 * ============================================================ */

typedef enum {
    OZAYN_ROUTER_ACTION_START         = 0,
    OZAYN_ROUTER_ACTION_STOP          = 1,
    OZAYN_ROUTER_ACTION_PAUSE         = 2,
    OZAYN_ROUTER_ACTION_RESUME        = 3,
    OZAYN_ROUTER_ACTION_QUERY         = 4,
    OZAYN_ROUTER_ACTION_RESTART       = 5,
    OZAYN_ROUTER_ACTION_ENABLE        = 6,
    OZAYN_ROUTER_ACTION_DISABLE       = 7,
    OZAYN_ROUTER_ACTION_DIAGNOSTIC    = 8,
    OZAYN_ROUTER_ACTION_COUNT
} ozayn_router_action_t;

/* ============================================================
 * SECTION 7 — EVENT TYPES
 * ============================================================ */

typedef enum {
    OZAYN_ROUTER_EVENT_REQUEST_RECEIVED       = 0,
    OZAYN_ROUTER_EVENT_REQUEST_VALIDATED      = 1,
    OZAYN_ROUTER_EVENT_REQUEST_REJECTED       = 2,
    OZAYN_ROUTER_EVENT_TARGET_RESOLVED        = 3,
    OZAYN_ROUTER_EVENT_TARGET_NOT_FOUND       = 4,
    OZAYN_ROUTER_EVENT_CAPABILITY_RESOLVED    = 5,
    OZAYN_ROUTER_EVENT_CAPABILITY_NOT_FOUND   = 6,
    OZAYN_ROUTER_EVENT_AUTHORIZATION_PASSED   = 7,
    OZAYN_ROUTER_EVENT_AUTHORIZATION_FAILED   = 8,
    OZAYN_ROUTER_EVENT_OPERATION_QUEUED       = 9,
    OZAYN_ROUTER_EVENT_OPERATION_STARTED      = 10,
    OZAYN_ROUTER_EVENT_OPERATION_SUCCEEDED    = 11,
    OZAYN_ROUTER_EVENT_OPERATION_FAILED       = 12,
    OZAYN_ROUTER_EVENT_OPERATION_CANCELLED    = 13,
    OZAYN_ROUTER_EVENT_OPERATION_TIMEOUT      = 14,
    OZAYN_ROUTER_EVENT_PRECONDITION_FAILED    = 15,
    OZAYN_ROUTER_EVENT_DUPLICATE_DETECTED     = 16,
    OZAYN_ROUTER_EVENT_RESOURCE_LIMIT_HIT     = 17,
    OZAYN_ROUTER_EVENT_COUNT
} ozayn_router_event_type_t;

/* ============================================================
 * SECTION 8 — STRUCTURES
 * ============================================================ */

/* Operation — internal representation of a routed request */
typedef struct {
    char                    operation_id[OZAYN_ROUTER_MAX_ID_LEN];
    char                    request_id[OZAYN_ROUTER_MAX_ID_LEN];
    ozayn_router_action_t   action;
    char                    target[OZAYN_ROUTER_MAX_TARGET_LEN];
    char                    capability[OZAYN_ROUTER_MAX_CAP_LEN];
    char                    context[OZAYN_ROUTER_MAX_META_LEN];
    ozayn_router_op_state_t state;
    ozayn_router_result_state_t result_state;
    int                     result_code;
    ozayn_router_precond_t  precondition_failure;
    char                    error_detail[OZAYN_ROUTER_MAX_ERROR_LEN];
    char                    requester_identity[OZAYN_ROUTER_MAX_IDENTITY_LEN];
    char                    session_id[OZAYN_ROUTER_MAX_SESSION_LEN];
    char                    required_permission[OZAYN_ROUTER_MAX_ID_LEN];
    int                     priority;
    int                     idempotent;
    time_t                  request_time;
    time_t                  start_time;
    time_t                  completion_time;
    int                     active;
} ozayn_router_operation_t;

/* Operation Result — returned to caller */
typedef struct {
    char                    operation_id[OZAYN_ROUTER_MAX_ID_LEN];
    char                    request_id[OZAYN_ROUTER_MAX_ID_LEN];
    ozayn_router_result_state_t result_state;
    int                     result_code;
    char                    target[OZAYN_ROUTER_MAX_TARGET_LEN];
    ozayn_router_action_t   action;
    time_t                  start_time;
    time_t                  completion_time;
    int                     duration_ms;
    char                    safe_metadata[OZAYN_ROUTER_MAX_META_LEN];
    char                    error_detail[OZAYN_ROUTER_MAX_ERROR_LEN];
} ozayn_router_result_t;

/* Policy */
typedef struct {
    int                     enabled;
    int                     max_concurrent_ops;
    int                     max_queue_size;
    int                     request_timeout_ms;
    int                     queue_timeout_ms;
    int                     execution_timeout_ms;
    int                     max_retries;
    int                     require_authorization;
    int                     require_session;
    int                     allow_idempotent_replay;
    int                     require_capability;
} ozayn_router_policy_t;

/* Service Configuration */
typedef struct {
    void                   *component_registry;
    void                   *control_room;
    void                   *authorization;
    void                   *audit;
    void                   *event_engine;
} ozayn_router_service_config_t;

/* Service State */
typedef struct {
    int                     initialized;

    /* Operations */
    ozayn_router_operation_t operations[OZAYN_ROUTER_MAX_OPERATIONS];
    int                     operation_head;
    int                     operation_count;
    uint32_t                operation_sequence;

    /* Active count */
    int                     active_ops;

    /* Policy */
    ozayn_router_policy_t   policy;

    /* Dependencies (not owned) */
    void                   *component_registry;
    void                   *control_room;
    void                   *authorization;
    void                   *audit;
    void                   *event_engine;

    /* Statistics */
    uint64_t                total_requests;
    uint64_t                total_succeeded;
    uint64_t                total_failed;
    uint64_t                total_rejected;
    uint64_t                total_cancelled;
    uint64_t                total_timeouts;
    uint64_t                total_duplicates;
    uint64_t                total_authorization_checks;
    uint64_t                total_authorization_denials;
} ozayn_router_service_t;

/* ============================================================
 * SECTION 9 — NAME HELPERS
 * ============================================================ */

const char *ozayn_router_err_name(ozayn_router_err_t err);
const char *ozayn_router_op_state_name(ozayn_router_op_state_t state);
const char *ozayn_router_result_state_name(ozayn_router_result_state_t state);
const char *ozayn_router_action_name(ozayn_router_action_t action);
const char *ozayn_router_event_type_name(ozayn_router_event_type_t type);
const char *ozayn_router_precond_name(ozayn_router_precond_t precond);

/* ============================================================
 * SECTION 10 — LIFECYCLE
 * ============================================================ */

ozayn_router_err_t ozayn_router_service_init(
    ozayn_router_service_t *svc,
    const ozayn_router_service_config_t *cfg);

void ozayn_router_service_shutdown(ozayn_router_service_t *svc);
int  ozayn_router_service_is_initialized(const ozayn_router_service_t *svc);

/* ============================================================
 * SECTION 11 — REQUEST VALIDATION
 * ============================================================ */

ozayn_router_err_t ozayn_router_validate_request(
    const ozayn_router_service_t *svc,
    const char *request_id,
    ozayn_router_action_t action,
    const char *target,
    const char *capability);

/* ============================================================
 * SECTION 12 — OPERATION SUBMISSION
 * ============================================================ */

ozayn_router_err_t ozayn_router_submit(
    ozayn_router_service_t *svc,
    const char *request_id,
    ozayn_router_action_t action,
    const char *target,
    const char *capability,
    const char *context,
    const char *requester_identity,
    const char *session_id,
    const char *required_permission,
    int priority,
    int idempotent,
    ozayn_router_operation_t **out_operation);

/* ============================================================
 * SECTION 13 — OPERATION PROCESSING
 * ============================================================ */

ozayn_router_err_t ozayn_router_process(
    ozayn_router_service_t *svc,
    const char *operation_id,
    ozayn_router_result_t *out_result);

/* ============================================================
 * SECTION 14 — CANCELLATION
 * ============================================================ */

ozayn_router_err_t ozayn_router_cancel(
    ozayn_router_service_t *svc,
    const char *operation_id);

int ozayn_router_operation_cancellable(
    const ozayn_router_service_t *svc,
    const char *operation_id);

/* ============================================================
 * SECTION 15 — QUERY
 * ============================================================ */

ozayn_router_operation_t *ozayn_router_get_operation(
    ozayn_router_service_t *svc,
    const char *operation_id);

int ozayn_router_operation_count(
    const ozayn_router_service_t *svc);

int ozayn_router_active_count(
    const ozayn_router_service_t *svc);

int ozayn_router_queue_full(
    const ozayn_router_service_t *svc);

int ozayn_router_concurrency_limit(
    const ozayn_router_service_t *svc);

/* ============================================================
 * SECTION 16 — EVENT OBSERVATION
 * ============================================================ */

ozayn_router_err_t ozayn_router_emit_event(
    ozayn_router_service_t *svc,
    ozayn_router_event_type_t event_type,
    const char *operation_id,
    const char *detail);

int ozayn_router_event_count(
    const ozayn_router_service_t *svc);

/* ============================================================
 * SECTION 17 — AUDIT
 * ============================================================ */

ozayn_router_err_t ozayn_router_audit_operation(
    ozayn_router_service_t *svc,
    const char *operation_id,
    const char *event_type,
    const char *detail);

/* ============================================================
 * SECTION 18 — POLICY
 * ============================================================ */

ozayn_router_policy_t ozayn_router_default_policy(void);
ozayn_router_err_t ozayn_router_set_policy(
    ozayn_router_service_t *svc,
    const ozayn_router_policy_t *policy);
const ozayn_router_policy_t *ozayn_router_get_policy(
    const ozayn_router_service_t *svc);

/* ============================================================
 * SECTION 19 — STATISTICS
 * ============================================================ */

uint64_t ozayn_router_total_requests(const ozayn_router_service_t *svc);
uint64_t ozayn_router_total_succeeded(const ozayn_router_service_t *svc);
uint64_t ozayn_router_total_failed(const ozayn_router_service_t *svc);
uint64_t ozayn_router_total_rejected(const ozayn_router_service_t *svc);
uint64_t ozayn_router_total_cancelled(const ozayn_router_service_t *svc);
uint64_t ozayn_router_total_timeouts(const ozayn_router_service_t *svc);
uint64_t ozayn_router_total_duplicates(const ozayn_router_service_t *svc);

/* ============================================================
 * SECTION 20 — CLEANUP
 * ============================================================ */

int ozayn_router_cleanup_completed(
    ozayn_router_service_t *svc);

int ozayn_router_cleanup_expired(
    ozayn_router_service_t *svc);

/* ============================================================
 * SECTION 21 — GLOBAL ACCESSOR
 * ============================================================ */

ozayn_router_service_t *ozayn_router_get_global(void);

#endif /* OZAYN_COMMAND_ROUTER_H */
