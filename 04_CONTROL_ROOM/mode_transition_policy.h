#ifndef OZAYN_MODE_TRANSITION_POLICY_H
#define OZAYN_MODE_TRANSITION_POLICY_H

#include "operational_readiness.h"

/* ============================================================
 * SECTION 1 — ERRORS
 * ============================================================ */

typedef enum {
    OZAYN_MTP_OK                        =   0,
    OZAYN_MTP_ERR_NULL                  =  -1,
    OZAYN_MTP_ERR_NOT_INITIALIZED       =  -2,
    OZAYN_MTP_ERR_ALREADY_INITIALIZED   =  -3,
    OZAYN_MTP_ERR_INVALID_PARAM         =  -4,
    OZAYN_MTP_ERR_STATE_INVALID         =  -5,
    OZAYN_MTP_ERR_POLICY_NOT_FOUND      =  -6,
    OZAYN_MTP_ERR_POLICY_DISABLED       =  -7,
    OZAYN_MTP_ERR_POLICY_CONFLICT       =  -8,
    OZAYN_MTP_ERR_TRANSITION_INVALID    =  -9,
    OZAYN_MTP_ERR_TRANSITION_CONFLICT   = -10,
    OZAYN_MTP_ERR_TRANSITION_ACTIVE     = -11,
    OZAYN_MTP_ERR_TRANSITION_TIMEOUT    = -12,
    OZAYN_MTP_ERR_TRANSITION_EXPIRED    = -13,
    OZAYN_MTP_ERR_TRANSITION_CANCELLED  = -14,
    OZAYN_MTP_ERR_TRANSITION_FAILED     = -15,
    OZAYN_MTP_ERR_AUTHORIZATION_FAILED  = -16,
    OZAYN_MTP_ERR_SAFETY_FAILED         = -17,
    OZAYN_MTP_ERR_RESOURCE_FAILED       = -18,
    OZAYN_MTP_ERR_READINESS_FAILED      = -19,
    OZAYN_MTP_ERR_CONCURRENCY_ERROR     = -20,
    OZAYN_MTP_ERR_LIMIT_REACHED         = -21,
    OZAYN_MTP_ERR_CONFIGURATION_ERROR   = -22,
    OZAYN_MTP_ERR_UNAVAILABLE           = -23,
    OZAYN_MTP_ERR_NOT_FOUND             = -24
} ozayn_mtp_err_t;

/* ============================================================
 * SECTION 2 — DECISION OUTCOMES
 * ============================================================ */

typedef enum {
    OZAYN_MTP_OUTCOME_ALLOW = 0,
    OZAYN_MTP_OUTCOME_DENY,
    OZAYN_MTP_OUTCOME_DEFER,
    OZAYN_MTP_OUTCOME_REQUIRES_REASSESSMENT,
    OZAYN_MTP_OUTCOME_REQUIRES_AUTHORIZATION,
    OZAYN_MTP_OUTCOME_REQUIRES_SAFETY_CHECK,
    OZAYN_MTP_OUTCOME_REQUIRES_RESOURCE_CHECK,
    OZAYN_MTP_OUTCOME_MANUAL_REVIEW,
    OZAYN_MTP_OUTCOME_UNAVAILABLE
} ozayn_mtp_outcome_t;

/* ============================================================
 * SECTION 3 — TRANSITION PHASES
 * ============================================================ */

typedef enum {
    OZAYN_MTP_PHASE_NONE = 0,
    OZAYN_MTP_PHASE_REQUESTED,
    OZAYN_MTP_PHASE_VALIDATING,
    OZAYN_MTP_PHASE_EVALUATING,
    OZAYN_MTP_PHASE_DECIDED,
    OZAYN_MTP_PHASE_EXECUTING,
    OZAYN_MTP_PHASE_VERIFYING,
    OZAYN_MTP_PHASE_COMPLETED,
    OZAYN_MTP_PHASE_REJECTED,
    OZAYN_MTP_PHASE_FAILED,
    OZAYN_MTP_PHASE_CANCELLED,
    OZAYN_MTP_PHASE_EXPIRED
} ozayn_mtp_phase_t;

/* ============================================================
 * SECTION 4 — TRIGGER TYPES
 * ============================================================ */

typedef enum {
    OZAYN_MTP_TRIGGER_NONE = 0,
    OZAYN_MTP_TRIGGER_STARTUP,
    OZAYN_MTP_TRIGGER_SHUTDOWN,
    OZAYN_MTP_TRIGGER_HEALTH_CHANGE,
    OZAYN_MTP_TRIGGER_SECURITY_CHANGE,
    OZAYN_MTP_TRIGGER_RESOURCE_CHANGE,
    OZAYN_MTP_TRIGGER_DEVICE_CHANGE,
    OZAYN_MTP_TRIGGER_RECOVERY,
    OZAYN_MTP_TRIGGER_MAINTENANCE_REQUEST,
    OZAYN_MTP_TRIGGER_ADMINISTRATIVE,
    OZAYN_MTP_TRIGGER_SYSTEM_FAILURE,
    OZAYN_MTP_TRIGGER_SAFETY_EVENT,
    OZAYN_MTP_TRIGGER_CONFIGURATION_CHANGE,
    OZAYN_MTP_TRIGGER_COUNT
} ozayn_mtp_trigger_t;

/* ============================================================
 * SECTION 5 — EVENT TYPES
 * ============================================================ */

typedef enum {
    OZAYN_MTP_EVENT_EVALUATION_STARTED = 0,
    OZAYN_MTP_EVENT_EVALUATION_COMPLETED,
    OZAYN_MTP_EVENT_TRANSITION_APPROVED,
    OZAYN_MTP_EVENT_TRANSITION_DENIED,
    OZAYN_MTP_EVENT_TRANSITION_DEFERRED,
    OZAYN_MTP_EVENT_POLICY_ADDED,
    OZAYN_MTP_EVENT_POLICY_REMOVED,
    OZAYN_MTP_EVENT_POLICY_ENABLED,
    OZAYN_MTP_EVENT_POLICY_DISABLED,
    OZAYN_MTP_EVENT_REQUEST_EXPIRED,
    OZAYN_MTP_EVENT_CONFLICT_DETECTED,
    OZAYN_MTP_EVENT_TRANSITION_EXECUTING,
    OZAYN_MTP_EVENT_TRANSITION_COMPLETED,
    OZAYN_MTP_EVENT_TRANSITION_FAILED,
    OZAYN_MTP_EVENT_COUNT
} ozayn_mtp_event_type_t;

/* ============================================================
 * SECTION 6 — BOUNDED LIMITS
 * ============================================================ */

#define OZAYN_MTP_MAX_POLICIES          32
#define OZAYN_MTP_MAX_REQUESTS          64
#define OZAYN_MTP_MAX_DECISIONS         64
#define OZAYN_MTP_MAX_EVENTS            256
#define OZAYN_MTP_MAX_BLOCKING          16
#define OZAYN_MTP_MAX_WARNINGS          16
#define OZAYN_MTP_MAX_NAME_LEN          64
#define OZAYN_MTP_MAX_DESC_LEN          128
#define OZAYN_MTP_MAX_ID_LEN            48
#define OZAYN_MTP_MAX_PERMISSION_LEN    64
#define OZAYN_MTP_DEFAULT_TIMEOUT_MS    30000
#define OZAYN_MTP_REQUEST_EXPIRY_MS     60000
#define OZAYN_MTP_DECISION_EXPIRY_MS    60000

/* ============================================================
 * SECTION 7 — TRANSITION POLICY
 * ============================================================ */

typedef struct {
    char id[OZAYN_MTP_MAX_ID_LEN];
    char name[OZAYN_MTP_MAX_NAME_LEN];
    ozayn_ord_mode_t source_mode;
    ozayn_ord_mode_t target_mode;

    /* Policy conditions */
    int require_security_valid;
    int require_safety_satisfied;
    int require_resources_available;
    int require_recovery_complete;
    int require_no_active_operations;
    int require_readiness_assessment;

    /* Authorization */
    char required_permission[OZAYN_MTP_MAX_PERMISSION_LEN];

    /* Behavior */
    int transition_timeout_ms;
    int enabled;
    int active;
} ozayn_mtp_policy_t;

/* ============================================================
 * SECTION 8 — TRANSITION REQUEST
 * ============================================================ */

typedef struct {
    char id[OZAYN_MTP_MAX_ID_LEN];
    ozayn_ord_mode_t source_mode;
    ozayn_ord_mode_t target_mode;
    ozayn_mtp_trigger_t trigger;
    char reason[OZAYN_MTP_MAX_DESC_LEN];
    char requester[OZAYN_MTP_MAX_NAME_LEN];
    int priority;
    int64_t timestamp_ms;
    int64_t expiration_ms;
    ozayn_mtp_phase_t phase;
    int active;
} ozayn_mtp_request_t;

/* ============================================================
 * SECTION 9 — TRANSITION DECISION
 * ============================================================ */

typedef struct {
    char id[OZAYN_MTP_MAX_ID_LEN];
    char request_id[OZAYN_MTP_MAX_ID_LEN];
    ozayn_ord_mode_t source_mode;
    ozayn_ord_mode_t target_mode;
    ozayn_mtp_outcome_t outcome;
    ozayn_mtp_phase_t phase;

    /* Sub-decisions */
    int security_passed;
    int safety_passed;
    int resource_passed;
    int dependency_passed;
    int operation_assessment_passed;
    int readiness_current;

    /* Blocking and warnings */
    char blocking[OZAYN_MTP_MAX_BLOCKING][OZAYN_MTP_MAX_DESC_LEN];
    int blocking_count;
    char warnings[OZAYN_MTP_MAX_WARNINGS][OZAYN_MTP_MAX_DESC_LEN];
    int warning_count;

    /* Timestamps */
    int64_t timestamp_ms;
    int64_t expiration_ms;
    int active;
} ozayn_mtp_decision_t;

/* ============================================================
 * SECTION 10 — EVENT ENTRY
 * ============================================================ */

typedef struct {
    ozayn_mtp_event_type_t type;
    char id[OZAYN_MTP_MAX_ID_LEN];
    char source[OZAYN_MTP_MAX_NAME_LEN];
    char message[OZAYN_MTP_MAX_DESC_LEN];
    int64_t timestamp_ms;
    int64_t sequence;
} ozayn_mtp_event_t;

/* ============================================================
 * SECTION 11 — STATS
 * ============================================================ */

typedef struct {
    int total_evaluations;
    int total_approvals;
    int total_denials;
    int total_deferrals;
    int total_transitions_executed;
    int total_transitions_failed;
    int total_policy_violations;
    int total_conflicts_detected;
    int total_requests_expired;
} ozayn_mtp_stats_t;

/* ============================================================
 * SECTION 12 — SERVICE CONFIG
 * ============================================================ */

typedef struct {
    void *readiness;
    void *audit;
    void *safety;
    void *resource_manager;
    void *component_registry;
} ozayn_mtp_service_config_t;

/* ============================================================
 * SECTION 13 — SERVICE
 * ============================================================ */

typedef struct {
    int initialized;
    int evaluation_in_progress;

    /* Policies */
    ozayn_mtp_policy_t policies[OZAYN_MTP_MAX_POLICIES];
    int policy_count;

    /* Requests */
    ozayn_mtp_request_t requests[OZAYN_MTP_MAX_REQUESTS];
    int request_count;
    int request_head;

    /* Decisions */
    ozayn_mtp_decision_t decisions[OZAYN_MTP_MAX_DECISIONS];
    int decision_count;
    int decision_head;

    /* Active transition */
    int has_active_transition;
    char active_request_id[OZAYN_MTP_MAX_ID_LEN];

    /* Events */
    ozayn_mtp_event_t events[OZAYN_MTP_MAX_EVENTS];
    int event_count;
    int event_head;
    int64_t event_sequence;

    /* Subsystem pointers */
    void *readiness;
    void *audit;
    void *safety;
    void *resource_manager;
    void *component_registry;

    /* Stats */
    ozayn_mtp_stats_t stats;
} ozayn_mtp_service_t;

/* ============================================================
 * SECTION 14 — FUNCTION DECLARATIONS
 * ============================================================ */

/* Lifecycle */
ozayn_mtp_err_t ozayn_mtp_service_init(ozayn_mtp_service_t *svc,
    const ozayn_mtp_service_config_t *cfg);
ozayn_mtp_err_t ozayn_mtp_service_shutdown(ozayn_mtp_service_t *svc);

/* Global */
ozayn_mtp_service_t *ozayn_mtp_get_global(void);

/* Subsystem binding */
ozayn_mtp_err_t ozayn_mtp_set_readiness(ozayn_mtp_service_t *svc, void *ptr);
ozayn_mtp_err_t ozayn_mtp_set_audit(ozayn_mtp_service_t *svc, void *ptr);
ozayn_mtp_err_t ozayn_mtp_set_safety(ozayn_mtp_service_t *svc, void *ptr);
ozayn_mtp_err_t ozayn_mtp_set_resource_manager(ozayn_mtp_service_t *svc, void *ptr);
ozayn_mtp_err_t ozayn_mtp_set_component_registry(ozayn_mtp_service_t *svc, void *ptr);

/* Policy management */
ozayn_mtp_err_t ozayn_mtp_add_policy(ozayn_mtp_service_t *svc,
    const ozayn_mtp_policy_t *policy);
ozayn_mtp_err_t ozayn_mtp_remove_policy(ozayn_mtp_service_t *svc,
    const char *policy_id);
ozayn_mtp_err_t ozayn_mtp_enable_policy(ozayn_mtp_service_t *svc,
    const char *policy_id, int enabled);
ozayn_mtp_err_t ozayn_mtp_get_policy(const ozayn_mtp_service_t *svc,
    const char *policy_id, ozayn_mtp_policy_t *out);
int ozayn_mtp_policy_count(const ozayn_mtp_service_t *svc);
ozayn_mtp_err_t ozayn_mtp_get_policy_at(const ozayn_mtp_service_t *svc,
    int index, ozayn_mtp_policy_t *out);

/* Evaluation */
ozayn_mtp_err_t ozayn_mtp_evaluate(ozayn_mtp_service_t *svc,
    ozayn_ord_mode_t source, ozayn_ord_mode_t target,
    ozayn_mtp_trigger_t trigger, const char *reason,
    const char *requester, ozayn_mtp_decision_t *out_decision);

/* Quick check */
int ozayn_mtp_can_transition(const ozayn_mtp_service_t *svc,
    ozayn_ord_mode_t source, ozayn_ord_mode_t target);

/* Request queries */
ozayn_mtp_err_t ozayn_mtp_get_request(const ozayn_mtp_service_t *svc,
    const char *request_id, ozayn_mtp_request_t *out);
int ozayn_mtp_request_count(const ozayn_mtp_service_t *svc);

/* Decision queries */
ozayn_mtp_err_t ozayn_mtp_get_decision(const ozayn_mtp_service_t *svc,
    const char *decision_id, ozayn_mtp_decision_t *out);
ozayn_mtp_err_t ozayn_mtp_get_latest_decision(const ozayn_mtp_service_t *svc,
    ozayn_mtp_decision_t *out);
int ozayn_mtp_decision_count(const ozayn_mtp_service_t *svc);

/* Events */
ozayn_mtp_err_t ozayn_mtp_get_event(const ozayn_mtp_service_t *svc,
    int index, ozayn_mtp_event_t *out);
int ozayn_mtp_event_count(const ozayn_mtp_service_t *svc);

/* Stats */
const ozayn_mtp_stats_t *ozayn_mtp_get_stats(const ozayn_mtp_service_t *svc);
ozayn_mtp_err_t ozayn_mtp_reset_stats(ozayn_mtp_service_t *svc);

/* Name helpers */
const char *ozayn_mtp_err_name(ozayn_mtp_err_t err);
const char *ozayn_mtp_outcome_name(ozayn_mtp_outcome_t outcome);
const char *ozayn_mtp_phase_name(ozayn_mtp_phase_t phase);
const char *ozayn_mtp_trigger_name(ozayn_mtp_trigger_t trigger);
const char *ozayn_mtp_event_type_name(ozayn_mtp_event_type_t type);

#endif /* OZAYN_MODE_TRANSITION_POLICY_H */
