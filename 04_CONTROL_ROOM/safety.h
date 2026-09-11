/*
 * safety.h — Safety, Preconditions & Policy Enforcement (Step 08).
 *
 * Ensures operations are validated through structured preconditions,
 * policy evaluation, and safety checks before dispatch.
 *
 * Design principles:
 * - Fail closed when safety decisions cannot be established
 * - Default deny unless explicitly allowed
 * - No authorization bypass, no safety bypass
 * - No arbitrary command/script execution
 * - No unbounded traversal or retries
 * - No secret logging
 */

#ifndef OZAYN_SAFETY_H
#define OZAYN_SAFETY_H

#ifdef __cplusplus
extern "C" {
#endif

#include <time.h>

/* ============================================================
 * SECTION 1 — ERROR CODES
 * ============================================================ */

typedef enum {
    OZAYN_SPE_OK = 0,
    OZAYN_SPE_ERR_NULL = -1,
    OZAYN_SPE_ERR_NOT_INITIALIZED = -2,
    OZAYN_SPE_ERR_ALREADY_INITIALIZED = -3,
    OZAYN_SPE_ERR_INVALID_PARAM = -4,
    OZAYN_SPE_ERR_LIMIT_REACHED = -5,
    OZAYN_SPE_ERR_NOT_FOUND = -6,
    OZAYN_SPE_ERR_STATE_INVALID = -7,
    OZAYN_SPE_ERR_PRECONDITION_FAILED = -8,
    OZAYN_SPE_ERR_PRECONDITION_UNKNOWN = -9,
    OZAYN_SPE_ERR_PRECONDITION_UNAVAILABLE = -10,
    OZAYN_SPE_ERR_POLICY_NOT_FOUND = -11,
    OZAYN_SPE_ERR_POLICY_INVALID = -12,
    OZAYN_SPE_ERR_POLICY_DENIED = -13,
    OZAYN_SPE_ERR_POLICY_UNAVAILABLE = -14,
    OZAYN_SPE_ERR_STATE_REQUIREMENT = -15,
    OZAYN_SPE_ERR_AVAILABILITY_REQUIREMENT = -16,
    OZAYN_SPE_ERR_HEALTH_REQUIREMENT = -17,
    OZAYN_SPE_ERR_DEPENDENCY_REQUIREMENT = -18,
    OZAYN_SPE_ERR_AUTHORIZATION_REQUIREMENT = -19,
    OZAYN_SPE_ERR_SESSION_REQUIREMENT = -20,
    OZAYN_SPE_ERR_RESOURCE_REQUIREMENT = -21,
    OZAYN_SPE_ERR_CONFIGURATION_REQUIREMENT = -22,
    OZAYN_SPE_ERR_SECURITY_REQUIREMENT = -23,
    OZAYN_SPE_ERR_OPERATION_CONFLICT = -24,
    OZAYN_SPE_ERR_SAFETY_CHECK_FAILED = -25,
    OZAYN_SPE_ERR_SAFETY_RECHECK_FAILED = -26,
    OZAYN_SPE_ERR_DECISION_EXPIRED = -27,
    OZAYN_SPE_ERR_CONCURRENCY_LIMIT = -28
} ozayn_spe_err_t;

/* ============================================================
 * SECTION 2 — PRECONDITION TYPES & CATEGORIES
 * ============================================================ */

typedef enum {
    OZAYN_SPE_PRECOND_TARGET_STATE = 0,
    OZAYN_SPE_PRECOND_TARGET_AVAILABILITY,
    OZAYN_SPE_PRECOND_TARGET_HEALTH,
    OZAYN_SPE_PRECOND_CAPABILITY,
    OZAYN_SPE_PRECOND_DEPENDENCY,
    OZAYN_SPE_PRECOND_AUTHORIZATION,
    OZAYN_SPE_PRECOND_SESSION,
    OZAYN_SPE_PRECOND_RESOURCE,
    OZAYN_SPE_PRECOND_CONFIGURATION,
    OZAYN_SPE_PRECOND_SECURITY,
    OZAYN_SPE_PRECOND_CONFLICT,
    OZAYN_SPE_PRECOND_LIFECYCLE,
    OZAYN_SPE_PRECOND_COUNT
} ozayn_spe_precond_category_t;

typedef enum {
    OZAYN_SPE_RESULT_SATISFIED = 0,
    OZAYN_SPE_RESULT_FAILED,
    OZAYN_SPE_RESULT_UNKNOWN,
    OZAYN_SPE_RESULT_UNAVAILABLE,
    OZAYN_SPE_RESULT_NOT_APPLICABLE,
    OZAYN_SPE_RESULT_COUNT
} ozayn_spe_precond_result_t;

/* ============================================================
 * SECTION 3 — SAFETY LEVELS
 * ============================================================ */

typedef enum {
    OZAYN_SPE_LEVEL_SAFE = 0,
    OZAYN_SPE_LEVEL_RESTRICTED,
    OZAYN_SPE_LEVEL_SENSITIVE,
    OZAYN_SPE_LEVEL_CRITICAL,
    OZAYN_SPE_LEVEL_COUNT
} ozayn_spe_safety_level_t;

/* ============================================================
 * SECTION 4 — POLICY DECISION
 * ============================================================ */

typedef enum {
    OZAYN_SPE_DECISION_ALLOW = 0,
    OZAYN_SPE_DECISION_DENY,
    OZAYN_SPE_DECISION_DEFER,
    OZAYN_SPE_DECISION_UNAVAILABLE,
    OZAYN_SPE_DECISION_COUNT
} ozayn_spe_decision_t;

/* ============================================================
 * SECTION 5 — EVENT TYPES
 * ============================================================ */

typedef enum {
    OZAYN_SPE_EVENT_PRECOND_EVALUATED = 0,
    OZAYN_SPE_EVENT_PRECOND_FAILED,
    OZAYN_SPE_EVENT_POLICY_EVALUATED,
    OZAYN_SPE_EVENT_POLICY_ALLOWED,
    OZAYN_SPE_EVENT_POLICY_DENIED,
    OZAYN_SPE_EVENT_POLICY_DEFERRED,
    OZAYN_SPE_EVENT_SAFETY_CHECK_STARTED,
    OZAYN_SPE_EVENT_SAFETY_CHECK_FAILED,
    OZAYN_SPE_EVENT_SAFETY_CHECK_PASSED,
    OZAYN_SPE_EVENT_SAFETY_RECHECK_REQUIRED,
    OZAYN_SPE_EVENT_CONFLICT_DETECTED,
    OZAYN_SPE_EVENT_OPERATION_BLOCKED,
    OZAYN_SPE_EVENT_COUNT
} ozayn_spe_event_type_t;

/* ============================================================
 * SECTION 6 — PRECONDITION STRUCT
 * ============================================================ */

#define OZAYN_SPE_MAX_ID_LEN       64
#define OZAYN_SPE_MAX_TARGET_LEN   64
#define OZAYN_SPE_MAX_DESC_LEN     256
#define OZAYN_SPE_MAX_META_LEN     256
#define OZAYN_SPE_MAX_DEPENDENCIES 16
#define OZAYN_SPE_MAX_PRECONDITIONS 128
#define OZAYN_SPE_MAX_POLICIES     64
#define OZAYN_SPE_MAX_DECISIONS    256
#define OZAYN_SPE_MAX_CONFLICT_RULES 32

typedef struct {
    char precondition_id[OZAYN_SPE_MAX_ID_LEN];
    int version;
    ozayn_spe_precond_category_t category;
    char description[OZAYN_SPE_MAX_DESC_LEN];
    char target[OZAYN_SPE_MAX_TARGET_LEN];
    char required_state[OZAYN_SPE_MAX_ID_LEN];
    int required_available;
    int required_health;       /* ozayn_dha_health_t cast */
    char required_capability[OZAYN_SPE_MAX_ID_LEN];
    char required_permission[OZAYN_SPE_MAX_ID_LEN];
    char required_dependencies[OZAYN_SPE_MAX_DEPENDENCIES][OZAYN_SPE_MAX_ID_LEN];
    int dependency_count;
    int resource_required;     /* 1 if resource check needed */
    ozayn_spe_precond_result_t result;
    time_t evaluation_time;
    char safe_metadata[OZAYN_SPE_MAX_META_LEN];
    int active;
} ozayn_spe_precondition_t;

/* ============================================================
 * SECTION 7 — POLICY STRUCT
 * ============================================================ */

typedef struct {
    char policy_id[OZAYN_SPE_MAX_ID_LEN];
    int version;
    char operation_type[OZAYN_SPE_MAX_ID_LEN];
    char target_type[OZAYN_SPE_MAX_ID_LEN];
    char capability[OZAYN_SPE_MAX_ID_LEN];
    char required_permission[OZAYN_SPE_MAX_ID_LEN];
    int required_health;        /* ozayn_dha_health_t cast, -1 = any */
    char required_state[OZAYN_SPE_MAX_ID_LEN]; /* empty = any */
    int required_available;     /* -1 = any, 0 = unavailable OK, 1 = must be available */
    char required_dependencies[OZAYN_SPE_MAX_DEPENDENCIES][OZAYN_SPE_MAX_ID_LEN];
    int dependency_count;
    int resource_required;
    char conflict_actions[OZAYN_SPE_MAX_CONFLICT_RULES][OZAYN_SPE_MAX_ID_LEN];
    int conflict_action_count;
    int timeout_limit_ms;
    int retry_limit;
    int cancellable;            /* 1 = can be cancelled */
    ozayn_spe_safety_level_t safety_level;
    int enabled;
    int active;
} ozayn_spe_policy_t;

/* ============================================================
 * SECTION 8 — POLICY DECISION STRUCT
 * ============================================================ */

typedef struct {
    char decision_id[OZAYN_SPE_MAX_ID_LEN];
    char request_id[OZAYN_SPE_MAX_ID_LEN];
    char operation_id[OZAYN_SPE_MAX_ID_LEN];
    ozayn_spe_decision_t decision;
    char policy_id[OZAYN_SPE_MAX_ID_LEN];
    int precondition_count;
    int failed_precondition_count;
    char failed_preconditions[OZAYN_SPE_MAX_PRECONDITIONS][OZAYN_SPE_MAX_ID_LEN];
    int warning_count;
    char warnings[OZAYN_SPE_MAX_PRECONDITIONS][OZAYN_SPE_MAX_DESC_LEN];
    time_t evaluation_time;
    time_t expiry_time;
    char safe_metadata[OZAYN_SPE_MAX_META_LEN];
    int active;
} ozayn_spe_decision_record_t;

/* ============================================================
 * SECTION 9 — STATISTICS
 * ============================================================ */

typedef struct {
    int total_evaluations;
    int total_allowed;
    int total_denied;
    int total_deferred;
    int total_unavailable;
    int total_precondition_pass;
    int total_precondition_fail;
    int total_conflicts_detected;
    int total_rechecks;
    int total_recheck_failures;
    int current_active_decisions;
} ozayn_spe_stats_t;

/* ============================================================
 * SECTION 10 — SERVICE CONFIGURATION
 * ============================================================ */

typedef struct {
    void *component_registry;
    void *command_router;
    void *operation_queue;
    void *operation_history;
    void *diagnostics;
    void *authorization;
    void *audit;
    void *event_engine;
    int max_preconditions;
    int max_policies;
    int max_decisions;
    int decision_ttl_ms;
} ozayn_spe_service_config_t;

/* ============================================================
 * SECTION 11 — SERVICE STATE
 * ============================================================ */

typedef struct {
    int initialized;
    void *component_registry;
    void *command_router;
    void *operation_queue;
    void *operation_history;
    void *diagnostics;
    void *authorization;
    void *audit;
    void *event_engine;
    int max_preconditions;
    int max_policies;
    int max_decisions;
    int decision_ttl_ms;
    ozayn_spe_precondition_t preconditions[OZAYN_SPE_MAX_PRECONDITIONS];
    int precondition_count;
    int precondition_sequence;
    ozayn_spe_policy_t policies[OZAYN_SPE_MAX_POLICIES];
    int policy_count;
    int policy_sequence;
    ozayn_spe_decision_record_t decisions[OZAYN_SPE_MAX_DECISIONS];
    int decision_count;
    int decision_head;
    int decision_sequence;
    ozayn_spe_stats_t stats;
} ozayn_spe_service_t;

/* ============================================================
 * SECTION 12 — LIFECYCLE
 * ============================================================ */

ozayn_spe_err_t ozayn_spe_service_init(ozayn_spe_service_t *svc,
                                        const ozayn_spe_service_config_t *cfg);
void ozayn_spe_service_shutdown(ozayn_spe_service_t *svc);
int ozayn_spe_service_is_initialized(const ozayn_spe_service_t *svc);

/* ============================================================
 * SECTION 13 — PRECONDITION MANAGEMENT
 * ============================================================ */

ozayn_spe_err_t ozayn_spe_precondition_create(ozayn_spe_service_t *svc,
                                               ozayn_spe_precond_category_t category,
                                               const char *description,
                                               const char *target,
                                               const char *required_state,
                                               int required_available,
                                               int required_health,
                                               const char *required_capability,
                                               const char *required_permission,
                                               int resource_required,
                                               ozayn_spe_precondition_t **out_precond);

ozayn_spe_err_t ozayn_spe_precondition_evaluate(ozayn_spe_service_t *svc,
                                                 const char *precondition_id,
                                                 ozayn_spe_precond_result_t result);

const ozayn_spe_precondition_t *ozayn_spe_precondition_get(
    const ozayn_spe_service_t *svc, const char *precondition_id);

int ozayn_spe_precondition_count(const ozayn_spe_service_t *svc);

ozayn_spe_err_t ozayn_spe_precondition_add_dependency(ozayn_spe_service_t *svc,
                                                       const char *precondition_id,
                                                       const char *dependency_id);

/* ============================================================
 * SECTION 14 — POLICY MANAGEMENT
 * ============================================================ */

ozayn_spe_err_t ozayn_spe_policy_create(ozayn_spe_service_t *svc,
                                         const char *operation_type,
                                         const char *target_type,
                                         const char *capability,
                                         const char *required_permission,
                                         int required_health,
                                         const char *required_state,
                                         int required_available,
                                         int resource_required,
                                         ozayn_spe_safety_level_t safety_level,
                                         int timeout_limit_ms,
                                         int retry_limit,
                                         int cancellable,
                                         ozayn_spe_policy_t **out_policy);

ozayn_spe_err_t ozayn_spe_policy_set_enabled(ozayn_spe_service_t *svc,
                                              const char *policy_id,
                                              int enabled);

const ozayn_spe_policy_t *ozayn_spe_policy_get(const ozayn_spe_service_t *svc,
                                                const char *policy_id);

const ozayn_spe_policy_t *ozayn_spe_policy_find(const ozayn_spe_service_t *svc,
                                                 const char *operation_type,
                                                 const char *target_type,
                                                 const char *capability);

int ozayn_spe_policy_count(const ozayn_spe_service_t *svc);

ozayn_spe_err_t ozayn_spe_policy_add_conflict(ozayn_spe_service_t *svc,
                                               const char *policy_id,
                                               const char *conflict_action);

ozayn_spe_err_t ozayn_spe_policy_add_dependency(ozayn_spe_service_t *svc,
                                                 const char *policy_id,
                                                 const char *dependency_id);

/* ============================================================
 * SECTION 15 — SAFETY EVALUATION
 * ============================================================ */

ozayn_spe_err_t ozayn_spe_evaluate(ozayn_spe_service_t *svc,
                                    const char *request_id,
                                    const char *operation_id,
                                    const char *target,
                                    const char *action,
                                    const char *capability,
                                    const char *session_id,
                                    const char *requester_identity,
                                    const char *required_permission,
                                    ozayn_spe_decision_record_t **out_decision);

ozayn_spe_err_t ozayn_spe_recheck(ozayn_spe_service_t *svc,
                                   const char *decision_id,
                                   const char *target,
                                   const char *capability,
                                   const char *session_id);

const ozayn_spe_decision_record_t *ozayn_spe_decision_get(
    const ozayn_spe_service_t *svc, const char *decision_id);

const ozayn_spe_decision_record_t *ozayn_spe_decision_get_by_request(
    const ozayn_spe_service_t *svc, const char *request_id);

int ozayn_spe_decision_count(const ozayn_spe_service_t *svc);

int ozayn_spe_decision_is_valid(const ozayn_spe_service_t *svc,
                                 const char *decision_id);

/* ============================================================
 * SECTION 16 — CONFLICT DETECTION
 * ============================================================ */

int ozayn_spe_has_conflict(const ozayn_spe_service_t *svc,
                            const char *target,
                            const char *action);

ozayn_spe_err_t ozayn_spe_check_conflict(const ozayn_spe_service_t *svc,
                                          const char *target,
                                          const char *action,
                                          int *out_conflict);

/* ============================================================
 * SECTION 17 — STATISTICS & QUERY
 * ============================================================ */

ozayn_spe_err_t ozayn_spe_get_stats(const ozayn_spe_service_t *svc,
                                     ozayn_spe_stats_t *out_stats);

/* ============================================================
 * SECTION 18 — CLEANUP
 * ============================================================ */

int ozayn_spe_cleanup_decisions(ozayn_spe_service_t *svc);
int ozayn_spe_cleanup_all(ozayn_spe_service_t *svc);

/* ============================================================
 * SECTION 19 — EVENT & AUDIT STUBS
 * ============================================================ */

ozayn_spe_err_t ozayn_spe_emit_event(ozayn_spe_service_t *svc,
                                      ozayn_spe_event_type_t event_type,
                                      const char *reference_id,
                                      const char *detail);

ozayn_spe_err_t ozayn_spe_audit(ozayn_spe_service_t *svc,
                                 const char *reference_id,
                                 const char *action,
                                 const char *detail);

/* ============================================================
 * SECTION 20 — VALIDATION
 * ============================================================ */

int ozayn_spe_precondition_validate(const ozayn_spe_precondition_t *precond);
int ozayn_spe_policy_validate(const ozayn_spe_policy_t *policy);
int ozayn_spe_decision_validate(const ozayn_spe_decision_record_t *decision);

/* ============================================================
 * SECTION 21 — NAME HELPERS
 * ============================================================ */

const char *ozayn_spe_err_name(ozayn_spe_err_t err);
const char *ozayn_spe_precond_category_name(ozayn_spe_precond_category_t cat);
const char *ozayn_spe_precond_result_name(ozayn_spe_precond_result_t result);
const char *ozayn_spe_safety_level_name(ozayn_spe_safety_level_t level);
const char *ozayn_spe_decision_name(ozayn_spe_decision_t decision);
const char *ozayn_spe_event_type_name(ozayn_spe_event_type_t event);

/* ============================================================
 * SECTION 22 — GLOBAL SINGLETON
 * ============================================================ */

ozayn_spe_service_t *ozayn_spe_get_global(void);

#ifdef __cplusplus
}
#endif

#endif /* OZAYN_SAFETY_H */
