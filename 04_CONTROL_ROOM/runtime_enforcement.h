#ifndef OZAYN_RUNTIME_ENFORCEMENT_H
#define OZAYN_RUNTIME_ENFORCEMENT_H

#include "operational_readiness.h"

/* ============================================================
 * SECTION 1 — ERROR CODES
 * ============================================================ */

typedef enum {
    OZAYN_ROE_OK                          =   0,
    OZAYN_ROE_ERR_NULL                    =  -1,
    OZAYN_ROE_ERR_NOT_INITIALIZED         =  -2,
    OZAYN_ROE_ERR_ALREADY_INITIALIZED     =  -3,
    OZAYN_ROE_ERR_INVALID_PARAM           =  -4,
    OZAYN_ROE_ERR_STATE_INVALID           =  -5,
    OZAYN_ROE_ERR_NOT_FOUND               =  -6,
    OZAYN_ROE_ERR_EXPIRED                 =  -7,
    OZAYN_ROE_ERR_INVALIDATED             =  -8,
    OZAYN_ROE_ERR_MODE_BLOCKED            =  -9,
    OZAYN_ROE_ERR_READINESS_BLOCKED       = -10,
    OZAYN_ROE_ERR_TARGET_INVALID          = -11,
    OZAYN_ROE_ERR_TARGET_UNAVAILABLE      = -12,
    OZAYN_ROE_ERR_CAPABILITY_UNAVAILABLE  = -13,
    OZAYN_ROE_ERR_AUTHORIZATION_FAILED    = -14,
    OZAYN_ROE_ERR_PERMISSION_DENIED       = -15,
    OZAYN_ROE_ERR_SECURITY_UNAVAILABLE    = -16,
    OZAYN_ROE_ERR_SAFETY_FAILED           = -17,
    OZAYN_ROE_ERR_POLICY_DENIED           = -18,
    OZAYN_ROE_ERR_SAFETY_UNAVAILABLE      = -19,
    OZAYN_ROE_ERR_RESOURCE_UNAVAILABLE    = -20,
    OZAYN_ROE_ERR_RESOURCE_CONFLICT       = -21,
    OZAYN_ROE_ERR_DEVICE_UNAVAILABLE      = -22,
    OZAYN_ROE_ERR_DEVICE_SESSION_INVALID  = -23,
    OZAYN_ROE_ERR_WORKFLOW_BLOCKED        = -24,
    OZAYN_ROE_ERR_PIPELINE_BLOCKED        = -25,
    OZAYN_ROE_ERR_DEPENDENCY_FAILED       = -26,
    OZAYN_ROE_ERR_CONFLICT                = -27,
    OZAYN_ROE_ERR_REASSESSMENT_REQUIRED   = -28,
    OZAYN_ROE_ERR_TIMEOUT                 = -29,
    OZAYN_ROE_ERR_CANCELLED               = -30,
    OZAYN_ROE_ERR_CONCURRENCY_ERROR       = -31,
    OZAYN_ROE_ERR_CONFIGURATION_ERROR     = -32,
    OZAYN_ROE_ERR_EVENT_ERROR             = -33,
    OZAYN_ROE_ERR_LIMIT_REACHED           = -34
} ozayn_roe_err_t;

/* ============================================================
 * SECTION 2 — ENFORCEMENT DECISIONS
 * ============================================================ */

typedef enum {
    OZAYN_ROE_DECISION_ALLOW_DISPATCH = 0,
    OZAYN_ROE_DECISION_BLOCK_DISPATCH,
    OZAYN_ROE_DECISION_REQUIRE_REASSESSMENT,
    OZAYN_ROE_DECISION_REQUIRE_AUTHORIZATION,
    OZAYN_ROE_DECISION_REQUIRE_SAFETY_RECHECK,
    OZAYN_ROE_DECISION_REQUIRE_RESOURCE_RECHECK,
    OZAYN_ROE_DECISION_REQUIRE_DEVICE_RECHECK,
    OZAYN_ROE_DECISION_REQUIRE_MODE_RECHECK,
    OZAYN_ROE_DECISION_EXPIRED,
    OZAYN_ROE_DECISION_UNAVAILABLE
} ozayn_roe_decision_t;

/* ============================================================
 * SECTION 3 — ENFORCEMENT PHASES
 * ============================================================ */

typedef enum {
    OZAYN_ROE_PHASE_NONE = 0,
    OZAYN_ROE_PHASE_REQUESTED,
    OZAYN_ROE_PHASE_VALIDATING,
    OZAYN_ROE_PHASE_REVALIDATING,
    OZAYN_ROE_PHASE_SECURITY_CHECK,
    OZAYN_ROE_PHASE_SAFETY_CHECK,
    OZAYN_ROE_PHASE_RESOURCE_CHECK,
    OZAYN_ROE_PHASE_DEVICE_CHECK,
    OZAYN_ROE_PHASE_MODE_CHECK,
    OZAYN_ROE_PHASE_TARGET_CHECK,
    OZAYN_ROE_PHASE_APPROVED,
    OZAYN_ROE_PHASE_DISPATCHING,
    OZAYN_ROE_PHASE_DISPATCHED,
    OZAYN_ROE_PHASE_REJECTED,
    OZAYN_ROE_PHASE_BLOCKED,
    OZAYN_ROE_PHASE_EXPIRED,
    OZAYN_ROE_PHASE_FAILED,
    OZAYN_ROE_PHASE_CANCELLED,
    OZAYN_ROE_PHASE_UNAVAILABLE
} ozayn_roe_phase_t;

/* ============================================================
 * SECTION 4 — EVENT TYPES
 * ============================================================ */

typedef enum {
    OZAYN_ROE_EVENT_REQUESTED = 0,
    OZAYN_ROE_EVENT_VALIDATING,
    OZAYN_ROE_EVENT_REVALIDATING,
    OZAYN_ROE_EVENT_APPROVED,
    OZAYN_ROE_EVENT_BLOCKED,
    OZAYN_ROE_EVENT_REASSESSMENT_REQUIRED,
    OZAYN_ROE_EVENT_AUTHORIZATION_REQUIRED,
    OZAYN_ROE_EVENT_SAFETY_CHECK_REQUIRED,
    OZAYN_ROE_EVENT_RESOURCE_CHECK_REQUIRED,
    OZAYN_ROE_EVENT_DEVICE_CHECK_REQUIRED,
    OZAYN_ROE_EVENT_MODE_CHECK_REQUIRED,
    OZAYN_ROE_EVENT_DISPATCHING,
    OZAYN_ROE_EVENT_DISPATCHED,
    OZAYN_ROE_EVENT_EXPIRED,
    OZAYN_ROE_EVENT_CANCELLED,
    OZAYN_ROE_EVENT_FAILED,
    OZAYN_ROE_EVENT_DUPLICATE_BLOCKED,
    OZAYN_ROE_EVENT_COUNT
} ozayn_roe_event_type_t;

/* ============================================================
 * SECTION 5 — BOUNDED LIMITS
 * ============================================================ */

#define OZAYN_ROE_MAX_REQUESTS          64
#define OZAYN_ROE_MAX_DECISIONS        128
#define OZAYN_ROE_MAX_EVENTS           256
#define OZAYN_ROE_MAX_BLOCKING          16
#define OZAYN_ROE_MAX_WARNINGS          16
#define OZAYN_ROE_MAX_ID_LEN            48
#define OZAYN_ROE_MAX_NAME_LEN          64
#define OZAYN_ROE_MAX_DESC_LEN         128
#define OZAYN_ROE_MAX_CORRELATION_LEN   64
#define OZAYN_ROE_DEFAULT_EXPIRY_MS     30000
#define OZAYN_ROE_MAX_REASSESSMENTS      3

/* ============================================================
 * SECTION 6 — ENFORCEMENT REQUEST
 * ============================================================ */

typedef struct {
    char id[OZAYN_ROE_MAX_ID_LEN];
    char admission_request_id[OZAYN_ROE_MAX_ID_LEN];
    char admission_decision_id[OZAYN_ROE_MAX_ID_LEN];
    char operation_id[OZAYN_ROE_MAX_ID_LEN];
    char request_id[OZAYN_ROE_MAX_ID_LEN];
    char workflow_id[OZAYN_ROE_MAX_ID_LEN];
    char stage_id[OZAYN_ROE_MAX_ID_LEN];
    char pipeline_id[OZAYN_ROE_MAX_ID_LEN];
    char target_component_id[OZAYN_ROE_MAX_NAME_LEN];
    char capability_id[OZAYN_ROE_MAX_NAME_LEN];
    char requested_action[OZAYN_ROE_MAX_NAME_LEN];
    char security_session_ref[OZAYN_ROE_MAX_CORRELATION_LEN];
    char safety_decision_ref[OZAYN_ROE_MAX_CORRELATION_LEN];
    char resource_reservation_ref[OZAYN_ROE_MAX_CORRELATION_LEN];
    char device_session_ref[OZAYN_ROE_MAX_CORRELATION_LEN];
    int runtime_mode;
    int priority;
    int64_t request_time_ms;
    int64_t expiration_ms;
    int active;
} ozayn_roe_request_t;

/* ============================================================
 * SECTION 7 — ENFORCEMENT CONTEXT
 * ============================================================ */

typedef struct {
    int runtime_mode;
    int readiness_satisfied;
    int component_available;
    int capability_available;
    int security_session_valid;
    int authorization_valid;
    int safety_policy_valid;
    int resources_available;
    int devices_available;
    int workflow_valid;
    int pipeline_valid;
    int dependencies_satisfied;
    int operation_active;
    int operation_cancelled;
    int operation_expired;
    int duplicate_detected;
} ozayn_roe_context_t;

/* ============================================================
 * SECTION 8 — ENFORCEMENT DECISION RECORD
 * ============================================================ */

typedef struct {
    char id[OZAYN_ROE_MAX_ID_LEN];
    char request_id[OZAYN_ROE_MAX_ID_LEN];
    char operation_id[OZAYN_ROE_MAX_ID_LEN];
    ozayn_roe_decision_t decision;
    ozayn_roe_phase_t phase;
    char reason[OZAYN_ROE_MAX_DESC_LEN];
    int mode_valid;
    int readiness_valid;
    int target_valid;
    int capability_valid;
    int security_valid;
    int authorization_valid;
    int safety_valid;
    int resource_valid;
    int device_valid;
    int workflow_valid;
    int pipeline_valid;
    int dependency_valid;
    int operation_valid;
    int expired;
    char blocking[OZAYN_ROE_MAX_BLOCKING][OZAYN_ROE_MAX_DESC_LEN];
    int blocking_count;
    char warnings[OZAYN_ROE_MAX_WARNINGS][OZAYN_ROE_MAX_DESC_LEN];
    int warning_count;
    int active;
    int64_t timestamp_ms;
    int64_t expiration_ms;
    int reassessment_count;
} ozayn_roe_enforcement_t;

/* ============================================================
 * SECTION 9 — ENFORCEMENT EVENT
 * ============================================================ */

typedef struct {
    char id[OZAYN_ROE_MAX_ID_LEN];
    ozayn_roe_event_type_t type;
    char source[OZAYN_ROE_MAX_NAME_LEN];
    char message[OZAYN_ROE_MAX_DESC_LEN];
    char request_id[OZAYN_ROE_MAX_ID_LEN];
    char operation_id[OZAYN_ROE_MAX_ID_LEN];
    int64_t timestamp_ms;
    uint32_t sequence;
} ozayn_roe_event_t;

/* ============================================================
 * SECTION 10 — STATISTICS
 * ============================================================ */

typedef struct {
    int total_requests;
    int total_approved;
    int total_blocked;
    int total_reassessments;
    int total_expired;
    int total_cancelled;
    int total_duplicates_blocked;
    int mode_blocks;
    int readiness_blocks;
    int target_blocks;
    int capability_blocks;
    int security_blocks;
    int authorization_blocks;
    int safety_blocks;
    int resource_blocks;
    int device_blocks;
    int workflow_blocks;
    int pipeline_blocks;
    int dependency_blocks;
    int operation_blocks;
    int total_dispatches;
    int total_invalidated;
} ozayn_roe_stats_t;

/* ============================================================
 * SECTION 11 — SERVICE CONFIGURATION
 * ============================================================ */

typedef struct {
    void *readiness;
    void *audit;
    void *safety;
    void *resource_manager;
    void *component_registry;
    void *device_session;
    void *operation_queue;
    void *operation_history;
    void *pipeline_scheduler;
    void *workflow_orchestrator;
    void *pipeline_coordinator;
    void *events_engine;
    void *diagnostics;
    void *command_router;
    void *mode_transition_policy;
} ozayn_roe_config_t;

/* ============================================================
 * SECTION 12 — SERVICE STRUCT
 * ============================================================ */

typedef struct {
    int initialized;
    ozayn_roe_request_t requests[OZAYN_ROE_MAX_REQUESTS];
    int request_head;
    int request_count;
    ozayn_roe_enforcement_t decisions[OZAYN_ROE_MAX_DECISIONS];
    int decision_head;
    int decision_count;
    ozayn_roe_event_t events[OZAYN_ROE_MAX_EVENTS];
    int event_head;
    int event_count;
    uint32_t event_sequence;
    ozayn_roe_stats_t stats;
    void *readiness;
    void *audit;
    void *safety;
    void *resource_manager;
    void *component_registry;
    void *device_session;
    void *operation_queue;
    void *operation_history;
    void *pipeline_scheduler;
    void *workflow_orchestrator;
    void *pipeline_coordinator;
    void *events_engine;
    void *diagnostics;
    void *command_router;
    void *mode_transition_policy;
} ozayn_roe_service_t;

/* ============================================================
 * SECTION 13 — LIFECYCLE
 * ============================================================ */

ozayn_roe_err_t ozayn_roe_service_init(ozayn_roe_service_t *svc,
                                       const ozayn_roe_config_t *cfg);
ozayn_roe_err_t ozayn_roe_service_shutdown(ozayn_roe_service_t *svc);

/* ============================================================
 * SECTION 14 — SUBSYSTEM BINDING (12 subsystems)
 * ============================================================ */

ozayn_roe_err_t ozayn_roe_set_readiness(ozayn_roe_service_t *svc, void *ptr);
ozayn_roe_err_t ozayn_roe_set_audit(ozayn_roe_service_t *svc, void *ptr);
ozayn_roe_err_t ozayn_roe_set_safety(ozayn_roe_service_t *svc, void *ptr);
ozayn_roe_err_t ozayn_roe_set_resource_manager(ozayn_roe_service_t *svc, void *ptr);
ozayn_roe_err_t ozayn_roe_set_component_registry(ozayn_roe_service_t *svc, void *ptr);
ozayn_roe_err_t ozayn_roe_set_device_session(ozayn_roe_service_t *svc, void *ptr);
ozayn_roe_err_t ozayn_roe_set_operation_queue(ozayn_roe_service_t *svc, void *ptr);
ozayn_roe_err_t ozayn_roe_set_operation_history(ozayn_roe_service_t *svc, void *ptr);
ozayn_roe_err_t ozayn_roe_set_pipeline_scheduler(ozayn_roe_service_t *svc, void *ptr);
ozayn_roe_err_t ozayn_roe_set_workflow_orchestrator(ozayn_roe_service_t *svc, void *ptr);
ozayn_roe_err_t ozayn_roe_set_pipeline_coordinator(ozayn_roe_service_t *svc, void *ptr);
ozayn_roe_err_t ozayn_roe_set_events_engine(ozayn_roe_service_t *svc, void *ptr);
ozayn_roe_err_t ozayn_roe_set_diagnostics(ozayn_roe_service_t *svc, void *ptr);
ozayn_roe_err_t ozayn_roe_set_command_router(ozayn_roe_service_t *svc, void *ptr);
ozayn_roe_err_t ozayn_roe_set_mode_transition_policy(ozayn_roe_service_t *svc, void *ptr);

/* ============================================================
 * SECTION 15 — ENFORCEMENT PIPELINE
 * ============================================================ */

ozayn_roe_err_t ozayn_roe_enforce(ozayn_roe_service_t *svc,
                                   const ozayn_roe_request_t *request,
                                   const ozayn_roe_context_t *ctx,
                                   ozayn_roe_enforcement_t *out);

/* ============================================================
 * SECTION 16 — QUICK CHECK
 * ============================================================ */

int ozayn_roe_can_dispatch(const ozayn_roe_service_t *svc,
                           const ozayn_roe_request_t *request,
                           const ozayn_roe_context_t *ctx);

/* ============================================================
 * SECTION 17 — REASSESSMENT
 * ============================================================ */

ozayn_roe_err_t ozayn_roe_reassess(ozayn_roe_service_t *svc,
                                    const char *enforcement_id,
                                    const ozayn_roe_context_t *ctx,
                                    ozayn_roe_enforcement_t *out);

/* ============================================================
 * SECTION 18 — INVALIDATION
 * ============================================================ */

ozayn_roe_err_t ozayn_roe_invalidate(ozayn_roe_service_t *svc,
                                      const char *enforcement_id);

/* ============================================================
 * SECTION 19 — QUERIES
 * ============================================================ */

ozayn_roe_err_t ozayn_roe_get_decision(const ozayn_roe_service_t *svc,
                                        const char *enforcement_id,
                                        ozayn_roe_enforcement_t *out);
ozayn_roe_err_t ozayn_roe_get_latest_decision(const ozayn_roe_service_t *svc,
                                                ozayn_roe_enforcement_t *out);
int ozayn_roe_decision_count(const ozayn_roe_service_t *svc);
ozayn_roe_err_t ozayn_roe_get_request(const ozayn_roe_service_t *svc,
                                       const char *request_id,
                                       ozayn_roe_request_t *out);
int ozayn_roe_request_count(const ozayn_roe_service_t *svc);

/* ============================================================
 * SECTION 20 — EVENTS
 * ============================================================ */

ozayn_roe_err_t ozayn_roe_get_event(const ozayn_roe_service_t *svc,
                                     int index, ozayn_roe_event_t *out);
int ozayn_roe_event_count(const ozayn_roe_service_t *svc);

/* ============================================================
 * SECTION 21 — STATISTICS
 * ============================================================ */

const ozayn_roe_stats_t *ozayn_roe_get_stats(const ozayn_roe_service_t *svc);
ozayn_roe_err_t ozayn_roe_reset_stats(ozayn_roe_service_t *svc);

/* ============================================================
 * SECTION 22 — NAME HELPERS
 * ============================================================ */

const char *ozayn_roe_err_name(ozayn_roe_err_t err);
const char *ozayn_roe_decision_name(ozayn_roe_decision_t d);
const char *ozayn_roe_phase_name(ozayn_roe_phase_t p);
const char *ozayn_roe_event_type_name(ozayn_roe_event_type_t t);

#endif /* OZAYN_RUNTIME_ENFORCEMENT_H */
