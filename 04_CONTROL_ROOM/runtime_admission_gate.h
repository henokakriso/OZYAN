#ifndef OZAYN_RUNTIME_ADMISSION_GATE_H
#define OZAYN_RUNTIME_ADMISSION_GATE_H

#include "operational_readiness.h"

/* ============================================================
 * SECTION 1 — ERROR CODES
 * ============================================================ */

typedef enum {
    OZAYN_RAG_OK                          =   0,
    OZAYN_RAG_ERR_NULL                    =  -1,
    OZAYN_RAG_ERR_NOT_INITIALIZED         =  -2,
    OZAYN_RAG_ERR_ALREADY_INITIALIZED     =  -3,
    OZAYN_RAG_ERR_INVALID_PARAM           =  -4,
    OZAYN_RAG_ERR_STATE_INVALID           =  -5,
    OZAYN_RAG_ERR_NOT_FOUND               =  -6,
    OZAYN_RAG_ERR_EXPIRED                 =  -7,
    OZAYN_RAG_ERR_INVALIDATED             =  -8,
    OZAYN_RAG_ERR_MODE_BLOCKED            =  -9,
    OZAYN_RAG_ERR_READINESS_BLOCKED       = -10,
    OZAYN_RAG_ERR_TARGET_INVALID          = -11,
    OZAYN_RAG_ERR_TARGET_UNAVAILABLE      = -12,
    OZAYN_RAG_ERR_CAPABILITY_UNAVAILABLE  = -13,
    OZAYN_RAG_ERR_AUTHORIZATION_FAILED    = -14,
    OZAYN_RAG_ERR_PERMISSION_DENIED       = -15,
    OZAYN_RAG_ERR_SECURITY_UNAVAILABLE    = -16,
    OZAYN_RAG_ERR_SAFETY_FAILED           = -17,
    OZAYN_RAG_ERR_POLICY_DENIED           = -18,
    OZAYN_RAG_ERR_SAFETY_UNAVAILABLE      = -19,
    OZAYN_RAG_ERR_RESOURCE_UNAVAILABLE    = -20,
    OZAYN_RAG_ERR_RESOURCE_CONFLICT       = -21,
    OZAYN_RAG_ERR_DEVICE_UNAVAILABLE      = -22,
    OZAYN_RAG_ERR_DEVICE_SESSION_INVALID  = -23,
    OZAYN_RAG_ERR_WORKFLOW_BLOCKED        = -24,
    OZAYN_RAG_ERR_PIPELINE_BLOCKED        = -25,
    OZAYN_RAG_ERR_DEPENDENCY_FAILED       = -26,
    OZAYN_RAG_ERR_CONFLICT                = -27,
    OZAYN_RAG_ERR_REASSESSMENT_REQUIRED   = -28,
    OZAYN_RAG_ERR_TIMEOUT                 = -29,
    OZAYN_RAG_ERR_CANCELLED               = -30,
    OZAYN_RAG_ERR_CONCURRENCY_ERROR       = -31,
    OZAYN_RAG_ERR_CONFIGURATION_ERROR     = -32,
    OZAYN_RAG_ERR_EVENT_ERROR             = -33,
    OZAYN_RAG_ERR_LIMIT_REACHED           = -34
} ozayn_rag_err_t;

/* ============================================================
 * SECTION 2 — ADMISSION DECISIONS
 * ============================================================ */

typedef enum {
    OZAYN_RAG_DECISION_ACCEPT = 0,
    OZAYN_RAG_DECISION_QUEUE,
    OZAYN_RAG_DECISION_DEFER,
    OZAYN_RAG_DECISION_DENY,
    OZAYN_RAG_DECISION_BLOCKED,
    OZAYN_RAG_DECISION_REQUIRES_REASSESSMENT,
    OZAYN_RAG_DECISION_REQUIRES_AUTHORIZATION,
    OZAYN_RAG_DECISION_REQUIRES_SAFETY_CHECK,
    OZAYN_RAG_DECISION_REQUIRES_RESOURCE_CHECK,
    OZAYN_RAG_DECISION_REQUIRES_DEVICE_CHECK,
    OZAYN_RAG_DECISION_REQUIRES_RECOVERY,
    OZAYN_RAG_DECISION_EXPIRED,
    OZAYN_RAG_DECISION_UNAVAILABLE
} ozayn_rag_decision_t;

/* ============================================================
 * SECTION 3 — ADMISSION PHASES
 * ============================================================ */

typedef enum {
    OZAYN_RAG_PHASE_NONE = 0,
    OZAYN_RAG_PHASE_REQUESTED,
    OZAYN_RAG_PHASE_VALIDATING,
    OZAYN_RAG_PHASE_EVALUATING,
    OZAYN_RAG_PHASE_DECIDED,
    OZAYN_RAG_PHASE_ACCEPTED,
    OZAYN_RAG_PHASE_DENIED,
    OZAYN_RAG_PHASE_DEFERRED,
    OZAYN_RAG_PHASE_BLOCKED,
    OZAYN_RAG_PHASE_EXPIRED,
    OZAYN_RAG_PHASE_INVALIDATED,
    OZAYN_RAG_PHASE_CANCELLED
} ozayn_rag_phase_t;

/* ============================================================
 * SECTION 4 — EVENT TYPES
 * ============================================================ */

typedef enum {
    OZAYN_RAG_EVENT_REQUESTED = 0,
    OZAYN_RAG_EVENT_VALIDATING,
    OZAYN_RAG_EVENT_ACCEPTED,
    OZAYN_RAG_EVENT_QUEUED,
    OZAYN_RAG_EVENT_DEFERRED,
    OZAYN_RAG_EVENT_DENIED,
    OZAYN_RAG_EVENT_BLOCKED,
    OZAYN_RAG_EVENT_REASSESSMENT_REQUIRED,
    OZAYN_RAG_EVENT_AUTHORIZATION_REQUIRED,
    OZAYN_RAG_EVENT_SAFETY_CHECK_REQUIRED,
    OZAYN_RAG_EVENT_RESOURCE_CHECK_REQUIRED,
    OZAYN_RAG_EVENT_DEVICE_CHECK_REQUIRED,
    OZAYN_RAG_EVENT_EXPIRED,
    OZAYN_RAG_EVENT_INVALIDATED,
    OZAYN_RAG_EVENT_REVOKED,
    OZAYN_RAG_EVENT_REASSESSMENT_STARTED,
    OZAYN_RAG_EVENT_REASSESSMENT_COMPLETED,
    OZAYN_RAG_EVENT_COUNT
} ozayn_rag_event_type_t;

/* ============================================================
 * SECTION 5 — BOUNDED LIMITS
 * ============================================================ */

#define OZAYN_RAG_MAX_REQUESTS          64
#define OZAYN_RAG_MAX_DECISIONS        128
#define OZAYN_RAG_MAX_EVENTS           256
#define OZAYN_RAG_MAX_BLOCKING          16
#define OZAYN_RAG_MAX_WARNINGS          16
#define OZAYN_RAG_MAX_ID_LEN            48
#define OZAYN_RAG_MAX_NAME_LEN          64
#define OZAYN_RAG_MAX_DESC_LEN         128
#define OZAYN_RAG_MAX_CORRELATION_LEN   64
#define OZAYN_RAG_DEFAULT_EXPIRY_MS     30000
#define OZAYN_RAG_MAX_REASSESSMENTS      3

/* ============================================================
 * SECTION 6 — ADMISSION REQUEST
 * ============================================================ */

typedef struct {
    char id[OZAYN_RAG_MAX_ID_LEN];
    char operation_id[OZAYN_RAG_MAX_ID_LEN];
    char request_id[OZAYN_RAG_MAX_ID_LEN];
    char workflow_id[OZAYN_RAG_MAX_ID_LEN];
    char stage_id[OZAYN_RAG_MAX_ID_LEN];
    char pipeline_id[OZAYN_RAG_MAX_ID_LEN];
    char target_component_id[OZAYN_RAG_MAX_NAME_LEN];
    char capability_id[OZAYN_RAG_MAX_NAME_LEN];
    char requested_action[OZAYN_RAG_MAX_NAME_LEN];
    char requester[OZAYN_RAG_MAX_NAME_LEN];
    char security_session_ref[OZAYN_RAG_MAX_CORRELATION_LEN];
    int priority;
    int64_t timestamp_ms;
    int64_t expiration_ms;
    int active;
} ozayn_rag_request_t;

/* ============================================================
 * SECTION 7 — ADMISSION CONTEXT
 * ============================================================ */

typedef struct {
    ozayn_ord_mode_t runtime_mode;
    ozayn_ord_mode_t previous_mode;
    int readiness_satisfied;
    int component_available;
    int capability_available;
    int security_session_valid;
    int authorization_valid;
    int safety_policy_valid;
    int health_ok;
    int resources_available;
    int devices_available;
    int workflow_valid;
    int pipeline_valid;
    int scheduler_eligible;
    int dependencies_satisfied;
    int recovery_state;
    int64_t timestamp_ms;
    int64_t version;
} ozayn_rag_context_t;

/* ============================================================
 * SECTION 8 — ADMISSION DECISION
 * ============================================================ */

typedef struct {
    char id[OZAYN_RAG_MAX_ID_LEN];
    char admission_request_id[OZAYN_RAG_MAX_ID_LEN];
    char operation_id[OZAYN_RAG_MAX_ID_LEN];
    ozayn_rag_decision_t decision;
    ozayn_rag_phase_t phase;

    char reason[OZAYN_RAG_MAX_DESC_LEN];
    char blocking[OZAYN_RAG_MAX_BLOCKING][OZAYN_RAG_MAX_DESC_LEN];
    int blocking_count;
    char warnings[OZAYN_RAG_MAX_WARNINGS][OZAYN_RAG_MAX_DESC_LEN];
    int warning_count;

    int security_result;
    int authorization_result;
    int safety_result;
    int resource_result;
    int device_result;
    int workflow_result;
    int pipeline_result;

    int64_t timestamp_ms;
    int64_t expiration_ms;
    int reassessment_count;
    int active;
} ozayn_rag_admission_t;

/* ============================================================
 * SECTION 9 — EVENT ENTRY
 * ============================================================ */

typedef struct {
    ozayn_rag_event_type_t type;
    char id[OZAYN_RAG_MAX_ID_LEN];
    char request_id[OZAYN_RAG_MAX_ID_LEN];
    char source[OZAYN_RAG_MAX_NAME_LEN];
    char message[OZAYN_RAG_MAX_DESC_LEN];
    int64_t timestamp_ms;
    int64_t sequence;
} ozayn_rag_event_t;

/* ============================================================
 * SECTION 10 — STATS
 * ============================================================ */

typedef struct {
    int total_requests;
    int total_accepted;
    int total_queued;
    int total_deferred;
    int total_denied;
    int total_blocked;
    int total_expired;
    int total_invalidated;
    int total_reassessments;
    int total_revoked;
    int mode_denials;
    int security_denials;
    int safety_denials;
    int resource_denials;
    int device_denials;
} ozayn_rag_stats_t;

/* ============================================================
 * SECTION 11 — SERVICE CONFIG
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
    void *events_engine;
    void *diagnostics;
} ozayn_rag_config_t;

/* ============================================================
 * SECTION 12 — SERVICE
 * ============================================================ */

typedef struct {
    int initialized;

    /* Requests */
    ozayn_rag_request_t requests[OZAYN_RAG_MAX_REQUESTS];
    int request_count;
    int request_head;

    /* Decisions */
    ozayn_rag_admission_t decisions[OZAYN_RAG_MAX_DECISIONS];
    int decision_count;
    int decision_head;

    /* Events */
    ozayn_rag_event_t events[OZAYN_RAG_MAX_EVENTS];
    int event_count;
    int event_head;
    int64_t event_sequence;

    /* Subsystem pointers */
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
    void *events_engine;
    void *diagnostics;

    /* Stats */
    ozayn_rag_stats_t stats;
} ozayn_rag_service_t;

/* ============================================================
 * SECTION 13 — FUNCTION DECLARATIONS
 * ============================================================ */

/* Lifecycle */
ozayn_rag_err_t ozayn_rag_service_init(ozayn_rag_service_t *svc,
    const ozayn_rag_config_t *cfg);
ozayn_rag_err_t ozayn_rag_service_shutdown(ozayn_rag_service_t *svc);

/* Subsystem binding */
ozayn_rag_err_t ozayn_rag_set_readiness(ozayn_rag_service_t *svc, void *ptr);
ozayn_rag_err_t ozayn_rag_set_audit(ozayn_rag_service_t *svc, void *ptr);
ozayn_rag_err_t ozayn_rag_set_safety(ozayn_rag_service_t *svc, void *ptr);
ozayn_rag_err_t ozayn_rag_set_resource_manager(ozayn_rag_service_t *svc, void *ptr);
ozayn_rag_err_t ozayn_rag_set_component_registry(ozayn_rag_service_t *svc, void *ptr);
ozayn_rag_err_t ozayn_rag_set_device_session(ozayn_rag_service_t *svc, void *ptr);
ozayn_rag_err_t ozayn_rag_set_operation_queue(ozayn_rag_service_t *svc, void *ptr);
ozayn_rag_err_t ozayn_rag_set_operation_history(ozayn_rag_service_t *svc, void *ptr);
ozayn_rag_err_t ozayn_rag_set_pipeline_scheduler(ozayn_rag_service_t *svc, void *ptr);
ozayn_rag_err_t ozayn_rag_set_workflow_orchestrator(ozayn_rag_service_t *svc, void *ptr);
ozayn_rag_err_t ozayn_rag_set_events_engine(ozayn_rag_service_t *svc, void *ptr);
ozayn_rag_err_t ozayn_rag_set_diagnostics(ozayn_rag_service_t *svc, void *ptr);

/* Admission */
ozayn_rag_err_t ozayn_rag_admit(ozayn_rag_service_t *svc,
    const ozayn_rag_request_t *request, const ozayn_rag_context_t *ctx,
    ozayn_rag_admission_t *out);

/* Quick check */
int ozayn_rag_can_admit(const ozayn_rag_service_t *svc,
    const ozayn_rag_request_t *request, const ozayn_rag_context_t *ctx);

/* Reassessment */
ozayn_rag_err_t ozayn_rag_reassess(ozayn_rag_service_t *svc,
    const char *admission_id, const ozayn_rag_context_t *ctx,
    ozayn_rag_admission_t *out);

/* Invalidation */
ozayn_rag_err_t ozayn_rag_invalidate(ozayn_rag_service_t *svc,
    const char *admission_id);

/* Query */
ozayn_rag_err_t ozayn_rag_get_decision(const ozayn_rag_service_t *svc,
    const char *admission_id, ozayn_rag_admission_t *out);
ozayn_rag_err_t ozayn_rag_get_latest_decision(const ozayn_rag_service_t *svc,
    ozayn_rag_admission_t *out);
int ozayn_rag_decision_count(const ozayn_rag_service_t *svc);
ozayn_rag_err_t ozayn_rag_get_request(const ozayn_rag_service_t *svc,
    const char *request_id, ozayn_rag_request_t *out);
int ozayn_rag_request_count(const ozayn_rag_service_t *svc);

/* Events */
ozayn_rag_err_t ozayn_rag_get_event(const ozayn_rag_service_t *svc,
    int index, ozayn_rag_event_t *out);
int ozayn_rag_event_count(const ozayn_rag_service_t *svc);

/* Stats */
const ozayn_rag_stats_t *ozayn_rag_get_stats(const ozayn_rag_service_t *svc);
ozayn_rag_err_t ozayn_rag_reset_stats(ozayn_rag_service_t *svc);

/* Name helpers */
const char *ozayn_rag_err_name(ozayn_rag_err_t err);
const char *ozayn_rag_decision_name(ozayn_rag_decision_t d);
const char *ozayn_rag_phase_name(ozayn_rag_phase_t p);
const char *ozayn_rag_event_type_name(ozayn_rag_event_type_t t);

#endif /* OZAYN_RUNTIME_ADMISSION_GATE_H */
