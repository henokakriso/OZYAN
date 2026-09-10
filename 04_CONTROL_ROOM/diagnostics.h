/*
 * diagnostics.h — Diagnostics & Health Assessment Foundation
 *
 * Provides structured, bounded diagnostics and health assessment
 * for the OZAYN Control Room. Integrates with Component Registry,
 * Operation History, and existing health infrastructure.
 *
 * Architecture:
 *   CONTROL ROOM → DIAGNOSTIC REQUEST → VALIDATION → TARGET RESOLUTION
 *   → CAPABILITY CHECK → AUTHORIZATION → BOUNDED EXECUTION → RESULT
 *   → HEALTH ASSESSMENT → STATE + EVENT + HISTORY
 *
 * This module does NOT:
 *   - Create a second authorization system
 *   - Execute arbitrary commands
 *   - Perform autonomous remediation
 *   - Bypass existing Section 03 security
 *
 * Step 07/35 — Control Room
 */

#ifndef OZAYN_DIAGNOSTICS_H
#define OZAYN_DIAGNOSTICS_H

#include <stdint.h>
#include <time.h>

/* ============================================================
 * SECTION 1 — LIMITS
 * ============================================================ */

#define OZAYN_DHA_MAX_ID_LEN          64
#define OZAYN_DHA_MAX_TARGET_LEN      64
#define OZAYN_DHA_MAX_CAP_LEN         64
#define OZAYN_DHA_MAX_META_LEN       256
#define OZAYN_DHA_MAX_SESSION_LEN     64
#define OZAYN_DHA_MAX_IDENTITY_LEN    64
#define OZAYN_DHA_MAX_ERROR_LEN      256
#define OZAYN_DHA_MAX_DESC_LEN       256
#define OZAYN_DHA_MAX_PERMISSION_LEN  64
#define OZAYN_DHA_MAX_REQUESTS       128
#define OZAYN_DHA_MAX_RESULTS        128
#define OZAYN_DHA_MAX_FINDINGS       256
#define OZAYN_DHA_MAX_ASSESSMENTS     64
#define OZAYN_DHA_MAX_DEPENDENCIES    16
#define OZAYN_DHA_MAX_EVIDENCE_REFS    8
#define OZAYN_DHA_MAX_RECOMMENDATIONS  4

/* ============================================================
 * SECTION 2 — ERROR CODES
 * ============================================================ */

typedef enum {
    OZAYN_DHA_OK                        =   0,
    OZAYN_DHA_ERR_NULL                  =  -1,
    OZAYN_DHA_ERR_NOT_INITIALIZED       =  -2,
    OZAYN_DHA_ERR_ALREADY_INITIALIZED   =  -3,
    OZAYN_DHA_ERR_INVALID_PARAM         =  -4,
    OZAYN_DHA_ERR_NOT_FOUND             =  -5,
    OZAYN_DHA_ERR_TARGET_NOT_FOUND      =  -6,
    OZAYN_DHA_ERR_CAPABILITY_NOT_FOUND  =  -7,
    OZAYN_DHA_ERR_UNAVAILABLE           =  -8,
    OZAYN_DHA_ERR_UNSUPPORTED           =  -9,
    OZAYN_DHA_ERR_AUTHORIZATION_FAILED  = -10,
    OZAYN_DHA_ERR_PRECONDITION_FAILED   = -11,
    OZAYN_DHA_ERR_TIMEOUT               = -12,
    OZAYN_DHA_ERR_CANCELLED             = -13,
    OZAYN_DHA_ERR_DEPENDENCY_FAILED     = -14,
    OZAYN_DHA_ERR_DEPENDENCY_CYCLE      = -15,
    OZAYN_DHA_ERR_RESOURCE_LIMIT        = -16,
    OZAYN_DHA_ERR_STORAGE_FAILURE       = -17,
    OZAYN_DHA_ERR_EXECUTION_ERROR       = -18,
    OZAYN_DHA_ERR_CONCURRENCY_LIMIT     = -19,
    OZAYN_DHA_ERR_STATE_INVALID         = -20
} ozayn_dha_err_t;

/* ============================================================
 * SECTION 3 — DIAGNOSTIC CATEGORIES
 * ============================================================ */

typedef enum {
    OZAYN_DHA_CAT_CONNECTIVITY        = 0,
    OZAYN_DHA_CAT_LIFECYCLE           = 1,
    OZAYN_DHA_CAT_CAPABILITY          = 2,
    OZAYN_DHA_CAT_RESOURCE            = 3,
    OZAYN_DHA_CAT_DEPENDENCY          = 4,
    OZAYN_DHA_CAT_CONFIGURATION       = 5,
    OZAYN_DHA_CAT_STORAGE             = 6,
    OZAYN_DHA_CAT_SECURITY_INTEGRATION = 7,
    OZAYN_DHA_CAT_EVENT_SYSTEM        = 8,
    OZAYN_DHA_CAT_OPERATION_SYSTEM    = 9,
    OZAYN_DHA_CAT_COUNT
} ozayn_dha_category_t;

/* ============================================================
 * SECTION 4 — HEALTH STATES
 * ============================================================ */

typedef enum {
    OZAYN_DHA_HEALTH_UNKNOWN      = 0,
    OZAYN_DHA_HEALTH_HEALTHY      = 1,
    OZAYN_DHA_HEALTH_DEGRADED     = 2,
    OZAYN_DHA_HEALTH_UNHEALTHY    = 3,
    OZAYN_DHA_HEALTH_UNAVAILABLE  = 4,
    OZAYN_DHA_HEALTH_COUNT
} ozayn_dha_health_t;

/* ============================================================
 * SECTION 5 — SEVERITY LEVELS
 * ============================================================ */

typedef enum {
    OZAYN_DHA_SEVERITY_INFO       = 0,
    OZAYN_DHA_SEVERITY_LOW        = 1,
    OZAYN_DHA_SEVERITY_MEDIUM     = 2,
    OZAYN_DHA_SEVERITY_HIGH       = 3,
    OZAYN_DHA_SEVERITY_CRITICAL   = 4,
    OZAYN_DHA_SEVERITY_COUNT
} ozayn_dha_severity_t;

/* ============================================================
 * SECTION 6 — RESULT STATES
 * ============================================================ */

typedef enum {
    OZAYN_DHA_RESULT_SUCCEEDED    = 0,
    OZAYN_DHA_RESULT_FAILED       = 1,
    OZAYN_DHA_RESULT_TIMEOUT      = 2,
    OZAYN_DHA_RESULT_REJECTED     = 3,
    OZAYN_DHA_RESULT_UNAVAILABLE  = 4,
    OZAYN_DHA_RESULT_UNSUPPORTED  = 5,
    OZAYN_DHA_RESULT_CANCELLED    = 6,
    OZAYN_DHA_RESULT_COUNT
} ozayn_dha_result_state_t;

/* ============================================================
 * SECTION 7 — FINDING STATUS
 * ============================================================ */

typedef enum {
    OZAYN_DHA_FINDING_OPEN           = 0,
    OZAYN_DHA_FINDING_RESOLVED       = 1,
    OZAYN_DHA_FINDING_ACKNOWLEDGED   = 2,
    OZAYN_DHA_FINDING_INFORMATIONAL  = 3,
    OZAYN_DHA_FINDING_COUNT
} ozayn_dha_finding_status_t;

/* ============================================================
 * SECTION 8 — DIAGNOSTIC EVENT TYPES
 * ============================================================ */

typedef enum {
    OZAYN_DHA_EVENT_REQUESTED       = 0,
    OZAYN_DHA_EVENT_STARTED         = 1,
    OZAYN_DHA_EVENT_SUCCEEDED       = 2,
    OZAYN_DHA_EVENT_FAILED          = 3,
    OZAYN_DHA_EVENT_TIMEOUT         = 4,
    OZAYN_DHA_EVENT_CANCELLED       = 5,
    OZAYN_DHA_EVENT_REJECTED        = 6,
    OZAYN_DHA_EVENT_HEALTH_CHANGED  = 7,
    OZAYN_DHA_EVENT_HEALTH_DEGRADED = 8,
    OZAYN_DHA_EVENT_HEALTH_RECOVERED = 9,
    OZAYN_DHA_EVENT_COUNT
} ozayn_dha_event_type_t;

/* ============================================================
 * SECTION 9 — REQUEST STATES
 * ============================================================ */

typedef enum {
    OZAYN_DHA_REQ_CREATED       = 0,
    OZAYN_DHA_REQ_VALIDATING    = 1,
    OZAYN_DHA_REQ_RESOLVING     = 2,
    OZAYN_DHA_REQ_CHECKING      = 3,
    OZAYN_DHA_REQ_AUTHORIZING   = 4,
    OZAYN_DHA_REQ_EXECUTING     = 5,
    OZAYN_DHA_REQ_COMPLETED     = 6,
    OZAYN_DHA_REQ_FAILED        = 7,
    OZAYN_DHA_REQ_REJECTED      = 8,
    OZAYN_DHA_REQ_CANCELLED     = 9,
    OZAYN_DHA_REQ_TIMEOUT       = 10,
    OZAYN_DHA_REQ_COUNT
} ozayn_dha_req_state_t;

/* ============================================================
 * SECTION 10 — STRUCTURES
 * ============================================================ */

/* Diagnostic Request */
typedef struct {
    char                    request_id[OZAYN_DHA_MAX_ID_LEN];
    uint32_t                version;
    char                    target[OZAYN_DHA_MAX_TARGET_LEN];
    char                    capability[OZAYN_DHA_MAX_CAP_LEN];
    ozayn_dha_category_t   category;
    char                    requester_identity[OZAYN_DHA_MAX_IDENTITY_LEN];
    char                    session_id[OZAYN_DHA_MAX_SESSION_LEN];
    char                    required_permission[OZAYN_DHA_MAX_PERMISSION_LEN];
    time_t                  request_time;
    int                     timeout_ms;
    int                     priority;
    char                    context[OZAYN_DHA_MAX_META_LEN];
    ozayn_dha_req_state_t  state;
    /* Correlation */
    char                    operation_id[OZAYN_DHA_MAX_ID_LEN];
    char                    history_record_id[OZAYN_DHA_MAX_ID_LEN];
    int                     active;
} ozayn_dha_request_t;

/* Diagnostic Finding */
typedef struct {
    char                    finding_id[OZAYN_DHA_MAX_ID_LEN];
    ozayn_dha_category_t   category;
    ozayn_dha_severity_t   severity;
    char                    component_id[OZAYN_DHA_MAX_ID_LEN];
    char                    description[OZAYN_DHA_MAX_DESC_LEN];
    char                    evidence_ref[OZAYN_DHA_MAX_ID_LEN];
    ozayn_dha_finding_status_t status;
    time_t                  created_time;
    int                     active;
} ozayn_dha_finding_t;

/* Diagnostic Result */
typedef struct {
    char                    result_id[OZAYN_DHA_MAX_ID_LEN];
    char                    request_id[OZAYN_DHA_MAX_ID_LEN];
    char                    target[OZAYN_DHA_MAX_TARGET_LEN];
    char                    capability[OZAYN_DHA_MAX_CAP_LEN];
    ozayn_dha_category_t   category;
    ozayn_dha_result_state_t result_state;
    ozayn_dha_health_t     health_state;
    time_t                  start_time;
    time_t                  completion_time;
    int                     duration_ms;
    /* Findings reference range (indices into findings array) */
    int                     finding_start;
    int                     finding_count;
    /* Severity of worst finding */
    ozayn_dha_severity_t   max_severity;
    /* Recommendations */
    char                    recommendations[OZAYN_DHA_MAX_RECOMMENDATIONS][OZAYN_DHA_MAX_DESC_LEN];
    int                     recommendation_count;
    /* Error info */
    int                     error_code;
    char                    error_detail[OZAYN_DHA_MAX_ERROR_LEN];
    /* Safe metadata */
    char                    safe_metadata[OZAYN_DHA_MAX_META_LEN];
    int                     active;
} ozayn_dha_result_t;

/* Health Assessment */
typedef struct {
    char                    assessment_id[OZAYN_DHA_MAX_ID_LEN];
    char                    component_id[OZAYN_DHA_MAX_ID_LEN];
    ozayn_dha_health_t     health_state;
    time_t                  assessment_time;
    char                    diagnostic_source[OZAYN_DHA_MAX_ID_LEN];
    ozayn_dha_severity_t   severity;
    char                    summary[OZAYN_DHA_MAX_DESC_LEN];
    /* Finding reference range */
    int                     finding_start;
    int                     finding_count;
    /* Evidence references */
    char                    evidence_refs[OZAYN_DHA_MAX_EVIDENCE_REFS][OZAYN_DHA_MAX_ID_LEN];
    int                     evidence_count;
    /* Dependency status */
    char                    dep_components[OZAYN_DHA_MAX_DEPENDENCIES][OZAYN_DHA_MAX_ID_LEN];
    ozayn_dha_health_t     dep_health[OZAYN_DHA_MAX_DEPENDENCIES];
    int                     dep_count;
    /* Timing */
    time_t                  last_successful_diagnostic;
    time_t                  last_failed_diagnostic;
    /* Safe metadata */
    char                    safe_metadata[OZAYN_DHA_MAX_META_LEN];
    int                     active;
} ozayn_dha_assessment_t;

/* Diagnostic Statistics */
typedef struct {
    uint64_t                total_requests;
    uint64_t                total_succeeded;
    uint64_t                total_failed;
    uint64_t                total_timeout;
    uint64_t                total_rejected;
    uint64_t                total_cancelled;
    uint64_t                total_unavailable;
    uint64_t                total_unsupported;
    uint64_t                total_authorization_denials;
    uint64_t                total_dependency_failures;
    uint64_t                total_health_changed;
    int                     current_requests;
    int                     current_results;
    int                     current_findings;
    int                     current_assessments;
} ozayn_dha_stats_t;

/* Service Configuration */
typedef struct {
    void                   *component_registry;
    void                   *authorization;
    void                   *audit;
    void                   *event_engine;
    int                     max_concurrent;
    int                     default_timeout_ms;
} ozayn_dha_service_config_t;

/* Service State */
typedef struct {
    int                     initialized;

    /* Requests (ring buffer) */
    ozayn_dha_request_t    requests[OZAYN_DHA_MAX_REQUESTS];
    int                     request_head;
    int                     request_count;
    uint32_t                request_sequence;

    /* Results (ring buffer) */
    ozayn_dha_result_t     results[OZAYN_DHA_MAX_RESULTS];
    int                     result_head;
    int                     result_count;
    uint32_t                result_sequence;

    /* Findings (ring buffer) */
    ozayn_dha_finding_t    findings[OZAYN_DHA_MAX_FINDINGS];
    int                     finding_head;
    int                     finding_count;
    uint32_t                finding_sequence;

    /* Health Assessments (ring buffer) */
    ozayn_dha_assessment_t assessments[OZAYN_DHA_MAX_ASSESSMENTS];
    int                     assessment_head;
    int                     assessment_count;
    uint32_t                assessment_sequence;

    /* Concurrency */
    int                     active_diagnostics;
    int                     max_concurrent;
    int                     default_timeout_ms;

    /* Dependencies (not owned) */
    void                   *component_registry;
    void                   *authorization;
    void                   *audit;
    void                   *event_engine;

    /* Statistics */
    ozayn_dha_stats_t      stats;
} ozayn_dha_service_t;

/* ============================================================
 * SECTION 11 — NAME HELPERS
 * ============================================================ */

const char *ozayn_dha_err_name(ozayn_dha_err_t err);
const char *ozayn_dha_category_name(ozayn_dha_category_t cat);
const char *ozayn_dha_health_name(ozayn_dha_health_t health);
const char *ozayn_dha_severity_name(ozayn_dha_severity_t sev);
const char *ozayn_dha_result_state_name(ozayn_dha_result_state_t state);
const char *ozayn_dha_finding_status_name(ozayn_dha_finding_status_t status);
const char *ozayn_dha_event_type_name(ozayn_dha_event_type_t type);
const char *ozayn_dha_req_state_name(ozayn_dha_req_state_t state);

/* ============================================================
 * SECTION 12 — LIFECYCLE
 * ============================================================ */

ozayn_dha_err_t ozayn_dha_service_init(
    ozayn_dha_service_t *svc,
    const ozayn_dha_service_config_t *cfg);

void ozayn_dha_service_shutdown(ozayn_dha_service_t *svc);
int  ozayn_dha_service_is_initialized(const ozayn_dha_service_t *svc);

/* ============================================================
 * SECTION 13 — REQUEST MANAGEMENT
 * ============================================================ */

ozayn_dha_err_t ozayn_dha_request_create(
    ozayn_dha_service_t *svc,
    const char *target,
    const char *capability,
    ozayn_dha_category_t category,
    const char *requester_identity,
    const char *session_id,
    const char *required_permission,
    int timeout_ms,
    int priority,
    const char *context,
    ozayn_dha_request_t **out_request);

ozayn_dha_err_t ozayn_dha_request_advance(
    ozayn_dha_service_t *svc,
    const char *request_id,
    ozayn_dha_req_state_t new_state);

ozayn_dha_err_t ozayn_dha_request_complete(
    ozayn_dha_service_t *svc,
    const char *request_id);

ozayn_dha_err_t ozayn_dha_request_fail(
    ozayn_dha_service_t *svc,
    const char *request_id,
    int error_code,
    const char *error_detail);

ozayn_dha_err_t ozayn_dha_request_cancel(
    ozayn_dha_service_t *svc,
    const char *request_id);

/* ============================================================
 * SECTION 14 — RESULT MANAGEMENT
 * ============================================================ */

ozayn_dha_err_t ozayn_dha_result_create(
    ozayn_dha_service_t *svc,
    const char *request_id,
    const char *target,
    const char *capability,
    ozayn_dha_category_t category,
    ozayn_dha_result_state_t result_state,
    ozayn_dha_health_t health_state,
    int error_code,
    const char *error_detail,
    ozayn_dha_result_t **out_result);

/* ============================================================
 * SECTION 15 — FINDING MANAGEMENT
 * ============================================================ */

ozayn_dha_err_t ozayn_dha_finding_create(
    ozayn_dha_service_t *svc,
    ozayn_dha_category_t category,
    ozayn_dha_severity_t severity,
    const char *component_id,
    const char *description,
    const char *evidence_ref,
    ozayn_dha_finding_t **out_finding);

ozayn_dha_err_t ozayn_dha_finding_update_status(
    ozayn_dha_service_t *svc,
    const char *finding_id,
    ozayn_dha_finding_status_t new_status);

/* ============================================================
 * SECTION 16 — HEALTH ASSESSMENT
 * ============================================================ */

ozayn_dha_err_t ozayn_dha_assess_health(
    ozayn_dha_service_t *svc,
    const char *component_id,
    const char *diagnostic_source,
    ozayn_dha_health_t health_state,
    ozayn_dha_severity_t severity,
    const char *summary,
    ozayn_dha_assessment_t **out_assessment);

/* ============================================================
 * SECTION 17 — QUERY
 * ============================================================ */

const ozayn_dha_request_t *ozayn_dha_request_get(
    const ozayn_dha_service_t *svc,
    const char *request_id);

const ozayn_dha_result_t *ozayn_dha_result_get(
    const ozayn_dha_service_t *svc,
    const char *result_id);

const ozayn_dha_finding_t *ozayn_dha_finding_get(
    const ozayn_dha_service_t *svc,
    const char *finding_id);

const ozayn_dha_assessment_t *ozayn_dha_assessment_get(
    const ozayn_dha_service_t *svc,
    const char *assessment_id);

const ozayn_dha_assessment_t *ozayn_dha_assessment_get_by_component(
    const ozayn_dha_service_t *svc,
    const char *component_id);

int ozayn_dha_request_count(const ozayn_dha_service_t *svc);
int ozayn_dha_result_count(const ozayn_dha_service_t *svc);
int ozayn_dha_finding_count(const ozayn_dha_service_t *svc);
int ozayn_dha_assessment_count(const ozayn_dha_service_t *svc);

/* ============================================================
 * SECTION 18 — STATISTICS
 * ============================================================ */

ozayn_dha_err_t ozayn_dha_get_stats(
    const ozayn_dha_service_t *svc,
    ozayn_dha_stats_t *out_stats);

/* ============================================================
 * SECTION 19 — EVENT INTEGRATION
 * ============================================================ */

ozayn_dha_err_t ozayn_dha_emit_event(
    ozayn_dha_service_t *svc,
    ozayn_dha_event_type_t event_type,
    const char *reference_id,
    const char *detail);

/* ============================================================
 * SECTION 20 — AUDIT INTEGRATION
 * ============================================================ */

ozayn_dha_err_t ozayn_dha_audit(
    ozayn_dha_service_t *svc,
    const char *reference_id,
    const char *event_type,
    const char *detail);

/* ============================================================
 * SECTION 21 — VALIDATION
 * ============================================================ */

int ozayn_dha_request_validate(const ozayn_dha_request_t *req);
int ozayn_dha_result_validate(const ozayn_dha_result_t *result);
int ozayn_dha_assessment_validate(const ozayn_dha_assessment_t *assess);
int ozayn_dha_health_is_terminal(ozayn_dha_health_t health);

/* ============================================================
 * SECTION 22 — CLEANUP
 * ============================================================ */

int ozayn_dha_cleanup_results(ozayn_dha_service_t *svc);
int ozayn_dha_cleanup_findings(ozayn_dha_service_t *svc);
int ozayn_dha_cleanup_all(ozayn_dha_service_t *svc);

/* ============================================================
 * SECTION 23 — GLOBAL ACCESSOR
 * ============================================================ */

ozayn_dha_service_t *ozayn_dha_get_global(void);

#endif /* OZAYN_DIAGNOSTICS_H */
