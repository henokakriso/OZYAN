/*
 * sec_detect.h — Security Event Correlation & Threat Detection Foundation (Step 31).
 *
 * Consumes security events from audit, health, diagnostics, incident response,
 * alerting, authentication, MFA, sessions, authorization, RBAC, permissions,
 * key management, vault, backup, and deletion.
 *
 * Answers: "Do multiple security events together form a recognizable
 *           suspicious or dangerous pattern?"
 *
 * Detection is DETERMINISTIC (no AI/ML). Detection informs enforcement
 * but does NOT replace enforcement.
 */

#ifndef OZAYN_SEC_DETECT_H
#define OZAYN_SEC_DETECT_H

#include "audit.h"
#include "sec_alert.h"
#include "sec_health.h"
#include "sec_diag.h"
#include "incident.h"
#include <stdint.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================
 * SECTION 1 — ERROR CODES
 * ============================================================ */

typedef enum {
    OZAYN_SDET_OK                          =   0,
    OZAYN_SDET_ERR_NULL                    =  -1,
    OZAYN_SDET_ERR_NOT_INITIALIZED         =  -2,
    OZAYN_SDET_ERR_ALREADY_INITIALIZED     =  -3,
    OZAYN_SDET_ERR_INVALID_PARAM           =  -4,
    OZAYN_SDET_ERR_LIMIT_REACHED           =  -5,
    OZAYN_SDET_ERR_NOT_FOUND               =  -6,
    OZAYN_SDET_ERR_STATE_INVALID           =  -7,
    OZAYN_SDET_ERR_STATE_TRANSITION        =  -8,
    OZAYN_SDET_ERR_POLICY_REJECTED         =  -9,
    OZAYN_SDET_ERR_PATTERN_INVALID         = -10,
    OZAYN_SDET_ERR_PATTERN_NOT_FOUND       = -11,
    OZAYN_SDET_ERR_PATTERN_EVALUATION      = -12,
    OZAYN_SDET_ERR_CORRELATION_INVALID     = -13,
    OZAYN_SDET_ERR_CORRELATION_LIMIT       = -14,
    OZAYN_SDET_ERR_FINDING_INVALID         = -15,
    OZAYN_SDET_ERR_FINDING_LIMIT           = -16,
    OZAYN_SDET_ERR_RESOURCE_EXHAUSTED      = -17,
    OZAYN_SDET_ERR_INTEGRITY_FAILURE       = -18,
    OZAYN_SDET_ERR_AUDIT_FAILURE           = -19,
    OZAYN_SDET_ERR_UNAVAILABLE             = -20
} ozayn_sdet_err_t;

/* ============================================================
 * SECTION 2 — NORMALIZED EVENT CATEGORIES
 *
 * Maps from raw audit event types to detection-relevant categories.
 * ============================================================ */

typedef enum {
    OZAYN_SDET_EVT_AUTH_SUCCESS            =  0,
    OZAYN_SDET_EVT_AUTH_FAILURE            =  1,
    OZAYN_SDET_EVT_AUTH_RATE_LIMIT         =  2,
    OZAYN_SDET_EVT_AUTH_BLOCKED            =  3,
    OZAYN_SDET_EVT_MFA_SUCCESS            =  4,
    OZAYN_SDET_EVT_MFA_FAILURE            =  5,
    OZAYN_SDET_EVT_MFA_BLOCKED            =  6,
    OZAYN_SDET_EVT_SESSION_CREATED        =  7,
    OZAYN_SDET_EVT_SESSION_VALIDATED      =  8,
    OZAYN_SDET_EVT_SESSION_FAILED         =  9,
    OZAYN_SDET_EVT_SESSION_TERMINATED     = 10,
    OZAYN_SDET_EVT_AUTHZ_ALLOWED          = 11,
    OZAYN_SDET_EVT_AUTHZ_DENIED           = 12,
    OZAYN_SDET_EVT_PERM_DENIED            = 13,
    OZAYN_SDET_EVT_PERM_MATCHED           = 14,
    OZAYN_SDET_EVT_ROLE_CREATED           = 15,
    OZAYN_SDET_EVT_ROLE_REVOKED           = 16,
    OZAYN_SDET_EVT_ROLE_ASSIGNED          = 17,
    OZAYN_SDET_EVT_ROLE_ASSIGN_REVOKED    = 18,
    OZAYN_SDET_EVT_KEY_CREATED            = 19,
    OZAYN_SDET_EVT_KEY_REVOKED            = 20,
    OZAYN_SDET_EVT_KEY_UNAVAILABLE        = 21,
    OZAYN_SDET_EVT_VAULT_ACCESS           = 22,
    OZAYN_SDET_EVT_VAULT_FAILURE          = 23,
    OZAYN_SDET_EVT_VAULT_INTEGRITY        = 24,
    OZAYN_SDET_EVT_AUDIT_FAILURE          = 25,
    OZAYN_SDET_EVT_AUDIT_INTEGRITY        = 26,
    OZAYN_SDET_EVT_CONFIG_CHANGED         = 27,
    OZAYN_SDET_EVT_CONFIG_REJECTED        = 28,
    OZAYN_SDET_EVT_INTEGRITY_FAILURE      = 29,
    OZAYN_SDET_EVT_HEALTH_DEGRADED        = 30,
    OZAYN_SDET_EVT_HEALTH_CRITICAL        = 31,
    OZAYN_SDET_EVT_COMPONENT_UNAVAILABLE  = 32,
    OZAYN_SDET_EVT_BACKUP_FAILURE         = 33,
    OZAYN_SDET_EVT_DELETION_FAILURE       = 34,
    OZAYN_SDET_EVT_INCIDENT_DETECTED      = 35,
    OZAYN_SDET_EVT_VIOLATION_DETECTED     = 36,
    OZAYN_SDET_EVT_CATEGORY_COUNT
} ozayn_sdet_event_category_t;

/* ============================================================
 * SECTION 3 — CORRELATION STATES
 * ============================================================ */

typedef enum {
    OZAYN_SDET_CORR_NEW                   = 0,
    OZAYN_SDET_CORR_ACTIVE                = 1,
    OZAYN_SDET_CORR_MATCHED               = 2,
    OZAYN_SDET_CORR_SUSPICIOUS            = 3,
    OZAYN_SDET_CORR_CONFIRMED             = 4,
    OZAYN_SDET_CORR_EXPIRED               = 5,
    OZAYN_SDET_CORR_DISMISSED             = 6
} ozayn_sdet_correlation_state_t;

/* ============================================================
 * SECTION 4 — PATTERN TYPES
 * ============================================================ */

typedef enum {
    OZAYN_SDET_PATTERN_SINGLE             = 0,
    OZAYN_SDET_PATTERN_THRESHOLD          = 1,
    OZAYN_SDET_PATTERN_SEQUENCE           = 2,
    OZAYN_SDET_PATTERN_CORRELATED_SEQ     = 3,
    OZAYN_SDET_PATTERN_STATE_TRANSITION   = 4
} ozayn_sdet_pattern_type_t;

/* ============================================================
 * SECTION 5 — DETECTION CONFIDENCE
 * ============================================================ */

typedef enum {
    OZAYN_SDET_CONFIDENCE_LOW             = 0,
    OZAYN_SDET_CONFIDENCE_MEDIUM          = 1,
    OZAYN_SDET_CONFIDENCE_HIGH            = 2,
    OZAYN_SDET_CONFIDENCE_VERY_HIGH       = 3
} ozayn_sdet_confidence_t;

/* ============================================================
 * SECTION 6 — THREAT FINDING STATES
 * ============================================================ */

typedef enum {
    OZAYN_SDET_FINDING_DETECTED           = 0,
    OZAYN_SDET_FINDING_INVESTIGATING      = 1,
    OZAYN_SDET_FINDING_CONFIRMED_THREAT   = 2,
    OZAYN_SDET_FINDING_FALSE_POSITIVE     = 3,
    OZAYN_SDET_FINDING_EXPIRED            = 4,
    OZAYN_SDET_FINDING_INCIDENT_CREATED   = 5,
    OZAYN_SDET_FINDING_ALERT_CREATED      = 6
} ozayn_sdet_finding_state_t;

/* ============================================================
 * SECTION 7 — PATTERN SEVERITY
 * ============================================================ */

typedef enum {
    OZAYN_SDET_SEV_INFO                   = 0,
    OZAYN_SDET_SEV_NOTICE                 = 1,
    OZAYN_SDET_SEV_WARNING                = 2,
    OZAYN_SDET_SEV_HIGH                   = 3,
    OZAYN_SDET_SEV_CRITICAL               = 4
} ozayn_sdet_severity_t;

/* ============================================================
 * SECTION 8 — NORMALIZED EVENT
 * ============================================================ */

#define OZAYN_SDET_MAX_EVENT_ID_LEN      64
#define OZAYN_SDET_MAX_ID_LEN            64
#define OZAYN_SDET_MAX_SOURCE_LEN        64
#define OZAYN_SDET_MAX_CORR_ID_LEN       64
#define OZAYN_SDET_MAX_META_LEN         256

typedef struct {
    char event_id[OZAYN_SDET_MAX_EVENT_ID_LEN];
    ozayn_sdet_event_category_t category;
    time_t timestamp;
    int outcome_success;
    ozayn_sdet_severity_t severity;
    char identity_id[OZAYN_SDET_MAX_ID_LEN];
    char session_id[OZAYN_SDET_MAX_ID_LEN];
    char resource_id[OZAYN_SDET_MAX_ID_LEN];
    char source_component[OZAYN_SDET_MAX_SOURCE_LEN];
    char request_id[OZAYN_SDET_MAX_ID_LEN];
    char correlation_id[OZAYN_SDET_MAX_CORR_ID_LEN];
    char safe_metadata[OZAYN_SDET_MAX_META_LEN];
} ozayn_sdet_event_t;

/* ============================================================
 * SECTION 9 — CORRELATION ENTRY
 * ============================================================ */

typedef struct {
    char corr_id[OZAYN_SDET_MAX_ID_LEN];
    ozayn_sdet_correlation_state_t state;
    time_t first_event_time;
    time_t last_event_time;
    int event_count;
    int matched_count;
    char identity_id[OZAYN_SDET_MAX_ID_LEN];
    char session_id[OZAYN_SDET_MAX_ID_LEN];
    char resource_id[OZAYN_SDET_MAX_ID_LEN];
    int pattern_index;
    int sequence_pos;
    time_t window_start;
} ozayn_sdet_correlation_t;

/* ============================================================
 * SECTION 10 — THREAT PATTERN
 * ============================================================ */

#define OZAYN_SDET_MAX_PATTERN_ID_LEN     64
#define OZAYN_SDET_MAX_PATTERN_NAME_LEN  128
#define OZAYN_SDET_MAX_PATTERN_DESC_LEN  256
#define OZAYN_SDET_MAX_EVENTS_PER_PATTERN 16

typedef struct {
    char pattern_id[OZAYN_SDET_MAX_PATTERN_ID_LEN];
    char name[OZAYN_SDET_MAX_PATTERN_NAME_LEN];
    char description[OZAYN_SDET_MAX_PATTERN_DESC_LEN];
    int enabled;
    uint32_t version;
    ozayn_sdet_pattern_type_t pattern_type;
    int threshold_count;
    int window_seconds;
    ozayn_sdet_severity_t severity;
    ozayn_sdet_confidence_t confidence;
    ozayn_sdet_event_category_t events[OZAYN_SDET_MAX_EVENTS_PER_PATTERN];
    int event_count;
    ozayn_sdet_event_category_t sequence[OZAYN_SDET_MAX_EVENTS_PER_PATTERN];
    int sequence_count;
    int require_identity_match;
    int require_session_match;
    int require_resource_match;
} ozayn_sdet_pattern_t;

/* ============================================================
 * SECTION 11 — THREAT FINDING
 * ============================================================ */

#define OZAYN_SDET_MAX_FINDING_ID_LEN     64
#define OZAYN_SDET_MAX_FINDING_META_LEN  256

typedef struct {
    char finding_id[OZAYN_SDET_MAX_FINDING_ID_LEN];
    uint32_t finding_version;
    char pattern_id[OZAYN_SDET_MAX_PATTERN_ID_LEN];
    uint32_t pattern_version;
    time_t detection_time;
    time_t first_event_time;
    time_t last_event_time;
    ozayn_sdet_severity_t severity;
    ozayn_sdet_confidence_t confidence;
    ozayn_sdet_finding_state_t state;
    char identity_id[OZAYN_SDET_MAX_ID_LEN];
    char session_id[OZAYN_SDET_MAX_ID_LEN];
    char resource_id[OZAYN_SDET_MAX_ID_LEN];
    char correlation_id[OZAYN_SDET_MAX_CORR_ID_LEN];
    int event_count;
    char incident_id[OZAYN_SDET_MAX_ID_LEN];
    char alert_id[OZAYN_SDET_MAX_ID_LEN];
    char safe_metadata[OZAYN_SDET_MAX_FINDING_META_LEN];
} ozayn_sdet_finding_t;

/* ============================================================
 * SECTION 12 — DETECTION POLICY
 * ============================================================ */

typedef struct {
    int enabled;
    int enabled_patterns[64];
    int max_correlation_window_seconds;
    int min_correlation_window_seconds;
    int max_events_per_correlation;
    int max_active_correlations;
    int max_findings;
    int max_findings_per_window;
    int finding_retention_seconds;
    int dedup_window_seconds;
    int threshold_max_count;
    int severity_escalation_enabled;
    int incident_integration_enabled;
    int alert_integration_enabled;
} ozayn_sdet_policy_t;

/* ============================================================
 * SECTION 13 — SERVICE CONFIGURATION
 * ============================================================ */

typedef struct {
    ozayn_salert_service_t *alert_service;
    ozayn_ir_service_t *incident_service;
    ozayn_audit_service_t *audit;
    int max_events;
    int max_correlations;
    int max_findings;
    int max_patterns;
} ozayn_sdet_service_config_t;

/* ============================================================
 * SECTION 14 — SERVICE STATE
 * ============================================================ */

#define OZAYN_SDET_MAX_EVENTS          512
#define OZAYN_SDET_MAX_CORRELATIONS    128
#define OZAYN_SDET_MAX_FINDINGS        256
#define OZAYN_SDET_MAX_PATTERNS         64

typedef struct {
    int initialized;

    /* Normalized events ring buffer */
    ozayn_sdet_event_t events[OZAYN_SDET_MAX_EVENTS];
    int event_head;
    int event_count;
    uint32_t event_sequence;

    /* Correlations */
    ozayn_sdet_correlation_t correlations[OZAYN_SDET_MAX_CORRELATIONS];
    int corr_count;

    /* Built-in + registered patterns */
    ozayn_sdet_pattern_t patterns[OZAYN_SDET_MAX_PATTERNS];
    int pattern_count;

    /* Findings ring buffer */
    ozayn_sdet_finding_t findings[OZAYN_SDET_MAX_FINDINGS];
    int finding_head;
    int finding_count;
    uint32_t finding_sequence;

    /* Policy */
    ozayn_sdet_policy_t policy;

    /* Dependencies */
    ozayn_salert_service_t *alert_service;
    ozayn_ir_service_t *incident_service;
    ozayn_audit_service_t *audit;

    /* Statistics */
    uint64_t total_events_received;
    uint64_t total_events_normalized;
    uint64_t total_correlations_created;
    uint64_t total_correlations_matched;
    uint64_t total_correlations_expired;
    uint64_t total_patterns_evaluated;
    uint64_t total_findings_created;
    uint64_t total_findings_deduplicated;
    uint64_t total_incidents_created;
    uint64_t total_alerts_created;
    uint64_t total_evaluations_failed;
} ozayn_sdet_service_t;

/* ============================================================
 * SECTION 15 — LIFECYCLE
 * ============================================================ */

ozayn_sdet_err_t ozayn_sdet_service_init(
    ozayn_sdet_service_t *svc,
    const ozayn_sdet_service_config_t *cfg);

void ozayn_sdet_service_shutdown(ozayn_sdet_service_t *svc);

int ozayn_sdet_service_is_initialized(const ozayn_sdet_service_t *svc);

/* ============================================================
 * SECTION 16 — STATE / NAME HELPERS
 * ============================================================ */

const char *ozayn_sdet_err_name(ozayn_sdet_err_t err);
const char *ozayn_sdet_event_category_name(ozayn_sdet_event_category_t cat);
const char *ozayn_sdet_correlation_state_name(ozayn_sdet_correlation_state_t s);
const char *ozayn_sdet_pattern_type_name(ozayn_sdet_pattern_type_t t);
const char *ozayn_sdet_confidence_name(ozayn_sdet_confidence_t c);
const char *ozayn_sdet_finding_state_name(ozayn_sdet_finding_state_t s);
const char *ozayn_sdet_severity_name(ozayn_sdet_severity_t sev);

int ozayn_sdet_severity_to_audit_severity(ozayn_sdet_severity_t sev);
int ozayn_sdet_severity_to_salert_severity(ozayn_sdet_severity_t sev);

/* ============================================================
 * SECTION 17 — EVENT PROCESSING
 * ============================================================ */

ozayn_sdet_err_t ozayn_sdet_process_event(
    ozayn_sdet_service_t *svc,
    const ozayn_sdet_event_t *event);

ozayn_sdet_err_t ozayn_sdet_normalize_audit_event(
    const ozayn_audit_event_t *audit_event,
    ozayn_sdet_event_t *out_event);

/* ============================================================
 * SECTION 18 — PATTERN MANAGEMENT
 * ============================================================ */

ozayn_sdet_err_t ozayn_sdet_register_pattern(
    ozayn_sdet_service_t *svc,
    const ozayn_sdet_pattern_t *pattern);

ozayn_sdet_err_t ozayn_sdet_unregister_pattern(
    ozayn_sdet_service_t *svc,
    const char *pattern_id);

const ozayn_sdet_pattern_t *ozayn_sdet_get_pattern(
    const ozayn_sdet_service_t *svc,
    const char *pattern_id);

int ozayn_sdet_pattern_count(const ozayn_sdet_service_t *svc);

ozayn_sdet_err_t ozayn_sdet_enable_pattern(
    ozayn_sdet_service_t *svc,
    const char *pattern_id,
    int enabled);

/* ============================================================
 * SECTION 19 — PATTERN EVALUATION
 * ============================================================ */

ozayn_sdet_err_t ozayn_sdet_evaluate_patterns(
    ozayn_sdet_service_t *svc);

ozayn_sdet_err_t ozayn_sdet_evaluate_single(
    ozayn_sdet_service_t *svc,
    const ozayn_sdet_event_t *event);

ozayn_sdet_err_t ozayn_sdet_evaluate_threshold(
    ozayn_sdet_service_t *svc,
    const ozayn_sdet_pattern_t *pattern);

ozayn_sdet_err_t ozayn_sdet_evaluate_sequence(
    ozayn_sdet_service_t *svc,
    const ozayn_sdet_pattern_t *pattern);

/* ============================================================
 * SECTION 20 — CORRELATION
 * ============================================================ */

ozayn_sdet_err_t ozayn_sdet_create_correlation(
    ozayn_sdet_service_t *svc,
    const ozayn_sdet_event_t *event,
    int pattern_index,
    ozayn_sdet_correlation_t **out_corr);

ozayn_sdet_err_t ozayn_sdet_expire_correlations(
    ozayn_sdet_service_t *svc);

ozayn_sdet_correlation_t *ozayn_sdet_find_correlation(
    ozayn_sdet_service_t *svc,
    const char *identity_id,
    const char *session_id,
    int pattern_index);

int ozayn_sdet_correlation_count(const ozayn_sdet_service_t *svc);

/* ============================================================
 * SECTION 21 — FINDINGS
 * ============================================================ */

ozayn_sdet_err_t ozayn_sdet_create_finding(
    ozayn_sdet_service_t *svc,
    const ozayn_sdet_pattern_t *pattern,
    const ozayn_sdet_correlation_t *corr,
    ozayn_sdet_finding_t **out_finding);

ozayn_sdet_finding_t *ozayn_sdet_get_finding(
    ozayn_sdet_service_t *svc,
    const char *finding_id);

int ozayn_sdet_finding_count(const ozayn_sdet_service_t *svc);

int ozayn_sdet_list_findings(
    const ozayn_sdet_service_t *svc,
    int filter_state,
    ozayn_sdet_finding_t **out_findings,
    int max_count);

ozayn_sdet_err_t ozayn_sdet_finding_set_state(
    ozayn_sdet_service_t *svc,
    const char *finding_id,
    ozayn_sdet_finding_state_t new_state);

int ozayn_sdet_cleanup_expired_findings(ozayn_sdet_service_t *svc);

/* ============================================================
 * SECTION 22 — DEDUPLICATION
 * ============================================================ */

int ozayn_sdet_finding_is_duplicate(
    const ozayn_sdet_service_t *svc,
    const char *pattern_id,
    const char *identity_id,
    const char *resource_id);

/* ============================================================
 * SECTION 23 — DETECTION POLICY
 * ============================================================ */

ozayn_sdet_policy_t ozayn_sdet_default_policy(void);

ozayn_sdet_err_t ozayn_sdet_set_policy(
    ozayn_sdet_service_t *svc,
    const ozayn_sdet_policy_t *policy);

const ozayn_sdet_policy_t *ozayn_sdet_get_policy(
    const ozayn_sdet_service_t *svc);

/* ============================================================
 * SECTION 24 — INTEGRATION: INCIDENT RESPONSE
 * ============================================================ */

ozayn_sdet_err_t ozayn_sdet_create_incident_from_finding(
    ozayn_sdet_service_t *svc,
    ozayn_sdet_finding_t *finding);

/* ============================================================
 * SECTION 25 — INTEGRATION: ALERTING
 * ============================================================ */

ozayn_sdet_err_t ozayn_sdet_create_alert_from_finding(
    ozayn_sdet_service_t *svc,
    ozayn_sdet_finding_t *finding);

/* ============================================================
 * SECTION 26 — INTEGRATION: AUDIT
 * ============================================================ */

ozayn_sdet_err_t ozayn_sdet_audit_event(
    ozayn_sdet_service_t *svc,
    const char *event_type,
    const char *detail);

/* ============================================================
 * SECTION 27 — QUERY
 * ============================================================ */

int ozayn_sdet_event_count(const ozayn_sdet_service_t *svc);

int ozayn_sdet_list_events(
    const ozayn_sdet_service_t *svc,
    int filter_category,
    ozayn_sdet_event_t **out_events,
    int max_count);

/* ============================================================
 * SECTION 28 — RESOURCE SAFETY
 * ============================================================ */

int ozayn_sdet_events_full(const ozayn_sdet_service_t *svc);
int ozayn_sdet_correlations_full(const ozayn_sdet_service_t *svc);
int ozayn_sdet_findings_full(const ozayn_sdet_service_t *svc);
int ozayn_sdet_patterns_full(const ozayn_sdet_service_t *svc);

/* ============================================================
 * SECTION 29 — GLOBAL ACCESSOR
 * ============================================================ */

ozayn_sdet_service_t *ozayn_sdet_get_global(void);

#ifdef __cplusplus
}
#endif

#endif /* OZAYN_SEC_DETECT_H */
