/*
 * sec_intel.h — Security Threat Intelligence & Evidence Analysis Foundation (Step 32).
 *
 * Answers: "What evidence do we have, how reliable is it, what does it
 *           indicate, and how should it be presented to the existing
 *           incident-response system?"
 *
 * Deterministic, explainable, auditable, bounded, fail-safe.
 * No AI/ML, no external threat feeds, no authorization bypass.
 */

#ifndef OZAYN_SEC_INTEL_H
#define OZAYN_SEC_INTEL_H

#include "audit.h"
#include "sec_detect.h"
#include "sec_alert.h"
#include "sec_notify.h"
#include "sec_health.h"
#include "sec_diag.h"
#include "incident.h"
#include "sec_config.h"
#include <stdint.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================
 * SECTION 1 — ERROR CODES
 * ============================================================ */

typedef enum {
    OZAYN_SINTEL_OK                          =   0,
    OZAYN_SINTEL_ERR_NULL                    =  -1,
    OZAYN_SINTEL_ERR_NOT_INITIALIZED         =  -2,
    OZAYN_SINTEL_ERR_ALREADY_INITIALIZED     =  -3,
    OZAYN_SINTEL_ERR_INVALID_PARAM           =  -4,
    OZAYN_SINTEL_ERR_LIMIT_REACHED           =  -5,
    OZAYN_SINTEL_ERR_NOT_FOUND               =  -6,
    OZAYN_SINTEL_ERR_STATE_INVALID           =  -7,
    OZAYN_SINTEL_ERR_STATE_TRANSITION        =  -8,
    OZAYN_SINTEL_ERR_POLICY_REJECTED         =  -9,
    OZAYN_SINTEL_ERR_INTEGRITY_FAILURE       = -10,
    OZAYN_SINTEL_ERR_EVIDENCE_INVALID        = -11,
    OZAYN_SINTEL_ERR_EVIDENCE_EXPIRED        = -12,
    OZAYN_SINTEL_ERR_EVIDENCE_REVOKED        = -13,
    OZAYN_SINTEL_ERR_SET_INVALID             = -14,
    OZAYN_SINTEL_ERR_SET_LIMIT               = -15,
    OZAYN_SINTEL_ERR_ASSESSMENT_INVALID      = -16,
    OZAYN_SINTEL_ERR_ASSESSMENT_LIMIT        = -17,
    OZAYN_SINTEL_ERR_RESOURCE_EXHAUSTED      = -18,
    OZAYN_SINTEL_ERR_UNAVAILABLE             = -19
} ozayn_sintel_err_t;

/* ============================================================
 * SECTION 2 — EVIDENCE TYPES
 * ============================================================ */

typedef enum {
    OZAYN_SINTEL_EVID_AUDIT_EVENT            =  0,
    OZAYN_SINTEL_EVID_AUDIT_INTEGRITY        =  1,
    OZAYN_SINTEL_EVID_HEALTH_RESULT          =  2,
    OZAYN_SINTEL_EVID_DIAGNOSTIC_RESULT      =  3,
    OZAYN_SINTEL_EVID_CORRELATION_RESULT     =  4,
    OZAYN_SINTEL_EVID_THREAT_FINDING         =  5,
    OZAYN_SINTEL_EVID_AUTH_RESULT            =  6,
    OZAYN_SINTEL_EVID_MFA_RESULT             =  7,
    OZAYN_SINTEL_EVID_SESSION_RESULT         =  8,
    OZAYN_SINTEL_EVID_AUTHZ_RESULT           =  9,
    OZAYN_SINTEL_EVID_RBAC_RESULT            = 10,
    OZAYN_SINTEL_EVID_PERMISSION_RESULT      = 11,
    OZAYN_SINTEL_EVID_KEY_SECURITY           = 12,
    OZAYN_SINTEL_EVID_VAULT_SECURITY         = 13,
    OZAYN_SINTEL_EVID_BACKUP_SECURITY        = 14,
    OZAYN_SINTEL_EVID_DELETION_SECURITY      = 15,
    OZAYN_SINTEL_EVID_CONFIG_SECURITY        = 16,
    OZAYN_SINTEL_EVID_INCIDENT_RESULT        = 17,
    OZAYN_SINTEL_EVID_TYPE_COUNT
} ozayn_sintel_evidence_type_t;

/* ============================================================
 * SECTION 3 — EVIDENCE RELIABILITY
 * ============================================================ */

typedef enum {
    OZAYN_SINTEL_RELIABILITY_UNKNOWN         = 0,
    OZAYN_SINTEL_RELIABILITY_LOW             = 1,
    OZAYN_SINTEL_RELIABILITY_MEDIUM          = 2,
    OZAYN_SINTEL_RELIABILITY_HIGH            = 3,
    OZAYN_SINTEL_RELIABILITY_VERIFIED        = 4
} ozayn_sintel_reliability_t;

/* ============================================================
 * SECTION 4 — EVIDENCE RELEVANCE
 * ============================================================ */

typedef enum {
    OZAYN_SINTEL_RELEVANCE_IRRELEVANT        = 0,
    OZAYN_SINTEL_RELEVANCE_LOW               = 1,
    OZAYN_SINTEL_RELEVANCE_MEDIUM            = 2,
    OZAYN_SINTEL_RELEVANCE_HIGH              = 3,
    OZAYN_SINTEL_RELEVANCE_CRITICAL          = 4
} ozayn_sintel_relevance_t;

/* ============================================================
 * SECTION 5 — EVIDENCE STATUS
 * ============================================================ */

typedef enum {
    OZAYN_SINTEL_EVID_STATUS_UNVERIFIED      = 0,
    OZAYN_SINTEL_EVID_STATUS_VALIDATING      = 1,
    OZAYN_SINTEL_EVID_STATUS_VALID           = 2,
    OZAYN_SINTEL_EVID_STATUS_INVALID         = 3,
    OZAYN_SINTEL_EVID_STATUS_SUPERSEDED      = 4,
    OZAYN_SINTEL_EVID_STATUS_EXPIRED         = 5,
    OZAYN_SINTEL_EVID_STATUS_REVOKED         = 6
} ozayn_sintel_evidence_status_t;

/* ============================================================
 * SECTION 6 — EVIDENCE CLASSIFICATION (reuse existing)
 * ============================================================ */

typedef enum {
    OZAYN_SINTEL_CLASS_PUBLIC                = 0,
    OZAYN_SINTEL_CLASS_INTERNAL              = 1,
    OZAYN_SINTEL_CLASS_SENSITIVE             = 2,
    OZAYN_SINTEL_CLASS_HIGHLY_SENSITIVE      = 3
} ozayn_sintel_classification_t;

/* ============================================================
 * SECTION 7 — INTEGRITY STATE (reuse existing)
 * ============================================================ */

typedef enum {
    OZAYN_SINTEL_INTEGRITY_UNKNOWN           = 0,
    OZAYN_SINTEL_INTEGRITY_VALID             = 1,
    OZAYN_SINTEL_INTEGRITY_INVALID           = 2,
    OZAYN_SINTEL_INTEGRITY_UNAVAILABLE       = 3
} ozayn_sintel_integrity_state_t;

/* ============================================================
 * SECTION 8 — EVIDENCE ROLE
 * ============================================================ */

typedef enum {
    OZAYN_SINTEL_ROLE_PRIMARY                = 0,
    OZAYN_SINTEL_ROLE_SUPPORTING             = 1,
    OZAYN_SINTEL_ROLE_CONFLICTING            = 2,
    OZAYN_SINTEL_ROLE_CONTEXTUAL             = 3
} ozayn_sintel_evidence_role_t;

/* ============================================================
 * SECTION 9 — THREAT CATEGORIES
 * ============================================================ */

typedef enum {
    OZAYN_SINTEL_THREAT_AUTH                 =  0,
    OZAYN_SINTEL_THREAT_CREDENTIAL           =  1,
    OZAYN_SINTEL_THREAT_SESSION              =  2,
    OZAYN_SINTEL_THREAT_AUTHORIZATION        =  3,
    OZAYN_SINTEL_THREAT_PRIVILEGE_ESCALATION =  4,
    OZAYN_SINTEL_THREAT_ROLE_TAMPERING       =  5,
    OZAYN_SINTEL_THREAT_PERMISSION_TAMPERING =  6,
    OZAYN_SINTEL_THREAT_KEY_SECURITY         =  7,
    OZAYN_SINTEL_THREAT_VAULT_SECURITY       =  8,
    OZAYN_SINTEL_THREAT_DATA_INTEGRITY       =  9,
    OZAYN_SINTEL_THREAT_AUDIT_INTEGRITY      = 10,
    OZAYN_SINTEL_THREAT_BACKUP_SECURITY      = 11,
    OZAYN_SINTEL_THREAT_DELETION_SECURITY    = 12,
    OZAYN_SINTEL_THREAT_CONFIG               = 13,
    OZAYN_SINTEL_THREAT_COMPONENT_FAILURE    = 14,
    OZAYN_SINTEL_THREAT_UNKNOWN              = 15
} ozayn_sintel_threat_category_t;

/* ============================================================
 * SECTION 10 — IMPACT CATEGORY
 * ============================================================ */

typedef enum {
    OZAYN_SINTEL_IMPACT_NONE                 = 0,
    OZAYN_SINTEL_IMPACT_LOW                  = 1,
    OZAYN_SINTEL_IMPACT_MODERATE             = 2,
    OZAYN_SINTEL_IMPACT_HIGH                 = 3,
    OZAYN_SINTEL_IMPACT_CRITICAL             = 4
} ozayn_sintel_impact_t;

/* ============================================================
 * SECTION 11 — ASSESSMENT STATES
 * ============================================================ */

typedef enum {
    OZAYN_SINTEL_ASSESS_PENDING              = 0,
    OZAYN_SINTEL_ASSESS_ASSESSING            = 1,
    OZAYN_SINTEL_ASSESS_ASSESSED             = 2,
    OZAYN_SINTEL_ASSESS_ESCALATED            = 3,
    OZAYN_SINTEL_ASSESS_DISPUTED             = 4,
    OZAYN_SINTEL_ASSESS_INVALID              = 5,
    OZAYN_SINTEL_ASSESS_EXPIRED              = 6
} ozayn_sintel_assessment_state_t;

/* ============================================================
 * SECTION 12 — CONFIDENCE (deterministic, rule-derived)
 * ============================================================ */

typedef enum {
    OZAYN_SINTEL_CONFIDENCE_LOW              = 0,
    OZAYN_SINTEL_CONFIDENCE_MEDIUM           = 1,
    OZAYN_SINTEL_CONFIDENCE_HIGH             = 2,
    OZAYN_SINTEL_CONFIDENCE_VERY_HIGH        = 3
} ozayn_sintel_confidence_t;

/* ============================================================
 * SECTION 13 — SEVERITY (reuse existing hierarchy)
 * ============================================================ */

typedef enum {
    OZAYN_SINTEL_SEV_INFO                    = 0,
    OZAYN_SINTEL_SEV_NOTICE                  = 1,
    OZAYN_SINTEL_SEV_WARNING                 = 2,
    OZAYN_SINTEL_SEV_HIGH                    = 3,
    OZAYN_SINTEL_SEV_CRITICAL                = 4
} ozayn_sintel_severity_t;

/* ============================================================
 * SECTION 14 — RECOMMENDED RESPONSE
 * ============================================================ */

typedef enum {
    OZAYN_SINTEL_RESPONSE_NONE               =  0,
    OZAYN_SINTEL_RESPONSE_MONITOR            =  1,
    OZAYN_SINTEL_RESPONSE_INVESTIGATE        =  2,
    OZAYN_SINTEL_RESPONSE_ESCALATE_INCIDENT  =  3,
    OZAYN_SINTEL_RESPONSE_REQUIRE_REAUTH     =  4,
    OZAYN_SINTEL_RESPONSE_REQUIRE_MFA        =  5,
    OZAYN_SINTEL_RESPONSE_REVOKE_SESSION     =  6,
    OZAYN_SINTEL_RESPONSE_SUSPEND_IDENTITY   =  7,
    OZAYN_SINTEL_RESPONSE_REVIEW_PERMISSION  =  8,
    OZAYN_SINTEL_RESPONSE_REVIEW_ROLE        =  9,
    OZAYN_SINTEL_RESPONSE_REVIEW_KEY_STATE   = 10,
    OZAYN_SINTEL_RESPONSE_SECURITY_LOCKDOWN  = 11
} ozayn_sintel_recommended_response_t;

/* ============================================================
 * SECTION 15 — EVIDENCE MODEL
 * ============================================================ */

#define OZAYN_SINTEL_MAX_ID_LEN            64
#define OZAYN_SINTEL_MAX_SOURCE_LEN        64
#define OZAYN_SINTEL_MAX_META_LEN         256

typedef struct {
    /* Identity */
    char evidence_id[OZAYN_SINTEL_MAX_ID_LEN];
    uint32_t evidence_version;
    ozayn_sintel_evidence_type_t evidence_type;

    /* Source */
    char source_component[OZAYN_SINTEL_MAX_SOURCE_LEN];
    char source_event_id[OZAYN_SINTEL_MAX_ID_LEN];
    char finding_id[OZAYN_SINTEL_MAX_ID_LEN];
    char correlation_id[OZAYN_SINTEL_MAX_ID_LEN];
    char incident_id[OZAYN_SINTEL_MAX_ID_LEN];

    /* Timing */
    time_t timestamp;
    time_t observation_window_start;
    time_t observation_window_end;

    /* Quality */
    ozayn_sintel_reliability_t reliability;
    ozayn_sintel_relevance_t relevance;
    ozayn_sintel_severity_t severity;
    ozayn_sintel_classification_t classification;
    ozayn_sintel_integrity_state_t integrity_state;
    ozayn_sintel_evidence_status_t status;

    /* Context */
    char identity_id[OZAYN_SINTEL_MAX_ID_LEN];
    char session_id[OZAYN_SINTEL_MAX_ID_LEN];
    char resource_id[OZAYN_SINTEL_MAX_ID_LEN];

    /* Safe metadata */
    char safe_metadata[OZAYN_SINTEL_MAX_META_LEN];
} ozayn_sintel_evidence_t;

/* ============================================================
 * SECTION 16 — EVIDENCE SET
 * ============================================================ */

#define OZAYN_SINTEL_MAX_EVIDENCE_PER_SET  32

typedef struct {
    char set_id[OZAYN_SINTEL_MAX_ID_LEN];
    char finding_id[OZAYN_SINTEL_MAX_ID_LEN];
    char incident_id[OZAYN_SINTEL_MAX_ID_LEN];
    char correlation_id[OZAYN_SINTEL_MAX_ID_LEN];

    time_t first_observation;
    time_t last_observation;
    int evidence_count;

    /* Evidence references by role */
    int primary_count;
    int supporting_count;
    int conflicting_count;
    int contextual_count;

    /* Summaries */
    ozayn_sintel_reliability_t reliability_summary;
    ozayn_sintel_relevance_t relevance_summary;
    ozayn_sintel_assessment_state_t assessment_state;

    char safe_metadata[OZAYN_SINTEL_MAX_META_LEN];
} ozayn_sintel_evidence_set_t;

/* ============================================================
 * SECTION 17 — EXPLANATION CODE
 * ============================================================ */

#define OZAYN_SINTEL_MAX_EXPLANATIONS       16

typedef enum {
    OZAYN_SINTEL_EXPLAIN_NONE                       =  0,
    OZAYN_SINTEL_EXPLAIN_MULTIPLE_AUTH_FAILURES     =  1,
    OZAYN_SINTEL_EXPLAIN_RATE_LIMIT_TRIGGERED       =  2,
    OZAYN_SINTEL_EXPLAIN_SENSITIVE_RESOURCE_TARGETED=  3,
    OZAYN_SINTEL_EXPLAIN_PRIVILEGE_CHANGE_ATTEMPT   =  4,
    OZAYN_SINTEL_EXPLAIN_AUDIT_INTEGRITY_FAILED     =  5,
    OZAYN_SINTEL_EXPLAIN_KEY_UNAVAILABLE            =  6,
    OZAYN_SINTEL_EXPLAIN_VAULT_INTEGRITY_FAILED     =  7,
    OZAYN_SINTEL_EXPLAIN_SESSION_ANOMALY            =  8,
    OZAYN_SINTEL_EXPLAIN_MFA_FAILURE                =  9,
    OZAYN_SINTEL_EXPLAIN_ROLE_TAMPERING             = 10,
    OZAYN_SINTEL_EXPLAIN_PERMISSION_DENIED           = 11,
    OZAYN_SINTEL_EXPLAIN_HEALTH_DEGRADED            = 12,
    OZAYN_SINTEL_EXPLAIN_COMPONENT_UNAVAILABLE      = 13,
    OZAYN_SINTEL_EXPLAIN_BACKUP_INTEGRITY_FAILED    = 14,
    OZAYN_SINTEL_EXPLAIN_CONFIG_VIOLATION           = 15
} ozayn_sintel_explanation_code_t;

/* ============================================================
 * SECTION 18 — THREAT ASSESSMENT
 * ============================================================ */

typedef struct {
    char assessment_id[OZAYN_SINTEL_MAX_ID_LEN];
    uint32_t assessment_version;
    char finding_id[OZAYN_SINTEL_MAX_ID_LEN];
    char evidence_set_id[OZAYN_SINTEL_MAX_ID_LEN];

    ozayn_sintel_assessment_state_t state;
    ozayn_sintel_severity_t severity;
    ozayn_sintel_confidence_t confidence;
    ozayn_sintel_reliability_t reliability;
    ozayn_sintel_impact_t impact;
    ozayn_sintel_threat_category_t threat_category;

    char affected_component[OZAYN_SINTEL_MAX_SOURCE_LEN];
    ozayn_sintel_recommended_response_t recommended_response;

    /* Explanation codes */
    int explanation_count;
    ozayn_sintel_explanation_code_t explanations[OZAYN_SINTEL_MAX_EXPLANATIONS];

    time_t created_time;
    time_t updated_time;

    char safe_metadata[OZAYN_SINTEL_MAX_META_LEN];
} ozayn_sintel_assessment_t;

/* ============================================================
 * SECTION 19 — INTEL POLICY
 * ============================================================ */

typedef struct {
    int enabled;
    int max_evidence;
    int max_evidence_sets;
    int max_assessments;
    int evidence_retention_seconds;
    int dedup_window_seconds;
    int min_reliability_for_assessment;
    int min_evidence_for_assessment;
    int incident_integration_enabled;
    int alert_integration_enabled;
} ozayn_sintel_policy_t;

/* ============================================================
 * SECTION 20 — SERVICE CONFIGURATION
 * ============================================================ */

typedef struct {
    ozayn_sdet_service_t *detect_service;
    ozayn_ir_service_t *incident_service;
    ozayn_salert_service_t *alert_service;
    ozayn_audit_service_t *audit;
} ozayn_sintel_service_config_t;

/* ============================================================
 * SECTION 21 — SERVICE STATE
 * ============================================================ */

#define OZAYN_SINTEL_MAX_EVIDENCE           512
#define OZAYN_SINTEL_MAX_EVIDENCE_SETS      64
#define OZAYN_SINTEL_MAX_ASSESSMENTS        128

typedef struct {
    int initialized;

    /* Evidence ring buffer */
    ozayn_sintel_evidence_t evidence[OZAYN_SINTEL_MAX_EVIDENCE];
    int evidence_head;
    int evidence_count;
    uint32_t evidence_sequence;

    /* Evidence sets */
    ozayn_sintel_evidence_set_t evidence_sets[OZAYN_SINTEL_MAX_EVIDENCE_SETS];
    int set_count;

    /* Assessments ring buffer */
    ozayn_sintel_assessment_t assessments[OZAYN_SINTEL_MAX_ASSESSMENTS];
    int assessment_head;
    int assessment_count;
    uint32_t assessment_sequence;

    /* Policy */
    ozayn_sintel_policy_t policy;

    /* Dependencies */
    ozayn_sdet_service_t *detect_service;
    ozayn_ir_service_t *incident_service;
    ozayn_salert_service_t *alert_service;
    ozayn_audit_service_t *audit;

    /* Statistics */
    uint64_t total_evidence_collected;
    uint64_t total_evidence_validated;
    uint64_t total_evidence_rejected;
    uint64_t total_evidence_expired;
    uint64_t total_sets_created;
    uint64_t total_assessments_created;
    uint64_t total_assessments_completed;
    uint64_t total_assessments_escalated;
    uint64_t total_incidents_created;
    uint64_t total_alerts_created;
} ozayn_sintel_service_t;

/* ============================================================
 * SECTION 22 — LIFECYCLE
 * ============================================================ */

ozayn_sintel_err_t ozayn_sintel_service_init(
    ozayn_sintel_service_t *svc,
    const ozayn_sintel_service_config_t *cfg);

void ozayn_sintel_service_shutdown(ozayn_sintel_service_t *svc);

int ozayn_sintel_service_is_initialized(const ozayn_sintel_service_t *svc);

/* ============================================================
 * SECTION 23 — NAME HELPERS
 * ============================================================ */

const char *ozayn_sintel_err_name(ozayn_sintel_err_t err);
const char *ozayn_sintel_evidence_type_name(ozayn_sintel_evidence_type_t t);
const char *ozayn_sintel_reliability_name(ozayn_sintel_reliability_t r);
const char *ozayn_sintel_relevance_name(ozayn_sintel_relevance_t r);
const char *ozayn_sintel_evidence_status_name(ozayn_sintel_evidence_status_t s);
const char *ozayn_sintel_classification_name(ozayn_sintel_classification_t c);
const char *ozayn_sintel_integrity_state_name(ozayn_sintel_integrity_state_t s);
const char *ozayn_sintel_evidence_role_name(ozayn_sintel_evidence_role_t r);
const char *ozayn_sintel_threat_category_name(ozayn_sintel_threat_category_t c);
const char *ozayn_sintel_impact_name(ozayn_sintel_impact_t i);
const char *ozayn_sintel_assessment_state_name(ozayn_sintel_assessment_state_t s);
const char *ozayn_sintel_confidence_name(ozayn_sintel_confidence_t c);
const char *ozayn_sintel_severity_name(ozayn_sintel_severity_t sev);
const char *ozayn_sintel_recommended_response_name(ozayn_sintel_recommended_response_t r);
const char *ozayn_sintel_explanation_code_name(ozayn_sintel_explanation_code_t c);

int ozayn_sintel_severity_to_audit_severity(ozayn_sintel_severity_t sev);
int ozayn_sintel_severity_to_salert_severity(ozayn_sintel_severity_t sev);
int ozayn_sintel_severity_to_ir_severity(ozayn_sintel_severity_t sev);

/* ============================================================
 * SECTION 24 — EVIDENCE OPERATIONS
 * ============================================================ */

ozayn_sintel_err_t ozayn_sintel_collect_evidence(
    ozayn_sintel_service_t *svc,
    const ozayn_sintel_evidence_t *evidence,
    ozayn_sintel_evidence_t **out_stored);

ozayn_sintel_err_t ozayn_sintel_validate_evidence(
    ozayn_sintel_service_t *svc,
    ozayn_sintel_evidence_t *evidence);

ozayn_sintel_evidence_t *ozayn_sintel_get_evidence(
    ozayn_sintel_service_t *svc,
    const char *evidence_id);

int ozayn_sintel_evidence_count(const ozayn_sintel_service_t *svc);

int ozayn_sintel_list_evidence(
    const ozayn_sintel_service_t *svc,
    int filter_type,
    ozayn_sintel_evidence_t **out_evidence,
    int max_count);

int ozayn_sintel_evidence_is_duplicate(
    const ozayn_sintel_service_t *svc,
    ozayn_sintel_evidence_type_t type,
    const char *source_event_id,
    const char *identity_id);

/* ============================================================
 * SECTION 25 — EVIDENCE SET OPERATIONS
 * ============================================================ */

ozayn_sintel_err_t ozayn_sintel_create_evidence_set(
    ozayn_sintel_service_t *svc,
    const char *finding_id,
    const char *correlation_id,
    ozayn_sintel_evidence_set_t **out_set);

ozayn_sintel_err_t ozayn_sintel_add_to_evidence_set(
    ozayn_sintel_service_t *svc,
    const char *set_id,
    const char *evidence_id,
    ozayn_sintel_evidence_role_t role);

ozayn_sintel_evidence_set_t *ozayn_sintel_get_evidence_set(
    ozayn_sintel_service_t *svc,
    const char *set_id);

int ozayn_sintel_evidence_set_count(const ozayn_sintel_service_t *svc);

int ozayn_sintel_list_evidence_sets(
    const ozayn_sintel_service_t *svc,
    const char *finding_id,
    ozayn_sintel_evidence_set_t **out_sets,
    int max_count);

/* ============================================================
 * SECTION 26 — RELIABILITY ASSESSMENT
 * ============================================================ */

ozayn_sintel_reliability_t ozayn_sintel_assess_reliability(
    const ozayn_sintel_evidence_t *evidence);

ozayn_sintel_relevance_t ozayn_sintel_assess_relevance(
    const ozayn_sintel_service_t *svc,
    const ozayn_sintel_evidence_t *evidence,
    const char *finding_id);

/* ============================================================
 * SECTION 27 — THREAT ASSESSMENT OPERATIONS
 * ============================================================ */

ozayn_sintel_err_t ozayn_sintel_create_assessment(
    ozayn_sintel_service_t *svc,
    const char *finding_id,
    const char *evidence_set_id,
    ozayn_sintel_assessment_t **out_assessment);

ozayn_sintel_err_t ozayn_sintel_complete_assessment(
    ozayn_sintel_service_t *svc,
    const char *assessment_id);

ozayn_sintel_err_t ozayn_sintel_escalate_assessment(
    ozayn_sintel_service_t *svc,
    const char *assessment_id);

ozayn_sintel_assessment_t *ozayn_sintel_get_assessment(
    ozayn_sintel_service_t *svc,
    const char *assessment_id);

int ozayn_sintel_assessment_count(const ozayn_sintel_service_t *svc);

int ozayn_sintel_list_assessments(
    const ozayn_sintel_service_t *svc,
    int filter_state,
    ozayn_sintel_assessment_t **out_assessments,
    int max_count);

/* ============================================================
 * SECTION 28 — ASSESSMENT EVALUATION
 * ============================================================ */

ozayn_sintel_err_t ozayn_sintel_evaluate_assessment(
    ozayn_sintel_service_t *svc,
    ozayn_sintel_assessment_t *assessment);

ozayn_sintel_err_t ozayn_sintel_add_explanation(
    ozayn_sintel_assessment_t *assessment,
    ozayn_sintel_explanation_code_t code);

/* ============================================================
 * SECTION 29 — DETERMINISTIC CONFIDENCE
 * ============================================================ */

ozayn_sintel_confidence_t ozayn_sintel_calculate_confidence(
    const ozayn_sintel_service_t *svc,
    const ozayn_sintel_evidence_set_t *set);

/* ============================================================
 * SECTION 30 — INCIDENT INTEGRATION
 * ============================================================ */

ozayn_sintel_err_t ozayn_sintel_create_incident_from_assessment(
    ozayn_sintel_service_t *svc,
    ozayn_sintel_assessment_t *assessment);

/* ============================================================
 * SECTION 31 — ALERT INTEGRATION
 * ============================================================ */

ozayn_sintel_err_t ozayn_sintel_create_alert_from_assessment(
    ozayn_sintel_service_t *svc,
    ozayn_sintel_assessment_t *assessment);

/* ============================================================
 * SECTION 32 — AUDIT INTEGRATION
 * ============================================================ */

ozayn_sintel_err_t ozayn_sintel_audit_event(
    ozayn_sintel_service_t *svc,
    const char *event_type,
    const char *detail);

/* ============================================================
 * SECTION 33 — POLICY
 * ============================================================ */

ozayn_sintel_policy_t ozayn_sintel_default_policy(void);

ozayn_sintel_err_t ozayn_sintel_set_policy(
    ozayn_sintel_service_t *svc,
    const ozayn_sintel_policy_t *policy);

const ozayn_sintel_policy_t *ozayn_sintel_get_policy(
    const ozayn_sintel_service_t *svc);

/* ============================================================
 * SECTION 34 — CLEANUP
 * ============================================================ */

int ozayn_sintel_cleanup_expired_evidence(ozayn_sintel_service_t *svc);

int ozayn_sintel_cleanup_expired_assessments(ozayn_sintel_service_t *svc);

/* ============================================================
 * SECTION 35 — RESOURCE SAFETY
 * ============================================================ */

int ozayn_sintel_evidence_full(const ozayn_sintel_service_t *svc);
int ozayn_sintel_sets_full(const ozayn_sintel_service_t *svc);
int ozayn_sintel_assessments_full(const ozayn_sintel_service_t *svc);

/* ============================================================
 * SECTION 36 — GLOBAL ACCESSOR
 * ============================================================ */

ozayn_sintel_service_t *ozayn_sintel_get_global(void);

#ifdef __cplusplus
}
#endif

#endif /* OZAYN_SEC_INTEL_H */
