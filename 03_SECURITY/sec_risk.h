/*
 * sec_risk.h — Security Risk Scoring & Decision Support Foundation (Step 33).
 *
 * Answers: "How significant is the identified security risk, how should
 *           it be prioritized, and what security response should be
 *           considered?"
 *
 * Converts existing threat findings and evidence assessments into a
 * deterministic, explainable security-risk assessment.
 *
 * Deterministic, explainable, auditable, bounded, fail-safe.
 * No AI/ML, no external threat feeds, no authorization bypass.
 * No direct containment — risk engine recommends, it does not enforce.
 */

#ifndef OZAYN_SEC_RISK_H
#define OZAYN_SEC_RISK_H

#include "sec_intel.h"
#include "sec_detect.h"
#include "sec_alert.h"
#include "sec_notify.h"
#include "sec_health.h"
#include "sec_diag.h"
#include "incident.h"
#include "sec_config.h"
#include "audit.h"
#include "data_classification.h"
#include <stdint.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================
 * SECTION 1 — ERROR CODES
 * ============================================================ */

typedef enum {
    OZAYN_SR_OK                               =   0,
    OZAYN_SR_ERR_NULL                         =  -1,
    OZAYN_SR_ERR_NOT_INITIALIZED              =  -2,
    OZAYN_SR_ERR_ALREADY_INITIALIZED          =  -3,
    OZAYN_SR_ERR_INVALID_PARAM                =  -4,
    OZAYN_SR_ERR_LIMIT_REACHED                =  -5,
    OZAYN_SR_ERR_NOT_FOUND                    =  -6,
    OZAYN_SR_ERR_STATE_INVALID                =  -7,
    OZAYN_SR_ERR_STATE_TRANSITION             =  -8,
    OZAYN_SR_ERR_POLICY_REJECTED              =  -9,
    OZAYN_SR_ERR_INTEGRITY_FAILURE            = -10,
    OZAYN_SR_ERR_EVIDENCE_INVALID             = -11,
    OZAYN_SR_ERR_EVIDENCE_EXPIRED             = -12,
    OZAYN_SR_ERR_EVIDENCE_REVOKED             = -13,
    OZAYN_SR_ERR_SET_INVALID                  = -14,
    OZAYN_SR_ERR_SET_LIMIT                    = -15,
    OZAYN_SR_ERR_ASSESSMENT_INVALID           = -16,
    OZAYN_SR_ERR_ASSESSMENT_LIMIT             = -17,
    OZAYN_SR_ERR_RESOURCE_EXHAUSTED           = -18,
    OZAYN_SR_ERR_UNAVAILABLE                  = -19,
    OZAYN_SR_ERR_AGGREGATION_FAILED           = -20,
    OZAYN_SR_ERR_DEDUPE_FAILED                = -21,
    OZAYN_SR_ERR_TEMPORAL_FAILED              = -22
} ozayn_sr_err_t;

/* ============================================================
 * SECTION 2 — RISK LEVELS
 * ============================================================ */

typedef enum {
    OZAYN_SR_LEVEL_UNKNOWN                    = 0,
    OZAYN_SR_LEVEL_LOW                        = 1,
    OZAYN_SR_LEVEL_MODERATE                   = 2,
    OZAYN_SR_LEVEL_HIGH                       = 3,
    OZAYN_SR_LEVEL_CRITICAL                   = 4
} ozayn_sr_level_t;

/* ============================================================
 * SECTION 3 — RISK FACTOR TYPES
 * ============================================================ */

typedef enum {
    OZAYN_SR_FACTOR_THREAT_SEVERITY           =  0,
    OZAYN_SR_FACTOR_THREAT_IMPACT             =  1,
    OZAYN_SR_FACTOR_EVIDENCE_RELIABILITY      =  2,
    OZAYN_SR_FACTOR_THREAT_CONFIDENCE         =  3,
    OZAYN_SR_FACTOR_DATA_CLASSIFICATION       =  4,
    OZAYN_SR_FACTOR_RESOURCE_SENSITIVITY      =  5,
    OZAYN_SR_FACTOR_IDENTITY_SCOPE            =  6,
    OZAYN_SR_FACTOR_SECURITY_ASSURANCE        =  7,
    OZAYN_SR_FACTOR_INTEGRITY_STATE           =  8,
    OZAYN_SR_FACTOR_PERSISTENCE               =  9,
    OZAYN_SR_FACTOR_INCIDENT_STATE            = 10,
    OZAYN_SR_FACTOR_SECURITY_HEALTH           = 11,
    OZAYN_SR_FACTOR_COUNT
} ozayn_sr_factor_type_t;

/* ============================================================
 * SECTION 4 — PERSISTENCE FACTOR
 * ============================================================ */

typedef enum {
    OZAYN_SR_PERSISTENCE_UNKNOWN              = 0,
    OZAYN_SR_PERSISTENCE_TRANSIENT            = 1,
    OZAYN_SR_PERSISTENCE_REPEATED             = 2,
    OZAYN_SR_PERSISTENCE_PERSISTENT           = 3
} ozayn_sr_persistence_t;

/* ============================================================
 * SECTION 5 — SECURITY ASSURANCE LEVEL
 * ============================================================ */

typedef enum {
    OZAYN_SR_ASSURANCE_UNKNOWN                = 0,
    OZAYN_SR_ASSURANCE_SINGLE_FACTOR          = 1,
    OZAYN_SR_ASSURANCE_MULTI_FACTOR           = 2,
    OZAYN_SR_ASSURANCE_HIGH_ASSURANCE         = 3
} ozayn_sr_assurance_t;

/* ============================================================
 * SECTION 6 — TEMPORAL STATE
 * ============================================================ */

typedef enum {
    OZAYN_SR_TEMPORAL_CURRENT                 = 0,
    OZAYN_SR_TEMPORAL_AGING                   = 1,
    OZAYN_SR_TEMPORAL_EXPIRED                 = 2,
    OZAYN_SR_TEMPORAL_UNKNOWN                 = 3
} ozayn_sr_temporal_t;

/* ============================================================
 * SECTION 7 — RISK LIFECYCLE STATES
 * ============================================================ */

typedef enum {
    OZAYN_SR_STATE_PENDING                    = 0,
    OZAYN_SR_STATE_ASSESSING                  = 1,
    OZAYN_SR_STATE_ASSESSED                   = 2,
    OZAYN_SR_STATE_ELEVATED                   = 3,
    OZAYN_SR_STATE_MITIGATING                 = 4,
    OZAYN_SR_STATE_MONITORING                 = 5,
    OZAYN_SR_STATE_RESOLVED                   = 6,
    OZAYN_SR_STATE_EXPIRED                    = 7,
    OZAYN_SR_STATE_INVALID                    = 8
} ozayn_sr_state_t;

/* ============================================================
 * SECTION 8 — DECISION SUPPORT RECOMMENDATIONS
 * ============================================================ */

typedef enum {
    OZAYN_SR_DECISION_NONE                    =  0,
    OZAYN_SR_DECISION_MONITOR                 =  1,
    OZAYN_SR_DECISION_INVESTIGATE             =  2,
    OZAYN_SR_DECISION_ESCALATE_INCIDENT       =  3,
    OZAYN_SR_DECISION_REQUIRE_REAUTH          =  4,
    OZAYN_SR_DECISION_REQUIRE_MFA             =  5,
    OZAYN_SR_DECISION_REVIEW_SESSION          =  6,
    OZAYN_SR_DECISION_REVOKE_SESSION          =  7,
    OZAYN_SR_DECISION_REVIEW_IDENTITY         =  8,
    OZAYN_SR_DECISION_SUSPEND_IDENTITY        =  9,
    OZAYN_SR_DECISION_REVIEW_PERMISSION       = 10,
    OZAYN_SR_DECISION_REVIEW_ROLE             = 11,
    OZAYN_SR_DECISION_REVIEW_KEY_STATE        = 12,
    OZAYN_SR_DECISION_SECURITY_LOCKDOWN       = 13
} ozayn_sr_decision_t;

/* ============================================================
 * SECTION 9 — EXPLANATION CODES
 * ============================================================ */

typedef enum {
    OZAYN_SR_EXPLAIN_NONE                     =  0,
    OZAYN_SR_EXPLAIN_HIGH_THREAT_SEVERITY     =  1,
    OZAYN_SR_EXPLAIN_HIGH_IMPACT_RESOURCE     =  2,
    OZAYN_SR_EXPLAIN_HIGH_CONFIDENCE          =  3,
    OZAYN_SR_EXPLAIN_VERIFIED_EVIDENCE        =  4,
    OZAYN_SR_EXPLAIN_LOW_RELIABILITY          =  5,
    OZAYN_SR_EXPLAIN_UNKNOWN_RELIABILITY      =  6,
    OZAYN_SR_EXPLAIN_CONFLICTING_EVIDENCE     =  7,
    OZAYN_SR_EXPLAIN_INTEGRITY_FAILURE        =  8,
    OZAYN_SR_EXPLAIN_SENSITIVE_CLASSIFICATION =  9,
    OZAYN_SR_EXPLAIN_PERSISTENT_THREAT        = 10,
    OZAYN_SR_EXPLAIN_ACTIVE_INCIDENT          = 11,
    OZAYN_SR_EXPLAIN_HEALTH_DEGRADED          = 12,
    OZAYN_SR_EXPLAIN_LOW_ASSURANCE            = 13,
    OZAYN_SR_EXPLAIN_INSUFFICIENT_EVIDENCE    = 14,
    OZAYN_SR_EXPLAIN_AGGREGATED_RISK          = 15
} ozayn_sr_explain_t;

/* ============================================================
 * SECTION 10 — RISK FACTOR
 * ============================================================ */

#define OZAYN_SR_MAX_SOURCE_LEN               64
#define OZAYN_SR_MAX_ID_LEN                   64
#define OZAYN_SR_MAX_META_LEN                256
#define OZAYN_SR_MAX_EXPLANATIONS             16

typedef struct {
    ozayn_sr_factor_type_t   type;
    int                      value;       /* Raw numeric value of the factor */
    int                      weight;      /* Policy-assigned weight (0-100) */
    char                     source[OZAYN_SR_MAX_SOURCE_LEN];
    ozayn_sr_explain_t       explanation;
} ozayn_sr_factor_t;

/* ============================================================
 * SECTION 11 — RISK CONTRIBUTION
 * ============================================================ */

typedef struct {
    ozayn_sr_factor_type_t   factor_type;
    char                     source_ref[OZAYN_SR_MAX_ID_LEN];
    int                      contribution;  /* Score contribution (-100 to +100) */
    ozayn_sr_explain_t       explanation;
} ozayn_sr_contribution_t;

/* ============================================================
 * SECTION 12 — AFFECTED RESOURCE
 * ============================================================ */

typedef struct {
    int                      resource_type; /* ozayn_authz_resource_type_t */
    char                     resource_id[OZAYN_SR_MAX_ID_LEN];
    int                      classification; /* ozayn_sintel_classification_t */
    int                      scope;
    char                     security_context[OZAYN_SR_MAX_SOURCE_LEN];
} ozayn_sr_resource_t;

/* ============================================================
 * SECTION 13 — RISK ASSESSMENT
 * ============================================================ */

typedef struct {
    /* Identity */
    char                     risk_id[OZAYN_SR_MAX_ID_LEN];
    uint32_t                 risk_version;

    /* References */
    char                     finding_id[OZAYN_SR_MAX_ID_LEN];
    char                     threat_assessment_id[OZAYN_SR_MAX_ID_LEN];
    char                     evidence_set_id[OZAYN_SR_MAX_ID_LEN];
    char                     incident_id[OZAYN_SR_MAX_ID_LEN];
    char                     correlation_id[OZAYN_SR_MAX_ID_LEN];

    /* Risk classification */
    ozayn_sr_level_t         risk_level;
    int                      risk_score;        /* 0-100 */
    ozayn_sintel_severity_t  severity;
    ozayn_sintel_confidence_t confidence;
    ozayn_sintel_impact_t    impact;
    ozayn_sintel_reliability_t reliability;
    int                      classification;    /* ozayn_sintel_classification_t */
    int                      integrity_state;   /* ozayn_sintel_integrity_state_t */

    /* Context */
    ozayn_sr_resource_t      affected_resource;
    ozayn_sr_persistence_t   persistence;
    ozayn_sr_assurance_t     assurance;
    ozayn_sr_temporal_t      temporal_state;

    /* Lifecycle */
    ozayn_sr_state_t         state;

    /* Factors */
    int                      factor_count;
    ozayn_sr_factor_t        factors[OZAYN_SR_FACTOR_COUNT];

    /* Contributions */
    int                      contribution_count;
    ozayn_sr_contribution_t  contributions[OZAYN_SR_FACTOR_COUNT];

    /* Explanation */
    int                      explanation_count;
    ozayn_sr_explain_t       explanations[OZAYN_SR_MAX_EXPLANATIONS];

    /* Decision support */
    ozayn_sr_decision_t      recommended_decision;
    int                      decision_priority;  /* 0-100 */

    /* Timing */
    time_t                   created_time;
    time_t                   updated_time;
    time_t                   expiration_time;

    /* Safe metadata */
    char                     safe_metadata[OZAYN_SR_MAX_META_LEN];
} ozayn_sr_assessment_t;

/* ============================================================
 * SECTION 14 — AGGREGATION GROUP
 * ============================================================ */

#define OZAYN_SR_MAX_AGGREGATION              32

typedef struct {
    char                     group_id[OZAYN_SR_MAX_ID_LEN];
    char                     identity_id[OZAYN_SR_MAX_ID_LEN];
    char                     resource_id[OZAYN_SR_MAX_ID_LEN];
    char                     incident_id[OZAYN_SR_MAX_ID_LEN];

    int                      assessment_count;
    char                     assessment_ids[OZAYN_SR_MAX_AGGREGATION][OZAYN_SR_MAX_ID_LEN];

    ozayn_sr_level_t         aggregated_level;
    int                      aggregated_score;
    int                      max_severity;
    int                      max_confidence;
    int                      max_impact;

    time_t                   created_time;
    time_t                   updated_time;
} ozayn_sr_aggregation_t;

/* ============================================================
 * SECTION 15 — RISK POLICY
 * ============================================================ */

typedef struct {
    int                      enabled;
    int                      max_assessments;
    int                      max_aggregations;
    int                      assessment_retention_seconds;
    int                      dedup_window_seconds;

    /* Score thresholds for level mapping */
    int                      score_threshold_low;
    int                      score_threshold_moderate;
    int                      score_threshold_high;
    /* score >= threshold_high = CRITICAL */

    /* Factor weights (0-100) */
    int                      weight_threat_severity;
    int                      weight_threat_impact;
    int                      weight_evidence_reliability;
    int                      weight_threat_confidence;
    int                      weight_data_classification;
    int                      weight_resource_sensitivity;
    int                      weight_identity_scope;
    int                      weight_security_assurance;
    int                      weight_integrity_state;
    int                      weight_persistence;
    int                      weight_incident_state;
    int                      weight_security_health;

    /* Integration toggles */
    int                      incident_integration_enabled;
    int                      alert_integration_enabled;
    int                      health_integration_enabled;
    int                      audit_integration_enabled;

    /* Decision thresholds */
    int                      decision_threshold_escalate_incident;
    int                      decision_threshold_lockdown;
    int                      decision_threshold_suspend_identity;
} ozayn_sr_policy_t;

/* ============================================================
 * SECTION 16 — SERVICE CONFIGURATION
 * ============================================================ */

typedef struct {
    ozayn_sintel_service_t   *intel_service;
    ozayn_sdet_service_t     *detect_service;
    ozayn_ir_service_t       *incident_service;
    ozayn_salert_service_t   *alert_service;
    ozayn_sh_service_t       *health_service;
    ozayn_sc_service_t       *config_service;
    ozayn_audit_service_t    *audit;
} ozayn_sr_service_config_t;

/* ============================================================
 * SECTION 17 — SERVICE STATE
 * ============================================================ */

#define OZAYN_SR_MAX_ASSESSMENTS              256
#define OZAYN_SR_MAX_AGGREGATIONS_SVC         64

typedef struct {
    int                      initialized;

    /* Risk assessments ring buffer */
    ozayn_sr_assessment_t    assessments[OZAYN_SR_MAX_ASSESSMENTS];
    int                      assessment_head;
    int                      assessment_count;
    uint32_t                 assessment_sequence;

    /* Aggregation groups */
    ozayn_sr_aggregation_t   aggregations[OZAYN_SR_MAX_AGGREGATIONS_SVC];
    int                      aggregation_count;

    /* Deduplication state */
    struct {
        char                 dedup_key[128];
        uint32_t             assessment_hash;
        time_t               first_time;
        time_t               last_time;
        int                  count;
    } dedup_state[256];
    int                      dedup_count;

    /* Policy */
    ozayn_sr_policy_t        policy;

    /* Dependencies (not owned) */
    ozayn_sintel_service_t  *intel_service;
    ozayn_sdet_service_t    *detect_service;
    ozayn_ir_service_t      *incident_service;
    ozayn_salert_service_t  *alert_service;
    ozayn_sh_service_t      *health_service;
    ozayn_sc_service_t      *config_service;
    ozayn_audit_service_t   *audit;

    /* Statistics */
    uint64_t                 total_assessments_created;
    uint64_t                 total_assessments_completed;
    uint64_t                 total_assessments_elevated;
    uint64_t                 total_assessments_resolved;
    uint64_t                 total_assessments_expired;
    uint64_t                 total_assessments_deduplicated;
    uint64_t                 total_aggregations_created;
    uint64_t                 total_incidents_created;
    uint64_t                 total_alerts_created;
    uint64_t                 total_calculations;
    uint64_t                 total_policy_rejections;
} ozayn_sr_service_t;

/* ============================================================
 * SECTION 18 — LIFECYCLE
 * ============================================================ */

ozayn_sr_err_t ozayn_sr_service_init(
    ozayn_sr_service_t *svc,
    const ozayn_sr_service_config_t *cfg);

void ozayn_sr_service_shutdown(ozayn_sr_service_t *svc);

int ozayn_sr_service_is_initialized(const ozayn_sr_service_t *svc);

/* ============================================================
 * SECTION 19 — NAME HELPERS
 * ============================================================ */

const char *ozayn_sr_err_name(ozayn_sr_err_t err);
const char *ozayn_sr_level_name(ozayn_sr_level_t level);
const char *ozayn_sr_factor_type_name(ozayn_sr_factor_type_t ft);
const char *ozayn_sr_persistence_name(ozayn_sr_persistence_t p);
const char *ozayn_sr_assurance_name(ozayn_sr_assurance_t a);
const char *ozayn_sr_temporal_name(ozayn_sr_temporal_t t);
const char *ozayn_sr_state_name(ozayn_sr_state_t s);
const char *ozayn_sr_decision_name(ozayn_sr_decision_t d);
const char *ozayn_sr_explain_name(ozayn_sr_explain_t e);

int ozayn_sr_level_to_audit_severity(ozayn_sr_level_t level);
int ozayn_sr_level_to_salert_severity(ozayn_sr_level_t level);
int ozayn_sr_level_to_ir_severity(ozayn_sr_level_t level);
int ozayn_sr_level_to_salert_priority(ozayn_sr_level_t level);

/* ============================================================
 * SECTION 20 — RISK ASSESSMENT OPERATIONS
 * ============================================================ */

ozayn_sr_err_t ozayn_sr_create_assessment(
    ozayn_sr_service_t *svc,
    const char *finding_id,
    const char *threat_assessment_id,
    const char *evidence_set_id,
    ozayn_sr_assessment_t **out_assessment);

ozayn_sr_err_t ozayn_sr_complete_assessment(
    ozayn_sr_service_t *svc,
    const char *risk_id);

ozayn_sr_err_t ozayn_sr_elevate_assessment(
    ozayn_sr_service_t *svc,
    const char *risk_id);

ozayn_sr_err_t ozayn_sr_resolve_assessment(
    ozayn_sr_service_t *svc,
    const char *risk_id);

ozayn_sr_assessment_t *ozayn_sr_get_assessment(
    ozayn_sr_service_t *svc,
    const char *risk_id);

int ozayn_sr_assessment_count(const ozayn_sr_service_t *svc);

int ozayn_sr_list_assessments(
    const ozayn_sr_service_t *svc,
    int filter_state,
    ozayn_sr_assessment_t **out_assessments,
    int max_count);

/* ============================================================
 * SECTION 21 — RISK FACTOR OPERATIONS
 * ============================================================ */

ozayn_sr_err_t ozayn_sr_add_factor(
    ozayn_sr_assessment_t *assessment,
    ozayn_sr_factor_type_t type,
    int value,
    int weight,
    const char *source,
    ozayn_sr_explain_t explanation);

/* ============================================================
 * SECTION 22 — DETERMINISTIC RISK CALCULATION
 * ============================================================ */

ozayn_sr_err_t ozayn_sr_calculate_risk(
    ozayn_sr_service_t *svc,
    ozayn_sr_assessment_t *assessment);

ozayn_sr_level_t ozayn_sr_score_to_level(
    const ozayn_sr_service_t *svc,
    int score);

/* ============================================================
 * SECTION 23 — RISK AGGREGATION
 * ============================================================ */

ozayn_sr_err_t ozayn_sr_create_aggregation(
    ozayn_sr_service_t *svc,
    const char *identity_id,
    const char *resource_id,
    const char *incident_id,
    ozayn_sr_aggregation_t **out_group);

ozayn_sr_err_t ozayn_sr_add_to_aggregation(
    ozayn_sr_service_t *svc,
    const char *group_id,
    const char *risk_id);

ozayn_sr_err_t ozayn_sr_evaluate_aggregation(
    ozayn_sr_service_t *svc,
    ozayn_sr_aggregation_t *group);

ozayn_sr_aggregation_t *ozayn_sr_get_aggregation(
    ozayn_sr_service_t *svc,
    const char *group_id);

int ozayn_sr_aggregation_count(const ozayn_sr_service_t *svc);

/* ============================================================
 * SECTION 24 — RISK DEDUPLICATION
 * ============================================================ */

int ozayn_sr_assessment_is_duplicate(
    const ozayn_sr_service_t *svc,
    const char *finding_id,
    const char *evidence_set_id,
    const char *threat_assessment_id);

/* ============================================================
 * SECTION 25 — TEMPORAL RISK
 * ============================================================ */

ozayn_sr_temporal_t ozayn_sr_evaluate_temporal(
    const ozayn_sr_service_t *svc,
    const ozayn_sr_assessment_t *assessment);

/* ============================================================
 * SECTION 26 — DECISION SUPPORT
 * ============================================================ */

ozayn_sr_err_t ozayn_sr_generate_decision(
    ozayn_sr_service_t *svc,
    ozayn_sr_assessment_t *assessment);

/* ============================================================
 * SECTION 27 — INCIDENT INTEGRATION
 * ============================================================ */

ozayn_sr_err_t ozayn_sr_create_incident_from_risk(
    ozayn_sr_service_t *svc,
    ozayn_sr_assessment_t *assessment);

/* ============================================================
 * SECTION 28 — ALERT INTEGRATION
 * ============================================================ */

ozayn_sr_err_t ozayn_sr_create_alert_from_risk(
    ozayn_sr_service_t *svc,
    ozayn_sr_assessment_t *assessment);

/* ============================================================
 * SECTION 29 — HEALTH INTEGRATION
 * ============================================================ */

int ozayn_sr_get_health_impact(
    const ozayn_sr_service_t *svc);

/* ============================================================
 * SECTION 30 — AUDIT INTEGRATION
 * ============================================================ */

ozayn_sr_err_t ozayn_sr_audit_event(
    ozayn_sr_service_t *svc,
    const char *event_type,
    const char *detail);

/* ============================================================
 * SECTION 31 — POLICY
 * ============================================================ */

ozayn_sr_policy_t ozayn_sr_default_policy(void);

ozayn_sr_err_t ozayn_sr_set_policy(
    ozayn_sr_service_t *svc,
    const ozayn_sr_policy_t *policy);

const ozayn_sr_policy_t *ozayn_sr_get_policy(
    const ozayn_sr_service_t *svc);

/* ============================================================
 * SECTION 32 — CLEANUP
 * ============================================================ */

int ozayn_sr_cleanup_expired_assessments(ozayn_sr_service_t *svc);

/* ============================================================
 * SECTION 33 — RESOURCE SAFETY
 * ============================================================ */

int ozayn_sr_assessments_full(const ozayn_sr_service_t *svc);
int ozayn_sr_aggregations_full(const ozayn_sr_service_t *svc);

/* ============================================================
 * SECTION 34 — GLOBAL ACCESSOR
 * ============================================================ */

ozayn_sr_service_t *ozayn_sr_get_global(void);

#ifdef __cplusplus
}
#endif

#endif /* OZAYN_SEC_RISK_H */
