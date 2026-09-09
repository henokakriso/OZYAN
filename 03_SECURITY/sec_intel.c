/*
 * sec_intel.c — Security Threat Intelligence & Evidence Analysis Foundation (Step 32).
 */

#include "sec_intel.h"
#include <stdio.h>
#include <string.h>
#include <time.h>

/* ============================================================
 * GLOBAL SINGLETON
 * ============================================================ */

static ozayn_sintel_service_t _sintel_global = {0};

ozayn_sintel_service_t *ozayn_sintel_get_global(void)
{
    return &_sintel_global;
}

/* ============================================================
 * INTERNAL HELPERS
 * ============================================================ */

static void _generate_id(char *buf, int buflen, const char *prefix, uint32_t seq)
{
    static const char hex[] = "0123456789ABCDEF";
    char raw[16];
    int len = 0;
    uint32_t v = seq;
    if (v == 0) v = 1;
    while (v > 0 && len < 16) {
        raw[len++] = hex[v & 0xF];
        v >>= 4;
    }
    int off = snprintf(buf, buflen, "%s-", prefix);
    for (int i = len - 1; i >= 0 && off < buflen - 1; i--)
        buf[off++] = raw[i];
    buf[off] = '\0';
}

static void _audit_event(ozayn_sintel_service_t *svc,
                          const char *event_type,
                          const char *detail)
{
    if (!svc->audit || !svc->audit->initialized) return;
    ozayn_audit_event_t ev;
    ozayn_audit_event_init(&ev);
    ozayn_audit_event_set_type(&ev, OZAYN_AUDIT_CONFIG_CHANGED);
    ozayn_audit_event_set_outcome(&ev, OZAYN_AUDIT_OUTCOME_SUCCESS);
    ozayn_audit_event_set_severity(&ev, OZAYN_AUDIT_SEV_NOTICE);
    ozayn_audit_event_set_source(&ev, "SEC_INTEL");
    char buf[512];
    snprintf(buf, sizeof(buf), "%s: %s", event_type,
             detail ? detail : "N/A");
    ozayn_audit_event_set_detail(&ev, buf);
    ozayn_audit_record(svc->audit, &ev);
}

static ozayn_sintel_evidence_t *_alloc_evidence(ozayn_sintel_service_t *svc)
{
    if (svc->evidence_count >= OZAYN_SINTEL_MAX_EVIDENCE) {
        svc->evidence_head = (svc->evidence_head + 1) % OZAYN_SINTEL_MAX_EVIDENCE;
        svc->evidence_count--;
    }
    int slot = (svc->evidence_head + svc->evidence_count) % OZAYN_SINTEL_MAX_EVIDENCE;
    memset(&svc->evidence[slot], 0, sizeof(ozayn_sintel_evidence_t));
    svc->evidence_count++;
    return &svc->evidence[slot];
}

static ozayn_sintel_assessment_t *_alloc_assessment(ozayn_sintel_service_t *svc)
{
    if (svc->assessment_count >= OZAYN_SINTEL_MAX_ASSESSMENTS) {
        svc->assessment_head = (svc->assessment_head + 1) % OZAYN_SINTEL_MAX_ASSESSMENTS;
        svc->assessment_count--;
    }
    int slot = (svc->assessment_head + svc->assessment_count) % OZAYN_SINTEL_MAX_ASSESSMENTS;
    memset(&svc->assessments[slot], 0, sizeof(ozayn_sintel_assessment_t));
    svc->assessment_count++;
    return &svc->assessments[slot];
}

/* ============================================================
 * SECTION 23 — NAME HELPERS
 * ============================================================ */

const char *ozayn_sintel_err_name(ozayn_sintel_err_t err)
{
    switch (err) {
    case OZAYN_SINTEL_OK:                      return "OK";
    case OZAYN_SINTEL_ERR_NULL:                return "NULL";
    case OZAYN_SINTEL_ERR_NOT_INITIALIZED:     return "NOT_INITIALIZED";
    case OZAYN_SINTEL_ERR_ALREADY_INITIALIZED: return "ALREADY_INITIALIZED";
    case OZAYN_SINTEL_ERR_INVALID_PARAM:       return "INVALID_PARAM";
    case OZAYN_SINTEL_ERR_LIMIT_REACHED:       return "LIMIT_REACHED";
    case OZAYN_SINTEL_ERR_NOT_FOUND:           return "NOT_FOUND";
    case OZAYN_SINTEL_ERR_STATE_INVALID:       return "STATE_INVALID";
    case OZAYN_SINTEL_ERR_STATE_TRANSITION:    return "STATE_TRANSITION";
    case OZAYN_SINTEL_ERR_POLICY_REJECTED:     return "POLICY_REJECTED";
    case OZAYN_SINTEL_ERR_INTEGRITY_FAILURE:   return "INTEGRITY_FAILURE";
    case OZAYN_SINTEL_ERR_EVIDENCE_INVALID:    return "EVIDENCE_INVALID";
    case OZAYN_SINTEL_ERR_EVIDENCE_EXPIRED:    return "EVIDENCE_EXPIRED";
    case OZAYN_SINTEL_ERR_EVIDENCE_REVOKED:    return "EVIDENCE_REVOKED";
    case OZAYN_SINTEL_ERR_SET_INVALID:         return "SET_INVALID";
    case OZAYN_SINTEL_ERR_SET_LIMIT:           return "SET_LIMIT";
    case OZAYN_SINTEL_ERR_ASSESSMENT_INVALID:  return "ASSESSMENT_INVALID";
    case OZAYN_SINTEL_ERR_ASSESSMENT_LIMIT:    return "ASSESSMENT_LIMIT";
    case OZAYN_SINTEL_ERR_RESOURCE_EXHAUSTED:  return "RESOURCE_EXHAUSTED";
    case OZAYN_SINTEL_ERR_UNAVAILABLE:         return "UNAVAILABLE";
    }
    return "UNKNOWN";
}

const char *ozayn_sintel_evidence_type_name(ozayn_sintel_evidence_type_t t)
{
    static const char *names[] = {
        "AUDIT_EVENT", "AUDIT_INTEGRITY", "HEALTH_RESULT",
        "DIAGNOSTIC_RESULT", "CORRELATION_RESULT", "THREAT_FINDING",
        "AUTH_RESULT", "MFA_RESULT", "SESSION_RESULT",
        "AUTHZ_RESULT", "RBAC_RESULT", "PERMISSION_RESULT",
        "KEY_SECURITY", "VAULT_SECURITY", "BACKUP_SECURITY",
        "DELETION_SECURITY", "CONFIG_SECURITY", "INCIDENT_RESULT"
    };
    if (t >= 0 && t < OZAYN_SINTEL_EVID_TYPE_COUNT)
        return names[t];
    return "UNKNOWN";
}

const char *ozayn_sintel_reliability_name(ozayn_sintel_reliability_t r)
{
    switch (r) {
    case OZAYN_SINTEL_RELIABILITY_UNKNOWN:  return "UNKNOWN";
    case OZAYN_SINTEL_RELIABILITY_LOW:      return "LOW";
    case OZAYN_SINTEL_RELIABILITY_MEDIUM:   return "MEDIUM";
    case OZAYN_SINTEL_RELIABILITY_HIGH:     return "HIGH";
    case OZAYN_SINTEL_RELIABILITY_VERIFIED: return "VERIFIED";
    }
    return "UNKNOWN";
}

const char *ozayn_sintel_relevance_name(ozayn_sintel_relevance_t r)
{
    switch (r) {
    case OZAYN_SINTEL_RELEVANCE_IRRELEVANT: return "IRRELEVANT";
    case OZAYN_SINTEL_RELEVANCE_LOW:        return "LOW";
    case OZAYN_SINTEL_RELEVANCE_MEDIUM:     return "MEDIUM";
    case OZAYN_SINTEL_RELEVANCE_HIGH:       return "HIGH";
    case OZAYN_SINTEL_RELEVANCE_CRITICAL:   return "CRITICAL";
    }
    return "UNKNOWN";
}

const char *ozayn_sintel_evidence_status_name(ozayn_sintel_evidence_status_t s)
{
    switch (s) {
    case OZAYN_SINTEL_EVID_STATUS_UNVERIFIED: return "UNVERIFIED";
    case OZAYN_SINTEL_EVID_STATUS_VALIDATING: return "VALIDATING";
    case OZAYN_SINTEL_EVID_STATUS_VALID:      return "VALID";
    case OZAYN_SINTEL_EVID_STATUS_INVALID:    return "INVALID";
    case OZAYN_SINTEL_EVID_STATUS_SUPERSEDED: return "SUPERSEDED";
    case OZAYN_SINTEL_EVID_STATUS_EXPIRED:    return "EXPIRED";
    case OZAYN_SINTEL_EVID_STATUS_REVOKED:    return "REVOKED";
    }
    return "UNKNOWN";
}

const char *ozayn_sintel_classification_name(ozayn_sintel_classification_t c)
{
    switch (c) {
    case OZAYN_SINTEL_CLASS_PUBLIC:           return "PUBLIC";
    case OZAYN_SINTEL_CLASS_INTERNAL:         return "INTERNAL";
    case OZAYN_SINTEL_CLASS_SENSITIVE:        return "SENSITIVE";
    case OZAYN_SINTEL_CLASS_HIGHLY_SENSITIVE: return "HIGHLY_SENSITIVE";
    }
    return "UNKNOWN";
}

const char *ozayn_sintel_integrity_state_name(ozayn_sintel_integrity_state_t s)
{
    switch (s) {
    case OZAYN_SINTEL_INTEGRITY_UNKNOWN:   return "UNKNOWN";
    case OZAYN_SINTEL_INTEGRITY_VALID:     return "VALID";
    case OZAYN_SINTEL_INTEGRITY_INVALID:   return "INVALID";
    case OZAYN_SINTEL_INTEGRITY_UNAVAILABLE: return "UNAVAILABLE";
    }
    return "UNKNOWN";
}

const char *ozayn_sintel_evidence_role_name(ozayn_sintel_evidence_role_t r)
{
    switch (r) {
    case OZAYN_SINTEL_ROLE_PRIMARY:    return "PRIMARY";
    case OZAYN_SINTEL_ROLE_SUPPORTING: return "SUPPORTING";
    case OZAYN_SINTEL_ROLE_CONFLICTING: return "CONFLICTING";
    case OZAYN_SINTEL_ROLE_CONTEXTUAL: return "CONTEXTUAL";
    }
    return "UNKNOWN";
}

const char *ozayn_sintel_threat_category_name(ozayn_sintel_threat_category_t c)
{
    static const char *names[] = {
        "AUTH", "CREDENTIAL", "SESSION", "AUTHORIZATION",
        "PRIVILEGE_ESCALATION", "ROLE_TAMPERING", "PERMISSION_TAMPERING",
        "KEY_SECURITY", "VAULT_SECURITY", "DATA_INTEGRITY",
        "AUDIT_INTEGRITY", "BACKUP_SECURITY", "DELETION_SECURITY",
        "CONFIG", "COMPONENT_FAILURE", "UNKNOWN"
    };
    if (c >= 0 && c <= OZAYN_SINTEL_THREAT_UNKNOWN)
        return names[c];
    return "UNKNOWN";
}

const char *ozayn_sintel_impact_name(ozayn_sintel_impact_t i)
{
    switch (i) {
    case OZAYN_SINTEL_IMPACT_NONE:     return "NONE";
    case OZAYN_SINTEL_IMPACT_LOW:      return "LOW";
    case OZAYN_SINTEL_IMPACT_MODERATE: return "MODERATE";
    case OZAYN_SINTEL_IMPACT_HIGH:     return "HIGH";
    case OZAYN_SINTEL_IMPACT_CRITICAL: return "CRITICAL";
    }
    return "UNKNOWN";
}

const char *ozayn_sintel_assessment_state_name(ozayn_sintel_assessment_state_t s)
{
    switch (s) {
    case OZAYN_SINTEL_ASSESS_PENDING:   return "PENDING";
    case OZAYN_SINTEL_ASSESS_ASSESSING: return "ASSESSING";
    case OZAYN_SINTEL_ASSESS_ASSESSED:  return "ASSESSED";
    case OZAYN_SINTEL_ASSESS_ESCALATED: return "ESCALATED";
    case OZAYN_SINTEL_ASSESS_DISPUTED:  return "DISPUTED";
    case OZAYN_SINTEL_ASSESS_INVALID:   return "INVALID";
    case OZAYN_SINTEL_ASSESS_EXPIRED:   return "EXPIRED";
    }
    return "UNKNOWN";
}

const char *ozayn_sintel_confidence_name(ozayn_sintel_confidence_t c)
{
    switch (c) {
    case OZAYN_SINTEL_CONFIDENCE_LOW:      return "LOW";
    case OZAYN_SINTEL_CONFIDENCE_MEDIUM:   return "MEDIUM";
    case OZAYN_SINTEL_CONFIDENCE_HIGH:     return "HIGH";
    case OZAYN_SINTEL_CONFIDENCE_VERY_HIGH: return "VERY_HIGH";
    }
    return "UNKNOWN";
}

const char *ozayn_sintel_severity_name(ozayn_sintel_severity_t sev)
{
    switch (sev) {
    case OZAYN_SINTEL_SEV_INFO:     return "INFO";
    case OZAYN_SINTEL_SEV_NOTICE:   return "NOTICE";
    case OZAYN_SINTEL_SEV_WARNING:  return "WARNING";
    case OZAYN_SINTEL_SEV_HIGH:     return "HIGH";
    case OZAYN_SINTEL_SEV_CRITICAL: return "CRITICAL";
    }
    return "UNKNOWN";
}

const char *ozayn_sintel_recommended_response_name(ozayn_sintel_recommended_response_t r)
{
    switch (r) {
    case OZAYN_SINTEL_RESPONSE_NONE:              return "NONE";
    case OZAYN_SINTEL_RESPONSE_MONITOR:           return "MONITOR";
    case OZAYN_SINTEL_RESPONSE_INVESTIGATE:       return "INVESTIGATE";
    case OZAYN_SINTEL_RESPONSE_ESCALATE_INCIDENT: return "ESCALATE_INCIDENT";
    case OZAYN_SINTEL_RESPONSE_REQUIRE_REAUTH:    return "REQUIRE_REAUTH";
    case OZAYN_SINTEL_RESPONSE_REQUIRE_MFA:       return "REQUIRE_MFA";
    case OZAYN_SINTEL_RESPONSE_REVOKE_SESSION:    return "REVOKE_SESSION";
    case OZAYN_SINTEL_RESPONSE_SUSPEND_IDENTITY:  return "SUSPEND_IDENTITY";
    case OZAYN_SINTEL_RESPONSE_REVIEW_PERMISSION: return "REVIEW_PERMISSION";
    case OZAYN_SINTEL_RESPONSE_REVIEW_ROLE:       return "REVIEW_ROLE";
    case OZAYN_SINTEL_RESPONSE_REVIEW_KEY_STATE:  return "REVIEW_KEY_STATE";
    case OZAYN_SINTEL_RESPONSE_SECURITY_LOCKDOWN: return "SECURITY_LOCKDOWN";
    }
    return "UNKNOWN";
}

const char *ozayn_sintel_explanation_code_name(ozayn_sintel_explanation_code_t c)
{
    static const char *names[] = {
        "NONE", "MULTIPLE_AUTH_FAILURES", "RATE_LIMIT_TRIGGERED",
        "SENSITIVE_RESOURCE_TARGETED", "PRIVILEGE_CHANGE_ATTEMPT",
        "AUDIT_INTEGRITY_FAILED", "KEY_UNAVAILABLE",
        "VAULT_INTEGRITY_FAILED", "SESSION_ANOMALY",
        "MFA_FAILURE", "ROLE_TAMPERING", "PERMISSION_DENIED",
        "HEALTH_DEGRADED", "COMPONENT_UNAVAILABLE",
        "BACKUP_INTEGRITY_FAILED", "CONFIG_VIOLATION"
    };
    if (c >= 0 && c <= OZAYN_SINTEL_EXPLAIN_CONFIG_VIOLATION)
        return names[c];
    return "UNKNOWN";
}

int ozayn_sintel_severity_to_audit_severity(ozayn_sintel_severity_t sev)
{
    switch (sev) {
    case OZAYN_SINTEL_SEV_INFO:     return 0;
    case OZAYN_SINTEL_SEV_NOTICE:   return 1;
    case OZAYN_SINTEL_SEV_WARNING:  return 2;
    case OZAYN_SINTEL_SEV_HIGH:     return 3;
    case OZAYN_SINTEL_SEV_CRITICAL: return 4;
    }
    return 0;
}

int ozayn_sintel_severity_to_salert_severity(ozayn_sintel_severity_t sev)
{
    switch (sev) {
    case OZAYN_SINTEL_SEV_INFO:     return 0;
    case OZAYN_SINTEL_SEV_NOTICE:   return 1;
    case OZAYN_SINTEL_SEV_WARNING:  return 2;
    case OZAYN_SINTEL_SEV_HIGH:     return 3;
    case OZAYN_SINTEL_SEV_CRITICAL: return 4;
    }
    return 0;
}

int ozayn_sintel_severity_to_ir_severity(ozayn_sintel_severity_t sev)
{
    switch (sev) {
    case OZAYN_SINTEL_SEV_INFO:     return 0;
    case OZAYN_SINTEL_SEV_NOTICE:   return 1;
    case OZAYN_SINTEL_SEV_WARNING:  return 2;
    case OZAYN_SINTEL_SEV_HIGH:     return 3;
    case OZAYN_SINTEL_SEV_CRITICAL: return 4;
    }
    return 0;
}

/* ============================================================
 * SECTION 22 — LIFECYCLE
 * ============================================================ */

ozayn_sintel_err_t ozayn_sintel_service_init(
    ozayn_sintel_service_t *svc,
    const ozayn_sintel_service_config_t *cfg)
{
    if (!svc) return OZAYN_SINTEL_ERR_NULL;
    if (svc->initialized) return OZAYN_SINTEL_ERR_ALREADY_INITIALIZED;

    memset(svc, 0, sizeof(*svc));

    if (cfg) {
        svc->detect_service    = cfg->detect_service;
        svc->incident_service  = cfg->incident_service;
        svc->alert_service     = cfg->alert_service;
        svc->audit             = cfg->audit;
    }

    svc->policy = ozayn_sintel_default_policy();
    svc->initialized = 1;
    return OZAYN_SINTEL_OK;
}

void ozayn_sintel_service_shutdown(ozayn_sintel_service_t *svc)
{
    if (!svc) return;
    svc->initialized = 0;
}

int ozayn_sintel_service_is_initialized(const ozayn_sintel_service_t *svc)
{
    return svc ? svc->initialized : 0;
}

/* ============================================================
 * SECTION 24 — EVIDENCE OPERATIONS
 * ============================================================ */

ozayn_sintel_err_t ozayn_sintel_collect_evidence(
    ozayn_sintel_service_t *svc,
    const ozayn_sintel_evidence_t *evidence,
    ozayn_sintel_evidence_t **out_stored)
{
    if (!svc) return OZAYN_SINTEL_ERR_NULL;
    if (!svc->initialized) return OZAYN_SINTEL_ERR_NOT_INITIALIZED;
    if (!evidence) return OZAYN_SINTEL_ERR_NULL;
    if (!out_stored) return OZAYN_SINTEL_ERR_NULL;
    if (!svc->policy.enabled) return OZAYN_SINTEL_ERR_POLICY_REJECTED;
    if (svc->evidence_count >= OZAYN_SINTEL_MAX_EVIDENCE)
        return OZAYN_SINTEL_ERR_RESOURCE_EXHAUSTED;
    if (svc->evidence_count >= svc->policy.max_evidence &&
        svc->policy.max_evidence > 0)
        return OZAYN_SINTEL_ERR_LIMIT_REACHED;

    if (ozayn_sintel_evidence_is_duplicate(svc, evidence->evidence_type,
            evidence->source_event_id, evidence->identity_id)) {
        *out_stored = NULL;
        return OZAYN_SINTEL_OK;
    }

    ozayn_sintel_evidence_t *e = _alloc_evidence(svc);
    *e = *evidence;
    if (!e->evidence_id[0])
        _generate_id(e->evidence_id, OZAYN_SINTEL_MAX_ID_LEN,
                     "SEVID", svc->evidence_sequence++);
    if (e->timestamp == 0) e->timestamp = time(NULL);
    e->evidence_version++;

    svc->total_evidence_collected++;
    _audit_event(svc, "EVIDENCE_COLLECTED", e->evidence_id);
    *out_stored = e;
    return OZAYN_SINTEL_OK;
}

ozayn_sintel_err_t ozayn_sintel_validate_evidence(
    ozayn_sintel_service_t *svc,
    ozayn_sintel_evidence_t *evidence)
{
    if (!svc) return OZAYN_SINTEL_ERR_NULL;
    if (!svc->initialized) return OZAYN_SINTEL_ERR_NOT_INITIALIZED;
    if (!evidence) return OZAYN_SINTEL_ERR_NULL;

    if (evidence->status == OZAYN_SINTEL_EVID_STATUS_REVOKED)
        return OZAYN_SINTEL_ERR_EVIDENCE_REVOKED;
    if (evidence->status == OZAYN_SINTEL_EVID_STATUS_EXPIRED)
        return OZAYN_SINTEL_ERR_EVIDENCE_EXPIRED;

    evidence->status = OZAYN_SINTEL_EVID_STATUS_VALIDATING;
    evidence->reliability = ozayn_sintel_assess_reliability(evidence);

    if (evidence->integrity_state == OZAYN_SINTEL_INTEGRITY_INVALID) {
        evidence->status = OZAYN_SINTEL_EVID_STATUS_INVALID;
        evidence->reliability = OZAYN_SINTEL_RELIABILITY_LOW;
        svc->total_evidence_rejected++;
        _audit_event(svc, "EVIDENCE_INTEGRITY_FAILURE", evidence->evidence_id);
        return OZAYN_SINTEL_ERR_INTEGRITY_FAILURE;
    }

    evidence->status = OZAYN_SINTEL_EVID_STATUS_VALID;
    svc->total_evidence_validated++;
    _audit_event(svc, "EVIDENCE_VALIDATED", evidence->evidence_id);
    return OZAYN_SINTEL_OK;
}

ozayn_sintel_evidence_t *ozayn_sintel_get_evidence(
    ozayn_sintel_service_t *svc,
    const char *evidence_id)
{
    if (!svc || !evidence_id) return NULL;
    for (int i = 0; i < svc->evidence_count; i++) {
        int slot = (svc->evidence_head + i) % OZAYN_SINTEL_MAX_EVIDENCE;
        if (strcmp(svc->evidence[slot].evidence_id, evidence_id) == 0)
            return &svc->evidence[slot];
    }
    return NULL;
}

int ozayn_sintel_evidence_count(const ozayn_sintel_service_t *svc)
{
    return svc ? svc->evidence_count : 0;
}

int ozayn_sintel_list_evidence(
    const ozayn_sintel_service_t *svc,
    int filter_type,
    ozayn_sintel_evidence_t **out_evidence,
    int max_count)
{
    if (!svc || !out_evidence || max_count <= 0) return 0;
    int count = 0;
    for (int i = 0; i < svc->evidence_count && count < max_count; i++) {
        int slot = (svc->evidence_head + i) % OZAYN_SINTEL_MAX_EVIDENCE;
        const ozayn_sintel_evidence_t *e = &svc->evidence[slot];
        int type_match = (filter_type < 0 ||
                          e->evidence_type == (ozayn_sintel_evidence_type_t)filter_type);
        if (type_match) {
            out_evidence[count] = (ozayn_sintel_evidence_t *)e;
            count++;
        }
    }
    return count;
}

int ozayn_sintel_evidence_is_duplicate(
    const ozayn_sintel_service_t *svc,
    ozayn_sintel_evidence_type_t type,
    const char *source_event_id,
    const char *identity_id)
{
    if (!svc || !source_event_id) return 0;
    time_t now = time(NULL);
    int window = svc->policy.dedup_window_seconds;
    if (window <= 0) window = 300;

    for (int i = 0; i < svc->evidence_count; i++) {
        int slot = (svc->evidence_head + i) % OZAYN_SINTEL_MAX_EVIDENCE;
        const ozayn_sintel_evidence_t *e = &svc->evidence[slot];
        if (e->evidence_type != type) continue;
        if (e->status == OZAYN_SINTEL_EVID_STATUS_REVOKED ||
            e->status == OZAYN_SINTEL_EVID_STATUS_EXPIRED)
            continue;
        if ((now - e->timestamp) > window) continue;
        if (strcmp(e->source_event_id, source_event_id) != 0) continue;
        if (identity_id && identity_id[0] && e->identity_id[0] &&
            strcmp(e->identity_id, identity_id) != 0)
            continue;
        return 1;
    }
    return 0;
}

/* ============================================================
 * SECTION 25 — EVIDENCE SET OPERATIONS
 * ============================================================ */

ozayn_sintel_err_t ozayn_sintel_create_evidence_set(
    ozayn_sintel_service_t *svc,
    const char *finding_id,
    const char *correlation_id,
    ozayn_sintel_evidence_set_t **out_set)
{
    if (!svc) return OZAYN_SINTEL_ERR_NULL;
    if (!svc->initialized) return OZAYN_SINTEL_ERR_NOT_INITIALIZED;
    if (!out_set) return OZAYN_SINTEL_ERR_NULL;
    if (svc->set_count >= OZAYN_SINTEL_MAX_EVIDENCE_SETS)
        return OZAYN_SINTEL_ERR_SET_LIMIT;
    if (svc->set_count >= svc->policy.max_evidence_sets &&
        svc->policy.max_evidence_sets > 0)
        return OZAYN_SINTEL_ERR_LIMIT_REACHED;

    ozayn_sintel_evidence_set_t *set = &svc->evidence_sets[svc->set_count];
    memset(set, 0, sizeof(*set));
    _generate_id(set->set_id, OZAYN_SINTEL_MAX_ID_LEN,
                 "SSET", svc->total_sets_created + 1);
    if (finding_id)
        strncpy(set->finding_id, finding_id, OZAYN_SINTEL_MAX_ID_LEN - 1);
    if (correlation_id)
        strncpy(set->correlation_id, correlation_id, OZAYN_SINTEL_MAX_ID_LEN - 1);
    set->first_observation = time(NULL);
    set->last_observation = time(NULL);
    set->assessment_state = OZAYN_SINTEL_ASSESS_PENDING;
    set->reliability_summary = OZAYN_SINTEL_RELIABILITY_UNKNOWN;
    set->relevance_summary = OZAYN_SINTEL_RELEVANCE_IRRELEVANT;

    svc->set_count++;
    svc->total_sets_created++;
    *out_set = set;
    return OZAYN_SINTEL_OK;
}

ozayn_sintel_err_t ozayn_sintel_add_to_evidence_set(
    ozayn_sintel_service_t *svc,
    const char *set_id,
    const char *evidence_id,
    ozayn_sintel_evidence_role_t role)
{
    if (!svc) return OZAYN_SINTEL_ERR_NULL;
    if (!svc->initialized) return OZAYN_SINTEL_ERR_NOT_INITIALIZED;
    if (!set_id || !evidence_id) return OZAYN_SINTEL_ERR_INVALID_PARAM;

    ozayn_sintel_evidence_set_t *set = NULL;
    for (int i = 0; i < svc->set_count; i++) {
        if (strcmp(svc->evidence_sets[i].set_id, set_id) == 0) {
            set = &svc->evidence_sets[i];
            break;
        }
    }
    if (!set) return OZAYN_SINTEL_ERR_NOT_FOUND;

    if (set->evidence_count >= OZAYN_SINTEL_MAX_EVIDENCE_PER_SET)
        return OZAYN_SINTEL_ERR_LIMIT_REACHED;

    ozayn_sintel_evidence_t *ev = ozayn_sintel_get_evidence(svc, evidence_id);
    if (!ev) return OZAYN_SINTEL_ERR_NOT_FOUND;

    set->evidence_count++;
    set->last_observation = time(NULL);

    switch (role) {
    case OZAYN_SINTEL_ROLE_PRIMARY:    set->primary_count++; break;
    case OZAYN_SINTEL_ROLE_SUPPORTING: set->supporting_count++; break;
    case OZAYN_SINTEL_ROLE_CONFLICTING: set->conflicting_count++; break;
    case OZAYN_SINTEL_ROLE_CONTEXTUAL: set->contextual_count++; break;
    }

    if (ev->reliability > set->reliability_summary)
        set->reliability_summary = ev->reliability;
    if (ev->relevance > set->relevance_summary)
        set->relevance_summary = ev->relevance;

    return OZAYN_SINTEL_OK;
}

ozayn_sintel_evidence_set_t *ozayn_sintel_get_evidence_set(
    ozayn_sintel_service_t *svc,
    const char *set_id)
{
    if (!svc || !set_id) return NULL;
    for (int i = 0; i < svc->set_count; i++) {
        if (strcmp(svc->evidence_sets[i].set_id, set_id) == 0)
            return &svc->evidence_sets[i];
    }
    return NULL;
}

int ozayn_sintel_evidence_set_count(const ozayn_sintel_service_t *svc)
{
    return svc ? svc->set_count : 0;
}

int ozayn_sintel_list_evidence_sets(
    const ozayn_sintel_service_t *svc,
    const char *finding_id,
    ozayn_sintel_evidence_set_t **out_sets,
    int max_count)
{
    if (!svc || !out_sets || max_count <= 0) return 0;
    int count = 0;
    for (int i = 0; i < svc->set_count && count < max_count; i++) {
        const ozayn_sintel_evidence_set_t *s = &svc->evidence_sets[i];
        if (!finding_id || !finding_id[0] ||
            strcmp(s->finding_id, finding_id) == 0) {
            out_sets[count] = (ozayn_sintel_evidence_set_t *)s;
            count++;
        }
    }
    return count;
}

/* ============================================================
 * SECTION 26 — RELIABILITY ASSESSMENT
 * ============================================================ */

ozayn_sintel_reliability_t ozayn_sintel_assess_reliability(
    const ozayn_sintel_evidence_t *evidence)
{
    if (!evidence) return OZAYN_SINTEL_RELIABILITY_UNKNOWN;

    if (evidence->integrity_state == OZAYN_SINTEL_INTEGRITY_INVALID)
        return OZAYN_SINTEL_RELIABILITY_LOW;
    if (evidence->integrity_state == OZAYN_SINTEL_INTEGRITY_UNAVAILABLE)
        return OZAYN_SINTEL_RELIABILITY_UNKNOWN;

    switch (evidence->evidence_type) {
    case OZAYN_SINTEL_EVID_AUDIT_EVENT:
        if (evidence->integrity_state == OZAYN_SINTEL_INTEGRITY_VALID)
            return OZAYN_SINTEL_RELIABILITY_HIGH;
        return OZAYN_SINTEL_RELIABILITY_MEDIUM;
    case OZAYN_SINTEL_EVID_AUDIT_INTEGRITY:
        if (evidence->integrity_state == OZAYN_SINTEL_INTEGRITY_VALID)
            return OZAYN_SINTEL_RELIABILITY_VERIFIED;
        return OZAYN_SINTEL_RELIABILITY_LOW;
    case OZAYN_SINTEL_EVID_HEALTH_RESULT:
    case OZAYN_SINTEL_EVID_DIAGNOSTIC_RESULT:
        return OZAYN_SINTEL_RELIABILITY_MEDIUM;
    case OZAYN_SINTEL_EVID_CORRELATION_RESULT:
    case OZAYN_SINTEL_EVID_THREAT_FINDING:
        return OZAYN_SINTEL_RELIABILITY_HIGH;
    case OZAYN_SINTEL_EVID_INCIDENT_RESULT:
        return OZAYN_SINTEL_RELIABILITY_HIGH;
    default:
        return OZAYN_SINTEL_RELIABILITY_MEDIUM;
    }
}

ozayn_sintel_relevance_t ozayn_sintel_assess_relevance(
    const ozayn_sintel_service_t *svc,
    const ozayn_sintel_evidence_t *evidence,
    const char *finding_id)
{
    if (!svc || !evidence) return OZAYN_SINTEL_RELEVANCE_IRRELEVANT;
    (void)finding_id;

    if (evidence->severity >= OZAYN_SINTEL_SEV_CRITICAL)
        return OZAYN_SINTEL_RELEVANCE_CRITICAL;
    if (evidence->severity >= OZAYN_SINTEL_SEV_HIGH)
        return OZAYN_SINTEL_RELEVANCE_HIGH;
    if (evidence->severity >= OZAYN_SINTEL_SEV_WARNING)
        return OZAYN_SINTEL_RELEVANCE_MEDIUM;
    return OZAYN_SINTEL_RELEVANCE_LOW;
}

/* ============================================================
 * SECTION 27 — THREAT ASSESSMENT OPERATIONS
 * ============================================================ */

ozayn_sintel_err_t ozayn_sintel_create_assessment(
    ozayn_sintel_service_t *svc,
    const char *finding_id,
    const char *evidence_set_id,
    ozayn_sintel_assessment_t **out_assessment)
{
    if (!svc) return OZAYN_SINTEL_ERR_NULL;
    if (!svc->initialized) return OZAYN_SINTEL_ERR_NOT_INITIALIZED;
    if (!out_assessment) return OZAYN_SINTEL_ERR_NULL;
    if (svc->assessment_count >= OZAYN_SINTEL_MAX_ASSESSMENTS)
        return OZAYN_SINTEL_ERR_ASSESSMENT_LIMIT;
    if (svc->assessment_count >= svc->policy.max_assessments &&
        svc->policy.max_assessments > 0)
        return OZAYN_SINTEL_ERR_LIMIT_REACHED;

    ozayn_sintel_assessment_t *a = _alloc_assessment(svc);
    _generate_id(a->assessment_id, OZAYN_SINTEL_MAX_ID_LEN,
                 "SASMT", svc->assessment_sequence + 1);
    svc->assessment_sequence++;
    a->state = OZAYN_SINTEL_ASSESS_PENDING;
    a->severity = OZAYN_SINTEL_SEV_INFO;
    a->confidence = OZAYN_SINTEL_CONFIDENCE_LOW;
    a->reliability = OZAYN_SINTEL_RELIABILITY_UNKNOWN;
    a->impact = OZAYN_SINTEL_IMPACT_NONE;
    a->threat_category = OZAYN_SINTEL_THREAT_UNKNOWN;
    a->recommended_response = OZAYN_SINTEL_RESPONSE_NONE;
    a->created_time = time(NULL);
    a->updated_time = a->created_time;

    if (finding_id)
        strncpy(a->finding_id, finding_id, OZAYN_SINTEL_MAX_ID_LEN - 1);
    if (evidence_set_id)
        strncpy(a->evidence_set_id, evidence_set_id, OZAYN_SINTEL_MAX_ID_LEN - 1);

    svc->total_assessments_created++;
    _audit_event(svc, "ASSESSMENT_CREATED", a->assessment_id);
    *out_assessment = a;
    return OZAYN_SINTEL_OK;
}

static int _valid_assessment_transition(ozayn_sintel_assessment_state_t from,
                                         ozayn_sintel_assessment_state_t to)
{
    switch (from) {
    case OZAYN_SINTEL_ASSESS_PENDING:
        return to == OZAYN_SINTEL_ASSESS_ASSESSING ||
               to == OZAYN_SINTEL_ASSESS_INVALID;
    case OZAYN_SINTEL_ASSESS_ASSESSING:
        return to == OZAYN_SINTEL_ASSESS_ASSESSED ||
               to == OZAYN_SINTEL_ASSESS_INVALID;
    case OZAYN_SINTEL_ASSESS_ASSESSED:
        return to == OZAYN_SINTEL_ASSESS_ESCALATED ||
               to == OZAYN_SINTEL_ASSESS_DISPUTED ||
               to == OZAYN_SINTEL_ASSESS_EXPIRED;
    case OZAYN_SINTEL_ASSESS_ESCALATED:
        return to == OZAYN_SINTEL_ASSESS_EXPIRED;
    case OZAYN_SINTEL_ASSESS_DISPUTED:
        return to == OZAYN_SINTEL_ASSESS_EXPIRED;
    case OZAYN_SINTEL_ASSESS_INVALID:
        return 0;
    case OZAYN_SINTEL_ASSESS_EXPIRED:
        return 0;
    }
    return 0;
}

ozayn_sintel_err_t ozayn_sintel_complete_assessment(
    ozayn_sintel_service_t *svc,
    const char *assessment_id)
{
    if (!svc) return OZAYN_SINTEL_ERR_NULL;
    if (!svc->initialized) return OZAYN_SINTEL_ERR_NOT_INITIALIZED;
    ozayn_sintel_assessment_t *a = ozayn_sintel_get_assessment(svc, assessment_id);
    if (!a) return OZAYN_SINTEL_ERR_NOT_FOUND;
    if (!_valid_assessment_transition(a->state, OZAYN_SINTEL_ASSESS_ASSESSED))
        return OZAYN_SINTEL_ERR_STATE_TRANSITION;
    a->state = OZAYN_SINTEL_ASSESS_ASSESSED;
    a->updated_time = time(NULL);
    svc->total_assessments_completed++;
    _audit_event(svc, "ASSESSMENT_COMPLETED", a->assessment_id);
    return OZAYN_SINTEL_OK;
}

ozayn_sintel_err_t ozayn_sintel_escalate_assessment(
    ozayn_sintel_service_t *svc,
    const char *assessment_id)
{
    if (!svc) return OZAYN_SINTEL_ERR_NULL;
    if (!svc->initialized) return OZAYN_SINTEL_ERR_NOT_INITIALIZED;
    ozayn_sintel_assessment_t *a = ozayn_sintel_get_assessment(svc, assessment_id);
    if (!a) return OZAYN_SINTEL_ERR_NOT_FOUND;
    if (!_valid_assessment_transition(a->state, OZAYN_SINTEL_ASSESS_ESCALATED))
        return OZAYN_SINTEL_ERR_STATE_TRANSITION;
    a->state = OZAYN_SINTEL_ASSESS_ESCALATED;
    a->updated_time = time(NULL);
    svc->total_assessments_escalated++;
    _audit_event(svc, "ASSESSMENT_ESCALATED", a->assessment_id);
    return OZAYN_SINTEL_OK;
}

ozayn_sintel_assessment_t *ozayn_sintel_get_assessment(
    ozayn_sintel_service_t *svc,
    const char *assessment_id)
{
    if (!svc || !assessment_id) return NULL;
    for (int i = 0; i < svc->assessment_count; i++) {
        int slot = (svc->assessment_head + i) % OZAYN_SINTEL_MAX_ASSESSMENTS;
        if (strcmp(svc->assessments[slot].assessment_id, assessment_id) == 0)
            return &svc->assessments[slot];
    }
    return NULL;
}

int ozayn_sintel_assessment_count(const ozayn_sintel_service_t *svc)
{
    return svc ? svc->assessment_count : 0;
}

int ozayn_sintel_list_assessments(
    const ozayn_sintel_service_t *svc,
    int filter_state,
    ozayn_sintel_assessment_t **out_assessments,
    int max_count)
{
    if (!svc || !out_assessments || max_count <= 0) return 0;
    int count = 0;
    for (int i = 0; i < svc->assessment_count && count < max_count; i++) {
        int slot = (svc->assessment_head + i) % OZAYN_SINTEL_MAX_ASSESSMENTS;
        const ozayn_sintel_assessment_t *a = &svc->assessments[slot];
        int state_match = (filter_state < 0 ||
                           a->state == (ozayn_sintel_assessment_state_t)filter_state);
        if (state_match) {
            out_assessments[count] = (ozayn_sintel_assessment_t *)a;
            count++;
        }
    }
    return count;
}

/* ============================================================
 * SECTION 28 — ASSESSMENT EVALUATION
 * ============================================================ */

ozayn_sintel_err_t ozayn_sintel_evaluate_assessment(
    ozayn_sintel_service_t *svc,
    ozayn_sintel_assessment_t *assessment)
{
    if (!svc || !assessment) return OZAYN_SINTEL_ERR_NULL;

    if (assessment->state == OZAYN_SINTEL_ASSESS_PENDING) {
        assessment->state = OZAYN_SINTEL_ASSESS_ASSESSING;
        assessment->updated_time = time(NULL);
    }

    ozayn_sintel_evidence_set_t *set =
        ozayn_sintel_get_evidence_set(svc, assessment->evidence_set_id);

    if (set) {
        assessment->reliability = set->reliability_summary;
        assessment->confidence = ozayn_sintel_calculate_confidence(svc, set);

        if (set->primary_count >= 2 && set->supporting_count >= 2)
            assessment->severity = OZAYN_SINTEL_SEV_CRITICAL;
        else if (set->primary_count >= 1 && set->supporting_count >= 1)
            assessment->severity = OZAYN_SINTEL_SEV_HIGH;
        else if (set->primary_count >= 1)
            assessment->severity = OZAYN_SINTEL_SEV_WARNING;
        else
            assessment->severity = OZAYN_SINTEL_SEV_NOTICE;

        if (set->conflicting_count > set->primary_count) {
            assessment->confidence = OZAYN_SINTEL_CONFIDENCE_LOW;
            assessment->impact = OZAYN_SINTEL_IMPACT_LOW;
        }

        if (set->evidence_count >= 4 && set->primary_count >= 2)
            assessment->impact = OZAYN_SINTEL_IMPACT_HIGH;
        else if (set->evidence_count >= 2)
            assessment->impact = OZAYN_SINTEL_IMPACT_MODERATE;
        else
            assessment->impact = OZAYN_SINTEL_IMPACT_LOW;

        if (set->evidence_count >= svc->policy.min_evidence_for_assessment &&
            assessment->reliability >= (ozayn_sintel_reliability_t)svc->policy.min_reliability_for_assessment) {
            if (assessment->severity >= OZAYN_SINTEL_SEV_HIGH)
                assessment->recommended_response = OZAYN_SINTEL_RESPONSE_ESCALATE_INCIDENT;
            else if (assessment->severity >= OZAYN_SINTEL_SEV_WARNING)
                assessment->recommended_response = OZAYN_SINTEL_RESPONSE_INVESTIGATE;
            else
                assessment->recommended_response = OZAYN_SINTEL_RESPONSE_MONITOR;
        }
    }

    if (assessment->severity >= OZAYN_SINTEL_SEV_HIGH &&
        assessment->confidence >= OZAYN_SINTEL_CONFIDENCE_HIGH)
        assessment->threat_category = OZAYN_SINTEL_THREAT_AUTH;
    else
        assessment->threat_category = OZAYN_SINTEL_THREAT_UNKNOWN;

    assessment->updated_time = time(NULL);
    return OZAYN_SINTEL_OK;
}

ozayn_sintel_err_t ozayn_sintel_add_explanation(
    ozayn_sintel_assessment_t *assessment,
    ozayn_sintel_explanation_code_t code)
{
    if (!assessment) return OZAYN_SINTEL_ERR_NULL;
    if (assessment->explanation_count >= OZAYN_SINTEL_MAX_EXPLANATIONS)
        return OZAYN_SINTEL_ERR_LIMIT_REACHED;
    for (int i = 0; i < assessment->explanation_count; i++) {
        if (assessment->explanations[i] == code)
            return OZAYN_SINTEL_OK;
    }
    assessment->explanations[assessment->explanation_count++] = code;
    return OZAYN_SINTEL_OK;
}

/* ============================================================
 * SECTION 29 — DETERMINISTIC CONFIDENCE
 * ============================================================ */

ozayn_sintel_confidence_t ozayn_sintel_calculate_confidence(
    const ozayn_sintel_service_t *svc,
    const ozayn_sintel_evidence_set_t *set)
{
    if (!svc || !set) return OZAYN_SINTEL_CONFIDENCE_LOW;

    int score = 0;

    if (set->primary_count >= 3) score += 3;
    else if (set->primary_count >= 2) score += 2;
    else if (set->primary_count >= 1) score += 1;

    if (set->supporting_count >= 3) score += 2;
    else if (set->supporting_count >= 1) score += 1;

    if (set->conflicting_count > 0) score -= set->conflicting_count;

    if (set->reliability_summary >= OZAYN_SINTEL_RELIABILITY_HIGH) score += 2;
    else if (set->reliability_summary >= OZAYN_SINTEL_RELIABILITY_MEDIUM) score += 1;

    if (set->reliability_summary == OZAYN_SINTEL_RELIABILITY_UNKNOWN) score -= 2;
    if (set->relevance_summary >= OZAYN_SINTEL_RELEVANCE_HIGH) score += 1;

    if (score >= 6) return OZAYN_SINTEL_CONFIDENCE_VERY_HIGH;
    if (score >= 4) return OZAYN_SINTEL_CONFIDENCE_HIGH;
    if (score >= 2) return OZAYN_SINTEL_CONFIDENCE_MEDIUM;
    return OZAYN_SINTEL_CONFIDENCE_LOW;
}

/* ============================================================
 * SECTION 30 — INCIDENT INTEGRATION
 * ============================================================ */

ozayn_sintel_err_t ozayn_sintel_create_incident_from_assessment(
    ozayn_sintel_service_t *svc,
    ozayn_sintel_assessment_t *assessment)
{
    if (!svc || !assessment) return OZAYN_SINTEL_ERR_NULL;
    if (!svc->incident_service || !svc->incident_service->initialized)
        return OZAYN_SINTEL_ERR_UNAVAILABLE;
    if (!svc->policy.incident_integration_enabled)
        return OZAYN_SINTEL_ERR_POLICY_REJECTED;

    ozayn_sintel_assessment_state_t allowed[] = {
        OZAYN_SINTEL_ASSESS_ASSESSED,
        OZAYN_SINTEL_ASSESS_ESCALATED
    };
    int ok = 0;
    for (int i = 0; i < 2; i++) {
        if (assessment->state == allowed[i]) { ok = 1; break; }
    }
    if (!ok) return OZAYN_SINTEL_ERR_STATE_TRANSITION;

    ozayn_ir_severity_t ir_sev = (ozayn_ir_severity_t)
        ozayn_sintel_severity_to_ir_severity(assessment->severity);

    ozayn_ir_incident_t *ir_inc = NULL;
    ozayn_ir_result_t rc = ozayn_ir_report(
        svc->incident_service,
        OZAYN_IR_TYPE_SUSPICIOUS_ACTIVITY,
        ir_sev,
        "SEC_INTEL",
        "",
        "",
        "",
        "",
        assessment->safe_metadata,
        &ir_inc);

    if (rc == OZAYN_IR_OK) {
        svc->total_incidents_created++;
        _audit_event(svc, "INCIDENT_CREATED_FROM_ASSESSMENT",
                     assessment->assessment_id);
    }
    return OZAYN_SINTEL_OK;
}

/* ============================================================
 * SECTION 31 — ALERT INTEGRATION
 * ============================================================ */

ozayn_sintel_err_t ozayn_sintel_create_alert_from_assessment(
    ozayn_sintel_service_t *svc,
    ozayn_sintel_assessment_t *assessment)
{
    if (!svc || !assessment) return OZAYN_SINTEL_ERR_NULL;
    if (!svc->alert_service || !svc->alert_service->initialized)
        return OZAYN_SINTEL_ERR_UNAVAILABLE;
    if (!svc->policy.alert_integration_enabled)
        return OZAYN_SINTEL_ERR_POLICY_REJECTED;

    ozayn_salert_severity_t al_sev = OZAYN_SALERT_SEV_NOTICE;
    switch (assessment->severity) {
    case OZAYN_SINTEL_SEV_INFO:     al_sev = OZAYN_SALERT_SEV_INFO; break;
    case OZAYN_SINTEL_SEV_NOTICE:   al_sev = OZAYN_SALERT_SEV_NOTICE; break;
    case OZAYN_SINTEL_SEV_WARNING:  al_sev = OZAYN_SALERT_SEV_WARNING; break;
    case OZAYN_SINTEL_SEV_HIGH:     al_sev = OZAYN_SALERT_SEV_HIGH; break;
    case OZAYN_SINTEL_SEV_CRITICAL: al_sev = OZAYN_SALERT_SEV_CRITICAL; break;
    }

    ozayn_salert_priority_t prio = OZAYN_SALERT_PRIO_NORMAL;
    if (assessment->severity == OZAYN_SINTEL_SEV_CRITICAL)
        prio = OZAYN_SALERT_PRIO_IMMEDIATE;
    else if (assessment->severity == OZAYN_SINTEL_SEV_HIGH)
        prio = OZAYN_SALERT_PRIO_HIGH;

    ozayn_salert_alert_t *alert = NULL;
    ozayn_salert_err_t rc = ozayn_salert_create(
        svc->alert_service,
        OZAYN_SALERT_TYPE_AUTH_ATTACK,
        al_sev,
        prio,
        OZAYN_SALERT_SOURCE_SECURITY_EVENT,
        "SEC_INTEL",
        assessment->evidence_set_id,
        assessment->finding_id,
        assessment->safe_metadata,
        &alert);

    if (rc == OZAYN_SALERT_OK && alert) {
        svc->total_alerts_created++;
        _audit_event(svc, "ALERT_CREATED_FROM_ASSESSMENT",
                     assessment->assessment_id);
    }
    return OZAYN_SINTEL_OK;
}

/* ============================================================
 * SECTION 32 — AUDIT INTEGRATION
 * ============================================================ */

ozayn_sintel_err_t ozayn_sintel_audit_event(
    ozayn_sintel_service_t *svc,
    const char *event_type,
    const char *detail)
{
    if (!svc) return OZAYN_SINTEL_ERR_NULL;
    _audit_event(svc, event_type, detail);
    return OZAYN_SINTEL_OK;
}

/* ============================================================
 * SECTION 33 — POLICY
 * ============================================================ */

ozayn_sintel_policy_t ozayn_sintel_default_policy(void)
{
    ozayn_sintel_policy_t p;
    memset(&p, 0, sizeof(p));
    p.enabled = 1;
    p.max_evidence = OZAYN_SINTEL_MAX_EVIDENCE;
    p.max_evidence_sets = OZAYN_SINTEL_MAX_EVIDENCE_SETS;
    p.max_assessments = OZAYN_SINTEL_MAX_ASSESSMENTS;
    p.evidence_retention_seconds = 86400;
    p.dedup_window_seconds = 300;
    p.min_reliability_for_assessment = OZAYN_SINTEL_RELIABILITY_MEDIUM;
    p.min_evidence_for_assessment = 2;
    p.incident_integration_enabled = 1;
    p.alert_integration_enabled = 1;
    return p;
}

ozayn_sintel_err_t ozayn_sintel_set_policy(
    ozayn_sintel_service_t *svc,
    const ozayn_sintel_policy_t *policy)
{
    if (!svc || !policy) return OZAYN_SINTEL_ERR_NULL;
    if (!svc->initialized) return OZAYN_SINTEL_ERR_NOT_INITIALIZED;
    if (!policy->enabled) return OZAYN_SINTEL_ERR_POLICY_REJECTED;
    svc->policy = *policy;
    return OZAYN_SINTEL_OK;
}

const ozayn_sintel_policy_t *ozayn_sintel_get_policy(
    const ozayn_sintel_service_t *svc)
{
    return svc ? &svc->policy : NULL;
}

/* ============================================================
 * SECTION 34 — CLEANUP
 * ============================================================ */

int ozayn_sintel_cleanup_expired_evidence(ozayn_sintel_service_t *svc)
{
    if (!svc) return 0;
    time_t now = time(NULL);
    int cleaned = 0;
    int retention = svc->policy.evidence_retention_seconds;
    if (retention <= 0) retention = 86400;

    for (int i = 0; i < svc->evidence_count; i++) {
        int slot = (svc->evidence_head + i) % OZAYN_SINTEL_MAX_EVIDENCE;
        ozayn_sintel_evidence_t *e = &svc->evidence[slot];
        if (e->status == OZAYN_SINTEL_EVID_STATUS_REVOKED) continue;
        if ((now - e->timestamp) > retention) {
            e->status = OZAYN_SINTEL_EVID_STATUS_EXPIRED;
            cleaned++;
        }
    }
    svc->total_evidence_expired += cleaned;
    return cleaned;
}

int ozayn_sintel_cleanup_expired_assessments(ozayn_sintel_service_t *svc)
{
    if (!svc) return 0;
    int cleaned = 0;
    for (int i = 0; i < svc->assessment_count; i++) {
        int slot = (svc->assessment_head + i) % OZAYN_SINTEL_MAX_ASSESSMENTS;
        ozayn_sintel_assessment_t *a = &svc->assessments[slot];
        if (a->state == OZAYN_SINTEL_ASSESS_ESCALATED) continue;
        if (a->state == OZAYN_SINTEL_ASSESS_INVALID) continue;
        if (a->state == OZAYN_SINTEL_ASSESS_EXPIRED) continue;
        time_t now = time(NULL);
        if ((now - a->created_time) > svc->policy.evidence_retention_seconds) {
            a->state = OZAYN_SINTEL_ASSESS_EXPIRED;
            cleaned++;
        }
    }
    return cleaned;
}

/* ============================================================
 * SECTION 35 — RESOURCE SAFETY
 * ============================================================ */

int ozayn_sintel_evidence_full(const ozayn_sintel_service_t *svc)
{
    if (!svc) return 1;
    return svc->evidence_count >= OZAYN_SINTEL_MAX_EVIDENCE;
}

int ozayn_sintel_sets_full(const ozayn_sintel_service_t *svc)
{
    if (!svc) return 1;
    return svc->set_count >= OZAYN_SINTEL_MAX_EVIDENCE_SETS;
}

int ozayn_sintel_assessments_full(const ozayn_sintel_service_t *svc)
{
    if (!svc) return 1;
    return svc->assessment_count >= OZAYN_SINTEL_MAX_ASSESSMENTS;
}
