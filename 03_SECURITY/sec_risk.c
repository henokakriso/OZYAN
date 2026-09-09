/*
 * sec_risk.c — Security Risk Scoring & Decision Support Foundation (Step 33).
 */

#include "sec_risk.h"
#include <stdio.h>
#include <string.h>
#include <time.h>

/* ============================================================
 * GLOBAL SINGLETON
 * ============================================================ */

static ozayn_sr_service_t _srisk_global = {0};

ozayn_sr_service_t *ozayn_sr_get_global(void)
{
    return &_srisk_global;
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

static void _audit_event(ozayn_sr_service_t *svc,
                          const char *event_type,
                          const char *detail)
{
    if (!svc->audit || !svc->audit->initialized) return;
    ozayn_audit_event_t ev;
    ozayn_audit_event_init(&ev);
    ozayn_audit_event_set_type(&ev, OZAYN_AUDIT_CONFIG_CHANGED);
    ozayn_audit_event_set_outcome(&ev, OZAYN_AUDIT_OUTCOME_SUCCESS);
    ozayn_audit_event_set_severity(&ev, OZAYN_AUDIT_SEV_NOTICE);
    ozayn_audit_event_set_source(&ev, "SEC_RISK");
    char buf[512];
    snprintf(buf, sizeof(buf), "%s: %s", event_type,
             detail ? detail : "N/A");
    ozayn_audit_event_set_detail(&ev, buf);
    ozayn_audit_record(svc->audit, &ev);
}

static ozayn_sr_assessment_t *_alloc_assessment(ozayn_sr_service_t *svc)
{
    if (svc->assessment_count >= OZAYN_SR_MAX_ASSESSMENTS) {
        svc->assessment_head = (svc->assessment_head + 1) % OZAYN_SR_MAX_ASSESSMENTS;
        svc->assessment_count--;
    }
    int slot = (svc->assessment_head + svc->assessment_count) % OZAYN_SR_MAX_ASSESSMENTS;
    memset(&svc->assessments[slot], 0, sizeof(ozayn_sr_assessment_t));
    svc->assessment_count++;
    return &svc->assessments[slot];
}

/* ============================================================
 * SECTION 19 — NAME HELPERS
 * ============================================================ */

const char *ozayn_sr_err_name(ozayn_sr_err_t err)
{
    switch (err) {
    case OZAYN_SR_OK:                        return "OK";
    case OZAYN_SR_ERR_NULL:                  return "NULL";
    case OZAYN_SR_ERR_NOT_INITIALIZED:       return "NOT_INITIALIZED";
    case OZAYN_SR_ERR_ALREADY_INITIALIZED:   return "ALREADY_INITIALIZED";
    case OZAYN_SR_ERR_INVALID_PARAM:         return "INVALID_PARAM";
    case OZAYN_SR_ERR_LIMIT_REACHED:         return "LIMIT_REACHED";
    case OZAYN_SR_ERR_NOT_FOUND:             return "NOT_FOUND";
    case OZAYN_SR_ERR_STATE_INVALID:         return "STATE_INVALID";
    case OZAYN_SR_ERR_STATE_TRANSITION:      return "STATE_TRANSITION";
    case OZAYN_SR_ERR_POLICY_REJECTED:       return "POLICY_REJECTED";
    case OZAYN_SR_ERR_INTEGRITY_FAILURE:     return "INTEGRITY_FAILURE";
    case OZAYN_SR_ERR_EVIDENCE_INVALID:      return "EVIDENCE_INVALID";
    case OZAYN_SR_ERR_EVIDENCE_EXPIRED:      return "EVIDENCE_EXPIRED";
    case OZAYN_SR_ERR_EVIDENCE_REVOKED:      return "EVIDENCE_REVOKED";
    case OZAYN_SR_ERR_SET_INVALID:           return "SET_INVALID";
    case OZAYN_SR_ERR_SET_LIMIT:             return "SET_LIMIT";
    case OZAYN_SR_ERR_ASSESSMENT_INVALID:    return "ASSESSMENT_INVALID";
    case OZAYN_SR_ERR_ASSESSMENT_LIMIT:      return "ASSESSMENT_LIMIT";
    case OZAYN_SR_ERR_RESOURCE_EXHAUSTED:    return "RESOURCE_EXHAUSTED";
    case OZAYN_SR_ERR_UNAVAILABLE:           return "UNAVAILABLE";
    case OZAYN_SR_ERR_AGGREGATION_FAILED:    return "AGGREGATION_FAILED";
    case OZAYN_SR_ERR_DEDUPE_FAILED:         return "DEDUPE_FAILED";
    case OZAYN_SR_ERR_TEMPORAL_FAILED:       return "TEMPORAL_FAILED";
    }
    return "UNKNOWN";
}

const char *ozayn_sr_level_name(ozayn_sr_level_t level)
{
    switch (level) {
    case OZAYN_SR_LEVEL_UNKNOWN:   return "UNKNOWN";
    case OZAYN_SR_LEVEL_LOW:       return "LOW";
    case OZAYN_SR_LEVEL_MODERATE:  return "MODERATE";
    case OZAYN_SR_LEVEL_HIGH:      return "HIGH";
    case OZAYN_SR_LEVEL_CRITICAL:  return "CRITICAL";
    }
    return "UNKNOWN";
}

const char *ozayn_sr_factor_type_name(ozayn_sr_factor_type_t ft)
{
    static const char *names[] = {
        "THREAT_SEVERITY", "THREAT_IMPACT", "EVIDENCE_RELIABILITY",
        "THREAT_CONFIDENCE", "DATA_CLASSIFICATION", "RESOURCE_SENSITIVITY",
        "IDENTITY_SCOPE", "SECURITY_ASSURANCE", "INTEGRITY_STATE",
        "PERSISTENCE", "INCIDENT_STATE", "SECURITY_HEALTH"
    };
    if (ft >= 0 && ft < OZAYN_SR_FACTOR_COUNT)
        return names[ft];
    return "UNKNOWN";
}

const char *ozayn_sr_persistence_name(ozayn_sr_persistence_t p)
{
    switch (p) {
    case OZAYN_SR_PERSISTENCE_UNKNOWN:   return "UNKNOWN";
    case OZAYN_SR_PERSISTENCE_TRANSIENT: return "TRANSIENT";
    case OZAYN_SR_PERSISTENCE_REPEATED:  return "REPEATED";
    case OZAYN_SR_PERSISTENCE_PERSISTENT: return "PERSISTENT";
    }
    return "UNKNOWN";
}

const char *ozayn_sr_assurance_name(ozayn_sr_assurance_t a)
{
    switch (a) {
    case OZAYN_SR_ASSURANCE_UNKNOWN:        return "UNKNOWN";
    case OZAYN_SR_ASSURANCE_SINGLE_FACTOR:  return "SINGLE_FACTOR";
    case OZAYN_SR_ASSURANCE_MULTI_FACTOR:   return "MULTI_FACTOR";
    case OZAYN_SR_ASSURANCE_HIGH_ASSURANCE: return "HIGH_ASSURANCE";
    }
    return "UNKNOWN";
}

const char *ozayn_sr_temporal_name(ozayn_sr_temporal_t t)
{
    switch (t) {
    case OZAYN_SR_TEMPORAL_CURRENT: return "CURRENT";
    case OZAYN_SR_TEMPORAL_AGING:   return "AGING";
    case OZAYN_SR_TEMPORAL_EXPIRED: return "EXPIRED";
    case OZAYN_SR_TEMPORAL_UNKNOWN: return "UNKNOWN";
    }
    return "UNKNOWN";
}

const char *ozayn_sr_state_name(ozayn_sr_state_t s)
{
    switch (s) {
    case OZAYN_SR_STATE_PENDING:    return "PENDING";
    case OZAYN_SR_STATE_ASSESSING:  return "ASSESSING";
    case OZAYN_SR_STATE_ASSESSED:   return "ASSESSED";
    case OZAYN_SR_STATE_ELEVATED:   return "ELEVATED";
    case OZAYN_SR_STATE_MITIGATING: return "MITIGATING";
    case OZAYN_SR_STATE_MONITORING: return "MONITORING";
    case OZAYN_SR_STATE_RESOLVED:   return "RESOLVED";
    case OZAYN_SR_STATE_EXPIRED:    return "EXPIRED";
    case OZAYN_SR_STATE_INVALID:    return "INVALID";
    }
    return "UNKNOWN";
}

const char *ozayn_sr_decision_name(ozayn_sr_decision_t d)
{
    switch (d) {
    case OZAYN_SR_DECISION_NONE:                 return "NONE";
    case OZAYN_SR_DECISION_MONITOR:              return "MONITOR";
    case OZAYN_SR_DECISION_INVESTIGATE:          return "INVESTIGATE";
    case OZAYN_SR_DECISION_ESCALATE_INCIDENT:    return "ESCALATE_INCIDENT";
    case OZAYN_SR_DECISION_REQUIRE_REAUTH:       return "REQUIRE_REAUTH";
    case OZAYN_SR_DECISION_REQUIRE_MFA:          return "REQUIRE_MFA";
    case OZAYN_SR_DECISION_REVIEW_SESSION:       return "REVIEW_SESSION";
    case OZAYN_SR_DECISION_REVOKE_SESSION:       return "REVOKE_SESSION";
    case OZAYN_SR_DECISION_REVIEW_IDENTITY:      return "REVIEW_IDENTITY";
    case OZAYN_SR_DECISION_SUSPEND_IDENTITY:     return "SUSPEND_IDENTITY";
    case OZAYN_SR_DECISION_REVIEW_PERMISSION:    return "REVIEW_PERMISSION";
    case OZAYN_SR_DECISION_REVIEW_ROLE:          return "REVIEW_ROLE";
    case OZAYN_SR_DECISION_REVIEW_KEY_STATE:     return "REVIEW_KEY_STATE";
    case OZAYN_SR_DECISION_SECURITY_LOCKDOWN:    return "SECURITY_LOCKDOWN";
    }
    return "UNKNOWN";
}

const char *ozayn_sr_explain_name(ozayn_sr_explain_t e)
{
    static const char *names[] = {
        "NONE", "HIGH_THREAT_SEVERITY", "HIGH_IMPACT_RESOURCE",
        "HIGH_CONFIDENCE", "VERIFIED_EVIDENCE", "LOW_RELIABILITY",
        "UNKNOWN_RELIABILITY", "CONFLICTING_EVIDENCE", "INTEGRITY_FAILURE",
        "SENSITIVE_CLASSIFICATION", "PERSISTENT_THREAT", "ACTIVE_INCIDENT",
        "HEALTH_DEGRADED", "LOW_ASSURANCE", "INSUFFICIENT_EVIDENCE",
        "AGGREGATED_RISK"
    };
    if (e >= 0 && e <= OZAYN_SR_EXPLAIN_AGGREGATED_RISK)
        return names[e];
    return "UNKNOWN";
}

int ozayn_sr_level_to_audit_severity(ozayn_sr_level_t level)
{
    switch (level) {
    case OZAYN_SR_LEVEL_UNKNOWN:  return 0;
    case OZAYN_SR_LEVEL_LOW:      return 1;
    case OZAYN_SR_LEVEL_MODERATE: return 2;
    case OZAYN_SR_LEVEL_HIGH:     return 3;
    case OZAYN_SR_LEVEL_CRITICAL: return 4;
    }
    return 0;
}

int ozayn_sr_level_to_salert_severity(ozayn_sr_level_t level)
{
    switch (level) {
    case OZAYN_SR_LEVEL_UNKNOWN:  return 0;
    case OZAYN_SR_LEVEL_LOW:      return 1;
    case OZAYN_SR_LEVEL_MODERATE: return 2;
    case OZAYN_SR_LEVEL_HIGH:     return 3;
    case OZAYN_SR_LEVEL_CRITICAL: return 4;
    }
    return 0;
}

int ozayn_sr_level_to_ir_severity(ozayn_sr_level_t level)
{
    switch (level) {
    case OZAYN_SR_LEVEL_UNKNOWN:  return 0;
    case OZAYN_SR_LEVEL_LOW:      return 1;
    case OZAYN_SR_LEVEL_MODERATE: return 2;
    case OZAYN_SR_LEVEL_HIGH:     return 3;
    case OZAYN_SR_LEVEL_CRITICAL: return 4;
    }
    return 0;
}

int ozayn_sr_level_to_salert_priority(ozayn_sr_level_t level)
{
    switch (level) {
    case OZAYN_SR_LEVEL_UNKNOWN:  return 0;
    case OZAYN_SR_LEVEL_LOW:      return 0;
    case OZAYN_SR_LEVEL_MODERATE: return 1;
    case OZAYN_SR_LEVEL_HIGH:     return 2;
    case OZAYN_SR_LEVEL_CRITICAL: return 4;
    }
    return 0;
}

/* ============================================================
 * SECTION 18 — LIFECYCLE
 * ============================================================ */

ozayn_sr_err_t ozayn_sr_service_init(
    ozayn_sr_service_t *svc,
    const ozayn_sr_service_config_t *cfg)
{
    if (!svc) return OZAYN_SR_ERR_NULL;
    if (svc->initialized) return OZAYN_SR_ERR_ALREADY_INITIALIZED;

    memset(svc, 0, sizeof(*svc));

    if (cfg) {
        svc->intel_service    = cfg->intel_service;
        svc->detect_service   = cfg->detect_service;
        svc->incident_service = cfg->incident_service;
        svc->alert_service    = cfg->alert_service;
        svc->health_service   = cfg->health_service;
        svc->config_service   = cfg->config_service;
        svc->audit            = cfg->audit;
    }

    svc->policy = ozayn_sr_default_policy();
    svc->initialized = 1;
    return OZAYN_SR_OK;
}

void ozayn_sr_service_shutdown(ozayn_sr_service_t *svc)
{
    if (!svc) return;
    svc->initialized = 0;
}

int ozayn_sr_service_is_initialized(const ozayn_sr_service_t *svc)
{
    return svc ? svc->initialized : 0;
}

/* ============================================================
 * SECTION 20 — RISK ASSESSMENT OPERATIONS
 * ============================================================ */

static int _valid_state_transition(ozayn_sr_state_t from, ozayn_sr_state_t to)
{
    switch (from) {
    case OZAYN_SR_STATE_PENDING:
        return to == OZAYN_SR_STATE_ASSESSING ||
               to == OZAYN_SR_STATE_INVALID;
    case OZAYN_SR_STATE_ASSESSING:
        return to == OZAYN_SR_STATE_ASSESSED ||
               to == OZAYN_SR_STATE_INVALID;
    case OZAYN_SR_STATE_ASSESSED:
        return to == OZAYN_SR_STATE_ELEVATED ||
               to == OZAYN_SR_STATE_MITIGATING ||
               to == OZAYN_SR_STATE_MONITORING ||
               to == OZAYN_SR_STATE_RESOLVED ||
               to == OZAYN_SR_STATE_EXPIRED;
    case OZAYN_SR_STATE_ELEVATED:
        return to == OZAYN_SR_STATE_MITIGATING ||
               to == OZAYN_SR_STATE_MONITORING ||
               to == OZAYN_SR_STATE_RESOLVED ||
               to == OZAYN_SR_STATE_EXPIRED;
    case OZAYN_SR_STATE_MITIGATING:
        return to == OZAYN_SR_STATE_MONITORING ||
               to == OZAYN_SR_STATE_RESOLVED ||
               to == OZAYN_SR_STATE_EXPIRED;
    case OZAYN_SR_STATE_MONITORING:
        return to == OZAYN_SR_STATE_ELEVATED ||
               to == OZAYN_SR_STATE_RESOLVED ||
               to == OZAYN_SR_STATE_EXPIRED;
    case OZAYN_SR_STATE_RESOLVED:
        return 0;
    case OZAYN_SR_STATE_EXPIRED:
        return 0;
    case OZAYN_SR_STATE_INVALID:
        return 0;
    }
    return 0;
}

ozayn_sr_err_t ozayn_sr_create_assessment(
    ozayn_sr_service_t *svc,
    const char *finding_id,
    const char *threat_assessment_id,
    const char *evidence_set_id,
    ozayn_sr_assessment_t **out_assessment)
{
    if (!svc) return OZAYN_SR_ERR_NULL;
    if (!svc->initialized) return OZAYN_SR_ERR_NOT_INITIALIZED;
    if (!out_assessment) return OZAYN_SR_ERR_NULL;
    if (!svc->policy.enabled) {
        svc->total_policy_rejections++;
        return OZAYN_SR_ERR_POLICY_REJECTED;
    }
    if (svc->assessment_count >= OZAYN_SR_MAX_ASSESSMENTS)
        return OZAYN_SR_ERR_ASSESSMENT_LIMIT;
    if (svc->assessment_count >= svc->policy.max_assessments &&
        svc->policy.max_assessments > 0)
        return OZAYN_SR_ERR_LIMIT_REACHED;

    /* Dedup check */
    if (ozayn_sr_assessment_is_duplicate(svc, finding_id ? finding_id : "",
            evidence_set_id ? evidence_set_id : "",
            threat_assessment_id ? threat_assessment_id : "")) {
        svc->total_assessments_deduplicated++;
        *out_assessment = NULL;
        return OZAYN_SR_OK;
    }

    ozayn_sr_assessment_t *a = _alloc_assessment(svc);
    _generate_id(a->risk_id, OZAYN_SR_MAX_ID_LEN,
                 "SRISK", svc->assessment_sequence + 1);
    svc->assessment_sequence++;
    a->state = OZAYN_SR_STATE_PENDING;
    a->risk_level = OZAYN_SR_LEVEL_UNKNOWN;
    a->risk_score = -1;
    a->severity = OZAYN_SINTEL_SEV_INFO;
    a->confidence = OZAYN_SINTEL_CONFIDENCE_LOW;
    a->impact = OZAYN_SINTEL_IMPACT_NONE;
    a->reliability = OZAYN_SINTEL_RELIABILITY_UNKNOWN;
    a->classification = OZAYN_SINTEL_CLASS_PUBLIC;
    a->integrity_state = OZAYN_SINTEL_INTEGRITY_UNKNOWN;
    a->persistence = OZAYN_SR_PERSISTENCE_UNKNOWN;
    a->assurance = OZAYN_SR_ASSURANCE_UNKNOWN;
    a->temporal_state = OZAYN_SR_TEMPORAL_UNKNOWN;
    a->recommended_decision = OZAYN_SR_DECISION_NONE;
    a->decision_priority = 0;
    a->created_time = time(NULL);
    a->updated_time = a->created_time;

    if (finding_id)
        strncpy(a->finding_id, finding_id, OZAYN_SR_MAX_ID_LEN - 1);
    if (threat_assessment_id)
        strncpy(a->threat_assessment_id, threat_assessment_id,
                OZAYN_SR_MAX_ID_LEN - 1);
    if (evidence_set_id)
        strncpy(a->evidence_set_id, evidence_set_id,
                OZAYN_SR_MAX_ID_LEN - 1);

    /* Register dedup */
    {
        char dedup_key[128];
        snprintf(dedup_key, sizeof(dedup_key), "%s:%s:%s",
                 finding_id ? finding_id : "",
                 evidence_set_id ? evidence_set_id : "",
                 threat_assessment_id ? threat_assessment_id : "");
        int slot = svc->dedup_count < 256 ? svc->dedup_count : 0;
        if (svc->dedup_count >= 256) {
            /* Evict oldest */
            int oldest = 0;
            time_t oldest_time = svc->dedup_state[0].last_time;
            for (int i = 1; i < 256; i++) {
                if (svc->dedup_state[i].last_time < oldest_time) {
                    oldest_time = svc->dedup_state[i].last_time;
                    oldest = i;
                }
            }
            slot = oldest;
        } else {
            svc->dedup_count++;
        }
        strncpy(svc->dedup_state[slot].dedup_key, dedup_key,
                sizeof(svc->dedup_state[slot].dedup_key) - 1);
        svc->dedup_state[slot].dedup_key[sizeof(svc->dedup_state[slot].dedup_key) - 1] = '\0';
        svc->dedup_state[slot].assessment_hash = 0;
        svc->dedup_state[slot].first_time = time(NULL);
        svc->dedup_state[slot].last_time = time(NULL);
        svc->dedup_state[slot].count = 1;
    }

    svc->total_assessments_created++;
    _audit_event(svc, "RISK_ASSESSMENT_CREATED", a->risk_id);
    *out_assessment = a;
    return OZAYN_SR_OK;
}

ozayn_sr_err_t ozayn_sr_complete_assessment(
    ozayn_sr_service_t *svc,
    const char *risk_id)
{
    if (!svc) return OZAYN_SR_ERR_NULL;
    if (!risk_id) return OZAYN_SR_ERR_NULL;
    if (!svc->initialized) return OZAYN_SR_ERR_NOT_INITIALIZED;
    ozayn_sr_assessment_t *a = ozayn_sr_get_assessment(svc, risk_id);
    if (!a) return OZAYN_SR_ERR_NOT_FOUND;
    /* Allow PENDING → ASSESSING → ASSESSED in one step if called directly */
    if (a->state == OZAYN_SR_STATE_PENDING)
        a->state = OZAYN_SR_STATE_ASSESSING;
    if (!_valid_state_transition(a->state, OZAYN_SR_STATE_ASSESSED))
        return OZAYN_SR_ERR_STATE_TRANSITION;
    a->state = OZAYN_SR_STATE_ASSESSED;
    a->updated_time = time(NULL);
    svc->total_assessments_completed++;
    _audit_event(svc, "RISK_ASSESSMENT_COMPLETED", a->risk_id);
    return OZAYN_SR_OK;
}

ozayn_sr_err_t ozayn_sr_elevate_assessment(
    ozayn_sr_service_t *svc,
    const char *risk_id)
{
    if (!svc) return OZAYN_SR_ERR_NULL;
    if (!risk_id) return OZAYN_SR_ERR_NULL;
    if (!svc->initialized) return OZAYN_SR_ERR_NOT_INITIALIZED;
    ozayn_sr_assessment_t *a = ozayn_sr_get_assessment(svc, risk_id);
    if (!a) return OZAYN_SR_ERR_NOT_FOUND;
    /* Allow PENDING → ASSESSING → ASSESSED → ELEVATED in one step */
    if (a->state == OZAYN_SR_STATE_PENDING) a->state = OZAYN_SR_STATE_ASSESSING;
    if (a->state == OZAYN_SR_STATE_ASSESSING) a->state = OZAYN_SR_STATE_ASSESSED;
    if (!_valid_state_transition(a->state, OZAYN_SR_STATE_ELEVATED))
        return OZAYN_SR_ERR_STATE_TRANSITION;
    a->state = OZAYN_SR_STATE_ELEVATED;
    a->updated_time = time(NULL);
    svc->total_assessments_elevated++;
    _audit_event(svc, "RISK_ASSESSMENT_ELEVATED", a->risk_id);
    return OZAYN_SR_OK;
}

ozayn_sr_err_t ozayn_sr_resolve_assessment(
    ozayn_sr_service_t *svc,
    const char *risk_id)
{
    if (!svc) return OZAYN_SR_ERR_NULL;
    if (!risk_id) return OZAYN_SR_ERR_NULL;
    if (!svc->initialized) return OZAYN_SR_ERR_NOT_INITIALIZED;
    ozayn_sr_assessment_t *a = ozayn_sr_get_assessment(svc, risk_id);
    if (!a) return OZAYN_SR_ERR_NOT_FOUND;
    /* Allow PENDING → ... → RESOLVED in one step */
    if (a->state == OZAYN_SR_STATE_PENDING) a->state = OZAYN_SR_STATE_ASSESSING;
    if (a->state == OZAYN_SR_STATE_ASSESSING) a->state = OZAYN_SR_STATE_ASSESSED;
    if (!_valid_state_transition(a->state, OZAYN_SR_STATE_RESOLVED))
        return OZAYN_SR_ERR_STATE_TRANSITION;
    a->state = OZAYN_SR_STATE_RESOLVED;
    a->updated_time = time(NULL);
    svc->total_assessments_resolved++;
    _audit_event(svc, "RISK_ASSESSMENT_RESOLVED", a->risk_id);
    return OZAYN_SR_OK;
}

ozayn_sr_assessment_t *ozayn_sr_get_assessment(
    ozayn_sr_service_t *svc,
    const char *risk_id)
{
    if (!svc || !risk_id) return NULL;
    for (int i = 0; i < svc->assessment_count; i++) {
        int slot = (svc->assessment_head + i) % OZAYN_SR_MAX_ASSESSMENTS;
        if (strcmp(svc->assessments[slot].risk_id, risk_id) == 0)
            return &svc->assessments[slot];
    }
    return NULL;
}

int ozayn_sr_assessment_count(const ozayn_sr_service_t *svc)
{
    return svc ? svc->assessment_count : 0;
}

int ozayn_sr_list_assessments(
    const ozayn_sr_service_t *svc,
    int filter_state,
    ozayn_sr_assessment_t **out_assessments,
    int max_count)
{
    if (!svc || !out_assessments || max_count <= 0) return 0;
    int count = 0;
    for (int i = 0; i < svc->assessment_count && count < max_count; i++) {
        int slot = (svc->assessment_head + i) % OZAYN_SR_MAX_ASSESSMENTS;
        const ozayn_sr_assessment_t *a = &svc->assessments[slot];
        int state_match = (filter_state < 0 ||
                           a->state == (ozayn_sr_state_t)filter_state);
        if (state_match) {
            out_assessments[count] = (ozayn_sr_assessment_t *)a;
            count++;
        }
    }
    return count;
}

/* ============================================================
 * SECTION 21 — RISK FACTOR OPERATIONS
 * ============================================================ */

ozayn_sr_err_t ozayn_sr_add_factor(
    ozayn_sr_assessment_t *assessment,
    ozayn_sr_factor_type_t type,
    int value,
    int weight,
    const char *source,
    ozayn_sr_explain_t explanation)
{
    if (!assessment) return OZAYN_SR_ERR_NULL;
    if (type < 0 || type >= OZAYN_SR_FACTOR_COUNT)
        return OZAYN_SR_ERR_INVALID_PARAM;

    /* Check if factor already exists — update it */
    for (int i = 0; i < assessment->factor_count; i++) {
        if (assessment->factors[i].type == type) {
            assessment->factors[i].value = value;
            assessment->factors[i].weight = weight;
            assessment->factors[i].explanation = explanation;
            if (source)
                strncpy(assessment->factors[i].source, source,
                        OZAYN_SR_MAX_SOURCE_LEN - 1);
            return OZAYN_SR_OK;
        }
    }

    if (assessment->factor_count >= OZAYN_SR_FACTOR_COUNT)
        return OZAYN_SR_ERR_LIMIT_REACHED;

    ozayn_sr_factor_t *f = &assessment->factors[assessment->factor_count];
    f->type = type;
    f->value = value;
    f->weight = weight;
    f->explanation = explanation;
    if (source)
        strncpy(f->source, source, OZAYN_SR_MAX_SOURCE_LEN - 1);
    assessment->factor_count++;
    return OZAYN_SR_OK;
}

/* ============================================================
 * SECTION 22 — DETERMINISTIC RISK CALCULATION
 * ============================================================ */

ozayn_sr_level_t ozayn_sr_score_to_level(
    const ozayn_sr_service_t *svc,
    int score)
{
    if (!svc) return OZAYN_SR_LEVEL_UNKNOWN;
    if (score < 0) return OZAYN_SR_LEVEL_UNKNOWN;
    if (score >= svc->policy.score_threshold_high) return OZAYN_SR_LEVEL_CRITICAL;
    if (score >= svc->policy.score_threshold_moderate) return OZAYN_SR_LEVEL_HIGH;
    if (score >= svc->policy.score_threshold_low) return OZAYN_SR_LEVEL_MODERATE;
    if (score > 0) return OZAYN_SR_LEVEL_LOW;
    return OZAYN_SR_LEVEL_UNKNOWN;
}

static int _factor_score(const ozayn_sr_factor_t *f, int max_value)
{
    if (max_value <= 0) return 0;
    int normalized = (f->value * 100) / max_value;
    if (normalized < 0) normalized = 0;
    if (normalized > 100) normalized = 100;
    return (normalized * f->weight) / 100;
}

ozayn_sr_err_t ozayn_sr_calculate_risk(
    ozayn_sr_service_t *svc,
    ozayn_sr_assessment_t *assessment)
{
    if (!svc || !assessment) return OZAYN_SR_ERR_NULL;
    if (!svc->initialized) return OZAYN_SR_ERR_NOT_INITIALIZED;
    if (!svc->policy.enabled) {
        svc->total_policy_rejections++;
        return OZAYN_SR_ERR_POLICY_REJECTED;
    }

    /* Transition to ASSESSING if PENDING */
    if (assessment->state == OZAYN_SR_STATE_PENDING) {
        assessment->state = OZAYN_SR_STATE_ASSESSING;
        assessment->updated_time = time(NULL);
    }

    int total_score = 0;
    int total_weight = 0;
    assessment->contribution_count = 0;
    assessment->explanation_count = 0;

    for (int i = 0; i < assessment->factor_count; i++) {
        const ozayn_sr_factor_t *f = &assessment->factors[i];
        int max_val = 4;  /* Most factors are 0-4 enums */
        int contrib = _factor_score(f, max_val);
        total_score += contrib;
        total_weight += f->weight;

        if (assessment->contribution_count < OZAYN_SR_FACTOR_COUNT) {
            ozayn_sr_contribution_t *c =
                &assessment->contributions[assessment->contribution_count];
            c->factor_type = f->type;
            c->contribution = contrib;
            c->explanation = f->explanation;
            if (f->source[0])
                strncpy(c->source_ref, f->source, OZAYN_SR_MAX_ID_LEN - 1);
            assessment->contribution_count++;
        }

        if (assessment->explanation_count < OZAYN_SR_MAX_EXPLANATIONS &&
            f->explanation != OZAYN_SR_EXPLAIN_NONE) {
            /* Dedup explanation codes */
            int found = 0;
            for (int j = 0; j < assessment->explanation_count; j++) {
                if (assessment->explanations[j] == f->explanation) {
                    found = 1;
                    break;
                }
            }
            if (!found)
                assessment->explanations[assessment->explanation_count++] =
                    f->explanation;
        }
    }

    /* Normalize score to 0-100 */
    if (total_weight > 0) {
        assessment->risk_score = (total_score * 100) / (total_weight > 100 ? total_weight : 100);
    } else {
        /* No factors — unknown risk */
        assessment->risk_score = -1;
        assessment->risk_level = OZAYN_SR_LEVEL_UNKNOWN;
        if (assessment->explanation_count < OZAYN_SR_MAX_EXPLANATIONS)
            assessment->explanations[assessment->explanation_count++] =
                OZAYN_SR_EXPLAIN_INSUFFICIENT_EVIDENCE;
    }

    /* Clamp */
    if (assessment->risk_score < 0) assessment->risk_score = 0;
    if (assessment->risk_score > 100) assessment->risk_score = 100;

    /* Map score to level */
    assessment->risk_level = ozayn_sr_score_to_level(svc, assessment->risk_score);

    /* Special case: if reliability is UNKNOWN and no verified evidence,
     * do NOT elevate to HIGH/CRITICAL — cap at MODERATE */
    if (assessment->reliability == OZAYN_SINTEL_RELIABILITY_UNKNOWN &&
        assessment->risk_level >= OZAYN_SR_LEVEL_HIGH) {
        assessment->risk_level = OZAYN_SR_LEVEL_MODERATE;
        if (assessment->risk_score > svc->policy.score_threshold_moderate)
            assessment->risk_score = svc->policy.score_threshold_moderate;
    }

    /* Integrity failure caps risk */
    if (assessment->integrity_state == OZAYN_SINTEL_INTEGRITY_INVALID &&
        assessment->risk_level >= OZAYN_SR_LEVEL_HIGH) {
        assessment->risk_level = OZAYN_SR_LEVEL_MODERATE;
    }

    /* Temporal evaluation */
    assessment->temporal_state = ozayn_sr_evaluate_temporal(svc, assessment);

    assessment->updated_time = time(NULL);
    svc->total_calculations++;

    _audit_event(svc, "RISK_CALCULATED", assessment->risk_id);
    return OZAYN_SR_OK;
}

/* ============================================================
 * SECTION 23 — RISK AGGREGATION
 * ============================================================ */

ozayn_sr_err_t ozayn_sr_create_aggregation(
    ozayn_sr_service_t *svc,
    const char *identity_id,
    const char *resource_id,
    const char *incident_id,
    ozayn_sr_aggregation_t **out_group)
{
    if (!svc) return OZAYN_SR_ERR_NULL;
    if (!svc->initialized) return OZAYN_SR_ERR_NOT_INITIALIZED;
    if (!out_group) return OZAYN_SR_ERR_NULL;
    if (svc->aggregation_count >= OZAYN_SR_MAX_AGGREGATIONS_SVC)
        return OZAYN_SR_ERR_LIMIT_REACHED;
    if (svc->aggregation_count >= svc->policy.max_aggregations &&
        svc->policy.max_aggregations > 0)
        return OZAYN_SR_ERR_LIMIT_REACHED;

    ozayn_sr_aggregation_t *g = &svc->aggregations[svc->aggregation_count];
    memset(g, 0, sizeof(*g));
    _generate_id(g->group_id, OZAYN_SR_MAX_ID_LEN,
                 "SAGG", svc->total_aggregations_created + 1);
    if (identity_id)
        strncpy(g->identity_id, identity_id, OZAYN_SR_MAX_ID_LEN - 1);
    if (resource_id)
        strncpy(g->resource_id, resource_id, OZAYN_SR_MAX_ID_LEN - 1);
    if (incident_id)
        strncpy(g->incident_id, incident_id, OZAYN_SR_MAX_ID_LEN - 1);
    g->created_time = time(NULL);
    g->updated_time = g->created_time;
    g->aggregated_level = OZAYN_SR_LEVEL_UNKNOWN;

    svc->aggregation_count++;
    svc->total_aggregations_created++;
    _audit_event(svc, "RISK_AGGREGATION_CREATED", g->group_id);
    *out_group = g;
    return OZAYN_SR_OK;
}

ozayn_sr_err_t ozayn_sr_add_to_aggregation(
    ozayn_sr_service_t *svc,
    const char *group_id,
    const char *risk_id)
{
    if (!svc) return OZAYN_SR_ERR_NULL;
    if (!svc->initialized) return OZAYN_SR_ERR_NOT_INITIALIZED;
    if (!group_id || !risk_id) return OZAYN_SR_ERR_INVALID_PARAM;

    ozayn_sr_aggregation_t *g = NULL;
    for (int i = 0; i < svc->aggregation_count; i++) {
        if (strcmp(svc->aggregations[i].group_id, group_id) == 0) {
            g = &svc->aggregations[i];
            break;
        }
    }
    if (!g) return OZAYN_SR_ERR_NOT_FOUND;

    if (g->assessment_count >= OZAYN_SR_MAX_AGGREGATION)
        return OZAYN_SR_ERR_LIMIT_REACHED;

    strncpy(g->assessment_ids[g->assessment_count], risk_id,
            OZAYN_SR_MAX_ID_LEN - 1);
    g->assessment_count++;
    g->updated_time = time(NULL);
    return OZAYN_SR_OK;
}

ozayn_sr_err_t ozayn_sr_evaluate_aggregation(
    ozayn_sr_service_t *svc,
    ozayn_sr_aggregation_t *group)
{
    if (!svc || !group) return OZAYN_SR_ERR_NULL;

    group->aggregated_level = OZAYN_SR_LEVEL_UNKNOWN;
    group->aggregated_score = 0;
    group->max_severity = -1;
    group->max_confidence = -1;
    group->max_impact = -1;

    int score_sum = 0;
    int score_count = 0;

    for (int i = 0; i < group->assessment_count; i++) {
        ozayn_sr_assessment_t *a =
            ozayn_sr_get_assessment(svc, group->assessment_ids[i]);
        if (!a) continue;
        if (a->state == OZAYN_SR_STATE_INVALID ||
            a->state == OZAYN_SR_STATE_EXPIRED)
            continue;

        if (a->risk_score >= 0) {
            score_sum += a->risk_score;
            score_count++;
        }
        if ((int)a->severity > group->max_severity)
            group->max_severity = (int)a->severity;
        if ((int)a->confidence > group->max_confidence)
            group->max_confidence = (int)a->confidence;
        if ((int)a->impact > group->max_impact)
            group->max_impact = (int)a->impact;

        /* Propagate identity/resource if not set */
        if (!group->identity_id[0] && a->affected_resource.resource_id[0])
            strncpy(group->resource_id, a->affected_resource.resource_id,
                    OZAYN_SR_MAX_ID_LEN - 1);
    }

    if (score_count > 0) {
        /* Average score but boosted by count (more related risks = higher) */
        group->aggregated_score = score_sum / score_count;
        /* Small boost for multiple related risks, capped at 100 */
        int boost = (score_count - 1) * 3;
        group->aggregated_score += boost;
        if (group->aggregated_score > 100)
            group->aggregated_score = 100;
    }

    group->aggregated_level = ozayn_sr_score_to_level(svc, group->aggregated_score);
    group->updated_time = time(NULL);
    return OZAYN_SR_OK;
}

ozayn_sr_aggregation_t *ozayn_sr_get_aggregation(
    ozayn_sr_service_t *svc,
    const char *group_id)
{
    if (!svc || !group_id) return NULL;
    for (int i = 0; i < svc->aggregation_count; i++) {
        if (strcmp(svc->aggregations[i].group_id, group_id) == 0)
            return &svc->aggregations[i];
    }
    return NULL;
}

int ozayn_sr_aggregation_count(const ozayn_sr_service_t *svc)
{
    return svc ? svc->aggregation_count : 0;
}

/* ============================================================
 * SECTION 24 — RISK DEDUPLICATION
 * ============================================================ */

int ozayn_sr_assessment_is_duplicate(
    const ozayn_sr_service_t *svc,
    const char *finding_id,
    const char *evidence_set_id,
    const char *threat_assessment_id)
{
    if (!svc) return 0;
    time_t now = time(NULL);
    int window = svc->policy.dedup_window_seconds;
    if (window <= 0) window = 300;

    char dedup_key[128];
    snprintf(dedup_key, sizeof(dedup_key), "%s:%s:%s",
             finding_id ? finding_id : "",
             evidence_set_id ? evidence_set_id : "",
             threat_assessment_id ? threat_assessment_id : "");

    for (int i = 0; i < svc->dedup_count; i++) {
        if (strcmp(svc->dedup_state[i].dedup_key, dedup_key) == 0) {
            if ((now - svc->dedup_state[i].last_time) < window)
                return 1;
            break;
        }
    }
    return 0;
}

/* ============================================================
 * SECTION 25 — TEMPORAL RISK
 * ============================================================ */

ozayn_sr_temporal_t ozayn_sr_evaluate_temporal(
    const ozayn_sr_service_t *svc,
    const ozayn_sr_assessment_t *assessment)
{
    if (!svc || !assessment) return OZAYN_SR_TEMPORAL_UNKNOWN;

    time_t now = time(NULL);
    int retention = svc->policy.assessment_retention_seconds;
    if (retention <= 0) retention = 86400;

    time_t age = now - assessment->created_time;
    if (age < 0) return OZAYN_SR_TEMPORAL_UNKNOWN;

    if (age > retention)
        return OZAYN_SR_TEMPORAL_EXPIRED;
    if (age > retention / 2)
        return OZAYN_SR_TEMPORAL_AGING;
    return OZAYN_SR_TEMPORAL_CURRENT;
}

/* ============================================================
 * SECTION 26 — DECISION SUPPORT
 * ============================================================ */

ozayn_sr_err_t ozayn_sr_generate_decision(
    ozayn_sr_service_t *svc,
    ozayn_sr_assessment_t *assessment)
{
    if (!svc || !assessment) return OZAYN_SR_ERR_NULL;
    if (!svc->initialized) return OZAYN_SR_ERR_NOT_INITIALIZED;

    int score = assessment->risk_score;
    if (score < 0) score = 0;

    /* Decision is deterministic based on score and level */
    if (score >= svc->policy.decision_threshold_lockdown) {
        assessment->recommended_decision = OZAYN_SR_DECISION_SECURITY_LOCKDOWN;
        assessment->decision_priority = 100;
    } else if (score >= svc->policy.decision_threshold_escalate_incident) {
        assessment->recommended_decision = OZAYN_SR_DECISION_ESCALATE_INCIDENT;
        assessment->decision_priority = 80;
    } else if (score >= svc->policy.decision_threshold_suspend_identity) {
        assessment->recommended_decision = OZAYN_SR_DECISION_SUSPEND_IDENTITY;
        assessment->decision_priority = 70;
    } else if (assessment->risk_level == OZAYN_SR_LEVEL_HIGH) {
        assessment->recommended_decision = OZAYN_SR_DECISION_INVESTIGATE;
        assessment->decision_priority = 60;
    } else if (assessment->risk_level == OZAYN_SR_LEVEL_MODERATE) {
        assessment->recommended_decision = OZAYN_SR_DECISION_REVIEW_SESSION;
        assessment->decision_priority = 40;
    } else if (assessment->risk_level == OZAYN_SR_LEVEL_LOW) {
        assessment->recommended_decision = OZAYN_SR_DECISION_MONITOR;
        assessment->decision_priority = 20;
    } else {
        assessment->recommended_decision = OZAYN_SR_DECISION_MONITOR;
        assessment->decision_priority = 10;
    }

    /* Factor-based overrides */
    for (int i = 0; i < assessment->factor_count; i++) {
        if (assessment->factors[i].type == OZAYN_SR_FACTOR_PERSISTENCE &&
            assessment->factors[i].value >= OZAYN_SR_PERSISTENCE_PERSISTENT) {
            if (assessment->recommended_decision < OZAYN_SR_DECISION_INVESTIGATE) {
                assessment->recommended_decision = OZAYN_SR_DECISION_INVESTIGATE;
                assessment->decision_priority = 60;
            }
        }
        if (assessment->factors[i].type == OZAYN_SR_FACTOR_SECURITY_ASSURANCE &&
            assessment->factors[i].value <= OZAYN_SR_ASSURANCE_SINGLE_FACTOR) {
            if (assessment->recommended_decision < OZAYN_SR_DECISION_REQUIRE_MFA &&
                assessment->risk_level >= OZAYN_SR_LEVEL_MODERATE) {
                assessment->recommended_decision = OZAYN_SR_DECISION_REQUIRE_MFA;
                assessment->decision_priority = 50;
            }
        }
    }

    /* Add decision explanation */
    if (assessment->explanation_count < OZAYN_SR_MAX_EXPLANATIONS) {
        ozayn_sr_explain_t explain = OZAYN_SR_EXPLAIN_NONE;
        switch (assessment->recommended_decision) {
        case OZAYN_SR_DECISION_ESCALATE_INCIDENT:
            explain = OZAYN_SR_EXPLAIN_HIGH_CONFIDENCE; break;
        case OZAYN_SR_DECISION_SECURITY_LOCKDOWN:
            explain = OZAYN_SR_EXPLAIN_PERSISTENT_THREAT; break;
        case OZAYN_SR_DECISION_SUSPEND_IDENTITY:
            explain = OZAYN_SR_EXPLAIN_ACTIVE_INCIDENT; break;
        default:
            break;
        }
        if (explain != OZAYN_SR_EXPLAIN_NONE) {
            int found = 0;
            for (int j = 0; j < assessment->explanation_count; j++) {
                if (assessment->explanations[j] == explain) {
                    found = 1;
                    break;
                }
            }
            if (!found)
                assessment->explanations[assessment->explanation_count++] = explain;
        }
    }

    assessment->updated_time = time(NULL);
    _audit_event(svc, "SECURITY_DECISION_SUPPORT_GENERATED", assessment->risk_id);
    return OZAYN_SR_OK;
}

/* ============================================================
 * SECTION 27 — INCIDENT INTEGRATION
 * ============================================================ */

ozayn_sr_err_t ozayn_sr_create_incident_from_risk(
    ozayn_sr_service_t *svc,
    ozayn_sr_assessment_t *assessment)
{
    if (!svc || !assessment) return OZAYN_SR_ERR_NULL;
    if (!svc->incident_service || !svc->incident_service->initialized)
        return OZAYN_SR_ERR_UNAVAILABLE;
    if (!svc->policy.incident_integration_enabled) {
        svc->total_policy_rejections++;
        return OZAYN_SR_ERR_POLICY_REJECTED;
    }

    /* Only escalate if risk is HIGH or CRITICAL and state allows it */
    if (assessment->state != OZAYN_SR_STATE_ASSESSED &&
        assessment->state != OZAYN_SR_STATE_ELEVATED)
        return OZAYN_SR_ERR_STATE_TRANSITION;

    if (assessment->risk_level < OZAYN_SR_LEVEL_HIGH)
        return OZAYN_SR_ERR_POLICY_REJECTED;

    ozayn_ir_severity_t ir_sev = (ozayn_ir_severity_t)
        ozayn_sr_level_to_ir_severity(assessment->risk_level);

    ozayn_ir_incident_t *ir_inc = NULL;
    ozayn_ir_result_t rc = ozayn_ir_report(
        svc->incident_service,
        OZAYN_IR_TYPE_SUSPICIOUS_ACTIVITY,
        ir_sev,
        "SEC_RISK",
        assessment->affected_resource.resource_id,
        "",
        "",
        "",
        assessment->safe_metadata,
        &ir_inc);

    if (rc == OZAYN_IR_OK) {
        if (ir_inc)
            strncpy(assessment->incident_id, ir_inc->incident_id,
                    OZAYN_SR_MAX_ID_LEN - 1);
        svc->total_incidents_created++;
        _audit_event(svc, "INCIDENT_CREATED_FROM_RISK", assessment->risk_id);
    }
    return OZAYN_SR_OK;
}

/* ============================================================
 * SECTION 28 — ALERT INTEGRATION
 * ============================================================ */

ozayn_sr_err_t ozayn_sr_create_alert_from_risk(
    ozayn_sr_service_t *svc,
    ozayn_sr_assessment_t *assessment)
{
    if (!svc || !assessment) return OZAYN_SR_ERR_NULL;
    if (!svc->alert_service || !svc->alert_service->initialized)
        return OZAYN_SR_ERR_UNAVAILABLE;
    if (!svc->policy.alert_integration_enabled) {
        svc->total_policy_rejections++;
        return OZAYN_SR_ERR_POLICY_REJECTED;
    }

    ozayn_salert_severity_t al_sev = OZAYN_SALERT_SEV_NOTICE;
    switch (assessment->risk_level) {
    case OZAYN_SR_LEVEL_UNKNOWN:  al_sev = OZAYN_SALERT_SEV_INFO; break;
    case OZAYN_SR_LEVEL_LOW:      al_sev = OZAYN_SALERT_SEV_NOTICE; break;
    case OZAYN_SR_LEVEL_MODERATE: al_sev = OZAYN_SALERT_SEV_WARNING; break;
    case OZAYN_SR_LEVEL_HIGH:     al_sev = OZAYN_SALERT_SEV_HIGH; break;
    case OZAYN_SR_LEVEL_CRITICAL: al_sev = OZAYN_SALERT_SEV_CRITICAL; break;
    }

    ozayn_salert_priority_t prio = OZAYN_SALERT_PRIO_NORMAL;
    if (assessment->risk_level == OZAYN_SR_LEVEL_CRITICAL)
        prio = OZAYN_SALERT_PRIO_IMMEDIATE;
    else if (assessment->risk_level == OZAYN_SR_LEVEL_HIGH)
        prio = OZAYN_SALERT_PRIO_HIGH;

    ozayn_salert_alert_t *alert = NULL;
    ozayn_salert_err_t rc = ozayn_salert_create(
        svc->alert_service,
        OZAYN_SALERT_TYPE_INCIDENT,
        al_sev,
        prio,
        OZAYN_SALERT_SOURCE_SECURITY_EVENT,
        "SEC_RISK",
        assessment->finding_id,
        ozayn_sr_level_name(assessment->risk_level),
        assessment->safe_metadata,
        &alert);

    if (rc == OZAYN_SALERT_OK && alert) {
        svc->total_alerts_created++;
        _audit_event(svc, "ALERT_CREATED_FROM_RISK", assessment->risk_id);
    }
    return OZAYN_SR_OK;
}

/* ============================================================
 * SECTION 29 — HEALTH INTEGRATION
 * ============================================================ */

int ozayn_sr_get_health_impact(const ozayn_sr_service_t *svc)
{
    if (!svc) return 0;

    int max_level = 0;
    for (int i = 0; i < svc->assessment_count; i++) {
        int slot = (svc->assessment_head + i) % OZAYN_SR_MAX_ASSESSMENTS;
        const ozayn_sr_assessment_t *a = &svc->assessments[slot];
        if (a->state == OZAYN_SR_STATE_RESOLVED ||
            a->state == OZAYN_SR_STATE_EXPIRED ||
            a->state == OZAYN_SR_STATE_INVALID)
            continue;
        if ((int)a->risk_level > max_level)
            max_level = (int)a->risk_level;
    }
    return max_level;
}

/* ============================================================
 * SECTION 30 — AUDIT INTEGRATION
 * ============================================================ */

ozayn_sr_err_t ozayn_sr_audit_event(
    ozayn_sr_service_t *svc,
    const char *event_type,
    const char *detail)
{
    if (!svc) return OZAYN_SR_ERR_NULL;
    _audit_event(svc, event_type, detail);
    return OZAYN_SR_OK;
}

/* ============================================================
 * SECTION 31 — POLICY
 * ============================================================ */

ozayn_sr_policy_t ozayn_sr_default_policy(void)
{
    ozayn_sr_policy_t p;
    memset(&p, 0, sizeof(p));
    p.enabled = 1;
    p.max_assessments = OZAYN_SR_MAX_ASSESSMENTS;
    p.max_aggregations = OZAYN_SR_MAX_AGGREGATIONS_SVC;
    p.assessment_retention_seconds = 86400;
    p.dedup_window_seconds = 300;

    /* Score thresholds */
    p.score_threshold_low = 10;
    p.score_threshold_moderate = 30;
    p.score_threshold_high = 60;

    /* Factor weights (0-100) */
    p.weight_threat_severity = 20;
    p.weight_threat_impact = 15;
    p.weight_evidence_reliability = 15;
    p.weight_threat_confidence = 10;
    p.weight_data_classification = 10;
    p.weight_resource_sensitivity = 8;
    p.weight_identity_scope = 5;
    p.weight_security_assurance = 5;
    p.weight_integrity_state = 5;
    p.weight_persistence = 4;
    p.weight_incident_state = 2;
    p.weight_security_health = 1;

    /* Integration */
    p.incident_integration_enabled = 1;
    p.alert_integration_enabled = 1;
    p.health_integration_enabled = 1;
    p.audit_integration_enabled = 1;

    /* Decision thresholds */
    p.decision_threshold_escalate_incident = 60;
    p.decision_threshold_lockdown = 85;
    p.decision_threshold_suspend_identity = 70;

    return p;
}

ozayn_sr_err_t ozayn_sr_set_policy(
    ozayn_sr_service_t *svc,
    const ozayn_sr_policy_t *policy)
{
    if (!svc || !policy) return OZAYN_SR_ERR_NULL;
    if (!svc->initialized) return OZAYN_SR_ERR_NOT_INITIALIZED;
    if (!policy->enabled) return OZAYN_SR_ERR_POLICY_REJECTED;
    svc->policy = *policy;
    _audit_event(svc, "RISK_POLICY_UPDATED", "policy_changed");
    return OZAYN_SR_OK;
}

const ozayn_sr_policy_t *ozayn_sr_get_policy(const ozayn_sr_service_t *svc)
{
    return svc ? &svc->policy : NULL;
}

/* ============================================================
 * SECTION 32 — CLEANUP
 * ============================================================ */

int ozayn_sr_cleanup_expired_assessments(ozayn_sr_service_t *svc)
{
    if (!svc) return 0;
    int cleaned = 0;
    for (int i = 0; i < svc->assessment_count; i++) {
        int slot = (svc->assessment_head + i) % OZAYN_SR_MAX_ASSESSMENTS;
        ozayn_sr_assessment_t *a = &svc->assessments[slot];
        if (a->state == OZAYN_SR_STATE_RESOLVED) continue;
        if (a->state == OZAYN_SR_STATE_EXPIRED) continue;
        if (a->state == OZAYN_SR_STATE_INVALID) continue;
        time_t now = time(NULL);
        if ((now - a->created_time) > svc->policy.assessment_retention_seconds) {
            a->state = OZAYN_SR_STATE_EXPIRED;
            a->updated_time = now;
            cleaned++;
        }
    }
    svc->total_assessments_expired += cleaned;
    return cleaned;
}

/* ============================================================
 * SECTION 33 — RESOURCE SAFETY
 * ============================================================ */

int ozayn_sr_assessments_full(const ozayn_sr_service_t *svc)
{
    if (!svc) return 1;
    return svc->assessment_count >= OZAYN_SR_MAX_ASSESSMENTS;
}

int ozayn_sr_aggregations_full(const ozayn_sr_service_t *svc)
{
    if (!svc) return 1;
    return svc->aggregation_count >= OZAYN_SR_MAX_AGGREGATIONS_SVC;
}
