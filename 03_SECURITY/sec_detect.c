/*
 * sec_detect.c — Security Event Correlation & Threat Detection Foundation (Step 31).
 */

#include "sec_detect.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* ============================================================
 * GLOBAL SINGLETON
 * ============================================================ */

static ozayn_sdet_service_t _sdet_global = {0};

ozayn_sdet_service_t *ozayn_sdet_get_global(void)
{
    return &_sdet_global;
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

static ozayn_sdet_event_t *_alloc_event(ozayn_sdet_service_t *svc)
{
    if (svc->event_count >= OZAYN_SDET_MAX_EVENTS) {
        svc->event_head = (svc->event_head + 1) % OZAYN_SDET_MAX_EVENTS;
        svc->event_count--;
    }
    int slot = (svc->event_head + svc->event_count) % OZAYN_SDET_MAX_EVENTS;
    memset(&svc->events[slot], 0, sizeof(ozayn_sdet_event_t));
    svc->event_count++;
    return &svc->events[slot];
}

static ozayn_sdet_finding_t *_alloc_finding(ozayn_sdet_service_t *svc)
{
    if (svc->finding_count >= OZAYN_SDET_MAX_FINDINGS) {
        svc->finding_head = (svc->finding_head + 1) % OZAYN_SDET_MAX_FINDINGS;
        svc->finding_count--;
    }
    int slot = (svc->finding_head + svc->finding_count) % OZAYN_SDET_MAX_FINDINGS;
    memset(&svc->findings[slot], 0, sizeof(ozayn_sdet_finding_t));
    svc->finding_count++;
    return &svc->findings[slot];
}

static void _audit_event(ozayn_sdet_service_t *svc,
                          const char *event_type,
                          const char *detail)
{
    if (!svc->audit || !svc->audit->initialized) return;
    ozayn_audit_event_t ev;
    ozayn_audit_event_init(&ev);
    ozayn_audit_event_set_type(&ev, OZAYN_AUDIT_CONFIG_CHANGED);
    ozayn_audit_event_set_outcome(&ev, OZAYN_AUDIT_OUTCOME_SUCCESS);
    ozayn_audit_event_set_severity(&ev, OZAYN_AUDIT_SEV_NOTICE);
    ozayn_audit_event_set_source(&ev, "SEC_DETECT");
    char buf[512];
    snprintf(buf, sizeof(buf), "%s: %s", event_type,
             detail ? detail : "N/A");
    ozayn_audit_event_set_detail(&ev, buf);
    ozayn_audit_record(svc->audit, &ev);
}

/* ============================================================
 * SECTION 16 — STATE / NAME HELPERS
 * ============================================================ */

const char *ozayn_sdet_err_name(ozayn_sdet_err_t err)
{
    switch (err) {
    case OZAYN_SDET_OK:                      return "OK";
    case OZAYN_SDET_ERR_NULL:                return "NULL";
    case OZAYN_SDET_ERR_NOT_INITIALIZED:     return "NOT_INITIALIZED";
    case OZAYN_SDET_ERR_ALREADY_INITIALIZED: return "ALREADY_INITIALIZED";
    case OZAYN_SDET_ERR_INVALID_PARAM:       return "INVALID_PARAM";
    case OZAYN_SDET_ERR_LIMIT_REACHED:       return "LIMIT_REACHED";
    case OZAYN_SDET_ERR_NOT_FOUND:           return "NOT_FOUND";
    case OZAYN_SDET_ERR_STATE_INVALID:       return "STATE_INVALID";
    case OZAYN_SDET_ERR_STATE_TRANSITION:    return "STATE_TRANSITION";
    case OZAYN_SDET_ERR_POLICY_REJECTED:     return "POLICY_REJECTED";
    case OZAYN_SDET_ERR_PATTERN_INVALID:     return "PATTERN_INVALID";
    case OZAYN_SDET_ERR_PATTERN_NOT_FOUND:   return "PATTERN_NOT_FOUND";
    case OZAYN_SDET_ERR_PATTERN_EVALUATION:  return "PATTERN_EVALUATION";
    case OZAYN_SDET_ERR_CORRELATION_INVALID: return "CORRELATION_INVALID";
    case OZAYN_SDET_ERR_CORRELATION_LIMIT:   return "CORRELATION_LIMIT";
    case OZAYN_SDET_ERR_FINDING_INVALID:     return "FINDING_INVALID";
    case OZAYN_SDET_ERR_FINDING_LIMIT:       return "FINDING_LIMIT";
    case OZAYN_SDET_ERR_RESOURCE_EXHAUSTED:  return "RESOURCE_EXHAUSTED";
    case OZAYN_SDET_ERR_INTEGRITY_FAILURE:   return "INTEGRITY_FAILURE";
    case OZAYN_SDET_ERR_AUDIT_FAILURE:       return "AUDIT_FAILURE";
    case OZAYN_SDET_ERR_UNAVAILABLE:         return "UNAVAILABLE";
    }
    return "UNKNOWN";
}

const char *ozayn_sdet_event_category_name(ozayn_sdet_event_category_t cat)
{
    static const char *names[] = {
        "AUTH_SUCCESS", "AUTH_FAILURE", "AUTH_RATE_LIMIT", "AUTH_BLOCKED",
        "MFA_SUCCESS", "MFA_FAILURE", "MFA_BLOCKED",
        "SESSION_CREATED", "SESSION_VALIDATED", "SESSION_FAILED",
        "SESSION_TERMINATED",
        "AUTHZ_ALLOWED", "AUTHZ_DENIED",
        "PERM_DENIED", "PERM_MATCHED",
        "ROLE_CREATED", "ROLE_REVOKED", "ROLE_ASSIGNED",
        "ROLE_ASSIGN_REVOKED",
        "KEY_CREATED", "KEY_REVOKED", "KEY_UNAVAILABLE",
        "VAULT_ACCESS", "VAULT_FAILURE", "VAULT_INTEGRITY",
        "AUDIT_FAILURE", "AUDIT_INTEGRITY",
        "CONFIG_CHANGED", "CONFIG_REJECTED", "INTEGRITY_FAILURE",
        "HEALTH_DEGRADED", "HEALTH_CRITICAL", "COMPONENT_UNAVAILABLE",
        "BACKUP_FAILURE", "DELETION_FAILURE",
        "INCIDENT_DETECTED", "VIOLATION_DETECTED"
    };
    if (cat >= 0 && cat < OZAYN_SDET_EVT_CATEGORY_COUNT)
        return names[cat];
    return "UNKNOWN";
}

const char *ozayn_sdet_correlation_state_name(ozayn_sdet_correlation_state_t s)
{
    switch (s) {
    case OZAYN_SDET_CORR_NEW:        return "NEW";
    case OZAYN_SDET_CORR_ACTIVE:     return "ACTIVE";
    case OZAYN_SDET_CORR_MATCHED:    return "MATCHED";
    case OZAYN_SDET_CORR_SUSPICIOUS: return "SUSPICIOUS";
    case OZAYN_SDET_CORR_CONFIRMED:  return "CONFIRMED";
    case OZAYN_SDET_CORR_EXPIRED:    return "EXPIRED";
    case OZAYN_SDET_CORR_DISMISSED:  return "DISMISSED";
    }
    return "UNKNOWN";
}

const char *ozayn_sdet_pattern_type_name(ozayn_sdet_pattern_type_t t)
{
    switch (t) {
    case OZAYN_SDET_PATTERN_SINGLE:           return "SINGLE";
    case OZAYN_SDET_PATTERN_THRESHOLD:        return "THRESHOLD";
    case OZAYN_SDET_PATTERN_SEQUENCE:         return "SEQUENCE";
    case OZAYN_SDET_PATTERN_CORRELATED_SEQ:   return "CORRELATED_SEQ";
    case OZAYN_SDET_PATTERN_STATE_TRANSITION:  return "STATE_TRANSITION";
    }
    return "UNKNOWN";
}

const char *ozayn_sdet_confidence_name(ozayn_sdet_confidence_t c)
{
    switch (c) {
    case OZAYN_SDET_CONFIDENCE_LOW:      return "LOW";
    case OZAYN_SDET_CONFIDENCE_MEDIUM:   return "MEDIUM";
    case OZAYN_SDET_CONFIDENCE_HIGH:     return "HIGH";
    case OZAYN_SDET_CONFIDENCE_VERY_HIGH: return "VERY_HIGH";
    }
    return "UNKNOWN";
}

const char *ozayn_sdet_finding_state_name(ozayn_sdet_finding_state_t s)
{
    switch (s) {
    case OZAYN_SDET_FINDING_DETECTED:         return "DETECTED";
    case OZAYN_SDET_FINDING_INVESTIGATING:    return "INVESTIGATING";
    case OZAYN_SDET_FINDING_CONFIRMED_THREAT: return "CONFIRMED_THREAT";
    case OZAYN_SDET_FINDING_FALSE_POSITIVE:   return "FALSE_POSITIVE";
    case OZAYN_SDET_FINDING_EXPIRED:          return "EXPIRED";
    case OZAYN_SDET_FINDING_INCIDENT_CREATED: return "INCIDENT_CREATED";
    case OZAYN_SDET_FINDING_ALERT_CREATED:    return "ALERT_CREATED";
    }
    return "UNKNOWN";
}

const char *ozayn_sdet_severity_name(ozayn_sdet_severity_t sev)
{
    switch (sev) {
    case OZAYN_SDET_SEV_INFO:     return "INFO";
    case OZAYN_SDET_SEV_NOTICE:   return "NOTICE";
    case OZAYN_SDET_SEV_WARNING:  return "WARNING";
    case OZAYN_SDET_SEV_HIGH:     return "HIGH";
    case OZAYN_SDET_SEV_CRITICAL: return "CRITICAL";
    }
    return "UNKNOWN";
}

int ozayn_sdet_severity_to_audit_severity(ozayn_sdet_severity_t sev)
{
    switch (sev) {
    case OZAYN_SDET_SEV_INFO:     return 0;
    case OZAYN_SDET_SEV_NOTICE:   return 1;
    case OZAYN_SDET_SEV_WARNING:  return 2;
    case OZAYN_SDET_SEV_HIGH:     return 3;
    case OZAYN_SDET_SEV_CRITICAL: return 4;
    }
    return 0;
}

int ozayn_sdet_severity_to_salert_severity(ozayn_sdet_severity_t sev)
{
    switch (sev) {
    case OZAYN_SDET_SEV_INFO:     return 0;
    case OZAYN_SDET_SEV_NOTICE:   return 1;
    case OZAYN_SDET_SEV_WARNING:  return 2;
    case OZAYN_SDET_SEV_HIGH:     return 3;
    case OZAYN_SDET_SEV_CRITICAL: return 4;
    }
    return 0;
}

/* ============================================================
 * SECTION 15 — LIFECYCLE
 * ============================================================ */

ozayn_sdet_err_t ozayn_sdet_service_init(
    ozayn_sdet_service_t *svc,
    const ozayn_sdet_service_config_t *cfg)
{
    if (!svc) return OZAYN_SDET_ERR_NULL;
    if (svc->initialized) return OZAYN_SDET_ERR_ALREADY_INITIALIZED;

    memset(svc, 0, sizeof(*svc));

    if (cfg) {
        svc->alert_service    = cfg->alert_service;
        svc->incident_service = cfg->incident_service;
        svc->audit            = cfg->audit;
    }

    svc->policy = ozayn_sdet_default_policy();
    svc->initialized = 1;
    return OZAYN_SDET_OK;
}

void ozayn_sdet_service_shutdown(ozayn_sdet_service_t *svc)
{
    if (!svc) return;
    svc->initialized = 0;
}

int ozayn_sdet_service_is_initialized(const ozayn_sdet_service_t *svc)
{
    return svc ? svc->initialized : 0;
}

/* ============================================================
 * SECTION 17 — EVENT PROCESSING
 * ============================================================ */

static ozayn_sdet_event_category_t _normalize_event_type(
    ozayn_audit_event_type_t audit_type,
    ozayn_audit_outcome_t outcome)
{
    (void)outcome;
    switch (audit_type) {
    case OZAYN_AUDIT_AUTH_STARTED:
    case OZAYN_AUDIT_AUTH_SUCCEEDED:
    case OZAYN_AUDIT_PWD_AUTH_SUCCEEDED:
        return OZAYN_SDET_EVT_AUTH_SUCCESS;
    case OZAYN_AUDIT_AUTH_FAILED:
    case OZAYN_AUDIT_PWD_AUTH_FAILED:
        return OZAYN_SDET_EVT_AUTH_FAILURE;
    case OZAYN_AUDIT_AUTH_REJECTED:
        return OZAYN_SDET_EVT_AUTH_BLOCKED;
    case OZAYN_AUDIT_RATE_LIMITED:
        return OZAYN_SDET_EVT_AUTH_RATE_LIMIT;
    case OZAYN_AUDIT_TEMPORARILY_BLOCKED:
        return OZAYN_SDET_EVT_AUTH_BLOCKED;
    case OZAYN_AUDIT_MFA_COMPLETED:
    case OZAYN_AUDIT_MFA_FACTOR_VERIFIED:
        return OZAYN_SDET_EVT_MFA_SUCCESS;
    case OZAYN_AUDIT_MFA_FAILED:
    case OZAYN_AUDIT_MFA_FACTOR_FAILED:
        return OZAYN_SDET_EVT_MFA_FAILURE;
    case OZAYN_AUDIT_MFA_BLOCKED:
        return OZAYN_SDET_EVT_MFA_BLOCKED;
    case OZAYN_AUDIT_SESSION_CREATED:
        return OZAYN_SDET_EVT_SESSION_CREATED;
    case OZAYN_AUDIT_SESSION_VALIDATED:
        return OZAYN_SDET_EVT_SESSION_VALIDATED;
    case OZAYN_AUDIT_SESSION_EXPIRED:
        return OZAYN_SDET_EVT_SESSION_FAILED;
    case OZAYN_AUDIT_SESSION_TERMINATED:
    case OZAYN_AUDIT_SESSION_REVOKED:
        return OZAYN_SDET_EVT_SESSION_TERMINATED;
    case OZAYN_AUDIT_AUTHZ_ALLOWED:
        return OZAYN_SDET_EVT_AUTHZ_ALLOWED;
    case OZAYN_AUDIT_AUTHZ_DENIED:
        return OZAYN_SDET_EVT_AUTHZ_DENIED;
    case OZAYN_AUDIT_PERM_DENIED:
        return OZAYN_SDET_EVT_PERM_DENIED;
    case OZAYN_AUDIT_PERM_MATCHED:
        return OZAYN_SDET_EVT_PERM_MATCHED;
    case OZAYN_AUDIT_ROLE_CREATED:
        return OZAYN_SDET_EVT_ROLE_CREATED;
    case OZAYN_AUDIT_ROLE_REVOKED:
    case OZAYN_AUDIT_ROLE_SUSPENDED:
        return OZAYN_SDET_EVT_ROLE_REVOKED;
    case OZAYN_AUDIT_ROLE_ASSIGNED:
        return OZAYN_SDET_EVT_ROLE_ASSIGNED;
    case OZAYN_AUDIT_ROLE_ASSIGNMENT_REVOKED:
        return OZAYN_SDET_EVT_ROLE_ASSIGN_REVOKED;
    case OZAYN_AUDIT_POLICY_REJECTED:
    case OZAYN_AUDIT_CONFIG_CHANGED:
        return OZAYN_SDET_EVT_CONFIG_CHANGED;
    case OZAYN_AUDIT_COMPONENT_UNAVAILABLE:
        return OZAYN_SDET_EVT_COMPONENT_UNAVAILABLE;
    case OZAYN_AUDIT_INTEGRITY_FAILURE:
        return OZAYN_SDET_EVT_INTEGRITY_FAILURE;
    case OZAYN_AUDIT_STORAGE_FAILURE:
        return OZAYN_SDET_EVT_VAULT_FAILURE;
    case OZAYN_AUDIT_VIOLATION_DETECTED:
        return OZAYN_SDET_EVT_VIOLATION_DETECTED;
    case OZAYN_AUDIT_SERVICE_UNAVAILABLE:
        return OZAYN_SDET_EVT_COMPONENT_UNAVAILABLE;
    default:
        return OZAYN_SDET_EVT_CONFIG_CHANGED;
    }
}

ozayn_sdet_err_t ozayn_sdet_normalize_audit_event(
    const ozayn_audit_event_t *audit_event,
    ozayn_sdet_event_t *out_event)
{
    if (!audit_event || !out_event)
        return OZAYN_SDET_ERR_NULL;

    memset(out_event, 0, sizeof(*out_event));
    strncpy(out_event->event_id, audit_event->event_id,
            OZAYN_SDET_MAX_EVENT_ID_LEN - 1);
    out_event->category = _normalize_event_type(
        audit_event->event_type, audit_event->outcome);
    out_event->timestamp = audit_event->timestamp;
    out_event->outcome_success =
        (audit_event->outcome == OZAYN_AUDIT_OUTCOME_SUCCESS);
    out_event->severity = (ozayn_sdet_severity_t)audit_event->severity;
    if (out_event->severity > OZAYN_SDET_SEV_CRITICAL)
        out_event->severity = OZAYN_SDET_SEV_CRITICAL;

    strncpy(out_event->identity_id, audit_event->identity_id,
            OZAYN_SDET_MAX_ID_LEN - 1);
    strncpy(out_event->session_id, audit_event->session_id,
            OZAYN_SDET_MAX_ID_LEN - 1);
    strncpy(out_event->resource_id, audit_event->resource_id,
            OZAYN_SDET_MAX_ID_LEN - 1);
    strncpy(out_event->source_component, audit_event->source_component,
            OZAYN_SDET_MAX_SOURCE_LEN - 1);
    strncpy(out_event->request_id, audit_event->request_id,
            OZAYN_SDET_MAX_ID_LEN - 1);
    strncpy(out_event->correlation_id, audit_event->correlation_id,
            OZAYN_SDET_MAX_CORR_ID_LEN - 1);

    return OZAYN_SDET_OK;
}

ozayn_sdet_err_t ozayn_sdet_process_event(
    ozayn_sdet_service_t *svc,
    const ozayn_sdet_event_t *event)
{
    if (!svc) return OZAYN_SDET_ERR_NULL;
    if (!svc->initialized) return OZAYN_SDET_ERR_NOT_INITIALIZED;
    if (!event) return OZAYN_SDET_ERR_NULL;
    if (!svc->policy.enabled) return OZAYN_SDET_ERR_POLICY_REJECTED;

    if (svc->event_count >= OZAYN_SDET_MAX_EVENTS)
        return OZAYN_SDET_ERR_RESOURCE_EXHAUSTED;

    ozayn_sdet_event_t *e = _alloc_event(svc);
    *e = *event;
    if (!e->event_id[0])
        _generate_id(e->event_id, OZAYN_SDET_MAX_EVENT_ID_LEN,
                     "SEVT", svc->event_sequence++);
    if (e->timestamp == 0) e->timestamp = time(NULL);

    svc->total_events_received++;
    svc->total_events_normalized++;

    ozayn_sdet_evaluate_single(svc, e);

    return OZAYN_SDET_OK;
}

/* ============================================================
 * SECTION 18 — PATTERN MANAGEMENT
 * ============================================================ */

ozayn_sdet_err_t ozayn_sdet_register_pattern(
    ozayn_sdet_service_t *svc,
    const ozayn_sdet_pattern_t *pattern)
{
    if (!svc) return OZAYN_SDET_ERR_NULL;
    if (!svc->initialized) return OZAYN_SDET_ERR_NOT_INITIALIZED;
    if (!pattern) return OZAYN_SDET_ERR_NULL;
    if (!pattern->pattern_id[0]) return OZAYN_SDET_ERR_INVALID_PARAM;
    if (svc->pattern_count >= svc->policy.threshold_max_count &&
        svc->policy.threshold_max_count > 0)
        return OZAYN_SDET_ERR_LIMIT_REACHED;
    if (svc->pattern_count >= OZAYN_SDET_MAX_PATTERNS)
        return OZAYN_SDET_ERR_LIMIT_REACHED;

    for (int i = 0; i < svc->pattern_count; i++) {
        if (strcmp(svc->patterns[i].pattern_id, pattern->pattern_id) == 0)
            return OZAYN_SDET_ERR_PATTERN_INVALID;
    }

    svc->patterns[svc->pattern_count] = *pattern;
    svc->pattern_count++;
    return OZAYN_SDET_OK;
}

ozayn_sdet_err_t ozayn_sdet_unregister_pattern(
    ozayn_sdet_service_t *svc,
    const char *pattern_id)
{
    if (!svc) return OZAYN_SDET_ERR_NULL;
    if (!svc->initialized) return OZAYN_SDET_ERR_NOT_INITIALIZED;
    if (!pattern_id) return OZAYN_SDET_ERR_INVALID_PARAM;

    for (int i = 0; i < svc->pattern_count; i++) {
        if (strcmp(svc->patterns[i].pattern_id, pattern_id) == 0) {
            svc->patterns[i] = svc->patterns[svc->pattern_count - 1];
            memset(&svc->patterns[svc->pattern_count - 1], 0,
                   sizeof(ozayn_sdet_pattern_t));
            svc->pattern_count--;
            return OZAYN_SDET_OK;
        }
    }
    return OZAYN_SDET_ERR_PATTERN_NOT_FOUND;
}

const ozayn_sdet_pattern_t *ozayn_sdet_get_pattern(
    const ozayn_sdet_service_t *svc,
    const char *pattern_id)
{
    if (!svc || !pattern_id) return NULL;
    for (int i = 0; i < svc->pattern_count; i++) {
        if (strcmp(svc->patterns[i].pattern_id, pattern_id) == 0)
            return &svc->patterns[i];
    }
    return NULL;
}

int ozayn_sdet_pattern_count(const ozayn_sdet_service_t *svc)
{
    return svc ? svc->pattern_count : 0;
}

ozayn_sdet_err_t ozayn_sdet_enable_pattern(
    ozayn_sdet_service_t *svc,
    const char *pattern_id,
    int enabled)
{
    if (!svc) return OZAYN_SDET_ERR_NULL;
    if (!svc->initialized) return OZAYN_SDET_ERR_NOT_INITIALIZED;
    ozayn_sdet_pattern_t *p = (ozayn_sdet_pattern_t *)
        ozayn_sdet_get_pattern(svc, pattern_id);
    if (!p) return OZAYN_SDET_ERR_PATTERN_NOT_FOUND;
    p->enabled = enabled;
    return OZAYN_SDET_OK;
}

/* ============================================================
 * SECTION 20 — CORRELATION
 * ============================================================ */

ozayn_sdet_err_t ozayn_sdet_create_correlation(
    ozayn_sdet_service_t *svc,
    const ozayn_sdet_event_t *event,
    int pattern_index,
    ozayn_sdet_correlation_t **out_corr)
{
    if (!svc || !event || !out_corr)
        return OZAYN_SDET_ERR_NULL;
    if (svc->corr_count >= OZAYN_SDET_MAX_CORRELATIONS)
        return OZAYN_SDET_ERR_CORRELATION_LIMIT;

    ozayn_sdet_correlation_t *c = &svc->correlations[svc->corr_count];
    memset(c, 0, sizeof(*c));
    _generate_id(c->corr_id, OZAYN_SDET_MAX_ID_LEN,
                 "SCORR", svc->total_correlations_created + 1);
    c->state = OZAYN_SDET_CORR_NEW;
    c->first_event_time = event->timestamp;
    c->last_event_time = event->timestamp;
    c->event_count = 1;
    c->pattern_index = pattern_index;
    c->window_start = event->timestamp;
    strncpy(c->identity_id, event->identity_id, OZAYN_SDET_MAX_ID_LEN - 1);
    strncpy(c->session_id, event->session_id, OZAYN_SDET_MAX_ID_LEN - 1);
    strncpy(c->resource_id, event->resource_id, OZAYN_SDET_MAX_ID_LEN - 1);
    svc->corr_count++;
    svc->total_correlations_created++;
    *out_corr = c;
    return OZAYN_SDET_OK;
}

ozayn_sdet_correlation_t *ozayn_sdet_find_correlation(
    ozayn_sdet_service_t *svc,
    const char *identity_id,
    const char *session_id,
    int pattern_index)
{
    if (!svc) return NULL;
    time_t now = time(NULL);
    for (int i = 0; i < svc->corr_count; i++) {
        ozayn_sdet_correlation_t *c = &svc->correlations[i];
        if (c->state == OZAYN_SDET_CORR_EXPIRED ||
            c->state == OZAYN_SDET_CORR_DISMISSED)
            continue;
        if (c->pattern_index != pattern_index) continue;
        if (identity_id && identity_id[0] &&
            c->identity_id[0] &&
            strcmp(c->identity_id, identity_id) != 0)
            continue;
        if (session_id && session_id[0] &&
            c->session_id[0] &&
            strcmp(c->session_id, session_id) != 0)
            continue;
        const ozayn_sdet_pattern_t *pat = &svc->patterns[c->pattern_index];
        if (pat->window_seconds > 0 &&
            (now - c->window_start) > pat->window_seconds) {
            c->state = OZAYN_SDET_CORR_EXPIRED;
            svc->total_correlations_expired++;
            continue;
        }
        return c;
    }
    return NULL;
}

ozayn_sdet_err_t ozayn_sdet_expire_correlations(ozayn_sdet_service_t *svc)
{
    if (!svc) return OZAYN_SDET_ERR_NULL;
    if (!svc->initialized) return OZAYN_SDET_ERR_NOT_INITIALIZED;
    time_t now = time(NULL);
    int expired = 0;
    for (int i = 0; i < svc->corr_count; i++) {
        ozayn_sdet_correlation_t *c = &svc->correlations[i];
        if (c->state == OZAYN_SDET_CORR_EXPIRED ||
            c->state == OZAYN_SDET_CORR_DISMISSED)
            continue;
        if (c->pattern_index >= 0 && c->pattern_index < svc->pattern_count) {
            const ozayn_sdet_pattern_t *pat = &svc->patterns[c->pattern_index];
            if (pat->window_seconds > 0 &&
                (now - c->window_start) > pat->window_seconds) {
                c->state = OZAYN_SDET_CORR_EXPIRED;
                expired++;
            }
        }
    }
    svc->total_correlations_expired += expired;
    return OZAYN_SDET_OK;
}

int ozayn_sdet_correlation_count(const ozayn_sdet_service_t *svc)
{
    if (!svc) return 0;
    int active = 0;
    for (int i = 0; i < svc->corr_count; i++) {
        if (svc->correlations[i].state != OZAYN_SDET_CORR_EXPIRED &&
            svc->correlations[i].state != OZAYN_SDET_CORR_DISMISSED)
            active++;
    }
    return active;
}

/* ============================================================
 * SECTION 19 — PATTERN EVALUATION
 * ============================================================ */

static int _event_matches_category(const ozayn_sdet_event_t *event,
                                    ozayn_sdet_event_category_t cat)
{
    return event->category == cat;
}

ozayn_sdet_err_t ozayn_sdet_evaluate_single(
    ozayn_sdet_service_t *svc,
    const ozayn_sdet_event_t *event)
{
    if (!svc || !event) return OZAYN_SDET_ERR_NULL;

    for (int i = 0; i < svc->pattern_count; i++) {
        ozayn_sdet_pattern_t *pat = &svc->patterns[i];
        if (!pat->enabled) continue;
        if (pat->pattern_type != OZAYN_SDET_PATTERN_SINGLE) continue;

        for (int j = 0; j < pat->event_count; j++) {
            if (_event_matches_category(event, pat->events[j])) {
                svc->total_patterns_evaluated++;
                ozayn_sdet_correlation_t *corr = NULL;
                ozayn_sdet_create_correlation(svc, event, i, &corr);
                if (corr) {
                    corr->state = OZAYN_SDET_CORR_MATCHED;
                    svc->total_correlations_matched++;
                }
                ozayn_sdet_finding_t *finding = NULL;
                ozayn_sdet_create_finding(svc, pat, corr, &finding);
                break;
            }
        }
    }
    return OZAYN_SDET_OK;
}

ozayn_sdet_err_t ozayn_sdet_evaluate_threshold(
    ozayn_sdet_service_t *svc,
    const ozayn_sdet_pattern_t *pattern)
{
    if (!svc || !pattern) return OZAYN_SDET_ERR_NULL;

    time_t now = time(NULL);
    int window = pattern->window_seconds;
    if (window <= 0) window = 300;

    int match_count = 0;
    for (int i = 0; i < svc->event_count; i++) {
        int slot = (svc->event_head + i) % OZAYN_SDET_MAX_EVENTS;
        const ozayn_sdet_event_t *e = &svc->events[slot];
        if ((now - e->timestamp) > window) continue;
        for (int j = 0; j < pattern->event_count; j++) {
            if (_event_matches_category(e, pattern->events[j])) {
                match_count++;
                break;
            }
        }
    }

    if (match_count >= pattern->threshold_count) {
        svc->total_patterns_evaluated++;
        ozayn_sdet_correlation_t *corr = NULL;
        ozayn_sdet_event_t synthetic;
        memset(&synthetic, 0, sizeof(synthetic));
        synthetic.timestamp = now;
        synthetic.category = pattern->events[0];
        ozayn_sdet_create_correlation(svc, &synthetic,
            (int)(pattern - svc->patterns), &corr);
        if (corr) {
            corr->state = OZAYN_SDET_CORR_MATCHED;
            corr->matched_count = match_count;
            svc->total_correlations_matched++;
        }
        ozayn_sdet_finding_t *finding = NULL;
        ozayn_sdet_create_finding(svc, pattern, corr, &finding);
        return OZAYN_SDET_OK;
    }
    return OZAYN_SDET_OK;
}

ozayn_sdet_err_t ozayn_sdet_evaluate_sequence(
    ozayn_sdet_service_t *svc,
    const ozayn_sdet_pattern_t *pattern)
{
    if (!svc || !pattern) return OZAYN_SDET_ERR_NULL;
    if (pattern->sequence_count <= 0) return OZAYN_SDET_OK;

    time_t now = time(NULL);
    int window = pattern->window_seconds;
    if (window <= 0) window = 300;

    int seq_pos = 0;
    time_t last_match_time = 0;

    for (int i = 0; i < svc->event_count; i++) {
        int slot = (svc->event_head + i) % OZAYN_SDET_MAX_EVENTS;
        const ozayn_sdet_event_t *e = &svc->events[slot];
        if ((now - e->timestamp) > window) continue;
        if (seq_pos < pattern->sequence_count &&
            _event_matches_category(e, pattern->sequence[seq_pos])) {
            if (seq_pos == 0 || e->timestamp >= last_match_time) {
                seq_pos++;
                last_match_time = e->timestamp;
            }
        }
    }

    if (seq_pos >= pattern->sequence_count) {
        svc->total_patterns_evaluated++;
        ozayn_sdet_correlation_t *corr = NULL;
        ozayn_sdet_event_t synthetic;
        memset(&synthetic, 0, sizeof(synthetic));
        synthetic.timestamp = now;
        synthetic.category = pattern->sequence[0];
        ozayn_sdet_create_correlation(svc, &synthetic,
            (int)(pattern - svc->patterns), &corr);
        if (corr) {
            corr->state = OZAYN_SDET_CORR_MATCHED;
            corr->matched_count = seq_pos;
            svc->total_correlations_matched++;
        }
        ozayn_sdet_finding_t *finding = NULL;
        ozayn_sdet_create_finding(svc, pattern, corr, &finding);
        return OZAYN_SDET_OK;
    }
    return OZAYN_SDET_OK;
}

ozayn_sdet_err_t ozayn_sdet_evaluate_patterns(ozayn_sdet_service_t *svc)
{
    if (!svc) return OZAYN_SDET_ERR_NULL;
    if (!svc->initialized) return OZAYN_SDET_ERR_NOT_INITIALIZED;

    ozayn_sdet_expire_correlations(svc);

    for (int i = 0; i < svc->pattern_count; i++) {
        ozayn_sdet_pattern_t *pat = &svc->patterns[i];
        if (!pat->enabled) continue;

        switch (pat->pattern_type) {
        case OZAYN_SDET_PATTERN_THRESHOLD:
            ozayn_sdet_evaluate_threshold(svc, pat);
            break;
        case OZAYN_SDET_PATTERN_SEQUENCE:
        case OZAYN_SDET_PATTERN_CORRELATED_SEQ:
            ozayn_sdet_evaluate_sequence(svc, pat);
            break;
        default:
            break;
        }
    }
    return OZAYN_SDET_OK;
}

/* ============================================================
 * SECTION 22 — DEDUPLICATION
 * ============================================================ */

int ozayn_sdet_finding_is_duplicate(
    const ozayn_sdet_service_t *svc,
    const char *pattern_id,
    const char *identity_id,
    const char *resource_id)
{
    if (!svc || !pattern_id) return 0;
    time_t now = time(NULL);
    int window = svc->policy.dedup_window_seconds;
    if (window <= 0) window = 300;

    for (int i = 0; i < svc->finding_count; i++) {
        int slot = (svc->finding_head + i) % OZAYN_SDET_MAX_FINDINGS;
        const ozayn_sdet_finding_t *f = &svc->findings[slot];
        if (strcmp(f->pattern_id, pattern_id) != 0) continue;
        if (f->state == OZAYN_SDET_FINDING_EXPIRED ||
            f->state == OZAYN_SDET_FINDING_FALSE_POSITIVE)
            continue;
        if ((now - f->detection_time) > window) continue;
        if (identity_id && identity_id[0] && f->identity_id[0] &&
            strcmp(f->identity_id, identity_id) != 0)
            continue;
        if (resource_id && resource_id[0] && f->resource_id[0] &&
            strcmp(f->resource_id, resource_id) != 0)
            continue;
        return 1;
    }
    return 0;
}

/* ============================================================
 * SECTION 21 — FINDINGS
 * ============================================================ */

ozayn_sdet_err_t ozayn_sdet_create_finding(
    ozayn_sdet_service_t *svc,
    const ozayn_sdet_pattern_t *pattern,
    const ozayn_sdet_correlation_t *corr,
    ozayn_sdet_finding_t **out_finding)
{
    if (!svc || !pattern) return OZAYN_SDET_ERR_NULL;
    if (!out_finding) return OZAYN_SDET_ERR_NULL;
    if (svc->finding_count >= OZAYN_SDET_MAX_FINDINGS)
        return OZAYN_SDET_ERR_FINDING_LIMIT;

    const char *identity = corr ? corr->identity_id : "";
    const char *resource = corr ? corr->resource_id : "";

    if (ozayn_sdet_finding_is_duplicate(svc, pattern->pattern_id,
                                         identity, resource)) {
        svc->total_findings_deduplicated++;
        *out_finding = NULL;
        return OZAYN_SDET_OK;
    }

    ozayn_sdet_finding_t *f = _alloc_finding(svc);
    _generate_id(f->finding_id, OZAYN_SDET_MAX_FINDING_ID_LEN,
                 "SFIND", svc->finding_sequence++);
    strncpy(f->pattern_id, pattern->pattern_id,
            OZAYN_SDET_MAX_PATTERN_ID_LEN - 1);
    f->pattern_version = pattern->version;
    f->detection_time = time(NULL);
    f->first_event_time = corr ? corr->first_event_time : f->detection_time;
    f->last_event_time = corr ? corr->last_event_time : f->detection_time;
    f->severity = pattern->severity;
    f->confidence = pattern->confidence;
    f->state = OZAYN_SDET_FINDING_DETECTED;
    f->event_count = corr ? corr->event_count : 1;

    if (corr) {
        strncpy(f->identity_id, corr->identity_id,
                OZAYN_SDET_MAX_ID_LEN - 1);
        strncpy(f->session_id, corr->session_id,
                OZAYN_SDET_MAX_ID_LEN - 1);
        strncpy(f->resource_id, corr->resource_id,
                OZAYN_SDET_MAX_ID_LEN - 1);
        strncpy(f->correlation_id, corr->corr_id,
                OZAYN_SDET_MAX_CORR_ID_LEN - 1);
    }

    svc->total_findings_created++;
    _audit_event(svc, "THREAT_DETECTED", f->finding_id);
    *out_finding = f;
    return OZAYN_SDET_OK;
}

ozayn_sdet_finding_t *ozayn_sdet_get_finding(
    ozayn_sdet_service_t *svc,
    const char *finding_id)
{
    if (!svc || !finding_id) return NULL;
    for (int i = 0; i < svc->finding_count; i++) {
        int slot = (svc->finding_head + i) % OZAYN_SDET_MAX_FINDINGS;
        if (strcmp(svc->findings[slot].finding_id, finding_id) == 0)
            return &svc->findings[slot];
    }
    return NULL;
}

int ozayn_sdet_finding_count(const ozayn_sdet_service_t *svc)
{
    return svc ? svc->finding_count : 0;
}

int ozayn_sdet_list_findings(
    const ozayn_sdet_service_t *svc,
    int filter_state,
    ozayn_sdet_finding_t **out_findings,
    int max_count)
{
    if (!svc || !out_findings || max_count <= 0) return 0;
    int count = 0;
    for (int i = 0; i < svc->finding_count && count < max_count; i++) {
        int slot = (svc->finding_head + i) % OZAYN_SDET_MAX_FINDINGS;
        const ozayn_sdet_finding_t *f = &svc->findings[slot];
        int state_match = (filter_state < 0 ||
                           f->state == (ozayn_sdet_finding_state_t)filter_state);
        if (state_match) {
            out_findings[count] = (ozayn_sdet_finding_t *)f;
            count++;
        }
    }
    return count;
}

ozayn_sdet_err_t ozayn_sdet_finding_set_state(
    ozayn_sdet_service_t *svc,
    const char *finding_id,
    ozayn_sdet_finding_state_t new_state)
{
    if (!svc) return OZAYN_SDET_ERR_NULL;
    if (!svc->initialized) return OZAYN_SDET_ERR_NOT_INITIALIZED;
    ozayn_sdet_finding_t *f = ozayn_sdet_get_finding(svc, finding_id);
    if (!f) return OZAYN_SDET_ERR_NOT_FOUND;

    switch (new_state) {
    case OZAYN_SDET_FINDING_INVESTIGATING:
        if (f->state != OZAYN_SDET_FINDING_DETECTED)
            return OZAYN_SDET_ERR_STATE_TRANSITION;
        break;
    case OZAYN_SDET_FINDING_CONFIRMED_THREAT:
        if (f->state != OZAYN_SDET_FINDING_DETECTED &&
            f->state != OZAYN_SDET_FINDING_INVESTIGATING)
            return OZAYN_SDET_ERR_STATE_TRANSITION;
        break;
    case OZAYN_SDET_FINDING_FALSE_POSITIVE:
        if (f->state == OZAYN_SDET_FINDING_EXPIRED ||
            f->state == OZAYN_SDET_FINDING_FALSE_POSITIVE)
            return OZAYN_SDET_ERR_STATE_TRANSITION;
        break;
    case OZAYN_SDET_FINDING_EXPIRED:
        break;
    case OZAYN_SDET_FINDING_INCIDENT_CREATED:
    case OZAYN_SDET_FINDING_ALERT_CREATED:
        break;
    default:
        return OZAYN_SDET_ERR_STATE_TRANSITION;
    }

    f->state = new_state;
    f->finding_version++;
    return OZAYN_SDET_OK;
}

int ozayn_sdet_cleanup_expired_findings(ozayn_sdet_service_t *svc)
{
    if (!svc) return 0;
    time_t now = time(NULL);
    int cleaned = 0;
    int retention = svc->policy.finding_retention_seconds;
    if (retention <= 0) retention = 86400;

    for (int i = 0; i < svc->finding_count; i++) {
        int slot = (svc->finding_head + i) % OZAYN_SDET_MAX_FINDINGS;
        ozayn_sdet_finding_t *f = &svc->findings[slot];
        if (f->state == OZAYN_SDET_FINDING_CONFIRMED_THREAT) continue;
        if (f->state == OZAYN_SDET_FINDING_INCIDENT_CREATED) continue;
        if ((now - f->detection_time) > retention) {
            f->state = OZAYN_SDET_FINDING_EXPIRED;
            cleaned++;
        }
    }
    return cleaned;
}

/* ============================================================
 * SECTION 23 — DETECTION POLICY
 * ============================================================ */

ozayn_sdet_policy_t ozayn_sdet_default_policy(void)
{
    ozayn_sdet_policy_t p;
    memset(&p, 0, sizeof(p));
    p.enabled = 1;
    for (int i = 0; i < 64; i++) p.enabled_patterns[i] = 1;
    p.max_correlation_window_seconds = 3600;
    p.min_correlation_window_seconds = 10;
    p.max_events_per_correlation = 100;
    p.max_active_correlations = 128;
    p.max_findings = OZAYN_SDET_MAX_FINDINGS;
    p.max_findings_per_window = 50;
    p.finding_retention_seconds = 86400;
    p.dedup_window_seconds = 300;
    p.threshold_max_count = 64;
    p.severity_escalation_enabled = 1;
    p.incident_integration_enabled = 1;
    p.alert_integration_enabled = 1;
    return p;
}

ozayn_sdet_err_t ozayn_sdet_set_policy(
    ozayn_sdet_service_t *svc,
    const ozayn_sdet_policy_t *policy)
{
    if (!svc || !policy) return OZAYN_SDET_ERR_NULL;
    if (!svc->initialized) return OZAYN_SDET_ERR_NOT_INITIALIZED;
    if (!policy->enabled) return OZAYN_SDET_ERR_POLICY_REJECTED;
    svc->policy = *policy;
    return OZAYN_SDET_OK;
}

const ozayn_sdet_policy_t *ozayn_sdet_get_policy(
    const ozayn_sdet_service_t *svc)
{
    return svc ? &svc->policy : NULL;
}

/* ============================================================
 * SECTION 24 — INTEGRATION: INCIDENT RESPONSE
 * ============================================================ */

ozayn_sdet_err_t ozayn_sdet_create_incident_from_finding(
    ozayn_sdet_service_t *svc,
    ozayn_sdet_finding_t *finding)
{
    if (!svc || !finding) return OZAYN_SDET_ERR_NULL;
    if (!svc->incident_service || !svc->incident_service->initialized)
        return OZAYN_SDET_ERR_UNAVAILABLE;
    if (!svc->policy.incident_integration_enabled)
        return OZAYN_SDET_ERR_POLICY_REJECTED;

    ozayn_sdet_finding_state_t allowed_states[] = {
        OZAYN_SDET_FINDING_DETECTED,
        OZAYN_SDET_FINDING_INVESTIGATING,
        OZAYN_SDET_FINDING_CONFIRMED_THREAT
    };
    int state_ok = 0;
    for (int i = 0; i < 3; i++) {
        if (finding->state == allowed_states[i]) { state_ok = 1; break; }
    }
    if (!state_ok) return OZAYN_SDET_ERR_STATE_TRANSITION;

    ozayn_ir_severity_t ir_sev = OZAYN_IR_SEV_LOW;
    switch (finding->severity) {
    case OZAYN_SDET_SEV_INFO:     ir_sev = OZAYN_IR_SEV_INFO; break;
    case OZAYN_SDET_SEV_NOTICE:   ir_sev = OZAYN_IR_SEV_LOW; break;
    case OZAYN_SDET_SEV_WARNING:  ir_sev = OZAYN_IR_SEV_MEDIUM; break;
    case OZAYN_SDET_SEV_HIGH:     ir_sev = OZAYN_IR_SEV_HIGH; break;
    case OZAYN_SDET_SEV_CRITICAL: ir_sev = OZAYN_IR_SEV_CRITICAL; break;
    }

    ozayn_ir_incident_t *ir_inc = NULL;
    ozayn_ir_result_t rc = ozayn_ir_report(
        svc->incident_service,
        OZAYN_IR_TYPE_SUSPICIOUS_ACTIVITY,
        ir_sev,
        "SEC_DETECT",
        finding->identity_id,
        finding->session_id,
        finding->resource_id,
        finding->correlation_id,
        finding->safe_metadata,
        &ir_inc);

    if (rc == OZAYN_IR_OK) {
        finding->state = OZAYN_SDET_FINDING_INCIDENT_CREATED;
        finding->finding_version++;
        svc->total_incidents_created++;
        _audit_event(svc, "INCIDENT_CREATED_FROM_FINDING",
                     finding->finding_id);
    }
    return OZAYN_SDET_OK;
}

/* ============================================================
 * SECTION 25 — INTEGRATION: ALERTING
 * ============================================================ */

ozayn_sdet_err_t ozayn_sdet_create_alert_from_finding(
    ozayn_sdet_service_t *svc,
    ozayn_sdet_finding_t *finding)
{
    if (!svc || !finding) return OZAYN_SDET_ERR_NULL;
    if (!svc->alert_service || !svc->alert_service->initialized)
        return OZAYN_SDET_ERR_UNAVAILABLE;
    if (!svc->policy.alert_integration_enabled)
        return OZAYN_SDET_ERR_POLICY_REJECTED;

    ozayn_salert_severity_t al_sev = OZAYN_SALERT_SEV_NOTICE;
    switch (finding->severity) {
    case OZAYN_SDET_SEV_INFO:     al_sev = OZAYN_SALERT_SEV_INFO; break;
    case OZAYN_SDET_SEV_NOTICE:   al_sev = OZAYN_SALERT_SEV_NOTICE; break;
    case OZAYN_SDET_SEV_WARNING:  al_sev = OZAYN_SALERT_SEV_WARNING; break;
    case OZAYN_SDET_SEV_HIGH:     al_sev = OZAYN_SALERT_SEV_HIGH; break;
    case OZAYN_SDET_SEV_CRITICAL: al_sev = OZAYN_SALERT_SEV_CRITICAL; break;
    }

    ozayn_salert_priority_t prio = OZAYN_SALERT_PRIO_NORMAL;
    if (finding->severity == OZAYN_SDET_SEV_CRITICAL)
        prio = OZAYN_SALERT_PRIO_IMMEDIATE;
    else if (finding->severity == OZAYN_SDET_SEV_HIGH)
        prio = OZAYN_SALERT_PRIO_HIGH;

    ozayn_salert_alert_t *alert = NULL;
    ozayn_salert_err_t rc = ozayn_salert_create(
        svc->alert_service,
        OZAYN_SALERT_TYPE_AUTH_ATTACK,
        al_sev,
        prio,
        OZAYN_SALERT_SOURCE_SECURITY_EVENT,
        "SEC_DETECT",
        finding->correlation_id,
        finding->pattern_id,
        finding->safe_metadata,
        &alert);

    if (rc == OZAYN_SALERT_OK && alert) {
        strncpy(finding->alert_id, alert->alert_id,
                OZAYN_SDET_MAX_ID_LEN - 1);
        finding->finding_version++;
        if (finding->state == OZAYN_SDET_FINDING_DETECTED ||
            finding->state == OZAYN_SDET_FINDING_INVESTIGATING) {
            finding->state = OZAYN_SDET_FINDING_ALERT_CREATED;
        }
        svc->total_alerts_created++;
        _audit_event(svc, "ALERT_CREATED_FROM_FINDING",
                     finding->finding_id);
    }
    return OZAYN_SDET_OK;
}

/* ============================================================
 * SECTION 26 — INTEGRATION: AUDIT
 * ============================================================ */

ozayn_sdet_err_t ozayn_sdet_audit_event(
    ozayn_sdet_service_t *svc,
    const char *event_type,
    const char *detail)
{
    if (!svc) return OZAYN_SDET_ERR_NULL;
    _audit_event(svc, event_type, detail);
    return OZAYN_SDET_OK;
}

/* ============================================================
 * SECTION 27 — QUERY
 * ============================================================ */

int ozayn_sdet_event_count(const ozayn_sdet_service_t *svc)
{
    return svc ? svc->event_count : 0;
}

int ozayn_sdet_list_events(
    const ozayn_sdet_service_t *svc,
    int filter_category,
    ozayn_sdet_event_t **out_events,
    int max_count)
{
    if (!svc || !out_events || max_count <= 0) return 0;
    int count = 0;
    for (int i = 0; i < svc->event_count && count < max_count; i++) {
        int slot = (svc->event_head + i) % OZAYN_SDET_MAX_EVENTS;
        const ozayn_sdet_event_t *e = &svc->events[slot];
        int cat_match = (filter_category < 0 ||
                         e->category == (ozayn_sdet_event_category_t)filter_category);
        if (cat_match) {
            out_events[count] = (ozayn_sdet_event_t *)e;
            count++;
        }
    }
    return count;
}

/* ============================================================
 * SECTION 28 — RESOURCE SAFETY
 * ============================================================ */

int ozayn_sdet_events_full(const ozayn_sdet_service_t *svc)
{
    if (!svc) return 1;
    return svc->event_count >= OZAYN_SDET_MAX_EVENTS;
}

int ozayn_sdet_correlations_full(const ozayn_sdet_service_t *svc)
{
    if (!svc) return 1;
    return svc->corr_count >= OZAYN_SDET_MAX_CORRELATIONS;
}

int ozayn_sdet_findings_full(const ozayn_sdet_service_t *svc)
{
    if (!svc) return 1;
    return svc->finding_count >= OZAYN_SDET_MAX_FINDINGS;
}

int ozayn_sdet_patterns_full(const ozayn_sdet_service_t *svc)
{
    if (!svc) return 1;
    if (svc->policy.threshold_max_count > 0 &&
        svc->pattern_count >= svc->policy.threshold_max_count)
        return 1;
    return svc->pattern_count >= OZAYN_SDET_MAX_PATTERNS;
}
