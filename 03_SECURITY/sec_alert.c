/*
 * sec_alert.c — Security Alerting & Security Notification Foundation
 *               (Step 29).
 */

#include "sec_alert.h"
#include <string.h>
#include <stdio.h>

/* ============================================================
 * INTERNAL — GLOBAL SERVICE
 * ============================================================ */

static ozayn_salert_service_t _salert_global = {0};

ozayn_salert_service_t *ozayn_salert_get_global(void)
{
    return &_salert_global;
}

/* ============================================================
 * INTERNAL — ID GENERATION
 * ============================================================ */

static uint32_t _hash_str(const char *s)
{
    uint32_t h = 5381;
    while (*s) {
        h = ((h << 5) + h) + (unsigned char)*s;
        s++;
    }
    return h;
}

static void _generate_id(char *out, int max_len, uint32_t seq)
{
    snprintf(out, (size_t)max_len, "SALERT-%08u", seq);
}

/* ============================================================
 * SECTION 28 — STATE TRANSITION VALIDATION
 * ============================================================ */

int ozayn_salert_state_transition_valid(ozayn_salert_state_t from,
                                         ozayn_salert_state_t to)
{
    switch (from) {
    case OZAYN_SALERT_STATE_DETECTED:
        return (to == OZAYN_SALERT_STATE_CREATED);
    case OZAYN_SALERT_STATE_CREATED:
        return (to == OZAYN_SALERT_STATE_ACTIVE);
    case OZAYN_SALERT_STATE_ACTIVE:
        return (to == OZAYN_SALERT_STATE_ACKNOWLEDGED ||
                to == OZAYN_SALERT_STATE_RESOLVED ||
                to == OZAYN_SALERT_STATE_SUPPRESSED ||
                to == OZAYN_SALERT_STATE_EXPIRED ||
                to == OZAYN_SALERT_STATE_CANCELLED);
    case OZAYN_SALERT_STATE_ACKNOWLEDGED:
        return (to == OZAYN_SALERT_STATE_RESOLVING ||
                to == OZAYN_SALERT_STATE_RESOLVED ||
                to == OZAYN_SALERT_STATE_CANCELLED);
    case OZAYN_SALERT_STATE_RESOLVING:
        return (to == OZAYN_SALERT_STATE_RESOLVED ||
                to == OZAYN_SALERT_STATE_FAILED);
    case OZAYN_SALERT_STATE_RESOLVED:
        return 0; /* terminal */
    case OZAYN_SALERT_STATE_SUPPRESSED:
        return (to == OZAYN_SALERT_STATE_ACTIVE);
    case OZAYN_SALERT_STATE_EXPIRED:
        return 0; /* terminal */
    case OZAYN_SALERT_STATE_FAILED:
        return (to == OZAYN_SALERT_STATE_ACTIVE);
    case OZAYN_SALERT_STATE_CANCELLED:
        return 0; /* terminal */
    default:
        return 0;
    }
}

/* ============================================================
 * SECTION 29 — NAME HELPERS
 * ============================================================ */

const char *ozayn_salert_err_name(ozayn_salert_err_t r)
{
    switch (r) {
    case OZAYN_SALERT_OK:                          return "OK";
    case OZAYN_SALERT_ERR:                         return "ERR";
    case OZAYN_SALERT_ERR_NULL:                    return "ERR_NULL";
    case OZAYN_SALERT_ERR_NOT_INITIALIZED:         return "ERR_NOT_INITIALIZED";
    case OZAYN_SALERT_ERR_ALREADY_INITIALIZED:     return "ERR_ALREADY_INITIALIZED";
    case OZAYN_SALERT_ERR_INVALID_REQUEST:         return "ERR_INVALID_REQUEST";
    case OZAYN_SALERT_ERR_INVALID_ID:              return "ERR_INVALID_ID";
    case OZAYN_SALERT_ERR_INVALID_TYPE:            return "ERR_INVALID_TYPE";
    case OZAYN_SALERT_ERR_INVALID_SEVERITY:        return "ERR_INVALID_SEVERITY";
    case OZAYN_SALERT_ERR_INVALID_PRIORITY:        return "ERR_INVALID_PRIORITY";
    case OZAYN_SALERT_ERR_INVALID_STATE:           return "ERR_INVALID_STATE";
    case OZAYN_SALERT_ERR_INVALID_SOURCE:          return "ERR_INVALID_SOURCE";
    case OZAYN_SALERT_ERR_NOT_FOUND:               return "ERR_NOT_FOUND";
    case OZAYN_SALERT_ERR_ALREADY_EXISTS:          return "ERR_ALREADY_EXISTS";
    case OZAYN_SALERT_ERR_STATE_TRANSITION_INVALID:return "ERR_STATE_TRANSITION_INVALID";
    case OZAYN_SALERT_ERR_POLICY_INVALID:          return "ERR_POLICY_INVALID";
    case OZAYN_SALERT_ERR_POLICY_REJECTED:         return "ERR_POLICY_REJECTED";
    case OZAYN_SALERT_ERR_THRESHOLD_INVALID:       return "ERR_THRESHOLD_INVALID";
    case OZAYN_SALERT_ERR_DEDUPLICATION_ERROR:     return "ERR_DEDUPLICATION_ERROR";
    case OZAYN_SALERT_ERR_SUPPRESSION_REJECTED:    return "ERR_SUPPRESSION_REJECTED";
    case OZAYN_SALERT_ERR_RATE_LIMITED:            return "ERR_RATE_LIMITED";
    case OZAYN_SALERT_ERR_LIMIT_REACHED:           return "ERR_LIMIT_REACHED";
    case OZAYN_SALERT_ERR_STORAGE_ERROR:           return "ERR_STORAGE_ERROR";
    case OZAYN_SALERT_ERR_AUDIT_FAILURE:           return "ERR_AUDIT_FAILURE";
    case OZAYN_SALERT_ERR_NOTIFICATION_ERROR:      return "ERR_NOTIFICATION_ERROR";
    case OZAYN_SALERT_ERR_NOTIFICATION_UNAVAILABLE:return "ERR_NOTIFICATION_UNAVAILABLE";
    case OZAYN_SALERT_ERR_NOTIFICATION_REJECTED:   return "ERR_NOTIFICATION_REJECTED";
    case OZAYN_SALERT_ERR_ESCALATION_REJECTED:     return "ERR_ESCALATION_REJECTED";
    case OZAYN_SALERT_ERR_CORRELATION_INVALID:     return "ERR_CORRELATION_INVALID";
    case OZAYN_SALERT_ERR_SOURCE_INVALID:          return "ERR_SOURCE_INVALID";
    case OZAYN_SALERT_ERR_RESOURCE_LIMIT:          return "ERR_RESOURCE_LIMIT";
    case OZAYN_SALERT_ERR_CONCURRENCY_CONFLICT:    return "ERR_CONCURRENCY_CONFLICT";
    case OZAYN_SALERT_ERR_UNAVAILABLE:             return "ERR_UNAVAILABLE";
    default:                                       return "UNKNOWN";
    }
}

const char *ozayn_salert_type_name(ozayn_salert_type_t t)
{
    switch (t) {
    case OZAYN_SALERT_TYPE_CONFIGURATION:          return "CONFIGURATION";
    case OZAYN_SALERT_TYPE_POLICY:                 return "POLICY";
    case OZAYN_SALERT_TYPE_AUTH_FAILURE:           return "AUTH_FAILURE";
    case OZAYN_SALERT_TYPE_AUTH_ATTACK:            return "AUTH_ATTACK";
    case OZAYN_SALERT_TYPE_AUTH_RATE_LIMIT:        return "AUTH_RATE_LIMIT";
    case OZAYN_SALERT_TYPE_MFA_FAILURE:            return "MFA_FAILURE";
    case OZAYN_SALERT_TYPE_MFA_ATTACK:             return "MFA_ATTACK";
    case OZAYN_SALERT_TYPE_SESSION_ANOMALY:        return "SESSION_ANOMALY";
    case OZAYN_SALERT_TYPE_SESSION_COMPROMISE:     return "SESSION_COMPROMISE";
    case OZAYN_SALERT_TYPE_AUTHZ_DENIAL:           return "AUTHZ_DENIAL";
    case OZAYN_SALERT_TYPE_PRIVILEGE_ESCALATION:   return "PRIVILEGE_ESCALATION";
    case OZAYN_SALERT_TYPE_ROLE_TAMPERING:         return "ROLE_TAMPERING";
    case OZAYN_SALERT_TYPE_PERMISSION_TAMPERING:   return "PERMISSION_TAMPERING";
    case OZAYN_SALERT_TYPE_KEY_AVAILABILITY:       return "KEY_AVAILABILITY";
    case OZAYN_SALERT_TYPE_KEY_COMPROMISE:         return "KEY_COMPROMISE";
    case OZAYN_SALERT_TYPE_KEY_STORAGE:            return "KEY_STORAGE";
    case OZAYN_SALERT_TYPE_VAULT_FAILURE:          return "VAULT_FAILURE";
    case OZAYN_SALERT_TYPE_VAULT_INTEGRITY:        return "VAULT_INTEGRITY";
    case OZAYN_SALERT_TYPE_DATA_INTEGRITY:         return "DATA_INTEGRITY";
    case OZAYN_SALERT_TYPE_AUDIT_FAILURE:          return "AUDIT_FAILURE";
    case OZAYN_SALERT_TYPE_AUDIT_INTEGRITY:        return "AUDIT_INTEGRITY";
    case OZAYN_SALERT_TYPE_BACKUP_FAILURE:         return "BACKUP_FAILURE";
    case OZAYN_SALERT_TYPE_BACKUP_INTEGRITY:       return "BACKUP_INTEGRITY";
    case OZAYN_SALERT_TYPE_RESTORE_FAILURE:        return "RESTORE_FAILURE";
    case OZAYN_SALERT_TYPE_DELETION_FAILURE:       return "DELETION_FAILURE";
    case OZAYN_SALERT_TYPE_INCIDENT:               return "INCIDENT";
    case OZAYN_SALERT_TYPE_HEALTH_DEGRADED:        return "HEALTH_DEGRADED";
    case OZAYN_SALERT_TYPE_HEALTH_CRITICAL:        return "HEALTH_CRITICAL";
    case OZAYN_SALERT_TYPE_DIAGNOSTIC_FAIL:        return "DIAGNOSTIC_FAIL";
    case OZAYN_SALERT_TYPE_COMPONENT_UNAVAILABLE:  return "COMPONENT_UNAVAILABLE";
    case OZAYN_SALERT_TYPE_LOCKDOWN:               return "LOCKDOWN";
    case OZAYN_SALERT_TYPE_RESOURCE_EXHAUSTION:    return "RESOURCE_EXHAUSTION";
    case OZAYN_SALERT_TYPE_UNKNOWN:                return "UNKNOWN";
    default:                                       return "UNKNOWN";
    }
}

const char *ozayn_salert_severity_name(ozayn_salert_severity_t s)
{
    switch (s) {
    case OZAYN_SALERT_SEV_INFO:      return "INFO";
    case OZAYN_SALERT_SEV_NOTICE:    return "NOTICE";
    case OZAYN_SALERT_SEV_WARNING:   return "WARNING";
    case OZAYN_SALERT_SEV_HIGH:      return "HIGH";
    case OZAYN_SALERT_SEV_CRITICAL:  return "CRITICAL";
    default:                         return "UNKNOWN";
    }
}

const char *ozayn_salert_priority_name(ozayn_salert_priority_t p)
{
    switch (p) {
    case OZAYN_SALERT_PRIO_LOW:      return "LOW";
    case OZAYN_SALERT_PRIO_NORMAL:   return "NORMAL";
    case OZAYN_SALERT_PRIO_HIGH:     return "HIGH";
    case OZAYN_SALERT_PRIO_URGENT:   return "URGENT";
    case OZAYN_SALERT_PRIO_IMMEDIATE:return "IMMEDIATE";
    default:                         return "UNKNOWN";
    }
}

const char *ozayn_salert_state_name(ozayn_salert_state_t s)
{
    switch (s) {
    case OZAYN_SALERT_STATE_DETECTED:      return "DETECTED";
    case OZAYN_SALERT_STATE_CREATED:       return "CREATED";
    case OZAYN_SALERT_STATE_ACTIVE:        return "ACTIVE";
    case OZAYN_SALERT_STATE_ACKNOWLEDGED:  return "ACKNOWLEDGED";
    case OZAYN_SALERT_STATE_RESOLVING:     return "RESOLVING";
    case OZAYN_SALERT_STATE_RESOLVED:      return "RESOLVED";
    case OZAYN_SALERT_STATE_SUPPRESSED:    return "SUPPRESSED";
    case OZAYN_SALERT_STATE_EXPIRED:       return "EXPIRED";
    case OZAYN_SALERT_STATE_FAILED:        return "FAILED";
    case OZAYN_SALERT_STATE_CANCELLED:     return "CANCELLED";
    default:                               return "UNKNOWN";
    }
}

const char *ozayn_salert_source_name(ozayn_salert_source_t s)
{
    switch (s) {
    case OZAYN_SALERT_SOURCE_SECURITY_EVENT:       return "SECURITY_EVENT";
    case OZAYN_SALERT_SOURCE_SECURITY_HEALTH:      return "SECURITY_HEALTH";
    case OZAYN_SALERT_SOURCE_SECURITY_DIAGNOSTICS: return "SECURITY_DIAGNOSTICS";
    case OZAYN_SALERT_SOURCE_INCIDENT_RESPONSE:    return "INCIDENT_RESPONSE";
    case OZAYN_SALERT_SOURCE_AUTHENTICATION:       return "AUTHENTICATION";
    case OZAYN_SALERT_SOURCE_MFA:                  return "MFA";
    case OZAYN_SALERT_SOURCE_SESSION:              return "SESSION";
    case OZAYN_SALERT_SOURCE_AUTHORIZATION:        return "AUTHORIZATION";
    case OZAYN_SALERT_SOURCE_RBAC:                 return "RBAC";
    case OZAYN_SALERT_SOURCE_PERMISSIONS:          return "PERMISSIONS";
    case OZAYN_SALERT_SOURCE_KEY_MANAGEMENT:       return "KEY_MANAGEMENT";
    case OZAYN_SALERT_SOURCE_KEY_STORAGE:          return "KEY_STORAGE";
    case OZAYN_SALERT_SOURCE_VAULT:                return "VAULT";
    case OZAYN_SALERT_SOURCE_BACKUP:               return "BACKUP";
    case OZAYN_SALERT_SOURCE_RECOVERY:             return "RECOVERY";
    case OZAYN_SALERT_SOURCE_DELETION:             return "DELETION";
    case OZAYN_SALERT_SOURCE_CONFIGURATION:        return "CONFIGURATION";
    case OZAYN_SALERT_SOURCE_SYSTEM:               return "SYSTEM";
    default:                                       return "UNKNOWN";
    }
}

const char *ozayn_salert_notify_channel_name(ozayn_salert_notify_channel_t c)
{
    switch (c) {
    case OZAYN_SALERT_NOTIFY_LOCAL:        return "LOCAL";
    case OZAYN_SALERT_NOTIFY_DESKTOP:      return "DESKTOP";
    case OZAYN_SALERT_NOTIFY_EMAIL:        return "EMAIL";
    case OZAYN_SALERT_NOTIFY_SMS:          return "SMS";
    case OZAYN_SALERT_NOTIFY_PUSH:         return "PUSH";
    case OZAYN_SALERT_NOTIFY_CONTROL_ROOM: return "CONTROL_ROOM";
    case OZAYN_SALERT_NOTIFY_EXTERNAL:     return "EXTERNAL";
    default:                               return "UNKNOWN";
    }
}

const char *ozayn_salert_notify_state_name(ozayn_salert_notify_state_t s)
{
    switch (s) {
    case OZAYN_SALERT_NOTIFY_STATE_NONE:         return "NONE";
    case OZAYN_SALERT_NOTIFY_STATE_PENDING:      return "PENDING";
    case OZAYN_SALERT_NOTIFY_STATE_SENT:         return "SENT";
    case OZAYN_SALERT_NOTIFY_STATE_FAILED:       return "FAILED";
    case OZAYN_SALERT_NOTIFY_STATE_UNAVAILABLE:  return "UNAVAILABLE";
    case OZAYN_SALERT_NOTIFY_STATE_RATE_LIMITED: return "RATE_LIMITED";
    default:                                      return "UNKNOWN";
    }
}

/* ============================================================
 * SECTION 30 — SEVERITY / PRIORITY HELPERS
 * ============================================================ */

ozayn_salert_severity_t ozayn_salert_worse_severity(
    ozayn_salert_severity_t a, ozayn_salert_severity_t b)
{
    return (a > b) ? a : b;
}

ozayn_salert_priority_t ozayn_salert_higher_priority(
    ozayn_salert_priority_t a, ozayn_salert_priority_t b)
{
    return (a > b) ? a : b;
}

int ozayn_salert_severity_meets_threshold(
    ozayn_salert_severity_t severity, ozayn_salert_severity_t threshold)
{
    return (severity >= threshold);
}

/* ============================================================
 * SECTION 31 — SAFE CONTENT GENERATION
 * ============================================================ */

ozayn_salert_err_t ozayn_salert_generate_safe_title(
    const ozayn_salert_alert_t *alert,
    char *out_title, int max_len)
{
    if (!alert || !out_title || max_len <= 0)
        return OZAYN_SALERT_ERR_NULL;
    snprintf(out_title, (size_t)max_len, "OZAYN Security Alert [%s] %s",
             ozayn_salert_severity_name(alert->severity),
             ozayn_salert_type_name(alert->alert_type));
    return OZAYN_SALERT_OK;
}

ozayn_salert_err_t ozayn_salert_generate_safe_body(
    const ozayn_salert_alert_t *alert,
    char *out_body, int max_len)
{
    if (!alert || !out_body || max_len <= 0)
        return OZAYN_SALERT_ERR_NULL;
    snprintf(out_body, (size_t)max_len,
             "Severity: %s\nPriority: %s\nComponent: %s\n"
             "Condition: %s\nReference: %s",
             ozayn_salert_severity_name(alert->severity),
             ozayn_salert_priority_name(alert->priority),
             alert->source_component[0] ? alert->source_component : "N/A",
             alert->safe_summary[0] ? alert->safe_summary : "No detail",
             alert->alert_id);
    return OZAYN_SALERT_OK;
}

/* ============================================================
 * SECTION 15 — LIFECYCLE
 * ============================================================ */

ozayn_salert_err_t ozayn_salert_service_init(
    ozayn_salert_service_t *svc,
    const ozayn_salert_service_config_t *cfg)
{
    if (!svc) return OZAYN_SALERT_ERR_NULL;
    if (svc->initialized) return OZAYN_SALERT_ERR_ALREADY_INITIALIZED;

    memset(svc, 0, sizeof(*svc));

    if (cfg) {
        svc->config_service  = cfg->config_service;
        svc->health_service  = cfg->health_service;
        svc->diag_service    = cfg->diag_service;
        svc->incident_service = cfg->incident_service;
        svc->audit           = cfg->audit;
        if (cfg->max_alerts > 0 && cfg->max_alerts <= OZAYN_SALERT_MAX_ALERTS)
            svc->alert_head = 0; /* will use default */
        if (cfg->max_notify_queue > 0 &&
            cfg->max_notify_queue <= OZAYN_SALERT_MAX_NOTIFY_QUEUE)
            svc->notify_queue_head = 0;
    }

    svc->policy = ozayn_salert_default_policy();
    svc->max_concurrent_ops = 1;
    svc->initialized = 1;
    return OZAYN_SALERT_OK;
}

void ozayn_salert_service_shutdown(ozayn_salert_service_t *svc)
{
    if (!svc) return;
    svc->initialized = 0;
}

int ozayn_salert_service_is_initialized(const ozayn_salert_service_t *svc)
{
    return svc ? svc->initialized : 0;
}

/* ============================================================
 * SECTION 27 — POLICY
 * ============================================================ */

ozayn_salert_policy_t ozayn_salert_default_policy(void)
{
    ozayn_salert_policy_t p;
    memset(&p, 0, sizeof(p));
    p.enabled                     = 1;
    p.max_active_alerts           = 256;
    p.max_history                 = 1024;
    p.dedup_window_seconds        = 300;
    p.max_notify_per_window       = 10;
    p.notify_window_seconds       = 60;
    p.max_notify_retries          = 3;
    p.alert_retention_seconds     = 86400;
    p.auto_suppress_duplicates    = 1;
    p.require_ack_for_critical    = 1;
    p.escalation_threshold        = 3;
    p.escalation_window_seconds   = 600;
    p.max_escalation_level        = 4;
    return p;
}

ozayn_salert_err_t ozayn_salert_set_policy(
    ozayn_salert_service_t *svc,
    const ozayn_salert_policy_t *policy)
{
    if (!svc || !policy) return OZAYN_SALERT_ERR_NULL;
    if (!svc->initialized) return OZAYN_SALERT_ERR_NOT_INITIALIZED;
    if (policy->max_active_alerts <= 0 ||
        policy->max_active_alerts > OZAYN_SALERT_MAX_ALERTS)
        return OZAYN_SALERT_ERR_POLICY_INVALID;
    if (policy->dedup_window_seconds < 0)
        return OZAYN_SALERT_ERR_POLICY_INVALID;
    if (policy->max_notify_per_window < 0)
        return OZAYN_SALERT_ERR_POLICY_INVALID;
    if (policy->max_escalation_level < 0 ||
        policy->max_escalation_level > 10)
        return OZAYN_SALERT_ERR_POLICY_INVALID;
    svc->policy = *policy;
    return OZAYN_SALERT_OK;
}

const ozayn_salert_policy_t *ozayn_salert_get_policy(
    const ozayn_salert_service_t *svc)
{
    if (!svc || !svc->initialized) return NULL;
    return &svc->policy;
}

/* ============================================================
 * INTERNAL — RING BUFFER HELPERS
 * ============================================================ */

static ozayn_salert_alert_t *_alloc_alert(ozayn_salert_service_t *svc)
{
    if (svc->alert_count >= OZAYN_SALERT_MAX_ALERTS) {
        /* Overwrite oldest */
        svc->alert_head = (svc->alert_head + 1) % OZAYN_SALERT_MAX_ALERTS;
        svc->alert_count--;
    }
    int slot = (svc->alert_head + svc->alert_count) % OZAYN_SALERT_MAX_ALERTS;
    memset(&svc->alerts[slot], 0, sizeof(ozayn_salert_alert_t));
    svc->alert_count++;
    return &svc->alerts[slot];
}

static ozayn_salert_alert_t *_find_alert(ozayn_salert_service_t *svc,
                                          const char *alert_id)
{
    if (!alert_id || !alert_id[0]) return NULL;
    for (int i = 0; i < svc->alert_count; i++) {
        int slot = (svc->alert_head + i) % OZAYN_SALERT_MAX_ALERTS;
        if (strcmp(svc->alerts[slot].alert_id, alert_id) == 0)
            return &svc->alerts[slot];
    }
    return NULL;
}

/* ============================================================
 * INTERNAL — AUDIT RECORDING
 * ============================================================ */

static void _audit_alert_event(ozayn_salert_service_t *svc,
                                const char *event_type,
                                const ozayn_salert_alert_t *alert)
{
    if (!svc->audit || !svc->audit->initialized) return;
    ozayn_audit_event_t ev;
    ozayn_audit_event_init(&ev);
    ozayn_audit_event_set_type(&ev, OZAYN_AUDIT_CONFIG_CHANGED);
    ozayn_audit_event_set_outcome(&ev, OZAYN_AUDIT_OUTCOME_SUCCESS);
    ozayn_audit_event_set_severity(&ev, OZAYN_AUDIT_SEV_NOTICE);
    ozayn_audit_event_set_source(&ev, "SEC_ALERT");
    char detail[256];
    snprintf(detail, sizeof(detail), "%s: %s [%s]",
             event_type, alert ? alert->alert_id : "N/A",
             alert ? ozayn_salert_type_name(alert->alert_type) : "N/A");
    ozayn_audit_event_set_detail(&ev, detail);
    if (alert && alert->correlation_id[0])
        ozayn_audit_event_set_correlation_id(&ev, alert->correlation_id);
    ozayn_audit_record(svc->audit, &ev);
}

/* ============================================================
 * SECTION 16 — ALERT CREATION
 * ============================================================ */

ozayn_salert_err_t ozayn_salert_create(
    ozayn_salert_service_t *svc,
    ozayn_salert_type_t type,
    ozayn_salert_severity_t severity,
    ozayn_salert_priority_t priority,
    ozayn_salert_source_t source,
    const char *source_component,
    const char *correlation_id,
    const char *safe_summary,
    const char *safe_detail,
    ozayn_salert_alert_t **out_alert)
{
    if (!svc) return OZAYN_SALERT_ERR_NULL;
    if (!svc->initialized) return OZAYN_SALERT_ERR_NOT_INITIALIZED;
    if (!out_alert) return OZAYN_SALERT_ERR_NULL;
    if (!svc->policy.enabled) return OZAYN_SALERT_ERR_POLICY_REJECTED;
    if (type < 0 || type > OZAYN_SALERT_TYPE_UNKNOWN)
        return OZAYN_SALERT_ERR_INVALID_TYPE;
    if (severity < OZAYN_SALERT_SEV_INFO || severity > OZAYN_SALERT_SEV_CRITICAL)
        return OZAYN_SALERT_ERR_INVALID_SEVERITY;
    if (priority < OZAYN_SALERT_PRIO_LOW || priority > OZAYN_SALERT_PRIO_IMMEDIATE)
        return OZAYN_SALERT_ERR_INVALID_PRIORITY;
    if (source < 0 || source > OZAYN_SALERT_SOURCE_SYSTEM)
        return OZAYN_SALERT_ERR_INVALID_SOURCE;

    /* Check active alert limit */
    if (svc->active_count >= svc->policy.max_active_alerts)
        return OZAYN_SALERT_ERR_LIMIT_REACHED;

    /* Check rate limit */
    if (!ozayn_salert_check_rate_limit(svc, type))
        return OZAYN_SALERT_ERR_RATE_LIMITED;

    /* Check deduplication */
    char dedup_key[OZAYN_SALERT_MAX_DEDUP_KEY_LEN];
    if (correlation_id && correlation_id[0]) {
        snprintf(dedup_key, sizeof(dedup_key), "%d:%s:%s",
                 type, source_component ? source_component : "", correlation_id);
    } else {
        snprintf(dedup_key, sizeof(dedup_key), "%d:%s:%s",
                 type, source_component ? source_component : "",
                 safe_summary ? safe_summary : "");
    }

    int is_dup = 0;
    uint32_t existing_hash = 0;
    ozayn_salert_check_dedup(svc, dedup_key, &is_dup, &existing_hash);

    if (is_dup && svc->policy.auto_suppress_duplicates) {
        /* Update existing alert dedup count */
        for (int i = 0; i < svc->dedup_count; i++) {
            if (strcmp(svc->dedup_state[i].dedup_key, dedup_key) == 0) {
                svc->dedup_state[i].count++;
                svc->dedup_state[i].last_time = time(NULL);
                break;
            }
        }
        svc->total_alerts_deduplicated++;

        /* Find the existing alert and update it */
        for (int i = 0; i < svc->alert_count; i++) {
            int slot = (svc->alert_head + i) % OZAYN_SALERT_MAX_ALERTS;
            uint32_t h = _hash_str(svc->alerts[slot].alert_id);
            if (h == existing_hash) {
                svc->alerts[slot].dedup_count++;
                svc->alerts[slot].dedup_last_time = time(NULL);
                svc->alerts[slot].updated_time = time(NULL);
                /* Escalate severity if dedup count is high */
                if (svc->alerts[slot].dedup_count >=
                    svc->policy.escalation_threshold) {
                    if (svc->alerts[slot].severity < OZAYN_SALERT_SEV_HIGH)
                        svc->alerts[slot].severity = OZAYN_SALERT_SEV_HIGH;
                }
                _audit_alert_event(svc, "ALERT_DEDUPLICATED", &svc->alerts[slot]);
                *out_alert = &svc->alerts[slot];
                return OZAYN_SALERT_OK;
            }
        }
    }

    /* Create new alert */
    ozayn_salert_alert_t *alert = _alloc_alert(svc);
    alert->alert_version = 1;
    alert->alert_type = type;
    alert->severity = severity;
    alert->priority = priority;
    alert->state = OZAYN_SALERT_STATE_CREATED;
    alert->source = source;
    alert->created_time = time(NULL);
    alert->updated_time = alert->created_time;

    _generate_id(alert->alert_id, OZAYN_SALERT_MAX_ID_LEN, svc->alert_sequence++);
    if (source_component)
        strncpy(alert->source_component, source_component,
                OZAYN_SALERT_MAX_SOURCE_LEN - 1);
    if (correlation_id)
        strncpy(alert->correlation_id, correlation_id,
                OZAYN_SALERT_MAX_CORR_ID_LEN - 1);
    if (safe_summary)
        strncpy(alert->safe_summary, safe_summary,
                OZAYN_SALERT_MAX_SUMMARY_LEN - 1);
    if (safe_detail)
        strncpy(alert->safe_detail, safe_detail,
                OZAYN_SALERT_MAX_DETAIL_LEN - 1);

    strncpy(alert->dedup_key, dedup_key, OZAYN_SALERT_MAX_DEDUP_KEY_LEN - 1);
    alert->dedup_first_time = alert->created_time;
    alert->dedup_last_time = alert->created_time;
    alert->dedup_count = 1;

    /* Move to ACTIVE */
    alert->state = OZAYN_SALERT_STATE_ACTIVE;
    svc->active_count++;
    svc->total_alerts_created++;

    /* Register dedup state */
    ozayn_salert_register_dedup(svc, dedup_key, _hash_str(alert->alert_id));

    /* Record threshold event */
    ozayn_salert_record_threshold_event(svc, type);

    /* Audit */
    _audit_alert_event(svc, "ALERT_CREATED", alert);

    *out_alert = alert;
    return OZAYN_SALERT_OK;
}

/* ============================================================
 * SECTION 17 — ALERT QUERY
 * ============================================================ */

ozayn_salert_err_t ozayn_salert_get(
    const ozayn_salert_service_t *svc,
    const char *alert_id,
    ozayn_salert_alert_t **out_alert)
{
    if (!svc || !out_alert) return OZAYN_SALERT_ERR_NULL;
    if (!svc->initialized) return OZAYN_SALERT_ERR_NOT_INITIALIZED;
    if (!alert_id) return OZAYN_SALERT_ERR_INVALID_ID;

    for (int i = 0; i < svc->alert_count; i++) {
        int slot = (svc->alert_head + i) % OZAYN_SALERT_MAX_ALERTS;
        if (strcmp(svc->alerts[slot].alert_id, alert_id) == 0) {
            *out_alert = (ozayn_salert_alert_t *)&svc->alerts[slot];
            return OZAYN_SALERT_OK;
        }
    }
    return OZAYN_SALERT_ERR_NOT_FOUND;
}

int ozayn_salert_list(
    const ozayn_salert_service_t *svc,
    int filter_type,
    int filter_state,
    ozayn_salert_alert_t **out_alerts,
    int max_count)
{
    if (!svc || !out_alerts || max_count <= 0) return 0;
    if (!svc->initialized) return 0;

    int count = 0;
    for (int i = 0; i < svc->alert_count && count < max_count; i++) {
        int slot = (svc->alert_head + i) % OZAYN_SALERT_MAX_ALERTS;
        const ozayn_salert_alert_t *a = &svc->alerts[slot];
        int type_match = (filter_type < 0 ||
                          a->alert_type == filter_type);
        int state_match = (filter_state < 0 ||
                           a->state == filter_state);
        if (type_match && state_match) {
            out_alerts[count] = (ozayn_salert_alert_t *)a;
            count++;
        }
    }
    return count;
}

int ozayn_salert_get_active_count(const ozayn_salert_service_t *svc)
{
    return svc ? svc->active_count : 0;
}

int ozayn_salert_get_total_count(const ozayn_salert_service_t *svc)
{
    return svc ? svc->alert_count : 0;
}

/* ============================================================
 * SECTION 18 — ALERT LIFECYCLE
 * ============================================================ */

static ozayn_salert_err_t _transition(ozayn_salert_service_t *svc,
                                       ozayn_salert_alert_t *alert,
                                       ozayn_salert_state_t new_state)
{
    if (!ozayn_salert_state_transition_valid(alert->state, new_state))
        return OZAYN_SALERT_ERR_STATE_TRANSITION_INVALID;

    ozayn_salert_state_t old_state = alert->state;
    alert->state = new_state;
    alert->updated_time = time(NULL);
    alert->alert_version++;

    if (new_state == OZAYN_SALERT_STATE_ACTIVE &&
        old_state != OZAYN_SALERT_STATE_ACTIVE)
        svc->active_count++;
    else if (old_state == OZAYN_SALERT_STATE_ACTIVE &&
             new_state != OZAYN_SALERT_STATE_ACTIVE)
        svc->active_count--;

    return OZAYN_SALERT_OK;
}

ozayn_salert_err_t ozayn_salert_acknowledge(
    ozayn_salert_service_t *svc, const char *alert_id)
{
    if (!svc) return OZAYN_SALERT_ERR_NULL;
    if (!svc->initialized) return OZAYN_SALERT_ERR_NOT_INITIALIZED;
    ozayn_salert_alert_t *alert = _find_alert(svc, alert_id);
    if (!alert) return OZAYN_SALERT_ERR_NOT_FOUND;

    ozayn_salert_err_t r = _transition(svc, alert,
                                        OZAYN_SALERT_STATE_ACKNOWLEDGED);
    if (r == OZAYN_SALERT_OK) {
        alert->acknowledged_time = time(NULL);
        _audit_alert_event(svc, "ALERT_ACKNOWLEDGED", alert);
    }
    return r;
}

ozayn_salert_err_t ozayn_salert_resolve(
    ozayn_salert_service_t *svc, const char *alert_id)
{
    if (!svc) return OZAYN_SALERT_ERR_NULL;
    if (!svc->initialized) return OZAYN_SALERT_ERR_NOT_INITIALIZED;
    ozayn_salert_alert_t *alert = _find_alert(svc, alert_id);
    if (!alert) return OZAYN_SALERT_ERR_NOT_FOUND;

    ozayn_salert_state_t target = OZAYN_SALERT_STATE_RESOLVED;
    if (alert->state == OZAYN_SALERT_STATE_ACTIVE ||
        alert->state == OZAYN_SALERT_STATE_ACKNOWLEDGED) {
        /* Direct resolve allowed from ACTIVE or ACKNOWLEDGED */
    } else if (alert->state == OZAYN_SALERT_STATE_RESOLVING) {
        target = OZAYN_SALERT_STATE_RESOLVED;
    } else {
        return OZAYN_SALERT_ERR_STATE_TRANSITION_INVALID;
    }

    ozayn_salert_err_t r = _transition(svc, alert, target);
    if (r == OZAYN_SALERT_OK) {
        alert->resolved_time = time(NULL);
        svc->total_alerts_resolved++;
        _audit_alert_event(svc, "ALERT_RESOLVED", alert);
    }
    return r;
}

ozayn_salert_err_t ozayn_salert_suppress(
    ozayn_salert_service_t *svc, const char *alert_id, int reason)
{
    if (!svc) return OZAYN_SALERT_ERR_NULL;
    if (!svc->initialized) return OZAYN_SALERT_ERR_NOT_INITIALIZED;
    if (reason < 0) return OZAYN_SALERT_ERR_INVALID_REQUEST;
    ozayn_salert_alert_t *alert = _find_alert(svc, alert_id);
    if (!alert) return OZAYN_SALERT_ERR_NOT_FOUND;

    /* Cannot suppress critical alerts unless explicit */
    if (alert->severity == OZAYN_SALERT_SEV_CRITICAL &&
        reason == 0)
        return OZAYN_SALERT_ERR_SUPPRESSION_REJECTED;

    ozayn_salert_err_t r = _transition(svc, alert,
                                        OZAYN_SALERT_STATE_SUPPRESSED);
    if (r == OZAYN_SALERT_OK) {
        alert->suppressed = 1;
        alert->suppression_reason = reason;
        svc->total_alerts_suppressed++;
        _audit_alert_event(svc, "ALERT_SUPPRESSED", alert);
    }
    return r;
}

ozayn_salert_err_t ozayn_salert_cancel(
    ozayn_salert_service_t *svc, const char *alert_id)
{
    if (!svc) return OZAYN_SALERT_ERR_NULL;
    if (!svc->initialized) return OZAYN_SALERT_ERR_NOT_INITIALIZED;
    ozayn_salert_alert_t *alert = _find_alert(svc, alert_id);
    if (!alert) return OZAYN_SALERT_ERR_NOT_FOUND;

    ozayn_salert_err_t r = _transition(svc, alert,
                                        OZAYN_SALERT_STATE_CANCELLED);
    if (r == OZAYN_SALERT_OK) {
        _audit_alert_event(svc, "ALERT_CANCELLED", alert);
    }
    return r;
}

/* ============================================================
 * SECTION 19 — ESCALATION
 * ============================================================ */

ozayn_salert_err_t ozayn_salert_escalate(
    ozayn_salert_service_t *svc, const char *alert_id)
{
    if (!svc) return OZAYN_SALERT_ERR_NULL;
    if (!svc->initialized) return OZAYN_SALERT_ERR_NOT_INITIALIZED;
    ozayn_salert_alert_t *alert = _find_alert(svc, alert_id);
    if (!alert) return OZAYN_SALERT_ERR_NOT_FOUND;

    if (alert->escalation_level >= svc->policy.max_escalation_level)
        return OZAYN_SALERT_ERR_ESCALATION_REJECTED;
    if (alert->state != OZAYN_SALERT_STATE_ACTIVE &&
        alert->state != OZAYN_SALERT_STATE_ACKNOWLEDGED)
        return OZAYN_SALERT_ERR_STATE_TRANSITION_INVALID;

    alert->escalation_level++;
    alert->escalation_count++;
    alert->updated_time = time(NULL);
    alert->alert_version++;

    /* Increase severity on escalation */
    if (alert->severity < OZAYN_SALERT_SEV_CRITICAL)
        alert->severity = (ozayn_salert_severity_t)(alert->severity + 1);

    /* Increase priority on escalation */
    if (alert->priority < OZAYN_SALERT_PRIO_IMMEDIATE)
        alert->priority = (ozayn_salert_priority_t)(alert->priority + 1);

    svc->total_escalations++;
    _audit_alert_event(svc, "ALERT_ESCALATED", alert);
    return OZAYN_SALERT_OK;
}

int ozayn_salert_get_escalation_level(
    const ozayn_salert_service_t *svc, const char *alert_id)
{
    if (!svc || !alert_id) return -1;
    for (int i = 0; i < svc->alert_count; i++) {
        int slot = (svc->alert_head + i) % OZAYN_SALERT_MAX_ALERTS;
        if (strcmp(svc->alerts[slot].alert_id, alert_id) == 0)
            return svc->alerts[slot].escalation_level;
    }
    return -1;
}

/* ============================================================
 * SECTION 20 — DEDUPLICATION
 * ============================================================ */

ozayn_salert_err_t ozayn_salert_check_dedup(
    ozayn_salert_service_t *svc,
    const char *dedup_key,
    int *is_duplicate,
    uint32_t *existing_alert_hash)
{
    if (!svc || !dedup_key || !is_duplicate)
        return OZAYN_SALERT_ERR_NULL;
    if (!svc->initialized) return OZAYN_SALERT_ERR_NOT_INITIALIZED;

    *is_duplicate = 0;
    if (existing_alert_hash) *existing_alert_hash = 0;

    time_t now = time(NULL);
    for (int i = 0; i < svc->dedup_count; i++) {
        if (strcmp(svc->dedup_state[i].dedup_key, dedup_key) == 0) {
            if ((now - svc->dedup_state[i].last_time) <
                svc->policy.dedup_window_seconds) {
                *is_duplicate = 1;
                if (existing_alert_hash)
                    *existing_alert_hash = svc->dedup_state[i].alert_id_hash;
                return OZAYN_SALERT_OK;
            }
            break;
        }
    }
    return OZAYN_SALERT_OK;
}

ozayn_salert_err_t ozayn_salert_register_dedup(
    ozayn_salert_service_t *svc,
    const char *dedup_key,
    uint32_t alert_id_hash)
{
    if (!svc || !dedup_key) return OZAYN_SALERT_ERR_NULL;
    if (!svc->initialized) return OZAYN_SALERT_ERR_NOT_INITIALIZED;

    if (svc->dedup_count >= OZAYN_SALERT_MAX_DEDUP_STATE) {
        /* Evict oldest */
        int oldest = 0;
        time_t oldest_time = svc->dedup_state[0].last_time;
        for (int i = 1; i < svc->dedup_count; i++) {
            if (svc->dedup_state[i].last_time < oldest_time) {
                oldest_time = svc->dedup_state[i].last_time;
                oldest = i;
            }
        }
        memmove(&svc->dedup_state[oldest], &svc->dedup_state[oldest + 1],
                (size_t)(svc->dedup_count - oldest - 1) *
                sizeof(svc->dedup_state[0]));
        svc->dedup_count--;
    }

    strncpy(svc->dedup_state[svc->dedup_count].dedup_key, dedup_key,
            OZAYN_SALERT_MAX_DEDUP_KEY_LEN - 1);
    svc->dedup_state[svc->dedup_count].alert_id_hash = alert_id_hash;
    svc->dedup_state[svc->dedup_count].first_time = time(NULL);
    svc->dedup_state[svc->dedup_count].last_time = time(NULL);
    svc->dedup_state[svc->dedup_count].count = 1;
    svc->dedup_count++;
    return OZAYN_SALERT_OK;
}

int ozayn_salert_is_in_dedup_window(
    const ozayn_salert_service_t *svc, const char *dedup_key)
{
    if (!svc || !dedup_key) return 0;
    time_t now = time(NULL);
    for (int i = 0; i < svc->dedup_count; i++) {
        if (strcmp(svc->dedup_state[i].dedup_key, dedup_key) == 0) {
            return ((now - svc->dedup_state[i].last_time) <
                    svc->policy.dedup_window_seconds);
        }
    }
    return 0;
}

/* ============================================================
 * SECTION 21 — THRESHOLD MANAGEMENT
 * ============================================================ */

ozayn_salert_err_t ozayn_salert_add_threshold(
    ozayn_salert_service_t *svc,
    const ozayn_salert_threshold_t *threshold)
{
    if (!svc || !threshold) return OZAYN_SALERT_ERR_NULL;
    if (!svc->initialized) return OZAYN_SALERT_ERR_NOT_INITIALIZED;
    if (svc->threshold_count >= OZAYN_SALERT_MAX_THRESHOLDS)
        return OZAYN_SALERT_ERR_LIMIT_REACHED;
    if (threshold->threshold_count <= 0 || threshold->window_seconds <= 0)
        return OZAYN_SALERT_ERR_THRESHOLD_INVALID;
    if (threshold->alert_type < 0 ||
        threshold->alert_type > OZAYN_SALERT_TYPE_UNKNOWN)
        return OZAYN_SALERT_ERR_INVALID_TYPE;

    svc->thresholds[svc->threshold_count] = *threshold;
    svc->threshold_state[svc->threshold_count].alert_type =
        threshold->alert_type;
    memset(svc->threshold_state[svc->threshold_count].counts, 0,
           sizeof(svc->threshold_state[0].counts));
    svc->threshold_state[svc->threshold_count].window_start = time(NULL);
    svc->threshold_state[svc->threshold_count].window_index = 0;
    svc->threshold_count++;
    return OZAYN_SALERT_OK;
}

ozayn_salert_err_t ozayn_salert_check_threshold(
    ozayn_salert_service_t *svc,
    ozayn_salert_type_t alert_type,
    int *threshold_exceeded,
    ozayn_salert_severity_t *resulting_severity)
{
    if (!svc || !threshold_exceeded)
        return OZAYN_SALERT_ERR_NULL;
    if (!svc->initialized) return OZAYN_SALERT_ERR_NOT_INITIALIZED;

    *threshold_exceeded = 0;
    if (resulting_severity) *resulting_severity = OZAYN_SALERT_SEV_WARNING;

    time_t now = time(NULL);
    for (int i = 0; i < svc->threshold_count; i++) {
        if (svc->thresholds[i].alert_type == alert_type &&
            svc->thresholds[i].enabled) {
            /* Check if window expired, reset if so */
            if ((now - svc->threshold_state[i].window_start) >=
                svc->thresholds[i].window_seconds) {
                memset(svc->threshold_state[i].counts, 0,
                       sizeof(svc->threshold_state[0].counts));
                svc->threshold_state[i].window_start = now;
                svc->threshold_state[i].window_index = 0;
            }

            /* Sum counts in current window */
            int total = 0;
            for (int j = 0; j < 16; j++)
                total += svc->threshold_state[i].counts[j];

            if (total >= svc->thresholds[i].threshold_count) {
                *threshold_exceeded = 1;
                if (resulting_severity)
                    *resulting_severity = svc->thresholds[i].resulting_severity;
                return OZAYN_SALERT_OK;
            }
        }
    }
    return OZAYN_SALERT_OK;
}

ozayn_salert_err_t ozayn_salert_record_threshold_event(
    ozayn_salert_service_t *svc,
    ozayn_salert_type_t alert_type)
{
    if (!svc) return OZAYN_SALERT_ERR_NULL;
    if (!svc->initialized) return OZAYN_SALERT_ERR_NOT_INITIALIZED;

    time_t now = time(NULL);
    for (int i = 0; i < svc->threshold_count; i++) {
        if (svc->threshold_state[i].alert_type == alert_type) {
            /* Reset window if expired */
            if ((now - svc->threshold_state[i].window_start) >=
                svc->thresholds[i].window_seconds) {
                memset(svc->threshold_state[i].counts, 0,
                       sizeof(svc->threshold_state[0].counts));
                svc->threshold_state[i].window_start = now;
                svc->threshold_state[i].window_index = 0;
            }
            int idx = svc->threshold_state[i].window_index % 16;
            svc->threshold_state[i].counts[idx]++;
            return OZAYN_SALERT_OK;
        }
    }
    return OZAYN_SALERT_OK;
}

/* ============================================================
 * SECTION 22 — NOTIFICATION
 * ============================================================ */

ozayn_salert_err_t ozayn_salert_register_provider(
    ozayn_salert_service_t *svc,
    const ozayn_salert_notify_provider_vtable_t *vtable,
    const void *context,
    ozayn_salert_notify_channel_t channel)
{
    if (!svc) return OZAYN_SALERT_ERR_NULL;
    if (!svc->initialized) return OZAYN_SALERT_ERR_NOT_INITIALIZED;
    if (!vtable || !vtable->notify) return OZAYN_SALERT_ERR_NULL;
    if (svc->provider_count >= 8) return OZAYN_SALERT_ERR_LIMIT_REACHED;

    svc->providers[svc->provider_count].vtable = vtable;
    svc->providers[svc->provider_count].context = context;
    svc->providers[svc->provider_count].registered = 1;
    svc->providers[svc->provider_count].channel = channel;
    svc->providers[svc->provider_count].enabled = 1;
    svc->providers[svc->provider_count].available = 1;
    svc->providers[svc->provider_count].fail_count = 0;
    svc->provider_count++;
    return OZAYN_SALERT_OK;
}

ozayn_salert_err_t ozayn_salert_queue_notification(
    ozayn_salert_service_t *svc,
    const char *alert_id,
    ozayn_salert_notify_channel_t channel)
{
    if (!svc) return OZAYN_SALERT_ERR_NULL;
    if (!svc->initialized) return OZAYN_SALERT_ERR_NOT_INITIALIZED;
    if (!alert_id) return OZAYN_SALERT_ERR_INVALID_ID;

    if (svc->notify_queue_count >= OZAYN_SALERT_MAX_NOTIFY_QUEUE)
        return OZAYN_SALERT_ERR_LIMIT_REACHED;

    /* Check rate limit for this channel */
    int rate_ok = 0;
    for (int i = 0; i < svc->notify_queue_count; i++) {
        int qslot = (svc->notify_queue_head + i) %
                     OZAYN_SALERT_MAX_NOTIFY_QUEUE;
        if (svc->notify_queue[qslot].channel == channel) {
            if ((time(NULL) - svc->notify_queue[qslot].queued_time) <
                svc->policy.notify_window_seconds) {
                rate_ok++;
            }
        }
    }
    if (rate_ok >= svc->policy.max_notify_per_window) {
        svc->total_rate_limited++;
        return OZAYN_SALERT_ERR_RATE_LIMITED;
    }

    int qslot = (svc->notify_queue_head + svc->notify_queue_count) %
                 OZAYN_SALERT_MAX_NOTIFY_QUEUE;
    svc->notify_queue[qslot].alert_id_hash = _hash_str(alert_id);
    svc->notify_queue[qslot].channel = channel;
    svc->notify_queue[qslot].queued_time = time(NULL);
    svc->notify_queue[qslot].retry_count = 0;
    svc->notify_queue_count++;

    /* Update alert notify state */
    ozayn_salert_alert_t *alert = _find_alert(svc, alert_id);
    if (alert) {
        alert->notify_state = OZAYN_SALERT_NOTIFY_STATE_PENDING;
        alert->notify_count++;
        alert->notify_channel = channel;
    }

    return OZAYN_SALERT_OK;
}

ozayn_salert_err_t ozayn_salert_process_notifications(
    ozayn_salert_service_t *svc)
{
    if (!svc) return OZAYN_SALERT_ERR_NULL;
    if (!svc->initialized) return OZAYN_SALERT_ERR_NOT_INITIALIZED;

    while (svc->notify_queue_count > 0) {
        int qslot = svc->notify_queue_head;
        uint32_t alert_hash = svc->notify_queue[qslot].alert_id_hash;
        ozayn_salert_notify_channel_t channel = svc->notify_queue[qslot].channel;
        int retry = svc->notify_queue[qslot].retry_count;

        /* Find matching provider */
        int sent = 0;
        for (int p = 0; p < svc->provider_count; p++) {
            if (svc->providers[p].registered &&
                svc->providers[p].enabled &&
                svc->providers[p].available &&
                svc->providers[p].channel == channel &&
                svc->providers[p].vtable &&
                svc->providers[p].vtable->notify) {

                /* Find the alert */
                ozayn_salert_alert_t *alert = NULL;
                for (int i = 0; i < svc->alert_count; i++) {
                    int aslot = (svc->alert_head + i) %
                                 OZAYN_SALERT_MAX_ALERTS;
                    uint32_t h = _hash_str(svc->alerts[aslot].alert_id);
                    if (h == alert_hash) {
                        alert = &svc->alerts[aslot];
                        break;
                    }
                }

                if (alert) {
                    char title[256], body[512];
                    ozayn_salert_generate_safe_title(alert, title, sizeof(title));
                    ozayn_salert_generate_safe_body(alert, body, sizeof(body));

                    int result = svc->providers[p].vtable->notify(
                        svc->providers[p].context, alert, title, body);

                    if (result == 0) {
                        sent = 1;
                        alert->notify_state = OZAYN_SALERT_NOTIFY_STATE_SENT;
                        svc->total_notifications_sent++;
                        _audit_alert_event(svc, "NOTIFICATION_SENT", alert);
                    } else {
                        svc->providers[p].fail_count++;
                        svc->providers[p].last_fail_time = time(NULL);
                        if (svc->providers[p].fail_count >= 5)
                            svc->providers[p].available = 0;
                    }
                }
                break;
            }
        }

        if (!sent) {
            if (retry < svc->policy.max_notify_retries) {
                svc->notify_queue[qslot].retry_count++;
                break;
            } else {
                /* Mark alert as failed notification */
                for (int i = 0; i < svc->alert_count; i++) {
                    int aslot = (svc->alert_head + i) %
                                 OZAYN_SALERT_MAX_ALERTS;
                    uint32_t h = _hash_str(svc->alerts[aslot].alert_id);
                    if (h == alert_hash) {
                        svc->alerts[aslot].notify_state =
                            OZAYN_SALERT_NOTIFY_STATE_FAILED;
                        break;
                    }
                }
                svc->total_notifications_failed++;
            }
        }

        /* Dequeue */
        svc->notify_queue_head = (svc->notify_queue_head + 1) %
                                  OZAYN_SALERT_MAX_NOTIFY_QUEUE;
        svc->notify_queue_count--;
    }

    return OZAYN_SALERT_OK;
}

int ozayn_salert_get_notify_queue_count(
    const ozayn_salert_service_t *svc)
{
    return svc ? svc->notify_queue_count : 0;
}

/* ============================================================
 * SECTION 23 — RATE LIMITING
 * ============================================================ */

int ozayn_salert_check_rate_limit(
    const ozayn_salert_service_t *svc,
    ozayn_salert_type_t alert_type)
{
    if (!svc) return 0;
    if (!svc->policy.enabled) return 0;

    /* Global rate limit: max_active_alerts */
    if (svc->active_count >= svc->policy.max_active_alerts)
        return 0;

    /* Per-type: check threshold */
    int exceeded = 0;
    ozayn_salert_severity_t sev;
    /* Use non-const version for check */
    ozayn_salert_service_t *mutable_svc = (ozayn_salert_service_t *)svc;
    ozayn_salert_check_threshold(mutable_svc, alert_type, &exceeded, &sev);
    if (exceeded) return 0;

    return 1;
}

ozayn_salert_err_t ozayn_salert_record_rate_event(
    ozayn_salert_service_t *svc,
    ozayn_salert_type_t alert_type)
{
    if (!svc) return OZAYN_SALERT_ERR_NULL;
    if (!svc->initialized) return OZAYN_SALERT_ERR_NOT_INITIALIZED;
    return ozayn_salert_record_threshold_event(svc, alert_type);
}

/* ============================================================
 * SECTION 24 — HEALTH INTEGRATION
 * ============================================================ */

ozayn_salert_err_t ozayn_salert_evaluate_health(
    ozayn_salert_service_t *svc)
{
    if (!svc) return OZAYN_SALERT_ERR_NULL;
    if (!svc->initialized) return OZAYN_SALERT_ERR_NOT_INITIALIZED;
    if (!svc->health_service || !svc->health_service->initialized)
        return OZAYN_SALERT_ERR_UNAVAILABLE;

    ozayn_sh_health_state_t health_state;
    ozayn_sh_result_t hr = ozayn_sh_get_status(svc->health_service,
                                                 &health_state);
    if (hr != OZAYN_SH_OK) return OZAYN_SALERT_ERR_UNAVAILABLE;

    switch (health_state) {
    case OZAYN_SH_HEALTHY:
        /* No alert needed */
        break;
    case OZAYN_SH_DEGRADED: {
        ozayn_salert_alert_t *alert = NULL;
        ozayn_salert_create(svc,
            OZAYN_SALERT_TYPE_HEALTH_DEGRADED,
            OZAYN_SALERT_SEV_HIGH,
            OZAYN_SALERT_PRIO_NORMAL,
            OZAYN_SALERT_SOURCE_SECURITY_HEALTH,
            "HEALTH", NULL,
            "Security health degraded", NULL, &alert);
        break;
    }
    case OZAYN_SH_WARNING: {
        ozayn_salert_alert_t *alert = NULL;
        ozayn_salert_create(svc,
            OZAYN_SALERT_TYPE_HEALTH_DEGRADED,
            OZAYN_SALERT_SEV_WARNING,
            OZAYN_SALERT_PRIO_NORMAL,
            OZAYN_SALERT_SOURCE_SECURITY_HEALTH,
            "HEALTH", NULL,
            "Security health warning", NULL, &alert);
        break;
    }
    case OZAYN_SH_CRITICAL: {
        ozayn_salert_alert_t *alert = NULL;
        ozayn_salert_create(svc,
            OZAYN_SALERT_TYPE_HEALTH_CRITICAL,
            OZAYN_SALERT_SEV_CRITICAL,
            OZAYN_SALERT_PRIO_URGENT,
            OZAYN_SALERT_SOURCE_SECURITY_HEALTH,
            "HEALTH", NULL,
            "Security health critical", NULL, &alert);
        break;
    }
    case OZAYN_SH_UNAVAILABLE: {
        ozayn_salert_alert_t *alert = NULL;
        ozayn_salert_create(svc,
            OZAYN_SALERT_TYPE_COMPONENT_UNAVAILABLE,
            OZAYN_SALERT_SEV_HIGH,
            OZAYN_SALERT_PRIO_HIGH,
            OZAYN_SALERT_SOURCE_SECURITY_HEALTH,
            "HEALTH", NULL,
            "Security health unavailable", NULL, &alert);
        break;
    }
    case OZAYN_SH_LOCKDOWN: {
        ozayn_salert_alert_t *alert = NULL;
        ozayn_salert_create(svc,
            OZAYN_SALERT_TYPE_LOCKDOWN,
            OZAYN_SALERT_SEV_CRITICAL,
            OZAYN_SALERT_PRIO_IMMEDIATE,
            OZAYN_SALERT_SOURCE_SECURITY_HEALTH,
            "HEALTH", NULL,
            "Security lockdown active", NULL, &alert);
        break;
    }
    case OZAYN_SH_UNKNOWN:
    default:
        break;
    }
    return OZAYN_SALERT_OK;
}

/* ============================================================
 * SECTION 25 — DIAGNOSTIC INTEGRATION
 * ============================================================ */

ozayn_salert_err_t ozayn_salert_evaluate_diagnostics(
    ozayn_salert_service_t *svc)
{
    if (!svc) return OZAYN_SALERT_ERR_NULL;
    if (!svc->initialized) return OZAYN_SALERT_ERR_NOT_INITIALIZED;
    if (!svc->diag_service || !svc->diag_service->initialized)
        return OZAYN_SALERT_ERR_UNAVAILABLE;

    ozayn_sdiag_summary_t summary;
    ozayn_sdiag_err_t dr = ozayn_sdiag_get_summary(svc->diag_service,
                                                     &summary);
    if (dr != OZAYN_SDIAG_OK) return OZAYN_SALERT_ERR_UNAVAILABLE;

    if (summary.fail_count > 0) {
        ozayn_salert_alert_t *alert = NULL;
        ozayn_salert_create(svc,
            OZAYN_SALERT_TYPE_DIAGNOSTIC_FAIL,
            OZAYN_SALERT_SEV_HIGH,
            OZAYN_SALERT_PRIO_NORMAL,
            OZAYN_SALERT_SOURCE_SECURITY_DIAGNOSTICS,
            "DIAG", NULL,
            "Security diagnostics report failures", NULL, &alert);
    }

    if (summary.critical_count > 0) {
        ozayn_salert_alert_t *alert = NULL;
        ozayn_salert_create(svc,
            OZAYN_SALERT_TYPE_DIAGNOSTIC_FAIL,
            OZAYN_SALERT_SEV_CRITICAL,
            OZAYN_SALERT_PRIO_URGENT,
            OZAYN_SALERT_SOURCE_SECURITY_DIAGNOSTICS,
            "DIAG", NULL,
            "Security diagnostics report critical failures", NULL, &alert);
    }

    return OZAYN_SALERT_OK;
}

/* ============================================================
 * SECTION 26 — INCIDENT INTEGRATION
 * ============================================================ */

ozayn_salert_err_t ozayn_salert_evaluate_incidents(
    ozayn_salert_service_t *svc)
{
    if (!svc) return OZAYN_SALERT_ERR_NULL;
    if (!svc->initialized) return OZAYN_SALERT_ERR_NOT_INITIALIZED;
    if (!svc->incident_service || !svc->incident_service->initialized)
        return OZAYN_SALERT_ERR_UNAVAILABLE;

    if (svc->incident_service->lockdown_active) {
        ozayn_salert_alert_t *alert = NULL;
        ozayn_salert_create(svc,
            OZAYN_SALERT_TYPE_LOCKDOWN,
            OZAYN_SALERT_SEV_CRITICAL,
            OZAYN_SALERT_PRIO_IMMEDIATE,
            OZAYN_SALERT_SOURCE_INCIDENT_RESPONSE,
            "INCIDENT", NULL,
            "Incident response lockdown active", NULL, &alert);
    }

    /* Evaluate recent incidents */
    ozayn_ir_incident_t *incidents[32];
    int inc_count = ozayn_ir_list(svc->incident_service,
                                   -1, incidents, 32);

    for (int i = 0; i < inc_count; i++) {
        if (incidents[i]->state == OZAYN_IR_STATE_DETECTED ||
            incidents[i]->state == OZAYN_IR_STATE_CONTAINMENT_REQUIRED) {

            ozayn_salert_severity_t sev = OZAYN_SALERT_SEV_HIGH;
            if (incidents[i]->severity == OZAYN_IR_SEV_CRITICAL)
                sev = OZAYN_SALERT_SEV_CRITICAL;
            else if (incidents[i]->severity == OZAYN_IR_SEV_HIGH)
                sev = OZAYN_SALERT_SEV_HIGH;
            else if (incidents[i]->severity >= OZAYN_IR_SEV_MEDIUM)
                sev = OZAYN_SALERT_SEV_WARNING;

            ozayn_salert_alert_t *alert = NULL;
            ozayn_salert_create(svc,
                OZAYN_SALERT_TYPE_INCIDENT,
                sev,
                OZAYN_SALERT_PRIO_HIGH,
                OZAYN_SALERT_SOURCE_INCIDENT_RESPONSE,
                "INCIDENT",
                incidents[i]->correlation_id,
                incidents[i]->detail[0] ?
                    incidents[i]->detail : "Incident detected",
                NULL, &alert);

            if (alert) {
                strncpy(alert->incident_id, incidents[i]->incident_id,
                        OZAYN_SALERT_MAX_ID_LEN - 1);
            }
        }
    }

    return OZAYN_SALERT_OK;
}

/* ============================================================
 * SECTION 32 — CLEANUP
 * ============================================================ */

int ozayn_salert_cleanup_expired(ozayn_salert_service_t *svc)
{
    if (!svc || !svc->initialized) return 0;

    int cleaned = 0;
    time_t now = time(NULL);

    for (int i = 0; i < svc->alert_count; i++) {
        int slot = (svc->alert_head + i) % OZAYN_SALERT_MAX_ALERTS;
        ozayn_salert_alert_t *a = &svc->alerts[slot];

        if (a->expiration_time > 0 && now > a->expiration_time &&
            a->state != OZAYN_SALERT_STATE_RESOLVED &&
            a->state != OZAYN_SALERT_STATE_CANCELLED) {
            a->state = OZAYN_SALERT_STATE_EXPIRED;
            a->updated_time = now;
            if (a->state == OZAYN_SALERT_STATE_ACTIVE)
                svc->active_count--;
            cleaned++;
        }
    }
    return cleaned;
}

int ozayn_salert_cleanup_resolved(ozayn_salert_service_t *svc,
                                   int max_age_seconds)
{
    if (!svc || !svc->initialized) return 0;
    if (max_age_seconds <= 0) return 0;

    int cleaned = 0;
    time_t now = time(NULL);

    for (int i = 0; i < svc->alert_count; i++) {
        int slot = (svc->alert_head + i) % OZAYN_SALERT_MAX_ALERTS;
        ozayn_salert_alert_t *a = &svc->alerts[slot];

        if ((a->state == OZAYN_SALERT_STATE_RESOLVED ||
             a->state == OZAYN_SALERT_STATE_EXPIRED ||
             a->state == OZAYN_SALERT_STATE_CANCELLED) &&
            a->resolved_time > 0 &&
            (now - a->resolved_time) > max_age_seconds) {
            /* Mark as cleaned by shifting state to a sentinel */
            a->state = OZAYN_SALERT_STATE_CANCELLED;
            a->alert_id[0] = '\0'; /* invalidate */
            cleaned++;
        }
    }
    return cleaned;
}
