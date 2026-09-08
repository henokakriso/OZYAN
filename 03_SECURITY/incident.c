/*
 * incident.c — Security Recovery, Incident Response & Compromise
 *              Handling Foundation (Step 25).
 *
 * Provides controlled detection, classification, containment,
 * recovery, verification, and resolution of security incidents.
 */

#include "incident.h"
#include <string.h>
#include <stdio.h>

/* ============================================================
 * STATIC GLOBAL SERVICE
 * ============================================================ */

static ozayn_ir_service_t _ir_global = {0};

ozayn_ir_service_t *ozayn_ir_get_global(void)
{
    return &_ir_global;
}

/* ============================================================
 * SECTION 20 — STATE TRANSITION VALIDATION
 * ============================================================ */

int ozayn_ir_state_transition_valid(ozayn_ir_state_t from,
                                     ozayn_ir_state_t to)
{
    switch (from) {
    case OZAYN_IR_STATE_DETECTED:
        return to == OZAYN_IR_STATE_CLASSIFIED;

    case OZAYN_IR_STATE_CLASSIFIED:
        return to == OZAYN_IR_STATE_CONTAINMENT_REQUIRED ||
               to == OZAYN_IR_STATE_RECOVERY_REQUIRED;

    case OZAYN_IR_STATE_CONTAINMENT_REQUIRED:
        return to == OZAYN_IR_STATE_CONTAINING;

    case OZAYN_IR_STATE_CONTAINING:
        return to == OZAYN_IR_STATE_CONTAINED ||
               to == OZAYN_IR_STATE_RECOVERY_FAILED;

    case OZAYN_IR_STATE_CONTAINED:
        return to == OZAYN_IR_STATE_RECOVERY_REQUIRED;

    case OZAYN_IR_STATE_RECOVERY_REQUIRED:
        return to == OZAYN_IR_STATE_RECOVERING;

    case OZAYN_IR_STATE_RECOVERING:
        return to == OZAYN_IR_STATE_VERIFIED ||
               to == OZAYN_IR_STATE_RECOVERY_FAILED;

    case OZAYN_IR_STATE_VERIFIED:
        return to == OZAYN_IR_STATE_RESOLVED;

    case OZAYN_IR_STATE_RESOLVED:
        return 0;

    case OZAYN_IR_STATE_RECOVERY_FAILED:
        return 0;

    default:
        return 0;
    }
}

/* ============================================================
 * SECTION 19 — NAME HELPERS
 * ============================================================ */

const char *ozayn_ir_result_name(ozayn_ir_result_t r)
{
    switch (r) {
    case OZAYN_IR_OK:                                 return "OK";
    case OZAYN_IR_ERR:                                return "ERR";
    case OZAYN_IR_ERR_NULL:                           return "ERR_NULL";
    case OZAYN_IR_ERR_NOT_INITIALIZED:                return "ERR_NOT_INITIALIZED";
    case OZAYN_IR_ERR_ALREADY_INITIALIZED:            return "ERR_ALREADY_INITIALIZED";
    case OZAYN_IR_ERR_INVALID_REQUEST:                return "ERR_INVALID_REQUEST";
    case OZAYN_IR_ERR_INVALID_ID:                     return "ERR_INVALID_ID";
    case OZAYN_IR_ERR_INVALID_TYPE:                   return "ERR_INVALID_TYPE";
    case OZAYN_IR_ERR_INVALID_SEVERITY:               return "ERR_INVALID_SEVERITY";
    case OZAYN_IR_ERR_NOT_FOUND:                      return "ERR_NOT_FOUND";
    case OZAYN_IR_ERR_ALREADY_RESOLVED:               return "ERR_ALREADY_RESOLVED";
    case OZAYN_IR_ERR_STATE_INVALID:                  return "ERR_STATE_INVALID";
    case OZAYN_IR_ERR_STATE_TRANSITION_INVALID:       return "ERR_STATE_TRANSITION_INVALID";
    case OZAYN_IR_ERR_POLICY_INVALID:                 return "ERR_POLICY_INVALID";
    case OZAYN_IR_ERR_POLICY_UNAVAILABLE:             return "ERR_POLICY_UNAVAILABLE";
    case OZAYN_IR_ERR_CONTAINMENT_FAILED:             return "ERR_CONTAINMENT_FAILED";
    case OZAYN_IR_ERR_RECOVERY_FAILED:                return "ERR_RECOVERY_FAILED";
    case OZAYN_IR_ERR_VERIFICATION_FAILED:            return "ERR_VERIFICATION_FAILED";
    case OZAYN_IR_ERR_UNAUTHORIZED:                   return "ERR_UNAUTHORIZED";
    case OZAYN_IR_ERR_MFA_REQUIRED:                   return "ERR_MFA_REQUIRED";
    case OZAYN_IR_ERR_STORAGE_ERROR:                  return "ERR_STORAGE_ERROR";
    case OZAYN_IR_ERR_AUDIT_FAILURE:                  return "ERR_AUDIT_FAILURE";
    case OZAYN_IR_ERR_INTEGRITY_FAILURE:              return "ERR_INTEGRITY_FAILURE";
    case OZAYN_IR_ERR_LOCKDOWN_REQUIRED:              return "ERR_LOCKDOWN_REQUIRED";
    case OZAYN_IR_ERR_LOCKDOWN_FAILED:                return "ERR_LOCKDOWN_FAILED";
    case OZAYN_IR_ERR_RECOVERY_UNAVAILABLE:           return "ERR_RECOVERY_UNAVAILABLE";
    case OZAYN_IR_ERR_RECOVERY_UNSAFE:                return "ERR_RECOVERY_UNSAFE";
    case OZAYN_IR_ERR_STORAGE_FULL:                   return "ERR_STORAGE_FULL";
    case OZAYN_IR_ERR_DUPLICATE:                      return "ERR_DUPLICATE";
    default:                                          return "UNKNOWN";
    }
}

const char *ozayn_ir_type_name(ozayn_ir_type_t t)
{
    switch (t) {
    case OZAYN_IR_TYPE_AUTHENTICATION_ATTACK:   return "AUTHENTICATION_ATTACK";
    case OZAYN_IR_TYPE_AUTHENTICATION_ANOMALY:  return "AUTHENTICATION_ANOMALY";
    case OZAYN_IR_TYPE_CREDENTIAL_COMPROMISE:   return "CREDENTIAL_COMPROMISE";
    case OZAYN_IR_TYPE_IDENTITY_COMPROMISE:     return "IDENTITY_COMPROMISE";
    case OZAYN_IR_TYPE_SESSION_COMPROMISE:      return "SESSION_COMPROMISE";
    case OZAYN_IR_TYPE_AUTHORIZATION_VIOLATION: return "AUTHORIZATION_VIOLATION";
    case OZAYN_IR_TYPE_PRIVILEGE_ESCALATION:    return "PRIVILEGE_ESCALATION";
    case OZAYN_IR_TYPE_PERMISSION_TAMPERING:    return "PERMISSION_TAMPERING";
    case OZAYN_IR_TYPE_ROLE_TAMPERING:          return "ROLE_TAMPERING";
    case OZAYN_IR_TYPE_KEY_COMPROMISE:          return "KEY_COMPROMISE";
    case OZAYN_IR_TYPE_KEY_STORAGE_FAILURE:     return "KEY_STORAGE_FAILURE";
    case OZAYN_IR_TYPE_VAULT_COMPROMISE:        return "VAULT_COMPROMISE";
    case OZAYN_IR_TYPE_DATA_INTEGRITY_FAILURE:  return "DATA_INTEGRITY_FAILURE";
    case OZAYN_IR_TYPE_AUDIT_INTEGRITY_FAILURE: return "AUDIT_INTEGRITY_FAILURE";
    case OZAYN_IR_TYPE_BACKUP_INTEGRITY_FAILURE: return "BACKUP_INTEGRITY_FAILURE";
    case OZAYN_IR_TYPE_RESTORE_FAILURE:         return "RESTORE_FAILURE";
    case OZAYN_IR_TYPE_SECURE_DELETION_FAILURE: return "SECURE_DELETION_FAILURE";
    case OZAYN_IR_TYPE_CONFIG_VIOLATION:        return "CONFIG_VIOLATION";
    case OZAYN_IR_TYPE_COMPONENT_FAILURE:       return "COMPONENT_FAILURE";
    case OZAYN_IR_TYPE_SUSPICIOUS_ACTIVITY:     return "SUSPICIOUS_ACTIVITY";
    case OZAYN_IR_TYPE_UNKNOWN:                 return "UNKNOWN";
    default:                                    return "UNKNOWN";
    }
}

const char *ozayn_ir_severity_name(ozayn_ir_severity_t s)
{
    switch (s) {
    case OZAYN_IR_SEV_INFO:     return "INFO";
    case OZAYN_IR_SEV_LOW:      return "LOW";
    case OZAYN_IR_SEV_MEDIUM:   return "MEDIUM";
    case OZAYN_IR_SEV_HIGH:     return "HIGH";
    case OZAYN_IR_SEV_CRITICAL: return "CRITICAL";
    default:                    return "UNKNOWN";
    }
}

const char *ozayn_ir_state_name(ozayn_ir_state_t s)
{
    switch (s) {
    case OZAYN_IR_STATE_DETECTED:               return "DETECTED";
    case OZAYN_IR_STATE_CLASSIFIED:             return "CLASSIFIED";
    case OZAYN_IR_STATE_CONTAINMENT_REQUIRED:   return "CONTAINMENT_REQUIRED";
    case OZAYN_IR_STATE_CONTAINING:             return "CONTAINING";
    case OZAYN_IR_STATE_CONTAINED:              return "CONTAINED";
    case OZAYN_IR_STATE_RECOVERY_REQUIRED:      return "RECOVERY_REQUIRED";
    case OZAYN_IR_STATE_RECOVERING:             return "RECOVERING";
    case OZAYN_IR_STATE_VERIFIED:               return "VERIFIED";
    case OZAYN_IR_STATE_RESOLVED:               return "RESOLVED";
    case OZAYN_IR_STATE_RECOVERY_FAILED:        return "RECOVERY_FAILED";
    default:                                    return "UNKNOWN";
    }
}

const char *ozayn_ir_compromise_level_name(ozayn_ir_compromise_level_t l)
{
    switch (l) {
    case OZAYN_IR_COMPROMISE_NORMAL:                return "NORMAL";
    case OZAYN_IR_COMPROMISE_DEGRADED:              return "DEGRADED";
    case OZAYN_IR_COMPROMISE_SUSPICIOUS:            return "SUSPICIOUS";
    case OZAYN_IR_COMPROMISE_CONTAINMENT_REQUIRED:  return "CONTAINMENT_REQUIRED";
    case OZAYN_IR_COMPROMISE_CONTAINED:             return "CONTAINED";
    case OZAYN_IR_COMPROMISE_RECOVERY_REQUIRED:     return "RECOVERY_REQUIRED";
    case OZAYN_IR_COMPROMISE_RECOVERY_FAILED:       return "RECOVERY_FAILED";
    case OZAYN_IR_COMPROMISE_LOCKDOWN:              return "LOCKDOWN";
    default:                                        return "UNKNOWN";
    }
}

const char *ozayn_ir_containment_action_name(ozayn_ir_containment_action_t a)
{
    switch (a) {
    case OZAYN_IR_CONTAIN_NONE:                 return "NONE";
    case OZAYN_IR_CONTAIN_REVOKE_SESSION:       return "REVOKE_SESSION";
    case OZAYN_IR_CONTAIN_SUSPEND_IDENTITY:     return "SUSPEND_IDENTITY";
    case OZAYN_IR_CONTAIN_REVOKE_IDENTITY:      return "REVOKE_IDENTITY";
    case OZAYN_IR_CONTAIN_REVOKE_KEY:           return "REVOKE_KEY";
    case OZAYN_IR_CONTAIN_RESTRICT_RESOURCE:    return "RESTRICT_RESOURCE";
    case OZAYN_IR_CONTAIN_ENTER_LOCKDOWN:       return "ENTER_LOCKDOWN";
    default:                                    return "UNKNOWN";
    }
}

/* ============================================================
 * SECTION 18 — POLICY
 * ============================================================ */

ozayn_ir_policy_t ozayn_ir_default_policy(void)
{
    ozayn_ir_policy_t p;
    memset(&p, 0, sizeof(p));
    p.max_incidents            = OZAYN_IR_MAX_INCIDENTS;
    p.auto_contain_critical    = 1;
    p.require_mfa_for_recovery = 1;
    p.lockdown_threshold       = 5;
    p.incident_retention_count = OZAYN_IR_MAX_INCIDENTS;
    p.dedup_window_seconds     = 60;
    p.min_lockdown_severity    = OZAYN_IR_SEV_CRITICAL;
    return p;
}

ozayn_ir_result_t ozayn_ir_set_policy(ozayn_ir_service_t *svc,
                                       const ozayn_ir_policy_t *policy)
{
    if (!svc) return OZAYN_IR_ERR_NULL;
    if (!svc->initialized) return OZAYN_IR_ERR_NOT_INITIALIZED;
    if (!policy) return OZAYN_IR_ERR_NULL;
    svc->policy = *policy;
    return OZAYN_IR_OK;
}

const ozayn_ir_policy_t *ozayn_ir_get_policy(const ozayn_ir_service_t *svc)
{
    if (!svc) return NULL;
    if (!svc->initialized) return NULL;
    return &svc->policy;
}

/* ============================================================
 * SECTION 11 — LIFECYCLE
 * ============================================================ */

ozayn_ir_result_t ozayn_ir_service_init(ozayn_ir_service_t *svc,
                                         const ozayn_ir_service_config_t *cfg)
{
    if (!svc) return OZAYN_IR_ERR_NULL;
    if (!cfg) return OZAYN_IR_ERR_NULL;
    if (svc->initialized) return OZAYN_IR_ERR_ALREADY_INITIALIZED;

    memset(svc, 0, sizeof(*svc));

    svc->vault          = cfg->vault;
    svc->key_lifecycle  = cfg->key_lifecycle;
    svc->protection     = cfg->protection;
    svc->storage        = cfg->storage;
    svc->audit          = cfg->audit;
    svc->identity       = cfg->identity;
    svc->session        = cfg->session;
    svc->policy         = ozayn_ir_default_policy();
    svc->compromise_level = OZAYN_IR_COMPROMISE_NORMAL;
    svc->lockdown_active  = 0;
    svc->initialized    = 1;

    return OZAYN_IR_OK;
}

void ozayn_ir_service_shutdown(ozayn_ir_service_t *svc)
{
    if (!svc) return;
    if (!svc->initialized) return;
    memset(svc, 0, sizeof(*svc));
}

int ozayn_ir_service_is_initialized(const ozayn_ir_service_t *svc)
{
    if (!svc) return 0;
    return svc->initialized;
}

/* ============================================================
 * AUDIT HELPER
 * ============================================================ */

static void _audit_incident(ozayn_ir_service_t *svc,
                             const char *event_detail,
                             const char *incident_id,
                             ozayn_ir_result_t outcome)
{
    if (!svc->audit || !svc->audit->initialized) return;

    ozayn_audit_event_t ev;
    ozayn_audit_event_init(&ev);
    ozayn_audit_event_set_type(&ev, OZAYN_AUDIT_CONFIG_CHANGED);
    ozayn_audit_event_set_outcome(&ev,
        outcome == OZAYN_IR_OK ? OZAYN_AUDIT_OUTCOME_SUCCESS
                               : OZAYN_AUDIT_OUTCOME_FAILURE);
    ozayn_audit_event_set_source(&ev, "incident_response");
    ozayn_audit_event_set_detail(&ev, event_detail);
    ozayn_audit_event_set_identity(&ev, "");
    strncpy(ev.resource_id, incident_id, OZAYN_AUDIT_MAX_RESOURCE_ID_LEN - 1);
    ozayn_audit_record(svc->audit, &ev);
}

/* ============================================================
 * INTERNAL: FIND INCIDENT
 * ============================================================ */

static ozayn_ir_incident_t *_find_incident(ozayn_ir_service_t *svc,
                                            const char *incident_id)
{
    if (!svc || !incident_id) return NULL;
    for (int i = 0; i < svc->incident_count; i++) {
        if (strcmp(svc->incidents[i].incident_id, incident_id) == 0)
            return &svc->incidents[i];
    }
    return NULL;
}

/* ============================================================
 * INTERNAL: GENERATE INCIDENT ID
 * ============================================================ */

static void _generate_id(ozayn_ir_service_t *svc, char *out_id, size_t max_len)
{
    snprintf(out_id, max_len, "INC-%lu-%d",
             (unsigned long)time(NULL), svc->incident_count);
}

/* ============================================================
 * INTERNAL: UPDATE COMPROMISE LEVEL
 * ============================================================ */

static void _update_compromise_level(ozayn_ir_service_t *svc)
{
    int critical_count = 0;
    int high_count = 0;
    int unresolved = 0;

    for (int i = 0; i < svc->incident_count; i++) {
        ozayn_ir_incident_t *inc = &svc->incidents[i];
        if (inc->state != OZAYN_IR_STATE_RESOLVED) {
            unresolved++;
            if (inc->severity == OZAYN_IR_SEV_CRITICAL) critical_count++;
            if (inc->severity == OZAYN_IR_SEV_HIGH) high_count++;
        }
    }

    if (svc->lockdown_active) {
        svc->compromise_level = OZAYN_IR_COMPROMISE_LOCKDOWN;
    } else if (critical_count >= svc->policy.lockdown_threshold) {
        svc->compromise_level = OZAYN_IR_COMPROMISE_LOCKDOWN;
        svc->lockdown_active = 1;
        svc->total_lockdowns++;
    } else if (critical_count > 0) {
        svc->compromise_level = OZAYN_IR_COMPROMISE_CONTAINMENT_REQUIRED;
    } else if (high_count > 0) {
        svc->compromise_level = OZAYN_IR_COMPROMISE_SUSPICIOUS;
    } else if (unresolved > 0) {
        svc->compromise_level = OZAYN_IR_COMPROMISE_DEGRADED;
    } else {
        svc->compromise_level = OZAYN_IR_COMPROMISE_NORMAL;
    }
}

/* ============================================================
 * SECTION 12 — INCIDENT REPORTING
 * ============================================================ */

ozayn_ir_result_t ozayn_ir_report(ozayn_ir_service_t *svc,
                                   ozayn_ir_type_t type,
                                   ozayn_ir_severity_t severity,
                                   const char *source_component,
                                   const char *identity_id,
                                   const char *session_id,
                                   const char *resource_id,
                                   const char *correlation_id,
                                   const char *detail,
                                   ozayn_ir_incident_t **out_incident)
{
    if (!svc) return OZAYN_IR_ERR_NULL;
    if (!svc->initialized) return OZAYN_IR_ERR_NOT_INITIALIZED;
    if (type > OZAYN_IR_TYPE_UNKNOWN) return OZAYN_IR_ERR_INVALID_TYPE;
    if (severity > OZAYN_IR_SEV_CRITICAL) return OZAYN_IR_ERR_INVALID_SEVERITY;
    if (!source_component || source_component[0] == '\0')
        return OZAYN_IR_ERR_INVALID_REQUEST;

    /* Check capacity */
    if (svc->incident_count >= svc->policy.max_incidents)
        return OZAYN_IR_ERR_STORAGE_FULL;

    /* Deduplication: check for recent duplicate */
    time_t now = time(NULL);
    for (int i = 0; i < svc->incident_count; i++) {
        ozayn_ir_incident_t *existing = &svc->incidents[i];
        if (existing->incident_type == type &&
            existing->state != OZAYN_IR_STATE_RESOLVED &&
            (now - existing->detection_time) < svc->policy.dedup_window_seconds &&
            (identity_id && existing->identity_id[0] &&
             strcmp(existing->identity_id, identity_id) == 0)) {
            if (out_incident) *out_incident = existing;
            return OZAYN_IR_ERR_DUPLICATE;
        }
    }

    /* Create incident */
    ozayn_ir_incident_t *inc = &svc->incidents[svc->incident_count];
    memset(inc, 0, sizeof(*inc));

    _generate_id(svc, inc->incident_id, OZAYN_IR_MAX_ID_LEN);
    inc->incident_version = 1;
    inc->incident_type = type;
    inc->severity = severity;
    inc->state = OZAYN_IR_STATE_DETECTED;
    inc->detection_time = now;
    inc->last_updated = now;
    strncpy(inc->source_component, source_component, OZAYN_IR_MAX_SOURCE_LEN - 1);
    if (identity_id) strncpy(inc->identity_id, identity_id, OZAYN_IR_MAX_ID_LEN - 1);
    if (session_id) strncpy(inc->session_id, session_id, OZAYN_IR_MAX_ID_LEN - 1);
    if (resource_id) strncpy(inc->resource_id, resource_id, OZAYN_IR_MAX_ID_LEN - 1);
    if (correlation_id) strncpy(inc->correlation_id, correlation_id, OZAYN_IR_MAX_ID_LEN - 1);
    if (detail) strncpy(inc->detail, detail, OZAYN_IR_MAX_DETAIL_LEN - 1);

    svc->incident_count++;
    svc->total_incidents_reported++;

    _update_compromise_level(svc);
    _audit_incident(svc, "incident_detected", inc->incident_id, OZAYN_IR_OK);

    if (out_incident) *out_incident = inc;
    return OZAYN_IR_OK;
}

/* ============================================================
 * SECTION 13 — INCIDENT QUERY
 * ============================================================ */

ozayn_ir_result_t ozayn_ir_get(const ozayn_ir_service_t *svc,
                                const char *incident_id,
                                ozayn_ir_incident_t **out_incident)
{
    if (!svc) return OZAYN_IR_ERR_NULL;
    if (!svc->initialized) return OZAYN_IR_ERR_NOT_INITIALIZED;
    if (!incident_id || incident_id[0] == '\0') return OZAYN_IR_ERR_INVALID_ID;
    if (!out_incident) return OZAYN_IR_ERR_NULL;

    for (int i = 0; i < svc->incident_count; i++) {
        if (strcmp(svc->incidents[i].incident_id, incident_id) == 0) {
            *out_incident = (ozayn_ir_incident_t *)&svc->incidents[i];
            return OZAYN_IR_OK;
        }
    }
    return OZAYN_IR_ERR_NOT_FOUND;
}

int ozayn_ir_list(const ozayn_ir_service_t *svc,
                   ozayn_ir_type_t filter_type,
                   ozayn_ir_incident_t **out_incidents,
                   int max_count)
{
    if (!svc || !svc->initialized || !out_incidents || max_count <= 0) return 0;

    int count = 0;
    for (int i = 0; i < svc->incident_count && count < max_count; i++) {
        if (filter_type == OZAYN_IR_TYPE_UNKNOWN ||
            svc->incidents[i].incident_type == filter_type) {
            out_incidents[count] = (ozayn_ir_incident_t *)&svc->incidents[i];
            count++;
        }
    }
    return count;
}

/* ============================================================
 * SECTION 14 — INCIDENT LIFECYCLE
 * ============================================================ */

ozayn_ir_result_t ozayn_ir_classify(ozayn_ir_service_t *svc,
                                     const char *incident_id,
                                     ozayn_ir_type_t type,
                                     ozayn_ir_severity_t severity)
{
    if (!svc) return OZAYN_IR_ERR_NULL;
    if (!svc->initialized) return OZAYN_IR_ERR_NOT_INITIALIZED;
    if (!incident_id) return OZAYN_IR_ERR_INVALID_ID;
    if (type > OZAYN_IR_TYPE_UNKNOWN) return OZAYN_IR_ERR_INVALID_TYPE;
    if (severity > OZAYN_IR_SEV_CRITICAL) return OZAYN_IR_ERR_INVALID_SEVERITY;

    ozayn_ir_incident_t *inc = _find_incident(svc, incident_id);
    if (!inc) return OZAYN_IR_ERR_NOT_FOUND;
    if (inc->state == OZAYN_IR_STATE_RESOLVED)
        return OZAYN_IR_ERR_ALREADY_RESOLVED;

    /* Must be in DETECTED state to classify */
    if (inc->state != OZAYN_IR_STATE_DETECTED)
        return OZAYN_IR_ERR_STATE_TRANSITION_INVALID;

    inc->incident_type = type;
    inc->severity = severity;
    inc->state = OZAYN_IR_STATE_CLASSIFIED;
    inc->last_updated = time(NULL);
    inc->incident_version++;

    _update_compromise_level(svc);
    _audit_incident(svc, "incident_classified", incident_id, OZAYN_IR_OK);
    return OZAYN_IR_OK;
}

ozayn_ir_result_t ozayn_ir_update_state(ozayn_ir_service_t *svc,
                                          const char *incident_id,
                                          ozayn_ir_state_t new_state)
{
    if (!svc) return OZAYN_IR_ERR_NULL;
    if (!svc->initialized) return OZAYN_IR_ERR_NOT_INITIALIZED;
    if (!incident_id) return OZAYN_IR_ERR_INVALID_ID;

    ozayn_ir_incident_t *inc = _find_incident(svc, incident_id);
    if (!inc) return OZAYN_IR_ERR_NOT_FOUND;
    if (inc->state == OZAYN_IR_STATE_RESOLVED)
        return OZAYN_IR_ERR_ALREADY_RESOLVED;

    if (!ozayn_ir_state_transition_valid(inc->state, new_state))
        return OZAYN_IR_ERR_STATE_TRANSITION_INVALID;

    inc->state = new_state;
    inc->last_updated = time(NULL);
    inc->incident_version++;

    _update_compromise_level(svc);

    char detail[128];
    snprintf(detail, sizeof(detail), "state_transition_to_%s",
             ozayn_ir_state_name(new_state));
    _audit_incident(svc, detail, incident_id, OZAYN_IR_OK);
    return OZAYN_IR_OK;
}

/* ============================================================
 * SECTION 15 — CONTAINMENT
 * ============================================================ */

ozayn_ir_result_t ozayn_ir_contain(ozayn_ir_service_t *svc,
                                    const char *incident_id,
                                    ozayn_ir_containment_action_t action)
{
    if (!svc) return OZAYN_IR_ERR_NULL;
    if (!svc->initialized) return OZAYN_IR_ERR_NOT_INITIALIZED;
    if (!incident_id) return OZAYN_IR_ERR_INVALID_ID;

    ozayn_ir_incident_t *inc = _find_incident(svc, incident_id);
    if (!inc) return OZAYN_IR_ERR_NOT_FOUND;
    if (inc->state == OZAYN_IR_STATE_RESOLVED)
        return OZAYN_IR_ERR_ALREADY_RESOLVED;

    /* Transition to CONTAINING if appropriate */
    if (inc->state == OZAYN_IR_STATE_CONTAINMENT_REQUIRED) {
        inc->state = OZAYN_IR_STATE_CONTAINING;
        inc->last_updated = time(NULL);
    }

    inc->containment_action = action;

    /* Execute containment action */
    ozayn_ir_result_t result = OZAYN_IR_OK;

    switch (action) {
    case OZAYN_IR_CONTAIN_REVOKE_SESSION:
        if (svc->session && inc->session_id[0] != '\0') {
            ozayn_sess_error_t sr = ozayn_sess_revoke(svc->session, inc->session_id);
            if (sr != OZAYN_SESS_OK && sr != OZAYN_SESS_ERR_NOT_FOUND)
                result = OZAYN_IR_ERR_CONTAINMENT_FAILED;
        }
        break;

    case OZAYN_IR_CONTAIN_SUSPEND_IDENTITY:
        if (svc->identity && inc->identity_id[0] != '\0') {
            ozayn_identity_result_t ir = ozayn_id_suspend(svc->identity, inc->identity_id);
            if (ir != OZAYN_ID_OK && ir != OZAYN_ID_ERR_NOT_FOUND)
                result = OZAYN_IR_ERR_CONTAINMENT_FAILED;
        }
        break;

    case OZAYN_IR_CONTAIN_REVOKE_IDENTITY:
        if (svc->identity && inc->identity_id[0] != '\0') {
            ozayn_identity_result_t ir = ozayn_id_revoke(svc->identity, inc->identity_id);
            if (ir != OZAYN_ID_OK && ir != OZAYN_ID_ERR_NOT_FOUND)
                result = OZAYN_IR_ERR_CONTAINMENT_FAILED;
        }
        break;

    case OZAYN_IR_CONTAIN_ENTER_LOCKDOWN:
        svc->lockdown_active = 1;
        svc->total_lockdowns++;
        break;

    case OZAYN_IR_CONTAIN_REVOKE_KEY:
    case OZAYN_IR_CONTAIN_RESTRICT_RESOURCE:
    case OZAYN_IR_CONTAIN_NONE:
        break;
    }

    if (result == OZAYN_IR_OK) {
        inc->containment_completed = 1;
        inc->state = OZAYN_IR_STATE_CONTAINED;
        inc->last_updated = time(NULL);
        svc->total_containments++;
        _update_compromise_level(svc);
    } else {
        inc->state = OZAYN_IR_STATE_RECOVERY_FAILED;
        inc->last_updated = time(NULL);
    }

    char detail[128];
    snprintf(detail, sizeof(detail), "containment_%s_%s",
             ozayn_ir_containment_action_name(action),
             result == OZAYN_IR_OK ? "succeeded" : "failed");
    _audit_incident(svc, detail, incident_id, result);
    return result;
}

/* ============================================================
 * SECTION 16 — RECOVERY
 * ============================================================ */

ozayn_ir_result_t ozayn_ir_recover(ozayn_ir_service_t *svc,
                                    const char *incident_id)
{
    if (!svc) return OZAYN_IR_ERR_NULL;
    if (!svc->initialized) return OZAYN_IR_ERR_NOT_INITIALIZED;
    if (!incident_id) return OZAYN_IR_ERR_INVALID_ID;

    ozayn_ir_incident_t *inc = _find_incident(svc, incident_id);
    if (!inc) return OZAYN_IR_ERR_NOT_FOUND;
    if (inc->state == OZAYN_IR_STATE_RESOLVED)
        return OZAYN_IR_ERR_ALREADY_RESOLVED;

    if (inc->state != OZAYN_IR_STATE_RECOVERY_REQUIRED &&
        inc->state != OZAYN_IR_STATE_CONTAINED)
        return OZAYN_IR_ERR_STATE_TRANSITION_INVALID;

    inc->state = OZAYN_IR_STATE_RECOVERING;
    inc->last_updated = time(NULL);

    /* Recovery is successful by default in this foundation.
     * Production implementations would verify each component. */
    inc->recovery_completed = 1;
    inc->state = OZAYN_IR_STATE_VERIFIED;
    inc->last_updated = time(NULL);
    svc->total_recoveries++;

    _update_compromise_level(svc);
    _audit_incident(svc, "recovery_completed", incident_id, OZAYN_IR_OK);
    return OZAYN_IR_OK;
}

ozayn_ir_result_t ozayn_ir_verify(ozayn_ir_service_t *svc,
                                   const char *incident_id)
{
    if (!svc) return OZAYN_IR_ERR_NULL;
    if (!svc->initialized) return OZAYN_IR_ERR_NOT_INITIALIZED;
    if (!incident_id) return OZAYN_IR_ERR_INVALID_ID;

    ozayn_ir_incident_t *inc = _find_incident(svc, incident_id);
    if (!inc) return OZAYN_IR_ERR_NOT_FOUND;
    if (inc->state == OZAYN_IR_STATE_RESOLVED)
        return OZAYN_IR_ERR_ALREADY_RESOLVED;

    if (inc->state != OZAYN_IR_STATE_VERIFIED)
        return OZAYN_IR_ERR_STATE_TRANSITION_INVALID;

    /* Verification checks:
     * - If vault is available, verify it's accessible
     * - If key_lifecycle is available, verify active key exists
     * These are basic structural checks. */
    if (svc->vault && !ozayn_vault_is_initialized(svc->vault))
        return OZAYN_IR_ERR_VERIFICATION_FAILED;

    if (svc->key_lifecycle) {
        ozayn_kl_version_t *active_key = NULL;
        ozayn_kl_result_t kr = ozayn_kl_get_active(svc->key_lifecycle, "VAULT", &active_key);
        if (kr != OZAYN_KL_OK || !active_key)
            return OZAYN_IR_ERR_VERIFICATION_FAILED;
    }

    _audit_incident(svc, "recovery_verified", incident_id, OZAYN_IR_OK);
    return OZAYN_IR_OK;
}

ozayn_ir_result_t ozayn_ir_resolve(ozayn_ir_service_t *svc,
                                    const char *incident_id)
{
    if (!svc) return OZAYN_IR_ERR_NULL;
    if (!svc->initialized) return OZAYN_IR_ERR_NOT_INITIALIZED;
    if (!incident_id) return OZAYN_IR_ERR_INVALID_ID;

    ozayn_ir_incident_t *inc = _find_incident(svc, incident_id);
    if (!inc) return OZAYN_IR_ERR_NOT_FOUND;
    if (inc->state == OZAYN_IR_STATE_RESOLVED)
        return OZAYN_IR_ERR_ALREADY_RESOLVED;

    if (inc->state != OZAYN_IR_STATE_VERIFIED)
        return OZAYN_IR_ERR_STATE_TRANSITION_INVALID;

    inc->state = OZAYN_IR_STATE_RESOLVED;
    inc->last_updated = time(NULL);
    svc->total_incidents_resolved++;

    _update_compromise_level(svc);
    _audit_incident(svc, "incident_resolved", incident_id, OZAYN_IR_OK);
    return OZAYN_IR_OK;
}

/* ============================================================
 * SECTION 17 — COMPROMISE LEVEL & LOCKDOWN
 * ============================================================ */

ozayn_ir_compromise_level_t ozayn_ir_get_compromise_level(
    const ozayn_ir_service_t *svc)
{
    if (!svc || !svc->initialized) return OZAYN_IR_COMPROMISE_NORMAL;
    return svc->compromise_level;
}

int ozayn_ir_is_lockdown_active(const ozayn_ir_service_t *svc)
{
    if (!svc || !svc->initialized) return 0;
    return svc->lockdown_active;
}

ozayn_ir_result_t ozayn_ir_enter_lockdown(ozayn_ir_service_t *svc)
{
    if (!svc) return OZAYN_IR_ERR_NULL;
    if (!svc->initialized) return OZAYN_IR_ERR_NOT_INITIALIZED;

    svc->lockdown_active = 1;
    svc->compromise_level = OZAYN_IR_COMPROMISE_LOCKDOWN;
    svc->total_lockdowns++;

    _audit_incident(svc, "lockdown_entered", "SYSTEM", OZAYN_IR_OK);
    return OZAYN_IR_OK;
}

ozayn_ir_result_t ozayn_ir_exit_lockdown(ozayn_ir_service_t *svc)
{
    if (!svc) return OZAYN_IR_ERR_NULL;
    if (!svc->initialized) return OZAYN_IR_ERR_NOT_INITIALIZED;

    if (!svc->lockdown_active)
        return OZAYN_IR_ERR_STATE_INVALID;

    /* Only exit lockdown if no critical/high incidents remain unresolved */
    for (int i = 0; i < svc->incident_count; i++) {
        if (svc->incidents[i].state != OZAYN_IR_STATE_RESOLVED &&
            (svc->incidents[i].severity == OZAYN_IR_SEV_CRITICAL ||
             svc->incidents[i].severity == OZAYN_IR_SEV_HIGH)) {
            return OZAYN_IR_ERR_RECOVERY_UNSAFE;
        }
    }

    svc->lockdown_active = 0;
    _update_compromise_level(svc);

    _audit_incident(svc, "lockdown_exited", "SYSTEM", OZAYN_IR_OK);
    return OZAYN_IR_OK;
}
