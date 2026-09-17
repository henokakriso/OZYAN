#include "operational_alert.h"
#include <string.h>
#include <stdio.h>

static int find_alert_index(const ozayn_oan_service_t *svc, uint64_t id) {
    for (uint64_t i = 0; i < svc->alert_count && i < OZAYN_OAN_MAX_ALERTS; i++) {
        if (svc->alerts[i].active && svc->alerts[i].alert_id == id)
            return (int)i;
    }
    return -1;
}

static int find_rule_index(const ozayn_oan_service_t *svc, uint64_t id) {
    for (uint64_t i = 0; i < svc->rule_count && i < OZAYN_OAN_MAX_RULES; i++) {
        if (svc->rules[i].active && svc->rules[i].rule_id == id)
            return (int)i;
    }
    return -1;
}

static int find_notif_index(const ozayn_oan_service_t *svc, uint64_t id) {
    for (uint64_t i = 0; i < svc->notif_count && i < OZAYN_OAN_MAX_NOTIFICATIONS; i++) {
        if (svc->notifications[i].active && svc->notifications[i].notif_id == id)
            return (int)i;
    }
    return -1;
}

static int find_policy_index(const ozayn_oan_service_t *svc, uint64_t id) {
    for (uint64_t i = 0; i < svc->policy_count && i < OZAYN_OAN_MAX_POLICIES; i++) {
        if (svc->policies[i].active && svc->policies[i].policy_id == id)
            return (int)i;
    }
    return -1;
}

static int find_dedup_index(const ozayn_oan_service_t *svc, uint64_t rule_id, const char *key) {
    for (uint64_t i = 0; i < svc->dedup_count && i < OZAYN_OAN_MAX_DEDUP; i++) {
        if (svc->dedup[i].active && svc->dedup[i].rule_id == rule_id &&
            strcmp(svc->dedup[i].dedup_key, key) == 0)
            return (int)i;
    }
    return -1;
}

static int find_alert_by_correlation_index(const ozayn_oan_service_t *svc, const char *cid) {
    for (uint64_t i = 0; i < svc->alert_count && i < OZAYN_OAN_MAX_ALERTS; i++) {
        if (svc->alerts[i].active && strcmp(svc->alerts[i].correlation_id, cid) == 0)
            return (int)i;
    }
    return -1;
}

/* ============================================================
 * NAME HELPERS
 * ============================================================ */

const char *ozayn_oan_err_name(ozayn_oan_err_t e) {
    switch (e) {
        case OZAYN_OAN_ERR_OK:                      return "OK";
        case OZAYN_OAN_ERR_NULL_PTR:                return "NULL_PTR";
        case OZAYN_OAN_ERR_NOT_INITIALIZED:         return "NOT_INITIALIZED";
        case OZAYN_OAN_ERR_ALREADY_INITIALIZED:     return "ALREADY_INITIALIZED";
        case OZAYN_OAN_ERR_NOT_FOUND:               return "NOT_FOUND";
        case OZAYN_OAN_ERR_FULL:                    return "FULL";
        case OZAYN_OAN_ERR_DUPLICATE:               return "DUPLICATE";
        case OZAYN_OAN_ERR_INVALID_PARAM:           return "INVALID_PARAM";
        case OZAYN_OAN_ERR_INVALID_STATE:           return "INVALID_STATE";
        case OZAYN_OAN_ERR_STATE_TRANSITION:        return "STATE_TRANSITION";
        case OZAYN_OAN_ERR_EXPIRED:                 return "EXPIRED";
        case OZAYN_OAN_ERR_SUPPRESSED:              return "SUPPRESSED";
        case OZAYN_OAN_ERR_RATE_LIMITED:            return "RATE_LIMITED";
        case OZAYN_OAN_ERR_RULE_DISABLED:           return "RULE_DISABLED";
        case OZAYN_OAN_ERR_RULE_EVAL_FAILED:        return "RULE_EVAL_FAILED";
        case OZAYN_OAN_ERR_NOTIFICATION_FULL:       return "NOTIFICATION_FULL";
        case OZAYN_OAN_ERR_NOTIFICATION_FAILED:     return "NOTIFICATION_FAILED";
        case OZAYN_OAN_ERR_NOTIFICATION_UNAVAILABLE: return "NOTIFICATION_UNAVAILABLE";
        case OZAYN_OAN_ERR_NOTIFICATION_RETRY_LIMIT: return "NOTIFICATION_RETRY_LIMIT";
        case OZAYN_OAN_ERR_NOTIFICATION_EXPIRED:    return "NOTIFICATION_EXPIRED";
        case OZAYN_OAN_ERR_AUTH_FAILED:             return "AUTH_FAILED";
        case OZAYN_OAN_ERR_UNAVAILABLE:             return "UNAVAILABLE";
        case OZAYN_OAN_ERR_INTERNAL:                return "INTERNAL";
    }
    return "UNKNOWN";
}

const char *ozayn_oan_category_name(ozayn_oan_category_t c) {
    static const char *names[] = {
        "SYSTEM", "PERFORMANCE", "RESOURCE", "DEVICE", "OPERATION",
        "WORKFLOW", "PIPELINE", "EXECUTION", "FAILURE", "SECURITY",
        "SAFETY", "READINESS", "RECOVERY", "CONFIGURATION", "EVENT",
        "STORAGE", "CAPACITY"
    };
    if (c >= 0 && c < OZAYN_OAN_CAT_COUNT) return names[c];
    return "UNKNOWN";
}

const char *ozayn_oan_severity_name(ozayn_oan_severity_t s) {
    static const char *names[] = { "INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL" };
    if (s >= 0 && s <= OZAYN_OAN_SEV_CRITICAL) return names[s];
    return "UNKNOWN";
}

const char *ozayn_oan_state_name(ozayn_oan_state_t s) {
    static const char *names[] = {
        "CREATED", "ACTIVE", "ACKNOWLEDGED", "SUPPRESSED",
        "RESOLVED", "EXPIRED", "CANCELLED", "CLOSED"
    };
    if (s >= 0 && s <= OZAYN_OAN_STATE_CLOSED) return names[s];
    return "UNKNOWN";
}

const char *ozayn_oan_source_name(ozayn_oan_source_t s) {
    static const char *names[] = {
        "EVENT_ENGINE", "TIMELINE", "METRICS", "DIAGNOSTICS",
        "HEALTH", "FAILURE", "RESOURCE", "DEVICE", "READINESS",
        "MODE", "OPERATION", "WORKFLOW", "PIPELINE", "MANUAL"
    };
    if (s >= 0 && s < OZAYN_OAN_SRC_COUNT) return names[s];
    return "UNKNOWN";
}

const char *ozayn_oan_trigger_name(ozayn_oan_trigger_type_t t) {
    static const char *names[] = {
        "EVENT", "METRIC_THRESHOLD", "FAILURE", "HEALTH_CHANGE",
        "RESOURCE_THRESHOLD", "DEVICE_STATE", "READINESS_CHANGE",
        "MODE_CHANGE", "OPERATION_FAILURE", "WORKFLOW_FAILURE",
        "PIPELINE_FAILURE", "RECOVERY_FAILURE", "CONFIG_CHANGE"
    };
    if (t >= 0 && t < OZAYN_OAN_TRIGGER_COUNT) return names[t];
    return "UNKNOWN";
}

const char *ozayn_oan_channel_name(ozayn_oan_channel_t c) {
    static const char *names[] = {
        "INTERNAL_EVENT", "LOCAL_LOG", "SYSTEM_NOTIFICATION",
        "EMAIL", "WEBHOOK", "FUTURE"
    };
    if (c >= 0 && c < OZAYN_OAN_CHAN_COUNT) return names[c];
    return "UNKNOWN";
}

const char *ozayn_oan_nstate_name(ozayn_oan_nstate_t s) {
    static const char *names[] = {
        "CREATED", "QUEUED", "SENDING", "SENT", "DELIVERED",
        "FAILED", "CANCELLED", "EXPIRED", "RETRYING"
    };
    if (s >= 0 && s <= OZAYN_OAN_NSTATE_RETRYING) return names[s];
    return "UNKNOWN";
}

/* ============================================================
 * STATE VALIDATION
 * ============================================================ */

int ozayn_oan_state_transition_valid(ozayn_oan_state_t from, ozayn_oan_state_t to) {
    switch (from) {
        case OZAYN_OAN_STATE_CREATED:
            return to == OZAYN_OAN_STATE_ACTIVE || to == OZAYN_OAN_STATE_CANCELLED ||
                   to == OZAYN_OAN_STATE_EXPIRED;
        case OZAYN_OAN_STATE_ACTIVE:
            return to == OZAYN_OAN_STATE_ACKNOWLEDGED || to == OZAYN_OAN_STATE_SUPPRESSED ||
                   to == OZAYN_OAN_STATE_RESOLVED || to == OZAYN_OAN_STATE_EXPIRED ||
                   to == OZAYN_OAN_STATE_CANCELLED || to == OZAYN_OAN_STATE_CLOSED;
        case OZAYN_OAN_STATE_ACKNOWLEDGED:
            return to == OZAYN_OAN_STATE_ACTIVE || to == OZAYN_OAN_STATE_RESOLVED ||
                   to == OZAYN_OAN_STATE_EXPIRED || to == OZAYN_OAN_STATE_CANCELLED ||
                   to == OZAYN_OAN_STATE_CLOSED;
        case OZAYN_OAN_STATE_SUPPRESSED:
            return to == OZAYN_OAN_STATE_ACTIVE || to == OZAYN_OAN_STATE_RESOLVED ||
                   to == OZAYN_OAN_STATE_EXPIRED || to == OZAYN_OAN_STATE_CANCELLED;
        case OZAYN_OAN_STATE_RESOLVED:
            return to == OZAYN_OAN_STATE_CLOSED;
        case OZAYN_OAN_STATE_EXPIRED:
            return to == OZAYN_OAN_STATE_CLOSED;
        case OZAYN_OAN_STATE_CANCELLED:
            return to == OZAYN_OAN_STATE_CLOSED;
        case OZAYN_OAN_STATE_CLOSED:
            return 0;
    }
    return 0;
}

int ozayn_oan_nstate_transition_valid(ozayn_oan_nstate_t from, ozayn_oan_nstate_t to) {
    switch (from) {
        case OZAYN_OAN_NSTATE_CREATED:
            return to == OZAYN_OAN_NSTATE_QUEUED || to == OZAYN_OAN_NSTATE_CANCELLED ||
                   to == OZAYN_OAN_NSTATE_EXPIRED;
        case OZAYN_OAN_NSTATE_QUEUED:
            return to == OZAYN_OAN_NSTATE_SENDING || to == OZAYN_OAN_NSTATE_CANCELLED ||
                   to == OZAYN_OAN_NSTATE_EXPIRED;
        case OZAYN_OAN_NSTATE_SENDING:
            return to == OZAYN_OAN_NSTATE_SENT || to == OZAYN_OAN_NSTATE_FAILED ||
                   to == OZAYN_OAN_NSTATE_CANCELLED;
        case OZAYN_OAN_NSTATE_SENT:
            return to == OZAYN_OAN_NSTATE_DELIVERED || to == OZAYN_OAN_NSTATE_FAILED;
        case OZAYN_OAN_NSTATE_DELIVERED:
            return 0;
        case OZAYN_OAN_NSTATE_FAILED:
            return to == OZAYN_OAN_NSTATE_RETRYING || to == OZAYN_OAN_NSTATE_CANCELLED ||
                   to == OZAYN_OAN_NSTATE_EXPIRED;
        case OZAYN_OAN_NSTATE_CANCELLED:
            return 0;
        case OZAYN_OAN_NSTATE_EXPIRED:
            return 0;
        case OZAYN_OAN_NSTATE_RETRYING:
            return to == OZAYN_OAN_NSTATE_QUEUED || to == OZAYN_OAN_NSTATE_CANCELLED ||
                   to == OZAYN_OAN_NSTATE_EXPIRED;
    }
    return 0;
}

/* ============================================================
 * LIFECYCLE
 * ============================================================ */

int ozayn_oan_init(ozayn_oan_service_t *svc) {
    if (!svc) return OZAYN_OAN_ERR_NULL_PTR;
    if (svc->initialized) return OZAYN_OAN_ERR_ALREADY_INITIALIZED;
    memset(svc, 0, sizeof(*svc));
    svc->initialized = 1;
    svc->alerts_per_window = 100;
    svc->notifs_per_window = 50;
    return OZAYN_OAN_ERR_OK;
}

int ozayn_oan_shutdown(ozayn_oan_service_t *svc) {
    if (!svc) return OZAYN_OAN_ERR_NULL_PTR;
    if (!svc->initialized) return OZAYN_OAN_ERR_NOT_INITIALIZED;
    for (uint64_t i = 0; i < svc->notif_count && i < OZAYN_OAN_MAX_NOTIFICATIONS; i++) {
        if (svc->notifications[i].active &&
            (svc->notifications[i].state == OZAYN_OAN_NSTATE_QUEUED ||
             svc->notifications[i].state == OZAYN_OAN_NSTATE_SENDING ||
             svc->notifications[i].state == OZAYN_OAN_NSTATE_RETRYING)) {
            svc->notifications[i].state = OZAYN_OAN_NSTATE_CANCELLED;
        }
    }
    svc->initialized = 0;
    return OZAYN_OAN_ERR_OK;
}

int ozayn_oan_is_initialized(const ozayn_oan_service_t *svc) {
    if (!svc) return 0;
    return svc->initialized;
}

int ozayn_oan_bind_subsystems(ozayn_oan_service_t *svc, const ozayn_oan_subsys_bind_t *bind) {
    if (!svc || !bind) return OZAYN_OAN_ERR_NULL_PTR;
    if (!svc->initialized) return OZAYN_OAN_ERR_NOT_INITIALIZED;
    svc->bind = *bind;
    return OZAYN_OAN_ERR_OK;
}

/* ============================================================
 * ALERT RULES
 * ============================================================ */

int ozayn_oan_rule_create(ozayn_oan_service_t *svc,
                          const char *name,
                          const char *description,
                          ozayn_oan_trigger_type_t trigger_type,
                          ozayn_oan_category_t category,
                          ozayn_oan_severity_t severity,
                          const char *source_ref,
                          int64_t warning_threshold,
                          int64_t critical_threshold,
                          uint64_t cooldown_seconds,
                          uint64_t expiration_seconds,
                          uint64_t dedup_window_seconds,
                          uint64_t *out_rule_id) {
    if (!svc || !name || !out_rule_id) return OZAYN_OAN_ERR_NULL_PTR;
    if (!svc->initialized) return OZAYN_OAN_ERR_NOT_INITIALIZED;
    if (svc->rule_count >= OZAYN_OAN_MAX_RULES) return OZAYN_OAN_ERR_FULL;
    if (trigger_type < 0 || trigger_type >= OZAYN_OAN_TRIGGER_COUNT) return OZAYN_OAN_ERR_INVALID_PARAM;
    if (category < 0 || category >= OZAYN_OAN_CAT_COUNT) return OZAYN_OAN_ERR_INVALID_PARAM;
    if (severity < 0 || severity > OZAYN_OAN_SEV_CRITICAL) return OZAYN_OAN_ERR_INVALID_PARAM;

    ozayn_oan_rule_t *r = &svc->rules[svc->rule_count];
    memset(r, 0, sizeof(*r));
    r->rule_id = ++svc->sequence;
    strncpy(r->name, name, OZAYN_OAN_MAX_RULE_NAME - 1);
    if (description) strncpy(r->description, description, OZAYN_OAN_MAX_RULE_DESC - 1);
    r->trigger_type = trigger_type;
    r->category = category;
    r->severity = severity;
    if (source_ref) strncpy(r->source_ref, source_ref, OZAYN_OAN_MAX_ALERT_ID_LEN - 1);
    r->warning_threshold = warning_threshold;
    r->critical_threshold = critical_threshold;
    r->cooldown_seconds = cooldown_seconds;
    r->expiration_seconds = expiration_seconds;
    r->dedup_window_seconds = dedup_window_seconds;
    r->max_active_alerts = 16;
    r->enabled = 1;
    r->active = 1;
    *out_rule_id = r->rule_id;
    svc->rule_count++;
    svc->stats.current_rules++;
    return OZAYN_OAN_ERR_OK;
}

int ozayn_oan_rule_enable(ozayn_oan_service_t *svc, uint64_t rule_id) {
    if (!svc) return OZAYN_OAN_ERR_NULL_PTR;
    if (!svc->initialized) return OZAYN_OAN_ERR_NOT_INITIALIZED;
    int idx = find_rule_index(svc, rule_id);
    if (idx < 0) return OZAYN_OAN_ERR_NOT_FOUND;
    svc->rules[idx].enabled = 1;
    return OZAYN_OAN_ERR_OK;
}

int ozayn_oan_rule_disable(ozayn_oan_service_t *svc, uint64_t rule_id) {
    if (!svc) return OZAYN_OAN_ERR_NULL_PTR;
    if (!svc->initialized) return OZAYN_OAN_ERR_NOT_INITIALIZED;
    int idx = find_rule_index(svc, rule_id);
    if (idx < 0) return OZAYN_OAN_ERR_NOT_FOUND;
    svc->rules[idx].enabled = 0;
    return OZAYN_OAN_ERR_OK;
}

int ozayn_oan_rule_remove(ozayn_oan_service_t *svc, uint64_t rule_id) {
    if (!svc) return OZAYN_OAN_ERR_NULL_PTR;
    if (!svc->initialized) return OZAYN_OAN_ERR_NOT_INITIALIZED;
    int idx = find_rule_index(svc, rule_id);
    if (idx < 0) return OZAYN_OAN_ERR_NOT_FOUND;
    svc->rules[idx].active = 0;
    svc->stats.current_rules--;
    return OZAYN_OAN_ERR_OK;
}

int ozayn_oan_rule_get(const ozayn_oan_service_t *svc,
                       uint64_t rule_id,
                       const ozayn_oan_rule_t **out_rule) {
    if (!svc || !out_rule) return OZAYN_OAN_ERR_NULL_PTR;
    if (!svc->initialized) return OZAYN_OAN_ERR_NOT_INITIALIZED;
    int idx = find_rule_index(svc, rule_id);
    if (idx < 0) return OZAYN_OAN_ERR_NOT_FOUND;
    *out_rule = &svc->rules[idx];
    return OZAYN_OAN_ERR_OK;
}

int ozayn_oan_rule_evaluate(ozayn_oan_service_t *svc, uint64_t rule_id,
                            int64_t current_value,
                            ozayn_oan_severity_t *out_severity) {
    if (!svc || !out_severity) return OZAYN_OAN_ERR_NULL_PTR;
    if (!svc->initialized) return OZAYN_OAN_ERR_NOT_INITIALIZED;
    int idx = find_rule_index(svc, rule_id);
    if (idx < 0) return OZAYN_OAN_ERR_NOT_FOUND;
    ozayn_oan_rule_t *r = &svc->rules[idx];
    if (!r->enabled) return OZAYN_OAN_ERR_RULE_DISABLED;
    svc->stats.total_rules_evaluated++;

    time_t now = time(0);
    if (r->cooldown_seconds > 0 && r->last_triggered_time > 0) {
        if ((uint64_t)(now - r->last_triggered_time) < r->cooldown_seconds) {
            *out_severity = OZAYN_OAN_SEV_INFO;
            return OZAYN_OAN_ERR_OK;
        }
    }

    if (current_value >= r->critical_threshold && r->critical_threshold > 0) {
        *out_severity = OZAYN_OAN_SEV_CRITICAL;
    } else if (current_value >= r->warning_threshold && r->warning_threshold > 0) {
        *out_severity = r->severity;
    } else {
        *out_severity = OZAYN_OAN_SEV_INFO;
    }
    return OZAYN_OAN_ERR_OK;
}

int ozayn_oan_rule_evaluate_all(ozayn_oan_service_t *svc) {
    if (!svc) return OZAYN_OAN_ERR_NULL_PTR;
    if (!svc->initialized) return OZAYN_OAN_ERR_NOT_INITIALIZED;
    for (uint64_t i = 0; i < svc->rule_count && i < OZAYN_OAN_MAX_RULES; i++) {
        if (svc->rules[i].active && svc->rules[i].enabled) {
            svc->stats.total_rules_evaluated++;
        }
    }
    return OZAYN_OAN_ERR_OK;
}

/* ============================================================
 * ALERT LIFECYCLE
 * ============================================================ */

int ozayn_oan_alert_create(ozayn_oan_service_t *svc,
                           ozayn_oan_category_t category,
                           ozayn_oan_severity_t severity,
                           ozayn_oan_source_t source,
                           ozayn_oan_trigger_type_t trigger_type,
                           const char *title,
                           const char *description,
                           const char *source_component,
                           const char *correlation_id,
                           uint64_t rule_id,
                           int64_t trigger_value,
                           int64_t threshold_value,
                           uint64_t *out_alert_id) {
    if (!svc || !title || !out_alert_id) return OZAYN_OAN_ERR_NULL_PTR;
    if (!svc->initialized) return OZAYN_OAN_ERR_NOT_INITIALIZED;
    if (svc->alert_count >= OZAYN_OAN_MAX_ALERTS) return OZAYN_OAN_ERR_FULL;
    if (category < 0 || category >= OZAYN_OAN_CAT_COUNT) return OZAYN_OAN_ERR_INVALID_PARAM;
    if (severity < 0 || severity > OZAYN_OAN_SEV_CRITICAL) return OZAYN_OAN_ERR_INVALID_PARAM;
    if (source < 0 || source >= OZAYN_OAN_SRC_COUNT) return OZAYN_OAN_ERR_INVALID_PARAM;

    if (correlation_id && correlation_id[0] != '\0') {
        int existing = find_alert_by_correlation_index(svc, correlation_id);
        if (existing >= 0) {
            *out_alert_id = svc->alerts[existing].alert_id;
            return OZAYN_OAN_ERR_DUPLICATE;
        }
    }

    ozayn_oan_alert_t *a = &svc->alerts[svc->alert_count];
    memset(a, 0, sizeof(*a));
    a->alert_id = ++svc->sequence;
    a->version = 1;
    a->category = category;
    a->severity = severity;
    a->state = OZAYN_OAN_STATE_CREATED;
    a->source = source;
    a->trigger_type = trigger_type;
    strncpy(a->title, title, OZAYN_OAN_MAX_ALERT_TITLE - 1);
    if (description) strncpy(a->description, description, OZAYN_OAN_MAX_ALERT_DESC - 1);
    if (source_component) strncpy(a->source_component, source_component, OZAYN_OAN_MAX_ALERT_SOURCE - 1);
    if (correlation_id) strncpy(a->correlation_id, correlation_id, OZAYN_OAN_MAX_CORRELATION_LEN - 1);
    a->rule_id = rule_id;
    a->trigger_value = trigger_value;
    a->threshold_value = threshold_value;
    a->created_time = time(0);
    a->updated_time = a->created_time;
    a->expiration_time = 0;
    a->resolution_time = 0;
    a->active = 1;
    *out_alert_id = a->alert_id;
    svc->alert_count++;
    svc->stats.total_alerts_created++;
    svc->stats.current_active_alerts++;
    return OZAYN_OAN_ERR_OK;
}

int ozayn_oan_alert_activate(ozayn_oan_service_t *svc, uint64_t alert_id) {
    if (!svc) return OZAYN_OAN_ERR_NULL_PTR;
    if (!svc->initialized) return OZAYN_OAN_ERR_NOT_INITIALIZED;
    int idx = find_alert_index(svc, alert_id);
    if (idx < 0) return OZAYN_OAN_ERR_NOT_FOUND;
    ozayn_oan_alert_t *a = &svc->alerts[idx];
    if (!ozayn_oan_state_transition_valid(a->state, OZAYN_OAN_STATE_ACTIVE))
        return OZAYN_OAN_ERR_STATE_TRANSITION;
    a->state = OZAYN_OAN_STATE_ACTIVE;
    a->updated_time = time(0);
    svc->stats.total_alerts_activated++;
    return OZAYN_OAN_ERR_OK;
}

int ozayn_oan_alert_acknowledge(ozayn_oan_service_t *svc, uint64_t alert_id,
                                const char *identity, const char *reason) {
    if (!svc) return OZAYN_OAN_ERR_NULL_PTR;
    if (!svc->initialized) return OZAYN_OAN_ERR_NOT_INITIALIZED;
    int idx = find_alert_index(svc, alert_id);
    if (idx < 0) return OZAYN_OAN_ERR_NOT_FOUND;
    ozayn_oan_alert_t *a = &svc->alerts[idx];
    if (!ozayn_oan_state_transition_valid(a->state, OZAYN_OAN_STATE_ACKNOWLEDGED))
        return OZAYN_OAN_ERR_STATE_TRANSITION;
    a->state = OZAYN_OAN_STATE_ACKNOWLEDGED;
    a->updated_time = time(0);
    a->ack_count++;
    svc->stats.total_alerts_acknowledged++;
    (void)identity;
    (void)reason;
    return OZAYN_OAN_ERR_OK;
}

int ozayn_oan_alert_suppress(ozayn_oan_service_t *svc, uint64_t alert_id) {
    if (!svc) return OZAYN_OAN_ERR_NULL_PTR;
    if (!svc->initialized) return OZAYN_OAN_ERR_NOT_INITIALIZED;
    int idx = find_alert_index(svc, alert_id);
    if (idx < 0) return OZAYN_OAN_ERR_NOT_FOUND;
    ozayn_oan_alert_t *a = &svc->alerts[idx];
    if (!ozayn_oan_state_transition_valid(a->state, OZAYN_OAN_STATE_SUPPRESSED))
        return OZAYN_OAN_ERR_STATE_TRANSITION;
    a->state = OZAYN_OAN_STATE_SUPPRESSED;
    a->updated_time = time(0);
    svc->stats.total_alerts_suppressed++;
    return OZAYN_OAN_ERR_OK;
}

int ozayn_oan_alert_resolve(ozayn_oan_service_t *svc, uint64_t alert_id) {
    if (!svc) return OZAYN_OAN_ERR_NULL_PTR;
    if (!svc->initialized) return OZAYN_OAN_ERR_NOT_INITIALIZED;
    int idx = find_alert_index(svc, alert_id);
    if (idx < 0) return OZAYN_OAN_ERR_NOT_FOUND;
    ozayn_oan_alert_t *a = &svc->alerts[idx];
    if (!ozayn_oan_state_transition_valid(a->state, OZAYN_OAN_STATE_RESOLVED))
        return OZAYN_OAN_ERR_STATE_TRANSITION;
    a->state = OZAYN_OAN_STATE_RESOLVED;
    a->resolution_time = time(0);
    a->updated_time = a->resolution_time;
    svc->stats.total_alerts_resolved++;
    if (svc->stats.current_active_alerts > 0) svc->stats.current_active_alerts--;
    return OZAYN_OAN_ERR_OK;
}

int ozayn_oan_alert_cancel(ozayn_oan_service_t *svc, uint64_t alert_id) {
    if (!svc) return OZAYN_OAN_ERR_NULL_PTR;
    if (!svc->initialized) return OZAYN_OAN_ERR_NOT_INITIALIZED;
    int idx = find_alert_index(svc, alert_id);
    if (idx < 0) return OZAYN_OAN_ERR_NOT_FOUND;
    ozayn_oan_alert_t *a = &svc->alerts[idx];
    if (!ozayn_oan_state_transition_valid(a->state, OZAYN_OAN_STATE_CANCELLED))
        return OZAYN_OAN_ERR_STATE_TRANSITION;
    a->state = OZAYN_OAN_STATE_CANCELLED;
    a->updated_time = time(0);
    svc->stats.total_alerts_cancelled++;
    if (svc->stats.current_active_alerts > 0) svc->stats.current_active_alerts--;
    return OZAYN_OAN_ERR_OK;
}

int ozayn_oan_alert_close(ozayn_oan_service_t *svc, uint64_t alert_id) {
    if (!svc) return OZAYN_OAN_ERR_NULL_PTR;
    if (!svc->initialized) return OZAYN_OAN_ERR_NOT_INITIALIZED;
    int idx = find_alert_index(svc, alert_id);
    if (idx < 0) return OZAYN_OAN_ERR_NOT_FOUND;
    ozayn_oan_alert_t *a = &svc->alerts[idx];
    if (!ozayn_oan_state_transition_valid(a->state, OZAYN_OAN_STATE_CLOSED))
        return OZAYN_OAN_ERR_STATE_TRANSITION;
    a->state = OZAYN_OAN_STATE_CLOSED;
    a->updated_time = time(0);
    return OZAYN_OAN_ERR_OK;
}

int ozayn_oan_alert_expire(ozayn_oan_service_t *svc, uint64_t alert_id) {
    if (!svc) return OZAYN_OAN_ERR_NULL_PTR;
    if (!svc->initialized) return OZAYN_OAN_ERR_NOT_INITIALIZED;
    int idx = find_alert_index(svc, alert_id);
    if (idx < 0) return OZAYN_OAN_ERR_NOT_FOUND;
    ozayn_oan_alert_t *a = &svc->alerts[idx];
    if (!ozayn_oan_state_transition_valid(a->state, OZAYN_OAN_STATE_EXPIRED))
        return OZAYN_OAN_ERR_STATE_TRANSITION;
    a->state = OZAYN_OAN_STATE_EXPIRED;
    a->updated_time = time(0);
    svc->stats.total_alerts_expired++;
    if (svc->stats.current_active_alerts > 0) svc->stats.current_active_alerts--;
    return OZAYN_OAN_ERR_OK;
}

int ozayn_oan_alert_set_refs(ozayn_oan_service_t *svc, uint64_t alert_id,
                             const char *event_ref,
                             const char *metric_ref,
                             const char *operation_ref,
                             const char *workflow_ref,
                             const char *pipeline_ref,
                             const char *resource_ref,
                             const char *device_ref,
                             const char *failure_ref) {
    if (!svc) return OZAYN_OAN_ERR_NULL_PTR;
    if (!svc->initialized) return OZAYN_OAN_ERR_NOT_INITIALIZED;
    int idx = find_alert_index(svc, alert_id);
    if (idx < 0) return OZAYN_OAN_ERR_NOT_FOUND;
    ozayn_oan_alert_t *a = &svc->alerts[idx];
    if (event_ref) strncpy(a->event_ref, event_ref, OZAYN_OAN_MAX_ALERT_ID_LEN - 1);
    if (metric_ref) strncpy(a->metric_ref, metric_ref, OZAYN_OAN_MAX_ALERT_ID_LEN - 1);
    if (operation_ref) strncpy(a->operation_ref, operation_ref, OZAYN_OAN_MAX_ALERT_ID_LEN - 1);
    if (workflow_ref) strncpy(a->workflow_ref, workflow_ref, OZAYN_OAN_MAX_ALERT_ID_LEN - 1);
    if (pipeline_ref) strncpy(a->pipeline_ref, pipeline_ref, OZAYN_OAN_MAX_ALERT_ID_LEN - 1);
    if (resource_ref) strncpy(a->resource_ref, resource_ref, OZAYN_OAN_MAX_ALERT_ID_LEN - 1);
    if (device_ref) strncpy(a->device_ref, device_ref, OZAYN_OAN_MAX_ALERT_ID_LEN - 1);
    if (failure_ref) strncpy(a->failure_ref, failure_ref, OZAYN_OAN_MAX_ALERT_ID_LEN - 1);
    a->updated_time = time(0);
    return OZAYN_OAN_ERR_OK;
}

int ozayn_oan_alert_set_group_key(ozayn_oan_service_t *svc, uint64_t alert_id,
                                  const char *group_key) {
    if (!svc || !group_key) return OZAYN_OAN_ERR_NULL_PTR;
    if (!svc->initialized) return OZAYN_OAN_ERR_NOT_INITIALIZED;
    int idx = find_alert_index(svc, alert_id);
    if (idx < 0) return OZAYN_OAN_ERR_NOT_FOUND;
    ozayn_oan_alert_t *a = &svc->alerts[idx];
    strncpy(a->group_key, group_key, OZAYN_OAN_MAX_GROUP_KEY - 1);
    return OZAYN_OAN_ERR_OK;
}

/* ============================================================
 * ALERT QUERIES
 * ============================================================ */

int ozayn_oan_alert_get(const ozayn_oan_service_t *svc,
                        uint64_t alert_id,
                        const ozayn_oan_alert_t **out_alert) {
    if (!svc || !out_alert) return OZAYN_OAN_ERR_NULL_PTR;
    if (!svc->initialized) return OZAYN_OAN_ERR_NOT_INITIALIZED;
    int idx = find_alert_index(svc, alert_id);
    if (idx < 0) return OZAYN_OAN_ERR_NOT_FOUND;
    *out_alert = &svc->alerts[idx];
    return OZAYN_OAN_ERR_OK;
}

int ozayn_oan_alert_get_by_correlation(const ozayn_oan_service_t *svc,
                                       const char *correlation_id,
                                       const ozayn_oan_alert_t **out_alert) {
    if (!svc || !correlation_id || !out_alert) return OZAYN_OAN_ERR_NULL_PTR;
    if (!svc->initialized) return OZAYN_OAN_ERR_NOT_INITIALIZED;
    int idx = find_alert_by_correlation_index(svc, correlation_id);
    if (idx < 0) return OZAYN_OAN_ERR_NOT_FOUND;
    *out_alert = &svc->alerts[idx];
    return OZAYN_OAN_ERR_OK;
}

int ozayn_oan_alert_list_active(const ozayn_oan_service_t *svc,
                                const ozayn_oan_alert_t **out_alerts,
                                uint32_t max_results,
                                uint32_t *out_count) {
    if (!svc || !out_alerts || !out_count) return OZAYN_OAN_ERR_NULL_PTR;
    if (!svc->initialized) return OZAYN_OAN_ERR_NOT_INITIALIZED;
    uint32_t cnt = 0;
    for (uint64_t i = 0; i < svc->alert_count && i < OZAYN_OAN_MAX_ALERTS && cnt < max_results; i++) {
        if (svc->alerts[i].active && svc->alerts[i].state == OZAYN_OAN_STATE_ACTIVE)
            out_alerts[cnt++] = &svc->alerts[i];
    }
    *out_count = cnt;
    return OZAYN_OAN_ERR_OK;
}

int ozayn_oan_alert_list_by_severity(const ozayn_oan_service_t *svc,
                                     ozayn_oan_severity_t severity,
                                     const ozayn_oan_alert_t **out_alerts,
                                     uint32_t max_results,
                                     uint32_t *out_count) {
    if (!svc || !out_alerts || !out_count) return OZAYN_OAN_ERR_NULL_PTR;
    if (!svc->initialized) return OZAYN_OAN_ERR_NOT_INITIALIZED;
    uint32_t cnt = 0;
    for (uint64_t i = 0; i < svc->alert_count && i < OZAYN_OAN_MAX_ALERTS && cnt < max_results; i++) {
        if (svc->alerts[i].active && svc->alerts[i].severity == severity)
            out_alerts[cnt++] = &svc->alerts[i];
    }
    *out_count = cnt;
    return OZAYN_OAN_ERR_OK;
}

int ozayn_oan_alert_list_by_category(const ozayn_oan_service_t *svc,
                                     ozayn_oan_category_t category,
                                     const ozayn_oan_alert_t **out_alerts,
                                     uint32_t max_results,
                                     uint32_t *out_count) {
    if (!svc || !out_alerts || !out_count) return OZAYN_OAN_ERR_NULL_PTR;
    if (!svc->initialized) return OZAYN_OAN_ERR_NOT_INITIALIZED;
    uint32_t cnt = 0;
    for (uint64_t i = 0; i < svc->alert_count && i < OZAYN_OAN_MAX_ALERTS && cnt < max_results; i++) {
        if (svc->alerts[i].active && svc->alerts[i].category == category)
            out_alerts[cnt++] = &svc->alerts[i];
    }
    *out_count = cnt;
    return OZAYN_OAN_ERR_OK;
}

int ozayn_oan_alert_list_by_source(const ozayn_oan_service_t *svc,
                                   ozayn_oan_source_t source,
                                   const ozayn_oan_alert_t **out_alerts,
                                   uint32_t max_results,
                                   uint32_t *out_count) {
    if (!svc || !out_alerts || !out_count) return OZAYN_OAN_ERR_NULL_PTR;
    if (!svc->initialized) return OZAYN_OAN_ERR_NOT_INITIALIZED;
    uint32_t cnt = 0;
    for (uint64_t i = 0; i < svc->alert_count && i < OZAYN_OAN_MAX_ALERTS && cnt < max_results; i++) {
        if (svc->alerts[i].active && svc->alerts[i].source == source)
            out_alerts[cnt++] = &svc->alerts[i];
    }
    *out_count = cnt;
    return OZAYN_OAN_ERR_OK;
}

int64_t ozayn_oan_alert_active_count(const ozayn_oan_service_t *svc) {
    if (!svc || !svc->initialized) return -1;
    return (int64_t)svc->stats.current_active_alerts;
}

int64_t ozayn_oan_alert_total_count(const ozayn_oan_service_t *svc) {
    if (!svc || !svc->initialized) return -1;
    return (int64_t)svc->alert_count;
}

/* ============================================================
 * ALERT SUMMARY
 * ============================================================ */

int ozayn_oan_summary(const ozayn_oan_service_t *svc, ozayn_oan_summary_t *out_summary) {
    if (!svc || !out_summary) return OZAYN_OAN_ERR_NULL_PTR;
    if (!svc->initialized) return OZAYN_OAN_ERR_NOT_INITIALIZED;
    memset(out_summary, 0, sizeof(*out_summary));
    for (uint64_t i = 0; i < svc->alert_count && i < OZAYN_OAN_MAX_ALERTS; i++) {
        if (!svc->alerts[i].active) continue;
        ozayn_oan_alert_t *a = (ozayn_oan_alert_t *)&svc->alerts[i];
        if (a->state == OZAYN_OAN_STATE_ACTIVE || a->state == OZAYN_OAN_STATE_ACKNOWLEDGED ||
            a->state == OZAYN_OAN_STATE_SUPPRESSED) {
            out_summary->total_active++;
            switch (a->severity) {
                case OZAYN_OAN_SEV_CRITICAL: out_summary->critical_count++; break;
                case OZAYN_OAN_SEV_HIGH:     out_summary->high_count++; break;
                case OZAYN_OAN_SEV_MEDIUM:   out_summary->medium_count++; break;
                case OZAYN_OAN_SEV_LOW:      out_summary->low_count++; break;
                case OZAYN_OAN_SEV_INFO:     out_summary->info_count++; break;
            }
            if (a->state == OZAYN_OAN_STATE_ACKNOWLEDGED) out_summary->acknowledged_count++;
            if (a->state == OZAYN_OAN_STATE_SUPPRESSED) out_summary->suppressed_count++;
        }
        if (a->state == OZAYN_OAN_STATE_RESOLVED) out_summary->recently_resolved_count++;
    }
    out_summary->notification_failures = (uint32_t)svc->stats.total_notifications_failed;
    out_summary->active_count = out_summary->total_active;
    return OZAYN_OAN_ERR_OK;
}

/* ============================================================
 * DEDUP
 * ============================================================ */

int ozayn_oan_dedup_check(const ozayn_oan_service_t *svc,
                          uint64_t rule_id,
                          const char *group_key) {
    if (!svc || !group_key) return 0;
    if (!svc->initialized) return 0;
    int idx = find_dedup_index(svc, rule_id, group_key);
    if (idx < 0) return 0;
    const ozayn_oan_dedup_t *d = &svc->dedup[idx];
    if (!d->active) return 0;
    time_t now = time(0);
    ozayn_oan_rule_t *rule = 0;
    int ridx = find_rule_index(svc, rule_id);
    if (ridx >= 0) rule = (ozayn_oan_rule_t *)&svc->rules[ridx];
    uint64_t window = rule ? rule->dedup_window_seconds : 60;
    if (window > 0 && (uint64_t)(now - d->last_time) > window) return 0;
    return 1;
}

int ozayn_oan_dedup_register(ozayn_oan_service_t *svc,
                             uint64_t rule_id,
                             const char *group_key,
                             uint64_t alert_id) {
    if (!svc || !group_key) return OZAYN_OAN_ERR_NULL_PTR;
    if (!svc->initialized) return OZAYN_OAN_ERR_NOT_INITIALIZED;
    if (svc->dedup_count >= OZAYN_OAN_MAX_DEDUP) {
        for (uint64_t i = 0; i < svc->dedup_count && i < OZAYN_OAN_MAX_DEDUP; i++) {
            if (!svc->dedup[i].active) {
                svc->dedup_count = i;
                break;
            }
        }
        if (svc->dedup_count >= OZAYN_OAN_MAX_DEDUP) return OZAYN_OAN_ERR_FULL;
    }
    int idx = find_dedup_index(svc, rule_id, group_key);
    if (idx >= 0) {
        svc->dedup[idx].last_alert_id = alert_id;
        svc->dedup[idx].count++;
        svc->dedup[idx].last_time = time(0);
        svc->stats.total_duplicates_detected++;
        return OZAYN_OAN_ERR_OK;
    }
    ozayn_oan_dedup_t *d = &svc->dedup[svc->dedup_count];
    memset(d, 0, sizeof(*d));
    strncpy(d->dedup_key, group_key, OZAYN_OAN_MAX_GROUP_KEY - 1);
    d->rule_id = rule_id;
    d->last_alert_id = alert_id;
    d->count = 1;
    d->first_time = time(0);
    d->last_time = d->first_time;
    d->active = 1;
    svc->dedup_count++;
    return OZAYN_OAN_ERR_OK;
}

int ozayn_oan_dedup_cleanup(ozayn_oan_service_t *svc, uint64_t window_seconds) {
    if (!svc) return OZAYN_OAN_ERR_NULL_PTR;
    if (!svc->initialized) return OZAYN_OAN_ERR_NOT_INITIALIZED;
    time_t now = time(0);
    for (uint64_t i = 0; i < svc->dedup_count && i < OZAYN_OAN_MAX_DEDUP; i++) {
        if (svc->dedup[i].active && window_seconds > 0 &&
            (uint64_t)(now - svc->dedup[i].last_time) > window_seconds) {
            svc->dedup[i].active = 0;
        }
    }
    return OZAYN_OAN_ERR_OK;
}

/* ============================================================
 * NOTIFICATIONS
 * ============================================================ */

int ozayn_oan_notif_create(ozayn_oan_service_t *svc,
                           uint64_t alert_id,
                           const char *recipient,
                           ozayn_oan_channel_t channel,
                           ozayn_oan_severity_t priority,
                           const char *title,
                           const char *body,
                           uint64_t *out_notif_id) {
    if (!svc || !recipient || !out_notif_id) return OZAYN_OAN_ERR_NULL_PTR;
    if (!svc->initialized) return OZAYN_OAN_ERR_NOT_INITIALIZED;
    if (svc->notif_count >= OZAYN_OAN_MAX_NOTIFICATIONS) return OZAYN_OAN_ERR_NOTIFICATION_FULL;
    if (channel < 0 || channel >= OZAYN_OAN_CHAN_COUNT) return OZAYN_OAN_ERR_INVALID_PARAM;

    int aidx = find_alert_index(svc, alert_id);
    if (aidx < 0) return OZAYN_OAN_ERR_NOT_FOUND;

    ozayn_oan_notification_t *n = &svc->notifications[svc->notif_count];
    memset(n, 0, sizeof(*n));
    n->notif_id = ++svc->sequence;
    n->alert_id = alert_id;
    strncpy(n->recipient, recipient, OZAYN_OAN_MAX_RECIPIENT_LEN - 1);
    n->channel = channel;
    n->priority = priority;
    n->state = OZAYN_OAN_NSTATE_CREATED;
    if (title) strncpy(n->title, title, OZAYN_OAN_MAX_NOTIF_TITLE - 1);
    if (body) strncpy(n->body, body, OZAYN_OAN_MAX_NOTIF_BODY - 1);
    n->created_time = time(0);
    n->max_attempts = 3;
    n->alert_ref = alert_id;
    n->active = 1;
    *out_notif_id = n->notif_id;
    svc->notif_count++;
    svc->alerts[aidx].notification_count++;
    svc->stats.total_notifications_created++;
    svc->stats.current_pending_notifications++;
    return OZAYN_OAN_ERR_OK;
}

int ozayn_oan_notif_get(const ozayn_oan_service_t *svc,
                        uint64_t notif_id,
                        const ozayn_oan_notification_t **out_notif) {
    if (!svc || !out_notif) return OZAYN_OAN_ERR_NULL_PTR;
    if (!svc->initialized) return OZAYN_OAN_ERR_NOT_INITIALIZED;
    int idx = find_notif_index(svc, notif_id);
    if (idx < 0) return OZAYN_OAN_ERR_NOT_FOUND;
    *out_notif = &svc->notifications[idx];
    return OZAYN_OAN_ERR_OK;
}

int ozayn_oan_notif_list_by_alert(const ozayn_oan_service_t *svc,
                                  uint64_t alert_id,
                                  const ozayn_oan_notification_t **out_notifs,
                                  uint32_t max_results,
                                  uint32_t *out_count) {
    if (!svc || !out_notifs || !out_count) return OZAYN_OAN_ERR_NULL_PTR;
    if (!svc->initialized) return OZAYN_OAN_ERR_NOT_INITIALIZED;
    uint32_t cnt = 0;
    for (uint64_t i = 0; i < svc->notif_count && i < OZAYN_OAN_MAX_NOTIFICATIONS && cnt < max_results; i++) {
        if (svc->notifications[i].active && svc->notifications[i].alert_id == alert_id)
            out_notifs[cnt++] = &svc->notifications[i];
    }
    *out_count = cnt;
    return OZAYN_OAN_ERR_OK;
}

int ozayn_oan_notif_advance(ozayn_oan_service_t *svc, uint64_t notif_id,
                            ozayn_oan_nstate_t new_state) {
    if (!svc) return OZAYN_OAN_ERR_NULL_PTR;
    if (!svc->initialized) return OZAYN_OAN_ERR_NOT_INITIALIZED;
    int idx = find_notif_index(svc, notif_id);
    if (idx < 0) return OZAYN_OAN_ERR_NOT_FOUND;
    ozayn_oan_notification_t *n = &svc->notifications[idx];
    if (!ozayn_oan_nstate_transition_valid(n->state, new_state))
        return OZAYN_OAN_ERR_STATE_TRANSITION;
    n->state = new_state;
    time_t now = time(0);
    if (new_state == OZAYN_OAN_NSTATE_SENDING) n->sent_time = now;
    if (new_state == OZAYN_OAN_NSTATE_DELIVERED) {
        n->delivered_time = now;
        svc->stats.total_notifications_delivered++;
        if (svc->stats.current_pending_notifications > 0) svc->stats.current_pending_notifications--;
    }
    if (new_state == OZAYN_OAN_NSTATE_FAILED) {
        svc->stats.total_notifications_failed++;
        if (n->attempt_count < n->max_attempts) {
            n->state = OZAYN_OAN_NSTATE_RETRYING;
            n->attempt_count++;
            svc->stats.total_notifications_retries++;
        } else {
            if (svc->stats.current_pending_notifications > 0) svc->stats.current_pending_notifications--;
        }
    }
    if (new_state == OZAYN_OAN_NSTATE_SENT) {
        svc->stats.total_notifications_sent++;
    }
    if (new_state == OZAYN_OAN_NSTATE_CANCELLED || new_state == OZAYN_OAN_NSTATE_EXPIRED) {
        if (svc->stats.current_pending_notifications > 0) svc->stats.current_pending_notifications--;
    }
    return OZAYN_OAN_ERR_OK;
}

int ozayn_oan_notif_cancel(ozayn_oan_service_t *svc, uint64_t notif_id) {
    if (!svc) return OZAYN_OAN_ERR_NULL_PTR;
    if (!svc->initialized) return OZAYN_OAN_ERR_NOT_INITIALIZED;
    return ozayn_oan_notif_advance(svc, notif_id, OZAYN_OAN_NSTATE_CANCELLED);
}

int64_t ozayn_oan_notif_pending_count(const ozayn_oan_service_t *svc) {
    if (!svc || !svc->initialized) return -1;
    return (int64_t)svc->stats.current_pending_notifications;
}

/* ============================================================
 * NOTIFICATION POLICIES
 * ============================================================ */

int ozayn_oan_policy_create(ozayn_oan_service_t *svc,
                            const char *name,
                            ozayn_oan_severity_t min_severity,
                            uint64_t cooldown_seconds,
                            uint32_t max_notifications_per_hour,
                            uint32_t retry_limit,
                            uint64_t retry_delay_seconds,
                            uint64_t expiration_seconds,
                            uint64_t *out_policy_id) {
    if (!svc || !name || !out_policy_id) return OZAYN_OAN_ERR_NULL_PTR;
    if (!svc->initialized) return OZAYN_OAN_ERR_NOT_INITIALIZED;
    if (svc->policy_count >= OZAYN_OAN_MAX_POLICIES) return OZAYN_OAN_ERR_FULL;
    if (min_severity < 0 || min_severity > OZAYN_OAN_SEV_CRITICAL) return OZAYN_OAN_ERR_INVALID_PARAM;

    ozayn_oan_policy_t *p = &svc->policies[svc->policy_count];
    memset(p, 0, sizeof(*p));
    p->policy_id = ++svc->sequence;
    strncpy(p->name, name, OZAYN_OAN_MAX_ALERT_NAME - 1);
    p->min_severity = min_severity;
    p->cooldown_seconds = cooldown_seconds;
    p->max_notifications_per_hour = max_notifications_per_hour;
    p->retry_limit = retry_limit;
    p->retry_delay_seconds = retry_delay_seconds;
    p->expiration_seconds = expiration_seconds;
    p->enabled = 1;
    p->active = 1;
    for (int i = 0; i < OZAYN_OAN_CAT_COUNT; i++) p->category_mask[i] = 1;
    for (int i = 0; i < OZAYN_OAN_CHAN_COUNT; i++) p->allowed_channels[i] = 1;
    *out_policy_id = p->policy_id;
    svc->policy_count++;
    return OZAYN_OAN_ERR_OK;
}

int ozayn_oan_policy_enable(ozayn_oan_service_t *svc, uint64_t policy_id) {
    if (!svc) return OZAYN_OAN_ERR_NULL_PTR;
    if (!svc->initialized) return OZAYN_OAN_ERR_NOT_INITIALIZED;
    int idx = find_policy_index(svc, policy_id);
    if (idx < 0) return OZAYN_OAN_ERR_NOT_FOUND;
    svc->policies[idx].enabled = 1;
    return OZAYN_OAN_ERR_OK;
}

int ozayn_oan_policy_disable(ozayn_oan_service_t *svc, uint64_t policy_id) {
    if (!svc) return OZAYN_OAN_ERR_NULL_PTR;
    if (!svc->initialized) return OZAYN_OAN_ERR_NOT_INITIALIZED;
    int idx = find_policy_index(svc, policy_id);
    if (idx < 0) return OZAYN_OAN_ERR_NOT_FOUND;
    svc->policies[idx].enabled = 0;
    return OZAYN_OAN_ERR_OK;
}

int ozayn_oan_policy_get(const ozayn_oan_service_t *svc,
                         uint64_t policy_id,
                         const ozayn_oan_policy_t **out_policy) {
    if (!svc || !out_policy) return OZAYN_OAN_ERR_NULL_PTR;
    if (!svc->initialized) return OZAYN_OAN_ERR_NOT_INITIALIZED;
    int idx = find_policy_index(svc, policy_id);
    if (idx < 0) return OZAYN_OAN_ERR_NOT_FOUND;
    *out_policy = &svc->policies[idx];
    return OZAYN_OAN_ERR_OK;
}

int ozayn_oan_policy_set_category(ozayn_oan_service_t *svc, uint64_t policy_id,
                                  ozayn_oan_category_t category, int enabled) {
    if (!svc) return OZAYN_OAN_ERR_NULL_PTR;
    if (!svc->initialized) return OZAYN_OAN_ERR_NOT_INITIALIZED;
    if (category < 0 || category >= OZAYN_OAN_CAT_COUNT) return OZAYN_OAN_ERR_INVALID_PARAM;
    int idx = find_policy_index(svc, policy_id);
    if (idx < 0) return OZAYN_OAN_ERR_NOT_FOUND;
    svc->policies[idx].category_mask[category] = enabled;
    return OZAYN_OAN_ERR_OK;
}

int ozayn_oan_policy_set_channel(ozayn_oan_service_t *svc, uint64_t policy_id,
                                 ozayn_oan_channel_t channel, int enabled) {
    if (!svc) return OZAYN_OAN_ERR_NULL_PTR;
    if (!svc->initialized) return OZAYN_OAN_ERR_NOT_INITIALIZED;
    if (channel < 0 || channel >= OZAYN_OAN_CHAN_COUNT) return OZAYN_OAN_ERR_INVALID_PARAM;
    int idx = find_policy_index(svc, policy_id);
    if (idx < 0) return OZAYN_OAN_ERR_NOT_FOUND;
    svc->policies[idx].allowed_channels[channel] = enabled;
    return OZAYN_OAN_ERR_OK;
}

int ozayn_oan_policy_evaluate(const ozayn_oan_service_t *svc,
                              ozayn_oan_category_t category,
                              ozayn_oan_severity_t severity,
                              const ozayn_oan_policy_t **out_policy) {
    if (!svc || !out_policy) return OZAYN_OAN_ERR_NULL_PTR;
    if (!svc->initialized) return OZAYN_OAN_ERR_NOT_INITIALIZED;
    *out_policy = 0;
    for (uint64_t i = 0; i < svc->policy_count && i < OZAYN_OAN_MAX_POLICIES; i++) {
        if (!svc->policies[i].active || !svc->policies[i].enabled) continue;
        if (svc->policies[i].category_mask[category] && severity >= svc->policies[i].min_severity) {
            *out_policy = &svc->policies[i];
            return OZAYN_OAN_ERR_OK;
        }
    }
    return OZAYN_OAN_ERR_NOT_FOUND;
}

/* ============================================================
 * RATE LIMITING
 * ============================================================ */

int ozayn_oan_rate_check_alerts(ozayn_oan_service_t *svc, uint64_t max_per_window) {
    if (!svc) return OZAYN_OAN_ERR_NULL_PTR;
    if (!svc->initialized) return OZAYN_OAN_ERR_NOT_INITIALIZED;
    time_t now = time(0);
    if (svc->window_start_time == 0 || (uint64_t)(now - svc->window_start_time) >= 60) {
        svc->window_start_time = now;
        svc->alerts_in_window = 0;
    }
    if (svc->alerts_in_window >= max_per_window) {
        svc->stats.total_rate_limited++;
        return OZAYN_OAN_ERR_RATE_LIMITED;
    }
    return OZAYN_OAN_ERR_OK;
}

int ozayn_oan_rate_check_notifications(ozayn_oan_service_t *svc, uint64_t max_per_window) {
    if (!svc) return OZAYN_OAN_ERR_NULL_PTR;
    if (!svc->initialized) return OZAYN_OAN_ERR_NOT_INITIALIZED;
    time_t now = time(0);
    if (svc->notif_window_start == 0 || (uint64_t)(now - svc->notif_window_start) >= 60) {
        svc->notif_window_start = now;
        svc->notifs_in_window = 0;
    }
    if (svc->notifs_in_window >= max_per_window) {
        svc->stats.total_rate_limited++;
        return OZAYN_OAN_ERR_RATE_LIMITED;
    }
    return OZAYN_OAN_ERR_OK;
}

int ozayn_oan_rate_record_alert(ozayn_oan_service_t *svc) {
    if (!svc) return OZAYN_OAN_ERR_NULL_PTR;
    if (!svc->initialized) return OZAYN_OAN_ERR_NOT_INITIALIZED;
    time_t now = time(0);
    if (svc->window_start_time == 0 || (uint64_t)(now - svc->window_start_time) >= 60) {
        svc->window_start_time = now;
        svc->alerts_in_window = 0;
    }
    svc->alerts_in_window++;
    return OZAYN_OAN_ERR_OK;
}

int ozayn_oan_rate_record_notification(ozayn_oan_service_t *svc) {
    if (!svc) return OZAYN_OAN_ERR_NULL_PTR;
    if (!svc->initialized) return OZAYN_OAN_ERR_NOT_INITIALIZED;
    time_t now = time(0);
    if (svc->notif_window_start == 0 || (uint64_t)(now - svc->notif_window_start) >= 60) {
        svc->notif_window_start = now;
        svc->notifs_in_window = 0;
    }
    svc->notifs_in_window++;
    return OZAYN_OAN_ERR_OK;
}

/* ============================================================
 * EXPIRATION
 * ============================================================ */

int ozayn_oan_cleanup_expired(ozayn_oan_service_t *svc) {
    if (!svc) return OZAYN_OAN_ERR_NULL_PTR;
    if (!svc->initialized) return OZAYN_OAN_ERR_NOT_INITIALIZED;
    time_t now = time(0);
    for (uint64_t i = 0; i < svc->alert_count && i < OZAYN_OAN_MAX_ALERTS; i++) {
        if (svc->alerts[i].active &&
            (svc->alerts[i].state == OZAYN_OAN_STATE_ACTIVE ||
             svc->alerts[i].state == OZAYN_OAN_STATE_CREATED) &&
            svc->alerts[i].expiration_time > 0 && now >= svc->alerts[i].expiration_time) {
            ozayn_oan_alert_expire(svc, svc->alerts[i].alert_id);
        }
    }
    for (uint64_t i = 0; i < svc->notif_count && i < OZAYN_OAN_MAX_NOTIFICATIONS; i++) {
        if (svc->notifications[i].active &&
            svc->notifications[i].state != OZAYN_OAN_NSTATE_DELIVERED &&
            svc->notifications[i].state != OZAYN_OAN_NSTATE_CANCELLED &&
            svc->notifications[i].state != OZAYN_OAN_NSTATE_EXPIRED &&
            svc->notifications[i].expiration_time > 0 && now >= svc->notifications[i].expiration_time) {
            svc->notifications[i].state = OZAYN_OAN_NSTATE_EXPIRED;
            svc->stats.total_notifications_failed++;
        }
    }
    ozayn_oan_dedup_cleanup(svc, 300);
    return OZAYN_OAN_ERR_OK;
}

/* ============================================================
 * SHUTDOWN
 * ============================================================ */

int ozayn_oan_shutdown_drain(ozayn_oan_service_t *svc,
                             uint64_t *out_active_alerts,
                             uint64_t *out_pending_notifs) {
    if (!svc) return OZAYN_OAN_ERR_NULL_PTR;
    if (!svc->initialized) return OZAYN_OAN_ERR_NOT_INITIALIZED;
    if (out_active_alerts) *out_active_alerts = svc->stats.current_active_alerts;
    if (out_pending_notifs) *out_pending_notifs = svc->stats.current_pending_notifications;
    return OZAYN_OAN_ERR_OK;
}

/* ============================================================
 * STATS
 * ============================================================ */

ozayn_oan_stats_t ozayn_oan_get_stats(const ozayn_oan_service_t *svc) {
    if (!svc) { ozayn_oan_stats_t z; memset(&z, 0, sizeof(z)); return z; }
    return svc->stats;
}
