/*
 * sec_notify.c — Security Notification Routing & Delivery Foundation (Step 30).
 */

#include "sec_notify.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <math.h>

/* ============================================================
 * GLOBAL SINGLETON
 * ============================================================ */

static ozayn_snotify_service_t _snotify_global = {0};

ozayn_snotify_service_t *ozayn_snotify_get_global(void)
{
    return &_snotify_global;
}

/* ============================================================
 * INTERNAL HELPERS
 * ============================================================ */

static void _generate_id(char *buf, int buflen, uint32_t seq)
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
    int off = snprintf(buf, buflen, "SNOTIF-");
    for (int i = len - 1; i >= 0 && off < buflen - 1; i--)
        buf[off++] = raw[i];
    buf[off] = '\0';
}

static ozayn_snotify_notification_t *_alloc_notif(ozayn_snotify_service_t *svc)
{
    if (svc->notif_count >= OZAYN_SNOTIFY_MAX_NOTIFICATIONS) {
        svc->notif_head = (svc->notif_head + 1) % OZAYN_SNOTIFY_MAX_NOTIFICATIONS;
        svc->notif_count--;
    }
    int slot = (svc->notif_head + svc->notif_count) % OZAYN_SNOTIFY_MAX_NOTIFICATIONS;
    memset(&svc->notifications[slot], 0, sizeof(ozayn_snotify_notification_t));
    svc->notif_count++;
    return &svc->notifications[slot];
}

static ozayn_snotify_notification_t *_find_notif(ozayn_snotify_service_t *svc,
                                                   const char *notif_id)
{
    if (!notif_id || !notif_id[0]) return NULL;
    for (int i = 0; i < svc->notif_count; i++) {
        int slot = (svc->notif_head + i) % OZAYN_SNOTIFY_MAX_NOTIFICATIONS;
        if (strcmp(svc->notifications[slot].notif_id, notif_id) == 0)
            return &svc->notifications[slot];
    }
    return NULL;
}

static void _audit_event(ozayn_snotify_service_t *svc,
                          const char *event_type,
                          const ozayn_snotify_notification_t *notif)
{
    if (!svc->audit || !svc->audit->initialized) return;
    ozayn_audit_event_t ev;
    ozayn_audit_event_init(&ev);
    ozayn_audit_event_set_type(&ev, OZAYN_AUDIT_CONFIG_CHANGED);
    ozayn_audit_event_set_outcome(&ev, OZAYN_AUDIT_OUTCOME_SUCCESS);
    ozayn_audit_event_set_severity(&ev, OZAYN_AUDIT_SEV_NOTICE);
    ozayn_audit_event_set_source(&ev, "SEC_NOTIFY");
    char detail[512];
    snprintf(detail, sizeof(detail), "%s: %s alert=%s ch=%d state=%d",
             event_type,
             notif ? notif->notif_id : "N/A",
             notif ? notif->alert_id : "N/A",
             notif ? (int)notif->channel : -1,
             notif ? (int)notif->state : -1);
    ozayn_audit_event_set_detail(&ev, detail);
    if (notif && notif->correlation_id[0])
        ozayn_audit_event_set_correlation_id(&ev, notif->correlation_id);
    ozayn_audit_record(svc->audit, &ev);
}

/* ============================================================
 * SECTION 18 — STATE HELPERS
 * ============================================================ */

const char *ozayn_snotify_state_name(ozayn_snotify_state_t state)
{
    switch (state) {
    case OZAYN_SNOTIFY_STATE_CREATED:         return "CREATED";
    case OZAYN_SNOTIFY_STATE_ROUTING:         return "ROUTING";
    case OZAYN_SNOTIFY_STATE_QUEUED:          return "QUEUED";
    case OZAYN_SNOTIFY_STATE_DELIVERING:      return "DELIVERING";
    case OZAYN_SNOTIFY_STATE_DELIVERED:       return "DELIVERED";
    case OZAYN_SNOTIFY_STATE_DELIVERY_FAILED: return "DELIVERY_FAILED";
    case OZAYN_SNOTIFY_STATE_RETRY_SCHEDULED: return "RETRY_SCHEDULED";
    case OZAYN_SNOTIFY_STATE_EXHAUSTED:       return "EXHAUSTED";
    case OZAYN_SNOTIFY_STATE_EXPIRED:         return "EXPIRED";
    case OZAYN_SNOTIFY_STATE_CANCELLED:       return "CANCELLED";
    }
    return "UNKNOWN";
}

const char *ozayn_snotify_result_name(ozayn_snotify_result_t result)
{
    switch (result) {
    case OZAYN_SNOTIFY_RESULT_NONE:              return "NONE";
    case OZAYN_SNOTIFY_RESULT_SUCCESS:           return "SUCCESS";
    case OZAYN_SNOTIFY_RESULT_TEMPORARY_FAILURE: return "TEMPORARY_FAILURE";
    case OZAYN_SNOTIFY_RESULT_PERMANENT_FAILURE: return "PERMANENT_FAILURE";
    case OZAYN_SNOTIFY_RESULT_UNAVAILABLE:       return "UNAVAILABLE";
    case OZAYN_SNOTIFY_RESULT_REJECTED:          return "REJECTED";
    case OZAYN_SNOTIFY_RESULT_TIMEOUT:           return "TIMEOUT";
    case OZAYN_SNOTIFY_RESULT_EXPIRED:           return "EXPIRED";
    case OZAYN_SNOTIFY_RESULT_CANCELLED:         return "CANCELLED";
    }
    return "UNKNOWN";
}

const char *ozayn_snotify_dest_state_name(ozayn_snotify_dest_state_t state)
{
    switch (state) {
    case OZAYN_SNOTIFY_DEST_UNINITIALIZED: return "UNINITIALIZED";
    case OZAYN_SNOTIFY_DEST_AVAILABLE:     return "AVAILABLE";
    case OZAYN_SNOTIFY_DEST_DISABLED:      return "DISABLED";
    case OZAYN_SNOTIFY_DEST_UNAVAILABLE:   return "UNAVAILABLE";
    case OZAYN_SNOTIFY_DEST_SUSPENDED:     return "SUSPENDED";
    case OZAYN_SNOTIFY_DEST_REVOKED:       return "REVOKED";
    }
    return "UNKNOWN";
}

const char *ozayn_snotify_dest_type_name(ozayn_snotify_dest_type_t type)
{
    switch (type) {
    case OZAYN_SNOTIFY_DEST_TYPE_UNKNOWN:  return "UNKNOWN";
    case OZAYN_SNOTIFY_DEST_TYPE_LOCAL:    return "LOCAL";
    case OZAYN_SNOTIFY_DEST_TYPE_CONSOLE:  return "CONSOLE";
    case OZAYN_SNOTIFY_DEST_TYPE_CALLBACK: return "CALLBACK";
    case OZAYN_SNOTIFY_DEST_TYPE_FILE:     return "FILE";
    case OZAYN_SNOTIFY_DEST_TYPE_SOCKET:   return "SOCKET";
    }
    return "UNKNOWN";
}

const char *ozayn_snotify_classification_name(ozayn_snotify_classification_t c)
{
    switch (c) {
    case OZAYN_SNOTIFY_CLASS_PUBLIC:           return "PUBLIC";
    case OZAYN_SNOTIFY_CLASS_INTERNAL:         return "INTERNAL";
    case OZAYN_SNOTIFY_CLASS_SENSITIVE:        return "SENSITIVE";
    case OZAYN_SNOTIFY_CLASS_HIGHLY_SENSITIVE: return "HIGHLY_SENSITIVE";
    }
    return "UNKNOWN";
}

const char *ozayn_snotify_err_name(ozayn_snotify_err_t err)
{
    switch (err) {
    case OZAYN_SNOTIFY_OK:                       return "OK";
    case OZAYN_SNOTIFY_ERR_NULL:                 return "NULL";
    case OZAYN_SNOTIFY_ERR_NOT_INITIALIZED:      return "NOT_INITIALIZED";
    case OZAYN_SNOTIFY_ERR_ALREADY_INITIALIZED:  return "ALREADY_INITIALIZED";
    case OZAYN_SNOTIFY_ERR_INVALID_PARAM:        return "INVALID_PARAM";
    case OZAYN_SNOTIFY_ERR_LIMIT_REACHED:        return "LIMIT_REACHED";
    case OZAYN_SNOTIFY_ERR_NOT_FOUND:            return "NOT_FOUND";
    case OZAYN_SNOTIFY_ERR_STATE_INVALID:        return "STATE_INVALID";
    case OZAYN_SNOTIFY_ERR_STATE_TRANSITION:     return "STATE_TRANSITION";
    case OZAYN_SNOTIFY_ERR_POLICY_REJECTED:      return "POLICY_REJECTED";
    case OZAYN_SNOTIFY_ERR_RATE_LIMITED:         return "RATE_LIMITED";
    case OZAYN_SNOTIFY_ERR_PROVIDER_UNAVAILABLE: return "PROVIDER_UNAVAILABLE";
    case OZAYN_SNOTIFY_ERR_PROVIDER_FAILED:      return "PROVIDER_FAILED";
    case OZAYN_SNOTIFY_ERR_ROUTING_FAILED:       return "ROUTING_FAILED";
    case OZAYN_SNOTIFY_ERR_DESTINATION_INVALID:  return "DESTINATION_INVALID";
    case OZAYN_SNOTIFY_ERR_DESTINATION_DISABLED: return "DESTINATION_DISABLED";
    case OZAYN_SNOTIFY_ERR_DESTINATION_REVOKED:  return "DESTINATION_REVOKED";
    case OZAYN_SNOTIFY_ERR_QUEUE_FULL:           return "QUEUE_FULL";
    case OZAYN_SNOTIFY_ERR_EXPIRED:              return "EXPIRED";
    case OZAYN_SNOTIFY_ERR_RETRY_EXHAUSTED:      return "RETRY_EXHAUSTED";
    case OZAYN_SNOTIFY_ERR_TIMEOUT:              return "TIMEOUT";
    case OZAYN_SNOTIFY_ERR_CLASSIFICATION:       return "CLASSIFICATION";
    case OZAYN_SNOTIFY_ERR_CONTENT_REJECTED:     return "CONTENT_REJECTED";
    case OZAYN_SNOTIFY_ERR_CONFLICT:             return "CONFLICT";
    case OZAYN_SNOTIFY_ERR_UNAVAILABLE:          return "UNAVAILABLE";
    }
    return "UNKNOWN";
}

int ozayn_snotify_state_transition_valid(
    ozayn_snotify_state_t from,
    ozayn_snotify_state_t to)
{
    switch (from) {
    case OZAYN_SNOTIFY_STATE_CREATED:
        return to == OZAYN_SNOTIFY_STATE_ROUTING ||
               to == OZAYN_SNOTIFY_STATE_CANCELLED;
    case OZAYN_SNOTIFY_STATE_ROUTING:
        return to == OZAYN_SNOTIFY_STATE_QUEUED ||
               to == OZAYN_SNOTIFY_STATE_DELIVERY_FAILED;
    case OZAYN_SNOTIFY_STATE_QUEUED:
        return to == OZAYN_SNOTIFY_STATE_DELIVERING ||
               to == OZAYN_SNOTIFY_STATE_EXPIRED ||
               to == OZAYN_SNOTIFY_STATE_CANCELLED;
    case OZAYN_SNOTIFY_STATE_DELIVERING:
        return to == OZAYN_SNOTIFY_STATE_DELIVERED ||
               to == OZAYN_SNOTIFY_STATE_DELIVERY_FAILED;
    case OZAYN_SNOTIFY_STATE_DELIVERED:
        return 0;
    case OZAYN_SNOTIFY_STATE_DELIVERY_FAILED:
        return to == OZAYN_SNOTIFY_STATE_RETRY_SCHEDULED ||
               to == OZAYN_SNOTIFY_STATE_EXHAUSTED;
    case OZAYN_SNOTIFY_STATE_RETRY_SCHEDULED:
        return to == OZAYN_SNOTIFY_STATE_QUEUED ||
               to == OZAYN_SNOTIFY_STATE_EXHAUSTED;
    case OZAYN_SNOTIFY_STATE_EXHAUSTED:
        return 0;
    case OZAYN_SNOTIFY_STATE_EXPIRED:
        return 0;
    case OZAYN_SNOTIFY_STATE_CANCELLED:
        return 0;
    }
    return 0;
}

int ozayn_snotify_dest_transition_valid(
    ozayn_snotify_dest_state_t from,
    ozayn_snotify_dest_state_t to)
{
    switch (from) {
    case OZAYN_SNOTIFY_DEST_UNINITIALIZED:
        return to == OZAYN_SNOTIFY_DEST_AVAILABLE;
    case OZAYN_SNOTIFY_DEST_AVAILABLE:
        return to == OZAYN_SNOTIFY_DEST_DISABLED ||
               to == OZAYN_SNOTIFY_DEST_UNAVAILABLE ||
               to == OZAYN_SNOTIFY_DEST_SUSPENDED ||
               to == OZAYN_SNOTIFY_DEST_REVOKED;
    case OZAYN_SNOTIFY_DEST_DISABLED:
        return to == OZAYN_SNOTIFY_DEST_AVAILABLE;
    case OZAYN_SNOTIFY_DEST_UNAVAILABLE:
        return to == OZAYN_SNOTIFY_DEST_AVAILABLE;
    case OZAYN_SNOTIFY_DEST_SUSPENDED:
        return to == OZAYN_SNOTIFY_DEST_AVAILABLE ||
               to == OZAYN_SNOTIFY_DEST_REVOKED;
    case OZAYN_SNOTIFY_DEST_REVOKED:
        return 0;
    }
    return 0;
}

/* ============================================================
 * SECTION 17 — LIFECYCLE
 * ============================================================ */

ozayn_snotify_err_t ozayn_snotify_service_init(
    ozayn_snotify_service_t *svc,
    const ozayn_snotify_service_config_t *cfg)
{
    if (!svc) return OZAYN_SNOTIFY_ERR_NULL;
    if (svc->initialized) return OZAYN_SNOTIFY_ERR_ALREADY_INITIALIZED;

    memset(svc, 0, sizeof(*svc));

    if (cfg) {
        svc->alert_service  = cfg->alert_service;
        svc->config_service = cfg->config_service;
        svc->audit          = cfg->audit;
    }

    svc->policy = ozayn_snotify_default_policy();
    svc->initialized = 1;
    return OZAYN_SNOTIFY_OK;
}

void ozayn_snotify_service_shutdown(ozayn_snotify_service_t *svc)
{
    if (!svc) return;
    svc->initialized = 0;
}

int ozayn_snotify_service_is_initialized(
    const ozayn_snotify_service_t *svc)
{
    return svc ? svc->initialized : 0;
}

/* ============================================================
 * SECTION 19 — DESTINATION MANAGEMENT
 * ============================================================ */

ozayn_snotify_err_t ozayn_snotify_dest_add(
    ozayn_snotify_service_t *svc,
    const char *dest_id,
    const char *name,
    ozayn_salert_notify_channel_t channel,
    ozayn_snotify_dest_type_t dest_type,
    ozayn_snotify_classification_t max_classification,
    const char *safe_metadata,
    ozayn_snotify_destination_t **out_dest)
{
    if (!svc) return OZAYN_SNOTIFY_ERR_NULL;
    if (!svc->initialized) return OZAYN_SNOTIFY_ERR_NOT_INITIALIZED;
    if (!dest_id || !dest_id[0]) return OZAYN_SNOTIFY_ERR_INVALID_PARAM;
    if (!out_dest) return OZAYN_SNOTIFY_ERR_NULL;
    if (svc->dest_count >= svc->policy.max_destinations &&
        svc->policy.max_destinations > 0)
        return OZAYN_SNOTIFY_ERR_LIMIT_REACHED;
    if (svc->dest_count >= OZAYN_SNOTIFY_MAX_DESTINATIONS)
        return OZAYN_SNOTIFY_ERR_LIMIT_REACHED;

    if (ozayn_snotify_dest_get(svc, dest_id))
        return OZAYN_SNOTIFY_ERR_CONFLICT;

    ozayn_snotify_destination_t *d = &svc->destinations[svc->dest_count];
    memset(d, 0, sizeof(*d));
    strncpy(d->dest_id, dest_id, OZAYN_SNOTIFY_MAX_DEST_ID_LEN - 1);
    if (name) strncpy(d->name, name, OZAYN_SNOTIFY_MAX_DEST_NAME_LEN - 1);
    d->channel = channel;
    d->dest_type = dest_type;
    d->state = OZAYN_SNOTIFY_DEST_AVAILABLE;
    d->max_classification = max_classification;
    if (safe_metadata)
        strncpy(d->safe_metadata, safe_metadata, OZAYN_SNOTIFY_MAX_DEST_META_LEN - 1);
    d->created_time = time(NULL);
    d->updated_time = d->created_time;
    svc->dest_count++;
    *out_dest = d;
    return OZAYN_SNOTIFY_OK;
}

ozayn_snotify_err_t ozayn_snotify_dest_remove(
    ozayn_snotify_service_t *svc,
    const char *dest_id)
{
    if (!svc) return OZAYN_SNOTIFY_ERR_NULL;
    if (!svc->initialized) return OZAYN_SNOTIFY_ERR_NOT_INITIALIZED;
    if (!dest_id) return OZAYN_SNOTIFY_ERR_INVALID_PARAM;

    for (int i = 0; i < svc->dest_count; i++) {
        if (strcmp(svc->destinations[i].dest_id, dest_id) == 0) {
            svc->destinations[i].state = OZAYN_SNOTIFY_DEST_REVOKED;
            svc->destinations[i].updated_time = time(NULL);
            return OZAYN_SNOTIFY_OK;
        }
    }
    return OZAYN_SNOTIFY_ERR_NOT_FOUND;
}

ozayn_snotify_destination_t *ozayn_snotify_dest_get(
    ozayn_snotify_service_t *svc,
    const char *dest_id)
{
    if (!svc || !dest_id) return NULL;
    for (int i = 0; i < svc->dest_count; i++) {
        if (strcmp(svc->destinations[i].dest_id, dest_id) == 0)
            return &svc->destinations[i];
    }
    return NULL;
}

int ozayn_snotify_dest_count(const ozayn_snotify_service_t *svc)
{
    return svc ? svc->dest_count : 0;
}

ozayn_snotify_err_t ozayn_snotify_dest_set_state(
    ozayn_snotify_service_t *svc,
    const char *dest_id,
    ozayn_snotify_dest_state_t new_state)
{
    if (!svc) return OZAYN_SNOTIFY_ERR_NULL;
    if (!svc->initialized) return OZAYN_SNOTIFY_ERR_NOT_INITIALIZED;
    ozayn_snotify_destination_t *d = ozayn_snotify_dest_get(svc, dest_id);
    if (!d) return OZAYN_SNOTIFY_ERR_NOT_FOUND;
    if (!ozayn_snotify_dest_transition_valid(d->state, new_state))
        return OZAYN_SNOTIFY_ERR_STATE_TRANSITION;
    d->state = new_state;
    d->updated_time = time(NULL);
    return OZAYN_SNOTIFY_OK;
}

int ozayn_snotify_dest_is_usable(const ozayn_snotify_destination_t *dest)
{
    return dest && dest->state == OZAYN_SNOTIFY_DEST_AVAILABLE;
}

/* ============================================================
 * SECTION 20 — ROUTING RULES
 * ============================================================ */

ozayn_snotify_err_t ozayn_snotify_routing_add(
    ozayn_snotify_service_t *svc,
    const ozayn_snotify_routing_rule_t *rule)
{
    if (!svc) return OZAYN_SNOTIFY_ERR_NULL;
    if (!svc->initialized) return OZAYN_SNOTIFY_ERR_NOT_INITIALIZED;
    if (!rule) return OZAYN_SNOTIFY_ERR_NULL;
    if (!rule->rule_id[0]) return OZAYN_SNOTIFY_ERR_INVALID_PARAM;
    if (svc->rule_count >= svc->policy.max_routing_rules &&
        svc->policy.max_routing_rules > 0)
        return OZAYN_SNOTIFY_ERR_LIMIT_REACHED;
    if (svc->rule_count >= OZAYN_SNOTIFY_MAX_ROUTING_RULES)
        return OZAYN_SNOTIFY_ERR_LIMIT_REACHED;

    for (int i = 0; i < svc->rule_count; i++) {
        if (strcmp(svc->rules[i].rule_id, rule->rule_id) == 0)
            return OZAYN_SNOTIFY_ERR_CONFLICT;
    }

    svc->rules[svc->rule_count] = *rule;
    svc->rule_count++;
    return OZAYN_SNOTIFY_OK;
}

ozayn_snotify_err_t ozayn_snotify_routing_remove(
    ozayn_snotify_service_t *svc,
    const char *rule_id)
{
    if (!svc) return OZAYN_SNOTIFY_ERR_NULL;
    if (!svc->initialized) return OZAYN_SNOTIFY_ERR_NOT_INITIALIZED;
    if (!rule_id) return OZAYN_SNOTIFY_ERR_INVALID_PARAM;

    for (int i = 0; i < svc->rule_count; i++) {
        if (strcmp(svc->rules[i].rule_id, rule_id) == 0) {
            svc->rules[i] = svc->rules[svc->rule_count - 1];
            memset(&svc->rules[svc->rule_count - 1], 0,
                   sizeof(ozayn_snotify_routing_rule_t));
            svc->rule_count--;
            return OZAYN_SNOTIFY_OK;
        }
    }
    return OZAYN_SNOTIFY_ERR_NOT_FOUND;
}

static int _rule_matches(const ozayn_snotify_routing_rule_t *rule,
                          const ozayn_salert_alert_t *alert)
{
    if (!rule->enabled) return 0;
    if ((int)alert->severity < (int)rule->min_severity) return 0;
    if ((int)alert->severity > (int)rule->max_severity) return 0;
    if ((int)alert->priority < (int)rule->min_priority) return 0;
    if ((int)alert->priority > (int)rule->max_priority) return 0;
    if (rule->type_filter_active && alert->alert_type != rule->alert_type)
        return 0;
    return 1;
}

ozayn_snotify_err_t ozayn_snotify_routing_evaluate(
    const ozayn_snotify_service_t *svc,
    const ozayn_salert_alert_t *alert,
    ozayn_salert_notify_channel_t *out_channel,
    char *out_dest_id,
    int max_dest_len)
{
    if (!svc || !alert || !out_channel)
        return OZAYN_SNOTIFY_ERR_NULL;
    if (!svc->initialized) return OZAYN_SNOTIFY_ERR_NOT_INITIALIZED;

    int best_priority = -1;
    int best_rule = -1;

    for (int i = 0; i < svc->rule_count; i++) {
        if (_rule_matches(&svc->rules[i], alert)) {
            if (svc->rules[i].priority_order > best_priority) {
                best_priority = svc->rules[i].priority_order;
                best_rule = i;
            }
        }
    }

    if (best_rule < 0)
        return OZAYN_SNOTIFY_ERR_ROUTING_FAILED;

    const ozayn_snotify_routing_rule_t *rule = &svc->rules[best_rule];

    if (rule->require_channel && rule->enabled_channels[rule->required_channel]) {
        *out_channel = rule->required_channel;
    } else {
        *out_channel = OZAYN_SALERT_NOTIFY_LOCAL;
    }

    if (out_dest_id && max_dest_len > 0) {
        out_dest_id[0] = '\0';
        for (int i = 0; i < svc->dest_count; i++) {
            if (ozayn_snotify_dest_is_usable(&svc->destinations[i]) &&
                svc->destinations[i].channel == *out_channel) {
                strncpy(out_dest_id, svc->destinations[i].dest_id,
                        max_dest_len - 1);
                break;
            }
        }
    }

    return OZAYN_SNOTIFY_OK;
}

ozayn_snotify_err_t ozayn_snotify_routing_evaluate_default(
    const ozayn_snotify_service_t *svc,
    const ozayn_salert_alert_t *alert,
    ozayn_salert_notify_channel_t *out_channel)
{
    if (!svc || !alert || !out_channel)
        return OZAYN_SNOTIFY_ERR_NULL;
    if (!svc->initialized) return OZAYN_SNOTIFY_ERR_NOT_INITIALIZED;

    ozayn_salert_notify_channel_t ch;
    ozayn_snotify_err_t rc = ozayn_snotify_routing_evaluate(
        svc, alert, &ch, NULL, 0);
    if (rc == OZAYN_SNOTIFY_OK) {
        *out_channel = ch;
        return OZAYN_SNOTIFY_OK;
    }

    switch (alert->severity) {
    case OZAYN_SALERT_SEV_INFO:
    case OZAYN_SALERT_SEV_NOTICE:
        *out_channel = OZAYN_SALERT_NOTIFY_LOCAL;
        break;
    case OZAYN_SALERT_SEV_WARNING:
        *out_channel = OZAYN_SALERT_NOTIFY_LOCAL;
        break;
    case OZAYN_SALERT_SEV_HIGH:
        *out_channel = OZAYN_SALERT_NOTIFY_LOCAL;
        break;
    case OZAYN_SALERT_SEV_CRITICAL:
        *out_channel = OZAYN_SALERT_NOTIFY_LOCAL;
        break;
    default:
        *out_channel = OZAYN_SALERT_NOTIFY_LOCAL;
        break;
    }

    if (!svc->policy.enabled_channels[*out_channel])
        return OZAYN_SNOTIFY_ERR_POLICY_REJECTED;

    return OZAYN_SNOTIFY_OK;
}

/* ============================================================
 * SECTION 21 — NOTIFICATION POLICY
 * ============================================================ */

ozayn_snotify_policy_t ozayn_snotify_default_policy(void)
{
    ozayn_snotify_policy_t p;
    memset(&p, 0, sizeof(p));
    p.enabled = 1;
    p.enabled_channels[OZAYN_SALERT_NOTIFY_LOCAL]   = 1;
    p.enabled_channels[OZAYN_SALERT_NOTIFY_DESKTOP]  = 1;
    p.enabled_channels[OZAYN_SALERT_NOTIFY_EMAIL]    = 0;
    p.enabled_channels[OZAYN_SALERT_NOTIFY_SMS]      = 0;
    p.enabled_channels[OZAYN_SALERT_NOTIFY_PUSH]     = 0;
    p.enabled_channels[OZAYN_SALERT_NOTIFY_CONTROL_ROOM] = 1;
    p.enabled_channels[OZAYN_SALERT_NOTIFY_EXTERNAL] = 0;

    p.retry_policy = ozayn_snotify_default_retry_policy();
    p.timeout_seconds = 30;
    p.expiration_seconds = 3600;
    p.max_rate_per_window = 50;
    p.rate_window_seconds = 60;
    p.max_queue_size = 128;
    p.max_destinations = OZAYN_SNOTIFY_MAX_DESTINATIONS;
    p.max_providers = OZAYN_SNOTIFY_MAX_PROVIDERS;
    p.max_routing_rules = OZAYN_SNOTIFY_MAX_ROUTING_RULES;
    p.default_classification = OZAYN_SNOTIFY_CLASS_INTERNAL;
    p.max_notification_size = 4096;
    p.max_metadata_size = OZAYN_SNOTIFY_MAX_META_LEN;
    return p;
}

ozayn_snotify_err_t ozayn_snotify_set_policy(
    ozayn_snotify_service_t *svc,
    const ozayn_snotify_policy_t *policy)
{
    if (!svc || !policy) return OZAYN_SNOTIFY_ERR_NULL;
    if (!svc->initialized) return OZAYN_SNOTIFY_ERR_NOT_INITIALIZED;
    svc->policy = *policy;
    return OZAYN_SNOTIFY_OK;
}

const ozayn_snotify_policy_t *ozayn_snotify_get_policy(
    const ozayn_snotify_service_t *svc)
{
    return svc ? &svc->policy : NULL;
}

int ozayn_snotify_channel_enabled(
    const ozayn_snotify_service_t *svc,
    ozayn_salert_notify_channel_t channel)
{
    if (!svc) return 0;
    if (channel < 0 || channel > OZAYN_SALERT_NOTIFY_EXTERNAL) return 0;
    return svc->policy.enabled_channels[channel];
}

/* ============================================================
 * SECTION 34 — CLASSIFICATION
 * ============================================================ */

ozayn_snotify_classification_t ozayn_snotify_severity_to_classification(
    ozayn_salert_severity_t severity)
{
    switch (severity) {
    case OZAYN_SALERT_SEV_INFO:
        return OZAYN_SNOTIFY_CLASS_PUBLIC;
    case OZAYN_SALERT_SEV_NOTICE:
        return OZAYN_SNOTIFY_CLASS_INTERNAL;
    case OZAYN_SALERT_SEV_WARNING:
        return OZAYN_SNOTIFY_CLASS_SENSITIVE;
    case OZAYN_SALERT_SEV_HIGH:
    case OZAYN_SALERT_SEV_CRITICAL:
        return OZAYN_SNOTIFY_CLASS_HIGHLY_SENSITIVE;
    }
    return OZAYN_SNOTIFY_CLASS_INTERNAL;
}

int ozayn_snotify_classification_allows_channel(
    ozayn_snotify_classification_t classification,
    ozayn_salert_notify_channel_t channel)
{
    (void)channel;
    switch (classification) {
    case OZAYN_SNOTIFY_CLASS_PUBLIC:
        return 1;
    case OZAYN_SNOTIFY_CLASS_INTERNAL:
        return (channel == OZAYN_SALERT_NOTIFY_LOCAL ||
                channel == OZAYN_SALERT_NOTIFY_DESKTOP ||
                channel == OZAYN_SALERT_NOTIFY_CONTROL_ROOM);
    case OZAYN_SNOTIFY_CLASS_SENSITIVE:
        return (channel == OZAYN_SALERT_NOTIFY_LOCAL ||
                channel == OZAYN_SALERT_NOTIFY_CONTROL_ROOM);
    case OZAYN_SNOTIFY_CLASS_HIGHLY_SENSITIVE:
        return (channel == OZAYN_SALERT_NOTIFY_LOCAL);
    }
    return 0;
}

/* ============================================================
 * SECTION 35 — RETRY POLICY HELPERS
 * ============================================================ */

ozayn_snotify_retry_policy_t ozayn_snotify_default_retry_policy(void)
{
    ozayn_snotify_retry_policy_t p;
    p.max_retries = 3;
    p.base_delay_ms = 1000;
    p.max_delay_ms = 30000;
    p.backoff_multiplier = 2.0;
    p.jitter_enabled = 1;
    p.expiration_seconds = 3600;
    return p;
}

int ozayn_snotify_result_is_retryable(ozayn_snotify_result_t result)
{
    switch (result) {
    case OZAYN_SNOTIFY_RESULT_TEMPORARY_FAILURE:
    case OZAYN_SNOTIFY_RESULT_TIMEOUT:
    case OZAYN_SNOTIFY_RESULT_UNAVAILABLE:
        return 1;
    default:
        return 0;
    }
}

/* ============================================================
 * SECTION 22 — NOTIFICATION CREATION & ROUTING
 * ============================================================ */

ozayn_snotify_err_t ozayn_snotify_create(
    ozayn_snotify_service_t *svc,
    const ozayn_salert_alert_t *alert,
    ozayn_snotify_notification_t **out_notif)
{
    if (!svc) return OZAYN_SNOTIFY_ERR_NULL;
    if (!svc->initialized) return OZAYN_SNOTIFY_ERR_NOT_INITIALIZED;
    if (!alert || !out_notif) return OZAYN_SNOTIFY_ERR_NULL;
    if (!svc->policy.enabled) return OZAYN_SNOTIFY_ERR_POLICY_REJECTED;

    for (int i = 0; i < svc->notif_count; i++) {
        int slot = (svc->notif_head + i) % OZAYN_SNOTIFY_MAX_NOTIFICATIONS;
        if (strcmp(svc->notifications[slot].alert_id, alert->alert_id) == 0 &&
            svc->notifications[slot].state != OZAYN_SNOTIFY_STATE_DELIVERED &&
            svc->notifications[slot].state != OZAYN_SNOTIFY_STATE_CANCELLED &&
            svc->notifications[slot].state != OZAYN_SNOTIFY_STATE_EXPIRED &&
            svc->notifications[slot].state != OZAYN_SNOTIFY_STATE_EXHAUSTED) {
            *out_notif = &svc->notifications[slot];
            return OZAYN_SNOTIFY_OK;
        }
    }

    ozayn_snotify_notification_t *n = _alloc_notif(svc);
    _generate_id(n->notif_id, OZAYN_SNOTIFY_MAX_NOTIF_ID_LEN,
                 svc->notif_sequence++);
    strncpy(n->alert_id, alert->alert_id, OZAYN_SNOTIFY_MAX_ALERT_REF_LEN - 1);
    n->severity = alert->severity;
    n->priority = alert->priority;
    n->state = OZAYN_SNOTIFY_STATE_CREATED;
    n->created_time = time(NULL);
    n->expiration_time = n->created_time + svc->policy.expiration_seconds;
    n->max_attempts = svc->policy.retry_policy.max_retries + 1;
    n->classification = ozayn_snotify_severity_to_classification(alert->severity);
    if (alert->correlation_id[0])
        strncpy(n->correlation_id, alert->correlation_id,
                OZAYN_SNOTIFY_MAX_CORR_ID_LEN - 1);

    ozayn_salert_generate_safe_title(alert, n->content.title,
                                      sizeof(n->content.title));
    ozayn_salert_generate_safe_body(alert, n->content.body,
                                     sizeof(n->content.body));
    strncpy(n->content.reference_id, alert->alert_id,
            sizeof(n->content.reference_id) - 1);
    n->content.classification = n->classification;

    svc->total_created++;
    _audit_event(svc, "NOTIFICATION_CREATED", n);
    *out_notif = n;
    return OZAYN_SNOTIFY_OK;
}

ozayn_snotify_err_t ozayn_snotify_route(
    ozayn_snotify_service_t *svc,
    ozayn_snotify_notification_t *notif)
{
    if (!svc) return OZAYN_SNOTIFY_ERR_NULL;
    if (!svc->initialized) return OZAYN_SNOTIFY_ERR_NOT_INITIALIZED;
    if (!notif) return OZAYN_SNOTIFY_ERR_NULL;
    if (!ozayn_snotify_state_transition_valid(notif->state,
                                              OZAYN_SNOTIFY_STATE_ROUTING))
        return OZAYN_SNOTIFY_ERR_STATE_TRANSITION;

    notif->state = OZAYN_SNOTIFY_STATE_ROUTING;
    notif->notif_version++;

    ozayn_salert_notify_channel_t ch;
    char dest_id[OZAYN_SNOTIFY_MAX_DEST_ID_LEN];
    ozayn_salert_service_t *asvc = svc->alert_service;
    ozayn_salert_alert_t *alert = NULL;

    if (asvc) {
        for (int i = 0; i < asvc->alert_count; i++) {
            int slot = (asvc->alert_head + i) % OZAYN_SALERT_MAX_ALERTS;
            if (strcmp(asvc->alerts[slot].alert_id, notif->alert_id) == 0) {
                alert = &asvc->alerts[slot];
                break;
            }
        }
    }

    if (!alert) {
        notif->state = OZAYN_SNOTIFY_STATE_DELIVERY_FAILED;
        svc->total_routing_failed++;
        _audit_event(svc, "ROUTING_FAILED_NO_ALERT", notif);
        return OZAYN_SNOTIFY_ERR_NOT_FOUND;
    }

    ozayn_snotify_err_t rc = ozayn_snotify_routing_evaluate(
        svc, alert, &ch, dest_id, sizeof(dest_id));

    if (rc != OZAYN_SNOTIFY_OK) {
        rc = ozayn_snotify_routing_evaluate_default(svc, alert, &ch);
        if (rc != OZAYN_SNOTIFY_OK) {
            notif->state = OZAYN_SNOTIFY_STATE_DELIVERY_FAILED;
            svc->total_routing_failed++;
            _audit_event(svc, "ROUTING_FAILED", notif);
            return OZAYN_SNOTIFY_ERR_ROUTING_FAILED;
        }
    }

    notif->channel = ch;
    if (dest_id[0])
        strncpy(notif->dest_id, dest_id, OZAYN_SNOTIFY_MAX_DEST_REF_LEN - 1);

    if (!ozayn_snotify_channel_enabled(svc, ch)) {
        notif->state = OZAYN_SNOTIFY_STATE_DELIVERY_FAILED;
        svc->total_routing_failed++;
        _audit_event(svc, "ROUTING_CHANNEL_DISABLED", notif);
        return OZAYN_SNOTIFY_ERR_POLICY_REJECTED;
    }

    if (!ozayn_snotify_classification_allows_channel(notif->classification, ch)) {
        notif->state = OZAYN_SNOTIFY_STATE_DELIVERY_FAILED;
        svc->total_classified_rejected++;
        _audit_event(svc, "CLASSIFICATION_REJECTED", notif);
        return OZAYN_SNOTIFY_ERR_CLASSIFICATION;
    }

    if (!ozayn_snotify_check_rate_limit(svc, ch)) {
        notif->state = OZAYN_SNOTIFY_STATE_DELIVERY_FAILED;
        svc->total_rate_limited++;
        _audit_event(svc, "RATE_LIMITED", notif);
        return OZAYN_SNOTIFY_ERR_RATE_LIMITED;
    }

    svc->total_routed++;
    _audit_event(svc, "NOTIFICATION_ROUTED", notif);
    return OZAYN_SNOTIFY_OK;
}

ozayn_snotify_err_t ozayn_snotify_enqueue(
    ozayn_snotify_service_t *svc,
    ozayn_snotify_notification_t *notif)
{
    if (!svc) return OZAYN_SNOTIFY_ERR_NULL;
    if (!svc->initialized) return OZAYN_SNOTIFY_ERR_NOT_INITIALIZED;
    if (!notif) return OZAYN_SNOTIFY_ERR_NULL;
    if (ozayn_snotify_queue_is_full(svc))
        return OZAYN_SNOTIFY_ERR_QUEUE_FULL;
    if (!ozayn_snotify_state_transition_valid(notif->state,
                                              OZAYN_SNOTIFY_STATE_QUEUED))
        return OZAYN_SNOTIFY_ERR_STATE_TRANSITION;

    notif->state = OZAYN_SNOTIFY_STATE_QUEUED;
    notif->scheduled_time = time(NULL);
    notif->notif_version++;

    svc->total_queued++;
    _audit_event(svc, "NOTIFICATION_QUEUED", notif);
    return OZAYN_SNOTIFY_OK;
}

/* ============================================================
 * SECTION 23 — DELIVERY
 * ============================================================ */

ozayn_snotify_err_t ozayn_snotify_deliver(
    ozayn_snotify_service_t *svc,
    ozayn_snotify_notification_t *notif)
{
    if (!svc) return OZAYN_SNOTIFY_ERR_NULL;
    if (!svc->initialized) return OZAYN_SNOTIFY_ERR_NOT_INITIALIZED;
    if (!notif) return OZAYN_SNOTIFY_ERR_NULL;
    if (!ozayn_snotify_state_transition_valid(notif->state,
                                              OZAYN_SNOTIFY_STATE_DELIVERING))
        return OZAYN_SNOTIFY_ERR_STATE_TRANSITION;

    notif->state = OZAYN_SNOTIFY_STATE_DELIVERING;
    notif->attempt_count++;
    notif->last_attempt_time = time(NULL);
    notif->notif_version++;

    ozayn_snotify_provider_t *prov = ozayn_snotify_get_provider(
        svc, notif->channel);
    if (!prov || !prov->vtable || !prov->vtable->send) {
        notif->state = OZAYN_SNOTIFY_STATE_DELIVERY_FAILED;
        svc->total_failed++;
        _audit_event(svc, "DELIVERY_NO_PROVIDER", notif);
        return OZAYN_SNOTIFY_ERR_PROVIDER_UNAVAILABLE;
    }

    if (!prov->available || !prov->enabled) {
        notif->state = OZAYN_SNOTIFY_STATE_DELIVERY_FAILED;
        prov->fail_count++;
        prov->last_fail_time = time(NULL);
        svc->total_failed++;
        _audit_event(svc, "DELIVERY_PROVIDER_UNAVAILABLE", notif);
        return OZAYN_SNOTIFY_ERR_PROVIDER_UNAVAILABLE;
    }

    ozayn_snotify_delivery_result_t result;
    memset(&result, 0, sizeof(result));
    int rc = prov->vtable->send(prov->context, notif, &notif->content, &result);

    if (rc == 0 && result.result == OZAYN_SNOTIFY_RESULT_SUCCESS) {
        notif->state = OZAYN_SNOTIFY_STATE_DELIVERED;
        notif->delivery_result = OZAYN_SNOTIFY_RESULT_SUCCESS;
        svc->total_delivered++;
        ozayn_snotify_record_result(svc, &result);
        _audit_event(svc, "NOTIFICATION_DELIVERED", notif);
        return OZAYN_SNOTIFY_OK;
    }

    notif->state = OZAYN_SNOTIFY_STATE_DELIVERY_FAILED;
    notif->delivery_result = result.result;
    prov->fail_count++;
    prov->last_fail_time = time(NULL);
    svc->total_failed++;
    ozayn_snotify_record_result(svc, &result);
    _audit_event(svc, "DELIVERY_FAILED", notif);
    return OZAYN_SNOTIFY_ERR_PROVIDER_FAILED;
}

ozayn_snotify_err_t ozayn_snotify_process_queue(
    ozayn_snotify_service_t *svc)
{
    if (!svc) return OZAYN_SNOTIFY_ERR_NULL;
    if (!svc->initialized) return OZAYN_SNOTIFY_ERR_NOT_INITIALIZED;

    ozayn_snotify_err_t last_err = OZAYN_SNOTIFY_OK;
    for (int i = 0; i < svc->notif_count; i++) {
        int slot = (svc->notif_head + i) % OZAYN_SNOTIFY_MAX_NOTIFICATIONS;
        ozayn_snotify_notification_t *n = &svc->notifications[slot];

        if (n->state == OZAYN_SNOTIFY_STATE_EXPIRED) continue;
        if (n->state == OZAYN_SNOTIFY_STATE_DELIVERED) continue;
        if (n->state == OZAYN_SNOTIFY_STATE_CANCELLED) continue;
        if (n->state == OZAYN_SNOTIFY_STATE_EXHAUSTED) continue;

        if (ozayn_snotify_is_expired(n)) {
            ozayn_snotify_expire(svc, n);
            continue;
        }

        if (n->state == OZAYN_SNOTIFY_STATE_CREATED) {
            ozayn_snotify_err_t rc = ozayn_snotify_route(svc, n);
            if (rc != OZAYN_SNOTIFY_OK) { last_err = rc; continue; }
        }

        if (n->state == OZAYN_SNOTIFY_STATE_ROUTING) {
            ozayn_snotify_err_t rc = ozayn_snotify_enqueue(svc, n);
            if (rc != OZAYN_SNOTIFY_OK) { last_err = rc; continue; }
        }

        if (n->state == OZAYN_SNOTIFY_STATE_QUEUED) {
            ozayn_snotify_err_t rc = ozayn_snotify_deliver(svc, n);
            if (rc != OZAYN_SNOTIFY_OK) {
                last_err = rc;
                if (n->state == OZAYN_SNOTIFY_STATE_DELIVERY_FAILED) {
                    if (ozayn_snotify_retry_allowed(n)) {
                        ozayn_snotify_retry(svc, n);
                    } else {
                        n->state = OZAYN_SNOTIFY_STATE_EXHAUSTED;
                        _audit_event(svc, "NOTIFICATION_EXHAUSTED", n);
                    }
                }
            }
        }

        if (n->state == OZAYN_SNOTIFY_STATE_RETRY_SCHEDULED) {
            if (time(NULL) >= n->next_retry_time) {
                n->state = OZAYN_SNOTIFY_STATE_QUEUED;
            }
        }
    }
    return last_err;
}

/* ============================================================
 * SECTION 24 — RETRY & BACKOFF
 * ============================================================ */

int ozayn_snotify_calculate_backoff_ms(
    const ozayn_snotify_retry_policy_t *policy,
    int attempt)
{
    if (!policy || attempt < 0) return 0;
    double delay = (double)policy->base_delay_ms;
    for (int i = 0; i < attempt; i++) {
        delay *= policy->backoff_multiplier;
        if (delay > (double)policy->max_delay_ms) {
            delay = (double)policy->max_delay_ms;
            break;
        }
    }
    if (delay < 0) delay = 0;
    if (delay > (double)policy->max_delay_ms)
        delay = (double)policy->max_delay_ms;
    return (int)delay;
}

int ozayn_snotify_retry_allowed(const ozayn_snotify_notification_t *notif)
{
    if (!notif) return 0;
    return notif->attempt_count < notif->max_attempts;
}

ozayn_snotify_err_t ozayn_snotify_retry(
    ozayn_snotify_service_t *svc,
    ozayn_snotify_notification_t *notif)
{
    if (!svc) return OZAYN_SNOTIFY_ERR_NULL;
    if (!svc->initialized) return OZAYN_SNOTIFY_ERR_NOT_INITIALIZED;
    if (!notif) return OZAYN_SNOTIFY_ERR_NULL;

    if (!ozayn_snotify_result_is_retryable(notif->delivery_result))
        return OZAYN_SNOTIFY_ERR_RETRY_EXHAUSTED;

    if (!ozayn_snotify_retry_allowed(notif)) {
        notif->state = OZAYN_SNOTIFY_STATE_EXHAUSTED;
        _audit_event(svc, "RETRY_EXHAUSTED", notif);
        return OZAYN_SNOTIFY_ERR_RETRY_EXHAUSTED;
    }

    if (!ozayn_snotify_state_transition_valid(notif->state,
                                              OZAYN_SNOTIFY_STATE_RETRY_SCHEDULED))
        return OZAYN_SNOTIFY_ERR_STATE_TRANSITION;

    int delay_ms = ozayn_snotify_calculate_backoff_ms(
        &svc->policy.retry_policy, notif->attempt_count);
    if (svc->policy.retry_policy.jitter_enabled && delay_ms > 0) {
        uint32_t h = 5381;
        const char *id = notif->notif_id;
        while (*id) h = h * 33 + (unsigned char)*id++;
        delay_ms = delay_ms / 2 + (int)(h % (unsigned int)(delay_ms / 2 + 1));
    }

    notif->state = OZAYN_SNOTIFY_STATE_RETRY_SCHEDULED;
    notif->next_retry_time = time(NULL) + (delay_ms / 1000);
    if (delay_ms > 0 && notif->next_retry_time == time(NULL))
        notif->next_retry_time = time(NULL) + 1;
    notif->notif_version++;

    svc->total_retries++;
    _audit_event(svc, "RETRY_SCHEDULED", notif);
    return OZAYN_SNOTIFY_OK;
}

/* ============================================================
 * SECTION 25 — EXPIRATION
 * ============================================================ */

int ozayn_snotify_is_expired(const ozayn_snotify_notification_t *notif)
{
    if (!notif) return 0;
    if (notif->expiration_time <= 0) return 0;
    return time(NULL) >= notif->expiration_time;
}

ozayn_snotify_err_t ozayn_snotify_expire(
    ozayn_snotify_service_t *svc,
    ozayn_snotify_notification_t *notif)
{
    if (!svc) return OZAYN_SNOTIFY_ERR_NULL;
    if (!svc->initialized) return OZAYN_SNOTIFY_ERR_NOT_INITIALIZED;
    if (!notif) return OZAYN_SNOTIFY_ERR_NULL;

    if (notif->state == OZAYN_SNOTIFY_STATE_DELIVERED ||
        notif->state == OZAYN_SNOTIFY_STATE_CANCELLED ||
        notif->state == OZAYN_SNOTIFY_STATE_EXPIRED)
        return OZAYN_SNOTIFY_OK;

    notif->state = OZAYN_SNOTIFY_STATE_EXPIRED;
    notif->delivery_result = OZAYN_SNOTIFY_RESULT_EXPIRED;
    notif->notif_version++;
    svc->total_expired++;
    _audit_event(svc, "NOTIFICATION_EXPIRED", notif);
    return OZAYN_SNOTIFY_OK;
}

int ozayn_snotify_cleanup_expired(ozayn_snotify_service_t *svc)
{
    if (!svc) return 0;
    if (!svc->initialized) return 0;
    int cleaned = 0;
    for (int i = 0; i < svc->notif_count; i++) {
        int slot = (svc->notif_head + i) % OZAYN_SNOTIFY_MAX_NOTIFICATIONS;
        ozayn_snotify_notification_t *n = &svc->notifications[slot];
        if ((n->state == OZAYN_SNOTIFY_STATE_DELIVERED ||
             n->state == OZAYN_SNOTIFY_STATE_CANCELLED ||
             n->state == OZAYN_SNOTIFY_STATE_EXHAUSTED) &&
            ozayn_snotify_is_expired(n)) {
            ozayn_snotify_expire(svc, n);
            cleaned++;
        }
    }
    return cleaned;
}

/* ============================================================
 * SECTION 26 — QUERY
 * ============================================================ */

ozayn_snotify_notification_t *ozayn_snotify_get(
    ozayn_snotify_service_t *svc,
    const char *notif_id)
{
    if (!svc || !notif_id) return NULL;
    if (!svc->initialized) return NULL;
    return _find_notif(svc, notif_id);
}

int ozayn_snotify_list(
    const ozayn_snotify_service_t *svc,
    int filter_state,
    ozayn_snotify_notification_t **out_notifs,
    int max_count)
{
    if (!svc || !out_notifs || max_count <= 0) return 0;
    if (!svc->initialized) return 0;

    int count = 0;
    for (int i = 0; i < svc->notif_count && count < max_count; i++) {
        int slot = (svc->notif_head + i) % OZAYN_SNOTIFY_MAX_NOTIFICATIONS;
        const ozayn_snotify_notification_t *n = &svc->notifications[slot];
        int state_match = (filter_state < 0 ||
                           n->state == (ozayn_snotify_state_t)filter_state);
        if (state_match) {
            out_notifs[count] = (ozayn_snotify_notification_t *)n;
            count++;
        }
    }
    return count;
}

int ozayn_snotify_get_queue_count(const ozayn_snotify_service_t *svc)
{
    if (!svc) return 0;
    int count = 0;
    for (int i = 0; i < svc->notif_count; i++) {
        int slot = (svc->notif_head + i) % OZAYN_SNOTIFY_MAX_NOTIFICATIONS;
        if (svc->notifications[slot].state == OZAYN_SNOTIFY_STATE_QUEUED ||
            svc->notifications[slot].state == OZAYN_SNOTIFY_STATE_DELIVERING ||
            svc->notifications[slot].state == OZAYN_SNOTIFY_STATE_RETRY_SCHEDULED)
            count++;
    }
    return count;
}

int ozayn_snotify_get_total_count(const ozayn_snotify_service_t *svc)
{
    return svc ? svc->notif_count : 0;
}

/* ============================================================
 * SECTION 27 — DELIVERY RESULTS
 * ============================================================ */

ozayn_snotify_err_t ozayn_snotify_record_result(
    ozayn_snotify_service_t *svc,
    const ozayn_snotify_delivery_result_t *result)
{
    if (!svc || !result) return OZAYN_SNOTIFY_ERR_NULL;
    if (!svc->initialized) return OZAYN_SNOTIFY_ERR_NOT_INITIALIZED;
    if (svc->result_count >= OZAYN_SNOTIFY_MAX_DELIVERY_RESULTS) {
        svc->result_head = (svc->result_head + 1) %
                           OZAYN_SNOTIFY_MAX_DELIVERY_RESULTS;
        svc->result_count--;
    }
    int slot = (svc->result_head + svc->result_count) %
               OZAYN_SNOTIFY_MAX_DELIVERY_RESULTS;
    svc->results[slot] = *result;
    svc->result_count++;
    return OZAYN_SNOTIFY_OK;
}

ozayn_snotify_err_t ozayn_snotify_get_last_result(
    const ozayn_snotify_service_t *svc,
    const char *notif_id,
    ozayn_snotify_delivery_result_t *out_result)
{
    if (!svc || !notif_id || !out_result)
        return OZAYN_SNOTIFY_ERR_NULL;
    if (!svc->initialized) return OZAYN_SNOTIFY_ERR_NOT_INITIALIZED;

    for (int i = svc->result_count - 1; i >= 0; i--) {
        int slot = (svc->result_head + i) % OZAYN_SNOTIFY_MAX_DELIVERY_RESULTS;
        if (strcmp(svc->results[slot].notif_id, notif_id) == 0) {
            *out_result = svc->results[slot];
            return OZAYN_SNOTIFY_OK;
        }
    }
    return OZAYN_SNOTIFY_ERR_NOT_FOUND;
}

/* ============================================================
 * SECTION 28 — ALERT INTEGRATION
 * ============================================================ */

int ozayn_snotify_should_notify(
    const ozayn_snotify_service_t *svc,
    const ozayn_salert_alert_t *alert)
{
    if (!svc || !alert) return 0;
    if (!svc->initialized) return 0;
    if (!svc->policy.enabled) return 0;
    if (alert->suppressed) return 0;
    if (alert->state == OZAYN_SALERT_STATE_RESOLVED) return 0;
    if (alert->state == OZAYN_SALERT_STATE_CANCELLED) return 0;
    if (alert->state == OZAYN_SALERT_STATE_EXPIRED) return 0;
    if (alert->state == OZAYN_SALERT_STATE_FAILED) return 0;
    return 1;
}

ozayn_snotify_err_t ozayn_snotify_process_alert(
    ozayn_snotify_service_t *svc,
    const ozayn_salert_alert_t *alert)
{
    if (!svc) return OZAYN_SNOTIFY_ERR_NULL;
    if (!svc->initialized) return OZAYN_SNOTIFY_ERR_NOT_INITIALIZED;
    if (!alert) return OZAYN_SNOTIFY_ERR_NULL;

    if (!ozayn_snotify_should_notify(svc, alert))
        return OZAYN_SNOTIFY_OK;

    for (int i = 0; i < svc->notif_count; i++) {
        int slot = (svc->notif_head + i) % OZAYN_SNOTIFY_MAX_NOTIFICATIONS;
        ozayn_snotify_notification_t *n = &svc->notifications[slot];
        if (strcmp(n->alert_id, alert->alert_id) == 0) {
            if (n->state == OZAYN_SNOTIFY_STATE_DELIVERED) {
                if (alert->escalation_level > 0 &&
                    n->severity != alert->severity) {
                    n->severity = alert->severity;
                    n->classification = ozayn_snotify_severity_to_classification(
                        alert->severity);
                    n->state = OZAYN_SNOTIFY_STATE_CREATED;
                    n->content.classification = n->classification;
                    ozayn_salert_generate_safe_title(alert, n->content.title,
                                                      sizeof(n->content.title));
                    ozayn_salert_generate_safe_body(alert, n->content.body,
                                                     sizeof(n->content.body));
                    _audit_event(svc, "NOTIFICATION_RE_ESCALATED", n);
                }
                return OZAYN_SNOTIFY_OK;
            }
            if (n->state != OZAYN_SNOTIFY_STATE_CANCELLED &&
                n->state != OZAYN_SNOTIFY_STATE_EXPIRED &&
                n->state != OZAYN_SNOTIFY_STATE_EXHAUSTED)
                return OZAYN_SNOTIFY_OK;
        }
    }

    ozayn_snotify_notification_t *notif = NULL;
    ozayn_snotify_err_t rc = ozayn_snotify_create(svc, alert, &notif);
    if (rc != OZAYN_SNOTIFY_OK) return rc;
    return OZAYN_SNOTIFY_OK;
}

/* ============================================================
 * SECTION 29 — CANCELLATION
 * ============================================================ */

ozayn_snotify_err_t ozayn_snotify_cancel(
    ozayn_snotify_service_t *svc,
    const char *notif_id)
{
    if (!svc) return OZAYN_SNOTIFY_ERR_NULL;
    if (!svc->initialized) return OZAYN_SNOTIFY_ERR_NOT_INITIALIZED;
    if (!notif_id) return OZAYN_SNOTIFY_ERR_INVALID_PARAM;

    ozayn_snotify_notification_t *n = _find_notif(svc, notif_id);
    if (!n) return OZAYN_SNOTIFY_ERR_NOT_FOUND;

    if (n->state == OZAYN_SNOTIFY_STATE_DELIVERED ||
        n->state == OZAYN_SNOTIFY_STATE_CANCELLED ||
        n->state == OZAYN_SNOTIFY_STATE_EXPIRED ||
        n->state == OZAYN_SNOTIFY_STATE_EXHAUSTED)
        return OZAYN_SNOTIFY_OK;

    n->state = OZAYN_SNOTIFY_STATE_CANCELLED;
    n->delivery_result = OZAYN_SNOTIFY_RESULT_CANCELLED;
    n->notif_version++;
    svc->total_cancelled++;
    _audit_event(svc, "NOTIFICATION_CANCELLED", n);
    return OZAYN_SNOTIFY_OK;
}

/* ============================================================
 * SECTION 30 — PROVIDER MANAGEMENT
 * ============================================================ */

ozayn_snotify_err_t ozayn_snotify_register_provider(
    ozayn_snotify_service_t *svc,
    const ozayn_snotify_provider_vtable_t *vtable,
    const void *context,
    ozayn_salert_notify_channel_t channel)
{
    if (!svc) return OZAYN_SNOTIFY_ERR_NULL;
    if (!svc->initialized) return OZAYN_SNOTIFY_ERR_NOT_INITIALIZED;
    if (!vtable) return OZAYN_SNOTIFY_ERR_NULL;
    if (svc->provider_count >= svc->policy.max_providers &&
        svc->policy.max_providers > 0)
        return OZAYN_SNOTIFY_ERR_LIMIT_REACHED;
    if (svc->provider_count >= OZAYN_SNOTIFY_MAX_PROVIDERS)
        return OZAYN_SNOTIFY_ERR_LIMIT_REACHED;

    for (int i = 0; i < svc->provider_count; i++) {
        if (svc->providers[i].registered &&
            svc->providers[i].channel == channel)
            return OZAYN_SNOTIFY_ERR_CONFLICT;
    }

    ozayn_snotify_provider_t *p = &svc->providers[svc->provider_count];
    memset(p, 0, sizeof(*p));
    p->vtable = vtable;
    p->context = context;
    p->registered = 1;
    p->enabled = 1;
    p->available = 1;
    p->channel = channel;
    svc->provider_count++;
    return OZAYN_SNOTIFY_OK;
}

ozayn_snotify_err_t ozayn_snotify_unregister_provider(
    ozayn_snotify_service_t *svc,
    const char *provider_id)
{
    if (!svc) return OZAYN_SNOTIFY_ERR_NULL;
    if (!svc->initialized) return OZAYN_SNOTIFY_ERR_NOT_INITIALIZED;
    if (!provider_id) return OZAYN_SNOTIFY_ERR_INVALID_PARAM;

    for (int i = 0; i < svc->provider_count; i++) {
        if (svc->providers[i].registered && svc->providers[i].vtable &&
            svc->providers[i].vtable->get_provider_id) {
            const char *id = svc->providers[i].vtable->get_provider_id(
                svc->providers[i].context);
            if (id && strcmp(id, provider_id) == 0) {
                svc->providers[i].registered = 0;
                svc->providers[i].enabled = 0;
                return OZAYN_SNOTIFY_OK;
            }
        }
    }
    return OZAYN_SNOTIFY_ERR_NOT_FOUND;
}

ozayn_snotify_provider_t *ozayn_snotify_get_provider(
    ozayn_snotify_service_t *svc,
    ozayn_salert_notify_channel_t channel)
{
    if (!svc) return NULL;
    for (int i = 0; i < svc->provider_count; i++) {
        if (svc->providers[i].registered &&
            svc->providers[i].channel == channel)
            return &svc->providers[i];
    }
    return NULL;
}

/* ============================================================
 * SECTION 31 — CONCURRENCY & RESOURCE SAFETY
 * ============================================================ */

int ozayn_snotify_queue_is_full(const ozayn_snotify_service_t *svc)
{
    if (!svc) return 1;
    return svc->notif_count >= OZAYN_SNOTIFY_MAX_NOTIFICATIONS;
}

int ozayn_snotify_dest_is_full(const ozayn_snotify_service_t *svc)
{
    if (!svc) return 1;
    if (svc->policy.max_destinations > 0 &&
        svc->dest_count >= svc->policy.max_destinations)
        return 1;
    return svc->dest_count >= OZAYN_SNOTIFY_MAX_DESTINATIONS;
}

int ozayn_snotify_rule_is_full(const ozayn_snotify_service_t *svc)
{
    if (!svc) return 1;
    if (svc->policy.max_routing_rules > 0 &&
        svc->rule_count >= svc->policy.max_routing_rules)
        return 1;
    return svc->rule_count >= OZAYN_SNOTIFY_MAX_ROUTING_RULES;
}

/* ============================================================
 * SECTION 32 — RATE LIMITING
 * ============================================================ */

int ozayn_snotify_check_rate_limit(
    ozayn_snotify_service_t *svc,
    ozayn_salert_notify_channel_t channel)
{
    if (!svc) return 0;
    (void)channel;
    if (svc->policy.max_rate_per_window <= 0) return 1;
    time_t now = time(NULL);
    int recent = 0;
    for (int i = 0; i < svc->notif_count; i++) {
        int slot = (svc->notif_head + i) % OZAYN_SNOTIFY_MAX_NOTIFICATIONS;
        if (svc->notifications[slot].channel == channel &&
            (now - svc->notifications[slot].created_time) <
            svc->policy.rate_window_seconds)
            recent++;
    }
    return recent < svc->policy.max_rate_per_window;
}

/* ============================================================
 * SECTION 33 — AUDIT INTEGRATION
 * ============================================================ */

ozayn_snotify_err_t ozayn_snotify_audit_event(
    ozayn_snotify_service_t *svc,
    const char *event_type,
    const ozayn_snotify_notification_t *notif)
{
    if (!svc) return OZAYN_SNOTIFY_ERR_NULL;
    _audit_event(svc, event_type, notif);
    return OZAYN_SNOTIFY_OK;
}
