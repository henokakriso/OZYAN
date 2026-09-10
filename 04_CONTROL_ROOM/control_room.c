/*
 * control_room.c — Control Room Foundation (Step 01).
 *
 * Implements the Control Room operational backend: lifecycle, state
 * management, component registration, capability registry, control
 * request processing, event observation, monitoring, and policy.
 *
 * The Control Room coordinates existing systems rather than replacing
 * them. It does NOT provide arbitrary command execution or bypass
 * existing security boundaries.
 */

#include "control_room.h"
#include "audit.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

/* ============================================================
 * GLOBAL SINGLETON
 * ============================================================ */

static ozayn_cr_service_t _cr_global = {0};

ozayn_cr_service_t *ozayn_cr_get_global(void)
{
    return &_cr_global;
}

/* ============================================================
 * INTERNAL — ID GENERATION
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

/* ============================================================
 * INTERNAL — AUDIT EVENT
 * ============================================================ */

static void _audit_event(ozayn_cr_service_t *svc,
                          const char *event_type,
                          const char *detail)
{
    if (!svc->audit) return;
    ozayn_audit_service_t *au = (ozayn_audit_service_t *)svc->audit;
    if (!au->initialized) return;
    ozayn_audit_event_t ev;
    ozayn_audit_event_init(&ev);
    ozayn_audit_event_set_type(&ev, OZAYN_AUDIT_CONFIG_CHANGED);
    ozayn_audit_event_set_outcome(&ev, OZAYN_AUDIT_OUTCOME_SUCCESS);
    ozayn_audit_event_set_severity(&ev, OZAYN_AUDIT_SEV_NOTICE);
    ozayn_audit_event_set_source(&ev, "CR");
    char buf[512];
    snprintf(buf, sizeof(buf), "%s: %s", event_type, detail ? detail : "N/A");
    ozayn_audit_event_set_detail(&ev, buf);
    ozayn_audit_record(au, &ev);
}

/* ============================================================
 * INTERNAL — RING BUFFER ALLOCATION
 * ============================================================ */

static ozayn_cr_request_t *_alloc_request(ozayn_cr_service_t *svc)
{
    if (svc->request_count >= OZAYN_CR_MAX_REQUESTS) {
        svc->request_head = (svc->request_head + 1) % OZAYN_CR_MAX_REQUESTS;
        svc->request_count--;
    }
    int slot = (svc->request_head + svc->request_count) % OZAYN_CR_MAX_REQUESTS;
    memset(&svc->requests[slot], 0, sizeof(ozayn_cr_request_t));
    svc->request_count++;
    return &svc->requests[slot];
}

static void _alloc_event(ozayn_cr_service_t *svc,
                          int event_type,
                          const char *source,
                          const char *detail)
{
    if (svc->event_count >= OZAYN_CR_MAX_EVENTS) {
        svc->event_head = (svc->event_head + 1) % OZAYN_CR_MAX_EVENTS;
        svc->event_count--;
    }
    int slot = (svc->event_head + svc->event_count) % OZAYN_CR_MAX_EVENTS;
    memset(&svc->events[slot], 0, sizeof(ozayn_cr_event_entry_t));
    svc->events[slot].event_type = event_type;
    svc->events[slot].timestamp = time(NULL);
    if (source) strncpy(svc->events[slot].source, source, OZAYN_CR_MAX_ID_LEN - 1);
    if (detail) strncpy(svc->events[slot].detail, detail, OZAYN_CR_MAX_META_LEN - 1);
    svc->event_count++;
}

/* ============================================================
 * SECTION 20 — NAME HELPERS — ERRORS
 * ============================================================ */

const char *ozayn_cr_err_name(ozayn_cr_err_t err)
{
    switch (err) {
    case OZAYN_CR_OK:                          return "OK";
    case OZAYN_CR_ERR_NULL:                    return "NULL";
    case OZAYN_CR_ERR_NOT_INITIALIZED:         return "NOT_INITIALIZED";
    case OZAYN_CR_ERR_ALREADY_INITIALIZED:     return "ALREADY_INITIALIZED";
    case OZAYN_CR_ERR_INVALID_PARAM:           return "INVALID_PARAM";
    case OZAYN_CR_ERR_LIMIT_REACHED:           return "LIMIT_REACHED";
    case OZAYN_CR_ERR_NOT_FOUND:               return "NOT_FOUND";
    case OZAYN_CR_ERR_STATE_INVALID:           return "STATE_INVALID";
    case OZAYN_CR_ERR_STATE_TRANSITION:        return "STATE_TRANSITION";
    case OZAYN_CR_ERR_POLICY_REJECTED:         return "POLICY_REJECTED";
    case OZAYN_CR_ERR_REQUEST_INVALID:         return "REQUEST_INVALID";
    case OZAYN_CR_ERR_REQUEST_NOT_FOUND:       return "REQUEST_NOT_FOUND";
    case OZAYN_CR_ERR_REQUEST_UNSUPPORTED:     return "REQUEST_UNSUPPORTED";
    case OZAYN_CR_ERR_TARGET_INVALID:          return "TARGET_INVALID";
    case OZAYN_CR_ERR_TARGET_NOT_FOUND:        return "TARGET_NOT_FOUND";
    case OZAYN_CR_ERR_ACTION_INVALID:          return "ACTION_INVALID";
    case OZAYN_CR_ERR_ACTION_UNSUPPORTED:      return "ACTION_UNSUPPORTED";
    case OZAYN_CR_ERR_OPERATION_FAILED:        return "OPERATION_FAILED";
    case OZAYN_CR_ERR_OPERATION_TIMEOUT:       return "OPERATION_TIMEOUT";
    case OZAYN_CR_ERR_CAPABILITY_INVALID:      return "CAPABILITY_INVALID";
    case OZAYN_CR_ERR_CAPABILITY_UNAVAILABLE:  return "CAPABILITY_UNAVAILABLE";
    case OZAYN_CR_ERR_CAPABILITY_NOT_SUPPORTED: return "CAPABILITY_NOT_SUPPORTED";
    case OZAYN_CR_ERR_EVENT_INVALID:           return "EVENT_INVALID";
    case OZAYN_CR_ERR_MONITOR_INVALID:         return "MONITOR_INVALID";
    case OZAYN_CR_ERR_MONITOR_UNAVAILABLE:     return "MONITOR_UNAVAILABLE";
    case OZAYN_CR_ERR_UNAVAILABLE:             return "UNAVAILABLE";
    }
    return "UNKNOWN";
}

/* ============================================================
 * SECTION 21 — NAME HELPERS — LIFECYCLE
 * ============================================================ */

const char *ozayn_cr_lifecycle_name(ozayn_cr_lifecycle_t lc)
{
    switch (lc) {
    case OZAYN_CR_LC_UNINITIALIZED:  return "UNINITIALIZED";
    case OZAYN_CR_LC_INITIALIZING:   return "INITIALIZING";
    case OZAYN_CR_LC_READY:          return "READY";
    case OZAYN_CR_LC_ACTIVE:         return "ACTIVE";
    case OZAYN_CR_LC_STOPPING:       return "STOPPING";
    case OZAYN_CR_LC_STOPPED:        return "STOPPED";
    case OZAYN_CR_LC_ERROR:          return "ERROR";
    }
    return "UNKNOWN";
}

/* ============================================================
 * SECTION 22 — NAME HELPERS — COMPONENT STATE
 * ============================================================ */

const char *ozayn_cr_comp_state_name(ozayn_cr_comp_state_t s)
{
    switch (s) {
    case OZAYN_CR_COMP_UNKNOWN:      return "UNKNOWN";
    case OZAYN_CR_COMP_INITIALIZING: return "INITIALIZING";
    case OZAYN_CR_COMP_READY:        return "READY";
    case OZAYN_CR_COMP_ACTIVE:       return "ACTIVE";
    case OZAYN_CR_COMP_PAUSED:       return "PAUSED";
    case OZAYN_CR_COMP_STOPPING:     return "STOPPING";
    case OZAYN_CR_COMP_STOPPED:      return "STOPPED";
    case OZAYN_CR_COMP_DEGRADED:     return "DEGRADED";
    case OZAYN_CR_COMP_ERROR:        return "ERROR";
    case OZAYN_CR_COMP_UNAVAILABLE:  return "UNAVAILABLE";
    }
    return "UNKNOWN";
}

/* ============================================================
 * SECTION 23 — NAME HELPERS — COMPONENT TYPE
 * ============================================================ */

const char *ozayn_cr_comp_type_name(ozayn_cr_comp_type_t t)
{
    switch (t) {
    case OZAYN_CR_COMP_TYPE_CORE:      return "CORE";
    case OZAYN_CR_COMP_TYPE_MODULE:    return "MODULE";
    case OZAYN_CR_COMP_TYPE_TASK:      return "TASK";
    case OZAYN_CR_COMP_TYPE_PROCESS:   return "PROCESS";
    case OZAYN_CR_COMP_TYPE_SECURITY:  return "SECURITY";
    case OZAYN_CR_COMP_TYPE_DEVICE:    return "DEVICE";
    case OZAYN_CR_COMP_TYPE_INPUT:     return "INPUT";
    case OZAYN_CR_COMP_TYPE_OUTPUT:    return "OUTPUT";
    case OZAYN_CR_COMP_TYPE_VISION:    return "VISION";
    case OZAYN_CR_COMP_TYPE_AI:        return "AI";
    case OZAYN_CR_COMP_TYPE_ARWE:      return "ARWE";
    case OZAYN_CR_COMP_TYPE_CUSTOM:    return "CUSTOM";
    }
    return "UNKNOWN";
}

/* ============================================================
 * SECTION 24 — NAME HELPERS — CAPABILITY TYPE
 * ============================================================ */

const char *ozayn_cr_cap_type_name(ozayn_cr_cap_type_t t)
{
    if (t >= 0 && t < OZAYN_CR_CAP_COUNT) {
        static const char *names[OZAYN_CR_CAP_COUNT] = {
            "CORE_MONITORING", "MODULE_MONITORING", "TASK_MONITORING",
            "PROCESS_MONITORING", "MODULE_CONTROL", "TASK_CONTROL",
            "PROCESS_CONTROL", "DEVICE_MONITORING", "DEVICE_CONTROL",
            "CAMERA_INPUT", "MICROPHONE_INPUT", "VOICE_INPUT",
            "GESTURE_INPUT", "FACE_INPUT", "VISION_PROCESSING",
            "3D_RENDERING", "AI_PROCESSING", "MEMORY_ACCESS",
            "ARWE_INTEGRATION", "WEB_INTELLIGENCE", "SECURITY_MONITORING",
            "SECURITY_CONTROL"
        };
        return names[t];
    }
    return "UNKNOWN";
}

/* ============================================================
 * SECTION 25 — NAME HELPERS — ACTION
 * ============================================================ */

const char *ozayn_cr_action_name(ozayn_cr_action_t a)
{
    switch (a) {
    case OZAYN_CR_ACTION_START:      return "START";
    case OZAYN_CR_ACTION_STOP:       return "STOP";
    case OZAYN_CR_ACTION_PAUSE:      return "PAUSE";
    case OZAYN_CR_ACTION_RESUME:     return "RESUME";
    case OZAYN_CR_ACTION_QUERY:      return "QUERY";
    case OZAYN_CR_ACTION_RESTART:    return "RESTART";
    case OZAYN_CR_ACTION_ENABLE:     return "ENABLE";
    case OZAYN_CR_ACTION_DISABLE:    return "DISABLE";
    case OZAYN_CR_ACTION_DIAGNOSTIC: return "DIAGNOSTIC";
    case OZAYN_CR_ACTION_COUNT:      return "COUNT";
    }
    return "UNKNOWN";
}

/* ============================================================
 * SECTION 26 — NAME HELPERS — REQUEST STATE
 * ============================================================ */

const char *ozayn_cr_req_state_name(ozayn_cr_req_state_t s)
{
    switch (s) {
    case OZAYN_CR_REQ_STATE_CREATED:    return "CREATED";
    case OZAYN_CR_REQ_STATE_VALIDATED:  return "VALIDATED";
    case OZAYN_CR_REQ_STATE_AUTHORIZED: return "AUTHORIZED";
    case OZAYN_CR_REQ_STATE_ACCEPTED:   return "ACCEPTED";
    case OZAYN_CR_REQ_STATE_RUNNING:    return "RUNNING";
    case OZAYN_CR_REQ_STATE_SUCCEEDED:  return "SUCCEEDED";
    case OZAYN_CR_REQ_STATE_FAILED:     return "FAILED";
    case OZAYN_CR_REQ_STATE_CANCELLED:  return "CANCELLED";
    case OZAYN_CR_REQ_STATE_TIMEOUT:    return "TIMEOUT";
    case OZAYN_CR_REQ_STATE_REJECTED:   return "REJECTED";
    case OZAYN_CR_REQ_STATE_UNAVAILABLE: return "UNAVAILABLE";
    case OZAYN_CR_REQ_STATE_UNSUPPORTED: return "UNSUPPORTED";
    }
    return "UNKNOWN";
}

/* ============================================================
 * SECTION 27 — NAME HELPERS — RESULT STATE
 * ============================================================ */

const char *ozayn_cr_result_state_name(ozayn_cr_result_state_t s)
{
    switch (s) {
    case OZAYN_CR_RESULT_ACCEPTED:   return "ACCEPTED";
    case OZAYN_CR_RESULT_REJECTED:   return "REJECTED";
    case OZAYN_CR_RESULT_PENDING:    return "PENDING";
    case OZAYN_CR_RESULT_RUNNING:    return "RUNNING";
    case OZAYN_CR_RESULT_SUCCEEDED:  return "SUCCEEDED";
    case OZAYN_CR_RESULT_FAILED:     return "FAILED";
    case OZAYN_CR_RESULT_CANCELLED:  return "CANCELLED";
    case OZAYN_CR_RESULT_TIMEOUT:    return "TIMEOUT";
    case OZAYN_CR_RESULT_UNAVAILABLE: return "UNAVAILABLE";
    case OZAYN_CR_RESULT_UNSUPPORTED: return "UNSUPPORTED";
    }
    return "UNKNOWN";
}

/* ============================================================
 * SECTION 28 — NAME HELPERS — CORE STATE
 * ============================================================ */

const char *ozayn_cr_core_state_name(ozayn_cr_core_state_t s)
{
    switch (s) {
    case OZAYN_CR_CORE_STATE_UNKNOWN:        return "UNKNOWN";
    case OZAYN_CR_CORE_STATE_STARTING:       return "STARTING";
    case OZAYN_CR_CORE_STATE_ONLINE:         return "ONLINE";
    case OZAYN_CR_CORE_STATE_DEGRADED:       return "DEGRADED";
    case OZAYN_CR_CORE_STATE_SHUTTING_DOWN:  return "SHUTTING_DOWN";
    case OZAYN_CR_CORE_STATE_OFFLINE:        return "OFFLINE";
    case OZAYN_CR_CORE_STATE_ERROR:          return "ERROR";
    }
    return "UNKNOWN";
}

/* ============================================================
 * SECTION 29 — LIFECYCLE
 * ============================================================ */

ozayn_cr_err_t ozayn_cr_service_init(
    ozayn_cr_service_t *svc,
    const ozayn_cr_service_config_t *cfg)
{
    if (!svc) return OZAYN_CR_ERR_NULL;
    if (svc->initialized) return OZAYN_CR_ERR_ALREADY_INITIALIZED;

    memset(svc, 0, sizeof(*svc));

    if (cfg) {
        svc->audit = (void *)cfg->audit;
    }

    svc->policy = ozayn_cr_default_policy();
    svc->lifecycle = OZAYN_CR_LC_INITIALIZING;
    svc->core_state = OZAYN_CR_CORE_STATE_STARTING;
    svc->version = 1;
    svc->start_time = time(NULL);
    svc->last_update = svc->start_time;
    svc->initialized = 1;

    _audit_event(svc, "INIT", "Control Room initialized");
    return OZAYN_CR_OK;
}

void ozayn_cr_service_shutdown(ozayn_cr_service_t *svc)
{
    if (!svc) return;
    _audit_event(svc, "SHUTDOWN", "Control Room shutting down");
    svc->lifecycle = OZAYN_CR_LC_STOPPING;
    svc->core_state = OZAYN_CR_CORE_STATE_SHUTTING_DOWN;
    svc->lifecycle = OZAYN_CR_LC_STOPPED;
    svc->core_state = OZAYN_CR_CORE_STATE_OFFLINE;
    svc->initialized = 0;
}

int ozayn_cr_service_is_initialized(const ozayn_cr_service_t *svc)
{
    return svc ? svc->initialized : 0;
}

/* ============================================================
 * SECTION 30 — STATE QUERY
 * ============================================================ */

ozayn_cr_err_t ozayn_cr_get_state(
    const ozayn_cr_service_t *svc,
    ozayn_cr_state_t *out_state)
{
    if (!svc) return OZAYN_CR_ERR_NULL;
    if (!svc->initialized) return OZAYN_CR_ERR_NOT_INITIALIZED;
    if (!out_state) return OZAYN_CR_ERR_INVALID_PARAM;

    memset(out_state, 0, sizeof(*out_state));
    out_state->lifecycle = svc->lifecycle;
    out_state->core_state = svc->core_state;
    out_state->version = svc->version;
    out_state->start_time = svc->start_time;
    out_state->last_update = svc->last_update;
    out_state->component_count = svc->component_count;
    out_state->active_requests = svc->request_count;
    out_state->event_count = svc->event_count;
    out_state->capability_count = svc->capability_count;

    const char *lc_name = ozayn_cr_lifecycle_name(svc->lifecycle);
    const char *cs_name = ozayn_cr_core_state_name(svc->core_state);
    snprintf(out_state->safe_status, OZAYN_CR_MAX_META_LEN,
             "LC:%s CORE:%s COMP:%d REQ:%d EVT:%d",
             lc_name, cs_name,
             svc->component_count, svc->request_count, svc->event_count);

    ((ozayn_cr_service_t *)svc)->total_state_queries++;
    return OZAYN_CR_OK;
}

/* ============================================================
 * SECTION 31 — LIFECYCLE TRANSITIONS
 * ============================================================ */

ozayn_cr_err_t ozayn_cr_activate(ozayn_cr_service_t *svc)
{
    if (!svc) return OZAYN_CR_ERR_NULL;
    if (!svc->initialized) return OZAYN_CR_ERR_NOT_INITIALIZED;
    if (svc->lifecycle != OZAYN_CR_LC_READY)
        return OZAYN_CR_ERR_STATE_TRANSITION;

    svc->lifecycle = OZAYN_CR_LC_ACTIVE;
    svc->core_state = OZAYN_CR_CORE_STATE_ONLINE;
    svc->last_update = time(NULL);
    _audit_event(svc, "ACTIVATE", "Control Room activated");
    return OZAYN_CR_OK;
}

ozayn_cr_err_t ozayn_cr_deactivate(ozayn_cr_service_t *svc)
{
    if (!svc) return OZAYN_CR_ERR_NULL;
    if (!svc->initialized) return OZAYN_CR_ERR_NOT_INITIALIZED;
    if (svc->lifecycle != OZAYN_CR_LC_ACTIVE)
        return OZAYN_CR_ERR_STATE_TRANSITION;

    svc->lifecycle = OZAYN_CR_LC_READY;
    svc->core_state = OZAYN_CR_CORE_STATE_OFFLINE;
    svc->last_update = time(NULL);
    _audit_event(svc, "DEACTIVATE", "Control Room deactivated");
    return OZAYN_CR_OK;
}

ozayn_cr_err_t ozayn_cr_set_error(ozayn_cr_service_t *svc)
{
    if (!svc) return OZAYN_CR_ERR_NULL;
    if (!svc->initialized) return OZAYN_CR_ERR_NOT_INITIALIZED;

    svc->lifecycle = OZAYN_CR_LC_ERROR;
    svc->core_state = OZAYN_CR_CORE_STATE_ERROR;
    svc->last_update = time(NULL);
    _audit_event(svc, "ERROR", "Control Room entered error state");
    return OZAYN_CR_OK;
}

/* ============================================================
 * SECTION 32 — COMPONENT REGISTRATION
 * ============================================================ */

ozayn_cr_err_t ozayn_cr_register_component(
    ozayn_cr_service_t *svc,
    const char *component_id,
    ozayn_cr_comp_type_t type,
    ozayn_cr_comp_state_t initial_state)
{
    if (!svc) return OZAYN_CR_ERR_NULL;
    if (!svc->initialized) return OZAYN_CR_ERR_NOT_INITIALIZED;
    if (!component_id || !component_id[0]) return OZAYN_CR_ERR_INVALID_PARAM;
    if (svc->component_count >= svc->policy.max_components)
        return OZAYN_CR_ERR_LIMIT_REACHED;

    /* Check duplicate */
    for (int i = 0; i < svc->component_count; i++) {
        if (strcmp(svc->components[i].component_id, component_id) == 0)
            return OZAYN_CR_ERR_ALREADY_INITIALIZED;
    }

    ozayn_cr_monitor_t *m = &svc->components[svc->component_count];
    memset(m, 0, sizeof(*m));
    strncpy(m->component_id, component_id, OZAYN_CR_MAX_ID_LEN - 1);
    m->component_type = type;
    m->state = initial_state;
    m->availability = 1;
    m->health = 100;
    m->last_update = time(NULL);
    svc->component_count++;
    svc->total_components_registered++;
    svc->last_update = time(NULL);
    return OZAYN_CR_OK;
}

ozayn_cr_monitor_t *ozayn_cr_get_component(
    ozayn_cr_service_t *svc,
    const char *component_id)
{
    if (!svc || !svc->initialized || !component_id) return NULL;
    for (int i = 0; i < svc->component_count; i++) {
        if (strcmp(svc->components[i].component_id, component_id) == 0)
            return &svc->components[i];
    }
    return NULL;
}

int ozayn_cr_component_count(const ozayn_cr_service_t *svc)
{
    return svc ? svc->component_count : 0;
}

ozayn_cr_err_t ozayn_cr_update_component_state(
    ozayn_cr_service_t *svc,
    const char *component_id,
    ozayn_cr_comp_state_t new_state)
{
    if (!svc) return OZAYN_CR_ERR_NULL;
    if (!svc->initialized) return OZAYN_CR_ERR_NOT_INITIALIZED;

    ozayn_cr_monitor_t *m = ozayn_cr_get_component(svc, component_id);
    if (!m) return OZAYN_CR_ERR_NOT_FOUND;

    m->state = new_state;
    m->last_update = time(NULL);
    svc->last_update = time(NULL);
    return OZAYN_CR_OK;
}

/* ============================================================
 * SECTION 33 — CAPABILITY REGISTRATION
 * ============================================================ */

ozayn_cr_err_t ozayn_cr_register_capability(
    ozayn_cr_service_t *svc,
    ozayn_cr_cap_type_t type,
    int available,
    const char *description)
{
    if (!svc) return OZAYN_CR_ERR_NULL;
    if (!svc->initialized) return OZAYN_CR_ERR_NOT_INITIALIZED;
    if (type < 0 || type >= OZAYN_CR_CAP_COUNT)
        return OZAYN_CR_ERR_CAPABILITY_INVALID;
    if (svc->capability_count >= svc->policy.max_capabilities)
        return OZAYN_CR_ERR_LIMIT_REACHED;

    /* Check duplicate */
    for (int i = 0; i < svc->capability_count; i++) {
        if (svc->capabilities[i].type == type)
            return OZAYN_CR_ERR_ALREADY_INITIALIZED;
    }

    ozayn_cr_capability_t *cap = &svc->capabilities[svc->capability_count];
    memset(cap, 0, sizeof(*cap));
    cap->type = type;
    cap->enabled = 1;
    cap->available = available;
    if (description)
        strncpy(cap->description, description, OZAYN_CR_MAX_META_LEN - 1);
    svc->capability_count++;
    svc->total_capabilities_registered++;
    svc->last_update = time(NULL);
    return OZAYN_CR_OK;
}

ozayn_cr_capability_t *ozayn_cr_get_capability(
    ozayn_cr_service_t *svc,
    ozayn_cr_cap_type_t type)
{
    if (!svc || !svc->initialized) return NULL;
    for (int i = 0; i < svc->capability_count; i++) {
        if (svc->capabilities[i].type == type)
            return &svc->capabilities[i];
    }
    return NULL;
}

int ozayn_cr_capability_count(const ozayn_cr_service_t *svc)
{
    return svc ? svc->capability_count : 0;
}

int ozayn_cr_capability_available(
    const ozayn_cr_service_t *svc,
    ozayn_cr_cap_type_t type)
{
    if (!svc || !svc->initialized) return 0;
    for (int i = 0; i < svc->capability_count; i++) {
        if (svc->capabilities[i].type == type)
            return svc->capabilities[i].enabled && svc->capabilities[i].available;
    }
    return 0;
}

/* ============================================================
 * SECTION 34 — CONTROL REQUESTS
 * ============================================================ */

ozayn_cr_err_t ozayn_cr_create_request(
    ozayn_cr_service_t *svc,
    ozayn_cr_action_t action,
    const char *target,
    const char *context,
    ozayn_cr_request_t **out_request)
{
    if (!svc) return OZAYN_CR_ERR_NULL;
    if (!svc->initialized) return OZAYN_CR_ERR_NOT_INITIALIZED;
    if (action < 0 || action >= OZAYN_CR_ACTION_COUNT)
        return OZAYN_CR_ERR_ACTION_INVALID;
    if (!target || !target[0]) return OZAYN_CR_ERR_TARGET_INVALID;
    if (!svc->policy.enabled) {
        svc->total_requests_rejected++;
        return OZAYN_CR_ERR_POLICY_REJECTED;
    }

    ozayn_cr_request_t *req = _alloc_request(svc);
    svc->request_sequence++;
    _generate_id(req->request_id, OZAYN_CR_MAX_ID_LEN, "CRQ", svc->request_sequence);
    req->request_version = 1;
    req->action = action;
    strncpy(req->target, target, OZAYN_CR_MAX_TARGET_LEN - 1);
    if (context) strncpy(req->context, context, OZAYN_CR_MAX_META_LEN - 1);
    req->state = OZAYN_CR_REQ_STATE_CREATED;
    req->result_state = OZAYN_CR_RESULT_PENDING;
    req->request_time = time(NULL);

    svc->total_requests_created++;
    svc->last_update = time(NULL);

    if (out_request) *out_request = req;
    return OZAYN_CR_OK;
}

ozayn_cr_request_t *ozayn_cr_get_request(
    ozayn_cr_service_t *svc,
    const char *request_id)
{
    if (!svc || !svc->initialized || !request_id) return NULL;
    /* Ring buffer search — most recent first */
    for (int i = svc->request_count - 1; i >= 0; i--) {
        int idx = (svc->request_head + i) % OZAYN_CR_MAX_REQUESTS;
        if (strcmp(svc->requests[idx].request_id, request_id) == 0)
            return &svc->requests[idx];
    }
    return NULL;
}

int ozayn_cr_request_count(const ozayn_cr_service_t *svc)
{
    return svc ? svc->request_count : 0;
}

/* ============================================================
 * SECTION 35 — CONTROL EXECUTION
 * ============================================================ */

ozayn_cr_err_t ozayn_cr_validate_request(
    const ozayn_cr_service_t *svc,
    const ozayn_cr_request_t *request)
{
    if (!svc) return OZAYN_CR_ERR_NULL;
    if (!svc->initialized) return OZAYN_CR_ERR_NOT_INITIALIZED;
    if (!request) return OZAYN_CR_ERR_REQUEST_INVALID;

    if (request->action < 0 || request->action >= OZAYN_CR_ACTION_COUNT)
        return OZAYN_CR_ERR_ACTION_INVALID;

    if (!request->target[0])
        return OZAYN_CR_ERR_TARGET_INVALID;

    /* Check that target exists as a registered component */
    int found = 0;
    for (int i = 0; i < svc->component_count; i++) {
        if (strcmp(svc->components[i].component_id, request->target) == 0) {
            found = 1;
            break;
        }
    }
    if (!found) return OZAYN_CR_ERR_TARGET_NOT_FOUND;

    /* Validate request state */
    if (request->state != OZAYN_CR_REQ_STATE_CREATED &&
        request->state != OZAYN_CR_REQ_STATE_VALIDATED &&
        request->state != OZAYN_CR_REQ_STATE_AUTHORIZED)
        return OZAYN_CR_ERR_STATE_INVALID;

    return OZAYN_CR_OK;
}

ozayn_cr_err_t ozayn_cr_execute_request(
    ozayn_cr_service_t *svc,
    ozayn_cr_request_t *request,
    ozayn_cr_result_t *out_result)
{
    if (!svc) return OZAYN_CR_ERR_NULL;
    if (!svc->initialized) return OZAYN_CR_ERR_NOT_INITIALIZED;
    if (!request) return OZAYN_CR_ERR_REQUEST_INVALID;
    if (!out_result) return OZAYN_CR_ERR_INVALID_PARAM;

    /* Validate first */
    ozayn_cr_err_t rv = ozayn_cr_validate_request(svc, request);
    if (rv != OZAYN_CR_OK) return rv;

    /* Transition to validated */
    request->state = OZAYN_CR_REQ_STATE_VALIDATED;

    /* In foundation: accept QUERY action only, others are unsupported */
    if (request->action == OZAYN_CR_ACTION_QUERY) {
        request->state = OZAYN_CR_REQ_STATE_ACCEPTED;
        request->state = OZAYN_CR_REQ_STATE_RUNNING;
        request->state = OZAYN_CR_REQ_STATE_SUCCEEDED;
        request->result_state = OZAYN_CR_RESULT_SUCCEEDED;
        request->result_code = 0;
        request->completion_time = time(NULL);
        svc->total_requests_succeeded++;
    } else {
        /* All non-QUERY actions are unsupported in foundation */
        request->state = OZAYN_CR_REQ_STATE_UNSUPPORTED;
        request->result_state = OZAYN_CR_RESULT_UNSUPPORTED;
        request->result_code = -1;
        request->completion_time = time(NULL);
        svc->total_requests_failed++;
    }

    /* Fill result */
    memset(out_result, 0, sizeof(*out_result));
    strncpy(out_result->request_id, request->request_id, OZAYN_CR_MAX_ID_LEN - 1);
    out_result->result_state = request->result_state;
    strncpy(out_result->target, request->target, OZAYN_CR_MAX_TARGET_LEN - 1);
    out_result->action = request->action;
    out_result->result_code = request->result_code;
    out_result->completion_time = request->completion_time;

    svc->last_update = time(NULL);

    char detail[256];
    snprintf(detail, sizeof(detail), "REQ:%s ACT:%s TGT:%s RES:%s",
             request->request_id,
             ozayn_cr_action_name(request->action),
             request->target,
             ozayn_cr_result_state_name(request->result_state));
    _audit_event(svc, "EXECUTE", detail);

    return OZAYN_CR_OK;
}

/* ============================================================
 * SECTION 36 — EVENT OBSERVATION
 * ============================================================ */

ozayn_cr_err_t ozayn_cr_observe_event(
    ozayn_cr_service_t *svc,
    int event_type,
    const char *source,
    const char *detail)
{
    if (!svc) return OZAYN_CR_ERR_NULL;
    if (!svc->initialized) return OZAYN_CR_ERR_NOT_INITIALIZED;
    if (event_type <= 0) return OZAYN_CR_ERR_EVENT_INVALID;
    if (!svc->policy.enabled) return OZAYN_CR_ERR_POLICY_REJECTED;

    _alloc_event(svc, event_type, source, detail);
    svc->total_events_observed++;
    svc->last_update = time(NULL);
    return OZAYN_CR_OK;
}

int ozayn_cr_event_count(const ozayn_cr_service_t *svc)
{
    return svc ? svc->event_count : 0;
}

/* ============================================================
 * SECTION 37 — MONITOR MANAGEMENT
 * ============================================================ */

ozayn_cr_err_t ozayn_cr_create_monitor(
    ozayn_cr_service_t *svc,
    const char *component_id,
    ozayn_cr_comp_type_t type,
    ozayn_cr_monitor_t **out_monitor)
{
    if (!svc) return OZAYN_CR_ERR_NULL;
    if (!svc->initialized) return OZAYN_CR_ERR_NOT_INITIALIZED;
    if (!component_id || !component_id[0]) return OZAYN_CR_ERR_INVALID_PARAM;
    if (svc->monitor_count >= svc->policy.max_monitors)
        return OZAYN_CR_ERR_LIMIT_REACHED;

    /* Check duplicate */
    for (int i = 0; i < svc->monitor_count; i++) {
        if (strcmp(svc->monitors[i].component_id, component_id) == 0)
            return OZAYN_CR_ERR_ALREADY_INITIALIZED;
    }

    ozayn_cr_monitor_t *m = &svc->monitors[svc->monitor_count];
    memset(m, 0, sizeof(*m));
    strncpy(m->component_id, component_id, OZAYN_CR_MAX_ID_LEN - 1);
    m->component_type = type;
    m->state = OZAYN_CR_COMP_INITIALIZING;
    m->availability = 1;
    m->health = 100;
    m->last_update = time(NULL);
    svc->monitor_count++;
    svc->last_update = time(NULL);

    if (out_monitor) *out_monitor = m;
    return OZAYN_CR_OK;
}

ozayn_cr_monitor_t *ozayn_cr_get_monitor(
    ozayn_cr_service_t *svc,
    const char *component_id)
{
    if (!svc || !svc->initialized || !component_id) return NULL;
    for (int i = 0; i < svc->monitor_count; i++) {
        if (strcmp(svc->monitors[i].component_id, component_id) == 0)
            return &svc->monitors[i];
    }
    return NULL;
}

int ozayn_cr_monitor_count(const ozayn_cr_service_t *svc)
{
    return svc ? svc->monitor_count : 0;
}

ozayn_cr_err_t ozayn_cr_update_monitor(
    ozayn_cr_service_t *svc,
    const char *component_id,
    ozayn_cr_comp_state_t state,
    int availability,
    int health)
{
    if (!svc) return OZAYN_CR_ERR_NULL;
    if (!svc->initialized) return OZAYN_CR_ERR_NOT_INITIALIZED;

    ozayn_cr_monitor_t *m = ozayn_cr_get_monitor(svc, component_id);
    if (!m) return OZAYN_CR_ERR_NOT_FOUND;

    m->state = state;
    m->availability = availability;
    m->health = health;
    m->last_update = time(NULL);
    svc->last_update = time(NULL);
    return OZAYN_CR_OK;
}

/* ============================================================
 * SECTION 38 — POLICY
 * ============================================================ */

ozayn_cr_policy_t ozayn_cr_default_policy(void)
{
    ozayn_cr_policy_t p;
    memset(&p, 0, sizeof(p));
    p.enabled = 1;
    p.max_components = OZAYN_CR_MAX_COMPONENTS;
    p.max_capabilities = OZAYN_CR_MAX_CAPABILITIES;
    p.max_requests = OZAYN_CR_MAX_REQUESTS;
    p.max_events = OZAYN_CR_MAX_EVENTS;
    p.max_monitors = OZAYN_CR_MAX_MONITORS;
    p.require_authorization = 0;
    p.require_approval = 0;
    return p;
}

ozayn_cr_err_t ozayn_cr_set_policy(
    ozayn_cr_service_t *svc,
    const ozayn_cr_policy_t *policy)
{
    if (!svc) return OZAYN_CR_ERR_NULL;
    if (!svc->initialized) return OZAYN_CR_ERR_NOT_INITIALIZED;
    if (!policy) return OZAYN_CR_ERR_INVALID_PARAM;
    svc->policy = *policy;
    svc->last_update = time(NULL);
    return OZAYN_CR_OK;
}

const ozayn_cr_policy_t *ozayn_cr_get_policy(const ozayn_cr_service_t *svc)
{
    if (!svc || !svc->initialized) return NULL;
    return &svc->policy;
}

/* ============================================================
 * SECTION 39 — AUDIT INTEGRATION
 * ============================================================ */

ozayn_cr_err_t ozayn_cr_audit_event(
    ozayn_cr_service_t *svc,
    const char *event_type,
    const char *detail)
{
    if (!svc) return OZAYN_CR_ERR_NULL;
    if (!svc->initialized) return OZAYN_CR_ERR_NOT_INITIALIZED;
    _audit_event(svc, event_type, detail);
    return OZAYN_CR_OK;
}

/* ============================================================
 * SECTION 40 — RESOURCE SAFETY
 * ============================================================ */

int ozayn_cr_components_full(const ozayn_cr_service_t *svc)
{
    if (!svc) return 1;
    return svc->component_count >= svc->policy.max_components;
}

int ozayn_cr_capabilities_full(const ozayn_cr_service_t *svc)
{
    if (!svc) return 1;
    return svc->capability_count >= svc->policy.max_capabilities;
}

int ozayn_cr_requests_full(const ozayn_cr_service_t *svc)
{
    if (!svc) return 1;
    return svc->request_count >= svc->policy.max_requests;
}

int ozayn_cr_events_full(const ozayn_cr_service_t *svc)
{
    if (!svc) return 1;
    return svc->event_count >= svc->policy.max_events;
}

/* ============================================================
 * SECTION 41 — STATISTICS
 * ============================================================ */

uint64_t ozayn_cr_total_requests(const ozayn_cr_service_t *svc)
{
    return svc ? svc->total_requests_created : 0;
}

uint64_t ozayn_cr_total_events(const ozayn_cr_service_t *svc)
{
    return svc ? svc->total_events_observed : 0;
}

/* ============================================================
 * SECTION 42 — CLEANUP
 * ============================================================ */

int ozayn_cr_cleanup_expired_requests(ozayn_cr_service_t *svc)
{
    if (!svc || !svc->initialized) return 0;
    int removed = 0;
    time_t now = time(NULL);
    for (int i = 0; i < svc->request_count; ) {
        int idx = (svc->request_head + i) % OZAYN_CR_MAX_REQUESTS;
        ozayn_cr_request_t *req = &svc->requests[idx];
        if ((req->state == OZAYN_CR_REQ_STATE_SUCCEEDED ||
             req->state == OZAYN_CR_REQ_STATE_FAILED ||
             req->state == OZAYN_CR_REQ_STATE_CANCELLED) &&
            req->completion_time > 0 &&
            (now - req->completion_time) > 3600) {
            /* Remove by shifting */
            for (int j = i; j < svc->request_count - 1; j++) {
                int cur = (svc->request_head + j) % OZAYN_CR_MAX_REQUESTS;
                int nxt = (svc->request_head + j + 1) % OZAYN_CR_MAX_REQUESTS;
                svc->requests[cur] = svc->requests[nxt];
            }
            svc->request_count--;
            removed++;
        } else {
            i++;
        }
    }
    return removed;
}

int ozayn_cr_cleanup_expired_events(ozayn_cr_service_t *svc)
{
    if (!svc || !svc->initialized) return 0;
    int removed = 0;
    time_t now = time(NULL);
    for (int i = 0; i < svc->event_count; ) {
        int idx = (svc->event_head + i) % OZAYN_CR_MAX_EVENTS;
        if (svc->events[idx].timestamp > 0 &&
            (now - svc->events[idx].timestamp) > 3600) {
            for (int j = i; j < svc->event_count - 1; j++) {
                int cur = (svc->event_head + j) % OZAYN_CR_MAX_EVENTS;
                int nxt = (svc->event_head + j + 1) % OZAYN_CR_MAX_EVENTS;
                svc->events[cur] = svc->events[nxt];
            }
            svc->event_count--;
            removed++;
        } else {
            i++;
        }
    }
    return removed;
}
