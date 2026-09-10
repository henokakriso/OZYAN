/*
 * operation_queue.c — Controlled Operation Queue & Execution Lifecycle
 *
 * Implements bounded, observable, deterministic, and security-aware
 * operation queuing for the OZAYN Control Room.
 */

#include "operation_queue.h"
#include "component_registry.h"
#include <string.h>
#include <stdio.h>
#include <time.h>

/* ============================================================
 * GLOBAL SINGLETON
 * ============================================================ */

static ozayn_oq_service_t _oq_global = {0};

ozayn_oq_service_t *ozayn_oq_get_global(void)
{
    return &_oq_global;
}

/* ============================================================
 * SECTION 9 — NAME HELPERS
 * ============================================================ */

const char *ozayn_oq_err_name(ozayn_oq_err_t err)
{
    switch (err) {
    case OZAYN_OQ_OK:                           return "OK";
    case OZAYN_OQ_ERR_NULL:                     return "NULL";
    case OZAYN_OQ_ERR_NOT_INITIALIZED:          return "NOT_INITIALIZED";
    case OZAYN_OQ_ERR_ALREADY_INITIALIZED:      return "ALREADY_INITIALIZED";
    case OZAYN_OQ_ERR_INVALID_PARAM:            return "INVALID_PARAM";
    case OZAYN_OQ_ERR_QUEUE_FULL:               return "QUEUE_FULL";
    case OZAYN_OQ_ERR_NOT_FOUND:                return "NOT_FOUND";
    case OZAYN_OQ_ERR_STATE_INVALID:            return "STATE_INVALID";
    case OZAYN_OQ_ERR_STATE_TRANSITION:         return "STATE_TRANSITION";
    case OZAYN_OQ_ERR_CANCELLATION_UNSUPPORTED: return "CANCELLATION_UNSUPPORTED";
    case OZAYN_OQ_ERR_DUPLICATE_REQUEST:        return "DUPLICATE_REQUEST";
    case OZAYN_OQ_ERR_TIMEOUT:                  return "TIMEOUT";
    case OZAYN_OQ_ERR_PRECONDITION_FAILED:      return "PRECONDITION_FAILED";
    case OZAYN_OQ_ERR_UNAVAILABLE:              return "UNAVAILABLE";
    case OZAYN_OQ_ERR_RESOURCE_LIMIT:           return "RESOURCE_LIMIT";
    case OZAYN_OQ_ERR_DISPATCH_FAILED:          return "DISPATCH_FAILED";
    case OZAYN_OQ_ERR_RETRY_EXHAUSTED:          return "RETRY_EXHAUSTED";
    }
    return "UNKNOWN";
}

const char *ozayn_oq_state_name(ozayn_oq_state_t state)
{
    switch (state) {
    case OZAYN_OQ_STATE_CREATED:      return "CREATED";
    case OZAYN_OQ_STATE_QUEUED:       return "QUEUED";
    case OZAYN_OQ_STATE_WAITING:      return "WAITING";
    case OZAYN_OQ_STATE_DISPATCHING:  return "DISPATCHING";
    case OZAYN_OQ_STATE_RUNNING:      return "RUNNING";
    case OZAYN_OQ_STATE_SUCCEEDED:    return "SUCCEEDED";
    case OZAYN_OQ_STATE_FAILED:       return "FAILED";
    case OZAYN_OQ_STATE_REJECTED:     return "REJECTED";
    case OZAYN_OQ_STATE_CANCELLED:    return "CANCELLED";
    case OZAYN_OQ_STATE_TIMEOUT:      return "TIMEOUT";
    case OZAYN_OQ_STATE_EXPIRED:      return "EXPIRED";
    case OZAYN_OQ_STATE_UNAVAILABLE:  return "UNAVAILABLE";
    case OZAYN_OQ_STATE_COUNT:        return "COUNT";
    }
    return "UNKNOWN";
}

const char *ozayn_oq_priority_name(ozayn_oq_priority_t priority)
{
    switch (priority) {
    case OZAYN_OQ_PRIORITY_LOW:      return "LOW";
    case OZAYN_OQ_PRIORITY_NORMAL:   return "NORMAL";
    case OZAYN_OQ_PRIORITY_HIGH:     return "HIGH";
    case OZAYN_OQ_PRIORITY_CRITICAL: return "CRITICAL";
    case OZAYN_OQ_PRIORITY_COUNT:    return "COUNT";
    }
    return "UNKNOWN";
}

const char *ozayn_oq_action_name(ozayn_oq_action_t action)
{
    switch (action) {
    case OZAYN_OQ_ACTION_START:     return "START";
    case OZAYN_OQ_ACTION_STOP:      return "STOP";
    case OZAYN_OQ_ACTION_PAUSE:     return "PAUSE";
    case OZAYN_OQ_ACTION_RESUME:    return "RESUME";
    case OZAYN_OQ_ACTION_QUERY:     return "QUERY";
    case OZAYN_OQ_ACTION_RESTART:   return "RESTART";
    case OZAYN_OQ_ACTION_ENABLE:    return "ENABLE";
    case OZAYN_OQ_ACTION_DISABLE:   return "DISABLE";
    case OZAYN_OQ_ACTION_DIAGNOSTIC:return "DIAGNOSTIC";
    case OZAYN_OQ_ACTION_COUNT:     return "COUNT";
    }
    return "UNKNOWN";
}

const char *ozayn_oq_event_type_name(ozayn_oq_event_type_t type)
{
    switch (type) {
    case OZAYN_OQ_EVENT_CREATED:             return "CREATED";
    case OZAYN_OQ_EVENT_QUEUED:              return "QUEUED";
    case OZAYN_OQ_EVENT_WAITING:             return "WAITING";
    case OZAYN_OQ_EVENT_DISPATCHING:         return "DISPATCHING";
    case OZAYN_OQ_EVENT_STARTED:             return "STARTED";
    case OZAYN_OQ_EVENT_SUCCEEDED:           return "SUCCEEDED";
    case OZAYN_OQ_EVENT_FAILED:              return "FAILED";
    case OZAYN_OQ_EVENT_CANCELLED:           return "CANCELLED";
    case OZAYN_OQ_EVENT_TIMEOUT:             return "TIMEOUT";
    case OZAYN_OQ_EVENT_EXPIRED:             return "EXPIRED";
    case OZAYN_OQ_EVENT_REJECTED:            return "REJECTED";
    case OZAYN_OQ_EVENT_RETRYING:            return "RETRYING";
    case OZAYN_OQ_EVENT_PRECONDITION_FAILED: return "PRECONDITION_FAILED";
    case OZAYN_OQ_EVENT_DUPLICATE_DETECTED:  return "DUPLICATE_DETECTED";
    case OZAYN_OQ_EVENT_RESOURCE_LIMIT_HIT:  return "RESOURCE_LIMIT_HIT";
    case OZAYN_OQ_EVENT_AUTHORIZATION_FAILED:return "AUTHORIZATION_FAILED";
    case OZAYN_OQ_EVENT_CONFLICT_DETECTED:   return "CONFLICT_DETECTED";
    case OZAYN_OQ_EVENT_COUNT:               return "COUNT";
    }
    return "UNKNOWN";
}

const char *ozayn_oq_conflict_mode_name(ozayn_oq_conflict_mode_t mode)
{
    switch (mode) {
    case OZAYN_OQ_CONFLICT_REJECT: return "REJECT";
    case OZAYN_OQ_CONFLICT_WAIT:   return "WAIT";
    case OZAYN_OQ_CONFLICT_ALLOW:  return "ALLOW";
    case OZAYN_OQ_CONFLICT_COUNT:  return "COUNT";
    }
    return "UNKNOWN";
}

/* ============================================================
 * INTERNAL HELPERS
 * ============================================================ */

static void _generate_entry_id(ozayn_oq_service_t *svc, char *buf, size_t bufsz)
{
    svc->sequence++;
    snprintf(buf, bufsz, "OQE-%08x", svc->sequence);
}

static int _is_terminal(ozayn_oq_state_t state)
{
    return (state == OZAYN_OQ_STATE_SUCCEEDED ||
            state == OZAYN_OQ_STATE_FAILED ||
            state == OZAYN_OQ_STATE_REJECTED ||
            state == OZAYN_OQ_STATE_CANCELLED ||
            state == OZAYN_OQ_STATE_TIMEOUT ||
            state == OZAYN_OQ_STATE_EXPIRED ||
            state == OZAYN_OQ_STATE_UNAVAILABLE);
}

static int _is_active(ozayn_oq_state_t state)
{
    return (state == OZAYN_OQ_STATE_CREATED ||
            state == OZAYN_OQ_STATE_QUEUED ||
            state == OZAYN_OQ_STATE_WAITING ||
            state == OZAYN_OQ_STATE_DISPATCHING ||
            state == OZAYN_OQ_STATE_RUNNING);
}

static int _is_running(ozayn_oq_state_t state)
{
    return (state == OZAYN_OQ_STATE_DISPATCHING ||
            state == OZAYN_OQ_STATE_RUNNING);
}

static int _is_valid_action(ozayn_oq_action_t action)
{
    return (action >= OZAYN_OQ_ACTION_START &&
            action < OZAYN_OQ_ACTION_COUNT);
}

/* Conflict rules: which actions conflict with each other */
static int _actions_conflict(ozayn_oq_action_t a, ozayn_oq_action_t b)
{
    if (a == b) return 0;
    /* START conflicts with STOP */
    if ((a == OZAYN_OQ_ACTION_START && b == OZAYN_OQ_ACTION_STOP) ||
        (a == OZAYN_OQ_ACTION_STOP && b == OZAYN_OQ_ACTION_START))
        return 1;
    /* PAUSE conflicts with RESUME */
    if ((a == OZAYN_OQ_ACTION_PAUSE && b == OZAYN_OQ_ACTION_RESUME) ||
        (a == OZAYN_OQ_ACTION_RESUME && b == OZAYN_OQ_ACTION_PAUSE))
        return 1;
    /* ENABLE conflicts with DISABLE */
    if ((a == OZAYN_OQ_ACTION_ENABLE && b == OZAYN_OQ_ACTION_DISABLE) ||
        (a == OZAYN_OQ_ACTION_DISABLE && b == OZAYN_OQ_ACTION_ENABLE))
        return 1;
    return 0;
}

static void _emit_event(ozayn_oq_service_t *svc,
                         ozayn_oq_event_type_t event_type,
                         const char *entry_id,
                         const char *detail)
{
    (void)svc;
    (void)event_type;
    (void)entry_id;
    (void)detail;
}

static void _audit_log(ozayn_oq_service_t *svc,
                        const char *entry_id,
                        const char *event_type,
                        const char *detail)
{
    (void)svc;
    (void)entry_id;
    (void)event_type;
    (void)detail;
}

/* ============================================================
 * SECTION 10 — LIFECYCLE
 * ============================================================ */

ozayn_oq_err_t ozayn_oq_service_init(
    ozayn_oq_service_t *svc,
    const ozayn_oq_service_config_t *cfg)
{
    if (!svc) return OZAYN_OQ_ERR_NULL;
    if (svc->initialized) return OZAYN_OQ_ERR_ALREADY_INITIALIZED;

    memset(svc, 0, sizeof(*svc));

    if (cfg) {
        svc->component_registry = cfg->component_registry;
        svc->authorization      = cfg->authorization;
        svc->audit              = cfg->audit;
        svc->event_engine       = cfg->event_engine;
    }

    svc->policy = ozayn_oq_default_policy();
    svc->head = 0;
    svc->count = 0;
    svc->sequence = 0;
    svc->running_count = 0;
    svc->queued_count = 0;

    svc->initialized = 1;
    return OZAYN_OQ_OK;
}

void ozayn_oq_service_shutdown(ozayn_oq_service_t *svc)
{
    if (!svc) return;
    svc->initialized = 0;
    memset(svc, 0, sizeof(*svc));
}

int ozayn_oq_service_is_initialized(const ozayn_oq_service_t *svc)
{
    if (!svc) return 0;
    return svc->initialized;
}

/* ============================================================
 * SECTION 11 — ENQUEUE
 * ============================================================ */

ozayn_oq_err_t ozayn_oq_enqueue(
    ozayn_oq_service_t *svc,
    const char *request_id,
    ozayn_oq_action_t action,
    const char *target,
    const char *capability,
    const char *context,
    const char *requester_identity,
    const char *session_id,
    const char *required_permission,
    int priority,
    int idempotent,
    int queue_timeout_ms,
    int execution_timeout_ms,
    int max_retries,
    ozayn_oq_entry_t **out_entry)
{
    if (!svc) return OZAYN_OQ_ERR_NULL;
    if (!svc->initialized) return OZAYN_OQ_ERR_NOT_INITIALIZED;

    /* Validate required fields */
    if (!request_id || request_id[0] == '\0')
        return OZAYN_OQ_ERR_INVALID_PARAM;
    if (!_is_valid_action(action))
        return OZAYN_OQ_ERR_INVALID_PARAM;
    if (!target || target[0] == '\0')
        return OZAYN_OQ_ERR_INVALID_PARAM;
    if (strlen(target) >= OZAYN_OQ_MAX_TARGET_LEN)
        return OZAYN_OQ_ERR_INVALID_PARAM;

    /* Check queue capacity */
    if (ozayn_oq_queue_full(svc)) {
        ozayn_oq_emit_event(svc, OZAYN_OQ_EVENT_RESOURCE_LIMIT_HIT,
                            NULL, "queue full");
        return OZAYN_OQ_ERR_QUEUE_FULL;
    }

    /* Check per-component limit */
    if (svc->policy.max_per_component > 0) {
        int comp_count = 0;
        for (int i = 0; i < svc->count; i++) {
            int idx = (svc->head + i) % OZAYN_OQ_MAX_ENTRIES;
            if (svc->entries[idx].active &&
                strcmp(svc->entries[idx].target, target) == 0 &&
                !_is_terminal(svc->entries[idx].state)) {
                comp_count++;
            }
        }
        if (comp_count >= svc->policy.max_per_component) {
            ozayn_oq_emit_event(svc, OZAYN_OQ_EVENT_RESOURCE_LIMIT_HIT,
                                NULL, "per-component limit");
            return OZAYN_OQ_ERR_RESOURCE_LIMIT;
        }
    }

    /* Check per-requester limit */
    if (svc->policy.max_per_requester > 0 && requester_identity &&
        requester_identity[0] != '\0') {
        int req_count = 0;
        for (int i = 0; i < svc->count; i++) {
            int idx = (svc->head + i) % OZAYN_OQ_MAX_ENTRIES;
            if (svc->entries[idx].active &&
                strcmp(svc->entries[idx].requester_identity, requester_identity) == 0 &&
                !_is_terminal(svc->entries[idx].state)) {
                req_count++;
            }
        }
        if (req_count >= svc->policy.max_per_requester) {
            ozayn_oq_emit_event(svc, OZAYN_OQ_EVENT_RESOURCE_LIMIT_HIT,
                                NULL, "per-requester limit");
            return OZAYN_OQ_ERR_RESOURCE_LIMIT;
        }
    }

    /* Idempotency check */
    if (idempotent && svc->policy.allow_idempotent_replay) {
        for (int i = 0; i < svc->count; i++) {
            int idx = (svc->head + i) % OZAYN_OQ_MAX_ENTRIES;
            if (svc->entries[idx].active &&
                strcmp(svc->entries[idx].request_id, request_id) == 0) {
                svc->total_duplicates++;
                ozayn_oq_emit_event(svc, OZAYN_OQ_EVENT_DUPLICATE_DETECTED,
                                    svc->entries[idx].entry_id, request_id);
                if (out_entry) *out_entry = &svc->entries[idx];
                return OZAYN_OQ_ERR_DUPLICATE_REQUEST;
            }
        }
    }

    /* Conflict detection with running operations */
    int has_conflict = 0;
    if (svc->policy.default_conflict_mode != OZAYN_OQ_CONFLICT_ALLOW) {
        for (int i = 0; i < svc->count; i++) {
            int idx = (svc->head + i) % OZAYN_OQ_MAX_ENTRIES;
            if (svc->entries[idx].active &&
                _is_running(svc->entries[idx].state) &&
                strcmp(svc->entries[idx].target, target) == 0 &&
                _actions_conflict(svc->entries[idx].action, action)) {
                has_conflict = 1;
                break;
            }
        }
    }

    if (has_conflict) {
        if (svc->policy.default_conflict_mode == OZAYN_OQ_CONFLICT_REJECT) {
            svc->total_rejected++;
            ozayn_oq_emit_event(svc, OZAYN_OQ_EVENT_CONFLICT_DETECTED,
                                NULL, "conflict, rejected");
            return OZAYN_OQ_ERR_STATE_INVALID;
        }
        /* CONFLICT_WAIT: allow but mark entry */
    }

    /* Allocate entry from ring buffer */
    int slot;
    if (svc->count < OZAYN_OQ_MAX_ENTRIES) {
        slot = (svc->head + svc->count) % OZAYN_OQ_MAX_ENTRIES;
        svc->count++;
    } else {
        slot = svc->head;
        svc->head = (svc->head + 1) % OZAYN_OQ_MAX_ENTRIES;
    }

    ozayn_oq_entry_t *e = &svc->entries[slot];
    memset(e, 0, sizeof(*e));

    /* Generate entry ID */
    _generate_entry_id(svc, e->entry_id, OZAYN_OQ_MAX_ID_LEN);

    /* Fill fields */
    strncpy(e->request_id, request_id, OZAYN_OQ_MAX_ID_LEN - 1);
    e->action = action;
    strncpy(e->target, target, OZAYN_OQ_MAX_TARGET_LEN - 1);
    if (capability)
        strncpy(e->capability, capability, OZAYN_OQ_MAX_CAP_LEN - 1);
    if (context)
        strncpy(e->context, context, OZAYN_OQ_MAX_META_LEN - 1);
    if (requester_identity)
        strncpy(e->requester_identity, requester_identity,
                OZAYN_OQ_MAX_IDENTITY_LEN - 1);
    if (session_id)
        strncpy(e->session_id, session_id, OZAYN_OQ_MAX_SESSION_LEN - 1);
    if (required_permission)
        strncpy(e->required_permission, required_permission,
                OZAYN_OQ_MAX_ID_LEN - 1);

    e->priority = priority;
    e->idempotent = idempotent;
    e->cancellable = 1;
    e->created_time = time(NULL);
    e->queue_timeout_ms = queue_timeout_ms > 0 ? queue_timeout_ms :
                          svc->policy.queue_timeout_ms;
    e->execution_timeout_ms = execution_timeout_ms > 0 ? execution_timeout_ms :
                              svc->policy.execution_timeout_ms;
    e->max_retries = max_retries >= 0 ? max_retries : svc->policy.max_retries;
    e->conflicts_with_running = has_conflict;
    e->state = OZAYN_OQ_STATE_CREATED;
    e->result_code = 0;
    e->active = 1;

    /* Move to QUEUED state */
    e->state = OZAYN_OQ_STATE_QUEUED;
    e->queued_time = time(NULL);
    svc->queued_count++;
    svc->total_submitted++;

    ozayn_oq_emit_event(svc, OZAYN_OQ_EVENT_CREATED, e->entry_id, "created");
    ozayn_oq_emit_event(svc, OZAYN_OQ_EVENT_QUEUED, e->entry_id, "queued");
    ozayn_oq_audit_operation(svc, e->entry_id, "ENQUEUED", "operation queued");

    if (out_entry) *out_entry = e;
    return OZAYN_OQ_OK;
}

/* ============================================================
 * SECTION 12 — DEQUEUE / DISPATCH
 * ============================================================ */

ozayn_oq_err_t ozayn_oq_dequeue_next(
    ozayn_oq_service_t *svc,
    ozayn_oq_entry_t **out_entry)
{
    if (!svc) return OZAYN_OQ_ERR_NULL;
    if (!svc->initialized) return OZAYN_OQ_ERR_NOT_INITIALIZED;
    if (!out_entry) return OZAYN_OQ_ERR_INVALID_PARAM;

    /* Check concurrency limit */
    if (ozayn_oq_running_limit(svc)) {
        return OZAYN_OQ_ERR_RESOURCE_LIMIT;
    }

    /* Find highest-priority QUEUED entry (priority order: CRITICAL > HIGH > NORMAL > LOW) */
    ozayn_oq_entry_t *best = NULL;
    int best_idx = -1;
    time_t oldest_time = 0;

    for (int p = OZAYN_OQ_PRIORITY_CRITICAL; p >= OZAYN_OQ_PRIORITY_LOW; p--) {
        for (int i = 0; i < svc->count; i++) {
            int idx = (svc->head + i) % OZAYN_OQ_MAX_ENTRIES;
            ozayn_oq_entry_t *e = &svc->entries[idx];
            if (e->active && e->state == OZAYN_OQ_STATE_QUEUED &&
                e->priority == p) {
                /* Fairness: among same priority, pick oldest */
                if (!best || e->queued_time < oldest_time) {
                    best = e;
                    best_idx = idx;
                    oldest_time = e->queued_time;
                }
            }
        }
        if (best) break;
    }

    if (!best) return OZAYN_OQ_ERR_NOT_FOUND;

    /* Recheck preconditions before dispatch */
    ozayn_oq_err_t pr = ozayn_oq_recheck_preconditions(svc, best->entry_id);
    if (pr != OZAYN_OQ_OK) {
        best->state = OZAYN_OQ_STATE_REJECTED;
        best->result_code = -1;
        snprintf(best->error_detail, OZAYN_OQ_MAX_ERROR_LEN,
                 "precondition recheck failed: %s", ozayn_oq_err_name(pr));
        best->completion_time = time(NULL);
        svc->queued_count--;
        svc->total_precondition_failures++;
        svc->total_rejected++;
        ozayn_oq_emit_event(svc, OZAYN_OQ_EVENT_PRECONDITION_FAILED,
                            best->entry_id, best->error_detail);
        ozayn_oq_audit_operation(svc, best->entry_id,
                                 "PRECONDITION_FAILED", best->error_detail);
        *out_entry = NULL;
        return OZAYN_OQ_OK;
    }

    /* Recheck authorization before dispatch */
    ozayn_oq_err_t ar = ozayn_oq_recheck_authorization(svc, best->entry_id);
    if (ar != OZAYN_OQ_OK) {
        best->state = OZAYN_OQ_STATE_REJECTED;
        best->result_code = -1;
        snprintf(best->error_detail, OZAYN_OQ_MAX_ERROR_LEN,
                 "authorization recheck failed: %s", ozayn_oq_err_name(ar));
        best->completion_time = time(NULL);
        svc->queued_count--;
        svc->total_authorization_denials++;
        svc->total_rejected++;
        ozayn_oq_emit_event(svc, OZAYN_OQ_EVENT_AUTHORIZATION_FAILED,
                            best->entry_id, best->error_detail);
        ozayn_oq_audit_operation(svc, best->entry_id,
                                 "AUTHORIZATION_FAILED", best->error_detail);
        *out_entry = NULL;
        return OZAYN_OQ_OK;
    }

    /* Transition to DISPATCHING */
    best->state = OZAYN_OQ_STATE_DISPATCHING;
    best->dispatch_time = time(NULL);
    svc->queued_count--;

    ozayn_oq_emit_event(svc, OZAYN_OQ_EVENT_DISPATCHING,
                        best->entry_id, "dispatching");

    /* Transition to RUNNING */
    best->state = OZAYN_OQ_STATE_RUNNING;
    best->start_time = time(NULL);
    svc->running_count++;

    ozayn_oq_emit_event(svc, OZAYN_OQ_EVENT_STARTED,
                        best->entry_id, "started");
    ozayn_oq_audit_operation(svc, best->entry_id,
                             "DISPATCHED", "operation started");

    *out_entry = best;
    return OZAYN_OQ_OK;
}

ozayn_oq_err_t ozayn_oq_complete(
    ozayn_oq_service_t *svc,
    const char *entry_id,
    int result_code,
    const char *error_detail)
{
    if (!svc) return OZAYN_OQ_ERR_NULL;
    if (!svc->initialized) return OZAYN_OQ_ERR_NOT_INITIALIZED;
    if (!entry_id || entry_id[0] == '\0') return OZAYN_OQ_ERR_INVALID_PARAM;

    ozayn_oq_entry_t *e = ozayn_oq_get_entry(svc, entry_id);
    if (!e) return OZAYN_OQ_ERR_NOT_FOUND;
    if (e->state != OZAYN_OQ_STATE_RUNNING)
        return OZAYN_OQ_ERR_STATE_INVALID;

    e->state = OZAYN_OQ_STATE_SUCCEEDED;
    e->result_code = result_code;
    e->completion_time = time(NULL);
    if (error_detail)
        strncpy(e->error_detail, error_detail, OZAYN_OQ_MAX_ERROR_LEN - 1);
    svc->running_count--;
    svc->total_succeeded++;

    ozayn_oq_emit_event(svc, OZAYN_OQ_EVENT_SUCCEEDED, e->entry_id, "succeeded");
    ozayn_oq_audit_operation(svc, e->entry_id, "SUCCEEDED", "operation completed");
    return OZAYN_OQ_OK;
}

ozayn_oq_err_t ozayn_oq_fail(
    ozayn_oq_service_t *svc,
    const char *entry_id,
    int result_code,
    const char *error_detail)
{
    if (!svc) return OZAYN_OQ_ERR_NULL;
    if (!svc->initialized) return OZAYN_OQ_ERR_NOT_INITIALIZED;
    if (!entry_id || entry_id[0] == '\0') return OZAYN_OQ_ERR_INVALID_PARAM;

    ozayn_oq_entry_t *e = ozayn_oq_get_entry(svc, entry_id);
    if (!e) return OZAYN_OQ_ERR_NOT_FOUND;
    if (e->state != OZAYN_OQ_STATE_RUNNING)
        return OZAYN_OQ_ERR_STATE_INVALID;

    e->state = OZAYN_OQ_STATE_FAILED;
    e->result_code = result_code;
    e->completion_time = time(NULL);
    if (error_detail)
        strncpy(e->error_detail, error_detail, OZAYN_OQ_MAX_ERROR_LEN - 1);
    svc->running_count--;
    svc->total_failed++;

    ozayn_oq_emit_event(svc, OZAYN_OQ_EVENT_FAILED, e->entry_id, "failed");
    ozayn_oq_audit_operation(svc, e->entry_id, "FAILED", e->error_detail);
    return OZAYN_OQ_OK;
}

/* ============================================================
 * SECTION 13 — CANCELLATION
 * ============================================================ */

ozayn_oq_err_t ozayn_oq_cancel(
    ozayn_oq_service_t *svc,
    const char *entry_id)
{
    if (!svc) return OZAYN_OQ_ERR_NULL;
    if (!svc->initialized) return OZAYN_OQ_ERR_NOT_INITIALIZED;
    if (!entry_id || entry_id[0] == '\0') return OZAYN_OQ_ERR_INVALID_PARAM;

    ozayn_oq_entry_t *e = ozayn_oq_get_entry(svc, entry_id);
    if (!e) return OZAYN_OQ_ERR_NOT_FOUND;

    if (_is_terminal(e->state))
        return OZAYN_OQ_ERR_STATE_INVALID;

    if (e->state == OZAYN_OQ_STATE_RUNNING ||
        e->state == OZAYN_OQ_STATE_DISPATCHING) {
        return OZAYN_OQ_ERR_CANCELLATION_UNSUPPORTED;
    }

    if (!e->cancellable)
        return OZAYN_OQ_ERR_CANCELLATION_UNSUPPORTED;

    e->state = OZAYN_OQ_STATE_CANCELLED;
    e->completion_time = time(NULL);
    if (e->state == OZAYN_OQ_STATE_QUEUED)
        svc->queued_count--;
    svc->total_cancelled++;

    ozayn_oq_emit_event(svc, OZAYN_OQ_EVENT_CANCELLED, e->entry_id, "cancelled");
    ozayn_oq_audit_operation(svc, e->entry_id, "CANCELLED", "user cancel");
    return OZAYN_OQ_OK;
}

int ozayn_oq_entry_cancellable(
    const ozayn_oq_service_t *svc,
    const char *entry_id)
{
    if (!svc || !entry_id || entry_id[0] == '\0') return 0;

    for (int i = 0; i < svc->count; i++) {
        int idx = (svc->head + i) % OZAYN_OQ_MAX_ENTRIES;
        const ozayn_oq_entry_t *e = &svc->entries[idx];
        if (e->active && strcmp(e->entry_id, entry_id) == 0) {
            return e->cancellable && !_is_terminal(e->state) &&
                   e->state != OZAYN_OQ_STATE_RUNNING &&
                   e->state != OZAYN_OQ_STATE_DISPATCHING;
        }
    }
    return 0;
}

/* ============================================================
 * SECTION 14 — TIMEOUT / EXPIRATION
 * ============================================================ */

int ozayn_oq_check_timeouts(ozayn_oq_service_t *svc)
{
    if (!svc || !svc->initialized) return 0;
    int timed_out = 0;
    time_t now = time(NULL);

    for (int i = 0; i < svc->count; i++) {
        int idx = (svc->head + i) % OZAYN_OQ_MAX_ENTRIES;
        ozayn_oq_entry_t *e = &svc->entries[idx];
        if (!e->active) continue;

        if (e->state == OZAYN_OQ_STATE_QUEUED) {
            /* Queue timeout */
            if (e->queue_timeout_ms > 0) {
                int elapsed_ms = (int)(now - e->queued_time) * 1000;
                if (elapsed_ms > e->queue_timeout_ms) {
                    e->state = OZAYN_OQ_STATE_TIMEOUT;
                    e->result_code = -1;
                    e->completion_time = now;
                    snprintf(e->error_detail, OZAYN_OQ_MAX_ERROR_LEN,
                             "queue timeout after %dms", elapsed_ms);
                    svc->queued_count--;
                    svc->total_timeouts++;
                    timed_out++;
                    ozayn_oq_emit_event(svc, OZAYN_OQ_EVENT_TIMEOUT,
                                        e->entry_id, "queue timeout");
                    ozayn_oq_audit_operation(svc, e->entry_id,
                                             "TIMEOUT", "queue timeout");
                }
            }
        } else if (e->state == OZAYN_OQ_STATE_RUNNING) {
            /* Execution timeout */
            if (e->execution_timeout_ms > 0) {
                int elapsed_ms = (int)(now - e->start_time) * 1000;
                if (elapsed_ms > e->execution_timeout_ms) {
                    e->state = OZAYN_OQ_STATE_TIMEOUT;
                    e->result_code = -1;
                    e->completion_time = now;
                    snprintf(e->error_detail, OZAYN_OQ_MAX_ERROR_LEN,
                             "execution timeout after %dms", elapsed_ms);
                    svc->running_count--;
                    svc->total_timeouts++;
                    timed_out++;
                    ozayn_oq_emit_event(svc, OZAYN_OQ_EVENT_TIMEOUT,
                                        e->entry_id, "execution timeout");
                    ozayn_oq_audit_operation(svc, e->entry_id,
                                             "TIMEOUT", "execution timeout");
                }
            }
        }
    }
    return timed_out;
}

int ozayn_oq_check_expired(ozayn_oq_service_t *svc)
{
    if (!svc || !svc->initialized) return 0;
    int expired = 0;
    time_t now = time(NULL);

    for (int i = 0; i < svc->count; i++) {
        int idx = (svc->head + i) % OZAYN_OQ_MAX_ENTRIES;
        ozayn_oq_entry_t *e = &svc->entries[idx];
        if (!e->active) continue;

        if (_is_terminal(e->state)) {
            /* Clean up old terminal entries after 300s */
            if (e->completion_time > 0 && (now - e->completion_time) > 300) {
                e->active = 0;
                expired++;
            }
        }
    }
    return expired;
}

/* ============================================================
 * SECTION 15 — PRECONDITION / AUTHORIZATION RECHECK
 * ============================================================ */

ozayn_oq_err_t ozayn_oq_recheck_preconditions(
    ozayn_oq_service_t *svc,
    const char *entry_id)
{
    if (!svc) return OZAYN_OQ_ERR_NULL;
    if (!entry_id || entry_id[0] == '\0') return OZAYN_OQ_ERR_INVALID_PARAM;

    ozayn_oq_entry_t *e = ozayn_oq_get_entry(svc, entry_id);
    if (!e) return OZAYN_OQ_ERR_NOT_FOUND;

    /* Check component registry if available */
    if (svc->component_registry) {
        ozayn_reg_service_t *reg = (ozayn_reg_service_t *)svc->component_registry;
        if (!ozayn_reg_service_is_initialized(reg))
            return OZAYN_OQ_ERR_UNAVAILABLE;

        if (!ozayn_reg_component_exists(reg, e->target))
            return OZAYN_OQ_ERR_PRECONDITION_FAILED;

        ozayn_reg_component_t *comp = ozayn_reg_get_component(reg, e->target);
        if (comp) {
            if (comp->availability == OZAYN_REG_AVAIL_UNAVAILABLE)
                return OZAYN_OQ_ERR_PRECONDITION_FAILED;
            if (comp->state == OZAYN_REG_COMP_ERROR ||
                comp->state == OZAYN_REG_COMP_STOPPED)
                return OZAYN_OQ_ERR_PRECONDITION_FAILED;
        }

        /* Check capability if specified */
        if (e->capability[0] != '\0') {
            if (!ozayn_reg_capability_exists(reg, e->capability))
                return OZAYN_OQ_ERR_PRECONDITION_FAILED;

            ozayn_reg_capability_desc_t *cap =
                ozayn_reg_get_capability(reg, e->capability);
            if (cap) {
                if (cap->state == OZAYN_REG_CAP_STATE_UNAVAILABLE ||
                    cap->state == OZAYN_REG_CAP_STATE_DISABLED)
                    return OZAYN_OQ_ERR_PRECONDITION_FAILED;
            }
        }
    }

    return OZAYN_OQ_OK;
}

ozayn_oq_err_t ozayn_oq_recheck_authorization(
    ozayn_oq_service_t *svc,
    const char *entry_id)
{
    if (!svc) return OZAYN_OQ_ERR_NULL;
    if (!entry_id || entry_id[0] == '\0') return OZAYN_OQ_ERR_INVALID_PARAM;

    if (!svc->policy.require_authorization)
        return OZAYN_OQ_OK;

    /* Authorization check delegated to Section 03 authz service */
    if (svc->authorization) {
        /* Authorization service available — actual check would be
         * performed here through ozayn_authz_authorize(). */
        return OZAYN_OQ_OK;
    }

    /* No authz service — fail-closed if required */
    return OZAYN_OQ_ERR_PRECONDITION_FAILED;
}

/* ============================================================
 * SECTION 16 — RETRY
 * ============================================================ */

ozayn_oq_err_t ozayn_oq_retry(
    ozayn_oq_service_t *svc,
    const char *entry_id)
{
    if (!svc) return OZAYN_OQ_ERR_NULL;
    if (!svc->initialized) return OZAYN_OQ_ERR_NOT_INITIALIZED;
    if (!entry_id || entry_id[0] == '\0') return OZAYN_OQ_ERR_INVALID_PARAM;

    ozayn_oq_entry_t *e = ozayn_oq_get_entry(svc, entry_id);
    if (!e) return OZAYN_OQ_ERR_NOT_FOUND;

    if (e->state != OZAYN_OQ_STATE_FAILED)
        return OZAYN_OQ_ERR_STATE_INVALID;

    if (e->retry_count >= e->max_retries) {
        svc->total_retries++;
        return OZAYN_OQ_ERR_RETRY_EXHAUSTED;
    }

    /* Reset for retry */
    e->retry_count++;
    e->state = OZAYN_OQ_STATE_QUEUED;
    e->queued_time = time(NULL);
    e->result_code = 0;
    e->error_detail[0] = '\0';
    svc->total_retries++;

    ozayn_oq_emit_event(svc, OZAYN_OQ_EVENT_RETRYING, e->entry_id, "retrying");
    ozayn_oq_audit_operation(svc, e->entry_id, "RETRYING",
                             "operation retried");
    return OZAYN_OQ_OK;
}

int ozayn_oq_entry_retryable(
    const ozayn_oq_service_t *svc,
    const char *entry_id)
{
    if (!svc || !entry_id || entry_id[0] == '\0') return 0;

    for (int i = 0; i < svc->count; i++) {
        int idx = (svc->head + i) % OZAYN_OQ_MAX_ENTRIES;
        const ozayn_oq_entry_t *e = &svc->entries[idx];
        if (e->active && strcmp(e->entry_id, entry_id) == 0) {
            return (e->state == OZAYN_OQ_STATE_FAILED &&
                    e->retry_count < e->max_retries);
        }
    }
    return 0;
}

/* ============================================================
 * SECTION 17 — CONFLICT DETECTION
 * ============================================================ */

int ozayn_oq_has_conflict(
    const ozayn_oq_service_t *svc,
    const char *target,
    ozayn_oq_action_t action)
{
    if (!svc || !target || target[0] == '\0') return 0;

    for (int i = 0; i < svc->count; i++) {
        int idx = (svc->head + i) % OZAYN_OQ_MAX_ENTRIES;
        const ozayn_oq_entry_t *e = &svc->entries[idx];
        if (e->active && _is_running(e->state) &&
            strcmp(e->target, target) == 0 &&
            _actions_conflict(e->action, action)) {
            return 1;
        }
    }
    return 0;
}

/* ============================================================
 * SECTION 18 — QUERY
 * ============================================================ */

ozayn_oq_entry_t *ozayn_oq_get_entry(
    ozayn_oq_service_t *svc,
    const char *entry_id)
{
    if (!svc || !entry_id || entry_id[0] == '\0') return NULL;

    for (int i = 0; i < svc->count; i++) {
        int idx = (svc->head + i) % OZAYN_OQ_MAX_ENTRIES;
        if (svc->entries[idx].active &&
            strcmp(svc->entries[idx].entry_id, entry_id) == 0) {
            return &svc->entries[idx];
        }
    }
    return NULL;
}

int ozayn_oq_entry_count(const ozayn_oq_service_t *svc)
{
    if (!svc) return 0;
    return svc->count;
}

int ozayn_oq_running_count(const ozayn_oq_service_t *svc)
{
    if (!svc) return 0;
    return svc->running_count;
}

int ozayn_oq_queued_count(const ozayn_oq_service_t *svc)
{
    if (!svc) return 0;
    return svc->queued_count;
}

int ozayn_oq_queue_full(const ozayn_oq_service_t *svc)
{
    if (!svc) return 1;
    return svc->count >= svc->policy.max_entries;
}

int ozayn_oq_running_limit(const ozayn_oq_service_t *svc)
{
    if (!svc) return 1;
    return svc->running_count >= svc->policy.max_running;
}

/* ============================================================
 * SECTION 19 — EVENT OBSERVATION
 * ============================================================ */

ozayn_oq_err_t ozayn_oq_emit_event(
    ozayn_oq_service_t *svc,
    ozayn_oq_event_type_t event_type,
    const char *entry_id,
    const char *detail)
{
    if (!svc) return OZAYN_OQ_ERR_NULL;
    (void)event_type;
    (void)entry_id;
    (void)detail;
    return OZAYN_OQ_OK;
}

/* ============================================================
 * SECTION 20 — AUDIT
 * ============================================================ */

ozayn_oq_err_t ozayn_oq_audit_operation(
    ozayn_oq_service_t *svc,
    const char *entry_id,
    const char *event_type,
    const char *detail)
{
    if (!svc) return OZAYN_OQ_ERR_NULL;
    if (!entry_id || !event_type) return OZAYN_OQ_ERR_INVALID_PARAM;
    _audit_log(svc, entry_id, event_type, detail);
    return OZAYN_OQ_OK;
}

/* ============================================================
 * SECTION 21 — POLICY
 * ============================================================ */

ozayn_oq_policy_t ozayn_oq_default_policy(void)
{
    ozayn_oq_policy_t p;
    memset(&p, 0, sizeof(p));
    p.enabled = 1;
    p.max_entries = OZAYN_OQ_MAX_ENTRIES;
    p.max_running = 16;
    p.max_per_component = 8;
    p.max_per_requester = 16;
    p.max_retries = 3;
    p.queue_timeout_ms = 10000;
    p.execution_timeout_ms = 60000;
    p.global_timeout_ms = 300000;
    p.require_authorization = 0;
    p.require_capability = 0;
    p.allow_idempotent_replay = 1;
    p.default_conflict_mode = OZAYN_OQ_CONFLICT_WAIT;
    return p;
}

ozayn_oq_err_t ozayn_oq_set_policy(
    ozayn_oq_service_t *svc,
    const ozayn_oq_policy_t *policy)
{
    if (!svc) return OZAYN_OQ_ERR_NULL;
    if (!policy) return OZAYN_OQ_ERR_INVALID_PARAM;
    svc->policy = *policy;
    return OZAYN_OQ_OK;
}

const ozayn_oq_policy_t *ozayn_oq_get_policy(
    const ozayn_oq_service_t *svc)
{
    if (!svc) return NULL;
    return &svc->policy;
}

/* ============================================================
 * SECTION 22 — STATISTICS
 * ============================================================ */

uint64_t ozayn_oq_total_submitted(const ozayn_oq_service_t *svc)
{
    if (!svc) return 0;
    return svc->total_submitted;
}

uint64_t ozayn_oq_total_succeeded(const ozayn_oq_service_t *svc)
{
    if (!svc) return 0;
    return svc->total_succeeded;
}

uint64_t ozayn_oq_total_failed(const ozayn_oq_service_t *svc)
{
    if (!svc) return 0;
    return svc->total_failed;
}

uint64_t ozayn_oq_total_rejected(const ozayn_oq_service_t *svc)
{
    if (!svc) return 0;
    return svc->total_rejected;
}

uint64_t ozayn_oq_total_cancelled(const ozayn_oq_service_t *svc)
{
    if (!svc) return 0;
    return svc->total_cancelled;
}

uint64_t ozayn_oq_total_timeouts(const ozayn_oq_service_t *svc)
{
    if (!svc) return 0;
    return svc->total_timeouts;
}

uint64_t ozayn_oq_total_expired(const ozayn_oq_service_t *svc)
{
    if (!svc) return 0;
    return svc->total_expired;
}

uint64_t ozayn_oq_total_duplicates(const ozayn_oq_service_t *svc)
{
    if (!svc) return 0;
    return svc->total_duplicates;
}

uint64_t ozayn_oq_total_retries(const ozayn_oq_service_t *svc)
{
    if (!svc) return 0;
    return svc->total_retries;
}

/* ============================================================
 * SECTION 23 — CLEANUP
 * ============================================================ */

int ozayn_oq_cleanup_completed(ozayn_oq_service_t *svc)
{
    if (!svc) return 0;
    int cleaned = 0;
    for (int i = 0; i < svc->count; i++) {
        int idx = (svc->head + i) % OZAYN_OQ_MAX_ENTRIES;
        ozayn_oq_entry_t *e = &svc->entries[idx];
        if (e->active && _is_terminal(e->state)) {
            e->active = 0;
            cleaned++;
        }
    }
    return cleaned;
}

int ozayn_oq_cleanup_all(ozayn_oq_service_t *svc)
{
    if (!svc) return 0;
    int cleaned = 0;
    for (int i = 0; i < svc->count; i++) {
        int idx = (svc->head + i) % OZAYN_OQ_MAX_ENTRIES;
        ozayn_oq_entry_t *e = &svc->entries[idx];
        if (e->active) {
            e->active = 0;
            cleaned++;
        }
    }
    svc->running_count = 0;
    svc->queued_count = 0;
    return cleaned;
}
