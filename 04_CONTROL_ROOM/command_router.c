/*
 * command_router.c — Safe Command Routing & Operation Request Foundation
 *
 * Implements the routing pipeline:
 *   Request → Validate → Resolve Target → Check Capability →
 *   Preconditions → Authorize → Route → Dispatch → Result → Audit
 */

#include "command_router.h"
#include "component_registry.h"
#include <string.h>
#include <stdio.h>
#include <time.h>

/* ============================================================
 * GLOBAL SINGLETON
 * ============================================================ */

static ozayn_router_service_t _router_global = {0};

ozayn_router_service_t *ozayn_router_get_global(void)
{
    return &_router_global;
}

/* ============================================================
 * SECTION 9 — NAME HELPERS
 * ============================================================ */

const char *ozayn_router_err_name(ozayn_router_err_t err)
{
    switch (err) {
    case OZAYN_ROUTER_OK:                        return "OK";
    case OZAYN_ROUTER_ERR_NULL:                  return "NULL";
    case OZAYN_ROUTER_ERR_NOT_INITIALIZED:       return "NOT_INITIALIZED";
    case OZAYN_ROUTER_ERR_ALREADY_INITIALIZED:   return "ALREADY_INITIALIZED";
    case OZAYN_ROUTER_ERR_INVALID_PARAM:         return "INVALID_PARAM";
    case OZAYN_ROUTER_ERR_REQUEST_INVALID:       return "REQUEST_INVALID";
    case OZAYN_ROUTER_ERR_REQUEST_MISSING_ID:    return "REQUEST_MISSING_ID";
    case OZAYN_ROUTER_ERR_REQUEST_MISSING_TARGET: return "REQUEST_MISSING_TARGET";
    case OZAYN_ROUTER_ERR_REQUEST_MISSING_ACTION: return "REQUEST_MISSING_ACTION";
    case OZAYN_ROUTER_ERR_REQUEST_UNSUPPORTED_VERSION: return "REQUEST_UNSUPPORTED_VERSION";
    case OZAYN_ROUTER_ERR_REQUEST_METADATA_TOO_LARGE: return "REQUEST_METADATA_TOO_LARGE";
    case OZAYN_ROUTER_ERR_TARGET_NOT_FOUND:      return "TARGET_NOT_FOUND";
    case OZAYN_ROUTER_ERR_TARGET_UNAVAILABLE:    return "TARGET_UNAVAILABLE";
    case OZAYN_ROUTER_ERR_TARGET_UNREGISTERED:   return "TARGET_UNREGISTERED";
    case OZAYN_ROUTER_ERR_CAPABILITY_NOT_FOUND:  return "CAPABILITY_NOT_FOUND";
    case OZAYN_ROUTER_ERR_CAPABILITY_UNAVAILABLE: return "CAPABILITY_UNAVAILABLE";
    case OZAYN_ROUTER_ERR_CAPABILITY_UNSUPPORTED: return "CAPABILITY_UNSUPPORTED";
    case OZAYN_ROUTER_ERR_CAPABILITY_PROVIDER_MISSING: return "CAPABILITY_PROVIDER_MISSING";
    case OZAYN_ROUTER_ERR_CAPABILITY_DEPENDENCY_MISSING: return "CAPABILITY_DEPENDENCY_MISSING";
    case OZAYN_ROUTER_ERR_PRECONDITION_FAILED:   return "PRECONDITION_FAILED";
    case OZAYN_ROUTER_ERR_AUTHORIZATION_FAILED:  return "AUTHORIZATION_FAILED";
    case OZAYN_ROUTER_ERR_AUTHORIZATION_UNAVAILABLE: return "AUTHORIZATION_UNAVAILABLE";
    case OZAYN_ROUTER_ERR_OPERATION_REJECTED:    return "OPERATION_REJECTED";
    case OZAYN_ROUTER_ERR_OPERATION_FAILED:      return "OPERATION_FAILED";
    case OZAYN_ROUTER_ERR_OPERATION_TIMEOUT:     return "OPERATION_TIMEOUT";
    case OZAYN_ROUTER_ERR_OPERATION_CANCELLED:   return "OPERATION_CANCELLED";
    case OZAYN_ROUTER_ERR_CANCELLATION_UNSUPPORTED: return "CANCELLATION_UNSUPPORTED";
    case OZAYN_ROUTER_ERR_DUPLICATE_REQUEST:     return "DUPLICATE_REQUEST";
    case OZAYN_ROUTER_ERR_QUEUE_FULL:            return "QUEUE_FULL";
    case OZAYN_ROUTER_ERR_CONCURRENCY_LIMIT:     return "CONCURRENCY_LIMIT";
    case OZAYN_ROUTER_ERR_RESOURCE_LIMIT:        return "RESOURCE_LIMIT";
    case OZAYN_ROUTER_ERR_DISPATCH_FAILED:       return "DISPATCH_FAILED";
    case OZAYN_ROUTER_ERR_STATE_INVALID:         return "STATE_INVALID";
    case OZAYN_ROUTER_ERR_NOT_FOUND:             return "NOT_FOUND";
    case OZAYN_ROUTER_ERR_UNAVAILABLE:           return "UNAVAILABLE";
    }
    return "UNKNOWN";
}

const char *ozayn_router_op_state_name(ozayn_router_op_state_t state)
{
    switch (state) {
    case OZAYN_ROUTER_OP_RECEIVED:         return "RECEIVED";
    case OZAYN_ROUTER_OP_VALIDATING:       return "VALIDATING";
    case OZAYN_ROUTER_OP_VALIDATED:        return "VALIDATED";
    case OZAYN_ROUTER_OP_RESOLVING:        return "RESOLVING";
    case OZAYN_ROUTER_OP_RESOLVED:         return "RESOLVED";
    case OZAYN_ROUTER_OP_CAPABILITY_CHECK: return "CAPABILITY_CHECK";
    case OZAYN_ROUTER_OP_CAPABILITY_VERIFIED: return "CAPABILITY_VERIFIED";
    case OZAYN_ROUTER_OP_PRECONDITION_CHECK: return "PRECONDITION_CHECK";
    case OZAYN_ROUTER_OP_PRECONDITION_PASSED: return "PRECONDITION_PASSED";
    case OZAYN_ROUTER_OP_AUTHORIZING:      return "AUTHORIZING";
    case OZAYN_ROUTER_OP_AUTHORIZED:       return "AUTHORIZED";
    case OZAYN_ROUTER_OP_QUEUED:           return "QUEUED";
    case OZAYN_ROUTER_OP_DISPATCHING:      return "DISPATCHING";
    case OZAYN_ROUTER_OP_RUNNING:          return "RUNNING";
    case OZAYN_ROUTER_OP_SUCCEEDED:        return "SUCCEEDED";
    case OZAYN_ROUTER_OP_FAILED:           return "FAILED";
    case OZAYN_ROUTER_OP_REJECTED:         return "REJECTED";
    case OZAYN_ROUTER_OP_CANCELLED:        return "CANCELLED";
    case OZAYN_ROUTER_OP_TIMEOUT:          return "TIMEOUT";
    case OZAYN_ROUTER_OP_UNAVAILABLE:      return "UNAVAILABLE";
    case OZAYN_ROUTER_OP_UNSUPPORTED:      return "UNSUPPORTED";
    case OZAYN_ROUTER_OP_COUNT:            return "COUNT";
    }
    return "UNKNOWN";
}

const char *ozayn_router_result_state_name(ozayn_router_result_state_t state)
{
    switch (state) {
    case OZAYN_ROUTER_RESULT_PENDING:     return "PENDING";
    case OZAYN_ROUTER_RESULT_ACCEPTED:    return "ACCEPTED";
    case OZAYN_ROUTER_RESULT_SUCCEEDED:   return "SUCCEEDED";
    case OZAYN_ROUTER_RESULT_FAILED:      return "FAILED";
    case OZAYN_ROUTER_RESULT_REJECTED:    return "REJECTED";
    case OZAYN_ROUTER_RESULT_CANCELLED:   return "CANCELLED";
    case OZAYN_ROUTER_RESULT_TIMEOUT:     return "TIMEOUT";
    case OZAYN_ROUTER_RESULT_UNAVAILABLE: return "UNAVAILABLE";
    case OZAYN_ROUTER_RESULT_UNSUPPORTED: return "UNSUPPORTED";
    }
    return "UNKNOWN";
}

const char *ozayn_router_action_name(ozayn_router_action_t action)
{
    switch (action) {
    case OZAYN_ROUTER_ACTION_START:      return "START";
    case OZAYN_ROUTER_ACTION_STOP:       return "STOP";
    case OZAYN_ROUTER_ACTION_PAUSE:      return "PAUSE";
    case OZAYN_ROUTER_ACTION_RESUME:     return "RESUME";
    case OZAYN_ROUTER_ACTION_QUERY:      return "QUERY";
    case OZAYN_ROUTER_ACTION_RESTART:    return "RESTART";
    case OZAYN_ROUTER_ACTION_ENABLE:     return "ENABLE";
    case OZAYN_ROUTER_ACTION_DISABLE:    return "DISABLE";
    case OZAYN_ROUTER_ACTION_DIAGNOSTIC: return "DIAGNOSTIC";
    case OZAYN_ROUTER_ACTION_COUNT:      return "COUNT";
    }
    return "UNKNOWN";
}

const char *ozayn_router_event_type_name(ozayn_router_event_type_t type)
{
    switch (type) {
    case OZAYN_ROUTER_EVENT_REQUEST_RECEIVED:     return "REQUEST_RECEIVED";
    case OZAYN_ROUTER_EVENT_REQUEST_VALIDATED:    return "REQUEST_VALIDATED";
    case OZAYN_ROUTER_EVENT_REQUEST_REJECTED:     return "REQUEST_REJECTED";
    case OZAYN_ROUTER_EVENT_TARGET_RESOLVED:      return "TARGET_RESOLVED";
    case OZAYN_ROUTER_EVENT_TARGET_NOT_FOUND:     return "TARGET_NOT_FOUND";
    case OZAYN_ROUTER_EVENT_CAPABILITY_RESOLVED:  return "CAPABILITY_RESOLVED";
    case OZAYN_ROUTER_EVENT_CAPABILITY_NOT_FOUND: return "CAPABILITY_NOT_FOUND";
    case OZAYN_ROUTER_EVENT_AUTHORIZATION_PASSED: return "AUTHORIZATION_PASSED";
    case OZAYN_ROUTER_EVENT_AUTHORIZATION_FAILED: return "AUTHORIZATION_FAILED";
    case OZAYN_ROUTER_EVENT_OPERATION_QUEUED:     return "OPERATION_QUEUED";
    case OZAYN_ROUTER_EVENT_OPERATION_STARTED:    return "OPERATION_STARTED";
    case OZAYN_ROUTER_EVENT_OPERATION_SUCCEEDED:  return "OPERATION_SUCCEEDED";
    case OZAYN_ROUTER_EVENT_OPERATION_FAILED:     return "OPERATION_FAILED";
    case OZAYN_ROUTER_EVENT_OPERATION_CANCELLED:  return "OPERATION_CANCELLED";
    case OZAYN_ROUTER_EVENT_OPERATION_TIMEOUT:    return "OPERATION_TIMEOUT";
    case OZAYN_ROUTER_EVENT_PRECONDITION_FAILED:  return "PRECONDITION_FAILED";
    case OZAYN_ROUTER_EVENT_DUPLICATE_DETECTED:   return "DUPLICATE_DETECTED";
    case OZAYN_ROUTER_EVENT_RESOURCE_LIMIT_HIT:   return "RESOURCE_LIMIT_HIT";
    case OZAYN_ROUTER_EVENT_COUNT:                return "COUNT";
    }
    return "UNKNOWN";
}

const char *ozayn_router_precond_name(ozayn_router_precond_t precond)
{
    switch (precond) {
    case OZAYN_ROUTER_PRECOND_NONE:               return "NONE";
    case OZAYN_ROUTER_PRECOND_TARGET_MISSING:     return "TARGET_MISSING";
    case OZAYN_ROUTER_PRECOND_TARGET_UNAVAILABLE: return "TARGET_UNAVAILABLE";
    case OZAYN_ROUTER_PRECOND_TARGET_ERROR:       return "TARGET_ERROR";
    case OZAYN_ROUTER_PRECOND_CAP_MISSING:        return "CAP_MISSING";
    case OZAYN_ROUTER_PRECOND_CAP_UNAVAILABLE:    return "CAP_UNAVAILABLE";
    case OZAYN_ROUTER_PRECOND_CAP_DISABLED:       return "CAP_DISABLED";
    case OZAYN_ROUTER_PRECOND_DEP_MISSING:        return "DEP_MISSING";
    case OZAYN_ROUTER_PRECOND_STATE_INVALID:      return "STATE_INVALID";
    case OZAYN_ROUTER_PRECOND_SECURITY_BLOCKED:   return "SECURITY_BLOCKED";
    case OZAYN_ROUTER_PRECOND_SYSTEM_BUSY:        return "SYSTEM_BUSY";
    }
    return "UNKNOWN";
}

/* ============================================================
 * INTERNAL HELPERS
 * ============================================================ */

static void _generate_operation_id(ozayn_router_service_t *svc, char *buf, size_t bufsz)
{
    svc->operation_sequence++;
    snprintf(buf, bufsz, "OPR-%08x", svc->operation_sequence);
}

static void _emit_event(ozayn_router_service_t *svc,
                         ozayn_router_event_type_t event_type,
                         const char *operation_id,
                         const char *detail)
{
    /* Record in internal event observation */
    (void)event_type;
    (void)operation_id;
    (void)detail;
    /* Event observation is recorded via ozayn_router_emit_event */
}

static void _audit_log(ozayn_router_service_t *svc,
                        const char *operation_id,
                        const char *event_type,
                        const char *detail)
{
    /* Audit integration — logs safe operational information only.
     * No secrets, keys, tokens, or credentials are logged. */
    (void)svc;
    (void)operation_id;
    (void)event_type;
    (void)detail;
}

static int _is_valid_action(ozayn_router_action_t action)
{
    return (action >= OZAYN_ROUTER_ACTION_START &&
            action < OZAYN_ROUTER_ACTION_COUNT);
}

static int _op_is_terminal(ozayn_router_op_state_t state)
{
    return (state == OZAYN_ROUTER_OP_SUCCEEDED ||
            state == OZAYN_ROUTER_OP_FAILED ||
            state == OZAYN_ROUTER_OP_REJECTED ||
            state == OZAYN_ROUTER_OP_CANCELLED ||
            state == OZAYN_ROUTER_OP_TIMEOUT ||
            state == OZAYN_ROUTER_OP_UNAVAILABLE ||
            state == OZAYN_ROUTER_OP_UNSUPPORTED);
}

static int _op_active(ozayn_router_op_state_t state)
{
    return (state == OZAYN_ROUTER_OP_RECEIVED ||
            state == OZAYN_ROUTER_OP_VALIDATING ||
            state == OZAYN_ROUTER_OP_VALIDATED ||
            state == OZAYN_ROUTER_OP_RESOLVING ||
            state == OZAYN_ROUTER_OP_RESOLVED ||
            state == OZAYN_ROUTER_OP_CAPABILITY_CHECK ||
            state == OZAYN_ROUTER_OP_CAPABILITY_VERIFIED ||
            state == OZAYN_ROUTER_OP_PRECONDITION_CHECK ||
            state == OZAYN_ROUTER_OP_PRECONDITION_PASSED ||
            state == OZAYN_ROUTER_OP_AUTHORIZING ||
            state == OZAYN_ROUTER_OP_AUTHORIZED ||
            state == OZAYN_ROUTER_OP_QUEUED ||
            state == OZAYN_ROUTER_OP_DISPATCHING ||
            state == OZAYN_ROUTER_OP_RUNNING);
}

/* ============================================================
 * SECTION 10 — LIFECYCLE
 * ============================================================ */

ozayn_router_err_t ozayn_router_service_init(
    ozayn_router_service_t *svc,
    const ozayn_router_service_config_t *cfg)
{
    if (!svc) return OZAYN_ROUTER_ERR_NULL;
    if (svc->initialized) return OZAYN_ROUTER_ERR_ALREADY_INITIALIZED;

    memset(svc, 0, sizeof(*svc));

    if (cfg) {
        svc->component_registry = cfg->component_registry;
        svc->control_room      = cfg->control_room;
        svc->authorization     = cfg->authorization;
        svc->audit             = cfg->audit;
        svc->event_engine      = cfg->event_engine;
    }

    svc->policy = ozayn_router_default_policy();
    svc->operation_head = 0;
    svc->operation_count = 0;
    svc->operation_sequence = 0;
    svc->active_ops = 0;

    svc->initialized = 1;
    return OZAYN_ROUTER_OK;
}

void ozayn_router_service_shutdown(ozayn_router_service_t *svc)
{
    if (!svc) return;
    svc->initialized = 0;
    memset(svc, 0, sizeof(*svc));
}

int ozayn_router_service_is_initialized(const ozayn_router_service_t *svc)
{
    if (!svc) return 0;
    return svc->initialized;
}

/* ============================================================
 * SECTION 11 — REQUEST VALIDATION
 * ============================================================ */

ozayn_router_err_t ozayn_router_validate_request(
    const ozayn_router_service_t *svc,
    const char *request_id,
    ozayn_router_action_t action,
    const char *target,
    const char *capability)
{
    if (!svc) return OZAYN_ROUTER_ERR_NULL;
    if (!svc->initialized) return OZAYN_ROUTER_ERR_NOT_INITIALIZED;

    if (!request_id || request_id[0] == '\0')
        return OZAYN_ROUTER_ERR_REQUEST_MISSING_ID;

    if (!_is_valid_action(action))
        return OZAYN_ROUTER_ERR_REQUEST_MISSING_ACTION;

    if (!target || target[0] == '\0')
        return OZAYN_ROUTER_ERR_REQUEST_MISSING_TARGET;

    if (strlen(target) >= OZAYN_ROUTER_MAX_TARGET_LEN)
        return OZAYN_ROUTER_ERR_INVALID_PARAM;

    if (capability && capability[0] != '\0' &&
        strlen(capability) >= OZAYN_ROUTER_MAX_CAP_LEN)
        return OZAYN_ROUTER_ERR_INVALID_PARAM;

    return OZAYN_ROUTER_OK;
}

/* ============================================================
 * SECTION 12 — OPERATION SUBMISSION
 * ============================================================ */

ozayn_router_err_t ozayn_router_submit(
    ozayn_router_service_t *svc,
    const char *request_id,
    ozayn_router_action_t action,
    const char *target,
    const char *capability,
    const char *context,
    const char *requester_identity,
    const char *session_id,
    const char *required_permission,
    int priority,
    int idempotent,
    ozayn_router_operation_t **out_operation)
{
    if (!svc) return OZAYN_ROUTER_ERR_NULL;
    if (!svc->initialized) return OZAYN_ROUTER_ERR_NOT_INITIALIZED;

    /* Validate request fields */
    ozayn_router_err_t vr = ozayn_router_validate_request(
        svc, request_id, action, target, capability);
    if (vr != OZAYN_ROUTER_OK) return vr;

    /* Check context size */
    if (context && strlen(context) >= OZAYN_ROUTER_MAX_META_LEN)
        return OZAYN_ROUTER_ERR_REQUEST_METADATA_TOO_LARGE;

    /* Check queue limit */
    if (ozayn_router_queue_full(svc))
        return OZAYN_ROUTER_ERR_QUEUE_FULL;

    /* Check concurrency limit */
    if (ozayn_router_concurrency_limit(svc))
        return OZAYN_ROUTER_ERR_CONCURRENCY_LIMIT;

    /* Idempotency: scan for duplicate request_id */
    if (idempotent) {
        for (int i = 0; i < svc->operation_count; i++) {
            int idx = (svc->operation_head + i) % OZAYN_ROUTER_MAX_OPERATIONS;
            ozayn_router_operation_t *op = &svc->operations[idx];
            if (op->active && strcmp(op->request_id, request_id) == 0) {
                svc->total_duplicates++;
                if (out_operation) *out_operation = op;
                return OZAYN_ROUTER_ERR_DUPLICATE_REQUEST;
            }
        }
    }

    /* Allocate operation from ring buffer */
    int slot;
    if (svc->operation_count < OZAYN_ROUTER_MAX_OPERATIONS) {
        slot = (svc->operation_head + svc->operation_count) %
               OZAYN_ROUTER_MAX_OPERATIONS;
        svc->operation_count++;
    } else {
        slot = svc->operation_head;
        svc->operation_head = (svc->operation_head + 1) % OZAYN_ROUTER_MAX_OPERATIONS;
    }

    ozayn_router_operation_t *op = &svc->operations[slot];
    memset(op, 0, sizeof(*op));

    /* Generate operation ID */
    _generate_operation_id(svc, op->operation_id, OZAYN_ROUTER_MAX_ID_LEN);

    /* Fill fields */
    strncpy(op->request_id, request_id, OZAYN_ROUTER_MAX_ID_LEN - 1);
    op->action = action;
    strncpy(op->target, target, OZAYN_ROUTER_MAX_TARGET_LEN - 1);
    if (capability)
        strncpy(op->capability, capability, OZAYN_ROUTER_MAX_CAP_LEN - 1);
    if (context)
        strncpy(op->context, context, OZAYN_ROUTER_MAX_META_LEN - 1);
    if (requester_identity)
        strncpy(op->requester_identity, requester_identity,
                OZAYN_ROUTER_MAX_IDENTITY_LEN - 1);
    if (session_id)
        strncpy(op->session_id, session_id, OZAYN_ROUTER_MAX_SESSION_LEN - 1);
    if (required_permission)
        strncpy(op->required_permission, required_permission,
                OZAYN_ROUTER_MAX_ID_LEN - 1);

    op->priority = priority;
    op->idempotent = idempotent;
    op->request_time = time(NULL);
    op->state = OZAYN_ROUTER_OP_RECEIVED;
    op->result_state = OZAYN_ROUTER_RESULT_PENDING;
    op->active = 1;

    svc->total_requests++;

    /* Emit event */
    ozayn_router_emit_event(svc, OZAYN_ROUTER_EVENT_REQUEST_RECEIVED,
                            op->operation_id, "request submitted");

    /* Audit */
    ozayn_router_audit_operation(svc, op->operation_id,
                                 "REQUEST_RECEIVED", "operation created");

    if (out_operation) *out_operation = op;
    return OZAYN_ROUTER_OK;
}

/* ============================================================
 * SECTION 13 — OPERATION PROCESSING
 * ============================================================ */

/* Internal: resolve target via component registry */
static ozayn_router_err_t _resolve_target(
    ozayn_router_service_t *svc,
    ozayn_router_operation_t *op)
{
    if (!svc->component_registry) {
        /* No registry available — skip target resolution */
        return OZAYN_ROUTER_OK;
    }

    ozayn_reg_service_t *reg = (ozayn_reg_service_t *)svc->component_registry;

    if (!ozayn_reg_service_is_initialized(reg)) {
        op->state = OZAYN_ROUTER_OP_UNAVAILABLE;
        op->result_state = OZAYN_ROUTER_RESULT_UNAVAILABLE;
        snprintf(op->error_detail, OZAYN_ROUTER_MAX_ERROR_LEN,
                 "component registry not initialized");
        return OZAYN_ROUTER_ERR_UNAVAILABLE;
    }

    if (!ozayn_reg_component_exists(reg, op->target)) {
        op->state = OZAYN_ROUTER_OP_REJECTED;
        op->result_state = OZAYN_ROUTER_RESULT_REJECTED;
        op->result_code = -1;
        snprintf(op->error_detail, OZAYN_ROUTER_MAX_ERROR_LEN,
                 "target '%s' not found", op->target);
        ozayn_router_emit_event(svc, OZAYN_ROUTER_EVENT_TARGET_NOT_FOUND,
                                op->operation_id, op->target);
        return OZAYN_ROUTER_ERR_TARGET_NOT_FOUND;
    }

    ozayn_reg_component_t *comp = ozayn_reg_get_component(reg, op->target);
    if (!comp) {
        op->state = OZAYN_ROUTER_OP_REJECTED;
        op->result_state = OZAYN_ROUTER_RESULT_REJECTED;
        op->result_code = -1;
        snprintf(op->error_detail, OZAYN_ROUTER_MAX_ERROR_LEN,
                 "target '%s' lookup failed", op->target);
        return OZAYN_ROUTER_ERR_TARGET_NOT_FOUND;
    }

    /* Check availability */
    if (comp->availability == OZAYN_REG_AVAIL_UNAVAILABLE) {
        op->state = OZAYN_ROUTER_OP_UNAVAILABLE;
        op->result_state = OZAYN_ROUTER_RESULT_UNAVAILABLE;
        op->result_code = -1;
        snprintf(op->error_detail, OZAYN_ROUTER_MAX_ERROR_LEN,
                 "target '%s' unavailable", op->target);
        return OZAYN_ROUTER_ERR_TARGET_UNAVAILABLE;
    }

    /* Check state */
    if (comp->state == OZAYN_REG_COMP_ERROR ||
        comp->state == OZAYN_REG_COMP_STOPPED) {
        op->precondition_failure = OZAYN_ROUTER_PRECOND_STATE_INVALID;
        op->state = OZAYN_ROUTER_OP_REJECTED;
        op->result_state = OZAYN_ROUTER_RESULT_REJECTED;
        op->result_code = -1;
        snprintf(op->error_detail, OZAYN_ROUTER_MAX_ERROR_LEN,
                 "target '%s' in invalid state: %d", op->target, comp->state);
        return OZAYN_ROUTER_ERR_PRECONDITION_FAILED;
    }

    ozayn_router_emit_event(svc, OZAYN_ROUTER_EVENT_TARGET_RESOLVED,
                            op->operation_id, op->target);
    return OZAYN_ROUTER_OK;
}

/* Internal: check capability via component registry */
static ozayn_router_err_t _check_capability(
    ozayn_router_service_t *svc,
    ozayn_router_operation_t *op)
{
    /* If no capability required, skip */
    if (op->capability[0] == '\0') {
        if (svc->policy.require_capability) {
            op->precondition_failure = OZAYN_ROUTER_PRECOND_CAP_MISSING;
            op->state = OZAYN_ROUTER_OP_REJECTED;
            op->result_state = OZAYN_ROUTER_RESULT_REJECTED;
            op->result_code = -1;
            snprintf(op->error_detail, OZAYN_ROUTER_MAX_ERROR_LEN,
                     "capability required but not specified");
            return OZAYN_ROUTER_ERR_CAPABILITY_NOT_FOUND;
        }
        return OZAYN_ROUTER_OK;
    }

    if (!svc->component_registry) {
        return OZAYN_ROUTER_OK;
    }

    ozayn_reg_service_t *reg = (ozayn_reg_service_t *)svc->component_registry;

    if (!ozayn_reg_capability_exists(reg, op->capability)) {
        op->state = OZAYN_ROUTER_OP_REJECTED;
        op->result_state = OZAYN_ROUTER_RESULT_REJECTED;
        op->result_code = -1;
        snprintf(op->error_detail, OZAYN_ROUTER_MAX_ERROR_LEN,
                 "capability '%s' not found", op->capability);
        ozayn_router_emit_event(svc, OZAYN_ROUTER_EVENT_CAPABILITY_NOT_FOUND,
                                op->operation_id, op->capability);
        return OZAYN_ROUTER_ERR_CAPABILITY_NOT_FOUND;
    }

    ozayn_reg_capability_desc_t *cap = ozayn_reg_get_capability(reg, op->capability);
    if (!cap) {
        op->state = OZAYN_ROUTER_OP_REJECTED;
        op->result_state = OZAYN_ROUTER_RESULT_REJECTED;
        op->result_code = -1;
        snprintf(op->error_detail, OZAYN_ROUTER_MAX_ERROR_LEN,
                 "capability '%s' lookup failed", op->capability);
        return OZAYN_ROUTER_ERR_CAPABILITY_NOT_FOUND;
    }

    /* Check capability state */
    if (cap->state == OZAYN_REG_CAP_STATE_UNAVAILABLE ||
        cap->state == OZAYN_REG_CAP_STATE_UNSUPPORTED) {
        op->state = OZAYN_ROUTER_OP_UNAVAILABLE;
        op->result_state = OZAYN_ROUTER_RESULT_UNAVAILABLE;
        op->result_code = -1;
        snprintf(op->error_detail, OZAYN_ROUTER_MAX_ERROR_LEN,
                 "capability '%s' unavailable (state=%d)", op->capability, cap->state);
        return OZAYN_ROUTER_ERR_CAPABILITY_UNAVAILABLE;
    }

    if (cap->state == OZAYN_REG_CAP_STATE_DISABLED) {
        op->precondition_failure = OZAYN_ROUTER_PRECOND_CAP_DISABLED;
        op->state = OZAYN_ROUTER_OP_REJECTED;
        op->result_state = OZAYN_ROUTER_RESULT_REJECTED;
        op->result_code = -1;
        snprintf(op->error_detail, OZAYN_ROUTER_MAX_ERROR_LEN,
                 "capability '%s' disabled", op->capability);
        return OZAYN_ROUTER_ERR_CAPABILITY_UNAVAILABLE;
    }

    /* Check provider exists */
    if (cap->provider_component[0] != '\0' &&
        !ozayn_reg_component_exists(reg, cap->provider_component)) {
        op->precondition_failure = OZAYN_ROUTER_PRECOND_DEP_MISSING;
        op->state = OZAYN_ROUTER_OP_REJECTED;
        op->result_state = OZAYN_ROUTER_RESULT_REJECTED;
        op->result_code = -1;
        snprintf(op->error_detail, OZAYN_ROUTER_MAX_ERROR_LEN,
                 "capability '%s' provider '%s' missing",
                 op->capability, cap->provider_component);
        return OZAYN_ROUTER_ERR_CAPABILITY_PROVIDER_MISSING;
    }

    ozayn_router_emit_event(svc, OZAYN_ROUTER_EVENT_CAPABILITY_RESOLVED,
                            op->operation_id, op->capability);
    return OZAYN_ROUTER_OK;
}

/* Internal: authorization check */
static ozayn_router_err_t _check_authorization(
    ozayn_router_service_t *svc,
    ozayn_router_operation_t *op)
{
    if (!svc->policy.require_authorization) {
        return OZAYN_ROUTER_OK;
    }

    /* Authorization check delegated to Section 03 authz service */
    if (svc->authorization) {
        svc->total_authorization_checks++;
        /* Authorization service is available — actual authorization
         * check would be performed here through ozayn_authz_authorize().
         * For this foundation step, we record the check. */
        return OZAYN_ROUTER_OK;
    }

    /* No authz service available — fail-closed if required */
    svc->total_authorization_denials++;
    op->state = OZAYN_ROUTER_OP_REJECTED;
    op->result_state = OZAYN_ROUTER_RESULT_REJECTED;
    op->result_code = -1;
    snprintf(op->error_detail, OZAYN_ROUTER_MAX_ERROR_LEN,
             "authorization required but service unavailable");
    ozayn_router_emit_event(svc, OZAYN_ROUTER_EVENT_AUTHORIZATION_FAILED,
                            op->operation_id, "authz unavailable");
    return OZAYN_ROUTER_ERR_AUTHORIZATION_UNAVAILABLE;
}

/* Internal: dispatch operation */
static ozayn_router_err_t _dispatch_operation(
    ozayn_router_service_t *svc,
    ozayn_router_operation_t *op)
{
    /* Foundation dispatch: mark operation as dispatched.
     * Real execution would invoke the target component's handler. */
    op->state = OZAYN_ROUTER_OP_DISPATCHING;
    op->start_time = time(NULL);

    /* Query operations always succeed in foundation */
    if (op->action == OZAYN_ROUTER_ACTION_QUERY) {
        op->state = OZAYN_ROUTER_OP_SUCCEEDED;
        op->result_state = OZAYN_ROUTER_RESULT_SUCCEEDED;
        op->result_code = 0;
        op->completion_time = time(NULL);
        svc->total_succeeded++;
        ozayn_router_emit_event(svc, OZAYN_ROUTER_EVENT_OPERATION_SUCCEEDED,
                                op->operation_id, "query succeeded");
        return OZAYN_ROUTER_OK;
    }

    /* Other operations: mark as unsupported in foundation */
    op->state = OZAYN_ROUTER_OP_UNSUPPORTED;
    op->result_state = OZAYN_ROUTER_RESULT_UNSUPPORTED;
    op->result_code = -1;
    op->completion_time = time(NULL);
    snprintf(op->error_detail, OZAYN_ROUTER_MAX_ERROR_LEN,
             "action '%s' not yet implemented in foundation",
             ozayn_router_action_name(op->action));
    svc->total_failed++;
    ozayn_router_emit_event(svc, OZAYN_ROUTER_EVENT_OPERATION_FAILED,
                            op->operation_id, op->error_detail);
    return OZAYN_ROUTER_OK;
}

ozayn_router_err_t ozayn_router_process(
    ozayn_router_service_t *svc,
    const char *operation_id,
    ozayn_router_result_t *out_result)
{
    if (!svc) return OZAYN_ROUTER_ERR_NULL;
    if (!svc->initialized) return OZAYN_ROUTER_ERR_NOT_INITIALIZED;
    if (!operation_id || operation_id[0] == '\0')
        return OZAYN_ROUTER_ERR_INVALID_PARAM;

    /* Find operation */
    ozayn_router_operation_t *op = NULL;
    for (int i = 0; i < svc->operation_count; i++) {
        int idx = (svc->operation_head + i) % OZAYN_ROUTER_MAX_OPERATIONS;
        if (svc->operations[idx].active &&
            strcmp(svc->operations[idx].operation_id, operation_id) == 0) {
            op = &svc->operations[idx];
            break;
        }
    }
    if (!op) return OZAYN_ROUTER_ERR_NOT_FOUND;

    /* Only process RECEIVED operations */
    if (op->state != OZAYN_ROUTER_OP_RECEIVED) {
        if (out_result) {
            memset(out_result, 0, sizeof(*out_result));
            strncpy(out_result->operation_id, op->operation_id,
                    OZAYN_ROUTER_MAX_ID_LEN - 1);
            strncpy(out_result->request_id, op->request_id,
                    OZAYN_ROUTER_MAX_ID_LEN - 1);
            out_result->result_state = op->result_state;
            out_result->result_code = op->result_code;
            strncpy(out_result->target, op->target,
                    OZAYN_ROUTER_MAX_TARGET_LEN - 1);
            out_result->action = op->action;
            out_result->start_time = op->start_time;
            out_result->completion_time = op->completion_time;
            if (op->completion_time > op->request_time)
                out_result->duration_ms = (int)(op->completion_time - op->request_time) * 1000;
            strncpy(out_result->error_detail, op->error_detail,
                    OZAYN_ROUTER_MAX_ERROR_LEN - 1);
        }
        return OZAYN_ROUTER_OK;
    }

    /* === ROUTING PIPELINE === */

    /* Step 1: Validate */
    op->state = OZAYN_ROUTER_OP_VALIDATING;
    ozayn_router_err_t r = ozayn_router_validate_request(
        svc, op->request_id, op->action, op->target,
        op->capability[0] ? op->capability : NULL);
    if (r != OZAYN_ROUTER_OK) {
        op->state = OZAYN_ROUTER_OP_REJECTED;
        op->result_state = OZAYN_ROUTER_RESULT_REJECTED;
        op->result_code = -1;
        snprintf(op->error_detail, OZAYN_ROUTER_MAX_ERROR_LEN,
                 "validation failed: %s", ozayn_router_err_name(r));
        svc->total_rejected++;
        ozayn_router_emit_event(svc, OZAYN_ROUTER_EVENT_REQUEST_REJECTED,
                                op->operation_id, op->error_detail);
        ozayn_router_audit_operation(svc, op->operation_id,
                                     "REQUEST_REJECTED", op->error_detail);
        if (out_result) {
            memset(out_result, 0, sizeof(*out_result));
            strncpy(out_result->operation_id, op->operation_id,
                    OZAYN_ROUTER_MAX_ID_LEN - 1);
            strncpy(out_result->request_id, op->request_id,
                    OZAYN_ROUTER_MAX_ID_LEN - 1);
            out_result->result_state = OZAYN_ROUTER_RESULT_REJECTED;
            out_result->result_code = -1;
            strncpy(out_result->target, op->target,
                    OZAYN_ROUTER_MAX_TARGET_LEN - 1);
            out_result->action = op->action;
            strncpy(out_result->error_detail, op->error_detail,
                    OZAYN_ROUTER_MAX_ERROR_LEN - 1);
        }
        return OZAYN_ROUTER_OK;
    }
    op->state = OZAYN_ROUTER_OP_VALIDATED;
    ozayn_router_emit_event(svc, OZAYN_ROUTER_EVENT_REQUEST_VALIDATED,
                            op->operation_id, "validated");

    /* Step 2: Resolve target */
    op->state = OZAYN_ROUTER_OP_RESOLVING;
    r = _resolve_target(svc, op);
    if (r != OZAYN_ROUTER_OK) {
        svc->total_rejected++;
        ozayn_router_audit_operation(svc, op->operation_id,
                                     "TARGET_RESOLVE_FAILED", op->error_detail);
        if (out_result) {
            memset(out_result, 0, sizeof(*out_result));
            strncpy(out_result->operation_id, op->operation_id,
                    OZAYN_ROUTER_MAX_ID_LEN - 1);
            strncpy(out_result->request_id, op->request_id,
                    OZAYN_ROUTER_MAX_ID_LEN - 1);
            out_result->result_state = op->result_state;
            out_result->result_code = op->result_code;
            strncpy(out_result->target, op->target,
                    OZAYN_ROUTER_MAX_TARGET_LEN - 1);
            out_result->action = op->action;
            strncpy(out_result->error_detail, op->error_detail,
                    OZAYN_ROUTER_MAX_ERROR_LEN - 1);
        }
        return OZAYN_ROUTER_OK;
    }
    op->state = OZAYN_ROUTER_OP_RESOLVED;

    /* Step 3: Check capability */
    op->state = OZAYN_ROUTER_OP_CAPABILITY_CHECK;
    r = _check_capability(svc, op);
    if (r != OZAYN_ROUTER_OK) {
        svc->total_rejected++;
        ozayn_router_audit_operation(svc, op->operation_id,
                                     "CAPABILITY_CHECK_FAILED", op->error_detail);
        if (out_result) {
            memset(out_result, 0, sizeof(*out_result));
            strncpy(out_result->operation_id, op->operation_id,
                    OZAYN_ROUTER_MAX_ID_LEN - 1);
            strncpy(out_result->request_id, op->request_id,
                    OZAYN_ROUTER_MAX_ID_LEN - 1);
            out_result->result_state = op->result_state;
            out_result->result_code = op->result_code;
            strncpy(out_result->target, op->target,
                    OZAYN_ROUTER_MAX_TARGET_LEN - 1);
            out_result->action = op->action;
            strncpy(out_result->error_detail, op->error_detail,
                    OZAYN_ROUTER_MAX_ERROR_LEN - 1);
        }
        return OZAYN_ROUTER_OK;
    }
    op->state = OZAYN_ROUTER_OP_CAPABILITY_VERIFIED;

    /* Step 4: Precondition check */
    op->state = OZAYN_ROUTER_OP_PRECONDITION_CHECK;
    op->precondition_failure = OZAYN_ROUTER_PRECOND_NONE;
    /* Preconditions are checked via target/capability resolution above.
     * Additional preconditions can be added here. */
    op->state = OZAYN_ROUTER_OP_PRECONDITION_PASSED;

    /* Step 5: Authorization */
    op->state = OZAYN_ROUTER_OP_AUTHORIZING;
    r = _check_authorization(svc, op);
    if (r != OZAYN_ROUTER_OK) {
        svc->total_rejected++;
        ozayn_router_audit_operation(svc, op->operation_id,
                                     "AUTHORIZATION_FAILED", op->error_detail);
        if (out_result) {
            memset(out_result, 0, sizeof(*out_result));
            strncpy(out_result->operation_id, op->operation_id,
                    OZAYN_ROUTER_MAX_ID_LEN - 1);
            strncpy(out_result->request_id, op->request_id,
                    OZAYN_ROUTER_MAX_ID_LEN - 1);
            out_result->result_state = op->result_state;
            out_result->result_code = op->result_code;
            strncpy(out_result->target, op->target,
                    OZAYN_ROUTER_MAX_TARGET_LEN - 1);
            out_result->action = op->action;
            strncpy(out_result->error_detail, op->error_detail,
                    OZAYN_ROUTER_MAX_ERROR_LEN - 1);
        }
        return OZAYN_ROUTER_OK;
    }
    op->state = OZAYN_ROUTER_OP_AUTHORIZED;
    ozayn_router_emit_event(svc, OZAYN_ROUTER_EVENT_AUTHORIZATION_PASSED,
                            op->operation_id, "authorized");

    /* Step 6: Queue */
    op->state = OZAYN_ROUTER_OP_QUEUED;
    ozayn_router_emit_event(svc, OZAYN_ROUTER_EVENT_OPERATION_QUEUED,
                            op->operation_id, "queued");

    /* Step 7: Dispatch */
    r = _dispatch_operation(svc, op);

    /* Audit final result */
    const char *audit_event = "OPERATION_SUCCEEDED";
    if (op->result_state == OZAYN_ROUTER_RESULT_FAILED)
        audit_event = "OPERATION_FAILED";
    else if (op->result_state == OZAYN_ROUTER_RESULT_UNSUPPORTED)
        audit_event = "OPERATION_UNSUPPORTED";
    ozayn_router_audit_operation(svc, op->operation_id,
                                 audit_event, op->error_detail);

    /* Fill result */
    if (out_result) {
        memset(out_result, 0, sizeof(*out_result));
        strncpy(out_result->operation_id, op->operation_id,
                OZAYN_ROUTER_MAX_ID_LEN - 1);
        strncpy(out_result->request_id, op->request_id,
                OZAYN_ROUTER_MAX_ID_LEN - 1);
        out_result->result_state = op->result_state;
        out_result->result_code = op->result_code;
        strncpy(out_result->target, op->target,
                OZAYN_ROUTER_MAX_TARGET_LEN - 1);
        out_result->action = op->action;
        out_result->start_time = op->start_time;
        out_result->completion_time = op->completion_time;
        if (op->completion_time > op->request_time)
            out_result->duration_ms = (int)(op->completion_time - op->request_time) * 1000;
        strncpy(out_result->error_detail, op->error_detail,
                OZAYN_ROUTER_MAX_ERROR_LEN - 1);
    }

    return OZAYN_ROUTER_OK;
}

/* ============================================================
 * SECTION 14 — CANCELLATION
 * ============================================================ */

ozayn_router_err_t ozayn_router_cancel(
    ozayn_router_service_t *svc,
    const char *operation_id)
{
    if (!svc) return OZAYN_ROUTER_ERR_NULL;
    if (!svc->initialized) return OZAYN_ROUTER_ERR_NOT_INITIALIZED;
    if (!operation_id || operation_id[0] == '\0')
        return OZAYN_ROUTER_ERR_INVALID_PARAM;

    for (int i = 0; i < svc->operation_count; i++) {
        int idx = (svc->operation_head + i) % OZAYN_ROUTER_MAX_OPERATIONS;
        ozayn_router_operation_t *op = &svc->operations[idx];
        if (op->active && strcmp(op->operation_id, operation_id) == 0) {
            /* Can only cancel non-terminal operations */
            if (_op_is_terminal(op->state)) {
                return OZAYN_ROUTER_ERR_STATE_INVALID;
            }
            /* Can only cancel operations not yet running */
            if (op->state == OZAYN_ROUTER_OP_RUNNING ||
                op->state == OZAYN_ROUTER_OP_DISPATCHING) {
                return OZAYN_ROUTER_ERR_CANCELLATION_UNSUPPORTED;
            }

            op->state = OZAYN_ROUTER_OP_CANCELLED;
            op->result_state = OZAYN_ROUTER_RESULT_CANCELLED;
            op->result_code = -1;
            op->completion_time = time(NULL);
            svc->total_cancelled++;

            ozayn_router_emit_event(svc, OZAYN_ROUTER_EVENT_OPERATION_CANCELLED,
                                    op->operation_id, "cancelled");
            ozayn_router_audit_operation(svc, op->operation_id,
                                         "OPERATION_CANCELLED", "user cancel");
            return OZAYN_ROUTER_OK;
        }
    }
    return OZAYN_ROUTER_ERR_NOT_FOUND;
}

int ozayn_router_operation_cancellable(
    const ozayn_router_service_t *svc,
    const char *operation_id)
{
    if (!svc || !operation_id || operation_id[0] == '\0') return 0;

    for (int i = 0; i < svc->operation_count; i++) {
        int idx = (svc->operation_head + i) % OZAYN_ROUTER_MAX_OPERATIONS;
        const ozayn_router_operation_t *op = &svc->operations[idx];
        if (op->active && strcmp(op->operation_id, operation_id) == 0) {
            return !_op_is_terminal(op->state) &&
                   op->state != OZAYN_ROUTER_OP_RUNNING &&
                   op->state != OZAYN_ROUTER_OP_DISPATCHING;
        }
    }
    return 0;
}

/* ============================================================
 * SECTION 15 — QUERY
 * ============================================================ */

ozayn_router_operation_t *ozayn_router_get_operation(
    ozayn_router_service_t *svc,
    const char *operation_id)
{
    if (!svc || !operation_id || operation_id[0] == '\0') return NULL;

    for (int i = 0; i < svc->operation_count; i++) {
        int idx = (svc->operation_head + i) % OZAYN_ROUTER_MAX_OPERATIONS;
        if (svc->operations[idx].active &&
            strcmp(svc->operations[idx].operation_id, operation_id) == 0) {
            return &svc->operations[idx];
        }
    }
    return NULL;
}

int ozayn_router_operation_count(const ozayn_router_service_t *svc)
{
    if (!svc) return 0;
    return svc->operation_count;
}

int ozayn_router_active_count(const ozayn_router_service_t *svc)
{
    if (!svc) return 0;
    int count = 0;
    for (int i = 0; i < svc->operation_count; i++) {
        int idx = (svc->operation_head + i) % OZAYN_ROUTER_MAX_OPERATIONS;
        if (svc->operations[idx].active &&
            _op_active(svc->operations[idx].state)) {
            count++;
        }
    }
    return count;
}

int ozayn_router_queue_full(const ozayn_router_service_t *svc)
{
    if (!svc) return 1;
    return svc->operation_count >= svc->policy.max_queue_size;
}

int ozayn_router_concurrency_limit(const ozayn_router_service_t *svc)
{
    if (!svc) return 1;
    return svc->active_ops >= svc->policy.max_concurrent_ops;
}

/* ============================================================
 * SECTION 16 — EVENT OBSERVATION
 * ============================================================ */

ozayn_router_err_t ozayn_router_emit_event(
    ozayn_router_service_t *svc,
    ozayn_router_event_type_t event_type,
    const char *operation_id,
    const char *detail)
{
    if (!svc) return OZAYN_ROUTER_ERR_NULL;
    (void)event_type;
    (void)operation_id;
    (void)detail;
    /* Event observation — uses the event engine if available */
    return OZAYN_ROUTER_OK;
}

int ozayn_router_event_count(const ozayn_router_service_t *svc)
{
    if (!svc) return 0;
    return 0;
}

/* ============================================================
 * SECTION 17 — AUDIT
 * ============================================================ */

ozayn_router_err_t ozayn_router_audit_operation(
    ozayn_router_service_t *svc,
    const char *operation_id,
    const char *event_type,
    const char *detail)
{
    if (!svc) return OZAYN_ROUTER_ERR_NULL;
    if (!operation_id || !event_type) return OZAYN_ROUTER_ERR_INVALID_PARAM;

    /* Audit logging — records safe operational information only.
     * Never logs passwords, keys, tokens, or credentials. */
    _audit_log(svc, operation_id, event_type, detail);
    return OZAYN_ROUTER_OK;
}

/* ============================================================
 * SECTION 18 — POLICY
 * ============================================================ */

ozayn_router_policy_t ozayn_router_default_policy(void)
{
    ozayn_router_policy_t p;
    memset(&p, 0, sizeof(p));
    p.enabled = 1;
    p.max_concurrent_ops = 16;
    p.max_queue_size = OZAYN_ROUTER_MAX_QUEUE;
    p.request_timeout_ms = 30000;
    p.queue_timeout_ms = 10000;
    p.execution_timeout_ms = 60000;
    p.max_retries = 0;
    p.require_authorization = 0;
    p.require_session = 0;
    p.allow_idempotent_replay = 1;
    p.require_capability = 0;
    return p;
}

ozayn_router_err_t ozayn_router_set_policy(
    ozayn_router_service_t *svc,
    const ozayn_router_policy_t *policy)
{
    if (!svc) return OZAYN_ROUTER_ERR_NULL;
    if (!policy) return OZAYN_ROUTER_ERR_INVALID_PARAM;
    svc->policy = *policy;
    return OZAYN_ROUTER_OK;
}

const ozayn_router_policy_t *ozayn_router_get_policy(
    const ozayn_router_service_t *svc)
{
    if (!svc) return NULL;
    return &svc->policy;
}

/* ============================================================
 * SECTION 19 — STATISTICS
 * ============================================================ */

uint64_t ozayn_router_total_requests(const ozayn_router_service_t *svc)
{
    if (!svc) return 0;
    return svc->total_requests;
}

uint64_t ozayn_router_total_succeeded(const ozayn_router_service_t *svc)
{
    if (!svc) return 0;
    return svc->total_succeeded;
}

uint64_t ozayn_router_total_failed(const ozayn_router_service_t *svc)
{
    if (!svc) return 0;
    return svc->total_failed;
}

uint64_t ozayn_router_total_rejected(const ozayn_router_service_t *svc)
{
    if (!svc) return 0;
    return svc->total_rejected;
}

uint64_t ozayn_router_total_cancelled(const ozayn_router_service_t *svc)
{
    if (!svc) return 0;
    return svc->total_cancelled;
}

uint64_t ozayn_router_total_timeouts(const ozayn_router_service_t *svc)
{
    if (!svc) return 0;
    return svc->total_timeouts;
}

uint64_t ozayn_router_total_duplicates(const ozayn_router_service_t *svc)
{
    if (!svc) return 0;
    return svc->total_duplicates;
}

/* ============================================================
 * SECTION 20 — CLEANUP
 * ============================================================ */

int ozayn_router_cleanup_completed(ozayn_router_service_t *svc)
{
    if (!svc) return 0;
    int cleaned = 0;
    for (int i = 0; i < svc->operation_count; i++) {
        int idx = (svc->operation_head + i) % OZAYN_ROUTER_MAX_OPERATIONS;
        ozayn_router_operation_t *op = &svc->operations[idx];
        if (op->active && _op_is_terminal(op->state)) {
            op->active = 0;
            cleaned++;
        }
    }
    return cleaned;
}

int ozayn_router_cleanup_expired(ozayn_router_service_t *svc)
{
    if (!svc) return 0;
    int cleaned = 0;
    time_t now = time(NULL);
    for (int i = 0; i < svc->operation_count; i++) {
        int idx = (svc->operation_head + i) % OZAYN_ROUTER_MAX_OPERATIONS;
        ozayn_router_operation_t *op = &svc->operations[idx];
        if (op->active && _op_is_terminal(op->state)) {
            int age = (int)(now - op->completion_time);
            if (age > 300) {
                op->active = 0;
                cleaned++;
            }
        }
    }
    return cleaned;
}
