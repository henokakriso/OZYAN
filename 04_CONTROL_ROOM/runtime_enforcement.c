#include "runtime_enforcement.h"
#include <string.h>
#include <stdio.h>
#include <time.h>

/* ============================================================
 * SECTION 1 — INTERNAL HELPERS
 * ============================================================ */

static int64_t _now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static void _generate_id(char *buf, int len, const char *prefix, int seq) {
    snprintf(buf, len, "%s-%06d", prefix, seq);
}

static void _emit_event(ozayn_roe_service_t *svc, ozayn_roe_event_type_t type,
                        const char *source, const char *message,
                        const char *request_id, const char *operation_id) {
    if (!svc || !message) return;
    int idx = svc->event_head;
    ozayn_roe_event_t *ev = &svc->events[idx];
    ev->type = type;
    _generate_id(ev->id, OZAYN_ROE_MAX_ID_LEN, "ROEE", (int)svc->event_sequence);
    strncpy(ev->source, source ? source : "enforcement", OZAYN_ROE_MAX_NAME_LEN - 1);
    strncpy(ev->message, message, OZAYN_ROE_MAX_DESC_LEN - 1);
    if (request_id)
        strncpy(ev->request_id, request_id, OZAYN_ROE_MAX_ID_LEN - 1);
    if (operation_id)
        strncpy(ev->operation_id, operation_id, OZAYN_ROE_MAX_ID_LEN - 1);
    ev->timestamp_ms = _now_ms();
    ev->sequence = svc->event_sequence++;
    svc->event_head = (svc->event_head + 1) % OZAYN_ROE_MAX_EVENTS;
    if (svc->event_count < OZAYN_ROE_MAX_EVENTS) svc->event_count++;
}

static int _add_blocking(ozayn_roe_enforcement_t *d, const char *msg) {
    if (d->blocking_count >= OZAYN_ROE_MAX_BLOCKING) return -1;
    strncpy(d->blocking[d->blocking_count], msg, OZAYN_ROE_MAX_DESC_LEN - 1);
    d->blocking_count++;
    return 0;
}

static int _add_warning(ozayn_roe_enforcement_t *d, const char *msg) {
    if (d->warning_count >= OZAYN_ROE_MAX_WARNINGS) return -1;
    strncpy(d->warnings[d->warning_count], msg, OZAYN_ROE_MAX_DESC_LEN - 1);
    d->warning_count++;
    return 0;
}

static void _store_decision(ozayn_roe_service_t *svc, ozayn_roe_enforcement_t *d) {
    int idx = svc->decision_head;
    svc->decisions[idx] = *d;
    svc->decision_head = (svc->decision_head + 1) % OZAYN_ROE_MAX_DECISIONS;
    if (svc->decision_count < OZAYN_ROE_MAX_DECISIONS) svc->decision_count++;
}

static ozayn_roe_enforcement_t *_find_decision(ozayn_roe_service_t *svc,
                                                const char *id) {
    for (int i = 0; i < svc->decision_count; i++) {
        int idx = (svc->decision_head - svc->decision_count + i +
                   OZAYN_ROE_MAX_DECISIONS) % OZAYN_ROE_MAX_DECISIONS;
        if (strcmp(svc->decisions[idx].id, id) == 0) {
            return &svc->decisions[idx];
        }
    }
    return NULL;
}

/* ============================================================
 * SECTION 2 — LIFECYCLE
 * ============================================================ */

ozayn_roe_err_t ozayn_roe_service_init(ozayn_roe_service_t *svc,
                                       const ozayn_roe_config_t *cfg) {
    if (!svc) return OZAYN_ROE_ERR_NULL;
    if (svc->initialized) return OZAYN_ROE_ERR_ALREADY_INITIALIZED;

    memset(svc, 0, sizeof(ozayn_roe_service_t));

    if (cfg) {
        svc->readiness = cfg->readiness;
        svc->audit = cfg->audit;
        svc->safety = cfg->safety;
        svc->resource_manager = cfg->resource_manager;
        svc->component_registry = cfg->component_registry;
        svc->device_session = cfg->device_session;
        svc->operation_queue = cfg->operation_queue;
        svc->operation_history = cfg->operation_history;
        svc->pipeline_scheduler = cfg->pipeline_scheduler;
        svc->workflow_orchestrator = cfg->workflow_orchestrator;
        svc->pipeline_coordinator = cfg->pipeline_coordinator;
        svc->events_engine = cfg->events_engine;
        svc->diagnostics = cfg->diagnostics;
        svc->command_router = cfg->command_router;
        svc->mode_transition_policy = cfg->mode_transition_policy;
    }

    svc->initialized = 1;
    return OZAYN_ROE_OK;
}

ozayn_roe_err_t ozayn_roe_service_shutdown(ozayn_roe_service_t *svc) {
    if (!svc) return OZAYN_ROE_ERR_NULL;
    if (!svc->initialized) return OZAYN_ROE_ERR_NOT_INITIALIZED;
    svc->initialized = 0;
    return OZAYN_ROE_OK;
}

/* ============================================================
 * SECTION 3 — SUBSYSTEM BINDING
 * ============================================================ */

ozayn_roe_err_t ozayn_roe_set_readiness(ozayn_roe_service_t *svc, void *ptr) {
    if (!svc) return OZAYN_ROE_ERR_NULL; svc->readiness = ptr; return OZAYN_ROE_OK;
}
ozayn_roe_err_t ozayn_roe_set_audit(ozayn_roe_service_t *svc, void *ptr) {
    if (!svc) return OZAYN_ROE_ERR_NULL; svc->audit = ptr; return OZAYN_ROE_OK;
}
ozayn_roe_err_t ozayn_roe_set_safety(ozayn_roe_service_t *svc, void *ptr) {
    if (!svc) return OZAYN_ROE_ERR_NULL; svc->safety = ptr; return OZAYN_ROE_OK;
}
ozayn_roe_err_t ozayn_roe_set_resource_manager(ozayn_roe_service_t *svc, void *ptr) {
    if (!svc) return OZAYN_ROE_ERR_NULL; svc->resource_manager = ptr; return OZAYN_ROE_OK;
}
ozayn_roe_err_t ozayn_roe_set_component_registry(ozayn_roe_service_t *svc, void *ptr) {
    if (!svc) return OZAYN_ROE_ERR_NULL; svc->component_registry = ptr; return OZAYN_ROE_OK;
}
ozayn_roe_err_t ozayn_roe_set_device_session(ozayn_roe_service_t *svc, void *ptr) {
    if (!svc) return OZAYN_ROE_ERR_NULL; svc->device_session = ptr; return OZAYN_ROE_OK;
}
ozayn_roe_err_t ozayn_roe_set_operation_queue(ozayn_roe_service_t *svc, void *ptr) {
    if (!svc) return OZAYN_ROE_ERR_NULL; svc->operation_queue = ptr; return OZAYN_ROE_OK;
}
ozayn_roe_err_t ozayn_roe_set_operation_history(ozayn_roe_service_t *svc, void *ptr) {
    if (!svc) return OZAYN_ROE_ERR_NULL; svc->operation_history = ptr; return OZAYN_ROE_OK;
}
ozayn_roe_err_t ozayn_roe_set_pipeline_scheduler(ozayn_roe_service_t *svc, void *ptr) {
    if (!svc) return OZAYN_ROE_ERR_NULL; svc->pipeline_scheduler = ptr; return OZAYN_ROE_OK;
}
ozayn_roe_err_t ozayn_roe_set_workflow_orchestrator(ozayn_roe_service_t *svc, void *ptr) {
    if (!svc) return OZAYN_ROE_ERR_NULL; svc->workflow_orchestrator = ptr; return OZAYN_ROE_OK;
}
ozayn_roe_err_t ozayn_roe_set_pipeline_coordinator(ozayn_roe_service_t *svc, void *ptr) {
    if (!svc) return OZAYN_ROE_ERR_NULL; svc->pipeline_coordinator = ptr; return OZAYN_ROE_OK;
}
ozayn_roe_err_t ozayn_roe_set_events_engine(ozayn_roe_service_t *svc, void *ptr) {
    if (!svc) return OZAYN_ROE_ERR_NULL; svc->events_engine = ptr; return OZAYN_ROE_OK;
}
ozayn_roe_err_t ozayn_roe_set_diagnostics(ozayn_roe_service_t *svc, void *ptr) {
    if (!svc) return OZAYN_ROE_ERR_NULL; svc->diagnostics = ptr; return OZAYN_ROE_OK;
}
ozayn_roe_err_t ozayn_roe_set_command_router(ozayn_roe_service_t *svc, void *ptr) {
    if (!svc) return OZAYN_ROE_ERR_NULL; svc->command_router = ptr; return OZAYN_ROE_OK;
}
ozayn_roe_err_t ozayn_roe_set_mode_transition_policy(ozayn_roe_service_t *svc, void *ptr) {
    if (!svc) return OZAYN_ROE_ERR_NULL; svc->mode_transition_policy = ptr; return OZAYN_ROE_OK;
}

/* ============================================================
 * SECTION 4 — ENFORCEMENT PIPELINE
 * ============================================================ */

ozayn_roe_err_t ozayn_roe_enforce(ozayn_roe_service_t *svc,
                                   const ozayn_roe_request_t *request,
                                   const ozayn_roe_context_t *ctx,
                                   ozayn_roe_enforcement_t *out) {
    if (!svc || !request || !ctx || !out) return OZAYN_ROE_ERR_NULL;
    if (!svc->initialized) return OZAYN_ROE_ERR_NOT_INITIALIZED;

    memset(out, 0, sizeof(ozayn_roe_enforcement_t));
    _generate_id(out->id, OZAYN_ROE_MAX_ID_LEN, "RENF", svc->stats.total_requests);
    strncpy(out->request_id, request->id, OZAYN_ROE_MAX_ID_LEN - 1);
    strncpy(out->operation_id, request->operation_id, OZAYN_ROE_MAX_ID_LEN - 1);
    out->timestamp_ms = _now_ms();
    out->expiration_ms = out->timestamp_ms + OZAYN_ROE_DEFAULT_EXPIRY_MS;
    out->active = 1;

    /* Record request */
    ozayn_roe_request_t *req = &svc->requests[svc->request_head];
    *req = *request;
    if (req->request_time_ms == 0) req->request_time_ms = _now_ms();
    if (req->expiration_ms == 0)
        req->expiration_ms = req->request_time_ms + OZAYN_ROE_DEFAULT_EXPIRY_MS;
    req->active = 1;
    svc->request_head = (svc->request_head + 1) % OZAYN_ROE_MAX_REQUESTS;
    if (svc->request_count < OZAYN_ROE_MAX_REQUESTS) svc->request_count++;

    svc->stats.total_requests++;

    _emit_event(svc, OZAYN_ROE_EVENT_REQUESTED, "enforcement",
                "Enforcement requested", request->id, request->operation_id);

    /* STEP 1: Request validation */
    out->phase = OZAYN_ROE_PHASE_VALIDATING;
    if (request->id[0] == '\0') {
        _add_blocking(out, "Request ID is empty");
        out->decision = OZAYN_ROE_DECISION_BLOCK_DISPATCH;
        out->phase = OZAYN_ROE_PHASE_REJECTED;
        strncpy(out->reason, "INVALID_REQUEST", OZAYN_ROE_MAX_DESC_LEN - 1);
        _emit_event(svc, OZAYN_ROE_EVENT_BLOCKED, "enforcement",
                    "Invalid request", request->id, request->operation_id);
        _store_decision(svc, out);
        return OZAYN_ROE_OK;
    }

    /* STEP 2: Expiration check */
    if (_now_ms() > request->expiration_ms && request->expiration_ms > 0) {
        out->decision = OZAYN_ROE_DECISION_EXPIRED;
        out->phase = OZAYN_ROE_PHASE_EXPIRED;
        out->expired = 1;
        strncpy(out->reason, "REQUEST_EXPIRED", OZAYN_ROE_MAX_DESC_LEN - 1);
        svc->stats.total_expired++;
        _emit_event(svc, OZAYN_ROE_EVENT_EXPIRED, "enforcement",
                    "Request expired", request->id, request->operation_id);
        _store_decision(svc, out);
        return OZAYN_ROE_OK;
    }

    /* STEP 3: Operation state validation */
    out->phase = OZAYN_ROE_PHASE_REVALIDATING;
    if (ctx->operation_cancelled) {
        _add_blocking(out, "Operation has been cancelled");
        out->decision = OZAYN_ROE_DECISION_BLOCK_DISPATCH;
        out->phase = OZAYN_ROE_PHASE_BLOCKED;
        out->operation_valid = 0;
        strncpy(out->reason, "OPERATION_CANCELLED", OZAYN_ROE_MAX_DESC_LEN - 1);
        svc->stats.operation_blocks++;
        _emit_event(svc, OZAYN_ROE_EVENT_BLOCKED, "enforcement",
                    "Operation cancelled", request->id, request->operation_id);
        _store_decision(svc, out);
        return OZAYN_ROE_OK;
    }
    if (ctx->operation_expired) {
        _add_blocking(out, "Operation has expired");
        out->decision = OZAYN_ROE_DECISION_BLOCK_DISPATCH;
        out->phase = OZAYN_ROE_PHASE_BLOCKED;
        out->operation_valid = 0;
        strncpy(out->reason, "OPERATION_EXPIRED", OZAYN_ROE_MAX_DESC_LEN - 1);
        svc->stats.operation_blocks++;
        _emit_event(svc, OZAYN_ROE_EVENT_BLOCKED, "enforcement",
                    "Operation expired", request->id, request->operation_id);
        _store_decision(svc, out);
        return OZAYN_ROE_OK;
    }
    if (!ctx->operation_active) {
        _add_blocking(out, "Operation is not active");
        out->decision = OZAYN_ROE_DECISION_BLOCK_DISPATCH;
        out->phase = OZAYN_ROE_PHASE_BLOCKED;
        out->operation_valid = 0;
        strncpy(out->reason, "OPERATION_INACTIVE", OZAYN_ROE_MAX_DESC_LEN - 1);
        svc->stats.operation_blocks++;
        _emit_event(svc, OZAYN_ROE_EVENT_BLOCKED, "enforcement",
                    "Operation inactive", request->id, request->operation_id);
        _store_decision(svc, out);
        return OZAYN_ROE_OK;
    }
    if (ctx->duplicate_detected) {
        _add_blocking(out, "Duplicate execution detected");
        out->decision = OZAYN_ROE_DECISION_BLOCK_DISPATCH;
        out->phase = OZAYN_ROE_PHASE_BLOCKED;
        out->operation_valid = 0;
        strncpy(out->reason, "DUPLICATE_DETECTED", OZAYN_ROE_MAX_DESC_LEN - 1);
        svc->stats.total_duplicates_blocked++;
        svc->stats.operation_blocks++;
        _emit_event(svc, OZAYN_ROE_EVENT_DUPLICATE_BLOCKED, "enforcement",
                    "Duplicate execution blocked", request->id, request->operation_id);
        _store_decision(svc, out);
        return OZAYN_ROE_OK;
    }
    out->operation_valid = 1;

    /* STEP 4: Runtime mode validation */
    switch (ctx->runtime_mode) {
        case OZAYN_ORD_MODE_READY:
            out->mode_valid = 1;
            break;
        case OZAYN_ORD_MODE_READY_DEGRADED:
            out->mode_valid = 1;
            _add_warning(out, "System degraded — requirements must be satisfied");
            break;
        case OZAYN_ORD_MODE_RECOVERY:
            out->mode_valid = 0;
            _add_blocking(out, "Recovery mode — only recovery operations allowed");
            out->decision = OZAYN_ROE_DECISION_REQUIRE_MODE_RECHECK;
            out->phase = OZAYN_ROE_PHASE_MODE_CHECK;
            strncpy(out->reason, "MODE_RECOVERY", OZAYN_ROE_MAX_DESC_LEN - 1);
            svc->stats.mode_blocks++;
            _emit_event(svc, OZAYN_ROE_EVENT_MODE_CHECK_REQUIRED, "enforcement",
                        "Mode is RECOVERY", request->id, request->operation_id);
            _store_decision(svc, out);
            return OZAYN_ROE_OK;
        case OZAYN_ORD_MODE_MAINTENANCE:
            out->mode_valid = 0;
            _add_blocking(out, "Maintenance mode — normal operations restricted");
            out->decision = OZAYN_ROE_DECISION_REQUIRE_MODE_RECHECK;
            out->phase = OZAYN_ROE_PHASE_MODE_CHECK;
            strncpy(out->reason, "MODE_MAINTENANCE", OZAYN_ROE_MAX_DESC_LEN - 1);
            svc->stats.mode_blocks++;
            _emit_event(svc, OZAYN_ROE_EVENT_MODE_CHECK_REQUIRED, "enforcement",
                        "Mode is MAINTENANCE", request->id, request->operation_id);
            _store_decision(svc, out);
            return OZAYN_ROE_OK;
        case OZAYN_ORD_MODE_SAFE_HOLD:
            out->mode_valid = 0;
            _add_blocking(out, "Safe hold — only diagnostics/security/recovery allowed");
            out->decision = OZAYN_ROE_DECISION_BLOCK_DISPATCH;
            out->phase = OZAYN_ROE_PHASE_BLOCKED;
            strncpy(out->reason, "MODE_SAFE_HOLD", OZAYN_ROE_MAX_DESC_LEN - 1);
            svc->stats.mode_blocks++;
            _emit_event(svc, OZAYN_ROE_EVENT_BLOCKED, "enforcement",
                        "Mode is SAFE_HOLD", request->id, request->operation_id);
            _store_decision(svc, out);
            return OZAYN_ROE_OK;
        case OZAYN_ORD_MODE_BLOCKED:
            out->mode_valid = 0;
            _add_blocking(out, "System blocked");
            out->decision = OZAYN_ROE_DECISION_BLOCK_DISPATCH;
            out->phase = OZAYN_ROE_PHASE_BLOCKED;
            strncpy(out->reason, "MODE_BLOCKED", OZAYN_ROE_MAX_DESC_LEN - 1);
            svc->stats.mode_blocks++;
            _emit_event(svc, OZAYN_ROE_EVENT_BLOCKED, "enforcement",
                        "Mode is BLOCKED", request->id, request->operation_id);
            _store_decision(svc, out);
            return OZAYN_ROE_OK;
        case OZAYN_ORD_MODE_SHUTTING_DOWN:
            out->mode_valid = 0;
            _add_blocking(out, "Shutting down — no new dispatches");
            out->decision = OZAYN_ROE_DECISION_BLOCK_DISPATCH;
            out->phase = OZAYN_ROE_PHASE_BLOCKED;
            strncpy(out->reason, "MODE_SHUTTING_DOWN", OZAYN_ROE_MAX_DESC_LEN - 1);
            svc->stats.mode_blocks++;
            _emit_event(svc, OZAYN_ROE_EVENT_BLOCKED, "enforcement",
                        "Mode is SHUTTING_DOWN", request->id, request->operation_id);
            _store_decision(svc, out);
            return OZAYN_ROE_OK;
        case OZAYN_ORD_MODE_FAILED:
            out->mode_valid = 0;
            _add_blocking(out, "System failed — no operations allowed");
            out->decision = OZAYN_ROE_DECISION_BLOCK_DISPATCH;
            out->phase = OZAYN_ROE_PHASE_BLOCKED;
            strncpy(out->reason, "MODE_FAILED", OZAYN_ROE_MAX_DESC_LEN - 1);
            svc->stats.mode_blocks++;
            _emit_event(svc, OZAYN_ROE_EVENT_BLOCKED, "enforcement",
                        "Mode is FAILED", request->id, request->operation_id);
            _store_decision(svc, out);
            return OZAYN_ROE_OK;
        case OZAYN_ORD_MODE_UNKNOWN:
        case OZAYN_ORD_MODE_INITIALIZING:
        default:
            out->mode_valid = 0;
            _add_blocking(out, "System not ready");
            out->decision = OZAYN_ROE_DECISION_REQUIRE_MODE_RECHECK;
            out->phase = OZAYN_ROE_PHASE_MODE_CHECK;
            strncpy(out->reason, "MODE_NOT_READY", OZAYN_ROE_MAX_DESC_LEN - 1);
            svc->stats.mode_blocks++;
            _emit_event(svc, OZAYN_ROE_EVENT_MODE_CHECK_REQUIRED, "enforcement",
                        "Mode not ready", request->id, request->operation_id);
            _store_decision(svc, out);
            return OZAYN_ROE_OK;
    }

    /* STEP 5: Readiness validation */
    if (!ctx->readiness_satisfied) {
        _add_blocking(out, "Readiness not satisfied");
        out->decision = OZAYN_ROE_DECISION_REQUIRE_REASSESSMENT;
        out->phase = OZAYN_ROE_PHASE_REVALIDATING;
        out->readiness_valid = 0;
        strncpy(out->reason, "READINESS_NOT_SATISFIED", OZAYN_ROE_MAX_DESC_LEN - 1);
        svc->stats.readiness_blocks++;
        _emit_event(svc, OZAYN_ROE_EVENT_REASSESSMENT_REQUIRED, "enforcement",
                    "Readiness not satisfied", request->id, request->operation_id);
        _store_decision(svc, out);
        return OZAYN_ROE_OK;
    }
    out->readiness_valid = 1;

    /* STEP 6: Target component validation */
    if (request->target_component_id[0] != '\0' && !ctx->component_available) {
        _add_blocking(out, "Target component unavailable");
        out->decision = OZAYN_ROE_DECISION_BLOCK_DISPATCH;
        out->phase = OZAYN_ROE_PHASE_TARGET_CHECK;
        out->target_valid = 0;
        strncpy(out->reason, "TARGET_UNAVAILABLE", OZAYN_ROE_MAX_DESC_LEN - 1);
        svc->stats.target_blocks++;
        _emit_event(svc, OZAYN_ROE_EVENT_BLOCKED, "enforcement",
                    "Target unavailable", request->id, request->operation_id);
        _store_decision(svc, out);
        return OZAYN_ROE_OK;
    }
    out->target_valid = 1;

    /* STEP 7: Capability validation */
    if (request->capability_id[0] != '\0' && !ctx->capability_available) {
        _add_blocking(out, "Required capability unavailable");
        out->decision = OZAYN_ROE_DECISION_BLOCK_DISPATCH;
        out->phase = OZAYN_ROE_PHASE_TARGET_CHECK;
        out->capability_valid = 0;
        strncpy(out->reason, "CAPABILITY_UNAVAILABLE", OZAYN_ROE_MAX_DESC_LEN - 1);
        svc->stats.capability_blocks++;
        _emit_event(svc, OZAYN_ROE_EVENT_BLOCKED, "enforcement",
                    "Capability unavailable", request->id, request->operation_id);
        _store_decision(svc, out);
        return OZAYN_ROE_OK;
    }
    out->capability_valid = 1;

    /* STEP 8: Security session validation */
    if (request->security_session_ref[0] != '\0' && !ctx->security_session_valid) {
        _add_blocking(out, "Security session invalid");
        out->decision = OZAYN_ROE_DECISION_REQUIRE_AUTHORIZATION;
        out->phase = OZAYN_ROE_PHASE_SECURITY_CHECK;
        out->security_valid = 0;
        strncpy(out->reason, "SECURITY_SESSION_INVALID", OZAYN_ROE_MAX_DESC_LEN - 1);
        svc->stats.security_blocks++;
        _emit_event(svc, OZAYN_ROE_EVENT_AUTHORIZATION_REQUIRED, "enforcement",
                    "Security session invalid", request->id, request->operation_id);
        _store_decision(svc, out);
        return OZAYN_ROE_OK;
    }

    /* STEP 9: Authorization validation */
    if (request->security_session_ref[0] != '\0' && !ctx->authorization_valid) {
        _add_blocking(out, "Authorization not granted");
        out->decision = OZAYN_ROE_DECISION_REQUIRE_AUTHORIZATION;
        out->phase = OZAYN_ROE_PHASE_SECURITY_CHECK;
        out->authorization_valid = 0;
        strncpy(out->reason, "AUTHORIZATION_FAILED", OZAYN_ROE_MAX_DESC_LEN - 1);
        svc->stats.authorization_blocks++;
        _emit_event(svc, OZAYN_ROE_EVENT_AUTHORIZATION_REQUIRED, "enforcement",
                    "Authorization failed", request->id, request->operation_id);
        _store_decision(svc, out);
        return OZAYN_ROE_OK;
    }
    out->security_valid = ctx->security_session_valid;
    out->authorization_valid = ctx->authorization_valid;

    /* STEP 10: Safety/policy validation */
    if (!ctx->safety_policy_valid) {
        _add_blocking(out, "Safety policy not satisfied");
        out->decision = OZAYN_ROE_DECISION_REQUIRE_SAFETY_RECHECK;
        out->phase = OZAYN_ROE_PHASE_SAFETY_CHECK;
        out->safety_valid = 0;
        strncpy(out->reason, "SAFETY_FAILED", OZAYN_ROE_MAX_DESC_LEN - 1);
        svc->stats.safety_blocks++;
        _emit_event(svc, OZAYN_ROE_EVENT_SAFETY_CHECK_REQUIRED, "enforcement",
                    "Safety check required", request->id, request->operation_id);
        _store_decision(svc, out);
        return OZAYN_ROE_OK;
    }
    out->safety_valid = 1;

    /* STEP 11: Dependency validation */
    if (!ctx->dependencies_satisfied) {
        _add_blocking(out, "Dependencies not satisfied");
        out->decision = OZAYN_ROE_DECISION_REQUIRE_REASSESSMENT;
        out->phase = OZAYN_ROE_PHASE_REVALIDATING;
        out->dependency_valid = 0;
        strncpy(out->reason, "DEPENDENCY_FAILED", OZAYN_ROE_MAX_DESC_LEN - 1);
        svc->stats.dependency_blocks++;
        _emit_event(svc, OZAYN_ROE_EVENT_REASSESSMENT_REQUIRED, "enforcement",
                    "Dependencies not satisfied", request->id, request->operation_id);
        _store_decision(svc, out);
        return OZAYN_ROE_OK;
    }
    out->dependency_valid = 1;

    /* STEP 12: Resource validation */
    if (!ctx->resources_available) {
        _add_blocking(out, "Resources unavailable");
        out->decision = OZAYN_ROE_DECISION_REQUIRE_RESOURCE_RECHECK;
        out->phase = OZAYN_ROE_PHASE_RESOURCE_CHECK;
        out->resource_valid = 0;
        strncpy(out->reason, "RESOURCE_UNAVAILABLE", OZAYN_ROE_MAX_DESC_LEN - 1);
        svc->stats.resource_blocks++;
        _emit_event(svc, OZAYN_ROE_EVENT_RESOURCE_CHECK_REQUIRED, "enforcement",
                    "Resources unavailable", request->id, request->operation_id);
        _store_decision(svc, out);
        return OZAYN_ROE_OK;
    }
    out->resource_valid = 1;

    /* STEP 13: Device validation */
    if (!ctx->devices_available) {
        _add_blocking(out, "Device unavailable");
        out->decision = OZAYN_ROE_DECISION_REQUIRE_DEVICE_RECHECK;
        out->phase = OZAYN_ROE_PHASE_DEVICE_CHECK;
        out->device_valid = 0;
        strncpy(out->reason, "DEVICE_UNAVAILABLE", OZAYN_ROE_MAX_DESC_LEN - 1);
        svc->stats.device_blocks++;
        _emit_event(svc, OZAYN_ROE_EVENT_DEVICE_CHECK_REQUIRED, "enforcement",
                    "Device unavailable", request->id, request->operation_id);
        _store_decision(svc, out);
        return OZAYN_ROE_OK;
    }
    out->device_valid = 1;

    /* STEP 14: Workflow/pipeline validation */
    if (request->workflow_id[0] != '\0' && !ctx->workflow_valid) {
        _add_blocking(out, "Workflow invalid");
        out->decision = OZAYN_ROE_DECISION_BLOCK_DISPATCH;
        out->phase = OZAYN_ROE_PHASE_TARGET_CHECK;
        out->workflow_valid = 0;
        strncpy(out->reason, "WORKFLOW_BLOCKED", OZAYN_ROE_MAX_DESC_LEN - 1);
        svc->stats.workflow_blocks++;
        _emit_event(svc, OZAYN_ROE_EVENT_BLOCKED, "enforcement",
                    "Workflow blocked", request->id, request->operation_id);
        _store_decision(svc, out);
        return OZAYN_ROE_OK;
    }
    if (request->pipeline_id[0] != '\0' && !ctx->pipeline_valid) {
        _add_blocking(out, "Pipeline unavailable");
        out->decision = OZAYN_ROE_DECISION_BLOCK_DISPATCH;
        out->phase = OZAYN_ROE_PHASE_TARGET_CHECK;
        out->pipeline_valid = 0;
        strncpy(out->reason, "PIPELINE_BLOCKED", OZAYN_ROE_MAX_DESC_LEN - 1);
        svc->stats.pipeline_blocks++;
        _emit_event(svc, OZAYN_ROE_EVENT_BLOCKED, "enforcement",
                    "Pipeline blocked", request->id, request->operation_id);
        _store_decision(svc, out);
        return OZAYN_ROE_OK;
    }
    out->workflow_valid = ctx->workflow_valid;
    out->pipeline_valid = ctx->pipeline_valid;

    /* STEP 15: Final decision — ALLOW DISPATCH */
    out->phase = OZAYN_ROE_PHASE_APPROVED;
    out->decision = OZAYN_ROE_DECISION_ALLOW_DISPATCH;
    strncpy(out->reason, "DISPATCH_APPROVED", OZAYN_ROE_MAX_DESC_LEN - 1);
    svc->stats.total_approved++;

    _emit_event(svc, OZAYN_ROE_EVENT_APPROVED, "enforcement",
                "Dispatch approved", request->id, request->operation_id);
    _store_decision(svc, out);
    return OZAYN_ROE_OK;
}

/* ============================================================
 * SECTION 5 — QUICK CHECK
 * ============================================================ */

int ozayn_roe_can_dispatch(const ozayn_roe_service_t *svc,
                           const ozayn_roe_request_t *request,
                           const ozayn_roe_context_t *ctx) {
    if (!svc || !request || !ctx) return 0;
    if (!svc->initialized) return 0;
    if (request->id[0] == '\0') return 0;
    if (request->expiration_ms > 0 && _now_ms() > request->expiration_ms) return 0;

    /* Operation state */
    if (ctx->operation_cancelled || ctx->operation_expired ||
        !ctx->operation_active || ctx->duplicate_detected) return 0;

    /* Mode check */
    switch (ctx->runtime_mode) {
        case OZAYN_ORD_MODE_READY: break;
        case OZAYN_ORD_MODE_READY_DEGRADED: break;
        default: return 0;
    }

    if (!ctx->readiness_satisfied) return 0;
    if (request->target_component_id[0] != '\0' && !ctx->component_available) return 0;
    if (request->capability_id[0] != '\0' && !ctx->capability_available) return 0;
    if (request->security_session_ref[0] != '\0' && !ctx->security_session_valid) return 0;
    if (request->security_session_ref[0] != '\0' && !ctx->authorization_valid) return 0;
    if (!ctx->safety_policy_valid) return 0;
    if (!ctx->resources_available) return 0;
    if (!ctx->devices_available) return 0;
    if (request->workflow_id[0] != '\0' && !ctx->workflow_valid) return 0;
    if (request->pipeline_id[0] != '\0' && !ctx->pipeline_valid) return 0;

    return 1;
}

/* ============================================================
 * SECTION 6 — REASSESSMENT
 * ============================================================ */

ozayn_roe_err_t ozayn_roe_reassess(ozayn_roe_service_t *svc,
                                    const char *enforcement_id,
                                    const ozayn_roe_context_t *ctx,
                                    ozayn_roe_enforcement_t *out) {
    if (!svc || !enforcement_id || !ctx || !out) return OZAYN_ROE_ERR_NULL;
    if (!svc->initialized) return OZAYN_ROE_ERR_NOT_INITIALIZED;

    ozayn_roe_enforcement_t *existing = _find_decision(svc, enforcement_id);
    if (!existing) return OZAYN_ROE_ERR_NOT_FOUND;
    if (!existing->active) return OZAYN_ROE_ERR_INVALIDATED;

    if (existing->reassessment_count >= OZAYN_ROE_MAX_REASSESSMENTS) {
        _add_blocking(out, "Maximum reassessments exceeded");
        out->decision = OZAYN_ROE_DECISION_BLOCK_DISPATCH;
        out->phase = OZAYN_ROE_PHASE_BLOCKED;
        strncpy(out->reason, "REASSESSMENT_LIMIT", OZAYN_ROE_MAX_DESC_LEN - 1);
        _store_decision(svc, out);
        return OZAYN_ROE_OK;
    }

    int prev_count = existing->reassessment_count;
    /* Invalidate the old decision before re-evaluation */
    existing->active = 0;

    svc->stats.total_reassessments++;
    _emit_event(svc, OZAYN_ROE_EVENT_REVALIDATING, "enforcement",
                "Reassessment started", enforcement_id, NULL);

    /* Reconstruct a request from the existing enforcement for re-evaluation */
    ozayn_roe_request_t req;
    memset(&req, 0, sizeof(req));
    strncpy(req.id, existing->request_id, OZAYN_ROE_MAX_ID_LEN - 1);
    strncpy(req.operation_id, existing->operation_id, OZAYN_ROE_MAX_ID_LEN - 1);
    /* Copy the original request from the ring buffer to restore security/session refs */
    for (int i = 0; i < svc->request_count; i++) {
        int ridx = (svc->request_head - svc->request_count + i +
                    OZAYN_ROE_MAX_REQUESTS) % OZAYN_ROE_MAX_REQUESTS;
        if (strcmp(svc->requests[ridx].id, existing->request_id) == 0) {
            req = svc->requests[ridx];
            strncpy(req.id, existing->request_id, OZAYN_ROE_MAX_ID_LEN - 1);
            strncpy(req.operation_id, existing->operation_id, OZAYN_ROE_MAX_ID_LEN - 1);
            break;
        }
    }

    ozayn_roe_err_t rc = ozayn_roe_enforce(svc, &req, ctx, out);
    if (rc == OZAYN_ROE_OK) {
        /* Update the stored decision with reassessment count */
        int stored_idx = (svc->decision_head - 1 + OZAYN_ROE_MAX_DECISIONS) %
                         OZAYN_ROE_MAX_DECISIONS;
        svc->decisions[stored_idx].reassessment_count = prev_count + 1;
        out->reassessment_count = prev_count + 1;
    }

    _emit_event(svc, OZAYN_ROE_EVENT_REVALIDATING, "enforcement",
                "Reassessment completed", enforcement_id, NULL);
    return rc;
}

/* ============================================================
 * SECTION 7 — INVALIDATION
 * ============================================================ */

ozayn_roe_err_t ozayn_roe_invalidate(ozayn_roe_service_t *svc,
                                      const char *enforcement_id) {
    if (!svc || !enforcement_id) return OZAYN_ROE_ERR_NULL;
    if (!svc->initialized) return OZAYN_ROE_ERR_NOT_INITIALIZED;

    ozayn_roe_enforcement_t *d = _find_decision(svc, enforcement_id);
    if (!d) return OZAYN_ROE_ERR_NOT_FOUND;
    if (!d->active) return OZAYN_ROE_ERR_INVALIDATED;

    d->active = 0;
    svc->stats.total_invalidated++;
    _emit_event(svc, OZAYN_ROE_EVENT_CANCELLED, "enforcement",
                "Decision invalidated", enforcement_id, NULL);
    return OZAYN_ROE_OK;
}

/* ============================================================
 * SECTION 8 — QUERIES
 * ============================================================ */

ozayn_roe_err_t ozayn_roe_get_decision(const ozayn_roe_service_t *svc,
                                        const char *enforcement_id,
                                        ozayn_roe_enforcement_t *out) {
    if (!svc || !out) return OZAYN_ROE_ERR_NULL;
    if (!svc->initialized) return OZAYN_ROE_ERR_NOT_INITIALIZED;
    for (int i = 0; i < svc->decision_count; i++) {
        int idx = (svc->decision_head - svc->decision_count + i +
                   OZAYN_ROE_MAX_DECISIONS) % OZAYN_ROE_MAX_DECISIONS;
        if (svc->decisions[idx].active &&
            strcmp(svc->decisions[idx].id, enforcement_id) == 0) {
            *out = svc->decisions[idx];
            return OZAYN_ROE_OK;
        }
    }
    return OZAYN_ROE_ERR_NOT_FOUND;
}

ozayn_roe_err_t ozayn_roe_get_latest_decision(const ozayn_roe_service_t *svc,
                                                ozayn_roe_enforcement_t *out) {
    if (!svc || !out) return OZAYN_ROE_ERR_NULL;
    if (!svc->initialized) return OZAYN_ROE_ERR_NOT_INITIALIZED;
    if (svc->decision_count == 0) return OZAYN_ROE_ERR_NOT_FOUND;
    int idx = (svc->decision_head - 1 + OZAYN_ROE_MAX_DECISIONS) %
              OZAYN_ROE_MAX_DECISIONS;
    *out = svc->decisions[idx];
    return OZAYN_ROE_OK;
}

int ozayn_roe_decision_count(const ozayn_roe_service_t *svc) {
    if (!svc || !svc->initialized) return 0;
    return svc->decision_count;
}

ozayn_roe_err_t ozayn_roe_get_request(const ozayn_roe_service_t *svc,
                                       const char *request_id,
                                       ozayn_roe_request_t *out) {
    if (!svc || !out) return OZAYN_ROE_ERR_NULL;
    if (!svc->initialized) return OZAYN_ROE_ERR_NOT_INITIALIZED;
    for (int i = 0; i < svc->request_count; i++) {
        int idx = (svc->request_head - svc->request_count + i +
                   OZAYN_ROE_MAX_REQUESTS) % OZAYN_ROE_MAX_REQUESTS;
        if (svc->requests[idx].active &&
            strcmp(svc->requests[idx].id, request_id) == 0) {
            *out = svc->requests[idx];
            return OZAYN_ROE_OK;
        }
    }
    return OZAYN_ROE_ERR_NOT_FOUND;
}

int ozayn_roe_request_count(const ozayn_roe_service_t *svc) {
    if (!svc || !svc->initialized) return 0;
    return svc->request_count;
}

/* ============================================================
 * SECTION 9 — EVENTS
 * ============================================================ */

ozayn_roe_err_t ozayn_roe_get_event(const ozayn_roe_service_t *svc,
                                     int index, ozayn_roe_event_t *out) {
    if (!svc || !out) return OZAYN_ROE_ERR_NULL;
    if (!svc->initialized) return OZAYN_ROE_ERR_NOT_INITIALIZED;
    if (index < 0 || index >= svc->event_count) return OZAYN_ROE_ERR_NOT_FOUND;
    int actual = (svc->event_head - svc->event_count + index +
                  OZAYN_ROE_MAX_EVENTS) % OZAYN_ROE_MAX_EVENTS;
    *out = svc->events[actual];
    return OZAYN_ROE_OK;
}

int ozayn_roe_event_count(const ozayn_roe_service_t *svc) {
    if (!svc || !svc->initialized) return 0;
    return svc->event_count;
}

/* ============================================================
 * SECTION 10 — STATISTICS
 * ============================================================ */

const ozayn_roe_stats_t *ozayn_roe_get_stats(const ozayn_roe_service_t *svc) {
    if (!svc || !svc->initialized) return NULL;
    return &svc->stats;
}

ozayn_roe_err_t ozayn_roe_reset_stats(ozayn_roe_service_t *svc) {
    if (!svc) return OZAYN_ROE_ERR_NULL;
    if (!svc->initialized) return OZAYN_ROE_ERR_NOT_INITIALIZED;
    memset(&svc->stats, 0, sizeof(ozayn_roe_stats_t));
    return OZAYN_ROE_OK;
}

/* ============================================================
 * SECTION 11 — NAME HELPERS
 * ============================================================ */

const char *ozayn_roe_err_name(ozayn_roe_err_t err) {
    switch (err) {
        case OZAYN_ROE_OK: return "OK";
        case OZAYN_ROE_ERR_NULL: return "NULL";
        case OZAYN_ROE_ERR_NOT_INITIALIZED: return "NOT_INITIALIZED";
        case OZAYN_ROE_ERR_ALREADY_INITIALIZED: return "ALREADY_INITIALIZED";
        case OZAYN_ROE_ERR_INVALID_PARAM: return "INVALID_PARAM";
        case OZAYN_ROE_ERR_STATE_INVALID: return "STATE_INVALID";
        case OZAYN_ROE_ERR_NOT_FOUND: return "NOT_FOUND";
        case OZAYN_ROE_ERR_EXPIRED: return "EXPIRED";
        case OZAYN_ROE_ERR_INVALIDATED: return "INVALIDATED";
        case OZAYN_ROE_ERR_MODE_BLOCKED: return "MODE_BLOCKED";
        case OZAYN_ROE_ERR_READINESS_BLOCKED: return "READINESS_BLOCKED";
        case OZAYN_ROE_ERR_TARGET_INVALID: return "TARGET_INVALID";
        case OZAYN_ROE_ERR_TARGET_UNAVAILABLE: return "TARGET_UNAVAILABLE";
        case OZAYN_ROE_ERR_CAPABILITY_UNAVAILABLE: return "CAPABILITY_UNAVAILABLE";
        case OZAYN_ROE_ERR_AUTHORIZATION_FAILED: return "AUTHORIZATION_FAILED";
        case OZAYN_ROE_ERR_PERMISSION_DENIED: return "PERMISSION_DENIED";
        case OZAYN_ROE_ERR_SECURITY_UNAVAILABLE: return "SECURITY_UNAVAILABLE";
        case OZAYN_ROE_ERR_SAFETY_FAILED: return "SAFETY_FAILED";
        case OZAYN_ROE_ERR_POLICY_DENIED: return "POLICY_DENIED";
        case OZAYN_ROE_ERR_SAFETY_UNAVAILABLE: return "SAFETY_UNAVAILABLE";
        case OZAYN_ROE_ERR_RESOURCE_UNAVAILABLE: return "RESOURCE_UNAVAILABLE";
        case OZAYN_ROE_ERR_RESOURCE_CONFLICT: return "RESOURCE_CONFLICT";
        case OZAYN_ROE_ERR_DEVICE_UNAVAILABLE: return "DEVICE_UNAVAILABLE";
        case OZAYN_ROE_ERR_DEVICE_SESSION_INVALID: return "DEVICE_SESSION_INVALID";
        case OZAYN_ROE_ERR_WORKFLOW_BLOCKED: return "WORKFLOW_BLOCKED";
        case OZAYN_ROE_ERR_PIPELINE_BLOCKED: return "PIPELINE_BLOCKED";
        case OZAYN_ROE_ERR_DEPENDENCY_FAILED: return "DEPENDENCY_FAILED";
        case OZAYN_ROE_ERR_CONFLICT: return "CONFLICT";
        case OZAYN_ROE_ERR_REASSESSMENT_REQUIRED: return "REASSESSMENT_REQUIRED";
        case OZAYN_ROE_ERR_TIMEOUT: return "TIMEOUT";
        case OZAYN_ROE_ERR_CANCELLED: return "CANCELLED";
        case OZAYN_ROE_ERR_CONCURRENCY_ERROR: return "CONCURRENCY_ERROR";
        case OZAYN_ROE_ERR_CONFIGURATION_ERROR: return "CONFIGURATION_ERROR";
        case OZAYN_ROE_ERR_EVENT_ERROR: return "EVENT_ERROR";
        case OZAYN_ROE_ERR_LIMIT_REACHED: return "LIMIT_REACHED";
    }
    return "UNKNOWN";
}

const char *ozayn_roe_decision_name(ozayn_roe_decision_t d) {
    switch (d) {
        case OZAYN_ROE_DECISION_ALLOW_DISPATCH: return "ALLOW_DISPATCH";
        case OZAYN_ROE_DECISION_BLOCK_DISPATCH: return "BLOCK_DISPATCH";
        case OZAYN_ROE_DECISION_REQUIRE_REASSESSMENT: return "REQUIRE_REASSESSMENT";
        case OZAYN_ROE_DECISION_REQUIRE_AUTHORIZATION: return "REQUIRE_AUTHORIZATION";
        case OZAYN_ROE_DECISION_REQUIRE_SAFETY_RECHECK: return "REQUIRE_SAFETY_RECHECK";
        case OZAYN_ROE_DECISION_REQUIRE_RESOURCE_RECHECK: return "REQUIRE_RESOURCE_RECHECK";
        case OZAYN_ROE_DECISION_REQUIRE_DEVICE_RECHECK: return "REQUIRE_DEVICE_RECHECK";
        case OZAYN_ROE_DECISION_REQUIRE_MODE_RECHECK: return "REQUIRE_MODE_RECHECK";
        case OZAYN_ROE_DECISION_EXPIRED: return "EXPIRED";
        case OZAYN_ROE_DECISION_UNAVAILABLE: return "UNAVAILABLE";
    }
    return "UNKNOWN";
}

const char *ozayn_roe_phase_name(ozayn_roe_phase_t p) {
    switch (p) {
        case OZAYN_ROE_PHASE_NONE: return "NONE";
        case OZAYN_ROE_PHASE_REQUESTED: return "REQUESTED";
        case OZAYN_ROE_PHASE_VALIDATING: return "VALIDATING";
        case OZAYN_ROE_PHASE_REVALIDATING: return "REVALIDATING";
        case OZAYN_ROE_PHASE_SECURITY_CHECK: return "SECURITY_CHECK";
        case OZAYN_ROE_PHASE_SAFETY_CHECK: return "SAFETY_CHECK";
        case OZAYN_ROE_PHASE_RESOURCE_CHECK: return "RESOURCE_CHECK";
        case OZAYN_ROE_PHASE_DEVICE_CHECK: return "DEVICE_CHECK";
        case OZAYN_ROE_PHASE_MODE_CHECK: return "MODE_CHECK";
        case OZAYN_ROE_PHASE_TARGET_CHECK: return "TARGET_CHECK";
        case OZAYN_ROE_PHASE_APPROVED: return "APPROVED";
        case OZAYN_ROE_PHASE_DISPATCHING: return "DISPATCHING";
        case OZAYN_ROE_PHASE_DISPATCHED: return "DISPATCHED";
        case OZAYN_ROE_PHASE_REJECTED: return "REJECTED";
        case OZAYN_ROE_PHASE_BLOCKED: return "BLOCKED";
        case OZAYN_ROE_PHASE_EXPIRED: return "EXPIRED";
        case OZAYN_ROE_PHASE_FAILED: return "FAILED";
        case OZAYN_ROE_PHASE_CANCELLED: return "CANCELLED";
        case OZAYN_ROE_PHASE_UNAVAILABLE: return "UNAVAILABLE";
    }
    return "UNKNOWN";
}

const char *ozayn_roe_event_type_name(ozayn_roe_event_type_t t) {
    switch (t) {
        case OZAYN_ROE_EVENT_REQUESTED: return "REQUESTED";
        case OZAYN_ROE_EVENT_VALIDATING: return "VALIDATING";
        case OZAYN_ROE_EVENT_REVALIDATING: return "REVALIDATING";
        case OZAYN_ROE_EVENT_APPROVED: return "APPROVED";
        case OZAYN_ROE_EVENT_BLOCKED: return "BLOCKED";
        case OZAYN_ROE_EVENT_REASSESSMENT_REQUIRED: return "REASSESSMENT_REQUIRED";
        case OZAYN_ROE_EVENT_AUTHORIZATION_REQUIRED: return "AUTHORIZATION_REQUIRED";
        case OZAYN_ROE_EVENT_SAFETY_CHECK_REQUIRED: return "SAFETY_CHECK_REQUIRED";
        case OZAYN_ROE_EVENT_RESOURCE_CHECK_REQUIRED: return "RESOURCE_CHECK_REQUIRED";
        case OZAYN_ROE_EVENT_DEVICE_CHECK_REQUIRED: return "DEVICE_CHECK_REQUIRED";
        case OZAYN_ROE_EVENT_MODE_CHECK_REQUIRED: return "MODE_CHECK_REQUIRED";
        case OZAYN_ROE_EVENT_DISPATCHING: return "DISPATCHING";
        case OZAYN_ROE_EVENT_DISPATCHED: return "DISPATCHED";
        case OZAYN_ROE_EVENT_EXPIRED: return "EXPIRED";
        case OZAYN_ROE_EVENT_CANCELLED: return "CANCELLED";
        case OZAYN_ROE_EVENT_FAILED: return "FAILED";
        case OZAYN_ROE_EVENT_DUPLICATE_BLOCKED: return "DUPLICATE_BLOCKED";
        case OZAYN_ROE_EVENT_COUNT: return "COUNT";
    }
    return "UNKNOWN";
}
