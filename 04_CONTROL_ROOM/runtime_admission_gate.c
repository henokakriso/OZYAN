#include "runtime_admission_gate.h"
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

static void _emit_event(ozayn_rag_service_t *svc, ozayn_rag_event_type_t type,
                        const char *source, const char *message,
                        const char *request_id) {
    if (!svc || !message) return;
    int idx = svc->event_head;
    ozayn_rag_event_t *ev = &svc->events[idx];
    ev->type = type;
    _generate_id(ev->id, OZAYN_RAG_MAX_ID_LEN, "RAGE", (int)svc->event_sequence);
    strncpy(ev->source, source ? source : "rag", OZAYN_RAG_MAX_NAME_LEN - 1);
    strncpy(ev->message, message, OZAYN_RAG_MAX_DESC_LEN - 1);
    if (request_id)
        strncpy(ev->request_id, request_id, OZAYN_RAG_MAX_ID_LEN - 1);
    ev->timestamp_ms = _now_ms();
    ev->sequence = svc->event_sequence++;
    svc->event_head = (svc->event_head + 1) % OZAYN_RAG_MAX_EVENTS;
    if (svc->event_count < OZAYN_RAG_MAX_EVENTS) svc->event_count++;
}

static int _add_blocking(ozayn_rag_admission_t *d, const char *msg) {
    if (d->blocking_count >= OZAYN_RAG_MAX_BLOCKING) return -1;
    strncpy(d->blocking[d->blocking_count], msg, OZAYN_RAG_MAX_DESC_LEN - 1);
    d->blocking_count++;
    return 0;
}

static int _add_warning(ozayn_rag_admission_t *d, const char *msg) {
    if (d->warning_count >= OZAYN_RAG_MAX_WARNINGS) return -1;
    strncpy(d->warnings[d->warning_count], msg, OZAYN_RAG_MAX_DESC_LEN - 1);
    d->warning_count++;
    return 0;
}

static void _store_decision(ozayn_rag_service_t *svc, ozayn_rag_admission_t *d) {
    int idx = svc->decision_head;
    svc->decisions[idx] = *d;
    svc->decision_head = (svc->decision_head + 1) % OZAYN_RAG_MAX_DECISIONS;
    if (svc->decision_count < OZAYN_RAG_MAX_DECISIONS) svc->decision_count++;
}

static ozayn_rag_admission_t *_find_decision(ozayn_rag_service_t *svc,
                                              const char *id) {
    for (int i = 0; i < svc->decision_count; i++) {
        int idx = (svc->decision_head - svc->decision_count + i +
                   OZAYN_RAG_MAX_DECISIONS) % OZAYN_RAG_MAX_DECISIONS;
        if (strcmp(svc->decisions[idx].id, id) == 0) {
            return &svc->decisions[idx];
        }
    }
    return NULL;
}

/* ============================================================
 * SECTION 2 — LIFECYCLE
 * ============================================================ */

ozayn_rag_err_t ozayn_rag_service_init(ozayn_rag_service_t *svc,
                                       const ozayn_rag_config_t *cfg) {
    if (!svc) return OZAYN_RAG_ERR_NULL;
    if (svc->initialized) return OZAYN_RAG_ERR_ALREADY_INITIALIZED;

    memset(svc, 0, sizeof(ozayn_rag_service_t));

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
        svc->events_engine = cfg->events_engine;
        svc->diagnostics = cfg->diagnostics;
    }

    svc->initialized = 1;
    return OZAYN_RAG_OK;
}

ozayn_rag_err_t ozayn_rag_service_shutdown(ozayn_rag_service_t *svc) {
    if (!svc) return OZAYN_RAG_ERR_NULL;
    if (!svc->initialized) return OZAYN_RAG_ERR_NOT_INITIALIZED;
    svc->initialized = 0;
    return OZAYN_RAG_OK;
}

/* ============================================================
 * SECTION 3 — SUBSYSTEM BINDING
 * ============================================================ */

ozayn_rag_err_t ozayn_rag_set_readiness(ozayn_rag_service_t *svc, void *ptr) {
    if (!svc) return OZAYN_RAG_ERR_NULL; svc->readiness = ptr; return OZAYN_RAG_OK;
}
ozayn_rag_err_t ozayn_rag_set_audit(ozayn_rag_service_t *svc, void *ptr) {
    if (!svc) return OZAYN_RAG_ERR_NULL; svc->audit = ptr; return OZAYN_RAG_OK;
}
ozayn_rag_err_t ozayn_rag_set_safety(ozayn_rag_service_t *svc, void *ptr) {
    if (!svc) return OZAYN_RAG_ERR_NULL; svc->safety = ptr; return OZAYN_RAG_OK;
}
ozayn_rag_err_t ozayn_rag_set_resource_manager(ozayn_rag_service_t *svc, void *ptr) {
    if (!svc) return OZAYN_RAG_ERR_NULL; svc->resource_manager = ptr; return OZAYN_RAG_OK;
}
ozayn_rag_err_t ozayn_rag_set_component_registry(ozayn_rag_service_t *svc, void *ptr) {
    if (!svc) return OZAYN_RAG_ERR_NULL; svc->component_registry = ptr; return OZAYN_RAG_OK;
}
ozayn_rag_err_t ozayn_rag_set_device_session(ozayn_rag_service_t *svc, void *ptr) {
    if (!svc) return OZAYN_RAG_ERR_NULL; svc->device_session = ptr; return OZAYN_RAG_OK;
}
ozayn_rag_err_t ozayn_rag_set_operation_queue(ozayn_rag_service_t *svc, void *ptr) {
    if (!svc) return OZAYN_RAG_ERR_NULL; svc->operation_queue = ptr; return OZAYN_RAG_OK;
}
ozayn_rag_err_t ozayn_rag_set_operation_history(ozayn_rag_service_t *svc, void *ptr) {
    if (!svc) return OZAYN_RAG_ERR_NULL; svc->operation_history = ptr; return OZAYN_RAG_OK;
}
ozayn_rag_err_t ozayn_rag_set_pipeline_scheduler(ozayn_rag_service_t *svc, void *ptr) {
    if (!svc) return OZAYN_RAG_ERR_NULL; svc->pipeline_scheduler = ptr; return OZAYN_RAG_OK;
}
ozayn_rag_err_t ozayn_rag_set_workflow_orchestrator(ozayn_rag_service_t *svc, void *ptr) {
    if (!svc) return OZAYN_RAG_ERR_NULL; svc->workflow_orchestrator = ptr; return OZAYN_RAG_OK;
}
ozayn_rag_err_t ozayn_rag_set_events_engine(ozayn_rag_service_t *svc, void *ptr) {
    if (!svc) return OZAYN_RAG_ERR_NULL; svc->events_engine = ptr; return OZAYN_RAG_OK;
}
ozayn_rag_err_t ozayn_rag_set_diagnostics(ozayn_rag_service_t *svc, void *ptr) {
    if (!svc) return OZAYN_RAG_ERR_NULL; svc->diagnostics = ptr; return OZAYN_RAG_OK;
}

/* ============================================================
 * SECTION 4 — EVALUATION PIPELINE
 * ============================================================ */

ozayn_rag_err_t ozayn_rag_admit(ozayn_rag_service_t *svc,
                                const ozayn_rag_request_t *request,
                                const ozayn_rag_context_t *ctx,
                                ozayn_rag_admission_t *out) {
    if (!svc || !request || !ctx || !out) return OZAYN_RAG_ERR_NULL;
    if (!svc->initialized) return OZAYN_RAG_ERR_NOT_INITIALIZED;

    memset(out, 0, sizeof(ozayn_rag_admission_t));
    _generate_id(out->id, OZAYN_RAG_MAX_ID_LEN, "RADM", svc->stats.total_requests);
    strncpy(out->admission_request_id, request->id, OZAYN_RAG_MAX_ID_LEN - 1);
    strncpy(out->operation_id, request->operation_id, OZAYN_RAG_MAX_ID_LEN - 1);
    out->timestamp_ms = _now_ms();
    out->expiration_ms = out->timestamp_ms + OZAYN_RAG_DEFAULT_EXPIRY_MS;
    out->active = 1;

    /* Record request */
    ozayn_rag_request_t *req = &svc->requests[svc->request_head];
    *req = *request;
    if (req->timestamp_ms == 0) req->timestamp_ms = _now_ms();
    if (req->expiration_ms == 0)
        req->expiration_ms = req->timestamp_ms + OZAYN_RAG_DEFAULT_EXPIRY_MS;
    req->active = 1;
    svc->request_head = (svc->request_head + 1) % OZAYN_RAG_MAX_REQUESTS;
    if (svc->request_count < OZAYN_RAG_MAX_REQUESTS) svc->request_count++;

    svc->stats.total_requests++;

    _emit_event(svc, OZAYN_RAG_EVENT_REQUESTED, "admission_gate",
                "Admission requested", request->id);

    /* STEP 1: Request validation */
    out->phase = OZAYN_RAG_PHASE_VALIDATING;
    if (request->id[0] == '\0') {
        _add_blocking(out, "Request ID is empty");
        out->decision = OZAYN_RAG_DECISION_DENY;
        out->phase = OZAYN_RAG_PHASE_DENIED;
        strncpy(out->reason, "INVALID_REQUEST", OZAYN_RAG_MAX_DESC_LEN - 1);
        svc->stats.total_denied++;
        _emit_event(svc, OZAYN_RAG_EVENT_DENIED, "admission_gate",
                    "Invalid request", request->id);
        _store_decision(svc, out);
        return OZAYN_RAG_OK;
    }

    /* STEP 2: Request expiration */
    if (_now_ms() > request->expiration_ms && request->expiration_ms > 0) {
        out->decision = OZAYN_RAG_DECISION_EXPIRED;
        out->phase = OZAYN_RAG_PHASE_EXPIRED;
        strncpy(out->reason, "REQUEST_EXPIRED", OZAYN_RAG_MAX_DESC_LEN - 1);
        svc->stats.total_expired++;
        _emit_event(svc, OZAYN_RAG_EVENT_EXPIRED, "admission_gate",
                    "Request expired", request->id);
        _store_decision(svc, out);
        return OZAYN_RAG_OK;
    }

    /* STEP 3: Runtime mode validation */
    out->phase = OZAYN_RAG_PHASE_EVALUATING;
    switch (ctx->runtime_mode) {
        case OZAYN_ORD_MODE_READY:
            break;
        case OZAYN_ORD_MODE_READY_DEGRADED:
            _add_warning(out, "System degraded — requirements must be satisfied");
            break;
        case OZAYN_ORD_MODE_RECOVERY:
            _add_blocking(out, "Recovery mode — only recovery operations allowed");
            out->decision = OZAYN_RAG_DECISION_DEFER;
            out->phase = OZAYN_RAG_PHASE_DEFERRED;
            strncpy(out->reason, "MODE_RECOVERY", OZAYN_RAG_MAX_DESC_LEN - 1);
            svc->stats.total_deferred++;
            svc->stats.mode_denials++;
            _emit_event(svc, OZAYN_RAG_EVENT_DEFERRED, "admission_gate",
                        "Mode is RECOVERY", request->id);
            _store_decision(svc, out);
            return OZAYN_RAG_OK;
        case OZAYN_ORD_MODE_MAINTENANCE:
            _add_blocking(out, "Maintenance mode — normal operations restricted");
            out->decision = OZAYN_RAG_DECISION_DEFER;
            out->phase = OZAYN_RAG_PHASE_DEFERRED;
            strncpy(out->reason, "MODE_MAINTENANCE", OZAYN_RAG_MAX_DESC_LEN - 1);
            svc->stats.total_deferred++;
            svc->stats.mode_denials++;
            _emit_event(svc, OZAYN_RAG_EVENT_DEFERRED, "admission_gate",
                        "Mode is MAINTENANCE", request->id);
            _store_decision(svc, out);
            return OZAYN_RAG_OK;
        case OZAYN_ORD_MODE_SAFE_HOLD:
            _add_blocking(out, "Safe hold — only diagnostics/security/recovery allowed");
            out->decision = OZAYN_RAG_DECISION_BLOCKED;
            out->phase = OZAYN_RAG_PHASE_BLOCKED;
            strncpy(out->reason, "MODE_SAFE_HOLD", OZAYN_RAG_MAX_DESC_LEN - 1);
            svc->stats.total_blocked++;
            svc->stats.mode_denials++;
            _emit_event(svc, OZAYN_RAG_EVENT_BLOCKED, "admission_gate",
                        "Mode is SAFE_HOLD", request->id);
            _store_decision(svc, out);
            return OZAYN_RAG_OK;
        case OZAYN_ORD_MODE_BLOCKED:
            _add_blocking(out, "System blocked");
            out->decision = OZAYN_RAG_DECISION_BLOCKED;
            out->phase = OZAYN_RAG_PHASE_BLOCKED;
            strncpy(out->reason, "MODE_BLOCKED", OZAYN_RAG_MAX_DESC_LEN - 1);
            svc->stats.total_blocked++;
            svc->stats.mode_denials++;
            _emit_event(svc, OZAYN_RAG_EVENT_BLOCKED, "admission_gate",
                        "Mode is BLOCKED", request->id);
            _store_decision(svc, out);
            return OZAYN_RAG_OK;
        case OZAYN_ORD_MODE_SHUTTING_DOWN:
            _add_blocking(out, "Shutting down — no new operations");
            out->decision = OZAYN_RAG_DECISION_DENY;
            out->phase = OZAYN_RAG_PHASE_DENIED;
            strncpy(out->reason, "MODE_SHUTTING_DOWN", OZAYN_RAG_MAX_DESC_LEN - 1);
            svc->stats.total_denied++;
            svc->stats.mode_denials++;
            _emit_event(svc, OZAYN_RAG_EVENT_DENIED, "admission_gate",
                        "Mode is SHUTTING_DOWN", request->id);
            _store_decision(svc, out);
            return OZAYN_RAG_OK;
        case OZAYN_ORD_MODE_FAILED:
            _add_blocking(out, "System failed — no operations allowed");
            out->decision = OZAYN_RAG_DECISION_BLOCKED;
            out->phase = OZAYN_RAG_PHASE_BLOCKED;
            strncpy(out->reason, "MODE_FAILED", OZAYN_RAG_MAX_DESC_LEN - 1);
            svc->stats.total_blocked++;
            svc->stats.mode_denials++;
            _emit_event(svc, OZAYN_RAG_EVENT_BLOCKED, "admission_gate",
                        "Mode is FAILED", request->id);
            _store_decision(svc, out);
            return OZAYN_RAG_OK;
        case OZAYN_ORD_MODE_UNKNOWN:
        case OZAYN_ORD_MODE_INITIALIZING:
        default:
            _add_blocking(out, "System not ready");
            out->decision = OZAYN_RAG_DECISION_DEFER;
            out->phase = OZAYN_RAG_PHASE_DEFERRED;
            strncpy(out->reason, "MODE_NOT_READY", OZAYN_RAG_MAX_DESC_LEN - 1);
            svc->stats.total_deferred++;
            svc->stats.mode_denials++;
            _emit_event(svc, OZAYN_RAG_EVENT_DEFERRED, "admission_gate",
                        "Mode not ready", request->id);
            _store_decision(svc, out);
            return OZAYN_RAG_OK;
    }

    /* STEP 4: Readiness validation */
    if (!ctx->readiness_satisfied) {
        _add_blocking(out, "Readiness not satisfied");
        out->decision = OZAYN_RAG_DECISION_DEFER;
        out->phase = OZAYN_RAG_PHASE_DEFERRED;
        strncpy(out->reason, "READINESS_NOT_SATISFIED", OZAYN_RAG_MAX_DESC_LEN - 1);
        svc->stats.total_deferred++;
        _emit_event(svc, OZAYN_RAG_EVENT_REASSESSMENT_REQUIRED, "admission_gate",
                    "Readiness not satisfied", request->id);
        _store_decision(svc, out);
        return OZAYN_RAG_OK;
    }

    /* STEP 5: Target component validation */
    if (request->target_component_id[0] != '\0' && !ctx->component_available) {
        _add_blocking(out, "Target component unavailable");
        out->decision = OZAYN_RAG_DECISION_DENY;
        out->phase = OZAYN_RAG_PHASE_DENIED;
        strncpy(out->reason, "TARGET_UNAVAILABLE", OZAYN_RAG_MAX_DESC_LEN - 1);
        svc->stats.total_denied++;
        _emit_event(svc, OZAYN_RAG_EVENT_DENIED, "admission_gate",
                    "Target component unavailable", request->id);
        _store_decision(svc, out);
        return OZAYN_RAG_OK;
    }

    /* STEP 6: Capability validation */
    if (request->capability_id[0] != '\0' && !ctx->capability_available) {
        _add_blocking(out, "Required capability unavailable");
        out->decision = OZAYN_RAG_DECISION_DENY;
        out->phase = OZAYN_RAG_PHASE_DENIED;
        strncpy(out->reason, "CAPABILITY_UNAVAILABLE", OZAYN_RAG_MAX_DESC_LEN - 1);
        svc->stats.total_denied++;
        _emit_event(svc, OZAYN_RAG_EVENT_DENIED, "admission_gate",
                    "Capability unavailable", request->id);
        _store_decision(svc, out);
        return OZAYN_RAG_OK;
    }

    /* STEP 7: Security session validation */
    if (request->security_session_ref[0] != '\0' && !ctx->security_session_valid) {
        _add_blocking(out, "Security session invalid");
        out->decision = OZAYN_RAG_DECISION_REQUIRES_AUTHORIZATION;
        out->phase = OZAYN_RAG_PHASE_DEFERRED;
        strncpy(out->reason, "SECURITY_SESSION_INVALID", OZAYN_RAG_MAX_DESC_LEN - 1);
        svc->stats.total_denied++;
        svc->stats.security_denials++;
        _emit_event(svc, OZAYN_RAG_EVENT_AUTHORIZATION_REQUIRED, "admission_gate",
                    "Security session invalid", request->id);
        _store_decision(svc, out);
        return OZAYN_RAG_OK;
    }

    /* STEP 8: Authorization validation */
    if (request->security_session_ref[0] != '\0' && !ctx->authorization_valid) {
        _add_blocking(out, "Authorization not granted");
        out->decision = OZAYN_RAG_DECISION_REQUIRES_AUTHORIZATION;
        out->phase = OZAYN_RAG_PHASE_DEFERRED;
        strncpy(out->reason, "AUTHORIZATION_FAILED", OZAYN_RAG_MAX_DESC_LEN - 1);
        svc->stats.total_denied++;
        svc->stats.security_denials++;
        _emit_event(svc, OZAYN_RAG_EVENT_AUTHORIZATION_REQUIRED, "admission_gate",
                    "Authorization failed", request->id);
        _store_decision(svc, out);
        return OZAYN_RAG_OK;
    }

    /* STEP 9: Safety/policy validation */
    if (!ctx->safety_policy_valid) {
        _add_blocking(out, "Safety policy not satisfied");
        out->decision = OZAYN_RAG_DECISION_REQUIRES_SAFETY_CHECK;
        out->phase = OZAYN_RAG_PHASE_DEFERRED;
        strncpy(out->reason, "SAFETY_FAILED", OZAYN_RAG_MAX_DESC_LEN - 1);
        svc->stats.total_denied++;
        svc->stats.safety_denials++;
        _emit_event(svc, OZAYN_RAG_EVENT_SAFETY_CHECK_REQUIRED, "admission_gate",
                    "Safety check required", request->id);
        _store_decision(svc, out);
        return OZAYN_RAG_OK;
    }

    /* STEP 10: Dependency validation */
    if (!ctx->dependencies_satisfied) {
        _add_blocking(out, "Dependencies not satisfied");
        out->decision = OZAYN_RAG_DECISION_DEFER;
        out->phase = OZAYN_RAG_PHASE_DEFERRED;
        strncpy(out->reason, "DEPENDENCY_FAILED", OZAYN_RAG_MAX_DESC_LEN - 1);
        svc->stats.total_deferred++;
        _emit_event(svc, OZAYN_RAG_EVENT_REASSESSMENT_REQUIRED, "admission_gate",
                    "Dependencies not satisfied", request->id);
        _store_decision(svc, out);
        return OZAYN_RAG_OK;
    }

    /* STEP 11: Resource validation */
    if (!ctx->resources_available) {
        _add_blocking(out, "Resources unavailable");
        out->decision = OZAYN_RAG_DECISION_REQUIRES_RESOURCE_CHECK;
        out->phase = OZAYN_RAG_PHASE_DEFERRED;
        strncpy(out->reason, "RESOURCE_UNAVAILABLE", OZAYN_RAG_MAX_DESC_LEN - 1);
        svc->stats.total_deferred++;
        svc->stats.resource_denials++;
        _emit_event(svc, OZAYN_RAG_EVENT_RESOURCE_CHECK_REQUIRED, "admission_gate",
                    "Resources unavailable", request->id);
        _store_decision(svc, out);
        return OZAYN_RAG_OK;
    }

    /* STEP 12: Device validation */
    if (!ctx->devices_available) {
        _add_blocking(out, "Device unavailable");
        out->decision = OZAYN_RAG_DECISION_REQUIRES_DEVICE_CHECK;
        out->phase = OZAYN_RAG_PHASE_DEFERRED;
        strncpy(out->reason, "DEVICE_UNAVAILABLE", OZAYN_RAG_MAX_DESC_LEN - 1);
        svc->stats.total_deferred++;
        svc->stats.device_denials++;
        _emit_event(svc, OZAYN_RAG_EVENT_DEVICE_CHECK_REQUIRED, "admission_gate",
                    "Device unavailable", request->id);
        _store_decision(svc, out);
        return OZAYN_RAG_OK;
    }

    /* STEP 13: Workflow/pipeline validation */
    if (request->workflow_id[0] != '\0' && !ctx->workflow_valid) {
        _add_blocking(out, "Workflow invalid");
        out->decision = OZAYN_RAG_DECISION_DENY;
        out->phase = OZAYN_RAG_PHASE_DENIED;
        strncpy(out->reason, "WORKFLOW_BLOCKED", OZAYN_RAG_MAX_DESC_LEN - 1);
        svc->stats.total_denied++;
        _emit_event(svc, OZAYN_RAG_EVENT_DENIED, "admission_gate",
                    "Workflow blocked", request->id);
        _store_decision(svc, out);
        return OZAYN_RAG_OK;
    }

    if (request->pipeline_id[0] != '\0' && !ctx->pipeline_valid) {
        _add_blocking(out, "Pipeline unavailable");
        out->decision = OZAYN_RAG_DECISION_DENY;
        out->phase = OZAYN_RAG_PHASE_DENIED;
        strncpy(out->reason, "PIPELINE_BLOCKED", OZAYN_RAG_MAX_DESC_LEN - 1);
        svc->stats.total_denied++;
        _emit_event(svc, OZAYN_RAG_EVENT_DENIED, "admission_gate",
                    "Pipeline blocked", request->id);
        _store_decision(svc, out);
        return OZAYN_RAG_OK;
    }

    /* STEP 14: Scheduler eligibility */
    if (!ctx->scheduler_eligible) {
        _add_blocking(out, "Not scheduler eligible");
        out->decision = OZAYN_RAG_DECISION_QUEUE;
        out->phase = OZAYN_RAG_PHASE_DEFERRED;
        strncpy(out->reason, "SCHEDULER_NOT_ELIGIBLE", OZAYN_RAG_MAX_DESC_LEN - 1);
        svc->stats.total_queued++;
        _emit_event(svc, OZAYN_RAG_EVENT_QUEUED, "admission_gate",
                    "Queued for scheduling", request->id);
        _store_decision(svc, out);
        return OZAYN_RAG_OK;
    }

    /* STEP 15: Final decision — ACCEPT */
    out->phase = OZAYN_RAG_PHASE_ACCEPTED;
    out->decision = OZAYN_RAG_DECISION_ACCEPT;
    out->security_result = ctx->security_session_valid ? 1 : 2;
    out->authorization_result = ctx->authorization_valid ? 1 : 2;
    out->safety_result = ctx->safety_policy_valid ? 1 : 2;
    out->resource_result = ctx->resources_available ? 1 : 2;
    out->device_result = ctx->devices_available ? 1 : 2;
    out->workflow_result = ctx->workflow_valid ? 1 : 2;
    out->pipeline_result = ctx->pipeline_valid ? 1 : 2;
    strncpy(out->reason, "ADMISSION_GRANTED", OZAYN_RAG_MAX_DESC_LEN - 1);
    svc->stats.total_accepted++;

    _emit_event(svc, OZAYN_RAG_EVENT_ACCEPTED, "admission_gate",
                "Admission accepted", request->id);
    _store_decision(svc, out);
    return OZAYN_RAG_OK;
}

/* ============================================================
 * SECTION 5 — QUICK CHECK
 * ============================================================ */

int ozayn_rag_can_admit(const ozayn_rag_service_t *svc,
                        const ozayn_rag_request_t *request,
                        const ozayn_rag_context_t *ctx) {
    if (!svc || !request || !ctx) return 0;
    if (!svc->initialized) return 0;
    if (request->id[0] == '\0') return 0;
    if (request->expiration_ms > 0 && _now_ms() > request->expiration_ms) return 0;

    switch (ctx->runtime_mode) {
        case OZAYN_ORD_MODE_READY: break;
        case OZAYN_ORD_MODE_READY_DEGRADED: break;
        default: return 0;
    }

    if (!ctx->readiness_satisfied) return 0;
    if (request->target_component_id[0] != '\0' && !ctx->component_available) return 0;
    if (request->capability_id[0] != '\0' && !ctx->capability_available) return 0;
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

ozayn_rag_err_t ozayn_rag_reassess(ozayn_rag_service_t *svc,
                                   const char *admission_id,
                                   const ozayn_rag_context_t *ctx,
                                   ozayn_rag_admission_t *out) {
    if (!svc || !admission_id || !ctx || !out) return OZAYN_RAG_ERR_NULL;
    if (!svc->initialized) return OZAYN_RAG_ERR_NOT_INITIALIZED;

    ozayn_rag_admission_t *existing = _find_decision(svc, admission_id);
    if (!existing) return OZAYN_RAG_ERR_NOT_FOUND;
    if (!existing->active) return OZAYN_RAG_ERR_INVALIDATED;

    if (existing->reassessment_count >= OZAYN_RAG_MAX_REASSESSMENTS) {
        _add_blocking(out, "Maximum reassessments exceeded");
        out->decision = OZAYN_RAG_DECISION_DENY;
        out->phase = OZAYN_RAG_PHASE_DENIED;
        strncpy(out->reason, "REASSESSMENT_LIMIT", OZAYN_RAG_MAX_DESC_LEN - 1);
        _store_decision(svc, out);
        return OZAYN_RAG_OK;
    }

    svc->stats.total_reassessments++;
    _emit_event(svc, OZAYN_RAG_EVENT_REASSESSMENT_STARTED, "admission_gate",
                "Reassessment started", admission_id);

    /* Reconstruct a request from the existing admission for re-evaluation */
    ozayn_rag_request_t req;
    memset(&req, 0, sizeof(req));
    strncpy(req.id, existing->admission_request_id, OZAYN_RAG_MAX_ID_LEN - 1);
    strncpy(req.operation_id, existing->operation_id, OZAYN_RAG_MAX_ID_LEN - 1);

    int prev_count = existing->reassessment_count;
    /* Invalidate the old decision before re-evaluation */
    existing->active = 0;

    ozayn_rag_err_t rc = ozayn_rag_admit(svc, &req, ctx, out);
    if (rc == OZAYN_RAG_OK) {
        /* Update the stored decision with reassessment count */
        int stored_idx = (svc->decision_head - 1 + OZAYN_RAG_MAX_DECISIONS) %
                         OZAYN_RAG_MAX_DECISIONS;
        svc->decisions[stored_idx].reassessment_count = prev_count + 1;
        out->reassessment_count = prev_count + 1;
    }

    _emit_event(svc, OZAYN_RAG_EVENT_REASSESSMENT_COMPLETED, "admission_gate",
                "Reassessment completed", admission_id);
    return rc;
}

/* ============================================================
 * SECTION 7 — INVALIDATION
 * ============================================================ */

ozayn_rag_err_t ozayn_rag_invalidate(ozayn_rag_service_t *svc,
                                     const char *admission_id) {
    if (!svc || !admission_id) return OZAYN_RAG_ERR_NULL;
    if (!svc->initialized) return OZAYN_RAG_ERR_NOT_INITIALIZED;

    ozayn_rag_admission_t *d = _find_decision(svc, admission_id);
    if (!d) return OZAYN_RAG_ERR_NOT_FOUND;
    if (!d->active) return OZAYN_RAG_ERR_INVALIDATED;

    d->active = 0;
    svc->stats.total_invalidated++;
    _emit_event(svc, OZAYN_RAG_EVENT_INVALIDATED, "admission_gate",
                "Decision invalidated", admission_id);
    return OZAYN_RAG_OK;
}

/* ============================================================
 * SECTION 8 — QUERIES
 * ============================================================ */

ozayn_rag_err_t ozayn_rag_get_decision(const ozayn_rag_service_t *svc,
                                       const char *admission_id,
                                       ozayn_rag_admission_t *out) {
    if (!svc || !out) return OZAYN_RAG_ERR_NULL;
    if (!svc->initialized) return OZAYN_RAG_ERR_NOT_INITIALIZED;
    for (int i = 0; i < svc->decision_count; i++) {
        int idx = (svc->decision_head - svc->decision_count + i +
                   OZAYN_RAG_MAX_DECISIONS) % OZAYN_RAG_MAX_DECISIONS;
        if (svc->decisions[idx].active &&
            strcmp(svc->decisions[idx].id, admission_id) == 0) {
            *out = svc->decisions[idx];
            return OZAYN_RAG_OK;
        }
    }
    return OZAYN_RAG_ERR_NOT_FOUND;
}

ozayn_rag_err_t ozayn_rag_get_latest_decision(const ozayn_rag_service_t *svc,
                                              ozayn_rag_admission_t *out) {
    if (!svc || !out) return OZAYN_RAG_ERR_NULL;
    if (!svc->initialized) return OZAYN_RAG_ERR_NOT_INITIALIZED;
    if (svc->decision_count == 0) return OZAYN_RAG_ERR_NOT_FOUND;
    int idx = (svc->decision_head - 1 + OZAYN_RAG_MAX_DECISIONS) %
              OZAYN_RAG_MAX_DECISIONS;
    *out = svc->decisions[idx];
    return OZAYN_RAG_OK;
}

int ozayn_rag_decision_count(const ozayn_rag_service_t *svc) {
    if (!svc || !svc->initialized) return 0;
    return svc->decision_count;
}

ozayn_rag_err_t ozayn_rag_get_request(const ozayn_rag_service_t *svc,
                                      const char *request_id,
                                      ozayn_rag_request_t *out) {
    if (!svc || !out) return OZAYN_RAG_ERR_NULL;
    if (!svc->initialized) return OZAYN_RAG_ERR_NOT_INITIALIZED;
    for (int i = 0; i < svc->request_count; i++) {
        int idx = (svc->request_head - svc->request_count + i +
                   OZAYN_RAG_MAX_REQUESTS) % OZAYN_RAG_MAX_REQUESTS;
        if (svc->requests[idx].active &&
            strcmp(svc->requests[idx].id, request_id) == 0) {
            *out = svc->requests[idx];
            return OZAYN_RAG_OK;
        }
    }
    return OZAYN_RAG_ERR_NOT_FOUND;
}

int ozayn_rag_request_count(const ozayn_rag_service_t *svc) {
    if (!svc || !svc->initialized) return 0;
    return svc->request_count;
}

/* ============================================================
 * SECTION 9 — EVENTS
 * ============================================================ */

ozayn_rag_err_t ozayn_rag_get_event(const ozayn_rag_service_t *svc,
                                    int index, ozayn_rag_event_t *out) {
    if (!svc || !out) return OZAYN_RAG_ERR_NULL;
    if (!svc->initialized) return OZAYN_RAG_ERR_NOT_INITIALIZED;
    if (index < 0 || index >= svc->event_count) return OZAYN_RAG_ERR_NOT_FOUND;
    int actual = (svc->event_head - svc->event_count + index +
                  OZAYN_RAG_MAX_EVENTS) % OZAYN_RAG_MAX_EVENTS;
    *out = svc->events[actual];
    return OZAYN_RAG_OK;
}

int ozayn_rag_event_count(const ozayn_rag_service_t *svc) {
    if (!svc || !svc->initialized) return 0;
    return svc->event_count;
}

/* ============================================================
 * SECTION 10 — STATS
 * ============================================================ */

const ozayn_rag_stats_t *ozayn_rag_get_stats(const ozayn_rag_service_t *svc) {
    if (!svc || !svc->initialized) return NULL;
    return &svc->stats;
}

ozayn_rag_err_t ozayn_rag_reset_stats(ozayn_rag_service_t *svc) {
    if (!svc) return OZAYN_RAG_ERR_NULL;
    if (!svc->initialized) return OZAYN_RAG_ERR_NOT_INITIALIZED;
    memset(&svc->stats, 0, sizeof(ozayn_rag_stats_t));
    return OZAYN_RAG_OK;
}

/* ============================================================
 * SECTION 11 — NAME HELPERS
 * ============================================================ */

const char *ozayn_rag_err_name(ozayn_rag_err_t err) {
    switch (err) {
        case OZAYN_RAG_OK: return "OK";
        case OZAYN_RAG_ERR_NULL: return "NULL";
        case OZAYN_RAG_ERR_NOT_INITIALIZED: return "NOT_INITIALIZED";
        case OZAYN_RAG_ERR_ALREADY_INITIALIZED: return "ALREADY_INITIALIZED";
        case OZAYN_RAG_ERR_INVALID_PARAM: return "INVALID_PARAM";
        case OZAYN_RAG_ERR_STATE_INVALID: return "STATE_INVALID";
        case OZAYN_RAG_ERR_NOT_FOUND: return "NOT_FOUND";
        case OZAYN_RAG_ERR_EXPIRED: return "EXPIRED";
        case OZAYN_RAG_ERR_INVALIDATED: return "INVALIDATED";
        case OZAYN_RAG_ERR_MODE_BLOCKED: return "MODE_BLOCKED";
        case OZAYN_RAG_ERR_READINESS_BLOCKED: return "READINESS_BLOCKED";
        case OZAYN_RAG_ERR_TARGET_INVALID: return "TARGET_INVALID";
        case OZAYN_RAG_ERR_TARGET_UNAVAILABLE: return "TARGET_UNAVAILABLE";
        case OZAYN_RAG_ERR_CAPABILITY_UNAVAILABLE: return "CAPABILITY_UNAVAILABLE";
        case OZAYN_RAG_ERR_AUTHORIZATION_FAILED: return "AUTHORIZATION_FAILED";
        case OZAYN_RAG_ERR_PERMISSION_DENIED: return "PERMISSION_DENIED";
        case OZAYN_RAG_ERR_SECURITY_UNAVAILABLE: return "SECURITY_UNAVAILABLE";
        case OZAYN_RAG_ERR_SAFETY_FAILED: return "SAFETY_FAILED";
        case OZAYN_RAG_ERR_POLICY_DENIED: return "POLICY_DENIED";
        case OZAYN_RAG_ERR_SAFETY_UNAVAILABLE: return "SAFETY_UNAVAILABLE";
        case OZAYN_RAG_ERR_RESOURCE_UNAVAILABLE: return "RESOURCE_UNAVAILABLE";
        case OZAYN_RAG_ERR_RESOURCE_CONFLICT: return "RESOURCE_CONFLICT";
        case OZAYN_RAG_ERR_DEVICE_UNAVAILABLE: return "DEVICE_UNAVAILABLE";
        case OZAYN_RAG_ERR_DEVICE_SESSION_INVALID: return "DEVICE_SESSION_INVALID";
        case OZAYN_RAG_ERR_WORKFLOW_BLOCKED: return "WORKFLOW_BLOCKED";
        case OZAYN_RAG_ERR_PIPELINE_BLOCKED: return "PIPELINE_BLOCKED";
        case OZAYN_RAG_ERR_DEPENDENCY_FAILED: return "DEPENDENCY_FAILED";
        case OZAYN_RAG_ERR_CONFLICT: return "CONFLICT";
        case OZAYN_RAG_ERR_REASSESSMENT_REQUIRED: return "REASSESSMENT_REQUIRED";
        case OZAYN_RAG_ERR_TIMEOUT: return "TIMEOUT";
        case OZAYN_RAG_ERR_CANCELLED: return "CANCELLED";
        case OZAYN_RAG_ERR_CONCURRENCY_ERROR: return "CONCURRENCY_ERROR";
        case OZAYN_RAG_ERR_CONFIGURATION_ERROR: return "CONFIGURATION_ERROR";
        case OZAYN_RAG_ERR_EVENT_ERROR: return "EVENT_ERROR";
        case OZAYN_RAG_ERR_LIMIT_REACHED: return "LIMIT_REACHED";
    }
    return "UNKNOWN";
}

const char *ozayn_rag_decision_name(ozayn_rag_decision_t d) {
    switch (d) {
        case OZAYN_RAG_DECISION_ACCEPT: return "ACCEPT";
        case OZAYN_RAG_DECISION_QUEUE: return "QUEUE";
        case OZAYN_RAG_DECISION_DEFER: return "DEFER";
        case OZAYN_RAG_DECISION_DENY: return "DENY";
        case OZAYN_RAG_DECISION_BLOCKED: return "BLOCKED";
        case OZAYN_RAG_DECISION_REQUIRES_REASSESSMENT: return "REQUIRES_REASSESSMENT";
        case OZAYN_RAG_DECISION_REQUIRES_AUTHORIZATION: return "REQUIRES_AUTHORIZATION";
        case OZAYN_RAG_DECISION_REQUIRES_SAFETY_CHECK: return "REQUIRES_SAFETY_CHECK";
        case OZAYN_RAG_DECISION_REQUIRES_RESOURCE_CHECK: return "REQUIRES_RESOURCE_CHECK";
        case OZAYN_RAG_DECISION_REQUIRES_DEVICE_CHECK: return "REQUIRES_DEVICE_CHECK";
        case OZAYN_RAG_DECISION_REQUIRES_RECOVERY: return "REQUIRES_RECOVERY";
        case OZAYN_RAG_DECISION_EXPIRED: return "EXPIRED";
        case OZAYN_RAG_DECISION_UNAVAILABLE: return "UNAVAILABLE";
    }
    return "UNKNOWN";
}

const char *ozayn_rag_phase_name(ozayn_rag_phase_t p) {
    switch (p) {
        case OZAYN_RAG_PHASE_NONE: return "NONE";
        case OZAYN_RAG_PHASE_REQUESTED: return "REQUESTED";
        case OZAYN_RAG_PHASE_VALIDATING: return "VALIDATING";
        case OZAYN_RAG_PHASE_EVALUATING: return "EVALUATING";
        case OZAYN_RAG_PHASE_DECIDED: return "DECIDED";
        case OZAYN_RAG_PHASE_ACCEPTED: return "ACCEPTED";
        case OZAYN_RAG_PHASE_DENIED: return "DENIED";
        case OZAYN_RAG_PHASE_DEFERRED: return "DEFERRED";
        case OZAYN_RAG_PHASE_BLOCKED: return "BLOCKED";
        case OZAYN_RAG_PHASE_EXPIRED: return "EXPIRED";
        case OZAYN_RAG_PHASE_INVALIDATED: return "INVALIDATED";
        case OZAYN_RAG_PHASE_CANCELLED: return "CANCELLED";
    }
    return "UNKNOWN";
}

const char *ozayn_rag_event_type_name(ozayn_rag_event_type_t t) {
    switch (t) {
        case OZAYN_RAG_EVENT_REQUESTED: return "REQUESTED";
        case OZAYN_RAG_EVENT_VALIDATING: return "VALIDATING";
        case OZAYN_RAG_EVENT_ACCEPTED: return "ACCEPTED";
        case OZAYN_RAG_EVENT_QUEUED: return "QUEUED";
        case OZAYN_RAG_EVENT_DEFERRED: return "DEFERRED";
        case OZAYN_RAG_EVENT_DENIED: return "DENIED";
        case OZAYN_RAG_EVENT_BLOCKED: return "BLOCKED";
        case OZAYN_RAG_EVENT_REASSESSMENT_REQUIRED: return "REASSESSMENT_REQUIRED";
        case OZAYN_RAG_EVENT_AUTHORIZATION_REQUIRED: return "AUTHORIZATION_REQUIRED";
        case OZAYN_RAG_EVENT_SAFETY_CHECK_REQUIRED: return "SAFETY_CHECK_REQUIRED";
        case OZAYN_RAG_EVENT_RESOURCE_CHECK_REQUIRED: return "RESOURCE_CHECK_REQUIRED";
        case OZAYN_RAG_EVENT_DEVICE_CHECK_REQUIRED: return "DEVICE_CHECK_REQUIRED";
        case OZAYN_RAG_EVENT_EXPIRED: return "EXPIRED";
        case OZAYN_RAG_EVENT_INVALIDATED: return "INVALIDATED";
        case OZAYN_RAG_EVENT_REVOKED: return "REVOKED";
        case OZAYN_RAG_EVENT_REASSESSMENT_STARTED: return "REASSESSMENT_STARTED";
        case OZAYN_RAG_EVENT_REASSESSMENT_COMPLETED: return "REASSESSMENT_COMPLETED";
        case OZAYN_RAG_EVENT_COUNT: return "COUNT";
    }
    return "UNKNOWN";
}
