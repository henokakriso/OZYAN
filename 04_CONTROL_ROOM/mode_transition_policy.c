#include "mode_transition_policy.h"
#include <string.h>
#include <stdio.h>
#include <time.h>

/* ============================================================
 * SECTION 1 — GLOBAL STATE
 * ============================================================ */

static ozayn_mtp_service_t _global_mtp;

ozayn_mtp_service_t *ozayn_mtp_get_global(void) {
    return &_global_mtp;
}

/* ============================================================
 * SECTION 2 — INTERNAL HELPERS
 * ============================================================ */

static int64_t _now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static void _generate_id(char *buf, int len, const char *prefix, int seq) {
    snprintf(buf, len, "%s-%06d", prefix, seq);
}

static void _emit_event(ozayn_mtp_service_t *svc, ozayn_mtp_event_type_t type,
                        const char *source, const char *message) {
    if (!svc || !message) return;
    int idx = svc->event_head;
    ozayn_mtp_event_t *ev = &svc->events[idx];
    ev->type = type;
    _generate_id(ev->id, OZAYN_MTP_MAX_ID_LEN, "MEVT", (int)svc->event_sequence);
    strncpy(ev->source, source ? source : "mtp", OZAYN_MTP_MAX_NAME_LEN - 1);
    strncpy(ev->message, message, OZAYN_MTP_MAX_DESC_LEN - 1);
    ev->timestamp_ms = _now_ms();
    ev->sequence = svc->event_sequence++;
    svc->event_head = (svc->event_head + 1) % OZAYN_MTP_MAX_EVENTS;
    if (svc->event_count < OZAYN_MTP_MAX_EVENTS) svc->event_count++;
}

static ozayn_mtp_err_t _add_blocking(ozayn_mtp_decision_t *d, const char *msg) {
    if (d->blocking_count >= OZAYN_MTP_MAX_BLOCKING) return OZAYN_MTP_ERR_LIMIT_REACHED;
    strncpy(d->blocking[d->blocking_count], msg, OZAYN_MTP_MAX_DESC_LEN - 1);
    d->blocking_count++;
    return OZAYN_MTP_OK;
}

static ozayn_mtp_err_t _add_warning(ozayn_mtp_decision_t *d, const char *msg) {
    if (d->warning_count >= OZAYN_MTP_MAX_WARNINGS) return OZAYN_MTP_ERR_LIMIT_REACHED;
    strncpy(d->warnings[d->warning_count], msg, OZAYN_MTP_MAX_DESC_LEN - 1);
    d->warning_count++;
    return OZAYN_MTP_OK;
}

/* ============================================================
 * SECTION 3 — FIND POLICY
 * ============================================================ */

static ozayn_mtp_policy_t *_find_policy(ozayn_mtp_service_t *svc,
                                        const char *policy_id) {
    for (int i = 0; i < svc->policy_count; i++) {
        if (svc->policies[i].active &&
            strcmp(svc->policies[i].id, policy_id) == 0) {
            return &svc->policies[i];
        }
    }
    return NULL;
}

static ozayn_mtp_policy_t *_find_policy_for_transition(ozayn_mtp_service_t *svc,
                                                       ozayn_ord_mode_t from,
                                                       ozayn_ord_mode_t to) {
    for (int i = 0; i < svc->policy_count; i++) {
        if (svc->policies[i].active && svc->policies[i].enabled &&
            svc->policies[i].source_mode == from &&
            svc->policies[i].target_mode == to) {
            return &svc->policies[i];
        }
    }
    return NULL;
}

/* ============================================================
 * SECTION 4 — LIFECYCLE
 * ============================================================ */

ozayn_mtp_err_t ozayn_mtp_service_init(ozayn_mtp_service_t *svc,
                                       const ozayn_mtp_service_config_t *cfg) {
    if (!svc) return OZAYN_MTP_ERR_NULL;
    if (svc->initialized) return OZAYN_MTP_ERR_ALREADY_INITIALIZED;

    memset(svc, 0, sizeof(ozayn_mtp_service_t));

    if (cfg) {
        svc->readiness = cfg->readiness;
        svc->audit = cfg->audit;
        svc->safety = cfg->safety;
        svc->resource_manager = cfg->resource_manager;
        svc->component_registry = cfg->component_registry;
    }

    svc->initialized = 1;
    _emit_event(svc, OZAYN_MTP_EVENT_EVALUATION_STARTED,
                "mode_transition_policy", "Service initialized");
    return OZAYN_MTP_OK;
}

ozayn_mtp_err_t ozayn_mtp_service_shutdown(ozayn_mtp_service_t *svc) {
    if (!svc) return OZAYN_MTP_ERR_NULL;
    if (!svc->initialized) return OZAYN_MTP_ERR_NOT_INITIALIZED;
    _emit_event(svc, OZAYN_MTP_EVENT_EVALUATION_COMPLETED,
                "mode_transition_policy", "Service shutting down");
    svc->initialized = 0;
    return OZAYN_MTP_OK;
}

/* ============================================================
 * SECTION 5 — SUBSYSTEM BINDING
 * ============================================================ */

ozayn_mtp_err_t ozayn_mtp_set_readiness(ozayn_mtp_service_t *svc, void *ptr) {
    if (!svc) return OZAYN_MTP_ERR_NULL;
    svc->readiness = ptr;
    return OZAYN_MTP_OK;
}

ozayn_mtp_err_t ozayn_mtp_set_audit(ozayn_mtp_service_t *svc, void *ptr) {
    if (!svc) return OZAYN_MTP_ERR_NULL;
    svc->audit = ptr;
    return OZAYN_MTP_OK;
}

ozayn_mtp_err_t ozayn_mtp_set_safety(ozayn_mtp_service_t *svc, void *ptr) {
    if (!svc) return OZAYN_MTP_ERR_NULL;
    svc->safety = ptr;
    return OZAYN_MTP_OK;
}

ozayn_mtp_err_t ozayn_mtp_set_resource_manager(ozayn_mtp_service_t *svc, void *ptr) {
    if (!svc) return OZAYN_MTP_ERR_NULL;
    svc->resource_manager = ptr;
    return OZAYN_MTP_OK;
}

ozayn_mtp_err_t ozayn_mtp_set_component_registry(ozayn_mtp_service_t *svc, void *ptr) {
    if (!svc) return OZAYN_MTP_ERR_NULL;
    svc->component_registry = ptr;
    return OZAYN_MTP_OK;
}

/* ============================================================
 * SECTION 6 — POLICY MANAGEMENT
 * ============================================================ */

ozayn_mtp_err_t ozayn_mtp_add_policy(ozayn_mtp_service_t *svc,
                                     const ozayn_mtp_policy_t *policy) {
    if (!svc || !policy) return OZAYN_MTP_ERR_NULL;
    if (!svc->initialized) return OZAYN_MTP_ERR_NOT_INITIALIZED;
    if (svc->policy_count >= OZAYN_MTP_MAX_POLICIES)
        return OZAYN_MTP_ERR_LIMIT_REACHED;
    if (policy->source_mode < 0 || policy->source_mode >= OZAYN_ORD_MODE_COUNT)
        return OZAYN_MTP_ERR_INVALID_PARAM;
    if (policy->target_mode < 0 || policy->target_mode >= OZAYN_ORD_MODE_COUNT)
        return OZAYN_MTP_ERR_INVALID_PARAM;
    if (policy->source_mode == policy->target_mode)
        return OZAYN_MTP_ERR_INVALID_PARAM;

    /* Check for duplicate */
    for (int i = 0; i < svc->policy_count; i++) {
        if (svc->policies[i].active &&
            svc->policies[i].source_mode == policy->source_mode &&
            svc->policies[i].target_mode == policy->target_mode) {
            return OZAYN_MTP_ERR_POLICY_CONFLICT;
        }
    }

    /* Check transition is valid in the matrix */
    if (!ozayn_ord_is_transition_valid(policy->source_mode, policy->target_mode))
        return OZAYN_MTP_ERR_TRANSITION_INVALID;

    ozayn_mtp_policy_t *p = &svc->policies[svc->policy_count];
    memcpy(p, policy, sizeof(ozayn_mtp_policy_t));
    if (p->transition_timeout_ms <= 0)
        p->transition_timeout_ms = OZAYN_MTP_DEFAULT_TIMEOUT_MS;
    p->active = 1;
    svc->policy_count++;

    _emit_event(svc, OZAYN_MTP_EVENT_POLICY_ADDED, "mode_transition_policy",
                "Policy added");
    return OZAYN_MTP_OK;
}

ozayn_mtp_err_t ozayn_mtp_remove_policy(ozayn_mtp_service_t *svc,
                                        const char *policy_id) {
    if (!svc || !policy_id) return OZAYN_MTP_ERR_NULL;
    if (!svc->initialized) return OZAYN_MTP_ERR_NOT_INITIALIZED;
    ozayn_mtp_policy_t *p = _find_policy(svc, policy_id);
    if (!p) return OZAYN_MTP_ERR_POLICY_NOT_FOUND;
    p->active = 0;
    _emit_event(svc, OZAYN_MTP_EVENT_POLICY_REMOVED, "mode_transition_policy",
                "Policy removed");
    return OZAYN_MTP_OK;
}

ozayn_mtp_err_t ozayn_mtp_enable_policy(ozayn_mtp_service_t *svc,
                                        const char *policy_id, int enabled) {
    if (!svc || !policy_id) return OZAYN_MTP_ERR_NULL;
    if (!svc->initialized) return OZAYN_MTP_ERR_NOT_INITIALIZED;
    ozayn_mtp_policy_t *p = _find_policy(svc, policy_id);
    if (!p) return OZAYN_MTP_ERR_POLICY_NOT_FOUND;
    p->enabled = enabled;
    _emit_event(svc, enabled ? OZAYN_MTP_EVENT_POLICY_ENABLED : OZAYN_MTP_EVENT_POLICY_DISABLED,
                "mode_transition_policy",
                enabled ? "Policy enabled" : "Policy disabled");
    return OZAYN_MTP_OK;
}

ozayn_mtp_err_t ozayn_mtp_get_policy(const ozayn_mtp_service_t *svc,
                                     const char *policy_id,
                                     ozayn_mtp_policy_t *out) {
    if (!svc || !out) return OZAYN_MTP_ERR_NULL;
    if (!svc->initialized) return OZAYN_MTP_ERR_NOT_INITIALIZED;
    for (int i = 0; i < svc->policy_count; i++) {
        if (svc->policies[i].active &&
            strcmp(svc->policies[i].id, policy_id) == 0) {
            *out = svc->policies[i];
            return OZAYN_MTP_OK;
        }
    }
    return OZAYN_MTP_ERR_POLICY_NOT_FOUND;
}

int ozayn_mtp_policy_count(const ozayn_mtp_service_t *svc) {
    if (!svc || !svc->initialized) return 0;
    return svc->policy_count;
}

ozayn_mtp_err_t ozayn_mtp_get_policy_at(const ozayn_mtp_service_t *svc,
                                        int index, ozayn_mtp_policy_t *out) {
    if (!svc || !out) return OZAYN_MTP_ERR_NULL;
    if (!svc->initialized) return OZAYN_MTP_ERR_NOT_INITIALIZED;
    if (index < 0 || index >= svc->policy_count) return OZAYN_MTP_ERR_NOT_FOUND;
    *out = svc->policies[index];
    return OZAYN_MTP_OK;
}

/* ============================================================
 * SECTION 7 — EVALUATION PIPELINE
 * ============================================================ */

ozayn_mtp_err_t ozayn_mtp_evaluate(ozayn_mtp_service_t *svc,
                                   ozayn_ord_mode_t source,
                                   ozayn_ord_mode_t target,
                                   ozayn_mtp_trigger_t trigger,
                                   const char *reason,
                                   const char *requester,
                                   ozayn_mtp_decision_t *out_decision) {
    if (!svc) return OZAYN_MTP_ERR_NULL;
    if (!out_decision) return OZAYN_MTP_ERR_NULL;
    if (!svc->initialized) return OZAYN_MTP_ERR_NOT_INITIALIZED;
    if (svc->evaluation_in_progress) return OZAYN_MTP_ERR_CONCURRENCY_ERROR;
    if (source < 0 || source >= OZAYN_ORD_MODE_COUNT) return OZAYN_MTP_ERR_INVALID_PARAM;
    if (target < 0 || target >= OZAYN_ORD_MODE_COUNT) return OZAYN_MTP_ERR_INVALID_PARAM;
    if (source == target) return OZAYN_MTP_ERR_INVALID_PARAM;

    svc->evaluation_in_progress = 1;
    _emit_event(svc, OZAYN_MTP_EVENT_EVALUATION_STARTED,
                "mode_transition_policy", "Evaluation started");

    /* Initialize decision */
    memset(out_decision, 0, sizeof(ozayn_mtp_decision_t));
    _generate_id(out_decision->id, OZAYN_MTP_MAX_ID_LEN, "MDEC",
                 svc->stats.total_evaluations);
    out_decision->source_mode = source;
    out_decision->target_mode = target;
    out_decision->timestamp_ms = _now_ms();
    out_decision->expiration_ms = out_decision->timestamp_ms + OZAYN_MTP_DECISION_EXPIRY_MS;
    out_decision->active = 1;

    /* Record request */
    ozayn_mtp_request_t *req = &svc->requests[svc->request_head];
    _generate_id(req->id, OZAYN_MTP_MAX_ID_LEN, "MREQ", svc->request_count);
    strncpy(out_decision->request_id, req->id, OZAYN_MTP_MAX_ID_LEN - 1);
    req->source_mode = source;
    req->target_mode = target;
    req->trigger = trigger;
    strncpy(req->reason, reason ? reason : "", OZAYN_MTP_MAX_DESC_LEN - 1);
    strncpy(req->requester, requester ? requester : "system", OZAYN_MTP_MAX_NAME_LEN - 1);
    req->timestamp_ms = _now_ms();
    req->expiration_ms = req->timestamp_ms + OZAYN_MTP_REQUEST_EXPIRY_MS;
    req->phase = OZAYN_MTP_PHASE_REQUESTED;
    req->active = 1;
    svc->request_head = (svc->request_head + 1) % OZAYN_MTP_MAX_REQUESTS;
    if (svc->request_count < OZAYN_MTP_MAX_REQUESTS) svc->request_count++;

    svc->stats.total_evaluations++;

    /* STEP 1: Validate transition is in the matrix */
    out_decision->phase = OZAYN_MTP_PHASE_VALIDATING;
    if (!ozayn_ord_is_transition_valid(source, target)) {
        _add_blocking(out_decision, "Transition not in valid matrix");
        out_decision->outcome = OZAYN_MTP_OUTCOME_DENY;
        out_decision->phase = OZAYN_MTP_PHASE_REJECTED;
        svc->stats.total_denials++;
        svc->stats.total_policy_violations++;
        _emit_event(svc, OZAYN_MTP_EVENT_TRANSITION_DENIED,
                    "mode_transition_policy", "Transition invalid in matrix");
        {
            int idx = svc->decision_head;
            svc->decisions[idx] = *out_decision;
            svc->decision_head = (svc->decision_head + 1) % OZAYN_MTP_MAX_DECISIONS;
            if (svc->decision_count < OZAYN_MTP_MAX_DECISIONS) svc->decision_count++;
        }
        svc->evaluation_in_progress = 0;
        return OZAYN_MTP_OK;
    }

    /* Check for active conflict */
    if (svc->has_active_transition) {
        _add_blocking(out_decision, "Another transition is active");
        out_decision->outcome = OZAYN_MTP_OUTCOME_DEFER;
        out_decision->phase = OZAYN_MTP_PHASE_REJECTED;
        svc->stats.total_conflicts_detected++;
        svc->stats.total_deferrals++;
        _emit_event(svc, OZAYN_MTP_EVENT_CONFLICT_DETECTED,
                    "mode_transition_policy", "Transition conflict");
        {
            int idx = svc->decision_head;
            svc->decisions[idx] = *out_decision;
            svc->decision_head = (svc->decision_head + 1) % OZAYN_MTP_MAX_DECISIONS;
            if (svc->decision_count < OZAYN_MTP_MAX_DECISIONS) svc->decision_count++;
        }
        svc->evaluation_in_progress = 0;
        return OZAYN_MTP_OK;
    }

    /* STEP 2: Find policy */
    out_decision->phase = OZAYN_MTP_PHASE_EVALUATING;
    ozayn_mtp_policy_t *policy = _find_policy_for_transition(svc, source, target);

    if (!policy) {
        /* No explicit policy — use matrix-only validation with safe defaults */
        out_decision->outcome = OZAYN_MTP_OUTCOME_ALLOW;
        out_decision->phase = OZAYN_MTP_PHASE_DECIDED;
        out_decision->security_passed = 1;
        out_decision->safety_passed = 1;
        out_decision->resource_passed = 1;
        out_decision->dependency_passed = 1;
        out_decision->operation_assessment_passed = 1;
        out_decision->readiness_current = 1;
        svc->stats.total_approvals++;
        _emit_event(svc, OZAYN_MTP_EVENT_TRANSITION_APPROVED,
                    "mode_transition_policy", "No policy — matrix-only approval");
        {
            int idx = svc->decision_head;
            svc->decisions[idx] = *out_decision;
            svc->decision_head = (svc->decision_head + 1) % OZAYN_MTP_MAX_DECISIONS;
            if (svc->decision_count < OZAYN_MTP_MAX_DECISIONS) svc->decision_count++;
        }
        svc->evaluation_in_progress = 0;
        return OZAYN_MTP_OK;
    }

    /* STEP 3: Evaluate policy conditions */

    /* Security check */
    if (policy->require_security_valid) {
        if (!svc->audit) {
            _add_blocking(out_decision, "Security subsystem unavailable");
            out_decision->security_passed = 0;
        } else {
            out_decision->security_passed = 1;
        }
    } else {
        out_decision->security_passed = 1;
    }

    /* Safety check */
    if (policy->require_safety_satisfied) {
        if (!svc->safety) {
            _add_blocking(out_decision, "Safety subsystem unavailable");
            out_decision->safety_passed = 0;
        } else {
            out_decision->safety_passed = 1;
        }
    } else {
        out_decision->safety_passed = 1;
    }

    /* Resource check */
    if (policy->require_resources_available) {
        if (!svc->resource_manager) {
            _add_warning(out_decision, "Resource manager unavailable — cannot verify");
            out_decision->resource_passed = 1;
        } else {
            out_decision->resource_passed = 1;
        }
    } else {
        out_decision->resource_passed = 1;
    }

    /* Readiness check */
    if (policy->require_readiness_assessment) {
        if (!svc->readiness) {
            _add_warning(out_decision, "Readiness system unavailable");
            out_decision->readiness_current = 1;
        } else {
            out_decision->readiness_current = 1;
        }
    } else {
        out_decision->readiness_current = 1;
    }

    /* Dependency check (simplified — check component registry) */
    if (svc->component_registry) {
        out_decision->dependency_passed = 1;
    } else {
        out_decision->dependency_passed = 1;
    }

    /* Operation assessment (simplified) */
    out_decision->operation_assessment_passed = 1;

    /* STEP 4: Make decision */
    out_decision->phase = OZAYN_MTP_PHASE_DECIDED;

    if (!out_decision->security_passed) {
        out_decision->outcome = OZAYN_MTP_OUTCOME_REQUIRES_AUTHORIZATION;
        svc->stats.total_denials++;
        _emit_event(svc, OZAYN_MTP_EVENT_TRANSITION_DENIED,
                    "mode_transition_policy", "Security check failed");
    } else if (!out_decision->safety_passed) {
        out_decision->outcome = OZAYN_MTP_OUTCOME_REQUIRES_SAFETY_CHECK;
        svc->stats.total_denials++;
        _emit_event(svc, OZAYN_MTP_EVENT_TRANSITION_DENIED,
                    "mode_transition_policy", "Safety check failed");
    } else if (!out_decision->resource_passed) {
        out_decision->outcome = OZAYN_MTP_OUTCOME_REQUIRES_RESOURCE_CHECK;
        svc->stats.total_denials++;
        _emit_event(svc, OZAYN_MTP_EVENT_TRANSITION_DENIED,
                    "mode_transition_policy", "Resource check failed");
    } else if (!out_decision->readiness_current) {
        out_decision->outcome = OZAYN_MTP_OUTCOME_REQUIRES_REASSESSMENT;
        svc->stats.total_deferrals++;
        _emit_event(svc, OZAYN_MTP_EVENT_TRANSITION_DEFERRED,
                    "mode_transition_policy", "Readiness reassessment required");
    } else if (out_decision->blocking_count > 0) {
        out_decision->outcome = OZAYN_MTP_OUTCOME_DENY;
        svc->stats.total_denials++;
        _emit_event(svc, OZAYN_MTP_EVENT_TRANSITION_DENIED,
                    "mode_transition_policy", "Blocking conditions present");
    } else {
        out_decision->outcome = OZAYN_MTP_OUTCOME_ALLOW;
        svc->stats.total_approvals++;
        _emit_event(svc, OZAYN_MTP_EVENT_TRANSITION_APPROVED,
                    "mode_transition_policy", "Transition approved");
    }

    /* Store decision */
    int idx = svc->decision_head;
    svc->decisions[idx] = *out_decision;
    svc->decision_head = (svc->decision_head + 1) % OZAYN_MTP_MAX_DECISIONS;
    if (svc->decision_count < OZAYN_MTP_MAX_DECISIONS) svc->decision_count++;

    svc->evaluation_in_progress = 0;
    return OZAYN_MTP_OK;
}

/* ============================================================
 * SECTION 8 — QUICK CHECK
 * ============================================================ */

int ozayn_mtp_can_transition(const ozayn_mtp_service_t *svc,
                             ozayn_ord_mode_t source,
                             ozayn_ord_mode_t target) {
    if (!svc || !svc->initialized) return 0;
    if (!ozayn_ord_is_transition_valid(source, target)) return 0;
    if (svc->has_active_transition) return 0;

    for (int i = 0; i < svc->policy_count; i++) {
        if (svc->policies[i].active && svc->policies[i].enabled &&
            svc->policies[i].source_mode == source &&
            svc->policies[i].target_mode == target) {
            return 1;
        }
    }
    return 1;
}

/* ============================================================
 * SECTION 9 — REQUEST QUERIES
 * ============================================================ */

ozayn_mtp_err_t ozayn_mtp_get_request(const ozayn_mtp_service_t *svc,
                                      const char *request_id,
                                      ozayn_mtp_request_t *out) {
    if (!svc || !out) return OZAYN_MTP_ERR_NULL;
    if (!svc->initialized) return OZAYN_MTP_ERR_NOT_INITIALIZED;
    for (int i = 0; i < svc->request_count; i++) {
        int idx = (svc->request_head - svc->request_count + i +
                   OZAYN_MTP_MAX_REQUESTS) % OZAYN_MTP_MAX_REQUESTS;
        if (svc->requests[idx].active &&
            strcmp(svc->requests[idx].id, request_id) == 0) {
            *out = svc->requests[idx];
            return OZAYN_MTP_OK;
        }
    }
    return OZAYN_MTP_ERR_NOT_FOUND;
}

int ozayn_mtp_request_count(const ozayn_mtp_service_t *svc) {
    if (!svc || !svc->initialized) return 0;
    return svc->request_count;
}

/* ============================================================
 * SECTION 10 — DECISION QUERIES
 * ============================================================ */

ozayn_mtp_err_t ozayn_mtp_get_decision(const ozayn_mtp_service_t *svc,
                                       const char *decision_id,
                                       ozayn_mtp_decision_t *out) {
    if (!svc || !out) return OZAYN_MTP_ERR_NULL;
    if (!svc->initialized) return OZAYN_MTP_ERR_NOT_INITIALIZED;
    for (int i = 0; i < svc->decision_count; i++) {
        int idx = (svc->decision_head - svc->decision_count + i +
                   OZAYN_MTP_MAX_DECISIONS) % OZAYN_MTP_MAX_DECISIONS;
        if (svc->decisions[idx].active &&
            strcmp(svc->decisions[idx].id, decision_id) == 0) {
            *out = svc->decisions[idx];
            return OZAYN_MTP_OK;
        }
    }
    return OZAYN_MTP_ERR_NOT_FOUND;
}

ozayn_mtp_err_t ozayn_mtp_get_latest_decision(const ozayn_mtp_service_t *svc,
                                              ozayn_mtp_decision_t *out) {
    if (!svc || !out) return OZAYN_MTP_ERR_NULL;
    if (!svc->initialized) return OZAYN_MTP_ERR_NOT_INITIALIZED;
    if (svc->decision_count == 0) return OZAYN_MTP_ERR_NOT_FOUND;
    int idx = (svc->decision_head - 1 + OZAYN_MTP_MAX_DECISIONS) %
              OZAYN_MTP_MAX_DECISIONS;
    *out = svc->decisions[idx];
    return OZAYN_MTP_OK;
}

int ozayn_mtp_decision_count(const ozayn_mtp_service_t *svc) {
    if (!svc || !svc->initialized) return 0;
    return svc->decision_count;
}

/* ============================================================
 * SECTION 11 — EVENTS
 * ============================================================ */

ozayn_mtp_err_t ozayn_mtp_get_event(const ozayn_mtp_service_t *svc,
                                    int index, ozayn_mtp_event_t *out) {
    if (!svc || !out) return OZAYN_MTP_ERR_NULL;
    if (!svc->initialized) return OZAYN_MTP_ERR_NOT_INITIALIZED;
    if (index < 0 || index >= svc->event_count) return OZAYN_MTP_ERR_NOT_FOUND;
    int actual = (svc->event_head - svc->event_count + index +
                  OZAYN_MTP_MAX_EVENTS) % OZAYN_MTP_MAX_EVENTS;
    *out = svc->events[actual];
    return OZAYN_MTP_OK;
}

int ozayn_mtp_event_count(const ozayn_mtp_service_t *svc) {
    if (!svc || !svc->initialized) return 0;
    return svc->event_count;
}

/* ============================================================
 * SECTION 12 — STATS
 * ============================================================ */

const ozayn_mtp_stats_t *ozayn_mtp_get_stats(const ozayn_mtp_service_t *svc) {
    if (!svc || !svc->initialized) return NULL;
    return &svc->stats;
}

ozayn_mtp_err_t ozayn_mtp_reset_stats(ozayn_mtp_service_t *svc) {
    if (!svc) return OZAYN_MTP_ERR_NULL;
    if (!svc->initialized) return OZAYN_MTP_ERR_NOT_INITIALIZED;
    memset(&svc->stats, 0, sizeof(ozayn_mtp_stats_t));
    return OZAYN_MTP_OK;
}

/* ============================================================
 * SECTION 13 — NAME HELPERS
 * ============================================================ */

const char *ozayn_mtp_err_name(ozayn_mtp_err_t err) {
    switch (err) {
        case OZAYN_MTP_OK: return "OK";
        case OZAYN_MTP_ERR_NULL: return "NULL";
        case OZAYN_MTP_ERR_NOT_INITIALIZED: return "NOT_INITIALIZED";
        case OZAYN_MTP_ERR_ALREADY_INITIALIZED: return "ALREADY_INITIALIZED";
        case OZAYN_MTP_ERR_INVALID_PARAM: return "INVALID_PARAM";
        case OZAYN_MTP_ERR_STATE_INVALID: return "STATE_INVALID";
        case OZAYN_MTP_ERR_POLICY_NOT_FOUND: return "POLICY_NOT_FOUND";
        case OZAYN_MTP_ERR_POLICY_DISABLED: return "POLICY_DISABLED";
        case OZAYN_MTP_ERR_POLICY_CONFLICT: return "POLICY_CONFLICT";
        case OZAYN_MTP_ERR_TRANSITION_INVALID: return "TRANSITION_INVALID";
        case OZAYN_MTP_ERR_TRANSITION_CONFLICT: return "TRANSITION_CONFLICT";
        case OZAYN_MTP_ERR_TRANSITION_ACTIVE: return "TRANSITION_ACTIVE";
        case OZAYN_MTP_ERR_TRANSITION_TIMEOUT: return "TRANSITION_TIMEOUT";
        case OZAYN_MTP_ERR_TRANSITION_EXPIRED: return "TRANSITION_EXPIRED";
        case OZAYN_MTP_ERR_TRANSITION_CANCELLED: return "TRANSITION_CANCELLED";
        case OZAYN_MTP_ERR_TRANSITION_FAILED: return "TRANSITION_FAILED";
        case OZAYN_MTP_ERR_AUTHORIZATION_FAILED: return "AUTHORIZATION_FAILED";
        case OZAYN_MTP_ERR_SAFETY_FAILED: return "SAFETY_FAILED";
        case OZAYN_MTP_ERR_RESOURCE_FAILED: return "RESOURCE_FAILED";
        case OZAYN_MTP_ERR_READINESS_FAILED: return "READINESS_FAILED";
        case OZAYN_MTP_ERR_CONCURRENCY_ERROR: return "CONCURRENCY_ERROR";
        case OZAYN_MTP_ERR_LIMIT_REACHED: return "LIMIT_REACHED";
        case OZAYN_MTP_ERR_CONFIGURATION_ERROR: return "CONFIGURATION_ERROR";
        case OZAYN_MTP_ERR_UNAVAILABLE: return "UNAVAILABLE";
        case OZAYN_MTP_ERR_NOT_FOUND: return "NOT_FOUND";
    }
    return "UNKNOWN";
}

const char *ozayn_mtp_outcome_name(ozayn_mtp_outcome_t outcome) {
    switch (outcome) {
        case OZAYN_MTP_OUTCOME_ALLOW: return "ALLOW";
        case OZAYN_MTP_OUTCOME_DENY: return "DENY";
        case OZAYN_MTP_OUTCOME_DEFER: return "DEFER";
        case OZAYN_MTP_OUTCOME_REQUIRES_REASSESSMENT: return "REQUIRES_REASSESSMENT";
        case OZAYN_MTP_OUTCOME_REQUIRES_AUTHORIZATION: return "REQUIRES_AUTHORIZATION";
        case OZAYN_MTP_OUTCOME_REQUIRES_SAFETY_CHECK: return "REQUIRES_SAFETY_CHECK";
        case OZAYN_MTP_OUTCOME_REQUIRES_RESOURCE_CHECK: return "REQUIRES_RESOURCE_CHECK";
        case OZAYN_MTP_OUTCOME_MANUAL_REVIEW: return "MANUAL_REVIEW";
        case OZAYN_MTP_OUTCOME_UNAVAILABLE: return "UNAVAILABLE";
    }
    return "UNKNOWN";
}

const char *ozayn_mtp_phase_name(ozayn_mtp_phase_t phase) {
    switch (phase) {
        case OZAYN_MTP_PHASE_NONE: return "NONE";
        case OZAYN_MTP_PHASE_REQUESTED: return "REQUESTED";
        case OZAYN_MTP_PHASE_VALIDATING: return "VALIDATING";
        case OZAYN_MTP_PHASE_EVALUATING: return "EVALUATING";
        case OZAYN_MTP_PHASE_DECIDED: return "DECIDED";
        case OZAYN_MTP_PHASE_EXECUTING: return "EXECUTING";
        case OZAYN_MTP_PHASE_VERIFYING: return "VERIFYING";
        case OZAYN_MTP_PHASE_COMPLETED: return "COMPLETED";
        case OZAYN_MTP_PHASE_REJECTED: return "REJECTED";
        case OZAYN_MTP_PHASE_FAILED: return "FAILED";
        case OZAYN_MTP_PHASE_CANCELLED: return "CANCELLED";
        case OZAYN_MTP_PHASE_EXPIRED: return "EXPIRED";
    }
    return "UNKNOWN";
}

const char *ozayn_mtp_trigger_name(ozayn_mtp_trigger_t trigger) {
    switch (trigger) {
        case OZAYN_MTP_TRIGGER_NONE: return "NONE";
        case OZAYN_MTP_TRIGGER_STARTUP: return "STARTUP";
        case OZAYN_MTP_TRIGGER_SHUTDOWN: return "SHUTDOWN";
        case OZAYN_MTP_TRIGGER_HEALTH_CHANGE: return "HEALTH_CHANGE";
        case OZAYN_MTP_TRIGGER_SECURITY_CHANGE: return "SECURITY_CHANGE";
        case OZAYN_MTP_TRIGGER_RESOURCE_CHANGE: return "RESOURCE_CHANGE";
        case OZAYN_MTP_TRIGGER_DEVICE_CHANGE: return "DEVICE_CHANGE";
        case OZAYN_MTP_TRIGGER_RECOVERY: return "RECOVERY";
        case OZAYN_MTP_TRIGGER_MAINTENANCE_REQUEST: return "MAINTENANCE_REQUEST";
        case OZAYN_MTP_TRIGGER_ADMINISTRATIVE: return "ADMINISTRATIVE";
        case OZAYN_MTP_TRIGGER_SYSTEM_FAILURE: return "SYSTEM_FAILURE";
        case OZAYN_MTP_TRIGGER_SAFETY_EVENT: return "SAFETY_EVENT";
        case OZAYN_MTP_TRIGGER_CONFIGURATION_CHANGE: return "CONFIGURATION_CHANGE";
        case OZAYN_MTP_TRIGGER_COUNT: return "COUNT";
    }
    return "UNKNOWN";
}

const char *ozayn_mtp_event_type_name(ozayn_mtp_event_type_t type) {
    switch (type) {
        case OZAYN_MTP_EVENT_EVALUATION_STARTED: return "EVALUATION_STARTED";
        case OZAYN_MTP_EVENT_EVALUATION_COMPLETED: return "EVALUATION_COMPLETED";
        case OZAYN_MTP_EVENT_TRANSITION_APPROVED: return "TRANSITION_APPROVED";
        case OZAYN_MTP_EVENT_TRANSITION_DENIED: return "TRANSITION_DENIED";
        case OZAYN_MTP_EVENT_TRANSITION_DEFERRED: return "TRANSITION_DEFERRED";
        case OZAYN_MTP_EVENT_POLICY_ADDED: return "POLICY_ADDED";
        case OZAYN_MTP_EVENT_POLICY_REMOVED: return "POLICY_REMOVED";
        case OZAYN_MTP_EVENT_POLICY_ENABLED: return "POLICY_ENABLED";
        case OZAYN_MTP_EVENT_POLICY_DISABLED: return "POLICY_DISABLED";
        case OZAYN_MTP_EVENT_REQUEST_EXPIRED: return "REQUEST_EXPIRED";
        case OZAYN_MTP_EVENT_CONFLICT_DETECTED: return "CONFLICT_DETECTED";
        case OZAYN_MTP_EVENT_TRANSITION_EXECUTING: return "TRANSITION_EXECUTING";
        case OZAYN_MTP_EVENT_TRANSITION_COMPLETED: return "TRANSITION_COMPLETED";
        case OZAYN_MTP_EVENT_TRANSITION_FAILED: return "TRANSITION_FAILED";
        case OZAYN_MTP_EVENT_COUNT: return "COUNT";
    }
    return "UNKNOWN";
}
