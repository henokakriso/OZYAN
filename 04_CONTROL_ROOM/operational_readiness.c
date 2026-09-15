#include "operational_readiness.h"
#include <string.h>
#include <stdio.h>
#include <time.h>

/* ============================================================
 * SECTION 1 — GLOBAL STATE
 * ============================================================ */

static ozayn_ord_service_t _global_ord;

ozayn_ord_service_t *ozayn_ord_get_global(void) {
    return &_global_ord;
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

/* ============================================================
 * SECTION 3 — VALID TRANSITION TABLE
 * ============================================================ */

static const int _valid_transitions[OZAYN_ORD_MODE_COUNT][OZAYN_ORD_MODE_COUNT] = {
    /* FROM \ TO        UNK  INIT  RDY  RDGD  REC  MAINT SHLD BLK  SDWN FAIL */
    /* UNKNOWN     */ {  0,   1,   0,   0,   0,   0,   0,   0,   0,   0 },
    /* INITIALIZING*/ {  0,   0,   1,   1,   0,   0,   0,   1,   1,   1 },
    /* READY       */ {  0,   0,   0,   1,   1,   1,   1,   1,   1,   1 },
    /* RDY_DEGRADED*/ {  0,   0,   1,   0,   1,   1,   1,   1,   1,   1 },
    /* RECOVERY    */ {  0,   0,   1,   1,   0,   0,   1,   1,   1,   1 },
    /* MAINTENANCE */ {  0,   0,   1,   1,   1,   0,   1,   0,   1,   1 },
    /* SAFE_HOLD   */ {  0,   0,   0,   0,   1,   0,   0,   0,   1,   1 },
    /* BLOCKED     */ {  0,   0,   1,   0,   1,   0,   0,   0,   1,   1 },
    /* SHUTTING_DN */ {  0,   0,   0,   0,   0,   0,   0,   0,   0,   0 },
    /* FAILED      */ {  0,   0,   0,   0,   1,   0,   0,   0,   1,   0 },
};

int ozayn_ord_is_transition_valid(ozayn_ord_mode_t from, ozayn_ord_mode_t to) {
    if (from < 0 || from >= OZAYN_ORD_MODE_COUNT) return 0;
    if (to < 0 || to >= OZAYN_ORD_MODE_COUNT) return 0;
    return _valid_transitions[from][to];
}

/* ============================================================
 * SECTION 4 — GATING TABLE
 * ============================================================ */

static const ozayn_ord_gate_decision_t _gating_table[OZAYN_ORD_MODE_COUNT][OZAYN_ORD_OPCLASS_COUNT] = {
    /* FROM \ OPCLASS     NORMAL         DIAGNOSTIC     RECOVERY       SHUTDOWN       MAINTENANCE */
    /* UNKNOWN        */ { OZAYN_ORD_GATE_UNAVAILABLE, OZAYN_ORD_GATE_UNAVAILABLE, OZAYN_ORD_GATE_UNAVAILABLE, OZAYN_ORD_GATE_UNAVAILABLE, OZAYN_ORD_GATE_UNAVAILABLE },
    /* INITIALIZING   */ { OZAYN_ORD_GATE_BLOCKED, OZAYN_ORD_GATE_ALLOWED, OZAYN_ORD_GATE_BLOCKED, OZAYN_ORD_GATE_ALLOWED, OZAYN_ORD_GATE_BLOCKED },
    /* READY          */ { OZAYN_ORD_GATE_ALLOWED, OZAYN_ORD_GATE_ALLOWED, OZAYN_ORD_GATE_ALLOWED, OZAYN_ORD_GATE_ALLOWED, OZAYN_ORD_GATE_BLOCKED },
    /* RDY_DEGRADED   */ { OZAYN_ORD_GATE_RESTRICTED, OZAYN_ORD_GATE_ALLOWED, OZAYN_ORD_GATE_ALLOWED, OZAYN_ORD_GATE_ALLOWED, OZAYN_ORD_GATE_BLOCKED },
    /* RECOVERY       */ { OZAYN_ORD_GATE_RESTRICTED, OZAYN_ORD_GATE_ALLOWED, OZAYN_ORD_GATE_ALLOWED, OZAYN_ORD_GATE_ALLOWED, OZAYN_ORD_GATE_BLOCKED },
    /* MAINTENANCE    */ { OZAYN_ORD_GATE_RESTRICTED, OZAYN_ORD_GATE_ALLOWED, OZAYN_ORD_GATE_ALLOWED, OZAYN_ORD_GATE_ALLOWED, OZAYN_ORD_GATE_ALLOWED },
    /* SAFE_HOLD      */ { OZAYN_ORD_GATE_BLOCKED, OZAYN_ORD_GATE_ALLOWED, OZAYN_ORD_GATE_ALLOWED, OZAYN_ORD_GATE_ALLOWED, OZAYN_ORD_GATE_BLOCKED },
    /* BLOCKED        */ { OZAYN_ORD_GATE_BLOCKED, OZAYN_ORD_GATE_ALLOWED, OZAYN_ORD_GATE_ALLOWED, OZAYN_ORD_GATE_ALLOWED, OZAYN_ORD_GATE_BLOCKED },
    /* SHUTTING_DOWN  */ { OZAYN_ORD_GATE_BLOCKED, OZAYN_ORD_GATE_RESTRICTED, OZAYN_ORD_GATE_BLOCKED, OZAYN_ORD_GATE_ALLOWED, OZAYN_ORD_GATE_BLOCKED },
    /* FAILED         */ { OZAYN_ORD_GATE_BLOCKED, OZAYN_ORD_GATE_RESTRICTED, OZAYN_ORD_GATE_ALLOWED, OZAYN_ORD_GATE_ALLOWED, OZAYN_ORD_GATE_BLOCKED },
};

/* ============================================================
 * SECTION 5 — EVENT EMITTER
 * ============================================================ */

static void _emit_event(ozayn_ord_service_t *svc, ozayn_ord_event_type_t type,
                        const char *source, const char *message) {
    if (!svc || !message) return;

    int idx = svc->event_head;
    ozayn_ord_event_t *ev = &svc->events[idx];

    ev->type = type;
    _generate_id(ev->id, OZAYN_ORD_MAX_ID_LEN, "EVT", (int)svc->event_sequence);
    strncpy(ev->source, source ? source : "ord", OZAYN_ORD_MAX_NAME_LEN - 1);
    strncpy(ev->message, message, OZAYN_ORD_MAX_DESC_LEN - 1);
    ev->timestamp_ms = _now_ms();
    ev->sequence = svc->event_sequence++;

    svc->event_head = (svc->event_head + 1) % OZAYN_ORD_MAX_EVENTS;
    if (svc->event_count < OZAYN_ORD_MAX_EVENTS)
        svc->event_count++;
}

/* ============================================================
 * SECTION 6 — ASSESSMENT HELPERS
 * ============================================================ */

static void _reset_assessment(ozayn_ord_assessment_t *a) {
    memset(a, 0, sizeof(ozayn_ord_assessment_t));
}

static void _add_condition(ozayn_ord_assessment_t *a, const char *name,
                           const char *desc, ozayn_ord_condition_status_t status) {
    if (a->condition_count >= OZAYN_ORD_MAX_CONDITIONS) return;
    ozayn_ord_condition_t *c = &a->conditions[a->condition_count];
    strncpy(c->name, name, OZAYN_ORD_MAX_NAME_LEN - 1);
    strncpy(c->description, desc, OZAYN_ORD_MAX_DESC_LEN - 1);
    c->status = status;
    c->active = 1;
    a->condition_count++;
}

static void _add_assessment_blocking(ozayn_ord_assessment_t *a, const char *msg) {
    if (a->blocking_count >= OZAYN_ORD_MAX_BLOCKING) return;
    strncpy(a->blocking[a->blocking_count], msg, OZAYN_ORD_MAX_DESC_LEN - 1);
    a->blocking_count++;
}

static void _add_assessment_warning(ozayn_ord_assessment_t *a, const char *msg) {
    if (a->warning_count >= OZAYN_ORD_MAX_WARNINGS) return;
    strncpy(a->warnings[a->warning_count], msg, OZAYN_ORD_MAX_DESC_LEN - 1);
    a->warning_count++;
}

/* ============================================================
 * SECTION 7 — READINESS EVALUATION
 * ============================================================ */

static ozayn_ord_subsys_status_t _eval_component_registry(void *ptr) {
    if (!ptr) return OZAYN_ORD_SUBSYS_UNAVAILABLE;
    return OZAYN_ORD_SUBSYS_OK;
}

static ozayn_ord_subsys_status_t _eval_resource_manager(void *ptr) {
    if (!ptr) return OZAYN_ORD_SUBSYS_UNAVAILABLE;
    return OZAYN_ORD_SUBSYS_OK;
}

static ozayn_ord_subsys_status_t _eval_device_session(void *ptr) {
    if (!ptr) return OZAYN_ORD_SUBSYS_UNAVAILABLE;
    return OZAYN_ORD_SUBSYS_OK;
}

static ozayn_ord_subsys_status_t _eval_safety(void *ptr) {
    if (!ptr) return OZAYN_ORD_SUBSYS_UNAVAILABLE;
    return OZAYN_ORD_SUBSYS_OK;
}

static ozayn_ord_subsys_status_t _eval_diagnostics(void *ptr) {
    if (!ptr) return OZAYN_ORD_SUBSYS_UNAVAILABLE;
    return OZAYN_ORD_SUBSYS_OK;
}

static ozayn_ord_subsys_status_t _eval_startup_recovery(void *ptr) {
    if (!ptr) return OZAYN_ORD_SUBSYS_UNAVAILABLE;
    return OZAYN_ORD_SUBSYS_OK;
}

static ozayn_ord_subsys_status_t _eval_workflow_recovery(void *ptr) {
    if (!ptr) return OZAYN_ORD_SUBSYS_UNAVAILABLE;
    return OZAYN_ORD_SUBSYS_OK;
}

static void _evaluate_readiness(ozayn_ord_service_t *svc,
                                ozayn_ord_assessment_t *a) {
    /* Evaluate each subsystem */
    a->core_status = _eval_component_registry(svc->component_registry);
    a->component_status = _eval_component_registry(svc->component_registry);
    a->dependency_status = _eval_component_registry(svc->component_registry);
    a->health_status = _eval_diagnostics(svc->diagnostics);
    a->resource_status = _eval_resource_manager(svc->resource_manager);
    a->device_status = _eval_device_session(svc->device_session);
    a->security_status = _eval_safety(svc->safety);
    a->safety_status = _eval_safety(svc->safety);
    a->recovery_status = _eval_startup_recovery(svc->startup_recovery);
    a->configuration_status = OZAYN_ORD_SUBSYS_OK;

    /* Build conditions based on subsystem evaluation */
    _add_condition(a, "core", "Core system operational",
        a->core_status == OZAYN_ORD_SUBSYS_OK ?
        OZAYN_ORD_CONDITION_SATISFIED :
        (a->core_status == OZAYN_ORD_SUBSYS_UNAVAILABLE ?
         OZAYN_ORD_CONDITION_SATISFIED :
         (a->core_status == OZAYN_ORD_SUBSYS_DEGRADED ?
          OZAYN_ORD_CONDITION_WARNING : OZAYN_ORD_CONDITION_FAILED)));

    _add_condition(a, "components", "Required components available",
        a->component_status == OZAYN_ORD_SUBSYS_OK ?
        OZAYN_ORD_CONDITION_SATISFIED :
        (a->component_status == OZAYN_ORD_SUBSYS_DEGRADED ?
         OZAYN_ORD_CONDITION_WARNING : OZAYN_ORD_CONDITION_UNKNOWN));

    _add_condition(a, "safety", "Safety conditions satisfied",
        a->safety_status == OZAYN_ORD_SUBSYS_OK ?
        OZAYN_ORD_CONDITION_SATISFIED :
        (a->safety_status == OZAYN_ORD_SUBSYS_UNAVAILABLE ?
         OZAYN_ORD_CONDITION_SATISFIED :
         (a->safety_status == OZAYN_ORD_SUBSYS_FAILED ?
          OZAYN_ORD_CONDITION_FAILED : OZAYN_ORD_CONDITION_WARNING)));

    _add_condition(a, "security", "Security state valid",
        a->security_status == OZAYN_ORD_SUBSYS_OK ?
        OZAYN_ORD_CONDITION_SATISFIED :
        (a->security_status == OZAYN_ORD_SUBSYS_UNAVAILABLE ?
         OZAYN_ORD_CONDITION_SATISFIED :
         (a->security_status == OZAYN_ORD_SUBSYS_FAILED ?
          OZAYN_ORD_CONDITION_FAILED : OZAYN_ORD_CONDITION_WARNING)));

    _add_condition(a, "resources", "Critical resources available",
        a->resource_status == OZAYN_ORD_SUBSYS_OK ?
        OZAYN_ORD_CONDITION_SATISFIED :
        (a->resource_status == OZAYN_ORD_SUBSYS_UNAVAILABLE ?
         OZAYN_ORD_CONDITION_UNKNOWN :
         (a->resource_status == OZAYN_ORD_SUBSYS_DEGRADED ?
          OZAYN_ORD_CONDITION_WARNING : OZAYN_ORD_CONDITION_FAILED)));

    _add_condition(a, "recovery", "Required recovery complete",
        a->recovery_status == OZAYN_ORD_SUBSYS_OK ?
        OZAYN_ORD_CONDITION_SATISFIED :
        (a->recovery_status == OZAYN_ORD_SUBSYS_UNAVAILABLE ?
         OZAYN_ORD_CONDITION_UNKNOWN : OZAYN_ORD_CONDITION_WARNING));

    _add_condition(a, "configuration", "Configuration valid",
        OZAYN_ORD_CONDITION_SATISFIED);

    /* Determine recommended mode based on conditions */
    int has_failed = 0;
    int has_unknown_safety = 0;
    int has_warnings = 0;
    int has_unknown_critical = 0;

    for (int i = 0; i < a->condition_count; i++) {
        if (!a->conditions[i].active) continue;
        switch (a->conditions[i].status) {
            case OZAYN_ORD_CONDITION_FAILED:
                if (strcmp(a->conditions[i].name, "safety") == 0 ||
                    strcmp(a->conditions[i].name, "security") == 0) {
                    has_unknown_safety = 1;
                }
                has_failed = 1;
                break;
            case OZAYN_ORD_CONDITION_UNKNOWN:
                if (strcmp(a->conditions[i].name, "safety") == 0 ||
                    strcmp(a->conditions[i].name, "security") == 0) {
                    has_unknown_safety = 1;
                }
                if (strcmp(a->conditions[i].name, "core") == 0 ||
                    strcmp(a->conditions[i].name, "configuration") == 0) {
                    has_unknown_critical = 1;
                }
                break;
            case OZAYN_ORD_CONDITION_WARNING:
                has_warnings = 1;
                break;
            default:
                break;
        }
    }

    if (svc->blocking_count > 0) {
        a->recommended_mode = OZAYN_ORD_MODE_BLOCKED;
        a->decision = OZAYN_ORD_ASSESS_TRANSITION_REQUIRED;
    } else if (has_unknown_safety) {
        a->recommended_mode = OZAYN_ORD_MODE_SAFE_HOLD;
        a->decision = OZAYN_ORD_ASSESS_TRANSITION_REQUIRED;
    } else if (has_failed && !has_unknown_critical) {
        a->recommended_mode = OZAYN_ORD_MODE_SAFE_HOLD;
        a->decision = OZAYN_ORD_ASSESS_TRANSITION_RECOMMENDED;
    } else if (has_unknown_critical) {
        a->recommended_mode = OZAYN_ORD_MODE_INITIALIZING;
        a->decision = OZAYN_ORD_ASSESS_TRANSITION_RECOMMENDED;
    } else if (has_warnings) {
        a->recommended_mode = OZAYN_ORD_MODE_READY_DEGRADED;
        a->decision = OZAYN_ORD_ASSESS_TRANSITION_RECOMMENDED;
    } else {
        a->recommended_mode = OZAYN_ORD_MODE_READY;
        a->decision = OZAYN_ORD_ASSESS_MAINTAIN_MODE;
    }
}

/* ============================================================
 * SECTION 8 — LIFECYCLE
 * ============================================================ */

ozayn_ord_err_t ozayn_ord_service_init(ozayn_ord_service_t *svc,
                                       const ozayn_ord_service_config_t *cfg) {
    if (!svc) return OZAYN_ORD_ERR_NULL;
    if (svc->initialized) return OZAYN_ORD_ERR_ALREADY_INITIALIZED;

    memset(svc, 0, sizeof(ozayn_ord_service_t));

    if (cfg) {
        svc->component_registry = cfg->component_registry;
        svc->resource_manager = cfg->resource_manager;
        svc->device_session = cfg->device_session;
        svc->safety = cfg->safety;
        svc->diagnostics = cfg->diagnostics;
        svc->startup_recovery = cfg->startup_recovery;
        svc->workflow_recovery = cfg->workflow_recovery;
        svc->workflow_checkpoint = cfg->workflow_checkpoint;
        svc->audit = cfg->audit;
    }

    svc->current_mode = OZAYN_ORD_MODE_UNKNOWN;
    svc->previous_mode = OZAYN_ORD_MODE_UNKNOWN;
    svc->initialized = 1;

    _emit_event(svc, OZAYN_ORD_EVENT_ASSESSMENT_STARTED,
                "operational_readiness", "Service initialized");

    return OZAYN_ORD_OK;
}

ozayn_ord_err_t ozayn_ord_service_shutdown(ozayn_ord_service_t *svc) {
    if (!svc) return OZAYN_ORD_ERR_NULL;
    if (!svc->initialized) return OZAYN_ORD_ERR_NOT_INITIALIZED;

    /* Transition to SHUTTING_DOWN if not already there */
    if (svc->current_mode != OZAYN_ORD_MODE_SHUTTING_DOWN &&
        svc->current_mode != OZAYN_ORD_MODE_UNKNOWN) {
        svc->previous_mode = svc->current_mode;
        svc->current_mode = OZAYN_ORD_MODE_SHUTTING_DOWN;
    }

    _emit_event(svc, OZAYN_ORD_EVENT_MODE_CHANGED,
                "operational_readiness", "Service shutting down");

    svc->initialized = 0;
    return OZAYN_ORD_OK;
}

/* ============================================================
 * SECTION 9 — SUBSYSTEM BINDING
 * ============================================================ */

ozayn_ord_err_t ozayn_ord_set_component_registry(ozayn_ord_service_t *svc, void *ptr) {
    if (!svc) return OZAYN_ORD_ERR_NULL;
    svc->component_registry = ptr;
    return OZAYN_ORD_OK;
}

ozayn_ord_err_t ozayn_ord_set_resource_manager(ozayn_ord_service_t *svc, void *ptr) {
    if (!svc) return OZAYN_ORD_ERR_NULL;
    svc->resource_manager = ptr;
    return OZAYN_ORD_OK;
}

ozayn_ord_err_t ozayn_ord_set_device_session(ozayn_ord_service_t *svc, void *ptr) {
    if (!svc) return OZAYN_ORD_ERR_NULL;
    svc->device_session = ptr;
    return OZAYN_ORD_OK;
}

ozayn_ord_err_t ozayn_ord_set_safety(ozayn_ord_service_t *svc, void *ptr) {
    if (!svc) return OZAYN_ORD_ERR_NULL;
    svc->safety = ptr;
    return OZAYN_ORD_OK;
}

ozayn_ord_err_t ozayn_ord_set_diagnostics(ozayn_ord_service_t *svc, void *ptr) {
    if (!svc) return OZAYN_ORD_ERR_NULL;
    svc->diagnostics = ptr;
    return OZAYN_ORD_OK;
}

ozayn_ord_err_t ozayn_ord_set_startup_recovery(ozayn_ord_service_t *svc, void *ptr) {
    if (!svc) return OZAYN_ORD_ERR_NULL;
    svc->startup_recovery = ptr;
    return OZAYN_ORD_OK;
}

ozayn_ord_err_t ozayn_ord_set_workflow_recovery(ozayn_ord_service_t *svc, void *ptr) {
    if (!svc) return OZAYN_ORD_ERR_NULL;
    svc->workflow_recovery = ptr;
    return OZAYN_ORD_OK;
}

ozayn_ord_err_t ozayn_ord_set_workflow_checkpoint(ozayn_ord_service_t *svc, void *ptr) {
    if (!svc) return OZAYN_ORD_ERR_NULL;
    svc->workflow_checkpoint = ptr;
    return OZAYN_ORD_OK;
}

/* ============================================================
 * SECTION 10 — MODE QUERIES
 * ============================================================ */

ozayn_ord_mode_t ozayn_ord_get_mode(const ozayn_ord_service_t *svc) {
    if (!svc || !svc->initialized) return OZAYN_ORD_MODE_UNKNOWN;
    return svc->current_mode;
}

ozayn_ord_mode_t ozayn_ord_get_previous_mode(const ozayn_ord_service_t *svc) {
    if (!svc || !svc->initialized) return OZAYN_ORD_MODE_UNKNOWN;
    return svc->previous_mode;
}

int ozayn_ord_is_running(const ozayn_ord_service_t *svc) {
    if (!svc || !svc->initialized) return 0;
    return svc->current_mode == OZAYN_ORD_MODE_READY ||
           svc->current_mode == OZAYN_ORD_MODE_READY_DEGRADED ||
           svc->current_mode == OZAYN_ORD_MODE_RECOVERY ||
           svc->current_mode == OZAYN_ORD_MODE_MAINTENANCE;
}

/* ============================================================
 * SECTION 11 — READINESS ASSESSMENT
 * ============================================================ */

ozayn_ord_err_t ozayn_ord_assess(ozayn_ord_service_t *svc,
                                 ozayn_ord_assessment_t *out) {
    if (!svc) return OZAYN_ORD_ERR_NULL;
    if (!svc->initialized) return OZAYN_ORD_ERR_NOT_INITIALIZED;
    if (!out) return OZAYN_ORD_ERR_NULL;
    if (svc->assessment_in_progress) return OZAYN_ORD_ERR_CONCURRENCY_ERROR;

    svc->assessment_in_progress = 1;

    _emit_event(svc, OZAYN_ORD_EVENT_ASSESSMENT_STARTED,
                "operational_readiness", "Readiness assessment started");

    /* Initialize assessment */
    _reset_assessment(out);
    _generate_id(out->id, OZAYN_ORD_MAX_ID_LEN, "ASSESS",
                 svc->stats.total_assessments);
    out->timestamp_ms = _now_ms();
    out->current_mode = svc->current_mode;
    out->active = 1;

    /* Evaluate readiness */
    _evaluate_readiness(svc, out);

    /* Set proposed mode */
    out->proposed_mode = out->recommended_mode;

    /* Store assessment */
    int idx = svc->assessment_head;
    svc->assessments[idx] = *out;
    svc->assessment_head = (svc->assessment_head + 1) % OZAYN_ORD_MAX_ASSESSMENTS;
    if (svc->assessment_count < OZAYN_ORD_MAX_ASSESSMENTS)
        svc->assessment_count++;
    svc->stats.total_assessments++;

    svc->assessment_in_progress = 0;

    _emit_event(svc, OZAYN_ORD_EVENT_ASSESSMENT_COMPLETED,
                "operational_readiness", "Readiness assessment completed");

    return OZAYN_ORD_OK;
}

ozayn_ord_err_t ozayn_ord_get_latest_assessment(const ozayn_ord_service_t *svc,
                                                ozayn_ord_assessment_t *out) {
    if (!svc) return OZAYN_ORD_ERR_NULL;
    if (!svc->initialized) return OZAYN_ORD_ERR_NOT_INITIALIZED;
    if (!out) return OZAYN_ORD_ERR_NULL;
    if (svc->assessment_count == 0) return OZAYN_ORD_ERR_NOT_FOUND;

    int idx = (svc->assessment_head - 1 + OZAYN_ORD_MAX_ASSESSMENTS) %
              OZAYN_ORD_MAX_ASSESSMENTS;
    *out = svc->assessments[idx];
    return OZAYN_ORD_OK;
}

int ozayn_ord_assessment_count(const ozayn_ord_service_t *svc) {
    if (!svc || !svc->initialized) return 0;
    return svc->assessment_count;
}

/* ============================================================
 * SECTION 12 — FLAPPING PROTECTION
 * ============================================================ */

static int _check_flapping(ozayn_ord_service_t *svc, int64_t now_ms) {
    /* If in cooldown, reject */
    if (svc->flapping && svc->flap_cooldown_ms > 0) {
        if (now_ms - svc->flap_cooldown_ms < OZAYN_ORD_FLAP_COOLDOWN_MS) {
            return 1;
        }
        svc->flapping = 0;
        svc->flap_cooldown_ms = 0;
    }

    /* Record this transition */
    svc->flap_timestamps[svc->flap_index] = now_ms;
    svc->flap_index = (svc->flap_index + 1) % OZAYN_ORD_FLAP_THRESHOLD;
    if (svc->flap_count < OZAYN_ORD_FLAP_THRESHOLD)
        svc->flap_count++;

    /* Check if too many transitions in window — detect but don't reject
     * the transition that first detects flapping. Only reject during
     * the subsequent cooldown period. */
    if (svc->flap_count >= OZAYN_ORD_FLAP_THRESHOLD && !svc->flapping) {
        int64_t oldest = svc->flap_timestamps[svc->flap_index];
        if (now_ms - oldest < OZAYN_ORD_FLAP_WINDOW_MS) {
            svc->flapping = 1;
            svc->flap_cooldown_ms = now_ms;
            svc->stats.total_flapping_detections++;
            _emit_event(svc, OZAYN_ORD_EVENT_FLAPPING_DETECTED,
                        "operational_readiness", "Flapping detected");
            return 0;
        }
    }

    return 0;
}

/* ============================================================
 * SECTION 13 — MODE TRANSITIONS
 * ============================================================ */

static ozayn_ord_err_t _perform_transition(ozayn_ord_service_t *svc,
                                           ozayn_ord_mode_t target,
                                           ozayn_ord_trigger_t trigger,
                                           const char *reason,
                                           const char *source,
                                           int force) {
    if (!svc) return OZAYN_ORD_ERR_NULL;
    if (!svc->initialized) return OZAYN_ORD_ERR_NOT_INITIALIZED;

    int64_t now_ms = _now_ms();

    /* Validate transition */
    if (!ozayn_ord_is_transition_valid(svc->current_mode, target)) {
        return OZAYN_ORD_ERR_MODE_TRANSITION_INVALID;
    }

    /* Check flapping (bypassed by force) */
    if (!force && _check_flapping(svc, now_ms)) {
        return OZAYN_ORD_ERR_MODE_TRANSITION_REJECTED;
    }

    _emit_event(svc, OZAYN_ORD_EVENT_TRANSITION_STARTED,
                "operational_readiness", "Mode transition started");

    /* Record transition */
    ozayn_ord_transition_t *t = &svc->transitions[svc->transition_head];
    _generate_id(t->id, OZAYN_ORD_MAX_ID_LEN, "TRANS",
                 svc->stats.total_transitions);
    t->previous_mode = svc->current_mode;
    t->requested_mode = target;
    t->final_mode = target;
    t->trigger = trigger;
    strncpy(t->reason, reason ? reason : "", OZAYN_ORD_MAX_DESC_LEN - 1);
    strncpy(t->source, source ? source : "manual", OZAYN_ORD_MAX_NAME_LEN - 1);
    t->timestamp_ms = now_ms;
    t->result = OZAYN_ORD_TRANSITION_ACCEPTED;
    t->active = 1;

    svc->transition_head = (svc->transition_head + 1) % OZAYN_ORD_MAX_TRANSITIONS;
    if (svc->transition_count < OZAYN_ORD_MAX_TRANSITIONS)
        svc->transition_count++;

    /* Perform transition */
    svc->previous_mode = svc->current_mode;
    svc->current_mode = target;
    svc->last_transition_ms = now_ms;
    svc->stats.total_transitions++;
    svc->stats.current_mode_entered_ms = now_ms;

    /* Emit mode-specific events */
    switch (target) {
        case OZAYN_ORD_MODE_READY:
            _emit_event(svc, OZAYN_ORD_EVENT_SYSTEM_READY,
                        "operational_readiness", "System ready");
            break;
        case OZAYN_ORD_MODE_READY_DEGRADED:
            _emit_event(svc, OZAYN_ORD_EVENT_SYSTEM_DEGRADED,
                        "operational_readiness", "System degraded");
            break;
        case OZAYN_ORD_MODE_RECOVERY:
            _emit_event(svc, OZAYN_ORD_EVENT_SYSTEM_RECOVERY,
                        "operational_readiness", "System recovery");
            break;
        case OZAYN_ORD_MODE_SAFE_HOLD:
            _emit_event(svc, OZAYN_ORD_EVENT_SYSTEM_SAFE_HOLD,
                        "operational_readiness", "System safe hold");
            break;
        case OZAYN_ORD_MODE_BLOCKED:
            _emit_event(svc, OZAYN_ORD_EVENT_SYSTEM_BLOCKED,
                        "operational_readiness", "System blocked");
            break;
        case OZAYN_ORD_MODE_MAINTENANCE:
            _emit_event(svc, OZAYN_ORD_EVENT_MAINTENANCE_ENTERED,
                        "operational_readiness", "Maintenance mode entered");
            break;
        default:
            break;
    }

    _emit_event(svc, OZAYN_ORD_EVENT_TRANSITION_COMPLETED,
                "operational_readiness", "Mode transition completed");

    _emit_event(svc, OZAYN_ORD_EVENT_MODE_CHANGED,
                "operational_readiness", "System mode changed");

    return OZAYN_ORD_OK;
}

ozayn_ord_err_t ozayn_ord_transition(ozayn_ord_service_t *svc,
                                     ozayn_ord_mode_t target,
                                     ozayn_ord_trigger_t trigger,
                                     const char *reason,
                                     const char *source) {
    return _perform_transition(svc, target, trigger, reason, source, 0);
}

ozayn_ord_err_t ozayn_ord_transition_force(ozayn_ord_service_t *svc,
                                           ozayn_ord_mode_t target,
                                           ozayn_ord_trigger_t trigger,
                                           const char *reason,
                                           const char *source) {
    return _perform_transition(svc, target, trigger, reason, source, 1);
}

ozayn_ord_err_t ozayn_ord_get_latest_transition(const ozayn_ord_service_t *svc,
                                                ozayn_ord_transition_t *out) {
    if (!svc) return OZAYN_ORD_ERR_NULL;
    if (!svc->initialized) return OZAYN_ORD_ERR_NOT_INITIALIZED;
    if (!out) return OZAYN_ORD_ERR_NULL;
    if (svc->transition_count == 0) return OZAYN_ORD_ERR_NOT_FOUND;

    int idx = (svc->transition_head - 1 + OZAYN_ORD_MAX_TRANSITIONS) %
              OZAYN_ORD_MAX_TRANSITIONS;
    *out = svc->transitions[idx];
    return OZAYN_ORD_OK;
}

int ozayn_ord_transition_count(const ozayn_ord_service_t *svc) {
    if (!svc || !svc->initialized) return 0;
    return svc->transition_count;
}

/* ============================================================
 * SECTION 14 — OPERATION GATING
 * ============================================================ */

ozayn_ord_gate_decision_t ozayn_ord_check_operation(const ozayn_ord_service_t *svc,
                                                    ozayn_ord_opclass_t opclass) {
    if (!svc || !svc->initialized) return OZAYN_ORD_GATE_UNAVAILABLE;
    if (opclass < 0 || opclass >= OZAYN_ORD_OPCLASS_COUNT) return OZAYN_ORD_GATE_UNAVAILABLE;
    return _gating_table[svc->current_mode][opclass];
}

ozayn_ord_err_t ozayn_ord_gate_operation(ozayn_ord_service_t *svc,
                                         ozayn_ord_opclass_t opclass,
                                         const char *operation_id) {
    if (!svc) return OZAYN_ORD_ERR_NULL;
    if (!svc->initialized) return OZAYN_ORD_ERR_NOT_INITIALIZED;

    ozayn_ord_gate_decision_t dec = ozayn_ord_check_operation(svc, opclass);

    /* Emit gating event */
    if (dec == OZAYN_ORD_GATE_ALLOWED || dec == OZAYN_ORD_GATE_RESTRICTED) {
        _emit_event(svc, OZAYN_ORD_EVENT_OPERATION_RELEASED,
                    "operational_readiness", "Operation released");
        svc->stats.total_operations_allowed++;
        if (dec == OZAYN_ORD_GATE_RESTRICTED)
            svc->stats.total_operations_restricted++;
    } else {
        _emit_event(svc, OZAYN_ORD_EVENT_OPERATION_GATED,
                    "operational_readiness", "Operation gated");
        if (dec == OZAYN_ORD_GATE_BLOCKED)
            svc->stats.total_operations_blocked++;
    }

    svc->stats.total_operations_gated++;

    if (dec == OZAYN_ORD_GATE_BLOCKED || dec == OZAYN_ORD_GATE_UNAVAILABLE) {
        return OZAYN_ORD_ERR_OPERATION_GATED;
    }

    return OZAYN_ORD_OK;
}

/* ============================================================
 * SECTION 15 — BLOCKING AND WARNINGS
 * ============================================================ */

ozayn_ord_err_t ozayn_ord_add_blocking(ozayn_ord_service_t *svc,
                                       const char *description) {
    if (!svc) return OZAYN_ORD_ERR_NULL;
    if (!description) return OZAYN_ORD_ERR_INVALID_PARAM;
    if (!svc->initialized) return OZAYN_ORD_ERR_NOT_INITIALIZED;
    if (svc->blocking_count >= OZAYN_ORD_MAX_BLOCKING)
        return OZAYN_ORD_ERR_LIMIT_REACHED;

    strncpy(svc->blocking[svc->blocking_count], description,
            OZAYN_ORD_MAX_DESC_LEN - 1);
    svc->blocking[svc->blocking_count][OZAYN_ORD_MAX_DESC_LEN - 1] = '\0';
    svc->blocking_count++;

    return OZAYN_ORD_OK;
}

ozayn_ord_err_t ozayn_ord_add_warning(ozayn_ord_service_t *svc,
                                      const char *description) {
    if (!svc) return OZAYN_ORD_ERR_NULL;
    if (!description) return OZAYN_ORD_ERR_INVALID_PARAM;
    if (!svc->initialized) return OZAYN_ORD_ERR_NOT_INITIALIZED;
    if (svc->warning_count >= OZAYN_ORD_MAX_WARNINGS)
        return OZAYN_ORD_ERR_LIMIT_REACHED;

    strncpy(svc->warnings[svc->warning_count], description,
            OZAYN_ORD_MAX_DESC_LEN - 1);
    svc->warnings[svc->warning_count][OZAYN_ORD_MAX_DESC_LEN - 1] = '\0';
    svc->warning_count++;

    return OZAYN_ORD_OK;
}

int ozayn_ord_blocking_count(const ozayn_ord_service_t *svc) {
    if (!svc || !svc->initialized) return 0;
    return svc->blocking_count;
}

int ozayn_ord_warning_count(const ozayn_ord_service_t *svc) {
    if (!svc || !svc->initialized) return 0;
    return svc->warning_count;
}

/* ============================================================
 * SECTION 16 — EVENTS
 * ============================================================ */

ozayn_ord_err_t ozayn_ord_emit_event(ozayn_ord_service_t *svc,
                                     ozayn_ord_event_type_t type,
                                     const char *source,
                                     const char *message) {
    if (!svc) return OZAYN_ORD_ERR_NULL;
    if (!message) return OZAYN_ORD_ERR_INVALID_PARAM;
    if (!svc->initialized) return OZAYN_ORD_ERR_NOT_INITIALIZED;

    _emit_event(svc, type, source, message);
    return OZAYN_ORD_OK;
}

ozayn_ord_err_t ozayn_ord_get_event(const ozayn_ord_service_t *svc,
                                    int index, ozayn_ord_event_t *out) {
    if (!svc) return OZAYN_ORD_ERR_NULL;
    if (!out) return OZAYN_ORD_ERR_NULL;
    if (!svc->initialized) return OZAYN_ORD_ERR_NOT_INITIALIZED;
    if (index < 0 || index >= svc->event_count) return OZAYN_ORD_ERR_NOT_FOUND;

    int actual = (svc->event_head - svc->event_count + index +
                  OZAYN_ORD_MAX_EVENTS) % OZAYN_ORD_MAX_EVENTS;
    *out = svc->events[actual];
    return OZAYN_ORD_OK;
}

int ozayn_ord_event_count(const ozayn_ord_service_t *svc) {
    if (!svc || !svc->initialized) return 0;
    return svc->event_count;
}

/* ============================================================
 * SECTION 17 — STATS
 * ============================================================ */

const ozayn_ord_stats_t *ozayn_ord_get_stats(const ozayn_ord_service_t *svc) {
    if (!svc || !svc->initialized) return NULL;
    return &svc->stats;
}

ozayn_ord_err_t ozayn_ord_reset_stats(ozayn_ord_service_t *svc) {
    if (!svc) return OZAYN_ORD_ERR_NULL;
    if (!svc->initialized) return OZAYN_ORD_ERR_NOT_INITIALIZED;
    memset(&svc->stats, 0, sizeof(ozayn_ord_stats_t));
    return OZAYN_ORD_OK;
}

/* ============================================================
 * SECTION 18 — FLAPPING QUERY
 * ============================================================ */

int ozayn_ord_is_flapping(const ozayn_ord_service_t *svc) {
    if (!svc || !svc->initialized) return 0;
    return svc->flapping;
}

/* ============================================================
 * SECTION 19 — NAME HELPERS
 * ============================================================ */

const char *ozayn_ord_err_name(ozayn_ord_err_t err) {
    switch (err) {
        case OZAYN_ORD_OK: return "OK";
        case OZAYN_ORD_ERR_NULL: return "NULL";
        case OZAYN_ORD_ERR_NOT_INITIALIZED: return "NOT_INITIALIZED";
        case OZAYN_ORD_ERR_ALREADY_INITIALIZED: return "ALREADY_INITIALIZED";
        case OZAYN_ORD_ERR_INVALID_PARAM: return "INVALID_PARAM";
        case OZAYN_ORD_ERR_STATE_INVALID: return "STATE_INVALID";
        case OZAYN_ORD_ERR_MODE_TRANSITION_INVALID: return "MODE_TRANSITION_INVALID";
        case OZAYN_ORD_ERR_MODE_TRANSITION_REJECTED: return "MODE_TRANSITION_REJECTED";
        case OZAYN_ORD_ERR_MODE_TRANSITION_FAILED: return "MODE_TRANSITION_FAILED";
        case OZAYN_ORD_ERR_ASSESSMENT_FAILED: return "ASSESSMENT_FAILED";
        case OZAYN_ORD_ERR_OPERATION_GATED: return "OPERATION_GATED";
        case OZAYN_ORD_ERR_CONCURRENCY_ERROR: return "CONCURRENCY_ERROR";
        case OZAYN_ORD_ERR_LIMIT_REACHED: return "LIMIT_REACHED";
        case OZAYN_ORD_ERR_CONFIGURATION_ERROR: return "CONFIGURATION_ERROR";
        case OZAYN_ORD_ERR_UNAVAILABLE: return "UNAVAILABLE";
    }
    return "UNKNOWN";
}

const char *ozayn_ord_mode_name(ozayn_ord_mode_t mode) {
    switch (mode) {
        case OZAYN_ORD_MODE_UNKNOWN: return "UNKNOWN";
        case OZAYN_ORD_MODE_INITIALIZING: return "INITIALIZING";
        case OZAYN_ORD_MODE_READY: return "READY";
        case OZAYN_ORD_MODE_READY_DEGRADED: return "READY_DEGRADED";
        case OZAYN_ORD_MODE_RECOVERY: return "RECOVERY";
        case OZAYN_ORD_MODE_MAINTENANCE: return "MAINTENANCE";
        case OZAYN_ORD_MODE_SAFE_HOLD: return "SAFE_HOLD";
        case OZAYN_ORD_MODE_BLOCKED: return "BLOCKED";
        case OZAYN_ORD_MODE_SHUTTING_DOWN: return "SHUTTING_DOWN";
        case OZAYN_ORD_MODE_FAILED: return "FAILED";
        case OZAYN_ORD_MODE_COUNT: return "COUNT";
    }
    return "UNKNOWN";
}

const char *ozayn_ord_opclass_name(ozayn_ord_opclass_t opclass) {
    switch (opclass) {
        case OZAYN_ORD_OPCLASS_NORMAL: return "NORMAL";
        case OZAYN_ORD_OPCLASS_DIAGNOSTIC: return "DIAGNOSTIC";
        case OZAYN_ORD_OPCLASS_RECOVERY: return "RECOVERY";
        case OZAYN_ORD_OPCLASS_SHUTDOWN: return "SHUTDOWN";
        case OZAYN_ORD_OPCLASS_MAINTENANCE: return "MAINTENANCE";
        case OZAYN_ORD_OPCLASS_COUNT: return "COUNT";
    }
    return "UNKNOWN";
}

const char *ozayn_ord_gate_name(ozayn_ord_gate_decision_t gate) {
    switch (gate) {
        case OZAYN_ORD_GATE_ALLOWED: return "ALLOWED";
        case OZAYN_ORD_GATE_RESTRICTED: return "RESTRICTED";
        case OZAYN_ORD_GATE_BLOCKED: return "BLOCKED";
        case OZAYN_ORD_GATE_UNAVAILABLE: return "UNAVAILABLE";
    }
    return "UNKNOWN";
}

const char *ozayn_ord_trigger_name(ozayn_ord_trigger_t trigger) {
    switch (trigger) {
        case OZAYN_ORD_TRIGGER_NONE: return "NONE";
        case OZAYN_ORD_TRIGGER_MANUAL: return "MANUAL";
        case OZAYN_ORD_TRIGGER_ASSESSMENT: return "ASSESSMENT";
        case OZAYN_ORD_TRIGGER_EVENT: return "EVENT";
        case OZAYN_ORD_TRIGGER_SAFETY: return "SAFETY";
        case OZAYN_ORD_TRIGGER_SECURITY: return "SECURITY";
        case OZAYN_ORD_TRIGGER_RESOURCE: return "RESOURCE";
        case OZAYN_ORD_TRIGGER_DEVICE: return "DEVICE";
        case OZAYN_ORD_TRIGGER_RECOVERY: return "RECOVERY";
        case OZAYN_ORD_TRIGGER_STARTUP: return "STARTUP";
        case OZAYN_ORD_TRIGGER_SHUTDOWN: return "SHUTDOWN";
        case OZAYN_ORD_TRIGGER_FAILURE: return "FAILURE";
        case OZAYN_ORD_TRIGGER_MAINTENANCE_REQUEST: return "MAINTENANCE_REQUEST";
        case OZAYN_ORD_TRIGGER_COUNT: return "COUNT";
    }
    return "UNKNOWN";
}

const char *ozayn_ord_assess_name(ozayn_ord_assess_decision_t assess) {
    switch (assess) {
        case OZAYN_ORD_ASSESS_NO_CHANGE: return "NO_CHANGE";
        case OZAYN_ORD_ASSESS_MAINTAIN_MODE: return "MAINTAIN_MODE";
        case OZAYN_ORD_ASSESS_TRANSITION_RECOMMENDED: return "TRANSITION_RECOMMENDED";
        case OZAYN_ORD_ASSESS_TRANSITION_REQUIRED: return "TRANSITION_REQUIRED";
        case OZAYN_ORD_ASSESS_UNAVAILABLE: return "UNAVAILABLE";
    }
    return "UNKNOWN";
}

const char *ozayn_ord_condition_name(ozayn_ord_condition_status_t status) {
    switch (status) {
        case OZAYN_ORD_CONDITION_UNSATISFIED: return "UNSATISFIED";
        case OZAYN_ORD_CONDITION_SATISFIED: return "SATISFIED";
        case OZAYN_ORD_CONDITION_FAILED: return "FAILED";
        case OZAYN_ORD_CONDITION_UNKNOWN: return "UNKNOWN";
        case OZAYN_ORD_CONDITION_WARNING: return "WARNING";
    }
    return "UNKNOWN";
}

const char *ozayn_ord_subsys_name(ozayn_ord_subsys_status_t status) {
    switch (status) {
        case OZAYN_ORD_SUBSYS_UNKNOWN: return "UNKNOWN";
        case OZAYN_ORD_SUBSYS_OK: return "OK";
        case OZAYN_ORD_SUBSYS_DEGRADED: return "DEGRADED";
        case OZAYN_ORD_SUBSYS_FAILED: return "FAILED";
        case OZAYN_ORD_SUBSYS_UNAVAILABLE: return "UNAVAILABLE";
    }
    return "UNKNOWN";
}

const char *ozayn_ord_transition_result_name(ozayn_ord_transition_result_t result) {
    switch (result) {
        case OZAYN_ORD_TRANSITION_ACCEPTED: return "ACCEPTED";
        case OZAYN_ORD_TRANSITION_REJECTED: return "REJECTED";
        case OZAYN_ORD_TRANSITION_FAILED: return "FAILED";
        case OZAYN_ORD_TRANSITION_SKIPPED: return "SKIPPED";
    }
    return "UNKNOWN";
}

const char *ozayn_ord_event_type_name(ozayn_ord_event_type_t type) {
    switch (type) {
        case OZAYN_ORD_EVENT_ASSESSMENT_STARTED: return "ASSESSMENT_STARTED";
        case OZAYN_ORD_EVENT_ASSESSMENT_COMPLETED: return "ASSESSMENT_COMPLETED";
        case OZAYN_ORD_EVENT_MODE_CHANGED: return "MODE_CHANGED";
        case OZAYN_ORD_EVENT_TRANSITION_REQUESTED: return "TRANSITION_REQUESTED";
        case OZAYN_ORD_EVENT_TRANSITION_STARTED: return "TRANSITION_STARTED";
        case OZAYN_ORD_EVENT_TRANSITION_COMPLETED: return "TRANSITION_COMPLETED";
        case OZAYN_ORD_EVENT_TRANSITION_REJECTED: return "TRANSITION_REJECTED";
        case OZAYN_ORD_EVENT_SYSTEM_READY: return "SYSTEM_READY";
        case OZAYN_ORD_EVENT_SYSTEM_DEGRADED: return "SYSTEM_DEGRADED";
        case OZAYN_ORD_EVENT_SYSTEM_RECOVERY: return "SYSTEM_RECOVERY";
        case OZAYN_ORD_EVENT_SYSTEM_SAFE_HOLD: return "SYSTEM_SAFE_HOLD";
        case OZAYN_ORD_EVENT_SYSTEM_BLOCKED: return "SYSTEM_BLOCKED";
        case OZAYN_ORD_EVENT_MAINTENANCE_ENTERED: return "MAINTENANCE_ENTERED";
        case OZAYN_ORD_EVENT_MAINTENANCE_EXITED: return "MAINTENANCE_EXITED";
        case OZAYN_ORD_EVENT_OPERATION_GATED: return "OPERATION_GATED";
        case OZAYN_ORD_EVENT_OPERATION_RELEASED: return "OPERATION_RELEASED";
        case OZAYN_ORD_EVENT_FLAPPING_DETECTED: return "FLAPPING_DETECTED";
        case OZAYN_ORD_EVENT_COUNT: return "COUNT";
    }
    return "UNKNOWN";
}
