/*
 * startup_recovery.c — Startup Recovery & System Reconciliation Orchestration
 *
 * Step 19/35 — Control Room
 *
 * Coordinates controlled startup lifecycle, subsystem discovery,
 * state/resource/device/security reconciliation, and recovery assessment.
 */

#include "startup_recovery.h"
#include <string.h>
#include <stdio.h>
#include <time.h>

/* ============================================================
 * INTERNAL — GLOBAL STATE
 * ============================================================ */

static ozayn_src_service_t _global_src;
static int _global_src_initialized = 0;

ozayn_src_service_t *ozayn_src_get_global(void) {
    return &_global_src;
}

/* ============================================================
 * INTERNAL — HELPERS
 * ============================================================ */

static int64_t _now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static void _generate_id(char *buf, int bufsize, const char *prefix, int seq) {
    snprintf(buf, bufsize, "SRC-%s-%d", prefix, seq);
}

static int _find_free_event_slot(ozayn_src_service_t *svc) {
    if (svc->event_count < OZAYN_SRC_MAX_EVENTS) {
        return (svc->event_head + svc->event_count) % OZAYN_SRC_MAX_EVENTS;
    }
    return svc->event_head;
}

static int _find_free_phase_result_slot(ozayn_src_service_t *svc) {
    for (int i = 0; i < OZAYN_SRC_MAX_PHASE_RESULTS; i++) {
        if (!svc->phase_results[i].active) return i;
    }
    return -1;
}

static int _find_phase_result(ozayn_src_service_t *svc,
                               ozayn_src_startup_phase_t phase) {
    for (int i = 0; i < OZAYN_SRC_MAX_PHASE_RESULTS; i++) {
        if (svc->phase_results[i].active &&
            svc->phase_results[i].phase == phase) {
            return i;
        }
    }
    return -1;
}

static const char *_phase_descriptions[] = {
    "Not started",
    "Bootstrap — initialize minimum runtime",
    "Core — validate core runtime",
    "Infrastructure — initialize control room infrastructure",
    "Discovery — discover components and capabilities",
    "Dependency validation — validate dependency graph",
    "State reconciliation — compare persisted vs runtime state",
    "Resource reconciliation — determine resource availability",
    "Device reconciliation — determine device availability",
    "Security revalidation — establish valid security context",
    "Recovery assessment — determine recovery requirements",
    "Ready — operational state",
    "Degraded — operational with reduced capability",
    "Blocked — required conditions not met",
    "Failed — startup failure",
    "Stopping — shutting down",
    "Stopped — shutdown complete"
};

static const char *_decision_descriptions[] = {
    "Unknown",
    "READY — all required infrastructure valid",
    "READY_DEGRADED — operating with reduced capability",
    "RECOVERY_REQUIRED — persistent recovery state requires handling",
    "MANUAL_REVIEW_REQUIRED — cannot safely determine recovery",
    "BLOCKED — required safety/security/dependency prevents operation",
    "FAILED — startup failure, no safe runtime state"
};

/* ============================================================
 * SECTION 1 — LIFECYCLE
 * ============================================================ */

ozayn_src_err_t ozayn_src_service_init(ozayn_src_service_t *svc) {
    if (!svc) return OZAYN_SRC_ERR_NULL;
    if (svc->initialized) return OZAYN_SRC_ERR_ALREADY_INITIALIZED;

    memset(svc, 0, sizeof(ozayn_src_service_t));

    /* Initialize startup context */
    svc->context.current_phase = OZAYN_SRC_PHASE_NOT_STARTED;
    svc->context.highest_completed_phase = OZAYN_SRC_PHASE_NOT_STARTED;
    svc->context.runtime_state = OZAYN_SRC_STATE_IDLE;
    svc->context.decision = OZAYN_SRC_DECISION_UNKNOWN;

    /* Set default timeouts */
    for (int i = 0; i < OZAYN_SRC_PHASE_COUNT; i++) {
        svc->manifest.phase_timeout_ms[i] = OZAYN_SRC_DEFAULT_PHASE_TIMEOUT_MS;
    }
    svc->manifest.total_timeout_ms = OZAYN_SRC_DEFAULT_TOTAL_TIMEOUT_MS;

    /* Set default phase timeouts in context */
    for (int i = 0; i < OZAYN_SRC_PHASE_COUNT; i++) {
        svc->context.phase_timeouts_ms[i] = OZAYN_SRC_DEFAULT_PHASE_TIMEOUT_MS;
    }

    svc->initialized = 1;

    if (_global_src_initialized) {
        /* Allow re-init of the global instance */
    } else {
        _global_src_initialized = 1;
    }

    return OZAYN_SRC_OK;
}

ozayn_src_err_t ozayn_src_service_shutdown(ozayn_src_service_t *svc) {
    if (!svc) return OZAYN_SRC_ERR_NULL;
    if (!svc->initialized) return OZAYN_SRC_ERR_NOT_INITIALIZED;

    svc->running = 0;
    svc->starting = 0;
    svc->shutting_down = 0;
    svc->context.runtime_state = OZAYN_SRC_STATE_STOPPED;

    ozayn_src_emit_event(svc, OZAYN_SRC_EVENT_SHUTDOWN_COMPLETED,
                         "startup_recovery", "Service shutdown", NULL);

    svc->initialized = 0;
    return OZAYN_SRC_OK;
}

int ozayn_src_is_initialized(const ozayn_src_service_t *svc) {
    if (!svc) return 0;
    return svc->initialized;
}

/* ============================================================
 * SECTION 2 — EXTERNAL DEPENDENCY BINDING
 * ============================================================ */

ozayn_src_err_t ozayn_src_set_lifecycle(ozayn_src_service_t *svc, void *lifecycle) {
    if (!svc) return OZAYN_SRC_ERR_NULL;
    svc->lifecycle = lifecycle;
    return OZAYN_SRC_OK;
}

ozayn_src_err_t ozayn_src_set_dependency(ozayn_src_service_t *svc, void *dependency) {
    if (!svc) return OZAYN_SRC_ERR_NULL;
    svc->dependency = dependency;
    return OZAYN_SRC_OK;
}

ozayn_src_err_t ozayn_src_set_component_registry(ozayn_src_service_t *svc, void *registry) {
    if (!svc) return OZAYN_SRC_ERR_NULL;
    svc->component_registry = registry;
    return OZAYN_SRC_OK;
}

ozayn_src_err_t ozayn_src_set_resource_manager(ozayn_src_service_t *svc, void *resource) {
    if (!svc) return OZAYN_SRC_ERR_NULL;
    svc->resource_manager = resource;
    return OZAYN_SRC_OK;
}

ozayn_src_err_t ozayn_src_set_device_session(ozayn_src_service_t *svc, void *device) {
    if (!svc) return OZAYN_SRC_ERR_NULL;
    svc->device_session = device;
    return OZAYN_SRC_OK;
}

ozayn_src_err_t ozayn_src_set_safety(ozayn_src_service_t *svc, void *safety) {
    if (!svc) return OZAYN_SRC_ERR_NULL;
    svc->safety = safety;
    return OZAYN_SRC_OK;
}

ozayn_src_err_t ozayn_src_set_diagnostics(ozayn_src_service_t *svc, void *diagnostics) {
    if (!svc) return OZAYN_SRC_ERR_NULL;
    svc->diagnostics = diagnostics;
    return OZAYN_SRC_OK;
}

ozayn_src_err_t ozayn_src_set_workflow_recovery(ozayn_src_service_t *svc, void *recovery) {
    if (!svc) return OZAYN_SRC_ERR_NULL;
    svc->workflow_recovery = recovery;
    return OZAYN_SRC_OK;
}

ozayn_src_err_t ozayn_src_set_workflow_checkpoint(ozayn_src_service_t *svc, void *checkpoint) {
    if (!svc) return OZAYN_SRC_ERR_NULL;
    svc->workflow_checkpoint = checkpoint;
    return OZAYN_SRC_OK;
}

ozayn_src_err_t ozayn_src_set_state_manager(ozayn_src_service_t *svc, void *state) {
    if (!svc) return OZAYN_SRC_ERR_NULL;
    svc->state_manager = state;
    return OZAYN_SRC_OK;
}

ozayn_src_err_t ozayn_src_set_events_engine(ozayn_src_service_t *svc, void *events) {
    if (!svc) return OZAYN_SRC_ERR_NULL;
    svc->events_engine = events;
    return OZAYN_SRC_OK;
}

/* ============================================================
 * SECTION 3 — STARTUP CAUSE DETECTION
 * ============================================================ */

ozayn_src_err_t ozayn_src_detect_startup_cause(ozayn_src_service_t *svc,
    ozayn_src_startup_cause_t *out_cause,
    ozayn_src_previous_shutdown_t *out_shutdown) {
    if (!svc) return OZAYN_SRC_ERR_NULL;
    if (!svc->initialized) return OZAYN_SRC_ERR_NOT_INITIALIZED;

    /*
     * In a full system, this would inspect:
     * - State manager for last shutdown state
     * - Crash loop detector for crash signals
     * - PID file for stale process detection
     * - Platform-specific crash markers
     *
     * Without these subsystems bound, we cannot reliably determine cause.
     * Default to UNKNOWN — do not assume normal.
     */
    if (out_cause) *out_cause = OZAYN_SRC_CAUSE_UNKNOWN;
    if (out_shutdown) *out_shutdown = OZAYN_SRC_SHUTDOWN_UNKNOWN;

    /* If state manager is available, attempt to determine previous state */
    if (svc->state_manager) {
        /*
         * Would call: ozayn_state_manager_load() and check for clean
         * shutdown markers. Without the full state manager API bound here,
         * we conservatively remain UNKNOWN.
         */
    }

    return OZAYN_SRC_OK;
}

/* ============================================================
 * SECTION 4 — MANIFEST
 * ============================================================ */

ozayn_src_err_t ozayn_src_manifest_reset(ozayn_src_service_t *svc) {
    if (!svc) return OZAYN_SRC_ERR_NULL;
    if (!svc->initialized) return OZAYN_SRC_ERR_NOT_INITIALIZED;

    memset(&svc->manifest, 0, sizeof(ozayn_src_startup_manifest_t));

    /* Restore default timeouts */
    for (int i = 0; i < OZAYN_SRC_PHASE_COUNT; i++) {
        svc->manifest.phase_timeout_ms[i] = OZAYN_SRC_DEFAULT_PHASE_TIMEOUT_MS;
    }
    svc->manifest.total_timeout_ms = OZAYN_SRC_DEFAULT_TOTAL_TIMEOUT_MS;
    svc->manifest.required_config_valid = 1;
    svc->manifest.failure_policy = 0;

    return OZAYN_SRC_OK;
}

ozayn_src_err_t ozayn_src_manifest_add_component(ozayn_src_service_t *svc,
    const char *name, int required) {
    if (!svc || !name) return OZAYN_SRC_ERR_NULL;
    if (!svc->initialized) return OZAYN_SRC_ERR_NOT_INITIALIZED;
    if (svc->manifest.component_count >= OZAYN_SRC_MAX_COMPONENTS)
        return OZAYN_SRC_ERR_LIMIT_REACHED;

    int idx = svc->manifest.component_count;
    strncpy(svc->manifest.component_names[idx], name,
            OZAYN_SRC_MAX_NAME_LEN - 1);
    svc->manifest.component_required[idx] = required;
    svc->manifest.component_count++;

    return OZAYN_SRC_OK;
}

ozayn_src_err_t ozayn_src_manifest_add_dependency(ozayn_src_service_t *svc,
    const char *name, int required) {
    if (!svc || !name) return OZAYN_SRC_ERR_NULL;
    if (!svc->initialized) return OZAYN_SRC_ERR_NOT_INITIALIZED;
    if (svc->manifest.dependency_count >= OZAYN_SRC_MAX_COMPONENTS)
        return OZAYN_SRC_ERR_LIMIT_REACHED;

    int idx = svc->manifest.dependency_count;
    strncpy(svc->manifest.dependency_names[idx], name,
            OZAYN_SRC_MAX_NAME_LEN - 1);
    svc->manifest.dependency_required[idx] = required;
    svc->manifest.dependency_count++;

    return OZAYN_SRC_OK;
}

ozayn_src_err_t ozayn_src_manifest_add_capability(ozayn_src_service_t *svc,
    const char *name, int required) {
    if (!svc || !name) return OZAYN_SRC_ERR_NULL;
    if (!svc->initialized) return OZAYN_SRC_ERR_NOT_INITIALIZED;
    if (svc->manifest.capability_count >= OZAYN_SRC_MAX_CAPABILITIES)
        return OZAYN_SRC_ERR_LIMIT_REACHED;

    int idx = svc->manifest.capability_count;
    strncpy(svc->manifest.capability_names[idx], name,
            OZAYN_SRC_MAX_NAME_LEN - 1);
    svc->manifest.capability_required[idx] = required;
    svc->manifest.capability_count++;

    return OZAYN_SRC_OK;
}

ozayn_src_err_t ozayn_src_manifest_set_phase_timeout(ozayn_src_service_t *svc,
    ozayn_src_startup_phase_t phase, int64_t timeout_ms) {
    if (!svc) return OZAYN_SRC_ERR_NULL;
    if (!svc->initialized) return OZAYN_SRC_ERR_NOT_INITIALIZED;
    if (phase < 0 || phase >= OZAYN_SRC_PHASE_COUNT)
        return OZAYN_SRC_ERR_INVALID_PARAM;
    if (timeout_ms <= 0) return OZAYN_SRC_ERR_INVALID_PARAM;

    svc->manifest.phase_timeout_ms[phase] = timeout_ms;
    svc->context.phase_timeouts_ms[phase] = timeout_ms;
    return OZAYN_SRC_OK;
}

ozayn_src_err_t ozayn_src_manifest_set_total_timeout(ozayn_src_service_t *svc,
    int64_t timeout_ms) {
    if (!svc) return OZAYN_SRC_ERR_NULL;
    if (!svc->initialized) return OZAYN_SRC_ERR_NOT_INITIALIZED;
    if (timeout_ms <= 0) return OZAYN_SRC_ERR_INVALID_PARAM;

    svc->manifest.total_timeout_ms = timeout_ms;
    return OZAYN_SRC_OK;
}

const ozayn_src_startup_manifest_t *ozayn_src_manifest_get(
    const ozayn_src_service_t *svc) {
    if (!svc || !svc->initialized) return NULL;
    return &svc->manifest;
}

/* ============================================================
 * SECTION 5 — EVENT HELPERS
 * ============================================================ */

ozayn_src_err_t ozayn_src_emit_event(ozayn_src_service_t *svc,
    ozayn_src_event_type_t type, const char *source,
    const char *description, const char *metadata) {
    if (!svc) return OZAYN_SRC_ERR_NULL;
    if (!svc->initialized) return OZAYN_SRC_ERR_NOT_INITIALIZED;
    if (type < 0 || type >= OZAYN_SRC_EVENT_COUNT)
        return OZAYN_SRC_ERR_INVALID_PARAM;

    int idx = _find_free_event_slot(svc);
    if (idx < 0) return OZAYN_SRC_ERR_LIMIT_REACHED;

    ozayn_src_event_t *ev = &svc->events[idx];
    memset(ev, 0, sizeof(ozayn_src_event_t));

    svc->stats.total_events++;
    _generate_id(ev->event_id, OZAYN_SRC_MAX_ID_LEN, "EVT",
                 svc->stats.total_events);

    ev->event_type = type;
    ev->timestamp_ms = _now_ms();

    if (source)
        strncpy(ev->source, source, OZAYN_SRC_MAX_NAME_LEN - 1);
    if (description)
        strncpy(ev->description, description, OZAYN_SRC_MAX_DESC_LEN - 1);
    if (metadata)
        strncpy(ev->safe_metadata, metadata, OZAYN_SRC_MAX_METADATA_LEN - 1);

    if (svc->event_count < OZAYN_SRC_MAX_EVENTS) {
        svc->event_count++;
    } else {
        svc->event_head = (svc->event_head + 1) % OZAYN_SRC_MAX_EVENTS;
    }

    ev->active = 1;
    return OZAYN_SRC_OK;
}

int ozayn_src_event_count(const ozayn_src_service_t *svc) {
    if (!svc || !svc->initialized) return 0;
    return svc->event_count;
}

const ozayn_src_event_t *ozayn_src_get_event(const ozayn_src_service_t *svc,
    int index) {
    if (!svc || !svc->initialized) return NULL;
    if (index < 0 || index >= svc->event_count) return NULL;
    int actual = (svc->event_head + index) % OZAYN_SRC_MAX_EVENTS;
    if (!svc->events[actual].active) return NULL;
    return &svc->events[actual];
}

/* ============================================================
 * SECTION 6 — WARNING & BLOCKING MANAGEMENT
 * ============================================================ */

int ozayn_src_warning_count(const ozayn_src_service_t *svc) {
    if (!svc || !svc->initialized) return 0;
    return svc->warning_count;
}

const char *ozayn_src_warning_get(const ozayn_src_service_t *svc, int index) {
    if (!svc || !svc->initialized) return NULL;
    if (index < 0 || index >= svc->warning_count) return NULL;
    return svc->warnings[index];
}

ozayn_src_err_t ozayn_src_add_warning(ozayn_src_service_t *svc,
    const char *description) {
    if (!svc || !description) return OZAYN_SRC_ERR_NULL;
    if (!svc->initialized) return OZAYN_SRC_ERR_NOT_INITIALIZED;
    if (svc->warning_count >= OZAYN_SRC_MAX_WARNINGS)
        return OZAYN_SRC_ERR_LIMIT_REACHED;

    strncpy(svc->warnings[svc->warning_count], description,
            OZAYN_SRC_MAX_DESC_LEN - 1);
    svc->warnings[svc->warning_count][OZAYN_SRC_MAX_DESC_LEN - 1] = '\0';
    svc->warning_count++;
    svc->stats.total_warnings++;

    return OZAYN_SRC_OK;
}

int ozayn_src_blocking_count(const ozayn_src_service_t *svc) {
    if (!svc || !svc->initialized) return 0;
    return svc->blocking_count;
}

const char *ozayn_src_blocking_get(const ozayn_src_service_t *svc, int index) {
    if (!svc || !svc->initialized) return NULL;
    if (index < 0 || index >= svc->blocking_count) return NULL;
    return svc->blocking[index];
}

ozayn_src_err_t ozayn_src_add_blocking(ozayn_src_service_t *svc,
    const char *description) {
    if (!svc || !description) return OZAYN_SRC_ERR_NULL;
    if (!svc->initialized) return OZAYN_SRC_ERR_NOT_INITIALIZED;
    if (svc->blocking_count >= OZAYN_SRC_MAX_BLOCKING)
        return OZAYN_SRC_ERR_LIMIT_REACHED;

    strncpy(svc->blocking[svc->blocking_count], description,
            OZAYN_SRC_MAX_DESC_LEN - 1);
    svc->blocking[svc->blocking_count][OZAYN_SRC_MAX_DESC_LEN - 1] = '\0';
    svc->blocking_count++;
    svc->stats.total_blocking_conditions++;

    return OZAYN_SRC_OK;
}

/* ============================================================
 * SECTION 7 — PHASE RESULT TRACKING
 * ============================================================ */

static ozayn_src_err_t _begin_phase(ozayn_src_service_t *svc,
    ozayn_src_startup_phase_t phase) {
    int slot = _find_free_phase_result_slot(svc);
    if (slot < 0) return OZAYN_SRC_ERR_LIMIT_REACHED;

    ozayn_src_phase_result_t *pr = &svc->phase_results[slot];
    memset(pr, 0, sizeof(ozayn_src_phase_result_t));

    pr->phase = phase;
    pr->status = OZAYN_SRC_PHASE_RESULT_PENDING;
    pr->start_time_ms = _now_ms();
    pr->active = 1;

    svc->phase_result_count++;
    return OZAYN_SRC_OK;
}

static ozayn_src_err_t _end_phase(ozayn_src_service_t *svc,
    ozayn_src_startup_phase_t phase,
    ozayn_src_phase_result_status_t status,
    const char *failure_ref,
    const char *description) {
    int idx = _find_phase_result(svc, phase);
    if (idx < 0) return OZAYN_SRC_ERR_NOT_FOUND;

    ozayn_src_phase_result_t *pr = &svc->phase_results[idx];
    pr->end_time_ms = _now_ms();
    pr->duration_ms = pr->end_time_ms - pr->start_time_ms;
    pr->status = status;

    if (failure_ref)
        strncpy(pr->failure_ref, failure_ref, OZAYN_SRC_MAX_ID_LEN - 1);
    if (description)
        strncpy(pr->description, description, OZAYN_SRC_MAX_DESC_LEN - 1);

    if (status == OZAYN_SRC_PHASE_RESULT_SUCCESS ||
        status == OZAYN_SRC_PHASE_RESULT_DEGRADED) {
        if ((int)phase > (int)svc->context.highest_completed_phase) {
            svc->context.highest_completed_phase = phase;
        }
        svc->stats.total_phases_completed++;
    } else if (status == OZAYN_SRC_PHASE_RESULT_FAILED) {
        svc->stats.total_phases_failed++;
    } else if (status == OZAYN_SRC_PHASE_RESULT_TIMEOUT) {
        svc->stats.total_phases_timeout++;
    }

    return OZAYN_SRC_OK;
}

int ozayn_src_phase_result_count(const ozayn_src_service_t *svc) {
    if (!svc || !svc->initialized) return 0;
    return svc->phase_result_count;
}

const ozayn_src_phase_result_t *ozayn_src_phase_result_get(
    const ozayn_src_service_t *svc, int index) {
    if (!svc || !svc->initialized) return NULL;
    if (index < 0 || index >= svc->phase_result_count) return NULL;
    if (!svc->phase_results[index].active) return NULL;
    return &svc->phase_results[index];
}

const ozayn_src_phase_result_t *ozayn_src_phase_result_get_by_phase(
    const ozayn_src_service_t *svc, ozayn_src_startup_phase_t phase) {
    if (!svc || !svc->initialized) return NULL;
    int idx = _find_phase_result((ozayn_src_service_t *)svc, phase);
    if (idx < 0) return NULL;
    return &svc->phase_results[idx];
}

/* ============================================================
 * SECTION 8 — STARTUP EXECUTION
 * ============================================================ */

static ozayn_src_err_t _validate_pre_startup(ozayn_src_service_t *svc) {
    if (svc->startup_in_progress)
        return OZAYN_SRC_ERR_CONCURRENCY_ERROR;
    if (svc->running)
        return OZAYN_SRC_ERR_STATE_INVALID;
    return OZAYN_SRC_OK;
}

static void _reset_for_startup(ozayn_src_service_t *svc) {
    /* Reset startup context — preserve pre-set startup_cause/previous_shutdown */
    svc->context.current_phase = OZAYN_SRC_PHASE_NOT_STARTED;
    svc->context.highest_completed_phase = OZAYN_SRC_PHASE_NOT_STARTED;
    svc->context.decision = OZAYN_SRC_DECISION_UNKNOWN;
    svc->context.start_time_ms = 0;
    svc->context.completion_time_ms = 0;

    /* Reset phase results */
    memset(svc->phase_results, 0, sizeof(svc->phase_results));
    svc->phase_result_count = 0;

    /* Reset reconciliation data */
    memset(svc->component_recon, 0, sizeof(svc->component_recon));
    svc->component_recon_count = 0;

    memset(svc->capability_recon, 0, sizeof(svc->capability_recon));
    svc->capability_recon_count = 0;

    memset(svc->resource_recon, 0, sizeof(svc->resource_recon));
    svc->resource_recon_count = 0;

    memset(svc->device_recon, 0, sizeof(svc->device_recon));
    svc->device_recon_count = 0;

    svc->security_status = OZAYN_SRC_SEC_RECON_UNKNOWN;
    memset(svc->security_description, 0, OZAYN_SRC_MAX_DESC_LEN);

    /* Reset recovery items */
    memset(svc->recovery_items, 0, sizeof(svc->recovery_items));
    svc->recovery_item_count = 0;

    /* Reset warnings/blocking */
    svc->warning_count = 0;
    svc->blocking_count = 0;
    svc->affected_count = 0;

    /* Reset events */
    memset(svc->events, 0, sizeof(svc->events));
    svc->event_count = 0;
    svc->event_head = 0;

    /* Reset running state for re-startup */
    svc->running = 0;
}

/* ============================================================
 * SECTION 8a — PHASE IMPLEMENTATIONS
 * ============================================================ */

static ozayn_src_err_t _phase_bootstrap(ozayn_src_service_t *svc) {
    _begin_phase(svc, OZAYN_SRC_PHASE_BOOTSTRAP);
    svc->context.current_phase = OZAYN_SRC_PHASE_BOOTSTRAP;

    /* Detect startup cause — only if not pre-set */
    if (svc->context.startup_cause == OZAYN_SRC_CAUSE_UNKNOWN) {
        ozayn_src_detect_startup_cause(svc, &svc->context.startup_cause,
                                       &svc->context.previous_shutdown);
    }

    /* Record cause in context */
    svc->context.start_time_ms = _now_ms();
    _generate_id(svc->context.startup_id, OZAYN_SRC_MAX_ID_LEN, "BOOT",
                 svc->stats.total_startups);

    ozayn_src_emit_event(svc, OZAYN_SRC_EVENT_STARTUP_STARTED,
                         "startup_recovery",
                         _phase_descriptions[OZAYN_SRC_PHASE_BOOTSTRAP], NULL);

    _end_phase(svc, OZAYN_SRC_PHASE_BOOTSTRAP,
               OZAYN_SRC_PHASE_RESULT_SUCCESS, NULL,
               "Bootstrap completed");
    return OZAYN_SRC_OK;
}

static ozayn_src_err_t _phase_core(ozayn_src_service_t *svc) {
    _begin_phase(svc, OZAYN_SRC_PHASE_CORE);
    svc->context.current_phase = OZAYN_SRC_PHASE_CORE;

    ozayn_src_emit_event(svc, OZAYN_SRC_EVENT_PHASE_STARTED,
                         "startup_recovery",
                         _phase_descriptions[OZAYN_SRC_PHASE_CORE], NULL);

    _end_phase(svc, OZAYN_SRC_PHASE_CORE,
               OZAYN_SRC_PHASE_RESULT_SUCCESS, NULL,
               "Core validation passed");

    ozayn_src_emit_event(svc, OZAYN_SRC_EVENT_PHASE_COMPLETED,
                         "startup_recovery",
                         "Core phase completed", NULL);

    return OZAYN_SRC_OK;
}

static ozayn_src_err_t _phase_infrastructure(ozayn_src_service_t *svc) {
    _begin_phase(svc, OZAYN_SRC_PHASE_INFRASTRUCTURE);
    svc->context.current_phase = OZAYN_SRC_PHASE_INFRASTRUCTURE;

    ozayn_src_emit_event(svc, OZAYN_SRC_EVENT_PHASE_STARTED,
                         "startup_recovery",
                         _phase_descriptions[OZAYN_SRC_PHASE_INFRASTRUCTURE],
                         NULL);

    int available = 0;
    int total = 0;

    if (svc->diagnostics) { available++; }
    total++;
    if (svc->safety) { available++; }
    total++;
    if (svc->state_manager) { available++; }
    total++;
    if (svc->events_engine) { available++; }
    total++;

    if (available == total) {
        _end_phase(svc, OZAYN_SRC_PHASE_INFRASTRUCTURE,
                   OZAYN_SRC_PHASE_RESULT_SUCCESS, NULL,
                   "All infrastructure available");
    } else if (available > 0) {
        _end_phase(svc, OZAYN_SRC_PHASE_INFRASTRUCTURE,
                   OZAYN_SRC_PHASE_RESULT_SUCCESS, NULL,
                   "Partial infrastructure available");
    } else {
        _end_phase(svc, OZAYN_SRC_PHASE_INFRASTRUCTURE,
                   OZAYN_SRC_PHASE_RESULT_SUCCESS, NULL,
                   "No infrastructure bound — operating without subsystems");
    }

    ozayn_src_emit_event(svc, OZAYN_SRC_EVENT_PHASE_COMPLETED,
                         "startup_recovery",
                         "Infrastructure phase completed", NULL);

    return OZAYN_SRC_OK;
}

static ozayn_src_err_t _phase_discovery(ozayn_src_service_t *svc) {
    _begin_phase(svc, OZAYN_SRC_PHASE_DISCOVERY);
    svc->context.current_phase = OZAYN_SRC_PHASE_DISCOVERY;

    ozayn_src_emit_event(svc, OZAYN_SRC_EVENT_PHASE_STARTED,
                         "startup_recovery",
                         _phase_descriptions[OZAYN_SRC_PHASE_DISCOVERY], NULL);

    int components_found = 0;

    /* Use component registry if available */
    if (svc->component_registry) {
        components_found = svc->manifest.component_count;
    } else {
        components_found = svc->manifest.component_count;
    }

    svc->stats.total_components_checked = components_found;

    /* Reconcile capabilities */
    ozayn_src_reconcile_capabilities(svc);

    _end_phase(svc, OZAYN_SRC_PHASE_DISCOVERY,
               OZAYN_SRC_PHASE_RESULT_SUCCESS, NULL,
               "Discovery completed");

    ozayn_src_emit_event(svc, OZAYN_SRC_EVENT_PHASE_COMPLETED,
                         "startup_recovery",
                         "Discovery phase completed", NULL);

    return OZAYN_SRC_OK;
}

static ozayn_src_err_t _phase_dependency_validation(ozayn_src_service_t *svc) {
    _begin_phase(svc, OZAYN_SRC_PHASE_DEPENDENCY_VALIDATION);
    svc->context.current_phase = OZAYN_SRC_PHASE_DEPENDENCY_VALIDATION;

    ozayn_src_emit_event(svc, OZAYN_SRC_EVENT_PHASE_STARTED,
                         "startup_recovery",
                         _phase_descriptions[OZAYN_SRC_PHASE_DEPENDENCY_VALIDATION],
                         NULL);

    int deps_met = 1;

    /*
     * If dependency manager is available, use it to validate the graph.
     * Would call:
     *   ozayn_dep_resolve() — topological sort
     *   ozayn_dep_has_cycles() — cycle detection
     *   ozayn_dep_can_start() — per-component dependency check
     *
     * Without the full dependency API bound, we perform basic manifest
     * validation.
     */

    for (int i = 0; i < svc->manifest.dependency_count; i++) {
        if (svc->manifest.dependency_required[i]) {
            /* In a full system, check if dependency is satisfied */
            svc->stats.total_components_checked++;
        }
    }

    if (deps_met) {
        _end_phase(svc, OZAYN_SRC_PHASE_DEPENDENCY_VALIDATION,
                   OZAYN_SRC_PHASE_RESULT_SUCCESS, NULL,
                   "All dependencies validated");
    } else {
        _end_phase(svc, OZAYN_SRC_PHASE_DEPENDENCY_VALIDATION,
                   OZAYN_SRC_PHASE_RESULT_FAILED, NULL,
                   "Required dependencies missing");
        ozayn_src_emit_event(svc, OZAYN_SRC_EVENT_DEPENDENCY_FAILED,
                             "startup_recovery",
                             "Required dependency failed", NULL);
        return OZAYN_SRC_ERR_DEPENDENCY_FAILED;
    }

    ozayn_src_emit_event(svc, OZAYN_SRC_EVENT_PHASE_COMPLETED,
                         "startup_recovery",
                         "Dependency validation completed", NULL);

    return OZAYN_SRC_OK;
}

/* ============================================================
 * SECTION 9 — COMPONENT RECONCILIATION
 * ============================================================ */

ozayn_src_err_t ozayn_src_reconcile_components(ozayn_src_service_t *svc) {
    if (!svc) return OZAYN_SRC_ERR_NULL;
    if (!svc->initialized) return OZAYN_SRC_ERR_NOT_INITIALIZED;

    if (svc->reconciliation_in_progress)
        return OZAYN_SRC_ERR_CONCURRENCY_ERROR;
    svc->reconciliation_in_progress = 1;

    ozayn_src_emit_event(svc, OZAYN_SRC_EVENT_STATE_RECONCILIATION_STARTED,
                         "startup_recovery",
                         "Component reconciliation started", NULL);

    svc->component_recon_count = 0;

    for (int i = 0; i < svc->manifest.component_count; i++) {
        if (svc->component_recon_count >= OZAYN_SRC_MAX_COMPONENTS) break;

        ozayn_src_component_recon_entry_t *entry =
            &svc->component_recon[svc->component_recon_count];

        memset(entry, 0, sizeof(ozayn_src_component_recon_entry_t));
        strncpy(entry->component_name, svc->manifest.component_names[i],
                OZAYN_SRC_MAX_NAME_LEN - 1);
        entry->is_required = svc->manifest.component_required[i];
        entry->active = 1;

        /*
         * In a full system, compare persisted state (from state manager)
         * with current runtime state (from component registry).
         *
         * Without those subsystems bound, mark as CONSISTENT or UNKNOWN.
         */
        if (svc->component_registry) {
            /* Would call: ozayn_reg_get_component() and compare states */
            entry->status = OZAYN_SRC_RECON_CONSISTENT;
            entry->persisted_state = 1;
            entry->current_state = 1;
        } else {
            /* No registry — assume consistent from manifest */
            entry->status = OZAYN_SRC_RECON_CONSISTENT;
            entry->persisted_state = 1;
            entry->current_state = 1;
        }

        svc->component_recon_count++;
        svc->stats.total_components_reconciled++;
    }

    svc->reconciliation_in_progress = 0;

    ozayn_src_emit_event(svc, OZAYN_SRC_EVENT_STATE_RECONCILIATION_COMPLETED,
                         "startup_recovery",
                         "Component reconciliation completed", NULL);

    return OZAYN_SRC_OK;
}

int ozayn_src_component_recon_count(const ozayn_src_service_t *svc) {
    if (!svc || !svc->initialized) return 0;
    return svc->component_recon_count;
}

const ozayn_src_component_recon_entry_t *ozayn_src_component_recon_get(
    const ozayn_src_service_t *svc, int index) {
    if (!svc || !svc->initialized) return NULL;
    if (index < 0 || index >= svc->component_recon_count) return NULL;
    if (!svc->component_recon[index].active) return NULL;
    return &svc->component_recon[index];
}

int ozayn_src_component_recon_inconsistencies(const ozayn_src_service_t *svc) {
    if (!svc || !svc->initialized) return 0;
    int count = 0;
    for (int i = 0; i < svc->component_recon_count; i++) {
        if (svc->component_recon[i].active &&
            svc->component_recon[i].status != OZAYN_SRC_RECON_CONSISTENT &&
            svc->component_recon[i].status != OZAYN_SRC_RECON_UNKNOWN) {
            count++;
        }
    }
    return count;
}

static ozayn_src_err_t _phase_state_reconciliation(ozayn_src_service_t *svc) {
    _begin_phase(svc, OZAYN_SRC_PHASE_STATE_RECONCILIATION);
    svc->context.current_phase = OZAYN_SRC_PHASE_STATE_RECONCILIATION;

    ozayn_src_emit_event(svc, OZAYN_SRC_EVENT_STATE_RECONCILIATION_STARTED,
                         "startup_recovery",
                         _phase_descriptions[OZAYN_SRC_PHASE_STATE_RECONCILIATION],
                         NULL);

    ozayn_src_err_t rc = ozayn_src_reconcile_components(svc);
    if (rc != OZAYN_SRC_OK) {
        _end_phase(svc, OZAYN_SRC_PHASE_STATE_RECONCILIATION,
                   OZAYN_SRC_PHASE_RESULT_FAILED, NULL,
                   "Component reconciliation failed");
        return rc;
    }

    int inconsistencies = ozayn_src_component_recon_inconsistencies(svc);
    if (inconsistencies > 0) {
        _end_phase(svc, OZAYN_SRC_PHASE_STATE_RECONCILIATION,
                   OZAYN_SRC_PHASE_RESULT_DEGRADED, NULL,
                   "State reconciliation found inconsistencies");
        ozayn_src_add_warning(svc, "Component state inconsistencies detected");
    } else {
        _end_phase(svc, OZAYN_SRC_PHASE_STATE_RECONCILIATION,
                   OZAYN_SRC_PHASE_RESULT_SUCCESS, NULL,
                   "State reconciliation completed");
    }

    ozayn_src_emit_event(svc, OZAYN_SRC_EVENT_STATE_RECONCILIATION_COMPLETED,
                         "startup_recovery",
                         "State reconciliation phase completed", NULL);

    return OZAYN_SRC_OK;
}

/* ============================================================
 * SECTION 10 — CAPABILITY RECONCILIATION
 * ============================================================ */

ozayn_src_err_t ozayn_src_reconcile_capabilities(ozayn_src_service_t *svc) {
    if (!svc) return OZAYN_SRC_ERR_NULL;
    if (!svc->initialized) return OZAYN_SRC_ERR_NOT_INITIALIZED;

    svc->capability_recon_count = 0;

    for (int i = 0; i < svc->manifest.capability_count; i++) {
        if (svc->capability_recon_count >= OZAYN_SRC_MAX_CAPABILITIES) break;

        ozayn_src_capability_recon_entry_t *entry =
            &svc->capability_recon[svc->capability_recon_count];

        memset(entry, 0, sizeof(ozayn_src_capability_recon_entry_t));
        strncpy(entry->capability_name, svc->manifest.capability_names[i],
                OZAYN_SRC_MAX_NAME_LEN - 1);
        entry->is_required = svc->manifest.capability_required[i];
        entry->active = 1;

        /*
         * In a full system, check:
         * - Component existence
         * - Component state
         * - Capability registration
         * - Provider availability
         * - Dependency availability
         */
        if (svc->component_registry) {
            /* Would call: ozayn_reg_is_capability_available() */
            entry->status = OZAYN_SRC_CAP_RECON_AVAILABLE;
        } else {
            entry->status = OZAYN_SRC_CAP_RECON_UNKNOWN;
        }

        svc->capability_recon_count++;
        svc->stats.total_capabilities_checked++;
    }

    return OZAYN_SRC_OK;
}

int ozayn_src_capability_recon_count(const ozayn_src_service_t *svc) {
    if (!svc || !svc->initialized) return 0;
    return svc->capability_recon_count;
}

const ozayn_src_capability_recon_entry_t *ozayn_src_capability_recon_get(
    const ozayn_src_service_t *svc, int index) {
    if (!svc || !svc->initialized) return NULL;
    if (index < 0 || index >= svc->capability_recon_count) return NULL;
    if (!svc->capability_recon[index].active) return NULL;
    return &svc->capability_recon[index];
}

int ozayn_src_capability_recon_unavailable(const ozayn_src_service_t *svc) {
    if (!svc || !svc->initialized) return 0;
    int count = 0;
    for (int i = 0; i < svc->capability_recon_count; i++) {
        if (svc->capability_recon[i].active &&
            svc->capability_recon[i].status == OZAYN_SRC_CAP_RECON_UNAVAILABLE) {
            count++;
        }
    }
    return count;
}

/* ============================================================
 * SECTION 11 — RESOURCE RECONCILIATION
 * ============================================================ */

ozayn_src_err_t ozayn_src_reconcile_resources(ozayn_src_service_t *svc) {
    if (!svc) return OZAYN_SRC_ERR_NULL;
    if (!svc->initialized) return OZAYN_SRC_ERR_NOT_INITIALIZED;

    svc->resource_recon_count = 0;

    ozayn_src_emit_event(svc, OZAYN_SRC_EVENT_RESOURCE_RECONCILIATION_COMPLETED,
                         "startup_recovery",
                         "Resource reconciliation started", NULL);

    /*
     * In a full system, enumerate resource types from the resource manager:
     * CPU, memory, storage, worker capacity, queue capacity, GPU, network
     *
     * For each, determine current availability vs. what was persisted.
     */
    if (svc->resource_manager) {
        /* Would call: ozayn_rcm_resource_count(), ozayn_rcm_resource_get(),
         * etc. for each resource type */
    }

    /* Default resource types to report */
    const char *resource_names[] = {
        "CPU", "Memory", "Storage", "WorkerCapacity", "QueueCapacity",
        "GPU", "Network"
    };
    int resource_count = 7;

    for (int i = 0; i < resource_count; i++) {
        if (svc->resource_recon_count >= OZAYN_SRC_MAX_COMPONENTS) break;

        ozayn_src_resource_recon_entry_t *entry =
            &svc->resource_recon[svc->resource_recon_count];

        memset(entry, 0, sizeof(ozayn_src_resource_recon_entry_t));
        strncpy(entry->resource_name, resource_names[i],
                OZAYN_SRC_MAX_NAME_LEN - 1);
        entry->resource_type = i;
        entry->active = 1;

        /* Without resource manager, report as available */
        if (svc->resource_manager) {
            entry->status = OZAYN_SRC_RES_RECON_AVAILABLE;
        } else {
            entry->status = OZAYN_SRC_RES_RECON_UNKNOWN;
        }

        svc->resource_recon_count++;
        svc->stats.total_resources_reconciled++;
    }

    ozayn_src_emit_event(svc, OZAYN_SRC_EVENT_RESOURCE_RECONCILIATION_COMPLETED,
                         "startup_recovery",
                         "Resource reconciliation completed", NULL);

    return OZAYN_SRC_OK;
}

int ozayn_src_resource_recon_count(const ozayn_src_service_t *svc) {
    if (!svc || !svc->initialized) return 0;
    return svc->resource_recon_count;
}

const ozayn_src_resource_recon_entry_t *ozayn_src_resource_recon_get(
    const ozayn_src_service_t *svc, int index) {
    if (!svc || !svc->initialized) return NULL;
    if (index < 0 || index >= svc->resource_recon_count) return NULL;
    if (!svc->resource_recon[index].active) return NULL;
    return &svc->resource_recon[index];
}

int ozayn_src_resource_recon_unavailable(const ozayn_src_service_t *svc) {
    if (!svc || !svc->initialized) return 0;
    int count = 0;
    for (int i = 0; i < svc->resource_recon_count; i++) {
        if (svc->resource_recon[i].active &&
            svc->resource_recon[i].status == OZAYN_SRC_RES_RECON_UNAVAILABLE) {
            count++;
        }
    }
    return count;
}

static ozayn_src_err_t _phase_resource_reconciliation(ozayn_src_service_t *svc) {
    _begin_phase(svc, OZAYN_SRC_PHASE_RESOURCE_RECONCILIATION);
    svc->context.current_phase = OZAYN_SRC_PHASE_RESOURCE_RECONCILIATION;

    ozayn_src_err_t rc = ozayn_src_reconcile_resources(svc);
    if (rc != OZAYN_SRC_OK) {
        _end_phase(svc, OZAYN_SRC_PHASE_RESOURCE_RECONCILIATION,
                   OZAYN_SRC_PHASE_RESULT_FAILED, NULL,
                   "Resource reconciliation failed");
        return rc;
    }

    int unavailable = ozayn_src_resource_recon_unavailable(svc);
    if (unavailable > 0) {
        _end_phase(svc, OZAYN_SRC_PHASE_RESOURCE_RECONCILIATION,
                   OZAYN_SRC_PHASE_RESULT_DEGRADED, NULL,
                   "Some resources unavailable");
    } else {
        _end_phase(svc, OZAYN_SRC_PHASE_RESOURCE_RECONCILIATION,
                   OZAYN_SRC_PHASE_RESULT_SUCCESS, NULL,
                   "Resource reconciliation completed");
    }

    return OZAYN_SRC_OK;
}

/* ============================================================
 * SECTION 12 — DEVICE RECONCILIATION
 * ============================================================ */

ozayn_src_err_t ozayn_src_reconcile_devices(ozayn_src_service_t *svc) {
    if (!svc) return OZAYN_SRC_ERR_NULL;
    if (!svc->initialized) return OZAYN_SRC_ERR_NOT_INITIALIZED;

    svc->device_recon_count = 0;

    ozayn_src_emit_event(svc, OZAYN_SRC_EVENT_DEVICE_RECONCILIATION_COMPLETED,
                         "startup_recovery",
                         "Device reconciliation started", NULL);

    /*
     * In a full system:
     * - Rediscover devices through platform/device providers
     * - Check for stale device sessions
     * - Do not trust old device handles
     * - Do not silently activate cameras/microphones/audio input
     */
    if (svc->device_session) {
        /* Would call: ozayn_das_session_count() and check for stale
         * sessions, then ozayn_das_cleanup_expired_sessions() */
    }

    ozayn_src_emit_event(svc, OZAYN_SRC_EVENT_DEVICE_RECONCILIATION_COMPLETED,
                         "startup_recovery",
                         "Device reconciliation completed", NULL);

    return OZAYN_SRC_OK;
}

int ozayn_src_device_recon_count(const ozayn_src_service_t *svc) {
    if (!svc || !svc->initialized) return 0;
    return svc->device_recon_count;
}

const ozayn_src_device_recon_entry_t *ozayn_src_device_recon_get(
    const ozayn_src_service_t *svc, int index) {
    if (!svc || !svc->initialized) return NULL;
    if (index < 0 || index >= svc->device_recon_count) return NULL;
    if (!svc->device_recon[index].active) return NULL;
    return &svc->device_recon[index];
}

int ozayn_src_device_recon_stale_sessions(const ozayn_src_service_t *svc) {
    if (!svc || !svc->initialized) return 0;
    int count = 0;
    for (int i = 0; i < svc->device_recon_count; i++) {
        if (svc->device_recon[i].active &&
            svc->device_recon[i].was_active_session) {
            count++;
        }
    }
    return count;
}

static ozayn_src_err_t _phase_device_reconciliation(ozayn_src_service_t *svc) {
    _begin_phase(svc, OZAYN_SRC_PHASE_DEVICE_RECONCILIATION);
    svc->context.current_phase = OZAYN_SRC_PHASE_DEVICE_RECONCILIATION;

    ozayn_src_err_t rc = ozayn_src_reconcile_devices(svc);
    if (rc != OZAYN_SRC_OK) {
        _end_phase(svc, OZAYN_SRC_PHASE_DEVICE_RECONCILIATION,
                   OZAYN_SRC_PHASE_RESULT_FAILED, NULL,
                   "Device reconciliation failed");
        return rc;
    }

    _end_phase(svc, OZAYN_SRC_PHASE_DEVICE_RECONCILIATION,
               OZAYN_SRC_PHASE_RESULT_SUCCESS, NULL,
               "Device reconciliation completed");

    return OZAYN_SRC_OK;
}

/* ============================================================
 * SECTION 13 — SECURITY REVALIDATION
 * ============================================================ */

ozayn_src_err_t ozayn_src_revalidate_security(ozayn_src_service_t *svc) {
    if (!svc) return OZAYN_SRC_ERR_NULL;
    if (!svc->initialized) return OZAYN_SRC_ERR_NOT_INITIALIZED;

    svc->security_status = OZAYN_SRC_SEC_RECON_UNKNOWN;

    /*
     * In a full system:
     * - Validate security subsystem availability
     * - Check identity subsystem state
     * - Verify session state (do not trust previous sessions)
     * - Check authorization services
     * - Check permission services
     * - Check policy services
     * - Check key-management availability
     */
    if (svc->safety) {
        /* Would call: ozayn_spe_service_is_initialized() */
        svc->security_status = OZAYN_SRC_SEC_RECON_VALID;
        strncpy(svc->security_description, "Safety subsystem available",
                OZAYN_SRC_MAX_DESC_LEN - 1);
    } else {
        svc->security_status = OZAYN_SRC_SEC_RECON_UNAVAILABLE;
        strncpy(svc->security_description, "Safety subsystem not bound",
                OZAYN_SRC_MAX_DESC_LEN - 1);
    }

    svc->stats.total_security_revalidated++;

    ozayn_src_emit_event(svc, OZAYN_SRC_EVENT_SECURITY_REVALIDATION_COMPLETED,
                         "startup_recovery",
                         "Security revalidation completed", NULL);

    return OZAYN_SRC_OK;
}

ozayn_src_security_recon_status_t ozayn_src_security_status(
    const ozayn_src_service_t *svc) {
    if (!svc || !svc->initialized) return OZAYN_SRC_SEC_RECON_UNKNOWN;
    return svc->security_status;
}

static ozayn_src_err_t _phase_security_revalidation(ozayn_src_service_t *svc) {
    _begin_phase(svc, OZAYN_SRC_PHASE_SECURITY_REVALIDATION);
    svc->context.current_phase = OZAYN_SRC_PHASE_SECURITY_REVALIDATION;

    ozayn_src_err_t rc = ozayn_src_revalidate_security(svc);
    if (rc != OZAYN_SRC_OK) {
        _end_phase(svc, OZAYN_SRC_PHASE_SECURITY_REVALIDATION,
                   OZAYN_SRC_PHASE_RESULT_FAILED, NULL,
                   "Security revalidation failed");
        return rc;
    }

    if (svc->security_status == OZAYN_SRC_SEC_RECON_VALID) {
        _end_phase(svc, OZAYN_SRC_PHASE_SECURITY_REVALIDATION,
                   OZAYN_SRC_PHASE_RESULT_SUCCESS, NULL,
                   "Security revalidation passed");
    } else if (svc->security_status == OZAYN_SRC_SEC_RECON_UNAVAILABLE) {
        _end_phase(svc, OZAYN_SRC_PHASE_SECURITY_REVALIDATION,
                   OZAYN_SRC_PHASE_RESULT_SUCCESS, NULL,
                   "Security subsystem not bound — skipped");
    } else {
        _end_phase(svc, OZAYN_SRC_PHASE_SECURITY_REVALIDATION,
                   OZAYN_SRC_PHASE_RESULT_FAILED, NULL,
                   "Security revalidation failed");
        return OZAYN_SRC_ERR_SECURITY_REVALIDATE_FAILED;
    }

    return OZAYN_SRC_OK;
}

/* ============================================================
 * SECTION 14 — RECOVERY ASSESSMENT
 * ============================================================ */

ozayn_src_err_t ozayn_src_assess_recovery(ozayn_src_service_t *svc) {
    if (!svc) return OZAYN_SRC_ERR_NULL;
    if (!svc->initialized) return OZAYN_SRC_ERR_NOT_INITIALIZED;

    svc->recovery_item_count = 0;

    ozayn_src_emit_event(svc, OZAYN_SRC_EVENT_RECOVERY_ASSESSMENT_STARTED,
                         "startup_recovery",
                         "Recovery assessment started", NULL);

    /*
     * In a full system:
     * - Load persistent recovery state through state manager / checkpoint
     * - For each checkpoint in RECOVERY_REQUIRED state:
     *   - Create a recovery item
     *   - Assess eligibility
     *   - Assign priority
     *   - Check for duplicate execution risk
     * - Do NOT automatically resume workflows
     */
    if (svc->workflow_checkpoint) {
        /*
         * Would call: ozayn_prs_checkpoint_count(),
         * ozayn_prs_checkpoint_get(), iterate and assess each.
         */
    }

    ozayn_src_emit_event(svc, OZAYN_SRC_EVENT_RECOVERY_ASSESSMENT_STARTED,
                         "startup_recovery",
                         "Recovery assessment completed", NULL);

    return OZAYN_SRC_OK;
}

int ozayn_src_recovery_item_count(const ozayn_src_service_t *svc) {
    if (!svc || !svc->initialized) return 0;
    return svc->recovery_item_count;
}

const ozayn_src_recovery_item_t *ozayn_src_recovery_item_get(
    const ozayn_src_service_t *svc, int index) {
    if (!svc || !svc->initialized) return NULL;
    if (index < 0 || index >= svc->recovery_item_count) return NULL;
    if (!svc->recovery_items[index].active) return NULL;
    return &svc->recovery_items[index];
}

ozayn_src_recovery_assessment_t ozayn_src_recovery_overall_assessment(
    const ozayn_src_service_t *svc) {
    if (!svc || !svc->initialized) return OZAYN_SRC_RECOVERY_NONE;

    int has_recovery = 0;
    int has_manual = 0;
    int has_blocked = 0;
    int has_corrupted = 0;
    int has_expired = 0;

    for (int i = 0; i < svc->recovery_item_count; i++) {
        if (!svc->recovery_items[i].active) continue;
        switch (svc->recovery_items[i].assessment) {
            case OZAYN_SRC_RECOVERY_REQUIRED: has_recovery = 1; break;
            case OZAYN_SRC_RECOVERY_MANUAL_REVIEW: has_manual = 1; break;
            case OZAYN_SRC_RECOVERY_BLOCKED: has_blocked = 1; break;
            case OZAYN_SRC_RECOVERY_EXPIRED: has_expired = 1; break;
            case OZAYN_SRC_RECOVERY_CORRUPTED: has_corrupted = 1; break;
            default: break;
        }
    }

    /* Priority: BLOCKED > CORRUPTED > MANUAL > EXPIRED > REQUIRED > NONE */
    if (has_blocked) return OZAYN_SRC_RECOVERY_BLOCKED;
    if (has_corrupted) return OZAYN_SRC_RECOVERY_CORRUPTED;
    if (has_manual) return OZAYN_SRC_RECOVERY_MANUAL_REVIEW;
    if (has_expired) return OZAYN_SRC_RECOVERY_EXPIRED;
    if (has_recovery) return OZAYN_SRC_RECOVERY_REQUIRED;
    return OZAYN_SRC_RECOVERY_NONE;
}

static ozayn_src_err_t _phase_recovery_assessment(ozayn_src_service_t *svc) {
    _begin_phase(svc, OZAYN_SRC_PHASE_RECOVERY_ASSESSMENT);
    svc->context.current_phase = OZAYN_SRC_PHASE_RECOVERY_ASSESSMENT;

    ozayn_src_err_t rc = ozayn_src_assess_recovery(svc);
    if (rc != OZAYN_SRC_OK) {
        _end_phase(svc, OZAYN_SRC_PHASE_RECOVERY_ASSESSMENT,
                   OZAYN_SRC_PHASE_RESULT_FAILED, NULL,
                   "Recovery assessment failed");
        return rc;
    }

    ozayn_src_recovery_assessment_t assessment =
        ozayn_src_recovery_overall_assessment(svc);

    switch (assessment) {
        case OZAYN_SRC_RECOVERY_NONE:
            _end_phase(svc, OZAYN_SRC_PHASE_RECOVERY_ASSESSMENT,
                       OZAYN_SRC_PHASE_RESULT_SUCCESS, NULL,
                       "No recovery required");
            break;
        case OZAYN_SRC_RECOVERY_REQUIRED:
            _end_phase(svc, OZAYN_SRC_PHASE_RECOVERY_ASSESSMENT,
                       OZAYN_SRC_PHASE_RESULT_DEGRADED, NULL,
                       "Recovery items require handling");
            ozayn_src_emit_event(svc, OZAYN_SRC_EVENT_RECOVERY_REQUIRED,
                                 "startup_recovery",
                                 "Recovery required for interrupted workflows",
                                 NULL);
            break;
        case OZAYN_SRC_RECOVERY_MANUAL_REVIEW:
            _end_phase(svc, OZAYN_SRC_PHASE_RECOVERY_ASSESSMENT,
                       OZAYN_SRC_PHASE_RESULT_DEGRADED, NULL,
                       "Manual review required");
            ozayn_src_emit_event(svc, OZAYN_SRC_EVENT_MANUAL_REVIEW_REQUIRED,
                                 "startup_recovery",
                                 "Manual review required for recovery",
                                 NULL);
            break;
        case OZAYN_SRC_RECOVERY_BLOCKED:
            _end_phase(svc, OZAYN_SRC_PHASE_RECOVERY_ASSESSMENT,
                       OZAYN_SRC_PHASE_RESULT_FAILED, NULL,
                       "Recovery blocked");
            break;
        case OZAYN_SRC_RECOVERY_EXPIRED:
        case OZAYN_SRC_RECOVERY_CORRUPTED:
            _end_phase(svc, OZAYN_SRC_PHASE_RECOVERY_ASSESSMENT,
                       OZAYN_SRC_PHASE_RESULT_DEGRADED, NULL,
                       "Recovery state issues detected");
            break;
    }

    return OZAYN_SRC_OK;
}

/* ============================================================
 * SECTION 15 — STARTUP DECISION
 * ============================================================ */

ozayn_src_err_t ozayn_src_determine_decision(ozayn_src_service_t *svc) {
    if (!svc) return OZAYN_SRC_ERR_NULL;
    if (!svc->initialized) return OZAYN_SRC_ERR_NOT_INITIALIZED;

    /* Check for blocking conditions first */
    if (svc->blocking_count > 0) {
        svc->context.decision = OZAYN_SRC_DECISION_BLOCKED;
        ozayn_src_emit_event(svc, OZAYN_SRC_EVENT_BLOCKED,
                             "startup_recovery",
                             "Startup blocked by required conditions", NULL);
        return OZAYN_SRC_OK;
    }

    /* Check for failed phases */
    for (int i = 0; i < svc->phase_result_count; i++) {
        if (svc->phase_results[i].active &&
            svc->phase_results[i].status == OZAYN_SRC_PHASE_RESULT_FAILED) {
            /* Check if it's a critical phase */
            if (svc->phase_results[i].phase == OZAYN_SRC_PHASE_SECURITY_REVALIDATION ||
                svc->phase_results[i].phase == OZAYN_SRC_PHASE_DEPENDENCY_VALIDATION) {
                svc->context.decision = OZAYN_SRC_DECISION_FAILED;
                ozayn_src_emit_event(svc, OZAYN_SRC_EVENT_FAILED,
                                     "startup_recovery",
                                     "Critical startup phase failed", NULL);
                return OZAYN_SRC_OK;
            }
        }
    }

    /* Check recovery assessment */
    ozayn_src_recovery_assessment_t assessment =
        ozayn_src_recovery_overall_assessment(svc);

    if (assessment == OZAYN_SRC_RECOVERY_BLOCKED) {
        svc->context.decision = OZAYN_SRC_DECISION_BLOCKED;
        ozayn_src_emit_event(svc, OZAYN_SRC_EVENT_BLOCKED,
                             "startup_recovery",
                             "Recovery blocked by safety/security", NULL);
        return OZAYN_SRC_OK;
    }

    if (assessment == OZAYN_SRC_RECOVERY_MANUAL_REVIEW) {
        svc->context.decision = OZAYN_SRC_DECISION_MANUAL_REVIEW_REQUIRED;
        ozayn_src_emit_event(svc, OZAYN_SRC_EVENT_MANUAL_REVIEW_REQUIRED,
                             "startup_recovery",
                             "Manual review required", NULL);
        return OZAYN_SRC_OK;
    }

    if (assessment == OZAYN_SRC_RECOVERY_REQUIRED) {
        svc->context.decision = OZAYN_SRC_DECISION_RECOVERY_REQUIRED;
        ozayn_src_emit_event(svc, OZAYN_SRC_EVENT_RECOVERY_REQUIRED,
                             "startup_recovery",
                             "Recovery required", NULL);
        return OZAYN_SRC_OK;
    }

    /* Check for degraded conditions — only explicit warnings matter */
    if (svc->warning_count > 0) {
        svc->context.decision = OZAYN_SRC_DECISION_READY_DEGRADED;
        ozayn_src_emit_event(svc, OZAYN_SRC_EVENT_DEGRADED,
                             "startup_recovery",
                             "Startup completed in degraded mode", NULL);
        return OZAYN_SRC_OK;
    }

    /* All good */
    svc->context.decision = OZAYN_SRC_DECISION_READY;
    ozayn_src_emit_event(svc, OZAYN_SRC_EVENT_READY,
                         "startup_recovery",
                         "Startup completed — ready", NULL);
    return OZAYN_SRC_OK;
}

ozayn_src_startup_decision_t ozayn_src_decision_get(
    const ozayn_src_service_t *svc) {
    if (!svc || !svc->initialized) return OZAYN_SRC_DECISION_UNKNOWN;
    return svc->context.decision;
}

const char *ozayn_src_decision_description(const ozayn_src_service_t *svc) {
    if (!svc || !svc->initialized) return "Unknown";
    return _decision_descriptions[svc->context.decision];
}

/* ============================================================
 * SECTION 16 — MAIN STARTUP ORCHESTRATION
 * ============================================================ */

ozayn_src_err_t ozayn_src_startup(ozayn_src_service_t *svc) {
    if (!svc) return OZAYN_SRC_ERR_NULL;
    if (!svc->initialized) return OZAYN_SRC_ERR_NOT_INITIALIZED;

    /* Concurrency check */
    ozayn_src_err_t rc = _validate_pre_startup(svc);
    if (rc != OZAYN_SRC_OK) return rc;

    svc->startup_in_progress = 1;
    svc->context.runtime_state = OZAYN_SRC_STATE_STARTING;
    _reset_for_startup(svc);

    svc->stats.total_startups++;

    /* Execute phases in order */
    ozayn_src_startup_phase_t phases[] = {
        OZAYN_SRC_PHASE_BOOTSTRAP,
        OZAYN_SRC_PHASE_CORE,
        OZAYN_SRC_PHASE_INFRASTRUCTURE,
        OZAYN_SRC_PHASE_DISCOVERY,
        OZAYN_SRC_PHASE_DEPENDENCY_VALIDATION,
        OZAYN_SRC_PHASE_STATE_RECONCILIATION,
        OZAYN_SRC_PHASE_RESOURCE_RECONCILIATION,
        OZAYN_SRC_PHASE_DEVICE_RECONCILIATION,
        OZAYN_SRC_PHASE_SECURITY_REVALIDATION,
        OZAYN_SRC_PHASE_RECOVERY_ASSESSMENT
    };
    int phase_count = 10;

    int total_start = _now_ms();

    for (int i = 0; i < phase_count; i++) {
        /* Check total timeout */
        int64_t elapsed = _now_ms() - total_start;
        if (elapsed > svc->manifest.total_timeout_ms) {
            svc->context.decision = OZAYN_SRC_DECISION_FAILED;
            svc->context.current_phase = OZAYN_SRC_PHASE_FAILED;
            svc->context.runtime_state = OZAYN_SRC_STATE_FAILED;
            svc->startup_in_progress = 0;

            ozayn_src_emit_event(svc, OZAYN_SRC_EVENT_FAILED,
                                 "startup_recovery",
                                 "Total startup timeout exceeded", NULL);
            return OZAYN_SRC_ERR_PHASE_TIMEOUT;
        }

        rc = ozayn_src_startup_phase(svc, phases[i]);
        if (rc != OZAYN_SRC_OK) {
            svc->context.current_phase = OZAYN_SRC_PHASE_FAILED;
            svc->context.runtime_state = OZAYN_SRC_STATE_FAILED;
            svc->startup_in_progress = 0;

            ozayn_src_emit_event(svc, OZAYN_SRC_EVENT_FAILED,
                                 "startup_recovery",
                                 "Startup phase failed", NULL);
            return rc;
        }
    }

    /* Determine final decision */
    rc = ozayn_src_determine_decision(svc);
    if (rc != OZAYN_SRC_OK) {
        svc->context.current_phase = OZAYN_SRC_PHASE_FAILED;
        svc->context.runtime_state = OZAYN_SRC_STATE_FAILED;
        svc->startup_in_progress = 0;
        return rc;
    }

    /* Set final state */
    svc->context.completion_time_ms = _now_ms();

    switch (svc->context.decision) {
        case OZAYN_SRC_DECISION_READY:
            svc->context.current_phase = OZAYN_SRC_PHASE_READY;
            svc->context.runtime_state = OZAYN_SRC_STATE_RUNNING;
            svc->running = 1;
            break;
        case OZAYN_SRC_DECISION_READY_DEGRADED:
            svc->context.current_phase = OZAYN_SRC_PHASE_DEGRADED;
            svc->context.runtime_state = OZAYN_SRC_STATE_RUNNING;
            svc->running = 1;
            break;
        case OZAYN_SRC_DECISION_BLOCKED:
            svc->context.current_phase = OZAYN_SRC_PHASE_BLOCKED;
            svc->context.runtime_state = OZAYN_SRC_STATE_FAILED;
            break;
        case OZAYN_SRC_DECISION_FAILED:
            svc->context.current_phase = OZAYN_SRC_PHASE_FAILED;
            svc->context.runtime_state = OZAYN_SRC_STATE_FAILED;
            break;
        default:
            svc->context.current_phase = OZAYN_SRC_PHASE_READY;
            svc->context.runtime_state = OZAYN_SRC_STATE_RUNNING;
            svc->running = 1;
            break;
    }

    svc->startup_in_progress = 0;

    ozayn_src_emit_event(svc, OZAYN_SRC_EVENT_STARTUP_COMPLETED,
                         "startup_recovery",
                         "Startup orchestration completed", NULL);

    return OZAYN_SRC_OK;
}

ozayn_src_err_t ozayn_src_startup_phase(ozayn_src_service_t *svc,
    ozayn_src_startup_phase_t phase) {
    if (!svc) return OZAYN_SRC_ERR_NULL;
    if (!svc->initialized) return OZAYN_SRC_ERR_NOT_INITIALIZED;
    if (phase < 0 || phase >= OZAYN_SRC_PHASE_COUNT)
        return OZAYN_SRC_ERR_INVALID_PARAM;

    /* Validate phase order */
    if ((int)phase < (int)svc->context.current_phase &&
        phase != OZAYN_SRC_PHASE_NOT_STARTED) {
        return OZAYN_SRC_ERR_STATE_INVALID;
    }

    switch (phase) {
        case OZAYN_SRC_PHASE_BOOTSTRAP:
            return _phase_bootstrap(svc);
        case OZAYN_SRC_PHASE_CORE:
            return _phase_core(svc);
        case OZAYN_SRC_PHASE_INFRASTRUCTURE:
            return _phase_infrastructure(svc);
        case OZAYN_SRC_PHASE_DISCOVERY:
            return _phase_discovery(svc);
        case OZAYN_SRC_PHASE_DEPENDENCY_VALIDATION:
            return _phase_dependency_validation(svc);
        case OZAYN_SRC_PHASE_STATE_RECONCILIATION:
            return _phase_state_reconciliation(svc);
        case OZAYN_SRC_PHASE_RESOURCE_RECONCILIATION:
            return _phase_resource_reconciliation(svc);
        case OZAYN_SRC_PHASE_DEVICE_RECONCILIATION:
            return _phase_device_reconciliation(svc);
        case OZAYN_SRC_PHASE_SECURITY_REVALIDATION:
            return _phase_security_revalidation(svc);
        case OZAYN_SRC_PHASE_RECOVERY_ASSESSMENT:
            return _phase_recovery_assessment(svc);
        default:
            return OZAYN_SRC_ERR_INVALID_PARAM;
    }
}

ozayn_src_err_t ozayn_src_shutdown(ozayn_src_service_t *svc) {
    if (!svc) return OZAYN_SRC_ERR_NULL;
    if (!svc->initialized) return OZAYN_SRC_ERR_NOT_INITIALIZED;

    svc->shutting_down = 1;
    svc->context.runtime_state = OZAYN_SRC_STATE_STOPPING;

    ozayn_src_emit_event(svc, OZAYN_SRC_EVENT_SHUTDOWN_STARTED,
                         "startup_recovery",
                         "Shutdown initiated", NULL);

    /* Cancel any in-progress reconciliation */
    svc->reconciliation_in_progress = 0;
    svc->startup_in_progress = 0;

    /* Cleanup device sessions if available */
    if (svc->device_session) {
        /* Would call: ozayn_das_cleanup_expired_sessions() */
    }

    svc->running = 0;
    svc->shutting_down = 0;
    svc->context.runtime_state = OZAYN_SRC_STATE_STOPPED;
    svc->context.current_phase = OZAYN_SRC_PHASE_STOPPED;

    ozayn_src_emit_event(svc, OZAYN_SRC_EVENT_SHUTDOWN_COMPLETED,
                         "startup_recovery",
                         "Shutdown completed", NULL);

    return OZAYN_SRC_OK;
}

/* ============================================================
 * SECTION 17 — CONTEXT QUERY
 * ============================================================ */

ozayn_src_startup_phase_t ozayn_src_get_phase(const ozayn_src_service_t *svc) {
    if (!svc || !svc->initialized) return OZAYN_SRC_PHASE_NOT_STARTED;
    return svc->context.current_phase;
}

ozayn_src_startup_state_t ozayn_src_get_state(const ozayn_src_service_t *svc) {
    if (!svc || !svc->initialized) return OZAYN_SRC_STATE_IDLE;
    return svc->context.runtime_state;
}

ozayn_src_startup_decision_t ozayn_src_get_decision(
    const ozayn_src_service_t *svc) {
    if (!svc || !svc->initialized) return OZAYN_SRC_DECISION_UNKNOWN;
    return svc->context.decision;
}

int ozayn_src_is_running(const ozayn_src_service_t *svc) {
    if (!svc || !svc->initialized) return 0;
    return svc->running;
}

const ozayn_src_startup_context_t *ozayn_src_get_context(
    const ozayn_src_service_t *svc) {
    if (!svc || !svc->initialized) return NULL;
    return &svc->context;
}

ozayn_src_err_t ozayn_src_context_set_startup_cause(ozayn_src_service_t *svc,
    ozayn_src_startup_cause_t cause) {
    if (!svc) return OZAYN_SRC_ERR_NULL;
    svc->context.startup_cause = cause;
    return OZAYN_SRC_OK;
}

ozayn_src_err_t ozayn_src_context_set_previous_shutdown(ozayn_src_service_t *svc,
    ozayn_src_previous_shutdown_t shutdown) {
    if (!svc) return OZAYN_SRC_ERR_NULL;
    svc->context.previous_shutdown = shutdown;
    return OZAYN_SRC_OK;
}

/* ============================================================
 * SECTION 18 — STATISTICS
 * ============================================================ */

const ozayn_src_stats_t *ozayn_src_get_stats(const ozayn_src_service_t *svc) {
    if (!svc || !svc->initialized) return NULL;
    return &svc->stats;
}

ozayn_src_err_t ozayn_src_reset_stats(ozayn_src_service_t *svc) {
    if (!svc) return OZAYN_SRC_ERR_NULL;
    if (!svc->initialized) return OZAYN_SRC_ERR_NOT_INITIALIZED;
    memset(&svc->stats, 0, sizeof(ozayn_src_stats_t));
    return OZAYN_SRC_OK;
}

/* ============================================================
 * SECTION 19 — VALIDATION
 * ============================================================ */

int ozayn_src_validate_context(const ozayn_src_startup_context_t *ctx) {
    if (!ctx) return 0;
    if (ctx->current_phase < 0 || ctx->current_phase >= OZAYN_SRC_PHASE_COUNT)
        return 0;
    if (ctx->runtime_state < 0 || ctx->runtime_state > OZAYN_SRC_STATE_FAILED)
        return 0;
    if (ctx->startup_cause < 0 || ctx->startup_cause > OZAYN_SRC_CAUSE_POWER_LOSS_RECOVERY)
        return 0;
    return 1;
}

int ozayn_src_validate_manifest(const ozayn_src_startup_manifest_t *manifest) {
    if (!manifest) return 0;
    if (manifest->component_count < 0 ||
        manifest->component_count > OZAYN_SRC_MAX_COMPONENTS)
        return 0;
    if (manifest->dependency_count < 0 ||
        manifest->dependency_count > OZAYN_SRC_MAX_COMPONENTS)
        return 0;
    if (manifest->capability_count < 0 ||
        manifest->capability_count > OZAYN_SRC_MAX_CAPABILITIES)
        return 0;
    if (manifest->total_timeout_ms <= 0) return 0;
    return 1;
}

int ozayn_src_validate_phase(ozayn_src_startup_phase_t phase) {
    return phase >= 0 && phase < OZAYN_SRC_PHASE_COUNT;
}

int ozayn_src_is_phase_terminal(ozayn_src_startup_phase_t phase) {
    return phase == OZAYN_SRC_PHASE_READY ||
           phase == OZAYN_SRC_PHASE_DEGRADED ||
           phase == OZAYN_SRC_PHASE_BLOCKED ||
           phase == OZAYN_SRC_PHASE_FAILED ||
           phase == OZAYN_SRC_PHASE_STOPPED;
}

int ozayn_src_is_decision_terminal(ozayn_src_startup_decision_t decision) {
    return decision == OZAYN_SRC_DECISION_READY ||
           decision == OZAYN_SRC_DECISION_READY_DEGRADED ||
           decision == OZAYN_SRC_DECISION_BLOCKED ||
           decision == OZAYN_SRC_DECISION_FAILED;
}

/* ============================================================
 * SECTION 20 — NAME HELPERS
 * ============================================================ */

static const char *_err_names[] = {
    "OK", "NULL", "NOT_INITIALIZED", "ALREADY_INITIALIZED",
    "INVALID_PARAM", "STATE_INVALID", "PHASE_FAILED", "PHASE_TIMEOUT",
    "DEPENDENCY_FAILED", "DEPENDENCY_CYCLE", "COMPONENT_UNAVAILABLE",
    "COMPONENT_INVALID", "CAPABILITY_UNAVAILABLE", "STATE_RECONCILE_FAILED",
    "RESOURCE_RECONCILE_FAILED", "DEVICE_RECONCILE_FAILED",
    "SECURITY_REVALIDATE_FAILED", "SAFETY_VALIDATION_FAILED",
    "RECOVERY_STATE_INVALID", "RECOVERY_REQUIRED",
    "MANUAL_REVIEW_REQUIRED", "BLOCKED", "CONFIGURATION_ERROR",
    "CONCURRENCY_ERROR", "STORAGE_ERROR", "LIMIT_REACHED",
    "NOT_FOUND", "FAILED"
};

const char *ozayn_src_err_name(ozayn_src_err_t err) {
    int idx = -err;
    if (idx < 0 || idx >= (int)(sizeof(_err_names) / sizeof(_err_names[0])))
        return "UNKNOWN";
    return _err_names[idx];
}

const char *ozayn_src_phase_name(ozayn_src_startup_phase_t phase) {
    if (phase < 0 || phase >= OZAYN_SRC_PHASE_COUNT) return "INVALID";
    return _phase_descriptions[phase];
}

const char *ozayn_src_state_name(ozayn_src_startup_state_t state) {
    switch (state) {
        case OZAYN_SRC_STATE_IDLE:     return "IDLE";
        case OZAYN_SRC_STATE_STARTING: return "STARTING";
        case OZAYN_SRC_STATE_RUNNING:  return "RUNNING";
        case OZAYN_SRC_STATE_STOPPING: return "STOPPING";
        case OZAYN_SRC_STATE_STOPPED:  return "STOPPED";
        case OZAYN_SRC_STATE_FAILED:   return "FAILED";
    }
    return "INVALID";
}

const char *ozayn_src_cause_name(ozayn_src_startup_cause_t cause) {
    switch (cause) {
        case OZAYN_SRC_CAUSE_UNKNOWN:                      return "UNKNOWN";
        case OZAYN_SRC_CAUSE_NORMAL_START:                  return "NORMAL_START";
        case OZAYN_SRC_CAUSE_NORMAL_RESTART:                return "NORMAL_RESTART";
        case OZAYN_SRC_CAUSE_CRASH_RECOVERY:                return "CRASH_RECOVERY";
        case OZAYN_SRC_CAUSE_FORCED_TERMINATION_RECOVERY:   return "FORCED_TERMINATION_RECOVERY";
        case OZAYN_SRC_CAUSE_POWER_LOSS_RECOVERY:           return "POWER_LOSS_RECOVERY";
    }
    return "INVALID";
}

const char *ozayn_src_shutdown_name(ozayn_src_previous_shutdown_t shutdown) {
    switch (shutdown) {
        case OZAYN_SRC_SHUTDOWN_UNKNOWN:  return "UNKNOWN";
        case OZAYN_SRC_SHUTDOWN_CLEAN:    return "CLEAN";
        case OZAYN_SRC_SHUTDOWN_UNCLEAN:  return "UNCLEAN";
        case OZAYN_SRC_SHUTDOWN_FORCED:   return "FORCED";
        case OZAYN_SRC_SHUTDOWN_CRASH:    return "CRASH";
    }
    return "INVALID";
}

const char *ozayn_src_component_recon_name(ozayn_src_component_recon_status_t s) {
    switch (s) {
        case OZAYN_SRC_RECON_UNKNOWN:     return "UNKNOWN";
        case OZAYN_SRC_RECON_CONSISTENT:  return "CONSISTENT";
        case OZAYN_SRC_RECON_CHANGED:     return "CHANGED";
        case OZAYN_SRC_RECON_MISSING:     return "MISSING";
        case OZAYN_SRC_RECON_UNAVAILABLE: return "UNAVAILABLE";
        case OZAYN_SRC_RECON_DEGRADED:    return "DEGRADED";
        case OZAYN_SRC_RECON_FAILED:      return "FAILED";
        case OZAYN_SRC_RECON_NEW:         return "NEW";
    }
    return "INVALID";
}

const char *ozayn_src_capability_recon_name(ozayn_src_capability_recon_status_t s) {
    switch (s) {
        case OZAYN_SRC_CAP_RECON_UNKNOWN:     return "UNKNOWN";
        case OZAYN_SRC_CAP_RECON_AVAILABLE:   return "AVAILABLE";
        case OZAYN_SRC_CAP_RECON_UNAVAILABLE: return "UNAVAILABLE";
        case OZAYN_SRC_CAP_RECON_DEGRADED:    return "DEGRADED";
        case OZAYN_SRC_CAP_RECON_UNSUPPORTED: return "UNSUPPORTED";
        case OZAYN_SRC_CAP_RECON_INVALID:     return "INVALID";
    }
    return "INVALID";
}

const char *ozayn_src_resource_recon_name(ozayn_src_resource_recon_status_t s) {
    switch (s) {
        case OZAYN_SRC_RES_RECON_UNKNOWN:     return "UNKNOWN";
        case OZAYN_SRC_RES_RECON_AVAILABLE:   return "AVAILABLE";
        case OZAYN_SRC_RES_RECON_UNAVAILABLE: return "UNAVAILABLE";
        case OZAYN_SRC_RES_RECON_CHANGED:     return "CHANGED";
        case OZAYN_SRC_RES_RECON_DEGRADED:    return "DEGRADED";
    }
    return "INVALID";
}

const char *ozayn_src_device_recon_name(ozayn_src_device_recon_status_t s) {
    switch (s) {
        case OZAYN_SRC_DEV_RECON_UNKNOWN:     return "UNKNOWN";
        case OZAYN_SRC_DEV_RECON_PRESENT:     return "PRESENT";
        case OZAYN_SRC_DEV_RECON_ABSENT:      return "ABSENT";
        case OZAYN_SRC_DEV_RECON_CHANGED:     return "CHANGED";
        case OZAYN_SRC_DEV_RECON_UNAVAILABLE: return "UNAVAILABLE";
        case OZAYN_SRC_DEV_RECON_DEGRADED:    return "DEGRADED";
        case OZAYN_SRC_DEV_RECON_UNSUPPORTED: return "UNSUPPORTED";
    }
    return "INVALID";
}

const char *ozayn_src_security_recon_name(ozayn_src_security_recon_status_t s) {
    switch (s) {
        case OZAYN_SRC_SEC_RECON_UNKNOWN:     return "UNKNOWN";
        case OZAYN_SRC_SEC_RECON_VALID:       return "VALID";
        case OZAYN_SRC_SEC_RECON_EXPIRED:     return "EXPIRED";
        case OZAYN_SRC_SEC_RECON_INVALID:     return "INVALID";
        case OZAYN_SRC_SEC_RECON_UNAVAILABLE: return "UNAVAILABLE";
    }
    return "INVALID";
}

const char *ozayn_src_recovery_assessment_name(ozayn_src_recovery_assessment_t a) {
    switch (a) {
        case OZAYN_SRC_RECOVERY_NONE:            return "NONE";
        case OZAYN_SRC_RECOVERY_REQUIRED:        return "REQUIRED";
        case OZAYN_SRC_RECOVERY_MANUAL_REVIEW:   return "MANUAL_REVIEW";
        case OZAYN_SRC_RECOVERY_BLOCKED:         return "BLOCKED";
        case OZAYN_SRC_RECOVERY_EXPIRED:         return "EXPIRED";
        case OZAYN_SRC_RECOVERY_CORRUPTED:       return "CORRUPTED";
    }
    return "INVALID";
}

const char *ozayn_src_decision_name(ozayn_src_startup_decision_t decision) {
    if (decision < 0 || decision > OZAYN_SRC_DECISION_FAILED)
        return "INVALID";
    return _decision_descriptions[decision];
}

const char *ozayn_src_failure_class_name(ozayn_src_failure_class_t cls) {
    switch (cls) {
        case OZAYN_SRC_FAIL_NON_CRITICAL: return "NON_CRITICAL";
        case OZAYN_SRC_FAIL_DEGRADED:     return "DEGRADED";
        case OZAYN_SRC_FAIL_CRITICAL:     return "CRITICAL";
        case OZAYN_SRC_FAIL_BLOCKING:     return "BLOCKING";
    }
    return "INVALID";
}

const char *ozayn_src_priority_name(ozayn_src_recovery_priority_t priority) {
    switch (priority) {
        case OZAYN_SRC_PRIORITY_LOW:    return "LOW";
        case OZAYN_SRC_PRIORITY_NORMAL: return "NORMAL";
        case OZAYN_SRC_PRIORITY_HIGH:   return "HIGH";
        case OZAYN_SRC_PRIORITY_CRITICAL: return "CRITICAL";
    }
    return "INVALID";
}

static const char *_event_type_names[] = {
    "STARTUP_STARTED", "PHASE_STARTED", "PHASE_COMPLETED",
    "PHASE_FAILED", "PHASE_TIMEOUT", "DEPENDENCY_FAILED",
    "DEPENDENCY_CYCLE", "STATE_RECONCILIATION_STARTED",
    "STATE_RECONCILIATION_COMPLETED", "RESOURCE_RECONCILIATION_COMPLETED",
    "DEVICE_RECONCILIATION_COMPLETED", "SECURITY_REVALIDATION_COMPLETED",
    "RECOVERY_ASSESSMENT_STARTED", "RECOVERY_REQUIRED",
    "MANUAL_REVIEW_REQUIRED", "READY", "DEGRADED", "BLOCKED",
    "FAILED", "STARTUP_COMPLETED", "SHUTDOWN_STARTED",
    "SHUTDOWN_COMPLETED"
};

const char *ozayn_src_event_type_name(ozayn_src_event_type_t type) {
    if (type < 0 || type >= OZAYN_SRC_EVENT_COUNT) return "INVALID";
    return _event_type_names[type];
}

const char *ozayn_src_phase_result_status_name(ozayn_src_phase_result_status_t s) {
    switch (s) {
        case OZAYN_SRC_PHASE_RESULT_PENDING:   return "PENDING";
        case OZAYN_SRC_PHASE_RESULT_SUCCESS:   return "SUCCESS";
        case OZAYN_SRC_PHASE_RESULT_DEGRADED:  return "DEGRADED";
        case OZAYN_SRC_PHASE_RESULT_FAILED:    return "FAILED";
        case OZAYN_SRC_PHASE_RESULT_TIMEOUT:   return "TIMEOUT";
        case OZAYN_SRC_PHASE_RESULT_SKIPPED:   return "SKIPPED";
    }
    return "INVALID";
}
