#include "workflow_orchestrator.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

/* ============================================================
 * STATIC GLOBAL STATE
 * ============================================================ */

static ozayn_wof_service_t _svc;

/* ============================================================
 * HELPER — TIMESTAMP
 * ============================================================ */

static int64_t _now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

/* ============================================================
 * HELPER — STATE MACHINES
 * ============================================================ */

static int _wf_transitions[OZAYN_WOF_WF_STATE_COUNT][OZAYN_WOF_WF_STATE_COUNT];
static int _stg_transitions[OZAYN_WOF_STG_STATE_COUNT][OZAYN_WOF_STG_STATE_COUNT];
static int _transitions_initialized = 0;

static void _init_transitions(void) {
    if (_transitions_initialized) return;
    memset(_wf_transitions, 0, sizeof(_wf_transitions));
    memset(_stg_transitions, 0, sizeof(_stg_transitions));

    /* Workflow transitions: from -> to = 1 (allowed) */
    _wf_transitions[OZAYN_WOF_WF_CREATED][OZAYN_WOF_WF_VALIDATING] = 1;
    _wf_transitions[OZAYN_WOF_WF_VALIDATING][OZAYN_WOF_WF_AUTHORIZED] = 1;
    _wf_transitions[OZAYN_WOF_WF_VALIDATING][OZAYN_WOF_WF_REJECTED] = 1;
    _wf_transitions[OZAYN_WOF_WF_VALIDATING][OZAYN_WOF_WF_UNAVAILABLE] = 1;
    _wf_transitions[OZAYN_WOF_WF_AUTHORIZED][OZAYN_WOF_WF_WAITING] = 1;
    _wf_transitions[OZAYN_WOF_WF_AUTHORIZED][OZAYN_WOF_WF_REJECTED] = 1;
    _wf_transitions[OZAYN_WOF_WF_AUTHORIZED][OZAYN_WOF_WF_CANCELLED] = 1;
    _wf_transitions[OZAYN_WOF_WF_WAITING][OZAYN_WOF_WF_READY] = 1;
    _wf_transitions[OZAYN_WOF_WF_WAITING][OZAYN_WOF_WF_CANCELLED] = 1;
    _wf_transitions[OZAYN_WOF_WF_WAITING][OZAYN_WOF_WF_EXPIRED] = 1;
    _wf_transitions[OZAYN_WOF_WF_READY][OZAYN_WOF_WF_SCHEDULED] = 1;
    _wf_transitions[OZAYN_WOF_WF_READY][OZAYN_WOF_WF_CANCELLED] = 1;
    _wf_transitions[OZAYN_WOF_WF_SCHEDULED][OZAYN_WOF_WF_STARTING] = 1;
    _wf_transitions[OZAYN_WOF_WF_SCHEDULED][OZAYN_WOF_WF_CANCELLED] = 1;
    _wf_transitions[OZAYN_WOF_WF_STARTING][OZAYN_WOF_WF_ACTIVE] = 1;
    _wf_transitions[OZAYN_WOF_WF_STARTING][OZAYN_WOF_WF_FAILED] = 1;
    _wf_transitions[OZAYN_WOF_WF_STARTING][OZAYN_WOF_WF_CANCELLED] = 1;
    _wf_transitions[OZAYN_WOF_WF_ACTIVE][OZAYN_WOF_WF_PAUSING] = 1;
    _wf_transitions[OZAYN_WOF_WF_ACTIVE][OZAYN_WOF_WF_DRAINING] = 1;
    _wf_transitions[OZAYN_WOF_WF_ACTIVE][OZAYN_WOF_WF_SUCCEEDED] = 1;
    _wf_transitions[OZAYN_WOF_WF_ACTIVE][OZAYN_WOF_WF_FAILED] = 1;
    _wf_transitions[OZAYN_WOF_WF_ACTIVE][OZAYN_WOF_WF_PARTIALLY_SUCCEEDED] = 1;
    _wf_transitions[OZAYN_WOF_WF_ACTIVE][OZAYN_WOF_WF_CANCELLED] = 1;
    _wf_transitions[OZAYN_WOF_WF_ACTIVE][OZAYN_WOF_WF_TIMEOUT] = 1;
    _wf_transitions[OZAYN_WOF_WF_ACTIVE][OZAYN_WOF_WF_EXPIRED] = 1;
    _wf_transitions[OZAYN_WOF_WF_PAUSING][OZAYN_WOF_WF_PAUSED] = 1;
    _wf_transitions[OZAYN_WOF_WF_PAUSING][OZAYN_WOF_WF_FAILED] = 1;
    _wf_transitions[OZAYN_WOF_WF_PAUSED][OZAYN_WOF_WF_RESUMING] = 1;
    _wf_transitions[OZAYN_WOF_WF_PAUSED][OZAYN_WOF_WF_CANCELLED] = 1;
    _wf_transitions[OZAYN_WOF_WF_PAUSED][OZAYN_WOF_WF_EXPIRED] = 1;
    _wf_transitions[OZAYN_WOF_WF_RESUMING][OZAYN_WOF_WF_ACTIVE] = 1;
    _wf_transitions[OZAYN_WOF_WF_RESUMING][OZAYN_WOF_WF_FAILED] = 1;
    _wf_transitions[OZAYN_WOF_WF_DRAINING][OZAYN_WOF_WF_STOPPING] = 1;
    _wf_transitions[OZAYN_WOF_WF_DRAINING][OZAYN_WOF_WF_SUCCEEDED] = 1;
    _wf_transitions[OZAYN_WOF_WF_DRAINING][OZAYN_WOF_WF_FAILED] = 1;
    _wf_transitions[OZAYN_WOF_WF_DRAINING][OZAYN_WOF_WF_PARTIALLY_SUCCEEDED] = 1;
    _wf_transitions[OZAYN_WOF_WF_STOPPING][OZAYN_WOF_WF_SUCCEEDED] = 1;
    _wf_transitions[OZAYN_WOF_WF_STOPPING][OZAYN_WOF_WF_FAILED] = 1;
    _wf_transitions[OZAYN_WOF_WF_STOPPING][OZAYN_WOF_WF_PARTIALLY_SUCCEEDED] = 1;

    /* Stage transitions */
    _stg_transitions[OZAYN_WOF_STG_CREATED][OZAYN_WOF_STG_WAITING_DEPS] = 1;
    _stg_transitions[OZAYN_WOF_STG_CREATED][OZAYN_WOF_STG_SKIPPED] = 1;
    _stg_transitions[OZAYN_WOF_STG_CREATED][OZAYN_WOF_STG_CANCELLED] = 1;
    _stg_transitions[OZAYN_WOF_STG_WAITING_DEPS][OZAYN_WOF_STG_DEPS_SATISFIED] = 1;
    _stg_transitions[OZAYN_WOF_STG_WAITING_DEPS][OZAYN_WOF_STG_BLOCKED] = 1;
    _stg_transitions[OZAYN_WOF_STG_WAITING_DEPS][OZAYN_WOF_STG_CANCELLED] = 1;
    _stg_transitions[OZAYN_WOF_STG_WAITING_DEPS][OZAYN_WOF_STG_TIMED_OUT] = 1;
    _stg_transitions[OZAYN_WOF_STG_DEPS_SATISFIED][OZAYN_WOF_STG_ELIGIBLE] = 1;
    _stg_transitions[OZAYN_WOF_STG_DEPS_SATISFIED][OZAYN_WOF_STG_CANCELLED] = 1;
    _stg_transitions[OZAYN_WOF_STG_ELIGIBLE][OZAYN_WOF_STG_SUBMITTED] = 1;
    _stg_transitions[OZAYN_WOF_STG_ELIGIBLE][OZAYN_WOF_STG_CANCELLED] = 1;
    _stg_transitions[OZAYN_WOF_STG_SUBMITTED][OZAYN_WOF_STG_SCHEDULED] = 1;
    _stg_transitions[OZAYN_WOF_STG_SUBMITTED][OZAYN_WOF_STG_CANCELLED] = 1;
    _stg_transitions[OZAYN_WOF_STG_SCHEDULED][OZAYN_WOF_STG_RUNNING] = 1;
    _stg_transitions[OZAYN_WOF_STG_SCHEDULED][OZAYN_WOF_STG_CANCELLED] = 1;
    _stg_transitions[OZAYN_WOF_STG_RUNNING][OZAYN_WOF_STG_PAUSED] = 1;
    _stg_transitions[OZAYN_WOF_STG_RUNNING][OZAYN_WOF_STG_COMPLETED] = 1;
    _stg_transitions[OZAYN_WOF_STG_RUNNING][OZAYN_WOF_STG_FAILED] = 1;
    _stg_transitions[OZAYN_WOF_STG_RUNNING][OZAYN_WOF_STG_CANCELLED] = 1;
    _stg_transitions[OZAYN_WOF_STG_RUNNING][OZAYN_WOF_STG_TIMED_OUT] = 1;
    _stg_transitions[OZAYN_WOF_STG_PAUSED][OZAYN_WOF_STG_RUNNING] = 1;
    _stg_transitions[OZAYN_WOF_STG_PAUSED][OZAYN_WOF_STG_CANCELLED] = 1;

    _transitions_initialized = 1;
}

/* ============================================================
 * HELPER — FIND FUNCTIONS
 * ============================================================ */

static ozayn_wof_workflow_t *_find_workflow(ozayn_wof_service_t *svc,
                                            const char *workflow_id) {
    if (!svc || !workflow_id) return NULL;
    for (int i = 0; i < OZAYN_WOF_MAX_WORKFLOWS; i++) {
        if (svc->workflows[i].active &&
            strcmp(svc->workflows[i].workflow_id, workflow_id) == 0) {
            return &svc->workflows[i];
        }
    }
    return NULL;
}

static int _find_free_workflow_slot(const ozayn_wof_service_t *svc) {
    for (int i = 0; i < OZAYN_WOF_MAX_WORKFLOWS; i++) {
        if (!svc->workflows[i].active) return i;
    }
    return -1;
}

static ozayn_wof_stage_t *_find_stage(ozayn_wof_service_t *svc,
                                       const char *workflow_id,
                                       const char *stage_id) {
    if (!svc || !workflow_id || !stage_id) return NULL;
    for (int i = 0; i < OZAYN_WOF_MAX_WORKFLOWS * OZAYN_WOF_MAX_STAGES_PER_WORKFLOW; i++) {
        if (svc->stages[i].active &&
            strcmp(svc->stages[i].workflow_id, workflow_id) == 0 &&
            strcmp(svc->stages[i].stage_id, stage_id) == 0) {
            return &svc->stages[i];
        }
    }
    return NULL;
}

static int _find_free_stage_slot(const ozayn_wof_service_t *svc) {
    for (int i = 0; i < OZAYN_WOF_MAX_WORKFLOWS * OZAYN_WOF_MAX_STAGES_PER_WORKFLOW; i++) {
        if (!svc->stages[i].active) return i;
    }
    return -1;
}

static int _find_free_dep_slot(const ozayn_wof_service_t *svc) {
    for (int i = 0; i < OZAYN_WOF_MAX_DEPENDENCIES; i++) {
        if (!svc->dependencies[i].active) return i;
    }
    return -1;
}

static ozayn_wof_dependency_t *_find_dependency(ozayn_wof_service_t *svc,
                                                const char *dep_id) {
    if (!svc || !dep_id) return NULL;
    for (int i = 0; i < OZAYN_WOF_MAX_DEPENDENCIES; i++) {
        if (svc->dependencies[i].active &&
            strcmp(svc->dependencies[i].dependency_id, dep_id) == 0) {
            return &svc->dependencies[i];
        }
    }
    return NULL;
}

static int _is_terminal_w(ozayn_wof_workflow_state_t s) {
    return s == OZAYN_WOF_WF_SUCCEEDED ||
           s == OZAYN_WOF_WF_FAILED ||
           s == OZAYN_WOF_WF_PARTIALLY_SUCCEEDED ||
           s == OZAYN_WOF_WF_CANCELLED ||
           s == OZAYN_WOF_WF_TIMEOUT ||
           s == OZAYN_WOF_WF_EXPIRED ||
           s == OZAYN_WOF_WF_REVOKED ||
           s == OZAYN_WOF_WF_REJECTED ||
           s == OZAYN_WOF_WF_UNAVAILABLE;
}

static int _is_terminal_s(ozayn_wof_stage_state_t s) {
    return s == OZAYN_WOF_STG_COMPLETED ||
           s == OZAYN_WOF_STG_FAILED ||
           s == OZAYN_WOF_STG_SKIPPED ||
           s == OZAYN_WOF_STG_CANCELLED ||
           s == OZAYN_WOF_STG_TIMED_OUT;
}

static int _count_stages_for_workflow(const ozayn_wof_service_t *svc,
                                       const char *workflow_id) {
    int count = 0;
    for (int i = 0; i < OZAYN_WOF_MAX_WORKFLOWS * OZAYN_WOF_MAX_STAGES_PER_WORKFLOW; i++) {
        if (svc->stages[i].active &&
            strcmp(svc->stages[i].workflow_id, workflow_id) == 0) {
            count++;
        }
    }
    return count;
}

static int _count_deps_for_workflow(const ozayn_wof_service_t *svc,
                                     const char *workflow_id) {
    int count = 0;
    for (int i = 0; i < OZAYN_WOF_MAX_DEPENDENCIES; i++) {
        if (svc->dependencies[i].active &&
            strcmp(svc->dependencies[i].workflow_id, workflow_id) == 0) {
            count++;
        }
    }
    return count;
}

static int _count_running_stages(const ozayn_wof_service_t *svc,
                                  const char *workflow_id) {
    int count = 0;
    for (int i = 0; i < OZAYN_WOF_MAX_WORKFLOWS * OZAYN_WOF_MAX_STAGES_PER_WORKFLOW; i++) {
        if (svc->stages[i].active &&
            strcmp(svc->stages[i].workflow_id, workflow_id) == 0 &&
            (svc->stages[i].state == OZAYN_WOF_STG_RUNNING ||
             svc->stages[i].state == OZAYN_WOF_STG_SCHEDULED ||
             svc->stages[i].state == OZAYN_WOF_STG_SUBMITTED)) {
            count++;
        }
    }
    return count;
}

static int _count_active_workflows(const ozayn_wof_service_t *svc) {
    int count = 0;
    for (int i = 0; i < OZAYN_WOF_MAX_WORKFLOWS; i++) {
        if (svc->workflows[i].active && !_is_terminal_w(svc->workflows[i].state)) {
            count++;
        }
    }
    return count;
}

/* ============================================================
 * HELPER — CYCLE DETECTION (DFS)
 * ============================================================ */

static int _has_cycle(ozayn_wof_service_t *svc, const char *workflow_id,
                       const char *stage_id, const char *target_id,
                       int depth) {
    if (depth > OZAYN_WOF_MAX_DEPENDENCY_DEPTH) return 1;
    for (int i = 0; i < OZAYN_WOF_MAX_DEPENDENCIES; i++) {
        if (svc->dependencies[i].active &&
            strcmp(svc->dependencies[i].workflow_id, workflow_id) == 0 &&
            strcmp(svc->dependencies[i].source_stage_id, stage_id) == 0) {
            const char *next = svc->dependencies[i].target_stage_id;
            if (strcmp(next, target_id) == 0) return 1;
            if (_has_cycle(svc, workflow_id, next, target_id, depth + 1))
                return 1;
        }
    }
    return 0;
}

/* ============================================================
 * HELPER — EVENT EMISSION
 * ============================================================ */

static void _emit_event(ozayn_wof_service_t *svc,
                         ozayn_wof_event_type_t event_type,
                         const char *workflow_id,
                         const char *stage_id,
                         const char *pipeline_id,
                         const char *operation_id,
                         const char *message) {
    if (!svc) return;
    int idx = -1;
    for (int i = 0; i < OZAYN_WOF_MAX_EVENTS; i++) {
        if (!svc->events[i].active) { idx = i; break; }
    }
    if (idx < 0) {
        idx = 0;
        memset(&svc->events[0], 0, sizeof(ozayn_wof_event_t));
    }
    ozayn_wof_event_t *e = &svc->events[idx];
    e->active = 1;
    e->event_type = event_type;
    e->timestamp = _now_ms();
    e->sequence = svc->event_sequence++;
    snprintf(e->event_id, OZAYN_WOF_MAX_ID_LEN, "WEVT-%lu",
             (unsigned long)(e->sequence));
    if (workflow_id) strncpy(e->workflow_id, workflow_id, OZAYN_WOF_MAX_ID_LEN - 1);
    if (stage_id) strncpy(e->stage_id, stage_id, OZAYN_WOF_MAX_ID_LEN - 1);
    if (pipeline_id) strncpy(e->pipeline_id, pipeline_id, OZAYN_WOF_MAX_ID_LEN - 1);
    if (operation_id) strncpy(e->operation_id, operation_id, OZAYN_WOF_MAX_ID_LEN - 1);
    if (message) strncpy(e->message, message, OZAYN_WOF_MAX_DESC_LEN - 1);
    svc->stats.total_events_emitted++;
}

/* ============================================================
 * HELPER — TRANSITION WITH VALIDATION
 * ============================================================ */

static ozayn_wof_err_t _wf_transition(ozayn_wof_service_t *svc,
                                       ozayn_wof_workflow_t *wf,
                                       ozayn_wof_workflow_state_t new_state) {
    if (!ozayn_wof_is_valid_transition(wf->state, new_state))
        return OZAYN_WOF_ERR_STATE_INVALID;
    wf->state = new_state;
    svc->stats.total_state_transitions++;
    return OZAYN_WOF_OK;
}

static ozayn_wof_err_t _stg_transition(ozayn_wof_service_t *svc __attribute__((unused)),
                                        ozayn_wof_stage_t *stg,
                                        ozayn_wof_stage_state_t new_state) {
    if (!ozayn_wof_is_valid_stage_transition(stg->state, new_state))
        return OZAYN_WOF_ERR_STATE_INVALID;
    stg->state = new_state;
    return OZAYN_WOF_OK;
}

/* ============================================================
 * HELPER — UPDATE WORKFLOW COUNTS
 * ============================================================ */

static void _update_workflow_counts(ozayn_wof_service_t *svc,
                                     const char *workflow_id) {
    ozayn_wof_workflow_t *wf = _find_workflow(svc, workflow_id);
    if (!wf) return;
    wf->completed_stage_count = 0;
    wf->failed_stage_count = 0;
    wf->cancelled_stage_count = 0;
    wf->skipped_stage_count = 0;
    wf->blocked_stage_count = 0;
    for (int i = 0; i < OZAYN_WOF_MAX_WORKFLOWS * OZAYN_WOF_MAX_STAGES_PER_WORKFLOW; i++) {
        if (!svc->stages[i].active ||
            strcmp(svc->stages[i].workflow_id, workflow_id) != 0) continue;
        switch (svc->stages[i].state) {
            case OZAYN_WOF_STG_COMPLETED:  wf->completed_stage_count++; break;
            case OZAYN_WOF_STG_FAILED:     wf->failed_stage_count++; break;
            case OZAYN_WOF_STG_CANCELLED:  wf->cancelled_stage_count++; break;
            case OZAYN_WOF_STG_SKIPPED:    wf->skipped_stage_count++; break;
            case OZAYN_WOF_STG_BLOCKED:    wf->blocked_stage_count++; break;
            default: break;
        }
    }
}

/* ============================================================
 * HELPER — CHECK IF STAGE DEPS SATISFIED
 * ============================================================ */

static int _deps_satisfied(ozayn_wof_service_t *svc,
                            const char *workflow_id,
                            const char *stage_id) {
    for (int i = 0; i < OZAYN_WOF_MAX_DEPENDENCIES; i++) {
        if (!svc->dependencies[i].active) continue;
        if (strcmp(svc->dependencies[i].workflow_id, workflow_id) != 0) continue;
        if (strcmp(svc->dependencies[i].target_stage_id, stage_id) != 0) continue;
        const char *src = svc->dependencies[i].source_stage_id;
        ozayn_wof_stage_t *src_stg = _find_stage(svc, workflow_id, src);
        if (!src_stg) return 0;
        if (src_stg->state != OZAYN_WOF_STG_COMPLETED &&
            src_stg->state != OZAYN_WOF_STG_SKIPPED) {
            return 0;
        }
    }
    return 1;
}

/* ============================================================
 * HELPER — CHECK IF WORKFLOW HAS CYCLE
 * ============================================================ */

static int _workflow_has_cycle(ozayn_wof_service_t *svc,
                                const char *workflow_id) {
    for (int i = 0; i < OZAYN_WOF_MAX_WORKFLOWS * OZAYN_WOF_MAX_STAGES_PER_WORKFLOW; i++) {
        if (!svc->stages[i].active) continue;
        if (strcmp(svc->stages[i].workflow_id, workflow_id) != 0) continue;
        const char *stage_id = svc->stages[i].stage_id;
        for (int j = 0; j < OZAYN_WOF_MAX_DEPENDENCIES; j++) {
            if (!svc->dependencies[j].active) continue;
            if (strcmp(svc->dependencies[j].workflow_id, workflow_id) != 0) continue;
            if (strcmp(svc->dependencies[j].source_stage_id, stage_id) == 0) {
                const char *target = svc->dependencies[j].target_stage_id;
                if (strcmp(target, stage_id) == 0) return 1;
                if (_has_cycle(svc, workflow_id, target, stage_id, 1))
                    return 1;
            }
        }
    }
    return 0;
}

/* ============================================================
 * HELPER — EVALUATE CONDITION STAGE
 * ============================================================ */

static int _evaluate_condition(ozayn_wof_service_t *svc,
                                const char *workflow_id,
                                const char *stage_id) {
    ozayn_wof_stage_t *stg = _find_stage(svc, workflow_id, stage_id);
    if (!stg) return 0;
    (void)svc;
    switch (stg->condition_type) {
        case OZAYN_WOF_COND_PIPELINE_COMPLETED:
        case OZAYN_WOF_COND_PIPELINE_FAILED:
        case OZAYN_WOF_COND_RESOURCE_AVAILABLE:
        case OZAYN_WOF_COND_DEVICE_AVAILABLE:
        case OZAYN_WOF_COND_HEALTH_STATE:
        case OZAYN_WOF_COND_CAPABILITY_STATE:
        case OZAYN_WOF_COND_OPERATION_RESULT:
            return 1;
        default:
            return 0;
    }
}

/* ============================================================
 * LIFECYCLE
 * ============================================================ */

ozayn_wof_err_t ozayn_wof_service_init(ozayn_wof_service_t *svc,
                                        const ozayn_wof_service_config_t *config) {
    if (!svc) return OZAYN_WOF_ERR_NULL;
    if (svc->initialized) return OZAYN_WOF_ERR_ALREADY_INIT;
    if (!config) return OZAYN_WOF_ERR_INVALID_PARAM;
    memset(svc, 0, sizeof(ozayn_wof_service_t));
    svc->config = *config;
    svc->init_time = _now_ms();
    svc->event_sequence = 0;
    svc->last_tick_time = 0;
    svc->initialized = 1;
    _init_transitions();
    _emit_event(svc, OZAYN_WOF_EVENT_ORCHESTRATOR_STARTED, NULL, NULL, NULL,
                NULL, "Workflow orchestrator initialized");
    return OZAYN_WOF_OK;
}

ozayn_wof_err_t ozayn_wof_service_shutdown(ozayn_wof_service_t *svc) {
    if (!svc) return OZAYN_WOF_ERR_NULL;
    if (!svc->initialized) return OZAYN_WOF_ERR_NOT_INITIALIZED;
    _emit_event(svc, OZAYN_WOF_EVENT_ORCHESTRATOR_STOPPED, NULL, NULL, NULL,
                NULL, "Workflow orchestrator shutting down");
    svc->initialized = 0;
    return OZAYN_WOF_OK;
}

int ozayn_wof_is_initialized(const ozayn_wof_service_t *svc) {
    if (!svc) return 0;
    return svc->initialized;
}

ozayn_wof_service_t *ozayn_wof_get_global(void) {
    return &_svc;
}

/* ============================================================
 * WORKFLOW LIFECYCLE
 * ============================================================ */

ozayn_wof_err_t ozayn_wof_create(ozayn_wof_service_t *svc,
                                  const char *name,
                                  const char *description,
                                  const char *version,
                                  ozayn_wof_workflow_type_t wf_type,
                                  const char *owner_ref,
                                  const char *requester_ref,
                                  const char *session_ref,
                                  const char *safe_metadata,
                                  char *out_workflow_id,
                                  int out_id_len) {
    if (!svc) return OZAYN_WOF_ERR_NULL;
    if (!svc->initialized) return OZAYN_WOF_ERR_NOT_INITIALIZED;
    if (!name || !name[0]) return OZAYN_WOF_ERR_INVALID_PARAM;
    if (wf_type < 0 || wf_type >= OZAYN_WOF_TYPE_COUNT)
        return OZAYN_WOF_ERR_INVALID_PARAM;
    if (!out_workflow_id || out_id_len < 8)
        return OZAYN_WOF_ERR_INVALID_PARAM;
    if (svc->stats.active_workflows >= OZAYN_WOF_MAX_CONCURRENT_WORKFLOWS)
        return OZAYN_WOF_ERR_LIMIT_REACHED;
    int slot = _find_free_workflow_slot(svc);
    if (slot < 0) return OZAYN_WOF_ERR_LIMIT_REACHED;
    ozayn_wof_workflow_t *wf = &svc->workflows[slot];
    memset(wf, 0, sizeof(ozayn_wof_workflow_t));
    wf->active = 1;
    wf->version_number = 1;
    snprintf(wf->workflow_id, OZAYN_WOF_MAX_ID_LEN, "WOF-%d", slot);
    strncpy(wf->name, name, OZAYN_WOF_MAX_NAME_LEN - 1);
    if (description) strncpy(wf->description, description, OZAYN_WOF_MAX_DESC_LEN - 1);
    if (version) strncpy(wf->version, version, OZAYN_WOF_MAX_VERSION_LEN - 1);
    else strncpy(wf->version, "1.0", OZAYN_WOF_MAX_VERSION_LEN - 1);
    if (owner_ref) strncpy(wf->owner_ref, owner_ref, OZAYN_WOF_MAX_ID_LEN - 1);
    if (requester_ref) strncpy(wf->requester_ref, requester_ref, OZAYN_WOF_MAX_ID_LEN - 1);
    if (session_ref) strncpy(wf->security_session_ref, session_ref, OZAYN_WOF_MAX_ID_LEN - 1);
    if (safe_metadata) strncpy(wf->safe_metadata, safe_metadata, OZAYN_WOF_MAX_METADATA_LEN - 1);
    wf->workflow_type = wf_type;
    wf->state = OZAYN_WOF_WF_CREATED;
    wf->failure_policy = OZAYN_WOF_FAIL_FAIL_WORKFLOW;
    wf->concurrency_policy = (wf_type == OZAYN_WOF_TYPE_SEQUENTIAL)
        ? OZAYN_WOF_CONC_SEQUENTIAL
        : (wf_type == OZAYN_WOF_TYPE_PARALLEL)
            ? OZAYN_WOF_CONC_PARALLEL
            : OZAYN_WOF_CONC_BOUNDED;
    wf->max_concurrent_stages = (wf_type == OZAYN_WOF_TYPE_BOUNDED_PARALLEL)
        ? OZAYN_WOF_MAX_CONCURRENT_STAGES : 1;
    wf->timeout_ms = OZAYN_WOF_DEFAULT_WORKFLOW_TIMEOUT_MS;
    wf->stage_timeout_ms = OZAYN_WOF_DEFAULT_STAGE_TIMEOUT_MS;
    wf->created_time = _now_ms();
    wf->last_tick_time = wf->created_time;
    strncpy(out_workflow_id, wf->workflow_id, out_id_len - 1);
    svc->stats.total_workflows_created++;
    svc->stats.active_workflows = _count_active_workflows(svc);
    if (svc->stats.active_workflows > svc->stats.peak_workflows)
        svc->stats.peak_workflows = svc->stats.active_workflows;
    _emit_event(svc, OZAYN_WOF_EVENT_CREATED, wf->workflow_id, NULL, NULL,
                NULL, "Workflow created");
    return OZAYN_WOF_OK;
}

ozayn_wof_err_t ozayn_wof_validate(ozayn_wof_service_t *svc,
                                    const char *workflow_id) {
    if (!svc) return OZAYN_WOF_ERR_NULL;
    if (!svc->initialized) return OZAYN_WOF_ERR_NOT_INITIALIZED;
    if (!workflow_id) return OZAYN_WOF_ERR_INVALID_PARAM;
    ozayn_wof_workflow_t *wf = _find_workflow(svc, workflow_id);
    if (!wf) return OZAYN_WOF_ERR_NOT_FOUND;
    if (wf->state != OZAYN_WOF_WF_CREATED &&
        wf->state != OZAYN_WOF_WF_VALIDATING)
        return OZAYN_WOF_ERR_STATE_INVALID;
    if (_workflow_has_cycle(svc, workflow_id))
        return OZAYN_WOF_ERR_DEPENDENCY_CYCLE;
    _wf_transition(svc, wf, OZAYN_WOF_WF_VALIDATING);
    svc->stats.total_workflows_validated++;
    int valid = 1;
    for (int i = 0; i < OZAYN_WOF_MAX_WORKFLOWS * OZAYN_WOF_MAX_STAGES_PER_WORKFLOW; i++) {
        if (!svc->stages[i].active) continue;
        if (strcmp(svc->stages[i].workflow_id, workflow_id) != 0) continue;
        ozayn_wof_stage_t *stg = &svc->stages[i];
        if (stg->stage_type == OZAYN_WOF_STAGE_PIPELINE && !stg->pipeline_id[0]) {
            valid = 0;
            break;
        }
        if (stg->stage_type == OZAYN_WOF_STAGE_OPERATION && !stg->operation_id[0]) {
            valid = 0;
            break;
        }
    }
    if (!valid) {
        _wf_transition(svc, wf, OZAYN_WOF_WF_REJECTED);
        wf->close_reason = OZAYN_WOF_CLOSE_ORCHESTRATION_ERROR;
        strncpy(wf->close_reason_detail, "Stage validation failed",
                OZAYN_WOF_MAX_DESC_LEN - 1);
        return OZAYN_WOF_ERR_STAGE_INVALID;
    }
    _emit_event(svc, OZAYN_WOF_EVENT_VALIDATING, workflow_id, NULL, NULL,
                NULL, "Workflow validated");
    return OZAYN_WOF_OK;
}

ozayn_wof_err_t ozayn_wof_authorize(ozayn_wof_service_t *svc,
                                     const char *workflow_id,
                                     const char *authorization_ref,
                                     const char *safety_ref) {
    if (!svc) return OZAYN_WOF_ERR_NULL;
    if (!svc->initialized) return OZAYN_WOF_ERR_NOT_INITIALIZED;
    if (!workflow_id) return OZAYN_WOF_ERR_INVALID_PARAM;
    ozayn_wof_workflow_t *wf = _find_workflow(svc, workflow_id);
    if (!wf) return OZAYN_WOF_ERR_NOT_FOUND;
    if (wf->state != OZAYN_WOF_WF_VALIDATING)
        return OZAYN_WOF_ERR_STATE_INVALID;
    if (authorization_ref) strncpy(wf->authorization_ref, authorization_ref,
                                    OZAYN_WOF_MAX_ID_LEN - 1);
    if (safety_ref) strncpy(wf->safety_decision_ref, safety_ref,
                             OZAYN_WOF_MAX_ID_LEN - 1);
    _wf_transition(svc, wf, OZAYN_WOF_WF_AUTHORIZED);
    svc->stats.total_workflows_authorized++;
    _emit_event(svc, OZAYN_WOF_EVENT_AUTHORIZED, workflow_id, NULL, NULL,
                NULL, "Workflow authorized");
    return OZAYN_WOF_OK;
}

ozayn_wof_err_t ozayn_wof_reject(ozayn_wof_service_t *svc,
                                  const char *workflow_id,
                                  ozayn_wof_close_reason_t reason,
                                  const char *detail) {
    if (!svc) return OZAYN_WOF_ERR_NULL;
    if (!svc->initialized) return OZAYN_WOF_ERR_NOT_INITIALIZED;
    if (!workflow_id) return OZAYN_WOF_ERR_INVALID_PARAM;
    ozayn_wof_workflow_t *wf = _find_workflow(svc, workflow_id);
    if (!wf) return OZAYN_WOF_ERR_NOT_FOUND;
    if (_is_terminal_w(wf->state)) return OZAYN_WOF_ERR_STATE_INVALID;
    wf->close_reason = reason;
    if (detail) strncpy(wf->close_reason_detail, detail, OZAYN_WOF_MAX_DESC_LEN - 1);
    _wf_transition(svc, wf, OZAYN_WOF_WF_REJECTED);
    svc->stats.total_workflows_rejected++;
    _emit_event(svc, OZAYN_WOF_EVENT_REJECTED, workflow_id, NULL, NULL,
                NULL, detail ? detail : "Workflow rejected");
    return OZAYN_WOF_OK;
}

ozayn_wof_err_t ozayn_wof_ready(ozayn_wof_service_t *svc,
                                 const char *workflow_id) {
    if (!svc) return OZAYN_WOF_ERR_NULL;
    if (!svc->initialized) return OZAYN_WOF_ERR_NOT_INITIALIZED;
    if (!workflow_id) return OZAYN_WOF_ERR_INVALID_PARAM;
    ozayn_wof_workflow_t *wf = _find_workflow(svc, workflow_id);
    if (!wf) return OZAYN_WOF_ERR_NOT_FOUND;
    if (wf->state != OZAYN_WOF_WF_AUTHORIZED &&
        wf->state != OZAYN_WOF_WF_WAITING)
        return OZAYN_WOF_ERR_STATE_INVALID;
    if (wf->stage_count == 0)
        return OZAYN_WOF_ERR_STAGE_INVALID;
    if (wf->state == OZAYN_WOF_WF_AUTHORIZED) {
        _wf_transition(svc, wf, OZAYN_WOF_WF_WAITING);
    }
    _wf_transition(svc, wf, OZAYN_WOF_WF_READY);
    svc->stats.total_workflows_ready++;
    _emit_event(svc, OZAYN_WOF_EVENT_READY, workflow_id, NULL, NULL,
                NULL, "Workflow ready");
    return OZAYN_WOF_OK;
}

ozayn_wof_err_t ozayn_wof_schedule(ozayn_wof_service_t *svc,
                                    const char *workflow_id) {
    if (!svc) return OZAYN_WOF_ERR_NULL;
    if (!svc->initialized) return OZAYN_WOF_ERR_NOT_INITIALIZED;
    if (!workflow_id) return OZAYN_WOF_ERR_INVALID_PARAM;
    ozayn_wof_workflow_t *wf = _find_workflow(svc, workflow_id);
    if (!wf) return OZAYN_WOF_ERR_NOT_FOUND;
    if (wf->state != OZAYN_WOF_WF_READY)
        return OZAYN_WOF_ERR_STATE_INVALID;
    _wf_transition(svc, wf, OZAYN_WOF_WF_SCHEDULED);
    svc->stats.total_workflows_scheduled++;
    _emit_event(svc, OZAYN_WOF_EVENT_SCHEDULED, workflow_id, NULL, NULL,
                NULL, "Workflow scheduled");
    return OZAYN_WOF_OK;
}

ozayn_wof_err_t ozayn_wof_start(ozayn_wof_service_t *svc,
                                 const char *workflow_id) {
    if (!svc) return OZAYN_WOF_ERR_NULL;
    if (!svc->initialized) return OZAYN_WOF_ERR_NOT_INITIALIZED;
    if (!workflow_id) return OZAYN_WOF_ERR_INVALID_PARAM;
    ozayn_wof_workflow_t *wf = _find_workflow(svc, workflow_id);
    if (!wf) return OZAYN_WOF_ERR_NOT_FOUND;
    if (wf->state != OZAYN_WOF_WF_SCHEDULED &&
        wf->state != OZAYN_WOF_WF_RESUMING)
        return OZAYN_WOF_ERR_STATE_INVALID;
    _wf_transition(svc, wf, OZAYN_WOF_WF_STARTING);
    _wf_transition(svc, wf, OZAYN_WOF_WF_ACTIVE);
    wf->start_time = _now_ms();
    svc->stats.total_workflows_started++;
    _emit_event(svc, OZAYN_WOF_EVENT_STARTED, workflow_id, NULL, NULL,
                NULL, "Workflow started");
    return OZAYN_WOF_OK;
}

ozayn_wof_err_t ozayn_wof_pause(ozayn_wof_service_t *svc,
                                 const char *workflow_id) {
    if (!svc) return OZAYN_WOF_ERR_NULL;
    if (!svc->initialized) return OZAYN_WOF_ERR_NOT_INITIALIZED;
    if (!workflow_id) return OZAYN_WOF_ERR_INVALID_PARAM;
    ozayn_wof_workflow_t *wf = _find_workflow(svc, workflow_id);
    if (!wf) return OZAYN_WOF_ERR_NOT_FOUND;
    if (wf->state != OZAYN_WOF_WF_ACTIVE)
        return OZAYN_WOF_ERR_STATE_INVALID;
    _wf_transition(svc, wf, OZAYN_WOF_WF_PAUSING);
    _wf_transition(svc, wf, OZAYN_WOF_WF_PAUSED);
    _emit_event(svc, OZAYN_WOF_EVENT_PAUSED, workflow_id, NULL, NULL,
                NULL, "Workflow paused");
    return OZAYN_WOF_OK;
}

ozayn_wof_err_t ozayn_wof_resume(ozayn_wof_service_t *svc,
                                  const char *workflow_id) {
    if (!svc) return OZAYN_WOF_ERR_NULL;
    if (!svc->initialized) return OZAYN_WOF_ERR_NOT_INITIALIZED;
    if (!workflow_id) return OZAYN_WOF_ERR_INVALID_PARAM;
    ozayn_wof_workflow_t *wf = _find_workflow(svc, workflow_id);
    if (!wf) return OZAYN_WOF_ERR_NOT_FOUND;
    if (wf->state != OZAYN_WOF_WF_PAUSED)
        return OZAYN_WOF_ERR_STATE_INVALID;
    _wf_transition(svc, wf, OZAYN_WOF_WF_RESUMING);
    _emit_event(svc, OZAYN_WOF_EVENT_RESUMED, workflow_id, NULL, NULL,
                NULL, "Workflow resumed");
    return OZAYN_WOF_OK;
}

ozayn_wof_err_t ozayn_wof_cancel(ozayn_wof_service_t *svc,
                                  const char *workflow_id,
                                  ozayn_wof_close_reason_t reason) {
    if (!svc) return OZAYN_WOF_ERR_NULL;
    if (!svc->initialized) return OZAYN_WOF_ERR_NOT_INITIALIZED;
    if (!workflow_id) return OZAYN_WOF_ERR_INVALID_PARAM;
    ozayn_wof_workflow_t *wf = _find_workflow(svc, workflow_id);
    if (!wf) return OZAYN_WOF_ERR_NOT_FOUND;
    if (_is_terminal_w(wf->state)) return OZAYN_WOF_ERR_STATE_INVALID;
    wf->close_reason = reason;
    _wf_transition(svc, wf, OZAYN_WOF_WF_CANCELLED);
    for (int i = 0; i < OZAYN_WOF_MAX_WORKFLOWS * OZAYN_WOF_MAX_STAGES_PER_WORKFLOW; i++) {
        if (!svc->stages[i].active) continue;
        if (strcmp(svc->stages[i].workflow_id, workflow_id) != 0) continue;
        if (!_is_terminal_s(svc->stages[i].state)) {
            svc->stages[i].state = OZAYN_WOF_STG_CANCELLED;
        }
    }
    svc->stats.total_workflows_cancelled++;
    svc->stats.active_workflows = _count_active_workflows(svc);
    _emit_event(svc, OZAYN_WOF_EVENT_CANCELLED, workflow_id, NULL, NULL,
                NULL, "Workflow cancelled");
    return OZAYN_WOF_OK;
}

ozayn_wof_err_t ozayn_wof_drain(ozayn_wof_service_t *svc,
                                 const char *workflow_id) {
    if (!svc) return OZAYN_WOF_ERR_NULL;
    if (!svc->initialized) return OZAYN_WOF_ERR_NOT_INITIALIZED;
    if (!workflow_id) return OZAYN_WOF_ERR_INVALID_PARAM;
    ozayn_wof_workflow_t *wf = _find_workflow(svc, workflow_id);
    if (!wf) return OZAYN_WOF_ERR_NOT_FOUND;
    if (wf->state != OZAYN_WOF_WF_ACTIVE)
        return OZAYN_WOF_ERR_STATE_INVALID;
    _wf_transition(svc, wf, OZAYN_WOF_WF_DRAINING);
    _emit_event(svc, OZAYN_WOF_EVENT_DRAINING, workflow_id, NULL, NULL,
                NULL, "Workflow draining");
    return OZAYN_WOF_OK;
}

ozayn_wof_err_t ozayn_wof_stop(ozayn_wof_service_t *svc,
                                const char *workflow_id) {
    if (!svc) return OZAYN_WOF_ERR_NULL;
    if (!svc->initialized) return OZAYN_WOF_ERR_NOT_INITIALIZED;
    if (!workflow_id) return OZAYN_WOF_ERR_INVALID_PARAM;
    ozayn_wof_workflow_t *wf = _find_workflow(svc, workflow_id);
    if (!wf) return OZAYN_WOF_ERR_NOT_FOUND;
    if (wf->state != OZAYN_WOF_WF_DRAINING)
        return OZAYN_WOF_ERR_STATE_INVALID;
    _wf_transition(svc, wf, OZAYN_WOF_WF_STOPPING);
    for (int i = 0; i < OZAYN_WOF_MAX_WORKFLOWS * OZAYN_WOF_MAX_STAGES_PER_WORKFLOW; i++) {
        if (!svc->stages[i].active) continue;
        if (strcmp(svc->stages[i].workflow_id, workflow_id) != 0) continue;
        if (svc->stages[i].state == OZAYN_WOF_STG_RUNNING) {
            svc->stages[i].state = OZAYN_WOF_STG_COMPLETED;
        }
    }
    _update_workflow_counts(svc, workflow_id);
    _wf_transition(svc, wf, OZAYN_WOF_WF_SUCCEEDED);
    wf->completion_time = _now_ms();
    svc->stats.total_workflows_succeeded++;
    svc->stats.active_workflows = _count_active_workflows(svc);
    _emit_event(svc, OZAYN_WOF_EVENT_SUCCEEDED, workflow_id, NULL, NULL,
                NULL, "Workflow succeeded");
    return OZAYN_WOF_OK;
}

ozayn_wof_err_t ozayn_wof_remove(ozayn_wof_service_t *svc,
                                  const char *workflow_id) {
    if (!svc) return OZAYN_WOF_ERR_NULL;
    if (!svc->initialized) return OZAYN_WOF_ERR_NOT_INITIALIZED;
    if (!workflow_id) return OZAYN_WOF_ERR_INVALID_PARAM;
    ozayn_wof_workflow_t *wf = _find_workflow(svc, workflow_id);
    if (!wf) return OZAYN_WOF_ERR_NOT_FOUND;
    if (!_is_terminal_w(wf->state)) return OZAYN_WOF_ERR_STATE_INVALID;
    for (int i = 0; i < OZAYN_WOF_MAX_WORKFLOWS * OZAYN_WOF_MAX_STAGES_PER_WORKFLOW; i++) {
        if (svc->stages[i].active &&
            strcmp(svc->stages[i].workflow_id, workflow_id) == 0) {
            memset(&svc->stages[i], 0, sizeof(ozayn_wof_stage_t));
        }
    }
    for (int i = 0; i < OZAYN_WOF_MAX_DEPENDENCIES; i++) {
        if (svc->dependencies[i].active &&
            strcmp(svc->dependencies[i].workflow_id, workflow_id) == 0) {
            memset(&svc->dependencies[i], 0, sizeof(ozayn_wof_dependency_t));
        }
    }
    wf->active = 0;
    return OZAYN_WOF_OK;
}

/* ============================================================
 * STAGE MANAGEMENT
 * ============================================================ */

ozayn_wof_err_t ozayn_wof_stage_add(ozayn_wof_service_t *svc,
                                     const char *workflow_id,
                                     const char *name,
                                     const char *description,
                                     ozayn_wof_stage_type_t stage_type,
                                     const char *pipeline_id,
                                     const char *operation_id,
                                     const char *required_capability,
                                     const char *required_permission,
                                     const char *session_ref,
                                     int timeout_ms,
                                     int is_optional,
                                     int is_critical,
                                     ozayn_wof_failure_policy_t failure_policy,
                                     ozayn_wof_compensation_action_t comp_action,
                                     const char *comp_pipeline_id,
                                     char *out_stage_id,
                                     int out_id_len) {
    if (!svc) return OZAYN_WOF_ERR_NULL;
    if (!svc->initialized) return OZAYN_WOF_ERR_NOT_INITIALIZED;
    if (!workflow_id || !name || !name[0]) return OZAYN_WOF_ERR_INVALID_PARAM;
    if (stage_type < 0 || stage_type >= OZAYN_WOF_STAGE_COUNT)
        return OZAYN_WOF_ERR_INVALID_PARAM;
    if (!out_stage_id || out_id_len <= 0)
        return OZAYN_WOF_ERR_INVALID_PARAM;
    ozayn_wof_workflow_t *wf = _find_workflow(svc, workflow_id);
    if (!wf) return OZAYN_WOF_ERR_NOT_FOUND;
    if (_is_terminal_w(wf->state)) return OZAYN_WOF_ERR_STATE_INVALID;
    if (_count_stages_for_workflow(svc, workflow_id) >= OZAYN_WOF_MAX_STAGES_PER_WORKFLOW)
        return OZAYN_WOF_ERR_LIMIT_REACHED;
    int slot = _find_free_stage_slot(svc);
    if (slot < 0) return OZAYN_WOF_ERR_LIMIT_REACHED;
    ozayn_wof_stage_t *stg = &svc->stages[slot];
    memset(stg, 0, sizeof(ozayn_wof_stage_t));
    stg->active = 1;
    stg->order = wf->stage_count;
    snprintf(stg->stage_id, OZAYN_WOF_MAX_ID_LEN, "STG-%d", slot);
    strncpy(stg->workflow_id, workflow_id, OZAYN_WOF_MAX_ID_LEN - 1);
    strncpy(stg->name, name, OZAYN_WOF_MAX_NAME_LEN - 1);
    if (description) strncpy(stg->description, description, OZAYN_WOF_MAX_DESC_LEN - 1);
    if (pipeline_id) strncpy(stg->pipeline_id, pipeline_id, OZAYN_WOF_MAX_ID_LEN - 1);
    if (operation_id) strncpy(stg->operation_id, operation_id, OZAYN_WOF_MAX_ID_LEN - 1);
    if (required_capability) strncpy(stg->required_capability, required_capability,
                                      OZAYN_WOF_MAX_ID_LEN - 1);
    if (required_permission) strncpy(stg->required_permission, required_permission,
                                      OZAYN_WOF_MAX_ID_LEN - 1);
    if (session_ref) strncpy(stg->security_session_ref, session_ref,
                              OZAYN_WOF_MAX_ID_LEN - 1);
    if (comp_pipeline_id) strncpy(stg->compensation_pipeline_id, comp_pipeline_id,
                                   OZAYN_WOF_MAX_ID_LEN - 1);
    stg->stage_type = stage_type;
    stg->state = OZAYN_WOF_STG_CREATED;
    stg->failure_policy = failure_policy;
    stg->compensation_action = comp_action;
    stg->is_optional = is_optional;
    stg->is_critical = is_critical;
    stg->timeout_ms = timeout_ms > 0 ? timeout_ms : OZAYN_WOF_DEFAULT_STAGE_TIMEOUT_MS;
    stg->max_retries = OZAYN_WOF_DEFAULT_MAX_RETRIES;
    stg->created_time = _now_ms();
    wf->stage_count++;
    strncpy(out_stage_id, stg->stage_id, out_id_len - 1);
    svc->stats.total_stages_created++;
    int total_active = 0;
    for (int i = 0; i < OZAYN_WOF_MAX_WORKFLOWS * OZAYN_WOF_MAX_STAGES_PER_WORKFLOW; i++) {
        if (svc->stages[i].active) total_active++;
    }
    svc->stats.active_stages = total_active;
    if ((uint64_t)total_active > svc->stats.peak_stages) svc->stats.peak_stages = (uint64_t)total_active;
    _emit_event(svc, OZAYN_WOF_EVENT_CREATED, workflow_id, stg->stage_id, NULL,
                NULL, "Stage added");
    return OZAYN_WOF_OK;
}

ozayn_wof_err_t ozayn_wof_stage_remove(ozayn_wof_service_t *svc,
                                        const char *workflow_id,
                                        const char *stage_id) {
    if (!svc) return OZAYN_WOF_ERR_NULL;
    if (!svc->initialized) return OZAYN_WOF_ERR_NOT_INITIALIZED;
    if (!workflow_id || !stage_id) return OZAYN_WOF_ERR_INVALID_PARAM;
    ozayn_wof_stage_t *stg = _find_stage(svc, workflow_id, stage_id);
    if (!stg) return OZAYN_WOF_ERR_NOT_FOUND;
    if (!_is_terminal_s(stg->state)) return OZAYN_WOF_ERR_STATE_INVALID;
    for (int i = 0; i < OZAYN_WOF_MAX_DEPENDENCIES; i++) {
        if (svc->dependencies[i].active &&
            strcmp(svc->dependencies[i].workflow_id, workflow_id) == 0 &&
            (strcmp(svc->dependencies[i].source_stage_id, stage_id) == 0 ||
             strcmp(svc->dependencies[i].target_stage_id, stage_id) == 0)) {
            memset(&svc->dependencies[i], 0, sizeof(ozayn_wof_dependency_t));
        }
    }
    stg->active = 0;
    return OZAYN_WOF_OK;
}

ozayn_wof_err_t ozayn_wof_stage_set_state(ozayn_wof_service_t *svc,
                                           const char *workflow_id,
                                           const char *stage_id,
                                           ozayn_wof_stage_state_t new_state) {
    if (!svc) return OZAYN_WOF_ERR_NULL;
    if (!svc->initialized) return OZAYN_WOF_ERR_NOT_INITIALIZED;
    if (!workflow_id || !stage_id) return OZAYN_WOF_ERR_INVALID_PARAM;
    ozayn_wof_stage_t *stg = _find_stage(svc, workflow_id, stage_id);
    if (!stg) return OZAYN_WOF_ERR_NOT_FOUND;
    ozayn_wof_err_t rc = _stg_transition(svc, stg, new_state);
    if (rc != OZAYN_WOF_OK) return rc;
    if (new_state == OZAYN_WOF_STG_RUNNING) {
        stg->started_time = _now_ms();
    } else if (new_state == OZAYN_WOF_STG_COMPLETED ||
               new_state == OZAYN_WOF_STG_FAILED) {
        stg->completed_time = _now_ms();
    }
    return OZAYN_WOF_OK;
}

/* ============================================================
 * DEPENDENCY MANAGEMENT
 * ============================================================ */

ozayn_wof_err_t ozayn_wof_add_dependency(ozayn_wof_service_t *svc,
                                          const char *workflow_id,
                                          const char *source_stage_id,
                                          const char *target_stage_id) {
    if (!svc) return OZAYN_WOF_ERR_NULL;
    if (!svc->initialized) return OZAYN_WOF_ERR_NOT_INITIALIZED;
    if (!workflow_id || !source_stage_id || !target_stage_id)
        return OZAYN_WOF_ERR_INVALID_PARAM;
    if (strcmp(source_stage_id, target_stage_id) == 0)
        return OZAYN_WOF_ERR_DEPENDENCY_INVALID;
    ozayn_wof_workflow_t *wf = _find_workflow(svc, workflow_id);
    if (!wf) return OZAYN_WOF_ERR_NOT_FOUND;
    if (_is_terminal_w(wf->state)) return OZAYN_WOF_ERR_STATE_INVALID;
    if (_count_deps_for_workflow(svc, workflow_id) >= OZAYN_WOF_MAX_DEPENDENCIES)
        return OZAYN_WOF_ERR_LIMIT_REACHED;
    ozayn_wof_stage_t *src = _find_stage(svc, workflow_id, source_stage_id);
    if (!src) return OZAYN_WOF_ERR_DEPENDENCY_NOT_FOUND;
    ozayn_wof_stage_t *tgt = _find_stage(svc, workflow_id, target_stage_id);
    if (!tgt) return OZAYN_WOF_ERR_DEPENDENCY_NOT_FOUND;
    for (int i = 0; i < OZAYN_WOF_MAX_DEPENDENCIES; i++) {
        if (!svc->dependencies[i].active) continue;
        if (strcmp(svc->dependencies[i].workflow_id, workflow_id) == 0 &&
            strcmp(svc->dependencies[i].source_stage_id, source_stage_id) == 0 &&
            strcmp(svc->dependencies[i].target_stage_id, target_stage_id) == 0) {
            return OZAYN_WOF_ERR_DUPLICATE;
        }
    }
    int slot = _find_free_dep_slot(svc);
    if (slot < 0) return OZAYN_WOF_ERR_LIMIT_REACHED;
    ozayn_wof_dependency_t *dep = &svc->dependencies[slot];
    memset(dep, 0, sizeof(ozayn_wof_dependency_t));
    dep->active = 1;
    snprintf(dep->dependency_id, OZAYN_WOF_MAX_ID_LEN, "DEP-%d", slot);
    strncpy(dep->workflow_id, workflow_id, OZAYN_WOF_MAX_ID_LEN - 1);
    strncpy(dep->source_stage_id, source_stage_id, OZAYN_WOF_MAX_ID_LEN - 1);
    strncpy(dep->target_stage_id, target_stage_id, OZAYN_WOF_MAX_ID_LEN - 1);
    svc->stats.total_dependencies_added++;
    return OZAYN_WOF_OK;
}

ozayn_wof_err_t ozayn_wof_remove_dependency(ozayn_wof_service_t *svc,
                                             const char *workflow_id,
                                             const char *dependency_id) {
    if (!svc) return OZAYN_WOF_ERR_NULL;
    if (!svc->initialized) return OZAYN_WOF_ERR_NOT_INITIALIZED;
    if (!workflow_id || !dependency_id) return OZAYN_WOF_ERR_INVALID_PARAM;
    ozayn_wof_dependency_t *dep = _find_dependency(svc, dependency_id);
    if (!dep) return OZAYN_WOF_ERR_NOT_FOUND;
    if (strcmp(dep->workflow_id, workflow_id) != 0)
        return OZAYN_WOF_ERR_NOT_FOUND;
    dep->active = 0;
    return OZAYN_WOF_OK;
}

/* ============================================================
 * TICK — ORCHESTRATION EVALUATION
 * ============================================================ */

ozayn_wof_err_t ozayn_wof_tick(ozayn_wof_service_t *svc, int64_t now_ms) {
    if (!svc) return OZAYN_WOF_ERR_NULL;
    if (!svc->initialized) return OZAYN_WOF_ERR_NOT_INITIALIZED;
    svc->last_tick_time = now_ms;
    for (int i = 0; i < OZAYN_WOF_MAX_WORKFLOWS; i++) {
        ozayn_wof_workflow_t *wf = &svc->workflows[i];
        if (!wf->active) continue;
        if (_is_terminal_w(wf->state)) continue;
        if (wf->state == OZAYN_WOF_WF_ACTIVE) {
            if (wf->timeout_ms > 0 &&
                (now_ms - wf->start_time) > wf->timeout_ms) {
                wf->close_reason = OZAYN_WOF_CLOSE_TIMEOUT;
                _wf_transition(svc, wf, OZAYN_WOF_WF_TIMEOUT);
                wf->completion_time = now_ms;
                svc->stats.total_workflows_timeout++;
                svc->stats.active_workflows = _count_active_workflows(svc);
                _emit_event(svc, OZAYN_WOF_EVENT_TIMEOUT, wf->workflow_id,
                            NULL, NULL, NULL, "Workflow timed out");
                continue;
            }
        }
        if (wf->state == OZAYN_WOF_WF_WAITING || wf->state == OZAYN_WOF_WF_READY) {
            if (wf->start_deadline_ms > 0 && now_ms > wf->start_deadline_ms) {
                wf->close_reason = OZAYN_WOF_CLOSE_DEADLINE_EXPIRED;
                _wf_transition(svc, wf, OZAYN_WOF_WF_EXPIRED);
                wf->completion_time = now_ms;
                svc->stats.total_workflows_expired++;
                svc->stats.active_workflows = _count_active_workflows(svc);
                _emit_event(svc, OZAYN_WOF_EVENT_EXPIRED, wf->workflow_id,
                            NULL, NULL, NULL, "Workflow expired");
                continue;
            }
        }
        if (wf->state == OZAYN_WOF_WF_ACTIVE ||
            wf->state == OZAYN_WOF_WF_READY) {
            for (int j = 0; j < OZAYN_WOF_MAX_WORKFLOWS * OZAYN_WOF_MAX_STAGES_PER_WORKFLOW; j++) {
                ozayn_wof_stage_t *stg = &svc->stages[j];
                if (!stg->active) continue;
                if (strcmp(stg->workflow_id, wf->workflow_id) != 0) continue;
                if (_is_terminal_s(stg->state)) continue;
                if (stg->state == OZAYN_WOF_STG_CREATED) {
                    _stg_transition(svc, stg, OZAYN_WOF_STG_WAITING_DEPS);
                }
                if (stg->state == OZAYN_WOF_STG_WAITING_DEPS) {
                    if (_deps_satisfied(svc, wf->workflow_id, stg->stage_id)) {
                        _stg_transition(svc, stg, OZAYN_WOF_STG_DEPS_SATISFIED);
                    }
                }
                if (stg->state == OZAYN_WOF_STG_DEPS_SATISFIED) {
                    if (stg->stage_type == OZAYN_WOF_STAGE_CONDITION) {
                        if (_evaluate_condition(svc, wf->workflow_id, stg->stage_id)) {
                            _stg_transition(svc, stg, OZAYN_WOF_STG_ELIGIBLE);
                        } else {
                            stg->state = OZAYN_WOF_STG_BLOCKED;
                        }
                    } else {
                        _stg_transition(svc, stg, OZAYN_WOF_STG_ELIGIBLE);
                    }
                }
                if (stg->state == OZAYN_WOF_STG_RUNNING) {
                    if (stg->timeout_ms > 0 &&
                        stg->started_time > 0 &&
                        (now_ms - stg->started_time) > stg->timeout_ms) {
                        stg->state = OZAYN_WOF_STG_TIMED_OUT;
                    }
                }
            }
            _update_workflow_counts(svc, wf->workflow_id);
            int all_done = 1;
            int any_failed = 0;
            int any_running = 0;
            for (int j = 0; j < OZAYN_WOF_MAX_WORKFLOWS * OZAYN_WOF_MAX_STAGES_PER_WORKFLOW; j++) {
                if (!svc->stages[j].active) continue;
                if (strcmp(svc->stages[j].workflow_id, wf->workflow_id) != 0) continue;
                if (!_is_terminal_s(svc->stages[j].state)) {
                    all_done = 0;
                }
                if (svc->stages[j].state == OZAYN_WOF_STG_RUNNING ||
                    svc->stages[j].state == OZAYN_WOF_STG_SCHEDULED) {
                    any_running = 1;
                }
                if (svc->stages[j].state == OZAYN_WOF_STG_FAILED ||
                    svc->stages[j].state == OZAYN_WOF_STG_TIMED_OUT) {
                    any_failed = 1;
                }
            }
            if (all_done && wf->state == OZAYN_WOF_WF_ACTIVE) {
                if (wf->failed_stage_count > 0 && wf->completed_stage_count > 0) {
                    wf->completion_time = now_ms;
                    _wf_transition(svc, wf, OZAYN_WOF_WF_PARTIALLY_SUCCEEDED);
                    svc->stats.total_workflows_partial++;
                    _emit_event(svc, OZAYN_WOF_EVENT_PARTIAL, wf->workflow_id,
                                NULL, NULL, NULL, "Workflow partially succeeded");
                } else if (wf->failed_stage_count > 0) {
                    wf->completion_time = now_ms;
                    _wf_transition(svc, wf, OZAYN_WOF_WF_FAILED);
                    svc->stats.total_workflows_failed++;
                    _emit_event(svc, OZAYN_WOF_EVENT_FAILED, wf->workflow_id,
                                NULL, NULL, NULL, "Workflow failed");
                } else {
                    wf->completion_time = now_ms;
                    _wf_transition(svc, wf, OZAYN_WOF_WF_SUCCEEDED);
                    svc->stats.total_workflows_succeeded++;
                    _emit_event(svc, OZAYN_WOF_EVENT_SUCCEEDED, wf->workflow_id,
                                NULL, NULL, NULL, "Workflow succeeded");
                }
                svc->stats.active_workflows = _count_active_workflows(svc);
            }
            if (any_failed && !all_done && wf->failure_policy == OZAYN_WOF_FAIL_FAIL_WORKFLOW) {
                for (int j = 0; j < OZAYN_WOF_MAX_WORKFLOWS * OZAYN_WOF_MAX_STAGES_PER_WORKFLOW; j++) {
                    if (!svc->stages[j].active) continue;
                    if (strcmp(svc->stages[j].workflow_id, wf->workflow_id) != 0) continue;
                    if (!_is_terminal_s(svc->stages[j].state)) {
                        svc->stages[j].state = OZAYN_WOF_STG_BLOCKED;
                    }
                }
                wf->completion_time = now_ms;
                _wf_transition(svc, wf, OZAYN_WOF_WF_FAILED);
                svc->stats.total_workflows_failed++;
                svc->stats.active_workflows = _count_active_workflows(svc);
                _emit_event(svc, OZAYN_WOF_EVENT_FAILED, wf->workflow_id,
                            NULL, NULL, NULL, "Workflow failed (fail-workflow policy)");
            }
            (void)any_running;
        }
    }
    return OZAYN_WOF_OK;
}

/* ============================================================
 * QUERY FUNCTIONS
 * ============================================================ */

const ozayn_wof_workflow_t *ozayn_wof_get_workflow(
    const ozayn_wof_service_t *svc, const char *workflow_id) {
    if (!svc || !workflow_id) return NULL;
    for (int i = 0; i < OZAYN_WOF_MAX_WORKFLOWS; i++) {
        if (svc->workflows[i].active &&
            strcmp(svc->workflows[i].workflow_id, workflow_id) == 0) {
            return &svc->workflows[i];
        }
    }
    return NULL;
}

const ozayn_wof_stage_t *ozayn_wof_get_stage(
    const ozayn_wof_service_t *svc, const char *workflow_id,
    const char *stage_id) {
    if (!svc || !workflow_id || !stage_id) return NULL;
    for (int i = 0; i < OZAYN_WOF_MAX_WORKFLOWS * OZAYN_WOF_MAX_STAGES_PER_WORKFLOW; i++) {
        if (svc->stages[i].active &&
            strcmp(svc->stages[i].workflow_id, workflow_id) == 0 &&
            strcmp(svc->stages[i].stage_id, stage_id) == 0) {
            return &svc->stages[i];
        }
    }
    return NULL;
}

int ozayn_wof_workflow_count(const ozayn_wof_service_t *svc) {
    if (!svc) return 0;
    int count = 0;
    for (int i = 0; i < OZAYN_WOF_MAX_WORKFLOWS; i++) {
        if (svc->workflows[i].active) count++;
    }
    return count;
}

int ozayn_wof_workflow_count_by_state(const ozayn_wof_service_t *svc,
                                      ozayn_wof_workflow_state_t state) {
    if (!svc) return 0;
    int count = 0;
    for (int i = 0; i < OZAYN_WOF_MAX_WORKFLOWS; i++) {
        if (svc->workflows[i].active && svc->workflows[i].state == state)
            count++;
    }
    return count;
}

int ozayn_wof_stage_count(const ozayn_wof_service_t *svc,
                           const char *workflow_id) {
    if (!svc || !workflow_id) return 0;
    return _count_stages_for_workflow(svc, workflow_id);
}

int ozayn_wof_dependency_count(const ozayn_wof_service_t *svc,
                                const char *workflow_id) {
    if (!svc || !workflow_id) return 0;
    return _count_deps_for_workflow(svc, workflow_id);
}

int ozayn_wof_is_terminal(ozayn_wof_workflow_state_t state) {
    return _is_terminal_w(state);
}

int ozayn_wof_is_stage_terminal(ozayn_wof_stage_state_t state) {
    return _is_terminal_s(state);
}

int ozayn_wof_concurrent_workflows(const ozayn_wof_service_t *svc) {
    if (!svc) return 0;
    return _count_active_workflows(svc);
}

int ozayn_wof_concurrent_stages(const ozayn_wof_service_t *svc,
                                 const char *workflow_id) {
    if (!svc || !workflow_id) return 0;
    return _count_running_stages(svc, workflow_id);
}

/* ============================================================
 * EVENT FUNCTIONS
 * ============================================================ */

ozayn_wof_err_t ozayn_wof_emit_event(ozayn_wof_service_t *svc,
                                      ozayn_wof_event_type_t event_type,
                                      const char *workflow_id,
                                      const char *stage_id,
                                      const char *pipeline_id,
                                      const char *operation_id,
                                      const char *message) {
    if (!svc) return OZAYN_WOF_ERR_NULL;
    if (!svc->initialized) return OZAYN_WOF_ERR_NOT_INITIALIZED;
    _emit_event(svc, event_type, workflow_id, stage_id, pipeline_id,
                operation_id, message);
    return OZAYN_WOF_OK;
}

const ozayn_wof_event_t *ozayn_wof_get_event(
    const ozayn_wof_service_t *svc, int index) {
    if (!svc || index < 0 || index >= OZAYN_WOF_MAX_EVENTS) return NULL;
    if (!svc->events[index].active) return NULL;
    return &svc->events[index];
}

int ozayn_wof_event_count(const ozayn_wof_service_t *svc) {
    if (!svc) return 0;
    int count = 0;
    for (int i = 0; i < OZAYN_WOF_MAX_EVENTS; i++) {
        if (svc->events[i].active) count++;
    }
    return count;
}

/* ============================================================
 * CLEANUP FUNCTIONS
 * ============================================================ */

ozayn_wof_err_t ozayn_wof_cleanup_terminal(ozayn_wof_service_t *svc) {
    if (!svc) return OZAYN_WOF_ERR_NULL;
    if (!svc->initialized) return OZAYN_WOF_ERR_NOT_INITIALIZED;
    for (int i = 0; i < OZAYN_WOF_MAX_WORKFLOWS; i++) {
        if (svc->workflows[i].active && _is_terminal_w(svc->workflows[i].state)) {
            const char *wid = svc->workflows[i].workflow_id;
            for (int j = 0; j < OZAYN_WOF_MAX_WORKFLOWS * OZAYN_WOF_MAX_STAGES_PER_WORKFLOW; j++) {
                if (svc->stages[j].active &&
                    strcmp(svc->stages[j].workflow_id, wid) == 0) {
                    memset(&svc->stages[j], 0, sizeof(ozayn_wof_stage_t));
                }
            }
            for (int j = 0; j < OZAYN_WOF_MAX_DEPENDENCIES; j++) {
                if (svc->dependencies[j].active &&
                    strcmp(svc->dependencies[j].workflow_id, wid) == 0) {
                    memset(&svc->dependencies[j], 0, sizeof(ozayn_wof_dependency_t));
                }
            }
            svc->workflows[i].active = 0;
        }
    }
    svc->stats.active_workflows = _count_active_workflows(svc);
    return OZAYN_WOF_OK;
}

ozayn_wof_err_t ozayn_wof_cleanup_expired(ozayn_wof_service_t *svc, int64_t now_ms) {
    if (!svc) return OZAYN_WOF_ERR_NULL;
    if (!svc->initialized) return OZAYN_WOF_ERR_NOT_INITIALIZED;
    for (int i = 0; i < OZAYN_WOF_MAX_WORKFLOWS; i++) {
        ozayn_wof_workflow_t *wf = &svc->workflows[i];
        if (!wf->active) continue;
        if (_is_terminal_w(wf->state)) continue;
        if (wf->execution_deadline_ms > 0 && now_ms > wf->execution_deadline_ms) {
            wf->close_reason = OZAYN_WOF_CLOSE_DEADLINE_EXPIRED;
            wf->state = OZAYN_WOF_WF_EXPIRED;
            wf->completion_time = now_ms;
            svc->stats.total_workflows_expired++;
        }
    }
    svc->stats.active_workflows = _count_active_workflows(svc);
    return OZAYN_WOF_OK;
}

ozayn_wof_err_t ozayn_wof_cleanup_all(ozayn_wof_service_t *svc) {
    if (!svc) return OZAYN_WOF_ERR_NULL;
    if (!svc->initialized) return OZAYN_WOF_ERR_NOT_INITIALIZED;
    for (int i = 0; i < OZAYN_WOF_MAX_WORKFLOWS; i++) {
        if (svc->workflows[i].active) {
            svc->workflows[i].active = 0;
        }
    }
    for (int i = 0; i < OZAYN_WOF_MAX_WORKFLOWS * OZAYN_WOF_MAX_STAGES_PER_WORKFLOW; i++) {
        if (svc->stages[i].active) {
            svc->stages[i].active = 0;
        }
    }
    for (int i = 0; i < OZAYN_WOF_MAX_DEPENDENCIES; i++) {
        if (svc->dependencies[i].active) {
            svc->dependencies[i].active = 0;
        }
    }
    svc->stats.active_workflows = 0;
    svc->stats.active_stages = 0;
    return OZAYN_WOF_OK;
}

/* ============================================================
 * STATISTICS
 * ============================================================ */

const ozayn_wof_stats_t *ozayn_wof_get_stats(const ozayn_wof_service_t *svc) {
    if (!svc) return NULL;
    return &svc->stats;
}

ozayn_wof_err_t ozayn_wof_reset_stats(ozayn_wof_service_t *svc) {
    if (!svc) return OZAYN_WOF_ERR_NULL;
    if (!svc->initialized) return OZAYN_WOF_ERR_NOT_INITIALIZED;
    memset(&svc->stats, 0, sizeof(ozayn_wof_stats_t));
    return OZAYN_WOF_OK;
}

/* ============================================================
 * VALIDATION
 * ============================================================ */

int ozayn_wof_validate_workflow(const ozayn_wof_service_t *svc,
                                 const char *workflow_id) {
    if (!svc || !workflow_id) return 0;
    const ozayn_wof_workflow_t *wf = ozayn_wof_get_workflow(svc, workflow_id);
    if (!wf) return 0;
    if (!wf->name[0]) return 0;
    if (wf->workflow_type < 0 || wf->workflow_type >= OZAYN_WOF_TYPE_COUNT) return 0;
    if (wf->state < 0 || wf->state >= OZAYN_WOF_WF_STATE_COUNT) return 0;
    return 1;
}

int ozayn_wof_validate_stage(const ozayn_wof_service_t *svc,
                              const char *workflow_id,
                              const char *stage_id) {
    if (!svc || !workflow_id || !stage_id) return 0;
    const ozayn_wof_stage_t *stg = ozayn_wof_get_stage(svc, workflow_id, stage_id);
    if (!stg) return 0;
    if (!stg->name[0]) return 0;
    if (stg->stage_type < 0 || stg->stage_type >= OZAYN_WOF_STAGE_COUNT) return 0;
    if (stg->state < 0 || stg->state >= OZAYN_WOF_STG_STATE_COUNT) return 0;
    return 1;
}

int ozayn_wof_validate_config(const ozayn_wof_service_config_t *config) {
    if (!config) return 0;
    return 1;
}

int ozayn_wof_is_valid_transition(ozayn_wof_workflow_state_t from,
                                   ozayn_wof_workflow_state_t to) {
    if (!_transitions_initialized) _init_transitions();
    if (from < 0 || from >= OZAYN_WOF_WF_STATE_COUNT) return 0;
    if (to < 0 || to >= OZAYN_WOF_WF_STATE_COUNT) return 0;
    return _wf_transitions[from][to];
}

int ozayn_wof_is_valid_stage_transition(ozayn_wof_stage_state_t from,
                                         ozayn_wof_stage_state_t to) {
    if (!_transitions_initialized) _init_transitions();
    if (from < 0 || from >= OZAYN_WOF_STG_STATE_COUNT) return 0;
    if (to < 0 || to >= OZAYN_WOF_STG_STATE_COUNT) return 0;
    return _stg_transitions[from][to];
}

/* ============================================================
 * NAME HELPERS
 * ============================================================ */

const char *ozayn_wof_err_name(ozayn_wof_err_t err) {
    switch (err) {
        case OZAYN_WOF_OK: return "OK";
        case OZAYN_WOF_ERR_NULL: return "NULL";
        case OZAYN_WOF_ERR_NOT_INITIALIZED: return "NOT_INITIALIZED";
        case OZAYN_WOF_ERR_ALREADY_INIT: return "ALREADY_INIT";
        case OZAYN_WOF_ERR_INVALID_PARAM: return "INVALID_PARAM";
        case OZAYN_WOF_ERR_LIMIT_REACHED: return "LIMIT_REACHED";
        case OZAYN_WOF_ERR_NOT_FOUND: return "NOT_FOUND";
        case OZAYN_WOF_ERR_DUPLICATE: return "DUPLICATE";
        case OZAYN_WOF_ERR_STATE_INVALID: return "STATE_INVALID";
        case OZAYN_WOF_ERR_DEPENDENCY_INVALID: return "DEPENDENCY_INVALID";
        case OZAYN_WOF_ERR_DEPENDENCY_NOT_FOUND: return "DEPENDENCY_NOT_FOUND";
        case OZAYN_WOF_ERR_DEPENDENCY_CYCLE: return "DEPENDENCY_CYCLE";
        case OZAYN_WOF_ERR_DEPENDENCY_FAILED: return "DEPENDENCY_FAILED";
        case OZAYN_WOF_ERR_DEPENDENCY_TIMEOUT: return "DEPENDENCY_TIMEOUT";
        case OZAYN_WOF_ERR_AUTH_FAILED: return "AUTH_FAILED";
        case OZAYN_WOF_ERR_PERMISSION_DENIED: return "PERMISSION_DENIED";
        case OZAYN_WOF_ERR_SESSION_INVALID: return "SESSION_INVALID";
        case OZAYN_WOF_ERR_POLICY_DENIED: return "POLICY_DENIED";
        case OZAYN_WOF_ERR_SAFETY_CHECK_FAILED: return "SAFETY_CHECK_FAILED";
        case OZAYN_WOF_ERR_SAFETY_RECHECK_FAILED: return "SAFETY_RECHECK_FAILED";
        case OZAYN_WOF_ERR_RESOURCE_UNAVAILABLE: return "RESOURCE_UNAVAILABLE";
        case OZAYN_WOF_ERR_RESOURCE_LIMIT: return "RESOURCE_LIMIT";
        case OZAYN_WOF_ERR_RESERVATION_FAILED: return "RESERVATION_FAILED";
        case OZAYN_WOF_ERR_PIPELINE_INVALID: return "PIPELINE_INVALID";
        case OZAYN_WOF_ERR_PIPELINE_NOT_FOUND: return "PIPELINE_NOT_FOUND";
        case OZAYN_WOF_ERR_PIPELINE_UNAVAILABLE: return "PIPELINE_UNAVAILABLE";
        case OZAYN_WOF_ERR_PIPELINE_CONFLICT: return "PIPELINE_CONFLICT";
        case OZAYN_WOF_ERR_TIMEOUT: return "TIMEOUT";
        case OZAYN_WOF_ERR_CANCELLED: return "CANCELLED";
        case OZAYN_WOF_ERR_EXPIRED: return "EXPIRED";
        case OZAYN_WOF_ERR_CONCURRENCY: return "CONCURRENCY";
        case OZAYN_WOF_ERR_CONFIGURATION: return "CONFIGURATION";
        case OZAYN_WOF_ERR_EVENT_ERROR: return "EVENT_ERROR";
        case OZAYN_WOF_ERR_HISTORY_ERROR: return "HISTORY_ERROR";
        case OZAYN_WOF_ERR_DIAGNOSTIC_ERROR: return "DIAGNOSTIC_ERROR";
        case OZAYN_WOF_ERR_ORCHESTRATION_ERROR: return "ORCHESTRATION_ERROR";
        case OZAYN_WOF_ERR_REJECTED: return "REJECTED";
        case OZAYN_WOF_ERR_UNAVAILABLE: return "UNAVAILABLE";
        case OZAYN_WOF_ERR_STAGE_INVALID: return "STAGE_INVALID";
        case OZAYN_WOF_ERR_STAGE_NOT_FOUND: return "STAGE_NOT_FOUND";
        case OZAYN_WOF_ERR_STAGE_CONFLICT: return "STAGE_CONFLICT";
        case OZAYN_WOF_ERR_STAGE_UNAVAILABLE: return "STAGE_UNAVAILABLE";
        case OZAYN_WOF_ERR_COMPENSATION_FAILED: return "COMPENSATION_FAILED";
        case OZAYN_WOF_ERR_PARTIALLY_SUCCEEDED: return "PARTIALLY_SUCCEEDED";
    }
    return "UNKNOWN";
}

const char *ozayn_wof_workflow_state_name(ozayn_wof_workflow_state_t state) {
    static const char *names[] = {
        "CREATED", "VALIDATING", "AUTHORIZED", "WAITING", "READY",
        "SCHEDULED", "STARTING", "ACTIVE", "PAUSING", "PAUSED",
        "RESUMING", "DRAINING", "STOPPING", "SUCCEEDED", "FAILED",
        "PARTIALLY_SUCCEEDED", "CANCELLED", "TIMEOUT", "EXPIRED",
        "REVOKED", "REJECTED", "UNAVAILABLE"
    };
    if (state < 0 || state >= OZAYN_WOF_WF_STATE_COUNT) return "INVALID";
    return names[state];
}

const char *ozayn_wof_workflow_type_name(ozayn_wof_workflow_type_t type) {
    static const char *names[] = {"SEQUENTIAL", "PARALLEL", "BOUNDED_PARALLEL"};
    if (type < 0 || type >= OZAYN_WOF_TYPE_COUNT) return "INVALID";
    return names[type];
}

const char *ozayn_wof_stage_type_name(ozayn_wof_stage_type_t type) {
    static const char *names[] = {"PIPELINE", "OPERATION", "WAIT", "CONDITION", "GROUP"};
    if (type < 0 || type >= OZAYN_WOF_STAGE_COUNT) return "INVALID";
    return names[type];
}

const char *ozayn_wof_stage_state_name(ozayn_wof_stage_state_t state) {
    static const char *names[] = {
        "CREATED", "WAITING_DEPS", "DEPS_SATISFIED", "ELIGIBLE",
        "SUBMITTED", "SCHEDULED", "RUNNING", "PAUSED",
        "COMPLETED", "FAILED", "SKIPPED", "CANCELLED",
        "TIMED_OUT", "BLOCKED"
    };
    if (state < 0 || state >= OZAYN_WOF_STG_STATE_COUNT) return "INVALID";
    return names[state];
}

const char *ozayn_wof_condition_type_name(ozayn_wof_condition_type_t cond) {
    static const char *names[] = {
        "RESOURCE_AVAILABLE", "DEVICE_AVAILABLE", "PIPELINE_COMPLETED",
        "PIPELINE_FAILED", "HEALTH_STATE", "CAPABILITY_STATE",
        "OPERATION_RESULT"
    };
    if (cond < 0 || cond >= OZAYN_WOF_COND_COUNT) return "INVALID";
    return names[cond];
}

const char *ozayn_wof_failure_policy_name(ozayn_wof_failure_policy_t policy) {
    static const char *names[] = {
        "FAIL_WORKFLOW", "SKIP_DEPENDENTS", "CONTINUE_INDEPENDENT", "MARK_PARTIAL"
    };
    if (policy < 0 || policy >= OZAYN_WOF_FAIL_COUNT) return "INVALID";
    return names[policy];
}

const char *ozayn_wof_compensation_action_name(ozayn_wof_compensation_action_t action) {
    static const char *names[] = {
        "NONE", "NOTIFY", "REVERSE_OPERATION", "RUN_COMPENSATION_PIPELINE"
    };
    if (action < 0 || action >= OZAYN_WOF_COMP_COUNT) return "INVALID";
    return names[action];
}

const char *ozayn_wof_concurrency_policy_name(ozayn_wof_concurrency_policy_t policy) {
    static const char *names[] = {"SEQUENTIAL", "PARALLEL", "BOUNDED"};
    if (policy < 0 || policy >= OZAYN_WOF_CONC_COUNT) return "INVALID";
    return names[policy];
}

const char *ozayn_wof_event_type_name(ozayn_wof_event_type_t type) {
    static const char *names[] = {
        "CREATED", "VALIDATING", "AUTHORIZED", "REJECTED", "READY",
        "SCHEDULED", "STARTED", "STAGE_READY", "STAGE_STARTED",
        "STAGE_COMPLETED", "STAGE_FAILED", "STAGE_BLOCKED",
        "STAGE_SKIPPED", "PAUSED", "RESUMED", "DRAINING",
        "CANCELLED", "TIMEOUT", "EXPIRED", "FAILED", "PARTIAL",
        "SUCCEEDED", "COMPENSATION_STARTED", "COMPENSATION_COMPLETED",
        "COMPENSATION_FAILED", "ORCHESTRATOR_STARTED", "ORCHESTRATOR_STOPPED"
    };
    if (type < 0 || type >= OZAYN_WOF_EVENT_COUNT) return "INVALID";
    return names[type];
}

const char *ozayn_wof_close_reason_name(ozayn_wof_close_reason_t reason) {
    static const char *names[] = {
        "MANUAL_CANCEL", "DEPENDENCY_FAILED", "PIPELINE_FAILED",
        "RESOURCE_EXHAUSTED", "DEVICE_UNAVAILABLE", "AUTH_REVOKED",
        "SAFETY_DENIED", "POLICY_DENIED", "TIMEOUT", "DEADLINE_EXPIRED",
        "CONFLICT", "CONCURRENCY_LIMIT", "SESSION_EXPIRED", "SHUTDOWN",
        "ORCHESTRATION_ERROR", "PARTIAL_COMPLETION"
    };
    if (reason < 0 || reason >= OZAYN_WOF_CLOSE_COUNT) return "INVALID";
    return names[reason];
}
