#include "workflow_recovery.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

/* ============================================================
 * STATIC GLOBAL STATE
 * ============================================================ */

static ozayn_wfr_service_t _svc;

/* ============================================================
 * HELPER — TIMESTAMP
 * ============================================================ */

static int64_t _now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

/* ============================================================
 * HELPER — FAILURE STATE MACHINE
 * ============================================================ */

static int _failure_transitions[OZAYN_WFR_FS_STATE_COUNT][OZAYN_WFR_FS_STATE_COUNT];
static int _ft_initialized = 0;

static void _init_failure_transitions(void) {
    if (_ft_initialized) return;
    memset(_failure_transitions, 0, sizeof(_failure_transitions));

    _failure_transitions[OZAYN_WFR_FS_DETECTED][OZAYN_WFR_FS_CLASSIFIED] = 1;
    _failure_transitions[OZAYN_WFR_FS_DETECTED][OZAYN_WFR_FS_CLOSED] = 1;

    _failure_transitions[OZAYN_WFR_FS_CLASSIFIED][OZAYN_WFR_FS_ASSESSING] = 1;
    _failure_transitions[OZAYN_WFR_FS_CLASSIFIED][OZAYN_WFR_FS_CONTAINING] = 1;
    _failure_transitions[OZAYN_WFR_FS_CLASSIFIED][OZAYN_WFR_FS_ACKNOWLEDGED] = 1;
    _failure_transitions[OZAYN_WFR_FS_CLASSIFIED][OZAYN_WFR_FS_CLOSED] = 1;

    _failure_transitions[OZAYN_WFR_FS_ASSESSING][OZAYN_WFR_FS_CONTAINING] = 1;
    _failure_transitions[OZAYN_WFR_FS_ASSESSING][OZAYN_WFR_FS_RECOVERING] = 1;
    _failure_transitions[OZAYN_WFR_FS_ASSESSING][OZAYN_WFR_FS_RECOVERED] = 1;
    _failure_transitions[OZAYN_WFR_FS_ASSESSING][OZAYN_WFR_FS_PARTIALLY_RECOVERED] = 1;
    _failure_transitions[OZAYN_WFR_FS_ASSESSING][OZAYN_WFR_FS_UNRECOVERABLE] = 1;
    _failure_transitions[OZAYN_WFR_FS_ASSESSING][OZAYN_WFR_FS_ESCALATED] = 1;
    _failure_transitions[OZAYN_WFR_FS_ASSESSING][OZAYN_WFR_FS_ACKNOWLEDGED] = 1;
    _failure_transitions[OZAYN_WFR_FS_ASSESSING][OZAYN_WFR_FS_CLOSED] = 1;

    _failure_transitions[OZAYN_WFR_FS_CONTAINING][OZAYN_WFR_FS_RECOVERING] = 1;
    _failure_transitions[OZAYN_WFR_FS_CONTAINING][OZAYN_WFR_FS_UNRECOVERABLE] = 1;
    _failure_transitions[OZAYN_WFR_FS_CONTAINING][OZAYN_WFR_FS_ESCALATED] = 1;
    _failure_transitions[OZAYN_WFR_FS_CONTAINING][OZAYN_WFR_FS_CLOSED] = 1;

    _failure_transitions[OZAYN_WFR_FS_RECOVERING][OZAYN_WFR_FS_RECOVERED] = 1;
    _failure_transitions[OZAYN_WFR_FS_RECOVERING][OZAYN_WFR_FS_PARTIALLY_RECOVERED] = 1;
    _failure_transitions[OZAYN_WFR_FS_RECOVERING][OZAYN_WFR_FS_UNRECOVERABLE] = 1;
    _failure_transitions[OZAYN_WFR_FS_RECOVERING][OZAYN_WFR_FS_ESCALATED] = 1;
    _failure_transitions[OZAYN_WFR_FS_RECOVERING][OZAYN_WFR_FS_ACKNOWLEDGED] = 1;
    _failure_transitions[OZAYN_WFR_FS_RECOVERING][OZAYN_WFR_FS_CLOSED] = 1;

    _failure_transitions[OZAYN_WFR_FS_RECOVERED][OZAYN_WFR_FS_ACKNOWLEDGED] = 1;
    _failure_transitions[OZAYN_WFR_FS_RECOVERED][OZAYN_WFR_FS_CLOSED] = 1;

    _failure_transitions[OZAYN_WFR_FS_PARTIALLY_RECOVERED][OZAYN_WFR_FS_ACKNOWLEDGED] = 1;
    _failure_transitions[OZAYN_WFR_FS_PARTIALLY_RECOVERED][OZAYN_WFR_FS_CLOSED] = 1;

    _failure_transitions[OZAYN_WFR_FS_UNRECOVERABLE][OZAYN_WFR_FS_ESCALATED] = 1;
    _failure_transitions[OZAYN_WFR_FS_UNRECOVERABLE][OZAYN_WFR_FS_ACKNOWLEDGED] = 1;
    _failure_transitions[OZAYN_WFR_FS_UNRECOVERABLE][OZAYN_WFR_FS_CLOSED] = 1;

    _failure_transitions[OZAYN_WFR_FS_ESCALATED][OZAYN_WFR_FS_ACKNOWLEDGED] = 1;
    _failure_transitions[OZAYN_WFR_FS_ESCALATED][OZAYN_WFR_FS_CLOSED] = 1;

    _failure_transitions[OZAYN_WFR_FS_ACKNOWLEDGED][OZAYN_WFR_FS_CLOSED] = 1;

    _ft_initialized = 1;
}

/* ============================================================
 * HELPER — FIND FUNCTIONS
 * ============================================================ */

static ozayn_wfr_failure_record_t *_find_failure(ozayn_wfr_service_t *svc,
                                                   const char *failure_id) {
    if (!svc || !failure_id) return NULL;
    for (int i = 0; i < OZAYN_WFR_MAX_FAILURES; i++) {
        if (svc->failures[i].active &&
            strcmp(svc->failures[i].failure_id, failure_id) == 0) {
            return &svc->failures[i];
        }
    }
    return NULL;
}

static int _find_free_failure_slot(const ozayn_wfr_service_t *svc) {
    for (int i = 0; i < OZAYN_WFR_MAX_FAILURES; i++) {
        if (!svc->failures[i].active) return i;
    }
    return -1;
}

static ozayn_wfr_recovery_decision_t *_find_decision(ozayn_wfr_service_t *svc,
                                                      const char *decision_id) {
    if (!svc || !decision_id) return NULL;
    for (int i = 0; i < OZAYN_WFR_MAX_RECOVERY_RECORDS; i++) {
        if (svc->decisions[i].active &&
            strcmp(svc->decisions[i].decision_id, decision_id) == 0) {
            return &svc->decisions[i];
        }
    }
    return NULL;
}

static int _find_free_decision_slot(const ozayn_wfr_service_t *svc) {
    for (int i = 0; i < OZAYN_WFR_MAX_RECOVERY_RECORDS; i++) {
        if (!svc->decisions[i].active) return i;
    }
    return -1;
}

static int _find_free_history_slot(const ozayn_wfr_service_t *svc) {
    for (int i = 0; i < OZAYN_WFR_MAX_RECOVERY_HISTORY; i++) {
        if (!svc->history[i].active) return i;
    }
    return -1;
}

static int _is_failure_terminal(ozayn_wfr_failure_state_t s) {
    return s == OZAYN_WFR_FS_RECOVERED ||
           s == OZAYN_WFR_FS_PARTIALLY_RECOVERED ||
           s == OZAYN_WFR_FS_UNRECOVERABLE ||
           s == OZAYN_WFR_FS_ACKNOWLEDGED ||
           s == OZAYN_WFR_FS_CLOSED;
}

static int _count_failures_by_state(const ozayn_wfr_service_t *svc,
                                     ozayn_wfr_failure_state_t state) {
    int count = 0;
    for (int i = 0; i < OZAYN_WFR_MAX_FAILURES; i++) {
        if (svc->failures[i].active && svc->failures[i].state == state)
            count++;
    }
    return count;
}

static int _count_active_failures(const ozayn_wfr_service_t *svc) {
    int count = 0;
    for (int i = 0; i < OZAYN_WFR_MAX_FAILURES; i++) {
        if (svc->failures[i].active && !_is_failure_terminal(svc->failures[i].state))
            count++;
    }
    return count;
}

/* ============================================================
 * HELPER — EVENT EMISSION
 * ============================================================ */

static void _emit_event(ozayn_wfr_service_t *svc,
                          ozayn_wfr_event_type_t event_type,
                          const char *failure_id,
                          const char *workflow_id,
                          const char *stage_id,
                          const char *message) {
    if (!svc) return;
    int idx = -1;
    for (int i = 0; i < OZAYN_WFR_MAX_EVENTS; i++) {
        if (!svc->events[i].active) { idx = i; break; }
    }
    if (idx < 0) {
        idx = 0;
        memset(&svc->events[0], 0, sizeof(ozayn_wfr_event_t));
    }
    ozayn_wfr_event_t *e = &svc->events[idx];
    e->active = 1;
    e->event_type = event_type;
    e->timestamp = _now_ms();
    e->sequence = svc->event_sequence++;
    snprintf(e->event_id, OZAYN_WFR_MAX_ID_LEN, "WFR-EVT-%lu",
             (unsigned long)(e->sequence));
    if (failure_id) strncpy(e->failure_id, failure_id, OZAYN_WFR_MAX_ID_LEN - 1);
    if (workflow_id) strncpy(e->workflow_id, workflow_id, OZAYN_WFR_MAX_ID_LEN - 1);
    if (stage_id) strncpy(e->stage_id, stage_id, OZAYN_WFR_MAX_ID_LEN - 1);
    if (message) strncpy(e->message, message, OZAYN_WFR_MAX_DESC_LEN - 1);
    svc->stats.total_events_emitted++;
}

/* ============================================================
 * HELPER — TRANSITION WITH VALIDATION
 * ============================================================ */

static ozayn_wfr_err_t _failure_transition(ozayn_wfr_service_t *svc,
                                            ozayn_wfr_failure_record_t *rec,
                                            ozayn_wfr_failure_state_t new_state) {
    if (!ozayn_wfr_is_valid_failure_transition(rec->state, new_state))
        return OZAYN_WFR_ERR_STATE_INVALID;
    rec->state = new_state;
    int64_t now = _now_ms();
    switch (new_state) {
        case OZAYN_WFR_FS_CLASSIFIED:  rec->classified_time = now; break;
        case OZAYN_WFR_FS_CONTAINING:  rec->contained_time = now; break;
        case OZAYN_WFR_FS_RECOVERED:
        case OZAYN_WFR_FS_PARTIALLY_RECOVERED:
        case OZAYN_WFR_FS_UNRECOVERABLE:
        case OZAYN_WFR_FS_CLOSED:      rec->resolved_time = now; break;
        default: break;
    }
    return OZAYN_WFR_OK;
}

/* ============================================================
 * HELPER — COMPUTE BACKOFF DELAY
 * ============================================================ */

static int64_t _compute_backoff(ozayn_wfr_backoff_strategy_t strategy,
                                 int attempt,
                                 int64_t base_delay_ms,
                                 int64_t max_delay_ms) {
    if (attempt <= 0) attempt = 1;
    switch (strategy) {
        case OZAYN_WFR_BACKOFF_IMMEDIATE:
            return 0;
        case OZAYN_WFR_BACKOFF_FIXED_DELAY:
            return base_delay_ms;
        case OZAYN_WFR_BACKOFF_BOUNDED_EXPONENTIAL: {
            int64_t delay = base_delay_ms;
            for (int i = 1; i < attempt && delay < max_delay_ms; i++)
                delay *= 2;
            if (delay > max_delay_ms) delay = max_delay_ms;
            return delay;
        }
        default:
            return base_delay_ms;
    }
}

/* ============================================================
 * LIFECYCLE
 * ============================================================ */

ozayn_wfr_err_t ozayn_wfr_service_init(ozayn_wfr_service_t *svc,
                                        const ozayn_wfr_service_config_t *config) {
    if (!svc) return OZAYN_WFR_ERR_NULL;
    if (svc->initialized) return OZAYN_WFR_ERR_ALREADY_INIT;
    if (!config) return OZAYN_WFR_ERR_INVALID_PARAM;
    memset(svc, 0, sizeof(ozayn_wfr_service_t));
    svc->config = *config;
    svc->init_time = _now_ms();
    svc->event_sequence = 0;
    svc->last_tick_time = 0;
    svc->initialized = 1;
    _init_failure_transitions();
    _emit_event(svc, OZAYN_WFR_EVENT_RECOVERY_STARTED, NULL, NULL, NULL,
                "Recovery subsystem initialized");
    return OZAYN_WFR_OK;
}

ozayn_wfr_err_t ozayn_wfr_service_shutdown(ozayn_wfr_service_t *svc) {
    if (!svc) return OZAYN_WFR_ERR_NULL;
    if (!svc->initialized) return OZAYN_WFR_ERR_NOT_INITIALIZED;
    _emit_event(svc, OZAYN_WFR_EVENT_RECOVERY_FAILED, NULL, NULL, NULL,
                "Recovery subsystem shutting down");
    svc->initialized = 0;
    return OZAYN_WFR_OK;
}

int ozayn_wfr_is_initialized(const ozayn_wfr_service_t *svc) {
    if (!svc) return 0;
    return svc->initialized;
}

ozayn_wfr_service_t *ozayn_wfr_get_global(void) {
    return &_svc;
}

/* ============================================================
 * FAILURE RECORD FUNCTIONS
 * ============================================================ */

ozayn_wfr_err_t ozayn_wfr_record_failure(ozayn_wfr_service_t *svc,
                                          const char *workflow_id,
                                          const char *stage_id,
                                          const char *operation_id,
                                          const char *pipeline_id,
                                          const char *request_id,
                                          const char *source_component,
                                          ozayn_wfr_failure_category_t category,
                                          ozayn_wfr_failure_severity_t severity,
                                          int error_code,
                                          const char *description,
                                          char *out_failure_id,
                                          int out_id_len) {
    if (!svc) return OZAYN_WFR_ERR_NULL;
    if (!svc->initialized) return OZAYN_WFR_ERR_NOT_INITIALIZED;
    if (!out_failure_id || out_id_len < 8) return OZAYN_WFR_ERR_INVALID_PARAM;
    if (category < 0 || category >= OZAYN_WFR_CAT_COUNT) return OZAYN_WFR_ERR_INVALID_PARAM;
    if (severity < 0 || severity >= OZAYN_WFR_SEV_COUNT) return OZAYN_WFR_ERR_INVALID_PARAM;
    int slot = _find_free_failure_slot(svc);
    if (slot < 0) return OZAYN_WFR_ERR_LIMIT_REACHED;
    ozayn_wfr_failure_record_t *rec = &svc->failures[slot];
    memset(rec, 0, sizeof(ozayn_wfr_failure_record_t));
    rec->active = 1;
    snprintf(rec->failure_id, OZAYN_WFR_MAX_ID_LEN, "WFR-FAIL-%d", slot);
    if (workflow_id) strncpy(rec->workflow_id, workflow_id, OZAYN_WFR_MAX_ID_LEN - 1);
    if (stage_id) strncpy(rec->stage_id, stage_id, OZAYN_WFR_MAX_ID_LEN - 1);
    if (operation_id) strncpy(rec->operation_id, operation_id, OZAYN_WFR_MAX_ID_LEN - 1);
    if (pipeline_id) strncpy(rec->pipeline_id, pipeline_id, OZAYN_WFR_MAX_ID_LEN - 1);
    if (request_id) strncpy(rec->request_id, request_id, OZAYN_WFR_MAX_ID_LEN - 1);
    if (source_component) strncpy(rec->source_component, source_component,
                                    OZAYN_WFR_MAX_ID_LEN - 1);
    if (description) strncpy(rec->description, description, OZAYN_WFR_MAX_DESC_LEN - 1);
    rec->category = category;
    rec->severity = severity;
    rec->state = OZAYN_WFR_FS_DETECTED;
    rec->error_code = error_code;
    rec->detected_time = _now_ms();
    rec->failure_time = rec->detected_time;
    strncpy(out_failure_id, rec->failure_id, out_id_len - 1);
    svc->stats.total_failures_detected++;
    svc->stats.active_failures = _count_active_failures(svc);
    if (svc->stats.active_failures > svc->stats.peak_failures)
        svc->stats.peak_failures = svc->stats.active_failures;
    _emit_event(svc, OZAYN_WFR_EVENT_FAILURE_DETECTED, rec->failure_id,
                workflow_id, stage_id, description ? description : "Failure detected");
    return OZAYN_WFR_OK;
}

ozayn_wfr_err_t ozayn_wfr_classify_failure(ozayn_wfr_service_t *svc,
                                            const char *failure_id,
                                            ozayn_wfr_failure_category_t category,
                                            ozayn_wfr_failure_severity_t severity,
                                            ozayn_wfr_impact_level_t impact) {
    if (!svc) return OZAYN_WFR_ERR_NULL;
    if (!svc->initialized) return OZAYN_WFR_ERR_NOT_INITIALIZED;
    if (!failure_id) return OZAYN_WFR_ERR_INVALID_PARAM;
    if (category < 0 || category >= OZAYN_WFR_CAT_COUNT) return OZAYN_WFR_ERR_INVALID_PARAM;
    if (severity < 0 || severity >= OZAYN_WFR_SEV_COUNT) return OZAYN_WFR_ERR_INVALID_PARAM;
    if (impact < 0 || impact >= OZAYN_WFR_IMPACT_COUNT) return OZAYN_WFR_ERR_INVALID_PARAM;
    ozayn_wfr_failure_record_t *rec = _find_failure(svc, failure_id);
    if (!rec) return OZAYN_WFR_ERR_NOT_FOUND;
    ozayn_wfr_err_t rc = _failure_transition(svc, rec, OZAYN_WFR_FS_CLASSIFIED);
    if (rc != OZAYN_WFR_OK) return rc;
    rec->category = category;
    rec->severity = severity;
    rec->impact_level = impact;
    svc->stats.total_failures_classified++;
    _emit_event(svc, OZAYN_WFR_EVENT_FAILURE_CLASSIFIED, failure_id,
                rec->workflow_id, rec->stage_id, "Failure classified");
    return OZAYN_WFR_OK;
}

ozayn_wfr_err_t ozayn_wfr_close_failure(ozayn_wfr_service_t *svc,
                                         const char *failure_id) {
    if (!svc) return OZAYN_WFR_ERR_NULL;
    if (!svc->initialized) return OZAYN_WFR_ERR_NOT_INITIALIZED;
    if (!failure_id) return OZAYN_WFR_ERR_INVALID_PARAM;
    ozayn_wfr_failure_record_t *rec = _find_failure(svc, failure_id);
    if (!rec) return OZAYN_WFR_ERR_NOT_FOUND;
    if (_is_failure_terminal(rec->state)) return OZAYN_WFR_ERR_STATE_INVALID;
    ozayn_wfr_err_t rc = _failure_transition(svc, rec, OZAYN_WFR_FS_CLOSED);
    if (rc != OZAYN_WFR_OK) return rc;
    svc->stats.active_failures = _count_active_failures(svc);
    return OZAYN_WFR_OK;
}

ozayn_wfr_err_t ozayn_wfr_acknowledge_failure(ozayn_wfr_service_t *svc,
                                               const char *failure_id) {
    if (!svc) return OZAYN_WFR_ERR_NULL;
    if (!svc->initialized) return OZAYN_WFR_ERR_NOT_INITIALIZED;
    if (!failure_id) return OZAYN_WFR_ERR_INVALID_PARAM;
    ozayn_wfr_failure_record_t *rec = _find_failure(svc, failure_id);
    if (!rec) return OZAYN_WFR_ERR_NOT_FOUND;
    if (_is_failure_terminal(rec->state)) return OZAYN_WFR_ERR_STATE_INVALID;
    ozayn_wfr_err_t rc = _failure_transition(svc, rec, OZAYN_WFR_FS_ACKNOWLEDGED);
    if (rc != OZAYN_WFR_OK) return rc;
    svc->stats.active_failures = _count_active_failures(svc);
    return OZAYN_WFR_OK;
}

/* ============================================================
 * CONTAINMENT
 * ============================================================ */

ozayn_wfr_err_t ozayn_wfr_contain_failure(ozayn_wfr_service_t *svc,
                                           const char *failure_id,
                                           ozayn_wfr_containment_action_t action) {
    if (!svc) return OZAYN_WFR_ERR_NULL;
    if (!svc->initialized) return OZAYN_WFR_ERR_NOT_INITIALIZED;
    if (!failure_id) return OZAYN_WFR_ERR_INVALID_PARAM;
    if (action < 0 || action >= OZAYN_WFR_CONTAIN_COUNT)
        return OZAYN_WFR_ERR_INVALID_PARAM;
    ozayn_wfr_failure_record_t *rec = _find_failure(svc, failure_id);
    if (!rec) return OZAYN_WFR_ERR_NOT_FOUND;
    if (rec->state == OZAYN_WFR_FS_DETECTED) {
        ozayn_wfr_err_t rc = _failure_transition(svc, rec, OZAYN_WFR_FS_CLASSIFIED);
        if (rc != OZAYN_WFR_OK) {
            rc = _failure_transition(svc, rec, OZAYN_WFR_FS_ASSESSING);
            if (rc != OZAYN_WFR_OK) return rc;
        }
    }
    if (rec->state == OZAYN_WFR_FS_ASSESSING) {
        ozayn_wfr_err_t rc = _failure_transition(svc, rec, OZAYN_WFR_FS_CONTAINING);
        if (rc != OZAYN_WFR_OK) return rc;
    } else if (rec->state == OZAYN_WFR_FS_CLASSIFIED) {
        ozayn_wfr_err_t rc = _failure_transition(svc, rec, OZAYN_WFR_FS_CONTAINING);
        if (rc != OZAYN_WFR_OK) return rc;
    }
    svc->stats.total_containment_actions++;
    _emit_event(svc, OZAYN_WFR_EVENT_FAILURE_CONTAINING, failure_id,
                rec->workflow_id, rec->stage_id, "Containment action taken");
    return OZAYN_WFR_OK;
}

/* ============================================================
 * RECOVERY DECISION
 * ============================================================ */

ozayn_wfr_err_t ozayn_wfr_make_recovery_decision(
    ozayn_wfr_service_t *svc,
    const char *failure_id,
    ozayn_wfr_recovery_decision_t *decision_template,
    char *out_decision_id,
    int out_id_len) {
    if (!svc) return OZAYN_WFR_ERR_NULL;
    if (!svc->initialized) return OZAYN_WFR_ERR_NOT_INITIALIZED;
    if (!failure_id || !decision_template || !out_decision_id || out_id_len < 8)
        return OZAYN_WFR_ERR_INVALID_PARAM;
    if (decision_template->decision < 0 || decision_template->decision >= OZAYN_WFR_DEC_COUNT)
        return OZAYN_WFR_ERR_INVALID_PARAM;
    ozayn_wfr_failure_record_t *rec = _find_failure(svc, failure_id);
    if (!rec) return OZAYN_WFR_ERR_NOT_FOUND;
    int slot = _find_free_decision_slot(svc);
    if (slot < 0) return OZAYN_WFR_ERR_LIMIT_REACHED;
    ozayn_wfr_recovery_decision_t *dec = &svc->decisions[slot];
    memset(dec, 0, sizeof(ozayn_wfr_recovery_decision_t));
    dec->active = 1;
    snprintf(dec->decision_id, OZAYN_WFR_MAX_ID_LEN, "WFR-DEC-%d", slot);
    strncpy(dec->failure_id, failure_id, OZAYN_WFR_MAX_ID_LEN - 1);
    if (decision_template->workflow_id[0])
        strncpy(dec->workflow_id, decision_template->workflow_id, OZAYN_WFR_MAX_ID_LEN - 1);
    else if (rec->workflow_id[0])
        strncpy(dec->workflow_id, rec->workflow_id, OZAYN_WFR_MAX_ID_LEN - 1);
    if (decision_template->stage_id[0])
        strncpy(dec->stage_id, decision_template->stage_id, OZAYN_WFR_MAX_ID_LEN - 1);
    else if (rec->stage_id[0])
        strncpy(dec->stage_id, rec->stage_id, OZAYN_WFR_MAX_ID_LEN - 1);
    dec->decision = decision_template->decision;
    if (decision_template->reason[0])
        strncpy(dec->reason, decision_template->reason, OZAYN_WFR_MAX_DESC_LEN - 1);
    dec->decision_time = _now_ms();
    dec->expiration_time = decision_template->expiration_time;
    strncpy(out_decision_id, dec->decision_id, out_id_len - 1);

    if (rec->state == OZAYN_WFR_FS_DETECTED) {
        _failure_transition(svc, rec, OZAYN_WFR_FS_CLASSIFIED);
    }
    if (rec->state == OZAYN_WFR_FS_CLASSIFIED) {
        _failure_transition(svc, rec, OZAYN_WFR_FS_ASSESSING);
    }

    return OZAYN_WFR_OK;
}

ozayn_wfr_err_t ozayn_wfr_authorize_recovery(ozayn_wfr_service_t *svc,
                                              const char *decision_id,
                                              const char *authorization_ref,
                                              const char *safety_ref) {
    if (!svc) return OZAYN_WFR_ERR_NULL;
    if (!svc->initialized) return OZAYN_WFR_ERR_NOT_INITIALIZED;
    if (!decision_id) return OZAYN_WFR_ERR_INVALID_PARAM;
    ozayn_wfr_recovery_decision_t *dec = _find_decision(svc, decision_id);
    if (!dec) return OZAYN_WFR_ERR_NOT_FOUND;
    if (!dec->active) return OZAYN_WFR_ERR_STATE_INVALID;
    if (authorization_ref) {
        strncpy(dec->authorization_ref, authorization_ref, OZAYN_WFR_MAX_ID_LEN - 1);
        dec->authorized = 1;
    }
    if (safety_ref) {
        strncpy(dec->safety_ref, safety_ref, OZAYN_WFR_MAX_ID_LEN - 1);
        dec->safety_ok = 1;
    }
    return OZAYN_WFR_OK;
}

ozayn_wfr_err_t ozayn_wfr_execute_recovery(ozayn_wfr_service_t *svc,
                                            const char *decision_id) {
    if (!svc) return OZAYN_WFR_ERR_NULL;
    if (!svc->initialized) return OZAYN_WFR_ERR_NOT_INITIALIZED;
    if (!decision_id) return OZAYN_WFR_ERR_INVALID_PARAM;
    ozayn_wfr_recovery_decision_t *dec = _find_decision(svc, decision_id);
    if (!dec) return OZAYN_WFR_ERR_NOT_FOUND;
    if (!dec->active) return OZAYN_WFR_ERR_STATE_INVALID;
    ozayn_wfr_failure_record_t *rec = _find_failure(svc, dec->failure_id);
    if (!rec) return OZAYN_WFR_ERR_NOT_FOUND;
    svc->stats.total_recovery_attempts++;

    switch (dec->decision) {
        case OZAYN_WFR_DEC_RETRY:
            _failure_transition(svc, rec, OZAYN_WFR_FS_RECOVERING);
            _emit_event(svc, OZAYN_WFR_EVENT_RECOVERY_RETRYING, dec->failure_id,
                        dec->workflow_id, dec->stage_id, "Recovery retry initiated");
            break;
        case OZAYN_WFR_DEC_CONTINUE:
            _failure_transition(svc, rec, OZAYN_WFR_FS_RECOVERED);
            svc->stats.total_recovery_successes++;
            _emit_event(svc, OZAYN_WFR_EVENT_RECOVERY_COMPLETED, dec->failure_id,
                        dec->workflow_id, dec->stage_id, "Recovery continue");
            break;
        case OZAYN_WFR_DEC_CANCEL:
        case OZAYN_WFR_DEC_FAIL_WORKFLOW:
            _failure_transition(svc, rec, OZAYN_WFR_FS_UNRECOVERABLE);
            svc->stats.total_recovery_failures++;
            _emit_event(svc, OZAYN_WFR_EVENT_RECOVERY_FAILED, dec->failure_id,
                        dec->workflow_id, dec->stage_id, "Recovery failed (cancel/fail)");
            break;
        case OZAYN_WFR_DEC_PARTIAL_CONTINUE:
            _failure_transition(svc, rec, OZAYN_WFR_FS_PARTIALLY_RECOVERED);
            svc->stats.total_failures_partially_recovered++;
            _emit_event(svc, OZAYN_WFR_EVENT_RECOVERY_PARTIAL, dec->failure_id,
                        dec->workflow_id, dec->stage_id, "Partial recovery");
            break;
        case OZAYN_WFR_DEC_COMPENSATE:
            _failure_transition(svc, rec, OZAYN_WFR_FS_RECOVERING);
            svc->stats.total_compensation_attempts++;
            _emit_event(svc, OZAYN_WFR_EVENT_COMPENSATION_STARTED, dec->failure_id,
                        dec->workflow_id, dec->stage_id, "Compensation started");
            break;
        case OZAYN_WFR_DEC_ESCALATE:
            _failure_transition(svc, rec, OZAYN_WFR_FS_ESCALATED);
            svc->stats.total_failures_escalated++;
            _emit_event(svc, OZAYN_WFR_EVENT_RECOVERY_ESCALATED, dec->failure_id,
                        dec->workflow_id, dec->stage_id, "Recovery escalated");
            break;
        case OZAYN_WFR_DEC_PAUSE:
            _emit_event(svc, OZAYN_WFR_EVENT_WORKFLOW_DEGRADED, dec->failure_id,
                        dec->workflow_id, dec->stage_id, "Workflow paused for recovery");
            break;
        case OZAYN_WFR_DEC_UNAVAILABLE:
            _failure_transition(svc, rec, OZAYN_WFR_FS_UNRECOVERABLE);
            svc->stats.total_recovery_failures++;
            _emit_event(svc, OZAYN_WFR_EVENT_WORKFLOW_UNRECOVERABLE, dec->failure_id,
                        dec->workflow_id, dec->stage_id, "Recovery unavailable");
            break;
        default:
            return OZAYN_WFR_ERR_INVALID_PARAM;
    }

    /* Record in history */
    int hslot = _find_free_history_slot(svc);
    if (hslot >= 0) {
        ozayn_wfr_recovery_history_t *h = &svc->history[hslot];
        memset(h, 0, sizeof(ozayn_wfr_recovery_history_t));
        h->active = 1;
        snprintf(h->history_id, OZAYN_WFR_MAX_ID_LEN, "WFR-HIST-%d", hslot);
        strncpy(h->failure_id, dec->failure_id, OZAYN_WFR_MAX_ID_LEN - 1);
        strncpy(h->decision_id, dec->decision_id, OZAYN_WFR_MAX_ID_LEN - 1);
        if (dec->workflow_id[0]) strncpy(h->workflow_id, dec->workflow_id, OZAYN_WFR_MAX_ID_LEN - 1);
        if (dec->stage_id[0]) strncpy(h->stage_id, dec->stage_id, OZAYN_WFR_MAX_ID_LEN - 1);
        h->decision = dec->decision;
        h->attempt_number = 1;
        h->attempt_time = _now_ms();
    }

    svc->stats.active_failures = _count_active_failures(svc);
    return OZAYN_WFR_OK;
}

/* ============================================================
 * RETRY FUNCTIONS
 * ============================================================ */

ozayn_wfr_err_t ozayn_wfr_evaluate_retry(ozayn_wfr_service_t *svc,
                                          const char *failure_id,
                                          ozayn_wfr_idempotency_t idempotency,
                                          ozayn_wfr_backoff_strategy_t backoff,
                                          int64_t backoff_delay_ms,
                                          int *out_retryable) {
    if (!svc) return OZAYN_WFR_ERR_NULL;
    if (!svc->initialized) return OZAYN_WFR_ERR_NOT_INITIALIZED;
    if (!failure_id || !out_retryable) return OZAYN_WFR_ERR_INVALID_PARAM;
    *out_retryable = 0;
    ozayn_wfr_failure_record_t *rec = _find_failure(svc, failure_id);
    if (!rec) return OZAYN_WFR_ERR_NOT_FOUND;
    if (_is_failure_terminal(rec->state)) return OZAYN_WFR_ERR_STATE_INVALID;
    if (idempotency == OZAYN_WFR_IDEMP_NON_IDEMPOTENT) {
        return OZAYN_WFR_OK;
    }
    if (idempotency == OZAYN_WFR_IDEMP_UNKNOWN) {
        return OZAYN_WFR_OK;
    }
    if (rec->category == OZAYN_WFR_CAT_AUTHORIZATION ||
        rec->category == OZAYN_WFR_CAT_SECURITY ||
        rec->category == OZAYN_WFR_CAT_SAFETY) {
        return OZAYN_WFR_OK;
    }
    if (rec->severity == OZAYN_WFR_SEV_CRITICAL) {
        return OZAYN_WFR_OK;
    }
    (void)backoff;
    (void)backoff_delay_ms;
    *out_retryable = 1;
    return OZAYN_WFR_OK;
}

ozayn_wfr_err_t ozayn_wfr_execute_retry(ozayn_wfr_service_t *svc,
                                         const char *failure_id,
                                         const char *decision_id) {
    if (!svc) return OZAYN_WFR_ERR_NULL;
    if (!svc->initialized) return OZAYN_WFR_ERR_NOT_INITIALIZED;
    if (!failure_id || !decision_id) return OZAYN_WFR_ERR_INVALID_PARAM;
    ozayn_wfr_failure_record_t *rec = _find_failure(svc, failure_id);
    if (!rec) return OZAYN_WFR_ERR_NOT_FOUND;
    ozayn_wfr_recovery_decision_t *dec = _find_decision(svc, decision_id);
    if (!dec) return OZAYN_WFR_ERR_NOT_FOUND;
    if (rec->category == OZAYN_WFR_CAT_AUTHORIZATION ||
        rec->category == OZAYN_WFR_CAT_SECURITY ||
        rec->category == OZAYN_WFR_CAT_SAFETY) {
        return OZAYN_WFR_ERR_RETRY_NOT_ALLOWED;
    }
    _failure_transition(svc, rec, OZAYN_WFR_FS_RECOVERING);
    svc->stats.total_retries++;
    _emit_event(svc, OZAYN_WFR_EVENT_RECOVERY_RETRYING, failure_id,
                rec->workflow_id, rec->stage_id, "Retry executed");
    return OZAYN_WFR_OK;
}

/* ============================================================
 * COMPENSATION FUNCTIONS
 * ============================================================ */

ozayn_wfr_err_t ozayn_wfr_evaluate_compensation(ozayn_wfr_service_t *svc,
                                                 const char *failure_id,
                                                 int *out_compensable) {
    if (!svc) return OZAYN_WFR_ERR_NULL;
    if (!svc->initialized) return OZAYN_WFR_ERR_NOT_INITIALIZED;
    if (!failure_id || !out_compensable) return OZAYN_WFR_ERR_INVALID_PARAM;
    *out_compensable = 0;
    ozayn_wfr_failure_record_t *rec = _find_failure(svc, failure_id);
    if (!rec) return OZAYN_WFR_ERR_NOT_FOUND;
    if (_is_failure_terminal(rec->state)) return OZAYN_WFR_ERR_STATE_INVALID;
    if (rec->category == OZAYN_WFR_CAT_VALIDATION ||
        rec->category == OZAYN_WFR_CAT_CONFIGURATION) {
        return OZAYN_WFR_OK;
    }
    *out_compensable = 1;
    return OZAYN_WFR_OK;
}

ozayn_wfr_err_t ozayn_wfr_execute_compensation(ozayn_wfr_service_t *svc,
                                                const char *failure_id,
                                                const char *decision_id) {
    if (!svc) return OZAYN_WFR_ERR_NULL;
    if (!svc->initialized) return OZAYN_WFR_ERR_NOT_INITIALIZED;
    if (!failure_id || !decision_id) return OZAYN_WFR_ERR_INVALID_PARAM;
    ozayn_wfr_failure_record_t *rec = _find_failure(svc, failure_id);
    if (!rec) return OZAYN_WFR_ERR_NOT_FOUND;
    _failure_transition(svc, rec, OZAYN_WFR_FS_RECOVERING);
    svc->stats.total_compensation_attempts++;
    _emit_event(svc, OZAYN_WFR_EVENT_COMPENSATION_STARTED, failure_id,
                rec->workflow_id, rec->stage_id, "Compensation executed");
    return OZAYN_WFR_OK;
}

/* ============================================================
 * TICK — RECOVERY ORCHESTRATION
 * ============================================================ */

ozayn_wfr_err_t ozayn_wfr_tick(ozayn_wfr_service_t *svc, int64_t now_ms) {
    if (!svc) return OZAYN_WFR_ERR_NULL;
    if (!svc->initialized) return OZAYN_WFR_ERR_NOT_INITIALIZED;
    svc->last_tick_time = now_ms;

    for (int i = 0; i < OZAYN_WFR_MAX_FAILURES; i++) {
        ozayn_wfr_failure_record_t *rec = &svc->failures[i];
        if (!rec->active) continue;
        if (_is_failure_terminal(rec->state)) continue;

        if (rec->state == OZAYN_WFR_FS_DETECTED) {
            _failure_transition(svc, rec, OZAYN_WFR_FS_CLASSIFIED);
        }

        if (rec->state == OZAYN_WFR_FS_CLASSIFIED) {
            _failure_transition(svc, rec, OZAYN_WFR_FS_ASSESSING);
        }

        if (rec->state == OZAYN_WFR_FS_RECOVERING) {
            if (rec->severity == OZAYN_WFR_SEV_CRITICAL ||
                rec->category == OZAYN_WFR_CAT_INTERNAL) {
                _failure_transition(svc, rec, OZAYN_WFR_FS_ESCALATED);
                svc->stats.total_failures_escalated++;
                _emit_event(svc, OZAYN_WFR_EVENT_RECOVERY_ESCALATED, rec->failure_id,
                            rec->workflow_id, rec->stage_id,
                            "Auto-escalated (critical/internal)");
            } else if (rec->category == OZAYN_WFR_CAT_TIMEOUT ||
                       rec->category == OZAYN_WFR_CAT_DEPENDENCY) {
                _failure_transition(svc, rec, OZAYN_WFR_FS_RECOVERED);
                svc->stats.total_recovery_successes++;
                _emit_event(svc, OZAYN_WFR_EVENT_RECOVERY_COMPLETED, rec->failure_id,
                            rec->workflow_id, rec->stage_id,
                            "Auto-recovered (timeout/dependency)");
            }
        }

        if (rec->state == OZAYN_WFR_FS_ESCALATED) {
            if (now_ms - rec->failure_time > OZAYN_WFR_DEFAULT_RECOVERY_TIMEOUT_MS) {
                _failure_transition(svc, rec, OZAYN_WFR_FS_CLOSED);
                rec->resolved_time = now_ms;
                svc->stats.active_failures = _count_active_failures(svc);
            }
        }
    }

    for (int i = 0; i < OZAYN_WFR_MAX_RECOVERY_RECORDS; i++) {
        ozayn_wfr_recovery_decision_t *dec = &svc->decisions[i];
        if (!dec->active) continue;
        if (dec->expiration_time > 0 && now_ms > dec->expiration_time) {
            dec->active = 0;
        }
    }

    return OZAYN_WFR_OK;
}

/* ============================================================
 * QUERY FUNCTIONS
 * ============================================================ */

const ozayn_wfr_failure_record_t *ozayn_wfr_get_failure(
    const ozayn_wfr_service_t *svc, const char *failure_id) {
    if (!svc || !failure_id) return NULL;
    for (int i = 0; i < OZAYN_WFR_MAX_FAILURES; i++) {
        if (svc->failures[i].active &&
            strcmp(svc->failures[i].failure_id, failure_id) == 0) {
            return &svc->failures[i];
        }
    }
    return NULL;
}

const ozayn_wfr_recovery_decision_t *ozayn_wfr_get_decision(
    const ozayn_wfr_service_t *svc, const char *decision_id) {
    if (!svc || !decision_id) return NULL;
    for (int i = 0; i < OZAYN_WFR_MAX_RECOVERY_RECORDS; i++) {
        if (svc->decisions[i].active &&
            strcmp(svc->decisions[i].decision_id, decision_id) == 0) {
            return &svc->decisions[i];
        }
    }
    return NULL;
}

const ozayn_wfr_recovery_history_t *ozayn_wfr_get_history_entry(
    const ozayn_wfr_service_t *svc, int index) {
    if (!svc || index < 0 || index >= OZAYN_WFR_MAX_RECOVERY_HISTORY) return NULL;
    if (!svc->history[index].active) return NULL;
    return &svc->history[index];
}

int ozayn_wfr_failure_count(const ozayn_wfr_service_t *svc) {
    if (!svc) return 0;
    int count = 0;
    for (int i = 0; i < OZAYN_WFR_MAX_FAILURES; i++) {
        if (svc->failures[i].active) count++;
    }
    return count;
}

int ozayn_wfr_failure_count_by_state(const ozayn_wfr_service_t *svc,
                                      ozayn_wfr_failure_state_t state) {
    if (!svc) return 0;
    return _count_failures_by_state(svc, state);
}

int ozayn_wfr_failure_count_by_category(const ozayn_wfr_service_t *svc,
                                         ozayn_wfr_failure_category_t category) {
    if (!svc) return 0;
    int count = 0;
    for (int i = 0; i < OZAYN_WFR_MAX_FAILURES; i++) {
        if (svc->failures[i].active && svc->failures[i].category == category)
            count++;
    }
    return count;
}

int ozayn_wfr_decision_count(const ozayn_wfr_service_t *svc) {
    if (!svc) return 0;
    int count = 0;
    for (int i = 0; i < OZAYN_WFR_MAX_RECOVERY_RECORDS; i++) {
        if (svc->decisions[i].active) count++;
    }
    return count;
}

int ozayn_wfr_history_count(const ozayn_wfr_service_t *svc) {
    if (!svc) return 0;
    int count = 0;
    for (int i = 0; i < OZAYN_WFR_MAX_RECOVERY_HISTORY; i++) {
        if (svc->history[i].active) count++;
    }
    return count;
}

int ozayn_wfr_active_failures(const ozayn_wfr_service_t *svc) {
    if (!svc) return 0;
    return _count_active_failures(svc);
}

int ozayn_wfr_active_recoveries(const ozayn_wfr_service_t *svc) {
    if (!svc) return 0;
    return _count_failures_by_state(svc, OZAYN_WFR_FS_RECOVERING);
}

int ozayn_wfr_is_failure_terminal(ozayn_wfr_failure_state_t state) {
    return _is_failure_terminal(state);
}

/* ============================================================
 * EVENT FUNCTIONS
 * ============================================================ */

ozayn_wfr_err_t ozayn_wfr_emit_event(ozayn_wfr_service_t *svc,
                                      ozayn_wfr_event_type_t event_type,
                                      const char *failure_id,
                                      const char *workflow_id,
                                      const char *stage_id,
                                      const char *message) {
    if (!svc) return OZAYN_WFR_ERR_NULL;
    if (!svc->initialized) return OZAYN_WFR_ERR_NOT_INITIALIZED;
    _emit_event(svc, event_type, failure_id, workflow_id, stage_id, message);
    return OZAYN_WFR_OK;
}

const ozayn_wfr_event_t *ozayn_wfr_get_event(
    const ozayn_wfr_service_t *svc, int index) {
    if (!svc || index < 0 || index >= OZAYN_WFR_MAX_EVENTS) return NULL;
    if (!svc->events[index].active) return NULL;
    return &svc->events[index];
}

int ozayn_wfr_event_count(const ozayn_wfr_service_t *svc) {
    if (!svc) return 0;
    int count = 0;
    for (int i = 0; i < OZAYN_WFR_MAX_EVENTS; i++) {
        if (svc->events[i].active) count++;
    }
    return count;
}

/* ============================================================
 * CLEANUP
 * ============================================================ */

ozayn_wfr_err_t ozayn_wfr_cleanup_closed(ozayn_wfr_service_t *svc) {
    if (!svc) return OZAYN_WFR_ERR_NULL;
    if (!svc->initialized) return OZAYN_WFR_ERR_NOT_INITIALIZED;
    for (int i = 0; i < OZAYN_WFR_MAX_FAILURES; i++) {
        if (svc->failures[i].active && svc->failures[i].state == OZAYN_WFR_FS_CLOSED) {
            svc->failures[i].active = 0;
        }
    }
    svc->stats.active_failures = _count_active_failures(svc);
    return OZAYN_WFR_OK;
}

ozayn_wfr_err_t ozayn_wfr_cleanup_all(ozayn_wfr_service_t *svc) {
    if (!svc) return OZAYN_WFR_ERR_NULL;
    if (!svc->initialized) return OZAYN_WFR_ERR_NOT_INITIALIZED;
    for (int i = 0; i < OZAYN_WFR_MAX_FAILURES; i++) {
        svc->failures[i].active = 0;
    }
    for (int i = 0; i < OZAYN_WFR_MAX_RECOVERY_RECORDS; i++) {
        svc->decisions[i].active = 0;
    }
    for (int i = 0; i < OZAYN_WFR_MAX_RECOVERY_HISTORY; i++) {
        svc->history[i].active = 0;
    }
    svc->stats.active_failures = 0;
    svc->stats.active_recoveries = 0;
    return OZAYN_WFR_OK;
}

/* ============================================================
 * STATISTICS
 * ============================================================ */

const ozayn_wfr_stats_t *ozayn_wfr_get_stats(const ozayn_wfr_service_t *svc) {
    if (!svc) return NULL;
    return &svc->stats;
}

ozayn_wfr_err_t ozayn_wfr_reset_stats(ozayn_wfr_service_t *svc) {
    if (!svc) return OZAYN_WFR_ERR_NULL;
    if (!svc->initialized) return OZAYN_WFR_ERR_NOT_INITIALIZED;
    memset(&svc->stats, 0, sizeof(ozayn_wfr_stats_t));
    return OZAYN_WFR_OK;
}

/* ============================================================
 * VALIDATION
 * ============================================================ */

int ozayn_wfr_validate_failure_record(const ozayn_wfr_service_t *svc,
                                       const char *failure_id) {
    if (!svc || !failure_id) return 0;
    const ozayn_wfr_failure_record_t *rec = ozayn_wfr_get_failure(svc, failure_id);
    if (!rec) return 0;
    if (!rec->failure_id[0]) return 0;
    if (rec->category < 0 || rec->category >= OZAYN_WFR_CAT_COUNT) return 0;
    if (rec->severity < 0 || rec->severity >= OZAYN_WFR_SEV_COUNT) return 0;
    if (rec->state < 0 || rec->state >= OZAYN_WFR_FS_STATE_COUNT) return 0;
    return 1;
}

int ozayn_wfr_validate_decision(const ozayn_wfr_service_t *svc,
                                 const char *decision_id) {
    if (!svc || !decision_id) return 0;
    const ozayn_wfr_recovery_decision_t *dec = ozayn_wfr_get_decision(svc, decision_id);
    if (!dec) return 0;
    if (!dec->decision_id[0]) return 0;
    if (dec->decision < 0 || dec->decision >= OZAYN_WFR_DEC_COUNT) return 0;
    return 1;
}

int ozayn_wfr_validate_config(const ozayn_wfr_service_config_t *config) {
    if (!config) return 0;
    return 1;
}

int ozayn_wfr_is_valid_failure_transition(ozayn_wfr_failure_state_t from,
                                           ozayn_wfr_failure_state_t to) {
    if (!_ft_initialized) _init_failure_transitions();
    if (from < 0 || from >= OZAYN_WFR_FS_STATE_COUNT) return 0;
    if (to < 0 || to >= OZAYN_WFR_FS_STATE_COUNT) return 0;
    return _failure_transitions[from][to];
}

/* ============================================================
 * NAME HELPERS
 * ============================================================ */

const char *ozayn_wfr_err_name(ozayn_wfr_err_t err) {
    switch (err) {
        case OZAYN_WFR_OK: return "OK";
        case OZAYN_WFR_ERR_NULL: return "NULL";
        case OZAYN_WFR_ERR_NOT_INITIALIZED: return "NOT_INITIALIZED";
        case OZAYN_WFR_ERR_ALREADY_INIT: return "ALREADY_INIT";
        case OZAYN_WFR_ERR_INVALID_PARAM: return "INVALID_PARAM";
        case OZAYN_WFR_ERR_LIMIT_REACHED: return "LIMIT_REACHED";
        case OZAYN_WFR_ERR_NOT_FOUND: return "NOT_FOUND";
        case OZAYN_WFR_ERR_DUPLICATE: return "DUPLICATE";
        case OZAYN_WFR_ERR_STATE_INVALID: return "STATE_INVALID";
        case OZAYN_WFR_ERR_AUTH_FAILED: return "AUTH_FAILED";
        case OZAYN_WFR_ERR_SAFETY_CHECK_FAILED: return "SAFETY_CHECK_FAILED";
        case OZAYN_WFR_ERR_RESOURCE_UNAVAILABLE: return "RESOURCE_UNAVAILABLE";
        case OZAYN_WFR_ERR_DEPENDENCY_FAILED: return "DEPENDENCY_FAILED";
        case OZAYN_WFR_ERR_PIPELINE_INVALID: return "PIPELINE_INVALID";
        case OZAYN_WFR_ERR_TIMEOUT: return "TIMEOUT";
        case OZAYN_WFR_ERR_CANCELLED: return "CANCELLED";
        case OZAYN_WFR_ERR_EXPIRED: return "EXPIRED";
        case OZAYN_WFR_ERR_UNRECOVERABLE: return "UNRECOVERABLE";
        case OZAYN_WFR_ERR_RETRY_NOT_ALLOWED: return "RETRY_NOT_ALLOWED";
        case OZAYN_WFR_ERR_RETRY_LIMIT_EXCEEDED: return "RETRY_LIMIT_EXCEEDED";
        case OZAYN_WFR_ERR_COMPENSATION_FAILED: return "COMPENSATION_FAILED";
        case OZAYN_WFR_ERR_COMPENSATION_DENIED: return "COMPENSATION_DENIED";
        case OZAYN_WFR_ERR_EVENT_ERROR: return "EVENT_ERROR";
        case OZAYN_WFR_ERR_HISTORY_ERROR: return "HISTORY_ERROR";
        case OZAYN_WFR_ERR_CONFIGURATION: return "CONFIGURATION";
        case OZAYN_WFR_ERR_UNAVAILABLE: return "UNAVAILABLE";
        case OZAYN_WFR_ERR_REJECTED: return "REJECTED";
        case OZAYN_WFR_ERR_RECOVERY_TIMEOUT: return "RECOVERY_TIMEOUT";
        case OZAYN_WFR_ERR_RECOVERY_FAILED: return "RECOVERY_FAILED";
        case OZAYN_WFR_ERR_ESCALATION_FAILED: return "ESCALATION_FAILED";
    }
    return "UNKNOWN";
}

const char *ozayn_wfr_failure_category_name(ozayn_wfr_failure_category_t cat) {
    static const char *names[] = {
        "VALIDATION", "AUTHORIZATION", "SECURITY", "SAFETY", "RESOURCE",
        "DEVICE", "CAPABILITY", "DEPENDENCY", "PIPELINE", "OPERATION",
        "TIMEOUT", "CANCELLATION", "CONFIGURATION", "STORAGE", "EVENT",
        "CONCURRENCY", "PLATFORM", "INTERNAL", "UNKNOWN"
    };
    if (cat < 0 || cat >= OZAYN_WFR_CAT_COUNT) return "INVALID";
    return names[cat];
}

const char *ozayn_wfr_failure_severity_name(ozayn_wfr_failure_severity_t sev) {
    static const char *names[] = {"INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"};
    if (sev < 0 || sev >= OZAYN_WFR_SEV_COUNT) return "INVALID";
    return names[sev];
}

const char *ozayn_wfr_failure_state_name(ozayn_wfr_failure_state_t state) {
    static const char *names[] = {
        "DETECTED", "CLASSIFIED", "ASSESSING", "CONTAINING", "RECOVERING",
        "RECOVERED", "PARTIALLY_RECOVERED", "UNRECOVERABLE", "ESCALATED",
        "ACKNOWLEDGED", "CLOSED"
    };
    if (state < 0 || state >= OZAYN_WFR_FS_STATE_COUNT) return "INVALID";
    return names[state];
}

const char *ozayn_wfr_recovery_decision_name(ozayn_wfr_decision_type_t dec) {
    static const char *names[] = {
        "CONTINUE", "RETRY", "PAUSE", "CANCEL", "FAIL_WORKFLOW",
        "PARTIAL_CONTINUE", "COMPENSATE", "ESCALATE", "UNAVAILABLE"
    };
    if (dec < 0 || dec >= OZAYN_WFR_DEC_COUNT) return "INVALID";
    return names[dec];
}

const char *ozayn_wfr_impact_level_name(ozayn_wfr_impact_level_t impact) {
    static const char *names[] = {
        "STAGE_ONLY", "DEPENDENT_STAGES", "WORKFLOW",
        "RELATED_RESOURCE", "RELATED_DEVICE", "RELATED_PIPELINES"
    };
    if (impact < 0 || impact >= OZAYN_WFR_IMPACT_COUNT) return "INVALID";
    return names[impact];
}

const char *ozayn_wfr_containment_action_name(ozayn_wfr_containment_action_t act) {
    static const char *names[] = {
        "STOP_DISPATCH", "BLOCK_DEPENDENTS", "CANCEL_PENDING",
        "PAUSE_WORKFLOW", "DRAIN_PIPELINE", "CANCEL_PIPELINE",
        "RELEASE_RESOURCES", "CLOSE_DEVICE_SESSION", "DISCONNECT_ROUTE",
        "CLOSE_STREAM"
    };
    if (act < 0 || act >= OZAYN_WFR_CONTAIN_COUNT) return "INVALID";
    return names[act];
}

const char *ozayn_wfr_idempotency_name(ozayn_wfr_idempotency_t idemp) {
    static const char *names[] = {"IDEMPOTENT", "SAFE_REPEAT", "NON_IDEMPOTENT", "UNKNOWN"};
    if (idemp < 0 || idemp >= OZAYN_WFR_IDEMP_COUNT) return "INVALID";
    return names[idemp];
}

const char *ozayn_wfr_backoff_strategy_name(ozayn_wfr_backoff_strategy_t backoff) {
    static const char *names[] = {"IMMEDIATE", "FIXED_DELAY", "BOUNDED_EXPONENTIAL"};
    if (backoff < 0 || backoff >= OZAYN_WFR_BACKOFF_COUNT) return "INVALID";
    return names[backoff];
}

const char *ozayn_wfr_recovery_state_name(ozayn_wfr_recovery_state_t state) {
    static const char *names[] = {"NONE", "RECOVERING", "COMPENSATING", "RETRYING", "ESCALATED"};
    if (state < 0 || state >= OZAYN_WFR_RECOVERY_COUNT) return "INVALID";
    return names[state];
}

const char *ozayn_wfr_event_type_name(ozayn_wfr_event_type_t type) {
    static const char *names[] = {
        "FAILURE_DETECTED", "FAILURE_CLASSIFIED", "FAILURE_ASSESSING",
        "FAILURE_CONTAINING", "FAILURE_CONTAINED", "RECOVERY_STARTED",
        "RECOVERY_RETRYING", "RECOVERY_COMPLETED", "RECOVERY_PARTIAL",
        "RECOVERY_FAILED", "RECOVERY_TIMEOUT", "RECOVERY_ESCALATED",
        "WORKFLOW_DEGRADED", "WORKFLOW_RECOVERING", "WORKFLOW_UNRECOVERABLE",
        "COMPENSATION_STARTED", "COMPENSATION_COMPLETED", "COMPENSATION_FAILED"
    };
    if (type < 0 || type >= OZAYN_WFR_EVENT_COUNT) return "INVALID";
    return names[type];
}

const char *ozayn_wfr_history_result_name(ozayn_wfr_history_result_t result) {
    static const char *names[] = {"SUCCESS", "FAILURE", "TIMEOUT", "DENIED", "ESCALATED"};
    if (result < 0 || result >= OZAYN_WFR_HIST_COUNT) return "INVALID";
    return names[result];
}
