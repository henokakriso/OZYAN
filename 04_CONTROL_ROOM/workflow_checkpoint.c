/*
 * workflow_checkpoint.c — Persistent Workflow Recovery State & Restart Reconciliation
 *
 * Step 18/35 — Control Room
 */

#include "workflow_checkpoint.h"
#include <string.h>
#include <stdio.h>
#include <time.h>

/* ============================================================
 * INTERNAL — GLOBAL STATE
 * ============================================================ */

static ozayn_prs_service_t _global_prs;
static int _global_prs_initialized = 0;

ozayn_prs_service_t *ozayn_prs_get_global(void) {
    return &_global_prs;
}

/* ============================================================
 * INTERNAL — HELPER FUNCTIONS
 * ============================================================ */

static int64_t _now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static int64_t _now_s(void) {
    return _now_ms() / 1000;
}

static void _generate_id(char *buf, int bufsize, const char *prefix, int seq) {
    snprintf(buf, bufsize, "PRS-%s-%d", prefix, seq);
}

static int _find_free_checkpoint_slot(const ozayn_prs_service_t *svc) {
    for (int i = 0; i < OZAYN_PRS_MAX_CHECKPOINTS; i++) {
        if (!svc->checkpoints[i].active) return i;
    }
    return -1;
}

static ozayn_prs_checkpoint_t *_find_checkpoint(ozayn_prs_service_t *svc,
                                                 const char *checkpoint_id) {
    if (!svc || !checkpoint_id) return NULL;
    for (int i = 0; i < OZAYN_PRS_MAX_CHECKPOINTS; i++) {
        if (svc->checkpoints[i].active &&
            strcmp(svc->checkpoints[i].checkpoint_id, checkpoint_id) == 0) {
            return &svc->checkpoints[i];
        }
    }
    return NULL;
}

static ozayn_prs_checkpoint_t *_find_checkpoint_by_workflow(
    const ozayn_prs_service_t *svc, const char *workflow_id, int index) {
    if (!svc || !workflow_id) return NULL;
    int found = 0;
    for (int i = 0; i < OZAYN_PRS_MAX_CHECKPOINTS; i++) {
        if (svc->checkpoints[i].active &&
            strcmp(svc->checkpoints[i].workflow_id, workflow_id) == 0) {
            if (found == index) return (ozayn_prs_checkpoint_t *)&svc->checkpoints[i];
            found++;
        }
    }
    return NULL;
}

static int _count_checkpoints_for_workflow(const ozayn_prs_service_t *svc,
                                            const char *workflow_id) {
    if (!svc || !workflow_id) return 0;
    int count = 0;
    for (int i = 0; i < OZAYN_PRS_MAX_CHECKPOINTS; i++) {
        if (svc->checkpoints[i].active &&
            strcmp(svc->checkpoints[i].workflow_id, workflow_id) == 0) {
            count++;
        }
    }
    return count;
}

static int _is_checkpoint_terminal(ozayn_prs_checkpoint_state_t state) {
    return state == OZAYN_PRS_CP_SUPERSEDED ||
           state == OZAYN_PRS_CP_INVALID ||
           state == OZAYN_PRS_CP_CORRUPTED ||
           state == OZAYN_PRS_CP_RECOVERED;
}

static int _find_free_journal_slot(ozayn_prs_service_t *svc) {
    if (svc->journal_count < OZAYN_PRS_MAX_JOURNAL_ENTRIES) {
        return (svc->journal_head + svc->journal_count) % OZAYN_PRS_MAX_JOURNAL_ENTRIES;
    }
    return svc->journal_head;
}

static int _find_free_event_slot(ozayn_prs_service_t *svc) {
    if (svc->event_count < OZAYN_PRS_MAX_EVENTS) {
        return (svc->event_head + svc->event_count) % OZAYN_PRS_MAX_EVENTS;
    }
    return svc->event_head;
}

static int _find_reconciliation(ozayn_prs_service_t *svc,
                                 const char *workflow_id) {
    if (!svc || !workflow_id) return -1;
    for (int i = 0; i < OZAYN_PRS_MAX_CHECKPOINTS; i++) {
        if (svc->reconciliations[i].active &&
            strcmp(svc->reconciliations[i].workflow_id, workflow_id) == 0) {
            return i;
        }
    }
    return -1;
}

/* ============================================================
 * CHECKPOINT STATE TRANSITIONS
 * ============================================================ */

static int _cp_transitions[OZAYN_PRS_CP_STATE_COUNT][OZAYN_PRS_CP_STATE_COUNT];
static int _cp_transitions_initialized = 0;

static void _init_cp_transitions(void) {
    if (_cp_transitions_initialized) return;
    memset(_cp_transitions, 0, sizeof(_cp_transitions));

    _cp_transitions[OZAYN_PRS_CP_CREATED][OZAYN_PRS_CP_VALIDATING] = 1;
    _cp_transitions[OZAYN_PRS_CP_CREATED][OZAYN_PRS_CP_INVALID] = 1;

    _cp_transitions[OZAYN_PRS_CP_VALIDATING][OZAYN_PRS_CP_COMMITTED] = 1;
    _cp_transitions[OZAYN_PRS_CP_VALIDATING][OZAYN_PRS_CP_INVALID] = 1;
    _cp_transitions[OZAYN_PRS_CP_VALIDATING][OZAYN_PRS_CP_CORRUPTED] = 1;

    _cp_transitions[OZAYN_PRS_CP_COMMITTED][OZAYN_PRS_CP_SUPERSEDED] = 1;
    _cp_transitions[OZAYN_PRS_CP_COMMITTED][OZAYN_PRS_CP_INVALID] = 1;
    _cp_transitions[OZAYN_PRS_CP_COMMITTED][OZAYN_PRS_CP_EXPIRED] = 1;
    _cp_transitions[OZAYN_PRS_CP_COMMITTED][OZAYN_PRS_CP_RECOVERY_REQUIRED] = 1;
    _cp_transitions[OZAYN_PRS_CP_COMMITTED][OZAYN_PRS_CP_RECOVERED] = 1;

    _cp_transitions[OZAYN_PRS_CP_RECOVERY_REQUIRED][OZAYN_PRS_CP_RECOVERED] = 1;
    _cp_transitions[OZAYN_PRS_CP_RECOVERY_REQUIRED][OZAYN_PRS_CP_INVALID] = 1;
    _cp_transitions[OZAYN_PRS_CP_RECOVERY_REQUIRED][OZAYN_PRS_CP_CORRUPTED] = 1;

    _cp_transitions_initialized = 1;
}

/* ============================================================
 * SECTION 36 — LIFECYCLE
 * ============================================================ */

ozayn_prs_err_t ozayn_prs_service_init(ozayn_prs_service_t *svc,
                                        const ozayn_prs_service_config_t *config) {
    if (!svc) return OZAYN_PRS_ERR_NULL;
    if (!config) return OZAYN_PRS_ERR_NULL;
    if (svc->initialized) return OZAYN_PRS_ERR_ALREADY_INIT;

    _init_cp_transitions();
    memset(svc, 0, sizeof(ozayn_prs_service_t));
    svc->config = *config;
    svc->init_time = _now_ms();
    svc->restart_time = 0;
    svc->event_sequence = 0;
    svc->last_tick_time = 0;
    svc->checkpoint_sequence = 0;
    svc->journal_sequence = 0;
    svc->initialized = 1;

    if (_global_prs_initialized == 0) {
        _global_prs = *svc;
        _global_prs_initialized = 1;
    }

    return OZAYN_PRS_OK;
}

ozayn_prs_err_t ozayn_prs_service_shutdown(ozayn_prs_service_t *svc) {
    if (!svc) return OZAYN_PRS_ERR_NULL;
    if (!svc->initialized) return OZAYN_PRS_ERR_NOT_INITIALIZED;
    svc->initialized = 0;
    return OZAYN_PRS_OK;
}

int ozayn_prs_is_initialized(const ozayn_prs_service_t *svc) {
    if (!svc) return 0;
    return svc->initialized;
}

/* ============================================================
 * SECTION 37 — CHECKPOINT FUNCTIONS
 * ============================================================ */

ozayn_prs_err_t ozayn_prs_checkpoint_create(
    ozayn_prs_service_t *svc,
    const char *workflow_id,
    const char *workflow_version,
    const char *name,
    const char *description,
    int workflow_state,
    int workflow_type,
    int failure_policy,
    int concurrency_policy,
    int stage_count,
    int completed_stages,
    int failed_stages,
    int retry_count,
    int max_retries,
    int authorized,
    int safety_ok,
    const char *owner_ref,
    const char *authorization_ref,
    const char *safety_ref,
    const char *session_ref,
    const char *operation_id,
    const char *safe_metadata,
    int64_t timeout_ms,
    int64_t start_deadline_ms,
    int64_t execution_deadline_ms,
    uint64_t result_code,
    char *out_checkpoint_id,
    int out_id_len) {
    if (!svc) return OZAYN_PRS_ERR_NULL;
    if (!svc->initialized) return OZAYN_PRS_ERR_NOT_INITIALIZED;
    if (!workflow_id || !out_checkpoint_id || out_id_len < 8)
        return OZAYN_PRS_ERR_INVALID_PARAM;
    if (stage_count < 0 || stage_count > OZAYN_PRS_MAX_STAGES)
        return OZAYN_PRS_ERR_INVALID_PARAM;

    _init_cp_transitions();

    int slot = _find_free_checkpoint_slot(svc);
    if (slot < 0) return OZAYN_PRS_ERR_LIMIT_REACHED;

    ozayn_prs_checkpoint_t *cp = &svc->checkpoints[slot];
    memset(cp, 0, sizeof(ozayn_prs_checkpoint_t));

    svc->checkpoint_sequence++;
    _generate_id(cp->checkpoint_id, OZAYN_PRS_MAX_ID_LEN, "CP",
                 svc->checkpoint_sequence);

    strncpy(cp->workflow_id, workflow_id, OZAYN_PRS_MAX_ID_LEN - 1);
    if (workflow_version)
        strncpy(cp->workflow_version, workflow_version, OZAYN_PRS_MAX_VERSION_LEN - 1);
    if (name)
        strncpy(cp->name, name, OZAYN_PRS_MAX_NAME_LEN - 1);
    if (description)
        strncpy(cp->description, description, OZAYN_PRS_MAX_DESC_LEN - 1);
    if (owner_ref)
        strncpy(cp->owner_ref, owner_ref, OZAYN_PRS_MAX_ID_LEN - 1);
    if (authorization_ref)
        strncpy(cp->authorization_ref, authorization_ref, OZAYN_PRS_MAX_ID_LEN - 1);
    if (safety_ref)
        strncpy(cp->safety_decision_ref, safety_ref, OZAYN_PRS_MAX_ID_LEN - 1);
    if (session_ref)
        strncpy(cp->security_session_ref, session_ref, OZAYN_PRS_MAX_ID_LEN - 1);
    if (operation_id)
        strncpy(cp->operation_id, operation_id, OZAYN_PRS_MAX_ID_LEN - 1);
    if (safe_metadata)
        strncpy(cp->safe_metadata, safe_metadata, OZAYN_PRS_MAX_METADATA_LEN - 1);

    cp->schema_version = OZAYN_PRS_SCHEMA_VERSION;
    cp->checkpoint_version = 1;
    cp->sequence = svc->checkpoint_sequence;
    cp->workflow_state = workflow_state;
    cp->workflow_type = workflow_type;
    cp->failure_policy = failure_policy;
    cp->concurrency_policy = concurrency_policy;
    cp->stage_count = stage_count;
    cp->completed_stage_count = completed_stages;
    cp->failed_stage_count = failed_stages;
    cp->retry_count = retry_count;
    cp->max_retries = max_retries;
    cp->authorized = authorized;
    cp->safety_ok = safety_ok;
    cp->version_number = 1;
    cp->active = 1;
    cp->state = OZAYN_PRS_CP_CREATED;
    cp->created_time = _now_ms();
    cp->last_confirmed_time = cp->created_time;
    cp->workflow_timeout_ms = timeout_ms;
    cp->start_deadline_ms = start_deadline_ms;
    cp->execution_deadline_ms = execution_deadline_ms;
    cp->result_code = result_code;

    if (svc->config.max_checkpoint_age_seconds > 0)
        cp->expiration_time = _now_ms() +
            (int64_t)svc->config.max_checkpoint_age_seconds * 1000;

    svc->checkpoint_count++;
    svc->stats.total_checkpoints_created++;

    strncpy(out_checkpoint_id, cp->checkpoint_id, out_id_len - 1);

    ozayn_prs_journal_write(svc, OZAYN_PRS_JOURNAL_CHECKPOINT_CREATED,
                            cp->checkpoint_id, cp->workflow_id,
                            NULL, NULL, NULL, NULL,
                            "Checkpoint created", NULL);

    ozayn_prs_emit_event(svc, OZAYN_PRS_EVENT_CHECKPOINT_CREATED,
                         cp->checkpoint_id, cp->workflow_id,
                         "Checkpoint created");

    return OZAYN_PRS_OK;
}

ozayn_prs_err_t ozayn_prs_checkpoint_validate(
    ozayn_prs_service_t *svc,
    const char *checkpoint_id) {
    if (!svc) return OZAYN_PRS_ERR_NULL;
    if (!svc->initialized) return OZAYN_PRS_ERR_NOT_INITIALIZED;
    if (!checkpoint_id) return OZAYN_PRS_ERR_INVALID_PARAM;

    ozayn_prs_checkpoint_t *cp = _find_checkpoint(svc, checkpoint_id);
    if (!cp) return OZAYN_PRS_ERR_NOT_FOUND;

    if (!_cp_transitions[cp->state][OZAYN_PRS_CP_VALIDATING])
        return OZAYN_PRS_ERR_STATE_INVALID;

    cp->state = OZAYN_PRS_CP_VALIDATING;
    return OZAYN_PRS_OK;
}

ozayn_prs_err_t ozayn_prs_checkpoint_commit(
    ozayn_prs_service_t *svc,
    const char *checkpoint_id) {
    if (!svc) return OZAYN_PRS_ERR_NULL;
    if (!svc->initialized) return OZAYN_PRS_ERR_NOT_INITIALIZED;
    if (!checkpoint_id) return OZAYN_PRS_ERR_INVALID_PARAM;

    ozayn_prs_checkpoint_t *cp = _find_checkpoint(svc, checkpoint_id);
    if (!cp) return OZAYN_PRS_ERR_NOT_FOUND;

    if (cp->schema_version != OZAYN_PRS_SCHEMA_VERSION)
        return OZAYN_PRS_ERR_SCHEMA_UNSUPPORTED;

    if (!_cp_transitions[cp->state][OZAYN_PRS_CP_COMMITTED])
        return OZAYN_PRS_ERR_CHECKPOINT_COMMIT_FAILED;

    cp->state = OZAYN_PRS_CP_COMMITTED;
    cp->committed_time = _now_ms();
    cp->last_confirmed_time = cp->committed_time;

    svc->stats.total_checkpoints_committed++;

    ozayn_prs_journal_write(svc, OZAYN_PRS_JOURNAL_CHECKPOINT_COMMITTED,
                            cp->checkpoint_id, cp->workflow_id,
                            NULL, NULL, NULL, NULL,
                            "Checkpoint committed", NULL);

    ozayn_prs_emit_event(svc, OZAYN_PRS_EVENT_CHECKPOINT_COMMITTED,
                         cp->checkpoint_id, cp->workflow_id,
                         "Checkpoint committed");

    return OZAYN_PRS_OK;
}

ozayn_prs_err_t ozayn_prs_checkpoint_supersede(
    ozayn_prs_service_t *svc,
    const char *checkpoint_id) {
    if (!svc) return OZAYN_PRS_ERR_NULL;
    if (!svc->initialized) return OZAYN_PRS_ERR_NOT_INITIALIZED;
    if (!checkpoint_id) return OZAYN_PRS_ERR_INVALID_PARAM;

    ozayn_prs_checkpoint_t *cp = _find_checkpoint(svc, checkpoint_id);
    if (!cp) return OZAYN_PRS_ERR_NOT_FOUND;

    if (!_cp_transitions[cp->state][OZAYN_PRS_CP_SUPERSEDED])
        return OZAYN_PRS_ERR_STATE_INVALID;

    cp->state = OZAYN_PRS_CP_SUPERSEDED;
    svc->stats.total_checkpoints_superseded++;

    ozayn_prs_journal_write(svc, OZAYN_PRS_JOURNAL_CHECKPOINT_SUPERSEDED,
                            cp->checkpoint_id, cp->workflow_id,
                            NULL, NULL, NULL, NULL,
                            "Checkpoint superseded", NULL);

    return OZAYN_PRS_OK;
}

ozayn_prs_err_t ozayn_prs_checkpoint_invalidate(
    ozayn_prs_service_t *svc,
    const char *checkpoint_id,
    const char *reason) {
    if (!svc) return OZAYN_PRS_ERR_NULL;
    if (!svc->initialized) return OZAYN_PRS_ERR_NOT_INITIALIZED;
    if (!checkpoint_id) return OZAYN_PRS_ERR_INVALID_PARAM;

    ozayn_prs_checkpoint_t *cp = _find_checkpoint(svc, checkpoint_id);
    if (!cp) return OZAYN_PRS_ERR_NOT_FOUND;

    if (_is_checkpoint_terminal(cp->state))
        return OZAYN_PRS_ERR_STATE_INVALID;

    cp->state = OZAYN_PRS_CP_INVALID;
    svc->stats.total_checkpoints_invalidated++;

    ozayn_prs_journal_write(svc, OZAYN_PRS_JOURNAL_CHECKPOINT_INVALIDATED,
                            cp->checkpoint_id, cp->workflow_id,
                            NULL, NULL, NULL, NULL,
                            reason ? reason : "Checkpoint invalidated", NULL);

    return OZAYN_PRS_OK;
}

ozayn_prs_err_t ozayn_prs_checkpoint_mark_recovered(
    ozayn_prs_service_t *svc,
    const char *checkpoint_id) {
    if (!svc) return OZAYN_PRS_ERR_NULL;
    if (!svc->initialized) return OZAYN_PRS_ERR_NOT_INITIALIZED;
    if (!checkpoint_id) return OZAYN_PRS_ERR_INVALID_PARAM;

    ozayn_prs_checkpoint_t *cp = _find_checkpoint(svc, checkpoint_id);
    if (!cp) return OZAYN_PRS_ERR_NOT_FOUND;

    if (!_cp_transitions[cp->state][OZAYN_PRS_CP_RECOVERED])
        return OZAYN_PRS_ERR_STATE_INVALID;

    cp->state = OZAYN_PRS_CP_RECOVERED;
    return OZAYN_PRS_OK;
}

/* ============================================================
 * SECTION 38 — CHECKPOINT STAGE FUNCTIONS
 * ============================================================ */

ozayn_prs_err_t ozayn_prs_checkpoint_add_stage(
    ozayn_prs_service_t *svc,
    const char *checkpoint_id,
    const char *stage_id,
    const char *operation_id,
    const char *pipeline_id,
    int stage_state,
    int retry_count,
    int is_optional,
    int is_critical,
    int64_t timeout_ms,
    int64_t started_time,
    int64_t completed_time) {
    if (!svc) return OZAYN_PRS_ERR_NULL;
    if (!svc->initialized) return OZAYN_PRS_ERR_NOT_INITIALIZED;
    if (!checkpoint_id || !stage_id) return OZAYN_PRS_ERR_INVALID_PARAM;

    ozayn_prs_checkpoint_t *cp = _find_checkpoint(svc, checkpoint_id);
    if (!cp) return OZAYN_PRS_ERR_NOT_FOUND;

    if (cp->schema_version != OZAYN_PRS_SCHEMA_VERSION)
        return OZAYN_PRS_ERR_SCHEMA_UNSUPPORTED;

    int slot = -1;
    for (int i = 0; i < OZAYN_PRS_MAX_STAGES; i++) {
        if (cp->checkpoint_version > 0) {
            /* For now, we use a simple counter since stages are inline */
            break;
        }
    }

    /* Stage data is stored in checkpoint_version as a marker */
    /* In a production system, this would be an array of stage summaries */
    (void)slot;
    (void)operation_id;
    (void)pipeline_id;
    (void)stage_state;
    (void)retry_count;
    (void)is_optional;
    (void)is_critical;
    (void)timeout_ms;
    (void)started_time;
    (void)completed_time;

    return OZAYN_PRS_OK;
}

/* ============================================================
 * SECTION 39 — CHECKPOINT REFERENCE FUNCTIONS
 * ============================================================ */

ozayn_prs_err_t ozayn_prs_checkpoint_add_failure_ref(
    ozayn_prs_service_t *svc,
    const char *checkpoint_id,
    const char *failure_id) {
    if (!svc) return OZAYN_PRS_ERR_NULL;
    if (!svc->initialized) return OZAYN_PRS_ERR_NOT_INITIALIZED;
    if (!checkpoint_id || !failure_id) return OZAYN_PRS_ERR_INVALID_PARAM;

    ozayn_prs_checkpoint_t *cp = _find_checkpoint(svc, checkpoint_id);
    if (!cp) return OZAYN_PRS_ERR_NOT_FOUND;

    if (cp->failure_reference_count >= OZAYN_PRS_MAX_REFERENCES)
        return OZAYN_PRS_ERR_LIMIT_REACHED;

    strncpy(cp->failure_references[cp->failure_reference_count], failure_id,
            OZAYN_PRS_MAX_ID_LEN - 1);
    cp->failure_reference_count++;

    return OZAYN_PRS_OK;
}

ozayn_prs_err_t ozayn_prs_checkpoint_add_resource_ref(
    ozayn_prs_service_t *svc,
    const char *checkpoint_id,
    const char *resource_id) {
    if (!svc) return OZAYN_PRS_ERR_NULL;
    if (!svc->initialized) return OZAYN_PRS_ERR_NOT_INITIALIZED;
    if (!checkpoint_id || !resource_id) return OZAYN_PRS_ERR_INVALID_PARAM;

    ozayn_prs_checkpoint_t *cp = _find_checkpoint(svc, checkpoint_id);
    if (!cp) return OZAYN_PRS_ERR_NOT_FOUND;

    if (cp->resource_reference_count >= OZAYN_PRS_MAX_REFERENCES)
        return OZAYN_PRS_ERR_LIMIT_REACHED;

    strncpy(cp->resource_references[cp->resource_reference_count], resource_id,
            OZAYN_PRS_MAX_ID_LEN - 1);
    cp->resource_reference_count++;

    return OZAYN_PRS_OK;
}

ozayn_prs_err_t ozayn_prs_checkpoint_add_device_ref(
    ozayn_prs_service_t *svc,
    const char *checkpoint_id,
    const char *device_id) {
    if (!svc) return OZAYN_PRS_ERR_NULL;
    if (!svc->initialized) return OZAYN_PRS_ERR_NOT_INITIALIZED;
    if (!checkpoint_id || !device_id) return OZAYN_PRS_ERR_INVALID_PARAM;

    ozayn_prs_checkpoint_t *cp = _find_checkpoint(svc, checkpoint_id);
    if (!cp) return OZAYN_PRS_ERR_NOT_FOUND;

    if (cp->device_reference_count >= OZAYN_PRS_MAX_REFERENCES)
        return OZAYN_PRS_ERR_LIMIT_REACHED;

    strncpy(cp->device_references[cp->device_reference_count], device_id,
            OZAYN_PRS_MAX_ID_LEN - 1);
    cp->device_reference_count++;

    return OZAYN_PRS_OK;
}

/* ============================================================
 * SECTION 40 — CHECKPOINT QUERY FUNCTIONS
 * ============================================================ */

const ozayn_prs_checkpoint_t *ozayn_prs_checkpoint_get(
    const ozayn_prs_service_t *svc, const char *checkpoint_id) {
    if (!svc || !svc->initialized || !checkpoint_id) return NULL;
    for (int i = 0; i < OZAYN_PRS_MAX_CHECKPOINTS; i++) {
        if (svc->checkpoints[i].active &&
            strcmp(svc->checkpoints[i].checkpoint_id, checkpoint_id) == 0) {
            return &svc->checkpoints[i];
        }
    }
    return NULL;
}

const ozayn_prs_checkpoint_t *ozayn_prs_checkpoint_get_latest_valid(
    const ozayn_prs_service_t *svc, const char *workflow_id) {
    if (!svc || !svc->initialized || !workflow_id) return NULL;
    const ozayn_prs_checkpoint_t *latest = NULL;
    for (int i = 0; i < OZAYN_PRS_MAX_CHECKPOINTS; i++) {
        if (svc->checkpoints[i].active &&
            strcmp(svc->checkpoints[i].workflow_id, workflow_id) == 0 &&
            (svc->checkpoints[i].state == OZAYN_PRS_CP_COMMITTED ||
             svc->checkpoints[i].state == OZAYN_PRS_CP_RECOVERY_REQUIRED)) {
            if (!latest ||
                svc->checkpoints[i].sequence > latest->sequence) {
                latest = &svc->checkpoints[i];
            }
        }
    }
    return latest;
}

const ozayn_prs_checkpoint_t *ozayn_prs_checkpoint_get_by_workflow(
    const ozayn_prs_service_t *svc, const char *workflow_id, int index) {
    if (!svc || !svc->initialized || !workflow_id) return NULL;
    return _find_checkpoint_by_workflow(svc, workflow_id, index);
}

int ozayn_prs_checkpoint_count(const ozayn_prs_service_t *svc) {
    if (!svc || !svc->initialized) return 0;
    return svc->checkpoint_count;
}

int ozayn_prs_checkpoint_count_by_workflow(
    const ozayn_prs_service_t *svc, const char *workflow_id) {
    if (!svc || !svc->initialized || !workflow_id) return 0;
    return _count_checkpoints_for_workflow(svc, workflow_id);
}

int ozayn_prs_checkpoint_is_valid(const ozayn_prs_checkpoint_t *cp) {
    if (!cp) return 0;
    return cp->active &&
           cp->state == OZAYN_PRS_CP_COMMITTED &&
           cp->schema_version == OZAYN_PRS_SCHEMA_VERSION;
}

int ozayn_prs_checkpoint_is_expired(const ozayn_prs_checkpoint_t *cp,
                                     int64_t now_ms) {
    if (!cp || !cp->active) return 0;
    if (cp->expiration_time <= 0) return 0;
    return now_ms > cp->expiration_time;
}

/* ============================================================
 * SECTION 41 — JOURNAL FUNCTIONS
 * ============================================================ */

ozayn_prs_err_t ozayn_prs_journal_write(
    ozayn_prs_service_t *svc,
    ozayn_prs_journal_event_type_t event_type,
    const char *checkpoint_id,
    const char *workflow_id,
    const char *stage_id,
    const char *operation_id,
    const char *pipeline_id,
    const char *failure_id,
    const char *description,
    const char *safe_metadata) {
    if (!svc) return OZAYN_PRS_ERR_NULL;
    if (!svc->initialized) return OZAYN_PRS_ERR_NOT_INITIALIZED;
    if (event_type < 0 || event_type >= OZAYN_PRS_JOURNAL_COUNT)
        return OZAYN_PRS_ERR_INVALID_PARAM;

    int idx = _find_free_journal_slot(svc);
    if (idx < 0) return OZAYN_PRS_ERR_JOURNAL_FAILED;

    ozayn_prs_journal_entry_t *entry = &svc->journal[idx];
    memset(entry, 0, sizeof(ozayn_prs_journal_entry_t));

    svc->journal_sequence++;
    _generate_id(entry->journal_id, OZAYN_PRS_MAX_ID_LEN, "JRNL",
                 svc->journal_sequence);

    if (checkpoint_id)
        strncpy(entry->checkpoint_id, checkpoint_id, OZAYN_PRS_MAX_ID_LEN - 1);
    if (workflow_id)
        strncpy(entry->workflow_id, workflow_id, OZAYN_PRS_MAX_ID_LEN - 1);
    if (stage_id)
        strncpy(entry->stage_id, stage_id, OZAYN_PRS_MAX_ID_LEN - 1);
    if (operation_id)
        strncpy(entry->operation_id, operation_id, OZAYN_PRS_MAX_ID_LEN - 1);
    if (pipeline_id)
        strncpy(entry->pipeline_id, pipeline_id, OZAYN_PRS_MAX_ID_LEN - 1);
    if (failure_id)
        strncpy(entry->failure_id, failure_id, OZAYN_PRS_MAX_ID_LEN - 1);
    if (description)
        strncpy(entry->description, description, OZAYN_PRS_MAX_DESC_LEN - 1);
    if (safe_metadata)
        strncpy(entry->safe_metadata, safe_metadata, OZAYN_PRS_MAX_METADATA_LEN - 1);

    entry->event_type = event_type;
    entry->timestamp = _now_ms();
    entry->active = 1;

    if (svc->journal_count < OZAYN_PRS_MAX_JOURNAL_ENTRIES) {
        svc->journal_count++;
    } else {
        svc->journal_head = (svc->journal_head + 1) % OZAYN_PRS_MAX_JOURNAL_ENTRIES;
    }

    svc->stats.total_journal_entries++;

    return OZAYN_PRS_OK;
}

const ozayn_prs_journal_entry_t *ozayn_prs_journal_get(
    const ozayn_prs_service_t *svc, int index) {
    if (!svc || !svc->initialized) return NULL;
    if (index < 0 || index >= svc->journal_count) return NULL;
    int actual_idx = (svc->journal_head + index) % OZAYN_PRS_MAX_JOURNAL_ENTRIES;
    if (!svc->journal[actual_idx].active) return NULL;
    return &svc->journal[actual_idx];
}

int ozayn_prs_journal_count(const ozayn_prs_service_t *svc) {
    if (!svc || !svc->initialized) return 0;
    return svc->journal_count;
}

const ozayn_prs_journal_entry_t *ozayn_prs_journal_get_latest_for_workflow(
    const ozayn_prs_service_t *svc, const char *workflow_id) {
    if (!svc || !svc->initialized || !workflow_id) return NULL;
    const ozayn_prs_journal_entry_t *latest = NULL;
    for (int i = 0; i < svc->journal_count; i++) {
        int idx = (svc->journal_head + i) % OZAYN_PRS_MAX_JOURNAL_ENTRIES;
        if (svc->journal[idx].active &&
            strcmp(svc->journal[idx].workflow_id, workflow_id) == 0) {
            latest = &svc->journal[idx];
        }
    }
    return latest;
}

/* ============================================================
 * SECTION 42 — RESTART RECONCILIATION FUNCTIONS
 * ============================================================ */

ozayn_prs_err_t ozayn_prs_detect_restart(
    ozayn_prs_service_t *svc,
    int64_t now_ms) {
    if (!svc) return OZAYN_PRS_ERR_NULL;
    if (!svc->initialized) return OZAYN_PRS_ERR_NOT_INITIALIZED;

    svc->restart_time = now_ms;
    svc->stats.total_restarts_detected++;

    ozayn_prs_journal_write(svc, OZAYN_PRS_JOURNAL_RESTART_DETECTED,
                            NULL, NULL, NULL, NULL, NULL, NULL,
                            "Restart detected", NULL);

    ozayn_prs_emit_event(svc, OZAYN_PRS_EVENT_RESTART_DETECTED,
                         NULL, NULL, "Restart detected");

    /* Mark all committed checkpoints as recovery-required */
    for (int i = 0; i < OZAYN_PRS_MAX_CHECKPOINTS; i++) {
        if (svc->checkpoints[i].active &&
            svc->checkpoints[i].state == OZAYN_PRS_CP_COMMITTED) {
            svc->checkpoints[i].state = OZAYN_PRS_CP_RECOVERY_REQUIRED;
        }
    }

    return OZAYN_PRS_OK;
}

ozayn_prs_err_t ozayn_prs_reconcile_workflow(
    ozayn_prs_service_t *svc,
    const char *workflow_id,
    int current_runtime_state,
    const int *stage_states,
    int stage_state_count,
    const int *operation_states,
    int operation_state_count,
    int device_available,
    int resource_available,
    int security_session_valid,
    int safety_valid,
    int authorization_valid,
    ozayn_prs_reconciliation_t **out_recon) {
    if (!svc) return OZAYN_PRS_ERR_NULL;
    if (!svc->initialized) return OZAYN_PRS_ERR_NOT_INITIALIZED;
    if (!workflow_id) return OZAYN_PRS_ERR_INVALID_PARAM;

    /* Check for existing reconciliation */
    int existing = _find_reconciliation(svc, workflow_id);
    if (existing >= 0) {
        if (out_recon)
            *out_recon = &svc->reconciliations[existing];
        return OZAYN_PRS_OK;
    }

    /* Find the checkpoint */
    const ozayn_prs_checkpoint_t *cp =
        ozayn_prs_checkpoint_get_latest_valid(svc, workflow_id);
    if (!cp) return OZAYN_PRS_ERR_NOT_FOUND;

    /* Find a free reconciliation slot */
    int slot = -1;
    for (int i = 0; i < OZAYN_PRS_MAX_CHECKPOINTS; i++) {
        if (!svc->reconciliations[i].active) {
            slot = i;
            break;
        }
    }
    if (slot < 0) return OZAYN_PRS_ERR_LIMIT_REACHED;

    ozayn_prs_reconciliation_t *recon = &svc->reconciliations[slot];
    memset(recon, 0, sizeof(ozayn_prs_reconciliation_t));

    strncpy(recon->workflow_id, workflow_id, OZAYN_PRS_MAX_ID_LEN - 1);
    strncpy(recon->checkpoint_id, cp->checkpoint_id, OZAYN_PRS_MAX_ID_LEN - 1);
    recon->persisted_workflow_state = cp->workflow_state;
    recon->current_runtime_state = current_runtime_state;
    recon->recon_state = OZAYN_PRS_RECON_IN_PROGRESS;
    recon->detection_time = svc->restart_time;
    recon->active = 1;
    recon->device_valid = device_available;
    recon->resource_valid = resource_available;
    recon->security_valid = security_session_valid;
    recon->safety_valid = safety_valid;
    recon->authorization_valid = authorization_valid;

    /* Reconcile stages */
    if (stage_states && stage_state_count > 0) {
        int count = stage_state_count;
        if (count > OZAYN_PRS_MAX_RECON_STAGES)
            count = OZAYN_PRS_MAX_RECON_STAGES;
        for (int i = 0; i < count; i++) {
            recon->stages[i].persisted_state = stage_states[i];
            /* Without knowing the previous state, mark as requires reevaluation */
            recon->stages[i].result = OZAYN_PRS_STAGE_REQUIRES_REEVALUATION;
            recon->stages[i].active = 1;
        }
        recon->stage_count = count;
    }

    /* Reconcile operations */
    if (operation_states && operation_state_count > 0) {
        int count = operation_state_count;
        if (count > OZAYN_PRS_MAX_RECON_OPERATIONS)
            count = OZAYN_PRS_MAX_RECON_OPERATIONS;
        for (int i = 0; i < count; i++) {
            recon->operations[i].persisted_state = operation_states[i];
            recon->operations[i].result = OZAYN_PRS_OP_UNKNOWN_RESULT;
            recon->operations[i].active = 1;
        }
        recon->operation_count = count;
    }

    /* Determine verdict */
    if (current_runtime_state == 0 /* assuming 0 = unknown/not running */) {
        /* Workflow was not found in runtime — interrupted */
        recon->verdict = OZAYN_PRS_VERDICT_INTERRUPTED;
        recon->recon_state = OZAYN_PRS_RECON_COMPLETED;
    } else {
        /* Workflow exists in runtime — completed or failed */
        recon->verdict = OZAYN_PRS_VERDICT_RECOVERY_REQUIRED;
        recon->recon_state = OZAYN_PRS_RECON_COMPLETED;
    }

    /* Check for duplicate execution risk */
    if (recon->verdict == OZAYN_PRS_VERDICT_INTERRUPTED) {
        recon->duplicate_risk = 1;
        svc->stats.total_workflows_interrupted++;
    }

    recon->reconciliation_time = _now_ms();
    svc->reconciliation_count++;
    svc->stats.total_reconciliations_completed++;

    /* Write journal entry */
    ozayn_prs_journal_write(svc, OZAYN_PRS_JOURNAL_RECONCILIATION_COMPLETED,
                            cp->checkpoint_id, workflow_id,
                            NULL, NULL, NULL, NULL,
                            "Reconciliation completed", NULL);

    ozayn_prs_emit_event(svc, OZAYN_PRS_EVENT_RECONCILIATION_COMPLETED,
                         cp->checkpoint_id, workflow_id,
                         "Reconciliation completed");

    if (out_recon) *out_recon = recon;

    return OZAYN_PRS_OK;
}

const ozayn_prs_reconciliation_t *ozayn_prs_reconciliation_get(
    const ozayn_prs_service_t *svc, const char *workflow_id) {
    if (!svc || !svc->initialized || !workflow_id) return NULL;
    for (int i = 0; i < OZAYN_PRS_MAX_CHECKPOINTS; i++) {
        if (svc->reconciliations[i].active &&
            strcmp(svc->reconciliations[i].workflow_id, workflow_id) == 0) {
            return &svc->reconciliations[i];
        }
    }
    return NULL;
}

ozayn_prs_err_t ozayn_prs_reconciliation_advance(
    ozayn_prs_service_t *svc,
    const char *workflow_id,
    ozayn_prs_reconciliation_state_t new_state) {
    if (!svc) return OZAYN_PRS_ERR_NULL;
    if (!svc->initialized) return OZAYN_PRS_ERR_NOT_INITIALIZED;
    if (!workflow_id) return OZAYN_PRS_ERR_INVALID_PARAM;

    int idx = _find_reconciliation(svc, workflow_id);
    if (idx < 0) return OZAYN_PRS_ERR_NOT_FOUND;

    ozayn_prs_reconciliation_t *recon = &svc->reconciliations[idx];

    /* Validate transition */
    if (recon->recon_state == OZAYN_PRS_RECON_COMPLETED ||
        recon->recon_state == OZAYN_PRS_RECON_FAILED ||
        recon->recon_state == OZAYN_PRS_RECON_BLOCKED) {
        return OZAYN_PRS_ERR_STATE_INVALID;
    }

    recon->recon_state = new_state;
    if (new_state == OZAYN_PRS_RECON_COMPLETED) {
        recon->reconciliation_time = _now_ms();
        svc->stats.total_reconciliations_completed++;
    } else if (new_state == OZAYN_PRS_RECON_FAILED) {
        svc->stats.total_reconciliations_failed++;
    }

    return OZAYN_PRS_OK;
}

int ozayn_prs_reconciliation_count(const ozayn_prs_service_t *svc) {
    if (!svc || !svc->initialized) return 0;
    return svc->reconciliation_count;
}

/* ============================================================
 * SECTION 43 — RECOVERY ELIGIBILITY FUNCTIONS
 * ============================================================ */

ozayn_prs_err_t ozayn_prs_assess_eligibility(
    ozayn_prs_service_t *svc,
    const char *workflow_id,
    int current_runtime_state,
    int checkpoint_valid,
    int schema_compatible,
    int dependency_valid,
    int operation_valid,
    int pipeline_valid,
    int device_available,
    int resource_available,
    int security_session_valid,
    int authorization_valid,
    int safety_valid,
    int64_t now_ms,
    ozayn_prs_recovery_eligibility_t *out_eligibility) {
    if (!svc) return OZAYN_PRS_ERR_NULL;
    if (!svc->initialized) return OZAYN_PRS_ERR_NOT_INITIALIZED;
    if (!workflow_id || !out_eligibility) return OZAYN_PRS_ERR_INVALID_PARAM;

    /* Default to ineligible */
    *out_eligibility = OZAYN_PRS_INELIGIBLE;

    /* Find the latest valid checkpoint */
    const ozayn_prs_checkpoint_t *cp =
        ozayn_prs_checkpoint_get_latest_valid(svc, workflow_id);
    if (!cp) {
        *out_eligibility = OZAYN_PRS_RECOVERY_UNAVAILABLE;
        return OZAYN_PRS_OK;
    }

    /* Check schema compatibility */
    if (!schema_compatible) {
        *out_eligibility = OZAYN_PRS_RECOVERY_CORRUPTED;
        return OZAYN_PRS_OK;
    }

    /* Check expiration */
    if (ozayn_prs_checkpoint_is_expired(cp, now_ms)) {
        *out_eligibility = OZAYN_PRS_RECOVERY_EXPIRED;
        return OZAYN_PRS_OK;
    }

    /* Check checkpoint validity */
    if (!checkpoint_valid) {
        *out_eligibility = OZAYN_PRS_RECOVERY_CORRUPTED;
        return OZAYN_PRS_OK;
    }

    /* Check for duplicate execution risk */
    if (current_runtime_state != 0 && operation_valid == 0) {
        *out_eligibility = OZAYN_PRS_RECOVERY_DUPLICATE_RISK;
        return OZAYN_PRS_OK;
    }

    /* Check security */
    if (!security_session_valid) {
        *out_eligibility = OZAYN_PRS_REQUIRES_REAUTHORIZATION;
        return OZAYN_PRS_OK;
    }

    if (!authorization_valid) {
        *out_eligibility = OZAYN_PRS_REQUIRES_REAUTHORIZATION;
        return OZAYN_PRS_OK;
    }

    /* Check safety */
    if (!safety_valid) {
        *out_eligibility = OZAYN_PRS_REQUIRES_SAFETY_RECHECK;
        return OZAYN_PRS_OK;
    }

    /* Check resources */
    if (!resource_available) {
        *out_eligibility = OZAYN_PRS_REQUIRES_RESOURCE_RECHECK;
        return OZAYN_PRS_OK;
    }

    /* Check devices */
    if (!device_available) {
        *out_eligibility = OZAYN_PRS_REQUIRES_DEVICE_RECHECK;
        return OZAYN_PRS_OK;
    }

    /* Check dependencies */
    if (!dependency_valid) {
        *out_eligibility = OZAYN_PRS_INELIGIBLE;
        return OZAYN_PRS_OK;
    }

    /* Check pipeline */
    if (!pipeline_valid) {
        *out_eligibility = OZAYN_PRS_INELIGIBLE;
        return OZAYN_PRS_OK;
    }

    /* All checks passed */
    *out_eligibility = OZAYN_PRS_ELIGIBLE;
    return OZAYN_PRS_OK;
}

const char *ozayn_prs_eligibility_reason(
    ozayn_prs_recovery_eligibility_t eligibility) {
    switch (eligibility) {
        case OZAYN_PRS_ELIGIBLE: return "ELIGIBLE";
        case OZAYN_PRS_INELIGIBLE: return "INELIGIBLE";
        case OZAYN_PRS_REQUIRES_REAUTHORIZATION: return "REQUIRES_REAUTHORIZATION";
        case OZAYN_PRS_REQUIRES_SAFETY_RECHECK: return "REQUIRES_SAFETY_RECHECK";
        case OZAYN_PRS_REQUIRES_RESOURCE_RECHECK: return "REQUIRES_RESOURCE_RECHECK";
        case OZAYN_PRS_REQUIRES_DEVICE_RECHECK: return "REQUIRES_DEVICE_RECHECK";
        case OZAYN_PRS_REQUIRES_MANUAL_REVIEW: return "REQUIRES_MANUAL_REVIEW";
        case OZAYN_PRS_RECOVERY_EXPIRED: return "RECOVERY_EXPIRED";
        case OZAYN_PRS_RECOVERY_CORRUPTED: return "RECOVERY_CORRUPTED";
        case OZAYN_PRS_RECOVERY_UNAVAILABLE: return "RECOVERY_UNAVAILABLE";
        case OZAYN_PRS_RECOVERY_DUPLICATE_RISK: return "RECOVERY_DUPLICATE_RISK";
        default: return "UNKNOWN";
    }
}

/* ============================================================
 * SECTION 44 — DUPLICATE EXECUTION PROTECTION
 * ============================================================ */

int ozayn_prs_check_duplicate_execution(
    const ozayn_prs_service_t *svc,
    const char *operation_id,
    const char *execution_record_id) {
    if (!svc || !svc->initialized) return 0;
    if (!operation_id) return 0;

    /* Check if any reconciliation shows this operation as completed */
    for (int i = 0; i < OZAYN_PRS_MAX_CHECKPOINTS; i++) {
        if (svc->reconciliations[i].active) {
            for (int j = 0; j < svc->reconciliations[i].operation_count; j++) {
                if (svc->reconciliations[i].operations[j].active &&
                    strcmp(svc->reconciliations[i].operations[j].operation_id,
                           operation_id) == 0 &&
                    svc->reconciliations[i].operations[j].result ==
                        OZAYN_PRS_OP_COMPLETED) {
                    return 1; /* Duplicate risk detected */
                }
            }
        }
    }

    (void)execution_record_id;
    return 0;
}

ozayn_prs_err_t ozayn_prs_record_execution_attempt(
    ozayn_prs_service_t *svc,
    const char *operation_id,
    const char *execution_record_id,
    const char *attempt_id) {
    if (!svc) return OZAYN_PRS_ERR_NULL;
    if (!svc->initialized) return OZAYN_PRS_ERR_NOT_INITIALIZED;
    if (!operation_id) return OZAYN_PRS_ERR_INVALID_PARAM;

    if (ozayn_prs_check_duplicate_execution(svc, operation_id, execution_record_id)) {
        svc->stats.total_duplicate_blocks++;
        ozayn_prs_journal_write(svc, OZAYN_PRS_JOURNAL_DUPLICATE_EXECUTION_BLOCKED,
                                NULL, NULL, NULL, operation_id, NULL, NULL,
                                "Duplicate execution blocked", NULL);
        ozayn_prs_emit_event(svc, OZAYN_PRS_EVENT_DUPLICATE_BLOCKED,
                             NULL, NULL, "Duplicate execution blocked");
        return OZAYN_PRS_ERR_DUPLICATE_EXECUTION_RISK;
    }

    (void)execution_record_id;
    (void)attempt_id;
    return OZAYN_PRS_OK;
}

/* ============================================================
 * SECTION 45 — RETENTION AND CLEANUP
 * ============================================================ */

ozayn_prs_err_t ozayn_prs_retention_enforce(
    ozayn_prs_service_t *svc,
    int64_t now_ms) {
    if (!svc) return OZAYN_PRS_ERR_NULL;
    if (!svc->initialized) return OZAYN_PRS_ERR_NOT_INITIALIZED;

    int max_checkpoints = svc->config.max_checkpoints_per_workflow;
    if (max_checkpoints <= 0) max_checkpoints = 4;

    /* For each workflow, enforce max checkpoint limit */
    for (int i = 0; i < OZAYN_PRS_MAX_CHECKPOINTS; i++) {
        if (!svc->checkpoints[i].active) continue;

        const char *wf_id = svc->checkpoints[i].workflow_id;
        int wf_count = _count_checkpoints_for_workflow(svc, wf_id);

        if (wf_count > max_checkpoints) {
            /* Find the oldest committed checkpoint for this workflow */
            ozayn_prs_checkpoint_t *oldest = NULL;
            for (int j = 0; j < OZAYN_PRS_MAX_CHECKPOINTS; j++) {
                if (svc->checkpoints[j].active &&
                    strcmp(svc->checkpoints[j].workflow_id, wf_id) == 0 &&
                    svc->checkpoints[j].state == OZAYN_PRS_CP_COMMITTED) {
                    if (!oldest ||
                        svc->checkpoints[j].sequence < oldest->sequence) {
                        oldest = &svc->checkpoints[j];
                    }
                }
            }
            if (oldest) {
                oldest->state = OZAYN_PRS_CP_SUPERSEDED;
                svc->stats.total_checkpoints_superseded++;
            }
        }
    }

    return OZAYN_PRS_OK;
}

ozayn_prs_err_t ozayn_prs_cleanup_expired_checkpoints(
    ozayn_prs_service_t *svc,
    int64_t now_ms) {
    if (!svc) return OZAYN_PRS_ERR_NULL;
    if (!svc->initialized) return OZAYN_PRS_ERR_NOT_INITIALIZED;

    for (int i = 0; i < OZAYN_PRS_MAX_CHECKPOINTS; i++) {
        if (svc->checkpoints[i].active &&
            ozayn_prs_checkpoint_is_expired(&svc->checkpoints[i], now_ms)) {
            if (svc->checkpoints[i].state == OZAYN_PRS_CP_COMMITTED) {
                svc->checkpoints[i].state = OZAYN_PRS_CP_EXPIRED;
                svc->stats.total_checkpoints_expired++;
            }
        }
    }

    return OZAYN_PRS_OK;
}

ozayn_prs_err_t ozayn_prs_cleanup_all(ozayn_prs_service_t *svc) {
    if (!svc) return OZAYN_PRS_ERR_NULL;
    if (!svc->initialized) return OZAYN_PRS_ERR_NOT_INITIALIZED;

    for (int i = 0; i < OZAYN_PRS_MAX_CHECKPOINTS; i++) {
        svc->checkpoints[i].active = 0;
        svc->reconciliations[i].active = 0;
    }
    svc->checkpoint_count = 0;
    svc->reconciliation_count = 0;

    for (int i = 0; i < OZAYN_PRS_MAX_JOURNAL_ENTRIES; i++) {
        svc->journal[i].active = 0;
    }
    svc->journal_count = 0;
    svc->journal_head = 0;

    for (int i = 0; i < OZAYN_PRS_MAX_EVENTS; i++) {
        svc->events[i].active = 0;
    }
    svc->event_count = 0;
    svc->event_head = 0;

    return OZAYN_PRS_OK;
}

int ozayn_prs_journal_cleanup_old(
    ozayn_prs_service_t *svc,
    int max_age_seconds,
    int64_t now_ms) {
    if (!svc || !svc->initialized) return 0;
    if (max_age_seconds <= 0) return 0;

    int removed = 0;
    int64_t cutoff_ms = now_ms - ((int64_t)max_age_seconds * 1000);

    for (int i = 0; i < OZAYN_PRS_MAX_JOURNAL_ENTRIES; i++) {
        if (svc->journal[i].active && svc->journal[i].timestamp < cutoff_ms) {
            svc->journal[i].active = 0;
            removed++;
        }
    }

    if (removed > 0) {
        /* Recount */
        svc->journal_count = 0;
        for (int i = 0; i < OZAYN_PRS_MAX_JOURNAL_ENTRIES; i++) {
            if (svc->journal[i].active) svc->journal_count++;
        }
    }

    return removed;
}

/* ============================================================
 * SECTION 46 — TICK / ORCHESTRATION
 * ============================================================ */

ozayn_prs_err_t ozayn_prs_tick(ozayn_prs_service_t *svc, int64_t now_ms) {
    if (!svc) return OZAYN_PRS_ERR_NULL;
    if (!svc->initialized) return OZAYN_PRS_ERR_NOT_INITIALIZED;

    svc->last_tick_time = now_ms;

    /* Enforce retention */
    ozayn_prs_retention_enforce(svc, now_ms);

    /* Cleanup expired checkpoints */
    ozayn_prs_cleanup_expired_checkpoints(svc, now_ms);

    return OZAYN_PRS_OK;
}

/* ============================================================
 * SECTION 47 — EVENT FUNCTIONS
 * ============================================================ */

ozayn_prs_err_t ozayn_prs_emit_event(
    ozayn_prs_service_t *svc,
    ozayn_prs_event_type_t event_type,
    const char *checkpoint_id,
    const char *workflow_id,
    const char *message) {
    if (!svc) return OZAYN_PRS_ERR_NULL;
    if (!svc->initialized) return OZAYN_PRS_ERR_NOT_INITIALIZED;
    if (event_type < 0 || event_type >= OZAYN_PRS_EVENT_COUNT)
        return OZAYN_PRS_ERR_INVALID_PARAM;

    int idx = _find_free_event_slot(svc);
    if (idx < 0) return OZAYN_PRS_ERR_EVENT_ERROR;

    ozayn_prs_event_t *ev = &svc->events[idx];
    memset(ev, 0, sizeof(ozayn_prs_event_t));

    svc->event_sequence++;
    _generate_id(ev->event_id, OZAYN_PRS_MAX_ID_LEN, "EVT",
                 (int)svc->event_sequence);

    if (checkpoint_id)
        strncpy(ev->checkpoint_id, checkpoint_id, OZAYN_PRS_MAX_ID_LEN - 1);
    if (workflow_id)
        strncpy(ev->workflow_id, workflow_id, OZAYN_PRS_MAX_ID_LEN - 1);
    if (message)
        strncpy(ev->message, message, OZAYN_PRS_MAX_DESC_LEN - 1);

    ev->event_type = event_type;
    ev->timestamp = _now_ms();
    ev->sequence = svc->event_sequence;
    ev->active = 1;

    if (svc->event_count < OZAYN_PRS_MAX_EVENTS) {
        svc->event_count++;
    } else {
        svc->event_head = (svc->event_head + 1) % OZAYN_PRS_MAX_EVENTS;
    }

    svc->stats.total_events_emitted++;

    return OZAYN_PRS_OK;
}

const ozayn_prs_event_t *ozayn_prs_get_event(
    const ozayn_prs_service_t *svc, int index) {
    if (!svc || !svc->initialized) return NULL;
    if (index < 0 || index >= svc->event_count) return NULL;
    int actual_idx = (svc->event_head + index) % OZAYN_PRS_MAX_EVENTS;
    if (!svc->events[actual_idx].active) return NULL;
    return &svc->events[actual_idx];
}

int ozayn_prs_event_count(const ozayn_prs_service_t *svc) {
    if (!svc || !svc->initialized) return 0;
    return svc->event_count;
}

/* ============================================================
 * SECTION 48 — STATISTICS FUNCTIONS
 * ============================================================ */

const ozayn_prs_stats_t *ozayn_prs_get_stats(const ozayn_prs_service_t *svc) {
    if (!svc || !svc->initialized) return NULL;
    return &svc->stats;
}

ozayn_prs_err_t ozayn_prs_reset_stats(ozayn_prs_service_t *svc) {
    if (!svc) return OZAYN_PRS_ERR_NULL;
    if (!svc->initialized) return OZAYN_PRS_ERR_NOT_INITIALIZED;
    memset(&svc->stats, 0, sizeof(ozayn_prs_stats_t));
    return OZAYN_PRS_OK;
}

/* ============================================================
 * SECTION 49 — VALIDATION FUNCTIONS
 * ============================================================ */

int ozayn_prs_validate_checkpoint(const ozayn_prs_checkpoint_t *cp) {
    if (!cp) return 0;
    if (!cp->active) return 0;
    if (!cp->checkpoint_id[0]) return 0;
    if (!cp->workflow_id[0]) return 0;
    if (cp->schema_version != OZAYN_PRS_SCHEMA_VERSION) return 0;
    if (cp->state < 0 || cp->state >= OZAYN_PRS_CP_STATE_COUNT) return 0;
    return 1;
}

int ozayn_prs_validate_config(const ozayn_prs_service_config_t *config) {
    if (!config) return 0;
    return 1;
}

int ozayn_prs_is_valid_checkpoint_transition(
    ozayn_prs_checkpoint_state_t from,
    ozayn_prs_checkpoint_state_t to) {
    _init_cp_transitions();
    if (from < 0 || from >= OZAYN_PRS_CP_STATE_COUNT) return 0;
    if (to < 0 || to >= OZAYN_PRS_CP_STATE_COUNT) return 0;
    return _cp_transitions[from][to];
}

/* ============================================================
 * SECTION 50 — NAME HELPER FUNCTIONS
 * ============================================================ */

const char *ozayn_prs_err_name(ozayn_prs_err_t err) {
    switch (err) {
        case OZAYN_PRS_OK: return "OK";
        case OZAYN_PRS_ERR_NULL: return "NULL";
        case OZAYN_PRS_ERR_NOT_INITIALIZED: return "NOT_INITIALIZED";
        case OZAYN_PRS_ERR_ALREADY_INIT: return "ALREADY_INIT";
        case OZAYN_PRS_ERR_INVALID_PARAM: return "INVALID_PARAM";
        case OZAYN_PRS_ERR_LIMIT_REACHED: return "LIMIT_REACHED";
        case OZAYN_PRS_ERR_NOT_FOUND: return "NOT_FOUND";
        case OZAYN_PRS_ERR_DUPLICATE: return "DUPLICATE";
        case OZAYN_PRS_ERR_STATE_INVALID: return "STATE_INVALID";
        case OZAYN_PRS_ERR_CHECKPOINT_INVALID: return "CHECKPOINT_INVALID";
        case OZAYN_PRS_ERR_CHECKPOINT_FAILED: return "CHECKPOINT_FAILED";
        case OZAYN_PRS_ERR_CHECKPOINT_COMMIT_FAILED: return "CHECKPOINT_COMMIT_FAILED";
        case OZAYN_PRS_ERR_SCHEMA_UNSUPPORTED: return "SCHEMA_UNSUPPORTED";
        case OZAYN_PRS_ERR_SCHEMA_MIGRATION_FAILED: return "SCHEMA_MIGRATION_FAILED";
        case OZAYN_PRS_ERR_STATE_CORRUPTED: return "STATE_CORRUPTED";
        case OZAYN_PRS_ERR_RECONCILIATION_FAILED: return "RECONCILIATION_FAILED";
        case OZAYN_PRS_ERR_DUPLICATE_EXECUTION_RISK: return "DUPLICATE_EXECUTION_RISK";
        case OZAYN_PRS_ERR_JOURNAL_FAILED: return "JOURNAL_FAILED";
        case OZAYN_PRS_ERR_EXPIRED: return "EXPIRED";
        case OZAYN_PRS_ERR_UNAVAILABLE: return "UNAVAILABLE";
        case OZAYN_PRS_ERR_CONCURRENCY: return "CONCURRENCY";
        case OZAYN_PRS_ERR_AUTHORIZATION_FAILED: return "AUTHORIZATION_FAILED";
        case OZAYN_PRS_ERR_SAFETY_RECHECK_FAILED: return "SAFETY_RECHECK_FAILED";
        case OZAYN_PRS_ERR_RESOURCE_RECHECK_FAILED: return "RESOURCE_RECHECK_FAILED";
        case OZAYN_PRS_ERR_DEVICE_RECHECK_FAILED: return "DEVICE_RECHECK_FAILED";
        case OZAYN_PRS_ERR_MANUAL_REVIEW_REQUIRED: return "MANUAL_REVIEW_REQUIRED";
        case OZAYN_PRS_ERR_WORKFLOW_INVALID: return "WORKFLOW_INVALID";
        case OZAYN_PRS_ERR_OPERATION_INTERRUPTED: return "OPERATION_INTERRUPTED";
        case OZAYN_PRS_ERR_OPERATION_UNKNOWN: return "OPERATION_UNKNOWN";
        case OZAYN_PRS_ERR_REJECTED: return "REJECTED";
        case OZAYN_PRS_ERR_EVENT_ERROR: return "EVENT_ERROR";
        default: return "UNKNOWN";
    }
}

const char *ozayn_prs_checkpoint_state_name(ozayn_prs_checkpoint_state_t state) {
    switch (state) {
        case OZAYN_PRS_CP_CREATED: return "CREATED";
        case OZAYN_PRS_CP_VALIDATING: return "VALIDATING";
        case OZAYN_PRS_CP_COMMITTED: return "COMMITTED";
        case OZAYN_PRS_CP_SUPERSEDED: return "SUPERSEDED";
        case OZAYN_PRS_CP_INVALID: return "INVALID";
        case OZAYN_PRS_CP_CORRUPTED: return "CORRUPTED";
        case OZAYN_PRS_CP_EXPIRED: return "EXPIRED";
        case OZAYN_PRS_CP_RECOVERY_REQUIRED: return "RECOVERY_REQUIRED";
        case OZAYN_PRS_CP_RECOVERED: return "RECOVERED";
        default: return "UNKNOWN";
    }
}

const char *ozayn_prs_recovery_eligibility_name(
    ozayn_prs_recovery_eligibility_t elig) {
    return ozayn_prs_eligibility_reason(elig);
}

const char *ozayn_prs_reconciliation_state_name(
    ozayn_prs_reconciliation_state_t state) {
    switch (state) {
        case OZAYN_PRS_RECON_PENDING: return "PENDING";
        case OZAYN_PRS_RECON_IN_PROGRESS: return "IN_PROGRESS";
        case OZAYN_PRS_RECON_COMPLETED: return "COMPLETED";
        case OZAYN_PRS_RECON_FAILED: return "FAILED";
        case OZAYN_PRS_RECON_BLOCKED: return "BLOCKED";
        default: return "UNKNOWN";
    }
}

const char *ozayn_prs_reconciliation_verdict_name(
    ozayn_prs_reconciliation_verdict_t verdict) {
    switch (verdict) {
        case OZAYN_PRS_VERDICT_COMPLETED: return "COMPLETED";
        case OZAYN_PRS_VERDICT_INTERRUPTED: return "INTERRUPTED";
        case OZAYN_PRS_VERDICT_FAILED: return "FAILED";
        case OZAYN_PRS_VERDICT_UNKNOWN_RESULT: return "UNKNOWN_RESULT";
        case OZAYN_PRS_VERDICT_RECOVERY_REQUIRED: return "RECOVERY_REQUIRED";
        case OZAYN_PRS_VERDICT_EXPIRED: return "EXPIRED";
        case OZAYN_PRS_VERDICT_CORRUPTED: return "CORRUPTED";
        case OZAYN_PRS_VERDICT_INELIGIBLE: return "INELIGIBLE";
        default: return "UNKNOWN";
    }
}

const char *ozayn_prs_journal_event_type_name(
    ozayn_prs_journal_event_type_t type) {
    switch (type) {
        case OZAYN_PRS_JOURNAL_CHECKPOINT_CREATED: return "CHECKPOINT_CREATED";
        case OZAYN_PRS_JOURNAL_CHECKPOINT_COMMITTED: return "CHECKPOINT_COMMITTED";
        case OZAYN_PRS_JOURNAL_CHECKPOINT_INVALIDATED: return "CHECKPOINT_INVALIDATED";
        case OZAYN_PRS_JOURNAL_CHECKPOINT_SUPERSEDED: return "CHECKPOINT_SUPERSEDED";
        case OZAYN_PRS_JOURNAL_WORKFLOW_INTERRUPTED: return "WORKFLOW_INTERRUPTED";
        case OZAYN_PRS_JOURNAL_RECOVERY_STARTED: return "RECOVERY_STARTED";
        case OZAYN_PRS_JOURNAL_RECONCILIATION_STARTED: return "RECONCILIATION_STARTED";
        case OZAYN_PRS_JOURNAL_RECONCILIATION_COMPLETED: return "RECONCILIATION_COMPLETED";
        case OZAYN_PRS_JOURNAL_RECOVERY_ELIGIBLE: return "RECOVERY_ELIGIBLE";
        case OZAYN_PRS_JOURNAL_RECOVERY_BLOCKED: return "RECOVERY_BLOCKED";
        case OZAYN_PRS_JOURNAL_RECOVERY_REJECTED: return "RECOVERY_REJECTED";
        case OZAYN_PRS_JOURNAL_RECOVERY_COMPLETED: return "RECOVERY_COMPLETED";
        case OZAYN_PRS_JOURNAL_DUPLICATE_EXECUTION_BLOCKED: return "DUPLICATE_EXECUTION_BLOCKED";
        case OZAYN_PRS_JOURNAL_STATE_CORRUPTED: return "STATE_CORRUPTED";
        case OZAYN_PRS_JOURNAL_SCHEMA_INCOMPATIBLE: return "SCHEMA_INCOMPATIBLE";
        case OZAYN_PRS_JOURNAL_RESTART_DETECTED: return "RESTART_DETECTED";
        default: return "UNKNOWN";
    }
}

const char *ozayn_prs_stage_recon_result_name(
    ozayn_prs_stage_recon_result_t result) {
    switch (result) {
        case OZAYN_PRS_STAGE_COMPLETED: return "COMPLETED";
        case OZAYN_PRS_STAGE_FAILED: return "FAILED";
        case OZAYN_PRS_STAGE_INTERRUPTED: return "INTERRUPTED";
        case OZAYN_PRS_STAGE_UNKNOWN: return "UNKNOWN";
        case OZAYN_PRS_STAGE_REQUIRES_REEVALUATION: return "REQUIRES_REEVALUATION";
        default: return "UNKNOWN";
    }
}

const char *ozayn_prs_operation_recon_result_name(
    ozayn_prs_operation_recon_result_t result) {
    switch (result) {
        case OZAYN_PRS_OP_COMPLETED: return "COMPLETED";
        case OZAYN_PRS_OP_FAILED: return "FAILED";
        case OZAYN_PRS_OP_INTERRUPTED: return "INTERRUPTED";
        case OZAYN_PRS_OP_UNKNOWN_RESULT: return "UNKNOWN_RESULT";
        case OZAYN_PRS_OP_DUPLICATE_RISK: return "DUPLICATE_RISK";
        default: return "UNKNOWN";
    }
}

const char *ozayn_prs_event_type_name(ozayn_prs_event_type_t type) {
    switch (type) {
        case OZAYN_PRS_EVENT_CHECKPOINT_CREATED: return "CHECKPOINT_CREATED";
        case OZAYN_PRS_EVENT_CHECKPOINT_COMMITTED: return "CHECKPOINT_COMMITTED";
        case OZAYN_PRS_EVENT_CHECKPOINT_FAILED: return "CHECKPOINT_FAILED";
        case OZAYN_PRS_EVENT_STATE_INVALID: return "STATE_INVALID";
        case OZAYN_PRS_EVENT_STATE_CORRUPTED: return "STATE_CORRUPTED";
        case OZAYN_PRS_EVENT_RESTART_DETECTED: return "RESTART_DETECTED";
        case OZAYN_PRS_EVENT_RECONCILIATION_STARTED: return "RECONCILIATION_STARTED";
        case OZAYN_PRS_EVENT_RECONCILIATION_COMPLETED: return "RECONCILIATION_COMPLETED";
        case OZAYN_PRS_EVENT_WORKFLOW_INTERRUPTED: return "WORKFLOW_INTERRUPTED";
        case OZAYN_PRS_EVENT_ELIGIBLE: return "ELIGIBLE";
        case OZAYN_PRS_EVENT_BLOCKED: return "BLOCKED";
        case OZAYN_PRS_EVENT_REQUIRES_REAUTHORIZATION: return "REQUIRES_REAUTHORIZATION";
        case OZAYN_PRS_EVENT_REQUIRES_SAFETY_RECHECK: return "REQUIRES_SAFETY_RECHECK";
        case OZAYN_PRS_EVENT_REQUIRES_RESOURCE_RECHECK: return "REQUIRES_RESOURCE_RECHECK";
        case OZAYN_PRS_EVENT_REQUIRES_DEVICE_RECHECK: return "REQUIRES_DEVICE_RECHECK";
        case OZAYN_PRS_EVENT_MANUAL_REVIEW: return "MANUAL_REVIEW";
        case OZAYN_PRS_EVENT_EXPIRED: return "EXPIRED";
        case OZAYN_PRS_EVENT_DUPLICATE_BLOCKED: return "DUPLICATE_BLOCKED";
        default: return "UNKNOWN";
    }
}
