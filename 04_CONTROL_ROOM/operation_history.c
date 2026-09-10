/*
 * operation_history.c — Operation History & Execution Records
 *
 * Provides persistent, immutable historical records of completed
 * operations for the OZAYN Control Room.
 *
 * Step 06/35 — Control Room
 */

#include "operation_history.h"
#include <string.h>
#include <stdio.h>

/* ============================================================
 * INTERNAL — STATIC GLOBAL
 * ============================================================ */

static ozayn_oh_service_t _oh_global;
static int _oh_global_init = 0;

/* ============================================================
 * SECTION 1 — NAME HELPERS
 * ============================================================ */

const char *ozayn_oh_err_name(ozayn_oh_err_t err)
{
    switch (err) {
    case OZAYN_OH_OK:                    return "OK";
    case OZAYN_OH_ERR_NULL:              return "NULL";
    case OZAYN_OH_ERR_NOT_INITIALIZED:   return "NOT_INITIALIZED";
    case OZAYN_OH_ERR_ALREADY_INITIALIZED: return "ALREADY_INITIALIZED";
    case OZAYN_OH_ERR_INVALID_PARAM:     return "INVALID_PARAM";
    case OZAYN_OH_ERR_NOT_FOUND:         return "NOT_FOUND";
    case OZAYN_OH_ERR_DUPLICATE_RECORD:  return "DUPLICATE_RECORD";
    case OZAYN_OH_ERR_IMMUTABLE:         return "IMMUTABLE";
    case OZAYN_OH_ERR_STORAGE_FULL:      return "STORAGE_FULL";
    case OZAYN_OH_ERR_STATE_INVALID:     return "STATE_INVALID";
    case OZAYN_OH_ERR_STATE_TRANSITION:  return "STATE_TRANSITION";
    case OZAYN_OH_ERR_RETRY_EXHAUSTED:   return "RETRY_EXHAUSTED";
    case OZAYN_OH_ERR_NOT_TERMINAL:      return "NOT_TERMINAL";
    case OZAYN_OH_ERR_STORAGE_FAILURE:   return "STORAGE_FAILURE";
    }
    return "UNKNOWN";
}

const char *ozayn_oh_state_name(ozayn_oh_state_t state)
{
    switch (state) {
    case OZAYN_OH_STATE_SUCCEEDED:   return "SUCCEEDED";
    case OZAYN_OH_STATE_FAILED:      return "FAILED";
    case OZAYN_OH_STATE_CANCELLED:   return "CANCELLED";
    case OZAYN_OH_STATE_TIMEOUT:     return "TIMEOUT";
    case OZAYN_OH_STATE_REJECTED:    return "REJECTED";
    case OZAYN_OH_STATE_EXPIRED:     return "EXPIRED";
    case OZAYN_OH_STATE_UNAVAILABLE: return "UNAVAILABLE";
    case OZAYN_OH_STATE_UNSUPPORTED: return "UNSUPPORTED";
    case OZAYN_OH_STATE_COUNT:       break;
    }
    return "UNKNOWN";
}

const char *ozayn_oh_result_name(ozayn_oh_result_t result)
{
    switch (result) {
    case OZAYN_OH_RESULT_SUCCESS:                return "SUCCESS";
    case OZAYN_OH_RESULT_TARGET_UNAVAILABLE:     return "TARGET_UNAVAILABLE";
    case OZAYN_OH_RESULT_CAPABILITY_UNAVAILABLE: return "CAPABILITY_UNAVAILABLE";
    case OZAYN_OH_RESULT_AUTHORIZATION_FAILED:   return "AUTHORIZATION_FAILED";
    case OZAYN_OH_RESULT_PRECONDITION_FAILED:    return "PRECONDITION_FAILED";
    case OZAYN_OH_RESULT_TIMEOUT:                return "TIMEOUT";
    case OZAYN_OH_RESULT_CANCELLED:              return "CANCELLED";
    case OZAYN_OH_RESULT_DISPATCH_FAILED:        return "DISPATCH_FAILED";
    case OZAYN_OH_RESULT_RESOURCE_LIMIT:         return "RESOURCE_LIMIT";
    case OZAYN_OH_RESULT_INTERNAL_ERROR:         return "INTERNAL_ERROR";
    case OZAYN_OH_RESULT_REJECTED:               return "REJECTED";
    case OZAYN_OH_RESULT_EXPIRED:                return "EXPIRED";
    case OZAYN_OH_RESULT_UNAVAILABLE:            return "UNAVAILABLE";
    case OZAYN_OH_RESULT_UNSUPPORTED:            return "UNSUPPORTED";
    case OZAYN_OH_RESULT_COUNT:                  break;
    }
    return "UNKNOWN";
}

const char *ozayn_oh_failure_name(ozayn_oh_failure_t failure)
{
    switch (failure) {
    case OZAYN_OH_FAILURE_NONE:                    return "NONE";
    case OZAYN_OH_FAILURE_COMPONENT_DOWN:          return "COMPONENT_DOWN";
    case OZAYN_OH_FAILURE_COMPONENT_BUSY:          return "COMPONENT_BUSY";
    case OZAYN_OH_FAILURE_COMPONENT_MISSING:       return "COMPONENT_MISSING";
    case OZAYN_OH_FAILURE_CAPABILITY_MISSING:      return "CAPABILITY_MISSING";
    case OZAYN_OH_FAILURE_CAPABILITY_MISSING_PROVIDER: return "CAPABILITY_MISSING_PROVIDER";
    case OZAYN_OH_FAILURE_AUTH_DENIED:             return "AUTH_DENIED";
    case OZAYN_OH_FAILURE_AUTH_UNAVAILABLE:        return "AUTH_UNAVAILABLE";
    case OZAYN_OH_FAILURE_PRECONDITION_UNMET:      return "PRECONDITION_UNMET";
    case OZAYN_OH_FAILURE_DEPENDENCY_MISSING:      return "DEPENDENCY_MISSING";
    case OZAYN_OH_FAILURE_TIMEOUT_EXCEEDED:        return "TIMEOUT_EXCEEDED";
    case OZAYN_OH_FAILURE_USER_CANCEL:             return "USER_CANCEL";
    case OZAYN_OH_FAILURE_DISPATCH_ERROR:          return "DISPATCH_ERROR";
    case OZAYN_OH_FAILURE_INTERNAL:                return "INTERNAL";
    case OZAYN_OH_FAILURE_STORAGE:                 return "STORAGE";
    case OZAYN_OH_FAILURE_RESOURCE_EXHAUSTED:      return "RESOURCE_EXHAUSTED";
    case OZAYN_OH_FAILURE_COUNT:                   break;
    }
    return "UNKNOWN";
}

const char *ozayn_oh_action_name(ozayn_oh_action_t action)
{
    switch (action) {
    case OZAYN_OH_ACTION_START:      return "START";
    case OZAYN_OH_ACTION_STOP:       return "STOP";
    case OZAYN_OH_ACTION_PAUSE:      return "PAUSE";
    case OZAYN_OH_ACTION_RESUME:     return "RESUME";
    case OZAYN_OH_ACTION_QUERY:      return "QUERY";
    case OZAYN_OH_ACTION_RESTART:    return "RESTART";
    case OZAYN_OH_ACTION_ENABLE:     return "ENABLE";
    case OZAYN_OH_ACTION_DISABLE:    return "DISABLE";
    case OZAYN_OH_ACTION_DIAGNOSTIC: return "DIAGNOSTIC";
    case OZAYN_OH_ACTION_COUNT:      break;
    }
    return "UNKNOWN";
}

const char *ozayn_oh_event_type_name(ozayn_oh_event_type_t type)
{
    switch (type) {
    case OZAYN_OH_EVENT_CREATED:           return "CREATED";
    case OZAYN_OH_EVENT_ATTEMPT_STARTED:   return "ATTEMPT_STARTED";
    case OZAYN_OH_EVENT_ATTEMPT_COMPLETED: return "ATTEMPT_COMPLETED";
    case OZAYN_OH_EVENT_ATTEMPT_FAILED:    return "ATTEMPT_FAILED";
    case OZAYN_OH_EVENT_ATTEMPT_CANCELLED: return "ATTEMPT_CANCELLED";
    case OZAYN_OH_EVENT_ATTEMPT_TIMEOUT:   return "ATTEMPT_TIMEOUT";
    case OZAYN_OH_EVENT_RECORD_FINALIZED:  return "RECORD_FINALIZED";
    case OZAYN_OH_EVENT_RECORD_EXPIRED:    return "RECORD_EXPIRED";
    case OZAYN_OH_EVENT_COUNT:             break;
    }
    return "UNKNOWN";
}

/* ============================================================
 * SECTION 2 — VALIDATION HELPERS
 * ============================================================ */

static int _is_terminal(ozayn_oh_state_t state)
{
    return state == OZAYN_OH_STATE_SUCCEEDED ||
           state == OZAYN_OH_STATE_FAILED ||
           state == OZAYN_OH_STATE_CANCELLED ||
           state == OZAYN_OH_STATE_TIMEOUT ||
           state == OZAYN_OH_STATE_REJECTED ||
           state == OZAYN_OH_STATE_EXPIRED ||
           state == OZAYN_OH_STATE_UNAVAILABLE ||
           state == OZAYN_OH_STATE_UNSUPPORTED;
}

static int _find_record(const ozayn_oh_service_t *svc, const char *record_id)
{
    if (!svc || !record_id || record_id[0] == '\0') return -1;
    for (int i = 0; i < svc->count; i++) {
        int idx = (svc->head + i) % OZAYN_OH_MAX_RECORDS;
        if (svc->records[idx].active &&
            strcmp(svc->records[idx].record_id, record_id) == 0)
            return idx;
    }
    return -1;
}

static int _find_record_by_request(const ozayn_oh_service_t *svc, const char *request_id)
{
    if (!svc || !request_id || request_id[0] == '\0') return -1;
    for (int i = 0; i < svc->count; i++) {
        int idx = (svc->head + i) % OZAYN_OH_MAX_RECORDS;
        if (svc->records[idx].active &&
            strcmp(svc->records[idx].request_id, request_id) == 0)
            return idx;
    }
    return -1;
}

static int _find_record_by_operation_id(const ozayn_oh_service_t *svc, const char *operation_id)
{
    if (!svc || !operation_id || operation_id[0] == '\0') return -1;
    for (int i = 0; i < svc->count; i++) {
        int idx = (svc->head + i) % OZAYN_OH_MAX_RECORDS;
        if (svc->records[idx].active &&
            strcmp(svc->records[idx].operation_id, operation_id) == 0)
            return idx;
    }
    return -1;
}

static void _update_stats(ozayn_oh_service_t *svc, ozayn_oh_state_t state)
{
    svc->stats.current_count = svc->count;
    switch (state) {
    case OZAYN_OH_STATE_SUCCEEDED:   svc->stats.total_succeeded++; break;
    case OZAYN_OH_STATE_FAILED:      svc->stats.total_failed++; break;
    case OZAYN_OH_STATE_CANCELLED:   svc->stats.total_cancelled++; break;
    case OZAYN_OH_STATE_TIMEOUT:     svc->stats.total_timeout++; break;
    case OZAYN_OH_STATE_REJECTED:    svc->stats.total_rejected++; break;
    case OZAYN_OH_STATE_EXPIRED:     svc->stats.total_expired++; break;
    case OZAYN_OH_STATE_UNAVAILABLE: svc->stats.total_unavailable++; break;
    case OZAYN_OH_STATE_UNSUPPORTED: svc->stats.total_unsupported++; break;
    case OZAYN_OH_STATE_COUNT:       break;
    }
}

static void _compute_durations(ozayn_oh_record_t *rec)
{
    if (rec->created_time > 0 && rec->completed_time > 0)
        rec->total_duration_ms = (int)(rec->completed_time - rec->created_time) * 1000;
    if (rec->queued_time > 0 && rec->started_time > 0)
        rec->queue_duration_ms = (int)(rec->started_time - rec->queued_time) * 1000;
    if (rec->started_time > 0 && rec->completed_time > 0)
        rec->execution_duration_ms = (int)(rec->completed_time - rec->started_time) * 1000;
}

/* ============================================================
 * SECTION 3 — LIFECYCLE
 * ============================================================ */

ozayn_oh_err_t ozayn_oh_service_init(
    ozayn_oh_service_t *svc,
    const ozayn_oh_service_config_t *cfg)
{
    if (!svc) return OZAYN_OH_ERR_NULL;
    if (svc->initialized) return OZAYN_OH_ERR_ALREADY_INITIALIZED;

    memset(svc, 0, sizeof(*svc));

    if (cfg) {
        svc->audit = cfg->audit;
        svc->event_engine = cfg->event_engine;
        if (cfg->retention.max_records > 0)
            svc->retention = cfg->retention;
        else {
            svc->retention.max_records = OZAYN_OH_MAX_RECORDS;
            svc->retention.max_age_seconds = 30 * 24 * 3600;
            svc->retention.max_storage_bytes = 0;
            svc->retention.retain_security_records = 1;
        }
    } else {
        svc->retention.max_records = OZAYN_OH_MAX_RECORDS;
        svc->retention.max_age_seconds = 30 * 24 * 3600;
        svc->retention.max_storage_bytes = 0;
        svc->retention.retain_security_records = 1;
    }

    svc->stats.storage_capacity = OZAYN_OH_MAX_RECORDS;
    svc->initialized = 1;

    if (!_oh_global_init) {
        memset(&_oh_global, 0, sizeof(_oh_global));
        _oh_global = *svc;
        _oh_global_init = 1;
    }

    return OZAYN_OH_OK;
}

void ozayn_oh_service_shutdown(ozayn_oh_service_t *svc)
{
    if (!svc) return;
    svc->initialized = 0;
    memset(svc->records, 0, sizeof(svc->records));
    svc->count = 0;
}

int ozayn_oh_service_is_initialized(const ozayn_oh_service_t *svc)
{
    if (!svc) return 0;
    return svc->initialized;
}

/* ============================================================
 * SECTION 4 — RECORD CREATION
 * ============================================================ */

ozayn_oh_err_t ozayn_oh_record_create(
    ozayn_oh_service_t *svc,
    const char *operation_id,
    const char *request_id,
    const char *target,
    const char *capability,
    ozayn_oh_action_t action,
    const char *required_permission,
    const char *requester_identity,
    const char *session_id,
    int max_retries,
    ozayn_oh_record_t **out_record)
{
    if (!svc) return OZAYN_OH_ERR_NULL;
    if (!svc->initialized) return OZAYN_OH_ERR_NOT_INITIALIZED;
    if (!operation_id || operation_id[0] == '\0') return OZAYN_OH_ERR_INVALID_PARAM;
    if (!request_id || request_id[0] == '\0') return OZAYN_OH_ERR_INVALID_PARAM;
    if (!target || target[0] == '\0') return OZAYN_OH_ERR_INVALID_PARAM;
    if (action < 0 || action >= OZAYN_OH_ACTION_COUNT) return OZAYN_OH_ERR_INVALID_PARAM;
    if (svc->count >= svc->retention.max_records) return OZAYN_OH_ERR_STORAGE_FULL;

    /* Check for duplicate operation_id */
    if (_find_record_by_operation_id(svc, operation_id) >= 0)
        return OZAYN_OH_ERR_DUPLICATE_RECORD;

    int idx = (svc->head + svc->count) % OZAYN_OH_MAX_RECORDS;
    ozayn_oh_record_t *rec = &svc->records[idx];
    memset(rec, 0, sizeof(*rec));

    svc->sequence++;
    snprintf(rec->record_id, OZAYN_OH_MAX_ID_LEN, "OHR-%u", svc->sequence);
    strncpy(rec->operation_id, operation_id, OZAYN_OH_MAX_ID_LEN - 1);
    strncpy(rec->request_id, request_id, OZAYN_OH_MAX_ID_LEN - 1);
    strncpy(rec->target, target, OZAYN_OH_MAX_TARGET_LEN - 1);
    if (capability) strncpy(rec->capability, capability, OZAYN_OH_MAX_CAP_LEN - 1);
    rec->action = action;
    if (required_permission)
        strncpy(rec->required_permission, required_permission, OZAYN_OH_MAX_PERMISSION_LEN - 1);
    if (requester_identity)
        strncpy(rec->requester_identity, requester_identity, OZAYN_OH_MAX_IDENTITY_LEN - 1);
    if (session_id)
        strncpy(rec->session_id, session_id, OZAYN_OH_MAX_SESSION_LEN - 1);
    rec->max_retries = max_retries;
    rec->created_time = time(NULL);
    rec->active = 1;
    rec->finalized = 0;

    svc->count++;
    svc->stats.total_recorded++;
    svc->stats.current_count = svc->count;

    ozayn_oh_emit_event(svc, OZAYN_OH_EVENT_CREATED, rec->record_id, "history record created");
    ozayn_oh_audit_record(svc, rec->record_id, "HISTORY_CREATED", "operation history record created");

    if (out_record) *out_record = rec;
    return OZAYN_OH_OK;
}

ozayn_oh_err_t ozayn_oh_record_finalize(
    ozayn_oh_service_t *svc,
    const char *record_id,
    ozayn_oh_state_t final_state,
    ozayn_oh_result_t result_category,
    int result_code,
    const char *failure_detail)
{
    if (!svc) return OZAYN_OH_ERR_NULL;
    if (!svc->initialized) return OZAYN_OH_ERR_NOT_INITIALIZED;
    if (!record_id || record_id[0] == '\0') return OZAYN_OH_ERR_INVALID_PARAM;
    if (!_is_terminal(final_state)) return OZAYN_OH_ERR_NOT_TERMINAL;

    int idx = _find_record(svc, record_id);
    if (idx < 0) return OZAYN_OH_ERR_NOT_FOUND;

    ozayn_oh_record_t *rec = &svc->records[idx];
    if (rec->finalized) return OZAYN_OH_ERR_IMMUTABLE;

    rec->final_state = final_state;
    rec->result_category = result_category;
    rec->result_code = result_code;
    rec->completed_time = time(NULL);
    if (failure_detail)
        strncpy(rec->failure_detail, failure_detail, OZAYN_OH_MAX_ERROR_LEN - 1);
    _compute_durations(rec);
    _update_stats(svc, final_state);
    rec->finalized = 1;

    ozayn_oh_emit_event(svc, OZAYN_OH_EVENT_RECORD_FINALIZED, rec->record_id,
        ozayn_oh_state_name(final_state));
    ozayn_oh_audit_record(svc, rec->record_id, "HISTORY_FINALIZED",
        ozayn_oh_state_name(final_state));

    return OZAYN_OH_OK;
}

/* ============================================================
 * SECTION 5 — ATTEMPT MANAGEMENT
 * ============================================================ */

ozayn_oh_err_t ozayn_oh_attempt_start(
    ozayn_oh_service_t *svc,
    const char *record_id,
    ozayn_oh_attempt_t **out_attempt)
{
    if (!svc) return OZAYN_OH_ERR_NULL;
    if (!svc->initialized) return OZAYN_OH_ERR_NOT_INITIALIZED;
    if (!record_id || record_id[0] == '\0') return OZAYN_OH_ERR_INVALID_PARAM;

    int idx = _find_record(svc, record_id);
    if (idx < 0) return OZAYN_OH_ERR_NOT_FOUND;

    ozayn_oh_record_t *rec = &svc->records[idx];
    if (rec->finalized) return OZAYN_OH_ERR_IMMUTABLE;
    if (rec->attempt_count >= OZAYN_OH_MAX_ATTEMPTS) return OZAYN_OH_ERR_RETRY_EXHAUSTED;

    ozayn_oh_attempt_t *att = &rec->attempts[rec->attempt_count];
    memset(att, 0, sizeof(*att));

    rec->attempt_count++;
    svc->stats.total_retries++;

    att->attempt_number = rec->attempt_count;
    snprintf(att->attempt_id, OZAYN_OH_MAX_ID_LEN, "ATM-%s-%d", record_id, att->attempt_number);
    att->attempt_state = OZAYN_OH_STATE_SUCCEEDED;
    att->started_time = time(NULL);

    if (rec->attempt_count == 1)
        rec->started_time = att->started_time;

    ozayn_oh_emit_event(svc, OZAYN_OH_EVENT_ATTEMPT_STARTED, rec->record_id,
        att->attempt_id);

    if (out_attempt) *out_attempt = att;
    return OZAYN_OH_OK;
}

ozayn_oh_err_t ozayn_oh_attempt_complete(
    ozayn_oh_service_t *svc,
    const char *record_id,
    const char *attempt_id,
    ozayn_oh_state_t attempt_state,
    ozayn_oh_result_t result_category,
    int result_code,
    const char *error_detail)
{
    if (!svc) return OZAYN_OH_ERR_NULL;
    if (!svc->initialized) return OZAYN_OH_ERR_NOT_INITIALIZED;
    if (!record_id || record_id[0] == '\0') return OZAYN_OH_ERR_INVALID_PARAM;
    if (!attempt_id || attempt_id[0] == '\0') return OZAYN_OH_ERR_INVALID_PARAM;

    int idx = _find_record(svc, record_id);
    if (idx < 0) return OZAYN_OH_ERR_NOT_FOUND;

    ozayn_oh_record_t *rec = &svc->records[idx];

    ozayn_oh_attempt_t *att = NULL;
    for (int i = 0; i < rec->attempt_count; i++) {
        if (strcmp(rec->attempts[i].attempt_id, attempt_id) == 0) {
            att = &rec->attempts[i];
            break;
        }
    }
    if (!att) return OZAYN_OH_ERR_NOT_FOUND;

    att->attempt_state = attempt_state;
    att->attempt_result = result_category;
    att->result_code = result_code;
    att->completed_time = time(NULL);
    if (att->started_time > 0)
        att->duration_ms = (int)(att->completed_time - att->started_time) * 1000;
    if (error_detail)
        strncpy(att->error_detail, error_detail, OZAYN_OH_MAX_ERROR_LEN - 1);

    if (attempt_state == OZAYN_OH_STATE_FAILED) {
        rec->retry_count++;
        ozayn_oh_emit_event(svc, OZAYN_OH_EVENT_ATTEMPT_FAILED, rec->record_id,
            att->attempt_id);
    } else if (attempt_state == OZAYN_OH_STATE_CANCELLED) {
        ozayn_oh_emit_event(svc, OZAYN_OH_EVENT_ATTEMPT_CANCELLED, rec->record_id,
            att->attempt_id);
    } else if (attempt_state == OZAYN_OH_STATE_TIMEOUT) {
        ozayn_oh_emit_event(svc, OZAYN_OH_EVENT_ATTEMPT_TIMEOUT, rec->record_id,
            att->attempt_id);
    } else {
        ozayn_oh_emit_event(svc, OZAYN_OH_EVENT_ATTEMPT_COMPLETED, rec->record_id,
            att->attempt_id);
    }

    return OZAYN_OH_OK;
}

/* ============================================================
 * SECTION 6 — IMMUTABILITY
 * ============================================================ */

int ozayn_oh_record_is_finalized(
    const ozayn_oh_service_t *svc,
    const char *record_id)
{
    if (!svc || !svc->initialized || !record_id || record_id[0] == '\0') return 0;
    int idx = _find_record(svc, record_id);
    if (idx < 0) return 0;
    return svc->records[idx].finalized;
}

/* ============================================================
 * SECTION 7 — QUERY
 * ============================================================ */

const ozayn_oh_record_t *ozayn_oh_record_get(
    const ozayn_oh_service_t *svc,
    const char *record_id)
{
    if (!svc || !svc->initialized || !record_id || record_id[0] == '\0') return NULL;
    int idx = _find_record(svc, record_id);
    if (idx < 0) return NULL;
    return &svc->records[idx];
}

const ozayn_oh_record_t *ozayn_oh_record_get_by_operation(
    const ozayn_oh_service_t *svc,
    const char *operation_id)
{
    if (!svc || !svc->initialized || !operation_id || operation_id[0] == '\0') return NULL;
    int idx = _find_record_by_operation_id(svc, operation_id);
    if (idx < 0) return NULL;
    return &svc->records[idx];
}

const ozayn_oh_record_t *ozayn_oh_record_get_by_request(
    const ozayn_oh_service_t *svc,
    const char *request_id)
{
    if (!svc || !svc->initialized || !request_id || request_id[0] == '\0') return NULL;
    int idx = _find_record_by_request(svc, request_id);
    if (idx < 0) return NULL;
    return &svc->records[idx];
}

static int _matches_filter(const ozayn_oh_record_t *rec, const ozayn_oh_query_t *filter)
{
    if (!filter) return 1;

    if ((filter->filter_flags & OZAYN_OH_FILTER_TARGET) &&
        strcmp(rec->target, filter->target) != 0) return 0;

    if ((filter->filter_flags & OZAYN_OH_FILTER_CAPABILITY) &&
        strcmp(rec->capability, filter->capability) != 0) return 0;

    if ((filter->filter_flags & OZAYN_OH_FILTER_ACTION) &&
        rec->action != filter->action) return 0;

    if ((filter->filter_flags & OZAYN_OH_FILTER_STATE) &&
        rec->final_state != filter->state) return 0;

    if ((filter->filter_flags & OZAYN_OH_FILTER_RESULT) &&
        rec->result_category != filter->result) return 0;

    if ((filter->filter_flags & OZAYN_OH_FILTER_REQUESTER) &&
        strcmp(rec->requester_identity, filter->requester_identity) != 0) return 0;

    if ((filter->filter_flags & OZAYN_OH_FILTER_REQUEST_ID) &&
        strcmp(rec->request_id, filter->request_id) != 0) return 0;

    if ((filter->filter_flags & OZAYN_OH_FILTER_TIME_START) &&
        rec->completed_time < filter->time_start) return 0;

    if ((filter->filter_flags & OZAYN_OH_FILTER_TIME_END) &&
        rec->completed_time > filter->time_end) return 0;

    return 1;
}

ozayn_oh_err_t ozayn_oh_query(
    const ozayn_oh_service_t *svc,
    const ozayn_oh_query_t *filter,
    ozayn_oh_query_results_t *results)
{
    if (!svc) return OZAYN_OH_ERR_NULL;
    if (!results) return OZAYN_OH_ERR_NULL;
    if (!svc->initialized) return OZAYN_OH_ERR_NOT_INITIALIZED;

    memset(results, 0, sizeof(*results));

    int limit = OZAYN_OH_MAX_QUERY_RESULTS;
    int offset = 0;
    if (filter) {
        if (filter->limit > 0 && filter->limit < OZAYN_OH_MAX_QUERY_RESULTS)
            limit = filter->limit;
        if (filter->offset > 0) offset = filter->offset;
    }

    int total = 0;
    int matched = 0;
    int skipped = 0;

    for (int i = 0; i < svc->count; i++) {
        int idx = (svc->head + i) % OZAYN_OH_MAX_RECORDS;
        if (!svc->records[idx].active) continue;

        if (_matches_filter(&svc->records[idx], filter)) {
            total++;
            if (skipped < offset) {
                skipped++;
                continue;
            }
            if (matched < limit) {
                results->results[matched] = &svc->records[idx];
                matched++;
            }
        }
    }

    results->result_count = matched;
    results->total_count = total;
    results->has_more = (skipped + matched) < total;

    return OZAYN_OH_OK;
}

int ozayn_oh_record_count(const ozayn_oh_service_t *svc)
{
    if (!svc || !svc->initialized) return 0;
    return svc->count;
}

int ozayn_oh_total_recorded(const ozayn_oh_service_t *svc)
{
    if (!svc || !svc->initialized) return 0;
    return (int)svc->stats.total_recorded;
}

/* ============================================================
 * SECTION 8 — RETENTION
 * ============================================================ */

int ozayn_oh_retention_check(ozayn_oh_service_t *svc)
{
    if (!svc || !svc->initialized) return 0;

    int expired = 0;
    time_t now = time(NULL);

    if (svc->retention.max_records > 0 && svc->count > svc->retention.max_records) {
        int excess = svc->count - svc->retention.max_records;
        for (int i = 0; i < excess && svc->count > 0; i++) {
            int idx = svc->head % OZAYN_OH_MAX_RECORDS;
            if (svc->retention.retain_security_records &&
                svc->records[idx].finalized) {
                continue;
            }
            svc->records[idx].active = 0;
            svc->head = (svc->head + 1) % OZAYN_OH_MAX_RECORDS;
            svc->count--;
            expired++;
        }
    }

    if (svc->retention.max_age_seconds > 0) {
        for (int i = 0; i < svc->count; i++) {
            int idx = (svc->head + i) % OZAYN_OH_MAX_RECORDS;
            if (!svc->records[idx].active) continue;
            if (svc->records[idx].finalized &&
                svc->records[idx].completed_time > 0 &&
                (now - svc->records[idx].completed_time) > svc->retention.max_age_seconds) {
                if (svc->retention.retain_security_records) continue;
                svc->records[idx].active = 0;
                svc->count--;
                expired++;
            }
        }
    }

    svc->stats.total_expired_by_retention += expired;
    svc->stats.current_count = svc->count;
    return expired;
}

ozayn_oh_err_t ozayn_oh_retention_set(
    ozayn_oh_service_t *svc,
    const ozayn_oh_retention_t *retention)
{
    if (!svc) return OZAYN_OH_ERR_NULL;
    if (!svc->initialized) return OZAYN_OH_ERR_NOT_INITIALIZED;
    if (!retention) return OZAYN_OH_ERR_INVALID_PARAM;
    svc->retention = *retention;
    return OZAYN_OH_OK;
}

const ozayn_oh_retention_t *ozayn_oh_retention_get(const ozayn_oh_service_t *svc)
{
    if (!svc || !svc->initialized) return NULL;
    return &svc->retention;
}

/* ============================================================
 * SECTION 9 — STATISTICS
 * ============================================================ */

ozayn_oh_err_t ozayn_oh_get_stats(
    const ozayn_oh_service_t *svc,
    ozayn_oh_stats_t *out_stats)
{
    if (!svc) return OZAYN_OH_ERR_NULL;
    if (!out_stats) return OZAYN_OH_ERR_NULL;
    if (!svc->initialized) return OZAYN_OH_ERR_NOT_INITIALIZED;
    *out_stats = svc->stats;
    return OZAYN_OH_OK;
}

/* ============================================================
 * SECTION 10 — EVENT INTEGRATION
 * ============================================================ */

ozayn_oh_err_t ozayn_oh_emit_event(
    ozayn_oh_service_t *svc,
    ozayn_oh_event_type_t event_type,
    const char *record_id,
    const char *detail)
{
    if (!svc) return OZAYN_OH_ERR_NULL;
    (void)event_type;
    (void)record_id;
    (void)detail;
    return OZAYN_OH_OK;
}

/* ============================================================
 * SECTION 11 — AUDIT INTEGRATION
 * ============================================================ */

ozayn_oh_err_t ozayn_oh_audit_record(
    ozayn_oh_service_t *svc,
    const char *record_id,
    const char *event_type,
    const char *detail)
{
    if (!svc) return OZAYN_OH_ERR_NULL;
    if (!record_id || record_id[0] == '\0') return OZAYN_OH_ERR_INVALID_PARAM;
    if (!event_type || event_type[0] == '\0') return OZAYN_OH_ERR_INVALID_PARAM;
    (void)detail;
    return OZAYN_OH_OK;
}

/* ============================================================
 * SECTION 12 — VALIDATION
 * ============================================================ */

int ozayn_oh_record_validate(const ozayn_oh_record_t *record)
{
    if (!record) return 0;
    if (record->record_id[0] == '\0') return 0;
    if (record->operation_id[0] == '\0') return 0;
    if (record->request_id[0] == '\0') return 0;
    if (record->target[0] == '\0') return 0;
    if (record->action < 0 || record->action >= OZAYN_OH_ACTION_COUNT) return 0;
    if (record->created_time <= 0) return 0;
    if (record->finalized && !_is_terminal(record->final_state)) return 0;
    return 1;
}

int ozayn_oh_record_is_terminal(ozayn_oh_state_t state)
{
    return _is_terminal(state);
}

/* ============================================================
 * SECTION 13 — CLEANUP
 * ============================================================ */

int ozayn_oh_cleanup_expired(ozayn_oh_service_t *svc)
{
    if (!svc || !svc->initialized) return 0;
    return ozayn_oh_retention_check(svc);
}

int ozayn_oh_cleanup_all(ozayn_oh_service_t *svc)
{
    if (!svc || !svc->initialized) return 0;
    int cleaned = svc->count;
    memset(svc->records, 0, sizeof(svc->records));
    svc->count = 0;
    svc->head = 0;
    svc->stats.current_count = 0;
    return cleaned;
}

/* ============================================================
 * SECTION 14 — GLOBAL ACCESSOR
 * ============================================================ */

ozayn_oh_service_t *ozayn_oh_get_global(void)
{
    if (!_oh_global_init) {
        memset(&_oh_global, 0, sizeof(_oh_global));
        _oh_global_init = 1;
    }
    return &_oh_global;
}
