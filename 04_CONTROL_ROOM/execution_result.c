#include "execution_result.h"
#include <string.h>
#include <stdio.h>

static ozayn_xr_result_record_t *find_result(ozayn_xr_service_t *svc, uint64_t record_id) {
    uint64_t count = svc->result_count < OZAYN_XR_MAX_RESULT_HISTORY ? svc->result_count : OZAYN_XR_MAX_RESULT_HISTORY;
    for (uint64_t i = 0; i < count; i++) {
        uint64_t idx = (svc->result_head - 1 - i + OZAYN_XR_MAX_RESULT_HISTORY) % OZAYN_XR_MAX_RESULT_HISTORY;
        if (svc->results[idx].record_id == record_id) return &svc->results[idx];
    }
    return 0;
}

static const ozayn_xr_result_record_t *find_result_const(const ozayn_xr_service_t *svc, uint64_t record_id) {
    uint64_t count = svc->result_count < OZAYN_XR_MAX_RESULT_HISTORY ? svc->result_count : OZAYN_XR_MAX_RESULT_HISTORY;
    for (uint64_t i = 0; i < count; i++) {
        uint64_t idx = (svc->result_head - 1 - i + OZAYN_XR_MAX_RESULT_HISTORY) % OZAYN_XR_MAX_RESULT_HISTORY;
        if (svc->results[idx].record_id == record_id) return &svc->results[idx];
    }
    return 0;
}

static void emit_event(ozayn_xr_service_t *svc, ozayn_xr_event_type_t etype,
                       const char *op_id, const char *res_id, const char *target_id) {
    ozayn_xr_event_t *ev = &svc->events[svc->event_head % OZAYN_XR_MAX_EVENTS];
    memset(ev, 0, sizeof(*ev));
    ev->event_id = ++svc->sequence;
    ev->event_type = etype;
    if (op_id) strncpy(ev->operation_id, op_id, OZAYN_XR_MAX_ID_LEN - 1);
    if (res_id) strncpy(ev->result_id, res_id, OZAYN_XR_MAX_ID_LEN - 1);
    if (target_id) strncpy(ev->target_component_id, target_id, OZAYN_XR_MAX_ID_LEN - 1);
    ev->event_time = time(0);
    svc->event_head++;
    svc->event_count++;
}

const char *ozayn_xr_exec_state_name(ozayn_xr_exec_state_t s) {
    switch (s) {
        case OZAYN_XR_EXEC_STARTED:      return "STARTED";
        case OZAYN_XR_EXEC_SUCCEEDED:    return "SUCCEEDED";
        case OZAYN_XR_EXEC_FAILED:       return "FAILED";
        case OZAYN_XR_EXEC_PARTIAL:      return "PARTIAL";
        case OZAYN_XR_EXEC_CANCELLED:    return "CANCELLED";
        case OZAYN_XR_EXEC_TIMEOUT:      return "TIMEOUT";
        case OZAYN_XR_EXEC_INTERRUPTED:  return "INTERRUPTED";
        case OZAYN_XR_EXEC_UNKNOWN:      return "UNKNOWN";
        case OZAYN_XR_EXEC_UNAVAILABLE:  return "UNAVAILABLE";
    }
    return "UNKNOWN";
}

const char *ozayn_xr_result_outcome_name(ozayn_xr_result_outcome_t o) {
    switch (o) {
        case OZAYN_XR_RESULT_SUCCESS:      return "SUCCESS";
        case OZAYN_XR_RESULT_FAILED:       return "FAILED";
        case OZAYN_XR_RESULT_PARTIAL:      return "PARTIAL";
        case OZAYN_XR_RESULT_CANCELLED:    return "CANCELLED";
        case OZAYN_XR_RESULT_TIMEOUT:      return "TIMEOUT";
        case OZAYN_XR_RESULT_INTERRUPTED:  return "INTERRUPTED";
        case OZAYN_XR_RESULT_UNKNOWN:      return "UNKNOWN";
        case OZAYN_XR_RESULT_UNAVAILABLE:  return "UNAVAILABLE";
        case OZAYN_XR_RESULT_DUPLICATE:    return "DUPLICATE";
    }
    return "UNKNOWN";
}

const char *ozayn_xr_recon_state_name(ozayn_xr_recon_state_t s) {
    switch (s) {
        case OZAYN_XR_RECON_PENDING:                    return "PENDING";
        case OZAYN_XR_RECON_IN_PROGRESS:                return "IN_PROGRESS";
        case OZAYN_XR_RECON_CONSISTENT:                 return "CONSISTENT";
        case OZAYN_XR_RECON_STATE_CHANGED_AS_EXPECTED:  return "STATE_CHANGED_AS_EXPECTED";
        case OZAYN_XR_RECON_STATE_CHANGED_UNEXPECTEDLY: return "STATE_CHANGED_UNEXPECTEDLY";
        case OZAYN_XR_RECON_PARTIAL:                    return "PARTIAL";
        case OZAYN_XR_RECON_INCONSISTENT:               return "INCONSISTENT";
        case OZAYN_XR_RECON_UNKNOWN:                    return "UNKNOWN";
        case OZAYN_XR_RECON_UNAVAILABLE:                return "UNAVAILABLE";
        case OZAYN_XR_RECON_REQUIRES_DIAGNOSTICS:       return "REQUIRES_DIAGNOSTICS";
    }
    return "UNKNOWN";
}

const char *ozayn_xr_event_type_name(ozayn_xr_event_type_t t) {
    switch (t) {
        case OZAYN_XR_EVENT_EXEC_STARTED:            return "EXEC_STARTED";
        case OZAYN_XR_EVENT_EXEC_COMPLETED:          return "EXEC_COMPLETED";
        case OZAYN_XR_EVENT_EXEC_SUCCEEDED:          return "EXEC_SUCCEEDED";
        case OZAYN_XR_EVENT_EXEC_FAILED:             return "EXEC_FAILED";
        case OZAYN_XR_EVENT_EXEC_PARTIAL:            return "EXEC_PARTIAL";
        case OZAYN_XR_EVENT_EXEC_CANCELLED:          return "EXEC_CANCELLED";
        case OZAYN_XR_EVENT_EXEC_TIMEOUT:            return "EXEC_TIMEOUT";
        case OZAYN_XR_EVENT_EXEC_INTERRUPTED:        return "EXEC_INTERRUPTED";
        case OZAYN_XR_EVENT_EXEC_UNKNOWN:            return "EXEC_UNKNOWN";
        case OZAYN_XR_EVENT_RECON_STARTED:           return "RECON_STARTED";
        case OZAYN_XR_EVENT_RECON_COMPLETED:         return "RECON_COMPLETED";
        case OZAYN_XR_EVENT_RECON_CONSISTENT:        return "RECON_CONSISTENT";
        case OZAYN_XR_EVENT_RECON_INCONSISTENT:      return "RECON_INCONSISTENT";
        case OZAYN_XR_EVENT_RECON_PARTIAL:           return "RECON_PARTIAL";
        case OZAYN_XR_EVENT_RECON_UNKNOWN:           return "RECON_UNKNOWN";
        case OZAYN_XR_EVENT_RECON_REQUIRED:          return "RECON_REQUIRED";
        case OZAYN_XR_EVENT_RESULT_RECORDED:         return "RESULT_RECORDED";
        case OZAYN_XR_EVENT_STATE_RECON_REQUIRED:    return "STATE_RECON_REQUIRED";
    }
    return "UNKNOWN";
}

const char *ozayn_xr_target_state_name(ozayn_xr_target_state_t s) {
    switch (s) {
        case OZAYN_XR_TARGET_AVAILABLE:    return "AVAILABLE";
        case OZAYN_XR_TARGET_UNAVAILABLE:  return "UNAVAILABLE";
        case OZAYN_XR_TARGET_UNKNOWN:      return "UNKNOWN";
    }
    return "UNKNOWN";
}

const char *ozayn_xr_resource_state_name(ozayn_xr_resource_state_t s) {
    switch (s) {
        case OZAYN_XR_RESOURCE_OK:              return "OK";
        case OZAYN_XR_RESOURCE_LEAK_DETECTED:   return "LEAK_DETECTED";
        case OZAYN_XR_RESOURCE_EXHAUSTED:       return "EXHAUSTED";
        case OZAYN_XR_RESOURCE_MISMATCH:        return "MISMATCH";
        case OZAYN_XR_RESOURCE_UNKNOWN:         return "UNKNOWN";
        case OZAYN_XR_RESOURCE_UNAVAILABLE:     return "UNAVAILABLE";
    }
    return "UNKNOWN";
}

const char *ozayn_xr_device_state_name(ozayn_xr_device_state_t s) {
    switch (s) {
        case OZAYN_XR_DEVICE_OK:                 return "OK";
        case OZAYN_XR_DEVICE_DISCONNECTED:       return "DISCONNECTED";
        case OZAYN_XR_DEVICE_SESSION_CLOSED:     return "SESSION_CLOSED";
        case OZAYN_XR_DEVICE_RESERVATION_LOST:   return "RESERVATION_LOST";
        case OZAYN_XR_DEVICE_UNKNOWN:            return "UNKNOWN";
        case OZAYN_XR_DEVICE_UNAVAILABLE:        return "UNAVAILABLE";
    }
    return "UNKNOWN";
}

const char *ozayn_xr_workflow_state_name(ozayn_xr_workflow_state_t s) {
    switch (s) {
        case OZAYN_XR_WORKFLOW_OK:               return "OK";
        case OZAYN_XR_WORKFLOW_STAGE_FAILED:     return "STAGE_FAILED";
        case OZAYN_XR_WORKFLOW_CANCELLED:        return "CANCELLED";
        case OZAYN_XR_WORKFLOW_UNKNOWN:          return "UNKNOWN";
        case OZAYN_XR_WORKFLOW_UNAVAILABLE:      return "UNAVAILABLE";
    }
    return "UNKNOWN";
}

const char *ozayn_xr_pipeline_state_name(ozayn_xr_pipeline_state_t s) {
    switch (s) {
        case OZAYN_XR_PIPELINE_OK:              return "OK";
        case OZAYN_XR_PIPELINE_STAGE_FAILED:    return "STAGE_FAILED";
        case OZAYN_XR_PIPELINE_FAILED:          return "FAILED";
        case OZAYN_XR_PIPELINE_UNKNOWN:         return "UNKNOWN";
        case OZAYN_XR_PIPELINE_UNAVAILABLE:     return "UNAVAILABLE";
    }
    return "UNKNOWN";
}

const char *ozayn_xr_scheduler_state_name(ozayn_xr_scheduler_state_t s) {
    switch (s) {
        case OZAYN_XR_SCHEDULER_RELEASED:       return "RELEASED";
        case OZAYN_XR_SCHEDULER_STILL_RUNNING:  return "STILL_RUNNING";
        case OZAYN_XR_SCHEDULER_UNKNOWN:        return "UNKNOWN";
        case OZAYN_XR_SCHEDULER_UNAVAILABLE:    return "UNAVAILABLE";
    }
    return "UNKNOWN";
}

const char *ozayn_xr_diagnostic_state_name(ozayn_xr_diagnostic_state_t s) {
    switch (s) {
        case OZAYN_XR_DIAG_NONE:        return "NONE";
        case OZAYN_XR_DIAG_REQUESTED:   return "REQUESTED";
        case OZAYN_XR_DIAG_COMPLETED:   return "COMPLETED";
        case OZAYN_XR_DIAG_UNAVAILABLE: return "UNAVAILABLE";
    }
    return "UNKNOWN";
}

int ozayn_xr_is_exec_terminal(ozayn_xr_exec_state_t state) {
    return state == OZAYN_XR_EXEC_SUCCEEDED ||
           state == OZAYN_XR_EXEC_FAILED ||
           state == OZAYN_XR_EXEC_PARTIAL ||
           state == OZAYN_XR_EXEC_CANCELLED ||
           state == OZAYN_XR_EXEC_TIMEOUT ||
           state == OZAYN_XR_EXEC_INTERRUPTED ||
           state == OZAYN_XR_EXEC_UNKNOWN ||
           state == OZAYN_XR_EXEC_UNAVAILABLE;
}

int ozayn_xr_is_recon_terminal(ozayn_xr_recon_state_t state) {
    return state == OZAYN_XR_RECON_CONSISTENT ||
           state == OZAYN_XR_RECON_STATE_CHANGED_AS_EXPECTED ||
           state == OZAYN_XR_RECON_STATE_CHANGED_UNEXPECTEDLY ||
           state == OZAYN_XR_RECON_PARTIAL ||
           state == OZAYN_XR_RECON_INCONSISTENT ||
           state == OZAYN_XR_RECON_UNKNOWN ||
           state == OZAYN_XR_RECON_UNAVAILABLE ||
           state == OZAYN_XR_RECON_REQUIRES_DIAGNOSTICS;
}

int ozayn_xr_init(ozayn_xr_service_t *svc) {
    if (!svc) return OZAYN_XR_ERR_NULL_PTR;
    if (svc->initialized) return OZAYN_XR_ERR_ALREADY_INITIALIZED;
    memset(svc, 0, sizeof(*svc));
    svc->initialized = 1;
    return OZAYN_XR_ERR_OK;
}

int ozayn_xr_shutdown(ozayn_xr_service_t *svc) {
    if (!svc) return OZAYN_XR_ERR_NULL_PTR;
    if (!svc->initialized) return OZAYN_XR_ERR_NOT_INITIALIZED;
    svc->initialized = 0;
    return OZAYN_XR_ERR_OK;
}

int ozayn_xr_is_initialized(const ozayn_xr_service_t *svc) {
    if (!svc) return 0;
    return svc->initialized;
}

int ozayn_xr_bind_subsystems(ozayn_xr_service_t *svc, const ozayn_xr_subsystem_bind_t *bind) {
    if (!svc || !bind) return OZAYN_XR_ERR_NULL_PTR;
    if (!svc->initialized) return OZAYN_XR_ERR_NOT_INITIALIZED;
    svc->bind = *bind;
    return OZAYN_XR_ERR_OK;
}

int ozayn_xr_result_record(ozayn_xr_service_t *svc,
                           const char *result_id,
                           const char *execution_record_id,
                           const char *operation_id,
                           const char *request_id,
                           const char *target_component_id,
                           const char *capability_id,
                           const char *action,
                           const char *requester_identity,
                           const char *session_id,
                           ozayn_xr_exec_state_t exec_state,
                           ozayn_xr_result_outcome_t outcome,
                           int result_code,
                           const char *error_detail,
                           time_t started_time,
                           time_t completed_time,
                           int64_t duration_ms,
                           int64_t admission_ref,
                           int64_t enforcement_ref,
                           ozayn_xr_result_record_t **out_record) {
    if (!svc) return OZAYN_XR_ERR_NULL_PTR;
    if (!svc->initialized) return OZAYN_XR_ERR_NOT_INITIALIZED;
    if (!result_id || !operation_id) return OZAYN_XR_ERR_NULL_PTR;
    if (ozayn_xr_is_exec_terminal(exec_state)) return OZAYN_XR_ERR_INVALID_STATE;

    {
    uint64_t search_count = svc->result_count < OZAYN_XR_MAX_RESULT_HISTORY ? svc->result_count : OZAYN_XR_MAX_RESULT_HISTORY;
    for (uint64_t i = 0; i < search_count; i++) {
        uint64_t idx = (svc->result_head - 1 - i + OZAYN_XR_MAX_RESULT_HISTORY) % OZAYN_XR_MAX_RESULT_HISTORY;
        if (svc->results[idx].finalized &&
            strncmp(svc->results[idx].result_id, result_id, OZAYN_XR_MAX_ID_LEN) == 0) {
            return OZAYN_XR_ERR_DUPLICATE;
        }
    }
    }

    uint64_t pos = svc->result_head % OZAYN_XR_MAX_RESULT_HISTORY;
    ozayn_xr_result_record_t *rec = &svc->results[pos];
    memset(rec, 0, sizeof(*rec));
    rec->record_id = ++svc->sequence;
    strncpy(rec->result_id, result_id, OZAYN_XR_MAX_ID_LEN - 1);
    if (execution_record_id) strncpy(rec->execution_record_id, execution_record_id, OZAYN_XR_MAX_ID_LEN - 1);
    strncpy(rec->operation_id, operation_id, OZAYN_XR_MAX_ID_LEN - 1);
    if (request_id) strncpy(rec->request_id, request_id, OZAYN_XR_MAX_ID_LEN - 1);
    if (target_component_id) strncpy(rec->target_component_id, target_component_id, OZAYN_XR_MAX_ID_LEN - 1);
    if (capability_id) strncpy(rec->capability_id, capability_id, OZAYN_XR_MAX_ID_LEN - 1);
    if (action) strncpy(rec->action, action, OZAYN_XR_MAX_COMPONENT_ID - 1);
    if (requester_identity) strncpy(rec->requester_identity, requester_identity, OZAYN_XR_MAX_ID_LEN - 1);
    if (session_id) strncpy(rec->session_id, session_id, OZAYN_XR_MAX_ID_LEN - 1);
    rec->result.exec_state = exec_state;
    rec->result.outcome = outcome;
    rec->result.result_code = result_code;
    if (error_detail) strncpy(rec->result.error_detail, error_detail, OZAYN_XR_MAX_ERROR_DETAIL - 1);
    rec->result.started_time = started_time;
    rec->result.completed_time = completed_time;
    rec->result.duration_ms = duration_ms;
    rec->admission_ref = admission_ref;
    rec->enforcement_ref = enforcement_ref;
    rec->reconciliation.recon_state = OZAYN_XR_RECON_PENDING;
    rec->recorded_time = time(0);
    rec->finalized = 0;

    svc->result_head++;
    svc->result_count++;
    svc->stats.total_results_received++;
    svc->stats.current_pending++;

    emit_event(svc, OZAYN_XR_EVENT_EXEC_STARTED, operation_id, result_id, target_component_id);
    emit_event(svc, OZAYN_XR_EVENT_RESULT_RECORDED, operation_id, result_id, target_component_id);

    if (out_record) *out_record = rec;
    return OZAYN_XR_ERR_OK;
}

int ozayn_xr_result_record_duplicate_check(const ozayn_xr_service_t *svc,
                                           const char *result_id,
                                           const char *operation_id,
                                           const char *execution_record_id) {
    if (!svc) return OZAYN_XR_ERR_NULL_PTR;
    if (!svc->initialized) return OZAYN_XR_ERR_NOT_INITIALIZED;
    if (!result_id) return OZAYN_XR_ERR_NULL_PTR;
    {
    uint64_t search_count = svc->result_count < OZAYN_XR_MAX_RESULT_HISTORY ? svc->result_count : OZAYN_XR_MAX_RESULT_HISTORY;
    for (uint64_t i = 0; i < search_count; i++) {
        uint64_t idx = (svc->result_head - 1 - i + OZAYN_XR_MAX_RESULT_HISTORY) % OZAYN_XR_MAX_RESULT_HISTORY;
        const ozayn_xr_result_record_t *r = &svc->results[idx];
        if (!r->finalized) continue;
        if (result_id && strncmp(r->result_id, result_id, OZAYN_XR_MAX_ID_LEN) == 0) return 1;
        if (operation_id && execution_record_id &&
            strncmp(r->operation_id, operation_id, OZAYN_XR_MAX_ID_LEN) == 0 &&
            strncmp(r->execution_record_id, execution_record_id, OZAYN_XR_MAX_ID_LEN) == 0) return 1;
    }
    }
    return 0;
}

int ozayn_xr_result_update(ozayn_xr_service_t *svc,
                           uint64_t record_id,
                           ozayn_xr_exec_state_t exec_state,
                           ozayn_xr_result_outcome_t outcome,
                           int result_code,
                           const char *error_detail,
                           time_t completed_time,
                           int64_t duration_ms) {
    if (!svc) return OZAYN_XR_ERR_NULL_PTR;
    if (!svc->initialized) return OZAYN_XR_ERR_NOT_INITIALIZED;
    ozayn_xr_result_record_t *rec = find_result(svc, record_id);
    if (!rec) return OZAYN_XR_ERR_NOT_FOUND;
    if (rec->finalized) return OZAYN_XR_ERR_INVALID_STATE;
    if (!ozayn_xr_is_exec_terminal(exec_state)) return OZAYN_XR_ERR_INVALID_STATE;
    rec->result.exec_state = exec_state;
    rec->result.outcome = outcome;
    rec->result.result_code = result_code;
    if (error_detail) strncpy(rec->result.error_detail, error_detail, OZAYN_XR_MAX_ERROR_DETAIL - 1);
    rec->result.completed_time = completed_time;
    rec->result.duration_ms = duration_ms;
    return OZAYN_XR_ERR_OK;
}

static int query_target_state(ozayn_xr_service_t *svc, const char *target_id, ozayn_xr_target_state_t *out) {
    (void)target_id;
    if (!svc->bind.component_registry) { *out = OZAYN_XR_TARGET_UNAVAILABLE; return OZAYN_XR_ERR_OK; }
    *out = OZAYN_XR_TARGET_AVAILABLE;
    return OZAYN_XR_ERR_OK;
}

static int query_resource_state(ozayn_xr_service_t *svc, const char *target_id, ozayn_xr_resource_state_t *out) {
    (void)target_id;
    if (!svc->bind.resource_manager) { *out = OZAYN_XR_RESOURCE_UNAVAILABLE; return OZAYN_XR_ERR_OK; }
    *out = OZAYN_XR_RESOURCE_OK;
    return OZAYN_XR_ERR_OK;
}

static int query_device_state(ozayn_xr_service_t *svc, const char *target_id, ozayn_xr_device_state_t *out) {
    (void)target_id;
    if (!svc->bind.device_session) { *out = OZAYN_XR_DEVICE_UNAVAILABLE; return OZAYN_XR_ERR_OK; }
    *out = OZAYN_XR_DEVICE_OK;
    return OZAYN_XR_ERR_OK;
}

static int query_workflow_state(ozayn_xr_service_t *svc, const char *operation_id, ozayn_xr_workflow_state_t *out) {
    (void)operation_id;
    if (!svc->bind.workflow_orchestrator) { *out = OZAYN_XR_WORKFLOW_UNAVAILABLE; return OZAYN_XR_ERR_OK; }
    *out = OZAYN_XR_WORKFLOW_OK;
    return OZAYN_XR_ERR_OK;
}

static int query_pipeline_state(ozayn_xr_service_t *svc, const char *operation_id, ozayn_xr_pipeline_state_t *out) {
    (void)operation_id;
    if (!svc->bind.pipeline_coordinator) { *out = OZAYN_XR_PIPELINE_UNAVAILABLE; return OZAYN_XR_ERR_OK; }
    *out = OZAYN_XR_PIPELINE_OK;
    return OZAYN_XR_ERR_OK;
}

static int query_scheduler_state(ozayn_xr_service_t *svc, const char *operation_id, ozayn_xr_scheduler_state_t *out) {
    (void)operation_id;
    if (!svc->bind.pipeline_scheduler) { *out = OZAYN_XR_SCHEDULER_UNAVAILABLE; return OZAYN_XR_ERR_OK; }
    *out = OZAYN_XR_SCHEDULER_RELEASED;
    return OZAYN_XR_ERR_OK;
}

int ozayn_xr_reconcile(ozayn_xr_service_t *svc,
                       uint64_t record_id,
                       ozayn_xr_recon_state_t *out_recon_state) {
    ozayn_xr_reconciliation_t recon;
    int rc = ozayn_xr_reconcile_full(svc, record_id, &recon);
    if (rc != OZAYN_XR_ERR_OK) return rc;
    if (out_recon_state) *out_recon_state = recon.recon_state;
    return OZAYN_XR_ERR_OK;
}

int ozayn_xr_reconcile_full(ozayn_xr_service_t *svc,
                            uint64_t record_id,
                            ozayn_xr_reconciliation_t *out_recon) {
    if (!svc || !out_recon) return OZAYN_XR_ERR_NULL_PTR;
    if (!svc->initialized) return OZAYN_XR_ERR_NOT_INITIALIZED;
    ozayn_xr_result_record_t *rec = find_result(svc, record_id);
    if (!rec) return OZAYN_XR_ERR_NOT_FOUND;
    memset(out_recon, 0, sizeof(*out_recon));

    ozayn_xr_target_state_t ts;
    ozayn_xr_resource_state_t rs;
    ozayn_xr_device_state_t ds;
    ozayn_xr_workflow_state_t ws;
    ozayn_xr_pipeline_state_t ps;
    ozayn_xr_scheduler_state_t ss;

    query_target_state(svc, rec->target_component_id, &ts);
    query_resource_state(svc, rec->target_component_id, &rs);
    query_device_state(svc, rec->target_component_id, &ds);
    query_workflow_state(svc, rec->operation_id, &ws);
    query_pipeline_state(svc, rec->operation_id, &ps);
    query_scheduler_state(svc, rec->operation_id, &ss);

    out_recon->target_state = ts;
    out_recon->resource_state = rs;
    out_recon->device_state = ds;
    out_recon->workflow_state = ws;
    out_recon->pipeline_state = ps;
    out_recon->scheduler_state = ss;

    if (rec->result.exec_state == OZAYN_XR_EXEC_UNKNOWN ||
        rec->result.exec_state == OZAYN_XR_EXEC_UNAVAILABLE) {
        out_recon->recon_state = OZAYN_XR_RECON_UNKNOWN;
        out_recon->requires_diagnostics = 1;
    } else if (rec->result.exec_state == OZAYN_XR_EXEC_SUCCEEDED) {
        if (ts == OZAYN_XR_TARGET_UNAVAILABLE) {
            out_recon->recon_state = OZAYN_XR_RECON_UNKNOWN;
        } else if (ts == OZAYN_XR_TARGET_AVAILABLE && rs == OZAYN_XR_RESOURCE_OK &&
            ds == OZAYN_XR_DEVICE_OK && ws == OZAYN_XR_WORKFLOW_OK &&
            ps == OZAYN_XR_PIPELINE_OK) {
            out_recon->recon_state = OZAYN_XR_RECON_CONSISTENT;
        } else if (ds == OZAYN_XR_DEVICE_DISCONNECTED ||
                   ds == OZAYN_XR_DEVICE_SESSION_CLOSED) {
            out_recon->recon_state = OZAYN_XR_RECON_STATE_CHANGED_UNEXPECTEDLY;
            out_recon->requires_diagnostics = 1;
        } else {
            out_recon->recon_state = OZAYN_XR_RECON_PARTIAL;
        }
    } else if (rec->result.exec_state == OZAYN_XR_EXEC_FAILED) {
        if (ts == OZAYN_XR_TARGET_UNAVAILABLE) {
            out_recon->recon_state = OZAYN_XR_RECON_UNKNOWN;
        } else if (ds == OZAYN_XR_DEVICE_DISCONNECTED || ds == OZAYN_XR_DEVICE_SESSION_CLOSED) {
            out_recon->recon_state = OZAYN_XR_RECON_INCONSISTENT;
            out_recon->requires_diagnostics = 1;
        } else if (ts == OZAYN_XR_TARGET_AVAILABLE && ds == OZAYN_XR_DEVICE_OK) {
            out_recon->recon_state = OZAYN_XR_RECON_INCONSISTENT;
            out_recon->requires_diagnostics = 1;
        } else {
            out_recon->recon_state = OZAYN_XR_RECON_PARTIAL;
        }
    } else if (rec->result.exec_state == OZAYN_XR_EXEC_TIMEOUT) {
        if (ts == OZAYN_XR_TARGET_UNAVAILABLE) {
            out_recon->recon_state = OZAYN_XR_RECON_UNKNOWN;
        } else if (ts == OZAYN_XR_TARGET_AVAILABLE && ds == OZAYN_XR_DEVICE_OK) {
            out_recon->recon_state = OZAYN_XR_RECON_STATE_CHANGED_UNEXPECTEDLY;
            out_recon->requires_diagnostics = 1;
        } else {
            out_recon->recon_state = OZAYN_XR_RECON_UNKNOWN;
        }
    } else if (rec->result.exec_state == OZAYN_XR_EXEC_CANCELLED) {
        if (ws == OZAYN_XR_WORKFLOW_UNAVAILABLE) {
            out_recon->recon_state = OZAYN_XR_RECON_UNKNOWN;
        } else if (ws == OZAYN_XR_WORKFLOW_CANCELLED) {
            out_recon->recon_state = OZAYN_XR_RECON_STATE_CHANGED_AS_EXPECTED;
        } else {
            out_recon->recon_state = OZAYN_XR_RECON_PARTIAL;
        }
    } else if (rec->result.exec_state == OZAYN_XR_EXEC_INTERRUPTED) {
        out_recon->recon_state = OZAYN_XR_RECON_UNKNOWN;
        out_recon->requires_diagnostics = 1;
    } else {
        out_recon->recon_state = OZAYN_XR_RECON_UNKNOWN;
    }

    if (out_recon->requires_diagnostics) {
        out_recon->diagnostic_state = OZAYN_XR_DIAG_REQUESTED;
        svc->stats.total_requires_diagnostics++;
    }

    rec->reconciliation = *out_recon;

    return OZAYN_XR_ERR_OK;
}

int ozayn_xr_reconcile_target(ozayn_xr_service_t *svc,
                              uint64_t record_id,
                              const char *expected_state,
                              const char *actual_state,
                              ozayn_xr_recon_state_t *out_recon_state) {
    if (!svc || !expected_state || !actual_state) return OZAYN_XR_ERR_NULL_PTR;
    if (!svc->initialized) return OZAYN_XR_ERR_NOT_INITIALIZED;
    ozayn_xr_result_record_t *rec = find_result(svc, record_id);
    if (!rec) return OZAYN_XR_ERR_NOT_FOUND;

    ozayn_xr_recon_state_t rs;
    if (strncmp(expected_state, actual_state, OZAYN_XR_MAX_COMPONENT_ID) == 0) {
        rs = OZAYN_XR_RECON_CONSISTENT;
    } else {
        rs = OZAYN_XR_RECON_INCONSISTENT;
    }

    if (rec->reconciliation.recon_state == OZAYN_XR_RECON_PENDING) {
        svc->recon_head++;
        svc->recon_count++;
    }
    strncpy(rec->reconciliation.target_expected_state, expected_state, OZAYN_XR_MAX_COMPONENT_ID - 1);
    strncpy(rec->reconciliation.target_actual_state, actual_state, OZAYN_XR_MAX_COMPONENT_ID - 1);
    rec->reconciliation.state_comparison_valid = 1;
    rec->reconciliation.recon_state = rs;
    svc->stats.total_reconciliations++;
    if (rs == OZAYN_XR_RECON_CONSISTENT) svc->stats.total_consistent++;
    else svc->stats.total_inconsistent++;

    if (out_recon_state) *out_recon_state = rs;
    return OZAYN_XR_ERR_OK;
}

int ozayn_xr_result_finalize(ozayn_xr_service_t *svc, uint64_t record_id) {
    if (!svc) return OZAYN_XR_ERR_NULL_PTR;
    if (!svc->initialized) return OZAYN_XR_ERR_NOT_INITIALIZED;
    ozayn_xr_result_record_t *rec = find_result(svc, record_id);
    if (!rec) return OZAYN_XR_ERR_NOT_FOUND;
    if (rec->finalized) return OZAYN_XR_ERR_INVALID_STATE;
    rec->finalized = 1;
    svc->stats.current_pending--;
    svc->stats.current_finalized++;

    ozayn_xr_exec_state_t es = rec->result.exec_state;
    if (es == OZAYN_XR_EXEC_SUCCEEDED) svc->stats.total_succeeded++;
    else if (es == OZAYN_XR_EXEC_FAILED) svc->stats.total_failed++;
    else if (es == OZAYN_XR_EXEC_PARTIAL) svc->stats.total_partial++;
    else if (es == OZAYN_XR_EXEC_CANCELLED) svc->stats.total_cancelled++;
    else if (es == OZAYN_XR_EXEC_TIMEOUT) svc->stats.total_timeout++;
    else if (es == OZAYN_XR_EXEC_INTERRUPTED) svc->stats.total_interrupted++;
    else if (es == OZAYN_XR_EXEC_UNKNOWN) svc->stats.total_unknown++;
    else if (es == OZAYN_XR_EXEC_UNAVAILABLE) svc->stats.total_unavailable++;

    ozayn_xr_recon_state_t rstate = rec->reconciliation.recon_state;
    if (rstate != OZAYN_XR_RECON_PENDING) {
        svc->stats.total_reconciliations++;
        if (rstate == OZAYN_XR_RECON_CONSISTENT || rstate == OZAYN_XR_RECON_STATE_CHANGED_AS_EXPECTED) {
            svc->stats.total_consistent++;
        } else if (rstate == OZAYN_XR_RECON_INCONSISTENT || rstate == OZAYN_XR_RECON_STATE_CHANGED_UNEXPECTEDLY) {
            svc->stats.total_inconsistent++;
        } else if (rstate == OZAYN_XR_RECON_PARTIAL) {
            svc->stats.total_partial_reconciliations++;
        } else if (rstate == OZAYN_XR_RECON_UNKNOWN || rstate == OZAYN_XR_RECON_UNAVAILABLE) {
            svc->stats.total_unknown_reconciliations++;
        }
    }

    emit_event(svc, OZAYN_XR_EVENT_EXEC_COMPLETED, rec->operation_id, rec->result_id, rec->target_component_id);
    if (es == OZAYN_XR_EXEC_SUCCEEDED) emit_event(svc, OZAYN_XR_EVENT_EXEC_SUCCEEDED, rec->operation_id, rec->result_id, rec->target_component_id);
    else if (es == OZAYN_XR_EXEC_FAILED) emit_event(svc, OZAYN_XR_EVENT_EXEC_FAILED, rec->operation_id, rec->result_id, rec->target_component_id);
    else if (es == OZAYN_XR_EXEC_PARTIAL) emit_event(svc, OZAYN_XR_EVENT_EXEC_PARTIAL, rec->operation_id, rec->result_id, rec->target_component_id);
    else if (es == OZAYN_XR_EXEC_CANCELLED) emit_event(svc, OZAYN_XR_EVENT_EXEC_CANCELLED, rec->operation_id, rec->result_id, rec->target_component_id);
    else if (es == OZAYN_XR_EXEC_TIMEOUT) emit_event(svc, OZAYN_XR_EVENT_EXEC_TIMEOUT, rec->operation_id, rec->result_id, rec->target_component_id);
    else if (es == OZAYN_XR_EXEC_INTERRUPTED) emit_event(svc, OZAYN_XR_EVENT_EXEC_INTERRUPTED, rec->operation_id, rec->result_id, rec->target_component_id);
    else if (es == OZAYN_XR_EXEC_UNKNOWN) emit_event(svc, OZAYN_XR_EVENT_EXEC_UNKNOWN, rec->operation_id, rec->result_id, rec->target_component_id);

    if (rec->reconciliation.recon_state != OZAYN_XR_RECON_PENDING) {
        emit_event(svc, OZAYN_XR_EVENT_RECON_COMPLETED, rec->operation_id, rec->result_id, rec->target_component_id);
    }

    return OZAYN_XR_ERR_OK;
}

int ozayn_xr_result_get(const ozayn_xr_service_t *svc,
                        uint64_t record_id,
                        const ozayn_xr_result_record_t **out_record) {
    if (!svc || !out_record) return OZAYN_XR_ERR_NULL_PTR;
    if (!svc->initialized) return OZAYN_XR_ERR_NOT_INITIALIZED;
    const ozayn_xr_result_record_t *rec = find_result_const(svc, record_id);
    if (!rec) return OZAYN_XR_ERR_NOT_FOUND;
    *out_record = rec;
    return OZAYN_XR_ERR_OK;
}

int ozayn_xr_result_get_by_operation(const ozayn_xr_service_t *svc,
                                     const char *operation_id,
                                     const ozayn_xr_result_record_t **out_record) {
    if (!svc || !operation_id || !out_record) return OZAYN_XR_ERR_NULL_PTR;
    if (!svc->initialized) return OZAYN_XR_ERR_NOT_INITIALIZED;
    {
    uint64_t count = svc->result_count < OZAYN_XR_MAX_RESULT_HISTORY ? svc->result_count : OZAYN_XR_MAX_RESULT_HISTORY;
    for (uint64_t i = 0; i < count; i++) {
        uint64_t idx = (svc->result_head - 1 - i + OZAYN_XR_MAX_RESULT_HISTORY) % OZAYN_XR_MAX_RESULT_HISTORY;
        if (strncmp(svc->results[idx].operation_id, operation_id, OZAYN_XR_MAX_ID_LEN) == 0) {
            *out_record = &svc->results[idx];
            return OZAYN_XR_ERR_OK;
        }
    }
    }
    return OZAYN_XR_ERR_NOT_FOUND;
}

int ozayn_xr_result_get_pending(const ozayn_xr_service_t *svc,
                                const ozayn_xr_result_record_t **out_records,
                                uint64_t max_count,
                                uint64_t *out_count) {
    if (!svc || !out_records || !out_count) return OZAYN_XR_ERR_NULL_PTR;
    if (!svc->initialized) return OZAYN_XR_ERR_NOT_INITIALIZED;
    uint64_t cnt = 0;
    {
    uint64_t count = svc->result_count < OZAYN_XR_MAX_RESULT_HISTORY ? svc->result_count : OZAYN_XR_MAX_RESULT_HISTORY;
    for (uint64_t i = 0; i < count && cnt < max_count; i++) {
        uint64_t idx = (svc->result_head - 1 - i + OZAYN_XR_MAX_RESULT_HISTORY) % OZAYN_XR_MAX_RESULT_HISTORY;
        if (!svc->results[idx].finalized) {
            out_records[cnt++] = &svc->results[idx];
        }
    }
    }
    *out_count = cnt;
    return OZAYN_XR_ERR_OK;
}

int ozayn_xr_result_get_finalized(const ozayn_xr_service_t *svc,
                                  const ozayn_xr_result_record_t **out_records,
                                  uint64_t max_count,
                                  uint64_t *out_count) {
    if (!svc || !out_records || !out_count) return OZAYN_XR_ERR_NULL_PTR;
    if (!svc->initialized) return OZAYN_XR_ERR_NOT_INITIALIZED;
    uint64_t cnt = 0;
    {
    uint64_t count = svc->result_count < OZAYN_XR_MAX_RESULT_HISTORY ? svc->result_count : OZAYN_XR_MAX_RESULT_HISTORY;
    for (uint64_t i = 0; i < count && cnt < max_count; i++) {
        uint64_t idx = (svc->result_head - 1 - i + OZAYN_XR_MAX_RESULT_HISTORY) % OZAYN_XR_MAX_RESULT_HISTORY;
        if (svc->results[idx].finalized) {
            out_records[cnt++] = &svc->results[idx];
        }
    }
    }
    *out_count = cnt;
    return OZAYN_XR_ERR_OK;
}

int ozayn_xr_recon_get(const ozayn_xr_service_t *svc,
                       uint64_t record_id,
                       const ozayn_xr_result_record_t **out_record) {
    if (!svc || !out_record) return OZAYN_XR_ERR_NULL_PTR;
    if (!svc->initialized) return OZAYN_XR_ERR_NOT_INITIALIZED;
    {
    uint64_t count = svc->recon_count < OZAYN_XR_MAX_RECONCILIATION_HISTORY ? svc->recon_count : OZAYN_XR_MAX_RECONCILIATION_HISTORY;
    for (uint64_t i = 0; i < count; i++) {
        uint64_t idx = (svc->recon_head - 1 - i + OZAYN_XR_MAX_RECONCILIATION_HISTORY) % OZAYN_XR_MAX_RECONCILIATION_HISTORY;
        if (svc->reconciliations[idx].record_id == record_id) {
            *out_record = &svc->reconciliations[idx];
            return OZAYN_XR_ERR_OK;
        }
    }
    }
    return OZAYN_XR_ERR_NOT_FOUND;
}

int ozayn_xr_recon_get_by_operation(const ozayn_xr_service_t *svc,
                                    const char *operation_id,
                                    const ozayn_xr_result_record_t **out_record) {
    if (!svc || !operation_id || !out_record) return OZAYN_XR_ERR_NULL_PTR;
    if (!svc->initialized) return OZAYN_XR_ERR_NOT_INITIALIZED;
    {
    uint64_t count = svc->recon_count < OZAYN_XR_MAX_RECONCILIATION_HISTORY ? svc->recon_count : OZAYN_XR_MAX_RECONCILIATION_HISTORY;
    for (uint64_t i = 0; i < count; i++) {
        uint64_t idx = (svc->recon_head - 1 - i + OZAYN_XR_MAX_RECONCILIATION_HISTORY) % OZAYN_XR_MAX_RECONCILIATION_HISTORY;
        if (strncmp(svc->reconciliations[idx].operation_id, operation_id, OZAYN_XR_MAX_ID_LEN) == 0) {
            *out_record = &svc->reconciliations[idx];
            return OZAYN_XR_ERR_OK;
        }
    }
    }
    return OZAYN_XR_ERR_NOT_FOUND;
}

int ozayn_xr_event_emit(ozayn_xr_service_t *svc,
                        ozayn_xr_event_type_t event_type,
                        const char *operation_id,
                        const char *result_id,
                        const char *target_component_id) {
    if (!svc) return OZAYN_XR_ERR_NULL_PTR;
    if (!svc->initialized) return OZAYN_XR_ERR_NOT_INITIALIZED;
    emit_event(svc, event_type, operation_id, result_id, target_component_id);
    return OZAYN_XR_ERR_OK;
}

int ozayn_xr_event_get(const ozayn_xr_service_t *svc,
                       uint64_t event_id,
                       const ozayn_xr_event_t **out_event) {
    if (!svc || !out_event) return OZAYN_XR_ERR_NULL_PTR;
    if (!svc->initialized) return OZAYN_XR_ERR_NOT_INITIALIZED;
    {
    uint64_t count = svc->event_count < OZAYN_XR_MAX_EVENTS ? svc->event_count : OZAYN_XR_MAX_EVENTS;
    for (uint64_t i = 0; i < count; i++) {
        uint64_t idx = (svc->event_head - 1 - i + OZAYN_XR_MAX_EVENTS) % OZAYN_XR_MAX_EVENTS;
        if (svc->events[idx].event_id == event_id) {
            *out_event = &svc->events[idx];
            return OZAYN_XR_ERR_OK;
        }
    }
    }
    return OZAYN_XR_ERR_NOT_FOUND;
}

int ozayn_xr_event_get_by_operation(const ozayn_xr_service_t *svc,
                                    const char *operation_id,
                                    const ozayn_xr_event_t **out_events,
                                    uint64_t max_count,
                                    uint64_t *out_count) {
    if (!svc || !operation_id || !out_events || !out_count) return OZAYN_XR_ERR_NULL_PTR;
    if (!svc->initialized) return OZAYN_XR_ERR_NOT_INITIALIZED;
    uint64_t cnt = 0;
    {
    uint64_t count = svc->event_count < OZAYN_XR_MAX_EVENTS ? svc->event_count : OZAYN_XR_MAX_EVENTS;
    for (uint64_t i = 0; i < count && cnt < max_count; i++) {
        uint64_t idx = (svc->event_head - 1 - i + OZAYN_XR_MAX_EVENTS) % OZAYN_XR_MAX_EVENTS;
        if (strncmp(svc->events[idx].operation_id, operation_id, OZAYN_XR_MAX_ID_LEN) == 0) {
            out_events[cnt++] = &svc->events[idx];
        }
    }
    }
    *out_count = cnt;
    return OZAYN_XR_ERR_OK;
}

int ozayn_xr_stats_get(const ozayn_xr_service_t *svc, ozayn_xr_stats_t *out_stats) {
    if (!svc || !out_stats) return OZAYN_XR_ERR_NULL_PTR;
    if (!svc->initialized) return OZAYN_XR_ERR_NOT_INITIALIZED;
    *out_stats = svc->stats;
    return OZAYN_XR_ERR_OK;
}

int64_t ozayn_xr_pending_count(const ozayn_xr_service_t *svc) {
    if (!svc || !svc->initialized) return -1;
    return (int64_t)svc->stats.current_pending;
}

int64_t ozayn_xr_finalized_count(const ozayn_xr_service_t *svc) {
    if (!svc || !svc->initialized) return -1;
    return (int64_t)svc->stats.current_finalized;
}

int ozayn_xr_shutdown_drain(ozayn_xr_service_t *svc,
                            ozayn_xr_result_record_t **out_unresolved,
                            uint64_t max_count,
                            uint64_t *out_count) {
    if (!svc || !out_unresolved || !out_count) return OZAYN_XR_ERR_NULL_PTR;
    if (!svc->initialized) return OZAYN_XR_ERR_NOT_INITIALIZED;
    uint64_t cnt = 0;
    {
    uint64_t count = svc->result_count < OZAYN_XR_MAX_RESULT_HISTORY ? svc->result_count : OZAYN_XR_MAX_RESULT_HISTORY;
    for (uint64_t i = 0; i < count && cnt < max_count; i++) {
        uint64_t idx = (svc->result_head - 1 - i + OZAYN_XR_MAX_RESULT_HISTORY) % OZAYN_XR_MAX_RESULT_HISTORY;
        if (!svc->results[idx].finalized) {
            out_unresolved[cnt++] = &svc->results[idx];
        }
    }
    }
    *out_count = cnt;
    return OZAYN_XR_ERR_OK;
}
