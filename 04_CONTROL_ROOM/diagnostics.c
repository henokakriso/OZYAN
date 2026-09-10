/*
 * diagnostics.c — Diagnostics & Health Assessment Foundation
 *
 * Provides structured, bounded diagnostics and health assessment
 * for the OZAYN Control Room.
 *
 * Step 07/35 — Control Room
 */

#include "diagnostics.h"
#include <string.h>
#include <stdio.h>

/* ============================================================
 * INTERNAL — STATIC GLOBAL
 * ============================================================ */

static ozayn_dha_service_t _diag_global;
static int _diag_global_init = 0;

/* ============================================================
 * SECTION 1 — NAME HELPERS
 * ============================================================ */

const char *ozayn_dha_err_name(ozayn_dha_err_t err)
{
    switch (err) {
    case OZAYN_DHA_OK:                      return "OK";
    case OZAYN_DHA_ERR_NULL:                return "NULL";
    case OZAYN_DHA_ERR_NOT_INITIALIZED:     return "NOT_INITIALIZED";
    case OZAYN_DHA_ERR_ALREADY_INITIALIZED: return "ALREADY_INITIALIZED";
    case OZAYN_DHA_ERR_INVALID_PARAM:       return "INVALID_PARAM";
    case OZAYN_DHA_ERR_NOT_FOUND:           return "NOT_FOUND";
    case OZAYN_DHA_ERR_TARGET_NOT_FOUND:    return "TARGET_NOT_FOUND";
    case OZAYN_DHA_ERR_CAPABILITY_NOT_FOUND: return "CAPABILITY_NOT_FOUND";
    case OZAYN_DHA_ERR_UNAVAILABLE:         return "UNAVAILABLE";
    case OZAYN_DHA_ERR_UNSUPPORTED:         return "UNSUPPORTED";
    case OZAYN_DHA_ERR_AUTHORIZATION_FAILED: return "AUTHORIZATION_FAILED";
    case OZAYN_DHA_ERR_PRECONDITION_FAILED: return "PRECONDITION_FAILED";
    case OZAYN_DHA_ERR_TIMEOUT:             return "TIMEOUT";
    case OZAYN_DHA_ERR_CANCELLED:           return "CANCELLED";
    case OZAYN_DHA_ERR_DEPENDENCY_FAILED:   return "DEPENDENCY_FAILED";
    case OZAYN_DHA_ERR_DEPENDENCY_CYCLE:    return "DEPENDENCY_CYCLE";
    case OZAYN_DHA_ERR_RESOURCE_LIMIT:      return "RESOURCE_LIMIT";
    case OZAYN_DHA_ERR_STORAGE_FAILURE:     return "STORAGE_FAILURE";
    case OZAYN_DHA_ERR_EXECUTION_ERROR:     return "EXECUTION_ERROR";
    case OZAYN_DHA_ERR_CONCURRENCY_LIMIT:   return "CONCURRENCY_LIMIT";
    case OZAYN_DHA_ERR_STATE_INVALID:       return "STATE_INVALID";
    }
    return "UNKNOWN";
}

const char *ozayn_dha_category_name(ozayn_dha_category_t cat)
{
    switch (cat) {
    case OZAYN_DHA_CAT_CONNECTIVITY:         return "CONNECTIVITY";
    case OZAYN_DHA_CAT_LIFECYCLE:            return "LIFECYCLE";
    case OZAYN_DHA_CAT_CAPABILITY:           return "CAPABILITY";
    case OZAYN_DHA_CAT_RESOURCE:             return "RESOURCE";
    case OZAYN_DHA_CAT_DEPENDENCY:           return "DEPENDENCY";
    case OZAYN_DHA_CAT_CONFIGURATION:        return "CONFIGURATION";
    case OZAYN_DHA_CAT_STORAGE:              return "STORAGE";
    case OZAYN_DHA_CAT_SECURITY_INTEGRATION: return "SECURITY_INTEGRATION";
    case OZAYN_DHA_CAT_EVENT_SYSTEM:         return "EVENT_SYSTEM";
    case OZAYN_DHA_CAT_OPERATION_SYSTEM:     return "OPERATION_SYSTEM";
    case OZAYN_DHA_CAT_COUNT:                break;
    }
    return "UNKNOWN";
}

const char *ozayn_dha_health_name(ozayn_dha_health_t health)
{
    switch (health) {
    case OZAYN_DHA_HEALTH_UNKNOWN:     return "UNKNOWN";
    case OZAYN_DHA_HEALTH_HEALTHY:     return "HEALTHY";
    case OZAYN_DHA_HEALTH_DEGRADED:    return "DEGRADED";
    case OZAYN_DHA_HEALTH_UNHEALTHY:   return "UNHEALTHY";
    case OZAYN_DHA_HEALTH_UNAVAILABLE: return "UNAVAILABLE";
    case OZAYN_DHA_HEALTH_COUNT:       break;
    }
    return "UNKNOWN";
}

const char *ozayn_dha_severity_name(ozayn_dha_severity_t sev)
{
    switch (sev) {
    case OZAYN_DHA_SEVERITY_INFO:     return "INFO";
    case OZAYN_DHA_SEVERITY_LOW:      return "LOW";
    case OZAYN_DHA_SEVERITY_MEDIUM:   return "MEDIUM";
    case OZAYN_DHA_SEVERITY_HIGH:     return "HIGH";
    case OZAYN_DHA_SEVERITY_CRITICAL: return "CRITICAL";
    case OZAYN_DHA_SEVERITY_COUNT:    break;
    }
    return "UNKNOWN";
}

const char *ozayn_dha_result_state_name(ozayn_dha_result_state_t state)
{
    switch (state) {
    case OZAYN_DHA_RESULT_SUCCEEDED:   return "SUCCEEDED";
    case OZAYN_DHA_RESULT_FAILED:      return "FAILED";
    case OZAYN_DHA_RESULT_TIMEOUT:     return "TIMEOUT";
    case OZAYN_DHA_RESULT_REJECTED:    return "REJECTED";
    case OZAYN_DHA_RESULT_UNAVAILABLE: return "UNAVAILABLE";
    case OZAYN_DHA_RESULT_UNSUPPORTED: return "UNSUPPORTED";
    case OZAYN_DHA_RESULT_CANCELLED:   return "CANCELLED";
    case OZAYN_DHA_RESULT_COUNT:       break;
    }
    return "UNKNOWN";
}

const char *ozayn_dha_finding_status_name(ozayn_dha_finding_status_t status)
{
    switch (status) {
    case OZAYN_DHA_FINDING_OPEN:          return "OPEN";
    case OZAYN_DHA_FINDING_RESOLVED:      return "RESOLVED";
    case OZAYN_DHA_FINDING_ACKNOWLEDGED:  return "ACKNOWLEDGED";
    case OZAYN_DHA_FINDING_INFORMATIONAL: return "INFORMATIONAL";
    case OZAYN_DHA_FINDING_COUNT:         break;
    }
    return "UNKNOWN";
}

const char *ozayn_dha_event_type_name(ozayn_dha_event_type_t type)
{
    switch (type) {
    case OZAYN_DHA_EVENT_REQUESTED:        return "REQUESTED";
    case OZAYN_DHA_EVENT_STARTED:          return "STARTED";
    case OZAYN_DHA_EVENT_SUCCEEDED:        return "SUCCEEDED";
    case OZAYN_DHA_EVENT_FAILED:           return "FAILED";
    case OZAYN_DHA_EVENT_TIMEOUT:          return "TIMEOUT";
    case OZAYN_DHA_EVENT_CANCELLED:        return "CANCELLED";
    case OZAYN_DHA_EVENT_REJECTED:         return "REJECTED";
    case OZAYN_DHA_EVENT_HEALTH_CHANGED:   return "HEALTH_CHANGED";
    case OZAYN_DHA_EVENT_HEALTH_DEGRADED:  return "HEALTH_DEGRADED";
    case OZAYN_DHA_EVENT_HEALTH_RECOVERED: return "HEALTH_RECOVERED";
    case OZAYN_DHA_EVENT_COUNT:            break;
    }
    return "UNKNOWN";
}

const char *ozayn_dha_req_state_name(ozayn_dha_req_state_t state)
{
    switch (state) {
    case OZAYN_DHA_REQ_CREATED:     return "CREATED";
    case OZAYN_DHA_REQ_VALIDATING:  return "VALIDATING";
    case OZAYN_DHA_REQ_RESOLVING:   return "RESOLVING";
    case OZAYN_DHA_REQ_CHECKING:    return "CHECKING";
    case OZAYN_DHA_REQ_AUTHORIZING: return "AUTHORIZING";
    case OZAYN_DHA_REQ_EXECUTING:   return "EXECUTING";
    case OZAYN_DHA_REQ_COMPLETED:   return "COMPLETED";
    case OZAYN_DHA_REQ_FAILED:      return "FAILED";
    case OZAYN_DHA_REQ_REJECTED:    return "REJECTED";
    case OZAYN_DHA_REQ_CANCELLED:   return "CANCELLED";
    case OZAYN_DHA_REQ_TIMEOUT:     return "TIMEOUT";
    case OZAYN_DHA_REQ_COUNT:       break;
    }
    return "UNKNOWN";
}

/* ============================================================
 * SECTION 2 — INTERNAL HELPERS
 * ============================================================ */

static int _is_req_terminal(ozayn_dha_req_state_t state)
{
    return state == OZAYN_DHA_REQ_COMPLETED ||
           state == OZAYN_DHA_REQ_FAILED ||
           state == OZAYN_DHA_REQ_REJECTED ||
           state == OZAYN_DHA_REQ_CANCELLED ||
           state == OZAYN_DHA_REQ_TIMEOUT;
}

static int _find_request(const ozayn_dha_service_t *svc, const char *request_id)
{
    if (!svc || !request_id || request_id[0] == '\0') return -1;
    for (int i = 0; i < svc->request_count; i++) {
        int idx = (svc->request_head + i) % OZAYN_DHA_MAX_REQUESTS;
        if (svc->requests[idx].active &&
            strcmp(svc->requests[idx].request_id, request_id) == 0)
            return idx;
    }
    return -1;
}

static int _find_result(const ozayn_dha_service_t *svc, const char *result_id)
{
    if (!svc || !result_id || result_id[0] == '\0') return -1;
    for (int i = 0; i < svc->result_count; i++) {
        int idx = (svc->result_head + i) % OZAYN_DHA_MAX_RESULTS;
        if (svc->results[idx].active &&
            strcmp(svc->results[idx].result_id, result_id) == 0)
            return idx;
    }
    return -1;
}

static int _find_finding(const ozayn_dha_service_t *svc, const char *finding_id)
{
    if (!svc || !finding_id || finding_id[0] == '\0') return -1;
    for (int i = 0; i < svc->finding_count; i++) {
        int idx = (svc->finding_head + i) % OZAYN_DHA_MAX_FINDINGS;
        if (svc->findings[idx].active &&
            strcmp(svc->findings[idx].finding_id, finding_id) == 0)
            return idx;
    }
    return -1;
}

static int _find_assessment(const ozayn_dha_service_t *svc, const char *assessment_id)
{
    if (!svc || !assessment_id || assessment_id[0] == '\0') return -1;
    for (int i = 0; i < svc->assessment_count; i++) {
        int idx = (svc->assessment_head + i) % OZAYN_DHA_MAX_ASSESSMENTS;
        if (svc->assessments[idx].active &&
            strcmp(svc->assessments[idx].assessment_id, assessment_id) == 0)
            return idx;
    }
    return -1;
}

static int _find_assessment_by_component(const ozayn_dha_service_t *svc, const char *component_id)
{
    if (!svc || !component_id || component_id[0] == '\0') return -1;
    /* Search backwards for most recent assessment for this component */
    for (int i = svc->assessment_count - 1; i >= 0; i--) {
        int idx = (svc->assessment_head + i) % OZAYN_DHA_MAX_ASSESSMENTS;
        if (svc->assessments[idx].active &&
            strcmp(svc->assessments[idx].component_id, component_id) == 0)
            return idx;
    }
    return -1;
}

/* ============================================================
 * SECTION 3 — LIFECYCLE
 * ============================================================ */

ozayn_dha_err_t ozayn_dha_service_init(
    ozayn_dha_service_t *svc,
    const ozayn_dha_service_config_t *cfg)
{
    if (!svc) return OZAYN_DHA_ERR_NULL;
    if (svc->initialized) return OZAYN_DHA_ERR_ALREADY_INITIALIZED;

    memset(svc, 0, sizeof(*svc));

    if (cfg) {
        svc->component_registry = cfg->component_registry;
        svc->authorization = cfg->authorization;
        svc->audit = cfg->audit;
        svc->event_engine = cfg->event_engine;
        svc->max_concurrent = cfg->max_concurrent > 0 ? cfg->max_concurrent : 8;
        svc->default_timeout_ms = cfg->default_timeout_ms > 0 ? cfg->default_timeout_ms : 30000;
    } else {
        svc->max_concurrent = 8;
        svc->default_timeout_ms = 30000;
    }

    svc->initialized = 1;

    if (!_diag_global_init) {
        memset(&_diag_global, 0, sizeof(_diag_global));
        _diag_global = *svc;
        _diag_global_init = 1;
    }

    return OZAYN_DHA_OK;
}

void ozayn_dha_service_shutdown(ozayn_dha_service_t *svc)
{
    if (!svc) return;
    svc->initialized = 0;
    memset(svc->requests, 0, sizeof(svc->requests));
    memset(svc->results, 0, sizeof(svc->results));
    memset(svc->findings, 0, sizeof(svc->findings));
    memset(svc->assessments, 0, sizeof(svc->assessments));
    svc->request_count = 0;
    svc->result_count = 0;
    svc->finding_count = 0;
    svc->assessment_count = 0;
    svc->active_diagnostics = 0;
}

int ozayn_dha_service_is_initialized(const ozayn_dha_service_t *svc)
{
    if (!svc) return 0;
    return svc->initialized;
}

/* ============================================================
 * SECTION 4 — REQUEST MANAGEMENT
 * ============================================================ */

ozayn_dha_err_t ozayn_dha_request_create(
    ozayn_dha_service_t *svc,
    const char *target,
    const char *capability,
    ozayn_dha_category_t category,
    const char *requester_identity,
    const char *session_id,
    const char *required_permission,
    int timeout_ms,
    int priority,
    const char *context,
    ozayn_dha_request_t **out_request)
{
    if (!svc) return OZAYN_DHA_ERR_NULL;
    if (!svc->initialized) return OZAYN_DHA_ERR_NOT_INITIALIZED;
    if (!target || target[0] == '\0') return OZAYN_DHA_ERR_INVALID_PARAM;
    if (category < 0 || category >= OZAYN_DHA_CAT_COUNT) return OZAYN_DHA_ERR_INVALID_PARAM;
    if (svc->request_count >= OZAYN_DHA_MAX_REQUESTS) return OZAYN_DHA_ERR_RESOURCE_LIMIT;
    if (svc->active_diagnostics >= svc->max_concurrent) return OZAYN_DHA_ERR_CONCURRENCY_LIMIT;

    int idx = (svc->request_head + svc->request_count) % OZAYN_DHA_MAX_REQUESTS;
    ozayn_dha_request_t *req = &svc->requests[idx];
    memset(req, 0, sizeof(*req));

    svc->request_sequence++;
    snprintf(req->request_id, OZAYN_DHA_MAX_ID_LEN, "DHAR-%u", svc->request_sequence);
    strncpy(req->target, target, OZAYN_DHA_MAX_TARGET_LEN - 1);
    if (capability) strncpy(req->capability, capability, OZAYN_DHA_MAX_CAP_LEN - 1);
    req->category = category;
    if (requester_identity)
        strncpy(req->requester_identity, requester_identity, OZAYN_DHA_MAX_IDENTITY_LEN - 1);
    if (session_id)
        strncpy(req->session_id, session_id, OZAYN_DHA_MAX_SESSION_LEN - 1);
    if (required_permission)
        strncpy(req->required_permission, required_permission, OZAYN_DHA_MAX_PERMISSION_LEN - 1);
    req->request_time = time(NULL);
    req->timeout_ms = timeout_ms > 0 ? timeout_ms : svc->default_timeout_ms;
    req->priority = priority;
    if (context) strncpy(req->context, context, OZAYN_DHA_MAX_META_LEN - 1);
    req->state = OZAYN_DHA_REQ_CREATED;
    req->active = 1;

    svc->request_count++;
    svc->stats.total_requests++;
    svc->stats.current_requests++;
    svc->active_diagnostics++;

    ozayn_dha_emit_event(svc, OZAYN_DHA_EVENT_REQUESTED, req->request_id,
        ozayn_dha_category_name(category));
    ozayn_dha_audit(svc, req->request_id, "DIAG_REQUESTED",
        ozayn_dha_category_name(category));

    if (out_request) *out_request = req;
    return OZAYN_DHA_OK;
}

ozayn_dha_err_t ozayn_dha_request_advance(
    ozayn_dha_service_t *svc,
    const char *request_id,
    ozayn_dha_req_state_t new_state)
{
    if (!svc) return OZAYN_DHA_ERR_NULL;
    if (!svc->initialized) return OZAYN_DHA_ERR_NOT_INITIALIZED;
    if (!request_id || request_id[0] == '\0') return OZAYN_DHA_ERR_INVALID_PARAM;

    int idx = _find_request(svc, request_id);
    if (idx < 0) return OZAYN_DHA_ERR_NOT_FOUND;

    ozayn_dha_request_t *req = &svc->requests[idx];
    if (_is_req_terminal(req->state)) return OZAYN_DHA_ERR_STATE_INVALID;
    if (_is_req_terminal(new_state)) return OZAYN_DHA_ERR_STATE_INVALID;

    req->state = new_state;

    if (new_state == OZAYN_DHA_REQ_EXECUTING)
        ozayn_dha_emit_event(svc, OZAYN_DHA_EVENT_STARTED, req->request_id, "executing");

    return OZAYN_DHA_OK;
}

ozayn_dha_err_t ozayn_dha_request_complete(
    ozayn_dha_service_t *svc,
    const char *request_id)
{
    if (!svc) return OZAYN_DHA_ERR_NULL;
    if (!svc->initialized) return OZAYN_DHA_ERR_NOT_INITIALIZED;
    if (!request_id || request_id[0] == '\0') return OZAYN_DHA_ERR_INVALID_PARAM;

    int idx = _find_request(svc, request_id);
    if (idx < 0) return OZAYN_DHA_ERR_NOT_FOUND;

    ozayn_dha_request_t *req = &svc->requests[idx];
    if (_is_req_terminal(req->state)) return OZAYN_DHA_ERR_STATE_INVALID;

    req->state = OZAYN_DHA_REQ_COMPLETED;
    svc->stats.total_succeeded++;
    svc->stats.current_requests--;
    svc->active_diagnostics--;

    ozayn_dha_emit_event(svc, OZAYN_DHA_EVENT_SUCCEEDED, req->request_id, "completed");
    return OZAYN_DHA_OK;
}

ozayn_dha_err_t ozayn_dha_request_fail(
    ozayn_dha_service_t *svc,
    const char *request_id,
    int error_code,
    const char *error_detail)
{
    if (!svc) return OZAYN_DHA_ERR_NULL;
    if (!svc->initialized) return OZAYN_DHA_ERR_NOT_INITIALIZED;
    if (!request_id || request_id[0] == '\0') return OZAYN_DHA_ERR_INVALID_PARAM;

    int idx = _find_request(svc, request_id);
    if (idx < 0) return OZAYN_DHA_ERR_NOT_FOUND;

    ozayn_dha_request_t *req = &svc->requests[idx];
    if (_is_req_terminal(req->state)) return OZAYN_DHA_ERR_STATE_INVALID;

    req->state = OZAYN_DHA_REQ_FAILED;
    svc->stats.total_failed++;
    svc->stats.current_requests--;
    svc->active_diagnostics--;

    (void)error_code;
    ozayn_dha_emit_event(svc, OZAYN_DHA_EVENT_FAILED, req->request_id,
        error_detail ? error_detail : "failed");
    return OZAYN_DHA_OK;
}

ozayn_dha_err_t ozayn_dha_request_cancel(
    ozayn_dha_service_t *svc,
    const char *request_id)
{
    if (!svc) return OZAYN_DHA_ERR_NULL;
    if (!svc->initialized) return OZAYN_DHA_ERR_NOT_INITIALIZED;
    if (!request_id || request_id[0] == '\0') return OZAYN_DHA_ERR_INVALID_PARAM;

    int idx = _find_request(svc, request_id);
    if (idx < 0) return OZAYN_DHA_ERR_NOT_FOUND;

    ozayn_dha_request_t *req = &svc->requests[idx];
    if (_is_req_terminal(req->state)) return OZAYN_DHA_ERR_STATE_INVALID;

    req->state = OZAYN_DHA_REQ_CANCELLED;
    svc->stats.total_cancelled++;
    svc->stats.current_requests--;
    svc->active_diagnostics--;

    ozayn_dha_emit_event(svc, OZAYN_DHA_EVENT_CANCELLED, req->request_id, "cancelled");
    return OZAYN_DHA_OK;
}

/* ============================================================
 * SECTION 5 — RESULT MANAGEMENT
 * ============================================================ */

ozayn_dha_err_t ozayn_dha_result_create(
    ozayn_dha_service_t *svc,
    const char *request_id,
    const char *target,
    const char *capability,
    ozayn_dha_category_t category,
    ozayn_dha_result_state_t result_state,
    ozayn_dha_health_t health_state,
    int error_code,
    const char *error_detail,
    ozayn_dha_result_t **out_result)
{
    if (!svc) return OZAYN_DHA_ERR_NULL;
    if (!svc->initialized) return OZAYN_DHA_ERR_NOT_INITIALIZED;
    if (!request_id || request_id[0] == '\0') return OZAYN_DHA_ERR_INVALID_PARAM;
    if (!target || target[0] == '\0') return OZAYN_DHA_ERR_INVALID_PARAM;
    if (svc->result_count >= OZAYN_DHA_MAX_RESULTS) return OZAYN_DHA_ERR_RESOURCE_LIMIT;

    int idx = (svc->result_head + svc->result_count) % OZAYN_DHA_MAX_RESULTS;
    ozayn_dha_result_t *res = &svc->results[idx];
    memset(res, 0, sizeof(*res));

    svc->result_sequence++;
    snprintf(res->result_id, OZAYN_DHA_MAX_ID_LEN, "DHAR-%u", svc->result_sequence);
    strncpy(res->request_id, request_id, OZAYN_DHA_MAX_ID_LEN - 1);
    strncpy(res->target, target, OZAYN_DHA_MAX_TARGET_LEN - 1);
    if (capability) strncpy(res->capability, capability, OZAYN_DHA_MAX_CAP_LEN - 1);
    res->category = category;
    res->result_state = result_state;
    res->health_state = health_state;
    res->start_time = time(NULL);
    res->completion_time = res->start_time;
    res->duration_ms = 0;
    res->error_code = error_code;
    if (error_detail)
        strncpy(res->error_detail, error_detail, OZAYN_DHA_MAX_ERROR_LEN - 1);
    res->max_severity = OZAYN_DHA_SEVERITY_INFO;
    res->active = 1;

    svc->result_count++;
    svc->stats.current_results++;
    res->finding_start = svc->finding_count;
    res->finding_count = 0;

    if (out_result) *out_result = res;
    return OZAYN_DHA_OK;
}

/* ============================================================
 * SECTION 6 — FINDING MANAGEMENT
 * ============================================================ */

ozayn_dha_err_t ozayn_dha_finding_create(
    ozayn_dha_service_t *svc,
    ozayn_dha_category_t category,
    ozayn_dha_severity_t severity,
    const char *component_id,
    const char *description,
    const char *evidence_ref,
    ozayn_dha_finding_t **out_finding)
{
    if (!svc) return OZAYN_DHA_ERR_NULL;
    if (!svc->initialized) return OZAYN_DHA_ERR_NOT_INITIALIZED;
    if (!component_id || component_id[0] == '\0') return OZAYN_DHA_ERR_INVALID_PARAM;
    if (!description || description[0] == '\0') return OZAYN_DHA_ERR_INVALID_PARAM;
    if (svc->finding_count >= OZAYN_DHA_MAX_FINDINGS) return OZAYN_DHA_ERR_RESOURCE_LIMIT;

    int idx = (svc->finding_head + svc->finding_count) % OZAYN_DHA_MAX_FINDINGS;
    ozayn_dha_finding_t *f = &svc->findings[idx];
    memset(f, 0, sizeof(*f));

    svc->finding_sequence++;
    snprintf(f->finding_id, OZAYN_DHA_MAX_ID_LEN, "DHAF-%u", svc->finding_sequence);
    f->category = category;
    f->severity = severity;
    strncpy(f->component_id, component_id, OZAYN_DHA_MAX_ID_LEN - 1);
    strncpy(f->description, description, OZAYN_DHA_MAX_DESC_LEN - 1);
    if (evidence_ref)
        strncpy(f->evidence_ref, evidence_ref, OZAYN_DHA_MAX_ID_LEN - 1);
    f->status = OZAYN_DHA_FINDING_OPEN;
    f->created_time = time(NULL);
    f->active = 1;

    svc->finding_count++;
    svc->stats.current_findings++;

    if (out_finding) *out_finding = f;
    return OZAYN_DHA_OK;
}

ozayn_dha_err_t ozayn_dha_finding_update_status(
    ozayn_dha_service_t *svc,
    const char *finding_id,
    ozayn_dha_finding_status_t new_status)
{
    if (!svc) return OZAYN_DHA_ERR_NULL;
    if (!svc->initialized) return OZAYN_DHA_ERR_NOT_INITIALIZED;
    if (!finding_id || finding_id[0] == '\0') return OZAYN_DHA_ERR_INVALID_PARAM;

    int idx = _find_finding(svc, finding_id);
    if (idx < 0) return OZAYN_DHA_ERR_NOT_FOUND;

    svc->findings[idx].status = new_status;
    return OZAYN_DHA_OK;
}

/* ============================================================
 * SECTION 7 — HEALTH ASSESSMENT
 * ============================================================ */

ozayn_dha_err_t ozayn_dha_assess_health(
    ozayn_dha_service_t *svc,
    const char *component_id,
    const char *diagnostic_source,
    ozayn_dha_health_t health_state,
    ozayn_dha_severity_t severity,
    const char *summary,
    ozayn_dha_assessment_t **out_assessment)
{
    if (!svc) return OZAYN_DHA_ERR_NULL;
    if (!svc->initialized) return OZAYN_DHA_ERR_NOT_INITIALIZED;
    if (!component_id || component_id[0] == '\0') return OZAYN_DHA_ERR_INVALID_PARAM;
    if (svc->assessment_count >= OZAYN_DHA_MAX_ASSESSMENTS) return OZAYN_DHA_ERR_RESOURCE_LIMIT;

    int idx = (svc->assessment_head + svc->assessment_count) % OZAYN_DHA_MAX_ASSESSMENTS;
    ozayn_dha_assessment_t *a = &svc->assessments[idx];
    memset(a, 0, sizeof(*a));

    svc->assessment_sequence++;
    snprintf(a->assessment_id, OZAYN_DHA_MAX_ID_LEN, "DHAA-%u", svc->assessment_sequence);
    strncpy(a->component_id, component_id, OZAYN_DHA_MAX_ID_LEN - 1);
    a->health_state = health_state;
    a->assessment_time = time(NULL);
    if (diagnostic_source)
        strncpy(a->diagnostic_source, diagnostic_source, OZAYN_DHA_MAX_ID_LEN - 1);
    a->severity = severity;
    if (summary)
        strncpy(a->summary, summary, OZAYN_DHA_MAX_DESC_LEN - 1);
    a->active = 1;

    svc->assessment_count++;
    svc->stats.current_assessments++;

    /* Check for health change */
    ozayn_dha_assessment_t *prev = NULL;
    for (int i = svc->assessment_count - 2; i >= 0; i--) {
        int pidx = (svc->assessment_head + i) % OZAYN_DHA_MAX_ASSESSMENTS;
        if (svc->assessments[pidx].active &&
            strcmp(svc->assessments[pidx].component_id, component_id) == 0) {
            prev = &svc->assessments[pidx];
            break;
        }
    }

    if (prev && prev->health_state != health_state) {
        svc->stats.total_health_changed++;
        if (health_state == OZAYN_DHA_HEALTH_DEGRADED ||
            health_state == OZAYN_DHA_HEALTH_UNHEALTHY) {
            ozayn_dha_emit_event(svc, OZAYN_DHA_EVENT_HEALTH_DEGRADED,
                component_id, ozayn_dha_health_name(health_state));
        } else if (health_state == OZAYN_DHA_HEALTH_HEALTHY &&
                   (prev->health_state == OZAYN_DHA_HEALTH_DEGRADED ||
                    prev->health_state == OZAYN_DHA_HEALTH_UNHEALTHY)) {
            ozayn_dha_emit_event(svc, OZAYN_DHA_EVENT_HEALTH_RECOVERED,
                component_id, "recovered");
        }
        ozayn_dha_emit_event(svc, OZAYN_DHA_EVENT_HEALTH_CHANGED,
            component_id, ozayn_dha_health_name(health_state));
    }

    if (out_assessment) *out_assessment = a;
    return OZAYN_DHA_OK;
}

/* ============================================================
 * SECTION 8 — QUERY
 * ============================================================ */

const ozayn_dha_request_t *ozayn_dha_request_get(
    const ozayn_dha_service_t *svc,
    const char *request_id)
{
    if (!svc || !svc->initialized || !request_id || request_id[0] == '\0') return NULL;
    int idx = _find_request(svc, request_id);
    if (idx < 0) return NULL;
    return &svc->requests[idx];
}

const ozayn_dha_result_t *ozayn_dha_result_get(
    const ozayn_dha_service_t *svc,
    const char *result_id)
{
    if (!svc || !svc->initialized || !result_id || result_id[0] == '\0') return NULL;
    int idx = _find_result(svc, result_id);
    if (idx < 0) return NULL;
    return &svc->results[idx];
}

const ozayn_dha_finding_t *ozayn_dha_finding_get(
    const ozayn_dha_service_t *svc,
    const char *finding_id)
{
    if (!svc || !svc->initialized || !finding_id || finding_id[0] == '\0') return NULL;
    int idx = _find_finding(svc, finding_id);
    if (idx < 0) return NULL;
    return &svc->findings[idx];
}

const ozayn_dha_assessment_t *ozayn_dha_assessment_get(
    const ozayn_dha_service_t *svc,
    const char *assessment_id)
{
    if (!svc || !svc->initialized || !assessment_id || assessment_id[0] == '\0') return NULL;
    int idx = _find_assessment(svc, assessment_id);
    if (idx < 0) return NULL;
    return &svc->assessments[idx];
}

const ozayn_dha_assessment_t *ozayn_dha_assessment_get_by_component(
    const ozayn_dha_service_t *svc,
    const char *component_id)
{
    if (!svc || !svc->initialized || !component_id || component_id[0] == '\0') return NULL;
    int idx = _find_assessment_by_component(svc, component_id);
    if (idx < 0) return NULL;
    return &svc->assessments[idx];
}

int ozayn_dha_request_count(const ozayn_dha_service_t *svc)
{
    if (!svc || !svc->initialized) return 0;
    return svc->request_count;
}

int ozayn_dha_result_count(const ozayn_dha_service_t *svc)
{
    if (!svc || !svc->initialized) return 0;
    return svc->result_count;
}

int ozayn_dha_finding_count(const ozayn_dha_service_t *svc)
{
    if (!svc || !svc->initialized) return 0;
    return svc->finding_count;
}

int ozayn_dha_assessment_count(const ozayn_dha_service_t *svc)
{
    if (!svc || !svc->initialized) return 0;
    return svc->assessment_count;
}

/* ============================================================
 * SECTION 9 — STATISTICS
 * ============================================================ */

ozayn_dha_err_t ozayn_dha_get_stats(
    const ozayn_dha_service_t *svc,
    ozayn_dha_stats_t *out_stats)
{
    if (!svc) return OZAYN_DHA_ERR_NULL;
    if (!out_stats) return OZAYN_DHA_ERR_NULL;
    if (!svc->initialized) return OZAYN_DHA_ERR_NOT_INITIALIZED;
    *out_stats = svc->stats;
    return OZAYN_DHA_OK;
}

/* ============================================================
 * SECTION 10 — EVENT INTEGRATION
 * ============================================================ */

ozayn_dha_err_t ozayn_dha_emit_event(
    ozayn_dha_service_t *svc,
    ozayn_dha_event_type_t event_type,
    const char *reference_id,
    const char *detail)
{
    if (!svc) return OZAYN_DHA_ERR_NULL;
    (void)event_type;
    (void)reference_id;
    (void)detail;
    return OZAYN_DHA_OK;
}

/* ============================================================
 * SECTION 11 — AUDIT INTEGRATION
 * ============================================================ */

ozayn_dha_err_t ozayn_dha_audit(
    ozayn_dha_service_t *svc,
    const char *reference_id,
    const char *event_type,
    const char *detail)
{
    if (!svc) return OZAYN_DHA_ERR_NULL;
    if (!reference_id || reference_id[0] == '\0') return OZAYN_DHA_ERR_INVALID_PARAM;
    if (!event_type || event_type[0] == '\0') return OZAYN_DHA_ERR_INVALID_PARAM;
    (void)detail;
    return OZAYN_DHA_OK;
}

/* ============================================================
 * SECTION 12 — VALIDATION
 * ============================================================ */

int ozayn_dha_request_validate(const ozayn_dha_request_t *req)
{
    if (!req) return 0;
    if (req->request_id[0] == '\0') return 0;
    if (req->target[0] == '\0') return 0;
    if (req->category < 0 || req->category >= OZAYN_DHA_CAT_COUNT) return 0;
    if (req->request_time <= 0) return 0;
    return 1;
}

int ozayn_dha_result_validate(const ozayn_dha_result_t *result)
{
    if (!result) return 0;
    if (result->result_id[0] == '\0') return 0;
    if (result->request_id[0] == '\0') return 0;
    if (result->target[0] == '\0') return 0;
    if (result->result_state < 0 || result->result_state >= OZAYN_DHA_RESULT_COUNT) return 0;
    return 1;
}

int ozayn_dha_assessment_validate(const ozayn_dha_assessment_t *assess)
{
    if (!assess) return 0;
    if (assess->assessment_id[0] == '\0') return 0;
    if (assess->component_id[0] == '\0') return 0;
    if (assess->health_state < 0 || assess->health_state >= OZAYN_DHA_HEALTH_COUNT) return 0;
    if (assess->assessment_time <= 0) return 0;
    return 1;
}

int ozayn_dha_health_is_terminal(ozayn_dha_health_t health)
{
    (void)health;
    return 0;
}

/* ============================================================
 * SECTION 13 — CLEANUP
 * ============================================================ */

int ozayn_dha_cleanup_results(ozayn_dha_service_t *svc)
{
    if (!svc || !svc->initialized) return 0;
    int cleaned = svc->result_count;
    memset(svc->results, 0, sizeof(svc->results));
    svc->result_count = 0;
    svc->result_head = 0;
    svc->stats.current_results = 0;
    return cleaned;
}

int ozayn_dha_cleanup_findings(ozayn_dha_service_t *svc)
{
    if (!svc || !svc->initialized) return 0;
    int cleaned = svc->finding_count;
    memset(svc->findings, 0, sizeof(svc->findings));
    svc->finding_count = 0;
    svc->finding_head = 0;
    svc->stats.current_findings = 0;
    return cleaned;
}

int ozayn_dha_cleanup_all(ozayn_dha_service_t *svc)
{
    if (!svc || !svc->initialized) return 0;
    int cleaned = svc->request_count + svc->result_count +
                  svc->finding_count + svc->assessment_count;
    memset(svc->requests, 0, sizeof(svc->requests));
    memset(svc->results, 0, sizeof(svc->results));
    memset(svc->findings, 0, sizeof(svc->findings));
    memset(svc->assessments, 0, sizeof(svc->assessments));
    svc->request_count = 0;
    svc->result_count = 0;
    svc->finding_count = 0;
    svc->assessment_count = 0;
    svc->request_head = 0;
    svc->result_head = 0;
    svc->finding_head = 0;
    svc->assessment_head = 0;
    svc->active_diagnostics = 0;
    svc->stats.current_requests = 0;
    svc->stats.current_results = 0;
    svc->stats.current_findings = 0;
    svc->stats.current_assessments = 0;
    return cleaned;
}

/* ============================================================
 * SECTION 14 — GLOBAL ACCESSOR
 * ============================================================ */

ozayn_dha_service_t *ozayn_dha_get_global(void)
{
    if (!_diag_global_init) {
        memset(&_diag_global, 0, sizeof(_diag_global));
        _diag_global_init = 1;
    }
    return &_diag_global;
}
