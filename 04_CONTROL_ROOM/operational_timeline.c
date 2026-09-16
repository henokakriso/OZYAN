#include "operational_timeline.h"
#include <string.h>
#include <stdio.h>

static ozayn_otl_event_t *find_event(ozayn_otl_service_t *svc, uint64_t event_id) {
    uint64_t count = svc->event_count < OZAYN_OTL_MAX_EVENTS ? svc->event_count : OZAYN_OTL_MAX_EVENTS;
    for (uint64_t i = 0; i < count; i++) {
        uint64_t idx = (svc->event_head - 1 - i + OZAYN_OTL_MAX_EVENTS) % OZAYN_OTL_MAX_EVENTS;
        if (svc->events[idx].event_id == event_id && svc->events[idx].active)
            return &svc->events[idx];
    }
    return 0;
}

static const ozayn_otl_event_t *find_event_const(const ozayn_otl_service_t *svc, uint64_t event_id) {
    uint64_t count = svc->event_count < OZAYN_OTL_MAX_EVENTS ? svc->event_count : OZAYN_OTL_MAX_EVENTS;
    for (uint64_t i = 0; i < count; i++) {
        uint64_t idx = (svc->event_head - 1 - i + OZAYN_OTL_MAX_EVENTS) % OZAYN_OTL_MAX_EVENTS;
        if (svc->events[idx].event_id == event_id && svc->events[idx].active)
            return &svc->events[idx];
    }
    return 0;
}

static ozayn_otl_timeline_t *find_timeline(ozayn_otl_service_t *svc, uint64_t timeline_id) {
    uint64_t count = svc->timeline_count < OZAYN_OTL_MAX_TIMELINES ? svc->timeline_count : OZAYN_OTL_MAX_TIMELINES;
    for (uint64_t i = 0; i < count; i++) {
        uint64_t idx = (svc->timeline_head - 1 - i + OZAYN_OTL_MAX_TIMELINES) % OZAYN_OTL_MAX_TIMELINES;
        if (svc->timelines[idx].timeline_id == timeline_id && svc->timelines[idx].active)
            return &svc->timelines[idx];
    }
    return 0;
}

static const ozayn_otl_timeline_t *find_timeline_const(const ozayn_otl_service_t *svc, uint64_t timeline_id) {
    uint64_t count = svc->timeline_count < OZAYN_OTL_MAX_TIMELINES ? svc->timeline_count : OZAYN_OTL_MAX_TIMELINES;
    for (uint64_t i = 0; i < count; i++) {
        uint64_t idx = (svc->timeline_head - 1 - i + OZAYN_OTL_MAX_TIMELINES) % OZAYN_OTL_MAX_TIMELINES;
        if (svc->timelines[idx].timeline_id == timeline_id && svc->timelines[idx].active)
            return &svc->timelines[idx];
    }
    return 0;
}

const char *ozayn_otl_err_name(ozayn_otl_err_t e) {
    switch (e) {
        case OZAYN_OTL_ERR_OK: return "OK";
        case OZAYN_OTL_ERR_NULL_PTR: return "NULL_PTR";
        case OZAYN_OTL_ERR_NOT_INITIALIZED: return "NOT_INITIALIZED";
        case OZAYN_OTL_ERR_ALREADY_INITIALIZED: return "ALREADY_INITIALIZED";
        case OZAYN_OTL_ERR_INVALID_ID: return "INVALID_ID";
        case OZAYN_OTL_ERR_NOT_FOUND: return "NOT_FOUND";
        case OZAYN_OTL_ERR_DUPLICATE: return "DUPLICATE";
        case OZAYN_OTL_ERR_FULL: return "FULL";
        case OZAYN_OTL_ERR_INVALID_STATE: return "INVALID_STATE";
        case OZAYN_OTL_ERR_INVALID_TRANSITION: return "INVALID_TRANSITION";
        case OZAYN_OTL_ERR_INVALID_EVENT: return "INVALID_EVENT";
        case OZAYN_OTL_ERR_CORRELATION_FAILED: return "CORRELATION_FAILED";
        case OZAYN_OTL_ERR_QUERY_INVALID: return "QUERY_INVALID";
        case OZAYN_OTL_ERR_QUERY_LIMIT: return "QUERY_LIMIT";
        case OZAYN_OTL_ERR_STORAGE_ERROR: return "STORAGE_ERROR";
        case OZAYN_OTL_ERR_SUBSYSTEM_UNAVAILABLE: return "SUBSYSTEM_UNAVAILABLE";
        case OZAYN_OTL_ERR_UNAUTHORIZED: return "UNAUTHORIZED";
        case OZAYN_OTL_ERR_INTERNAL: return "INTERNAL";
    }
    return "UNKNOWN";
}

const char *ozayn_otl_category_name(ozayn_otl_category_t c) {
    switch (c) {
        case OZAYN_OTL_CAT_SYSTEM: return "SYSTEM";
        case OZAYN_OTL_CAT_STARTUP: return "STARTUP";
        case OZAYN_OTL_CAT_SHUTDOWN: return "SHUTDOWN";
        case OZAYN_OTL_CAT_LIFECYCLE: return "LIFECYCLE";
        case OZAYN_OTL_CAT_COMPONENT: return "COMPONENT";
        case OZAYN_OTL_CAT_CAPABILITY: return "CAPABILITY";
        case OZAYN_OTL_CAT_OPERATION: return "OPERATION";
        case OZAYN_OTL_CAT_QUEUE: return "QUEUE";
        case OZAYN_OTL_CAT_SCHEDULER: return "SCHEDULER";
        case OZAYN_OTL_CAT_WORKFLOW: return "WORKFLOW";
        case OZAYN_OTL_CAT_PIPELINE: return "PIPELINE";
        case OZAYN_OTL_CAT_ADMISSION: return "ADMISSION";
        case OZAYN_OTL_CAT_ENFORCEMENT: return "ENFORCEMENT";
        case OZAYN_OTL_CAT_EXECUTION: return "EXECUTION";
        case OZAYN_OTL_CAT_RECONCILIATION: return "RECONCILIATION";
        case OZAYN_OTL_CAT_RESOURCE: return "RESOURCE";
        case OZAYN_OTL_CAT_DEVICE: return "DEVICE";
        case OZAYN_OTL_CAT_IO: return "IO";
        case OZAYN_OTL_CAT_SECURITY: return "SECURITY";
        case OZAYN_OTL_CAT_SAFETY: return "SAFETY";
        case OZAYN_OTL_CAT_DIAGNOSTIC: return "DIAGNOSTIC";
        case OZAYN_OTL_CAT_RECOVERY: return "RECOVERY";
        case OZAYN_OTL_CAT_CONFIGURATION: return "CONFIGURATION";
        case OZAYN_OTL_CAT_ERROR: return "ERROR";
    }
    return "UNKNOWN";
}

const char *ozayn_otl_severity_name(ozayn_otl_severity_t s) {
    switch (s) {
        case OZAYN_OTL_SEV_INFO: return "INFO";
        case OZAYN_OTL_SEV_LOW: return "LOW";
        case OZAYN_OTL_SEV_MEDIUM: return "MEDIUM";
        case OZAYN_OTL_SEV_HIGH: return "HIGH";
        case OZAYN_OTL_SEV_CRITICAL: return "CRITICAL";
    }
    return "UNKNOWN";
}

const char *ozayn_otl_relationship_name(ozayn_otl_relationship_t r) {
    switch (r) {
        case OZAYN_OTL_REL_NONE: return "NONE";
        case OZAYN_OTL_REL_PARENT: return "PARENT";
        case OZAYN_OTL_REL_CHILD: return "CHILD";
        case OZAYN_OTL_REL_PRECEDES: return "PRECEDES";
        case OZAYN_OTL_REL_FOLLOWS: return "FOLLOWS";
        case OZAYN_OTL_REL_CAUSED_BY: return "CAUSED_BY";
        case OZAYN_OTL_REL_RESULT_OF: return "RESULT_OF";
        case OZAYN_OTL_REL_PART_OF: return "PART_OF";
        case OZAYN_OTL_REL_RETRY_OF: return "RETRY_OF";
        case OZAYN_OTL_REL_COMPENSATES: return "COMPENSATES";
        case OZAYN_OTL_REL_RECONCILES: return "RECONCILES";
        case OZAYN_OTL_REL_DEPENDS_ON: return "DEPENDS_ON";
        case OZAYN_OTL_REL_AFFECTS: return "AFFECTS";
    }
    return "UNKNOWN";
}

const char *ozayn_otl_confidence_name(ozayn_otl_confidence_t c) {
    switch (c) {
        case OZAYN_OTL_CORR_EXACT: return "EXACT";
        case OZAYN_OTL_CORR_EXPLICIT: return "EXPLICIT";
        case OZAYN_OTL_CORR_DERIVED: return "DERIVED";
        case OZAYN_OTL_CORR_PARTIAL: return "PARTIAL";
        case OZAYN_OTL_CORR_UNKNOWN: return "UNKNOWN";
        case OZAYN_OTL_CORR_INVALID: return "INVALID";
    }
    return "UNKNOWN";
}

const char *ozayn_otl_timeline_state_name(ozayn_otl_timeline_state_t s) {
    switch (s) {
        case OZAYN_OTL_TL_CREATED: return "CREATED";
        case OZAYN_OTL_TL_ACTIVE: return "ACTIVE";
        case OZAYN_OTL_TL_COMPLETED: return "COMPLETED";
        case OZAYN_OTL_TL_FAILED: return "FAILED";
        case OZAYN_OTL_TL_PARTIAL: return "PARTIAL";
        case OZAYN_OTL_TL_CANCELLED: return "CANCELLED";
        case OZAYN_OTL_TL_EXPIRED: return "EXPIRED";
        case OZAYN_OTL_TL_UNKNOWN: return "UNKNOWN";
        case OZAYN_OTL_TL_UNAVAILABLE: return "UNAVAILABLE";
    }
    return "UNKNOWN";
}

const char *ozayn_otl_event_state_name(ozayn_otl_event_state_t s) {
    switch (s) {
        case OZAYN_OTL_EVT_NORMAL: return "NORMAL";
        case OZAYN_OTL_EVT_DUPLICATE_DETECTED: return "DUPLICATE_DETECTED";
        case OZAYN_OTL_EVT_OUT_OF_ORDER: return "OUT_OF_ORDER";
        case OZAYN_OTL_EVT_LATE_ARRIVAL: return "LATE_ARRIVAL";
        case OZAYN_OTL_EVT_INCONSISTENCY_DETECTED: return "INCONSISTENCY_DETECTED";
    }
    return "UNKNOWN";
}

const char *ozayn_otl_emit_type_name(ozayn_otl_emit_type_t t) {
    switch (t) {
        case OZAYN_OTL_EVENT_TIMELINE_CREATED: return "TIMELINE_CREATED";
        case OZAYN_OTL_EVENT_TIMELINE_UPDATED: return "TIMELINE_UPDATED";
        case OZAYN_OTL_EVENT_TIMELINE_COMPLETED: return "TIMELINE_COMPLETED";
        case OZAYN_OTL_EVENT_TIMELINE_FAILED: return "TIMELINE_FAILED";
        case OZAYN_OTL_EVENT_TIMELINE_PARTIAL: return "TIMELINE_PARTIAL";
        case OZAYN_OTL_EVENT_TIMELINE_EXPIRED: return "TIMELINE_EXPIRED";
        case OZAYN_OTL_EVENT_CORRELATION_STARTED: return "CORRELATION_STARTED";
        case OZAYN_OTL_EVENT_CORRELATED: return "CORRELATED";
        case OZAYN_OTL_EVENT_CORRELATION_PARTIAL: return "CORRELATION_PARTIAL";
        case OZAYN_OTL_EVENT_CORRELATION_UNKNOWN: return "CORRELATION_UNKNOWN";
        case OZAYN_OTL_EVENT_CORRELATION_INVALID: return "CORRELATION_INVALID";
        case OZAYN_OTL_EVENT_DUPLICATE_DETECTED: return "DUPLICATE_DETECTED";
        case OZAYN_OTL_EVENT_OUT_OF_ORDER: return "OUT_OF_ORDER";
        case OZAYN_OTL_EVENT_LATE_ARRIVAL: return "LATE_ARRIVAL";
        case OZAYN_OTL_EVENT_INCONSISTENCY_DETECTED: return "INCONSISTENCY_DETECTED";
        case OZAYN_OTL_EVENT_RECONCILIATION_REQUIRED: return "RECONCILIATION_REQUIRED";
    }
    return "UNKNOWN";
}

int ozayn_otl_init(ozayn_otl_service_t *svc) {
    if (!svc) return OZAYN_OTL_ERR_NULL_PTR;
    if (svc->initialized) return OZAYN_OTL_ERR_ALREADY_INITIALIZED;
    memset(svc, 0, sizeof(*svc));
    svc->initialized = 1;
    return OZAYN_OTL_ERR_OK;
}

int ozayn_otl_shutdown(ozayn_otl_service_t *svc) {
    if (!svc) return OZAYN_OTL_ERR_NULL_PTR;
    if (!svc->initialized) return OZAYN_OTL_ERR_NOT_INITIALIZED;
    svc->initialized = 0;
    return OZAYN_OTL_ERR_OK;
}

int ozayn_otl_is_initialized(const ozayn_otl_service_t *svc) {
    if (!svc) return 0;
    return svc->initialized;
}

int ozayn_otl_bind_subsystems(ozayn_otl_service_t *svc, const ozayn_otl_subsystem_bind_t *bind) {
    if (!svc || !bind) return OZAYN_OTL_ERR_NULL_PTR;
    if (!svc->initialized) return OZAYN_OTL_ERR_NOT_INITIALIZED;
    svc->bind = *bind;
    return OZAYN_OTL_ERR_OK;
}

int ozayn_otl_event_ingest(ozayn_otl_service_t *svc,
                           const ozayn_otl_event_t *event,
                           uint64_t *out_event_id) {
    if (!svc || !event) return OZAYN_OTL_ERR_NULL_PTR;
    if (!svc->initialized) return OZAYN_OTL_ERR_NOT_INITIALIZED;
    if (!event->active) return OZAYN_OTL_ERR_INVALID_EVENT;

    if (svc->event_count >= OZAYN_OTL_MAX_EVENTS) return OZAYN_OTL_ERR_FULL;

    uint64_t pos = svc->event_head % OZAYN_OTL_MAX_EVENTS;
    ozayn_otl_event_t *stored = &svc->events[pos];
    *stored = *event;
    if (stored->event_id == 0) stored->event_id = ++svc->sequence;
    stored->ingestion_time = time(0);
    stored->active = 1;
    if (out_event_id) *out_event_id = stored->event_id;

    svc->event_head++;
    svc->event_count++;
    svc->stats.total_events_ingested++;
    svc->stats.current_events_stored++;

    return OZAYN_OTL_ERR_OK;
}

int ozayn_otl_event_ingest_simple(ozayn_otl_service_t *svc,
                                  ozayn_otl_category_t category,
                                  ozayn_otl_severity_t severity,
                                  const char *event_type_name,
                                  const char *source_component_id,
                                  const char *operation_id,
                                  const char *request_id,
                                  const char *target_component_id,
                                  const char *description,
                                  time_t occurrence_time,
                                  uint64_t *out_event_id) {
    if (!svc) return OZAYN_OTL_ERR_NULL_PTR;
    if (!svc->initialized) return OZAYN_OTL_ERR_NOT_INITIALIZED;
    if (svc->event_count >= OZAYN_OTL_MAX_EVENTS) return OZAYN_OTL_ERR_FULL;

    uint64_t pos = svc->event_head % OZAYN_OTL_MAX_EVENTS;
    ozayn_otl_event_t *stored = &svc->events[pos];
    memset(stored, 0, sizeof(*stored));
    stored->event_id = ++svc->sequence;
    stored->category = category;
    stored->severity = severity;
    stored->state = OZAYN_OTL_EVT_NORMAL;
    if (event_type_name) strncpy(stored->event_type_name, event_type_name, OZAYN_OTL_MAX_MSG_LEN - 1);
    if (source_component_id) strncpy(stored->source_component_id, source_component_id, OZAYN_OTL_MAX_ID_LEN - 1);
    if (operation_id) strncpy(stored->operation_id, operation_id, OZAYN_OTL_MAX_ID_LEN - 1);
    if (request_id) strncpy(stored->request_id, request_id, OZAYN_OTL_MAX_ID_LEN - 1);
    if (target_component_id) strncpy(stored->target_component_id, target_component_id, OZAYN_OTL_MAX_ID_LEN - 1);
    if (description) strncpy(stored->description, description, OZAYN_OTL_MAX_MSG_LEN - 1);
    stored->occurrence_time = occurrence_time;
    stored->ingestion_time = time(0);
    stored->correlation_confidence = OZAYN_OTL_CORR_UNKNOWN;
    stored->active = 1;

    if (out_event_id) *out_event_id = stored->event_id;
    svc->event_head++;
    svc->event_count++;
    svc->stats.total_events_ingested++;
    svc->stats.current_events_stored++;
    return OZAYN_OTL_ERR_OK;
}

int ozayn_otl_event_get(const ozayn_otl_service_t *svc,
                        uint64_t event_id,
                        const ozayn_otl_event_t **out_event) {
    if (!svc || !out_event) return OZAYN_OTL_ERR_NULL_PTR;
    if (!svc->initialized) return OZAYN_OTL_ERR_NOT_INITIALIZED;
    const ozayn_otl_event_t *evt = find_event_const(svc, event_id);
    if (!evt) return OZAYN_OTL_ERR_NOT_FOUND;
    *out_event = evt;
    return OZAYN_OTL_ERR_OK;
}

static int match_str(const char *a, const char *b) {
    if (!a[0] && !b[0]) return 1;
    return strcmp(a, b) == 0;
}

int ozayn_otl_event_get_by_operation(const ozayn_otl_service_t *svc,
                                     const char *operation_id,
                                     const ozayn_otl_event_t **out_events,
                                     uint64_t max_count,
                                     uint64_t *out_count) {
    if (!svc || !operation_id || !out_events || !out_count) return OZAYN_OTL_ERR_NULL_PTR;
    if (!svc->initialized) return OZAYN_OTL_ERR_NOT_INITIALIZED;
    uint64_t cnt = 0;
    uint64_t count = svc->event_count < OZAYN_OTL_MAX_EVENTS ? svc->event_count : OZAYN_OTL_MAX_EVENTS;
    for (uint64_t i = 0; i < count && cnt < max_count; i++) {
        uint64_t idx = (svc->event_head - 1 - i + OZAYN_OTL_MAX_EVENTS) % OZAYN_OTL_MAX_EVENTS;
        if (svc->events[idx].active && match_str(svc->events[idx].operation_id, operation_id))
            out_events[cnt++] = &svc->events[idx];
    }
    *out_count = cnt;
    return OZAYN_OTL_ERR_OK;
}

int ozayn_otl_event_get_by_request(const ozayn_otl_service_t *svc,
                                   const char *request_id,
                                   const ozayn_otl_event_t **out_events,
                                   uint64_t max_count,
                                   uint64_t *out_count) {
    if (!svc || !request_id || !out_events || !out_count) return OZAYN_OTL_ERR_NULL_PTR;
    if (!svc->initialized) return OZAYN_OTL_ERR_NOT_INITIALIZED;
    uint64_t cnt = 0;
    uint64_t count = svc->event_count < OZAYN_OTL_MAX_EVENTS ? svc->event_count : OZAYN_OTL_MAX_EVENTS;
    for (uint64_t i = 0; i < count && cnt < max_count; i++) {
        uint64_t idx = (svc->event_head - 1 - i + OZAYN_OTL_MAX_EVENTS) % OZAYN_OTL_MAX_EVENTS;
        if (svc->events[idx].active && match_str(svc->events[idx].request_id, request_id))
            out_events[cnt++] = &svc->events[idx];
    }
    *out_count = cnt;
    return OZAYN_OTL_ERR_OK;
}

int ozayn_otl_event_get_by_correlation(const ozayn_otl_service_t *svc,
                                       const char *correlation_id,
                                       const ozayn_otl_event_t **out_events,
                                       uint64_t max_count,
                                       uint64_t *out_count) {
    if (!svc || !correlation_id || !out_events || !out_count) return OZAYN_OTL_ERR_NULL_PTR;
    if (!svc->initialized) return OZAYN_OTL_ERR_NOT_INITIALIZED;
    uint64_t cnt = 0;
    uint64_t count = svc->event_count < OZAYN_OTL_MAX_EVENTS ? svc->event_count : OZAYN_OTL_MAX_EVENTS;
    for (uint64_t i = 0; i < count && cnt < max_count; i++) {
        uint64_t idx = (svc->event_head - 1 - i + OZAYN_OTL_MAX_EVENTS) % OZAYN_OTL_MAX_EVENTS;
        if (svc->events[idx].active && svc->events[idx].has_correlation_id &&
            match_str(svc->events[idx].correlation_id, correlation_id))
            out_events[cnt++] = &svc->events[idx];
    }
    *out_count = cnt;
    return OZAYN_OTL_ERR_OK;
}

int ozayn_otl_event_get_by_category(const ozayn_otl_service_t *svc,
                                    ozayn_otl_category_t category,
                                    const ozayn_otl_event_t **out_events,
                                    uint64_t max_count,
                                    uint64_t *out_count) {
    if (!svc || !out_events || !out_count) return OZAYN_OTL_ERR_NULL_PTR;
    if (!svc->initialized) return OZAYN_OTL_ERR_NOT_INITIALIZED;
    uint64_t cnt = 0;
    uint64_t count = svc->event_count < OZAYN_OTL_MAX_EVENTS ? svc->event_count : OZAYN_OTL_MAX_EVENTS;
    for (uint64_t i = 0; i < count && cnt < max_count; i++) {
        uint64_t idx = (svc->event_head - 1 - i + OZAYN_OTL_MAX_EVENTS) % OZAYN_OTL_MAX_EVENTS;
        if (svc->events[idx].active && svc->events[idx].category == category)
            out_events[cnt++] = &svc->events[idx];
    }
    *out_count = cnt;
    return OZAYN_OTL_ERR_OK;
}

int ozayn_otl_event_get_by_component(const ozayn_otl_service_t *svc,
                                     const char *component_id,
                                     const ozayn_otl_event_t **out_events,
                                     uint64_t max_count,
                                     uint64_t *out_count) {
    if (!svc || !component_id || !out_events || !out_count) return OZAYN_OTL_ERR_NULL_PTR;
    if (!svc->initialized) return OZAYN_OTL_ERR_NOT_INITIALIZED;
    uint64_t cnt = 0;
    uint64_t count = svc->event_count < OZAYN_OTL_MAX_EVENTS ? svc->event_count : OZAYN_OTL_MAX_EVENTS;
    for (uint64_t i = 0; i < count && cnt < max_count; i++) {
        uint64_t idx = (svc->event_head - 1 - i + OZAYN_OTL_MAX_EVENTS) % OZAYN_OTL_MAX_EVENTS;
        if (svc->events[idx].active &&
            (match_str(svc->events[idx].source_component_id, component_id) ||
             match_str(svc->events[idx].target_component_id, component_id)))
            out_events[cnt++] = &svc->events[idx];
    }
    *out_count = cnt;
    return OZAYN_OTL_ERR_OK;
}

int ozayn_otl_event_get_by_severity(const ozayn_otl_service_t *svc,
                                    ozayn_otl_severity_t min_severity,
                                    const ozayn_otl_event_t **out_events,
                                    uint64_t max_count,
                                    uint64_t *out_count) {
    if (!svc || !out_events || !out_count) return OZAYN_OTL_ERR_NULL_PTR;
    if (!svc->initialized) return OZAYN_OTL_ERR_NOT_INITIALIZED;
    uint64_t cnt = 0;
    uint64_t count = svc->event_count < OZAYN_OTL_MAX_EVENTS ? svc->event_count : OZAYN_OTL_MAX_EVENTS;
    for (uint64_t i = 0; i < count && cnt < max_count; i++) {
        uint64_t idx = (svc->event_head - 1 - i + OZAYN_OTL_MAX_EVENTS) % OZAYN_OTL_MAX_EVENTS;
        if (svc->events[idx].active && svc->events[idx].severity >= min_severity)
            out_events[cnt++] = &svc->events[idx];
    }
    *out_count = cnt;
    return OZAYN_OTL_ERR_OK;
}

int ozayn_otl_event_get_by_time_range(const ozayn_otl_service_t *svc,
                                      time_t start_time,
                                      time_t end_time,
                                      const ozayn_otl_event_t **out_events,
                                      uint64_t max_count,
                                      uint64_t *out_count) {
    if (!svc || !out_events || !out_count) return OZAYN_OTL_ERR_NULL_PTR;
    if (!svc->initialized) return OZAYN_OTL_ERR_NOT_INITIALIZED;
    uint64_t cnt = 0;
    uint64_t count = svc->event_count < OZAYN_OTL_MAX_EVENTS ? svc->event_count : OZAYN_OTL_MAX_EVENTS;
    for (uint64_t i = 0; i < count && cnt < max_count; i++) {
        uint64_t idx = (svc->event_head - 1 - i + OZAYN_OTL_MAX_EVENTS) % OZAYN_OTL_MAX_EVENTS;
        if (svc->events[idx].active &&
            svc->events[idx].occurrence_time >= start_time &&
            svc->events[idx].occurrence_time <= end_time)
            out_events[cnt++] = &svc->events[idx];
    }
    *out_count = cnt;
    return OZAYN_OTL_ERR_OK;
}

int ozayn_otl_event_get_recent(const ozayn_otl_service_t *svc,
                               uint64_t count,
                               const ozayn_otl_event_t **out_events,
                               uint64_t *out_count) {
    if (!svc || !out_events || !out_count) return OZAYN_OTL_ERR_NULL_PTR;
    if (!svc->initialized) return OZAYN_OTL_ERR_NOT_INITIALIZED;
    uint64_t cnt = 0;
    uint64_t avail = svc->event_count < OZAYN_OTL_MAX_EVENTS ? svc->event_count : OZAYN_OTL_MAX_EVENTS;
    uint64_t limit = count < avail ? count : avail;
    for (uint64_t i = 0; i < limit; i++) {
        uint64_t idx = (svc->event_head - 1 - i + OZAYN_OTL_MAX_EVENTS) % OZAYN_OTL_MAX_EVENTS;
        if (svc->events[idx].active)
            out_events[cnt++] = &svc->events[idx];
    }
    *out_count = cnt;
    return OZAYN_OTL_ERR_OK;
}

int ozayn_otl_event_get_duplicate_check(const ozayn_otl_service_t *svc,
                                        uint64_t event_id,
                                        const char *source_component_id,
                                        uint64_t source_sequence) {
    if (!svc) return 0;
    if (!svc->initialized) return 0;
    uint64_t count = svc->event_count < OZAYN_OTL_MAX_EVENTS ? svc->event_count : OZAYN_OTL_MAX_EVENTS;
    for (uint64_t i = 0; i < count; i++) {
        uint64_t idx = (svc->event_head - 1 - i + OZAYN_OTL_MAX_EVENTS) % OZAYN_OTL_MAX_EVENTS;
        const ozayn_otl_event_t *e = &svc->events[idx];
        if (!e->active) continue;
        if (e->event_id == event_id) return 1;
        if (source_component_id && e->source_sequence == source_sequence &&
            match_str(e->source_component_id, source_component_id))
            return 1;
    }
    return 0;
}

int ozayn_otl_event_set_correlation(ozayn_otl_service_t *svc,
                                    uint64_t event_id,
                                    const char *correlation_id,
                                    ozayn_otl_confidence_t confidence) {
    if (!svc || !correlation_id) return OZAYN_OTL_ERR_NULL_PTR;
    if (!svc->initialized) return OZAYN_OTL_ERR_NOT_INITIALIZED;
    ozayn_otl_event_t *evt = find_event(svc, event_id);
    if (!evt) return OZAYN_OTL_ERR_NOT_FOUND;
    strncpy(evt->correlation_id, correlation_id, OZAYN_OTL_MAX_ID_LEN - 1);
    evt->has_correlation_id = 1;
    evt->correlation_confidence = confidence;
    return OZAYN_OTL_ERR_OK;
}

int ozayn_otl_event_set_parent(ozayn_otl_service_t *svc,
                               uint64_t event_id,
                               uint64_t parent_event_id,
                               ozayn_otl_relationship_t relationship) {
    if (!svc) return OZAYN_OTL_ERR_NULL_PTR;
    if (!svc->initialized) return OZAYN_OTL_ERR_NOT_INITIALIZED;
    ozayn_otl_event_t *evt = find_event(svc, event_id);
    if (!evt) return OZAYN_OTL_ERR_NOT_FOUND;
    const ozayn_otl_event_t *parent = find_event_const(svc, parent_event_id);
    if (!parent) return OZAYN_OTL_ERR_NOT_FOUND;
    (void)relationship;
    char pid_str[32];
    snprintf(pid_str, sizeof(pid_str), "%lu", (unsigned long)parent_event_id);
    strncpy(evt->parent_event_id, pid_str, OZAYN_OTL_MAX_ID_LEN - 1);
    evt->has_parent = 1;
    return OZAYN_OTL_ERR_OK;
}

int ozayn_otl_event_set_description(ozayn_otl_service_t *svc,
                                    uint64_t event_id,
                                    const char *description) {
    if (!svc || !description) return OZAYN_OTL_ERR_NULL_PTR;
    if (!svc->initialized) return OZAYN_OTL_ERR_NOT_INITIALIZED;
    ozayn_otl_event_t *evt = find_event(svc, event_id);
    if (!evt) return OZAYN_OTL_ERR_NOT_FOUND;
    strncpy(evt->description, description, OZAYN_OTL_MAX_MSG_LEN - 1);
    return OZAYN_OTL_ERR_OK;
}

int ozayn_otl_relationship_add(ozayn_otl_service_t *svc,
                               uint64_t from_event_id,
                               uint64_t to_event_id,
                               ozayn_otl_relationship_t relationship,
                               ozayn_otl_confidence_t confidence,
                               uint64_t *out_edge_id) {
    if (!svc) return OZAYN_OTL_ERR_NULL_PTR;
    if (!svc->initialized) return OZAYN_OTL_ERR_NOT_INITIALIZED;
    if (svc->edge_count >= OZAYN_OTL_MAX_EVENTS) return OZAYN_OTL_ERR_FULL;
    const ozayn_otl_event_t *from_evt = find_event_const(svc, from_event_id);
    const ozayn_otl_event_t *to_evt = find_event_const(svc, to_event_id);
    if (!from_evt || !to_evt) return OZAYN_OTL_ERR_NOT_FOUND;

    uint64_t pos = svc->edge_head % OZAYN_OTL_MAX_EVENTS;
    ozayn_otl_edge_t *edge = &svc->edges[pos];
    edge->from_event_id = from_event_id;
    edge->to_event_id = to_event_id;
    edge->type = relationship;
    edge->confidence = confidence;
    edge->active = 1;

    if (out_edge_id) *out_edge_id = pos;
    svc->edge_head++;
    svc->edge_count++;
    return OZAYN_OTL_ERR_OK;
}

int ozayn_otl_relationship_get_by_event(const ozayn_otl_service_t *svc,
                                        uint64_t event_id,
                                        const ozayn_otl_edge_t **out_edges,
                                        uint64_t max_count,
                                        uint64_t *out_count) {
    if (!svc || !out_edges || !out_count) return OZAYN_OTL_ERR_NULL_PTR;
    if (!svc->initialized) return OZAYN_OTL_ERR_NOT_INITIALIZED;
    uint64_t cnt = 0;
    uint64_t count = svc->edge_count < OZAYN_OTL_MAX_EVENTS ? svc->edge_count : OZAYN_OTL_MAX_EVENTS;
    for (uint64_t i = 0; i < count && cnt < max_count; i++) {
        uint64_t idx = (svc->edge_head - 1 - i + OZAYN_OTL_MAX_EVENTS) % OZAYN_OTL_MAX_EVENTS;
        if (svc->edges[idx].active &&
            (svc->edges[idx].from_event_id == event_id || svc->edges[idx].to_event_id == event_id))
            out_edges[cnt++] = &svc->edges[idx];
    }
    *out_count = cnt;
    return OZAYN_OTL_ERR_OK;
}

int ozayn_otl_timeline_create(ozayn_otl_service_t *svc,
                              const char *correlation_id,
                              const char *operation_id,
                              const char *request_id,
                              const char *workflow_id,
                              const char *pipeline_id,
                              uint64_t *out_timeline_id) {
    if (!svc) return OZAYN_OTL_ERR_NULL_PTR;
    if (!svc->initialized) return OZAYN_OTL_ERR_NOT_INITIALIZED;
    if (!correlation_id) return OZAYN_OTL_ERR_NULL_PTR;
    if (svc->timeline_count >= OZAYN_OTL_MAX_TIMELINES) return OZAYN_OTL_ERR_FULL;

    for (uint64_t i = 0; i < svc->timeline_count; i++) {
        uint64_t idx = (svc->timeline_head - 1 - i + OZAYN_OTL_MAX_TIMELINES) % OZAYN_OTL_MAX_TIMELINES;
        if (svc->timelines[idx].active && match_str(svc->timelines[idx].correlation_id, correlation_id))
            return OZAYN_OTL_ERR_DUPLICATE;
    }

    uint64_t pos = svc->timeline_head % OZAYN_OTL_MAX_TIMELINES;
    ozayn_otl_timeline_t *tl = &svc->timelines[pos];
    memset(tl, 0, sizeof(*tl));
    tl->timeline_id = ++svc->sequence;
    strncpy(tl->correlation_id, correlation_id, OZAYN_OTL_MAX_ID_LEN - 1);
    if (operation_id) strncpy(tl->operation_id, operation_id, OZAYN_OTL_MAX_ID_LEN - 1);
    if (request_id) strncpy(tl->request_id, request_id, OZAYN_OTL_MAX_ID_LEN - 1);
    if (workflow_id) strncpy(tl->workflow_id, workflow_id, OZAYN_OTL_MAX_ID_LEN - 1);
    if (pipeline_id) strncpy(tl->pipeline_id, pipeline_id, OZAYN_OTL_MAX_ID_LEN - 1);
    tl->state = OZAYN_OTL_TL_CREATED;
    tl->start_time = time(0);
    tl->active = 1;

    if (out_timeline_id) *out_timeline_id = tl->timeline_id;
    svc->timeline_head++;
    svc->timeline_count++;
    svc->stats.total_timelines_created++;
    svc->stats.current_active_timelines++;
    return OZAYN_OTL_ERR_OK;
}

int ozayn_otl_timeline_add_event(ozayn_otl_service_t *svc,
                                 uint64_t timeline_id,
                                 uint64_t event_id) {
    if (!svc) return OZAYN_OTL_ERR_NULL_PTR;
    if (!svc->initialized) return OZAYN_OTL_ERR_NOT_INITIALIZED;
    ozayn_otl_timeline_t *tl = find_timeline(svc, timeline_id);
    if (!tl) return OZAYN_OTL_ERR_NOT_FOUND;
    const ozayn_otl_event_t *evt = find_event_const(svc, event_id);
    if (!evt) return OZAYN_OTL_ERR_NOT_FOUND;
    if (tl->event_ref_count >= OZAYN_OTL_MAX_EVENTS_PER_TIMELINE) return OZAYN_OTL_ERR_FULL;

    tl->event_refs[tl->event_ref_count++] = event_id;
    tl->event_count++;
    tl->current_event_id = event_id;
    tl->last_event_time = evt->occurrence_time;
    if (tl->event_ref_count == 1) tl->root_event_id = event_id;
    if (tl->state == OZAYN_OTL_TL_CREATED) tl->state = OZAYN_OTL_TL_ACTIVE;
    return OZAYN_OTL_ERR_OK;
}

int ozayn_otl_timeline_complete(ozayn_otl_service_t *svc,
                                uint64_t timeline_id,
                                ozayn_otl_timeline_state_t final_state) {
    if (!svc) return OZAYN_OTL_ERR_NULL_PTR;
    if (!svc->initialized) return OZAYN_OTL_ERR_NOT_INITIALIZED;
    ozayn_otl_timeline_t *tl = find_timeline(svc, timeline_id);
    if (!tl) return OZAYN_OTL_ERR_NOT_FOUND;
    if (tl->state == OZAYN_OTL_TL_COMPLETED || tl->state == OZAYN_OTL_TL_FAILED ||
        tl->state == OZAYN_OTL_TL_CANCELLED || tl->state == OZAYN_OTL_TL_EXPIRED)
        return OZAYN_OTL_ERR_INVALID_STATE;

    tl->state = final_state;
    tl->end_time = time(0);
    svc->stats.current_active_timelines--;
    if (final_state == OZAYN_OTL_TL_COMPLETED) svc->stats.total_timelines_completed++;
    else if (final_state == OZAYN_OTL_TL_FAILED) svc->stats.total_timelines_failed++;
    return OZAYN_OTL_ERR_OK;
}

int ozayn_otl_timeline_get(const ozayn_otl_service_t *svc,
                           uint64_t timeline_id,
                           const ozayn_otl_timeline_t **out_timeline) {
    if (!svc || !out_timeline) return OZAYN_OTL_ERR_NULL_PTR;
    if (!svc->initialized) return OZAYN_OTL_ERR_NOT_INITIALIZED;
    const ozayn_otl_timeline_t *tl = find_timeline_const(svc, timeline_id);
    if (!tl) return OZAYN_OTL_ERR_NOT_FOUND;
    *out_timeline = tl;
    return OZAYN_OTL_ERR_OK;
}

int ozayn_otl_timeline_get_by_correlation(const ozayn_otl_service_t *svc,
                                          const char *correlation_id,
                                          const ozayn_otl_timeline_t **out_timeline) {
    if (!svc || !correlation_id || !out_timeline) return OZAYN_OTL_ERR_NULL_PTR;
    if (!svc->initialized) return OZAYN_OTL_ERR_NOT_INITIALIZED;
    uint64_t count = svc->timeline_count < OZAYN_OTL_MAX_TIMELINES ? svc->timeline_count : OZAYN_OTL_MAX_TIMELINES;
    for (uint64_t i = 0; i < count; i++) {
        uint64_t idx = (svc->timeline_head - 1 - i + OZAYN_OTL_MAX_TIMELINES) % OZAYN_OTL_MAX_TIMELINES;
        if (svc->timelines[idx].active && match_str(svc->timelines[idx].correlation_id, correlation_id)) {
            *out_timeline = &svc->timelines[idx];
            return OZAYN_OTL_ERR_OK;
        }
    }
    return OZAYN_OTL_ERR_NOT_FOUND;
}

int ozayn_otl_timeline_get_by_operation(const ozayn_otl_service_t *svc,
                                        const char *operation_id,
                                        const ozayn_otl_timeline_t **out_timeline) {
    if (!svc || !operation_id || !out_timeline) return OZAYN_OTL_ERR_NULL_PTR;
    if (!svc->initialized) return OZAYN_OTL_ERR_NOT_INITIALIZED;
    uint64_t count = svc->timeline_count < OZAYN_OTL_MAX_TIMELINES ? svc->timeline_count : OZAYN_OTL_MAX_TIMELINES;
    for (uint64_t i = 0; i < count; i++) {
        uint64_t idx = (svc->timeline_head - 1 - i + OZAYN_OTL_MAX_TIMELINES) % OZAYN_OTL_MAX_TIMELINES;
        if (svc->timelines[idx].active && match_str(svc->timelines[idx].operation_id, operation_id)) {
            *out_timeline = &svc->timelines[idx];
            return OZAYN_OTL_ERR_OK;
        }
    }
    return OZAYN_OTL_ERR_NOT_FOUND;
}

int ozayn_otl_timeline_get_active(const ozayn_otl_service_t *svc,
                                  const ozayn_otl_timeline_t **out_timelines,
                                  uint64_t max_count,
                                  uint64_t *out_count) {
    if (!svc || !out_timelines || !out_count) return OZAYN_OTL_ERR_NULL_PTR;
    if (!svc->initialized) return OZAYN_OTL_ERR_NOT_INITIALIZED;
    uint64_t cnt = 0;
    uint64_t count = svc->timeline_count < OZAYN_OTL_MAX_TIMELINES ? svc->timeline_count : OZAYN_OTL_MAX_TIMELINES;
    for (uint64_t i = 0; i < count && cnt < max_count; i++) {
        uint64_t idx = (svc->timeline_head - 1 - i + OZAYN_OTL_MAX_TIMELINES) % OZAYN_OTL_MAX_TIMELINES;
        if (svc->timelines[idx].active &&
            (svc->timelines[idx].state == OZAYN_OTL_TL_ACTIVE || svc->timelines[idx].state == OZAYN_OTL_TL_CREATED))
            out_timelines[cnt++] = &svc->timelines[idx];
    }
    *out_count = cnt;
    return OZAYN_OTL_ERR_OK;
}

int ozayn_otl_timeline_get_events(const ozayn_otl_service_t *svc,
                                  uint64_t timeline_id,
                                  const ozayn_otl_event_t **out_events,
                                  uint64_t max_count,
                                  uint64_t *out_count) {
    if (!svc || !out_events || !out_count) return OZAYN_OTL_ERR_NULL_PTR;
    if (!svc->initialized) return OZAYN_OTL_ERR_NOT_INITIALIZED;
    const ozayn_otl_timeline_t *tl = find_timeline_const(svc, timeline_id);
    if (!tl) return OZAYN_OTL_ERR_NOT_FOUND;
    uint64_t cnt = 0;
    for (uint64_t i = 0; i < tl->event_ref_count && cnt < max_count; i++) {
        const ozayn_otl_event_t *evt = find_event_const(svc, tl->event_refs[i]);
        if (evt) out_events[cnt++] = evt;
    }
    *out_count = cnt;
    return OZAYN_OTL_ERR_OK;
}

int ozayn_otl_timeline_get_operation_chain(const ozayn_otl_service_t *svc,
                                           const char *operation_id,
                                           const ozayn_otl_event_t **out_events,
                                           uint64_t max_count,
                                           uint64_t *out_count) {
    if (!svc || !operation_id || !out_events || !out_count) return OZAYN_OTL_ERR_NULL_PTR;
    if (!svc->initialized) return OZAYN_OTL_ERR_NOT_INITIALIZED;
    return ozayn_otl_event_get_by_request(svc, operation_id, out_events, max_count, out_count);
}

int ozayn_otl_timeline_get_workflow_chain(const ozayn_otl_service_t *svc,
                                          const char *workflow_id,
                                          const ozayn_otl_event_t **out_events,
                                          uint64_t max_count,
                                          uint64_t *out_count) {
    if (!svc || !workflow_id || !out_events || !out_count) return OZAYN_OTL_ERR_NULL_PTR;
    if (!svc->initialized) return OZAYN_OTL_ERR_NOT_INITIALIZED;
    uint64_t cnt = 0;
    uint64_t count = svc->event_count < OZAYN_OTL_MAX_EVENTS ? svc->event_count : OZAYN_OTL_MAX_EVENTS;
    for (uint64_t i = 0; i < count && cnt < max_count; i++) {
        uint64_t idx = (svc->event_head - 1 - i + OZAYN_OTL_MAX_EVENTS) % OZAYN_OTL_MAX_EVENTS;
        if (svc->events[idx].active && match_str(svc->events[idx].workflow_id, workflow_id))
            out_events[cnt++] = &svc->events[idx];
    }
    *out_count = cnt;
    return OZAYN_OTL_ERR_OK;
}

int ozayn_otl_timeline_get_pipeline_chain(const ozayn_otl_service_t *svc,
                                           const char *pipeline_id,
                                           const ozayn_otl_event_t **out_events,
                                           uint64_t max_count,
                                           uint64_t *out_count) {
    if (!svc || !pipeline_id || !out_events || !out_count) return OZAYN_OTL_ERR_NULL_PTR;
    if (!svc->initialized) return OZAYN_OTL_ERR_NOT_INITIALIZED;
    uint64_t cnt = 0;
    uint64_t count = svc->event_count < OZAYN_OTL_MAX_EVENTS ? svc->event_count : OZAYN_OTL_MAX_EVENTS;
    for (uint64_t i = 0; i < count && cnt < max_count; i++) {
        uint64_t idx = (svc->event_head - 1 - i + OZAYN_OTL_MAX_EVENTS) % OZAYN_OTL_MAX_EVENTS;
        if (svc->events[idx].active && match_str(svc->events[idx].pipeline_id, pipeline_id))
            out_events[cnt++] = &svc->events[idx];
    }
    *out_count = cnt;
    return OZAYN_OTL_ERR_OK;
}

int ozayn_otl_timeline_get_children(const ozayn_otl_service_t *svc,
                                    uint64_t event_id,
                                    const ozayn_otl_event_t **out_events,
                                    uint64_t max_count,
                                    uint64_t *out_count) {
    if (!svc || !out_events || !out_count) return OZAYN_OTL_ERR_NULL_PTR;
    if (!svc->initialized) return OZAYN_OTL_ERR_NOT_INITIALIZED;
    uint64_t cnt = 0;
    uint64_t ecount = svc->edge_count < OZAYN_OTL_MAX_EVENTS ? svc->edge_count : OZAYN_OTL_MAX_EVENTS;
    for (uint64_t i = 0; i < ecount && cnt < max_count; i++) {
        uint64_t idx = (svc->edge_head - 1 - i + OZAYN_OTL_MAX_EVENTS) % OZAYN_OTL_MAX_EVENTS;
        if (svc->edges[idx].active && svc->edges[idx].from_event_id == event_id) {
            const ozayn_otl_event_t *child = find_event_const(svc, svc->edges[idx].to_event_id);
            if (child) out_events[cnt++] = child;
        }
    }
    *out_count = cnt;
    return OZAYN_OTL_ERR_OK;
}

int ozayn_otl_timeline_get_predecessors(const ozayn_otl_service_t *svc,
                                        uint64_t event_id,
                                        const ozayn_otl_event_t **out_events,
                                        uint64_t max_count,
                                        uint64_t *out_count) {
    if (!svc || !out_events || !out_count) return OZAYN_OTL_ERR_NULL_PTR;
    if (!svc->initialized) return OZAYN_OTL_ERR_NOT_INITIALIZED;
    uint64_t cnt = 0;
    uint64_t ecount = svc->edge_count < OZAYN_OTL_MAX_EVENTS ? svc->edge_count : OZAYN_OTL_MAX_EVENTS;
    for (uint64_t i = 0; i < ecount && cnt < max_count; i++) {
        uint64_t idx = (svc->edge_head - 1 - i + OZAYN_OTL_MAX_EVENTS) % OZAYN_OTL_MAX_EVENTS;
        if (svc->edges[idx].active && svc->edges[idx].to_event_id == event_id) {
            const ozayn_otl_event_t *parent = find_event_const(svc, svc->edges[idx].from_event_id);
            if (parent) out_events[cnt++] = parent;
        }
    }
    *out_count = cnt;
    return OZAYN_OTL_ERR_OK;
}

int ozayn_otl_timeline_get_successors(const ozayn_otl_service_t *svc,
                                      uint64_t event_id,
                                      const ozayn_otl_event_t **out_events,
                                      uint64_t max_count,
                                      uint64_t *out_count) {
    return ozayn_otl_timeline_get_children(svc, event_id, out_events, max_count, out_count);
}

int ozayn_otl_consistency_check(const ozayn_otl_service_t *svc,
                                uint64_t timeline_id,
                                int *out_consistent,
                                char *out_issue,
                                uint64_t issue_len) {
    if (!svc || !out_consistent) return OZAYN_OTL_ERR_NULL_PTR;
    if (!svc->initialized) return OZAYN_OTL_ERR_NOT_INITIALIZED;
    const ozayn_otl_timeline_t *tl = find_timeline_const(svc, timeline_id);
    if (!tl) return OZAYN_OTL_ERR_NOT_FOUND;

    *out_consistent = 1;
    if (out_issue) out_issue[0] = '\0';

    if (tl->state == OZAYN_OTL_TL_COMPLETED && tl->start_time > tl->end_time) {
        *out_consistent = 0;
        if (out_issue) snprintf(out_issue, issue_len, "completion before start");
        return OZAYN_OTL_ERR_OK;
    }
    if (tl->event_count == 0 && tl->state != OZAYN_OTL_TL_CREATED) {
        *out_consistent = 0;
        if (out_issue) snprintf(out_issue, issue_len, "no events in non-created timeline");
        return OZAYN_OTL_ERR_OK;
    }
    for (uint64_t i = 0; i < tl->event_ref_count; i++) {
        const ozayn_otl_event_t *evt = find_event_const(svc, tl->event_refs[i]);
        if (!evt) {
            *out_consistent = 0;
            if (out_issue) snprintf(out_issue, issue_len, "missing event ref %lu", (unsigned long)tl->event_refs[i]);
            return OZAYN_OTL_ERR_OK;
        }
    }
    return OZAYN_OTL_ERR_OK;
}

int ozayn_otl_stats_get(const ozayn_otl_service_t *svc, ozayn_otl_stats_t *out_stats) {
    if (!svc || !out_stats) return OZAYN_OTL_ERR_NULL_PTR;
    if (!svc->initialized) return OZAYN_OTL_ERR_NOT_INITIALIZED;
    *out_stats = svc->stats;
    return OZAYN_OTL_ERR_OK;
}

int64_t ozayn_otl_event_count(const ozayn_otl_service_t *svc) {
    if (!svc || !svc->initialized) return -1;
    return (int64_t)svc->stats.current_events_stored;
}

int64_t ozayn_otl_timeline_count(const ozayn_otl_service_t *svc) {
    if (!svc || !svc->initialized) return -1;
    return (int64_t)svc->timeline_count;
}

int64_t ozayn_otl_active_timeline_count(const ozayn_otl_service_t *svc) {
    if (!svc || !svc->initialized) return -1;
    return (int64_t)svc->stats.current_active_timelines;
}

int ozayn_otl_shutdown_drain(ozayn_otl_service_t *svc,
                             const ozayn_otl_timeline_t **out_active,
                             uint64_t max_count,
                             uint64_t *out_count) {
    if (!svc || !out_active || !out_count) return OZAYN_OTL_ERR_NULL_PTR;
    if (!svc->initialized) return OZAYN_OTL_ERR_NOT_INITIALIZED;
    uint64_t cnt = 0;
    uint64_t count = svc->timeline_count < OZAYN_OTL_MAX_TIMELINES ? svc->timeline_count : OZAYN_OTL_MAX_TIMELINES;
    for (uint64_t i = 0; i < count && cnt < max_count; i++) {
        uint64_t idx = (svc->timeline_head - 1 - i + OZAYN_OTL_MAX_TIMELINES) % OZAYN_OTL_MAX_TIMELINES;
        if (svc->timelines[idx].active &&
            (svc->timelines[idx].state == OZAYN_OTL_TL_ACTIVE || svc->timelines[idx].state == OZAYN_OTL_TL_CREATED))
            out_active[cnt++] = &svc->timelines[idx];
    }
    *out_count = cnt;
    return OZAYN_OTL_ERR_OK;
}

int ozayn_otl_retention_prune(ozayn_otl_service_t *svc,
                              uint64_t max_events,
                              uint64_t max_age_seconds,
                              uint64_t *out_pruned) {
    if (!svc) return OZAYN_OTL_ERR_NULL_PTR;
    if (!svc->initialized) return OZAYN_OTL_ERR_NOT_INITIALIZED;
    if (!out_pruned) return OZAYN_OTL_ERR_NULL_PTR;
    *out_pruned = 0;
    time_t now = time(0);
    uint64_t count = svc->event_count < OZAYN_OTL_MAX_EVENTS ? svc->event_count : OZAYN_OTL_MAX_EVENTS;
    for (uint64_t i = 0; i < count; i++) {
        uint64_t idx = (svc->event_head - 1 - i + OZAYN_OTL_MAX_EVENTS) % OZAYN_OTL_MAX_EVENTS;
        ozayn_otl_event_t *evt = &svc->events[idx];
        if (!evt->active) continue;
        int should_prune = 0;
        if (max_events > 0 && svc->stats.current_events_stored > max_events) should_prune = 1;
        if (max_age_seconds > 0 && (now - evt->occurrence_time) > (time_t)max_age_seconds) should_prune = 1;
        if (should_prune) {
            evt->active = 0;
            svc->stats.current_events_stored--;
            (*out_pruned)++;
        }
    }
    return OZAYN_OTL_ERR_OK;
}
