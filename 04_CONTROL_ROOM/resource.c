#include "resource.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

/* ============================================================
 * SECTION 1 — INTERNAL HELPERS
 * ============================================================ */

static ozayn_rcm_service_t _svc;

static int _find_resource(const ozayn_rcm_service_t *svc, const char *resource_id)
{
    if (!svc || !resource_id) return -1;
    for (int i = 0; i < svc->resource_count; i++) {
        if (svc->resources[i].active &&
            strcmp(svc->resources[i].resource_id, resource_id) == 0)
            return i;
    }
    return -1;
}

static int _find_reservation(const ozayn_rcm_service_t *svc, const char *reservation_id)
{
    if (!svc || !reservation_id) return -1;
    for (int i = 0; i < svc->reservation_count; i++) {
        if (svc->reservations[i].active &&
            strcmp(svc->reservations[i].reservation_id, reservation_id) == 0)
            return i;
    }
    return -1;
}

static int _find_decision(const ozayn_rcm_service_t *svc, const char *decision_id)
{
    if (!svc || !decision_id) return -1;
    for (int i = 0; i < svc->decision_count; i++) {
        int idx = (svc->decision_head + i) % svc->max_decisions;
        if (svc->decisions[idx].active &&
            strcmp(svc->decisions[idx].decision_id, decision_id) == 0)
            return idx;
    }
    return -1;
}

static int _find_snapshot(const ozayn_rcm_service_t *svc, const char *snapshot_id)
{
    if (!svc || !snapshot_id) return -1;
    for (int i = 0; i < svc->snapshot_count; i++) {
        if (strcmp(svc->snapshots[i].snapshot_id, snapshot_id) == 0)
            return i;
    }
    return -1;
}

static void _compute_capacity(ozayn_rcm_resource_desc_t *res)
{
    uint64_t cap = res->capacity.total;
    uint64_t used = res->capacity.used;
    uint64_t reserved = res->capacity.reserved;
    if (used + reserved > cap) {
        res->capacity.available = 0;
    } else {
        res->capacity.available = cap - used - reserved;
    }
    if (res->capacity.available == 0 && cap > 0) {
        res->state = OZAYN_RCM_STATE_EXHAUSTED;
    } else if (res->capacity.available < cap / 4 && cap > 0) {
        res->state = OZAYN_RCM_STATE_BUSY;
    }
}

static void _emit_event(ozayn_rcm_service_t *svc,
                         ozayn_rcm_event_type_t type,
                         const char *resource_id,
                         const char *message)
{
    int idx = (svc->event_head + svc->event_count) %
              OZAYN_RCM_MAX_DECISIONS;
    if (svc->event_count >= OZAYN_RCM_MAX_DECISIONS) {
        svc->event_head = (svc->event_head + 1) % OZAYN_RCM_MAX_DECISIONS;
    } else {
        svc->event_count++;
    }
    ozayn_rcm_event_t *ev = &svc->events[idx];
    memset(ev, 0, sizeof(*ev));
    ev->type = type;
    ev->timestamp = time(NULL);
    if (resource_id) strncpy(ev->resource_id, resource_id, OZAYN_RCM_MAX_ID_LEN - 1);
    if (message) strncpy(ev->message, message, OZAYN_RCM_MAX_METADATA_LEN - 1);
}

static int _check_reservations_conflict(const ozayn_rcm_service_t *svc,
                                         const char *resource_id,
                                         const char *exclude_operation)
{
    for (int i = 0; i < svc->reservation_count; i++) {
        if (!svc->reservations[i].active) continue;
        if (svc->reservations[i].state == OZAYN_RCM_RESERV_RELEASED ||
            svc->reservations[i].state == OZAYN_RCM_RESERV_CANCELLED ||
            svc->reservations[i].state == OZAYN_RCM_RESERV_EXPIRED ||
            svc->reservations[i].state == OZAYN_RCM_RESERV_FAILED)
            continue;
        if (strcmp(svc->reservations[i].resource_id, resource_id) == 0) {
            if (exclude_operation &&
                strcmp(svc->reservations[i].operation_id, exclude_operation) == 0)
                continue;
            time_t now = time(NULL);
            if (svc->reservations[i].expiry_time > 0 && now > svc->reservations[i].expiry_time)
                continue;
            return 1;
        }
    }
    return 0;
}

/* ============================================================
 * SECTION 2 — NAME HELPERS
 * ============================================================ */

const char *ozayn_rcm_resource_type_name(ozayn_rcm_resource_type_t val)
{
    static const char *names[] = {
        "CPU", "Memory", "Storage", "WorkerCapacity", "QueueCapacity",
        "GPU", "Audio", "Camera", "Microphone", "Network"
    };
    if (val < 0 || val >= OZAYN_RCM_RES_TYPE_COUNT) return "Invalid";
    return names[val];
}

const char *ozayn_rcm_resource_state_name(ozayn_rcm_resource_state_t val)
{
    static const char *names[] = {
        "Unknown", "Available", "Busy", "Degraded", "Exhausted",
        "Unavailable", "Unsupported", "Error"
    };
    if (val < 0 || val >= OZAYN_RCM_STATE_COUNT) return "Invalid";
    return names[val];
}

const char *ozayn_rcm_resource_health_name(ozayn_rcm_resource_health_t val)
{
    static const char *names[] = {
        "Unknown", "Healthy", "Degraded", "Unhealthy", "Failed"
    };
    if (val < 0 || val >= OZAYN_RCM_HEALTH_COUNT) return "Invalid";
    return names[val];
}

const char *ozayn_rcm_availability_name(ozayn_rcm_availability_t val)
{
    static const char *names[] = {
        "Unknown", "Available", "Unavailable", "Limited"
    };
    if (val < 0 || val >= OZAYN_RCM_AVAIL_COUNT) return "Invalid";
    return names[val];
}

const char *ozayn_rcm_resource_decision_name(ozayn_rcm_decision_result_t val)
{
    static const char *names[] = {
        "Available", "Insufficient", "Unavailable", "Unknown",
        "Reserved", "Conflict"
    };
    if (val < 0 || val >= OZAYN_RCM_DECISION_COUNT) return "Invalid";
    return names[val];
}

const char *ozayn_rcm_reservation_state_name(ozayn_rcm_reservation_state_t val)
{
    static const char *names[] = {
        "Requested", "Reserved", "Active", "Released",
        "Expired", "Cancelled", "Failed"
    };
    if (val < 0 || val >= OZAYN_RCM_RESERV_COUNT) return "Invalid";
    return names[val];
}

const char *ozayn_rcm_priority_name(ozayn_rcm_priority_t val)
{
    static const char *names[] = {
        "Low", "Normal", "High", "Critical"
    };
    if (val < 0 || val >= OZAYN_RCM_PRIORITY_COUNT) return "Invalid";
    return names[val];
}

const char *ozayn_rcm_event_type_name(ozayn_rcm_event_type_t val)
{
    static const char *names[] = {
        "ResourceRegistered", "ResourceUpdated", "ResourceUnavailable",
        "ResourceDegraded", "ResourceExhausted", "ReservationCreated",
        "ReservationReserved", "ReservationReleased", "ReservationExpired",
        "ReservationFailed", "CapacityChanged", "ConflictDetected"
    };
    if (val < 0 || val >= OZAYN_RCM_EVENT_COUNT) return "Invalid";
    return names[val];
}

const char *ozayn_rcm_err_name(ozayn_rcm_err_t val)
{
    static const char *names[] = {
        "OK", "Null", "NotInitialized", "AlreadyInitialized",
        "InvalidParam", "LimitReached", "NotFound", "Duplicate",
        "Invalid", "Unavailable", "Unsupported", "MeasurementFailed",
        "CapacityInvalid", "RequirementFailed", "Conflict",
        "ReservationFailed", "ReservationExpired", "ReservationNotFound",
        "ReservationConflict", "LimitReachedReservation", "Timeout",
        "Concurrency", "ProviderError"
    };
    int idx = -val;
    if (idx < 0 || idx > 22) return "Invalid";
    return names[idx];
}

/* ============================================================
 * SECTION 3 — LIFECYCLE
 * ============================================================ */

ozayn_rcm_err_t ozayn_rcm_service_init(ozayn_rcm_service_t *svc,
                                        const ozayn_rcm_service_config_t *cfg)
{
    if (!svc || !cfg) return OZAYN_RCM_ERR_NULL;
    if (svc->initialized) return OZAYN_RCM_ERR_ALREADY_INITIALIZED;

    memset(svc, 0, sizeof(*svc));

    svc->max_resources = cfg->max_resources > 0 ?
        cfg->max_resources : OZAYN_RCM_MAX_RESOURCES;
    svc->max_decisions = cfg->max_decisions > 0 ?
        cfg->max_decisions : OZAYN_RCM_MAX_DECISIONS;
    svc->max_reservations = cfg->max_reservations > 0 ?
        cfg->max_reservations : OZAYN_RCM_MAX_RESERVATIONS;
    svc->reservation_ttl_ms = cfg->reservation_ttl_ms > 0 ?
        cfg->reservation_ttl_ms : OZAYN_RCM_DEFAULT_RESERVATION_TTL_MS;
    svc->max_reservation_duration_ms = cfg->max_reservation_duration_ms > 0 ?
        cfg->max_reservation_duration_ms : 300000;
    svc->max_concurrent_operations = cfg->max_concurrent_operations > 0 ?
        cfg->max_concurrent_operations : 16;
    svc->max_workers = cfg->max_workers > 0 ? cfg->max_workers : 8;
    svc->max_queue_size = cfg->max_queue_size > 0 ? cfg->max_queue_size : 64;
    svc->component_registry = cfg->component_registry;
    svc->diagnostics = cfg->diagnostics;
    svc->audit = cfg->audit;
    svc->authorization = cfg->authorization;

    svc->initialized = 1;
    return OZAYN_RCM_OK;
}

void ozayn_rcm_service_shutdown(ozayn_rcm_service_t *svc)
{
    if (!svc) return;
    svc->initialized = 0;
    memset(svc, 0, sizeof(*svc));
}

int ozayn_rcm_service_is_initialized(const ozayn_rcm_service_t *svc)
{
    if (!svc) return 0;
    return svc->initialized;
}

ozayn_rcm_service_t *ozayn_rcm_get_global(void)
{
    return &_svc;
}

/* ============================================================
 * SECTION 4 — RESOURCE REGISTRATION & MANAGEMENT
 * ============================================================ */

ozayn_rcm_err_t ozayn_rcm_resource_register(ozayn_rcm_service_t *svc,
                                             ozayn_rcm_resource_type_t type,
                                             const char *name,
                                             const char *provider,
                                             const char *unit,
                                             uint64_t total_capacity,
                                             ozayn_rcm_resource_desc_t **out_resource)
{
    if (!svc) return OZAYN_RCM_ERR_NULL;
    if (!svc->initialized) return OZAYN_RCM_ERR_NOT_INITIALIZED;
    if (type < 0 || type >= OZAYN_RCM_RES_TYPE_COUNT)
        return OZAYN_RCM_ERR_INVALID_PARAM;
    if (!name || name[0] == '\0') return OZAYN_RCM_ERR_INVALID_PARAM;
    if (!out_resource) return OZAYN_RCM_ERR_NULL;

    for (int i = 0; i < svc->resource_count; i++) {
        if (svc->resources[i].active &&
            svc->resources[i].type == type &&
            strcmp(svc->resources[i].name, name) == 0)
            return OZAYN_RCM_ERR_DUPLICATE;
    }

    if (svc->resource_count >= svc->max_resources)
        return OZAYN_RCM_ERR_LIMIT_REACHED;

    int idx = svc->resource_count;
    ozayn_rcm_resource_desc_t *res = &svc->resources[idx];
    memset(res, 0, sizeof(*res));

    svc->resource_sequence++;
    snprintf(res->resource_id, OZAYN_RCM_MAX_ID_LEN, "RCR-%u",
             svc->resource_sequence);
    res->type = type;
    strncpy(res->name, name, OZAYN_RCM_MAX_NAME_LEN - 1);
    if (provider) strncpy(res->provider, provider, OZAYN_RCM_MAX_PROVIDER_LEN - 1);
    res->version = 1;
    res->availability = OZAYN_RCM_AVAIL_AVAILABLE;
    res->capacity.total = total_capacity;
    res->capacity.available = total_capacity;
    if (unit) strncpy(res->unit, unit, OZAYN_RCM_MAX_UNIT_LEN - 1);
    res->state = OZAYN_RCM_STATE_AVAILABLE;
    res->health = OZAYN_RCM_HEALTH_HEALTHY;
    res->last_update = time(NULL);
    res->active = 1;

    svc->resource_count++;
    svc->stats.total_resources_registered++;

    _emit_event(svc, OZAYN_RCM_EVENT_RESOURCE_REGISTERED,
                res->resource_id, name);

    *out_resource = res;
    return OZAYN_RCM_OK;
}

ozayn_rcm_err_t ozayn_rcm_resource_unregister(ozayn_rcm_service_t *svc,
                                               const char *resource_id)
{
    if (!svc) return OZAYN_RCM_ERR_NULL;
    if (!svc->initialized) return OZAYN_RCM_ERR_NOT_INITIALIZED;
    if (!resource_id || resource_id[0] == '\0')
        return OZAYN_RCM_ERR_INVALID_PARAM;

    int idx = _find_resource(svc, resource_id);
    if (idx < 0) return OZAYN_RCM_ERR_NOT_FOUND;

    svc->resources[idx].active = 0;
    svc->resource_count--;
    return OZAYN_RCM_OK;
}

const ozayn_rcm_resource_desc_t *ozayn_rcm_resource_get(
    const ozayn_rcm_service_t *svc,
    const char *resource_id)
{
    if (!svc || !resource_id) return NULL;
    int idx = _find_resource(svc, resource_id);
    if (idx < 0) return NULL;
    return &svc->resources[idx];
}

const ozayn_rcm_resource_desc_t *ozayn_rcm_resource_get_by_type(
    const ozayn_rcm_service_t *svc,
    ozayn_rcm_resource_type_t type)
{
    if (!svc) return NULL;
    for (int i = 0; i < svc->resource_count; i++) {
        if (svc->resources[i].active && svc->resources[i].type == type)
            return &svc->resources[i];
    }
    return NULL;
}

int ozayn_rcm_resource_count(const ozayn_rcm_service_t *svc)
{
    if (!svc) return 0;
    return svc->resource_count;
}

int ozayn_rcm_resource_full(const ozayn_rcm_service_t *svc)
{
    if (!svc) return 1;
    return svc->resource_count >= svc->max_resources;
}

/* ============================================================
 * SECTION 5 — RESOURCE STATE UPDATES
 * ============================================================ */

ozayn_rcm_err_t ozayn_rcm_resource_update_usage(ozayn_rcm_service_t *svc,
                                                 const char *resource_id,
                                                 uint64_t used)
{
    if (!svc) return OZAYN_RCM_ERR_NULL;
    if (!svc->initialized) return OZAYN_RCM_ERR_NOT_INITIALIZED;
    if (!resource_id || resource_id[0] == '\0')
        return OZAYN_RCM_ERR_INVALID_PARAM;

    int idx = _find_resource(svc, resource_id);
    if (idx < 0) return OZAYN_RCM_ERR_NOT_FOUND;

    ozayn_rcm_resource_desc_t *res = &svc->resources[idx];
    if (used > res->capacity.total)
        return OZAYN_RCM_ERR_CAPACITY_INVALID;

    res->capacity.used = used;
    _compute_capacity(res);
    res->last_update = time(NULL);
    svc->stats.total_resources_updated++;

    _emit_event(svc, OZAYN_RCM_EVENT_RESOURCE_UPDATED,
                resource_id, "usage updated");

    if (res->capacity.available == 0) {
        _emit_event(svc, OZAYN_RCM_EVENT_RESOURCE_EXHAUSTED,
                    resource_id, "resource exhausted");
    }

    return OZAYN_RCM_OK;
}

ozayn_rcm_err_t ozayn_rcm_resource_update_state(ozayn_rcm_service_t *svc,
                                                 const char *resource_id,
                                                 ozayn_rcm_resource_state_t state)
{
    if (!svc) return OZAYN_RCM_ERR_NULL;
    if (!svc->initialized) return OZAYN_RCM_ERR_NOT_INITIALIZED;
    if (!resource_id || resource_id[0] == '\0')
        return OZAYN_RCM_ERR_INVALID_PARAM;
    if (state < 0 || state >= OZAYN_RCM_STATE_COUNT)
        return OZAYN_RCM_ERR_INVALID_PARAM;

    int idx = _find_resource(svc, resource_id);
    if (idx < 0) return OZAYN_RCM_ERR_NOT_FOUND;

    svc->resources[idx].state = state;
    svc->resources[idx].last_update = time(NULL);
    svc->stats.total_resources_updated++;

    if (state == OZAYN_RCM_STATE_UNAVAILABLE) {
        _emit_event(svc, OZAYN_RCM_EVENT_RESOURCE_UNAVAILABLE,
                    resource_id, "resource unavailable");
    } else if (state == OZAYN_RCM_STATE_DEGRADED) {
        _emit_event(svc, OZAYN_RCM_EVENT_RESOURCE_DEGRADED,
                    resource_id, "resource degraded");
    } else if (state == OZAYN_RCM_STATE_EXHAUSTED) {
        _emit_event(svc, OZAYN_RCM_EVENT_RESOURCE_EXHAUSTED,
                    resource_id, "resource exhausted");
    }

    return OZAYN_RCM_OK;
}

ozayn_rcm_err_t ozayn_rcm_resource_update_health(ozayn_rcm_service_t *svc,
                                                  const char *resource_id,
                                                  ozayn_rcm_resource_health_t health)
{
    if (!svc) return OZAYN_RCM_ERR_NULL;
    if (!svc->initialized) return OZAYN_RCM_ERR_NOT_INITIALIZED;
    if (!resource_id || resource_id[0] == '\0')
        return OZAYN_RCM_ERR_INVALID_PARAM;
    if (health < 0 || health >= OZAYN_RCM_HEALTH_COUNT)
        return OZAYN_RCM_ERR_INVALID_PARAM;

    int idx = _find_resource(svc, resource_id);
    if (idx < 0) return OZAYN_RCM_ERR_NOT_FOUND;

    svc->resources[idx].health = health;
    svc->resources[idx].last_update = time(NULL);
    return OZAYN_RCM_OK;
}

ozayn_rcm_err_t ozayn_rcm_resource_update_availability(ozayn_rcm_service_t *svc,
                                                        const char *resource_id,
                                                        ozayn_rcm_availability_t avail)
{
    if (!svc) return OZAYN_RCM_ERR_NULL;
    if (!svc->initialized) return OZAYN_RCM_ERR_NOT_INITIALIZED;
    if (!resource_id || resource_id[0] == '\0')
        return OZAYN_RCM_ERR_INVALID_PARAM;
    if (avail < 0 || avail >= OZAYN_RCM_AVAIL_COUNT)
        return OZAYN_RCM_ERR_INVALID_PARAM;

    int idx = _find_resource(svc, resource_id);
    if (idx < 0) return OZAYN_RCM_ERR_NOT_FOUND;

    svc->resources[idx].availability = avail;
    svc->resources[idx].last_update = time(NULL);
    return OZAYN_RCM_OK;
}

/* ============================================================
 * SECTION 6 — CAPACITY ASSESSMENT
 * ============================================================ */

ozayn_rcm_err_t ozayn_rcm_capacity_get(const ozayn_rcm_service_t *svc,
                                        const char *resource_id,
                                        ozayn_rcm_capacity_t *out_capacity)
{
    if (!svc) return OZAYN_RCM_ERR_NULL;
    if (!svc->initialized) return OZAYN_RCM_ERR_NOT_INITIALIZED;
    if (!resource_id || resource_id[0] == '\0')
        return OZAYN_RCM_ERR_INVALID_PARAM;
    if (!out_capacity) return OZAYN_RCM_ERR_NULL;

    int idx = _find_resource(svc, resource_id);
    if (idx < 0) return OZAYN_RCM_ERR_NOT_FOUND;

    *out_capacity = svc->resources[idx].capacity;
    return OZAYN_RCM_OK;
}

ozayn_rcm_err_t ozayn_rcm_capacity_check(const ozayn_rcm_service_t *svc,
                                          const char *resource_id,
                                          uint64_t required,
                                          int *sufficient)
{
    if (!svc) return OZAYN_RCM_ERR_NULL;
    if (!svc->initialized) return OZAYN_RCM_ERR_NOT_INITIALIZED;
    if (!resource_id || resource_id[0] == '\0')
        return OZAYN_RCM_ERR_INVALID_PARAM;
    if (!sufficient) return OZAYN_RCM_ERR_NULL;

    int idx = _find_resource(svc, resource_id);
    if (idx < 0) return OZAYN_RCM_ERR_NOT_FOUND;

    const ozayn_rcm_resource_desc_t *res = &svc->resources[idx];
    if (res->state == OZAYN_RCM_STATE_UNAVAILABLE ||
        res->state == OZAYN_RCM_STATE_UNSUPPORTED ||
        res->state == OZAYN_RCM_STATE_ERROR) {
        *sufficient = 0;
        return OZAYN_RCM_OK;
    }

    *sufficient = res->capacity.available >= required;
    return OZAYN_RCM_OK;
}

ozayn_rcm_err_t ozayn_rcm_capacity_check_all(
    const ozayn_rcm_service_t *svc,
    const ozayn_rcm_resource_requirement_t *reqs,
    int req_count,
    int *all_met)
{
    if (!svc) return OZAYN_RCM_ERR_NULL;
    if (!svc->initialized) return OZAYN_RCM_ERR_NOT_INITIALIZED;
    if (!reqs || req_count <= 0) return OZAYN_RCM_ERR_INVALID_PARAM;
    if (!all_met) return OZAYN_RCM_ERR_NULL;

    *all_met = 1;
    for (int i = 0; i < req_count; i++) {
        if (reqs[i].resource_id[0] != '\0') {
            int sufficient = 0;
            ozayn_rcm_err_t rc = ozayn_rcm_capacity_check(svc,
                reqs[i].resource_id, reqs[i].min_capacity, &sufficient);
            if (rc != OZAYN_RCM_OK || !sufficient) {
                *all_met = 0;
                return OZAYN_RCM_OK;
            }
        }
    }
    return OZAYN_RCM_OK;
}

/* ============================================================
 * SECTION 7 — RESOURCE REQUIREMENTS & DECISIONS
 * ============================================================ */

ozayn_rcm_err_t ozayn_rcm_requirement_create(ozayn_rcm_service_t *svc,
                                              ozayn_rcm_resource_type_t type,
                                              const char *resource_id,
                                              uint64_t min_capacity,
                                              uint64_t max_usage,
                                              ozayn_rcm_availability_t required_avail,
                                              int reservation_required,
                                              ozayn_rcm_priority_t priority,
                                              int timeout_ms,
                                              ozayn_rcm_resource_requirement_t **out_req)
{
    if (!svc) return OZAYN_RCM_ERR_NULL;
    if (!svc->initialized) return OZAYN_RCM_ERR_NOT_INITIALIZED;
    if (type < 0 || type >= OZAYN_RCM_RES_TYPE_COUNT)
        return OZAYN_RCM_ERR_INVALID_PARAM;
    if (priority < 0 || priority >= OZAYN_RCM_PRIORITY_COUNT)
        return OZAYN_RCM_ERR_INVALID_PARAM;
    if (!out_req) return OZAYN_RCM_ERR_NULL;

    static ozayn_rcm_resource_requirement_t _req_pool[OZAYN_RCM_MAX_REQUIREMENTS];
    static int _req_count = 0;

    if (_req_count >= OZAYN_RCM_MAX_REQUIREMENTS)
        return OZAYN_RCM_ERR_LIMIT_REACHED;

    ozayn_rcm_resource_requirement_t *req = &_req_pool[_req_count];
    memset(req, 0, sizeof(*req));

    svc->requirement_sequence++;
    snprintf(req->requirement_id, OZAYN_RCM_MAX_ID_LEN, "RCQ-%u",
             svc->requirement_sequence);
    req->resource_type = type;
    if (resource_id) strncpy(req->resource_id, resource_id, OZAYN_RCM_MAX_ID_LEN - 1);
    req->min_capacity = min_capacity;
    req->max_usage = max_usage;
    req->required_availability = required_avail;
    req->reservation_required = reservation_required;
    req->priority = priority;
    req->timeout_ms = timeout_ms > 0 ? timeout_ms : 30000;

    _req_count++;
    *out_req = req;
    return OZAYN_RCM_OK;
}

static void _create_decision(ozayn_rcm_service_t *svc,
                              const char *operation_id,
                              ozayn_rcm_decision_result_t decision,
                              ozayn_rcm_resource_decision_t *dec)
{
    memset(dec, 0, sizeof(*dec));
    svc->decision_sequence++;
    snprintf(dec->decision_id, OZAYN_RCM_MAX_ID_LEN, "RCD-%u",
             svc->decision_sequence);
    if (operation_id) strncpy(dec->operation_id, operation_id, OZAYN_RCM_MAX_ID_LEN - 1);
    dec->decision = decision;
    dec->evaluation_time = time(NULL);
    dec->active = 1;
}

ozayn_rcm_err_t ozayn_rcm_evaluate(ozayn_rcm_service_t *svc,
                                    const char *operation_id,
                                    const ozayn_rcm_resource_requirement_t *reqs,
                                    int req_count,
                                    ozayn_rcm_resource_decision_t **out_decision)
{
    if (!svc) return OZAYN_RCM_ERR_NULL;
    if (!svc->initialized) return OZAYN_RCM_ERR_NOT_INITIALIZED;
    if (!reqs || req_count <= 0) return OZAYN_RCM_ERR_INVALID_PARAM;
    if (!out_decision) return OZAYN_RCM_ERR_NULL;

    if (svc->decision_count >= svc->max_decisions)
        return OZAYN_RCM_ERR_LIMIT_REACHED;

    svc->stats.total_decisions++;

    ozayn_rcm_resource_decision_t *dec = &svc->decisions[
        (svc->decision_head + svc->decision_count) % svc->max_decisions];
    _create_decision(svc, operation_id, OZAYN_RCM_DECISION_AVAILABLE, dec);

    int all_met = 1;
    int idx = 0;
    for (int i = 0; i < req_count && i < OZAYN_RCM_MAX_REQUIREMENTS; i++) {
        dec->requirement_count++;

        const ozayn_rcm_resource_desc_t *res = NULL;
        if (reqs[i].resource_id[0] != '\0') {
            res = ozayn_rcm_resource_get(svc, reqs[i].resource_id);
        } else {
            res = ozayn_rcm_resource_get_by_type(svc, reqs[i].resource_type);
        }

        if (!res) {
            dec->decision = OZAYN_RCM_DECISION_UNKNOWN;
            if (idx < OZAYN_RCM_MAX_FAILED_REQS) {
                strncpy(dec->failed_requirements[idx],
                        reqs[i].requirement_id, OZAYN_RCM_MAX_ID_LEN - 1);
                idx++;
            }
            dec->failed_requirement_count = idx;
            all_met = 0;
            continue;
        }

        strncpy(dec->resource_refs[dec->resource_ref_count], res->resource_id,
                OZAYN_RCM_MAX_ID_LEN - 1);
        dec->min_capacities[dec->resource_ref_count] = reqs[i].min_capacity;
        dec->resource_ref_count++;

        if (res->state == OZAYN_RCM_STATE_UNAVAILABLE ||
            res->state == OZAYN_RCM_STATE_UNSUPPORTED) {
            dec->decision = OZAYN_RCM_DECISION_UNAVAILABLE;
            if (idx < OZAYN_RCM_MAX_FAILED_REQS) {
                strncpy(dec->failed_requirements[idx],
                        reqs[i].requirement_id, OZAYN_RCM_MAX_ID_LEN - 1);
                idx++;
            }
            all_met = 0;
            continue;
        }

        if (reqs[i].min_capacity > 0 && res->capacity.available < reqs[i].min_capacity) {
            dec->decision = OZAYN_RCM_DECISION_INSUFFICIENT;
            if (idx < OZAYN_RCM_MAX_FAILED_REQS) {
                strncpy(dec->failed_requirements[idx],
                        reqs[i].requirement_id, OZAYN_RCM_MAX_ID_LEN - 1);
                idx++;
            }
            all_met = 0;
        }

        if (reqs[i].required_availability != OZAYN_RCM_AVAIL_UNKNOWN &&
            res->availability != reqs[i].required_availability) {
            dec->decision = OZAYN_RCM_DECISION_INSUFFICIENT;
            if (idx < OZAYN_RCM_MAX_FAILED_REQS) {
                strncpy(dec->failed_requirements[idx],
                        reqs[i].requirement_id, OZAYN_RCM_MAX_ID_LEN - 1);
                idx++;
            }
            all_met = 0;
        }

        if (reqs[i].reservation_required) {
            if (_check_reservations_conflict(svc, res->resource_id, operation_id)) {
                dec->decision = OZAYN_RCM_DECISION_CONFLICT;
                if (idx < OZAYN_RCM_MAX_FAILED_REQS) {
                    strncpy(dec->failed_requirements[idx],
                            reqs[i].requirement_id, OZAYN_RCM_MAX_ID_LEN - 1);
                    idx++;
                }
                all_met = 0;
            }
        }

        if (dec->capacity_observed.total == 0) {
            dec->capacity_observed = res->capacity;
        }
    }

    if (all_met) {
        dec->decision = OZAYN_RCM_DECISION_AVAILABLE;
        svc->stats.total_available++;
    } else {
        if (dec->decision == OZAYN_RCM_DECISION_AVAILABLE)
            dec->decision = OZAYN_RCM_DECISION_INSUFFICIENT;
        switch (dec->decision) {
        case OZAYN_RCM_DECISION_INSUFFICIENT: svc->stats.total_insufficient++; break;
        case OZAYN_RCM_DECISION_UNAVAILABLE: svc->stats.total_unavailable++; break;
        case OZAYN_RCM_DECISION_UNKNOWN: svc->stats.total_unknown++; break;
        case OZAYN_RCM_DECISION_CONFLICT:
        case OZAYN_RCM_DECISION_RESERVED: svc->stats.total_insufficient++; break;
        default: break;
        }
    }

    dec->failed_requirement_count = idx;
    svc->decision_count++;
    svc->stats.current_active_decisions++;

    if (req_count > 0 && reqs[0].timeout_ms > 0) {
        dec->expiry_time = dec->evaluation_time + (reqs[0].timeout_ms / 1000);
    } else {
        dec->expiry_time = dec->evaluation_time + (svc->reservation_ttl_ms / 1000);
    }

    *out_decision = dec;
    return OZAYN_RCM_OK;
}

const ozayn_rcm_resource_decision_t *ozayn_rcm_decision_get(
    const ozayn_rcm_service_t *svc,
    const char *decision_id)
{
    if (!svc || !decision_id) return NULL;
    int idx = _find_decision(svc, decision_id);
    if (idx < 0) return NULL;
    return &svc->decisions[idx];
}

const ozayn_rcm_resource_decision_t *ozayn_rcm_decision_get_by_operation(
    const ozayn_rcm_service_t *svc,
    const char *operation_id)
{
    if (!svc || !operation_id) return NULL;
    for (int i = 0; i < svc->decision_count; i++) {
        int idx = (svc->decision_head + i) % svc->max_decisions;
        if (svc->decisions[idx].active &&
            strcmp(svc->decisions[idx].operation_id, operation_id) == 0)
            return &svc->decisions[idx];
    }
    return NULL;
}

int ozayn_rcm_decision_count(const ozayn_rcm_service_t *svc)
{
    if (!svc) return 0;
    return svc->decision_count;
}

int ozayn_rcm_decision_is_valid(const ozayn_rcm_service_t *svc,
                                 const char *decision_id)
{
    if (!svc || !decision_id) return 0;
    int idx = _find_decision(svc, decision_id);
    if (idx < 0) return 0;
    if (!svc->decisions[idx].active) return 0;
    time_t now = time(NULL);
    if (svc->decisions[idx].expiry_time > 0 && now > svc->decisions[idx].expiry_time)
        return 0;
    return 1;
}

/* ============================================================
 * SECTION 8 — RESOURCE RECHECK
 * ============================================================ */

ozayn_rcm_err_t ozayn_rcm_recheck(ozayn_rcm_service_t *svc,
                                   const char *decision_id)
{
    if (!svc) return OZAYN_RCM_ERR_NULL;
    if (!svc->initialized) return OZAYN_RCM_ERR_NOT_INITIALIZED;
    if (!decision_id || decision_id[0] == '\0')
        return OZAYN_RCM_ERR_INVALID_PARAM;

    int idx = _find_decision(svc, decision_id);
    if (idx < 0) return OZAYN_RCM_ERR_RESERVATION_NOT_FOUND;

    ozayn_rcm_resource_decision_t *dec = &svc->decisions[idx];

    time_t now = time(NULL);
    if (dec->expiry_time > 0 && now > dec->expiry_time) {
        dec->active = 0;
        svc->stats.current_active_decisions--;
        return OZAYN_RCM_ERR_RESERVATION_EXPIRED;
    }

    svc->stats.total_rechecks++;

    int still_met = 1;
    for (int i = 0; i < dec->resource_ref_count; i++) {
        const ozayn_rcm_resource_desc_t *res = ozayn_rcm_resource_get(svc,
            dec->resource_refs[i]);

        if (!res) {
            still_met = 0;
            break;
        }

        if (res->state == OZAYN_RCM_STATE_UNAVAILABLE ||
            res->state == OZAYN_RCM_STATE_UNSUPPORTED) {
            still_met = 0;
            break;
        }

        if (res->capacity.available < dec->min_capacities[i]) {
            still_met = 0;
            break;
        }
    }

    if (!still_met) {
        dec->decision = OZAYN_RCM_DECISION_INSUFFICIENT;
    } else {
        dec->decision = OZAYN_RCM_DECISION_AVAILABLE;
    }

    return OZAYN_RCM_OK;
}

/* ============================================================
 * SECTION 9 — RESERVATIONS
 * ============================================================ */

ozayn_rcm_err_t ozayn_rcm_reservation_create(ozayn_rcm_service_t *svc,
                                              const char *operation_id,
                                              const char *resource_id,
                                              ozayn_rcm_resource_type_t type,
                                              uint64_t requested_capacity,
                                              ozayn_rcm_reservation_t **out_reservation)
{
    if (!svc) return OZAYN_RCM_ERR_NULL;
    if (!svc->initialized) return OZAYN_RCM_ERR_NOT_INITIALIZED;
    if (!operation_id || operation_id[0] == '\0')
        return OZAYN_RCM_ERR_INVALID_PARAM;
    if (!resource_id || resource_id[0] == '\0')
        return OZAYN_RCM_ERR_INVALID_PARAM;
    if (type < 0 || type >= OZAYN_RCM_RES_TYPE_COUNT)
        return OZAYN_RCM_ERR_INVALID_PARAM;
    if (!out_reservation) return OZAYN_RCM_ERR_NULL;
    if (svc->reservation_count >= svc->max_reservations)
        return OZAYN_RCM_ERR_LIMIT_REACHED_RES;

    int res_idx = _find_resource(svc, resource_id);
    if (res_idx < 0) return OZAYN_RCM_ERR_NOT_FOUND;

    ozayn_rcm_resource_desc_t *res = &svc->resources[res_idx];
    if (res->capacity.available < requested_capacity)
        return OZAYN_RCM_ERR_RESERVATION_FAILED;

    for (int i = 0; i < svc->reservation_count; i++) {
        if (svc->reservations[i].active &&
            svc->reservations[i].state != OZAYN_RCM_RESERV_RELEASED &&
            svc->reservations[i].state != OZAYN_RCM_RESERV_CANCELLED &&
            svc->reservations[i].state != OZAYN_RCM_RESERV_EXPIRED &&
            svc->reservations[i].state != OZAYN_RCM_RESERV_FAILED &&
            strcmp(svc->reservations[i].operation_id, operation_id) == 0 &&
            strcmp(svc->reservations[i].resource_id, resource_id) == 0)
            return OZAYN_RCM_ERR_DUPLICATE;
    }

    res->capacity.reserved += requested_capacity;
    _compute_capacity(res);

    int idx = svc->reservation_count;
    ozayn_rcm_reservation_t *resv = &svc->reservations[idx];
    memset(resv, 0, sizeof(*resv));

    svc->reservation_sequence++;
    snprintf(resv->reservation_id, OZAYN_RCM_MAX_ID_LEN, "RCV-%u",
             svc->reservation_sequence);
    strncpy(resv->operation_id, operation_id, OZAYN_RCM_MAX_ID_LEN - 1);
    strncpy(resv->resource_id, resource_id, OZAYN_RCM_MAX_ID_LEN - 1);
    resv->resource_type = type;
    resv->requested_capacity = requested_capacity;
    resv->reserved_capacity = requested_capacity;
    resv->created_time = time(NULL);
    resv->expiry_time = resv->created_time + (svc->reservation_ttl_ms / 1000);
    resv->state = OZAYN_RCM_RESERV_RESERVED;
    resv->active = 1;

    svc->reservation_count++;
    svc->stats.total_reservations_created++;
    svc->stats.current_active_reservations++;

    _emit_event(svc, OZAYN_RCM_EVENT_RESERVATION_CREATED,
                resv->reservation_id, resource_id);

    *out_reservation = resv;
    return OZAYN_RCM_OK;
}

ozayn_rcm_err_t ozayn_rcm_reservation_activate(ozayn_rcm_service_t *svc,
                                                 const char *reservation_id)
{
    if (!svc) return OZAYN_RCM_ERR_NULL;
    if (!svc->initialized) return OZAYN_RCM_ERR_NOT_INITIALIZED;
    if (!reservation_id || reservation_id[0] == '\0')
        return OZAYN_RCM_ERR_INVALID_PARAM;

    int idx = _find_reservation(svc, reservation_id);
    if (idx < 0) return OZAYN_RCM_ERR_RESERVATION_NOT_FOUND;

    ozayn_rcm_reservation_t *resv = &svc->reservations[idx];
    if (resv->state != OZAYN_RCM_RESERV_RESERVED)
        return OZAYN_RCM_ERR_RESERVATION_FAILED;

    resv->state = OZAYN_RCM_RESERV_ACTIVE;

    _emit_event(svc, OZAYN_RCM_EVENT_RESERVATION_RESERVED,
                reservation_id, "activated");
    return OZAYN_RCM_OK;
}

ozayn_rcm_err_t ozayn_rcm_reservation_release(ozayn_rcm_service_t *svc,
                                               const char *reservation_id)
{
    if (!svc) return OZAYN_RCM_ERR_NULL;
    if (!svc->initialized) return OZAYN_RCM_ERR_NOT_INITIALIZED;
    if (!reservation_id || reservation_id[0] == '\0')
        return OZAYN_RCM_ERR_INVALID_PARAM;

    int idx = _find_reservation(svc, reservation_id);
    if (idx < 0) return OZAYN_RCM_ERR_RESERVATION_NOT_FOUND;

    ozayn_rcm_reservation_t *resv = &svc->reservations[idx];
    if (resv->state == OZAYN_RCM_RESERV_RELEASED ||
        resv->state == OZAYN_RCM_RESERV_CANCELLED ||
        resv->state == OZAYN_RCM_RESERV_EXPIRED ||
        resv->state == OZAYN_RCM_RESERV_FAILED)
        return OZAYN_RCM_ERR_RESERVATION_FAILED;

    int res_idx = _find_resource(svc, resv->resource_id);
    if (res_idx >= 0) {
        ozayn_rcm_resource_desc_t *res = &svc->resources[res_idx];
        if (res->capacity.reserved >= resv->reserved_capacity) {
            res->capacity.reserved -= resv->reserved_capacity;
        } else {
            res->capacity.reserved = 0;
        }
        _compute_capacity(res);
    }

    resv->state = OZAYN_RCM_RESERV_RELEASED;
    svc->stats.total_reservations_released++;
    svc->stats.current_active_reservations--;

    _emit_event(svc, OZAYN_RCM_EVENT_RESERVATION_RELEASED,
                reservation_id, "released");
    return OZAYN_RCM_OK;
}

ozayn_rcm_err_t ozayn_rcm_reservation_cancel(ozayn_rcm_service_t *svc,
                                              const char *reservation_id)
{
    if (!svc) return OZAYN_RCM_ERR_NULL;
    if (!svc->initialized) return OZAYN_RCM_ERR_NOT_INITIALIZED;
    if (!reservation_id || reservation_id[0] == '\0')
        return OZAYN_RCM_ERR_INVALID_PARAM;

    int idx = _find_reservation(svc, reservation_id);
    if (idx < 0) return OZAYN_RCM_ERR_RESERVATION_NOT_FOUND;

    ozayn_rcm_reservation_t *resv = &svc->reservations[idx];
    if (resv->state == OZAYN_RCM_RESERV_RELEASED ||
        resv->state == OZAYN_RCM_RESERV_CANCELLED ||
        resv->state == OZAYN_RCM_RESERV_EXPIRED ||
        resv->state == OZAYN_RCM_RESERV_FAILED)
        return OZAYN_RCM_ERR_RESERVATION_FAILED;

    int res_idx = _find_resource(svc, resv->resource_id);
    if (res_idx >= 0) {
        ozayn_rcm_resource_desc_t *res = &svc->resources[res_idx];
        if (res->capacity.reserved >= resv->reserved_capacity) {
            res->capacity.reserved -= resv->reserved_capacity;
        } else {
            res->capacity.reserved = 0;
        }
        _compute_capacity(res);
    }

    resv->state = OZAYN_RCM_RESERV_CANCELLED;
    svc->stats.current_active_reservations--;

    _emit_event(svc, OZAYN_RCM_EVENT_RESERVATION_RELEASED,
                reservation_id, "cancelled");
    return OZAYN_RCM_OK;
}

const ozayn_rcm_reservation_t *ozayn_rcm_reservation_get(
    const ozayn_rcm_service_t *svc,
    const char *reservation_id)
{
    if (!svc || !reservation_id) return NULL;
    int idx = _find_reservation(svc, reservation_id);
    if (idx < 0) return NULL;
    return &svc->reservations[idx];
}

int ozayn_rcm_reservation_count(const ozayn_rcm_service_t *svc)
{
    if (!svc) return 0;
    return svc->reservation_count;
}

int ozayn_rcm_reservation_count_by_resource(const ozayn_rcm_service_t *svc,
                                             const char *resource_id)
{
    if (!svc || !resource_id) return 0;
    int count = 0;
    for (int i = 0; i < svc->reservation_count; i++) {
        if (svc->reservations[i].active &&
            svc->reservations[i].state != OZAYN_RCM_RESERV_RELEASED &&
            svc->reservations[i].state != OZAYN_RCM_RESERV_CANCELLED &&
            svc->reservations[i].state != OZAYN_RCM_RESERV_EXPIRED &&
            svc->reservations[i].state != OZAYN_RCM_RESERV_FAILED &&
            strcmp(svc->reservations[i].resource_id, resource_id) == 0)
            count++;
    }
    return count;
}

/* ============================================================
 * SECTION 10 — SNAPSHOTS
 * ============================================================ */

ozayn_rcm_err_t ozayn_rcm_snapshot_create(ozayn_rcm_service_t *svc,
                                           ozayn_rcm_snapshot_t **out_snapshot)
{
    if (!svc) return OZAYN_RCM_ERR_NULL;
    if (!svc->initialized) return OZAYN_RCM_ERR_NOT_INITIALIZED;
    if (!out_snapshot) return OZAYN_RCM_ERR_NULL;
    if (svc->snapshot_count >= OZAYN_RCM_MAX_SNAPSHOTS)
        return OZAYN_RCM_ERR_LIMIT_REACHED;

    int idx = svc->snapshot_count;
    ozayn_rcm_snapshot_t *snap = &svc->snapshots[idx];
    memset(snap, 0, sizeof(*snap));

    svc->snapshot_sequence++;
    snprintf(snap->snapshot_id, OZAYN_RCM_MAX_ID_LEN, "RCS-%u",
             svc->snapshot_sequence);
    snap->version = 1;
    snap->timestamp = time(NULL);
    snap->resource_count = svc->resource_count;

    int res_count = 0;
    for (int i = 0; i < svc->resource_count && res_count < OZAYN_RCM_MAX_RESOURCES; i++) {
        if (svc->resources[i].active) {
            strncpy(snap->resource_ids[res_count], svc->resources[i].resource_id,
                    OZAYN_RCM_MAX_ID_LEN - 1);
            snap->resource_ids[res_count][OZAYN_RCM_MAX_ID_LEN - 1] = '\0';
            res_count++;
        }
    }
    snap->resource_count = res_count;

    snap->overall_state = OZAYN_RCM_STATE_UNKNOWN;
    memset(&snap->summary, 0, sizeof(snap->summary));
    int has_unavailable = 0;
    int has_degraded = 0;
    for (int i = 0; i < svc->resource_count && i < res_count; i++) {
        if (!svc->resources[i].active) continue;
        snap->summary.total += svc->resources[i].capacity.total;
        snap->summary.used += svc->resources[i].capacity.used;
        snap->summary.reserved += svc->resources[i].capacity.reserved;
        snap->summary.available += svc->resources[i].capacity.available;
        if (svc->resources[i].state == OZAYN_RCM_STATE_UNAVAILABLE ||
            svc->resources[i].state == OZAYN_RCM_STATE_ERROR)
            has_unavailable = 1;
        if (svc->resources[i].state == OZAYN_RCM_STATE_DEGRADED ||
            svc->resources[i].state == OZAYN_RCM_STATE_BUSY)
            has_degraded = 1;
    }

    if (has_unavailable)
        snap->overall_state = OZAYN_RCM_STATE_DEGRADED;
    else if (has_degraded)
        snap->overall_state = OZAYN_RCM_STATE_BUSY;
    else if (res_count > 0)
        snap->overall_state = OZAYN_RCM_STATE_AVAILABLE;
    else
        snap->overall_state = OZAYN_RCM_STATE_UNKNOWN;

    svc->stats.total_snapshots++;
    svc->snapshot_count++;

    *out_snapshot = snap;
    return OZAYN_RCM_OK;
}

const ozayn_rcm_snapshot_t *ozayn_rcm_snapshot_get(
    const ozayn_rcm_service_t *svc,
    const char *snapshot_id)
{
    if (!svc || !snapshot_id) return NULL;
    int idx = _find_snapshot(svc, snapshot_id);
    if (idx < 0) return NULL;
    return &svc->snapshots[idx];
}

int ozayn_rcm_snapshot_count(const ozayn_rcm_service_t *svc)
{
    if (!svc) return 0;
    return svc->snapshot_count;
}

/* ============================================================
 * SECTION 11 — CLEANUP
 * ============================================================ */

int ozayn_rcm_cleanup_expired_reservations(ozayn_rcm_service_t *svc)
{
    if (!svc) return 0;
    int cleaned = 0;
    time_t now = time(NULL);
    for (int i = 0; i < svc->reservation_count; i++) {
        if (!svc->reservations[i].active) continue;
        if (svc->reservations[i].state == OZAYN_RCM_RESERV_RELEASED ||
            svc->reservations[i].state == OZAYN_RCM_RESERV_CANCELLED)
            continue;
        if (svc->reservations[i].expiry_time > 0 &&
            now > svc->reservations[i].expiry_time) {
            int res_idx = _find_resource(svc, svc->reservations[i].resource_id);
            if (res_idx >= 0) {
                ozayn_rcm_resource_desc_t *res = &svc->resources[res_idx];
                if (res->capacity.reserved >= svc->reservations[i].reserved_capacity)
                    res->capacity.reserved -= svc->reservations[i].reserved_capacity;
                else
                    res->capacity.reserved = 0;
                _compute_capacity(res);
            }
            svc->reservations[i].state = OZAYN_RCM_RESERV_EXPIRED;
            svc->reservations[i].active = 0;
            svc->stats.total_reservations_expired++;
            svc->stats.current_active_reservations--;
            cleaned++;
            _emit_event(svc, OZAYN_RCM_EVENT_RESERVATION_EXPIRED,
                        svc->reservations[i].reservation_id, "expired");
        }
    }
    svc->reservation_count -= cleaned;
    return cleaned;
}

int ozayn_rcm_cleanup_expired_decisions(ozayn_rcm_service_t *svc)
{
    if (!svc) return 0;
    int cleaned = 0;
    time_t now = time(NULL);
    for (int i = 0; i < svc->decision_count; i++) {
        int idx = (svc->decision_head + i) % svc->max_decisions;
        if (svc->decisions[idx].active) {
            if (svc->decisions[idx].expiry_time > 0 &&
                now > svc->decisions[idx].expiry_time) {
                svc->decisions[idx].active = 0;
                svc->stats.current_active_decisions--;
                cleaned++;
            }
        }
    }
    svc->decision_count -= cleaned;
    return cleaned;
}

int ozayn_rcm_cleanup_all(ozayn_rcm_service_t *svc)
{
    if (!svc) return 0;
    int cleaned = 0;
    cleaned += ozayn_rcm_cleanup_expired_reservations(svc);
    cleaned += ozayn_rcm_cleanup_expired_decisions(svc);
    for (int i = 0; i < svc->snapshot_count; i++) {
        memset(&svc->snapshots[i], 0, sizeof(svc->snapshots[i]));
    }
    svc->snapshot_count = 0;
    cleaned++;
    return cleaned;
}

/* ============================================================
 * SECTION 12 — STATISTICS
 * ============================================================ */

ozayn_rcm_err_t ozayn_rcm_get_stats(const ozayn_rcm_service_t *svc,
                                     ozayn_rcm_stats_t *out_stats)
{
    if (!svc) return OZAYN_RCM_ERR_NULL;
    if (!out_stats) return OZAYN_RCM_ERR_NULL;
    if (!svc->initialized) return OZAYN_RCM_ERR_NOT_INITIALIZED;
    *out_stats = svc->stats;
    return OZAYN_RCM_OK;
}

/* ============================================================
 * SECTION 13 — VALIDATION
 * ============================================================ */

int ozayn_rcm_resource_validate(const ozayn_rcm_resource_desc_t *res)
{
    if (!res) return 0;
    if (res->resource_id[0] == '\0') return 0;
    if (res->type < 0 || res->type >= OZAYN_RCM_RES_TYPE_COUNT) return 0;
    if (res->state < 0 || res->state >= OZAYN_RCM_STATE_COUNT) return 0;
    if (res->health < 0 || res->health >= OZAYN_RCM_HEALTH_COUNT) return 0;
    if (res->availability < 0 || res->availability >= OZAYN_RCM_AVAIL_COUNT) return 0;
    return 1;
}

int ozayn_rcm_capacity_validate(const ozayn_rcm_capacity_t *cap)
{
    if (!cap) return 0;
    if (cap->used > cap->total) return 0;
    if (cap->reserved > cap->total) return 0;
    if (cap->used + cap->reserved > cap->total) return 0;
    return 1;
}

int ozayn_rcm_decision_validate(const ozayn_rcm_resource_decision_t *d)
{
    if (!d) return 0;
    if (d->decision_id[0] == '\0') return 0;
    if (d->decision < 0 || d->decision >= OZAYN_RCM_DECISION_COUNT) return 0;
    return 1;
}

int ozayn_rcm_reservation_validate(const ozayn_rcm_reservation_t *res)
{
    if (!res) return 0;
    if (res->reservation_id[0] == '\0') return 0;
    if (res->state < 0 || res->state >= OZAYN_RCM_RESERV_COUNT) return 0;
    return 1;
}

int ozayn_rcm_requirement_validate(const ozayn_rcm_resource_requirement_t *req)
{
    if (!req) return 0;
    if (req->requirement_id[0] == '\0') return 0;
    if (req->resource_type < 0 || req->resource_type >= OZAYN_RCM_RES_TYPE_COUNT)
        return 0;
    return 1;
}
