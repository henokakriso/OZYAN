#include "io_router.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

/* ============================================================
 * SECTION 1 — INTERNAL HELPERS
 * ============================================================ */

static ozayn_ior_service_t _svc;

static int _find_route(const ozayn_ior_service_t *svc,
                        const char *route_id)
{
    if (!svc || !route_id) return -1;
    for (int i = 0; i < svc->config.max_routes; i++) {
        if (svc->routes[i].active &&
            strncmp(svc->routes[i].route_id, route_id,
                    OZAYN_IOR_MAX_ID_LEN) == 0)
            return i;
    }
    return -1;
}

static int _find_route_slot(const ozayn_ior_service_t *svc)
{
    for (int i = 0; i < svc->config.max_routes; i++) {
        if (!svc->routes[i].active) return i;
    }
    return -1;
}

static int _find_route_any(const ozayn_ior_service_t *svc,
                            const char *route_id)
{
    if (!svc || !route_id) return -1;
    for (int i = 0; i < svc->config.max_routes; i++) {
        if (svc->routes[i].route_id[0] != '\0' &&
            strncmp(svc->routes[i].route_id, route_id,
                    OZAYN_IOR_MAX_ID_LEN) == 0)
            return i;
    }
    return -1;
}

static int _find_endpoint(const ozayn_ior_service_t *svc,
                           const char *endpoint_id)
{
    if (!svc || !endpoint_id) return -1;
    for (int i = 0; i < svc->config.max_endpoints; i++) {
        if (svc->endpoints[i].active &&
            strncmp(svc->endpoints[i].endpoint_id, endpoint_id,
                    OZAYN_IOR_MAX_ID_LEN) == 0)
            return i;
    }
    return -1;
}

static int _find_endpoint_slot(const ozayn_ior_service_t *svc)
{
    for (int i = 0; i < svc->config.max_endpoints; i++) {
        if (!svc->endpoints[i].active) return i;
    }
    return -1;
}

static void _emit_event(ozayn_ior_service_t *svc,
                          ozayn_ior_event_type_t type,
                          const char *route_id,
                          const char *stream_id,
                          const char *source_id,
                          const char *destination_id,
                          const char *message)
{
    if (!svc) return;
    int idx = (svc->event_head + svc->event_count) %
              OZAYN_IOR_MAX_EVENTS;
    if (svc->event_count >= OZAYN_IOR_MAX_EVENTS) {
        svc->event_head = (svc->event_head + 1) % OZAYN_IOR_MAX_EVENTS;
    } else {
        svc->event_count++;
    }
    svc->events[idx].type = type;
    strncpy(svc->events[idx].route_id, route_id ? route_id : "",
            OZAYN_IOR_MAX_ID_LEN - 1);
    svc->events[idx].route_id[OZAYN_IOR_MAX_ID_LEN - 1] = '\0';
    strncpy(svc->events[idx].stream_id, stream_id ? stream_id : "",
            OZAYN_IOR_MAX_ID_LEN - 1);
    svc->events[idx].stream_id[OZAYN_IOR_MAX_ID_LEN - 1] = '\0';
    strncpy(svc->events[idx].source_id, source_id ? source_id : "",
            OZAYN_IOR_MAX_ID_LEN - 1);
    svc->events[idx].source_id[OZAYN_IOR_MAX_ID_LEN - 1] = '\0';
    strncpy(svc->events[idx].destination_id, destination_id ? destination_id : "",
            OZAYN_IOR_MAX_ID_LEN - 1);
    svc->events[idx].destination_id[OZAYN_IOR_MAX_ID_LEN - 1] = '\0';
    strncpy(svc->events[idx].message, message ? message : "",
            OZAYN_IOR_MAX_DESCRIPTION_LEN - 1);
    svc->events[idx].message[OZAYN_IOR_MAX_DESCRIPTION_LEN - 1] = '\0';
    svc->events[idx].timestamp = time(NULL);
    svc->event_sequence++;
}

/* ============================================================
 * SECTION 2 — STATE MACHINE
 * ============================================================ */

static const int _valid_transitions[OZAYN_IOR_ROUTE_STATE_COUNT]
                                   [OZAYN_IOR_ROUTE_STATE_COUNT] = {
    /* REQUESTED -> */
    {   0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1 },
    /* VALIDATING -> */
    {   0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1 },
    /* AUTHORIZED -> */
    {   0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 1, 1, 1, 0 },
    /* WAITING -> */
    {   0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 1, 1, 1, 1 },
    /* CONNECTING -> */
    {   0, 0, 0, 0, 0, 1, 0, 0, 1, 0, 1, 1, 1, 1 },
    /* ACTIVE -> */
    {   0, 0, 0, 0, 0, 0, 1, 1, 1, 0, 1, 1, 1, 1 },
    /* PAUSED -> */
    {   0, 0, 0, 0, 0, 1, 0, 0, 1, 0, 1, 1, 1, 1 },
    /* BACKPRESSURED -> */
    {   0, 0, 0, 0, 0, 1, 1, 0, 1, 0, 1, 1, 1, 1 },
    /* DISCONNECTING -> */
    {   0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1 },
    /* CLOSED -> */
    {   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    /* FAILED -> */
    {   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    /* EXPIRED -> */
    {   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    /* REVOKED -> */
    {   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    /* UNAVAILABLE -> */
    {   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }
};

static int _transition(ozayn_ior_service_t *svc,
                        ozayn_ior_route_t *r,
                        ozayn_ior_route_state_t new_state)
{
    if (!_valid_transitions[r->state][new_state]) {
        svc->stats.total_validation_failures++;
        return 0;
    }
    r->state = new_state;
    svc->stats.total_state_transitions++;
    return 1;
}

static int _is_terminal(ozayn_ior_route_state_t state)
{
    return state == OZAYN_IOR_ROUTE_CLOSED ||
           state == OZAYN_IOR_ROUTE_FAILED ||
           state == OZAYN_IOR_ROUTE_EXPIRED ||
           state == OZAYN_IOR_ROUTE_REVOKED ||
           state == OZAYN_IOR_ROUTE_UNAVAILABLE;
}

static int _check_loop(const ozayn_ior_service_t *svc,
                        const char *source_id,
                        const char *destination_id,
                        int depth)
{
    if (depth <= 0) return 1;
    if (!source_id || !destination_id) return 0;
    if (strncmp(source_id, destination_id, OZAYN_IOR_MAX_ID_LEN) == 0)
        return 1;
    for (int i = 0; i < svc->config.max_routes; i++) {
        if (svc->routes[i].active &&
            strncmp(svc->routes[i].source_id, destination_id,
                    OZAYN_IOR_MAX_ID_LEN) == 0) {
            if (strncmp(svc->routes[i].destination_id, source_id,
                        OZAYN_IOR_MAX_ID_LEN) == 0)
                return 1;
            if (_check_loop(svc, source_id,
                            svc->routes[i].destination_id, depth - 1))
                return 1;
        }
    }
    return 0;
}

/* ============================================================
 * SECTION 3 — LIFECYCLE
 * ============================================================ */

ozayn_ior_err_t ozayn_ior_service_init(ozayn_ior_service_t *svc,
                                        const ozayn_ior_service_config_t *cfg)
{
    if (!svc) return OZAYN_IOR_ERR_NULL;
    if (!cfg) return OZAYN_IOR_ERR_NULL;
    if (svc->initialized) return OZAYN_IOR_ERR_ALREADY_INIT;

    memset(svc, 0, sizeof(*svc));
    svc->config = *cfg;

    if (svc->config.max_routes <= 0)
        svc->config.max_routes = OZAYN_IOR_MAX_ROUTES;
    if (svc->config.max_endpoints <= 0)
        svc->config.max_endpoints = OZAYN_IOR_MAX_ENDPOINTS;
    if (svc->config.route_ttl_ms <= 0)
        svc->config.route_ttl_ms = OZAYN_IOR_DEFAULT_ROUTE_TTL_MS;
    if (svc->config.idle_timeout_ms <= 0)
        svc->config.idle_timeout_ms = OZAYN_IOR_DEFAULT_IDLE_TIMEOUT_MS;
    if (svc->config.max_loop_depth <= 0)
        svc->config.max_loop_depth = OZAYN_IOR_MAX_LOOP_DEPTH;

    svc->initialized = 1;
    return OZAYN_IOR_OK;
}

void ozayn_ior_service_shutdown(ozayn_ior_service_t *svc)
{
    if (!svc) return;
    svc->initialized = 0;
}

int ozayn_ior_service_is_initialized(const ozayn_ior_service_t *svc)
{
    if (!svc) return 0;
    return svc->initialized;
}

ozayn_ior_service_t *ozayn_ior_get_global(void)
{
    return &_svc;
}

/* ============================================================
 * SECTION 4 — ENDPOINT REGISTRATION
 * ============================================================ */

ozayn_ior_err_t ozayn_ior_endpoint_register(ozayn_ior_service_t *svc,
                                             const ozayn_ior_endpoint_t *ep)
{
    if (!svc) return OZAYN_IOR_ERR_NULL;
    if (!svc->initialized) return OZAYN_IOR_ERR_NOT_INITIALIZED;
    if (!ep) return OZAYN_IOR_ERR_NULL;
    if (!ep->endpoint_id[0]) return OZAYN_IOR_ERR_INVALID_PARAM;
    if (ep->type < 0 || ep->type >= OZAYN_IOR_ENDPOINT_COUNT)
        return OZAYN_IOR_ERR_INVALID_PARAM;

    if (_find_endpoint(svc, ep->endpoint_id) >= 0)
        return OZAYN_IOR_ERR_INVALID_PARAM;

    int slot = _find_endpoint_slot(svc);
    if (slot < 0) return OZAYN_IOR_ERR_LIMIT_REACHED;

    memcpy(&svc->endpoints[slot], ep, sizeof(ozayn_ior_endpoint_t));
    svc->endpoints[slot].active = 1;
    svc->endpoints[slot].registered_time = time(NULL);
    svc->endpoint_count++;
    svc->stats.endpoints_registered++;
    return OZAYN_IOR_OK;
}

ozayn_ior_err_t ozayn_ior_endpoint_unregister(ozayn_ior_service_t *svc,
                                               const char *endpoint_id)
{
    if (!svc) return OZAYN_IOR_ERR_NULL;
    if (!svc->initialized) return OZAYN_IOR_ERR_NOT_INITIALIZED;
    if (!endpoint_id || endpoint_id[0] == '\0')
        return OZAYN_IOR_ERR_INVALID_PARAM;

    int idx = _find_endpoint(svc, endpoint_id);
    if (idx < 0) return OZAYN_IOR_ERR_NOT_FOUND;

    svc->endpoints[idx].active = 0;
    svc->endpoint_count--;
    return OZAYN_IOR_OK;
}

const ozayn_ior_endpoint_t *ozayn_ior_endpoint_get(
    const ozayn_ior_service_t *svc, const char *endpoint_id)
{
    if (!svc || !svc->initialized || !endpoint_id) return NULL;
    int idx = _find_endpoint(svc, endpoint_id);
    if (idx < 0) return NULL;
    return &svc->endpoints[idx];
}

int ozayn_ior_endpoint_count(const ozayn_ior_service_t *svc)
{
    if (!svc || !svc->initialized) return 0;
    return svc->endpoint_count;
}

int ozayn_ior_endpoint_is_available(const ozayn_ior_service_t *svc,
                                     const char *endpoint_id)
{
    if (!svc || !svc->initialized || !endpoint_id) return 0;
    int idx = _find_endpoint(svc, endpoint_id);
    if (idx < 0) return 0;
    return svc->endpoints[idx].available;
}

/* ============================================================
 * SECTION 5 — ROUTE CREATION
 * ============================================================ */

ozayn_ior_err_t ozayn_ior_route_create(ozayn_ior_service_t *svc,
                                        const ozayn_ior_route_request_t *req,
                                        ozayn_ior_route_t **out_route)
{
    if (!svc) return OZAYN_IOR_ERR_NULL;
    if (!svc->initialized) return OZAYN_IOR_ERR_NOT_INITIALIZED;
    if (!req) return OZAYN_IOR_ERR_NULL;
    if (!out_route) return OZAYN_IOR_ERR_NULL;

    if (!req->stream_id[0]) return OZAYN_IOR_ERR_INVALID_PARAM;
    if (!req->source_id[0]) return OZAYN_IOR_ERR_INVALID_PARAM;
    if (!req->destination_id[0]) return OZAYN_IOR_ERR_INVALID_PARAM;
    if (req->source_type < 0 || req->source_type >= OZAYN_IOR_ENDPOINT_COUNT)
        return OZAYN_IOR_ERR_INVALID_PARAM;
    if (req->destination_type < 0 ||
        req->destination_type >= OZAYN_IOR_ENDPOINT_COUNT)
        return OZAYN_IOR_ERR_INVALID_PARAM;
    if (req->mode < 0 || req->mode >= OZAYN_IOR_MODE_COUNT)
        return OZAYN_IOR_ERR_INVALID_PARAM;
    if (!req->requester_ref[0]) return OZAYN_IOR_ERR_INVALID_PARAM;

    if (strncmp(req->source_id, req->destination_id,
                OZAYN_IOR_MAX_ID_LEN) == 0)
        return OZAYN_IOR_ERR_LOOP_DETECTED;

    int slot = _find_route_slot(svc);
    if (slot < 0) return OZAYN_IOR_ERR_LIMIT_REACHED;

    svc->route_sequence++;
    ozayn_ior_route_t *r = &svc->routes[slot];
    memset(r, 0, sizeof(*r));

    snprintf(r->route_id, OZAYN_IOR_MAX_ID_LEN, "IOR-%u",
             svc->route_sequence);
    r->version = 1;
    strncpy(r->stream_id, req->stream_id, OZAYN_IOR_MAX_ID_LEN - 1);
    strncpy(r->source_id, req->source_id, OZAYN_IOR_MAX_ID_LEN - 1);
    r->source_type = req->source_type;
    strncpy(r->destination_id, req->destination_id, OZAYN_IOR_MAX_ID_LEN - 1);
    r->destination_type = req->destination_type;
    r->mode = req->mode;
    if (req->device_session_id[0])
        strncpy(r->device_session_id, req->device_session_id,
                OZAYN_IOR_MAX_ID_LEN - 1);
    strncpy(r->requester_ref, req->requester_ref, OZAYN_IOR_MAX_ID_LEN - 1);
    if (req->security_session_ref[0])
        strncpy(r->security_session_ref, req->security_session_ref,
                OZAYN_IOR_MAX_ID_LEN - 1);
    if (req->required_permission[0])
        strncpy(r->required_permission, req->required_permission,
                OZAYN_IOR_MAX_PERMISSION_LEN - 1);
    if (req->metadata[0])
        strncpy(r->metadata, req->metadata, OZAYN_IOR_MAX_METADATA_LEN - 1);

    r->state = OZAYN_IOR_ROUTE_REQUESTED;
    r->close_reason = OZAYN_IOR_CLOSE_NONE;
    r->created_time = time(NULL);
    r->expiry_time = r->created_time + (svc->config.route_ttl_ms / 1000);
    r->active = 1;

    svc->route_count++;
    svc->stats.total_routes_created++;
    svc->stats.current_active_routes++;

    _emit_event(svc, OZAYN_IOR_EVENT_ROUTE_REQUESTED, r->route_id,
                r->stream_id, r->source_id, r->destination_id,
                "Route requested");

    *out_route = r;
    return OZAYN_IOR_OK;
}

ozayn_ior_err_t ozayn_ior_route_authorize(ozayn_ior_service_t *svc,
                                           const char *route_id)
{
    if (!svc) return OZAYN_IOR_ERR_NULL;
    if (!svc->initialized) return OZAYN_IOR_ERR_NOT_INITIALIZED;
    if (!route_id || route_id[0] == '\0')
        return OZAYN_IOR_ERR_INVALID_PARAM;

    int idx = _find_route(svc, route_id);
    if (idx < 0) return OZAYN_IOR_ERR_NOT_FOUND;

    ozayn_ior_route_t *r = &svc->routes[idx];

    time_t now = time(NULL);
    if (r->expiry_time > 0 && now > r->expiry_time) {
        r->state = OZAYN_IOR_ROUTE_EXPIRED;
        r->close_reason = OZAYN_IOR_CLOSE_TIMEOUT;
        r->closed_time = now;
        r->active = 0;
        svc->route_count--;
        svc->stats.total_routes_expired++;
        svc->stats.current_active_routes--;
        _emit_event(svc, OZAYN_IOR_EVENT_ROUTE_EXPIRED, r->route_id,
                    r->stream_id, r->source_id, r->destination_id,
                    "Route expired during authorization");
        return OZAYN_IOR_ERR_EXPIRED;
    }

    if (!_transition(svc, r, OZAYN_IOR_ROUTE_VALIDATING)) {
        svc->stats.total_errors++;
        _emit_event(svc, OZAYN_IOR_EVENT_ROUTE_FAILED, r->route_id,
                    r->stream_id, r->source_id, r->destination_id,
                    "Invalid state for validation");
        return OZAYN_IOR_ERR_STATE_INVALID;
    }

    if (_find_endpoint(svc, r->source_id) < 0) {
        r->state = OZAYN_IOR_ROUTE_FAILED;
        r->close_reason = OZAYN_IOR_CLOSE_ENDPOINT_UNAVAILABLE;
        r->active = 0;
        svc->route_count--;
        svc->stats.total_routes_failed++;
        svc->stats.current_active_routes--;
        _emit_event(svc, OZAYN_IOR_EVENT_ROUTE_ENDPOINT_UNAVAILABLE,
                    r->route_id, r->stream_id, r->source_id,
                    r->destination_id, "Source endpoint not found");
        return OZAYN_IOR_ERR_SOURCE_NOT_FOUND;
    }

    if (_find_endpoint(svc, r->destination_id) < 0) {
        r->state = OZAYN_IOR_ROUTE_FAILED;
        r->close_reason = OZAYN_IOR_CLOSE_ENDPOINT_UNAVAILABLE;
        r->active = 0;
        svc->route_count--;
        svc->stats.total_routes_failed++;
        svc->stats.current_active_routes--;
        _emit_event(svc, OZAYN_IOR_EVENT_ROUTE_ENDPOINT_UNAVAILABLE,
                    r->route_id, r->stream_id, r->source_id,
                    r->destination_id, "Destination endpoint not found");
        return OZAYN_IOR_ERR_DESTINATION_NOT_FOUND;
    }

    if (_check_loop(svc, r->source_id, r->destination_id,
                     svc->config.max_loop_depth)) {
        r->state = OZAYN_IOR_ROUTE_FAILED;
        r->close_reason = OZAYN_IOR_CLOSE_LOOP_DETECTED;
        r->active = 0;
        svc->route_count--;
        svc->stats.total_routes_failed++;
        svc->stats.total_loop_detections++;
        svc->stats.current_active_routes--;
        _emit_event(svc, OZAYN_IOR_EVENT_ROUTE_LOOP_DETECTED, r->route_id,
                    r->stream_id, r->source_id, r->destination_id,
                    "Routing loop detected");
        return OZAYN_IOR_ERR_LOOP_DETECTED;
    }

    if (!_transition(svc, r, OZAYN_IOR_ROUTE_AUTHORIZED)) {
        r->state = OZAYN_IOR_ROUTE_FAILED;
        r->close_reason = OZAYN_IOR_CLOSE_CONCURRENT_ERROR;
        r->active = 0;
        svc->route_count--;
        svc->stats.total_routes_failed++;
        svc->stats.current_active_routes--;
        return OZAYN_IOR_ERR_STATE_INVALID;
    }

    svc->stats.total_routes_authorized++;
    _emit_event(svc, OZAYN_IOR_EVENT_ROUTE_AUTHORIZED, r->route_id,
                r->stream_id, r->source_id, r->destination_id,
                "Route authorized");
    return OZAYN_IOR_OK;
}

ozayn_ior_err_t ozayn_ior_route_connect(ozayn_ior_service_t *svc,
                                         const char *route_id)
{
    if (!svc) return OZAYN_IOR_ERR_NULL;
    if (!svc->initialized) return OZAYN_IOR_ERR_NOT_INITIALIZED;
    if (!route_id || route_id[0] == '\0')
        return OZAYN_IOR_ERR_INVALID_PARAM;

    int idx = _find_route(svc, route_id);
    if (idx < 0) return OZAYN_IOR_ERR_NOT_FOUND;

    ozayn_ior_route_t *r = &svc->routes[idx];

    if (!_transition(svc, r, OZAYN_IOR_ROUTE_WAITING)) {
        svc->stats.total_errors++;
        return OZAYN_IOR_ERR_STATE_INVALID;
    }

    if (!_transition(svc, r, OZAYN_IOR_ROUTE_CONNECTING)) {
        svc->stats.total_errors++;
        return OZAYN_IOR_ERR_STATE_INVALID;
    }

    svc->stats.current_connecting_routes++;
    _emit_event(svc, OZAYN_IOR_EVENT_ROUTE_CONNECTING, r->route_id,
                r->stream_id, r->source_id, r->destination_id,
                "Route connecting");
    return OZAYN_IOR_OK;
}

/* ============================================================
 * SECTION 6 — ROUTE LIFECYCLE OPERATIONS
 * ============================================================ */

ozayn_ior_err_t ozayn_ior_route_activate(ozayn_ior_service_t *svc,
                                          const char *route_id)
{
    if (!svc) return OZAYN_IOR_ERR_NULL;
    if (!svc->initialized) return OZAYN_IOR_ERR_NOT_INITIALIZED;
    if (!route_id || route_id[0] == '\0')
        return OZAYN_IOR_ERR_INVALID_PARAM;

    int idx = _find_route(svc, route_id);
    if (idx < 0) return OZAYN_IOR_ERR_NOT_FOUND;

    ozayn_ior_route_t *r = &svc->routes[idx];

    if (!_transition(svc, r, OZAYN_IOR_ROUTE_ACTIVE)) {
        svc->stats.total_errors++;
        return OZAYN_IOR_ERR_STATE_INVALID;
    }

    r->activated_time = time(NULL);
    r->last_activity_time = r->activated_time;
    svc->stats.current_connecting_routes--;
    svc->stats.total_routes_active++;
    _emit_event(svc, OZAYN_IOR_EVENT_ROUTE_ACTIVE, r->route_id,
                r->stream_id, r->source_id, r->destination_id,
                "Route active");
    return OZAYN_IOR_OK;
}

ozayn_ior_err_t ozayn_ior_route_pause(ozayn_ior_service_t *svc,
                                       const char *route_id)
{
    if (!svc) return OZAYN_IOR_ERR_NULL;
    if (!svc->initialized) return OZAYN_IOR_ERR_NOT_INITIALIZED;
    if (!route_id || route_id[0] == '\0')
        return OZAYN_IOR_ERR_INVALID_PARAM;

    int idx = _find_route(svc, route_id);
    if (idx < 0) return OZAYN_IOR_ERR_NOT_FOUND;

    ozayn_ior_route_t *r = &svc->routes[idx];

    if (!_transition(svc, r, OZAYN_IOR_ROUTE_PAUSED)) {
        svc->stats.total_errors++;
        return OZAYN_IOR_ERR_STATE_INVALID;
    }

    svc->stats.total_routes_paused++;
    svc->stats.current_paused_routes++;
    _emit_event(svc, OZAYN_IOR_EVENT_ROUTE_PAUSED, r->route_id,
                r->stream_id, r->source_id, r->destination_id,
                "Route paused");
    return OZAYN_IOR_OK;
}

ozayn_ior_err_t ozayn_ior_route_resume(ozayn_ior_service_t *svc,
                                        const char *route_id)
{
    if (!svc) return OZAYN_IOR_ERR_NULL;
    if (!svc->initialized) return OZAYN_IOR_ERR_NOT_INITIALIZED;
    if (!route_id || route_id[0] == '\0')
        return OZAYN_IOR_ERR_INVALID_PARAM;

    int idx = _find_route(svc, route_id);
    if (idx < 0) return OZAYN_IOR_ERR_NOT_FOUND;

    ozayn_ior_route_t *r = &svc->routes[idx];

    if (!_transition(svc, r, OZAYN_IOR_ROUTE_ACTIVE)) {
        svc->stats.total_errors++;
        return OZAYN_IOR_ERR_STATE_INVALID;
    }

    svc->stats.current_paused_routes--;
    r->last_activity_time = time(NULL);
    _emit_event(svc, OZAYN_IOR_EVENT_ROUTE_RESUMED, r->route_id,
                r->stream_id, r->source_id, r->destination_id,
                "Route resumed");
    return OZAYN_IOR_OK;
}

ozayn_ior_err_t ozayn_ior_route_disconnect(ozayn_ior_service_t *svc,
                                            const char *route_id)
{
    if (!svc) return OZAYN_IOR_ERR_NULL;
    if (!svc->initialized) return OZAYN_IOR_ERR_NOT_INITIALIZED;
    if (!route_id || route_id[0] == '\0')
        return OZAYN_IOR_ERR_INVALID_PARAM;

    int idx = _find_route(svc, route_id);
    if (idx < 0) return OZAYN_IOR_ERR_NOT_FOUND;

    ozayn_ior_route_t *r = &svc->routes[idx];

    if (_is_terminal(r->state))
        return OZAYN_IOR_ERR_STATE_INVALID;

    if (r->state == OZAYN_IOR_ROUTE_CONNECTING)
        svc->stats.current_connecting_routes--;
    if (r->state == OZAYN_IOR_ROUTE_PAUSED)
        svc->stats.current_paused_routes--;

    _emit_event(svc, OZAYN_IOR_EVENT_ROUTE_DISCONNECTING, r->route_id,
                r->stream_id, r->source_id, r->destination_id,
                "Route disconnecting");

    if (!_transition(svc, r, OZAYN_IOR_ROUTE_DISCONNECTING)) {
        r->state = OZAYN_IOR_ROUTE_DISCONNECTING;
    }
    if (!_transition(svc, r, OZAYN_IOR_ROUTE_CLOSED)) {
        r->state = OZAYN_IOR_ROUTE_CLOSED;
    }

    r->close_reason = OZAYN_IOR_CLOSE_MANUAL_CLOSE;
    r->closed_time = time(NULL);
    r->active = 0;
    svc->route_count--;
    svc->stats.total_routes_closed++;
    svc->stats.current_active_routes--;

    _emit_event(svc, OZAYN_IOR_EVENT_ROUTE_CLOSED, r->route_id,
                r->stream_id, r->source_id, r->destination_id,
                "Route closed");
    return OZAYN_IOR_OK;
}

ozayn_ior_err_t ozayn_ior_route_close(ozayn_ior_service_t *svc,
                                       const char *route_id,
                                       ozayn_ior_close_reason_t reason)
{
    if (!svc) return OZAYN_IOR_ERR_NULL;
    if (!svc->initialized) return OZAYN_IOR_ERR_NOT_INITIALIZED;
    if (!route_id || route_id[0] == '\0')
        return OZAYN_IOR_ERR_INVALID_PARAM;

    int idx = _find_route(svc, route_id);
    if (idx < 0) return OZAYN_IOR_ERR_NOT_FOUND;

    ozayn_ior_route_t *r = &svc->routes[idx];

    if (_is_terminal(r->state))
        return OZAYN_IOR_ERR_STATE_INVALID;

    if (r->state == OZAYN_IOR_ROUTE_CONNECTING)
        svc->stats.current_connecting_routes--;
    if (r->state == OZAYN_IOR_ROUTE_PAUSED)
        svc->stats.current_paused_routes--;

    if (!_transition(svc, r, OZAYN_IOR_ROUTE_DISCONNECTING)) {
        r->state = OZAYN_IOR_ROUTE_DISCONNECTING;
    }
    if (!_transition(svc, r, OZAYN_IOR_ROUTE_CLOSED)) {
        r->state = OZAYN_IOR_ROUTE_CLOSED;
    }

    r->close_reason = reason;
    r->closed_time = time(NULL);
    r->active = 0;
    svc->route_count--;
    svc->stats.total_routes_closed++;
    svc->stats.current_active_routes--;

    _emit_event(svc, OZAYN_IOR_EVENT_ROUTE_CLOSED, r->route_id,
                r->stream_id, r->source_id, r->destination_id,
                "Route closed");
    return OZAYN_IOR_OK;
}

ozayn_ior_err_t ozayn_ior_route_revoke(ozayn_ior_service_t *svc,
                                        const char *route_id,
                                        ozayn_ior_close_reason_t reason)
{
    if (!svc) return OZAYN_IOR_ERR_NULL;
    if (!svc->initialized) return OZAYN_IOR_ERR_NOT_INITIALIZED;
    if (!route_id || route_id[0] == '\0')
        return OZAYN_IOR_ERR_INVALID_PARAM;

    int idx = _find_route(svc, route_id);
    if (idx < 0) return OZAYN_IOR_ERR_NOT_FOUND;

    ozayn_ior_route_t *r = &svc->routes[idx];

    if (_is_terminal(r->state))
        return OZAYN_IOR_ERR_STATE_INVALID;

    if (r->state == OZAYN_IOR_ROUTE_CONNECTING)
        svc->stats.current_connecting_routes--;
    if (r->state == OZAYN_IOR_ROUTE_PAUSED)
        svc->stats.current_paused_routes--;

    if (!_transition(svc, r, OZAYN_IOR_ROUTE_REVOKED)) {
        r->state = OZAYN_IOR_ROUTE_REVOKED;
    }

    r->close_reason = reason;
    r->closed_time = time(NULL);
    r->active = 0;
    svc->route_count--;
    svc->stats.total_routes_revoked++;
    svc->stats.current_active_routes--;

    _emit_event(svc, OZAYN_IOR_EVENT_ROUTE_REVOKED, r->route_id,
                r->stream_id, r->source_id, r->destination_id,
                "Route revoked");
    return OZAYN_IOR_OK;
}

ozayn_ior_err_t ozayn_ior_route_remove(ozayn_ior_service_t *svc,
                                        const char *route_id)
{
    if (!svc) return OZAYN_IOR_ERR_NULL;
    if (!svc->initialized) return OZAYN_IOR_ERR_NOT_INITIALIZED;
    if (!route_id || route_id[0] == '\0')
        return OZAYN_IOR_ERR_INVALID_PARAM;

    int idx = _find_route_any(svc, route_id);
    if (idx < 0) return OZAYN_IOR_ERR_NOT_FOUND;

    ozayn_ior_route_t *r = &svc->routes[idx];
    if (r->active) return OZAYN_IOR_ERR_STATE_INVALID;

    memset(r, 0, sizeof(ozayn_ior_route_t));
    return OZAYN_IOR_OK;
}

/* ============================================================
 * SECTION 7 — ROUTE QUERY
 * ============================================================ */

const ozayn_ior_route_t *ozayn_ior_route_get(const ozayn_ior_service_t *svc,
                                              const char *route_id)
{
    if (!svc || !svc->initialized || !route_id) return NULL;
    int idx = _find_route(svc, route_id);
    if (idx < 0) return NULL;
    return &svc->routes[idx];
}

const ozayn_ior_route_t *ozayn_ior_route_get_by_stream(
    const ozayn_ior_service_t *svc, const char *stream_id)
{
    if (!svc || !svc->initialized || !stream_id) return NULL;
    for (int i = 0; i < svc->config.max_routes; i++) {
        if (svc->routes[i].active &&
            strncmp(svc->routes[i].stream_id, stream_id,
                    OZAYN_IOR_MAX_ID_LEN) == 0)
            return &svc->routes[i];
    }
    return NULL;
}

const ozayn_ior_route_t *ozayn_ior_route_get_by_source(
    const ozayn_ior_service_t *svc, const char *source_id)
{
    if (!svc || !svc->initialized || !source_id) return NULL;
    for (int i = 0; i < svc->config.max_routes; i++) {
        if (svc->routes[i].active &&
            strncmp(svc->routes[i].source_id, source_id,
                    OZAYN_IOR_MAX_ID_LEN) == 0)
            return &svc->routes[i];
    }
    return NULL;
}

const ozayn_ior_route_t *ozayn_ior_route_get_by_destination(
    const ozayn_ior_service_t *svc, const char *destination_id)
{
    if (!svc || !svc->initialized || !destination_id) return NULL;
    for (int i = 0; i < svc->config.max_routes; i++) {
        if (svc->routes[i].active &&
            strncmp(svc->routes[i].destination_id, destination_id,
                    OZAYN_IOR_MAX_ID_LEN) == 0)
            return &svc->routes[i];
    }
    return NULL;
}

int ozayn_ior_route_count(const ozayn_ior_service_t *svc)
{
    if (!svc || !svc->initialized) return 0;
    return svc->route_count;
}

int ozayn_ior_route_count_by_stream(const ozayn_ior_service_t *svc,
                                     const char *stream_id)
{
    if (!svc || !svc->initialized || !stream_id) return 0;
    int count = 0;
    for (int i = 0; i < svc->config.max_routes; i++) {
        if (svc->routes[i].active &&
            strncmp(svc->routes[i].stream_id, stream_id,
                    OZAYN_IOR_MAX_ID_LEN) == 0)
            count++;
    }
    return count;
}

int ozayn_ior_route_is_active(const ozayn_ior_service_t *svc,
                               const char *route_id)
{
    if (!svc || !svc->initialized || !route_id) return 0;
    int idx = _find_route(svc, route_id);
    if (idx < 0) return 0;
    return svc->routes[idx].state == OZAYN_IOR_ROUTE_ACTIVE;
}

/* ============================================================
 * SECTION 8 — STREAM CHANGE HANDLING
 * ============================================================ */

int ozayn_ior_routes_for_stream(ozayn_ior_service_t *svc,
                                 const char *stream_id,
                                 ozayn_ior_route_t **out_routes,
                                 int max_out)
{
    if (!svc || !svc->initialized || !stream_id || !out_routes)
        return 0;
    int count = 0;
    for (int i = 0; i < svc->config.max_routes && count < max_out; i++) {
        if (svc->routes[i].active &&
            strncmp(svc->routes[i].stream_id, stream_id,
                    OZAYN_IOR_MAX_ID_LEN) == 0) {
            out_routes[count++] = &svc->routes[i];
        }
    }
    return count;
}

ozayn_ior_err_t ozayn_ior_stream_closed(ozayn_ior_service_t *svc,
                                         const char *stream_id)
{
    if (!svc) return OZAYN_IOR_ERR_NULL;
    if (!svc->initialized) return OZAYN_IOR_ERR_NOT_INITIALIZED;
    if (!stream_id || stream_id[0] == '\0')
        return OZAYN_IOR_ERR_INVALID_PARAM;

    int changed = 0;
    for (int i = 0; i < svc->config.max_routes; i++) {
        if (svc->routes[i].active &&
            strncmp(svc->routes[i].stream_id, stream_id,
                    OZAYN_IOR_MAX_ID_LEN) == 0) {
            svc->routes[i].state = OZAYN_IOR_ROUTE_UNAVAILABLE;
            svc->routes[i].close_reason = OZAYN_IOR_CLOSE_STREAM_CLOSED;
            svc->routes[i].closed_time = time(NULL);
            svc->routes[i].active = 0;
            svc->route_count--;
            svc->stats.total_routes_closed++;
            svc->stats.current_active_routes--;
            changed++;
            _emit_event(svc, OZAYN_IOR_EVENT_ROUTE_UNAVAILABLE,
                        svc->routes[i].route_id, stream_id,
                        svc->routes[i].source_id,
                        svc->routes[i].destination_id,
                        "Stream closed, route unavailable");
        }
    }
    return changed > 0 ? OZAYN_IOR_OK : OZAYN_IOR_ERR_NOT_FOUND;
}

ozayn_ior_err_t ozayn_ior_device_disconnected(ozayn_ior_service_t *svc,
                                               const char *device_id)
{
    if (!svc) return OZAYN_IOR_ERR_NULL;
    if (!svc->initialized) return OZAYN_IOR_ERR_NOT_INITIALIZED;
    if (!device_id || device_id[0] == '\0')
        return OZAYN_IOR_ERR_INVALID_PARAM;

    int changed = 0;
    for (int i = 0; i < svc->config.max_routes; i++) {
        if (svc->routes[i].active &&
            strncmp(svc->routes[i].device_id, device_id,
                    OZAYN_IOR_MAX_ID_LEN) == 0) {
            svc->routes[i].state = OZAYN_IOR_ROUTE_UNAVAILABLE;
            svc->routes[i].close_reason = OZAYN_IOR_CLOSE_DEVICE_DISCONNECTED;
            svc->routes[i].closed_time = time(NULL);
            svc->routes[i].active = 0;
            svc->route_count--;
            svc->stats.total_routes_closed++;
            svc->stats.current_active_routes--;
            changed++;
            _emit_event(svc, OZAYN_IOR_EVENT_ROUTE_UNAVAILABLE,
                        svc->routes[i].route_id,
                        svc->routes[i].stream_id,
                        svc->routes[i].source_id,
                        svc->routes[i].destination_id,
                        "Device disconnected, route unavailable");
        }
    }
    return changed > 0 ? OZAYN_IOR_OK : OZAYN_IOR_ERR_NOT_FOUND;
}

/* ============================================================
 * SECTION 9 — EVENTS
 * ============================================================ */

ozayn_ior_err_t ozayn_ior_emit_event(ozayn_ior_service_t *svc,
                                      ozayn_ior_event_type_t type,
                                      const char *route_id,
                                      const char *stream_id,
                                      const char *source_id,
                                      const char *destination_id,
                                      const char *message)
{
    if (!svc) return OZAYN_IOR_ERR_NULL;
    if (!svc->initialized) return OZAYN_IOR_ERR_NOT_INITIALIZED;
    _emit_event(svc, type, route_id, stream_id, source_id, destination_id,
                message);
    return OZAYN_IOR_OK;
}

const ozayn_ior_event_t *ozayn_ior_event_get(const ozayn_ior_service_t *svc,
                                              int index)
{
    if (!svc || !svc->initialized) return NULL;
    if (index < 0 || index >= svc->event_count) return NULL;
    int idx = (svc->event_head + index) % OZAYN_IOR_MAX_EVENTS;
    return &svc->events[idx];
}

int ozayn_ior_event_count(const ozayn_ior_service_t *svc)
{
    if (!svc || !svc->initialized) return 0;
    return svc->event_count;
}

/* ============================================================
 * SECTION 10 — CLEANUP
 * ============================================================ */

int ozayn_ior_cleanup_expired_routes(ozayn_ior_service_t *svc)
{
    if (!svc) return 0;
    int cleaned = 0;
    time_t now = time(NULL);
    for (int i = 0; i < svc->config.max_routes; i++) {
        if (svc->routes[i].active) {
            if (svc->routes[i].expiry_time > 0 &&
                now > svc->routes[i].expiry_time) {
                svc->routes[i].state = OZAYN_IOR_ROUTE_EXPIRED;
                svc->routes[i].close_reason = OZAYN_IOR_CLOSE_TIMEOUT;
                svc->routes[i].closed_time = now;
                svc->routes[i].active = 0;
                svc->stats.total_routes_expired++;
                svc->stats.current_active_routes--;
                cleaned++;
            }
        }
    }
    svc->route_count -= cleaned;
    return cleaned;
}

int ozayn_ior_cleanup_idle_routes(ozayn_ior_service_t *svc)
{
    if (!svc) return 0;
    int cleaned = 0;
    time_t now = time(NULL);
    int idle_limit_s = svc->config.idle_timeout_ms / 1000;
    for (int i = 0; i < svc->config.max_routes; i++) {
        if (svc->routes[i].active &&
            svc->routes[i].last_activity_time > 0 &&
            (now - svc->routes[i].last_activity_time) > idle_limit_s) {
            svc->routes[i].state = OZAYN_IOR_ROUTE_CLOSED;
            svc->routes[i].close_reason = OZAYN_IOR_CLOSE_TIMEOUT;
            svc->routes[i].closed_time = now;
            svc->routes[i].active = 0;
            svc->stats.total_routes_closed++;
            svc->stats.current_active_routes--;
            cleaned++;
        }
    }
    svc->route_count -= cleaned;
    return cleaned;
}

int ozayn_ior_cleanup_closed_routes(ozayn_ior_service_t *svc)
{
    if (!svc) return 0;
    int cleaned = 0;
    for (int i = 0; i < svc->config.max_routes; i++) {
        if (!svc->routes[i].active &&
            svc->routes[i].state == OZAYN_IOR_ROUTE_CLOSED) {
            memset(&svc->routes[i], 0, sizeof(ozayn_ior_route_t));
            cleaned++;
        }
    }
    return cleaned;
}

int ozayn_ior_cleanup_all(ozayn_ior_service_t *svc)
{
    if (!svc) return 0;
    int cleaned = 0;
    cleaned += ozayn_ior_cleanup_expired_routes(svc);
    cleaned += ozayn_ior_cleanup_idle_routes(svc);
    cleaned += ozayn_ior_cleanup_closed_routes(svc);
    return cleaned;
}

/* ============================================================
 * SECTION 11 — STATISTICS
 * ============================================================ */

ozayn_ior_err_t ozayn_ior_get_stats(const ozayn_ior_service_t *svc,
                                     ozayn_ior_stats_t *out_stats)
{
    if (!svc) return OZAYN_IOR_ERR_NULL;
    if (!out_stats) return OZAYN_IOR_ERR_NULL;
    *out_stats = svc->stats;
    return OZAYN_IOR_OK;
}

/* ============================================================
 * SECTION 12 — VALIDATION
 * ============================================================ */

int ozayn_ior_route_validate(const ozayn_ior_route_t *route)
{
    if (!route) return 0;
    if (route->route_id[0] == '\0') return 0;
    if (route->stream_id[0] == '\0') return 0;
    if (route->source_id[0] == '\0') return 0;
    if (route->destination_id[0] == '\0') return 0;
    if (route->state < 0 || route->state >= OZAYN_IOR_ROUTE_STATE_COUNT)
        return 0;
    if (route->created_time <= 0) return 0;
    return 1;
}

int ozayn_ior_route_request_validate(const ozayn_ior_route_request_t *req)
{
    if (!req) return 0;
    if (!req->stream_id[0]) return 0;
    if (!req->source_id[0]) return 0;
    if (!req->destination_id[0]) return 0;
    if (req->source_type < 0 || req->source_type >= OZAYN_IOR_ENDPOINT_COUNT)
        return 0;
    if (req->destination_type < 0 ||
        req->destination_type >= OZAYN_IOR_ENDPOINT_COUNT)
        return 0;
    if (req->mode < 0 || req->mode >= OZAYN_IOR_MODE_COUNT)
        return 0;
    if (!req->requester_ref[0]) return 0;
    return 1;
}

int ozayn_ior_state_transition_valid(ozayn_ior_route_state_t from,
                                      ozayn_ior_route_state_t to)
{
    if (from < 0 || from >= OZAYN_IOR_ROUTE_STATE_COUNT) return 0;
    if (to < 0 || to >= OZAYN_IOR_ROUTE_STATE_COUNT) return 0;
    return _valid_transitions[from][to];
}

/* ============================================================
 * SECTION 13 — NAME HELPERS
 * ============================================================ */

const char *ozayn_ior_err_name(ozayn_ior_err_t err)
{
    switch (err) {
    case OZAYN_IOR_OK:                          return "OK";
    case OZAYN_IOR_ERR_NULL:                    return "NULL";
    case OZAYN_IOR_ERR_NOT_INITIALIZED:         return "NOT_INITIALIZED";
    case OZAYN_IOR_ERR_ALREADY_INIT:            return "ALREADY_INIT";
    case OZAYN_IOR_ERR_INVALID_PARAM:           return "INVALID_PARAM";
    case OZAYN_IOR_ERR_LIMIT_REACHED:           return "LIMIT_REACHED";
    case OZAYN_IOR_ERR_NOT_FOUND:               return "NOT_FOUND";
    case OZAYN_IOR_ERR_STATE_INVALID:           return "STATE_INVALID";
    case OZAYN_IOR_ERR_AUTH_FAILED:             return "AUTH_FAILED";
    case OZAYN_IOR_ERR_PERMISSION_DENIED:       return "PERMISSION_DENIED";
    case OZAYN_IOR_ERR_STREAM_INVALID:          return "STREAM_INVALID";
    case OZAYN_IOR_ERR_STREAM_UNAVAILABLE:      return "STREAM_UNAVAILABLE";
    case OZAYN_IOR_ERR_SOURCE_INVALID:          return "SOURCE_INVALID";
    case OZAYN_IOR_ERR_SOURCE_NOT_FOUND:        return "SOURCE_NOT_FOUND";
    case OZAYN_IOR_ERR_DESTINATION_INVALID:     return "DESTINATION_INVALID";
    case OZAYN_IOR_ERR_DESTINATION_NOT_FOUND:   return "DESTINATION_NOT_FOUND";
    case OZAYN_IOR_ERR_ENDPOINT_UNAVAILABLE:    return "ENDPOINT_UNAVAILABLE";
    case OZAYN_IOR_ERR_DATA_TYPE_MISMATCH:      return "DATA_TYPE_MISMATCH";
    case OZAYN_IOR_ERR_DIRECTION_INVALID:       return "DIRECTION_INVALID";
    case OZAYN_IOR_ERR_POLICY_DENIED:           return "POLICY_DENIED";
    case OZAYN_IOR_ERR_PRECONDITION_FAILED:     return "PRECONDITION_FAILED";
    case OZAYN_IOR_ERR_RESOURCE_UNAVAILABLE:    return "RESOURCE_UNAVAILABLE";
    case OZAYN_IOR_ERR_RESOURCE_LIMIT:          return "RESOURCE_LIMIT";
    case OZAYN_IOR_ERR_BUFFER_LIMIT:            return "BUFFER_LIMIT";
    case OZAYN_IOR_ERR_RATE_LIMIT:              return "RATE_LIMIT";
    case OZAYN_IOR_ERR_LOOP_DETECTED:           return "LOOP_DETECTED";
    case OZAYN_IOR_ERR_TIMEOUT:                 return "TIMEOUT";
    case OZAYN_IOR_ERR_EXPIRED:                 return "EXPIRED";
    case OZAYN_IOR_ERR_REVOKED:                 return "REVOKED";
    case OZAYN_IOR_ERR_DEVICE_DISCONNECTED:     return "DEVICE_DISCONNECTED";
    case OZAYN_IOR_ERR_CONCURRENCY:             return "CONCURRENCY";
    case OZAYN_IOR_ERR_PROVIDER_ERROR:          return "PROVIDER_ERROR";
    case OZAYN_IOR_ERR_EXECUTION:               return "EXECUTION";
    default:                                    return "UNKNOWN";
    }
}

const char *ozayn_ior_route_state_name(ozayn_ior_route_state_t state)
{
    switch (state) {
    case OZAYN_IOR_ROUTE_REQUESTED:      return "REQUESTED";
    case OZAYN_IOR_ROUTE_VALIDATING:     return "VALIDATING";
    case OZAYN_IOR_ROUTE_AUTHORIZED:     return "AUTHORIZED";
    case OZAYN_IOR_ROUTE_WAITING:        return "WAITING";
    case OZAYN_IOR_ROUTE_CONNECTING:     return "CONNECTING";
    case OZAYN_IOR_ROUTE_ACTIVE:         return "ACTIVE";
    case OZAYN_IOR_ROUTE_PAUSED:         return "PAUSED";
    case OZAYN_IOR_ROUTE_BACKPRESSURED:  return "BACKPRESSURED";
    case OZAYN_IOR_ROUTE_DISCONNECTING:  return "DISCONNECTING";
    case OZAYN_IOR_ROUTE_CLOSED:         return "CLOSED";
    case OZAYN_IOR_ROUTE_FAILED:         return "FAILED";
    case OZAYN_IOR_ROUTE_EXPIRED:        return "EXPIRED";
    case OZAYN_IOR_ROUTE_REVOKED:        return "REVOKED";
    case OZAYN_IOR_ROUTE_UNAVAILABLE:    return "UNAVAILABLE";
    default:                             return "UNKNOWN";
    }
}

const char *ozayn_ior_endpoint_type_name(ozayn_ior_endpoint_type_t type)
{
    switch (type) {
    case OZAYN_IOR_ENDPOINT_DEVICE:              return "DEVICE";
    case OZAYN_IOR_ENDPOINT_DEVICE_SESSION:      return "DEVICE_SESSION";
    case OZAYN_IOR_ENDPOINT_STREAM:              return "STREAM";
    case OZAYN_IOR_ENDPOINT_CORE_COMPONENT:      return "CORE_COMPONENT";
    case OZAYN_IOR_ENDPOINT_MODULE:              return "MODULE";
    case OZAYN_IOR_ENDPOINT_TASK:                return "TASK";
    case OZAYN_IOR_ENDPOINT_CONTROLLED_SERVICE:  return "CONTROLLED_SERVICE";
    default:                                     return "UNKNOWN";
    }
}

const char *ozayn_ior_close_reason_name(ozayn_ior_close_reason_t reason)
{
    switch (reason) {
    case OZAYN_IOR_CLOSE_NONE:                   return "NONE";
    case OZAYN_IOR_CLOSE_MANUAL_CLOSE:           return "MANUAL_CLOSE";
    case OZAYN_IOR_CLOSE_STREAM_CLOSED:          return "STREAM_CLOSED";
    case OZAYN_IOR_CLOSE_STREAM_EXPIRED:         return "STREAM_EXPIRED";
    case OZAYN_IOR_CLOSE_STREAM_REVOKED:         return "STREAM_REVOKED";
    case OZAYN_IOR_CLOSE_DEVICE_DISCONNECTED:    return "DEVICE_DISCONNECTED";
    case OZAYN_IOR_CLOSE_SESSION_EXPIRED:        return "SESSION_EXPIRED";
    case OZAYN_IOR_CLOSE_SESSION_REVOKED:        return "SESSION_REVOKED";
    case OZAYN_IOR_CLOSE_ENDPOINT_UNAVAILABLE:   return "ENDPOINT_UNAVAILABLE";
    case OZAYN_IOR_CLOSE_POLICY_CHANGED:         return "POLICY_CHANGED";
    case OZAYN_IOR_CLOSE_RESOURCE_EXHAUSTED:     return "RESOURCE_EXHAUSTED";
    case OZAYN_IOR_CLOSE_BUFFER_OVERFLOW:        return "BUFFER_OVERFLOW";
    case OZAYN_IOR_CLOSE_RATE_EXCEEDED:          return "RATE_EXCEEDED";
    case OZAYN_IOR_CLOSE_TIMEOUT:                return "TIMEOUT";
    case OZAYN_IOR_CLOSE_SYSTEM_SHUTDOWN:        return "SYSTEM_SHUTDOWN";
    case OZAYN_IOR_CLOSE_LOOP_DETECTED:          return "LOOP_DETECTED";
    case OZAYN_IOR_CLOSE_CONCURRENT_ERROR:       return "CONCURRENT_ERROR";
    default:                                     return "UNKNOWN";
    }
}

const char *ozayn_ior_event_type_name(ozayn_ior_event_type_t type)
{
    switch (type) {
    case OZAYN_IOR_EVENT_ROUTE_REQUESTED:            return "ROUTE_REQUESTED";
    case OZAYN_IOR_EVENT_ROUTE_VALIDATED:            return "ROUTE_VALIDATED";
    case OZAYN_IOR_EVENT_ROUTE_AUTHORIZED:           return "ROUTE_AUTHORIZED";
    case OZAYN_IOR_EVENT_ROUTE_REJECTED:             return "ROUTE_REJECTED";
    case OZAYN_IOR_EVENT_ROUTE_CONNECTING:           return "ROUTE_CONNECTING";
    case OZAYN_IOR_EVENT_ROUTE_ACTIVE:               return "ROUTE_ACTIVE";
    case OZAYN_IOR_EVENT_ROUTE_PAUSED:               return "ROUTE_PAUSED";
    case OZAYN_IOR_EVENT_ROUTE_RESUMED:              return "ROUTE_RESUMED";
    case OZAYN_IOR_EVENT_ROUTE_BACKPRESSURED:        return "ROUTE_BACKPRESSURED";
    case OZAYN_IOR_EVENT_ROUTE_DATA_DROPPED:         return "ROUTE_DATA_DROPPED";
    case OZAYN_IOR_EVENT_ROUTE_DISCONNECTING:        return "ROUTE_DISCONNECTING";
    case OZAYN_IOR_EVENT_ROUTE_CLOSED:               return "ROUTE_CLOSED";
    case OZAYN_IOR_EVENT_ROUTE_EXPIRED:              return "ROUTE_EXPIRED";
    case OZAYN_IOR_EVENT_ROUTE_REVOKED:              return "ROUTE_REVOKED";
    case OZAYN_IOR_EVENT_ROUTE_UNAVAILABLE:          return "ROUTE_UNAVAILABLE";
    case OZAYN_IOR_EVENT_ROUTE_FAILED:               return "ROUTE_FAILED";
    case OZAYN_IOR_EVENT_ROUTE_LOOP_DETECTED:        return "ROUTE_LOOP_DETECTED";
    case OZAYN_IOR_EVENT_ROUTE_ENDPOINT_UNAVAILABLE: return "ROUTE_ENDPOINT_UNAVAILABLE";
    default:                                         return "UNKNOWN";
    }
}

const char *ozayn_ior_route_mode_name(ozayn_ior_route_mode_t mode)
{
    switch (mode) {
    case OZAYN_IOR_MODE_ONE_TO_ONE:   return "ONE_TO_ONE";
    case OZAYN_IOR_MODE_ONE_TO_MANY:  return "ONE_TO_MANY";
    default:                          return "UNKNOWN";
    }
}
