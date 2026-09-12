#include "io_stream.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

/* ============================================================
 * SECTION 1 — INTERNAL HELPERS
 * ============================================================ */

static ozayn_ios_service_t _svc;

static int _find_stream(const ozayn_ios_service_t *svc,
                         const char *stream_id)
{
    if (!svc || !stream_id) return -1;
    for (int i = 0; i < svc->config.max_streams; i++) {
        if (svc->streams[i].active &&
            strncmp(svc->streams[i].stream_id, stream_id,
                    OZAYN_IOS_MAX_ID_LEN) == 0)
            return i;
    }
    return -1;
}

static int _find_stream_slot(const ozayn_ios_service_t *svc)
{
    for (int i = 0; i < svc->config.max_streams; i++) {
        if (!svc->streams[i].active) return i;
    }
    return -1;
}

static void _emit_event(ozayn_ios_service_t *svc,
                          ozayn_ios_event_type_t type,
                          const char *stream_id,
                          const char *device_id,
                          const char *session_id,
                          const char *message)
{
    if (!svc) return;
    int idx = (svc->event_head + svc->event_count) %
              OZAYN_IOS_MAX_EVENTS;
    if (svc->event_count >= OZAYN_IOS_MAX_EVENTS) {
        svc->event_head = (svc->event_head + 1) % OZAYN_IOS_MAX_EVENTS;
    } else {
        svc->event_count++;
    }
    svc->events[idx].type = type;
    strncpy(svc->events[idx].stream_id, stream_id ? stream_id : "",
            OZAYN_IOS_MAX_ID_LEN - 1);
    svc->events[idx].stream_id[OZAYN_IOS_MAX_ID_LEN - 1] = '\0';
    strncpy(svc->events[idx].device_id, device_id ? device_id : "",
            OZAYN_IOS_MAX_ID_LEN - 1);
    svc->events[idx].device_id[OZAYN_IOS_MAX_ID_LEN - 1] = '\0';
    strncpy(svc->events[idx].session_id, session_id ? session_id : "",
            OZAYN_IOS_MAX_ID_LEN - 1);
    svc->events[idx].session_id[OZAYN_IOS_MAX_ID_LEN - 1] = '\0';
    strncpy(svc->events[idx].message, message ? message : "",
            OZAYN_IOS_MAX_DESCRIPTION_LEN - 1);
    svc->events[idx].message[OZAYN_IOS_MAX_DESCRIPTION_LEN - 1] = '\0';
    svc->events[idx].timestamp = time(NULL);
    svc->event_sequence++;
}

/* ============================================================
 * SECTION 2 — STATE MACHINE
 * ============================================================ */

static const int _valid_transitions[OZAYN_IOS_STATE_COUNT]
                                   [OZAYN_IOS_STATE_COUNT] = {
    /* REQUESTED -> */
    {   0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1 },
    /* AUTHORIZING -> */
    {   0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1 },
    /* AUTHORIZED -> */
    {   0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 1, 1, 1, 0 },
    /* OPENING -> */
    {   0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 1, 1, 1, 1 },
    /* ACTIVE -> */
    {   0, 0, 0, 0, 0, 1, 1, 1, 1, 0, 1, 1, 1, 1 },
    /* PAUSED -> */
    {   0, 0, 0, 0, 1, 0, 0, 1, 1, 0, 1, 1, 1, 1 },
    /* BACKPRESSURED -> */
    {   0, 0, 0, 0, 1, 1, 0, 1, 1, 0, 1, 1, 1, 1 },
    /* DRAINING -> */
    {   0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 1, 1, 1 },
    /* CLOSING -> */
    {   0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0 },
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

static int _transition(ozayn_ios_service_t *svc,
                        ozayn_ios_stream_t *s,
                        ozayn_ios_stream_state_t new_state)
{
    if (!_valid_transitions[s->state][new_state]) {
        svc->stats.total_validation_failures++;
        return 0;
    }
    s->state = new_state;
    svc->stats.total_state_transitions++;
    return 1;
}

static int _is_terminal(ozayn_ios_stream_state_t state)
{
    return state == OZAYN_IOS_STATE_CLOSED ||
           state == OZAYN_IOS_STATE_FAILED ||
           state == OZAYN_IOS_STATE_EXPIRED ||
           state == OZAYN_IOS_STATE_REVOKED;
}

/* ============================================================
 * SECTION 3 — LIFECYCLE
 * ============================================================ */

ozayn_ios_err_t ozayn_ios_service_init(ozayn_ios_service_t *svc,
                                       const ozayn_ios_service_config_t *cfg)
{
    if (!svc) return OZAYN_IOS_ERR_NULL;
    if (!cfg) return OZAYN_IOS_ERR_NULL;
    if (svc->initialized) return OZAYN_IOS_ERR_ALREADY_INIT;

    memset(svc, 0, sizeof(*svc));
    svc->config = *cfg;

    if (svc->config.max_streams <= 0)
        svc->config.max_streams = OZAYN_IOS_MAX_STREAMS;
    if (svc->config.stream_ttl_ms <= 0)
        svc->config.stream_ttl_ms = OZAYN_IOS_DEFAULT_STREAM_TTL_MS;
    if (svc->config.idle_timeout_ms <= 0)
        svc->config.idle_timeout_ms = OZAYN_IOS_DEFAULT_IDLE_TIMEOUT_MS;
    if (svc->config.open_timeout_ms <= 0)
        svc->config.open_timeout_ms = OZAYN_IOS_DEFAULT_OPEN_TIMEOUT_MS;
    if (svc->config.drain_timeout_ms <= 0)
        svc->config.drain_timeout_ms = OZAYN_IOS_DEFAULT_DRAIN_TIMEOUT_MS;
    if (svc->config.default_max_buffer_size <= 0)
        svc->config.default_max_buffer_size = OZAYN_IOS_DEFAULT_MAX_BUFFER_SIZE;
    if (svc->config.default_max_queue_depth <= 0)
        svc->config.default_max_queue_depth = OZAYN_IOS_DEFAULT_MAX_QUEUE_DEPTH;
    if (svc->config.default_max_rate <= 0)
        svc->config.default_max_rate = OZAYN_IOS_DEFAULT_MAX_RATE;
    if (svc->config.default_max_data_size <= 0)
        svc->config.default_max_data_size = OZAYN_IOS_DEFAULT_MAX_DATA_SIZE;

    svc->initialized = 1;
    return OZAYN_IOS_OK;
}

void ozayn_ios_service_shutdown(ozayn_ios_service_t *svc)
{
    if (!svc) return;
    svc->initialized = 0;
}

int ozayn_ios_service_is_initialized(const ozayn_ios_service_t *svc)
{
    if (!svc) return 0;
    return svc->initialized;
}

ozayn_ios_service_t *ozayn_ios_get_global(void)
{
    return &_svc;
}

/* ============================================================
 * SECTION 4 — STREAM CREATION
 * ============================================================ */

ozayn_ios_err_t ozayn_ios_stream_create(ozayn_ios_service_t *svc,
                                         const ozayn_ios_stream_request_t *req,
                                         ozayn_ios_stream_t **out_stream)
{
    if (!svc) return OZAYN_IOS_ERR_NULL;
    if (!svc->initialized) return OZAYN_IOS_ERR_NOT_INITIALIZED;
    if (!req) return OZAYN_IOS_ERR_NULL;
    if (!out_stream) return OZAYN_IOS_ERR_NULL;

    if (!req->device_session_id[0]) return OZAYN_IOS_ERR_INVALID_PARAM;
    if (!req->device_id[0]) return OZAYN_IOS_ERR_INVALID_PARAM;
    if (!req->capability_id[0]) return OZAYN_IOS_ERR_INVALID_PARAM;
    if (req->direction < 0 || req->direction >= OZAYN_IOS_DIR_COUNT)
        return OZAYN_IOS_ERR_INVALID_PARAM;
    if (req->data_type < 0 || req->data_type >= OZAYN_IOS_DATA_COUNT)
        return OZAYN_IOS_ERR_INVALID_PARAM;
    if (req->buffer_policy < 0 || req->buffer_policy >= OZAYN_IOS_POLICY_COUNT)
        return OZAYN_IOS_ERR_INVALID_PARAM;
    if (!req->requester_ref[0]) return OZAYN_IOS_ERR_INVALID_PARAM;

    int slot = _find_stream_slot(svc);
    if (slot < 0) return OZAYN_IOS_ERR_LIMIT_REACHED;

    svc->stream_sequence++;
    ozayn_ios_stream_t *s = &svc->streams[slot];
    memset(s, 0, sizeof(*s));

    snprintf(s->stream_id, OZAYN_IOS_MAX_ID_LEN, "IOS-%u",
             svc->stream_sequence);
    s->version = 1;
    strncpy(s->device_session_id, req->device_session_id,
            OZAYN_IOS_MAX_ID_LEN - 1);
    strncpy(s->device_id, req->device_id, OZAYN_IOS_MAX_ID_LEN - 1);
    strncpy(s->capability_id, req->capability_id, OZAYN_IOS_MAX_ID_LEN - 1);
    if (req->operation_id[0])
        strncpy(s->operation_id, req->operation_id,
                OZAYN_IOS_MAX_ID_LEN - 1);
    s->direction = req->direction;
    s->data_type = req->data_type;
    s->buffer_policy = req->buffer_policy;

    s->max_buffer_size = req->requested_buffer_size > 0 ?
        req->requested_buffer_size : svc->config.default_max_buffer_size;
    s->max_queue_depth = svc->config.default_max_queue_depth;
    s->max_rate = req->requested_rate > 0 ?
        req->requested_rate : svc->config.default_max_rate;
    s->max_data_size = req->requested_max_data_size > 0 ?
        req->requested_max_data_size : svc->config.default_max_data_size;

    strncpy(s->owner_ref, req->requester_ref, OZAYN_IOS_MAX_ID_LEN - 1);
    strncpy(s->producer_ref, req->requester_ref, OZAYN_IOS_MAX_ID_LEN - 1);
    if (req->security_session_ref[0])
        strncpy(s->security_session_ref, req->security_session_ref,
                OZAYN_IOS_MAX_ID_LEN - 1);
    if (req->required_permission[0])
        strncpy(s->required_permission, req->required_permission,
                OZAYN_IOS_MAX_PERMISSION_LEN - 1);
    if (req->metadata[0])
        strncpy(s->metadata, req->metadata, OZAYN_IOS_MAX_METADATA_LEN - 1);

    s->state = OZAYN_IOS_STATE_REQUESTED;
    s->close_reason = OZAYN_IOS_CLOSE_NONE;
    s->created_time = time(NULL);
    s->expiry_time = s->created_time +
                     (svc->config.stream_ttl_ms / 1000);
    s->active = 1;

    svc->stream_count++;
    svc->stats.total_streams_created++;
    svc->stats.current_active_streams++;

    _emit_event(svc, OZAYN_IOS_EVENT_STREAM_REQUESTED, s->stream_id,
                s->device_id, s->device_session_id, "Stream requested");

    *out_stream = s;
    return OZAYN_IOS_OK;
}

ozayn_ios_err_t ozayn_ios_stream_authorize(ozayn_ios_service_t *svc,
                                            const char *stream_id)
{
    if (!svc) return OZAYN_IOS_ERR_NULL;
    if (!svc->initialized) return OZAYN_IOS_ERR_NOT_INITIALIZED;
    if (!stream_id || stream_id[0] == '\0')
        return OZAYN_IOS_ERR_INVALID_PARAM;

    int idx = _find_stream(svc, stream_id);
    if (idx < 0) return OZAYN_IOS_ERR_NOT_FOUND;

    ozayn_ios_stream_t *s = &svc->streams[idx];

    time_t now = time(NULL);
    if (s->expiry_time > 0 && now > s->expiry_time) {
        s->state = OZAYN_IOS_STATE_EXPIRED;
        s->close_reason = OZAYN_IOS_CLOSE_TIMEOUT;
        s->closed_time = now;
        s->active = 0;
        svc->stream_count--;
        svc->stats.total_streams_expired++;
        svc->stats.current_active_streams--;
        _emit_event(svc, OZAYN_IOS_EVENT_STREAM_EXPIRED, s->stream_id,
                    s->device_id, s->device_session_id,
                    "Stream expired during authorization");
        return OZAYN_IOS_ERR_EXPIRED;
    }

    if (!_transition(svc, s, OZAYN_IOS_STATE_AUTHORIZING)) {
        svc->stats.total_errors++;
        _emit_event(svc, OZAYN_IOS_EVENT_STREAM_FAILED, s->stream_id,
                    s->device_id, s->device_session_id,
                    "Invalid state for authorization");
        return OZAYN_IOS_ERR_STATE_INVALID;
    }

    if (!_transition(svc, s, OZAYN_IOS_STATE_AUTHORIZED)) {
        s->state = OZAYN_IOS_STATE_FAILED;
        s->close_reason = OZAYN_IOS_CLOSE_CONCURRENT_ERROR;
        s->active = 0;
        svc->stream_count--;
        svc->stats.total_streams_failed++;
        svc->stats.current_active_streams--;
        return OZAYN_IOS_ERR_STATE_INVALID;
    }

    svc->stats.total_streams_authorized++;
    _emit_event(svc, OZAYN_IOS_EVENT_STREAM_AUTHORIZED, s->stream_id,
                s->device_id, s->device_session_id, "Stream authorized");
    return OZAYN_IOS_OK;
}

ozayn_ios_err_t ozayn_ios_stream_open(ozayn_ios_service_t *svc,
                                       const char *stream_id)
{
    if (!svc) return OZAYN_IOS_ERR_NULL;
    if (!svc->initialized) return OZAYN_IOS_ERR_NOT_INITIALIZED;
    if (!stream_id || stream_id[0] == '\0')
        return OZAYN_IOS_ERR_INVALID_PARAM;

    int idx = _find_stream(svc, stream_id);
    if (idx < 0) return OZAYN_IOS_ERR_NOT_FOUND;

    ozayn_ios_stream_t *s = &svc->streams[idx];

    if (!_transition(svc, s, OZAYN_IOS_STATE_OPENING)) {
        svc->stats.total_errors++;
        return OZAYN_IOS_ERR_STATE_INVALID;
    }

    svc->stats.current_opening_streams++;
    _emit_event(svc, OZAYN_IOS_EVENT_STREAM_OPENING, s->stream_id,
                s->device_id, s->device_session_id, "Stream opening");
    return OZAYN_IOS_OK;
}

/* ============================================================
 * SECTION 5 — STREAM LIFECYCLE OPERATIONS
 * ============================================================ */

ozayn_ios_err_t ozayn_ios_stream_activate(ozayn_ios_service_t *svc,
                                           const char *stream_id)
{
    if (!svc) return OZAYN_IOS_ERR_NULL;
    if (!svc->initialized) return OZAYN_IOS_ERR_NOT_INITIALIZED;
    if (!stream_id || stream_id[0] == '\0')
        return OZAYN_IOS_ERR_INVALID_PARAM;

    int idx = _find_stream(svc, stream_id);
    if (idx < 0) return OZAYN_IOS_ERR_NOT_FOUND;

    ozayn_ios_stream_t *s = &svc->streams[idx];

    if (!_transition(svc, s, OZAYN_IOS_STATE_ACTIVE)) {
        svc->stats.total_errors++;
        return OZAYN_IOS_ERR_STATE_INVALID;
    }

    s->activated_time = time(NULL);
    s->last_activity_time = s->activated_time;
    svc->stats.current_opening_streams--;
    svc->stats.total_streams_active++;
    _emit_event(svc, OZAYN_IOS_EVENT_STREAM_ACTIVE, s->stream_id,
                s->device_id, s->device_session_id, "Stream active");
    return OZAYN_IOS_OK;
}

ozayn_ios_err_t ozayn_ios_stream_pause(ozayn_ios_service_t *svc,
                                        const char *stream_id)
{
    if (!svc) return OZAYN_IOS_ERR_NULL;
    if (!svc->initialized) return OZAYN_IOS_ERR_NOT_INITIALIZED;
    if (!stream_id || stream_id[0] == '\0')
        return OZAYN_IOS_ERR_INVALID_PARAM;

    int idx = _find_stream(svc, stream_id);
    if (idx < 0) return OZAYN_IOS_ERR_NOT_FOUND;

    ozayn_ios_stream_t *s = &svc->streams[idx];

    if (!_transition(svc, s, OZAYN_IOS_STATE_PAUSED)) {
        svc->stats.total_errors++;
        return OZAYN_IOS_ERR_STATE_INVALID;
    }

    svc->stats.total_streams_paused++;
    svc->stats.current_paused_streams++;
    _emit_event(svc, OZAYN_IOS_EVENT_STREAM_PAUSED, s->stream_id,
                s->device_id, s->device_session_id, "Stream paused");
    return OZAYN_IOS_OK;
}

ozayn_ios_err_t ozayn_ios_stream_resume(ozayn_ios_service_t *svc,
                                         const char *stream_id)
{
    if (!svc) return OZAYN_IOS_ERR_NULL;
    if (!svc->initialized) return OZAYN_IOS_ERR_NOT_INITIALIZED;
    if (!stream_id || stream_id[0] == '\0')
        return OZAYN_IOS_ERR_INVALID_PARAM;

    int idx = _find_stream(svc, stream_id);
    if (idx < 0) return OZAYN_IOS_ERR_NOT_FOUND;

    ozayn_ios_stream_t *s = &svc->streams[idx];

    if (!_transition(svc, s, OZAYN_IOS_STATE_ACTIVE)) {
        svc->stats.total_errors++;
        return OZAYN_IOS_ERR_STATE_INVALID;
    }

    svc->stats.current_paused_streams--;
    s->last_activity_time = time(NULL);
    _emit_event(svc, OZAYN_IOS_EVENT_STREAM_RESUMED, s->stream_id,
                s->device_id, s->device_session_id, "Stream resumed");
    return OZAYN_IOS_OK;
}

ozayn_ios_err_t ozayn_ios_stream_drain(ozayn_ios_service_t *svc,
                                        const char *stream_id)
{
    if (!svc) return OZAYN_IOS_ERR_NULL;
    if (!svc->initialized) return OZAYN_IOS_ERR_NOT_INITIALIZED;
    if (!stream_id || stream_id[0] == '\0')
        return OZAYN_IOS_ERR_INVALID_PARAM;

    int idx = _find_stream(svc, stream_id);
    if (idx < 0) return OZAYN_IOS_ERR_NOT_FOUND;

    ozayn_ios_stream_t *s = &svc->streams[idx];

    if (!_transition(svc, s, OZAYN_IOS_STATE_DRAINING)) {
        svc->stats.total_errors++;
        return OZAYN_IOS_ERR_STATE_INVALID;
    }

    svc->stats.current_draining_streams++;
    _emit_event(svc, OZAYN_IOS_EVENT_STREAM_DRAINING, s->stream_id,
                s->device_id, s->device_session_id, "Stream draining");
    return OZAYN_IOS_OK;
}

ozayn_ios_err_t ozayn_ios_stream_close(ozayn_ios_service_t *svc,
                                        const char *stream_id,
                                        ozayn_ios_close_reason_t reason)
{
    if (!svc) return OZAYN_IOS_ERR_NULL;
    if (!svc->initialized) return OZAYN_IOS_ERR_NOT_INITIALIZED;
    if (!stream_id || stream_id[0] == '\0')
        return OZAYN_IOS_ERR_INVALID_PARAM;

    int idx = _find_stream(svc, stream_id);
    if (idx < 0) return OZAYN_IOS_ERR_NOT_FOUND;

    ozayn_ios_stream_t *s = &svc->streams[idx];

    if (_is_terminal(s->state))
        return OZAYN_IOS_ERR_STATE_INVALID;

    if (s->state == OZAYN_IOS_STATE_ACTIVE ||
        s->state == OZAYN_IOS_STATE_PAUSED ||
        s->state == OZAYN_IOS_STATE_BACKPRESSURED)
        svc->stats.total_buffer_bytes_in_use -= s->buffer_occupied;

    if (s->state == OZAYN_IOS_STATE_OPENING)
        svc->stats.current_opening_streams--;
    if (s->state == OZAYN_IOS_STATE_DRAINING)
        svc->stats.current_draining_streams--;
    if (s->state == OZAYN_IOS_STATE_PAUSED)
        svc->stats.current_paused_streams--;

    _emit_event(svc, OZAYN_IOS_EVENT_STREAM_CLOSING, s->stream_id,
                s->device_id, s->device_session_id, "Stream closing");

    if (!_transition(svc, s, OZAYN_IOS_STATE_CLOSING)) {
        s->state = OZAYN_IOS_STATE_CLOSING;
    }
    if (!_transition(svc, s, OZAYN_IOS_STATE_CLOSED)) {
        s->state = OZAYN_IOS_STATE_CLOSED;
    }

    s->close_reason = reason;
    s->closed_time = time(NULL);
    s->active = 0;
    svc->stream_count--;
    svc->stats.total_streams_closed++;
    svc->stats.current_active_streams--;

    _emit_event(svc, OZAYN_IOS_EVENT_STREAM_CLOSED, s->stream_id,
                s->device_id, s->device_session_id, "Stream closed");
    return OZAYN_IOS_OK;
}

ozayn_ios_err_t ozayn_ios_stream_revoke(ozayn_ios_service_t *svc,
                                         const char *stream_id,
                                         ozayn_ios_close_reason_t reason)
{
    if (!svc) return OZAYN_IOS_ERR_NULL;
    if (!svc->initialized) return OZAYN_IOS_ERR_NOT_INITIALIZED;
    if (!stream_id || stream_id[0] == '\0')
        return OZAYN_IOS_ERR_INVALID_PARAM;

    int idx = _find_stream(svc, stream_id);
    if (idx < 0) return OZAYN_IOS_ERR_NOT_FOUND;

    ozayn_ios_stream_t *s = &svc->streams[idx];

    if (_is_terminal(s->state))
        return OZAYN_IOS_ERR_STATE_INVALID;

    if (s->state == OZAYN_IOS_STATE_ACTIVE ||
        s->state == OZAYN_IOS_STATE_PAUSED ||
        s->state == OZAYN_IOS_STATE_BACKPRESSURED)
        svc->stats.total_buffer_bytes_in_use -= s->buffer_occupied;

    if (s->state == OZAYN_IOS_STATE_OPENING)
        svc->stats.current_opening_streams--;
    if (s->state == OZAYN_IOS_STATE_DRAINING)
        svc->stats.current_draining_streams--;
    if (s->state == OZAYN_IOS_STATE_PAUSED)
        svc->stats.current_paused_streams--;

    if (!_transition(svc, s, OZAYN_IOS_STATE_REVOKED)) {
        s->state = OZAYN_IOS_STATE_REVOKED;
    }

    s->close_reason = reason;
    s->closed_time = time(NULL);
    s->active = 0;
    svc->stream_count--;
    svc->stats.total_streams_revoked++;
    svc->stats.current_active_streams--;

    _emit_event(svc, OZAYN_IOS_EVENT_STREAM_REVOKED, s->stream_id,
                s->device_id, s->device_session_id, "Stream revoked");
    return OZAYN_IOS_OK;
}

/* ============================================================
 * SECTION 6 — DATA FLOW OPERATIONS
 * ============================================================ */

ozayn_ios_err_t ozayn_ios_stream_push_data(ozayn_ios_service_t *svc,
                                            const char *stream_id,
                                            const ozayn_ios_data_unit_t *unit)
{
    if (!svc) return OZAYN_IOS_ERR_NULL;
    if (!svc->initialized) return OZAYN_IOS_ERR_NOT_INITIALIZED;
    if (!stream_id || stream_id[0] == '\0')
        return OZAYN_IOS_ERR_INVALID_PARAM;
    if (!unit) return OZAYN_IOS_ERR_INVALID_PARAM;

    int idx = _find_stream(svc, stream_id);
    if (idx < 0) return OZAYN_IOS_ERR_NOT_FOUND;

    ozayn_ios_stream_t *s = &svc->streams[idx];

    if (s->state != OZAYN_IOS_STATE_ACTIVE &&
        s->state != OZAYN_IOS_STATE_BACKPRESSURED)
        return OZAYN_IOS_ERR_STATE_INVALID;

    if (unit->payload_size > s->max_data_size)
        return OZAYN_IOS_ERR_BUFFER_LIMIT;

    if (s->queue_depth >= s->max_queue_depth) {
        switch (s->buffer_policy) {
        case OZAYN_IOS_POLICY_BLOCK:
            return OZAYN_IOS_ERR_BACKPRESSURE;
        case OZAYN_IOS_POLICY_DROP_OLDEST:
            svc->stats.total_data_units_dropped++;
            s->total_units_dropped++;
            s->queue_depth--;
            s->buffer_occupied -= s->max_data_size;
            if (s->buffer_occupied < 0) s->buffer_occupied = 0;
            break;
        case OZAYN_IOS_POLICY_DROP_NEWEST:
            svc->stats.total_data_units_dropped++;
            s->total_units_dropped++;
            return OZAYN_IOS_ERR_OVERFLOW;
        case OZAYN_IOS_POLICY_PAUSE_PRODUCER:
            return OZAYN_IOS_ERR_BACKPRESSURE;
        case OZAYN_IOS_POLICY_FAIL_STREAM:
            s->state = OZAYN_IOS_STATE_FAILED;
            s->close_reason = OZAYN_IOS_CLOSE_BUFFER_OVERFLOW;
            s->active = 0;
            svc->stream_count--;
            svc->stats.total_streams_failed++;
            svc->stats.total_overflow_events++;
            svc->stats.current_active_streams--;
            _emit_event(svc, OZAYN_IOS_EVENT_STREAM_OVERFLOW_PROTECTED,
                        s->stream_id, s->device_id, s->device_session_id,
                        "Stream failed: buffer overflow");
            return OZAYN_IOS_ERR_OVERFLOW;
        default:
            return OZAYN_IOS_ERR_BACKPRESSURE;
        }
    }

    if (s->buffer_occupied + unit->payload_size > s->max_buffer_size) {
        svc->stats.total_backpressure_events++;
        s->total_backpressure_events++;
        if (s->state != OZAYN_IOS_STATE_BACKPRESSURED) {
            s->state = OZAYN_IOS_STATE_BACKPRESSURED;
            _emit_event(svc, OZAYN_IOS_EVENT_STREAM_BACKPRESSURED,
                        s->stream_id, s->device_id, s->device_session_id,
                        "Stream backpressured");
        }
        return OZAYN_IOS_ERR_BACKPRESSURE;
    }

    s->buffer_occupied += unit->payload_size;
    s->queue_depth++;
    s->total_bytes_produced += unit->payload_size;
    s->total_units_produced++;
    svc->stats.total_data_units_produced++;
    s->last_activity_time = time(NULL);

    return OZAYN_IOS_OK;
}

ozayn_ios_err_t ozayn_ios_stream_pull_data(ozayn_ios_service_t *svc,
                                            const char *stream_id,
                                            ozayn_ios_data_unit_t *out_unit)
{
    if (!svc) return OZAYN_IOS_ERR_NULL;
    if (!svc->initialized) return OZAYN_IOS_ERR_NOT_INITIALIZED;
    if (!stream_id || stream_id[0] == '\0')
        return OZAYN_IOS_ERR_INVALID_PARAM;
    if (!out_unit) return OZAYN_IOS_ERR_INVALID_PARAM;

    int idx = _find_stream(svc, stream_id);
    if (idx < 0) return OZAYN_IOS_ERR_NOT_FOUND;

    ozayn_ios_stream_t *s = &svc->streams[idx];

    if (s->state != OZAYN_IOS_STATE_ACTIVE &&
        s->state != OZAYN_IOS_STATE_BACKPRESSURED &&
        s->state != OZAYN_IOS_STATE_DRAINING)
        return OZAYN_IOS_ERR_STATE_INVALID;

    if (s->queue_depth <= 0)
        return OZAYN_IOS_ERR_NOT_FOUND;

    int data_size = s->max_data_size < 1024 ? s->max_data_size : 1024;
    s->buffer_occupied -= data_size;
    if (s->buffer_occupied < 0) s->buffer_occupied = 0;
    s->queue_depth--;
    s->total_bytes_consumed += data_size;
    s->total_units_consumed++;
    svc->stats.total_data_units_consumed++;
    s->last_activity_time = time(NULL);

    if (s->state == OZAYN_IOS_STATE_BACKPRESSURED &&
        s->queue_depth < s->max_queue_depth / 2) {
        s->state = OZAYN_IOS_STATE_ACTIVE;
    }

    return OZAYN_IOS_OK;
}

ozayn_ios_err_t ozayn_ios_stream_heartbeat(ozayn_ios_service_t *svc,
                                            const char *stream_id)
{
    if (!svc) return OZAYN_IOS_ERR_NULL;
    if (!svc->initialized) return OZAYN_IOS_ERR_NOT_INITIALIZED;
    if (!stream_id || stream_id[0] == '\0')
        return OZAYN_IOS_ERR_INVALID_PARAM;

    int idx = _find_stream(svc, stream_id);
    if (idx < 0) return OZAYN_IOS_ERR_NOT_FOUND;

    ozayn_ios_stream_t *s = &svc->streams[idx];

    if (s->state != OZAYN_IOS_STATE_ACTIVE &&
        s->state != OZAYN_IOS_STATE_PAUSED &&
        s->state != OZAYN_IOS_STATE_BACKPRESSURED)
        return OZAYN_IOS_ERR_STATE_INVALID;

    s->last_activity_time = time(NULL);
    return OZAYN_IOS_OK;
}

/* ============================================================
 * SECTION 7 — PRODUCER / CONSUMER
 * ============================================================ */

ozayn_ios_err_t ozayn_ios_stream_attach_producer(ozayn_ios_service_t *svc,
                                                  const char *stream_id,
                                                  const char *producer_ref)
{
    if (!svc) return OZAYN_IOS_ERR_NULL;
    if (!svc->initialized) return OZAYN_IOS_ERR_NOT_INITIALIZED;
    if (!stream_id || stream_id[0] == '\0')
        return OZAYN_IOS_ERR_INVALID_PARAM;
    if (!producer_ref || producer_ref[0] == '\0')
        return OZAYN_IOS_ERR_INVALID_PARAM;

    int idx = _find_stream(svc, stream_id);
    if (idx < 0) return OZAYN_IOS_ERR_NOT_FOUND;

    ozayn_ios_stream_t *s = &svc->streams[idx];
    if (_is_terminal(s->state))
        return OZAYN_IOS_ERR_STATE_INVALID;

    strncpy(s->producer_ref, producer_ref, OZAYN_IOS_MAX_ID_LEN - 1);
    s->producer_ref[OZAYN_IOS_MAX_ID_LEN - 1] = '\0';
    return OZAYN_IOS_OK;
}

ozayn_ios_err_t ozayn_ios_stream_attach_consumer(ozayn_ios_service_t *svc,
                                                  const char *stream_id,
                                                  const char *consumer_ref)
{
    if (!svc) return OZAYN_IOS_ERR_NULL;
    if (!svc->initialized) return OZAYN_IOS_ERR_NOT_INITIALIZED;
    if (!stream_id || stream_id[0] == '\0')
        return OZAYN_IOS_ERR_INVALID_PARAM;
    if (!consumer_ref || consumer_ref[0] == '\0')
        return OZAYN_IOS_ERR_INVALID_PARAM;

    int idx = _find_stream(svc, stream_id);
    if (idx < 0) return OZAYN_IOS_ERR_NOT_FOUND;

    ozayn_ios_stream_t *s = &svc->streams[idx];
    if (_is_terminal(s->state))
        return OZAYN_IOS_ERR_STATE_INVALID;

    strncpy(s->consumer_ref, consumer_ref, OZAYN_IOS_MAX_ID_LEN - 1);
    s->consumer_ref[OZAYN_IOS_MAX_ID_LEN - 1] = '\0';
    return OZAYN_IOS_OK;
}

ozayn_ios_err_t ozayn_ios_stream_detach_producer(ozayn_ios_service_t *svc,
                                                  const char *stream_id)
{
    if (!svc) return OZAYN_IOS_ERR_NULL;
    if (!svc->initialized) return OZAYN_IOS_ERR_NOT_INITIALIZED;
    if (!stream_id || stream_id[0] == '\0')
        return OZAYN_IOS_ERR_INVALID_PARAM;

    int idx = _find_stream(svc, stream_id);
    if (idx < 0) return OZAYN_IOS_ERR_NOT_FOUND;

    ozayn_ios_stream_t *s = &svc->streams[idx];
    s->producer_ref[0] = '\0';
    return OZAYN_IOS_OK;
}

ozayn_ios_err_t ozayn_ios_stream_detach_consumer(ozayn_ios_service_t *svc,
                                                  const char *stream_id)
{
    if (!svc) return OZAYN_IOS_ERR_NULL;
    if (!svc->initialized) return OZAYN_IOS_ERR_NOT_INITIALIZED;
    if (!stream_id || stream_id[0] == '\0')
        return OZAYN_IOS_ERR_INVALID_PARAM;

    int idx = _find_stream(svc, stream_id);
    if (idx < 0) return OZAYN_IOS_ERR_NOT_FOUND;

    ozayn_ios_stream_t *s = &svc->streams[idx];
    s->consumer_ref[0] = '\0';
    return OZAYN_IOS_OK;
}

/* ============================================================
 * SECTION 8 — DEVICE DISCONNECT HANDLING
 * ============================================================ */

ozayn_ios_err_t ozayn_ios_stream_device_disconnected(
    ozayn_ios_service_t *svc, const char *stream_id)
{
    if (!svc) return OZAYN_IOS_ERR_NULL;
    if (!svc->initialized) return OZAYN_IOS_ERR_NOT_INITIALIZED;
    if (!stream_id || stream_id[0] == '\0')
        return OZAYN_IOS_ERR_INVALID_PARAM;

    int idx = _find_stream(svc, stream_id);
    if (idx < 0) return OZAYN_IOS_ERR_NOT_FOUND;

    ozayn_ios_stream_t *s = &svc->streams[idx];
    if (_is_terminal(s->state))
        return OZAYN_IOS_ERR_STATE_INVALID;

    if (s->state == OZAYN_IOS_STATE_ACTIVE ||
        s->state == OZAYN_IOS_STATE_PAUSED ||
        s->state == OZAYN_IOS_STATE_BACKPRESSURED)
        svc->stats.total_buffer_bytes_in_use -= s->buffer_occupied;

    if (s->state == OZAYN_IOS_STATE_OPENING)
        svc->stats.current_opening_streams--;
    if (s->state == OZAYN_IOS_STATE_DRAINING)
        svc->stats.current_draining_streams--;
    if (s->state == OZAYN_IOS_STATE_PAUSED)
        svc->stats.current_paused_streams--;

    s->state = OZAYN_IOS_STATE_UNAVAILABLE;
    s->close_reason = OZAYN_IOS_CLOSE_DEVICE_DISCONNECTED;
    s->closed_time = time(NULL);

    _emit_event(svc, OZAYN_IOS_EVENT_STREAM_DEVICE_DISCONNECTED,
                s->stream_id, s->device_id, s->device_session_id,
                "Device disconnected");
    return OZAYN_IOS_OK;
}

ozayn_ios_err_t ozayn_ios_stream_device_reconnected(
    ozayn_ios_service_t *svc, const char *stream_id)
{
    if (!svc) return OZAYN_IOS_ERR_NULL;
    if (!svc->initialized) return OZAYN_IOS_ERR_NOT_INITIALIZED;
    if (!stream_id || stream_id[0] == '\0')
        return OZAYN_IOS_ERR_INVALID_PARAM;

    int idx = _find_stream(svc, stream_id);
    if (idx < 0) return OZAYN_IOS_ERR_NOT_FOUND;

    ozayn_ios_stream_t *s = &svc->streams[idx];
    if (s->state != OZAYN_IOS_STATE_UNAVAILABLE)
        return OZAYN_IOS_ERR_STATE_INVALID;

    return OZAYN_IOS_OK;
}

/* ============================================================
 * SECTION 9 — SESSION CHANGE HANDLING
 * ============================================================ */

int ozayn_ios_streams_for_session(ozayn_ios_service_t *svc,
                                   const char *session_id,
                                   ozayn_ios_stream_t **out_streams,
                                   int max_out)
{
    if (!svc || !svc->initialized || !session_id || !out_streams)
        return 0;
    int count = 0;
    for (int i = 0; i < svc->config.max_streams && count < max_out; i++) {
        if (svc->streams[i].active &&
            strncmp(svc->streams[i].device_session_id, session_id,
                    OZAYN_IOS_MAX_ID_LEN) == 0) {
            out_streams[count++] = &svc->streams[i];
        }
    }
    return count;
}

/* ============================================================
 * SECTION 10 — QUERY
 * ============================================================ */

const ozayn_ios_stream_t *ozayn_ios_stream_get(
    const ozayn_ios_service_t *svc, const char *stream_id)
{
    if (!svc || !svc->initialized || !stream_id) return NULL;
    int idx = _find_stream(svc, stream_id);
    if (idx < 0) return NULL;
    return &svc->streams[idx];
}

const ozayn_ios_stream_t *ozayn_ios_stream_get_by_device(
    const ozayn_ios_service_t *svc, const char *device_id)
{
    if (!svc || !svc->initialized || !device_id) return NULL;
    for (int i = 0; i < svc->config.max_streams; i++) {
        if (svc->streams[i].active &&
            strncmp(svc->streams[i].device_id, device_id,
                    OZAYN_IOS_MAX_ID_LEN) == 0)
            return &svc->streams[i];
    }
    return NULL;
}

const ozayn_ios_stream_t *ozayn_ios_stream_get_by_session(
    const ozayn_ios_service_t *svc, const char *session_id)
{
    if (!svc || !svc->initialized || !session_id) return NULL;
    for (int i = 0; i < svc->config.max_streams; i++) {
        if (svc->streams[i].active &&
            strncmp(svc->streams[i].device_session_id, session_id,
                    OZAYN_IOS_MAX_ID_LEN) == 0)
            return &svc->streams[i];
    }
    return NULL;
}

int ozayn_ios_stream_count(const ozayn_ios_service_t *svc)
{
    if (!svc || !svc->initialized) return 0;
    return svc->stream_count;
}

int ozayn_ios_stream_count_by_device(const ozayn_ios_service_t *svc,
                                      const char *device_id)
{
    if (!svc || !svc->initialized || !device_id) return 0;
    int count = 0;
    for (int i = 0; i < svc->config.max_streams; i++) {
        if (svc->streams[i].active &&
            strncmp(svc->streams[i].device_id, device_id,
                    OZAYN_IOS_MAX_ID_LEN) == 0)
            count++;
    }
    return count;
}

int ozayn_ios_stream_count_by_session(const ozayn_ios_service_t *svc,
                                       const char *session_id)
{
    if (!svc || !svc->initialized || !session_id) return 0;
    int count = 0;
    for (int i = 0; i < svc->config.max_streams; i++) {
        if (svc->streams[i].active &&
            strncmp(svc->streams[i].device_session_id, session_id,
                    OZAYN_IOS_MAX_ID_LEN) == 0)
            count++;
    }
    return count;
}

int ozayn_ios_stream_is_active(const ozayn_ios_service_t *svc,
                                const char *stream_id)
{
    if (!svc || !svc->initialized || !stream_id) return 0;
    int idx = _find_stream(svc, stream_id);
    if (idx < 0) return 0;
    return svc->streams[idx].state == OZAYN_IOS_STATE_ACTIVE;
}

int ozayn_ios_stream_is_expired(const ozayn_ios_service_t *svc,
                                 const char *stream_id)
{
    if (!svc || !svc->initialized || !stream_id) return 0;
    int idx = _find_stream(svc, stream_id);
    if (idx < 0) return 0;
    const ozayn_ios_stream_t *s = &svc->streams[idx];
    if (!s->active) return 1;
    time_t now = time(NULL);
    return s->expiry_time > 0 && now > s->expiry_time;
}

/* ============================================================
 * SECTION 11 — EVENTS
 * ============================================================ */

ozayn_ios_err_t ozayn_ios_emit_event(ozayn_ios_service_t *svc,
                                      ozayn_ios_event_type_t type,
                                      const char *stream_id,
                                      const char *device_id,
                                      const char *session_id,
                                      const char *message)
{
    if (!svc) return OZAYN_IOS_ERR_NULL;
    if (!svc->initialized) return OZAYN_IOS_ERR_NOT_INITIALIZED;
    _emit_event(svc, type, stream_id, device_id, session_id, message);
    return OZAYN_IOS_OK;
}

const ozayn_ios_event_t *ozayn_ios_event_get(const ozayn_ios_service_t *svc,
                                              int index)
{
    if (!svc || !svc->initialized) return NULL;
    if (index < 0 || index >= svc->event_count) return NULL;
    int idx = (svc->event_head + index) % OZAYN_IOS_MAX_EVENTS;
    return &svc->events[idx];
}

int ozayn_ios_event_count(const ozayn_ios_service_t *svc)
{
    if (!svc || !svc->initialized) return 0;
    return svc->event_count;
}

/* ============================================================
 * SECTION 12 — CLEANUP
 * ============================================================ */

int ozayn_ios_cleanup_expired_streams(ozayn_ios_service_t *svc)
{
    if (!svc) return 0;
    int cleaned = 0;
    time_t now = time(NULL);
    for (int i = 0; i < svc->config.max_streams; i++) {
        if (svc->streams[i].active) {
            if (svc->streams[i].expiry_time > 0 &&
                now > svc->streams[i].expiry_time) {
                svc->streams[i].state = OZAYN_IOS_STATE_EXPIRED;
                svc->streams[i].close_reason = OZAYN_IOS_CLOSE_TIMEOUT;
                svc->streams[i].closed_time = now;
                svc->streams[i].active = 0;
                svc->stats.total_streams_expired++;
                svc->stats.current_active_streams--;
                cleaned++;
            }
        }
    }
    svc->stream_count -= cleaned;
    return cleaned;
}

int ozayn_ios_cleanup_idle_streams(ozayn_ios_service_t *svc)
{
    if (!svc) return 0;
    int cleaned = 0;
    time_t now = time(NULL);
    int idle_limit_s = svc->config.idle_timeout_ms / 1000;
    for (int i = 0; i < svc->config.max_streams; i++) {
        if (svc->streams[i].active &&
            svc->streams[i].last_activity_time > 0 &&
            (now - svc->streams[i].last_activity_time) > idle_limit_s) {
            svc->streams[i].state = OZAYN_IOS_STATE_CLOSED;
            svc->streams[i].close_reason = OZAYN_IOS_CLOSE_TIMEOUT;
            svc->streams[i].closed_time = now;
            svc->streams[i].active = 0;
            svc->stats.total_streams_closed++;
            svc->stats.current_active_streams--;
            cleaned++;
        }
    }
    svc->stream_count -= cleaned;
    return cleaned;
}

int ozayn_ios_cleanup_closed_streams(ozayn_ios_service_t *svc)
{
    if (!svc) return 0;
    int cleaned = 0;
    for (int i = 0; i < svc->config.max_streams; i++) {
        if (!svc->streams[i].active &&
            svc->streams[i].state == OZAYN_IOS_STATE_CLOSED) {
            memset(&svc->streams[i], 0, sizeof(ozayn_ios_stream_t));
            cleaned++;
        }
    }
    return cleaned;
}

int ozayn_ios_cleanup_all(ozayn_ios_service_t *svc)
{
    if (!svc) return 0;
    int cleaned = 0;
    cleaned += ozayn_ios_cleanup_expired_streams(svc);
    cleaned += ozayn_ios_cleanup_idle_streams(svc);
    cleaned += ozayn_ios_cleanup_closed_streams(svc);
    return cleaned;
}

/* ============================================================
 * SECTION 13 — STATISTICS
 * ============================================================ */

ozayn_ios_err_t ozayn_ios_get_stats(const ozayn_ios_service_t *svc,
                                     ozayn_ios_stats_t *out_stats)
{
    if (!svc) return OZAYN_IOS_ERR_NULL;
    if (!out_stats) return OZAYN_IOS_ERR_NULL;
    *out_stats = svc->stats;
    return OZAYN_IOS_OK;
}

/* ============================================================
 * SECTION 14 — VALIDATION
 * ============================================================ */

int ozayn_ios_stream_validate(const ozayn_ios_stream_t *stream)
{
    if (!stream) return 0;
    if (stream->stream_id[0] == '\0') return 0;
    if (stream->device_id[0] == '\0') return 0;
    if (stream->state < 0 || stream->state >= OZAYN_IOS_STATE_COUNT)
        return 0;
    if (stream->direction < 0 || stream->direction >= OZAYN_IOS_DIR_COUNT)
        return 0;
    if (stream->data_type < 0 || stream->data_type >= OZAYN_IOS_DATA_COUNT)
        return 0;
    if (stream->created_time <= 0) return 0;
    return 1;
}

int ozayn_ios_stream_request_validate(const ozayn_ios_stream_request_t *req)
{
    if (!req) return 0;
    if (!req->device_session_id[0]) return 0;
    if (!req->device_id[0]) return 0;
    if (!req->capability_id[0]) return 0;
    if (req->direction < 0 || req->direction >= OZAYN_IOS_DIR_COUNT)
        return 0;
    if (req->data_type < 0 || req->data_type >= OZAYN_IOS_DATA_COUNT)
        return 0;
    if (req->buffer_policy < 0 || req->buffer_policy >= OZAYN_IOS_POLICY_COUNT)
        return 0;
    if (!req->requester_ref[0]) return 0;
    return 1;
}

int ozayn_ios_state_transition_valid(ozayn_ios_stream_state_t from,
                                      ozayn_ios_stream_state_t to)
{
    if (from < 0 || from >= OZAYN_IOS_STATE_COUNT) return 0;
    if (to < 0 || to >= OZAYN_IOS_STATE_COUNT) return 0;
    return _valid_transitions[from][to];
}

/* ============================================================
 * SECTION 15 — NAME HELPERS
 * ============================================================ */

const char *ozayn_ios_err_name(ozayn_ios_err_t err)
{
    switch (err) {
    case OZAYN_IOS_OK:                          return "OK";
    case OZAYN_IOS_ERR_NULL:                    return "NULL";
    case OZAYN_IOS_ERR_NOT_INITIALIZED:         return "NOT_INITIALIZED";
    case OZAYN_IOS_ERR_ALREADY_INIT:            return "ALREADY_INIT";
    case OZAYN_IOS_ERR_INVALID_PARAM:           return "INVALID_PARAM";
    case OZAYN_IOS_ERR_LIMIT_REACHED:           return "LIMIT_REACHED";
    case OZAYN_IOS_ERR_NOT_FOUND:               return "NOT_FOUND";
    case OZAYN_IOS_ERR_STATE_INVALID:           return "STATE_INVALID";
    case OZAYN_IOS_ERR_AUTH_FAILED:             return "AUTH_FAILED";
    case OZAYN_IOS_ERR_PERMISSION_DENIED:       return "PERMISSION_DENIED";
    case OZAYN_IOS_ERR_SESSION_INVALID:         return "SESSION_INVALID";
    case OZAYN_IOS_ERR_SESSION_EXPIRED:         return "SESSION_EXPIRED";
    case OZAYN_IOS_ERR_SESSION_REVOKED:         return "SESSION_REVOKED";
    case OZAYN_IOS_ERR_DEVICE_UNAVAILABLE:      return "DEVICE_UNAVAILABLE";
    case OZAYN_IOS_ERR_CAPABILITY_INVALID:      return "CAPABILITY_INVALID";
    case OZAYN_IOS_ERR_CAPABILITY_UNAVAILABLE:  return "CAPABILITY_UNAVAILABLE";
    case OZAYN_IOS_ERR_POLICY_DENIED:           return "POLICY_DENIED";
    case OZAYN_IOS_ERR_PRECONDITION_FAILED:     return "PRECONDITION_FAILED";
    case OZAYN_IOS_ERR_RESOURCE_UNAVAILABLE:    return "RESOURCE_UNAVAILABLE";
    case OZAYN_IOS_ERR_RESOURCE_LIMIT:          return "RESOURCE_LIMIT";
    case OZAYN_IOS_ERR_BUFFER_LIMIT:            return "BUFFER_LIMIT";
    case OZAYN_IOS_ERR_QUEUE_LIMIT:             return "QUEUE_LIMIT";
    case OZAYN_IOS_ERR_RATE_LIMIT:              return "RATE_LIMIT";
    case OZAYN_IOS_ERR_BACKPRESSURE:            return "BACKPRESSURE";
    case OZAYN_IOS_ERR_OVERFLOW:                return "OVERFLOW";
    case OZAYN_IOS_ERR_TIMEOUT:                 return "TIMEOUT";
    case OZAYN_IOS_ERR_EXPIRED:                 return "EXPIRED";
    case OZAYN_IOS_ERR_REVOKED:                 return "REVOKED";
    case OZAYN_IOS_ERR_OPEN_FAILED:             return "OPEN_FAILED";
    case OZAYN_IOS_ERR_CLOSE_FAILED:            return "CLOSE_FAILED";
    case OZAYN_IOS_ERR_DEVICE_DISCONNECTED:     return "DEVICE_DISCONNECTED";
    case OZAYN_IOS_ERR_PROVIDER_ERROR:          return "PROVIDER_ERROR";
    case OZAYN_IOS_ERR_CONCURRENCY:             return "CONCURRENCY";
    case OZAYN_IOS_ERR_EXECUTION:               return "EXECUTION";
    default:                                    return "UNKNOWN";
    }
}

const char *ozayn_ios_direction_name(ozayn_ios_direction_t dir)
{
    switch (dir) {
    case OZAYN_IOS_DIR_INPUT:         return "INPUT";
    case OZAYN_IOS_DIR_OUTPUT:        return "OUTPUT";
    case OZAYN_IOS_DIR_BIDIRECTIONAL: return "BIDIRECTIONAL";
    default:                          return "UNKNOWN";
    }
}

const char *ozayn_ios_data_type_name(ozayn_ios_data_type_t dt)
{
    switch (dt) {
    case OZAYN_IOS_DATA_CAMERA_FRAME:    return "CAMERA_FRAME";
    case OZAYN_IOS_DATA_AUDIO_SAMPLE:    return "AUDIO_SAMPLE";
    case OZAYN_IOS_DATA_AUDIO_BUFFER:    return "AUDIO_BUFFER";
    case OZAYN_IOS_DATA_INPUT_EVENT:     return "INPUT_EVENT";
    case OZAYN_IOS_DATA_DISPLAY_OUTPUT:  return "DISPLAY_OUTPUT";
    case OZAYN_IOS_DATA_GPU_BUFFER:      return "GPU_BUFFER";
    case OZAYN_IOS_DATA_NETWORK_DATA:    return "NETWORK_DATA";
    case OZAYN_IOS_DATA_GENERIC_SAFE:    return "GENERIC_SAFE";
    default:                             return "UNKNOWN";
    }
}

const char *ozayn_ios_stream_state_name(ozayn_ios_stream_state_t state)
{
    switch (state) {
    case OZAYN_IOS_STATE_REQUESTED:      return "REQUESTED";
    case OZAYN_IOS_STATE_AUTHORIZING:    return "AUTHORIZING";
    case OZAYN_IOS_STATE_AUTHORIZED:     return "AUTHORIZED";
    case OZAYN_IOS_STATE_OPENING:        return "OPENING";
    case OZAYN_IOS_STATE_ACTIVE:         return "ACTIVE";
    case OZAYN_IOS_STATE_PAUSED:         return "PAUSED";
    case OZAYN_IOS_STATE_BACKPRESSURED:  return "BACKPRESSURED";
    case OZAYN_IOS_STATE_DRAINING:       return "DRAINING";
    case OZAYN_IOS_STATE_CLOSING:        return "CLOSING";
    case OZAYN_IOS_STATE_CLOSED:         return "CLOSED";
    case OZAYN_IOS_STATE_FAILED:         return "FAILED";
    case OZAYN_IOS_STATE_EXPIRED:        return "EXPIRED";
    case OZAYN_IOS_STATE_REVOKED:        return "REVOKED";
    case OZAYN_IOS_STATE_UNAVAILABLE:    return "UNAVAILABLE";
    default:                             return "UNKNOWN";
    }
}

const char *ozayn_ios_buffer_policy_name(ozayn_ios_buffer_policy_t policy)
{
    switch (policy) {
    case OZAYN_IOS_POLICY_BLOCK:           return "BLOCK";
    case OZAYN_IOS_POLICY_DROP_OLDEST:     return "DROP_OLDEST";
    case OZAYN_IOS_POLICY_DROP_NEWEST:     return "DROP_NEWEST";
    case OZAYN_IOS_POLICY_PAUSE_PRODUCER:  return "PAUSE_PRODUCER";
    case OZAYN_IOS_POLICY_FAIL_STREAM:     return "FAIL_STREAM";
    default:                               return "UNKNOWN";
    }
}

const char *ozayn_ios_close_reason_name(ozayn_ios_close_reason_t reason)
{
    switch (reason) {
    case OZAYN_IOS_CLOSE_NONE:                 return "NONE";
    case OZAYN_IOS_CLOSE_MANUAL_CLOSE:         return "MANUAL_CLOSE";
    case OZAYN_IOS_CLOSE_SESSION_EXPIRED:      return "SESSION_EXPIRED";
    case OZAYN_IOS_CLOSE_SESSION_REVOKED:      return "SESSION_REVOKED";
    case OZAYN_IOS_CLOSE_DEVICE_UNAVAILABLE:   return "DEVICE_UNAVAILABLE";
    case OZAYN_IOS_CLOSE_DEVICE_DISCONNECTED:  return "DEVICE_DISCONNECTED";
    case OZAYN_IOS_CLOSE_POLICY_CHANGED:       return "POLICY_CHANGED";
    case OZAYN_IOS_CLOSE_RESOURCE_EXHAUSTED:   return "RESOURCE_EXHAUSTED";
    case OZAYN_IOS_CLOSE_BUFFER_OVERFLOW:      return "BUFFER_OVERFLOW";
    case OZAYN_IOS_CLOSE_RATE_EXCEEDED:        return "RATE_EXCEEDED";
    case OZAYN_IOS_CLOSE_TIMEOUT:              return "TIMEOUT";
    case OZAYN_IOS_CLOSE_SYSTEM_SHUTDOWN:      return "SYSTEM_SHUTDOWN";
    case OZAYN_IOS_CLOSE_PROVIDER_ERROR:       return "PROVIDER_ERROR";
    case OZAYN_IOS_CLOSE_OPEN_FAILED:          return "OPEN_FAILED";
    case OZAYN_IOS_CLOSE_CONCURRENT_ERROR:     return "CONCURRENT_ERROR";
    default:                                   return "UNKNOWN";
    }
}

const char *ozayn_ios_event_type_name(ozayn_ios_event_type_t type)
{
    switch (type) {
    case OZAYN_IOS_EVENT_STREAM_REQUESTED:           return "STREAM_REQUESTED";
    case OZAYN_IOS_EVENT_STREAM_AUTHORIZING:         return "STREAM_AUTHORIZING";
    case OZAYN_IOS_EVENT_STREAM_AUTHORIZED:          return "STREAM_AUTHORIZED";
    case OZAYN_IOS_EVENT_STREAM_OPENING:             return "STREAM_OPENING";
    case OZAYN_IOS_EVENT_STREAM_OPENED:              return "STREAM_OPENED";
    case OZAYN_IOS_EVENT_STREAM_ACTIVE:              return "STREAM_ACTIVE";
    case OZAYN_IOS_EVENT_STREAM_PAUSED:              return "STREAM_PAUSED";
    case OZAYN_IOS_EVENT_STREAM_RESUMED:             return "STREAM_RESUMED";
    case OZAYN_IOS_EVENT_STREAM_BACKPRESSURED:       return "STREAM_BACKPRESSURED";
    case OZAYN_IOS_EVENT_STREAM_DATA_DROPPED:        return "STREAM_DATA_DROPPED";
    case OZAYN_IOS_EVENT_STREAM_OVERFLOW_PROTECTED:   return "STREAM_OVERFLOW_PROTECTED";
    case OZAYN_IOS_EVENT_STREAM_DRAINING:            return "STREAM_DRAINING";
    case OZAYN_IOS_EVENT_STREAM_CLOSING:             return "STREAM_CLOSING";
    case OZAYN_IOS_EVENT_STREAM_CLOSED:              return "STREAM_CLOSED";
    case OZAYN_IOS_EVENT_STREAM_EXPIRED:             return "STREAM_EXPIRED";
    case OZAYN_IOS_EVENT_STREAM_REVOKED:             return "STREAM_REVOKED";
    case OZAYN_IOS_EVENT_STREAM_UNAVAILABLE:         return "STREAM_UNAVAILABLE";
    case OZAYN_IOS_EVENT_STREAM_FAILED:              return "STREAM_FAILED";
    case OZAYN_IOS_EVENT_STREAM_DEVICE_DISCONNECTED: return "STREAM_DEVICE_DISCONNECTED";
    default:                                         return "UNKNOWN";
    }
}
