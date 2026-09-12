#include "device_session.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

/* ============================================================
 * SECTION 1 — INTERNAL HELPERS
 * ============================================================ */

static ozayn_das_service_t _svc;

static int _find_session(const ozayn_das_service_t *svc,
                         const char *session_id)
{
    if (!svc || !session_id) return -1;
    for (int i = 0; i < svc->config.max_sessions; i++) {
        if (svc->sessions[i].active &&
            strncmp(svc->sessions[i].session_id, session_id,
                    OZAYN_DAS_MAX_ID_LEN) == 0)
            return i;
    }
    return -1;
}

static int _find_session_slot(const ozayn_das_service_t *svc)
{
    for (int i = 0; i < svc->config.max_sessions; i++) {
        if (!svc->sessions[i].active) return i;
    }
    return -1;
}

static void _emit_event(ozayn_das_service_t *svc,
                         ozayn_das_event_type_t type,
                         const char *session_id,
                         const char *device_id,
                         const char *message)
{
    if (!svc) return;
    int idx = (svc->event_head + svc->event_count) %
              svc->config.max_sessions;
    if (svc->event_count >= OZAYN_DAS_MAX_EVENTS) {
        svc->event_head = (svc->event_head + 1) % OZAYN_DAS_MAX_EVENTS;
    } else {
        svc->event_count++;
    }
    svc->events[idx].type = type;
    strncpy(svc->events[idx].session_id, session_id ? session_id : "",
            OZAYN_DAS_MAX_ID_LEN - 1);
    svc->events[idx].session_id[OZAYN_DAS_MAX_ID_LEN - 1] = '\0';
    strncpy(svc->events[idx].device_id, device_id ? device_id : "",
            OZAYN_DAS_MAX_ID_LEN - 1);
    svc->events[idx].device_id[OZAYN_DAS_MAX_ID_LEN - 1] = '\0';
    strncpy(svc->events[idx].message, message ? message : "",
            OZAYN_DAS_MAX_DESCRIPTION_LEN - 1);
    svc->events[idx].message[OZAYN_DAS_MAX_DESCRIPTION_LEN - 1] = '\0';
    svc->events[idx].timestamp = time(NULL);
    svc->event_sequence++;
}

/* ============================================================
 * SECTION 2 — STATE MACHINE
 * ============================================================ */

static const int _valid_transitions[OZAYN_DAS_STATE_COUNT]
                                   [OZAYN_DAS_STATE_COUNT] = {
    /* REQUESTED -> */
    {   0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0 }, /* auth, cancel, fail */
    /* AUTHORIZING -> */
    {   0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1 }, /* auth, exp, canc, fail, rev */
    /* AUTHORIZED -> */
    {   0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 1, 1, 0 }, /* res, close, canc, fail */
    /* RESERVED -> */
    {   0, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 1, 0 }, /* open, close, fail */
    /* OPENING -> */
    {   0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 1, 0 }, /* active, close, fail */
    /* ACTIVE -> */
    {   0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 1, 1 }, /* idle, close, fail, rev */
    /* IDLE -> */
    {   0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 1, 1 }, /* active, close, fail, rev */
    /* CLOSING -> */
    {   0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0 }, /* closed, fail */
    /* CLOSED -> */
    {   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    /* EXPIRED -> */
    {   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    /* CANCELLED -> */
    {   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    /* FAILED -> */
    {   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    /* REVOKED -> */
    {   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }
};

/* ============================================================
 * SECTION 3 — LIFECYCLE
 * ============================================================ */

ozayn_das_err_t ozayn_das_service_init(ozayn_das_service_t *svc,
                                        const ozayn_das_service_config_t *cfg)
{
    if (!svc) return OZAYN_DAS_ERR_NULL;
    if (!cfg) return OZAYN_DAS_ERR_NULL;
    if (svc->initialized) return OZAYN_DAS_ERR_ALREADY_INIT;

    memset(svc, 0, sizeof(*svc));
    svc->config = *cfg;

    if (svc->config.max_sessions <= 0)
        svc->config.max_sessions = OZAYN_DAS_MAX_SESSIONS;
    if (svc->config.session_ttl_ms <= 0)
        svc->config.session_ttl_ms = OZAYN_DAS_DEFAULT_SESSION_TTL_MS;
    if (svc->config.idle_timeout_ms <= 0)
        svc->config.idle_timeout_ms = OZAYN_DAS_DEFAULT_IDLE_TIMEOUT_MS;

    svc->initialized = 1;
    return OZAYN_DAS_OK;
}

void ozayn_das_service_shutdown(ozayn_das_service_t *svc)
{
    if (!svc) return;
    svc->initialized = 0;
}

int ozayn_das_service_is_initialized(const ozayn_das_service_t *svc)
{
    if (!svc) return 0;
    return svc->initialized;
}

ozayn_das_service_t *ozayn_das_get_global(void)
{
    return &_svc;
}

/* ============================================================
 * SECTION 4 — SESSION MANAGEMENT
 * ============================================================ */

ozayn_das_err_t ozayn_das_session_create(ozayn_das_service_t *svc,
                                          const char *device_id,
                                          const char *capability,
                                          ozayn_das_access_mode_t access_mode,
                                          const char *reservation_id,
                                          const char *requester_ref,
                                          const char *security_session_ref,
                                          const char *operation_id,
                                          const char *required_permission,
                                          ozayn_das_session_t **out_session)
{
    if (!svc) return OZAYN_DAS_ERR_NULL;
    if (!svc->initialized) return OZAYN_DAS_ERR_NOT_INITIALIZED;
    if (!device_id || device_id[0] == '\0')
        return OZAYN_DAS_ERR_INVALID_PARAM;
    if (!capability || capability[0] == '\0')
        return OZAYN_DAS_ERR_INVALID_PARAM;
    if (access_mode < 0 || access_mode >= OZAYN_DAS_MODE_COUNT)
        return OZAYN_DAS_ERR_INVALID_PARAM;
    if (!requester_ref || requester_ref[0] == '\0')
        return OZAYN_DAS_ERR_INVALID_PARAM;
    if (!out_session) return OZAYN_DAS_ERR_NULL;

    int slot = _find_session_slot(svc);
    if (slot < 0) return OZAYN_DAS_ERR_LIMIT_REACHED;

    svc->session_sequence++;
    ozayn_das_session_t *s = &svc->sessions[slot];
    memset(s, 0, sizeof(*s));
    snprintf(s->session_id, OZAYN_DAS_MAX_ID_LEN, "DAS-%u",
             svc->session_sequence);
    strncpy(s->device_id, device_id, OZAYN_DAS_MAX_ID_LEN - 1);
    strncpy(s->capability, capability, OZAYN_DAS_MAX_ID_LEN - 1);
    s->access_mode = access_mode;
    if (reservation_id)
        strncpy(s->reservation_id, reservation_id,
                OZAYN_DAS_MAX_ID_LEN - 1);
    strncpy(s->requester_ref, requester_ref, OZAYN_DAS_MAX_ID_LEN - 1);
    if (security_session_ref)
        strncpy(s->security_session_ref, security_session_ref,
                OZAYN_DAS_MAX_ID_LEN - 1);
    if (operation_id)
        strncpy(s->operation_id, operation_id, OZAYN_DAS_MAX_ID_LEN - 1);
    if (required_permission)
        strncpy(s->required_permission, required_permission,
                OZAYN_DAS_MAX_PERMISSION_LEN - 1);

    s->state = OZAYN_DAS_STATE_REQUESTED;
    s->close_reason = OZAYN_DAS_CLOSE_NONE;
    s->created_time = time(NULL);
    s->expiry_time = s->created_time +
                     (svc->config.session_ttl_ms / 1000);
    s->active = 1;

    svc->session_count++;
    svc->stats.total_sessions_created++;
    svc->stats.current_active_sessions++;

    _emit_event(svc, OZAYN_DAS_EVENT_SESSION_REQUESTED, s->session_id,
                device_id, "Session requested");

    *out_session = s;
    return OZAYN_DAS_OK;
}

static int _transition(ozayn_das_service_t *svc,
                       ozayn_das_session_t *s,
                       ozayn_das_session_state_t new_state)
{
    if (!_valid_transitions[s->state][new_state]) {
        svc->stats.total_validation_failures++;
        return 0;
    }
    s->state = new_state;
    svc->stats.total_state_transitions++;
    return 1;
}

ozayn_das_err_t ozayn_das_session_authorize(ozayn_das_service_t *svc,
                                             const char *session_id)
{
    if (!svc) return OZAYN_DAS_ERR_NULL;
    if (!svc->initialized) return OZAYN_DAS_ERR_NOT_INITIALIZED;
    if (!session_id || session_id[0] == '\0')
        return OZAYN_DAS_ERR_INVALID_PARAM;

    int idx = _find_session(svc, session_id);
    if (idx < 0) return OZAYN_DAS_ERR_NOT_FOUND;

    ozayn_das_session_t *s = &svc->sessions[idx];

    time_t now = time(NULL);
    if (s->expiry_time > 0 && now > s->expiry_time) {
        s->state = OZAYN_DAS_STATE_EXPIRED;
        s->close_reason = OZAYN_DAS_CLOSE_TIMEOUT;
        s->closed_time = now;
        s->active = 0;
        svc->session_count--;
        svc->stats.total_sessions_expired++;
        svc->stats.current_active_sessions--;
        _emit_event(svc, OZAYN_DAS_EVENT_SESSION_EXPIRED, s->session_id,
                    s->device_id, "Session expired during authorization");
        return OZAYN_DAS_ERR_EXPIRED;
    }

    if (!_transition(svc, s, OZAYN_DAS_STATE_AUTHORIZING)) {
        svc->stats.total_errors++;
        _emit_event(svc, OZAYN_DAS_EVENT_SESSION_FAILED, s->session_id,
                    s->device_id, "Invalid state for authorization");
        return OZAYN_DAS_ERR_STATE_INVALID;
    }

    if (!_transition(svc, s, OZAYN_DAS_STATE_AUTHORIZED)) {
        s->state = OZAYN_DAS_STATE_FAILED;
        s->close_reason = OZAYN_DAS_CLOSE_CONCURRENT_ERROR;
        s->active = 0;
        svc->session_count--;
        svc->stats.total_sessions_failed++;
        svc->stats.current_active_sessions--;
        return OZAYN_DAS_ERR_STATE_INVALID;
    }

    svc->stats.total_sessions_authorized++;
    _emit_event(svc, OZAYN_DAS_EVENT_SESSION_AUTHORIZED, s->session_id,
                s->device_id, "Session authorized");
    return OZAYN_DAS_OK;
}

ozayn_das_err_t ozayn_das_session_reserve(ozayn_das_service_t *svc,
                                           const char *session_id)
{
    if (!svc) return OZAYN_DAS_ERR_NULL;
    if (!svc->initialized) return OZAYN_DAS_ERR_NOT_INITIALIZED;
    if (!session_id || session_id[0] == '\0')
        return OZAYN_DAS_ERR_INVALID_PARAM;

    int idx = _find_session(svc, session_id);
    if (idx < 0) return OZAYN_DAS_ERR_NOT_FOUND;

    ozayn_das_session_t *s = &svc->sessions[idx];

    if (s->reservation_id[0] == '\0')
        return OZAYN_DAS_ERR_RESERVATION_INVALID;

    if (!_transition(svc, s, OZAYN_DAS_STATE_RESERVED)) {
        svc->stats.total_errors++;
        return OZAYN_DAS_ERR_STATE_INVALID;
    }

    _emit_event(svc, OZAYN_DAS_EVENT_SESSION_RESERVED, s->session_id,
                s->device_id, "Session reserved");
    return OZAYN_DAS_OK;
}

ozayn_das_err_t ozayn_das_session_open(ozayn_das_service_t *svc,
                                        const char *session_id)
{
    if (!svc) return OZAYN_DAS_ERR_NULL;
    if (!svc->initialized) return OZAYN_DAS_ERR_NOT_INITIALIZED;
    if (!session_id || session_id[0] == '\0')
        return OZAYN_DAS_ERR_INVALID_PARAM;

    int idx = _find_session(svc, session_id);
    if (idx < 0) return OZAYN_DAS_ERR_NOT_FOUND;

    ozayn_das_session_t *s = &svc->sessions[idx];

    if (!_transition(svc, s, OZAYN_DAS_STATE_OPENING)) {
        svc->stats.total_errors++;
        return OZAYN_DAS_ERR_STATE_INVALID;
    }

    svc->stats.current_opening_sessions++;
    _emit_event(svc, OZAYN_DAS_EVENT_SESSION_OPENING, s->session_id,
                s->device_id, "Session opening");
    return OZAYN_DAS_OK;
}

ozayn_das_err_t ozayn_das_session_activate(ozayn_das_service_t *svc,
                                            const char *session_id)
{
    if (!svc) return OZAYN_DAS_ERR_NULL;
    if (!svc->initialized) return OZAYN_DAS_ERR_NOT_INITIALIZED;
    if (!session_id || session_id[0] == '\0')
        return OZAYN_DAS_ERR_INVALID_PARAM;

    int idx = _find_session(svc, session_id);
    if (idx < 0) return OZAYN_DAS_ERR_NOT_FOUND;

    ozayn_das_session_t *s = &svc->sessions[idx];

    if (!_transition(svc, s, OZAYN_DAS_STATE_ACTIVE)) {
        svc->stats.total_errors++;
        return OZAYN_DAS_ERR_STATE_INVALID;
    }

    s->activated_time = time(NULL);
    s->last_activity_time = s->activated_time;
    svc->stats.current_opening_sessions--;
    svc->stats.total_sessions_opened++;
    _emit_event(svc, OZAYN_DAS_EVENT_SESSION_ACTIVE, s->session_id,
                s->device_id, "Session active");
    return OZAYN_DAS_OK;
}

ozayn_das_err_t ozayn_das_session_set_idle(ozayn_das_service_t *svc,
                                            const char *session_id)
{
    if (!svc) return OZAYN_DAS_ERR_NULL;
    if (!svc->initialized) return OZAYN_DAS_ERR_NOT_INITIALIZED;
    if (!session_id || session_id[0] == '\0')
        return OZAYN_DAS_ERR_INVALID_PARAM;

    int idx = _find_session(svc, session_id);
    if (idx < 0) return OZAYN_DAS_ERR_NOT_FOUND;

    ozayn_das_session_t *s = &svc->sessions[idx];

    if (!_transition(svc, s, OZAYN_DAS_STATE_IDLE)) {
        svc->stats.total_errors++;
        return OZAYN_DAS_ERR_STATE_INVALID;
    }

    svc->stats.current_idle_sessions++;
    _emit_event(svc, OZAYN_DAS_EVENT_SESSION_IDLE, s->session_id,
                s->device_id, "Session idle");
    return OZAYN_DAS_OK;
}

ozayn_das_err_t ozayn_das_session_close(ozayn_das_service_t *svc,
                                         const char *session_id,
                                         ozayn_das_close_reason_t reason)
{
    if (!svc) return OZAYN_DAS_ERR_NULL;
    if (!svc->initialized) return OZAYN_DAS_ERR_NOT_INITIALIZED;
    if (!session_id || session_id[0] == '\0')
        return OZAYN_DAS_ERR_INVALID_PARAM;

    int idx = _find_session(svc, session_id);
    if (idx < 0) return OZAYN_DAS_ERR_NOT_FOUND;

    ozayn_das_session_t *s = &svc->sessions[idx];

    if (s->state == OZAYN_DAS_STATE_CLOSED ||
        s->state == OZAYN_DAS_STATE_EXPIRED ||
        s->state == OZAYN_DAS_STATE_CANCELLED ||
        s->state == OZAYN_DAS_STATE_FAILED ||
        s->state == OZAYN_DAS_STATE_REVOKED)
        return OZAYN_DAS_ERR_STATE_INVALID;

    if (s->state == OZAYN_DAS_STATE_ACTIVE ||
        s->state == OZAYN_DAS_STATE_IDLE)
        svc->stats.current_idle_sessions--;

    if (s->state == OZAYN_DAS_STATE_OPENING)
        svc->stats.current_opening_sessions--;

    _emit_event(svc, OZAYN_DAS_EVENT_SESSION_CLOSING, s->session_id,
                s->device_id, "Session closing");

    if (!_transition(svc, s, OZAYN_DAS_STATE_CLOSING)) {
        s->state = OZAYN_DAS_STATE_CLOSED;
    }
    if (!_transition(svc, s, OZAYN_DAS_STATE_CLOSED)) {
        s->state = OZAYN_DAS_STATE_CLOSED;
    }

    s->close_reason = reason;
    s->closed_time = time(NULL);
    s->active = 0;
    svc->session_count--;
    svc->stats.total_sessions_closed++;
    svc->stats.current_active_sessions--;

    _emit_event(svc, OZAYN_DAS_EVENT_SESSION_CLOSED, s->session_id,
                s->device_id, "Session closed");
    return OZAYN_DAS_OK;
}

ozayn_das_err_t ozayn_das_session_revoke(ozayn_das_service_t *svc,
                                          const char *session_id,
                                          ozayn_das_close_reason_t reason)
{
    if (!svc) return OZAYN_DAS_ERR_NULL;
    if (!svc->initialized) return OZAYN_DAS_ERR_NOT_INITIALIZED;
    if (!session_id || session_id[0] == '\0')
        return OZAYN_DAS_ERR_INVALID_PARAM;

    int idx = _find_session(svc, session_id);
    if (idx < 0) return OZAYN_DAS_ERR_NOT_FOUND;

    ozayn_das_session_t *s = &svc->sessions[idx];

    if (s->state == OZAYN_DAS_STATE_CLOSED ||
        s->state == OZAYN_DAS_STATE_EXPIRED ||
        s->state == OZAYN_DAS_STATE_CANCELLED ||
        s->state == OZAYN_DAS_STATE_FAILED ||
        s->state == OZAYN_DAS_STATE_REVOKED)
        return OZAYN_DAS_ERR_STATE_INVALID;

    if (s->state == OZAYN_DAS_STATE_ACTIVE ||
        s->state == OZAYN_DAS_STATE_IDLE)
        svc->stats.current_idle_sessions--;

    if (s->state == OZAYN_DAS_STATE_OPENING)
        svc->stats.current_opening_sessions--;

    if (!_transition(svc, s, OZAYN_DAS_STATE_REVOKED)) {
        s->state = OZAYN_DAS_STATE_REVOKED;
    }

    s->close_reason = reason;
    s->closed_time = time(NULL);
    s->active = 0;
    svc->session_count--;
    svc->stats.total_sessions_revoked++;
    svc->stats.current_active_sessions--;

    _emit_event(svc, OZAYN_DAS_EVENT_SESSION_REVOKED, s->session_id,
                s->device_id, "Session revoked");
    return OZAYN_DAS_OK;
}

ozayn_das_err_t ozayn_das_session_cancel(ozayn_das_service_t *svc,
                                          const char *session_id)
{
    if (!svc) return OZAYN_DAS_ERR_NULL;
    if (!svc->initialized) return OZAYN_DAS_ERR_NOT_INITIALIZED;
    if (!session_id || session_id[0] == '\0')
        return OZAYN_DAS_ERR_INVALID_PARAM;

    int idx = _find_session(svc, session_id);
    if (idx < 0) return OZAYN_DAS_ERR_NOT_FOUND;

    ozayn_das_session_t *s = &svc->sessions[idx];

    if (s->state == OZAYN_DAS_STATE_CLOSED ||
        s->state == OZAYN_DAS_STATE_EXPIRED ||
        s->state == OZAYN_DAS_STATE_CANCELLED ||
        s->state == OZAYN_DAS_STATE_FAILED ||
        s->state == OZAYN_DAS_STATE_REVOKED)
        return OZAYN_DAS_ERR_STATE_INVALID;

    if (!_transition(svc, s, OZAYN_DAS_STATE_CANCELLED)) {
        s->state = OZAYN_DAS_STATE_CANCELLED;
    }

    s->close_reason = OZAYN_DAS_CLOSE_MANUAL_CLOSE;
    s->closed_time = time(NULL);
    s->active = 0;
    svc->session_count--;
    svc->stats.total_sessions_cancelled++;
    svc->stats.current_active_sessions--;

    _emit_event(svc, OZAYN_DAS_EVENT_SESSION_FAILED, s->session_id,
                s->device_id, "Session cancelled");
    return OZAYN_DAS_OK;
}

ozayn_das_err_t ozayn_das_session_heartbeat(ozayn_das_service_t *svc,
                                             const char *session_id)
{
    if (!svc) return OZAYN_DAS_ERR_NULL;
    if (!svc->initialized) return OZAYN_DAS_ERR_NOT_INITIALIZED;
    if (!session_id || session_id[0] == '\0')
        return OZAYN_DAS_ERR_INVALID_PARAM;

    int idx = _find_session(svc, session_id);
    if (idx < 0) return OZAYN_DAS_ERR_NOT_FOUND;

    ozayn_das_session_t *s = &svc->sessions[idx];

    if (s->state != OZAYN_DAS_STATE_ACTIVE &&
        s->state != OZAYN_DAS_STATE_IDLE)
        return OZAYN_DAS_ERR_STATE_INVALID;

    s->last_activity_time = time(NULL);
    svc->stats.total_heartbeats++;

    _emit_event(svc, OZAYN_DAS_EVENT_SESSION_HEARTBEAT, s->session_id,
                s->device_id, "Heartbeat");
    return OZAYN_DAS_OK;
}

/* ============================================================
 * SECTION 5 — SESSION QUERY
 * ============================================================ */

const ozayn_das_session_t *ozayn_das_session_get(
    const ozayn_das_service_t *svc,
    const char *session_id)
{
    if (!svc || !svc->initialized || !session_id) return NULL;
    int idx = _find_session(svc, session_id);
    if (idx < 0) return NULL;
    return &svc->sessions[idx];
}

const ozayn_das_session_t *ozayn_das_session_get_by_device(
    const ozayn_das_service_t *svc,
    const char *device_id)
{
    if (!svc || !svc->initialized || !device_id) return NULL;
    for (int i = 0; i < svc->config.max_sessions; i++) {
        if (svc->sessions[i].active &&
            strncmp(svc->sessions[i].device_id, device_id,
                    OZAYN_DAS_MAX_ID_LEN) == 0)
            return &svc->sessions[i];
    }
    return NULL;
}

const ozayn_das_session_t *ozayn_das_session_get_by_reservation(
    const ozayn_das_service_t *svc,
    const char *reservation_id)
{
    if (!svc || !svc->initialized || !reservation_id) return NULL;
    for (int i = 0; i < svc->config.max_sessions; i++) {
        if (svc->sessions[i].active &&
            strncmp(svc->sessions[i].reservation_id, reservation_id,
                    OZAYN_DAS_MAX_ID_LEN) == 0)
            return &svc->sessions[i];
    }
    return NULL;
}

int ozayn_das_session_count(const ozayn_das_service_t *svc)
{
    if (!svc || !svc->initialized) return 0;
    return svc->session_count;
}

int ozayn_das_session_count_by_device(const ozayn_das_service_t *svc,
                                      const char *device_id)
{
    if (!svc || !svc->initialized || !device_id) return 0;
    int count = 0;
    for (int i = 0; i < svc->config.max_sessions; i++) {
        if (svc->sessions[i].active &&
            strncmp(svc->sessions[i].device_id, device_id,
                    OZAYN_DAS_MAX_ID_LEN) == 0)
            count++;
    }
    return count;
}

int ozayn_das_session_is_active(const ozayn_das_service_t *svc,
                                const char *session_id)
{
    if (!svc || !svc->initialized || !session_id) return 0;
    int idx = _find_session(svc, session_id);
    if (idx < 0) return 0;
    return svc->sessions[idx].state == OZAYN_DAS_STATE_ACTIVE;
}

int ozayn_das_session_is_expired(const ozayn_das_service_t *svc,
                                 const char *session_id)
{
    if (!svc || !svc->initialized || !session_id) return 0;
    int idx = _find_session(svc, session_id);
    if (idx < 0) return 0;
    const ozayn_das_session_t *s = &svc->sessions[idx];
    if (!s->active) return 1;
    time_t now = time(NULL);
    return s->expiry_time > 0 && now > s->expiry_time;
}

/* ============================================================
 * SECTION 6 — EVENTS
 * ============================================================ */

ozayn_das_err_t ozayn_das_emit_event(ozayn_das_service_t *svc,
                                      ozayn_das_event_type_t type,
                                      const char *session_id,
                                      const char *device_id,
                                      const char *message)
{
    if (!svc) return OZAYN_DAS_ERR_NULL;
    if (!svc->initialized) return OZAYN_DAS_ERR_NOT_INITIALIZED;
    _emit_event(svc, type, session_id, device_id, message);
    return OZAYN_DAS_OK;
}

const ozayn_das_event_t *ozayn_das_event_get(const ozayn_das_service_t *svc,
                                              int index)
{
    if (!svc || !svc->initialized) return NULL;
    if (index < 0 || index >= svc->event_count) return NULL;
    int idx = (svc->event_head + index) % OZAYN_DAS_MAX_EVENTS;
    return &svc->events[idx];
}

int ozayn_das_event_count(const ozayn_das_service_t *svc)
{
    if (!svc || !svc->initialized) return 0;
    return svc->event_count;
}

/* ============================================================
 * SECTION 7 — CLEANUP
 * ============================================================ */

int ozayn_das_cleanup_expired_sessions(ozayn_das_service_t *svc)
{
    if (!svc) return 0;
    int cleaned = 0;
    time_t now = time(NULL);
    for (int i = 0; i < svc->config.max_sessions; i++) {
        if (svc->sessions[i].active) {
            if (svc->sessions[i].expiry_time > 0 &&
                now > svc->sessions[i].expiry_time) {
                svc->sessions[i].state = OZAYN_DAS_STATE_EXPIRED;
                svc->sessions[i].close_reason = OZAYN_DAS_CLOSE_TIMEOUT;
                svc->sessions[i].closed_time = now;
                svc->sessions[i].active = 0;
                svc->stats.total_sessions_expired++;
                svc->stats.current_active_sessions--;
                cleaned++;
            }
        }
    }
    svc->session_count -= cleaned;
    return cleaned;
}

int ozayn_das_cleanup_idle_sessions(ozayn_das_service_t *svc)
{
    if (!svc) return 0;
    int cleaned = 0;
    time_t now = time(NULL);
    int idle_limit_s = svc->config.idle_timeout_ms / 1000;
    for (int i = 0; i < svc->config.max_sessions; i++) {
        if (svc->sessions[i].active &&
            svc->sessions[i].state == OZAYN_DAS_STATE_IDLE) {
            if (svc->sessions[i].last_activity_time > 0 &&
                (now - svc->sessions[i].last_activity_time) > idle_limit_s) {
                svc->sessions[i].state = OZAYN_DAS_STATE_CLOSING;
                svc->sessions[i].close_reason = OZAYN_DAS_CLOSE_TIMEOUT;
                svc->sessions[i].state = OZAYN_DAS_STATE_CLOSED;
                svc->sessions[i].closed_time = now;
                svc->sessions[i].active = 0;
                svc->stats.total_sessions_expired++;
                svc->stats.current_active_sessions--;
                svc->stats.current_idle_sessions--;
                cleaned++;
            }
        }
    }
    svc->session_count -= cleaned;
    return cleaned;
}

int ozayn_das_cleanup_all(ozayn_das_service_t *svc)
{
    if (!svc) return 0;
    int cleaned = 0;
    cleaned += ozayn_das_cleanup_expired_sessions(svc);
    cleaned += ozayn_das_cleanup_idle_sessions(svc);
    return cleaned;
}

/* ============================================================
 * SECTION 8 — STATISTICS
 * ============================================================ */

ozayn_das_err_t ozayn_das_get_stats(const ozayn_das_service_t *svc,
                                     ozayn_das_stats_t *out_stats)
{
    if (!svc) return OZAYN_DAS_ERR_NULL;
    if (!out_stats) return OZAYN_DAS_ERR_NULL;
    *out_stats = svc->stats;
    return OZAYN_DAS_OK;
}

/* ============================================================
 * SECTION 9 — VALIDATION
 * ============================================================ */

int ozayn_das_session_validate(const ozayn_das_session_t *session)
{
    if (!session) return 0;
    if (session->session_id[0] == '\0') return 0;
    if (session->device_id[0] == '\0') return 0;
    if (session->state < 0 || session->state >= OZAYN_DAS_STATE_COUNT)
        return 0;
    if (session->access_mode < 0 || session->access_mode >= OZAYN_DAS_MODE_COUNT)
        return 0;
    if (session->created_time <= 0) return 0;
    return 1;
}

int ozayn_das_state_transition_valid(ozayn_das_session_state_t from,
                                     ozayn_das_session_state_t to)
{
    if (from < 0 || from >= OZAYN_DAS_STATE_COUNT) return 0;
    if (to < 0 || to >= OZAYN_DAS_STATE_COUNT) return 0;
    return _valid_transitions[from][to];
}

/* ============================================================
 * SECTION 10 — NAME HELPERS
 * ============================================================ */

const char *ozayn_das_access_mode_name(ozayn_das_access_mode_t mode)
{
    switch (mode) {
    case OZAYN_DAS_MODE_OBSERVE:   return "OBSERVE";
    case OZAYN_DAS_MODE_INPUT:     return "INPUT";
    case OZAYN_DAS_MODE_OUTPUT:    return "OUTPUT";
    case OZAYN_DAS_MODE_CONTROL:   return "CONTROL";
    case OZAYN_DAS_MODE_STREAM:    return "STREAM";
    default:                       return "UNKNOWN";
    }
}

const char *ozayn_das_session_state_name(ozayn_das_session_state_t state)
{
    switch (state) {
    case OZAYN_DAS_STATE_REQUESTED:   return "REQUESTED";
    case OZAYN_DAS_STATE_AUTHORIZING: return "AUTHORIZING";
    case OZAYN_DAS_STATE_AUTHORIZED:  return "AUTHORIZED";
    case OZAYN_DAS_STATE_RESERVED:    return "RESERVED";
    case OZAYN_DAS_STATE_OPENING:     return "OPENING";
    case OZAYN_DAS_STATE_ACTIVE:      return "ACTIVE";
    case OZAYN_DAS_STATE_IDLE:        return "IDLE";
    case OZAYN_DAS_STATE_CLOSING:     return "CLOSING";
    case OZAYN_DAS_STATE_CLOSED:      return "CLOSED";
    case OZAYN_DAS_STATE_EXPIRED:     return "EXPIRED";
    case OZAYN_DAS_STATE_CANCELLED:   return "CANCELLED";
    case OZAYN_DAS_STATE_FAILED:      return "FAILED";
    case OZAYN_DAS_STATE_REVOKED:     return "REVOKED";
    default:                          return "UNKNOWN";
    }
}

const char *ozayn_das_close_reason_name(ozayn_das_close_reason_t reason)
{
    switch (reason) {
    case OZAYN_DAS_CLOSE_NONE:               return "NONE";
    case OZAYN_DAS_CLOSE_SECURITY_EXPIRED:   return "SECURITY_EXPIRED";
    case OZAYN_DAS_CLOSE_AUTH_REVOKED:       return "AUTH_REVOKED";
    case OZAYN_DAS_CLOSE_RESERVATION_EXPIRED:return "RESERVATION_EXPIRED";
    case OZAYN_DAS_CLOSE_DEVICE_UNAVAILABLE: return "DEVICE_UNAVAILABLE";
    case OZAYN_DAS_CLOSE_DEVICE_ERROR:       return "DEVICE_ERROR";
    case OZAYN_DAS_CLOSE_POLICY_CHANGED:     return "POLICY_CHANGED";
    case OZAYN_DAS_CLOSE_RESOURCE_LIMIT:     return "RESOURCE_LIMIT";
    case OZAYN_DAS_CLOSE_MANUAL_CLOSE:       return "MANUAL_CLOSE";
    case OZAYN_DAS_CLOSE_TIMEOUT:            return "TIMEOUT";
    case OZAYN_DAS_CLOSE_SYSTEM_SHUTDOWN:    return "SYSTEM_SHUTDOWN";
    case OZAYN_DAS_CLOSE_PROVIDER_ERROR:     return "PROVIDER_ERROR";
    case OZAYN_DAS_CLOSE_OPEN_FAILED:        return "OPEN_FAILED";
    case OZAYN_DAS_CLOSE_CONCURRENT_ERROR:   return "CONCURRENT_ERROR";
    default:                                 return "UNKNOWN";
    }
}

const char *ozayn_das_event_type_name(ozayn_das_event_type_t type)
{
    switch (type) {
    case OZAYN_DAS_EVENT_SESSION_REQUESTED:  return "SESSION_REQUESTED";
    case OZAYN_DAS_EVENT_SESSION_AUTHORIZED: return "SESSION_AUTHORIZED";
    case OZAYN_DAS_EVENT_SESSION_REJECTED:   return "SESSION_REJECTED";
    case OZAYN_DAS_EVENT_SESSION_RESERVED:   return "SESSION_RESERVED";
    case OZAYN_DAS_EVENT_SESSION_OPENING:    return "SESSION_OPENING";
    case OZAYN_DAS_EVENT_SESSION_ACTIVE:     return "SESSION_ACTIVE";
    case OZAYN_DAS_EVENT_SESSION_IDLE:       return "SESSION_IDLE";
    case OZAYN_DAS_EVENT_SESSION_CLOSING:    return "SESSION_CLOSING";
    case OZAYN_DAS_EVENT_SESSION_CLOSED:     return "SESSION_CLOSED";
    case OZAYN_DAS_EVENT_SESSION_EXPIRED:    return "SESSION_EXPIRED";
    case OZAYN_DAS_EVENT_SESSION_REVOKED:    return "SESSION_REVOKED";
    case OZAYN_DAS_EVENT_SESSION_FAILED:     return "SESSION_FAILED";
    case OZAYN_DAS_EVENT_SESSION_HEARTBEAT:  return "SESSION_HEARTBEAT";
    default:                                 return "UNKNOWN";
    }
}

const char *ozayn_das_err_name(ozayn_das_err_t err)
{
    switch (err) {
    case OZAYN_DAS_OK:                          return "OK";
    case OZAYN_DAS_ERR_NULL:                    return "NULL";
    case OZAYN_DAS_ERR_NOT_INITIALIZED:         return "NOT_INITIALIZED";
    case OZAYN_DAS_ERR_ALREADY_INIT:            return "ALREADY_INIT";
    case OZAYN_DAS_ERR_INVALID_PARAM:           return "INVALID_PARAM";
    case OZAYN_DAS_ERR_LIMIT_REACHED:           return "LIMIT_REACHED";
    case OZAYN_DAS_ERR_NOT_FOUND:               return "NOT_FOUND";
    case OZAYN_DAS_ERR_STATE_INVALID:           return "STATE_INVALID";
    case OZAYN_DAS_ERR_AUTH_FAILED:             return "AUTH_FAILED";
    case OZAYN_DAS_ERR_PERMISSION_DENIED:       return "PERMISSION_DENIED";
    case OZAYN_DAS_ERR_RESERVATION_INVALID:     return "RESERVATION_INVALID";
    case OZAYN_DAS_ERR_RESERVATION_EXPIRED:     return "RESERVATION_EXPIRED";
    case OZAYN_DAS_ERR_DEVICE_UNAVAILABLE:      return "DEVICE_UNAVAILABLE";
    case OZAYN_DAS_ERR_CAPABILITY_UNAVAILABLE:  return "CAPABILITY_UNAVAILABLE";
    case OZAYN_DAS_ERR_OPEN_FAILED:             return "OPEN_FAILED";
    case OZAYN_DAS_ERR_CLOSE_FAILED:            return "CLOSE_FAILED";
    case OZAYN_DAS_ERR_TIMEOUT:                 return "TIMEOUT";
    case OZAYN_DAS_ERR_EXPIRED:                 return "EXPIRED";
    case OZAYN_DAS_ERR_REVOKED:                 return "REVOKED";
    case OZAYN_DAS_ERR_RESOURCE_UNAVAILABLE:    return "RESOURCE_UNAVAILABLE";
    case OZAYN_DAS_ERR_POLICY_DENIED:           return "POLICY_DENIED";
    case OZAYN_DAS_ERR_SECURITY_INVALID:        return "SECURITY_INVALID";
    case OZAYN_DAS_ERR_PROVIDER_ERROR:          return "PROVIDER_ERROR";
    case OZAYN_DAS_ERR_CONCURRENCY:             return "CONCURRENCY";
    default:                                    return "UNKNOWN";
    }
}
