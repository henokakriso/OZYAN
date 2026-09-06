#include "session_management.h"
#include <sodium.h>
#include <string.h>

/* ============================================================
 * VALIDATION
 * ============================================================ */

int ozayn_sess_validate_state(ozayn_sess_state_t state)
{
    if (state < OZAYN_SESS_STATE_UNINITIALIZED ||
        state > OZAYN_SESS_STATE_TERMINATED)
        return -1;
    return 0;
}

int ozayn_sess_validate_policy(const ozayn_sess_policy_t *policy)
{
    if (!policy)
        return -1;
    if (policy->enabled == 0)
        return 0;
    if (policy->max_sessions_total < 1)
        return -1;
    if (policy->max_sessions_per_identity < 1)
        return -1;
    if (policy->idle_timeout_seconds < 1)
        return -1;
    if (policy->absolute_lifetime_seconds < 1)
        return -1;
    if (policy->idle_timeout_seconds > policy->absolute_lifetime_seconds)
        return -1;
    return 0;
}

int ozayn_sess_validate_transition(ozayn_sess_state_t from,
                                    ozayn_sess_state_t to)
{
    if (ozayn_sess_validate_state(from) != 0)
        return -1;
    if (ozayn_sess_validate_state(to) != 0)
        return -1;

    switch (from) {
        case OZAYN_SESS_STATE_UNINITIALIZED:
            return (to == OZAYN_SESS_STATE_ACTIVE) ? 0 : -1;
        case OZAYN_SESS_STATE_ACTIVE:
            return (to == OZAYN_SESS_STATE_EXPIRED ||
                    to == OZAYN_SESS_STATE_REVOKED ||
                    to == OZAYN_SESS_STATE_TERMINATED) ? 0 : -1;
        case OZAYN_SESS_STATE_EXPIRED:
        case OZAYN_SESS_STATE_REVOKED:
        case OZAYN_SESS_STATE_TERMINATED:
            return -1;
        default:
            return -1;
    }
}

int ozayn_sess_validate_id(const char *session_id)
{
    if (!session_id)
        return -1;
    if (session_id[0] == '\0')
        return -1;
    size_t len = strlen(session_id);
    if (len < 8 || len >= OZAYN_SESS_MAX_ID_LEN)
        return -1;
    return 0;
}

/* ============================================================
 * NAME HELPERS
 * ============================================================ */

const char *ozayn_sess_state_name(ozayn_sess_state_t state)
{
    switch (state) {
        case OZAYN_SESS_STATE_UNINITIALIZED: return "UNINITIALIZED";
        case OZAYN_SESS_STATE_ACTIVE:        return "ACTIVE";
        case OZAYN_SESS_STATE_EXPIRED:       return "EXPIRED";
        case OZAYN_SESS_STATE_REVOKED:       return "REVOKED";
        case OZAYN_SESS_STATE_TERMINATED:    return "TERMINATED";
        default:                             return "UNKNOWN";
    }
}

const char *ozayn_sess_error_name(ozayn_sess_error_t error)
{
    switch (error) {
        case OZAYN_SESS_OK:                          return "OK";
        case OZAYN_SESS_ERR_NULL:                    return "NULL";
        case OZAYN_SESS_ERR_NOT_INITIALIZED:         return "NOT_INITIALIZED";
        case OZAYN_SESS_ERR_NOT_FOUND:               return "NOT_FOUND";
        case OZAYN_SESS_ERR_INVALID:                 return "INVALID";
        case OZAYN_SESS_ERR_ID_INVALID:              return "ID_INVALID";
        case OZAYN_SESS_ERR_ID_GENERATION_FAILED:    return "ID_GENERATION_FAILED";
        case OZAYN_SESS_ERR_IDENTITY_INVALID:        return "IDENTITY_INVALID";
        case OZAYN_SESS_ERR_IDENTITY_REVOKED:        return "IDENTITY_REVOKED";
        case OZAYN_SESS_ERR_IDENTITY_SUSPENDED:      return "IDENTITY_SUSPENDED";
        case OZAYN_SESS_ERR_AUTH_REQUIRED:           return "AUTH_REQUIRED";
        case OZAYN_SESS_ERR_AUTH_FAILED:             return "AUTH_FAILED";
        case OZAYN_SESS_ERR_STATE_INVALID:           return "STATE_INVALID";
        case OZAYN_SESS_ERR_STATE_TRANSITION_INVALID:return "STATE_TRANSITION_INVALID";
        case OZAYN_SESS_ERR_EXPIRED:                 return "EXPIRED";
        case OZAYN_SESS_ERR_REVOKED:                 return "REVOKED";
        case OZAYN_SESS_ERR_TERMINATED:              return "TERMINATED";
        case OZAYN_SESS_ERR_LIMIT_REACHED:           return "LIMIT_REACHED";
        case OZAYN_SESS_ERR_POLICY_INVALID:          return "POLICY_INVALID";
        case OZAYN_SESS_ERR_TIMEOUT_INVALID:         return "TIMEOUT_INVALID";
        case OZAYN_SESS_ERR_UNAVAILABLE:             return "UNAVAILABLE";
        default:                                     return "UNKNOWN";
    }
}

/* ============================================================
 * DEFAULT / TEST POLICIES
 * ============================================================ */

ozayn_sess_policy_t ozayn_sess_default_policy(void)
{
    ozayn_sess_policy_t p;
    memset(&p, 0, sizeof(p));
    p.enabled                   = 1;
    p.max_sessions_total        = 512;
    p.max_sessions_per_identity = 8;
    p.idle_timeout_seconds      = 1800;
    p.absolute_lifetime_seconds = 86400;
    return p;
}

ozayn_sess_policy_t ozayn_sess_test_policy(void)
{
    ozayn_sess_policy_t p;
    memset(&p, 0, sizeof(p));
    p.enabled                   = 1;
    p.max_sessions_total        = 32;
    p.max_sessions_per_identity = 4;
    p.idle_timeout_seconds      = 5;
    p.absolute_lifetime_seconds = 30;
    return p;
}

/* ============================================================
 * INTERNAL: SESSION ID GENERATION
 * ============================================================ */

static ozayn_sess_error_t _generate_session_id(char *buf, size_t buf_size)
{
    if (!buf || buf_size < OZAYN_SESS_MAX_ID_LEN)
        return OZAYN_SESS_ERR_NULL;

    unsigned char random_bytes[OZAYN_SESS_ID_BYTES];
    randombytes_buf(random_bytes, sizeof(random_bytes));

    char *result = sodium_bin2base64(buf, buf_size,
                                      random_bytes, sizeof(random_bytes),
                                      sodium_base64_VARIANT_URLSAFE_NO_PADDING);
    if (!result)
        return OZAYN_SESS_ERR_ID_GENERATION_FAILED;

    return OZAYN_SESS_OK;
}

/* ============================================================
 * INTERNAL: FIND SESSION
 * ============================================================ */

static ozayn_sess_t *_find_session(ozayn_sess_service_t *svc,
                                    const char *session_id)
{
    if (!svc || !session_id)
        return NULL;
    for (int i = 0; i < svc->session_count; i++) {
        if (svc->sessions[i].in_use &&
            strcmp(svc->sessions[i].id, session_id) == 0)
            return &svc->sessions[i];
    }
    return NULL;
}

/* ============================================================
 * INTERNAL: COUNT SESSIONS PER IDENTITY
 * ============================================================ */

static int _count_sessions_for_identity(const ozayn_sess_service_t *svc,
                                         const char *identity_id)
{
    int count = 0;
    for (int i = 0; i < svc->session_count; i++) {
        if (svc->sessions[i].in_use &&
            svc->sessions[i].state == OZAYN_SESS_STATE_ACTIVE &&
            strcmp(svc->sessions[i].identity_id, identity_id) == 0)
            count++;
    }
    return count;
}

/* ============================================================
 * SERVICE LIFECYCLE
 * ============================================================ */

ozayn_sess_error_t ozayn_sess_service_init(
    ozayn_sess_service_t *svc,
    const ozayn_sess_service_config_t *config)
{
    if (!svc || !config)
        return OZAYN_SESS_ERR_NULL;
    if (!config->identity_service)
        return OZAYN_SESS_ERR_IDENTITY_INVALID;
    if (ozayn_sess_validate_policy(&config->policy) != 0)
        return OZAYN_SESS_ERR_POLICY_INVALID;

    memset(svc, 0, sizeof(*svc));
    svc->config = *config;
    svc->initialized = 1;

    return OZAYN_SESS_OK;
}

void ozayn_sess_service_shutdown(ozayn_sess_service_t *svc)
{
    if (!svc)
        return;

    for (int i = 0; i < svc->session_count; i++) {
        if (svc->sessions[i].in_use) {
            sodium_memzero(&svc->sessions[i], sizeof(svc->sessions[i]));
        }
    }

    svc->session_count = 0;
    svc->initialized = 0;
}

/* ============================================================
 * CREATE SESSION
 * ============================================================ */

ozayn_sess_error_t ozayn_sess_create(
    ozayn_sess_service_t *svc,
    const ozayn_authn_response_t *auth_response,
    ozayn_sess_t *out_session)
{
    if (!svc || !auth_response || !out_session)
        return OZAYN_SESS_ERR_NULL;
    if (!svc->initialized)
        return OZAYN_SESS_ERR_NOT_INITIALIZED;

    if (!svc->config.policy.enabled)
        return OZAYN_SESS_ERR_UNAVAILABLE;

    if (auth_response->result != OZAYN_AuthN_RESULT_SUCCESS ||
        auth_response->verification != OZAYN_AuthN_VERIFY_VERIFIED)
        return OZAYN_SESS_ERR_AUTH_FAILED;

    if (auth_response->identity_id[0] == '\0')
        return OZAYN_SESS_ERR_IDENTITY_INVALID;

    ozayn_identity_t identity;
    ozayn_identity_result_t id_r = ozayn_id_get(
        svc->config.identity_service,
        auth_response->identity_id,
        &identity);
    if (id_r != OZAYN_ID_OK)
        return OZAYN_SESS_ERR_IDENTITY_INVALID;

    if (identity.state == OZAYN_ID_STATE_REVOKED)
        return OZAYN_SESS_ERR_IDENTITY_REVOKED;
    if (identity.state == OZAYN_ID_STATE_SUSPENDED)
        return OZAYN_SESS_ERR_IDENTITY_SUSPENDED;

    if (svc->session_count >= svc->config.policy.max_sessions_total)
        return OZAYN_SESS_ERR_LIMIT_REACHED;

    if (_count_sessions_for_identity(svc, auth_response->identity_id) >=
        svc->config.policy.max_sessions_per_identity)
        return OZAYN_SESS_ERR_LIMIT_REACHED;

    ozayn_sess_t *session = &svc->sessions[svc->session_count];
    memset(session, 0, sizeof(*session));

    ozayn_sess_error_t gen_r = _generate_session_id(session->id,
                                                     sizeof(session->id));
    if (gen_r != OZAYN_SESS_OK)
        return gen_r;

    strncpy(session->identity_id, auth_response->identity_id,
            sizeof(session->identity_id) - 1);
    session->method = auth_response->method;
    session->state = OZAYN_SESS_STATE_ACTIVE;
    session->created_at = auth_response->auth_time;
    session->last_activity_at = auth_response->auth_time;
    session->expires_at = auth_response->auth_time +
        svc->config.policy.idle_timeout_seconds;
    session->absolute_expires_at = auth_response->auth_time +
        svc->config.policy.absolute_lifetime_seconds;
    session->version = 1;
    session->in_use = 1;

    svc->session_count++;

    *out_session = *session;

    return OZAYN_SESS_OK;
}

/* ============================================================
 * VALIDATE SESSION
 * ============================================================ */

ozayn_sess_error_t ozayn_sess_validate(
    ozayn_sess_service_t *svc,
    const char *session_id,
    ozayn_sess_t *out_session)
{
    if (!svc || !session_id || !out_session)
        return OZAYN_SESS_ERR_NULL;
    if (!svc->initialized)
        return OZAYN_SESS_ERR_NOT_INITIALIZED;

    ozayn_sess_t *session = _find_session(svc, session_id);
    if (!session)
        return OZAYN_SESS_ERR_NOT_FOUND;

    if (session->state == OZAYN_SESS_STATE_EXPIRED) {
        *out_session = *session;
        return OZAYN_SESS_ERR_EXPIRED;
    }
    if (session->state == OZAYN_SESS_STATE_REVOKED) {
        *out_session = *session;
        return OZAYN_SESS_ERR_REVOKED;
    }
    if (session->state == OZAYN_SESS_STATE_TERMINATED) {
        *out_session = *session;
        return OZAYN_SESS_ERR_TERMINATED;
    }
    if (session->state != OZAYN_SESS_STATE_ACTIVE) {
        *out_session = *session;
        return OZAYN_SESS_ERR_STATE_INVALID;
    }

    time_t now = time(NULL);
    if (now >= session->expires_at) {
        session->state = OZAYN_SESS_STATE_EXPIRED;
        session->version++;
        *out_session = *session;
        return OZAYN_SESS_ERR_EXPIRED;
    }
    if (now >= session->absolute_expires_at) {
        session->state = OZAYN_SESS_STATE_EXPIRED;
        session->version++;
        *out_session = *session;
        return OZAYN_SESS_ERR_EXPIRED;
    }

    ozayn_identity_t identity;
    ozayn_identity_result_t id_r = ozayn_id_get(
        svc->config.identity_service,
        session->identity_id,
        &identity);
    if (id_r != OZAYN_ID_OK) {
        session->state = OZAYN_SESS_STATE_REVOKED;
        session->version++;
        *out_session = *session;
        return OZAYN_SESS_ERR_IDENTITY_INVALID;
    }
    if (identity.state == OZAYN_ID_STATE_REVOKED) {
        session->state = OZAYN_SESS_STATE_REVOKED;
        session->version++;
        *out_session = *session;
        return OZAYN_SESS_ERR_IDENTITY_REVOKED;
    }
    if (identity.state == OZAYN_ID_STATE_SUSPENDED) {
        session->state = OZAYN_SESS_STATE_REVOKED;
        session->version++;
        *out_session = *session;
        return OZAYN_SESS_ERR_IDENTITY_SUSPENDED;
    }

    *out_session = *session;
    return OZAYN_SESS_OK;
}

/* ============================================================
 * GET SESSION (without validation)
 * ============================================================ */

ozayn_sess_error_t ozayn_sess_get(
    ozayn_sess_service_t *svc,
    const char *session_id,
    ozayn_sess_t *out_session)
{
    if (!svc || !session_id || !out_session)
        return OZAYN_SESS_ERR_NULL;
    if (!svc->initialized)
        return OZAYN_SESS_ERR_NOT_INITIALIZED;

    ozayn_sess_t *session = _find_session(svc, session_id);
    if (!session)
        return OZAYN_SESS_ERR_NOT_FOUND;

    *out_session = *session;
    return OZAYN_SESS_OK;
}

/* ============================================================
 * TOUCH (record activity)
 * ============================================================ */

ozayn_sess_error_t ozayn_sess_touch(
    ozayn_sess_service_t *svc,
    const char *session_id)
{
    if (!svc || !session_id)
        return OZAYN_SESS_ERR_NULL;
    if (!svc->initialized)
        return OZAYN_SESS_ERR_NOT_INITIALIZED;

    ozayn_sess_t *session = _find_session(svc, session_id);
    if (!session)
        return OZAYN_SESS_ERR_NOT_FOUND;

    if (session->state != OZAYN_SESS_STATE_ACTIVE)
        return OZAYN_SESS_ERR_STATE_INVALID;

    time_t now = time(NULL);
    session->last_activity_at = now;
    session->expires_at = now + svc->config.policy.idle_timeout_seconds;
    session->version++;

    return OZAYN_SESS_OK;
}

/* ============================================================
 * TERMINATE
 * ============================================================ */

ozayn_sess_error_t ozayn_sess_terminate(
    ozayn_sess_service_t *svc,
    const char *session_id)
{
    if (!svc || !session_id)
        return OZAYN_SESS_ERR_NULL;
    if (!svc->initialized)
        return OZAYN_SESS_ERR_NOT_INITIALIZED;

    ozayn_sess_t *session = _find_session(svc, session_id);
    if (!session)
        return OZAYN_SESS_ERR_NOT_FOUND;

    if (session->state == OZAYN_SESS_STATE_TERMINATED)
        return OZAYN_SESS_OK;

    if (session->state == OZAYN_SESS_STATE_ACTIVE) {
        time_t now = time(NULL);
        if (now >= session->expires_at ||
            now >= session->absolute_expires_at) {
            session->state = OZAYN_SESS_STATE_EXPIRED;
            session->version++;
            return OZAYN_SESS_ERR_STATE_TRANSITION_INVALID;
        }
    }

    if (ozayn_sess_validate_transition(session->state,
                                       OZAYN_SESS_STATE_TERMINATED) != 0)
        return OZAYN_SESS_ERR_STATE_TRANSITION_INVALID;

    session->state = OZAYN_SESS_STATE_TERMINATED;
    session->version++;

    return OZAYN_SESS_OK;
}

/* ============================================================
 * REVOKE
 * ============================================================ */

ozayn_sess_error_t ozayn_sess_revoke(
    ozayn_sess_service_t *svc,
    const char *session_id)
{
    if (!svc || !session_id)
        return OZAYN_SESS_ERR_NULL;
    if (!svc->initialized)
        return OZAYN_SESS_ERR_NOT_INITIALIZED;

    ozayn_sess_t *session = _find_session(svc, session_id);
    if (!session)
        return OZAYN_SESS_ERR_NOT_FOUND;

    if (session->state == OZAYN_SESS_STATE_REVOKED)
        return OZAYN_SESS_OK;

    if (session->state == OZAYN_SESS_STATE_ACTIVE) {
        time_t now = time(NULL);
        if (now >= session->expires_at ||
            now >= session->absolute_expires_at) {
            session->state = OZAYN_SESS_STATE_EXPIRED;
            session->version++;
            return OZAYN_SESS_ERR_STATE_TRANSITION_INVALID;
        }
    }

    if (ozayn_sess_validate_transition(session->state,
                                       OZAYN_SESS_STATE_REVOKED) != 0)
        return OZAYN_SESS_ERR_STATE_TRANSITION_INVALID;

    session->state = OZAYN_SESS_STATE_REVOKED;
    session->version++;

    return OZAYN_SESS_OK;
}

/* ============================================================
 * EXPIRE
 * ============================================================ */

ozayn_sess_error_t ozayn_sess_expire(
    ozayn_sess_service_t *svc)
{
    if (!svc)
        return OZAYN_SESS_ERR_NULL;
    if (!svc->initialized)
        return OZAYN_SESS_ERR_NOT_INITIALIZED;

    time_t now = time(NULL);

    for (int i = 0; i < svc->session_count; i++) {
        ozayn_sess_t *s = &svc->sessions[i];
        if (!s->in_use || s->state != OZAYN_SESS_STATE_ACTIVE)
            continue;

        if (now >= s->expires_at || now >= s->absolute_expires_at) {
            s->state = OZAYN_SESS_STATE_EXPIRED;
            s->version++;
        }
    }

    return OZAYN_SESS_OK;
}

/* ============================================================
 * QUERY
 * ============================================================ */

int ozayn_sess_service_is_initialized(const ozayn_sess_service_t *svc)
{
    if (!svc)
        return 0;
    return svc->initialized;
}

int ozayn_sess_service_session_count(const ozayn_sess_service_t *svc)
{
    if (!svc || !svc->initialized)
        return 0;
    int count = 0;
    for (int i = 0; i < svc->session_count; i++) {
        if (svc->sessions[i].in_use)
            count++;
    }
    return count;
}
