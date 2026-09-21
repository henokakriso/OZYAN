/*
 * operational_access.c — Section 04, Step 28
 * Operational Access, Session & Command Authority Management Foundation
 */

#include "operational_access.h"
#include <string.h>
#include <stdio.h>
#include <time.h>

/* ============================================================
 * INTERNAL HELPERS
 * ============================================================ */

static uint64_t _next_id = 1;

static uint64_t _gen_id(void) {
    return _next_id++;
}

static int _find_context_index(const ozayn_oac_service_t *svc, uint64_t ctx_id) {
    for (int i = 0; i < svc->context_count && i < OZAYN_OAC_MAX_ACCESS_CONTEXTS; i++) {
        if (svc->contexts[i].active && svc->contexts[i].context_id[0] != '\0') {
            char id_str[32];
            snprintf(id_str, sizeof(id_str), "%lu", (unsigned long)ctx_id);
            if (strcmp(svc->contexts[i].context_id, id_str) == 0) return i;
        }
    }
    return -1;
}

static int _find_authority_index(const ozayn_oac_service_t *svc, uint64_t auth_id) {
    for (int i = 0; i < svc->authority_count && i < OZAYN_OAC_MAX_AUTHORITIES; i++) {
        if (svc->authorities[i].active && svc->authorities[i].authority_id[0] != '\0') {
            char id_str[32];
            snprintf(id_str, sizeof(id_str), "%lu", (unsigned long)auth_id);
            if (strcmp(svc->authorities[i].authority_id, id_str) == 0) return i;
        }
    }
    return -1;
}

static void _record_validation(ozayn_oac_service_t *svc,
                                const char *auth_id,
                                const char *session_id,
                                ozayn_oac_event_type_t evt,
                                int result_code) {
    if (svc->validation_count >= OZAYN_OAC_MAX_VALIDATION_LOG) {
        svc->validation_head = (svc->validation_head + 1) % OZAYN_OAC_MAX_VALIDATION_LOG;
        if (svc->validation_count > OZAYN_OAC_MAX_VALIDATION_LOG)
            svc->validation_count = OZAYN_OAC_MAX_VALIDATION_LOG;
    } else {
        svc->validation_head = (svc->validation_head + svc->validation_count) % OZAYN_OAC_MAX_VALIDATION_LOG;
    }
    int idx = svc->validation_head;
    memset(&svc->validation_log[idx], 0, sizeof(ozayn_oac_validation_entry_t));
    if (auth_id) strncpy(svc->validation_log[idx].authority_id, auth_id, OZAYN_OAC_MAX_ID_LEN - 1);
    if (session_id) strncpy(svc->validation_log[idx].session_id, session_id, OZAYN_OAC_MAX_SESSION_LEN - 1);
    svc->validation_log[idx].event_type = evt;
    svc->validation_log[idx].timestamp = time(0);
    svc->validation_log[idx].result_code = result_code;
    if (svc->validation_count < OZAYN_OAC_MAX_VALIDATION_LOG)
        svc->validation_count++;
}

static void _add_to_history(ozayn_oac_service_t *svc, const ozayn_oac_authority_t *auth) {
    if (svc->history_count >= OZAYN_OAC_MAX_AUTHORITY_HISTORY) {
        memmove(&svc->authority_history[0], &svc->authority_history[1],
                sizeof(ozayn_oac_authority_t) * (OZAYN_OAC_MAX_AUTHORITY_HISTORY - 1));
        svc->history_count = OZAYN_OAC_MAX_AUTHORITY_HISTORY - 1;
    }
    svc->authority_history[svc->history_count] = *auth;
    svc->history_count++;
}

/* ============================================================
 * NAME HELPERS
 * ============================================================ */

const char *ozayn_oac_err_name(ozayn_oac_err_t err) {
    switch (err) {
        case OZAYN_OAC_OK:                      return "OK";
        case OZAYN_OAC_ERR_NULL:                return "NULL";
        case OZAYN_OAC_ERR_NOT_INITIALIZED:     return "NOT_INITIALIZED";
        case OZAYN_OAC_ERR_ALREADY_INITIALIZED: return "ALREADY_INITIALIZED";
        case OZAYN_OAC_ERR_NOT_FOUND:           return "NOT_FOUND";
        case OZAYN_OAC_ERR_FULL:                return "FULL";
        case OZAYN_OAC_ERR_DUPLICATE:           return "DUPLICATE";
        case OZAYN_OAC_ERR_STATE_TRANSITION:    return "STATE_TRANSITION";
        case OZAYN_OAC_ERR_INVALID_PARAM:       return "INVALID_PARAM";
        case OZAYN_OAC_ERR_ACCESS_INVALID:      return "ACCESS_INVALID";
        case OZAYN_OAC_ERR_ACCESS_DENIED:       return "ACCESS_DENIED";
        case OZAYN_OAC_ERR_ACCESS_EXPIRED:      return "ACCESS_EXPIRED";
        case OZAYN_OAC_ERR_ACCESS_REVOKED:      return "ACCESS_REVOKED";
        case OZAYN_OAC_ERR_SESSION_INVALID:     return "SESSION_INVALID";
        case OZAYN_OAC_ERR_SESSION_EXPIRED:     return "SESSION_EXPIRED";
        case OZAYN_OAC_ERR_SESSION_REVOKED:     return "SESSION_REVOKED";
        case OZAYN_OAC_ERR_SESSION_MISMATCH:    return "SESSION_MISMATCH";
        case OZAYN_OAC_ERR_AUTHORITY_INVALID:   return "AUTHORITY_INVALID";
        case OZAYN_OAC_ERR_AUTHORITY_EXPIRED:   return "AUTHORITY_EXPIRED";
        case OZAYN_OAC_ERR_AUTHORITY_REVOKED:   return "AUTHORITY_REVOKED";
        case OZAYN_OAC_ERR_AUTHORITY_CONSUMED:  return "AUTHORITY_CONSUMED";
        case OZAYN_OAC_ERR_AUTHORITY_MISMATCH:  return "AUTHORITY_MISMATCH";
        case OZAYN_OAC_ERR_AUTHORITY_DUPLICATE: return "AUTHORITY_DUPLICATE";
        case OZAYN_OAC_ERR_AUTHORITY_SCOPE:     return "AUTHORITY_SCOPE";
        case OZAYN_OAC_ERR_IDENTITY_MISMATCH:   return "IDENTITY_MISMATCH";
        case OZAYN_OAC_ERR_AUTHORIZATION_UNAVAIL: return "AUTHORIZATION_UNAVAIL";
        case OZAYN_OAC_ERR_AUTHORIZATION_FAILED:  return "AUTHORIZATION_FAILED";
        case OZAYN_OAC_ERR_PERMISSION_DENIED:   return "PERMISSION_DENIED";
        case OZAYN_OAC_ERR_CONCURRENCY:         return "CONCURRENCY";
        case OZAYN_OAC_ERR_STORAGE:             return "STORAGE";
        case OZAYN_OAC_ERR_AUDIT:               return "AUDIT";
        case OZAYN_OAC_ERR_EVENT:               return "EVENT";
    }
    return "UNKNOWN";
}

const char *ozayn_oac_access_level_name(ozayn_oac_access_level_t level) {
    switch (level) {
        case OZAYN_OAC_LEVEL_NONE:       return "NONE";
        case OZAYN_OAC_LEVEL_OBSERVE:    return "OBSERVE";
        case OZAYN_OAC_LEVEL_DIAGNOSTIC: return "DIAGNOSTIC";
        case OZAYN_OAC_LEVEL_OPERATE:    return "OPERATE";
        case OZAYN_OAC_LEVEL_ADMIN:      return "ADMIN";
    }
    return "UNKNOWN";
}

const char *ozayn_oac_ctx_state_name(ozayn_oac_ctx_state_t state) {
    switch (state) {
        case OZAYN_OAC_CTX_CREATED:    return "CREATED";
        case OZAYN_OAC_CTX_ACTIVE:     return "ACTIVE";
        case OZAYN_OAC_CTX_VALIDATED:  return "VALIDATED";
        case OZAYN_OAC_CTX_EXPIRED:    return "EXPIRED";
        case OZAYN_OAC_CTX_REVOKED:    return "REVOKED";
        case OZAYN_OAC_CTX_TERMINATED: return "TERMINATED";
    }
    return "UNKNOWN";
}

const char *ozayn_oac_auth_state_name(ozayn_oac_auth_state_t state) {
    switch (state) {
        case OZAYN_OAC_AUTH_REQUESTED:  return "REQUESTED";
        case OZAYN_OAC_AUTH_VALIDATING: return "VALIDATING";
        case OZAYN_OAC_AUTH_AUTHORIZED: return "AUTHORIZED";
        case OZAYN_OAC_AUTH_DENIED:     return "DENIED";
        case OZAYN_OAC_AUTH_EXPIRED:    return "EXPIRED";
        case OZAYN_OAC_AUTH_REVOKED:    return "REVOKED";
        case OZAYN_OAC_AUTH_INVALID:    return "INVALID";
        case OZAYN_OAC_AUTH_CONSUMED:   return "CONSUMED";
        case OZAYN_OAC_AUTH_CANCELLED:  return "CANCELLED";
    }
    return "UNKNOWN";
}

const char *ozayn_oac_scope_type_name(ozayn_oac_scope_type_t scope) {
    switch (scope) {
        case OZAYN_OAC_SCOPE_SYSTEM_WIDE:         return "SYSTEM_WIDE";
        case OZAYN_OAC_SCOPE_COMPONENT_SPECIFIC:   return "COMPONENT_SPECIFIC";
        case OZAYN_OAC_SCOPE_CAPABILITY_SPECIFIC:  return "CAPABILITY_SPECIFIC";
        case OZAYN_OAC_SCOPE_OPERATION_SPECIFIC:   return "OPERATION_SPECIFIC";
        case OZAYN_OAC_SCOPE_WORKFLOW_SPECIFIC:    return "WORKFLOW_SPECIFIC";
        case OZAYN_OAC_SCOPE_DEVICE_SPECIFIC:      return "DEVICE_SPECIFIC";
        case OZAYN_OAC_SCOPE_RESOURCE_SPECIFIC:    return "RESOURCE_SPECIFIC";
    }
    return "UNKNOWN";
}

const char *ozayn_oac_event_type_name(ozayn_oac_event_type_t evt) {
    switch (evt) {
        case OZAYN_OAC_EVT_ACCESS_CREATED:          return "ACCESS_CREATED";
        case OZAYN_OAC_EVT_ACCESS_VALIDATED:        return "ACCESS_VALIDATED";
        case OZAYN_OAC_EVT_ACCESS_DENIED:           return "ACCESS_DENIED";
        case OZAYN_OAC_EVT_ACCESS_EXPIRED:          return "ACCESS_EXPIRED";
        case OZAYN_OAC_EVT_ACCESS_REVOKED:          return "ACCESS_REVOKED";
        case OZAYN_OAC_EVT_AUTHORITY_REQUESTED:     return "AUTHORITY_REQUESTED";
        case OZAYN_OAC_EVT_AUTHORITY_GRANTED:       return "AUTHORITY_GRANTED";
        case OZAYN_OAC_EVT_AUTHORITY_DENIED:        return "AUTHORITY_DENIED";
        case OZAYN_OAC_EVT_AUTHORITY_EXPIRED:       return "AUTHORITY_EXPIRED";
        case OZAYN_OAC_EVT_AUTHORITY_REVOKED:       return "AUTHORITY_REVOKED";
        case OZAYN_OAC_EVT_AUTHORITY_CONSUMED:      return "AUTHORITY_CONSUMED";
        case OZAYN_OAC_EVT_AUTHORITY_INVALIDATED:   return "AUTHORITY_INVALIDATED";
        case OZAYN_OAC_EVT_DUPLICATE_ATTEMPT:       return "DUPLICATE_ATTEMPT";
        case OZAYN_OAC_EVT_STALE_AUTHORITY:         return "STALE_AUTHORITY";
        case OZAYN_OAC_EVT_SESSION_INVALIDATED:     return "SESSION_INVALIDATED";
        case OZAYN_OAC_EVT_MODE_CHANGE_INVALIDATED: return "MODE_CHANGE_INVALIDATED";
    }
    return "UNKNOWN";
}

/* ============================================================
 * STATE TRANSITION VALIDATION
 * ============================================================ */

int ozayn_oac_ctx_state_transition_valid(ozayn_oac_ctx_state_t from, ozayn_oac_ctx_state_t to) {
    switch (from) {
        case OZAYN_OAC_CTX_CREATED:
            return to == OZAYN_OAC_CTX_ACTIVE || to == OZAYN_OAC_CTX_TERMINATED;
        case OZAYN_OAC_CTX_ACTIVE:
            return to == OZAYN_OAC_CTX_VALIDATED || to == OZAYN_OAC_CTX_EXPIRED ||
                   to == OZAYN_OAC_CTX_REVOKED || to == OZAYN_OAC_CTX_TERMINATED;
        case OZAYN_OAC_CTX_VALIDATED:
            return to == OZAYN_OAC_CTX_ACTIVE || to == OZAYN_OAC_CTX_EXPIRED ||
                   to == OZAYN_OAC_CTX_REVOKED || to == OZAYN_OAC_CTX_TERMINATED;
        case OZAYN_OAC_CTX_EXPIRED:
        case OZAYN_OAC_CTX_REVOKED:
        case OZAYN_OAC_CTX_TERMINATED:
            return 0;
    }
    return 0;
}

int ozayn_oac_auth_state_transition_valid(ozayn_oac_auth_state_t from, ozayn_oac_auth_state_t to) {
    switch (from) {
        case OZAYN_OAC_AUTH_REQUESTED:
            return to == OZAYN_OAC_AUTH_VALIDATING || to == OZAYN_OAC_AUTH_DENIED ||
                   to == OZAYN_OAC_AUTH_CANCELLED || to == OZAYN_OAC_AUTH_EXPIRED ||
                   to == OZAYN_OAC_AUTH_REVOKED;
        case OZAYN_OAC_AUTH_VALIDATING:
            return to == OZAYN_OAC_AUTH_AUTHORIZED || to == OZAYN_OAC_AUTH_DENIED ||
                   to == OZAYN_OAC_AUTH_INVALID || to == OZAYN_OAC_AUTH_CANCELLED;
        case OZAYN_OAC_AUTH_AUTHORIZED:
            return to == OZAYN_OAC_AUTH_CONSUMED || to == OZAYN_OAC_AUTH_EXPIRED ||
                   to == OZAYN_OAC_AUTH_REVOKED || to == OZAYN_OAC_AUTH_INVALID ||
                   to == OZAYN_OAC_AUTH_CANCELLED;
        case OZAYN_OAC_AUTH_DENIED:
        case OZAYN_OAC_AUTH_EXPIRED:
        case OZAYN_OAC_AUTH_REVOKED:
        case OZAYN_OAC_AUTH_INVALID:
        case OZAYN_OAC_AUTH_CONSUMED:
        case OZAYN_OAC_AUTH_CANCELLED:
            return 0;
    }
    return 0;
}

/* ============================================================
 * LIFECYCLE
 * ============================================================ */

ozayn_oac_err_t ozayn_oac_init(ozayn_oac_service_t *svc) {
    if (!svc) return OZAYN_OAC_ERR_NULL;
    if (svc->initialized) return OZAYN_OAC_ERR_ALREADY_INITIALIZED;
    memset(svc, 0, sizeof(ozayn_oac_service_t));
    svc->initialized = 1;
    return OZAYN_OAC_OK;
}

ozayn_oac_err_t ozayn_oac_shutdown(ozayn_oac_service_t *svc) {
    if (!svc) return OZAYN_OAC_ERR_NULL;
    if (!svc->initialized) return OZAYN_OAC_ERR_NOT_INITIALIZED;
    svc->initialized = 0;
    return OZAYN_OAC_OK;
}

int ozayn_oac_is_initialized(const ozayn_oac_service_t *svc) {
    if (!svc) return 0;
    return svc->initialized;
}

/* ============================================================
 * SUBSYSTEM BIND
 * ============================================================ */

ozayn_oac_err_t ozayn_oac_bind_subsystems(ozayn_oac_service_t *svc, const ozayn_oac_subsys_bind_t *bind) {
    if (!svc || !bind) return OZAYN_OAC_ERR_NULL;
    if (!svc->initialized) return OZAYN_OAC_ERR_NOT_INITIALIZED;
    svc->bind = *bind;
    return OZAYN_OAC_OK;
}

/* ============================================================
 * ACCESS CONTEXT
 * ============================================================ */

ozayn_oac_err_t ozayn_oac_context_create(ozayn_oac_service_t *svc,
                                          const char *identity_id,
                                          const char *session_id,
                                          const char *authorization_ref,
                                          ozayn_oac_access_level_t level,
                                          ozayn_oac_scope_type_t scope_type,
                                          const char *scope_target,
                                          uint64_t lifetime_seconds,
                                          uint64_t *out_context_id) {
    if (!svc) return OZAYN_OAC_ERR_NULL;
    if (!svc->initialized) return OZAYN_OAC_ERR_NOT_INITIALIZED;
    if (!identity_id || !session_id || !out_context_id) return OZAYN_OAC_ERR_INVALID_PARAM;
    if (svc->context_count >= OZAYN_OAC_MAX_ACCESS_CONTEXTS) return OZAYN_OAC_ERR_FULL;

    ozayn_oac_access_ctx_t *ctx = &svc->contexts[svc->context_count];
    memset(ctx, 0, sizeof(ozayn_oac_access_ctx_t));

    uint64_t id = _gen_id();
    char id_str[32];
    snprintf(id_str, sizeof(id_str), "%lu", (unsigned long)id);
    strncpy(ctx->context_id, id_str, OZAYN_OAC_MAX_ID_LEN - 1);

    strncpy(ctx->identity_id, identity_id, OZAYN_OAC_MAX_IDENTITY_LEN - 1);
    strncpy(ctx->session_id, session_id, OZAYN_OAC_MAX_SESSION_LEN - 1);
    if (authorization_ref) strncpy(ctx->authorization_ref, authorization_ref, OZAYN_OAC_MAX_AUTHZ_REF_LEN - 1);

    ctx->access_level = level;
    ctx->scope_type = scope_type;
    if (scope_target) strncpy(ctx->scope_target, scope_target, OZAYN_OAC_MAX_TARGET_LEN - 1);

    time_t now = time(0);
    ctx->created_time = now;
    ctx->last_validated_time = now;
    if (lifetime_seconds > 0)
        ctx->expiration_time = now + (time_t)lifetime_seconds;
    else
        ctx->expiration_time = 0;

    ctx->state = OZAYN_OAC_CTX_ACTIVE;
    ctx->version = 1;
    ctx->active = 1;

    svc->context_count++;
    svc->stats.total_access_contexts_created++;
    svc->stats.current_active_contexts++;

    *out_context_id = id;

    _record_validation(svc, id_str, session_id, OZAYN_OAC_EVT_ACCESS_CREATED, 0);
    return OZAYN_OAC_OK;
}

ozayn_oac_err_t ozayn_oac_context_get(const ozayn_oac_service_t *svc,
                                       uint64_t context_id,
                                       const ozayn_oac_access_ctx_t **out_ctx) {
    if (!svc) return OZAYN_OAC_ERR_NULL;
    if (!out_ctx) return OZAYN_OAC_ERR_INVALID_PARAM;
    int idx = _find_context_index(svc, context_id);
    if (idx < 0) return OZAYN_OAC_ERR_NOT_FOUND;
    *out_ctx = &svc->contexts[idx];
    return OZAYN_OAC_OK;
}

ozayn_oac_err_t ozayn_oac_context_validate(ozayn_oac_service_t *svc, uint64_t context_id) {
    if (!svc) return OZAYN_OAC_ERR_NULL;
    if (!svc->initialized) return OZAYN_OAC_ERR_NOT_INITIALIZED;
    int idx = _find_context_index(svc, context_id);
    if (idx < 0) return OZAYN_OAC_ERR_NOT_FOUND;

    ozayn_oac_access_ctx_t *ctx = &svc->contexts[idx];
    if (ctx->state == OZAYN_OAC_CTX_EXPIRED || ctx->state == OZAYN_OAC_CTX_REVOKED ||
        ctx->state == OZAYN_OAC_CTX_TERMINATED) {
        svc->stats.total_access_denials++;
        _record_validation(svc, ctx->context_id, ctx->session_id, OZAYN_OAC_EVT_ACCESS_DENIED, -1);
        return OZAYN_OAC_ERR_ACCESS_DENIED;
    }

    if (ctx->expiration_time > 0 && time(0) > ctx->expiration_time) {
        ctx->state = OZAYN_OAC_CTX_EXPIRED;
        svc->stats.total_access_expired++;
        _record_validation(svc, ctx->context_id, ctx->session_id, OZAYN_OAC_EVT_ACCESS_EXPIRED, -1);
        return OZAYN_OAC_ERR_ACCESS_EXPIRED;
    }

    if (!ozayn_oac_ctx_state_transition_valid(ctx->state, OZAYN_OAC_CTX_VALIDATED))
        return OZAYN_OAC_ERR_STATE_TRANSITION;

    ctx->state = OZAYN_OAC_CTX_VALIDATED;
    ctx->last_validated_time = time(0);
    ctx->validation_count++;
    svc->stats.total_validations++;

    _record_validation(svc, ctx->context_id, ctx->session_id, OZAYN_OAC_EVT_ACCESS_VALIDATED, 0);
    return OZAYN_OAC_OK;
}

ozayn_oac_err_t ozayn_oac_context_expire(ozayn_oac_service_t *svc, uint64_t context_id) {
    if (!svc) return OZAYN_OAC_ERR_NULL;
    if (!svc->initialized) return OZAYN_OAC_ERR_NOT_INITIALIZED;
    int idx = _find_context_index(svc, context_id);
    if (idx < 0) return OZAYN_OAC_ERR_NOT_FOUND;

    ozayn_oac_access_ctx_t *ctx = &svc->contexts[idx];
    if (!ozayn_oac_ctx_state_transition_valid(ctx->state, OZAYN_OAC_CTX_EXPIRED))
        return OZAYN_OAC_ERR_STATE_TRANSITION;

    ctx->state = OZAYN_OAC_CTX_EXPIRED;
    svc->stats.total_access_expired++;
    if (svc->stats.current_active_contexts > 0) svc->stats.current_active_contexts--;
    _record_validation(svc, ctx->context_id, ctx->session_id, OZAYN_OAC_EVT_ACCESS_EXPIRED, -1);
    return OZAYN_OAC_OK;
}

ozayn_oac_err_t ozayn_oac_context_revoke(ozayn_oac_service_t *svc, uint64_t context_id) {
    if (!svc) return OZAYN_OAC_ERR_NULL;
    if (!svc->initialized) return OZAYN_OAC_ERR_NOT_INITIALIZED;
    int idx = _find_context_index(svc, context_id);
    if (idx < 0) return OZAYN_OAC_ERR_NOT_FOUND;

    ozayn_oac_access_ctx_t *ctx = &svc->contexts[idx];
    if (!ozayn_oac_ctx_state_transition_valid(ctx->state, OZAYN_OAC_CTX_REVOKED))
        return OZAYN_OAC_ERR_STATE_TRANSITION;

    ctx->state = OZAYN_OAC_CTX_REVOKED;
    svc->stats.total_access_revoked++;
    if (svc->stats.current_active_contexts > 0) svc->stats.current_active_contexts--;
    _record_validation(svc, ctx->context_id, ctx->session_id, OZAYN_OAC_EVT_ACCESS_REVOKED, -1);
    return OZAYN_OAC_OK;
}

ozayn_oac_err_t ozayn_oac_context_terminate(ozayn_oac_service_t *svc, uint64_t context_id) {
    if (!svc) return OZAYN_OAC_ERR_NULL;
    if (!svc->initialized) return OZAYN_OAC_ERR_NOT_INITIALIZED;
    int idx = _find_context_index(svc, context_id);
    if (idx < 0) return OZAYN_OAC_ERR_NOT_FOUND;

    ozayn_oac_access_ctx_t *ctx = &svc->contexts[idx];
    if (!ozayn_oac_ctx_state_transition_valid(ctx->state, OZAYN_OAC_CTX_TERMINATED))
        return OZAYN_OAC_ERR_STATE_TRANSITION;

    ctx->state = OZAYN_OAC_CTX_TERMINATED;
    if (svc->stats.current_active_contexts > 0) svc->stats.current_active_contexts--;
    return OZAYN_OAC_OK;
}

int ozayn_oac_context_active_count(const ozayn_oac_service_t *svc) {
    if (!svc || !svc->initialized) return -1;
    return (int)svc->stats.current_active_contexts;
}

int ozayn_oac_context_total_count(const ozayn_oac_service_t *svc) {
    if (!svc || !svc->initialized) return -1;
    return svc->context_count;
}

ozayn_oac_err_t ozayn_oac_context_list_by_identity(const ozayn_oac_service_t *svc,
                                                     const char *identity_id,
                                                     const ozayn_oac_access_ctx_t **out_results,
                                                     uint32_t max_results,
                                                     uint32_t *out_count) {
    if (!svc || !identity_id || !out_count) return OZAYN_OAC_ERR_NULL;
    if (!out_results || max_results == 0) return OZAYN_OAC_ERR_INVALID_PARAM;
    uint32_t count = 0;
    for (int i = 0; i < svc->context_count && i < OZAYN_OAC_MAX_ACCESS_CONTEXTS; i++) {
        if (svc->contexts[i].active && strcmp(svc->contexts[i].identity_id, identity_id) == 0) {
            if (count < max_results)
                out_results[count] = &svc->contexts[i];
            count++;
        }
    }
    *out_count = count;
    return OZAYN_OAC_OK;
}

/* ============================================================
 * OPERATIONAL AUTHORITY
 * ============================================================ */

ozayn_oac_err_t ozayn_oac_authority_create(ozayn_oac_service_t *svc,
                                            uint64_t context_id,
                                            const char *request_id,
                                            const char *operation_id,
                                            const char *target,
                                            const char *capability,
                                            const char *action,
                                            const char *required_permission,
                                            uint64_t lifetime_seconds,
                                            uint64_t *out_authority_id) {
    if (!svc) return OZAYN_OAC_ERR_NULL;
    if (!svc->initialized) return OZAYN_OAC_ERR_NOT_INITIALIZED;
    if (!request_id || !operation_id || !out_authority_id) return OZAYN_OAC_ERR_INVALID_PARAM;
    if (svc->authority_count >= OZAYN_OAC_MAX_AUTHORITIES) return OZAYN_OAC_ERR_FULL;

    int ctx_idx = _find_context_index(svc, context_id);
    if (ctx_idx < 0) return OZAYN_OAC_ERR_ACCESS_INVALID;

    ozayn_oac_access_ctx_t *ctx = &svc->contexts[ctx_idx];
    if (ctx->state != OZAYN_OAC_CTX_ACTIVE && ctx->state != OZAYN_OAC_CTX_VALIDATED) {
        svc->stats.total_access_denials++;
        _record_validation(svc, ctx->context_id, ctx->session_id, OZAYN_OAC_EVT_ACCESS_DENIED, -1);
        return OZAYN_OAC_ERR_ACCESS_DENIED;
    }

    if (ctx->expiration_time > 0 && time(0) > ctx->expiration_time) {
        ctx->state = OZAYN_OAC_CTX_EXPIRED;
        svc->stats.total_access_expired++;
        return OZAYN_OAC_ERR_ACCESS_EXPIRED;
    }

    for (int i = 0; i < svc->authority_count && i < OZAYN_OAC_MAX_AUTHORITIES; i++) {
        if (svc->authorities[i].active &&
            strcmp(svc->authorities[i].request_id, request_id) == 0 &&
            strcmp(svc->authorities[i].operation_id, operation_id) == 0) {
            svc->stats.total_duplicate_authority_attempts++;
            _record_validation(svc, svc->authorities[i].authority_id, ctx->session_id,
                               OZAYN_OAC_EVT_DUPLICATE_ATTEMPT, -1);
            *out_authority_id = 0;
            return OZAYN_OAC_ERR_AUTHORITY_DUPLICATE;
        }
    }

    ozayn_oac_authority_t *auth = &svc->authorities[svc->authority_count];
    memset(auth, 0, sizeof(ozayn_oac_authority_t));

    uint64_t id = _gen_id();
    char id_str[32];
    snprintf(id_str, sizeof(id_str), "%lu", (unsigned long)id);
    strncpy(auth->authority_id, id_str, OZAYN_OAC_MAX_ID_LEN - 1);

    strncpy(auth->identity_id, ctx->identity_id, OZAYN_OAC_MAX_IDENTITY_LEN - 1);
    strncpy(auth->session_id, ctx->session_id, OZAYN_OAC_MAX_SESSION_LEN - 1);
    strncpy(auth->context_id, ctx->context_id, OZAYN_OAC_MAX_ID_LEN - 1);
    strncpy(auth->request_id, request_id, OZAYN_OAC_MAX_ID_LEN - 1);
    strncpy(auth->operation_id, operation_id, OZAYN_OAC_MAX_ID_LEN - 1);
    if (target) strncpy(auth->target, target, OZAYN_OAC_MAX_TARGET_LEN - 1);
    if (capability) strncpy(auth->capability, capability, OZAYN_OAC_MAX_CAPABILITY_LEN - 1);
    if (action) strncpy(auth->action, action, OZAYN_OAC_MAX_ACTION_LEN - 1);
    if (required_permission) strncpy(auth->required_permission, required_permission, OZAYN_OAC_MAX_PERMISSION_LEN - 1);

    time_t now = time(0);
    auth->created_time = now;
    if (lifetime_seconds > 0)
        auth->expiration_time = now + (time_t)lifetime_seconds;
    else
        auth->expiration_time = 0;

    auth->state = OZAYN_OAC_AUTH_REQUESTED;
    auth->consumed = 0;
    auth->version = 1;
    auth->active = 1;

    svc->authority_count++;
    svc->stats.total_authorities_created++;
    svc->stats.current_active_authorities++;

    *out_authority_id = id;

    _record_validation(svc, id_str, ctx->session_id, OZAYN_OAC_EVT_AUTHORITY_REQUESTED, 0);
    return OZAYN_OAC_OK;
}

ozayn_oac_err_t ozayn_oac_authority_get(const ozayn_oac_service_t *svc,
                                         uint64_t authority_id,
                                         const ozayn_oac_authority_t **out_auth) {
    if (!svc) return OZAYN_OAC_ERR_NULL;
    if (!out_auth) return OZAYN_OAC_ERR_INVALID_PARAM;
    int idx = _find_authority_index(svc, authority_id);
    if (idx < 0) return OZAYN_OAC_ERR_NOT_FOUND;
    *out_auth = &svc->authorities[idx];
    return OZAYN_OAC_OK;
}

ozayn_oac_err_t ozayn_oac_authority_validate(ozayn_oac_service_t *svc,
                                               uint64_t authority_id,
                                               const char *request_id,
                                               const char *operation_id,
                                               const char *session_id,
                                               const char *identity_id) {
    if (!svc) return OZAYN_OAC_ERR_NULL;
    if (!svc->initialized) return OZAYN_OAC_ERR_NOT_INITIALIZED;

    int idx = _find_authority_index(svc, authority_id);
    if (idx < 0) return OZAYN_OAC_ERR_NOT_FOUND;

    ozayn_oac_authority_t *auth = &svc->authorities[idx];

    if (auth->state != OZAYN_OAC_AUTH_REQUESTED && auth->state != OZAYN_OAC_AUTH_VALIDATING &&
        auth->state != OZAYN_OAC_AUTH_AUTHORIZED) {
        svc->stats.total_stale_authority_attempts++;
        _record_validation(svc, auth->authority_id, auth->session_id,
                           OZAYN_OAC_EVT_STALE_AUTHORITY, -1);
        return OZAYN_OAC_ERR_AUTHORITY_INVALID;
    }

    if (auth->expiration_time > 0 && time(0) > auth->expiration_time) {
        auth->state = OZAYN_OAC_AUTH_EXPIRED;
        svc->stats.total_authorities_expired++;
        if (svc->stats.current_active_authorities > 0) svc->stats.current_active_authorities--;
        _record_validation(svc, auth->authority_id, auth->session_id,
                           OZAYN_OAC_EVT_AUTHORITY_EXPIRED, -1);
        return OZAYN_OAC_ERR_AUTHORITY_EXPIRED;
    }

    if (session_id && strcmp(auth->session_id, session_id) != 0) {
        svc->stats.total_stale_authority_attempts++;
        _record_validation(svc, auth->authority_id, auth->session_id,
                           OZAYN_OAC_EVT_STALE_AUTHORITY, -1);
        return OZAYN_OAC_ERR_SESSION_MISMATCH;
    }

    if (identity_id && strcmp(auth->identity_id, identity_id) != 0) {
        svc->stats.total_stale_authority_attempts++;
        _record_validation(svc, auth->authority_id, auth->session_id,
                           OZAYN_OAC_EVT_STALE_AUTHORITY, -1);
        return OZAYN_OAC_ERR_IDENTITY_MISMATCH;
    }

    if (request_id && strcmp(auth->request_id, request_id) != 0) {
        svc->stats.total_stale_authority_attempts++;
        return OZAYN_OAC_ERR_AUTHORITY_MISMATCH;
    }

    if (operation_id && strcmp(auth->operation_id, operation_id) != 0) {
        svc->stats.total_stale_authority_attempts++;
        return OZAYN_OAC_ERR_AUTHORITY_MISMATCH;
    }

    if (!ozayn_oac_auth_state_transition_valid(auth->state, OZAYN_OAC_AUTH_VALIDATING))
        return OZAYN_OAC_ERR_STATE_TRANSITION;

    auth->state = OZAYN_OAC_AUTH_VALIDATING;
    svc->stats.total_validations++;

    if (!ozayn_oac_auth_state_transition_valid(auth->state, OZAYN_OAC_AUTH_AUTHORIZED))
        return OZAYN_OAC_ERR_STATE_TRANSITION;

    auth->state = OZAYN_OAC_AUTH_AUTHORIZED;
    svc->stats.total_authorities_granted++;

    _record_validation(svc, auth->authority_id, auth->session_id,
                       OZAYN_OAC_EVT_AUTHORITY_GRANTED, 0);
    return OZAYN_OAC_OK;
}

ozayn_oac_err_t ozayn_oac_authority_consume(ozayn_oac_service_t *svc, uint64_t authority_id) {
    if (!svc) return OZAYN_OAC_ERR_NULL;
    if (!svc->initialized) return OZAYN_OAC_ERR_NOT_INITIALIZED;

    int idx = _find_authority_index(svc, authority_id);
    if (idx < 0) return OZAYN_OAC_ERR_NOT_FOUND;

    ozayn_oac_authority_t *auth = &svc->authorities[idx];

    if (auth->consumed) {
        svc->stats.total_duplicate_authority_attempts++;
        _record_validation(svc, auth->authority_id, auth->session_id,
                           OZAYN_OAC_EVT_DUPLICATE_ATTEMPT, -1);
        return OZAYN_OAC_ERR_AUTHORITY_CONSUMED;
    }

    if (auth->state != OZAYN_OAC_AUTH_AUTHORIZED) {
        return OZAYN_OAC_ERR_AUTHORITY_INVALID;
    }

    if (!ozayn_oac_auth_state_transition_valid(auth->state, OZAYN_OAC_AUTH_CONSUMED))
        return OZAYN_OAC_ERR_STATE_TRANSITION;

    auth->state = OZAYN_OAC_AUTH_CONSUMED;
    auth->consumed = 1;
    svc->stats.total_authorities_consumed++;
    if (svc->stats.current_active_authorities > 0) svc->stats.current_active_authorities--;

    _record_validation(svc, auth->authority_id, auth->session_id,
                       OZAYN_OAC_EVT_AUTHORITY_CONSUMED, 0);

    _add_to_history(svc, auth);
    return OZAYN_OAC_OK;
}

ozayn_oac_err_t ozayn_oac_authority_expire(ozayn_oac_service_t *svc, uint64_t authority_id) {
    if (!svc) return OZAYN_OAC_ERR_NULL;
    if (!svc->initialized) return OZAYN_OAC_ERR_NOT_INITIALIZED;

    int idx = _find_authority_index(svc, authority_id);
    if (idx < 0) return OZAYN_OAC_ERR_NOT_FOUND;

    ozayn_oac_authority_t *auth = &svc->authorities[idx];
    if (!ozayn_oac_auth_state_transition_valid(auth->state, OZAYN_OAC_AUTH_EXPIRED))
        return OZAYN_OAC_ERR_STATE_TRANSITION;

    auth->state = OZAYN_OAC_AUTH_EXPIRED;
    svc->stats.total_authorities_expired++;
    if (svc->stats.current_active_authorities > 0) svc->stats.current_active_authorities--;

    _record_validation(svc, auth->authority_id, auth->session_id,
                       OZAYN_OAC_EVT_AUTHORITY_EXPIRED, -1);
    return OZAYN_OAC_OK;
}

ozayn_oac_err_t ozayn_oac_authority_revoke(ozayn_oac_service_t *svc, uint64_t authority_id) {
    if (!svc) return OZAYN_OAC_ERR_NULL;
    if (!svc->initialized) return OZAYN_OAC_ERR_NOT_INITIALIZED;

    int idx = _find_authority_index(svc, authority_id);
    if (idx < 0) return OZAYN_OAC_ERR_NOT_FOUND;

    ozayn_oac_authority_t *auth = &svc->authorities[idx];
    if (!ozayn_oac_auth_state_transition_valid(auth->state, OZAYN_OAC_AUTH_REVOKED))
        return OZAYN_OAC_ERR_STATE_TRANSITION;

    auth->state = OZAYN_OAC_AUTH_REVOKED;
    svc->stats.total_authorities_revoked++;
    if (svc->stats.current_active_authorities > 0) svc->stats.current_active_authorities--;

    _record_validation(svc, auth->authority_id, auth->session_id,
                       OZAYN_OAC_EVT_AUTHORITY_REVOKED, -1);
    return OZAYN_OAC_OK;
}

ozayn_oac_err_t ozayn_oac_authority_cancel(ozayn_oac_service_t *svc, uint64_t authority_id) {
    if (!svc) return OZAYN_OAC_ERR_NULL;
    if (!svc->initialized) return OZAYN_OAC_ERR_NOT_INITIALIZED;

    int idx = _find_authority_index(svc, authority_id);
    if (idx < 0) return OZAYN_OAC_ERR_NOT_FOUND;

    ozayn_oac_authority_t *auth = &svc->authorities[idx];
    if (!ozayn_oac_auth_state_transition_valid(auth->state, OZAYN_OAC_AUTH_CANCELLED))
        return OZAYN_OAC_ERR_STATE_TRANSITION;

    auth->state = OZAYN_OAC_AUTH_CANCELLED;
    if (svc->stats.current_active_authorities > 0) svc->stats.current_active_authorities--;
    return OZAYN_OAC_OK;
}

ozayn_oac_err_t ozayn_oac_authority_invalidate_by_session(ozayn_oac_service_t *svc,
                                                           const char *session_id) {
    if (!svc) return OZAYN_OAC_ERR_NULL;
    if (!session_id) return OZAYN_OAC_ERR_INVALID_PARAM;
    if (!svc->initialized) return OZAYN_OAC_ERR_NOT_INITIALIZED;

    uint32_t count = 0;
    for (int i = 0; i < svc->authority_count && i < OZAYN_OAC_MAX_AUTHORITIES; i++) {
        ozayn_oac_authority_t *auth = &svc->authorities[i];
        if (auth->active && strcmp(auth->session_id, session_id) == 0) {
            if (auth->state != OZAYN_OAC_AUTH_EXPIRED && auth->state != OZAYN_OAC_AUTH_REVOKED &&
                auth->state != OZAYN_OAC_AUTH_CONSUMED && auth->state != OZAYN_OAC_AUTH_INVALID) {
                auth->state = OZAYN_OAC_AUTH_INVALID;
                svc->stats.total_authorities_invalidated++;
                if (svc->stats.current_active_authorities > 0) svc->stats.current_active_authorities--;
                _record_validation(svc, auth->authority_id, session_id,
                                   OZAYN_OAC_EVT_SESSION_INVALIDATED, -1);
                count++;
            }
        }
    }
    svc->stats.total_session_invalidations++;
    (void)count;
    return OZAYN_OAC_OK;
}

ozayn_oac_err_t ozayn_oac_authority_invalidate_by_context(ozayn_oac_service_t *svc,
                                                           uint64_t context_id) {
    if (!svc) return OZAYN_OAC_ERR_NULL;
    if (!svc->initialized) return OZAYN_OAC_ERR_NOT_INITIALIZED;

    char ctx_id_str[32];
    snprintf(ctx_id_str, sizeof(ctx_id_str), "%lu", (unsigned long)context_id);

    for (int i = 0; i < svc->authority_count && i < OZAYN_OAC_MAX_AUTHORITIES; i++) {
        ozayn_oac_authority_t *auth = &svc->authorities[i];
        if (auth->active && strcmp(auth->context_id, ctx_id_str) == 0) {
            if (auth->state != OZAYN_OAC_AUTH_EXPIRED && auth->state != OZAYN_OAC_AUTH_REVOKED &&
                auth->state != OZAYN_OAC_AUTH_CONSUMED && auth->state != OZAYN_OAC_AUTH_INVALID) {
                auth->state = OZAYN_OAC_AUTH_INVALID;
                svc->stats.total_authorities_invalidated++;
                if (svc->stats.current_active_authorities > 0) svc->stats.current_active_authorities--;
                _record_validation(svc, auth->authority_id, auth->session_id,
                                   OZAYN_OAC_EVT_AUTHORITY_INVALIDATED, -1);
            }
        }
    }
    return OZAYN_OAC_OK;
}

int ozayn_oac_authority_active_count(const ozayn_oac_service_t *svc) {
    if (!svc || !svc->initialized) return -1;
    return (int)svc->stats.current_active_authorities;
}

int ozayn_oac_authority_total_count(const ozayn_oac_service_t *svc) {
    if (!svc || !svc->initialized) return -1;
    return svc->authority_count;
}

ozayn_oac_err_t ozayn_oac_authority_list_by_session(const ozayn_oac_service_t *svc,
                                                      const char *session_id,
                                                      const ozayn_oac_authority_t **out_results,
                                                      uint32_t max_results,
                                                      uint32_t *out_count) {
    if (!svc || !session_id || !out_count) return OZAYN_OAC_ERR_NULL;
    if (!out_results || max_results == 0) return OZAYN_OAC_ERR_INVALID_PARAM;
    uint32_t count = 0;
    for (int i = 0; i < svc->authority_count && i < OZAYN_OAC_MAX_AUTHORITIES; i++) {
        if (svc->authorities[i].active && strcmp(svc->authorities[i].session_id, session_id) == 0) {
            if (count < max_results)
                out_results[count] = &svc->authorities[i];
            count++;
        }
    }
    *out_count = count;
    return OZAYN_OAC_OK;
}

ozayn_oac_err_t ozayn_oac_authority_list_by_context(const ozayn_oac_service_t *svc,
                                                      uint64_t context_id,
                                                      const ozayn_oac_authority_t **out_results,
                                                      uint32_t max_results,
                                                      uint32_t *out_count) {
    if (!svc || !out_count) return OZAYN_OAC_ERR_NULL;
    if (!out_results || max_results == 0) return OZAYN_OAC_ERR_INVALID_PARAM;

    char ctx_id_str[32];
    snprintf(ctx_id_str, sizeof(ctx_id_str), "%lu", (unsigned long)context_id);

    uint32_t count = 0;
    for (int i = 0; i < svc->authority_count && i < OZAYN_OAC_MAX_AUTHORITIES; i++) {
        if (svc->authorities[i].active && strcmp(svc->authorities[i].context_id, ctx_id_str) == 0) {
            if (count < max_results)
                out_results[count] = &svc->authorities[i];
            count++;
        }
    }
    *out_count = count;
    return OZAYN_OAC_OK;
}

/* ============================================================
 * AUTHORITY HISTORY
 * ============================================================ */

int ozayn_oac_history_find(const ozayn_oac_service_t *svc,
                            const char *request_id,
                            const char *operation_id) {
    if (!svc || !request_id || !operation_id) return 0;
    for (int i = 0; i < svc->history_count && i < OZAYN_OAC_MAX_AUTHORITY_HISTORY; i++) {
        if (strcmp(svc->authority_history[i].request_id, request_id) == 0 &&
            strcmp(svc->authority_history[i].operation_id, operation_id) == 0) {
            return 1;
        }
    }
    return 0;
}

/* ============================================================
 * BATCH INVALIDATION
 * ============================================================ */

ozayn_oac_err_t ozayn_oac_revoke_all_for_session(ozayn_oac_service_t *svc,
                                                   const char *session_id,
                                                   uint32_t *out_count) {
    if (!svc) return OZAYN_OAC_ERR_NULL;
    if (!session_id) return OZAYN_OAC_ERR_INVALID_PARAM;
    if (!svc->initialized) return OZAYN_OAC_ERR_NOT_INITIALIZED;

    uint32_t count = 0;
    for (int i = 0; i < svc->authority_count && i < OZAYN_OAC_MAX_AUTHORITIES; i++) {
        ozayn_oac_authority_t *auth = &svc->authorities[i];
        if (auth->active && strcmp(auth->session_id, session_id) == 0) {
            if (auth->state != OZAYN_OAC_AUTH_REVOKED && auth->state != OZAYN_OAC_AUTH_EXPIRED &&
                auth->state != OZAYN_OAC_AUTH_CONSUMED) {
                if (ozayn_oac_auth_state_transition_valid(auth->state, OZAYN_OAC_AUTH_REVOKED)) {
                    auth->state = OZAYN_OAC_AUTH_REVOKED;
                    svc->stats.total_authorities_revoked++;
                    if (svc->stats.current_active_authorities > 0) svc->stats.current_active_authorities--;
                    _record_validation(svc, auth->authority_id, session_id,
                                       OZAYN_OAC_EVT_AUTHORITY_REVOKED, -1);
                    count++;
                }
            }
        }
    }
    if (out_count) *out_count = count;
    return OZAYN_OAC_OK;
}

ozayn_oac_err_t ozayn_oac_expire_all_for_context(ozayn_oac_service_t *svc,
                                                   uint64_t context_id,
                                                   uint32_t *out_count) {
    if (!svc) return OZAYN_OAC_ERR_NULL;
    if (!svc->initialized) return OZAYN_OAC_ERR_NOT_INITIALIZED;

    char ctx_id_str[32];
    snprintf(ctx_id_str, sizeof(ctx_id_str), "%lu", (unsigned long)context_id);

    uint32_t count = 0;
    for (int i = 0; i < svc->authority_count && i < OZAYN_OAC_MAX_AUTHORITIES; i++) {
        ozayn_oac_authority_t *auth = &svc->authorities[i];
        if (auth->active && strcmp(auth->context_id, ctx_id_str) == 0) {
            if (auth->state != OZAYN_OAC_AUTH_EXPIRED && auth->state != OZAYN_OAC_AUTH_REVOKED &&
                auth->state != OZAYN_OAC_AUTH_CONSUMED) {
                if (ozayn_oac_auth_state_transition_valid(auth->state, OZAYN_OAC_AUTH_EXPIRED)) {
                    auth->state = OZAYN_OAC_AUTH_EXPIRED;
                    svc->stats.total_authorities_expired++;
                    if (svc->stats.current_active_authorities > 0) svc->stats.current_active_authorities--;
                    count++;
                }
            }
        }
    }
    if (out_count) *out_count = count;
    return OZAYN_OAC_OK;
}

ozayn_oac_err_t ozayn_oac_cleanup_expired(ozayn_oac_service_t *svc) {
    if (!svc) return OZAYN_OAC_ERR_NULL;
    if (!svc->initialized) return OZAYN_OAC_ERR_NOT_INITIALIZED;

    time_t now = time(0);

    for (int i = 0; i < svc->authority_count && i < OZAYN_OAC_MAX_AUTHORITIES; i++) {
        ozayn_oac_authority_t *auth = &svc->authorities[i];
        if (auth->active && auth->expiration_time > 0 && now > auth->expiration_time) {
            if (auth->state != OZAYN_OAC_AUTH_EXPIRED && auth->state != OZAYN_OAC_AUTH_REVOKED &&
                auth->state != OZAYN_OAC_AUTH_CONSUMED) {
                auth->state = OZAYN_OAC_AUTH_EXPIRED;
                svc->stats.total_authorities_expired++;
                if (svc->stats.current_active_authorities > 0) svc->stats.current_active_authorities--;
            }
        }
    }

    for (int i = 0; i < svc->context_count && i < OZAYN_OAC_MAX_ACCESS_CONTEXTS; i++) {
        ozayn_oac_access_ctx_t *ctx = &svc->contexts[i];
        if (ctx->active && ctx->expiration_time > 0 && now > ctx->expiration_time) {
            if (ctx->state != OZAYN_OAC_CTX_EXPIRED && ctx->state != OZAYN_OAC_CTX_REVOKED &&
                ctx->state != OZAYN_OAC_CTX_TERMINATED) {
                ctx->state = OZAYN_OAC_CTX_EXPIRED;
                svc->stats.total_access_expired++;
                if (svc->stats.current_active_contexts > 0) svc->stats.current_active_contexts--;
            }
        }
    }

    return OZAYN_OAC_OK;
}

/* ============================================================
 * VALIDATION LOG
 * ============================================================ */

int ozayn_oac_validation_log_count(const ozayn_oac_service_t *svc) {
    if (!svc) return 0;
    return svc->validation_count;
}

/* ============================================================
 * STATS
 * ============================================================ */

ozayn_oac_stats_t ozayn_oac_get_stats(const ozayn_oac_service_t *svc) {
    if (!svc) {
        ozayn_oac_stats_t zero;
        memset(&zero, 0, sizeof(zero));
        return zero;
    }
    return svc->stats;
}
