#include "permission.h"
#include <string.h>
#include <stdio.h>

/* ============================================================
 * VALIDATION
 * ============================================================ */

int ozayn_perm_validate_id(const char *perm_id)
{
    if (!perm_id || perm_id[0] == '\0')
        return -1;
    if (strlen(perm_id) >= OZAYN_PERM_MAX_ID_LEN)
        return -1;
    for (const char *p = perm_id; *p; p++) {
        char c = *p;
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') || c == '_' || c == '-' || c == '.'))
            return -1;
    }
    return 0;
}

int ozayn_perm_validate_state(ozayn_perm_state_t state)
{
    return (state >= OZAYN_PERM_UNINITIALIZED &&
            state <= OZAYN_PERM_ARCHIVED) ? 0 : -1;
}

int ozayn_perm_validate_transition(ozayn_perm_state_t from,
                                    ozayn_perm_state_t to)
{
    if (from == OZAYN_PERM_UNINITIALIZED && to == OZAYN_PERM_ACTIVE)
        return 0;
    if (from == OZAYN_PERM_ACTIVE && to == OZAYN_PERM_SUSPENDED)
        return 0;
    if (from == OZAYN_PERM_ACTIVE && to == OZAYN_PERM_REVOKED)
        return 0;
    if (from == OZAYN_PERM_ACTIVE && to == OZAYN_PERM_ARCHIVED)
        return 0;
    if (from == OZAYN_PERM_SUSPENDED && to == OZAYN_PERM_ACTIVE)
        return 0;
    if (from == OZAYN_PERM_SUSPENDED && to == OZAYN_PERM_REVOKED)
        return 0;
    if (from == OZAYN_PERM_SUSPENDED && to == OZAYN_PERM_ARCHIVED)
        return 0;
    if (from == OZAYN_PERM_REVOKED && to == OZAYN_PERM_ARCHIVED)
        return 0;
    return -1;
}

/* ============================================================
 * NAME HELPERS
 * ============================================================ */

const char *ozayn_perm_error_name(ozayn_perm_error_t error)
{
    switch (error) {
        case OZAYN_PERM_OK:                     return "OK";
        case OZAYN_PERM_ERR_NULL:               return "NULL";
        case OZAYN_PERM_ERR_NOT_INITIALIZED:    return "NOT_INITIALIZED";
        case OZAYN_PERM_ERR_NOT_FOUND:          return "NOT_FOUND";
        case OZAYN_PERM_ERR_ALREADY_EXISTS:     return "ALREADY_EXISTS";
        case OZAYN_PERM_ERR_INVALID:            return "INVALID";
        case OZAYN_PERM_ERR_ID_INVALID:         return "ID_INVALID";
        case OZAYN_PERM_ERR_STATE_INVALID:      return "STATE_INVALID";
        case OZAYN_PERM_ERR_STATE_TRANSITION:   return "STATE_TRANSITION";
        case OZAYN_PERM_ERR_SCOPE_INVALID:      return "SCOPE_INVALID";
        case OZAYN_PERM_ERR_LIMIT_REACHED:      return "LIMIT_REACHED";
        case OZAYN_PERM_ERR_RESOURCE_INVALID:   return "RESOURCE_INVALID";
        case OZAYN_PERM_ERR_ACTION_INVALID:     return "ACTION_INVALID";
        case OZAYN_PERM_ERR_DENIED:             return "DENIED";
        case OZAYN_PERM_ERR_ENFORCEMENT_FAILED: return "ENFORCEMENT_FAILED";
        default:                                return "UNKNOWN";
    }
}

const char *ozayn_perm_state_name(ozayn_perm_state_t state)
{
    switch (state) {
        case OZAYN_PERM_UNINITIALIZED: return "UNINITIALIZED";
        case OZAYN_PERM_ACTIVE:        return "ACTIVE";
        case OZAYN_PERM_SUSPENDED:     return "SUSPENDED";
        case OZAYN_PERM_REVOKED:       return "REVOKED";
        case OZAYN_PERM_ARCHIVED:      return "ARCHIVED";
        default:                       return "UNKNOWN";
    }
}

/* ============================================================
 * INTERNAL HELPERS
 * ============================================================ */

static ozayn_permission_t *_find_perm(ozayn_perm_service_t *svc,
                                       const char *perm_id)
{
    if (!svc || !perm_id)
        return NULL;
    for (int i = 0; i < svc->perm_count; i++) {
        if (svc->perms[i].in_use &&
            strcmp(svc->perms[i].id, perm_id) == 0)
            return &svc->perms[i];
    }
    return NULL;
}

static ozayn_protected_resource_t *_find_resource(ozayn_perm_service_t *svc,
                                                    const char *resource_id)
{
    if (!svc || !resource_id)
        return NULL;
    for (int i = 0; i < svc->resource_count; i++) {
        if (svc->resources[i].id[0] != '\0' &&
            strcmp(svc->resources[i].id, resource_id) == 0)
            return &svc->resources[i];
    }
    return NULL;
}

static ozayn_perm_error_t _perm_transition(ozayn_perm_service_t *svc,
                                            const char *perm_id,
                                            ozayn_perm_state_t target)
{
    if (!svc || !perm_id)
        return OZAYN_PERM_ERR_NULL;
    if (!svc->initialized)
        return OZAYN_PERM_ERR_NOT_INITIALIZED;

    ozayn_permission_t *perm = _find_perm(svc, perm_id);
    if (!perm)
        return OZAYN_PERM_ERR_NOT_FOUND;

    if (ozayn_perm_validate_transition(perm->state, target) != 0)
        return OZAYN_PERM_ERR_STATE_TRANSITION;

    perm->state = target;
    perm->modified_at = time(NULL);
    perm->version++;
    return OZAYN_PERM_OK;
}

/* ============================================================
 * SERVICE LIFECYCLE
 * ============================================================ */

ozayn_perm_error_t ozayn_perm_service_init(
    ozayn_perm_service_t *svc,
    const ozayn_perm_service_config_t *config)
{
    if (!svc)
        return OZAYN_PERM_ERR_NULL;
    (void)config;

    memset(svc, 0, sizeof(*svc));
    svc->initialized = 1;
    return OZAYN_PERM_OK;
}

void ozayn_perm_service_shutdown(ozayn_perm_service_t *svc)
{
    if (!svc)
        return;
    svc->initialized = 0;
}

int ozayn_perm_service_is_initialized(const ozayn_perm_service_t *svc)
{
    if (!svc)
        return 0;
    return svc->initialized;
}

/* ============================================================
 * PERMISSION MANAGEMENT
 * ============================================================ */

ozayn_perm_error_t ozayn_perm_create(
    ozayn_perm_service_t *svc,
    const char *perm_id,
    const char *name,
    const char *description,
    ozayn_authz_resource_type_t resource,
    ozayn_authz_action_type_t action,
    ozayn_authz_scope_t scope,
    ozayn_permission_t *out_perm)
{
    if (!svc || !perm_id || !out_perm)
        return OZAYN_PERM_ERR_NULL;
    if (!svc->initialized)
        return OZAYN_PERM_ERR_NOT_INITIALIZED;
    if (ozayn_perm_validate_id(perm_id) != 0)
        return OZAYN_PERM_ERR_ID_INVALID;
    if (resource == OZAYN_AUTHZ_RESOURCE_UNKNOWN)
        return OZAYN_PERM_ERR_RESOURCE_INVALID;
    if (action == OZAYN_AUTHZ_ACTION_UNKNOWN)
        return OZAYN_PERM_ERR_ACTION_INVALID;
    if (scope == OZAYN_AUTHZ_SCOPE_UNKNOWN)
        return OZAYN_PERM_ERR_SCOPE_INVALID;
    if (_find_perm(svc, perm_id))
        return OZAYN_PERM_ERR_ALREADY_EXISTS;
    if (svc->perm_count >= OZAYN_PERM_MAX_PERMS)
        return OZAYN_PERM_ERR_LIMIT_REACHED;

    int idx = svc->perm_count;
    ozayn_permission_t *perm = &svc->perms[idx];
    memset(perm, 0, sizeof(*perm));

    strncpy(perm->id, perm_id, sizeof(perm->id) - 1);
    if (name)
        strncpy(perm->name, name, sizeof(perm->name) - 1);
    else
        strncpy(perm->name, perm_id, sizeof(perm->name) - 1);
    if (description)
        strncpy(perm->description, description, sizeof(perm->description) - 1);
    perm->resource = resource;
    perm->action = action;
    perm->scope = scope;
    perm->state = OZAYN_PERM_ACTIVE;
    perm->version = 1;
    perm->created_at = time(NULL);
    perm->modified_at = perm->created_at;
    perm->in_use = 1;

    svc->perm_count++;

    *out_perm = *perm;
    return OZAYN_PERM_OK;
}

ozayn_perm_error_t ozayn_perm_get(
    const ozayn_perm_service_t *svc,
    const char *perm_id,
    ozayn_permission_t *out_perm)
{
    if (!svc || !perm_id || !out_perm)
        return OZAYN_PERM_ERR_NULL;
    if (!svc->initialized)
        return OZAYN_PERM_ERR_NOT_INITIALIZED;

    const ozayn_permission_t *perm =
        _find_perm((ozayn_perm_service_t *)svc, perm_id);
    if (!perm)
        return OZAYN_PERM_ERR_NOT_FOUND;

    *out_perm = *perm;
    return OZAYN_PERM_OK;
}

int ozayn_perm_exists(
    const ozayn_perm_service_t *svc,
    const char *perm_id)
{
    if (!svc || !perm_id)
        return 0;
    return _find_perm((ozayn_perm_service_t *)svc, perm_id) != NULL ? 1 : 0;
}

ozayn_perm_error_t ozayn_perm_suspend(
    ozayn_perm_service_t *svc,
    const char *perm_id)
{
    return _perm_transition(svc, perm_id, OZAYN_PERM_SUSPENDED);
}

ozayn_perm_error_t ozayn_perm_resume(
    ozayn_perm_service_t *svc,
    const char *perm_id)
{
    return _perm_transition(svc, perm_id, OZAYN_PERM_ACTIVE);
}

ozayn_perm_error_t ozayn_perm_revoke(
    ozayn_perm_service_t *svc,
    const char *perm_id)
{
    return _perm_transition(svc, perm_id, OZAYN_PERM_REVOKED);
}

ozayn_perm_error_t ozayn_perm_archive(
    ozayn_perm_service_t *svc,
    const char *perm_id)
{
    return _perm_transition(svc, perm_id, OZAYN_PERM_ARCHIVED);
}

int ozayn_perm_count(const ozayn_perm_service_t *svc)
{
    if (!svc)
        return 0;
    return svc->perm_count;
}

/* ============================================================
 * PERMISSION MATCHING
 * ============================================================ */

int ozayn_perm_matches(
    const ozayn_permission_t *perm,
    ozayn_authz_resource_type_t resource,
    ozayn_authz_action_type_t action,
    ozayn_authz_scope_t request_scope)
{
    if (!perm)
        return 0;
    if (perm->resource != resource)
        return 0;
    if (perm->action != action)
        return 0;
    /* Scope matching: GLOBAL covers all, otherwise exact match */
    if (perm->scope == OZAYN_AUTHZ_SCOPE_GLOBAL)
        return 1;
    return perm->scope == request_scope;
}

int ozayn_perm_service_check(
    const ozayn_perm_service_t *svc,
    const char *perm_id,
    ozayn_authz_resource_type_t resource,
    ozayn_authz_action_type_t action,
    ozayn_authz_scope_t request_scope)
{
    if (!svc || !perm_id)
        return 0;
    if (!svc->initialized)
        return 0;

    const ozayn_permission_t *perm =
        _find_perm((ozayn_perm_service_t *)svc, perm_id);
    if (!perm)
        return 0;
    if (perm->state != OZAYN_PERM_ACTIVE)
        return 0;

    return ozayn_perm_matches(perm, resource, action, request_scope);
}

/* ============================================================
 * PROTECTED RESOURCE MANAGEMENT
 * ============================================================ */

ozayn_perm_error_t ozayn_perm_protect_resource(
    ozayn_perm_service_t *svc,
    const char *resource_id,
    const char *resource_type,
    const char *resource_ref,
    ozayn_authz_scope_t required_scope,
    int requires_auth,
    int requires_authz,
    ozayn_protected_resource_t *out_resource)
{
    if (!svc || !resource_id || !resource_type || !out_resource)
        return OZAYN_PERM_ERR_NULL;
    if (!svc->initialized)
        return OZAYN_PERM_ERR_NOT_INITIALIZED;
    if (resource_id[0] == '\0')
        return OZAYN_PERM_ERR_ID_INVALID;
    if (required_scope == OZAYN_AUTHZ_SCOPE_UNKNOWN)
        return OZAYN_PERM_ERR_SCOPE_INVALID;
    if (_find_resource(svc, resource_id))
        return OZAYN_PERM_ERR_ALREADY_EXISTS;
    if (svc->resource_count >= OZAYN_PERM_MAX_PERMS)
        return OZAYN_PERM_ERR_LIMIT_REACHED;

    int idx = svc->resource_count;
    ozayn_protected_resource_t *res = &svc->resources[idx];
    memset(res, 0, sizeof(*res));

    strncpy(res->id, resource_id, sizeof(res->id) - 1);
    strncpy(res->resource_type, resource_type, sizeof(res->resource_type) - 1);
    if (resource_ref)
        strncpy(res->resource_id, resource_ref, sizeof(res->resource_id) - 1);
    res->required_scope = required_scope;
    res->requires_authentication = requires_auth;
    res->requires_authorization = requires_authz;

    svc->resource_count++;

    *out_resource = *res;
    return OZAYN_PERM_OK;
}

ozayn_perm_error_t ozayn_perm_get_protected_resource(
    const ozayn_perm_service_t *svc,
    const char *resource_id,
    ozayn_protected_resource_t *out_resource)
{
    if (!svc || !resource_id || !out_resource)
        return OZAYN_PERM_ERR_NULL;
    if (!svc->initialized)
        return OZAYN_PERM_ERR_NOT_INITIALIZED;

    const ozayn_protected_resource_t *res =
        _find_resource((ozayn_perm_service_t *)svc, resource_id);
    if (!res)
        return OZAYN_PERM_ERR_NOT_FOUND;

    *out_resource = *res;
    return OZAYN_PERM_OK;
}

int ozayn_perm_is_protected(
    const ozayn_perm_service_t *svc,
    const char *resource_type,
    const char *resource_ref)
{
    if (!svc || !resource_type || !resource_ref)
        return 0;
    for (int i = 0; i < svc->resource_count; i++) {
        if (svc->resources[i].id[0] != '\0' &&
            strcmp(svc->resources[i].resource_type, resource_type) == 0 &&
            strcmp(svc->resources[i].resource_id, resource_ref) == 0)
            return 1;
    }
    return 0;
}

/* ============================================================
 * POLICY ENFORCEMENT
 * ============================================================ */

ozayn_enforcement_result_t ozayn_perm_enforce(
    const ozayn_perm_service_t *svc,
    const char *perm_id,
    const char *resource_type,
    const char *resource_id,
    ozayn_authz_scope_t request_scope)
{
    ozayn_enforcement_result_t result;
    memset(&result, 0, sizeof(result));

    if (!svc || !perm_id || !resource_type || !resource_id) {
        result.allowed = 0;
        result.error = OZAYN_PERM_ERR_NULL;
        strncpy(result.detail, "NULL argument", sizeof(result.detail) - 1);
        return result;
    }
    if (!svc->initialized) {
        result.allowed = 0;
        result.error = OZAYN_PERM_ERR_NOT_INITIALIZED;
        strncpy(result.detail, "Service not initialized",
                sizeof(result.detail) - 1);
        return result;
    }

    /* Find the permission */
    const ozayn_permission_t *perm =
        _find_perm((ozayn_perm_service_t *)svc, perm_id);
    if (!perm) {
        result.allowed = 0;
        result.error = OZAYN_PERM_ERR_NOT_FOUND;
        strncpy(result.detail, "Permission not found",
                sizeof(result.detail) - 1);
        return result;
    }

    /* Check permission is active */
    if (perm->state != OZAYN_PERM_ACTIVE) {
        result.allowed = 0;
        result.error = OZAYN_PERM_ERR_STATE_INVALID;
        snprintf(result.detail, sizeof(result.detail),
                 "Permission state: %s", ozayn_perm_state_name(perm->state));
        return result;
    }

    /* Resolve resource type from string */
    ozayn_authz_resource_type_t res_type = OZAYN_AUTHZ_RESOURCE_UNKNOWN;
    static const char *res_names[] = {
        "UNKNOWN", "core", "module", "plugin", "document", "memory",
        "database", "device", "camera", "microphone", "system",
        "identity", "session", "service"
    };
    for (int i = 1; i <= 13; i++) {
        if (strcmp(res_names[i], resource_type) == 0) {
            res_type = (ozayn_authz_resource_type_t)i;
            break;
        }
    }
    if (res_type == OZAYN_AUTHZ_RESOURCE_UNKNOWN) {
        result.allowed = 0;
        result.error = OZAYN_PERM_ERR_RESOURCE_INVALID;
        strncpy(result.detail, "Invalid resource type",
                sizeof(result.detail) - 1);
        return result;
    }

    /* Check if resource is protected and scope matches */
    for (int i = 0; i < svc->resource_count; i++) {
        const ozayn_protected_resource_t *res = &svc->resources[i];
        if (res->id[0] == '\0')
            continue;
        if (strcmp(res->resource_type, resource_type) != 0)
            continue;
        if (res->resource_id[0] != '\0' &&
            strcmp(res->resource_id, resource_id) != 0)
            continue;

        /* Resource found - check scope */
        if (res->required_scope != OZAYN_AUTHZ_SCOPE_GLOBAL &&
            res->required_scope != request_scope) {
            result.allowed = 0;
            result.error = OZAYN_PERM_ERR_DENIED;
            snprintf(result.detail, sizeof(result.detail),
                     "Scope mismatch: required=%d, requested=%d",
                     res->required_scope, request_scope);
            return result;
        }
        break;
    }

    /* Check permission matches */
    if (!ozayn_perm_matches(perm, res_type, perm->action, request_scope)) {
        result.allowed = 0;
        result.error = OZAYN_PERM_ERR_DENIED;
        strncpy(result.detail, "Permission does not match resource/action/scope",
                sizeof(result.detail) - 1);
        return result;
    }

    result.allowed = 1;
    result.error = OZAYN_PERM_OK;
    strncpy(result.detail, "Access granted", sizeof(result.detail) - 1);
    return result;
}

int ozayn_perm_validate_access(
    const ozayn_perm_service_t *svc,
    const char *perm_id,
    const ozayn_protected_resource_t *resource,
    ozayn_authz_scope_t request_scope)
{
    if (!svc || !perm_id || !resource)
        return 0;

    const ozayn_permission_t *perm =
        _find_perm((ozayn_perm_service_t *)svc, perm_id);
    if (!perm)
        return 0;
    if (perm->state != OZAYN_PERM_ACTIVE)
        return 0;

    /* Check scope */
    if (resource->required_scope != OZAYN_AUTHZ_SCOPE_GLOBAL &&
        resource->required_scope != request_scope)
        return 0;

    /* Resolve resource type string to enum */
    ozayn_authz_resource_type_t res_type = OZAYN_AUTHZ_RESOURCE_UNKNOWN;
    static const char *res_names[] = {
        "UNKNOWN", "core", "module", "plugin", "document", "memory",
        "database", "device", "camera", "microphone", "system",
        "identity", "session", "service"
    };
    for (int i = 1; i <= 13; i++) {
        if (strcmp(res_names[i], resource->resource_type) == 0) {
            res_type = (ozayn_authz_resource_type_t)i;
            break;
        }
    }

    return ozayn_perm_matches(perm, res_type, perm->action, request_scope);
}

/* ============================================================
 * AUTHORIZATION INTEGRATION
 * ============================================================ */

static ozayn_perm_service_t *_perm_svc_global = NULL;

ozayn_authz_error_t ozayn_authz_set_permission_service(
    ozayn_authz_service_t *authz_svc,
    ozayn_perm_service_t *perm_svc)
{
    if (!authz_svc)
        return OZAYN_AUTHZ_ERR_NULL;
    (void)perm_svc;
    _perm_svc_global = perm_svc;
    return OZAYN_AUTHZ_OK;
}

ozayn_perm_service_t *ozayn_authz_get_permission_service(
    const ozayn_authz_service_t *authz_svc)
{
    if (!authz_svc)
        return NULL;
    return _perm_svc_global;
}
