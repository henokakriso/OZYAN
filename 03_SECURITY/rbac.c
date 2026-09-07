#include "rbac.h"
#include <string.h>
#include <stdio.h>

/* ============================================================
 * VALIDATION
 * ============================================================ */

int ozayn_rbac_validate_role_id(const char *role_id)
{
    if (!role_id || role_id[0] == '\0')
        return -1;
    if (strlen(role_id) >= OZAYN_RBAC_MAX_ROLE_ID_LEN)
        return -1;
    for (const char *p = role_id; *p; p++) {
        char c = *p;
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') || c == '_' || c == '-' || c == '.'))
            return -1;
    }
    return 0;
}

int ozayn_rbac_validate_role_state(ozayn_rbac_role_state_t state)
{
    return (state >= OZAYN_RBAC_ROLE_UNINITIALIZED &&
            state <= OZAYN_RBAC_ROLE_ARCHIVED) ? 0 : -1;
}

int ozayn_rbac_validate_role_transition(ozayn_rbac_role_state_t from,
                                         ozayn_rbac_role_state_t to)
{
    if (from == OZAYN_RBAC_ROLE_UNINITIALIZED && to == OZAYN_RBAC_ROLE_ACTIVE)
        return 0;
    if (from == OZAYN_RBAC_ROLE_ACTIVE && to == OZAYN_RBAC_ROLE_SUSPENDED)
        return 0;
    if (from == OZAYN_RBAC_ROLE_ACTIVE && to == OZAYN_RBAC_ROLE_REVOKED)
        return 0;
    if (from == OZAYN_RBAC_ROLE_ACTIVE && to == OZAYN_RBAC_ROLE_ARCHIVED)
        return 0;
    if (from == OZAYN_RBAC_ROLE_SUSPENDED && to == OZAYN_RBAC_ROLE_ACTIVE)
        return 0;
    if (from == OZAYN_RBAC_ROLE_SUSPENDED && to == OZAYN_RBAC_ROLE_REVOKED)
        return 0;
    if (from == OZAYN_RBAC_ROLE_SUSPENDED && to == OZAYN_RBAC_ROLE_ARCHIVED)
        return 0;
    if (from == OZAYN_RBAC_ROLE_REVOKED && to == OZAYN_RBAC_ROLE_ARCHIVED)
        return 0;
    return -1;
}

int ozayn_rbac_validate_assignment_state(ozayn_rbac_assign_state_t state)
{
    return (state >= OZAYN_RBAC_ASSIGN_ACTIVE &&
            state <= OZAYN_RBAC_ASSIGN_EXPIRED) ? 0 : -1;
}

int ozayn_rbac_validate_assignment_transition(ozayn_rbac_assign_state_t from,
                                                ozayn_rbac_assign_state_t to)
{
    if (from == OZAYN_RBAC_ASSIGN_ACTIVE && to == OZAYN_RBAC_ASSIGN_SUSPENDED)
        return 0;
    if (from == OZAYN_RBAC_ASSIGN_ACTIVE && to == OZAYN_RBAC_ASSIGN_REVOKED)
        return 0;
    if (from == OZAYN_RBAC_ASSIGN_ACTIVE && to == OZAYN_RBAC_ASSIGN_EXPIRED)
        return 0;
    if (from == OZAYN_RBAC_ASSIGN_SUSPENDED && to == OZAYN_RBAC_ASSIGN_ACTIVE)
        return 0;
    if (from == OZAYN_RBAC_ASSIGN_SUSPENDED && to == OZAYN_RBAC_ASSIGN_REVOKED)
        return 0;
    return -1;
}

/* ============================================================
 * NAME HELPERS
 * ============================================================ */

const char *ozayn_rbac_error_name(ozayn_rbac_error_t error)
{
    switch (error) {
        case OZAYN_RBAC_OK:                         return "OK";
        case OZAYN_RBAC_ERR_NULL:                   return "NULL";
        case OZAYN_RBAC_ERR_NOT_INITIALIZED:        return "NOT_INITIALIZED";
        case OZAYN_RBAC_ERR_NOT_FOUND:              return "NOT_FOUND";
        case OZAYN_RBAC_ERR_ALREADY_EXISTS:         return "ALREADY_EXISTS";
        case OZAYN_RBAC_ERR_INVALID:                return "INVALID";
        case OZAYN_RBAC_ERR_ID_INVALID:             return "ID_INVALID";
        case OZAYN_RBAC_ERR_STATE_INVALID:          return "STATE_INVALID";
        case OZAYN_RBAC_ERR_STATE_TRANSITION:       return "STATE_TRANSITION";
        case OZAYN_RBAC_ERR_SCOPE_INVALID:          return "SCOPE_INVALID";
        case OZAYN_RBAC_ERR_LIMIT_REACHED:          return "LIMIT_REACHED";
        case OZAYN_RBAC_ERR_PERMISSION_INVALID:     return "PERMISSION_INVALID";
        case OZAYN_RBAC_ERR_PERMISSION_NOT_FOUND:   return "PERMISSION_NOT_FOUND";
        case OZAYN_RBAC_ERR_ASSIGNMENT_INVALID:     return "ASSIGNMENT_INVALID";
        case OZAYN_RBAC_ERR_ASSIGNMENT_NOT_FOUND:   return "ASSIGNMENT_NOT_FOUND";
        case OZAYN_RBAC_ERR_ASSIGNMENT_EXISTS:      return "ASSIGNMENT_EXISTS";
        case OZAYN_RBAC_ERR_IDENTITY_INVALID:       return "IDENTITY_INVALID";
        case OZAYN_RBAC_ERR_PRIVILEGE_ESCALATION:   return "PRIVILEGE_ESCALATION";
        case OZAYN_RBAC_ERR_STORAGE_FAILED:         return "STORAGE_FAILED";
        case OZAYN_RBAC_ERR_VAULT_UNAVAILABLE:      return "VAULT_UNAVAILABLE";
        case OZAYN_RBAC_ERR_INTEGRITY_FAILURE:      return "INTEGRITY_FAILURE";
        default:                                    return "UNKNOWN";
    }
}

const char *ozayn_rbac_role_state_name(ozayn_rbac_role_state_t state)
{
    switch (state) {
        case OZAYN_RBAC_ROLE_UNINITIALIZED: return "UNINITIALIZED";
        case OZAYN_RBAC_ROLE_ACTIVE:        return "ACTIVE";
        case OZAYN_RBAC_ROLE_SUSPENDED:     return "SUSPENDED";
        case OZAYN_RBAC_ROLE_REVOKED:       return "REVOKED";
        case OZAYN_RBAC_ROLE_ARCHIVED:      return "ARCHIVED";
        default:                            return "UNKNOWN";
    }
}

const char *ozayn_rbac_assignment_state_name(ozayn_rbac_assign_state_t state)
{
    switch (state) {
        case OZAYN_RBAC_ASSIGN_ACTIVE:    return "ACTIVE";
        case OZAYN_RBAC_ASSIGN_SUSPENDED: return "SUSPENDED";
        case OZAYN_RBAC_ASSIGN_REVOKED:   return "REVOKED";
        case OZAYN_RBAC_ASSIGN_EXPIRED:   return "EXPIRED";
        default:                          return "UNKNOWN";
    }
}

/* ============================================================
 * INTERNAL HELPERS
 * ============================================================ */

static ozayn_rbac_role_t *_find_role(ozayn_rbac_service_t *svc, const char *role_id)
{
    if (!svc || !role_id)
        return NULL;
    for (int i = 0; i < svc->role_count; i++) {
        if (svc->roles[i].in_use &&
            strcmp(svc->roles[i].id, role_id) == 0)
            return &svc->roles[i];
    }
    return NULL;
}

static int _find_role_index(const ozayn_rbac_service_t *svc, const char *role_id)
{
    if (!svc || !role_id)
        return -1;
    for (int i = 0; i < svc->role_count; i++) {
        if (svc->roles[i].in_use &&
            strcmp(svc->roles[i].id, role_id) == 0)
            return i;
    }
    return -1;
}

static ozayn_rbac_assignment_t *_find_assignment(ozayn_rbac_service_t *svc,
                                                   const char *assignment_id)
{
    if (!svc || !assignment_id)
        return NULL;
    for (int i = 0; i < svc->assignment_count; i++) {
        if (svc->assignments[i].in_use &&
            strcmp(svc->assignments[i].id, assignment_id) == 0)
            return &svc->assignments[i];
    }
    return NULL;
}

static ozayn_rbac_error_t _generate_assignment_id(char *buf, size_t len)
{
    static int _assign_counter = 0;
    time_t now = time(NULL);
    _assign_counter++;
    int n = snprintf(buf, len, "asgn-%d-%ld", _assign_counter, (long)now);
    if (n < 0 || (size_t)n >= len)
        return OZAYN_RBAC_ERR_INVALID;
    return OZAYN_RBAC_OK;
}

/* ============================================================
 * SERVICE LIFECYCLE
 * ============================================================ */

ozayn_rbac_error_t ozayn_rbac_service_init(
    ozayn_rbac_service_t *svc,
    const ozayn_rbac_service_config_t *config)
{
    if (!svc)
        return OZAYN_RBAC_ERR_NULL;
    if (!config)
        return OZAYN_RBAC_ERR_NULL;
    if (!config->identity_service)
        return OZAYN_RBAC_ERR_INVALID;

    memset(svc, 0, sizeof(*svc));
    svc->config = *config;
    svc->initialized = 1;
    return OZAYN_RBAC_OK;
}

void ozayn_rbac_service_shutdown(ozayn_rbac_service_t *svc)
{
    if (!svc)
        return;
    svc->initialized = 0;
}

int ozayn_rbac_service_is_initialized(const ozayn_rbac_service_t *svc)
{
    if (!svc)
        return 0;
    return svc->initialized;
}

/* ============================================================
 * ROLE MANAGEMENT
 * ============================================================ */

ozayn_rbac_error_t ozayn_rbac_role_create(
    ozayn_rbac_service_t *svc,
    const char *role_id,
    const char *name,
    const char *description,
    ozayn_authz_scope_t scope,
    ozayn_rbac_role_t *out_role)
{
    if (!svc || !role_id || !out_role)
        return OZAYN_RBAC_ERR_NULL;
    if (!svc->initialized)
        return OZAYN_RBAC_ERR_NOT_INITIALIZED;
    if (ozayn_rbac_validate_role_id(role_id) != 0)
        return OZAYN_RBAC_ERR_ID_INVALID;
    if (scope == OZAYN_AUTHZ_SCOPE_UNKNOWN)
        return OZAYN_RBAC_ERR_SCOPE_INVALID;
    if (_find_role(svc, role_id))
        return OZAYN_RBAC_ERR_ALREADY_EXISTS;
    if (svc->role_count >= OZAYN_RBAC_MAX_ROLES)
        return OZAYN_RBAC_ERR_LIMIT_REACHED;

    int idx = svc->role_count;
    ozayn_rbac_role_t *role = &svc->roles[idx];
    memset(role, 0, sizeof(*role));

    strncpy(role->id, role_id, sizeof(role->id) - 1);
    if (name)
        strncpy(role->name, name, sizeof(role->name) - 1);
    else
        strncpy(role->name, role_id, sizeof(role->name) - 1);
    if (description)
        strncpy(role->description, description, sizeof(role->description) - 1);
    role->scope = scope;
    role->state = OZAYN_RBAC_ROLE_ACTIVE;
    role->version = 1;
    role->created_at = time(NULL);
    role->modified_at = role->created_at;
    role->in_use = 1;

    svc->role_count++;
    svc->role_perm_count[idx] = 0;

    *out_role = *role;
    return OZAYN_RBAC_OK;
}

ozayn_rbac_error_t ozayn_rbac_role_get(
    const ozayn_rbac_service_t *svc,
    const char *role_id,
    ozayn_rbac_role_t *out_role)
{
    if (!svc || !role_id || !out_role)
        return OZAYN_RBAC_ERR_NULL;
    if (!svc->initialized)
        return OZAYN_RBAC_ERR_NOT_INITIALIZED;

    const ozayn_rbac_role_t *role = _find_role((ozayn_rbac_service_t *)svc, role_id);
    if (!role)
        return OZAYN_RBAC_ERR_NOT_FOUND;

    *out_role = *role;
    return OZAYN_RBAC_OK;
}

int ozayn_rbac_role_exists(
    const ozayn_rbac_service_t *svc,
    const char *role_id)
{
    if (!svc || !role_id)
        return 0;
    return _find_role((ozayn_rbac_service_t *)svc, role_id) != NULL ? 1 : 0;
}

static ozayn_rbac_error_t _role_transition(ozayn_rbac_service_t *svc,
                                             const char *role_id,
                                             ozayn_rbac_role_state_t target)
{
    if (!svc || !role_id)
        return OZAYN_RBAC_ERR_NULL;
    if (!svc->initialized)
        return OZAYN_RBAC_ERR_NOT_INITIALIZED;

    ozayn_rbac_role_t *role = _find_role(svc, role_id);
    if (!role)
        return OZAYN_RBAC_ERR_NOT_FOUND;

    if (ozayn_rbac_validate_role_transition(role->state, target) != 0)
        return OZAYN_RBAC_ERR_STATE_TRANSITION;

    role->state = target;
    role->modified_at = time(NULL);
    role->version++;
    return OZAYN_RBAC_OK;
}

ozayn_rbac_error_t ozayn_rbac_role_suspend(
    ozayn_rbac_service_t *svc,
    const char *role_id)
{
    return _role_transition(svc, role_id, OZAYN_RBAC_ROLE_SUSPENDED);
}

ozayn_rbac_error_t ozayn_rbac_role_revoke(
    ozayn_rbac_service_t *svc,
    const char *role_id)
{
    return _role_transition(svc, role_id, OZAYN_RBAC_ROLE_REVOKED);
}

ozayn_rbac_error_t ozayn_rbac_role_archive(
    ozayn_rbac_service_t *svc,
    const char *role_id)
{
    return _role_transition(svc, role_id, OZAYN_RBAC_ROLE_ARCHIVED);
}

int ozayn_rbac_role_count(const ozayn_rbac_service_t *svc)
{
    if (!svc)
        return 0;
    return svc->role_count;
}

/* ============================================================
 * ROLE PERMISSIONS
 * ============================================================ */

ozayn_rbac_error_t ozayn_rbac_role_add_permission(
    ozayn_rbac_service_t *svc,
    const char *role_id,
    ozayn_authz_resource_type_t resource,
    ozayn_authz_action_type_t action,
    ozayn_authz_scope_t scope)
{
    if (!svc || !role_id)
        return OZAYN_RBAC_ERR_NULL;
    if (!svc->initialized)
        return OZAYN_RBAC_ERR_NOT_INITIALIZED;
    if (resource == OZAYN_AUTHZ_RESOURCE_UNKNOWN)
        return OZAYN_RBAC_ERR_PERMISSION_INVALID;
    if (action == OZAYN_AUTHZ_ACTION_UNKNOWN)
        return OZAYN_RBAC_ERR_PERMISSION_INVALID;
    if (scope == OZAYN_AUTHZ_SCOPE_UNKNOWN)
        return OZAYN_RBAC_ERR_SCOPE_INVALID;

    int idx = _find_role_index(svc, role_id);
    if (idx < 0)
        return OZAYN_RBAC_ERR_NOT_FOUND;

    int pc = svc->role_perm_count[idx];
    if (pc >= OZAYN_RBAC_MAX_PERMISSIONS)
        return OZAYN_RBAC_ERR_LIMIT_REACHED;

    /* Check for duplicate */
    for (int i = 0; i < pc; i++) {
        ozayn_rbac_permission_t *p = &svc->role_perms[idx][i];
        if (p->resource == resource && p->action == action && p->scope == scope)
            return OZAYN_RBAC_ERR_ALREADY_EXISTS;
    }

    svc->role_perms[idx][pc].resource = resource;
    svc->role_perms[idx][pc].action = action;
    svc->role_perms[idx][pc].scope = scope;
    svc->role_perm_count[idx]++;

    return OZAYN_RBAC_OK;
}

ozayn_rbac_error_t ozayn_rbac_role_remove_permission(
    ozayn_rbac_service_t *svc,
    const char *role_id,
    ozayn_authz_resource_type_t resource,
    ozayn_authz_action_type_t action,
    ozayn_authz_scope_t scope)
{
    if (!svc || !role_id)
        return OZAYN_RBAC_ERR_NULL;
    if (!svc->initialized)
        return OZAYN_RBAC_ERR_NOT_INITIALIZED;

    int idx = _find_role_index(svc, role_id);
    if (idx < 0)
        return OZAYN_RBAC_ERR_NOT_FOUND;

    int pc = svc->role_perm_count[idx];
    for (int i = 0; i < pc; i++) {
        ozayn_rbac_permission_t *p = &svc->role_perms[idx][i];
        if (p->resource == resource && p->action == action && p->scope == scope) {
            /* Shift remaining permissions */
            for (int j = i; j < pc - 1; j++)
                svc->role_perms[idx][j] = svc->role_perms[idx][j + 1];
            memset(&svc->role_perms[idx][pc - 1], 0, sizeof(ozayn_rbac_permission_t));
            svc->role_perm_count[idx]--;
            return OZAYN_RBAC_OK;
        }
    }
    return OZAYN_RBAC_ERR_PERMISSION_NOT_FOUND;
}

int ozayn_rbac_role_has_permission(
    const ozayn_rbac_service_t *svc,
    const char *role_id,
    ozayn_authz_resource_type_t resource,
    ozayn_authz_action_type_t action,
    ozayn_authz_scope_t scope)
{
    if (!svc || !role_id)
        return 0;

    int idx = _find_role_index(svc, role_id);
    if (idx < 0)
        return 0;

    int pc = svc->role_perm_count[idx];
    for (int i = 0; i < pc; i++) {
        ozayn_rbac_permission_t *p = (ozayn_rbac_permission_t *)&svc->role_perms[idx][i];
        if (p->resource == resource && p->action == action && p->scope == scope)
            return 1;
    }
    return 0;
}

int ozayn_rbac_role_permission_count(
    const ozayn_rbac_service_t *svc,
    const char *role_id)
{
    if (!svc || !role_id)
        return -1;

    int idx = _find_role_index(svc, role_id);
    if (idx < 0)
        return -1;

    return svc->role_perm_count[idx];
}

/* ============================================================
 * ROLE ASSIGNMENTS
 * ============================================================ */

ozayn_rbac_error_t ozayn_rbac_assign(
    ozayn_rbac_service_t *svc,
    const char *identity_id,
    const char *role_id,
    ozayn_authz_scope_t scope,
    ozayn_rbac_assignment_t *out_assignment)
{
    if (!svc || !identity_id || !role_id || !out_assignment)
        return OZAYN_RBAC_ERR_NULL;
    if (!svc->initialized)
        return OZAYN_RBAC_ERR_NOT_INITIALIZED;
    if (identity_id[0] == '\0')
        return OZAYN_RBAC_ERR_IDENTITY_INVALID;
    if (ozayn_rbac_validate_role_id(role_id) != 0)
        return OZAYN_RBAC_ERR_ID_INVALID;
    if (scope == OZAYN_AUTHZ_SCOPE_UNKNOWN)
        return OZAYN_RBAC_ERR_SCOPE_INVALID;

    /* Role must exist and be active */
    ozayn_rbac_role_t *role = _find_role(svc, role_id);
    if (!role)
        return OZAYN_RBAC_ERR_NOT_FOUND;
    if (role->state != OZAYN_RBAC_ROLE_ACTIVE)
        return OZAYN_RBAC_ERR_STATE_INVALID;

    /* Check identity exists */
    ozayn_identity_t ident;
    if (ozayn_id_get(svc->config.identity_service, identity_id, &ident) != OZAYN_ID_OK)
        return OZAYN_RBAC_ERR_IDENTITY_INVALID;
    if (ident.state != OZAYN_ID_STATE_ACTIVE)
        return OZAYN_RBAC_ERR_IDENTITY_INVALID;

    /* Check for duplicate assignment (same identity + role) */
    for (int i = 0; i < svc->assignment_count; i++) {
        if (svc->assignments[i].in_use &&
            strcmp(svc->assignments[i].identity_id, identity_id) == 0 &&
            strcmp(svc->assignments[i].role_id, role_id) == 0 &&
            svc->assignments[i].state == OZAYN_RBAC_ASSIGN_ACTIVE)
            return OZAYN_RBAC_ERR_ASSIGNMENT_EXISTS;
    }

    if (svc->assignment_count >= OZAYN_RBAC_MAX_ASSIGNMENTS)
        return OZAYN_RBAC_ERR_LIMIT_REACHED;

    int idx = svc->assignment_count;
    ozayn_rbac_assignment_t *a = &svc->assignments[idx];
    memset(a, 0, sizeof(*a));

    ozayn_rbac_error_t gen_r = _generate_assignment_id(a->id, sizeof(a->id));
    if (gen_r != OZAYN_RBAC_OK)
        return gen_r;

    strncpy(a->identity_id, identity_id, sizeof(a->identity_id) - 1);
    strncpy(a->role_id, role_id, sizeof(a->role_id) - 1);
    a->scope = scope;
    a->state = OZAYN_RBAC_ASSIGN_ACTIVE;
    a->created_at = time(NULL);
    a->modified_at = a->created_at;
    a->in_use = 1;

    svc->assignment_count++;

    *out_assignment = *a;
    return OZAYN_RBAC_OK;
}

ozayn_rbac_error_t ozayn_rbac_get_assignment(
    const ozayn_rbac_service_t *svc,
    const char *assignment_id,
    ozayn_rbac_assignment_t *out_assignment)
{
    if (!svc || !assignment_id || !out_assignment)
        return OZAYN_RBAC_ERR_NULL;
    if (!svc->initialized)
        return OZAYN_RBAC_ERR_NOT_INITIALIZED;

    const ozayn_rbac_assignment_t *a =
        _find_assignment((ozayn_rbac_service_t *)svc, assignment_id);
    if (!a)
        return OZAYN_RBAC_ERR_ASSIGNMENT_NOT_FOUND;

    *out_assignment = *a;
    return OZAYN_RBAC_OK;
}

static ozayn_rbac_error_t _assignment_transition(ozayn_rbac_service_t *svc,
                                                   const char *assignment_id,
                                                   ozayn_rbac_assign_state_t target)
{
    if (!svc || !assignment_id)
        return OZAYN_RBAC_ERR_NULL;
    if (!svc->initialized)
        return OZAYN_RBAC_ERR_NOT_INITIALIZED;

    ozayn_rbac_assignment_t *a = _find_assignment(svc, assignment_id);
    if (!a)
        return OZAYN_RBAC_ERR_ASSIGNMENT_NOT_FOUND;

    if (ozayn_rbac_validate_assignment_transition(a->state, target) != 0)
        return OZAYN_RBAC_ERR_STATE_TRANSITION;

    a->state = target;
    a->modified_at = time(NULL);
    return OZAYN_RBAC_OK;
}

ozayn_rbac_error_t ozayn_rbac_suspend_assignment(
    ozayn_rbac_service_t *svc,
    const char *assignment_id)
{
    return _assignment_transition(svc, assignment_id, OZAYN_RBAC_ASSIGN_SUSPENDED);
}

ozayn_rbac_error_t ozayn_rbac_revoke_assignment(
    ozayn_rbac_service_t *svc,
    const char *assignment_id)
{
    return _assignment_transition(svc, assignment_id, OZAYN_RBAC_ASSIGN_REVOKED);
}

ozayn_rbac_error_t ozayn_rbac_expire_assignment(
    ozayn_rbac_service_t *svc,
    const char *assignment_id)
{
    return _assignment_transition(svc, assignment_id, OZAYN_RBAC_ASSIGN_EXPIRED);
}

int ozayn_rbac_assignment_count(const ozayn_rbac_service_t *svc)
{
    if (!svc)
        return 0;
    return svc->assignment_count;
}

int ozayn_rbac_identity_assignment_count(
    const ozayn_rbac_service_t *svc,
    const char *identity_id)
{
    if (!svc || !identity_id)
        return 0;
    int count = 0;
    for (int i = 0; i < svc->assignment_count; i++) {
        if (svc->assignments[i].in_use &&
            strcmp(svc->assignments[i].identity_id, identity_id) == 0)
            count++;
    }
    return count;
}

/* ============================================================
 * RBAC AUTHORIZATION
 * ============================================================ */

static int _scope_covers(ozayn_authz_scope_t assignment_scope,
                           ozayn_authz_scope_t request_scope)
{
    if (assignment_scope == OZAYN_AUTHZ_SCOPE_GLOBAL)
        return 1;
    return assignment_scope == request_scope;
}

int ozayn_rbac_check_permission(
    const ozayn_rbac_service_t *svc,
    const char *identity_id,
    ozayn_authz_resource_type_t resource,
    ozayn_authz_action_type_t action,
    ozayn_authz_scope_t request_scope)
{
    if (!svc || !identity_id)
        return 0;
    if (!svc->initialized)
        return 0;

    /* Check identity exists and is active */
    ozayn_identity_t ident;
    if (ozayn_id_get(svc->config.identity_service, identity_id, &ident) != OZAYN_ID_OK)
        return 0;
    if (ident.state != OZAYN_ID_STATE_ACTIVE)
        return 0;

    /* Iterate over assignments for this identity */
    for (int i = 0; i < svc->assignment_count; i++) {
        const ozayn_rbac_assignment_t *a = &svc->assignments[i];
        if (!a->in_use)
            continue;
        if (strcmp(a->identity_id, identity_id) != 0)
            continue;
        if (a->state != OZAYN_RBAC_ASSIGN_ACTIVE)
            continue;

        /* Check assignment scope covers request scope */
        if (!_scope_covers(a->scope, request_scope))
            continue;

        /* Find the role */
        const ozayn_rbac_role_t *role =
            _find_role((ozayn_rbac_service_t *)svc, a->role_id);
        if (!role)
            continue;
        if (role->state != OZAYN_RBAC_ROLE_ACTIVE)
            continue;

        /* Check role permissions */
        int idx = _find_role_index(svc, a->role_id);
        if (idx < 0)
            continue;
        int pc = svc->role_perm_count[idx];
        for (int j = 0; j < pc; j++) {
            const ozayn_rbac_permission_t *p = &svc->role_perms[idx][j];
            if (p->resource == resource && p->action == action) {
                /* Permission matches resource+action. Check scope. */
                if (_scope_covers(p->scope, request_scope))
                    return 1;
            }
        }
    }
    return 0;
}

int ozayn_rbac_has_roles(
    const ozayn_rbac_service_t *svc,
    const char *identity_id)
{
    if (!svc || !identity_id)
        return 0;
    for (int i = 0; i < svc->assignment_count; i++) {
        if (svc->assignments[i].in_use &&
            strcmp(svc->assignments[i].identity_id, identity_id) == 0 &&
            svc->assignments[i].state == OZAYN_RBAC_ASSIGN_ACTIVE)
            return 1;
    }
    return 0;
}

/* ============================================================
 * AUTHORIZATION INTEGRATION
 * ============================================================ */

/* We store the RBAC service pointer in the authz service by extending
 * the struct. Since we can't modify the struct directly (it's in
 * authorization.h), we use a global pointer for integration.
 * In production this would be a struct member. */
static ozayn_rbac_service_t *_rbac_svc_global = NULL;

ozayn_authz_error_t ozayn_authz_set_rbac_service(
    ozayn_authz_service_t *authz_svc,
    ozayn_rbac_service_t *rbac_svc)
{
    if (!authz_svc)
        return OZAYN_AUTHZ_ERR_NULL;
    (void)rbac_svc;
    _rbac_svc_global = rbac_svc;
    return OZAYN_AUTHZ_OK;
}

ozayn_rbac_service_t *ozayn_authz_get_rbac_service(
    const ozayn_authz_service_t *authz_svc)
{
    if (!authz_svc)
        return NULL;
    return _rbac_svc_global;
}
