#ifndef OZAYN_RBAC_H
#define OZAYN_RBAC_H

#include "authorization.h"
#include "identity.h"
#include <stdint.h>
#include <stddef.h>

/*
 * rbac.h — Role-Based Access Control Foundation (Step 18).
 *
 * Answers: "Does this identity, through its role assignments and
 *           role permissions, have the right to perform this action?"
 *
 * Architecture:
 *   IDENTITY
 *      |
 *   ROLE ASSIGNMENT
 *      |
 *   ROLE
 *      |
 *   PERMISSIONS
 *      |
 *   AUTHORIZATION SERVICE
 *      |
 *   ALLOW / DENY / ERROR
 *
 * Flow:
 *   1. Validate session (from Step 16)
 *   2. Validate identity (from Step 17)
 *   3. Load active role assignments for identity
 *   4. Load active roles for each assignment
 *   5. Resolve permissions from all active roles
 *   6. Match requested resource + action + scope against permissions
 *   7. Return decision
 *
 * Default behavior: DENY on all error paths.
 *
 * Uses ozayn_rbac_ prefix to avoid collision with other modules.
 *
 * Step 18 scope:
 *   - Role management (create, get, suspend, revoke, archive)
 *   - Role permissions (add, remove, list)
 *   - Role assignments (assign, revoke, expire)
 *   - RBAC authorization integration
 *   - Permission matching (resource + action + scope)
 *   - Scope enforcement
 *   - Identity state integration
 *   - Session integration
 *   - Default-deny behavior
 *   - Security tests
 *
 * NOT in scope:
 *   - Role hierarchy / inheritance
 *   - MFA / Biometric
 *   - GUI / Admin dashboard
 *   - Distributed authorization
 *   - Cloud IAM / OAuth
 *   - Wildcard permissions
 *   - Administrative bypasses
 */

/* ============================================================
 * CONSTANTS
 * ============================================================ */

#define OZAYN_RBAC_MAX_ROLES            64
#define OZAYN_RBAC_MAX_PERMISSIONS      16
#define OZAYN_RBAC_MAX_ASSIGNMENTS     256
#define OZAYN_RBAC_MAX_ROLE_ID_LEN      64
#define OZAYN_RBAC_MAX_ROLE_NAME_LEN   128
#define OZAYN_RBAC_MAX_ROLE_DESC_LEN   256
#define OZAYN_RBAC_MAX_ASSIGNMENT_ID_LEN 64

/* ============================================================
 * RBAC ERROR CODES
 * ============================================================ */

typedef enum {
    OZAYN_RBAC_OK                          =   0,
    OZAYN_RBAC_ERR_NULL                    =  -1,
    OZAYN_RBAC_ERR_NOT_INITIALIZED         =  -2,
    OZAYN_RBAC_ERR_NOT_FOUND               =  -3,
    OZAYN_RBAC_ERR_ALREADY_EXISTS          =  -4,
    OZAYN_RBAC_ERR_INVALID                 =  -5,
    OZAYN_RBAC_ERR_ID_INVALID              =  -6,
    OZAYN_RBAC_ERR_STATE_INVALID           =  -7,
    OZAYN_RBAC_ERR_STATE_TRANSITION        =  -8,
    OZAYN_RBAC_ERR_SCOPE_INVALID           =  -9,
    OZAYN_RBAC_ERR_LIMIT_REACHED           = -10,
    OZAYN_RBAC_ERR_PERMISSION_INVALID      = -11,
    OZAYN_RBAC_ERR_PERMISSION_NOT_FOUND    = -12,
    OZAYN_RBAC_ERR_ASSIGNMENT_INVALID      = -13,
    OZAYN_RBAC_ERR_ASSIGNMENT_NOT_FOUND    = -14,
    OZAYN_RBAC_ERR_ASSIGNMENT_EXISTS       = -15,
    OZAYN_RBAC_ERR_IDENTITY_INVALID        = -16,
    OZAYN_RBAC_ERR_PRIVILEGE_ESCALATION    = -17,
    OZAYN_RBAC_ERR_STORAGE_FAILED          = -18,
    OZAYN_RBAC_ERR_VAULT_UNAVAILABLE       = -19,
    OZAYN_RBAC_ERR_INTEGRITY_FAILURE       = -20
} ozayn_rbac_error_t;

/* ============================================================
 * ROLE STATE
 * ============================================================ */

typedef enum {
    OZAYN_RBAC_ROLE_UNINITIALIZED = 0,
    OZAYN_RBAC_ROLE_ACTIVE        = 1,
    OZAYN_RBAC_ROLE_SUSPENDED     = 2,
    OZAYN_RBAC_ROLE_REVOKED       = 3,
    OZAYN_RBAC_ROLE_ARCHIVED      = 4
} ozayn_rbac_role_state_t;

/* ============================================================
 * ROLE ASSIGNMENT STATE
 * ============================================================ */

typedef enum {
    OZAYN_RBAC_ASSIGN_ACTIVE   = 0,
    OZAYN_RBAC_ASSIGN_SUSPENDED = 1,
    OZAYN_RBAC_ASSIGN_REVOKED  = 2,
    OZAYN_RBAC_ASSIGN_EXPIRED  = 3
} ozayn_rbac_assign_state_t;

/* ============================================================
 * ROLE OBJECT
 * ============================================================ */

typedef struct {
    char                        id[OZAYN_RBAC_MAX_ROLE_ID_LEN];
    char                        name[OZAYN_RBAC_MAX_ROLE_NAME_LEN];
    char                        description[OZAYN_RBAC_MAX_ROLE_DESC_LEN];
    ozayn_rbac_role_state_t     state;
    ozayn_authz_scope_t         scope;
    int                         version;
    time_t                      created_at;
    time_t                      modified_at;
    int                         in_use;
} ozayn_rbac_role_t;

/* ============================================================
 * ROLE PERMISSION (resource + action + scope tuple)
 * ============================================================ */

typedef struct {
    ozayn_authz_resource_type_t  resource;
    ozayn_authz_action_type_t    action;
    ozayn_authz_scope_t          scope;
} ozayn_rbac_permission_t;

/* ============================================================
 * ROLE ASSIGNMENT (identity → role)
 * ============================================================ */

typedef struct {
    char                        id[OZAYN_RBAC_MAX_ASSIGNMENT_ID_LEN];
    char                        identity_id[OZAYN_ID_MAX_ID_LEN];
    char                        role_id[OZAYN_RBAC_MAX_ROLE_ID_LEN];
    ozayn_authz_scope_t         scope;
    ozayn_rbac_assign_state_t   state;
    time_t                      created_at;
    time_t                      modified_at;
    int                         in_use;
} ozayn_rbac_assignment_t;

/* ============================================================
 * RBAC SERVICE CONFIGURATION
 * ============================================================ */

typedef struct {
    ozayn_identity_service_t    *identity_service;
} ozayn_rbac_service_config_t;

/* ============================================================
 * RBAC SERVICE
 * ============================================================ */

typedef struct ozayn_rbac_service {
    ozayn_rbac_role_t           roles[OZAYN_RBAC_MAX_ROLES];
    int                         role_count;

    /* Permissions are stored per-role in a parallel structure.
     * role_perms[i] holds permissions for roles[i]. */
    ozayn_rbac_permission_t     role_perms[OZAYN_RBAC_MAX_ROLES][OZAYN_RBAC_MAX_PERMISSIONS];
    int                         role_perm_count[OZAYN_RBAC_MAX_ROLES];

    ozayn_rbac_assignment_t     assignments[OZAYN_RBAC_MAX_ASSIGNMENTS];
    int                         assignment_count;

    ozayn_rbac_service_config_t config;
    int                         initialized;
} ozayn_rbac_service_t;

/* ============================================================
 * SERVICE LIFECYCLE
 * ============================================================ */

ozayn_rbac_error_t ozayn_rbac_service_init(
    ozayn_rbac_service_t *svc,
    const ozayn_rbac_service_config_t *config);

void ozayn_rbac_service_shutdown(ozayn_rbac_service_t *svc);

int ozayn_rbac_service_is_initialized(const ozayn_rbac_service_t *svc);

/* ============================================================
 * ROLE MANAGEMENT
 * ============================================================ */

ozayn_rbac_error_t ozayn_rbac_role_create(
    ozayn_rbac_service_t *svc,
    const char *role_id,
    const char *name,
    const char *description,
    ozayn_authz_scope_t scope,
    ozayn_rbac_role_t *out_role);

ozayn_rbac_error_t ozayn_rbac_role_get(
    const ozayn_rbac_service_t *svc,
    const char *role_id,
    ozayn_rbac_role_t *out_role);

int ozayn_rbac_role_exists(
    const ozayn_rbac_service_t *svc,
    const char *role_id);

ozayn_rbac_error_t ozayn_rbac_role_suspend(
    ozayn_rbac_service_t *svc,
    const char *role_id);

ozayn_rbac_error_t ozayn_rbac_role_revoke(
    ozayn_rbac_service_t *svc,
    const char *role_id);

ozayn_rbac_error_t ozayn_rbac_role_archive(
    ozayn_rbac_service_t *svc,
    const char *role_id);

int ozayn_rbac_role_count(const ozayn_rbac_service_t *svc);

/* ============================================================
 * ROLE PERMISSIONS
 * ============================================================ */

ozayn_rbac_error_t ozayn_rbac_role_add_permission(
    ozayn_rbac_service_t *svc,
    const char *role_id,
    ozayn_authz_resource_type_t resource,
    ozayn_authz_action_type_t action,
    ozayn_authz_scope_t scope);

ozayn_rbac_error_t ozayn_rbac_role_remove_permission(
    ozayn_rbac_service_t *svc,
    const char *role_id,
    ozayn_authz_resource_type_t resource,
    ozayn_authz_action_type_t action,
    ozayn_authz_scope_t scope);

int ozayn_rbac_role_has_permission(
    const ozayn_rbac_service_t *svc,
    const char *role_id,
    ozayn_authz_resource_type_t resource,
    ozayn_authz_action_type_t action,
    ozayn_authz_scope_t scope);

int ozayn_rbac_role_permission_count(
    const ozayn_rbac_service_t *svc,
    const char *role_id);

/* ============================================================
 * ROLE ASSIGNMENTS
 * ============================================================ */

ozayn_rbac_error_t ozayn_rbac_assign(
    ozayn_rbac_service_t *svc,
    const char *identity_id,
    const char *role_id,
    ozayn_authz_scope_t scope,
    ozayn_rbac_assignment_t *out_assignment);

ozayn_rbac_error_t ozayn_rbac_get_assignment(
    const ozayn_rbac_service_t *svc,
    const char *assignment_id,
    ozayn_rbac_assignment_t *out_assignment);

ozayn_rbac_error_t ozayn_rbac_suspend_assignment(
    ozayn_rbac_service_t *svc,
    const char *assignment_id);

ozayn_rbac_error_t ozayn_rbac_revoke_assignment(
    ozayn_rbac_service_t *svc,
    const char *assignment_id);

ozayn_rbac_error_t ozayn_rbac_expire_assignment(
    ozayn_rbac_service_t *svc,
    const char *assignment_id);

int ozayn_rbac_assignment_count(const ozayn_rbac_service_t *svc);

int ozayn_rbac_identity_assignment_count(
    const ozayn_rbac_service_t *svc,
    const char *identity_id);

/* ============================================================
 * RBAC AUTHORIZATION
 * ============================================================ */

/* Check if identity has a specific permission through active roles.
 * Returns 1 if permitted, 0 if not. */
int ozayn_rbac_check_permission(
    const ozayn_rbac_service_t *svc,
    const char *identity_id,
    ozayn_authz_resource_type_t resource,
    ozayn_authz_action_type_t action,
    ozayn_authz_scope_t request_scope);

/* Check if identity has any active role assignments. */
int ozayn_rbac_has_roles(
    const ozayn_rbac_service_t *svc,
    const char *identity_id);

/* ============================================================
 * VALIDATION
 * ============================================================ */

int ozayn_rbac_validate_role_id(const char *role_id);
int ozayn_rbac_validate_role_state(ozayn_rbac_role_state_t state);
int ozayn_rbac_validate_role_transition(ozayn_rbac_role_state_t from,
                                         ozayn_rbac_role_state_t to);
int ozayn_rbac_validate_assignment_state(ozayn_rbac_assign_state_t state);
int ozayn_rbac_validate_assignment_transition(ozayn_rbac_assign_state_t from,
                                                ozayn_rbac_assign_state_t to);

/* ============================================================
 * NAME HELPERS
 * ============================================================ */

const char *ozayn_rbac_error_name(ozayn_rbac_error_t error);
const char *ozayn_rbac_role_state_name(ozayn_rbac_role_state_t state);
const char *ozayn_rbac_assignment_state_name(ozayn_rbac_assign_state_t state);

/* ============================================================
 * AUTHORIZATION INTEGRATION
 * ============================================================ */

/* Set RBAC service on authorization service.
 * When set, authorize() will check RBAC permissions after
 * session/identity validation, before policy provider evaluation. */
ozayn_authz_error_t ozayn_authz_set_rbac_service(
    ozayn_authz_service_t *authz_svc,
    ozayn_rbac_service_t *rbac_svc);

/* Get RBAC service from authorization service. */
ozayn_rbac_service_t *ozayn_authz_get_rbac_service(
    const ozayn_authz_service_t *authz_svc);

#endif
