#ifndef OZAYN_PERMISSION_H
#define OZAYN_PERMISSION_H

#include "authorization.h"
#include <stdint.h>
#include <stddef.h>
#include <time.h>

/*
 * permission.h — Permission Management & Policy Enforcement (Step 19).
 *
 * Answers: "What can this identity do, and how is that enforced?"
 *
 * Architecture:
 *   PERMISSION OBJECT (standalone, lifecycle-managed)
 *      |
 *   ROLE-PERMISSION LINKS (roles reference permission IDs)
 *      |
 *   RBAC CHECK (from Step 18)
 *      |
 *   AUTHORIZATION SERVICE (from Step 17)
 *      |
 *   POLICY ENFORCEMENT
 *      |
 *   ALLOW / DENY / ERROR
 *
 * Flow:
 *   1. Permission objects created independently with unique IDs
 *   2. Roles reference permission IDs (not inline tuples)
 *   3. RBAC resolves permissions through role assignments
 *   4. Authorization service enforces policy via permission service
 *   5. Protected resource boundary validates access
 *
 * Step 19 scope:
 *   - Permission object lifecycle (create, get, suspend, revoke, archive)
 *   - Permission validation (resource + action + scope)
 *   - Permission matching
 *   - Role-permission integration enhancement
 *   - Policy enforcement layer
 *   - Protected resource boundary
 *   - Comprehensive tests
 *
 * NOT in scope:
 *   - Wildcard permissions
 *   - Permission inheritance
 *   - Dynamic policy generation
 *   - Distributed permission management
 *   - GUI / Admin dashboard
 *   - Cloud IAM integration
 */

/* ============================================================
 * CONSTANTS
 * ============================================================ */

#define OZAYN_PERM_MAX_ID_LEN       64
#define OZAYN_PERM_MAX_NAME_LEN    128
#define OZAYN_PERM_MAX_DESC_LEN    256
#define OZAYN_PERM_MAX_PERMS      1024
#define OZAYN_PERM_MAX_ROLE_PERMS   64

/* ============================================================
 * PERMISSION ERROR CODES
 * ============================================================ */

typedef enum {
    OZAYN_PERM_OK                     =   0,
    OZAYN_PERM_ERR_NULL               =  -1,
    OZAYN_PERM_ERR_NOT_INITIALIZED    =  -2,
    OZAYN_PERM_ERR_NOT_FOUND          =  -3,
    OZAYN_PERM_ERR_ALREADY_EXISTS     =  -4,
    OZAYN_PERM_ERR_INVALID            =  -5,
    OZAYN_PERM_ERR_ID_INVALID         =  -6,
    OZAYN_PERM_ERR_STATE_INVALID      =  -7,
    OZAYN_PERM_ERR_STATE_TRANSITION   =  -8,
    OZAYN_PERM_ERR_SCOPE_INVALID      =  -9,
    OZAYN_PERM_ERR_LIMIT_REACHED      = -10,
    OZAYN_PERM_ERR_RESOURCE_INVALID   = -11,
    OZAYN_PERM_ERR_ACTION_INVALID     = -12,
    OZAYN_PERM_ERR_DENIED             = -13,
    OZAYN_PERM_ERR_ENFORCEMENT_FAILED = -14
} ozayn_perm_error_t;

/* ============================================================
 * PERMISSION STATE
 * ============================================================ */

typedef enum {
    OZAYN_PERM_UNINITIALIZED = 0,
    OZAYN_PERM_ACTIVE        = 1,
    OZAYN_PERM_SUSPENDED     = 2,
    OZAYN_PERM_REVOKED       = 3,
    OZAYN_PERM_ARCHIVED      = 4
} ozayn_perm_state_t;

/* ============================================================
 * PERMISSION OBJECT
 * ============================================================ */

typedef struct {
    char                        id[OZAYN_PERM_MAX_ID_LEN];
    char                        name[OZAYN_PERM_MAX_NAME_LEN];
    char                        description[OZAYN_PERM_MAX_DESC_LEN];
    ozayn_authz_resource_type_t resource;
    ozayn_authz_action_type_t   action;
    ozayn_authz_scope_t         scope;
    ozayn_perm_state_t          state;
    int                         version;
    time_t                      created_at;
    time_t                      modified_at;
    int                         in_use;
} ozayn_permission_t;

/* ============================================================
 * PROTECTED RESOURCE
 * ============================================================ */

typedef struct {
    char                        id[OZAYN_PERM_MAX_ID_LEN];
    char                        resource_type[OZAYN_AUTHZ_MAX_RESOURCE_TYPE_LEN];
    char                        resource_id[OZAYN_AUTHZ_MAX_RESOURCE_ID_LEN];
    ozayn_authz_scope_t         required_scope;
    int                         requires_authentication;
    int                         requires_authorization;
} ozayn_protected_resource_t;

/* ============================================================
 * ENFORCEMENT RESULT
 * ============================================================ */

typedef struct {
    int                         allowed;
    ozayn_perm_error_t          error;
    char                        detail[OZAYN_PERM_MAX_DESC_LEN];
} ozayn_enforcement_result_t;

/* ============================================================
 * PERMISSION SERVICE CONFIGURATION
 * ============================================================ */

typedef struct {
    /* No external dependencies required for permission management */
    int reserved;
} ozayn_perm_service_config_t;

/* ============================================================
 * PERMISSION SERVICE
 * ============================================================ */

typedef struct ozayn_perm_service {
    ozayn_permission_t          perms[OZAYN_PERM_MAX_PERMS];
    int                         perm_count;

    ozayn_protected_resource_t  resources[OZAYN_PERM_MAX_PERMS];
    int                         resource_count;

    ozayn_perm_service_config_t config;
    int                         initialized;
} ozayn_perm_service_t;

/* ============================================================
 * SERVICE LIFECYCLE
 * ============================================================ */

ozayn_perm_error_t ozayn_perm_service_init(
    ozayn_perm_service_t *svc,
    const ozayn_perm_service_config_t *config);

void ozayn_perm_service_shutdown(ozayn_perm_service_t *svc);

int ozayn_perm_service_is_initialized(const ozayn_perm_service_t *svc);

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
    ozayn_permission_t *out_perm);

ozayn_perm_error_t ozayn_perm_get(
    const ozayn_perm_service_t *svc,
    const char *perm_id,
    ozayn_permission_t *out_perm);

int ozayn_perm_exists(
    const ozayn_perm_service_t *svc,
    const char *perm_id);

ozayn_perm_error_t ozayn_perm_suspend(
    ozayn_perm_service_t *svc,
    const char *perm_id);

ozayn_perm_error_t ozayn_perm_resume(
    ozayn_perm_service_t *svc,
    const char *perm_id);

ozayn_perm_error_t ozayn_perm_revoke(
    ozayn_perm_service_t *svc,
    const char *perm_id);

ozayn_perm_error_t ozayn_perm_archive(
    ozayn_perm_service_t *svc,
    const char *perm_id);

int ozayn_perm_count(const ozayn_perm_service_t *svc);

/* ============================================================
 * PERMISSION MATCHING
 * ============================================================ */

int ozayn_perm_matches(
    const ozayn_permission_t *perm,
    ozayn_authz_resource_type_t resource,
    ozayn_authz_action_type_t action,
    ozayn_authz_scope_t request_scope);

int ozayn_perm_service_check(
    const ozayn_perm_service_t *svc,
    const char *perm_id,
    ozayn_authz_resource_type_t resource,
    ozayn_authz_action_type_t action,
    ozayn_authz_scope_t request_scope);

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
    ozayn_protected_resource_t *out_resource);

ozayn_perm_error_t ozayn_perm_get_protected_resource(
    const ozayn_perm_service_t *svc,
    const char *resource_id,
    ozayn_protected_resource_t *out_resource);

int ozayn_perm_is_protected(
    const ozayn_perm_service_t *svc,
    const char *resource_type,
    const char *resource_ref);

/* ============================================================
 * POLICY ENFORCEMENT
 * ============================================================ */

ozayn_enforcement_result_t ozayn_perm_enforce(
    const ozayn_perm_service_t *svc,
    const char *perm_id,
    const char *resource_type,
    const char *resource_id,
    ozayn_authz_scope_t request_scope);

int ozayn_perm_validate_access(
    const ozayn_perm_service_t *svc,
    const char *perm_id,
    const ozayn_protected_resource_t *resource,
    ozayn_authz_scope_t request_scope);

/* ============================================================
 * VALIDATION
 * ============================================================ */

int ozayn_perm_validate_id(const char *perm_id);
int ozayn_perm_validate_state(ozayn_perm_state_t state);
int ozayn_perm_validate_transition(ozayn_perm_state_t from,
                                    ozayn_perm_state_t to);

/* ============================================================
 * NAME HELPERS
 * ============================================================ */

const char *ozayn_perm_error_name(ozayn_perm_error_t error);
const char *ozayn_perm_state_name(ozayn_perm_state_t state);

/* ============================================================
 * AUTHORIZATION INTEGRATION
 * ============================================================ */

/* Set Permission Management service on authorization service.
 * When set, authorize() will check permissions after RBAC check. */
ozayn_authz_error_t ozayn_authz_set_permission_service(
    ozayn_authz_service_t *authz_svc,
    ozayn_perm_service_t *perm_svc);

/* Get Permission Management service from authorization service. */
ozayn_perm_service_t *ozayn_authz_get_permission_service(
    const ozayn_authz_service_t *authz_svc);

#endif
