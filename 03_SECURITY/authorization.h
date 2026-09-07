#ifndef OZAYN_AUTHZ_SVC_H
#define OZAYN_AUTHZ_SVC_H

#include "session_management.h"
#include "identity.h"
#include <stdint.h>
#include <stddef.h>

/*
 * authorization.h — Authorization & Access-Control Foundation (Step 17).
 *
 * Answers: "Is this authenticated session allowed to perform this action?"
 *
 * Architecture:
 *   AUTHENTICATED SESSION
 *          |
 *          v
 *   AUTHORIZATION SERVICE  <-- this layer
 *          |
 *   +------+------+------+
 *   |      |      |      |
 *   v      v      v      v
 *  SESS  IDNTY  SCPE  POLICY
 *  CHECK CHECK CHECK PROVIDER
 *          |
 *          v
 *   ALLOW / DENY / ERROR
 *
 * Flow:
 *   1. Validate session (active, not expired/revoked/terminated)
 *   2. Validate identity (active, not suspended/revoked/archived)
 *   3. Evaluate policy via provider
 *   4. Return decision
 *
 * Default behavior: DENY on all error paths.
 *
 * Uses ozayn_authz_ prefix to avoid collision with existing platform-level
 * ozayn_authz_* types in include/authorization.h.
 *
 * Step 17 scope:
 *   - Authorization service lifecycle
 *   - Policy provider abstraction (vtable)
 *   - Authorization request with session context
 *   - Authorization decision (ALLOW/DENY/ERROR)
 *   - Deny reason model
 *   - Resource type identification
 *   - Action type identification
 *   - Scope boundary (exact match)
 *   - Session integration (validate before authorize)
 *   - Identity integration (active state required)
 *   - Default-deny behavior
 *   - Test policy provider
 *   - Authorization error model
 *   - Security tests
 *
 * NOT in scope:
 *   - RBAC (role-based access control)
 *   - Roles / role management UI
 *   - Permission administration UI
 *   - MFA / Biometric / Face / Voice / Gesture
 *   - Password recovery / Account recovery
 *   - Authorization GUI
 *   - Distributed authorization
 *   - Cloud IAM / OAuth
 *   - Wildcard permission matching
 *   - Authorization caching
 *   - Policy-as-code external servers
 *   - Administrative bypasses
 */

/* ============================================================
 * CONSTANTS
 * ============================================================ */

#define OZAYN_AUTHZ_MAX_RESOURCE_TYPE_LEN  64
#define OZAYN_AUTHZ_MAX_RESOURCE_ID_LEN   128
#define OZAYN_AUTHZ_MAX_SCOPE_LEN          64
#define OZAYN_AUTHZ_MAX_ACTION_LEN         64
#define OZAYN_AUTHZ_MAX_REQUEST_ID_LEN     64
#define OZAYN_AUTHZ_MAX_PROVIDER_NAME_LEN  64
#define OZAYN_AUTHZ_MAX_DENY_REASON_LEN   128
#define OZAYN_AUTHZ_MAX_PROVIDERS          16

/* ============================================================
 * RESOURCE TYPE
 * ============================================================ */

typedef enum {
    OZAYN_AUTHZ_RESOURCE_UNKNOWN     = 0,
    OZAYN_AUTHZ_RESOURCE_CORE        = 1,
    OZAYN_AUTHZ_RESOURCE_MODULE      = 2,
    OZAYN_AUTHZ_RESOURCE_PLUGIN      = 3,
    OZAYN_AUTHZ_RESOURCE_DOCUMENT    = 4,
    OZAYN_AUTHZ_RESOURCE_MEMORY      = 5,
    OZAYN_AUTHZ_RESOURCE_DATABASE    = 6,
    OZAYN_AUTHZ_RESOURCE_DEVICE      = 7,
    OZAYN_AUTHZ_RESOURCE_CAMERA      = 8,
    OZAYN_AUTHZ_RESOURCE_MICROPHONE  = 9,
    OZAYN_AUTHZ_RESOURCE_SYSTEM      = 10,
    OZAYN_AUTHZ_RESOURCE_IDENTITY    = 11,
    OZAYN_AUTHZ_RESOURCE_SESSION     = 12,
    OZAYN_AUTHZ_RESOURCE_SERVICE     = 13
} ozayn_authz_resource_type_t;

/* ============================================================
 * ACTION TYPE
 * ============================================================ */

typedef enum {
    OZAYN_AUTHZ_ACTION_UNKNOWN   = 0,
    OZAYN_AUTHZ_ACTION_READ      = 1,
    OZAYN_AUTHZ_ACTION_CREATE    = 2,
    OZAYN_AUTHZ_ACTION_UPDATE    = 3,
    OZAYN_AUTHZ_ACTION_DELETE    = 4,
    OZAYN_AUTHZ_ACTION_EXECUTE   = 5,
    OZAYN_AUTHZ_ACTION_CONTROL   = 6,
    OZAYN_AUTHZ_ACTION_CONFIGURE = 7,
    OZAYN_AUTHZ_ACTION_INSTALL   = 8,
    OZAYN_AUTHZ_ACTION_UNINSTALL = 9
} ozayn_authz_action_type_t;

/* ============================================================
 * SCOPE
 * ============================================================ */

typedef enum {
    OZAYN_AUTHZ_SCOPE_UNKNOWN = 0,
    OZAYN_AUTHZ_SCOPE_SYSTEM  = 1,
    OZAYN_AUTHZ_SCOPE_USER    = 2,
    OZAYN_AUTHZ_SCOPE_DEVICE  = 3,
    OZAYN_AUTHZ_SCOPE_MODULE  = 4,
    OZAYN_AUTHZ_SCOPE_SERVICE = 5,
    OZAYN_AUTHZ_SCOPE_GLOBAL  = 6
} ozayn_authz_scope_t;

/* ============================================================
 * AUTHORIZATION DECISION
 * ============================================================ */

typedef enum {
    OZAYN_AUTHZ_DECISION_ALLOW  = 0,
    OZAYN_AUTHZ_DECISION_DENY   = 1,
    OZAYN_AUTHZ_DECISION_ERROR  = 2
} ozayn_authz_decision_t;

/* ============================================================
 * DENY REASON
 * ============================================================ */

typedef enum {
    OZAYN_AUTHZ_DENY_NONE                    = 0,
    OZAYN_AUTHZ_DENY_SESSION_INVALID         = 1,
    OZAYN_AUTHZ_DENY_SESSION_EXPIRED         = 2,
    OZAYN_AUTHZ_DENY_SESSION_REVOKED         = 3,
    OZAYN_AUTHZ_DENY_SESSION_TERMINATED      = 4,
    OZAYN_AUTHZ_DENY_IDENTITY_INVALID        = 5,
    OZAYN_AUTHZ_DENY_IDENTITY_SUSPENDED      = 6,
    OZAYN_AUTHZ_DENY_IDENTITY_REVOKED        = 7,
    OZAYN_AUTHZ_DENY_IDENTITY_ARCHIVED       = 8,
    OZAYN_AUTHZ_DENY_PERMISSION_MISSING      = 9,
    OZAYN_AUTHZ_DENY_ACTION_NOT_ALLOWED      = 10,
    OZAYN_AUTHZ_DENY_RESOURCE_NOT_FOUND      = 11,
    OZAYN_AUTHZ_DENY_SCOPE_MISMATCH          = 12,
    OZAYN_AUTHZ_DENY_POLICY_REJECTED         = 13,
    OZAYN_AUTHZ_DENY_POLICY_UNAVAILABLE      = 14,
    OZAYN_AUTHZ_DENY_POLICY_ERROR            = 15,
    OZAYN_AUTHZ_DENY_DEFAULT                 = 16
} ozayn_authz_deny_reason_t;

/* ============================================================
 * AUTHORIZATION ERROR CODES
 * ============================================================ */

typedef enum {
    OZAYN_AUTHZ_OK                        =   0,
    OZAYN_AUTHZ_ERR_NULL                  =  -1,
    OZAYN_AUTHZ_ERR_NOT_INITIALIZED       =  -2,
    OZAYN_AUTHZ_ERR_NOT_FOUND             =  -3,
    OZAYN_AUTHZ_ERR_INVALID               =  -4,
    OZAYN_AUTHZ_ERR_SESSION_INVALID       =  -5,
    OZAYN_AUTHZ_ERR_IDENTITY_INVALID      =  -6,
    OZAYN_AUTHZ_ERR_PROVIDER_UNAVAILABLE  =  -7,
    OZAYN_AUTHZ_ERR_PROVIDER_FAILED       =  -8,
    OZAYN_AUTHZ_ERR_POLICY_INVALID        =  -9,
    OZAYN_AUTHZ_ERR_REQUEST_INVALID       = -10,
    OZAYN_AUTHZ_ERR_RESOURCE_INVALID      = -11,
    OZAYN_AUTHZ_ERR_ACTION_INVALID        = -12,
    OZAYN_AUTHZ_ERR_SCOPE_INVALID         = -13,
    OZAYN_AUTHZ_ERR_LIMIT_REACHED         = -14
} ozayn_authz_error_t;

/* ============================================================
 * AUTHORIZATION REQUEST
 * ============================================================ */

typedef struct {
    char    session_id[64];
    char    resource_type[OZAYN_AUTHZ_MAX_RESOURCE_TYPE_LEN];
    char    resource_id[OZAYN_AUTHZ_MAX_RESOURCE_ID_LEN];
    char    scope[OZAYN_AUTHZ_MAX_SCOPE_LEN];
    char    action[OZAYN_AUTHZ_MAX_ACTION_LEN];
    char    request_id[OZAYN_AUTHZ_MAX_REQUEST_ID_LEN];
} ozayn_authz_request_t;

/* ============================================================
 * AUTHORIZATION RESULT
 * ============================================================ */

typedef struct {
    ozayn_authz_decision_t   decision;
    ozayn_authz_deny_reason_t reason;
    char                    reason_detail[OZAYN_AUTHZ_MAX_DENY_REASON_LEN];
} ozayn_authz_result_t;

/* ============================================================
 * POLICY PROVIDER OPERATIONS (vtable)
 * ============================================================ */

typedef struct ozayn_authz_policy_provider ozayn_authz_policy_provider_t;

typedef struct {
    /* Initialize the provider */
    int (*init)(ozayn_authz_policy_provider_t *provider);

    /* Shutdown the provider */
    void (*shutdown)(ozayn_authz_policy_provider_t *provider);

    /* Evaluate authorization request against policy */
    ozayn_authz_result_t (*evaluate)(ozayn_authz_policy_provider_t *provider,
                                      const ozayn_authz_request_t *request,
                                      const char *identity_id);

    /* Check if provider is available and ready */
    int (*is_available)(const ozayn_authz_policy_provider_t *provider);

    /* Get policy version (for cache invalidation) */
    int (*get_version)(const ozayn_authz_policy_provider_t *provider);
} ozayn_authz_policy_ops_t;

/* ============================================================
 * POLICY PROVIDER
 * ============================================================ */

struct ozayn_authz_policy_provider {
    const char                      *name;
    const ozayn_authz_policy_ops_t  *ops;
    void                            *impl_data;
    int                              initialized;
};

/* ============================================================
 * AUTHORIZATION SERVICE CONFIGURATION
 * ============================================================ */

typedef struct {
    ozayn_sess_service_t        *session_service;
    ozayn_identity_service_t    *identity_service;
} ozayn_authz_service_config_t;

/* ============================================================
 * AUTHORIZATION SERVICE
 * ============================================================ */

typedef struct {
    ozayn_authz_policy_provider_t   *providers[OZAYN_AUTHZ_MAX_PROVIDERS];
    int                              provider_count;
    ozayn_authz_service_config_t     config;
    int                              initialized;
} ozayn_authz_service_t;

/* ============================================================
 * SERVICE LIFECYCLE
 * ============================================================ */

ozayn_authz_error_t ozayn_authz_service_init(
    ozayn_authz_service_t *svc,
    const ozayn_authz_service_config_t *config);

void ozayn_authz_service_shutdown(ozayn_authz_service_t *svc);

/* ============================================================
 * PROVIDER MANAGEMENT
 * ============================================================ */

ozayn_authz_error_t ozayn_authz_register_provider(
    ozayn_authz_service_t *svc,
    ozayn_authz_policy_provider_t *provider);

ozayn_authz_error_t ozayn_authz_unregister_provider(
    ozayn_authz_service_t *svc,
    ozayn_authz_policy_provider_t *provider);

/* ============================================================
 * AUTHORIZATION OPERATIONS
 * ============================================================ */

/* Authorize: validate session, validate identity, evaluate policy.
 * Returns explicit ALLOW/DENY/ERROR decision with reason. */
ozayn_authz_result_t ozayn_authz_authorize(
    ozayn_authz_service_t *svc,
    const ozayn_authz_request_t *request);

/* ============================================================
 * QUERY
 * ============================================================ */

int ozayn_authz_service_is_initialized(const ozayn_authz_service_t *svc);
int ozayn_authz_service_provider_count(const ozayn_authz_service_t *svc);

/* ============================================================
 * VALIDATION
 * ============================================================ */

int ozayn_authz_validate_resource_type(const char *resource_type);
int ozayn_authz_validate_action(const char *action);
int ozayn_authz_validate_scope(const char *scope);
int ozayn_authz_validate_request(const ozayn_authz_request_t *request);

/* ============================================================
 * NAME HELPERS
 * ============================================================ */

const char *ozayn_authz_svc_decision_name(ozayn_authz_decision_t decision);
const char *ozayn_authz_deny_reason_name(ozayn_authz_deny_reason_t reason);
const char *ozayn_authz_error_name(ozayn_authz_error_t error);
const char *ozayn_authz_resource_type_name(const char *resource_type);
const char *ozayn_authz_action_name(const char *action);
const char *ozayn_authz_scope_name_value(const char *scope);

/* ============================================================
 * RESULT HELPERS
 * ============================================================ */

ozayn_authz_result_t ozayn_authz_make_allow(void);
ozayn_authz_result_t ozayn_authz_make_deny(ozayn_authz_deny_reason_t reason);
ozayn_authz_result_t ozayn_authz_make_error(ozayn_authz_deny_reason_t reason);

/* ============================================================
 * DEFAULT / TEST POLICIES
 * ============================================================ */

ozayn_authz_policy_provider_t *ozayn_authz_test_provider_create(void);
void ozayn_authz_test_provider_destroy(ozayn_authz_policy_provider_t *provider);
void ozayn_authz_test_provider_set_result(ozayn_authz_policy_provider_t *provider,
                                           ozayn_authz_result_t result);
void ozayn_authz_test_provider_set_available(ozayn_authz_policy_provider_t *provider,
                                              int available);
void ozayn_authz_test_provider_set_version(ozayn_authz_policy_provider_t *provider,
                                            int version);

#endif
