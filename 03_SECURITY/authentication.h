#ifndef OZAYN_AUTHENTICATION_H
#define OZAYN_AUTHENTICATION_H

#include "identity.h"
#include "secure_vault.h"
#include <stdint.h>
#include <stddef.h>
#include <time.h>

/*
 * authentication.h — Authentication Architecture & Credential Boundary
 *                      (Section 03, Step 13).
 *
 * Establishes the authentication contract for OZAYN: HOW can the system
 * verify that an identity is legitimate? Creates the authentication
 * service, provider abstraction, request/response models, credential
 * reference boundary, and verification state machine.
 *
 * Architecture:
 *   IDENTITY SERVICE
 *          |
 *          v
 *   AUTHENTICATION SERVICE  <-- this layer
 *          |
 *   +------+------+
 *   |      |      |
 *   v      v      v
 *  PROV   PROV   PROV   (password, device, biometric, ...)
 *   |      |      |
 *   +------+------+
 *          |
 *          v
 *   VERIFICATION RESULT
 *          |
 *          v
 *   FUTURE SESSION
 *
 * Step 13 scope:
 *   - Authentication service lifecycle
 *   - Authentication provider abstraction (ops table)
 *   - Authentication request / response models
 *   - Verification state machine
 *   - Credential reference boundary (non-secret)
 *   - Credential lifecycle states
 *   - Authentication method model
 *   - Identity integration (resolve, validate state)
 *   - Secure Vault boundary (fail closed on vault failure)
 *   - Fail-closed authentication behavior
 *   - Authentication error model
 *   - Authentication tests
 *
 * NOT in scope:
 *   - Password authentication implementation
 *   - Password hashing / storage
 *   - Face recognition / embeddings
 *   - Voice recognition / voiceprints
 *   - Fingerprint authentication
 *   - Gesture authentication
 *   - Biometric matching
 *   - Multi-factor authentication orchestration
 *   - Session management
 *   - Authorization / RBAC
 *   - Login GUI
 *   - Credential recovery
 *   - Account recovery
 */

/* ============================================================
 * AUTHENTICATION PREFIX NOTE
 *
 * This layer uses OZAYN_AuthN_ prefix to avoid collision with
 * the IPC-level ozayn_auth_method_t / ozayn_auth_result_t in
 * include/security.h (component authentication).
 * ============================================================ */

/* ============================================================
 * AUTHENTICATION METHOD
 * ============================================================ */

typedef enum {
    OZAYN_AuthN_METHOD_UNKNOWN    = 0,
    OZAYN_AuthN_METHOD_PASSWORD   = 1,  /* Password / passphrase */
    OZAYN_AuthN_METHOD_DEVICE     = 2,  /* Device-based proof */
    OZAYN_AuthN_METHOD_BIOMETRIC  = 3,  /* Biometric (face, fingerprint, ...) */
    OZAYN_AuthN_METHOD_VOICE      = 4,  /* Voice recognition */
    OZAYN_AuthN_METHOD_FACE       = 5,  /* Face recognition */
    OZAYN_AuthN_METHOD_GESTURE    = 6,  /* Gesture / pattern */
    OZAYN_AuthN_METHOD_MULTI      = 7   /* Multi-factor combination */
} ozayn_authn_method_t;

/* ============================================================
 * AUTHENTICATION RESULT
 * ============================================================ */

typedef enum {
    OZAYN_AuthN_RESULT_SUCCESS        =  0,  /* Authentication succeeded */
    OZAYN_AuthN_RESULT_FAILED         = -1,  /* Authentication failed (generic) */
    OZAYN_AuthN_RESULT_REJECTED       = -2,  /* Explicitly rejected by policy */
    OZAYN_AuthN_RESULT_UNAVAILABLE    = -3,  /* Provider / method unavailable */
    OZAYN_AuthN_RESULT_ERROR          = -4   /* Internal error */
} ozayn_authn_result_t;

/* ============================================================
 * VERIFICATION STATE
 * ============================================================ */

typedef enum {
    OZAYN_AuthN_VERIFY_NOT_VERIFIED   = 0,
    OZAYN_AuthN_VERIFY_PENDING        = 1,
    OZAYN_AuthN_VERIFY_VERIFIED       = 2,
    OZAYN_AuthN_VERIFY_FAILED         = 3,
    OZAYN_AuthN_VERIFY_UNAVAILABLE    = 4,
    OZAYN_AuthN_VERIFY_ERROR          = 5
} ozayn_authn_verification_t;

/* ============================================================
 * CREDENTIAL REFERENCE LIFECYCLE
 * ============================================================ */

typedef enum {
    OZAYN_AuthN_CRED_UNINITIALIZED = 0,
    OZAYN_AuthN_CRED_ACTIVE        = 1,
    OZAYN_AuthN_CRED_SUSPENDED     = 2,
    OZAYN_AuthN_CRED_REVOKED       = 3,
    OZAYN_AuthN_CRED_EXPIRED       = 4
} ozayn_authn_credential_state_t;

/* ============================================================
 * ERROR CODES
 * ============================================================ */

typedef enum {
    OZAYN_AuthN_OK                           =   0,
    OZAYN_AuthN_ERR_NULL                     =  -1,
    OZAYN_AuthN_ERR_NOT_INITIALIZED          =  -2,
    OZAYN_AuthN_ERR_NOT_FOUND                =  -3,
    OZAYN_AuthN_ERR_INVALID                  =  -4,
    OZAYN_AuthN_ERR_METHOD_UNSUPPORTED       =  -5,
    OZAYN_AuthN_ERR_IDENTITY_NOT_FOUND       =  -6,
    OZAYN_AuthN_ERR_IDENTITY_REVOKED         =  -7,
    OZAYN_AuthN_ERR_IDENTITY_SUSPENDED       =  -8,
    OZAYN_AuthN_ERR_IDENTITY_ARCHIVED        =  -9,
    OZAYN_AuthN_ERR_PROVIDER_UNAVAILABLE     = -10,
    OZAYN_AuthN_ERR_PROVIDER_FAILED          = -11,
    OZAYN_AuthN_ERR_CREDENTIAL_UNAVAILABLE   = -12,
    OZAYN_AuthN_ERR_CREDENTIAL_INVALID       = -13,
    OZAYN_AuthN_ERR_VERIFICATION_FAILED      = -14,
    OZAYN_AuthN_ERR_VAULT_UNAVAILABLE        = -15,
    OZAYN_AuthN_ERR_POLICY_REJECTED          = -16,
    OZAYN_AuthN_ERR_CONTEXT_INVALID          = -17,
    OZAYN_AuthN_ERR_MAX_RETRIES              = -18
} ozayn_authn_error_t;

/* ============================================================
 * CONSTANTS
 * ============================================================ */

#define OZAYN_AuthN_MAX_METHODS         8
#define OZAYN_AuthN_MAX_PROVIDERS      16
#define OZAYN_AuthN_MAX_ID_LEN         64
#define OZAYN_AuthN_MAX_CRED_REF_LEN   64
#define OZAYN_AuthN_MAX_REQUEST_ID_LEN 64
#define OZAYN_AuthN_MAX_REASON_LEN    128

/* ============================================================
 * CREDENTIAL REFERENCE (non-secret locator only)
 *
 * This structure identifies a credential relationship.
 * It must NEVER contain:
 *   - passwords, password hashes, private keys
 *   - biometric templates, face embeddings, voiceprints
 *   - authentication tokens, session secrets
 *   - encryption keys, recovery secrets, API secrets
 * ============================================================ */

typedef struct {
    char                                id[OZAYN_AuthN_MAX_CRED_REF_LEN];
    ozayn_authn_credential_state_t      state;
    ozayn_authn_method_t                method;
    uint32_t                            version;
    char                                provider_id[OZAYN_AuthN_MAX_CRED_REF_LEN];
    time_t                              created_at;
    time_t                              modified_at;
    int                                 in_use;
} ozayn_authn_credential_ref_t;

/* ============================================================
 * AUTHENTICATION REQUEST
 * ============================================================ */

typedef struct {
    char                        identity_id[OZAYN_AuthN_MAX_ID_LEN];
    ozayn_authn_method_t        method;
    char                        request_id[OZAYN_AuthN_MAX_REQUEST_ID_LEN];
    time_t                      timestamp;
} ozayn_authn_request_t;

/* ============================================================
 * AUTHENTICATION RESPONSE (result)
 * ============================================================ */

typedef struct {
    ozayn_authn_result_t            result;
    ozayn_authn_verification_t      verification;
    char                            identity_id[OZAYN_AuthN_MAX_ID_LEN];
    ozayn_authn_method_t            method;
    time_t                          auth_time;
    char                            reason[OZAYN_AuthN_MAX_REASON_LEN];
} ozayn_authn_response_t;

/* ============================================================
 * AUTHENTICATION PROVIDER OPERATIONS (vtable)
 * ============================================================ */

typedef struct ozayn_authn_provider ozayn_authn_provider_t;

typedef struct {
    /* Initialize the provider */
    int (*init)(ozayn_authn_provider_t *provider);

    /* Shutdown the provider */
    void (*shutdown)(ozayn_authn_provider_t *provider);

    /* Authenticate: verify credentials for the given identity */
    ozayn_authn_result_t (*authenticate)(ozayn_authn_provider_t *provider,
                                         const ozayn_authn_request_t *request,
                                         ozayn_authn_response_t *out);

    /* Check if this provider is available and ready */
    int (*is_available)(const ozayn_authn_provider_t *provider);

    /* Get the method this provider handles */
    ozayn_authn_method_t (*get_method)(const ozayn_authn_provider_t *provider);
} ozayn_authn_provider_ops_t;

/* ============================================================
 * AUTHENTICATION PROVIDER
 * ============================================================ */

struct ozayn_authn_provider {
    const char                     *name;
    const ozayn_authn_provider_ops_t *ops;
    void                           *impl_data;
    int                             initialized;
};

/* ============================================================
 * AUTHENTICATION SERVICE CONFIGURATION
 * ============================================================ */

typedef struct {
    ozayn_identity_service_t    *identity_service;
    ozayn_vault_t               *vault;
} ozayn_authn_service_config_t;

/* ============================================================
 * AUTHENTICATION SERVICE
 * ============================================================ */

typedef struct {
    ozayn_authn_provider_t      *providers[OZAYN_AuthN_MAX_PROVIDERS];
    int                          provider_count;
    ozayn_authn_service_config_t config;
    int                          initialized;
} ozayn_authn_service_t;

/* ============================================================
 * SERVICE LIFECYCLE
 * ============================================================ */

ozayn_authn_error_t ozayn_authn_service_init(ozayn_authn_service_t *svc,
                                              const ozayn_authn_service_config_t *config);

void ozayn_authn_service_shutdown(ozayn_authn_service_t *svc);

/* ============================================================
 * PROVIDER MANAGEMENT
 * ============================================================ */

ozayn_authn_error_t ozayn_authn_register_provider(ozayn_authn_service_t *svc,
                                                    ozayn_authn_provider_t *provider);

ozayn_authn_error_t ozayn_authn_unregister_provider(ozayn_authn_service_t *svc,
                                                      ozayn_authn_provider_t *provider);

/* ============================================================
 * AUTHENTICATION OPERATIONS
 * ============================================================ */

/* Authenticate: resolve identity, select provider, execute verification */
ozayn_authn_error_t ozayn_authn_authenticate(ozayn_authn_service_t *svc,
                                               const ozayn_authn_request_t *request,
                                               ozayn_authn_response_t *out);

/* ============================================================
 * QUERY
 * ============================================================ */

int ozayn_authn_service_is_initialized(const ozayn_authn_service_t *svc);
int ozayn_authn_service_provider_count(const ozayn_authn_service_t *svc);

/* ============================================================
 * VALIDATION
 * ============================================================ */

int ozayn_authn_validate_request(const ozayn_authn_request_t *request);
int ozayn_authn_validate_method(ozayn_authn_method_t method);
int ozayn_authn_validate_credential_state(ozayn_authn_credential_state_t state);

/* ============================================================
 * CREDENTIAL REFERENCE OPERATIONS
 * ============================================================ */

int ozayn_authn_credential_ref_init(ozayn_authn_credential_ref_t *ref,
                                     const char *cred_id,
                                     ozayn_authn_method_t method,
                                     const char *provider_id);

int ozayn_authn_credential_ref_validate(const ozayn_authn_credential_ref_t *ref);

int ozayn_authn_credential_ref_is_usable(const ozayn_authn_credential_ref_t *ref);

int ozayn_authn_credential_validate_transition(ozayn_authn_credential_state_t from,
                                                ozayn_authn_credential_state_t to);

/* ============================================================
 * NAME HELPERS
 * ============================================================ */

const char *ozayn_authn_method_name(ozayn_authn_method_t method);
const char *ozayn_authn_result_name(ozayn_authn_result_t result);
const char *ozayn_authn_verification_name(ozayn_authn_verification_t state);
const char *ozayn_authn_credential_state_name(ozayn_authn_credential_state_t state);
const char *ozayn_authn_error_name(ozayn_authn_error_t error);

#endif
