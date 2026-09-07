#ifndef OZAYN_MFA_H
#define OZAYN_MFA_H

#include "authentication.h"
#include "attempt_control.h"
#include "identity.h"
#include <stdint.h>
#include <stddef.h>
#include <time.h>

/*
 * mfa.h — Multi-Factor Authentication Foundation & Enforcement (Step 20).
 *
 * Answers: "Does this identity satisfy multiple independent authentication
 *           factors before being granted a session or authorization?"
 *
 * Architecture:
 *   IDENTITY
 *      ↓
 *   AUTHENTICATION (Step 13)
 *      ↓
 *   ATTEMPT CONTROL (Step 15)
 *      ↓
 *   MFA SERVICE  <-- this layer
 *      ↓
 *   FACTOR 1 → FACTOR 2 → ... → ALL REQUIRED FACTORS VERIFIED
 *      ↓
 *   MFA RESULT
 *      ↓
 *   SESSION (Step 16)
 *      ↓
 *   AUTHORIZATION (Step 17)
 *      ↓
 *   RBAC (Step 18)
 *      ↓
 *   PERMISSION (Step 19)
 *      ↓
 *   RESOURCE
 *
 * Flow:
 *   1. MFA policy defines required factor count and types
 *   2. MFA transaction created for an identity
 *   3. Each factor verified independently via authentication providers
 *   4. Factor independence enforced (no same-category duplicates)
 *   5. All required factors verified → MFA VERIFIED
 *   6. Session created with MULTI assurance level
 *
 * Factor categories (independence):
 *   KNOWLEDGE — something the user knows (password, PIN)
 *   POSSESSION — something the user has (device, token)
 *   INHERENCE — something the user is (biometric, face, voice)
 *
 * Two factors of the SAME category do NOT satisfy MFA.
 *
 * Step 20 scope:
 *   - MFA factor type abstraction
 *   - MFA factor state machine
 *   - MFA policy (required factors, timeout, failure policy)
 *   - MFA transaction (state machine, replay protection, timeout)
 *   - Factor verification orchestration
 *   - Factor independence enforcement
 *   - MFA result with assurance level
 *   - Session assurance integration
 *   - Authorization assurance boundary
 *   - Attempt control integration
 *   - Transaction timeout and cancellation
 *   - Resource limits
 *   - Security tests
 *
 * NOT in scope:
 *   - Biometric verification (face, fingerprint, voice, gesture)
 *   - Token/SMS/OTP implementations
 *   - Device authentication providers
 *   - GUI / MFA login screens
 *   - OAuth / cloud MFA
 *   - Master MFA bypass
 *   - Security architecture redesign
 */

/* ============================================================
 * CONSTANTS
 * ============================================================ */

#define OZAYN_MFA_MAX_TX_ID_LEN          64
#define OZAYN_MFA_MAX_POLICY_ID_LEN      64
#define OZAYN_MFA_MAX_POLICY_NAME_LEN   128
#define OZAYN_MFA_MAX_FACTOR_ID_LEN      64
#define OZAYN_MFA_MAX_FACTORS_PER_TX      8
#define OZAYN_MFA_MAX_FACTORS_PER_POLICY  8
#define OZAYN_MFA_MAX_POLICIES            16
#define OZAYN_MFA_MAX_TRANSACTIONS       64
#define OZAYN_MFA_MAX_FACTOR_TYPES        8

/* ============================================================
 * MFA ERROR CODES
 * ============================================================ */

typedef enum {
    OZAYN_MFA_OK                          =   0,
    OZAYN_MFA_ERR_NULL                    =  -1,
    OZAYN_MFA_ERR_NOT_INITIALIZED         =  -2,
    OZAYN_MFA_ERR_NOT_FOUND               =  -3,
    OZAYN_MFA_ERR_ALREADY_EXISTS          =  -4,
    OZAYN_MFA_ERR_INVALID                 =  -5,
    OZAYN_MFA_ERR_ID_INVALID              =  -6,
    OZAYN_MFA_ERR_STATE_INVALID           =  -7,
    OZAYN_MFA_ERR_STATE_TRANSITION        =  -8,
    OZAYN_MFA_ERR_LIMIT_REACHED           =  -9,
    OZAYN_MFA_ERR_POLICY_INVALID          = -10,
    OZAYN_MFA_ERR_POLICY_UNAVAILABLE      = -11,
    OZAYN_MFA_ERR_FACTOR_INVALID          = -12,
    OZAYN_MFA_ERR_FACTOR_UNSUPPORTED      = -13,
    OZAYN_MFA_ERR_FACTOR_UNAVAILABLE      = -14,
    OZAYN_MFA_ERR_FACTOR_FAILED           = -15,
    OZAYN_MFA_ERR_FACTOR_ALREADY_VERIFIED = -16,
    OZAYN_MFA_ERR_INSUFFICIENT_FACTORS    = -17,
    OZAYN_MFA_ERR_TRANSACTION_INVALID     = -18,
    OZAYN_MFA_ERR_TRANSACTION_NOT_FOUND   = -19,
    OZAYN_MFA_ERR_TRANSACTION_EXPIRED     = -20,
    OZAYN_MFA_ERR_TRANSACTION_CANCELLED   = -21,
    OZAYN_MFA_ERR_TRANSACTION_REPLAYED    = -22,
    OZAYN_MFA_ERR_IDENTITY_INVALID        = -23,
    OZAYN_MFA_ERR_IDENTITY_REVOKED        = -24,
    OZAYN_MFA_ERR_IDENTITY_SUSPENDED      = -25,
    OZAYN_MFA_ERR_SESSION_INVALID         = -26,
    OZAYN_MFA_ERR_ATTEMPT_BLOCKED         = -27,
    OZAYN_MFA_ERR_TIMEOUT                 = -28,
    OZAYN_MFA_ERR_PROVIDER_ERROR          = -29,
    OZAYN_MFA_ERR_PROVIDER_UNAVAILABLE    = -30,
    OZAYN_MFA_ERR_STORAGE_FAILED          = -31,
    OZAYN_MFA_ERR_VAULT_UNAVAILABLE       = -32,
    OZAYN_MFA_ERR_POLICY_REJECTED         = -33
} ozayn_mfa_error_t;

/* ============================================================
 * MFA FACTOR TYPE (category)
 * ============================================================ */

typedef enum {
    OZAYN_MFA_FACTOR_UNKNOWN   = 0,
    OZAYN_MFA_FACTOR_PASSWORD  = 1,  /* KNOWLEDGE — something you know */
    OZAYN_MFA_FACTOR_TOKEN     = 2,  /* POSSESSION — something you have (TOTP, HOTP) */
    OZAYN_MFA_FACTOR_DEVICE    = 3,  /* POSSESSION — registered device */
    OZAYN_MFA_FACTOR_BIOMETRIC = 4,  /* INHERENCE — something you are */
    OZAYN_MFA_FACTOR_VOICE     = 5,  /* INHERENCE — voice recognition */
    OZAYN_MFA_FACTOR_FACE      = 6,  /* INHERENCE — face recognition */
    OZAYN_MFA_FACTOR_GESTURE   = 7   /* INHERENCE — gesture / pattern */
} ozayn_mfa_factor_type_t;

/* ============================================================
 * MFA FACTOR CATEGORY (for independence rules)
 * ============================================================ */

typedef enum {
    OZAYN_MFA_CATEGORY_UNKNOWN    = 0,
    OZAYN_MFA_CATEGORY_KNOWLEDGE  = 1,  /* Password, PIN */
    OZAYN_MFA_CATEGORY_POSSESSION = 2,  /* Token, Device */
    OZAYN_MFA_CATEGORY_INHERENCE  = 3   /* Biometric, Face, Voice, Gesture */
} ozayn_mfa_category_t;

/* ============================================================
 * MFA FACTOR STATE
 * ============================================================ */

typedef enum {
    OZAYN_MFA_FACT_STATE_UNINITIALIZED = 0,
    OZAYN_MFA_FACT_STATE_PENDING       = 1,  /* Awaiting verification */
    OZAYN_MFA_FACT_STATE_VERIFIED      = 2,  /* Successfully verified */
    OZAYN_MFA_FACT_STATE_FAILED        = 3,  /* Verification failed */
    OZAYN_MFA_FACT_STATE_UNAVAILABLE   = 4,  /* Provider unavailable */
    OZAYN_MFA_FACT_STATE_SKIPPED       = 5   /* Not required by policy */
} ozayn_mfa_factor_state_t;

/* ============================================================
 * MFA TRANSACTION STATE
 * ============================================================ */

typedef enum {
    OZAYN_MFA_TX_UNINITIALIZED = 0,
    OZAYN_MFA_TX_NOT_STARTED   = 1,
    OZAYN_MFA_TX_IN_PROGRESS   = 2,  /* At least one factor pending */
    OZAYN_MFA_TX_FACTOR_VERIFIED = 3, /* All factors verified */
    OZAYN_MFA_TX_VERIFIED      = 4,  /* MFA complete — session can be created */
    OZAYN_MFA_TX_FAILED        = 5,  /* One or more factors failed */
    OZAYN_MFA_TX_EXPIRED       = 6,  /* Transaction timed out */
    OZAYN_MFA_TX_CANCELLED     = 7,  /* Explicitly cancelled */
    OZAYN_MFA_TX_UNAVAILABLE   = 8   /* Required provider unavailable */
} ozayn_mfa_tx_state_t;

/* ============================================================
 * MFA ASSURANCE LEVEL
 * ============================================================ */

typedef enum {
    OZAYN_MFA_ASSURANCE_NONE       = 0,
    OZAYN_MFA_ASSURANCE_SINGLE     = 1,  /* Single factor verified */
    OZAYN_MFA_ASSURANCE_MULTI      = 2,  /* Multiple independent factors */
    OZAYN_MFA_ASSURANCE_HIGH       = 3   /* High assurance (3+ factors) */
} ozayn_mfa_assurance_t;

/* ============================================================
 * MFA RESULT
 * ============================================================ */

typedef enum {
    OZAYN_MFA_RESULT_VERIFIED   = 0,
    OZAYN_MFA_RESULT_FAILED     = 1,
    OZAYN_MFA_RESULT_PENDING    = 2,
    OZAYN_MFA_RESULT_EXPIRED    = 3,
    OZAYN_MFA_RESULT_CANCELLED  = 4,
    OZAYN_MFA_RESULT_UNAVAILABLE = 5,
    OZAYN_MFA_RESULT_ERROR      = 6
} ozayn_mfa_result_status_t;

/* ============================================================
 * FACTOR TYPE INFO
 * ============================================================ */

typedef struct {
    ozayn_mfa_factor_type_t type;
    ozayn_mfa_category_t    category;
    const char             *name;
    int                     implemented;  /* 1 = has real provider, 0 = abstract */
} ozayn_mfa_factor_info_t;

/* ============================================================
 * MFA FACTOR OBJECT (within a transaction)
 * ============================================================ */

typedef struct {
    char                        id[OZAYN_MFA_MAX_FACTOR_ID_LEN];
    ozayn_mfa_factor_type_t     type;
    ozayn_mfa_category_t        category;
    ozayn_mfa_factor_state_t    state;
    char                        provider_id[OZAYN_AuthN_MAX_CRED_REF_LEN];
    time_t                      verified_at;
    int                         attempt_count;
    int                         in_use;
} ozayn_mfa_factor_t;

/* ============================================================
 * MFA POLICY
 * ============================================================ */

typedef struct {
    char                        id[OZAYN_MFA_MAX_POLICY_ID_LEN];
    char                        name[OZAYN_MFA_MAX_POLICY_NAME_LEN];
    int                         enabled;
    int                         required_factor_count;
    ozayn_mfa_factor_type_t     required_factors[OZAYN_MFA_MAX_FACTORS_PER_POLICY];
    int                         required_factor_count_required; /* distinct categories needed */
    int                         transaction_timeout_seconds;
    int                         factor_timeout_seconds;
    int                         max_failures;
    int                         block_seconds;
    int                         version;
    time_t                      created_at;
    time_t                      modified_at;
    int                         in_use;
} ozayn_mfa_policy_t;

/* ============================================================
 * MFA TRANSACTION
 * ============================================================ */

typedef struct {
    char                        id[OZAYN_MFA_MAX_TX_ID_LEN];
    char                        identity_id[OZAYN_ID_MAX_ID_LEN];
    char                        policy_id[OZAYN_MFA_MAX_POLICY_ID_LEN];
    ozayn_mfa_tx_state_t        state;
    ozayn_mfa_factor_t          factors[OZAYN_MFA_MAX_FACTORS_PER_TX];
    int                         factor_count;
    int                         verified_factor_count;
    ozayn_mfa_assurance_t       assurance;
    time_t                      created_at;
    time_t                      expires_at;
    time_t                      completed_at;
    int                         version;
    int                         in_use;
} ozayn_mfa_tx_t;

/* ============================================================
 * MFA VERIFICATION REQUEST
 * ============================================================ */

typedef struct {
    char                        tx_id[OZAYN_MFA_MAX_TX_ID_LEN];
    char                        identity_id[OZAYN_ID_MAX_ID_LEN];
    ozayn_mfa_factor_type_t     factor_type;
    /* Authentication data is passed through the provider, not stored here */
} ozayn_mfa_verify_request_t;

/* ============================================================
 * MFA RESULT OBJECT
 * ============================================================ */

typedef struct {
    ozayn_mfa_result_status_t   status;
    ozayn_mfa_error_t           error;
    char                        tx_id[OZAYN_MFA_MAX_TX_ID_LEN];
    char                        identity_id[OZAYN_ID_MAX_ID_LEN];
    char                        policy_id[OZAYN_MFA_MAX_POLICY_ID_LEN];
    ozayn_mfa_assurance_t       assurance;
    int                         verified_factor_count;
    int                         required_factor_count;
    time_t                      timestamp;
    char                        detail[256];
} ozayn_mfa_result_t;

/* ============================================================
 * MFA SERVICE CONFIGURATION
 * ============================================================ */

typedef struct {
    ozayn_identity_service_t    *identity_service;
    ozayn_ac_service_t          *attempt_control;
    ozayn_authn_service_t       *authn_service;
} ozayn_mfa_service_config_t;

/* ============================================================
 * MFA SERVICE
 * ============================================================ */

typedef struct {
    ozayn_mfa_policy_t          policies[OZAYN_MFA_MAX_POLICIES];
    int                         policy_count;

    ozayn_mfa_tx_t              transactions[OZAYN_MFA_MAX_TRANSACTIONS];
    int                         transaction_count;

    ozayn_mfa_service_config_t  config;
    int                         initialized;
} ozayn_mfa_service_t;

/* ============================================================
 * SERVICE LIFECYCLE
 * ============================================================ */

ozayn_mfa_error_t ozayn_mfa_service_init(
    ozayn_mfa_service_t *svc,
    const ozayn_mfa_service_config_t *config);

void ozayn_mfa_service_shutdown(ozayn_mfa_service_t *svc);

int ozayn_mfa_service_is_initialized(const ozayn_mfa_service_t *svc);

/* ============================================================
 * POLICY MANAGEMENT
 * ============================================================ */

ozayn_mfa_error_t ozayn_mfa_policy_create(
    ozayn_mfa_service_t *svc,
    const char *policy_id,
    const char *name,
    const ozayn_mfa_factor_type_t *required_factors,
    int required_factor_count,
    int transaction_timeout_seconds,
    int factor_timeout_seconds,
    int max_failures,
    int block_seconds,
    ozayn_mfa_policy_t *out_policy);

ozayn_mfa_error_t ozayn_mfa_policy_get(
    const ozayn_mfa_service_t *svc,
    const char *policy_id,
    ozayn_mfa_policy_t *out_policy);

int ozayn_mfa_policy_exists(
    const ozayn_mfa_service_t *svc,
    const char *policy_id);

ozayn_mfa_error_t ozayn_mfa_policy_enable(
    ozayn_mfa_service_t *svc,
    const char *policy_id);

ozayn_mfa_error_t ozayn_mfa_policy_disable(
    ozayn_mfa_service_t *svc,
    const char *policy_id);

ozayn_mfa_error_t ozayn_mfa_policy_delete(
    ozayn_mfa_service_t *svc,
    const char *policy_id);

int ozayn_mfa_policy_count(const ozayn_mfa_service_t *svc);

/* ============================================================
 * TRANSACTION MANAGEMENT
 * ============================================================ */

ozayn_mfa_error_t ozayn_mfa_tx_create(
    ozayn_mfa_service_t *svc,
    const char *identity_id,
    const char *policy_id,
    ozayn_mfa_tx_t *out_tx);

ozayn_mfa_error_t ozayn_mfa_tx_get(
    const ozayn_mfa_service_t *svc,
    const char *tx_id,
    ozayn_mfa_tx_t *out_tx);

ozayn_mfa_error_t ozayn_mfa_tx_cancel(
    ozayn_mfa_service_t *svc,
    const char *tx_id);

ozayn_mfa_error_t ozayn_mfa_tx_cancel_by_identity(
    ozayn_mfa_service_t *svc,
    const char *identity_id);

int ozayn_mfa_tx_count(const ozayn_mfa_service_t *svc);

int ozayn_mfa_tx_identity_count(
    const ozayn_mfa_service_t *svc,
    const char *identity_id);

/* ============================================================
 * FACTOR VERIFICATION
 * ============================================================ */

ozayn_mfa_error_t ozayn_mfa_verify_factor(
    ozayn_mfa_service_t *svc,
    const ozayn_mfa_verify_request_t *request,
    ozayn_mfa_result_t *out_result);

/* ============================================================
 * TRANSACTION COMPLETION
 * ============================================================ */

ozayn_mfa_error_t ozayn_mfa_tx_complete(
    ozayn_mfa_service_t *svc,
    const char *tx_id,
    ozayn_mfa_result_t *out_result);

/* ============================================================
 * FACTOR TYPE HELPERS
 * ============================================================ */

ozayn_mfa_category_t ozayn_mfa_factor_type_category(
    ozayn_mfa_factor_type_t type);

int ozayn_mfa_factor_type_is_implemented(ozayn_mfa_factor_type_t type);

int ozayn_mfa_factors_require_distinct_categories(
    const ozayn_mfa_factor_type_t *factors,
    int factor_count);

/* ============================================================
 * VALIDATION
 * ============================================================ */

int ozayn_mfa_validate_factor_type(ozayn_mfa_factor_type_t type);
int ozayn_mfa_validate_category(ozayn_mfa_category_t category);
int ozayn_mfa_validate_factor_state(ozayn_mfa_factor_state_t state);
int ozayn_mfa_validate_tx_state(ozayn_mfa_tx_state_t state);
int ozayn_mfa_validate_tx_transition(ozayn_mfa_tx_state_t from,
                                      ozayn_mfa_tx_state_t to);
int ozayn_mfa_validate_assurance(ozayn_mfa_assurance_t level);
int ozayn_mfa_validate_policy(const ozayn_mfa_policy_t *policy);
int ozayn_mfa_validate_result_status(ozayn_mfa_result_status_t status);

/* ============================================================
 * NAME HELPERS
 * ============================================================ */

const char *ozayn_mfa_error_name(ozayn_mfa_error_t error);
const char *ozayn_mfa_factor_type_name(ozayn_mfa_factor_type_t type);
const char *ozayn_mfa_category_name(ozayn_mfa_category_t category);
const char *ozayn_mfa_factor_state_name(ozayn_mfa_factor_state_t state);
const char *ozayn_mfa_tx_state_name(ozayn_mfa_tx_state_t state);
const char *ozayn_mfa_assurance_name(ozayn_mfa_assurance_t level);
const char *ozayn_mfa_result_status_name(ozayn_mfa_result_status_t status);

/* ============================================================
 * DEFAULT / TEST POLICIES
 * ============================================================ */

ozayn_mfa_policy_t ozayn_mfa_default_policy(void);
ozayn_mfa_policy_t ozayn_mfa_test_policy(void);
ozayn_mfa_policy_t ozayn_mfa_high_security_policy(void);

#endif
