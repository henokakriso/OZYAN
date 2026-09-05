#ifndef OZAYN_IDENTITY_H
#define OZAYN_IDENTITY_H

#include "data_classification.h"
#include "secure_data_object.h"
#include "secure_vault.h"
#include <stdint.h>
#include <stddef.h>
#include <time.h>

/*
 * identity.h — Identity Foundation & Identity Data Boundary (Section 03, Step 12).
 *
 * Establishes the identity model for OZAYN users, devices, system components,
 * and services. Answers "Who or what is this?" without proving legitimacy.
 *
 * Architecture:
 *   OZAYN COMPONENT
 *          |
 *          v
 *   IDENTITY SERVICE  <-- this layer
 *          |
 *          v
 *   IDENTITY OBJECT
 *          |
 *          v
 *   IDENTITY VALIDATION
 *          |
 *          v
 *   SECURE VAULT
 *          |
 *          v
 *   PROTECTION LAYER
 *          |
 *          v
 *   KEY MANAGEMENT
 *          |
 *          v
 *   SECURE KEY STORAGE
 *          |
 *          v
 *   LOCAL STORAGE
 *
 * Step 12 scope:
 *   - Identity types (USER, DEVICE, SYSTEM, MODULE, SERVICE)
 *   - Identity states (UNINITIALIZED, ACTIVE, SUSPENDED, REVOKED, ARCHIVED)
 *   - Identity identifier
 *   - Identity object / record
 *   - Identity service interface
 *   - Identity validation
 *   - Identity scope / ownership
 *   - Credential references (non-secret only)
 *   - Secure Vault integration
 *
 * NOT in scope:
 *   - Authentication (passwords, biometrics, MFA)
 *   - Sessions
 *   - Authorization / RBAC
 *   - Credential storage
 *   - GUI
 */

/* ============================================================
 * IDENTITY TYPES (persistent identity management)
 *
 * NOTE: This is distinct from the component-level ozayn_identity_type_t
 * in security.h (CORE, MODULE, PLUGIN, SERVICE, EXTERNAL, USER).
 * This enum represents persistent identity entity types.
 * ============================================================ */

typedef enum {
    OZAYN_ID_TYPE_UNKNOWN  = 0,
    OZAYN_ID_TYPE_USER     = 1,  /* Human user */
    OZAYN_ID_TYPE_DEVICE   = 2,  /* Physical device */
    OZAYN_ID_TYPE_SYSTEM   = 3,  /* OZAYN core system */
    OZAYN_ID_TYPE_MODULE   = 4,  /* OZAYN module */
    OZAYN_ID_TYPE_SERVICE  = 5   /* External service */
} ozayn_id_type_t;

/* ============================================================
 * IDENTITY STATES
 * ============================================================ */

typedef enum {
    OZAYN_ID_STATE_UNINITIALIZED = 0,
    OZAYN_ID_STATE_ACTIVE        = 1,
    OZAYN_ID_STATE_SUSPENDED     = 2,
    OZAYN_ID_STATE_REVOKED       = 3,
    OZAYN_ID_STATE_ARCHIVED      = 4
} ozayn_id_state_t;

/* ============================================================
 * IDENTITY SCOPE
 * ============================================================ */

typedef enum {
    OZAYN_ID_SCOPE_UNKNOWN  = 0,
    OZAYN_ID_SCOPE_SYSTEM   = 1,  /* System-wide identity */
    OZAYN_ID_SCOPE_USER     = 2,  /* User-scoped identity */
    OZAYN_ID_SCOPE_DEVICE   = 3,  /* Device-scoped identity */
    OZAYN_ID_SCOPE_MODULE   = 4,  /* Module-scoped identity */
    OZAYN_ID_SCOPE_SERVICE  = 5,  /* Service-scoped identity */
    OZAYN_ID_SCOPE_GLOBAL   = 6   /* Global identity */
} ozayn_id_scope_t;

/* ============================================================
 * IDENTITY ERROR CODES
 * ============================================================ */

typedef enum {
    OZAYN_ID_OK                         =   0,
    OZAYN_ID_ERR_NULL                   =  -1,
    OZAYN_ID_ERR_NOT_INITIALIZED        =  -2,
    OZAYN_ID_ERR_NOT_FOUND              =  -3,
    OZAYN_ID_ERR_ALREADY_EXISTS         =  -4,
    OZAYN_ID_ERR_INVALID                =  -5,
    OZAYN_ID_ERR_ID_INVALID             =  -6,
    OZAYN_ID_ERR_TYPE_INVALID           =  -7,
    OZAYN_ID_ERR_STATE_INVALID          =  -8,
    OZAYN_ID_ERR_SCOPE_INVALID          =  -9,
    OZAYN_ID_ERR_OWNER_INVALID          = -10,
    OZAYN_ID_ERR_STATE_TRANSITION       = -11,
    OZAYN_ID_ERR_SUSPENDED              = -12,
    OZAYN_ID_ERR_REVOKED                = -13,
    OZAYN_ID_ERR_ARCHIVED               = -14,
    OZAYN_ID_ERR_STORAGE_FAILED         = -15,
    OZAYN_ID_ERR_VAULT_UNAVAILABLE      = -16,
    OZAYN_ID_ERR_LOAD_FAILED            = -17,
    OZAYN_ID_ERR_SAVE_FAILED            = -18,
    OZAYN_ID_ERR_CORRUPTED              = -19,
    OZAYN_ID_ERR_METADATA_INVALID       = -20
} ozayn_identity_result_t;

/* ============================================================
 * IDENTITY CONSTANTS
 * ============================================================ */

#define OZAYN_ID_MAX_ID_LEN       64
#define OZAYN_ID_MAX_LABEL_LEN   128
#define OZAYN_ID_MAX_OWNER_LEN    64
#define OZAYN_ID_MAX_CREDENTIAL_REFS  4
#define OZAYN_ID_MAX_CREDENTIAL_REF_LEN 64
#define OZAYN_ID_MAX_IDENTITIES  256

/* ============================================================
 * CREDENTIAL REFERENCE (non-secret locator only)
 * ============================================================ */

typedef struct {
    char    ref_id[OZAYN_ID_MAX_CREDENTIAL_REF_LEN]; /* Reference identifier */
    int     in_use;
} ozayn_identity_credential_ref_t;

/* ============================================================
 * IDENTITY OBJECT
 * ============================================================ */

typedef struct {
    /* Identifier */
    char                            id[OZAYN_ID_MAX_ID_LEN];
    uint32_t                        version;

    /* Type and State */
    ozayn_id_type_t                 type;
    ozayn_id_state_t                state;

    /* Display */
    char                            label[OZAYN_ID_MAX_LABEL_LEN];

    /* Scope and Ownership */
    ozayn_id_scope_t                scope;
    char                            owner[OZAYN_ID_MAX_OWNER_LEN];

    /* Timestamps */
    time_t                          created_at;
    time_t                          modified_at;

    /* Credential References (non-secret) */
    ozayn_identity_credential_ref_t credential_refs[OZAYN_ID_MAX_CREDENTIAL_REFS];
    int                             credential_count;
} ozayn_identity_t;

/* ============================================================
 * IDENTITY SERVICE CONFIGURATION
 * ============================================================ */

typedef struct {
    ozayn_vault_t   *vault;     /* Secure Vault for persistence */
} ozayn_identity_service_config_t;

/* ============================================================
 * IDENTITY SERVICE
 * ============================================================ */

typedef struct {
    ozayn_identity_t                identities[OZAYN_ID_MAX_IDENTITIES];
    int                             identity_count;
    ozayn_identity_service_config_t config;
    int                             initialized;
} ozayn_identity_service_t;

/* ============================================================
 * IDENTITY SERVICE LIFECYCLE
 * ============================================================ */

ozayn_identity_result_t ozayn_id_service_init(ozayn_identity_service_t *svc,
                                               const ozayn_identity_service_config_t *config);

void ozayn_id_service_shutdown(ozayn_identity_service_t *svc);

/* ============================================================
 * IDENTITY OPERATIONS
 * ============================================================ */

/* Create: create a new identity */
ozayn_identity_result_t ozayn_id_create(ozayn_identity_service_t *svc,
                                         ozayn_id_type_t type,
                                         const char *label,
                                         ozayn_id_scope_t scope,
                                         const char *owner,
                                         ozayn_identity_t *out_id);

/* Get: retrieve an identity by ID */
ozayn_identity_result_t ozayn_id_get(ozayn_identity_service_t *svc,
                                      const char *id,
                                      ozayn_identity_t *out_id);

/* Update: modify identity metadata (label, scope) */
ozayn_identity_result_t ozayn_id_update(ozayn_identity_service_t *svc,
                                         const char *id,
                                         const char *new_label,
                                         ozayn_id_scope_t new_scope);

/* Suspend: transition to suspended state */
ozayn_identity_result_t ozayn_id_suspend(ozayn_identity_service_t *svc,
                                          const char *id);

/* Revoke: transition to revoked state */
ozayn_identity_result_t ozayn_id_revoke(ozayn_identity_service_t *svc,
                                         const char *id);

/* Archive: transition to archived state */
ozayn_identity_result_t ozayn_id_archive(ozayn_identity_service_t *svc,
                                          const char *id);

/* Reactivate: transition from suspended back to active */
ozayn_identity_result_t ozayn_id_reactivate(ozayn_identity_service_t *svc,
                                             const char *id);

/* Remove: remove identity (marks for deletion) */
ozayn_identity_result_t ozayn_id_remove(ozayn_identity_service_t *svc,
                                         const char *id);

/* Exists: check if an identity exists */
int ozayn_id_exists(ozayn_identity_service_t *svc, const char *id);

/* List: retrieve identities of a given type */
int ozayn_id_list(ozayn_identity_service_t *svc,
                   ozayn_id_type_t type,
                   ozayn_identity_t *out_items,
                   int max_count);

/* ============================================================
 * QUERY
 * ============================================================ */

int ozayn_id_service_count(const ozayn_identity_service_t *svc);
int ozayn_id_service_is_initialized(const ozayn_identity_service_t *svc);

/* ============================================================
 * VALIDATION
 * ============================================================ */

int ozayn_id_validate(const ozayn_identity_t *id);
int ozayn_id_validate_type(ozayn_id_type_t type);
int ozayn_id_validate_state(ozayn_id_state_t state);
int ozayn_id_validate_scope(ozayn_id_scope_t scope);
int ozayn_id_validate_state_transition(ozayn_id_state_t from,
                                        ozayn_id_state_t to);

/* ============================================================
 * NAME HELPERS
 * ============================================================ */

const char *ozayn_id_type_name(ozayn_id_type_t type);
const char *ozayn_id_state_name(ozayn_id_state_t state);
const char *ozayn_id_scope_name(ozayn_id_scope_t scope);
const char *ozayn_id_result_name(ozayn_identity_result_t result);

#endif
