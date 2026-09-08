#ifndef OZAYN_DELETION_H
#define OZAYN_DELETION_H

#include "secure_vault.h"
#include "key_lifecycle.h"
#include "protection_provider.h"
#include "storage_provider.h"
#include "data_classification.h"
#include "secure_data_object.h"
#include "audit.h"
#include <stdint.h>
#include <stddef.h>
#include <time.h>

/*
 * deletion.h — Secure Deletion & Data Destruction Foundation (Step 24).
 *
 * Provides controlled, auditable, fail-safe deletion of protected OZAYN
 * data and associated temporary artifacts. Distinguishes logical deletion,
 * storage deletion, temporary-data cleanup, cryptographic erasure, and
 * key destruction.
 *
 * Architecture:
 *   OZAYN COMPONENT
 *        ↓
 *   DELETION REQUEST
 *        ↓
 *   DELETION POLICY
 *        ↓
 *   DELETION AUTHORIZATION
 *        ↓
 *   DELETION SERVICE  <-- this layer
 *        ↓
 *   DELETION VALIDATION
 *        ↓
 *   STORAGE / KEY / TEMPORARY DATA BOUNDARY
 *        ↓
 *   DELETION RESULT
 *        ↓
 *   SECURITY AUDIT
 *
 * For cryptographic erasure:
 *   PROTECTED DATA
 *        ↓
 *   KEY REFERENCE
 *        ↓
 *   KEY LIFECYCLE
 *        ↓
 *   KEY REVOCATION / DESTRUCTION POLICY
 *        ↓
 *   DATA BECOMES CRYPTOGRAPHICALLY UNRECOVERABLE
 *
 * Step 24 scope:
 *   - Deletion types (logical, storage, temporary, crypto, key, backup)
 *   - Deletion request contract (no secrets)
 *   - Deletion result with verification
 *   - Deletion state model
 *   - Deletion policy
 *   - Deletion service with vault integration
 *   - Key dependency checking before key destruction
 *   - Cryptographic erasure boundary
 *   - Temporary data cleanup boundary
 *   - Audit integration for all deletion operations
 *   - Authorization boundary
 *   - Resource limits
 *   - Partial deletion handling
 *   - Cross-platform safety
 *   - No false physical-erasure claims
 *
 * NOT in scope:
 *   - Physical media sanitization (SSD/flash/journaling limitations)
 *   - Cloud deletion
 *   - Hardware secure erase
 *   - GUI
 */

/* ============================================================
 * SECTION 1 — ERROR CODES
 * ============================================================ */

typedef enum {
    OZAYN_DEL_OK                         =   0,
    OZAYN_DEL_ERR                        =  -1,
    OZAYN_DEL_ERR_NULL                   =  -2,
    OZAYN_DEL_ERR_NOT_INITIALIZED        =  -3,
    OZAYN_DEL_ERR_ALREADY_INITIALIZED    =  -4,
    OZAYN_DEL_ERR_INVALID_REQUEST        =  -5,
    OZAYN_DEL_ERR_INVALID_ID             =  -6,
    OZAYN_DEL_ERR_INVALID_TYPE           =  -7,
    OZAYN_DEL_ERR_NOT_FOUND              =  -8,
    OZAYN_DEL_ERR_ALREADY_DELETED        =  -9,
    OZAYN_DEL_ERR_UNAUTHORIZED           = -10,
    OZAYN_DEL_ERR_MFA_REQUIRED           = -11,
    OZAYN_DEL_ERR_POLICY_REJECTED        = -12,
    OZAYN_DEL_ERR_VAULT_UNAVAILABLE      = -13,
    OZAYN_DEL_ERR_VAULT_FAILED           = -14,
    OZAYN_DEL_ERR_KEY_IN_USE             = -15,
    OZAYN_DEL_ERR_KEY_DESTRUCTION_DENIED = -16,
    OZAYN_DEL_ERR_KEY_DESTRUCTION_FAILED = -17,
    OZAYN_DEL_ERR_CRYPTO_ERASURE_UNAVAIL = -18,
    OZAYN_DEL_ERR_STORAGE_FAILED         = -19,
    OZAYN_DEL_ERR_INTEGRITY_FAILURE      = -20,
    OZAYN_DEL_ERR_PARTIAL                = -21,
    OZAYN_DEL_ERR_CONCURRENCY            = -22,
    OZAYN_DEL_ERR_UNSUPPORTED            = -23
} ozayn_del_result_t;

/* ============================================================
 * SECTION 2 — DELETION TYPES
 * ============================================================ */

typedef enum {
    OZAYN_DEL_TYPE_LOGICAL          = 0,
    OZAYN_DEL_TYPE_STORAGE          = 1,
    OZAYN_DEL_TYPE_TEMPORARY        = 2,
    OZAYN_DEL_TYPE_CRYPTO_ERASURE   = 3,
    OZAYN_DEL_TYPE_KEY_DESTRUCTION  = 4,
    OZAYN_DEL_TYPE_BACKUP           = 5,
    OZAYN_DEL_TYPE_PHYSICAL_MEDIA   = 6
} ozayn_del_type_t;

/* ============================================================
 * SECTION 3 — DELETION STATE MODEL
 * ============================================================ */

typedef enum {
    OZAYN_DEL_STATE_IDLE                   = 0,
    OZAYN_DEL_STATE_MARKED_FOR_DELETION    = 1,
    OZAYN_DEL_STATE_DELETING               = 2,
    OZAYN_DEL_STATE_DELETED                = 3,
    OZAYN_DEL_STATE_DELETION_FAILED        = 4,
    OZAYN_DEL_STATE_CRYPTO_ERASED          = 5
} ozayn_del_state_t;

/* ============================================================
 * SECTION 4 — DELETION REQUEST
 * ============================================================ */

#define OZAYN_DEL_MAX_ID_LEN    64
#define OZAYN_DEL_MAX_REASON_LEN 128

typedef struct {
    char                        request_id[OZAYN_DEL_MAX_ID_LEN];
    char                        object_id[OZAYN_DEL_MAX_ID_LEN];
    ozayn_data_category_t       data_category;
    ozayn_del_type_t            deletion_type;
    char                        identity_id[OZAYN_DEL_MAX_ID_LEN];
    char                        session_id[OZAYN_DEL_MAX_ID_LEN];
    char                        reason[OZAYN_DEL_MAX_REASON_LEN];
    int                         force;
} ozayn_del_request_t;

/* ============================================================
 * SECTION 5 — DELETION RESULT
 * ============================================================ */

typedef struct {
    ozayn_del_result_t           result;
    char                        object_id[OZAYN_DEL_MAX_ID_LEN];
    ozayn_del_type_t            deletion_type;
    ozayn_del_state_t           previous_state;
    ozayn_del_state_t           final_state;
    time_t                      timestamp;
    char                        audit_ref[OZAYN_DEL_MAX_ID_LEN];
    char                        failure_reason[OZAYN_DEL_MAX_REASON_LEN];
} ozayn_del_result_data_t;

/* ============================================================
 * SECTION 6 — DELETION POLICY
 * ============================================================ */

#define OZAYN_DEL_MAX_BATCH_SIZE    64
#define OZAYN_DEL_MAX_CATEGORIES    16

typedef struct {
    int                         require_authorization;
    int                         require_mfa_for_sensitive;
    int                         require_mfa_for_keys;
    int                         allow_logical_delete;
    int                         allow_storage_delete;
    int                         allow_crypto_erasure;
    int                         allow_key_destruction;
    int                         verify_after_delete;
    int                         max_batch_size;
    ozayn_security_level_t      mfa_threshold;
} ozayn_del_policy_t;

/* ============================================================
 * SECTION 7 — DELETION SERVICE
 * ============================================================ */

typedef struct {
    int                         initialized;
    ozayn_del_state_t           state;
    ozayn_del_policy_t          policy;

    /* Dependencies (not owned) */
    ozayn_vault_t              *vault;
    ozayn_kl_manager_t         *key_lifecycle;
    ozayn_protection_provider_t *protection;
    ozayn_storage_provider_t   *storage;
    ozayn_audit_service_t      *audit;

    /* Tracking */
    char                        active_object_id[OZAYN_DEL_MAX_ID_LEN];
    ozayn_del_type_t            active_deletion_type;

    /* Stats */
    uint64_t                    total_deletions_requested;
    uint64_t                    total_deletions_completed;
    uint64_t                    total_deletions_failed;
    uint64_t                    total_crypto_erasures;
    uint64_t                    total_key_destructions;
    uint64_t                    total_temp_cleanups;
} ozayn_del_service_t;

/* ============================================================
 * SECTION 8 — SERVICE CONFIGURATION
 * ============================================================ */

typedef struct {
    ozayn_vault_t              *vault;
    ozayn_kl_manager_t         *key_lifecycle;
    ozayn_protection_provider_t *protection;
    ozayn_storage_provider_t   *storage;
    ozayn_audit_service_t      *audit;
} ozayn_del_service_config_t;

/* ============================================================
 * SECTION 9 — LIFECYCLE
 * ============================================================ */

ozayn_del_result_t ozayn_del_service_init(ozayn_del_service_t *svc,
                                           const ozayn_del_service_config_t *cfg);

void               ozayn_del_service_shutdown(ozayn_del_service_t *svc);

int                ozayn_del_service_is_initialized(const ozayn_del_service_t *svc);

/* ============================================================
 * SECTION 10 — REQUEST MANAGEMENT
 * ============================================================ */

ozayn_del_result_t ozayn_del_request_init(ozayn_del_request_t *request,
                                           const char *object_id,
                                           ozayn_data_category_t category,
                                           ozayn_del_type_t deletion_type,
                                           const char *identity_id);

ozayn_del_result_t ozayn_del_validate_request(const ozayn_del_service_t *svc,
                                               const ozayn_del_request_t *request);

/* ============================================================
 * SECTION 11 — DELETION EXECUTION
 * ============================================================ */

ozayn_del_result_t ozayn_del_execute(ozayn_del_service_t *svc,
                                      const ozayn_del_request_t *request,
                                      ozayn_del_result_data_t *out_result);

ozayn_del_result_t ozayn_del_check_state(const ozayn_del_service_t *svc,
                                          const char *object_id,
                                          ozayn_del_state_t *out_state);

/* ============================================================
 * SECTION 12 — KEY DEPENDENCY
 * ============================================================ */

ozayn_del_result_t ozayn_del_check_key_dependency(const ozayn_del_service_t *svc,
                                                    const char *object_id,
                                                    int *out_key_still_required);

ozayn_del_result_t ozayn_del_destroy_key(ozayn_del_service_t *svc,
                                           const char *object_id,
                                           const char *key_name,
                                           uint32_t key_version);

/* ============================================================
 * SECTION 13 — CRYPTOGRAPHIC ERASURE
 * ============================================================ */

ozayn_del_result_t ozayn_del_crypto_erasure(ozayn_del_service_t *svc,
                                              const ozayn_del_request_t *request,
                                              ozayn_del_result_data_t *out_result);

/* ============================================================
 * SECTION 14 — TEMPORARY DATA CLEANUP
 * ============================================================ */

ozayn_del_result_t ozayn_del_cleanup_temporary(ozayn_del_service_t *svc);

/* ============================================================
 * SECTION 15 — POLICY
 * ============================================================ */

ozayn_del_result_t ozayn_del_set_policy(ozayn_del_service_t *svc,
                                          const ozayn_del_policy_t *policy);

const ozayn_del_policy_t *ozayn_del_get_policy(const ozayn_del_service_t *svc);

ozayn_del_policy_t ozayn_del_default_policy(void);

/* ============================================================
 * SECTION 16 — NAME HELPERS
 * ============================================================ */

const char *ozayn_del_result_name(ozayn_del_result_t r);

const char *ozayn_del_type_name(ozayn_del_type_t t);

const char *ozayn_del_state_name(ozayn_del_state_t s);

/* ============================================================
 * SECTION 17 — GLOBAL SERVICE ACCESSOR
 * ============================================================ */

ozayn_del_service_t *ozayn_del_get_global(void);

#endif /* OZAYN_DELETION_H */
