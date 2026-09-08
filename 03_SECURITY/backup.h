#ifndef OZAYN_BACKUP_H
#define OZAYN_BACKUP_H

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
 * backup.h — Secure Backup & Recovery Foundation (Step 23).
 *
 * Provides controlled backup and restore of OZAYN security data
 * while preserving confidentiality, integrity, data classification,
 * key-version compatibility, and audit integrity.
 *
 * Architecture:
 *   SECURE VAULT
 *        ↓
 *   BACKUP SERVICE  <-- this layer
 *        ↓
 *   BACKUP VALIDATION
 *        ↓
 *   PROTECTED BACKUP
 *        ↓
 *   BACKUP STORAGE
 *
 * Recovery:
 *   BACKUP
 *        ↓
 *   VALIDATION
 *        ↓
 *   INTEGRITY CHECK
 *        ↓
 *   KEY AVAILABILITY
 *        ↓
 *   SAFE RESTORE
 *
 * Step 23 scope:
 *   - Versioned backup format
 *   - Backup identifiers
 *   - Backup types (FULL, SELECTIVE, CONFIGURATION)
 *   - Backup policy (data categories, size limits, protection)
 *   - Backup creation with integrity verification
 *   - Backup validation
 *   - Controlled restore (VALIDATE_ONLY, RESTORE_NEW, RESTORE_REPLACE)
 *   - Restore authorization boundary
 *   - Key-version compatibility
 *   - Audit event integration
 *   - Resource limits (max size, max objects, max metadata)
 *   - Crash-safe restore boundary
 *   - Test-only backup providers
 *
 * NOT in scope:
 *   - Cloud backup
 *   - Automatic synchronization
 *   - Disaster recovery infrastructure
 *   - Remote backup server
 *   - GUI backup manager
 *   - Password recovery
 *   - Account recovery
 *   - Full secure deletion
 */

/* ============================================================
 * SECTION 1 — ERROR / RESULT CODES
 * ============================================================ */

typedef enum {
    OZAYN_BK_OK                           = 0,
    OZAYN_BK_ERR                          = -1,
    OZAYN_BK_ERR_NULL                     = -2,
    OZAYN_BK_ERR_NOT_INITIALIZED          = -3,
    OZAYN_BK_ERR_ALREADY_INITIALIZED      = -4,
    OZAYN_BK_ERR_INVALID_REQUEST          = -5,
    OZAYN_BK_ERR_POLICY_REJECTED          = -6,
    OZAYN_BK_ERR_UNAVAILABLE              = -7,
    OZAYN_BK_ERR_STORAGE_ERROR            = -8,
    OZAYN_BK_ERR_WRITE_FAILED             = -9,
    OZAYN_BK_ERR_READ_FAILED              = -10,
    OZAYN_BK_ERR_TOO_LARGE                = -11,
    OZAYN_BK_ERR_FORMAT_INVALID           = -12,
    OZAYN_BK_ERR_FORMAT_UNSUPPORTED       = -13,
    OZAYN_BK_ERR_INTEGRITY_FAILURE        = -14,
    OZAYN_BK_ERR_PROTECTION_FAILURE       = -15,
    OZAYN_BK_ERR_KEY_UNAVAILABLE          = -16,
    OZAYN_BK_ERR_KEY_INVALID              = -17,
    OZAYN_BK_ERR_PERMISSION_DENIED        = -18,
    OZAYN_BK_ERR_DUPLICATE                = -19,
    OZAYN_BK_ERR_OBJECT_NOT_FOUND         = -20,
    OZAYN_BK_ERR_VAULT_UNAVAILABLE        = -21,
    OZAYN_BK_ERR_VAULT_FAILED             = -22,
    OZAYN_BK_ERR_CATEGORY_NOT_ALLOWED     = -23,
    OZAYN_BK_ERR_VERSION_INCOMPATIBLE     = -24,
    OZAYN_BK_ERR_BACKUP_CORRUPTED         = -25,
    OZAYN_BK_ERR_RESTORE_UNAUTHORIZED     = -26,
    OZAYN_BK_ERR_RESTORE_MFA_REQUIRED     = -27,
    OZAYN_BK_ERR_RESTORE_CONFLICT         = -28,
    OZAYN_BK_ERR_RESTORE_FAILED           = -29,
    OZAYN_BK_ERR_RESTORE_ROLLBACK_FAILED  = -30,
    OZAYN_BK_ERR_AUDIT_FAILED             = -31,
    OZAYN_BK_ERR_RESOURCE_EXHAUSTED       = -32,
    OZAYN_BK_ERR_INTEGRITY_REQUIRED       = -33,
} ozayn_bk_result_t;

/* ============================================================
 * SECTION 2 — BACKUP FORMAT VERSION
 * ============================================================ */

#define OZAYN_BK_FORMAT_VERSION     1
#define OZAYN_BK_MAX_BACKUP_ID_LEN  64
#define OZAYN_BK_MAX_OBJECT_ID_LEN  64
#define OZAYN_BK_MAX_VERSION_LEN    32
#define OZAYN_BK_MAX_NAME_LEN       64
#define OZAYN_BK_MAX_KEY_REF_LEN    64
#define OZAYN_BK_MAX_CHECKSUM_LEN   128

/* ============================================================
 * SECTION 3 — BACKUP TYPES
 * ============================================================ */

typedef enum {
    OZAYN_BK_TYPE_FULL                 = 0,
    OZAYN_BK_TYPE_SELECTIVE            = 1,
    OZAYN_BK_TYPE_CONFIGURATION        = 2,

    OZAYN_BK_TYPE_COUNT                = 3,
} ozayn_bk_type_t;

/* ============================================================
 * SECTION 4 — BACKUP STATE
 * ============================================================ */

typedef enum {
    OZAYN_BK_STATE_UNINITIALIZED       = 0,
    OZAYN_BK_STATE_READY               = 1,
    OZAYN_BK_STATE_BACKING_UP          = 2,
    OZAYN_BK_STATE_RESTORING           = 3,
    OZAYN_BK_STATE_ERROR               = 4,
} ozayn_bk_state_t;

/* ============================================================
 * SECTION 5 — RESTORE MODES
 * ============================================================ */

typedef enum {
    OZAYN_BK_RESTORE_VALIDATE_ONLY     = 0,
    OZAYN_BK_RESTORE_NEW               = 1,
    OZAYN_BK_RESTORE_REPLACE           = 2,
} ozayn_bk_restore_mode_t;

/* ============================================================
 * SECTION 6 — VERSION COMPATIBILITY
 * ============================================================ */

typedef enum {
    OZAYN_BK_COMPAT_SUPPORTED          = 0,
    OZAYN_BK_COMPAT_WITH_MIGRATION     = 1,
    OZAYN_BK_COMPAT_UNSUPPORTED        = 2,
    OZAYN_BK_COMPAT_CORRUPTED          = 3,
    OZAYN_BK_COMPAT_INCOMPATIBLE       = 4,
} ozayn_bk_compat_t;

/* ============================================================
 * SECTION 7 — KEY REFERENCE (metadata only, no secrets)
 * ============================================================ */

typedef struct {
    char                    key_name[OZAYN_BK_MAX_KEY_REF_LEN];
    uint32_t                key_version;
    uint8_t                 algorithm;
    uint8_t                 format_version;
} ozayn_bk_key_ref_t;

/* ============================================================
 * SECTION 8 — BACKUP OBJECT METADATA
 * ============================================================ */

typedef struct {
    char                        id[OZAYN_BK_MAX_OBJECT_ID_LEN];
    ozayn_data_category_t       category;
    ozayn_security_level_t      classification;
    uint32_t                    key_version;
    time_t                      created_at;
    uint64_t                    plaintext_size;
    uint64_t                    protected_size;
    uint32_t                    checksum;
} ozayn_bk_object_meta_t;

/* ============================================================
 * SECTION 9 — BACKUP MANIFEST
 * ============================================================ */

#define OZAYN_BK_MAX_OBJECTS        128
#define OZAYN_BK_MAX_KEY_REFS       16

typedef struct {
    char                        backup_id[OZAYN_BK_MAX_BACKUP_ID_LEN];
    uint32_t                    format_version;
    uint32_t                    ozayn_version_major;
    uint32_t                    ozayn_version_minor;
    uint32_t                    ozayn_version_patch;
    uint32_t                    security_schema_version;
    ozayn_bk_type_t             backup_type;
    time_t                      created_at;
    int                         object_count;
    ozayn_bk_object_meta_t      objects[OZAYN_BK_MAX_OBJECTS];
    int                         key_ref_count;
    ozayn_bk_key_ref_t          key_refs[OZAYN_BK_MAX_KEY_REFS];
    uint64_t                    total_protected_size;
    uint32_t                    manifest_checksum;
    int                         integrity_verified;
} ozayn_bk_manifest_t;

/* ============================================================
 * SECTION 10 — BACKUP OBJECT (protected payload)
 * ============================================================ */

typedef struct {
    char                        id[OZAYN_BK_MAX_OBJECT_ID_LEN];
    ozayn_data_category_t       category;
    ozayn_security_level_t      classification;
    uint32_t                    key_version;
    ozayn_protected_data_t      protected_data;
    uint32_t                    checksum;
    int                         in_use;
} ozayn_bk_object_t;

/* ============================================================
 * SECTION 11 — BACKUP PACKAGE
 * ============================================================ */

typedef struct {
    ozayn_bk_manifest_t         manifest;
    ozayn_bk_object_t           objects[OZAYN_BK_MAX_OBJECTS];
    int                         object_count;
    int                         in_use;
} ozayn_bk_package_t;

/* ============================================================
 * SECTION 12 — BACKUP POLICY
 * ============================================================ */

typedef struct {
    int                         enabled;
    int                         allowed_categories[OZAYN_DATA_CATEGORY_COUNT];
    int                         require_integrity;
    int                         require_protection;
    int                         require_audit;
    uint64_t                    max_backup_size;
    int                         max_object_count;
    int                         max_object_size;
    int                         retention_days;
    ozayn_security_level_t      min_classification;
    ozayn_security_level_t      max_classification;
} ozayn_bk_policy_t;

/* ============================================================
 * SECTION 13 — RESTORE REQUEST
 * ============================================================ */

typedef struct {
    char                        backup_id[OZAYN_BK_MAX_BACKUP_ID_LEN];
    ozayn_bk_restore_mode_t     mode;
    char                        identity_id[OZAYN_BK_MAX_OBJECT_ID_LEN];
    char                        session_id[OZAYN_BK_MAX_OBJECT_ID_LEN];
    int                         force;
} ozayn_bk_restore_request_t;

/* ============================================================
 * SECTION 14 — BACKUP SERVICE
 * ============================================================ */

typedef struct {
    int                         initialized;
    ozayn_bk_state_t            state;
    ozayn_bk_policy_t           policy;

    /* Dependencies (not owned) */
    ozayn_vault_t              *vault;
    ozayn_kl_manager_t         *key_lifecycle;
    ozayn_protection_provider_t *protection;
    ozayn_audit_service_t      *audit;

    /* Stats */
    uint64_t                    total_backups_created;
    uint64_t                    total_restores_completed;
    uint64_t                    total_backups_failed;
    uint64_t                    total_restores_failed;
} ozayn_bk_service_t;

/* ============================================================
 * SECTION 15 — SERVICE CONFIGURATION
 * ============================================================ */

typedef struct {
    ozayn_vault_t              *vault;
    ozayn_kl_manager_t         *key_lifecycle;
    ozayn_protection_provider_t *protection;
    ozayn_audit_service_t      *audit;
    int                         max_packages;
    uint64_t                    max_backup_size;
    int                         max_object_count;
} ozayn_bk_service_config_t;

/* ============================================================
 * SECTION 16 — LIFECYCLE
 * ============================================================ */

ozayn_bk_result_t ozayn_bk_service_init(ozayn_bk_service_t *svc,
                                         const ozayn_bk_service_config_t *cfg);
void              ozayn_bk_service_shutdown(ozayn_bk_service_t *svc);
int               ozayn_bk_service_is_initialized(const ozayn_bk_service_t *svc);

/* ============================================================
 * SECTION 17 — BACKUP CREATION
 * ============================================================ */

ozayn_bk_result_t ozayn_bk_create(ozayn_bk_service_t *svc,
                                   ozayn_bk_type_t type,
                                   ozayn_bk_package_t *out_package);

ozayn_bk_result_t ozayn_bk_add_object(ozayn_bk_service_t *svc,
                                        ozayn_bk_package_t *package,
                                        const char *object_id);

ozayn_bk_result_t ozayn_bk_finalize(ozayn_bk_service_t *svc,
                                     ozayn_bk_package_t *package);

/* ============================================================
 * SECTION 18 — BACKUP VALIDATION
 * ============================================================ */

ozayn_bk_result_t ozayn_bk_validate_package(const ozayn_bk_service_t *svc,
                                             const ozayn_bk_package_t *package);

ozayn_bk_result_t ozayn_bk_validate_manifest(const ozayn_bk_service_t *svc,
                                               const ozayn_bk_manifest_t *manifest);

ozayn_bk_compat_t ozayn_bk_check_compatibility(const ozayn_bk_service_t *svc,
                                                 const ozayn_bk_manifest_t *manifest);

/* ============================================================
 * SECTION 19 — RESTORE
 * ============================================================ */

ozayn_bk_result_t ozayn_bk_restore(const ozayn_bk_service_t *svc,
                                    const ozayn_bk_restore_request_t *request,
                                    const ozayn_bk_package_t *package);

ozayn_bk_result_t ozayn_bk_restore_validate_only(const ozayn_bk_service_t *svc,
                                                   const ozayn_bk_package_t *package);

/* ============================================================
 * SECTION 20 — POLICY
 * ============================================================ */

ozayn_bk_result_t ozayn_bk_set_policy(ozayn_bk_service_t *svc,
                                       const ozayn_bk_policy_t *policy);

const ozayn_bk_policy_t *ozayn_bk_get_policy(const ozayn_bk_service_t *svc);

ozayn_bk_policy_t ozayn_bk_default_policy(void);

/* ============================================================
 * SECTION 21 — NAME HELPERS
 * ============================================================ */

const char *ozayn_bk_result_name(ozayn_bk_result_t r);
const char *ozayn_bk_type_name(ozayn_bk_type_t t);
const char *ozayn_bk_state_name(ozayn_bk_state_t s);
const char *ozayn_bk_restore_mode_name(ozayn_bk_restore_mode_t m);
const char *ozayn_bk_compat_name(ozayn_bk_compat_t c);

/* ============================================================
 * SECTION 22 — CHECKSUM
 * ============================================================ */

uint32_t ozayn_bk_checksum(const uint8_t *data, size_t len);

/* ============================================================
 * SECTION 23 — QH MANAGER (static global accessor)
 * ============================================================ */

ozayn_bk_service_t *ozayn_bk_get_global(void);

#endif
