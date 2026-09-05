#ifndef OZAYN_SECURE_VAULT_H
#define OZAYN_SECURE_VAULT_H

#include "secure_data_object.h"
#include "protection_provider.h"
#include "storage_provider.h"
#include "key_lifecycle.h"
#include "secure_key_storage.h"
#include <stdint.h>
#include <stddef.h>

/*
 * secure_vault.h — Secure Vault (Section 03, Step 11).
 *
 * Provides protected persistent storage for OZAYN data objects.
 * Orchestrates validation, encryption, key management, and storage.
 *
 * Architecture:
 *   OZAYN COMPONENT
 *          |
 *          v
 *   SECURE VAULT  <-- this layer
 *          |
 *   +------+------+------+
 *   |             |      |
 *   v             v      v
 * VALIDATION  PROTECTION  STORAGE
 *                |
 *                v
 *          KEY MANAGEMENT
 *                |
 *                v
 *          KEY STORAGE
 *                |
 *                v
 *          PERSISTENT STORAGE
 *
 * Step 11 scope:
 *   - Vault interface (STORE, LOAD, UPDATE, REMOVE, EXISTS, LIST)
 *   - Protected persistence through existing security components
 *   - Key-version association
 *   - Classification preservation
 *   - Corruption/tamper detection
 *   - Fail-closed behavior
 *
 * NOT in scope:
 *   - User authentication / authorization
 *   - Biometrics, sessions, permissions, RBAC
 *   - Key recovery / escrow
 *   - Secure deletion / wiping
 *   - GUI
 */

#define OZAYN_VAULT_MAX_OBJECTS     128
#define OZAYN_VAULT_MAX_ID_LEN      64
#define OZAYN_VAULT_MAX_NAME_LEN    32

/* ============================================================
 * VAULT ERROR CODES
 * ============================================================ */

typedef enum {
    OZAYN_VAULT_OK                      =   0,
    OZAYN_VAULT_ERR_NULL                =  -1,
    OZAYN_VAULT_ERR_NOT_INITIALIZED     =  -2,
    OZAYN_VAULT_ERR_UNAVAILABLE         =  -3,
    OZAYN_VAULT_ERR_STORE_FAILED        =  -4,
    OZAYN_VAULT_ERR_LOAD_FAILED         =  -5,
    OZAYN_VAULT_ERR_UPDATE_FAILED       =  -6,
    OZAYN_VAULT_ERR_REMOVE_FAILED       =  -7,
    OZAYN_VAULT_ERR_OBJECT_NOT_FOUND    =  -8,
    OZAYN_VAULT_ERR_INVALID_OBJECT      =  -9,
    OZAYN_VAULT_ERR_PROTECTION_FAILED   = -10,
    OZAYN_VAULT_ERR_UNPROTECTION_FAILED = -11,
    OZAYN_VAULT_ERR_KEY_UNAVAILABLE     = -12,
    OZAYN_VAULT_ERR_KEY_INVALID         = -13,
    OZAYN_VAULT_ERR_STORAGE_FAILED      = -14,
    OZAYN_VAULT_ERR_INTEGRITY_FAILURE   = -15,
    OZAYN_VAULT_ERR_FORMAT_UNSUPPORTED  = -16,
    OZAYN_VAULT_ERR_DUPLICATE           = -17,
    OZAYN_VAULT_ERR_CLASSIFICATION      = -18,
    OZAYN_VAULT_ERR_AUTH_FAILED         = -19
} ozayn_vault_result_t;

/* ============================================================
 * VAULT OBJECT ENTRY (metadata stored alongside protected data)
 * ============================================================ */

typedef struct {
    char                        id[OZAYN_VAULT_MAX_ID_LEN];
    ozayn_data_category_t       category;
    ozayn_security_level_t      classification;
    uint32_t                    key_version;       /* Key version used for encryption */
    time_t                      created_at;
    time_t                      modified_at;
    uint64_t                    plaintext_size;    /* Original plaintext size */
    int                         in_use;
} ozayn_vault_entry_t;

/* ============================================================
 * VAULT LIST RESULT
 * ============================================================ */

typedef struct {
    char                        id[OZAYN_VAULT_MAX_ID_LEN];
    ozayn_data_category_t       category;
    ozayn_security_level_t      classification;
    uint32_t                    key_version;
    time_t                      created_at;
    time_t                      modified_at;
} ozayn_vault_list_item_t;

/* ============================================================
 * VAULT CONFIGURATION
 * ============================================================ */

typedef struct {
    ozayn_protection_provider_t    *protection;     /* Encryption provider */
    ozayn_storage_provider_t       *storage;        /* Persistent storage */
    ozayn_kl_manager_t             *key_lifecycle;  /* Key lifecycle manager */
} ozayn_vault_config_t;

/* ============================================================
 * SECURE VAULT
 * ============================================================ */

typedef struct {
    ozayn_vault_entry_t             entries[OZAYN_VAULT_MAX_OBJECTS];
    int                             entry_count;
    ozayn_vault_config_t            config;
    int                             initialized;
} ozayn_vault_t;

/* ============================================================
 * VAULT LIFECYCLE
 * ============================================================ */

ozayn_vault_result_t ozayn_vault_init(ozayn_vault_t *vault,
                                       const ozayn_vault_config_t *config);

void ozayn_vault_shutdown(ozayn_vault_t *vault);

/* ============================================================
 * VAULT OPERATIONS
 * ============================================================ */

/* Store: encrypt and persist a data object */
ozayn_vault_result_t ozayn_vault_store(ozayn_vault_t *vault,
                                        const ozayn_secure_data_object_t *obj,
                                        const uint8_t *plaintext,
                                        size_t plaintext_len);

/* Load: retrieve and decrypt a data object */
ozayn_vault_result_t ozayn_vault_load(ozayn_vault_t *vault,
                                        const char *id,
                                        ozayn_secure_data_object_t *out_obj,
                                        uint8_t *out_plaintext,
                                        size_t max_plaintext_len,
                                        size_t *out_plaintext_len);

/* Update: re-encrypt and replace an existing object */
ozayn_vault_result_t ozayn_vault_update(ozayn_vault_t *vault,
                                          const ozayn_secure_data_object_t *obj,
                                          const uint8_t *plaintext,
                                          size_t plaintext_len);

/* Remove: delete a vault entry (ordinary removal, not secure wipe) */
ozayn_vault_result_t ozayn_vault_remove(ozayn_vault_t *vault,
                                          const char *id);

/* Exists: check if a vault entry exists */
int ozayn_vault_exists(ozayn_vault_t *vault, const char *id);

/* List: retrieve safe metadata for objects of a given category */
int ozayn_vault_list(ozayn_vault_t *vault,
                      ozayn_data_category_t category,
                      ozayn_vault_list_item_t *out_items,
                      int max_count);

/* ============================================================
 * QUERY
 * ============================================================ */

int ozayn_vault_count(const ozayn_vault_t *vault);
int ozayn_vault_is_initialized(const ozayn_vault_t *vault);

/* ============================================================
 * NAME HELPERS
 * ============================================================ */

const char *ozayn_vault_result_name(ozayn_vault_result_t result);

#endif
