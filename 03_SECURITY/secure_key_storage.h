#ifndef OZAYN_SECURE_KEY_STORAGE_H
#define OZAYN_SECURE_KEY_STORAGE_H

#include "key_provider.h"
#include <stdint.h>
#include <stddef.h>
#include <time.h>

/*
 * secure_key_storage.h — Secure Key Storage Layer (Section 03, Step 09).
 *
 * Establishes the storage boundary responsible for protecting production
 * encryption keys. Keys must never be stored as ordinary plaintext files,
 * configuration values, source-code constants, logs, or application data.
 *
 * Architecture:
 *   ProtectionProvider -> KeyProvider -> SecureKeyStorage -> PlatformKeyStore
 *
 * The secure key storage layer is independent from:
 *   - Application business logic
 *   - Local storage
 *   - Encryption implementation
 *   - Authentication
 *   - GUI
 */

#define OZAYN_KS_MAX_KEY_SIZE    64
#define OZAYN_KS_MAX_LABEL_LEN  128

/* ============================================================
 * KEY STORAGE ERROR CODES
 * ============================================================ */

typedef enum {
    OZAYN_KS_OK                       =  0,
    OZAYN_KS_ERR_NULL                 = -1,
    OZAYN_KS_ERR_NOT_INITIALIZED      = -2,
    OZAYN_KS_ERR_UNAVAILABLE          = -3,
    OZAYN_KS_ERR_NOT_FOUND            = -4,
    OZAYN_KS_ERR_ALREADY_EXISTS       = -5,
    OZAYN_KS_ERR_INVALID_REQUEST      = -6,
    OZAYN_KS_ERR_INVALID_KEY          = -7,
    OZAYN_KS_ERR_ACCESS_DENIED        = -8,
    OZAYN_KS_ERR_STORAGE_FAILED       = -9,
    OZAYN_KS_ERR_PLATFORM_ERROR       = -10,
    OZAYN_KS_ERR_UNSUPPORTED          = -11,
    OZAYN_KS_ERR_KEY_REMOVED          = -12
} ozayn_ks_result_t;

/* ============================================================
 * KEY STORAGE OPERATION
 * ============================================================ */

typedef enum {
    OZAYN_KS_OP_STORE    = 1,
    OZAYN_KS_OP_LOAD     = 2,
    OZAYN_KS_OP_EXISTS   = 3,
    OZAYN_KS_OP_REMOVE   = 4,
    OZAYN_KS_OP_METADATA = 5
} ozayn_ks_operation_t;

/* ============================================================
 * KEY STORAGE STATE
 * ============================================================ */

typedef enum {
    OZAYN_KS_STATE_UNINITIALIZED = 0,
    OZAYN_KS_STATE_INITIALIZED   = 1,
    OZAYN_KS_STATE_READY         = 2,
    OZAYN_KS_STATE_STOPPED       = 3
} ozayn_ks_state_t;

/* ============================================================
 * KEY STORAGE REQUEST
 * ============================================================ */

typedef struct {
    ozayn_ks_operation_t  operation;
    ozayn_key_id_t        key_id;
    ozayn_key_purpose_t   purpose;
    uint8_t               key_material[OZAYN_KS_MAX_KEY_SIZE];
    size_t                key_length;
    char                  label[OZAYN_KS_MAX_LABEL_LEN];
} ozayn_ks_request_t;

/* ============================================================
 * KEY STORAGE RESULT
 * ============================================================ */

typedef struct {
    ozayn_ks_result_t     status;
    uint8_t               key_material[OZAYN_KS_MAX_KEY_SIZE];
    size_t                key_length;
    ozayn_key_id_t        key_id;
    ozayn_key_lifecycle_t  lifecycle;
    ozayn_key_purpose_t   purpose;
    uint32_t              key_version;
    time_t                created_at;
    time_t                stored_at;
    int                   exists;
    char                  platform_type[32];
} ozayn_ks_result_data_t;

/* ============================================================
 * KEY STORAGE METADATA
 * ============================================================ */

typedef struct {
    ozayn_key_id_t        key_id;
    ozayn_key_lifecycle_t  lifecycle;
    ozayn_key_purpose_t   purpose;
    uint32_t              key_version;
    size_t                key_length;
    time_t                created_at;
    time_t                stored_at;
    char                  platform_type[32];
    int                   is_valid;
} ozayn_ks_metadata_t;

/* ============================================================
 * KEY STORAGE PROVIDER INTERFACE (vtable)
 * ============================================================ */

typedef struct ozayn_key_storage ozayn_key_storage_t;

typedef struct {
    /* Lifecycle */
    ozayn_ks_result_t (*init)(ozayn_key_storage_t *storage);
    void              (*shutdown)(ozayn_key_storage_t *storage);

    /* Operations */
    ozayn_ks_result_t (*store)(ozayn_key_storage_t *storage,
                                const ozayn_ks_request_t *request,
                                ozayn_ks_result_data_t *out);

    ozayn_ks_result_t (*load)(ozayn_key_storage_t *storage,
                               const ozayn_ks_request_t *request,
                               ozayn_ks_result_data_t *out);

    ozayn_ks_result_t (*exists)(ozayn_key_storage_t *storage,
                                 const ozayn_key_id_t *key_id,
                                 int *out_exists);

    ozayn_ks_result_t (*remove)(ozayn_key_storage_t *storage,
                                 const ozayn_key_id_t *key_id);

    ozayn_ks_result_t (*get_metadata)(ozayn_key_storage_t *storage,
                                       const ozayn_key_id_t *key_id,
                                       ozayn_ks_metadata_t *out);

    /* Query */
    int               (*is_available)(const ozayn_key_storage_t *storage);
    const char       *(*platform_name)(const ozayn_key_storage_t *storage);
} ozayn_ks_ops_t;

/* ============================================================
 * KEY STORAGE PROVIDER
 * ============================================================ */

struct ozayn_key_storage {
    const char              *name;
    ozayn_ks_state_t         state;
    const ozayn_ks_ops_t    *ops;
    void                    *impl_data;
};

/* ============================================================
 * LIFECYCLE
 * ============================================================ */

ozayn_ks_result_t ozayn_ks_init(ozayn_key_storage_t *storage);
void ozayn_ks_shutdown(ozayn_key_storage_t *storage);
int  ozayn_ks_is_ready(const ozayn_key_storage_t *storage);

/* ============================================================
 * OPERATIONS
 * ============================================================ */

ozayn_ks_result_t ozayn_ks_store(ozayn_key_storage_t *storage,
                                  const ozayn_ks_request_t *request,
                                  ozayn_ks_result_data_t *out);

ozayn_ks_result_t ozayn_ks_load(ozayn_key_storage_t *storage,
                                 const ozayn_ks_request_t *request,
                                 ozayn_ks_result_data_t *out);

ozayn_ks_result_t ozayn_ks_exists(ozayn_key_storage_t *storage,
                                   const ozayn_key_id_t *key_id,
                                   int *out_exists);

ozayn_ks_result_t ozayn_ks_remove(ozayn_key_storage_t *storage,
                                   const ozayn_key_id_t *key_id);

ozayn_ks_result_t ozayn_ks_get_metadata(ozayn_key_storage_t *storage,
                                          const ozayn_key_id_t *key_id,
                                          ozayn_ks_metadata_t *out);

/* ============================================================
 * QUERY
 * ============================================================ */

int ozayn_ks_is_available(const ozayn_key_storage_t *storage);
const char *ozayn_ks_platform_name(const ozayn_key_storage_t *storage);

/* ============================================================
 * NAME HELPERS
 * ============================================================ */

const char *ozayn_ks_result_name(ozayn_ks_result_t result);
const char *ozayn_ks_operation_name(ozayn_ks_operation_t op);
const char *ozayn_ks_state_name(ozayn_ks_state_t state);

/* ============================================================
 * REQUEST HELPERS
 * ============================================================ */

void ozayn_ks_request_init(ozayn_ks_request_t *req, ozayn_ks_operation_t op,
                            const ozayn_key_id_t *id, ozayn_key_purpose_t purpose);

void ozayn_ks_request_set_store(ozayn_ks_request_t *req,
                                 const ozayn_key_id_t *id,
                                 const uint8_t *key, size_t key_len,
                                 ozayn_key_purpose_t purpose);

#endif
