#ifndef OZAYN_KEY_PROVIDER_H
#define OZAYN_KEY_PROVIDER_H

#include <stdint.h>
#include <stddef.h>
#include <time.h>

/*
 * key_provider.h — Key Management Foundation (Section 03, Step 08).
 *
 * Establishes the key management architecture for OZAYN's Secure Data Layer.
 * Provides key identification, metadata, lifecycle states, purpose validation,
 * and version handling.
 *
 * The protection layer accesses keys ONLY through this abstraction.
 * The protection layer must not know where keys originate.
 *
 * Architecture:
 *   ProtectionProvider -> KeyProvider -> KeyMaterial
 *
 * Step 08 scope:
 *   - Key identifier, metadata, lifecycle, purpose, version
 *   - Key provider abstraction (extended from Step 07)
 *   - Key validation and purpose enforcement
 *   - Test key provider
 *
 * NOT in scope:
 *   - Production secure key storage
 *   - Key rotation, recovery
 *   - Vault, authentication, permissions
 */

#define OZAYN_KEY_MAX_SIZE      64
#define OZAYN_KEY_MAX_ID_LEN    64
#define OZAYN_KEY_MAX_NAME_LEN  64

/* ============================================================
 * KEY IDENTIFIER
 * ============================================================ */

typedef struct {
    char     name[OZAYN_KEY_MAX_NAME_LEN]; /* Key name (e.g. "OZAYN-DATA-PRIMARY") */
    uint32_t version;                       /* Key version (1, 2, 3, ...) */
    char     context[32];                   /* Optional context (e.g. "production", "test") */
} ozayn_key_id_t;

/* Check if two key identifiers match */
int ozayn_key_id_equal(const ozayn_key_id_t *a, const ozayn_key_id_t *b);

/* Set a key identifier */
void ozayn_key_id_set(ozayn_key_id_t *id, const char *name, uint32_t version,
                       const char *context);

/* ============================================================
 * KEY PURPOSE
 * ============================================================ */

typedef enum {
    OZAYN_KEY_PURPOSE_UNKNOWN           = 0,
    OZAYN_KEY_PURPOSE_DATA_ENCRYPTION   = 1,
    OZAYN_KEY_PURPOSE_DATA_DECRYPTION   = 2,
    OZAYN_KEY_PURPOSE_AUTH_ENCRYPTION   = 3,  /* Future: authenticated encryption */
    OZAYN_KEY_PURPOSE_AUTH_DECRYPTION   = 4   /* Future: authenticated decryption */
} ozayn_key_purpose_t;

const char *ozayn_key_purpose_name(ozayn_key_purpose_t purpose);

/* ============================================================
 * KEY LIFECYCLE STATE
 * ============================================================ */

typedef enum {
    OZAYN_KEY_LIFECYCLE_UNINITIALIZED = 0,
    OZAYN_KEY_LIFECYCLE_AVAILABLE     = 1,  /* Key generated/stored, not yet active */
    OZAYN_KEY_LIFECYCLE_ACTIVE        = 2,  /* Key is in use */
    OZAYN_KEY_LIFECYCLE_RETIRED       = 3,  /* Key retired from new use, may decrypt old data */
    OZAYN_KEY_LIFECYCLE_REVOKED       = 4,  /* Key revoked, must not be used */
    OZAYN_KEY_LIFECYCLE_INVALID       = 5   /* Key is invalid/corrupt */
} ozayn_key_lifecycle_t;

const char *ozayn_key_lifecycle_name(ozayn_key_lifecycle_t state);

/* Valid lifecycle transitions */
int ozayn_key_lifecycle_transition_valid(ozayn_key_lifecycle_t from,
                                          ozayn_key_lifecycle_t to);

/* ============================================================
 * KEY METADATA
 * ============================================================ */

typedef struct {
    ozayn_key_id_t        id;              /* Key identifier */
    ozayn_key_lifecycle_t  lifecycle;       /* Current lifecycle state */
    ozayn_key_purpose_t   purpose;         /* Key purpose */
    uint32_t              key_length;      /* Key length in bytes */
    uint8_t               algorithm;       /* Algorithm identifier */
    time_t                created_at;      /* Creation timestamp */
    time_t                activated_at;    /* Activation timestamp */
    time_t                retired_at;      /* Retirement timestamp */
    int                   is_valid;        /* 1 if metadata is populated */
} ozayn_key_metadata_t;

/* ============================================================
 * KEY PROVIDER ERROR CODES (extended)
 * ============================================================ */

typedef enum {
    OZAYN_KEY_OK                       =  0,
    OZAYN_KEY_ERR_NULL                 = -1,
    OZAYN_KEY_ERR_UNAVAILABLE          = -2,
    OZAYN_KEY_ERR_INVALID_SIZE         = -3,
    OZAYN_KEY_ERR_NOT_INITIALIZED      = -4,
    OZAYN_KEY_ERR_NOT_FOUND            = -5,
    OZAYN_KEY_ERR_INVALID_KEY          = -6,
    OZAYN_KEY_ERR_PURPOSE_MISMATCH     = -7,
    OZAYN_KEY_ERR_VERSION_UNSUPPORTED  = -8,
    OZAYN_KEY_ERR_REVOKED              = -9,
    OZAYN_KEY_ERR_RETIRED              = -10,
    OZAYN_KEY_ERR_LIFECYCLE_INVALID    = -11,
    OZAYN_KEY_ERR_ACCESS_DENIED        = -12
} ozayn_key_result_t;

/* ============================================================
 * KEY PROVIDER STATE (provider-level, not key-level)
 * ============================================================ */

typedef enum {
    OZAYN_KEY_STATE_UNINITIALIZED = 0,
    OZAYN_KEY_STATE_INITIALIZED   = 1,
    OZAYN_KEY_STATE_READY         = 2,
    OZAYN_KEY_STATE_STOPPED       = 3
} ozayn_key_state_t;

/* ============================================================
 * KEY PROVIDER INTERFACE (vtable, extended from Step 07)
 * ============================================================ */

typedef struct ozayn_key_provider ozayn_key_provider_t;

typedef struct {
    /* Lifecycle */
    ozayn_key_result_t (*init)(ozayn_key_provider_t *provider);
    void               (*shutdown)(ozayn_key_provider_t *provider);

    /* Basic key access (Step 07 compatible) */
    ozayn_key_result_t (*get_key)(ozayn_key_provider_t *provider,
                                   uint8_t *key_out, size_t key_size);

    /* Extended key access (Step 08) */
    ozayn_key_result_t (*get_key_by_id)(ozayn_key_provider_t *provider,
                                         const ozayn_key_id_t *id,
                                         ozayn_key_purpose_t purpose,
                                         uint8_t *key_out, size_t key_size);

    /* Metadata */
    ozayn_key_result_t (*get_metadata)(ozayn_key_provider_t *provider,
                                        const ozayn_key_id_t *id,
                                        ozayn_key_metadata_t *out_metadata);

    /* Lifecycle management */
    ozayn_key_result_t (*transition)(ozayn_key_provider_t *provider,
                                      const ozayn_key_id_t *id,
                                      ozayn_key_lifecycle_t target);

    /* Query */
    int                (*is_available)(const ozayn_key_provider_t *provider);
    size_t             (*key_length)(const ozayn_key_provider_t *provider);
    int                (*key_count)(const ozayn_key_provider_t *provider);
} ozayn_key_ops_t;

/* ============================================================
 * KEY PROVIDER
 * ============================================================ */

struct ozayn_key_provider {
    const char              *name;
    ozayn_key_state_t        state;
    const ozayn_key_ops_t   *ops;
    void                    *impl_data;
};

/* ============================================================
 * LIFECYCLE
 * ============================================================ */

ozayn_key_result_t ozayn_key_init(ozayn_key_provider_t *provider);
void ozayn_key_shutdown(ozayn_key_provider_t *provider);
int  ozayn_key_is_ready(const ozayn_key_provider_t *provider);

/* ============================================================
 * BASIC KEY ACCESS (Step 07 compatible)
 * ============================================================ */

ozayn_key_result_t ozayn_key_get(ozayn_key_provider_t *provider,
                                   uint8_t *key_out, size_t key_size);
int  ozayn_key_is_available(const ozayn_key_provider_t *provider);
size_t ozayn_key_length(const ozayn_key_provider_t *provider);

/* ============================================================
 * EXTENDED KEY ACCESS (Step 08)
 * ============================================================ */

ozayn_key_result_t ozayn_key_get_by_id(ozayn_key_provider_t *provider,
                                         const ozayn_key_id_t *id,
                                         ozayn_key_purpose_t purpose,
                                         uint8_t *key_out, size_t key_size);

ozayn_key_result_t ozayn_key_get_metadata(ozayn_key_provider_t *provider,
                                            const ozayn_key_id_t *id,
                                            ozayn_key_metadata_t *out_metadata);

ozayn_key_result_t ozayn_key_transition(ozayn_key_provider_t *provider,
                                          const ozayn_key_id_t *id,
                                          ozayn_key_lifecycle_t target);

int ozayn_key_count(const ozayn_key_provider_t *provider);

/* ============================================================
 * NAME HELPERS
 * ============================================================ */

const char *ozayn_key_result_name(ozayn_key_result_t result);

#endif
