#ifndef OZAYN_PROTECTION_PROVIDER_H
#define OZAYN_PROTECTION_PROVIDER_H

#include "secure_data_object.h"
#include <stdint.h>
#include <stddef.h>

/*
 * protection_provider.h — Encryption Architecture & Protection Boundary
 *                          (Section 03, Step 06).
 *
 * Establishes the encryption/protection architecture that separates data
 * logic from cryptographic protection logic. This is an ARCHITECTURE step —
 * it defines contracts and interfaces, not production cryptographic algorithms.
 *
 * Architecture:
 *
 *   SECURE DATA OBJECT
 *          |
 *          v
 *   VALIDATION
 *          |
 *          v
 *   PROTECTION BOUNDARY  <-- this layer
 *          |
 *          v
 *   STORAGE ABSTRACTION
 *          |
 *          v
 *   PERSISTENT STORAGE
 *
 * IMPORTANT:
 *   - This step does NOT implement production encryption
 *   - This step does NOT implement key management
 *   - This step does NOT store encryption keys
 *   - This step establishes the ARCHITECTURE for future encryption
 */

/* ---- Protection Error Codes ---- */
typedef enum {
    OZAYN_PROT_OK                       =   0,
    OZAYN_PROT_ERR_NULL                 =  -1,
    OZAYN_PROT_ERR_NOT_INITIALIZED      =  -2,
    OZAYN_PROT_ERR_INVALID_REQUEST      =  -3,
    OZAYN_PROT_ERR_INVALID_DATA         =  -4,
    OZAYN_PROT_ERR_PROTECTION_FAILED    =  -5,
    OZAYN_PROT_ERR_UNPROTECTION_FAILED  =  -6,
    OZAYN_PROT_ERR_AUTH_FAILED          =  -7,
    OZAYN_PROT_ERR_UNSUPPORTED_FORMAT   =  -8,
    OZAYN_PROT_ERR_UNSUPPORTED_VERSION  =  -9,
    OZAYN_PROT_ERR_INTEGRITY            = -10,
    OZAYN_PROT_ERR_UNAVAILABLE          = -11,
    OZAYN_PROT_ERR_INVALID_PROTECTED    = -12
} ozayn_prot_result_t;

/* ---- Protection Algorithm Identifiers ---- */
typedef enum {
    OZAYN_PROT_ALG_NONE         = 0,
    OZAYN_PROT_ALG_AES_256_GCM  = 1,  /* Future: AES-256-GCM */
    OZAYN_PROT_ALG_CHACHA20_POLY1305 = 2  /* Future: ChaCha20-Poly1305 */
} ozayn_prot_algorithm_t;

/* ---- Protection Format Version ---- */
#define OZAYN_PROT_FORMAT_VERSION_1  1
#define OZAYN_PROT_CURRENT_VERSION   OZAYN_PROT_FORMAT_VERSION_1

/* ---- Constants ---- */
#define OZAYN_PROT_MAX_CIPHERTEXT_SIZE  (1024 * 1024)  /* 1 MB max */
#define OZAYN_PROT_MAX_NONCE_SIZE       32
#define OZAYN_PROT_MAX_TAG_SIZE         32
#define OZAYN_PROT_MAX_ASSOCIATED_SIZE  256

/* ---- Protected Data Representation ---- */
typedef struct {
    uint8_t   format_version;                    /* Format version */
    uint8_t   algorithm;                         /* ozayn_prot_algorithm_t */
    uint8_t   nonce_len;                         /* Nonce/IV length */
    uint8_t   tag_len;                           /* Authentication tag length */
    uint16_t  associated_len;                    /* Associated data length */
    uint32_t  ciphertext_len;                    /* Ciphertext length */

    uint8_t   nonce[OZAYN_PROT_MAX_NONCE_SIZE];       /* Nonce/IV (not a key) */
    uint8_t   tag[OZAYN_PROT_MAX_TAG_SIZE];            /* Authentication tag */
    uint8_t   associated[OZAYN_PROT_MAX_ASSOCIATED_SIZE]; /* Associated data */
    uint8_t   ciphertext[OZAYN_PROT_MAX_CIPHERTEXT_SIZE]; /* Encrypted payload */

    /* Non-secret metadata (may be stored in plaintext) */
    char      object_id[64];                     /* Object identifier */
    uint8_t   data_category;                     /* Data category */
    uint8_t   data_classification;               /* Security classification */
} ozayn_protected_data_t;

/* ---- Protection Request ---- */
typedef struct {
    const uint8_t              *plaintext;       /* Input data */
    size_t                      plaintext_len;   /* Input length */
    ozayn_data_category_t       category;        /* Data category */
    ozayn_security_level_t      classification;  /* Security classification */
    const char                 *object_id;       /* Object identifier (for AAD) */
    const uint8_t              *associated;      /* Optional associated data */
    size_t                      associated_len;  /* Associated data length */
} ozayn_prot_request_t;

/* ---- Protection Result ---- */
typedef struct {
    ozayn_prot_result_t         result;          /* Operation result */
    ozayn_protected_data_t      protected_data;  /* Protected output (on success) */
} ozayn_prot_result_data_t;

/* ---- Unprotection Request ---- */
typedef struct {
    const ozayn_protected_data_t *protected_data; /* Input protected data */
} ozayn_unprot_request_t;

/* ---- Unprotection Result ---- */
typedef struct {
    ozayn_prot_result_t         result;          /* Operation result */
    const uint8_t              *plaintext;       /* Recovered plaintext (on success) */
    size_t                      plaintext_len;   /* Recovered length */
    ozayn_data_category_t       category;        /* Data category (from metadata) */
    ozayn_security_level_t      classification;  /* Classification (from metadata) */
} ozayn_unprot_result_t;

/* ---- Protection Provider State ---- */
typedef enum {
    OZAYN_PROT_STATE_UNINITIALIZED = 0,
    OZAYN_PROT_STATE_INITIALIZED   = 1,
    OZAYN_PROT_STATE_READY         = 2,
    OZAYN_PROT_STATE_SHUTTING_DOWN = 3,
    OZAYN_PROT_STATE_STOPPED       = 4
} ozayn_prot_state_t;

/* ---- Protection Provider Interface (vtable) ---- */
typedef struct ozayn_protection_provider ozayn_protection_provider_t;

typedef struct {
    /* Lifecycle */
    ozayn_prot_result_t (*init)(ozayn_protection_provider_t *provider);
    void                (*shutdown)(ozayn_protection_provider_t *provider);

    /* Operations */
    ozayn_prot_result_t (*protect)(ozayn_protection_provider_t *provider,
                                    const ozayn_prot_request_t *request,
                                    ozayn_protected_data_t *out_protected);

    ozayn_prot_result_t (*unprotect)(ozayn_protection_provider_t *provider,
                                      const ozayn_protected_data_t *protected_data,
                                      ozayn_unprot_result_t *out_result);

    /* Query */
    int (*is_available)(const ozayn_protection_provider_t *provider);
    const char *(*algorithm_name)(const ozayn_protection_provider_t *provider);
} ozayn_prot_ops_t;

/* ---- Protection Provider ---- */
struct ozayn_protection_provider {
    const char                 *name;
    ozayn_prot_state_t          state;
    const ozayn_prot_ops_t     *ops;
    void                       *impl_data;
};

/* ---- Provider Lifecycle ---- */
ozayn_prot_result_t ozayn_prot_init(ozayn_protection_provider_t *provider);
void ozayn_prot_shutdown(ozayn_protection_provider_t *provider);
int  ozayn_prot_is_ready(const ozayn_protection_provider_t *provider);

/* ---- Provider Operations (dispatch through vtable) ---- */
ozayn_prot_result_t ozayn_prot_protect(ozayn_protection_provider_t *provider,
                                         const ozayn_prot_request_t *request,
                                         ozayn_protected_data_t *out_protected);

ozayn_prot_result_t ozayn_prot_unprotect(ozayn_protection_provider_t *provider,
                                           const ozayn_protected_data_t *protected_data,
                                           ozayn_unprot_result_t *out_result);

int ozayn_prot_is_available(const ozayn_protection_provider_t *provider);
const char *ozayn_prot_algorithm_name(const ozayn_protection_provider_t *provider);

/* ---- Protected Data Validation ---- */
int ozayn_protected_data_validate(const ozayn_protected_data_t *pd);

/* ---- Name Helpers ---- */
const char *ozayn_prot_result_name(ozayn_prot_result_t result);
const char *ozayn_prot_state_name(ozayn_prot_state_t state);
const char *ozayn_prot_algorithm_name_enum(ozayn_prot_algorithm_t alg);

#endif
