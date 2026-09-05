#include "protection_provider_sodium.h"
#include <sodium.h>
#include <string.h>

/*
 * protection_provider_sodium.c — Production Protection Provider (Section 03, Step 07).
 *
 * Uses libsodium's crypto_aead_aes256gcm for authenticated encryption.
 * Falls back to crypto_aead_xchacha20poly1305_ietf if AES-NI is not available.
 *
 * Key requirements:
 *   - 32 bytes for AES-256-GCM
 *   - 32 bytes for XChaCha20-Poly1305
 *
 * Nonce: fresh random per encryption, stored in ProtectedData.
 * Tag: stored in ProtectedData, verified before decryption.
 */

typedef struct {
    ozayn_key_provider_t *key_provider;
    int                   use_aes_gcm;  /* 1 = AES-256-GCM, 0 = XChaCha20-Poly1305 */
} _sodium_impl_t;

static _sodium_impl_t _sodium_data;

/* ---- Init ---- */
static ozayn_prot_result_t _sodium_init(ozayn_protection_provider_t *provider)
{
    (void)provider;
    if (sodium_init() < 0)
        return OZAYN_PROT_ERR_UNAVAILABLE;

    _sodium_impl_t *impl = &_sodium_data;

    /* Check if AES-256-GCM is available (requires AES-NI) */
    impl->use_aes_gcm = crypto_aead_aes256gcm_is_available();

    return OZAYN_PROT_OK;
}

static void _sodium_shutdown(ozayn_protection_provider_t *provider)
{
    (void)provider;
    memset(&_sodium_data, 0, sizeof(_sodium_data));
}

/* ---- Build AAD from request metadata ---- */
static void _build_aad(const ozayn_prot_request_t *request,
                        uint8_t *aad_out, size_t *aad_len_out)
{
    size_t pos = 0;

    /* Format version (1 byte) */
    aad_out[pos++] = OZAYN_PROT_CURRENT_VERSION;

    /* Algorithm (1 byte) */
    if (_sodium_data.use_aes_gcm)
        aad_out[pos++] = OZAYN_PROT_ALG_AES_256_GCM;
    else
        aad_out[pos++] = OZAYN_PROT_ALG_CHACHA20_POLY1305;

    /* Category (1 byte) */
    aad_out[pos++] = (uint8_t)request->category;

    /* Classification (1 byte) */
    aad_out[pos++] = (uint8_t)request->classification;

    /* Object ID length + data (up to 63 bytes) */
    size_t id_len = strlen(request->object_id);
    if (id_len > 63) id_len = 63;
    aad_out[pos++] = (uint8_t)id_len;
    memcpy(&aad_out[pos], request->object_id, id_len);
    pos += id_len;

    /* User-provided associated data */
    if (request->associated && request->associated_len > 0) {
        size_t copy_len = request->associated_len;
        if (copy_len > OZAYN_PROT_MAX_ASSOCIATED_SIZE - pos)
            copy_len = OZAYN_PROT_MAX_ASSOCIATED_SIZE - pos;
        memcpy(&aad_out[pos], request->associated, copy_len);
        pos += copy_len;
    }

    *aad_len_out = pos;
}

/* ---- Build AAD from protected data (for decryption verification) ---- */
static void _build_aad_from_protected(const ozayn_protected_data_t *pd,
                                       uint8_t *aad_out, size_t *aad_len_out)
{
    size_t pos = 0;

    aad_out[pos++] = pd->format_version;
    aad_out[pos++] = pd->algorithm;
    aad_out[pos++] = pd->data_category;
    aad_out[pos++] = pd->data_classification;

    size_t id_len = strlen(pd->object_id);
    if (id_len > 63) id_len = 63;
    aad_out[pos++] = (uint8_t)id_len;
    memcpy(&aad_out[pos], pd->object_id, id_len);
    pos += id_len;

    if (pd->associated_len > 0) {
        size_t copy_len = pd->associated_len;
        if (copy_len > OZAYN_PROT_MAX_ASSOCIATED_SIZE - pos)
            copy_len = OZAYN_PROT_MAX_ASSOCIATED_SIZE - pos;
        memcpy(&aad_out[pos], pd->associated, copy_len);
        pos += copy_len;
    }

    *aad_len_out = pos;
}

/* ---- Protect (Encrypt) ---- */
static ozayn_prot_result_t _sodium_protect(ozayn_protection_provider_t *provider,
                                             const ozayn_prot_request_t *request,
                                             ozayn_protected_data_t *out)
{
    (void)provider;
    _sodium_impl_t *impl = &_sodium_data;

    if (!impl->key_provider || !ozayn_key_is_ready(impl->key_provider))
        return OZAYN_PROT_ERR_UNAVAILABLE;

    /* Get key */
    uint8_t key[OZAYN_KEY_MAX_SIZE];
    size_t key_len = ozayn_key_length(impl->key_provider);
    if (key_len != OZAYN_PROT_SODIUM_KEY_SIZE)
        return OZAYN_PROT_ERR_INVALID_REQUEST;

    if (ozayn_key_get(impl->key_provider, key, key_len) != OZAYN_KEY_OK)
        return OZAYN_PROT_ERR_UNAVAILABLE;

    /* Clear key on stack when done (best effort) */
    memset(out, 0, sizeof(*out));
    out->format_version = OZAYN_PROT_CURRENT_VERSION;
    out->data_category = (uint8_t)request->category;
    out->data_classification = (uint8_t)request->classification;
    strncpy(out->object_id, request->object_id, sizeof(out->object_id) - 1);

    /* Copy associated data */
    if (request->associated && request->associated_len > 0) {
        size_t copy_len = request->associated_len;
        if (copy_len > OZAYN_PROT_MAX_ASSOCIATED_SIZE)
            copy_len = OZAYN_PROT_MAX_ASSOCIATED_SIZE;
        memcpy(out->associated, request->associated, copy_len);
        out->associated_len = (uint16_t)copy_len;
    }

    /* Build AAD */
    uint8_t aad[OZAYN_PROT_MAX_ASSOCIATED_SIZE];
    size_t aad_len = 0;
    _build_aad(request, aad, &aad_len);

    if (impl->use_aes_gcm) {
        out->algorithm = OZAYN_PROT_ALG_AES_256_GCM;
        out->nonce_len = crypto_aead_aes256gcm_NPUBBYTES;  /* 12 */
        out->tag_len = crypto_aead_aes256gcm_ABYTES;       /* 16 */

        /* Generate random nonce */
        randombytes_buf(out->nonce, out->nonce_len);

        /* Encrypt with authentication */
        unsigned long long ciphertext_len = 0;
        if (crypto_aead_aes256gcm_encrypt(
                out->ciphertext, &ciphertext_len,
                request->plaintext, request->plaintext_len,
                aad, aad_len,
                NULL,  /* nsec (unused) */
                out->nonce, key) != 0)
        {
            sodium_memzero(key, sizeof(key));
            return OZAYN_PROT_ERR_PROTECTION_FAILED;
        }
        out->ciphertext_len = (uint32_t)ciphertext_len;
    } else {
        out->algorithm = OZAYN_PROT_ALG_CHACHA20_POLY1305;
        out->nonce_len = crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;  /* 24 */
        out->tag_len = crypto_aead_xchacha20poly1305_ietf_ABYTES;       /* 16 */

        randombytes_buf(out->nonce, out->nonce_len);

        unsigned long long ciphertext_len = 0;
        if (crypto_aead_xchacha20poly1305_ietf_encrypt(
                out->ciphertext, &ciphertext_len,
                request->plaintext, request->plaintext_len,
                aad, aad_len,
                NULL,
                out->nonce, key) != 0)
        {
            sodium_memzero(key, sizeof(key));
            return OZAYN_PROT_ERR_PROTECTION_FAILED;
        }
        out->ciphertext_len = (uint32_t)ciphertext_len;
    }

    /* The tag is appended to ciphertext by libsodium — extract it.
     * For AES-256-GCM: ciphertext || tag (16 bytes) */
    if (impl->use_aes_gcm) {
        /* libsodium appends tag after ciphertext */
        if (out->ciphertext_len >= OZAYN_PROT_SODIUM_TAG_SIZE) {
            out->ciphertext_len -= OZAYN_PROT_SODIUM_TAG_SIZE;
            memcpy(out->tag,
                   &out->ciphertext[out->ciphertext_len],
                   OZAYN_PROT_SODIUM_TAG_SIZE);
        }
    } else {
        if (out->ciphertext_len >= OZAYN_PROT_SODIUM_TAG_SIZE) {
            out->ciphertext_len -= OZAYN_PROT_SODIUM_TAG_SIZE;
            memcpy(out->tag,
                   &out->ciphertext[out->ciphertext_len],
                   OZAYN_PROT_SODIUM_TAG_SIZE);
        }
    }

    sodium_memzero(key, sizeof(key));
    return OZAYN_PROT_OK;
}

/* ---- Unprotect (Decrypt) ---- */
static ozayn_prot_result_t _sodium_unprotect(ozayn_protection_provider_t *provider,
                                               const ozayn_protected_data_t *pd,
                                               ozayn_unprot_result_t *out)
{
    (void)provider;
    _sodium_impl_t *impl = &_sodium_data;

    /* Validate format before attempting decryption */
    if (pd->format_version != OZAYN_PROT_CURRENT_VERSION)
        return OZAYN_PROT_ERR_UNSUPPORTED_VERSION;
    if (pd->algorithm == OZAYN_PROT_ALG_NONE)
        return OZAYN_PROT_ERR_UNSUPPORTED_FORMAT;
    if (pd->algorithm != OZAYN_PROT_ALG_AES_256_GCM &&
        pd->algorithm != OZAYN_PROT_ALG_CHACHA20_POLY1305)
        return OZAYN_PROT_ERR_UNSUPPORTED_FORMAT;

    if (!impl->key_provider || !ozayn_key_is_ready(impl->key_provider))
        return OZAYN_PROT_ERR_UNAVAILABLE;

    /* Get key */
    uint8_t key[OZAYN_KEY_MAX_SIZE];
    size_t key_len = ozayn_key_length(impl->key_provider);
    if (key_len != OZAYN_PROT_SODIUM_KEY_SIZE)
        return OZAYN_PROT_ERR_INVALID_REQUEST;

    if (ozayn_key_get(impl->key_provider, key, key_len) != OZAYN_KEY_OK)
        return OZAYN_PROT_ERR_UNAVAILABLE;

    /* Build AAD for verification */
    uint8_t aad[OZAYN_PROT_MAX_ASSOCIATED_SIZE];
    size_t aad_len = 0;
    _build_aad_from_protected(pd, aad, &aad_len);

    /* Reconstruct ciphertext + tag for libsodium verification */
    uint8_t combined[OZAYN_PROT_MAX_CIPHERTEXT_SIZE + OZAYN_PROT_MAX_TAG_SIZE];
    size_t combined_len = pd->ciphertext_len + pd->tag_len;
    if (combined_len > sizeof(combined)) {
        sodium_memzero(key, sizeof(key));
        return OZAYN_PROT_ERR_INVALID_PROTECTED;
    }
    memcpy(combined, pd->ciphertext, pd->ciphertext_len);
    memcpy(&combined[pd->ciphertext_len], pd->tag, pd->tag_len);

    /* Static buffer for decrypted plaintext */
    static uint8_t _decrypted[OZAYN_PROT_MAX_CIPHERTEXT_SIZE];
    memset(out, 0, sizeof(*out));

    if (pd->algorithm == OZAYN_PROT_ALG_AES_256_GCM) {
        unsigned long long plaintext_len = 0;
        if (crypto_aead_aes256gcm_decrypt(
                _decrypted, &plaintext_len,
                NULL,  /* nsec (unused) */
                combined, combined_len,
                aad, aad_len,
                pd->nonce, key) != 0)
        {
            sodium_memzero(key, sizeof(key));
            return OZAYN_PROT_ERR_AUTH_FAILED;
        }
        out->result = OZAYN_PROT_OK;
        out->plaintext = _decrypted;
        out->plaintext_len = (size_t)plaintext_len;
    } else if (pd->algorithm == OZAYN_PROT_ALG_CHACHA20_POLY1305) {
        unsigned long long plaintext_len = 0;
        if (crypto_aead_xchacha20poly1305_ietf_decrypt(
                _decrypted, &plaintext_len,
                NULL,
                combined, combined_len,
                aad, aad_len,
                pd->nonce, key) != 0)
        {
            sodium_memzero(key, sizeof(key));
            return OZAYN_PROT_ERR_AUTH_FAILED;
        }
        out->result = OZAYN_PROT_OK;
        out->plaintext = _decrypted;
        out->plaintext_len = (size_t)plaintext_len;
    } else {
        sodium_memzero(key, sizeof(key));
        return OZAYN_PROT_ERR_UNSUPPORTED_FORMAT;
    }

    out->category = (ozayn_data_category_t)pd->data_category;
    out->classification = (ozayn_security_level_t)pd->data_classification;

    sodium_memzero(key, sizeof(key));
    return OZAYN_PROT_OK;
}

/* ---- Query ---- */
static int _sodium_is_available(const ozayn_protection_provider_t *provider)
{
    (void)provider;
    return sodium_init() >= 0;
}

static const char *_sodium_algorithm_name(const ozayn_protection_provider_t *provider)
{
    (void)provider;
    if (_sodium_data.use_aes_gcm)
        return "AES-256-GCM (libsodium)";
    return "XChaCha20-Poly1305 (libsodium)";
}

/* ---- Ops Table ---- */
static const ozayn_prot_ops_t _sodium_ops = {
    .init          = _sodium_init,
    .shutdown      = _sodium_shutdown,
    .protect       = _sodium_protect,
    .unprotect     = _sodium_unprotect,
    .is_available  = _sodium_is_available,
    .algorithm_name = _sodium_algorithm_name
};

/* ---- Public API ---- */
void ozayn_prot_sodium_create(ozayn_protection_provider_t *provider,
                               ozayn_key_provider_t *key_provider)
{
    if (!provider)
        return;
    memset(provider, 0, sizeof(*provider));
    provider->name = "sodium-protection-provider";
    provider->state = OZAYN_PROT_STATE_UNINITIALIZED;
    provider->ops = &_sodium_ops;
    provider->impl_data = &_sodium_data;

    memset(&_sodium_data, 0, sizeof(_sodium_data));
    _sodium_data.key_provider = key_provider;
}
