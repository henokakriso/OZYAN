#include "protection_provider_mock.h"
#include <string.h>

/*
 * protection_provider_mock.c — Test-Only Protection Provider (Section 03, Step 06).
 *
 * Deterministic mock for testing protection architecture. Uses XOR-based
 * "encryption" with a fixed key. NOT cryptographically secure.
 * Production encryption must use a vetted cryptographic library.
 */

/* Fixed key for mock operations — DO NOT use in production */
static const uint8_t _mock_key[OZAYN_PROT_MOCK_KEY_SIZE] = {
    0x4F, 0x5A, 0x59, 0x4E, 0x2D, 0x4D, 0x4F, 0x43,
    0x4B, 0x2D, 0x4B, 0x45, 0x59, 0x2D, 0x44, 0x4F,
    0x20, 0x4E, 0x4F, 0x54, 0x20, 0x55, 0x53, 0x45,
    0x20, 0x49, 0x4E, 0x20, 0x50, 0x52, 0x4F, 0x44
};

/* Mock implementation data */
typedef struct {
    ozayn_prot_mock_config_t *config;
    int                       protection_count;
    int                       unprotection_count;
} _mock_impl_t;

static _mock_impl_t _mock_data;

/* Simple XOR-based transform (NOT secure — test only) */
static void _xor_transform(const uint8_t *input, size_t len,
                            uint8_t *output, const uint8_t *key, size_t key_len)
{
    for (size_t i = 0; i < len; i++)
        output[i] = input[i] ^ key[i % key_len];
}

/* Compute a simple checksum tag (NOT HMAC — test only) */
static void _compute_tag(const uint8_t *ciphertext, size_t ciphertext_len,
                          const uint8_t *associated, size_t associated_len,
                          uint8_t tag_out[OZAYN_PROT_MOCK_TAG_SIZE])
{
    uint64_t sum = 0x4F5A594EULL;  /* "OZAYN" seed */
    for (size_t i = 0; i < ciphertext_len; i++)
        sum = (sum << 3) ^ ciphertext[i] ^ (sum >> 5);
    for (size_t i = 0; i < associated_len; i++)
        sum = (sum << 7) ^ associated[i] ^ (sum >> 3);
    memcpy(tag_out, &sum, OZAYN_PROT_MOCK_TAG_SIZE);
}

/* ---- Mock Lifecycle ---- */
static ozayn_prot_result_t _mock_init(ozayn_protection_provider_t *provider)
{
    (void)provider;
    _mock_data.protection_count = 0;
    _mock_data.unprotection_count = 0;
    return OZAYN_PROT_OK;
}

static void _mock_shutdown(ozayn_protection_provider_t *provider)
{
    (void)provider;
    memset(&_mock_data, 0, sizeof(_mock_data));
}

/* ---- Mock Protect ---- */
static ozayn_prot_result_t _mock_protect(ozayn_protection_provider_t *provider,
                                           const ozayn_prot_request_t *request,
                                           ozayn_protected_data_t *out)
{
    (void)provider;
    _mock_impl_t *impl = &_mock_data;

    if (impl->config && impl->config->fail_protect)
        return OZAYN_PROT_ERR_PROTECTION_FAILED;

    if (request->plaintext_len > OZAYN_PROT_MAX_CIPHERTEXT_SIZE)
        return OZAYN_PROT_ERR_INVALID_REQUEST;

    memset(out, 0, sizeof(*out));
    out->format_version = OZAYN_PROT_CURRENT_VERSION;
    out->algorithm = OZAYN_PROT_ALG_AES_256_GCM;
    out->nonce_len = 12;
    out->tag_len = OZAYN_PROT_MOCK_TAG_SIZE;

    /* Fixed nonce for testing (production must generate unique nonces) */
    const uint8_t fixed_nonce[12] = {0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0A,0x0B,0x0C};
    memcpy(out->nonce, fixed_nonce, 12);

    /* Copy associated data */
    if (request->associated && request->associated_len > 0) {
        size_t copy_len = request->associated_len;
        if (copy_len > OZAYN_PROT_MAX_ASSOCIATED_SIZE)
            copy_len = OZAYN_PROT_MAX_ASSOCIATED_SIZE;
        memcpy(out->associated, request->associated, copy_len);
        out->associated_len = (uint16_t)copy_len;
    }

    /* XOR "encrypt" the plaintext */
    _xor_transform(request->plaintext, request->plaintext_len,
                    out->ciphertext, _mock_key, OZAYN_PROT_MOCK_KEY_SIZE);
    out->ciphertext_len = (uint32_t)request->plaintext_len;

    /* Copy metadata */
    strncpy(out->object_id, request->object_id, sizeof(out->object_id) - 1);
    out->data_category = (uint8_t)request->category;
    out->data_classification = (uint8_t)request->classification;

    /* Compute tag */
    _compute_tag(out->ciphertext, out->ciphertext_len,
                  out->associated, out->associated_len, out->tag);

    if (impl->config && impl->config->inject_tag_error) {
        out->tag[0] ^= 0xFF;  /* Corrupt tag for testing */
    }

    impl->protection_count++;
    return OZAYN_PROT_OK;
}

/* ---- Mock Unprotect ---- */
static ozayn_prot_result_t _mock_unprotect(ozayn_protection_provider_t *provider,
                                             const ozayn_protected_data_t *protected_data,
                                             ozayn_unprot_result_t *out)
{
    (void)provider;
    _mock_impl_t *impl = &_mock_data;

    if (impl->config && impl->config->fail_unprotect)
        return OZAYN_PROT_ERR_UNPROTECTION_FAILED;

    if (protected_data->algorithm == OZAYN_PROT_ALG_NONE)
        return OZAYN_PROT_ERR_UNSUPPORTED_FORMAT;

    if (protected_data->format_version != OZAYN_PROT_CURRENT_VERSION)
        return OZAYN_PROT_ERR_UNSUPPORTED_VERSION;

    /* Verify tag if configured */
    if (impl->config && impl->config->require_auth_check) {
        uint8_t expected_tag[OZAYN_PROT_MOCK_TAG_SIZE];
        _compute_tag(protected_data->ciphertext, protected_data->ciphertext_len,
                      protected_data->associated, protected_data->associated_len,
                      expected_tag);
        if (memcmp(protected_data->tag, expected_tag, OZAYN_PROT_MOCK_TAG_SIZE) != 0)
            return OZAYN_PROT_ERR_AUTH_FAILED;
    }

    if (protected_data->ciphertext_len == 0)
        return OZAYN_PROT_ERR_INVALID_PROTECTED;

    /* XOR "decrypt" */
    static uint8_t _recovered[OZAYN_PROT_MAX_CIPHERTEXT_SIZE];
    _xor_transform(protected_data->ciphertext, protected_data->ciphertext_len,
                    _recovered, _mock_key, OZAYN_PROT_MOCK_KEY_SIZE);

    out->result = OZAYN_PROT_OK;
    out->plaintext = _recovered;
    out->plaintext_len = protected_data->ciphertext_len;
    out->category = (ozayn_data_category_t)protected_data->data_category;
    out->classification = (ozayn_security_level_t)protected_data->data_classification;

    impl->unprotection_count++;
    return OZAYN_PROT_OK;
}

/* ---- Mock Query ---- */
static int _mock_is_available(const ozayn_protection_provider_t *provider)
{
    (void)provider;
    return 1;
}

static const char *_mock_algorithm_name(const ozayn_protection_provider_t *provider)
{
    (void)provider;
    return "aes-256-gcm (mock)";
}

/* ---- Mock Ops Table ---- */
static const ozayn_prot_ops_t _mock_ops = {
    .init          = _mock_init,
    .shutdown      = _mock_shutdown,
    .protect       = _mock_protect,
    .unprotect     = _mock_unprotect,
    .is_available  = _mock_is_available,
    .algorithm_name = _mock_algorithm_name
};

/* ---- Public API ---- */
void ozayn_prot_mock_create(ozayn_protection_provider_t *provider,
                             ozayn_prot_mock_config_t *config)
{
    if (!provider)
        return;
    memset(provider, 0, sizeof(*provider));
    provider->name = "mock-protection-provider";
    provider->state = OZAYN_PROT_STATE_UNINITIALIZED;
    provider->ops = &_mock_ops;
    provider->impl_data = &_mock_data;

    memset(&_mock_data, 0, sizeof(_mock_data));
    _mock_data.config = config;
}

const ozayn_prot_ops_t *ozayn_prot_mock_get_ops(void)
{
    return &_mock_ops;
}

int ozayn_prot_mock_verify_tag(const ozayn_protected_data_t *pd)
{
    if (!pd)
        return 0;
    uint8_t expected_tag[OZAYN_PROT_MOCK_TAG_SIZE];
    _compute_tag(pd->ciphertext, pd->ciphertext_len,
                  pd->associated, pd->associated_len, expected_tag);
    return memcmp(pd->tag, expected_tag, OZAYN_PROT_MOCK_TAG_SIZE) == 0;
}
