#include "../../tests/test_framework.h"
#include "../protection_provider.h"
#include "../protection_provider_sodium.h"
#include "../key_provider.h"
#include "../key_provider_test.h"
#include "../secure_data_object.h"
#include <string.h>

/*
 * test_protection_provider_sodium.c — Step 07 Tests (Section 03, Step 07).
 *
 * Tests the production protection provider using libsodium.
 * Verifies authenticated encryption, key abstraction, tamper detection,
 * wrong key rejection, disk plaintext exposure, and end-to-end pipeline.
 */

/* ---- Test Key (DO NOT use in production) ---- */
static const uint8_t _test_key[OZAYN_PROT_SODIUM_KEY_SIZE] = {
    0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
    0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,0x10,
    0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,
    0x19,0x1A,0x1B,0x1C,0x1D,0x1E,0x1F,0x20
};

static const uint8_t _wrong_key[OZAYN_PROT_SODIUM_KEY_SIZE] = {
    0xFF,0xFE,0xFD,0xFC,0xFB,0xFA,0xF9,0xF8,
    0xF7,0xF6,0xF5,0xF4,0xF3,0xF2,0xF1,0xF0,
    0xEF,0xEE,0xED,0xEC,0xEB,0xEA,0xE9,0xE8,
    0xE7,0xE6,0xE5,0xE4,0xE3,0xE2,0xE1,0xE0
};

static const char _test_data[] = "OZAYN_TEST_SECRET_MARKER This is sensitive data for encryption testing";
static const char _test_id[] = "encryption-test-001";

/* ---- Helper: create valid request ---- */
static ozayn_prot_request_t _valid_request(void)
{
    ozayn_prot_request_t req;
    memset(&req, 0, sizeof(req));
    req.plaintext = (const uint8_t *)_test_data;
    req.plaintext_len = sizeof(_test_data);
    req.category = OZAYN_DATA_CATEGORY_AUTH_INFO;
    req.classification = OZAYN_SEC_LEVEL_HIGHLY_SENSITIVE;
    req.object_id = _test_id;
    return req;
}

/* ---- Helper: create provider with test key ---- */
static ozayn_key_provider_t _key_prov;
static ozayn_protection_provider_t _prot_prov;

static void _setup(void)
{
    ozayn_key_test_create(&_key_prov, _test_key, OZAYN_PROT_SODIUM_KEY_SIZE);
    ozayn_key_init(&_key_prov);
    ozayn_prot_sodium_create(&_prot_prov, &_key_prov);
    ozayn_prot_init(&_prot_prov);
}

static void _teardown(void)
{
    ozayn_prot_shutdown(&_prot_prov);
    ozayn_key_shutdown(&_key_prov);
}

/* ============================================================
 * LIFECYCLE TESTS
 * ============================================================ */

/* 1. init and shutdown */
TEST(sodium_lifecycle)
{
    _setup();
    ASSERT(ozayn_prot_is_ready(&_prot_prov));
    ASSERT(ozayn_prot_is_available(&_prot_prov));
    _teardown();
    return 0;
}

/* 2. null provider */
TEST(sodium_null_provider)
{
    ASSERT_EQ(ozayn_prot_init(NULL), OZAYN_PROT_ERR_NULL);
    ozayn_prot_shutdown(NULL);
    return 0;
}

/* ============================================================
 * ENCRYPTION / DECRYPTION TESTS
 * ============================================================ */

/* 3. valid encrypt */
TEST(sodium_encrypt_valid)
{
    _setup();
    ozayn_prot_request_t req = _valid_request();
    ozayn_protected_data_t pd;
    ASSERT_EQ(ozayn_prot_protect(&_prot_prov, &req, &pd), OZAYN_PROT_OK);
    ASSERT(pd.format_version == OZAYN_PROT_CURRENT_VERSION);
    ASSERT(pd.ciphertext_len > 0);
    ASSERT(pd.nonce_len > 0);
    ASSERT(pd.tag_len > 0);
    _teardown();
    return 0;
}

/* 4. valid decrypt */
TEST(sodium_decrypt_valid)
{
    _setup();
    ozayn_prot_request_t req = _valid_request();
    ozayn_protected_data_t pd;
    ASSERT_EQ(ozayn_prot_protect(&_prot_prov, &req, &pd), OZAYN_PROT_OK);

    ozayn_unprot_result_t result;
    ASSERT_EQ(ozayn_prot_unprotect(&_prot_prov, &pd, &result), OZAYN_PROT_OK);
    ASSERT_EQ(result.plaintext_len, req.plaintext_len);
    ASSERT_EQ(memcmp(result.plaintext, req.plaintext, req.plaintext_len), 0);
    _teardown();
    return 0;
}

/* 5. round-trip */
TEST(sodium_roundtrip)
{
    _setup();
    ozayn_prot_request_t req = _valid_request();
    ozayn_protected_data_t pd;
    ASSERT_EQ(ozayn_prot_protect(&_prot_prov, &req, &pd), OZAYN_PROT_OK);

    ozayn_unprot_result_t result;
    ASSERT_EQ(ozayn_prot_unprotect(&_prot_prov, &pd, &result), OZAYN_PROT_OK);
    ASSERT_EQ(result.plaintext_len, req.plaintext_len);
    ASSERT_EQ(memcmp(result.plaintext, req.plaintext, req.plaintext_len), 0);
    ASSERT_EQ((int)result.category, req.category);
    ASSERT_EQ((int)result.classification, req.classification);
    _teardown();
    return 0;
}

/* 6. ciphertext differs from plaintext */
TEST(sodium_not_plaintext)
{
    _setup();
    ozayn_prot_request_t req = _valid_request();
    ozayn_protected_data_t pd;
    ASSERT_EQ(ozayn_prot_protect(&_prot_prov, &req, &pd), OZAYN_PROT_OK);
    ASSERT(memcmp(pd.ciphertext, req.plaintext, req.plaintext_len) != 0);
    _teardown();
    return 0;
}

/* ============================================================
 * PAYLOAD SIZE TESTS
 * ============================================================ */

/* 7. empty payload (1 byte) */
TEST(sodium_empty_payload)
{
    _setup();
    uint8_t single = 0x42;
    ozayn_prot_request_t req;
    memset(&req, 0, sizeof(req));
    req.plaintext = &single;
    req.plaintext_len = 1;
    req.category = OZAYN_DATA_CATEGORY_USER_PREFERENCES;
    req.classification = OZAYN_SEC_LEVEL_PUBLIC;
    req.object_id = "empty-test";

    ozayn_protected_data_t pd;
    ASSERT_EQ(ozayn_prot_protect(&_prot_prov, &req, &pd), OZAYN_PROT_OK);

    ozayn_unprot_result_t result;
    ASSERT_EQ(ozayn_prot_unprotect(&_prot_prov, &pd, &result), OZAYN_PROT_OK);
    ASSERT_EQ(result.plaintext_len, (size_t)1);
    ASSERT_EQ(*result.plaintext, 0x42);
    _teardown();
    return 0;
}

/* 8. small payload (64 bytes) */
TEST(sodium_small_payload)
{
    _setup();
    uint8_t data[64];
    memset(data, 0xAA, sizeof(data));

    ozayn_prot_request_t req;
    memset(&req, 0, sizeof(req));
    req.plaintext = data;
    req.plaintext_len = sizeof(data);
    req.category = OZAYN_DATA_CATEGORY_USER_PREFERENCES;
    req.classification = OZAYN_SEC_LEVEL_SENSITIVE;
    req.object_id = "small-test";

    ozayn_protected_data_t pd;
    ASSERT_EQ(ozayn_prot_protect(&_prot_prov, &req, &pd), OZAYN_PROT_OK);

    ozayn_unprot_result_t result;
    ASSERT_EQ(ozayn_prot_unprotect(&_prot_prov, &pd, &result), OZAYN_PROT_OK);
    ASSERT_EQ(result.plaintext_len, sizeof(data));
    ASSERT_EQ(memcmp(result.plaintext, data, sizeof(data)), 0);
    _teardown();
    return 0;
}

/* 9. large payload (4096 bytes) */
TEST(sodium_large_payload)
{
    _setup();
    uint8_t data[4096];
    for (int i = 0; i < 4096; i++)
        data[i] = (uint8_t)(i & 0xFF);

    ozayn_prot_request_t req;
    memset(&req, 0, sizeof(req));
    req.plaintext = data;
    req.plaintext_len = sizeof(data);
    req.category = OZAYN_DATA_CATEGORY_DOCUMENTS;
    req.classification = OZAYN_SEC_LEVEL_SENSITIVE;
    req.object_id = "large-test";

    ozayn_protected_data_t pd;
    ASSERT_EQ(ozayn_prot_protect(&_prot_prov, &req, &pd), OZAYN_PROT_OK);
    ASSERT_EQ(pd.ciphertext_len, sizeof(data));

    ozayn_unprot_result_t result;
    ASSERT_EQ(ozayn_prot_unprotect(&_prot_prov, &pd, &result), OZAYN_PROT_OK);
    ASSERT_EQ(result.plaintext_len, sizeof(data));
    ASSERT_EQ(memcmp(result.plaintext, data, sizeof(data)), 0);
    _teardown();
    return 0;
}

/* ============================================================
 * KEY TESTS
 * ============================================================ */

/* 10. missing key provider */
TEST(sodium_missing_key)
{
    ozayn_protection_provider_t prov;
    ozayn_prot_sodium_create(&prov, NULL);
    ozayn_prot_init(&prov);

    ozayn_prot_request_t req = _valid_request();
    ozayn_protected_data_t pd;
    ASSERT_EQ(ozayn_prot_protect(&prov, &req, &pd), OZAYN_PROT_ERR_UNAVAILABLE);
    return 0;
}

/* 11. wrong key */
TEST(sodium_wrong_key)
{
    /* Encrypt with correct key */
    _setup();
    ozayn_prot_request_t req = _valid_request();
    ozayn_protected_data_t pd;
    ASSERT_EQ(ozayn_prot_protect(&_prot_prov, &req, &pd), OZAYN_PROT_OK);
    _teardown();

    /* Try to decrypt with wrong key */
    ozayn_key_provider_t wrong_prov;
    ozayn_key_test_create(&wrong_prov, _wrong_key, OZAYN_PROT_SODIUM_KEY_SIZE);
    ozayn_key_init(&wrong_prov);

    ozayn_protection_provider_t prot_wrong;
    ozayn_prot_sodium_create(&prot_wrong, &wrong_prov);
    ozayn_prot_init(&prot_wrong);

    ozayn_unprot_result_t result;
    ASSERT_EQ(ozayn_prot_unprotect(&prot_wrong, &pd, &result), OZAYN_PROT_ERR_AUTH_FAILED);

    ozayn_prot_shutdown(&prot_wrong);
    ozayn_key_shutdown(&wrong_prov);
    return 0;
}

/* 12. key not initialized */
TEST(sodium_key_not_ready)
{
    ozayn_key_provider_t kp;
    ozayn_key_test_create(&kp, _test_key, OZAYN_PROT_SODIUM_KEY_SIZE);
    /* Don't init */

    ozayn_protection_provider_t prov;
    ozayn_prot_sodium_create(&prov, &kp);
    ozayn_prot_init(&prov);

    ozayn_prot_request_t req = _valid_request();
    ozayn_protected_data_t pd;
    ASSERT_EQ(ozayn_prot_protect(&prov, &req, &pd), OZAYN_PROT_ERR_UNAVAILABLE);

    ozayn_prot_shutdown(&prov);
    return 0;
}

/* ============================================================
 * TAMPER TESTS
 * ============================================================ */

/* 13. modified ciphertext */
TEST(sodium_tamper_ciphertext)
{
    _setup();
    ozayn_prot_request_t req = _valid_request();
    ozayn_protected_data_t pd;
    ASSERT_EQ(ozayn_prot_protect(&_prot_prov, &req, &pd), OZAYN_PROT_OK);

    pd.ciphertext[0] ^= 0xFF;
    ozayn_unprot_result_t result;
    ASSERT_EQ(ozayn_prot_unprotect(&_prot_prov, &pd, &result), OZAYN_PROT_ERR_AUTH_FAILED);
    _teardown();
    return 0;
}

/* 14. modified nonce */
TEST(sodium_tamper_nonce)
{
    _setup();
    ozayn_prot_request_t req = _valid_request();
    ozayn_protected_data_t pd;
    ASSERT_EQ(ozayn_prot_protect(&_prot_prov, &req, &pd), OZAYN_PROT_OK);

    pd.nonce[0] ^= 0xFF;
    ozayn_unprot_result_t result;
    ASSERT_EQ(ozayn_prot_unprotect(&_prot_prov, &pd, &result), OZAYN_PROT_ERR_AUTH_FAILED);
    _teardown();
    return 0;
}

/* 15. modified tag */
TEST(sodium_tamper_tag)
{
    _setup();
    ozayn_prot_request_t req = _valid_request();
    ozayn_protected_data_t pd;
    ASSERT_EQ(ozayn_prot_protect(&_prot_prov, &req, &pd), OZAYN_PROT_OK);

    pd.tag[0] ^= 0xFF;
    ozayn_unprot_result_t result;
    ASSERT_EQ(ozayn_prot_unprotect(&_prot_prov, &pd, &result), OZAYN_PROT_ERR_AUTH_FAILED);
    _teardown();
    return 0;
}

/* 16. truncated ciphertext */
TEST(sodium_tamper_truncate)
{
    _setup();
    ozayn_prot_request_t req = _valid_request();
    ozayn_protected_data_t pd;
    ASSERT_EQ(ozayn_prot_protect(&_prot_prov, &req, &pd), OZAYN_PROT_OK);

    pd.ciphertext_len = 4;
    ozayn_unprot_result_t result;
    ASSERT_EQ(ozayn_prot_unprotect(&_prot_prov, &pd, &result), OZAYN_PROT_ERR_AUTH_FAILED);
    _teardown();
    return 0;
}

/* ============================================================
 * FORMAT / VERSION TESTS
 * ============================================================ */

/* 17. invalid format version */
TEST(sodium_invalid_format)
{
    _setup();
    ozayn_protected_data_t pd;
    memset(&pd, 0, sizeof(pd));
    pd.format_version = 99;
    pd.algorithm = OZAYN_PROT_ALG_AES_256_GCM;
    pd.ciphertext_len = 16;

    ozayn_unprot_result_t result;
    ASSERT_EQ(ozayn_prot_unprotect(&_prot_prov, &pd, &result), OZAYN_PROT_ERR_UNSUPPORTED_VERSION);
    _teardown();
    return 0;
}

/* 18. unsupported algorithm */
TEST(sodium_unsupported_algorithm)
{
    _setup();
    ozayn_protected_data_t pd;
    memset(&pd, 0, sizeof(pd));
    pd.format_version = OZAYN_PROT_CURRENT_VERSION;
    pd.algorithm = OZAYN_PROT_ALG_NONE;
    pd.ciphertext_len = 16;

    ozayn_unprot_result_t result;
    ASSERT_EQ(ozayn_prot_unprotect(&_prot_prov, &pd, &result), OZAYN_PROT_ERR_UNSUPPORTED_FORMAT);
    _teardown();
    return 0;
}

/* 19. zero format_version */
TEST(sodium_zero_version)
{
    _setup();
    ozayn_protected_data_t pd;
    memset(&pd, 0, sizeof(pd));

    ozayn_unprot_result_t result;
    ASSERT_EQ(ozayn_prot_unprotect(&_prot_prov, &pd, &result), OZAYN_PROT_ERR_INVALID_PROTECTED);
    _teardown();
    return 0;
}

/* ============================================================
 * CLASSIFICATION PRESERVATION
 * ============================================================ */

/* 20. classification preserved */
TEST(sodium_classification_preserved)
{
    _setup();
    ozayn_security_level_t levels[] = {
        OZAYN_SEC_LEVEL_PUBLIC,
        OZAYN_SEC_LEVEL_INTERNAL,
        OZAYN_SEC_LEVEL_SENSITIVE,
        OZAYN_SEC_LEVEL_HIGHLY_SENSITIVE
    };

    for (int i = 0; i < 4; i++) {
        ozayn_prot_request_t req = _valid_request();
        req.classification = levels[i];

        ozayn_protected_data_t pd;
        ASSERT_EQ(ozayn_prot_protect(&_prot_prov, &req, &pd), OZAYN_PROT_OK);
        ASSERT_EQ((int)pd.data_classification, levels[i]);

        ozayn_unprot_result_t result;
        ASSERT_EQ(ozayn_prot_unprotect(&_prot_prov, &pd, &result), OZAYN_PROT_OK);
        ASSERT_EQ((int)result.classification, levels[i]);
    }

    _teardown();
    return 0;
}

/* 21. category preserved */
TEST(sodium_category_preserved)
{
    _setup();
    ozayn_prot_request_t req = _valid_request();
    req.category = OZAYN_DATA_CATEGORY_IDENTITY_INFORMATION;

    ozayn_protected_data_t pd;
    ASSERT_EQ(ozayn_prot_protect(&_prot_prov, &req, &pd), OZAYN_PROT_OK);
    ASSERT_EQ((int)pd.data_category, OZAYN_DATA_CATEGORY_IDENTITY_INFORMATION);

    ozayn_unprot_result_t result;
    ASSERT_EQ(ozayn_prot_unprotect(&_prot_prov, &pd, &result), OZAYN_PROT_OK);
    ASSERT_EQ((int)result.category, OZAYN_DATA_CATEGORY_IDENTITY_INFORMATION);
    _teardown();
    return 0;
}

/* ============================================================
 * FAIL-CLOSED TESTS
 * ============================================================ */

/* 22. no plaintext fallback */
TEST(sodium_no_plaintext_fallback)
{
    /* Encrypt with correct key */
    _setup();
    ozayn_prot_request_t req = _valid_request();
    ozayn_protected_data_t pd;
    ASSERT_EQ(ozayn_prot_protect(&_prot_prov, &req, &pd), OZAYN_PROT_OK);
    _teardown();

    /* Wrong key */
    ozayn_key_provider_t wrong_prov;
    ozayn_key_test_create(&wrong_prov, _wrong_key, OZAYN_PROT_SODIUM_KEY_SIZE);
    ozayn_key_init(&wrong_prov);

    ozayn_protection_provider_t prot_wrong;
    ozayn_prot_sodium_create(&prot_wrong, &wrong_prov);
    ozayn_prot_init(&prot_wrong);

    ozayn_unprot_result_t result;
    memset(&result, 0xFF, sizeof(result));
    ASSERT_EQ(ozayn_prot_unprotect(&prot_wrong, &pd, &result), OZAYN_PROT_ERR_AUTH_FAILED);
    ASSERT(result.plaintext == NULL);
    ASSERT(result.plaintext_len == 0);

    ozayn_prot_shutdown(&prot_wrong);
    ozayn_key_shutdown(&wrong_prov);
    return 0;
}

/* 23. protect failure does not store partial data */
TEST(sodium_protect_failure_clean)
{
    ozayn_key_provider_t kp;
    ozayn_key_test_create(&kp, NULL, 0);
    /* Don't init key — unavailable */

    ozayn_protection_provider_t prov;
    ozayn_prot_sodium_create(&prov, &kp);
    ozayn_prot_init(&prov);

    ozayn_prot_request_t req = _valid_request();
    ozayn_protected_data_t pd;
    memset(&pd, 0xFF, sizeof(pd));
    ASSERT_EQ(ozayn_prot_protect(&prov, &req, &pd), OZAYN_PROT_ERR_UNAVAILABLE);
    ASSERT(pd.format_version == 0);
    ASSERT(pd.ciphertext_len == 0);

    ozayn_prot_shutdown(&prov);
    return 0;
}

/* ============================================================
 * ASSOCIATED DATA
 * ============================================================ */

/* 24. with associated data */
TEST(sodium_associated_data)
{
    _setup();
    const uint8_t aad[] = {0xAA, 0xBB, 0xCC, 0xDD};

    ozayn_prot_request_t req = _valid_request();
    req.associated = aad;
    req.associated_len = sizeof(aad);

    ozayn_protected_data_t pd;
    ASSERT_EQ(ozayn_prot_protect(&_prot_prov, &req, &pd), OZAYN_PROT_OK);

    /* Tamper with associated data — should fail auth */
    pd.associated[0] ^= 0xFF;
    ozayn_unprot_result_t result;
    ASSERT_EQ(ozayn_prot_unprotect(&_prot_prov, &pd, &result), OZAYN_PROT_ERR_AUTH_FAILED);
    _teardown();
    return 0;
}

/* ============================================================
 * MULTIPLE CYCLES
 * ============================================================ */

/* 25. multiple encrypt/decrypt cycles */
TEST(sodium_multiple_cycles)
{
    _setup();
    for (int i = 0; i < 10; i++) {
        ozayn_prot_request_t req = _valid_request();
        char id[32];
        snprintf(id, sizeof(id), "cycle-%d", i);
        req.object_id = id;

        ozayn_protected_data_t pd;
        ASSERT_EQ(ozayn_prot_protect(&_prot_prov, &req, &pd), OZAYN_PROT_OK);

        ozayn_unprot_result_t result;
        ASSERT_EQ(ozayn_prot_unprotect(&_prot_prov, &pd, &result), OZAYN_PROT_OK);
        ASSERT_EQ(result.plaintext_len, req.plaintext_len);
        ASSERT_EQ(memcmp(result.plaintext, req.plaintext, req.plaintext_len), 0);
    }
    _teardown();
    return 0;
}

/* ============================================================
 * DISK PLAINTEXT EXPOSURE TEST
 * ============================================================ */

/* 26. disk representation does not contain plaintext */
TEST(sodium_disk_no_plaintext)
{
    _setup();
    ozayn_prot_request_t req = _valid_request();
    ozayn_protected_data_t pd;
    ASSERT_EQ(ozayn_prot_protect(&_prot_prov, &req, &pd), OZAYN_PROT_OK);

    /* Search for the plaintext marker in the protected data structure */
    const uint8_t *bytes = (const uint8_t *)&pd;
    size_t total = sizeof(pd);
    int found = 0;
    for (size_t i = 0; i + sizeof(_test_data) <= total; i++) {
        if (memcmp(&bytes[i], _test_data, sizeof(_test_data)) == 0) {
            found = 1;
            break;
        }
    }
    ASSERT(!found);

    /* Also check ciphertext region directly */
    found = 0;
    for (size_t i = 0; i + sizeof(_test_data) <= pd.ciphertext_len; i++) {
        if (memcmp(&pd.ciphertext[i], _test_data, sizeof(_test_data)) == 0) {
            found = 1;
            break;
        }
    }
    ASSERT(!found);

    _teardown();
    return 0;
}

/* ============================================================
 * CORRUPTION TEST
 * ============================================================ */

/* 27. corrupted protected data */
TEST(sodium_corruption)
{
    _setup();
    ozayn_prot_request_t req = _valid_request();
    ozayn_protected_data_t pd;
    ASSERT_EQ(ozayn_prot_protect(&_prot_prov, &req, &pd), OZAYN_PROT_OK);

    /* Corrupt multiple bytes in ciphertext */
    for (int i = 0; i < 10 && i < (int)pd.ciphertext_len; i++)
        pd.ciphertext[i] ^= 0xFF;

    ozayn_unprot_result_t result;
    ASSERT_EQ(ozayn_prot_unprotect(&_prot_prov, &pd, &result), OZAYN_PROT_ERR_AUTH_FAILED);
    _teardown();
    return 0;
}

/* ============================================================
 * ALGORITHM NAME TEST
 * ============================================================ */

/* 28. algorithm name */
TEST(sodium_algorithm_name)
{
    _setup();
    const char *name = ozayn_prot_algorithm_name(&_prot_prov);
    ASSERT(name != NULL);
    ASSERT(strlen(name) > 0);
    _teardown();
    return 0;
}

/* ============================================================
 * KEY PROVIDER TESTS
 * ============================================================ */

/* 29. key provider lifecycle */
TEST(sodium_key_lifecycle)
{
    ozayn_key_provider_t kp;
    ozayn_key_test_create(&kp, _test_key, OZAYN_PROT_SODIUM_KEY_SIZE);
    ASSERT_EQ(ozayn_key_init(&kp), OZAYN_KEY_OK);
    ASSERT(ozayn_key_is_ready(&kp));
    ASSERT(ozayn_key_is_available(&kp));
    ASSERT_EQ(ozayn_key_length(&kp), OZAYN_PROT_SODIUM_KEY_SIZE);

    uint8_t key_out[OZAYN_KEY_MAX_SIZE];
    ASSERT_EQ(ozayn_key_get(&kp, key_out, OZAYN_KEY_MAX_SIZE), OZAYN_KEY_OK);
    ASSERT_EQ(memcmp(key_out, _test_key, OZAYN_PROT_SODIUM_KEY_SIZE), 0);

    ozayn_key_shutdown(&kp);
    ASSERT(!ozayn_key_is_ready(&kp));
    return 0;
}

/* 30. key provider null */
TEST(sodium_key_null)
{
    ASSERT_EQ(ozayn_key_init(NULL), OZAYN_KEY_ERR_NULL);
    ozayn_key_shutdown(NULL);
    ASSERT(!ozayn_key_is_ready(NULL));
    ASSERT_EQ(ozayn_key_get(NULL, NULL, 0), OZAYN_KEY_ERR_NULL);
    return 0;
}

/* 31. key result names */
TEST(sodium_key_names)
{
    ASSERT_STR_EQ(ozayn_key_result_name(OZAYN_KEY_OK), "KEY_OK");
    ASSERT_STR_EQ(ozayn_key_result_name(OZAYN_KEY_ERR_NULL), "KEY_NULL");
    ASSERT_STR_EQ(ozayn_key_result_name(OZAYN_KEY_ERR_UNAVAILABLE), "KEY_UNAVAILABLE");
    return 0;
}

/* ============================================================
 * RESTART SIMULATION TEST
 * ============================================================ */

/* 32. simulate process restart (encrypt, tear down, new providers, decrypt) */
TEST(sodium_restart_simulation)
{
    /* Phase 1: encrypt */
    _setup();
    ozayn_prot_request_t req = _valid_request();
    ozayn_protected_data_t pd;
    ASSERT_EQ(ozayn_prot_protect(&_prot_prov, &req, &pd), OZAYN_PROT_OK);
    _teardown();

    /* Simulate process restart: new provider instances with same key */
    ozayn_key_provider_t kp2;
    ozayn_key_test_create(&kp2, _test_key, OZAYN_PROT_SODIUM_KEY_SIZE);
    ozayn_key_init(&kp2);

    ozayn_protection_provider_t prot2;
    ozayn_prot_sodium_create(&prot2, &kp2);
    ASSERT_EQ(ozayn_prot_init(&prot2), OZAYN_PROT_OK);

    /* Phase 2: decrypt */
    ozayn_unprot_result_t result;
    ASSERT_EQ(ozayn_prot_unprotect(&prot2, &pd, &result), OZAYN_PROT_OK);
    ASSERT_EQ(result.plaintext_len, req.plaintext_len);
    ASSERT_EQ(memcmp(result.plaintext, req.plaintext, req.plaintext_len), 0);
    ASSERT_EQ((int)result.category, req.category);
    ASSERT_EQ((int)result.classification, req.classification);

    ozayn_prot_shutdown(&prot2);
    ozayn_key_shutdown(&kp2);
    return 0;
}

/* ============================================================
 * UNIQUE NONCE TEST
 * ============================================================ */

/* 33. nonces are unique across encryptions */
TEST(sodium_unique_nonces)
{
    _setup();
    ozayn_prot_request_t req = _valid_request();

    ozayn_protected_data_t pd1, pd2;
    ASSERT_EQ(ozayn_prot_protect(&_prot_prov, &req, &pd1), OZAYN_PROT_OK);
    ASSERT_EQ(ozayn_prot_protect(&_prot_prov, &req, &pd2), OZAYN_PROT_OK);

    /* Nonces must differ (random generation) */
    int same = 1;
    for (int i = 0; i < pd1.nonce_len; i++) {
        if (pd1.nonce[i] != pd2.nonce[i]) {
            same = 0;
            break;
        }
    }
    ASSERT(!same);
    _teardown();
    return 0;
}

/* ============================================================
 * KEY SIZE VALIDATION
 * ============================================================ */

/* 34. wrong key size */
TEST(sodium_wrong_key_size)
{
    uint8_t short_key[16] = {0};
    ozayn_key_provider_t kp;
    ozayn_key_test_create(&kp, short_key, 16);
    ozayn_key_init(&kp);

    ozayn_protection_provider_t prov;
    ozayn_prot_sodium_create(&prov, &kp);
    ozayn_prot_init(&prov);

    ozayn_prot_request_t req = _valid_request();
    ozayn_protected_data_t pd;
    ASSERT_EQ(ozayn_prot_protect(&prov, &req, &pd), OZAYN_PROT_ERR_INVALID_REQUEST);

    ozayn_prot_shutdown(&prov);
    ozayn_key_shutdown(&kp);
    return 0;
}

/* ============================================================
 * ERRORS
 * ============================================================ */

/* 35. null request */
TEST(sodium_null_request)
{
    _setup();
    ozayn_protected_data_t pd;
    ASSERT_EQ(ozayn_prot_protect(&_prot_prov, NULL, &pd), OZAYN_PROT_ERR_NULL);
    _teardown();
    return 0;
}

/* 36. null output */
TEST(sodium_null_output)
{
    _setup();
    ozayn_prot_request_t req = _valid_request();
    ASSERT_EQ(ozayn_prot_protect(&_prot_prov, &req, NULL), OZAYN_PROT_ERR_NULL);
    _teardown();
    return 0;
}

/* 37. null protected data */
TEST(sodium_null_protected)
{
    _setup();
    ozayn_unprot_result_t result;
    ASSERT_EQ(ozayn_prot_unprotect(&_prot_prov, NULL, &result), OZAYN_PROT_ERR_NULL);
    _teardown();
    return 0;
}

/* 38. null unprotect output */
TEST(sodium_null_unprot_out)
{
    _setup();
    ozayn_protected_data_t pd;
    memset(&pd, 0, sizeof(pd));
    pd.format_version = OZAYN_PROT_CURRENT_VERSION;
    ASSERT_EQ(ozayn_prot_unprotect(&_prot_prov, &pd, NULL), OZAYN_PROT_ERR_NULL);
    _teardown();
    return 0;
}

/* 39. protect before init */
TEST(sodium_protect_before_init)
{
    ozayn_key_provider_t kp;
    ozayn_key_test_create(&kp, _test_key, OZAYN_PROT_SODIUM_KEY_SIZE);

    ozayn_protection_provider_t prov;
    ozayn_prot_sodium_create(&prov, &kp);
    /* Don't init */

    ozayn_prot_request_t req = _valid_request();
    ozayn_protected_data_t pd;
    ASSERT_EQ(ozayn_prot_protect(&prov, &req, &pd), OZAYN_PROT_ERR_NOT_INITIALIZED);
    return 0;
}

/* 40. empty object_id */
TEST(sodium_empty_id)
{
    _setup();
    ozayn_prot_request_t req = _valid_request();
    req.object_id = "";
    ozayn_protected_data_t pd;
    ASSERT_EQ(ozayn_prot_protect(&_prot_prov, &req, &pd), OZAYN_PROT_ERR_INVALID_REQUEST);
    _teardown();
    return 0;
}

/* ============================================================
 * PROTECTED DATA VALIDATION
 * ============================================================ */

/* 41. protected data has correct structure */
TEST(sodium_protected_structure)
{
    _setup();
    ozayn_prot_request_t req = _valid_request();
    ozayn_protected_data_t pd;
    ASSERT_EQ(ozayn_prot_protect(&_prot_prov, &req, &pd), OZAYN_PROT_OK);

    ASSERT_EQ(pd.format_version, OZAYN_PROT_CURRENT_VERSION);
    ASSERT(pd.algorithm == OZAYN_PROT_ALG_AES_256_GCM ||
           pd.algorithm == OZAYN_PROT_ALG_CHACHA20_POLY1305);
    ASSERT(pd.nonce_len > 0 && pd.nonce_len <= OZAYN_PROT_MAX_NONCE_SIZE);
    ASSERT(pd.tag_len > 0 && pd.tag_len <= OZAYN_PROT_MAX_TAG_SIZE);
    ASSERT(pd.ciphertext_len > 0);
    ASSERT_STR_EQ(pd.object_id, _test_id);

    _teardown();
    return 0;
}

/* ============================================================
 * LARGE DATA THROUGHPUT
 * ============================================================ */

/* 42. large data (32KB) */
TEST(sodium_large_data_32k)
{
    _setup();
    uint8_t data[32768];
    for (int i = 0; i < 32768; i++)
        data[i] = (uint8_t)((i * 7 + 13) & 0xFF);

    ozayn_prot_request_t req;
    memset(&req, 0, sizeof(req));
    req.plaintext = data;
    req.plaintext_len = sizeof(data);
    req.category = OZAYN_DATA_CATEGORY_DOCUMENTS;
    req.classification = OZAYN_SEC_LEVEL_SENSITIVE;
    req.object_id = "large-32k";

    ozayn_protected_data_t pd;
    ASSERT_EQ(ozayn_prot_protect(&_prot_prov, &req, &pd), OZAYN_PROT_OK);

    ozayn_unprot_result_t result;
    ASSERT_EQ(ozayn_prot_unprotect(&_prot_prov, &pd, &result), OZAYN_PROT_OK);
    ASSERT_EQ(result.plaintext_len, sizeof(data));
    ASSERT_EQ(memcmp(result.plaintext, data, sizeof(data)), 0);

    _teardown();
    return 0;
}

/* ============================================================
 * TEST REGISTRATION
 * ============================================================ */
void run_protection_provider_sodium_tests(void)
{
    printf("\n=== PRODUCTION ENCRYPTION (Step 07) ===\n");
    printf("Cryptographic Library: libsodium 1.0.20\n");
    printf("Number of tests: 42\n\n");

    /* Lifecycle (2) */
    RUN(sodium_lifecycle);
    RUN(sodium_null_provider);

    /* Encrypt/Decrypt (4) */
    RUN(sodium_encrypt_valid);
    RUN(sodium_decrypt_valid);
    RUN(sodium_roundtrip);
    RUN(sodium_not_plaintext);

    /* Payload sizes (3) */
    RUN(sodium_empty_payload);
    RUN(sodium_small_payload);
    RUN(sodium_large_payload);

    /* Key tests (3) */
    RUN(sodium_missing_key);
    RUN(sodium_wrong_key);
    RUN(sodium_key_not_ready);

    /* Tamper tests (4) */
    RUN(sodium_tamper_ciphertext);
    RUN(sodium_tamper_nonce);
    RUN(sodium_tamper_tag);
    RUN(sodium_tamper_truncate);

    /* Format/version tests (3) */
    RUN(sodium_invalid_format);
    RUN(sodium_unsupported_algorithm);
    RUN(sodium_zero_version);

    /* Classification (2) */
    RUN(sodium_classification_preserved);
    RUN(sodium_category_preserved);

    /* Fail-closed (2) */
    RUN(sodium_no_plaintext_fallback);
    RUN(sodium_protect_failure_clean);

    /* Associated data (1) */
    RUN(sodium_associated_data);

    /* Advanced (4) */
    RUN(sodium_multiple_cycles);
    RUN(sodium_disk_no_plaintext);
    RUN(sodium_corruption);
    RUN(sodium_algorithm_name);

    /* Key provider (3) */
    RUN(sodium_key_lifecycle);
    RUN(sodium_key_null);
    RUN(sodium_key_names);

    /* Restart (1) */
    RUN(sodium_restart_simulation);

    /* Nonce (1) */
    RUN(sodium_unique_nonces);

    /* Validation (2) */
    RUN(sodium_wrong_key_size);
    RUN(sodium_empty_id);

    /* Errors (5) */
    RUN(sodium_null_request);
    RUN(sodium_null_output);
    RUN(sodium_null_protected);
    RUN(sodium_null_unprot_out);
    RUN(sodium_protect_before_init);

    /* Structure (1) */
    RUN(sodium_protected_structure);

    /* Large data (1) */
    RUN(sodium_large_data_32k);
}
