#include "../../tests/test_framework.h"
#include "../protection_provider.h"
#include "../protection_provider_mock.h"
#include <string.h>

/*
 * test_protection_provider.c — Step 06 Tests (Section 03, Step 06).
 *
 * Tests the encryption/protection architecture, contracts, fail-closed
 * behavior, and integration with the mock provider.
 */

/* ---- Test Data ---- */
static const char _test_data[] = "Sensitive user data requiring protection";
static const char _test_id[] = "user-prefs-001";

/* ---- Helper: create a valid protection request ---- */
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

/* ============================================================
 * LIFECYCLE TESTS
 * ============================================================ */

/* 1. init and shutdown */
TEST(prot_lifecycle_init_shutdown)
{
    ozayn_protection_provider_t provider;
    ozayn_prot_mock_config_t cfg = {0};
    ozayn_prot_mock_create(&provider, &cfg);

    ASSERT_EQ(provider.state, OZAYN_PROT_STATE_UNINITIALIZED);

    ozayn_prot_result_t r = ozayn_prot_init(&provider);
    ASSERT_EQ(r, OZAYN_PROT_OK);
    ASSERT_EQ(provider.state, OZAYN_PROT_STATE_READY);
    ASSERT(ozayn_prot_is_ready(&provider));

    ozayn_prot_shutdown(&provider);
    ASSERT_EQ(provider.state, OZAYN_PROT_STATE_STOPPED);
    ASSERT(!ozayn_prot_is_ready(&provider));

    return 0;
}

/* 2. null provider */
TEST(prot_lifecycle_null_provider)
{
    ASSERT_EQ(ozayn_prot_init(NULL), OZAYN_PROT_ERR_NULL);
    ozayn_prot_shutdown(NULL);
    ASSERT(!ozayn_prot_is_ready(NULL));
    return 0;
}

/* 3. init with null ops */
TEST(prot_lifecycle_null_ops)
{
    ozayn_protection_provider_t provider;
    memset(&provider, 0, sizeof(provider));
    provider.ops = NULL;
    ASSERT_EQ(ozayn_prot_init(&provider), OZAYN_PROT_ERR_UNAVAILABLE);
    return 0;
}

/* ============================================================
 * REQUEST VALIDATION TESTS
 * ============================================================ */

/* 4. valid protection request */
TEST(prot_request_valid)
{
    ozayn_protection_provider_t provider;
    ozayn_prot_mock_config_t cfg = {0};
    ozayn_prot_mock_create(&provider, &cfg);
    ozayn_prot_init(&provider);

    ozayn_prot_request_t req = _valid_request();
    ozayn_protected_data_t out;
    memset(&out, 0, sizeof(out));

    ozayn_prot_result_t r = ozayn_prot_protect(&provider, &req, &out);
    ASSERT_EQ(r, OZAYN_PROT_OK);
    ASSERT(out.format_version == OZAYN_PROT_CURRENT_VERSION);
    ASSERT(out.ciphertext_len > 0);
    ASSERT(out.algorithm == OZAYN_PROT_ALG_AES_256_GCM);

    ozayn_prot_shutdown(&provider);
    return 0;
}

/* 5. null plaintext */
TEST(prot_request_null_plaintext)
{
    ozayn_protection_provider_t provider;
    ozayn_prot_mock_config_t cfg = {0};
    ozayn_prot_mock_create(&provider, &cfg);
    ozayn_prot_init(&provider);

    ozayn_prot_request_t req = _valid_request();
    req.plaintext = NULL;
    ozayn_protected_data_t out;

    ASSERT_EQ(ozayn_prot_protect(&provider, &req, &out), OZAYN_PROT_ERR_INVALID_REQUEST);

    ozayn_prot_shutdown(&provider);
    return 0;
}

/* 6. empty plaintext */
TEST(prot_request_empty_plaintext)
{
    ozayn_protection_provider_t provider;
    ozayn_prot_mock_config_t cfg = {0};
    ozayn_prot_mock_create(&provider, &cfg);
    ozayn_prot_init(&provider);

    ozayn_prot_request_t req = _valid_request();
    req.plaintext_len = 0;
    ozayn_protected_data_t out;

    ASSERT_EQ(ozayn_prot_protect(&provider, &req, &out), OZAYN_PROT_ERR_INVALID_REQUEST);

    ozayn_prot_shutdown(&provider);
    return 0;
}

/* 7. null object_id */
TEST(prot_request_null_object_id)
{
    ozayn_protection_provider_t provider;
    ozayn_prot_mock_config_t cfg = {0};
    ozayn_prot_mock_create(&provider, &cfg);
    ozayn_prot_init(&provider);

    ozayn_prot_request_t req = _valid_request();
    req.object_id = NULL;
    ozayn_protected_data_t out;

    ASSERT_EQ(ozayn_prot_protect(&provider, &req, &out), OZAYN_PROT_ERR_INVALID_REQUEST);

    ozayn_prot_shutdown(&provider);
    return 0;
}

/* 8. empty object_id */
TEST(prot_request_empty_object_id)
{
    ozayn_protection_provider_t provider;
    ozayn_prot_mock_config_t cfg = {0};
    ozayn_prot_mock_create(&provider, &cfg);
    ozayn_prot_init(&provider);

    ozayn_prot_request_t req = _valid_request();
    req.object_id = "";
    ozayn_protected_data_t out;

    ASSERT_EQ(ozayn_prot_protect(&provider, &req, &out), OZAYN_PROT_ERR_INVALID_REQUEST);

    ozayn_prot_shutdown(&provider);
    return 0;
}

/* 9. null provider for protect */
TEST(prot_dispatch_null_provider)
{
    ozayn_prot_request_t req = _valid_request();
    ozayn_protected_data_t out;
    ASSERT_EQ(ozayn_prot_protect(NULL, &req, &out), OZAYN_PROT_ERR_NULL);
    return 0;
}

/* 10. null request */
TEST(prot_dispatch_null_request)
{
    ozayn_protection_provider_t provider;
    ozayn_prot_mock_config_t cfg = {0};
    ozayn_prot_mock_create(&provider, &cfg);
    ozayn_prot_init(&provider);

    ozayn_protected_data_t out;
    ASSERT_EQ(ozayn_prot_protect(&provider, NULL, &out), OZAYN_PROT_ERR_NULL);

    ozayn_prot_shutdown(&provider);
    return 0;
}

/* 11. null output */
TEST(prot_dispatch_null_output)
{
    ozayn_protection_provider_t provider;
    ozayn_prot_mock_config_t cfg = {0};
    ozayn_prot_mock_create(&provider, &cfg);
    ozayn_prot_init(&provider);

    ozayn_prot_request_t req = _valid_request();
    ASSERT_EQ(ozayn_prot_protect(&provider, &req, NULL), OZAYN_PROT_ERR_NULL);

    ozayn_prot_shutdown(&provider);
    return 0;
}

/* ============================================================
 * STATE MACHINE TESTS
 * ============================================================ */

/* 12. protect when not initialized */
TEST(prot_state_not_initialized)
{
    ozayn_protection_provider_t provider;
    ozayn_prot_mock_config_t cfg = {0};
    ozayn_prot_mock_create(&provider, &cfg);

    ozayn_prot_request_t req = _valid_request();
    ozayn_protected_data_t out;

    ASSERT_EQ(ozayn_prot_protect(&provider, &req, &out), OZAYN_PROT_ERR_NOT_INITIALIZED);
    return 0;
}

/* 13. unprotect when not initialized */
TEST(prot_state_not_initialized_unprotect)
{
    ozayn_protection_provider_t provider;
    ozayn_prot_mock_config_t cfg = {0};
    ozayn_prot_mock_create(&provider, &cfg);

    ozayn_protected_data_t fake_pd;
    memset(&fake_pd, 0, sizeof(fake_pd));
    fake_pd.format_version = OZAYN_PROT_CURRENT_VERSION;
    ozayn_unprot_result_t out;

    ASSERT_EQ(ozayn_prot_unprotect(&provider, &fake_pd, &out), OZAYN_PROT_ERR_NOT_INITIALIZED);
    return 0;
}

/* 14. protect after shutdown */
TEST(prot_state_after_shutdown)
{
    ozayn_protection_provider_t provider;
    ozayn_prot_mock_config_t cfg = {0};
    ozayn_prot_mock_create(&provider, &cfg);
    ozayn_prot_init(&provider);
    ozayn_prot_shutdown(&provider);

    ozayn_prot_request_t req = _valid_request();
    ozayn_protected_data_t out;

    ASSERT_EQ(ozayn_prot_protect(&provider, &req, &out), OZAYN_PROT_ERR_NOT_INITIALIZED);
    return 0;
}

/* ============================================================
 * PROTECTION FAILURE TESTS
 * ============================================================ */

/* 15. configure mock to fail on protect */
TEST(prot_failure_protect)
{
    ozayn_protection_provider_t provider;
    ozayn_prot_mock_config_t cfg = {0};
    cfg.fail_protect = 1;
    ozayn_prot_mock_create(&provider, &cfg);
    ozayn_prot_init(&provider);

    ozayn_prot_request_t req = _valid_request();
    ozayn_protected_data_t out;

    ASSERT_EQ(ozayn_prot_protect(&provider, &req, &out), OZAYN_PROT_ERR_PROTECTION_FAILED);

    ozayn_prot_shutdown(&provider);
    return 0;
}

/* 16. configure mock to fail on unprotect */
TEST(prot_failure_unprotect)
{
    ozayn_protection_provider_t provider;
    ozayn_prot_mock_config_t cfg = {0};
    cfg.fail_unprotect = 1;
    ozayn_prot_mock_create(&provider, &cfg);
    ozayn_prot_init(&provider);

    ozayn_protected_data_t fake_pd;
    memset(&fake_pd, 0, sizeof(fake_pd));
    fake_pd.format_version = OZAYN_PROT_CURRENT_VERSION;
    fake_pd.algorithm = OZAYN_PROT_ALG_AES_256_GCM;
    ozayn_unprot_result_t out;

    ASSERT_EQ(ozayn_prot_unprotect(&provider, &fake_pd, &out), OZAYN_PROT_ERR_UNPROTECTION_FAILED);

    ozayn_prot_shutdown(&provider);
    return 0;
}

/* 17. unsupported format */
TEST(prot_unsupported_format)
{
    ozayn_protection_provider_t provider;
    ozayn_prot_mock_config_t cfg = {0};
    ozayn_prot_mock_create(&provider, &cfg);
    ozayn_prot_init(&provider);

    ozayn_protected_data_t bad_pd;
    memset(&bad_pd, 0, sizeof(bad_pd));
    bad_pd.format_version = OZAYN_PROT_CURRENT_VERSION;
    bad_pd.algorithm = OZAYN_PROT_ALG_NONE;
    ozayn_unprot_result_t out;

    ASSERT_EQ(ozayn_prot_unprotect(&provider, &bad_pd, &out), OZAYN_PROT_ERR_UNSUPPORTED_FORMAT);

    ozayn_prot_shutdown(&provider);
    return 0;
}

/* 18. unsupported version */
TEST(prot_unsupported_version)
{
    ozayn_protection_provider_t provider;
    ozayn_prot_mock_config_t cfg = {0};
    ozayn_prot_mock_create(&provider, &cfg);
    ozayn_prot_init(&provider);

    ozayn_protected_data_t bad_pd;
    memset(&bad_pd, 0, sizeof(bad_pd));
    bad_pd.format_version = 99;
    bad_pd.algorithm = OZAYN_PROT_ALG_AES_256_GCM;
    bad_pd.ciphertext_len = 16;
    ozayn_unprot_result_t out;

    ASSERT_EQ(ozayn_prot_unprotect(&provider, &bad_pd, &out), OZAYN_PROT_ERR_UNSUPPORTED_VERSION);

    ozayn_prot_shutdown(&provider);
    return 0;
}

/* 19. invalid protected data (format_version = 0) */
TEST(prot_invalid_protected_data)
{
    ozayn_protection_provider_t provider;
    ozayn_prot_mock_config_t cfg = {0};
    ozayn_prot_mock_create(&provider, &cfg);
    ozayn_prot_init(&provider);

    ozayn_protected_data_t bad_pd;
    memset(&bad_pd, 0, sizeof(bad_pd));
    /* format_version remains 0 */
    ozayn_unprot_result_t out;

    ASSERT_EQ(ozayn_prot_unprotect(&provider, &bad_pd, &out), OZAYN_PROT_ERR_INVALID_PROTECTED);

    ozayn_prot_shutdown(&provider);
    return 0;
}

/* 20. null provider for unprotect */
TEST(prot_dispatch_null_provider_unprotect)
{
    ozayn_protected_data_t fake_pd;
    memset(&fake_pd, 0, sizeof(fake_pd));
    fake_pd.format_version = OZAYN_PROT_CURRENT_VERSION;
    ozayn_unprot_result_t out;

    ASSERT_EQ(ozayn_prot_unprotect(NULL, &fake_pd, &out), OZAYN_PROT_ERR_NULL);
    return 0;
}

/* 21. null protected data */
TEST(prot_dispatch_null_protected_data)
{
    ozayn_protection_provider_t provider;
    ozayn_prot_mock_config_t cfg = {0};
    ozayn_prot_mock_create(&provider, &cfg);
    ozayn_prot_init(&provider);

    ozayn_unprot_result_t out;
    ASSERT_EQ(ozayn_prot_unprotect(&provider, NULL, &out), OZAYN_PROT_ERR_NULL);

    ozayn_prot_shutdown(&provider);
    return 0;
}

/* 22. null unprotect output */
TEST(prot_dispatch_null_unprotect_output)
{
    ozayn_protection_provider_t provider;
    ozayn_prot_mock_config_t cfg = {0};
    ozayn_prot_mock_create(&provider, &cfg);
    ozayn_prot_init(&provider);

    ozayn_protected_data_t fake_pd;
    memset(&fake_pd, 0, sizeof(fake_pd));
    fake_pd.format_version = OZAYN_PROT_CURRENT_VERSION;

    ASSERT_EQ(ozayn_prot_unprotect(&provider, &fake_pd, NULL), OZAYN_PROT_ERR_NULL);

    ozayn_prot_shutdown(&provider);
    return 0;
}

/* ============================================================
 * ROUND-TRIP TESTS
 * ============================================================ */

/* 23. protect → unprotect round-trip */
TEST(prot_roundtrip_basic)
{
    ozayn_protection_provider_t provider;
    ozayn_prot_mock_config_t cfg = {0};
    ozayn_prot_mock_create(&provider, &cfg);
    ozayn_prot_init(&provider);

    ozayn_prot_request_t req = _valid_request();
    ozayn_protected_data_t protected;
    memset(&protected, 0, sizeof(protected));

    ASSERT_EQ(ozayn_prot_protect(&provider, &req, &protected), OZAYN_PROT_OK);

    ozayn_unprot_result_t unprot;
    memset(&unprot, 0, sizeof(unprot));

    ASSERT_EQ(ozayn_prot_unprotect(&provider, &protected, &unprot), OZAYN_PROT_OK);
    ASSERT_EQ(unprot.plaintext_len, req.plaintext_len);
    ASSERT_EQ(memcmp(unprot.plaintext, req.plaintext, req.plaintext_len), 0);
    ASSERT_EQ(unprot.category, req.category);
    ASSERT_EQ(unprot.classification, req.classification);

    ozayn_prot_shutdown(&provider);
    return 0;
}

/* 24. protect → unprotect with associated data */
TEST(prot_roundtrip_associated_data)
{
    ozayn_protection_provider_t provider;
    ozayn_prot_mock_config_t cfg = {0};
    ozayn_prot_mock_create(&provider, &cfg);
    ozayn_prot_init(&provider);

    const uint8_t aad[] = {0xAA, 0xBB, 0xCC, 0xDD};

    ozayn_prot_request_t req = _valid_request();
    req.associated = aad;
    req.associated_len = sizeof(aad);

    ozayn_protected_data_t protected;
    ASSERT_EQ(ozayn_prot_protect(&provider, &req, &protected), OZAYN_PROT_OK);
    ASSERT(protected.associated_len == sizeof(aad));
    ASSERT_EQ(memcmp(protected.associated, aad, sizeof(aad)), 0);

    ozayn_unprot_result_t unprot;
    ASSERT_EQ(ozayn_prot_unprotect(&provider, &protected, &unprot), OZAYN_PROT_OK);
    ASSERT_EQ(unprot.plaintext_len, req.plaintext_len);

    ozayn_prot_shutdown(&provider);
    return 0;
}

/* 25. protected data is NOT plaintext */
TEST(prot_not_plaintext)
{
    ozayn_protection_provider_t provider;
    ozayn_prot_mock_config_t cfg = {0};
    ozayn_prot_mock_create(&provider, &cfg);
    ozayn_prot_init(&provider);

    ozayn_prot_request_t req = _valid_request();
    ozayn_protected_data_t protected;
    ASSERT_EQ(ozayn_prot_protect(&provider, &req, &protected), OZAYN_PROT_OK);

    /* Ciphertext must differ from plaintext */
    int differs = memcmp(protected.ciphertext, req.plaintext, req.plaintext_len);
    ASSERT(differs != 0);

    ozayn_prot_shutdown(&provider);
    return 0;
}

/* ============================================================
 * TAMPER / AUTHENTICATION TESTS
 * ============================================================ */

/* 26. tamper with ciphertext — authentication failure */
TEST(prot_tamper_ciphertext)
{
    ozayn_protection_provider_t provider;
    ozayn_prot_mock_config_t cfg = {0};
    cfg.require_auth_check = 1;
    ozayn_prot_mock_create(&provider, &cfg);
    ozayn_prot_init(&provider);

    ozayn_prot_request_t req = _valid_request();
    ozayn_protected_data_t protected;
    ASSERT_EQ(ozayn_prot_protect(&provider, &req, &protected), OZAYN_PROT_OK);

    /* Tamper with first byte of ciphertext */
    protected.ciphertext[0] ^= 0xFF;

    ozayn_unprot_result_t unprot;
    ASSERT_EQ(ozayn_prot_unprotect(&provider, &protected, &unprot), OZAYN_PROT_ERR_AUTH_FAILED);

    ozayn_prot_shutdown(&provider);
    return 0;
}

/* 27. tamper with tag — authentication failure */
TEST(prot_tamper_tag)
{
    ozayn_protection_provider_t provider;
    ozayn_prot_mock_config_t cfg = {0};
    cfg.require_auth_check = 1;
    ozayn_prot_mock_create(&provider, &cfg);
    ozayn_prot_init(&provider);

    ozayn_prot_request_t req = _valid_request();
    ozayn_protected_data_t protected;
    ASSERT_EQ(ozayn_prot_protect(&provider, &req, &protected), OZAYN_PROT_OK);

    /* Tamper with tag */
    protected.tag[0] ^= 0xFF;

    ozayn_unprot_result_t unprot;
    ASSERT_EQ(ozayn_prot_unprotect(&provider, &protected, &unprot), OZAYN_PROT_ERR_AUTH_FAILED);

    ozayn_prot_shutdown(&provider);
    return 0;
}

/* 28. inject tag error on protect */
TEST(prot_inject_tag_error)
{
    ozayn_protection_provider_t provider;
    ozayn_prot_mock_config_t cfg = {0};
    cfg.inject_tag_error = 1;
    cfg.require_auth_check = 1;
    ozayn_prot_mock_create(&provider, &cfg);
    ozayn_prot_init(&provider);

    ozayn_prot_request_t req = _valid_request();
    ozayn_protected_data_t protected;
    ASSERT_EQ(ozayn_prot_protect(&provider, &req, &protected), OZAYN_PROT_OK);

    /* Tag is corrupted, verify detects it */
    ASSERT(!ozayn_prot_mock_verify_tag(&protected));

    ozayn_unprot_result_t unprot;
    ASSERT_EQ(ozayn_prot_unprotect(&provider, &protected, &unprot), OZAYN_PROT_ERR_AUTH_FAILED);

    ozayn_prot_shutdown(&provider);
    return 0;
}

/* ============================================================
 * CLASSIFICATION PRESERVATION TESTS
 * ============================================================ */

/* 29. classification preserved through protect/unprotect */
TEST(prot_classification_preserved)
{
    ozayn_protection_provider_t provider;
    ozayn_prot_mock_config_t cfg = {0};
    ozayn_prot_mock_create(&provider, &cfg);
    ozayn_prot_init(&provider);

    ozayn_security_level_t levels[] = {
        OZAYN_SEC_LEVEL_PUBLIC,
        OZAYN_SEC_LEVEL_INTERNAL,
        OZAYN_SEC_LEVEL_SENSITIVE,
        OZAYN_SEC_LEVEL_HIGHLY_SENSITIVE
    };

    for (int i = 0; i < 4; i++) {
        ozayn_prot_request_t req = _valid_request();
        req.classification = levels[i];

        ozayn_protected_data_t protected;
        ASSERT_EQ(ozayn_prot_protect(&provider, &req, &protected), OZAYN_PROT_OK);
        ASSERT_EQ((int)protected.data_classification, levels[i]);

        ozayn_unprot_result_t unprot;
        ASSERT_EQ(ozayn_prot_unprotect(&provider, &protected, &unprot), OZAYN_PROT_OK);
        ASSERT_EQ((int)unprot.classification, levels[i]);
    }

    ozayn_prot_shutdown(&provider);
    return 0;
}

/* 30. category preserved through protect/unprotect */
TEST(prot_category_preserved)
{
    ozayn_protection_provider_t provider;
    ozayn_prot_mock_config_t cfg = {0};
    ozayn_prot_mock_create(&provider, &cfg);
    ozayn_prot_init(&provider);

    ozayn_prot_request_t req = _valid_request();
    req.category = OZAYN_DATA_CATEGORY_IDENTITY_INFORMATION;

    ozayn_protected_data_t protected;
    ASSERT_EQ(ozayn_prot_protect(&provider, &req, &protected), OZAYN_PROT_OK);
    ASSERT_EQ((int)protected.data_category, OZAYN_DATA_CATEGORY_IDENTITY_INFORMATION);

    ozayn_unprot_result_t unprot;
    ASSERT_EQ(ozayn_prot_unprotect(&provider, &protected, &unprot), OZAYN_PROT_OK);
    ASSERT_EQ((int)unprot.category, OZAYN_DATA_CATEGORY_IDENTITY_INFORMATION);

    ozayn_prot_shutdown(&provider);
    return 0;
}

/* ============================================================
 * PROTECTED DATA VALIDATION TESTS
 * ============================================================ */

/* 31. valid protected data */
TEST(prot_validate_valid)
{
    ozayn_protected_data_t pd;
    memset(&pd, 0, sizeof(pd));
    pd.format_version = OZAYN_PROT_CURRENT_VERSION;
    pd.algorithm = OZAYN_PROT_ALG_AES_256_GCM;
    pd.ciphertext_len = 32;
    pd.nonce_len = 12;
    pd.tag_len = 16;
    ASSERT(ozayn_protected_data_validate(&pd));
    return 0;
}

/* 32. null protected data */
TEST(prot_validate_null)
{
    ASSERT(!ozayn_protected_data_validate(NULL));
    return 0;
}

/* 33. wrong version */
TEST(prot_validate_wrong_version)
{
    ozayn_protected_data_t pd;
    memset(&pd, 0, sizeof(pd));
    pd.format_version = 99;
    pd.algorithm = OZAYN_PROT_ALG_AES_256_GCM;
    pd.ciphertext_len = 32;
    pd.nonce_len = 12;
    pd.tag_len = 16;
    ASSERT(!ozayn_protected_data_validate(&pd));
    return 0;
}

/* 34. no algorithm */
TEST(prot_validate_no_algorithm)
{
    ozayn_protected_data_t pd;
    memset(&pd, 0, sizeof(pd));
    pd.format_version = OZAYN_PROT_CURRENT_VERSION;
    pd.algorithm = OZAYN_PROT_ALG_NONE;
    pd.ciphertext_len = 32;
    pd.nonce_len = 12;
    pd.tag_len = 16;
    ASSERT(!ozayn_protected_data_validate(&pd));
    return 0;
}

/* 35. zero ciphertext */
TEST(prot_validate_zero_ciphertext)
{
    ozayn_protected_data_t pd;
    memset(&pd, 0, sizeof(pd));
    pd.format_version = OZAYN_PROT_CURRENT_VERSION;
    pd.algorithm = OZAYN_PROT_ALG_AES_256_GCM;
    pd.ciphertext_len = 0;
    pd.nonce_len = 12;
    pd.tag_len = 16;
    ASSERT(!ozayn_protected_data_validate(&pd));
    return 0;
}

/* 36. zero nonce */
TEST(prot_validate_zero_nonce)
{
    ozayn_protected_data_t pd;
    memset(&pd, 0, sizeof(pd));
    pd.format_version = OZAYN_PROT_CURRENT_VERSION;
    pd.algorithm = OZAYN_PROT_ALG_AES_256_GCM;
    pd.ciphertext_len = 32;
    pd.nonce_len = 0;
    pd.tag_len = 16;
    ASSERT(!ozayn_protected_data_validate(&pd));
    return 0;
}

/* 37. zero tag */
TEST(prot_validate_zero_tag)
{
    ozayn_protected_data_t pd;
    memset(&pd, 0, sizeof(pd));
    pd.format_version = OZAYN_PROT_CURRENT_VERSION;
    pd.algorithm = OZAYN_PROT_ALG_AES_256_GCM;
    pd.ciphertext_len = 32;
    pd.nonce_len = 12;
    pd.tag_len = 0;
    ASSERT(!ozayn_protected_data_validate(&pd));
    return 0;
}

/* ============================================================
 * NAME HELPER TESTS
 * ============================================================ */

/* 38. result name helper */
TEST(prot_names_result)
{
    ASSERT_STR_EQ(ozayn_prot_result_name(OZAYN_PROT_OK), "PROT_OK");
    ASSERT_STR_EQ(ozayn_prot_result_name(OZAYN_PROT_ERR_NULL), "PROT_NULL");
    ASSERT_STR_EQ(ozayn_prot_result_name(OZAYN_PROT_ERR_AUTH_FAILED), "PROT_AUTH_FAILED");
    ASSERT_STR_EQ(ozayn_prot_result_name(-999), "UNKNOWN");
    return 0;
}

/* 39. state name helper */
TEST(prot_names_state)
{
    ASSERT_STR_EQ(ozayn_prot_state_name(OZAYN_PROT_STATE_UNINITIALIZED), "UNINITIALIZED");
    ASSERT_STR_EQ(ozayn_prot_state_name(OZAYN_PROT_STATE_READY), "READY");
    ASSERT_STR_EQ(ozayn_prot_state_name(OZAYN_PROT_STATE_STOPPED), "STOPPED");
    ASSERT_STR_EQ(ozayn_prot_state_name((ozayn_prot_state_t)99), "UNKNOWN");
    return 0;
}

/* 40. algorithm name helper */
TEST(prot_names_algorithm)
{
    ASSERT_STR_EQ(ozayn_prot_algorithm_name_enum(OZAYN_PROT_ALG_NONE), "none");
    ASSERT_STR_EQ(ozayn_prot_algorithm_name_enum(OZAYN_PROT_ALG_AES_256_GCM), "aes-256-gcm");
    ASSERT_STR_EQ(ozayn_prot_algorithm_name_enum((ozayn_prot_algorithm_t)99), "unknown");
    return 0;
}

/* ============================================================
 * QUERY TESTS
 * ============================================================ */

/* 41. is_available when ready */
TEST(prot_query_available)
{
    ozayn_protection_provider_t provider;
    ozayn_prot_mock_config_t cfg = {0};
    ozayn_prot_mock_create(&provider, &cfg);
    ozayn_prot_init(&provider);

    ASSERT(ozayn_prot_is_available(&provider));
    ASSERT_STR_EQ(ozayn_prot_algorithm_name(&provider), "aes-256-gcm (mock)");

    ozayn_prot_shutdown(&provider);
    return 0;
}

/* 42. is_available when not ready */
TEST(prot_query_not_available)
{
    ozayn_protection_provider_t provider;
    ozayn_prot_mock_config_t cfg = {0};
    ozayn_prot_mock_create(&provider, &cfg);

    ASSERT(!ozayn_prot_is_available(&provider));
    ASSERT_STR_EQ(ozayn_prot_algorithm_name(&provider), "aes-256-gcm (mock)");
    return 0;
}

/* 43. is_available null */
TEST(prot_query_null)
{
    ASSERT(!ozayn_prot_is_available(NULL));
    ASSERT_STR_EQ(ozayn_prot_algorithm_name(NULL), "null");
    return 0;
}

/* ============================================================
 * MOCK INTEGRITY TESTS
 * ============================================================ */

/* 44. mock tag verify on clean data */
TEST(prot_mock_tag_clean)
{
    ozayn_protection_provider_t provider;
    ozayn_prot_mock_config_t cfg = {0};
    ozayn_prot_mock_create(&provider, &cfg);
    ozayn_prot_init(&provider);

    ozayn_prot_request_t req = _valid_request();
    ozayn_protected_data_t protected;
    ASSERT_EQ(ozayn_prot_protect(&provider, &req, &protected), OZAYN_PROT_OK);
    ASSERT(ozayn_prot_mock_verify_tag(&protected));

    ozayn_prot_shutdown(&provider);
    return 0;
}

/* 45. mock tag verify on tampered data */
TEST(prot_mock_tag_tampered)
{
    ozayn_protection_provider_t provider;
    ozayn_prot_mock_config_t cfg = {0};
    ozayn_prot_mock_create(&provider, &cfg);
    ozayn_prot_init(&provider);

    ozayn_prot_request_t req = _valid_request();
    ozayn_protected_data_t protected;
    ASSERT_EQ(ozayn_prot_protect(&provider, &req, &protected), OZAYN_PROT_OK);

    /* Tamper */
    protected.ciphertext[4] ^= 0x55;
    ASSERT(!ozayn_prot_mock_verify_tag(&protected));

    ozayn_prot_shutdown(&provider);
    return 0;
}

/* 46. mock tag verify null */
TEST(prot_mock_tag_null)
{
    ASSERT(!ozayn_prot_mock_verify_tag(NULL));
    return 0;
}

/* ============================================================
 * EXISTING STORAGE COMPATIBILITY
 * ============================================================ */

/* 47. protection layer does not break Step 05 storage */
TEST(prot_storage_compatibility)
{
    ozayn_protection_provider_t prot;
    ozayn_prot_mock_config_t cfg = {0};
    ozayn_prot_mock_create(&prot, &cfg);
    ozayn_prot_init(&prot);

    /* Protect data */
    ozayn_prot_request_t req = _valid_request();
    ozayn_protected_data_t protected;
    ASSERT_EQ(ozayn_prot_protect(&prot, &req, &protected), OZAYN_PROT_OK);

    /* Protected data is a valid struct that could be serialized to storage */
    ASSERT(ozayn_protected_data_validate(&protected));
    ASSERT_EQ(protected.format_version, OZAYN_PROT_CURRENT_VERSION);
    ASSERT(protected.ciphertext_len > 0);
    ASSERT(protected.nonce_len > 0);
    ASSERT(protected.tag_len > 0);

    /* Unprotect works */
    ozayn_unprot_result_t unprot;
    ASSERT_EQ(ozayn_prot_unprotect(&prot, &protected, &unprot), OZAYN_PROT_OK);
    ASSERT_EQ(unprot.plaintext_len, req.plaintext_len);
    ASSERT_EQ(memcmp(unprot.plaintext, req.plaintext, req.plaintext_len), 0);

    ozayn_prot_shutdown(&prot);
    return 0;
}

/* 48. large data protection */
TEST(prot_large_data)
{
    ozayn_protection_provider_t provider;
    ozayn_prot_mock_config_t cfg = {0};
    ozayn_prot_mock_create(&provider, &cfg);
    ozayn_prot_init(&provider);

    uint8_t large[4096];
    for (int i = 0; i < 4096; i++)
        large[i] = (uint8_t)(i & 0xFF);

    ozayn_prot_request_t req;
    memset(&req, 0, sizeof(req));
    req.plaintext = large;
    req.plaintext_len = sizeof(large);
    req.category = OZAYN_DATA_CATEGORY_DOCUMENTS;
    req.classification = OZAYN_SEC_LEVEL_SENSITIVE;
    req.object_id = "large-doc-001";

    ozayn_protected_data_t protected;
    ASSERT_EQ(ozayn_prot_protect(&provider, &req, &protected), OZAYN_PROT_OK);
    ASSERT_EQ(protected.ciphertext_len, sizeof(large));

    ozayn_unprot_result_t unprot;
    ASSERT_EQ(ozayn_prot_unprotect(&provider, &protected, &unprot), OZAYN_PROT_OK);
    ASSERT_EQ(unprot.plaintext_len, sizeof(large));
    ASSERT_EQ(memcmp(unprot.plaintext, large, sizeof(large)), 0);

    ozayn_prot_shutdown(&provider);
    return 0;
}

/* 49. multiple protect/unprotect cycles */
TEST(prot_multiple_cycles)
{
    ozayn_protection_provider_t provider;
    ozayn_prot_mock_config_t cfg = {0};
    ozayn_prot_mock_create(&provider, &cfg);
    ozayn_prot_init(&provider);

    for (int i = 0; i < 10; i++) {
        ozayn_prot_request_t req = _valid_request();
        char id[32];
        snprintf(id, sizeof(id), "cycle-%d", i);
        req.object_id = id;

        ozayn_protected_data_t protected;
        ASSERT_EQ(ozayn_prot_protect(&provider, &req, &protected), OZAYN_PROT_OK);

        ozayn_unprot_result_t unprot;
        ASSERT_EQ(ozayn_prot_unprotect(&provider, &protected, &unprot), OZAYN_PROT_OK);
        ASSERT_EQ(unprot.plaintext_len, req.plaintext_len);
        ASSERT_EQ(memcmp(unprot.plaintext, req.plaintext, req.plaintext_len), 0);
    }

    ozayn_prot_shutdown(&provider);
    return 0;
}

/* 50. empty data round-trip */
TEST(prot_empty_data)
{
    ozayn_protection_provider_t provider;
    ozayn_prot_mock_config_t cfg = {0};
    ozayn_prot_mock_create(&provider, &cfg);
    ozayn_prot_init(&provider);

    uint8_t single_byte = 0x42;
    ozayn_prot_request_t req;
    memset(&req, 0, sizeof(req));
    req.plaintext = &single_byte;
    req.plaintext_len = 1;
    req.category = OZAYN_DATA_CATEGORY_USER_PREFERENCES;
    req.classification = OZAYN_SEC_LEVEL_PUBLIC;
    req.object_id = "single-byte";

    ozayn_protected_data_t protected;
    ASSERT_EQ(ozayn_prot_protect(&provider, &req, &protected), OZAYN_PROT_OK);

    ozayn_unprot_result_t unprot;
    ASSERT_EQ(ozayn_prot_unprotect(&provider, &protected, &unprot), OZAYN_PROT_OK);
    ASSERT_EQ(unprot.plaintext_len, (size_t)1);
    ASSERT_EQ(*unprot.plaintext, 0x42);

    ozayn_prot_shutdown(&provider);
    return 0;
}

/* ============================================================
 * FAIL-CLOSED TESTS
 * ============================================================ */

/* 51. no plaintext fallback on protect failure */
TEST(prot_fail_closed_no_fallback)
{
    ozayn_protection_provider_t provider;
    ozayn_prot_mock_config_t cfg = {0};
    cfg.fail_protect = 1;
    ozayn_prot_mock_create(&provider, &cfg);
    ozayn_prot_init(&provider);

    ozayn_prot_request_t req = _valid_request();
    ozayn_protected_data_t out;
    memset(&out, 0, sizeof(out));

    ozayn_prot_result_t r = ozayn_prot_protect(&provider, &req, &out);
    ASSERT_EQ(r, OZAYN_PROT_ERR_PROTECTION_FAILED);

    /* out must remain zeroed — no partial data leaked */
    ASSERT(out.format_version == 0);
    ASSERT(out.ciphertext_len == 0);

    ozayn_prot_shutdown(&provider);
    return 0;
}

/* 52. no plaintext fallback on unprotect failure */
TEST(prot_fail_closed_unprotect)
{
    ozayn_protection_provider_t provider;
    ozayn_prot_mock_config_t cfg = {0};
    cfg.fail_unprotect = 1;
    ozayn_prot_mock_create(&provider, &cfg);
    ozayn_prot_init(&provider);

    ozayn_protected_data_t fake_pd;
    memset(&fake_pd, 0, sizeof(fake_pd));
    fake_pd.format_version = OZAYN_PROT_CURRENT_VERSION;
    fake_pd.algorithm = OZAYN_PROT_ALG_AES_256_GCM;
    fake_pd.ciphertext_len = 16;

    ozayn_unprot_result_t out;
    memset(&out, 0xFF, sizeof(out));

    ozayn_prot_result_t r = ozayn_prot_unprotect(&provider, &fake_pd, &out);
    ASSERT_EQ(r, OZAYN_PROT_ERR_UNPROTECTION_FAILED);
    ASSERT(out.plaintext == NULL);

    ozayn_prot_shutdown(&provider);
    return 0;
}

/* 53. no secret in protected data struct */
TEST(prot_no_key_in_protected)
{
    ozayn_protection_provider_t provider;
    ozayn_prot_mock_config_t cfg = {0};
    ozayn_prot_mock_create(&provider, &cfg);
    ozayn_prot_init(&provider);

    ozayn_prot_request_t req = _valid_request();
    ozayn_protected_data_t protected;
    ASSERT_EQ(ozayn_prot_protect(&provider, &req, &protected), OZAYN_PROT_OK);

    /* Verify struct does not contain obvious key material (mock key) */
    int has_mock_key = 0;
    const uint8_t *bytes = (const uint8_t *)&protected;
    for (size_t i = 0; i < sizeof(protected) - 32; i++) {
        if (memcmp(&bytes[i], "OZYN", 4) == 0) {
            has_mock_key = 1;
            break;
        }
    }
    ASSERT(!has_mock_key);

    ozayn_prot_shutdown(&provider);
    return 0;
}

/* 54. algorithm enum validation */
TEST(prot_algorithm_enums)
{
    /* Verify the enum values we defined match expectations */
    ASSERT_EQ((int)OZAYN_PROT_ALG_NONE, 0);
    ASSERT_EQ((int)OZAYN_PROT_ALG_AES_256_GCM, 1);
    ASSERT_EQ((int)OZAYN_PROT_ALG_CHACHA20_POLY1305, 2);
    return 0;
}

/* 55. error code enum validation */
TEST(prot_error_enums)
{
    /* Verify error codes are distinct and negative */
    ASSERT(OZAYN_PROT_ERR_NULL < 0);
    ASSERT(OZAYN_PROT_ERR_NOT_INITIALIZED < 0);
    ASSERT(OZAYN_PROT_ERR_INVALID_REQUEST < 0);
    ASSERT(OZAYN_PROT_ERR_PROTECTION_FAILED < 0);
    ASSERT(OZAYN_PROT_ERR_UNPROTECTION_FAILED < 0);
    ASSERT(OZAYN_PROT_ERR_AUTH_FAILED < 0);

    /* All distinct */
    ASSERT(OZAYN_PROT_ERR_NULL != OZAYN_PROT_ERR_NOT_INITIALIZED);
    ASSERT(OZAYN_PROT_ERR_PROTECTION_FAILED != OZAYN_PROT_ERR_UNPROTECTION_FAILED);
    ASSERT(OZAYN_PROT_ERR_AUTH_FAILED != OZAYN_PROT_ERR_INTEGRITY);

    return 0;
}

/* 56. state enum validation */
TEST(prot_state_enums)
{
    ASSERT_EQ((int)OZAYN_PROT_STATE_UNINITIALIZED, 0);
    ASSERT_EQ((int)OZAYN_PROT_STATE_INITIALIZED, 1);
    ASSERT_EQ((int)OZAYN_PROT_STATE_READY, 2);
    ASSERT_EQ((int)OZAYN_PROT_STATE_SHUTTING_DOWN, 3);
    ASSERT_EQ((int)OZAYN_PROT_STATE_STOPPED, 4);
    return 0;
}

/* 57. metadata in protected data */
TEST(prot_metadata_in_protected)
{
    ozayn_protection_provider_t provider;
    ozayn_prot_mock_config_t cfg = {0};
    ozayn_prot_mock_create(&provider, &cfg);
    ozayn_prot_init(&provider);

    ozayn_prot_request_t req = _valid_request();
    req.category = OZAYN_DATA_CATEGORY_SECURITY_EVENTS;
    req.classification = OZAYN_SEC_LEVEL_HIGHLY_SENSITIVE;

    ozayn_protected_data_t protected;
    ASSERT_EQ(ozayn_prot_protect(&provider, &req, &protected), OZAYN_PROT_OK);

    /* Metadata must be non-secret and accessible */
    ASSERT_STR_EQ(protected.object_id, _test_id);
    ASSERT_EQ((int)protected.data_category, OZAYN_DATA_CATEGORY_SECURITY_EVENTS);
    ASSERT_EQ((int)protected.data_classification, OZAYN_SEC_LEVEL_HIGHLY_SENSITIVE);
    ASSERT(protected.format_version > 0);
    ASSERT(protected.algorithm > 0);

    ozayn_prot_shutdown(&provider);
    return 0;
}

/* 58. format version constant */
TEST(prot_format_version)
{
    ASSERT_EQ(OZAYN_PROT_FORMAT_VERSION_1, 1);
    ASSERT_EQ(OZAYN_PROT_CURRENT_VERSION, OZAYN_PROT_FORMAT_VERSION_1);
    return 0;
}

/* ============================================================
 * TEST REGISTRATION
 * ============================================================ */
void run_protection_provider_tests(void)
{
    printf("\n=== PROTECTION ARCHITECTURE & PROTECTION BOUNDARY (Step 06) ===\n");
    printf("Number of tests: 58\n\n");

    /* Lifecycle (3) */
    RUN(prot_lifecycle_init_shutdown);
    RUN(prot_lifecycle_null_provider);
    RUN(prot_lifecycle_null_ops);

    /* Request validation (8) */
    RUN(prot_request_valid);
    RUN(prot_request_null_plaintext);
    RUN(prot_request_empty_plaintext);
    RUN(prot_request_null_object_id);
    RUN(prot_request_empty_object_id);
    RUN(prot_dispatch_null_provider);
    RUN(prot_dispatch_null_request);
    RUN(prot_dispatch_null_output);

    /* State machine (3) */
    RUN(prot_state_not_initialized);
    RUN(prot_state_not_initialized_unprotect);
    RUN(prot_state_after_shutdown);

    /* Failure modes (8) */
    RUN(prot_failure_protect);
    RUN(prot_failure_unprotect);
    RUN(prot_unsupported_format);
    RUN(prot_unsupported_version);
    RUN(prot_invalid_protected_data);
    RUN(prot_dispatch_null_provider_unprotect);
    RUN(prot_dispatch_null_protected_data);
    RUN(prot_dispatch_null_unprotect_output);

    /* Round-trip (3) */
    RUN(prot_roundtrip_basic);
    RUN(prot_roundtrip_associated_data);
    RUN(prot_not_plaintext);

    /* Tamper / authentication (3) */
    RUN(prot_tamper_ciphertext);
    RUN(prot_tamper_tag);
    RUN(prot_inject_tag_error);

    /* Classification preservation (2) */
    RUN(prot_classification_preserved);
    RUN(prot_category_preserved);

    /* Protected data validation (7) */
    RUN(prot_validate_valid);
    RUN(prot_validate_null);
    RUN(prot_validate_wrong_version);
    RUN(prot_validate_no_algorithm);
    RUN(prot_validate_zero_ciphertext);
    RUN(prot_validate_zero_nonce);
    RUN(prot_validate_zero_tag);

    /* Name helpers (3) */
    RUN(prot_names_result);
    RUN(prot_names_state);
    RUN(prot_names_algorithm);

    /* Query (3) */
    RUN(prot_query_available);
    RUN(prot_query_not_available);
    RUN(prot_query_null);

    /* Mock integrity (3) */
    RUN(prot_mock_tag_clean);
    RUN(prot_mock_tag_tampered);
    RUN(prot_mock_tag_null);

    /* Storage compatibility (1) */
    RUN(prot_storage_compatibility);

    /* Advanced (3) */
    RUN(prot_large_data);
    RUN(prot_multiple_cycles);
    RUN(prot_empty_data);

    /* Fail-closed (3) */
    RUN(prot_fail_closed_no_fallback);
    RUN(prot_fail_closed_unprotect);
    RUN(prot_no_key_in_protected);

    /* Architectural constants (4) */
    RUN(prot_algorithm_enums);
    RUN(prot_error_enums);
    RUN(prot_state_enums);
    RUN(prot_format_version);

    /* Metadata (1) */
    RUN(prot_metadata_in_protected);
}
