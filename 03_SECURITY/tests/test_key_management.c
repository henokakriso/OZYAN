#include "../../tests/test_framework.h"
#include "../key_provider.h"
#include "../key_provider_test.h"
#include "../protection_provider.h"
#include "../protection_provider_sodium.h"
#include <string.h>

/*
 * test_key_management.c — Step 08 Tests (Section 03, Step 08).
 *
 * Tests key management foundation: identifiers, metadata, lifecycle,
 * purpose validation, version handling, and protection integration.
 */

/* ---- Test Keys ---- */
static const uint8_t _test_key[32] = {
    0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
    0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,0x10,
    0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,
    0x19,0x1A,0x1B,0x1C,0x1D,0x1E,0x1F,0x20
};

static const uint8_t _wrong_key[32] = {
    0xFF,0xFE,0xFD,0xFC,0xFB,0xFA,0xF9,0xF8,
    0xF7,0xF6,0xF5,0xF4,0xF3,0xF2,0xF1,0xF0,
    0xEF,0xEE,0xED,0xEC,0xEB,0xEA,0xE9,0xE8,
    0xE7,0xE6,0xE5,0xE4,0xE3,0xE2,0xE1,0xE0
};

/* ============================================================
 * KEY IDENTIFIER TESTS
 * ============================================================ */

/* 1. valid key identifier */
TEST(key_id_valid)
{
    ozayn_key_id_t id;
    ozayn_key_id_set(&id, "OZAYN-DATA-PRIMARY", 1, "production");
    ASSERT_STR_EQ(id.name, "OZAYN-DATA-PRIMARY");
    ASSERT(id.version == 1);
    ASSERT_STR_EQ(id.context, "production");
    return 0;
}

/* 2. key identifier equality */
TEST(key_id_equal)
{
    ozayn_key_id_t a, b;
    ozayn_key_id_set(&a, "KEY-A", 1, "ctx");
    ozayn_key_id_set(&b, "KEY-A", 1, "ctx");
    ASSERT(ozayn_key_id_equal(&a, &b));

    ozayn_key_id_t c;
    ozayn_key_id_set(&c, "KEY-A", 2, "ctx");
    ASSERT(!ozayn_key_id_equal(&a, &c));

    ozayn_key_id_t d;
    ozayn_key_id_set(&d, "KEY-B", 1, "ctx");
    ASSERT(!ozayn_key_id_equal(&a, &d));

    return 0;
}

/* 3. key identifier null */
TEST(key_id_null)
{
    ASSERT(!ozayn_key_id_equal(NULL, NULL));
    ozayn_key_id_t a;
    ozayn_key_id_set(&a, "X", 1, "");
    ASSERT(!ozayn_key_id_equal(NULL, &a));
    ASSERT(!ozayn_key_id_equal(&a, NULL));
    return 0;
}

/* 4. key identifier set null */
TEST(key_id_set_null)
{
    ozayn_key_id_set(NULL, "X", 1, "ctx");
    return 0;
}

/* ============================================================
 * KEY LIFECYCLE TESTS
 * ============================================================ */

/* 5. valid lifecycle transitions */
TEST(key_lifecycle_valid_transitions)
{
    ASSERT(ozayn_key_lifecycle_transition_valid(
        OZAYN_KEY_LIFECYCLE_UNINITIALIZED, OZAYN_KEY_LIFECYCLE_AVAILABLE));
    ASSERT(ozayn_key_lifecycle_transition_valid(
        OZAYN_KEY_LIFECYCLE_AVAILABLE, OZAYN_KEY_LIFECYCLE_ACTIVE));
    ASSERT(ozayn_key_lifecycle_transition_valid(
        OZAYN_KEY_LIFECYCLE_ACTIVE, OZAYN_KEY_LIFECYCLE_RETIRED));
    ASSERT(ozayn_key_lifecycle_transition_valid(
        OZAYN_KEY_LIFECYCLE_ACTIVE, OZAYN_KEY_LIFECYCLE_REVOKED));
    ASSERT(ozayn_key_lifecycle_transition_valid(
        OZAYN_KEY_LIFECYCLE_AVAILABLE, OZAYN_KEY_LIFECYCLE_REVOKED));
    return 0;
}

/* 6. invalid lifecycle transitions */
TEST(key_lifecycle_invalid_transitions)
{
    ASSERT(!ozayn_key_lifecycle_transition_valid(
        OZAYN_KEY_LIFECYCLE_UNINITIALIZED, OZAYN_KEY_LIFECYCLE_ACTIVE));
    ASSERT(!ozayn_key_lifecycle_transition_valid(
        OZAYN_KEY_LIFECYCLE_UNINITIALIZED, OZAYN_KEY_LIFECYCLE_RETIRED));
    ASSERT(!ozayn_key_lifecycle_transition_valid(
        OZAYN_KEY_LIFECYCLE_REVOKED, OZAYN_KEY_LIFECYCLE_ACTIVE));
    ASSERT(!ozayn_key_lifecycle_transition_valid(
        OZAYN_KEY_LIFECYCLE_RETIRED, OZAYN_KEY_LIFECYCLE_ACTIVE));
    return 0;
}

/* 7. lifecycle name helper */
TEST(key_lifecycle_names)
{
    ASSERT_STR_EQ(ozayn_key_lifecycle_name(OZAYN_KEY_LIFECYCLE_UNINITIALIZED), "uninitialized");
    ASSERT_STR_EQ(ozayn_key_lifecycle_name(OZAYN_KEY_LIFECYCLE_ACTIVE), "active");
    ASSERT_STR_EQ(ozayn_key_lifecycle_name(OZAYN_KEY_LIFECYCLE_RETIRED), "retired");
    ASSERT_STR_EQ(ozayn_key_lifecycle_name(OZAYN_KEY_LIFECYCLE_REVOKED), "revoked");
    ASSERT_STR_EQ(ozayn_key_lifecycle_name((ozayn_key_lifecycle_t)99), "unknown");
    return 0;
}

/* ============================================================
 * KEY PURPOSE TESTS
 * ============================================================ */

/* 8. purpose name helper */
TEST(key_purpose_names)
{
    ASSERT_STR_EQ(ozayn_key_purpose_name(OZAYN_KEY_PURPOSE_UNKNOWN), "unknown");
    ASSERT_STR_EQ(ozayn_key_purpose_name(OZAYN_KEY_PURPOSE_DATA_ENCRYPTION), "data-encryption");
    ASSERT_STR_EQ(ozayn_key_purpose_name(OZAYN_KEY_PURPOSE_DATA_DECRYPTION), "data-decryption");
    ASSERT_STR_EQ(ozayn_key_purpose_name(OZAYN_KEY_PURPOSE_AUTH_ENCRYPTION), "auth-encryption");
    ASSERT_STR_EQ(ozayn_key_purpose_name((ozayn_key_purpose_t)99), "unknown");
    return 0;
}

/* ============================================================
 * ERROR NAME TESTS
 * ============================================================ */

/* 9. result name helper */
TEST(key_result_names)
{
    ASSERT_STR_EQ(ozayn_key_result_name(OZAYN_KEY_OK), "KEY_OK");
    ASSERT_STR_EQ(ozayn_key_result_name(OZAYN_KEY_ERR_NULL), "KEY_NULL");
    ASSERT_STR_EQ(ozayn_key_result_name(OZAYN_KEY_ERR_NOT_FOUND), "KEY_NOT_FOUND");
    ASSERT_STR_EQ(ozayn_key_result_name(OZAYN_KEY_ERR_PURPOSE_MISMATCH), "KEY_PURPOSE_MISMATCH");
    ASSERT_STR_EQ(ozayn_key_result_name(OZAYN_KEY_ERR_REVOKED), "KEY_REVOKED");
    ASSERT_STR_EQ(ozayn_key_result_name(OZAYN_KEY_ERR_RETIRED), "KEY_RETIRED");
    ASSERT_STR_EQ(ozayn_key_result_name(-999), "KEY_UNKNOWN");
    return 0;
}

/* ============================================================
 * SINGLE KEY PROVIDER TESTS
 * ============================================================ */

/* 10. single key lifecycle */
TEST(key_single_lifecycle)
{
    ozayn_key_provider_t kp;
    ozayn_key_test_create(&kp, _test_key, 32);
    ASSERT_EQ(ozayn_key_init(&kp), OZAYN_KEY_OK);
    ASSERT(ozayn_key_is_ready(&kp));
    ASSERT(ozayn_key_is_available(&kp));
    ASSERT_EQ(ozayn_key_length(&kp), (size_t)32);

    uint8_t out[32];
    ASSERT_EQ(ozayn_key_get(&kp, out, 32), OZAYN_KEY_OK);
    ASSERT_EQ(memcmp(out, _test_key, 32), 0);

    ozayn_key_shutdown(&kp);
    ASSERT(!ozayn_key_is_ready(&kp));
    return 0;
}

/* 11. single key null provider */
TEST(key_single_null)
{
    ASSERT_EQ(ozayn_key_init(NULL), OZAYN_KEY_ERR_NULL);
    ozayn_key_shutdown(NULL);
    ASSERT(!ozayn_key_is_ready(NULL));
    ASSERT_EQ(ozayn_key_get(NULL, NULL, 0), OZAYN_KEY_ERR_NULL);
    return 0;
}

/* 12. single key not initialized */
TEST(key_single_not_initialized)
{
    ozayn_key_provider_t kp;
    ozayn_key_test_create(&kp, _test_key, 32);
    /* Don't init */

    uint8_t out[32];
    ASSERT_EQ(ozayn_key_get(&kp, out, 32), OZAYN_KEY_ERR_NOT_INITIALIZED);
    return 0;
}

/* 13. single key invalid size */
TEST(key_single_invalid_size)
{
    ozayn_key_provider_t kp;
    ozayn_key_test_create(&kp, _test_key, 32);
    ozayn_key_init(&kp);

    uint8_t out[32];
    ASSERT_EQ(ozayn_key_get(&kp, out, 0), OZAYN_KEY_ERR_INVALID_SIZE);
    ASSERT_EQ(ozayn_key_get(&kp, out, 65), OZAYN_KEY_ERR_INVALID_SIZE);

    ozayn_key_shutdown(&kp);
    return 0;
}

/* ============================================================
 * MANAGED KEY PROVIDER TESTS
 * ============================================================ */

/* 14. managed provider lifecycle */
TEST(key_managed_lifecycle)
{
    ozayn_key_provider_t kp;
    ozayn_key_test_create_managed(&kp);
    ASSERT_EQ(ozayn_key_init(&kp), OZAYN_KEY_OK);
    ASSERT(ozayn_key_is_ready(&kp));
    ASSERT(ozayn_key_is_available(&kp));
    ASSERT_EQ(ozayn_key_count(&kp), 4);

    ozayn_key_shutdown(&kp);
    return 0;
}

/* 15. managed get default active key */
TEST(key_managed_get_default)
{
    ozayn_key_provider_t kp;
    ozayn_key_test_create_managed(&kp);
    ozayn_key_init(&kp);

    uint8_t out[32];
    ASSERT_EQ(ozayn_key_get(&kp, out, 32), OZAYN_KEY_OK);
    /* Should return first active data-encryption key */
    ASSERT(out[0] == 0x01);

    ozayn_key_shutdown(&kp);
    return 0;
}

/* 16. get key by identifier - success */
TEST(key_managed_get_by_id)
{
    ozayn_key_provider_t kp;
    ozayn_key_test_create_managed(&kp);
    ozayn_key_init(&kp);

    ozayn_key_id_t id;
    ozayn_key_id_set(&id, "OZAYN-DATA-PRIMARY", 1, "test");

    uint8_t out[32];
    ASSERT_EQ(ozayn_key_get_by_id(&kp, &id, OZAYN_KEY_PURPOSE_DATA_ENCRYPTION, out, 32),
              OZAYN_KEY_OK);
    ASSERT(out[0] == 0x01);

    ozayn_key_shutdown(&kp);
    return 0;
}

/* 17. get key by identifier - not found */
TEST(key_managed_not_found)
{
    ozayn_key_provider_t kp;
    ozayn_key_test_create_managed(&kp);
    ozayn_key_init(&kp);

    ozayn_key_id_t id;
    ozayn_key_id_set(&id, "NONEXISTENT-KEY", 1, "test");

    uint8_t out[32];
    ASSERT_EQ(ozayn_key_get_by_id(&kp, &id, OZAYN_KEY_PURPOSE_DATA_ENCRYPTION, out, 32),
              OZAYN_KEY_ERR_NOT_FOUND);

    ozayn_key_shutdown(&kp);
    return 0;
}

/* 18. purpose mismatch */
TEST(key_managed_purpose_mismatch)
{
    ozayn_key_provider_t kp;
    ozayn_key_test_create_managed(&kp);
    ozayn_key_init(&kp);

    ozayn_key_id_t id;
    ozayn_key_id_set(&id, "OZAYN-DATA-PRIMARY", 1, "test");

    /* Request auth-encryption purpose for data-encryption key */
    uint8_t out[32];
    ASSERT_EQ(ozayn_key_get_by_id(&kp, &id, OZAYN_KEY_PURPOSE_AUTH_ENCRYPTION, out, 32),
              OZAYN_KEY_ERR_PURPOSE_MISMATCH);

    ozayn_key_shutdown(&kp);
    return 0;
}

/* 19. revoked key rejected */
TEST(key_managed_revoked)
{
    ozayn_key_provider_t kp;
    ozayn_key_test_create_managed(&kp);
    ozayn_key_init(&kp);

    ozayn_key_id_t id;
    ozayn_key_id_set(&id, "OZAYN-DATA-REVOKED", 1, "test");

    uint8_t out[32];
    ASSERT_EQ(ozayn_key_get_by_id(&kp, &id, OZAYN_KEY_PURPOSE_DATA_ENCRYPTION, out, 32),
              OZAYN_KEY_ERR_REVOKED);

    ozayn_key_shutdown(&kp);
    return 0;
}

/* 20. retired key rejected for new encryption */
TEST(key_managed_retired)
{
    ozayn_key_provider_t kp;
    ozayn_key_test_create_managed(&kp);
    ozayn_key_init(&kp);

    /* Retired key has version 0 */
    ozayn_key_id_t id;
    ozayn_key_id_set(&id, "OZAYN-DATA-PRIMARY", 0, "test");

    uint8_t out[32];
    ASSERT_EQ(ozayn_key_get_by_id(&kp, &id, OZAYN_KEY_PURPOSE_DATA_ENCRYPTION, out, 32),
              OZAYN_KEY_ERR_RETIRED);

    ozayn_key_shutdown(&kp);
    return 0;
}

/* 21. key version selection */
TEST(key_managed_version)
{
    ozayn_key_provider_t kp;
    ozayn_key_test_create_managed(&kp);
    ozayn_key_init(&kp);

    /* Version 1 (active) works */
    ozayn_key_id_t id1;
    ozayn_key_id_set(&id1, "OZAYN-DATA-PRIMARY", 1, "test");
    uint8_t out1[32];
    ASSERT_EQ(ozayn_key_get_by_id(&kp, &id1, OZAYN_KEY_PURPOSE_DATA_ENCRYPTION, out1, 32),
              OZAYN_KEY_OK);

    /* Version 0 (retired) fails */
    ozayn_key_id_t id0;
    ozayn_key_id_set(&id0, "OZAYN-DATA-PRIMARY", 0, "test");
    uint8_t out0[32];
    ASSERT_EQ(ozayn_key_get_by_id(&kp, &id0, OZAYN_KEY_PURPOSE_DATA_ENCRYPTION, out0, 32),
              OZAYN_KEY_ERR_RETIRED);

    ozayn_key_shutdown(&kp);
    return 0;
}

/* 22. key metadata */
TEST(key_managed_metadata)
{
    ozayn_key_provider_t kp;
    ozayn_key_test_create_managed(&kp);
    ozayn_key_init(&kp);

    ozayn_key_id_t id;
    ozayn_key_id_set(&id, "OZAYN-DATA-PRIMARY", 1, "test");

    ozayn_key_metadata_t meta;
    ASSERT_EQ(ozayn_key_get_metadata(&kp, &id, &meta), OZAYN_KEY_OK);
    ASSERT(meta.is_valid);
    ASSERT_EQ(meta.key_length, (uint32_t)32);
    ASSERT_EQ(meta.lifecycle, OZAYN_KEY_LIFECYCLE_ACTIVE);
    ASSERT_EQ(meta.purpose, OZAYN_KEY_PURPOSE_DATA_ENCRYPTION);
    ASSERT_STR_EQ(meta.id.name, "OZAYN-DATA-PRIMARY");
    ASSERT(meta.id.version == 1);

    ozayn_key_shutdown(&kp);
    return 0;
}

/* 23. metadata for nonexistent key */
TEST(key_managed_metadata_not_found)
{
    ozayn_key_provider_t kp;
    ozayn_key_test_create_managed(&kp);
    ozayn_key_init(&kp);

    ozayn_key_id_t id;
    ozayn_key_id_set(&id, "NONEXISTENT", 1, "test");

    ozayn_key_metadata_t meta;
    ASSERT_EQ(ozayn_key_get_metadata(&kp, &id, &meta), OZAYN_KEY_ERR_NOT_FOUND);

    ozayn_key_shutdown(&kp);
    return 0;
}

/* 24. lifecycle transition */
TEST(key_managed_transition)
{
    ozayn_key_provider_t kp;
    ozayn_key_test_create_managed(&kp);
    ozayn_key_init(&kp);

    ozayn_key_id_t id;
    ozayn_key_id_set(&id, "OZAYN-DATA-PRIMARY", 1, "test");

    /* Retire the active key */
    ASSERT_EQ(ozayn_key_transition(&kp, &id, OZAYN_KEY_LIFECYCLE_RETIRED), OZAYN_KEY_OK);

    /* Verify it's retired */
    ozayn_key_metadata_t meta;
    ASSERT_EQ(ozayn_key_get_metadata(&kp, &id, &meta), OZAYN_KEY_OK);
    ASSERT_EQ(meta.lifecycle, OZAYN_KEY_LIFECYCLE_RETIRED);

    /* Can't use retired key for new operations */
    uint8_t out[32];
    ASSERT_EQ(ozayn_key_get_by_id(&kp, &id, OZAYN_KEY_PURPOSE_DATA_ENCRYPTION, out, 32),
              OZAYN_KEY_ERR_RETIRED);

    ozayn_key_shutdown(&kp);
    return 0;
}

/* 25. invalid lifecycle transition */
TEST(key_managed_invalid_transition)
{
    ozayn_key_provider_t kp;
    ozayn_key_test_create_managed(&kp);
    ozayn_key_init(&kp);

    ozayn_key_id_t id;
    ozayn_key_id_set(&id, "OZAYN-DATA-PRIMARY", 1, "test");

    /* Can't go from ACTIVE back to UNINITIALIZED */
    ASSERT_EQ(ozayn_key_transition(&kp, &id, OZAYN_KEY_LIFECYCLE_UNINITIALIZED),
              OZAYN_KEY_ERR_LIFECYCLE_INVALID);

    /* Verify still active */
    ozayn_key_metadata_t meta;
    ASSERT_EQ(ozayn_key_get_metadata(&kp, &id, &meta), OZAYN_KEY_OK);
    ASSERT_EQ(meta.lifecycle, OZAYN_KEY_LIFECYCLE_ACTIVE);

    ozayn_key_shutdown(&kp);
    return 0;
}

/* ============================================================
 * DISPATCH ERROR TESTS
 * ============================================================ */

/* 26. get_by_id null */
TEST(key_dispatch_null_id)
{
    ozayn_key_provider_t kp;
    ozayn_key_test_create_managed(&kp);
    ozayn_key_init(&kp);

    uint8_t out[32];
    ASSERT_EQ(ozayn_key_get_by_id(&kp, NULL, OZAYN_KEY_PURPOSE_DATA_ENCRYPTION, out, 32),
              OZAYN_KEY_ERR_NULL);
    ASSERT_EQ(ozayn_key_get_by_id(NULL, NULL, OZAYN_KEY_PURPOSE_DATA_ENCRYPTION, out, 32),
              OZAYN_KEY_ERR_NULL);

    ozayn_key_shutdown(&kp);
    return 0;
}

/* 27. get_by_id unknown purpose */
TEST(key_dispatch_unknown_purpose)
{
    ozayn_key_provider_t kp;
    ozayn_key_test_create_managed(&kp);
    ozayn_key_init(&kp);

    ozayn_key_id_t id;
    ozayn_key_id_set(&id, "OZAYN-DATA-PRIMARY", 1, "test");

    uint8_t out[32];
    ASSERT_EQ(ozayn_key_get_by_id(&kp, &id, OZAYN_KEY_PURPOSE_UNKNOWN, out, 32),
              OZAYN_KEY_ERR_PURPOSE_MISMATCH);

    ozayn_key_shutdown(&kp);
    return 0;
}

/* 28. get_metadata null */
TEST(key_dispatch_metadata_null)
{
    ozayn_key_provider_t kp;
    ozayn_key_test_create_managed(&kp);
    ozayn_key_init(&kp);

    ozayn_key_id_t id;
    ozayn_key_id_set(&id, "X", 1, "");

    ASSERT_EQ(ozayn_key_get_metadata(&kp, NULL, NULL), OZAYN_KEY_ERR_NULL);
    ASSERT_EQ(ozayn_key_get_metadata(&kp, &id, NULL), OZAYN_KEY_ERR_NULL);
    ASSERT_EQ(ozayn_key_get_metadata(NULL, &id, NULL), OZAYN_KEY_ERR_NULL);

    ozayn_key_shutdown(&kp);
    return 0;
}

/* 29. transition null */
TEST(key_dispatch_transition_null)
{
    ozayn_key_provider_t kp;
    ozayn_key_test_create_managed(&kp);
    ozayn_key_init(&kp);

    ASSERT_EQ(ozayn_key_transition(&kp, NULL, OZAYN_KEY_LIFECYCLE_ACTIVE), OZAYN_KEY_ERR_NULL);
    ASSERT_EQ(ozayn_key_transition(NULL, NULL, OZAYN_KEY_LIFECYCLE_ACTIVE), OZAYN_KEY_ERR_NULL);

    ozayn_key_shutdown(&kp);
    return 0;
}

/* 30. count before init */
TEST(key_dispatch_count_not_ready)
{
    ozayn_key_provider_t kp;
    ozayn_key_test_create_managed(&kp);
    /* Don't init */
    ASSERT_EQ(ozayn_key_count(&kp), 0);
    return 0;
}

/* ============================================================
 * KEY LEAKAGE TESTS
 * ============================================================ */

/* 31. key not in metadata */
TEST(key_no_leakage_metadata)
{
    ozayn_key_provider_t kp;
    ozayn_key_test_create_managed(&kp);
    ozayn_key_init(&kp);

    ozayn_key_id_t id;
    ozayn_key_id_set(&id, "OZAYN-DATA-PRIMARY", 1, "test");

    ozayn_key_metadata_t meta;
    ASSERT_EQ(ozayn_key_get_metadata(&kp, &id, &meta), OZAYN_KEY_OK);

    /* Metadata must not contain actual key bytes */
    const uint8_t *bytes = (const uint8_t *)&meta;
    int has_key = 0;
    for (size_t i = 0; i + 32 <= sizeof(meta); i++) {
        if (memcmp(&bytes[i], _test_key, 32) == 0) {
            has_key = 1;
            break;
        }
    }
    ASSERT(!has_key);

    ozayn_key_shutdown(&kp);
    return 0;
}

/* 32. key not in identifier */
TEST(key_no_leakage_id)
{
    ozayn_key_id_t id;
    ozayn_key_id_set(&id, "OZAYN-DATA-PRIMARY", 1, "test");

    /* Identifier must not contain actual key bytes */
    const uint8_t *bytes = (const uint8_t *)&id;
    int has_key = 0;
    for (size_t i = 0; i + 32 <= sizeof(id); i++) {
        if (memcmp(&bytes[i], _test_key, 32) == 0) {
            has_key = 1;
            break;
        }
    }
    ASSERT(!has_key);
    return 0;
}

/* ============================================================
 * PROTECTION INTEGRATION TESTS
 * ============================================================ */

/* 33. managed key with encryption round-trip */
TEST(key_managed_encrypt_roundtrip)
{
    ozayn_key_provider_t kp;
    ozayn_key_test_create_managed(&kp);
    ozayn_key_init(&kp);

    ozayn_protection_provider_t prot;
    ozayn_prot_sodium_create(&prot, &kp);
    ozayn_prot_init(&prot);

    const char *data = "Test data protected with managed key";
    ozayn_prot_request_t req;
    memset(&req, 0, sizeof(req));
    req.plaintext = (const uint8_t *)data;
    req.plaintext_len = sizeof(data);
    req.category = OZAYN_DATA_CATEGORY_AUTH_INFO;
    req.classification = OZAYN_SEC_LEVEL_HIGHLY_SENSITIVE;
    req.object_id = "managed-key-test";

    ozayn_protected_data_t pd;
    ASSERT_EQ(ozayn_prot_protect(&prot, &req, &pd), OZAYN_KEY_OK);

    ozayn_unprot_result_t result;
    ASSERT_EQ(ozayn_prot_unprotect(&prot, &pd, &result), OZAYN_KEY_OK);
    ASSERT_EQ(result.plaintext_len, req.plaintext_len);
    ASSERT_EQ(memcmp(result.plaintext, req.plaintext, req.plaintext_len), 0);

    ozayn_prot_shutdown(&prot);
    ozayn_key_shutdown(&kp);
    return 0;
}

/* 34. wrong key cannot decrypt */
TEST(key_managed_wrong_key_cannot_decrypt)
{
    /* Encrypt with managed key */
    ozayn_key_provider_t kp;
    ozayn_key_test_create_managed(&kp);
    ozayn_key_init(&kp);

    ozayn_protection_provider_t prot;
    ozayn_prot_sodium_create(&prot, &kp);
    ozayn_prot_init(&prot);

    const char *data = "Protected with managed key";
    ozayn_prot_request_t req;
    memset(&req, 0, sizeof(req));
    req.plaintext = (const uint8_t *)data;
    req.plaintext_len = sizeof(data);
    req.category = OZAYN_DATA_CATEGORY_AUTH_INFO;
    req.classification = OZAYN_SEC_LEVEL_SENSITIVE;
    req.object_id = "wrong-key-test";

    ozayn_protected_data_t pd;
    ASSERT_EQ(ozayn_prot_protect(&prot, &req, &pd), OZAYN_KEY_OK);
    ozayn_prot_shutdown(&prot);
    ozayn_key_shutdown(&kp);

    /* Try with different key */
    ozayn_key_provider_t kp2;
    ozayn_key_test_create(&kp2, _wrong_key, 32);
    ozayn_key_init(&kp2);

    ozayn_protection_provider_t prot2;
    ozayn_prot_sodium_create(&prot2, &kp2);
    ozayn_prot_init(&prot2);

    ozayn_unprot_result_t result;
    ASSERT_EQ(ozayn_prot_unprotect(&prot2, &pd, &result), OZAYN_PROT_ERR_AUTH_FAILED);

    ozayn_prot_shutdown(&prot2);
    ozayn_key_shutdown(&kp2);
    return 0;
}

/* 35. key version in metadata matches encryption */
TEST(key_managed_version_matches)
{
    ozayn_key_provider_t kp;
    ozayn_key_test_create_managed(&kp);
    ozayn_key_init(&kp);

    /* Get metadata for active key */
    ozayn_key_id_t id;
    ozayn_key_id_set(&id, "OZAYN-DATA-PRIMARY", 1, "test");

    ozayn_key_metadata_t meta;
    ASSERT_EQ(ozayn_key_get_metadata(&kp, &id, &meta), OZAYN_KEY_OK);
    ASSERT(meta.id.version == 1);
    ASSERT(meta.key_length == 32);

    /* Verify we can encrypt with this key */
    uint8_t key_out[32];
    ASSERT_EQ(ozayn_key_get_by_id(&kp, &id, OZAYN_KEY_PURPOSE_DATA_ENCRYPTION, key_out, 32),
              OZAYN_KEY_OK);

    ozayn_key_shutdown(&kp);
    return 0;
}

/* ============================================================
 * ENUM VALIDATION TESTS
 * ============================================================ */

/* 36. error codes distinct */
TEST(key_error_codes_distinct)
{
    ASSERT(OZAYN_KEY_OK == 0);
    ASSERT(OZAYN_KEY_ERR_NULL < 0);
    ASSERT(OZAYN_KEY_ERR_NOT_FOUND < 0);
    ASSERT(OZAYN_KEY_ERR_PURPOSE_MISMATCH < 0);
    ASSERT(OZAYN_KEY_ERR_REVOKED < 0);
    ASSERT(OZAYN_KEY_ERR_RETIRED < 0);

    ASSERT(OZAYN_KEY_ERR_NULL != OZAYN_KEY_ERR_NOT_FOUND);
    ASSERT(OZAYN_KEY_ERR_PURPOSE_MISMATCH != OZAYN_KEY_ERR_REVOKED);

    return 0;
}

/* 37. lifecycle enum values */
TEST(key_lifecycle_enums)
{
    ASSERT_EQ((int)OZAYN_KEY_LIFECYCLE_UNINITIALIZED, 0);
    ASSERT_EQ((int)OZAYN_KEY_LIFECYCLE_AVAILABLE, 1);
    ASSERT_EQ((int)OZAYN_KEY_LIFECYCLE_ACTIVE, 2);
    ASSERT_EQ((int)OZAYN_KEY_LIFECYCLE_RETIRED, 3);
    ASSERT_EQ((int)OZAYN_KEY_LIFECYCLE_REVOKED, 4);
    ASSERT_EQ((int)OZAYN_KEY_LIFECYCLE_INVALID, 5);
    return 0;
}

/* 38. purpose enum values */
TEST(key_purpose_enums)
{
    ASSERT_EQ((int)OZAYN_KEY_PURPOSE_UNKNOWN, 0);
    ASSERT_EQ((int)OZAYN_KEY_PURPOSE_DATA_ENCRYPTION, 1);
    ASSERT_EQ((int)OZAYN_KEY_PURPOSE_DATA_DECRYPTION, 2);
    return 0;
}

/* 39. key count */
TEST(key_managed_count)
{
    ozayn_key_provider_t kp;
    ozayn_key_test_create_managed(&kp);
    ozayn_key_init(&kp);

    ASSERT_EQ(ozayn_key_count(&kp), 4);

    ozayn_key_shutdown(&kp);
    return 0;
}

/* 40. transition for nonexistent key */
TEST(key_transition_not_found)
{
    ozayn_key_provider_t kp;
    ozayn_key_test_create_managed(&kp);
    ozayn_key_init(&kp);

    ozayn_key_id_t id;
    ozayn_key_id_set(&id, "NONEXISTENT", 1, "test");

    ASSERT_EQ(ozayn_key_transition(&kp, &id, OZAYN_KEY_LIFECYCLE_RETIRED),
              OZAYN_KEY_ERR_NOT_FOUND);

    ozayn_key_shutdown(&kp);
    return 0;
}

/* ============================================================
 * TEST REGISTRATION
 * ============================================================ */
void run_key_management_tests(void)
{
    printf("\n=== KEY MANAGEMENT FOUNDATION (Step 08) ===\n");
    printf("Number of tests: 40\n\n");

    /* Key Identifier (4) */
    RUN(key_id_valid);
    RUN(key_id_equal);
    RUN(key_id_null);
    RUN(key_id_set_null);

    /* Lifecycle (3) */
    RUN(key_lifecycle_valid_transitions);
    RUN(key_lifecycle_invalid_transitions);
    RUN(key_lifecycle_names);

    /* Purpose (1) */
    RUN(key_purpose_names);

    /* Error names (1) */
    RUN(key_result_names);

    /* Single key provider (4) */
    RUN(key_single_lifecycle);
    RUN(key_single_null);
    RUN(key_single_not_initialized);
    RUN(key_single_invalid_size);

    /* Managed key provider (12) */
    RUN(key_managed_lifecycle);
    RUN(key_managed_get_default);
    RUN(key_managed_get_by_id);
    RUN(key_managed_not_found);
    RUN(key_managed_purpose_mismatch);
    RUN(key_managed_revoked);
    RUN(key_managed_retired);
    RUN(key_managed_version);
    RUN(key_managed_metadata);
    RUN(key_managed_metadata_not_found);
    RUN(key_managed_transition);
    RUN(key_managed_invalid_transition);

    /* Dispatch errors (5) */
    RUN(key_dispatch_null_id);
    RUN(key_dispatch_unknown_purpose);
    RUN(key_dispatch_metadata_null);
    RUN(key_dispatch_transition_null);
    RUN(key_dispatch_count_not_ready);

    /* Key leakage (2) */
    RUN(key_no_leakage_metadata);
    RUN(key_no_leakage_id);

    /* Protection integration (3) */
    RUN(key_managed_encrypt_roundtrip);
    RUN(key_managed_wrong_key_cannot_decrypt);
    RUN(key_managed_version_matches);

    /* Enum validation (3) */
    RUN(key_error_codes_distinct);
    RUN(key_lifecycle_enums);
    RUN(key_purpose_enums);

    /* Additional (2) */
    RUN(key_managed_count);
    RUN(key_transition_not_found);
}
