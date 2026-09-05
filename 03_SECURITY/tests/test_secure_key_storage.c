#include "../../tests/test_framework.h"
#include "../secure_key_storage.h"
#include "../secure_key_storage_test.h"
#include "../key_provider.h"
#include <string.h>

/*
 * test_secure_key_storage.c — Step 09 Tests (Section 03, Step 09).
 *
 * Tests secure key storage: store, load, exists, remove, metadata,
 * error handling, fail-closed, and security properties.
 */

/* ---- Test Keys ---- */
static const uint8_t _test_key[32] = {
    0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
    0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,0x10,
    0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,
    0x19,0x1A,0x1B,0x1C,0x1D,0x1E,0x1F,0x20
};

static const uint8_t _test_key2[32] = {
    0xA1,0xA2,0xA3,0xA4,0xA5,0xA6,0xA7,0xA8,
    0xA9,0xAA,0xAB,0xAC,0xAD,0xAE,0xAF,0xB0,
    0xB1,0xB2,0xB3,0xB4,0xB5,0xB6,0xB7,0xB8,
    0xB9,0xBA,0xBB,0xBC,0xBD,0xBE,0xBF,0xC0
};

/* ============================================================
 * LIFECYCLE TESTS
 * ============================================================ */

/* 1. init and shutdown */
TEST(ks_lifecycle)
{
    ozayn_key_storage_t ks;
    ozayn_ks_test_config_t cfg = {0};
    ozayn_ks_test_create(&ks, &cfg);

    ASSERT_EQ(ozayn_ks_init(&ks), OZAYN_KS_OK);
    ASSERT(ozayn_ks_is_ready(&ks));
    ASSERT(ozayn_ks_is_available(&ks));

    ozayn_ks_shutdown(&ks);
    ASSERT(!ozayn_ks_is_ready(&ks));
    return 0;
}

/* 2. null provider */
TEST(ks_null_provider)
{
    ASSERT_EQ(ozayn_ks_init(NULL), OZAYN_KS_ERR_NULL);
    ozayn_ks_shutdown(NULL);
    ASSERT(!ozayn_ks_is_ready(NULL));
    return 0;
}

/* ============================================================
 * STORE TESTS
 * ============================================================ */

/* 3. store key */
TEST(ks_store)
{
    ozayn_key_storage_t ks;
    ozayn_ks_test_config_t cfg = {0};
    ozayn_ks_test_create(&ks, &cfg);
    ozayn_ks_init(&ks);

    ozayn_key_id_t id;
    ozayn_key_id_set(&id, "OZAYN-DATA-PRIMARY", 1, "test");

    ozayn_ks_request_t req;
    ozayn_ks_request_set_store(&req, &id, _test_key, 32, OZAYN_KEY_PURPOSE_DATA_ENCRYPTION);

    ozayn_ks_result_data_t out;
    ASSERT_EQ(ozayn_ks_store(&ks, &req, &out), OZAYN_KS_OK);

    ozayn_ks_shutdown(&ks);
    return 0;
}

/* 4. store duplicate key */
TEST(ks_store_duplicate)
{
    ozayn_key_storage_t ks;
    ozayn_ks_test_config_t cfg = {0};
    ozayn_ks_test_create(&ks, &cfg);
    ozayn_ks_init(&ks);

    ozayn_key_id_t id;
    ozayn_key_id_set(&id, "DUP-KEY", 1, "test");

    ozayn_ks_request_t req;
    ozayn_ks_request_set_store(&req, &id, _test_key, 32, OZAYN_KEY_PURPOSE_DATA_ENCRYPTION);

    ozayn_ks_result_data_t out;
    ASSERT_EQ(ozayn_ks_store(&ks, &req, &out), OZAYN_KS_OK);
    ASSERT_EQ(ozayn_ks_store(&ks, &req, &out), OZAYN_KS_ERR_ALREADY_EXISTS);

    ozayn_ks_shutdown(&ks);
    return 0;
}

/* 5. store invalid key (zero length) */
TEST(ks_store_invalid_key)
{
    ozayn_key_storage_t ks;
    ozayn_ks_test_config_t cfg = {0};
    ozayn_ks_test_create(&ks, &cfg);
    ozayn_ks_init(&ks);

    ozayn_key_id_t id;
    ozayn_key_id_set(&id, "BAD-KEY", 1, "test");

    ozayn_ks_request_t req;
    memset(&req, 0, sizeof(req));
    req.operation = OZAYN_KS_OP_STORE;
    req.key_id = id;
    req.key_length = 0;  /* invalid */
    req.purpose = OZAYN_KEY_PURPOSE_DATA_ENCRYPTION;

    ozayn_ks_result_data_t out;
    ASSERT_EQ(ozayn_ks_store(&ks, &req, &out), OZAYN_KS_ERR_INVALID_KEY);

    ozayn_ks_shutdown(&ks);
    return 0;
}

/* 6. store unknown purpose */
TEST(ks_store_unknown_purpose)
{
    ozayn_key_storage_t ks;
    ozayn_ks_test_config_t cfg = {0};
    ozayn_ks_test_create(&ks, &cfg);
    ozayn_ks_init(&ks);

    ozayn_key_id_t id;
    ozayn_key_id_set(&id, "PURP-KEY", 1, "test");

    ozayn_ks_request_t req;
    ozayn_ks_request_set_store(&req, &id, _test_key, 32, OZAYN_KEY_PURPOSE_UNKNOWN);

    ozayn_ks_result_data_t out;
    ASSERT_EQ(ozayn_ks_store(&ks, &req, &out), OZAYN_KS_ERR_INVALID_REQUEST);

    ozayn_ks_shutdown(&ks);
    return 0;
}

/* ============================================================
 * LOAD TESTS
 * ============================================================ */

/* 7. load key */
TEST(ks_load)
{
    ozayn_key_storage_t ks;
    ozayn_ks_test_config_t cfg = {0};
    ozayn_ks_test_create(&ks, &cfg);
    ozayn_ks_init(&ks);

    ozayn_key_id_t id;
    ozayn_key_id_set(&id, "LOAD-KEY", 1, "test");

    /* Store first */
    ozayn_ks_request_t store_req;
    ozayn_ks_request_set_store(&store_req, &id, _test_key, 32, OZAYN_KEY_PURPOSE_DATA_ENCRYPTION);
    ozayn_ks_result_data_t store_out;
    ASSERT_EQ(ozayn_ks_store(&ks, &store_req, &store_out), OZAYN_KS_OK);

    /* Load */
    ozayn_ks_request_t load_req;
    ozayn_ks_request_init(&load_req, OZAYN_KS_OP_LOAD, &id, OZAYN_KEY_PURPOSE_DATA_ENCRYPTION);
    ozayn_ks_result_data_t load_out;
    ASSERT_EQ(ozayn_ks_load(&ks, &load_req, &load_out), OZAYN_KS_OK);
    ASSERT_EQ(load_out.key_length, (size_t)32);
    ASSERT_EQ(memcmp(load_out.key_material, _test_key, 32), 0);

    ozayn_ks_shutdown(&ks);
    return 0;
}

/* 8. load nonexistent key */
TEST(ks_load_not_found)
{
    ozayn_key_storage_t ks;
    ozayn_ks_test_config_t cfg = {0};
    ozayn_ks_test_create(&ks, &cfg);
    ozayn_ks_init(&ks);

    ozayn_key_id_t id;
    ozayn_key_id_set(&id, "MISSING-KEY", 1, "test");

    ozayn_ks_request_t req;
    ozayn_ks_request_init(&req, OZAYN_KS_OP_LOAD, &id, OZAYN_KEY_PURPOSE_DATA_ENCRYPTION);
    ozayn_ks_result_data_t out;
    ASSERT_EQ(ozayn_ks_load(&ks, &req, &out), OZAYN_KS_ERR_NOT_FOUND);

    ozayn_ks_shutdown(&ks);
    return 0;
}

/* ============================================================
 * EXISTS TESTS
 * ============================================================ */

/* 9. exists true */
TEST(ks_exists_true)
{
    ozayn_key_storage_t ks;
    ozayn_ks_test_config_t cfg = {0};
    ozayn_ks_test_create(&ks, &cfg);
    ozayn_ks_init(&ks);

    ozayn_key_id_t id;
    ozayn_key_id_set(&id, "EXIST-KEY", 1, "test");

    ozayn_ks_request_t store_req;
    ozayn_ks_request_set_store(&store_req, &id, _test_key, 32, OZAYN_KEY_PURPOSE_DATA_ENCRYPTION);
    ozayn_ks_result_data_t store_out;
    ASSERT_EQ(ozayn_ks_store(&ks, &store_req, &store_out), OZAYN_KS_OK);

    int exists = 0;
    ASSERT_EQ(ozayn_ks_exists(&ks, &id, &exists), OZAYN_KS_OK);
    ASSERT(exists == 1);

    ozayn_ks_shutdown(&ks);
    return 0;
}

/* 10. exists false */
TEST(ks_exists_false)
{
    ozayn_key_storage_t ks;
    ozayn_ks_test_config_t cfg = {0};
    ozayn_ks_test_create(&ks, &cfg);
    ozayn_ks_init(&ks);

    ozayn_key_id_t id;
    ozayn_key_id_set(&id, "NOEXIST-KEY", 1, "test");

    int exists = 1;
    ASSERT_EQ(ozayn_ks_exists(&ks, &id, &exists), OZAYN_KS_OK);
    ASSERT(exists == 0);

    ozayn_ks_shutdown(&ks);
    return 0;
}

/* ============================================================
 * REMOVE TESTS
 * ============================================================ */

/* 11. remove key */
TEST(ks_remove)
{
    ozayn_key_storage_t ks;
    ozayn_ks_test_config_t cfg = {0};
    ozayn_ks_test_create(&ks, &cfg);
    ozayn_ks_init(&ks);

    ozayn_key_id_t id;
    ozayn_key_id_set(&id, "REM-KEY", 1, "test");

    ozayn_ks_request_t store_req;
    ozayn_ks_request_set_store(&store_req, &id, _test_key, 32, OZAYN_KEY_PURPOSE_DATA_ENCRYPTION);
    ozayn_ks_result_data_t store_out;
    ASSERT_EQ(ozayn_ks_store(&ks, &store_req, &store_out), OZAYN_KS_OK);

    ASSERT_EQ(ozayn_ks_remove(&ks, &id), OZAYN_KS_OK);

    /* Verify gone */
    int exists = 0;
    ASSERT_EQ(ozayn_ks_exists(&ks, &id, &exists), OZAYN_KS_OK);
    ASSERT(exists == 0);

    /* Load fails */
    ozayn_ks_request_t load_req;
    ozayn_ks_request_init(&load_req, OZAYN_KS_OP_LOAD, &id, OZAYN_KEY_PURPOSE_DATA_ENCRYPTION);
    ozayn_ks_result_data_t load_out;
    ASSERT_EQ(ozayn_ks_load(&ks, &load_req, &load_out), OZAYN_KS_ERR_NOT_FOUND);

    ozayn_ks_shutdown(&ks);
    return 0;
}

/* 12. remove nonexistent key */
TEST(ks_remove_not_found)
{
    ozayn_key_storage_t ks;
    ozayn_ks_test_config_t cfg = {0};
    ozayn_ks_test_create(&ks, &cfg);
    ozayn_ks_init(&ks);

    ozayn_key_id_t id;
    ozayn_key_id_set(&id, "NOREM-KEY", 1, "test");

    ASSERT_EQ(ozayn_ks_remove(&ks, &id), OZAYN_KS_ERR_NOT_FOUND);

    ozayn_ks_shutdown(&ks);
    return 0;
}

/* ============================================================
 * METADATA TESTS
 * ============================================================ */

/* 13. get metadata */
TEST(ks_metadata)
{
    ozayn_key_storage_t ks;
    ozayn_ks_test_config_t cfg = {0};
    ozayn_ks_test_create(&ks, &cfg);
    ozayn_ks_init(&ks);

    ozayn_key_id_t id;
    ozayn_key_id_set(&id, "META-KEY", 1, "test");

    ozayn_ks_request_t store_req;
    ozayn_ks_request_set_store(&store_req, &id, _test_key, 32, OZAYN_KEY_PURPOSE_DATA_ENCRYPTION);
    ozayn_ks_result_data_t store_out;
    ASSERT_EQ(ozayn_ks_store(&ks, &store_req, &store_out), OZAYN_KS_OK);

    ozayn_ks_metadata_t meta;
    ASSERT_EQ(ozayn_ks_get_metadata(&ks, &id, &meta), OZAYN_KS_OK);
    ASSERT(meta.is_valid);
    ASSERT_EQ(meta.key_length, (size_t)32);
    ASSERT_EQ(meta.purpose, OZAYN_KEY_PURPOSE_DATA_ENCRYPTION);
    ASSERT_STR_EQ(meta.platform_type, "in-memory-test");

    ozayn_ks_shutdown(&ks);
    return 0;
}

/* 14. metadata not found */
TEST(ks_metadata_not_found)
{
    ozayn_key_storage_t ks;
    ozayn_ks_test_config_t cfg = {0};
    ozayn_ks_test_create(&ks, &cfg);
    ozayn_ks_init(&ks);

    ozayn_key_id_t id;
    ozayn_key_id_set(&id, "NOMETA-KEY", 1, "test");

    ozayn_ks_metadata_t meta;
    ASSERT_EQ(ozayn_ks_get_metadata(&ks, &id, &meta), OZAYN_KS_ERR_NOT_FOUND);

    ozayn_ks_shutdown(&ks);
    return 0;
}

/* ============================================================
 * FAILURE / FAIL-CLOSED TESTS
 * ============================================================ */

/* 15. storage unavailable */
TEST(ks_unavailable)
{
    ozayn_key_storage_t ks;
    ozayn_ks_test_config_t cfg = {0};
    cfg.unavailable = 1;
    ozayn_ks_test_create(&ks, &cfg);
    ozayn_ks_init(&ks);

    ozayn_key_id_t id;
    ozayn_key_id_set(&id, "UNAVAIL-KEY", 1, "test");

    /* Store fails */
    ozayn_ks_request_t store_req;
    ozayn_ks_request_set_store(&store_req, &id, _test_key, 32, OZAYN_KEY_PURPOSE_DATA_ENCRYPTION);
    ozayn_ks_result_data_t store_out;
    ASSERT_EQ(ozayn_ks_store(&ks, &store_req, &store_out), OZAYN_KS_ERR_UNAVAILABLE);

    /* Load fails */
    ozayn_ks_request_t load_req;
    ozayn_ks_request_init(&load_req, OZAYN_KS_OP_LOAD, &id, OZAYN_KEY_PURPOSE_DATA_ENCRYPTION);
    ozayn_ks_result_data_t load_out;
    ASSERT_EQ(ozayn_ks_load(&ks, &load_req, &load_out), OZAYN_KS_ERR_UNAVAILABLE);

    /* Exists fails */
    int exists = 0;
    ASSERT_EQ(ozayn_ks_exists(&ks, &id, &exists), OZAYN_KS_ERR_UNAVAILABLE);

    /* Remove fails */
    ASSERT_EQ(ozayn_ks_remove(&ks, &id), OZAYN_KS_ERR_UNAVAILABLE);

    /* Metadata fails */
    ozayn_ks_metadata_t meta;
    ASSERT_EQ(ozayn_ks_get_metadata(&ks, &id, &meta), OZAYN_KS_ERR_UNAVAILABLE);

    /* Not available */
    ASSERT(!ozayn_ks_is_available(&ks));

    ozayn_ks_shutdown(&ks);
    return 0;
}

/* 16. access denied */
TEST(ks_access_denied)
{
    ozayn_key_storage_t ks;
    ozayn_ks_test_config_t cfg = {0};
    cfg.access_denied = 1;
    ozayn_ks_test_create(&ks, &cfg);
    ozayn_ks_init(&ks);

    ozayn_key_id_t id;
    ozayn_key_id_set(&id, "DENIED-KEY", 1, "test");

    ozayn_ks_request_t store_req;
    ozayn_ks_request_set_store(&store_req, &id, _test_key, 32, OZAYN_KEY_PURPOSE_DATA_ENCRYPTION);
    ozayn_ks_result_data_t store_out;
    ASSERT_EQ(ozayn_ks_store(&ks, &store_req, &store_out), OZAYN_KS_ERR_ACCESS_DENIED);

    ozayn_ks_shutdown(&ks);
    return 0;
}

/* 17. store failure */
TEST(ks_store_failure)
{
    ozayn_key_storage_t ks;
    ozayn_ks_test_config_t cfg = {0};
    cfg.fail_store = 1;
    ozayn_ks_test_create(&ks, &cfg);
    ozayn_ks_init(&ks);

    ozayn_key_id_t id;
    ozayn_key_id_set(&id, "FAIL-KEY", 1, "test");

    ozayn_ks_request_t store_req;
    ozayn_ks_request_set_store(&store_req, &id, _test_key, 32, OZAYN_KEY_PURPOSE_DATA_ENCRYPTION);
    ozayn_ks_result_data_t store_out;
    ASSERT_EQ(ozayn_ks_store(&ks, &store_req, &store_out), OZAYN_KS_ERR_STORAGE_FAILED);

    ozayn_ks_shutdown(&ks);
    return 0;
}

/* 18. load failure */
TEST(ks_load_failure)
{
    ozayn_key_storage_t ks;
    ozayn_ks_test_config_t cfg = {0};
    cfg.fail_load = 1;
    ozayn_ks_test_create(&ks, &cfg);
    ozayn_ks_init(&ks);

    ozayn_key_id_t id;
    ozayn_key_id_set(&id, "FAILLOAD-KEY", 1, "test");

    /* Store first (store works) */
    ozayn_ks_request_t store_req;
    ozayn_ks_request_set_store(&store_req, &id, _test_key, 32, OZAYN_KEY_PURPOSE_DATA_ENCRYPTION);
    ozayn_ks_result_data_t store_out;
    ASSERT_EQ(ozayn_ks_store(&ks, &store_req, &store_out), OZAYN_KS_OK);

    /* Load fails */
    ozayn_ks_request_t load_req;
    ozayn_ks_request_init(&load_req, OZAYN_KS_OP_LOAD, &id, OZAYN_KEY_PURPOSE_DATA_ENCRYPTION);
    ozayn_ks_result_data_t load_out;
    ASSERT_EQ(ozayn_ks_load(&ks, &load_req, &load_out), OZAYN_KS_ERR_STORAGE_FAILED);

    ozayn_ks_shutdown(&ks);
    return 0;
}

/* 19. remove failure */
TEST(ks_remove_failure)
{
    ozayn_key_storage_t ks;
    ozayn_ks_test_config_t cfg = {0};
    cfg.fail_remove = 1;
    ozayn_ks_test_create(&ks, &cfg);
    ozayn_ks_init(&ks);

    ozayn_key_id_t id;
    ozayn_key_id_set(&id, "FAILREM-KEY", 1, "test");

    /* Store first */
    ozayn_ks_request_t store_req;
    ozayn_ks_request_set_store(&store_req, &id, _test_key, 32, OZAYN_KEY_PURPOSE_DATA_ENCRYPTION);
    ozayn_ks_result_data_t store_out;
    ASSERT_EQ(ozayn_ks_store(&ks, &store_req, &store_out), OZAYN_KS_OK);

    /* Remove fails */
    ASSERT_EQ(ozayn_ks_remove(&ks, &id), OZAYN_KS_ERR_STORAGE_FAILED);

    ozayn_ks_shutdown(&ks);
    return 0;
}

/* ============================================================
 * DISPATCH ERROR TESTS
 * ============================================================ */

/* 20. null request */
TEST(ks_dispatch_null_request)
{
    ozayn_key_storage_t ks;
    ozayn_ks_test_config_t cfg = {0};
    ozayn_ks_test_create(&ks, &cfg);
    ozayn_ks_init(&ks);

    ozayn_ks_result_data_t out;
    ASSERT_EQ(ozayn_ks_store(&ks, NULL, &out), OZAYN_KS_ERR_NULL);
    ASSERT_EQ(ozayn_ks_load(&ks, NULL, &out), OZAYN_KS_ERR_NULL);

    ozayn_ks_shutdown(&ks);
    return 0;
}

/* 21. null output */
TEST(ks_dispatch_null_output)
{
    ozayn_key_storage_t ks;
    ozayn_ks_test_config_t cfg = {0};
    ozayn_ks_test_create(&ks, &cfg);
    ozayn_ks_init(&ks);

    ozayn_key_id_t id;
    ozayn_key_id_set(&id, "X", 1, "test");
    ozayn_ks_request_t req;
    ozayn_ks_request_set_store(&req, &id, _test_key, 32, OZAYN_KEY_PURPOSE_DATA_ENCRYPTION);

    ASSERT_EQ(ozayn_ks_store(&ks, &req, NULL), OZAYN_KS_ERR_NULL);

    ozayn_ks_shutdown(&ks);
    return 0;
}

/* 22. wrong operation */
TEST(ks_dispatch_wrong_op)
{
    ozayn_key_storage_t ks;
    ozayn_ks_test_config_t cfg = {0};
    ozayn_ks_test_create(&ks, &cfg);
    ozayn_ks_init(&ks);

    ozayn_key_id_t id;
    ozayn_key_id_set(&id, "X", 1, "test");
    ozayn_ks_request_t req;
    memset(&req, 0, sizeof(req));
    req.operation = OZAYN_KS_OP_LOAD;  /* wrong op for store */
    req.key_id = id;
    req.key_length = 32;

    ozayn_ks_result_data_t out;
    ASSERT_EQ(ozayn_ks_store(&ks, &req, &out), OZAYN_KS_ERR_INVALID_REQUEST);

    ozayn_ks_shutdown(&ks);
    return 0;
}

/* 23. not initialized */
TEST(ks_not_initialized)
{
    ozayn_key_storage_t ks;
    ozayn_ks_test_config_t cfg = {0};
    ozayn_ks_test_create(&ks, &cfg);

    ozayn_key_id_t id;
    ozayn_key_id_set(&id, "X", 1, "test");
    ozayn_ks_request_t req;
    ozayn_ks_request_set_store(&req, &id, _test_key, 32, OZAYN_KEY_PURPOSE_DATA_ENCRYPTION);

    ozayn_ks_result_data_t out;
    ASSERT_EQ(ozayn_ks_store(&ks, &req, &out), OZAYN_KS_ERR_NOT_INITIALIZED);

    return 0;
}

/* ============================================================
 * NAME HELPER TESTS
 * ============================================================ */

/* 24. result names */
TEST(ks_names_result)
{
    ASSERT_STR_EQ(ozayn_ks_result_name(OZAYN_KS_OK), "KS_OK");
    ASSERT_STR_EQ(ozayn_ks_result_name(OZAYN_KS_ERR_NULL), "KS_NULL");
    ASSERT_STR_EQ(ozayn_ks_result_name(OZAYN_KS_ERR_NOT_FOUND), "KS_NOT_FOUND");
    ASSERT_STR_EQ(ozayn_ks_result_name(OZAYN_KS_ERR_ALREADY_EXISTS), "KS_ALREADY_EXISTS");
    ASSERT_STR_EQ(ozayn_ks_result_name(OZAYN_KS_ERR_UNAVAILABLE), "KS_UNAVAILABLE");
    ASSERT_STR_EQ(ozayn_ks_result_name(OZAYN_KS_ERR_ACCESS_DENIED), "KS_ACCESS_DENIED");
    ASSERT_STR_EQ(ozayn_ks_result_name(-999), "KS_UNKNOWN");
    return 0;
}

/* 25. operation names */
TEST(ks_names_operation)
{
    ASSERT_STR_EQ(ozayn_ks_operation_name(OZAYN_KS_OP_STORE), "store");
    ASSERT_STR_EQ(ozayn_ks_operation_name(OZAYN_KS_OP_LOAD), "load");
    ASSERT_STR_EQ(ozayn_ks_operation_name(OZAYN_KS_OP_EXISTS), "exists");
    ASSERT_STR_EQ(ozayn_ks_operation_name(OZAYN_KS_OP_REMOVE), "remove");
    ASSERT_STR_EQ(ozayn_ks_operation_name(OZAYN_KS_OP_METADATA), "metadata");
    return 0;
}

/* 26. state names */
TEST(ks_names_state)
{
    ASSERT_STR_EQ(ozayn_ks_state_name(OZAYN_KS_STATE_UNINITIALIZED), "uninitialized");
    ASSERT_STR_EQ(ozayn_ks_state_name(OZAYN_KS_STATE_READY), "ready");
    ASSERT_STR_EQ(ozayn_ks_state_name(OZAYN_KS_STATE_STOPPED), "stopped");
    return 0;
}

/* ============================================================
 * PLATFORM NAME TEST
 * ============================================================ */

/* 27. platform name */
TEST(ks_platform_name)
{
    ozayn_key_storage_t ks;
    ozayn_ks_test_config_t cfg = {0};
    ozayn_ks_test_create(&ks, &cfg);
    ozayn_ks_init(&ks);

    ASSERT_STR_EQ(ozayn_ks_platform_name(&ks), "in-memory-test");

    ozayn_ks_shutdown(&ks);
    return 0;
}

/* 28. platform name null */
TEST(ks_platform_name_null)
{
    ASSERT_STR_EQ(ozayn_ks_platform_name(NULL), "null");
    return 0;
}

/* ============================================================
 * SECURITY TESTS
 * ============================================================ */

/* 29. key not in metadata */
TEST(ks_security_no_key_in_metadata)
{
    ozayn_key_storage_t ks;
    ozayn_ks_test_config_t cfg = {0};
    ozayn_ks_test_create(&ks, &cfg);
    ozayn_ks_init(&ks);

    ozayn_key_id_t id;
    ozayn_key_id_set(&id, "SEC-META-KEY", 1, "test");

    ozayn_ks_request_t store_req;
    ozayn_ks_request_set_store(&store_req, &id, _test_key, 32, OZAYN_KEY_PURPOSE_DATA_ENCRYPTION);
    ozayn_ks_result_data_t store_out;
    ASSERT_EQ(ozayn_ks_store(&ks, &store_req, &store_out), OZAYN_KS_OK);

    ozayn_ks_metadata_t meta;
    ASSERT_EQ(ozayn_ks_get_metadata(&ks, &id, &meta), OZAYN_KS_OK);

    /* Metadata struct must not contain actual key bytes */
    const uint8_t *bytes = (const uint8_t *)&meta;
    int has_key = 0;
    for (size_t i = 0; i + 32 <= sizeof(meta); i++) {
        if (memcmp(&bytes[i], _test_key, 32) == 0) {
            has_key = 1;
            break;
        }
    }
    ASSERT(!has_key);

    ozayn_ks_shutdown(&ks);
    return 0;
}

/* 30. store result doesn't contain key in metadata fields */
TEST(ks_security_store_result_clean)
{
    ozayn_key_storage_t ks;
    ozayn_ks_test_config_t cfg = {0};
    ozayn_ks_test_create(&ks, &cfg);
    ozayn_ks_init(&ks);

    ozayn_key_id_t id;
    ozayn_key_id_set(&id, "SEC-STORE-KEY", 1, "test");

    ozayn_ks_request_t store_req;
    ozayn_ks_request_set_store(&store_req, &id, _test_key, 32, OZAYN_KEY_PURPOSE_DATA_ENCRYPTION);
    ozayn_ks_result_data_t store_out;
    ASSERT_EQ(ozayn_ks_store(&ks, &store_req, &store_out), OZAYN_KS_OK);

    /* Store result should not contain the key */
    int has_key = 0;
    const uint8_t *bytes = (const uint8_t *)&store_out;
    for (size_t i = 0; i + 32 <= sizeof(store_out); i++) {
        if (memcmp(&bytes[i], _test_key, 32) == 0) {
            has_key = 1;
            break;
        }
    }
    ASSERT(!has_key);

    ozayn_ks_shutdown(&ks);
    return 0;
}

/* ============================================================
 * ROUND TRIP TEST
 * ============================================================ */

/* 31. full round trip: store, exists, load, metadata, remove */
TEST(ks_full_roundtrip)
{
    ozayn_key_storage_t ks;
    ozayn_ks_test_config_t cfg = {0};
    ozayn_ks_test_create(&ks, &cfg);
    ozayn_ks_init(&ks);

    ozayn_key_id_t id;
    ozayn_key_id_set(&id, "ROUNDTRIP-KEY", 1, "test");

    /* Store */
    ozayn_ks_request_t store_req;
    ozayn_ks_request_set_store(&store_req, &id, _test_key, 32, OZAYN_KEY_PURPOSE_DATA_ENCRYPTION);
    ozayn_ks_result_data_t store_out;
    ASSERT_EQ(ozayn_ks_store(&ks, &store_req, &store_out), OZAYN_KS_OK);

    /* Exists */
    int exists = 0;
    ASSERT_EQ(ozayn_ks_exists(&ks, &id, &exists), OZAYN_KS_OK);
    ASSERT(exists == 1);

    /* Load */
    ozayn_ks_request_t load_req;
    ozayn_ks_request_init(&load_req, OZAYN_KS_OP_LOAD, &id, OZAYN_KEY_PURPOSE_DATA_ENCRYPTION);
    ozayn_ks_result_data_t load_out;
    ASSERT_EQ(ozayn_ks_load(&ks, &load_req, &load_out), OZAYN_KS_OK);
    ASSERT_EQ(load_out.key_length, (size_t)32);
    ASSERT_EQ(memcmp(load_out.key_material, _test_key, 32), 0);

    /* Metadata */
    ozayn_ks_metadata_t meta;
    ASSERT_EQ(ozayn_ks_get_metadata(&ks, &id, &meta), OZAYN_KS_OK);
    ASSERT(meta.is_valid);

    /* Remove */
    ASSERT_EQ(ozayn_ks_remove(&ks, &id), OZAYN_KS_OK);

    /* Verify gone */
    exists = 1;
    ASSERT_EQ(ozayn_ks_exists(&ks, &id, &exists), OZAYN_KS_OK);
    ASSERT(exists == 0);

    ozayn_ks_shutdown(&ks);
    return 0;
}

/* ============================================================
 * MULTIPLE KEYS TEST
 * ============================================================ */

/* 32. multiple keys */
TEST(ks_multiple_keys)
{
    ozayn_key_storage_t ks;
    ozayn_ks_test_config_t cfg = {0};
    ozayn_ks_test_create(&ks, &cfg);
    ozayn_ks_init(&ks);

    for (int i = 0; i < 5; i++) {
        ozayn_key_id_t id;
        char name[32];
        snprintf(name, sizeof(name), "MULTI-KEY-%d", i);
        ozayn_key_id_set(&id, name, 1, "test");

        ozayn_ks_request_t store_req;
        ozayn_ks_request_set_store(&store_req, &id, _test_key, 32, OZAYN_KEY_PURPOSE_DATA_ENCRYPTION);
        ozayn_ks_result_data_t store_out;
        ASSERT_EQ(ozayn_ks_store(&ks, &store_req, &store_out), OZAYN_KS_OK);
    }

    /* Verify all exist */
    for (int i = 0; i < 5; i++) {
        ozayn_key_id_t id;
        char name[32];
        snprintf(name, sizeof(name), "MULTI-KEY-%d", i);
        ozayn_key_id_set(&id, name, 1, "test");

        int exists = 0;
        ASSERT_EQ(ozayn_ks_exists(&ks, &id, &exists), OZAYN_KS_OK);
        ASSERT(exists == 1);
    }

    ozayn_ks_shutdown(&ks);
    return 0;
}

/* ============================================================
 * KEY VERSION SUPPORT TEST
 * ============================================================ */

/* 33. multiple versions of same key name */
TEST(ks_key_versions)
{
    ozayn_key_storage_t ks;
    ozayn_ks_test_config_t cfg = {0};
    ozayn_ks_test_create(&ks, &cfg);
    ozayn_ks_init(&ks);

    ozayn_key_id_t id_v1, id_v2;
    ozayn_key_id_set(&id_v1, "VERSIONED-KEY", 1, "test");
    ozayn_key_id_set(&id_v2, "VERSIONED-KEY", 2, "test");

    /* Store v1 */
    ozayn_ks_request_t req1;
    ozayn_ks_request_set_store(&req1, &id_v1, _test_key, 32, OZAYN_KEY_PURPOSE_DATA_ENCRYPTION);
    ozayn_ks_result_data_t out1;
    ASSERT_EQ(ozayn_ks_store(&ks, &req1, &out1), OZAYN_KS_OK);

    /* Store v2 */
    ozayn_ks_request_t req2;
    ozayn_ks_request_set_store(&req2, &id_v2, _test_key2, 32, OZAYN_KEY_PURPOSE_DATA_ENCRYPTION);
    ozayn_ks_result_data_t out2;
    ASSERT_EQ(ozayn_ks_store(&ks, &req2, &out2), OZAYN_KS_OK);

    /* Load v1 */
    ozayn_ks_request_t load1;
    ozayn_ks_request_init(&load1, OZAYN_KS_OP_LOAD, &id_v1, OZAYN_KEY_PURPOSE_DATA_ENCRYPTION);
    ozayn_ks_result_data_t lout1;
    ASSERT_EQ(ozayn_ks_load(&ks, &load1, &lout1), OZAYN_KS_OK);
    ASSERT_EQ(memcmp(lout1.key_material, _test_key, 32), 0);

    /* Load v2 */
    ozayn_ks_request_t load2;
    ozayn_ks_request_init(&load2, OZAYN_KS_OP_LOAD, &id_v2, OZAYN_KEY_PURPOSE_DATA_ENCRYPTION);
    ozayn_ks_result_data_t lout2;
    ASSERT_EQ(ozayn_ks_load(&ks, &load2, &lout2), OZAYN_KS_OK);
    ASSERT_EQ(memcmp(lout2.key_material, _test_key2, 32), 0);

    ozayn_ks_shutdown(&ks);
    return 0;
}

/* ============================================================
 * REQUEST HELPER TEST
 * ============================================================ */

/* 34. request init helper */
TEST(ks_request_init_helper)
{
    ozayn_key_id_t id;
    ozayn_key_id_set(&id, "HELPER-KEY", 1, "test");

    ozayn_ks_request_t req;
    ozayn_ks_request_init(&req, OZAYN_KS_OP_LOAD, &id, OZAYN_KEY_PURPOSE_DATA_ENCRYPTION);

    ASSERT_EQ(req.operation, OZAYN_KS_OP_LOAD);
    ASSERT(ozayn_key_id_equal(&req.key_id, &id));
    ASSERT_EQ(req.purpose, OZAYN_KEY_PURPOSE_DATA_ENCRYPTION);
    return 0;
}

/* 35. request set store helper */
TEST(ks_request_store_helper)
{
    ozayn_key_id_t id;
    ozayn_key_id_set(&id, "STORE-HELPER", 1, "test");

    ozayn_ks_request_t req;
    ozayn_ks_request_set_store(&req, &id, _test_key, 32, OZAYN_KEY_PURPOSE_DATA_ENCRYPTION);

    ASSERT_EQ(req.operation, OZAYN_KS_OP_STORE);
    ASSERT(ozayn_key_id_equal(&req.key_id, &id));
    ASSERT_EQ(req.key_length, (size_t)32);
    ASSERT_EQ(req.purpose, OZAYN_KEY_PURPOSE_DATA_ENCRYPTION);
    ASSERT_EQ(memcmp(req.key_material, _test_key, 32), 0);
    return 0;
}

/* ============================================================
 * ENUM VALIDATION
 * ============================================================ */

/* 36. error codes distinct */
TEST(ks_error_codes_distinct)
{
    ASSERT(OZAYN_KS_OK == 0);
    ASSERT(OZAYN_KS_ERR_NULL < 0);
    ASSERT(OZAYN_KS_ERR_NOT_FOUND < 0);
    ASSERT(OZAYN_KS_ERR_ALREADY_EXISTS < 0);
    ASSERT(OZAYN_KS_ERR_UNAVAILABLE < 0);
    ASSERT(OZAYN_KS_ERR_ACCESS_DENIED < 0);

    ASSERT(OZAYN_KS_ERR_NULL != OZAYN_KS_ERR_NOT_FOUND);
    ASSERT(OZAYN_KS_ERR_STORAGE_FAILED != OZAYN_KS_ERR_PLATFORM_ERROR);
    return 0;
}

/* ============================================================
 * TEST REGISTRATION
 * ============================================================ */
void run_secure_key_storage_tests(void)
{
    printf("\n=== SECURE KEY STORAGE (Step 09) ===\n");
    printf("Number of tests: 36\n\n");

    /* Lifecycle (2) */
    RUN(ks_lifecycle);
    RUN(ks_null_provider);

    /* Store (4) */
    RUN(ks_store);
    RUN(ks_store_duplicate);
    RUN(ks_store_invalid_key);
    RUN(ks_store_unknown_purpose);

    /* Load (2) */
    RUN(ks_load);
    RUN(ks_load_not_found);

    /* Exists (2) */
    RUN(ks_exists_true);
    RUN(ks_exists_false);

    /* Remove (2) */
    RUN(ks_remove);
    RUN(ks_remove_not_found);

    /* Metadata (2) */
    RUN(ks_metadata);
    RUN(ks_metadata_not_found);

    /* Fail-closed (5) */
    RUN(ks_unavailable);
    RUN(ks_access_denied);
    RUN(ks_store_failure);
    RUN(ks_load_failure);
    RUN(ks_remove_failure);

    /* Dispatch errors (4) */
    RUN(ks_dispatch_null_request);
    RUN(ks_dispatch_null_output);
    RUN(ks_dispatch_wrong_op);
    RUN(ks_not_initialized);

    /* Names (3) */
    RUN(ks_names_result);
    RUN(ks_names_operation);
    RUN(ks_names_state);

    /* Platform (2) */
    RUN(ks_platform_name);
    RUN(ks_platform_name_null);

    /* Security (2) */
    RUN(ks_security_no_key_in_metadata);
    RUN(ks_security_store_result_clean);

    /* Round trip (1) */
    RUN(ks_full_roundtrip);

    /* Advanced (2) */
    RUN(ks_multiple_keys);
    RUN(ks_key_versions);

    /* Request helpers (2) */
    RUN(ks_request_init_helper);
    RUN(ks_request_store_helper);

    /* Enum validation (1) */
    RUN(ks_error_codes_distinct);
}
