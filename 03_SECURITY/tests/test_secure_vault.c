#include "../../tests/test_framework.h"
#include "../secure_vault.h"
#include "../protection_provider.h"
#include "../protection_provider_mock.h"
#include "../storage_provider.h"
#include "../storage_provider_mem.h"
#include "../key_lifecycle.h"
#include "../key_provider.h"
#include <string.h>

/*
 * test_secure_vault.c — Secure Vault tests (Section 03, Step 11).
 *
 * Tests the vault orchestration of validation, encryption, key management,
 * and storage. Uses mock protection provider and memory storage.
 */

/* ---- Test Helpers ---- */
static ozayn_protection_provider_t _prot;
static ozayn_storage_provider_t _stor;
static ozayn_kl_manager_t _kl;
static ozayn_vault_t _vault;

static void _setup_vault_deps(void)
{
    ozayn_prot_mock_create(&_prot, NULL);
    ozayn_prot_init(&_prot);

    ozayn_sp_mem_create_provider(&_stor);
    ozayn_sp_init(&_stor);

    ozayn_kl_init(&_kl);
    ozayn_kl_register_key(&_kl, "VAULT", OZAYN_KEY_PURPOSE_DATA_ENCRYPTION);
    ozayn_key_id_t kid;
    ozayn_key_id_set(&kid, "VAULT", 1, "test");
    ozayn_kl_add_version(&_kl, "VAULT", &kid, 32);
    ozayn_kl_activate(&_kl, "VAULT", 1);
}

static void _teardown_vault_deps(void)
{
    ozayn_vault_shutdown(&_vault);
    ozayn_kl_shutdown(&_kl);
    ozayn_sp_shutdown(&_stor);
    ozayn_prot_shutdown(&_prot);
}

static ozayn_vault_config_t _make_config(void)
{
    ozayn_vault_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.protection = &_prot;
    cfg.storage = &_stor;
    cfg.key_lifecycle = &_kl;
    return cfg;
}

/* ============================================================
 * INIT/SHUTDOWN TESTS
 * ============================================================ */

int test_vault_init_shutdown(void)
{
    _setup_vault_deps();
    ozayn_vault_config_t cfg = _make_config();
    ASSERT_EQ(OZAYN_VAULT_OK, ozayn_vault_init(&_vault, &cfg));
    ASSERT_EQ(1, ozayn_vault_is_initialized(&_vault));
    ASSERT_EQ(0, ozayn_vault_count(&_vault));
    ozayn_vault_shutdown(&_vault);
    ASSERT_EQ(0, ozayn_vault_is_initialized(&_vault));
    _teardown_vault_deps();
    return 0;
}

int test_vault_init_null(void)
{
    ASSERT_EQ(OZAYN_VAULT_ERR_NULL, ozayn_vault_init(NULL, NULL));
    ozayn_vault_t v;
    ASSERT_EQ(OZAYN_VAULT_ERR_NULL, ozayn_vault_init(&v, NULL));
    _teardown_vault_deps();
    return 0;
}

int test_vault_init_missing_deps(void)
{
    _setup_vault_deps();
    ozayn_vault_config_t cfg = _make_config();
    cfg.protection = NULL;
    ASSERT_EQ(OZAYN_VAULT_ERR_UNAVAILABLE, ozayn_vault_init(&_vault, &cfg));
    cfg = _make_config();
    cfg.storage = NULL;
    ASSERT_EQ(OZAYN_VAULT_ERR_UNAVAILABLE, ozayn_vault_init(&_vault, &cfg));
    cfg = _make_config();
    cfg.key_lifecycle = NULL;
    ASSERT_EQ(OZAYN_VAULT_ERR_UNAVAILABLE, ozayn_vault_init(&_vault, &cfg));
    _teardown_vault_deps();
    return 0;
}

int test_vault_shutdown_null(void)
{
    ozayn_vault_shutdown(NULL); /* No crash */
    return 0;
}

/* ============================================================
 * STORE TESTS
 * ============================================================ */

int test_vault_store_valid(void)
{
    _setup_vault_deps();
    ozayn_vault_config_t cfg = _make_config();
    ASSERT_EQ(OZAYN_VAULT_OK, ozayn_vault_init(&_vault, &cfg));

    ozayn_secure_data_object_t obj;
    ozayn_sdo_init(&obj, "test-obj-1", OZAYN_DATA_CATEGORY_AUTH_INFO, "test-owner", OZAYN_DATA_SCOPE_USER);
    obj.classification = OZAYN_SEC_LEVEL_SENSITIVE;

    const uint8_t data[] = "secret data for vault";
    ASSERT_EQ(OZAYN_VAULT_OK, ozayn_vault_store(&_vault, &obj, data, sizeof(data)));
    ASSERT_EQ(1, ozayn_vault_count(&_vault));
    ASSERT_EQ(1, ozayn_vault_exists(&_vault, "test-obj-1"));

    _teardown_vault_deps();
    return 0;
}

int test_vault_store_duplicate(void)
{
    _setup_vault_deps();
    ozayn_vault_config_t cfg = _make_config();
    ASSERT_EQ(OZAYN_VAULT_OK, ozayn_vault_init(&_vault, &cfg));

    ozayn_secure_data_object_t obj;
    ozayn_sdo_init(&obj, "dup-obj", OZAYN_DATA_CATEGORY_AUTH_INFO, "test", OZAYN_DATA_SCOPE_USER);
    obj.classification = OZAYN_SEC_LEVEL_SENSITIVE;

    const uint8_t data[] = "data";
    ASSERT_EQ(OZAYN_VAULT_OK, ozayn_vault_store(&_vault, &obj, data, sizeof(data)));
    ASSERT_EQ(OZAYN_VAULT_ERR_DUPLICATE, ozayn_vault_store(&_vault, &obj, data, sizeof(data)));

    _teardown_vault_deps();
    return 0;
}

int test_vault_store_empty_id(void)
{
    _setup_vault_deps();
    ozayn_vault_config_t cfg = _make_config();
    ASSERT_EQ(OZAYN_VAULT_OK, ozayn_vault_init(&_vault, &cfg));

    ozayn_secure_data_object_t obj;
    ozayn_sdo_init(&obj, "valid-id", OZAYN_DATA_CATEGORY_AUTH_INFO, "test", OZAYN_DATA_SCOPE_USER);
    obj.classification = OZAYN_SEC_LEVEL_SENSITIVE;
    /* Manually clear the id to simulate empty ID */
    obj.id[0] = '\0';

    const uint8_t data[] = "data";
    ASSERT_EQ(OZAYN_VAULT_ERR_INVALID_OBJECT, ozayn_vault_store(&_vault, &obj, data, sizeof(data)));

    _teardown_vault_deps();
    return 0;
}

int test_vault_store_path_traversal(void)
{
    _setup_vault_deps();
    ozayn_vault_config_t cfg = _make_config();
    ASSERT_EQ(OZAYN_VAULT_OK, ozayn_vault_init(&_vault, &cfg));

    ozayn_secure_data_object_t obj;
    ozayn_sdo_init(&obj, "../etc/passwd", OZAYN_DATA_CATEGORY_AUTH_INFO, "test", OZAYN_DATA_SCOPE_USER);
    obj.classification = OZAYN_SEC_LEVEL_SENSITIVE;

    const uint8_t data[] = "data";
    ASSERT_EQ(OZAYN_VAULT_ERR_INVALID_OBJECT, ozayn_vault_store(&_vault, &obj, data, sizeof(data)));

    _teardown_vault_deps();
    return 0;
}

int test_vault_store_not_initialized(void)
{
    ozayn_secure_data_object_t obj;
    ozayn_sdo_init(&obj, "obj", OZAYN_DATA_CATEGORY_AUTH_INFO, "test", OZAYN_DATA_SCOPE_USER);
    obj.classification = OZAYN_SEC_LEVEL_SENSITIVE;
    const uint8_t data[] = "data";
    ASSERT_EQ(OZAYN_VAULT_ERR_NOT_INITIALIZED, ozayn_vault_store(&_vault, &obj, data, sizeof(data)));
    return 0;
}

/* ============================================================
 * LOAD TESTS
 * ============================================================ */

int test_vault_load_existing(void)
{
    _setup_vault_deps();
    ozayn_vault_config_t cfg = _make_config();
    ASSERT_EQ(OZAYN_VAULT_OK, ozayn_vault_init(&_vault, &cfg));

    ozayn_secure_data_object_t obj;
    ozayn_sdo_init(&obj, "load-obj", OZAYN_DATA_CATEGORY_AUTH_INFO, "test", OZAYN_DATA_SCOPE_USER);
    obj.classification = OZAYN_SEC_LEVEL_SENSITIVE;

    const uint8_t data[] = "secret load data";
    ASSERT_EQ(OZAYN_VAULT_OK, ozayn_vault_store(&_vault, &obj, data, sizeof(data)));

    ozayn_secure_data_object_t loaded;
    size_t loaded_len = 0;
    ASSERT_EQ(OZAYN_VAULT_OK, ozayn_vault_load(&_vault, "load-obj", &loaded, NULL, 0, &loaded_len));
    ASSERT_STR_EQ("load-obj", loaded.id);

    _teardown_vault_deps();
    return 0;
}

int test_vault_load_missing(void)
{
    _setup_vault_deps();
    ozayn_vault_config_t cfg = _make_config();
    ASSERT_EQ(OZAYN_VAULT_OK, ozayn_vault_init(&_vault, &cfg));

    ozayn_secure_data_object_t loaded;
    ASSERT_EQ(OZAYN_VAULT_ERR_OBJECT_NOT_FOUND, ozayn_vault_load(&_vault, "nonexistent", &loaded, NULL, 0, NULL));

    _teardown_vault_deps();
    return 0;
}

int test_vault_load_not_initialized(void)
{
    ozayn_secure_data_object_t loaded;
    ASSERT_EQ(OZAYN_VAULT_ERR_NOT_INITIALIZED, ozayn_vault_load(&_vault, "obj", &loaded, NULL, 0, NULL));
    return 0;
}

/* ============================================================
 * UPDATE TESTS
 * ============================================================ */

int test_vault_update_existing(void)
{
    _setup_vault_deps();
    ozayn_vault_config_t cfg = _make_config();
    ASSERT_EQ(OZAYN_VAULT_OK, ozayn_vault_init(&_vault, &cfg));

    ozayn_secure_data_object_t obj;
    ozayn_sdo_init(&obj, "upd-obj", OZAYN_DATA_CATEGORY_AUTH_INFO, "test", OZAYN_DATA_SCOPE_USER);
    obj.classification = OZAYN_SEC_LEVEL_SENSITIVE;

    const uint8_t data1[] = "original";
    ASSERT_EQ(OZAYN_VAULT_OK, ozayn_vault_store(&_vault, &obj, data1, sizeof(data1)));

    const uint8_t data2[] = "updated";
    obj.classification = OZAYN_SEC_LEVEL_HIGHLY_SENSITIVE; /* Upgrade allowed */
    ASSERT_EQ(OZAYN_VAULT_OK, ozayn_vault_update(&_vault, &obj, data2, sizeof(data2)));
    ASSERT_EQ(1, ozayn_vault_count(&_vault));

    _teardown_vault_deps();
    return 0;
}

int test_vault_update_missing(void)
{
    _setup_vault_deps();
    ozayn_vault_config_t cfg = _make_config();
    ASSERT_EQ(OZAYN_VAULT_OK, ozayn_vault_init(&_vault, &cfg));

    ozayn_secure_data_object_t obj;
    ozayn_sdo_init(&obj, "nonexistent", OZAYN_DATA_CATEGORY_AUTH_INFO, "test", OZAYN_DATA_SCOPE_USER);
    obj.classification = OZAYN_SEC_LEVEL_SENSITIVE;

    const uint8_t data[] = "data";
    ASSERT_EQ(OZAYN_VAULT_ERR_OBJECT_NOT_FOUND, ozayn_vault_update(&_vault, &obj, data, sizeof(data)));

    _teardown_vault_deps();
    return 0;
}

int test_vault_update_classification_downgrade(void)
{
    _setup_vault_deps();
    ozayn_vault_config_t cfg = _make_config();
    ASSERT_EQ(OZAYN_VAULT_OK, ozayn_vault_init(&_vault, &cfg));

    ozayn_secure_data_object_t obj;
    ozayn_sdo_init(&obj, "class-obj", OZAYN_DATA_CATEGORY_AUTH_INFO, "test", OZAYN_DATA_SCOPE_USER);
    obj.classification = OZAYN_SEC_LEVEL_HIGHLY_SENSITIVE;

    const uint8_t data[] = "data";
    ASSERT_EQ(OZAYN_VAULT_OK, ozayn_vault_store(&_vault, &obj, data, sizeof(data)));

    /* Try to downgrade classification */
    obj.classification = OZAYN_SEC_LEVEL_SENSITIVE;
    ASSERT_EQ(OZAYN_VAULT_ERR_CLASSIFICATION, ozayn_vault_update(&_vault, &obj, data, sizeof(data)));

    _teardown_vault_deps();
    return 0;
}

/* ============================================================
 * REMOVE TESTS
 * ============================================================ */

int test_vault_remove_existing(void)
{
    _setup_vault_deps();
    ozayn_vault_config_t cfg = _make_config();
    ASSERT_EQ(OZAYN_VAULT_OK, ozayn_vault_init(&_vault, &cfg));

    ozayn_secure_data_object_t obj;
    ozayn_sdo_init(&obj, "rm-obj", OZAYN_DATA_CATEGORY_AUTH_INFO, "test", OZAYN_DATA_SCOPE_USER);
    obj.classification = OZAYN_SEC_LEVEL_SENSITIVE;

    const uint8_t data[] = "data";
    ASSERT_EQ(OZAYN_VAULT_OK, ozayn_vault_store(&_vault, &obj, data, sizeof(data)));
    ASSERT_EQ(1, ozayn_vault_count(&_vault));

    ASSERT_EQ(OZAYN_VAULT_OK, ozayn_vault_remove(&_vault, "rm-obj"));
    ASSERT_EQ(0, ozayn_vault_count(&_vault));
    ASSERT_EQ(0, ozayn_vault_exists(&_vault, "rm-obj"));

    _teardown_vault_deps();
    return 0;
}

int test_vault_remove_missing(void)
{
    _setup_vault_deps();
    ozayn_vault_config_t cfg = _make_config();
    ASSERT_EQ(OZAYN_VAULT_OK, ozayn_vault_init(&_vault, &cfg));

    ASSERT_EQ(OZAYN_VAULT_ERR_OBJECT_NOT_FOUND, ozayn_vault_remove(&_vault, "nonexistent"));

    _teardown_vault_deps();
    return 0;
}

/* ============================================================
 * EXISTS TESTS
 * ============================================================ */

int test_vault_exists_after_store(void)
{
    _setup_vault_deps();
    ozayn_vault_config_t cfg = _make_config();
    ASSERT_EQ(OZAYN_VAULT_OK, ozayn_vault_init(&_vault, &cfg));

    ASSERT_EQ(0, ozayn_vault_exists(&_vault, "exists-obj"));

    ozayn_secure_data_object_t obj;
    ozayn_sdo_init(&obj, "exists-obj", OZAYN_DATA_CATEGORY_AUTH_INFO, "test", OZAYN_DATA_SCOPE_USER);
    obj.classification = OZAYN_SEC_LEVEL_SENSITIVE;

    const uint8_t data[] = "data";
    ASSERT_EQ(OZAYN_VAULT_OK, ozayn_vault_store(&_vault, &obj, data, sizeof(data)));
    ASSERT_EQ(1, ozayn_vault_exists(&_vault, "exists-obj"));

    ASSERT_EQ(OZAYN_VAULT_OK, ozayn_vault_remove(&_vault, "exists-obj"));
    ASSERT_EQ(0, ozayn_vault_exists(&_vault, "exists-obj"));

    _teardown_vault_deps();
    return 0;
}

int test_vault_exists_null(void)
{
    ASSERT_EQ(0, ozayn_vault_exists(NULL, "obj"));
    ASSERT_EQ(0, ozayn_vault_exists(&_vault, NULL));
    return 0;
}

/* ============================================================
 * LIST TESTS
 * ============================================================ */

int test_vault_list_category(void)
{
    _setup_vault_deps();
    ozayn_vault_config_t cfg = _make_config();
    ASSERT_EQ(OZAYN_VAULT_OK, ozayn_vault_init(&_vault, &cfg));

    /* Store objects in different categories */
    ozayn_secure_data_object_t obj1, obj2, obj3;
    ozayn_sdo_init(&obj1, "auth-1", OZAYN_DATA_CATEGORY_AUTH_INFO, "test", OZAYN_DATA_SCOPE_USER);
    obj1.classification = OZAYN_SEC_LEVEL_SENSITIVE;
    ozayn_sdo_init(&obj2, "auth-2", OZAYN_DATA_CATEGORY_AUTH_INFO, "test", OZAYN_DATA_SCOPE_USER);
    obj2.classification = OZAYN_SEC_LEVEL_SENSITIVE;
    ozayn_sdo_init(&obj3, "sys-1", OZAYN_DATA_CATEGORY_SYSTEM_CONFIGURATION, "test", OZAYN_DATA_SCOPE_USER);
    obj3.classification = OZAYN_SEC_LEVEL_INTERNAL;

    const uint8_t data[] = "data";
    ASSERT_EQ(OZAYN_VAULT_OK, ozayn_vault_store(&_vault, &obj1, data, sizeof(data)));
    ASSERT_EQ(OZAYN_VAULT_OK, ozayn_vault_store(&_vault, &obj2, data, sizeof(data)));
    ASSERT_EQ(OZAYN_VAULT_OK, ozayn_vault_store(&_vault, &obj3, data, sizeof(data)));

    /* List auth category */
    ozayn_vault_list_item_t items[10];
    int count = ozayn_vault_list(&_vault, OZAYN_DATA_CATEGORY_AUTH_INFO, items, 10);
    ASSERT_EQ(2, count);

    /* List sys category */
    count = ozayn_vault_list(&_vault, OZAYN_DATA_CATEGORY_SYSTEM_CONFIGURATION, items, 10);
    ASSERT_EQ(1, count);

    /* List empty category */
    count = ozayn_vault_list(&_vault, OZAYN_DATA_CATEGORY_AI_MEMORY, items, 10);
    ASSERT_EQ(0, count);

    _teardown_vault_deps();
    return 0;
}

int test_vault_list_empty(void)
{
    _setup_vault_deps();
    ozayn_vault_config_t cfg = _make_config();
    ASSERT_EQ(OZAYN_VAULT_OK, ozayn_vault_init(&_vault, &cfg));

    ozayn_vault_list_item_t items[10];
    int count = ozayn_vault_list(&_vault, OZAYN_DATA_CATEGORY_AUTH_INFO, items, 10);
    ASSERT_EQ(0, count);

    _teardown_vault_deps();
    return 0;
}

/* ============================================================
 * KEY ROTATION INTEGRATION TESTS
 * ============================================================ */

int test_vault_rotation_two_versions(void)
{
    _setup_vault_deps();
    ozayn_vault_config_t cfg = _make_config();
    ASSERT_EQ(OZAYN_VAULT_OK, ozayn_vault_init(&_vault, &cfg));

    /* Store with V1 */
    ozayn_secure_data_object_t obj;
    ozayn_sdo_init(&obj, "rot-obj", OZAYN_DATA_CATEGORY_AUTH_INFO, "test", OZAYN_DATA_SCOPE_USER);
    obj.classification = OZAYN_SEC_LEVEL_SENSITIVE;

    const uint8_t data1[] = "version 1 data";
    ASSERT_EQ(OZAYN_VAULT_OK, ozayn_vault_store(&_vault, &obj, data1, sizeof(data1)));

    /* Rotate to V2 */
    ozayn_key_id_t kid;
    ozayn_key_id_set(&kid, "VAULT", 2, "test");
    ASSERT_EQ(OZAYN_KL_OK, ozayn_kl_add_version(&_kl, "VAULT", &kid, 32));
    ASSERT_EQ(OZAYN_KL_OK, ozayn_kl_activate(&_kl, "VAULT", 2));

    /* Store with V2 */
    ozayn_secure_data_object_t obj2;
    ozayn_sdo_init(&obj2, "rot-obj-2", OZAYN_DATA_CATEGORY_AUTH_INFO, "test", OZAYN_DATA_SCOPE_USER);
    obj2.classification = OZAYN_SEC_LEVEL_SENSITIVE;

    const uint8_t data2[] = "version 2 data";
    ASSERT_EQ(OZAYN_VAULT_OK, ozayn_vault_store(&_vault, &obj2, data2, sizeof(data2)));

    /* Both exist */
    ASSERT_EQ(1, ozayn_vault_exists(&_vault, "rot-obj"));
    ASSERT_EQ(1, ozayn_vault_exists(&_vault, "rot-obj-2"));

    /* List shows both with correct key versions */
    ozayn_vault_list_item_t items[10];
    int count = ozayn_vault_list(&_vault, OZAYN_DATA_CATEGORY_AUTH_INFO, items, 10);
    ASSERT_EQ(2, count);

    /* V1 retired but still usable for historical */
    ASSERT_EQ(1, ozayn_kl_is_usable(&_kl, "VAULT", 1));
    ASSERT_EQ(1, ozayn_kl_is_active(&_kl, "VAULT", 2));

    _teardown_vault_deps();
    return 0;
}

/* ============================================================
 * CLASSIFICATION PRESERVATION TEST
 * ============================================================ */

int test_vault_classification_preserved(void)
{
    _setup_vault_deps();
    ozayn_vault_config_t cfg = _make_config();
    ASSERT_EQ(OZAYN_VAULT_OK, ozayn_vault_init(&_vault, &cfg));

    ozayn_secure_data_object_t obj;
    ozayn_sdo_init(&obj, "class-preserve", OZAYN_DATA_CATEGORY_AUTH_INFO, "test", OZAYN_DATA_SCOPE_USER);
    obj.classification = OZAYN_SEC_LEVEL_HIGHLY_SENSITIVE;

    const uint8_t data[] = "classified data";
    ASSERT_EQ(OZAYN_VAULT_OK, ozayn_vault_store(&_vault, &obj, data, sizeof(data)));

    /* Load and verify classification */
    ozayn_secure_data_object_t loaded;
    ASSERT_EQ(OZAYN_VAULT_OK, ozayn_vault_load(&_vault, "class-preserve", &loaded, NULL, 0, NULL));
    ASSERT_EQ(OZAYN_SEC_LEVEL_HIGHLY_SENSITIVE, (int)loaded.classification);

    _teardown_vault_deps();
    return 0;
}

/* ============================================================
 * NULL SAFETY TESTS
 * ============================================================ */

int test_vault_null_safety(void)
{
    ASSERT_EQ(OZAYN_VAULT_ERR_NULL, ozayn_vault_store(NULL, NULL, NULL, 0));
    ASSERT_EQ(OZAYN_VAULT_ERR_NULL, ozayn_vault_load(NULL, NULL, NULL, NULL, 0, NULL));
    ASSERT_EQ(OZAYN_VAULT_ERR_NULL, ozayn_vault_update(NULL, NULL, NULL, 0));
    ASSERT_EQ(OZAYN_VAULT_ERR_NULL, ozayn_vault_remove(NULL, NULL));
    ASSERT_EQ(0, ozayn_vault_exists(NULL, NULL));
    ASSERT_EQ(0, ozayn_vault_list(NULL, 0, NULL, 0));
    ASSERT_EQ(0, ozayn_vault_count(NULL));
    ASSERT_EQ(0, ozayn_vault_is_initialized(NULL));
    return 0;
}

/* ============================================================
 * RESULT NAME TEST
 * ============================================================ */

int test_vault_result_names(void)
{
    ASSERT_STR_EQ("VAULT_OK", ozayn_vault_result_name(OZAYN_VAULT_OK));
    ASSERT_STR_EQ("VAULT_NULL", ozayn_vault_result_name(OZAYN_VAULT_ERR_NULL));
    ASSERT_STR_EQ("VAULT_OBJECT_NOT_FOUND", ozayn_vault_result_name(OZAYN_VAULT_ERR_OBJECT_NOT_FOUND));
    ASSERT_STR_EQ("VAULT_UNKNOWN", ozayn_vault_result_name((ozayn_vault_result_t)999));
    return 0;
}

/* ============================================================
 * TEST RUNNER
 * ============================================================ */

int run_secure_vault_tests(void)
{
    int failed = 0;
    int total = 0;

    printf("\n  --- SECURE VAULT TESTS ---\n");

    #define RUN_SV(name) do { total++; printf("    [%d] %s ... ", total, #name); if (name() == 0) { printf("PASS\n"); } else { printf("FAIL\n"); failed++; } } while(0)

    /* Init/Shutdown */
    RUN_SV(test_vault_init_shutdown);
    RUN_SV(test_vault_init_null);
    RUN_SV(test_vault_init_missing_deps);
    RUN_SV(test_vault_shutdown_null);

    /* Store */
    RUN_SV(test_vault_store_valid);
    RUN_SV(test_vault_store_duplicate);
    RUN_SV(test_vault_store_empty_id);
    RUN_SV(test_vault_store_path_traversal);
    RUN_SV(test_vault_store_not_initialized);

    /* Load */
    RUN_SV(test_vault_load_existing);
    RUN_SV(test_vault_load_missing);
    RUN_SV(test_vault_load_not_initialized);

    /* Update */
    RUN_SV(test_vault_update_existing);
    RUN_SV(test_vault_update_missing);
    RUN_SV(test_vault_update_classification_downgrade);

    /* Remove */
    RUN_SV(test_vault_remove_existing);
    RUN_SV(test_vault_remove_missing);

    /* Exists */
    RUN_SV(test_vault_exists_after_store);
    RUN_SV(test_vault_exists_null);

    /* List */
    RUN_SV(test_vault_list_category);
    RUN_SV(test_vault_list_empty);

    /* Integration */
    RUN_SV(test_vault_rotation_two_versions);
    RUN_SV(test_vault_classification_preserved);

    /* Safety */
    RUN_SV(test_vault_null_safety);
    RUN_SV(test_vault_result_names);

    #undef RUN_SV

    printf("  SECURE VAULT: %d/%d passed\n", total - failed, total);
    return failed;
}
