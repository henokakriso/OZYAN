/*
 * test_storage_provider.c — Step 04 Tests: Storage Abstraction & Provider Contract.
 *
 * Tests:
 *   - Provider lifecycle (init, shutdown, readiness)
 *   - CREATE (valid, duplicate, invalid, null)
 *   - READ (existing, missing, null, empty id)
 *   - UPDATE (existing, missing, invalid, null)
 *   - DELETE (existing, missing, null)
 *   - EXISTS (true, false)
 *   - LIST (by category, empty, multiple)
 *   - COUNT
 *   - ROUND TRIP (create → read → compare)
 *   - Classification preservation
 *   - Stats
 *   - Security (no secrets, provider name)
 *   - Invalid provider
 */

#include "../../tests/test_framework.h"
#include "../storage_provider.h"
#include "../storage_provider_mem.h"
#include <string.h>

/* ============================================================
 * PROVIDER LIFECYCLE TESTS
 * ============================================================ */

TEST(sp_lifecycle_init_success) {
    ozayn_storage_provider_t sp;
    ASSERT_EQ(ozayn_sp_mem_create_provider(&sp), 0);
    ASSERT_EQ(ozayn_sp_init(&sp), OZAYN_SD_OK);
    ASSERT_EQ(sp.state, OZAYN_SP_STATE_READY);
    ozayn_sp_shutdown(&sp);
    return 0;
}

TEST(sp_lifecycle_init_null) {
    ASSERT_EQ(ozayn_sp_init(NULL), OZAYN_SD_ERR_NULL);
    return 0;
}

TEST(sp_lifecycle_shutdown) {
    ozayn_storage_provider_t sp;
    ozayn_sp_mem_create_provider(&sp);
    ozayn_sp_init(&sp);
    ozayn_sp_shutdown(&sp);
    ASSERT_EQ(sp.state, OZAYN_SP_STATE_STOPPED);
    return 0;
}

TEST(sp_lifecycle_is_ready) {
    ozayn_storage_provider_t sp;
    ozayn_sp_mem_create_provider(&sp);
    ASSERT_EQ(ozayn_sp_is_ready(&sp), 0);
    ozayn_sp_init(&sp);
    ASSERT_EQ(ozayn_sp_is_ready(&sp), 1);
    ozayn_sp_shutdown(&sp);
    return 0;
}

TEST(sp_lifecycle_not_ready_before_init) {
    ozayn_storage_provider_t sp;
    ozayn_sp_mem_create_provider(&sp);
    ozayn_secure_data_object_t obj;
    ozayn_sdo_init(&obj, "x", OZAYN_DATA_CATEGORY_DOCUMENTS, "u", OZAYN_DATA_SCOPE_USER);
    ASSERT_EQ(ozayn_sp_create(&sp, &obj), OZAYN_SD_ERR_NOT_INITIALIZED);
    return 0;
}

/* ============================================================
 * CREATE TESTS
 * ============================================================ */

TEST(sp_create_valid) {
    ozayn_storage_provider_t sp;
    ozayn_sp_mem_create_provider(&sp);
    ozayn_sp_init(&sp);
    ozayn_secure_data_object_t obj;
    ozayn_sdo_init(&obj, "crt_001", OZAYN_DATA_CATEGORY_DOCUMENTS, "u", OZAYN_DATA_SCOPE_USER);
    ASSERT_EQ(ozayn_sp_create(&sp, &obj), OZAYN_SD_OK);
    ASSERT_EQ(ozayn_sp_count(&sp), 1);
    ozayn_sp_shutdown(&sp);
    return 0;
}

TEST(sp_create_duplicate) {
    ozayn_storage_provider_t sp;
    ozayn_sp_mem_create_provider(&sp);
    ozayn_sp_init(&sp);
    ozayn_secure_data_object_t obj;
    ozayn_sdo_init(&obj, "dup_001", OZAYN_DATA_CATEGORY_DOCUMENTS, "u", OZAYN_DATA_SCOPE_USER);
    ozayn_sp_create(&sp, &obj);
    ASSERT_EQ(ozayn_sp_create(&sp, &obj), OZAYN_SD_ERR_STATE);
    ozayn_sp_shutdown(&sp);
    return 0;
}

TEST(sp_create_invalid_object) {
    ozayn_storage_provider_t sp;
    ozayn_sp_mem_create_provider(&sp);
    ozayn_sp_init(&sp);
    ozayn_secure_data_object_t obj;
    memset(&obj, 0, sizeof(obj));
    /* Empty id makes it invalid — dispatch should reject */
    ASSERT_EQ(ozayn_sp_create(&sp, &obj), OZAYN_SD_ERR_INVALID_DATA);
    ozayn_sp_shutdown(&sp);
    return 0;
}

TEST(sp_create_null) {
    ozayn_storage_provider_t sp;
    ozayn_sp_mem_create_provider(&sp);
    ozayn_sp_init(&sp);
    ASSERT_EQ(ozayn_sp_create(&sp, NULL), OZAYN_SD_ERR_NULL);
    ozayn_sp_shutdown(&sp);
    return 0;
}

/* ============================================================
 * READ TESTS
 * ============================================================ */

TEST(sp_read_existing) {
    ozayn_storage_provider_t sp;
    ozayn_sp_mem_create_provider(&sp);
    ozayn_sp_init(&sp);
    ozayn_secure_data_object_t obj;
    ozayn_sdo_init(&obj, "rd_001", OZAYN_DATA_CATEGORY_AI_MEMORY, "u", OZAYN_DATA_SCOPE_USER);
    ozayn_sp_create(&sp, &obj);

    ozayn_secure_data_object_t out;
    ASSERT_EQ(ozayn_sp_read(&sp, "rd_001", &out), OZAYN_SD_OK);
    ASSERT_STR_EQ(out.id, "rd_001");
    ASSERT_EQ(out.category, OZAYN_DATA_CATEGORY_AI_MEMORY);
    ozayn_sp_shutdown(&sp);
    return 0;
}

TEST(sp_read_missing) {
    ozayn_storage_provider_t sp;
    ozayn_sp_mem_create_provider(&sp);
    ozayn_sp_init(&sp);
    ozayn_secure_data_object_t out;
    ASSERT_EQ(ozayn_sp_read(&sp, "ghost", &out), OZAYN_SD_ERR_NOT_FOUND);
    ozayn_sp_shutdown(&sp);
    return 0;
}

TEST(sp_read_null) {
    ozayn_storage_provider_t sp;
    ozayn_sp_mem_create_provider(&sp);
    ozayn_sp_init(&sp);
    ASSERT_EQ(ozayn_sp_read(&sp, NULL, NULL), OZAYN_SD_ERR_NULL);
    ozayn_sp_shutdown(&sp);
    return 0;
}

TEST(sp_read_empty_id) {
    ozayn_storage_provider_t sp;
    ozayn_sp_mem_create_provider(&sp);
    ozayn_sp_init(&sp);
    ozayn_secure_data_object_t out;
    ASSERT_EQ(ozayn_sp_read(&sp, "", &out), OZAYN_SD_ERR_INVALID_REQUEST);
    ozayn_sp_shutdown(&sp);
    return 0;
}

/* ============================================================
 * UPDATE TESTS
 * ============================================================ */

TEST(sp_update_existing) {
    ozayn_storage_provider_t sp;
    ozayn_sp_mem_create_provider(&sp);
    ozayn_sp_init(&sp);
    ozayn_secure_data_object_t obj;
    ozayn_sdo_init(&obj, "upd_001", OZAYN_DATA_CATEGORY_DOCUMENTS, "u", OZAYN_DATA_SCOPE_USER);
    ozayn_sp_create(&sp, &obj);

    ozayn_secure_data_object_t new_obj;
    ozayn_sdo_init(&new_obj, "upd_001", OZAYN_DATA_CATEGORY_CONVERSATION_HISTORY, "u2", OZAYN_DATA_SCOPE_SESSION);
    ASSERT_EQ(ozayn_sp_update(&sp, &new_obj), OZAYN_SD_OK);

    ozayn_secure_data_object_t read_back;
    ozayn_sp_read(&sp, "upd_001", &read_back);
    ASSERT_EQ(read_back.category, OZAYN_DATA_CATEGORY_CONVERSATION_HISTORY);
    ozayn_sp_shutdown(&sp);
    return 0;
}

TEST(sp_update_missing) {
    ozayn_storage_provider_t sp;
    ozayn_sp_mem_create_provider(&sp);
    ozayn_sp_init(&sp);
    ozayn_secure_data_object_t obj;
    ozayn_sdo_init(&obj, "nope", OZAYN_DATA_CATEGORY_DOCUMENTS, "u", OZAYN_DATA_SCOPE_USER);
    ASSERT_EQ(ozayn_sp_update(&sp, &obj), OZAYN_SD_ERR_NOT_FOUND);
    ozayn_sp_shutdown(&sp);
    return 0;
}

TEST(sp_update_invalid) {
    ozayn_storage_provider_t sp;
    ozayn_sp_mem_create_provider(&sp);
    ozayn_sp_init(&sp);
    ozayn_secure_data_object_t obj;
    memset(&obj, 0, sizeof(obj));
    ASSERT_EQ(ozayn_sp_update(&sp, &obj), OZAYN_SD_ERR_INVALID_DATA);
    ozayn_sp_shutdown(&sp);
    return 0;
}

TEST(sp_update_null) {
    ozayn_storage_provider_t sp;
    ozayn_sp_mem_create_provider(&sp);
    ozayn_sp_init(&sp);
    ASSERT_EQ(ozayn_sp_update(&sp, NULL), OZAYN_SD_ERR_NULL);
    ozayn_sp_shutdown(&sp);
    return 0;
}

/* ============================================================
 * DELETE TESTS
 * ============================================================ */

TEST(sp_delete_existing) {
    ozayn_storage_provider_t sp;
    ozayn_sp_mem_create_provider(&sp);
    ozayn_sp_init(&sp);
    ozayn_secure_data_object_t obj;
    ozayn_sdo_init(&obj, "del_001", OZAYN_DATA_CATEGORY_DOCUMENTS, "u", OZAYN_DATA_SCOPE_USER);
    ozayn_sp_create(&sp, &obj);
    ASSERT_EQ(ozayn_sp_delete(&sp, "del_001"), OZAYN_SD_OK);
    ASSERT_EQ(ozayn_sp_exists(&sp, "del_001"), 0);
    ozayn_sp_shutdown(&sp);
    return 0;
}

TEST(sp_delete_missing) {
    ozayn_storage_provider_t sp;
    ozayn_sp_mem_create_provider(&sp);
    ozayn_sp_init(&sp);
    ASSERT_EQ(ozayn_sp_delete(&sp, "ghost"), OZAYN_SD_ERR_NOT_FOUND);
    ozayn_sp_shutdown(&sp);
    return 0;
}

TEST(sp_delete_null) {
    ozayn_storage_provider_t sp;
    ozayn_sp_mem_create_provider(&sp);
    ozayn_sp_init(&sp);
    ASSERT_EQ(ozayn_sp_delete(&sp, NULL), OZAYN_SD_ERR_NULL);
    ozayn_sp_shutdown(&sp);
    return 0;
}

/* ============================================================
 * EXISTS TESTS
 * ============================================================ */

TEST(sp_exists_true) {
    ozayn_storage_provider_t sp;
    ozayn_sp_mem_create_provider(&sp);
    ozayn_sp_init(&sp);
    ozayn_secure_data_object_t obj;
    ozayn_sdo_init(&obj, "ex_001", OZAYN_DATA_CATEGORY_DOCUMENTS, "u", OZAYN_DATA_SCOPE_USER);
    ozayn_sp_create(&sp, &obj);
    ASSERT_EQ(ozayn_sp_exists(&sp, "ex_001"), 1);
    ozayn_sp_shutdown(&sp);
    return 0;
}

TEST(sp_exists_false) {
    ozayn_storage_provider_t sp;
    ozayn_sp_mem_create_provider(&sp);
    ozayn_sp_init(&sp);
    ASSERT_EQ(ozayn_sp_exists(&sp, "nope"), 0);
    ozayn_sp_shutdown(&sp);
    return 0;
}

/* ============================================================
 * LIST TESTS
 * ============================================================ */

TEST(sp_list_by_category) {
    ozayn_storage_provider_t sp;
    ozayn_sp_mem_create_provider(&sp);
    ozayn_sp_init(&sp);
    ozayn_secure_data_object_t m1, m2, m3;
    ozayn_sdo_init(&m1, "ls_a", OZAYN_DATA_CATEGORY_DOCUMENTS, "u", OZAYN_DATA_SCOPE_USER);
    ozayn_sdo_init(&m2, "ls_b", OZAYN_DATA_CATEGORY_AI_MEMORY, "u", OZAYN_DATA_SCOPE_USER);
    ozayn_sdo_init(&m3, "ls_c", OZAYN_DATA_CATEGORY_DOCUMENTS, "u", OZAYN_DATA_SCOPE_USER);
    ozayn_sp_create(&sp, &m1);
    ozayn_sp_create(&sp, &m2);
    ozayn_sp_create(&sp, &m3);

    ozayn_secure_data_object_t out[10];
    int count = ozayn_sp_list(&sp, OZAYN_DATA_CATEGORY_DOCUMENTS, out, 10);
    ASSERT_EQ(count, 2);
    ozayn_sp_shutdown(&sp);
    return 0;
}

TEST(sp_list_empty_category) {
    ozayn_storage_provider_t sp;
    ozayn_sp_mem_create_provider(&sp);
    ozayn_sp_init(&sp);
    ozayn_secure_data_object_t out[10];
    int count = ozayn_sp_list(&sp, OZAYN_DATA_CATEGORY_ARWE_INFORMATION, out, 10);
    ASSERT_EQ(count, 0);
    ozayn_sp_shutdown(&sp);
    return 0;
}

TEST(sp_list_empty_store) {
    ozayn_storage_provider_t sp;
    ozayn_sp_mem_create_provider(&sp);
    ozayn_sp_init(&sp);
    ozayn_secure_data_object_t out[10];
    int count = ozayn_sp_list(&sp, OZAYN_DATA_CATEGORY_DOCUMENTS, out, 10);
    ASSERT_EQ(count, 0);
    ozayn_sp_shutdown(&sp);
    return 0;
}

/* ============================================================
 * COUNT TEST
 * ============================================================ */

TEST(sp_count_after_operations) {
    ozayn_storage_provider_t sp;
    ozayn_sp_mem_create_provider(&sp);
    ozayn_sp_init(&sp);
    ozayn_secure_data_object_t m1, m2;
    ozayn_sdo_init(&m1, "cnt_a", OZAYN_DATA_CATEGORY_DOCUMENTS, "u", OZAYN_DATA_SCOPE_USER);
    ozayn_sdo_init(&m2, "cnt_b", OZAYN_DATA_CATEGORY_AI_MEMORY, "u", OZAYN_DATA_SCOPE_USER);
    ozayn_sp_create(&sp, &m1);
    ozayn_sp_create(&sp, &m2);
    ASSERT_EQ(ozayn_sp_count(&sp), 2);
    ozayn_sp_delete(&sp, "cnt_a");
    ASSERT_EQ(ozayn_sp_count(&sp), 1);
    ozayn_sp_shutdown(&sp);
    return 0;
}

/* ============================================================
 * ROUND TRIP TEST
 * ============================================================ */

TEST(sp_round_trip_create_read) {
    ozayn_storage_provider_t sp;
    ozayn_sp_mem_create_provider(&sp);
    ozayn_sp_init(&sp);

    ozayn_secure_data_object_t orig;
    ozayn_sdo_init(&orig, "rt_001", OZAYN_DATA_CATEGORY_CONVERSATION_HISTORY, "user1", OZAYN_DATA_SCOPE_USER);
    orig.content_size = 1024;
    ozayn_sp_create(&sp, &orig);

    ozayn_secure_data_object_t read_back;
    ASSERT_EQ(ozayn_sp_read(&sp, "rt_001", &read_back), OZAYN_SD_OK);
    ASSERT_STR_EQ(read_back.id, orig.id);
    ASSERT_EQ(read_back.category, orig.category);
    ASSERT_EQ(read_back.classification, orig.classification);
    ASSERT_EQ(read_back.scope, orig.scope);
    ASSERT_EQ(read_back.content_size, orig.content_size);
    ozayn_sp_shutdown(&sp);
    return 0;
}

/* ============================================================
 * CLASSIFICATION PRESERVATION TEST
 * ============================================================ */

TEST(sp_classification_preserved) {
    ozayn_storage_provider_t sp;
    ozayn_sp_mem_create_provider(&sp);
    ozayn_sp_init(&sp);

    ozayn_secure_data_object_t obj;
    ozayn_sdo_init(&obj, "cp_001", OZAYN_DATA_CATEGORY_AUTH_INFO, "sys", OZAYN_DATA_SCOPE_SYSTEM);
    ASSERT_EQ(obj.classification, OZAYN_SEC_LEVEL_HIGHLY_SENSITIVE);
    ozayn_sp_create(&sp, &obj);

    ozayn_secure_data_object_t read_back;
    ozayn_sp_read(&sp, "cp_001", &read_back);
    ASSERT_EQ(read_back.classification, OZAYN_SEC_LEVEL_HIGHLY_SENSITIVE);
    ASSERT_EQ(read_back.category, OZAYN_DATA_CATEGORY_AUTH_INFO);
    ozayn_sp_shutdown(&sp);
    return 0;
}

/* ============================================================
 * STATS TEST
 * ============================================================ */

TEST(sp_stats_after_operations) {
    ozayn_storage_provider_t sp;
    ozayn_sp_mem_create_provider(&sp);
    ozayn_sp_init(&sp);
    ozayn_secure_data_object_t obj;
    ozayn_sdo_init(&obj, "st_001", OZAYN_DATA_CATEGORY_DOCUMENTS, "u", OZAYN_DATA_SCOPE_USER);
    ozayn_sp_create(&sp, &obj);

    ozayn_secure_data_object_t out;
    ozayn_sp_read(&sp, "st_001", &out);
    ozayn_sp_delete(&sp, "st_001");

    ozayn_sp_stats_t stats = ozayn_sp_stats(&sp);
    ASSERT_EQ(stats.total_creates, 1);
    ASSERT_EQ(stats.total_reads, 1);
    ASSERT_EQ(stats.total_deletes, 1);
    ozayn_sp_shutdown(&sp);
    return 0;
}

/* ============================================================
 * SECURITY TESTS
 * ============================================================ */

TEST(sp_no_secrets_in_provider_name) {
    ozayn_storage_provider_t sp;
    ozayn_sp_mem_create_provider(&sp);
    const char *name = sp.name;
    ASSERT_NOT_NULL(name);
    ASSERT(name[0] != '\0');
    const char *danger[] = { "password", "secret", "private_key", "key", "token", NULL };
    for (int d = 0; danger[d]; d++) {
        ASSERT(strstr(name, danger[d]) == NULL);
    }
    return 0;
}

TEST(sp_state_name_safe) {
    const char *n = ozayn_sp_state_name(OZAYN_SP_STATE_READY);
    ASSERT_NOT_NULL(n);
    ASSERT(n[0] != '\0');
    const char *danger[] = { "password", "secret", "private_key", NULL };
    for (int d = 0; danger[d]; d++) {
        ASSERT(strstr(n, danger[d]) == NULL);
    }
    return 0;
}

/* ============================================================
 * INVALID PROVIDER TEST
 * ============================================================ */

TEST(sp_null_ops_provider) {
    ozayn_storage_provider_t sp;
    memset(&sp, 0, sizeof(sp));
    sp.state = OZAYN_SP_STATE_READY;
    /* No ops — dispatch should return error */
    ozayn_secure_data_object_t obj;
    ozayn_sdo_init(&obj, "x", OZAYN_DATA_CATEGORY_DOCUMENTS, "u", OZAYN_DATA_SCOPE_USER);
    ASSERT_EQ(ozayn_sp_create(&sp, &obj), OZAYN_SD_ERR_INVALID_REQUEST);
    return 0;
}

/* ============================================================
 * RUN
 * ============================================================ */

int run_storage_provider_tests(void) {
    SUITE_BEGIN("Step 04: Storage Abstraction & Provider Contract");

    /* Provider lifecycle (5 tests) */
    RUN(sp_lifecycle_init_success);
    RUN(sp_lifecycle_init_null);
    RUN(sp_lifecycle_shutdown);
    RUN(sp_lifecycle_is_ready);
    RUN(sp_lifecycle_not_ready_before_init);

    /* CREATE (4 tests) */
    RUN(sp_create_valid);
    RUN(sp_create_duplicate);
    RUN(sp_create_invalid_object);
    RUN(sp_create_null);

    /* READ (4 tests) */
    RUN(sp_read_existing);
    RUN(sp_read_missing);
    RUN(sp_read_null);
    RUN(sp_read_empty_id);

    /* UPDATE (4 tests) */
    RUN(sp_update_existing);
    RUN(sp_update_missing);
    RUN(sp_update_invalid);
    RUN(sp_update_null);

    /* DELETE (3 tests) */
    RUN(sp_delete_existing);
    RUN(sp_delete_missing);
    RUN(sp_delete_null);

    /* EXISTS (2 tests) */
    RUN(sp_exists_true);
    RUN(sp_exists_false);

    /* LIST (3 tests) */
    RUN(sp_list_by_category);
    RUN(sp_list_empty_category);
    RUN(sp_list_empty_store);

    /* COUNT (1 test) */
    RUN(sp_count_after_operations);

    /* ROUND TRIP (1 test) */
    RUN(sp_round_trip_create_read);

    /* Classification preservation (1 test) */
    RUN(sp_classification_preserved);

    /* Stats (1 test) */
    RUN(sp_stats_after_operations);

    /* Security (2 tests) */
    RUN(sp_no_secrets_in_provider_name);
    RUN(sp_state_name_safe);

    /* Invalid provider (1 test) */
    RUN(sp_null_ops_provider);

    SUITE_END();
    return TOTAL_FAIL();
}
