/*
 * test_storage_provider_local.c — Step 05 Tests: Local Persistent Storage.
 *
 * Tests:
 *   - Provider lifecycle (init, shutdown)
 *   - ID validation (path traversal, invalid chars)
 *   - CRUD operations (create, read, update, delete, exists, list, count)
 *   - Persistence across restart
 *   - Round-trip metadata preservation
 *   - Classification preservation
 *   - Corruption handling
 *   - Path traversal blocking
 *   - Security (no secrets, no path escapes)
 */

#include "../../tests/test_framework.h"
#include "../storage_provider.h"
#include "../storage_provider_local.h"
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

/* Test storage directory (under /tmp for safety) */
#define TEST_STORAGE_DIR "/tmp/ozayn_test_local_storage"

/* Helper: recursively remove test directory */
static void _cleanup_test_dir(void)
{
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "rm -rf %s", TEST_STORAGE_DIR);
    system(cmd);
}

/* ============================================================
 * PROVIDER LIFECYCLE TESTS
 * ============================================================ */

TEST(local_init_custom_dir) {
    _cleanup_test_dir();
    ozayn_storage_provider_t sp;
    ASSERT_EQ(ozayn_sp_local_create_provider(&sp, TEST_STORAGE_DIR), 0);
    ASSERT_EQ(ozayn_sp_init(&sp), OZAYN_SD_OK);
    ASSERT_EQ(ozayn_sp_is_ready(&sp), 1);

    /* Verify directory was created */
    struct stat st;
    ASSERT_EQ(stat(TEST_STORAGE_DIR, &st), 0);
    ASSERT(S_ISDIR(st.st_mode));

    ozayn_sp_shutdown(&sp);
    _cleanup_test_dir();
    return 0;
}

TEST(local_init_null_provider) {
    ASSERT_EQ(ozayn_sp_local_create_provider(NULL, "/tmp/x"), -1);
    return 0;
}

TEST(local_init_default_dir) {
    ozayn_storage_provider_t sp;
    ASSERT_EQ(ozayn_sp_local_create_provider(&sp, NULL), 0);
    ASSERT_EQ(ozayn_sp_init(&sp), OZAYN_SD_OK);
    ozayn_sp_shutdown(&sp);
    return 0;
}

/* ============================================================
 * ID VALIDATION TESTS
 * ============================================================ */

TEST(local_validate_id_valid) {
    ASSERT_EQ(ozayn_sp_local_validate_id("my_object_001"), 0);
    return 0;
}

TEST(local_validate_id_empty) {
    ASSERT_EQ(ozayn_sp_local_validate_id(""), -1);
    return 0;
}

TEST(local_validate_id_null) {
    ASSERT_EQ(ozayn_sp_local_validate_id(NULL), -1);
    return 0;
}

TEST(local_validate_id_traversal_dotdot) {
    ASSERT_EQ(ozayn_sp_local_validate_id("../test"), -1);
    return 0;
}

TEST(local_validate_id_traversal_backslash) {
    ASSERT_EQ(ozayn_sp_local_validate_id("..\\test"), -1);
    return 0;
}

TEST(local_validate_id_leading_dot) {
    ASSERT_EQ(ozayn_sp_local_validate_id(".hidden"), -1);
    return 0;
}

TEST(local_validate_id_absolute_path) {
    ASSERT_EQ(ozayn_sp_local_validate_id("/etc/passwd"), -1);
    return 0;
}

TEST(local_validate_id_long_id) {
    char long_id[200];
    memset(long_id, 'a', sizeof(long_id) - 1);
    long_id[sizeof(long_id) - 1] = '\0';
    ASSERT_EQ(ozayn_sp_local_validate_id(long_id), -1);
    return 0;
}

/* ============================================================
 * CREATE TESTS
 * ============================================================ */

TEST(local_create_valid) {
    _cleanup_test_dir();
    ozayn_storage_provider_t sp;
    ozayn_sp_local_create_provider(&sp, TEST_STORAGE_DIR);
    ozayn_sp_init(&sp);

    ozayn_secure_data_object_t obj;
    ozayn_sdo_init(&obj, "crt_001", OZAYN_DATA_CATEGORY_DOCUMENTS, "u", OZAYN_DATA_SCOPE_USER);
    ASSERT_EQ(ozayn_sp_create(&sp, &obj), OZAYN_SD_OK);
    ASSERT_EQ(ozayn_sp_count(&sp), 1);

    ozayn_sp_shutdown(&sp);
    _cleanup_test_dir();
    return 0;
}

TEST(local_create_duplicate) {
    _cleanup_test_dir();
    ozayn_storage_provider_t sp;
    ozayn_sp_local_create_provider(&sp, TEST_STORAGE_DIR);
    ozayn_sp_init(&sp);

    ozayn_secure_data_object_t obj;
    ozayn_sdo_init(&obj, "dup_001", OZAYN_DATA_CATEGORY_DOCUMENTS, "u", OZAYN_DATA_SCOPE_USER);
    ozayn_sp_create(&sp, &obj);
    ASSERT_EQ(ozayn_sp_create(&sp, &obj), OZAYN_SD_ERR_STATE);

    ozayn_sp_shutdown(&sp);
    _cleanup_test_dir();
    return 0;
}

TEST(local_create_invalid_id) {
    _cleanup_test_dir();
    ozayn_storage_provider_t sp;
    ozayn_sp_local_create_provider(&sp, TEST_STORAGE_DIR);
    ozayn_sp_init(&sp);

    ozayn_secure_data_object_t obj;
    ozayn_sdo_init(&obj, "../escape", OZAYN_DATA_CATEGORY_DOCUMENTS, "u", OZAYN_DATA_SCOPE_USER);
    ASSERT_EQ(ozayn_sp_create(&sp, &obj), OZAYN_SD_ERR_INVALID_DATA);

    ozayn_sp_shutdown(&sp);
    _cleanup_test_dir();
    return 0;
}

TEST(local_create_null) {
    _cleanup_test_dir();
    ozayn_storage_provider_t sp;
    ozayn_sp_local_create_provider(&sp, TEST_STORAGE_DIR);
    ozayn_sp_init(&sp);
    ASSERT_EQ(ozayn_sp_create(&sp, NULL), OZAYN_SD_ERR_NULL);

    ozayn_sp_shutdown(&sp);
    _cleanup_test_dir();
    return 0;
}

/* ============================================================
 * READ TESTS
 * ============================================================ */

TEST(local_read_existing) {
    _cleanup_test_dir();
    ozayn_storage_provider_t sp;
    ozayn_sp_local_create_provider(&sp, TEST_STORAGE_DIR);
    ozayn_sp_init(&sp);

    ozayn_secure_data_object_t obj;
    ozayn_sdo_init(&obj, "rd_001", OZAYN_DATA_CATEGORY_AI_MEMORY, "u", OZAYN_DATA_SCOPE_USER);
    ozayn_sp_create(&sp, &obj);

    ozayn_secure_data_object_t out;
    ASSERT_EQ(ozayn_sp_read(&sp, "rd_001", &out), OZAYN_SD_OK);
    ASSERT_STR_EQ(out.id, "rd_001");
    ASSERT_EQ(out.category, OZAYN_DATA_CATEGORY_AI_MEMORY);

    ozayn_sp_shutdown(&sp);
    _cleanup_test_dir();
    return 0;
}

TEST(local_read_missing) {
    _cleanup_test_dir();
    ozayn_storage_provider_t sp;
    ozayn_sp_local_create_provider(&sp, TEST_STORAGE_DIR);
    ozayn_sp_init(&sp);

    ozayn_secure_data_object_t out;
    ASSERT_EQ(ozayn_sp_read(&sp, "ghost", &out), OZAYN_SD_ERR_NOT_FOUND);

    ozayn_sp_shutdown(&sp);
    _cleanup_test_dir();
    return 0;
}

TEST(local_read_null) {
    _cleanup_test_dir();
    ozayn_storage_provider_t sp;
    ozayn_sp_local_create_provider(&sp, TEST_STORAGE_DIR);
    ozayn_sp_init(&sp);
    ASSERT_EQ(ozayn_sp_read(&sp, NULL, NULL), OZAYN_SD_ERR_NULL);

    ozayn_sp_shutdown(&sp);
    _cleanup_test_dir();
    return 0;
}

TEST(local_read_invalid_id) {
    _cleanup_test_dir();
    ozayn_storage_provider_t sp;
    ozayn_sp_local_create_provider(&sp, TEST_STORAGE_DIR);
    ozayn_sp_init(&sp);

    ozayn_secure_data_object_t out;
    ASSERT_EQ(ozayn_sp_read(&sp, "../../etc/passwd", &out), OZAYN_SD_ERR_INVALID_DATA);

    ozayn_sp_shutdown(&sp);
    _cleanup_test_dir();
    return 0;
}

/* ============================================================
 * UPDATE TESTS
 * ============================================================ */

TEST(local_update_existing) {
    _cleanup_test_dir();
    ozayn_storage_provider_t sp;
    ozayn_sp_local_create_provider(&sp, TEST_STORAGE_DIR);
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
    _cleanup_test_dir();
    return 0;
}

TEST(local_update_missing) {
    _cleanup_test_dir();
    ozayn_storage_provider_t sp;
    ozayn_sp_local_create_provider(&sp, TEST_STORAGE_DIR);
    ozayn_sp_init(&sp);

    ozayn_secure_data_object_t obj;
    ozayn_sdo_init(&obj, "nope", OZAYN_DATA_CATEGORY_DOCUMENTS, "u", OZAYN_DATA_SCOPE_USER);
    ASSERT_EQ(ozayn_sp_update(&sp, &obj), OZAYN_SD_ERR_NOT_FOUND);

    ozayn_sp_shutdown(&sp);
    _cleanup_test_dir();
    return 0;
}

TEST(local_update_invalid) {
    _cleanup_test_dir();
    ozayn_storage_provider_t sp;
    ozayn_sp_local_create_provider(&sp, TEST_STORAGE_DIR);
    ozayn_sp_init(&sp);

    ozayn_secure_data_object_t obj;
    memset(&obj, 0, sizeof(obj));
    ASSERT_EQ(ozayn_sp_update(&sp, &obj), OZAYN_SD_ERR_INVALID_DATA);

    ozayn_sp_shutdown(&sp);
    _cleanup_test_dir();
    return 0;
}

TEST(local_update_null) {
    _cleanup_test_dir();
    ozayn_storage_provider_t sp;
    ozayn_sp_local_create_provider(&sp, TEST_STORAGE_DIR);
    ozayn_sp_init(&sp);
    ASSERT_EQ(ozayn_sp_update(&sp, NULL), OZAYN_SD_ERR_NULL);

    ozayn_sp_shutdown(&sp);
    _cleanup_test_dir();
    return 0;
}

/* ============================================================
 * DELETE TESTS
 * ============================================================ */

TEST(local_delete_existing) {
    _cleanup_test_dir();
    ozayn_storage_provider_t sp;
    ozayn_sp_local_create_provider(&sp, TEST_STORAGE_DIR);
    ozayn_sp_init(&sp);

    ozayn_secure_data_object_t obj;
    ozayn_sdo_init(&obj, "del_001", OZAYN_DATA_CATEGORY_DOCUMENTS, "u", OZAYN_DATA_SCOPE_USER);
    ozayn_sp_create(&sp, &obj);
    ASSERT_EQ(ozayn_sp_delete(&sp, "del_001"), OZAYN_SD_OK);
    ASSERT_EQ(ozayn_sp_exists(&sp, "del_001"), 0);

    ozayn_sp_shutdown(&sp);
    _cleanup_test_dir();
    return 0;
}

TEST(local_delete_missing) {
    _cleanup_test_dir();
    ozayn_storage_provider_t sp;
    ozayn_sp_local_create_provider(&sp, TEST_STORAGE_DIR);
    ozayn_sp_init(&sp);
    ASSERT_EQ(ozayn_sp_delete(&sp, "ghost"), OZAYN_SD_ERR_NOT_FOUND);

    ozayn_sp_shutdown(&sp);
    _cleanup_test_dir();
    return 0;
}

TEST(local_delete_null) {
    _cleanup_test_dir();
    ozayn_storage_provider_t sp;
    ozayn_sp_local_create_provider(&sp, TEST_STORAGE_DIR);
    ozayn_sp_init(&sp);
    ASSERT_EQ(ozayn_sp_delete(&sp, NULL), OZAYN_SD_ERR_NULL);

    ozayn_sp_shutdown(&sp);
    _cleanup_test_dir();
    return 0;
}

/* ============================================================
 * EXISTS TESTS
 * ============================================================ */

TEST(local_exists_true) {
    _cleanup_test_dir();
    ozayn_storage_provider_t sp;
    ozayn_sp_local_create_provider(&sp, TEST_STORAGE_DIR);
    ozayn_sp_init(&sp);

    ozayn_secure_data_object_t obj;
    ozayn_sdo_init(&obj, "ex_001", OZAYN_DATA_CATEGORY_DOCUMENTS, "u", OZAYN_DATA_SCOPE_USER);
    ozayn_sp_create(&sp, &obj);
    ASSERT_EQ(ozayn_sp_exists(&sp, "ex_001"), 1);

    ozayn_sp_shutdown(&sp);
    _cleanup_test_dir();
    return 0;
}

TEST(local_exists_false) {
    _cleanup_test_dir();
    ozayn_storage_provider_t sp;
    ozayn_sp_local_create_provider(&sp, TEST_STORAGE_DIR);
    ozayn_sp_init(&sp);
    ASSERT_EQ(ozayn_sp_exists(&sp, "nope"), 0);

    ozayn_sp_shutdown(&sp);
    _cleanup_test_dir();
    return 0;
}

/* ============================================================
 * LIST TESTS
 * ============================================================ */

TEST(local_list_by_category) {
    _cleanup_test_dir();
    ozayn_storage_provider_t sp;
    ozayn_sp_local_create_provider(&sp, TEST_STORAGE_DIR);
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
    _cleanup_test_dir();
    return 0;
}

TEST(local_list_empty_category) {
    _cleanup_test_dir();
    ozayn_storage_provider_t sp;
    ozayn_sp_local_create_provider(&sp, TEST_STORAGE_DIR);
    ozayn_sp_init(&sp);

    ozayn_secure_data_object_t out[10];
    int count = ozayn_sp_list(&sp, OZAYN_DATA_CATEGORY_ARWE_INFORMATION, out, 10);
    ASSERT_EQ(count, 0);

    ozayn_sp_shutdown(&sp);
    _cleanup_test_dir();
    return 0;
}

TEST(local_list_empty_store) {
    _cleanup_test_dir();
    ozayn_storage_provider_t sp;
    ozayn_sp_local_create_provider(&sp, TEST_STORAGE_DIR);
    ozayn_sp_init(&sp);

    ozayn_secure_data_object_t out[10];
    int count = ozayn_sp_list(&sp, OZAYN_DATA_CATEGORY_DOCUMENTS, out, 10);
    ASSERT_EQ(count, 0);

    ozayn_sp_shutdown(&sp);
    _cleanup_test_dir();
    return 0;
}

/* ============================================================
 * COUNT TEST
 * ============================================================ */

TEST(local_count_after_ops) {
    _cleanup_test_dir();
    ozayn_storage_provider_t sp;
    ozayn_sp_local_create_provider(&sp, TEST_STORAGE_DIR);
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
    _cleanup_test_dir();
    return 0;
}

/* ============================================================
 * PERSISTENCE ACROSS RESTART TEST
 * ============================================================ */

TEST(local_persistence_across_restart) {
    _cleanup_test_dir();

    /* Provider instance A: create */
    ozayn_storage_provider_t sp_a;
    ozayn_sp_local_create_provider(&sp_a, TEST_STORAGE_DIR);
    ozayn_sp_init(&sp_a);

    ozayn_secure_data_object_t obj;
    ozayn_sdo_init(&obj, "persist_001", OZAYN_DATA_CATEGORY_CONVERSATION_HISTORY,
                   "user1", OZAYN_DATA_SCOPE_USER);
    obj.content_size = 2048;
    obj.created_at = 1700000000;
    ASSERT_EQ(ozayn_sp_create(&sp_a, &obj), OZAYN_SD_OK);
    ozayn_sp_shutdown(&sp_a);

    /* Provider instance B: read (simulates restart) */
    ozayn_storage_provider_t sp_b;
    ozayn_sp_local_create_provider(&sp_b, TEST_STORAGE_DIR);
    ozayn_sp_init(&sp_b);

    ozayn_secure_data_object_t read_back;
    ASSERT_EQ(ozayn_sp_read(&sp_b, "persist_001", &read_back), OZAYN_SD_OK);
    ASSERT_STR_EQ(read_back.id, "persist_001");
    ASSERT_EQ(read_back.category, OZAYN_DATA_CATEGORY_CONVERSATION_HISTORY);
    ASSERT_EQ(read_back.classification, OZAYN_SEC_LEVEL_SENSITIVE);
    ASSERT_EQ(read_back.scope, OZAYN_DATA_SCOPE_USER);
    ASSERT_EQ(read_back.content_size, 2048);
    ASSERT_EQ(read_back.created_at, 1700000000);

    ozayn_sp_shutdown(&sp_b);
    _cleanup_test_dir();
    return 0;
}

/* ============================================================
 * ROUND TRIP TEST
 * ============================================================ */

TEST(local_round_trip) {
    _cleanup_test_dir();
    ozayn_storage_provider_t sp;
    ozayn_sp_local_create_provider(&sp, TEST_STORAGE_DIR);
    ozayn_sp_init(&sp);

    ozayn_secure_data_object_t orig;
    ozayn_sdo_init(&orig, "rt_001", OZAYN_DATA_CATEGORY_DOCUMENTS, "user1", OZAYN_DATA_SCOPE_USER);
    orig.content_size = 4096;
    orig.checksum = 0xDEADBEEF;
    ozayn_sp_create(&sp, &orig);

    ozayn_secure_data_object_t read_back;
    ozayn_sp_read(&sp, "rt_001", &read_back);

    ASSERT_STR_EQ(read_back.id, orig.id);
    ASSERT_STR_EQ(read_back.version, orig.version);
    ASSERT_EQ(read_back.category, orig.category);
    ASSERT_EQ(read_back.classification, orig.classification);
    ASSERT_EQ(read_back.scope, orig.scope);
    ASSERT_STR_EQ(read_back.owner, orig.owner);
    ASSERT_EQ(read_back.content_size, orig.content_size);
    ASSERT_EQ(read_back.checksum, orig.checksum);

    ozayn_sp_shutdown(&sp);
    _cleanup_test_dir();
    return 0;
}

/* ============================================================
 * CLASSIFICATION PRESERVATION TEST
 * ============================================================ */

TEST(local_classification_preserved) {
    _cleanup_test_dir();
    ozayn_storage_provider_t sp;
    ozayn_sp_local_create_provider(&sp, TEST_STORAGE_DIR);
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
    _cleanup_test_dir();
    return 0;
}

/* ============================================================
 * CORRUPTION HANDLING TEST
 * ============================================================ */

TEST(local_corruption_handling) {
    _cleanup_test_dir();
    ozayn_storage_provider_t sp;
    ozayn_sp_local_create_provider(&sp, TEST_STORAGE_DIR);
    ozayn_sp_init(&sp);

    /* Create a valid object first */
    ozayn_secure_data_object_t obj;
    ozayn_sdo_init(&obj, "corr_001", OZAYN_DATA_CATEGORY_DOCUMENTS, "u", OZAYN_DATA_SCOPE_USER);
    ozayn_sp_create(&sp, &obj);

    /* Overwrite the file with garbage */
    char path[256];
    snprintf(path, sizeof(path), "%s/corr_001.sdo", TEST_STORAGE_DIR);
    FILE *f = fopen(path, "w");
    if (f) {
        fprintf(f, "GARBAGE DATA NOT A VALID OBJECT\n");
        fclose(f);
    }

    /* Read must fail with controlled error */
    ozayn_secure_data_object_t out;
    ozayn_secure_data_result_t rc = ozayn_sp_read(&sp, "corr_001", &out);
    ASSERT(rc == OZAYN_SD_ERR_INTEGRITY || rc == OZAYN_SD_ERR_NOT_FOUND);

    ozayn_sp_shutdown(&sp);
    _cleanup_test_dir();
    return 0;
}

/* ============================================================
 * PATH TRAVERSAL COMPREHENSIVE TEST
 * ============================================================ */

TEST(local_path_traversal_blocked) {
    _cleanup_test_dir();
    ozayn_storage_provider_t sp;
    ozayn_sp_local_create_provider(&sp, TEST_STORAGE_DIR);
    ozayn_sp_init(&sp);

    const char *bad_ids[] = {
        "../test", "../../test", "/etc/passwd",
        "..\\test", "..\\..\\test",
        ".hidden", "../../../etc/shadow",
        "a/b/c", "a\\b\\c",
        NULL
    };

    for (int i = 0; bad_ids[i]; i++) {
        ozayn_secure_data_object_t obj;
        ozayn_sdo_init(&obj, bad_ids[i], OZAYN_DATA_CATEGORY_DOCUMENTS, "u", OZAYN_DATA_SCOPE_USER);
        ASSERT_EQ(ozayn_sp_create(&sp, &obj), OZAYN_SD_ERR_INVALID_DATA);
    }

    ozayn_sp_shutdown(&sp);
    _cleanup_test_dir();
    return 0;
}

/* ============================================================
 * SECURITY TESTS
 * ============================================================ */

TEST(local_no_secrets_in_provider_name) {
    ozayn_storage_provider_t sp;
    ozayn_sp_local_create_provider(&sp, TEST_STORAGE_DIR);
    const char *name = sp.name;
    ASSERT_NOT_NULL(name);
    ASSERT(name[0] != '\0');
    const char *danger[] = { "password", "secret", "private_key", "token", NULL };
    for (int d = 0; danger[d]; d++) {
        ASSERT(strstr(name, danger[d]) == NULL);
    }
    return 0;
}

TEST(local_no_files_outside_dir) {
    _cleanup_test_dir();
    ozayn_storage_provider_t sp;
    ozayn_sp_local_create_provider(&sp, TEST_STORAGE_DIR);
    ozayn_sp_init(&sp);

    /* Attempt path traversal via create */
    ozayn_secure_data_object_t obj;
    ozayn_sdo_init(&obj, "../../escape_test", OZAYN_DATA_CATEGORY_DOCUMENTS, "u", OZAYN_DATA_SCOPE_USER);
    ozayn_sp_create(&sp, &obj);

    /* Verify no file was created outside the test dir */
    struct stat st;
    ASSERT_NEQ(stat("/tmp/escape_test.sdo", &st), 0);

    ozayn_sp_shutdown(&sp);
    _cleanup_test_dir();
    return 0;
}

/* ============================================================
 * RUN
 * ============================================================ */

int run_storage_provider_local_tests(void) {
    SUITE_BEGIN("Step 05: Local Persistent Storage Provider");

    /* Provider lifecycle (3 tests) */
    RUN(local_init_custom_dir);
    RUN(local_init_null_provider);
    RUN(local_init_default_dir);

    /* ID validation (7 tests) */
    RUN(local_validate_id_valid);
    RUN(local_validate_id_empty);
    RUN(local_validate_id_null);
    RUN(local_validate_id_traversal_dotdot);
    RUN(local_validate_id_traversal_backslash);
    RUN(local_validate_id_leading_dot);
    RUN(local_validate_id_absolute_path);
    RUN(local_validate_id_long_id);

    /* CREATE (4 tests) */
    RUN(local_create_valid);
    RUN(local_create_duplicate);
    RUN(local_create_invalid_id);
    RUN(local_create_null);

    /* READ (4 tests) */
    RUN(local_read_existing);
    RUN(local_read_missing);
    RUN(local_read_null);
    RUN(local_read_invalid_id);

    /* UPDATE (4 tests) */
    RUN(local_update_existing);
    RUN(local_update_missing);
    RUN(local_update_invalid);
    RUN(local_update_null);

    /* DELETE (3 tests) */
    RUN(local_delete_existing);
    RUN(local_delete_missing);
    RUN(local_delete_null);

    /* EXISTS (2 tests) */
    RUN(local_exists_true);
    RUN(local_exists_false);

    /* LIST (3 tests) */
    RUN(local_list_by_category);
    RUN(local_list_empty_category);
    RUN(local_list_empty_store);

    /* COUNT (1 test) */
    RUN(local_count_after_ops);

    /* PERSISTENCE (1 test) */
    RUN(local_persistence_across_restart);

    /* ROUND TRIP (1 test) */
    RUN(local_round_trip);

    /* CLASSIFICATION (1 test) */
    RUN(local_classification_preserved);

    /* CORRUPTION (1 test) */
    RUN(local_corruption_handling);

    /* PATH TRAVERSAL (1 test) */
    RUN(local_path_traversal_blocked);

    /* SECURITY (2 tests) */
    RUN(local_no_secrets_in_provider_name);
    RUN(local_no_files_outside_dir);

    SUITE_END();
    return TOTAL_FAIL();
}
