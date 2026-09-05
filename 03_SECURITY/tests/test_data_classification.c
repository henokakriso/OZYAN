/*
 * test_data_classification.c — Step 02 Tests: Data Classification & Storage Boundary.
 *
 * Tests:
 *   - Classification: every data category has a valid default classification
 *   - Boundary: Secure Data interface initializes and operates correctly
 *   - Invalid requests: malformed operations fail safely
 *   - Missing data: non-existent data returns correct errors
 *   - Sensitive logging: protected data not exposed through name helpers
 *   - Metadata: init, validate, sensitivity checks
 *   - Storage lifecycle: create, read, update, delete, exists, list
 */

#include "../../tests/test_framework.h"
#include "../data_classification.h"
#include "../secure_data.h"

/* ============================================================
 * CLASSIFICATION TESTS
 * ============================================================ */

TEST(classification_user_preferences_has_default) {
    ozayn_security_level_t lvl = ozayn_data_default_classification(OZAYN_DATA_CATEGORY_USER_PREFERENCES);
    ASSERT_EQ(lvl, OZAYN_SEC_LEVEL_SENSITIVE);
    return 0;
}

TEST(classification_identity_information_has_default) {
    ozayn_security_level_t lvl = ozayn_data_default_classification(OZAYN_DATA_CATEGORY_IDENTITY_INFORMATION);
    ASSERT_EQ(lvl, OZAYN_SEC_LEVEL_HIGHLY_SENSITIVE);
    return 0;
}

TEST(classification_auth_info_has_default) {
    ozayn_security_level_t lvl = ozayn_data_default_classification(OZAYN_DATA_CATEGORY_AUTH_INFO);
    ASSERT_EQ(lvl, OZAYN_SEC_LEVEL_HIGHLY_SENSITIVE);
    return 0;
}

TEST(classification_conversation_history_has_default) {
    ozayn_security_level_t lvl = ozayn_data_default_classification(OZAYN_DATA_CATEGORY_CONVERSATION_HISTORY);
    ASSERT_EQ(lvl, OZAYN_SEC_LEVEL_SENSITIVE);
    return 0;
}

TEST(classification_ai_memory_has_default) {
    ozayn_security_level_t lvl = ozayn_data_default_classification(OZAYN_DATA_CATEGORY_AI_MEMORY);
    ASSERT_EQ(lvl, OZAYN_SEC_LEVEL_SENSITIVE);
    return 0;
}

TEST(classification_documents_has_default) {
    ozayn_security_level_t lvl = ozayn_data_default_classification(OZAYN_DATA_CATEGORY_DOCUMENTS);
    ASSERT_EQ(lvl, OZAYN_SEC_LEVEL_SENSITIVE);
    return 0;
}

TEST(classification_system_config_has_default) {
    ozayn_security_level_t lvl = ozayn_data_default_classification(OZAYN_DATA_CATEGORY_SYSTEM_CONFIGURATION);
    ASSERT_EQ(lvl, OZAYN_SEC_LEVEL_INTERNAL);
    return 0;
}

TEST(classification_security_events_has_default) {
    ozayn_security_level_t lvl = ozayn_data_default_classification(OZAYN_DATA_CATEGORY_SECURITY_EVENTS);
    ASSERT_EQ(lvl, OZAYN_SEC_LEVEL_SENSITIVE);
    return 0;
}

TEST(classification_arwe_info_has_default) {
    ozayn_security_level_t lvl = ozayn_data_default_classification(OZAYN_DATA_CATEGORY_ARWE_INFORMATION);
    ASSERT_EQ(lvl, OZAYN_SEC_LEVEL_SENSITIVE);
    return 0;
}

TEST(classification_invalid_category_returns_public) {
    ozayn_security_level_t lvl = ozayn_data_default_classification((ozayn_data_category_t)99);
    ASSERT_EQ(lvl, OZAYN_SEC_LEVEL_PUBLIC);
    return 0;
}

TEST(classification_category_count_is_nine) {
    ASSERT_EQ(OZAYN_DATA_CATEGORY_COUNT, 9);
    return 0;
}

/* ============================================================
 * NAME HELPER TESTS (no sensitive data exposed)
 * ============================================================ */

TEST(name_helpers_category_returns_string) {
    const char *name = ozayn_data_category_name(OZAYN_DATA_CATEGORY_USER_PREFERENCES);
    ASSERT_NOT_NULL(name);
    ASSERT(name[0] != '\0');
    return 0;
}

TEST(name_helpers_level_returns_string) {
    const char *name = ozayn_security_level_name(OZAYN_SEC_LEVEL_SENSITIVE);
    ASSERT_NOT_NULL(name);
    ASSERT(name[0] != '\0');
    return 0;
}

TEST(name_helpers_integrity_returns_string) {
    const char *name = ozayn_data_integrity_name(OZAYN_DATA_INTEGRITY_VALID);
    ASSERT_NOT_NULL(name);
    ASSERT(name[0] != '\0');
    return 0;
}

TEST(name_helpers_storage_state_returns_string) {
    const char *name = ozayn_data_storage_state_name(OZAYN_DATA_STORAGE_ACTIVE);
    ASSERT_NOT_NULL(name);
    ASSERT(name[0] != '\0');
    return 0;
}

TEST(name_helpers_result_returns_string) {
    const char *name = ozayn_secure_data_result_name(OZAYN_SD_OK);
    ASSERT_NOT_NULL(name);
    ASSERT(name[0] != '\0');
    return 0;
}

TEST(name_helpers_invalid_category_returns_unknown) {
    const char *name = ozayn_data_category_name((ozayn_data_category_t)99);
    ASSERT_STR_EQ(name, "Unknown Category");
    return 0;
}

TEST(name_helpers_invalid_level_returns_unknown) {
    const char *name = ozayn_security_level_name((ozayn_security_level_t)99);
    ASSERT_STR_EQ(name, "Unknown Level");
    return 0;
}

TEST(name_helpers_no_secrets_in_names) {
    /* Verify name strings do not contain sensitive keywords */
    const char *danger[] = { "password", "secret", "private_key", "token", "credential", NULL };
    for (int c = 0; c < OZAYN_DATA_CATEGORY_COUNT; c++) {
        const char *cat_name = ozayn_data_category_name((ozayn_data_category_t)c);
        for (int d = 0; danger[d]; d++) {
            ASSERT(strstr(cat_name, danger[d]) == NULL);
        }
    }
    return 0;
}

/* ============================================================
 * METADATA TESTS
 * ============================================================ */

TEST(metadata_init_valid) {
    ozayn_data_metadata_t meta;
    int rc = ozayn_data_metadata_init(&meta, "test_obj_001",
                                       OZAYN_DATA_CATEGORY_USER_PREFERENCES, "test_scope");
    ASSERT_EQ(rc, 0);
    ASSERT_STR_EQ(meta.id, "test_obj_001");
    ASSERT_EQ(meta.category, OZAYN_DATA_CATEGORY_USER_PREFERENCES);
    ASSERT_EQ(meta.classification, OZAYN_SEC_LEVEL_SENSITIVE);
    ASSERT_STR_EQ(meta.owner, "test_scope");
    ASSERT_EQ(meta.storage_state, OZAYN_DATA_STORAGE_INACTIVE);
    return 0;
}

TEST(metadata_init_null_fails) {
    ASSERT_EQ(ozayn_data_metadata_init(NULL, "id", OZAYN_DATA_CATEGORY_DOCUMENTS, "owner"), -1);
    return 0;
}

TEST(metadata_init_empty_id_fails) {
    ozayn_data_metadata_t meta;
    ASSERT_EQ(ozayn_data_metadata_init(&meta, "", OZAYN_DATA_CATEGORY_DOCUMENTS, "owner"), -1);
    return 0;
}

TEST(metadata_validate_valid) {
    ozayn_data_metadata_t meta;
    ozayn_data_metadata_init(&meta, "valid_id", OZAYN_DATA_CATEGORY_AI_MEMORY, "scope");
    ASSERT_EQ(ozayn_data_metadata_validate(&meta), 0);
    return 0;
}

TEST(metadata_validate_null_fails) {
    ASSERT_EQ(ozayn_data_metadata_validate(NULL), -1);
    return 0;
}

TEST(metadata_is_sensitive_true_for_sensitive) {
    ozayn_data_metadata_t meta;
    ozayn_data_metadata_init(&meta, "s", OZAYN_DATA_CATEGORY_USER_PREFERENCES, "o");
    ASSERT_EQ(ozayn_data_metadata_is_sensitive(&meta), 1);
    return 0;
}

TEST(metadata_is_sensitive_false_for_internal) {
    ozayn_data_metadata_t meta;
    ozayn_data_metadata_init(&meta, "i", OZAYN_DATA_CATEGORY_SYSTEM_CONFIGURATION, "o");
    ASSERT_EQ(ozayn_data_metadata_is_sensitive(&meta), 0);
    return 0;
}

TEST(metadata_is_sensitive_false_for_null) {
    ASSERT_EQ(ozayn_data_metadata_is_sensitive(NULL), 0);
    return 0;
}

/* ============================================================
 * STORAGE BOUNDARY TESTS
 * ============================================================ */

TEST(boundary_init_success) {
    ozayn_secure_data_manager_t mgr;
    ozayn_secure_data_result_t rc = ozayn_secure_data_init(&mgr);
    ASSERT_EQ(rc, OZAYN_SD_OK);
    ASSERT_EQ(mgr.initialized, 1);
    ASSERT_EQ(mgr.object_count, 0);
    return 0;
}

TEST(boundary_init_null_fails) {
    ASSERT_EQ(ozayn_secure_data_init(NULL), OZAYN_SD_ERR_NULL);
    return 0;
}

TEST(boundary_shutdown_clears) {
    ozayn_secure_data_manager_t mgr;
    ozayn_secure_data_init(&mgr);
    ozayn_secure_data_shutdown(&mgr);
    ASSERT_EQ(mgr.initialized, 0);
    return 0;
}

TEST(boundary_is_initialized_true) {
    ozayn_secure_data_manager_t mgr;
    ozayn_secure_data_init(&mgr);
    ASSERT_EQ(ozayn_secure_data_is_initialized(&mgr), 1);
    return 0;
}

TEST(boundary_is_initialized_false) {
    ozayn_secure_data_manager_t mgr;
    memset(&mgr, 0, sizeof(mgr));
    ASSERT_EQ(ozayn_secure_data_is_initialized(&mgr), 0);
    return 0;
}

/* ============================================================
 * CREATE / READ / UPDATE / DELETE TESTS
 * ============================================================ */

TEST(create_valid_object) {
    ozayn_secure_data_manager_t mgr;
    ozayn_secure_data_init(&mgr);
    ozayn_data_metadata_t meta;
    ozayn_data_metadata_init(&meta, "doc_001", OZAYN_DATA_CATEGORY_DOCUMENTS, "user1");
    ASSERT_EQ(ozayn_secure_data_create(&mgr, &meta), OZAYN_SD_OK);
    ASSERT_EQ(mgr.object_count, 1);
    return 0;
}

TEST(create_duplicate_fails) {
    ozayn_secure_data_manager_t mgr;
    ozayn_secure_data_init(&mgr);
    ozayn_data_metadata_t meta;
    ozayn_data_metadata_init(&meta, "dup_001", OZAYN_DATA_CATEGORY_DOCUMENTS, "user1");
    ASSERT_EQ(ozayn_secure_data_create(&mgr, &meta), OZAYN_SD_OK);
    ASSERT_EQ(ozayn_secure_data_create(&mgr, &meta), OZAYN_SD_ERR_STATE);
    return 0;
}

TEST(create_not_initialized_fails) {
    ozayn_secure_data_manager_t mgr;
    memset(&mgr, 0, sizeof(mgr));
    ozayn_data_metadata_t meta;
    ozayn_data_metadata_init(&meta, "x", OZAYN_DATA_CATEGORY_DOCUMENTS, "u");
    ASSERT_EQ(ozayn_secure_data_create(&mgr, &meta), OZAYN_SD_ERR_NOT_INITIALIZED);
    return 0;
}

TEST(create_null_fails) {
    ASSERT_EQ(ozayn_secure_data_create(NULL, NULL), OZAYN_SD_ERR_NULL);
    return 0;
}

TEST(read_existing_object) {
    ozayn_secure_data_manager_t mgr;
    ozayn_secure_data_init(&mgr);
    ozayn_data_metadata_t meta;
    ozayn_data_metadata_init(&meta, "read_001", OZAYN_DATA_CATEGORY_AI_MEMORY, "user1");
    ozayn_secure_data_create(&mgr, &meta);

    ozayn_data_metadata_t out;
    ASSERT_EQ(ozayn_secure_data_read(&mgr, "read_001", &out), OZAYN_SD_OK);
    ASSERT_STR_EQ(out.id, "read_001");
    ASSERT_EQ(out.category, OZAYN_DATA_CATEGORY_AI_MEMORY);
    return 0;
}

TEST(read_not_found) {
    ozayn_secure_data_manager_t mgr;
    ozayn_secure_data_init(&mgr);
    ozayn_data_metadata_t out;
    ASSERT_EQ(ozayn_secure_data_read(&mgr, "nonexistent", &out), OZAYN_SD_ERR_NOT_FOUND);
    return 0;
}

TEST(read_not_initialized) {
    ozayn_secure_data_manager_t mgr;
    memset(&mgr, 0, sizeof(mgr));
    ozayn_data_metadata_t out;
    ASSERT_EQ(ozayn_secure_data_read(&mgr, "x", &out), OZAYN_SD_ERR_NOT_INITIALIZED);
    return 0;
}

TEST(read_null_fails) {
    ASSERT_EQ(ozayn_secure_data_read(NULL, NULL, NULL), OZAYN_SD_ERR_NULL);
    return 0;
}

TEST(update_existing_object) {
    ozayn_secure_data_manager_t mgr;
    ozayn_secure_data_init(&mgr);
    ozayn_data_metadata_t meta;
    ozayn_data_metadata_init(&meta, "upd_001", OZAYN_DATA_CATEGORY_DOCUMENTS, "user1");
    ozayn_secure_data_create(&mgr, &meta);

    ozayn_data_metadata_t new_meta;
    ozayn_data_metadata_init(&new_meta, "upd_001", OZAYN_DATA_CATEGORY_CONVERSATION_HISTORY, "user2");
    ASSERT_EQ(ozayn_secure_data_update(&mgr, "upd_001", &new_meta), OZAYN_SD_OK);
    ASSERT_EQ(mgr.objects[0].category, OZAYN_DATA_CATEGORY_CONVERSATION_HISTORY);
    return 0;
}

TEST(update_not_found) {
    ozayn_secure_data_manager_t mgr;
    ozayn_secure_data_init(&mgr);
    ozayn_data_metadata_t meta;
    ozayn_data_metadata_init(&meta, "x", OZAYN_DATA_CATEGORY_DOCUMENTS, "u");
    ASSERT_EQ(ozayn_secure_data_update(&mgr, "nope", &meta), OZAYN_SD_ERR_NOT_FOUND);
    return 0;
}

TEST(delete_existing_object) {
    ozayn_secure_data_manager_t mgr;
    ozayn_secure_data_init(&mgr);
    ozayn_data_metadata_t meta;
    ozayn_data_metadata_init(&meta, "del_001", OZAYN_DATA_CATEGORY_SECURITY_EVENTS, "user1");
    ozayn_secure_data_create(&mgr, &meta);

    ASSERT_EQ(ozayn_secure_data_delete(&mgr, "del_001"), OZAYN_SD_OK);
    ASSERT_EQ(mgr.objects[0].storage_state, OZAYN_DATA_STORAGE_DELETED);
    return 0;
}

TEST(delete_not_found) {
    ozayn_secure_data_manager_t mgr;
    ozayn_secure_data_init(&mgr);
    ASSERT_EQ(ozayn_secure_data_delete(&mgr, "ghost"), OZAYN_SD_ERR_NOT_FOUND);
    return 0;
}

TEST(exists_true) {
    ozayn_secure_data_manager_t mgr;
    ozayn_secure_data_init(&mgr);
    ozayn_data_metadata_t meta;
    ozayn_data_metadata_init(&meta, "ex_001", OZAYN_DATA_CATEGORY_DOCUMENTS, "u");
    ozayn_secure_data_create(&mgr, &meta);
    ASSERT_EQ(ozayn_secure_data_exists(&mgr, "ex_001"), 1);
    return 0;
}

TEST(exists_false) {
    ozayn_secure_data_manager_t mgr;
    ozayn_secure_data_init(&mgr);
    ASSERT_EQ(ozayn_secure_data_exists(&mgr, "nope"), 0);
    return 0;
}

/* ============================================================
 * LIST TESTS
 * ============================================================ */

TEST(list_filters_by_category) {
    ozayn_secure_data_manager_t mgr;
    ozayn_secure_data_init(&mgr);
    ozayn_data_metadata_t m1, m2, m3;
    ozayn_data_metadata_init(&m1, "a", OZAYN_DATA_CATEGORY_DOCUMENTS, "u");
    ozayn_data_metadata_init(&m2, "b", OZAYN_DATA_CATEGORY_AI_MEMORY, "u");
    ozayn_data_metadata_init(&m3, "c", OZAYN_DATA_CATEGORY_DOCUMENTS, "u");
    ozayn_secure_data_create(&mgr, &m1);
    ozayn_secure_data_create(&mgr, &m2);
    ozayn_secure_data_create(&mgr, &m3);

    ozayn_data_metadata_t out[10];
    int count = ozayn_secure_data_list(&mgr, OZAYN_DATA_CATEGORY_DOCUMENTS, out, 10);
    ASSERT_EQ(count, 2);
    return 0;
}

TEST(list_excludes_deleted) {
    ozayn_secure_data_manager_t mgr;
    ozayn_secure_data_init(&mgr);
    ozayn_data_metadata_t m1;
    ozayn_data_metadata_init(&m1, "del_a", OZAYN_DATA_CATEGORY_DOCUMENTS, "u");
    ozayn_secure_data_create(&mgr, &m1);
    ozayn_secure_data_delete(&mgr, "del_a");

    ozayn_data_metadata_t out[10];
    int count = ozayn_secure_data_list(&mgr, OZAYN_DATA_CATEGORY_DOCUMENTS, out, 10);
    ASSERT_EQ(count, 0);
    return 0;
}

TEST(list_empty_category) {
    ozayn_secure_data_manager_t mgr;
    ozayn_secure_data_init(&mgr);
    ozayn_data_metadata_t out[10];
    int count = ozayn_secure_data_list(&mgr, OZAYN_DATA_CATEGORY_ARWE_INFORMATION, out, 10);
    ASSERT_EQ(count, 0);
    return 0;
}

/* ============================================================
 * QUERY TESTS
 * ============================================================ */

TEST(object_count_after_operations) {
    ozayn_secure_data_manager_t mgr;
    ozayn_secure_data_init(&mgr);
    ozayn_data_metadata_t m1, m2;
    ozayn_data_metadata_init(&m1, "cnt_a", OZAYN_DATA_CATEGORY_DOCUMENTS, "u");
    ozayn_data_metadata_init(&m2, "cnt_b", OZAYN_DATA_CATEGORY_AI_MEMORY, "u");
    ozayn_secure_data_create(&mgr, &m1);
    ozayn_secure_data_create(&mgr, &m2);
    ASSERT_EQ(ozayn_secure_data_object_count(&mgr), 2);
    return 0;
}

TEST(category_count_works) {
    ozayn_secure_data_manager_t mgr;
    ozayn_secure_data_init(&mgr);
    ozayn_data_metadata_t m1, m2;
    ozayn_data_metadata_init(&m1, "cc_a", OZAYN_DATA_CATEGORY_DOCUMENTS, "u");
    ozayn_data_metadata_init(&m2, "cc_b", OZAYN_DATA_CATEGORY_DOCUMENTS, "u");
    ozayn_secure_data_create(&mgr, &m1);
    ozayn_secure_data_create(&mgr, &m2);
    ASSERT_EQ(ozayn_secure_data_category_count(&mgr, OZAYN_DATA_CATEGORY_DOCUMENTS), 2);
    ASSERT_EQ(ozayn_secure_data_category_count(&mgr, OZAYN_DATA_CATEGORY_AI_MEMORY), 0);
    return 0;
}

/* ============================================================
 * STATISTICS TESTS
 * ============================================================ */

TEST(stats_after_operations) {
    ozayn_secure_data_manager_t mgr;
    ozayn_secure_data_init(&mgr);
    ozayn_data_metadata_t m;
    ozayn_data_metadata_init(&m, "st_001", OZAYN_DATA_CATEGORY_DOCUMENTS, "u");
    ozayn_secure_data_create(&mgr, &m);

    ozayn_data_metadata_t out;
    ozayn_secure_data_read(&mgr, "st_001", &out);
    ozayn_secure_data_delete(&mgr, "st_001");

    ozayn_secure_data_stats_t stats = ozayn_secure_data_stats(&mgr);
    ASSERT_EQ(stats.total_creates, 1);
    ASSERT_EQ(stats.total_reads, 1);
    ASSERT_EQ(stats.total_deletes, 1);
    return 0;
}

TEST(stats_not_initialized) {
    ozayn_secure_data_manager_t mgr;
    memset(&mgr, 0, sizeof(mgr));
    ozayn_secure_data_stats_t stats = ozayn_secure_data_stats(&mgr);
    ASSERT_EQ(stats.total_objects, 0);
    return 0;
}

/* ============================================================
 * ERROR MODEL TESTS
 * ============================================================ */

TEST(error_result_names_are_strings) {
    /* Verify all error codes have valid name strings */
    ozayn_secure_data_result_t codes[] = {
        OZAYN_SD_OK, OZAYN_SD_ERR_NOT_FOUND, OZAYN_SD_ERR_ACCESS_DENIED,
        OZAYN_SD_ERR_INVALID_DATA, OZAYN_SD_ERR_STORAGE_FAILURE,
        OZAYN_SD_ERR_INTEGRITY, OZAYN_SD_ERR_SECURITY,
        OZAYN_SD_ERR_INVALID_REQUEST, OZAYN_SD_ERR_NULL,
        OZAYN_SD_ERR_STATE, OZAYN_SD_ERR_NOT_INITIALIZED
    };
    for (int i = 0; i < 11; i++) {
        const char *name = ozayn_secure_data_result_name(codes[i]);
        ASSERT_NOT_NULL(name);
        ASSERT(name[0] != '\0');
    }
    return 0;
}

TEST(operation_names_are_strings) {
    ozayn_sd_operation_t ops[] = {
        OZAYN_SD_OP_CREATE, OZAYN_SD_OP_READ, OZAYN_SD_OP_UPDATE,
        OZAYN_SD_OP_DELETE, OZAYN_SD_OP_EXISTS, OZAYN_SD_OP_LIST
    };
    for (int i = 0; i < 6; i++) {
        const char *name = ozayn_sd_operation_name(ops[i]);
        ASSERT_NOT_NULL(name);
        ASSERT(name[0] != '\0');
    }
    return 0;
}

/* ============================================================
 * RUN
 * ============================================================ */

int run_data_classification_tests(void) {
    SUITE_BEGIN("Step 02: Data Classification & Storage Boundary");

    /* Classification (11 tests) */
    RUN(classification_user_preferences_has_default);
    RUN(classification_identity_information_has_default);
    RUN(classification_auth_info_has_default);
    RUN(classification_conversation_history_has_default);
    RUN(classification_ai_memory_has_default);
    RUN(classification_documents_has_default);
    RUN(classification_system_config_has_default);
    RUN(classification_security_events_has_default);
    RUN(classification_arwe_info_has_default);
    RUN(classification_invalid_category_returns_public);
    RUN(classification_category_count_is_nine);

    /* Name helpers (9 tests) */
    RUN(name_helpers_category_returns_string);
    RUN(name_helpers_level_returns_string);
    RUN(name_helpers_integrity_returns_string);
    RUN(name_helpers_storage_state_returns_string);
    RUN(name_helpers_result_returns_string);
    RUN(name_helpers_invalid_category_returns_unknown);
    RUN(name_helpers_invalid_level_returns_unknown);
    RUN(name_helpers_no_secrets_in_names);

    /* Metadata (8 tests) */
    RUN(metadata_init_valid);
    RUN(metadata_init_null_fails);
    RUN(metadata_init_empty_id_fails);
    RUN(metadata_validate_valid);
    RUN(metadata_validate_null_fails);
    RUN(metadata_is_sensitive_true_for_sensitive);
    RUN(metadata_is_sensitive_false_for_internal);
    RUN(metadata_is_sensitive_false_for_null);

    /* Boundary (5 tests) */
    RUN(boundary_init_success);
    RUN(boundary_init_null_fails);
    RUN(boundary_shutdown_clears);
    RUN(boundary_is_initialized_true);
    RUN(boundary_is_initialized_false);

    /* CRUD (14 tests) */
    RUN(create_valid_object);
    RUN(create_duplicate_fails);
    RUN(create_not_initialized_fails);
    RUN(create_null_fails);
    RUN(read_existing_object);
    RUN(read_not_found);
    RUN(read_not_initialized);
    RUN(read_null_fails);
    RUN(update_existing_object);
    RUN(update_not_found);
    RUN(delete_existing_object);
    RUN(delete_not_found);
    RUN(exists_true);
    RUN(exists_false);

    /* List (3 tests) */
    RUN(list_filters_by_category);
    RUN(list_excludes_deleted);
    RUN(list_empty_category);

    /* Query (2 tests) */
    RUN(object_count_after_operations);
    RUN(category_count_works);

    /* Statistics (2 tests) */
    RUN(stats_after_operations);
    RUN(stats_not_initialized);

    /* Error model (2 tests) */
    RUN(error_result_names_are_strings);
    RUN(operation_names_are_strings);

    SUITE_END();
    return TOTAL_FAIL();
}
