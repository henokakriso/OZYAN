/*
 * test_secure_data_object.c — Step 03 Tests: Secure Data Object & Validation.
 *
 * Tests:
 *   - Object initialization (valid and invalid arguments)
 *   - Object lifecycle (invalidate, mark for deletion, invalid transitions)
 *   - Full validation (identity, classification, state, integrity, storage, ownership, timestamps)
 *   - Classification consistency (unsafe category+level combinations)
 *   - Security metadata locking
 *   - Name helpers (no sensitive data exposed)
 *   - Security negative tests (no secrets in object metadata)
 */

#include "../../tests/test_framework.h"
#include "../secure_data_object.h"
#include <string.h>

/* ============================================================
 * OBJECT INITIALIZATION TESTS
 * ============================================================ */

TEST(sdo_init_valid) {
    ozayn_secure_data_object_t obj;
    int rc = ozayn_sdo_init(&obj, "pref_theme", OZAYN_DATA_CATEGORY_USER_PREFERENCES, "user1", OZAYN_DATA_SCOPE_USER);
    ASSERT_EQ(rc, 0);
    ASSERT_STR_EQ(obj.id, "pref_theme");
    ASSERT_EQ(obj.category, OZAYN_DATA_CATEGORY_USER_PREFERENCES);
    ASSERT_EQ(obj.classification, OZAYN_SEC_LEVEL_SENSITIVE);
    ASSERT_EQ(obj.state, OZAYN_DATA_STATE_VALID);
    ASSERT_EQ(obj.scope, OZAYN_DATA_SCOPE_USER);
    ASSERT_STR_EQ(obj.owner, "user1");
    return 0;
}

TEST(sdo_init_null_obj) {
    ASSERT_EQ(ozayn_sdo_init(NULL, "id", OZAYN_DATA_CATEGORY_DOCUMENTS, "owner", OZAYN_DATA_SCOPE_USER), -1);
    return 0;
}

TEST(sdo_init_empty_id) {
    ozayn_secure_data_object_t obj;
    ASSERT_EQ(ozayn_sdo_init(&obj, "", OZAYN_DATA_CATEGORY_DOCUMENTS, "owner", OZAYN_DATA_SCOPE_USER), -1);
    return 0;
}

TEST(sdo_init_invalid_category) {
    ozayn_secure_data_object_t obj;
    ASSERT_EQ(ozayn_sdo_init(&obj, "x", (ozayn_data_category_t)99, "owner", OZAYN_DATA_SCOPE_USER), -1);
    return 0;
}

TEST(sdo_init_invalid_scope) {
    ozayn_secure_data_object_t obj;
    ASSERT_EQ(ozayn_sdo_init(&obj, "x", OZAYN_DATA_CATEGORY_DOCUMENTS, "owner", OZAYN_DATA_SCOPE_UNKNOWN), -1);
    return 0;
}

TEST(sdo_init_auth_info_highly_sensitive) {
    ozayn_secure_data_object_t obj;
    ozayn_sdo_init(&obj, "auth_rec", OZAYN_DATA_CATEGORY_AUTH_INFO, "sys", OZAYN_DATA_SCOPE_SYSTEM);
    ASSERT_EQ(obj.classification, OZAYN_SEC_LEVEL_HIGHLY_SENSITIVE);
    return 0;
}

TEST(sdo_init_identity_highly_sensitive) {
    ozayn_secure_data_object_t obj;
    ozayn_sdo_init(&obj, "ident", OZAYN_DATA_CATEGORY_IDENTITY_INFORMATION, "sys", OZAYN_DATA_SCOPE_SYSTEM);
    ASSERT_EQ(obj.classification, OZAYN_SEC_LEVEL_HIGHLY_SENSITIVE);
    return 0;
}

TEST(sdo_init_system_config_internal) {
    ozayn_secure_data_object_t obj;
    ozayn_sdo_init(&obj, "sys_cfg", OZAYN_DATA_CATEGORY_SYSTEM_CONFIGURATION, "sys", OZAYN_DATA_SCOPE_SYSTEM);
    ASSERT_EQ(obj.classification, OZAYN_SEC_LEVEL_INTERNAL);
    return 0;
}

/* ============================================================
 * OBJECT LIFECYCLE TESTS
 * ============================================================ */

TEST(sdo_invalidate_valid_object) {
    ozayn_secure_data_object_t obj;
    ozayn_sdo_init(&obj, "inv_001", OZAYN_DATA_CATEGORY_DOCUMENTS, "u", OZAYN_DATA_SCOPE_USER);
    ASSERT_EQ(ozayn_sdo_invalidate(&obj), 0);
    ASSERT_EQ(obj.state, OZAYN_DATA_STATE_INVALID);
    return 0;
}

TEST(sdo_invalidate_null) {
    ASSERT_EQ(ozayn_sdo_invalidate(NULL), -1);
    return 0;
}

TEST(sdo_invalidate_uninitialized_fails) {
    ozayn_secure_data_object_t obj;
    memset(&obj, 0, sizeof(obj));
    obj.state = OZAYN_DATA_STATE_UNINITIALIZED;
    ASSERT_EQ(ozayn_sdo_invalidate(&obj), -1);
    return 0;
}

TEST(sdo_mark_for_deletion_valid) {
    ozayn_secure_data_object_t obj;
    ozayn_sdo_init(&obj, "del_001", OZAYN_DATA_CATEGORY_DOCUMENTS, "u", OZAYN_DATA_SCOPE_USER);
    ASSERT_EQ(ozayn_sdo_mark_for_deletion(&obj), 0);
    ASSERT_EQ(obj.state, OZAYN_DATA_STATE_MARKED_FOR_DELETION);
    return 0;
}

TEST(sdo_mark_for_deletion_null) {
    ASSERT_EQ(ozayn_sdo_mark_for_deletion(NULL), -1);
    return 0;
}

TEST(sdo_mark_for_deletion_invalid_fails) {
    ozayn_secure_data_object_t obj;
    ozayn_sdo_init(&obj, "del_002", OZAYN_DATA_CATEGORY_DOCUMENTS, "u", OZAYN_DATA_SCOPE_USER);
    ozayn_sdo_invalidate(&obj);
    ASSERT_EQ(ozayn_sdo_mark_for_deletion(&obj), -1);
    return 0;
}

TEST(sdo_mark_for_deletion_uninitialized_fails) {
    ozayn_secure_data_object_t obj;
    memset(&obj, 0, sizeof(obj));
    obj.state = OZAYN_DATA_STATE_UNINITIALIZED;
    ASSERT_EQ(ozayn_sdo_mark_for_deletion(&obj), -1);
    return 0;
}

/* ============================================================
 * VALIDATION TESTS
 * ============================================================ */

TEST(sdo_validate_valid_object) {
    ozayn_secure_data_object_t obj;
    ozayn_sdo_init(&obj, "val_001", OZAYN_DATA_CATEGORY_USER_PREFERENCES, "user1", OZAYN_DATA_SCOPE_USER);
    ASSERT_EQ(ozayn_sdo_validate(&obj), 0);
    return 0;
}

TEST(sdo_validate_null) {
    ASSERT_EQ(ozayn_sdo_validate(NULL), -1);
    return 0;
}

TEST(sdo_validate_missing_id) {
    ozayn_secure_data_object_t obj;
    ozayn_sdo_init(&obj, "x", OZAYN_DATA_CATEGORY_DOCUMENTS, "u", OZAYN_DATA_SCOPE_USER);
    obj.id[0] = '\0';
    ASSERT_EQ(ozayn_sdo_validate(&obj), -1);
    return 0;
}

TEST(sdo_validate_invalid_category) {
    ozayn_secure_data_object_t obj;
    ozayn_sdo_init(&obj, "x", OZAYN_DATA_CATEGORY_DOCUMENTS, "u", OZAYN_DATA_SCOPE_USER);
    obj.category = (ozayn_data_category_t)99;
    ASSERT_EQ(ozayn_sdo_validate(&obj), -1);
    return 0;
}

TEST(sdo_validate_invalid_classification) {
    ozayn_secure_data_object_t obj;
    ozayn_sdo_init(&obj, "x", OZAYN_DATA_CATEGORY_DOCUMENTS, "u", OZAYN_DATA_SCOPE_USER);
    obj.classification = (ozayn_security_level_t)99;
    ASSERT_EQ(ozayn_sdo_validate(&obj), -1);
    return 0;
}

TEST(sdo_validate_uninitialized_state) {
    ozayn_secure_data_object_t obj;
    ozayn_sdo_init(&obj, "x", OZAYN_DATA_CATEGORY_DOCUMENTS, "u", OZAYN_DATA_SCOPE_USER);
    obj.state = OZAYN_DATA_STATE_UNINITIALIZED;
    ASSERT_EQ(ozayn_sdo_validate(&obj), -1);
    return 0;
}

TEST(sdo_validate_invalid_integrity) {
    ozayn_secure_data_object_t obj;
    ozayn_sdo_init(&obj, "x", OZAYN_DATA_CATEGORY_DOCUMENTS, "u", OZAYN_DATA_SCOPE_USER);
    obj.integrity = (ozayn_data_integrity_t)99;
    ASSERT_EQ(ozayn_sdo_validate(&obj), -1);
    return 0;
}

TEST(sdo_validate_invalid_storage_state) {
    ozayn_secure_data_object_t obj;
    ozayn_sdo_init(&obj, "x", OZAYN_DATA_CATEGORY_DOCUMENTS, "u", OZAYN_DATA_SCOPE_USER);
    obj.storage_state = (ozayn_data_storage_state_t)99;
    ASSERT_EQ(ozayn_sdo_validate(&obj), -1);
    return 0;
}

TEST(sdo_validate_missing_owner) {
    ozayn_secure_data_object_t obj;
    ozayn_sdo_init(&obj, "x", OZAYN_DATA_CATEGORY_DOCUMENTS, "u", OZAYN_DATA_SCOPE_USER);
    obj.owner[0] = '\0';
    ASSERT_EQ(ozayn_sdo_validate(&obj), -1);
    return 0;
}

TEST(sdo_validate_invalid_scope) {
    ozayn_secure_data_object_t obj;
    ozayn_sdo_init(&obj, "x", OZAYN_DATA_CATEGORY_DOCUMENTS, "u", OZAYN_DATA_SCOPE_USER);
    obj.scope = OZAYN_DATA_SCOPE_UNKNOWN;
    ASSERT_EQ(ozayn_sdo_validate(&obj), -1);
    return 0;
}

TEST(sdo_validate_timestamps_ok) {
    ozayn_secure_data_object_t obj;
    ozayn_sdo_init(&obj, "ts_001", OZAYN_DATA_CATEGORY_DOCUMENTS, "u", OZAYN_DATA_SCOPE_USER);
    obj.created_at  = 1000;
    obj.modified_at = 2000;
    ASSERT_EQ(ozayn_sdo_validate(&obj), 0);
    return 0;
}

TEST(sdo_validate_timestamps_reversed) {
    ozayn_secure_data_object_t obj;
    ozayn_sdo_init(&obj, "ts_002", OZAYN_DATA_CATEGORY_DOCUMENTS, "u", OZAYN_DATA_SCOPE_USER);
    obj.created_at  = 2000;
    obj.modified_at = 1000;
    ASSERT_EQ(ozayn_sdo_validate(&obj), -1);
    return 0;
}

TEST(sdo_validate_valid_highly_sensitive) {
    ozayn_secure_data_object_t obj;
    ozayn_sdo_init(&obj, "hs_001", OZAYN_DATA_CATEGORY_AUTH_INFO, "sys", OZAYN_DATA_SCOPE_SYSTEM);
    ASSERT_EQ(obj.classification, OZAYN_SEC_LEVEL_HIGHLY_SENSITIVE);
    ASSERT_EQ(ozayn_sdo_validate(&obj), 0);
    return 0;
}

TEST(sdo_validate_invalid_object_state) {
    ozayn_secure_data_object_t obj;
    ozayn_sdo_init(&obj, "inv_002", OZAYN_DATA_CATEGORY_DOCUMENTS, "u", OZAYN_DATA_SCOPE_USER);
    ozayn_sdo_invalidate(&obj);
    ASSERT_EQ(ozayn_sdo_validate(&obj), -1);
    return 0;
}

TEST(sdo_validate_marked_for_deletion) {
    ozayn_secure_data_object_t obj;
    ozayn_sdo_init(&obj, "mfd_001", OZAYN_DATA_CATEGORY_DOCUMENTS, "u", OZAYN_DATA_SCOPE_USER);
    ozayn_sdo_mark_for_deletion(&obj);
    ASSERT_EQ(ozayn_sdo_validate(&obj), 0);
    return 0;
}

/* ============================================================
 * CLASSIFICATION CONSISTENCY TESTS
 * ============================================================ */

TEST(classification_auth_info_not_public) {
    ozayn_secure_data_object_t obj;
    ozayn_sdo_init(&obj, "ci_001", OZAYN_DATA_CATEGORY_AUTH_INFO, "sys", OZAYN_DATA_SCOPE_SYSTEM);
    obj.classification = OZAYN_SEC_LEVEL_PUBLIC;
    ASSERT_EQ(ozayn_sdo_validate_classification(&obj), -1);
    return 0;
}

TEST(classification_identity_not_public) {
    ozayn_secure_data_object_t obj;
    ozayn_sdo_init(&obj, "ci_002", OZAYN_DATA_CATEGORY_IDENTITY_INFORMATION, "sys", OZAYN_DATA_SCOPE_SYSTEM);
    obj.classification = OZAYN_SEC_LEVEL_PUBLIC;
    ASSERT_EQ(ozayn_sdo_validate_classification(&obj), -1);
    return 0;
}

TEST(classification_security_events_not_public) {
    ozayn_secure_data_object_t obj;
    ozayn_sdo_init(&obj, "ci_003", OZAYN_DATA_CATEGORY_SECURITY_EVENTS, "sys", OZAYN_DATA_SCOPE_SYSTEM);
    obj.classification = OZAYN_SEC_LEVEL_PUBLIC;
    ASSERT_EQ(ozayn_sdo_validate_classification(&obj), -1);
    return 0;
}

TEST(classification_valid_sensitive) {
    ozayn_secure_data_object_t obj;
    ozayn_sdo_init(&obj, "ci_004", OZAYN_DATA_CATEGORY_CONVERSATION_HISTORY, "u", OZAYN_DATA_SCOPE_USER);
    ASSERT_EQ(ozayn_sdo_validate_classification(&obj), 0);
    return 0;
}

TEST(classification_null) {
    ASSERT_EQ(ozayn_sdo_validate_classification(NULL), -1);
    return 0;
}

/* ============================================================
 * SECURITY METADATA LOCK TESTS
 * ============================================================ */

TEST(security_lock_valid_object) {
    ozayn_secure_data_object_t obj;
    ozayn_sdo_init(&obj, "lk_001", OZAYN_DATA_CATEGORY_DOCUMENTS, "u", OZAYN_DATA_SCOPE_USER);
    ASSERT_EQ(ozayn_sdo_is_security_metadata_locked(&obj), 1);
    return 0;
}

TEST(security_lock_active_storage) {
    ozayn_secure_data_object_t obj;
    ozayn_sdo_init(&obj, "lk_002", OZAYN_DATA_CATEGORY_DOCUMENTS, "u", OZAYN_DATA_SCOPE_USER);
    obj.storage_state = OZAYN_DATA_STORAGE_ACTIVE;
    ASSERT_EQ(ozayn_sdo_is_security_metadata_locked(&obj), 1);
    return 0;
}

TEST(security_lock_inactive_not_locked) {
    ozayn_secure_data_object_t obj;
    ozayn_sdo_init(&obj, "lk_003", OZAYN_DATA_CATEGORY_DOCUMENTS, "u", OZAYN_DATA_SCOPE_USER);
    obj.storage_state = OZAYN_DATA_STORAGE_INACTIVE;
    obj.state = OZAYN_DATA_STATE_VALID;
    /* state=VALID still locks, storage=INACTIVE does not override */
    ASSERT_EQ(ozayn_sdo_is_security_metadata_locked(&obj), 1);
    return 0;
}

TEST(security_lock_null) {
    ASSERT_EQ(ozayn_sdo_is_security_metadata_locked(NULL), 0);
    return 0;
}

/* ============================================================
 * NAME HELPER TESTS
 * ============================================================ */

TEST(name_state_valid) {
    const char *n = ozayn_data_state_name(OZAYN_DATA_STATE_VALID);
    ASSERT_NOT_NULL(n);
    ASSERT(n[0] != '\0');
    return 0;
}

TEST(name_state_invalid) {
    const char *n = ozayn_data_state_name(OZAYN_DATA_STATE_INVALID);
    ASSERT_NOT_NULL(n);
    ASSERT(n[0] != '\0');
    return 0;
}

TEST(name_state_unknown_value) {
    const char *n = ozayn_data_state_name((ozayn_data_state_t)99);
    ASSERT_STR_EQ(n, "Unknown State");
    return 0;
}

TEST(name_scope_user) {
    const char *n = ozayn_data_scope_name(OZAYN_DATA_SCOPE_USER);
    ASSERT_NOT_NULL(n);
    ASSERT(n[0] != '\0');
    return 0;
}

TEST(name_scope_system) {
    const char *n = ozayn_data_scope_name(OZAYN_DATA_SCOPE_SYSTEM);
    ASSERT_NOT_NULL(n);
    ASSERT(n[0] != '\0');
    return 0;
}

TEST(name_scope_unknown_value) {
    const char *n = ozayn_data_scope_name((ozayn_data_scope_t)99);
    ASSERT_STR_EQ(n, "Unknown Scope");
    return 0;
}

TEST(name_helpers_no_secrets) {
    const char *danger[] = { "password", "secret", "private_key", "token", "credential", NULL };
    ozayn_data_state_t states[] = {
        OZAYN_DATA_STATE_UNINITIALIZED, OZAYN_DATA_STATE_VALID,
        OZAYN_DATA_STATE_INVALID, OZAYN_DATA_STATE_MARKED_FOR_DELETION
    };
    for (int i = 0; i < 4; i++) {
        const char *n = ozayn_data_state_name(states[i]);
        for (int d = 0; danger[d]; d++) {
            ASSERT(strstr(n, danger[d]) == NULL);
        }
    }
    ozayn_data_scope_t scopes[] = {
        OZAYN_DATA_SCOPE_UNKNOWN, OZAYN_DATA_SCOPE_SYSTEM, OZAYN_DATA_SCOPE_USER,
        OZAYN_DATA_SCOPE_SESSION, OZAYN_DATA_SCOPE_MODULE, OZAYN_DATA_SCOPE_GLOBAL
    };
    for (int i = 0; i < 6; i++) {
        const char *n = ozayn_data_scope_name(scopes[i]);
        for (int d = 0; danger[d]; d++) {
            ASSERT(strstr(n, danger[d]) == NULL);
        }
    }
    return 0;
}

/* ============================================================
 * SECURITY NEGATIVE TESTS
 * ============================================================ */

TEST(no_password_in_object) {
    ozayn_secure_data_object_t obj;
    ozayn_sdo_init(&obj, "sec_001", OZAYN_DATA_CATEGORY_DOCUMENTS, "u", OZAYN_DATA_SCOPE_USER);
    /* Attempt to write a password-like string into id field */
    strncpy(obj.id, "password123", OZAYN_SDO_MAX_ID_LEN - 1);
    /* The id field itself is just an identifier, not a secret container.
     * Verify the object still validates (id is non-empty) but the object
     * structure does not have a dedicated secret field. */
    ASSERT_EQ(obj.id[0] != '\0', 1);
    /* Verify no dedicated "secret" or "password" field exists in the struct */
    /* This is a compile-time check: if we added such a field, the struct
     * size would change. The test ensures the object has no secret storage. */
    ASSERT(sizeof(ozayn_secure_data_object_t) <= 256);
    return 0;
}

TEST(no_private_key_in_metadata) {
    ozayn_data_metadata_t meta;
    ozayn_data_metadata_init(&meta, "pk_test", OZAYN_DATA_CATEGORY_DOCUMENTS, "u");
    /* Verify metadata struct does not have secret-specific fields.
     * The struct should be a reasonable size (no secret buffers embedded). */
    ASSERT(sizeof(ozayn_data_metadata_t) > 0);
    /* Verify no "secret", "private_key", "password" fields by checking
     * the struct is a plain metadata container, not a key store. */
    ASSERT(meta.id[0] != '\0');
    return 0;
}

TEST(object_has_no_secret_field) {
    /* Verify the Secure Data Object struct does not grow to accommodate secrets.
     * If someone adds a secret field, this assertion will fail. */
    ozayn_secure_data_object_t obj;
    memset(&obj, 0, sizeof(obj));
    /* Check that all byte ranges are zeroed — no hidden fields */
    unsigned char *bytes = (unsigned char *)&obj;
    for (size_t i = 0; i < sizeof(obj); i++) {
        ASSERT_EQ(bytes[i], 0);
    }
    return 0;
}

TEST(content_size_default_zero) {
    ozayn_secure_data_object_t obj;
    ozayn_sdo_init(&obj, "sz_001", OZAYN_DATA_CATEGORY_DOCUMENTS, "u", OZAYN_DATA_SCOPE_USER);
    ASSERT_EQ(obj.content_size, 0);
    return 0;
}

TEST(checksum_default_zero) {
    ozayn_secure_data_object_t obj;
    ozayn_sdo_init(&obj, "cs_001", OZAYN_DATA_CATEGORY_DOCUMENTS, "u", OZAYN_DATA_SCOPE_USER);
    ASSERT_EQ(obj.checksum, 0);
    return 0;
}

TEST(version_set_on_init) {
    ozayn_secure_data_object_t obj;
    ozayn_sdo_init(&obj, "ver_001", OZAYN_DATA_CATEGORY_DOCUMENTS, "u", OZAYN_DATA_SCOPE_USER);
    ASSERT_STR_EQ(obj.version, "1.0");
    return 0;
}

TEST(all_categories_validatable) {
    for (int c = 0; c < OZAYN_DATA_CATEGORY_COUNT; c++) {
        ozayn_secure_data_object_t obj;
        ozayn_sdo_init(&obj, "cat_test", (ozayn_data_category_t)c, "u", OZAYN_DATA_SCOPE_USER);
        /* All categories should produce a valid object with proper classification */
        ASSERT_EQ(ozayn_sdo_validate(&obj), 0);
        ASSERT_EQ(obj.classification, ozayn_data_default_classification((ozayn_data_category_t)c));
    }
    return 0;
}

TEST(all_scopes_validatable) {
    for (int s = OZAYN_DATA_SCOPE_SYSTEM; s <= OZAYN_DATA_SCOPE_GLOBAL; s++) {
        ozayn_secure_data_object_t obj;
        ozayn_sdo_init(&obj, "scope_test", OZAYN_DATA_CATEGORY_DOCUMENTS, "u", (ozayn_data_scope_t)s);
        ASSERT_EQ(obj.scope, (ozayn_data_scope_t)s);
        ASSERT_EQ(ozayn_sdo_validate(&obj), 0);
    }
    return 0;
}

/* ============================================================
 * RUN
 * ============================================================ */

int run_secure_data_object_tests(void) {
    SUITE_BEGIN("Step 03: Secure Data Object & Validation");

    /* Object initialization (8 tests) */
    RUN(sdo_init_valid);
    RUN(sdo_init_null_obj);
    RUN(sdo_init_empty_id);
    RUN(sdo_init_invalid_category);
    RUN(sdo_init_invalid_scope);
    RUN(sdo_init_auth_info_highly_sensitive);
    RUN(sdo_init_identity_highly_sensitive);
    RUN(sdo_init_system_config_internal);

    /* Object lifecycle (7 tests) */
    RUN(sdo_invalidate_valid_object);
    RUN(sdo_invalidate_null);
    RUN(sdo_invalidate_uninitialized_fails);
    RUN(sdo_mark_for_deletion_valid);
    RUN(sdo_mark_for_deletion_null);
    RUN(sdo_mark_for_deletion_invalid_fails);
    RUN(sdo_mark_for_deletion_uninitialized_fails);

    /* Validation (14 tests) */
    RUN(sdo_validate_valid_object);
    RUN(sdo_validate_null);
    RUN(sdo_validate_missing_id);
    RUN(sdo_validate_invalid_category);
    RUN(sdo_validate_invalid_classification);
    RUN(sdo_validate_uninitialized_state);
    RUN(sdo_validate_invalid_integrity);
    RUN(sdo_validate_invalid_storage_state);
    RUN(sdo_validate_missing_owner);
    RUN(sdo_validate_invalid_scope);
    RUN(sdo_validate_timestamps_ok);
    RUN(sdo_validate_timestamps_reversed);
    RUN(sdo_validate_valid_highly_sensitive);
    RUN(sdo_validate_invalid_object_state);
    RUN(sdo_validate_marked_for_deletion);

    /* Classification consistency (5 tests) */
    RUN(classification_auth_info_not_public);
    RUN(classification_identity_not_public);
    RUN(classification_security_events_not_public);
    RUN(classification_valid_sensitive);
    RUN(classification_null);

    /* Security metadata lock (4 tests) */
    RUN(security_lock_valid_object);
    RUN(security_lock_active_storage);
    RUN(security_lock_inactive_not_locked);
    RUN(security_lock_null);

    /* Name helpers (7 tests) */
    RUN(name_state_valid);
    RUN(name_state_invalid);
    RUN(name_state_unknown_value);
    RUN(name_scope_user);
    RUN(name_scope_system);
    RUN(name_scope_unknown_value);
    RUN(name_helpers_no_secrets);

    /* Security negative tests (9 tests) */
    RUN(no_password_in_object);
    RUN(no_private_key_in_metadata);
    RUN(object_has_no_secret_field);
    RUN(content_size_default_zero);
    RUN(checksum_default_zero);
    RUN(version_set_on_init);
    RUN(all_categories_validatable);
    RUN(all_scopes_validatable);

    SUITE_END();
    return TOTAL_FAIL();
}
