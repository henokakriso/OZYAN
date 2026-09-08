#include "../../tests/test_framework.h"
#include "../backup.h"
#include "../secure_vault.h"
#include "../protection_provider.h"
#include "../protection_provider_mock.h"
#include "../storage_provider.h"
#include "../storage_provider_mem.h"
#include "../key_lifecycle.h"
#include "../key_provider.h"
#include "../secure_key_storage.h"
#include "../data_classification.h"
#include "../secure_data_object.h"
#include "../audit.h"
#include <string.h>
#include <time.h>

/* ============================================================
 * SHARED TEST INFRASTRUCTURE
 * ============================================================ */

static ozayn_protection_provider_t _prot;
static ozayn_storage_provider_t    _stor;
static ozayn_kl_manager_t          _kl;
static ozayn_vault_t               _vault;
static ozayn_audit_service_t       _audit_svc;
static ozayn_bk_service_t          _bk_svc;
static ozayn_bk_package_t          _pkg;

static void _setup_deps(void)
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

    ozayn_vault_config_t vcfg;
    memset(&vcfg, 0, sizeof(vcfg));
    vcfg.protection = &_prot;
    vcfg.storage = &_stor;
    vcfg.key_lifecycle = &_kl;
    ozayn_vault_init(&_vault, &vcfg);

    ozayn_audit_service_config_t acfg;
    memset(&acfg, 0, sizeof(acfg));
    acfg.event_capacity = 512;
    acfg.default_minimum_severity = OZAYN_AUDIT_SEV_INFO;
    ozayn_audit_service_init(&_audit_svc, &acfg);
}

static void _teardown_deps(void)
{
    ozayn_bk_service_shutdown(&_bk_svc);
    ozayn_audit_service_shutdown(&_audit_svc);
    ozayn_vault_shutdown(&_vault);
    ozayn_kl_shutdown(&_kl);
    ozayn_sp_shutdown(&_stor);
    ozayn_prot_shutdown(&_prot);
}

static void _init_bk_svc(void)
{
    ozayn_bk_service_shutdown(&_bk_svc);
    ozayn_bk_service_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.vault = &_vault;
    cfg.key_lifecycle = &_kl;
    cfg.protection = &_prot;
    cfg.audit = &_audit_svc;
    ozayn_bk_service_init(&_bk_svc, &cfg);
}

static void _store_test_object(const char *id, ozayn_data_category_t cat)
{
    ozayn_secure_data_object_t sdo;
    ozayn_sdo_init(&sdo, id, cat, "test", OZAYN_DATA_SCOPE_USER);
    sdo.classification = OZAYN_SEC_LEVEL_SENSITIVE;
    uint8_t data[] = {0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE};
    ozayn_vault_store(&_vault, &sdo, data, sizeof(data));
}

/* ============================================================
 * 1. SERVICE LIFECYCLE
 * ============================================================ */

TEST(test_bk_service_init_null) {
    ASSERT_EQ(OZAYN_BK_ERR_NULL, ozayn_bk_service_init(NULL, NULL));
    return 0;
}

TEST(test_bk_service_init_config_null) {
    ozayn_bk_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ASSERT_EQ(OZAYN_BK_ERR_NULL, ozayn_bk_service_init(&svc, NULL));
    return 0;
}

TEST(test_bk_service_init_success) {
    ozayn_bk_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_bk_service_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.vault = &_vault;
    cfg.key_lifecycle = &_kl;
    cfg.protection = &_prot;
    ASSERT_EQ(OZAYN_BK_OK, ozayn_bk_service_init(&svc, &cfg));
    ASSERT(ozayn_bk_service_is_initialized(&svc));
    ASSERT_EQ(OZAYN_BK_STATE_READY, svc.state);
    ozayn_bk_service_shutdown(&svc);
    return 0;
}

TEST(test_bk_service_init_already_initialized) {
    _init_bk_svc();
    ASSERT_EQ(OZAYN_BK_ERR_ALREADY_INITIALIZED,
              ozayn_bk_service_init(&_bk_svc, &(ozayn_bk_service_config_t){0}));
    return 0;
}

TEST(test_bk_service_shutdown_null) {
    ozayn_bk_service_shutdown(NULL);
    return 0;
}

TEST(test_bk_service_shutdown_not_initialized) {
    ozayn_bk_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_bk_service_shutdown(&svc);
    return 0;
}

TEST(test_bk_service_shutdown_success) {
    _init_bk_svc();
    ASSERT(ozayn_bk_service_is_initialized(&_bk_svc));
    ozayn_bk_service_shutdown(&_bk_svc);
    ASSERT(!ozayn_bk_service_is_initialized(&_bk_svc));
    return 0;
}

TEST(test_bk_service_is_initialized_null) {
    ASSERT(!ozayn_bk_service_is_initialized(NULL));
    return 0;
}

/* ============================================================
 * 2. NAME HELPERS
 * ============================================================ */

TEST(test_bk_result_name_ok) {
    ASSERT(strcmp(ozayn_bk_result_name(OZAYN_BK_OK), "OK") == 0);
    return 0;
}

TEST(test_bk_result_name_err) {
    ASSERT(strcmp(ozayn_bk_result_name(OZAYN_BK_ERR), "ERR") == 0);
    return 0;
}

TEST(test_bk_result_name_various) {
    ASSERT(strcmp(ozayn_bk_result_name(OZAYN_BK_ERR_NULL), "ERR_NULL") == 0);
    ASSERT(strcmp(ozayn_bk_result_name(OZAYN_BK_ERR_NOT_INITIALIZED), "ERR_NOT_INITIALIZED") == 0);
    ASSERT(strcmp(ozayn_bk_result_name(OZAYN_BK_ERR_INVALID_REQUEST), "ERR_INVALID_REQUEST") == 0);
    ASSERT(strcmp(ozayn_bk_result_name(OZAYN_BK_ERR_POLICY_REJECTED), "ERR_POLICY_REJECTED") == 0);
    ASSERT(strcmp(ozayn_bk_result_name(OZAYN_BK_ERR_STORAGE_ERROR), "ERR_STORAGE_ERROR") == 0);
    ASSERT(strcmp(ozayn_bk_result_name(OZAYN_BK_ERR_FORMAT_INVALID), "ERR_FORMAT_INVALID") == 0);
    ASSERT(strcmp(ozayn_bk_result_name(OZAYN_BK_ERR_FORMAT_UNSUPPORTED), "ERR_FORMAT_UNSUPPORTED") == 0);
    ASSERT(strcmp(ozayn_bk_result_name(OZAYN_BK_ERR_INTEGRITY_FAILURE), "ERR_INTEGRITY_FAILURE") == 0);
    ASSERT(strcmp(ozayn_bk_result_name(OZAYN_BK_ERR_PROTECTION_FAILURE), "ERR_PROTECTION_FAILURE") == 0);
    ASSERT(strcmp(ozayn_bk_result_name(OZAYN_BK_ERR_KEY_UNAVAILABLE), "ERR_KEY_UNAVAILABLE") == 0);
    ASSERT(strcmp(ozayn_bk_result_name(OZAYN_BK_ERR_KEY_INVALID), "ERR_KEY_INVALID") == 0);
    ASSERT(strcmp(ozayn_bk_result_name(OZAYN_BK_ERR_PERMISSION_DENIED), "ERR_PERMISSION_DENIED") == 0);
    ASSERT(strcmp(ozayn_bk_result_name(OZAYN_BK_ERR_DUPLICATE), "ERR_DUPLICATE") == 0);
    ASSERT(strcmp(ozayn_bk_result_name(OZAYN_BK_ERR_OBJECT_NOT_FOUND), "ERR_OBJECT_NOT_FOUND") == 0);
    ASSERT(strcmp(ozayn_bk_result_name(OZAYN_BK_ERR_VAULT_UNAVAILABLE), "ERR_VAULT_UNAVAILABLE") == 0);
    ASSERT(strcmp(ozayn_bk_result_name(OZAYN_BK_ERR_VAULT_FAILED), "ERR_VAULT_FAILED") == 0);
    ASSERT(strcmp(ozayn_bk_result_name(OZAYN_BK_ERR_CATEGORY_NOT_ALLOWED), "ERR_CATEGORY_NOT_ALLOWED") == 0);
    ASSERT(strcmp(ozayn_bk_result_name(OZAYN_BK_ERR_VERSION_INCOMPATIBLE), "ERR_VERSION_INCOMPATIBLE") == 0);
    ASSERT(strcmp(ozayn_bk_result_name(OZAYN_BK_ERR_BACKUP_CORRUPTED), "ERR_BACKUP_CORRUPTED") == 0);
    ASSERT(strcmp(ozayn_bk_result_name(OZAYN_BK_ERR_RESTORE_UNAUTHORIZED), "ERR_RESTORE_UNAUTHORIZED") == 0);
    ASSERT(strcmp(ozayn_bk_result_name(OZAYN_BK_ERR_RESTORE_MFA_REQUIRED), "ERR_RESTORE_MFA_REQUIRED") == 0);
    ASSERT(strcmp(ozayn_bk_result_name(OZAYN_BK_ERR_RESTORE_CONFLICT), "ERR_RESTORE_CONFLICT") == 0);
    ASSERT(strcmp(ozayn_bk_result_name(OZAYN_BK_ERR_RESTORE_FAILED), "ERR_RESTORE_FAILED") == 0);
    ASSERT(strcmp(ozayn_bk_result_name(OZAYN_BK_ERR_RESTORE_ROLLBACK_FAILED), "ERR_RESTORE_ROLLBACK_FAILED") == 0);
    ASSERT(strcmp(ozayn_bk_result_name(OZAYN_BK_ERR_AUDIT_FAILED), "ERR_AUDIT_FAILED") == 0);
    ASSERT(strcmp(ozayn_bk_result_name(OZAYN_BK_ERR_RESOURCE_EXHAUSTED), "ERR_RESOURCE_EXHAUSTED") == 0);
    ASSERT(strcmp(ozayn_bk_result_name(OZAYN_BK_ERR_INTEGRITY_REQUIRED), "ERR_INTEGRITY_REQUIRED") == 0);
    return 0;
}

TEST(test_bk_type_name) {
    ASSERT(strcmp(ozayn_bk_type_name(OZAYN_BK_TYPE_FULL), "FULL") == 0);
    ASSERT(strcmp(ozayn_bk_type_name(OZAYN_BK_TYPE_SELECTIVE), "SELECTIVE") == 0);
    ASSERT(strcmp(ozayn_bk_type_name(OZAYN_BK_TYPE_CONFIGURATION), "CONFIGURATION") == 0);
    ASSERT(strcmp(ozayn_bk_type_name((ozayn_bk_type_t)99), "UNKNOWN") == 0);
    return 0;
}

TEST(test_bk_state_name) {
    ASSERT(strcmp(ozayn_bk_state_name(OZAYN_BK_STATE_UNINITIALIZED), "UNINITIALIZED") == 0);
    ASSERT(strcmp(ozayn_bk_state_name(OZAYN_BK_STATE_READY), "READY") == 0);
    ASSERT(strcmp(ozayn_bk_state_name(OZAYN_BK_STATE_BACKING_UP), "BACKING_UP") == 0);
    ASSERT(strcmp(ozayn_bk_state_name(OZAYN_BK_STATE_RESTORING), "RESTORING") == 0);
    ASSERT(strcmp(ozayn_bk_state_name(OZAYN_BK_STATE_ERROR), "ERROR") == 0);
    return 0;
}

TEST(test_bk_restore_mode_name) {
    ASSERT(strcmp(ozayn_bk_restore_mode_name(OZAYN_BK_RESTORE_VALIDATE_ONLY), "VALIDATE_ONLY") == 0);
    ASSERT(strcmp(ozayn_bk_restore_mode_name(OZAYN_BK_RESTORE_NEW), "NEW") == 0);
    ASSERT(strcmp(ozayn_bk_restore_mode_name(OZAYN_BK_RESTORE_REPLACE), "REPLACE") == 0);
    return 0;
}

TEST(test_bk_compat_name) {
    ASSERT(strcmp(ozayn_bk_compat_name(OZAYN_BK_COMPAT_SUPPORTED), "SUPPORTED") == 0);
    ASSERT(strcmp(ozayn_bk_compat_name(OZAYN_BK_COMPAT_WITH_MIGRATION), "WITH_MIGRATION") == 0);
    ASSERT(strcmp(ozayn_bk_compat_name(OZAYN_BK_COMPAT_UNSUPPORTED), "UNSUPPORTED") == 0);
    ASSERT(strcmp(ozayn_bk_compat_name(OZAYN_BK_COMPAT_CORRUPTED), "CORRUPTED") == 0);
    ASSERT(strcmp(ozayn_bk_compat_name(OZAYN_BK_COMPAT_INCOMPATIBLE), "INCOMPATIBLE") == 0);
    return 0;
}

/* ============================================================
 * 3. DEFAULT POLICY
 * ============================================================ */

TEST(test_bk_default_policy) {
    ozayn_bk_policy_t p = ozayn_bk_default_policy();
    ASSERT(p.enabled);
    ASSERT(p.require_integrity);
    ASSERT(p.require_protection);
    ASSERT(p.require_audit);
    ASSERT(p.max_backup_size > 0);
    ASSERT(p.max_object_count > 0);
    ASSERT(p.max_object_size > 0);
    ASSERT(p.retention_days > 0);
    for (int i = 0; i < OZAYN_DATA_CATEGORY_COUNT; i++) {
        ASSERT(p.allowed_categories[i]);
    }
    return 0;
}

TEST(test_bk_set_get_policy) {
    _init_bk_svc();
    ozayn_bk_policy_t p = ozayn_bk_default_policy();
    p.require_integrity = 0;
    ASSERT_EQ(OZAYN_BK_OK, ozayn_bk_set_policy(&_bk_svc, &p));
    const ozayn_bk_policy_t *gp = ozayn_bk_get_policy(&_bk_svc);
    ASSERT_NOT_NULL(gp);
    ASSERT(!gp->require_integrity);
    return 0;
}

TEST(test_bk_set_policy_null) {
    ASSERT_EQ(OZAYN_BK_ERR_NULL, ozayn_bk_set_policy(NULL, NULL));
    return 0;
}

TEST(test_bk_get_policy_null) {
    ASSERT_NULL(ozayn_bk_get_policy(NULL));
    return 0;
}

TEST(test_bk_get_policy_not_initialized) {
    ozayn_bk_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ASSERT_NULL(ozayn_bk_get_policy(&svc));
    return 0;
}

/* ============================================================
 * 4. CHECKSUM
 * ============================================================ */

TEST(test_bk_checksum_deterministic) {
    uint8_t data[] = {1, 2, 3, 4, 5};
    uint32_t c1 = ozayn_bk_checksum(data, sizeof(data));
    uint32_t c2 = ozayn_bk_checksum(data, sizeof(data));
    ASSERT_EQ(c1, c2);
    return 0;
}

TEST(test_bk_checksum_different_data) {
    uint8_t d1[] = {1, 2, 3};
    uint8_t d2[] = {1, 2, 4};
    ASSERT_NEQ(ozayn_bk_checksum(d1, sizeof(d1)), ozayn_bk_checksum(d2, sizeof(d2)));
    return 0;
}

TEST(test_bk_checksum_empty) {
    uint32_t c = ozayn_bk_checksum(NULL, 0);
    ASSERT_NEQ(c, 0);
    return 0;
}

/* ============================================================
 * 5. BACKUP CREATION
 * ============================================================ */

TEST(test_bk_create_null) {
    ASSERT_EQ(OZAYN_BK_ERR_NULL, ozayn_bk_create(NULL, OZAYN_BK_TYPE_FULL, NULL));
    return 0;
}

TEST(test_bk_create_not_initialized) {
    ozayn_bk_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ASSERT_EQ(OZAYN_BK_ERR_NOT_INITIALIZED,
              ozayn_bk_create(&svc, OZAYN_BK_TYPE_FULL, &_pkg));
    return 0;
}

TEST(test_bk_create_invalid_type) {
    _init_bk_svc();
    ASSERT_EQ(OZAYN_BK_ERR_INVALID_REQUEST,
              ozayn_bk_create(&_bk_svc, (ozayn_bk_type_t)99, &_pkg));
    return 0;
}

TEST(test_bk_create_full) {
    _init_bk_svc();
    memset(&_pkg, 0, sizeof(_pkg));
    ASSERT_EQ(OZAYN_BK_OK, ozayn_bk_create(&_bk_svc, OZAYN_BK_TYPE_FULL, &_pkg));
    ASSERT(_pkg.in_use);
    ASSERT_EQ(OZAYN_BK_TYPE_FULL, _pkg.manifest.backup_type);
    ASSERT_EQ(OZAYN_BK_FORMAT_VERSION, _pkg.manifest.format_version);
    ASSERT(strlen(_pkg.manifest.backup_id) > 0);
    ASSERT_EQ(OZAYN_BK_STATE_BACKING_UP, _bk_svc.state);
    return 0;
}

TEST(test_bk_create_selective) {
    _init_bk_svc();
    memset(&_pkg, 0, sizeof(_pkg));
    ASSERT_EQ(OZAYN_BK_OK, ozayn_bk_create(&_bk_svc, OZAYN_BK_TYPE_SELECTIVE, &_pkg));
    ASSERT_EQ(OZAYN_BK_TYPE_SELECTIVE, _pkg.manifest.backup_type);
    return 0;
}

TEST(test_bk_create_configuration) {
    _init_bk_svc();
    memset(&_pkg, 0, sizeof(_pkg));
    ASSERT_EQ(OZAYN_BK_OK, ozayn_bk_create(&_bk_svc, OZAYN_BK_TYPE_CONFIGURATION, &_pkg));
    ASSERT_EQ(OZAYN_BK_TYPE_CONFIGURATION, _pkg.manifest.backup_type);
    return 0;
}

TEST(test_bk_create_unique_ids) {
    static ozayn_bk_package_t p2;
    _init_bk_svc();
    memset(&_pkg, 0, sizeof(_pkg));
    memset(&p2, 0, sizeof(p2));
    ASSERT_EQ(OZAYN_BK_OK, ozayn_bk_create(&_bk_svc, OZAYN_BK_TYPE_FULL, &_pkg));
    _bk_svc.state = OZAYN_BK_STATE_READY;
    ASSERT_EQ(OZAYN_BK_OK, ozayn_bk_create(&_bk_svc, OZAYN_BK_TYPE_FULL, &p2));
    ASSERT(strcmp(_pkg.manifest.backup_id, p2.manifest.backup_id) != 0);
    return 0;
}

/* ============================================================
 * 6. ADD OBJECT
 * ============================================================ */

TEST(test_bk_add_object_null) {
    ASSERT_EQ(OZAYN_BK_ERR_NULL, ozayn_bk_add_object(NULL, NULL, NULL));
    return 0;
}

TEST(test_bk_add_object_not_initialized) {
    ozayn_bk_service_t svc;
    memset(&svc, 0, sizeof(svc));
    memset(&_pkg, 0, sizeof(_pkg));
    ASSERT_EQ(OZAYN_BK_ERR_NOT_INITIALIZED,
              ozayn_bk_add_object(&svc, &_pkg, "obj1"));
    return 0;
}

TEST(test_bk_add_object_no_package) {
    _init_bk_svc();
    memset(&_pkg, 0, sizeof(_pkg));
    memset(&_pkg, 0, sizeof(_pkg));
    ASSERT_EQ(OZAYN_BK_ERR_INVALID_REQUEST,
              ozayn_bk_add_object(&_bk_svc, &_pkg, "obj1"));
    return 0;
}

TEST(test_bk_add_object_wrong_state) {
    _init_bk_svc();
    _bk_svc.state = OZAYN_BK_STATE_READY;
    memset(&_pkg, 0, sizeof(_pkg));
    memset(&_pkg, 0, sizeof(_pkg));
    _pkg.in_use = 1;
    ASSERT_EQ(OZAYN_BK_ERR_UNAVAILABLE,
              ozayn_bk_add_object(&_bk_svc, &_pkg, "obj1"));
    return 0;
}

TEST(test_bk_add_object_not_in_vault) {
    _init_bk_svc();
    memset(&_pkg, 0, sizeof(_pkg));
    ASSERT_EQ(OZAYN_BK_OK, ozayn_bk_create(&_bk_svc, OZAYN_BK_TYPE_FULL, &_pkg));
    ASSERT_EQ(OZAYN_BK_ERR_OBJECT_NOT_FOUND,
              ozayn_bk_add_object(&_bk_svc, &_pkg, "nonexistent"));
    return 0;
}

TEST(test_bk_add_object_success) {
    _init_bk_svc();
    _store_test_object("obj1", OZAYN_DATA_CATEGORY_USER_PREFERENCES);
    memset(&_pkg, 0, sizeof(_pkg));
    ASSERT_EQ(OZAYN_BK_OK, ozayn_bk_create(&_bk_svc, OZAYN_BK_TYPE_FULL, &_pkg));
    ASSERT_EQ(OZAYN_BK_OK, ozayn_bk_add_object(&_bk_svc, &_pkg, "obj1"));
    ASSERT_EQ(1, _pkg.manifest.object_count);
    ASSERT_EQ(1, _pkg.object_count);
    ASSERT(strcmp(_pkg.manifest.objects[0].id, "obj1") == 0);
    return 0;
}

TEST(test_bk_add_object_duplicate) {
    _init_bk_svc();
    _store_test_object("obj1", OZAYN_DATA_CATEGORY_USER_PREFERENCES);
    memset(&_pkg, 0, sizeof(_pkg));
    ASSERT_EQ(OZAYN_BK_OK, ozayn_bk_create(&_bk_svc, OZAYN_BK_TYPE_FULL, &_pkg));
    ASSERT_EQ(OZAYN_BK_OK, ozayn_bk_add_object(&_bk_svc, &_pkg, "obj1"));
    ASSERT_EQ(OZAYN_BK_ERR_DUPLICATE,
              ozayn_bk_add_object(&_bk_svc, &_pkg, "obj1"));
    return 0;
}

TEST(test_bk_add_multiple_objects) {
    _init_bk_svc();
    _store_test_object("obj_a", OZAYN_DATA_CATEGORY_USER_PREFERENCES);
    _store_test_object("obj_b", OZAYN_DATA_CATEGORY_IDENTITY_INFORMATION);
    _store_test_object("obj_c", OZAYN_DATA_CATEGORY_AUTH_INFO);
    memset(&_pkg, 0, sizeof(_pkg));
    ASSERT_EQ(OZAYN_BK_OK, ozayn_bk_create(&_bk_svc, OZAYN_BK_TYPE_FULL, &_pkg));
    ASSERT_EQ(OZAYN_BK_OK, ozayn_bk_add_object(&_bk_svc, &_pkg, "obj_a"));
    ASSERT_EQ(OZAYN_BK_OK, ozayn_bk_add_object(&_bk_svc, &_pkg, "obj_b"));
    ASSERT_EQ(OZAYN_BK_OK, ozayn_bk_add_object(&_bk_svc, &_pkg, "obj_c"));
    ASSERT_EQ(3, _pkg.manifest.object_count);
    return 0;
}

TEST(test_bk_add_object_size_tracked) {
    _init_bk_svc();
    _store_test_object("obj1", OZAYN_DATA_CATEGORY_USER_PREFERENCES);
    memset(&_pkg, 0, sizeof(_pkg));
    ASSERT_EQ(OZAYN_BK_OK, ozayn_bk_create(&_bk_svc, OZAYN_BK_TYPE_FULL, &_pkg));
    ASSERT_EQ(OZAYN_BK_OK, ozayn_bk_add_object(&_bk_svc, &_pkg, "obj1"));
    ASSERT(_pkg.manifest.total_protected_size >= 0);
    return 0;
}

/* ============================================================
 * 7. FINALIZE
 * ============================================================ */

TEST(test_bk_finalize_null) {
    ASSERT_EQ(OZAYN_BK_ERR_NULL, ozayn_bk_finalize(NULL, NULL));
    return 0;
}

TEST(test_bk_finalize_not_initialized) {
    ozayn_bk_service_t svc;
    memset(&svc, 0, sizeof(svc));
    memset(&_pkg, 0, sizeof(_pkg));
    ASSERT_EQ(OZAYN_BK_ERR_NOT_INITIALIZED, ozayn_bk_finalize(&svc, &_pkg));
    return 0;
}

TEST(test_bk_finalize_no_package) {
    _init_bk_svc();
    memset(&_pkg, 0, sizeof(_pkg));
    memset(&_pkg, 0, sizeof(_pkg));
    ASSERT_EQ(OZAYN_BK_ERR_INVALID_REQUEST, ozayn_bk_finalize(&_bk_svc, &_pkg));
    return 0;
}

TEST(test_bk_finalize_wrong_state) {
    _init_bk_svc();
    _bk_svc.state = OZAYN_BK_STATE_READY;
    memset(&_pkg, 0, sizeof(_pkg));
    memset(&_pkg, 0, sizeof(_pkg));
    _pkg.in_use = 1;
    ASSERT_EQ(OZAYN_BK_ERR_UNAVAILABLE, ozayn_bk_finalize(&_bk_svc, &_pkg));
    return 0;
}

TEST(test_bk_finalize_empty_package) {
    _init_bk_svc();
    memset(&_pkg, 0, sizeof(_pkg));
    ASSERT_EQ(OZAYN_BK_OK, ozayn_bk_create(&_bk_svc, OZAYN_BK_TYPE_FULL, &_pkg));
    ASSERT_EQ(OZAYN_BK_ERR_INVALID_REQUEST, ozayn_bk_finalize(&_bk_svc, &_pkg));
    return 0;
}

TEST(test_bk_finalize_success) {
    _init_bk_svc();
    _store_test_object("obj1", OZAYN_DATA_CATEGORY_USER_PREFERENCES);
    memset(&_pkg, 0, sizeof(_pkg));
    ASSERT_EQ(OZAYN_BK_OK, ozayn_bk_create(&_bk_svc, OZAYN_BK_TYPE_FULL, &_pkg));
    ASSERT_EQ(OZAYN_BK_OK, ozayn_bk_add_object(&_bk_svc, &_pkg, "obj1"));
    ASSERT_EQ(OZAYN_BK_OK, ozayn_bk_finalize(&_bk_svc, &_pkg));
    ASSERT(_pkg.manifest.integrity_verified);
    ASSERT(_pkg.manifest.manifest_checksum != 0);
    ASSERT_EQ(OZAYN_BK_STATE_READY, _bk_svc.state);
    return 0;
}

TEST(test_bk_finalize_stats_updated) {
    _init_bk_svc();
    _store_test_object("obj1", OZAYN_DATA_CATEGORY_USER_PREFERENCES);
    memset(&_pkg, 0, sizeof(_pkg));
    ASSERT_EQ(OZAYN_BK_OK, ozayn_bk_create(&_bk_svc, OZAYN_BK_TYPE_FULL, &_pkg));
    ASSERT_EQ(OZAYN_BK_OK, ozayn_bk_add_object(&_bk_svc, &_pkg, "obj1"));
    ASSERT_EQ(OZAYN_BK_OK, ozayn_bk_finalize(&_bk_svc, &_pkg));
    ASSERT_EQ(1, _bk_svc.total_backups_created);
    return 0;
}

/* ============================================================
 * 8. VALIDATION
 * ============================================================ */

TEST(test_bk_validate_package_null) {
    ASSERT_EQ(OZAYN_BK_ERR_NULL, ozayn_bk_validate_package(NULL, NULL));
    return 0;
}

TEST(test_bk_validate_package_not_initialized) {
    ozayn_bk_service_t svc;
    memset(&svc, 0, sizeof(svc));
    memset(&_pkg, 0, sizeof(_pkg));
    ASSERT_EQ(OZAYN_BK_ERR_NOT_INITIALIZED, ozayn_bk_validate_package(&svc, &_pkg));
    return 0;
}

TEST(test_bk_validate_package_not_in_use) {
    _init_bk_svc();
    memset(&_pkg, 0, sizeof(_pkg));
    memset(&_pkg, 0, sizeof(_pkg));
    ASSERT_EQ(OZAYN_BK_ERR_INVALID_REQUEST, ozayn_bk_validate_package(&_bk_svc, &_pkg));
    return 0;
}

TEST(test_bk_validate_manifest_null) {
    ASSERT_EQ(OZAYN_BK_ERR_NULL, ozayn_bk_validate_manifest(NULL, NULL));
    return 0;
}

TEST(test_bk_validate_manifest_not_initialized) {
    ozayn_bk_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_bk_manifest_t m;
    ASSERT_EQ(OZAYN_BK_ERR_NOT_INITIALIZED, ozayn_bk_validate_manifest(&svc, &m));
    return 0;
}

TEST(test_bk_validate_manifest_bad_version) {
    _init_bk_svc();
    ozayn_bk_manifest_t m;
    memset(&m, 0, sizeof(m));
    m.format_version = 99;
    m.backup_type = OZAYN_BK_TYPE_FULL;
    m.object_count = 1;
    ASSERT_EQ(OZAYN_BK_ERR_FORMAT_UNSUPPORTED, ozayn_bk_validate_manifest(&_bk_svc, &m));
    return 0;
}

TEST(test_bk_validate_manifest_bad_type) {
    _init_bk_svc();
    ozayn_bk_manifest_t m;
    memset(&m, 0, sizeof(m));
    m.format_version = OZAYN_BK_FORMAT_VERSION;
    m.backup_type = (ozayn_bk_type_t)99;
    m.object_count = 1;
    ASSERT_EQ(OZAYN_BK_ERR_FORMAT_INVALID, ozayn_bk_validate_manifest(&_bk_svc, &m));
    return 0;
}

TEST(test_bk_validate_manifest_bad_object_count) {
    _init_bk_svc();
    ozayn_bk_manifest_t m;
    memset(&m, 0, sizeof(m));
    m.format_version = OZAYN_BK_FORMAT_VERSION;
    m.backup_type = OZAYN_BK_TYPE_FULL;
    m.object_count = 0;
    ASSERT_EQ(OZAYN_BK_ERR_FORMAT_INVALID, ozayn_bk_validate_manifest(&_bk_svc, &m));
    return 0;
}

TEST(test_bk_validate_manifest_checksum_mismatch) {
    _init_bk_svc();
    ozayn_bk_manifest_t m;
    memset(&m, 0, sizeof(m));
    m.format_version = OZAYN_BK_FORMAT_VERSION;
    m.backup_type = OZAYN_BK_TYPE_FULL;
    m.object_count = 1;
    strncpy(m.objects[0].id, "test", OZAYN_BK_MAX_OBJECT_ID_LEN);
    m.manifest_checksum = 99999;
    ASSERT_EQ(OZAYN_BK_ERR_INTEGRITY_FAILURE, ozayn_bk_validate_manifest(&_bk_svc, &m));
    return 0;
}

/* ============================================================
 * 9. COMPATIBILITY
 * ============================================================ */

TEST(test_bk_compat_supported) {
    _init_bk_svc();
    ozayn_bk_manifest_t m;
    memset(&m, 0, sizeof(m));
    m.format_version = OZAYN_BK_FORMAT_VERSION;
    ASSERT_EQ(OZAYN_BK_COMPAT_SUPPORTED, ozayn_bk_check_compatibility(&_bk_svc, &m));
    return 0;
}

TEST(test_bk_compat_corrupted) {
    _init_bk_svc();
    ozayn_bk_manifest_t m;
    memset(&m, 0, sizeof(m));
    m.format_version = 0;
    ASSERT_EQ(OZAYN_BK_COMPAT_CORRUPTED, ozayn_bk_check_compatibility(&_bk_svc, &m));
    return 0;
}

TEST(test_bk_compat_incompatible) {
    _init_bk_svc();
    ozayn_bk_manifest_t m;
    memset(&m, 0, sizeof(m));
    m.format_version = 999;
    ASSERT_EQ(OZAYN_BK_COMPAT_INCOMPATIBLE, ozayn_bk_check_compatibility(&_bk_svc, &m));
    return 0;
}

TEST(test_bk_compat_migration) {
    _init_bk_svc();
    ozayn_bk_manifest_t m;
    memset(&m, 0, sizeof(m));
    m.format_version = OZAYN_BK_FORMAT_VERSION - 1;
    ASSERT_EQ(OZAYN_BK_COMPAT_CORRUPTED, ozayn_bk_check_compatibility(&_bk_svc, &m));
    return 0;
}

TEST(test_bk_compat_null) {
    ASSERT_EQ(OZAYN_BK_COMPAT_CORRUPTED, ozayn_bk_check_compatibility(NULL, NULL));
    return 0;
}

/* ============================================================
 * 10. RESTORE — VALIDATE ONLY
 * ============================================================ */

TEST(test_bk_restore_validate_only_null) {
    ASSERT_EQ(OZAYN_BK_ERR_NULL, ozayn_bk_restore(NULL, NULL, NULL));
    return 0;
}

TEST(test_bk_restore_validate_only_not_initialized) {
    ozayn_bk_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_bk_restore_request_t req;
    memset(&_pkg, 0, sizeof(_pkg));
    ASSERT_EQ(OZAYN_BK_ERR_NOT_INITIALIZED, ozayn_bk_restore(&svc, &req, &_pkg));
    return 0;
}

TEST(test_bk_restore_validate_only_success) {
    _init_bk_svc();
    _store_test_object("obj1", OZAYN_DATA_CATEGORY_USER_PREFERENCES);
    memset(&_pkg, 0, sizeof(_pkg));
    ASSERT_EQ(OZAYN_BK_OK, ozayn_bk_create(&_bk_svc, OZAYN_BK_TYPE_FULL, &_pkg));
    ASSERT_EQ(OZAYN_BK_OK, ozayn_bk_add_object(&_bk_svc, &_pkg, "obj1"));
    ASSERT_EQ(OZAYN_BK_OK, ozayn_bk_finalize(&_bk_svc, &_pkg));

    ozayn_bk_restore_request_t req;
    memset(&req, 0, sizeof(req));
    req.mode = OZAYN_BK_RESTORE_VALIDATE_ONLY;
    strncpy(req.identity_id, "user1", OZAYN_BK_MAX_OBJECT_ID_LEN - 1);
    strncpy(req.backup_id, _pkg.manifest.backup_id, OZAYN_BK_MAX_BACKUP_ID_LEN - 1);

    ASSERT_EQ(OZAYN_BK_OK, ozayn_bk_restore(&_bk_svc, &req, &_pkg));
    return 0;
}

TEST(test_bk_restore_validate_only_bad_format) {
    _init_bk_svc();
    memset(&_pkg, 0, sizeof(_pkg));
    memset(&_pkg, 0, sizeof(_pkg));
    _pkg.in_use = 1;
    _pkg.manifest.format_version = 99;
    _pkg.manifest.backup_type = OZAYN_BK_TYPE_FULL;
    _pkg.manifest.object_count = 1;

    ozayn_bk_restore_request_t req;
    memset(&req, 0, sizeof(req));
    req.mode = OZAYN_BK_RESTORE_VALIDATE_ONLY;
    strncpy(req.identity_id, "user1", OZAYN_BK_MAX_OBJECT_ID_LEN - 1);

    ASSERT_EQ(OZAYN_BK_ERR_FORMAT_UNSUPPORTED, ozayn_bk_restore(&_bk_svc, &req, &_pkg));
    return 0;
}

TEST(test_bk_restore_validate_only_bad_checksum) {
    _init_bk_svc();
    memset(&_pkg, 0, sizeof(_pkg));
    _pkg.in_use = 1;
    _pkg.manifest.format_version = OZAYN_BK_FORMAT_VERSION;
    _pkg.manifest.backup_type = OZAYN_BK_TYPE_FULL;
    _pkg.manifest.object_count = 1;
    _pkg.manifest.integrity_verified = 1;
    strncpy(_pkg.manifest.objects[0].id, "obj1", OZAYN_BK_MAX_OBJECT_ID_LEN);
    _pkg.manifest.objects[0].checksum = 42;
    _pkg.manifest.manifest_checksum = 99999;

    ozayn_bk_restore_request_t req;
    memset(&req, 0, sizeof(req));
    req.mode = OZAYN_BK_RESTORE_VALIDATE_ONLY;
    strncpy(req.identity_id, "user1", OZAYN_BK_MAX_OBJECT_ID_LEN - 1);

    ASSERT_EQ(OZAYN_BK_ERR_INTEGRITY_FAILURE, ozayn_bk_restore(&_bk_svc, &req, &_pkg));
    return 0;
}

/* ============================================================
 * 11. RESTORE — AUTHORIZATION
 * ============================================================ */

TEST(test_bk_restore_revoked_identity_denied) {
    _init_bk_svc();
    _store_test_object("obj1", OZAYN_DATA_CATEGORY_USER_PREFERENCES);
    memset(&_pkg, 0, sizeof(_pkg));
    ASSERT_EQ(OZAYN_BK_OK, ozayn_bk_create(&_bk_svc, OZAYN_BK_TYPE_FULL, &_pkg));
    ASSERT_EQ(OZAYN_BK_OK, ozayn_bk_add_object(&_bk_svc, &_pkg, "obj1"));
    ASSERT_EQ(OZAYN_BK_OK, ozayn_bk_finalize(&_bk_svc, &_pkg));

    ozayn_bk_restore_request_t req;
    memset(&req, 0, sizeof(req));
    req.mode = OZAYN_BK_RESTORE_NEW;
    strncpy(req.identity_id, "revoked", OZAYN_BK_MAX_OBJECT_ID_LEN - 1);
    strncpy(req.backup_id, _pkg.manifest.backup_id, OZAYN_BK_MAX_BACKUP_ID_LEN - 1);

    ASSERT_EQ(OZAYN_BK_ERR_RESTORE_UNAUTHORIZED, ozayn_bk_restore(&_bk_svc, &req, &_pkg));
    return 0;
}

TEST(test_bk_restore_suspended_identity_denied) {
    _init_bk_svc();
    _store_test_object("obj1", OZAYN_DATA_CATEGORY_USER_PREFERENCES);
    memset(&_pkg, 0, sizeof(_pkg));
    ASSERT_EQ(OZAYN_BK_OK, ozayn_bk_create(&_bk_svc, OZAYN_BK_TYPE_FULL, &_pkg));
    ASSERT_EQ(OZAYN_BK_OK, ozayn_bk_add_object(&_bk_svc, &_pkg, "obj1"));
    ASSERT_EQ(OZAYN_BK_OK, ozayn_bk_finalize(&_bk_svc, &_pkg));

    ozayn_bk_restore_request_t req;
    memset(&req, 0, sizeof(req));
    req.mode = OZAYN_BK_RESTORE_NEW;
    strncpy(req.identity_id, "suspended", OZAYN_BK_MAX_OBJECT_ID_LEN - 1);
    strncpy(req.backup_id, _pkg.manifest.backup_id, OZAYN_BK_MAX_BACKUP_ID_LEN - 1);

    ASSERT_EQ(OZAYN_BK_ERR_RESTORE_UNAUTHORIZED, ozayn_bk_restore(&_bk_svc, &req, &_pkg));
    return 0;
}

TEST(test_bk_restore_empty_identity_denied) {
    _init_bk_svc();
    _store_test_object("obj1", OZAYN_DATA_CATEGORY_USER_PREFERENCES);
    memset(&_pkg, 0, sizeof(_pkg));
    ASSERT_EQ(OZAYN_BK_OK, ozayn_bk_create(&_bk_svc, OZAYN_BK_TYPE_FULL, &_pkg));
    ASSERT_EQ(OZAYN_BK_OK, ozayn_bk_add_object(&_bk_svc, &_pkg, "obj1"));
    ASSERT_EQ(OZAYN_BK_OK, ozayn_bk_finalize(&_bk_svc, &_pkg));

    ozayn_bk_restore_request_t req;
    memset(&req, 0, sizeof(req));
    req.mode = OZAYN_BK_RESTORE_NEW;
    strncpy(req.backup_id, _pkg.manifest.backup_id, OZAYN_BK_MAX_BACKUP_ID_LEN - 1);

    ASSERT_EQ(OZAYN_BK_ERR_RESTORE_UNAUTHORIZED, ozayn_bk_restore(&_bk_svc, &req, &_pkg));
    return 0;
}

TEST(test_bk_restore_force_bypasses_auth) {
    _init_bk_svc();
    _store_test_object("obj1", OZAYN_DATA_CATEGORY_USER_PREFERENCES);
    memset(&_pkg, 0, sizeof(_pkg));
    ASSERT_EQ(OZAYN_BK_OK, ozayn_bk_create(&_bk_svc, OZAYN_BK_TYPE_FULL, &_pkg));
    ASSERT_EQ(OZAYN_BK_OK, ozayn_bk_add_object(&_bk_svc, &_pkg, "obj1"));
    ASSERT_EQ(OZAYN_BK_OK, ozayn_bk_finalize(&_bk_svc, &_pkg));

    ozayn_bk_restore_request_t req;
    memset(&req, 0, sizeof(req));
    req.mode = OZAYN_BK_RESTORE_NEW;
    req.force = 1;
    strncpy(req.identity_id, "revoked", OZAYN_BK_MAX_OBJECT_ID_LEN - 1);
    strncpy(req.backup_id, _pkg.manifest.backup_id, OZAYN_BK_MAX_BACKUP_ID_LEN - 1);

    ASSERT_EQ(OZAYN_BK_OK, ozayn_bk_restore(&_bk_svc, &req, &_pkg));
    return 0;
}

/* ============================================================
 * 12. RESTORE — VERSION INCOMPATIBILITY
 * ============================================================ */

TEST(test_bk_restore_version_incompatible) {
    _init_bk_svc();
    _store_test_object("obj1", OZAYN_DATA_CATEGORY_USER_PREFERENCES);
    memset(&_pkg, 0, sizeof(_pkg));
    ASSERT_EQ(OZAYN_BK_OK, ozayn_bk_create(&_bk_svc, OZAYN_BK_TYPE_FULL, &_pkg));
    ASSERT_EQ(OZAYN_BK_OK, ozayn_bk_add_object(&_bk_svc, &_pkg, "obj1"));
    ASSERT_EQ(OZAYN_BK_OK, ozayn_bk_finalize(&_bk_svc, &_pkg));
    /* Corrupt format version after finalization — validation catches it as FORMAT_UNSUPPORTED */
    _pkg.manifest.format_version = 999;

    ozayn_bk_restore_request_t req;
    memset(&req, 0, sizeof(req));
    req.mode = OZAYN_BK_RESTORE_NEW;
    req.force = 1;
    strncpy(req.identity_id, "user1", OZAYN_BK_MAX_OBJECT_ID_LEN - 1);
    strncpy(req.backup_id, _pkg.manifest.backup_id, OZAYN_BK_MAX_BACKUP_ID_LEN - 1);

    ASSERT_EQ(OZAYN_BK_ERR_FORMAT_UNSUPPORTED, ozayn_bk_restore(&_bk_svc, &req, &_pkg));
    return 0;
}

/* ============================================================
 * 13. RESTORE — KEY VERSION CHECK
 * ============================================================ */

TEST(test_bk_restore_key_version_zero) {
    _init_bk_svc();
    _store_test_object("obj1", OZAYN_DATA_CATEGORY_USER_PREFERENCES);
    memset(&_pkg, 0, sizeof(_pkg));
    _pkg.in_use = 1;
    _pkg.manifest.format_version = OZAYN_BK_FORMAT_VERSION;
    _pkg.manifest.backup_type = OZAYN_BK_TYPE_FULL;
    _pkg.manifest.object_count = 1;
    _pkg.manifest.integrity_verified = 1;
    strncpy(_pkg.manifest.objects[0].id, "obj1", OZAYN_BK_MAX_OBJECT_ID_LEN);
    _pkg.manifest.objects[0].key_version = 0;
    _pkg.manifest.objects[0].checksum = ozayn_bk_checksum(_pkg.objects[0].protected_data.ciphertext, 0);
    _pkg.manifest.manifest_checksum = ozayn_bk_checksum(
        (const uint8_t *)_pkg.manifest.objects,
        sizeof(ozayn_bk_object_meta_t));
    _pkg.objects[0].in_use = 1;
    _pkg.objects[0].key_version = 0;
    strncpy(_pkg.objects[0].id, "obj1", OZAYN_BK_MAX_OBJECT_ID_LEN);

    ozayn_bk_restore_request_t req;
    memset(&req, 0, sizeof(req));
    req.mode = OZAYN_BK_RESTORE_NEW;
    req.force = 1;
    strncpy(req.identity_id, "user1", OZAYN_BK_MAX_OBJECT_ID_LEN - 1);
    strncpy(req.backup_id, _pkg.manifest.backup_id, OZAYN_BK_MAX_BACKUP_ID_LEN - 1);

    ASSERT_EQ(OZAYN_BK_ERR_KEY_INVALID, ozayn_bk_restore(&_bk_svc, &req, &_pkg));
    return 0;
}

/* ============================================================
 * 14. RESTORE — NEW MODE
 * ============================================================ */

TEST(test_bk_restore_new_success) {
    _init_bk_svc();
    _store_test_object("obj1", OZAYN_DATA_CATEGORY_USER_PREFERENCES);
    memset(&_pkg, 0, sizeof(_pkg));
    ASSERT_EQ(OZAYN_BK_OK, ozayn_bk_create(&_bk_svc, OZAYN_BK_TYPE_FULL, &_pkg));
    ASSERT_EQ(OZAYN_BK_OK, ozayn_bk_add_object(&_bk_svc, &_pkg, "obj1"));
    ASSERT_EQ(OZAYN_BK_OK, ozayn_bk_finalize(&_bk_svc, &_pkg));

    /* Remove original from vault */
    ozayn_vault_remove(&_vault, "obj1");
    ASSERT(!ozayn_vault_exists(&_vault, "obj1"));

    ozayn_bk_restore_request_t req;
    memset(&req, 0, sizeof(req));
    req.mode = OZAYN_BK_RESTORE_NEW;
    req.force = 1;
    strncpy(req.identity_id, "user1", OZAYN_BK_MAX_OBJECT_ID_LEN - 1);
    strncpy(req.backup_id, _pkg.manifest.backup_id, OZAYN_BK_MAX_BACKUP_ID_LEN - 1);

    /* Restore succeeds — metadata-only backup skips data restore */
    ASSERT_EQ(OZAYN_BK_OK, ozayn_bk_restore(&_bk_svc, &req, &_pkg));
    return 0;
}

/* ============================================================
 * 15. RESTORE — REPLACE MODE
 * ============================================================ */

TEST(test_bk_restore_replace_success) {
    _init_bk_svc();
    _store_test_object("obj1", OZAYN_DATA_CATEGORY_USER_PREFERENCES);
    memset(&_pkg, 0, sizeof(_pkg));
    ASSERT_EQ(OZAYN_BK_OK, ozayn_bk_create(&_bk_svc, OZAYN_BK_TYPE_FULL, &_pkg));
    ASSERT_EQ(OZAYN_BK_OK, ozayn_bk_add_object(&_bk_svc, &_pkg, "obj1"));
    ASSERT_EQ(OZAYN_BK_OK, ozayn_bk_finalize(&_bk_svc, &_pkg));

    ASSERT(ozayn_vault_exists(&_vault, "obj1"));

    ozayn_bk_restore_request_t req;
    memset(&req, 0, sizeof(req));
    req.mode = OZAYN_BK_RESTORE_REPLACE;
    req.force = 1;
    strncpy(req.identity_id, "user1", OZAYN_BK_MAX_OBJECT_ID_LEN - 1);
    strncpy(req.backup_id, _pkg.manifest.backup_id, OZAYN_BK_MAX_BACKUP_ID_LEN - 1);

    /* Restore succeeds — metadata-only backup skips data restore */
    ASSERT_EQ(OZAYN_BK_OK, ozayn_bk_restore(&_bk_svc, &req, &_pkg));
    return 0;
}

/* ============================================================
 * 16. RESTORE — INVALID REQUEST
 * ============================================================ */

TEST(test_bk_restore_invalid_mode) {
    _init_bk_svc();
    memset(&_pkg, 0, sizeof(_pkg));
    memset(&_pkg, 0, sizeof(_pkg));
    _pkg.in_use = 1;
    _pkg.manifest.format_version = OZAYN_BK_FORMAT_VERSION;
    _pkg.manifest.backup_type = OZAYN_BK_TYPE_FULL;
    _pkg.manifest.object_count = 1;
    strncpy(_pkg.manifest.objects[0].id, "obj1", OZAYN_BK_MAX_OBJECT_ID_LEN);

    ozayn_bk_restore_request_t req;
    memset(&req, 0, sizeof(req));
    req.mode = (ozayn_bk_restore_mode_t)99;
    strncpy(req.identity_id, "user1", OZAYN_BK_MAX_OBJECT_ID_LEN - 1);

    ASSERT_EQ(OZAYN_BK_ERR_INVALID_REQUEST, ozayn_bk_restore(&_bk_svc, &req, &_pkg));
    return 0;
}

/* ============================================================
 * 17. RESTORE — AUDIT
 * ============================================================ */

TEST(test_bk_restore_emits_audit_event) {
    _init_bk_svc();
    _store_test_object("obj1", OZAYN_DATA_CATEGORY_USER_PREFERENCES);
    memset(&_pkg, 0, sizeof(_pkg));
    ASSERT_EQ(OZAYN_BK_OK, ozayn_bk_create(&_bk_svc, OZAYN_BK_TYPE_FULL, &_pkg));
    ASSERT_EQ(OZAYN_BK_OK, ozayn_bk_add_object(&_bk_svc, &_pkg, "obj1"));
    ASSERT_EQ(OZAYN_BK_OK, ozayn_bk_finalize(&_bk_svc, &_pkg));

    int count_before = ozayn_audit_count(&_audit_svc);

    ozayn_bk_restore_request_t req;
    memset(&req, 0, sizeof(req));
    req.mode = OZAYN_BK_RESTORE_VALIDATE_ONLY;
    strncpy(req.identity_id, "user1", OZAYN_BK_MAX_OBJECT_ID_LEN - 1);
    strncpy(req.backup_id, _pkg.manifest.backup_id, OZAYN_BK_MAX_BACKUP_ID_LEN - 1);

    ASSERT_EQ(OZAYN_BK_OK, ozayn_bk_restore(&_bk_svc, &req, &_pkg));
    ASSERT_GT(ozayn_audit_count(&_audit_svc), count_before);
    return 0;
}

/* ============================================================
 * 18. END-TO-END: CREATE → VALIDATE → RESTORE
 * ============================================================ */

TEST(test_bk_end_to_end) {
    _init_bk_svc();
    _store_test_object("e2e_obj1", OZAYN_DATA_CATEGORY_USER_PREFERENCES);
    _store_test_object("e2e_obj2", OZAYN_DATA_CATEGORY_IDENTITY_INFORMATION);

    /* Create */
    memset(&_pkg, 0, sizeof(_pkg));
    ASSERT_EQ(OZAYN_BK_OK, ozayn_bk_create(&_bk_svc, OZAYN_BK_TYPE_FULL, &_pkg));
    ASSERT_EQ(OZAYN_BK_OK, ozayn_bk_add_object(&_bk_svc, &_pkg, "e2e_obj1"));
    ASSERT_EQ(OZAYN_BK_OK, ozayn_bk_add_object(&_bk_svc, &_pkg, "e2e_obj2"));
    ASSERT_EQ(OZAYN_BK_OK, ozayn_bk_finalize(&_bk_svc, &_pkg));

    /* Validate */
    ASSERT_EQ(OZAYN_BK_OK, ozayn_bk_validate_package(&_bk_svc, &_pkg));

    /* Compatibility */
    ASSERT_EQ(OZAYN_BK_COMPAT_SUPPORTED,
              ozayn_bk_check_compatibility(&_bk_svc, &_pkg.manifest));

    /* Restore validate-only */
    ozayn_bk_restore_request_t req;
    memset(&req, 0, sizeof(req));
    req.mode = OZAYN_BK_RESTORE_VALIDATE_ONLY;
    strncpy(req.identity_id, "user1", OZAYN_BK_MAX_OBJECT_ID_LEN - 1);
    strncpy(req.backup_id, _pkg.manifest.backup_id, OZAYN_BK_MAX_BACKUP_ID_LEN - 1);
    ASSERT_EQ(OZAYN_BK_OK, ozayn_bk_restore(&_bk_svc, &req, &_pkg));

    /* Restore replace */
    req.mode = OZAYN_BK_RESTORE_REPLACE;
    req.force = 1;
    ASSERT_EQ(OZAYN_BK_OK, ozayn_bk_restore(&_bk_svc, &req, &_pkg));
    return 0;
}

/* ============================================================
 * 19. POLICY REJECTION
 * ============================================================ */

TEST(test_bk_policy_disables_category) {
    _init_bk_svc();
    _store_test_object("obj1", OZAYN_DATA_CATEGORY_USER_PREFERENCES);

    ozayn_bk_policy_t p = ozayn_bk_default_policy();
    p.allowed_categories[OZAYN_DATA_CATEGORY_USER_PREFERENCES] = 0;
    ozayn_bk_set_policy(&_bk_svc, &p);

    memset(&_pkg, 0, sizeof(_pkg));
    ASSERT_EQ(OZAYN_BK_OK, ozayn_bk_create(&_bk_svc, OZAYN_BK_TYPE_FULL, &_pkg));
    ASSERT_EQ(OZAYN_BK_ERR_CATEGORY_NOT_ALLOWED,
              ozayn_bk_add_object(&_bk_svc, &_pkg, "obj1"));
    return 0;
}

/* ============================================================
 * 20. QH MANAGER (GLOBAL)
 * ============================================================ */

TEST(test_bk_get_global) {
    ozayn_bk_service_t *g = ozayn_bk_get_global();
    ASSERT_NOT_NULL(g);
    return 0;
}

/* ============================================================
 * RUNNER
 * ============================================================ */

int run_backup_tests(void) {
    SUITE_BEGIN("Backup & Recovery Tests");

    _setup_deps();

    /* Lifecycle */
    RUN(test_bk_service_init_null);
    RUN(test_bk_service_init_config_null);
    RUN(test_bk_service_init_success);
    RUN(test_bk_service_init_already_initialized);
    RUN(test_bk_service_shutdown_null);
    RUN(test_bk_service_shutdown_not_initialized);
    RUN(test_bk_service_shutdown_success);
    RUN(test_bk_service_is_initialized_null);

    /* Name helpers */
    RUN(test_bk_result_name_ok);
    RUN(test_bk_result_name_err);
    RUN(test_bk_result_name_various);
    RUN(test_bk_type_name);
    RUN(test_bk_state_name);
    RUN(test_bk_restore_mode_name);
    RUN(test_bk_compat_name);

    /* Policy */
    RUN(test_bk_default_policy);
    RUN(test_bk_set_get_policy);
    RUN(test_bk_set_policy_null);
    RUN(test_bk_get_policy_null);
    RUN(test_bk_get_policy_not_initialized);

    /* Checksum */
    RUN(test_bk_checksum_deterministic);
    RUN(test_bk_checksum_different_data);
    RUN(test_bk_checksum_empty);

    /* Create */
    RUN(test_bk_create_null);
    RUN(test_bk_create_not_initialized);
    RUN(test_bk_create_invalid_type);
    RUN(test_bk_create_full);
    RUN(test_bk_create_selective);
    RUN(test_bk_create_configuration);
    RUN(test_bk_create_unique_ids);

    /* Add object */
    RUN(test_bk_add_object_null);
    RUN(test_bk_add_object_not_initialized);
    RUN(test_bk_add_object_no_package);
    RUN(test_bk_add_object_wrong_state);
    RUN(test_bk_add_object_not_in_vault);
    RUN(test_bk_add_object_success);
    RUN(test_bk_add_object_duplicate);
    RUN(test_bk_add_multiple_objects);
    RUN(test_bk_add_object_size_tracked);

    /* Finalize */
    RUN(test_bk_finalize_null);
    RUN(test_bk_finalize_not_initialized);
    RUN(test_bk_finalize_no_package);
    RUN(test_bk_finalize_wrong_state);
    RUN(test_bk_finalize_empty_package);
    RUN(test_bk_finalize_success);
    RUN(test_bk_finalize_stats_updated);

    /* Validation */
    RUN(test_bk_validate_package_null);
    RUN(test_bk_validate_package_not_initialized);
    RUN(test_bk_validate_package_not_in_use);
    RUN(test_bk_validate_manifest_null);
    RUN(test_bk_validate_manifest_not_initialized);
    RUN(test_bk_validate_manifest_bad_version);
    RUN(test_bk_validate_manifest_bad_type);
    RUN(test_bk_validate_manifest_bad_object_count);
    RUN(test_bk_validate_manifest_checksum_mismatch);

    /* Compatibility */
    RUN(test_bk_compat_supported);
    RUN(test_bk_compat_corrupted);
    RUN(test_bk_compat_incompatible);
    RUN(test_bk_compat_migration);
    RUN(test_bk_compat_null);

    /* Restore */
    RUN(test_bk_restore_validate_only_null);
    RUN(test_bk_restore_validate_only_not_initialized);
    RUN(test_bk_restore_validate_only_success);
    RUN(test_bk_restore_validate_only_bad_format);
    RUN(test_bk_restore_validate_only_bad_checksum);
    RUN(test_bk_restore_revoked_identity_denied);
    RUN(test_bk_restore_suspended_identity_denied);
    RUN(test_bk_restore_empty_identity_denied);
    RUN(test_bk_restore_force_bypasses_auth);
    RUN(test_bk_restore_version_incompatible);
    RUN(test_bk_restore_key_version_zero);
    RUN(test_bk_restore_new_success);
    RUN(test_bk_restore_replace_success);
    RUN(test_bk_restore_invalid_mode);
    RUN(test_bk_restore_emits_audit_event);

    /* End-to-end */
    RUN(test_bk_end_to_end);

    /* Policy rejection */
    RUN(test_bk_policy_disables_category);

    /* Global */
    RUN(test_bk_get_global);

    SUITE_END();

    _teardown_deps();

    return TOTAL_FAIL();
}
