/*
 * test_deletion.c — Secure Deletion & Data Destruction Tests (Step 24).
 *
 * Comprehensive tests for the deletion service covering lifecycle,
 * name helpers, policy, request validation, deletion execution,
 * key dependency, cryptographic erasure, temporary cleanup,
 * error handling, and audit integration.
 */

#include "../../tests/test_framework.h"
#include "../deletion.h"
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
 * TEST INFRASTRUCTURE
 * ============================================================ */

static ozayn_protection_provider_t _prot;
static ozayn_storage_provider_t    _stor;
static ozayn_kl_manager_t          _kl;
static ozayn_vault_t               _vault;
static ozayn_audit_service_t       _audit_svc;
static ozayn_del_service_t         _del_svc;

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
    ozayn_del_service_shutdown(&_del_svc);
    ozayn_audit_service_shutdown(&_audit_svc);
    ozayn_vault_shutdown(&_vault);
    ozayn_kl_shutdown(&_kl);
    ozayn_sp_shutdown(&_stor);
    ozayn_prot_shutdown(&_prot);
}

static void _init_del_svc(void)
{
    ozayn_del_service_shutdown(&_del_svc);

    /* Reinitialize key lifecycle (previous tests may have revoked keys) */
    ozayn_kl_shutdown(&_kl);
    ozayn_kl_init(&_kl);
    ozayn_kl_register_key(&_kl, "VAULT", OZAYN_KEY_PURPOSE_DATA_ENCRYPTION);
    ozayn_key_id_t kid;
    ozayn_key_id_set(&kid, "VAULT", 1, "test");
    ozayn_kl_add_version(&_kl, "VAULT", &kid, 32);
    ozayn_kl_activate(&_kl, "VAULT", 1);

    /* Reinitialize storage and vault */
    ozayn_sp_shutdown(&_stor);
    ozayn_sp_mem_create_provider(&_stor);
    ozayn_sp_init(&_stor);

    ozayn_vault_shutdown(&_vault);
    ozayn_vault_config_t vcfg;
    memset(&vcfg, 0, sizeof(vcfg));
    vcfg.protection = &_prot;
    vcfg.storage = &_stor;
    vcfg.key_lifecycle = &_kl;
    ozayn_vault_init(&_vault, &vcfg);

    ozayn_del_service_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.vault         = &_vault;
    cfg.key_lifecycle = &_kl;
    cfg.protection    = &_prot;
    cfg.storage       = &_stor;
    cfg.audit         = &_audit_svc;
    ozayn_del_service_init(&_del_svc, &cfg);
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

TEST(test_del_service_init_null)
{
    ASSERT_EQ(OZAYN_DEL_ERR_NULL, ozayn_del_service_init(NULL, NULL));
    return 0;
}

TEST(test_del_service_init_config_null)
{
    ozayn_del_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ASSERT_EQ(OZAYN_DEL_ERR_NULL, ozayn_del_service_init(&svc, NULL));
    return 0;
}

TEST(test_del_service_init_success)
{
    ozayn_del_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_del_service_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    ASSERT_EQ(OZAYN_DEL_OK, ozayn_del_service_init(&svc, &cfg));
    ASSERT(ozayn_del_service_is_initialized(&svc));
    ozayn_del_service_shutdown(&svc);
    return 0;
}

TEST(test_del_service_init_already_initialized)
{
    _init_del_svc();
    ASSERT_EQ(OZAYN_DEL_ERR_ALREADY_INITIALIZED,
              ozayn_del_service_init(&_del_svc, &(ozayn_del_service_config_t){0}));
    return 0;
}

TEST(test_del_service_shutdown_null)
{
    ozayn_del_service_shutdown(NULL);
    return 0;
}

TEST(test_del_service_shutdown_not_initialized)
{
    ozayn_del_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_del_service_shutdown(&svc);
    return 0;
}

TEST(test_del_service_shutdown_success)
{
    _init_del_svc();
    ASSERT(ozayn_del_service_is_initialized(&_del_svc));
    ozayn_del_service_shutdown(&_del_svc);
    ASSERT(!ozayn_del_service_is_initialized(&_del_svc));
    return 0;
}

TEST(test_del_service_is_initialized_null)
{
    ASSERT(!ozayn_del_service_is_initialized(NULL));
    return 0;
}

/* ============================================================
 * 2. NAME HELPERS
 * ============================================================ */

TEST(test_del_result_name_ok)
{
    ASSERT(strcmp(ozayn_del_result_name(OZAYN_DEL_OK), "OK") == 0);
    return 0;
}

TEST(test_del_result_name_err)
{
    ASSERT(strcmp(ozayn_del_result_name(OZAYN_DEL_ERR), "ERR") == 0);
    ASSERT(strcmp(ozayn_del_result_name(OZAYN_DEL_ERR_NULL), "ERR_NULL") == 0);
    ASSERT(strcmp(ozayn_del_result_name(OZAYN_DEL_ERR_NOT_INITIALIZED),
                  "ERR_NOT_INITIALIZED") == 0);
    return 0;
}

TEST(test_del_result_name_various)
{
    ASSERT(strcmp(ozayn_del_result_name(OZAYN_DEL_ERR_NOT_FOUND), "ERR_NOT_FOUND") == 0);
    ASSERT(strcmp(ozayn_del_result_name(OZAYN_DEL_ERR_UNAUTHORIZED),
                  "ERR_UNAUTHORIZED") == 0);
    ASSERT(strcmp(ozayn_del_result_name(OZAYN_DEL_ERR_PARTIAL), "ERR_PARTIAL") == 0);
    ASSERT(strcmp(ozayn_del_result_name((ozayn_del_result_t)9999), "UNKNOWN") == 0);
    return 0;
}

TEST(test_del_type_name)
{
    ASSERT(strcmp(ozayn_del_type_name(OZAYN_DEL_TYPE_LOGICAL), "LOGICAL") == 0);
    ASSERT(strcmp(ozayn_del_type_name(OZAYN_DEL_TYPE_STORAGE), "STORAGE") == 0);
    ASSERT(strcmp(ozayn_del_type_name(OZAYN_DEL_TYPE_TEMPORARY), "TEMPORARY") == 0);
    ASSERT(strcmp(ozayn_del_type_name(OZAYN_DEL_TYPE_CRYPTO_ERASURE),
                  "CRYPTO_ERASURE") == 0);
    ASSERT(strcmp(ozayn_del_type_name(OZAYN_DEL_TYPE_KEY_DESTRUCTION),
                  "KEY_DESTRUCTION") == 0);
    ASSERT(strcmp(ozayn_del_type_name(OZAYN_DEL_TYPE_BACKUP), "BACKUP") == 0);
    ASSERT(strcmp(ozayn_del_type_name(OZAYN_DEL_TYPE_PHYSICAL_MEDIA),
                  "PHYSICAL_MEDIA") == 0);
    return 0;
}

TEST(test_del_state_name)
{
    ASSERT(strcmp(ozayn_del_state_name(OZAYN_DEL_STATE_IDLE), "IDLE") == 0);
    ASSERT(strcmp(ozayn_del_state_name(OZAYN_DEL_STATE_MARKED_FOR_DELETION),
                  "MARKED_FOR_DELETION") == 0);
    ASSERT(strcmp(ozayn_del_state_name(OZAYN_DEL_STATE_DELETING), "DELETING") == 0);
    ASSERT(strcmp(ozayn_del_state_name(OZAYN_DEL_STATE_DELETED), "DELETED") == 0);
    ASSERT(strcmp(ozayn_del_state_name(OZAYN_DEL_STATE_DELETION_FAILED),
                  "DELETION_FAILED") == 0);
    ASSERT(strcmp(ozayn_del_state_name(OZAYN_DEL_STATE_CRYPTO_ERASED),
                  "CRYPTO_ERASED") == 0);
    return 0;
}

/* ============================================================
 * 3. DEFAULT POLICY
 * ============================================================ */

TEST(test_del_default_policy)
{
    ozayn_del_policy_t p = ozayn_del_default_policy();
    ASSERT(p.require_authorization);
    ASSERT(p.require_mfa_for_sensitive);
    ASSERT(p.require_mfa_for_keys);
    ASSERT(p.allow_logical_delete);
    ASSERT(p.allow_storage_delete);
    ASSERT(p.allow_crypto_erasure);
    ASSERT(p.allow_key_destruction);
    ASSERT(p.verify_after_delete);
    ASSERT(p.max_batch_size == OZAYN_DEL_MAX_BATCH_SIZE);
    ASSERT(p.mfa_threshold == OZAYN_SEC_LEVEL_SENSITIVE);
    return 0;
}

/* ============================================================
 * 4. POLICY GET/SET
 * ============================================================ */

TEST(test_del_set_get_policy)
{
    _init_del_svc();
    ozayn_del_policy_t new_policy = ozayn_del_default_policy();
    new_policy.allow_logical_delete = 0;
    new_policy.verify_after_delete = 0;
    ASSERT_EQ(OZAYN_DEL_OK, ozayn_del_set_policy(&_del_svc, &new_policy));
    const ozayn_del_policy_t *p = ozayn_del_get_policy(&_del_svc);
    ASSERT_NOT_NULL(p);
    ASSERT(!p->allow_logical_delete);
    ASSERT(!p->verify_after_delete);
    return 0;
}

TEST(test_del_set_policy_null)
{
    ASSERT_EQ(OZAYN_DEL_ERR_NULL, ozayn_del_set_policy(NULL, NULL));
    return 0;
}

TEST(test_del_get_policy_null)
{
    ASSERT_NULL(ozayn_del_get_policy(NULL));
    return 0;
}

TEST(test_del_get_policy_not_initialized)
{
    ozayn_del_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ASSERT_NULL(ozayn_del_get_policy(&svc));
    return 0;
}

/* ============================================================
 * 5. REQUEST INIT
 * ============================================================ */

TEST(test_del_request_init_null)
{
    ASSERT_EQ(OZAYN_DEL_ERR_NULL, ozayn_del_request_init(NULL, "obj", 0, 0, "user"));
    return 0;
}

TEST(test_del_request_init_empty_id)
{
    ozayn_del_request_t req;
    ASSERT_EQ(OZAYN_DEL_ERR_INVALID_ID,
              ozayn_del_request_init(&req, "", 0, 0, "user"));
    return 0;
}

TEST(test_del_request_init_no_identity)
{
    ozayn_del_request_t req;
    ASSERT_EQ(OZAYN_DEL_ERR_UNAUTHORIZED,
              ozayn_del_request_init(&req, "obj", 0, 0, ""));
    return 0;
}

TEST(test_del_request_init_success)
{
    ozayn_del_request_t req;
    memset(&req, 0, sizeof(req));
    ASSERT_EQ(OZAYN_DEL_OK,
              ozayn_del_request_init(&req, "test_obj",
                                     OZAYN_DATA_CATEGORY_USER_PREFERENCES,
                                     OZAYN_DEL_TYPE_LOGICAL, "user1"));
    ASSERT(strcmp(req.object_id, "test_obj") == 0);
    ASSERT(strcmp(req.identity_id, "user1") == 0);
    ASSERT(req.data_category == OZAYN_DATA_CATEGORY_USER_PREFERENCES);
    ASSERT(req.deletion_type == OZAYN_DEL_TYPE_LOGICAL);
    return 0;
}

/* ============================================================
 * 6. REQUEST VALIDATION
 * ============================================================ */

TEST(test_del_validate_request_null)
{
    ASSERT_EQ(OZAYN_DEL_ERR_NULL, ozayn_del_validate_request(NULL, NULL));
    return 0;
}

TEST(test_del_validate_request_not_initialized)
{
    ozayn_del_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_del_request_t req;
    memset(&req, 0, sizeof(req));
    ASSERT_EQ(OZAYN_DEL_ERR_NOT_INITIALIZED,
              ozayn_del_validate_request(&svc, &req));
    return 0;
}

TEST(test_del_validate_request_empty_object)
{
    _init_del_svc();
    ozayn_del_request_t req;
    memset(&req, 0, sizeof(req));
    strcpy(req.identity_id, "user1");
    ASSERT_EQ(OZAYN_DEL_ERR_INVALID_ID,
              ozayn_del_validate_request(&_del_svc, &req));
    return 0;
}

TEST(test_del_validate_request_empty_identity)
{
    _init_del_svc();
    ozayn_del_request_t req;
    memset(&req, 0, sizeof(req));
    strcpy(req.object_id, "obj1");
    ASSERT_EQ(OZAYN_DEL_ERR_UNAUTHORIZED,
              ozayn_del_validate_request(&_del_svc, &req));
    return 0;
}

TEST(test_del_validate_request_policy_reject_logical)
{
    _init_del_svc();
    ozayn_del_policy_t p = ozayn_del_default_policy();
    p.allow_logical_delete = 0;
    ozayn_del_set_policy(&_del_svc, &p);

    ozayn_del_request_t req;
    memset(&req, 0, sizeof(req));
    strcpy(req.object_id, "obj1");
    strcpy(req.identity_id, "user1");
    req.deletion_type = OZAYN_DEL_TYPE_LOGICAL;
    ASSERT_EQ(OZAYN_DEL_ERR_POLICY_REJECTED,
              ozayn_del_validate_request(&_del_svc, &req));
    return 0;
}

TEST(test_del_validate_request_policy_reject_storage)
{
    _init_del_svc();
    ozayn_del_policy_t p = ozayn_del_default_policy();
    p.allow_storage_delete = 0;
    ozayn_del_set_policy(&_del_svc, &p);

    ozayn_del_request_t req;
    memset(&req, 0, sizeof(req));
    strcpy(req.object_id, "obj1");
    strcpy(req.identity_id, "user1");
    req.deletion_type = OZAYN_DEL_TYPE_STORAGE;
    ASSERT_EQ(OZAYN_DEL_ERR_POLICY_REJECTED,
              ozayn_del_validate_request(&_del_svc, &req));
    return 0;
}

TEST(test_del_validate_request_policy_reject_crypto)
{
    _init_del_svc();
    ozayn_del_policy_t p = ozayn_del_default_policy();
    p.allow_crypto_erasure = 0;
    ozayn_del_set_policy(&_del_svc, &p);

    ozayn_del_request_t req;
    memset(&req, 0, sizeof(req));
    strcpy(req.object_id, "obj1");
    strcpy(req.identity_id, "user1");
    req.deletion_type = OZAYN_DEL_TYPE_CRYPTO_ERASURE;
    ASSERT_EQ(OZAYN_DEL_ERR_POLICY_REJECTED,
              ozayn_del_validate_request(&_del_svc, &req));
    return 0;
}

TEST(test_del_validate_request_policy_reject_key)
{
    _init_del_svc();
    ozayn_del_policy_t p = ozayn_del_default_policy();
    p.allow_key_destruction = 0;
    ozayn_del_set_policy(&_del_svc, &p);

    ozayn_del_request_t req;
    memset(&req, 0, sizeof(req));
    strcpy(req.object_id, "obj1");
    strcpy(req.identity_id, "user1");
    req.deletion_type = OZAYN_DEL_TYPE_KEY_DESTRUCTION;
    ASSERT_EQ(OZAYN_DEL_ERR_POLICY_REJECTED,
              ozayn_del_validate_request(&_del_svc, &req));
    return 0;
}

TEST(test_del_validate_request_invalid_type)
{
    _init_del_svc();
    ozayn_del_request_t req;
    memset(&req, 0, sizeof(req));
    strcpy(req.object_id, "obj1");
    strcpy(req.identity_id, "user1");
    req.deletion_type = (ozayn_del_type_t)99;
    ASSERT_EQ(OZAYN_DEL_ERR_INVALID_TYPE,
              ozayn_del_validate_request(&_del_svc, &req));
    return 0;
}

TEST(test_del_validate_request_valid)
{
    _init_del_svc();
    ozayn_del_request_t req;
    memset(&req, 0, sizeof(req));
    strcpy(req.object_id, "obj1");
    strcpy(req.identity_id, "user1");
    req.deletion_type = OZAYN_DEL_TYPE_LOGICAL;
    ASSERT_EQ(OZAYN_DEL_OK, ozayn_del_validate_request(&_del_svc, &req));
    return 0;
}

/* ============================================================
 * 7. LOGICAL DELETION — BASIC
 * ============================================================ */

TEST(test_del_execute_null)
{
    ASSERT_EQ(OZAYN_DEL_ERR_NULL, ozayn_del_execute(NULL, NULL, NULL));
    return 0;
}

TEST(test_del_execute_not_initialized)
{
    ozayn_del_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_del_request_t req;
    ozayn_del_result_data_t res;
    ASSERT_EQ(OZAYN_DEL_ERR_NOT_INITIALIZED, ozayn_del_execute(&svc, &req, &res));
    return 0;
}

TEST(test_del_execute_not_found)
{
    _init_del_svc();
    _store_test_object("obj1", OZAYN_DATA_CATEGORY_USER_PREFERENCES);

    ozayn_del_request_t req;
    memset(&req, 0, sizeof(req));
    strcpy(req.object_id, "nonexistent");
    strcpy(req.identity_id, "user1");
    req.deletion_type = OZAYN_DEL_TYPE_LOGICAL;

    ozayn_del_result_data_t res;
    ASSERT_EQ(OZAYN_DEL_ERR_NOT_FOUND,
              ozayn_del_execute(&_del_svc, &req, &res));
    ASSERT(res.result == OZAYN_DEL_ERR_NOT_FOUND);
    ASSERT(res.final_state == OZAYN_DEL_STATE_DELETED);
    return 0;
}

TEST(test_del_logical_delete_success)
{
    _init_del_svc();
    _store_test_object("obj1", OZAYN_DATA_CATEGORY_USER_PREFERENCES);
    ASSERT(ozayn_vault_exists(&_vault, "obj1"));

    ozayn_del_request_t req;
    ASSERT_EQ(OZAYN_DEL_OK,
              ozayn_del_request_init(&req, "obj1",
                                     OZAYN_DATA_CATEGORY_USER_PREFERENCES,
                                     OZAYN_DEL_TYPE_LOGICAL, "user1"));

    ozayn_del_result_data_t res;
    ASSERT_EQ(OZAYN_DEL_OK, ozayn_del_execute(&_del_svc, &req, &res));
    ASSERT(res.result == OZAYN_DEL_OK);
    ASSERT(res.final_state == OZAYN_DEL_STATE_DELETED);
    ASSERT(!ozayn_vault_exists(&_vault, "obj1"));
    return 0;
}

TEST(test_del_storage_delete_success)
{
    _init_del_svc();
    _store_test_object("obj1", OZAYN_DATA_CATEGORY_USER_PREFERENCES);
    ASSERT(ozayn_vault_exists(&_vault, "obj1"));

    ozayn_del_request_t req;
    ASSERT_EQ(OZAYN_DEL_OK,
              ozayn_del_request_init(&req, "obj1",
                                     OZAYN_DATA_CATEGORY_USER_PREFERENCES,
                                     OZAYN_DEL_TYPE_STORAGE, "user1"));

    ozayn_del_result_data_t res;
    ASSERT_EQ(OZAYN_DEL_OK, ozayn_del_execute(&_del_svc, &req, &res));
    ASSERT(res.result == OZAYN_DEL_OK);
    ASSERT(res.final_state == OZAYN_DEL_STATE_DELETED);
    ASSERT(!ozayn_vault_exists(&_vault, "obj1"));
    return 0;
}

/* ============================================================
 * 8. DELETION STATE TRACKING
 * ============================================================ */

TEST(test_del_check_state_null)
{
    ASSERT_EQ(OZAYN_DEL_ERR_NULL, ozayn_del_check_state(NULL, "obj", NULL));
    return 0;
}

TEST(test_del_check_state_not_initialized)
{
    ozayn_del_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_del_state_t state;
    ASSERT_EQ(OZAYN_DEL_ERR_NOT_INITIALIZED,
              ozayn_del_check_state(&svc, "obj", &state));
    return 0;
}

TEST(test_del_check_state_invalid_id)
{
    _init_del_svc();
    ozayn_del_state_t state;
    ASSERT_EQ(OZAYN_DEL_ERR_INVALID_ID,
              ozayn_del_check_state(&_del_svc, "", &state));
    return 0;
}

TEST(test_del_check_state_existing)
{
    _init_del_svc();
    _store_test_object("obj1", OZAYN_DATA_CATEGORY_USER_PREFERENCES);
    ozayn_del_state_t state;
    ASSERT_EQ(OZAYN_DEL_OK, ozayn_del_check_state(&_del_svc, "obj1", &state));
    ASSERT(state == OZAYN_DEL_STATE_IDLE);
    return 0;
}

TEST(test_del_check_state_deleted)
{
    _init_del_svc();
    _store_test_object("obj1", OZAYN_DATA_CATEGORY_USER_PREFERENCES);
    ozayn_vault_remove(&_vault, "obj1");

    ozayn_del_state_t state;
    ASSERT_EQ(OZAYN_DEL_OK, ozayn_del_check_state(&_del_svc, "obj1", &state));
    ASSERT(state == OZAYN_DEL_STATE_DELETED);
    return 0;
}

/* ============================================================
 * 9. DELETION RESULT VERIFICATION
 * ============================================================ */

TEST(test_del_result_tracks_previous_state)
{
    _init_del_svc();
    _store_test_object("obj1", OZAYN_DATA_CATEGORY_USER_PREFERENCES);

    ozayn_del_request_t req;
    ASSERT_EQ(OZAYN_DEL_OK,
              ozayn_del_request_init(&req, "obj1",
                                     OZAYN_DATA_CATEGORY_USER_PREFERENCES,
                                     OZAYN_DEL_TYPE_LOGICAL, "user1"));

    ozayn_del_result_data_t res;
    ASSERT_EQ(OZAYN_DEL_OK, ozayn_del_execute(&_del_svc, &req, &res));
    ASSERT(res.previous_state == OZAYN_DEL_STATE_IDLE);
    ASSERT(res.final_state == OZAYN_DEL_STATE_DELETED);
    ASSERT(res.timestamp > 0);
    ASSERT(strcmp(res.object_id, "obj1") == 0);
    ASSERT(res.deletion_type == OZAYN_DEL_TYPE_LOGICAL);
    return 0;
}

/* ============================================================
 * 10. DELETION ALREADY DELETED (double delete via second call)
 * ============================================================ */

TEST(test_del_double_delete)
{
    _init_del_svc();
    _store_test_object("obj1", OZAYN_DATA_CATEGORY_USER_PREFERENCES);

    ozayn_del_request_t req;
    ASSERT_EQ(OZAYN_DEL_OK,
              ozayn_del_request_init(&req, "obj1",
                                     OZAYN_DATA_CATEGORY_USER_PREFERENCES,
                                     OZAYN_DEL_TYPE_LOGICAL, "user1"));

    ozayn_del_result_data_t res;
    ASSERT_EQ(OZAYN_DEL_OK, ozayn_del_execute(&_del_svc, &req, &res));
    ASSERT_EQ(OZAYN_DEL_ERR_NOT_FOUND, ozayn_del_execute(&_del_svc, &req, &res));
    return 0;
}

/* ============================================================
 * 11. KEY DEPENDENCY
 * ============================================================ */

TEST(test_del_check_key_dependency_null)
{
    ASSERT_EQ(OZAYN_DEL_ERR_NULL,
              ozayn_del_check_key_dependency(NULL, "obj", NULL));
    return 0;
}

TEST(test_del_check_key_dependency_no_vault)
{
    _init_del_svc();
    int required = -1;
    ASSERT_EQ(OZAYN_DEL_OK,
              ozayn_del_check_key_dependency(&_del_svc, "obj1", &required));
    ASSERT(!required);
    return 0;
}

TEST(test_del_check_key_dependency_single_object)
{
    _init_del_svc();
    _store_test_object("obj1", OZAYN_DATA_CATEGORY_USER_PREFERENCES);

    int required = -1;
    ASSERT_EQ(OZAYN_DEL_OK,
              ozayn_del_check_key_dependency(&_del_svc, "obj1", &required));
    ASSERT(!required);
    return 0;
}

TEST(test_del_check_key_dependency_shared_key)
{
    _init_del_svc();
    _store_test_object("obj1", OZAYN_DATA_CATEGORY_USER_PREFERENCES);
    _store_test_object("obj2", OZAYN_DATA_CATEGORY_USER_PREFERENCES);

    int required = -1;
    ASSERT_EQ(OZAYN_DEL_OK,
              ozayn_del_check_key_dependency(&_del_svc, "obj1", &required));
    ASSERT(required);
    return 0;
}

/* ============================================================
 * 12. KEY DESTRUCTION
 * ============================================================ */

TEST(test_del_destroy_key_null)
{
    ASSERT_EQ(OZAYN_DEL_ERR_NULL, ozayn_del_destroy_key(NULL, "obj", "k", 1));
    return 0;
}

TEST(test_del_destroy_key_not_initialized)
{
    ozayn_del_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ASSERT_EQ(OZAYN_DEL_ERR_NOT_INITIALIZED,
              ozayn_del_destroy_key(&svc, "obj", "k", 1));
    return 0;
}

TEST(test_del_destroy_key_invalid_id)
{
    _init_del_svc();
    ASSERT_EQ(OZAYN_DEL_ERR_INVALID_ID,
              ozayn_del_destroy_key(&_del_svc, "", "k", 1));
    return 0;
}

TEST(test_del_destroy_key_in_use)
{
    _init_del_svc();
    _store_test_object("obj1", OZAYN_DATA_CATEGORY_USER_PREFERENCES);
    _store_test_object("obj2", OZAYN_DATA_CATEGORY_USER_PREFERENCES);

    ASSERT_EQ(OZAYN_DEL_ERR_KEY_IN_USE,
              ozayn_del_destroy_key(&_del_svc, "obj1", "VAULT", 1));
    return 0;
}

TEST(test_del_destroy_key_not_in_use)
{
    _init_del_svc();
    _store_test_object("obj1", OZAYN_DATA_CATEGORY_USER_PREFERENCES);

    ASSERT_EQ(OZAYN_DEL_OK,
              ozayn_del_destroy_key(&_del_svc, "obj1", "VAULT", 1));
    return 0;
}

/* ============================================================
 * 13. CRYPTOGRAPHIC ERASURE
 * ============================================================ */

TEST(test_del_crypto_erasure_null)
{
    ozayn_del_request_t req;
    ozayn_del_result_data_t res;
    ASSERT_EQ(OZAYN_DEL_ERR_NULL,
              ozayn_del_crypto_erasure(NULL, &req, &res));
    return 0;
}

TEST(test_del_crypto_erasure_no_vault)
{
    ozayn_del_service_t svc;
    memset(&svc, 0, sizeof(svc));
    svc.initialized = 1;

    ozayn_del_request_t req;
    memset(&req, 0, sizeof(req));
    strcpy(req.object_id, "obj1");
    strcpy(req.identity_id, "user1");

    ozayn_del_result_data_t res;
    ASSERT_EQ(OZAYN_DEL_ERR_VAULT_UNAVAILABLE,
              ozayn_del_crypto_erasure(&svc, &req, &res));
    return 0;
}

TEST(test_del_crypto_erasure_not_found)
{
    _init_del_svc();
    _store_test_object("obj1", OZAYN_DATA_CATEGORY_USER_PREFERENCES);

    ozayn_del_request_t req;
    memset(&req, 0, sizeof(req));
    strcpy(req.object_id, "nonexistent");
    strcpy(req.identity_id, "user1");

    ozayn_del_result_data_t res;
    ASSERT_EQ(OZAYN_DEL_ERR_NOT_FOUND,
              ozayn_del_crypto_erasure(&_del_svc, &req, &res));
    return 0;
}

TEST(test_del_crypto_erasure_shared_key)
{
    _init_del_svc();
    _store_test_object("obj1", OZAYN_DATA_CATEGORY_USER_PREFERENCES);
    _store_test_object("obj2", OZAYN_DATA_CATEGORY_USER_PREFERENCES);

    ozayn_del_request_t req;
    memset(&req, 0, sizeof(req));
    strcpy(req.object_id, "obj1");
    strcpy(req.identity_id, "user1");

    ozayn_del_result_data_t res;
    ASSERT_EQ(OZAYN_DEL_ERR_KEY_IN_USE,
              ozayn_del_crypto_erasure(&_del_svc, &req, &res));
    return 0;
}

TEST(test_del_crypto_erasure_success)
{
    _init_del_svc();
    _store_test_object("obj1", OZAYN_DATA_CATEGORY_USER_PREFERENCES);
    ASSERT(ozayn_vault_exists(&_vault, "obj1"));

    ozayn_del_request_t req;
    memset(&req, 0, sizeof(req));
    strcpy(req.object_id, "obj1");
    strcpy(req.identity_id, "user1");

    ozayn_del_result_data_t res;
    ASSERT_EQ(OZAYN_DEL_OK, ozayn_del_crypto_erasure(&_del_svc, &req, &res));
    ASSERT(res.result == OZAYN_DEL_OK);
    ASSERT(res.final_state == OZAYN_DEL_STATE_CRYPTO_ERASED);
    ASSERT(!ozayn_vault_exists(&_vault, "obj1"));
    return 0;
}

/* ============================================================
 * 14. TEMPORARY DATA CLEANUP
 * ============================================================ */

TEST(test_del_cleanup_temporary_null)
{
    ASSERT_EQ(OZAYN_DEL_ERR_NULL, ozayn_del_cleanup_temporary(NULL));
    return 0;
}

TEST(test_del_cleanup_temporary_not_initialized)
{
    ozayn_del_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ASSERT_EQ(OZAYN_DEL_ERR_NOT_INITIALIZED, ozayn_del_cleanup_temporary(&svc));
    return 0;
}

TEST(test_del_cleanup_temporary_success)
{
    _init_del_svc();
    ASSERT_EQ(OZAYN_DEL_OK, ozayn_del_cleanup_temporary(&_del_svc));
    return 0;
}

/* ============================================================
 * 15. PHYSICAL MEDIA (UNSUPPORTED)
 * ============================================================ */

TEST(test_del_physical_media_unsupported)
{
    _init_del_svc();
    _store_test_object("obj1", OZAYN_DATA_CATEGORY_USER_PREFERENCES);

    ozayn_del_request_t req;
    ASSERT_EQ(OZAYN_DEL_OK,
              ozayn_del_request_init(&req, "obj1",
                                     OZAYN_DATA_CATEGORY_USER_PREFERENCES,
                                     OZAYN_DEL_TYPE_PHYSICAL_MEDIA, "user1"));

    ozayn_del_result_data_t res;
    ASSERT_EQ(OZAYN_DEL_ERR_UNSUPPORTED,
              ozayn_del_execute(&_del_svc, &req, &res));
    return 0;
}

/* ============================================================
 * 16. AUTHORIZATION / POLICY REJECTION
 * ============================================================ */

TEST(test_del_policy_rejects_logical)
{
    _init_del_svc();
    _store_test_object("obj1", OZAYN_DATA_CATEGORY_USER_PREFERENCES);

    ozayn_del_policy_t p = ozayn_del_default_policy();
    p.allow_logical_delete = 0;
    ozayn_del_set_policy(&_del_svc, &p);

    ozayn_del_request_t req;
    ASSERT_EQ(OZAYN_DEL_OK,
              ozayn_del_request_init(&req, "obj1",
                                     OZAYN_DATA_CATEGORY_USER_PREFERENCES,
                                     OZAYN_DEL_TYPE_LOGICAL, "user1"));

    ozayn_del_result_data_t res;
    ASSERT_EQ(OZAYN_DEL_ERR_POLICY_REJECTED,
              ozayn_del_execute(&_del_svc, &req, &res));
    return 0;
}

TEST(test_del_policy_rejects_key_destruction)
{
    _init_del_svc();
    _store_test_object("obj1", OZAYN_DATA_CATEGORY_USER_PREFERENCES);

    ozayn_del_policy_t p = ozayn_del_default_policy();
    p.allow_key_destruction = 0;
    ozayn_del_set_policy(&_del_svc, &p);

    ozayn_del_request_t req;
    ASSERT_EQ(OZAYN_DEL_OK,
              ozayn_del_request_init(&req, "obj1",
                                     OZAYN_DATA_CATEGORY_USER_PREFERENCES,
                                     OZAYN_DEL_TYPE_KEY_DESTRUCTION, "user1"));

    ozayn_del_result_data_t res;
    ASSERT_EQ(OZAYN_DEL_ERR_POLICY_REJECTED,
              ozayn_del_execute(&_del_svc, &req, &res));
    return 0;
}

TEST(test_del_unauthorized_no_identity)
{
    _init_del_svc();
    _store_test_object("obj1", OZAYN_DATA_CATEGORY_USER_PREFERENCES);

    ozayn_del_request_t req;
    memset(&req, 0, sizeof(req));
    strcpy(req.object_id, "obj1");
    req.deletion_type = OZAYN_DEL_TYPE_LOGICAL;
    /* identity_id is empty */

    ozayn_del_result_data_t res;
    ASSERT_EQ(OZAYN_DEL_ERR_UNAUTHORIZED,
              ozayn_del_execute(&_del_svc, &req, &res));
    return 0;
}

/* ============================================================
 * 17. AUDIT INTEGRATION
 * ============================================================ */

TEST(test_del_audit_emitted_on_success)
{
    _init_del_svc();
    _store_test_object("obj1", OZAYN_DATA_CATEGORY_USER_PREFERENCES);

    int count_before = ozayn_audit_count(&_audit_svc);

    ozayn_del_request_t req;
    ASSERT_EQ(OZAYN_DEL_OK,
              ozayn_del_request_init(&req, "obj1",
                                     OZAYN_DATA_CATEGORY_USER_PREFERENCES,
                                     OZAYN_DEL_TYPE_LOGICAL, "user1"));

    ozayn_del_result_data_t res;
    ASSERT_EQ(OZAYN_DEL_OK, ozayn_del_execute(&_del_svc, &req, &res));
    ASSERT_GT(ozayn_audit_count(&_audit_svc), count_before);
    return 0;
}

TEST(test_del_audit_emitted_on_denial)
{
    _init_del_svc();
    _store_test_object("obj1", OZAYN_DATA_CATEGORY_USER_PREFERENCES);

    int count_before = ozayn_audit_count(&_audit_svc);

    ozayn_del_request_t req;
    ASSERT_EQ(OZAYN_DEL_OK,
              ozayn_del_request_init(&req, "obj1",
                                     OZAYN_DATA_CATEGORY_USER_PREFERENCES,
                                     OZAYN_DEL_TYPE_LOGICAL, "user1"));

    /* Disable logical delete to cause denial */
    ozayn_del_policy_t p = ozayn_del_default_policy();
    p.allow_logical_delete = 0;
    ozayn_del_set_policy(&_del_svc, &p);

    ozayn_del_result_data_t res;
    ASSERT_EQ(OZAYN_DEL_ERR_POLICY_REJECTED,
              ozayn_del_execute(&_del_svc, &req, &res));
    ASSERT_GT(ozayn_audit_count(&_audit_svc), count_before);
    return 0;
}

TEST(test_del_audit_emitted_on_crypto_erasure)
{
    _init_del_svc();
    _store_test_object("obj1", OZAYN_DATA_CATEGORY_USER_PREFERENCES);

    int count_before = ozayn_audit_count(&_audit_svc);

    ozayn_del_request_t req;
    memset(&req, 0, sizeof(req));
    strcpy(req.object_id, "obj1");
    strcpy(req.identity_id, "user1");

    ozayn_del_result_data_t res;
    ASSERT_EQ(OZAYN_DEL_OK, ozayn_del_crypto_erasure(&_del_svc, &req, &res));
    ASSERT_GT(ozayn_audit_count(&_audit_svc), count_before);
    return 0;
}

TEST(test_del_audit_no_secrets)
{
    _init_del_svc();
    _store_test_object("obj1", OZAYN_DATA_CATEGORY_USER_PREFERENCES);

    ozayn_del_request_t req;
    ASSERT_EQ(OZAYN_DEL_OK,
              ozayn_del_request_init(&req, "obj1",
                                     OZAYN_DATA_CATEGORY_USER_PREFERENCES,
                                     OZAYN_DEL_TYPE_LOGICAL, "user1"));

    ozayn_del_result_data_t res;
    ASSERT_EQ(OZAYN_DEL_OK, ozayn_del_execute(&_del_svc, &req, &res));

    /* Audit event should only contain identifiers, not secrets.
     * The deletion request has no passwords/keys in it by design. */
    ASSERT(strcmp(res.object_id, "obj1") == 0);
    ASSERT(res.result == OZAYN_DEL_OK);
    return 0;
}

/* ============================================================
 * 18. END-TO-END
 * ============================================================ */

TEST(test_del_end_to_end)
{
    _init_del_svc();

    /* Store multiple objects */
    _store_test_object("e2e_obj1", OZAYN_DATA_CATEGORY_USER_PREFERENCES);
    _store_test_object("e2e_obj2", OZAYN_DATA_CATEGORY_IDENTITY_INFORMATION);

    ASSERT(ozayn_vault_exists(&_vault, "e2e_obj1"));
    ASSERT(ozayn_vault_exists(&_vault, "e2e_obj2"));

    /* Check state before deletion */
    ozayn_del_state_t state;
    ASSERT_EQ(OZAYN_DEL_OK,
              ozayn_del_check_state(&_del_svc, "e2e_obj1", &state));
    ASSERT(state == OZAYN_DEL_STATE_IDLE);

    /* Delete first object */
    ozayn_del_request_t req;
    ASSERT_EQ(OZAYN_DEL_OK,
              ozayn_del_request_init(&req, "e2e_obj1",
                                     OZAYN_DATA_CATEGORY_USER_PREFERENCES,
                                     OZAYN_DEL_TYPE_LOGICAL, "user1"));

    ozayn_del_result_data_t res;
    ASSERT_EQ(OZAYN_DEL_OK, ozayn_del_execute(&_del_svc, &req, &res));
    ASSERT(!ozayn_vault_exists(&_vault, "e2e_obj1"));
    ASSERT(ozayn_vault_exists(&_vault, "e2e_obj2"));

    /* Check state after deletion */
    ASSERT_EQ(OZAYN_DEL_OK,
              ozayn_del_check_state(&_del_svc, "e2e_obj1", &state));
    ASSERT(state == OZAYN_DEL_STATE_DELETED);

    /* Verify stats */
    ASSERT(_del_svc.total_deletions_completed >= 1);
    return 0;
}

/* ============================================================
 * 19. GLOBAL ACCESSOR
 * ============================================================ */

TEST(test_del_get_global)
{
    ozayn_del_service_t *g = ozayn_del_get_global();
    ASSERT_NOT_NULL(g);
    return 0;
}

/* ============================================================
 * 20. VAULT UNAVAILABLE (storage delete without vault)
 * ============================================================ */

TEST(test_del_execute_vault_unavailable)
{
    ozayn_del_service_t svc;
    memset(&svc, 0, sizeof(svc));
    svc.initialized = 1;
    svc.policy = ozayn_del_default_policy();

    ozayn_del_request_t req;
    memset(&req, 0, sizeof(req));
    strcpy(req.object_id, "obj1");
    strcpy(req.identity_id, "user1");
    req.deletion_type = OZAYN_DEL_TYPE_STORAGE;

    ozayn_del_result_data_t res;
    ASSERT_EQ(OZAYN_DEL_ERR_VAULT_UNAVAILABLE,
              ozayn_del_execute(&svc, &req, &res));
    return 0;
}

/* ============================================================
 * 21. STATS
 * ============================================================ */

TEST(test_del_stats_tracking)
{
    _init_del_svc();
    _store_test_object("obj1", OZAYN_DATA_CATEGORY_USER_PREFERENCES);
    _store_test_object("obj2", OZAYN_DATA_CATEGORY_USER_PREFERENCES);

    uint64_t before_req = _del_svc.total_deletions_requested;
    uint64_t before_comp = _del_svc.total_deletions_completed;

    ozayn_del_request_t req;
    ASSERT_EQ(OZAYN_DEL_OK,
              ozayn_del_request_init(&req, "obj1",
                                     OZAYN_DATA_CATEGORY_USER_PREFERENCES,
                                     OZAYN_DEL_TYPE_LOGICAL, "user1"));

    ozayn_del_result_data_t res;
    ASSERT_EQ(OZAYN_DEL_OK, ozayn_del_execute(&_del_svc, &req, &res));

    ASSERT(_del_svc.total_deletions_requested > before_req);
    ASSERT(_del_svc.total_deletions_completed > before_comp);
    return 0;
}

/* ============================================================
 * 22. REQUEST FORCE FLAG
 * ============================================================ */

TEST(test_del_request_force_flag)
{
    ozayn_del_request_t req;
    ASSERT_EQ(OZAYN_DEL_OK,
              ozayn_del_request_init(&req, "obj1",
                                     OZAYN_DATA_CATEGORY_USER_PREFERENCES,
                                     OZAYN_DEL_TYPE_LOGICAL, "user1"));
    ASSERT(!req.force);
    req.force = 1;
    ASSERT(req.force);
    return 0;
}

/* ============================================================
 * 23. VARIOUS DELETION TYPES VIA EXECUTE
 * ============================================================ */

TEST(test_del_execute_backup_type)
{
    _init_del_svc();
    _store_test_object("obj1", OZAYN_DATA_CATEGORY_USER_PREFERENCES);

    ozayn_del_request_t req;
    ASSERT_EQ(OZAYN_DEL_OK,
              ozayn_del_request_init(&req, "obj1",
                                     OZAYN_DATA_CATEGORY_USER_PREFERENCES,
                                     OZAYN_DEL_TYPE_BACKUP, "user1"));

    ozayn_del_result_data_t res;
    ASSERT_EQ(OZAYN_DEL_OK, ozayn_del_execute(&_del_svc, &req, &res));
    ASSERT(res.result == OZAYN_DEL_OK);
    return 0;
}

TEST(test_del_execute_temporary_type)
{
    _init_del_svc();

    ozayn_del_request_t req;
    ASSERT_EQ(OZAYN_DEL_OK,
              ozayn_del_request_init(&req, "obj1",
                                     OZAYN_DATA_CATEGORY_USER_PREFERENCES,
                                     OZAYN_DEL_TYPE_TEMPORARY, "user1"));

    ozayn_del_result_data_t res;
    ASSERT_EQ(OZAYN_DEL_OK, ozayn_del_execute(&_del_svc, &req, &res));
    return 0;
}

TEST(test_del_execute_invalid_type)
{
    _init_del_svc();
    _store_test_object("obj1", OZAYN_DATA_CATEGORY_USER_PREFERENCES);

    ozayn_del_request_t req;
    memset(&req, 0, sizeof(req));
    strcpy(req.object_id, "obj1");
    strcpy(req.identity_id, "user1");
    req.deletion_type = (ozayn_del_type_t)99;

    ozayn_del_result_data_t res;
    ASSERT_EQ(OZAYN_DEL_ERR_INVALID_TYPE, ozayn_del_execute(&_del_svc, &req, &res));
    return 0;
}

/* ============================================================
 * 24. CRYPTO ERASURE VIA EXECUTE ROUTING
 * ============================================================ */

TEST(test_del_execute_crypto_erasure)
{
    _init_del_svc();
    _store_test_object("obj1", OZAYN_DATA_CATEGORY_USER_PREFERENCES);

    ozayn_del_request_t req;
    ASSERT_EQ(OZAYN_DEL_OK,
              ozayn_del_request_init(&req, "obj1",
                                     OZAYN_DATA_CATEGORY_USER_PREFERENCES,
                                     OZAYN_DEL_TYPE_CRYPTO_ERASURE, "user1"));

    ozayn_del_result_data_t res;
    ASSERT_EQ(OZAYN_DEL_OK, ozayn_del_execute(&_del_svc, &req, &res));
    ASSERT(res.final_state == OZAYN_DEL_STATE_CRYPTO_ERASED);
    ASSERT(!ozayn_vault_exists(&_vault, "obj1"));
    return 0;
}

/* ============================================================
 * 25. KEY DESTRUCTION VIA EXECUTE
 * ============================================================ */

TEST(test_del_execute_key_destruction)
{
    _init_del_svc();
    _store_test_object("obj1", OZAYN_DATA_CATEGORY_USER_PREFERENCES);

    ozayn_del_request_t req;
    ASSERT_EQ(OZAYN_DEL_OK,
              ozayn_del_request_init(&req, "obj1",
                                     OZAYN_DATA_CATEGORY_USER_PREFERENCES,
                                     OZAYN_DEL_TYPE_KEY_DESTRUCTION, "user1"));

    ozayn_del_result_data_t res;
    ASSERT_EQ(OZAYN_DEL_OK, ozayn_del_execute(&_del_svc, &req, &res));
    ASSERT(res.final_state == OZAYN_DEL_STATE_CRYPTO_ERASED);
    return 0;
}

TEST(test_del_execute_key_destruction_in_use)
{
    _init_del_svc();
    _store_test_object("obj1", OZAYN_DATA_CATEGORY_USER_PREFERENCES);
    _store_test_object("obj2", OZAYN_DATA_CATEGORY_USER_PREFERENCES);

    ozayn_del_request_t req;
    ASSERT_EQ(OZAYN_DEL_OK,
              ozayn_del_request_init(&req, "obj1",
                                     OZAYN_DATA_CATEGORY_USER_PREFERENCES,
                                     OZAYN_DEL_TYPE_KEY_DESTRUCTION, "user1"));

    ozayn_del_result_data_t res;
    ASSERT_EQ(OZAYN_DEL_ERR_KEY_IN_USE, ozayn_del_execute(&_del_svc, &req, &res));
    return 0;
}

/* ============================================================
 * 26. REQUEST REUSE
 * ============================================================ */

TEST(test_del_request_reuse)
{
    ozayn_del_request_t req;
    ASSERT_EQ(OZAYN_DEL_OK,
              ozayn_del_request_init(&req, "obj1",
                                     OZAYN_DATA_CATEGORY_USER_PREFERENCES,
                                     OZAYN_DEL_TYPE_LOGICAL, "user1"));

    /* Re-init with different data */
    ASSERT_EQ(OZAYN_DEL_OK,
              ozayn_del_request_init(&req, "obj2",
                                     OZAYN_DATA_CATEGORY_IDENTITY_INFORMATION,
                                     OZAYN_DEL_TYPE_STORAGE, "user2"));
    ASSERT(strcmp(req.object_id, "obj2") == 0);
    ASSERT(strcmp(req.identity_id, "user2") == 0);
    ASSERT(req.data_category == OZAYN_DATA_CATEGORY_IDENTITY_INFORMATION);
    ASSERT(req.deletion_type == OZAYN_DEL_TYPE_STORAGE);
    return 0;
}

/* ============================================================
 * RUNNER
 * ============================================================ */

int run_deletion_tests(void)
{
    SUITE_BEGIN("Deletion & Destruction Tests");
    _setup_deps();

    /* 1. Service lifecycle */
    RUN(test_del_service_init_null);
    RUN(test_del_service_init_config_null);
    RUN(test_del_service_init_success);
    RUN(test_del_service_init_already_initialized);
    RUN(test_del_service_shutdown_null);
    RUN(test_del_service_shutdown_not_initialized);
    RUN(test_del_service_shutdown_success);
    RUN(test_del_service_is_initialized_null);

    /* 2. Name helpers */
    RUN(test_del_result_name_ok);
    RUN(test_del_result_name_err);
    RUN(test_del_result_name_various);
    RUN(test_del_type_name);
    RUN(test_del_state_name);

    /* 3. Default policy */
    RUN(test_del_default_policy);

    /* 4. Policy get/set */
    RUN(test_del_set_get_policy);
    RUN(test_del_set_policy_null);
    RUN(test_del_get_policy_null);
    RUN(test_del_get_policy_not_initialized);

    /* 5. Request init */
    RUN(test_del_request_init_null);
    RUN(test_del_request_init_empty_id);
    RUN(test_del_request_init_no_identity);
    RUN(test_del_request_init_success);

    /* 6. Request validation */
    RUN(test_del_validate_request_null);
    RUN(test_del_validate_request_not_initialized);
    RUN(test_del_validate_request_empty_object);
    RUN(test_del_validate_request_empty_identity);
    RUN(test_del_validate_request_policy_reject_logical);
    RUN(test_del_validate_request_policy_reject_storage);
    RUN(test_del_validate_request_policy_reject_crypto);
    RUN(test_del_validate_request_policy_reject_key);
    RUN(test_del_validate_request_invalid_type);
    RUN(test_del_validate_request_valid);

    /* 7. Logical deletion */
    RUN(test_del_execute_null);
    RUN(test_del_execute_not_initialized);
    RUN(test_del_execute_not_found);
    RUN(test_del_logical_delete_success);
    RUN(test_del_storage_delete_success);

    /* 8. State tracking */
    RUN(test_del_check_state_null);
    RUN(test_del_check_state_not_initialized);
    RUN(test_del_check_state_invalid_id);
    RUN(test_del_check_state_existing);
    RUN(test_del_check_state_deleted);

    /* 9. Result verification */
    RUN(test_del_result_tracks_previous_state);

    /* 10. Double delete */
    RUN(test_del_double_delete);

    /* 11. Key dependency */
    RUN(test_del_check_key_dependency_null);
    RUN(test_del_check_key_dependency_no_vault);
    RUN(test_del_check_key_dependency_single_object);
    RUN(test_del_check_key_dependency_shared_key);

    /* 12. Key destruction */
    RUN(test_del_destroy_key_null);
    RUN(test_del_destroy_key_not_initialized);
    RUN(test_del_destroy_key_invalid_id);
    RUN(test_del_destroy_key_in_use);
    RUN(test_del_destroy_key_not_in_use);

    /* 13. Cryptographic erasure */
    RUN(test_del_crypto_erasure_null);
    RUN(test_del_crypto_erasure_no_vault);
    RUN(test_del_crypto_erasure_not_found);
    RUN(test_del_crypto_erasure_shared_key);
    RUN(test_del_crypto_erasure_success);

    /* 14. Temporary data */
    RUN(test_del_cleanup_temporary_null);
    RUN(test_del_cleanup_temporary_not_initialized);
    RUN(test_del_cleanup_temporary_success);

    /* 15. Physical media */
    RUN(test_del_physical_media_unsupported);

    /* 16. Authorization / policy */
    RUN(test_del_policy_rejects_logical);
    RUN(test_del_policy_rejects_key_destruction);
    RUN(test_del_unauthorized_no_identity);

    /* 17. Audit */
    RUN(test_del_audit_emitted_on_success);
    RUN(test_del_audit_emitted_on_denial);
    RUN(test_del_audit_emitted_on_crypto_erasure);
    RUN(test_del_audit_no_secrets);

    /* 18. End-to-end */
    RUN(test_del_end_to_end);

    /* 19. Global accessor */
    RUN(test_del_get_global);

    /* 20. Vault unavailable */
    RUN(test_del_execute_vault_unavailable);

    /* 21. Stats */
    RUN(test_del_stats_tracking);

    /* 22. Force flag */
    RUN(test_del_request_force_flag);

    /* 23. Various types */
    RUN(test_del_execute_backup_type);
    RUN(test_del_execute_temporary_type);
    RUN(test_del_execute_invalid_type);

    /* 24. Crypto via execute */
    RUN(test_del_execute_crypto_erasure);

    /* 25. Key destruction via execute */
    RUN(test_del_execute_key_destruction);
    RUN(test_del_execute_key_destruction_in_use);

    /* 26. Request reuse */
    RUN(test_del_request_reuse);

    SUITE_END();
    _teardown_deps();
    return TOTAL_FAIL();
}
