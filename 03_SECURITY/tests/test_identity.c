#include "../../tests/test_framework.h"
#include "../identity.h"
#include "../protection_provider.h"
#include "../protection_provider_mock.h"
#include "../storage_provider.h"
#include "../storage_provider_mem.h"
#include "../key_lifecycle.h"
#include "../key_provider.h"
#include "../secure_vault.h"
#include <string.h>

/*
 * test_identity.c — Identity Foundation tests (Section 03, Step 12).
 *
 * Tests identity creation, validation, lifecycle transitions,
 * vault integration, and security properties.
 */

/* ---- Test Helpers ---- */
static ozayn_protection_provider_t _prot;
static ozayn_storage_provider_t _stor;
static ozayn_kl_manager_t _kl;
static ozayn_vault_t _vault;
static ozayn_identity_service_t _svc;

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

    ozayn_identity_service_config_t icfg;
    memset(&icfg, 0, sizeof(icfg));
    icfg.vault = &_vault;
    ozayn_id_service_init(&_svc, &icfg);
}

static void _teardown_deps(void)
{
    ozayn_id_service_shutdown(&_svc);
    ozayn_vault_shutdown(&_vault);
    ozayn_kl_shutdown(&_kl);
    ozayn_sp_shutdown(&_stor);
    ozayn_prot_shutdown(&_prot);
}

/* ============================================================
 * INIT/SHUTDOWN TESTS
 * ============================================================ */

int test_id_init_shutdown(void)
{
    _setup_deps();
    ASSERT_EQ(1, ozayn_id_service_is_initialized(&_svc));
    ASSERT_EQ(0, ozayn_id_service_count(&_svc));
    ozayn_id_service_shutdown(&_svc);
    ASSERT_EQ(0, ozayn_id_service_is_initialized(&_svc));
    _teardown_deps();
    return 0;
}

int test_id_init_null(void)
{
    ASSERT_EQ(OZAYN_ID_ERR_NULL, ozayn_id_service_init(NULL, NULL));
    ozayn_identity_service_t svc;
    ASSERT_EQ(OZAYN_ID_ERR_NULL, ozayn_id_service_init(&svc, NULL));
    return 0;
}

int test_id_init_missing_vault(void)
{
    ozayn_identity_service_t svc;
    ozayn_identity_service_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    ASSERT_EQ(OZAYN_ID_ERR_VAULT_UNAVAILABLE, ozayn_id_service_init(&svc, &cfg));
    return 0;
}

int test_id_shutdown_null(void)
{
    ozayn_id_service_shutdown(NULL);
    return 0;
}

/* ============================================================
 * VALIDATION TESTS
 * ============================================================ */

int test_id_validate_type(void)
{
    ASSERT_EQ(0, ozayn_id_validate_type(OZAYN_ID_TYPE_USER));
    ASSERT_EQ(0, ozayn_id_validate_type(OZAYN_ID_TYPE_DEVICE));
    ASSERT_EQ(0, ozayn_id_validate_type(OZAYN_ID_TYPE_SYSTEM));
    ASSERT_EQ(0, ozayn_id_validate_type(OZAYN_ID_TYPE_MODULE));
    ASSERT_EQ(0, ozayn_id_validate_type(OZAYN_ID_TYPE_SERVICE));
    ASSERT_EQ(-1, ozayn_id_validate_type(OZAYN_ID_TYPE_UNKNOWN));
    ASSERT_EQ(-1, ozayn_id_validate_type((ozayn_id_type_t)99));
    return 0;
}

int test_id_validate_state(void)
{
    ASSERT_EQ(0, ozayn_id_validate_state(OZAYN_ID_STATE_ACTIVE));
    ASSERT_EQ(0, ozayn_id_validate_state(OZAYN_ID_STATE_SUSPENDED));
    ASSERT_EQ(0, ozayn_id_validate_state(OZAYN_ID_STATE_REVOKED));
    ASSERT_EQ(0, ozayn_id_validate_state(OZAYN_ID_STATE_ARCHIVED));
    ASSERT_EQ(-1, ozayn_id_validate_state(OZAYN_ID_STATE_UNINITIALIZED));
    ASSERT_EQ(-1, ozayn_id_validate_state((ozayn_id_state_t)99));
    return 0;
}

int test_id_validate_scope(void)
{
    ASSERT_EQ(0, ozayn_id_validate_scope(OZAYN_ID_SCOPE_SYSTEM));
    ASSERT_EQ(0, ozayn_id_validate_scope(OZAYN_ID_SCOPE_USER));
    ASSERT_EQ(0, ozayn_id_validate_scope(OZAYN_ID_SCOPE_DEVICE));
    ASSERT_EQ(0, ozayn_id_validate_scope(OZAYN_ID_SCOPE_MODULE));
    ASSERT_EQ(0, ozayn_id_validate_scope(OZAYN_ID_SCOPE_SERVICE));
    ASSERT_EQ(0, ozayn_id_validate_scope(OZAYN_ID_SCOPE_GLOBAL));
    ASSERT_EQ(-1, ozayn_id_validate_scope(OZAYN_ID_SCOPE_UNKNOWN));
    ASSERT_EQ(-1, ozayn_id_validate_scope((ozayn_id_scope_t)99));
    return 0;
}

int test_id_validate_state_transition(void)
{
    /* Valid transitions */
    ASSERT_EQ(0, ozayn_id_validate_state_transition(
        OZAYN_ID_STATE_UNINITIALIZED, OZAYN_ID_STATE_ACTIVE));
    ASSERT_EQ(0, ozayn_id_validate_state_transition(
        OZAYN_ID_STATE_ACTIVE, OZAYN_ID_STATE_SUSPENDED));
    ASSERT_EQ(0, ozayn_id_validate_state_transition(
        OZAYN_ID_STATE_ACTIVE, OZAYN_ID_STATE_REVOKED));
    ASSERT_EQ(0, ozayn_id_validate_state_transition(
        OZAYN_ID_STATE_SUSPENDED, OZAYN_ID_STATE_ACTIVE));
    ASSERT_EQ(0, ozayn_id_validate_state_transition(
        OZAYN_ID_STATE_SUSPENDED, OZAYN_ID_STATE_REVOKED));
    ASSERT_EQ(0, ozayn_id_validate_state_transition(
        OZAYN_ID_STATE_REVOKED, OZAYN_ID_STATE_ARCHIVED));

    /* Invalid transitions */
    ASSERT_EQ(-1, ozayn_id_validate_state_transition(
        OZAYN_ID_STATE_REVOKED, OZAYN_ID_STATE_ACTIVE));
    ASSERT_EQ(-1, ozayn_id_validate_state_transition(
        OZAYN_ID_STATE_ARCHIVED, OZAYN_ID_STATE_ACTIVE));
    ASSERT_EQ(-1, ozayn_id_validate_state_transition(
        OZAYN_ID_STATE_ACTIVE, OZAYN_ID_STATE_ARCHIVED));
    ASSERT_EQ(-1, ozayn_id_validate_state_transition(
        OZAYN_ID_STATE_UNINITIALIZED, OZAYN_ID_STATE_SUSPENDED));
    return 0;
}

int test_id_validate_object(void)
{
    ozayn_identity_t id;
    memset(&id, 0, sizeof(id));

    /* Empty ID */
    ASSERT_EQ(-1, ozayn_id_validate(&id));

    /* Valid identity */
    strncpy(id.id, "test-id", sizeof(id.id));
    id.version = 1;
    id.type = OZAYN_ID_TYPE_USER;
    id.state = OZAYN_ID_STATE_ACTIVE;
    id.scope = OZAYN_ID_SCOPE_USER;
    strncpy(id.owner, "owner", sizeof(id.owner));
    id.created_at = time(NULL);
    id.modified_at = id.created_at;
    ASSERT_EQ(0, ozayn_id_validate(&id));

    /* Path traversal */
    strncpy(id.id, "../etc/passwd", sizeof(id.id));
    ASSERT_EQ(-1, ozayn_id_validate(&id));

    /* Invalid type */
    strncpy(id.id, "valid-id", sizeof(id.id));
    id.type = OZAYN_ID_TYPE_UNKNOWN;
    ASSERT_EQ(-1, ozayn_id_validate(&id));

    /* Invalid state */
    id.type = OZAYN_ID_TYPE_USER;
    id.state = OZAYN_ID_STATE_UNINITIALIZED;
    ASSERT_EQ(-1, ozayn_id_validate(&id));

    /* Invalid scope */
    id.state = OZAYN_ID_STATE_ACTIVE;
    id.scope = OZAYN_ID_SCOPE_UNKNOWN;
    ASSERT_EQ(-1, ozayn_id_validate(&id));

    /* Empty owner */
    id.scope = OZAYN_ID_SCOPE_USER;
    id.owner[0] = '\0';
    ASSERT_EQ(-1, ozayn_id_validate(&id));

    /* Invalid timestamp */
    strncpy(id.owner, "owner", sizeof(id.owner));
    id.created_at = 0;
    ASSERT_EQ(-1, ozayn_id_validate(&id));

    return 0;
}

/* ============================================================
 * CREATE TESTS
 * ============================================================ */

int test_id_create_user(void)
{
    _setup_deps();
    ozayn_identity_t id;
    ASSERT_EQ(OZAYN_ID_OK, ozayn_id_create(&_svc, OZAYN_ID_TYPE_USER,
                                             "Test User", OZAYN_ID_SCOPE_USER,
                                             "owner", &id));
    ASSERT_STR_EQ("Test User", id.label);
    ASSERT_EQ(OZAYN_ID_TYPE_USER, (int)id.type);
    ASSERT_EQ(OZAYN_ID_STATE_ACTIVE, (int)id.state);
    ASSERT_EQ(OZAYN_ID_SCOPE_USER, (int)id.scope);
    ASSERT_EQ(1, ozayn_id_service_count(&_svc));
    _teardown_deps();
    return 0;
}

int test_id_create_device(void)
{
    _setup_deps();
    ozayn_identity_t id;
    ASSERT_EQ(OZAYN_ID_OK, ozayn_id_create(&_svc, OZAYN_ID_TYPE_DEVICE,
                                             "Test Device", OZAYN_ID_SCOPE_DEVICE,
                                             "owner", &id));
    ASSERT_EQ(OZAYN_ID_TYPE_DEVICE, (int)id.type);
    _teardown_deps();
    return 0;
}

int test_id_create_system(void)
{
    _setup_deps();
    ozayn_identity_t id;
    ASSERT_EQ(OZAYN_ID_OK, ozayn_id_create(&_svc, OZAYN_ID_TYPE_SYSTEM,
                                             "System Core", OZAYN_ID_SCOPE_SYSTEM,
                                             "ozayn", &id));
    ASSERT_EQ(OZAYN_ID_TYPE_SYSTEM, (int)id.type);
    _teardown_deps();
    return 0;
}

int test_id_create_invalid_type(void)
{
    _setup_deps();
    ozayn_identity_t id;
    ASSERT_EQ(OZAYN_ID_ERR_TYPE_INVALID, ozayn_id_create(&_svc,
        OZAYN_ID_TYPE_UNKNOWN, "label", OZAYN_ID_SCOPE_USER,
        "owner", &id));
    _teardown_deps();
    return 0;
}

int test_id_create_invalid_scope(void)
{
    _setup_deps();
    ozayn_identity_t id;
    ASSERT_EQ(OZAYN_ID_ERR_SCOPE_INVALID, ozayn_id_create(&_svc,
        OZAYN_ID_TYPE_USER, "label", OZAYN_ID_SCOPE_UNKNOWN,
        "owner", &id));
    _teardown_deps();
    return 0;
}

int test_id_create_empty_owner(void)
{
    _setup_deps();
    ozayn_identity_t id;
    ASSERT_EQ(OZAYN_ID_ERR_OWNER_INVALID, ozayn_id_create(&_svc,
        OZAYN_ID_TYPE_USER, "label", OZAYN_ID_SCOPE_USER,
        "", &id));
    _teardown_deps();
    return 0;
}

int test_id_create_empty_label(void)
{
    _setup_deps();
    ozayn_identity_t id;
    ASSERT_EQ(OZAYN_ID_ERR_INVALID, ozayn_id_create(&_svc,
        OZAYN_ID_TYPE_USER, "", OZAYN_ID_SCOPE_USER,
        "owner", &id));
    _teardown_deps();
    return 0;
}

int test_id_create_not_initialized(void)
{
    ozayn_identity_t id;
    ASSERT_EQ(OZAYN_ID_ERR_NOT_INITIALIZED, ozayn_id_create(&_svc,
        OZAYN_ID_TYPE_USER, "label", OZAYN_ID_SCOPE_USER,
        "owner", &id));
    return 0;
}

/* ============================================================
 * GET TESTS
 * ============================================================ */

int test_id_get_existing(void)
{
    _setup_deps();
    ozayn_identity_t created, loaded;
    ASSERT_EQ(OZAYN_ID_OK, ozayn_id_create(&_svc, OZAYN_ID_TYPE_USER,
                                             "Test User", OZAYN_ID_SCOPE_USER,
                                             "owner", &created));
    ASSERT_EQ(OZAYN_ID_OK, ozayn_id_get(&_svc, created.id, &loaded));
    ASSERT_STR_EQ(created.id, loaded.id);
    ASSERT_STR_EQ("Test User", loaded.label);
    _teardown_deps();
    return 0;
}

int test_id_get_missing(void)
{
    _setup_deps();
    ozayn_identity_t id;
    ASSERT_EQ(OZAYN_ID_ERR_NOT_FOUND, ozayn_id_get(&_svc, "nonexistent", &id));
    _teardown_deps();
    return 0;
}

int test_id_get_not_initialized(void)
{
    ozayn_identity_t id;
    ASSERT_EQ(OZAYN_ID_ERR_NOT_INITIALIZED, ozayn_id_get(&_svc, "id", &id));
    return 0;
}

/* ============================================================
 * UPDATE TESTS
 * ============================================================ */

int test_id_update_label(void)
{
    _setup_deps();
    ozayn_identity_t created;
    ASSERT_EQ(OZAYN_ID_OK, ozayn_id_create(&_svc, OZAYN_ID_TYPE_USER,
                                             "Original", OZAYN_ID_SCOPE_USER,
                                             "owner", &created));
    ASSERT_EQ(OZAYN_ID_OK, ozayn_id_update(&_svc, created.id,
                                             "Updated", OZAYN_ID_SCOPE_USER));
    ozayn_identity_t loaded;
    ASSERT_EQ(OZAYN_ID_OK, ozayn_id_get(&_svc, created.id, &loaded));
    ASSERT_STR_EQ("Updated", loaded.label);
    _teardown_deps();
    return 0;
}

int test_id_update_scope(void)
{
    _setup_deps();
    ozayn_identity_t created;
    ASSERT_EQ(OZAYN_ID_OK, ozayn_id_create(&_svc, OZAYN_ID_TYPE_USER,
                                             "User", OZAYN_ID_SCOPE_USER,
                                             "owner", &created));
    ASSERT_EQ(OZAYN_ID_OK, ozayn_id_update(&_svc, created.id,
                                             "User", OZAYN_ID_SCOPE_GLOBAL));
    ozayn_identity_t loaded;
    ASSERT_EQ(OZAYN_ID_OK, ozayn_id_get(&_svc, created.id, &loaded));
    ASSERT_EQ(OZAYN_ID_SCOPE_GLOBAL, (int)loaded.scope);
    _teardown_deps();
    return 0;
}

int test_id_update_missing(void)
{
    _setup_deps();
    ASSERT_EQ(OZAYN_ID_ERR_NOT_FOUND, ozayn_id_update(&_svc, "nonexistent",
                                                        "label", OZAYN_ID_SCOPE_USER));
    _teardown_deps();
    return 0;
}

int test_id_update_preserves_id(void)
{
    _setup_deps();
    ozayn_identity_t created;
    ASSERT_EQ(OZAYN_ID_OK, ozayn_id_create(&_svc, OZAYN_ID_TYPE_USER,
                                             "User", OZAYN_ID_SCOPE_USER,
                                             "owner", &created));
    char original_id[OZAYN_ID_MAX_ID_LEN];
    strncpy(original_id, created.id, sizeof(original_id));

    ASSERT_EQ(OZAYN_ID_OK, ozayn_id_update(&_svc, created.id,
                                             "Updated", OZAYN_ID_SCOPE_USER));
    ozayn_identity_t loaded;
    ASSERT_EQ(OZAYN_ID_OK, ozayn_id_get(&_svc, original_id, &loaded));
    ASSERT_STR_EQ(original_id, loaded.id);
    _teardown_deps();
    return 0;
}

/* ============================================================
 * LIFECYCLE TESTS
 * ============================================================ */

int test_id_lifecycle_full(void)
{
    _setup_deps();
    ozayn_identity_t id;
    ASSERT_EQ(OZAYN_ID_OK, ozayn_id_create(&_svc, OZAYN_ID_TYPE_USER,
                                             "User", OZAYN_ID_SCOPE_USER,
                                             "owner", &id));

    /* ACTIVE -> SUSPENDED */
    ASSERT_EQ(OZAYN_ID_OK, ozayn_id_suspend(&_svc, id.id));
    ozayn_identity_t loaded;
    ASSERT_EQ(OZAYN_ID_OK, ozayn_id_get(&_svc, id.id, &loaded));
    ASSERT_EQ(OZAYN_ID_STATE_SUSPENDED, (int)loaded.state);

    /* SUSPENDED -> ACTIVE */
    ASSERT_EQ(OZAYN_ID_OK, ozayn_id_reactivate(&_svc, id.id));
    ASSERT_EQ(OZAYN_ID_OK, ozayn_id_get(&_svc, id.id, &loaded));
    ASSERT_EQ(OZAYN_ID_STATE_ACTIVE, (int)loaded.state);

    /* ACTIVE -> REVOKED */
    ASSERT_EQ(OZAYN_ID_OK, ozayn_id_revoke(&_svc, id.id));
    ASSERT_EQ(OZAYN_ID_OK, ozayn_id_get(&_svc, id.id, &loaded));
    ASSERT_EQ(OZAYN_ID_STATE_REVOKED, (int)loaded.state);

    /* REVOKED -> ARCHIVED */
    ASSERT_EQ(OZAYN_ID_OK, ozayn_id_archive(&_svc, id.id));
    ASSERT_EQ(OZAYN_ID_OK, ozayn_id_get(&_svc, id.id, &loaded));
    ASSERT_EQ(OZAYN_ID_STATE_ARCHIVED, (int)loaded.state);

    _teardown_deps();
    return 0;
}

int test_id_lifecycle_invalid_revoked_to_active(void)
{
    _setup_deps();
    ozayn_identity_t id;
    ASSERT_EQ(OZAYN_ID_OK, ozayn_id_create(&_svc, OZAYN_ID_TYPE_USER,
                                             "User", OZAYN_ID_SCOPE_USER,
                                             "owner", &id));

    /* ACTIVE -> REVOKED */
    ASSERT_EQ(OZAYN_ID_OK, ozayn_id_revoke(&_svc, id.id));

    /* REVOKED -> ACTIVE (invalid) */
    ASSERT_EQ(OZAYN_ID_ERR_STATE_TRANSITION, ozayn_id_reactivate(&_svc, id.id));
    _teardown_deps();
    return 0;
}

int test_id_lifecycle_invalid_archived_to_active(void)
{
    _setup_deps();
    ozayn_identity_t id;
    ASSERT_EQ(OZAYN_ID_OK, ozayn_id_create(&_svc, OZAYN_ID_TYPE_USER,
                                             "User", OZAYN_ID_SCOPE_USER,
                                             "owner", &id));

    /* ACTIVE -> REVOKED -> ARCHIVED */
    ASSERT_EQ(OZAYN_ID_OK, ozayn_id_revoke(&_svc, id.id));
    ASSERT_EQ(OZAYN_ID_OK, ozayn_id_archive(&_svc, id.id));

    /* ARCHIVED -> ACTIVE (invalid) */
    ASSERT_EQ(OZAYN_ID_ERR_STATE_TRANSITION, ozayn_id_reactivate(&_svc, id.id));
    _teardown_deps();
    return 0;
}

/* ============================================================
 * REMOVE TESTS
 * ============================================================ */

int test_id_remove_existing(void)
{
    _setup_deps();
    ozayn_identity_t id;
    ASSERT_EQ(OZAYN_ID_OK, ozayn_id_create(&_svc, OZAYN_ID_TYPE_USER,
                                             "User", OZAYN_ID_SCOPE_USER,
                                             "owner", &id));
    ASSERT_EQ(1, ozayn_id_service_count(&_svc));
    ASSERT_EQ(OZAYN_ID_OK, ozayn_id_remove(&_svc, id.id));
    ASSERT_EQ(0, ozayn_id_service_count(&_svc));
    ASSERT_EQ(0, ozayn_id_exists(&_svc, id.id));
    _teardown_deps();
    return 0;
}

int test_id_remove_missing(void)
{
    _setup_deps();
    ASSERT_EQ(OZAYN_ID_ERR_NOT_FOUND, ozayn_id_remove(&_svc, "nonexistent"));
    _teardown_deps();
    return 0;
}

/* ============================================================
 * EXISTS TESTS
 * ============================================================ */

int test_id_exists(void)
{
    _setup_deps();
    ozayn_identity_t id;
    ASSERT_EQ(0, ozayn_id_exists(&_svc, "test-id"));
    ASSERT_EQ(OZAYN_ID_OK, ozayn_id_create(&_svc, OZAYN_ID_TYPE_USER,
                                             "User", OZAYN_ID_SCOPE_USER,
                                             "owner", &id));
    ASSERT_EQ(1, ozayn_id_exists(&_svc, id.id));
    ASSERT_EQ(OZAYN_ID_OK, ozayn_id_remove(&_svc, id.id));
    ASSERT_EQ(0, ozayn_id_exists(&_svc, id.id));
    _teardown_deps();
    return 0;
}

int test_id_exists_null(void)
{
    ASSERT_EQ(0, ozayn_id_exists(NULL, "id"));
    ASSERT_EQ(0, ozayn_id_exists(&_svc, NULL));
    return 0;
}

/* ============================================================
 * LIST TESTS
 * ============================================================ */

int test_id_list_by_type(void)
{
    _setup_deps();
    ozayn_identity_t id1, id2, id3;
    ASSERT_EQ(OZAYN_ID_OK, ozayn_id_create(&_svc, OZAYN_ID_TYPE_USER,
                                             "User 1", OZAYN_ID_SCOPE_USER,
                                             "owner", &id1));
    ASSERT_EQ(OZAYN_ID_OK, ozayn_id_create(&_svc, OZAYN_ID_TYPE_USER,
                                             "User 2", OZAYN_ID_SCOPE_USER,
                                             "owner", &id2));
    ASSERT_EQ(OZAYN_ID_OK, ozayn_id_create(&_svc, OZAYN_ID_TYPE_DEVICE,
                                             "Device", OZAYN_ID_SCOPE_DEVICE,
                                             "owner", &id3));

    ozayn_identity_t items[10];
    int count = ozayn_id_list(&_svc, OZAYN_ID_TYPE_USER, items, 10);
    ASSERT_EQ(2, count);

    count = ozayn_id_list(&_svc, OZAYN_ID_TYPE_DEVICE, items, 10);
    ASSERT_EQ(1, count);

    count = ozayn_id_list(&_svc, OZAYN_ID_TYPE_SYSTEM, items, 10);
    ASSERT_EQ(0, count);

    _teardown_deps();
    return 0;
}

int test_id_list_empty(void)
{
    _setup_deps();
    ozayn_identity_t items[10];
    int count = ozayn_id_list(&_svc, OZAYN_ID_TYPE_USER, items, 10);
    ASSERT_EQ(0, count);
    _teardown_deps();
    return 0;
}

/* ============================================================
 * VAULT INTEGRATION TESTS
 * ============================================================ */

int test_id_vault_persistence(void)
{
    _setup_deps();
    ozayn_identity_t created;
    ASSERT_EQ(OZAYN_ID_OK, ozayn_id_create(&_svc, OZAYN_ID_TYPE_USER,
                                             "Persistent User", OZAYN_ID_SCOPE_USER,
                                             "owner", &created));

    /* Shutdown service (simulates app restart) */
    ozayn_id_service_shutdown(&_svc);

    /* Re-initialize service */
    ozayn_identity_service_config_t icfg;
    memset(&icfg, 0, sizeof(icfg));
    icfg.vault = &_vault;
    ozayn_id_service_init(&_svc, &icfg);

    /* Identity should be loadable from vault */
    ozayn_secure_data_object_t sdo;
    size_t loaded_len = 0;
    ASSERT_EQ(OZAYN_VAULT_OK, ozayn_vault_load(&_vault, created.id, &sdo,
                                                 NULL, 0, &loaded_len));
    _teardown_deps();
    return 0;
}

/* ============================================================
 * SECURITY TESTS
 * ============================================================ */

int test_id_no_password_stored(void)
{
    _setup_deps();
    ozayn_identity_t id;
    ASSERT_EQ(OZAYN_ID_OK, ozayn_id_create(&_svc, OZAYN_ID_TYPE_USER,
                                             "User", OZAYN_ID_SCOPE_USER,
                                             "owner", &id));

    /* Identity object should not contain password field */
    /* This is enforced by the struct design - no password field exists */
    ASSERT_EQ(0, id.credential_count); /* No credentials stored */
    _teardown_deps();
    return 0;
}

int test_id_no_biometric_stored(void)
{
    _setup_deps();
    ozayn_identity_t id;
    ASSERT_EQ(OZAYN_ID_OK, ozayn_id_create(&_svc, OZAYN_ID_TYPE_USER,
                                             "User", OZAYN_ID_SCOPE_USER,
                                             "owner", &id));

    /* Identity object should not contain biometric data */
    /* This is enforced by the struct design - no biometric fields exist */
    ASSERT_EQ(0, id.credential_count);
    _teardown_deps();
    return 0;
}

/* ============================================================
 * NAME HELPER TESTS
 * ============================================================ */

int test_id_name_helpers(void)
{
    ASSERT_STR_EQ("USER", ozayn_id_type_name(OZAYN_ID_TYPE_USER));
    ASSERT_STR_EQ("DEVICE", ozayn_id_type_name(OZAYN_ID_TYPE_DEVICE));
    ASSERT_STR_EQ("SYSTEM", ozayn_id_type_name(OZAYN_ID_TYPE_SYSTEM));

    ASSERT_STR_EQ("ACTIVE", ozayn_id_state_name(OZAYN_ID_STATE_ACTIVE));
    ASSERT_STR_EQ("SUSPENDED", ozayn_id_state_name(OZAYN_ID_STATE_SUSPENDED));
    ASSERT_STR_EQ("REVOKED", ozayn_id_state_name(OZAYN_ID_STATE_REVOKED));

    ASSERT_STR_EQ("USER", ozayn_id_scope_name(OZAYN_ID_SCOPE_USER));
    ASSERT_STR_EQ("GLOBAL", ozayn_id_scope_name(OZAYN_ID_SCOPE_GLOBAL));

    ASSERT_STR_EQ("OK", ozayn_id_result_name(OZAYN_ID_OK));
    ASSERT_STR_EQ("NOT_FOUND", ozayn_id_result_name(OZAYN_ID_ERR_NOT_FOUND));
    ASSERT_STR_EQ("UNKNOWN", ozayn_id_result_name((ozayn_identity_result_t)999));
    return 0;
}

/* ============================================================
 * NULL SAFETY TESTS
 * ============================================================ */

int test_id_null_safety(void)
{
    ASSERT_EQ(OZAYN_ID_ERR_NULL, ozayn_id_create(NULL, 0, NULL, 0, NULL, NULL));
    ASSERT_EQ(OZAYN_ID_ERR_NULL, ozayn_id_get(NULL, NULL, NULL));
    ASSERT_EQ(OZAYN_ID_ERR_NULL, ozayn_id_update(NULL, NULL, NULL, 0));
    ASSERT_EQ(OZAYN_ID_ERR_NULL, ozayn_id_suspend(NULL, NULL));
    ASSERT_EQ(OZAYN_ID_ERR_NULL, ozayn_id_revoke(NULL, NULL));
    ASSERT_EQ(OZAYN_ID_ERR_NULL, ozayn_id_archive(NULL, NULL));
    ASSERT_EQ(OZAYN_ID_ERR_NULL, ozayn_id_reactivate(NULL, NULL));
    ASSERT_EQ(OZAYN_ID_ERR_NULL, ozayn_id_remove(NULL, NULL));
    ASSERT_EQ(0, ozayn_id_exists(NULL, NULL));
    ASSERT_EQ(0, ozayn_id_list(NULL, 0, NULL, 0));
    ASSERT_EQ(0, ozayn_id_service_count(NULL));
    ASSERT_EQ(0, ozayn_id_service_is_initialized(NULL));
    return 0;
}

/* ============================================================
 * TEST RUNNER
 * ============================================================ */

int run_identity_tests(void)
{
    int failed = 0;
    int total = 0;

    printf("\n  --- IDENTITY TESTS ---\n");

    #define RUN_ID(name) do { total++; printf("    [%d] %s ... ", total, #name); if (name() == 0) { printf("PASS\n"); } else { printf("FAIL\n"); failed++; } } while(0)

    /* Init/Shutdown */
    RUN_ID(test_id_init_shutdown);
    RUN_ID(test_id_init_null);
    RUN_ID(test_id_init_missing_vault);
    RUN_ID(test_id_shutdown_null);

    /* Validation */
    RUN_ID(test_id_validate_type);
    RUN_ID(test_id_validate_state);
    RUN_ID(test_id_validate_scope);
    RUN_ID(test_id_validate_state_transition);
    RUN_ID(test_id_validate_object);

    /* Create */
    RUN_ID(test_id_create_user);
    RUN_ID(test_id_create_device);
    RUN_ID(test_id_create_system);
    RUN_ID(test_id_create_invalid_type);
    RUN_ID(test_id_create_invalid_scope);
    RUN_ID(test_id_create_empty_owner);
    RUN_ID(test_id_create_empty_label);
    RUN_ID(test_id_create_not_initialized);

    /* Get */
    RUN_ID(test_id_get_existing);
    RUN_ID(test_id_get_missing);
    RUN_ID(test_id_get_not_initialized);

    /* Update */
    RUN_ID(test_id_update_label);
    RUN_ID(test_id_update_scope);
    RUN_ID(test_id_update_missing);
    RUN_ID(test_id_update_preserves_id);

    /* Lifecycle */
    RUN_ID(test_id_lifecycle_full);
    RUN_ID(test_id_lifecycle_invalid_revoked_to_active);
    RUN_ID(test_id_lifecycle_invalid_archived_to_active);

    /* Remove */
    RUN_ID(test_id_remove_existing);
    RUN_ID(test_id_remove_missing);

    /* Exists */
    RUN_ID(test_id_exists);
    RUN_ID(test_id_exists_null);

    /* List */
    RUN_ID(test_id_list_by_type);
    RUN_ID(test_id_list_empty);

    /* Vault Integration */
    RUN_ID(test_id_vault_persistence);

    /* Security */
    RUN_ID(test_id_no_password_stored);
    RUN_ID(test_id_no_biometric_stored);

    /* Name Helpers */
    RUN_ID(test_id_name_helpers);

    /* Null Safety */
    RUN_ID(test_id_null_safety);

    #undef RUN_ID

    printf("  IDENTITY: %d/%d passed\n", total - failed, total);
    return failed;
}
