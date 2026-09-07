#include "../../tests/test_framework.h"
#include "../rbac.h"
#include "../identity.h"
#include "../authentication.h"
#include "../protection_provider.h"
#include "../protection_provider_mock.h"
#include "../storage_provider.h"
#include "../storage_provider_mem.h"
#include "../key_lifecycle.h"
#include "../key_provider.h"
#include "../secure_vault.h"
#include <string.h>

/* ============================================================
 * SHARED TEST INFRASTRUCTURE
 * ============================================================ */

static ozayn_protection_provider_t _prot;
static ozayn_storage_provider_t    _stor;
static ozayn_kl_manager_t          _kl;
static ozayn_vault_t               _vault;
static ozayn_identity_service_t    _id_svc;
static ozayn_rbac_service_t        _rbac_svc;

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
    ozayn_id_service_init(&_id_svc, &icfg);
}

static void _teardown_deps(void)
{
    ozayn_rbac_service_shutdown(&_rbac_svc);
    ozayn_id_service_shutdown(&_id_svc);
    ozayn_vault_shutdown(&_vault);
    ozayn_kl_shutdown(&_kl);
    ozayn_sp_shutdown(&_stor);
    ozayn_prot_shutdown(&_prot);
}

static void _init_rbac_svc(void)
{
    ozayn_rbac_service_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.identity_service = &_id_svc;
    ozayn_rbac_service_init(&_rbac_svc, &cfg);
}

static ozayn_identity_t _create_identity(const char *label)
{
    ozayn_identity_t id_out;
    memset(&id_out, 0, sizeof(id_out));
    ozayn_id_create(&_id_svc, OZAYN_ID_TYPE_USER, label,
                     OZAYN_ID_SCOPE_USER, "test", &id_out);
    return id_out;
}

/* ============================================================
 * 1. SERVICE LIFECYCLE
 * ============================================================ */

TEST(test_service_init)
{
    _setup_deps();
    _init_rbac_svc();
    ASSERT(ozayn_rbac_service_is_initialized(&_rbac_svc));
    ASSERT_EQ(0, ozayn_rbac_role_count(&_rbac_svc));
    ASSERT_EQ(0, ozayn_rbac_assignment_count(&_rbac_svc));
    _teardown_deps();
    return 0;
}

TEST(test_service_init_null)
{
    ASSERT_EQ(OZAYN_RBAC_ERR_NULL, ozayn_rbac_service_init(NULL, NULL));
    _setup_deps();
    ozayn_rbac_service_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    ASSERT_EQ(OZAYN_RBAC_ERR_NULL, ozayn_rbac_service_init(NULL, &cfg));
    _teardown_deps();
    return 0;
}

TEST(test_service_init_null_config)
{
    ozayn_rbac_service_t svc;
    ASSERT_EQ(OZAYN_RBAC_ERR_NULL, ozayn_rbac_service_init(&svc, NULL));
    return 0;
}

TEST(test_service_init_no_identity_service)
{
    ozayn_rbac_service_t svc;
    ozayn_rbac_service_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    ASSERT_EQ(OZAYN_RBAC_ERR_INVALID, ozayn_rbac_service_init(&svc, &cfg));
    return 0;
}

TEST(test_service_shutdown)
{
    _setup_deps();
    _init_rbac_svc();
    ozayn_rbac_service_shutdown(&_rbac_svc);
    ASSERT(!ozayn_rbac_service_is_initialized(&_rbac_svc));
    _teardown_deps();
    return 0;
}

TEST(test_service_shutdown_null)
{
    ozayn_rbac_service_shutdown(NULL);
    return 0;
}

/* ============================================================
 * 2. ROLE MANAGEMENT
 * ============================================================ */

TEST(test_role_create)
{
    _setup_deps();
    _init_rbac_svc();
    ozayn_rbac_role_t role;
    ozayn_rbac_error_t r = ozayn_rbac_role_create(&_rbac_svc, "admin",
        "Administrator", "Full access role", OZAYN_AUTHZ_SCOPE_SYSTEM, &role);
    ASSERT_EQ(OZAYN_RBAC_OK, r);
    ASSERT_STR_EQ("admin", role.id);
    ASSERT_STR_EQ("Administrator", role.name);
    ASSERT_EQ(OZAYN_RBAC_ROLE_ACTIVE, role.state);
    ASSERT_EQ(OZAYN_AUTHZ_SCOPE_SYSTEM, role.scope);
    ASSERT_EQ(1, role.version);
    ASSERT_EQ(1, ozayn_rbac_role_count(&_rbac_svc));
    _teardown_deps();
    return 0;
}

TEST(test_role_create_null)
{
    _setup_deps();
    _init_rbac_svc();
    ASSERT_EQ(OZAYN_RBAC_ERR_NULL, ozayn_rbac_role_create(NULL, "a", "A", "D", OZAYN_AUTHZ_SCOPE_SYSTEM, &(ozayn_rbac_role_t){0}));
    ASSERT_EQ(OZAYN_RBAC_ERR_NULL, ozayn_rbac_role_create(&_rbac_svc, NULL, "A", "D", OZAYN_AUTHZ_SCOPE_SYSTEM, &(ozayn_rbac_role_t){0}));
    ASSERT_EQ(OZAYN_RBAC_ERR_NULL, ozayn_rbac_role_create(&_rbac_svc, "a", "A", "D", OZAYN_AUTHZ_SCOPE_SYSTEM, NULL));
    _teardown_deps();
    return 0;
}

TEST(test_role_create_not_initialized)
{
    ozayn_rbac_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_rbac_role_t role;
    ASSERT_EQ(OZAYN_RBAC_ERR_NOT_INITIALIZED,
              ozayn_rbac_role_create(&svc, "admin", "A", "D", OZAYN_AUTHZ_SCOPE_SYSTEM, &role));
    return 0;
}

TEST(test_role_create_invalid_id)
{
    _setup_deps();
    _init_rbac_svc();
    ozayn_rbac_role_t role;
    ASSERT_EQ(OZAYN_RBAC_ERR_ID_INVALID,
              ozayn_rbac_role_create(&_rbac_svc, "", "A", "D", OZAYN_AUTHZ_SCOPE_SYSTEM, &role));
    ASSERT_EQ(OZAYN_RBAC_ERR_ID_INVALID,
              ozayn_rbac_role_create(&_rbac_svc, "admin/user", "A", "D", OZAYN_AUTHZ_SCOPE_SYSTEM, &role));
    ASSERT_EQ(OZAYN_RBAC_ERR_ID_INVALID,
              ozayn_rbac_role_create(&_rbac_svc, "admin user", "A", "D", OZAYN_AUTHZ_SCOPE_SYSTEM, &role));
    _teardown_deps();
    return 0;
}

TEST(test_role_create_unknown_scope)
{
    _setup_deps();
    _init_rbac_svc();
    ozayn_rbac_role_t role;
    ASSERT_EQ(OZAYN_RBAC_ERR_SCOPE_INVALID,
              ozayn_rbac_role_create(&_rbac_svc, "admin", "A", "D", OZAYN_AUTHZ_SCOPE_UNKNOWN, &role));
    _teardown_deps();
    return 0;
}

TEST(test_role_create_duplicate)
{
    _setup_deps();
    _init_rbac_svc();
    ozayn_rbac_role_t role;
    ASSERT_EQ(OZAYN_RBAC_OK,
              ozayn_rbac_role_create(&_rbac_svc, "admin", "A", "D", OZAYN_AUTHZ_SCOPE_SYSTEM, &role));
    ASSERT_EQ(OZAYN_RBAC_ERR_ALREADY_EXISTS,
              ozayn_rbac_role_create(&_rbac_svc, "admin", "B", "E", OZAYN_AUTHZ_SCOPE_SYSTEM, &role));
    _teardown_deps();
    return 0;
}

TEST(test_role_create_limit)
{
    _setup_deps();
    _init_rbac_svc();
    ozayn_rbac_role_t role;
    char id[64];
    for (int i = 0; i < OZAYN_RBAC_MAX_ROLES; i++) {
        snprintf(id, sizeof(id), "role-%d", i);
        ASSERT_EQ(OZAYN_RBAC_OK,
                  ozayn_rbac_role_create(&_rbac_svc, id, id, "D", OZAYN_AUTHZ_SCOPE_SYSTEM, &role));
    }
    ASSERT_EQ(OZAYN_RBAC_ERR_LIMIT_REACHED,
              ozayn_rbac_role_create(&_rbac_svc, "overflow", "O", "D", OZAYN_AUTHZ_SCOPE_SYSTEM, &role));
    _teardown_deps();
    return 0;
}

TEST(test_role_get)
{
    _setup_deps();
    _init_rbac_svc();
    ozayn_rbac_role_t role;
    ozayn_rbac_role_create(&_rbac_svc, "admin", "Admin", "D", OZAYN_AUTHZ_SCOPE_SYSTEM, &role);

    ozayn_rbac_role_t got;
    ASSERT_EQ(OZAYN_RBAC_OK, ozayn_rbac_role_get(&_rbac_svc, "admin", &got));
    ASSERT_STR_EQ("admin", got.id);
    _teardown_deps();
    return 0;
}

TEST(test_role_get_not_found)
{
    _setup_deps();
    _init_rbac_svc();
    ozayn_rbac_role_t got;
    ASSERT_EQ(OZAYN_RBAC_ERR_NOT_FOUND, ozayn_rbac_role_get(&_rbac_svc, "nonexistent", &got));
    _teardown_deps();
    return 0;
}

TEST(test_role_get_null)
{
    ASSERT_EQ(OZAYN_RBAC_ERR_NULL, ozayn_rbac_role_get(NULL, "a", &(ozayn_rbac_role_t){0}));
    _setup_deps();
    _init_rbac_svc();
    ASSERT_EQ(OZAYN_RBAC_ERR_NULL, ozayn_rbac_role_get(&_rbac_svc, NULL, &(ozayn_rbac_role_t){0}));
    ASSERT_EQ(OZAYN_RBAC_ERR_NULL, ozayn_rbac_role_get(&_rbac_svc, "a", NULL));
    _teardown_deps();
    return 0;
}

TEST(test_role_exists)
{
    _setup_deps();
    _init_rbac_svc();
    ASSERT(!ozayn_rbac_role_exists(&_rbac_svc, "admin"));
    ozayn_rbac_role_t role;
    ozayn_rbac_role_create(&_rbac_svc, "admin", "Admin", "D", OZAYN_AUTHZ_SCOPE_SYSTEM, &role);
    ASSERT(ozayn_rbac_role_exists(&_rbac_svc, "admin"));
    ASSERT(!ozayn_rbac_role_exists(&_rbac_svc, "other"));
    _teardown_deps();
    return 0;
}

/* ============================================================
 * 3. ROLE LIFECYCLE (state transitions)
 * ============================================================ */

TEST(test_role_suspend)
{
    _setup_deps();
    _init_rbac_svc();
    ozayn_rbac_role_t role;
    ozayn_rbac_role_create(&_rbac_svc, "admin", "Admin", "D", OZAYN_AUTHZ_SCOPE_SYSTEM, &role);
    ASSERT_EQ(OZAYN_RBAC_OK, ozayn_rbac_role_suspend(&_rbac_svc, "admin"));
    ozayn_rbac_role_get(&_rbac_svc, "admin", &role);
    ASSERT_EQ(OZAYN_RBAC_ROLE_SUSPENDED, role.state);
    _teardown_deps();
    return 0;
}

TEST(test_role_revoke)
{
    _setup_deps();
    _init_rbac_svc();
    ozayn_rbac_role_t role;
    ozayn_rbac_role_create(&_rbac_svc, "admin", "Admin", "D", OZAYN_AUTHZ_SCOPE_SYSTEM, &role);
    ASSERT_EQ(OZAYN_RBAC_OK, ozayn_rbac_role_revoke(&_rbac_svc, "admin"));
    ozayn_rbac_role_get(&_rbac_svc, "admin", &role);
    ASSERT_EQ(OZAYN_RBAC_ROLE_REVOKED, role.state);
    _teardown_deps();
    return 0;
}

TEST(test_role_archive)
{
    _setup_deps();
    _init_rbac_svc();
    ozayn_rbac_role_t role;
    ozayn_rbac_role_create(&_rbac_svc, "admin", "Admin", "D", OZAYN_AUTHZ_SCOPE_SYSTEM, &role);
    ASSERT_EQ(OZAYN_RBAC_OK, ozayn_rbac_role_archive(&_rbac_svc, "admin"));
    ozayn_rbac_role_get(&_rbac_svc, "admin", &role);
    ASSERT_EQ(OZAYN_RBAC_ROLE_ARCHIVED, role.state);
    _teardown_deps();
    return 0;
}

TEST(test_role_suspend_not_found)
{
    _setup_deps();
    _init_rbac_svc();
    ASSERT_EQ(OZAYN_RBAC_ERR_NOT_FOUND, ozayn_rbac_role_suspend(&_rbac_svc, "nonexistent"));
    _teardown_deps();
    return 0;
}

TEST(test_role_transition_active_to_suspended_to_active)
{
    _setup_deps();
    _init_rbac_svc();
    ozayn_rbac_role_t role;
    ozayn_rbac_role_create(&_rbac_svc, "admin", "Admin", "D", OZAYN_AUTHZ_SCOPE_SYSTEM, &role);
    ASSERT_EQ(OZAYN_RBAC_OK, ozayn_rbac_role_suspend(&_rbac_svc, "admin"));
    ozayn_rbac_role_get(&_rbac_svc, "admin", &role);
    ASSERT_EQ(OZAYN_RBAC_ROLE_SUSPENDED, role.state);
    /* SUSPENDED -> ACTIVE is a valid transition (verified by validate) */
    ASSERT_EQ(0, ozayn_rbac_validate_role_transition(OZAYN_RBAC_ROLE_SUSPENDED, OZAYN_RBAC_ROLE_ACTIVE));
    /* SUSPENDED -> SUSPENDED is invalid */
    ASSERT_EQ(OZAYN_RBAC_ERR_STATE_TRANSITION, ozayn_rbac_role_suspend(&_rbac_svc, "admin"));
    _teardown_deps();
    return 0;
}

TEST(test_role_transition_revoked_cannot_activate)
{
    _setup_deps();
    _init_rbac_svc();
    ozayn_rbac_role_t role;
    ozayn_rbac_role_create(&_rbac_svc, "admin", "Admin", "D", OZAYN_AUTHZ_SCOPE_SYSTEM, &role);
    ozayn_rbac_role_revoke(&_rbac_svc, "admin");
    /* Revoked -> Active is not a valid transition */
    ASSERT_EQ(OZAYN_RBAC_ERR_STATE_TRANSITION, ozayn_rbac_role_suspend(&_rbac_svc, "admin"));
    /* Revoke -> Revoke is not valid either */
    ASSERT_EQ(OZAYN_RBAC_ERR_STATE_TRANSITION, ozayn_rbac_role_revoke(&_rbac_svc, "admin"));
    /* Revoke -> Archived IS valid */
    ASSERT_EQ(OZAYN_RBAC_OK, ozayn_rbac_role_archive(&_rbac_svc, "admin"));
    _teardown_deps();
    return 0;
}

TEST(test_role_transition_suspended_can_reactivate)
{
    _setup_deps();
    _init_rbac_svc();
    ozayn_rbac_role_t role;
    ozayn_rbac_role_create(&_rbac_svc, "admin", "Admin", "D", OZAYN_AUTHZ_SCOPE_SYSTEM, &role);
    ozayn_rbac_role_suspend(&_rbac_svc, "admin");
    /* Suspended -> Active (reactivate via ozayn_rbac_role_reactivate) */
    /* We need to expose this... actually, _role_transition handles this.
     * The function takes target state. But our public API only exposes
     * suspend/revoke/archive. Let me check - actually ozayn_rbac_role_suspend
     * transitions to SUSPENDED. We don't have a "reactivate" function yet.
     * For now, test the state machine via validate_role_transition. */
    ASSERT_EQ(0, ozayn_rbac_validate_role_transition(OZAYN_RBAC_ROLE_SUSPENDED, OZAYN_RBAC_ROLE_ACTIVE));
    ASSERT_EQ(0, ozayn_rbac_validate_role_transition(OZAYN_RBAC_ROLE_SUSPENDED, OZAYN_RBAC_ROLE_REVOKED));
    ASSERT_EQ(0, ozayn_rbac_validate_role_transition(OZAYN_RBAC_ROLE_SUSPENDED, OZAYN_RBAC_ROLE_ARCHIVED));
    ASSERT_EQ(-1, ozayn_rbac_validate_role_transition(OZAYN_RBAC_ROLE_REVOKED, OZAYN_RBAC_ROLE_ACTIVE));
    _teardown_deps();
    return 0;
}

TEST(test_role_active_to_archived)
{
    _setup_deps();
    _init_rbac_svc();
    ozayn_rbac_role_t role;
    ozayn_rbac_role_create(&_rbac_svc, "admin", "Admin", "D", OZAYN_AUTHZ_SCOPE_SYSTEM, &role);
    ASSERT_EQ(OZAYN_RBAC_OK, ozayn_rbac_role_archive(&_rbac_svc, "admin"));
    ozayn_rbac_role_get(&_rbac_svc, "admin", &role);
    ASSERT_EQ(OZAYN_RBAC_ROLE_ARCHIVED, role.state);
    _teardown_deps();
    return 0;
}

TEST(test_role_active_to_revoked_to_archived)
{
    _setup_deps();
    _init_rbac_svc();
    ozayn_rbac_role_t role;
    ozayn_rbac_role_create(&_rbac_svc, "admin", "Admin", "D", OZAYN_AUTHZ_SCOPE_SYSTEM, &role);
    ASSERT_EQ(OZAYN_RBAC_OK, ozayn_rbac_role_revoke(&_rbac_svc, "admin"));
    ASSERT_EQ(OZAYN_RBAC_OK, ozayn_rbac_role_archive(&_rbac_svc, "admin"));
    _teardown_deps();
    return 0;
}

/* ============================================================
 * 4. ROLE PERMISSIONS
 * ============================================================ */

TEST(test_permission_add)
{
    _setup_deps();
    _init_rbac_svc();
    ozayn_rbac_role_t role;
    ozayn_rbac_role_create(&_rbac_svc, "reader", "Reader", "D", OZAYN_AUTHZ_SCOPE_USER, &role);
    ASSERT_EQ(OZAYN_RBAC_OK,
              ozayn_rbac_role_add_permission(&_rbac_svc, "reader",
                OZAYN_AUTHZ_RESOURCE_DOCUMENT, OZAYN_AUTHZ_ACTION_READ, OZAYN_AUTHZ_SCOPE_USER));
    ASSERT_EQ(1, ozayn_rbac_role_permission_count(&_rbac_svc, "reader"));
    ASSERT(ozayn_rbac_role_has_permission(&_rbac_svc, "reader",
              OZAYN_AUTHZ_RESOURCE_DOCUMENT, OZAYN_AUTHZ_ACTION_READ, OZAYN_AUTHZ_SCOPE_USER));
    _teardown_deps();
    return 0;
}

TEST(test_permission_add_null)
{
    _setup_deps();
    _init_rbac_svc();
    ASSERT_EQ(OZAYN_RBAC_ERR_NULL,
              ozayn_rbac_role_add_permission(NULL, "a", OZAYN_AUTHZ_RESOURCE_DOCUMENT,
                OZAYN_AUTHZ_ACTION_READ, OZAYN_AUTHZ_SCOPE_USER));
    ASSERT_EQ(OZAYN_RBAC_ERR_NULL,
              ozayn_rbac_role_add_permission(&_rbac_svc, NULL, OZAYN_AUTHZ_RESOURCE_DOCUMENT,
                OZAYN_AUTHZ_ACTION_READ, OZAYN_AUTHZ_SCOPE_USER));
    _teardown_deps();
    return 0;
}

TEST(test_permission_add_not_initialized)
{
    ozayn_rbac_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ASSERT_EQ(OZAYN_RBAC_ERR_NOT_INITIALIZED,
              ozayn_rbac_role_add_permission(&svc, "a", OZAYN_AUTHZ_RESOURCE_DOCUMENT,
                OZAYN_AUTHZ_ACTION_READ, OZAYN_AUTHZ_SCOPE_USER));
    return 0;
}

TEST(test_permission_add_invalid_resource)
{
    _setup_deps();
    _init_rbac_svc();
    ozayn_rbac_role_t role;
    ozayn_rbac_role_create(&_rbac_svc, "reader", "Reader", "D", OZAYN_AUTHZ_SCOPE_USER, &role);
    ASSERT_EQ(OZAYN_RBAC_ERR_PERMISSION_INVALID,
              ozayn_rbac_role_add_permission(&_rbac_svc, "reader",
                OZAYN_AUTHZ_RESOURCE_UNKNOWN, OZAYN_AUTHZ_ACTION_READ, OZAYN_AUTHZ_SCOPE_USER));
    _teardown_deps();
    return 0;
}

TEST(test_permission_add_invalid_action)
{
    _setup_deps();
    _init_rbac_svc();
    ozayn_rbac_role_t role;
    ozayn_rbac_role_create(&_rbac_svc, "reader", "Reader", "D", OZAYN_AUTHZ_SCOPE_USER, &role);
    ASSERT_EQ(OZAYN_RBAC_ERR_PERMISSION_INVALID,
              ozayn_rbac_role_add_permission(&_rbac_svc, "reader",
                OZAYN_AUTHZ_RESOURCE_DOCUMENT, OZAYN_AUTHZ_ACTION_UNKNOWN, OZAYN_AUTHZ_SCOPE_USER));
    _teardown_deps();
    return 0;
}

TEST(test_permission_add_unknown_scope)
{
    _setup_deps();
    _init_rbac_svc();
    ozayn_rbac_role_t role;
    ozayn_rbac_role_create(&_rbac_svc, "reader", "Reader", "D", OZAYN_AUTHZ_SCOPE_USER, &role);
    ASSERT_EQ(OZAYN_RBAC_ERR_SCOPE_INVALID,
              ozayn_rbac_role_add_permission(&_rbac_svc, "reader",
                OZAYN_AUTHZ_RESOURCE_DOCUMENT, OZAYN_AUTHZ_ACTION_READ, OZAYN_AUTHZ_SCOPE_UNKNOWN));
    _teardown_deps();
    return 0;
}

TEST(test_permission_add_role_not_found)
{
    _setup_deps();
    _init_rbac_svc();
    ASSERT_EQ(OZAYN_RBAC_ERR_NOT_FOUND,
              ozayn_rbac_role_add_permission(&_rbac_svc, "nonexistent",
                OZAYN_AUTHZ_RESOURCE_DOCUMENT, OZAYN_AUTHZ_ACTION_READ, OZAYN_AUTHZ_SCOPE_USER));
    _teardown_deps();
    return 0;
}

TEST(test_permission_add_duplicate)
{
    _setup_deps();
    _init_rbac_svc();
    ozayn_rbac_role_t role;
    ozayn_rbac_role_create(&_rbac_svc, "reader", "Reader", "D", OZAYN_AUTHZ_SCOPE_USER, &role);
    ASSERT_EQ(OZAYN_RBAC_OK,
              ozayn_rbac_role_add_permission(&_rbac_svc, "reader",
                OZAYN_AUTHZ_RESOURCE_DOCUMENT, OZAYN_AUTHZ_ACTION_READ, OZAYN_AUTHZ_SCOPE_USER));
    ASSERT_EQ(OZAYN_RBAC_ERR_ALREADY_EXISTS,
              ozayn_rbac_role_add_permission(&_rbac_svc, "reader",
                OZAYN_AUTHZ_RESOURCE_DOCUMENT, OZAYN_AUTHZ_ACTION_READ, OZAYN_AUTHZ_SCOPE_USER));
    _teardown_deps();
    return 0;
}

TEST(test_permission_add_limit)
{
    _setup_deps();
    _init_rbac_svc();
    ozayn_rbac_role_t role;
    ozayn_rbac_role_create(&_rbac_svc, "multi", "Multi", "D", OZAYN_AUTHZ_SCOPE_USER, &role);
    for (int i = 0; i < OZAYN_RBAC_MAX_PERMISSIONS; i++) {
        ASSERT_EQ(OZAYN_RBAC_OK,
                  ozayn_rbac_role_add_permission(&_rbac_svc, "multi",
                    (ozayn_authz_resource_type_t)(i + 1), OZAYN_AUTHZ_ACTION_READ, OZAYN_AUTHZ_SCOPE_USER));
    }
    ASSERT_EQ(OZAYN_RBAC_ERR_LIMIT_REACHED,
              ozayn_rbac_role_add_permission(&_rbac_svc, "multi",
                OZAYN_AUTHZ_RESOURCE_SYSTEM, (ozayn_authz_action_type_t)100, OZAYN_AUTHZ_SCOPE_USER));
    _teardown_deps();
    return 0;
}

TEST(test_permission_remove)
{
    _setup_deps();
    _init_rbac_svc();
    ozayn_rbac_role_t role;
    ozayn_rbac_role_create(&_rbac_svc, "reader", "Reader", "D", OZAYN_AUTHZ_SCOPE_USER, &role);
    ozayn_rbac_role_add_permission(&_rbac_svc, "reader",
        OZAYN_AUTHZ_RESOURCE_DOCUMENT, OZAYN_AUTHZ_ACTION_READ, OZAYN_AUTHZ_SCOPE_USER);
    ASSERT_EQ(OZAYN_RBAC_OK,
              ozayn_rbac_role_remove_permission(&_rbac_svc, "reader",
                OZAYN_AUTHZ_RESOURCE_DOCUMENT, OZAYN_AUTHZ_ACTION_READ, OZAYN_AUTHZ_SCOPE_USER));
    ASSERT_EQ(0, ozayn_rbac_role_permission_count(&_rbac_svc, "reader"));
    ASSERT(!ozayn_rbac_role_has_permission(&_rbac_svc, "reader",
              OZAYN_AUTHZ_RESOURCE_DOCUMENT, OZAYN_AUTHZ_ACTION_READ, OZAYN_AUTHZ_SCOPE_USER));
    _teardown_deps();
    return 0;
}

TEST(test_permission_remove_not_found)
{
    _setup_deps();
    _init_rbac_svc();
    ozayn_rbac_role_t role;
    ozayn_rbac_role_create(&_rbac_svc, "reader", "Reader", "D", OZAYN_AUTHZ_SCOPE_USER, &role);
    ASSERT_EQ(OZAYN_RBAC_ERR_PERMISSION_NOT_FOUND,
              ozayn_rbac_role_remove_permission(&_rbac_svc, "reader",
                OZAYN_AUTHZ_RESOURCE_DOCUMENT, OZAYN_AUTHZ_ACTION_READ, OZAYN_AUTHZ_SCOPE_USER));
    _teardown_deps();
    return 0;
}

TEST(test_permission_has_returns_zero_for_missing)
{
    _setup_deps();
    _init_rbac_svc();
    ozayn_rbac_role_t role;
    ozayn_rbac_role_create(&_rbac_svc, "reader", "Reader", "D", OZAYN_AUTHZ_SCOPE_USER, &role);
    ASSERT(!ozayn_rbac_role_has_permission(&_rbac_svc, "reader",
              OZAYN_AUTHZ_RESOURCE_DOCUMENT, OZAYN_AUTHZ_ACTION_READ, OZAYN_AUTHZ_SCOPE_USER));
    _teardown_deps();
    return 0;
}

TEST(test_permission_count_not_found)
{
    _setup_deps();
    _init_rbac_svc();
    ASSERT_EQ(-1, ozayn_rbac_role_permission_count(&_rbac_svc, "nonexistent"));
    _teardown_deps();
    return 0;
}

TEST(test_permission_different_scopes_allowed)
{
    _setup_deps();
    _init_rbac_svc();
    ozayn_rbac_role_t role;
    ozayn_rbac_role_create(&_rbac_svc, "reader", "Reader", "D", OZAYN_AUTHZ_SCOPE_USER, &role);
    /* Same resource+action but different scopes should be allowed */
    ASSERT_EQ(OZAYN_RBAC_OK,
              ozayn_rbac_role_add_permission(&_rbac_svc, "reader",
                OZAYN_AUTHZ_RESOURCE_DOCUMENT, OZAYN_AUTHZ_ACTION_READ, OZAYN_AUTHZ_SCOPE_USER));
    ASSERT_EQ(OZAYN_RBAC_OK,
              ozayn_rbac_role_add_permission(&_rbac_svc, "reader",
                OZAYN_AUTHZ_RESOURCE_DOCUMENT, OZAYN_AUTHZ_ACTION_READ, OZAYN_AUTHZ_SCOPE_SYSTEM));
    ASSERT_EQ(2, ozayn_rbac_role_permission_count(&_rbac_svc, "reader"));
    _teardown_deps();
    return 0;
}

/* ============================================================
 * 5. ROLE ASSIGNMENTS
 * ============================================================ */

TEST(test_assign)
{
    _setup_deps();
    _init_rbac_svc();
    ozayn_identity_t id = _create_identity("alice");
    ozayn_rbac_role_t role;
    ozayn_rbac_role_create(&_rbac_svc, "reader", "Reader", "D", OZAYN_AUTHZ_SCOPE_USER, &role);

    ozayn_rbac_assignment_t asgn;
    ozayn_rbac_error_t r = ozayn_rbac_assign(&_rbac_svc, id.id, "reader",
                                              OZAYN_AUTHZ_SCOPE_USER, &asgn);
    ASSERT_EQ(OZAYN_RBAC_OK, r);
    ASSERT_STR_EQ(id.id, asgn.identity_id);
    ASSERT_STR_EQ("reader", asgn.role_id);
    ASSERT_EQ(OZAYN_RBAC_ASSIGN_ACTIVE, asgn.state);
    ASSERT_EQ(1, ozayn_rbac_assignment_count(&_rbac_svc));
    _teardown_deps();
    return 0;
}

TEST(test_assign_null)
{
    _setup_deps();
    _init_rbac_svc();
    ASSERT_EQ(OZAYN_RBAC_ERR_NULL,
              ozayn_rbac_assign(NULL, "a", "r", OZAYN_AUTHZ_SCOPE_USER, &(ozayn_rbac_assignment_t){0}));
    ASSERT_EQ(OZAYN_RBAC_ERR_NULL,
              ozayn_rbac_assign(&_rbac_svc, NULL, "r", OZAYN_AUTHZ_SCOPE_USER, &(ozayn_rbac_assignment_t){0}));
    ASSERT_EQ(OZAYN_RBAC_ERR_NULL,
              ozayn_rbac_assign(&_rbac_svc, "a", NULL, OZAYN_AUTHZ_SCOPE_USER, &(ozayn_rbac_assignment_t){0}));
    ASSERT_EQ(OZAYN_RBAC_ERR_NULL,
              ozayn_rbac_assign(&_rbac_svc, "a", "r", OZAYN_AUTHZ_SCOPE_USER, NULL));
    _teardown_deps();
    return 0;
}

TEST(test_assign_not_initialized)
{
    ozayn_rbac_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ASSERT_EQ(OZAYN_RBAC_ERR_NOT_INITIALIZED,
              ozayn_rbac_assign(&svc, "a", "r", OZAYN_AUTHZ_SCOPE_USER, &(ozayn_rbac_assignment_t){0}));
    return 0;
}

TEST(test_assign_empty_identity)
{
    _setup_deps();
    _init_rbac_svc();
    ozayn_rbac_role_t role;
    ozayn_rbac_role_create(&_rbac_svc, "reader", "Reader", "D", OZAYN_AUTHZ_SCOPE_USER, &role);
    ASSERT_EQ(OZAYN_RBAC_ERR_IDENTITY_INVALID,
              ozayn_rbac_assign(&_rbac_svc, "", "reader", OZAYN_AUTHZ_SCOPE_USER, &(ozayn_rbac_assignment_t){0}));
    _teardown_deps();
    return 0;
}

TEST(test_assign_role_not_found)
{
    _setup_deps();
    _init_rbac_svc();
    ozayn_identity_t id = _create_identity("alice");
    ASSERT_EQ(OZAYN_RBAC_ERR_NOT_FOUND,
              ozayn_rbac_assign(&_rbac_svc, id.id, "nonexistent", OZAYN_AUTHZ_SCOPE_USER, &(ozayn_rbac_assignment_t){0}));
    _teardown_deps();
    return 0;
}

TEST(test_assign_role_not_active)
{
    _setup_deps();
    _init_rbac_svc();
    ozayn_identity_t id = _create_identity("alice");
    ozayn_rbac_role_t role;
    ozayn_rbac_role_create(&_rbac_svc, "reader", "Reader", "D", OZAYN_AUTHZ_SCOPE_USER, &role);
    ozayn_rbac_role_revoke(&_rbac_svc, "reader");
    ASSERT_EQ(OZAYN_RBAC_ERR_STATE_INVALID,
              ozayn_rbac_assign(&_rbac_svc, id.id, "reader", OZAYN_AUTHZ_SCOPE_USER, &(ozayn_rbac_assignment_t){0}));
    _teardown_deps();
    return 0;
}

TEST(test_assign_identity_not_active)
{
    _setup_deps();
    _init_rbac_svc();
    ozayn_identity_t id = _create_identity("alice");
    ozayn_rbac_role_t role;
    ozayn_rbac_role_create(&_rbac_svc, "reader", "Reader", "D", OZAYN_AUTHZ_SCOPE_USER, &role);
    ozayn_id_revoke(&_id_svc, id.id);
    ASSERT_EQ(OZAYN_RBAC_ERR_IDENTITY_INVALID,
              ozayn_rbac_assign(&_rbac_svc, id.id, "reader", OZAYN_AUTHZ_SCOPE_USER, &(ozayn_rbac_assignment_t){0}));
    _teardown_deps();
    return 0;
}

TEST(test_assign_unknown_scope)
{
    _setup_deps();
    _init_rbac_svc();
    ozayn_identity_t id = _create_identity("alice");
    ozayn_rbac_role_t role;
    ozayn_rbac_role_create(&_rbac_svc, "reader", "Reader", "D", OZAYN_AUTHZ_SCOPE_USER, &role);
    ASSERT_EQ(OZAYN_RBAC_ERR_SCOPE_INVALID,
              ozayn_rbac_assign(&_rbac_svc, id.id, "reader", OZAYN_AUTHZ_SCOPE_UNKNOWN, &(ozayn_rbac_assignment_t){0}));
    _teardown_deps();
    return 0;
}

TEST(test_assign_duplicate)
{
    _setup_deps();
    _init_rbac_svc();
    ozayn_identity_t id = _create_identity("alice");
    ozayn_rbac_role_t role;
    ozayn_rbac_role_create(&_rbac_svc, "reader", "Reader", "D", OZAYN_AUTHZ_SCOPE_USER, &role);
    ozayn_rbac_assignment_t asgn;
    ASSERT_EQ(OZAYN_RBAC_OK,
              ozayn_rbac_assign(&_rbac_svc, id.id, "reader", OZAYN_AUTHZ_SCOPE_USER, &asgn));
    ASSERT_EQ(OZAYN_RBAC_ERR_ASSIGNMENT_EXISTS,
              ozayn_rbac_assign(&_rbac_svc, id.id, "reader", OZAYN_AUTHZ_SCOPE_USER, &asgn));
    _teardown_deps();
    return 0;
}

TEST(test_get_assignment)
{
    _setup_deps();
    _init_rbac_svc();
    ozayn_identity_t id = _create_identity("alice");
    ozayn_rbac_role_t role;
    ozayn_rbac_role_create(&_rbac_svc, "reader", "Reader", "D", OZAYN_AUTHZ_SCOPE_USER, &role);
    ozayn_rbac_assignment_t asgn;
    ozayn_rbac_assign(&_rbac_svc, id.id, "reader", OZAYN_AUTHZ_SCOPE_USER, &asgn);

    ozayn_rbac_assignment_t got;
    ASSERT_EQ(OZAYN_RBAC_OK, ozayn_rbac_get_assignment(&_rbac_svc, asgn.id, &got));
    ASSERT_STR_EQ(asgn.id, got.id);
    _teardown_deps();
    return 0;
}

TEST(test_get_assignment_not_found)
{
    _setup_deps();
    _init_rbac_svc();
    ozayn_rbac_assignment_t got;
    ASSERT_EQ(OZAYN_RBAC_ERR_ASSIGNMENT_NOT_FOUND,
              ozayn_rbac_get_assignment(&_rbac_svc, "nonexistent", &got));
    _teardown_deps();
    return 0;
}

TEST(test_suspend_assignment)
{
    _setup_deps();
    _init_rbac_svc();
    ozayn_identity_t id = _create_identity("alice");
    ozayn_rbac_role_t role;
    ozayn_rbac_role_create(&_rbac_svc, "reader", "Reader", "D", OZAYN_AUTHZ_SCOPE_USER, &role);
    ozayn_rbac_assignment_t asgn;
    ozayn_rbac_assign(&_rbac_svc, id.id, "reader", OZAYN_AUTHZ_SCOPE_USER, &asgn);

    ASSERT_EQ(OZAYN_RBAC_OK, ozayn_rbac_suspend_assignment(&_rbac_svc, asgn.id));
    ozayn_rbac_assignment_t got;
    ozayn_rbac_get_assignment(&_rbac_svc, asgn.id, &got);
    ASSERT_EQ(OZAYN_RBAC_ASSIGN_SUSPENDED, got.state);
    _teardown_deps();
    return 0;
}

TEST(test_revoke_assignment)
{
    _setup_deps();
    _init_rbac_svc();
    ozayn_identity_t id = _create_identity("alice");
    ozayn_rbac_role_t role;
    ozayn_rbac_role_create(&_rbac_svc, "reader", "Reader", "D", OZAYN_AUTHZ_SCOPE_USER, &role);
    ozayn_rbac_assignment_t asgn;
    ozayn_rbac_assign(&_rbac_svc, id.id, "reader", OZAYN_AUTHZ_SCOPE_USER, &asgn);

    ASSERT_EQ(OZAYN_RBAC_OK, ozayn_rbac_revoke_assignment(&_rbac_svc, asgn.id));
    ozayn_rbac_assignment_t got;
    ozayn_rbac_get_assignment(&_rbac_svc, asgn.id, &got);
    ASSERT_EQ(OZAYN_RBAC_ASSIGN_REVOKED, got.state);
    _teardown_deps();
    return 0;
}

TEST(test_expire_assignment)
{
    _setup_deps();
    _init_rbac_svc();
    ozayn_identity_t id = _create_identity("alice");
    ozayn_rbac_role_t role;
    ozayn_rbac_role_create(&_rbac_svc, "reader", "Reader", "D", OZAYN_AUTHZ_SCOPE_USER, &role);
    ozayn_rbac_assignment_t asgn;
    ozayn_rbac_assign(&_rbac_svc, id.id, "reader", OZAYN_AUTHZ_SCOPE_USER, &asgn);

    ASSERT_EQ(OZAYN_RBAC_OK, ozayn_rbac_expire_assignment(&_rbac_svc, asgn.id));
    ozayn_rbac_assignment_t got;
    ozayn_rbac_get_assignment(&_rbac_svc, asgn.id, &got);
    ASSERT_EQ(OZAYN_RBAC_ASSIGN_EXPIRED, got.state);
    _teardown_deps();
    return 0;
}

TEST(test_assignment_suspend_revoke_invalid)
{
    _setup_deps();
    _init_rbac_svc();
    ozayn_identity_t id = _create_identity("alice");
    ozayn_rbac_role_t role;
    ozayn_rbac_role_create(&_rbac_svc, "reader", "Reader", "D", OZAYN_AUTHZ_SCOPE_USER, &role);
    ozayn_rbac_assignment_t asgn;
    ozayn_rbac_assign(&_rbac_svc, id.id, "reader", OZAYN_AUTHZ_SCOPE_USER, &asgn);
    ozayn_rbac_revoke_assignment(&_rbac_svc, asgn.id);
    /* Revoked -> suspended is invalid */
    ASSERT_EQ(OZAYN_RBAC_ERR_STATE_TRANSITION,
              ozayn_rbac_suspend_assignment(&_rbac_svc, asgn.id));
    /* Revoked -> expired is invalid */
    ASSERT_EQ(OZAYN_RBAC_ERR_STATE_TRANSITION,
              ozayn_rbac_expire_assignment(&_rbac_svc, asgn.id));
    _teardown_deps();
    return 0;
}

TEST(test_assignment_suspend_can_reactivate)
{
    _setup_deps();
    _init_rbac_svc();
    ozayn_identity_t id = _create_identity("alice");
    ozayn_rbac_role_t role;
    ozayn_rbac_role_create(&_rbac_svc, "reader", "Reader", "D", OZAYN_AUTHZ_SCOPE_USER, &role);
    ozayn_rbac_assignment_t asgn;
    ozayn_rbac_assign(&_rbac_svc, id.id, "reader", OZAYN_AUTHZ_SCOPE_USER, &asgn);
    ozayn_rbac_suspend_assignment(&_rbac_svc, asgn.id);
    /* Suspended -> Active is valid */
    ASSERT_EQ(0, ozayn_rbac_validate_assignment_transition(
        OZAYN_RBAC_ASSIGN_SUSPENDED, OZAYN_RBAC_ASSIGN_ACTIVE));
    /* Suspended -> Revoked is valid */
    ASSERT_EQ(0, ozayn_rbac_validate_assignment_transition(
        OZAYN_RBAC_ASSIGN_SUSPENDED, OZAYN_RBAC_ASSIGN_REVOKED));
    _teardown_deps();
    return 0;
}

TEST(test_identity_assignment_count)
{
    _setup_deps();
    _init_rbac_svc();
    ozayn_identity_t id = _create_identity("alice");
    ozayn_rbac_role_t r1, r2;
    ozayn_rbac_role_create(&_rbac_svc, "reader", "Reader", "D", OZAYN_AUTHZ_SCOPE_USER, &r1);
    ozayn_rbac_role_create(&_rbac_svc, "writer", "Writer", "D", OZAYN_AUTHZ_SCOPE_USER, &r2);
    ozayn_rbac_assignment_t a1, a2;
    ozayn_rbac_assign(&_rbac_svc, id.id, "reader", OZAYN_AUTHZ_SCOPE_USER, &a1);
    ozayn_rbac_assign(&_rbac_svc, id.id, "writer", OZAYN_AUTHZ_SCOPE_USER, &a2);
    ASSERT_EQ(2, ozayn_rbac_identity_assignment_count(&_rbac_svc, id.id));
    _teardown_deps();
    return 0;
}

/* ============================================================
 * 6. RBAC AUTHORIZATION (permission check)
 * ============================================================ */

TEST(test_check_permission_allowed)
{
    _setup_deps();
    _init_rbac_svc();
    ozayn_identity_t id = _create_identity("alice");
    ozayn_rbac_role_t role;
    ozayn_rbac_role_create(&_rbac_svc, "reader", "Reader", "D", OZAYN_AUTHZ_SCOPE_USER, &role);
    ozayn_rbac_role_add_permission(&_rbac_svc, "reader",
        OZAYN_AUTHZ_RESOURCE_DOCUMENT, OZAYN_AUTHZ_ACTION_READ, OZAYN_AUTHZ_SCOPE_USER);
    ozayn_rbac_assignment_t asgn;
    ozayn_rbac_assign(&_rbac_svc, id.id, "reader", OZAYN_AUTHZ_SCOPE_USER, &asgn);

    ASSERT(ozayn_rbac_check_permission(&_rbac_svc, id.id,
              OZAYN_AUTHZ_RESOURCE_DOCUMENT, OZAYN_AUTHZ_ACTION_READ, OZAYN_AUTHZ_SCOPE_USER));
    _teardown_deps();
    return 0;
}

TEST(test_check_permission_denied_no_permission)
{
    _setup_deps();
    _init_rbac_svc();
    ozayn_identity_t id = _create_identity("alice");
    ozayn_rbac_role_t role;
    ozayn_rbac_role_create(&_rbac_svc, "reader", "Reader", "D", OZAYN_AUTHZ_SCOPE_USER, &role);
    ozayn_rbac_role_add_permission(&_rbac_svc, "reader",
        OZAYN_AUTHZ_RESOURCE_DOCUMENT, OZAYN_AUTHZ_ACTION_READ, OZAYN_AUTHZ_SCOPE_USER);
    ozayn_rbac_assignment_t asgn;
    ozayn_rbac_assign(&_rbac_svc, id.id, "reader", OZAYN_AUTHZ_SCOPE_USER, &asgn);

    /* Different action */
    ASSERT(!ozayn_rbac_check_permission(&_rbac_svc, id.id,
              OZAYN_AUTHZ_RESOURCE_DOCUMENT, OZAYN_AUTHZ_ACTION_UPDATE, OZAYN_AUTHZ_SCOPE_USER));
    _teardown_deps();
    return 0;
}

TEST(test_check_permission_denied_no_role)
{
    _setup_deps();
    _init_rbac_svc();
    ozayn_identity_t id = _create_identity("alice");
    ASSERT(!ozayn_rbac_check_permission(&_rbac_svc, id.id,
              OZAYN_AUTHZ_RESOURCE_DOCUMENT, OZAYN_AUTHZ_ACTION_READ, OZAYN_AUTHZ_SCOPE_USER));
    _teardown_deps();
    return 0;
}

TEST(test_check_permission_denied_suspended_role)
{
    _setup_deps();
    _init_rbac_svc();
    ozayn_identity_t id = _create_identity("alice");
    ozayn_rbac_role_t role;
    ozayn_rbac_role_create(&_rbac_svc, "reader", "Reader", "D", OZAYN_AUTHZ_SCOPE_USER, &role);
    ozayn_rbac_role_add_permission(&_rbac_svc, "reader",
        OZAYN_AUTHZ_RESOURCE_DOCUMENT, OZAYN_AUTHZ_ACTION_READ, OZAYN_AUTHZ_SCOPE_USER);
    ozayn_rbac_assignment_t asgn;
    ozayn_rbac_assign(&_rbac_svc, id.id, "reader", OZAYN_AUTHZ_SCOPE_USER, &asgn);
    ozayn_rbac_role_suspend(&_rbac_svc, "reader");

    ASSERT(!ozayn_rbac_check_permission(&_rbac_svc, id.id,
              OZAYN_AUTHZ_RESOURCE_DOCUMENT, OZAYN_AUTHZ_ACTION_READ, OZAYN_AUTHZ_SCOPE_USER));
    _teardown_deps();
    return 0;
}

TEST(test_check_permission_denied_revoked_role)
{
    _setup_deps();
    _init_rbac_svc();
    ozayn_identity_t id = _create_identity("alice");
    ozayn_rbac_role_t role;
    ozayn_rbac_role_create(&_rbac_svc, "reader", "Reader", "D", OZAYN_AUTHZ_SCOPE_USER, &role);
    ozayn_rbac_role_add_permission(&_rbac_svc, "reader",
        OZAYN_AUTHZ_RESOURCE_DOCUMENT, OZAYN_AUTHZ_ACTION_READ, OZAYN_AUTHZ_SCOPE_USER);
    ozayn_rbac_assignment_t asgn;
    ozayn_rbac_assign(&_rbac_svc, id.id, "reader", OZAYN_AUTHZ_SCOPE_USER, &asgn);
    ozayn_rbac_role_revoke(&_rbac_svc, "reader");

    ASSERT(!ozayn_rbac_check_permission(&_rbac_svc, id.id,
              OZAYN_AUTHZ_RESOURCE_DOCUMENT, OZAYN_AUTHZ_ACTION_READ, OZAYN_AUTHZ_SCOPE_USER));
    _teardown_deps();
    return 0;
}

TEST(test_check_permission_denied_revoked_assignment)
{
    _setup_deps();
    _init_rbac_svc();
    ozayn_identity_t id = _create_identity("alice");
    ozayn_rbac_role_t role;
    ozayn_rbac_role_create(&_rbac_svc, "reader", "Reader", "D", OZAYN_AUTHZ_SCOPE_USER, &role);
    ozayn_rbac_role_add_permission(&_rbac_svc, "reader",
        OZAYN_AUTHZ_RESOURCE_DOCUMENT, OZAYN_AUTHZ_ACTION_READ, OZAYN_AUTHZ_SCOPE_USER);
    ozayn_rbac_assignment_t asgn;
    ozayn_rbac_assign(&_rbac_svc, id.id, "reader", OZAYN_AUTHZ_SCOPE_USER, &asgn);
    ozayn_rbac_revoke_assignment(&_rbac_svc, asgn.id);

    ASSERT(!ozayn_rbac_check_permission(&_rbac_svc, id.id,
              OZAYN_AUTHZ_RESOURCE_DOCUMENT, OZAYN_AUTHZ_ACTION_READ, OZAYN_AUTHZ_SCOPE_USER));
    _teardown_deps();
    return 0;
}

TEST(test_check_permission_denied_suspended_identity)
{
    _setup_deps();
    _init_rbac_svc();
    ozayn_identity_t id = _create_identity("alice");
    ozayn_rbac_role_t role;
    ozayn_rbac_role_create(&_rbac_svc, "reader", "Reader", "D", OZAYN_AUTHZ_SCOPE_USER, &role);
    ozayn_rbac_role_add_permission(&_rbac_svc, "reader",
        OZAYN_AUTHZ_RESOURCE_DOCUMENT, OZAYN_AUTHZ_ACTION_READ, OZAYN_AUTHZ_SCOPE_USER);
    ozayn_rbac_assignment_t asgn;
    ozayn_rbac_assign(&_rbac_svc, id.id, "reader", OZAYN_AUTHZ_SCOPE_USER, &asgn);
    ozayn_id_suspend(&_id_svc, id.id);

    ASSERT(!ozayn_rbac_check_permission(&_rbac_svc, id.id,
              OZAYN_AUTHZ_RESOURCE_DOCUMENT, OZAYN_AUTHZ_ACTION_READ, OZAYN_AUTHZ_SCOPE_USER));
    _teardown_deps();
    return 0;
}

TEST(test_check_permission_scope_mismatch)
{
    _setup_deps();
    _init_rbac_svc();
    ozayn_identity_t id = _create_identity("alice");
    ozayn_rbac_role_t role;
    ozayn_rbac_role_create(&_rbac_svc, "reader", "Reader", "D", OZAYN_AUTHZ_SCOPE_USER, &role);
    ozayn_rbac_role_add_permission(&_rbac_svc, "reader",
        OZAYN_AUTHZ_RESOURCE_DOCUMENT, OZAYN_AUTHZ_ACTION_READ, OZAYN_AUTHZ_SCOPE_USER);
    ozayn_rbac_assignment_t asgn;
    ozayn_rbac_assign(&_rbac_svc, id.id, "reader", OZAYN_AUTHZ_SCOPE_USER, &asgn);

    /* Request in SYSTEM scope, but permission is USER scope */
    ASSERT(!ozayn_rbac_check_permission(&_rbac_svc, id.id,
              OZAYN_AUTHZ_RESOURCE_DOCUMENT, OZAYN_AUTHZ_ACTION_READ, OZAYN_AUTHZ_SCOPE_SYSTEM));
    _teardown_deps();
    return 0;
}

TEST(test_check_permission_global_scope_covers_all)
{
    _setup_deps();
    _init_rbac_svc();
    ozayn_identity_t id = _create_identity("alice");
    ozayn_rbac_role_t role;
    ozayn_rbac_role_create(&_rbac_svc, "admin", "Admin", "D", OZAYN_AUTHZ_SCOPE_GLOBAL, &role);
    ozayn_rbac_role_add_permission(&_rbac_svc, "admin",
        OZAYN_AUTHZ_RESOURCE_DOCUMENT, OZAYN_AUTHZ_ACTION_READ, OZAYN_AUTHZ_SCOPE_GLOBAL);
    ozayn_rbac_assignment_t asgn;
    ozayn_rbac_assign(&_rbac_svc, id.id, "admin", OZAYN_AUTHZ_SCOPE_GLOBAL, &asgn);

    /* GLOBAL permission should cover USER scope request */
    ASSERT(ozayn_rbac_check_permission(&_rbac_svc, id.id,
              OZAYN_AUTHZ_RESOURCE_DOCUMENT, OZAYN_AUTHZ_ACTION_READ, OZAYN_AUTHZ_SCOPE_USER));
    /* GLOBAL permission should cover SYSTEM scope request */
    ASSERT(ozayn_rbac_check_permission(&_rbac_svc, id.id,
              OZAYN_AUTHZ_RESOURCE_DOCUMENT, OZAYN_AUTHZ_ACTION_READ, OZAYN_AUTHZ_SCOPE_SYSTEM));
    _teardown_deps();
    return 0;
}

TEST(test_check_permission_multiple_roles)
{
    _setup_deps();
    _init_rbac_svc();
    ozayn_identity_t id = _create_identity("alice");
    ozayn_rbac_role_t r1, r2;
    ozayn_rbac_role_create(&_rbac_svc, "reader", "Reader", "D", OZAYN_AUTHZ_SCOPE_USER, &r1);
    ozayn_rbac_role_create(&_rbac_svc, "writer", "Writer", "D", OZAYN_AUTHZ_SCOPE_USER, &r2);
    ozayn_rbac_role_add_permission(&_rbac_svc, "reader",
        OZAYN_AUTHZ_RESOURCE_DOCUMENT, OZAYN_AUTHZ_ACTION_READ, OZAYN_AUTHZ_SCOPE_USER);
    ozayn_rbac_role_add_permission(&_rbac_svc, "writer",
        OZAYN_AUTHZ_RESOURCE_DOCUMENT, OZAYN_AUTHZ_ACTION_CREATE, OZAYN_AUTHZ_SCOPE_USER);
    ozayn_rbac_assignment_t a1, a2;
    ozayn_rbac_assign(&_rbac_svc, id.id, "reader", OZAYN_AUTHZ_SCOPE_USER, &a1);
    ozayn_rbac_assign(&_rbac_svc, id.id, "writer", OZAYN_AUTHZ_SCOPE_USER, &a2);

    ASSERT(ozayn_rbac_check_permission(&_rbac_svc, id.id,
              OZAYN_AUTHZ_RESOURCE_DOCUMENT, OZAYN_AUTHZ_ACTION_READ, OZAYN_AUTHZ_SCOPE_USER));
    ASSERT(ozayn_rbac_check_permission(&_rbac_svc, id.id,
              OZAYN_AUTHZ_RESOURCE_DOCUMENT, OZAYN_AUTHZ_ACTION_CREATE, OZAYN_AUTHZ_SCOPE_USER));
    /* Not allowed for UPDATE */
    ASSERT(!ozayn_rbac_check_permission(&_rbac_svc, id.id,
              OZAYN_AUTHZ_RESOURCE_DOCUMENT, OZAYN_AUTHZ_ACTION_UPDATE, OZAYN_AUTHZ_SCOPE_USER));
    _teardown_deps();
    return 0;
}

TEST(test_has_roles)
{
    _setup_deps();
    _init_rbac_svc();
    ozayn_identity_t id = _create_identity("alice");
    ASSERT(!ozayn_rbac_has_roles(&_rbac_svc, id.id));

    ozayn_rbac_role_t role;
    ozayn_rbac_role_create(&_rbac_svc, "reader", "Reader", "D", OZAYN_AUTHZ_SCOPE_USER, &role);
    ozayn_rbac_assignment_t asgn;
    ozayn_rbac_assign(&_rbac_svc, id.id, "reader", OZAYN_AUTHZ_SCOPE_USER, &asgn);
    ASSERT(ozayn_rbac_has_roles(&_rbac_svc, id.id));
    _teardown_deps();
    return 0;
}

/* ============================================================
 * 7. VALIDATION
 * ============================================================ */

TEST(test_validate_role_id)
{
    ASSERT_EQ(0, ozayn_rbac_validate_role_id("admin"));
    ASSERT_EQ(0, ozayn_rbac_validate_role_id("role-1"));
    ASSERT_EQ(0, ozayn_rbac_validate_role_id("role_2"));
    ASSERT_EQ(0, ozayn_rbac_validate_role_id("Role.V3"));
    ASSERT_EQ(-1, ozayn_rbac_validate_role_id(""));
    ASSERT_EQ(-1, ozayn_rbac_validate_role_id(NULL));
    ASSERT_EQ(-1, ozayn_rbac_validate_role_id("admin user"));
    ASSERT_EQ(-1, ozayn_rbac_validate_role_id("admin/user"));
    ASSERT_EQ(-1, ozayn_rbac_validate_role_id("admin@user"));
    return 0;
}

TEST(test_validate_role_state)
{
    ASSERT_EQ(0, ozayn_rbac_validate_role_state(OZAYN_RBAC_ROLE_UNINITIALIZED));
    ASSERT_EQ(0, ozayn_rbac_validate_role_state(OZAYN_RBAC_ROLE_ACTIVE));
    ASSERT_EQ(0, ozayn_rbac_validate_role_state(OZAYN_RBAC_ROLE_SUSPENDED));
    ASSERT_EQ(0, ozayn_rbac_validate_role_state(OZAYN_RBAC_ROLE_REVOKED));
    ASSERT_EQ(0, ozayn_rbac_validate_role_state(OZAYN_RBAC_ROLE_ARCHIVED));
    return 0;
}

TEST(test_validate_role_transition)
{
    ASSERT_EQ(0, ozayn_rbac_validate_role_transition(OZAYN_RBAC_ROLE_UNINITIALIZED, OZAYN_RBAC_ROLE_ACTIVE));
    ASSERT_EQ(0, ozayn_rbac_validate_role_transition(OZAYN_RBAC_ROLE_ACTIVE, OZAYN_RBAC_ROLE_SUSPENDED));
    ASSERT_EQ(0, ozayn_rbac_validate_role_transition(OZAYN_RBAC_ROLE_ACTIVE, OZAYN_RBAC_ROLE_REVOKED));
    ASSERT_EQ(0, ozayn_rbac_validate_role_transition(OZAYN_RBAC_ROLE_ACTIVE, OZAYN_RBAC_ROLE_ARCHIVED));
    ASSERT_EQ(0, ozayn_rbac_validate_role_transition(OZAYN_RBAC_ROLE_SUSPENDED, OZAYN_RBAC_ROLE_ACTIVE));
    ASSERT_EQ(0, ozayn_rbac_validate_role_transition(OZAYN_RBAC_ROLE_SUSPENDED, OZAYN_RBAC_ROLE_REVOKED));
    ASSERT_EQ(0, ozayn_rbac_validate_role_transition(OZAYN_RBAC_ROLE_SUSPENDED, OZAYN_RBAC_ROLE_ARCHIVED));
    ASSERT_EQ(0, ozayn_rbac_validate_role_transition(OZAYN_RBAC_ROLE_REVOKED, OZAYN_RBAC_ROLE_ARCHIVED));
    /* Invalid transitions */
    ASSERT_EQ(-1, ozayn_rbac_validate_role_transition(OZAYN_RBAC_ROLE_REVOKED, OZAYN_RBAC_ROLE_ACTIVE));
    ASSERT_EQ(-1, ozayn_rbac_validate_role_transition(OZAYN_RBAC_ROLE_ARCHIVED, OZAYN_RBAC_ROLE_ACTIVE));
    ASSERT_EQ(-1, ozayn_rbac_validate_role_transition(OZAYN_RBAC_ROLE_ACTIVE, OZAYN_RBAC_ROLE_ACTIVE));
    return 0;
}

TEST(test_validate_assignment_state)
{
    ASSERT_EQ(0, ozayn_rbac_validate_assignment_state(OZAYN_RBAC_ASSIGN_ACTIVE));
    ASSERT_EQ(0, ozayn_rbac_validate_assignment_state(OZAYN_RBAC_ASSIGN_SUSPENDED));
    ASSERT_EQ(0, ozayn_rbac_validate_assignment_state(OZAYN_RBAC_ASSIGN_REVOKED));
    ASSERT_EQ(0, ozayn_rbac_validate_assignment_state(OZAYN_RBAC_ASSIGN_EXPIRED));
    return 0;
}

TEST(test_validate_assignment_transition)
{
    ASSERT_EQ(0, ozayn_rbac_validate_assignment_transition(OZAYN_RBAC_ASSIGN_ACTIVE, OZAYN_RBAC_ASSIGN_SUSPENDED));
    ASSERT_EQ(0, ozayn_rbac_validate_assignment_transition(OZAYN_RBAC_ASSIGN_ACTIVE, OZAYN_RBAC_ASSIGN_REVOKED));
    ASSERT_EQ(0, ozayn_rbac_validate_assignment_transition(OZAYN_RBAC_ASSIGN_ACTIVE, OZAYN_RBAC_ASSIGN_EXPIRED));
    ASSERT_EQ(0, ozayn_rbac_validate_assignment_transition(OZAYN_RBAC_ASSIGN_SUSPENDED, OZAYN_RBAC_ASSIGN_ACTIVE));
    ASSERT_EQ(0, ozayn_rbac_validate_assignment_transition(OZAYN_RBAC_ASSIGN_SUSPENDED, OZAYN_RBAC_ASSIGN_REVOKED));
    /* Invalid */
    ASSERT_EQ(-1, ozayn_rbac_validate_assignment_transition(OZAYN_RBAC_ASSIGN_REVOKED, OZAYN_RBAC_ASSIGN_ACTIVE));
    ASSERT_EQ(-1, ozayn_rbac_validate_assignment_transition(OZAYN_RBAC_ASSIGN_EXPIRED, OZAYN_RBAC_ASSIGN_ACTIVE));
    return 0;
}

/* ============================================================
 * 8. NAME HELPERS
 * ============================================================ */

TEST(test_error_names)
{
    ASSERT_STR_EQ("OK", ozayn_rbac_error_name(OZAYN_RBAC_OK));
    ASSERT_STR_EQ("NULL", ozayn_rbac_error_name(OZAYN_RBAC_ERR_NULL));
    ASSERT_STR_EQ("NOT_INITIALIZED", ozayn_rbac_error_name(OZAYN_RBAC_ERR_NOT_INITIALIZED));
    ASSERT_STR_EQ("NOT_FOUND", ozayn_rbac_error_name(OZAYN_RBAC_ERR_NOT_FOUND));
    ASSERT_STR_EQ("ALREADY_EXISTS", ozayn_rbac_error_name(OZAYN_RBAC_ERR_ALREADY_EXISTS));
    ASSERT_STR_EQ("INVALID", ozayn_rbac_error_name(OZAYN_RBAC_ERR_INVALID));
    ASSERT_STR_EQ("ID_INVALID", ozayn_rbac_error_name(OZAYN_RBAC_ERR_ID_INVALID));
    ASSERT_STR_EQ("STATE_INVALID", ozayn_rbac_error_name(OZAYN_RBAC_ERR_STATE_INVALID));
    ASSERT_STR_EQ("STATE_TRANSITION", ozayn_rbac_error_name(OZAYN_RBAC_ERR_STATE_TRANSITION));
    ASSERT_STR_EQ("SCOPE_INVALID", ozayn_rbac_error_name(OZAYN_RBAC_ERR_SCOPE_INVALID));
    ASSERT_STR_EQ("LIMIT_REACHED", ozayn_rbac_error_name(OZAYN_RBAC_ERR_LIMIT_REACHED));
    ASSERT_STR_EQ("PERMISSION_INVALID", ozayn_rbac_error_name(OZAYN_RBAC_ERR_PERMISSION_INVALID));
    ASSERT_STR_EQ("PERMISSION_NOT_FOUND", ozayn_rbac_error_name(OZAYN_RBAC_ERR_PERMISSION_NOT_FOUND));
    ASSERT_STR_EQ("ASSIGNMENT_INVALID", ozayn_rbac_error_name(OZAYN_RBAC_ERR_ASSIGNMENT_INVALID));
    ASSERT_STR_EQ("ASSIGNMENT_NOT_FOUND", ozayn_rbac_error_name(OZAYN_RBAC_ERR_ASSIGNMENT_NOT_FOUND));
    ASSERT_STR_EQ("ASSIGNMENT_EXISTS", ozayn_rbac_error_name(OZAYN_RBAC_ERR_ASSIGNMENT_EXISTS));
    ASSERT_STR_EQ("IDENTITY_INVALID", ozayn_rbac_error_name(OZAYN_RBAC_ERR_IDENTITY_INVALID));
    ASSERT_STR_EQ("PRIVILEGE_ESCALATION", ozayn_rbac_error_name(OZAYN_RBAC_ERR_PRIVILEGE_ESCALATION));
    ASSERT_STR_EQ("STORAGE_FAILED", ozayn_rbac_error_name(OZAYN_RBAC_ERR_STORAGE_FAILED));
    ASSERT_STR_EQ("VAULT_UNAVAILABLE", ozayn_rbac_error_name(OZAYN_RBAC_ERR_VAULT_UNAVAILABLE));
    ASSERT_STR_EQ("INTEGRITY_FAILURE", ozayn_rbac_error_name(OZAYN_RBAC_ERR_INTEGRITY_FAILURE));
    ASSERT_STR_EQ("UNKNOWN", ozayn_rbac_error_name((ozayn_rbac_error_t)999));
    return 0;
}

TEST(test_role_state_names)
{
    ASSERT_STR_EQ("UNINITIALIZED", ozayn_rbac_role_state_name(OZAYN_RBAC_ROLE_UNINITIALIZED));
    ASSERT_STR_EQ("ACTIVE", ozayn_rbac_role_state_name(OZAYN_RBAC_ROLE_ACTIVE));
    ASSERT_STR_EQ("SUSPENDED", ozayn_rbac_role_state_name(OZAYN_RBAC_ROLE_SUSPENDED));
    ASSERT_STR_EQ("REVOKED", ozayn_rbac_role_state_name(OZAYN_RBAC_ROLE_REVOKED));
    ASSERT_STR_EQ("ARCHIVED", ozayn_rbac_role_state_name(OZAYN_RBAC_ROLE_ARCHIVED));
    ASSERT_STR_EQ("UNKNOWN", ozayn_rbac_role_state_name((ozayn_rbac_role_state_t)999));
    return 0;
}

TEST(test_assignment_state_names)
{
    ASSERT_STR_EQ("ACTIVE", ozayn_rbac_assignment_state_name(OZAYN_RBAC_ASSIGN_ACTIVE));
    ASSERT_STR_EQ("SUSPENDED", ozayn_rbac_assignment_state_name(OZAYN_RBAC_ASSIGN_SUSPENDED));
    ASSERT_STR_EQ("REVOKED", ozayn_rbac_assignment_state_name(OZAYN_RBAC_ASSIGN_REVOKED));
    ASSERT_STR_EQ("EXPIRED", ozayn_rbac_assignment_state_name(OZAYN_RBAC_ASSIGN_EXPIRED));
    ASSERT_STR_EQ("UNKNOWN", ozayn_rbac_assignment_state_name((ozayn_rbac_assign_state_t)999));
    return 0;
}

/* ============================================================
 * 9. SECURITY TESTS
 * ============================================================ */

TEST(test_suspended_assignment_does_not_grant)
{
    _setup_deps();
    _init_rbac_svc();
    ozayn_identity_t id = _create_identity("alice");
    ozayn_rbac_role_t role;
    ozayn_rbac_role_create(&_rbac_svc, "reader", "Reader", "D", OZAYN_AUTHZ_SCOPE_USER, &role);
    ozayn_rbac_role_add_permission(&_rbac_svc, "reader",
        OZAYN_AUTHZ_RESOURCE_DOCUMENT, OZAYN_AUTHZ_ACTION_READ, OZAYN_AUTHZ_SCOPE_USER);
    ozayn_rbac_assignment_t asgn;
    ozayn_rbac_assign(&_rbac_svc, id.id, "reader", OZAYN_AUTHZ_SCOPE_USER, &asgn);
    ozayn_rbac_suspend_assignment(&_rbac_svc, asgn.id);

    ASSERT(!ozayn_rbac_check_permission(&_rbac_svc, id.id,
              OZAYN_AUTHZ_RESOURCE_DOCUMENT, OZAYN_AUTHZ_ACTION_READ, OZAYN_AUTHZ_SCOPE_USER));
    _teardown_deps();
    return 0;
}

TEST(test_expired_assignment_does_not_grant)
{
    _setup_deps();
    _init_rbac_svc();
    ozayn_identity_t id = _create_identity("alice");
    ozayn_rbac_role_t role;
    ozayn_rbac_role_create(&_rbac_svc, "reader", "Reader", "D", OZAYN_AUTHZ_SCOPE_USER, &role);
    ozayn_rbac_role_add_permission(&_rbac_svc, "reader",
        OZAYN_AUTHZ_RESOURCE_DOCUMENT, OZAYN_AUTHZ_ACTION_READ, OZAYN_AUTHZ_SCOPE_USER);
    ozayn_rbac_assignment_t asgn;
    ozayn_rbac_assign(&_rbac_svc, id.id, "reader", OZAYN_AUTHZ_SCOPE_USER, &asgn);
    ozayn_rbac_expire_assignment(&_rbac_svc, asgn.id);

    ASSERT(!ozayn_rbac_check_permission(&_rbac_svc, id.id,
              OZAYN_AUTHZ_RESOURCE_DOCUMENT, OZAYN_AUTHZ_ACTION_READ, OZAYN_AUTHZ_SCOPE_USER));
    _teardown_deps();
    return 0;
}

TEST(test_revoked_identity_cannot_use_roles)
{
    _setup_deps();
    _init_rbac_svc();
    ozayn_identity_t id = _create_identity("alice");
    ozayn_rbac_role_t role;
    ozayn_rbac_role_create(&_rbac_svc, "reader", "Reader", "D", OZAYN_AUTHZ_SCOPE_USER, &role);
    ozayn_rbac_role_add_permission(&_rbac_svc, "reader",
        OZAYN_AUTHZ_RESOURCE_DOCUMENT, OZAYN_AUTHZ_ACTION_READ, OZAYN_AUTHZ_SCOPE_USER);
    ozayn_rbac_assignment_t asgn;
    ozayn_rbac_assign(&_rbac_svc, id.id, "reader", OZAYN_AUTHZ_SCOPE_USER, &asgn);
    ozayn_id_revoke(&_id_svc, id.id);

    ASSERT(!ozayn_rbac_check_permission(&_rbac_svc, id.id,
              OZAYN_AUTHZ_RESOURCE_DOCUMENT, OZAYN_AUTHZ_ACTION_READ, OZAYN_AUTHZ_SCOPE_USER));
    _teardown_deps();
    return 0;
}

TEST(test_archived_role_does_not_grant)
{
    _setup_deps();
    _init_rbac_svc();
    ozayn_identity_t id = _create_identity("alice");
    ozayn_rbac_role_t role;
    ozayn_rbac_role_create(&_rbac_svc, "reader", "Reader", "D", OZAYN_AUTHZ_SCOPE_USER, &role);
    ozayn_rbac_role_add_permission(&_rbac_svc, "reader",
        OZAYN_AUTHZ_RESOURCE_DOCUMENT, OZAYN_AUTHZ_ACTION_READ, OZAYN_AUTHZ_SCOPE_USER);
    ozayn_rbac_assignment_t asgn;
    ozayn_rbac_assign(&_rbac_svc, id.id, "reader", OZAYN_AUTHZ_SCOPE_USER, &asgn);
    ozayn_rbac_role_archive(&_rbac_svc, "reader");

    ASSERT(!ozayn_rbac_check_permission(&_rbac_svc, id.id,
              OZAYN_AUTHZ_RESOURCE_DOCUMENT, OZAYN_AUTHZ_ACTION_READ, OZAYN_AUTHZ_SCOPE_USER));
    _teardown_deps();
    return 0;
}

TEST(test_scope_escalation_prevented)
{
    _setup_deps();
    _init_rbac_svc();
    ozayn_identity_t id = _create_identity("alice");
    ozayn_rbac_role_t role;
    ozayn_rbac_role_create(&_rbac_svc, "user-role", "User Role", "D", OZAYN_AUTHZ_SCOPE_USER, &role);
    ozayn_rbac_role_add_permission(&_rbac_svc, "user-role",
        OZAYN_AUTHZ_RESOURCE_DOCUMENT, OZAYN_AUTHZ_ACTION_READ, OZAYN_AUTHZ_SCOPE_USER);
    ozayn_rbac_assignment_t asgn;
    ozayn_rbac_assign(&_rbac_svc, id.id, "user-role", OZAYN_AUTHZ_SCOPE_USER, &asgn);

    /* User-scope role should NOT grant system-scope access */
    ASSERT(!ozayn_rbac_check_permission(&_rbac_svc, id.id,
              OZAYN_AUTHZ_RESOURCE_DOCUMENT, OZAYN_AUTHZ_ACTION_READ, OZAYN_AUTHZ_SCOPE_SYSTEM));
    _teardown_deps();
    return 0;
}

TEST(test_no_hardcoded_superuser)
{
    _setup_deps();
    _init_rbac_svc();
    ozayn_identity_t id = _create_identity("admin");
    /* No roles assigned — even "admin" identity should not get access */
    ASSERT(!ozayn_rbac_check_permission(&_rbac_svc, id.id,
              OZAYN_AUTHZ_RESOURCE_DOCUMENT, OZAYN_AUTHZ_ACTION_READ, OZAYN_AUTHZ_SCOPE_USER));
    ASSERT(!ozayn_rbac_has_roles(&_rbac_svc, id.id));
    _teardown_deps();
    return 0;
}

TEST(test_cannot_assign_to_inactive_role)
{
    _setup_deps();
    _init_rbac_svc();
    ozayn_identity_t id = _create_identity("alice");
    ozayn_rbac_role_t role;
    ozayn_rbac_role_create(&_rbac_svc, "reader", "Reader", "D", OZAYN_AUTHZ_SCOPE_USER, &role);
    ozayn_rbac_role_suspend(&_rbac_svc, "reader");

    ASSERT_EQ(OZAYN_RBAC_ERR_STATE_INVALID,
              ozayn_rbac_assign(&_rbac_svc, id.id, "reader", OZAYN_AUTHZ_SCOPE_USER, &(ozayn_rbac_assignment_t){0}));
    _teardown_deps();
    return 0;
}

TEST(test_check_permission_null_args)
{
    _setup_deps();
    _init_rbac_svc();
    ASSERT(!ozayn_rbac_check_permission(NULL, "a", OZAYN_AUTHZ_RESOURCE_DOCUMENT,
              OZAYN_AUTHZ_ACTION_READ, OZAYN_AUTHZ_SCOPE_USER));
    ASSERT(!ozayn_rbac_check_permission(&_rbac_svc, NULL, OZAYN_AUTHZ_RESOURCE_DOCUMENT,
              OZAYN_AUTHZ_ACTION_READ, OZAYN_AUTHZ_SCOPE_USER));
    _teardown_deps();
    return 0;
}

TEST(test_has_roles_null)
{
    ASSERT(!ozayn_rbac_has_roles(NULL, "a"));
    _setup_deps();
    _init_rbac_svc();
    ASSERT(!ozayn_rbac_has_roles(&_rbac_svc, NULL));
    _teardown_deps();
    return 0;
}

TEST(test_role_version_increments)
{
    _setup_deps();
    _init_rbac_svc();
    ozayn_rbac_role_t role;
    ozayn_rbac_role_create(&_rbac_svc, "admin", "Admin", "D", OZAYN_AUTHZ_SCOPE_SYSTEM, &role);
    ASSERT_EQ(1, role.version);
    ozayn_rbac_role_suspend(&_rbac_svc, "admin");
    ozayn_rbac_role_get(&_rbac_svc, "admin", &role);
    ASSERT_EQ(2, role.version);
    _teardown_deps();
    return 0;
}

TEST(test_role_null_ops)
{
    ASSERT_EQ(OZAYN_RBAC_ERR_NULL, ozayn_rbac_role_suspend(NULL, "a"));
    ASSERT_EQ(OZAYN_RBAC_ERR_NULL, ozayn_rbac_role_revoke(NULL, "a"));
    ASSERT_EQ(OZAYN_RBAC_ERR_NULL, ozayn_rbac_role_archive(NULL, "a"));
    ASSERT_EQ(0, ozayn_rbac_role_exists(NULL, "a"));
    _setup_deps();
    _init_rbac_svc();
    ASSERT_EQ(0, ozayn_rbac_role_exists(NULL, "a"));
    _teardown_deps();
    return 0;
}

TEST(test_assignment_null_ops)
{
    ASSERT_EQ(OZAYN_RBAC_ERR_NULL, ozayn_rbac_suspend_assignment(NULL, "a"));
    ASSERT_EQ(OZAYN_RBAC_ERR_NULL, ozayn_rbac_revoke_assignment(NULL, "a"));
    ASSERT_EQ(OZAYN_RBAC_ERR_NULL, ozayn_rbac_expire_assignment(NULL, "a"));
    ASSERT_EQ(OZAYN_RBAC_ERR_NULL, ozayn_rbac_get_assignment(NULL, "a", &(ozayn_rbac_assignment_t){0}));
    _setup_deps();
    _init_rbac_svc();
    ASSERT_EQ(OZAYN_RBAC_ERR_NULL, ozayn_rbac_get_assignment(&_rbac_svc, NULL, &(ozayn_rbac_assignment_t){0}));
    ASSERT_EQ(OZAYN_RBAC_ERR_NULL, ozayn_rbac_get_assignment(&_rbac_svc, "a", NULL));
    _teardown_deps();
    return 0;
}

/* ============================================================
 * RUN ALL TESTS
 * ============================================================ */

int run_rbac_tests(void)
{
    SUITE_BEGIN("RBAC");

    /* 1. Service lifecycle */
    RUN(test_service_init);
    RUN(test_service_init_null);
    RUN(test_service_init_null_config);
    RUN(test_service_init_no_identity_service);
    RUN(test_service_shutdown);
    RUN(test_service_shutdown_null);

    /* 2. Role management */
    RUN(test_role_create);
    RUN(test_role_create_null);
    RUN(test_role_create_not_initialized);
    RUN(test_role_create_invalid_id);
    RUN(test_role_create_unknown_scope);
    RUN(test_role_create_duplicate);
    RUN(test_role_create_limit);
    RUN(test_role_get);
    RUN(test_role_get_not_found);
    RUN(test_role_get_null);
    RUN(test_role_exists);

    /* 3. Role lifecycle */
    RUN(test_role_suspend);
    RUN(test_role_revoke);
    RUN(test_role_archive);
    RUN(test_role_suspend_not_found);
    RUN(test_role_transition_active_to_suspended_to_active);
    RUN(test_role_transition_revoked_cannot_activate);
    RUN(test_role_transition_suspended_can_reactivate);
    RUN(test_role_active_to_archived);
    RUN(test_role_active_to_revoked_to_archived);

    /* 4. Role permissions */
    RUN(test_permission_add);
    RUN(test_permission_add_null);
    RUN(test_permission_add_not_initialized);
    RUN(test_permission_add_invalid_resource);
    RUN(test_permission_add_invalid_action);
    RUN(test_permission_add_unknown_scope);
    RUN(test_permission_add_role_not_found);
    RUN(test_permission_add_duplicate);
    RUN(test_permission_add_limit);
    RUN(test_permission_remove);
    RUN(test_permission_remove_not_found);
    RUN(test_permission_has_returns_zero_for_missing);
    RUN(test_permission_count_not_found);
    RUN(test_permission_different_scopes_allowed);

    /* 5. Role assignments */
    RUN(test_assign);
    RUN(test_assign_null);
    RUN(test_assign_not_initialized);
    RUN(test_assign_empty_identity);
    RUN(test_assign_role_not_found);
    RUN(test_assign_role_not_active);
    RUN(test_assign_identity_not_active);
    RUN(test_assign_unknown_scope);
    RUN(test_assign_duplicate);
    RUN(test_get_assignment);
    RUN(test_get_assignment_not_found);
    RUN(test_suspend_assignment);
    RUN(test_revoke_assignment);
    RUN(test_expire_assignment);
    RUN(test_assignment_suspend_revoke_invalid);
    RUN(test_assignment_suspend_can_reactivate);
    RUN(test_identity_assignment_count);

    /* 6. RBAC authorization */
    RUN(test_check_permission_allowed);
    RUN(test_check_permission_denied_no_permission);
    RUN(test_check_permission_denied_no_role);
    RUN(test_check_permission_denied_suspended_role);
    RUN(test_check_permission_denied_revoked_role);
    RUN(test_check_permission_denied_revoked_assignment);
    RUN(test_check_permission_denied_suspended_identity);
    RUN(test_check_permission_scope_mismatch);
    RUN(test_check_permission_global_scope_covers_all);
    RUN(test_check_permission_multiple_roles);
    RUN(test_has_roles);

    /* 7. Validation */
    RUN(test_validate_role_id);
    RUN(test_validate_role_state);
    RUN(test_validate_role_transition);
    RUN(test_validate_assignment_state);
    RUN(test_validate_assignment_transition);

    /* 8. Name helpers */
    RUN(test_error_names);
    RUN(test_role_state_names);
    RUN(test_assignment_state_names);

    /* 9. Security tests */
    RUN(test_suspended_assignment_does_not_grant);
    RUN(test_expired_assignment_does_not_grant);
    RUN(test_revoked_identity_cannot_use_roles);
    RUN(test_archived_role_does_not_grant);
    RUN(test_scope_escalation_prevented);
    RUN(test_no_hardcoded_superuser);
    RUN(test_cannot_assign_to_inactive_role);
    RUN(test_check_permission_null_args);
    RUN(test_has_roles_null);
    RUN(test_role_version_increments);
    RUN(test_role_null_ops);
    RUN(test_assignment_null_ops);

    SUITE_END();
}
