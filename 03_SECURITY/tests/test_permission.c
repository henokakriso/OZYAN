#include "../../tests/test_framework.h"
#include "../permission.h"
#include <string.h>

/* ============================================================
 * SHARED TEST INFRASTRUCTURE
 * ============================================================ */

static ozayn_perm_service_t _perm_svc;

static void _setup_perm_svc(void)
{
    ozayn_perm_service_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    ozayn_perm_service_init(&_perm_svc, &cfg);
}

static void _teardown_perm_svc(void)
{
    ozayn_perm_service_shutdown(&_perm_svc);
}

/* ============================================================
 * 1. SERVICE LIFECYCLE
 * ============================================================ */

TEST(test_service_init)
{
    _setup_perm_svc();
    ASSERT(ozayn_perm_service_is_initialized(&_perm_svc));
    ASSERT_EQ(0, ozayn_perm_count(&_perm_svc));
    _teardown_perm_svc();
    return 0;
}

TEST(test_service_init_null)
{
    ASSERT_EQ(OZAYN_PERM_ERR_NULL, ozayn_perm_service_init(NULL, NULL));
    return 0;
}

TEST(test_service_shutdown)
{
    _setup_perm_svc();
    ozayn_perm_service_shutdown(&_perm_svc);
    ASSERT(!ozayn_perm_service_is_initialized(&_perm_svc));
    return 0;
}

TEST(test_service_shutdown_null)
{
    ozayn_perm_service_shutdown(NULL);
    return 0;
}

TEST(test_service_not_initialized)
{
    ozayn_perm_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ASSERT_EQ(OZAYN_PERM_ERR_NOT_INITIALIZED,
              ozayn_perm_create(&svc, "p1", "Perm1", "Desc",
                                OZAYN_AUTHZ_RESOURCE_CORE,
                                OZAYN_AUTHZ_ACTION_READ,
                                OZAYN_AUTHZ_SCOPE_USER, &(ozayn_permission_t){0}));
    return 0;
}

/* ============================================================
 * 2. PERMISSION CREATION
 * ============================================================ */

TEST(test_perm_create_basic)
{
    _setup_perm_svc();
    ozayn_permission_t perm;
    ozayn_perm_error_t r = ozayn_perm_create(&_perm_svc, "perm-read-core",
        "Read Core", "Read core resources",
        OZAYN_AUTHZ_RESOURCE_CORE, OZAYN_AUTHZ_ACTION_READ,
        OZAYN_AUTHZ_SCOPE_USER, &perm);
    ASSERT_EQ(OZAYN_PERM_OK, r);
    ASSERT_STR_EQ("perm-read-core", perm.id);
    ASSERT_STR_EQ("Read Core", perm.name);
    ASSERT_EQ(OZAYN_AUTHZ_RESOURCE_CORE, perm.resource);
    ASSERT_EQ(OZAYN_AUTHZ_ACTION_READ, perm.action);
    ASSERT_EQ(OZAYN_AUTHZ_SCOPE_USER, perm.scope);
    ASSERT_EQ(OZAYN_PERM_ACTIVE, perm.state);
    ASSERT_EQ(1, perm.version);
    ASSERT(perm.in_use);
    _teardown_perm_svc();
    return 0;
}

TEST(test_perm_create_null)
{
    _setup_perm_svc();
    ozayn_permission_t perm;
    ASSERT_EQ(OZAYN_PERM_ERR_NULL,
              ozayn_perm_create(NULL, "p1", "P", "D",
                                OZAYN_AUTHZ_RESOURCE_CORE,
                                OZAYN_AUTHZ_ACTION_READ,
                                OZAYN_AUTHZ_SCOPE_USER, &perm));
    ASSERT_EQ(OZAYN_PERM_ERR_NULL,
              ozayn_perm_create(&_perm_svc, NULL, "P", "D",
                                OZAYN_AUTHZ_RESOURCE_CORE,
                                OZAYN_AUTHZ_ACTION_READ,
                                OZAYN_AUTHZ_SCOPE_USER, &perm));
    ASSERT_EQ(OZAYN_PERM_ERR_NULL,
              ozayn_perm_create(&_perm_svc, "p1", "P", "D",
                                OZAYN_AUTHZ_RESOURCE_CORE,
                                OZAYN_AUTHZ_ACTION_READ,
                                OZAYN_AUTHZ_SCOPE_USER, NULL));
    _teardown_perm_svc();
    return 0;
}

TEST(test_perm_create_invalid_id)
{
    _setup_perm_svc();
    ozayn_permission_t perm;
    ASSERT_EQ(OZAYN_PERM_ERR_ID_INVALID,
              ozayn_perm_create(&_perm_svc, "", "P", "D",
                                OZAYN_AUTHZ_RESOURCE_CORE,
                                OZAYN_AUTHZ_ACTION_READ,
                                OZAYN_AUTHZ_SCOPE_USER, &perm));
    ASSERT_EQ(OZAYN_PERM_ERR_ID_INVALID,
              ozayn_perm_create(&_perm_svc, "id with spaces", "P", "D",
                                OZAYN_AUTHZ_RESOURCE_CORE,
                                OZAYN_AUTHZ_ACTION_READ,
                                OZAYN_AUTHZ_SCOPE_USER, &perm));
    _teardown_perm_svc();
    return 0;
}

TEST(test_perm_create_duplicate)
{
    _setup_perm_svc();
    ozayn_permission_t perm;
    ASSERT_EQ(OZAYN_PERM_OK,
              ozayn_perm_create(&_perm_svc, "p1", "P", "D",
                                OZAYN_AUTHZ_RESOURCE_CORE,
                                OZAYN_AUTHZ_ACTION_READ,
                                OZAYN_AUTHZ_SCOPE_USER, &perm));
    ASSERT_EQ(OZAYN_PERM_ERR_ALREADY_EXISTS,
              ozayn_perm_create(&_perm_svc, "p1", "P2", "D2",
                                OZAYN_AUTHZ_RESOURCE_CORE,
                                OZAYN_AUTHZ_ACTION_READ,
                                OZAYN_AUTHZ_SCOPE_USER, &perm));
    _teardown_perm_svc();
    return 0;
}

TEST(test_perm_create_unknown_resource)
{
    _setup_perm_svc();
    ozayn_permission_t perm;
    ASSERT_EQ(OZAYN_PERM_ERR_RESOURCE_INVALID,
              ozayn_perm_create(&_perm_svc, "p1", "P", "D",
                                OZAYN_AUTHZ_RESOURCE_UNKNOWN,
                                OZAYN_AUTHZ_ACTION_READ,
                                OZAYN_AUTHZ_SCOPE_USER, &perm));
    _teardown_perm_svc();
    return 0;
}

TEST(test_perm_create_unknown_action)
{
    _setup_perm_svc();
    ozayn_permission_t perm;
    ASSERT_EQ(OZAYN_PERM_ERR_ACTION_INVALID,
              ozayn_perm_create(&_perm_svc, "p1", "P", "D",
                                OZAYN_AUTHZ_RESOURCE_CORE,
                                OZAYN_AUTHZ_ACTION_UNKNOWN,
                                OZAYN_AUTHZ_SCOPE_USER, &perm));
    _teardown_perm_svc();
    return 0;
}

TEST(test_perm_create_unknown_scope)
{
    _setup_perm_svc();
    ozayn_permission_t perm;
    ASSERT_EQ(OZAYN_PERM_ERR_SCOPE_INVALID,
              ozayn_perm_create(&_perm_svc, "p1", "P", "D",
                                OZAYN_AUTHZ_RESOURCE_CORE,
                                OZAYN_AUTHZ_ACTION_READ,
                                OZAYN_AUTHZ_SCOPE_UNKNOWN, &perm));
    _teardown_perm_svc();
    return 0;
}

TEST(test_perm_create_name_defaults_to_id)
{
    _setup_perm_svc();
    ozayn_permission_t perm;
    ASSERT_EQ(OZAYN_PERM_OK,
              ozayn_perm_create(&_perm_svc, "my-perm", NULL, NULL,
                                OZAYN_AUTHZ_RESOURCE_CORE,
                                OZAYN_AUTHZ_ACTION_READ,
                                OZAYN_AUTHZ_SCOPE_USER, &perm));
    ASSERT_STR_EQ("my-perm", perm.name);
    ASSERT_STR_EQ("", perm.description);
    _teardown_perm_svc();
    return 0;
}

TEST(test_perm_create_all_scopes)
{
    _setup_perm_svc();
    ozayn_permission_t perm;
    ozayn_authz_scope_t scopes[] = {
        OZAYN_AUTHZ_SCOPE_SYSTEM, OZAYN_AUTHZ_SCOPE_USER,
        OZAYN_AUTHZ_SCOPE_DEVICE, OZAYN_AUTHZ_SCOPE_MODULE,
        OZAYN_AUTHZ_SCOPE_SERVICE, OZAYN_AUTHZ_SCOPE_GLOBAL
    };
    const char *ids[] = {
        "p-system", "p-user", "p-device", "p-module", "p-service", "p-global"
    };
    for (int i = 0; i < 6; i++) {
        ASSERT_EQ(OZAYN_PERM_OK,
                  ozayn_perm_create(&_perm_svc, ids[i], NULL, NULL,
                                    OZAYN_AUTHZ_RESOURCE_CORE,
                                    OZAYN_AUTHZ_ACTION_READ,
                                    scopes[i], &perm));
    }
    ASSERT_EQ(6, ozayn_perm_count(&_perm_svc));
    _teardown_perm_svc();
    return 0;
}

TEST(test_perm_create_all_resources)
{
    _setup_perm_svc();
    ozayn_permission_t perm;
    ozayn_authz_resource_type_t resources[] = {
        OZAYN_AUTHZ_RESOURCE_CORE, OZAYN_AUTHZ_RESOURCE_MODULE,
        OZAYN_AUTHZ_RESOURCE_PLUGIN, OZAYN_AUTHZ_RESOURCE_DOCUMENT,
        OZAYN_AUTHZ_RESOURCE_MEMORY, OZAYN_AUTHZ_RESOURCE_DATABASE,
        OZAYN_AUTHZ_RESOURCE_DEVICE, OZAYN_AUTHZ_RESOURCE_CAMERA,
        OZAYN_AUTHZ_RESOURCE_MICROPHONE, OZAYN_AUTHZ_RESOURCE_SYSTEM,
        OZAYN_AUTHZ_RESOURCE_IDENTITY, OZAYN_AUTHZ_RESOURCE_SESSION,
        OZAYN_AUTHZ_RESOURCE_SERVICE
    };
    for (int i = 0; i < 13; i++) {
        char id[32];
        snprintf(id, sizeof(id), "res-%d", i);
        ASSERT_EQ(OZAYN_PERM_OK,
                  ozayn_perm_create(&_perm_svc, id, NULL, NULL,
                                    resources[i],
                                    OZAYN_AUTHZ_ACTION_READ,
                                    OZAYN_AUTHZ_SCOPE_USER, &perm));
    }
    ASSERT_EQ(13, ozayn_perm_count(&_perm_svc));
    _teardown_perm_svc();
    return 0;
}

TEST(test_perm_create_all_actions)
{
    _setup_perm_svc();
    ozayn_permission_t perm;
    ozayn_authz_action_type_t actions[] = {
        OZAYN_AUTHZ_ACTION_READ, OZAYN_AUTHZ_ACTION_CREATE,
        OZAYN_AUTHZ_ACTION_UPDATE, OZAYN_AUTHZ_ACTION_DELETE,
        OZAYN_AUTHZ_ACTION_EXECUTE, OZAYN_AUTHZ_ACTION_CONTROL,
        OZAYN_AUTHZ_ACTION_CONFIGURE, OZAYN_AUTHZ_ACTION_INSTALL,
        OZAYN_AUTHZ_ACTION_UNINSTALL
    };
    for (int i = 0; i < 9; i++) {
        char id[32];
        snprintf(id, sizeof(id), "act-%d", i);
        ASSERT_EQ(OZAYN_PERM_OK,
                  ozayn_perm_create(&_perm_svc, id, NULL, NULL,
                                    OZAYN_AUTHZ_RESOURCE_CORE,
                                    actions[i],
                                    OZAYN_AUTHZ_SCOPE_USER, &perm));
    }
    ASSERT_EQ(9, ozayn_perm_count(&_perm_svc));
    _teardown_perm_svc();
    return 0;
}

/* ============================================================
 * 3. PERMISSION GET / EXISTS
 * ============================================================ */

TEST(test_perm_get)
{
    _setup_perm_svc();
    ozayn_permission_t perm;
    ASSERT_EQ(OZAYN_PERM_OK,
              ozayn_perm_create(&_perm_svc, "p1", "Perm1", "Desc",
                                OZAYN_AUTHZ_RESOURCE_CORE,
                                OZAYN_AUTHZ_ACTION_READ,
                                OZAYN_AUTHZ_SCOPE_USER, &perm));

    ozayn_permission_t got;
    ASSERT_EQ(OZAYN_PERM_OK, ozayn_perm_get(&_perm_svc, "p1", &got));
    ASSERT_STR_EQ("p1", got.id);
    ASSERT_STR_EQ("Perm1", got.name);
    _teardown_perm_svc();
    return 0;
}

TEST(test_perm_get_not_found)
{
    _setup_perm_svc();
    ozayn_permission_t perm;
    ASSERT_EQ(OZAYN_PERM_ERR_NOT_FOUND,
              ozayn_perm_get(&_perm_svc, "nonexistent", &perm));
    _teardown_perm_svc();
    return 0;
}

TEST(test_perm_get_null)
{
    _setup_perm_svc();
    ozayn_permission_t perm;
    ASSERT_EQ(OZAYN_PERM_ERR_NULL, ozayn_perm_get(NULL, "p1", &perm));
    ASSERT_EQ(OZAYN_PERM_ERR_NULL, ozayn_perm_get(&_perm_svc, NULL, &perm));
    ASSERT_EQ(OZAYN_PERM_ERR_NULL, ozayn_perm_get(&_perm_svc, "p1", NULL));
    _teardown_perm_svc();
    return 0;
}

TEST(test_perm_exists)
{
    _setup_perm_svc();
    ozayn_permission_t perm;
    ASSERT(!ozayn_perm_exists(&_perm_svc, "p1"));
    ASSERT_EQ(OZAYN_PERM_OK,
              ozayn_perm_create(&_perm_svc, "p1", "P", "D",
                                OZAYN_AUTHZ_RESOURCE_CORE,
                                OZAYN_AUTHZ_ACTION_READ,
                                OZAYN_AUTHZ_SCOPE_USER, &perm));
    ASSERT(ozayn_perm_exists(&_perm_svc, "p1"));
    ASSERT(!ozayn_perm_exists(&_perm_svc, "p2"));
    _teardown_perm_svc();
    return 0;
}

TEST(test_perm_count)
{
    _setup_perm_svc();
    ASSERT_EQ(0, ozayn_perm_count(&_perm_svc));
    ozayn_permission_t perm;
    ASSERT_EQ(OZAYN_PERM_OK,
              ozayn_perm_create(&_perm_svc, "p1", "P", "D",
                                OZAYN_AUTHZ_RESOURCE_CORE,
                                OZAYN_AUTHZ_ACTION_READ,
                                OZAYN_AUTHZ_SCOPE_USER, &perm));
    ASSERT_EQ(1, ozayn_perm_count(&_perm_svc));
    ASSERT_EQ(OZAYN_PERM_OK,
              ozayn_perm_create(&_perm_svc, "p2", "P2", "D2",
                                OZAYN_AUTHZ_RESOURCE_MODULE,
                                OZAYN_AUTHZ_ACTION_UPDATE,
                                OZAYN_AUTHZ_SCOPE_SYSTEM, &perm));
    ASSERT_EQ(2, ozayn_perm_count(&_perm_svc));
    _teardown_perm_svc();
    return 0;
}

/* ============================================================
 * 4. PERMISSION LIFECYCLE (STATE TRANSITIONS)
 * ============================================================ */

TEST(test_perm_suspend)
{
    _setup_perm_svc();
    ozayn_permission_t perm;
    ASSERT_EQ(OZAYN_PERM_OK,
              ozayn_perm_create(&_perm_svc, "p1", "P", "D",
                                OZAYN_AUTHZ_RESOURCE_CORE,
                                OZAYN_AUTHZ_ACTION_READ,
                                OZAYN_AUTHZ_SCOPE_USER, &perm));
    ASSERT_EQ(OZAYN_PERM_OK, ozayn_perm_suspend(&_perm_svc, "p1"));
    ASSERT_EQ(OZAYN_PERM_OK, ozayn_perm_get(&_perm_svc, "p1", &perm));
    ASSERT_EQ(OZAYN_PERM_SUSPENDED, perm.state);
    _teardown_perm_svc();
    return 0;
}

TEST(test_perm_suspend_reactivate)
{
    _setup_perm_svc();
    ozayn_permission_t perm;
    ASSERT_EQ(OZAYN_PERM_OK,
              ozayn_perm_create(&_perm_svc, "p1", "P", "D",
                                OZAYN_AUTHZ_RESOURCE_CORE,
                                OZAYN_AUTHZ_ACTION_READ,
                                OZAYN_AUTHZ_SCOPE_USER, &perm));
    ASSERT_EQ(OZAYN_PERM_OK, ozayn_perm_suspend(&_perm_svc, "p1"));
    /* Suspended -> Active (reactivate) */
    ASSERT_EQ(OZAYN_PERM_OK, ozayn_perm_resume(&_perm_svc, "p1"));
    ASSERT_EQ(OZAYN_PERM_OK, ozayn_perm_get(&_perm_svc, "p1", &perm));
    ASSERT_EQ(OZAYN_PERM_ACTIVE, perm.state);
    _teardown_perm_svc();
    return 0;
}

TEST(test_perm_revoke)
{
    _setup_perm_svc();
    ozayn_permission_t perm;
    ASSERT_EQ(OZAYN_PERM_OK,
              ozayn_perm_create(&_perm_svc, "p1", "P", "D",
                                OZAYN_AUTHZ_RESOURCE_CORE,
                                OZAYN_AUTHZ_ACTION_READ,
                                OZAYN_AUTHZ_SCOPE_USER, &perm));
    ASSERT_EQ(OZAYN_PERM_OK, ozayn_perm_revoke(&_perm_svc, "p1"));
    ASSERT_EQ(OZAYN_PERM_OK, ozayn_perm_get(&_perm_svc, "p1", &perm));
    ASSERT_EQ(OZAYN_PERM_REVOKED, perm.state);
    _teardown_perm_svc();
    return 0;
}

TEST(test_perm_archive)
{
    _setup_perm_svc();
    ozayn_permission_t perm;
    ASSERT_EQ(OZAYN_PERM_OK,
              ozayn_perm_create(&_perm_svc, "p1", "P", "D",
                                OZAYN_AUTHZ_RESOURCE_CORE,
                                OZAYN_AUTHZ_ACTION_READ,
                                OZAYN_AUTHZ_SCOPE_USER, &perm));
    ASSERT_EQ(OZAYN_PERM_OK, ozayn_perm_archive(&_perm_svc, "p1"));
    ASSERT_EQ(OZAYN_PERM_OK, ozayn_perm_get(&_perm_svc, "p1", &perm));
    ASSERT_EQ(OZAYN_PERM_ARCHIVED, perm.state);
    _teardown_perm_svc();
    return 0;
}

TEST(test_perm_revoke_then_archive)
{
    _setup_perm_svc();
    ozayn_permission_t perm;
    ASSERT_EQ(OZAYN_PERM_OK,
              ozayn_perm_create(&_perm_svc, "p1", "P", "D",
                                OZAYN_AUTHZ_RESOURCE_CORE,
                                OZAYN_AUTHZ_ACTION_READ,
                                OZAYN_AUTHZ_SCOPE_USER, &perm));
    ASSERT_EQ(OZAYN_PERM_OK, ozayn_perm_revoke(&_perm_svc, "p1"));
    ASSERT_EQ(OZAYN_PERM_OK, ozayn_perm_archive(&_perm_svc, "p1"));
    ASSERT_EQ(OZAYN_PERM_OK, ozayn_perm_get(&_perm_svc, "p1", &perm));
    ASSERT_EQ(OZAYN_PERM_ARCHIVED, perm.state);
    _teardown_perm_svc();
    return 0;
}

TEST(test_perm_suspend_then_revoke)
{
    _setup_perm_svc();
    ozayn_permission_t perm;
    ASSERT_EQ(OZAYN_PERM_OK,
              ozayn_perm_create(&_perm_svc, "p1", "P", "D",
                                OZAYN_AUTHZ_RESOURCE_CORE,
                                OZAYN_AUTHZ_ACTION_READ,
                                OZAYN_AUTHZ_SCOPE_USER, &perm));
    ASSERT_EQ(OZAYN_PERM_OK, ozayn_perm_suspend(&_perm_svc, "p1"));
    ASSERT_EQ(OZAYN_PERM_OK, ozayn_perm_revoke(&_perm_svc, "p1"));
    ASSERT_EQ(OZAYN_PERM_OK, ozayn_perm_get(&_perm_svc, "p1", &perm));
    ASSERT_EQ(OZAYN_PERM_REVOKED, perm.state);
    _teardown_perm_svc();
    return 0;
}

TEST(test_perm_invalid_transition)
{
    _setup_perm_svc();
    ozayn_permission_t perm;
    ASSERT_EQ(OZAYN_PERM_OK,
              ozayn_perm_create(&_perm_svc, "p1", "P", "D",
                                OZAYN_AUTHZ_RESOURCE_CORE,
                                OZAYN_AUTHZ_ACTION_READ,
                                OZAYN_AUTHZ_SCOPE_USER, &perm));
    /* Revoked -> Active is not valid */
    ASSERT_EQ(OZAYN_PERM_OK, ozayn_perm_revoke(&_perm_svc, "p1"));
    ASSERT_EQ(OZAYN_PERM_ERR_STATE_TRANSITION,
              ozayn_perm_suspend(&_perm_svc, "p1"));
    _teardown_perm_svc();
    return 0;
}

TEST(test_perm_version_increments)
{
    _setup_perm_svc();
    ozayn_permission_t perm;
    ASSERT_EQ(OZAYN_PERM_OK,
              ozayn_perm_create(&_perm_svc, "p1", "P", "D",
                                OZAYN_AUTHZ_RESOURCE_CORE,
                                OZAYN_AUTHZ_ACTION_READ,
                                OZAYN_AUTHZ_SCOPE_USER, &perm));
    ASSERT_EQ(1, perm.version);
    ASSERT_EQ(OZAYN_PERM_OK, ozayn_perm_suspend(&_perm_svc, "p1"));
    ozayn_perm_get(&_perm_svc, "p1", &perm);
    ASSERT_EQ(2, perm.version);
    ASSERT_EQ(OZAYN_PERM_OK, ozayn_perm_revoke(&_perm_svc, "p1"));
    ozayn_perm_get(&_perm_svc, "p1", &perm);
    ASSERT_EQ(3, perm.version);
    _teardown_perm_svc();
    return 0;
}

TEST(test_perm_not_found_transitions)
{
    _setup_perm_svc();
    ASSERT_EQ(OZAYN_PERM_ERR_NOT_FOUND,
              ozayn_perm_suspend(&_perm_svc, "nonexistent"));
    ASSERT_EQ(OZAYN_PERM_ERR_NOT_FOUND,
              ozayn_perm_revoke(&_perm_svc, "nonexistent"));
    ASSERT_EQ(OZAYN_PERM_ERR_NOT_FOUND,
              ozayn_perm_archive(&_perm_svc, "nonexistent"));
    _teardown_perm_svc();
    return 0;
}

TEST(test_perm_transition_null)
{
    _setup_perm_svc();
    ASSERT_EQ(OZAYN_PERM_ERR_NULL, ozayn_perm_suspend(NULL, "p1"));
    ASSERT_EQ(OZAYN_PERM_ERR_NULL, ozayn_perm_suspend(&_perm_svc, NULL));
    ASSERT_EQ(OZAYN_PERM_ERR_NULL, ozayn_perm_revoke(NULL, "p1"));
    ASSERT_EQ(OZAYN_PERM_ERR_NULL, ozayn_perm_revoke(&_perm_svc, NULL));
    ASSERT_EQ(OZAYN_PERM_ERR_NULL, ozayn_perm_archive(NULL, "p1"));
    ASSERT_EQ(OZAYN_PERM_ERR_NULL, ozayn_perm_archive(&_perm_svc, NULL));
    _teardown_perm_svc();
    return 0;
}

/* ============================================================
 * 5. PERMISSION MATCHING
 * ============================================================ */

TEST(test_perm_matches_exact)
{
    ozayn_permission_t perm;
    memset(&perm, 0, sizeof(perm));
    perm.resource = OZAYN_AUTHZ_RESOURCE_CORE;
    perm.action = OZAYN_AUTHZ_ACTION_READ;
    perm.scope = OZAYN_AUTHZ_SCOPE_USER;

    ASSERT(ozayn_perm_matches(&perm, OZAYN_AUTHZ_RESOURCE_CORE,
                              OZAYN_AUTHZ_ACTION_READ, OZAYN_AUTHZ_SCOPE_USER));
    return 0;
}

TEST(test_perm_matches_wrong_resource)
{
    ozayn_permission_t perm;
    memset(&perm, 0, sizeof(perm));
    perm.resource = OZAYN_AUTHZ_RESOURCE_CORE;
    perm.action = OZAYN_AUTHZ_ACTION_READ;
    perm.scope = OZAYN_AUTHZ_SCOPE_USER;

    ASSERT(!ozayn_perm_matches(&perm, OZAYN_AUTHZ_RESOURCE_MODULE,
                               OZAYN_AUTHZ_ACTION_READ, OZAYN_AUTHZ_SCOPE_USER));
    return 0;
}

TEST(test_perm_matches_wrong_action)
{
    ozayn_permission_t perm;
    memset(&perm, 0, sizeof(perm));
    perm.resource = OZAYN_AUTHZ_RESOURCE_CORE;
    perm.action = OZAYN_AUTHZ_ACTION_READ;
    perm.scope = OZAYN_AUTHZ_SCOPE_USER;

    ASSERT(!ozayn_perm_matches(&perm, OZAYN_AUTHZ_RESOURCE_CORE,
                               OZAYN_AUTHZ_ACTION_UPDATE, OZAYN_AUTHZ_SCOPE_USER));
    return 0;
}

TEST(test_perm_matches_wrong_scope)
{
    ozayn_permission_t perm;
    memset(&perm, 0, sizeof(perm));
    perm.resource = OZAYN_AUTHZ_RESOURCE_CORE;
    perm.action = OZAYN_AUTHZ_ACTION_READ;
    perm.scope = OZAYN_AUTHZ_SCOPE_USER;

    ASSERT(!ozayn_perm_matches(&perm, OZAYN_AUTHZ_RESOURCE_CORE,
                               OZAYN_AUTHZ_ACTION_READ, OZAYN_AUTHZ_SCOPE_SYSTEM));
    return 0;
}

TEST(test_perm_matches_global_scope)
{
    ozayn_permission_t perm;
    memset(&perm, 0, sizeof(perm));
    perm.resource = OZAYN_AUTHZ_RESOURCE_CORE;
    perm.action = OZAYN_AUTHZ_ACTION_READ;
    perm.scope = OZAYN_AUTHZ_SCOPE_GLOBAL;

    ASSERT(ozayn_perm_matches(&perm, OZAYN_AUTHZ_RESOURCE_CORE,
                              OZAYN_AUTHZ_ACTION_READ, OZAYN_AUTHZ_SCOPE_USER));
    ASSERT(ozayn_perm_matches(&perm, OZAYN_AUTHZ_RESOURCE_CORE,
                              OZAYN_AUTHZ_ACTION_READ, OZAYN_AUTHZ_SCOPE_SYSTEM));
    ASSERT(ozayn_perm_matches(&perm, OZAYN_AUTHZ_RESOURCE_CORE,
                              OZAYN_AUTHZ_ACTION_READ, OZAYN_AUTHZ_SCOPE_DEVICE));
    return 0;
}

TEST(test_perm_matches_null)
{
    ASSERT(!ozayn_perm_matches(NULL, OZAYN_AUTHZ_RESOURCE_CORE,
                               OZAYN_AUTHZ_ACTION_READ, OZAYN_AUTHZ_SCOPE_USER));
    return 0;
}

TEST(test_perm_service_check)
{
    _setup_perm_svc();
    ozayn_permission_t perm;
    ASSERT_EQ(OZAYN_PERM_OK,
              ozayn_perm_create(&_perm_svc, "p1", "P", "D",
                                OZAYN_AUTHZ_RESOURCE_CORE,
                                OZAYN_AUTHZ_ACTION_READ,
                                OZAYN_AUTHZ_SCOPE_USER, &perm));

    ASSERT(ozayn_perm_service_check(&_perm_svc, "p1",
                                     OZAYN_AUTHZ_RESOURCE_CORE,
                                     OZAYN_AUTHZ_ACTION_READ,
                                     OZAYN_AUTHZ_SCOPE_USER));
    ASSERT(!ozayn_perm_service_check(&_perm_svc, "p1",
                                      OZAYN_AUTHZ_RESOURCE_MODULE,
                                      OZAYN_AUTHZ_ACTION_READ,
                                      OZAYN_AUTHZ_SCOPE_USER));
    ASSERT(!ozayn_perm_service_check(&_perm_svc, "nonexistent",
                                      OZAYN_AUTHZ_RESOURCE_CORE,
                                      OZAYN_AUTHZ_ACTION_READ,
                                      OZAYN_AUTHZ_SCOPE_USER));
    _teardown_perm_svc();
    return 0;
}

TEST(test_perm_service_check_suspended)
{
    _setup_perm_svc();
    ozayn_permission_t perm;
    ASSERT_EQ(OZAYN_PERM_OK,
              ozayn_perm_create(&_perm_svc, "p1", "P", "D",
                                OZAYN_AUTHZ_RESOURCE_CORE,
                                OZAYN_AUTHZ_ACTION_READ,
                                OZAYN_AUTHZ_SCOPE_USER, &perm));
    ASSERT_EQ(OZAYN_PERM_OK, ozayn_perm_suspend(&_perm_svc, "p1"));
    ASSERT(!ozayn_perm_service_check(&_perm_svc, "p1",
                                      OZAYN_AUTHZ_RESOURCE_CORE,
                                      OZAYN_AUTHZ_ACTION_READ,
                                      OZAYN_AUTHZ_SCOPE_USER));
    _teardown_perm_svc();
    return 0;
}

TEST(test_perm_service_check_null)
{
    _setup_perm_svc();
    ASSERT(!ozayn_perm_service_check(NULL, "p1",
                                      OZAYN_AUTHZ_RESOURCE_CORE,
                                      OZAYN_AUTHZ_ACTION_READ,
                                      OZAYN_AUTHZ_SCOPE_USER));
    ASSERT(!ozayn_perm_service_check(&_perm_svc, NULL,
                                      OZAYN_AUTHZ_RESOURCE_CORE,
                                      OZAYN_AUTHZ_ACTION_READ,
                                      OZAYN_AUTHZ_SCOPE_USER));
    _teardown_perm_svc();
    return 0;
}

/* ============================================================
 * 6. PROTECTED RESOURCE MANAGEMENT
 * ============================================================ */

TEST(test_protect_resource)
{
    _setup_perm_svc();
    ozayn_protected_resource_t res;
    ozayn_perm_error_t r = ozayn_perm_protect_resource(
        &_perm_svc, "res-1", "core", "/data/secret",
        OZAYN_AUTHZ_SCOPE_USER, 1, 1, &res);
    ASSERT_EQ(OZAYN_PERM_OK, r);
    ASSERT_STR_EQ("res-1", res.id);
    ASSERT_STR_EQ("core", res.resource_type);
    ASSERT_STR_EQ("/data/secret", res.resource_id);
    ASSERT_EQ(OZAYN_AUTHZ_SCOPE_USER, res.required_scope);
    ASSERT(res.requires_authentication);
    ASSERT(res.requires_authorization);
    _teardown_perm_svc();
    return 0;
}

TEST(test_protect_resource_null)
{
    _setup_perm_svc();
    ozayn_protected_resource_t res;
    ASSERT_EQ(OZAYN_PERM_ERR_NULL,
              ozayn_perm_protect_resource(NULL, "r1", "core", NULL,
                                           OZAYN_AUTHZ_SCOPE_USER, 1, 1, &res));
    ASSERT_EQ(OZAYN_PERM_ERR_NULL,
              ozayn_perm_protect_resource(&_perm_svc, NULL, "core", NULL,
                                           OZAYN_AUTHZ_SCOPE_USER, 1, 1, &res));
    ASSERT_EQ(OZAYN_PERM_ERR_NULL,
              ozayn_perm_protect_resource(&_perm_svc, "r1", NULL, NULL,
                                           OZAYN_AUTHZ_SCOPE_USER, 1, 1, &res));
    ASSERT_EQ(OZAYN_PERM_ERR_NULL,
              ozayn_perm_protect_resource(&_perm_svc, "r1", "core", NULL,
                                           OZAYN_AUTHZ_SCOPE_USER, 1, 1, NULL));
    _teardown_perm_svc();
    return 0;
}

TEST(test_protect_resource_duplicate)
{
    _setup_perm_svc();
    ozayn_protected_resource_t res;
    ASSERT_EQ(OZAYN_PERM_OK,
              ozayn_perm_protect_resource(&_perm_svc, "r1", "core", NULL,
                                           OZAYN_AUTHZ_SCOPE_USER, 1, 1, &res));
    ASSERT_EQ(OZAYN_PERM_ERR_ALREADY_EXISTS,
              ozayn_perm_protect_resource(&_perm_svc, "r1", "core", NULL,
                                           OZAYN_AUTHZ_SCOPE_USER, 1, 1, &res));
    _teardown_perm_svc();
    return 0;
}

TEST(test_get_protected_resource)
{
    _setup_perm_svc();
    ozayn_protected_resource_t res;
    ASSERT_EQ(OZAYN_PERM_OK,
              ozayn_perm_protect_resource(&_perm_svc, "r1", "core", "/path",
                                           OZAYN_AUTHZ_SCOPE_USER, 1, 1, &res));

    ozayn_protected_resource_t got;
    ASSERT_EQ(OZAYN_PERM_OK,
              ozayn_perm_get_protected_resource(&_perm_svc, "r1", &got));
    ASSERT_STR_EQ("r1", got.id);
    ASSERT_STR_EQ("core", got.resource_type);
    _teardown_perm_svc();
    return 0;
}

TEST(test_get_protected_resource_not_found)
{
    _setup_perm_svc();
    ozayn_protected_resource_t res;
    ASSERT_EQ(OZAYN_PERM_ERR_NOT_FOUND,
              ozayn_perm_get_protected_resource(&_perm_svc, "nonexistent", &res));
    _teardown_perm_svc();
    return 0;
}

TEST(test_is_protected)
{
    _setup_perm_svc();
    ozayn_protected_resource_t res;
    ASSERT_EQ(OZAYN_PERM_OK,
              ozayn_perm_protect_resource(&_perm_svc, "r1", "core", "/path",
                                           OZAYN_AUTHZ_SCOPE_USER, 1, 1, &res));

    ASSERT(ozayn_perm_is_protected(&_perm_svc, "core", "/path"));
    ASSERT(!ozayn_perm_is_protected(&_perm_svc, "core", "/other"));
    ASSERT(!ozayn_perm_is_protected(&_perm_svc, "module", "/path"));
    _teardown_perm_svc();
    return 0;
}

TEST(test_is_protected_null)
{
    _setup_perm_svc();
    ASSERT(!ozayn_perm_is_protected(NULL, "core", "/path"));
    ASSERT(!ozayn_perm_is_protected(&_perm_svc, NULL, "/path"));
    ASSERT(!ozayn_perm_is_protected(&_perm_svc, "core", NULL));
    _teardown_perm_svc();
    return 0;
}

/* ============================================================
 * 7. POLICY ENFORCEMENT
 * ============================================================ */

TEST(test_enforce_granted)
{
    _setup_perm_svc();
    ozayn_permission_t perm;
    ASSERT_EQ(OZAYN_PERM_OK,
              ozayn_perm_create(&_perm_svc, "p1", "P", "D",
                                OZAYN_AUTHZ_RESOURCE_CORE,
                                OZAYN_AUTHZ_ACTION_READ,
                                OZAYN_AUTHZ_SCOPE_USER, &perm));

    ozayn_enforcement_result_t r = ozayn_perm_enforce(
        &_perm_svc, "p1", "core", "/data",
        OZAYN_AUTHZ_SCOPE_USER);
    ASSERT(r.allowed);
    ASSERT_EQ(OZAYN_PERM_OK, r.error);
    _teardown_perm_svc();
    return 0;
}

TEST(test_enforce_denied_wrong_scope)
{
    _setup_perm_svc();
    ozayn_permission_t perm;
    ASSERT_EQ(OZAYN_PERM_OK,
              ozayn_perm_create(&_perm_svc, "p1", "P", "D",
                                OZAYN_AUTHZ_RESOURCE_CORE,
                                OZAYN_AUTHZ_ACTION_READ,
                                OZAYN_AUTHZ_SCOPE_USER, &perm));

    ozayn_enforcement_result_t r = ozayn_perm_enforce(
        &_perm_svc, "p1", "core", "/data",
        OZAYN_AUTHZ_SCOPE_SYSTEM);
    ASSERT(!r.allowed);
    _teardown_perm_svc();
    return 0;
}

TEST(test_enforce_denied_suspended)
{
    _setup_perm_svc();
    ozayn_permission_t perm;
    ASSERT_EQ(OZAYN_PERM_OK,
              ozayn_perm_create(&_perm_svc, "p1", "P", "D",
                                OZAYN_AUTHZ_RESOURCE_CORE,
                                OZAYN_AUTHZ_ACTION_READ,
                                OZAYN_AUTHZ_SCOPE_USER, &perm));
    ASSERT_EQ(OZAYN_PERM_OK, ozayn_perm_suspend(&_perm_svc, "p1"));

    ozayn_enforcement_result_t r = ozayn_perm_enforce(
        &_perm_svc, "p1", "core", "/data",
        OZAYN_AUTHZ_SCOPE_USER);
    ASSERT(!r.allowed);
    _teardown_perm_svc();
    return 0;
}

TEST(test_enforce_not_found)
{
    _setup_perm_svc();
    ozayn_enforcement_result_t r = ozayn_perm_enforce(
        &_perm_svc, "nonexistent", "core", "/data",
        OZAYN_AUTHZ_SCOPE_USER);
    ASSERT(!r.allowed);
    ASSERT_EQ(OZAYN_PERM_ERR_NOT_FOUND, r.error);
    _teardown_perm_svc();
    return 0;
}

TEST(test_enforce_null)
{
    _setup_perm_svc();
    ozayn_enforcement_result_t r = ozayn_perm_enforce(
        NULL, "p1", "core", "/data", OZAYN_AUTHZ_SCOPE_USER);
    ASSERT(!r.allowed);
    ASSERT_EQ(OZAYN_PERM_ERR_NULL, r.error);
    r = ozayn_perm_enforce(&_perm_svc, NULL, "core", "/data",
                            OZAYN_AUTHZ_SCOPE_USER);
    ASSERT(!r.allowed);
    ASSERT_EQ(OZAYN_PERM_ERR_NULL, r.error);
    r = ozayn_perm_enforce(&_perm_svc, "p1", NULL, "/data",
                            OZAYN_AUTHZ_SCOPE_USER);
    ASSERT(!r.allowed);
    ASSERT_EQ(OZAYN_PERM_ERR_NULL, r.error);
    r = ozayn_perm_enforce(&_perm_svc, "p1", "core", NULL,
                            OZAYN_AUTHZ_SCOPE_USER);
    ASSERT(!r.allowed);
    ASSERT_EQ(OZAYN_PERM_ERR_NULL, r.error);
    _teardown_perm_svc();
    return 0;
}

TEST(test_enforce_protected_resource_scope_check)
{
    _setup_perm_svc();
    ozayn_permission_t perm;
    ASSERT_EQ(OZAYN_PERM_OK,
              ozayn_perm_create(&_perm_svc, "p1", "P", "D",
                                OZAYN_AUTHZ_RESOURCE_CORE,
                                OZAYN_AUTHZ_ACTION_READ,
                                OZAYN_AUTHZ_SCOPE_SYSTEM, &perm));

    ozayn_protected_resource_t res;
    ASSERT_EQ(OZAYN_PERM_OK,
              ozayn_perm_protect_resource(&_perm_svc, "r1", "core", "/secret",
                                           OZAYN_AUTHZ_SCOPE_SYSTEM, 1, 1, &res));

    /* Correct scope - should pass */
    ozayn_enforcement_result_t r = ozayn_perm_enforce(
        &_perm_svc, "p1", "core", "/secret",
        OZAYN_AUTHZ_SCOPE_SYSTEM);
    ASSERT(r.allowed);

    /* Wrong scope - should fail */
    r = ozayn_perm_enforce(&_perm_svc, "p1", "core", "/secret",
                            OZAYN_AUTHZ_SCOPE_USER);
    ASSERT(!r.allowed);
    _teardown_perm_svc();
    return 0;
}

TEST(test_validate_access)
{
    _setup_perm_svc();
    ozayn_permission_t perm;
    ASSERT_EQ(OZAYN_PERM_OK,
              ozayn_perm_create(&_perm_svc, "p1", "P", "D",
                                OZAYN_AUTHZ_RESOURCE_CORE,
                                OZAYN_AUTHZ_ACTION_READ,
                                OZAYN_AUTHZ_SCOPE_USER, &perm));

    ozayn_protected_resource_t res;
    memset(&res, 0, sizeof(res));
    strncpy(res.resource_type, "core", sizeof(res.resource_type) - 1);
    res.required_scope = OZAYN_AUTHZ_SCOPE_USER;

    ASSERT(ozayn_perm_validate_access(&_perm_svc, "p1", &res,
                                       OZAYN_AUTHZ_SCOPE_USER));
    ASSERT(!ozayn_perm_validate_access(&_perm_svc, "p1", &res,
                                        OZAYN_AUTHZ_SCOPE_SYSTEM));
    _teardown_perm_svc();
    return 0;
}

TEST(test_validate_access_null)
{
    _setup_perm_svc();
    ozayn_protected_resource_t res;
    memset(&res, 0, sizeof(res));
    ASSERT(!ozayn_perm_validate_access(NULL, "p1", &res,
                                        OZAYN_AUTHZ_SCOPE_USER));
    ASSERT(!ozayn_perm_validate_access(&_perm_svc, NULL, &res,
                                        OZAYN_AUTHZ_SCOPE_USER));
    ASSERT(!ozayn_perm_validate_access(&_perm_svc, "p1", NULL,
                                        OZAYN_AUTHZ_SCOPE_USER));
    _teardown_perm_svc();
    return 0;
}

/* ============================================================
 * 8. VALIDATION
 * ============================================================ */

TEST(test_validate_perm_id)
{
    ASSERT_EQ(0, ozayn_perm_validate_id("valid-id"));
    ASSERT_EQ(0, ozayn_perm_validate_id("VALID_ID"));
    ASSERT_EQ(0, ozayn_perm_validate_id("test123"));
    ASSERT_EQ(-1, ozayn_perm_validate_id(NULL));
    ASSERT_EQ(-1, ozayn_perm_validate_id(""));
    ASSERT_EQ(-1, ozayn_perm_validate_id("invalid id"));
    ASSERT_EQ(-1, ozayn_perm_validate_id("id@invalid"));
    return 0;
}

TEST(test_validate_perm_state)
{
    ASSERT_EQ(0, ozayn_perm_validate_state(OZAYN_PERM_UNINITIALIZED));
    ASSERT_EQ(0, ozayn_perm_validate_state(OZAYN_PERM_ACTIVE));
    ASSERT_EQ(0, ozayn_perm_validate_state(OZAYN_PERM_SUSPENDED));
    ASSERT_EQ(0, ozayn_perm_validate_state(OZAYN_PERM_REVOKED));
    ASSERT_EQ(0, ozayn_perm_validate_state(OZAYN_PERM_ARCHIVED));
    ASSERT_EQ(-1, ozayn_perm_validate_state((ozayn_perm_state_t)99));
    return 0;
}

TEST(test_validate_perm_transition)
{
    /* Valid transitions */
    ASSERT_EQ(0, ozayn_perm_validate_transition(OZAYN_PERM_UNINITIALIZED,
                                                 OZAYN_PERM_ACTIVE));
    ASSERT_EQ(0, ozayn_perm_validate_transition(OZAYN_PERM_ACTIVE,
                                                 OZAYN_PERM_SUSPENDED));
    ASSERT_EQ(0, ozayn_perm_validate_transition(OZAYN_PERM_ACTIVE,
                                                 OZAYN_PERM_REVOKED));
    ASSERT_EQ(0, ozayn_perm_validate_transition(OZAYN_PERM_ACTIVE,
                                                 OZAYN_PERM_ARCHIVED));
    ASSERT_EQ(0, ozayn_perm_validate_transition(OZAYN_PERM_SUSPENDED,
                                                 OZAYN_PERM_ACTIVE));
    ASSERT_EQ(0, ozayn_perm_validate_transition(OZAYN_PERM_SUSPENDED,
                                                 OZAYN_PERM_REVOKED));
    ASSERT_EQ(0, ozayn_perm_validate_transition(OZAYN_PERM_SUSPENDED,
                                                 OZAYN_PERM_ARCHIVED));
    ASSERT_EQ(0, ozayn_perm_validate_transition(OZAYN_PERM_REVOKED,
                                                 OZAYN_PERM_ARCHIVED));
    /* Invalid transitions */
    ASSERT_EQ(-1, ozayn_perm_validate_transition(OZAYN_PERM_REVOKED,
                                                  OZAYN_PERM_ACTIVE));
    ASSERT_EQ(-1, ozayn_perm_validate_transition(OZAYN_PERM_ARCHIVED,
                                                  OZAYN_PERM_ACTIVE));
    ASSERT_EQ(-1, ozayn_perm_validate_transition(OZAYN_PERM_UNINITIALIZED,
                                                  OZAYN_PERM_SUSPENDED));
    return 0;
}

/* ============================================================
 * 9. NAME HELPERS
 * ============================================================ */

TEST(test_error_names)
{
    ASSERT_STR_EQ("OK", ozayn_perm_error_name(OZAYN_PERM_OK));
    ASSERT_STR_EQ("NULL", ozayn_perm_error_name(OZAYN_PERM_ERR_NULL));
    ASSERT_STR_EQ("NOT_INITIALIZED",
                  ozayn_perm_error_name(OZAYN_PERM_ERR_NOT_INITIALIZED));
    ASSERT_STR_EQ("NOT_FOUND",
                  ozayn_perm_error_name(OZAYN_PERM_ERR_NOT_FOUND));
    ASSERT_STR_EQ("ALREADY_EXISTS",
                  ozayn_perm_error_name(OZAYN_PERM_ERR_ALREADY_EXISTS));
    ASSERT_STR_EQ("INVALID", ozayn_perm_error_name(OZAYN_PERM_ERR_INVALID));
    ASSERT_STR_EQ("ID_INVALID",
                  ozayn_perm_error_name(OZAYN_PERM_ERR_ID_INVALID));
    ASSERT_STR_EQ("STATE_INVALID",
                  ozayn_perm_error_name(OZAYN_PERM_ERR_STATE_INVALID));
    ASSERT_STR_EQ("STATE_TRANSITION",
                  ozayn_perm_error_name(OZAYN_PERM_ERR_STATE_TRANSITION));
    ASSERT_STR_EQ("SCOPE_INVALID",
                  ozayn_perm_error_name(OZAYN_PERM_ERR_SCOPE_INVALID));
    ASSERT_STR_EQ("LIMIT_REACHED",
                  ozayn_perm_error_name(OZAYN_PERM_ERR_LIMIT_REACHED));
    ASSERT_STR_EQ("RESOURCE_INVALID",
                  ozayn_perm_error_name(OZAYN_PERM_ERR_RESOURCE_INVALID));
    ASSERT_STR_EQ("ACTION_INVALID",
                  ozayn_perm_error_name(OZAYN_PERM_ERR_ACTION_INVALID));
    ASSERT_STR_EQ("DENIED", ozayn_perm_error_name(OZAYN_PERM_ERR_DENIED));
    ASSERT_STR_EQ("ENFORCEMENT_FAILED",
                  ozayn_perm_error_name(OZAYN_PERM_ERR_ENFORCEMENT_FAILED));
    ASSERT_STR_EQ("UNKNOWN",
                  ozayn_perm_error_name((ozayn_perm_error_t)999));
    return 0;
}

TEST(test_state_names)
{
    ASSERT_STR_EQ("UNINITIALIZED",
                  ozayn_perm_state_name(OZAYN_PERM_UNINITIALIZED));
    ASSERT_STR_EQ("ACTIVE", ozayn_perm_state_name(OZAYN_PERM_ACTIVE));
    ASSERT_STR_EQ("SUSPENDED", ozayn_perm_state_name(OZAYN_PERM_SUSPENDED));
    ASSERT_STR_EQ("REVOKED", ozayn_perm_state_name(OZAYN_PERM_REVOKED));
    ASSERT_STR_EQ("ARCHIVED", ozayn_perm_state_name(OZAYN_PERM_ARCHIVED));
    ASSERT_STR_EQ("UNKNOWN",
                  ozayn_perm_state_name((ozayn_perm_state_t)99));
    return 0;
}

/* ============================================================
 * 10. SECURITY TESTS
 * ============================================================ */

TEST(test_suspended_perm_does_not_grant)
{
    _setup_perm_svc();
    ozayn_permission_t perm;
    ASSERT_EQ(OZAYN_PERM_OK,
              ozayn_perm_create(&_perm_svc, "p1", "P", "D",
                                OZAYN_AUTHZ_RESOURCE_CORE,
                                OZAYN_AUTHZ_ACTION_READ,
                                OZAYN_AUTHZ_SCOPE_USER, &perm));
    ASSERT_EQ(OZAYN_PERM_OK, ozayn_perm_suspend(&_perm_svc, "p1"));
    ASSERT(!ozayn_perm_service_check(&_perm_svc, "p1",
                                      OZAYN_AUTHZ_RESOURCE_CORE,
                                      OZAYN_AUTHZ_ACTION_READ,
                                      OZAYN_AUTHZ_SCOPE_USER));
    _teardown_perm_svc();
    return 0;
}

TEST(test_revoked_perm_does_not_grant)
{
    _setup_perm_svc();
    ozayn_permission_t perm;
    ASSERT_EQ(OZAYN_PERM_OK,
              ozayn_perm_create(&_perm_svc, "p1", "P", "D",
                                OZAYN_AUTHZ_RESOURCE_CORE,
                                OZAYN_AUTHZ_ACTION_READ,
                                OZAYN_AUTHZ_SCOPE_USER, &perm));
    ASSERT_EQ(OZAYN_PERM_OK, ozayn_perm_revoke(&_perm_svc, "p1"));
    ASSERT(!ozayn_perm_service_check(&_perm_svc, "p1",
                                      OZAYN_AUTHZ_RESOURCE_CORE,
                                      OZAYN_AUTHZ_ACTION_READ,
                                      OZAYN_AUTHZ_SCOPE_USER));
    _teardown_perm_svc();
    return 0;
}

TEST(test_archived_perm_does_not_grant)
{
    _setup_perm_svc();
    ozayn_permission_t perm;
    ASSERT_EQ(OZAYN_PERM_OK,
              ozayn_perm_create(&_perm_svc, "p1", "P", "D",
                                OZAYN_AUTHZ_RESOURCE_CORE,
                                OZAYN_AUTHZ_ACTION_READ,
                                OZAYN_AUTHZ_SCOPE_USER, &perm));
    ASSERT_EQ(OZAYN_PERM_OK, ozayn_perm_archive(&_perm_svc, "p1"));
    ASSERT(!ozayn_perm_service_check(&_perm_svc, "p1",
                                      OZAYN_AUTHZ_RESOURCE_CORE,
                                      OZAYN_AUTHZ_ACTION_READ,
                                      OZAYN_AUTHZ_SCOPE_USER));
    _teardown_perm_svc();
    return 0;
}

TEST(test_scope_escalation_prevented)
{
    _setup_perm_svc();
    ozayn_permission_t perm;
    ASSERT_EQ(OZAYN_PERM_OK,
              ozayn_perm_create(&_perm_svc, "p1", "P", "D",
                                OZAYN_AUTHZ_RESOURCE_CORE,
                                OZAYN_AUTHZ_ACTION_READ,
                                OZAYN_AUTHZ_SCOPE_USER, &perm));
    /* User scope cannot grant system access */
    ASSERT(!ozayn_perm_service_check(&_perm_svc, "p1",
                                      OZAYN_AUTHZ_RESOURCE_CORE,
                                      OZAYN_AUTHZ_ACTION_READ,
                                      OZAYN_AUTHZ_SCOPE_SYSTEM));
    _teardown_perm_svc();
    return 0;
}

TEST(test_no_hardcoded_superuser)
{
    _setup_perm_svc();
    /* No permission should automatically grant all access */
    ozayn_permission_t perm;
    ASSERT_EQ(OZAYN_PERM_OK,
              ozayn_perm_create(&_perm_svc, "p1", "Admin", "Admin perm",
                                OZAYN_AUTHZ_RESOURCE_CORE,
                                OZAYN_AUTHZ_ACTION_READ,
                                OZAYN_AUTHZ_SCOPE_USER, &perm));

    /* Cannot access system scope */
    ASSERT(!ozayn_perm_service_check(&_perm_svc, "p1",
                                      OZAYN_AUTHZ_RESOURCE_SYSTEM,
                                      OZAYN_AUTHZ_ACTION_READ,
                                      OZAYN_AUTHZ_SCOPE_SYSTEM));
    /* Cannot access different resource */
    ASSERT(!ozayn_perm_service_check(&_perm_svc, "p1",
                                      OZAYN_AUTHZ_RESOURCE_DEVICE,
                                      OZAYN_AUTHZ_ACTION_READ,
                                      OZAYN_AUTHZ_SCOPE_USER));
    _teardown_perm_svc();
    return 0;
}

TEST(test_no_bypass_inactive_perms)
{
    _setup_perm_svc();
    ozayn_permission_t perm;
    ASSERT_EQ(OZAYN_PERM_OK,
              ozayn_perm_create(&_perm_svc, "p1", "P", "D",
                                OZAYN_AUTHZ_RESOURCE_CORE,
                                OZAYN_AUTHZ_ACTION_READ,
                                OZAYN_AUTHZ_SCOPE_USER, &perm));
    ASSERT_EQ(OZAYN_PERM_OK, ozayn_perm_suspend(&_perm_svc, "p1"));

    /* Enforcement should deny suspended perms */
    ozayn_enforcement_result_t r = ozayn_perm_enforce(
        &_perm_svc, "p1", "core", "/data", OZAYN_AUTHZ_SCOPE_USER);
    ASSERT(!r.allowed);
    _teardown_perm_svc();
    return 0;
}

/* ============================================================
 * 11. LIMIT TEST
 * ============================================================ */

TEST(test_perm_limit_reached)
{
    _setup_perm_svc();
    ozayn_permission_t perm;
    for (int i = 0; i < OZAYN_PERM_MAX_PERMS; i++) {
        char id[32];
        snprintf(id, sizeof(id), "perm-%d", i);
        ASSERT_EQ(OZAYN_PERM_OK,
                  ozayn_perm_create(&_perm_svc, id, NULL, NULL,
                                    OZAYN_AUTHZ_RESOURCE_CORE,
                                    OZAYN_AUTHZ_ACTION_READ,
                                    OZAYN_AUTHZ_SCOPE_USER, &perm));
    }
    ASSERT_EQ(OZAYN_PERM_MAX_PERMS, ozayn_perm_count(&_perm_svc));
    ASSERT_EQ(OZAYN_PERM_ERR_LIMIT_REACHED,
              ozayn_perm_create(&_perm_svc, "overflow", NULL, NULL,
                                OZAYN_AUTHZ_RESOURCE_CORE,
                                OZAYN_AUTHZ_ACTION_READ,
                                OZAYN_AUTHZ_SCOPE_USER, &perm));
    _teardown_perm_svc();
    return 0;
}

/* ============================================================
 * TEST REGISTRATION
 * ============================================================ */

int run_permission_tests(void)
{
    printf("\n  --- PERMISSION MANAGEMENT TESTS ---\n");

    /* 1. Service lifecycle */
    RUN(test_service_init);
    RUN(test_service_init_null);
    RUN(test_service_shutdown);
    RUN(test_service_shutdown_null);
    RUN(test_service_not_initialized);

    /* 2. Permission creation */
    RUN(test_perm_create_basic);
    RUN(test_perm_create_null);
    RUN(test_perm_create_invalid_id);
    RUN(test_perm_create_duplicate);
    RUN(test_perm_create_unknown_resource);
    RUN(test_perm_create_unknown_action);
    RUN(test_perm_create_unknown_scope);
    RUN(test_perm_create_name_defaults_to_id);
    RUN(test_perm_create_all_scopes);
    RUN(test_perm_create_all_resources);
    RUN(test_perm_create_all_actions);

    /* 3. Permission get / exists */
    RUN(test_perm_get);
    RUN(test_perm_get_not_found);
    RUN(test_perm_get_null);
    RUN(test_perm_exists);
    RUN(test_perm_count);

    /* 4. Permission lifecycle (state transitions) */
    RUN(test_perm_suspend);
    RUN(test_perm_suspend_reactivate);
    RUN(test_perm_revoke);
    RUN(test_perm_archive);
    RUN(test_perm_revoke_then_archive);
    RUN(test_perm_suspend_then_revoke);
    RUN(test_perm_invalid_transition);
    RUN(test_perm_version_increments);
    RUN(test_perm_not_found_transitions);
    RUN(test_perm_transition_null);

    /* 5. Permission matching */
    RUN(test_perm_matches_exact);
    RUN(test_perm_matches_wrong_resource);
    RUN(test_perm_matches_wrong_action);
    RUN(test_perm_matches_wrong_scope);
    RUN(test_perm_matches_global_scope);
    RUN(test_perm_matches_null);
    RUN(test_perm_service_check);
    RUN(test_perm_service_check_suspended);
    RUN(test_perm_service_check_null);

    /* 6. Protected resource management */
    RUN(test_protect_resource);
    RUN(test_protect_resource_null);
    RUN(test_protect_resource_duplicate);
    RUN(test_get_protected_resource);
    RUN(test_get_protected_resource_not_found);
    RUN(test_is_protected);
    RUN(test_is_protected_null);

    /* 7. Policy enforcement */
    RUN(test_enforce_granted);
    RUN(test_enforce_denied_wrong_scope);
    RUN(test_enforce_denied_suspended);
    RUN(test_enforce_not_found);
    RUN(test_enforce_null);
    RUN(test_enforce_protected_resource_scope_check);
    RUN(test_validate_access);
    RUN(test_validate_access_null);

    /* 8. Validation */
    RUN(test_validate_perm_id);
    RUN(test_validate_perm_state);
    RUN(test_validate_perm_transition);

    /* 9. Name helpers */
    RUN(test_error_names);
    RUN(test_state_names);

    /* 10. Security tests */
    RUN(test_suspended_perm_does_not_grant);
    RUN(test_revoked_perm_does_not_grant);
    RUN(test_archived_perm_does_not_grant);
    RUN(test_scope_escalation_prevented);
    RUN(test_no_hardcoded_superuser);
    RUN(test_no_bypass_inactive_perms);

    /* 11. Limits */
    RUN(test_perm_limit_reached);

    SUITE_END();
    return _tf_suite_fail;
}
