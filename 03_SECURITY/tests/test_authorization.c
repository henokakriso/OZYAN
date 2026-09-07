#include "../../tests/test_framework.h"
#include "../authorization.h"
#include "../session_management.h"
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
static ozayn_sess_service_t        _sess_svc;
static ozayn_authz_service_t       _authz_svc;

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
    ozayn_authz_service_shutdown(&_authz_svc);
    ozayn_sess_service_shutdown(&_sess_svc);
    ozayn_id_service_shutdown(&_id_svc);
    ozayn_vault_shutdown(&_vault);
    ozayn_kl_shutdown(&_kl);
    ozayn_sp_shutdown(&_stor);
    ozayn_prot_shutdown(&_prot);
}

static void _init_session_svc(void)
{
    ozayn_sess_service_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.identity_service = &_id_svc;
    cfg.policy = ozayn_sess_test_policy();
    ozayn_sess_service_init(&_sess_svc, &cfg);
}

static void _init_authz_svc(void)
{
    ozayn_authz_service_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.session_service = &_sess_svc;
    cfg.identity_service = &_id_svc;
    ozayn_authz_service_init(&_authz_svc, &cfg);
}

static ozayn_identity_t _create_identity(const char *label)
{
    ozayn_identity_t id_out;
    memset(&id_out, 0, sizeof(id_out));
    ozayn_id_create(&_id_svc, OZAYN_ID_TYPE_USER, label,
                     OZAYN_ID_SCOPE_USER, "test", &id_out);
    return id_out;
}

static ozayn_authn_response_t _make_auth_response(const char *identity_id)
{
    ozayn_authn_response_t resp;
    memset(&resp, 0, sizeof(resp));
    resp.result = OZAYN_AuthN_RESULT_SUCCESS;
    resp.verification = OZAYN_AuthN_VERIFY_VERIFIED;
    strncpy(resp.identity_id, identity_id, sizeof(resp.identity_id) - 1);
    resp.method = OZAYN_AuthN_METHOD_PASSWORD;
    resp.auth_time = time(NULL);
    return resp;
}

static ozayn_sess_t _create_session_for(const char *label)
{
    ozayn_identity_t id = _create_identity(label);
    ozayn_authn_response_t resp = _make_auth_response(id.id);
    ozayn_sess_t session;
    memset(&session, 0, sizeof(session));
    ozayn_sess_create(&_sess_svc, &resp, &session);
    return session;
}

static ozayn_authz_request_t _make_request(const char *session_id,
                                            const char *resource_type,
                                            const char *action)
{
    ozayn_authz_request_t req;
    memset(&req, 0, sizeof(req));
    strncpy(req.session_id, session_id, sizeof(req.session_id) - 1);
    strncpy(req.resource_type, resource_type, sizeof(req.resource_type) - 1);
    strncpy(req.action, action, sizeof(req.action) - 1);
    return req;
}

/* ============================================================
 * 1. SERVICE LIFECYCLE
 * ============================================================ */

TEST(test_service_init)
{
    _setup_deps();
    _init_session_svc();
    _init_authz_svc();
    ASSERT(ozayn_authz_service_is_initialized(&_authz_svc));
    _teardown_deps();
    return 0;
}

TEST(test_service_init_null)
{
    ASSERT_EQ(OZAYN_AUTHZ_ERR_NULL,
              ozayn_authz_service_init(NULL, NULL));
    return 0;
}

TEST(test_service_init_null_config)
{
    ozayn_authz_service_t svc;
    ASSERT_EQ(OZAYN_AUTHZ_ERR_NULL,
              ozayn_authz_service_init(&svc, NULL));
    return 0;
}

TEST(test_service_init_no_session_service)
{
    ozayn_authz_service_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    ozayn_authz_service_t svc;
    ASSERT_EQ(OZAYN_AUTHZ_ERR_INVALID,
              ozayn_authz_service_init(&svc, &cfg));
    return 0;
}

TEST(test_service_init_no_identity_service)
{
    _setup_deps();
    _init_session_svc();
    ozayn_authz_service_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.session_service = &_sess_svc;
    ozayn_authz_service_t svc;
    ASSERT_EQ(OZAYN_AUTHZ_ERR_INVALID,
              ozayn_authz_service_init(&svc, &cfg));
    _teardown_deps();
    return 0;
}

TEST(test_service_shutdown)
{
    _setup_deps();
    _init_session_svc();
    _init_authz_svc();
    ozayn_authz_service_shutdown(&_authz_svc);
    ASSERT(!ozayn_authz_service_is_initialized(&_authz_svc));
    _teardown_deps();
    return 0;
}

TEST(test_service_shutdown_null)
{
    ozayn_authz_service_shutdown(NULL);
    return 0;
}

/* ============================================================
 * 2. PROVIDER MANAGEMENT
 * ============================================================ */

TEST(test_register_provider)
{
    _setup_deps();
    _init_session_svc();
    _init_authz_svc();
    ozayn_authz_policy_provider_t *p = ozayn_authz_test_provider_create();
    ASSERT_EQ(OZAYN_AUTHZ_OK,
              ozayn_authz_register_provider(&_authz_svc, p));
    ASSERT_EQ(1, ozayn_authz_service_provider_count(&_authz_svc));
    ozayn_authz_test_provider_destroy(p);
    _teardown_deps();
    return 0;
}

TEST(test_register_provider_null)
{
    _setup_deps();
    _init_session_svc();
    _init_authz_svc();
    ASSERT_EQ(OZAYN_AUTHZ_ERR_NULL,
              ozayn_authz_register_provider(NULL, NULL));
    ozayn_authz_test_provider_destroy(NULL);
    _teardown_deps();
    return 0;
}

TEST(test_register_provider_not_initialized)
{
    ozayn_authz_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_authz_policy_provider_t *p = ozayn_authz_test_provider_create();
    ASSERT_EQ(OZAYN_AUTHZ_ERR_NOT_INITIALIZED,
              ozayn_authz_register_provider(&svc, p));
    ozayn_authz_test_provider_destroy(p);
    return 0;
}

TEST(test_register_provider_no_ops)
{
    _setup_deps();
    _init_session_svc();
    _init_authz_svc();
    ozayn_authz_policy_provider_t p;
    memset(&p, 0, sizeof(p));
    p.name = "no_ops";
    p.ops = NULL;
    ASSERT_EQ(OZAYN_AUTHZ_ERR_INVALID,
              ozayn_authz_register_provider(&_authz_svc, &p));
    _teardown_deps();
    return 0;
}

TEST(test_register_provider_duplicate)
{
    _setup_deps();
    _init_session_svc();
    _init_authz_svc();
    ozayn_authz_policy_provider_t *p = ozayn_authz_test_provider_create();
    ASSERT_EQ(OZAYN_AUTHZ_OK,
              ozayn_authz_register_provider(&_authz_svc, p));
    ASSERT_EQ(OZAYN_AUTHZ_ERR_INVALID,
              ozayn_authz_register_provider(&_authz_svc, p));
    ozayn_authz_test_provider_destroy(p);
    _teardown_deps();
    return 0;
}

TEST(test_unregister_provider)
{
    _setup_deps();
    _init_session_svc();
    _init_authz_svc();
    ozayn_authz_policy_provider_t *p = ozayn_authz_test_provider_create();
    ozayn_authz_register_provider(&_authz_svc, p);
    ASSERT_EQ(OZAYN_AUTHZ_OK,
              ozayn_authz_unregister_provider(&_authz_svc, p));
    ASSERT_EQ(0, ozayn_authz_service_provider_count(&_authz_svc));
    ozayn_authz_test_provider_destroy(p);
    _teardown_deps();
    return 0;
}

TEST(test_unregister_provider_not_found)
{
    _setup_deps();
    _init_session_svc();
    _init_authz_svc();
    ozayn_authz_policy_provider_t *p = ozayn_authz_test_provider_create();
    ASSERT_EQ(OZAYN_AUTHZ_ERR_NOT_FOUND,
              ozayn_authz_unregister_provider(&_authz_svc, p));
    ozayn_authz_test_provider_destroy(p);
    _teardown_deps();
    return 0;
}

TEST(test_unregister_provider_null)
{
    _setup_deps();
    _init_session_svc();
    _init_authz_svc();
    ASSERT_EQ(OZAYN_AUTHZ_ERR_NULL,
              ozayn_authz_unregister_provider(NULL, NULL));
    _teardown_deps();
    return 0;
}

/* ============================================================
 * 3. REQUEST VALIDATION
 * ============================================================ */

TEST(test_validate_request_valid)
{
    ozayn_authz_request_t req = _make_request("sess1", "document", "read");
    ASSERT_EQ(0, ozayn_authz_validate_request(&req));
    return 0;
}

TEST(test_validate_request_null)
{
    ASSERT_EQ(-1, ozayn_authz_validate_request(NULL));
    return 0;
}

TEST(test_validate_request_empty_session)
{
    ozayn_authz_request_t req = _make_request("", "document", "read");
    ASSERT_EQ(-1, ozayn_authz_validate_request(&req));
    return 0;
}

TEST(test_validate_request_empty_resource_type)
{
    ozayn_authz_request_t req = _make_request("sess1", "", "read");
    ASSERT_EQ(-1, ozayn_authz_validate_request(&req));
    return 0;
}

TEST(test_validate_request_empty_action)
{
    ozayn_authz_request_t req = _make_request("sess1", "document", "");
    ASSERT_EQ(-1, ozayn_authz_validate_request(&req));
    return 0;
}

TEST(test_validate_request_invalid_resource_type)
{
    ozayn_authz_request_t req = _make_request("sess1", "invalid_type", "read");
    ASSERT_EQ(-1, ozayn_authz_validate_request(&req));
    return 0;
}

TEST(test_validate_request_invalid_action)
{
    ozayn_authz_request_t req = _make_request("sess1", "document", "fly");
    ASSERT_EQ(-1, ozayn_authz_validate_request(&req));
    return 0;
}

TEST(test_validate_request_invalid_scope)
{
    ozayn_authz_request_t req = _make_request("sess1", "document", "read");
    strncpy(req.scope, "bad_scope", sizeof(req.scope) - 1);
    ASSERT_EQ(-1, ozayn_authz_validate_request(&req));
    return 0;
}

TEST(test_validate_request_with_valid_scope)
{
    ozayn_authz_request_t req = _make_request("sess1", "document", "read");
    strncpy(req.scope, "user", sizeof(req.scope) - 1);
    ASSERT_EQ(0, ozayn_authz_validate_request(&req));
    return 0;
}

TEST(test_validate_request_without_scope)
{
    ozayn_authz_request_t req = _make_request("sess1", "document", "read");
    req.scope[0] = '\0';
    ASSERT_EQ(0, ozayn_authz_validate_request(&req));
    return 0;
}

TEST(test_validate_resource_type_valid)
{
    ASSERT_EQ(0, ozayn_authz_validate_resource_type("core"));
    ASSERT_EQ(0, ozayn_authz_validate_resource_type("module"));
    ASSERT_EQ(0, ozayn_authz_validate_resource_type("document"));
    ASSERT_EQ(0, ozayn_authz_validate_resource_type("system"));
    ASSERT_EQ(0, ozayn_authz_validate_resource_type("identity"));
    return 0;
}

TEST(test_validate_resource_type_invalid)
{
    ASSERT_EQ(-1, ozayn_authz_validate_resource_type(NULL));
    ASSERT_EQ(-1, ozayn_authz_validate_resource_type(""));
    ASSERT_EQ(-1, ozayn_authz_validate_resource_type("nonexistent"));
    return 0;
}

TEST(test_validate_action_valid)
{
    ASSERT_EQ(0, ozayn_authz_validate_action("read"));
    ASSERT_EQ(0, ozayn_authz_validate_action("create"));
    ASSERT_EQ(0, ozayn_authz_validate_action("update"));
    ASSERT_EQ(0, ozayn_authz_validate_action("delete"));
    ASSERT_EQ(0, ozayn_authz_validate_action("execute"));
    ASSERT_EQ(0, ozayn_authz_validate_action("control"));
    ASSERT_EQ(0, ozayn_authz_validate_action("configure"));
    ASSERT_EQ(0, ozayn_authz_validate_action("install"));
    ASSERT_EQ(0, ozayn_authz_validate_action("uninstall"));
    return 0;
}

TEST(test_validate_action_invalid)
{
    ASSERT_EQ(-1, ozayn_authz_validate_action(NULL));
    ASSERT_EQ(-1, ozayn_authz_validate_action(""));
    ASSERT_EQ(-1, ozayn_authz_validate_action("fly"));
    return 0;
}

TEST(test_validate_scope_valid)
{
    ASSERT_EQ(0, ozayn_authz_validate_scope("system"));
    ASSERT_EQ(0, ozayn_authz_validate_scope("user"));
    ASSERT_EQ(0, ozayn_authz_validate_scope("device"));
    ASSERT_EQ(0, ozayn_authz_validate_scope("module"));
    ASSERT_EQ(0, ozayn_authz_validate_scope("service"));
    ASSERT_EQ(0, ozayn_authz_validate_scope("global"));
    return 0;
}

TEST(test_validate_scope_invalid)
{
    ASSERT_EQ(-1, ozayn_authz_validate_scope(NULL));
    ASSERT_EQ(-1, ozayn_authz_validate_scope(""));
    ASSERT_EQ(-1, ozayn_authz_validate_scope("world"));
    return 0;
}

/* ============================================================
 * 4. SESSION INTEGRATION
 * ============================================================ */

TEST(test_active_session_authorize)
{
    _setup_deps();
    _init_session_svc();
    _init_authz_svc();
    ozayn_authz_policy_provider_t *p = ozayn_authz_test_provider_create();
    ozayn_authz_register_provider(&_authz_svc, p);
    ozayn_authz_test_provider_set_result(p, ozayn_authz_make_allow());

    ozayn_identity_t id = _create_identity("alice");
    ozayn_authn_response_t resp = _make_auth_response(id.id);
    ozayn_sess_t session;
    ozayn_sess_create(&_sess_svc, &resp, &session);

    ozayn_authz_request_t req = _make_request(session.id, "document", "read");
    ozayn_authz_result_t result = ozayn_authz_authorize(&_authz_svc, &req);
    ASSERT_EQ(OZAYN_AUTHZ_DECISION_ALLOW, result.decision);

    ozayn_authz_test_provider_destroy(p);
    _teardown_deps();
    return 0;
}

TEST(test_expired_session_denies)
{
    _setup_deps();

    ozayn_sess_service_config_t scfg;
    memset(&scfg, 0, sizeof(scfg));
    scfg.identity_service = &_id_svc;
    scfg.policy = ozayn_sess_test_policy();
    scfg.policy.idle_timeout_seconds = 1;
    scfg.policy.absolute_lifetime_seconds = 300;
    ozayn_sess_service_init(&_sess_svc, &scfg);

    _init_authz_svc();
    ozayn_authz_policy_provider_t *p = ozayn_authz_test_provider_create();
    ozayn_authz_register_provider(&_authz_svc, p);

    ozayn_identity_t id = _create_identity("alice");
    ozayn_authn_response_t resp = _make_auth_response(id.id);
    resp.auth_time = time(NULL) - 10;
    ozayn_sess_t session;
    ozayn_sess_create(&_sess_svc, &resp, &session);

    ozayn_authz_request_t req = _make_request(session.id, "document", "read");
    ozayn_authz_result_t result = ozayn_authz_authorize(&_authz_svc, &req);
    ASSERT_EQ(OZAYN_AUTHZ_DECISION_DENY, result.decision);
    ASSERT_EQ(OZAYN_AUTHZ_DENY_SESSION_EXPIRED, result.reason);

    ozayn_authz_test_provider_destroy(p);
    _teardown_deps();
    return 0;
}

TEST(test_revoked_session_denies)
{
    _setup_deps();
    _init_session_svc();
    _init_authz_svc();
    ozayn_authz_policy_provider_t *p = ozayn_authz_test_provider_create();
    ozayn_authz_register_provider(&_authz_svc, p);

    ozayn_identity_t id = _create_identity("alice");
    ozayn_authn_response_t resp = _make_auth_response(id.id);
    ozayn_sess_t session;
    ozayn_sess_create(&_sess_svc, &resp, &session);
    ozayn_sess_revoke(&_sess_svc, session.id);

    ozayn_authz_request_t req = _make_request(session.id, "document", "read");
    ozayn_authz_result_t result = ozayn_authz_authorize(&_authz_svc, &req);
    ASSERT_EQ(OZAYN_AUTHZ_DECISION_DENY, result.decision);
    ASSERT_EQ(OZAYN_AUTHZ_DENY_SESSION_REVOKED, result.reason);

    ozayn_authz_test_provider_destroy(p);
    _teardown_deps();
    return 0;
}

TEST(test_terminated_session_denies)
{
    _setup_deps();
    _init_session_svc();
    _init_authz_svc();
    ozayn_authz_policy_provider_t *p = ozayn_authz_test_provider_create();
    ozayn_authz_register_provider(&_authz_svc, p);

    ozayn_identity_t id = _create_identity("alice");
    ozayn_authn_response_t resp = _make_auth_response(id.id);
    ozayn_sess_t session;
    ozayn_sess_create(&_sess_svc, &resp, &session);
    ozayn_sess_terminate(&_sess_svc, session.id);

    ozayn_authz_request_t req = _make_request(session.id, "document", "read");
    ozayn_authz_result_t result = ozayn_authz_authorize(&_authz_svc, &req);
    ASSERT_EQ(OZAYN_AUTHZ_DECISION_DENY, result.decision);
    ASSERT_EQ(OZAYN_AUTHZ_DENY_SESSION_TERMINATED, result.reason);

    ozayn_authz_test_provider_destroy(p);
    _teardown_deps();
    return 0;
}

TEST(test_invalid_session_denies)
{
    _setup_deps();
    _init_session_svc();
    _init_authz_svc();
    ozayn_authz_policy_provider_t *p = ozayn_authz_test_provider_create();
    ozayn_authz_register_provider(&_authz_svc, p);

    ozayn_authz_request_t req = _make_request("nonexistent_session", "document", "read");
    ozayn_authz_result_t result = ozayn_authz_authorize(&_authz_svc, &req);
    ASSERT_EQ(OZAYN_AUTHZ_DECISION_DENY, result.decision);
    ASSERT_EQ(OZAYN_AUTHZ_DENY_SESSION_INVALID, result.reason);

    ozayn_authz_test_provider_destroy(p);
    _teardown_deps();
    return 0;
}

TEST(test_missing_session_denies)
{
    _setup_deps();
    _init_session_svc();
    _init_authz_svc();
    ozayn_authz_policy_provider_t *p = ozayn_authz_test_provider_create();
    ozayn_authz_register_provider(&_authz_svc, p);

    ozayn_authz_request_t req = _make_request("", "document", "read");
    ozayn_authz_result_t result = ozayn_authz_authorize(&_authz_svc, &req);
    ASSERT_EQ(OZAYN_AUTHZ_DECISION_DENY, result.decision);

    ozayn_authz_test_provider_destroy(p);
    _teardown_deps();
    return 0;
}

/* ============================================================
 * 5. IDENTITY INTEGRATION
 * ============================================================ */

TEST(test_suspended_identity_denies)
{
    _setup_deps();
    _init_session_svc();
    _init_authz_svc();
    ozayn_authz_policy_provider_t *p = ozayn_authz_test_provider_create();
    ozayn_authz_register_provider(&_authz_svc, p);

    ozayn_identity_t id = _create_identity("alice");
    ozayn_authn_response_t resp = _make_auth_response(id.id);
    ozayn_sess_t session;
    ozayn_sess_create(&_sess_svc, &resp, &session);
    ozayn_id_suspend(&_id_svc, id.id);

    ozayn_authz_request_t req = _make_request(session.id, "document", "read");
    ozayn_authz_result_t result = ozayn_authz_authorize(&_authz_svc, &req);
    ASSERT_EQ(OZAYN_AUTHZ_DECISION_DENY, result.decision);
    ASSERT_EQ(OZAYN_AUTHZ_DENY_IDENTITY_SUSPENDED, result.reason);

    ozayn_authz_test_provider_destroy(p);
    _teardown_deps();
    return 0;
}

TEST(test_revoked_identity_denies)
{
    _setup_deps();
    _init_session_svc();
    _init_authz_svc();
    ozayn_authz_policy_provider_t *p = ozayn_authz_test_provider_create();
    ozayn_authz_register_provider(&_authz_svc, p);

    ozayn_identity_t id = _create_identity("alice");
    ozayn_authn_response_t resp = _make_auth_response(id.id);
    ozayn_sess_t session;
    ozayn_sess_create(&_sess_svc, &resp, &session);
    ozayn_id_revoke(&_id_svc, id.id);

    ozayn_authz_request_t req = _make_request(session.id, "document", "read");
    ozayn_authz_result_t result = ozayn_authz_authorize(&_authz_svc, &req);
    ASSERT_EQ(OZAYN_AUTHZ_DECISION_DENY, result.decision);
    ASSERT_EQ(OZAYN_AUTHZ_DENY_IDENTITY_REVOKED, result.reason);

    ozayn_authz_test_provider_destroy(p);
    _teardown_deps();
    return 0;
}

TEST(test_archived_identity_denies)
{
    _setup_deps();
    _init_session_svc();
    _init_authz_svc();
    ozayn_authz_policy_provider_t *p = ozayn_authz_test_provider_create();
    ozayn_authz_register_provider(&_authz_svc, p);

    ozayn_identity_t id = _create_identity("alice");
    ozayn_id_revoke(&_id_svc, id.id);
    ozayn_id_archive(&_id_svc, id.id);
    ozayn_authn_response_t resp = _make_auth_response(id.id);
    ozayn_sess_t session;
    ozayn_sess_create(&_sess_svc, &resp, &session);

    ozayn_authz_request_t req = _make_request(session.id, "document", "read");
    ozayn_authz_result_t result = ozayn_authz_authorize(&_authz_svc, &req);
    ASSERT_EQ(OZAYN_AUTHZ_DECISION_DENY, result.decision);
    ASSERT_EQ(OZAYN_AUTHZ_DENY_IDENTITY_ARCHIVED, result.reason);

    ozayn_authz_test_provider_destroy(p);
    _teardown_deps();
    return 0;
}

/* ============================================================
 * 6. POLICY PROVIDER BEHAVIOR
 * ============================================================ */

TEST(test_provider_evaluate_called)
{
    _setup_deps();
    _init_session_svc();
    _init_authz_svc();
    ozayn_authz_policy_provider_t *p = ozayn_authz_test_provider_create();
    ozayn_authz_register_provider(&_authz_svc, p);

    ozayn_authz_test_provider_set_result(p, ozayn_authz_make_allow());

    ozayn_identity_t id = _create_identity("alice");
    ozayn_authn_response_t resp = _make_auth_response(id.id);
    ozayn_sess_t session;
    ozayn_sess_create(&_sess_svc, &resp, &session);

    ozayn_authz_request_t req = _make_request(session.id, "document", "read");
    ozayn_authz_result_t result = ozayn_authz_authorize(&_authz_svc, &req);
    ASSERT_EQ(OZAYN_AUTHZ_DECISION_ALLOW, result.decision);

    ozayn_authz_test_provider_destroy(p);
    _teardown_deps();
    return 0;
}

TEST(test_provider_unavailable_denies)
{
    _setup_deps();
    _init_session_svc();
    _init_authz_svc();
    ozayn_authz_policy_provider_t *p = ozayn_authz_test_provider_create();
    ozayn_authz_register_provider(&_authz_svc, p);

    ozayn_authz_test_provider_set_available(p, 0);

    ozayn_identity_t id = _create_identity("alice");
    ozayn_authn_response_t resp = _make_auth_response(id.id);
    ozayn_sess_t session;
    ozayn_sess_create(&_sess_svc, &resp, &session);

    ozayn_authz_request_t req = _make_request(session.id, "document", "read");
    ozayn_authz_result_t result = ozayn_authz_authorize(&_authz_svc, &req);
    ASSERT_EQ(OZAYN_AUTHZ_DECISION_DENY, result.decision);
    ASSERT_EQ(OZAYN_AUTHZ_DENY_POLICY_UNAVAILABLE, result.reason);

    ozayn_authz_test_provider_destroy(p);
    _teardown_deps();
    return 0;
}

TEST(test_no_provider_denies)
{
    _setup_deps();
    _init_session_svc();
    _init_authz_svc();

    ozayn_identity_t id = _create_identity("alice");
    ozayn_authn_response_t resp = _make_auth_response(id.id);
    ozayn_sess_t session;
    ozayn_sess_create(&_sess_svc, &resp, &session);

    ozayn_authz_request_t req = _make_request(session.id, "document", "read");
    ozayn_authz_result_t result = ozayn_authz_authorize(&_authz_svc, &req);
    ASSERT_EQ(OZAYN_AUTHZ_DECISION_DENY, result.decision);
    ASSERT_EQ(OZAYN_AUTHZ_DENY_POLICY_UNAVAILABLE, result.reason);

    _teardown_deps();
    return 0;
}

TEST(test_provider_deny_result)
{
    _setup_deps();
    _init_session_svc();
    _init_authz_svc();
    ozayn_authz_policy_provider_t *p = ozayn_authz_test_provider_create();
    ozayn_authz_register_provider(&_authz_svc, p);

    ozayn_authz_test_provider_set_result(p, ozayn_authz_make_deny(OZAYN_AUTHZ_DENY_POLICY_REJECTED));

    ozayn_identity_t id = _create_identity("alice");
    ozayn_authn_response_t resp = _make_auth_response(id.id);
    ozayn_sess_t session;
    ozayn_sess_create(&_sess_svc, &resp, &session);

    ozayn_authz_request_t req = _make_request(session.id, "document", "read");
    ozayn_authz_result_t result = ozayn_authz_authorize(&_authz_svc, &req);
    ASSERT_EQ(OZAYN_AUTHZ_DECISION_DENY, result.decision);
    ASSERT_EQ(OZAYN_AUTHZ_DENY_POLICY_REJECTED, result.reason);

    ozayn_authz_test_provider_destroy(p);
    _teardown_deps();
    return 0;
}

TEST(test_provider_version)
{
    _setup_deps();
    _init_session_svc();
    _init_authz_svc();
    ozayn_authz_policy_provider_t *p = ozayn_authz_test_provider_create();
    ozayn_authz_register_provider(&_authz_svc, p);

    ASSERT_EQ(1, p->ops->get_version(p));
    ozayn_authz_test_provider_set_version(p, 42);
    ASSERT_EQ(42, p->ops->get_version(p));

    ozayn_authz_test_provider_destroy(p);
    _teardown_deps();
    return 0;
}

/* ============================================================
 * 7. AUTHORIZATION DECISIONS
 * ============================================================ */

TEST(test_decision_allow_name)
{
    ASSERT_STR_EQ("ALLOW", ozayn_authz_svc_decision_name(OZAYN_AUTHZ_DECISION_ALLOW));
    return 0;
}

TEST(test_decision_deny_name)
{
    ASSERT_STR_EQ("DENY", ozayn_authz_svc_decision_name(OZAYN_AUTHZ_DECISION_DENY));
    return 0;
}

TEST(test_decision_error_name)
{
    ASSERT_STR_EQ("ERROR", ozayn_authz_svc_decision_name(OZAYN_AUTHZ_DECISION_ERROR));
    return 0;
}

TEST(test_decision_unknown_name)
{
    ASSERT_STR_EQ("UNKNOWN", ozayn_authz_svc_decision_name((ozayn_authz_decision_t)99));
    return 0;
}

TEST(test_deny_reason_names)
{
    ASSERT_STR_EQ("SESSION_INVALID", ozayn_authz_deny_reason_name(OZAYN_AUTHZ_DENY_SESSION_INVALID));
    ASSERT_STR_EQ("SESSION_EXPIRED", ozayn_authz_deny_reason_name(OZAYN_AUTHZ_DENY_SESSION_EXPIRED));
    ASSERT_STR_EQ("SESSION_REVOKED", ozayn_authz_deny_reason_name(OZAYN_AUTHZ_DENY_SESSION_REVOKED));
    ASSERT_STR_EQ("SESSION_TERMINATED", ozayn_authz_deny_reason_name(OZAYN_AUTHZ_DENY_SESSION_TERMINATED));
    ASSERT_STR_EQ("IDENTITY_INVALID", ozayn_authz_deny_reason_name(OZAYN_AUTHZ_DENY_IDENTITY_INVALID));
    ASSERT_STR_EQ("IDENTITY_SUSPENDED", ozayn_authz_deny_reason_name(OZAYN_AUTHZ_DENY_IDENTITY_SUSPENDED));
    ASSERT_STR_EQ("IDENTITY_REVOKED", ozayn_authz_deny_reason_name(OZAYN_AUTHZ_DENY_IDENTITY_REVOKED));
    ASSERT_STR_EQ("IDENTITY_ARCHIVED", ozayn_authz_deny_reason_name(OZAYN_AUTHZ_DENY_IDENTITY_ARCHIVED));
    ASSERT_STR_EQ("DEFAULT_DENY", ozayn_authz_deny_reason_name(OZAYN_AUTHZ_DENY_DEFAULT));
    return 0;
}

TEST(test_deny_reason_none_name)
{
    ASSERT_STR_EQ("NONE", ozayn_authz_deny_reason_name(OZAYN_AUTHZ_DENY_NONE));
    return 0;
}

TEST(test_deny_reason_unknown_name)
{
    ASSERT_STR_EQ("UNKNOWN", ozayn_authz_deny_reason_name((ozayn_authz_deny_reason_t)99));
    return 0;
}

TEST(test_error_names)
{
    ASSERT_STR_EQ("OK", ozayn_authz_error_name(OZAYN_AUTHZ_OK));
    ASSERT_STR_EQ("NULL", ozayn_authz_error_name(OZAYN_AUTHZ_ERR_NULL));
    ASSERT_STR_EQ("NOT_INITIALIZED", ozayn_authz_error_name(OZAYN_AUTHZ_ERR_NOT_INITIALIZED));
    ASSERT_STR_EQ("NOT_FOUND", ozayn_authz_error_name(OZAYN_AUTHZ_ERR_NOT_FOUND));
    ASSERT_STR_EQ("INVALID", ozayn_authz_error_name(OZAYN_AUTHZ_ERR_INVALID));
    ASSERT_STR_EQ("SESSION_INVALID", ozayn_authz_error_name(OZAYN_AUTHZ_ERR_SESSION_INVALID));
    ASSERT_STR_EQ("IDENTITY_INVALID", ozayn_authz_error_name(OZAYN_AUTHZ_ERR_IDENTITY_INVALID));
    ASSERT_STR_EQ("PROVIDER_UNAVAILABLE", ozayn_authz_error_name(OZAYN_AUTHZ_ERR_PROVIDER_UNAVAILABLE));
    ASSERT_STR_EQ("PROVIDER_FAILED", ozayn_authz_error_name(OZAYN_AUTHZ_ERR_PROVIDER_FAILED));
    return 0;
}

TEST(test_error_unknown_name)
{
    ASSERT_STR_EQ("UNKNOWN", ozayn_authz_error_name((ozayn_authz_error_t)99));
    return 0;
}

/* ============================================================
 * 8. RESOURCE TYPE NAMES
 * ============================================================ */

TEST(test_resource_type_names)
{
    ASSERT_STR_EQ("CORE", ozayn_authz_resource_type_name("core"));
    ASSERT_STR_EQ("MODULE", ozayn_authz_resource_type_name("module"));
    ASSERT_STR_EQ("PLUGIN", ozayn_authz_resource_type_name("plugin"));
    ASSERT_STR_EQ("DOCUMENT", ozayn_authz_resource_type_name("document"));
    ASSERT_STR_EQ("MEMORY", ozayn_authz_resource_type_name("memory"));
    ASSERT_STR_EQ("DATABASE", ozayn_authz_resource_type_name("database"));
    ASSERT_STR_EQ("DEVICE", ozayn_authz_resource_type_name("device"));
    ASSERT_STR_EQ("CAMERA", ozayn_authz_resource_type_name("camera"));
    ASSERT_STR_EQ("MICROPHONE", ozayn_authz_resource_type_name("microphone"));
    ASSERT_STR_EQ("SYSTEM", ozayn_authz_resource_type_name("system"));
    ASSERT_STR_EQ("IDENTITY", ozayn_authz_resource_type_name("identity"));
    ASSERT_STR_EQ("SESSION", ozayn_authz_resource_type_name("session"));
    ASSERT_STR_EQ("SERVICE", ozayn_authz_resource_type_name("service"));
    return 0;
}

TEST(test_resource_type_unknown)
{
    ASSERT_STR_EQ("UNKNOWN", ozayn_authz_resource_type_name(NULL));
    ASSERT_STR_EQ("UNKNOWN", ozayn_authz_resource_type_name("bogus"));
    return 0;
}

/* ============================================================
 * 9. ACTION NAMES
 * ============================================================ */

TEST(test_action_names)
{
    ASSERT_STR_EQ("READ", ozayn_authz_action_name("read"));
    ASSERT_STR_EQ("CREATE", ozayn_authz_action_name("create"));
    ASSERT_STR_EQ("UPDATE", ozayn_authz_action_name("update"));
    ASSERT_STR_EQ("DELETE", ozayn_authz_action_name("delete"));
    ASSERT_STR_EQ("EXECUTE", ozayn_authz_action_name("execute"));
    ASSERT_STR_EQ("CONTROL", ozayn_authz_action_name("control"));
    ASSERT_STR_EQ("CONFIGURE", ozayn_authz_action_name("configure"));
    ASSERT_STR_EQ("INSTALL", ozayn_authz_action_name("install"));
    ASSERT_STR_EQ("UNINSTALL", ozayn_authz_action_name("uninstall"));
    return 0;
}

TEST(test_action_unknown)
{
    ASSERT_STR_EQ("UNKNOWN", ozayn_authz_action_name(NULL));
    ASSERT_STR_EQ("UNKNOWN", ozayn_authz_action_name("fly"));
    return 0;
}

/* ============================================================
 * 10. SCOPE NAMES
 * ============================================================ */

TEST(test_scope_names)
{
    ASSERT_STR_EQ("SYSTEM", ozayn_authz_scope_name_value("system"));
    ASSERT_STR_EQ("USER", ozayn_authz_scope_name_value("user"));
    ASSERT_STR_EQ("DEVICE", ozayn_authz_scope_name_value("device"));
    ASSERT_STR_EQ("MODULE", ozayn_authz_scope_name_value("module"));
    ASSERT_STR_EQ("SERVICE", ozayn_authz_scope_name_value("service"));
    ASSERT_STR_EQ("GLOBAL", ozayn_authz_scope_name_value("global"));
    return 0;
}

TEST(test_scope_unknown)
{
    ASSERT_STR_EQ("UNKNOWN", ozayn_authz_scope_name_value(NULL));
    ASSERT_STR_EQ("UNKNOWN", ozayn_authz_scope_name_value("bogus"));
    return 0;
}

/* ============================================================
 * 11. SECURITY — DEFAULT DENY
 * ============================================================ */

TEST(test_default_deny_null_service)
{
    ozayn_authz_request_t req = _make_request("s", "document", "read");
    ozayn_authz_result_t result = ozayn_authz_authorize(NULL, &req);
    ASSERT_EQ(OZAYN_AUTHZ_DECISION_DENY, result.decision);
    return 0;
}

TEST(test_default_deny_null_request)
{
    _setup_deps();
    _init_session_svc();
    _init_authz_svc();
    ozayn_authz_result_t result = ozayn_authz_authorize(&_authz_svc, NULL);
    ASSERT_EQ(OZAYN_AUTHZ_DECISION_DENY, result.decision);
    _teardown_deps();
    return 0;
}

TEST(test_default_deny_not_initialized)
{
    ozayn_authz_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_authz_request_t req = _make_request("s", "document", "read");
    ozayn_authz_result_t result = ozayn_authz_authorize(&svc, &req);
    ASSERT_EQ(OZAYN_AUTHZ_DECISION_DENY, result.decision);
    return 0;
}

TEST(test_default_deny_invalid_request)
{
    _setup_deps();
    _init_session_svc();
    _init_authz_svc();
    ozayn_authz_request_t req;
    memset(&req, 0, sizeof(req));
    ozayn_authz_result_t result = ozayn_authz_authorize(&_authz_svc, &req);
    ASSERT_EQ(OZAYN_AUTHZ_DECISION_DENY, result.decision);
    _teardown_deps();
    return 0;
}

TEST(test_default_deny_invalid_resource)
{
    _setup_deps();
    _init_session_svc();
    _init_authz_svc();
    ozayn_authz_request_t req = _make_request("s", "nonexistent", "read");
    ozayn_authz_result_t result = ozayn_authz_authorize(&_authz_svc, &req);
    ASSERT_EQ(OZAYN_AUTHZ_DECISION_DENY, result.decision);
    _teardown_deps();
    return 0;
}

TEST(test_default_deny_invalid_action)
{
    _setup_deps();
    _init_session_svc();
    _init_authz_svc();
    ozayn_authz_request_t req = _make_request("s", "document", "fly");
    ozayn_authz_result_t result = ozayn_authz_authorize(&_authz_svc, &req);
    ASSERT_EQ(OZAYN_AUTHZ_DECISION_DENY, result.decision);
    _teardown_deps();
    return 0;
}

/* ============================================================
 * 12. ALL RESOURCE TYPES ACCEPTED
 * ============================================================ */

TEST(test_all_resource_types_validate)
{
    ASSERT_EQ(0, ozayn_authz_validate_resource_type("core"));
    ASSERT_EQ(0, ozayn_authz_validate_resource_type("plugin"));
    ASSERT_EQ(0, ozayn_authz_validate_resource_type("memory"));
    ASSERT_EQ(0, ozayn_authz_validate_resource_type("database"));
    ASSERT_EQ(0, ozayn_authz_validate_resource_type("device"));
    ASSERT_EQ(0, ozayn_authz_validate_resource_type("camera"));
    ASSERT_EQ(0, ozayn_authz_validate_resource_type("microphone"));
    return 0;
}

/* ============================================================
 * 13. ALL ACTIONS ACCEPTED
 * ============================================================ */

TEST(test_all_actions_validate)
{
    ASSERT_EQ(0, ozayn_authz_validate_action("read"));
    ASSERT_EQ(0, ozayn_authz_validate_action("create"));
    ASSERT_EQ(0, ozayn_authz_validate_action("update"));
    ASSERT_EQ(0, ozayn_authz_validate_action("delete"));
    ASSERT_EQ(0, ozayn_authz_validate_action("execute"));
    ASSERT_EQ(0, ozayn_authz_validate_action("control"));
    ASSERT_EQ(0, ozayn_authz_validate_action("configure"));
    ASSERT_EQ(0, ozayn_authz_validate_action("install"));
    ASSERT_EQ(0, ozayn_authz_validate_action("uninstall"));
    return 0;
}

/* ============================================================
 * 14. ALL SCOPES ACCEPTED
 * ============================================================ */

TEST(test_all_scopes_validate)
{
    ASSERT_EQ(0, ozayn_authz_validate_scope("system"));
    ASSERT_EQ(0, ozayn_authz_validate_scope("user"));
    ASSERT_EQ(0, ozayn_authz_validate_scope("device"));
    ASSERT_EQ(0, ozayn_authz_validate_scope("module"));
    ASSERT_EQ(0, ozayn_authz_validate_scope("service"));
    ASSERT_EQ(0, ozayn_authz_validate_scope("global"));
    return 0;
}

/* ============================================================
 * 15. PROVIDER LIFECYCLE
 * ============================================================ */

TEST(test_provider_create_destroy)
{
    ozayn_authz_policy_provider_t *p = ozayn_authz_test_provider_create();
    ASSERT_NOT_NULL(p);
    ASSERT_STR_EQ("test_policy_provider", p->name);
    ASSERT_NOT_NULL(p->ops);
    ASSERT(!p->initialized);
    ozayn_authz_test_provider_destroy(p);
    return 0;
}

TEST(test_provider_destroy_null)
{
    ozayn_authz_test_provider_destroy(NULL);
    return 0;
}

TEST(test_provider_init_sets_state)
{
    ozayn_authz_policy_provider_t *p = ozayn_authz_test_provider_create();
    ASSERT_EQ(0, p->ops->init(p));
    ASSERT(!p->initialized);
    ASSERT(p->ops->is_available(p));
    ASSERT_EQ(1, p->ops->get_version(p));
    ozayn_authz_test_provider_destroy(p);
    return 0;
}

/* ============================================================
 * 16. CONCURRENCY SCENARIOS
 * ============================================================ */

TEST(test_concurrent_authorize_same_session)
{
    _setup_deps();
    _init_session_svc();
    _init_authz_svc();
    ozayn_authz_policy_provider_t *p = ozayn_authz_test_provider_create();
    ozayn_authz_register_provider(&_authz_svc, p);
    ozayn_authz_test_provider_set_result(p, ozayn_authz_make_allow());

    ozayn_identity_t id = _create_identity("alice");
    ozayn_authn_response_t resp = _make_auth_response(id.id);
    ozayn_sess_t session;
    ozayn_sess_create(&_sess_svc, &resp, &session);

    ozayn_authz_request_t req = _make_request(session.id, "document", "read");
    for (int i = 0; i < 10; i++) {
        ozayn_authz_result_t result = ozayn_authz_authorize(&_authz_svc, &req);
        ASSERT_EQ(OZAYN_AUTHZ_DECISION_ALLOW, result.decision);
    }

    ozayn_authz_test_provider_destroy(p);
    _teardown_deps();
    return 0;
}

TEST(test_concurrent_authorize_different_sessions)
{
    _setup_deps();
    _init_session_svc();
    _init_authz_svc();
    ozayn_authz_policy_provider_t *p = ozayn_authz_test_provider_create();
    ozayn_authz_register_provider(&_authz_svc, p);
    ozayn_authz_test_provider_set_result(p, ozayn_authz_make_allow());

    ozayn_sess_t s1 = _create_session_for("alice");
    ozayn_sess_t s2 = _create_session_for("bob");

    ozayn_authz_request_t r1 = _make_request(s1.id, "document", "read");
    ozayn_authz_request_t r2 = _make_request(s2.id, "module", "execute");

    ozayn_authz_result_t res1 = ozayn_authz_authorize(&_authz_svc, &r1);
    ozayn_authz_result_t res2 = ozayn_authz_authorize(&_authz_svc, &r2);
    ASSERT_EQ(OZAYN_AUTHZ_DECISION_ALLOW, res1.decision);
    ASSERT_EQ(OZAYN_AUTHZ_DECISION_ALLOW, res2.decision);

    ozayn_authz_test_provider_destroy(p);
    _teardown_deps();
    return 0;
}

TEST(test_session_revoke_then_authorize)
{
    _setup_deps();
    _init_session_svc();
    _init_authz_svc();
    ozayn_authz_policy_provider_t *p = ozayn_authz_test_provider_create();
    ozayn_authz_register_provider(&_authz_svc, p);
    ozayn_authz_test_provider_set_result(p, ozayn_authz_make_allow());

    ozayn_identity_t id = _create_identity("alice");
    ozayn_authn_response_t resp = _make_auth_response(id.id);
    ozayn_sess_t session;
    ozayn_sess_create(&_sess_svc, &resp, &session);

    ozayn_authz_request_t req = _make_request(session.id, "document", "read");
    ozayn_authz_result_t r1 = ozayn_authz_authorize(&_authz_svc, &req);
    ASSERT_EQ(OZAYN_AUTHZ_DECISION_ALLOW, r1.decision);

    ozayn_sess_revoke(&_sess_svc, session.id);
    ozayn_authz_result_t r2 = ozayn_authz_authorize(&_authz_svc, &req);
    ASSERT_EQ(OZAYN_AUTHZ_DECISION_DENY, r2.decision);

    ozayn_authz_test_provider_destroy(p);
    _teardown_deps();
    return 0;
}

TEST(test_identity_revoke_then_authorize)
{
    _setup_deps();
    _init_session_svc();
    _init_authz_svc();
    ozayn_authz_policy_provider_t *p = ozayn_authz_test_provider_create();
    ozayn_authz_register_provider(&_authz_svc, p);
    ozayn_authz_test_provider_set_result(p, ozayn_authz_make_allow());

    ozayn_identity_t id = _create_identity("alice");
    ozayn_authn_response_t resp = _make_auth_response(id.id);
    ozayn_sess_t session;
    ozayn_sess_create(&_sess_svc, &resp, &session);

    ozayn_authz_request_t req = _make_request(session.id, "document", "read");
    ozayn_authz_result_t r1 = ozayn_authz_authorize(&_authz_svc, &req);
    ASSERT_EQ(OZAYN_AUTHZ_DECISION_ALLOW, r1.decision);

    ozayn_id_revoke(&_id_svc, id.id);
    ozayn_authz_result_t r2 = ozayn_authz_authorize(&_authz_svc, &req);
    ASSERT_EQ(OZAYN_AUTHZ_DECISION_DENY, r2.decision);

    ozayn_authz_test_provider_destroy(p);
    _teardown_deps();
    return 0;
}

/* ============================================================
 * 17. REQUEST WITH SCOPE
 * ============================================================ */

TEST(test_request_with_scope)
{
    _setup_deps();
    _init_session_svc();
    _init_authz_svc();
    ozayn_authz_policy_provider_t *p = ozayn_authz_test_provider_create();
    ozayn_authz_register_provider(&_authz_svc, p);
    ozayn_authz_test_provider_set_result(p, ozayn_authz_make_allow());

    ozayn_identity_t id = _create_identity("alice");
    ozayn_authn_response_t resp = _make_auth_response(id.id);
    ozayn_sess_t session;
    ozayn_sess_create(&_sess_svc, &resp, &session);

    ozayn_authz_request_t req = _make_request(session.id, "document", "read");
    strncpy(req.scope, "user", sizeof(req.scope) - 1);
    ozayn_authz_result_t result = ozayn_authz_authorize(&_authz_svc, &req);
    ASSERT_EQ(OZAYN_AUTHZ_DECISION_ALLOW, result.decision);

    ozayn_authz_test_provider_destroy(p);
    _teardown_deps();
    return 0;
}

TEST(test_request_with_scope_system)
{
    _setup_deps();
    _init_session_svc();
    _init_authz_svc();
    ozayn_authz_policy_provider_t *p = ozayn_authz_test_provider_create();
    ozayn_authz_register_provider(&_authz_svc, p);
    ozayn_authz_test_provider_set_result(p, ozayn_authz_make_allow());

    ozayn_identity_t id = _create_identity("alice");
    ozayn_authn_response_t resp = _make_auth_response(id.id);
    ozayn_sess_t session;
    ozayn_sess_create(&_sess_svc, &resp, &session);

    ozayn_authz_request_t req = _make_request(session.id, "system", "configure");
    strncpy(req.scope, "system", sizeof(req.scope) - 1);
    ozayn_authz_result_t result = ozayn_authz_authorize(&_authz_svc, &req);
    ASSERT_EQ(OZAYN_AUTHZ_DECISION_ALLOW, result.decision);

    ozayn_authz_test_provider_destroy(p);
    _teardown_deps();
    return 0;
}

/* ============================================================
 * 18. PROVIDER UNREGISTER AND RE-REGISTER
 * ============================================================ */

TEST(test_unregister_and_reregister)
{
    _setup_deps();
    _init_session_svc();
    _init_authz_svc();
    ozayn_authz_policy_provider_t *p = ozayn_authz_test_provider_create();

    ozayn_authz_register_provider(&_authz_svc, p);
    ASSERT_EQ(1, ozayn_authz_service_provider_count(&_authz_svc));

    ozayn_authz_unregister_provider(&_authz_svc, p);
    ASSERT_EQ(0, ozayn_authz_service_provider_count(&_authz_svc));

    ozayn_authz_register_provider(&_authz_svc, p);
    ASSERT_EQ(1, ozayn_authz_service_provider_count(&_authz_svc));

    ozayn_authz_test_provider_destroy(p);
    _teardown_deps();
    return 0;
}

/* ============================================================
 * 19. AUTHORIZATION RESULT DETAIL
 * ============================================================ */

TEST(test_result_has_reason_detail)
{
    _setup_deps();
    _init_session_svc();
    _init_authz_svc();
    ozayn_authz_policy_provider_t *p = ozayn_authz_test_provider_create();
    ozayn_authz_register_provider(&_authz_svc, p);

    ozayn_authz_request_t req = _make_request("nonexistent", "document", "read");
    ozayn_authz_result_t result = ozayn_authz_authorize(&_authz_svc, &req);
    ASSERT_EQ(OZAYN_AUTHZ_DECISION_DENY, result.decision);
    ASSERT(result.reason_detail[0] != '\0');

    ozayn_authz_test_provider_destroy(p);
    _teardown_deps();
    return 0;
}

TEST(test_allow_has_no_reason_detail)
{
    _setup_deps();
    _init_session_svc();
    _init_authz_svc();
    ozayn_authz_policy_provider_t *p = ozayn_authz_test_provider_create();
    ozayn_authz_register_provider(&_authz_svc, p);
    ozayn_authz_test_provider_set_result(p, ozayn_authz_make_allow());

    ozayn_identity_t id = _create_identity("alice");
    ozayn_authn_response_t resp = _make_auth_response(id.id);
    ozayn_sess_t session;
    ozayn_sess_create(&_sess_svc, &resp, &session);

    ozayn_authz_request_t req = _make_request(session.id, "document", "read");
    ozayn_authz_result_t result = ozayn_authz_authorize(&_authz_svc, &req);
    ASSERT_EQ(OZAYN_AUTHZ_DECISION_ALLOW, result.decision);
    ASSERT_EQ(OZAYN_AUTHZ_DENY_NONE, result.reason);

    ozayn_authz_test_provider_destroy(p);
    _teardown_deps();
    return 0;
}

/* ============================================================
 * 20. EDGE CASES
 * ============================================================ */

TEST(test_authorize_all_resource_action_combos)
{
    _setup_deps();
    _init_session_svc();
    _init_authz_svc();
    ozayn_authz_policy_provider_t *p = ozayn_authz_test_provider_create();
    ozayn_authz_register_provider(&_authz_svc, p);
    ozayn_authz_test_provider_set_result(p, ozayn_authz_make_allow());

    ozayn_identity_t id = _create_identity("alice");
    ozayn_authn_response_t resp = _make_auth_response(id.id);
    ozayn_sess_t session;
    ozayn_sess_create(&_sess_svc, &resp, &session);

    const char *resources[] = {"core", "module", "document", "device", "system"};
    const char *actions[] = {"read", "create", "update", "delete", "execute"};
    int n_res = 5;
    int n_act = 5;

    for (int i = 0; i < n_res; i++) {
        for (int j = 0; j < n_act; j++) {
            ozayn_authz_request_t req = _make_request(session.id,
                                                       resources[i], actions[j]);
            ozayn_authz_result_t result = ozayn_authz_authorize(&_authz_svc, &req);
            ASSERT_EQ(OZAYN_AUTHZ_DECISION_ALLOW, result.decision);
        }
    }

    ozayn_authz_test_provider_destroy(p);
    _teardown_deps();
    return 0;
}

TEST(test_authorize_with_all_scopes)
{
    _setup_deps();
    _init_session_svc();
    _init_authz_svc();
    ozayn_authz_policy_provider_t *p = ozayn_authz_test_provider_create();
    ozayn_authz_register_provider(&_authz_svc, p);
    ozayn_authz_test_provider_set_result(p, ozayn_authz_make_allow());

    ozayn_identity_t id = _create_identity("alice");
    ozayn_authn_response_t resp = _make_auth_response(id.id);
    ozayn_sess_t session;
    ozayn_sess_create(&_sess_svc, &resp, &session);

    const char *scopes[] = {"system", "user", "device", "module", "service", "global"};
    for (int i = 0; i < 6; i++) {
        ozayn_authz_request_t req = _make_request(session.id, "document", "read");
        strncpy(req.scope, scopes[i], sizeof(req.scope) - 1);
        ozayn_authz_result_t result = ozayn_authz_authorize(&_authz_svc, &req);
        ASSERT_EQ(OZAYN_AUTHZ_DECISION_ALLOW, result.decision);
    }

    ozayn_authz_test_provider_destroy(p);
    _teardown_deps();
    return 0;
}

/* ============================================================
 * 21. SHUTDOWN CLEANS UP PROVIDERS
 * ============================================================ */

TEST(test_shutdown_cleans_providers)
{
    _setup_deps();
    _init_session_svc();
    _init_authz_svc();
    ozayn_authz_policy_provider_t *p = ozayn_authz_test_provider_create();
    ozayn_authz_register_provider(&_authz_svc, p);
    ASSERT_EQ(1, ozayn_authz_service_provider_count(&_authz_svc));

    ozayn_authz_service_shutdown(&_authz_svc);
    ASSERT_EQ(0, ozayn_authz_service_provider_count(&_authz_svc));
    ASSERT(!ozayn_authz_service_is_initialized(&_authz_svc));

    ozayn_authz_test_provider_destroy(p);
    _teardown_deps();
    return 0;
}

/* ============================================================
 * TEST RUNNER
 * ============================================================ */

int run_authorization_tests(void)
{
    SUITE_BEGIN("Authorization");

    /* Service lifecycle */
    RUN(test_service_init);
    RUN(test_service_init_null);
    RUN(test_service_init_null_config);
    RUN(test_service_init_no_session_service);
    RUN(test_service_init_no_identity_service);
    RUN(test_service_shutdown);
    RUN(test_service_shutdown_null);

    /* Provider management */
    RUN(test_register_provider);
    RUN(test_register_provider_null);
    RUN(test_register_provider_not_initialized);
    RUN(test_register_provider_no_ops);
    RUN(test_register_provider_duplicate);
    RUN(test_unregister_provider);
    RUN(test_unregister_provider_not_found);
    RUN(test_unregister_provider_null);

    /* Request validation */
    RUN(test_validate_request_valid);
    RUN(test_validate_request_null);
    RUN(test_validate_request_empty_session);
    RUN(test_validate_request_empty_resource_type);
    RUN(test_validate_request_empty_action);
    RUN(test_validate_request_invalid_resource_type);
    RUN(test_validate_request_invalid_action);
    RUN(test_validate_request_invalid_scope);
    RUN(test_validate_request_with_valid_scope);
    RUN(test_validate_request_without_scope);
    RUN(test_validate_resource_type_valid);
    RUN(test_validate_resource_type_invalid);
    RUN(test_validate_action_valid);
    RUN(test_validate_action_invalid);
    RUN(test_validate_scope_valid);
    RUN(test_validate_scope_invalid);

    /* Session integration */
    RUN(test_active_session_authorize);
    RUN(test_expired_session_denies);
    RUN(test_revoked_session_denies);
    RUN(test_terminated_session_denies);
    RUN(test_invalid_session_denies);
    RUN(test_missing_session_denies);

    /* Identity integration */
    RUN(test_suspended_identity_denies);
    RUN(test_revoked_identity_denies);
    RUN(test_archived_identity_denies);

    /* Policy provider */
    RUN(test_provider_evaluate_called);
    RUN(test_provider_unavailable_denies);
    RUN(test_no_provider_denies);
    RUN(test_provider_deny_result);
    RUN(test_provider_version);

    /* Decision names */
    RUN(test_decision_allow_name);
    RUN(test_decision_deny_name);
    RUN(test_decision_error_name);
    RUN(test_decision_unknown_name);
    RUN(test_deny_reason_names);
    RUN(test_deny_reason_none_name);
    RUN(test_deny_reason_unknown_name);
    RUN(test_error_names);
    RUN(test_error_unknown_name);

    /* Resource type names */
    RUN(test_resource_type_names);
    RUN(test_resource_type_unknown);

    /* Action names */
    RUN(test_action_names);
    RUN(test_action_unknown);

    /* Scope names */
    RUN(test_scope_names);
    RUN(test_scope_unknown);

    /* Security — default deny */
    RUN(test_default_deny_null_service);
    RUN(test_default_deny_null_request);
    RUN(test_default_deny_not_initialized);
    RUN(test_default_deny_invalid_request);
    RUN(test_default_deny_invalid_resource);
    RUN(test_default_deny_invalid_action);

    /* All types accepted */
    RUN(test_all_resource_types_validate);
    RUN(test_all_actions_validate);
    RUN(test_all_scopes_validate);

    /* Provider lifecycle */
    RUN(test_provider_create_destroy);
    RUN(test_provider_destroy_null);
    RUN(test_provider_init_sets_state);

    /* Concurrency */
    RUN(test_concurrent_authorize_same_session);
    RUN(test_concurrent_authorize_different_sessions);
    RUN(test_session_revoke_then_authorize);
    RUN(test_identity_revoke_then_authorize);

    /* Scope requests */
    RUN(test_request_with_scope);
    RUN(test_request_with_scope_system);

    /* Provider register/unregister cycle */
    RUN(test_unregister_and_reregister);

    /* Result detail */
    RUN(test_result_has_reason_detail);
    RUN(test_allow_has_no_reason_detail);

    /* Edge cases */
    RUN(test_authorize_all_resource_action_combos);
    RUN(test_authorize_with_all_scopes);

    /* Shutdown cleanup */
    RUN(test_shutdown_cleans_providers);

    SUITE_END();
    return _tf_suite_fail;
}
