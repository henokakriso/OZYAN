#include "../../tests/test_framework.h"
#include "../session_management.h"
#include "../identity.h"
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

static ozayn_sess_service_t      _svc;
static ozayn_protection_provider_t _prot;
static ozayn_storage_provider_t   _stor;
static ozayn_kl_manager_t         _kl;
static ozayn_vault_t              _vault;
static ozayn_identity_service_t   _id_svc;

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
    ozayn_sess_service_shutdown(&_svc);
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
    ozayn_sess_service_init(&_svc, &cfg);
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
    ozayn_sess_create(&_svc, &resp, &session);
    return session;
}

/* ============================================================
 * 1. POLICY VALIDATION
 * ============================================================ */

TEST(test_default_policy_valid)
{
    ozayn_sess_policy_t p = ozayn_sess_default_policy();
    ASSERT(p.enabled);
    ASSERT_EQ(p.max_sessions_total, 512);
    ASSERT_EQ(p.max_sessions_per_identity, 8);
    ASSERT_EQ(p.idle_timeout_seconds, 1800);
    ASSERT_EQ(p.absolute_lifetime_seconds, 86400);
    return 0;
}

TEST(test_default_policy_validates)
{
    ozayn_sess_policy_t p = ozayn_sess_default_policy();
    ASSERT_EQ(0, ozayn_sess_validate_policy(&p));
    return 0;
}

TEST(test_test_policy_valid)
{
    ozayn_sess_policy_t p = ozayn_sess_test_policy();
    ASSERT(p.enabled);
    ASSERT_EQ(p.max_sessions_total, 32);
    ASSERT_EQ(p.max_sessions_per_identity, 4);
    ASSERT_EQ(p.idle_timeout_seconds, 5);
    ASSERT_EQ(p.absolute_lifetime_seconds, 30);
    return 0;
}

TEST(test_test_policy_validates)
{
    ozayn_sess_policy_t p = ozayn_sess_test_policy();
    ASSERT_EQ(0, ozayn_sess_validate_policy(&p));
    return 0;
}

TEST(test_policy_disabled_valid)
{
    ozayn_sess_policy_t p;
    memset(&p, 0, sizeof(p));
    p.enabled = 0;
    ASSERT_EQ(0, ozayn_sess_validate_policy(&p));
    return 0;
}

TEST(test_policy_null_invalid)
{
    ASSERT_EQ(-1, ozayn_sess_validate_policy(NULL));
    return 0;
}

TEST(test_policy_invalid_max_sessions)
{
    ozayn_sess_policy_t p = ozayn_sess_default_policy();
    p.max_sessions_total = 0;
    ASSERT_EQ(-1, ozayn_sess_validate_policy(&p));
    p.max_sessions_total = 512;
    p.max_sessions_per_identity = 0;
    ASSERT_EQ(-1, ozayn_sess_validate_policy(&p));
    return 0;
}

TEST(test_policy_invalid_timeouts)
{
    ozayn_sess_policy_t p = ozayn_sess_default_policy();
    p.idle_timeout_seconds = 0;
    ASSERT_EQ(-1, ozayn_sess_validate_policy(&p));
    p.idle_timeout_seconds = 1800;
    p.absolute_lifetime_seconds = 0;
    ASSERT_EQ(-1, ozayn_sess_validate_policy(&p));
    p.absolute_lifetime_seconds = 86400;
    p.idle_timeout_seconds = 100000;
    ASSERT_EQ(-1, ozayn_sess_validate_policy(&p));
    return 0;
}

/* ============================================================
 * 2. STATE VALIDATION
 * ============================================================ */

TEST(test_validate_state_all_valid)
{
    ASSERT_EQ(0, ozayn_sess_validate_state(OZAYN_SESS_STATE_UNINITIALIZED));
    ASSERT_EQ(0, ozayn_sess_validate_state(OZAYN_SESS_STATE_ACTIVE));
    ASSERT_EQ(0, ozayn_sess_validate_state(OZAYN_SESS_STATE_EXPIRED));
    ASSERT_EQ(0, ozayn_sess_validate_state(OZAYN_SESS_STATE_REVOKED));
    ASSERT_EQ(0, ozayn_sess_validate_state(OZAYN_SESS_STATE_TERMINATED));
    return 0;
}

TEST(test_validate_state_invalid)
{
    ASSERT_EQ(-1, ozayn_sess_validate_state((ozayn_sess_state_t)-1));
    ASSERT_EQ(-1, ozayn_sess_validate_state((ozayn_sess_state_t)5));
    ASSERT_EQ(-1, ozayn_sess_validate_state((ozayn_sess_state_t)99));
    return 0;
}

/* ============================================================
 * 3. STATE TRANSITION VALIDATION
 * ============================================================ */

TEST(test_transition_uninitialized_to_active)
{
    ASSERT_EQ(0, ozayn_sess_validate_transition(
        OZAYN_SESS_STATE_UNINITIALIZED, OZAYN_SESS_STATE_ACTIVE));
    return 0;
}

TEST(test_transition_uninitialized_rejects_all_others)
{
    ASSERT_EQ(-1, ozayn_sess_validate_transition(
        OZAYN_SESS_STATE_UNINITIALIZED, OZAYN_SESS_STATE_EXPIRED));
    ASSERT_EQ(-1, ozayn_sess_validate_transition(
        OZAYN_SESS_STATE_UNINITIALIZED, OZAYN_SESS_STATE_REVOKED));
    ASSERT_EQ(-1, ozayn_sess_validate_transition(
        OZAYN_SESS_STATE_UNINITIALIZED, OZAYN_SESS_STATE_TERMINATED));
    return 0;
}

TEST(test_transition_active_to_expired)
{
    ASSERT_EQ(0, ozayn_sess_validate_transition(
        OZAYN_SESS_STATE_ACTIVE, OZAYN_SESS_STATE_EXPIRED));
    return 0;
}

TEST(test_transition_active_to_revoked)
{
    ASSERT_EQ(0, ozayn_sess_validate_transition(
        OZAYN_SESS_STATE_ACTIVE, OZAYN_SESS_STATE_REVOKED));
    return 0;
}

TEST(test_transition_active_to_terminated)
{
    ASSERT_EQ(0, ozayn_sess_validate_transition(
        OZAYN_SESS_STATE_ACTIVE, OZAYN_SESS_STATE_TERMINATED));
    return 0;
}

TEST(test_transition_active_rejects_others)
{
    ASSERT_EQ(-1, ozayn_sess_validate_transition(
        OZAYN_SESS_STATE_ACTIVE, OZAYN_SESS_STATE_UNINITIALIZED));
    return 0;
}

TEST(test_terminal_states_reject_all)
{
    ASSERT_EQ(-1, ozayn_sess_validate_transition(
        OZAYN_SESS_STATE_EXPIRED, OZAYN_SESS_STATE_ACTIVE));
    ASSERT_EQ(-1, ozayn_sess_validate_transition(
        OZAYN_SESS_STATE_EXPIRED, OZAYN_SESS_STATE_REVOKED));
    ASSERT_EQ(-1, ozayn_sess_validate_transition(
        OZAYN_SESS_STATE_REVOKED, OZAYN_SESS_STATE_ACTIVE));
    ASSERT_EQ(-1, ozayn_sess_validate_transition(
        OZAYN_SESS_STATE_REVOKED, OZAYN_SESS_STATE_TERMINATED));
    ASSERT_EQ(-1, ozayn_sess_validate_transition(
        OZAYN_SESS_STATE_TERMINATED, OZAYN_SESS_STATE_ACTIVE));
    ASSERT_EQ(-1, ozayn_sess_validate_transition(
        OZAYN_SESS_STATE_TERMINATED, OZAYN_SESS_STATE_EXPIRED));
    return 0;
}

TEST(test_transition_invalid_states)
{
    ASSERT_EQ(-1, ozayn_sess_validate_transition(
        (ozayn_sess_state_t)-1, OZAYN_SESS_STATE_ACTIVE));
    ASSERT_EQ(-1, ozayn_sess_validate_transition(
        OZAYN_SESS_STATE_ACTIVE, (ozayn_sess_state_t)-1));
    return 0;
}

/* ============================================================
 * 4. SESSION ID VALIDATION
 * ============================================================ */

TEST(test_validate_id_null)
{
    ASSERT_EQ(-1, ozayn_sess_validate_id(NULL));
    return 0;
}

TEST(test_validate_id_empty)
{
    ASSERT_EQ(-1, ozayn_sess_validate_id(""));
    return 0;
}

TEST(test_validate_id_too_short)
{
    ASSERT_EQ(-1, ozayn_sess_validate_id("abc"));
    return 0;
}

TEST(test_validate_id_valid)
{
    ASSERT_EQ(0, ozayn_sess_validate_id("abcdefghijklmnopqrstuvwxyz0123456789"));
    return 0;
}

/* ============================================================
 * 5. SERVICE INIT/SHUTDOWN
 * ============================================================ */

TEST(test_init_shutdown)
{
    _setup_deps();
    _init_session_svc();
    ASSERT(ozayn_sess_service_is_initialized(&_svc));
    ASSERT_EQ(0, ozayn_sess_service_session_count(&_svc));
    ozayn_sess_service_shutdown(&_svc);
    ASSERT(!ozayn_sess_service_is_initialized(&_svc));
    _teardown_deps();
    return 0;
}

TEST(test_init_null)
{
    ASSERT_EQ(OZAYN_SESS_ERR_NULL,
              ozayn_sess_service_init(NULL, NULL));
    ozayn_sess_service_t svc;
    ASSERT_EQ(OZAYN_SESS_ERR_NULL,
              ozayn_sess_service_init(&svc, NULL));
    return 0;
}

TEST(test_init_missing_identity_service)
{
    ozayn_sess_service_t svc;
    ozayn_sess_service_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.policy = ozayn_sess_default_policy();
    ASSERT_EQ(OZAYN_SESS_ERR_IDENTITY_INVALID,
              ozayn_sess_service_init(&svc, &cfg));
    return 0;
}

TEST(test_init_invalid_policy)
{
    _setup_deps();
    ozayn_sess_service_t svc;
    ozayn_sess_service_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.identity_service = &_id_svc;
    cfg.policy.enabled = 1;
    cfg.policy.max_sessions_total = 0;
    ASSERT_EQ(OZAYN_SESS_ERR_POLICY_INVALID,
              ozayn_sess_service_init(&svc, &cfg));
    _teardown_deps();
    return 0;
}

TEST(test_shutdown_null)
{
    ozayn_sess_service_shutdown(NULL);
    return 0;
}

TEST(test_query_not_initialized)
{
    ozayn_sess_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ASSERT(!ozayn_sess_service_is_initialized(&svc));
    ASSERT_EQ(0, ozayn_sess_service_session_count(&svc));
    return 0;
}

/* ============================================================
 * 6. SESSION CREATION — HAPPY PATH
 * ============================================================ */

TEST(test_create_session)
{
    _setup_deps();
    _init_session_svc();
    ozayn_identity_t _id_alice = _create_identity("alice");

    ozayn_authn_response_t resp = _make_auth_response(_id_alice.id);
    ozayn_sess_t session;
    ASSERT_EQ(OZAYN_SESS_OK,
              ozayn_sess_create(&_svc, &resp, &session));
    ASSERT_EQ(OZAYN_SESS_STATE_ACTIVE, session.state);
    ASSERT_STR_EQ(_id_alice.id, session.identity_id);
    ASSERT_EQ(OZAYN_AuthN_METHOD_PASSWORD, session.method);
    ASSERT(session.created_at > 0);
    ASSERT(session.last_activity_at > 0);
    ASSERT(session.expires_at > session.created_at);
    ASSERT(session.absolute_expires_at > session.created_at);
    ASSERT_EQ(1, session.version);
    ASSERT(session.in_use);
    ASSERT_EQ(1, ozayn_sess_service_session_count(&_svc));
    _teardown_deps();
    return 0;
}

TEST(test_create_session_generates_unique_id)
{
    _setup_deps();
    _init_session_svc();
    ozayn_identity_t _id_alice = _create_identity("alice");

    ozayn_authn_response_t resp = _make_auth_response(_id_alice.id);
    ozayn_sess_t s1, s2;
    ASSERT_EQ(OZAYN_SESS_OK,
              ozayn_sess_create(&_svc, &resp, &s1));
    ASSERT_EQ(OZAYN_SESS_OK,
              ozayn_sess_create(&_svc, &resp, &s2));
    ASSERT(strcmp((s1.id), (s2.id)) != 0);
    ASSERT_EQ(2, ozayn_sess_service_session_count(&_svc));
    _teardown_deps();
    return 0;
}

TEST(test_create_session_id_length)
{
    _setup_deps();
    _init_session_svc();
    ozayn_identity_t _id_alice = _create_identity("alice");

    ozayn_authn_response_t resp = _make_auth_response(_id_alice.id);
    ozayn_sess_t session;
    ASSERT_EQ(OZAYN_SESS_OK,
              ozayn_sess_create(&_svc, &resp, &session));
    size_t len = strlen(session.id);
    ASSERT(len >= 8);
    ASSERT(len < OZAYN_SESS_MAX_ID_LEN);
    _teardown_deps();
    return 0;
}

/* ============================================================
 * 7. SESSION CREATION — AUTH FAILURES
 * ============================================================ */

TEST(test_create_null)
{
    _setup_deps();
    _init_session_svc();
    ASSERT_EQ(OZAYN_SESS_ERR_NULL,
              ozayn_sess_create(NULL, NULL, NULL));
    _teardown_deps();
    return 0;
}

TEST(test_create_not_initialized)
{
    ozayn_sess_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_authn_response_t resp;
    memset(&resp, 0, sizeof(resp));
    resp.result = OZAYN_AuthN_RESULT_SUCCESS;
    resp.verification = OZAYN_AuthN_VERIFY_VERIFIED;
    strncpy(resp.identity_id, "dummy_id", sizeof(resp.identity_id) - 1);
    ozayn_sess_t session;
    ASSERT_EQ(OZAYN_SESS_ERR_NOT_INITIALIZED,
              ozayn_sess_create(&svc, &resp, &session));
    return 0;
}

TEST(test_create_auth_failed)
{
    _setup_deps();
    _init_session_svc();
    ozayn_identity_t _id_alice = _create_identity("alice");

    ozayn_authn_response_t resp = _make_auth_response(_id_alice.id);
    resp.result = OZAYN_AuthN_RESULT_FAILED;
    ozayn_sess_t session;
    ASSERT_EQ(OZAYN_SESS_ERR_AUTH_FAILED,
              ozayn_sess_create(&_svc, &resp, &session));
    ASSERT_EQ(0, ozayn_sess_service_session_count(&_svc));
    _teardown_deps();
    return 0;
}

TEST(test_create_auth_rejected)
{
    _setup_deps();
    _init_session_svc();
    ozayn_identity_t _id_alice = _create_identity("alice");

    ozayn_authn_response_t resp = _make_auth_response(_id_alice.id);
    resp.result = OZAYN_AuthN_RESULT_REJECTED;
    ozayn_sess_t session;
    ASSERT_EQ(OZAYN_SESS_ERR_AUTH_FAILED,
              ozayn_sess_create(&_svc, &resp, &session));
    _teardown_deps();
    return 0;
}

TEST(test_create_not_verified)
{
    _setup_deps();
    _init_session_svc();
    ozayn_identity_t _id_alice = _create_identity("alice");

    ozayn_authn_response_t resp = _make_auth_response(_id_alice.id);
    resp.verification = OZAYN_AuthN_VERIFY_PENDING;
    ozayn_sess_t session;
    ASSERT_EQ(OZAYN_SESS_ERR_AUTH_FAILED,
              ozayn_sess_create(&_svc, &resp, &session));
    _teardown_deps();
    return 0;
}

TEST(test_create_empty_identity)
{
    _setup_deps();
    _init_session_svc();

    ozayn_authn_response_t resp = _make_auth_response("");
    ozayn_sess_t session;
    ASSERT_EQ(OZAYN_SESS_ERR_IDENTITY_INVALID,
              ozayn_sess_create(&_svc, &resp, &session));
    _teardown_deps();
    return 0;
}

/* ============================================================
 * 8. SESSION CREATION — IDENTITY FAILURES
 * ============================================================ */

TEST(test_create_identity_not_found)
{
    _setup_deps();
    _init_session_svc();

    ozayn_authn_response_t resp = _make_auth_response("ghost");
    ozayn_sess_t session;
    ASSERT_EQ(OZAYN_SESS_ERR_IDENTITY_INVALID,
              ozayn_sess_create(&_svc, &resp, &session));
    _teardown_deps();
    return 0;
}

TEST(test_create_identity_revoked)
{
    _setup_deps();
    _init_session_svc();
    ozayn_identity_t _id_alice = _create_identity("alice");

    ozayn_identity_t id;
    ozayn_id_get(&_id_svc, "alice", &id);
    ozayn_id_revoke(&_id_svc, _id_alice.id);

    ozayn_authn_response_t resp = _make_auth_response(_id_alice.id);
    ozayn_sess_t session;
    ASSERT_EQ(OZAYN_SESS_ERR_IDENTITY_REVOKED,
              ozayn_sess_create(&_svc, &resp, &session));
    _teardown_deps();
    return 0;
}

TEST(test_create_identity_suspended)
{
    _setup_deps();
    _init_session_svc();
    ozayn_identity_t _id_alice = _create_identity("alice");

    ozayn_id_suspend(&_id_svc, _id_alice.id);

    ozayn_authn_response_t resp = _make_auth_response(_id_alice.id);
    ozayn_sess_t session;
    ASSERT_EQ(OZAYN_SESS_ERR_IDENTITY_SUSPENDED,
              ozayn_sess_create(&_svc, &resp, &session));
    _teardown_deps();
    return 0;
}

/* ============================================================
 * 9. SESSION CREATION — LIMITS
 * ============================================================ */

TEST(test_create_limit_total)
{
    _setup_deps();
    _init_session_svc();

    ozayn_sess_service_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.identity_service = &_id_svc;
    cfg.policy = ozayn_sess_test_policy();
    cfg.policy.max_sessions_total = 2;
    ozayn_sess_service_init(&_svc, &cfg);

    ozayn_identity_t _id_alice = _create_identity("alice");
    ozayn_authn_response_t resp = _make_auth_response(_id_alice.id);
    ozayn_sess_t session;

    ASSERT_EQ(OZAYN_SESS_OK,
              ozayn_sess_create(&_svc, &resp, &session));
    ASSERT_EQ(OZAYN_SESS_OK,
              ozayn_sess_create(&_svc, &resp, &session));
    ASSERT_EQ(OZAYN_SESS_ERR_LIMIT_REACHED,
              ozayn_sess_create(&_svc, &resp, &session));
    ASSERT_EQ(2, ozayn_sess_service_session_count(&_svc));
    _teardown_deps();
    return 0;
}

TEST(test_create_limit_per_identity)
{
    _setup_deps();
    _init_session_svc();

    ozayn_sess_service_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.identity_service = &_id_svc;
    cfg.policy = ozayn_sess_test_policy();
    cfg.policy.max_sessions_per_identity = 2;
    cfg.policy.max_sessions_total = 100;
    ozayn_sess_service_init(&_svc, &cfg);

    ozayn_identity_t _id_alice = _create_identity("alice");
    ozayn_authn_response_t resp = _make_auth_response(_id_alice.id);
    ozayn_sess_t session;

    ASSERT_EQ(OZAYN_SESS_OK,
              ozayn_sess_create(&_svc, &resp, &session));
    ASSERT_EQ(OZAYN_SESS_OK,
              ozayn_sess_create(&_svc, &resp, &session));
    ASSERT_EQ(OZAYN_SESS_ERR_LIMIT_REACHED,
              ozayn_sess_create(&_svc, &resp, &session));
    _teardown_deps();
    return 0;
}

TEST(test_create_multiple_identities)
{
    _setup_deps();
    _init_session_svc();

    ozayn_identity_t _id_alice = _create_identity("alice");
    ozayn_identity_t _id_bob = _create_identity("bob");

    ozayn_authn_response_t resp_a = _make_auth_response(_id_alice.id);
    ozayn_authn_response_t resp_b = _make_auth_response(_id_bob.id);
    ozayn_sess_t s1, s2;

    ASSERT_EQ(OZAYN_SESS_OK,
              ozayn_sess_create(&_svc, &resp_a, &s1));
    ASSERT_EQ(OZAYN_SESS_OK,
              ozayn_sess_create(&_svc, &resp_b, &s2));
    ASSERT(strcmp((s1.id), (s2.id)) != 0);
    ASSERT_STR_EQ(_id_alice.id, s1.identity_id);
    ASSERT_STR_EQ(_id_bob.id, s2.identity_id);
    _teardown_deps();
    return 0;
}

/* ============================================================
 * 10. SESSION VALIDATION — HAPPY PATH
 * ============================================================ */

TEST(test_validate_active_session)
{
    _setup_deps();
    _init_session_svc();
    ozayn_identity_t _id_alice = _create_identity("alice");
    ozayn_authn_response_t resp = _make_auth_response(_id_alice.id);
    ozayn_sess_t created;
    ASSERT_EQ(OZAYN_SESS_OK,
              ozayn_sess_create(&_svc, &resp, &created));

    ozayn_sess_t validated;
    ASSERT_EQ(OZAYN_SESS_OK,
              ozayn_sess_validate(&_svc, created.id, &validated));
    ASSERT_EQ(OZAYN_SESS_STATE_ACTIVE, validated.state);
    ASSERT_STR_EQ(created.id, validated.id);
    ASSERT_STR_EQ(_id_alice.id, validated.identity_id);
    _teardown_deps();
    return 0;
}

/* ============================================================
 * 11. SESSION VALIDATION — FAILURES
 * ============================================================ */

TEST(test_validate_null)
{
    _setup_deps();
    _init_session_svc();
    ASSERT_EQ(OZAYN_SESS_ERR_NULL,
              ozayn_sess_validate(NULL, NULL, NULL));
    _teardown_deps();
    return 0;
}

TEST(test_validate_not_initialized)
{
    ozayn_sess_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_sess_t out;
    ASSERT_EQ(OZAYN_SESS_ERR_NOT_INITIALIZED,
              ozayn_sess_validate(&svc, "fake_id", &out));
    return 0;
}

TEST(test_validate_not_found)
{
    _setup_deps();
    _init_session_svc();
    ozayn_sess_t out;
    ASSERT_EQ(OZAYN_SESS_ERR_NOT_FOUND,
              ozayn_sess_validate(&_svc, "nonexistent_session_id_here", &out));
    _teardown_deps();
    return 0;
}

TEST(test_validate_terminated)
{
    _setup_deps();
    _init_session_svc();
    ozayn_identity_t _id_alice = _create_identity("alice");
    ozayn_authn_response_t resp = _make_auth_response(_id_alice.id);
    ozayn_sess_t created;
    ozayn_sess_create(&_svc, &resp, &created);

    ozayn_sess_terminate(&_svc, created.id);

    ozayn_sess_t out;
    ASSERT_EQ(OZAYN_SESS_ERR_TERMINATED,
              ozayn_sess_validate(&_svc, created.id, &out));
    _teardown_deps();
    return 0;
}

TEST(test_validate_revoked)
{
    _setup_deps();
    _init_session_svc();
    ozayn_identity_t _id_alice = _create_identity("alice");
    ozayn_authn_response_t resp = _make_auth_response(_id_alice.id);
    ozayn_sess_t created;
    ozayn_sess_create(&_svc, &resp, &created);

    ozayn_sess_revoke(&_svc, created.id);

    ozayn_sess_t out;
    ASSERT_EQ(OZAYN_SESS_ERR_REVOKED,
              ozayn_sess_validate(&_svc, created.id, &out));
    _teardown_deps();
    return 0;
}

TEST(test_validate_expired_idle)
{
    _setup_deps();

    ozayn_sess_service_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.identity_service = &_id_svc;
    cfg.policy = ozayn_sess_test_policy();
    cfg.policy.idle_timeout_seconds = 1;
    cfg.policy.absolute_lifetime_seconds = 300;
    ozayn_sess_service_init(&_svc, &cfg);

    ozayn_identity_t _id_alice = _create_identity("alice");
    ozayn_authn_response_t resp = _make_auth_response(_id_alice.id);
    resp.auth_time = time(NULL) - 10;
    ozayn_sess_t session;
    ozayn_sess_create(&_svc, &resp, &session);

    ozayn_sess_t out;
    ASSERT_EQ(OZAYN_SESS_ERR_EXPIRED,
              ozayn_sess_validate(&_svc, session.id, &out));
    ASSERT_EQ(OZAYN_SESS_STATE_EXPIRED, out.state);
    _teardown_deps();
    return 0;
}

TEST(test_validate_expired_absolute)
{
    _setup_deps();

    ozayn_sess_service_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.identity_service = &_id_svc;
    cfg.policy = ozayn_sess_test_policy();
    cfg.policy.idle_timeout_seconds = 2;
    cfg.policy.absolute_lifetime_seconds = 2;
    ozayn_sess_service_init(&_svc, &cfg);

    ozayn_identity_t _id_alice = _create_identity("alice");
    ozayn_authn_response_t resp = _make_auth_response(_id_alice.id);
    resp.auth_time = time(NULL) - 10;
    ozayn_sess_t session;
    ozayn_sess_create(&_svc, &resp, &session);

    ozayn_sess_t out;
    ASSERT_EQ(OZAYN_SESS_ERR_EXPIRED,
              ozayn_sess_validate(&_svc, session.id, &out));
    _teardown_deps();
    return 0;
}

TEST(test_validate_identity_revoked)
{
    _setup_deps();
    _init_session_svc();
    ozayn_identity_t _id_alice = _create_identity("alice");
    ozayn_authn_response_t resp = _make_auth_response(_id_alice.id);
    ozayn_sess_t created;
    ozayn_sess_create(&_svc, &resp, &created);

    ozayn_id_revoke(&_id_svc, _id_alice.id);

    ozayn_sess_t out;
    ASSERT_EQ(OZAYN_SESS_ERR_IDENTITY_REVOKED,
              ozayn_sess_validate(&_svc, created.id, &out));
    ASSERT_EQ(OZAYN_SESS_STATE_REVOKED, out.state);
    _teardown_deps();
    return 0;
}

TEST(test_validate_identity_suspended)
{
    _setup_deps();
    _init_session_svc();
    ozayn_identity_t _id_alice = _create_identity("alice");
    ozayn_authn_response_t resp = _make_auth_response(_id_alice.id);
    ozayn_sess_t created;
    ozayn_sess_create(&_svc, &resp, &created);

    ozayn_id_suspend(&_id_svc, _id_alice.id);

    ozayn_sess_t out;
    ASSERT_EQ(OZAYN_SESS_ERR_IDENTITY_SUSPENDED,
              ozayn_sess_validate(&_svc, created.id, &out));
    ASSERT_EQ(OZAYN_SESS_STATE_REVOKED, out.state);
    _teardown_deps();
    return 0;
}

/* ============================================================
 * 12. SESSION GET (lookup without validation)
 * ============================================================ */

TEST(test_get_session)
{
    _setup_deps();
    _init_session_svc();
    ozayn_identity_t _id_alice = _create_identity("alice");
    ozayn_authn_response_t resp = _make_auth_response(_id_alice.id);
    ozayn_sess_t created;
    ozayn_sess_create(&_svc, &resp, &created);

    ozayn_sess_t out;
    ASSERT_EQ(OZAYN_SESS_OK,
              ozayn_sess_get(&_svc, created.id, &out));
    ASSERT_STR_EQ(created.id, out.id);
    _teardown_deps();
    return 0;
}

TEST(test_get_not_found)
{
    _setup_deps();
    _init_session_svc();
    ozayn_sess_t out;
    ASSERT_EQ(OZAYN_SESS_ERR_NOT_FOUND,
              ozayn_sess_get(&_svc, "nonexistent_id_here", &out));
    _teardown_deps();
    return 0;
}

TEST(test_get_null)
{
    ASSERT_EQ(OZAYN_SESS_ERR_NULL,
              ozayn_sess_get(NULL, NULL, NULL));
    return 0;
}

/* ============================================================
 * 13. SESSION TOUCH (activity tracking)
 * ============================================================ */

TEST(test_touch_updates_activity)
{
    _setup_deps();
    _init_session_svc();
    ozayn_identity_t _id_alice = _create_identity("alice");
    ozayn_authn_response_t resp = _make_auth_response(_id_alice.id);
    ozayn_sess_t created;
    ozayn_sess_create(&_svc, &resp, &created);

    ASSERT_EQ(OZAYN_SESS_OK,
              ozayn_sess_touch(&_svc, created.id));

    ozayn_sess_t out;
    ozayn_sess_get(&_svc, created.id, &out);
    ASSERT(out.last_activity_at >= created.last_activity_at);
    ASSERT(out.expires_at >= created.expires_at);
    _teardown_deps();
    return 0;
}

TEST(test_touch_not_found)
{
    _setup_deps();
    _init_session_svc();
    ASSERT_EQ(OZAYN_SESS_ERR_NOT_FOUND,
              ozayn_sess_touch(&_svc, "nonexistent_id_here"));
    _teardown_deps();
    return 0;
}

TEST(test_touch_inactive_session)
{
    _setup_deps();
    _init_session_svc();
    ozayn_identity_t _id_alice = _create_identity("alice");
    ozayn_authn_response_t resp = _make_auth_response(_id_alice.id);
    ozayn_sess_t created;
    ozayn_sess_create(&_svc, &resp, &created);
    ozayn_sess_terminate(&_svc, created.id);

    ASSERT_EQ(OZAYN_SESS_ERR_STATE_INVALID,
              ozayn_sess_touch(&_svc, created.id));
    _teardown_deps();
    return 0;
}

TEST(test_touch_extends_idle_timeout)
{
    _setup_deps();

    ozayn_sess_service_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.identity_service = &_id_svc;
    cfg.policy = ozayn_sess_test_policy();
    cfg.policy.idle_timeout_seconds = 2;
    cfg.policy.absolute_lifetime_seconds = 300;
    ozayn_sess_service_init(&_svc, &cfg);

    ozayn_identity_t _id_alice = _create_identity("alice");
    ozayn_authn_response_t resp = _make_auth_response(_id_alice.id);
    ozayn_sess_t session;
    ozayn_sess_create(&_svc, &resp, &session);

    time_t first_expiry = session.expires_at;

    ozayn_sess_touch(&_svc, session.id);

    ozayn_sess_t out;
    ozayn_sess_get(&_svc, session.id, &out);
    ASSERT(out.expires_at >= first_expiry);
    _teardown_deps();
    return 0;
}

/* ============================================================
 * 14. SESSION TERMINATE
 * ============================================================ */

TEST(test_terminate)
{
    _setup_deps();
    _init_session_svc();
    ozayn_identity_t _id_alice = _create_identity("alice");
    ozayn_authn_response_t resp = _make_auth_response(_id_alice.id);
    ozayn_sess_t created;
    ozayn_sess_create(&_svc, &resp, &created);

    ASSERT_EQ(OZAYN_SESS_OK,
              ozayn_sess_terminate(&_svc, created.id));

    ozayn_sess_t out;
    ASSERT_EQ(OZAYN_SESS_OK,
              ozayn_sess_get(&_svc, created.id, &out));
    ASSERT_EQ(OZAYN_SESS_STATE_TERMINATED, out.state);
    _teardown_deps();
    return 0;
}

TEST(test_terminate_already_terminated)
{
    _setup_deps();
    _init_session_svc();
    ozayn_identity_t _id_alice = _create_identity("alice");
    ozayn_authn_response_t resp = _make_auth_response(_id_alice.id);
    ozayn_sess_t created;
    ozayn_sess_create(&_svc, &resp, &created);

    ASSERT_EQ(OZAYN_SESS_OK,
              ozayn_sess_terminate(&_svc, created.id));
    ASSERT_EQ(OZAYN_SESS_OK,
              ozayn_sess_terminate(&_svc, created.id));
    _teardown_deps();
    return 0;
}

TEST(test_terminate_not_found)
{
    _setup_deps();
    _init_session_svc();
    ASSERT_EQ(OZAYN_SESS_ERR_NOT_FOUND,
              ozayn_sess_terminate(&_svc, "nonexistent_id_here"));
    _teardown_deps();
    return 0;
}

TEST(test_terminate_revoked_session)
{
    _setup_deps();
    _init_session_svc();
    ozayn_sess_t created = _create_session_for("alice");

    ozayn_sess_revoke(&_svc, created.id);
    ASSERT_EQ(OZAYN_SESS_ERR_STATE_TRANSITION_INVALID,
              ozayn_sess_terminate(&_svc, created.id));
    _teardown_deps();
    return 0;
}

TEST(test_terminate_expired_session)
{
    _setup_deps();

    ozayn_sess_service_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.identity_service = &_id_svc;
    cfg.policy = ozayn_sess_test_policy();
    cfg.policy.idle_timeout_seconds = 1;
    cfg.policy.absolute_lifetime_seconds = 300;
    ozayn_sess_service_init(&_svc, &cfg);

    ozayn_identity_t _id_alice = _create_identity("alice");
    ozayn_authn_response_t resp = _make_auth_response(_id_alice.id);
    resp.auth_time = time(NULL) - 10;
    ozayn_sess_t session;
    ozayn_sess_create(&_svc, &resp, &session);

    ASSERT_EQ(OZAYN_SESS_ERR_STATE_TRANSITION_INVALID,
              ozayn_sess_terminate(&_svc, session.id));
    _teardown_deps();
    return 0;
}

TEST(test_terminate_null)
{
    ASSERT_EQ(OZAYN_SESS_ERR_NULL,
              ozayn_sess_terminate(NULL, NULL));
    return 0;
}

/* ============================================================
 * 15. SESSION REVOKE
 * ============================================================ */

TEST(test_revoke)
{
    _setup_deps();
    _init_session_svc();
    ozayn_identity_t _id_alice = _create_identity("alice");
    ozayn_authn_response_t resp = _make_auth_response(_id_alice.id);
    ozayn_sess_t created;
    ozayn_sess_create(&_svc, &resp, &created);

    ASSERT_EQ(OZAYN_SESS_OK,
              ozayn_sess_revoke(&_svc, created.id));

    ozayn_sess_t out;
    ASSERT_EQ(OZAYN_SESS_OK,
              ozayn_sess_get(&_svc, created.id, &out));
    ASSERT_EQ(OZAYN_SESS_STATE_REVOKED, out.state);
    _teardown_deps();
    return 0;
}

TEST(test_revoke_already_revoked)
{
    _setup_deps();
    _init_session_svc();
    ozayn_identity_t _id_alice = _create_identity("alice");
    ozayn_authn_response_t resp = _make_auth_response(_id_alice.id);
    ozayn_sess_t created;
    ozayn_sess_create(&_svc, &resp, &created);

    ASSERT_EQ(OZAYN_SESS_OK,
              ozayn_sess_revoke(&_svc, created.id));
    ASSERT_EQ(OZAYN_SESS_OK,
              ozayn_sess_revoke(&_svc, created.id));
    _teardown_deps();
    return 0;
}

TEST(test_revoke_not_found)
{
    _setup_deps();
    _init_session_svc();
    ASSERT_EQ(OZAYN_SESS_ERR_NOT_FOUND,
              ozayn_sess_revoke(&_svc, "nonexistent_id_here"));
    _teardown_deps();
    return 0;
}

TEST(test_revoke_terminated_session)
{
    _setup_deps();
    _init_session_svc();
    ozayn_sess_t created = _create_session_for("alice");

    ozayn_sess_terminate(&_svc, created.id);
    ASSERT_EQ(OZAYN_SESS_ERR_STATE_TRANSITION_INVALID,
              ozayn_sess_revoke(&_svc, created.id));
    _teardown_deps();
    return 0;
}

TEST(test_revoke_null)
{
    ASSERT_EQ(OZAYN_SESS_ERR_NULL,
              ozayn_sess_revoke(NULL, NULL));
    return 0;
}

/* ============================================================
 * 16. SESSION EXPIRE (batch scan)
 * ============================================================ */

TEST(test_expire_scans_all)
{
    _setup_deps();

    ozayn_sess_service_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.identity_service = &_id_svc;
    cfg.policy = ozayn_sess_test_policy();
    cfg.policy.idle_timeout_seconds = 1;
    cfg.policy.absolute_lifetime_seconds = 300;
    ozayn_sess_service_init(&_svc, &cfg);

    ozayn_identity_t _id_alice = _create_identity("alice");
    ozayn_authn_response_t resp = _make_auth_response(_id_alice.id);
    resp.auth_time = time(NULL) - 10;
    ozayn_sess_t session;
    ozayn_sess_create(&_svc, &resp, &session);

    ASSERT_EQ(OZAYN_SESS_OK, ozayn_sess_expire(&_svc));

    ozayn_sess_t out;
    ozayn_sess_get(&_svc, session.id, &out);
    ASSERT_EQ(OZAYN_SESS_STATE_EXPIRED, out.state);
    _teardown_deps();
    return 0;
}

TEST(test_expire_leaves_active_alone)
{
    _setup_deps();
    _init_session_svc();

    ozayn_identity_t _id_alice = _create_identity("alice");
    ozayn_authn_response_t resp = _make_auth_response(_id_alice.id);
    ozayn_sess_t session;
    ozayn_sess_create(&_svc, &resp, &session);

    ASSERT_EQ(OZAYN_SESS_OK, ozayn_sess_expire(&_svc));

    ozayn_sess_t out;
    ASSERT_EQ(OZAYN_SESS_OK,
              ozayn_sess_validate(&_svc, session.id, &out));
    ASSERT_EQ(OZAYN_SESS_STATE_ACTIVE, out.state);
    _teardown_deps();
    return 0;
}

TEST(test_expire_null)
{
    ASSERT_EQ(OZAYN_SESS_ERR_NULL, ozayn_sess_expire(NULL));
    return 0;
}

TEST(test_expire_not_initialized)
{
    ozayn_sess_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ASSERT_EQ(OZAYN_SESS_ERR_NOT_INITIALIZED, ozayn_sess_expire(&svc));
    return 0;
}

/* ============================================================
 * 17. SECURITY — SESSION ID UNIQUENESS
 * ============================================================ */

TEST(test_unique_ids_across_many_sessions)
{
    _setup_deps();

    ozayn_sess_service_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.identity_service = &_id_svc;
    cfg.policy = ozayn_sess_test_policy();
    cfg.policy.max_sessions_per_identity = 16;
    cfg.policy.max_sessions_total = 16;
    ozayn_sess_service_init(&_svc, &cfg);

    ozayn_identity_t _id_alice = _create_identity("alice");

    ozayn_authn_response_t resp = _make_auth_response(_id_alice.id);
    char seen[16][OZAYN_SESS_MAX_ID_LEN];

    for (int i = 0; i < 16; i++) {
        ozayn_sess_t s;
        ASSERT_EQ(OZAYN_SESS_OK,
                  ozayn_sess_create(&_svc, &resp, &s));
        strncpy(seen[i], s.id, sizeof(seen[i]));
    }

    for (int i = 0; i < 16; i++) {
        for (int j = i + 1; j < 16; j++) {
            ASSERT(strcmp(seen[i], seen[j]) != 0);
        }
    }
    _teardown_deps();
    return 0;
}

TEST(test_session_id_not_empty)
{
    _setup_deps();
    _init_session_svc();
    ozayn_identity_t _id_alice = _create_identity("alice");
    ozayn_authn_response_t resp = _make_auth_response(_id_alice.id);
    ozayn_sess_t s;
    ozayn_sess_create(&_svc, &resp, &s);
    ASSERT(s.id[0] != '\0');
    _teardown_deps();
    return 0;
}

/* ============================================================
 * 18. SECURITY — NO SESSION RESURRECTION
 * ============================================================ */

TEST(test_terminated_session_cannot_be_validated)
{
    _setup_deps();
    _init_session_svc();
    ozayn_identity_t _id_alice = _create_identity("alice");
    ozayn_authn_response_t resp = _make_auth_response(_id_alice.id);
    ozayn_sess_t created;
    ozayn_sess_create(&_svc, &resp, &created);

    ozayn_sess_terminate(&_svc, created.id);

    ozayn_sess_t out;
    ASSERT_NEQ(OZAYN_SESS_OK,
               ozayn_sess_validate(&_svc, created.id, &out));
    _teardown_deps();
    return 0;
}

TEST(test_revoked_session_cannot_be_validated)
{
    _setup_deps();
    _init_session_svc();
    ozayn_identity_t _id_alice = _create_identity("alice");
    ozayn_authn_response_t resp = _make_auth_response(_id_alice.id);
    ozayn_sess_t created;
    ozayn_sess_create(&_svc, &resp, &created);

    ozayn_sess_revoke(&_svc, created.id);

    ozayn_sess_t out;
    ASSERT_NEQ(OZAYN_SESS_OK,
               ozayn_sess_validate(&_svc, created.id, &out));
    _teardown_deps();
    return 0;
}

TEST(test_expired_session_cannot_be_validated)
{
    _setup_deps();

    ozayn_sess_service_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.identity_service = &_id_svc;
    cfg.policy = ozayn_sess_test_policy();
    cfg.policy.idle_timeout_seconds = 1;
    cfg.policy.absolute_lifetime_seconds = 300;
    ozayn_sess_service_init(&_svc, &cfg);

    ozayn_identity_t _id_alice = _create_identity("alice");
    ozayn_authn_response_t resp = _make_auth_response(_id_alice.id);
    resp.auth_time = time(NULL) - 10;
    ozayn_sess_t session;
    ozayn_sess_create(&_svc, &resp, &session);

    ozayn_sess_expire(&_svc);

    ozayn_sess_t out;
    ASSERT_NEQ(OZAYN_SESS_OK,
               ozayn_sess_validate(&_svc, session.id, &out));
    _teardown_deps();
    return 0;
}

TEST(test_revoked_cannot_be_terminated)
{
    _setup_deps();
    _init_session_svc();
    ozayn_identity_t _id_alice = _create_identity("alice");
    ozayn_authn_response_t resp = _make_auth_response(_id_alice.id);
    ozayn_sess_t created;
    ozayn_sess_create(&_svc, &resp, &created);

    ozayn_sess_revoke(&_svc, created.id);
    ASSERT_EQ(OZAYN_SESS_ERR_STATE_TRANSITION_INVALID,
              ozayn_sess_terminate(&_svc, created.id));
    _teardown_deps();
    return 0;
}

/* ============================================================
 * 19. SECURITY — NO UNAUTHENTICATED SESSION CREATION
 * ============================================================ */

TEST(test_no_session_without_auth_success)
{
    _setup_deps();
    _init_session_svc();
    ozayn_identity_t _id_alice = _create_identity("alice");

    ozayn_authn_response_t resp = _make_auth_response(_id_alice.id);
    resp.result = OZAYN_AuthN_RESULT_FAILED;
    ozayn_sess_t session;
    ASSERT_EQ(OZAYN_SESS_ERR_AUTH_FAILED,
              ozayn_sess_create(&_svc, &resp, &session));
    ASSERT_EQ(0, ozayn_sess_service_session_count(&_svc));
    _teardown_deps();
    return 0;
}

TEST(test_no_session_without_verification)
{
    _setup_deps();
    _init_session_svc();
    ozayn_identity_t _id_alice = _create_identity("alice");

    ozayn_authn_response_t resp = _make_auth_response(_id_alice.id);
    resp.verification = OZAYN_AuthN_VERIFY_NOT_VERIFIED;
    ozayn_sess_t session;
    ASSERT_EQ(OZAYN_SESS_ERR_AUTH_FAILED,
              ozayn_sess_create(&_svc, &resp, &session));
    _teardown_deps();
    return 0;
}

/* ============================================================
 * 20. SECURITY — NO AUTHORIZATION LOGIC
 * ============================================================ */

TEST(test_session_has_no_role_field)
{
    _setup_deps();
    _init_session_svc();
    ozayn_sess_t s = _create_session_for("alice");
    ASSERT(sizeof(s) > 0);
    ASSERT(sizeof(s) < 1024);
    _teardown_deps();
    return 0;
}

/* ============================================================
 * 21. CONCURRENCY-LIKE SCENARIOS (sequential)
 * ============================================================ */

TEST(test_concurrent_create_validate)
{
    _setup_deps();
    _init_session_svc();
    ozayn_identity_t _id_alice = _create_identity("alice");

    ozayn_authn_response_t resp = _make_auth_response(_id_alice.id);
    ozayn_sess_t s1, s2, v1;

    ASSERT_EQ(OZAYN_SESS_OK,
              ozayn_sess_create(&_svc, &resp, &s1));
    ASSERT_EQ(OZAYN_SESS_OK,
              ozayn_sess_validate(&_svc, s1.id, &v1));
    ASSERT_EQ(OZAYN_SESS_OK,
              ozayn_sess_create(&_svc, &resp, &s2));
    ASSERT(strcmp((s1.id), (s2.id)) != 0);
    _teardown_deps();
    return 0;
}

TEST(test_concurrent_create_terminate)
{
    _setup_deps();
    _init_session_svc();
    ozayn_identity_t _id_alice = _create_identity("alice");

    ozayn_authn_response_t resp = _make_auth_response(_id_alice.id);
    ozayn_sess_t s1, s2;

    ASSERT_EQ(OZAYN_SESS_OK,
              ozayn_sess_create(&_svc, &resp, &s1));
    ASSERT_EQ(OZAYN_SESS_OK,
              ozayn_sess_terminate(&_svc, s1.id));
    ASSERT_EQ(OZAYN_SESS_OK,
              ozayn_sess_create(&_svc, &resp, &s2));
    ASSERT(strcmp((s1.id), (s2.id)) != 0);
    _teardown_deps();
    return 0;
}

TEST(test_concurrent_validate_expire)
{
    _setup_deps();

    ozayn_sess_service_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.identity_service = &_id_svc;
    cfg.policy = ozayn_sess_test_policy();
    cfg.policy.idle_timeout_seconds = 1;
    cfg.policy.absolute_lifetime_seconds = 300;
    ozayn_sess_service_init(&_svc, &cfg);

    ozayn_identity_t _id_alice = _create_identity("alice");
    ozayn_authn_response_t resp = _make_auth_response(_id_alice.id);
    resp.auth_time = time(NULL) - 10;
    ozayn_sess_t session;
    ozayn_sess_create(&_svc, &resp, &session);

    ozayn_sess_expire(&_svc);

    ozayn_sess_t out;
    ASSERT_NEQ(OZAYN_SESS_OK,
               ozayn_sess_validate(&_svc, session.id, &out));
    _teardown_deps();
    return 0;
}

TEST(test_concurrent_validate_revoke)
{
    _setup_deps();
    _init_session_svc();
    ozayn_identity_t _id_alice = _create_identity("alice");

    ozayn_authn_response_t resp = _make_auth_response(_id_alice.id);
    ozayn_sess_t s1;
    ASSERT_EQ(OZAYN_SESS_OK,
              ozayn_sess_create(&_svc, &resp, &s1));

    ozayn_sess_revoke(&_svc, s1.id);

    ozayn_sess_t out;
    ASSERT_NEQ(OZAYN_SESS_OK,
               ozayn_sess_validate(&_svc, s1.id, &out));
    _teardown_deps();
    return 0;
}

TEST(test_concurrent_terminate_revoke)
{
    _setup_deps();
    _init_session_svc();
    ozayn_identity_t _id_alice = _create_identity("alice");

    ozayn_authn_response_t resp = _make_auth_response(_id_alice.id);
    ozayn_sess_t s1;
    ASSERT_EQ(OZAYN_SESS_OK,
              ozayn_sess_create(&_svc, &resp, &s1));

    ozayn_sess_terminate(&_svc, s1.id);
    ASSERT_EQ(OZAYN_SESS_ERR_STATE_TRANSITION_INVALID,
              ozayn_sess_revoke(&_svc, s1.id));
    _teardown_deps();
    return 0;
}

TEST(test_concurrent_validate_terminate_validate)
{
    _setup_deps();
    _init_session_svc();
    ozayn_identity_t _id_alice = _create_identity("alice");

    ozayn_authn_response_t resp = _make_auth_response(_id_alice.id);
    ozayn_sess_t s1;
    ASSERT_EQ(OZAYN_SESS_OK,
              ozayn_sess_create(&_svc, &resp, &s1));

    ozayn_sess_t out;
    ASSERT_EQ(OZAYN_SESS_OK,
              ozayn_sess_validate(&_svc, s1.id, &out));
    ozayn_sess_terminate(&_svc, s1.id);
    ASSERT_NEQ(OZAYN_SESS_OK,
               ozayn_sess_validate(&_svc, s1.id, &out));
    _teardown_deps();
    return 0;
}

TEST(test_concurrent_identity_revoke_session_validate)
{
    _setup_deps();
    _init_session_svc();
    ozayn_identity_t _id_alice = _create_identity("alice");

    ozayn_authn_response_t resp = _make_auth_response(_id_alice.id);
    ozayn_sess_t s1;
    ASSERT_EQ(OZAYN_SESS_OK,
              ozayn_sess_create(&_svc, &resp, &s1));

    ozayn_id_revoke(&_id_svc, _id_alice.id);

    ozayn_sess_t out;
    ASSERT_NEQ(OZAYN_SESS_OK,
               ozayn_sess_validate(&_svc, s1.id, &out));
    ASSERT_EQ(OZAYN_SESS_STATE_REVOKED, out.state);
    _teardown_deps();
    return 0;
}

/* ============================================================
 * 22. CONCURRENT VALIDATE OPERATIONS
 * ============================================================ */

TEST(test_multiple_validate_same_session)
{
    _setup_deps();
    _init_session_svc();
    ozayn_identity_t _id_alice = _create_identity("alice");

    ozayn_authn_response_t resp = _make_auth_response(_id_alice.id);
    ozayn_sess_t s1;
    ASSERT_EQ(OZAYN_SESS_OK,
              ozayn_sess_create(&_svc, &resp, &s1));

    ozayn_sess_t out;
    for (int i = 0; i < 10; i++) {
        ASSERT_EQ(OZAYN_SESS_OK,
                  ozayn_sess_validate(&_svc, s1.id, &out));
    }
    _teardown_deps();
    return 0;
}

TEST(test_multiple_validate_different_sessions)
{
    _setup_deps();
    _init_session_svc();
    ozayn_identity_t _id_alice = _create_identity("alice");
    ozayn_identity_t _id_bob = _create_identity("bob");

    ozayn_authn_response_t resp_a = _make_auth_response(_id_alice.id);
    ozayn_authn_response_t resp_b = _make_auth_response(_id_bob.id);
    ozayn_sess_t sa, sb;
    ASSERT_EQ(OZAYN_SESS_OK,
              ozayn_sess_create(&_svc, &resp_a, &sa));
    ASSERT_EQ(OZAYN_SESS_OK,
              ozayn_sess_create(&_svc, &resp_b, &sb));

    ozayn_sess_t out_a, out_b;
    ASSERT_EQ(OZAYN_SESS_OK,
              ozayn_sess_validate(&_svc, sa.id, &out_a));
    ASSERT_EQ(OZAYN_SESS_OK,
              ozayn_sess_validate(&_svc, sb.id, &out_b));
    ASSERT_STR_EQ(_id_alice.id, out_a.identity_id);
    ASSERT_STR_EQ(_id_bob.id, out_b.identity_id);
    _teardown_deps();
    return 0;
}

/* ============================================================
 * 23. RESOURCE LIMITS
 * ============================================================ */

TEST(test_max_sessions_boundary)
{
    _setup_deps();

    ozayn_sess_service_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.identity_service = &_id_svc;
    cfg.policy = ozayn_sess_test_policy();
    cfg.policy.max_sessions_total = 4;
    cfg.policy.max_sessions_per_identity = 100;
    ozayn_sess_service_init(&_svc, &cfg);

    ozayn_identity_t _id_alice = _create_identity("alice");
    ozayn_authn_response_t resp = _make_auth_response(_id_alice.id);
    ozayn_sess_t s;

    for (int i = 0; i < 4; i++) {
        ASSERT_EQ(OZAYN_SESS_OK,
                  ozayn_sess_create(&_svc, &resp, &s));
    }
    ASSERT_EQ(OZAYN_SESS_ERR_LIMIT_REACHED,
              ozayn_sess_create(&_svc, &resp, &s));
    ASSERT_EQ(4, ozayn_sess_service_session_count(&_svc));
    _teardown_deps();
    return 0;
}

TEST(test_per_identity_limit)
{
    _setup_deps();

    ozayn_sess_service_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.identity_service = &_id_svc;
    cfg.policy = ozayn_sess_test_policy();
    cfg.policy.max_sessions_per_identity = 2;
    cfg.policy.max_sessions_total = 100;
    ozayn_sess_service_init(&_svc, &cfg);

    ozayn_identity_t _id_alice = _create_identity("alice");
    ozayn_authn_response_t resp = _make_auth_response(_id_alice.id);
    ozayn_sess_t s;

    ASSERT_EQ(OZAYN_SESS_OK,
              ozayn_sess_create(&_svc, &resp, &s));
    ASSERT_EQ(OZAYN_SESS_OK,
              ozayn_sess_create(&_svc, &resp, &s));
    ASSERT_EQ(OZAYN_SESS_ERR_LIMIT_REACHED,
              ozayn_sess_create(&_svc, &resp, &s));
    _teardown_deps();
    return 0;
}

TEST(test_terminated_sessions_free_slot)
{
    _setup_deps();

    ozayn_sess_service_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.identity_service = &_id_svc;
    cfg.policy = ozayn_sess_test_policy();
    cfg.policy.max_sessions_total = 2;
    cfg.policy.max_sessions_per_identity = 100;
    ozayn_sess_service_init(&_svc, &cfg);

    ozayn_identity_t _id_alice = _create_identity("alice");
    ozayn_authn_response_t resp = _make_auth_response(_id_alice.id);
    ozayn_sess_t s1, s2;

    ASSERT_EQ(OZAYN_SESS_OK,
              ozayn_sess_create(&_svc, &resp, &s1));
    ASSERT_EQ(OZAYN_SESS_OK,
              ozayn_sess_create(&_svc, &resp, &s2));
    ASSERT_EQ(OZAYN_SESS_ERR_LIMIT_REACHED,
              ozayn_sess_create(&_svc, &resp, &s1));

    ozayn_sess_terminate(&_svc, s1.id);
    ASSERT_EQ(2, ozayn_sess_service_session_count(&_svc));
    _teardown_deps();
    return 0;
}

/* ============================================================
 * 24. NAME HELPERS
 * ============================================================ */

TEST(test_state_name)
{
    ASSERT_STR_EQ("UNINITIALIZED",
                  ozayn_sess_state_name(OZAYN_SESS_STATE_UNINITIALIZED));
    ASSERT_STR_EQ("ACTIVE",
                  ozayn_sess_state_name(OZAYN_SESS_STATE_ACTIVE));
    ASSERT_STR_EQ("EXPIRED",
                  ozayn_sess_state_name(OZAYN_SESS_STATE_EXPIRED));
    ASSERT_STR_EQ("REVOKED",
                  ozayn_sess_state_name(OZAYN_SESS_STATE_REVOKED));
    ASSERT_STR_EQ("TERMINATED",
                  ozayn_sess_state_name(OZAYN_SESS_STATE_TERMINATED));
    ASSERT_STR_EQ("UNKNOWN",
                  ozayn_sess_state_name((ozayn_sess_state_t)99));
    return 0;
}

TEST(test_error_name)
{
    ASSERT_STR_EQ("OK", ozayn_sess_error_name(OZAYN_SESS_OK));
    ASSERT_STR_EQ("NULL", ozayn_sess_error_name(OZAYN_SESS_ERR_NULL));
    ASSERT_STR_EQ("NOT_INITIALIZED",
                  ozayn_sess_error_name(OZAYN_SESS_ERR_NOT_INITIALIZED));
    ASSERT_STR_EQ("NOT_FOUND",
                  ozayn_sess_error_name(OZAYN_SESS_ERR_NOT_FOUND));
    ASSERT_STR_EQ("AUTH_FAILED",
                  ozayn_sess_error_name(OZAYN_SESS_ERR_AUTH_FAILED));
    ASSERT_STR_EQ("EXPIRED",
                  ozayn_sess_error_name(OZAYN_SESS_ERR_EXPIRED));
    ASSERT_STR_EQ("REVOKED",
                  ozayn_sess_error_name(OZAYN_SESS_ERR_REVOKED));
    ASSERT_STR_EQ("TERMINATED",
                  ozayn_sess_error_name(OZAYN_SESS_ERR_TERMINATED));
    ASSERT_STR_EQ("LIMIT_REACHED",
                  ozayn_sess_error_name(OZAYN_SESS_ERR_LIMIT_REACHED));
    ASSERT_STR_EQ("UNKNOWN",
                  ozayn_sess_error_name((ozayn_sess_error_t)999));
    return 0;
}

/* ============================================================
 * 25. EDGE CASES
 * ============================================================ */

TEST(test_create_disabled_policy)
{
    _setup_deps();

    ozayn_sess_service_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.identity_service = &_id_svc;
    cfg.policy = ozayn_sess_test_policy();
    cfg.policy.enabled = 0;
    ozayn_sess_service_init(&_svc, &cfg);

    ozayn_identity_t _id_alice = _create_identity("alice");
    ozayn_authn_response_t resp = _make_auth_response(_id_alice.id);
    ozayn_sess_t session;
    ASSERT_EQ(OZAYN_SESS_ERR_UNAVAILABLE,
              ozayn_sess_create(&_svc, &resp, &session));
    _teardown_deps();
    return 0;
}

TEST(test_validate_no_policy_rejects_creation)
{
    _setup_deps();

    ozayn_sess_service_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.identity_service = &_id_svc;
    cfg.policy.enabled = 0;
    ASSERT_EQ(OZAYN_SESS_OK,
              ozayn_sess_service_init(&_svc, &cfg));

    ozayn_identity_t id = _create_identity("alice");
    ozayn_authn_response_t resp = _make_auth_response(id.id);
    ozayn_sess_t session;
    ASSERT_EQ(OZAYN_SESS_ERR_UNAVAILABLE,
              ozayn_sess_create(&_svc, &resp, &session));

    _teardown_deps();
    return 0;
}

TEST(test_touch_not_initialized)
{
    ozayn_sess_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ASSERT_EQ(OZAYN_SESS_ERR_NOT_INITIALIZED,
              ozayn_sess_touch(&svc, "some_id"));
    return 0;
}

TEST(test_terminate_not_initialized)
{
    ozayn_sess_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ASSERT_EQ(OZAYN_SESS_ERR_NOT_INITIALIZED,
              ozayn_sess_terminate(&svc, "some_id"));
    return 0;
}

TEST(test_revoke_not_initialized)
{
    ozayn_sess_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ASSERT_EQ(OZAYN_SESS_ERR_NOT_INITIALIZED,
              ozayn_sess_revoke(&svc, "some_id"));
    return 0;
}

TEST(test_get_not_initialized)
{
    ozayn_sess_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_sess_t out;
    ASSERT_EQ(OZAYN_SESS_ERR_NOT_INITIALIZED,
              ozayn_sess_get(&svc, "some_id", &out));
    return 0;
}

/* ============================================================
 * 26. SCENARIO — FULL LIFECYCLE
 * ============================================================ */

TEST(test_scenario_full_lifecycle)
{
    _setup_deps();
    _init_session_svc();

    ozayn_identity_t _id_alice = _create_identity("alice");
    ozayn_authn_response_t resp = _make_auth_response(_id_alice.id);

    ozayn_sess_t s;
    ASSERT_EQ(OZAYN_SESS_OK,
              ozayn_sess_create(&_svc, &resp, &s));
    ASSERT_EQ(OZAYN_SESS_STATE_ACTIVE, s.state);

    ozayn_sess_t v;
    ASSERT_EQ(OZAYN_SESS_OK,
              ozayn_sess_validate(&_svc, s.id, &v));
    ASSERT_EQ(OZAYN_SESS_STATE_ACTIVE, v.state);

    ASSERT_EQ(OZAYN_SESS_OK,
              ozayn_sess_touch(&_svc, s.id));

    ASSERT_EQ(OZAYN_SESS_OK,
              ozayn_sess_terminate(&_svc, s.id));

    ASSERT_NEQ(OZAYN_SESS_OK,
               ozayn_sess_validate(&_svc, s.id, &v));
    ASSERT_EQ(OZAYN_SESS_STATE_TERMINATED, v.state);
    _teardown_deps();
    return 0;
}

TEST(test_scenario_revoke_and_validate)
{
    _setup_deps();
    _init_session_svc();

    ozayn_identity_t _id_alice = _create_identity("alice");
    ozayn_authn_response_t resp = _make_auth_response(_id_alice.id);

    ozayn_sess_t s;
    ASSERT_EQ(OZAYN_SESS_OK,
              ozayn_sess_create(&_svc, &resp, &s));

    ASSERT_EQ(OZAYN_SESS_OK,
              ozayn_sess_revoke(&_svc, s.id));

    ozayn_sess_t v;
    ASSERT_NEQ(OZAYN_SESS_OK,
               ozayn_sess_validate(&_svc, s.id, &v));
    ASSERT_EQ(OZAYN_SESS_STATE_REVOKED, v.state);
    _teardown_deps();
    return 0;
}

TEST(test_scenario_expire_and_validate)
{
    _setup_deps();

    ozayn_sess_service_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.identity_service = &_id_svc;
    cfg.policy = ozayn_sess_test_policy();
    cfg.policy.idle_timeout_seconds = 1;
    cfg.policy.absolute_lifetime_seconds = 300;
    ozayn_sess_service_init(&_svc, &cfg);

    ozayn_identity_t _id_alice = _create_identity("alice");
    ozayn_authn_response_t resp = _make_auth_response(_id_alice.id);
    resp.auth_time = time(NULL) - 10;
    ozayn_sess_t s;
    ozayn_sess_create(&_svc, &resp, &s);

    ozayn_sess_expire(&_svc);

    ozayn_sess_t v;
    ASSERT_NEQ(OZAYN_SESS_OK,
               ozayn_sess_validate(&_svc, s.id, &v));
    ASSERT_EQ(OZAYN_SESS_STATE_EXPIRED, v.state);
    _teardown_deps();
    return 0;
}

TEST(test_scenario_identity_revoke_invalidates_session)
{
    _setup_deps();
    _init_session_svc();

    ozayn_identity_t _id_alice = _create_identity("alice");
    ozayn_authn_response_t resp = _make_auth_response(_id_alice.id);

    ozayn_sess_t s;
    ASSERT_EQ(OZAYN_SESS_OK,
              ozayn_sess_create(&_svc, &resp, &s));

    ozayn_id_revoke(&_id_svc, _id_alice.id);

    ozayn_sess_t v;
    ASSERT_NEQ(OZAYN_SESS_OK,
               ozayn_sess_validate(&_svc, s.id, &v));
    ASSERT_EQ(OZAYN_SESS_STATE_REVOKED, v.state);
    _teardown_deps();
    return 0;
}

/* ============================================================
 * 27. NO SESSION SECRETS IN ERRORS
 * ============================================================ */

TEST(test_error_names_do_not_contain_session_id)
{
    const char *name = ozayn_sess_error_name(OZAYN_SESS_ERR_NOT_FOUND);
    ASSERT(name != NULL);
    ASSERT(strlen(name) > 0);
    ASSERT(strlen(name) < 100);
    return 0;
}

/* ============================================================
 * 28. ID GENERATION FAILURE (simulated)
 * ============================================================ */

TEST(test_generate_id_uses_libsodium)
{
    _setup_deps();
    _init_session_svc();
    ozayn_identity_t _id_alice = _create_identity("alice");
    ozayn_authn_response_t resp = _make_auth_response(_id_alice.id);
    ozayn_sess_t s;
    ASSERT_EQ(OZAYN_SESS_OK,
              ozayn_sess_create(&_svc, &resp, &s));
    size_t len = strlen(s.id);
    ASSERT(len > 20);
    _teardown_deps();
    return 0;
}

/* ============================================================
 * RUN SUITE
 * ============================================================ */

int run_session_management_tests(void)
{
    SUITE_BEGIN("Session Management");

    /* Policy */
    RUN(test_default_policy_valid);
    RUN(test_default_policy_validates);
    RUN(test_test_policy_valid);
    RUN(test_test_policy_validates);
    RUN(test_policy_disabled_valid);
    RUN(test_policy_null_invalid);
    RUN(test_policy_invalid_max_sessions);
    RUN(test_policy_invalid_timeouts);

    /* State */
    RUN(test_validate_state_all_valid);
    RUN(test_validate_state_invalid);

    /* Transitions */
    RUN(test_transition_uninitialized_to_active);
    RUN(test_transition_uninitialized_rejects_all_others);
    RUN(test_transition_active_to_expired);
    RUN(test_transition_active_to_revoked);
    RUN(test_transition_active_to_terminated);
    RUN(test_transition_active_rejects_others);
    RUN(test_terminal_states_reject_all);
    RUN(test_transition_invalid_states);

    /* ID validation */
    RUN(test_validate_id_null);
    RUN(test_validate_id_empty);
    RUN(test_validate_id_too_short);
    RUN(test_validate_id_valid);

    /* Service lifecycle */
    RUN(test_init_shutdown);
    RUN(test_init_null);
    RUN(test_init_missing_identity_service);
    RUN(test_init_invalid_policy);
    RUN(test_shutdown_null);
    RUN(test_query_not_initialized);

    /* Creation — happy path */
    RUN(test_create_session);
    RUN(test_create_session_generates_unique_id);
    RUN(test_create_session_id_length);

    /* Creation — auth failures */
    RUN(test_create_null);
    RUN(test_create_not_initialized);
    RUN(test_create_auth_failed);
    RUN(test_create_auth_rejected);
    RUN(test_create_not_verified);
    RUN(test_create_empty_identity);

    /* Creation — identity failures */
    RUN(test_create_identity_not_found);
    RUN(test_create_identity_revoked);
    RUN(test_create_identity_suspended);

    /* Creation — limits */
    RUN(test_create_limit_total);
    RUN(test_create_limit_per_identity);
    RUN(test_create_multiple_identities);

    /* Validation */
    RUN(test_validate_active_session);
    RUN(test_validate_null);
    RUN(test_validate_not_initialized);
    RUN(test_validate_not_found);
    RUN(test_validate_terminated);
    RUN(test_validate_revoked);
    RUN(test_validate_expired_idle);
    RUN(test_validate_expired_absolute);
    RUN(test_validate_identity_revoked);
    RUN(test_validate_identity_suspended);

    /* Get */
    RUN(test_get_session);
    RUN(test_get_not_found);
    RUN(test_get_null);

    /* Touch */
    RUN(test_touch_updates_activity);
    RUN(test_touch_not_found);
    RUN(test_touch_inactive_session);
    RUN(test_touch_extends_idle_timeout);

    /* Terminate */
    RUN(test_terminate);
    RUN(test_terminate_already_terminated);
    RUN(test_terminate_not_found);
    RUN(test_terminate_revoked_session);
    RUN(test_terminate_expired_session);
    RUN(test_terminate_null);

    /* Revoke */
    RUN(test_revoke);
    RUN(test_revoke_already_revoked);
    RUN(test_revoke_not_found);
    RUN(test_revoke_terminated_session);
    RUN(test_revoke_null);

    /* Expire */
    RUN(test_expire_scans_all);
    RUN(test_expire_leaves_active_alone);
    RUN(test_expire_null);
    RUN(test_expire_not_initialized);

    /* Security */
    RUN(test_unique_ids_across_many_sessions);
    RUN(test_session_id_not_empty);
    RUN(test_terminated_session_cannot_be_validated);
    RUN(test_revoked_session_cannot_be_validated);
    RUN(test_expired_session_cannot_be_validated);
    RUN(test_revoked_cannot_be_terminated);
    RUN(test_no_session_without_auth_success);
    RUN(test_no_session_without_verification);
    RUN(test_session_has_no_role_field);

    /* Concurrency scenarios */
    RUN(test_concurrent_create_validate);
    RUN(test_concurrent_create_terminate);
    RUN(test_concurrent_validate_expire);
    RUN(test_concurrent_validate_revoke);
    RUN(test_concurrent_terminate_revoke);
    RUN(test_concurrent_validate_terminate_validate);
    RUN(test_concurrent_identity_revoke_session_validate);

    /* Concurrent validate operations */
    RUN(test_multiple_validate_same_session);
    RUN(test_multiple_validate_different_sessions);

    /* Resource limits */
    RUN(test_max_sessions_boundary);
    RUN(test_per_identity_limit);
    RUN(test_terminated_sessions_free_slot);

    /* Name helpers */
    RUN(test_state_name);
    RUN(test_error_name);

    /* Edge cases */
    RUN(test_create_disabled_policy);
    RUN(test_validate_no_policy_rejects_creation);
    RUN(test_touch_not_initialized);
    RUN(test_terminate_not_initialized);
    RUN(test_revoke_not_initialized);
    RUN(test_get_not_initialized);

    /* Scenarios */
    RUN(test_scenario_full_lifecycle);
    RUN(test_scenario_revoke_and_validate);
    RUN(test_scenario_expire_and_validate);
    RUN(test_scenario_identity_revoke_invalidates_session);

    /* Security misc */
    RUN(test_error_names_do_not_contain_session_id);
    RUN(test_generate_id_uses_libsodium);

    SUITE_END();
    return _tf_suite_fail;
}
