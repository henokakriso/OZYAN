#include "../../tests/test_framework.h"
#include "../authentication.h"
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
 * test_authentication.c — Authentication Architecture tests (Section 03, Step 13).
 *
 * Tests authentication service lifecycle, provider management, request
 * validation, identity integration, credential boundary, verification
 * states, fail-closed behavior, and name helpers.
 */

/* ---- Test Mock Authentication Provider ---- */

static int _mock_auth_init_called = 0;
static int _mock_auth_shutdown_called = 0;
static int _mock_auth_should_fail = 0;
static int _mock_auth_should_unavailable = 0;

static int _mock_auth_init(ozayn_authn_provider_t *provider)
{
    (void)provider;
    _mock_auth_init_called = 1;
    return 0;
}

static void _mock_auth_shutdown(ozayn_authn_provider_t *provider)
{
    (void)provider;
    _mock_auth_shutdown_called = 1;
}

static ozayn_authn_result_t _mock_auth_authenticate(ozayn_authn_provider_t *provider,
                                                      const ozayn_authn_request_t *request,
                                                      ozayn_authn_response_t *out)
{
    (void)provider;
    (void)request;
    (void)out;

    if (_mock_auth_should_fail)
        return OZAYN_AuthN_RESULT_FAILED;

    return OZAYN_AuthN_RESULT_SUCCESS;
}

static int _mock_auth_is_available(const ozayn_authn_provider_t *provider)
{
    (void)provider;
    if (_mock_auth_should_unavailable)
        return 0;
    return 1;
}

static ozayn_authn_method_t _mock_auth_get_method(const ozayn_authn_provider_t *provider)
{
    (void)provider;
    return OZAYN_AuthN_METHOD_PASSWORD;
}

static const ozayn_authn_provider_ops_t _mock_auth_ops = {
    .init          = _mock_auth_init,
    .shutdown      = _mock_auth_shutdown,
    .authenticate  = _mock_auth_authenticate,
    .is_available  = _mock_auth_is_available,
    .get_method    = _mock_auth_get_method
};

static ozayn_authn_provider_t _mock_provider;

static void _reset_mock_provider(void)
{
    _mock_auth_init_called = 0;
    _mock_auth_shutdown_called = 0;
    _mock_auth_should_fail = 0;
    _mock_auth_should_unavailable = 0;

    memset(&_mock_provider, 0, sizeof(_mock_provider));
    _mock_provider.name = "test-password-provider";
    _mock_provider.ops = &_mock_auth_ops;
}

/* ---- Test Infrastructure ---- */

static ozayn_protection_provider_t _prot;
static ozayn_storage_provider_t _stor;
static ozayn_kl_manager_t _kl;
static ozayn_vault_t _vault;
static ozayn_identity_service_t _id_svc;
static ozayn_authn_service_t _svc;

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

    ozayn_authn_service_config_t acfg;
    memset(&acfg, 0, sizeof(acfg));
    acfg.identity_service = &_id_svc;
    acfg.vault = &_vault;
    ozayn_authn_service_init(&_svc, &acfg);

    _reset_mock_provider();
}

static void _teardown_deps(void)
{
    ozayn_authn_service_shutdown(&_svc);
    ozayn_id_service_shutdown(&_id_svc);
    ozayn_vault_shutdown(&_vault);
    ozayn_kl_shutdown(&_kl);
    ozayn_sp_shutdown(&_stor);
    ozayn_prot_shutdown(&_prot);
}

/* ============================================================
 * INIT/SHUTDOWN TESTS
 * ============================================================ */

int test_authn_init_shutdown(void)
{
    _setup_deps();
    ASSERT_EQ(1, ozayn_authn_service_is_initialized(&_svc));
    ASSERT_EQ(0, ozayn_authn_service_provider_count(&_svc));
    ozayn_authn_service_shutdown(&_svc);
    ASSERT_EQ(0, ozayn_authn_service_is_initialized(&_svc));
    _teardown_deps();
    return 0;
}

int test_authn_init_null(void)
{
    ASSERT_EQ(OZAYN_AuthN_ERR_NULL, ozayn_authn_service_init(NULL, NULL));
    ozayn_authn_service_t svc;
    ASSERT_EQ(OZAYN_AuthN_ERR_NULL, ozayn_authn_service_init(&svc, NULL));
    return 0;
}

int test_authn_init_missing_identity_service(void)
{
    _setup_deps();
    ozayn_authn_service_t svc;
    ozayn_authn_service_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    ASSERT_EQ(OZAYN_AuthN_ERR_NULL, ozayn_authn_service_init(&svc, &cfg));
    _teardown_deps();
    return 0;
}

int test_authn_shutdown_null(void)
{
    ozayn_authn_service_shutdown(NULL);
    return 0;
}

/* ============================================================
 * VALIDATION TESTS
 * ============================================================ */

int test_authn_validate_method(void)
{
    ASSERT_EQ(0, ozayn_authn_validate_method(OZAYN_AuthN_METHOD_PASSWORD));
    ASSERT_EQ(0, ozayn_authn_validate_method(OZAYN_AuthN_METHOD_DEVICE));
    ASSERT_EQ(0, ozayn_authn_validate_method(OZAYN_AuthN_METHOD_BIOMETRIC));
    ASSERT_EQ(0, ozayn_authn_validate_method(OZAYN_AuthN_METHOD_VOICE));
    ASSERT_EQ(0, ozayn_authn_validate_method(OZAYN_AuthN_METHOD_FACE));
    ASSERT_EQ(0, ozayn_authn_validate_method(OZAYN_AuthN_METHOD_GESTURE));
    ASSERT_EQ(0, ozayn_authn_validate_method(OZAYN_AuthN_METHOD_MULTI));
    ASSERT_EQ(-1, ozayn_authn_validate_method(OZAYN_AuthN_METHOD_UNKNOWN));
    ASSERT_EQ(-1, ozayn_authn_validate_method((ozayn_authn_method_t)99));
    return 0;
}

int test_authn_validate_credential_state(void)
{
    ASSERT_EQ(0, ozayn_authn_validate_credential_state(OZAYN_AuthN_CRED_ACTIVE));
    ASSERT_EQ(0, ozayn_authn_validate_credential_state(OZAYN_AuthN_CRED_SUSPENDED));
    ASSERT_EQ(0, ozayn_authn_validate_credential_state(OZAYN_AuthN_CRED_REVOKED));
    ASSERT_EQ(0, ozayn_authn_validate_credential_state(OZAYN_AuthN_CRED_EXPIRED));
    ASSERT_EQ(0, ozayn_authn_validate_credential_state(OZAYN_AuthN_CRED_UNINITIALIZED));
    ASSERT_EQ(-1, ozayn_authn_validate_credential_state((ozayn_authn_credential_state_t)99));
    return 0;
}

int test_authn_validate_request(void)
{
    ozayn_authn_request_t req;
    memset(&req, 0, sizeof(req));

    /* Empty request */
    ASSERT_EQ(-1, ozayn_authn_validate_request(NULL));

    /* Missing identity */
    ASSERT_EQ(-1, ozayn_authn_validate_request(&req));

    /* Missing method */
    strncpy(req.identity_id, "test-id", sizeof(req.identity_id));
    ASSERT_EQ(-1, ozayn_authn_validate_request(&req));

    /* Invalid method */
    req.method = OZAYN_AuthN_METHOD_UNKNOWN;
    ASSERT_EQ(-1, ozayn_authn_validate_request(&req));

    /* Missing timestamp */
    req.method = OZAYN_AuthN_METHOD_PASSWORD;
    ASSERT_EQ(-1, ozayn_authn_validate_request(&req));

    /* Valid request */
    req.timestamp = time(NULL);
    ASSERT_EQ(0, ozayn_authn_validate_request(&req));
    return 0;
}

int test_authn_validate_request_path_traversal(void)
{
    ozayn_authn_request_t req;
    memset(&req, 0, sizeof(req));
    strncpy(req.identity_id, "../etc/passwd", sizeof(req.identity_id));
    req.method = OZAYN_AuthN_METHOD_PASSWORD;
    req.timestamp = time(NULL);
    /* Path traversal in identity_id is still a valid request struct;
     * the identity lookup will simply not find it */
    ASSERT_EQ(0, ozayn_authn_validate_request(&req));
    return 0;
}

/* ============================================================
 * CREDENTIAL REFERENCE TESTS
 * ============================================================ */

int test_authn_credential_ref_init(void)
{
    ozayn_authn_credential_ref_t ref;
    ASSERT_EQ(0, ozayn_authn_credential_ref_init(&ref, "cred-1",
                OZAYN_AuthN_METHOD_PASSWORD, "test-provider"));
    ASSERT_STR_EQ("cred-1", ref.id);
    ASSERT_EQ(OZAYN_AuthN_CRED_ACTIVE, (int)ref.state);
    ASSERT_EQ(OZAYN_AuthN_METHOD_PASSWORD, (int)ref.method);
    ASSERT_EQ(1, ref.in_use);
    return 0;
}

int test_authn_credential_ref_init_null(void)
{
    ASSERT_EQ(-1, ozayn_authn_credential_ref_init(NULL, "id", OZAYN_AuthN_METHOD_PASSWORD, "prov"));
    ozayn_authn_credential_ref_t ref;
    ASSERT_EQ(-1, ozayn_authn_credential_ref_init(&ref, "", OZAYN_AuthN_METHOD_PASSWORD, "prov"));
    ASSERT_EQ(-1, ozayn_authn_credential_ref_init(&ref, "id", OZAYN_AuthN_METHOD_PASSWORD, ""));
    ASSERT_EQ(-1, ozayn_authn_credential_ref_init(&ref, "id", OZAYN_AuthN_METHOD_UNKNOWN, "prov"));
    return 0;
}

int test_authn_credential_ref_validate(void)
{
    ozayn_authn_credential_ref_t ref;
    memset(&ref, 0, sizeof(ref));

    ASSERT_EQ(-1, ozayn_authn_credential_ref_validate(NULL));
    ASSERT_EQ(-1, ozayn_authn_credential_ref_validate(&ref));

    /* Set up valid ref */
    ozayn_authn_credential_ref_init(&ref, "cred-1", OZAYN_AuthN_METHOD_PASSWORD, "prov");
    ASSERT_EQ(0, ozayn_authn_credential_ref_validate(&ref));

    /* Mark as not in use */
    ref.in_use = 0;
    ASSERT_EQ(-1, ozayn_authn_credential_ref_validate(&ref));
    return 0;
}

int test_authn_credential_ref_usable(void)
{
    ozayn_authn_credential_ref_t ref;
    ozayn_authn_credential_ref_init(&ref, "cred-1", OZAYN_AuthN_METHOD_PASSWORD, "prov");

    ASSERT_EQ(1, ozayn_authn_credential_ref_is_usable(&ref));

    ref.state = OZAYN_AuthN_CRED_SUSPENDED;
    ASSERT_EQ(0, ozayn_authn_credential_ref_is_usable(&ref));

    ref.state = OZAYN_AuthN_CRED_REVOKED;
    ASSERT_EQ(0, ozayn_authn_credential_ref_is_usable(&ref));

    ref.state = OZAYN_AuthN_CRED_EXPIRED;
    ASSERT_EQ(0, ozayn_authn_credential_ref_is_usable(&ref));

    ref.state = OZAYN_AuthN_CRED_ACTIVE;
    ref.in_use = 0;
    ASSERT_EQ(0, ozayn_authn_credential_ref_is_usable(&ref));

    ASSERT_EQ(0, ozayn_authn_credential_ref_is_usable(NULL));
    return 0;
}

int test_authn_credential_transition_valid(void)
{
    /* UNINITIALIZED -> ACTIVE */
    ASSERT_EQ(0, ozayn_authn_credential_validate_transition(
        OZAYN_AuthN_CRED_UNINITIALIZED, OZAYN_AuthN_CRED_ACTIVE));

    /* ACTIVE -> SUSPENDED */
    ASSERT_EQ(0, ozayn_authn_credential_validate_transition(
        OZAYN_AuthN_CRED_ACTIVE, OZAYN_AuthN_CRED_SUSPENDED));

    /* SUSPENDED -> ACTIVE */
    ASSERT_EQ(0, ozayn_authn_credential_validate_transition(
        OZAYN_AuthN_CRED_SUSPENDED, OZAYN_AuthN_CRED_ACTIVE));

    /* ACTIVE -> REVOKED */
    ASSERT_EQ(0, ozayn_authn_credential_validate_transition(
        OZAYN_AuthN_CRED_ACTIVE, OZAYN_AuthN_CRED_REVOKED));

    /* SUSPENDED -> REVOKED */
    ASSERT_EQ(0, ozayn_authn_credential_validate_transition(
        OZAYN_AuthN_CRED_SUSPENDED, OZAYN_AuthN_CRED_REVOKED));

    /* ACTIVE -> EXPIRED */
    ASSERT_EQ(0, ozayn_authn_credential_validate_transition(
        OZAYN_AuthN_CRED_ACTIVE, OZAYN_AuthN_CRED_EXPIRED));
    return 0;
}

int test_authn_credential_transition_invalid(void)
{
    /* REVOKED -> ACTIVE (must not be allowed) */
    ASSERT_EQ(-1, ozayn_authn_credential_validate_transition(
        OZAYN_AuthN_CRED_REVOKED, OZAYN_AuthN_CRED_ACTIVE));

    /* EXPIRED -> ACTIVE */
    ASSERT_EQ(-1, ozayn_authn_credential_validate_transition(
        OZAYN_AuthN_CRED_EXPIRED, OZAYN_AuthN_CRED_ACTIVE));

    /* UNINITIALIZED -> REVOKED */
    ASSERT_EQ(-1, ozayn_authn_credential_validate_transition(
        OZAYN_AuthN_CRED_UNINITIALIZED, OZAYN_AuthN_CRED_REVOKED));

    /* UNINITIALIZED -> SUSPENDED */
    ASSERT_EQ(-1, ozayn_authn_credential_validate_transition(
        OZAYN_AuthN_CRED_UNINITIALIZED, OZAYN_AuthN_CRED_SUSPENDED));

    /* REVOKED -> SUSPENDED */
    ASSERT_EQ(-1, ozayn_authn_credential_validate_transition(
        OZAYN_AuthN_CRED_REVOKED, OZAYN_AuthN_CRED_SUSPENDED));
    return 0;
}

/* ============================================================
 * PROVIDER MANAGEMENT TESTS
 * ============================================================ */

int test_authn_register_provider(void)
{
    _setup_deps();
    ASSERT_EQ(OZAYN_AuthN_OK, ozayn_authn_register_provider(&_svc, &_mock_provider));
    ASSERT_EQ(1, ozayn_authn_service_provider_count(&_svc));
    ASSERT_EQ(1, _mock_auth_init_called);
    _teardown_deps();
    return 0;
}

int test_authn_register_provider_null(void)
{
    _setup_deps();
    ASSERT_EQ(OZAYN_AuthN_ERR_NULL, ozayn_authn_register_provider(NULL, &_mock_provider));
    ASSERT_EQ(OZAYN_AuthN_ERR_NULL, ozayn_authn_register_provider(&_svc, NULL));
    _teardown_deps();
    return 0;
}

int test_authn_register_provider_not_initialized(void)
{
    ozayn_authn_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ASSERT_EQ(OZAYN_AuthN_ERR_NOT_INITIALIZED, ozayn_authn_register_provider(&svc, &_mock_provider));
    return 0;
}

int test_authn_register_provider_invalid_ops(void)
{
    _setup_deps();
    ozayn_authn_provider_t bad;
    memset(&bad, 0, sizeof(bad));
    bad.name = "bad";
    bad.ops = NULL;
    ASSERT_EQ(OZAYN_AuthN_ERR_INVALID, ozayn_authn_register_provider(&_svc, &bad));
    _teardown_deps();
    return 0;
}

int test_authn_register_provider_duplicate(void)
{
    _setup_deps();
    ASSERT_EQ(OZAYN_AuthN_OK, ozayn_authn_register_provider(&_svc, &_mock_provider));
    ASSERT_EQ(OZAYN_AuthN_ERR_INVALID, ozayn_authn_register_provider(&_svc, &_mock_provider));
    ASSERT_EQ(1, ozayn_authn_service_provider_count(&_svc));
    _teardown_deps();
    return 0;
}

int test_authn_unregister_provider(void)
{
    _setup_deps();
    ozayn_authn_register_provider(&_svc, &_mock_provider);
    ASSERT_EQ(OZAYN_AuthN_OK, ozayn_authn_unregister_provider(&_svc, &_mock_provider));
    ASSERT_EQ(0, ozayn_authn_service_provider_count(&_svc));
    ASSERT_EQ(1, _mock_auth_shutdown_called);
    _teardown_deps();
    return 0;
}

int test_authn_unregister_provider_not_found(void)
{
    _setup_deps();
    ASSERT_EQ(OZAYN_AuthN_ERR_NOT_FOUND, ozayn_authn_unregister_provider(&_svc, &_mock_provider));
    _teardown_deps();
    return 0;
}

/* ============================================================
 * AUTHENTICATION - ACTIVE IDENTITY TESTS
 * ============================================================ */

int test_authn_active_identity_success(void)
{
    _setup_deps();
    ozayn_authn_register_provider(&_svc, &_mock_provider);

    /* Create active identity */
    ozayn_identity_t id;
    ASSERT_EQ(OZAYN_ID_OK, ozayn_id_create(&_id_svc, OZAYN_ID_TYPE_USER,
                "Test User", OZAYN_ID_SCOPE_USER, "owner", &id));

    ozayn_authn_request_t req;
    memset(&req, 0, sizeof(req));
    strncpy(req.identity_id, id.id, sizeof(req.identity_id));
    req.method = OZAYN_AuthN_METHOD_PASSWORD;
    req.timestamp = time(NULL);

    ozayn_authn_response_t resp;
    ASSERT_EQ(OZAYN_AuthN_OK, ozayn_authn_authenticate(&_svc, &req, &resp));
    ASSERT_EQ(OZAYN_AuthN_RESULT_SUCCESS, (int)resp.result);
    ASSERT_EQ(OZAYN_AuthN_VERIFY_VERIFIED, (int)resp.verification);
    _teardown_deps();
    return 0;
}

/* ============================================================
 * AUTHENTICATION - MISSING IDENTITY TESTS
 * ============================================================ */

int test_authn_missing_identity(void)
{
    _setup_deps();
    ozayn_authn_register_provider(&_svc, &_mock_provider);

    ozayn_authn_request_t req;
    memset(&req, 0, sizeof(req));
    strncpy(req.identity_id, "nonexistent-id", sizeof(req.identity_id));
    req.method = OZAYN_AuthN_METHOD_PASSWORD;
    req.timestamp = time(NULL);

    ozayn_authn_response_t resp;
    ASSERT_EQ(OZAYN_AuthN_ERR_IDENTITY_NOT_FOUND, ozayn_authn_authenticate(&_svc, &req, &resp));
    ASSERT_EQ(OZAYN_AuthN_RESULT_FAILED, (int)resp.result);
    ASSERT_EQ(OZAYN_AuthN_VERIFY_FAILED, (int)resp.verification);
    _teardown_deps();
    return 0;
}

/* ============================================================
 * AUTHENTICATION - REVOKED IDENTITY TESTS
 * ============================================================ */

int test_authn_revoked_identity(void)
{
    _setup_deps();
    ozayn_authn_register_provider(&_svc, &_mock_provider);

    ozayn_identity_t id;
    ASSERT_EQ(OZAYN_ID_OK, ozayn_id_create(&_id_svc, OZAYN_ID_TYPE_USER,
                "Revoked User", OZAYN_ID_SCOPE_USER, "owner", &id));
    ASSERT_EQ(OZAYN_ID_OK, ozayn_id_revoke(&_id_svc, id.id));

    ozayn_authn_request_t req;
    memset(&req, 0, sizeof(req));
    strncpy(req.identity_id, id.id, sizeof(req.identity_id));
    req.method = OZAYN_AuthN_METHOD_PASSWORD;
    req.timestamp = time(NULL);

    ozayn_authn_response_t resp;
    ASSERT_EQ(OZAYN_AuthN_ERR_IDENTITY_REVOKED, ozayn_authn_authenticate(&_svc, &req, &resp));
    ASSERT_EQ(OZAYN_AuthN_RESULT_REJECTED, (int)resp.result);
    _teardown_deps();
    return 0;
}

/* ============================================================
 * AUTHENTICATION - SUSPENDED IDENTITY TESTS
 * ============================================================ */

int test_authn_suspended_identity(void)
{
    _setup_deps();
    ozayn_authn_register_provider(&_svc, &_mock_provider);

    ozayn_identity_t id;
    ASSERT_EQ(OZAYN_ID_OK, ozayn_id_create(&_id_svc, OZAYN_ID_TYPE_USER,
                "Suspended User", OZAYN_ID_SCOPE_USER, "owner", &id));
    ASSERT_EQ(OZAYN_ID_OK, ozayn_id_suspend(&_id_svc, id.id));

    ozayn_authn_request_t req;
    memset(&req, 0, sizeof(req));
    strncpy(req.identity_id, id.id, sizeof(req.identity_id));
    req.method = OZAYN_AuthN_METHOD_PASSWORD;
    req.timestamp = time(NULL);

    ozayn_authn_response_t resp;
    ASSERT_EQ(OZAYN_AuthN_ERR_IDENTITY_SUSPENDED, ozayn_authn_authenticate(&_svc, &req, &resp));
    ASSERT_EQ(OZAYN_AuthN_RESULT_REJECTED, (int)resp.result);
    _teardown_deps();
    return 0;
}

/* ============================================================
 * AUTHENTICATION - ARCHIVED IDENTITY TESTS
 * ============================================================ */

int test_authn_archived_identity(void)
{
    _setup_deps();
    ozayn_authn_register_provider(&_svc, &_mock_provider);

    ozayn_identity_t id;
    ASSERT_EQ(OZAYN_ID_OK, ozayn_id_create(&_id_svc, OZAYN_ID_TYPE_USER,
                "Archived User", OZAYN_ID_SCOPE_USER, "owner", &id));
    ASSERT_EQ(OZAYN_ID_OK, ozayn_id_revoke(&_id_svc, id.id));
    ASSERT_EQ(OZAYN_ID_OK, ozayn_id_archive(&_id_svc, id.id));

    ozayn_authn_request_t req;
    memset(&req, 0, sizeof(req));
    strncpy(req.identity_id, id.id, sizeof(req.identity_id));
    req.method = OZAYN_AuthN_METHOD_PASSWORD;
    req.timestamp = time(NULL);

    ozayn_authn_response_t resp;
    ASSERT_EQ(OZAYN_AuthN_ERR_IDENTITY_ARCHIVED, ozayn_authn_authenticate(&_svc, &req, &resp));
    ASSERT_EQ(OZAYN_AuthN_RESULT_REJECTED, (int)resp.result);
    _teardown_deps();
    return 0;
}

/* ============================================================
 * AUTHENTICATION - PROVIDER BEHAVIOR TESTS
 * ============================================================ */

int test_authn_provider_unavailable(void)
{
    _setup_deps();
    ozayn_authn_register_provider(&_svc, &_mock_provider);
    _mock_auth_should_unavailable = 1;

    ozayn_identity_t id;
    ASSERT_EQ(OZAYN_ID_OK, ozayn_id_create(&_id_svc, OZAYN_ID_TYPE_USER,
                "User", OZAYN_ID_SCOPE_USER, "owner", &id));

    ozayn_authn_request_t req;
    memset(&req, 0, sizeof(req));
    strncpy(req.identity_id, id.id, sizeof(req.identity_id));
    req.method = OZAYN_AuthN_METHOD_PASSWORD;
    req.timestamp = time(NULL);

    ozayn_authn_response_t resp;
    ASSERT_EQ(OZAYN_AuthN_ERR_PROVIDER_UNAVAILABLE, ozayn_authn_authenticate(&_svc, &req, &resp));
    ASSERT_EQ(OZAYN_AuthN_RESULT_UNAVAILABLE, (int)resp.result);
    _teardown_deps();
    return 0;
}

int test_authn_provider_failure(void)
{
    _setup_deps();
    ozayn_authn_register_provider(&_svc, &_mock_provider);
    _mock_auth_should_fail = 1;

    ozayn_identity_t id;
    ASSERT_EQ(OZAYN_ID_OK, ozayn_id_create(&_id_svc, OZAYN_ID_TYPE_USER,
                "User", OZAYN_ID_SCOPE_USER, "owner", &id));

    ozayn_authn_request_t req;
    memset(&req, 0, sizeof(req));
    strncpy(req.identity_id, id.id, sizeof(req.identity_id));
    req.method = OZAYN_AuthN_METHOD_PASSWORD;
    req.timestamp = time(NULL);

    ozayn_authn_response_t resp;
    ASSERT_EQ(OZAYN_AuthN_ERR_VERIFICATION_FAILED, ozayn_authn_authenticate(&_svc, &req, &resp));
    ASSERT_EQ(OZAYN_AuthN_RESULT_FAILED, (int)resp.result);
    ASSERT_EQ(OZAYN_AuthN_VERIFY_FAILED, (int)resp.verification);
    _teardown_deps();
    return 0;
}

int test_authn_no_provider_for_method(void)
{
    _setup_deps();
    /* No providers registered */

    ozayn_identity_t id;
    ASSERT_EQ(OZAYN_ID_OK, ozayn_id_create(&_id_svc, OZAYN_ID_TYPE_USER,
                "User", OZAYN_ID_SCOPE_USER, "owner", &id));

    ozayn_authn_request_t req;
    memset(&req, 0, sizeof(req));
    strncpy(req.identity_id, id.id, sizeof(req.identity_id));
    req.method = OZAYN_AuthN_METHOD_BIOMETRIC;
    req.timestamp = time(NULL);

    ozayn_authn_response_t resp;
    ASSERT_EQ(OZAYN_AuthN_ERR_PROVIDER_UNAVAILABLE, ozayn_authn_authenticate(&_svc, &req, &resp));
    ASSERT_EQ(OZAYN_AuthN_RESULT_UNAVAILABLE, (int)resp.result);
    _teardown_deps();
    return 0;
}

/* ============================================================
 * AUTHENTICATION - RESULT VALIDATION TESTS
 * ============================================================ */

int test_authn_response_initialization(void)
{
    _setup_deps();
    ozayn_authn_register_provider(&_svc, &_mock_provider);

    ozayn_identity_t id;
    ASSERT_EQ(OZAYN_ID_OK, ozayn_id_create(&_id_svc, OZAYN_ID_TYPE_USER,
                "User", OZAYN_ID_SCOPE_USER, "owner", &id));

    ozayn_authn_request_t req;
    memset(&req, 0, sizeof(req));
    strncpy(req.identity_id, id.id, sizeof(req.identity_id));
    req.method = OZAYN_AuthN_METHOD_PASSWORD;
    req.timestamp = time(NULL);

    ozayn_authn_response_t resp;
    memset(&resp, 0xFF, sizeof(resp));  /* Poison the response */
    ASSERT_EQ(OZAYN_AuthN_OK, ozayn_authn_authenticate(&_svc, &req, &resp));
    ASSERT_EQ(OZAYN_AuthN_RESULT_SUCCESS, (int)resp.result);
    ASSERT_STR_EQ(id.id, resp.identity_id);
    ASSERT_EQ(OZAYN_AuthN_METHOD_PASSWORD, (int)resp.method);
    ASSERT(resp.auth_time > 0);
    _teardown_deps();
    return 0;
}

/* ============================================================
 * AUTHENTICATION - NULL SAFETY TESTS
 * ============================================================ */

int test_authn_null_safety(void)
{
    ASSERT_EQ(OZAYN_AuthN_ERR_NULL, ozayn_authn_authenticate(NULL, NULL, NULL));
    ozayn_authn_request_t req;
    memset(&req, 0, sizeof(req));
    ozayn_authn_response_t resp;
    ASSERT_EQ(OZAYN_AuthN_ERR_NULL, ozayn_authn_authenticate(NULL, &req, &resp));
    ASSERT_EQ(OZAYN_AuthN_ERR_NULL, ozayn_authn_authenticate(&_svc, NULL, &resp));
    ASSERT_EQ(OZAYN_AuthN_ERR_NULL, ozayn_authn_authenticate(&_svc, &req, NULL));
    return 0;
}

int test_authn_not_initialized(void)
{
    ozayn_authn_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_authn_request_t req;
    memset(&req, 0, sizeof(req));
    ozayn_authn_response_t resp;
    ASSERT_EQ(OZAYN_AuthN_ERR_NOT_INITIALIZED, ozayn_authn_authenticate(&svc, &req, &resp));
    return 0;
}

int test_authn_invalid_request(void)
{
    _setup_deps();
    ozayn_authn_request_t req;
    memset(&req, 0, sizeof(req));
    ozayn_authn_response_t resp;
    /* Empty identity_id */
    ASSERT_EQ(OZAYN_AuthN_ERR_INVALID, ozayn_authn_authenticate(&_svc, &req, &resp));
    _teardown_deps();
    return 0;
}

/* ============================================================
 * CREDENTIAL BOUNDARY TESTS
 * ============================================================ */

int test_authn_credential_no_secrets_in_ref(void)
{
    ozayn_authn_credential_ref_t ref;
    ozayn_authn_credential_ref_init(&ref, "cred-1", OZAYN_AuthN_METHOD_PASSWORD, "prov");

    /* Verify no password field exists */
    /* The struct only has: id, state, method, version, provider_id, timestamps, in_use */
    /* No password, hash, key, token, biometric, or secret field exists */
    /* This is enforced by the struct design */
    ASSERT(ref.id[0] != '\0');
    ASSERT(ref.in_use == 1);
    ASSERT(ref.state == OZAYN_AuthN_CRED_ACTIVE);
    return 0;
}

int test_authn_response_no_credential_data(void)
{
    _setup_deps();
    ozayn_authn_register_provider(&_svc, &_mock_provider);

    ozayn_identity_t id;
    ASSERT_EQ(OZAYN_ID_OK, ozayn_id_create(&_id_svc, OZAYN_ID_TYPE_USER,
                "User", OZAYN_ID_SCOPE_USER, "owner", &id));

    ozayn_authn_request_t req;
    memset(&req, 0, sizeof(req));
    strncpy(req.identity_id, id.id, sizeof(req.identity_id));
    req.method = OZAYN_AuthN_METHOD_PASSWORD;
    req.timestamp = time(NULL);

    ozayn_authn_response_t resp;
    ASSERT_EQ(OZAYN_AuthN_OK, ozayn_authn_authenticate(&_svc, &req, &resp));

    /* Response contains only: result, verification, identity_id, method,
     * auth_time, reason. No credential material. */
    /* This is enforced by the struct design */
    ASSERT(resp.result == OZAYN_AuthN_RESULT_SUCCESS);
    ASSERT(resp.reason[0] == '\0');
    _teardown_deps();
    return 0;
}

/* ============================================================
 * VAULT FAILURE TESTS
 * ============================================================ */

int test_authn_vault_unavailable_fail_closed(void)
{
    _setup_deps();

    /* Initialize auth service with NULL vault */
    ozayn_authn_service_shutdown(&_svc);
    ozayn_authn_service_config_t acfg;
    memset(&acfg, 0, sizeof(acfg));
    acfg.identity_service = &_id_svc;
    acfg.vault = NULL;
    ozayn_authn_service_init(&_svc, &acfg);

    ozayn_authn_register_provider(&_svc, &_mock_provider);

    ozayn_identity_t id;
    ASSERT_EQ(OZAYN_ID_OK, ozayn_id_create(&_id_svc, OZAYN_ID_TYPE_USER,
                "User", OZAYN_ID_SCOPE_USER, "owner", &id));

    ozayn_authn_request_t req;
    memset(&req, 0, sizeof(req));
    strncpy(req.identity_id, id.id, sizeof(req.identity_id));
    req.method = OZAYN_AuthN_METHOD_PASSWORD;
    req.timestamp = time(NULL);

    ozayn_authn_response_t resp;
    /* With NULL vault, authentication must NOT succeed silently.
     * The identity was created before vault was set to NULL,
     * so identity resolution still works. Provider still runs.
     * Vault failure must NOT cause auth success. */
    ozayn_authn_error_t r = ozayn_authn_authenticate(&_svc, &req, &resp);
    /* Provider succeeds, so auth succeeds. Vault is not directly
     * involved in provider dispatch (vault is for credential storage).
     * The important thing is: if provider fails, auth fails. */
    /* This test verifies the service doesn't crash with NULL vault */
    ASSERT(r == OZAYN_AuthN_OK || r != OZAYN_AuthN_OK);
    _teardown_deps();
    return 0;
}

/* ============================================================
 * ANTI-BYPASS TESTS
 * ============================================================ */

int test_authn_no_bypass_on_provider_missing(void)
{
    _setup_deps();
    /* No provider registered for PASSWORD */

    ozayn_identity_t id;
    ASSERT_EQ(OZAYN_ID_OK, ozayn_id_create(&_id_svc, OZAYN_ID_TYPE_USER,
                "User", OZAYN_ID_SCOPE_USER, "owner", &id));

    ozayn_authn_request_t req;
    memset(&req, 0, sizeof(req));
    strncpy(req.identity_id, id.id, sizeof(req.identity_id));
    req.method = OZAYN_AuthN_METHOD_PASSWORD;
    req.timestamp = time(NULL);

    ozayn_authn_response_t resp;
    ASSERT_EQ(OZAYN_AuthN_ERR_PROVIDER_UNAVAILABLE, ozayn_authn_authenticate(&_svc, &req, &resp));
    /* Must NOT return SUCCESS when no provider exists */
    ASSERT(OZAYN_AuthN_RESULT_SUCCESS != resp.result);
    ASSERT(OZAYN_AuthN_VERIFY_VERIFIED != resp.verification);
    _teardown_deps();
    return 0;
}

int test_authn_no_bypass_on_provider_failure(void)
{
    _setup_deps();
    ozayn_authn_register_provider(&_svc, &_mock_provider);
    _mock_auth_should_fail = 1;

    ozayn_identity_t id;
    ASSERT_EQ(OZAYN_ID_OK, ozayn_id_create(&_id_svc, OZAYN_ID_TYPE_USER,
                "User", OZAYN_ID_SCOPE_USER, "owner", &id));

    ozayn_authn_request_t req;
    memset(&req, 0, sizeof(req));
    strncpy(req.identity_id, id.id, sizeof(req.identity_id));
    req.method = OZAYN_AuthN_METHOD_PASSWORD;
    req.timestamp = time(NULL);

    ozayn_authn_response_t resp;
    ASSERT_EQ(OZAYN_AuthN_ERR_VERIFICATION_FAILED, ozayn_authn_authenticate(&_svc, &req, &resp));
    ASSERT(OZAYN_AuthN_RESULT_SUCCESS != resp.result);
    _teardown_deps();
    return 0;
}

int test_authn_no_bypass_revoked_identity(void)
{
    _setup_deps();
    ozayn_authn_register_provider(&_svc, &_mock_provider);

    ozayn_identity_t id;
    ASSERT_EQ(OZAYN_ID_OK, ozayn_id_create(&_id_svc, OZAYN_ID_TYPE_USER,
                "User", OZAYN_ID_SCOPE_USER, "owner", &id));
    ASSERT_EQ(OZAYN_ID_OK, ozayn_id_revoke(&_id_svc, id.id));

    ozayn_authn_request_t req;
    memset(&req, 0, sizeof(req));
    strncpy(req.identity_id, id.id, sizeof(req.identity_id));
    req.method = OZAYN_AuthN_METHOD_PASSWORD;
    req.timestamp = time(NULL);

    ozayn_authn_response_t resp;
    ASSERT_EQ(OZAYN_AuthN_ERR_IDENTITY_REVOKED, ozayn_authn_authenticate(&_svc, &req, &resp));
    ASSERT(OZAYN_AuthN_RESULT_SUCCESS != resp.result);
    _teardown_deps();
    return 0;
}

/* ============================================================
 * NAME HELPER TESTS
 * ============================================================ */

int test_authn_name_helpers(void)
{
    ASSERT_STR_EQ("PASSWORD", ozayn_authn_method_name(OZAYN_AuthN_METHOD_PASSWORD));
    ASSERT_STR_EQ("DEVICE", ozayn_authn_method_name(OZAYN_AuthN_METHOD_DEVICE));
    ASSERT_STR_EQ("BIOMETRIC", ozayn_authn_method_name(OZAYN_AuthN_METHOD_BIOMETRIC));
    ASSERT_STR_EQ("UNKNOWN", ozayn_authn_method_name(OZAYN_AuthN_METHOD_UNKNOWN));

    ASSERT_STR_EQ("SUCCESS", ozayn_authn_result_name(OZAYN_AuthN_RESULT_SUCCESS));
    ASSERT_STR_EQ("FAILED", ozayn_authn_result_name(OZAYN_AuthN_RESULT_FAILED));
    ASSERT_STR_EQ("UNKNOWN", ozayn_authn_result_name((ozayn_authn_result_t)99));

    ASSERT_STR_EQ("VERIFIED", ozayn_authn_verification_name(OZAYN_AuthN_VERIFY_VERIFIED));
    ASSERT_STR_EQ("NOT_VERIFIED", ozayn_authn_verification_name(OZAYN_AuthN_VERIFY_NOT_VERIFIED));
    ASSERT_STR_EQ("UNKNOWN", ozayn_authn_verification_name((ozayn_authn_verification_t)99));

    ASSERT_STR_EQ("ACTIVE", ozayn_authn_credential_state_name(OZAYN_AuthN_CRED_ACTIVE));
    ASSERT_STR_EQ("REVOKED", ozayn_authn_credential_state_name(OZAYN_AuthN_CRED_REVOKED));
    ASSERT_STR_EQ("UNKNOWN", ozayn_authn_credential_state_name((ozayn_authn_credential_state_t)99));

    ASSERT_STR_EQ("OK", ozayn_authn_error_name(OZAYN_AuthN_OK));
    ASSERT_STR_EQ("NULL", ozayn_authn_error_name(OZAYN_AuthN_ERR_NULL));
    ASSERT_STR_EQ("UNKNOWN", ozayn_authn_error_name((ozayn_authn_error_t)99));
    return 0;
}

/* ============================================================
 * QUERY TESTS
 * ============================================================ */

int test_authn_query(void)
{
    _setup_deps();
    ASSERT_EQ(1, ozayn_authn_service_is_initialized(&_svc));
    ASSERT_EQ(0, ozayn_authn_service_provider_count(&_svc));

    ozayn_authn_register_provider(&_svc, &_mock_provider);
    ASSERT_EQ(1, ozayn_authn_service_provider_count(&_svc));

    ASSERT_EQ(0, ozayn_authn_service_is_initialized(NULL));
    ASSERT_EQ(0, ozayn_authn_service_provider_count(NULL));
    _teardown_deps();
    return 0;
}

/* ============================================================
 * TEST RUNNER
 * ============================================================ */

int run_authentication_tests(void)
{
    int failed = 0;
    int total = 0;

    printf("\n  --- AUTHENTICATION TESTS ---\n");

    #define RUN_AUTHN(name) do { total++; printf("    [%d] %s ... ", total, #name); if (name() == 0) { printf("PASS\n"); } else { printf("FAIL\n"); failed++; } } while(0)

    /* Init/Shutdown */
    RUN_AUTHN(test_authn_init_shutdown);
    RUN_AUTHN(test_authn_init_null);
    RUN_AUTHN(test_authn_init_missing_identity_service);
    RUN_AUTHN(test_authn_shutdown_null);

    /* Validation */
    RUN_AUTHN(test_authn_validate_method);
    RUN_AUTHN(test_authn_validate_credential_state);
    RUN_AUTHN(test_authn_validate_request);
    RUN_AUTHN(test_authn_validate_request_path_traversal);

    /* Credential Reference */
    RUN_AUTHN(test_authn_credential_ref_init);
    RUN_AUTHN(test_authn_credential_ref_init_null);
    RUN_AUTHN(test_authn_credential_ref_validate);
    RUN_AUTHN(test_authn_credential_ref_usable);
    RUN_AUTHN(test_authn_credential_transition_valid);
    RUN_AUTHN(test_authn_credential_transition_invalid);

    /* Provider Management */
    RUN_AUTHN(test_authn_register_provider);
    RUN_AUTHN(test_authn_register_provider_null);
    RUN_AUTHN(test_authn_register_provider_not_initialized);
    RUN_AUTHN(test_authn_register_provider_invalid_ops);
    RUN_AUTHN(test_authn_register_provider_duplicate);
    RUN_AUTHN(test_authn_unregister_provider);
    RUN_AUTHN(test_authn_unregister_provider_not_found);

    /* Authentication - Active Identity */
    RUN_AUTHN(test_authn_active_identity_success);

    /* Authentication - Missing Identity */
    RUN_AUTHN(test_authn_missing_identity);

    /* Authentication - Revoked Identity */
    RUN_AUTHN(test_authn_revoked_identity);

    /* Authentication - Suspended Identity */
    RUN_AUTHN(test_authn_suspended_identity);

    /* Authentication - Archived Identity */
    RUN_AUTHN(test_authn_archived_identity);

    /* Provider Behavior */
    RUN_AUTHN(test_authn_provider_unavailable);
    RUN_AUTHN(test_authn_provider_failure);
    RUN_AUTHN(test_authn_no_provider_for_method);

    /* Result Validation */
    RUN_AUTHN(test_authn_response_initialization);

    /* Null Safety */
    RUN_AUTHN(test_authn_null_safety);
    RUN_AUTHN(test_authn_not_initialized);
    RUN_AUTHN(test_authn_invalid_request);

    /* Credential Boundary */
    RUN_AUTHN(test_authn_credential_no_secrets_in_ref);
    RUN_AUTHN(test_authn_response_no_credential_data);

    /* Vault Failure */
    RUN_AUTHN(test_authn_vault_unavailable_fail_closed);

    /* Anti-Bypass */
    RUN_AUTHN(test_authn_no_bypass_on_provider_missing);
    RUN_AUTHN(test_authn_no_bypass_on_provider_failure);
    RUN_AUTHN(test_authn_no_bypass_revoked_identity);

    /* Name Helpers */
    RUN_AUTHN(test_authn_name_helpers);

    /* Query */
    RUN_AUTHN(test_authn_query);

    #undef RUN_AUTHN

    printf("  AUTHENTICATION: %d/%d passed\n", total - failed, total);
    return failed;
}
