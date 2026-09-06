#include "../../tests/test_framework.h"
#include "../password_auth.h"
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
 * test_password_auth.c — Password Authentication tests (Section 03, Step 14).
 *
 * Tests password provisioning, verification, credential lifecycle,
 * identity integration, vault persistence, security properties,
 * and fail-closed behavior.
 */

/* ---- Test Infrastructure ---- */

static ozayn_protection_provider_t _prot;
static ozayn_storage_provider_t _stor;
static ozayn_kl_manager_t _kl;
static ozayn_vault_t _vault;
static ozayn_identity_service_t _id_svc;
static ozayn_pwd_service_t _pwd_svc;

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

    ozayn_pwd_service_config_t pcfg;
    memset(&pcfg, 0, sizeof(pcfg));
    pcfg.identity_service = &_id_svc;
    pcfg.vault = &_vault;
    ozayn_pwd_service_init(&_pwd_svc, &pcfg);
}

static void _teardown_deps(void)
{
    ozayn_pwd_service_shutdown(&_pwd_svc);
    ozayn_id_service_shutdown(&_id_svc);
    ozayn_vault_shutdown(&_vault);
    ozayn_kl_shutdown(&_kl);
    ozayn_sp_shutdown(&_stor);
    ozayn_prot_shutdown(&_prot);
}

static ozayn_identity_t _create_test_user(const char *label)
{
    ozayn_identity_t id;
    memset(&id, 0, sizeof(id));
    ozayn_id_create(&_id_svc, OZAYN_ID_TYPE_USER, label,
                    OZAYN_ID_SCOPE_USER, "owner", &id);
    return id;
}

/* ============================================================
 * INIT/SHUTDOWN TESTS
 * ============================================================ */

int test_pwd_init_shutdown(void)
{
    _setup_deps();
    ASSERT_EQ(1, ozayn_pwd_service_is_initialized(&_pwd_svc));
    ASSERT_EQ(0, ozayn_pwd_service_credential_count(&_pwd_svc));
    ozayn_pwd_service_shutdown(&_pwd_svc);
    ASSERT_EQ(0, ozayn_pwd_service_is_initialized(&_pwd_svc));
    _teardown_deps();
    return 0;
}

int test_pwd_init_null(void)
{
    ASSERT_EQ(OZAYN_PWD_ERR_NULL, ozayn_pwd_service_init(NULL, NULL));
    ozayn_pwd_service_t svc;
    ASSERT_EQ(OZAYN_PWD_ERR_NULL, ozayn_pwd_service_init(&svc, NULL));
    return 0;
}

int test_pwd_init_missing_deps(void)
{
    _setup_deps();
    ozayn_pwd_service_t svc;
    ozayn_pwd_service_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    ASSERT_EQ(OZAYN_PWD_ERR_NULL, ozayn_pwd_service_init(&svc, &cfg));
    cfg.identity_service = &_id_svc;
    ASSERT_EQ(OZAYN_PWD_ERR_NULL, ozayn_pwd_service_init(&svc, &cfg));
    _teardown_deps();
    return 0;
}

int test_pwd_shutdown_null(void)
{
    ozayn_pwd_service_shutdown(NULL);
    return 0;
}

/* ============================================================
 * VALIDATION TESTS
 * ============================================================ */

int test_pwd_validate_credential_state(void)
{
    ASSERT_EQ(0, ozayn_pwd_validate_credential_state(OZAYN_PWD_CRED_ACTIVE));
    ASSERT_EQ(0, ozayn_pwd_validate_credential_state(OZAYN_PWD_CRED_SUSPENDED));
    ASSERT_EQ(0, ozayn_pwd_validate_credential_state(OZAYN_PWD_CRED_REVOKED));
    ASSERT_EQ(0, ozayn_pwd_validate_credential_state(OZAYN_PWD_CRED_EXPIRED));
    ASSERT_EQ(-1, ozayn_pwd_validate_credential_state((ozayn_pwd_credential_state_t)99));
    return 0;
}

int test_pwd_validate_credential_transition_valid(void)
{
    ASSERT_EQ(0, ozayn_pwd_validate_credential_transition(
        OZAYN_PWD_CRED_UNINITIALIZED, OZAYN_PWD_CRED_ACTIVE));
    ASSERT_EQ(0, ozayn_pwd_validate_credential_transition(
        OZAYN_PWD_CRED_ACTIVE, OZAYN_PWD_CRED_SUSPENDED));
    ASSERT_EQ(0, ozayn_pwd_validate_credential_transition(
        OZAYN_PWD_CRED_SUSPENDED, OZAYN_PWD_CRED_ACTIVE));
    ASSERT_EQ(0, ozayn_pwd_validate_credential_transition(
        OZAYN_PWD_CRED_ACTIVE, OZAYN_PWD_CRED_REVOKED));
    ASSERT_EQ(0, ozayn_pwd_validate_credential_transition(
        OZAYN_PWD_CRED_SUSPENDED, OZAYN_PWD_CRED_REVOKED));
    ASSERT_EQ(0, ozayn_pwd_validate_credential_transition(
        OZAYN_PWD_CRED_ACTIVE, OZAYN_PWD_CRED_EXPIRED));
    return 0;
}

int test_pwd_validate_credential_transition_invalid(void)
{
    ASSERT_EQ(-1, ozayn_pwd_validate_credential_transition(
        OZAYN_PWD_CRED_REVOKED, OZAYN_PWD_CRED_ACTIVE));
    ASSERT_EQ(-1, ozayn_pwd_validate_credential_transition(
        OZAYN_PWD_CRED_EXPIRED, OZAYN_PWD_CRED_ACTIVE));
    ASSERT_EQ(-1, ozayn_pwd_validate_credential_transition(
        OZAYN_PWD_CRED_UNINITIALIZED, OZAYN_PWD_CRED_SUSPENDED));
    ASSERT_EQ(-1, ozayn_pwd_validate_credential_transition(
        OZAYN_PWD_CRED_REVOKED, OZAYN_PWD_CRED_SUSPENDED));
    return 0;
}

int test_pwd_validate_password(void)
{
    _setup_deps();
    /* Null password with non-zero length */
    ASSERT_EQ(-1, ozayn_pwd_validate_password(&_pwd_svc, NULL, 5));
    /* Empty password */
    ASSERT_EQ(-1, ozayn_pwd_validate_password(&_pwd_svc, "", 0));
    /* Too short (policy min 8) */
    ASSERT_EQ(-1, ozayn_pwd_validate_password(&_pwd_svc, "short", 5));
    /* Valid password */
    ASSERT_EQ(0, ozayn_pwd_validate_password(&_pwd_svc, "validpassword", 12));
    _teardown_deps();
    return 0;
}

/* ============================================================
 * PROVISIONING TESTS
 * ============================================================ */

int test_pwd_provision_valid(void)
{
    _setup_deps();
    ozayn_identity_t user = _create_test_user("Test User");

    ozayn_pwd_provision_request_t req;
    memset(&req, 0, sizeof(req));
    strncpy(req.identity_id, user.id, sizeof(req.identity_id));
    strncpy(req.password, "SecureP@ssw0rd!", sizeof(req.password));
    req.password_len = strlen(req.password);

    ozayn_authn_credential_ref_t ref;
    ASSERT_EQ(OZAYN_PWD_OK, ozayn_pwd_provision(&_pwd_svc, &req, &ref));
    ASSERT_EQ(1, ozayn_pwd_service_credential_count(&_pwd_svc));
    ASSERT_EQ(1, ref.in_use);
    ASSERT_STR_EQ("password-provider", ref.provider_id);
    ASSERT_EQ(OZAYN_AuthN_METHOD_PASSWORD, (int)ref.method);
    _teardown_deps();
    return 0;
}

int test_pwd_provision_long_passphrase(void)
{
    _setup_deps();
    ozayn_identity_t user = _create_test_user("Long Pass User");

    char long_pass[256];
    memset(long_pass, 'A', sizeof(long_pass) - 1);
    long_pass[sizeof(long_pass) - 1] = '\0';

    ozayn_pwd_provision_request_t req;
    memset(&req, 0, sizeof(req));
    strncpy(req.identity_id, user.id, sizeof(req.identity_id));
    strncpy(req.password, long_pass, sizeof(req.password));
    req.password_len = strlen(req.password);

    ozayn_authn_credential_ref_t ref;
    ASSERT_EQ(OZAYN_PWD_OK, ozayn_pwd_provision(&_pwd_svc, &req, &ref));
    ASSERT_EQ(1, ozayn_pwd_service_credential_count(&_pwd_svc));
    _teardown_deps();
    return 0;
}

int test_pwd_provision_empty_password(void)
{
    _setup_deps();
    ozayn_identity_t user = _create_test_user("Empty Pass User");

    ozayn_pwd_provision_request_t req;
    memset(&req, 0, sizeof(req));
    strncpy(req.identity_id, user.id, sizeof(req.identity_id));

    ozayn_authn_credential_ref_t ref;
    ASSERT_EQ(OZAYN_PWD_ERR_EMPTY_PASSWORD, ozayn_pwd_provision(&_pwd_svc, &req, &ref));
    _teardown_deps();
    return 0;
}

int test_pwd_provision_too_short(void)
{
    _setup_deps();
    ozayn_identity_t user = _create_test_user("Short Pass User");

    ozayn_pwd_provision_request_t req;
    memset(&req, 0, sizeof(req));
    strncpy(req.identity_id, user.id, sizeof(req.identity_id));
    strncpy(req.password, "short", sizeof(req.password));
    req.password_len = strlen(req.password);

    ozayn_authn_credential_ref_t ref;
    ASSERT_EQ(OZAYN_PWD_ERR_PASSWORD_TOO_SHORT, ozayn_pwd_provision(&_pwd_svc, &req, &ref));
    _teardown_deps();
    return 0;
}

int test_pwd_provision_duplicate(void)
{
    _setup_deps();
    ozayn_identity_t user = _create_test_user("Dup User");

    ozayn_pwd_provision_request_t req;
    memset(&req, 0, sizeof(req));
    strncpy(req.identity_id, user.id, sizeof(req.identity_id));
    strncpy(req.password, "ValidPass123", sizeof(req.password));
    req.password_len = strlen(req.password);

    ozayn_authn_credential_ref_t ref;
    ASSERT_EQ(OZAYN_PWD_OK, ozayn_pwd_provision(&_pwd_svc, &req, &ref));
    ASSERT_EQ(OZAYN_PWD_ERR_ALREADY_EXISTS, ozayn_pwd_provision(&_pwd_svc, &req, &ref));
    _teardown_deps();
    return 0;
}

int test_pwd_provision_null(void)
{
    _setup_deps();
    ASSERT_EQ(OZAYN_PWD_ERR_NULL, ozayn_pwd_provision(NULL, NULL, NULL));
    _teardown_deps();
    return 0;
}

int test_pwd_provision_not_initialized(void)
{
    ozayn_pwd_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_pwd_provision_request_t req;
    memset(&req, 0, sizeof(req));
    ozayn_authn_credential_ref_t ref;
    ASSERT_EQ(OZAYN_PWD_ERR_NOT_INITIALIZED, ozayn_pwd_provision(&svc, &req, &ref));
    return 0;
}

int test_pwd_provision_revoked_identity(void)
{
    _setup_deps();
    ozayn_identity_t user = _create_test_user("Revoked User");
    ozayn_id_revoke(&_id_svc, user.id);

    ozayn_pwd_provision_request_t req;
    memset(&req, 0, sizeof(req));
    strncpy(req.identity_id, user.id, sizeof(req.identity_id));
    strncpy(req.password, "ValidPass123", sizeof(req.password));
    req.password_len = strlen(req.password);

    ozayn_authn_credential_ref_t ref;
    ASSERT_EQ(OZAYN_PWD_ERR_IDENTITY_REVOKED, ozayn_pwd_provision(&_pwd_svc, &req, &ref));
    _teardown_deps();
    return 0;
}

int test_pwd_provision_nonexistent_identity(void)
{
    _setup_deps();

    ozayn_pwd_provision_request_t req;
    memset(&req, 0, sizeof(req));
    strncpy(req.identity_id, "nonexistent-id", sizeof(req.identity_id));
    strncpy(req.password, "ValidPass123", sizeof(req.password));
    req.password_len = strlen(req.password);

    ozayn_authn_credential_ref_t ref;
    ASSERT_EQ(OZAYN_PWD_ERR_INVALID, ozayn_pwd_provision(&_pwd_svc, &req, &ref));
    _teardown_deps();
    return 0;
}

/* ============================================================
 * VERIFICATION TESTS
 * ============================================================ */

int test_pwd_verify_correct_password(void)
{
    _setup_deps();
    ozayn_identity_t user = _create_test_user("Verify User");

    ozayn_pwd_provision_request_t preq;
    memset(&preq, 0, sizeof(preq));
    strncpy(preq.identity_id, user.id, sizeof(preq.identity_id));
    strncpy(preq.password, "CorrectP@ss1", sizeof(preq.password));
    preq.password_len = strlen(preq.password);

    ozayn_authn_credential_ref_t ref;
    ASSERT_EQ(OZAYN_PWD_OK, ozayn_pwd_provision(&_pwd_svc, &preq, &ref));

    ozayn_pwd_verify_request_t vreq;
    memset(&vreq, 0, sizeof(vreq));
    strncpy(vreq.identity_id, user.id, sizeof(vreq.identity_id));
    strncpy(vreq.password, "CorrectP@ss1", sizeof(vreq.password));
    vreq.password_len = strlen(vreq.password);

    ozayn_authn_result_t result;
    ASSERT_EQ(OZAYN_PWD_OK, ozayn_pwd_verify(&_pwd_svc, &vreq, &result));
    ASSERT_EQ(OZAYN_AuthN_RESULT_SUCCESS, (int)result);
    _teardown_deps();
    return 0;
}

int test_pwd_verify_wrong_password(void)
{
    _setup_deps();
    ozayn_identity_t user = _create_test_user("Wrong Pass User");

    ozayn_pwd_provision_request_t preq;
    memset(&preq, 0, sizeof(preq));
    strncpy(preq.identity_id, user.id, sizeof(preq.identity_id));
    strncpy(preq.password, "CorrectP@ss1", sizeof(preq.password));
    preq.password_len = strlen(preq.password);

    ozayn_authn_credential_ref_t ref;
    ASSERT_EQ(OZAYN_PWD_OK, ozayn_pwd_provision(&_pwd_svc, &preq, &ref));

    ozayn_pwd_verify_request_t vreq;
    memset(&vreq, 0, sizeof(vreq));
    strncpy(vreq.identity_id, user.id, sizeof(vreq.identity_id));
    strncpy(vreq.password, "WrongPassword!", sizeof(vreq.password));
    vreq.password_len = strlen(vreq.password);

    ozayn_authn_result_t result;
    ASSERT_EQ(OZAYN_PWD_ERR_VERIFICATION_FAILED, ozayn_pwd_verify(&_pwd_svc, &vreq, &result));
    ASSERT_EQ(OZAYN_AuthN_RESULT_FAILED, (int)result);
    _teardown_deps();
    return 0;
}

int test_pwd_verify_no_credential(void)
{
    _setup_deps();
    ozayn_identity_t user = _create_test_user("No Cred User");

    ozayn_pwd_verify_request_t vreq;
    memset(&vreq, 0, sizeof(vreq));
    strncpy(vreq.identity_id, user.id, sizeof(vreq.identity_id));
    strncpy(vreq.password, "SomePass123!", sizeof(vreq.password));
    vreq.password_len = strlen(vreq.password);

    ozayn_authn_result_t result;
    ASSERT_EQ(OZAYN_PWD_ERR_NOT_FOUND, ozayn_pwd_verify(&_pwd_svc, &vreq, &result));
    ASSERT_EQ(OZAYN_AuthN_RESULT_UNAVAILABLE, (int)result);
    _teardown_deps();
    return 0;
}

int test_pwd_verify_empty_password(void)
{
    _setup_deps();
    ozayn_identity_t user = _create_test_user("Empty Verify User");

    ozayn_pwd_provision_request_t preq;
    memset(&preq, 0, sizeof(preq));
    strncpy(preq.identity_id, user.id, sizeof(preq.identity_id));
    strncpy(preq.password, "ValidPass123!", sizeof(preq.password));
    preq.password_len = strlen(preq.password);

    ozayn_authn_credential_ref_t ref;
    ASSERT_EQ(OZAYN_PWD_OK, ozayn_pwd_provision(&_pwd_svc, &preq, &ref));

    ozayn_pwd_verify_request_t vreq;
    memset(&vreq, 0, sizeof(vreq));
    strncpy(vreq.identity_id, user.id, sizeof(vreq.identity_id));

    ozayn_authn_result_t result;
    ASSERT_EQ(OZAYN_PWD_ERR_EMPTY_PASSWORD, ozayn_pwd_verify(&_pwd_svc, &vreq, &result));
    _teardown_deps();
    return 0;
}

int test_pwd_verify_null(void)
{
    _setup_deps();
    ASSERT_EQ(OZAYN_PWD_ERR_NULL, ozayn_pwd_verify(NULL, NULL, NULL));
    _teardown_deps();
    return 0;
}

int test_pwd_verify_not_initialized(void)
{
    ozayn_pwd_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_pwd_verify_request_t vreq;
    memset(&vreq, 0, sizeof(vreq));
    ozayn_authn_result_t result;
    ASSERT_EQ(OZAYN_PWD_ERR_NOT_INITIALIZED, ozayn_pwd_verify(&svc, &vreq, &result));
    return 0;
}

/* ============================================================
 * SALT UNIQUENESS TESTS
 * ============================================================ */

int test_pwd_unique_salts(void)
{
    _setup_deps();
    ozayn_identity_t user1 = _create_test_user("User 1");
    ozayn_identity_t user2 = _create_test_user("User 2");

    /* Provision two users with the SAME password */
    ozayn_pwd_provision_request_t preq;
    memset(&preq, 0, sizeof(preq));
    strncpy(preq.password, "SamePassword123!", sizeof(preq.password));
    preq.password_len = strlen(preq.password);

    strncpy(preq.identity_id, user1.id, sizeof(preq.identity_id));
    ozayn_authn_credential_ref_t ref1;
    ASSERT_EQ(OZAYN_PWD_OK, ozayn_pwd_provision(&_pwd_svc, &preq, &ref1));

    strncpy(preq.identity_id, user2.id, sizeof(preq.identity_id));
    ozayn_authn_credential_ref_t ref2;
    ASSERT_EQ(OZAYN_PWD_OK, ozayn_pwd_provision(&_pwd_svc, &preq, &ref2));

    /* Both should verify correctly with the same password */
    ozayn_pwd_verify_request_t vreq;
    memset(&vreq, 0, sizeof(vreq));
    strncpy(vreq.password, "SamePassword123!", sizeof(vreq.password));
    vreq.password_len = strlen(vreq.password);

    ozayn_authn_result_t result;
    strncpy(vreq.identity_id, user1.id, sizeof(vreq.identity_id));
    ASSERT_EQ(OZAYN_PWD_OK, ozayn_pwd_verify(&_pwd_svc, &vreq, &result));
    ASSERT_EQ(OZAYN_AuthN_RESULT_SUCCESS, (int)result);

    strncpy(vreq.identity_id, user2.id, sizeof(vreq.identity_id));
    ASSERT_EQ(OZAYN_PWD_OK, ozayn_pwd_verify(&_pwd_svc, &vreq, &result));
    ASSERT_EQ(OZAYN_AuthN_RESULT_SUCCESS, (int)result);

    /* Credential IDs must be different */
    ASSERT(strcmp(ref1.id, ref2.id) != 0);
    _teardown_deps();
    return 0;
}

/* ============================================================
 * CREDENTIAL LIFECYCLE TESTS
 * ============================================================ */

int test_pwd_suspend_credential(void)
{
    _setup_deps();
    ozayn_identity_t user = _create_test_user("Suspend User");

    ozayn_pwd_provision_request_t preq;
    memset(&preq, 0, sizeof(preq));
    strncpy(preq.identity_id, user.id, sizeof(preq.identity_id));
    strncpy(preq.password, "ValidPass123!", sizeof(preq.password));
    preq.password_len = strlen(preq.password);

    ozayn_authn_credential_ref_t ref;
    ASSERT_EQ(OZAYN_PWD_OK, ozayn_pwd_provision(&_pwd_svc, &preq, &ref));

    /* Suspend */
    ASSERT_EQ(OZAYN_PWD_OK, ozayn_pwd_suspend(&_pwd_svc, user.id));

    /* Verify fails on suspended credential */
    ozayn_pwd_verify_request_t vreq;
    memset(&vreq, 0, sizeof(vreq));
    strncpy(vreq.identity_id, user.id, sizeof(vreq.identity_id));
    strncpy(vreq.password, "ValidPass123!", sizeof(vreq.password));
    vreq.password_len = strlen(vreq.password);

    ozayn_authn_result_t result;
    ASSERT_EQ(OZAYN_PWD_ERR_CREDENTIAL_SUSPENDED, ozayn_pwd_verify(&_pwd_svc, &vreq, &result));
    ASSERT_EQ(OZAYN_AuthN_RESULT_REJECTED, (int)result);
    _teardown_deps();
    return 0;
}

int test_pwd_revoke_credential(void)
{
    _setup_deps();
    ozayn_identity_t user = _create_test_user("Revoke User");

    ozayn_pwd_provision_request_t preq;
    memset(&preq, 0, sizeof(preq));
    strncpy(preq.identity_id, user.id, sizeof(preq.identity_id));
    strncpy(preq.password, "ValidPass123!", sizeof(preq.password));
    preq.password_len = strlen(preq.password);

    ozayn_authn_credential_ref_t ref;
    ASSERT_EQ(OZAYN_PWD_OK, ozayn_pwd_provision(&_pwd_svc, &preq, &ref));

    /* Revoke */
    ASSERT_EQ(OZAYN_PWD_OK, ozayn_pwd_revoke(&_pwd_svc, user.id));

    /* Verify fails on revoked credential */
    ozayn_pwd_verify_request_t vreq;
    memset(&vreq, 0, sizeof(vreq));
    strncpy(vreq.identity_id, user.id, sizeof(vreq.identity_id));
    strncpy(vreq.password, "ValidPass123!", sizeof(vreq.password));
    vreq.password_len = strlen(vreq.password);

    ozayn_authn_result_t result;
    ASSERT_EQ(OZAYN_PWD_ERR_CREDENTIAL_REVOKED, ozayn_pwd_verify(&_pwd_svc, &vreq, &result));
    ASSERT_EQ(OZAYN_AuthN_RESULT_REJECTED, (int)result);
    _teardown_deps();
    return 0;
}

int test_pwd_suspend_revoked_fails(void)
{
    _setup_deps();
    ozayn_identity_t user = _create_test_user("Suspend Revoked");

    ozayn_pwd_provision_request_t preq;
    memset(&preq, 0, sizeof(preq));
    strncpy(preq.identity_id, user.id, sizeof(preq.identity_id));
    strncpy(preq.password, "ValidPass123!", sizeof(preq.password));
    preq.password_len = strlen(preq.password);

    ozayn_authn_credential_ref_t ref;
    ASSERT_EQ(OZAYN_PWD_OK, ozayn_pwd_provision(&_pwd_svc, &preq, &ref));

    ASSERT_EQ(OZAYN_PWD_OK, ozayn_pwd_revoke(&_pwd_svc, user.id));
    ASSERT_EQ(OZAYN_PWD_ERR_INVALID, ozayn_pwd_suspend(&_pwd_svc, user.id));
    _teardown_deps();
    return 0;
}

/* ============================================================
 * IDENTITY LIFECYCLE TESTS
 * ============================================================ */

int test_pwd_revoked_identity_rejected(void)
{
    _setup_deps();
    ozayn_identity_t user = _create_test_user("Revoked Identity");

    ozayn_pwd_provision_request_t preq;
    memset(&preq, 0, sizeof(preq));
    strncpy(preq.identity_id, user.id, sizeof(preq.identity_id));
    strncpy(preq.password, "ValidPass123!", sizeof(preq.password));
    preq.password_len = strlen(preq.password);

    ozayn_authn_credential_ref_t ref;
    ASSERT_EQ(OZAYN_PWD_OK, ozayn_pwd_provision(&_pwd_svc, &preq, &ref));

    /* Revoke identity */
    ASSERT_EQ(OZAYN_ID_OK, ozayn_id_revoke(&_id_svc, user.id));

    /* Verify fails on revoked identity */
    ozayn_pwd_verify_request_t vreq;
    memset(&vreq, 0, sizeof(vreq));
    strncpy(vreq.identity_id, user.id, sizeof(vreq.identity_id));
    strncpy(vreq.password, "ValidPass123!", sizeof(vreq.password));
    vreq.password_len = strlen(vreq.password);

    ozayn_authn_result_t result;
    ASSERT_EQ(OZAYN_PWD_ERR_IDENTITY_REVOKED, ozayn_pwd_verify(&_pwd_svc, &vreq, &result));
    ASSERT_EQ(OZAYN_AuthN_RESULT_REJECTED, (int)result);
    _teardown_deps();
    return 0;
}

int test_pwd_suspended_identity_rejected(void)
{
    _setup_deps();
    ozayn_identity_t user = _create_test_user("Suspended Identity");

    ozayn_pwd_provision_request_t preq;
    memset(&preq, 0, sizeof(preq));
    strncpy(preq.identity_id, user.id, sizeof(preq.identity_id));
    strncpy(preq.password, "ValidPass123!", sizeof(preq.password));
    preq.password_len = strlen(preq.password);

    ozayn_authn_credential_ref_t ref;
    ASSERT_EQ(OZAYN_PWD_OK, ozayn_pwd_provision(&_pwd_svc, &preq, &ref));

    ASSERT_EQ(OZAYN_ID_OK, ozayn_id_suspend(&_id_svc, user.id));

    ozayn_pwd_verify_request_t vreq;
    memset(&vreq, 0, sizeof(vreq));
    strncpy(vreq.identity_id, user.id, sizeof(vreq.identity_id));
    strncpy(vreq.password, "ValidPass123!", sizeof(vreq.password));
    vreq.password_len = strlen(vreq.password);

    ozayn_authn_result_t result;
    ASSERT_EQ(OZAYN_PWD_ERR_IDENTITY_SUSPENDED, ozayn_pwd_verify(&_pwd_svc, &vreq, &result));
    ASSERT_EQ(OZAYN_AuthN_RESULT_REJECTED, (int)result);
    _teardown_deps();
    return 0;
}

/* ============================================================
 * PASSWORD UPDATE TESTS
 * ============================================================ */

int test_pwd_update_success(void)
{
    _setup_deps();
    ozayn_identity_t user = _create_test_user("Update User");

    /* Provision */
    ozayn_pwd_provision_request_t preq;
    memset(&preq, 0, sizeof(preq));
    strncpy(preq.identity_id, user.id, sizeof(preq.identity_id));
    strncpy(preq.password, "OldPassword123!", sizeof(preq.password));
    preq.password_len = strlen(preq.password);

    ozayn_authn_credential_ref_t ref;
    ASSERT_EQ(OZAYN_PWD_OK, ozayn_pwd_provision(&_pwd_svc, &preq, &ref));

    /* Update to new password */
    ASSERT_EQ(OZAYN_PWD_OK, ozayn_pwd_update(&_pwd_svc, user.id,
                                               "NewPassword456!", 15));

    /* Old password fails */
    ozayn_pwd_verify_request_t vreq;
    memset(&vreq, 0, sizeof(vreq));
    strncpy(vreq.identity_id, user.id, sizeof(vreq.identity_id));
    strncpy(vreq.password, "OldPassword123!", sizeof(vreq.password));
    vreq.password_len = strlen(vreq.password);

    ozayn_authn_result_t result;
    ASSERT_EQ(OZAYN_PWD_ERR_VERIFICATION_FAILED, ozayn_pwd_verify(&_pwd_svc, &vreq, &result));

    /* New password succeeds */
    strncpy(vreq.password, "NewPassword456!", sizeof(vreq.password));
    vreq.password_len = strlen(vreq.password);
    ASSERT_EQ(OZAYN_PWD_OK, ozayn_pwd_verify(&_pwd_svc, &vreq, &result));
    ASSERT_EQ(OZAYN_AuthN_RESULT_SUCCESS, (int)result);
    _teardown_deps();
    return 0;
}

int test_pwd_update_not_found(void)
{
    _setup_deps();
    ASSERT_EQ(OZAYN_PWD_ERR_NOT_FOUND, ozayn_pwd_update(&_pwd_svc,
                                                           "nonexistent",
                                                           "NewPass123!", 11));
    _teardown_deps();
    return 0;
}

/* ============================================================
 * SECURITY TESTS
 * ============================================================ */

int test_pwd_no_plaintext_persisted(void)
{
    _setup_deps();
    ozayn_identity_t user = _create_test_user("No Plaintext");

    ozayn_pwd_provision_request_t preq;
    memset(&preq, 0, sizeof(preq));
    strncpy(preq.identity_id, user.id, sizeof(preq.identity_id));
    strncpy(preq.password, "SecretPassword123!", sizeof(preq.password));
    preq.password_len = strlen(preq.password);

    ozayn_authn_credential_ref_t ref;
    ASSERT_EQ(OZAYN_PWD_OK, ozayn_pwd_provision(&_pwd_svc, &preq, &ref));

    /* The credential ref should not contain any password data */
    /* ref only has: id, state, method, version, provider_id, timestamps, in_use */
    /* No password field exists in the struct */
    ASSERT(ref.id[0] != '\0');
    ASSERT(ref.in_use == 1);
    ASSERT_STR_EQ("password-provider", ref.provider_id);
    _teardown_deps();
    return 0;
}

int test_pwd_hash_not_reversible(void)
{
    _setup_deps();
    ozayn_identity_t user = _create_test_user("Hash Not Reversible");

    ozayn_pwd_provision_request_t preq;
    memset(&preq, 0, sizeof(preq));
    strncpy(preq.identity_id, user.id, sizeof(preq.identity_id));
    strncpy(preq.password, "MySecretP@ss", sizeof(preq.password));
    preq.password_len = strlen(preq.password);

    ozayn_authn_credential_ref_t ref;
    ASSERT_EQ(OZAYN_PWD_OK, ozayn_pwd_provision(&_pwd_svc, &preq, &ref));

    /* Look at the stored hash - it should start with $argon2id$ */
    ozayn_pwd_credential_t *cred = &_pwd_svc.credentials[0];
    ASSERT(cred->hash_str[0] == '$');
    ASSERT(strncmp("$argon2id$", cred->hash_str, 10) == 0);
    _teardown_deps();
    return 0;
}

int test_pwd_credential_uses_vault(void)
{
    _setup_deps();
    ozayn_identity_t user = _create_test_user("Vault User");

    ozayn_pwd_provision_request_t preq;
    memset(&preq, 0, sizeof(preq));
    strncpy(preq.identity_id, user.id, sizeof(preq.identity_id));
    strncpy(preq.password, "VaultP@ss123!", sizeof(preq.password));
    preq.password_len = strlen(preq.password);

    ozayn_authn_credential_ref_t ref;
    ASSERT_EQ(OZAYN_PWD_OK, ozayn_pwd_provision(&_pwd_svc, &preq, &ref));

    /* Verify the credential is stored in the vault */
    ASSERT(ozayn_vault_exists(&_vault, ref.id));
    _teardown_deps();
    return 0;
}

/* ============================================================
 * QUERY TESTS
 * ============================================================ */

int test_pwd_query(void)
{
    _setup_deps();
    ozayn_identity_t user = _create_test_user("Query User");

    ASSERT_EQ(1, ozayn_pwd_service_is_initialized(&_pwd_svc));
    ASSERT_EQ(0, ozayn_pwd_service_credential_count(&_pwd_svc));
    ASSERT_EQ(0, ozayn_pwd_has_credential(&_pwd_svc, user.id));

    ozayn_pwd_provision_request_t preq;
    memset(&preq, 0, sizeof(preq));
    strncpy(preq.identity_id, user.id, sizeof(preq.identity_id));
    strncpy(preq.password, "ValidPass123!", sizeof(preq.password));
    preq.password_len = strlen(preq.password);

    ozayn_authn_credential_ref_t ref;
    ASSERT_EQ(OZAYN_PWD_OK, ozayn_pwd_provision(&_pwd_svc, &preq, &ref));

    ASSERT_EQ(1, ozayn_pwd_service_credential_count(&_pwd_svc));
    ASSERT_EQ(1, ozayn_pwd_has_credential(&_pwd_svc, user.id));
    ASSERT_EQ(0, ozayn_pwd_has_credential(&_pwd_svc, "nonexistent"));

    ASSERT_EQ(0, ozayn_pwd_service_is_initialized(NULL));
    ASSERT_EQ(0, ozayn_pwd_service_credential_count(NULL));
    ASSERT_EQ(0, ozayn_pwd_has_credential(NULL, NULL));
    _teardown_deps();
    return 0;
}

/* ============================================================
 * NAME HELPER TESTS
 * ============================================================ */

int test_pwd_name_helpers(void)
{
    ASSERT_STR_EQ("ACTIVE", ozayn_pwd_credential_state_name(OZAYN_PWD_CRED_ACTIVE));
    ASSERT_STR_EQ("REVOKED", ozayn_pwd_credential_state_name(OZAYN_PWD_CRED_REVOKED));
    ASSERT_STR_EQ("UNKNOWN", ozayn_pwd_credential_state_name((ozayn_pwd_credential_state_t)99));

    ASSERT_STR_EQ("OK", ozayn_pwd_error_name(OZAYN_PWD_OK));
    ASSERT_STR_EQ("NULL", ozayn_pwd_error_name(OZAYN_PWD_ERR_NULL));
    ASSERT_STR_EQ("EMPTY_PASSWORD", ozayn_pwd_error_name(OZAYN_PWD_ERR_EMPTY_PASSWORD));
    ASSERT_STR_EQ("UNKNOWN", ozayn_pwd_error_name((ozayn_pwd_error_t)99));
    return 0;
}

/* ============================================================
 * PROVIDER TESTS
 * ============================================================ */

int test_pwd_provider_create(void)
{
    ozayn_authn_provider_t provider;
    ozayn_pwd_provider_create(&provider, &_pwd_svc);
    ASSERT_STR_EQ("password-provider", provider.name);
    ASSERT_EQ(1, provider.initialized);
    ASSERT(provider.ops != NULL);
    ASSERT(provider.ops->authenticate != NULL);
    ASSERT(provider.ops->is_available != NULL);
    ASSERT(provider.ops->get_method != NULL);
    ASSERT_EQ(OZAYN_AuthN_METHOD_PASSWORD,
              (int)provider.ops->get_method(&provider));
    ASSERT_EQ(1, provider.ops->is_available(&provider));
    return 0;
}

/* ============================================================
 * VAULT FAILURE TEST
 * ============================================================ */

int test_pwd_vault_unavailable(void)
{
    _setup_deps();

    /* Create identity BEFORE shutting down vault */
    ozayn_identity_t user = _create_test_user("Vault Fail User");

    /* Now shutdown vault */
    ozayn_vault_shutdown(&_vault);

    ozayn_pwd_provision_request_t preq;
    memset(&preq, 0, sizeof(preq));
    strncpy(preq.identity_id, user.id, sizeof(preq.identity_id));
    strncpy(preq.password, "ValidPass123!", sizeof(preq.password));
    preq.password_len = strlen(preq.password);

    ozayn_authn_credential_ref_t ref;
    ASSERT_EQ(OZAYN_PWD_ERR_VAULT_FAILED, ozayn_pwd_provision(&_pwd_svc, &preq, &ref));
    _teardown_deps();
    return 0;
}

/* ============================================================
 * TEST RUNNER
 * ============================================================ */

int run_password_auth_tests(void)
{
    int failed = 0;
    int total = 0;

    printf("\n  --- PASSWORD AUTH TESTS ---\n");

    #define RUN_PWD(name) do { total++; printf("    [%d] %s ... ", total, #name); if (name() == 0) { printf("PASS\n"); } else { printf("FAIL\n"); failed++; } } while(0)

    /* Init/Shutdown */
    RUN_PWD(test_pwd_init_shutdown);
    RUN_PWD(test_pwd_init_null);
    RUN_PWD(test_pwd_init_missing_deps);
    RUN_PWD(test_pwd_shutdown_null);

    /* Validation */
    RUN_PWD(test_pwd_validate_credential_state);
    RUN_PWD(test_pwd_validate_credential_transition_valid);
    RUN_PWD(test_pwd_validate_credential_transition_invalid);
    RUN_PWD(test_pwd_validate_password);

    /* Provisioning */
    RUN_PWD(test_pwd_provision_valid);
    RUN_PWD(test_pwd_provision_long_passphrase);
    RUN_PWD(test_pwd_provision_empty_password);
    RUN_PWD(test_pwd_provision_too_short);
    RUN_PWD(test_pwd_provision_duplicate);
    RUN_PWD(test_pwd_provision_null);
    RUN_PWD(test_pwd_provision_not_initialized);
    RUN_PWD(test_pwd_provision_revoked_identity);
    RUN_PWD(test_pwd_provision_nonexistent_identity);

    /* Verification */
    RUN_PWD(test_pwd_verify_correct_password);
    RUN_PWD(test_pwd_verify_wrong_password);
    RUN_PWD(test_pwd_verify_no_credential);
    RUN_PWD(test_pwd_verify_empty_password);
    RUN_PWD(test_pwd_verify_null);
    RUN_PWD(test_pwd_verify_not_initialized);

    /* Salt Uniqueness */
    RUN_PWD(test_pwd_unique_salts);

    /* Credential Lifecycle */
    RUN_PWD(test_pwd_suspend_credential);
    RUN_PWD(test_pwd_revoke_credential);
    RUN_PWD(test_pwd_suspend_revoked_fails);

    /* Identity Lifecycle */
    RUN_PWD(test_pwd_revoked_identity_rejected);
    RUN_PWD(test_pwd_suspended_identity_rejected);

    /* Password Update */
    RUN_PWD(test_pwd_update_success);
    RUN_PWD(test_pwd_update_not_found);

    /* Security */
    RUN_PWD(test_pwd_no_plaintext_persisted);
    RUN_PWD(test_pwd_hash_not_reversible);
    RUN_PWD(test_pwd_credential_uses_vault);

    /* Query */
    RUN_PWD(test_pwd_query);

    /* Name Helpers */
    RUN_PWD(test_pwd_name_helpers);

    /* Provider */
    RUN_PWD(test_pwd_provider_create);

    /* Vault Failure */
    RUN_PWD(test_pwd_vault_unavailable);

    #undef RUN_PWD

    printf("  PASSWORD AUTH: %d/%d passed\n", total - failed, total);
    return failed;
}
