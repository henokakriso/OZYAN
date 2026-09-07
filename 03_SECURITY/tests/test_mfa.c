#include "../../tests/test_framework.h"
#include "../mfa.h"
#include "../identity.h"
#include "../authentication.h"
#include "../attempt_control.h"
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
static ozayn_ac_service_t          _ac_svc;
static ozayn_authn_service_t       _authn_svc;
static ozayn_mfa_service_t         _mfa_svc;

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

    ozayn_ac_service_config_t ac_cfg;
    memset(&ac_cfg, 0, sizeof(ac_cfg));
    ac_cfg.policy = ozayn_ac_default_policy();
    ozayn_ac_service_init(&_ac_svc, &ac_cfg);

    ozayn_authn_service_config_t an_cfg;
    memset(&an_cfg, 0, sizeof(an_cfg));
    an_cfg.identity_service = &_id_svc;
    an_cfg.vault = &_vault;
    ozayn_authn_service_init(&_authn_svc, &an_cfg);
}

static void _teardown_deps(void)
{
    ozayn_mfa_service_shutdown(&_mfa_svc);
    ozayn_authn_service_shutdown(&_authn_svc);
    ozayn_ac_service_shutdown(&_ac_svc);
    ozayn_id_service_shutdown(&_id_svc);
    ozayn_vault_shutdown(&_vault);
    ozayn_kl_shutdown(&_kl);
    ozayn_sp_shutdown(&_stor);
    ozayn_prot_shutdown(&_prot);
}

static void _init_mfa_svc(void)
{
    ozayn_mfa_service_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.identity_service = &_id_svc;
    cfg.attempt_control = &_ac_svc;
    cfg.authn_service = &_authn_svc;
    ozayn_mfa_service_init(&_mfa_svc, &cfg);
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
    _init_mfa_svc();
    ASSERT(ozayn_mfa_service_is_initialized(&_mfa_svc));
    ASSERT_EQ(0, ozayn_mfa_policy_count(&_mfa_svc));
    ASSERT_EQ(0, ozayn_mfa_tx_count(&_mfa_svc));
    _teardown_deps();
    return 0;
}

TEST(test_service_init_null)
{
    ASSERT_EQ(OZAYN_MFA_ERR_NULL, ozayn_mfa_service_init(NULL, NULL));
    return 0;
}

TEST(test_service_init_no_identity)
{
    ozayn_mfa_service_t svc;
    ozayn_mfa_service_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    ASSERT_EQ(OZAYN_MFA_ERR_INVALID, ozayn_mfa_service_init(&svc, &cfg));
    return 0;
}

TEST(test_service_shutdown)
{
    _setup_deps();
    _init_mfa_svc();
    ozayn_mfa_service_shutdown(&_mfa_svc);
    ASSERT(!ozayn_mfa_service_is_initialized(&_mfa_svc));
    return 0;
}

TEST(test_service_shutdown_null)
{
    ozayn_mfa_service_shutdown(NULL);
    return 0;
}

TEST(test_service_not_initialized)
{
    ozayn_mfa_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_mfa_tx_t tx;
    ASSERT_EQ(OZAYN_MFA_ERR_NOT_INITIALIZED,
              ozayn_mfa_tx_create(&svc, "id1", "pol1", &tx));
    return 0;
}

/* ============================================================
 * 2. POLICY MANAGEMENT
 * ============================================================ */

TEST(test_policy_create)
{
    _setup_deps();
    _init_mfa_svc();
    ozayn_mfa_factor_type_t factors[] = {
        OZAYN_MFA_FACTOR_PASSWORD, OZAYN_MFA_FACTOR_TOKEN
    };
    ozayn_mfa_policy_t pol;
    ozayn_mfa_error_t r = ozayn_mfa_policy_create(
        &_mfa_svc, "pol1", "Test Policy", factors, 2,
        300, 60, 5, 900, &pol);
    ASSERT_EQ(OZAYN_MFA_OK, r);
    ASSERT_STR_EQ("pol1", pol.id);
    ASSERT_STR_EQ("Test Policy", pol.name);
    ASSERT_EQ(2, pol.required_factor_count);
    ASSERT_EQ(OZAYN_MFA_FACTOR_PASSWORD, pol.required_factors[0]);
    ASSERT_EQ(OZAYN_MFA_FACTOR_TOKEN, pol.required_factors[1]);
    ASSERT(pol.enabled);
    ASSERT_EQ(300, pol.transaction_timeout_seconds);
    _teardown_deps();
    return 0;
}

TEST(test_policy_create_null)
{
    _setup_deps();
    _init_mfa_svc();
    ozayn_mfa_factor_type_t factors[] = { OZAYN_MFA_FACTOR_PASSWORD };
    ozayn_mfa_policy_t pol;
    ASSERT_EQ(OZAYN_MFA_ERR_NULL,
              ozayn_mfa_policy_create(NULL, "p1", "P", factors, 1, 300, 60, 5, 900, &pol));
    ASSERT_EQ(OZAYN_MFA_ERR_NULL,
              ozayn_mfa_policy_create(&_mfa_svc, NULL, "P", factors, 1, 300, 60, 5, 900, &pol));
    ASSERT_EQ(OZAYN_MFA_ERR_NULL,
              ozayn_mfa_policy_create(&_mfa_svc, "p1", "P", factors, 1, 300, 60, 5, 900, NULL));
    _teardown_deps();
    return 0;
}

TEST(test_policy_create_duplicate)
{
    _setup_deps();
    _init_mfa_svc();
    ozayn_mfa_factor_type_t factors[] = { OZAYN_MFA_FACTOR_PASSWORD };
    ozayn_mfa_policy_t pol;
    ASSERT_EQ(OZAYN_MFA_OK,
              ozayn_mfa_policy_create(&_mfa_svc, "p1", "P", factors, 1, 300, 60, 5, 900, &pol));
    ASSERT_EQ(OZAYN_MFA_ERR_ALREADY_EXISTS,
              ozayn_mfa_policy_create(&_mfa_svc, "p1", "P2", factors, 1, 300, 60, 5, 900, &pol));
    _teardown_deps();
    return 0;
}

TEST(test_policy_create_same_category_rejected)
{
    _setup_deps();
    _init_mfa_svc();
    /* Two PASSWORD factors — same category (KNOWLEDGE), should fail */
    ozayn_mfa_factor_type_t factors[] = {
        OZAYN_MFA_FACTOR_PASSWORD, OZAYN_MFA_FACTOR_PASSWORD
    };
    ozayn_mfa_policy_t pol;
    ASSERT_EQ(OZAYN_MFA_ERR_POLICY_INVALID,
              ozayn_mfa_policy_create(&_mfa_svc, "p1", "P", factors, 2, 300, 60, 5, 900, &pol));
    _teardown_deps();
    return 0;
}

TEST(test_policy_create_invalid_factor)
{
    _setup_deps();
    _init_mfa_svc();
    ozayn_mfa_factor_type_t factors[] = { OZAYN_MFA_FACTOR_UNKNOWN };
    ozayn_mfa_policy_t pol;
    ASSERT_EQ(OZAYN_MFA_ERR_FACTOR_INVALID,
              ozayn_mfa_policy_create(&_mfa_svc, "p1", "P", factors, 1, 300, 60, 5, 900, &pol));
    _teardown_deps();
    return 0;
}

TEST(test_policy_create_zero_timeout)
{
    _setup_deps();
    _init_mfa_svc();
    ozayn_mfa_factor_type_t factors[] = { OZAYN_MFA_FACTOR_PASSWORD };
    ozayn_mfa_policy_t pol;
    ASSERT_EQ(OZAYN_MFA_ERR_POLICY_INVALID,
              ozayn_mfa_policy_create(&_mfa_svc, "p1", "P", factors, 1, 0, 60, 5, 900, &pol));
    _teardown_deps();
    return 0;
}

TEST(test_policy_get)
{
    _setup_deps();
    _init_mfa_svc();
    ozayn_mfa_factor_type_t factors[] = { OZAYN_MFA_FACTOR_PASSWORD };
    ozayn_mfa_policy_t pol;
    ASSERT_EQ(OZAYN_MFA_OK,
              ozayn_mfa_policy_create(&_mfa_svc, "p1", "P", factors, 1, 300, 60, 5, 900, &pol));

    ozayn_mfa_policy_t got;
    ASSERT_EQ(OZAYN_MFA_OK, ozayn_mfa_policy_get(&_mfa_svc, "p1", &got));
    ASSERT_STR_EQ("p1", got.id);
    _teardown_deps();
    return 0;
}

TEST(test_policy_get_not_found)
{
    _setup_deps();
    _init_mfa_svc();
    ozayn_mfa_policy_t pol;
    ASSERT_EQ(OZAYN_MFA_ERR_NOT_FOUND,
              ozayn_mfa_policy_get(&_mfa_svc, "nonexistent", &pol));
    _teardown_deps();
    return 0;
}

TEST(test_policy_exists)
{
    _setup_deps();
    _init_mfa_svc();
    ASSERT(!ozayn_mfa_policy_exists(&_mfa_svc, "p1"));
    ozayn_mfa_factor_type_t factors[] = { OZAYN_MFA_FACTOR_PASSWORD };
    ozayn_mfa_policy_t pol;
    ASSERT_EQ(OZAYN_MFA_OK,
              ozayn_mfa_policy_create(&_mfa_svc, "p1", "P", factors, 1, 300, 60, 5, 900, &pol));
    ASSERT(ozayn_mfa_policy_exists(&_mfa_svc, "p1"));
    _teardown_deps();
    return 0;
}

TEST(test_policy_enable_disable)
{
    _setup_deps();
    _init_mfa_svc();
    ozayn_mfa_factor_type_t factors[] = { OZAYN_MFA_FACTOR_PASSWORD };
    ozayn_mfa_policy_t pol;
    ASSERT_EQ(OZAYN_MFA_OK,
              ozayn_mfa_policy_create(&_mfa_svc, "p1", "P", factors, 1, 300, 60, 5, 900, &pol));
    ASSERT_EQ(OZAYN_MFA_OK, ozayn_mfa_policy_disable(&_mfa_svc, "p1"));
    ASSERT_EQ(OZAYN_MFA_OK, ozayn_mfa_policy_get(&_mfa_svc, "p1", &pol));
    ASSERT(!pol.enabled);
    ASSERT_EQ(OZAYN_MFA_OK, ozayn_mfa_policy_enable(&_mfa_svc, "p1"));
    ASSERT_EQ(OZAYN_MFA_OK, ozayn_mfa_policy_get(&_mfa_svc, "p1", &pol));
    ASSERT(pol.enabled);
    _teardown_deps();
    return 0;
}

TEST(test_policy_delete)
{
    _setup_deps();
    _init_mfa_svc();
    ozayn_mfa_factor_type_t factors[] = { OZAYN_MFA_FACTOR_PASSWORD };
    ozayn_mfa_policy_t pol;
    ASSERT_EQ(OZAYN_MFA_OK,
              ozayn_mfa_policy_create(&_mfa_svc, "p1", "P", factors, 1, 300, 60, 5, 900, &pol));
    ASSERT_EQ(1, ozayn_mfa_policy_count(&_mfa_svc));
    ASSERT_EQ(OZAYN_MFA_OK, ozayn_mfa_policy_delete(&_mfa_svc, "p1"));
    ASSERT_EQ(0, ozayn_mfa_policy_count(&_mfa_svc));
    ASSERT(!ozayn_mfa_policy_exists(&_mfa_svc, "p1"));
    _teardown_deps();
    return 0;
}

TEST(test_policy_count)
{
    _setup_deps();
    _init_mfa_svc();
    ASSERT_EQ(0, ozayn_mfa_policy_count(&_mfa_svc));
    ozayn_mfa_factor_type_t factors[] = { OZAYN_MFA_FACTOR_PASSWORD };
    ozayn_mfa_policy_t pol;
    ASSERT_EQ(OZAYN_MFA_OK,
              ozayn_mfa_policy_create(&_mfa_svc, "p1", "P", factors, 1, 300, 60, 5, 900, &pol));
    ASSERT_EQ(1, ozayn_mfa_policy_count(&_mfa_svc));
    ASSERT_EQ(OZAYN_MFA_OK,
              ozayn_mfa_policy_create(&_mfa_svc, "p2", "P2", factors, 1, 300, 60, 5, 900, &pol));
    ASSERT_EQ(2, ozayn_mfa_policy_count(&_mfa_svc));
    _teardown_deps();
    return 0;
}

/* ============================================================
 * 3. FACTOR INDEPENDENCE
 * ============================================================ */

TEST(test_factor_independence_password_token)
{
    ozayn_mfa_factor_type_t factors[] = {
        OZAYN_MFA_FACTOR_PASSWORD, OZAYN_MFA_FACTOR_TOKEN
    };
    ASSERT(ozayn_mfa_factors_require_distinct_categories(factors, 2));
    return 0;
}

TEST(test_factor_independence_all_different)
{
    ozayn_mfa_factor_type_t factors[] = {
        OZAYN_MFA_FACTOR_PASSWORD, OZAYN_MFA_FACTOR_TOKEN, OZAYN_MFA_FACTOR_BIOMETRIC
    };
    ASSERT(ozayn_mfa_factors_require_distinct_categories(factors, 3));
    return 0;
}

TEST(test_factor_independence_same_category_rejected)
{
    ozayn_mfa_factor_type_t factors[] = {
        OZAYN_MFA_FACTOR_PASSWORD, OZAYN_MFA_FACTOR_PASSWORD
    };
    ASSERT(!ozayn_mfa_factors_require_distinct_categories(factors, 2));
    return 0;
}

TEST(test_factor_independence_token_device_same)
{
    /* TOKEN and DEVICE are both POSSESSION */
    ozayn_mfa_factor_type_t factors[] = {
        OZAYN_MFA_FACTOR_TOKEN, OZAYN_MFA_FACTOR_DEVICE
    };
    ASSERT(!ozayn_mfa_factors_require_distinct_categories(factors, 2));
    return 0;
}

TEST(test_factor_independence_face_voice_same)
{
    /* FACE and VOICE are both INHERENCE */
    ozayn_mfa_factor_type_t factors[] = {
        OZAYN_MFA_FACTOR_FACE, OZAYN_MFA_FACTOR_VOICE
    };
    ASSERT(!ozayn_mfa_factors_require_distinct_categories(factors, 2));
    return 0;
}

TEST(test_factor_independence_null)
{
    ASSERT(ozayn_mfa_factors_require_distinct_categories(NULL, 0));
    return 0;
}

/* ============================================================
 * 4. TRANSACTION MANAGEMENT
 * ============================================================ */

TEST(test_tx_create)
{
    _setup_deps();
    _init_mfa_svc();
    ozayn_identity_t ident = _create_identity("user1");
    ozayn_mfa_factor_type_t factors[] = { OZAYN_MFA_FACTOR_PASSWORD };
    ozayn_mfa_policy_t pol;
    ASSERT_EQ(OZAYN_MFA_OK,
              ozayn_mfa_policy_create(&_mfa_svc, "p1", "P", factors, 1, 300, 60, 5, 900, &pol));

    ozayn_mfa_tx_t tx;
    ozayn_mfa_error_t r = ozayn_mfa_tx_create(&_mfa_svc, ident.id, "p1", &tx);
    ASSERT_EQ(OZAYN_MFA_OK, r);
    ASSERT(tx.id[0] != '\0');
    ASSERT_STR_EQ(ident.id, tx.identity_id);
    ASSERT_STR_EQ("p1", tx.policy_id);
    ASSERT_EQ(OZAYN_MFA_TX_NOT_STARTED, tx.state);
    ASSERT_EQ(1, tx.factor_count);
    ASSERT(tx.in_use);
    _teardown_deps();
    return 0;
}

TEST(test_tx_create_null)
{
    _setup_deps();
    _init_mfa_svc();
    ozayn_mfa_tx_t tx;
    ASSERT_EQ(OZAYN_MFA_ERR_NULL,
              ozayn_mfa_tx_create(NULL, "id1", "p1", &tx));
    ASSERT_EQ(OZAYN_MFA_ERR_NULL,
              ozayn_mfa_tx_create(&_mfa_svc, NULL, "p1", &tx));
    ASSERT_EQ(OZAYN_MFA_ERR_NULL,
              ozayn_mfa_tx_create(&_mfa_svc, "id1", NULL, &tx));
    ASSERT_EQ(OZAYN_MFA_ERR_NULL,
              ozayn_mfa_tx_create(&_mfa_svc, "id1", "p1", NULL));
    _teardown_deps();
    return 0;
}

TEST(test_tx_create_invalid_identity)
{
    _setup_deps();
    _init_mfa_svc();
    ozayn_mfa_factor_type_t factors[] = { OZAYN_MFA_FACTOR_PASSWORD };
    ozayn_mfa_policy_t pol;
    ASSERT_EQ(OZAYN_MFA_OK,
              ozayn_mfa_policy_create(&_mfa_svc, "p1", "P", factors, 1, 300, 60, 5, 900, &pol));

    ozayn_mfa_tx_t tx;
    ASSERT_EQ(OZAYN_MFA_ERR_IDENTITY_INVALID,
              ozayn_mfa_tx_create(&_mfa_svc, "nonexistent", "p1", &tx));
    _teardown_deps();
    return 0;
}

TEST(test_tx_create_disabled_policy)
{
    _setup_deps();
    _init_mfa_svc();
    ozayn_identity_t ident = _create_identity("user1");
    ozayn_mfa_factor_type_t factors[] = { OZAYN_MFA_FACTOR_PASSWORD };
    ozayn_mfa_policy_t pol;
    ASSERT_EQ(OZAYN_MFA_OK,
              ozayn_mfa_policy_create(&_mfa_svc, "p1", "P", factors, 1, 300, 60, 5, 900, &pol));
    ASSERT_EQ(OZAYN_MFA_OK, ozayn_mfa_policy_disable(&_mfa_svc, "p1"));

    ozayn_mfa_tx_t tx;
    ASSERT_EQ(OZAYN_MFA_ERR_POLICY_REJECTED,
              ozayn_mfa_tx_create(&_mfa_svc, ident.id, "p1", &tx));
    _teardown_deps();
    return 0;
}

TEST(test_tx_create_policy_not_found)
{
    _setup_deps();
    _init_mfa_svc();
    ozayn_identity_t ident = _create_identity("user1");
    ozayn_mfa_tx_t tx;
    ASSERT_EQ(OZAYN_MFA_ERR_POLICY_UNAVAILABLE,
              ozayn_mfa_tx_create(&_mfa_svc, ident.id, "nonexistent", &tx));
    _teardown_deps();
    return 0;
}

TEST(test_tx_get)
{
    _setup_deps();
    _init_mfa_svc();
    ozayn_identity_t ident = _create_identity("user1");
    ozayn_mfa_factor_type_t factors[] = { OZAYN_MFA_FACTOR_PASSWORD };
    ozayn_mfa_policy_t pol;
    ASSERT_EQ(OZAYN_MFA_OK,
              ozayn_mfa_policy_create(&_mfa_svc, "p1", "P", factors, 1, 300, 60, 5, 900, &pol));

    ozayn_mfa_tx_t tx;
    ASSERT_EQ(OZAYN_MFA_OK, ozayn_mfa_tx_create(&_mfa_svc, ident.id, "p1", &tx));

    ozayn_mfa_tx_t got;
    ASSERT_EQ(OZAYN_MFA_OK, ozayn_mfa_tx_get(&_mfa_svc, tx.id, &got));
    ASSERT_STR_EQ(tx.id, got.id);
    _teardown_deps();
    return 0;
}

TEST(test_tx_get_not_found)
{
    _setup_deps();
    _init_mfa_svc();
    ozayn_mfa_tx_t tx;
    ASSERT_EQ(OZAYN_MFA_ERR_TRANSACTION_NOT_FOUND,
              ozayn_mfa_tx_get(&_mfa_svc, "nonexistent", &tx));
    _teardown_deps();
    return 0;
}

TEST(test_tx_cancel)
{
    _setup_deps();
    _init_mfa_svc();
    ozayn_identity_t ident = _create_identity("user1");
    ozayn_mfa_factor_type_t factors[] = { OZAYN_MFA_FACTOR_PASSWORD };
    ozayn_mfa_policy_t pol;
    ASSERT_EQ(OZAYN_MFA_OK,
              ozayn_mfa_policy_create(&_mfa_svc, "p1", "P", factors, 1, 300, 60, 5, 900, &pol));

    ozayn_mfa_tx_t tx;
    ASSERT_EQ(OZAYN_MFA_OK, ozayn_mfa_tx_create(&_mfa_svc, ident.id, "p1", &tx));
    ASSERT_EQ(OZAYN_MFA_OK, ozayn_mfa_tx_cancel(&_mfa_svc, tx.id));

    ozayn_mfa_tx_t got;
    ASSERT_EQ(OZAYN_MFA_OK, ozayn_mfa_tx_get(&_mfa_svc, tx.id, &got));
    ASSERT_EQ(OZAYN_MFA_TX_CANCELLED, got.state);
    _teardown_deps();
    return 0;
}

TEST(test_tx_cancel_already_verified)
{
    _setup_deps();
    _init_mfa_svc();
    ozayn_identity_t ident = _create_identity("user1");
    ozayn_mfa_factor_type_t factors[] = { OZAYN_MFA_FACTOR_PASSWORD };
    ozayn_mfa_policy_t pol;
    ASSERT_EQ(OZAYN_MFA_OK,
              ozayn_mfa_policy_create(&_mfa_svc, "p1", "P", factors, 1, 300, 60, 5, 900, &pol));

    ozayn_mfa_tx_t tx;
    ASSERT_EQ(OZAYN_MFA_OK, ozayn_mfa_tx_create(&_mfa_svc, ident.id, "p1", &tx));

    /* Verify the password factor */
    ozayn_mfa_verify_request_t vreq;
    memset(&vreq, 0, sizeof(vreq));
    strncpy(vreq.tx_id, tx.id, sizeof(vreq.tx_id) - 1);
    strncpy(vreq.identity_id, ident.id, sizeof(vreq.identity_id) - 1);
    vreq.factor_type = OZAYN_MFA_FACTOR_PASSWORD;
    ozayn_mfa_result_t mres;
    ASSERT_EQ(OZAYN_MFA_OK, ozayn_mfa_verify_factor(&_mfa_svc, &vreq, &mres));

    /* Complete the transaction */
    ASSERT_EQ(OZAYN_MFA_OK, ozayn_mfa_tx_complete(&_mfa_svc, tx.id, &mres));

    /* Cannot cancel a verified transaction */
    ASSERT_EQ(OZAYN_MFA_ERR_STATE_TRANSITION,
              ozayn_mfa_tx_cancel(&_mfa_svc, tx.id));
    _teardown_deps();
    return 0;
}

TEST(test_tx_cancel_by_identity)
{
    _setup_deps();
    _init_mfa_svc();
    ozayn_identity_t ident = _create_identity("user1");
    ozayn_mfa_factor_type_t factors[] = { OZAYN_MFA_FACTOR_PASSWORD };
    ozayn_mfa_policy_t pol;
    ASSERT_EQ(OZAYN_MFA_OK,
              ozayn_mfa_policy_create(&_mfa_svc, "p1", "P", factors, 1, 300, 60, 5, 900, &pol));

    ozayn_mfa_tx_t tx;
    ASSERT_EQ(OZAYN_MFA_OK, ozayn_mfa_tx_create(&_mfa_svc, ident.id, "p1", &tx));
    ASSERT_EQ(OZAYN_MFA_OK, ozayn_mfa_tx_cancel_by_identity(&_mfa_svc, ident.id));

    ozayn_mfa_tx_t got;
    ASSERT_EQ(OZAYN_MFA_OK, ozayn_mfa_tx_get(&_mfa_svc, tx.id, &got));
    ASSERT_EQ(OZAYN_MFA_TX_CANCELLED, got.state);
    _teardown_deps();
    return 0;
}

TEST(test_tx_count)
{
    _setup_deps();
    _init_mfa_svc();
    ASSERT_EQ(0, ozayn_mfa_tx_count(&_mfa_svc));
    ozayn_identity_t ident = _create_identity("user1");
    ozayn_mfa_factor_type_t factors[] = { OZAYN_MFA_FACTOR_PASSWORD };
    ozayn_mfa_policy_t pol;
    ASSERT_EQ(OZAYN_MFA_OK,
              ozayn_mfa_policy_create(&_mfa_svc, "p1", "P", factors, 1, 300, 60, 5, 900, &pol));

    ozayn_mfa_tx_t tx;
    ASSERT_EQ(OZAYN_MFA_OK, ozayn_mfa_tx_create(&_mfa_svc, ident.id, "p1", &tx));
    ASSERT_EQ(1, ozayn_mfa_tx_count(&_mfa_svc));
    _teardown_deps();
    return 0;
}

TEST(test_tx_identity_count)
{
    _setup_deps();
    _init_mfa_svc();
    ozayn_identity_t ident = _create_identity("user1");
    ozayn_mfa_factor_type_t factors[] = { OZAYN_MFA_FACTOR_PASSWORD };
    ozayn_mfa_policy_t pol;
    ASSERT_EQ(OZAYN_MFA_OK,
              ozayn_mfa_policy_create(&_mfa_svc, "p1", "P", factors, 1, 300, 60, 5, 900, &pol));

    ASSERT_EQ(0, ozayn_mfa_tx_identity_count(&_mfa_svc, ident.id));
    ozayn_mfa_tx_t tx;
    ASSERT_EQ(OZAYN_MFA_OK, ozayn_mfa_tx_create(&_mfa_svc, ident.id, "p1", &tx));
    ASSERT_EQ(1, ozayn_mfa_tx_identity_count(&_mfa_svc, ident.id));
    _teardown_deps();
    return 0;
}

/* ============================================================
 * 5. FACTOR VERIFICATION
 * ============================================================ */

TEST(test_verify_password_factor)
{
    _setup_deps();
    _init_mfa_svc();
    ozayn_identity_t ident = _create_identity("user1");
    ozayn_mfa_factor_type_t factors[] = { OZAYN_MFA_FACTOR_PASSWORD };
    ozayn_mfa_policy_t pol;
    ASSERT_EQ(OZAYN_MFA_OK,
              ozayn_mfa_policy_create(&_mfa_svc, "p1", "P", factors, 1, 300, 60, 5, 900, &pol));

    ozayn_mfa_tx_t tx;
    ASSERT_EQ(OZAYN_MFA_OK, ozayn_mfa_tx_create(&_mfa_svc, ident.id, "p1", &tx));

    ozayn_mfa_verify_request_t vreq;
    memset(&vreq, 0, sizeof(vreq));
    strncpy(vreq.tx_id, tx.id, sizeof(vreq.tx_id) - 1);
    strncpy(vreq.identity_id, ident.id, sizeof(vreq.identity_id) - 1);
    vreq.factor_type = OZAYN_MFA_FACTOR_PASSWORD;

    ozayn_mfa_result_t result;
    ASSERT_EQ(OZAYN_MFA_OK, ozayn_mfa_verify_factor(&_mfa_svc, &vreq, &result));
    ASSERT_EQ(OZAYN_MFA_RESULT_PENDING, result.status);
    ASSERT_EQ(1, result.verified_factor_count);

    /* Transaction should now be in FACTOR_VERIFIED */
    ozayn_mfa_tx_t got;
    ASSERT_EQ(OZAYN_MFA_OK, ozayn_mfa_tx_get(&_mfa_svc, tx.id, &got));
    ASSERT_EQ(OZAYN_MFA_TX_FACTOR_VERIFIED, got.state);
    ASSERT_EQ(1, got.verified_factor_count);
    _teardown_deps();
    return 0;
}

TEST(test_verify_unsupported_factor)
{
    _setup_deps();
    _init_mfa_svc();
    ozayn_identity_t ident = _create_identity("user1");
    ozayn_mfa_factor_type_t factors[] = { OZAYN_MFA_FACTOR_PASSWORD };
    ozayn_mfa_policy_t pol;
    ASSERT_EQ(OZAYN_MFA_OK,
              ozayn_mfa_policy_create(&_mfa_svc, "p1", "P", factors, 1, 300, 60, 5, 900, &pol));

    ozayn_mfa_tx_t tx;
    ASSERT_EQ(OZAYN_MFA_OK, ozayn_mfa_tx_create(&_mfa_svc, ident.id, "p1", &tx));

    /* Try to verify TOKEN factor — not in policy, should fail */
    ozayn_mfa_verify_request_t vreq;
    memset(&vreq, 0, sizeof(vreq));
    strncpy(vreq.tx_id, tx.id, sizeof(vreq.tx_id) - 1);
    strncpy(vreq.identity_id, ident.id, sizeof(vreq.identity_id) - 1);
    vreq.factor_type = OZAYN_MFA_FACTOR_TOKEN;

    ozayn_mfa_result_t result;
    ASSERT_EQ(OZAYN_MFA_ERR_FACTOR_INVALID,
              ozayn_mfa_verify_factor(&_mfa_svc, &vreq, &result));
    _teardown_deps();
    return 0;
}

TEST(test_verify_wrong_identity)
{
    _setup_deps();
    _init_mfa_svc();
    ozayn_identity_t ident1 = _create_identity("user1");
    ozayn_identity_t ident2 = _create_identity("user2");
    ozayn_mfa_factor_type_t factors[] = { OZAYN_MFA_FACTOR_PASSWORD };
    ozayn_mfa_policy_t pol;
    ASSERT_EQ(OZAYN_MFA_OK,
              ozayn_mfa_policy_create(&_mfa_svc, "p1", "P", factors, 1, 300, 60, 5, 900, &pol));

    ozayn_mfa_tx_t tx;
    ASSERT_EQ(OZAYN_MFA_OK, ozayn_mfa_tx_create(&_mfa_svc, ident1.id, "p1", &tx));

    /* Verify with wrong identity */
    ozayn_mfa_verify_request_t vreq;
    memset(&vreq, 0, sizeof(vreq));
    strncpy(vreq.tx_id, tx.id, sizeof(vreq.tx_id) - 1);
    strncpy(vreq.identity_id, ident2.id, sizeof(vreq.identity_id) - 1);
    vreq.factor_type = OZAYN_MFA_FACTOR_PASSWORD;

    ozayn_mfa_result_t result;
    ASSERT_EQ(OZAYN_MFA_ERR_IDENTITY_INVALID,
              ozayn_mfa_verify_factor(&_mfa_svc, &vreq, &result));
    _teardown_deps();
    return 0;
}

TEST(test_verify_replay_protection)
{
    _setup_deps();
    _init_mfa_svc();
    ozayn_identity_t ident = _create_identity("user1");
    ozayn_mfa_factor_type_t factors[] = { OZAYN_MFA_FACTOR_PASSWORD };
    ozayn_mfa_policy_t pol;
    ASSERT_EQ(OZAYN_MFA_OK,
              ozayn_mfa_policy_create(&_mfa_svc, "p1", "P", factors, 1, 300, 60, 5, 900, &pol));

    ozayn_mfa_tx_t tx;
    ASSERT_EQ(OZAYN_MFA_OK, ozayn_mfa_tx_create(&_mfa_svc, ident.id, "p1", &tx));

    /* Verify and complete */
    ozayn_mfa_verify_request_t vreq;
    memset(&vreq, 0, sizeof(vreq));
    strncpy(vreq.tx_id, tx.id, sizeof(vreq.tx_id) - 1);
    strncpy(vreq.identity_id, ident.id, sizeof(vreq.identity_id) - 1);
    vreq.factor_type = OZAYN_MFA_FACTOR_PASSWORD;
    ozayn_mfa_result_t result;
    ASSERT_EQ(OZAYN_MFA_OK, ozayn_mfa_verify_factor(&_mfa_svc, &vreq, &result));
    ASSERT_EQ(OZAYN_MFA_OK, ozayn_mfa_tx_complete(&_mfa_svc, tx.id, &result));

    /* Re-verify — should fail (replay) */
    ASSERT_EQ(OZAYN_MFA_ERR_TRANSACTION_REPLAYED,
              ozayn_mfa_verify_factor(&_mfa_svc, &vreq, &result));
    _teardown_deps();
    return 0;
}

TEST(test_verify_null)
{
    _setup_deps();
    _init_mfa_svc();
    ozayn_mfa_verify_request_t vreq;
    ozayn_mfa_result_t result;
    ASSERT_EQ(OZAYN_MFA_ERR_NULL,
              ozayn_mfa_verify_factor(NULL, &vreq, &result));
    ASSERT_EQ(OZAYN_MFA_ERR_NULL,
              ozayn_mfa_verify_factor(&_mfa_svc, NULL, &result));
    ASSERT_EQ(OZAYN_MFA_ERR_NULL,
              ozayn_mfa_verify_factor(&_mfa_svc, &vreq, NULL));
    _teardown_deps();
    return 0;
}

TEST(test_verify_cancelled_tx)
{
    _setup_deps();
    _init_mfa_svc();
    ozayn_identity_t ident = _create_identity("user1");
    ozayn_mfa_factor_type_t factors[] = { OZAYN_MFA_FACTOR_PASSWORD };
    ozayn_mfa_policy_t pol;
    ASSERT_EQ(OZAYN_MFA_OK,
              ozayn_mfa_policy_create(&_mfa_svc, "p1", "P", factors, 1, 300, 60, 5, 900, &pol));

    ozayn_mfa_tx_t tx;
    ASSERT_EQ(OZAYN_MFA_OK, ozayn_mfa_tx_create(&_mfa_svc, ident.id, "p1", &tx));
    ASSERT_EQ(OZAYN_MFA_OK, ozayn_mfa_tx_cancel(&_mfa_svc, tx.id));

    ozayn_mfa_verify_request_t vreq;
    memset(&vreq, 0, sizeof(vreq));
    strncpy(vreq.tx_id, tx.id, sizeof(vreq.tx_id) - 1);
    strncpy(vreq.identity_id, ident.id, sizeof(vreq.identity_id) - 1);
    vreq.factor_type = OZAYN_MFA_FACTOR_PASSWORD;

    ozayn_mfa_result_t result;
    ASSERT_EQ(OZAYN_MFA_ERR_TRANSACTION_CANCELLED,
              ozayn_mfa_verify_factor(&_mfa_svc, &vreq, &result));
    _teardown_deps();
    return 0;
}

/* ============================================================
 * 6. TRANSACTION COMPLETION
 * ============================================================ */

TEST(test_tx_complete_single_factor)
{
    _setup_deps();
    _init_mfa_svc();
    ozayn_identity_t ident = _create_identity("user1");
    ozayn_mfa_factor_type_t factors[] = { OZAYN_MFA_FACTOR_PASSWORD };
    ozayn_mfa_policy_t pol;
    ASSERT_EQ(OZAYN_MFA_OK,
              ozayn_mfa_policy_create(&_mfa_svc, "p1", "P", factors, 1, 300, 60, 5, 900, &pol));

    ozayn_mfa_tx_t tx;
    ASSERT_EQ(OZAYN_MFA_OK, ozayn_mfa_tx_create(&_mfa_svc, ident.id, "p1", &tx));

    /* Verify factor */
    ozayn_mfa_verify_request_t vreq;
    memset(&vreq, 0, sizeof(vreq));
    strncpy(vreq.tx_id, tx.id, sizeof(vreq.tx_id) - 1);
    strncpy(vreq.identity_id, ident.id, sizeof(vreq.identity_id) - 1);
    vreq.factor_type = OZAYN_MFA_FACTOR_PASSWORD;
    ozayn_mfa_result_t result;
    ASSERT_EQ(OZAYN_MFA_OK, ozayn_mfa_verify_factor(&_mfa_svc, &vreq, &result));

    /* Complete */
    ASSERT_EQ(OZAYN_MFA_OK, ozayn_mfa_tx_complete(&_mfa_svc, tx.id, &result));
    ASSERT_EQ(OZAYN_MFA_RESULT_VERIFIED, result.status);
    ASSERT_EQ(OZAYN_MFA_ASSURANCE_SINGLE, result.assurance);

    /* Verify final state */
    ozayn_mfa_tx_t got;
    ASSERT_EQ(OZAYN_MFA_OK, ozayn_mfa_tx_get(&_mfa_svc, tx.id, &got));
    ASSERT_EQ(OZAYN_MFA_TX_VERIFIED, got.state);
    _teardown_deps();
    return 0;
}

TEST(test_tx_complete_not_all_factors)
{
    _setup_deps();
    _init_mfa_svc();
    ozayn_identity_t ident = _create_identity("user1");
    ozayn_mfa_factor_type_t factors[] = {
        OZAYN_MFA_FACTOR_PASSWORD, OZAYN_MFA_FACTOR_TOKEN
    };
    ozayn_mfa_policy_t pol;
    ASSERT_EQ(OZAYN_MFA_OK,
              ozayn_mfa_policy_create(&_mfa_svc, "p1", "P", factors, 2, 300, 60, 5, 900, &pol));

    ozayn_mfa_tx_t tx;
    ASSERT_EQ(OZAYN_MFA_OK, ozayn_mfa_tx_create(&_mfa_svc, ident.id, "p1", &tx));

    /* Verify only password factor */
    ozayn_mfa_verify_request_t vreq;
    memset(&vreq, 0, sizeof(vreq));
    strncpy(vreq.tx_id, tx.id, sizeof(vreq.tx_id) - 1);
    strncpy(vreq.identity_id, ident.id, sizeof(vreq.identity_id) - 1);
    vreq.factor_type = OZAYN_MFA_FACTOR_PASSWORD;
    ozayn_mfa_result_t result;
    ASSERT_EQ(OZAYN_MFA_OK, ozayn_mfa_verify_factor(&_mfa_svc, &vreq, &result));

    /* Cannot complete — token not verified */
    ASSERT_EQ(OZAYN_MFA_ERR_STATE_TRANSITION,
              ozayn_mfa_tx_complete(&_mfa_svc, tx.id, &result));
    _teardown_deps();
    return 0;
}

TEST(test_tx_complete_not_started)
{
    _setup_deps();
    _init_mfa_svc();
    ozayn_identity_t ident = _create_identity("user1");
    ozayn_mfa_factor_type_t factors[] = { OZAYN_MFA_FACTOR_PASSWORD };
    ozayn_mfa_policy_t pol;
    ASSERT_EQ(OZAYN_MFA_OK,
              ozayn_mfa_policy_create(&_mfa_svc, "p1", "P", factors, 1, 300, 60, 5, 900, &pol));

    ozayn_mfa_tx_t tx;
    ASSERT_EQ(OZAYN_MFA_OK, ozayn_mfa_tx_create(&_mfa_svc, ident.id, "p1", &tx));

    /* Cannot complete before any factor is verified */
    ozayn_mfa_result_t result;
    ASSERT_EQ(OZAYN_MFA_ERR_STATE_TRANSITION,
              ozayn_mfa_tx_complete(&_mfa_svc, tx.id, &result));
    _teardown_deps();
    return 0;
}

TEST(test_tx_complete_null)
{
    _setup_deps();
    _init_mfa_svc();
    ozayn_mfa_result_t result;
    ASSERT_EQ(OZAYN_MFA_ERR_NULL,
              ozayn_mfa_tx_complete(NULL, "tx1", &result));
    ASSERT_EQ(OZAYN_MFA_ERR_NULL,
              ozayn_mfa_tx_complete(&_mfa_svc, NULL, &result));
    ASSERT_EQ(OZAYN_MFA_ERR_NULL,
              ozayn_mfa_tx_complete(&_mfa_svc, "tx1", NULL));
    _teardown_deps();
    return 0;
}

/* ============================================================
 * 7. VALIDATION
 * ============================================================ */

TEST(test_validate_factor_type)
{
    ASSERT_EQ(0, ozayn_mfa_validate_factor_type(OZAYN_MFA_FACTOR_PASSWORD));
    ASSERT_EQ(0, ozayn_mfa_validate_factor_type(OZAYN_MFA_FACTOR_TOKEN));
    ASSERT_EQ(0, ozayn_mfa_validate_factor_type(OZAYN_MFA_FACTOR_DEVICE));
    ASSERT_EQ(0, ozayn_mfa_validate_factor_type(OZAYN_MFA_FACTOR_BIOMETRIC));
    ASSERT_EQ(0, ozayn_mfa_validate_factor_type(OZAYN_MFA_FACTOR_VOICE));
    ASSERT_EQ(0, ozayn_mfa_validate_factor_type(OZAYN_MFA_FACTOR_FACE));
    ASSERT_EQ(0, ozayn_mfa_validate_factor_type(OZAYN_MFA_FACTOR_GESTURE));
    ASSERT_EQ(-1, ozayn_mfa_validate_factor_type(OZAYN_MFA_FACTOR_UNKNOWN));
    ASSERT_EQ(-1, ozayn_mfa_validate_factor_type((ozayn_mfa_factor_type_t)99));
    return 0;
}

TEST(test_validate_category)
{
    ASSERT_EQ(0, ozayn_mfa_validate_category(OZAYN_MFA_CATEGORY_KNOWLEDGE));
    ASSERT_EQ(0, ozayn_mfa_validate_category(OZAYN_MFA_CATEGORY_POSSESSION));
    ASSERT_EQ(0, ozayn_mfa_validate_category(OZAYN_MFA_CATEGORY_INHERENCE));
    ASSERT_EQ(-1, ozayn_mfa_validate_category(OZAYN_MFA_CATEGORY_UNKNOWN));
    ASSERT_EQ(-1, ozayn_mfa_validate_category((ozayn_mfa_category_t)99));
    return 0;
}

TEST(test_validate_tx_transition)
{
    ASSERT_EQ(0, ozayn_mfa_validate_tx_transition(OZAYN_MFA_TX_NOT_STARTED,
                                                   OZAYN_MFA_TX_IN_PROGRESS));
    ASSERT_EQ(0, ozayn_mfa_validate_tx_transition(OZAYN_MFA_TX_NOT_STARTED,
                                                   OZAYN_MFA_TX_CANCELLED));
    ASSERT_EQ(0, ozayn_mfa_validate_tx_transition(OZAYN_MFA_TX_IN_PROGRESS,
                                                   OZAYN_MFA_TX_FACTOR_VERIFIED));
    ASSERT_EQ(0, ozayn_mfa_validate_tx_transition(OZAYN_MFA_TX_IN_PROGRESS,
                                                   OZAYN_MFA_TX_FAILED));
    ASSERT_EQ(0, ozayn_mfa_validate_tx_transition(OZAYN_MFA_TX_FACTOR_VERIFIED,
                                                   OZAYN_MFA_TX_VERIFIED));
    /* Invalid transitions */
    ASSERT_EQ(-1, ozayn_mfa_validate_tx_transition(OZAYN_MFA_TX_VERIFIED,
                                                    OZAYN_MFA_TX_IN_PROGRESS));
    ASSERT_EQ(-1, ozayn_mfa_validate_tx_transition(OZAYN_MFA_TX_FAILED,
                                                    OZAYN_MFA_TX_VERIFIED));
    ASSERT_EQ(-1, ozayn_mfa_validate_tx_transition(OZAYN_MFA_TX_CANCELLED,
                                                    OZAYN_MFA_TX_IN_PROGRESS));
    return 0;
}

TEST(test_validate_assurance)
{
    ASSERT_EQ(0, ozayn_mfa_validate_assurance(OZAYN_MFA_ASSURANCE_NONE));
    ASSERT_EQ(0, ozayn_mfa_validate_assurance(OZAYN_MFA_ASSURANCE_SINGLE));
    ASSERT_EQ(0, ozayn_mfa_validate_assurance(OZAYN_MFA_ASSURANCE_MULTI));
    ASSERT_EQ(0, ozayn_mfa_validate_assurance(OZAYN_MFA_ASSURANCE_HIGH));
    ASSERT_EQ(-1, ozayn_mfa_validate_assurance((ozayn_mfa_assurance_t)99));
    return 0;
}

/* ============================================================
 * 8. NAME HELPERS
 * ============================================================ */

TEST(test_error_names)
{
    ASSERT_STR_EQ("OK", ozayn_mfa_error_name(OZAYN_MFA_OK));
    ASSERT_STR_EQ("NULL", ozayn_mfa_error_name(OZAYN_MFA_ERR_NULL));
    ASSERT_STR_EQ("NOT_INITIALIZED",
                  ozayn_mfa_error_name(OZAYN_MFA_ERR_NOT_INITIALIZED));
    ASSERT_STR_EQ("NOT_FOUND",
                  ozayn_mfa_error_name(OZAYN_MFA_ERR_NOT_FOUND));
    ASSERT_STR_EQ("ALREADY_EXISTS",
                  ozayn_mfa_error_name(OZAYN_MFA_ERR_ALREADY_EXISTS));
    ASSERT_STR_EQ("INVALID", ozayn_mfa_error_name(OZAYN_MFA_ERR_INVALID));
    ASSERT_STR_EQ("ID_INVALID",
                  ozayn_mfa_error_name(OZAYN_MFA_ERR_ID_INVALID));
    ASSERT_STR_EQ("STATE_INVALID",
                  ozayn_mfa_error_name(OZAYN_MFA_ERR_STATE_INVALID));
    ASSERT_STR_EQ("STATE_TRANSITION",
                  ozayn_mfa_error_name(OZAYN_MFA_ERR_STATE_TRANSITION));
    ASSERT_STR_EQ("LIMIT_REACHED",
                  ozayn_mfa_error_name(OZAYN_MFA_ERR_LIMIT_REACHED));
    ASSERT_STR_EQ("POLICY_INVALID",
                  ozayn_mfa_error_name(OZAYN_MFA_ERR_POLICY_INVALID));
    ASSERT_STR_EQ("POLICY_UNAVAILABLE",
                  ozayn_mfa_error_name(OZAYN_MFA_ERR_POLICY_UNAVAILABLE));
    ASSERT_STR_EQ("FACTOR_INVALID",
                  ozayn_mfa_error_name(OZAYN_MFA_ERR_FACTOR_INVALID));
    ASSERT_STR_EQ("FACTOR_UNSUPPORTED",
                  ozayn_mfa_error_name(OZAYN_MFA_ERR_FACTOR_UNSUPPORTED));
    ASSERT_STR_EQ("FACTOR_UNAVAILABLE",
                  ozayn_mfa_error_name(OZAYN_MFA_ERR_FACTOR_UNAVAILABLE));
    ASSERT_STR_EQ("FACTOR_FAILED",
                  ozayn_mfa_error_name(OZAYN_MFA_ERR_FACTOR_FAILED));
    ASSERT_STR_EQ("FACTOR_ALREADY_VERIFIED",
                  ozayn_mfa_error_name(OZAYN_MFA_ERR_FACTOR_ALREADY_VERIFIED));
    ASSERT_STR_EQ("INSUFFICIENT_FACTORS",
                  ozayn_mfa_error_name(OZAYN_MFA_ERR_INSUFFICIENT_FACTORS));
    ASSERT_STR_EQ("TRANSACTION_INVALID",
                  ozayn_mfa_error_name(OZAYN_MFA_ERR_TRANSACTION_INVALID));
    ASSERT_STR_EQ("TRANSACTION_NOT_FOUND",
                  ozayn_mfa_error_name(OZAYN_MFA_ERR_TRANSACTION_NOT_FOUND));
    ASSERT_STR_EQ("TRANSACTION_EXPIRED",
                  ozayn_mfa_error_name(OZAYN_MFA_ERR_TRANSACTION_EXPIRED));
    ASSERT_STR_EQ("TRANSACTION_CANCELLED",
                  ozayn_mfa_error_name(OZAYN_MFA_ERR_TRANSACTION_CANCELLED));
    ASSERT_STR_EQ("TRANSACTION_REPLAYED",
                  ozayn_mfa_error_name(OZAYN_MFA_ERR_TRANSACTION_REPLAYED));
    ASSERT_STR_EQ("IDENTITY_INVALID",
                  ozayn_mfa_error_name(OZAYN_MFA_ERR_IDENTITY_INVALID));
    ASSERT_STR_EQ("IDENTITY_REVOKED",
                  ozayn_mfa_error_name(OZAYN_MFA_ERR_IDENTITY_REVOKED));
    ASSERT_STR_EQ("IDENTITY_SUSPENDED",
                  ozayn_mfa_error_name(OZAYN_MFA_ERR_IDENTITY_SUSPENDED));
    ASSERT_STR_EQ("SESSION_INVALID",
                  ozayn_mfa_error_name(OZAYN_MFA_ERR_SESSION_INVALID));
    ASSERT_STR_EQ("ATTEMPT_BLOCKED",
                  ozayn_mfa_error_name(OZAYN_MFA_ERR_ATTEMPT_BLOCKED));
    ASSERT_STR_EQ("TIMEOUT",
                  ozayn_mfa_error_name(OZAYN_MFA_ERR_TIMEOUT));
    ASSERT_STR_EQ("PROVIDER_ERROR",
                  ozayn_mfa_error_name(OZAYN_MFA_ERR_PROVIDER_ERROR));
    ASSERT_STR_EQ("PROVIDER_UNAVAILABLE",
                  ozayn_mfa_error_name(OZAYN_MFA_ERR_PROVIDER_UNAVAILABLE));
    ASSERT_STR_EQ("STORAGE_FAILED",
                  ozayn_mfa_error_name(OZAYN_MFA_ERR_STORAGE_FAILED));
    ASSERT_STR_EQ("VAULT_UNAVAILABLE",
                  ozayn_mfa_error_name(OZAYN_MFA_ERR_VAULT_UNAVAILABLE));
    ASSERT_STR_EQ("POLICY_REJECTED",
                  ozayn_mfa_error_name(OZAYN_MFA_ERR_POLICY_REJECTED));
    ASSERT_STR_EQ("UNKNOWN",
                  ozayn_mfa_error_name((ozayn_mfa_error_t)999));
    return 0;
}

TEST(test_factor_type_names)
{
    ASSERT_STR_EQ("PASSWORD", ozayn_mfa_factor_type_name(OZAYN_MFA_FACTOR_PASSWORD));
    ASSERT_STR_EQ("TOKEN", ozayn_mfa_factor_type_name(OZAYN_MFA_FACTOR_TOKEN));
    ASSERT_STR_EQ("DEVICE", ozayn_mfa_factor_type_name(OZAYN_MFA_FACTOR_DEVICE));
    ASSERT_STR_EQ("BIOMETRIC", ozayn_mfa_factor_type_name(OZAYN_MFA_FACTOR_BIOMETRIC));
    ASSERT_STR_EQ("VOICE", ozayn_mfa_factor_type_name(OZAYN_MFA_FACTOR_VOICE));
    ASSERT_STR_EQ("FACE", ozayn_mfa_factor_type_name(OZAYN_MFA_FACTOR_FACE));
    ASSERT_STR_EQ("GESTURE", ozayn_mfa_factor_type_name(OZAYN_MFA_FACTOR_GESTURE));
    return 0;
}

TEST(test_category_names)
{
    ASSERT_STR_EQ("KNOWLEDGE", ozayn_mfa_category_name(OZAYN_MFA_CATEGORY_KNOWLEDGE));
    ASSERT_STR_EQ("POSSESSION", ozayn_mfa_category_name(OZAYN_MFA_CATEGORY_POSSESSION));
    ASSERT_STR_EQ("INHERENCE", ozayn_mfa_category_name(OZAYN_MFA_CATEGORY_INHERENCE));
    ASSERT_STR_EQ("UNKNOWN", ozayn_mfa_category_name(OZAYN_MFA_CATEGORY_UNKNOWN));
    return 0;
}

TEST(test_factor_state_names)
{
    ASSERT_STR_EQ("PENDING", ozayn_mfa_factor_state_name(OZAYN_MFA_FACT_STATE_PENDING));
    ASSERT_STR_EQ("VERIFIED", ozayn_mfa_factor_state_name(OZAYN_MFA_FACT_STATE_VERIFIED));
    ASSERT_STR_EQ("FAILED", ozayn_mfa_factor_state_name(OZAYN_MFA_FACT_STATE_FAILED));
    ASSERT_STR_EQ("UNAVAILABLE", ozayn_mfa_factor_state_name(OZAYN_MFA_FACT_STATE_UNAVAILABLE));
    ASSERT_STR_EQ("SKIPPED", ozayn_mfa_factor_state_name(OZAYN_MFA_FACT_STATE_SKIPPED));
    return 0;
}

TEST(test_tx_state_names)
{
    ASSERT_STR_EQ("NOT_STARTED", ozayn_mfa_tx_state_name(OZAYN_MFA_TX_NOT_STARTED));
    ASSERT_STR_EQ("IN_PROGRESS", ozayn_mfa_tx_state_name(OZAYN_MFA_TX_IN_PROGRESS));
    ASSERT_STR_EQ("FACTOR_VERIFIED", ozayn_mfa_tx_state_name(OZAYN_MFA_TX_FACTOR_VERIFIED));
    ASSERT_STR_EQ("VERIFIED", ozayn_mfa_tx_state_name(OZAYN_MFA_TX_VERIFIED));
    ASSERT_STR_EQ("FAILED", ozayn_mfa_tx_state_name(OZAYN_MFA_TX_FAILED));
    ASSERT_STR_EQ("EXPIRED", ozayn_mfa_tx_state_name(OZAYN_MFA_TX_EXPIRED));
    ASSERT_STR_EQ("CANCELLED", ozayn_mfa_tx_state_name(OZAYN_MFA_TX_CANCELLED));
    ASSERT_STR_EQ("UNAVAILABLE", ozayn_mfa_tx_state_name(OZAYN_MFA_TX_UNAVAILABLE));
    return 0;
}

TEST(test_assurance_names)
{
    ASSERT_STR_EQ("NONE", ozayn_mfa_assurance_name(OZAYN_MFA_ASSURANCE_NONE));
    ASSERT_STR_EQ("SINGLE_FACTOR", ozayn_mfa_assurance_name(OZAYN_MFA_ASSURANCE_SINGLE));
    ASSERT_STR_EQ("MULTI_FACTOR", ozayn_mfa_assurance_name(OZAYN_MFA_ASSURANCE_MULTI));
    ASSERT_STR_EQ("HIGH_ASSURANCE", ozayn_mfa_assurance_name(OZAYN_MFA_ASSURANCE_HIGH));
    return 0;
}

TEST(test_result_status_names)
{
    ASSERT_STR_EQ("VERIFIED", ozayn_mfa_result_status_name(OZAYN_MFA_RESULT_VERIFIED));
    ASSERT_STR_EQ("FAILED", ozayn_mfa_result_status_name(OZAYN_MFA_RESULT_FAILED));
    ASSERT_STR_EQ("PENDING", ozayn_mfa_result_status_name(OZAYN_MFA_RESULT_PENDING));
    ASSERT_STR_EQ("EXPIRED", ozayn_mfa_result_status_name(OZAYN_MFA_RESULT_EXPIRED));
    ASSERT_STR_EQ("CANCELLED", ozayn_mfa_result_status_name(OZAYN_MFA_RESULT_CANCELLED));
    ASSERT_STR_EQ("UNAVAILABLE", ozayn_mfa_result_status_name(OZAYN_MFA_RESULT_UNAVAILABLE));
    ASSERT_STR_EQ("ERROR", ozayn_mfa_result_status_name(OZAYN_MFA_RESULT_ERROR));
    return 0;
}

/* ============================================================
 * 9. SECURITY TESTS
 * ============================================================ */

TEST(test_no_master_bypass)
{
    /* No master bypass code exists — verify with a non-existent identity */
    _setup_deps();
    _init_mfa_svc();
    ozayn_mfa_factor_type_t factors[] = { OZAYN_MFA_FACTOR_PASSWORD };
    ozayn_mfa_policy_t pol;
    ASSERT_EQ(OZAYN_MFA_OK,
              ozayn_mfa_policy_create(&_mfa_svc, "p1", "P", factors, 1, 300, 60, 5, 900, &pol));

    /* Cannot create transaction for non-existent identity */
    ozayn_mfa_tx_t tx;
    ASSERT_EQ(OZAYN_MFA_ERR_IDENTITY_INVALID,
              ozayn_mfa_tx_create(&_mfa_svc, "fake-identity", "p1", &tx));
    _teardown_deps();
    return 0;
}

TEST(test_revoked_identity_cannot_start_mfa)
{
    _setup_deps();
    _init_mfa_svc();
    ozayn_identity_t ident = _create_identity("user1");
    ozayn_id_revoke(&_id_svc, ident.id);

    ozayn_mfa_factor_type_t factors[] = { OZAYN_MFA_FACTOR_PASSWORD };
    ozayn_mfa_policy_t pol;
    ASSERT_EQ(OZAYN_MFA_OK,
              ozayn_mfa_policy_create(&_mfa_svc, "p1", "P", factors, 1, 300, 60, 5, 900, &pol));

    ozayn_mfa_tx_t tx;
    ASSERT_EQ(OZAYN_MFA_ERR_IDENTITY_REVOKED,
              ozayn_mfa_tx_create(&_mfa_svc, ident.id, "p1", &tx));
    _teardown_deps();
    return 0;
}

TEST(test_suspended_identity_cannot_start_mfa)
{
    _setup_deps();
    _init_mfa_svc();
    ozayn_identity_t ident = _create_identity("user1");
    ozayn_id_suspend(&_id_svc, ident.id);

    ozayn_mfa_factor_type_t factors[] = { OZAYN_MFA_FACTOR_PASSWORD };
    ozayn_mfa_policy_t pol;
    ASSERT_EQ(OZAYN_MFA_OK,
              ozayn_mfa_policy_create(&_mfa_svc, "p1", "P", factors, 1, 300, 60, 5, 900, &pol));

    ozayn_mfa_tx_t tx;
    ASSERT_EQ(OZAYN_MFA_ERR_IDENTITY_SUSPENDED,
              ozayn_mfa_tx_create(&_mfa_svc, ident.id, "p1", &tx));
    _teardown_deps();
    return 0;
}

TEST(test_cannot_bypass_mfa_for_session)
{
    /* A single-factor auth should not produce MULTI assurance */
    _setup_deps();
    _init_mfa_svc();
    ozayn_identity_t ident = _create_identity("user1");
    ozayn_mfa_factor_type_t factors[] = { OZAYN_MFA_FACTOR_PASSWORD };
    ozayn_mfa_policy_t pol;
    ASSERT_EQ(OZAYN_MFA_OK,
              ozayn_mfa_policy_create(&_mfa_svc, "p1", "P", factors, 1, 300, 60, 5, 900, &pol));

    ozayn_mfa_tx_t tx;
    ASSERT_EQ(OZAYN_MFA_OK, ozayn_mfa_tx_create(&_mfa_svc, ident.id, "p1", &tx));

    /* Verify password factor */
    ozayn_mfa_verify_request_t vreq;
    memset(&vreq, 0, sizeof(vreq));
    strncpy(vreq.tx_id, tx.id, sizeof(vreq.tx_id) - 1);
    strncpy(vreq.identity_id, ident.id, sizeof(vreq.identity_id) - 1);
    vreq.factor_type = OZAYN_MFA_FACTOR_PASSWORD;
    ozayn_mfa_result_t result;
    ASSERT_EQ(OZAYN_MFA_OK, ozayn_mfa_verify_factor(&_mfa_svc, &vreq, &result));

    /* Complete — should be SINGLE, not MULTI */
    ASSERT_EQ(OZAYN_MFA_OK, ozayn_mfa_tx_complete(&_mfa_svc, tx.id, &result));
    ASSERT_EQ(OZAYN_MFA_ASSURANCE_SINGLE, result.assurance);
    ASSERT(result.assurance != OZAYN_MFA_ASSURANCE_MULTI);
    _teardown_deps();
    return 0;
}

TEST(test_scope_escalation_prevented)
{
    /* Cannot verify factor for wrong transaction identity */
    _setup_deps();
    _init_mfa_svc();
    ozayn_identity_t ident1 = _create_identity("user1");
    ozayn_identity_t ident2 = _create_identity("user2");
    ozayn_mfa_factor_type_t factors[] = { OZAYN_MFA_FACTOR_PASSWORD };
    ozayn_mfa_policy_t pol;
    ASSERT_EQ(OZAYN_MFA_OK,
              ozayn_mfa_policy_create(&_mfa_svc, "p1", "P", factors, 1, 300, 60, 5, 900, &pol));

    /* Create transaction for user1 */
    ozayn_mfa_tx_t tx;
    ASSERT_EQ(OZAYN_MFA_OK, ozayn_mfa_tx_create(&_mfa_svc, ident1.id, "p1", &tx));

    /* Try to verify as user2 — should fail */
    ozayn_mfa_verify_request_t vreq;
    memset(&vreq, 0, sizeof(vreq));
    strncpy(vreq.tx_id, tx.id, sizeof(vreq.tx_id) - 1);
    strncpy(vreq.identity_id, ident2.id, sizeof(vreq.identity_id) - 1);
    vreq.factor_type = OZAYN_MFA_FACTOR_PASSWORD;

    ozayn_mfa_result_t result;
    ASSERT_EQ(OZAYN_MFA_ERR_IDENTITY_INVALID,
              ozayn_mfa_verify_factor(&_mfa_svc, &vreq, &result));
    _teardown_deps();
    return 0;
}

TEST(test_no_hardcoded_superuser)
{
    /* Verify no special identity bypasses MFA */
    _setup_deps();
    _init_mfa_svc();
    ozayn_identity_t ident = _create_identity("admin");
    ozayn_mfa_factor_type_t factors[] = { OZAYN_MFA_FACTOR_PASSWORD };
    ozayn_mfa_policy_t pol;
    ASSERT_EQ(OZAYN_MFA_OK,
              ozayn_mfa_policy_create(&_mfa_svc, "p1", "P", factors, 1, 300, 60, 5, 900, &pol));

    ozayn_mfa_tx_t tx;
    ASSERT_EQ(OZAYN_MFA_OK, ozayn_mfa_tx_create(&_mfa_svc, ident.id, "p1", &tx));

    /* Must still verify factor — no bypass */
    ozayn_mfa_verify_request_t vreq;
    memset(&vreq, 0, sizeof(vreq));
    strncpy(vreq.tx_id, tx.id, sizeof(vreq.tx_id) - 1);
    strncpy(vreq.identity_id, ident.id, sizeof(vreq.identity_id) - 1);
    vreq.factor_type = OZAYN_MFA_FACTOR_PASSWORD;

    /* Verify before completing */
    ozayn_mfa_result_t result;
    ASSERT_EQ(OZAYN_MFA_OK, ozayn_mfa_verify_factor(&_mfa_svc, &vreq, &result));

    /* Complete only works after all factors verified */
    ASSERT_EQ(OZAYN_MFA_OK, ozayn_mfa_tx_complete(&_mfa_svc, tx.id, &result));
    ASSERT_EQ(OZAYN_MFA_ASSURANCE_SINGLE, result.assurance);
    _teardown_deps();
    return 0;
}

TEST(test_tx_new_cancels_old)
{
    /* Creating a new transaction cancels any existing one for same identity */
    _setup_deps();
    _init_mfa_svc();
    ozayn_identity_t ident = _create_identity("user1");
    ozayn_mfa_factor_type_t factors[] = { OZAYN_MFA_FACTOR_PASSWORD };
    ozayn_mfa_policy_t pol;
    ASSERT_EQ(OZAYN_MFA_OK,
              ozayn_mfa_policy_create(&_mfa_svc, "p1", "P", factors, 1, 300, 60, 5, 900, &pol));

    ozayn_mfa_tx_t tx1;
    ASSERT_EQ(OZAYN_MFA_OK, ozayn_mfa_tx_create(&_mfa_svc, ident.id, "p1", &tx1));
    ASSERT_EQ(OZAYN_MFA_TX_NOT_STARTED, tx1.state);

    /* Create another — first should be cancelled */
    ozayn_mfa_tx_t tx2;
    ASSERT_EQ(OZAYN_MFA_OK, ozayn_mfa_tx_create(&_mfa_svc, ident.id, "p1", &tx2));

    ozayn_mfa_tx_t got1;
    ASSERT_EQ(OZAYN_MFA_OK, ozayn_mfa_tx_get(&_mfa_svc, tx1.id, &got1));
    ASSERT_EQ(OZAYN_MFA_TX_CANCELLED, got1.state);
    _teardown_deps();
    return 0;
}

/* ============================================================
 * 10. DEFAULT / TEST POLICIES
 * ============================================================ */

TEST(test_default_policy)
{
    ozayn_mfa_policy_t p = ozayn_mfa_default_policy();
    ASSERT_STR_EQ("default", p.id);
    ASSERT_STR_EQ("Default MFA Policy", p.name);
    ASSERT(p.enabled);
    ASSERT_EQ(2, p.required_factor_count);
    ASSERT_EQ(OZAYN_MFA_FACTOR_PASSWORD, p.required_factors[0]);
    ASSERT_EQ(OZAYN_MFA_FACTOR_TOKEN, p.required_factors[1]);
    ASSERT_EQ(300, p.transaction_timeout_seconds);
    ASSERT_EQ(5, p.max_failures);
    return 0;
}

TEST(test_test_policy)
{
    ozayn_mfa_policy_t p = ozayn_mfa_test_policy();
    ASSERT_STR_EQ("test-mfa", p.id);
    ASSERT_EQ(2, p.required_factor_count);
    ASSERT_EQ(30, p.transaction_timeout_seconds);
    ASSERT_EQ(3, p.max_failures);
    return 0;
}

TEST(test_high_security_policy)
{
    ozayn_mfa_policy_t p = ozayn_mfa_high_security_policy();
    ASSERT_STR_EQ("high-security", p.id);
    ASSERT_EQ(3, p.required_factor_count);
    ASSERT_EQ(OZAYN_MFA_FACTOR_PASSWORD, p.required_factors[0]);
    ASSERT_EQ(OZAYN_MFA_FACTOR_TOKEN, p.required_factors[1]);
    ASSERT_EQ(OZAYN_MFA_FACTOR_BIOMETRIC, p.required_factors[2]);
    ASSERT_EQ(120, p.transaction_timeout_seconds);
    return 0;
}

TEST(test_factor_type_category)
{
    ASSERT_EQ(OZAYN_MFA_CATEGORY_KNOWLEDGE,
              ozayn_mfa_factor_type_category(OZAYN_MFA_FACTOR_PASSWORD));
    ASSERT_EQ(OZAYN_MFA_CATEGORY_POSSESSION,
              ozayn_mfa_factor_type_category(OZAYN_MFA_FACTOR_TOKEN));
    ASSERT_EQ(OZAYN_MFA_CATEGORY_POSSESSION,
              ozayn_mfa_factor_type_category(OZAYN_MFA_FACTOR_DEVICE));
    ASSERT_EQ(OZAYN_MFA_CATEGORY_INHERENCE,
              ozayn_mfa_factor_type_category(OZAYN_MFA_FACTOR_BIOMETRIC));
    ASSERT_EQ(OZAYN_MFA_CATEGORY_INHERENCE,
              ozayn_mfa_factor_type_category(OZAYN_MFA_FACTOR_VOICE));
    ASSERT_EQ(OZAYN_MFA_CATEGORY_INHERENCE,
              ozayn_mfa_factor_type_category(OZAYN_MFA_FACTOR_FACE));
    ASSERT_EQ(OZAYN_MFA_CATEGORY_INHERENCE,
              ozayn_mfa_factor_type_category(OZAYN_MFA_FACTOR_GESTURE));
    return 0;
}

TEST(test_factor_type_implemented)
{
    ASSERT(ozayn_mfa_factor_type_is_implemented(OZAYN_MFA_FACTOR_PASSWORD));
    ASSERT(!ozayn_mfa_factor_type_is_implemented(OZAYN_MFA_FACTOR_TOKEN));
    ASSERT(!ozayn_mfa_factor_type_is_implemented(OZAYN_MFA_FACTOR_DEVICE));
    ASSERT(!ozayn_mfa_factor_type_is_implemented(OZAYN_MFA_FACTOR_BIOMETRIC));
    return 0;
}

/* ============================================================
 * TEST REGISTRATION
 * ============================================================ */

int run_mfa_tests(void)
{
    printf("\n  --- MFA TESTS ---\n");

    /* 1. Service lifecycle */
    RUN(test_service_init);
    RUN(test_service_init_null);
    RUN(test_service_init_no_identity);
    RUN(test_service_shutdown);
    RUN(test_service_shutdown_null);
    RUN(test_service_not_initialized);

    /* 2. Policy management */
    RUN(test_policy_create);
    RUN(test_policy_create_null);
    RUN(test_policy_create_duplicate);
    RUN(test_policy_create_same_category_rejected);
    RUN(test_policy_create_invalid_factor);
    RUN(test_policy_create_zero_timeout);
    RUN(test_policy_get);
    RUN(test_policy_get_not_found);
    RUN(test_policy_exists);
    RUN(test_policy_enable_disable);
    RUN(test_policy_delete);
    RUN(test_policy_count);

    /* 3. Factor independence */
    RUN(test_factor_independence_password_token);
    RUN(test_factor_independence_all_different);
    RUN(test_factor_independence_same_category_rejected);
    RUN(test_factor_independence_token_device_same);
    RUN(test_factor_independence_face_voice_same);
    RUN(test_factor_independence_null);

    /* 4. Transaction management */
    RUN(test_tx_create);
    RUN(test_tx_create_null);
    RUN(test_tx_create_invalid_identity);
    RUN(test_tx_create_disabled_policy);
    RUN(test_tx_create_policy_not_found);
    RUN(test_tx_get);
    RUN(test_tx_get_not_found);
    RUN(test_tx_cancel);
    RUN(test_tx_cancel_already_verified);
    RUN(test_tx_cancel_by_identity);
    RUN(test_tx_count);
    RUN(test_tx_identity_count);

    /* 5. Factor verification */
    RUN(test_verify_password_factor);
    RUN(test_verify_unsupported_factor);
    RUN(test_verify_wrong_identity);
    RUN(test_verify_replay_protection);
    RUN(test_verify_null);
    RUN(test_verify_cancelled_tx);

    /* 6. Transaction completion */
    RUN(test_tx_complete_single_factor);
    RUN(test_tx_complete_not_all_factors);
    RUN(test_tx_complete_not_started);
    RUN(test_tx_complete_null);

    /* 7. Validation */
    RUN(test_validate_factor_type);
    RUN(test_validate_category);
    RUN(test_validate_tx_transition);
    RUN(test_validate_assurance);

    /* 8. Name helpers */
    RUN(test_error_names);
    RUN(test_factor_type_names);
    RUN(test_category_names);
    RUN(test_factor_state_names);
    RUN(test_tx_state_names);
    RUN(test_assurance_names);
    RUN(test_result_status_names);

    /* 9. Security tests */
    RUN(test_no_master_bypass);
    RUN(test_revoked_identity_cannot_start_mfa);
    RUN(test_suspended_identity_cannot_start_mfa);
    RUN(test_cannot_bypass_mfa_for_session);
    RUN(test_scope_escalation_prevented);
    RUN(test_no_hardcoded_superuser);
    RUN(test_tx_new_cancels_old);

    /* 10. Default/test policies */
    RUN(test_default_policy);
    RUN(test_test_policy);
    RUN(test_high_security_policy);
    RUN(test_factor_type_category);
    RUN(test_factor_type_implemented);

    SUITE_END();
    return _tf_suite_fail;
}
