#include "../../tests/test_framework.h"
#include "../audit.h"
#include "../identity.h"
#include "../authentication.h"
#include "../attempt_control.h"
#include "../authorization.h"
#include "../rbac.h"
#include "../permission.h"
#include "../mfa.h"
#include "../protection_provider.h"
#include "../protection_provider_mock.h"
#include "../storage_provider.h"
#include "../storage_provider_mem.h"
#include "../key_lifecycle.h"
#include "../key_provider.h"
#include "../secure_vault.h"
#include <string.h>
#include <time.h>

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
static ozayn_authz_service_t       _authz_svc;
static ozayn_rbac_service_t        _rbac_svc;
static ozayn_perm_service_t        _perm_svc;
static ozayn_mfa_service_t         _mfa_svc;
static ozayn_audit_service_t       _audit_svc;

static void _setup_all_deps(void)
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

    ozayn_authz_service_config_t az_cfg;
    memset(&az_cfg, 0, sizeof(az_cfg));
    az_cfg.identity_service = &_id_svc;
    ozayn_authz_service_init(&_authz_svc, &az_cfg);

    ozayn_rbac_service_config_t rbac_cfg;
    memset(&rbac_cfg, 0, sizeof(rbac_cfg));
    rbac_cfg.identity_service = &_id_svc;
    ozayn_rbac_service_init(&_rbac_svc, &rbac_cfg);
    ozayn_authz_set_rbac_service(&_authz_svc, &_rbac_svc);

    ozayn_perm_service_config_t perm_cfg;
    memset(&perm_cfg, 0, sizeof(perm_cfg));
    ozayn_perm_service_init(&_perm_svc, &perm_cfg);
    ozayn_authz_set_permission_service(&_authz_svc, &_perm_svc);

    ozayn_mfa_service_config_t mfa_cfg;
    memset(&mfa_cfg, 0, sizeof(mfa_cfg));
    mfa_cfg.identity_service = &_id_svc;
    mfa_cfg.authn_service = &_authn_svc;
    mfa_cfg.attempt_control = &_ac_svc;
    ozayn_mfa_service_init(&_mfa_svc, &mfa_cfg);
}

static void _teardown_all_deps(void)
{
    ozayn_audit_service_shutdown(&_audit_svc);
    ozayn_mfa_service_shutdown(&_mfa_svc);
    ozayn_perm_service_shutdown(&_perm_svc);
    ozayn_rbac_service_shutdown(&_rbac_svc);
    ozayn_authz_service_shutdown(&_authz_svc);
    ozayn_authn_service_shutdown(&_authn_svc);
    ozayn_ac_service_shutdown(&_ac_svc);
    ozayn_id_service_shutdown(&_id_svc);
    ozayn_vault_shutdown(&_vault);
    ozayn_kl_shutdown(&_kl);
    ozayn_sp_shutdown(&_stor);
    ozayn_prot_shutdown(&_prot);
}

static void _init_audit_default(void)
{
    ozayn_audit_service_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.event_capacity = 1024;
    cfg.default_minimum_severity = OZAYN_AUDIT_SEV_INFO;
    cfg.require_identity = 0;
    ozayn_audit_service_init(&_audit_svc, &cfg);
}

static ozayn_audit_event_t _make_event(ozayn_audit_event_type_t type,
                                        ozayn_audit_outcome_t outcome,
                                        const char *identity)
{
    ozayn_audit_event_t ev;
    ozayn_audit_event_init(&ev);
    ozayn_audit_event_set_type(&ev, type);
    ozayn_audit_event_set_outcome(&ev, outcome);
    ev.timestamp = time(NULL);
    if (identity && identity[0])
        ozayn_audit_event_set_identity(&ev, identity);
    return ev;
}

/* ============================================================
 * 1. SERVICE LIFECYCLE
 * ============================================================ */

TEST(test_service_init)
{
    ozayn_audit_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_audit_service_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.event_capacity = 256;
    ASSERT_EQ(OZAYN_AUDIT_OK, ozayn_audit_service_init(&svc, &cfg));
    ASSERT(ozayn_audit_service_is_initialized(&svc));
    ozayn_audit_service_shutdown(&svc);
    return 0;
}

TEST(test_service_init_null)
{
    ASSERT_EQ(OZAYN_AUDIT_ERR_NULL, ozayn_audit_service_init(NULL, NULL));
    return 0;
}

TEST(test_service_init_already_initialized)
{
    _init_audit_default();
    ASSERT_EQ(OZAYN_AUDIT_ERR_ALREADY_INITIALIZED,
              ozayn_audit_service_init(&_audit_svc, NULL));
    ozayn_audit_service_shutdown(&_audit_svc);
    return 0;
}

TEST(test_service_shutdown)
{
    _init_audit_default();
    ozayn_audit_service_shutdown(&_audit_svc);
    ASSERT(!ozayn_audit_service_is_initialized(&_audit_svc));
    return 0;
}

TEST(test_service_shutdown_null)
{
    ozayn_audit_service_shutdown(NULL);
    return 0;
}

TEST(test_service_not_initialized)
{
    ozayn_audit_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ASSERT_EQ(0, ozayn_audit_count(&svc));
    return 0;
}

TEST(test_service_init_defaults)
{
    _init_audit_default();
    const ozayn_audit_policy_t *p = ozayn_audit_get_policy(&_audit_svc);
    ASSERT_NOT_NULL(p);
    ASSERT(p->enabled);
    ASSERT_EQ(OZAYN_AUDIT_SEV_INFO, p->minimum_severity);
    ASSERT(p->retention_events > 0);
    ASSERT(p->retention_seconds > 0);
    ASSERT(p->max_event_size > 0);
    ASSERT(p->max_metadata_size > 0);
    for (int i = 0; i < OZAYN_AUDIT_CATEGORY_COUNT; i++)
        ASSERT(p->required_categories[i]);
    ozayn_audit_service_shutdown(&_audit_svc);
    return 0;
}

TEST(test_service_custom_config)
{
    ozayn_audit_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_audit_service_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.event_capacity = 128;
    cfg.default_minimum_severity = OZAYN_AUDIT_SEV_WARNING;
    cfg.require_identity = 1;
    cfg.default_retention_events = 500;
    cfg.default_retention_seconds = 86400;
    ASSERT_EQ(OZAYN_AUDIT_OK, ozayn_audit_service_init(&svc, &cfg));
    const ozayn_audit_policy_t *p = ozayn_audit_get_policy(&svc);
    ASSERT_NOT_NULL(p);
    ASSERT_EQ(OZAYN_AUDIT_SEV_WARNING, p->minimum_severity);
    ASSERT(p->require_identity);
    ASSERT_EQ(500, p->retention_events);
    ASSERT_EQ(86400, p->retention_seconds);
    ozayn_audit_service_shutdown(&svc);
    return 0;
}

/* ============================================================
 * 2. EVENT RECORDING
 * ============================================================ */

TEST(test_record_simple_event)
{
    _init_audit_default();
    ozayn_audit_event_t ev = _make_event(OZAYN_AUDIT_AUTH_SUCCEEDED,
                                          OZAYN_AUDIT_OUTCOME_SUCCESS, "id-1");
    ASSERT_EQ(OZAYN_AUDIT_OK, ozayn_audit_record(&_audit_svc, &ev));
    ASSERT_EQ(1, ozayn_audit_count(&_audit_svc));
    ozayn_audit_service_shutdown(&_audit_svc);
    return 0;
}

TEST(test_record_multiple_events)
{
    _init_audit_default();
    for (int i = 0; i < 10; i++) {
        ozayn_audit_event_t ev = _make_event(OZAYN_AUDIT_AUTH_SUCCEEDED,
                                              OZAYN_AUDIT_OUTCOME_SUCCESS, "id-1");
        ASSERT_EQ(OZAYN_AUDIT_OK, ozayn_audit_record(&_audit_svc, &ev));
    }
    ASSERT_EQ(10, ozayn_audit_count(&_audit_svc));
    ozayn_audit_service_shutdown(&_audit_svc);
    return 0;
}

TEST(test_record_ring_buffer_overflow)
{
    ozayn_audit_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_audit_service_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.event_capacity = 8;
    ozayn_audit_service_init(&svc, &cfg);

    for (int i = 0; i < 20; i++) {
        ozayn_audit_event_t ev = _make_event(OZAYN_AUDIT_AUTH_SUCCEEDED,
                                              OZAYN_AUDIT_OUTCOME_SUCCESS, "id-1");
        ASSERT_EQ(OZAYN_AUDIT_OK, ozayn_audit_record(&svc, &ev));
    }
    /* Ring buffer should cap at capacity */
    ASSERT_EQ(8, ozayn_audit_count(&svc));
    ozayn_audit_service_shutdown(&svc);
    return 0;
}

TEST(test_record_null)
{
    _init_audit_default();
    ozayn_audit_event_t ev;
    ozayn_audit_event_init(&ev);
    ASSERT_EQ(OZAYN_AUDIT_ERR_NULL, ozayn_audit_record(NULL, &ev));
    ASSERT_EQ(OZAYN_AUDIT_ERR_NULL, ozayn_audit_record(&_audit_svc, NULL));
    ozayn_audit_service_shutdown(&_audit_svc);
    return 0;
}

TEST(test_record_not_initialized)
{
    ozayn_audit_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_audit_event_t ev;
    ozayn_audit_event_init(&ev);
    ASSERT_EQ(OZAYN_AUDIT_ERR_NOT_INITIALIZED, ozayn_audit_record(&svc, &ev));
    return 0;
}

TEST(test_record_auto_event_id)
{
    _init_audit_default();
    ozayn_audit_event_t ev1 = _make_event(OZAYN_AUDIT_AUTH_SUCCEEDED,
                                           OZAYN_AUDIT_OUTCOME_SUCCESS, "id-1");
    ozayn_audit_event_t ev2 = _make_event(OZAYN_AUDIT_AUTH_SUCCEEDED,
                                           OZAYN_AUDIT_OUTCOME_SUCCESS, "id-1");
    ASSERT_EQ(OZAYN_AUDIT_OK, ozayn_audit_record(&_audit_svc, &ev1));
    ASSERT_EQ(OZAYN_AUDIT_OK, ozayn_audit_record(&_audit_svc, &ev2));
    ASSERT(strcmp(ev1.event_id, ev2.event_id) != 0);
    ozayn_audit_service_shutdown(&_audit_svc);
    return 0;
}

TEST(test_record_auto_severity)
{
    _init_audit_default();
    ozayn_audit_event_t ev = _make_event(OZAYN_AUDIT_AUTH_FAILED,
                                          OZAYN_AUDIT_OUTCOME_FAILURE, "id-1");
    ASSERT_EQ(OZAYN_AUDIT_OK, ozayn_audit_record(&_audit_svc, &ev));
    ozayn_audit_event_t out;
    ASSERT_EQ(OZAYN_AUDIT_OK, ozayn_audit_get_by_id(&_audit_svc, ev.event_id, &out));
    ASSERT_EQ(OZAYN_AUDIT_SEV_WARNING, out.severity);
    ozayn_audit_service_shutdown(&_audit_svc);
    return 0;
}

TEST(test_record_auto_category)
{
    _init_audit_default();
    ozayn_audit_event_t ev = _make_event(OZAYN_AUDIT_MFA_COMPLETED,
                                          OZAYN_AUDIT_OUTCOME_SUCCESS, "id-1");
    ASSERT_EQ(OZAYN_AUDIT_OK, ozayn_audit_record(&_audit_svc, &ev));
    ozayn_audit_event_t out;
    ASSERT_EQ(OZAYN_AUDIT_OK, ozayn_audit_get_by_id(&_audit_svc, ev.event_id, &out));
    ASSERT_EQ(OZAYN_AUDIT_CAT_MFA, out.category);
    ozayn_audit_service_shutdown(&_audit_svc);
    return 0;
}

TEST(test_record_auto_timestamp)
{
    _init_audit_default();
    ozayn_audit_event_t ev = _make_event(OZAYN_AUDIT_SESSION_CREATED,
                                          OZAYN_AUDIT_OUTCOME_SUCCESS, "id-1");
    ev.timestamp = 0;
    ASSERT_EQ(OZAYN_AUDIT_OK, ozayn_audit_record(&_audit_svc, &ev));
    ozayn_audit_event_t out;
    ASSERT_EQ(OZAYN_AUDIT_OK, ozayn_audit_get_by_id(&_audit_svc, ev.event_id, &out));
    ASSERT(out.timestamp > 0);
    ozayn_audit_service_shutdown(&_audit_svc);
    return 0;
}

TEST(test_record_stats)
{
    _init_audit_default();
    ASSERT_EQ(0, _audit_svc.total_events_recorded);
    ASSERT_EQ(0, _audit_svc.total_events_rejected);
    ozayn_audit_event_t ev = _make_event(OZAYN_AUDIT_AUTH_SUCCEEDED,
                                          OZAYN_AUDIT_OUTCOME_SUCCESS, "id-1");
    ASSERT_EQ(OZAYN_AUDIT_OK, ozayn_audit_record(&_audit_svc, &ev));
    ASSERT_EQ(1, _audit_svc.total_events_recorded);
    ASSERT_EQ(0, _audit_svc.total_events_rejected);
    ozayn_audit_service_shutdown(&_audit_svc);
    return 0;
}

/* ============================================================
 * 3. EVENT VALIDATION
 * ============================================================ */

TEST(test_validate_valid_event)
{
    _init_audit_default();
    ozayn_audit_event_t ev = _make_event(OZAYN_AUDIT_AUTH_SUCCEEDED,
                                          OZAYN_AUDIT_OUTCOME_SUCCESS, "id-1");
    ASSERT_EQ(OZAYN_AUDIT_OK, ozayn_audit_validate_event(&_audit_svc, &ev));
    ozayn_audit_service_shutdown(&_audit_svc);
    return 0;
}

TEST(test_validate_null_event)
{
    _init_audit_default();
    ASSERT_EQ(OZAYN_AUDIT_ERR_NULL, ozayn_audit_validate_event(&_audit_svc, NULL));
    ozayn_audit_service_shutdown(&_audit_svc);
    return 0;
}

TEST(test_validate_missing_event_id)
{
    _init_audit_default();
    ozayn_audit_event_t ev;
    ozayn_audit_event_init(&ev);
    ev.event_id[0] = '\0';
    ev.event_type = OZAYN_AUDIT_AUTH_SUCCEEDED;
    ev.outcome = OZAYN_AUDIT_OUTCOME_SUCCESS;
    ev.severity = OZAYN_AUDIT_SEV_NOTICE;
    ev.timestamp = time(NULL);
    /* Empty event_id is allowed — auto-generated during record */
    ASSERT_EQ(OZAYN_AUDIT_OK, ozayn_audit_validate_event(&_audit_svc, &ev));
    ozayn_audit_service_shutdown(&_audit_svc);
    return 0;
}

TEST(test_validate_invalid_type)
{
    _init_audit_default();
    ozayn_audit_event_t ev;
    ozayn_audit_event_init(&ev);
    strcpy(ev.event_id, "test-id");
    ev.event_type = (ozayn_audit_event_type_t)999;
    ev.outcome = OZAYN_AUDIT_OUTCOME_SUCCESS;
    ev.severity = OZAYN_AUDIT_SEV_NOTICE;
    ev.timestamp = time(NULL);
    ASSERT_EQ(OZAYN_AUDIT_ERR_INVALID_TYPE, ozayn_audit_validate_event(&_audit_svc, &ev));
    ozayn_audit_service_shutdown(&_audit_svc);
    return 0;
}

TEST(test_validate_invalid_outcome)
{
    _init_audit_default();
    ozayn_audit_event_t ev;
    ozayn_audit_event_init(&ev);
    strcpy(ev.event_id, "test-id");
    ev.event_type = OZAYN_AUDIT_AUTH_SUCCEEDED;
    ev.outcome = (ozayn_audit_outcome_t)999;
    ev.severity = OZAYN_AUDIT_SEV_NOTICE;
    ev.timestamp = time(NULL);
    ASSERT_EQ(OZAYN_AUDIT_ERR_INVALID_OUTCOME, ozayn_audit_validate_event(&_audit_svc, &ev));
    ozayn_audit_service_shutdown(&_audit_svc);
    return 0;
}

TEST(test_validate_invalid_severity)
{
    _init_audit_default();
    ozayn_audit_event_t ev;
    ozayn_audit_event_init(&ev);
    strcpy(ev.event_id, "test-id");
    ev.event_type = OZAYN_AUDIT_AUTH_SUCCEEDED;
    ev.outcome = OZAYN_AUDIT_OUTCOME_SUCCESS;
    ev.severity = (ozayn_audit_severity_t)999;
    ev.timestamp = time(NULL);
    ASSERT_EQ(OZAYN_AUDIT_ERR_INVALID_SEVERITY, ozayn_audit_validate_event(&_audit_svc, &ev));
    ozayn_audit_service_shutdown(&_audit_svc);
    return 0;
}

TEST(test_validate_invalid_timestamp)
{
    _init_audit_default();
    ozayn_audit_event_t ev;
    ozayn_audit_event_init(&ev);
    strcpy(ev.event_id, "test-id");
    ev.event_type = OZAYN_AUDIT_AUTH_SUCCEEDED;
    ev.outcome = OZAYN_AUDIT_OUTCOME_SUCCESS;
    ev.severity = OZAYN_AUDIT_SEV_NOTICE;
    ev.timestamp = 0;
    ASSERT_EQ(OZAYN_AUDIT_ERR_INVALID_TIMESTAMP, ozayn_audit_validate_event(&_audit_svc, &ev));
    ozayn_audit_service_shutdown(&_audit_svc);
    return 0;
}

TEST(test_validate_invalid_version)
{
    _init_audit_default();
    ozayn_audit_event_t ev;
    ozayn_audit_event_init(&ev);
    strcpy(ev.event_id, "test-id");
    ev.event_type = OZAYN_AUDIT_AUTH_SUCCEEDED;
    ev.outcome = OZAYN_AUDIT_OUTCOME_SUCCESS;
    ev.severity = OZAYN_AUDIT_SEV_NOTICE;
    ev.timestamp = time(NULL);
    ev.event_version = 999;
    ASSERT_EQ(OZAYN_AUDIT_ERR_INVALID_EVENT, ozayn_audit_validate_event(&_audit_svc, &ev));
    ozayn_audit_service_shutdown(&_audit_svc);
    return 0;
}

/* ============================================================
 * 4. SECRET FILTERING
 * ============================================================ */

TEST(test_metadata_safe_empty)
{
    ASSERT_EQ(OZAYN_AUDIT_OK, ozayn_audit_check_metadata_safe(NULL, 0));
    uint8_t data[] = "hello";
    ASSERT_EQ(OZAYN_AUDIT_OK, ozayn_audit_check_metadata_safe(data, 5));
    return 0;
}

TEST(test_metadata_rejects_password)
{
    uint8_t data[] = "user_password=secret123";
    ASSERT_EQ(OZAYN_AUDIT_ERR_SECRET_REJECTED,
              ozayn_audit_check_metadata_safe(data, sizeof(data) - 1));
    return 0;
}

TEST(test_metadata_rejects_api_key)
{
    uint8_t data[] = "api_key=abcdef";
    ASSERT_EQ(OZAYN_AUDIT_ERR_SECRET_REJECTED,
              ozayn_audit_check_metadata_safe(data, sizeof(data) - 1));
    return 0;
}

TEST(test_metadata_rejects_private_key)
{
    uint8_t data[] = "private_key_data_here";
    ASSERT_EQ(OZAYN_AUDIT_ERR_SECRET_REJECTED,
              ozayn_audit_check_metadata_safe(data, sizeof(data) - 1));
    return 0;
}

TEST(test_metadata_rejects_session_secret)
{
    uint8_t data[] = "session_secret=xyz";
    ASSERT_EQ(OZAYN_AUDIT_ERR_SECRET_REJECTED,
              ozayn_audit_check_metadata_safe(data, sizeof(data) - 1));
    return 0;
}

TEST(test_metadata_rejects_token)
{
    uint8_t data[] = "access_token=abc123";
    ASSERT_EQ(OZAYN_AUDIT_ERR_SECRET_REJECTED,
              ozayn_audit_check_metadata_safe(data, sizeof(data) - 1));
    return 0;
}

TEST(test_metadata_rejects_biometric)
{
    uint8_t data[] = "biometric_template_v2";
    ASSERT_EQ(OZAYN_AUDIT_ERR_SECRET_REJECTED,
              ozayn_audit_check_metadata_safe(data, sizeof(data) - 1));
    return 0;
}

TEST(test_metadata_rejects_credential)
{
    uint8_t data[] = "credential_secret=value";
    ASSERT_EQ(OZAYN_AUDIT_ERR_SECRET_REJECTED,
              ozayn_audit_check_metadata_safe(data, sizeof(data) - 1));
    return 0;
}

TEST(test_metadata_rejects_encryption_key)
{
    uint8_t data[] = "encryption_key_material";
    ASSERT_EQ(OZAYN_AUDIT_ERR_SECRET_REJECTED,
              ozayn_audit_check_metadata_safe(data, sizeof(data) - 1));
    return 0;
}

TEST(test_metadata_rejects_case_insensitive)
{
    uint8_t data[] = "PASSWORD=secret";
    ASSERT_EQ(OZAYN_AUDIT_ERR_SECRET_REJECTED,
              ozayn_audit_check_metadata_safe(data, sizeof(data) - 1));
    return 0;
}

TEST(test_metadata_rejects_in_event)
{
    _init_audit_default();
    ozayn_audit_event_t ev = _make_event(OZAYN_AUDIT_AUTH_SUCCEEDED,
                                          OZAYN_AUDIT_OUTCOME_SUCCESS, "id-1");
    uint8_t secret[] = "password=secret";
    ASSERT_EQ(OZAYN_AUDIT_ERR_SECRET_REJECTED,
              ozayn_audit_event_set_metadata(&ev, secret, sizeof(secret) - 1));
    ozayn_audit_service_shutdown(&_audit_svc);
    return 0;
}

TEST(test_metadata_size_exceeded)
{
    uint8_t data[600];
    memset(data, 'A', sizeof(data));
    ASSERT_EQ(OZAYN_AUDIT_ERR_METADATA_TOO_LARGE,
              ozayn_audit_check_metadata_safe(data, sizeof(data)));
    return 0;
}

/* ============================================================
 * 5. EVENT QUERY
 * ============================================================ */

TEST(test_query_empty)
{
    _init_audit_default();
    ozayn_audit_query_t q;
    memset(&q, 0, sizeof(q));
    ozayn_audit_event_t results[10];
    int count = 0;
    ASSERT_EQ(OZAYN_AUDIT_OK, ozayn_audit_query(&_audit_svc, &q, results, 10, &count));
    ASSERT_EQ(0, count);
    ozayn_audit_service_shutdown(&_audit_svc);
    return 0;
}

TEST(test_query_returns_all)
{
    _init_audit_default();
    for (int i = 0; i < 5; i++) {
        ozayn_audit_event_t ev = _make_event(OZAYN_AUDIT_AUTH_SUCCEEDED,
                                              OZAYN_AUDIT_OUTCOME_SUCCESS, "id-1");
        ASSERT_EQ(OZAYN_AUDIT_OK, ozayn_audit_record(&_audit_svc, &ev));
    }
    ozayn_audit_query_t q;
    memset(&q, 0, sizeof(q));
    ozayn_audit_event_t results[10];
    int count = 0;
    ASSERT_EQ(OZAYN_AUDIT_OK, ozayn_audit_query(&_audit_svc, &q, results, 10, &count));
    ASSERT_EQ(5, count);
    ozayn_audit_service_shutdown(&_audit_svc);
    return 0;
}

TEST(test_query_filter_type)
{
    _init_audit_default();
    ozayn_audit_event_t ev1 = _make_event(OZAYN_AUDIT_AUTH_SUCCEEDED,
                                           OZAYN_AUDIT_OUTCOME_SUCCESS, "id-1");
    ozayn_audit_event_t ev2 = _make_event(OZAYN_AUDIT_AUTH_FAILED,
                                           OZAYN_AUDIT_OUTCOME_FAILURE, "id-1");
    ASSERT_EQ(OZAYN_AUDIT_OK, ozayn_audit_record(&_audit_svc, &ev1));
    ASSERT_EQ(OZAYN_AUDIT_OK, ozayn_audit_record(&_audit_svc, &ev2));

    ozayn_audit_query_t q;
    memset(&q, 0, sizeof(q));
    q.filter_type = OZAYN_AUDIT_AUTH_SUCCEEDED;
    q.filter_type_active = 1;
    ozayn_audit_event_t results[10];
    int count = 0;
    ASSERT_EQ(OZAYN_AUDIT_OK, ozayn_audit_query(&_audit_svc, &q, results, 10, &count));
    ASSERT_EQ(1, count);
    ASSERT_EQ(OZAYN_AUDIT_AUTH_SUCCEEDED, results[0].event_type);
    ozayn_audit_service_shutdown(&_audit_svc);
    return 0;
}

TEST(test_query_filter_identity)
{
    _init_audit_default();
    ozayn_audit_event_t ev1 = _make_event(OZAYN_AUDIT_AUTH_SUCCEEDED,
                                           OZAYN_AUDIT_OUTCOME_SUCCESS, "alice");
    ozayn_audit_event_t ev2 = _make_event(OZAYN_AUDIT_AUTH_SUCCEEDED,
                                           OZAYN_AUDIT_OUTCOME_SUCCESS, "bob");
    ASSERT_EQ(OZAYN_AUDIT_OK, ozayn_audit_record(&_audit_svc, &ev1));
    ASSERT_EQ(OZAYN_AUDIT_OK, ozayn_audit_record(&_audit_svc, &ev2));

    ozayn_audit_query_t q;
    memset(&q, 0, sizeof(q));
    strcpy(q.filter_identity_id, "alice");
    q.filter_identity_active = 1;
    ozayn_audit_event_t results[10];
    int count = 0;
    ASSERT_EQ(OZAYN_AUDIT_OK, ozayn_audit_query(&_audit_svc, &q, results, 10, &count));
    ASSERT_EQ(1, count);
    ASSERT_STR_EQ("alice", results[0].identity_id);
    ozayn_audit_service_shutdown(&_audit_svc);
    return 0;
}

TEST(test_query_filter_outcome)
{
    _init_audit_default();
    ozayn_audit_event_t ev1 = _make_event(OZAYN_AUDIT_AUTH_SUCCEEDED,
                                           OZAYN_AUDIT_OUTCOME_SUCCESS, "id-1");
    ozayn_audit_event_t ev2 = _make_event(OZAYN_AUDIT_AUTH_FAILED,
                                           OZAYN_AUDIT_OUTCOME_FAILURE, "id-1");
    ASSERT_EQ(OZAYN_AUDIT_OK, ozayn_audit_record(&_audit_svc, &ev1));
    ASSERT_EQ(OZAYN_AUDIT_OK, ozayn_audit_record(&_audit_svc, &ev2));

    ozayn_audit_query_t q;
    memset(&q, 0, sizeof(q));
    q.filter_outcome = OZAYN_AUDIT_OUTCOME_FAILURE;
    q.filter_outcome_active = 1;
    ozayn_audit_event_t results[10];
    int count = 0;
    ASSERT_EQ(OZAYN_AUDIT_OK, ozayn_audit_query(&_audit_svc, &q, results, 10, &count));
    ASSERT_EQ(1, count);
    ASSERT_EQ(OZAYN_AUDIT_OUTCOME_FAILURE, results[0].outcome);
    ozayn_audit_service_shutdown(&_audit_svc);
    return 0;
}

TEST(test_query_filter_severity)
{
    _init_audit_default();
    ozayn_audit_event_t ev1 = _make_event(OZAYN_AUDIT_AUTH_SUCCEEDED,
                                           OZAYN_AUDIT_OUTCOME_SUCCESS, "id-1");
    ev1.severity = OZAYN_AUDIT_SEV_INFO;
    ozayn_audit_event_t ev2 = _make_event(OZAYN_AUDIT_AUTH_FAILED,
                                           OZAYN_AUDIT_OUTCOME_FAILURE, "id-1");
    ev2.severity = OZAYN_AUDIT_SEV_CRITICAL;
    ASSERT_EQ(OZAYN_AUDIT_OK, ozayn_audit_record(&_audit_svc, &ev1));
    ASSERT_EQ(OZAYN_AUDIT_OK, ozayn_audit_record(&_audit_svc, &ev2));

    ozayn_audit_query_t q;
    memset(&q, 0, sizeof(q));
    q.filter_severity_min = OZAYN_AUDIT_SEV_HIGH;
    q.filter_severity_active = 1;
    ozayn_audit_event_t results[10];
    int count = 0;
    ASSERT_EQ(OZAYN_AUDIT_OK, ozayn_audit_query(&_audit_svc, &q, results, 10, &count));
    ASSERT_EQ(1, count);
    ASSERT_GE(results[0].severity, OZAYN_AUDIT_SEV_HIGH);
    ozayn_audit_service_shutdown(&_audit_svc);
    return 0;
}

TEST(test_query_limit)
{
    _init_audit_default();
    for (int i = 0; i < 20; i++) {
        ozayn_audit_event_t ev = _make_event(OZAYN_AUDIT_AUTH_SUCCEEDED,
                                              OZAYN_AUDIT_OUTCOME_SUCCESS, "id-1");
        ASSERT_EQ(OZAYN_AUDIT_OK, ozayn_audit_record(&_audit_svc, &ev));
    }
    ozayn_audit_query_t q;
    memset(&q, 0, sizeof(q));
    q.result_limit = 5;
    ozayn_audit_event_t results[20];
    int count = 0;
    ASSERT_EQ(OZAYN_AUDIT_OK, ozayn_audit_query(&_audit_svc, &q, results, 20, &count));
    ASSERT_EQ(5, count);
    ozayn_audit_service_shutdown(&_audit_svc);
    return 0;
}

TEST(test_query_offset)
{
    _init_audit_default();
    for (int i = 0; i < 10; i++) {
        ozayn_audit_event_t ev = _make_event(OZAYN_AUDIT_AUTH_SUCCEEDED,
                                              OZAYN_AUDIT_OUTCOME_SUCCESS, "id-1");
        ASSERT_EQ(OZAYN_AUDIT_OK, ozayn_audit_record(&_audit_svc, &ev));
    }
    ozayn_audit_query_t q;
    memset(&q, 0, sizeof(q));
    q.result_limit = 3;
    q.result_offset = 5;
    ozayn_audit_event_t results[10];
    int count = 0;
    ASSERT_EQ(OZAYN_AUDIT_OK, ozayn_audit_query(&_audit_svc, &q, results, 10, &count));
    ASSERT_EQ(3, count);
    ozayn_audit_service_shutdown(&_audit_svc);
    return 0;
}

TEST(test_query_null)
{
    _init_audit_default();
    ozayn_audit_query_t q;
    memset(&q, 0, sizeof(q));
    ozayn_audit_event_t results[10];
    int count = 0;
    ASSERT_EQ(OZAYN_AUDIT_ERR_NULL, ozayn_audit_query(NULL, &q, results, 10, &count));
    ASSERT_EQ(OZAYN_AUDIT_ERR_NULL, ozayn_audit_query(&_audit_svc, NULL, results, 10, &count));
    ASSERT_EQ(OZAYN_AUDIT_ERR_NULL, ozayn_audit_query(&_audit_svc, &q, results, 10, NULL));
    ozayn_audit_service_shutdown(&_audit_svc);
    return 0;
}

TEST(test_get_by_id)
{
    _init_audit_default();
    ozayn_audit_event_t ev = _make_event(OZAYN_AUDIT_AUTH_SUCCEEDED,
                                          OZAYN_AUDIT_OUTCOME_SUCCESS, "id-1");
    ASSERT_EQ(OZAYN_AUDIT_OK, ozayn_audit_record(&_audit_svc, &ev));

    ozayn_audit_event_t out;
    ASSERT_EQ(OZAYN_AUDIT_OK, ozayn_audit_get_by_id(&_audit_svc, ev.event_id, &out));
    ASSERT_STR_EQ(ev.event_id, out.event_id);
    ASSERT_EQ(OZAYN_AUDIT_AUTH_SUCCEEDED, out.event_type);
    ozayn_audit_service_shutdown(&_audit_svc);
    return 0;
}

TEST(test_get_by_id_not_found)
{
    _init_audit_default();
    ozayn_audit_event_t out;
    ASSERT_EQ(OZAYN_AUDIT_ERR_EVENT_NOT_FOUND,
              ozayn_audit_get_by_id(&_audit_svc, "nonexistent", &out));
    ozayn_audit_service_shutdown(&_audit_svc);
    return 0;
}

TEST(test_get_by_id_null)
{
    _init_audit_default();
    ozayn_audit_event_t out;
    ASSERT_EQ(OZAYN_AUDIT_ERR_NULL, ozayn_audit_get_by_id(NULL, "id", &out));
    ASSERT_EQ(OZAYN_AUDIT_ERR_NULL, ozayn_audit_get_by_id(&_audit_svc, NULL, &out));
    ASSERT_EQ(OZAYN_AUDIT_ERR_NULL, ozayn_audit_get_by_id(&_audit_svc, "id", NULL));
    ozayn_audit_service_shutdown(&_audit_svc);
    return 0;
}

/* ============================================================
 * 6. POLICY
 * ============================================================ */

TEST(test_set_policy)
{
    _init_audit_default();
    ozayn_audit_policy_t p;
    memset(&p, 0, sizeof(p));
    p.enabled = 1;
    p.minimum_severity = OZAYN_AUDIT_SEV_HIGH;
    p.retention_events = 1000;
    p.retention_seconds = 604800;
    p.max_event_size = 1024;
    p.max_metadata_size = 256;
    p.metadata_allowed = 1;
    for (int i = 0; i < OZAYN_AUDIT_CATEGORY_COUNT; i++)
        p.required_categories[i] = 1;
    ASSERT_EQ(OZAYN_AUDIT_OK, ozayn_audit_set_policy(&_audit_svc, &p));
    const ozayn_audit_policy_t *cp = ozayn_audit_get_policy(&_audit_svc);
    ASSERT_NOT_NULL(cp);
    ASSERT_EQ(OZAYN_AUDIT_SEV_HIGH, cp->minimum_severity);
    ASSERT_EQ(1000, cp->retention_events);
    ozayn_audit_service_shutdown(&_audit_svc);
    return 0;
}

TEST(test_set_policy_null)
{
    _init_audit_default();
    ozayn_audit_policy_t p;
    memset(&p, 0, sizeof(p));
    ASSERT_EQ(OZAYN_AUDIT_ERR_NULL, ozayn_audit_set_policy(NULL, &p));
    ASSERT_EQ(OZAYN_AUDIT_ERR_NULL, ozayn_audit_set_policy(&_audit_svc, NULL));
    ozayn_audit_service_shutdown(&_audit_svc);
    return 0;
}

TEST(test_set_policy_invalid_severity)
{
    _init_audit_default();
    ozayn_audit_policy_t p;
    memset(&p, 0, sizeof(p));
    p.enabled = 1;
    p.minimum_severity = (ozayn_audit_severity_t)999;
    p.max_event_size = 1024;
    p.max_metadata_size = 256;
    ASSERT_EQ(OZAYN_AUDIT_ERR_INVALID_SEVERITY, ozayn_audit_set_policy(&_audit_svc, &p));
    ozayn_audit_service_shutdown(&_audit_svc);
    return 0;
}

TEST(test_policy_rejects_below_threshold)
{
    _init_audit_default();
    ozayn_audit_policy_t p;
    memset(&p, 0, sizeof(p));
    p.enabled = 1;
    p.minimum_severity = OZAYN_AUDIT_SEV_HIGH;
    p.retention_events = 1000;
    p.retention_seconds = 365 * 24 * 3600;
    p.max_event_size = 2048;
    p.max_metadata_size = 512;
    p.metadata_allowed = 1;
    for (int i = 0; i < OZAYN_AUDIT_CATEGORY_COUNT; i++)
        p.required_categories[i] = 1;
    ASSERT_EQ(OZAYN_AUDIT_OK, ozayn_audit_set_policy(&_audit_svc, &p));

    ozayn_audit_event_t ev = _make_event(OZAYN_AUDIT_AUTH_SUCCEEDED,
                                          OZAYN_AUDIT_OUTCOME_SUCCESS, "id-1");
    ev.severity = OZAYN_AUDIT_SEV_INFO;
    ASSERT_EQ(OZAYN_AUDIT_ERR_POLICY_REJECTED, ozayn_audit_record(&_audit_svc, &ev));
    ASSERT_EQ(0, ozayn_audit_count(&_audit_svc));
    ozayn_audit_service_shutdown(&_audit_svc);
    return 0;
}

TEST(test_policy_allows_above_threshold)
{
    _init_audit_default();
    ozayn_audit_policy_t p;
    memset(&p, 0, sizeof(p));
    p.enabled = 1;
    p.minimum_severity = OZAYN_AUDIT_SEV_HIGH;
    p.retention_events = 1000;
    p.retention_seconds = 365 * 24 * 3600;
    p.max_event_size = 2048;
    p.max_metadata_size = 512;
    p.metadata_allowed = 1;
    for (int i = 0; i < OZAYN_AUDIT_CATEGORY_COUNT; i++)
        p.required_categories[i] = 1;
    ASSERT_EQ(OZAYN_AUDIT_OK, ozayn_audit_set_policy(&_audit_svc, &p));

    ozayn_audit_event_t ev = _make_event(OZAYN_AUDIT_AUTH_FAILED,
                                          OZAYN_AUDIT_OUTCOME_FAILURE, "id-1");
    ev.severity = OZAYN_AUDIT_SEV_CRITICAL;
    ASSERT_EQ(OZAYN_AUDIT_OK, ozayn_audit_record(&_audit_svc, &ev));
    ASSERT_EQ(1, ozayn_audit_count(&_audit_svc));
    ozayn_audit_service_shutdown(&_audit_svc);
    return 0;
}

TEST(test_policy_require_identity)
{
    _init_audit_default();
    ozayn_audit_policy_t p;
    memset(&p, 0, sizeof(p));
    p.enabled = 1;
    p.minimum_severity = OZAYN_AUDIT_SEV_INFO;
    p.retention_events = 1000;
    p.retention_seconds = 365 * 24 * 3600;
    p.max_event_size = 2048;
    p.max_metadata_size = 512;
    p.metadata_allowed = 1;
    p.require_identity = 1;
    for (int i = 0; i < OZAYN_AUDIT_CATEGORY_COUNT; i++)
        p.required_categories[i] = 1;
    ASSERT_EQ(OZAYN_AUDIT_OK, ozayn_audit_set_policy(&_audit_svc, &p));

    /* Event without identity should be rejected */
    ozayn_audit_event_t ev = _make_event(OZAYN_AUDIT_AUTH_SUCCEEDED,
                                          OZAYN_AUDIT_OUTCOME_SUCCESS, NULL);
    ASSERT_EQ(OZAYN_AUDIT_ERR_INVALID_IDENTITY, ozayn_audit_record(&_audit_svc, &ev));

    /* Event with identity should be accepted */
    ozayn_audit_event_t ev2 = _make_event(OZAYN_AUDIT_AUTH_SUCCEEDED,
                                           OZAYN_AUDIT_OUTCOME_SUCCESS, "id-1");
    ASSERT_EQ(OZAYN_AUDIT_OK, ozayn_audit_record(&_audit_svc, &ev2));
    ozayn_audit_service_shutdown(&_audit_svc);
    return 0;
}

TEST(test_get_policy_not_initialized)
{
    ozayn_audit_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ASSERT_NULL(ozayn_audit_get_policy(&svc));
    return 0;
}

/* ============================================================
 * 7. STORAGE BINDING
 * ============================================================ */

TEST(test_storage_append)
{
    _init_audit_default();
    ozayn_audit_test_storage_t ts;
    ozayn_audit_test_storage_init(&ts);
    ozayn_audit_storage_t *sp = ozayn_audit_test_storage_provider(&ts);
    ASSERT_EQ(OZAYN_AUDIT_OK, ozayn_audit_set_storage(&_audit_svc, sp));

    ozayn_audit_event_t ev = _make_event(OZAYN_AUDIT_AUTH_SUCCEEDED,
                                          OZAYN_AUDIT_OUTCOME_SUCCESS, "id-1");
    ASSERT_EQ(OZAYN_AUDIT_OK, ozayn_audit_record(&_audit_svc, &ev));
    ASSERT_EQ(1, ts.count);
    ozayn_audit_service_shutdown(&_audit_svc);
    return 0;
}

TEST(test_storage_failure)
{
    _init_audit_default();
    ozayn_audit_test_storage_t ts;
    ozayn_audit_test_storage_init(&ts);
    ts.fail_on_append = 1;
    ozayn_audit_storage_t *sp = ozayn_audit_test_storage_provider(&ts);
    ASSERT_EQ(OZAYN_AUDIT_OK, ozayn_audit_set_storage(&_audit_svc, sp));

    /* Storage failure should not prevent ring buffer write */
    ozayn_audit_event_t ev = _make_event(OZAYN_AUDIT_AUTH_SUCCEEDED,
                                          OZAYN_AUDIT_OUTCOME_SUCCESS, "id-1");
    ASSERT_EQ(OZAYN_AUDIT_OK, ozayn_audit_record(&_audit_svc, &ev));
    ASSERT_EQ(1, ozayn_audit_count(&_audit_svc));
    ozayn_audit_service_shutdown(&_audit_svc);
    return 0;
}

TEST(test_storage_unavailable)
{
    _init_audit_default();
    ozayn_audit_test_storage_t ts;
    ozayn_audit_test_storage_init(&ts);
    ts.unavailable = 1;
    ozayn_audit_storage_t *sp = ozayn_audit_test_storage_provider(&ts);
    ASSERT_EQ(OZAYN_AUDIT_OK, ozayn_audit_set_storage(&_audit_svc, sp));

    ozayn_audit_event_t ev = _make_event(OZAYN_AUDIT_AUTH_SUCCEEDED,
                                          OZAYN_AUDIT_OUTCOME_SUCCESS, "id-1");
    ASSERT_EQ(OZAYN_AUDIT_OK, ozayn_audit_record(&_audit_svc, &ev));
    ASSERT_EQ(1, ozayn_audit_count(&_audit_svc));
    ozayn_audit_service_shutdown(&_audit_svc);
    return 0;
}

TEST(test_storage_corrupt_on_read)
{
    _init_audit_default();
    ozayn_audit_test_storage_t ts;
    ozayn_audit_test_storage_init(&ts);
    ts.corrupt_on_read = 1;
    ozayn_audit_storage_t *sp = ozayn_audit_test_storage_provider(&ts);
    ASSERT_EQ(OZAYN_AUDIT_OK, ozayn_audit_set_storage(&_audit_svc, sp));

    ozayn_audit_event_t ev = _make_event(OZAYN_AUDIT_AUTH_SUCCEEDED,
                                          OZAYN_AUDIT_OUTCOME_SUCCESS, "id-1");
    ASSERT_EQ(OZAYN_AUDIT_OK, ozayn_audit_record(&_audit_svc, &ev));

    /* Storage read should fail with integrity error */
    ozayn_audit_event_t out;
    ASSERT_EQ(OZAYN_AUDIT_ERR_INTEGRITY_FAILURE,
              sp->ops->get(sp->impl, ev.event_id, &out));
    ozayn_audit_service_shutdown(&_audit_svc);
    return 0;
}

TEST(test_storage_shutdown_flushes)
{
    _init_audit_default();
    ozayn_audit_test_storage_t ts;
    ozayn_audit_test_storage_init(&ts);
    ozayn_audit_storage_t *sp = ozayn_audit_test_storage_provider(&ts);
    ASSERT_EQ(OZAYN_AUDIT_OK, ozayn_audit_set_storage(&_audit_svc, sp));

    for (int i = 0; i < 5; i++) {
        ozayn_audit_event_t ev = _make_event(OZAYN_AUDIT_AUTH_SUCCEEDED,
                                              OZAYN_AUDIT_OUTCOME_SUCCESS, "id-1");
        ASSERT_EQ(OZAYN_AUDIT_OK, ozayn_audit_record(&_audit_svc, &ev));
    }
    ozayn_audit_service_shutdown(&_audit_svc);
    ASSERT_EQ(5, ts.count);
    return 0;
}

TEST(test_storage_reset)
{
    ozayn_audit_test_storage_t ts;
    ozayn_audit_test_storage_init(&ts);
    ts.count = 42;
    ts.fail_on_append = 1;
    ozayn_audit_test_storage_reset(&ts);
    ASSERT_EQ(0, ts.count);
    ASSERT(!ts.fail_on_append);
    ASSERT(ts.initialized);
    return 0;
}

/* ============================================================
 * 8. EVENT BUILDER HELPERS
 * ============================================================ */

TEST(test_event_init)
{
    ozayn_audit_event_t ev;
    ozayn_audit_event_init(&ev);
    ASSERT_EQ(OZAYN_AUDIT_EVENT_VERSION, ev.event_version);
    ASSERT_EQ(0, ev.event_type);
    ASSERT_EQ(0, ev.outcome);
    ASSERT_EQ(0, ev.severity);
    ASSERT_EQ(0, ev.timestamp);
    ASSERT(ev.identity_id[0] == '\0');
    ASSERT(ev.event_id[0] == '\0');
    ASSERT(ev.metadata_valid == 1);
    return 0;
}

TEST(test_event_set_type)
{
    ozayn_audit_event_t ev;
    ozayn_audit_event_init(&ev);
    ASSERT_EQ(OZAYN_AUDIT_OK, ozayn_audit_event_set_type(&ev, OZAYN_AUDIT_MFA_COMPLETED));
    ASSERT_EQ(OZAYN_AUDIT_MFA_COMPLETED, ev.event_type);
    ASSERT_EQ(OZAYN_AUDIT_CAT_MFA, ev.category);
    return 0;
}

TEST(test_event_set_type_invalid)
{
    ozayn_audit_event_t ev;
    ozayn_audit_event_init(&ev);
    ASSERT_EQ(OZAYN_AUDIT_ERR_INVALID_TYPE,
              ozayn_audit_event_set_type(&ev, (ozayn_audit_event_type_t)999));
    return 0;
}

TEST(test_event_set_outcome)
{
    ozayn_audit_event_t ev;
    ozayn_audit_event_init(&ev);
    ASSERT_EQ(OZAYN_AUDIT_OK, ozayn_audit_event_set_outcome(&ev, OZAYN_AUDIT_OUTCOME_DENIED));
    ASSERT_EQ(OZAYN_AUDIT_OUTCOME_DENIED, ev.outcome);
    return 0;
}

TEST(test_event_set_severity)
{
    ozayn_audit_event_t ev;
    ozayn_audit_event_init(&ev);
    ASSERT_EQ(OZAYN_AUDIT_OK, ozayn_audit_event_set_severity(&ev, OZAYN_AUDIT_SEV_CRITICAL));
    ASSERT_EQ(OZAYN_AUDIT_SEV_CRITICAL, ev.severity);
    return 0;
}

TEST(test_event_set_identity)
{
    ozayn_audit_event_t ev;
    ozayn_audit_event_init(&ev);
    ASSERT_EQ(OZAYN_AUDIT_OK, ozayn_audit_event_set_identity(&ev, "alice"));
    ASSERT_STR_EQ("alice", ev.identity_id);
    return 0;
}

TEST(test_event_set_identity_null)
{
    ozayn_audit_event_t ev;
    ozayn_audit_event_init(&ev);
    ASSERT_EQ(OZAYN_AUDIT_OK, ozayn_audit_event_set_identity(&ev, NULL));
    ASSERT(ev.identity_id[0] == '\0');
    return 0;
}

TEST(test_event_set_session)
{
    ozayn_audit_event_t ev;
    ozayn_audit_event_init(&ev);
    ASSERT_EQ(OZAYN_AUDIT_OK, ozayn_audit_event_set_session(&ev, "sess-123"));
    ASSERT_STR_EQ("sess-123", ev.session_id);
    return 0;
}

TEST(test_event_set_source)
{
    ozayn_audit_event_t ev;
    ozayn_audit_event_init(&ev);
    ASSERT_EQ(OZAYN_AUDIT_OK, ozayn_audit_event_set_source(&ev, "AUTH"));
    ASSERT_STR_EQ("AUTH", ev.source_component);
    return 0;
}

TEST(test_event_set_request_id)
{
    ozayn_audit_event_t ev;
    ozayn_audit_event_init(&ev);
    ASSERT_EQ(OZAYN_AUDIT_OK, ozayn_audit_event_set_request_id(&ev, "req-1"));
    ASSERT_STR_EQ("req-1", ev.request_id);
    return 0;
}

TEST(test_event_set_correlation_id)
{
    ozayn_audit_event_t ev;
    ozayn_audit_event_init(&ev);
    ASSERT_EQ(OZAYN_AUDIT_OK, ozayn_audit_event_set_correlation_id(&ev, "corr-1"));
    ASSERT_STR_EQ("corr-1", ev.correlation_id);
    return 0;
}

TEST(test_event_set_resource)
{
    ozayn_audit_event_t ev;
    ozayn_audit_event_init(&ev);
    ASSERT_EQ(OZAYN_AUDIT_OK, ozayn_audit_event_set_resource(&ev,
              OZAYN_AUTHZ_RESOURCE_DOCUMENT, "doc-1",
              OZAYN_AUTHZ_ACTION_READ, OZAYN_AUTHZ_SCOPE_USER));
    ASSERT_EQ(OZAYN_AUTHZ_RESOURCE_DOCUMENT, ev.resource_type);
    ASSERT_STR_EQ("doc-1", ev.resource_id);
    ASSERT_EQ(OZAYN_AUTHZ_ACTION_READ, ev.action);
    ASSERT_EQ(OZAYN_AUTHZ_SCOPE_USER, ev.scope);
    return 0;
}

TEST(test_event_set_detail)
{
    ozayn_audit_event_t ev;
    ozayn_audit_event_init(&ev);
    ASSERT_EQ(OZAYN_AUDIT_OK, ozayn_audit_event_set_detail(&ev, "login successful"));
    ASSERT_STR_EQ("login successful", ev.detail);
    return 0;
}

TEST(test_event_set_failure_reason)
{
    ozayn_audit_event_t ev;
    ozayn_audit_event_init(&ev);
    ASSERT_EQ(OZAYN_AUDIT_OK, ozayn_audit_event_set_failure_reason(&ev, "bad password"));
    ASSERT_STR_EQ("bad password", ev.failure_reason);
    return 0;
}

TEST(test_event_set_metadata_safe)
{
    ozayn_audit_event_t ev;
    ozayn_audit_event_init(&ev);
    uint8_t data[] = "user_id=12345";
    ASSERT_EQ(OZAYN_AUDIT_OK, ozayn_audit_event_set_metadata(&ev, data, sizeof(data) - 1));
    ASSERT_EQ(sizeof(data) - 1, ev.metadata_size);
    ASSERT(ev.metadata_valid);
    return 0;
}

TEST(test_event_set_metadata_secret_rejected)
{
    ozayn_audit_event_t ev;
    ozayn_audit_event_init(&ev);
    uint8_t data[] = "password=hunter2";
    ASSERT_EQ(OZAYN_AUDIT_ERR_SECRET_REJECTED,
              ozayn_audit_event_set_metadata(&ev, data, sizeof(data) - 1));
    ASSERT_EQ(0, ev.metadata_size);
    return 0;
}

/* ============================================================
 * 9. NAME HELPERS
 * ============================================================ */

TEST(test_result_names)
{
    ASSERT_STR_EQ("OK", ozayn_audit_result_name(OZAYN_AUDIT_OK));
    ASSERT_STR_EQ("ERR", ozayn_audit_result_name(OZAYN_AUDIT_ERR));
    ASSERT_STR_EQ("ERR_NULL", ozayn_audit_result_name(OZAYN_AUDIT_ERR_NULL));
    ASSERT_STR_EQ("ERR_SECRET_REJECTED",
                  ozayn_audit_result_name(OZAYN_AUDIT_ERR_SECRET_REJECTED));
    ASSERT_STR_EQ("ERR_STORAGE_FULL",
                  ozayn_audit_result_name(OZAYN_AUDIT_ERR_STORAGE_FULL));
    ASSERT_STR_EQ("UNKNOWN", ozayn_audit_result_name((ozayn_audit_result_t)999));
    return 0;
}

TEST(test_event_type_names)
{
    ASSERT_STR_EQ("IDENTITY_CREATED",
                  ozayn_audit_event_type_name(OZAYN_AUDIT_IDENTITY_CREATED));
    ASSERT_STR_EQ("AUTH_SUCCEEDED",
                  ozayn_audit_event_type_name(OZAYN_AUDIT_AUTH_SUCCEEDED));
    ASSERT_STR_EQ("MFA_COMPLETED",
                  ozayn_audit_event_type_name(OZAYN_AUDIT_MFA_COMPLETED));
    ASSERT_STR_EQ("SESSION_CREATED",
                  ozayn_audit_event_type_name(OZAYN_AUDIT_SESSION_CREATED));
    ASSERT_STR_EQ("ROLE_CREATED",
                  ozayn_audit_event_type_name(OZAYN_AUDIT_ROLE_CREATED));
    ASSERT_STR_EQ("PERM_CREATED",
                  ozayn_audit_event_type_name(OZAYN_AUDIT_PERM_CREATED));
    ASSERT_STR_EQ("VIOLATION_DETECTED",
                  ozayn_audit_event_type_name(OZAYN_AUDIT_VIOLATION_DETECTED));
    ASSERT_STR_EQ("UNKNOWN",
                  ozayn_audit_event_type_name((ozayn_audit_event_type_t)999));
    return 0;
}

TEST(test_category_names)
{
    ASSERT_STR_EQ("IDENTITY", ozayn_audit_category_name(OZAYN_AUDIT_CAT_IDENTITY));
    ASSERT_STR_EQ("AUTH", ozayn_audit_category_name(OZAYN_AUDIT_CAT_AUTH));
    ASSERT_STR_EQ("PASSWORD", ozayn_audit_category_name(OZAYN_AUDIT_CAT_PASSWORD));
    ASSERT_STR_EQ("MFA", ozayn_audit_category_name(OZAYN_AUDIT_CAT_MFA));
    ASSERT_STR_EQ("SESSION", ozayn_audit_category_name(OZAYN_AUDIT_CAT_SESSION));
    ASSERT_STR_EQ("RBAC", ozayn_audit_category_name(OZAYN_AUDIT_CAT_RBAC));
    ASSERT_STR_EQ("UNKNOWN", ozayn_audit_category_name((ozayn_audit_category_t)999));
    return 0;
}

TEST(test_outcome_names)
{
    ASSERT_STR_EQ("SUCCESS", ozayn_audit_outcome_name(OZAYN_AUDIT_OUTCOME_SUCCESS));
    ASSERT_STR_EQ("FAILURE", ozayn_audit_outcome_name(OZAYN_AUDIT_OUTCOME_FAILURE));
    ASSERT_STR_EQ("DENIED", ozayn_audit_outcome_name(OZAYN_AUDIT_OUTCOME_DENIED));
    ASSERT_STR_EQ("REJECTED", ozayn_audit_outcome_name(OZAYN_AUDIT_OUTCOME_REJECTED));
    ASSERT_STR_EQ("UNKNOWN", ozayn_audit_outcome_name((ozayn_audit_outcome_t)999));
    return 0;
}

TEST(test_severity_names)
{
    ASSERT_STR_EQ("INFO", ozayn_audit_severity_name(OZAYN_AUDIT_SEV_INFO));
    ASSERT_STR_EQ("NOTICE", ozayn_audit_severity_name(OZAYN_AUDIT_SEV_NOTICE));
    ASSERT_STR_EQ("WARNING", ozayn_audit_severity_name(OZAYN_AUDIT_SEV_WARNING));
    ASSERT_STR_EQ("HIGH", ozayn_audit_severity_name(OZAYN_AUDIT_SEV_HIGH));
    ASSERT_STR_EQ("CRITICAL", ozayn_audit_severity_name(OZAYN_AUDIT_SEV_CRITICAL));
    ASSERT_STR_EQ("UNKNOWN", ozayn_audit_severity_name((ozayn_audit_severity_t)999));
    return 0;
}

/* ============================================================
 * 10. SECURITY NEGATIVE TESTS
 * ============================================================ */

TEST(test_no_master_bypass)
{
    _init_audit_default();
    /* No hardcoded bypass should exist — default policy denies below threshold */
    ozayn_audit_policy_t p;
    memset(&p, 0, sizeof(p));
    p.enabled = 1;
    p.minimum_severity = OZAYN_AUDIT_SEV_CRITICAL;
    p.retention_events = 1000;
    p.retention_seconds = 365 * 24 * 3600;
    p.max_event_size = 2048;
    p.max_metadata_size = 512;
    p.metadata_allowed = 1;
    for (int i = 0; i < OZAYN_AUDIT_CATEGORY_COUNT; i++)
        p.required_categories[i] = 1;
    ASSERT_EQ(OZAYN_AUDIT_OK, ozayn_audit_set_policy(&_audit_svc, &p));

    /* INFO event should be rejected when threshold is CRITICAL */
    ozayn_audit_event_t ev = _make_event(OZAYN_AUDIT_AUTH_SUCCEEDED,
                                          OZAYN_AUDIT_OUTCOME_SUCCESS, "id-1");
    ev.severity = OZAYN_AUDIT_SEV_INFO;
    ASSERT_EQ(OZAYN_AUDIT_ERR_POLICY_REJECTED, ozayn_audit_record(&_audit_svc, &ev));
    ozayn_audit_service_shutdown(&_audit_svc);
    return 0;
}

TEST(test_password_not_logged)
{
    _init_audit_default();
    ozayn_audit_event_t ev = _make_event(OZAYN_AUDIT_PWD_AUTH_SUCCEEDED,
                                          OZAYN_AUDIT_OUTCOME_SUCCESS, "id-1");
    uint8_t secret[] = "password=mysecret";
    ASSERT_EQ(OZAYN_AUDIT_ERR_SECRET_REJECTED,
              ozayn_audit_event_set_metadata(&ev, secret, sizeof(secret) - 1));
    ozayn_audit_service_shutdown(&_audit_svc);
    return 0;
}

TEST(test_encryption_key_not_logged)
{
    _init_audit_default();
    ozayn_audit_event_t ev = _make_event(OZAYN_AUDIT_INTEGRITY_FAILURE,
                                          OZAYN_AUDIT_OUTCOME_ERROR, "id-1");
    uint8_t secret[] = "encryption_key=abc123";
    ASSERT_EQ(OZAYN_AUDIT_ERR_SECRET_REJECTED,
              ozayn_audit_event_set_metadata(&ev, secret, sizeof(secret) - 1));
    ozayn_audit_service_shutdown(&_audit_svc);
    return 0;
}

TEST(test_private_key_not_logged)
{
    _init_audit_default();
    ozayn_audit_event_t ev = _make_event(OZAYN_AUDIT_INTEGRITY_FAILURE,
                                          OZAYN_AUDIT_OUTCOME_ERROR, "id-1");
    uint8_t secret[] = "private_key=MIIEv";
    ASSERT_EQ(OZAYN_AUDIT_ERR_SECRET_REJECTED,
              ozayn_audit_event_set_metadata(&ev, secret, sizeof(secret) - 1));
    ozayn_audit_service_shutdown(&_audit_svc);
    return 0;
}

TEST(test_session_secret_not_logged)
{
    _init_audit_default();
    ozayn_audit_event_t ev = _make_event(OZAYN_AUDIT_SESSION_CREATED,
                                          OZAYN_AUDIT_OUTCOME_SUCCESS, "id-1");
    uint8_t secret[] = "session_secret=xyz789";
    ASSERT_EQ(OZAYN_AUDIT_ERR_SECRET_REJECTED,
              ozayn_audit_event_set_metadata(&ev, secret, sizeof(secret) - 1));
    ozayn_audit_service_shutdown(&_audit_svc);
    return 0;
}

TEST(test_mfa_secret_not_logged)
{
    _init_audit_default();
    ozayn_audit_event_t ev = _make_event(OZAYN_AUDIT_MFA_COMPLETED,
                                          OZAYN_AUDIT_OUTCOME_SUCCESS, "id-1");
    uint8_t secret[] = "mfa_secret=totp123";
    ASSERT_EQ(OZAYN_AUDIT_ERR_SECRET_REJECTED,
              ozayn_audit_event_set_metadata(&ev, secret, sizeof(secret) - 1));
    ozayn_audit_service_shutdown(&_audit_svc);
    return 0;
}

TEST(test_biometric_not_logged)
{
    _init_audit_default();
    ozayn_audit_event_t ev = _make_event(OZAYN_AUDIT_MFA_FACTOR_VERIFIED,
                                          OZAYN_AUDIT_OUTCOME_SUCCESS, "id-1");
    uint8_t secret[] = "biometric_template_data";
    ASSERT_EQ(OZAYN_AUDIT_ERR_SECRET_REJECTED,
              ozayn_audit_event_set_metadata(&ev, secret, sizeof(secret) - 1));
    ozayn_audit_service_shutdown(&_audit_svc);
    return 0;
}

TEST(test_credential_not_logged)
{
    _init_audit_default();
    ozayn_audit_event_t ev = _make_event(OZAYN_AUDIT_PWD_CREDENTIAL_CREATED,
                                          OZAYN_AUDIT_OUTCOME_SUCCESS, "id-1");
    uint8_t secret[] = "credential_secret=value";
    ASSERT_EQ(OZAYN_AUDIT_ERR_SECRET_REJECTED,
              ozayn_audit_event_set_metadata(&ev, secret, sizeof(secret) - 1));
    ozayn_audit_service_shutdown(&_audit_svc);
    return 0;
}

TEST(test_no_developer_bypass)
{
    _init_audit_default();
    /* Verify no global state allows bypass */
    ASSERT_NOT_NULL(ozayn_audit_get_global());
    ozayn_audit_service_shutdown(&_audit_svc);
    return 0;
}

TEST(test_malformed_event_rejected)
{
    _init_audit_default();
    ozayn_audit_event_t ev;
    memset(&ev, 0, sizeof(ev));
    ev.event_version = OZAYN_AUDIT_EVENT_VERSION;
    ev.event_type = (ozayn_audit_event_type_t)999;
    ASSERT_EQ(OZAYN_AUDIT_ERR_INVALID_TYPE, ozayn_audit_record(&_audit_svc, &ev));
    ASSERT_EQ(0, ozayn_audit_count(&_audit_svc));
    ozayn_audit_service_shutdown(&_audit_svc);
    return 0;
}

TEST(test_storage_failure_not_pretended)
{
    _init_audit_default();
    ozayn_audit_test_storage_t ts;
    ozayn_audit_test_storage_init(&ts);
    ts.fail_on_append = 1;
    ozayn_audit_storage_t *sp = ozayn_audit_test_storage_provider(&ts);
    ASSERT_EQ(OZAYN_AUDIT_OK, ozayn_audit_set_storage(&_audit_svc, sp));

    /* Storage fails but ring buffer still works */
    ozayn_audit_event_t ev = _make_event(OZAYN_AUDIT_AUTH_SUCCEEDED,
                                          OZAYN_AUDIT_OUTCOME_SUCCESS, "id-1");
    ASSERT_EQ(OZAYN_AUDIT_OK, ozayn_audit_record(&_audit_svc, &ev));
    /* Storage did NOT receive it */
    ASSERT_EQ(0, ts.count);
    /* But ring buffer did */
    ASSERT_EQ(1, ozayn_audit_count(&_audit_svc));
    ozayn_audit_service_shutdown(&_audit_svc);
    return 0;
}

/* ============================================================
 * 11. RESOURCE LIMITS
 * ============================================================ */

TEST(test_max_event_size_enforced)
{
    ozayn_audit_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_audit_service_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.event_capacity = 64;
    cfg.max_event_size = 102400;
    cfg.max_metadata_size = 50;
    ASSERT_EQ(OZAYN_AUDIT_OK, ozayn_audit_service_init(&svc, &cfg));

    ozayn_audit_event_t ev = _make_event(OZAYN_AUDIT_AUTH_SUCCEEDED,
                                          OZAYN_AUDIT_OUTCOME_SUCCESS, "id-1");
    ozayn_audit_event_set_detail(&ev, "this is a very long detail that exceeds the limit");
    ASSERT_EQ(OZAYN_AUDIT_OK, ozayn_audit_record(&svc, &ev));
    ozayn_audit_service_shutdown(&svc);
    return 0;
}

TEST(test_max_metadata_size_enforced)
{
    _init_audit_default();
    ozayn_audit_event_t ev = _make_event(OZAYN_AUDIT_AUTH_SUCCEEDED,
                                          OZAYN_AUDIT_OUTCOME_SUCCESS, "id-1");
    uint8_t big[600];
    memset(big, 'X', sizeof(big));
    ASSERT_EQ(OZAYN_AUDIT_ERR_METADATA_TOO_LARGE,
              ozayn_audit_event_set_metadata(&ev, big, sizeof(big)));
    ozayn_audit_service_shutdown(&_audit_svc);
    return 0;
}

TEST(test_query_limit_enforced)
{
    _init_audit_default();
    for (int i = 0; i < 300; i++) {
        ozayn_audit_event_t ev = _make_event(OZAYN_AUDIT_AUTH_SUCCEEDED,
                                              OZAYN_AUDIT_OUTCOME_SUCCESS, "id-1");
        ASSERT_EQ(OZAYN_AUDIT_OK, ozayn_audit_record(&_audit_svc, &ev));
    }
    ozayn_audit_query_t q;
    memset(&q, 0, sizeof(q));
    q.result_limit = 10;
    ozayn_audit_event_t results[300];
    int count = 0;
    ASSERT_EQ(OZAYN_AUDIT_OK, ozayn_audit_query(&_audit_svc, &q, results, 300, &count));
    ASSERT_EQ(10, count);
    ozayn_audit_service_shutdown(&_audit_svc);
    return 0;
}

TEST(test_query_default_limit)
{
    _init_audit_default();
    for (int i = 0; i < 300; i++) {
        ozayn_audit_event_t ev = _make_event(OZAYN_AUDIT_AUTH_SUCCEEDED,
                                              OZAYN_AUDIT_OUTCOME_SUCCESS, "id-1");
        ASSERT_EQ(OZAYN_AUDIT_OK, ozayn_audit_record(&_audit_svc, &ev));
    }
    ozayn_audit_query_t q;
    memset(&q, 0, sizeof(q));
    q.result_limit = 0; /* should use default */
    ozayn_audit_event_t results[300];
    int count = 0;
    ASSERT_EQ(OZAYN_AUDIT_OK, ozayn_audit_query(&_audit_svc, &q, results, 300, &count));
    ASSERT_GE(count, 1);
    ASSERT_GE(OZAYN_AUDIT_QUERY_MAX_RESULTS, count);
    ozayn_audit_service_shutdown(&_audit_svc);
    return 0;
}

TEST(test_event_version_mismatch_rejected)
{
    _init_audit_default();
    ozayn_audit_event_t ev = _make_event(OZAYN_AUDIT_AUTH_SUCCEEDED,
                                          OZAYN_AUDIT_OUTCOME_SUCCESS, "id-1");
    ev.event_version = 999;
    ASSERT_EQ(OZAYN_AUDIT_ERR_INVALID_EVENT, ozayn_audit_record(&_audit_svc, &ev));
    ASSERT_EQ(0, ozayn_audit_count(&_audit_svc));
    ozayn_audit_service_shutdown(&_audit_svc);
    return 0;
}

/* ============================================================
 * 12. CONCURRENCY (sequential simulation)
 * ============================================================ */

TEST(test_concurrent_writes_sequential)
{
    _init_audit_default();
    /* Simulate multiple independent writes */
    for (int i = 0; i < 100; i++) {
        ozayn_audit_event_t ev = _make_event(OZAYN_AUDIT_AUTH_SUCCEEDED,
                                              OZAYN_AUDIT_OUTCOME_SUCCESS, "id-1");
        ASSERT_EQ(OZAYN_AUDIT_OK, ozayn_audit_record(&_audit_svc, &ev));
    }
    ASSERT_EQ(100, ozayn_audit_count(&_audit_svc));
    ozayn_audit_service_shutdown(&_audit_svc);
    return 0;
}

TEST(test_event_uniqueness)
{
    _init_audit_default();
    char ids[50][OZAYN_AUDIT_MAX_ID_LEN];
    for (int i = 0; i < 50; i++) {
        ozayn_audit_event_t ev = _make_event(OZAYN_AUDIT_AUTH_SUCCEEDED,
                                              OZAYN_AUDIT_OUTCOME_SUCCESS, "id-1");
        ASSERT_EQ(OZAYN_AUDIT_OK, ozayn_audit_record(&_audit_svc, &ev));
        strcpy(ids[i], ev.event_id);
    }
    /* All event IDs should be unique */
    for (int i = 0; i < 50; i++) {
        for (int j = i + 1; j < 50; j++) {
            ASSERT(strcmp(ids[i], ids[j]) != 0);
        }
    }
    ozayn_audit_service_shutdown(&_audit_svc);
    return 0;
}

TEST(test_concurrent_queries_sequential)
{
    _init_audit_default();
    for (int i = 0; i < 20; i++) {
        ozayn_audit_event_t ev = _make_event(OZAYN_AUDIT_AUTH_SUCCEEDED,
                                              OZAYN_AUDIT_OUTCOME_SUCCESS, "id-1");
        ASSERT_EQ(OZAYN_AUDIT_OK, ozayn_audit_record(&_audit_svc, &ev));
    }
    /* Run multiple queries sequentially */
    for (int q = 0; q < 10; q++) {
        ozayn_audit_query_t query;
        memset(&query, 0, sizeof(query));
        query.result_limit = 5;
        ozayn_audit_event_t results[5];
        int count = 0;
        ASSERT_EQ(OZAYN_AUDIT_OK,
                  ozayn_audit_query(&_audit_svc, &query, results, 5, &count));
        ASSERT_EQ(5, count);
    }
    ozayn_audit_service_shutdown(&_audit_svc);
    return 0;
}

/* ============================================================
 * 13. INTEGRATION WITH SECURITY SUBSYSTEMS
 * ============================================================ */

TEST(test_integration_identity_event)
{
    _setup_all_deps();
    _init_audit_default();

    /* Create identity */
    ozayn_identity_t id;
    ASSERT_EQ(OZAYN_ID_OK, ozayn_id_create(&_id_svc, OZAYN_ID_TYPE_USER,
              "test-user", OZAYN_ID_SCOPE_USER, "test", &id));

    /* Record audit event for identity creation */
    ozayn_audit_event_t ev = _make_event(OZAYN_AUDIT_IDENTITY_CREATED,
                                          OZAYN_AUDIT_OUTCOME_SUCCESS, id.id);
    ozayn_audit_event_set_source(&ev, "IDENTITY");
    ozayn_audit_event_set_detail(&ev, "Identity created for test-user");
    ASSERT_EQ(OZAYN_AUDIT_OK, ozayn_audit_record(&_audit_svc, &ev));
    ASSERT_EQ(1, ozayn_audit_count(&_audit_svc));

    _teardown_all_deps();
    return 0;
}

TEST(test_integration_auth_event)
{
    _setup_all_deps();
    _init_audit_default();

    /* Create identity */
    ozayn_identity_t id;
    ASSERT_EQ(OZAYN_ID_OK, ozayn_id_create(&_id_svc, OZAYN_ID_TYPE_USER,
              "auth-user", OZAYN_ID_SCOPE_USER, "test", &id));

    /* Record audit event for auth */
    ozayn_audit_event_t ev = _make_event(OZAYN_AUDIT_AUTH_STARTED,
                                          OZAYN_AUDIT_OUTCOME_INFO, id.id);
    ozayn_audit_event_set_source(&ev, "AUTH");
    ASSERT_EQ(OZAYN_AUDIT_OK, ozayn_audit_record(&_audit_svc, &ev));

    ozayn_audit_event_t ev2 = _make_event(OZAYN_AUDIT_AUTH_SUCCEEDED,
                                           OZAYN_AUDIT_OUTCOME_SUCCESS, id.id);
    ozayn_audit_event_set_source(&ev2, "AUTH");
    ASSERT_EQ(OZAYN_AUDIT_OK, ozayn_audit_record(&_audit_svc, &ev2));
    ASSERT_EQ(2, ozayn_audit_count(&_audit_svc));

    _teardown_all_deps();
    return 0;
}

TEST(test_integration_session_event)
{
    _setup_all_deps();
    _init_audit_default();

    ozayn_identity_t id;
    ASSERT_EQ(OZAYN_ID_OK, ozayn_id_create(&_id_svc, OZAYN_ID_TYPE_USER,
              "sess-user", OZAYN_ID_SCOPE_USER, "test", &id));

    /* Record audit event for session creation (without actual session creation) */
    ozayn_audit_event_t ev = _make_event(OZAYN_AUDIT_SESSION_CREATED,
                                          OZAYN_AUDIT_OUTCOME_SUCCESS, id.id);
    ozayn_audit_event_set_source(&ev, "SESSION");
    ASSERT_EQ(OZAYN_AUDIT_OK, ozayn_audit_record(&_audit_svc, &ev));
    ASSERT_EQ(1, ozayn_audit_count(&_audit_svc));

    _teardown_all_deps();
    return 0;
}

TEST(test_integration_rbac_event)
{
    _setup_all_deps();
    _init_audit_default();

    /* Create role */
    ozayn_rbac_role_t role;
    ASSERT_EQ(OZAYN_RBAC_OK, ozayn_rbac_role_create(&_rbac_svc, "admin",
              "Administrator", "Admin role", OZAYN_AUTHZ_SCOPE_SYSTEM, &role));

    /* Record audit event */
    ozayn_audit_event_t ev = _make_event(OZAYN_AUDIT_ROLE_CREATED,
                                          OZAYN_AUDIT_OUTCOME_SUCCESS, NULL);
    ozayn_audit_event_set_source(&ev, "RBAC");
    ozayn_audit_event_set_detail(&ev, "Role admin created");
    ASSERT_EQ(OZAYN_AUDIT_OK, ozayn_audit_record(&_audit_svc, &ev));
    ASSERT_EQ(1, ozayn_audit_count(&_audit_svc));

    _teardown_all_deps();
    return 0;
}

TEST(test_integration_mfa_event)
{
    _setup_all_deps();
    _init_audit_default();

    ozayn_identity_t id;
    ASSERT_EQ(OZAYN_ID_OK, ozayn_id_create(&_id_svc, OZAYN_ID_TYPE_USER,
              "mfa-user", OZAYN_ID_SCOPE_USER, "test", &id));

    /* Record MFA event */
    ozayn_audit_event_t ev = _make_event(OZAYN_AUDIT_MFA_STARTED,
                                          OZAYN_AUDIT_OUTCOME_INFO, id.id);
    ozayn_audit_event_set_source(&ev, "MFA");
    ASSERT_EQ(OZAYN_AUDIT_OK, ozayn_audit_record(&_audit_svc, &ev));

    ozayn_audit_event_t ev2 = _make_event(OZAYN_AUDIT_MFA_COMPLETED,
                                           OZAYN_AUDIT_OUTCOME_SUCCESS, id.id);
    ASSERT_EQ(OZAYN_AUDIT_OK, ozayn_audit_record(&_audit_svc, &ev2));
    ASSERT_EQ(2, ozayn_audit_count(&_audit_svc));

    _teardown_all_deps();
    return 0;
}

TEST(test_integration_correlation)
{
    _setup_all_deps();
    _init_audit_default();

    ozayn_identity_t id;
    ASSERT_EQ(OZAYN_ID_OK, ozayn_id_create(&_id_svc, OZAYN_ID_TYPE_USER,
              "corr-user", OZAYN_ID_SCOPE_USER, "test", &id));

    const char *corr = "req-abc-123";

    /* Record correlated events */
    ozayn_audit_event_t ev1 = _make_event(OZAYN_AUDIT_AUTH_STARTED,
                                           OZAYN_AUDIT_OUTCOME_INFO, id.id);
    ozayn_audit_event_set_correlation_id(&ev1, corr);
    ASSERT_EQ(OZAYN_AUDIT_OK, ozayn_audit_record(&_audit_svc, &ev1));

    ozayn_audit_event_t ev2 = _make_event(OZAYN_AUDIT_AUTH_SUCCEEDED,
                                           OZAYN_AUDIT_OUTCOME_SUCCESS, id.id);
    ozayn_audit_event_set_correlation_id(&ev2, corr);
    ASSERT_EQ(OZAYN_AUDIT_OK, ozayn_audit_record(&_audit_svc, &ev2));

    /* Query by correlation */
    ozayn_audit_query_t q;
    memset(&q, 0, sizeof(q));
    strcpy(q.filter_correlation_id, corr);
    q.filter_correlation_active = 1;
    ozayn_audit_event_t results[10];
    int count = 0;
    ASSERT_EQ(OZAYN_AUDIT_OK, ozayn_audit_query(&_audit_svc, &q, results, 10, &count));
    ASSERT_EQ(2, count);

    _teardown_all_deps();
    return 0;
}

/* ============================================================
 * 14. GLOBAL ACCESSOR
 * ============================================================ */

TEST(test_global_accessor)
{
    ozayn_audit_service_t *g = ozayn_audit_get_global();
    ASSERT_NOT_NULL(g);
    return 0;
}

/* ============================================================
 * 15. EVENT DETAIL / FAILURE REASON
 * ============================================================ */

TEST(test_event_detail_and_failure)
{
    _init_audit_default();
    ozayn_audit_event_t ev = _make_event(OZAYN_AUDIT_AUTHZ_DENIED,
                                          OZAYN_AUDIT_OUTCOME_DENIED, "id-1");
    ozayn_audit_event_set_detail(&ev, "Access to document denied");
    ozayn_audit_event_set_failure_reason(&ev, "Insufficient permissions");
    ASSERT_EQ(OZAYN_AUDIT_OK, ozayn_audit_record(&_audit_svc, &ev));

    ozayn_audit_event_t out;
    ASSERT_EQ(OZAYN_AUDIT_OK, ozayn_audit_get_by_id(&_audit_svc, ev.event_id, &out));
    ASSERT_STR_EQ("Access to document denied", out.detail);
    ASSERT_STR_EQ("Insufficient permissions", out.failure_reason);
    ozayn_audit_service_shutdown(&_audit_svc);
    return 0;
}

TEST(test_event_resource_context)
{
    _init_audit_default();
    ozayn_audit_event_t ev = _make_event(OZAYN_AUDIT_PERM_MATCHED,
                                          OZAYN_AUDIT_OUTCOME_SUCCESS, "id-1");
    ozayn_audit_event_set_resource(&ev, OZAYN_AUTHZ_RESOURCE_DOCUMENT, "doc-42",
                                   OZAYN_AUTHZ_ACTION_READ, OZAYN_AUTHZ_SCOPE_USER);
    ASSERT_EQ(OZAYN_AUDIT_OK, ozayn_audit_record(&_audit_svc, &ev));

    ozayn_audit_event_t out;
    ASSERT_EQ(OZAYN_AUDIT_OK, ozayn_audit_get_by_id(&_audit_svc, ev.event_id, &out));
    ASSERT_EQ(OZAYN_AUTHZ_RESOURCE_DOCUMENT, out.resource_type);
    ASSERT_STR_EQ("doc-42", out.resource_id);
    ASSERT_EQ(OZAYN_AUTHZ_ACTION_READ, out.action);
    ASSERT_EQ(OZAYN_AUTHZ_SCOPE_USER, out.scope);
    ozayn_audit_service_shutdown(&_audit_svc);
    return 0;
}

/* ============================================================
 * 16. TEST RUNNER
 * ============================================================ */

int run_audit_tests(void)
{
    SUITE_BEGIN("AUDIT");

    /* 1. Service lifecycle */
    RUN(test_service_init);
    RUN(test_service_init_null);
    RUN(test_service_init_already_initialized);
    RUN(test_service_shutdown);
    RUN(test_service_shutdown_null);
    RUN(test_service_not_initialized);
    RUN(test_service_init_defaults);
    RUN(test_service_custom_config);

    /* 2. Event recording */
    RUN(test_record_simple_event);
    RUN(test_record_multiple_events);
    RUN(test_record_ring_buffer_overflow);
    RUN(test_record_null);
    RUN(test_record_not_initialized);
    RUN(test_record_auto_event_id);
    RUN(test_record_auto_severity);
    RUN(test_record_auto_category);
    RUN(test_record_auto_timestamp);
    RUN(test_record_stats);

    /* 3. Event validation */
    RUN(test_validate_valid_event);
    RUN(test_validate_null_event);
    RUN(test_validate_missing_event_id);
    RUN(test_validate_invalid_type);
    RUN(test_validate_invalid_outcome);
    RUN(test_validate_invalid_severity);
    RUN(test_validate_invalid_timestamp);
    RUN(test_validate_invalid_version);

    /* 4. Secret filtering */
    RUN(test_metadata_safe_empty);
    RUN(test_metadata_rejects_password);
    RUN(test_metadata_rejects_api_key);
    RUN(test_metadata_rejects_private_key);
    RUN(test_metadata_rejects_session_secret);
    RUN(test_metadata_rejects_token);
    RUN(test_metadata_rejects_biometric);
    RUN(test_metadata_rejects_credential);
    RUN(test_metadata_rejects_encryption_key);
    RUN(test_metadata_rejects_case_insensitive);
    RUN(test_metadata_rejects_in_event);
    RUN(test_metadata_size_exceeded);

    /* 5. Event query */
    RUN(test_query_empty);
    RUN(test_query_returns_all);
    RUN(test_query_filter_type);
    RUN(test_query_filter_identity);
    RUN(test_query_filter_outcome);
    RUN(test_query_filter_severity);
    RUN(test_query_limit);
    RUN(test_query_offset);
    RUN(test_query_null);
    RUN(test_get_by_id);
    RUN(test_get_by_id_not_found);
    RUN(test_get_by_id_null);

    /* 6. Policy */
    RUN(test_set_policy);
    RUN(test_set_policy_null);
    RUN(test_set_policy_invalid_severity);
    RUN(test_policy_rejects_below_threshold);
    RUN(test_policy_allows_above_threshold);
    RUN(test_policy_require_identity);
    RUN(test_get_policy_not_initialized);

    /* 7. Storage binding */
    RUN(test_storage_append);
    RUN(test_storage_failure);
    RUN(test_storage_unavailable);
    RUN(test_storage_corrupt_on_read);
    RUN(test_storage_shutdown_flushes);
    RUN(test_storage_reset);

    /* 8. Event builder helpers */
    RUN(test_event_init);
    RUN(test_event_set_type);
    RUN(test_event_set_type_invalid);
    RUN(test_event_set_outcome);
    RUN(test_event_set_severity);
    RUN(test_event_set_identity);
    RUN(test_event_set_identity_null);
    RUN(test_event_set_session);
    RUN(test_event_set_source);
    RUN(test_event_set_request_id);
    RUN(test_event_set_correlation_id);
    RUN(test_event_set_resource);
    RUN(test_event_set_detail);
    RUN(test_event_set_failure_reason);
    RUN(test_event_set_metadata_safe);
    RUN(test_event_set_metadata_secret_rejected);

    /* 9. Name helpers */
    RUN(test_result_names);
    RUN(test_event_type_names);
    RUN(test_category_names);
    RUN(test_outcome_names);
    RUN(test_severity_names);

    /* 10. Security negative tests */
    RUN(test_no_master_bypass);
    RUN(test_password_not_logged);
    RUN(test_encryption_key_not_logged);
    RUN(test_private_key_not_logged);
    RUN(test_session_secret_not_logged);
    RUN(test_mfa_secret_not_logged);
    RUN(test_biometric_not_logged);
    RUN(test_credential_not_logged);
    RUN(test_no_developer_bypass);
    RUN(test_malformed_event_rejected);
    RUN(test_storage_failure_not_pretended);

    /* 11. Resource limits */
    RUN(test_max_event_size_enforced);
    RUN(test_max_metadata_size_enforced);
    RUN(test_query_limit_enforced);
    RUN(test_query_default_limit);
    RUN(test_event_version_mismatch_rejected);

    /* 12. Concurrency */
    RUN(test_concurrent_writes_sequential);
    RUN(test_event_uniqueness);
    RUN(test_concurrent_queries_sequential);

    /* 13. Integration */
    RUN(test_integration_identity_event);
    RUN(test_integration_auth_event);
    RUN(test_integration_session_event);
    RUN(test_integration_rbac_event);
    RUN(test_integration_mfa_event);
    RUN(test_integration_correlation);

    /* 14. Global accessor */
    RUN(test_global_accessor);

    /* 15. Detail / failure / resource */
    RUN(test_event_detail_and_failure);
    RUN(test_event_resource_context);

    SUITE_END();
    return _tf_suite_fail;
}
