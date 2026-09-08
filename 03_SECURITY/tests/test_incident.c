/*
 * test_incident.c — Security Recovery, Incident Response & Compromise
 *                   Handling Tests (Step 25).
 *
 * Comprehensive tests covering lifecycle, classification, containment,
 * recovery, verification, resolution, lockdown, policy, and edge cases.
 */

#include "../../tests/test_framework.h"
#include "../incident.h"
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
#include "../identity.h"
#include "../session_management.h"
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
static ozayn_identity_service_t    _id_svc;
static ozayn_sess_service_t        _sess_svc;
static ozayn_ir_service_t          _ir_svc;

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

    ozayn_identity_service_config_t icfg;
    memset(&icfg, 0, sizeof(icfg));
    icfg.vault = &_vault;
    ozayn_id_service_init(&_id_svc, &icfg);

    ozayn_sess_service_config_t scfg;
    memset(&scfg, 0, sizeof(scfg));
    scfg.identity_service = &_id_svc;
    ozayn_sess_service_init(&_sess_svc, &scfg);
}

static void _teardown_deps(void)
{
    ozayn_ir_service_shutdown(&_ir_svc);
    ozayn_sess_service_shutdown(&_sess_svc);
    ozayn_id_service_shutdown(&_id_svc);
    ozayn_audit_service_shutdown(&_audit_svc);
    ozayn_vault_shutdown(&_vault);
    ozayn_kl_shutdown(&_kl);
    ozayn_sp_shutdown(&_stor);
    ozayn_prot_shutdown(&_prot);
}

static void _init_ir_svc(void)
{
    ozayn_ir_service_shutdown(&_ir_svc);

    /* Reinitialize key lifecycle (tests revoke keys) */
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

    ozayn_ir_service_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.vault         = &_vault;
    cfg.key_lifecycle = &_kl;
    cfg.protection    = &_prot;
    cfg.storage       = &_stor;
    cfg.audit         = &_audit_svc;
    cfg.identity      = &_id_svc;
    cfg.session       = &_sess_svc;
    ozayn_ir_service_init(&_ir_svc, &cfg);
}

static ozayn_identity_t _create_identity(const char *label)
{
    ozayn_identity_t id;
    memset(&id, 0, sizeof(id));
    ozayn_id_create(&_id_svc, OZAYN_ID_TYPE_USER, label,
                     OZAYN_ID_SCOPE_USER, "test", &id);
    return id;
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

/* ============================================================
 * LIFECYCLE TESTS
 * ============================================================ */

TEST(test_ir_service_init_valid)
{
    _init_ir_svc();
    ASSERT(ozayn_ir_service_is_initialized(&_ir_svc));
    return 0;
}

TEST(test_ir_service_init_null)
{
    ASSERT_EQ(OZAYN_IR_ERR_NULL, ozayn_ir_service_init(NULL, NULL));
    return 0;
}

TEST(test_ir_service_init_null_config)
{
    ozayn_ir_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ASSERT_EQ(OZAYN_IR_ERR_NULL, ozayn_ir_service_init(&svc, NULL));
    return 0;
}

TEST(test_ir_service_init_already_initialized)
{
    _init_ir_svc();
    ozayn_ir_service_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    ASSERT_EQ(OZAYN_IR_ERR_ALREADY_INITIALIZED,
              ozayn_ir_service_init(&_ir_svc, &cfg));
    return 0;
}

TEST(test_ir_service_shutdown_null)
{
    ozayn_ir_service_shutdown(NULL);
    return 0;
}

TEST(test_ir_service_shutdown_reinit)
{
    _init_ir_svc();
    ozayn_ir_service_shutdown(&_ir_svc);
    ASSERT_EQ(0, ozayn_ir_service_is_initialized(&_ir_svc));
    _init_ir_svc();
    ASSERT_EQ(1, ozayn_ir_service_is_initialized(&_ir_svc));
    return 0;
}

TEST(test_ir_service_default_policy)
{
    _init_ir_svc();
    ASSERT_EQ(OZAYN_IR_MAX_INCIDENTS, _ir_svc.policy.max_incidents);
    ASSERT_EQ(1, _ir_svc.policy.auto_contain_critical);
    ASSERT_EQ(1, _ir_svc.policy.require_mfa_for_recovery);
    ASSERT_EQ(5, _ir_svc.policy.lockdown_threshold);
    ASSERT_EQ(60, _ir_svc.policy.dedup_window_seconds);
    return 0;
}

TEST(test_ir_global_accessor)
{
    ozayn_ir_service_t *g = ozayn_ir_get_global();
    ASSERT_NOT_NULL(g);
    return 0;
}

TEST(test_ir_is_initialized_null)
{
    ASSERT_EQ(0, ozayn_ir_service_is_initialized(NULL));
    return 0;
}

/* ============================================================
 * REPORTING TESTS
 * ============================================================ */

TEST(test_ir_report_basic)
{
    _init_ir_svc();
    ozayn_ir_incident_t *inc = NULL;
    ASSERT_EQ(OZAYN_IR_OK, ozayn_ir_report(&_ir_svc,
        OZAYN_IR_TYPE_AUTHENTICATION_ATTACK, OZAYN_IR_SEV_HIGH,
        "test_auth", "id-001", "sess-001", "res-001", "corr-001",
        "Brute force detected", &inc));
    ASSERT_NOT_NULL(inc);
    ASSERT(strncmp(inc->incident_id, "INC-", 4) == 0);
    ASSERT_EQ(OZAYN_IR_TYPE_AUTHENTICATION_ATTACK, inc->incident_type);
    ASSERT_EQ(OZAYN_IR_SEV_HIGH, inc->severity);
    ASSERT_EQ(OZAYN_IR_STATE_DETECTED, inc->state);
    ASSERT_STR_EQ("test_auth", inc->source_component);
    ASSERT_STR_EQ("id-001", inc->identity_id);
    ASSERT_STR_EQ("sess-001", inc->session_id);
    ASSERT_STR_EQ("res-001", inc->resource_id);
    ASSERT_STR_EQ("corr-001", inc->correlation_id);
    ASSERT_STR_EQ("Brute force detected", inc->detail);
    ASSERT_EQ(1, _ir_svc.incident_count);
    return 0;
}

TEST(test_ir_report_null_svc)
{
    ASSERT_EQ(OZAYN_IR_ERR_NULL, ozayn_ir_report(NULL,
        OZAYN_IR_TYPE_AUTHENTICATION_ATTACK, OZAYN_IR_SEV_HIGH,
        "test", "", "", "", "", NULL, NULL));
    return 0;
}

TEST(test_ir_report_not_initialized)
{
    ozayn_ir_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ASSERT_EQ(OZAYN_IR_ERR_NOT_INITIALIZED, ozayn_ir_report(&svc,
        OZAYN_IR_TYPE_AUTHENTICATION_ATTACK, OZAYN_IR_SEV_HIGH,
        "test", "", "", "", "", NULL, NULL));
    return 0;
}

TEST(test_ir_report_invalid_type)
{
    _init_ir_svc();
    ASSERT_EQ(OZAYN_IR_ERR_INVALID_TYPE, ozayn_ir_report(&_ir_svc,
        255, OZAYN_IR_SEV_HIGH, "test", "", "", "", "", NULL, NULL));
    return 0;
}

TEST(test_ir_report_invalid_severity)
{
    _init_ir_svc();
    ASSERT_EQ(OZAYN_IR_ERR_INVALID_SEVERITY, ozayn_ir_report(&_ir_svc,
        OZAYN_IR_TYPE_AUTHENTICATION_ATTACK, 255,
        "test", "", "", "", "", NULL, NULL));
    return 0;
}

TEST(test_ir_report_empty_source)
{
    _init_ir_svc();
    ASSERT_EQ(OZAYN_IR_ERR_INVALID_REQUEST, ozayn_ir_report(&_ir_svc,
        OZAYN_IR_TYPE_AUTHENTICATION_ATTACK, OZAYN_IR_SEV_HIGH,
        "", "", "", "", "", NULL, NULL));
    return 0;
}

TEST(test_ir_report_null_source)
{
    _init_ir_svc();
    ASSERT_EQ(OZAYN_IR_ERR_INVALID_REQUEST, ozayn_ir_report(&_ir_svc,
        OZAYN_IR_TYPE_AUTHENTICATION_ATTACK, OZAYN_IR_SEV_HIGH,
        NULL, "", "", "", "", NULL, NULL));
    return 0;
}

TEST(test_ir_report_no_out_ptr)
{
    _init_ir_svc();
    ASSERT_EQ(OZAYN_IR_OK, ozayn_ir_report(&_ir_svc,
        OZAYN_IR_TYPE_AUTHENTICATION_ATTACK, OZAYN_IR_SEV_HIGH,
        "test", "", "", "", "", NULL, NULL));
    ASSERT_EQ(1, _ir_svc.incident_count);
    return 0;
}

TEST(test_ir_report_multiple_incidents)
{
    _init_ir_svc();
    for (int i = 0; i < 10; i++) {
        char src[32];
        snprintf(src, sizeof(src), "src_%d", i);
        ASSERT_EQ(OZAYN_IR_OK, ozayn_ir_report(&_ir_svc,
            OZAYN_IR_TYPE_UNKNOWN, OZAYN_IR_SEV_INFO,
            src, "", "", "", "", NULL, NULL));
    }
    ASSERT_EQ(10, _ir_svc.incident_count);
    return 0;
}

TEST(test_ir_report_stats)
{
    _init_ir_svc();
    ASSERT_EQ(OZAYN_IR_OK, ozayn_ir_report(&_ir_svc,
        OZAYN_IR_TYPE_VAULT_COMPROMISE, OZAYN_IR_SEV_LOW,
        "test", "", "", "", "", NULL, NULL));
    ASSERT_EQ(1, _ir_svc.total_incidents_reported);
    return 0;
}

TEST(test_ir_report_storage_full)
{
    _init_ir_svc();
    _ir_svc.policy.max_incidents = 2;
    ASSERT_EQ(OZAYN_IR_OK, ozayn_ir_report(&_ir_svc,
        OZAYN_IR_TYPE_UNKNOWN, OZAYN_IR_SEV_INFO,
        "s1", "", "", "", "", NULL, NULL));
    ASSERT_EQ(OZAYN_IR_OK, ozayn_ir_report(&_ir_svc,
        OZAYN_IR_TYPE_UNKNOWN, OZAYN_IR_SEV_INFO,
        "s2", "", "", "", "", NULL, NULL));
    ASSERT_EQ(OZAYN_IR_ERR_STORAGE_FULL, ozayn_ir_report(&_ir_svc,
        OZAYN_IR_TYPE_UNKNOWN, OZAYN_IR_SEV_INFO,
        "s3", "", "", "", "", NULL, NULL));
    return 0;
}

/* ============================================================
 * QUERY TESTS
 * ============================================================ */

TEST(test_ir_get_valid)
{
    _init_ir_svc();
    ozayn_ir_incident_t *inc = NULL;
    ozayn_ir_report(&_ir_svc, OZAYN_IR_TYPE_KEY_COMPROMISE,
        OZAYN_IR_SEV_HIGH, "test", "", "", "", "", NULL, &inc);
    ozayn_ir_incident_t *found = NULL;
    ASSERT_EQ(OZAYN_IR_OK, ozayn_ir_get(&_ir_svc, inc->incident_id, &found));
    ASSERT_NOT_NULL(found);
    ASSERT_STR_EQ(inc->incident_id, found->incident_id);
    return 0;
}

TEST(test_ir_get_null)
{
    ASSERT_EQ(OZAYN_IR_ERR_NULL, ozayn_ir_get(NULL, "x", NULL));
    return 0;
}

TEST(test_ir_get_not_initialized)
{
    ozayn_ir_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ASSERT_EQ(OZAYN_IR_ERR_NOT_INITIALIZED, ozayn_ir_get(&svc, "x", NULL));
    return 0;
}

TEST(test_ir_get_invalid_id)
{
    _init_ir_svc();
    ASSERT_EQ(OZAYN_IR_ERR_INVALID_ID, ozayn_ir_get(&_ir_svc, "", NULL));
    ASSERT_EQ(OZAYN_IR_ERR_INVALID_ID, ozayn_ir_get(&_ir_svc, NULL, NULL));
    return 0;
}

TEST(test_ir_get_not_found)
{
    _init_ir_svc();
    ozayn_ir_incident_t *found = NULL;
    ASSERT_EQ(OZAYN_IR_ERR_NOT_FOUND, ozayn_ir_get(&_ir_svc, "NOPE-999", &found));
    return 0;
}

TEST(test_ir_list_all)
{
    _init_ir_svc();
    ozayn_ir_report(&_ir_svc, OZAYN_IR_TYPE_AUTHENTICATION_ATTACK,
        OZAYN_IR_SEV_LOW, "s1", "", "", "", "", NULL, NULL);
    ozayn_ir_report(&_ir_svc, OZAYN_IR_TYPE_KEY_COMPROMISE,
        OZAYN_IR_SEV_HIGH, "s2", "", "", "", "", NULL, NULL);

    ozayn_ir_incident_t *list[10];
    int count = ozayn_ir_list(&_ir_svc, OZAYN_IR_TYPE_UNKNOWN, list, 10);
    ASSERT_EQ(2, count);
    return 0;
}

TEST(test_ir_list_filtered)
{
    _init_ir_svc();
    ozayn_ir_report(&_ir_svc, OZAYN_IR_TYPE_AUTHENTICATION_ATTACK,
        OZAYN_IR_SEV_LOW, "s1", "", "", "", "", NULL, NULL);
    ozayn_ir_report(&_ir_svc, OZAYN_IR_TYPE_KEY_COMPROMISE,
        OZAYN_IR_SEV_HIGH, "s2", "", "", "", "", NULL, NULL);

    ozayn_ir_incident_t *list[10];
    int count = ozayn_ir_list(&_ir_svc, OZAYN_IR_TYPE_KEY_COMPROMISE, list, 10);
    ASSERT_EQ(1, count);
    return 0;
}

TEST(test_ir_list_empty)
{
    _init_ir_svc();
    ozayn_ir_incident_t *list[10];
    int count = ozayn_ir_list(&_ir_svc, OZAYN_IR_TYPE_UNKNOWN, list, 10);
    ASSERT_EQ(0, count);
    return 0;
}

TEST(test_ir_list_null)
{
    ASSERT_EQ(0, ozayn_ir_list(NULL, OZAYN_IR_TYPE_UNKNOWN, NULL, 0));
    return 0;
}

TEST(test_ir_list_max_count)
{
    _init_ir_svc();
    for (int i = 0; i < 5; i++)
        ozayn_ir_report(&_ir_svc, OZAYN_IR_TYPE_UNKNOWN, OZAYN_IR_SEV_INFO,
            "s", "", "", "", "", NULL, NULL);
    ozayn_ir_incident_t *list[3];
    int count = ozayn_ir_list(&_ir_svc, OZAYN_IR_TYPE_UNKNOWN, list, 3);
    ASSERT_EQ(3, count);
    return 0;
}

/* ============================================================
 * CLASSIFY TESTS
 * ============================================================ */

TEST(test_ir_classify_valid)
{
    _init_ir_svc();
    ozayn_ir_incident_t *inc = NULL;
    ozayn_ir_report(&_ir_svc, OZAYN_IR_TYPE_SUSPICIOUS_ACTIVITY,
        OZAYN_IR_SEV_INFO, "test", "", "", "", "", NULL, &inc);
    ASSERT_EQ(OZAYN_IR_OK, ozayn_ir_classify(&_ir_svc, inc->incident_id,
        OZAYN_IR_TYPE_VAULT_COMPROMISE, OZAYN_IR_SEV_CRITICAL));
    ASSERT_EQ(OZAYN_IR_STATE_CLASSIFIED, inc->state);
    ASSERT_EQ(OZAYN_IR_TYPE_VAULT_COMPROMISE, inc->incident_type);
    ASSERT_EQ(OZAYN_IR_SEV_CRITICAL, inc->severity);
    return 0;
}

TEST(test_ir_classify_null)
{
    ASSERT_EQ(OZAYN_IR_ERR_NULL, ozayn_ir_classify(NULL, "x", 0, 0));
    return 0;
}

TEST(test_ir_classify_not_found)
{
    _init_ir_svc();
    ASSERT_EQ(OZAYN_IR_ERR_NOT_FOUND, ozayn_ir_classify(&_ir_svc, "NOPE",
        OZAYN_IR_TYPE_UNKNOWN, OZAYN_IR_SEV_LOW));
    return 0;
}

TEST(test_ir_classify_invalid_type)
{
    _init_ir_svc();
    ozayn_ir_incident_t *inc = NULL;
    ozayn_ir_report(&_ir_svc, OZAYN_IR_TYPE_UNKNOWN, OZAYN_IR_SEV_INFO,
        "test", "", "", "", "", NULL, &inc);
    ASSERT_EQ(OZAYN_IR_ERR_INVALID_TYPE, ozayn_ir_classify(&_ir_svc,
        inc->incident_id, 255, OZAYN_IR_SEV_LOW));
    return 0;
}

TEST(test_ir_classify_invalid_severity)
{
    _init_ir_svc();
    ozayn_ir_incident_t *inc = NULL;
    ozayn_ir_report(&_ir_svc, OZAYN_IR_TYPE_UNKNOWN, OZAYN_IR_SEV_INFO,
        "test", "", "", "", "", NULL, &inc);
    ASSERT_EQ(OZAYN_IR_ERR_INVALID_SEVERITY, ozayn_ir_classify(&_ir_svc,
        inc->incident_id, OZAYN_IR_TYPE_UNKNOWN, 255));
    return 0;
}

TEST(test_ir_classify_already_resolved)
{
    _init_ir_svc();
    ozayn_ir_incident_t *inc = NULL;
    ozayn_ir_report(&_ir_svc, OZAYN_IR_TYPE_UNKNOWN, OZAYN_IR_SEV_INFO,
        "test", "", "", "", "", NULL, &inc);
    ozayn_ir_classify(&_ir_svc, inc->incident_id,
        OZAYN_IR_TYPE_UNKNOWN, OZAYN_IR_SEV_INFO);
    ozayn_ir_update_state(&_ir_svc, inc->incident_id, OZAYN_IR_STATE_CONTAINMENT_REQUIRED);
    ozayn_ir_update_state(&_ir_svc, inc->incident_id, OZAYN_IR_STATE_CONTAINING);
    ozayn_ir_update_state(&_ir_svc, inc->incident_id, OZAYN_IR_STATE_CONTAINED);
    ozayn_ir_update_state(&_ir_svc, inc->incident_id, OZAYN_IR_STATE_RECOVERY_REQUIRED);
    ozayn_ir_update_state(&_ir_svc, inc->incident_id, OZAYN_IR_STATE_RECOVERING);
    ozayn_ir_update_state(&_ir_svc, inc->incident_id, OZAYN_IR_STATE_VERIFIED);
    ozayn_ir_update_state(&_ir_svc, inc->incident_id, OZAYN_IR_STATE_RESOLVED);
    ASSERT_EQ(OZAYN_IR_ERR_ALREADY_RESOLVED, ozayn_ir_classify(&_ir_svc,
        inc->incident_id, OZAYN_IR_TYPE_UNKNOWN, OZAYN_IR_SEV_LOW));
    return 0;
}

/* ============================================================
 * STATE TRANSITION TESTS
 * ============================================================ */

TEST(test_ir_state_transition_valid)
{
    /* DETECTED -> CLASSIFIED */
    ASSERT(ozayn_ir_state_transition_valid(
        OZAYN_IR_STATE_DETECTED, OZAYN_IR_STATE_CLASSIFIED));
    /* CLASSIFIED -> CONTAINMENT_REQUIRED */
    ASSERT(ozayn_ir_state_transition_valid(
        OZAYN_IR_STATE_CLASSIFIED, OZAYN_IR_STATE_CONTAINMENT_REQUIRED));
    /* CLASSIFIED -> RECOVERY_REQUIRED */
    ASSERT(ozayn_ir_state_transition_valid(
        OZAYN_IR_STATE_CLASSIFIED, OZAYN_IR_STATE_RECOVERY_REQUIRED));
    /* RESOLVED -> DETECTED (terminal) */
    ASSERT(!ozayn_ir_state_transition_valid(
        OZAYN_IR_STATE_RESOLVED, OZAYN_IR_STATE_DETECTED));
    /* RECOVERY_FAILED -> DETECTED (terminal) */
    ASSERT(!ozayn_ir_state_transition_valid(
        OZAYN_IR_STATE_RECOVERY_FAILED, OZAYN_IR_STATE_DETECTED));
    return 0;
}

TEST(test_ir_state_transition_full_containment_path)
{
    /* DETECTED -> CLASSIFIED -> CONTAINMENT_REQUIRED -> CONTAINING
     * -> CONTAINED -> RECOVERY_REQUIRED -> RECOVERING -> VERIFIED -> RESOLVED */
    ASSERT(ozayn_ir_state_transition_valid(
        OZAYN_IR_STATE_DETECTED, OZAYN_IR_STATE_CLASSIFIED));
    ASSERT(ozayn_ir_state_transition_valid(
        OZAYN_IR_STATE_CLASSIFIED, OZAYN_IR_STATE_CONTAINMENT_REQUIRED));
    ASSERT(ozayn_ir_state_transition_valid(
        OZAYN_IR_STATE_CONTAINMENT_REQUIRED, OZAYN_IR_STATE_CONTAINING));
    ASSERT(ozayn_ir_state_transition_valid(
        OZAYN_IR_STATE_CONTAINING, OZAYN_IR_STATE_CONTAINED));
    ASSERT(ozayn_ir_state_transition_valid(
        OZAYN_IR_STATE_CONTAINED, OZAYN_IR_STATE_RECOVERY_REQUIRED));
    ASSERT(ozayn_ir_state_transition_valid(
        OZAYN_IR_STATE_RECOVERY_REQUIRED, OZAYN_IR_STATE_RECOVERING));
    ASSERT(ozayn_ir_state_transition_valid(
        OZAYN_IR_STATE_RECOVERING, OZAYN_IR_STATE_VERIFIED));
    ASSERT(ozayn_ir_state_transition_valid(
        OZAYN_IR_STATE_VERIFIED, OZAYN_IR_STATE_RESOLVED));
    return 0;
}

TEST(test_ir_state_transition_full_recovery_path)
{
    /* DETECTED -> CLASSIFIED -> RECOVERY_REQUIRED -> RECOVERING
     * -> VERIFIED -> RESOLVED */
    ASSERT(ozayn_ir_state_transition_valid(
        OZAYN_IR_STATE_DETECTED, OZAYN_IR_STATE_CLASSIFIED));
    ASSERT(ozayn_ir_state_transition_valid(
        OZAYN_IR_STATE_CLASSIFIED, OZAYN_IR_STATE_RECOVERY_REQUIRED));
    ASSERT(ozayn_ir_state_transition_valid(
        OZAYN_IR_STATE_RECOVERY_REQUIRED, OZAYN_IR_STATE_RECOVERING));
    ASSERT(ozayn_ir_state_transition_valid(
        OZAYN_IR_STATE_RECOVERING, OZAYN_IR_STATE_VERIFIED));
    ASSERT(ozayn_ir_state_transition_valid(
        OZAYN_IR_STATE_VERIFIED, OZAYN_IR_STATE_RESOLVED));
    return 0;
}

TEST(test_ir_update_state_valid)
{
    _init_ir_svc();
    ozayn_ir_incident_t *inc = NULL;
    ozayn_ir_report(&_ir_svc, OZAYN_IR_TYPE_UNKNOWN, OZAYN_IR_SEV_LOW,
        "test", "", "", "", "", NULL, &inc);
    ASSERT_EQ(OZAYN_IR_OK, ozayn_ir_update_state(&_ir_svc,
        inc->incident_id, OZAYN_IR_STATE_CLASSIFIED));
    ASSERT_EQ(OZAYN_IR_STATE_CLASSIFIED, inc->state);
    return 0;
}

TEST(test_ir_update_state_invalid_transition)
{
    _init_ir_svc();
    ozayn_ir_incident_t *inc = NULL;
    ozayn_ir_report(&_ir_svc, OZAYN_IR_TYPE_UNKNOWN, OZAYN_IR_SEV_LOW,
        "test", "", "", "", "", NULL, &inc);
    /* DETECTED -> RESOLVED is invalid */
    ASSERT_EQ(OZAYN_IR_ERR_STATE_TRANSITION_INVALID,
        ozayn_ir_update_state(&_ir_svc, inc->incident_id, OZAYN_IR_STATE_RESOLVED));
    return 0;
}

TEST(test_ir_update_state_already_resolved)
{
    _init_ir_svc();
    ozayn_ir_incident_t *inc = NULL;
    ozayn_ir_report(&_ir_svc, OZAYN_IR_TYPE_UNKNOWN, OZAYN_IR_SEV_INFO,
        "test", "", "", "", "", NULL, &inc);
    /* Full lifecycle to RESOLVED */
    ozayn_ir_classify(&_ir_svc, inc->incident_id, OZAYN_IR_TYPE_UNKNOWN, OZAYN_IR_SEV_INFO);
    ozayn_ir_update_state(&_ir_svc, inc->incident_id, OZAYN_IR_STATE_RECOVERY_REQUIRED);
    ozayn_ir_update_state(&_ir_svc, inc->incident_id, OZAYN_IR_STATE_RECOVERING);
    ozayn_ir_update_state(&_ir_svc, inc->incident_id, OZAYN_IR_STATE_VERIFIED);
    ozayn_ir_update_state(&_ir_svc, inc->incident_id, OZAYN_IR_STATE_RESOLVED);
    ASSERT_EQ(OZAYN_IR_ERR_ALREADY_RESOLVED,
        ozayn_ir_update_state(&_ir_svc, inc->incident_id, OZAYN_IR_STATE_DETECTED));
    return 0;
}

TEST(test_ir_update_state_null)
{
    ASSERT_EQ(OZAYN_IR_ERR_NULL, ozayn_ir_update_state(NULL, "x", 0));
    return 0;
}

TEST(test_ir_update_state_not_found)
{
    _init_ir_svc();
    ASSERT_EQ(OZAYN_IR_ERR_NOT_FOUND,
        ozayn_ir_update_state(&_ir_svc, "NOPE", OZAYN_IR_STATE_CLASSIFIED));
    return 0;
}

/* ============================================================
 * CONTAINMENT TESTS
 * ============================================================ */

TEST(test_ir_contain_none)
{
    _init_ir_svc();
    ozayn_ir_incident_t *inc = NULL;
    ozayn_ir_report(&_ir_svc, OZAYN_IR_TYPE_SUSPICIOUS_ACTIVITY,
        OZAYN_IR_SEV_LOW, "test", "", "", "", "", NULL, &inc);
    ozayn_ir_classify(&_ir_svc, inc->incident_id,
        OZAYN_IR_TYPE_SUSPICIOUS_ACTIVITY, OZAYN_IR_SEV_LOW);
    ozayn_ir_update_state(&_ir_svc, inc->incident_id, OZAYN_IR_STATE_CONTAINMENT_REQUIRED);
    ASSERT_EQ(OZAYN_IR_OK, ozayn_ir_contain(&_ir_svc, inc->incident_id,
        OZAYN_IR_CONTAIN_NONE));
    ASSERT(inc->containment_completed);
    ASSERT_EQ(OZAYN_IR_STATE_CONTAINED, inc->state);
    return 0;
}

TEST(test_ir_contain_revoke_session)
{
    _init_ir_svc();
    ozayn_sess_t sess = _create_session_for("sess_user");

    ozayn_ir_incident_t *inc = NULL;
    ozayn_ir_report(&_ir_svc, OZAYN_IR_TYPE_SESSION_COMPROMISE,
        OZAYN_IR_SEV_HIGH, "test", "", sess.id, "", "Session hijack", NULL, &inc);
    ozayn_ir_classify(&_ir_svc, inc->incident_id,
        OZAYN_IR_TYPE_SESSION_COMPROMISE, OZAYN_IR_SEV_HIGH);
    ozayn_ir_update_state(&_ir_svc, inc->incident_id, OZAYN_IR_STATE_CONTAINMENT_REQUIRED);
    ASSERT_EQ(OZAYN_IR_OK, ozayn_ir_contain(&_ir_svc, inc->incident_id,
        OZAYN_IR_CONTAIN_REVOKE_SESSION));
    ASSERT(inc->containment_completed);
    ASSERT_EQ(1, _ir_svc.total_containments);
    return 0;
}

TEST(test_ir_contain_suspend_identity)
{
    _init_ir_svc();
    ozayn_identity_t id = _create_identity("sus_user");

    ozayn_ir_incident_t *inc = NULL;
    ozayn_ir_report(&_ir_svc, OZAYN_IR_TYPE_IDENTITY_COMPROMISE,
        OZAYN_IR_SEV_HIGH, "test", id.id, "", "", "", NULL, &inc);
    ozayn_ir_classify(&_ir_svc, inc->incident_id,
        OZAYN_IR_TYPE_IDENTITY_COMPROMISE, OZAYN_IR_SEV_HIGH);
    ozayn_ir_update_state(&_ir_svc, inc->incident_id, OZAYN_IR_STATE_CONTAINMENT_REQUIRED);
    ASSERT_EQ(OZAYN_IR_OK, ozayn_ir_contain(&_ir_svc, inc->incident_id,
        OZAYN_IR_CONTAIN_SUSPEND_IDENTITY));
    ASSERT(inc->containment_completed);
    return 0;
}

TEST(test_ir_contain_revoke_identity)
{
    _init_ir_svc();
    ozayn_identity_t id = _create_identity("rev_id_user");

    ozayn_ir_incident_t *inc = NULL;
    ozayn_ir_report(&_ir_svc, OZAYN_IR_TYPE_CREDENTIAL_COMPROMISE,
        OZAYN_IR_SEV_CRITICAL, "test", id.id, "", "", "", NULL, &inc);
    ozayn_ir_classify(&_ir_svc, inc->incident_id,
        OZAYN_IR_TYPE_CREDENTIAL_COMPROMISE, OZAYN_IR_SEV_CRITICAL);
    ozayn_ir_update_state(&_ir_svc, inc->incident_id, OZAYN_IR_STATE_CONTAINMENT_REQUIRED);
    ASSERT_EQ(OZAYN_IR_OK, ozayn_ir_contain(&_ir_svc, inc->incident_id,
        OZAYN_IR_CONTAIN_REVOKE_IDENTITY));
    ASSERT(inc->containment_completed);
    return 0;
}

TEST(test_ir_contain_enter_lockdown)
{
    _init_ir_svc();
    ASSERT(!ozayn_ir_is_lockdown_active(&_ir_svc));
    ozayn_ir_incident_t *inc = NULL;
    ozayn_ir_report(&_ir_svc, OZAYN_IR_TYPE_VAULT_COMPROMISE,
        OZAYN_IR_SEV_CRITICAL, "test", "", "", "", "", NULL, &inc);
    ozayn_ir_classify(&_ir_svc, inc->incident_id,
        OZAYN_IR_TYPE_VAULT_COMPROMISE, OZAYN_IR_SEV_CRITICAL);
    ozayn_ir_update_state(&_ir_svc, inc->incident_id, OZAYN_IR_STATE_CONTAINMENT_REQUIRED);
    ASSERT_EQ(OZAYN_IR_OK, ozayn_ir_contain(&_ir_svc, inc->incident_id,
        OZAYN_IR_CONTAIN_ENTER_LOCKDOWN));
    ASSERT(ozayn_ir_is_lockdown_active(&_ir_svc));
    ASSERT_EQ(1, _ir_svc.total_lockdowns);
    return 0;
}

TEST(test_ir_contain_null)
{
    ASSERT_EQ(OZAYN_IR_ERR_NULL, ozayn_ir_contain(NULL, "x", OZAYN_IR_CONTAIN_NONE));
    return 0;
}

TEST(test_ir_contain_not_found)
{
    _init_ir_svc();
    ASSERT_EQ(OZAYN_IR_ERR_NOT_FOUND, ozayn_ir_contain(&_ir_svc, "NOPE",
        OZAYN_IR_CONTAIN_NONE));
    return 0;
}

TEST(test_ir_contain_already_resolved)
{
    _init_ir_svc();
    ozayn_ir_incident_t *inc = NULL;
    ozayn_ir_report(&_ir_svc, OZAYN_IR_TYPE_UNKNOWN, OZAYN_IR_SEV_INFO,
        "test", "", "", "", "", NULL, &inc);
    ozayn_ir_classify(&_ir_svc, inc->incident_id, OZAYN_IR_TYPE_UNKNOWN, OZAYN_IR_SEV_INFO);
    ozayn_ir_update_state(&_ir_svc, inc->incident_id, OZAYN_IR_STATE_RECOVERY_REQUIRED);
    ozayn_ir_update_state(&_ir_svc, inc->incident_id, OZAYN_IR_STATE_RECOVERING);
    ozayn_ir_update_state(&_ir_svc, inc->incident_id, OZAYN_IR_STATE_VERIFIED);
    ozayn_ir_update_state(&_ir_svc, inc->incident_id, OZAYN_IR_STATE_RESOLVED);
    ASSERT_EQ(OZAYN_IR_ERR_ALREADY_RESOLVED, ozayn_ir_contain(&_ir_svc,
        inc->incident_id, OZAYN_IR_CONTAIN_NONE));
    return 0;
}

TEST(test_ir_contain_no_session)
{
    _init_ir_svc();
    ozayn_ir_incident_t *inc = NULL;
    ozayn_ir_report(&_ir_svc, OZAYN_IR_TYPE_SESSION_COMPROMISE,
        OZAYN_IR_SEV_HIGH, "test", "", "", "", "", NULL, &inc);
    ozayn_ir_classify(&_ir_svc, inc->incident_id,
        OZAYN_IR_TYPE_SESSION_COMPROMISE, OZAYN_IR_SEV_HIGH);
    ozayn_ir_update_state(&_ir_svc, inc->incident_id, OZAYN_IR_STATE_CONTAINMENT_REQUIRED);
    /* No session_id set, but containment still succeeds */
    ASSERT_EQ(OZAYN_IR_OK, ozayn_ir_contain(&_ir_svc, inc->incident_id,
        OZAYN_IR_CONTAIN_REVOKE_SESSION));
    ASSERT(inc->containment_completed);
    return 0;
}

TEST(test_ir_contain_no_identity)
{
    _init_ir_svc();
    ozayn_ir_incident_t *inc = NULL;
    ozayn_ir_report(&_ir_svc, OZAYN_IR_TYPE_IDENTITY_COMPROMISE,
        OZAYN_IR_SEV_HIGH, "test", "", "", "", "", NULL, &inc);
    ozayn_ir_classify(&_ir_svc, inc->incident_id,
        OZAYN_IR_TYPE_IDENTITY_COMPROMISE, OZAYN_IR_SEV_HIGH);
    ozayn_ir_update_state(&_ir_svc, inc->incident_id, OZAYN_IR_STATE_CONTAINMENT_REQUIRED);
    /* No identity_id set, but containment still succeeds */
    ASSERT_EQ(OZAYN_IR_OK, ozayn_ir_contain(&_ir_svc, inc->incident_id,
        OZAYN_IR_CONTAIN_SUSPEND_IDENTITY));
    ASSERT(inc->containment_completed);
    return 0;
}

TEST(test_ir_contain_stats)
{
    _init_ir_svc();
    ozayn_ir_incident_t *inc = NULL;
    ozayn_ir_report(&_ir_svc, OZAYN_IR_TYPE_UNKNOWN, OZAYN_IR_SEV_LOW,
        "test", "", "", "", "", NULL, &inc);
    ozayn_ir_classify(&_ir_svc, inc->incident_id, OZAYN_IR_TYPE_UNKNOWN, OZAYN_IR_SEV_LOW);
    ozayn_ir_update_state(&_ir_svc, inc->incident_id, OZAYN_IR_STATE_CONTAINMENT_REQUIRED);
    ASSERT_EQ(0, _ir_svc.total_containments);
    ozayn_ir_contain(&_ir_svc, inc->incident_id, OZAYN_IR_CONTAIN_NONE);
    ASSERT_EQ(1, _ir_svc.total_containments);
    return 0;
}

/* ============================================================
 * RECOVERY TESTS
 * ============================================================ */

TEST(test_ir_recover_valid)
{
    _init_ir_svc();
    ozayn_ir_incident_t *inc = NULL;
    ozayn_ir_report(&_ir_svc, OZAYN_IR_TYPE_COMPONENT_FAILURE,
        OZAYN_IR_SEV_MEDIUM, "test", "", "", "", "", NULL, &inc);
    ozayn_ir_classify(&_ir_svc, inc->incident_id,
        OZAYN_IR_TYPE_COMPONENT_FAILURE, OZAYN_IR_SEV_MEDIUM);
    ozayn_ir_update_state(&_ir_svc, inc->incident_id, OZAYN_IR_STATE_RECOVERY_REQUIRED);
    ASSERT_EQ(OZAYN_IR_OK, ozayn_ir_recover(&_ir_svc, inc->incident_id));
    ASSERT(inc->recovery_completed);
    ASSERT_EQ(OZAYN_IR_STATE_VERIFIED, inc->state);
    ASSERT_EQ(1, _ir_svc.total_recoveries);
    return 0;
}

TEST(test_ir_recover_after_contain)
{
    _init_ir_svc();
    ozayn_ir_incident_t *inc = NULL;
    ozayn_ir_report(&_ir_svc, OZAYN_IR_TYPE_VAULT_COMPROMISE,
        OZAYN_IR_SEV_HIGH, "test", "", "", "", "", NULL, &inc);
    ozayn_ir_classify(&_ir_svc, inc->incident_id,
        OZAYN_IR_TYPE_VAULT_COMPROMISE, OZAYN_IR_SEV_HIGH);
    ozayn_ir_update_state(&_ir_svc, inc->incident_id, OZAYN_IR_STATE_CONTAINMENT_REQUIRED);
    ozayn_ir_contain(&_ir_svc, inc->incident_id, OZAYN_IR_CONTAIN_NONE);
    ASSERT_EQ(OZAYN_IR_OK, ozayn_ir_recover(&_ir_svc, inc->incident_id));
    ASSERT_EQ(OZAYN_IR_STATE_VERIFIED, inc->state);
    return 0;
}

TEST(test_ir_recover_null)
{
    ASSERT_EQ(OZAYN_IR_ERR_NULL, ozayn_ir_recover(NULL, "x"));
    return 0;
}

TEST(test_ir_recover_not_found)
{
    _init_ir_svc();
    ASSERT_EQ(OZAYN_IR_ERR_NOT_FOUND, ozayn_ir_recover(&_ir_svc, "NOPE"));
    return 0;
}

TEST(test_ir_recover_invalid_state)
{
    _init_ir_svc();
    ozayn_ir_incident_t *inc = NULL;
    ozayn_ir_report(&_ir_svc, OZAYN_IR_TYPE_UNKNOWN, OZAYN_IR_SEV_INFO,
        "test", "", "", "", "", NULL, &inc);
    /* DETECTED state -> cannot recover */
    ASSERT_EQ(OZAYN_IR_ERR_STATE_TRANSITION_INVALID,
        ozayn_ir_recover(&_ir_svc, inc->incident_id));
    return 0;
}

TEST(test_ir_recover_already_resolved)
{
    _init_ir_svc();
    ozayn_ir_incident_t *inc = NULL;
    ozayn_ir_report(&_ir_svc, OZAYN_IR_TYPE_UNKNOWN, OZAYN_IR_SEV_INFO,
        "test", "", "", "", "", NULL, &inc);
    ozayn_ir_classify(&_ir_svc, inc->incident_id, OZAYN_IR_TYPE_UNKNOWN, OZAYN_IR_SEV_INFO);
    ozayn_ir_update_state(&_ir_svc, inc->incident_id, OZAYN_IR_STATE_RECOVERY_REQUIRED);
    ozayn_ir_update_state(&_ir_svc, inc->incident_id, OZAYN_IR_STATE_RECOVERING);
    ozayn_ir_update_state(&_ir_svc, inc->incident_id, OZAYN_IR_STATE_VERIFIED);
    ozayn_ir_update_state(&_ir_svc, inc->incident_id, OZAYN_IR_STATE_RESOLVED);
    ASSERT_EQ(OZAYN_IR_ERR_ALREADY_RESOLVED,
        ozayn_ir_recover(&_ir_svc, inc->incident_id));
    return 0;
}

/* ============================================================
 * VERIFICATION TESTS
 * ============================================================ */

TEST(test_ir_verify_valid)
{
    _init_ir_svc();
    ozayn_ir_incident_t *inc = NULL;
    ozayn_ir_report(&_ir_svc, OZAYN_IR_TYPE_DATA_INTEGRITY_FAILURE,
        OZAYN_IR_SEV_HIGH, "test", "", "", "", "", NULL, &inc);
    ozayn_ir_classify(&_ir_svc, inc->incident_id,
        OZAYN_IR_TYPE_DATA_INTEGRITY_FAILURE, OZAYN_IR_SEV_HIGH);
    ozayn_ir_update_state(&_ir_svc, inc->incident_id, OZAYN_IR_STATE_RECOVERY_REQUIRED);
    ozayn_ir_recover(&_ir_svc, inc->incident_id);
    ASSERT_EQ(OZAYN_IR_OK, ozayn_ir_verify(&_ir_svc, inc->incident_id));
    return 0;
}

TEST(test_ir_verify_null)
{
    ASSERT_EQ(OZAYN_IR_ERR_NULL, ozayn_ir_verify(NULL, "x"));
    return 0;
}

TEST(test_ir_verify_not_found)
{
    _init_ir_svc();
    ASSERT_EQ(OZAYN_IR_ERR_NOT_FOUND, ozayn_ir_verify(&_ir_svc, "NOPE"));
    return 0;
}

TEST(test_ir_verify_invalid_state)
{
    _init_ir_svc();
    ozayn_ir_incident_t *inc = NULL;
    ozayn_ir_report(&_ir_svc, OZAYN_IR_TYPE_UNKNOWN, OZAYN_IR_SEV_INFO,
        "test", "", "", "", "", NULL, &inc);
    /* CLASSIFIED state -> cannot verify */
    ozayn_ir_classify(&_ir_svc, inc->incident_id, OZAYN_IR_TYPE_UNKNOWN, OZAYN_IR_SEV_INFO);
    ASSERT_EQ(OZAYN_IR_ERR_STATE_TRANSITION_INVALID,
        ozayn_ir_verify(&_ir_svc, inc->incident_id));
    return 0;
}

TEST(test_ir_verify_already_resolved)
{
    _init_ir_svc();
    ozayn_ir_incident_t *inc = NULL;
    ozayn_ir_report(&_ir_svc, OZAYN_IR_TYPE_UNKNOWN, OZAYN_IR_SEV_INFO,
        "test", "", "", "", "", NULL, &inc);
    ozayn_ir_classify(&_ir_svc, inc->incident_id, OZAYN_IR_TYPE_UNKNOWN, OZAYN_IR_SEV_INFO);
    ozayn_ir_update_state(&_ir_svc, inc->incident_id, OZAYN_IR_STATE_RECOVERY_REQUIRED);
    ozayn_ir_update_state(&_ir_svc, inc->incident_id, OZAYN_IR_STATE_RECOVERING);
    ozayn_ir_update_state(&_ir_svc, inc->incident_id, OZAYN_IR_STATE_VERIFIED);
    ozayn_ir_update_state(&_ir_svc, inc->incident_id, OZAYN_IR_STATE_RESOLVED);
    ASSERT_EQ(OZAYN_IR_ERR_ALREADY_RESOLVED,
        ozayn_ir_verify(&_ir_svc, inc->incident_id));
    return 0;
}

/* ============================================================
 * RESOLUTION TESTS
 * ============================================================ */

TEST(test_ir_resolve_valid)
{
    _init_ir_svc();
    ozayn_ir_incident_t *inc = NULL;
    ozayn_ir_report(&_ir_svc, OZAYN_IR_TYPE_CONFIG_VIOLATION,
        OZAYN_IR_SEV_LOW, "test", "", "", "", "", NULL, &inc);
    ozayn_ir_classify(&_ir_svc, inc->incident_id,
        OZAYN_IR_TYPE_CONFIG_VIOLATION, OZAYN_IR_SEV_LOW);
    ozayn_ir_update_state(&_ir_svc, inc->incident_id, OZAYN_IR_STATE_RECOVERY_REQUIRED);
    ozayn_ir_recover(&_ir_svc, inc->incident_id);
    ASSERT_EQ(OZAYN_IR_OK, ozayn_ir_resolve(&_ir_svc, inc->incident_id));
    ASSERT_EQ(OZAYN_IR_STATE_RESOLVED, inc->state);
    ASSERT_EQ(1, _ir_svc.total_incidents_resolved);
    return 0;
}

TEST(test_ir_resolve_null)
{
    ASSERT_EQ(OZAYN_IR_ERR_NULL, ozayn_ir_resolve(NULL, "x"));
    return 0;
}

TEST(test_ir_resolve_not_found)
{
    _init_ir_svc();
    ASSERT_EQ(OZAYN_IR_ERR_NOT_FOUND, ozayn_ir_resolve(&_ir_svc, "NOPE"));
    return 0;
}

TEST(test_ir_resolve_invalid_state)
{
    _init_ir_svc();
    ozayn_ir_incident_t *inc = NULL;
    ozayn_ir_report(&_ir_svc, OZAYN_IR_TYPE_UNKNOWN, OZAYN_IR_SEV_INFO,
        "test", "", "", "", "", NULL, &inc);
    /* DETECTED -> cannot resolve */
    ASSERT_EQ(OZAYN_IR_ERR_STATE_TRANSITION_INVALID,
        ozayn_ir_resolve(&_ir_svc, inc->incident_id));
    return 0;
}

TEST(test_ir_resolve_already_resolved)
{
    _init_ir_svc();
    ozayn_ir_incident_t *inc = NULL;
    ozayn_ir_report(&_ir_svc, OZAYN_IR_TYPE_UNKNOWN, OZAYN_IR_SEV_INFO,
        "test", "", "", "", "", NULL, &inc);
    ozayn_ir_classify(&_ir_svc, inc->incident_id, OZAYN_IR_TYPE_UNKNOWN, OZAYN_IR_SEV_INFO);
    ozayn_ir_update_state(&_ir_svc, inc->incident_id, OZAYN_IR_STATE_RECOVERY_REQUIRED);
    ozayn_ir_update_state(&_ir_svc, inc->incident_id, OZAYN_IR_STATE_RECOVERING);
    ozayn_ir_update_state(&_ir_svc, inc->incident_id, OZAYN_IR_STATE_VERIFIED);
    ozayn_ir_update_state(&_ir_svc, inc->incident_id, OZAYN_IR_STATE_RESOLVED);
    ASSERT_EQ(OZAYN_IR_ERR_ALREADY_RESOLVED,
        ozayn_ir_resolve(&_ir_svc, inc->incident_id));
    return 0;
}

/* ============================================================
 * FULL LIFECYCLE TESTS
 * ============================================================ */

TEST(test_ir_full_lifecycle_containment)
{
    _init_ir_svc();
    ozayn_ir_incident_t *inc = NULL;
    ASSERT_EQ(OZAYN_IR_OK, ozayn_ir_report(&_ir_svc,
        OZAYN_IR_TYPE_VAULT_COMPROMISE, OZAYN_IR_SEV_HIGH,
        "vault_monitor", "", "", "", "", NULL, &inc));

    /* Classify */
    ASSERT_EQ(OZAYN_IR_OK, ozayn_ir_classify(&_ir_svc, inc->incident_id,
        OZAYN_IR_TYPE_VAULT_COMPROMISE, OZAYN_IR_SEV_HIGH));
    ASSERT_EQ(OZAYN_IR_STATE_CLASSIFIED, inc->state);

    /* Require containment */
    ASSERT_EQ(OZAYN_IR_OK, ozayn_ir_update_state(&_ir_svc, inc->incident_id,
        OZAYN_IR_STATE_CONTAINMENT_REQUIRED));
    ASSERT_EQ(OZAYN_IR_STATE_CONTAINMENT_REQUIRED, inc->state);

    /* Contain */
    ASSERT_EQ(OZAYN_IR_OK, ozayn_ir_contain(&_ir_svc, inc->incident_id,
        OZAYN_IR_CONTAIN_NONE));
    ASSERT_EQ(OZAYN_IR_STATE_CONTAINED, inc->state);

    /* Recover */
    ASSERT_EQ(OZAYN_IR_OK, ozayn_ir_recover(&_ir_svc, inc->incident_id));
    ASSERT_EQ(OZAYN_IR_STATE_VERIFIED, inc->state);

    /* Verify */
    ASSERT_EQ(OZAYN_IR_OK, ozayn_ir_verify(&_ir_svc, inc->incident_id));

    /* Resolve */
    ASSERT_EQ(OZAYN_IR_OK, ozayn_ir_resolve(&_ir_svc, inc->incident_id));
    ASSERT_EQ(OZAYN_IR_STATE_RESOLVED, inc->state);
    return 0;
}

TEST(test_ir_full_lifecycle_recovery)
{
    _init_ir_svc();
    ozayn_ir_incident_t *inc = NULL;
    ozayn_ir_report(&_ir_svc, OZAYN_IR_TYPE_RESTORE_FAILURE,
        OZAYN_IR_SEV_MEDIUM, "backup_svc", "", "", "", "", NULL, &inc);

    ozayn_ir_classify(&_ir_svc, inc->incident_id,
        OZAYN_IR_TYPE_RESTORE_FAILURE, OZAYN_IR_SEV_MEDIUM);
    ozayn_ir_update_state(&_ir_svc, inc->incident_id, OZAYN_IR_STATE_RECOVERY_REQUIRED);
    ozayn_ir_recover(&_ir_svc, inc->incident_id);
    ozayn_ir_verify(&_ir_svc, inc->incident_id);
    ozayn_ir_resolve(&_ir_svc, inc->incident_id);
    ASSERT_EQ(OZAYN_IR_STATE_RESOLVED, inc->state);
    return 0;
}

/* ============================================================
 * LOCKDOWN TESTS
 * ============================================================ */

TEST(test_ir_lockdown_enter_exit)
{
    _init_ir_svc();
    ASSERT(!ozayn_ir_is_lockdown_active(&_ir_svc));
    ASSERT_EQ(OZAYN_IR_OK, ozayn_ir_enter_lockdown(&_ir_svc));
    ASSERT(ozayn_ir_is_lockdown_active(&_ir_svc));
    ASSERT_EQ(OZAYN_IR_COMPROMISE_LOCKDOWN, ozayn_ir_get_compromise_level(&_ir_svc));

    /* Exit requires no critical/high unresolved */
    ASSERT_EQ(OZAYN_IR_OK, ozayn_ir_exit_lockdown(&_ir_svc));
    ASSERT(!ozayn_ir_is_lockdown_active(&_ir_svc));
    return 0;
}

TEST(test_ir_lockdown_enter_null)
{
    ASSERT_EQ(OZAYN_IR_ERR_NULL, ozayn_ir_enter_lockdown(NULL));
    return 0;
}

TEST(test_ir_lockdown_exit_not_active)
{
    _init_ir_svc();
    ASSERT_EQ(OZAYN_IR_ERR_STATE_INVALID, ozayn_ir_exit_lockdown(&_ir_svc));
    return 0;
}

TEST(test_ir_lockdown_exit_critical_blocks)
{
    _init_ir_svc();
    ozayn_ir_enter_lockdown(&_ir_svc);

    /* Add unresolved critical incident */
    ozayn_ir_incident_t *inc = NULL;
    ozayn_ir_report(&_ir_svc, OZAYN_IR_TYPE_VAULT_COMPROMISE,
        OZAYN_IR_SEV_CRITICAL, "test", "", "", "", "", NULL, &inc);

    ASSERT_EQ(OZAYN_IR_ERR_RECOVERY_UNSAFE, ozayn_ir_exit_lockdown(&_ir_svc));
    ASSERT(ozayn_ir_is_lockdown_active(&_ir_svc));
    return 0;
}

TEST(test_ir_lockdown_exit_high_blocks)
{
    _init_ir_svc();
    ozayn_ir_enter_lockdown(&_ir_svc);

    ozayn_ir_incident_t *inc = NULL;
    ozayn_ir_report(&_ir_svc, OZAYN_IR_TYPE_KEY_COMPROMISE,
        OZAYN_IR_SEV_HIGH, "test", "", "", "", "", NULL, &inc);

    ASSERT_EQ(OZAYN_IR_ERR_RECOVERY_UNSAFE, ozayn_ir_exit_lockdown(&_ir_svc));
    return 0;
}

TEST(test_ir_lockdown_exit_after_resolve)
{
    _init_ir_svc();
    ozayn_ir_enter_lockdown(&_ir_svc);

    /* Add and resolve critical incident */
    ozayn_ir_incident_t *inc = NULL;
    ozayn_ir_report(&_ir_svc, OZAYN_IR_TYPE_VAULT_COMPROMISE,
        OZAYN_IR_SEV_CRITICAL, "test", "", "", "", "", NULL, &inc);
    ozayn_ir_classify(&_ir_svc, inc->incident_id,
        OZAYN_IR_TYPE_VAULT_COMPROMISE, OZAYN_IR_SEV_CRITICAL);
    ozayn_ir_update_state(&_ir_svc, inc->incident_id, OZAYN_IR_STATE_RECOVERY_REQUIRED);
    ozayn_ir_recover(&_ir_svc, inc->incident_id);
    ozayn_ir_resolve(&_ir_svc, inc->incident_id);

    ASSERT_EQ(OZAYN_IR_OK, ozayn_ir_exit_lockdown(&_ir_svc));
    ASSERT(!ozayn_ir_is_lockdown_active(&_ir_svc));
    return 0;
}

TEST(test_ir_lockdown_stats)
{
    _init_ir_svc();
    ASSERT_EQ(0, _ir_svc.total_lockdowns);
    ozayn_ir_enter_lockdown(&_ir_svc);
    ASSERT_EQ(1, _ir_svc.total_lockdowns);
    ozayn_ir_exit_lockdown(&_ir_svc);
    ozayn_ir_enter_lockdown(&_ir_svc);
    ASSERT_EQ(2, _ir_svc.total_lockdowns);
    return 0;
}

TEST(test_ir_lockdown_via_contain)
{
    _init_ir_svc();
    ozayn_ir_incident_t *inc = NULL;
    ozayn_ir_report(&_ir_svc, OZAYN_IR_TYPE_VAULT_COMPROMISE,
        OZAYN_IR_SEV_CRITICAL, "test", "", "", "", "", NULL, &inc);
    ozayn_ir_classify(&_ir_svc, inc->incident_id,
        OZAYN_IR_TYPE_VAULT_COMPROMISE, OZAYN_IR_SEV_CRITICAL);
    ozayn_ir_update_state(&_ir_svc, inc->incident_id, OZAYN_IR_STATE_CONTAINMENT_REQUIRED);
    ozayn_ir_contain(&_ir_svc, inc->incident_id, OZAYN_IR_CONTAIN_ENTER_LOCKDOWN);
    ASSERT(ozayn_ir_is_lockdown_active(&_ir_svc));
    return 0;
}

/* ============================================================
 * COMPROMISE LEVEL TESTS
 * ============================================================ */

TEST(test_ir_compromise_level_normal)
{
    _init_ir_svc();
    ASSERT_EQ(OZAYN_IR_COMPROMISE_NORMAL, ozayn_ir_get_compromise_level(&_ir_svc));
    return 0;
}

TEST(test_ir_compromise_level_null)
{
    ASSERT_EQ(OZAYN_IR_COMPROMISE_NORMAL, ozayn_ir_get_compromise_level(NULL));
    return 0;
}

TEST(test_ir_compromise_level_degraded)
{
    _init_ir_svc();
    ozayn_ir_report(&_ir_svc, OZAYN_IR_TYPE_UNKNOWN, OZAYN_IR_SEV_INFO,
        "test", "", "", "", "", NULL, NULL);
    ASSERT_EQ(OZAYN_IR_COMPROMISE_DEGRADED, ozayn_ir_get_compromise_level(&_ir_svc));
    return 0;
}

TEST(test_ir_compromise_level_suspicious)
{
    _init_ir_svc();
    ozayn_ir_report(&_ir_svc, OZAYN_IR_TYPE_UNKNOWN, OZAYN_IR_SEV_HIGH,
        "test", "", "", "", "", NULL, NULL);
    ASSERT_EQ(OZAYN_IR_COMPROMISE_SUSPICIOUS, ozayn_ir_get_compromise_level(&_ir_svc));
    return 0;
}

TEST(test_ir_compromise_level_lockdown)
{
    _init_ir_svc();
    ozayn_ir_enter_lockdown(&_ir_svc);
    ASSERT_EQ(OZAYN_IR_COMPROMISE_LOCKDOWN, ozayn_ir_get_compromise_level(&_ir_svc));
    return 0;
}

TEST(test_ir_auto_lockdown_threshold)
{
    _init_ir_svc();
    _ir_svc.policy.lockdown_threshold = 3;

    for (int i = 0; i < 3; i++) {
        char src[32];
        snprintf(src, sizeof(src), "src_%d", i);
        ozayn_ir_report(&_ir_svc, OZAYN_IR_TYPE_VAULT_COMPROMISE,
            OZAYN_IR_SEV_CRITICAL, src, "", "", "", "", NULL, NULL);
    }
    ASSERT(ozayn_ir_is_lockdown_active(&_ir_svc));
    return 0;
}

/* ============================================================
 * POLICY TESTS
 * ============================================================ */

TEST(test_ir_set_policy)
{
    _init_ir_svc();
    ozayn_ir_policy_t p = ozayn_ir_default_policy();
    p.auto_contain_critical = 0;
    p.lockdown_threshold = 10;
    ASSERT_EQ(OZAYN_IR_OK, ozayn_ir_set_policy(&_ir_svc, &p));
    const ozayn_ir_policy_t *got = ozayn_ir_get_policy(&_ir_svc);
    ASSERT_NOT_NULL(got);
    ASSERT_EQ(0, got->auto_contain_critical);
    ASSERT_EQ(10, got->lockdown_threshold);
    return 0;
}

TEST(test_ir_set_policy_null)
{
    ASSERT_EQ(OZAYN_IR_ERR_NULL, ozayn_ir_set_policy(NULL, NULL));
    return 0;
}

TEST(test_ir_set_policy_not_initialized)
{
    ozayn_ir_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_ir_policy_t p = ozayn_ir_default_policy();
    ASSERT_EQ(OZAYN_IR_ERR_NOT_INITIALIZED, ozayn_ir_set_policy(&svc, &p));
    return 0;
}

TEST(test_ir_get_policy_null)
{
    ASSERT_NULL(ozayn_ir_get_policy(NULL));
    return 0;
}

TEST(test_ir_get_policy_not_initialized)
{
    ozayn_ir_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ASSERT_NULL(ozayn_ir_get_policy(&svc));
    return 0;
}

TEST(test_ir_default_policy_values)
{
    ozayn_ir_policy_t p = ozayn_ir_default_policy();
    ASSERT_EQ(OZAYN_IR_MAX_INCIDENTS, p.max_incidents);
    ASSERT_EQ(1, p.auto_contain_critical);
    ASSERT_EQ(1, p.require_mfa_for_recovery);
    ASSERT_EQ(5, p.lockdown_threshold);
    ASSERT_EQ(60, p.dedup_window_seconds);
    ASSERT_EQ(OZAYN_IR_SEV_CRITICAL, p.min_lockdown_severity);
    return 0;
}

/* ============================================================
 * NAME HELPERS TESTS
 * ============================================================ */

TEST(test_ir_result_name)
{
    ASSERT_STR_EQ("OK", ozayn_ir_result_name(OZAYN_IR_OK));
    ASSERT_STR_EQ("ERR_NULL", ozayn_ir_result_name(OZAYN_IR_ERR_NULL));
    ASSERT_STR_EQ("UNKNOWN", ozayn_ir_result_name((ozayn_ir_result_t)9999));
    return 0;
}

TEST(test_ir_type_name)
{
    ASSERT_STR_EQ("AUTHENTICATION_ATTACK", ozayn_ir_type_name(OZAYN_IR_TYPE_AUTHENTICATION_ATTACK));
    ASSERT_STR_EQ("VAULT_COMPROMISE", ozayn_ir_type_name(OZAYN_IR_TYPE_VAULT_COMPROMISE));
    ASSERT_STR_EQ("UNKNOWN", ozayn_ir_type_name(OZAYN_IR_TYPE_UNKNOWN));
    ASSERT_STR_EQ("UNKNOWN", ozayn_ir_type_name((ozayn_ir_type_t)999));
    return 0;
}

TEST(test_ir_severity_name)
{
    ASSERT_STR_EQ("INFO", ozayn_ir_severity_name(OZAYN_IR_SEV_INFO));
    ASSERT_STR_EQ("LOW", ozayn_ir_severity_name(OZAYN_IR_SEV_LOW));
    ASSERT_STR_EQ("MEDIUM", ozayn_ir_severity_name(OZAYN_IR_SEV_MEDIUM));
    ASSERT_STR_EQ("HIGH", ozayn_ir_severity_name(OZAYN_IR_SEV_HIGH));
    ASSERT_STR_EQ("CRITICAL", ozayn_ir_severity_name(OZAYN_IR_SEV_CRITICAL));
    ASSERT_STR_EQ("UNKNOWN", ozayn_ir_severity_name((ozayn_ir_severity_t)999));
    return 0;
}

TEST(test_ir_state_name)
{
    ASSERT_STR_EQ("DETECTED", ozayn_ir_state_name(OZAYN_IR_STATE_DETECTED));
    ASSERT_STR_EQ("CLASSIFIED", ozayn_ir_state_name(OZAYN_IR_STATE_CLASSIFIED));
    ASSERT_STR_EQ("RESOLVED", ozayn_ir_state_name(OZAYN_IR_STATE_RESOLVED));
    ASSERT_STR_EQ("RECOVERY_FAILED", ozayn_ir_state_name(OZAYN_IR_STATE_RECOVERY_FAILED));
    ASSERT_STR_EQ("UNKNOWN", ozayn_ir_state_name((ozayn_ir_state_t)999));
    return 0;
}

TEST(test_ir_compromise_level_name)
{
    ASSERT_STR_EQ("NORMAL", ozayn_ir_compromise_level_name(OZAYN_IR_COMPROMISE_NORMAL));
    ASSERT_STR_EQ("LOCKDOWN", ozayn_ir_compromise_level_name(OZAYN_IR_COMPROMISE_LOCKDOWN));
    ASSERT_STR_EQ("UNKNOWN", ozayn_ir_compromise_level_name((ozayn_ir_compromise_level_t)999));
    return 0;
}

TEST(test_ir_containment_action_name)
{
    ASSERT_STR_EQ("NONE", ozayn_ir_containment_action_name(OZAYN_IR_CONTAIN_NONE));
    ASSERT_STR_EQ("REVOKE_SESSION", ozayn_ir_containment_action_name(OZAYN_IR_CONTAIN_REVOKE_SESSION));
    ASSERT_STR_EQ("SUSPEND_IDENTITY", ozayn_ir_containment_action_name(OZAYN_IR_CONTAIN_SUSPEND_IDENTITY));
    ASSERT_STR_EQ("REVOKE_IDENTITY", ozayn_ir_containment_action_name(OZAYN_IR_CONTAIN_REVOKE_IDENTITY));
    ASSERT_STR_EQ("REVOKE_KEY", ozayn_ir_containment_action_name(OZAYN_IR_CONTAIN_REVOKE_KEY));
    ASSERT_STR_EQ("RESTRICT_RESOURCE", ozayn_ir_containment_action_name(OZAYN_IR_CONTAIN_RESTRICT_RESOURCE));
    ASSERT_STR_EQ("ENTER_LOCKDOWN", ozayn_ir_containment_action_name(OZAYN_IR_CONTAIN_ENTER_LOCKDOWN));
    ASSERT_STR_EQ("UNKNOWN", ozayn_ir_containment_action_name((ozayn_ir_containment_action_t)999));
    return 0;
}

/* ============================================================
 * DEDUPLICATION TESTS
 * ============================================================ */

TEST(test_ir_dedup_same_type_and_identity)
{
    _init_ir_svc();
    _ir_svc.policy.dedup_window_seconds = 300;

    ozayn_ir_incident_t *inc1 = NULL;
    ASSERT_EQ(OZAYN_IR_OK, ozayn_ir_report(&_ir_svc,
        OZAYN_IR_TYPE_AUTHENTICATION_ATTACK, OZAYN_IR_SEV_HIGH,
        "test", "id-001", "", "", "", NULL, &inc1));

    /* Same type + same identity within window = duplicate */
    ozayn_ir_incident_t *inc2 = NULL;
    ASSERT_EQ(OZAYN_IR_ERR_DUPLICATE, ozayn_ir_report(&_ir_svc,
        OZAYN_IR_TYPE_AUTHENTICATION_ATTACK, OZAYN_IR_SEV_HIGH,
        "test", "id-001", "", "", "", NULL, &inc2));
    ASSERT_EQ(1, _ir_svc.incident_count);
    return 0;
}

TEST(test_ir_dedup_different_identity)
{
    _init_ir_svc();
    _ir_svc.policy.dedup_window_seconds = 300;

    ozayn_ir_report(&_ir_svc, OZAYN_IR_TYPE_AUTHENTICATION_ATTACK,
        OZAYN_IR_SEV_HIGH, "test", "id-001", "", "", "", NULL, NULL);

    /* Same type but different identity = not duplicate */
    ASSERT_EQ(OZAYN_IR_OK, ozayn_ir_report(&_ir_svc,
        OZAYN_IR_TYPE_AUTHENTICATION_ATTACK, OZAYN_IR_SEV_HIGH,
        "test", "id-002", "", "", "", NULL, NULL));
    ASSERT_EQ(2, _ir_svc.incident_count);
    return 0;
}

TEST(test_ir_dedup_different_type)
{
    _init_ir_svc();
    _ir_svc.policy.dedup_window_seconds = 300;

    ozayn_ir_report(&_ir_svc, OZAYN_IR_TYPE_AUTHENTICATION_ATTACK,
        OZAYN_IR_SEV_HIGH, "test", "id-001", "", "", "", NULL, NULL);

    /* Different type = not duplicate */
    ASSERT_EQ(OZAYN_IR_OK, ozayn_ir_report(&_ir_svc,
        OZAYN_IR_TYPE_KEY_COMPROMISE, OZAYN_IR_SEV_HIGH,
        "test", "id-001", "", "", "", NULL, NULL));
    ASSERT_EQ(2, _ir_svc.incident_count);
    return 0;
}

TEST(test_ir_dedup_resolved_not_counted)
{
    _init_ir_svc();
    _ir_svc.policy.dedup_window_seconds = 300;

    ozayn_ir_incident_t *inc = NULL;
    ozayn_ir_report(&_ir_svc, OZAYN_IR_TYPE_AUTHENTICATION_ATTACK,
        OZAYN_IR_SEV_HIGH, "test", "id-001", "", "", "", NULL, &inc);

    /* Resolve the first incident */
    ozayn_ir_classify(&_ir_svc, inc->incident_id,
        OZAYN_IR_TYPE_AUTHENTICATION_ATTACK, OZAYN_IR_SEV_HIGH);
    ozayn_ir_update_state(&_ir_svc, inc->incident_id, OZAYN_IR_STATE_RECOVERY_REQUIRED);
    ozayn_ir_recover(&_ir_svc, inc->incident_id);
    ozayn_ir_resolve(&_ir_svc, inc->incident_id);

    /* Resolved incident not counted for dedup */
    ASSERT_EQ(OZAYN_IR_OK, ozayn_ir_report(&_ir_svc,
        OZAYN_IR_TYPE_AUTHENTICATION_ATTACK, OZAYN_IR_SEV_HIGH,
        "test", "id-001", "", "", "", NULL, NULL));
    ASSERT_EQ(2, _ir_svc.incident_count);
    return 0;
}

/* ============================================================
 * INCIDENT TYPES COVERAGE
 * ============================================================ */

TEST(test_ir_all_types_reportable)
{
    _init_ir_svc();
    for (int t = 0; t <= OZAYN_IR_TYPE_UNKNOWN; t++) {
        char src[32];
        snprintf(src, sizeof(src), "type_%d", t);
        ASSERT_EQ(OZAYN_IR_OK, ozayn_ir_report(&_ir_svc,
            (ozayn_ir_type_t)t, OZAYN_IR_SEV_LOW,
            src, "", "", "", "", NULL, NULL));
    }
    ASSERT_EQ(OZAYN_IR_TYPE_UNKNOWN + 1, _ir_svc.incident_count);
    return 0;
}

TEST(test_ir_all_severities_reportable)
{
    _init_ir_svc();
    for (int s = 0; s <= OZAYN_IR_SEV_CRITICAL; s++) {
        char src[32];
        snprintf(src, sizeof(src), "sev_%d", s);
        ASSERT_EQ(OZAYN_IR_OK, ozayn_ir_report(&_ir_svc,
            OZAYN_IR_TYPE_UNKNOWN, (ozayn_ir_severity_t)s,
            src, "", "", "", "", NULL, NULL));
    }
    ASSERT_EQ(OZAYN_IR_SEV_CRITICAL + 1, _ir_svc.incident_count);
    return 0;
}

/* ============================================================
 * MULTIPLE INCIDENTS INTERACTION
 * ============================================================ */

TEST(test_ir_multiple_incidents_independent)
{
    _init_ir_svc();
    ozayn_ir_incident_t *inc1 = NULL, *inc2 = NULL;
    ozayn_ir_report(&_ir_svc, OZAYN_IR_TYPE_AUTHENTICATION_ATTACK,
        OZAYN_IR_SEV_LOW, "s1", "", "", "", "", NULL, &inc1);
    ozayn_ir_report(&_ir_svc, OZAYN_IR_TYPE_KEY_COMPROMISE,
        OZAYN_IR_SEV_HIGH, "s2", "", "", "", "", NULL, &inc2);

    /* Resolve inc1 */
    ozayn_ir_classify(&_ir_svc, inc1->incident_id,
        OZAYN_IR_TYPE_AUTHENTICATION_ATTACK, OZAYN_IR_SEV_LOW);
    ozayn_ir_update_state(&_ir_svc, inc1->incident_id, OZAYN_IR_STATE_RECOVERY_REQUIRED);
    ozayn_ir_recover(&_ir_svc, inc1->incident_id);
    ozayn_ir_resolve(&_ir_svc, inc1->incident_id);

    /* inc2 still active */
    ASSERT_EQ(OZAYN_IR_STATE_DETECTED, inc2->state);
    return 0;
}

TEST(test_ir_compromise_level_changes)
{
    _init_ir_svc();
    ASSERT_EQ(OZAYN_IR_COMPROMISE_NORMAL, ozayn_ir_get_compromise_level(&_ir_svc));

    /* Info -> DEGRADED */
    ozayn_ir_incident_t *inc1 = NULL;
    ozayn_ir_report(&_ir_svc, OZAYN_IR_TYPE_UNKNOWN, OZAYN_IR_SEV_INFO,
        "s", "", "", "", "", NULL, &inc1);
    ASSERT_EQ(OZAYN_IR_COMPROMISE_DEGRADED, ozayn_ir_get_compromise_level(&_ir_svc));

    /* High -> SUSPICIOUS */
    ozayn_ir_incident_t *inc2 = NULL;
    ozayn_ir_report(&_ir_svc, OZAYN_IR_TYPE_UNKNOWN, OZAYN_IR_SEV_HIGH,
        "s", "", "", "", "", NULL, &inc2);
    ASSERT_EQ(OZAYN_IR_COMPROMISE_SUSPICIOUS, ozayn_ir_get_compromise_level(&_ir_svc));

    /* Resolve inc2 */
    ozayn_ir_classify(&_ir_svc, inc2->incident_id, OZAYN_IR_TYPE_UNKNOWN, OZAYN_IR_SEV_HIGH);
    ozayn_ir_update_state(&_ir_svc, inc2->incident_id, OZAYN_IR_STATE_RECOVERY_REQUIRED);
    ozayn_ir_recover(&_ir_svc, inc2->incident_id);
    ozayn_ir_resolve(&_ir_svc, inc2->incident_id);

    /* Back to DEGRADED (inc1 still active) */
    ASSERT_EQ(OZAYN_IR_COMPROMISE_DEGRADED, ozayn_ir_get_compromise_level(&_ir_svc));

    /* Resolve inc1 */
    ozayn_ir_classify(&_ir_svc, inc1->incident_id, OZAYN_IR_TYPE_UNKNOWN, OZAYN_IR_SEV_INFO);
    ozayn_ir_update_state(&_ir_svc, inc1->incident_id, OZAYN_IR_STATE_RECOVERY_REQUIRED);
    ozayn_ir_recover(&_ir_svc, inc1->incident_id);
    ozayn_ir_resolve(&_ir_svc, inc1->incident_id);

    ASSERT_EQ(OZAYN_IR_COMPROMISE_NORMAL, ozayn_ir_get_compromise_level(&_ir_svc));
    return 0;
}

/* ============================================================
 * RESOURCE LIMITS
 * ============================================================ */

TEST(test_ir_resource_limit_respected)
{
    _init_ir_svc();
    _ir_svc.policy.max_incidents = 5;
    for (int i = 0; i < 5; i++) {
        char src[32];
        snprintf(src, sizeof(src), "r_%d", i);
        ASSERT_EQ(OZAYN_IR_OK, ozayn_ir_report(&_ir_svc,
            OZAYN_IR_TYPE_UNKNOWN, OZAYN_IR_SEV_INFO,
            src, "", "", "", "", NULL, NULL));
    }
    ASSERT_EQ(OZAYN_IR_ERR_STORAGE_FULL, ozayn_ir_report(&_ir_svc,
        OZAYN_IR_TYPE_UNKNOWN, OZAYN_IR_SEV_INFO,
        "overflow", "", "", "", "", NULL, NULL));
    return 0;
}

/* ============================================================
 * AUDIT INTEGRATION
 * ============================================================ */

TEST(test_ir_audit_events_generated)
{
    _init_ir_svc();
    int before = (int)ozayn_audit_count(&_audit_svc);

    ozayn_ir_incident_t *inc = NULL;
    ozayn_ir_report(&_ir_svc, OZAYN_IR_TYPE_AUTHENTICATION_ATTACK,
        OZAYN_IR_SEV_HIGH, "test", "", "", "", "", NULL, &inc);

    ASSERT((int)ozayn_audit_count(&_audit_svc) > before);
    return 0;
}

TEST(test_ir_audit_classify_generates_event)
{
    _init_ir_svc();
    ozayn_ir_incident_t *inc = NULL;
    ozayn_ir_report(&_ir_svc, OZAYN_IR_TYPE_UNKNOWN, OZAYN_IR_SEV_INFO,
        "test", "", "", "", "", NULL, &inc);
    int before = (int)ozayn_audit_count(&_audit_svc);
    ozayn_ir_classify(&_ir_svc, inc->incident_id, OZAYN_IR_TYPE_UNKNOWN, OZAYN_IR_SEV_INFO);
    ASSERT((int)ozayn_audit_count(&_audit_svc) > before);
    return 0;
}

TEST(test_ir_audit_containment_generates_event)
{
    _init_ir_svc();
    ozayn_ir_incident_t *inc = NULL;
    ozayn_ir_report(&_ir_svc, OZAYN_IR_TYPE_UNKNOWN, OZAYN_IR_SEV_LOW,
        "test", "", "", "", "", NULL, &inc);
    ozayn_ir_classify(&_ir_svc, inc->incident_id, OZAYN_IR_TYPE_UNKNOWN, OZAYN_IR_SEV_LOW);
    ozayn_ir_update_state(&_ir_svc, inc->incident_id, OZAYN_IR_STATE_CONTAINMENT_REQUIRED);
    int before = (int)ozayn_audit_count(&_audit_svc);
    ozayn_ir_contain(&_ir_svc, inc->incident_id, OZAYN_IR_CONTAIN_NONE);
    ASSERT((int)ozayn_audit_count(&_audit_svc) > before);
    return 0;
}

TEST(test_ir_audit_recovery_generates_event)
{
    _init_ir_svc();
    ozayn_ir_incident_t *inc = NULL;
    ozayn_ir_report(&_ir_svc, OZAYN_IR_TYPE_UNKNOWN, OZAYN_IR_SEV_LOW,
        "test", "", "", "", "", NULL, &inc);
    ozayn_ir_classify(&_ir_svc, inc->incident_id, OZAYN_IR_TYPE_UNKNOWN, OZAYN_IR_SEV_LOW);
    ozayn_ir_update_state(&_ir_svc, inc->incident_id, OZAYN_IR_STATE_RECOVERY_REQUIRED);
    int before = (int)ozayn_audit_count(&_audit_svc);
    ozayn_ir_recover(&_ir_svc, inc->incident_id);
    ASSERT((int)ozayn_audit_count(&_audit_svc) > before);
    return 0;
}

TEST(test_ir_audit_resolve_generates_event)
{
    _init_ir_svc();
    ozayn_ir_incident_t *inc = NULL;
    ozayn_ir_report(&_ir_svc, OZAYN_IR_TYPE_UNKNOWN, OZAYN_IR_SEV_LOW,
        "test", "", "", "", "", NULL, &inc);
    ozayn_ir_classify(&_ir_svc, inc->incident_id, OZAYN_IR_TYPE_UNKNOWN, OZAYN_IR_SEV_LOW);
    ozayn_ir_update_state(&_ir_svc, inc->incident_id, OZAYN_IR_STATE_RECOVERY_REQUIRED);
    ozayn_ir_recover(&_ir_svc, inc->incident_id);
    int before = (int)ozayn_audit_count(&_audit_svc);
    ozayn_ir_resolve(&_ir_svc, inc->incident_id);
    ASSERT((int)ozayn_audit_count(&_audit_svc) > before);
    return 0;
}

/* ============================================================
 * SPECIFIC INCIDENT TYPE TESTS
 * ============================================================ */

TEST(test_ir_auth_attack_incident)
{
    _init_ir_svc();
    ozayn_ir_incident_t *inc = NULL;
    ASSERT_EQ(OZAYN_IR_OK, ozayn_ir_report(&_ir_svc,
        OZAYN_IR_TYPE_AUTHENTICATION_ATTACK, OZAYN_IR_SEV_HIGH,
        "auth_monitor", "", "", "", "Multiple failed logins", NULL, &inc));
    ASSERT_EQ(OZAYN_IR_TYPE_AUTHENTICATION_ATTACK, inc->incident_type);
    ASSERT_EQ(OZAYN_IR_SEV_HIGH, inc->severity);
    return 0;
}

TEST(test_ir_credential_compromise_incident)
{
    _init_ir_svc();
    ozayn_identity_t id = _create_identity("cred_user");
    ozayn_ir_incident_t *inc = NULL;
    ASSERT_EQ(OZAYN_IR_OK, ozayn_ir_report(&_ir_svc,
        OZAYN_IR_TYPE_CREDENTIAL_COMPROMISE, OZAYN_IR_SEV_CRITICAL,
        "credential_svc", id.id, "", "", "Password found in breach", NULL, &inc));
    ASSERT_EQ(OZAYN_IR_TYPE_CREDENTIAL_COMPROMISE, inc->incident_type);
    return 0;
}

TEST(test_ir_privilege_escalation_incident)
{
    _init_ir_svc();
    ozayn_ir_incident_t *inc = NULL;
    ASSERT_EQ(OZAYN_IR_OK, ozayn_ir_report(&_ir_svc,
        OZAYN_IR_TYPE_PRIVILEGE_ESCALATION, OZAYN_IR_SEV_CRITICAL,
        "rbac_monitor", "id-001", "", "", "User gained admin access", NULL, &inc));
    ASSERT_EQ(OZAYN_IR_TYPE_PRIVILEGE_ESCALATION, inc->incident_type);
    return 0;
}

TEST(test_ir_key_compromise_incident)
{
    _init_ir_svc();
    ozayn_ir_incident_t *inc = NULL;
    ASSERT_EQ(OZAYN_IR_OK, ozayn_ir_report(&_ir_svc,
        OZAYN_IR_TYPE_KEY_COMPROMISE, OZAYN_IR_SEV_CRITICAL,
        "key_monitor", "", "", "", "Key leaked to untrusted path", NULL, &inc));
    ASSERT_EQ(OZAYN_IR_TYPE_KEY_COMPROMISE, inc->incident_type);
    return 0;
}

TEST(test_ir_vault_compromise_incident)
{
    _init_ir_svc();
    ozayn_ir_incident_t *inc = NULL;
    ASSERT_EQ(OZAYN_IR_OK, ozayn_ir_report(&_ir_svc,
        OZAYN_IR_TYPE_VAULT_COMPROMISE, OZAYN_IR_SEV_CRITICAL,
        "vault_monitor", "", "", "", "Vault integrity check failed", NULL, &inc));
    ASSERT_EQ(OZAYN_IR_TYPE_VAULT_COMPROMISE, inc->incident_type);
    return 0;
}

TEST(test_ir_data_integrity_incident)
{
    _init_ir_svc();
    ozayn_ir_incident_t *inc = NULL;
    ASSERT_EQ(OZAYN_IR_OK, ozayn_ir_report(&_ir_svc,
        OZAYN_IR_TYPE_DATA_INTEGRITY_FAILURE, OZAYN_IR_SEV_HIGH,
        "data_monitor", "", "", "res-001", "Checksum mismatch", NULL, &inc));
    ASSERT_STR_EQ("res-001", inc->resource_id);
    return 0;
}

TEST(test_ir_audit_integrity_incident)
{
    _init_ir_svc();
    ozayn_ir_incident_t *inc = NULL;
    ASSERT_EQ(OZAYN_IR_OK, ozayn_ir_report(&_ir_svc,
        OZAYN_IR_TYPE_AUDIT_INTEGRITY_FAILURE, OZAYN_IR_SEV_CRITICAL,
        "audit_monitor", "", "", "", "Audit log tampered", NULL, &inc));
    ASSERT_EQ(OZAYN_IR_TYPE_AUDIT_INTEGRITY_FAILURE, inc->incident_type);
    return 0;
}

/* ============================================================
 * VERSION TRACKING
 * ============================================================ */

TEST(test_ir_version_increments)
{
    _init_ir_svc();
    ozayn_ir_incident_t *inc = NULL;
    ozayn_ir_report(&_ir_svc, OZAYN_IR_TYPE_UNKNOWN, OZAYN_IR_SEV_INFO,
        "test", "", "", "", "", NULL, &inc);
    ASSERT_EQ(1, inc->incident_version);
    ozayn_ir_classify(&_ir_svc, inc->incident_id, OZAYN_IR_TYPE_UNKNOWN, OZAYN_IR_SEV_INFO);
    ASSERT_EQ(2, inc->incident_version);
    ozayn_ir_update_state(&_ir_svc, inc->incident_id, OZAYN_IR_STATE_RECOVERY_REQUIRED);
    ASSERT_EQ(3, inc->incident_version);
    return 0;
}

/* ============================================================
 * TIMESTAMP TRACKING
 * ============================================================ */

TEST(test_ir_timestamps_updated)
{
    _init_ir_svc();
    ozayn_ir_incident_t *inc = NULL;
    ozayn_ir_report(&_ir_svc, OZAYN_IR_TYPE_UNKNOWN, OZAYN_IR_SEV_INFO,
        "test", "", "", "", "", NULL, &inc);
    time_t t1 = inc->last_updated;

    /* Small delay to ensure timestamp changes */
    struct timespec ts = {0, 10000000}; /* 10ms */
    nanosleep(&ts, NULL);

    ozayn_ir_classify(&_ir_svc, inc->incident_id, OZAYN_IR_TYPE_UNKNOWN, OZAYN_IR_SEV_INFO);
    ASSERT(inc->last_updated >= t1);
    return 0;
}

/* ============================================================
 * CONCURRENT TYPE CLASSIFICATION
 * ============================================================ */

TEST(test_ir_classify_type_affects_type_name)
{
    _init_ir_svc();
    ozayn_ir_incident_t *inc = NULL;
    ozayn_ir_report(&_ir_svc, OZAYN_IR_TYPE_SUSPICIOUS_ACTIVITY,
        OZAYN_IR_SEV_LOW, "test", "", "", "", "", NULL, &inc);
    ozayn_ir_classify(&_ir_svc, inc->incident_id,
        OZAYN_IR_TYPE_VAULT_COMPROMISE, OZAYN_IR_SEV_CRITICAL);
    ASSERT_STR_EQ("VAULT_COMPROMISE", ozayn_ir_type_name(inc->incident_type));
    return 0;
}

/* ============================================================
 * GLOBAL ACCESSOR
 * ============================================================ */

TEST(test_ir_global_not_null_after_init)
{
    ozayn_ir_service_t *g = ozayn_ir_get_global();
    ASSERT_NOT_NULL(g);
    return 0;
}

TEST(test_ir_global_is_static)
{
    ozayn_ir_service_t *g1 = ozayn_ir_get_global();
    ozayn_ir_service_t *g2 = ozayn_ir_get_global();
    ASSERT(g1 == g2);
    return 0;
}

/* ============================================================
 * FULL CONTAINMENT LIFECYCLE WITH SESSION
 * ============================================================ */

TEST(test_ir_full_session_compromise_lifecycle)
{
    _init_ir_svc();
    ozayn_sess_t sess = _create_session_for("hijack_user");

    ozayn_ir_incident_t *inc = NULL;
    ASSERT_EQ(OZAYN_IR_OK, ozayn_ir_report(&_ir_svc,
        OZAYN_IR_TYPE_SESSION_COMPROMISE, OZAYN_IR_SEV_HIGH,
        "session_monitor", "", sess.id, "", "Session stolen", NULL, &inc));

    ozayn_ir_classify(&_ir_svc, inc->incident_id,
        OZAYN_IR_TYPE_SESSION_COMPROMISE, OZAYN_IR_SEV_HIGH);
    ozayn_ir_update_state(&_ir_svc, inc->incident_id, OZAYN_IR_STATE_CONTAINMENT_REQUIRED);
    ASSERT_EQ(OZAYN_IR_OK, ozayn_ir_contain(&_ir_svc, inc->incident_id,
        OZAYN_IR_CONTAIN_REVOKE_SESSION));
    ASSERT(inc->containment_completed);

    ozayn_ir_recover(&_ir_svc, inc->incident_id);
    ozayn_ir_verify(&_ir_svc, inc->incident_id);
    ozayn_ir_resolve(&_ir_svc, inc->incident_id);
    ASSERT_EQ(OZAYN_IR_STATE_RESOLVED, inc->state);
    return 0;
}

/* ============================================================
 * FULL IDENTITY COMPROMISE LIFECYCLE
 * ============================================================ */

TEST(test_ir_full_identity_compromise_lifecycle)
{
    _init_ir_svc();
    ozayn_identity_t id = _create_identity("compromised_user");

    ozayn_ir_incident_t *inc = NULL;
    ASSERT_EQ(OZAYN_IR_OK, ozayn_ir_report(&_ir_svc,
        OZAYN_IR_TYPE_IDENTITY_COMPROMISE, OZAYN_IR_SEV_HIGH,
        "id_monitor", id.id, "", "", "Identity used from unknown device", NULL, &inc));

    ozayn_ir_classify(&_ir_svc, inc->incident_id,
        OZAYN_IR_TYPE_IDENTITY_COMPROMISE, OZAYN_IR_SEV_HIGH);
    ozayn_ir_update_state(&_ir_svc, inc->incident_id, OZAYN_IR_STATE_CONTAINMENT_REQUIRED);
    ASSERT_EQ(OZAYN_IR_OK, ozayn_ir_contain(&_ir_svc, inc->incident_id,
        OZAYN_IR_CONTAIN_SUSPEND_IDENTITY));
    ASSERT(inc->containment_completed);

    ozayn_ir_recover(&_ir_svc, inc->incident_id);
    ozayn_ir_verify(&_ir_svc, inc->incident_id);
    ozayn_ir_resolve(&_ir_svc, inc->incident_id);
    ASSERT_EQ(OZAYN_IR_STATE_RESOLVED, inc->state);
    return 0;
}

/* ============================================================
 * RUNNER
 * ============================================================ */

int run_incident_tests(void)
{
    _setup_deps();
    printf("\n  --- INCIDENT RESPONSE TESTS ---\n");

    /* Lifecycle */
    RUN(test_ir_service_init_valid);
    RUN(test_ir_service_init_null);
    RUN(test_ir_service_init_null_config);
    RUN(test_ir_service_init_already_initialized);
    RUN(test_ir_service_shutdown_null);
    RUN(test_ir_service_shutdown_reinit);
    RUN(test_ir_service_default_policy);
    RUN(test_ir_global_accessor);
    RUN(test_ir_is_initialized_null);

    /* Reporting */
    RUN(test_ir_report_basic);
    RUN(test_ir_report_null_svc);
    RUN(test_ir_report_not_initialized);
    RUN(test_ir_report_invalid_type);
    RUN(test_ir_report_invalid_severity);
    RUN(test_ir_report_empty_source);
    RUN(test_ir_report_null_source);
    RUN(test_ir_report_no_out_ptr);
    RUN(test_ir_report_multiple_incidents);
    RUN(test_ir_report_stats);
    RUN(test_ir_report_storage_full);

    /* Query */
    RUN(test_ir_get_valid);
    RUN(test_ir_get_null);
    RUN(test_ir_get_not_initialized);
    RUN(test_ir_get_invalid_id);
    RUN(test_ir_get_not_found);
    RUN(test_ir_list_all);
    RUN(test_ir_list_filtered);
    RUN(test_ir_list_empty);
    RUN(test_ir_list_null);
    RUN(test_ir_list_max_count);

    /* Classify */
    RUN(test_ir_classify_valid);
    RUN(test_ir_classify_null);
    RUN(test_ir_classify_not_found);
    RUN(test_ir_classify_invalid_type);
    RUN(test_ir_classify_invalid_severity);
    RUN(test_ir_classify_already_resolved);

    /* State transitions */
    RUN(test_ir_state_transition_valid);
    RUN(test_ir_state_transition_full_containment_path);
    RUN(test_ir_state_transition_full_recovery_path);
    RUN(test_ir_update_state_valid);
    RUN(test_ir_update_state_invalid_transition);
    RUN(test_ir_update_state_already_resolved);
    RUN(test_ir_update_state_null);
    RUN(test_ir_update_state_not_found);

    /* Containment */
    RUN(test_ir_contain_none);
    RUN(test_ir_contain_revoke_session);
    RUN(test_ir_contain_suspend_identity);
    RUN(test_ir_contain_revoke_identity);
    RUN(test_ir_contain_enter_lockdown);
    RUN(test_ir_contain_null);
    RUN(test_ir_contain_not_found);
    RUN(test_ir_contain_already_resolved);
    RUN(test_ir_contain_no_session);
    RUN(test_ir_contain_no_identity);
    RUN(test_ir_contain_stats);

    /* Recovery */
    RUN(test_ir_recover_valid);
    RUN(test_ir_recover_after_contain);
    RUN(test_ir_recover_null);
    RUN(test_ir_recover_not_found);
    RUN(test_ir_recover_invalid_state);
    RUN(test_ir_recover_already_resolved);

    /* Verification */
    RUN(test_ir_verify_valid);
    RUN(test_ir_verify_null);
    RUN(test_ir_verify_not_found);
    RUN(test_ir_verify_invalid_state);
    RUN(test_ir_verify_already_resolved);

    /* Resolution */
    RUN(test_ir_resolve_valid);
    RUN(test_ir_resolve_null);
    RUN(test_ir_resolve_not_found);
    RUN(test_ir_resolve_invalid_state);
    RUN(test_ir_resolve_already_resolved);

    /* Full lifecycle */
    RUN(test_ir_full_lifecycle_containment);
    RUN(test_ir_full_lifecycle_recovery);

    /* Lockdown */
    RUN(test_ir_lockdown_enter_exit);
    RUN(test_ir_lockdown_enter_null);
    RUN(test_ir_lockdown_exit_not_active);
    RUN(test_ir_lockdown_exit_critical_blocks);
    RUN(test_ir_lockdown_exit_high_blocks);
    RUN(test_ir_lockdown_exit_after_resolve);
    RUN(test_ir_lockdown_stats);
    RUN(test_ir_lockdown_via_contain);

    /* Compromise level */
    RUN(test_ir_compromise_level_normal);
    RUN(test_ir_compromise_level_null);
    RUN(test_ir_compromise_level_degraded);
    RUN(test_ir_compromise_level_suspicious);
    RUN(test_ir_compromise_level_lockdown);
    RUN(test_ir_auto_lockdown_threshold);

    /* Policy */
    RUN(test_ir_set_policy);
    RUN(test_ir_set_policy_null);
    RUN(test_ir_set_policy_not_initialized);
    RUN(test_ir_get_policy_null);
    RUN(test_ir_get_policy_not_initialized);
    RUN(test_ir_default_policy_values);

    /* Name helpers */
    RUN(test_ir_result_name);
    RUN(test_ir_type_name);
    RUN(test_ir_severity_name);
    RUN(test_ir_state_name);
    RUN(test_ir_compromise_level_name);
    RUN(test_ir_containment_action_name);

    /* Dedup */
    RUN(test_ir_dedup_same_type_and_identity);
    RUN(test_ir_dedup_different_identity);
    RUN(test_ir_dedup_different_type);
    RUN(test_ir_dedup_resolved_not_counted);

    /* Coverage */
    RUN(test_ir_all_types_reportable);
    RUN(test_ir_all_severities_reportable);

    /* Interaction */
    RUN(test_ir_multiple_incidents_independent);
    RUN(test_ir_compromise_level_changes);

    /* Resources */
    RUN(test_ir_resource_limit_respected);

    /* Audit */
    RUN(test_ir_audit_events_generated);
    RUN(test_ir_audit_classify_generates_event);
    RUN(test_ir_audit_containment_generates_event);
    RUN(test_ir_audit_recovery_generates_event);
    RUN(test_ir_audit_resolve_generates_event);

    /* Specific incident types */
    RUN(test_ir_auth_attack_incident);
    RUN(test_ir_credential_compromise_incident);
    RUN(test_ir_privilege_escalation_incident);
    RUN(test_ir_key_compromise_incident);
    RUN(test_ir_vault_compromise_incident);
    RUN(test_ir_data_integrity_incident);
    RUN(test_ir_audit_integrity_incident);

    /* Versioning */
    RUN(test_ir_version_increments);

    /* Timestamps */
    RUN(test_ir_timestamps_updated);

    /* Classification */
    RUN(test_ir_classify_type_affects_type_name);

    /* Global */
    RUN(test_ir_global_not_null_after_init);
    RUN(test_ir_global_is_static);

    /* Full session compromise lifecycle */
    RUN(test_ir_full_session_compromise_lifecycle);

    /* Full identity compromise lifecycle */
    RUN(test_ir_full_identity_compromise_lifecycle);

    SUITE_END();
    _teardown_deps();
    return TOTAL_FAIL();
}
