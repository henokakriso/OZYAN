/*
 * test_sec_config.c — Security Policy & Configuration Hardening Tests
 *                     (Step 26).
 *
 * Comprehensive tests covering default policy, validation, lifecycle,
 * staging, activation, locking, history, cross-field validation,
 * secret prohibition, name helpers, and edge cases.
 */

#include "../../tests/test_framework.h"
#include "../sec_config.h"
#include "../audit.h"
#include <string.h>
#include <time.h>

/* ============================================================
 * TEST INFRASTRUCTURE
 * ============================================================ */

static ozayn_audit_service_t  _audit_svc;
static ozayn_sc_service_t     _sc_svc;

static void _setup_deps(void)
{
    ozayn_audit_service_config_t acfg;
    memset(&acfg, 0, sizeof(acfg));
    acfg.event_capacity = 512;
    acfg.default_minimum_severity = OZAYN_AUDIT_SEV_INFO;
    ozayn_audit_service_init(&_audit_svc, &acfg);
}

static void _teardown_deps(void)
{
    ozayn_sc_service_shutdown(&_sc_svc);
    ozayn_audit_service_shutdown(&_audit_svc);
}

static void _init_sc_svc(void)
{
    ozayn_sc_service_shutdown(&_sc_svc);
    ozayn_sc_service_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.audit = &_audit_svc;
    ozayn_sc_service_init(&_sc_svc, &cfg);
}

/* ============================================================
 * LIFECYCLE TESTS
 * ============================================================ */

TEST(test_sc_service_init_valid)
{
    _init_sc_svc();
    ASSERT(ozayn_sc_service_is_initialized(&_sc_svc));
    return 0;
}

TEST(test_sc_service_init_null)
{
    ASSERT_EQ(OZAYN_SC_ERR_NULL, ozayn_sc_service_init(NULL, NULL));
    return 0;
}

TEST(test_sc_service_init_null_config)
{
    ozayn_sc_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ASSERT_EQ(OZAYN_SC_ERR_NULL, ozayn_sc_service_init(&svc, NULL));
    return 0;
}

TEST(test_sc_service_init_already_initialized)
{
    _init_sc_svc();
    ozayn_sc_service_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    ASSERT_EQ(OZAYN_SC_ERR_ALREADY_INITIALIZED,
              ozayn_sc_service_init(&_sc_svc, &cfg));
    return 0;
}

TEST(test_sc_service_shutdown_null)
{
    ozayn_sc_service_shutdown(NULL);
    return 0;
}

TEST(test_sc_service_shutdown_reinit)
{
    _init_sc_svc();
    ozayn_sc_service_shutdown(&_sc_svc);
    ASSERT(!ozayn_sc_service_is_initialized(&_sc_svc));
    _init_sc_svc();
    ASSERT(ozayn_sc_service_is_initialized(&_sc_svc));
    return 0;
}

TEST(test_sc_is_initialized_null)
{
    ASSERT(!ozayn_sc_service_is_initialized(NULL));
    return 0;
}

TEST(test_sc_global_accessor)
{
    ozayn_sc_service_t *g = ozayn_sc_get_global();
    ASSERT_NOT_NULL(g);
    return 0;
}

TEST(test_sc_global_is_static)
{
    ozayn_sc_service_t *g1 = ozayn_sc_get_global();
    ozayn_sc_service_t *g2 = ozayn_sc_get_global();
    ASSERT(g1 == g2);
    return 0;
}

/* ============================================================
 * DEFAULT POLICY TESTS
 * ============================================================ */

TEST(test_sc_default_policy_valid)
{
    ozayn_sc_policy_t p = ozayn_sc_default_policy();
    ASSERT_EQ(OZAYN_SC_OK, ozayn_sc_validate_policy(&p));
    return 0;
}

TEST(test_sc_default_policy_authentication)
{
    ozayn_sc_policy_t p = ozayn_sc_default_policy();
    ASSERT_EQ(1, p.authentication.enabled);
    ASSERT_EQ(1, p.authentication.require_identity_state_active);
    ASSERT_EQ(1, p.authentication.require_credential_valid);
    ASSERT_EQ(300, p.authentication.auth_timeout_seconds);
    ASSERT_EQ(5, p.authentication.max_concurrent_auth_attempts);
    return 0;
}

TEST(test_sc_default_policy_password)
{
    ozayn_sc_policy_t p = ozayn_sc_default_policy();
    ASSERT_EQ(1, p.password.enabled);
    ASSERT_EQ(8, p.password.min_length);
    ASSERT_EQ(4096, p.password.max_length);
    return 0;
}

TEST(test_sc_default_policy_attempt_control)
{
    ozayn_sc_policy_t p = ozayn_sc_default_policy();
    ASSERT_EQ(1, p.attempt_control.enabled);
    ASSERT_EQ(5, p.attempt_control.max_failures);
    ASSERT_EQ(300, p.attempt_control.window_seconds);
    ASSERT_EQ(1000, p.attempt_control.initial_delay_ms);
    ASSERT_EQ(30000, p.attempt_control.max_delay_ms);
    ASSERT_EQ(900, p.attempt_control.block_seconds);
    return 0;
}

TEST(test_sc_default_policy_mfa)
{
    ozayn_sc_policy_t p = ozayn_sc_default_policy();
    ASSERT_EQ(1, p.mfa.enabled);
    ASSERT_EQ(2, p.mfa.required_factor_count);
    ASSERT_EQ(300, p.mfa.transaction_timeout_seconds);
    ASSERT_EQ(60, p.mfa.factor_timeout_seconds);
    return 0;
}

TEST(test_sc_default_policy_session)
{
    ozayn_sc_policy_t p = ozayn_sc_default_policy();
    ASSERT_EQ(1, p.session.enabled);
    ASSERT_EQ(512, p.session.max_sessions_total);
    ASSERT_EQ(8, p.session.max_sessions_per_identity);
    ASSERT_EQ(1800, p.session.idle_timeout_seconds);
    ASSERT_EQ(86400, p.session.absolute_lifetime_seconds);
    return 0;
}

TEST(test_sc_default_policy_authorization)
{
    ozayn_sc_policy_t p = ozayn_sc_default_policy();
    ASSERT_EQ(1, p.authorization.default_deny);
    ASSERT_EQ(1, p.authorization.require_resource);
    ASSERT_EQ(1, p.authorization.require_action);
    ASSERT_EQ(1, p.authorization.require_scope);
    return 0;
}

TEST(test_sc_default_policy_rbac)
{
    ozayn_sc_policy_t p = ozayn_sc_default_policy();
    ASSERT_EQ(1, p.rbac.enabled);
    ASSERT_EQ(1, p.rbac.require_explicit_roles);
    ASSERT_EQ(16, p.rbac.max_roles_per_identity);
    ASSERT_EQ(64, p.rbac.max_permissions_per_role);
    return 0;
}

TEST(test_sc_default_policy_permission)
{
    ozayn_sc_policy_t p = ozayn_sc_default_policy();
    ASSERT_EQ(1, p.permission.enabled);
    ASSERT_EQ(1, p.permission.default_deny_unknown);
    ASSERT_EQ(1, p.permission.require_explicit_grant);
    return 0;
}

TEST(test_sc_default_policy_key_management)
{
    ozayn_sc_policy_t p = ozayn_sc_default_policy();
    ASSERT_EQ(1, p.key_management.require_active_key);
    ASSERT_EQ(8, p.key_management.max_key_versions);
    ASSERT_EQ(1, p.key_management.require_retirement_before_revoke);
    return 0;
}

TEST(test_sc_default_policy_cryptographic)
{
    ozayn_sc_policy_t p = ozayn_sc_default_policy();
    ASSERT_EQ(1, p.cryptographic.require_protection);
    ASSERT_EQ(1, p.cryptographic.reject_obsolete_algorithms);
    return 0;
}

TEST(test_sc_default_policy_vault)
{
    ozayn_sc_policy_t p = ozayn_sc_default_policy();
    ASSERT_EQ(1, p.vault.require_encryption);
    ASSERT_EQ(1, p.vault.require_integrity);
    ASSERT_EQ(1, p.vault.require_classification);
    return 0;
}

TEST(test_sc_default_policy_backup)
{
    ozayn_sc_policy_t p = ozayn_sc_default_policy();
    ASSERT_EQ(1, p.backup.enabled);
    ASSERT_EQ(1, p.backup.require_integrity);
    ASSERT_EQ(1, p.backup.require_protection);
    ASSERT_EQ(1, p.backup.require_audit);
    ASSERT_EQ(67108864, p.backup.max_backup_size);
    return 0;
}

TEST(test_sc_default_policy_deletion)
{
    ozayn_sc_policy_t p = ozayn_sc_default_policy();
    ASSERT_EQ(1, p.deletion.require_authorization);
    ASSERT_EQ(1, p.deletion.require_mfa_for_sensitive);
    ASSERT_EQ(1, p.deletion.require_mfa_for_keys);
    ASSERT_EQ(1, p.deletion.verify_after_delete);
    return 0;
}

TEST(test_sc_default_policy_audit)
{
    ozayn_sc_policy_t p = ozayn_sc_default_policy();
    ASSERT_EQ(1, p.audit.enabled);
    ASSERT_EQ(1, p.audit.mandatory_event_protection);
    ASSERT_EQ(4096, p.audit.retention_events);
    return 0;
}

TEST(test_sc_default_policy_incident)
{
    ozayn_sc_policy_t p = ozayn_sc_default_policy();
    ASSERT_EQ(256, p.incident_response.max_incidents);
    ASSERT_EQ(1, p.incident_response.auto_contain_critical);
    ASSERT_EQ(1, p.incident_response.require_mfa_for_recovery);
    ASSERT_EQ(5, p.incident_response.lockdown_threshold);
    return 0;
}

TEST(test_sc_default_policy_version)
{
    ozayn_sc_policy_t p = ozayn_sc_default_policy();
    ASSERT_EQ(OZAYN_SC_POLICY_VERSION_MAJOR, p.schema_version);
    ASSERT_EQ(1, p.policy_version);
    ASSERT_EQ(1, p.config_version);
    return 0;
}

TEST(test_sc_default_policy_id)
{
    ozayn_sc_policy_t p = ozayn_sc_default_policy();
    ASSERT_STR_EQ("default", p.policy_id);
    return 0;
}

/* ============================================================
 * VALIDATION TESTS
 * ============================================================ */

TEST(test_sc_validate_null)
{
    ASSERT_EQ(OZAYN_SC_ERR_NULL, ozayn_sc_validate_policy(NULL));
    return 0;
}

TEST(test_sc_validate_valid_default)
{
    ozayn_sc_policy_t p = ozayn_sc_default_policy();
    ASSERT_EQ(OZAYN_SC_OK, ozayn_sc_validate_policy(&p));
    return 0;
}

TEST(test_sc_validate_invalid_schema_version)
{
    ozayn_sc_policy_t p = ozayn_sc_default_policy();
    p.schema_version = 0;
    ASSERT_EQ(OZAYN_SC_ERR_INCOMPATIBLE_VERSION,
              ozayn_sc_validate_policy(&p));
    return 0;
}

TEST(test_sc_validate_unsupported_version)
{
    ozayn_sc_policy_t p = ozayn_sc_default_policy();
    p.schema_version = 999;
    ASSERT_EQ(OZAYN_SC_ERR_INCOMPATIBLE_VERSION,
              ozayn_sc_validate_policy(&p));
    return 0;
}

/* Sub-policy validation */
TEST(test_sc_validate_authn_null)
{
    ASSERT_EQ(OZAYN_SC_ERR_NULL, ozayn_sc_validate_sub_policy_authn(NULL));
    return 0;
}

TEST(test_sc_validate_authn_negative_timeout)
{
    ozayn_sc_authn_policy_t p = {0};
    p.enabled = 1;
    p.auth_timeout_seconds = -1;
    ASSERT_EQ(OZAYN_SC_ERR_OUT_OF_RANGE,
              ozayn_sc_validate_sub_policy_authn(&p));
    return 0;
}

TEST(test_sc_validate_password_null)
{
    ASSERT_EQ(OZAYN_SC_ERR_NULL, ozayn_sc_validate_sub_policy_password(NULL));
    return 0;
}

TEST(test_sc_validate_password_zero_min)
{
    ozayn_sc_pwd_policy_t p = {0};
    p.enabled = 1;
    p.min_length = 0;
    p.max_length = 100;
    ASSERT_EQ(OZAYN_SC_ERR_OUT_OF_RANGE,
              ozayn_sc_validate_sub_policy_password(&p));
    return 0;
}

TEST(test_sc_validate_password_max_less_than_min)
{
    ozayn_sc_pwd_policy_t p = {0};
    p.enabled = 1;
    p.min_length = 16;
    p.max_length = 8;
    ASSERT_EQ(OZAYN_SC_ERR_OUT_OF_RANGE,
              ozayn_sc_validate_sub_policy_password(&p));
    return 0;
}

TEST(test_sc_validate_password_max_too_large)
{
    ozayn_sc_pwd_policy_t p = {0};
    p.enabled = 1;
    p.min_length = 8;
    p.max_length = 10000;
    ASSERT_EQ(OZAYN_SC_ERR_OUT_OF_RANGE,
              ozayn_sc_validate_sub_policy_password(&p));
    return 0;
}

TEST(test_sc_validate_password_disabled_ok)
{
    ozayn_sc_pwd_policy_t p = {0};
    p.enabled = 0;
    ASSERT_EQ(OZAYN_SC_OK, ozayn_sc_validate_sub_policy_password(&p));
    return 0;
}

TEST(test_sc_validate_ac_null)
{
    ASSERT_EQ(OZAYN_SC_ERR_NULL,
              ozayn_sc_validate_sub_policy_attempt_control(NULL));
    return 0;
}

TEST(test_sc_validate_ac_zero_failures)
{
    ozayn_sc_ac_policy_t p = {0};
    p.enabled = 1;
    p.max_failures = 0;
    ASSERT_EQ(OZAYN_SC_ERR_OUT_OF_RANGE,
              ozayn_sc_validate_sub_policy_attempt_control(&p));
    return 0;
}

TEST(test_sc_validate_ac_backoff_below_one)
{
    ozayn_sc_ac_policy_t p = {0};
    p.enabled = 1;
    p.max_failures = 5;
    p.window_seconds = 300;
    p.backoff_multiplier = 0.5;
    p.block_seconds = 900;
    p.initial_delay_ms = 1000;
    p.max_delay_ms = 30000;
    ASSERT_EQ(OZAYN_SC_ERR_OUT_OF_RANGE,
              ozayn_sc_validate_sub_policy_attempt_control(&p));
    return 0;
}

TEST(test_sc_validate_mfa_null)
{
    ASSERT_EQ(OZAYN_SC_ERR_NULL, ozayn_sc_validate_sub_policy_mfa(NULL));
    return 0;
}

TEST(test_sc_validate_mfa_zero_factors)
{
    ozayn_sc_mfa_policy_t p = {0};
    p.enabled = 1;
    p.required_factor_count = 0;
    ASSERT_EQ(OZAYN_SC_ERR_OUT_OF_RANGE,
              ozayn_sc_validate_sub_policy_mfa(&p));
    return 0;
}

TEST(test_sc_validate_mfa_too_many_factors)
{
    ozayn_sc_mfa_policy_t p = {0};
    p.enabled = 1;
    p.required_factor_count = 9;
    p.transaction_timeout_seconds = 300;
    p.factor_timeout_seconds = 60;
    p.max_failures = 5;
    p.block_seconds = 900;
    ASSERT_EQ(OZAYN_SC_ERR_OUT_OF_RANGE,
              ozayn_sc_validate_sub_policy_mfa(&p));
    return 0;
}

TEST(test_sc_validate_sess_null)
{
    ASSERT_EQ(OZAYN_SC_ERR_NULL, ozayn_sc_validate_sub_policy_session(NULL));
    return 0;
}

TEST(test_sc_validate_sess_zero_sessions)
{
    ozayn_sc_sess_policy_t p = {0};
    p.enabled = 1;
    p.max_sessions_total = 0;
    ASSERT_EQ(OZAYN_SC_ERR_OUT_OF_RANGE,
              ozayn_sc_validate_sub_policy_session(&p));
    return 0;
}

TEST(test_sc_validate_authz_null)
{
    ASSERT_EQ(OZAYN_SC_ERR_NULL,
              ozayn_sc_validate_sub_policy_authorization(NULL));
    return 0;
}

TEST(test_sc_validate_authz_no_default_deny)
{
    ozayn_sc_authz_policy_t p = {0};
    p.default_deny = 0;
    ASSERT_EQ(OZAYN_SC_ERR_INSECURE_CONFIGURATION,
              ozayn_sc_validate_sub_policy_authorization(&p));
    return 0;
}

TEST(test_sc_validate_rbac_null)
{
    ASSERT_EQ(OZAYN_SC_ERR_NULL, ozayn_sc_validate_sub_policy_rbac(NULL));
    return 0;
}

TEST(test_sc_validate_perm_null)
{
    ASSERT_EQ(OZAYN_SC_ERR_NULL, ozayn_sc_validate_sub_policy_permission(NULL));
    return 0;
}

TEST(test_sc_validate_perm_no_default_deny)
{
    ozayn_sc_perm_policy_t p = {0};
    p.enabled = 1;
    p.default_deny_unknown = 0;
    ASSERT_EQ(OZAYN_SC_ERR_INSECURE_CONFIGURATION,
              ozayn_sc_validate_sub_policy_permission(&p));
    return 0;
}

TEST(test_sc_validate_key_null)
{
    ASSERT_EQ(OZAYN_SC_ERR_NULL, ozayn_sc_validate_sub_policy_key(NULL));
    return 0;
}

TEST(test_sc_validate_key_zero_versions)
{
    ozayn_sc_key_policy_t p = {0};
    p.max_key_versions = 0;
    ASSERT_EQ(OZAYN_SC_ERR_OUT_OF_RANGE,
              ozayn_sc_validate_sub_policy_key(&p));
    return 0;
}

TEST(test_sc_validate_crypto_null)
{
    ASSERT_EQ(OZAYN_SC_ERR_NULL, ozayn_sc_validate_sub_policy_crypto(NULL));
    return 0;
}

TEST(test_sc_validate_crypto_no_protection)
{
    ozayn_sc_crypto_policy_t p = {0};
    p.require_protection = 0;
    ASSERT_EQ(OZAYN_SC_ERR_INSECURE_CONFIGURATION,
              ozayn_sc_validate_sub_policy_crypto(&p));
    return 0;
}

TEST(test_sc_validate_vault_null)
{
    ASSERT_EQ(OZAYN_SC_ERR_NULL, ozayn_sc_validate_sub_policy_vault(NULL));
    return 0;
}

TEST(test_sc_validate_vault_no_encryption)
{
    ozayn_sc_vault_policy_t p = {0};
    p.require_encryption = 0;
    ASSERT_EQ(OZAYN_SC_ERR_INSECURE_CONFIGURATION,
              ozayn_sc_validate_sub_policy_vault(&p));
    return 0;
}

TEST(test_sc_validate_backup_null)
{
    ASSERT_EQ(OZAYN_SC_ERR_NULL, ozayn_sc_validate_sub_policy_backup(NULL));
    return 0;
}

TEST(test_sc_validate_backup_no_integrity)
{
    ozayn_sc_bk_policy_t p = {0};
    p.enabled = 1;
    p.require_integrity = 0;
    p.require_protection = 1;
    p.max_backup_size = 1024;
    p.max_object_count = 1;
    p.retention_days = 1;
    ASSERT_EQ(OZAYN_SC_ERR_INSECURE_CONFIGURATION,
              ozayn_sc_validate_sub_policy_backup(&p));
    return 0;
}

TEST(test_sc_validate_del_null)
{
    ASSERT_EQ(OZAYN_SC_ERR_NULL, ozayn_sc_validate_sub_policy_deletion(NULL));
    return 0;
}

TEST(test_sc_validate_del_no_authz)
{
    ozayn_sc_del_policy_t p = {0};
    p.require_authorization = 0;
    ASSERT_EQ(OZAYN_SC_ERR_INSECURE_CONFIGURATION,
              ozayn_sc_validate_sub_policy_deletion(&p));
    return 0;
}

TEST(test_sc_validate_audit_null)
{
    ASSERT_EQ(OZAYN_SC_ERR_NULL, ozayn_sc_validate_sub_policy_audit(NULL));
    return 0;
}

TEST(test_sc_validate_audit_no_mandatory)
{
    ozayn_sc_audit_policy_t p = {0};
    p.mandatory_event_protection = 0;
    ASSERT_EQ(OZAYN_SC_ERR_INSECURE_CONFIGURATION,
              ozayn_sc_validate_sub_policy_audit(&p));
    return 0;
}

TEST(test_sc_validate_ir_null)
{
    ASSERT_EQ(OZAYN_SC_ERR_NULL, ozayn_sc_validate_sub_policy_incident(NULL));
    return 0;
}

TEST(test_sc_validate_ir_zero_max)
{
    ozayn_sc_ir_policy_t p = {0};
    p.max_incidents = 0;
    ASSERT_EQ(OZAYN_SC_ERR_OUT_OF_RANGE,
              ozayn_sc_validate_sub_policy_incident(&p));
    return 0;
}

/* ============================================================
 * CROSS-FIELD VALIDATION TESTS
 * ============================================================ */

TEST(test_cross_field_valid)
{
    ozayn_sc_policy_t p = ozayn_sc_default_policy();
    ASSERT_EQ(OZAYN_SC_OK, ozayn_sc_validate_cross_field(&p));
    return 0;
}

TEST(test_cross_field_null)
{
    ASSERT_EQ(OZAYN_SC_ERR_NULL, ozayn_sc_validate_cross_field(NULL));
    return 0;
}

TEST(test_cross_field_mfa_without_ac)
{
    ozayn_sc_policy_t p = ozayn_sc_default_policy();
    p.mfa.enabled = 1;
    p.attempt_control.enabled = 0;
    ASSERT_EQ(OZAYN_SC_ERR_CROSS_FIELD_INVALID,
              ozayn_sc_validate_cross_field(&p));
    return 0;
}

TEST(test_cross_field_session_idle_gte_absolute)
{
    ozayn_sc_policy_t p = ozayn_sc_default_policy();
    p.session.idle_timeout_seconds = 86400;
    p.session.absolute_lifetime_seconds = 86400;
    ASSERT_EQ(OZAYN_SC_ERR_CROSS_FIELD_INVALID,
              ozayn_sc_validate_cross_field(&p));
    return 0;
}

TEST(test_cross_field_session_per_identity_exceeds_total)
{
    ozayn_sc_policy_t p = ozayn_sc_default_policy();
    p.session.max_sessions_total = 8;
    p.session.max_sessions_per_identity = 16;
    ASSERT_EQ(OZAYN_SC_ERR_CROSS_FIELD_INVALID,
              ozayn_sc_validate_cross_field(&p));
    return 0;
}

TEST(test_cross_field_rotation_required_no_interval)
{
    ozayn_sc_policy_t p = ozayn_sc_default_policy();
    p.key_management.rotation_required = 1;
    p.key_management.rotation_interval_seconds = 0;
    ASSERT_EQ(OZAYN_SC_ERR_CROSS_FIELD_INVALID,
              ozayn_sc_validate_cross_field(&p));
    return 0;
}

TEST(test_cross_field_ir_exceeds_audit)
{
    ozayn_sc_policy_t p = ozayn_sc_default_policy();
    p.audit.retention_events = 100;
    p.incident_response.max_incidents = 200;
    ASSERT_EQ(OZAYN_SC_ERR_CROSS_FIELD_INVALID,
              ozayn_sc_validate_cross_field(&p));
    return 0;
}

/* ============================================================
 * STAGING AND ACTIVATION TESTS
 * ============================================================ */

TEST(test_sc_stage_policy_valid)
{
    _init_sc_svc();
    ozayn_sc_policy_t p = ozayn_sc_default_policy();
    p.policy_version = 2;
    ASSERT_EQ(OZAYN_SC_OK, ozayn_sc_stage_policy(&_sc_svc, &p));
    ASSERT(_sc_svc.has_staged);
    return 0;
}

TEST(test_sc_stage_policy_null_svc)
{
    ASSERT_EQ(OZAYN_SC_ERR_NULL,
              ozayn_sc_stage_policy(NULL, NULL));
    return 0;
}

TEST(test_sc_stage_policy_not_initialized)
{
    ozayn_sc_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_sc_policy_t p = ozayn_sc_default_policy();
    ASSERT_EQ(OZAYN_SC_ERR_NOT_INITIALIZED,
              ozayn_sc_stage_policy(&svc, &p));
    return 0;
}

TEST(test_sc_stage_policy_null_policy)
{
    _init_sc_svc();
    ASSERT_EQ(OZAYN_SC_ERR_NULL,
              ozayn_sc_stage_policy(&_sc_svc, NULL));
    return 0;
}

TEST(test_sc_stage_policy_invalid)
{
    _init_sc_svc();
    ozayn_sc_policy_t p = ozayn_sc_default_policy();
    p.schema_version = 0;
    ASSERT_EQ(OZAYN_SC_ERR_INCOMPATIBLE_VERSION,
              ozayn_sc_stage_policy(&_sc_svc, &p));
    ASSERT(!_sc_svc.has_staged);
    return 0;
}

TEST(test_sc_activate_valid)
{
    _init_sc_svc();
    ozayn_sc_policy_t p = ozayn_sc_default_policy();
    p.policy_version = 2;
    ozayn_sc_stage_policy(&_sc_svc, &p);
    ASSERT_EQ(OZAYN_SC_OK, ozayn_sc_activate(&_sc_svc));
    ozayn_sc_policy_t active;
    ozayn_sc_get_active_policy(&_sc_svc, &active);
    ASSERT_EQ(2, active.policy_version);
    ASSERT(active.activated_at > 0);
    return 0;
}

TEST(test_sc_activate_no_staged)
{
    _init_sc_svc();
    ASSERT_EQ(OZAYN_SC_ERR_NO_ACTIVE_POLICY, ozayn_sc_activate(&_sc_svc));
    return 0;
}

TEST(test_sc_activate_null)
{
    ASSERT_EQ(OZAYN_SC_ERR_NULL, ozayn_sc_activate(NULL));
    return 0;
}

TEST(test_sc_reject_staged)
{
    _init_sc_svc();
    ozayn_sc_policy_t p = ozayn_sc_default_policy();
    ozayn_sc_stage_policy(&_sc_svc, &p);
    ASSERT_EQ(OZAYN_SC_OK, ozayn_sc_reject_staged(&_sc_svc));
    ASSERT(!_sc_svc.has_staged);
    ASSERT_EQ(1, _sc_svc.total_rejections);
    return 0;
}

TEST(test_sc_reject_no_staged)
{
    _init_sc_svc();
    ASSERT_EQ(OZAYN_SC_ERR_NO_ACTIVE_POLICY, ozayn_sc_reject_staged(&_sc_svc));
    return 0;
}

TEST(test_sc_get_active_policy)
{
    _init_sc_svc();
    ozayn_sc_policy_t p;
    ASSERT_EQ(OZAYN_SC_OK, ozayn_sc_get_active_policy(&_sc_svc, &p));
    ASSERT_STR_EQ("default", p.policy_id);
    return 0;
}

TEST(test_sc_get_active_policy_null)
{
    ASSERT_EQ(OZAYN_SC_ERR_NULL, ozayn_sc_get_active_policy(NULL, NULL));
    return 0;
}

TEST(test_sc_get_staged_policy_none)
{
    _init_sc_svc();
    ozayn_sc_policy_t p;
    ASSERT_EQ(OZAYN_SC_ERR_NO_ACTIVE_POLICY,
              ozayn_sc_get_staged_policy(&_sc_svc, &p));
    return 0;
}

TEST(test_sc_get_staged_policy_valid)
{
    _init_sc_svc();
    ozayn_sc_policy_t p = ozayn_sc_default_policy();
    ozayn_sc_stage_policy(&_sc_svc, &p);
    ozayn_sc_policy_t staged;
    ASSERT_EQ(OZAYN_SC_OK, ozayn_sc_get_staged_policy(&_sc_svc, &staged));
    return 0;
}

/* ============================================================
 * LOCKING TESTS
 * ============================================================ */

TEST(test_sc_lock_unlock)
{
    _init_sc_svc();
    ASSERT(!ozayn_sc_is_locked(&_sc_svc));
    ASSERT_EQ(OZAYN_SC_OK, ozayn_sc_lock(&_sc_svc));
    ASSERT(ozayn_sc_is_locked(&_sc_svc));
    ASSERT_EQ(OZAYN_SC_OK, ozayn_sc_unlock(&_sc_svc));
    ASSERT(!ozayn_sc_is_locked(&_sc_svc));
    return 0;
}

TEST(test_sc_lock_blocks_stage)
{
    _init_sc_svc();
    ozayn_sc_lock(&_sc_svc);
    ozayn_sc_policy_t p = ozayn_sc_default_policy();
    ASSERT_EQ(OZAYN_SC_ERR_CONFIGURATION_LOCKED,
              ozayn_sc_stage_policy(&_sc_svc, &p));
    return 0;
}

TEST(test_sc_lock_blocks_activate)
{
    _init_sc_svc();
    ozayn_sc_policy_t p = ozayn_sc_default_policy();
    ozayn_sc_stage_policy(&_sc_svc, &p);
    ozayn_sc_lock(&_sc_svc);
    ASSERT_EQ(OZAYN_SC_ERR_CONFIGURATION_LOCKED,
              ozayn_sc_activate(&_sc_svc));
    return 0;
}

TEST(test_sc_lock_null)
{
    ASSERT_EQ(OZAYN_SC_ERR_NULL, ozayn_sc_lock(NULL));
    return 0;
}

TEST(test_sc_unlock_null)
{
    ASSERT_EQ(OZAYN_SC_ERR_NULL, ozayn_sc_unlock(NULL));
    return 0;
}

TEST(test_sc_is_locked_null)
{
    ASSERT(!ozayn_sc_is_locked(NULL));
    return 0;
}

/* ============================================================
 * HISTORY TESTS
 * ============================================================ */

TEST(test_sc_history_empty)
{
    _init_sc_svc();
    ASSERT_EQ(0, ozayn_sc_get_history_count(&_sc_svc));
    return 0;
}

TEST(test_sc_history_after_activation)
{
    _init_sc_svc();
    ozayn_sc_policy_t p = ozayn_sc_default_policy();
    p.policy_version = 2;
    ozayn_sc_stage_policy(&_sc_svc, &p);
    ozayn_sc_activate(&_sc_svc);
    ASSERT_EQ(1, ozayn_sc_get_history_count(&_sc_svc));
    uint32_t pv, cv;
    time_t at;
    ASSERT_EQ(OZAYN_SC_OK, ozayn_sc_get_history_entry(&_sc_svc, 0, &pv, &cv, &at));
    ASSERT_EQ(1, pv);
    return 0;
}

TEST(test_sc_history_multiple_activations)
{
    _init_sc_svc();
    for (int i = 2; i <= 4; i++) {
        ozayn_sc_policy_t p = ozayn_sc_default_policy();
        p.policy_version = i;
        ozayn_sc_stage_policy(&_sc_svc, &p);
        ozayn_sc_activate(&_sc_svc);
    }
    ASSERT_EQ(3, ozayn_sc_get_history_count(&_sc_svc));
    return 0;
}

TEST(test_sc_history_overflow)
{
    _init_sc_svc();
    for (int i = 0; i < OZAYN_SC_MAX_CONFIG_HISTORY + 2; i++) {
        ozayn_sc_policy_t p = ozayn_sc_default_policy();
        p.policy_version = i + 1;
        ozayn_sc_stage_policy(&_sc_svc, &p);
        ozayn_sc_activate(&_sc_svc);
    }
    ASSERT_EQ(OZAYN_SC_MAX_CONFIG_HISTORY,
              ozayn_sc_get_history_count(&_sc_svc));
    return 0;
}

TEST(test_sc_history_out_of_range)
{
    _init_sc_svc();
    uint32_t pv, cv;
    time_t at;
    ASSERT_EQ(OZAYN_SC_ERR_OUT_OF_RANGE,
              ozayn_sc_get_history_entry(&_sc_svc, 0, &pv, &cv, &at));
    return 0;
}

TEST(test_sc_history_null)
{
    ASSERT_EQ(0, ozayn_sc_get_history_count(NULL));
    uint32_t pv, cv;
    time_t at;
    ASSERT_EQ(OZAYN_SC_ERR_NULL,
              ozayn_sc_get_history_entry(NULL, 0, &pv, &cv, &at));
    return 0;
}

/* ============================================================
 * COMPATIBILITY TESTS
 * ============================================================ */

TEST(test_sc_compatibility_supported)
{
    ASSERT_EQ(OZAYN_SC_POLICY_STATE_SUPPORTED,
              ozayn_sc_check_compatibility(OZAYN_SC_POLICY_VERSION_MAJOR));
    return 0;
}

TEST(test_sc_compatibility_corrupted_zero)
{
    ASSERT_EQ(OZAYN_SC_POLICY_STATE_CORRUPTED,
              ozayn_sc_check_compatibility(0));
    return 0;
}

TEST(test_sc_compatibility_unsupported)
{
    ASSERT_EQ(OZAYN_SC_POLICY_STATE_UNSUPPORTED,
              ozayn_sc_check_compatibility(999));
    return 0;
}

/* ============================================================
 * NAME HELPERS TESTS
 * ============================================================ */

TEST(test_sc_result_name)
{
    ASSERT_STR_EQ("OK", ozayn_sc_result_name(OZAYN_SC_OK));
    ASSERT_STR_EQ("ERR_NULL", ozayn_sc_result_name(OZAYN_SC_ERR_NULL));
    ASSERT_STR_EQ("UNKNOWN", ozayn_sc_result_name((ozayn_sc_result_t)9999));
    return 0;
}

TEST(test_sc_class_name)
{
    ASSERT_STR_EQ("PUBLIC", ozayn_sc_class_name(OZAYN_SC_CLASS_PUBLIC));
    ASSERT_STR_EQ("SECRET", ozayn_sc_class_name(OZAYN_SC_CLASS_SECRET));
    ASSERT_STR_EQ("UNKNOWN", ozayn_sc_class_name((ozayn_sc_class_t)99));
    return 0;
}

TEST(test_sc_mutability_name)
{
    ASSERT_STR_EQ("RUNTIME_MUTABLE",
        ozayn_sc_mutability_name(OZAYN_SC_MUTABLE_RUNTIME));
    ASSERT_STR_EQ("IMMUTABLE",
        ozayn_sc_mutability_name(OZAYN_SC_IMMUTABLE));
    ASSERT_STR_EQ("UNKNOWN",
        ozayn_sc_mutability_name((ozayn_sc_mutability_t)99));
    return 0;
}

TEST(test_sc_policy_state_name)
{
    ASSERT_STR_EQ("SUPPORTED",
        ozayn_sc_policy_state_name(OZAYN_SC_POLICY_STATE_SUPPORTED));
    ASSERT_STR_EQ("CORRUPTED",
        ozayn_sc_policy_state_name(OZAYN_SC_POLICY_STATE_CORRUPTED));
    ASSERT_STR_EQ("UNKNOWN",
        ozayn_sc_policy_state_name((ozayn_sc_policy_state_t)99));
    return 0;
}

/* ============================================================
 * SECRET PROHIBITION TESTS
 * ============================================================ */

TEST(test_sc_check_no_secrets_valid)
{
    ozayn_sc_policy_t p = ozayn_sc_default_policy();
    ASSERT_EQ(OZAYN_SC_OK, ozayn_sc_check_no_secrets(&p));
    return 0;
}

TEST(test_sc_check_no_secrets_null)
{
    ASSERT_EQ(OZAYN_SC_ERR_NULL, ozayn_sc_check_no_secrets(NULL));
    return 0;
}

TEST(test_sc_check_no_secrets_empty_id)
{
    ozayn_sc_policy_t p = ozayn_sc_default_policy();
    p.policy_id[0] = '\0';
    ASSERT_EQ(OZAYN_SC_ERR_MANDATORY_FIELD_MISSING,
              ozayn_sc_check_no_secrets(&p));
    return 0;
}

/* ============================================================
 * STATS TESTS
 * ============================================================ */

TEST(test_sc_stats_activation)
{
    _init_sc_svc();
    ASSERT_EQ(0, _sc_svc.total_activations);
    ozayn_sc_policy_t p = ozayn_sc_default_policy();
    ozayn_sc_stage_policy(&_sc_svc, &p);
    ozayn_sc_activate(&_sc_svc);
    ASSERT_EQ(1, _sc_svc.total_activations);
    return 0;
}

TEST(test_sc_stats_rejection)
{
    _init_sc_svc();
    ASSERT_EQ(0, _sc_svc.total_rejections);
    ozayn_sc_policy_t p = ozayn_sc_default_policy();
    ozayn_sc_stage_policy(&_sc_svc, &p);
    ozayn_sc_reject_staged(&_sc_svc);
    ASSERT_EQ(1, _sc_svc.total_rejections);
    return 0;
}

TEST(test_sc_stats_validation)
{
    _init_sc_svc();
    ASSERT_EQ(0, _sc_svc.total_validations);
    ozayn_sc_policy_t p = ozayn_sc_default_policy();
    ozayn_sc_stage_policy(&_sc_svc, &p);
    ASSERT(_sc_svc.total_validations > 0);
    return 0;
}

/* ============================================================
 * ATOMIC ACTIVATION TESTS
 * ============================================================ */

TEST(test_sc_atomic_activation_preserves_old)
{
    _init_sc_svc();
    ozayn_sc_policy_t p1 = ozayn_sc_default_policy();
    p1.policy_version = 1;
    ozayn_sc_stage_policy(&_sc_svc, &p1);
    ozayn_sc_activate(&_sc_svc);

    ozayn_sc_policy_t p2 = ozayn_sc_default_policy();
    p2.policy_version = 2;
    ozayn_sc_stage_policy(&_sc_svc, &p2);

    /* Activate should be atomic */
    ASSERT_EQ(OZAYN_SC_OK, ozayn_sc_activate(&_sc_svc));
    ozayn_sc_policy_t active;
    ozayn_sc_get_active_policy(&_sc_svc, &active);
    ASSERT_EQ(2, active.policy_version);
    return 0;
}

TEST(test_sc_atomic_invalid_reverts)
{
    _init_sc_svc();
    ozayn_sc_policy_t p1 = ozayn_sc_default_policy();
    p1.policy_version = 1;
    ozayn_sc_stage_policy(&_sc_svc, &p1);
    ozayn_sc_activate(&_sc_svc);

    /* Stage invalid policy */
    ozayn_sc_policy_t bad = ozayn_sc_default_policy();
    bad.schema_version = 0;
    ASSERT_EQ(OZAYN_SC_ERR_INCOMPATIBLE_VERSION,
              ozayn_sc_stage_policy(&_sc_svc, &bad));

    /* Active policy should still be the old one */
    ozayn_sc_policy_t active;
    ozayn_sc_get_active_policy(&_sc_svc, &active);
    ASSERT_EQ(1, active.policy_version);
    return 0;
}

/* ============================================================
 * FAIL-CLOSED TESTS
 * ============================================================ */

TEST(test_sc_fail_closed_invalid_policy)
{
    _init_sc_svc();
    ozayn_sc_policy_t p = ozayn_sc_default_policy();
    p.authorization.default_deny = 0;
    ASSERT_EQ(OZAYN_SC_ERR_INSECURE_CONFIGURATION,
              ozayn_sc_stage_policy(&_sc_svc, &p));
    ASSERT(!_sc_svc.has_staged);
    return 0;
}

TEST(test_sc_fail_closed_mfa_zero_factors)
{
    _init_sc_svc();
    ozayn_sc_policy_t p = ozayn_sc_default_policy();
    p.mfa.required_factor_count = 0;
    ASSERT_EQ(OZAYN_SC_ERR_OUT_OF_RANGE,
              ozayn_sc_stage_policy(&_sc_svc, &p));
    return 0;
}

TEST(test_sc_fail_closed_vault_no_encryption)
{
    _init_sc_svc();
    ozayn_sc_policy_t p = ozayn_sc_default_policy();
    p.vault.require_encryption = 0;
    ASSERT_EQ(OZAYN_SC_ERR_INSECURE_CONFIGURATION,
              ozayn_sc_stage_policy(&_sc_svc, &p));
    return 0;
}

/* ============================================================
 * RUNNER
 * ============================================================ */

int run_sec_config_tests(void)
{
    _setup_deps();
    printf("\n  --- SECURITY CONFIGURATION TESTS ---\n");

    /* Lifecycle */
    RUN(test_sc_service_init_valid);
    RUN(test_sc_service_init_null);
    RUN(test_sc_service_init_null_config);
    RUN(test_sc_service_init_already_initialized);
    RUN(test_sc_service_shutdown_null);
    RUN(test_sc_service_shutdown_reinit);
    RUN(test_sc_is_initialized_null);
    RUN(test_sc_global_accessor);
    RUN(test_sc_global_is_static);

    /* Default policy */
    RUN(test_sc_default_policy_valid);
    RUN(test_sc_default_policy_authentication);
    RUN(test_sc_default_policy_password);
    RUN(test_sc_default_policy_attempt_control);
    RUN(test_sc_default_policy_mfa);
    RUN(test_sc_default_policy_session);
    RUN(test_sc_default_policy_authorization);
    RUN(test_sc_default_policy_rbac);
    RUN(test_sc_default_policy_permission);
    RUN(test_sc_default_policy_key_management);
    RUN(test_sc_default_policy_cryptographic);
    RUN(test_sc_default_policy_vault);
    RUN(test_sc_default_policy_backup);
    RUN(test_sc_default_policy_deletion);
    RUN(test_sc_default_policy_audit);
    RUN(test_sc_default_policy_incident);
    RUN(test_sc_default_policy_version);
    RUN(test_sc_default_policy_id);

    /* Validation */
    RUN(test_sc_validate_null);
    RUN(test_sc_validate_valid_default);
    RUN(test_sc_validate_invalid_schema_version);
    RUN(test_sc_validate_unsupported_version);
    RUN(test_sc_validate_authn_null);
    RUN(test_sc_validate_authn_negative_timeout);
    RUN(test_sc_validate_password_null);
    RUN(test_sc_validate_password_zero_min);
    RUN(test_sc_validate_password_max_less_than_min);
    RUN(test_sc_validate_password_max_too_large);
    RUN(test_sc_validate_password_disabled_ok);
    RUN(test_sc_validate_ac_null);
    RUN(test_sc_validate_ac_zero_failures);
    RUN(test_sc_validate_ac_backoff_below_one);
    RUN(test_sc_validate_mfa_null);
    RUN(test_sc_validate_mfa_zero_factors);
    RUN(test_sc_validate_mfa_too_many_factors);
    RUN(test_sc_validate_sess_null);
    RUN(test_sc_validate_sess_zero_sessions);
    RUN(test_sc_validate_authz_null);
    RUN(test_sc_validate_authz_no_default_deny);
    RUN(test_sc_validate_rbac_null);
    RUN(test_sc_validate_perm_null);
    RUN(test_sc_validate_perm_no_default_deny);
    RUN(test_sc_validate_key_null);
    RUN(test_sc_validate_key_zero_versions);
    RUN(test_sc_validate_crypto_null);
    RUN(test_sc_validate_crypto_no_protection);
    RUN(test_sc_validate_vault_null);
    RUN(test_sc_validate_vault_no_encryption);
    RUN(test_sc_validate_backup_null);
    RUN(test_sc_validate_backup_no_integrity);
    RUN(test_sc_validate_del_null);
    RUN(test_sc_validate_del_no_authz);
    RUN(test_sc_validate_audit_null);
    RUN(test_sc_validate_audit_no_mandatory);
    RUN(test_sc_validate_ir_null);
    RUN(test_sc_validate_ir_zero_max);

    /* Cross-field */
    RUN(test_cross_field_valid);
    RUN(test_cross_field_null);
    RUN(test_cross_field_mfa_without_ac);
    RUN(test_cross_field_session_idle_gte_absolute);
    RUN(test_cross_field_session_per_identity_exceeds_total);
    RUN(test_cross_field_rotation_required_no_interval);
    RUN(test_cross_field_ir_exceeds_audit);

    /* Staging and activation */
    RUN(test_sc_stage_policy_valid);
    RUN(test_sc_stage_policy_null_svc);
    RUN(test_sc_stage_policy_not_initialized);
    RUN(test_sc_stage_policy_null_policy);
    RUN(test_sc_stage_policy_invalid);
    RUN(test_sc_activate_valid);
    RUN(test_sc_activate_no_staged);
    RUN(test_sc_activate_null);
    RUN(test_sc_reject_staged);
    RUN(test_sc_reject_no_staged);
    RUN(test_sc_get_active_policy);
    RUN(test_sc_get_active_policy_null);
    RUN(test_sc_get_staged_policy_none);
    RUN(test_sc_get_staged_policy_valid);

    /* Locking */
    RUN(test_sc_lock_unlock);
    RUN(test_sc_lock_blocks_stage);
    RUN(test_sc_lock_blocks_activate);
    RUN(test_sc_lock_null);
    RUN(test_sc_unlock_null);
    RUN(test_sc_is_locked_null);

    /* History */
    RUN(test_sc_history_empty);
    RUN(test_sc_history_after_activation);
    RUN(test_sc_history_multiple_activations);
    RUN(test_sc_history_overflow);
    RUN(test_sc_history_out_of_range);
    RUN(test_sc_history_null);

    /* Compatibility */
    RUN(test_sc_compatibility_supported);
    RUN(test_sc_compatibility_corrupted_zero);
    RUN(test_sc_compatibility_unsupported);

    /* Name helpers */
    RUN(test_sc_result_name);
    RUN(test_sc_class_name);
    RUN(test_sc_mutability_name);
    RUN(test_sc_policy_state_name);

    /* Secret prohibition */
    RUN(test_sc_check_no_secrets_valid);
    RUN(test_sc_check_no_secrets_null);
    RUN(test_sc_check_no_secrets_empty_id);

    /* Stats */
    RUN(test_sc_stats_activation);
    RUN(test_sc_stats_rejection);
    RUN(test_sc_stats_validation);

    /* Atomic activation */
    RUN(test_sc_atomic_activation_preserves_old);
    RUN(test_sc_atomic_invalid_reverts);

    /* Fail-closed */
    RUN(test_sc_fail_closed_invalid_policy);
    RUN(test_sc_fail_closed_mfa_zero_factors);
    RUN(test_sc_fail_closed_vault_no_encryption);

    SUITE_END();
    _teardown_deps();
    return TOTAL_FAIL();
}
