/*
 * test_sec_health.c — Security Health Monitoring Tests (Step 27).
 *
 * Comprehensive tests for the security health monitoring system:
 * lifecycle, registration, health checks, dependency evaluation,
 * aggregation, operation safety, snapshots, events, change detection,
 * name helpers, and negative security tests.
 */

#include "../../tests/test_framework.h"
#include "../sec_health.h"
#include "../sec_config.h"
#include "../incident.h"
#include <string.h>
#include <time.h>

/* ============================================================
 * TEST HELPERS
 * ============================================================ */

static ozayn_sh_service_t _sh_svc;
static ozayn_sc_service_t _sc_svc;
static ozayn_ir_service_t _ir_svc;
static ozayn_audit_service_t _au_svc;

static void _reset_all(void)
{
    memset(&_sh_svc, 0, sizeof(_sh_svc));
    memset(&_sc_svc, 0, sizeof(_sc_svc));
    memset(&_ir_svc, 0, sizeof(_ir_svc));
    memset(&_au_svc, 0, sizeof(_au_svc));
}

static void _init_sc_svc(void)
{
    _sc_svc.initialized = 1;
    _sc_svc.active_policy = ozayn_sc_default_policy();
}

static void _init_au_svc(void)
{
    _au_svc.initialized = 1;
}

static void _init_ir_svc(void)
{
    _ir_svc.initialized = 1;
}

static void _init_sh_svc_basic(void)
{
    _reset_all();
    _init_sc_svc();
    _init_au_svc();
    _init_ir_svc();

    ozayn_sh_service_config_t cfg = {0};
    cfg.config_service = &_sc_svc;
    cfg.incident_service = &_ir_svc;
    cfg.audit = &_au_svc;
    cfg.max_concurrent_checks = 1;
    ozayn_sh_service_init(&_sh_svc, &cfg);
}

static void _register_core_components(void)
{
    ozayn_sh_component_id_t deps[8];
    int dc;

    dc = 0;
    ozayn_sh_register_component(&_sh_svc,
        OZAYN_SH_COMP_SECURITY_CONFIGURATION,
        "SECURITY_CONFIGURATION", 1, deps, dc);

    dc = 1; deps[0] = OZAYN_SH_COMP_SECURITY_CONFIGURATION;
    ozayn_sh_register_component(&_sh_svc,
        OZAYN_SH_COMP_SECURITY_POLICY,
        "SECURITY_POLICY", 1, deps, dc);

    dc = 0;
    ozayn_sh_register_component(&_sh_svc,
        OZAYN_SH_COMP_IDENTITY,
        "IDENTITY", 1, deps, dc);

    dc = 0;
    ozayn_sh_register_component(&_sh_svc,
        OZAYN_SH_COMP_AUTHENTICATION,
        "AUTHENTICATION", 1, deps, dc);

    dc = 0;
    ozayn_sh_register_component(&_sh_svc,
        OZAYN_SH_COMP_ATTEMPT_CONTROL,
        "ATTEMPT_CONTROL", 1, deps, dc);

    dc = 0;
    ozayn_sh_register_component(&_sh_svc,
        OZAYN_SH_COMP_MFA,
        "MFA", 0, deps, dc);

    dc = 0;
    ozayn_sh_register_component(&_sh_svc,
        OZAYN_SH_COMP_SESSION,
        "SESSION", 1, deps, dc);

    dc = 0;
    ozayn_sh_register_component(&_sh_svc,
        OZAYN_SH_COMP_AUTHORIZATION,
        "AUTHORIZATION", 1, deps, dc);

    dc = 0;
    ozayn_sh_register_component(&_sh_svc,
        OZAYN_SH_COMP_RBAC,
        "RBAC", 0, deps, dc);

    dc = 0;
    ozayn_sh_register_component(&_sh_svc,
        OZAYN_SH_COMP_PERMISSION,
        "PERMISSION", 1, deps, dc);

    dc = 0;
    ozayn_sh_register_component(&_sh_svc,
        OZAYN_SH_COMP_SECURE_DATA,
        "SECURE_DATA", 1, deps, dc);

    dc = 0;
    ozayn_sh_register_component(&_sh_svc,
        OZAYN_SH_COMP_STORAGE,
        "STORAGE", 1, deps, dc);

    dc = 0;
    ozayn_sh_register_component(&_sh_svc,
        OZAYN_SH_COMP_PROTECTION,
        "PROTECTION", 1, deps, dc);

    dc = 0;
    ozayn_sh_register_component(&_sh_svc,
        OZAYN_SH_COMP_KEY_MANAGEMENT,
        "KEY_MANAGEMENT", 1, deps, dc);

    dc = 0;
    ozayn_sh_register_component(&_sh_svc,
        OZAYN_SH_COMP_KEY_STORAGE,
        "KEY_STORAGE", 1, deps, dc);

    dc = 0;
    ozayn_sh_register_component(&_sh_svc,
        OZAYN_SH_COMP_KEY_LIFECYCLE,
        "KEY_LIFECYCLE", 1, deps, dc);

    dc = 1; deps[0] = OZAYN_SH_COMP_PROTECTION;
    ozayn_sh_register_component(&_sh_svc,
        OZAYN_SH_COMP_SECURE_VAULT,
        "SECURE_VAULT", 1, deps, dc);

    dc = 0;
    ozayn_sh_register_component(&_sh_svc,
        OZAYN_SH_COMP_AUDIT,
        "AUDIT", 1, deps, dc);

    dc = 1; deps[0] = OZAYN_SH_COMP_AUDIT;
    ozayn_sh_register_component(&_sh_svc,
        OZAYN_SH_COMP_AUDIT_INTEGRITY,
        "AUDIT_INTEGRITY", 1, deps, dc);

    dc = 0;
    ozayn_sh_register_component(&_sh_svc,
        OZAYN_SH_COMP_BACKUP,
        "BACKUP", 0, deps, dc);

    dc = 0;
    ozayn_sh_register_component(&_sh_svc,
        OZAYN_SH_COMP_RECOVERY,
        "RECOVERY", 0, deps, dc);

    dc = 0;
    ozayn_sh_register_component(&_sh_svc,
        OZAYN_SH_COMP_SECURE_DELETION,
        "SECURE_DELETION", 0, deps, dc);

    dc = 1; deps[0] = OZAYN_SH_COMP_AUDIT;
    ozayn_sh_register_component(&_sh_svc,
        OZAYN_SH_COMP_INCIDENT_RESPONSE,
        "INCIDENT_RESPONSE", 1, deps, dc);
}

/* ============================================================
 * LIFECYCLE TESTS
 * ============================================================ */

TEST(test_sh_init)
{
    _reset_all();
    ozayn_sh_service_config_t cfg = {0};
    ASSERT_EQ(OZAYN_SH_OK, ozayn_sh_service_init(&_sh_svc, &cfg));
    ASSERT(ozayn_sh_service_is_initialized(&_sh_svc));
    ozayn_sh_service_shutdown(&_sh_svc);
    ASSERT(!ozayn_sh_service_is_initialized(&_sh_svc));
    return 0;
}

TEST(test_sh_init_null)
{
    ASSERT_EQ(OZAYN_SH_ERR_NULL,
              ozayn_sh_service_init(NULL, NULL));
    return 0;
}

TEST(test_sh_init_double)
{
    _reset_all();
    ozayn_sh_service_config_t cfg = {0};
    ASSERT_EQ(OZAYN_SH_OK, ozayn_sh_service_init(&_sh_svc, &cfg));
    ASSERT_EQ(OZAYN_SH_ERR_ALREADY_INITIALIZED,
              ozayn_sh_service_init(&_sh_svc, &cfg));
    ozayn_sh_service_shutdown(&_sh_svc);
    return 0;
}

TEST(test_sh_shutdown_null)
{
    ozayn_sh_service_shutdown(NULL);
    return 0;
}

TEST(test_sh_is_init_null)
{
    ASSERT(!ozayn_sh_service_is_initialized(NULL));
    return 0;
}

TEST(test_sh_default_config)
{
    _reset_all();
    ozayn_sh_service_config_t cfg = {0};
    ASSERT_EQ(OZAYN_SH_OK, ozayn_sh_service_init(&_sh_svc, &cfg));
    ASSERT_EQ(1, _sh_svc.max_concurrent_checks);
    ozayn_sh_service_shutdown(&_sh_svc);
    return 0;
}

/* ============================================================
 * REGISTRATION TESTS
 * ============================================================ */

TEST(test_sh_register_component)
{
    _init_sh_svc_basic();
    ozayn_sh_component_id_t deps[2] = {0};
    ASSERT_EQ(OZAYN_SH_OK,
              ozayn_sh_register_component(&_sh_svc,
                  OZAYN_SH_COMP_IDENTITY, "IDENTITY", 1, deps, 0));
    ASSERT_EQ(1, _sh_svc.component_count);
    return 0;
}

TEST(test_sh_register_duplicate)
{
    _init_sh_svc_basic();
    ozayn_sh_component_id_t deps[2] = {0};
    ASSERT_EQ(OZAYN_SH_OK,
              ozayn_sh_register_component(&_sh_svc,
                  OZAYN_SH_COMP_IDENTITY, "IDENTITY", 1, deps, 0));
    ASSERT_EQ(OZAYN_SH_ERR_INVALID_REQUEST,
              ozayn_sh_register_component(&_sh_svc,
                  OZAYN_SH_COMP_IDENTITY, "IDENTITY", 1, deps, 0));
    return 0;
}

TEST(test_sh_register_not_init)
{
    _reset_all();
    ozayn_sh_service_t svc = {0};
    ozayn_sh_component_id_t deps[2] = {0};
    ASSERT_EQ(OZAYN_SH_ERR_NOT_INITIALIZED,
              ozayn_sh_register_component(&svc,
                  OZAYN_SH_COMP_IDENTITY, "IDENTITY", 1, deps, 0));
    return 0;
}

TEST(test_sh_register_null)
{
    ASSERT_EQ(OZAYN_SH_ERR_NULL,
              ozayn_sh_register_component(NULL,
                  OZAYN_SH_COMP_IDENTITY, "IDENTITY", 1, NULL, 0));
    return 0;
}

TEST(test_sh_register_invalid_component)
{
    _init_sh_svc_basic();
    ozayn_sh_component_id_t deps[2] = {0};
    ASSERT_EQ(OZAYN_SH_ERR_INVALID_COMPONENT,
              ozayn_sh_register_component(&_sh_svc,
                  (ozayn_sh_component_id_t)99, "BAD", 1, deps, 0));
    return 0;
}

TEST(test_sh_register_with_dependencies)
{
    _init_sh_svc_basic();
    ozayn_sh_component_id_t deps[1] = {
        OZAYN_SH_COMP_KEY_STORAGE
    };
    ASSERT_EQ(OZAYN_SH_OK,
              ozayn_sh_register_component(&_sh_svc,
                  OZAYN_SH_COMP_KEY_MANAGEMENT,
                  "KEY_MANAGEMENT", 1, deps, 1));
    ASSERT_EQ(1, _sh_svc.components[0].dependency_count);
    ASSERT_EQ(OZAYN_SH_COMP_KEY_STORAGE,
              _sh_svc.components[0].dependencies[0]);
    return 0;
}

TEST(test_sh_register_resource_limit)
{
    _reset_all();
    ozayn_sh_service_config_t cfg = {0};
    cfg.max_concurrent_checks = 1;
    ozayn_sh_service_init(&_sh_svc, &cfg);
    ozayn_sh_component_id_t deps[2] = {0};
    for (int i = 0; i < OZAYN_SH_MAX_COMPONENTS; i++) {
        ozayn_sh_register_component(&_sh_svc,
            (ozayn_sh_component_id_t)i, "COMP", 1, deps, 0);
    }
    ASSERT_EQ(OZAYN_SH_ERR_RESOURCE_LIMIT,
              ozayn_sh_register_component(&_sh_svc,
                  OZAYN_SH_COMP_SECURE_VAULT, "EXTRA", 1, deps, 0));
    ozayn_sh_service_shutdown(&_sh_svc);
    return 0;
}

TEST(test_sh_register_provider)
{
    _init_sh_svc_basic();
    ozayn_sh_provider_vtable_t vt = {0};
    vt.check = NULL;
    ASSERT_EQ(OZAYN_SH_ERR_NULL,
              ozayn_sh_register_provider(&_sh_svc, &vt, NULL));
    ASSERT_EQ(0, _sh_svc.provider_count);
    return 0;
}

TEST(test_sh_register_provider_not_init)
{
    _reset_all();
    ozayn_sh_service_t svc = {0};
    ASSERT_EQ(OZAYN_SH_ERR_NOT_INITIALIZED,
              ozayn_sh_register_provider(&svc, NULL, NULL));
    return 0;
}

/* ============================================================
 * HEALTH CHECK TESTS
 * ============================================================ */

TEST(test_sh_check_single)
{
    _init_sh_svc_basic();
    _register_core_components();
    ozayn_sh_component_health_t health = {0};
    ASSERT_EQ(OZAYN_SH_OK,
              ozayn_sh_check(&_sh_svc, OZAYN_SH_COMP_IDENTITY, &health));
    ASSERT_EQ(OZAYN_SH_COMP_IDENTITY, health.component_id);
    ASSERT_EQ(OZAYN_SH_HEALTHY, health.health_state);
    return 0;
}

TEST(test_sh_check_not_init)
{
    ozayn_sh_service_t svc = {0};
    ozayn_sh_component_health_t health = {0};
    ASSERT_EQ(OZAYN_SH_ERR_NOT_INITIALIZED,
              ozayn_sh_check(&svc, OZAYN_SH_COMP_IDENTITY, &health));
    return 0;
}

TEST(test_sh_check_null)
{
    ASSERT_EQ(OZAYN_SH_ERR_NULL,
              ozayn_sh_check(NULL, OZAYN_SH_COMP_IDENTITY, NULL));
    return 0;
}

TEST(test_sh_check_invalid_component)
{
    _init_sh_svc_basic();
    ozayn_sh_component_health_t health = {0};
    ASSERT_EQ(OZAYN_SH_ERR_INVALID_COMPONENT,
              ozayn_sh_check(&_sh_svc,
                  (ozayn_sh_component_id_t)99, &health));
    return 0;
}

TEST(test_sh_check_config_health)
{
    _init_sh_svc_basic();
    _register_core_components();
    ozayn_sh_component_health_t health = {0};
    ASSERT_EQ(OZAYN_SH_OK,
              ozayn_sh_check(&_sh_svc,
                  OZAYN_SH_COMP_SECURITY_CONFIGURATION, &health));
    ASSERT_EQ(OZAYN_SH_HEALTHY, health.health_state);
    ASSERT_EQ(1, health.available);
    ASSERT_EQ(OZAYN_SH_CONFIG_VALID, health.config_state);
    return 0;
}

TEST(test_sh_check_config_unavailable)
{
    _reset_all();
    _au_svc.initialized = 1;
    _ir_svc.initialized = 1;
    ozayn_sh_service_config_t cfg = {0};
    cfg.audit = &_au_svc;
    cfg.incident_service = &_ir_svc;
    cfg.max_concurrent_checks = 1;
    ozayn_sh_service_init(&_sh_svc, &cfg);

    ozayn_sh_component_id_t deps[2] = {0};
    ozayn_sh_register_component(&_sh_svc,
        OZAYN_SH_COMP_SECURITY_CONFIGURATION,
        "SECURITY_CONFIGURATION", 1, deps, 0);

    ozayn_sh_component_health_t health = {0};
    ASSERT_EQ(OZAYN_SH_OK,
              ozayn_sh_check(&_sh_svc,
                  OZAYN_SH_COMP_SECURITY_CONFIGURATION, &health));
    ASSERT_EQ(OZAYN_SH_UNAVAILABLE, health.health_state);
    ASSERT_EQ(0, health.available);
    ozayn_sh_service_shutdown(&_sh_svc);
    return 0;
}

TEST(test_sh_check_policy_health)
{
    _init_sh_svc_basic();
    _register_core_components();
    ozayn_sh_component_health_t health = {0};
    ASSERT_EQ(OZAYN_SH_OK,
              ozayn_sh_check(&_sh_svc,
                  OZAYN_SH_COMP_SECURITY_POLICY, &health));
    ASSERT_EQ(OZAYN_SH_HEALTHY, health.health_state);
    ASSERT_EQ(OZAYN_SH_POLICY_VALID, health.policy_state);
    return 0;
}

TEST(test_sh_check_policy_default_deny_disabled)
{
    _init_sh_svc_basic();
    _sc_svc.active_policy.authorization.default_deny = 0;
    _register_core_components();
    ozayn_sh_component_health_t health = {0};
    ASSERT_EQ(OZAYN_SH_OK,
              ozayn_sh_check(&_sh_svc,
                  OZAYN_SH_COMP_SECURITY_POLICY, &health));
    ASSERT_EQ(OZAYN_SH_CRITICAL, health.health_state);
    return 0;
}

TEST(test_sh_check_policy_no_active)
{
    _init_sh_svc_basic();
    memset(&_sc_svc.active_policy, 0, sizeof(_sc_svc.active_policy));
    _register_core_components();
    ozayn_sh_component_health_t health = {0};
    ASSERT_EQ(OZAYN_SH_OK,
              ozayn_sh_check(&_sh_svc,
                  OZAYN_SH_COMP_SECURITY_POLICY, &health));
    ASSERT_EQ(OZAYN_SH_CRITICAL, health.health_state);
    return 0;
}

TEST(test_sh_check_authn_disabled)
{
    _init_sh_svc_basic();
    _sc_svc.active_policy.authentication.enabled = 0;
    _register_core_components();
    ozayn_sh_component_health_t health = {0};
    ASSERT_EQ(OZAYN_SH_OK,
              ozayn_sh_check(&_sh_svc,
                  OZAYN_SH_COMP_AUTHENTICATION, &health));
    ASSERT_EQ(OZAYN_SH_DEGRADED, health.health_state);
    return 0;
}

TEST(test_sh_check_ac_health)
{
    _init_sh_svc_basic();
    _register_core_components();
    ozayn_sh_component_health_t health = {0};
    ASSERT_EQ(OZAYN_SH_OK,
              ozayn_sh_check(&_sh_svc,
                  OZAYN_SH_COMP_ATTEMPT_CONTROL, &health));
    ASSERT_EQ(OZAYN_SH_HEALTHY, health.health_state);
    return 0;
}

TEST(test_sh_check_ac_disabled)
{
    _init_sh_svc_basic();
    _sc_svc.active_policy.attempt_control.enabled = 0;
    _register_core_components();
    ozayn_sh_component_health_t health = {0};
    ASSERT_EQ(OZAYN_SH_OK,
              ozayn_sh_check(&_sh_svc,
                  OZAYN_SH_COMP_ATTEMPT_CONTROL, &health));
    ASSERT_EQ(OZAYN_SH_DEGRADED, health.health_state);
    return 0;
}

TEST(test_sh_check_mfa_health)
{
    _init_sh_svc_basic();
    _register_core_components();
    ozayn_sh_component_health_t health = {0};
    ASSERT_EQ(OZAYN_SH_OK,
              ozayn_sh_check(&_sh_svc,
                  OZAYN_SH_COMP_MFA, &health));
    ASSERT_EQ(OZAYN_SH_HEALTHY, health.health_state);
    return 0;
}

TEST(test_sh_check_mfa_not_configured)
{
    _init_sh_svc_basic();
    _sc_svc.active_policy.mfa.enabled = 0;
    _register_core_components();
    ozayn_sh_component_health_t health = {0};
    ASSERT_EQ(OZAYN_SH_OK,
              ozayn_sh_check(&_sh_svc,
                  OZAYN_SH_COMP_MFA, &health));
    ASSERT_EQ(OZAYN_SH_WARNING, health.health_state);
    return 0;
}

TEST(test_sh_check_session_health)
{
    _init_sh_svc_basic();
    _register_core_components();
    ozayn_sh_component_health_t health = {0};
    ASSERT_EQ(OZAYN_SH_OK,
              ozayn_sh_check(&_sh_svc,
                  OZAYN_SH_COMP_SESSION, &health));
    ASSERT_EQ(OZAYN_SH_HEALTHY, health.health_state);
    return 0;
}

TEST(test_sh_check_session_disabled)
{
    _init_sh_svc_basic();
    _sc_svc.active_policy.session.enabled = 0;
    _register_core_components();
    ozayn_sh_component_health_t health = {0};
    ASSERT_EQ(OZAYN_SH_OK,
              ozayn_sh_check(&_sh_svc,
                  OZAYN_SH_COMP_SESSION, &health));
    ASSERT_EQ(OZAYN_SH_DEGRADED, health.health_state);
    return 0;
}

TEST(test_sh_check_authz_health)
{
    _init_sh_svc_basic();
    _register_core_components();
    ozayn_sh_component_health_t health = {0};
    ASSERT_EQ(OZAYN_SH_OK,
              ozayn_sh_check(&_sh_svc,
                  OZAYN_SH_COMP_AUTHORIZATION, &health));
    ASSERT_EQ(OZAYN_SH_HEALTHY, health.health_state);
    return 0;
}

TEST(test_sh_check_authz_default_deny_off)
{
    _init_sh_svc_basic();
    _sc_svc.active_policy.authorization.default_deny = 0;
    _register_core_components();
    ozayn_sh_component_health_t health = {0};
    ASSERT_EQ(OZAYN_SH_OK,
              ozayn_sh_check(&_sh_svc,
                  OZAYN_SH_COMP_AUTHORIZATION, &health));
    ASSERT_EQ(OZAYN_SH_CRITICAL, health.health_state);
    return 0;
}

TEST(test_sh_check_rbac_health)
{
    _init_sh_svc_basic();
    _register_core_components();
    ozayn_sh_component_health_t health = {0};
    ASSERT_EQ(OZAYN_SH_OK,
              ozayn_sh_check(&_sh_svc,
                  OZAYN_SH_COMP_RBAC, &health));
    ASSERT_EQ(OZAYN_SH_HEALTHY, health.health_state);
    return 0;
}

TEST(test_sh_check_rbac_disabled)
{
    _init_sh_svc_basic();
    _sc_svc.active_policy.rbac.enabled = 0;
    _register_core_components();
    ozayn_sh_component_health_t health = {0};
    ASSERT_EQ(OZAYN_SH_OK,
              ozayn_sh_check(&_sh_svc,
                  OZAYN_SH_COMP_RBAC, &health));
    ASSERT_EQ(OZAYN_SH_DEGRADED, health.health_state);
    return 0;
}

TEST(test_sh_check_perm_health)
{
    _init_sh_svc_basic();
    _register_core_components();
    ozayn_sh_component_health_t health = {0};
    ASSERT_EQ(OZAYN_SH_OK,
              ozayn_sh_check(&_sh_svc,
                  OZAYN_SH_COMP_PERMISSION, &health));
    ASSERT_EQ(OZAYN_SH_HEALTHY, health.health_state);
    return 0;
}

TEST(test_sh_check_perm_disabled)
{
    _init_sh_svc_basic();
    _sc_svc.active_policy.permission.enabled = 0;
    _register_core_components();
    ozayn_sh_component_health_t health = {0};
    ASSERT_EQ(OZAYN_SH_OK,
              ozayn_sh_check(&_sh_svc,
                  OZAYN_SH_COMP_PERMISSION, &health));
    ASSERT_EQ(OZAYN_SH_DEGRADED, health.health_state);
    return 0;
}

TEST(test_sh_check_protection_health)
{
    _init_sh_svc_basic();
    _register_core_components();
    ozayn_sh_component_health_t health = {0};
    ASSERT_EQ(OZAYN_SH_OK,
              ozayn_sh_check(&_sh_svc,
                  OZAYN_SH_COMP_PROTECTION, &health));
    ASSERT_EQ(OZAYN_SH_HEALTHY, health.health_state);
    return 0;
}

TEST(test_sh_check_protection_not_required)
{
    _init_sh_svc_basic();
    _sc_svc.active_policy.cryptographic.require_protection = 0;
    _register_core_components();
    ozayn_sh_component_health_t health = {0};
    ASSERT_EQ(OZAYN_SH_OK,
              ozayn_sh_check(&_sh_svc,
                  OZAYN_SH_COMP_PROTECTION, &health));
    ASSERT_EQ(OZAYN_SH_CRITICAL, health.health_state);
    return 0;
}

TEST(test_sh_check_key_mgmt_health)
{
    _init_sh_svc_basic();
    _register_core_components();
    ozayn_sh_component_health_t health = {0};
    ASSERT_EQ(OZAYN_SH_OK,
              ozayn_sh_check(&_sh_svc,
                  OZAYN_SH_COMP_KEY_MANAGEMENT, &health));
    ASSERT_EQ(OZAYN_SH_HEALTHY, health.health_state);
    return 0;
}

TEST(test_sh_check_key_mgmt_no_active)
{
    _init_sh_svc_basic();
    _sc_svc.active_policy.key_management.require_active_key = 0;
    _register_core_components();
    ozayn_sh_component_health_t health = {0};
    ASSERT_EQ(OZAYN_SH_OK,
              ozayn_sh_check(&_sh_svc,
                  OZAYN_SH_COMP_KEY_MANAGEMENT, &health));
    ASSERT_EQ(OZAYN_SH_DEGRADED, health.health_state);
    return 0;
}

TEST(test_sh_check_vault_health)
{
    _init_sh_svc_basic();
    _register_core_components();
    ozayn_sh_component_health_t health = {0};
    ASSERT_EQ(OZAYN_SH_OK,
              ozayn_sh_check(&_sh_svc,
                  OZAYN_SH_COMP_SECURE_VAULT, &health));
    ASSERT_EQ(OZAYN_SH_HEALTHY, health.health_state);
    return 0;
}

TEST(test_sh_check_vault_no_encryption)
{
    _init_sh_svc_basic();
    _sc_svc.active_policy.vault.require_encryption = 0;
    _register_core_components();
    ozayn_sh_component_health_t health = {0};
    ASSERT_EQ(OZAYN_SH_OK,
              ozayn_sh_check(&_sh_svc,
                  OZAYN_SH_COMP_SECURE_VAULT, &health));
    ASSERT_EQ(OZAYN_SH_CRITICAL, health.health_state);
    return 0;
}

TEST(test_sh_check_audit_health)
{
    _init_sh_svc_basic();
    _register_core_components();
    ozayn_sh_component_health_t health = {0};
    ASSERT_EQ(OZAYN_SH_OK,
              ozayn_sh_check(&_sh_svc,
                  OZAYN_SH_COMP_AUDIT, &health));
    ASSERT_EQ(OZAYN_SH_HEALTHY, health.health_state);
    return 0;
}

TEST(test_sh_check_audit_unavailable)
{
    _reset_all();
    _sc_svc.initialized = 1;
    _sc_svc.active_policy = ozayn_sc_default_policy();
    _ir_svc.initialized = 1;
    ozayn_sh_service_config_t cfg = {0};
    cfg.config_service = &_sc_svc;
    cfg.incident_service = &_ir_svc;
    cfg.max_concurrent_checks = 1;
    ozayn_sh_service_init(&_sh_svc, &cfg);

    ozayn_sh_component_id_t deps[2] = {0};
    ozayn_sh_register_component(&_sh_svc,
        OZAYN_SH_COMP_AUDIT, "AUDIT", 1, deps, 0);

    ozayn_sh_component_health_t health = {0};
    ASSERT_EQ(OZAYN_SH_OK,
              ozayn_sh_check(&_sh_svc,
                  OZAYN_SH_COMP_AUDIT, &health));
    ASSERT_EQ(OZAYN_SH_UNAVAILABLE, health.health_state);
    ozayn_sh_service_shutdown(&_sh_svc);
    return 0;
}

TEST(test_sh_check_audit_integrity_health)
{
    _init_sh_svc_basic();
    _register_core_components();
    ozayn_sh_component_health_t health = {0};
    ASSERT_EQ(OZAYN_SH_OK,
              ozayn_sh_check(&_sh_svc,
                  OZAYN_SH_COMP_AUDIT_INTEGRITY, &health));
    ASSERT_EQ(OZAYN_SH_HEALTHY, health.health_state);
    ASSERT_EQ(OZAYN_SH_INTEGRITY_VALID, health.integrity_state);
    return 0;
}

TEST(test_sh_check_backup_health)
{
    _init_sh_svc_basic();
    _register_core_components();
    ozayn_sh_component_health_t health = {0};
    ASSERT_EQ(OZAYN_SH_OK,
              ozayn_sh_check(&_sh_svc,
                  OZAYN_SH_COMP_BACKUP, &health));
    ASSERT_EQ(OZAYN_SH_HEALTHY, health.health_state);
    return 0;
}

TEST(test_sh_check_backup_disabled)
{
    _init_sh_svc_basic();
    _sc_svc.active_policy.backup.enabled = 0;
    _register_core_components();
    ozayn_sh_component_health_t health = {0};
    ASSERT_EQ(OZAYN_SH_OK,
              ozayn_sh_check(&_sh_svc,
                  OZAYN_SH_COMP_BACKUP, &health));
    ASSERT_EQ(OZAYN_SH_DEGRADED, health.health_state);
    return 0;
}

TEST(test_sh_check_deletion_health)
{
    _init_sh_svc_basic();
    _register_core_components();
    ozayn_sh_component_health_t health = {0};
    ASSERT_EQ(OZAYN_SH_OK,
              ozayn_sh_check(&_sh_svc,
                  OZAYN_SH_COMP_SECURE_DELETION, &health));
    ASSERT_EQ(OZAYN_SH_HEALTHY, health.health_state);
    return 0;
}

TEST(test_sh_check_deletion_no_authz)
{
    _init_sh_svc_basic();
    _sc_svc.active_policy.deletion.require_authorization = 0;
    _register_core_components();
    ozayn_sh_component_health_t health = {0};
    ASSERT_EQ(OZAYN_SH_OK,
              ozayn_sh_check(&_sh_svc,
                  OZAYN_SH_COMP_SECURE_DELETION, &health));
    ASSERT_EQ(OZAYN_SH_WARNING, health.health_state);
    return 0;
}

TEST(test_sh_check_incident_health)
{
    _init_sh_svc_basic();
    _register_core_components();
    ozayn_sh_component_health_t health = {0};
    ASSERT_EQ(OZAYN_SH_OK,
              ozayn_sh_check(&_sh_svc,
                  OZAYN_SH_COMP_INCIDENT_RESPONSE, &health));
    ASSERT_EQ(OZAYN_SH_HEALTHY, health.health_state);
    return 0;
}

TEST(test_sh_check_incident_lockdown)
{
    _init_sh_svc_basic();
    _ir_svc.lockdown_active = 1;
    _register_core_components();
    ozayn_sh_component_health_t health = {0};
    ASSERT_EQ(OZAYN_SH_OK,
              ozayn_sh_check(&_sh_svc,
                  OZAYN_SH_COMP_INCIDENT_RESPONSE, &health));
    ASSERT_EQ(OZAYN_SH_LOCKDOWN, health.health_state);
    return 0;
}

TEST(test_sh_check_incident_unavailable)
{
    _reset_all();
    _sc_svc.initialized = 1;
    _sc_svc.active_policy = ozayn_sc_default_policy();
    _au_svc.initialized = 1;
    ozayn_sh_service_config_t cfg = {0};
    cfg.config_service = &_sc_svc;
    cfg.audit = &_au_svc;
    cfg.max_concurrent_checks = 1;
    ozayn_sh_service_init(&_sh_svc, &cfg);

    ozayn_sh_component_id_t deps[2] = {0};
    ozayn_sh_register_component(&_sh_svc,
        OZAYN_SH_COMP_INCIDENT_RESPONSE,
        "INCIDENT_RESPONSE", 1, deps, 0);

    ozayn_sh_component_health_t health = {0};
    ASSERT_EQ(OZAYN_SH_OK,
              ozayn_sh_check(&_sh_svc,
                  OZAYN_SH_COMP_INCIDENT_RESPONSE, &health));
    ASSERT_EQ(OZAYN_SH_UNAVAILABLE, health.health_state);
    ozayn_sh_service_shutdown(&_sh_svc);
    return 0;
}

TEST(test_sh_check_concurrency_limit)
{
    _init_sh_svc_basic();
    _sh_svc.max_concurrent_checks = 0;
    _sh_svc.active_checks = 1;
    ozayn_sh_component_health_t health = {0};
    ASSERT_EQ(OZAYN_SH_ERR_CONCURRENCY_CONFLICT,
              ozayn_sh_check(&_sh_svc,
                  OZAYN_SH_COMP_IDENTITY, &health));
    return 0;
}

/* ============================================================
 * CHECK ALL TESTS
 * ============================================================ */

TEST(test_sh_check_all)
{
    _init_sh_svc_basic();
    _register_core_components();
    ASSERT_EQ(OZAYN_SH_OK, ozayn_sh_check_all(&_sh_svc));
    ASSERT_GT(_sh_svc.total_checks, (uint64_t)0);
    ASSERT_EQ(OZAYN_SH_HEALTHY, _sh_svc.aggregation.overall_state);
    return 0;
}

TEST(test_sh_check_all_increments_version)
{
    _init_sh_svc_basic();
    _register_core_components();
    uint32_t v1 = _sh_svc.check_version;
    ASSERT_EQ(OZAYN_SH_OK, ozayn_sh_check_all(&_sh_svc));
    ASSERT_GT(_sh_svc.check_version, v1);
    return 0;
}

/* ============================================================
 * DEPENDENCY EVALUATION TESTS
 * ============================================================ */

TEST(test_sh_depends_vault_protected)
{
    _init_sh_svc_basic();
    _register_core_components();

    /* Disable protection via policy -> check_all will set protection to CRITICAL */
    _sc_svc.active_policy.cryptographic.require_protection = 0;

    /* Also need vault to depend on protection — run check_all to propagate */
    ozayn_sh_check_all(&_sh_svc);

    /* Vault should be degraded or worse because protection is critical */
    int vault_idx = -1;
    for (int i = 0; i < _sh_svc.component_count; i++) {
        if (_sh_svc.components[i].component_id ==
            OZAYN_SH_COMP_SECURE_VAULT) {
            vault_idx = i;
            break;
        }
    }
    ASSERT(vault_idx >= 0);
    ASSERT(_sh_svc.components[vault_idx].health_state !=
           OZAYN_SH_HEALTHY);
    return 0;
}

TEST(test_sh_depends_propagation)
{
    _init_sh_svc_basic();
    _register_core_components();

    /* Remove audit service -> audit becomes UNAVAILABLE */
    ozayn_sc_service_t *saved_cfg = _sh_svc.config_service;
    ozayn_audit_service_t *saved_audit = _sh_svc.audit;
    _sh_svc.audit = NULL;

    ozayn_sh_check_all(&_sh_svc);

    /* Audit integrity should be degraded because audit is unavailable */
    int ai_idx = -1;
    for (int i = 0; i < _sh_svc.component_count; i++) {
        if (_sh_svc.components[i].component_id ==
            OZAYN_SH_COMP_AUDIT_INTEGRITY) {
            ai_idx = i;
            break;
        }
    }
    ASSERT(ai_idx >= 0);
    ASSERT(_sh_svc.components[ai_idx].health_state !=
           OZAYN_SH_HEALTHY);

    _sh_svc.audit = saved_audit;
    _sh_svc.config_service = saved_cfg;
    return 0;
}

TEST(test_sh_depends_null)
{
    ASSERT_EQ(OZAYN_SH_ERR_NULL, ozayn_sh_evaluate_dependencies(NULL));
    return 0;
}

/* ============================================================
 * AGGREGATION TESTS
 * ============================================================ */

TEST(test_sh_agg_all_healthy)
{
    _init_sh_svc_basic();
    _register_core_components();
    ozayn_sh_check_all(&_sh_svc);
    ASSERT_EQ(OZAYN_SH_HEALTHY, _sh_svc.aggregation.overall_state);
    ASSERT_GT(_sh_svc.aggregation.healthy_count, 0);
    return 0;
}

TEST(test_sh_agg_one_optional_unavailable)
{
    _init_sh_svc_basic();
    _register_core_components();

    /* Set backup (optional) to unavailable */
    int idx = -1;
    for (int i = 0; i < _sh_svc.component_count; i++) {
        if (_sh_svc.components[i].component_id ==
            OZAYN_SH_COMP_BACKUP) {
            idx = i;
            break;
        }
    }
    ASSERT(idx >= 0);
    _sh_svc.components[idx].health_state = OZAYN_SH_UNAVAILABLE;

    /* Run aggregation check_all */
    ozayn_sh_check_all(&_sh_svc);

    /* Should not be CRITICAL since backup is optional */
    ASSERT(_sh_svc.aggregation.overall_state != OZAYN_SH_CRITICAL);
    return 0;
}

TEST(test_sh_agg_one_critical_required)
{
    _init_sh_svc_basic();
    _register_core_components();

    /* Disable vault encryption -> vault check returns CRITICAL */
    _sc_svc.active_policy.vault.require_encryption = 0;

    ozayn_sh_check_all(&_sh_svc);
    ASSERT_EQ(OZAYN_SH_CRITICAL, _sh_svc.aggregation.overall_state);
    return 0;
}

TEST(test_sh_agg_lockdown)
{
    _init_sh_svc_basic();
    _register_core_components();

    /* Set incident service to lockdown */
    _ir_svc.lockdown_active = 1;

    ozayn_sh_check_all(&_sh_svc);
    ASSERT_EQ(OZAYN_SH_LOCKDOWN, _sh_svc.aggregation.overall_state);
    return 0;
}

TEST(test_sh_agg_unknown)
{
    _init_sh_svc_basic();
    _register_core_components();

    /* Remove config service -> config check returns UNAVAILABLE */
    ozayn_sc_service_t *saved = _sh_svc.config_service;
    _sh_svc.config_service = NULL;

    ozayn_sh_check_all(&_sh_svc);

    /* Without config, many checks return UNKNOWN/UNAVAILABLE */
    ASSERT(_sh_svc.aggregation.overall_state == OZAYN_SH_UNKNOWN ||
           _sh_svc.aggregation.overall_state == OZAYN_SH_CRITICAL);

    _sh_svc.config_service = saved;
    return 0;
}

TEST(test_sh_agg_empty)
{
    _reset_all();
    ozayn_sh_service_config_t cfg = {0};
    cfg.max_concurrent_checks = 1;
    ozayn_sh_service_init(&_sh_svc, &cfg);
    ozayn_sh_check_all(&_sh_svc);
    ASSERT_EQ(OZAYN_SH_UNKNOWN, _sh_svc.aggregation.overall_state);
    ozayn_sh_service_shutdown(&_sh_svc);
    return 0;
}

/* ============================================================
 * OPERATION SAFETY TESTS
 * ============================================================ */

TEST(test_sh_op_safe_healthy)
{
    _init_sh_svc_basic();
    _register_core_components();
    ozayn_sh_check_all(&_sh_svc);
    ozayn_sh_operation_safety_t safety = OZAYN_SH_SAFE_DENY;
    ASSERT_EQ(OZAYN_SH_OK,
              ozayn_sh_is_operation_safe(&_sh_svc,
                  OZAYN_SH_OP_VAULT_ACCESS, &safety));
    ASSERT_EQ(OZAYN_SH_SAFE_ALLOW, safety);
    return 0;
}

TEST(test_sh_op_safe_lockdown)
{
    _init_sh_svc_basic();
    _register_core_components();
    _ir_svc.lockdown_active = 1;
    ozayn_sh_check_all(&_sh_svc);
    ozayn_sh_operation_safety_t safety = OZAYN_SH_SAFE_ALLOW;
    ASSERT_EQ(OZAYN_SH_OK,
              ozayn_sh_is_operation_safe(&_sh_svc,
                  OZAYN_SH_OP_VAULT_ACCESS, &safety));
    ASSERT_EQ(OZAYN_SH_SAFE_DENY, safety);
    return 0;
}

TEST(test_sh_op_safe_unknown)
{
    _init_sh_svc_basic();
    /* No components -> UNKNOWN */
    ozayn_sh_check_all(&_sh_svc);
    ozayn_sh_operation_safety_t safety = OZAYN_SH_SAFE_ALLOW;
    ASSERT_EQ(OZAYN_SH_OK,
              ozayn_sh_is_operation_safe(&_sh_svc,
                  OZAYN_SH_OP_VAULT_ACCESS, &safety));
    ASSERT_EQ(OZAYN_SH_SAFE_DENY, safety);
    return 0;
}

TEST(test_sh_op_safe_critical)
{
    _init_sh_svc_basic();
    _register_core_components();

    int idx = -1;
    for (int i = 0; i < _sh_svc.component_count; i++) {
        if (_sh_svc.components[i].component_id ==
            OZAYN_SH_COMP_SECURE_VAULT) {
            idx = i;
            break;
        }
    }
    ASSERT(idx >= 0);
    _sh_svc.components[idx].health_state = OZAYN_SH_CRITICAL;
    _sh_svc.aggregation.overall_state = OZAYN_SH_CRITICAL;

    ozayn_sh_operation_safety_t safety = OZAYN_SH_SAFE_ALLOW;
    ASSERT_EQ(OZAYN_SH_OK,
              ozayn_sh_is_operation_safe(&_sh_svc,
                  OZAYN_SH_OP_VAULT_ACCESS, &safety));
    ASSERT_EQ(OZAYN_SH_SAFE_DENY, safety);
    return 0;
}

TEST(test_sh_op_safe_vault_component_down)
{
    _init_sh_svc_basic();
    _register_core_components();

    int idx = -1;
    for (int i = 0; i < _sh_svc.component_count; i++) {
        if (_sh_svc.components[i].component_id ==
            OZAYN_SH_COMP_SECURE_VAULT) {
            idx = i;
            break;
        }
    }
    ASSERT(idx >= 0);
    _sh_svc.components[idx].health_state = OZAYN_SH_UNAVAILABLE;
    _sh_svc.aggregation.overall_state = OZAYN_SH_DEGRADED;

    ozayn_sh_operation_safety_t safety = OZAYN_SH_SAFE_ALLOW;
    ASSERT_EQ(OZAYN_SH_OK,
              ozayn_sh_is_operation_safe(&_sh_svc,
                  OZAYN_SH_OP_VAULT_ACCESS, &safety));
    ASSERT_EQ(OZAYN_SH_SAFE_DENY, safety);
    return 0;
}

TEST(test_sh_op_safe_null)
{
    ASSERT_EQ(OZAYN_SH_ERR_NULL,
              ozayn_sh_is_operation_safe(NULL,
                  OZAYN_SH_OP_VAULT_ACCESS, NULL));
    return 0;
}

/* ============================================================
 * SNAPSHOT TESTS
 * ============================================================ */

TEST(test_sh_snapshot_generate)
{
    _init_sh_svc_basic();
    _register_core_components();
    ozayn_sh_check_all(&_sh_svc);

    ozayn_sh_snapshot_t snap = {0};
    ASSERT_EQ(OZAYN_SH_OK,
              ozayn_sh_generate_snapshot(&_sh_svc, &snap));
    ASSERT_EQ(OZAYN_SH_SNAPSHOT_VERSION, snap.snapshot_version);
    ASSERT(snap.timestamp > 0);
    ASSERT_EQ(_sh_svc.component_count, snap.component_count);
    ASSERT_EQ(OZAYN_SH_HEALTHY, snap.overall_state);
    ASSERT(strlen(snap.summary) > 0);
    return 0;
}

TEST(test_sh_snapshot_fresh)
{
    ozayn_sh_snapshot_t snap = {0};
    snap.timestamp = time(NULL);
    int fresh = 0;
    ASSERT_EQ(OZAYN_SH_OK,
              ozayn_sh_snapshot_is_fresh(&snap, 60, &fresh));
    ASSERT(fresh);
    return 0;
}

TEST(test_sh_snapshot_stale)
{
    ozayn_sh_snapshot_t snap = {0};
    snap.timestamp = time(NULL) - 120;
    int fresh = 1;
    ASSERT_EQ(OZAYN_SH_OK,
              ozayn_sh_snapshot_is_fresh(&snap, 60, &fresh));
    ASSERT(!fresh);
    return 0;
}

TEST(test_sh_snapshot_null)
{
    ASSERT_EQ(OZAYN_SH_ERR_NULL,
              ozayn_sh_generate_snapshot(NULL, NULL));
    return 0;
}

TEST(test_sh_snapshot_fresh_null)
{
    ASSERT_EQ(OZAYN_SH_ERR_NULL,
              ozayn_sh_snapshot_is_fresh(NULL, 60, NULL));
    return 0;
}

TEST(test_sh_snapshot_includes_policy_version)
{
    _init_sh_svc_basic();
    _register_core_components();
    _sc_svc.active_policy.policy_version = 42;
    _sc_svc.active_policy.config_version = 7;
    ozayn_sh_check_all(&_sh_svc);

    ozayn_sh_snapshot_t snap = {0};
    ASSERT_EQ(OZAYN_SH_OK,
              ozayn_sh_generate_snapshot(&_sh_svc, &snap));
    ASSERT_EQ(42, (int)snap.policy_version);
    ASSERT_EQ(7, (int)snap.config_version);
    return 0;
}

TEST(test_sh_snapshot_incident_info)
{
    _init_sh_svc_basic();
    _register_core_components();
    _ir_svc.incident_count = 3;
    _ir_svc.lockdown_active = 1;
    ozayn_sh_check_all(&_sh_svc);

    ozayn_sh_snapshot_t snap = {0};
    ASSERT_EQ(OZAYN_SH_OK,
              ozayn_sh_generate_snapshot(&_sh_svc, &snap));
    ASSERT_EQ(3, snap.active_incidents);
    ASSERT(snap.lockdown_active);
    return 0;
}

/* ============================================================
 * EVENT LOG TESTS
 * ============================================================ */

TEST(test_sh_event_record)
{
    _init_sh_svc_basic();
    ASSERT_EQ(OZAYN_SH_OK,
              ozayn_sh_record_event(&_sh_svc,
                  OZAYN_SH_EVENT_CHECK_STARTED,
                  OZAYN_SH_COMP_IDENTITY,
                  OZAYN_SH_HEALTHY, "test event"));
    ASSERT_EQ(1, ozayn_sh_get_event_count(&_sh_svc));
    return 0;
}

TEST(test_sh_event_get)
{
    _init_sh_svc_basic();
    ozayn_sh_record_event(&_sh_svc,
        OZAYN_SH_EVENT_HEALTH_CRITICAL,
        OZAYN_SH_COMP_AUDIT,
        OZAYN_SH_CRITICAL, "audit down");

    ozayn_sh_event_t ev = {0};
    ASSERT_EQ(OZAYN_SH_OK, ozayn_sh_get_event(&_sh_svc, 0, &ev));
    ASSERT_EQ(OZAYN_SH_EVENT_HEALTH_CRITICAL, ev.event_type);
    ASSERT_EQ(OZAYN_SH_COMP_AUDIT, ev.component_id);
    ASSERT_EQ(OZAYN_SH_CRITICAL, ev.health_state);
    ASSERT(strcmp(ev.detail, "audit down") == 0);
    return 0;
}

TEST(test_sh_event_ring_buffer)
{
    _init_sh_svc_basic();
    for (int i = 0; i < OZAYN_SH_MAX_EVENTS + 10; i++) {
        ozayn_sh_record_event(&_sh_svc,
            OZAYN_SH_EVENT_CHECK_STARTED,
            OZAYN_SH_COMP_IDENTITY,
            OZAYN_SH_HEALTHY, NULL);
    }
    ASSERT_EQ(OZAYN_SH_MAX_EVENTS,
              ozayn_sh_get_event_count(&_sh_svc));
    return 0;
}

TEST(test_sh_event_null)
{
    ASSERT_EQ(OZAYN_SH_ERR_NULL,
              ozayn_sh_record_event(NULL,
                  OZAYN_SH_EVENT_CHECK_STARTED,
                  OZAYN_SH_COMP_IDENTITY,
                  OZAYN_SH_HEALTHY, NULL));
    return 0;
}

TEST(test_sh_event_invalid_index)
{
    _init_sh_svc_basic();
    ozayn_sh_event_t ev = {0};
    ASSERT_EQ(OZAYN_SH_ERR_INVALID_REQUEST,
              ozayn_sh_get_event(&_sh_svc, -1, &ev));
    ASSERT_EQ(OZAYN_SH_ERR_INVALID_REQUEST,
              ozayn_sh_get_event(&_sh_svc, 0, &ev));
    return 0;
}

/* ============================================================
 * STATUS QUERY TESTS
 * ============================================================ */

TEST(test_sh_get_status)
{
    _init_sh_svc_basic();
    _register_core_components();
    ozayn_sh_check_all(&_sh_svc);
    ozayn_sh_health_state_t state = OZAYN_SH_UNKNOWN;
    ASSERT_EQ(OZAYN_SH_OK, ozayn_sh_get_status(&_sh_svc, &state));
    ASSERT_EQ(OZAYN_SH_HEALTHY, state);
    return 0;
}

TEST(test_sh_get_status_null)
{
    ASSERT_EQ(OZAYN_SH_ERR_NULL,
              ozayn_sh_get_status(NULL, NULL));
    return 0;
}

TEST(test_sh_get_component_status)
{
    _init_sh_svc_basic();
    _register_core_components();
    ozayn_sh_check_all(&_sh_svc);
    ozayn_sh_component_health_t health = {0};
    ASSERT_EQ(OZAYN_SH_OK,
              ozayn_sh_get_component_status(&_sh_svc,
                  OZAYN_SH_COMP_IDENTITY, &health));
    ASSERT_EQ(OZAYN_SH_HEALTHY, health.health_state);
    return 0;
}

TEST(test_sh_get_component_status_invalid)
{
    _init_sh_svc_basic();
    _register_core_components();
    ozayn_sh_component_health_t health = {0};
    ASSERT_EQ(OZAYN_SH_ERR_INVALID_COMPONENT,
              ozayn_sh_get_component_status(&_sh_svc,
                  (ozayn_sh_component_id_t)99, &health));
    return 0;
}

TEST(test_sh_get_safe_summary)
{
    _init_sh_svc_basic();
    _register_core_components();
    ozayn_sh_check_all(&_sh_svc);
    const char *summary = ozayn_sh_get_safe_summary(&_sh_svc);
    ASSERT_NOT_NULL(summary);
    ASSERT(strstr(summary, "OZAYN SECURITY STATUS") != NULL);
    ASSERT(strstr(summary, "HEALTHY") != NULL);
    return 0;
}

TEST(test_sh_get_safe_summary_null)
{
    const char *summary = ozayn_sh_get_safe_summary(NULL);
    ASSERT_NOT_NULL(summary);
    ASSERT(strstr(summary, "UNKNOWN") != NULL);
    return 0;
}

/* ============================================================
 * CHANGE DETECTION TESTS
 * ============================================================ */

TEST(test_sh_changes_none)
{
    _init_sh_svc_basic();
    _register_core_components();
    ozayn_sh_check_all(&_sh_svc);
    int changes = -1;
    ASSERT_EQ(OZAYN_SH_OK,
              ozayn_sh_detect_changes(&_sh_svc, &changes));
    ASSERT_EQ(0, changes);
    return 0;
}

TEST(test_sh_changes_null)
{
    ASSERT_EQ(OZAYN_SH_ERR_NULL,
              ozayn_sh_detect_changes(NULL, NULL));
    return 0;
}

/* ============================================================
 * NAME HELPER TESTS
 * ============================================================ */

TEST(test_sh_name_result)
{
    ASSERT(strcmp(ozayn_sh_result_name(OZAYN_SH_OK), "OK") == 0);
    ASSERT(strcmp(ozayn_sh_result_name(OZAYN_SH_ERR_NULL),
                  "ERR_NULL") == 0);
    ASSERT(strcmp(ozayn_sh_result_name((ozayn_sh_result_t)999),
                  "UNKNOWN") == 0);
    return 0;
}

TEST(test_sh_name_health_state)
{
    ASSERT(strcmp(ozayn_sh_health_state_name(OZAYN_SH_HEALTHY),
                  "HEALTHY") == 0);
    ASSERT(strcmp(ozayn_sh_health_state_name(OZAYN_SH_LOCKDOWN),
                  "LOCKDOWN") == 0);
    ASSERT(strcmp(ozayn_sh_health_state_name(
                  (ozayn_sh_health_state_t)99), "UNKNOWN") == 0);
    return 0;
}

TEST(test_sh_name_component)
{
    ASSERT(strcmp(ozayn_sh_component_name(OZAYN_SH_COMP_IDENTITY),
                  "IDENTITY") == 0);
    ASSERT(strcmp(ozayn_sh_component_name(
                  (ozayn_sh_component_id_t)99),
                  "UNKNOWN_COMPONENT") == 0);
    return 0;
}

TEST(test_sh_name_check_type)
{
    ASSERT(strcmp(ozayn_sh_check_type_name(OZAYN_SH_CHECK_AVAILABILITY),
                  "AVAILABILITY") == 0);
    ASSERT(strcmp(ozayn_sh_check_type_name(
                  (ozayn_sh_check_type_t)99),
                  "UNKNOWN_CHECK") == 0);
    return 0;
}

TEST(test_sh_name_integrity)
{
    ASSERT(strcmp(ozayn_sh_integrity_state_name(
                  OZAYN_SH_INTEGRITY_VALID), "VALID") == 0);
    ASSERT(strcmp(ozayn_sh_integrity_state_name(
                  (ozayn_sh_integrity_state_t)99), "UNKNOWN") == 0);
    return 0;
}

TEST(test_sh_name_config)
{
    ASSERT(strcmp(ozayn_sh_config_state_name(OZAYN_SH_CONFIG_VALID),
                  "VALID") == 0);
    ASSERT(strcmp(ozayn_sh_config_state_name(
                  (ozayn_sh_config_state_t)99), "UNKNOWN") == 0);
    return 0;
}

TEST(test_sh_name_policy)
{
    ASSERT(strcmp(ozayn_sh_policy_state_name(OZAYN_SH_POLICY_VALID),
                  "VALID") == 0);
    ASSERT(strcmp(ozayn_sh_policy_state_name(
                  (ozayn_sh_policy_state_t)99), "UNKNOWN") == 0);
    return 0;
}

TEST(test_sh_name_event_type)
{
    ASSERT(strcmp(ozayn_sh_event_type_name(
                  OZAYN_SH_EVENT_CHECK_STARTED),
                  "CHECK_STARTED") == 0);
    ASSERT(strcmp(ozayn_sh_event_type_name(
                  (ozayn_sh_event_type_t)99), "UNKNOWN_EVENT") == 0);
    return 0;
}

TEST(test_sh_name_operation_type)
{
    ASSERT(strcmp(ozayn_sh_operation_type_name(OZAYN_SH_OP_VAULT_ACCESS),
                  "VAULT_ACCESS") == 0);
    ASSERT(strcmp(ozayn_sh_operation_type_name(
                  (ozayn_sh_operation_type_t)99),
                  "UNKNOWN_OPERATION") == 0);
    return 0;
}

TEST(test_sh_name_operation_safety)
{
    ASSERT(strcmp(ozayn_sh_operation_safety_name(OZAYN_SH_SAFE_ALLOW),
                  "ALLOW") == 0);
    ASSERT(strcmp(ozayn_sh_operation_safety_name(
                  (ozayn_sh_operation_safety_t)99),
                  "UNKNOWN") == 0);
    return 0;
}

/* ============================================================
 * STATE COMPARISON HELPER TESTS
 * ============================================================ */

TEST(test_sh_worse_state)
{
    ASSERT_EQ(OZAYN_SH_HEALTHY,
              ozayn_sh_worse_state(OZAYN_SH_HEALTHY, OZAYN_SH_HEALTHY));
    ASSERT_EQ(OZAYN_SH_DEGRADED,
              ozayn_sh_worse_state(OZAYN_SH_HEALTHY, OZAYN_SH_DEGRADED));
    ASSERT_EQ(OZAYN_SH_CRITICAL,
              ozayn_sh_worse_state(OZAYN_SH_HEALTHY, OZAYN_SH_CRITICAL));
    ASSERT_EQ(OZAYN_SH_LOCKDOWN,
              ozayn_sh_worse_state(OZAYN_SH_HEALTHY, OZAYN_SH_LOCKDOWN));
    ASSERT_EQ(OZAYN_SH_CRITICAL,
              ozayn_sh_worse_state(OZAYN_SH_DEGRADED, OZAYN_SH_CRITICAL));
    return 0;
}

TEST(test_sh_state_usable)
{
    ASSERT(ozayn_sh_state_is_usable(OZAYN_SH_HEALTHY));
    ASSERT(ozayn_sh_state_is_usable(OZAYN_SH_DEGRADED));
    ASSERT(!ozayn_sh_state_is_usable(OZAYN_SH_WARNING));
    ASSERT(!ozayn_sh_state_is_usable(OZAYN_SH_CRITICAL));
    ASSERT(!ozayn_sh_state_is_usable(OZAYN_SH_UNAVAILABLE));
    ASSERT(!ozayn_sh_state_is_usable(OZAYN_SH_UNKNOWN));
    ASSERT(!ozayn_sh_state_is_usable(OZAYN_SH_LOCKDOWN));
    return 0;
}

TEST(test_sh_state_allows_op)
{
    ASSERT(ozayn_sh_state_allows_operation(OZAYN_SH_HEALTHY,
        OZAYN_SH_OP_VAULT_ACCESS));
    ASSERT(ozayn_sh_state_allows_operation(OZAYN_SH_DEGRADED,
        OZAYN_SH_OP_VAULT_ACCESS));
    ASSERT(!ozayn_sh_state_allows_operation(OZAYN_SH_CRITICAL,
        OZAYN_SH_OP_VAULT_ACCESS));
    ASSERT(!ozayn_sh_state_allows_operation(OZAYN_SH_LOCKDOWN,
        OZAYN_SH_OP_VAULT_ACCESS));
    ASSERT(!ozayn_sh_state_allows_operation(OZAYN_SH_UNKNOWN,
        OZAYN_SH_OP_VAULT_ACCESS));
    return 0;
}

/* ============================================================
 * GLOBAL ACCESSOR TESTS
 * ============================================================ */

TEST(test_sh_global)
{
    ASSERT_NOT_NULL(ozayn_sh_get_global());
    return 0;
}

/* ============================================================
 * NEGATIVE SECURITY TESTS
 * ============================================================ */

TEST(test_sh_no_unknown_to_healthy)
{
    _init_sh_svc_basic();
    _register_core_components();

    /* Check all to get a baseline */
    ozayn_sh_check_all(&_sh_svc);

    /* Force a component to UNKNOWN */
    int idx = -1;
    for (int i = 0; i < _sh_svc.component_count; i++) {
        if (_sh_svc.components[i].component_id ==
            OZAYN_SH_COMP_KEY_MANAGEMENT) {
            idx = i;
            break;
        }
    }
    ASSERT(idx >= 0);
    _sh_svc.components[idx].health_state = OZAYN_SH_UNKNOWN;
    _sh_svc.aggregation.overall_state = OZAYN_SH_UNKNOWN;

    /* Operation must NOT be allowed */
    ozayn_sh_operation_safety_t safety = OZAYN_SH_SAFE_ALLOW;
    ASSERT_EQ(OZAYN_SH_OK,
              ozayn_sh_is_operation_safe(&_sh_svc,
                  OZAYN_SH_OP_KEY_ACCESS, &safety));
    ASSERT_NEQ(OZAYN_SH_SAFE_ALLOW, safety);
    return 0;
}

TEST(test_sh_no_lockdown_bypass)
{
    _init_sh_svc_basic();
    _register_core_components();
    _ir_svc.lockdown_active = 1;
    ozayn_sh_check_all(&_sh_svc);

    /* Every operation must be denied in lockdown */
    ozayn_sh_operation_type_t ops[] = {
        OZAYN_SH_OP_VAULT_ACCESS, OZAYN_SH_OP_KEY_ACCESS,
        OZAYN_SH_OP_ENCRYPT, OZAYN_SH_OP_DECRYPT,
        OZAYN_SH_OP_AUTHENTICATE, OZAYN_SH_OP_AUTHORIZE,
        OZAYN_SH_OP_BACKUP, OZAYN_SH_OP_RESTORE,
        OZAYN_SH_OP_DELETE, OZAYN_SH_OP_CONFIG_CHANGE,
        OZAYN_SH_OP_AUDIT_READ, OZAYN_SH_OP_INCIDENT_REPORT
    };
    for (int i = 0; i < 12; i++) {
        ozayn_sh_operation_safety_t safety = OZAYN_SH_SAFE_ALLOW;
        ASSERT_EQ(OZAYN_SH_OK,
                  ozayn_sh_is_operation_safe(&_sh_svc, ops[i], &safety));
        ASSERT_EQ(OZAYN_SH_SAFE_DENY, safety);
    }
    return 0;
}

TEST(test_sh_no_health_based_authz)
{
    _init_sh_svc_basic();
    _register_core_components();
    ozayn_sh_check_all(&_sh_svc);

    /* Health check result is not authorization */
    ozayn_sh_component_health_t health = {0};
    ASSERT_EQ(OZAYN_SH_OK,
              ozayn_sh_check(&_sh_svc,
                  OZAYN_SH_COMP_AUTHORIZATION, &health));
    /* Healthy authorization does NOT mean a user is authorized */
    ASSERT_EQ(OZAYN_SH_HEALTHY, health.health_state);
    /* Still must go through proper authz flow */
    return 0;
}

TEST(test_sh_no_secrets_in_snapshot)
{
    _init_sh_svc_basic();
    _register_core_components();
    ozayn_sh_check_all(&_sh_svc);

    ozayn_sh_snapshot_t snap = {0};
    ASSERT_EQ(OZAYN_SH_OK,
              ozayn_sh_generate_snapshot(&_sh_svc, &snap));

    /* Summary must not contain secret-like content */
    ASSERT(strstr(snap.summary, "key") == NULL ||
           strstr(snap.summary, "password") == NULL ||
           strstr(snap.summary, "token") == NULL);
    return 0;
}

TEST(test_sh_fail_closed_no_config)
{
    _reset_all();
    /* No config service -> overall must be UNKNOWN or CRITICAL */
    ozayn_sh_service_config_t cfg = {0};
    cfg.max_concurrent_checks = 1;
    ozayn_sh_service_init(&_sh_svc, &cfg);

    ozayn_sh_component_id_t deps[2] = {0};
    ozayn_sh_register_component(&_sh_svc,
        OZAYN_SH_COMP_SECURITY_CONFIGURATION,
        "SECURITY_CONFIGURATION", 1, deps, 0);

    ozayn_sh_check_all(&_sh_svc);

    /* Config unavailable -> UNKNOWN/CRITICAL */
    ASSERT(_sh_svc.aggregation.overall_state == OZAYN_SH_UNKNOWN ||
           _sh_svc.aggregation.overall_state == OZAYN_SH_CRITICAL);
    ozayn_sh_service_shutdown(&_sh_svc);
    return 0;
}

TEST(test_sh_critical_blocks_operations)
{
    _init_sh_svc_basic();
    _register_core_components();

    /* Set overall to CRITICAL */
    _sh_svc.aggregation.overall_state = OZAYN_SH_CRITICAL;

    ozayn_sh_operation_safety_t safety = OZAYN_SH_SAFE_ALLOW;
    ASSERT_EQ(OZAYN_SH_OK,
              ozayn_sh_is_operation_safe(&_sh_svc,
                  OZAYN_SH_OP_CONFIG_CHANGE, &safety));
    ASSERT_EQ(OZAYN_SH_SAFE_DENY, safety);
    return 0;
}

TEST(test_sh_no_plaintext_fallback)
{
    _init_sh_svc_basic();
    _register_core_components();

    /* Disable protection via policy -> check_all will set protection to CRITICAL */
    _sc_svc.active_policy.cryptographic.require_protection = 0;

    ozayn_sh_check_all(&_sh_svc);

    /* Vault should be degraded or worse, never healthy */
    int vault_idx = -1;
    for (int i = 0; i < _sh_svc.component_count; i++) {
        if (_sh_svc.components[i].component_id ==
            OZAYN_SH_COMP_SECURE_VAULT) {
            vault_idx = i;
            break;
        }
    }
    ASSERT(vault_idx >= 0);
    ASSERT(_sh_svc.components[vault_idx].health_state !=
           OZAYN_SH_HEALTHY);
    return 0;
}

/* ============================================================
 * SUITE
 * ============================================================ */

int run_sec_health_tests(void) {
    SUITE_BEGIN("SECURITY HEALTH TESTS");

    /* Lifecycle */
    RUN(test_sh_init);
    RUN(test_sh_init_null);
    RUN(test_sh_init_double);
    RUN(test_sh_shutdown_null);
    RUN(test_sh_is_init_null);
    RUN(test_sh_default_config);

    /* Registration */
    RUN(test_sh_register_component);
    RUN(test_sh_register_duplicate);
    RUN(test_sh_register_not_init);
    RUN(test_sh_register_null);
    RUN(test_sh_register_invalid_component);
    RUN(test_sh_register_with_dependencies);
    RUN(test_sh_register_resource_limit);
    RUN(test_sh_register_provider);
    RUN(test_sh_register_provider_not_init);

    /* Health checks */
    RUN(test_sh_check_single);
    RUN(test_sh_check_not_init);
    RUN(test_sh_check_null);
    RUN(test_sh_check_invalid_component);
    RUN(test_sh_check_config_health);
    RUN(test_sh_check_config_unavailable);
    RUN(test_sh_check_policy_health);
    RUN(test_sh_check_policy_default_deny_disabled);
    RUN(test_sh_check_policy_no_active);
    RUN(test_sh_check_authn_disabled);
    RUN(test_sh_check_ac_health);
    RUN(test_sh_check_ac_disabled);
    RUN(test_sh_check_mfa_health);
    RUN(test_sh_check_mfa_not_configured);
    RUN(test_sh_check_session_health);
    RUN(test_sh_check_session_disabled);
    RUN(test_sh_check_authz_health);
    RUN(test_sh_check_authz_default_deny_off);
    RUN(test_sh_check_rbac_health);
    RUN(test_sh_check_rbac_disabled);
    RUN(test_sh_check_perm_health);
    RUN(test_sh_check_perm_disabled);
    RUN(test_sh_check_protection_health);
    RUN(test_sh_check_protection_not_required);
    RUN(test_sh_check_key_mgmt_health);
    RUN(test_sh_check_key_mgmt_no_active);
    RUN(test_sh_check_vault_health);
    RUN(test_sh_check_vault_no_encryption);
    RUN(test_sh_check_audit_health);
    RUN(test_sh_check_audit_unavailable);
    RUN(test_sh_check_audit_integrity_health);
    RUN(test_sh_check_backup_health);
    RUN(test_sh_check_backup_disabled);
    RUN(test_sh_check_deletion_health);
    RUN(test_sh_check_deletion_no_authz);
    RUN(test_sh_check_incident_health);
    RUN(test_sh_check_incident_lockdown);
    RUN(test_sh_check_incident_unavailable);
    RUN(test_sh_check_concurrency_limit);

    /* Check all */
    RUN(test_sh_check_all);
    RUN(test_sh_check_all_increments_version);

    /* Dependencies */
    RUN(test_sh_depends_vault_protected);
    RUN(test_sh_depends_propagation);
    RUN(test_sh_depends_null);

    /* Aggregation */
    RUN(test_sh_agg_all_healthy);
    RUN(test_sh_agg_one_optional_unavailable);
    RUN(test_sh_agg_one_critical_required);
    RUN(test_sh_agg_lockdown);
    RUN(test_sh_agg_unknown);
    RUN(test_sh_agg_empty);

    /* Operation safety */
    RUN(test_sh_op_safe_healthy);
    RUN(test_sh_op_safe_lockdown);
    RUN(test_sh_op_safe_unknown);
    RUN(test_sh_op_safe_critical);
    RUN(test_sh_op_safe_vault_component_down);
    RUN(test_sh_op_safe_null);

    /* Snapshots */
    RUN(test_sh_snapshot_generate);
    RUN(test_sh_snapshot_fresh);
    RUN(test_sh_snapshot_stale);
    RUN(test_sh_snapshot_null);
    RUN(test_sh_snapshot_fresh_null);
    RUN(test_sh_snapshot_includes_policy_version);
    RUN(test_sh_snapshot_incident_info);

    /* Events */
    RUN(test_sh_event_record);
    RUN(test_sh_event_get);
    RUN(test_sh_event_ring_buffer);
    RUN(test_sh_event_null);
    RUN(test_sh_event_invalid_index);

    /* Status query */
    RUN(test_sh_get_status);
    RUN(test_sh_get_status_null);
    RUN(test_sh_get_component_status);
    RUN(test_sh_get_component_status_invalid);
    RUN(test_sh_get_safe_summary);
    RUN(test_sh_get_safe_summary_null);

    /* Change detection */
    RUN(test_sh_changes_none);
    RUN(test_sh_changes_null);

    /* Name helpers */
    RUN(test_sh_name_result);
    RUN(test_sh_name_health_state);
    RUN(test_sh_name_component);
    RUN(test_sh_name_check_type);
    RUN(test_sh_name_integrity);
    RUN(test_sh_name_config);
    RUN(test_sh_name_policy);
    RUN(test_sh_name_event_type);
    RUN(test_sh_name_operation_type);
    RUN(test_sh_name_operation_safety);

    /* State helpers */
    RUN(test_sh_worse_state);
    RUN(test_sh_state_usable);
    RUN(test_sh_state_allows_op);

    /* Global */
    RUN(test_sh_global);

    /* Negative security */
    RUN(test_sh_no_unknown_to_healthy);
    RUN(test_sh_no_lockdown_bypass);
    RUN(test_sh_no_health_based_authz);
    RUN(test_sh_no_secrets_in_snapshot);
    RUN(test_sh_fail_closed_no_config);
    RUN(test_sh_critical_blocks_operations);
    RUN(test_sh_no_plaintext_fallback);

    SUITE_END();
    return _tf_suite_fail;
}
