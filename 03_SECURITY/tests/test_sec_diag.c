/*
 * test_sec_diag.c — Security Diagnostics Tests (Step 28).
 *
 * Comprehensive tests for the security diagnostics system:
 * lifecycle, check registration, provider, dependency graph,
 * cycle detection, all component diagnostics, result query,
 * summary, modes, cost control, freshness, and negative tests.
 */

#include "../../tests/test_framework.h"
#include "../sec_diag.h"
#include "../sec_config.h"
#include "../incident.h"
#include <string.h>
#include <time.h>

/* ============================================================
 * TEST HELPERS
 * ============================================================ */

static ozayn_sdiag_service_t _sd_svc;
static ozayn_sc_service_t _sc_svc;
static ozayn_sh_service_t _sh_svc;
static ozayn_ir_service_t _ir_svc;
static ozayn_audit_service_t _au_svc;

static void _reset_all(void)
{
    memset(&_sd_svc, 0, sizeof(_sd_svc));
    memset(&_sc_svc, 0, sizeof(_sc_svc));
    memset(&_sh_svc, 0, sizeof(_sh_svc));
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

static void _init_sd_svc(void)
{
    _reset_all();
    _init_sc_svc();
    _init_au_svc();
    _init_ir_svc();

    ozayn_sdiag_service_config_t cfg = {0};
    cfg.config_service = &_sc_svc;
    cfg.incident_service = &_ir_svc;
    cfg.audit = &_au_svc;
    cfg.max_concurrent = 2;
    ozayn_sdiag_service_init(&_sd_svc, &cfg);
}

static void _register_core_checks(void)
{
    static uint32_t id = 1;
    ozayn_sdiag_check_t check = {0};
    check.enabled = 1;
    check.cost = OZAYN_SDIAG_COST_LOW;
    check.severity = OZAYN_SDIAG_SEV_INFO;

    static const ozayn_sh_component_id_t comps[] = {
        OZAYN_SH_COMP_SECURITY_CONFIGURATION,
        OZAYN_SH_COMP_SECURITY_POLICY,
        OZAYN_SH_COMP_IDENTITY,
        OZAYN_SH_COMP_AUTHENTICATION,
        OZAYN_SH_COMP_ATTEMPT_CONTROL,
        OZAYN_SH_COMP_MFA,
        OZAYN_SH_COMP_SESSION,
        OZAYN_SH_COMP_AUTHORIZATION,
        OZAYN_SH_COMP_RBAC,
        OZAYN_SH_COMP_PERMISSION,
        OZAYN_SH_COMP_SECURE_DATA,
        OZAYN_SH_COMP_STORAGE,
        OZAYN_SH_COMP_PROTECTION,
        OZAYN_SH_COMP_KEY_MANAGEMENT,
        OZAYN_SH_COMP_KEY_STORAGE,
        OZAYN_SH_COMP_KEY_LIFECYCLE,
        OZAYN_SH_COMP_SECURE_VAULT,
        OZAYN_SH_COMP_AUDIT,
        OZAYN_SH_COMP_AUDIT_INTEGRITY,
        OZAYN_SH_COMP_BACKUP,
        OZAYN_SH_COMP_RECOVERY,
        OZAYN_SH_COMP_SECURE_DELETION,
        OZAYN_SH_COMP_INCIDENT_RESPONSE
    };

    for (int i = 0; i < 23; i++) {
        check.check_id = id++;
        check.component = comps[i];
        check.category = OZAYN_SDIAG_CAT_AVAILABILITY;
        snprintf(check.check_name, OZAYN_SDIAG_MAX_CHECK_NAME_LEN,
                 "check_%s", ozayn_sh_component_name(comps[i]));
        ozayn_sdiag_register_check(&_sd_svc, &check);
    }
}

/* ============================================================
 * LIFECYCLE TESTS
 * ============================================================ */

TEST(test_sd_init)
{
    _reset_all();
    ozayn_sdiag_service_config_t cfg = {0};
    ASSERT_EQ(OZAYN_SDIAG_OK, ozayn_sdiag_service_init(&_sd_svc, &cfg));
    ASSERT(ozayn_sdiag_service_is_initialized(&_sd_svc));
    ozayn_sdiag_service_shutdown(&_sd_svc);
    ASSERT(!ozayn_sdiag_service_is_initialized(&_sd_svc));
    return 0;
}

TEST(test_sd_init_null)
{
    ASSERT_EQ(OZAYN_SDIAG_ERR_NULL, ozayn_sdiag_service_init(NULL, NULL));
    return 0;
}

TEST(test_sd_init_double)
{
    _reset_all();
    ozayn_sdiag_service_config_t cfg = {0};
    ASSERT_EQ(OZAYN_SDIAG_OK, ozayn_sdiag_service_init(&_sd_svc, &cfg));
    ASSERT_EQ(OZAYN_SDIAG_ERR_ALREADY_INITIALIZED,
              ozayn_sdiag_service_init(&_sd_svc, &cfg));
    ozayn_sdiag_service_shutdown(&_sd_svc);
    return 0;
}

TEST(test_sd_shutdown_null)
{
    ozayn_sdiag_service_shutdown(NULL);
    return 0;
}

TEST(test_sd_is_init_null)
{
    ASSERT(!ozayn_sdiag_service_is_initialized(NULL));
    return 0;
}

TEST(test_sd_default_config)
{
    _reset_all();
    ozayn_sdiag_service_config_t cfg = {0};
    ASSERT_EQ(OZAYN_SDIAG_OK, ozayn_sdiag_service_init(&_sd_svc, &cfg));
    ASSERT_EQ(1, _sd_svc.max_concurrent);
    ASSERT_EQ(OZAYN_SDIAG_MODE_STANDARD, _sd_svc.mode);
    ozayn_sdiag_service_shutdown(&_sd_svc);
    return 0;
}

/* ============================================================
 * CHECK REGISTRATION TESTS
 * ============================================================ */

TEST(test_sd_register_check)
{
    _init_sd_svc();
    ozayn_sdiag_check_t check = {0};
    check.check_id = 1;
    check.component = OZAYN_SH_COMP_IDENTITY;
    check.category = OZAYN_SDIAG_CAT_AVAILABILITY;
    check.enabled = 1;
    check.cost = OZAYN_SDIAG_COST_LOW;
    ASSERT_EQ(OZAYN_SDIAG_OK, ozayn_sdiag_register_check(&_sd_svc, &check));
    ASSERT_EQ(1, _sd_svc.check_count);
    return 0;
}

TEST(test_sd_register_check_duplicate)
{
    _init_sd_svc();
    ozayn_sdiag_check_t check = {0};
    check.check_id = 1;
    check.component = OZAYN_SH_COMP_IDENTITY;
    ASSERT_EQ(OZAYN_SDIAG_OK, ozayn_sdiag_register_check(&_sd_svc, &check));
    ASSERT_EQ(OZAYN_SDIAG_ERR_INVALID_REQUEST,
              ozayn_sdiag_register_check(&_sd_svc, &check));
    return 0;
}

TEST(test_sd_register_check_null)
{
    ASSERT_EQ(OZAYN_SDIAG_ERR_NULL,
              ozayn_sdiag_register_check(NULL, NULL));
    return 0;
}

TEST(test_sd_register_check_not_init)
{
    ozayn_sdiag_service_t svc = {0};
    ozayn_sdiag_check_t check = {0};
    ASSERT_EQ(OZAYN_SDIAG_ERR_NOT_INITIALIZED,
              ozayn_sdiag_register_check(&svc, &check));
    return 0;
}

TEST(test_sd_register_check_resource_limit)
{
    _init_sd_svc();
    ozayn_sdiag_check_t check = {0};
    check.component = OZAYN_SH_COMP_IDENTITY;
    for (uint32_t i = 0; i < OZAYN_SDIAG_MAX_CHECKS; i++) {
        check.check_id = i + 1;
        ozayn_sdiag_register_check(&_sd_svc, &check);
    }
    check.check_id = OZAYN_SDIAG_MAX_CHECKS + 1;
    ASSERT_EQ(OZAYN_SDIAG_ERR_RESOURCE_LIMIT,
              ozayn_sdiag_register_check(&_sd_svc, &check));
    return 0;
}

TEST(test_sd_register_provider)
{
    _init_sd_svc();
    ozayn_sdiag_provider_vtable_t vt = {0};
    vt.run_check = NULL;
    ASSERT_EQ(OZAYN_SDIAG_ERR_NULL,
              ozayn_sdiag_register_provider(&_sd_svc, &vt, NULL));
    return 0;
}

TEST(test_sd_register_provider_null)
{
    _init_sd_svc();
    ASSERT_EQ(OZAYN_SDIAG_ERR_NULL,
              ozayn_sdiag_register_provider(&_sd_svc, NULL, NULL));
    return 0;
}

TEST(test_sd_register_provider_not_init)
{
    ozayn_sdiag_service_t svc = {0};
    ASSERT_EQ(OZAYN_SDIAG_ERR_NOT_INITIALIZED,
              ozayn_sdiag_register_provider(&svc, NULL, NULL));
    return 0;
}

/* ============================================================
 * DEPENDENCY GRAPH TESTS
 * ============================================================ */

TEST(test_sd_dep_add)
{
    _init_sd_svc();
    ASSERT_EQ(OZAYN_SDIAG_OK,
              ozayn_sdiag_add_dependency(&_sd_svc,
                  OZAYN_SH_COMP_SECURE_VAULT,
                  OZAYN_SH_COMP_PROTECTION));
    ASSERT_EQ(1, _sd_svc.graph.edge_count);
    return 0;
}

TEST(test_sd_dep_self)
{
    _init_sd_svc();
    ASSERT_EQ(OZAYN_SDIAG_ERR_INVALID_REQUEST,
              ozayn_sdiag_add_dependency(&_sd_svc,
                  OZAYN_SH_COMP_IDENTITY,
                  OZAYN_SH_COMP_IDENTITY));
    return 0;
}

TEST(test_sd_dep_duplicate)
{
    _init_sd_svc();
    ASSERT_EQ(OZAYN_SDIAG_OK,
              ozayn_sdiag_add_dependency(&_sd_svc,
                  OZAYN_SH_COMP_SECURE_VAULT,
                  OZAYN_SH_COMP_PROTECTION));
    ASSERT_EQ(OZAYN_SDIAG_ERR_INVALID_REQUEST,
              ozayn_sdiag_add_dependency(&_sd_svc,
                  OZAYN_SH_COMP_SECURE_VAULT,
                  OZAYN_SH_COMP_PROTECTION));
    return 0;
}

TEST(test_sd_dep_cycle_detect)
{
    _init_sd_svc();
    ASSERT_EQ(OZAYN_SDIAG_OK,
              ozayn_sdiag_add_dependency(&_sd_svc,
                  OZAYN_SH_COMP_SECURE_VAULT,
                  OZAYN_SH_COMP_PROTECTION));
    ASSERT_EQ(OZAYN_SDIAG_OK,
              ozayn_sdiag_add_dependency(&_sd_svc,
                  OZAYN_SH_COMP_PROTECTION,
                  OZAYN_SH_COMP_KEY_MANAGEMENT));
    /* This should create a cycle: VAULT->PROT->KEYMGMT,
     * but we need to add an edge that creates A->B->C->A.
     * Let's add KEYMGMT->VAULT */
    ASSERT_EQ(OZAYN_SDIAG_ERR_RECURSION,
              ozayn_sdiag_add_dependency(&_sd_svc,
                  OZAYN_SH_COMP_KEY_MANAGEMENT,
                  OZAYN_SH_COMP_SECURE_VAULT));
    ASSERT(ozayn_sdiag_has_cycle(&_sd_svc));
    return 0;
}

TEST(test_sd_dep_no_cycle)
{
    _init_sd_svc();
    ASSERT_EQ(OZAYN_SDIAG_OK,
              ozayn_sdiag_add_dependency(&_sd_svc,
                  OZAYN_SH_COMP_SECURE_VAULT,
                  OZAYN_SH_COMP_PROTECTION));
    ASSERT_EQ(OZAYN_SDIAG_OK,
              ozayn_sdiag_add_dependency(&_sd_svc,
                  OZAYN_SH_COMP_PROTECTION,
                  OZAYN_SH_COMP_KEY_MANAGEMENT));
    ASSERT(!ozayn_sdiag_has_cycle(&_sd_svc));
    return 0;
}

TEST(test_sd_dep_get_cycle)
{
    _init_sd_svc();
    ozayn_sdiag_add_dependency(&_sd_svc,
        OZAYN_SH_COMP_SECURE_VAULT, OZAYN_SH_COMP_PROTECTION);
    ozayn_sdiag_add_dependency(&_sd_svc,
        OZAYN_SH_COMP_PROTECTION, OZAYN_SH_COMP_KEY_MANAGEMENT);
    ozayn_sdiag_add_dependency(&_sd_svc,
        OZAYN_SH_COMP_KEY_MANAGEMENT, OZAYN_SH_COMP_SECURE_VAULT);

    ozayn_sh_component_id_t start = 0, end = 0;
    ASSERT_EQ(OZAYN_SDIAG_OK,
              ozayn_sdiag_get_cycle(&_sd_svc, &start, &end));
    ASSERT(start > 0);
    ASSERT(end > 0);
    return 0;
}

TEST(test_sd_dep_get_cycle_no_cycle)
{
    _init_sd_svc();
    ozayn_sh_component_id_t start = 0, end = 0;
    ASSERT_EQ(OZAYN_SDIAG_ERR_INVALID_REQUEST,
              ozayn_sdiag_get_cycle(&_sd_svc, &start, &end));
    return 0;
}

TEST(test_sd_dep_null)
{
    ASSERT_EQ(OZAYN_SDIAG_ERR_NULL,
              ozayn_sdiag_add_dependency(NULL, 0, 0));
    return 0;
}

TEST(test_sd_dep_resource_limit)
{
    _init_sd_svc();
    int edge_count = 0;
    for (int from = 0; from < 23 && edge_count < OZAYN_SDIAG_MAX_DEPENDENCIES; from++) {
        for (int to = from + 1; to < 23 && edge_count < OZAYN_SDIAG_MAX_DEPENDENCIES; to++) {
            ozayn_sdiag_err_t e = ozayn_sdiag_add_dependency(&_sd_svc,
                (ozayn_sh_component_id_t)from,
                (ozayn_sh_component_id_t)to);
            if (e == OZAYN_SDIAG_OK) edge_count++;
        }
    }
    ASSERT_EQ(OZAYN_SDIAG_ERR_RESOURCE_LIMIT,
              ozayn_sdiag_add_dependency(&_sd_svc,
                  OZAYN_SH_COMP_AUDIT,
                  OZAYN_SH_COMP_AUDIT_INTEGRITY));
    return 0;
}

/* ============================================================
 * CHECK EXECUTION TESTS
 * ============================================================ */

TEST(test_sd_run_check_config)
{
    _init_sd_svc();
    _register_core_checks();

    ozayn_sdiag_result_t r = {0};
    ASSERT_EQ(OZAYN_SDIAG_OK,
              ozayn_sdiag_run_check(&_sd_svc, 1, &r));
    ASSERT_EQ(OZAYN_SDIAG_STATE_PASS, r.state);
    ASSERT_EQ(OZAYN_SH_COMP_SECURITY_CONFIGURATION, r.component);
    return 0;
}

TEST(test_sd_run_check_config_no_service)
{
    _reset_all();
    _au_svc.initialized = 1;
    _ir_svc.initialized = 1;
    ozayn_sdiag_service_config_t cfg = {0};
    cfg.audit = &_au_svc;
    cfg.incident_service = &_ir_svc;
    cfg.max_concurrent = 2;
    ozayn_sdiag_service_init(&_sd_svc, &cfg);

    ozayn_sdiag_check_t check = {0};
    check.check_id = 100;
    check.component = OZAYN_SH_COMP_SECURITY_CONFIGURATION;
    check.enabled = 1;
    check.cost = OZAYN_SDIAG_COST_LOW;
    ozayn_sdiag_register_check(&_sd_svc, &check);

    ozayn_sdiag_result_t r = {0};
    ASSERT_EQ(OZAYN_SDIAG_OK,
              ozayn_sdiag_run_check(&_sd_svc, 100, &r));
    ASSERT_EQ(OZAYN_SDIAG_STATE_UNAVAILABLE, r.state);
    ozayn_sdiag_service_shutdown(&_sd_svc);
    return 0;
}

TEST(test_sd_run_check_policy_default_deny_off)
{
    _init_sd_svc();
    _sc_svc.active_policy.authorization.default_deny = 0;

    ozayn_sdiag_check_t check = {0};
    check.check_id = 200;
    check.component = OZAYN_SH_COMP_SECURITY_POLICY;
    check.enabled = 1;
    check.cost = OZAYN_SDIAG_COST_LOW;
    ozayn_sdiag_register_check(&_sd_svc, &check);

    ozayn_sdiag_result_t r = {0};
    ASSERT_EQ(OZAYN_SDIAG_OK,
              ozayn_sdiag_run_check(&_sd_svc, 200, &r));
    ASSERT_EQ(OZAYN_SDIAG_STATE_FAIL, r.state);
    ASSERT_EQ(OZAYN_SDIAG_SEV_CRITICAL, r.severity);
    return 0;
}

TEST(test_sd_run_check_authn_disabled)
{
    _init_sd_svc();
    _sc_svc.active_policy.authentication.enabled = 0;

    ozayn_sdiag_check_t check = {0};
    check.check_id = 300;
    check.component = OZAYN_SH_COMP_AUTHENTICATION;
    check.enabled = 1;
    check.cost = OZAYN_SDIAG_COST_LOW;
    ozayn_sdiag_register_check(&_sd_svc, &check);

    ozayn_sdiag_result_t r = {0};
    ASSERT_EQ(OZAYN_SDIAG_OK,
              ozayn_sdiag_run_check(&_sd_svc, 300, &r));
    ASSERT_EQ(OZAYN_SDIAG_STATE_WARNING, r.state);
    return 0;
}

TEST(test_sd_run_check_ac_disabled)
{
    _init_sd_svc();
    _sc_svc.active_policy.attempt_control.enabled = 0;

    ozayn_sdiag_check_t check = {0};
    check.check_id = 400;
    check.component = OZAYN_SH_COMP_ATTEMPT_CONTROL;
    check.enabled = 1;
    check.cost = OZAYN_SDIAG_COST_LOW;
    ozayn_sdiag_register_check(&_sd_svc, &check);

    ozayn_sdiag_result_t r = {0};
    ASSERT_EQ(OZAYN_SDIAG_OK,
              ozayn_sdiag_run_check(&_sd_svc, 400, &r));
    ASSERT_EQ(OZAYN_SDIAG_STATE_WARNING, r.state);
    return 0;
}

TEST(test_sd_run_check_mfa_no_factors)
{
    _init_sd_svc();
    _sc_svc.active_policy.mfa.enabled = 1;
    _sc_svc.active_policy.mfa.required_factor_count = 0;

    ozayn_sdiag_check_t check = {0};
    check.check_id = 500;
    check.component = OZAYN_SH_COMP_MFA;
    check.enabled = 1;
    check.cost = OZAYN_SDIAG_COST_LOW;
    ozayn_sdiag_register_check(&_sd_svc, &check);

    ozayn_sdiag_result_t r = {0};
    ASSERT_EQ(OZAYN_SDIAG_OK,
              ozayn_sdiag_run_check(&_sd_svc, 500, &r));
    ASSERT_EQ(OZAYN_SDIAG_STATE_FAIL, r.state);
    return 0;
}

TEST(test_sd_run_check_session_disabled)
{
    _init_sd_svc();
    _sc_svc.active_policy.session.enabled = 0;

    ozayn_sdiag_check_t check = {0};
    check.check_id = 600;
    check.component = OZAYN_SH_COMP_SESSION;
    check.enabled = 1;
    check.cost = OZAYN_SDIAG_COST_LOW;
    ozayn_sdiag_register_check(&_sd_svc, &check);

    ozayn_sdiag_result_t r = {0};
    ASSERT_EQ(OZAYN_SDIAG_OK,
              ozayn_sdiag_run_check(&_sd_svc, 600, &r));
    ASSERT_EQ(OZAYN_SDIAG_STATE_WARNING, r.state);
    return 0;
}

TEST(test_sd_run_check_authz_default_deny_off)
{
    _init_sd_svc();
    _sc_svc.active_policy.authorization.default_deny = 0;

    ozayn_sdiag_check_t check = {0};
    check.check_id = 700;
    check.component = OZAYN_SH_COMP_AUTHORIZATION;
    check.enabled = 1;
    check.cost = OZAYN_SDIAG_COST_LOW;
    ozayn_sdiag_register_check(&_sd_svc, &check);

    ozayn_sdiag_result_t r = {0};
    ASSERT_EQ(OZAYN_SDIAG_OK,
              ozayn_sdiag_run_check(&_sd_svc, 700, &r));
    ASSERT_EQ(OZAYN_SDIAG_STATE_FAIL, r.state);
    ASSERT_EQ(OZAYN_SDIAG_SEV_CRITICAL, r.severity);
    return 0;
}

TEST(test_sd_run_check_protection_not_required)
{
    _init_sd_svc();
    _sc_svc.active_policy.cryptographic.require_protection = 0;

    ozayn_sdiag_check_t check = {0};
    check.check_id = 800;
    check.component = OZAYN_SH_COMP_PROTECTION;
    check.enabled = 1;
    check.cost = OZAYN_SDIAG_COST_LOW;
    ozayn_sdiag_register_check(&_sd_svc, &check);

    ozayn_sdiag_result_t r = {0};
    ASSERT_EQ(OZAYN_SDIAG_OK,
              ozayn_sdiag_run_check(&_sd_svc, 800, &r));
    ASSERT_EQ(OZAYN_SDIAG_STATE_FAIL, r.state);
    ASSERT_EQ(OZAYN_SDIAG_SEV_CRITICAL, r.severity);
    return 0;
}

TEST(test_sd_run_check_key_mgmt_no_active)
{
    _init_sd_svc();
    _sc_svc.active_policy.key_management.require_active_key = 0;

    ozayn_sdiag_check_t check = {0};
    check.check_id = 900;
    check.component = OZAYN_SH_COMP_KEY_MANAGEMENT;
    check.enabled = 1;
    check.cost = OZAYN_SDIAG_COST_LOW;
    ozayn_sdiag_register_check(&_sd_svc, &check);

    ozayn_sdiag_result_t r = {0};
    ASSERT_EQ(OZAYN_SDIAG_OK,
              ozayn_sdiag_run_check(&_sd_svc, 900, &r));
    ASSERT_EQ(OZAYN_SDIAG_STATE_WARNING, r.state);
    return 0;
}

TEST(test_sd_run_check_vault_no_encryption)
{
    _init_sd_svc();
    _sc_svc.active_policy.vault.require_encryption = 0;

    ozayn_sdiag_check_t check = {0};
    check.check_id = 1000;
    check.component = OZAYN_SH_COMP_SECURE_VAULT;
    check.enabled = 1;
    check.cost = OZAYN_SDIAG_COST_LOW;
    ozayn_sdiag_register_check(&_sd_svc, &check);

    ozayn_sdiag_result_t r = {0};
    ASSERT_EQ(OZAYN_SDIAG_OK,
              ozayn_sdiag_run_check(&_sd_svc, 1000, &r));
    ASSERT_EQ(OZAYN_SDIAG_STATE_FAIL, r.state);
    return 0;
}

TEST(test_sd_run_check_audit_unavailable)
{
    _reset_all();
    _sc_svc.initialized = 1;
    _sc_svc.active_policy = ozayn_sc_default_policy();
    _ir_svc.initialized = 1;
    ozayn_sdiag_service_config_t cfg = {0};
    cfg.config_service = &_sc_svc;
    cfg.incident_service = &_ir_svc;
    cfg.max_concurrent = 2;
    ozayn_sdiag_service_init(&_sd_svc, &cfg);

    ozayn_sdiag_check_t check = {0};
    check.check_id = 1100;
    check.component = OZAYN_SH_COMP_AUDIT;
    check.enabled = 1;
    check.cost = OZAYN_SDIAG_COST_LOW;
    ozayn_sdiag_register_check(&_sd_svc, &check);

    ozayn_sdiag_result_t r = {0};
    ASSERT_EQ(OZAYN_SDIAG_OK,
              ozayn_sdiag_run_check(&_sd_svc, 1100, &r));
    ASSERT_EQ(OZAYN_SDIAG_STATE_UNAVAILABLE, r.state);
    ozayn_sdiag_service_shutdown(&_sd_svc);
    return 0;
}

TEST(test_sd_run_check_incident_lockdown)
{
    _init_sd_svc();
    _ir_svc.lockdown_active = 1;

    ozayn_sdiag_check_t check = {0};
    check.check_id = 1200;
    check.component = OZAYN_SH_COMP_INCIDENT_RESPONSE;
    check.enabled = 1;
    check.cost = OZAYN_SDIAG_COST_LOW;
    ozayn_sdiag_register_check(&_sd_svc, &check);

    ozayn_sdiag_result_t r = {0};
    ASSERT_EQ(OZAYN_SDIAG_OK,
              ozayn_sdiag_run_check(&_sd_svc, 1200, &r));
    ASSERT_EQ(OZAYN_SDIAG_STATE_WARNING, r.state);
    ASSERT_EQ(OZAYN_SDIAG_SEV_CRITICAL, r.severity);
    return 0;
}

TEST(test_sd_run_check_deletion_no_authz)
{
    _init_sd_svc();
    _sc_svc.active_policy.deletion.require_authorization = 0;

    ozayn_sdiag_check_t check = {0};
    check.check_id = 1300;
    check.component = OZAYN_SH_COMP_SECURE_DELETION;
    check.enabled = 1;
    check.cost = OZAYN_SDIAG_COST_LOW;
    ozayn_sdiag_register_check(&_sd_svc, &check);

    ozayn_sdiag_result_t r = {0};
    ASSERT_EQ(OZAYN_SDIAG_OK,
              ozayn_sdiag_run_check(&_sd_svc, 1300, &r));
    ASSERT_EQ(OZAYN_SDIAG_STATE_WARNING, r.state);
    return 0;
}

TEST(test_sd_run_check_backup_disabled)
{
    _init_sd_svc();
    _sc_svc.active_policy.backup.enabled = 0;

    ozayn_sdiag_check_t check = {0};
    check.check_id = 1400;
    check.component = OZAYN_SH_COMP_BACKUP;
    check.enabled = 1;
    check.cost = OZAYN_SDIAG_COST_LOW;
    ozayn_sdiag_register_check(&_sd_svc, &check);

    ozayn_sdiag_result_t r = {0};
    ASSERT_EQ(OZAYN_SDIAG_OK,
              ozayn_sdiag_run_check(&_sd_svc, 1400, &r));
    ASSERT_EQ(OZAYN_SDIAG_STATE_WARNING, r.state);
    return 0;
}

TEST(test_sd_run_check_null)
{
    ASSERT_EQ(OZAYN_SDIAG_ERR_NULL,
              ozayn_sdiag_run_check(NULL, 1, NULL));
    return 0;
}

TEST(test_sd_run_check_not_init)
{
    ozayn_sdiag_service_t svc = {0};
    ozayn_sdiag_result_t r = {0};
    ASSERT_EQ(OZAYN_SDIAG_ERR_NOT_INITIALIZED,
              ozayn_sdiag_run_check(&svc, 1, &r));
    return 0;
}

TEST(test_sd_run_check_invalid_id)
{
    _init_sd_svc();
    ozayn_sdiag_result_t r = {0};
    ASSERT_EQ(OZAYN_SDIAG_ERR_INVALID_CHECK,
              ozayn_sdiag_run_check(&_sd_svc, 99999, &r));
    return 0;
}

TEST(test_sd_run_check_concurrency)
{
    _init_sd_svc();
    _sd_svc.max_concurrent = 0;
    _sd_svc.active_diagnostics = 1;

    ozayn_sdiag_check_t check = {0};
    check.check_id = 1500;
    check.component = OZAYN_SH_COMP_IDENTITY;
    check.enabled = 1;
    check.cost = OZAYN_SDIAG_COST_LOW;
    ozayn_sdiag_register_check(&_sd_svc, &check);

    ozayn_sdiag_result_t r = {0};
    ASSERT_EQ(OZAYN_SDIAG_ERR_CONCURRENCY_CONFLICT,
              ozayn_sdiag_run_check(&_sd_svc, 1500, &r));
    return 0;
}

TEST(test_sd_run_all)
{
    _init_sd_svc();
    _register_core_checks();
    ASSERT_EQ(OZAYN_SDIAG_OK, ozayn_sdiag_run_all(&_sd_svc));
    ASSERT_GT(_sd_svc.total_checks_run, (uint64_t)0);
    return 0;
}

TEST(test_sd_run_component_checks)
{
    _init_sd_svc();
    _register_core_checks();
    ASSERT_EQ(OZAYN_SDIAG_OK,
              ozayn_sdiag_run_component_checks(&_sd_svc,
                  OZAYN_SH_COMP_IDENTITY));
    return 0;
}

TEST(test_sd_run_component_checks_invalid)
{
    _init_sd_svc();
    _register_core_checks();
    ASSERT_EQ(OZAYN_SDIAG_ERR_INVALID_COMPONENT,
              ozayn_sdiag_run_component_checks(&_sd_svc,
                  (ozayn_sh_component_id_t)99));
    return 0;
}

/* ============================================================
 * RESULT QUERY TESTS
 * ============================================================ */

TEST(test_sd_get_result)
{
    _init_sd_svc();
    _register_core_checks();

    ozayn_sdiag_result_t r = {0};
    uint32_t first_id = _sd_svc.checks[0].check_id;
    ASSERT_EQ(OZAYN_SDIAG_OK,
              ozayn_sdiag_run_check(&_sd_svc, first_id, &r));

    ozayn_sdiag_result_t fetched = {0};
    ASSERT_EQ(OZAYN_SDIAG_OK,
              ozayn_sdiag_get_result(&_sd_svc, r.result_id, &fetched));
    ASSERT_EQ(r.result_id, fetched.result_id);
    return 0;
}

TEST(test_sd_get_result_not_found)
{
    _init_sd_svc();
    ozayn_sdiag_result_t r = {0};
    ASSERT_EQ(OZAYN_SDIAG_ERR_NOT_FOUND,
              ozayn_sdiag_get_result(&_sd_svc, 99999, &r));
    return 0;
}

TEST(test_sd_get_result_count)
{
    _init_sd_svc();
    _register_core_checks();
    ASSERT_EQ(0, ozayn_sdiag_get_result_count(&_sd_svc));
    ozayn_sdiag_run_all(&_sd_svc);
    ASSERT_GT(ozayn_sdiag_get_result_count(&_sd_svc), 0);
    return 0;
}

TEST(test_sd_get_latest_result)
{
    _init_sd_svc();
    _register_core_checks();
    ozayn_sdiag_run_all(&_sd_svc);

    ozayn_sdiag_result_t r = {0};
    ASSERT_EQ(OZAYN_SDIAG_OK,
              ozayn_sdiag_get_latest_result(&_sd_svc,
                  OZAYN_SH_COMP_IDENTITY, &r));
    ASSERT_EQ(OZAYN_SH_COMP_IDENTITY, r.component);
    return 0;
}

TEST(test_sd_get_latest_result_not_found)
{
    _init_sd_svc();
    ozayn_sdiag_result_t r = {0};
    ASSERT_EQ(OZAYN_SDIAG_ERR_NOT_FOUND,
              ozayn_sdiag_get_latest_result(&_sd_svc,
                  OZAYN_SH_COMP_IDENTITY, &r));
    return 0;
}

/* ============================================================
 * SUMMARY TESTS
 * ============================================================ */

TEST(test_sd_summary_all_pass)
{
    _init_sd_svc();
    _register_core_checks();
    ozayn_sdiag_run_all(&_sd_svc);

    ozayn_sdiag_summary_t sum = {0};
    ASSERT_EQ(OZAYN_SDIAG_OK, ozayn_sdiag_get_summary(&_sd_svc, &sum));
    ASSERT_EQ(OZAYN_SDIAG_STATE_PASS, sum.overall_state);
    ASSERT_GT(sum.pass_count, 0);
    return 0;
}

TEST(test_sd_summary_with_fail)
{
    _init_sd_svc();
    _sc_svc.active_policy.authorization.default_deny = 0;

    ozayn_sdiag_check_t check = {0};
    check.check_id = 2000;
    check.component = OZAYN_SH_COMP_AUTHORIZATION;
    check.enabled = 1;
    check.cost = OZAYN_SDIAG_COST_LOW;
    ozayn_sdiag_register_check(&_sd_svc, &check);

    ozayn_sdiag_run_all(&_sd_svc);

    ozayn_sdiag_summary_t sum = {0};
    ASSERT_EQ(OZAYN_SDIAG_OK, ozayn_sdiag_get_summary(&_sd_svc, &sum));
    ASSERT_EQ(OZAYN_SDIAG_STATE_FAIL, sum.overall_state);
    ASSERT_GT(sum.fail_count, 0);
    return 0;
}

TEST(test_sd_summary_null)
{
    ASSERT_EQ(OZAYN_SDIAG_ERR_NULL,
              ozayn_sdiag_get_summary(NULL, NULL));
    return 0;
}

TEST(test_sd_safe_summary)
{
    _init_sd_svc();
    _register_core_checks();
    ozayn_sdiag_run_all(&_sd_svc);

    const char *s = ozayn_sdiag_get_safe_summary(&_sd_svc);
    ASSERT_NOT_NULL(s);
    ASSERT(strstr(s, "OZAYN SECURITY DIAGNOSTICS") != NULL);
    return 0;
}

TEST(test_sd_safe_summary_null)
{
    const char *s = ozayn_sdiag_get_safe_summary(NULL);
    ASSERT_NOT_NULL(s);
    ASSERT(strstr(s, "UNKNOWN") != NULL);
    return 0;
}

/* ============================================================
 * CHECK LISTING TESTS
 * ============================================================ */

TEST(test_sd_list_checks_all)
{
    _init_sd_svc();
    _register_core_checks();
    ozayn_sdiag_check_t checks[64];
    int count = ozayn_sdiag_list_checks(&_sd_svc,
        (ozayn_sh_component_id_t)-1, checks, 64);
    ASSERT_EQ(23, count);
    return 0;
}

TEST(test_sd_list_checks_filter)
{
    _init_sd_svc();
    _register_core_checks();
    ozayn_sdiag_check_t checks[64];
    int count = ozayn_sdiag_list_checks(&_sd_svc,
        OZAYN_SH_COMP_IDENTITY, checks, 64);
    ASSERT_EQ(1, count);
    ASSERT_EQ(OZAYN_SH_COMP_IDENTITY, checks[0].component);
    return 0;
}

TEST(test_sd_list_checks_null)
{
    int count = ozayn_sdiag_list_checks(NULL, 0, NULL, 0);
    ASSERT_EQ(0, count);
    return 0;
}

/* ============================================================
 * MODE & COST CONTROL TESTS
 * ============================================================ */

TEST(test_sd_mode_default)
{
    _init_sd_svc();
    ASSERT_EQ(OZAYN_SDIAG_MODE_STANDARD, ozayn_sdiag_get_mode(&_sd_svc));
    return 0;
}

TEST(test_sd_mode_set)
{
    _init_sd_svc();
    ASSERT_EQ(OZAYN_SDIAG_OK,
              ozayn_sdiag_set_mode(&_sd_svc, OZAYN_SDIAG_MODE_DEEP));
    ASSERT_EQ(OZAYN_SDIAG_MODE_DEEP, ozayn_sdiag_get_mode(&_sd_svc));
    return 0;
}

TEST(test_sd_mode_null)
{
    ASSERT_EQ(OZAYN_SDIAG_MODE_READ_ONLY, ozayn_sdiag_get_mode(NULL));
    return 0;
}

TEST(test_sd_cost_read_only_allows_low)
{
    _init_sd_svc();
    _sd_svc.mode = OZAYN_SDIAG_MODE_READ_ONLY;
    ASSERT(ozayn_sdiag_check_cost_allowed(&_sd_svc, OZAYN_SDIAG_COST_LOW));
    ASSERT(!ozayn_sdiag_check_cost_allowed(&_sd_svc, OZAYN_SDIAG_COST_MEDIUM));
    ASSERT(!ozayn_sdiag_check_cost_allowed(&_sd_svc, OZAYN_SDIAG_COST_HIGH));
    return 0;
}

TEST(test_sd_cost_standard_allows_low_medium)
{
    _init_sd_svc();
    _sd_svc.mode = OZAYN_SDIAG_MODE_STANDARD;
    ASSERT(ozayn_sdiag_check_cost_allowed(&_sd_svc, OZAYN_SDIAG_COST_LOW));
    ASSERT(ozayn_sdiag_check_cost_allowed(&_sd_svc, OZAYN_SDIAG_COST_MEDIUM));
    ASSERT(!ozayn_sdiag_check_cost_allowed(&_sd_svc, OZAYN_SDIAG_COST_HIGH));
    return 0;
}

TEST(test_sd_cost_deep_allows_all)
{
    _init_sd_svc();
    _sd_svc.mode = OZAYN_SDIAG_MODE_DEEP;
    ASSERT(ozayn_sdiag_check_cost_allowed(&_sd_svc, OZAYN_SDIAG_COST_LOW));
    ASSERT(ozayn_sdiag_check_cost_allowed(&_sd_svc, OZAYN_SDIAG_COST_MEDIUM));
    ASSERT(ozayn_sdiag_check_cost_allowed(&_sd_svc, OZAYN_SDIAG_COST_HIGH));
    return 0;
}

TEST(test_sd_cost_skip_high_in_standard)
{
    _init_sd_svc();
    _sd_svc.mode = OZAYN_SDIAG_MODE_STANDARD;

    ozayn_sdiag_check_t check = {0};
    check.check_id = 3000;
    check.component = OZAYN_SH_COMP_IDENTITY;
    check.enabled = 1;
    check.cost = OZAYN_SDIAG_COST_HIGH;
    ozayn_sdiag_register_check(&_sd_svc, &check);

    ozayn_sdiag_result_t r = {0};
    ASSERT_EQ(OZAYN_SDIAG_OK,
              ozayn_sdiag_run_check(&_sd_svc, 3000, &r));
    ASSERT_EQ(OZAYN_SDIAG_STATE_SKIPPED, r.state);
    return 0;
}

/* ============================================================
 * FRESHNESS TESTS
 * ============================================================ */

TEST(test_sd_fresh)
{
    ozayn_sdiag_result_t r = {0};
    r.timestamp = time(NULL);
    int fresh = 0;
    ASSERT_EQ(OZAYN_SDIAG_OK,
              ozayn_sdiag_result_is_fresh(&r, 60, &fresh));
    ASSERT(fresh);
    return 0;
}

TEST(test_sd_stale)
{
    ozayn_sdiag_result_t r = {0};
    r.timestamp = time(NULL) - 120;
    int fresh = 1;
    ASSERT_EQ(OZAYN_SDIAG_OK,
              ozayn_sdiag_result_is_fresh(&r, 60, &fresh));
    ASSERT(!fresh);
    return 0;
}

TEST(test_sd_fresh_null)
{
    ASSERT_EQ(OZAYN_SDIAG_ERR_NULL,
              ozayn_sdiag_result_is_fresh(NULL, 60, NULL));
    return 0;
}

/* ============================================================
 * NAME HELPER TESTS
 * ============================================================ */

TEST(test_sd_name_result)
{
    ASSERT(strcmp(ozayn_sdiag_err_name(OZAYN_SDIAG_OK), "OK") == 0);
    ASSERT(strcmp(ozayn_sdiag_err_name(OZAYN_SDIAG_ERR_NULL),
                  "ERR_NULL") == 0);
    ASSERT(strcmp(ozayn_sdiag_err_name((ozayn_sdiag_err_t)999),
                  "UNKNOWN") == 0);
    return 0;
}

TEST(test_sd_name_state)
{
    ASSERT(strcmp(ozayn_sdiag_state_name(OZAYN_SDIAG_STATE_PASS),
                  "PASS") == 0);
    ASSERT(strcmp(ozayn_sdiag_state_name(OZAYN_SDIAG_STATE_FAIL),
                  "FAIL") == 0);
    ASSERT(strcmp(ozayn_sdiag_state_name(
                  (ozayn_sdiag_state_t)99), "UNKNOWN") == 0);
    return 0;
}

TEST(test_sd_name_severity)
{
    ASSERT(strcmp(ozayn_sdiag_severity_name(OZAYN_SDIAG_SEV_INFO),
                  "INFO") == 0);
    ASSERT(strcmp(ozayn_sdiag_severity_name(OZAYN_SDIAG_SEV_CRITICAL),
                  "CRITICAL") == 0);
    ASSERT(strcmp(ozayn_sdiag_severity_name(
                  (ozayn_sdiag_severity_t)99), "UNKNOWN") == 0);
    return 0;
}

TEST(test_sd_name_category)
{
    ASSERT(strcmp(ozayn_sdiag_category_name(OZAYN_SDIAG_CAT_CONFIGURATION),
                  "CONFIGURATION") == 0);
    ASSERT(strcmp(ozayn_sdiag_category_name(OZAYN_SDIAG_CAT_RESOURCE),
                  "RESOURCE") == 0);
    ASSERT(strcmp(ozayn_sdiag_category_name(
                  (ozayn_sdiag_category_t)99), "UNKNOWN") == 0);
    return 0;
}

TEST(test_sd_name_mode)
{
    ASSERT(strcmp(ozayn_sdiag_mode_name(OZAYN_SDIAG_MODE_READ_ONLY),
                  "READ_ONLY") == 0);
    ASSERT(strcmp(ozayn_sdiag_mode_name(OZAYN_SDIAG_MODE_DEEP),
                  "DEEP") == 0);
    ASSERT(strcmp(ozayn_sdiag_mode_name(
                  (ozayn_sdiag_mode_t)99), "UNKNOWN") == 0);
    return 0;
}

TEST(test_sd_name_cost)
{
    ASSERT(strcmp(ozayn_sdiag_cost_name(OZAYN_SDIAG_COST_LOW), "LOW") == 0);
    ASSERT(strcmp(ozayn_sdiag_cost_name(OZAYN_SDIAG_COST_HIGH),
                  "HIGH") == 0);
    ASSERT(strcmp(ozayn_sdiag_cost_name(
                  (ozayn_sdiag_cost_t)99), "UNKNOWN") == 0);
    return 0;
}

TEST(test_sd_name_recommendation)
{
    ASSERT(strcmp(ozayn_sdiag_recommendation_name(OZAYN_SDIAG_REC_NONE),
                  "NONE") == 0);
    ASSERT(strcmp(ozayn_sdiag_recommendation_name(
                  OZAYN_SDIAG_REC_CHECK_SECURITY_POLICY),
                  "CHECK_SECURITY_POLICY") == 0);
    ASSERT(strcmp(ozayn_sdiag_recommendation_name(
                  (ozayn_sdiag_recommendation_t)99), "UNKNOWN") == 0);
    return 0;
}

/* ============================================================
 * GLOBAL ACCESSOR TESTS
 * ============================================================ */

TEST(test_sd_global)
{
    ASSERT_NOT_NULL(ozayn_sdiag_get_global());
    return 0;
}

/* ============================================================
 * NEGATIVE SECURITY TESTS
 * ============================================================ */

TEST(test_sd_no_secrets_in_results)
{
    _init_sd_svc();
    _register_core_checks();
    ozayn_sdiag_run_all(&_sd_svc);

    for (int i = 0; i < ozayn_sdiag_get_result_count(&_sd_svc); i++) {
        ozayn_sdiag_result_t r = {0};
        ozayn_sdiag_get_result(&_sd_svc,
            _sd_svc.results[i].result_id, &r);
        ASSERT(strstr(r.detail, "password") == NULL);
        ASSERT(strstr(r.detail, "secret") == NULL);
        ASSERT(strstr(r.detail, "private_key") == NULL);
    }
    return 0;
}

TEST(test_sd_no_secrets_in_summary)
{
    _init_sd_svc();
    _register_core_checks();
    ozayn_sdiag_run_all(&_sd_svc);

    const char *s = ozayn_sdiag_get_safe_summary(&_sd_svc);
    ASSERT(strstr(s, "password") == NULL);
    ASSERT(strstr(s, "secret") == NULL);
    ASSERT(strstr(s, "private_key") == NULL);
    return 0;
}

TEST(test_sd_no_diag_bypass)
{
    _init_sd_svc();
    _register_core_checks();
    ozayn_sdiag_run_all(&_sd_svc);

    /* Diagnostic results should never contain authorization grants */
    for (int i = 0; i < ozayn_sdiag_get_result_count(&_sd_svc); i++) {
        ozayn_sdiag_result_t r = {0};
        ozayn_sdiag_get_result(&_sd_svc,
            _sd_svc.results[i].result_id, &r);
        ASSERT(strstr(r.detail, "authorized") == NULL);
        ASSERT(strstr(r.detail, "granted") == NULL);
    }
    return 0;
}

TEST(test_sd_no_recursive_diagnosis)
{
    _init_sd_svc();
    _register_core_checks();

    /* Run all checks should not cause stack overflow or infinite loop */
    for (int i = 0; i < 10; i++) {
        ozayn_sdiag_run_all(&_sd_svc);
    }
    ASSERT_GT(_sd_svc.total_checks_run, (uint64_t)0);
    return 0;
}

TEST(test_sd_no_plaintext_fallback)
{
    _init_sd_svc();
    _sc_svc.active_policy.vault.require_encryption = 0;
    _sc_svc.active_policy.cryptographic.require_protection = 0;

    ozayn_sdiag_check_t check = {0};
    check.check_id = 4000;
    check.component = OZAYN_SH_COMP_SECURE_VAULT;
    check.enabled = 1;
    check.cost = OZAYN_SDIAG_COST_LOW;
    ozayn_sdiag_register_check(&_sd_svc, &check);

    ozayn_sdiag_result_t r = {0};
    ASSERT_EQ(OZAYN_SDIAG_OK,
              ozayn_sdiag_run_check(&_sd_svc, 4000, &r));
    ASSERT_EQ(OZAYN_SDIAG_STATE_FAIL, r.state);
    return 0;
}

TEST(test_sd_recommendation_on_failure)
{
    _init_sd_svc();
    _sc_svc.active_policy.vault.require_encryption = 0;

    ozayn_sdiag_check_t check = {0};
    check.check_id = 5000;
    check.component = OZAYN_SH_COMP_SECURE_VAULT;
    check.enabled = 1;
    check.cost = OZAYN_SDIAG_COST_LOW;
    ozayn_sdiag_register_check(&_sd_svc, &check);

    ozayn_sdiag_result_t r = {0};
    ASSERT_EQ(OZAYN_SDIAG_OK,
              ozayn_sdiag_run_check(&_sd_svc, 5000, &r));
    ASSERT_EQ(OZAYN_SDIAG_STATE_FAIL, r.state);
    ASSERT(r.recommendation != OZAYN_SDIAG_REC_NONE);
    return 0;
}

/* ============================================================
 * SUITE
 * ============================================================ */

int run_sec_diag_tests(void) {
    SUITE_BEGIN("SECURITY DIAGNOSTICS TESTS");

    /* Lifecycle */
    RUN(test_sd_init);
    RUN(test_sd_init_null);
    RUN(test_sd_init_double);
    RUN(test_sd_shutdown_null);
    RUN(test_sd_is_init_null);
    RUN(test_sd_default_config);

    /* Registration */
    RUN(test_sd_register_check);
    RUN(test_sd_register_check_duplicate);
    RUN(test_sd_register_check_null);
    RUN(test_sd_register_check_not_init);
    RUN(test_sd_register_check_resource_limit);
    RUN(test_sd_register_provider);
    RUN(test_sd_register_provider_null);
    RUN(test_sd_register_provider_not_init);

    /* Dependency graph */
    RUN(test_sd_dep_add);
    RUN(test_sd_dep_self);
    RUN(test_sd_dep_duplicate);
    RUN(test_sd_dep_cycle_detect);
    RUN(test_sd_dep_no_cycle);
    RUN(test_sd_dep_get_cycle);
    RUN(test_sd_dep_get_cycle_no_cycle);
    RUN(test_sd_dep_null);
    RUN(test_sd_dep_resource_limit);

    /* Check execution */
    RUN(test_sd_run_check_config);
    RUN(test_sd_run_check_config_no_service);
    RUN(test_sd_run_check_policy_default_deny_off);
    RUN(test_sd_run_check_authn_disabled);
    RUN(test_sd_run_check_ac_disabled);
    RUN(test_sd_run_check_mfa_no_factors);
    RUN(test_sd_run_check_session_disabled);
    RUN(test_sd_run_check_authz_default_deny_off);
    RUN(test_sd_run_check_protection_not_required);
    RUN(test_sd_run_check_key_mgmt_no_active);
    RUN(test_sd_run_check_vault_no_encryption);
    RUN(test_sd_run_check_audit_unavailable);
    RUN(test_sd_run_check_incident_lockdown);
    RUN(test_sd_run_check_deletion_no_authz);
    RUN(test_sd_run_check_backup_disabled);
    RUN(test_sd_run_check_null);
    RUN(test_sd_run_check_not_init);
    RUN(test_sd_run_check_invalid_id);
    RUN(test_sd_run_check_concurrency);
    RUN(test_sd_run_all);
    RUN(test_sd_run_component_checks);
    RUN(test_sd_run_component_checks_invalid);

    /* Result query */
    RUN(test_sd_get_result);
    RUN(test_sd_get_result_not_found);
    RUN(test_sd_get_result_count);
    RUN(test_sd_get_latest_result);
    RUN(test_sd_get_latest_result_not_found);

    /* Summary */
    RUN(test_sd_summary_all_pass);
    RUN(test_sd_summary_with_fail);
    RUN(test_sd_summary_null);
    RUN(test_sd_safe_summary);
    RUN(test_sd_safe_summary_null);

    /* Check listing */
    RUN(test_sd_list_checks_all);
    RUN(test_sd_list_checks_filter);
    RUN(test_sd_list_checks_null);

    /* Mode & cost */
    RUN(test_sd_mode_default);
    RUN(test_sd_mode_set);
    RUN(test_sd_mode_null);
    RUN(test_sd_cost_read_only_allows_low);
    RUN(test_sd_cost_standard_allows_low_medium);
    RUN(test_sd_cost_deep_allows_all);
    RUN(test_sd_cost_skip_high_in_standard);

    /* Freshness */
    RUN(test_sd_fresh);
    RUN(test_sd_stale);
    RUN(test_sd_fresh_null);

    /* Name helpers */
    RUN(test_sd_name_result);
    RUN(test_sd_name_state);
    RUN(test_sd_name_severity);
    RUN(test_sd_name_category);
    RUN(test_sd_name_mode);
    RUN(test_sd_name_cost);
    RUN(test_sd_name_recommendation);

    /* Global */
    RUN(test_sd_global);

    /* Negative security */
    RUN(test_sd_no_secrets_in_results);
    RUN(test_sd_no_secrets_in_summary);
    RUN(test_sd_no_diag_bypass);
    RUN(test_sd_no_recursive_diagnosis);
    RUN(test_sd_no_plaintext_fallback);
    RUN(test_sd_recommendation_on_failure);

    SUITE_END();
    return _tf_suite_fail;
}
