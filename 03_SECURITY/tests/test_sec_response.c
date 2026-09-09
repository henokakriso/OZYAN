/*
 * test_sec_response.c — Security Orchestration & Controlled Response Tests (Step 34).
 */

#include "../../tests/test_framework.h"
#include "../sec_response.h"
#include "../audit.h"
#include "../sec_alert.h"
#include "../incident.h"
#include "../sec_detect.h"
#include "../sec_intel.h"
#include "../sec_risk.h"
#include "../sec_config.h"
#include <string.h>
#include <time.h>

/* ============================================================
 * TEST HELPERS
 * ============================================================ */

static ozayn_sresp_service_t _svc;
static ozayn_salert_service_t _alert_svc;
static ozayn_ir_service_t _ir_svc;
static ozayn_sdet_service_t _det_svc;
static ozayn_audit_service_t _au_svc;
static ozayn_sr_service_t _sr_svc;
static ozayn_sintel_service_t _si_svc;
static ozayn_sc_service_t _sc_svc;

static void _reset_all(void)
{
    memset(&_svc, 0, sizeof(_svc));
    memset(&_alert_svc, 0, sizeof(_alert_svc));
    memset(&_ir_svc, 0, sizeof(_ir_svc));
    memset(&_det_svc, 0, sizeof(_det_svc));
    memset(&_au_svc, 0, sizeof(_au_svc));
    memset(&_sr_svc, 0, sizeof(_sr_svc));
    memset(&_si_svc, 0, sizeof(_si_svc));
    memset(&_sc_svc, 0, sizeof(_sc_svc));
}

static void _init_svc(void)
{
    _reset_all();
    _au_svc.initialized = 1;
    _det_svc.initialized = 1;
    _sr_svc.initialized = 1;
    _si_svc.initialized = 1;
    _sc_svc.initialized = 1;
    _sc_svc.active_policy = ozayn_sc_default_policy();

    ozayn_salert_service_config_t acfg;
    memset(&acfg, 0, sizeof(acfg));
    acfg.audit = &_au_svc;
    ozayn_salert_service_init(&_alert_svc, &acfg);

    ozayn_ir_service_config_t icfg;
    memset(&icfg, 0, sizeof(icfg));
    icfg.audit = &_au_svc;
    icfg.identity = NULL;
    ozayn_ir_service_init(&_ir_svc, &icfg);

    ozayn_sresp_service_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.risk_service = &_sr_svc;
    cfg.intel_service = &_si_svc;
    cfg.incident_service = &_ir_svc;
    cfg.alert_service = &_alert_svc;
    cfg.audit = &_au_svc;
    cfg.config_service = &_sc_svc;
    ozayn_sresp_service_init(&_svc, &cfg);
}

/* ============================================================
 * NAME HELPERS
 * ============================================================ */

TEST(test_err_name)
{
    ASSERT(strcmp(ozayn_sresp_err_name(OZAYN_SRESP_OK), "OK") == 0);
    ASSERT(strcmp(ozayn_sresp_err_name(OZAYN_SRESP_ERR_NULL), "NULL") == 0);
    ASSERT(strcmp(ozayn_sresp_err_name(OZAYN_SRESP_ERR_NOT_INITIALIZED), "NOT_INITIALIZED") == 0);
    ASSERT(strcmp(ozayn_sresp_err_name(OZAYN_SRESP_ERR_POLICY_DENIED), "POLICY_DENIED") == 0);
    ASSERT(strcmp(ozayn_sresp_err_name(OZAYN_SRESP_ERR_AUTHORIZATION_DENIED), "AUTHORIZATION_DENIED") == 0);
    ASSERT(strcmp(ozayn_sresp_err_name(OZAYN_SRESP_ERR_APPROVAL_REQUIRED), "APPROVAL_REQUIRED") == 0);
    ASSERT(strcmp(ozayn_sresp_err_name(OZAYN_SRESP_ERR_EXECUTION_FAILED), "EXECUTION_FAILED") == 0);
    ASSERT(strcmp(ozayn_sresp_err_name(OZAYN_SRESP_ERR_CONCURRENCY_CONFLICT), "CONCURRENCY_CONFLICT") == 0);
    return 0;
}

TEST(test_action_name)
{
    ASSERT(strcmp(ozayn_sresp_action_name(OZAYN_SRESP_ACTION_NONE), "NONE") == 0);
    ASSERT(strcmp(ozayn_sresp_action_name(OZAYN_SRESP_ACTION_MONITOR), "MONITOR") == 0);
    ASSERT(strcmp(ozayn_sresp_action_name(OZAYN_SRESP_ACTION_REVOKE_SESSION), "REVOKE_SESSION") == 0);
    ASSERT(strcmp(ozayn_sresp_action_name(OZAYN_SRESP_ACTION_SUSPEND_IDENTITY), "SUSPEND_IDENTITY") == 0);
    ASSERT(strcmp(ozayn_sresp_action_name(OZAYN_SRESP_ACTION_SECURITY_LOCKDOWN), "SECURITY_LOCKDOWN") == 0);
    return 0;
}

TEST(test_state_name)
{
    ASSERT(strcmp(ozayn_sresp_state_name(OZAYN_SRESP_STATE_CREATED), "CREATED") == 0);
    ASSERT(strcmp(ozayn_sresp_state_name(OZAYN_SRESP_STATE_VALIDATED), "VALIDATED") == 0);
    ASSERT(strcmp(ozayn_sresp_state_name(OZAYN_SRESP_STATE_EXECUTING), "EXECUTING") == 0);
    ASSERT(strcmp(ozayn_sresp_state_name(OZAYN_SRESP_STATE_SUCCEEDED), "SUCCEEDED") == 0);
    ASSERT(strcmp(ozayn_sresp_state_name(OZAYN_SRESP_STATE_FAILED), "FAILED") == 0);
    return 0;
}

TEST(test_exec_mode_name)
{
    ASSERT(strcmp(ozayn_sresp_exec_mode_name(OZAYN_SRESP_MODE_VALIDATE_ONLY), "VALIDATE_ONLY") == 0);
    ASSERT(strcmp(ozayn_sresp_exec_mode_name(OZAYN_SRESP_MODE_DRY_RUN), "DRY_RUN") == 0);
    ASSERT(strcmp(ozayn_sresp_exec_mode_name(OZAYN_SRESP_MODE_APPROVED_EXECUTION), "APPROVED_EXECUTION") == 0);
    return 0;
}

TEST(test_assurance_name)
{
    ASSERT(strcmp(ozayn_sresp_assurance_name(OZAYN_SRESP_ASSURANCE_NONE), "NONE") == 0);
    ASSERT(strcmp(ozayn_sresp_assurance_name(OZAYN_SRESP_ASSURANCE_SINGLE), "SINGLE") == 0);
    ASSERT(strcmp(ozayn_sresp_assurance_name(OZAYN_SRESP_ASSURANCE_MULTI), "MULTI") == 0);
    ASSERT(strcmp(ozayn_sresp_assurance_name(OZAYN_SRESP_ASSURANCE_HIGH), "HIGH") == 0);
    return 0;
}

TEST(test_rollback_name)
{
    ASSERT(strcmp(ozayn_sresp_rollback_name(OZAYN_SRESP_ROLLBACK_UNKNOWN), "UNKNOWN") == 0);
    ASSERT(strcmp(ozayn_sresp_rollback_name(OZAYN_SRESP_ROLLBACK_REVERSIBLE), "REVERSIBLE") == 0);
    ASSERT(strcmp(ozayn_sresp_rollback_name(OZAYN_SRESP_ROLLBACK_NOT_REVERSIBLE), "NOT_REVERSIBLE") == 0);
    return 0;
}

TEST(test_verify_name)
{
    ASSERT(strcmp(ozayn_sresp_verify_name(OZAYN_SRESP_VERIFY_NOT_REQUIRED), "NOT_REQUIRED") == 0);
    ASSERT(strcmp(ozayn_sresp_verify_name(OZAYN_SRESP_VERIFY_SUCCEEDED), "SUCCEEDED") == 0);
    ASSERT(strcmp(ozayn_sresp_verify_name(OZAYN_SRESP_VERIFY_FAILED), "FAILED") == 0);
    return 0;
}

TEST(test_plan_state_name)
{
    ASSERT(strcmp(ozayn_sresp_plan_state_name(OZAYN_SRESP_PLAN_CREATED), "CREATED") == 0);
    ASSERT(strcmp(ozayn_sresp_plan_state_name(OZAYN_SRESP_PLAN_COMPLETED), "COMPLETED") == 0);
    ASSERT(strcmp(ozayn_sresp_plan_state_name(OZAYN_SRESP_PLAN_FAILED), "FAILED") == 0);
    return 0;
}

TEST(test_approval_name)
{
    ASSERT(strcmp(ozayn_sresp_approval_name(OZAYN_SRESP_APPROVAL_NOT_REQUIRED), "NOT_REQUIRED") == 0);
    ASSERT(strcmp(ozayn_sresp_approval_name(OZAYN_SRESP_APPROVAL_PENDING), "PENDING") == 0);
    ASSERT(strcmp(ozayn_sresp_approval_name(OZAYN_SRESP_APPROVAL_GRANTED), "GRANTED") == 0);
    ASSERT(strcmp(ozayn_sresp_approval_name(OZAYN_SRESP_APPROVAL_DENIED), "DENIED") == 0);
    return 0;
}

TEST(test_precond_name)
{
    ASSERT(strcmp(ozayn_sresp_precond_name(OZAYN_SRESP_PRECOND_OK), "OK") == 0);
    ASSERT(strcmp(ozayn_sresp_precond_name(OZAYN_SRESP_PRECOND_RESPONSE_NOT_FOUND), "RESPONSE_NOT_FOUND") == 0);
    ASSERT(strcmp(ozayn_sresp_precond_name(OZAYN_SRESP_PRECOND_RESPONSE_EXPIRED), "RESPONSE_EXPIRED") == 0);
    return 0;
}

TEST(test_explain_name)
{
    ASSERT(strcmp(ozayn_sresp_explain_name(OZAYN_SRESP_EXPLAIN_NONE), "NONE") == 0);
    ASSERT(strcmp(ozayn_sresp_explain_name(OZAYN_SRESP_EXPLAIN_POLICY_ALLOWED), "POLICY_ALLOWED") == 0);
    ASSERT(strcmp(ozayn_sresp_explain_name(OZAYN_SRESP_EXPLAIN_AUTHORIZED), "AUTHORIZED") == 0);
    ASSERT(strcmp(ozayn_sresp_explain_name(OZAYN_SRESP_EXPLAIN_ASSURANCE_MET), "ASSURANCE_MET") == 0);
    ASSERT(strcmp(ozayn_sresp_explain_name(OZAYN_SRESP_EXPLAIN_EXECUTION_SUCCEEDED), "EXECUTION_SUCCEEDED") == 0);
    return 0;
}

/* ============================================================
 * STATE TRANSITION VALIDATION
 * ============================================================ */

TEST(test_state_transition_valid)
{
    ASSERT(ozayn_sresp_state_transition_valid(OZAYN_SRESP_STATE_CREATED, OZAYN_SRESP_STATE_VALIDATING));
    ASSERT(ozayn_sresp_state_transition_valid(OZAYN_SRESP_STATE_VALIDATING, OZAYN_SRESP_STATE_VALIDATED));
    ASSERT(ozayn_sresp_state_transition_valid(OZAYN_SRESP_STATE_VALIDATED, OZAYN_SRESP_STATE_APPROVED));
    ASSERT(ozayn_sresp_state_transition_valid(OZAYN_SRESP_STATE_APPROVED, OZAYN_SRESP_STATE_EXECUTING));
    ASSERT(ozayn_sresp_state_transition_valid(OZAYN_SRESP_STATE_EXECUTING, OZAYN_SRESP_STATE_SUCCEEDED));
    /* Invalid transitions */
    ASSERT(!ozayn_sresp_state_transition_valid(OZAYN_SRESP_STATE_SUCCEEDED, OZAYN_SRESP_STATE_CREATED));
    ASSERT(!ozayn_sresp_state_transition_valid(OZAYN_SRESP_STATE_FAILED, OZAYN_SRESP_STATE_EXECUTING));
    ASSERT(!ozayn_sresp_state_transition_valid(OZAYN_SRESP_STATE_CANCELLED, OZAYN_SRESP_STATE_EXECUTING));
    return 0;
}

TEST(test_plan_state_transition_valid)
{
    ASSERT(ozayn_sresp_plan_state_transition_valid(OZAYN_SRESP_PLAN_CREATED, OZAYN_SRESP_PLAN_VALIDATING));
    ASSERT(ozayn_sresp_plan_state_transition_valid(OZAYN_SRESP_PLAN_VALIDATING, OZAYN_SRESP_PLAN_VALIDATED));
    ASSERT(ozayn_sresp_plan_state_transition_valid(OZAYN_SRESP_PLAN_VALIDATED, OZAYN_SRESP_PLAN_APPROVED));
    ASSERT(ozayn_sresp_plan_state_transition_valid(OZAYN_SRESP_PLAN_APPROVED, OZAYN_SRESP_PLAN_EXECUTING));
    ASSERT(ozayn_sresp_plan_state_transition_valid(OZAYN_SRESP_PLAN_EXECUTING, OZAYN_SRESP_PLAN_COMPLETED));
    /* Invalid */
    ASSERT(!ozayn_sresp_plan_state_transition_valid(OZAYN_SRESP_PLAN_COMPLETED, OZAYN_SRESP_PLAN_CREATED));
    ASSERT(!ozayn_sresp_plan_state_transition_valid(OZAYN_SRESP_PLAN_FAILED, OZAYN_SRESP_PLAN_EXECUTING));
    return 0;
}

/* ============================================================
 * ACTION TYPE VALIDATION
 * ============================================================ */

TEST(test_valid_action_type)
{
    ASSERT(ozayn_sresp_is_valid_action_type(OZAYN_SRESP_ACTION_MONITOR));
    ASSERT(ozayn_sresp_is_valid_action_type(OZAYN_SRESP_ACTION_REVOKE_SESSION));
    ASSERT(ozayn_sresp_is_valid_action_type(OZAYN_SRESP_ACTION_SECURITY_LOCKDOWN));
    ASSERT(!ozayn_sresp_is_valid_action_type(OZAYN_SRESP_ACTION_NONE));
    ASSERT(!ozayn_sresp_is_valid_action_type(-1));
    ASSERT(!ozayn_sresp_is_valid_action_type(100));
    return 0;
}

TEST(test_action_requires_target)
{
    ASSERT(!ozayn_sresp_action_requires_target(OZAYN_SRESP_ACTION_MONITOR));
    ASSERT(!ozayn_sresp_action_requires_target(OZAYN_SRESP_ACTION_INVESTIGATE));
    ASSERT(!ozayn_sresp_action_requires_target(OZAYN_SRESP_ACTION_SECURITY_LOCKDOWN));
    ASSERT(ozayn_sresp_action_requires_target(OZAYN_SRESP_ACTION_REVOKE_SESSION));
    ASSERT(ozayn_sresp_action_requires_target(OZAYN_SRESP_ACTION_SUSPEND_IDENTITY));
    ASSERT(ozayn_sresp_action_requires_target(OZAYN_SRESP_ACTION_REVIEW_PERMISSION));
    return 0;
}

/* ============================================================
 * LIFECYCLE
 * ============================================================ */

TEST(test_lifecycle_null)
{
    ASSERT_EQ(ozayn_sresp_service_init(NULL, NULL), OZAYN_SRESP_ERR_NULL);
    return 0;
}

TEST(test_lifecycle_init)
{
    _reset_all();
    ozayn_sresp_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ASSERT_EQ(ozayn_sresp_service_init(&svc, NULL), OZAYN_SRESP_OK);
    ASSERT(svc.initialized);
    ASSERT(ozayn_sresp_service_is_initialized(&svc));
    ozayn_sresp_service_shutdown(&svc);
    ASSERT(!svc.initialized);
    return 0;
}

TEST(test_lifecycle_init_with_deps)
{
    _reset_all();
    _au_svc.initialized = 1;
    ozayn_sresp_service_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.audit = &_au_svc;
    ozayn_sresp_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ASSERT_EQ(ozayn_sresp_service_init(&svc, &cfg), OZAYN_SRESP_OK);
    ASSERT(svc.audit == &_au_svc);
    ozayn_sresp_service_shutdown(&svc);
    return 0;
}

TEST(test_lifecycle_double_init)
{
    _reset_all();
    ozayn_sresp_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ASSERT_EQ(ozayn_sresp_service_init(&svc, NULL), OZAYN_SRESP_OK);
    ASSERT_EQ(ozayn_sresp_service_init(&svc, NULL), OZAYN_SRESP_ERR_ALREADY_INITIALIZED);
    ozayn_sresp_service_shutdown(&svc);
    return 0;
}

TEST(test_global_accessor)
{
    ASSERT_NOT_NULL(ozayn_sresp_get_global());
    return 0;
}

/* ============================================================
 * PLAN OPERATIONS
 * ============================================================ */

TEST(test_create_plan_basic)
{
    _init_svc();
    ozayn_sresp_plan_t *p = NULL;
    ASSERT_EQ(ozayn_sresp_create_plan(&_svc, "INC-1", "RISK-1", "CORR-1", &p), OZAYN_SRESP_OK);
    ASSERT_NOT_NULL(p);
    ASSERT(p->plan_id[0] != '\0');
    ASSERT(strcmp(p->incident_id, "INC-1") == 0);
    ASSERT(strcmp(p->risk_id, "RISK-1") == 0);
    ASSERT(strcmp(p->correlation_id, "CORR-1") == 0);
    ASSERT_EQ(p->state, OZAYN_SRESP_PLAN_CREATED);
    ASSERT_EQ(_svc.plan_count, 1);
    return 0;
}

TEST(test_create_plan_null)
{
    _init_svc();
    ASSERT_EQ(ozayn_sresp_create_plan(&_svc, NULL, NULL, NULL, NULL), OZAYN_SRESP_ERR_NULL);
    return 0;
}

TEST(test_create_plan_not_initialized)
{
    _reset_all();
    ozayn_sresp_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_sresp_plan_t *p = NULL;
    ASSERT_EQ(ozayn_sresp_create_plan(&svc, "I", "R", "C", &p), OZAYN_SRESP_ERR_NOT_INITIALIZED);
    return 0;
}

TEST(test_get_plan)
{
    _init_svc();
    ozayn_sresp_plan_t *p = NULL;
    ozayn_sresp_create_plan(&_svc, "I", "R", "C", &p);
    ASSERT_NOT_NULL(ozayn_sresp_get_plan(&_svc, p->plan_id));
    ASSERT_NULL(ozayn_sresp_get_plan(&_svc, "NONEXISTENT"));
    ASSERT_NULL(ozayn_sresp_get_plan(NULL, "X"));
    return 0;
}

TEST(test_plan_count)
{
    _init_svc();
    ASSERT_EQ(ozayn_sresp_plan_count(&_svc), 0);
    ozayn_sresp_plan_t *p = NULL;
    ozayn_sresp_create_plan(&_svc, "I", "R", "C", &p);
    ASSERT_EQ(ozayn_sresp_plan_count(&_svc), 1);
    ASSERT_EQ(ozayn_sresp_plan_count(NULL), 0);
    return 0;
}

TEST(test_list_plans)
{
    _init_svc();
    ozayn_sresp_plan_t *p1, *p2;
    ozayn_sresp_create_plan(&_svc, "I1", "R1", "C1", &p1);
    ozayn_sresp_create_plan(&_svc, "I2", "R2", "C2", &p2);
    ozayn_sresp_plan_t *list[4] = {0};
    int count = ozayn_sresp_list_plans(&_svc, -1, list, 4);
    ASSERT_EQ(count, 2);
    /* Filter by CREATED */
    count = ozayn_sresp_list_plans(&_svc, OZAYN_SRESP_PLAN_CREATED, list, 4);
    ASSERT_EQ(count, 2);
    return 0;
}

/* ============================================================
 * ACTION OPERATIONS
 * ============================================================ */

TEST(test_add_action_to_plan)
{
    _init_svc();
    ozayn_sresp_plan_t *p = NULL;
    ozayn_sresp_create_plan(&_svc, "I", "R", "C", &p);
    ozayn_sresp_action_t *a = NULL;
    ASSERT_EQ(ozayn_sresp_add_action_to_plan(&_svc, p->plan_id,
        OZAYN_SRESP_ACTION_MONITOR, NULL, NULL, NULL, &a), OZAYN_SRESP_OK);
    ASSERT_NOT_NULL(a);
    ASSERT_EQ(a->action_type, OZAYN_SRESP_ACTION_MONITOR);
    ASSERT_EQ(a->state, OZAYN_SRESP_STATE_CREATED);
    ASSERT_EQ(p->action_count, 1);
    return 0;
}

TEST(test_add_action_invalid_type)
{
    _init_svc();
    ozayn_sresp_plan_t *p = NULL;
    ozayn_sresp_create_plan(&_svc, "I", "R", "C", &p);
    ozayn_sresp_action_t *a = NULL;
    ASSERT_EQ(ozayn_sresp_add_action_to_plan(&_svc, p->plan_id,
        OZAYN_SRESP_ACTION_NONE, NULL, NULL, NULL, &a), OZAYN_SRESP_ERR_ACTION_INVALID);
    return 0;
}

TEST(test_add_action_requires_target)
{
    _init_svc();
    ozayn_sresp_plan_t *p = NULL;
    ozayn_sresp_create_plan(&_svc, "I", "R", "C", &p);
    ozayn_sresp_action_t *a = NULL;
    /* REVOKE_SESSION requires a target */
    ASSERT_EQ(ozayn_sresp_add_action_to_plan(&_svc, p->plan_id,
        OZAYN_SRESP_ACTION_REVOKE_SESSION, NULL, NULL, NULL, &a),
        OZAYN_SRESP_ERR_TARGET_INVALID);
    /* With target, should succeed */
    ASSERT_EQ(ozayn_sresp_add_action_to_plan(&_svc, p->plan_id,
        OZAYN_SRESP_ACTION_REVOKE_SESSION, NULL, "SESS-1", NULL, &a),
        OZAYN_SRESP_OK);
    return 0;
}

TEST(test_add_action_not_found)
{
    _init_svc();
    ozayn_sresp_action_t *a = NULL;
    ASSERT_EQ(ozayn_sresp_add_action_to_plan(&_svc, "NONEXISTENT",
        OZAYN_SRESP_ACTION_MONITOR, NULL, NULL, NULL, &a),
        OZAYN_SRESP_ERR_NOT_FOUND);
    return 0;
}

TEST(test_add_multiple_actions)
{
    _init_svc();
    ozayn_sresp_plan_t *p = NULL;
    ozayn_sresp_create_plan(&_svc, "I", "R", "C", &p);
    ozayn_sresp_action_t *a1, *a2, *a3;
    ozayn_sresp_add_action_to_plan(&_svc, p->plan_id,
        OZAYN_SRESP_ACTION_MONITOR, NULL, NULL, NULL, &a1);
    ozayn_sresp_add_action_to_plan(&_svc, p->plan_id,
        OZAYN_SRESP_ACTION_INVESTIGATE, NULL, NULL, NULL, &a2);
    ozayn_sresp_add_action_to_plan(&_svc, p->plan_id,
        OZAYN_SRESP_ACTION_REQUIRE_MFA, NULL, "SESS-1", NULL, &a3);
    ASSERT_EQ(p->action_count, 3);
    return 0;
}

TEST(test_add_action_wrong_plan_state)
{
    _init_svc();
    ozayn_sresp_plan_t *p = NULL;
    ozayn_sresp_create_plan(&_svc, "I", "R", "C", &p);
    /* Validate the plan */
    ozayn_sresp_validate_plan(&_svc, p->plan_id);
    /* Now try to add action to validated plan */
    ozayn_sresp_action_t *a = NULL;
    ASSERT_EQ(ozayn_sresp_add_action_to_plan(&_svc, p->plan_id,
        OZAYN_SRESP_ACTION_MONITOR, NULL, NULL, NULL, &a),
        OZAYN_SRESP_ERR_STATE_TRANSITION);
    return 0;
}

/* ============================================================
 * POLICY VALIDATION
 * ============================================================ */

TEST(test_validate_plan_basic)
{
    _init_svc();
    ozayn_sresp_plan_t *p = NULL;
    ozayn_sresp_create_plan(&_svc, "I", "R", "C", &p);
    ozayn_sresp_add_action_to_plan(&_svc, p->plan_id,
        OZAYN_SRESP_ACTION_MONITOR, NULL, NULL, NULL, NULL);
    ASSERT_EQ(ozayn_sresp_validate_plan(&_svc, p->plan_id), OZAYN_SRESP_OK);
    ASSERT_EQ(p->state, OZAYN_SRESP_PLAN_VALIDATED);
    return 0;
}

TEST(test_validate_plan_not_found)
{
    _init_svc();
    ASSERT_EQ(ozayn_sresp_validate_plan(&_svc, "NONEXISTENT"),
        OZAYN_SRESP_ERR_NOT_FOUND);
    return 0;
}

TEST(test_validate_plan_policy_disabled)
{
    _init_svc();
    ozayn_sresp_plan_t *p = NULL;
    ozayn_sresp_create_plan(&_svc, "I", "R", "C", &p);
    _svc.policy.enabled = 0;
    ASSERT_EQ(ozayn_sresp_validate_plan(&_svc, p->plan_id),
        OZAYN_SRESP_ERR_POLICY_UNAVAILABLE);
    ASSERT_EQ(p->state, OZAYN_SRESP_PLAN_FAILED);
    return 0;
}

TEST(test_validate_action)
{
    _init_svc();
    ozayn_sresp_action_t a;
    memset(&a, 0, sizeof(a));
    a.action_type = OZAYN_SRESP_ACTION_MONITOR;
    a.state = OZAYN_SRESP_STATE_CREATED;
    ASSERT_EQ(ozayn_sresp_validate_action(&_svc, &a), OZAYN_SRESP_OK);
    ASSERT_EQ(a.state, OZAYN_SRESP_STATE_VALIDATED);
    return 0;
}

TEST(test_validate_action_none_not_allowed)
{
    _init_svc();
    ozayn_sresp_action_t a;
    memset(&a, 0, sizeof(a));
    a.action_type = OZAYN_SRESP_ACTION_NONE;
    a.state = OZAYN_SRESP_STATE_CREATED;
    ASSERT_EQ(ozayn_sresp_validate_action(&_svc, &a), OZAYN_SRESP_ERR_ACTION_INVALID);
    return 0;
}

/* ============================================================
 * AUTHORIZATION
 * ============================================================ */

TEST(test_authorization_no_service)
{
    _init_svc();
    ozayn_sresp_plan_t *p = NULL;
    ozayn_sresp_create_plan(&_svc, "I", "R", "C", &p);
    ozayn_sresp_add_action_to_plan(&_svc, p->plan_id,
        OZAYN_SRESP_ACTION_MONITOR, NULL, NULL, NULL, NULL);
    /* No authz service — should pass permissive */
    ASSERT_EQ(ozayn_sresp_check_authorization(&_svc, p->plan_id), OZAYN_SRESP_OK);
    return 0;
}

TEST(test_authorization_not_found)
{
    _init_svc();
    ASSERT_EQ(ozayn_sresp_check_authorization(&_svc, "NONEXISTENT"),
        OZAYN_SRESP_ERR_NOT_FOUND);
    return 0;
}

/* ============================================================
 * ASSURANCE & APPROVAL
 * ============================================================ */

TEST(test_assurance_no_service)
{
    _init_svc();
    ozayn_sresp_plan_t *p = NULL;
    ozayn_sresp_create_plan(&_svc, "I", "R", "C", &p);
    ozayn_sresp_add_action_to_plan(&_svc, p->plan_id,
        OZAYN_SRESP_ACTION_MONITOR, NULL, NULL, NULL, NULL);
    /* No MFA service — should pass permissive */
    ASSERT_EQ(ozayn_sresp_check_assurance(&_svc, p->plan_id), OZAYN_SRESP_OK);
    return 0;
}

TEST(test_approve_plan_auto)
{
    _init_svc();
    ozayn_sresp_plan_t *p = NULL;
    ozayn_sresp_create_plan(&_svc, "I", "R", "C", &p);
    ozayn_sresp_add_action_to_plan(&_svc, p->plan_id,
        OZAYN_SRESP_ACTION_MONITOR, NULL, NULL, NULL, NULL);
    ozayn_sresp_validate_plan(&_svc, p->plan_id);
    /* MONITOR doesn't require approval — auto-approve */
    ASSERT_EQ(ozayn_sresp_approve_plan(&_svc, p->plan_id, NULL), OZAYN_SRESP_OK);
    ASSERT_EQ(p->state, OZAYN_SRESP_PLAN_APPROVED);
    return 0;
}

TEST(test_approve_plan_explicit)
{
    _init_svc();
    ozayn_sresp_plan_t *p = NULL;
    ozayn_sresp_create_plan(&_svc, "I", "R", "C", &p);
    ozayn_sresp_add_action_to_plan(&_svc, p->plan_id,
        OZAYN_SRESP_ACTION_REVOKE_SESSION, NULL, "SESS-1", NULL, NULL);
    ozayn_sresp_validate_plan(&_svc, p->plan_id);
    /* REVOKE_SESSION requires approval */
    ASSERT_EQ(p->approval_state, OZAYN_SRESP_APPROVAL_PENDING);
    ASSERT_EQ(ozayn_sresp_approve_plan(&_svc, p->plan_id, "ADMIN-1"), OZAYN_SRESP_OK);
    ASSERT_EQ(p->state, OZAYN_SRESP_PLAN_APPROVED);
    ASSERT_EQ(p->approval_state, OZAYN_SRESP_APPROVAL_GRANTED);
    ASSERT(strcmp(p->approver_identity_id, "ADMIN-1") == 0);
    return 0;
}

TEST(test_reject_plan)
{
    _init_svc();
    ozayn_sresp_plan_t *p = NULL;
    ozayn_sresp_create_plan(&_svc, "I", "R", "C", &p);
    ozayn_sresp_add_action_to_plan(&_svc, p->plan_id,
        OZAYN_SRESP_ACTION_REVOKE_SESSION, NULL, "SESS-1", NULL, NULL);
    ozayn_sresp_validate_plan(&_svc, p->plan_id);
    ASSERT_EQ(ozayn_sresp_reject_plan(&_svc, p->plan_id, "ADMIN-1"), OZAYN_SRESP_OK);
    ASSERT_EQ(p->state, OZAYN_SRESP_PLAN_FAILED);
    ASSERT_EQ(p->approval_state, OZAYN_SRESP_APPROVAL_DENIED);
    return 0;
}

TEST(test_approve_not_found)
{
    _init_svc();
    ASSERT_EQ(ozayn_sresp_approve_plan(&_svc, "NONEXISTENT", NULL),
        OZAYN_SRESP_ERR_NOT_FOUND);
    return 0;
}

TEST(test_reject_not_found)
{
    _init_svc();
    ASSERT_EQ(ozayn_sresp_reject_plan(&_svc, "NONEXISTENT", NULL),
        OZAYN_SRESP_ERR_NOT_FOUND);
    return 0;
}

/* ============================================================
 * PRECONDITIONS
 * ============================================================ */

TEST(test_preconditions_ok)
{
    _init_svc();
    ozayn_sresp_plan_t *p = NULL;
    ozayn_sresp_create_plan(&_svc, "I", "R", "C", &p);
    ozayn_sresp_precond_t result;
    ASSERT_EQ(ozayn_sresp_check_preconditions(&_svc, p->plan_id, &result), OZAYN_SRESP_OK);
    ASSERT_EQ(result, OZAYN_SRESP_PRECOND_OK);
    return 0;
}

TEST(test_preconditions_not_found)
{
    _init_svc();
    ozayn_sresp_precond_t result;
    ASSERT_EQ(ozayn_sresp_check_preconditions(&_svc, "NONEXISTENT", &result), OZAYN_SRESP_OK);
    ASSERT_EQ(result, OZAYN_SRESP_PRECOND_RESPONSE_NOT_FOUND);
    return 0;
}

TEST(test_preconditions_expired)
{
    _init_svc();
    ozayn_sresp_plan_t *p = NULL;
    ozayn_sresp_create_plan(&_svc, "I", "R", "C", &p);
    p->expiration_time = time(NULL) - 1;
    ozayn_sresp_precond_t result;
    ASSERT_EQ(ozayn_sresp_check_preconditions(&_svc, p->plan_id, &result), OZAYN_SRESP_OK);
    ASSERT_EQ(result, OZAYN_SRESP_PRECOND_RESPONSE_EXPIRED);
    return 0;
}

/* ============================================================
 * EXECUTION
 * ============================================================ */

TEST(test_execute_plan_monitor)
{
    _init_svc();
    ozayn_sresp_plan_t *p = NULL;
    ozayn_sresp_create_plan(&_svc, "I", "R", "C", &p);
    ozayn_sresp_add_action_to_plan(&_svc, p->plan_id,
        OZAYN_SRESP_ACTION_MONITOR, NULL, NULL, NULL, NULL);
    ozayn_sresp_validate_plan(&_svc, p->plan_id);
    ozayn_sresp_approve_plan(&_svc, p->plan_id, NULL);
    ASSERT_EQ(ozayn_sresp_execute_plan(&_svc, p->plan_id,
        OZAYN_SRESP_MODE_APPROVED_EXECUTION), OZAYN_SRESP_OK);
    ASSERT_EQ(p->state, OZAYN_SRESP_PLAN_COMPLETED);
    ASSERT_EQ(_svc.total_plans_succeeded, 1);
    return 0;
}

TEST(test_execute_plan_dry_run)
{
    _init_svc();
    ozayn_sresp_plan_t *p = NULL;
    ozayn_sresp_create_plan(&_svc, "I", "R", "C", &p);
    ozayn_sresp_add_action_to_plan(&_svc, p->plan_id,
        OZAYN_SRESP_ACTION_REVOKE_SESSION, NULL, "SESS-1", NULL, NULL);
    ozayn_sresp_validate_plan(&_svc, p->plan_id);
    ozayn_sresp_approve_plan(&_svc, p->plan_id, "ADMIN-1");
    ASSERT_EQ(ozayn_sresp_execute_plan(&_svc, p->plan_id,
        OZAYN_SRESP_MODE_DRY_RUN), OZAYN_SRESP_OK);
    ASSERT_EQ(p->state, OZAYN_SRESP_PLAN_COMPLETED);
    /* Session should NOT be revoked in dry run */
    return 0;
}

TEST(test_execute_plan_validate_only)
{
    _init_svc();
    ozayn_sresp_plan_t *p = NULL;
    ozayn_sresp_create_plan(&_svc, "I", "R", "C", &p);
    ozayn_sresp_add_action_to_plan(&_svc, p->plan_id,
        OZAYN_SRESP_ACTION_SUSPEND_IDENTITY, "IDENT-1", NULL, NULL, NULL);
    ozayn_sresp_validate_plan(&_svc, p->plan_id);
    ozayn_sresp_approve_plan(&_svc, p->plan_id, "ADMIN-1");
    ASSERT_EQ(ozayn_sresp_execute_plan(&_svc, p->plan_id,
        OZAYN_SRESP_MODE_VALIDATE_ONLY), OZAYN_SRESP_OK);
    ASSERT_EQ(p->state, OZAYN_SRESP_PLAN_COMPLETED);
    return 0;
}

TEST(test_execute_plan_not_approved)
{
    _init_svc();
    ozayn_sresp_plan_t *p = NULL;
    ozayn_sresp_create_plan(&_svc, "I", "R", "C", &p);
    ozayn_sresp_add_action_to_plan(&_svc, p->plan_id,
        OZAYN_SRESP_ACTION_REVOKE_SESSION, NULL, "SESS-1", NULL, NULL);
    ozayn_sresp_validate_plan(&_svc, p->plan_id);
    /* Not yet approved */
    ASSERT_EQ(ozayn_sresp_execute_plan(&_svc, p->plan_id,
        OZAYN_SRESP_MODE_APPROVED_EXECUTION), OZAYN_SRESP_ERR_STATE_TRANSITION);
    return 0;
}

TEST(test_execute_plan_not_found)
{
    _init_svc();
    ASSERT_EQ(ozayn_sresp_execute_plan(&_svc, "NONEXISTENT",
        OZAYN_SRESP_MODE_APPROVED_EXECUTION), OZAYN_SRESP_ERR_NOT_FOUND);
    return 0;
}

TEST(test_execute_plan_multi_action)
{
    _init_svc();
    ozayn_sresp_plan_t *p = NULL;
    ozayn_sresp_create_plan(&_svc, "I", "R", "C", &p);
    ozayn_sresp_add_action_to_plan(&_svc, p->plan_id,
        OZAYN_SRESP_ACTION_MONITOR, NULL, NULL, NULL, NULL);
    ozayn_sresp_add_action_to_plan(&_svc, p->plan_id,
        OZAYN_SRESP_ACTION_INVESTIGATE, NULL, NULL, NULL, NULL);
    ozayn_sresp_add_action_to_plan(&_svc, p->plan_id,
        OZAYN_SRESP_ACTION_REQUIRE_MFA, NULL, "SESS-1", NULL, NULL);
    ozayn_sresp_validate_plan(&_svc, p->plan_id);
    ozayn_sresp_approve_plan(&_svc, p->plan_id, NULL);
    ASSERT_EQ(ozayn_sresp_execute_plan(&_svc, p->plan_id,
        OZAYN_SRESP_MODE_APPROVED_EXECUTION), OZAYN_SRESP_OK);
    ASSERT_EQ(p->state, OZAYN_SRESP_PLAN_COMPLETED);
    ASSERT_EQ(_svc.total_actions_succeeded, 3);
    return 0;
}

TEST(test_execute_plan_lockdown)
{
    _init_svc();
    ozayn_sresp_plan_t *p = NULL;
    ozayn_sresp_create_plan(&_svc, "I", "R", "C", &p);
    ozayn_sresp_add_action_to_plan(&_svc, p->plan_id,
        OZAYN_SRESP_ACTION_SECURITY_LOCKDOWN, NULL, NULL, NULL, NULL);
    ozayn_sresp_validate_plan(&_svc, p->plan_id);
    ozayn_sresp_approve_plan(&_svc, p->plan_id, "ADMIN-1");
    ASSERT_EQ(ozayn_sresp_execute_plan(&_svc, p->plan_id,
        OZAYN_SRESP_MODE_APPROVED_EXECUTION), OZAYN_SRESP_OK);
    ASSERT_EQ(p->state, OZAYN_SRESP_PLAN_COMPLETED);
    return 0;
}

/* ============================================================
 * IDEMPOTENCY
 * ============================================================ */

TEST(test_idempotent_execute)
{
    _init_svc();
    ozayn_sresp_plan_t *p = NULL;
    ozayn_sresp_create_plan(&_svc, "I", "R", "C", &p);
    ozayn_sresp_add_action_to_plan(&_svc, p->plan_id,
        OZAYN_SRESP_ACTION_MONITOR, NULL, NULL, NULL, NULL);
    ozayn_sresp_validate_plan(&_svc, p->plan_id);
    ozayn_sresp_approve_plan(&_svc, p->plan_id, NULL);
    /* Execute plan twice — second time actions are already succeeded */
    ozayn_sresp_execute_plan(&_svc, p->plan_id, OZAYN_SRESP_MODE_APPROVED_EXECUTION);
    ASSERT_EQ(p->state, OZAYN_SRESP_PLAN_COMPLETED);
    /* Re-executing completed plan should fail */
    ASSERT_EQ(ozayn_sresp_execute_plan(&_svc, p->plan_id,
        OZAYN_SRESP_MODE_APPROVED_EXECUTION), OZAYN_SRESP_ERR_STATE_TRANSITION);
    return 0;
}

/* ============================================================
 * CANCELLATION
 * ============================================================ */

TEST(test_cancel_plan)
{
    _init_svc();
    ozayn_sresp_plan_t *p = NULL;
    ozayn_sresp_create_plan(&_svc, "I", "R", "C", &p);
    ASSERT_EQ(ozayn_sresp_cancel_plan(&_svc, p->plan_id), OZAYN_SRESP_OK);
    ASSERT_EQ(p->state, OZAYN_SRESP_PLAN_CANCELLED);
    return 0;
}

TEST(test_cancel_plan_not_found)
{
    _init_svc();
    ASSERT_EQ(ozayn_sresp_cancel_plan(&_svc, "NONEXISTENT"),
        OZAYN_SRESP_ERR_NOT_FOUND);
    return 0;
}

TEST(test_cancel_plan_already_completed)
{
    _init_svc();
    ozayn_sresp_plan_t *p = NULL;
    ozayn_sresp_create_plan(&_svc, "I", "R", "C", &p);
    ozayn_sresp_add_action_to_plan(&_svc, p->plan_id,
        OZAYN_SRESP_ACTION_MONITOR, NULL, NULL, NULL, NULL);
    ozayn_sresp_validate_plan(&_svc, p->plan_id);
    ozayn_sresp_approve_plan(&_svc, p->plan_id, NULL);
    ozayn_sresp_execute_plan(&_svc, p->plan_id, OZAYN_SRESP_MODE_APPROVED_EXECUTION);
    ASSERT_EQ(ozayn_sresp_cancel_plan(&_svc, p->plan_id),
        OZAYN_SRESP_ERR_STATE_TRANSITION);
    return 0;
}

/* ============================================================
 * VERIFICATION
 * ============================================================ */

TEST(test_verify_plan)
{
    _init_svc();
    ozayn_sresp_plan_t *p = NULL;
    ozayn_sresp_create_plan(&_svc, "I", "R", "C", &p);
    ozayn_sresp_add_action_to_plan(&_svc, p->plan_id,
        OZAYN_SRESP_ACTION_MONITOR, NULL, NULL, NULL, NULL);
    ozayn_sresp_validate_plan(&_svc, p->plan_id);
    ozayn_sresp_approve_plan(&_svc, p->plan_id, NULL);
    ozayn_sresp_execute_plan(&_svc, p->plan_id, OZAYN_SRESP_MODE_APPROVED_EXECUTION);
    ASSERT_EQ(ozayn_sresp_verify_plan(&_svc, p->plan_id), OZAYN_SRESP_OK);
    return 0;
}

/* ============================================================
 * CONFLICT DETECTION
 * ============================================================ */

TEST(test_conflict_detection)
{
    _init_svc();
    ozayn_sresp_plan_t *p1 = NULL, *p2 = NULL;
    ozayn_sresp_create_plan(&_svc, "I1", "R1", "C1", &p1);
    ozayn_sresp_action_t *a1;
    ozayn_sresp_add_action_to_plan(&_svc, p1->plan_id,
        OZAYN_SRESP_ACTION_REVOKE_SESSION, NULL, "SESS-1", NULL, &a1);
    /* Validate and approve to keep it active */
    ozayn_sresp_validate_plan(&_svc, p1->plan_id);
    ozayn_sresp_approve_plan(&_svc, p1->plan_id, "ADMIN-1");

    /* Check for conflict — same action, same target */
    ASSERT(ozayn_sresp_has_conflicting_action(&_svc,
        OZAYN_SRESP_ACTION_REVOKE_SESSION, "SESS-1"));
    /* Different target — no conflict */
    ASSERT(!ozayn_sresp_has_conflicting_action(&_svc,
        OZAYN_SRESP_ACTION_REVOKE_SESSION, "SESS-99"));
    return 0;
}

/* ============================================================
 * HISTORY
 * ============================================================ */

TEST(test_history)
{
    _init_svc();
    ASSERT_EQ(ozayn_sresp_history_count(&_svc), 0);
    ozayn_sresp_plan_t *p = NULL;
    ozayn_sresp_create_plan(&_svc, "I", "R", "C", &p);
    ozayn_sresp_add_action_to_plan(&_svc, p->plan_id,
        OZAYN_SRESP_ACTION_MONITOR, NULL, NULL, NULL, NULL);
    ozayn_sresp_validate_plan(&_svc, p->plan_id);
    ozayn_sresp_approve_plan(&_svc, p->plan_id, NULL);
    ozayn_sresp_execute_plan(&_svc, p->plan_id, OZAYN_SRESP_MODE_APPROVED_EXECUTION);
    ASSERT_GE(ozayn_sresp_history_count(&_svc), 1);
    ozayn_sresp_history_entry_t entries[4];
    int count = ozayn_sresp_list_history(&_svc, entries, 4);
    ASSERT_GE(count, 1);
    return 0;
}

/* ============================================================
 * POLICY
 * ============================================================ */

TEST(test_default_policy)
{
    ozayn_sresp_policy_t p = ozayn_sresp_default_policy();
    ASSERT(p.enabled);
    ASSERT(p.max_plans > 0);
    ASSERT(p.max_actions_per_plan > 0);
    ASSERT(p.max_concurrent_executions > 0);
    ASSERT(p.plan_retention_seconds > 0);
    ASSERT(p.approval_timeout_seconds > 0);
    ASSERT(p.execution_timeout_seconds > 0);
    /* MONITOR should not require approval */
    ASSERT_EQ(p.approval_required[OZAYN_SRESP_ACTION_MONITOR], 0);
    /* REVOKE_SESSION should require approval */
    ASSERT_EQ(p.approval_required[OZAYN_SRESP_ACTION_REVOKE_SESSION], 1);
    /* SUSPEND_IDENTITY should require approval */
    ASSERT_EQ(p.approval_required[OZAYN_SRESP_ACTION_SUSPEND_IDENTITY], 1);
    /* SECURITY_LOCKDOWN should require approval */
    ASSERT_EQ(p.approval_required[OZAYN_SRESP_ACTION_SECURITY_LOCKDOWN], 1);
    return 0;
}

TEST(test_set_get_policy)
{
    _init_svc();
    ozayn_sresp_policy_t p = ozayn_sresp_default_policy();
    p.max_plans = 32;
    ASSERT_EQ(ozayn_sresp_set_policy(&_svc, &p), OZAYN_SRESP_OK);
    ASSERT_EQ(_svc.policy.max_plans, 32);
    const ozayn_sresp_policy_t *gp = ozayn_sresp_get_policy(&_svc);
    ASSERT_NOT_NULL(gp);
    ASSERT_EQ(gp->max_plans, 32);
    return 0;
}

TEST(test_set_policy_disabled)
{
    _init_svc();
    ozayn_sresp_policy_t p = ozayn_sresp_default_policy();
    p.enabled = 0;
    ASSERT_EQ(ozayn_sresp_set_policy(&_svc, &p), OZAYN_SRESP_ERR_POLICY_DENIED);
    return 0;
}

TEST(test_set_policy_null)
{
    _init_svc();
    ASSERT_EQ(ozayn_sresp_set_policy(&_svc, NULL), OZAYN_SRESP_ERR_NULL);
    ASSERT_EQ(ozayn_sresp_set_policy(NULL, NULL), OZAYN_SRESP_ERR_NULL);
    ASSERT_NULL(ozayn_sresp_get_policy(NULL));
    return 0;
}

/* ============================================================
 * CLEANUP
 * ============================================================ */

TEST(test_cleanup_expired)
{
    _init_svc();
    ozayn_sresp_plan_t *p1, *p2;
    ozayn_sresp_create_plan(&_svc, "I1", "R1", "C1", &p1);
    ozayn_sresp_create_plan(&_svc, "I2", "R2", "C2", &p2);
    p1->expiration_time = time(NULL) - 1; /* expired */
    p2->expiration_time = time(NULL) + 3600; /* fresh */
    int cleaned = ozayn_sresp_cleanup_expired_plans(&_svc);
    ASSERT_EQ(cleaned, 1);
    ASSERT_EQ(p1->state, OZAYN_SRESP_PLAN_EXPIRED);
    ASSERT_EQ(p2->state, OZAYN_SRESP_PLAN_CREATED);
    return 0;
}

TEST(test_cleanup_null)
{
    ASSERT_EQ(ozayn_sresp_cleanup_expired_plans(NULL), 0);
    return 0;
}

/* ============================================================
 * RESOURCE SAFETY
 * ============================================================ */

TEST(test_plans_full)
{
    _init_svc();
    ASSERT(!ozayn_sresp_plans_full(&_svc));
    _svc.plan_count = _svc.policy.max_plans;
    ASSERT(ozayn_sresp_plans_full(&_svc));
    ASSERT(ozayn_sresp_plans_full(NULL));
    return 0;
}

TEST(test_executions_at_limit)
{
    _init_svc();
    ASSERT(!ozayn_sresp_executions_at_limit(&_svc));
    _svc.active_executions = _svc.policy.max_concurrent_executions;
    ASSERT(ozayn_sresp_executions_at_limit(&_svc));
    ASSERT(ozayn_sresp_executions_at_limit(NULL));
    return 0;
}

/* ============================================================
 * NEGATIVE / SECURITY TESTS
 * ============================================================ */

TEST(test_not_initialized_ops)
{
    _reset_all();
    ozayn_sresp_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_sresp_plan_t *p = NULL;
    ASSERT_EQ(ozayn_sresp_create_plan(&svc, "I", "R", "C", &p),
        OZAYN_SRESP_ERR_NOT_INITIALIZED);
    ASSERT_EQ(ozayn_sresp_validate_plan(&svc, "X"),
        OZAYN_SRESP_ERR_NOT_INITIALIZED);
    ASSERT_EQ(ozayn_sresp_check_authorization(&svc, "X"),
        OZAYN_SRESP_ERR_NOT_INITIALIZED);
    ASSERT_EQ(ozayn_sresp_check_assurance(&svc, "X"),
        OZAYN_SRESP_ERR_NOT_INITIALIZED);
    ASSERT_EQ(ozayn_sresp_approve_plan(&svc, "X", NULL),
        OZAYN_SRESP_ERR_NOT_INITIALIZED);
    ASSERT_EQ(ozayn_sresp_execute_plan(&svc, "X",
        OZAYN_SRESP_MODE_APPROVED_EXECUTION), OZAYN_SRESP_ERR_NOT_INITIALIZED);
    ASSERT_EQ(ozayn_sresp_cancel_plan(&svc, "X"),
        OZAYN_SRESP_ERR_NOT_INITIALIZED);
    ASSERT_EQ(ozayn_sresp_set_policy(&svc, &svc.policy),
        OZAYN_SRESP_ERR_NOT_INITIALIZED);
    return 0;
}

TEST(test_no_bypass_after_policy_failure)
{
    _init_svc();
    ozayn_sresp_plan_t *p = NULL;
    ozayn_sresp_create_plan(&_svc, "I", "R", "C", &p);
    _svc.policy.enabled = 0;
    ASSERT_EQ(ozayn_sresp_validate_plan(&_svc, p->plan_id),
        OZAYN_SRESP_ERR_POLICY_UNAVAILABLE);
    /* Cannot execute after policy failure */
    ASSERT_EQ(ozayn_sresp_execute_plan(&_svc, p->plan_id,
        OZAYN_SRESP_MODE_APPROVED_EXECUTION), OZAYN_SRESP_ERR_STATE_TRANSITION);
    return 0;
}

TEST(test_no_bypass_after_rejection)
{
    _init_svc();
    ozayn_sresp_plan_t *p = NULL;
    ozayn_sresp_create_plan(&_svc, "I", "R", "C", &p);
    ozayn_sresp_add_action_to_plan(&_svc, p->plan_id,
        OZAYN_SRESP_ACTION_REVOKE_SESSION, NULL, "SESS-1", NULL, NULL);
    ozayn_sresp_validate_plan(&_svc, p->plan_id);
    ozayn_sresp_reject_plan(&_svc, p->plan_id, "ADMIN-1");
    /* Cannot execute after rejection */
    ASSERT_EQ(ozayn_sresp_execute_plan(&_svc, p->plan_id,
        OZAYN_SRESP_MODE_APPROVED_EXECUTION), OZAYN_SRESP_ERR_STATE_TRANSITION);
    return 0;
}

TEST(test_no_hidden_admin_bypass)
{
    /* Verify there is no hidden admin bypass */
    ozayn_sresp_policy_t p = ozayn_sresp_default_policy();
    /* No action has 0 assurance AND 0 approval when it should */
    /* SECURITY_LOCKDOWN should require highest assurance */
    ASSERT_GE(p.assurance_requirement[OZAYN_SRESP_ACTION_SECURITY_LOCKDOWN], 3);
    ASSERT_EQ(p.approval_required[OZAYN_SRESP_ACTION_SECURITY_LOCKDOWN], 1);
    /* SUSPEND_IDENTITY should require approval */
    ASSERT_EQ(p.approval_required[OZAYN_SRESP_ACTION_SUSPEND_IDENTITY], 1);
    /* REVOKE_SESSION should require approval */
    ASSERT_EQ(p.approval_required[OZAYN_SRESP_ACTION_REVOKE_SESSION], 1);
    return 0;
}

/* ============================================================
 * AUDIT
 * ============================================================ */

TEST(test_audit_event)
{
    _init_svc();
    ASSERT_EQ(ozayn_sresp_audit_event(&_svc, "TEST_EVENT", "test detail"), OZAYN_SRESP_OK);
    ASSERT_EQ(ozayn_sresp_audit_event(NULL, "E", "D"), OZAYN_SRESP_ERR_NULL);
    return 0;
}

/* ============================================================
 * STATISTICS
 * ============================================================ */

TEST(test_statistics)
{
    _init_svc();
    ASSERT_EQ(_svc.total_plans_created, 0);
    ASSERT_EQ(_svc.total_plans_executed, 0);
    ozayn_sresp_plan_t *p = NULL;
    ozayn_sresp_create_plan(&_svc, "I", "R", "C", &p);
    ASSERT_EQ(_svc.total_plans_created, 1);
    ozayn_sresp_add_action_to_plan(&_svc, p->plan_id,
        OZAYN_SRESP_ACTION_MONITOR, NULL, NULL, NULL, NULL);
    ozayn_sresp_validate_plan(&_svc, p->plan_id);
    ASSERT_EQ(_svc.total_plans_validated, 1);
    ozayn_sresp_approve_plan(&_svc, p->plan_id, NULL);
    ASSERT_EQ(_svc.total_plans_approved, 1);
    ozayn_sresp_execute_plan(&_svc, p->plan_id, OZAYN_SRESP_MODE_APPROVED_EXECUTION);
    ASSERT_EQ(_svc.total_plans_succeeded, 1);
    return 0;
}

/* ============================================================
 * FULL ORCHESTRATION FLOW
 * ============================================================ */

TEST(test_full_orchestration_flow)
{
    _init_svc();
    /* 1. Create plan from risk decision */
    ozayn_sresp_plan_t *p = NULL;
    ASSERT_EQ(ozayn_sresp_create_plan(&_svc, "INC-1", "RISK-1", "CORR-1", &p), OZAYN_SRESP_OK);

    /* 2. Add response actions */
    ozayn_sresp_action_t *a_monitor, *a_revoke;
    ozayn_sresp_add_action_to_plan(&_svc, p->plan_id,
        OZAYN_SRESP_ACTION_MONITOR, NULL, NULL, NULL, &a_monitor);
    ozayn_sresp_add_action_to_plan(&_svc, p->plan_id,
        OZAYN_SRESP_ACTION_REVOKE_SESSION, NULL, "SESS-SUSPICIOUS", NULL, &a_revoke);

    /* 3. Policy validation */
    ASSERT_EQ(ozayn_sresp_validate_plan(&_svc, p->plan_id), OZAYN_SRESP_OK);
    ASSERT_EQ(p->state, OZAYN_SRESP_PLAN_VALIDATED);

    /* 4. Precondition check */
    ozayn_sresp_precond_t precond;
    ASSERT_EQ(ozayn_sresp_check_preconditions(&_svc, p->plan_id, &precond), OZAYN_SRESP_OK);
    ASSERT_EQ(precond, OZAYN_SRESP_PRECOND_OK);

    /* 5. Authorization (no authz service — permissive) */
    ASSERT_EQ(ozayn_sresp_check_authorization(&_svc, p->plan_id), OZAYN_SRESP_OK);

    /* 6. Assurance check (no MFA — permissive) */
    ASSERT_EQ(ozayn_sresp_check_assurance(&_svc, p->plan_id), OZAYN_SRESP_OK);

    /* 7. Approval (REVOKE_SESSION requires approval) */
    ASSERT_EQ(ozayn_sresp_approve_plan(&_svc, p->plan_id, "ADMIN-1"), OZAYN_SRESP_OK);
    ASSERT_EQ(p->state, OZAYN_SRESP_PLAN_APPROVED);

    /* 8. Execution */
    ASSERT_EQ(ozayn_sresp_execute_plan(&_svc, p->plan_id,
        OZAYN_SRESP_MODE_APPROVED_EXECUTION), OZAYN_SRESP_OK);
    ASSERT_EQ(p->state, OZAYN_SRESP_PLAN_COMPLETED);

    /* 9. Verification */
    ASSERT_EQ(ozayn_sresp_verify_plan(&_svc, p->plan_id), OZAYN_SRESP_OK);

    /* 10. Audit trail exists */
    ASSERT_GE(ozayn_sresp_history_count(&_svc), 2);

    /* 11. Statistics */
    ASSERT_GE(_svc.total_plans_succeeded, 1);
    ASSERT_GE(_svc.total_actions_succeeded, 2);
    return 0;
}

/* ============================================================
 * RUN ALL TESTS
 * ============================================================ */

int run_sec_response_tests(void)
{
    SUITE_BEGIN("Security Orchestration & Controlled Response");

    /* Name helpers */
    RUN(test_err_name);
    RUN(test_action_name);
    RUN(test_state_name);
    RUN(test_exec_mode_name);
    RUN(test_assurance_name);
    RUN(test_rollback_name);
    RUN(test_verify_name);
    RUN(test_plan_state_name);
    RUN(test_approval_name);
    RUN(test_precond_name);
    RUN(test_explain_name);

    /* State transitions */
    RUN(test_state_transition_valid);
    RUN(test_plan_state_transition_valid);

    /* Action type validation */
    RUN(test_valid_action_type);
    RUN(test_action_requires_target);

    /* Lifecycle */
    RUN(test_lifecycle_null);
    RUN(test_lifecycle_init);
    RUN(test_lifecycle_init_with_deps);
    RUN(test_lifecycle_double_init);
    RUN(test_global_accessor);

    /* Plan operations */
    RUN(test_create_plan_basic);
    RUN(test_create_plan_null);
    RUN(test_create_plan_not_initialized);
    RUN(test_get_plan);
    RUN(test_plan_count);
    RUN(test_list_plans);

    /* Action operations */
    RUN(test_add_action_to_plan);
    RUN(test_add_action_invalid_type);
    RUN(test_add_action_requires_target);
    RUN(test_add_action_not_found);
    RUN(test_add_multiple_actions);
    RUN(test_add_action_wrong_plan_state);

    /* Policy validation */
    RUN(test_validate_plan_basic);
    RUN(test_validate_plan_not_found);
    RUN(test_validate_plan_policy_disabled);
    RUN(test_validate_action);
    RUN(test_validate_action_none_not_allowed);

    /* Authorization */
    RUN(test_authorization_no_service);
    RUN(test_authorization_not_found);

    /* Assurance & approval */
    RUN(test_assurance_no_service);
    RUN(test_approve_plan_auto);
    RUN(test_approve_plan_explicit);
    RUN(test_reject_plan);
    RUN(test_approve_not_found);
    RUN(test_reject_not_found);

    /* Preconditions */
    RUN(test_preconditions_ok);
    RUN(test_preconditions_not_found);
    RUN(test_preconditions_expired);

    /* Execution */
    RUN(test_execute_plan_monitor);
    RUN(test_execute_plan_dry_run);
    RUN(test_execute_plan_validate_only);
    RUN(test_execute_plan_not_approved);
    RUN(test_execute_plan_not_found);
    RUN(test_execute_plan_multi_action);
    RUN(test_execute_plan_lockdown);

    /* Idempotency */
    RUN(test_idempotent_execute);

    /* Cancellation */
    RUN(test_cancel_plan);
    RUN(test_cancel_plan_not_found);
    RUN(test_cancel_plan_already_completed);

    /* Verification */
    RUN(test_verify_plan);

    /* Conflict detection */
    RUN(test_conflict_detection);

    /* History */
    RUN(test_history);

    /* Policy */
    RUN(test_default_policy);
    RUN(test_set_get_policy);
    RUN(test_set_policy_disabled);
    RUN(test_set_policy_null);

    /* Cleanup */
    RUN(test_cleanup_expired);
    RUN(test_cleanup_null);

    /* Resource safety */
    RUN(test_plans_full);
    RUN(test_executions_at_limit);

    /* Negative / security */
    RUN(test_not_initialized_ops);
    RUN(test_no_bypass_after_policy_failure);
    RUN(test_no_bypass_after_rejection);
    RUN(test_no_hidden_admin_bypass);

    /* Audit */
    RUN(test_audit_event);

    /* Statistics */
    RUN(test_statistics);

    /* Full orchestration flow */
    RUN(test_full_orchestration_flow);

    SUITE_END();
    return TOTAL_FAIL();
}
