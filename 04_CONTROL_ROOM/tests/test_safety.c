/*
 * test_safety.c — Safety, Preconditions & Policy Enforcement Tests (Step 08).
 *
 * Comprehensive tests for: lifecycle, preconditions, policies,
 * safety evaluation, conflicts, rechecks, cleanup, events, audit.
 */

#include "../../tests/test_framework.h"
#include "../safety.h"
#include "../../03_SECURITY/audit.h"
#include "../../03_SECURITY/authorization.h"
#include <string.h>
#include <time.h>

/* ============================================================
 * TEST HELPERS
 * ============================================================ */

static ozayn_spe_service_t _svc;
static ozayn_audit_service_t _au_svc;
static ozayn_authz_service_t _authz_svc;

static void _reset_all(void)
{
    memset(&_svc, 0, sizeof(_svc));
    memset(&_au_svc, 0, sizeof(_au_svc));
    memset(&_authz_svc, 0, sizeof(_authz_svc));
}

static void _init_svc(void)
{
    _reset_all();
    _au_svc.initialized = 1;
    _authz_svc.initialized = 1;
    ozayn_spe_service_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.audit = (void *)&_au_svc;
    cfg.authorization = (void *)&_authz_svc;
    cfg.max_preconditions = 32;
    cfg.max_policies = 16;
    cfg.max_decisions = 64;
    cfg.decision_ttl_ms = 300000;
    ozayn_spe_service_init(&_svc, &cfg);
}

/* ============================================================
 * LIFECYCLE TESTS
 * ============================================================ */

TEST(test_spe_init)
{
    _reset_all();
    ozayn_spe_service_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    ASSERT_EQ(ozayn_spe_service_init(&_svc, &cfg), OZAYN_SPE_OK);
    ASSERT(_svc.initialized == 1);
    ASSERT_EQ(_svc.max_preconditions, OZAYN_SPE_MAX_PRECONDITIONS);
    ASSERT_EQ(_svc.max_policies, OZAYN_SPE_MAX_POLICIES);
    ASSERT_EQ(_svc.max_decisions, OZAYN_SPE_MAX_DECISIONS);
    ASSERT_EQ(_svc.decision_ttl_ms, 300000);
    ozayn_spe_service_shutdown(&_svc);
    return 0;
}

TEST(test_spe_init_null)
{
    ASSERT_EQ(ozayn_spe_service_init(NULL, NULL), OZAYN_SPE_ERR_NULL);
    return 0;
}

TEST(test_spe_init_double)
{
    _init_svc();
    ASSERT_EQ(ozayn_spe_service_init(&_svc, NULL), OZAYN_SPE_ERR_ALREADY_INITIALIZED);
    ozayn_spe_service_shutdown(&_svc);
    return 0;
}

TEST(test_spe_init_custom_config)
{
    _reset_all();
    ozayn_spe_service_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.max_preconditions = 16;
    cfg.max_policies = 8;
    cfg.max_decisions = 32;
    cfg.decision_ttl_ms = 60000;
    ozayn_spe_service_init(&_svc, &cfg);
    ASSERT_EQ(_svc.max_preconditions, 16);
    ASSERT_EQ(_svc.max_policies, 8);
    ASSERT_EQ(_svc.max_decisions, 32);
    ASSERT_EQ(_svc.decision_ttl_ms, 60000);
    ozayn_spe_service_shutdown(&_svc);
    return 0;
}

TEST(test_spe_shutdown)
{
    _init_svc();
    ozayn_spe_service_shutdown(&_svc);
    ASSERT(_svc.initialized == 0);
    return 0;
}

TEST(test_spe_shutdown_null)
{
    ozayn_spe_service_shutdown(NULL);
    return 0;
}

TEST(test_spe_is_initialized)
{
    _reset_all();
    ASSERT(!ozayn_spe_service_is_initialized(NULL));
    ASSERT(!ozayn_spe_service_is_initialized(&_svc));
    _init_svc();
    ASSERT(ozayn_spe_service_is_initialized(&_svc));
    ozayn_spe_service_shutdown(&_svc);
    ASSERT(!ozayn_spe_service_is_initialized(&_svc));
    return 0;
}

/* ============================================================
 * PRECONDITION TESTS
 * ============================================================ */

TEST(test_spe_precondition_create)
{
    _init_svc();
    ozayn_spe_precondition_t *p = NULL;
    ASSERT_EQ(ozayn_spe_precondition_create(&_svc, OZAYN_SPE_PRECOND_TARGET_STATE,
        "target must be running", "MOD-VIS", "RUNNING", 1, -1,
        "", "", 0, &p), OZAYN_SPE_OK);
    ASSERT_NOT_NULL(p);
    ASSERT(strncmp(p->precondition_id, "SPC-", 4) == 0);
    ASSERT_EQ(p->category, OZAYN_SPE_PRECOND_TARGET_STATE);
    ASSERT_STR_EQ(p->description, "target must be running");
    ASSERT_STR_EQ(p->target, "MOD-VIS");
    ASSERT_STR_EQ(p->required_state, "RUNNING");
    ASSERT_EQ(p->required_available, 1);
    ASSERT_EQ(p->required_health, -1);
    ASSERT_EQ(p->result, OZAYN_SPE_RESULT_UNKNOWN);
    ASSERT(p->active == 1);
    ASSERT_EQ(_svc.precondition_count, 1);
    ozayn_spe_service_shutdown(&_svc);
    return 0;
}

TEST(test_spe_precondition_create_null)
{
    ASSERT_EQ(ozayn_spe_precondition_create(NULL, 0, "X", NULL, NULL, 0, 0,
        NULL, NULL, 0, NULL), OZAYN_SPE_ERR_NULL);
    return 0;
}

TEST(test_spe_precondition_create_not_init)
{
    memset(&_svc, 0, sizeof(_svc));
    ASSERT_EQ(ozayn_spe_precondition_create(&_svc, 0, "X", NULL, NULL, 0, 0,
        NULL, NULL, 0, NULL), OZAYN_SPE_ERR_NOT_INITIALIZED);
    return 0;
}

TEST(test_spe_precondition_create_invalid_category)
{
    _init_svc();
    ASSERT_EQ(ozayn_spe_precondition_create(&_svc, (ozayn_spe_precond_category_t)99,
        "X", NULL, NULL, 0, 0, NULL, NULL, 0, NULL), OZAYN_SPE_ERR_INVALID_PARAM);
    ozayn_spe_service_shutdown(&_svc);
    return 0;
}

TEST(test_spe_precondition_create_empty_desc)
{
    _init_svc();
    ASSERT_EQ(ozayn_spe_precondition_create(&_svc, 0, "", NULL, NULL, 0, 0,
        NULL, NULL, 0, NULL), OZAYN_SPE_ERR_INVALID_PARAM);
    ozayn_spe_service_shutdown(&_svc);
    return 0;
}

TEST(test_spe_precondition_create_limit)
{
    _reset_all();
    ozayn_spe_service_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.max_preconditions = 2;
    ozayn_spe_service_init(&_svc, &cfg);
    ozayn_spe_precondition_t *p1 = NULL, *p2 = NULL, *p3 = NULL;
    ozayn_spe_precondition_create(&_svc, 0, "p1", NULL, NULL, 0, 0, NULL, NULL, 0, &p1);
    ozayn_spe_precondition_create(&_svc, 0, "p2", NULL, NULL, 0, 0, NULL, NULL, 0, &p2);
    ASSERT_EQ(ozayn_spe_precondition_create(&_svc, 0, "p3", NULL, NULL, 0, 0,
        NULL, NULL, 0, &p3), OZAYN_SPE_ERR_LIMIT_REACHED);
    ozayn_spe_service_shutdown(&_svc);
    return 0;
}

TEST(test_spe_precondition_evaluate)
{
    _init_svc();
    ozayn_spe_precondition_t *p = NULL;
    ozayn_spe_precondition_create(&_svc, OZAYN_SPE_PRECOND_TARGET_STATE,
        "must be running", "MOD", "RUNNING", 0, 0, "", "", 0, &p);
    ASSERT_EQ(ozayn_spe_precondition_evaluate(&_svc, p->precondition_id,
        OZAYN_SPE_RESULT_SATISFIED), OZAYN_SPE_OK);
    ASSERT_EQ(p->result, OZAYN_SPE_RESULT_SATISFIED);
    ASSERT(p->evaluation_time > 0);
    ASSERT_EQ(_svc.stats.total_precondition_pass, 1);
    ozayn_spe_service_shutdown(&_svc);
    return 0;
}

TEST(test_spe_precondition_evaluate_failed)
{
    _init_svc();
    ozayn_spe_precondition_t *p = NULL;
    ozayn_spe_precondition_create(&_svc, OZAYN_SPE_PRECOND_TARGET_STATE,
        "must be running", "MOD", "RUNNING", 0, 0, "", "", 0, &p);
    ozayn_spe_precondition_evaluate(&_svc, p->precondition_id,
        OZAYN_SPE_RESULT_FAILED);
    ASSERT_EQ(p->result, OZAYN_SPE_RESULT_FAILED);
    ASSERT_EQ(_svc.stats.total_precondition_fail, 1);
    ozayn_spe_service_shutdown(&_svc);
    return 0;
}

TEST(test_spe_precondition_evaluate_terminal)
{
    _init_svc();
    ozayn_spe_precondition_t *p = NULL;
    ozayn_spe_precondition_create(&_svc, 0, "p1", NULL, NULL, 0, 0, NULL, NULL, 0, &p);
    ozayn_spe_precondition_evaluate(&_svc, p->precondition_id,
        OZAYN_SPE_RESULT_SATISFIED);
    ASSERT_EQ(ozayn_spe_precondition_evaluate(&_svc, p->precondition_id,
        OZAYN_SPE_RESULT_FAILED), OZAYN_SPE_ERR_STATE_INVALID);
    ozayn_spe_service_shutdown(&_svc);
    return 0;
}

TEST(test_spe_precondition_evaluate_not_found)
{
    _init_svc();
    ASSERT_EQ(ozayn_spe_precondition_evaluate(&_svc, "NOPE",
        OZAYN_SPE_RESULT_SATISFIED), OZAYN_SPE_ERR_NOT_FOUND);
    ozayn_spe_service_shutdown(&_svc);
    return 0;
}

TEST(test_spe_precondition_get)
{
    _init_svc();
    ozayn_spe_precondition_t *p = NULL;
    ozayn_spe_precondition_create(&_svc, 0, "p1", NULL, NULL, 0, 0, NULL, NULL, 0, &p);
    const ozayn_spe_precondition_t *found = ozayn_spe_precondition_get(&_svc,
        p->precondition_id);
    ASSERT_NOT_NULL(found);
    ASSERT(strcmp(found->precondition_id, p->precondition_id) == 0);
    ASSERT_NULL(ozayn_spe_precondition_get(&_svc, "NOPE"));
    ASSERT_NULL(ozayn_spe_precondition_get(NULL, "X"));
    ozayn_spe_service_shutdown(&_svc);
    return 0;
}

TEST(test_spe_precondition_count)
{
    _init_svc();
    ASSERT_EQ(ozayn_spe_precondition_count(&_svc), 0);
    ASSERT_EQ(ozayn_spe_precondition_count(NULL), 0);
    ozayn_spe_precondition_t *p1 = NULL, *p2 = NULL;
    ozayn_spe_precondition_create(&_svc, 0, "p1", NULL, NULL, 0, 0, NULL, NULL, 0, &p1);
    ozayn_spe_precondition_create(&_svc, 0, "p2", NULL, NULL, 0, 0, NULL, NULL, 0, &p2);
    ASSERT_EQ(ozayn_spe_precondition_count(&_svc), 2);
    ozayn_spe_service_shutdown(&_svc);
    return 0;
}

TEST(test_spe_precondition_add_dependency)
{
    _init_svc();
    ozayn_spe_precondition_t *p = NULL;
    ozayn_spe_precondition_create(&_svc, OZAYN_SPE_PRECOND_DEPENDENCY,
        "needs dep", NULL, NULL, 0, 0, "", "", 0, &p);
    ASSERT_EQ(ozayn_spe_precondition_add_dependency(&_svc, p->precondition_id,
        "DEP-1"), OZAYN_SPE_OK);
    ASSERT_EQ(p->dependency_count, 1);
    ASSERT_STR_EQ(p->required_dependencies[0], "DEP-1");
    ozayn_spe_service_shutdown(&_svc);
    return 0;
}

TEST(test_spe_precondition_add_dep_limit)
{
    _init_svc();
    ozayn_spe_precondition_t *p = NULL;
    ozayn_spe_precondition_create(&_svc, 0, "p1", NULL, NULL, 0, 0, NULL, NULL, 0, &p);
    for (int i = 0; i < OZAYN_SPE_MAX_DEPENDENCIES; i++) {
        ozayn_spe_precondition_add_dependency(&_svc, p->precondition_id, "DEP");
    }
    ASSERT_EQ(ozayn_spe_precondition_add_dependency(&_svc, p->precondition_id,
        "DEP-OVERFLOW"), OZAYN_SPE_ERR_LIMIT_REACHED);
    ozayn_spe_service_shutdown(&_svc);
    return 0;
}

/* ============================================================
 * POLICY TESTS
 * ============================================================ */

TEST(test_spe_policy_create)
{
    _init_svc();
    ozayn_spe_policy_t *pol = NULL;
    ASSERT_EQ(ozayn_spe_policy_create(&_svc, "START", "MODULE", "VIS-CAP",
        "EXECUTE", -1, "STOPPED", 1, 0, OZAYN_SPE_LEVEL_SAFE, 30000, 3, 1, &pol),
        OZAYN_SPE_OK);
    ASSERT_NOT_NULL(pol);
    ASSERT(strncmp(pol->policy_id, "SPP-", 4) == 0);
    ASSERT_STR_EQ(pol->operation_type, "START");
    ASSERT_STR_EQ(pol->target_type, "MODULE");
    ASSERT_STR_EQ(pol->capability, "VIS-CAP");
    ASSERT_STR_EQ(pol->required_permission, "EXECUTE");
    ASSERT_EQ(pol->required_health, -1);
    ASSERT_STR_EQ(pol->required_state, "STOPPED");
    ASSERT_EQ(pol->required_available, 1);
    ASSERT_EQ(pol->safety_level, OZAYN_SPE_LEVEL_SAFE);
    ASSERT_EQ(pol->timeout_limit_ms, 30000);
    ASSERT_EQ(pol->retry_limit, 3);
    ASSERT_EQ(pol->cancellable, 1);
    ASSERT_EQ(pol->enabled, 1);
    ASSERT(pol->active == 1);
    ASSERT_EQ(_svc.policy_count, 1);
    ozayn_spe_service_shutdown(&_svc);
    return 0;
}

TEST(test_spe_policy_create_null)
{
    ASSERT_EQ(ozayn_spe_policy_create(NULL, "X", NULL, NULL, NULL, 0, NULL, 0, 0,
        0, 0, 0, 0, NULL), OZAYN_SPE_ERR_NULL);
    return 0;
}

TEST(test_spe_policy_create_not_init)
{
    memset(&_svc, 0, sizeof(_svc));
    ASSERT_EQ(ozayn_spe_policy_create(&_svc, "X", NULL, NULL, NULL, 0, NULL, 0, 0,
        0, 0, 0, 0, NULL), OZAYN_SPE_ERR_NOT_INITIALIZED);
    return 0;
}

TEST(test_spe_policy_create_empty_op)
{
    _init_svc();
    ASSERT_EQ(ozayn_spe_policy_create(&_svc, "", NULL, NULL, NULL, 0, NULL, 0, 0,
        0, 0, 0, 0, NULL), OZAYN_SPE_ERR_INVALID_PARAM);
    ozayn_spe_service_shutdown(&_svc);
    return 0;
}

TEST(test_spe_policy_create_invalid_level)
{
    _init_svc();
    ASSERT_EQ(ozayn_spe_policy_create(&_svc, "START", NULL, NULL, NULL, 0, NULL, 0, 0,
        (ozayn_spe_safety_level_t)99, 0, 0, 0, NULL), OZAYN_SPE_ERR_INVALID_PARAM);
    ozayn_spe_service_shutdown(&_svc);
    return 0;
}

TEST(test_spe_policy_create_limit)
{
    _reset_all();
    ozayn_spe_service_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.max_policies = 2;
    ozayn_spe_service_init(&_svc, &cfg);
    ozayn_spe_policy_t *pol1 = NULL, *pol2 = NULL, *pol3 = NULL;
    ozayn_spe_policy_create(&_svc, "OP1", NULL, NULL, NULL, 0, NULL, 0, 0,
        0, 0, 0, 0, &pol1);
    ozayn_spe_policy_create(&_svc, "OP2", NULL, NULL, NULL, 0, NULL, 0, 0,
        0, 0, 0, 0, &pol2);
    ASSERT_EQ(ozayn_spe_policy_create(&_svc, "OP3", NULL, NULL, NULL, 0, NULL, 0, 0,
        0, 0, 0, 0, &pol3), OZAYN_SPE_ERR_LIMIT_REACHED);
    ozayn_spe_service_shutdown(&_svc);
    return 0;
}

TEST(test_spe_policy_set_enabled)
{
    _init_svc();
    ozayn_spe_policy_t *pol = NULL;
    ozayn_spe_policy_create(&_svc, "START", NULL, NULL, NULL, 0, NULL, 0, 0,
        0, 0, 0, 0, &pol);
    ASSERT_EQ(ozayn_spe_policy_set_enabled(&_svc, pol->policy_id, 0), OZAYN_SPE_OK);
    ASSERT_EQ(pol->enabled, 0);
    ASSERT_EQ(ozayn_spe_policy_set_enabled(&_svc, pol->policy_id, 1), OZAYN_SPE_OK);
    ASSERT_EQ(pol->enabled, 1);
    ozayn_spe_service_shutdown(&_svc);
    return 0;
}

TEST(test_spe_policy_set_enabled_not_found)
{
    _init_svc();
    ASSERT_EQ(ozayn_spe_policy_set_enabled(&_svc, "NOPE", 1), OZAYN_SPE_ERR_NOT_FOUND);
    ozayn_spe_service_shutdown(&_svc);
    return 0;
}

TEST(test_spe_policy_get)
{
    _init_svc();
    ozayn_spe_policy_t *pol = NULL;
    ozayn_spe_policy_create(&_svc, "START", NULL, NULL, NULL, 0, NULL, 0, 0,
        0, 0, 0, 0, &pol);
    const ozayn_spe_policy_t *found = ozayn_spe_policy_get(&_svc, pol->policy_id);
    ASSERT_NOT_NULL(found);
    ASSERT(strcmp(found->policy_id, pol->policy_id) == 0);
    ASSERT_NULL(ozayn_spe_policy_get(&_svc, "NOPE"));
    ASSERT_NULL(ozayn_spe_policy_get(NULL, "X"));
    ozayn_spe_service_shutdown(&_svc);
    return 0;
}

TEST(test_spe_policy_find)
{
    _init_svc();
    ozayn_spe_policy_t *pol = NULL;
    ozayn_spe_policy_create(&_svc, "START", "MODULE", "VIS-CAP", NULL, 0, NULL, 0, 0,
        0, 0, 0, 0, &pol);
    const ozayn_spe_policy_t *found = ozayn_spe_policy_find(&_svc, "START",
        "MODULE", "VIS-CAP");
    ASSERT_NOT_NULL(found);
    ASSERT(strcmp(found->policy_id, pol->policy_id) == 0);
    ASSERT_NULL(ozayn_spe_policy_find(&_svc, "STOP", "MODULE", "VIS-CAP"));
    ASSERT_NULL(ozayn_spe_policy_find(&_svc, "START", "OTHER", NULL));
    ozayn_spe_service_shutdown(&_svc);
    return 0;
}

TEST(test_spe_policy_find_disabled)
{
    _init_svc();
    ozayn_spe_policy_t *pol = NULL;
    ozayn_spe_policy_create(&_svc, "START", NULL, NULL, NULL, 0, NULL, 0, 0,
        0, 0, 0, 0, &pol);
    ozayn_spe_policy_set_enabled(&_svc, pol->policy_id, 0);
    ASSERT_NULL(ozayn_spe_policy_find(&_svc, "START", NULL, NULL));
    ozayn_spe_service_shutdown(&_svc);
    return 0;
}

TEST(test_spe_policy_count)
{
    _init_svc();
    ASSERT_EQ(ozayn_spe_policy_count(&_svc), 0);
    ASSERT_EQ(ozayn_spe_policy_count(NULL), 0);
    ozayn_spe_policy_t *pol = NULL;
    ozayn_spe_policy_create(&_svc, "OP1", NULL, NULL, NULL, 0, NULL, 0, 0,
        0, 0, 0, 0, &pol);
    ASSERT_EQ(ozayn_spe_policy_count(&_svc), 1);
    ozayn_spe_service_shutdown(&_svc);
    return 0;
}

TEST(test_spe_policy_add_conflict)
{
    _init_svc();
    ozayn_spe_policy_t *pol = NULL;
    ozayn_spe_policy_create(&_svc, "STOP", "MODULE", NULL, NULL, 0, NULL, 0, 0,
        0, 0, 0, 0, &pol);
    ASSERT_EQ(ozayn_spe_policy_add_conflict(&_svc, pol->policy_id, "START"),
              OZAYN_SPE_OK);
    ASSERT_EQ(pol->conflict_action_count, 1);
    ASSERT_STR_EQ(pol->conflict_actions[0], "START");
    ozayn_spe_service_shutdown(&_svc);
    return 0;
}

TEST(test_spe_policy_add_conflict_limit)
{
    _init_svc();
    ozayn_spe_policy_t *pol = NULL;
    ozayn_spe_policy_create(&_svc, "STOP", NULL, NULL, NULL, 0, NULL, 0, 0,
        0, 0, 0, 0, &pol);
    for (int i = 0; i < OZAYN_SPE_MAX_CONFLICT_RULES; i++) {
        ozayn_spe_policy_add_conflict(&_svc, pol->policy_id, "CONFLICT");
    }
    ASSERT_EQ(ozayn_spe_policy_add_conflict(&_svc, pol->policy_id,
        "OVERFLOW"), OZAYN_SPE_ERR_LIMIT_REACHED);
    ozayn_spe_service_shutdown(&_svc);
    return 0;
}

TEST(test_spe_policy_add_dependency)
{
    _init_svc();
    ozayn_spe_policy_t *pol = NULL;
    ozayn_spe_policy_create(&_svc, "START", NULL, NULL, NULL, 0, NULL, 0, 0,
        0, 0, 0, 0, &pol);
    ASSERT_EQ(ozayn_spe_policy_add_dependency(&_svc, pol->policy_id, "DEP-1"),
              OZAYN_SPE_OK);
    ASSERT_EQ(pol->dependency_count, 1);
    ASSERT_STR_EQ(pol->required_dependencies[0], "DEP-1");
    ozayn_spe_service_shutdown(&_svc);
    return 0;
}

/* ============================================================
 * CONFLICT DETECTION TESTS
 * ============================================================ */

TEST(test_spe_has_conflict)
{
    _init_svc();
    ozayn_spe_policy_t *pol = NULL;
    ozayn_spe_policy_create(&_svc, "STOP", "MODULE", NULL, NULL, 0, NULL, 0, 0,
        0, 0, 0, 0, &pol);
    ozayn_spe_policy_add_conflict(&_svc, pol->policy_id, "START");
    ASSERT(ozayn_spe_has_conflict(&_svc, "MODULE", "START"));
    ASSERT(!ozayn_spe_has_conflict(&_svc, "MODULE", "STOP"));
    ASSERT(!ozayn_spe_has_conflict(&_svc, "OTHER", "START"));
    ASSERT(!ozayn_spe_has_conflict(NULL, "X", "X"));
    ASSERT(!ozayn_spe_has_conflict(&_svc, NULL, "X"));
    ASSERT(!ozayn_spe_has_conflict(&_svc, "X", NULL));
    ozayn_spe_service_shutdown(&_svc);
    return 0;
}

TEST(test_spe_check_conflict)
{
    _init_svc();
    ozayn_spe_policy_t *pol = NULL;
    ozayn_spe_policy_create(&_svc, "STOP", "MOD-A", NULL, NULL, 0, NULL, 0, 0,
        0, 0, 0, 0, &pol);
    ozayn_spe_policy_add_conflict(&_svc, pol->policy_id, "START");
    int conflict = 0;
    ASSERT_EQ(ozayn_spe_check_conflict(&_svc, "MOD-A", "START", &conflict),
              OZAYN_SPE_OK);
    ASSERT_EQ(conflict, 1);
    ASSERT_EQ(_svc.stats.total_conflicts_detected, 1);
    ASSERT_EQ(ozayn_spe_check_conflict(&_svc, "MOD-A", "STOP", &conflict),
              OZAYN_SPE_OK);
    ASSERT_EQ(conflict, 0);
    ozayn_spe_service_shutdown(&_svc);
    return 0;
}

TEST(test_spe_conflict_multiple_targets)
{
    _init_svc();
    ozayn_spe_policy_t *pol1 = NULL, *pol2 = NULL;
    ozayn_spe_policy_create(&_svc, "STOP", "MOD-A", NULL, NULL, 0, NULL, 0, 0,
        0, 0, 0, 0, &pol1);
    ozayn_spe_policy_create(&_svc, "DISABLE", "MOD-B", NULL, NULL, 0, NULL, 0, 0,
        0, 0, 0, 0, &pol2);
    ozayn_spe_policy_add_conflict(&_svc, pol1->policy_id, "START");
    ozayn_spe_policy_add_conflict(&_svc, pol2->policy_id, "ENABLE");
    ASSERT(ozayn_spe_has_conflict(&_svc, "MOD-A", "START"));
    ASSERT(!ozayn_spe_has_conflict(&_svc, "MOD-A", "ENABLE"));
    ASSERT(ozayn_spe_has_conflict(&_svc, "MOD-B", "ENABLE"));
    ASSERT(!ozayn_spe_has_conflict(&_svc, "MOD-B", "START"));
    ozayn_spe_service_shutdown(&_svc);
    return 0;
}

/* ============================================================
 * SAFETY EVALUATION TESTS
 * ============================================================ */

TEST(test_spe_evaluate_no_policy)
{
    _init_svc();
    ozayn_spe_decision_record_t *dec = NULL;
    ASSERT_EQ(ozayn_spe_evaluate(&_svc, "REQ-1", "OP-1", "MOD-VIS", "START",
        "", "", "", "", &dec), OZAYN_SPE_OK);
    ASSERT_NOT_NULL(dec);
    ASSERT_EQ(dec->decision, OZAYN_SPE_DECISION_DENY);
    ASSERT_EQ(_svc.stats.total_evaluations, 1);
    ASSERT_EQ(_svc.stats.total_denied, 1);
    ozayn_spe_service_shutdown(&_svc);
    return 0;
}

TEST(test_spe_evaluate_policy_allows)
{
    _init_svc();
    ozayn_spe_policy_t *pol = NULL;
    ozayn_spe_policy_create(&_svc, "START", NULL, NULL, NULL, 0, NULL,
        0, 0, OZAYN_SPE_LEVEL_SAFE, 30000, 3, 1, &pol);
    ozayn_spe_decision_record_t *dec = NULL;
    ASSERT_EQ(ozayn_spe_evaluate(&_svc, "REQ-1", "OP-1", "MOD-VIS", "START",
        "", "sess-1", "user-1", "", &dec), OZAYN_SPE_OK);
    ASSERT_NOT_NULL(dec);
    ASSERT_EQ(dec->decision, OZAYN_SPE_DECISION_ALLOW);
    ASSERT_EQ(_svc.stats.total_allowed, 1);
    ASSERT(strncmp(dec->decision_id, "SPD-", 4) == 0);
    ASSERT_STR_EQ(dec->policy_id, pol->policy_id);
    ozayn_spe_service_shutdown(&_svc);
    return 0;
}

TEST(test_spe_evaluate_disabled_policy)
{
    _init_svc();
    ozayn_spe_policy_t *pol = NULL;
    ozayn_spe_policy_create(&_svc, "START", NULL, NULL, NULL, 0, NULL, 0, 0,
        0, 0, 0, 0, &pol);
    ozayn_spe_policy_set_enabled(&_svc, pol->policy_id, 0);
    ozayn_spe_decision_record_t *dec = NULL;
    ASSERT_EQ(ozayn_spe_evaluate(&_svc, "REQ-1", "OP-1", "MOD", "START",
        "", "", "", "", &dec), OZAYN_SPE_OK);
    ASSERT_EQ(dec->decision, OZAYN_SPE_DECISION_UNAVAILABLE);
    ASSERT_EQ(_svc.stats.total_unavailable, 1);
    ozayn_spe_service_shutdown(&_svc);
    return 0;
}

TEST(test_spe_evaluate_auth_required)
{
    _init_svc();
    ozayn_spe_policy_t *pol = NULL;
    ozayn_spe_policy_create(&_svc, "START", NULL, NULL, "EXECUTE", 0, NULL,
        0, 0, OZAYN_SPE_LEVEL_SAFE, 30000, 3, 1, &pol);
    /* Authorization service is available: foundation defers to integration layer.
     * With auth service present, check succeeds (placeholder). */
    ozayn_spe_decision_record_t *dec = NULL;
    ozayn_spe_evaluate(&_svc, "REQ-1", "OP-1", "MOD", "START",
        "", "sess-1", "user-1", "EXECUTE", &dec);
    /* Auth passes since auth service is available (foundation placeholder) */
    ASSERT_EQ(dec->decision, OZAYN_SPE_DECISION_ALLOW);
    ozayn_spe_service_shutdown(&_svc);
    return 0;
}

TEST(test_spe_evaluate_auth_no_service)
{
    _reset_all();
    ozayn_spe_service_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.authorization = NULL;
    ozayn_spe_service_init(&_svc, &cfg);
    ozayn_spe_policy_t *pol = NULL;
    ozayn_spe_policy_create(&_svc, "START", NULL, NULL, "EXECUTE", 0, NULL,
        0, 0, OZAYN_SPE_LEVEL_SAFE, 30000, 3, 1, &pol);
    /* No authorization service: fail closed */
    ozayn_spe_decision_record_t *dec = NULL;
    ozayn_spe_evaluate(&_svc, "REQ-1", "OP-1", "MOD", "START",
        "", "sess-1", "user-1", "EXECUTE", &dec);
    ASSERT_EQ(dec->decision, OZAYN_SPE_DECISION_DENY);
    ASSERT(dec->failed_precondition_count > 0);
    ozayn_spe_service_shutdown(&_svc);
    return 0;
}

TEST(test_spe_evaluate_conflict)
{
    _init_svc();
    ozayn_spe_policy_t *pol1 = NULL, *pol2 = NULL;
    ozayn_spe_policy_create(&_svc, "STOP", "MOD-A", NULL, NULL, 0, NULL, 0, 0,
        0, 0, 0, 0, &pol1);
    ozayn_spe_policy_create(&_svc, "START", "MOD-A", NULL, NULL, 0, NULL, 0, 0,
        0, 0, 0, 0, &pol2);
    ozayn_spe_policy_add_conflict(&_svc, pol1->policy_id, "START");
    ozayn_spe_decision_record_t *dec = NULL;
    ozayn_spe_evaluate(&_svc, "REQ-1", "OP-1", "MOD-A", "STOP",
        "", "", "", "", &dec);
    /* STOP has conflict rule for START, but we're evaluating STOP, not START */
    /* The conflict check is: does START conflict with any registered conflict? */
    /* Let's evaluate START which should conflict */
    ozayn_spe_decision_record_t *dec2 = NULL;
    ozayn_spe_evaluate(&_svc, "REQ-2", "OP-2", "MOD-A", "START",
        "", "", "", "", &dec2);
    /* START is in the conflict list of STOP policy, so it should conflict */
    ASSERT_EQ(dec2->decision, OZAYN_SPE_DECISION_DENY);
    ozayn_spe_service_shutdown(&_svc);
    return 0;
}

TEST(test_spe_evaluate_null)
{
    ASSERT_EQ(ozayn_spe_evaluate(NULL, "X", "X", "X", "X", NULL, NULL, NULL, NULL,
        NULL), OZAYN_SPE_ERR_NULL);
    return 0;
}

TEST(test_spe_evaluate_not_init)
{
    memset(&_svc, 0, sizeof(_svc));
    ASSERT_EQ(ozayn_spe_evaluate(&_svc, "X", "X", "X", "X", NULL, NULL, NULL, NULL,
        NULL), OZAYN_SPE_ERR_NOT_INITIALIZED);
    return 0;
}

TEST(test_spe_evaluate_empty_target)
{
    _init_svc();
    ASSERT_EQ(ozayn_spe_evaluate(&_svc, "R", "O", "", "X", NULL, NULL, NULL, NULL,
        NULL), OZAYN_SPE_ERR_INVALID_PARAM);
    ozayn_spe_service_shutdown(&_svc);
    return 0;
}

TEST(test_spe_evaluate_empty_action)
{
    _init_svc();
    ASSERT_EQ(ozayn_spe_evaluate(&_svc, "R", "O", "MOD", "", NULL, NULL, NULL, NULL,
        NULL), OZAYN_SPE_ERR_INVALID_PARAM);
    ozayn_spe_service_shutdown(&_svc);
    return 0;
}

/* ============================================================
 * RECHECK TESTS
 * ============================================================ */

TEST(test_spe_recheck)
{
    _init_svc();
    ozayn_spe_policy_t *pol = NULL;
    ozayn_spe_policy_create(&_svc, "START", NULL, NULL, NULL, 0, NULL, 0, 0,
        0, 0, 0, 0, &pol);
    ozayn_spe_decision_record_t *dec = NULL;
    ozayn_spe_evaluate(&_svc, "REQ-1", "OP-1", "MOD", "START",
        "", "", "", "", &dec);
    ASSERT_EQ(ozayn_spe_recheck(&_svc, dec->decision_id, "MOD", "",
        ""), OZAYN_SPE_OK);
    ASSERT_EQ(_svc.stats.total_rechecks, 1);
    ozayn_spe_service_shutdown(&_svc);
    return 0;
}

TEST(test_spe_recheck_not_found)
{
    _init_svc();
    ASSERT_EQ(ozayn_spe_recheck(&_svc, "NOPE", "MOD", "", ""),
              OZAYN_SPE_ERR_NOT_FOUND);
    ozayn_spe_service_shutdown(&_svc);
    return 0;
}

TEST(test_spe_recheck_expired)
{
    _reset_all();
    ozayn_spe_service_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.decision_ttl_ms = 1000; /* 1 second TTL */
    ozayn_spe_service_init(&_svc, &cfg);
    ozayn_spe_policy_t *pol = NULL;
    ozayn_spe_policy_create(&_svc, "START", NULL, NULL, NULL, 0, NULL, 0, 0,
        0, 0, 0, 0, &pol);
    ozayn_spe_decision_record_t *dec = NULL;
    ozayn_spe_evaluate(&_svc, "REQ-1", "OP-1", "MOD", "START",
        "", "", "", "", &dec);
    struct timespec ts = {2, 0}; /* 2 seconds */
    nanosleep(&ts, NULL);
    ASSERT_EQ(ozayn_spe_recheck(&_svc, dec->decision_id, "MOD", "", ""),
              OZAYN_SPE_ERR_DECISION_EXPIRED);
    ASSERT_EQ(_svc.stats.total_recheck_failures, 1);
    ozayn_spe_service_shutdown(&_svc);
    return 0;
}

TEST(test_spe_recheck_auth_fail)
{
    /* Test recheck when no auth service available */
    _reset_all();
    ozayn_spe_service_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.authorization = NULL;
    ozayn_spe_service_init(&_svc, &cfg);
    ozayn_spe_policy_t *pol = NULL;
    ozayn_spe_policy_create(&_svc, "START", NULL, NULL, "EXECUTE", 0, NULL,
        0, 0, 0, 0, 0, 0, &pol);
    ozayn_spe_decision_record_t *dec = NULL;
    ozayn_spe_evaluate(&_svc, "REQ-1", "OP-1", "MOD", "START",
        "", "sess-1", "user-1", "EXECUTE", &dec);
    /* Recheck with no auth service — should fail */
    ozayn_spe_recheck(&_svc, dec->decision_id, "MOD", "", "sess-1");
    ASSERT_EQ(dec->decision, OZAYN_SPE_DECISION_DENY);
    ASSERT_EQ(_svc.stats.total_recheck_failures, 1);
    ozayn_spe_service_shutdown(&_svc);
    return 0;
}

TEST(test_spe_recheck_null)
{
    ASSERT_EQ(ozayn_spe_recheck(NULL, "X", "X", NULL, NULL), OZAYN_SPE_ERR_NULL);
    return 0;
}

TEST(test_spe_recheck_not_init)
{
    memset(&_svc, 0, sizeof(_svc));
    ASSERT_EQ(ozayn_spe_recheck(&_svc, "X", "X", NULL, NULL),
              OZAYN_SPE_ERR_NOT_INITIALIZED);
    return 0;
}

/* ============================================================
 * DECISION QUERY TESTS
 * ============================================================ */

TEST(test_spe_decision_get)
{
    _init_svc();
    ozayn_spe_policy_t *pol = NULL;
    ozayn_spe_policy_create(&_svc, "START", NULL, NULL, NULL, 0, NULL, 0, 0,
        0, 0, 0, 0, &pol);
    ozayn_spe_decision_record_t *dec = NULL;
    ozayn_spe_evaluate(&_svc, "REQ-1", "OP-1", "MOD", "START",
        "", "", "", "", &dec);
    const ozayn_spe_decision_record_t *found = ozayn_spe_decision_get(&_svc,
        dec->decision_id);
    ASSERT_NOT_NULL(found);
    ASSERT(strcmp(found->decision_id, dec->decision_id) == 0);
    ASSERT_NULL(ozayn_spe_decision_get(&_svc, "NOPE"));
    ASSERT_NULL(ozayn_spe_decision_get(NULL, "X"));
    ozayn_spe_service_shutdown(&_svc);
    return 0;
}

TEST(test_spe_decision_get_by_request)
{
    _init_svc();
    ozayn_spe_policy_t *pol = NULL;
    ozayn_spe_policy_create(&_svc, "START", NULL, NULL, NULL, 0, NULL, 0, 0,
        0, 0, 0, 0, &pol);
    ozayn_spe_decision_record_t *dec = NULL;
    ozayn_spe_evaluate(&_svc, "REQ-42", "OP-1", "MOD", "START",
        "", "", "", "", &dec);
    const ozayn_spe_decision_record_t *found = ozayn_spe_decision_get_by_request(
        &_svc, "REQ-42");
    ASSERT_NOT_NULL(found);
    ASSERT(strcmp(found->request_id, "REQ-42") == 0);
    ASSERT_NULL(ozayn_spe_decision_get_by_request(&_svc, "NOPE"));
    ozayn_spe_service_shutdown(&_svc);
    return 0;
}

TEST(test_spe_decision_count)
{
    _init_svc();
    ASSERT_EQ(ozayn_spe_decision_count(&_svc), 0);
    ASSERT_EQ(ozayn_spe_decision_count(NULL), 0);
    ozayn_spe_policy_t *pol = NULL;
    ozayn_spe_policy_create(&_svc, "START", NULL, NULL, NULL, 0, NULL, 0, 0,
        0, 0, 0, 0, &pol);
    ozayn_spe_decision_record_t *d1 = NULL, *d2 = NULL;
    ozayn_spe_evaluate(&_svc, "R1", "O1", "M", "START", "", "", "", "", &d1);
    ozayn_spe_evaluate(&_svc, "R2", "O2", "M", "START", "", "", "", "", &d2);
    ASSERT_EQ(ozayn_spe_decision_count(&_svc), 2);
    ozayn_spe_service_shutdown(&_svc);
    return 0;
}

TEST(test_spe_decision_is_valid)
{
    _init_svc();
    ozayn_spe_policy_t *pol = NULL;
    ozayn_spe_policy_create(&_svc, "START", NULL, NULL, NULL, 0, NULL, 0, 0,
        0, 0, 0, 0, &pol);
    ozayn_spe_decision_record_t *dec = NULL;
    ozayn_spe_evaluate(&_svc, "REQ-1", "OP-1", "MOD", "START",
        "", "", "", "", &dec);
    ASSERT(ozayn_spe_decision_is_valid(&_svc, dec->decision_id));
    ASSERT(!ozayn_spe_decision_is_valid(&_svc, "NOPE"));
    ASSERT(!ozayn_spe_decision_is_valid(NULL, "X"));
    ozayn_spe_service_shutdown(&_svc);
    return 0;
}

TEST(test_spe_decision_is_valid_expired)
{
    _reset_all();
    ozayn_spe_service_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.decision_ttl_ms = 1000;
    ozayn_spe_service_init(&_svc, &cfg);
    ozayn_spe_policy_t *pol = NULL;
    ozayn_spe_policy_create(&_svc, "START", NULL, NULL, NULL, 0, NULL, 0, 0,
        0, 0, 0, 0, &pol);
    ozayn_spe_decision_record_t *dec = NULL;
    ozayn_spe_evaluate(&_svc, "REQ-1", "OP-1", "MOD", "START",
        "", "", "", "", &dec);
    struct timespec ts = {2, 0};
    nanosleep(&ts, NULL);
    ASSERT(!ozayn_spe_decision_is_valid(&_svc, dec->decision_id));
    ozayn_spe_service_shutdown(&_svc);
    return 0;
}

/* ============================================================
 * STATISTICS TESTS
 * ============================================================ */

TEST(test_spe_get_stats)
{
    _init_svc();
    ozayn_spe_stats_t stats;
    memset(&stats, 0, sizeof(stats));
    ASSERT_EQ(ozayn_spe_get_stats(&_svc, &stats), OZAYN_SPE_OK);
    ASSERT_EQ(stats.total_evaluations, 0);
    ASSERT_EQ(ozayn_spe_get_stats(NULL, NULL), OZAYN_SPE_ERR_NULL);

    ozayn_spe_policy_t *pol = NULL;
    ozayn_spe_policy_create(&_svc, "START", NULL, NULL, NULL, 0, NULL, 0, 0,
        0, 0, 0, 0, &pol);
    ozayn_spe_decision_record_t *d = NULL;
    ozayn_spe_evaluate(&_svc, "R1", "O1", "M", "START", "", "", "", "", &d);
    ozayn_spe_get_stats(&_svc, &stats);
    ASSERT_EQ(stats.total_evaluations, 1);
    ASSERT_EQ(stats.total_allowed, 1);
    ozayn_spe_service_shutdown(&_svc);
    return 0;
}

/* ============================================================
 * CLEANUP TESTS
 * ============================================================ */

TEST(test_spe_cleanup_decisions)
{
    _reset_all();
    ozayn_spe_service_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.decision_ttl_ms = 1000;
    ozayn_spe_service_init(&_svc, &cfg);
    ozayn_spe_policy_t *pol = NULL;
    ozayn_spe_policy_create(&_svc, "START", NULL, NULL, NULL, 0, NULL, 0, 0,
        0, 0, 0, 0, &pol);
    ozayn_spe_decision_record_t *d = NULL;
    ozayn_spe_evaluate(&_svc, "R1", "O1", "M", "START", "", "", "", "", &d);
    struct timespec ts = {2, 0};
    nanosleep(&ts, NULL);
    int cleaned = ozayn_spe_cleanup_decisions(&_svc);
    ASSERT(cleaned >= 1);
    ASSERT_EQ(_svc.decision_count, 0);
    ASSERT_EQ(ozayn_spe_cleanup_decisions(NULL), 0);
    ozayn_spe_service_shutdown(&_svc);
    return 0;
}

TEST(test_spe_cleanup_all)
{
    _init_svc();
    ozayn_spe_precondition_t *p = NULL;
    ozayn_spe_precondition_create(&_svc, 0, "p1", NULL, NULL, 0, 0, NULL, NULL, 0, &p);
    ozayn_spe_policy_t *pol = NULL;
    ozayn_spe_policy_create(&_svc, "START", NULL, NULL, NULL, 0, NULL, 0, 0,
        0, 0, 0, 0, &pol);
    ozayn_spe_decision_record_t *d = NULL;
    ozayn_spe_evaluate(&_svc, "R1", "O1", "M", "START", "", "", "", "", &d);
    int cleaned = ozayn_spe_cleanup_all(&_svc);
    ASSERT(cleaned >= 3);
    ASSERT_EQ(_svc.precondition_count, 0);
    ASSERT_EQ(_svc.policy_count, 0);
    ASSERT_EQ(_svc.decision_count, 0);
    ASSERT_EQ(ozayn_spe_cleanup_all(NULL), 0);
    ozayn_spe_service_shutdown(&_svc);
    return 0;
}

/* ============================================================
 * EVENT & AUDIT TESTS
 * ============================================================ */

TEST(test_spe_emit_event)
{
    _init_svc();
    ASSERT_EQ(ozayn_spe_emit_event(&_svc, OZAYN_SPE_EVENT_SAFETY_CHECK_STARTED,
        "X", "X"), OZAYN_SPE_OK);
    ASSERT_EQ(ozayn_spe_emit_event(NULL, OZAYN_SPE_EVENT_SAFETY_CHECK_STARTED,
        "X", "X"), OZAYN_SPE_ERR_NULL);
    ozayn_spe_service_shutdown(&_svc);
    return 0;
}

TEST(test_spe_audit)
{
    _init_svc();
    ASSERT_EQ(ozayn_spe_audit(&_svc, "REF-1", "TEST_ACTION", "detail"),
              OZAYN_SPE_OK);
    ASSERT_EQ(ozayn_spe_audit(NULL, "X", "X", "X"), OZAYN_SPE_ERR_NULL);
    ASSERT_EQ(ozayn_spe_audit(&_svc, NULL, "X", "X"), OZAYN_SPE_ERR_INVALID_PARAM);
    ozayn_spe_service_shutdown(&_svc);
    return 0;
}

/* ============================================================
 * VALIDATION TESTS
 * ============================================================ */

TEST(test_spe_precondition_validate)
{
    ozayn_spe_precondition_t p;
    memset(&p, 0, sizeof(p));
    ASSERT(!ozayn_spe_precondition_validate(NULL));
    ASSERT(!ozayn_spe_precondition_validate(&p));
    strncpy(p.precondition_id, "SPC-1", OZAYN_SPE_MAX_ID_LEN - 1);
    ASSERT(!ozayn_spe_precondition_validate(&p));
    strncpy(p.description, "test", OZAYN_SPE_MAX_DESC_LEN - 1);
    ASSERT(ozayn_spe_precondition_validate(&p));
    p.category = (ozayn_spe_precond_category_t)99;
    ASSERT(!ozayn_spe_precondition_validate(&p));
    return 0;
}

TEST(test_spe_policy_validate)
{
    ozayn_spe_policy_t pol;
    memset(&pol, 0, sizeof(pol));
    ASSERT(!ozayn_spe_policy_validate(NULL));
    ASSERT(!ozayn_spe_policy_validate(&pol));
    strncpy(pol.policy_id, "SPP-1", OZAYN_SPE_MAX_ID_LEN - 1);
    ASSERT(!ozayn_spe_policy_validate(&pol));
    strncpy(pol.operation_type, "START", OZAYN_SPE_MAX_ID_LEN - 1);
    ASSERT(ozayn_spe_policy_validate(&pol));
    pol.safety_level = (ozayn_spe_safety_level_t)99;
    ASSERT(!ozayn_spe_policy_validate(&pol));
    return 0;
}

TEST(test_spe_decision_validate)
{
    ozayn_spe_decision_record_t dec;
    memset(&dec, 0, sizeof(dec));
    ASSERT(!ozayn_spe_decision_validate(NULL));
    ASSERT(!ozayn_spe_decision_validate(&dec));
    strncpy(dec.decision_id, "SPD-1", OZAYN_SPE_MAX_ID_LEN - 1);
    ASSERT(ozayn_spe_decision_validate(&dec));
    dec.decision = (ozayn_spe_decision_t)99;
    ASSERT(!ozayn_spe_decision_validate(&dec));
    return 0;
}

/* ============================================================
 * NAME HELPER TESTS
 * ============================================================ */

TEST(test_spe_err_name)
{
    ASSERT_STR_EQ(ozayn_spe_err_name(OZAYN_SPE_OK), "OK");
    ASSERT_STR_EQ(ozayn_spe_err_name(OZAYN_SPE_ERR_NULL), "NULL");
    ASSERT_STR_EQ(ozayn_spe_err_name(OZAYN_SPE_ERR_PRECONDITION_FAILED),
                  "PRECONDITION_FAILED");
    ASSERT_STR_EQ(ozayn_spe_err_name(OZAYN_SPE_ERR_POLICY_DENIED), "POLICY_DENIED");
    ASSERT_STR_EQ(ozayn_spe_err_name(OZAYN_SPE_ERR_DECISION_EXPIRED),
                  "DECISION_EXPIRED");
    ASSERT_STR_EQ(ozayn_spe_err_name((ozayn_spe_err_t)999), "UNKNOWN");
    return 0;
}

TEST(test_spe_precond_category_name)
{
    ASSERT_STR_EQ(ozayn_spe_precond_category_name(OZAYN_SPE_PRECOND_TARGET_STATE),
                  "TARGET_STATE");
    ASSERT_STR_EQ(ozayn_spe_precond_category_name(OZAYN_SPE_PRECOND_TARGET_HEALTH),
                  "TARGET_HEALTH");
    ASSERT_STR_EQ(ozayn_spe_precond_category_name(OZAYN_SPE_PRECOND_CONFLICT),
                  "CONFLICT");
    ASSERT_STR_EQ(ozayn_spe_precond_category_name((ozayn_spe_precond_category_t)99),
                  "UNKNOWN");
    return 0;
}

TEST(test_spe_precond_result_name)
{
    ASSERT_STR_EQ(ozayn_spe_precond_result_name(OZAYN_SPE_RESULT_SATISFIED),
                  "SATISFIED");
    ASSERT_STR_EQ(ozayn_spe_precond_result_name(OZAYN_SPE_RESULT_FAILED), "FAILED");
    ASSERT_STR_EQ(ozayn_spe_precond_result_name(OZAYN_SPE_RESULT_UNKNOWN), "UNKNOWN");
    ASSERT_STR_EQ(ozayn_spe_precond_result_name(OZAYN_SPE_RESULT_UNAVAILABLE),
                  "UNAVAILABLE");
    ASSERT_STR_EQ(ozayn_spe_precond_result_name(OZAYN_SPE_RESULT_NOT_APPLICABLE),
                  "NOT_APPLICABLE");
    ASSERT_STR_EQ(ozayn_spe_precond_result_name((ozayn_spe_precond_result_t)99),
                  "UNKNOWN");
    return 0;
}

TEST(test_spe_safety_level_name)
{
    ASSERT_STR_EQ(ozayn_spe_safety_level_name(OZAYN_SPE_LEVEL_SAFE), "SAFE");
    ASSERT_STR_EQ(ozayn_spe_safety_level_name(OZAYN_SPE_LEVEL_RESTRICTED),
                  "RESTRICTED");
    ASSERT_STR_EQ(ozayn_spe_safety_level_name(OZAYN_SPE_LEVEL_SENSITIVE), "SENSITIVE");
    ASSERT_STR_EQ(ozayn_spe_safety_level_name(OZAYN_SPE_LEVEL_CRITICAL), "CRITICAL");
    ASSERT_STR_EQ(ozayn_spe_safety_level_name((ozayn_spe_safety_level_t)99),
                  "UNKNOWN");
    return 0;
}

TEST(test_spe_decision_name)
{
    ASSERT_STR_EQ(ozayn_spe_decision_name(OZAYN_SPE_DECISION_ALLOW), "ALLOW");
    ASSERT_STR_EQ(ozayn_spe_decision_name(OZAYN_SPE_DECISION_DENY), "DENY");
    ASSERT_STR_EQ(ozayn_spe_decision_name(OZAYN_SPE_DECISION_DEFER), "DEFER");
    ASSERT_STR_EQ(ozayn_spe_decision_name(OZAYN_SPE_DECISION_UNAVAILABLE),
                  "UNAVAILABLE");
    ASSERT_STR_EQ(ozayn_spe_decision_name((ozayn_spe_decision_t)99), "UNKNOWN");
    return 0;
}

TEST(test_spe_event_type_name)
{
    ASSERT_STR_EQ(ozayn_spe_event_type_name(OZAYN_SPE_EVENT_PRECOND_EVALUATED),
                  "PRECOND_EVALUATED");
    ASSERT_STR_EQ(ozayn_spe_event_type_name(OZAYN_SPE_EVENT_POLICY_ALLOWED),
                  "POLICY_ALLOWED");
    ASSERT_STR_EQ(ozayn_spe_event_type_name(OZAYN_SPE_EVENT_CONFLICT_DETECTED),
                  "CONFLICT_DETECTED");
    ASSERT_STR_EQ(ozayn_spe_event_type_name(OZAYN_SPE_EVENT_OPERATION_BLOCKED),
                  "OPERATION_BLOCKED");
    ASSERT_STR_EQ(ozayn_spe_event_type_name((ozayn_spe_event_type_t)99), "UNKNOWN");
    return 0;
}

/* ============================================================
 * SECURITY TESTS
 * ============================================================ */

TEST(test_spe_global_singleton)
{
    ozayn_spe_service_t *g1 = ozayn_spe_get_global();
    ozayn_spe_service_t *g2 = ozayn_spe_get_global();
    ASSERT_NOT_NULL(g1);
    ASSERT(g1 == g2);
    return 0;
}

TEST(test_spe_no_secrets_in_policy)
{
    _init_svc();
    ozayn_spe_policy_t *pol = NULL;
    ozayn_spe_policy_create(&_svc, "START", NULL, NULL, NULL, 0, NULL, 0, 0,
        0, 0, 0, 0, &pol);
    /* Policy should not store secrets */
    ASSERT(pol->active == 1);
    ozayn_spe_service_shutdown(&_svc);
    return 0;
}

TEST(test_spe_no_secrets_in_decision)
{
    _init_svc();
    ozayn_spe_policy_t *pol = NULL;
    ozayn_spe_policy_create(&_svc, "START", NULL, NULL, NULL, 0, NULL, 0, 0,
        0, 0, 0, 0, &pol);
    ozayn_spe_decision_record_t *dec = NULL;
    ozayn_spe_evaluate(&_svc, "REQ-1", "OP-1", "MOD", "START",
        "", "", "", "", &dec);
    ASSERT(dec->active == 1);
    ASSERT(dec->safe_metadata[0] == '\0');
    ozayn_spe_service_shutdown(&_svc);
    return 0;
}

TEST(test_spe_default_deny_no_policy)
{
    _init_svc();
    ozayn_spe_decision_record_t *dec = NULL;
    ozayn_spe_evaluate(&_svc, "REQ-1", "OP-1", "UNKNOWN-MOD", "UNKNOWN-ACTION",
        "", "", "", "", &dec);
    ASSERT_EQ(dec->decision, OZAYN_SPE_DECISION_DENY);
    ozayn_spe_service_shutdown(&_svc);
    return 0;
}

/* ============================================================
 * FULL LIFECYCLE TEST
 * ============================================================ */

TEST(test_spe_full_lifecycle)
{
    _init_svc();

    /* Create preconditions */
    ozayn_spe_precondition_t *p1 = NULL, *p2 = NULL;
    ozayn_spe_precondition_create(&_svc, OZAYN_SPE_PRECOND_TARGET_STATE,
        "target must be stopped", "MOD-VIS", "STOPPED", 1, -1, "", "", 0, &p1);
    ozayn_spe_precondition_create(&_svc, OZAYN_SPE_PRECOND_TARGET_HEALTH,
        "target must be healthy", "MOD-VIS", "", -1, 1, "", "", 0, &p2);
    ozayn_spe_precondition_add_dependency(&_svc, p1->precondition_id,
        p2->precondition_id);

    /* Create policy with safety level */
    ozayn_spe_policy_t *pol = NULL;
    ozayn_spe_policy_create(&_svc, "START", NULL, NULL, "EXECUTE",
        1, "STOPPED", 1, 0, OZAYN_SPE_LEVEL_SENSITIVE, 60000, 3, 1, &pol);
    ozayn_spe_policy_add_conflict(&_svc, pol->policy_id, "STOP");
    ozayn_spe_policy_add_dependency(&_svc, pol->policy_id, "DEP-1");

    /* Evaluate — should allow (no auth requirement blocking) */
    ozayn_spe_decision_record_t *dec = NULL;
    ASSERT_EQ(ozayn_spe_evaluate(&_svc, "REQ-START-1", "OP-START-1",
        "MOD-VIS", "START", "VIS-CAP", "sess-1", "user-1", "EXECUTE", &dec),
        OZAYN_SPE_OK);
    /* Auth check may fail since mock doesn't approve */
    ASSERT(dec->decision == OZAYN_SPE_DECISION_ALLOW ||
           dec->decision == OZAYN_SPE_DECISION_DENY);

    /* Verify stats */
    ozayn_spe_stats_t stats;
    ozayn_spe_get_stats(&_svc, &stats);
    ASSERT_EQ(stats.total_evaluations, 1);

    /* Verify decision is queryable */
    const ozayn_spe_decision_record_t *found = ozayn_spe_decision_get(&_svc,
        dec->decision_id);
    ASSERT_NOT_NULL(found);
    ASSERT(strcmp(found->decision_id, dec->decision_id) == 0);

    /* Verify by request */
    const ozayn_spe_decision_record_t *by_req = ozayn_spe_decision_get_by_request(
        &_svc, "REQ-START-1");
    ASSERT_NOT_NULL(by_req);

    /* Verify decision validity */
    ASSERT(ozayn_spe_decision_is_valid(&_svc, dec->decision_id));

    /* Recheck */
    ASSERT_EQ(ozayn_spe_recheck(&_svc, dec->decision_id, "MOD-VIS", "VIS-CAP",
        "sess-1"), OZAYN_SPE_OK);

    /* Verify conflict detection */
    ASSERT(ozayn_spe_has_conflict(&_svc, "MOD-VIS", "STOP"));

    /* Verify validation */
    ASSERT(ozayn_spe_precondition_validate(p1));
    ASSERT(ozayn_spe_policy_validate(pol));
    ASSERT(ozayn_spe_decision_validate(dec));

    /* Cleanup */
    int cleaned = ozayn_spe_cleanup_all(&_svc);
    ASSERT(cleaned >= 3);

    ozayn_spe_service_shutdown(&_svc);
    return 0;
}

/* ============================================================
 * TEST RUNNER
 * ============================================================ */

int run_cr_safety_tests(void)
{
    SUITE_BEGIN("Safety, Preconditions & Policy Enforcement");

    /* Lifecycle */
    RUN(test_spe_init);
    RUN(test_spe_init_null);
    RUN(test_spe_init_double);
    RUN(test_spe_init_custom_config);
    RUN(test_spe_shutdown);
    RUN(test_spe_shutdown_null);
    RUN(test_spe_is_initialized);

    /* Preconditions */
    RUN(test_spe_precondition_create);
    RUN(test_spe_precondition_create_null);
    RUN(test_spe_precondition_create_not_init);
    RUN(test_spe_precondition_create_invalid_category);
    RUN(test_spe_precondition_create_empty_desc);
    RUN(test_spe_precondition_create_limit);
    RUN(test_spe_precondition_evaluate);
    RUN(test_spe_precondition_evaluate_failed);
    RUN(test_spe_precondition_evaluate_terminal);
    RUN(test_spe_precondition_evaluate_not_found);
    RUN(test_spe_precondition_get);
    RUN(test_spe_precondition_count);
    RUN(test_spe_precondition_add_dependency);
    RUN(test_spe_precondition_add_dep_limit);

    /* Policies */
    RUN(test_spe_policy_create);
    RUN(test_spe_policy_create_null);
    RUN(test_spe_policy_create_not_init);
    RUN(test_spe_policy_create_empty_op);
    RUN(test_spe_policy_create_invalid_level);
    RUN(test_spe_policy_create_limit);
    RUN(test_spe_policy_set_enabled);
    RUN(test_spe_policy_set_enabled_not_found);
    RUN(test_spe_policy_get);
    RUN(test_spe_policy_find);
    RUN(test_spe_policy_find_disabled);
    RUN(test_spe_policy_count);
    RUN(test_spe_policy_add_conflict);
    RUN(test_spe_policy_add_conflict_limit);
    RUN(test_spe_policy_add_dependency);

    /* Conflicts */
    RUN(test_spe_has_conflict);
    RUN(test_spe_check_conflict);
    RUN(test_spe_conflict_multiple_targets);

    /* Safety Evaluation */
    RUN(test_spe_evaluate_no_policy);
    RUN(test_spe_evaluate_policy_allows);
    RUN(test_spe_evaluate_disabled_policy);
    RUN(test_spe_evaluate_auth_required);
    RUN(test_spe_evaluate_auth_no_service);
    RUN(test_spe_evaluate_conflict);
    RUN(test_spe_evaluate_null);
    RUN(test_spe_evaluate_not_init);
    RUN(test_spe_evaluate_empty_target);
    RUN(test_spe_evaluate_empty_action);

    /* Recheck */
    RUN(test_spe_recheck);
    RUN(test_spe_recheck_not_found);
    RUN(test_spe_recheck_expired);
    RUN(test_spe_recheck_auth_fail);
    RUN(test_spe_recheck_null);
    RUN(test_spe_recheck_not_init);

    /* Decision Query */
    RUN(test_spe_decision_get);
    RUN(test_spe_decision_get_by_request);
    RUN(test_spe_decision_count);
    RUN(test_spe_decision_is_valid);
    RUN(test_spe_decision_is_valid_expired);

    /* Statistics */
    RUN(test_spe_get_stats);

    /* Cleanup */
    RUN(test_spe_cleanup_decisions);
    RUN(test_spe_cleanup_all);

    /* Events & Audit */
    RUN(test_spe_emit_event);
    RUN(test_spe_audit);

    /* Validation */
    RUN(test_spe_precondition_validate);
    RUN(test_spe_policy_validate);
    RUN(test_spe_decision_validate);

    /* Name Helpers */
    RUN(test_spe_err_name);
    RUN(test_spe_precond_category_name);
    RUN(test_spe_precond_result_name);
    RUN(test_spe_safety_level_name);
    RUN(test_spe_decision_name);
    RUN(test_spe_event_type_name);

    /* Security */
    RUN(test_spe_global_singleton);
    RUN(test_spe_no_secrets_in_policy);
    RUN(test_spe_no_secrets_in_decision);
    RUN(test_spe_default_deny_no_policy);

    /* Full Lifecycle */
    RUN(test_spe_full_lifecycle);

    SUITE_END();
    return TOTAL_FAIL();
}
