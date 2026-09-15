/*
 * test_mode_transition_policy.c — Section 04, Step 21
 * Mode Transition Policy Engine tests
 * Prefix: run_cr_mode_transition_policy_tests
 */

#include "../../tests/test_framework.h"
#include "../mode_transition_policy.h"
#include <string.h>

/* ============================================================
 * LIFECYCLE TESTS
 * ============================================================ */

TEST(test_mtp_init_null) {
    ASSERT_EQ(ozayn_mtp_service_init(NULL, NULL), OZAYN_MTP_ERR_NULL);
    return 0;
}

TEST(test_mtp_init_default_config) {
    ozayn_mtp_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ASSERT_EQ(ozayn_mtp_service_init(&svc, NULL), OZAYN_MTP_OK);
    ASSERT(svc.initialized);
    ASSERT_EQ(svc.policy_count, 0);
    ASSERT_EQ(svc.request_count, 0);
    ASSERT_EQ(svc.decision_count, 0);
    ASSERT_EQ(svc.event_count, 1);
    ozayn_mtp_service_shutdown(&svc);
    return 0;
}

TEST(test_mtp_init_with_config) {
    ozayn_mtp_service_t svc;
    memset(&svc, 0, sizeof(svc));
    int dummy = 42;
    ozayn_mtp_service_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.readiness = &dummy;
    cfg.audit = &dummy;
    ASSERT_EQ(ozayn_mtp_service_init(&svc, &cfg), OZAYN_MTP_OK);
    ASSERT_EQ(svc.readiness, &dummy);
    ASSERT_EQ(svc.audit, &dummy);
    ozayn_mtp_service_shutdown(&svc);
    return 0;
}

TEST(test_mtp_double_init) {
    ozayn_mtp_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ASSERT_EQ(ozayn_mtp_service_init(&svc, NULL), OZAYN_MTP_OK);
    ASSERT_EQ(ozayn_mtp_service_init(&svc, NULL), OZAYN_MTP_ERR_ALREADY_INITIALIZED);
    ozayn_mtp_service_shutdown(&svc);
    return 0;
}

TEST(test_mtp_shutdown_null) {
    ASSERT_EQ(ozayn_mtp_service_shutdown(NULL), OZAYN_MTP_ERR_NULL);
    return 0;
}

TEST(test_mtp_shutdown_not_init) {
    ozayn_mtp_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ASSERT_EQ(ozayn_mtp_service_shutdown(&svc), OZAYN_MTP_ERR_NOT_INITIALIZED);
    return 0;
}

TEST(test_mtp_shutdown_normal) {
    ozayn_mtp_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ASSERT_EQ(ozayn_mtp_service_init(&svc, NULL), OZAYN_MTP_OK);
    ASSERT_EQ(ozayn_mtp_service_shutdown(&svc), OZAYN_MTP_OK);
    ASSERT(!svc.initialized);
    return 0;
}

TEST(test_mtp_global_singleton) {
    ozayn_mtp_service_t *g1 = ozayn_mtp_get_global();
    ozayn_mtp_service_t *g2 = ozayn_mtp_get_global();
    ASSERT(g1 != NULL);
    ASSERT(g1 == g2);
    return 0;
}

/* ============================================================
 * SUBSYSTEM BINDING TESTS
 * ============================================================ */

TEST(test_mtp_set_readiness_null) {
    ASSERT_EQ(ozayn_mtp_set_readiness(NULL, NULL), OZAYN_MTP_ERR_NULL);
    return 0;
}

TEST(test_mtp_set_audit_null) {
    ASSERT_EQ(ozayn_mtp_set_audit(NULL, NULL), OZAYN_MTP_ERR_NULL);
    return 0;
}

TEST(test_mtp_set_safety_null) {
    ASSERT_EQ(ozayn_mtp_set_safety(NULL, NULL), OZAYN_MTP_ERR_NULL);
    return 0;
}

TEST(test_mtp_set_resource_null) {
    ASSERT_EQ(ozayn_mtp_set_resource_manager(NULL, NULL), OZAYN_MTP_ERR_NULL);
    return 0;
}

TEST(test_mtp_set_component_null) {
    ASSERT_EQ(ozayn_mtp_set_component_registry(NULL, NULL), OZAYN_MTP_ERR_NULL);
    return 0;
}

TEST(test_mtp_set_readiness_ok) {
    ozayn_mtp_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_mtp_service_init(&svc, NULL);
    int dummy = 1;
    ASSERT_EQ(ozayn_mtp_set_readiness(&svc, &dummy), OZAYN_MTP_OK);
    ASSERT_EQ(svc.readiness, &dummy);
    ozayn_mtp_service_shutdown(&svc);
    return 0;
}

TEST(test_mtp_set_all_subsystems) {
    ozayn_mtp_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_mtp_service_init(&svc, NULL);
    int a = 1, b = 2, c = 3, d = 4, e = 5;
    ASSERT_EQ(ozayn_mtp_set_readiness(&svc, &a), OZAYN_MTP_OK);
    ASSERT_EQ(ozayn_mtp_set_audit(&svc, &b), OZAYN_MTP_OK);
    ASSERT_EQ(ozayn_mtp_set_safety(&svc, &c), OZAYN_MTP_OK);
    ASSERT_EQ(ozayn_mtp_set_resource_manager(&svc, &d), OZAYN_MTP_OK);
    ASSERT_EQ(ozayn_mtp_set_component_registry(&svc, &e), OZAYN_MTP_OK);
    ASSERT_EQ(svc.readiness, &a);
    ASSERT_EQ(svc.audit, &b);
    ASSERT_EQ(svc.safety, &c);
    ASSERT_EQ(svc.resource_manager, &d);
    ASSERT_EQ(svc.component_registry, &e);
    ozayn_mtp_service_shutdown(&svc);
    return 0;
}

/* ============================================================
 * POLICY MANAGEMENT TESTS
 * ============================================================ */

static ozayn_mtp_policy_t _make_policy(const char *id, ozayn_ord_mode_t src,
                                        ozayn_ord_mode_t tgt) {
    ozayn_mtp_policy_t p;
    memset(&p, 0, sizeof(p));
    strncpy(p.id, id, OZAYN_MTP_MAX_ID_LEN - 1);
    snprintf(p.name, OZAYN_MTP_MAX_NAME_LEN, "policy_%s", id);
    p.source_mode = src;
    p.target_mode = tgt;
    p.enabled = 1;
    return p;
}

TEST(test_mtp_add_policy_null) {
    ASSERT_EQ(ozayn_mtp_add_policy(NULL, NULL), OZAYN_MTP_ERR_NULL);
    return 0;
}

TEST(test_mtp_add_policy_not_init) {
    ozayn_mtp_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_mtp_policy_t p = _make_policy("p1", OZAYN_ORD_MODE_READY,
                                        OZAYN_ORD_MODE_MAINTENANCE);
    ASSERT_EQ(ozayn_mtp_add_policy(&svc, &p), OZAYN_MTP_ERR_NOT_INITIALIZED);
    return 0;
}

TEST(test_mtp_add_policy_ok) {
    ozayn_mtp_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_mtp_service_init(&svc, NULL);
    ozayn_mtp_policy_t p = _make_policy("p1", OZAYN_ORD_MODE_READY,
                                        OZAYN_ORD_MODE_MAINTENANCE);
    ASSERT_EQ(ozayn_mtp_add_policy(&svc, &p), OZAYN_MTP_OK);
    ASSERT_EQ(ozayn_mtp_policy_count(&svc), 1);
    ozayn_mtp_service_shutdown(&svc);
    return 0;
}

TEST(test_mtp_add_policy_invalid_source) {
    ozayn_mtp_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_mtp_service_init(&svc, NULL);
    ozayn_mtp_policy_t p = _make_policy("p1", -1, OZAYN_ORD_MODE_MAINTENANCE);
    ASSERT_EQ(ozayn_mtp_add_policy(&svc, &p), OZAYN_MTP_ERR_INVALID_PARAM);
    ozayn_mtp_service_shutdown(&svc);
    return 0;
}

TEST(test_mtp_add_policy_invalid_target) {
    ozayn_mtp_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_mtp_service_init(&svc, NULL);
    ozayn_mtp_policy_t p = _make_policy("p1", OZAYN_ORD_MODE_READY,
                                        OZAYN_ORD_MODE_COUNT);
    ASSERT_EQ(ozayn_mtp_add_policy(&svc, &p), OZAYN_MTP_ERR_INVALID_PARAM);
    ozayn_mtp_service_shutdown(&svc);
    return 0;
}

TEST(test_mtp_add_policy_same_mode) {
    ozayn_mtp_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_mtp_service_init(&svc, NULL);
    ozayn_mtp_policy_t p = _make_policy("p1", OZAYN_ORD_MODE_READY,
                                        OZAYN_ORD_MODE_READY);
    ASSERT_EQ(ozayn_mtp_add_policy(&svc, &p), OZAYN_MTP_ERR_INVALID_PARAM);
    ozayn_mtp_service_shutdown(&svc);
    return 0;
}

TEST(test_mtp_add_policy_invalid_transition) {
    ozayn_mtp_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_mtp_service_init(&svc, NULL);
    /* OFFLINE -> EMERGENCY is invalid in the matrix */
    ozayn_mtp_policy_t p = _make_policy("p1", OZAYN_ORD_MODE_UNKNOWN,
                                        OZAYN_ORD_MODE_BLOCKED);
    ASSERT_EQ(ozayn_mtp_add_policy(&svc, &p), OZAYN_MTP_ERR_TRANSITION_INVALID);
    ozayn_mtp_service_shutdown(&svc);
    return 0;
}

TEST(test_mtp_add_policy_duplicate) {
    ozayn_mtp_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_mtp_service_init(&svc, NULL);
    ozayn_mtp_policy_t p1 = _make_policy("p1", OZAYN_ORD_MODE_READY,
                                         OZAYN_ORD_MODE_MAINTENANCE);
    ozayn_mtp_policy_t p2 = _make_policy("p2", OZAYN_ORD_MODE_READY,
                                         OZAYN_ORD_MODE_MAINTENANCE);
    ASSERT_EQ(ozayn_mtp_add_policy(&svc, &p1), OZAYN_MTP_OK);
    ASSERT_EQ(ozayn_mtp_add_policy(&svc, &p2), OZAYN_MTP_ERR_POLICY_CONFLICT);
    ozayn_mtp_service_shutdown(&svc);
    return 0;
}

TEST(test_mtp_remove_policy_null) {
    ASSERT_EQ(ozayn_mtp_remove_policy(NULL, NULL), OZAYN_MTP_ERR_NULL);
    return 0;
}

TEST(test_mtp_remove_policy_not_found) {
    ozayn_mtp_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_mtp_service_init(&svc, NULL);
    ASSERT_EQ(ozayn_mtp_remove_policy(&svc, "nonexistent"), OZAYN_MTP_ERR_POLICY_NOT_FOUND);
    ozayn_mtp_service_shutdown(&svc);
    return 0;
}

TEST(test_mtp_remove_policy_ok) {
    ozayn_mtp_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_mtp_service_init(&svc, NULL);
    ozayn_mtp_policy_t p = _make_policy("p1", OZAYN_ORD_MODE_READY,
                                        OZAYN_ORD_MODE_MAINTENANCE);
    ASSERT_EQ(ozayn_mtp_add_policy(&svc, &p), OZAYN_MTP_OK);
    ASSERT_EQ(ozayn_mtp_remove_policy(&svc, "p1"), OZAYN_MTP_OK);
    ASSERT_EQ(ozayn_mtp_policy_count(&svc), 1);
    /* Should be gone now (inactive) */
    ozayn_mtp_policy_t out;
    ASSERT_EQ(ozayn_mtp_get_policy(&svc, "p1", &out), OZAYN_MTP_ERR_POLICY_NOT_FOUND);
    ozayn_mtp_service_shutdown(&svc);
    return 0;
}

TEST(test_mtp_enable_policy_null) {
    ASSERT_EQ(ozayn_mtp_enable_policy(NULL, NULL, 0), OZAYN_MTP_ERR_NULL);
    return 0;
}

TEST(test_mtp_enable_policy_not_found) {
    ozayn_mtp_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_mtp_service_init(&svc, NULL);
    ASSERT_EQ(ozayn_mtp_enable_policy(&svc, "no", 1), OZAYN_MTP_ERR_POLICY_NOT_FOUND);
    ozayn_mtp_service_shutdown(&svc);
    return 0;
}

TEST(test_mtp_enable_policy_ok) {
    ozayn_mtp_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_mtp_service_init(&svc, NULL);
    ozayn_mtp_policy_t p = _make_policy("p1", OZAYN_ORD_MODE_READY,
                                        OZAYN_ORD_MODE_MAINTENANCE);
    p.enabled = 0;
    ASSERT_EQ(ozayn_mtp_add_policy(&svc, &p), OZAYN_MTP_OK);
    ASSERT_EQ(ozayn_mtp_enable_policy(&svc, "p1", 1), OZAYN_MTP_OK);
    ozayn_mtp_policy_t out;
    ASSERT_EQ(ozayn_mtp_get_policy(&svc, "p1", &out), OZAYN_MTP_OK);
    ASSERT(out.enabled);
    ozayn_mtp_service_shutdown(&svc);
    return 0;
}

TEST(test_mtp_disable_policy_ok) {
    ozayn_mtp_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_mtp_service_init(&svc, NULL);
    ozayn_mtp_policy_t p = _make_policy("p1", OZAYN_ORD_MODE_READY,
                                        OZAYN_ORD_MODE_MAINTENANCE);
    ASSERT_EQ(ozayn_mtp_add_policy(&svc, &p), OZAYN_MTP_OK);
    ASSERT_EQ(ozayn_mtp_enable_policy(&svc, "p1", 0), OZAYN_MTP_OK);
    ozayn_mtp_policy_t out;
    ASSERT_EQ(ozayn_mtp_get_policy(&svc, "p1", &out), OZAYN_MTP_OK);
    ASSERT(!out.enabled);
    ozayn_mtp_service_shutdown(&svc);
    return 0;
}

TEST(test_mtp_get_policy_null) {
    ASSERT_EQ(ozayn_mtp_get_policy(NULL, "x", NULL), OZAYN_MTP_ERR_NULL);
    return 0;
}

TEST(test_mtp_get_policy_not_init) {
    ozayn_mtp_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_mtp_policy_t out;
    ASSERT_EQ(ozayn_mtp_get_policy(&svc, "x", &out), OZAYN_MTP_ERR_NOT_INITIALIZED);
    return 0;
}

TEST(test_mtp_get_policy_found) {
    ozayn_mtp_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_mtp_service_init(&svc, NULL);
    ozayn_mtp_policy_t p = _make_policy("p1", OZAYN_ORD_MODE_READY,
                                        OZAYN_ORD_MODE_MAINTENANCE);
    ASSERT_EQ(ozayn_mtp_add_policy(&svc, &p), OZAYN_MTP_OK);
    ozayn_mtp_policy_t out;
    ASSERT_EQ(ozayn_mtp_get_policy(&svc, "p1", &out), OZAYN_MTP_OK);
    ASSERT(strcmp(out.id, "p1") == 0);
    ASSERT_EQ(out.source_mode, OZAYN_ORD_MODE_READY);
    ASSERT_EQ(out.target_mode, OZAYN_ORD_MODE_MAINTENANCE);
    ozayn_mtp_service_shutdown(&svc);
    return 0;
}

TEST(test_mtp_get_policy_at_null) {
    ASSERT_EQ(ozayn_mtp_get_policy_at(NULL, 0, NULL), OZAYN_MTP_ERR_NULL);
    return 0;
}

TEST(test_mtp_get_policy_at_ok) {
    ozayn_mtp_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_mtp_service_init(&svc, NULL);
    ozayn_mtp_policy_t p = _make_policy("p1", OZAYN_ORD_MODE_READY,
                                        OZAYN_ORD_MODE_MAINTENANCE);
    ASSERT_EQ(ozayn_mtp_add_policy(&svc, &p), OZAYN_MTP_OK);
    ozayn_mtp_policy_t out;
    ASSERT_EQ(ozayn_mtp_get_policy_at(&svc, 0, &out), OZAYN_MTP_OK);
    ASSERT(strcmp(out.id, "p1") == 0);
    ASSERT_EQ(ozayn_mtp_get_policy_at(&svc, 1, &out), OZAYN_MTP_ERR_NOT_FOUND);
    ozayn_mtp_service_shutdown(&svc);
    return 0;
}

TEST(test_mtp_policy_count_null) {
    ASSERT_EQ(ozayn_mtp_policy_count(NULL), 0);
    return 0;
}

TEST(test_mtp_policy_count_not_init) {
    ozayn_mtp_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ASSERT_EQ(ozayn_mtp_policy_count(&svc), 0);
    return 0;
}

TEST(test_mtp_policy_count_after_add) {
    ozayn_mtp_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_mtp_service_init(&svc, NULL);
    ASSERT_EQ(ozayn_mtp_policy_count(&svc), 0);
    ozayn_mtp_policy_t p = _make_policy("p1", OZAYN_ORD_MODE_READY,
                                        OZAYN_ORD_MODE_MAINTENANCE);
    ozayn_mtp_add_policy(&svc, &p);
    ASSERT_EQ(ozayn_mtp_policy_count(&svc), 1);
    ozayn_mtp_policy_t p2 = _make_policy("p2", OZAYN_ORD_MODE_MAINTENANCE,
                                         OZAYN_ORD_MODE_READY);
    ozayn_mtp_add_policy(&svc, &p2);
    ASSERT_EQ(ozayn_mtp_policy_count(&svc), 2);
    ozayn_mtp_service_shutdown(&svc);
    return 0;
}

TEST(test_mtp_add_policy_default_timeout) {
    ozayn_mtp_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_mtp_service_init(&svc, NULL);
    ozayn_mtp_policy_t p = _make_policy("p1", OZAYN_ORD_MODE_READY,
                                        OZAYN_ORD_MODE_MAINTENANCE);
    p.transition_timeout_ms = 0;
    ASSERT_EQ(ozayn_mtp_add_policy(&svc, &p), OZAYN_MTP_OK);
    ozayn_mtp_policy_t out;
    ASSERT_EQ(ozayn_mtp_get_policy(&svc, "p1", &out), OZAYN_MTP_OK);
    ASSERT_EQ(out.transition_timeout_ms, OZAYN_MTP_DEFAULT_TIMEOUT_MS);
    ozayn_mtp_service_shutdown(&svc);
    return 0;
}

/* ============================================================
 * EVALUATION TESTS
 * ============================================================ */

TEST(test_evaluate_null) {
    ozayn_mtp_decision_t d;
    ASSERT_EQ(ozayn_mtp_evaluate(NULL, 0, 0, 0, NULL, NULL, &d),
              OZAYN_MTP_ERR_NULL);
    return 0;
}

TEST(test_evaluate_not_init) {
    ozayn_mtp_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_mtp_decision_t d;
    ASSERT_EQ(ozayn_mtp_evaluate(&svc, OZAYN_ORD_MODE_READY,
              OZAYN_ORD_MODE_MAINTENANCE, OZAYN_MTP_TRIGGER_ADMINISTRATIVE,
              "test", "user", &d), OZAYN_MTP_ERR_NOT_INITIALIZED);
    return 0;
}

TEST(test_evaluate_null_decision) {
    ozayn_mtp_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_mtp_service_init(&svc, NULL);
    ASSERT_EQ(ozayn_mtp_evaluate(&svc, OZAYN_ORD_MODE_READY,
              OZAYN_ORD_MODE_MAINTENANCE, OZAYN_MTP_TRIGGER_ADMINISTRATIVE,
              "test", "user", NULL), OZAYN_MTP_ERR_NULL);
    ozayn_mtp_service_shutdown(&svc);
    return 0;
}

TEST(test_evaluate_invalid_source) {
    ozayn_mtp_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_mtp_service_init(&svc, NULL);
    ozayn_mtp_decision_t d;
    ASSERT_EQ(ozayn_mtp_evaluate(&svc, -1, OZAYN_ORD_MODE_MAINTENANCE,
              OZAYN_MTP_TRIGGER_ADMINISTRATIVE, "test", "user", &d),
              OZAYN_MTP_ERR_INVALID_PARAM);
    ozayn_mtp_service_shutdown(&svc);
    return 0;
}

TEST(test_evaluate_invalid_target) {
    ozayn_mtp_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_mtp_service_init(&svc, NULL);
    ozayn_mtp_decision_t d;
    ASSERT_EQ(ozayn_mtp_evaluate(&svc, OZAYN_ORD_MODE_READY,
              OZAYN_ORD_MODE_COUNT, OZAYN_MTP_TRIGGER_ADMINISTRATIVE,
              "test", "user", &d), OZAYN_MTP_ERR_INVALID_PARAM);
    ozayn_mtp_service_shutdown(&svc);
    return 0;
}

TEST(test_evaluate_same_mode) {
    ozayn_mtp_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_mtp_service_init(&svc, NULL);
    ozayn_mtp_decision_t d;
    ASSERT_EQ(ozayn_mtp_evaluate(&svc, OZAYN_ORD_MODE_READY,
              OZAYN_ORD_MODE_READY, OZAYN_MTP_TRIGGER_ADMINISTRATIVE,
              "test", "user", &d), OZAYN_MTP_ERR_INVALID_PARAM);
    ozayn_mtp_service_shutdown(&svc);
    return 0;
}

TEST(test_evaluate_invalid_matrix_transition) {
    ozayn_mtp_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_mtp_service_init(&svc, NULL);
    ozayn_mtp_decision_t d;
    /* OFFLINE -> EMERGENCY not in matrix */
    ASSERT_EQ(ozayn_mtp_evaluate(&svc, OZAYN_ORD_MODE_UNKNOWN,
              OZAYN_ORD_MODE_BLOCKED, OZAYN_MTP_TRIGGER_ADMINISTRATIVE,
              "test", "user", &d), OZAYN_MTP_OK);
    ASSERT_EQ(d.outcome, OZAYN_MTP_OUTCOME_DENY);
    ASSERT_EQ(d.phase, OZAYN_MTP_PHASE_REJECTED);
    ASSERT(d.blocking_count > 0);
    ozayn_mtp_service_shutdown(&svc);
    return 0;
}

TEST(test_evaluate_valid_no_policy) {
    ozayn_mtp_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_mtp_service_init(&svc, NULL);
    ozayn_mtp_decision_t d;
    ASSERT_EQ(ozayn_mtp_evaluate(&svc, OZAYN_ORD_MODE_READY,
              OZAYN_ORD_MODE_MAINTENANCE, OZAYN_MTP_TRIGGER_ADMINISTRATIVE,
              "test", "user", &d), OZAYN_MTP_OK);
    ASSERT_EQ(d.outcome, OZAYN_MTP_OUTCOME_ALLOW);
    ASSERT_EQ(d.phase, OZAYN_MTP_PHASE_DECIDED);
    ASSERT(d.security_passed);
    ASSERT(d.safety_passed);
    ASSERT(d.resource_passed);
    ASSERT(d.dependency_passed);
    ASSERT_EQ(d.blocking_count, 0);
    ozayn_mtp_service_shutdown(&svc);
    return 0;
}

TEST(test_evaluate_with_policy_no_subsystems) {
    ozayn_mtp_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_mtp_service_init(&svc, NULL);
    ozayn_mtp_policy_t p = _make_policy("p1", OZAYN_ORD_MODE_READY,
                                        OZAYN_ORD_MODE_MAINTENANCE);
    p.require_security_valid = 1;
    p.require_safety_satisfied = 1;
    ASSERT_EQ(ozayn_mtp_add_policy(&svc, &p), OZAYN_MTP_OK);

    ozayn_mtp_decision_t d;
    ASSERT_EQ(ozayn_mtp_evaluate(&svc, OZAYN_ORD_MODE_READY,
              OZAYN_ORD_MODE_MAINTENANCE, OZAYN_MTP_TRIGGER_ADMINISTRATIVE,
              "test", "user", &d), OZAYN_MTP_OK);
    /* Security and safety subsystems not bound -> blocking */
    ASSERT(!d.security_passed);
    ASSERT(!d.safety_passed);
    ASSERT_EQ(d.outcome, OZAYN_MTP_OUTCOME_REQUIRES_AUTHORIZATION);
    ozayn_mtp_service_shutdown(&svc);
    return 0;
}

TEST(test_evaluate_with_policy_and_subsystems) {
    ozayn_mtp_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_mtp_service_init(&svc, NULL);
    int dummy = 1;
    ozayn_mtp_set_audit(&svc, &dummy);
    ozayn_mtp_set_safety(&svc, &dummy);

    ozayn_mtp_policy_t p = _make_policy("p1", OZAYN_ORD_MODE_READY,
                                        OZAYN_ORD_MODE_MAINTENANCE);
    p.require_security_valid = 1;
    p.require_safety_satisfied = 1;
    ASSERT_EQ(ozayn_mtp_add_policy(&svc, &p), OZAYN_MTP_OK);

    ozayn_mtp_decision_t d;
    ASSERT_EQ(ozayn_mtp_evaluate(&svc, OZAYN_ORD_MODE_READY,
              OZAYN_ORD_MODE_MAINTENANCE, OZAYN_MTP_TRIGGER_ADMINISTRATIVE,
              "test", "user", &d), OZAYN_MTP_OK);
    ASSERT(d.security_passed);
    ASSERT(d.safety_passed);
    ASSERT_EQ(d.outcome, OZAYN_MTP_OUTCOME_ALLOW);
    ozayn_mtp_service_shutdown(&svc);
    return 0;
}

TEST(test_evaluate_records_request) {
    ozayn_mtp_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_mtp_service_init(&svc, NULL);
    ozayn_mtp_decision_t d;
    ASSERT_EQ(ozayn_mtp_evaluate(&svc, OZAYN_ORD_MODE_READY,
              OZAYN_ORD_MODE_MAINTENANCE, OZAYN_MTP_TRIGGER_ADMINISTRATIVE,
              "my reason", "myuser", &d), OZAYN_MTP_OK);
    ASSERT_EQ(ozayn_mtp_request_count(&svc), 1);
    ozayn_mtp_request_t req;
    ASSERT_EQ(ozayn_mtp_get_request(&svc, d.request_id, &req), OZAYN_MTP_OK);
    ASSERT(strcmp(req.reason, "my reason") == 0);
    ASSERT(strcmp(req.requester, "myuser") == 0);
    ASSERT_EQ(req.trigger, OZAYN_MTP_TRIGGER_ADMINISTRATIVE);
    ozayn_mtp_service_shutdown(&svc);
    return 0;
}

TEST(test_evaluate_records_decision) {
    ozayn_mtp_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_mtp_service_init(&svc, NULL);
    ozayn_mtp_decision_t d;
    ASSERT_EQ(ozayn_mtp_evaluate(&svc, OZAYN_ORD_MODE_READY,
              OZAYN_ORD_MODE_MAINTENANCE, OZAYN_MTP_TRIGGER_ADMINISTRATIVE,
              "test", "user", &d), OZAYN_MTP_OK);
    ASSERT_EQ(ozayn_mtp_decision_count(&svc), 1);
    ozayn_mtp_decision_t stored;
    ASSERT_EQ(ozayn_mtp_get_decision(&svc, d.id, &stored), OZAYN_MTP_OK);
    ASSERT_EQ(stored.outcome, OZAYN_MTP_OUTCOME_ALLOW);
    ozayn_mtp_service_shutdown(&svc);
    return 0;
}

TEST(test_evaluate_multiple) {
    ozayn_mtp_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_mtp_service_init(&svc, NULL);
    ozayn_mtp_decision_t d;

    ASSERT_EQ(ozayn_mtp_evaluate(&svc, OZAYN_ORD_MODE_READY,
              OZAYN_ORD_MODE_MAINTENANCE, OZAYN_MTP_TRIGGER_ADMINISTRATIVE,
              "1", "user", &d), OZAYN_MTP_OK);
    ASSERT_EQ(ozayn_mtp_evaluate(&svc, OZAYN_ORD_MODE_READY,
              OZAYN_ORD_MODE_RECOVERY, OZAYN_MTP_TRIGGER_HEALTH_CHANGE,
              "2", "user", &d), OZAYN_MTP_OK);
    ASSERT_EQ(ozayn_mtp_evaluate(&svc, OZAYN_ORD_MODE_MAINTENANCE,
              OZAYN_ORD_MODE_READY, OZAYN_MTP_TRIGGER_ADMINISTRATIVE,
              "3", "user", &d), OZAYN_MTP_OK);

    ASSERT_EQ(ozayn_mtp_request_count(&svc), 3);
    ASSERT_EQ(ozayn_mtp_decision_count(&svc), 3);
    ozayn_mtp_service_shutdown(&svc);
    return 0;
}

TEST(test_evaluate_generates_ids) {
    ozayn_mtp_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_mtp_service_init(&svc, NULL);
    ozayn_mtp_decision_t d1, d2;
    ASSERT_EQ(ozayn_mtp_evaluate(&svc, OZAYN_ORD_MODE_READY,
              OZAYN_ORD_MODE_MAINTENANCE, OZAYN_MTP_TRIGGER_ADMINISTRATIVE,
              "1", "user", &d1), OZAYN_MTP_OK);
    ASSERT_EQ(ozayn_mtp_evaluate(&svc, OZAYN_ORD_MODE_MAINTENANCE,
              OZAYN_ORD_MODE_READY, OZAYN_MTP_TRIGGER_ADMINISTRATIVE,
              "2", "user", &d2), OZAYN_MTP_OK);
    ASSERT(strcmp(d1.id, d2.id) != 0);
    ASSERT(strcmp(d1.request_id, d2.request_id) != 0);
    ozayn_mtp_service_shutdown(&svc);
    return 0;
}

TEST(test_evaluate_safety_required_no_subsystem) {
    ozayn_mtp_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_mtp_service_init(&svc, NULL);
    ozayn_mtp_policy_t p = _make_policy("p1", OZAYN_ORD_MODE_READY,
                                        OZAYN_ORD_MODE_MAINTENANCE);
    p.require_safety_satisfied = 1;
    ASSERT_EQ(ozayn_mtp_add_policy(&svc, &p), OZAYN_MTP_OK);

    ozayn_mtp_decision_t d;
    ASSERT_EQ(ozayn_mtp_evaluate(&svc, OZAYN_ORD_MODE_READY,
              OZAYN_ORD_MODE_MAINTENANCE, OZAYN_MTP_TRIGGER_ADMINISTRATIVE,
              "test", "user", &d), OZAYN_MTP_OK);
    ASSERT(!d.safety_passed);
    ASSERT_EQ(d.outcome, OZAYN_MTP_OUTCOME_REQUIRES_SAFETY_CHECK);
    ozayn_mtp_service_shutdown(&svc);
    return 0;
}

TEST(test_evaluate_resource_warning) {
    ozayn_mtp_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_mtp_service_init(&svc, NULL);
    ozayn_mtp_policy_t p = _make_policy("p1", OZAYN_ORD_MODE_READY,
                                        OZAYN_ORD_MODE_MAINTENANCE);
    p.require_resources_available = 1;
    ASSERT_EQ(ozayn_mtp_add_policy(&svc, &p), OZAYN_MTP_OK);

    ozayn_mtp_decision_t d;
    ASSERT_EQ(ozayn_mtp_evaluate(&svc, OZAYN_ORD_MODE_READY,
              OZAYN_ORD_MODE_MAINTENANCE, OZAYN_MTP_TRIGGER_ADMINISTRATIVE,
              "test", "user", &d), OZAYN_MTP_OK);
    /* No resource_manager -> warning but still allowed */
    ASSERT_EQ(d.outcome, OZAYN_MTP_OUTCOME_ALLOW);
    ASSERT(d.warning_count > 0);
    ASSERT(d.resource_passed);
    ozayn_mtp_service_shutdown(&svc);
    return 0;
}

TEST(test_evaluate_readiness_warning) {
    ozayn_mtp_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_mtp_service_init(&svc, NULL);
    ozayn_mtp_policy_t p = _make_policy("p1", OZAYN_ORD_MODE_READY,
                                        OZAYN_ORD_MODE_MAINTENANCE);
    p.require_readiness_assessment = 1;
    ASSERT_EQ(ozayn_mtp_add_policy(&svc, &p), OZAYN_MTP_OK);

    ozayn_mtp_decision_t d;
    ASSERT_EQ(ozayn_mtp_evaluate(&svc, OZAYN_ORD_MODE_READY,
              OZAYN_ORD_MODE_MAINTENANCE, OZAYN_MTP_TRIGGER_ADMINISTRATIVE,
              "test", "user", &d), OZAYN_MTP_OK);
    ASSERT_EQ(d.outcome, OZAYN_MTP_OUTCOME_ALLOW);
    ASSERT(d.warning_count > 0);
    ASSERT(d.readiness_current);
    ozayn_mtp_service_shutdown(&svc);
    return 0;
}

/* ============================================================
 * QUICK CHECK TESTS
 * ============================================================ */

TEST(test_can_transition_null) {
    ASSERT(!ozayn_mtp_can_transition(NULL, OZAYN_ORD_MODE_READY,
           OZAYN_ORD_MODE_MAINTENANCE));
    return 0;
}

TEST(test_can_transition_not_init) {
    ozayn_mtp_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ASSERT(!ozayn_mtp_can_transition(&svc, OZAYN_ORD_MODE_READY,
           OZAYN_ORD_MODE_MAINTENANCE));
    return 0;
}

TEST(test_can_transition_invalid) {
    ozayn_mtp_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_mtp_service_init(&svc, NULL);
    ASSERT(!ozayn_mtp_can_transition(&svc, OZAYN_ORD_MODE_UNKNOWN,
           OZAYN_ORD_MODE_BLOCKED));
    ozayn_mtp_service_shutdown(&svc);
    return 0;
}

TEST(test_can_transition_valid_no_policy) {
    ozayn_mtp_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_mtp_service_init(&svc, NULL);
    ASSERT(ozayn_mtp_can_transition(&svc, OZAYN_ORD_MODE_READY,
           OZAYN_ORD_MODE_MAINTENANCE));
    ozayn_mtp_service_shutdown(&svc);
    return 0;
}

TEST(test_can_transition_valid_with_policy) {
    ozayn_mtp_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_mtp_service_init(&svc, NULL);
    ozayn_mtp_policy_t p = _make_policy("p1", OZAYN_ORD_MODE_READY,
                                        OZAYN_ORD_MODE_MAINTENANCE);
    ASSERT_EQ(ozayn_mtp_add_policy(&svc, &p), OZAYN_MTP_OK);
    ASSERT(ozayn_mtp_can_transition(&svc, OZAYN_ORD_MODE_READY,
           OZAYN_ORD_MODE_MAINTENANCE));
    ozayn_mtp_service_shutdown(&svc);
    return 0;
}

TEST(test_can_transition_disabled_policy) {
    ozayn_mtp_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_mtp_service_init(&svc, NULL);
    ozayn_mtp_policy_t p = _make_policy("p1", OZAYN_ORD_MODE_READY,
                                        OZAYN_ORD_MODE_MAINTENANCE);
    p.enabled = 0;
    ASSERT_EQ(ozayn_mtp_add_policy(&svc, &p), OZAYN_MTP_OK);
    /* Disabled policy is skipped — still allowed via matrix */
    ASSERT(ozayn_mtp_can_transition(&svc, OZAYN_ORD_MODE_READY,
           OZAYN_ORD_MODE_MAINTENANCE));
    ozayn_mtp_service_shutdown(&svc);
    return 0;
}

/* ============================================================
 * DECISION QUERIES
 * ============================================================ */

TEST(test_get_decision_null) {
    ozayn_mtp_decision_t d;
    ASSERT_EQ(ozayn_mtp_get_decision(NULL, "x", &d), OZAYN_MTP_ERR_NULL);
    return 0;
}

TEST(test_get_decision_not_init) {
    ozayn_mtp_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_mtp_decision_t d;
    ASSERT_EQ(ozayn_mtp_get_decision(&svc, "x", &d), OZAYN_MTP_ERR_NOT_INITIALIZED);
    return 0;
}

TEST(test_get_decision_not_found) {
    ozayn_mtp_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_mtp_service_init(&svc, NULL);
    ozayn_mtp_decision_t d;
    ASSERT_EQ(ozayn_mtp_get_decision(&svc, "MDEC-999999", &d),
              OZAYN_MTP_ERR_NOT_FOUND);
    ozayn_mtp_service_shutdown(&svc);
    return 0;
}

TEST(test_get_latest_decision_empty) {
    ozayn_mtp_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_mtp_service_init(&svc, NULL);
    ozayn_mtp_decision_t d;
    ASSERT_EQ(ozayn_mtp_get_latest_decision(&svc, &d), OZAYN_MTP_ERR_NOT_FOUND);
    ozayn_mtp_service_shutdown(&svc);
    return 0;
}

TEST(test_get_latest_decision_ok) {
    ozayn_mtp_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_mtp_service_init(&svc, NULL);
    ozayn_mtp_decision_t d;
    ozayn_mtp_evaluate(&svc, OZAYN_ORD_MODE_READY,
              OZAYN_ORD_MODE_MAINTENANCE, OZAYN_MTP_TRIGGER_ADMINISTRATIVE,
              "test", "user", &d);
    ozayn_mtp_decision_t latest;
    ASSERT_EQ(ozayn_mtp_get_latest_decision(&svc, &latest), OZAYN_MTP_OK);
    ASSERT(strcmp(latest.id, d.id) == 0);
    ozayn_mtp_service_shutdown(&svc);
    return 0;
}

TEST(test_decision_count_null) {
    ASSERT_EQ(ozayn_mtp_decision_count(NULL), 0);
    return 0;
}

TEST(test_decision_count_after_eval) {
    ozayn_mtp_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_mtp_service_init(&svc, NULL);
    ASSERT_EQ(ozayn_mtp_decision_count(&svc), 0);
    ozayn_mtp_decision_t d;
    ozayn_mtp_evaluate(&svc, OZAYN_ORD_MODE_READY,
              OZAYN_ORD_MODE_MAINTENANCE, OZAYN_MTP_TRIGGER_ADMINISTRATIVE,
              "test", "user", &d);
    ASSERT_EQ(ozayn_mtp_decision_count(&svc), 1);
    ozayn_mtp_service_shutdown(&svc);
    return 0;
}

/* ============================================================
 * REQUEST QUERIES
 * ============================================================ */

TEST(test_get_request_null) {
    ozayn_mtp_request_t r;
    ASSERT_EQ(ozayn_mtp_get_request(NULL, "x", &r), OZAYN_MTP_ERR_NULL);
    return 0;
}

TEST(test_get_request_not_found) {
    ozayn_mtp_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_mtp_service_init(&svc, NULL);
    ozayn_mtp_request_t r;
    ASSERT_EQ(ozayn_mtp_get_request(&svc, "MREQ-999999", &r),
              OZAYN_MTP_ERR_NOT_FOUND);
    ozayn_mtp_service_shutdown(&svc);
    return 0;
}

TEST(test_request_count_null) {
    ASSERT_EQ(ozayn_mtp_request_count(NULL), 0);
    return 0;
}

TEST(test_request_count_after_eval) {
    ozayn_mtp_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_mtp_service_init(&svc, NULL);
    ASSERT_EQ(ozayn_mtp_request_count(&svc), 0);
    ozayn_mtp_decision_t d;
    ozayn_mtp_evaluate(&svc, OZAYN_ORD_MODE_READY,
              OZAYN_ORD_MODE_MAINTENANCE, OZAYN_MTP_TRIGGER_ADMINISTRATIVE,
              "test", "user", &d);
    ASSERT_EQ(ozayn_mtp_request_count(&svc), 1);
    ozayn_mtp_service_shutdown(&svc);
    return 0;
}

TEST(test_request_default_requester) {
    ozayn_mtp_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_mtp_service_init(&svc, NULL);
    ozayn_mtp_decision_t d;
    ozayn_mtp_evaluate(&svc, OZAYN_ORD_MODE_READY,
              OZAYN_ORD_MODE_MAINTENANCE, OZAYN_MTP_TRIGGER_ADMINISTRATIVE,
              "test", NULL, &d);
    ozayn_mtp_request_t req;
    ASSERT_EQ(ozayn_mtp_get_request(&svc, d.request_id, &req), OZAYN_MTP_OK);
    ASSERT(strcmp(req.requester, "system") == 0);
    ozayn_mtp_service_shutdown(&svc);
    return 0;
}

/* ============================================================
 * EVENT TESTS
 * ============================================================ */

TEST(test_event_count_null) {
    ASSERT_EQ(ozayn_mtp_event_count(NULL), 0);
    return 0;
}

TEST(test_event_count_after_init) {
    ozayn_mtp_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_mtp_service_init(&svc, NULL);
    ASSERT(ozayn_mtp_event_count(&svc) >= 1);
    ozayn_mtp_service_shutdown(&svc);
    return 0;
}

TEST(test_event_count_after_eval) {
    ozayn_mtp_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_mtp_service_init(&svc, NULL);
    int before = ozayn_mtp_event_count(&svc);
    ozayn_mtp_decision_t d;
    ozayn_mtp_evaluate(&svc, OZAYN_ORD_MODE_READY,
              OZAYN_ORD_MODE_MAINTENANCE, OZAYN_MTP_TRIGGER_ADMINISTRATIVE,
              "test", "user", &d);
    ASSERT(ozayn_mtp_event_count(&svc) > before);
    ozayn_mtp_service_shutdown(&svc);
    return 0;
}

TEST(test_get_event_null) {
    ozayn_mtp_event_t e;
    ASSERT_EQ(ozayn_mtp_get_event(NULL, 0, &e), OZAYN_MTP_ERR_NULL);
    return 0;
}

TEST(test_get_event_not_init) {
    ozayn_mtp_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_mtp_event_t e;
    ASSERT_EQ(ozayn_mtp_get_event(&svc, 0, &e), OZAYN_MTP_ERR_NOT_INITIALIZED);
    return 0;
}

TEST(test_get_event_out_of_range) {
    ozayn_mtp_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_mtp_service_init(&svc, NULL);
    ozayn_mtp_event_t e;
    ASSERT_EQ(ozayn_mtp_get_event(&svc, 9999, &e), OZAYN_MTP_ERR_NOT_FOUND);
    ozayn_mtp_service_shutdown(&svc);
    return 0;
}

TEST(test_get_event_valid) {
    ozayn_mtp_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_mtp_service_init(&svc, NULL);
    ozayn_mtp_event_t e;
    ASSERT_EQ(ozayn_mtp_get_event(&svc, 0, &e), OZAYN_MTP_OK);
    ASSERT(e.timestamp_ms > 0);
    ASSERT(e.sequence >= 0);
    ozayn_mtp_service_shutdown(&svc);
    return 0;
}

TEST(test_event_sequence_increments) {
    ozayn_mtp_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_mtp_service_init(&svc, NULL);
    ozayn_mtp_event_t e1, e2;
    ozayn_mtp_get_event(&svc, 0, &e1);
    ozayn_mtp_decision_t d;
    ozayn_mtp_evaluate(&svc, OZAYN_ORD_MODE_READY,
              OZAYN_ORD_MODE_MAINTENANCE, OZAYN_MTP_TRIGGER_ADMINISTRATIVE,
              "test", "user", &d);
    ozayn_mtp_get_event(&svc, 1, &e2);
    ASSERT(e2.sequence > e1.sequence);
    ozayn_mtp_service_shutdown(&svc);
    return 0;
}

/* ============================================================
 * STATS TESTS
 * ============================================================ */

TEST(test_stats_null) {
    ASSERT(ozayn_mtp_get_stats(NULL) == NULL);
    return 0;
}

TEST(test_stats_initial_zero) {
    ozayn_mtp_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_mtp_service_init(&svc, NULL);
    const ozayn_mtp_stats_t *s = ozayn_mtp_get_stats(&svc);
    ASSERT(s != NULL);
    ASSERT_EQ(s->total_evaluations, 0);
    ASSERT_EQ(s->total_approvals, 0);
    ASSERT_EQ(s->total_denials, 0);
    ASSERT_EQ(s->total_deferrals, 0);
    ozayn_mtp_service_shutdown(&svc);
    return 0;
}

TEST(test_stats_after_approval) {
    ozayn_mtp_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_mtp_service_init(&svc, NULL);
    ozayn_mtp_decision_t d;
    ozayn_mtp_evaluate(&svc, OZAYN_ORD_MODE_READY,
              OZAYN_ORD_MODE_MAINTENANCE, OZAYN_MTP_TRIGGER_ADMINISTRATIVE,
              "test", "user", &d);
    const ozayn_mtp_stats_t *s = ozayn_mtp_get_stats(&svc);
    ASSERT_EQ(s->total_evaluations, 1);
    ASSERT_EQ(s->total_approvals, 1);
    ASSERT_EQ(s->total_denials, 0);
    ozayn_mtp_service_shutdown(&svc);
    return 0;
}

TEST(test_stats_after_denial) {
    ozayn_mtp_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_mtp_service_init(&svc, NULL);
    ozayn_mtp_decision_t d;
    ozayn_mtp_evaluate(&svc, OZAYN_ORD_MODE_UNKNOWN,
              OZAYN_ORD_MODE_BLOCKED, OZAYN_MTP_TRIGGER_ADMINISTRATIVE,
              "test", "user", &d);
    const ozayn_mtp_stats_t *s = ozayn_mtp_get_stats(&svc);
    ASSERT_EQ(s->total_evaluations, 1);
    ASSERT_EQ(s->total_denials, 1);
    ASSERT_EQ(s->total_approvals, 0);
    ozayn_mtp_service_shutdown(&svc);
    return 0;
}

TEST(test_stats_after_deferral) {
    ozayn_mtp_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_mtp_service_init(&svc, NULL);
    ozayn_mtp_policy_t p = _make_policy("p1", OZAYN_ORD_MODE_READY,
                                        OZAYN_ORD_MODE_MAINTENANCE);
    p.require_security_valid = 1;
    ASSERT_EQ(ozayn_mtp_add_policy(&svc, &p), OZAYN_MTP_OK);

    /* First eval -> deny (security) */
    ozayn_mtp_decision_t d1;
    ozayn_mtp_evaluate(&svc, OZAYN_ORD_MODE_READY,
              OZAYN_ORD_MODE_MAINTENANCE, OZAYN_MTP_TRIGGER_ADMINISTRATIVE,
              "test", "user", &d1);

    /* Second eval -> conflict (active transition) — but no active, so deny again */
    ozayn_mtp_decision_t d2;
    ozayn_mtp_evaluate(&svc, OZAYN_ORD_MODE_READY,
              OZAYN_ORD_MODE_MAINTENANCE, OZAYN_MTP_TRIGGER_ADMINISTRATIVE,
              "test2", "user", &d2);

    const ozayn_mtp_stats_t *s = ozayn_mtp_get_stats(&svc);
    ASSERT_EQ(s->total_evaluations, 2);
    ozayn_mtp_service_shutdown(&svc);
    return 0;
}

TEST(test_reset_stats) {
    ozayn_mtp_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_mtp_service_init(&svc, NULL);
    ozayn_mtp_decision_t d;
    ozayn_mtp_evaluate(&svc, OZAYN_ORD_MODE_READY,
              OZAYN_ORD_MODE_MAINTENANCE, OZAYN_MTP_TRIGGER_ADMINISTRATIVE,
              "test", "user", &d);
    ASSERT_EQ(ozayn_mtp_reset_stats(&svc), OZAYN_MTP_OK);
    const ozayn_mtp_stats_t *s = ozayn_mtp_get_stats(&svc);
    ASSERT_EQ(s->total_evaluations, 0);
    ASSERT_EQ(s->total_approvals, 0);
    ozayn_mtp_service_shutdown(&svc);
    return 0;
}

TEST(test_reset_stats_null) {
    ASSERT_EQ(ozayn_mtp_reset_stats(NULL), OZAYN_MTP_ERR_NULL);
    return 0;
}

TEST(test_stats_conflict_detected) {
    ozayn_mtp_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_mtp_service_init(&svc, NULL);
    /* Simulate active transition */
    svc.has_active_transition = 1;
    ozayn_mtp_decision_t d;
    ozayn_mtp_evaluate(&svc, OZAYN_ORD_MODE_READY,
              OZAYN_ORD_MODE_MAINTENANCE, OZAYN_MTP_TRIGGER_ADMINISTRATIVE,
              "test", "user", &d);
    const ozayn_mtp_stats_t *s = ozayn_mtp_get_stats(&svc);
    ASSERT_EQ(s->total_conflicts_detected, 1);
    ASSERT_EQ(d.outcome, OZAYN_MTP_OUTCOME_DEFER);
    ozayn_mtp_service_shutdown(&svc);
    return 0;
}

/* ============================================================
 * NAME HELPERS TESTS
 * ============================================================ */

TEST(test_err_name_ok) {
    ASSERT(strcmp(ozayn_mtp_err_name(OZAYN_MTP_OK), "OK") == 0);
    return 0;
}

TEST(test_err_name_null) {
    ASSERT(strcmp(ozayn_mtp_err_name(OZAYN_MTP_ERR_NULL), "NULL") == 0);
    return 0;
}

TEST(test_err_name_all) {
    ASSERT(strcmp(ozayn_mtp_err_name(OZAYN_MTP_ERR_NOT_INITIALIZED),
                  "NOT_INITIALIZED") == 0);
    ASSERT(strcmp(ozayn_mtp_err_name(OZAYN_MTP_ERR_POLICY_NOT_FOUND),
                  "POLICY_NOT_FOUND") == 0);
    ASSERT(strcmp(ozayn_mtp_err_name(OZAYN_MTP_ERR_TRANSITION_INVALID),
                  "TRANSITION_INVALID") == 0);
    ASSERT(strcmp(ozayn_mtp_err_name(OZAYN_MTP_ERR_CONCURRENCY_ERROR),
                  "CONCURRENCY_ERROR") == 0);
    ASSERT(strcmp(ozayn_mtp_err_name(OZAYN_MTP_ERR_LIMIT_REACHED),
                  "LIMIT_REACHED") == 0);
    ASSERT(strcmp(ozayn_mtp_err_name(OZAYN_MTP_ERR_UNAVAILABLE),
                  "UNAVAILABLE") == 0);
    ASSERT(strcmp(ozayn_mtp_err_name(OZAYN_MTP_ERR_NOT_FOUND),
                  "NOT_FOUND") == 0);
    return 0;
}

TEST(test_outcome_name_all) {
    ASSERT(strcmp(ozayn_mtp_outcome_name(OZAYN_MTP_OUTCOME_ALLOW), "ALLOW") == 0);
    ASSERT(strcmp(ozayn_mtp_outcome_name(OZAYN_MTP_OUTCOME_DENY), "DENY") == 0);
    ASSERT(strcmp(ozayn_mtp_outcome_name(OZAYN_MTP_OUTCOME_DEFER), "DEFER") == 0);
    ASSERT(strcmp(ozayn_mtp_outcome_name(OZAYN_MTP_OUTCOME_REQUIRES_REASSESSMENT),
                  "REQUIRES_REASSESSMENT") == 0);
    ASSERT(strcmp(ozayn_mtp_outcome_name(OZAYN_MTP_OUTCOME_REQUIRES_AUTHORIZATION),
                  "REQUIRES_AUTHORIZATION") == 0);
    ASSERT(strcmp(ozayn_mtp_outcome_name(OZAYN_MTP_OUTCOME_REQUIRES_SAFETY_CHECK),
                  "REQUIRES_SAFETY_CHECK") == 0);
    ASSERT(strcmp(ozayn_mtp_outcome_name(OZAYN_MTP_OUTCOME_REQUIRES_RESOURCE_CHECK),
                  "REQUIRES_RESOURCE_CHECK") == 0);
    ASSERT(strcmp(ozayn_mtp_outcome_name(OZAYN_MTP_OUTCOME_MANUAL_REVIEW),
                  "MANUAL_REVIEW") == 0);
    ASSERT(strcmp(ozayn_mtp_outcome_name(OZAYN_MTP_OUTCOME_UNAVAILABLE),
                  "UNAVAILABLE") == 0);
    return 0;
}

TEST(test_phase_name_all) {
    ASSERT(strcmp(ozayn_mtp_phase_name(OZAYN_MTP_PHASE_NONE), "NONE") == 0);
    ASSERT(strcmp(ozayn_mtp_phase_name(OZAYN_MTP_PHASE_REQUESTED), "REQUESTED") == 0);
    ASSERT(strcmp(ozayn_mtp_phase_name(OZAYN_MTP_PHASE_VALIDATING), "VALIDATING") == 0);
    ASSERT(strcmp(ozayn_mtp_phase_name(OZAYN_MTP_PHASE_EVALUATING), "EVALUATING") == 0);
    ASSERT(strcmp(ozayn_mtp_phase_name(OZAYN_MTP_PHASE_DECIDED), "DECIDED") == 0);
    ASSERT(strcmp(ozayn_mtp_phase_name(OZAYN_MTP_PHASE_EXECUTING), "EXECUTING") == 0);
    ASSERT(strcmp(ozayn_mtp_phase_name(OZAYN_MTP_PHASE_COMPLETED), "COMPLETED") == 0);
    ASSERT(strcmp(ozayn_mtp_phase_name(OZAYN_MTP_PHASE_REJECTED), "REJECTED") == 0);
    ASSERT(strcmp(ozayn_mtp_phase_name(OZAYN_MTP_PHASE_FAILED), "FAILED") == 0);
    ASSERT(strcmp(ozayn_mtp_phase_name(OZAYN_MTP_PHASE_CANCELLED), "CANCELLED") == 0);
    ASSERT(strcmp(ozayn_mtp_phase_name(OZAYN_MTP_PHASE_EXPIRED), "EXPIRED") == 0);
    return 0;
}

TEST(test_trigger_name_all) {
    ASSERT(strcmp(ozayn_mtp_trigger_name(OZAYN_MTP_TRIGGER_NONE), "NONE") == 0);
    ASSERT(strcmp(ozayn_mtp_trigger_name(OZAYN_MTP_TRIGGER_STARTUP), "STARTUP") == 0);
    ASSERT(strcmp(ozayn_mtp_trigger_name(OZAYN_MTP_TRIGGER_SHUTDOWN), "SHUTDOWN") == 0);
    ASSERT(strcmp(ozayn_mtp_trigger_name(OZAYN_MTP_TRIGGER_HEALTH_CHANGE),
                  "HEALTH_CHANGE") == 0);
    ASSERT(strcmp(ozayn_mtp_trigger_name(OZAYN_MTP_TRIGGER_SECURITY_CHANGE),
                  "SECURITY_CHANGE") == 0);
    ASSERT(strcmp(ozayn_mtp_trigger_name(OZAYN_MTP_TRIGGER_RESOURCE_CHANGE),
                  "RESOURCE_CHANGE") == 0);
    ASSERT(strcmp(ozayn_mtp_trigger_name(OZAYN_MTP_TRIGGER_DEVICE_CHANGE),
                  "DEVICE_CHANGE") == 0);
    ASSERT(strcmp(ozayn_mtp_trigger_name(OZAYN_MTP_TRIGGER_RECOVERY), "RECOVERY") == 0);
    ASSERT(strcmp(ozayn_mtp_trigger_name(OZAYN_MTP_TRIGGER_MAINTENANCE_REQUEST),
                  "MAINTENANCE_REQUEST") == 0);
    ASSERT(strcmp(ozayn_mtp_trigger_name(OZAYN_MTP_TRIGGER_ADMINISTRATIVE),
                  "ADMINISTRATIVE") == 0);
    ASSERT(strcmp(ozayn_mtp_trigger_name(OZAYN_MTP_TRIGGER_SYSTEM_FAILURE),
                  "SYSTEM_FAILURE") == 0);
    ASSERT(strcmp(ozayn_mtp_trigger_name(OZAYN_MTP_TRIGGER_SAFETY_EVENT),
                  "SAFETY_EVENT") == 0);
    ASSERT(strcmp(ozayn_mtp_trigger_name(OZAYN_MTP_TRIGGER_CONFIGURATION_CHANGE),
                  "CONFIGURATION_CHANGE") == 0);
    return 0;
}

TEST(test_event_type_name_all) {
    ASSERT(strcmp(ozayn_mtp_event_type_name(OZAYN_MTP_EVENT_EVALUATION_STARTED),
                  "EVALUATION_STARTED") == 0);
    ASSERT(strcmp(ozayn_mtp_event_type_name(OZAYN_MTP_EVENT_TRANSITION_APPROVED),
                  "TRANSITION_APPROVED") == 0);
    ASSERT(strcmp(ozayn_mtp_event_type_name(OZAYN_MTP_EVENT_TRANSITION_DENIED),
                  "TRANSITION_DENIED") == 0);
    ASSERT(strcmp(ozayn_mtp_event_type_name(OZAYN_MTP_EVENT_TRANSITION_DEFERRED),
                  "TRANSITION_DEFERRED") == 0);
    ASSERT(strcmp(ozayn_mtp_event_type_name(OZAYN_MTP_EVENT_POLICY_ADDED),
                  "POLICY_ADDED") == 0);
    ASSERT(strcmp(ozayn_mtp_event_type_name(OZAYN_MTP_EVENT_POLICY_REMOVED),
                  "POLICY_REMOVED") == 0);
    ASSERT(strcmp(ozayn_mtp_event_type_name(OZAYN_MTP_EVENT_POLICY_ENABLED),
                  "POLICY_ENABLED") == 0);
    ASSERT(strcmp(ozayn_mtp_event_type_name(OZAYN_MTP_EVENT_POLICY_DISABLED),
                  "POLICY_DISABLED") == 0);
    ASSERT(strcmp(ozayn_mtp_event_type_name(OZAYN_MTP_EVENT_CONFLICT_DETECTED),
                  "CONFLICT_DETECTED") == 0);
    ASSERT(strcmp(ozayn_mtp_event_type_name(OZAYN_MTP_EVENT_TRANSITION_EXECUTING),
                  "TRANSITION_EXECUTING") == 0);
    ASSERT(strcmp(ozayn_mtp_event_type_name(OZAYN_MTP_EVENT_TRANSITION_COMPLETED),
                  "TRANSITION_COMPLETED") == 0);
    ASSERT(strcmp(ozayn_mtp_event_type_name(OZAYN_MTP_EVENT_TRANSITION_FAILED),
                  "TRANSITION_FAILED") == 0);
    ASSERT(strcmp(ozayn_mtp_event_type_name(OZAYN_MTP_EVENT_REQUEST_EXPIRED),
                  "REQUEST_EXPIRED") == 0);
    return 0;
}

/* ============================================================
 * SHUTDOWN STATE TESTS
 * ============================================================ */

TEST(test_ops_after_shutdown) {
    ozayn_mtp_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_mtp_service_init(&svc, NULL);
    ozayn_mtp_service_shutdown(&svc);

    ozayn_mtp_decision_t d;
    ASSERT_EQ(ozayn_mtp_evaluate(&svc, OZAYN_ORD_MODE_READY,
              OZAYN_ORD_MODE_MAINTENANCE, OZAYN_MTP_TRIGGER_ADMINISTRATIVE,
              "test", "user", &d), OZAYN_MTP_ERR_NOT_INITIALIZED);
    ASSERT_EQ(ozayn_mtp_policy_count(&svc), 0);
    ASSERT_EQ(ozayn_mtp_request_count(&svc), 0);
    ASSERT_EQ(ozayn_mtp_decision_count(&svc), 0);
    ASSERT_EQ(ozayn_mtp_event_count(&svc), 0);
    ASSERT(!ozayn_mtp_can_transition(&svc, OZAYN_ORD_MODE_READY,
           OZAYN_ORD_MODE_MAINTENANCE));
    return 0;
}

TEST(test_policy_operations_after_shutdown) {
    ozayn_mtp_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_mtp_service_init(&svc, NULL);
    ozayn_mtp_service_shutdown(&svc);

    ozayn_mtp_policy_t p = _make_policy("p1", OZAYN_ORD_MODE_READY,
                                        OZAYN_ORD_MODE_MAINTENANCE);
    ASSERT_EQ(ozayn_mtp_add_policy(&svc, &p), OZAYN_MTP_ERR_NOT_INITIALIZED);
    ASSERT_EQ(ozayn_mtp_remove_policy(&svc, "p1"), OZAYN_MTP_ERR_NOT_INITIALIZED);
    ASSERT_EQ(ozayn_mtp_enable_policy(&svc, "p1", 1), OZAYN_MTP_ERR_NOT_INITIALIZED);

    ozayn_mtp_policy_t out;
    ASSERT_EQ(ozayn_mtp_get_policy(&svc, "p1", &out), OZAYN_MTP_ERR_NOT_INITIALIZED);
    ASSERT_EQ(ozayn_mtp_get_policy_at(&svc, 0, &out), OZAYN_MTP_ERR_NOT_INITIALIZED);

    ozayn_mtp_event_t e;
    ASSERT_EQ(ozayn_mtp_get_event(&svc, 0, &e), OZAYN_MTP_ERR_NOT_INITIALIZED);
    ASSERT_EQ(ozayn_mtp_reset_stats(&svc), OZAYN_MTP_ERR_NOT_INITIALIZED);
    return 0;
}

/* ============================================================
 * RUNNER
 * ============================================================ */

int run_cr_mode_transition_policy_tests(void) {
    int fail = 0;
    printf("\n  --- CR MODE TRANSITION POLICY ---");
    SUITE_BEGIN("Mode Transition Policy");

    /* Lifecycle */
    RUN(test_mtp_init_null);
    RUN(test_mtp_init_default_config);
    RUN(test_mtp_init_with_config);
    RUN(test_mtp_double_init);
    RUN(test_mtp_shutdown_null);
    RUN(test_mtp_shutdown_not_init);
    RUN(test_mtp_shutdown_normal);
    RUN(test_mtp_global_singleton);

    /* Subsystem binding */
    RUN(test_mtp_set_readiness_null);
    RUN(test_mtp_set_audit_null);
    RUN(test_mtp_set_safety_null);
    RUN(test_mtp_set_resource_null);
    RUN(test_mtp_set_component_null);
    RUN(test_mtp_set_readiness_ok);
    RUN(test_mtp_set_all_subsystems);

    /* Policy management */
    RUN(test_mtp_add_policy_null);
    RUN(test_mtp_add_policy_not_init);
    RUN(test_mtp_add_policy_ok);
    RUN(test_mtp_add_policy_invalid_source);
    RUN(test_mtp_add_policy_invalid_target);
    RUN(test_mtp_add_policy_same_mode);
    RUN(test_mtp_add_policy_invalid_transition);
    RUN(test_mtp_add_policy_duplicate);
    RUN(test_mtp_remove_policy_null);
    RUN(test_mtp_remove_policy_not_found);
    RUN(test_mtp_remove_policy_ok);
    RUN(test_mtp_enable_policy_null);
    RUN(test_mtp_enable_policy_not_found);
    RUN(test_mtp_enable_policy_ok);
    RUN(test_mtp_disable_policy_ok);
    RUN(test_mtp_get_policy_null);
    RUN(test_mtp_get_policy_not_init);
    RUN(test_mtp_get_policy_found);
    RUN(test_mtp_get_policy_at_null);
    RUN(test_mtp_get_policy_at_ok);
    RUN(test_mtp_policy_count_null);
    RUN(test_mtp_policy_count_not_init);
    RUN(test_mtp_policy_count_after_add);
    RUN(test_mtp_add_policy_default_timeout);

    /* Evaluation */
    RUN(test_evaluate_null);
    RUN(test_evaluate_not_init);
    RUN(test_evaluate_null_decision);
    RUN(test_evaluate_invalid_source);
    RUN(test_evaluate_invalid_target);
    RUN(test_evaluate_same_mode);
    RUN(test_evaluate_invalid_matrix_transition);
    RUN(test_evaluate_valid_no_policy);
    RUN(test_evaluate_with_policy_no_subsystems);
    RUN(test_evaluate_with_policy_and_subsystems);
    RUN(test_evaluate_records_request);
    RUN(test_evaluate_records_decision);
    RUN(test_evaluate_multiple);
    RUN(test_evaluate_generates_ids);
    RUN(test_evaluate_safety_required_no_subsystem);
    RUN(test_evaluate_resource_warning);
    RUN(test_evaluate_readiness_warning);

    /* Quick check */
    RUN(test_can_transition_null);
    RUN(test_can_transition_not_init);
    RUN(test_can_transition_invalid);
    RUN(test_can_transition_valid_no_policy);
    RUN(test_can_transition_valid_with_policy);
    RUN(test_can_transition_disabled_policy);

    /* Decision queries */
    RUN(test_get_decision_null);
    RUN(test_get_decision_not_init);
    RUN(test_get_decision_not_found);
    RUN(test_get_latest_decision_empty);
    RUN(test_get_latest_decision_ok);
    RUN(test_decision_count_null);
    RUN(test_decision_count_after_eval);

    /* Request queries */
    RUN(test_get_request_null);
    RUN(test_get_request_not_found);
    RUN(test_request_count_null);
    RUN(test_request_count_after_eval);
    RUN(test_request_default_requester);

    /* Events */
    RUN(test_event_count_null);
    RUN(test_event_count_after_init);
    RUN(test_event_count_after_eval);
    RUN(test_get_event_null);
    RUN(test_get_event_not_init);
    RUN(test_get_event_out_of_range);
    RUN(test_get_event_valid);
    RUN(test_event_sequence_increments);

    /* Stats */
    RUN(test_stats_null);
    RUN(test_stats_initial_zero);
    RUN(test_stats_after_approval);
    RUN(test_stats_after_denial);
    RUN(test_stats_after_deferral);
    RUN(test_reset_stats);
    RUN(test_reset_stats_null);
    RUN(test_stats_conflict_detected);

    /* Name helpers */
    RUN(test_err_name_ok);
    RUN(test_err_name_null);
    RUN(test_err_name_all);
    RUN(test_outcome_name_all);
    RUN(test_phase_name_all);
    RUN(test_trigger_name_all);
    RUN(test_event_type_name_all);

    /* Shutdown state */
    RUN(test_ops_after_shutdown);
    RUN(test_policy_operations_after_shutdown);

    SUITE_END();
    fail = TOTAL_FAIL();
    return fail;
}
