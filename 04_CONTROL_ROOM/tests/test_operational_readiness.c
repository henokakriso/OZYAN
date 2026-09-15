#include "../../tests/test_framework.h"
#include "../operational_readiness.h"
#include <string.h>

static ozayn_ord_service_t _svc;

static void _reset_all(void) {
    memset(&_svc, 0, sizeof(_svc));
}

static void _init_svc(void) {
    _reset_all();
    ozayn_ord_service_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    ozayn_ord_service_init(&_svc, &cfg);
}

static void _init_svc_with_subsystems(void) {
    _reset_all();
    ozayn_ord_service_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    int dummy = 1;
    cfg.component_registry = &dummy;
    cfg.resource_manager = &dummy;
    cfg.device_session = &dummy;
    cfg.safety = &dummy;
    cfg.diagnostics = &dummy;
    cfg.startup_recovery = &dummy;
    cfg.workflow_recovery = &dummy;
    cfg.workflow_checkpoint = &dummy;
    ozayn_ord_service_init(&_svc, &cfg);
}

static void _shutdown_svc(void) {
    ozayn_ord_service_shutdown(&_svc);
    _reset_all();
}

/* ============================================================
 * LIFECYCLE TESTS
 * ============================================================ */

TEST(test_ord_init) {
    _init_svc();
    ASSERT(_svc.initialized);
    ASSERT_EQ(ozayn_ord_get_mode(&_svc), OZAYN_ORD_MODE_UNKNOWN);
    _shutdown_svc();
    return 0;
}

TEST(test_ord_init_null) {
    ASSERT_EQ(ozayn_ord_service_init(NULL, NULL), OZAYN_ORD_ERR_NULL);
    return 0;
}

TEST(test_ord_init_double) {
    _init_svc();
    ASSERT_EQ(ozayn_ord_service_init(&_svc, NULL),
              OZAYN_ORD_ERR_ALREADY_INITIALIZED);
    _shutdown_svc();
    return 0;
}

TEST(test_ord_shutdown) {
    _init_svc();
    ASSERT_EQ(ozayn_ord_service_shutdown(&_svc), OZAYN_ORD_OK);
    ASSERT(!_svc.initialized);
    _reset_all();
    return 0;
}

TEST(test_ord_shutdown_null) {
    ASSERT_EQ(ozayn_ord_service_shutdown(NULL), OZAYN_ORD_ERR_NULL);
    return 0;
}

TEST(test_ord_shutdown_not_init) {
    ozayn_ord_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ASSERT_EQ(ozayn_ord_service_shutdown(&svc), OZAYN_ORD_ERR_NOT_INITIALIZED);
    return 0;
}

TEST(test_ord_global) {
    ASSERT_NOT_NULL(ozayn_ord_get_global());
    return 0;
}

/* ============================================================
 * SUBSYSTEM BINDING TESTS
 * ============================================================ */

TEST(test_ord_set_component_registry) {
    _init_svc();
    int dummy = 1;
    ASSERT_EQ(ozayn_ord_set_component_registry(&_svc, &dummy), OZAYN_ORD_OK);
    ASSERT(_svc.component_registry == &dummy);
    _shutdown_svc();
    return 0;
}

TEST(test_ord_set_component_registry_null) {
    ASSERT_EQ(ozayn_ord_set_component_registry(NULL, NULL), OZAYN_ORD_ERR_NULL);
    return 0;
}

TEST(test_ord_set_resource_manager) {
    _init_svc();
    int dummy = 1;
    ASSERT_EQ(ozayn_ord_set_resource_manager(&_svc, &dummy), OZAYN_ORD_OK);
    ASSERT(_svc.resource_manager == &dummy);
    _shutdown_svc();
    return 0;
}

TEST(test_ord_set_device_session) {
    _init_svc();
    int dummy = 1;
    ASSERT_EQ(ozayn_ord_set_device_session(&_svc, &dummy), OZAYN_ORD_OK);
    _shutdown_svc();
    return 0;
}

TEST(test_ord_set_safety) {
    _init_svc();
    int dummy = 1;
    ASSERT_EQ(ozayn_ord_set_safety(&_svc, &dummy), OZAYN_ORD_OK);
    _shutdown_svc();
    return 0;
}

TEST(test_ord_set_diagnostics) {
    _init_svc();
    int dummy = 1;
    ASSERT_EQ(ozayn_ord_set_diagnostics(&_svc, &dummy), OZAYN_ORD_OK);
    _shutdown_svc();
    return 0;
}

TEST(test_ord_set_startup_recovery) {
    _init_svc();
    int dummy = 1;
    ASSERT_EQ(ozayn_ord_set_startup_recovery(&_svc, &dummy), OZAYN_ORD_OK);
    _shutdown_svc();
    return 0;
}

TEST(test_ord_set_workflow_recovery) {
    _init_svc();
    int dummy = 1;
    ASSERT_EQ(ozayn_ord_set_workflow_recovery(&_svc, &dummy), OZAYN_ORD_OK);
    _shutdown_svc();
    return 0;
}

TEST(test_ord_set_workflow_checkpoint) {
    _init_svc();
    int dummy = 1;
    ASSERT_EQ(ozayn_ord_set_workflow_checkpoint(&_svc, &dummy), OZAYN_ORD_OK);
    _shutdown_svc();
    return 0;
}

/* ============================================================
 * MODE QUERY TESTS
 * ============================================================ */

TEST(test_ord_get_mode) {
    _init_svc();
    ASSERT_EQ(ozayn_ord_get_mode(&_svc), OZAYN_ORD_MODE_UNKNOWN);
    _shutdown_svc();
    return 0;
}

TEST(test_ord_get_mode_null) {
    ASSERT_EQ(ozayn_ord_get_mode(NULL), OZAYN_ORD_MODE_UNKNOWN);
    return 0;
}

TEST(test_ord_get_mode_not_init) {
    ozayn_ord_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ASSERT_EQ(ozayn_ord_get_mode(&svc), OZAYN_ORD_MODE_UNKNOWN);
    return 0;
}

TEST(test_ord_get_previous_mode) {
    _init_svc();
    ASSERT_EQ(ozayn_ord_get_previous_mode(&_svc), OZAYN_ORD_MODE_UNKNOWN);
    _shutdown_svc();
    return 0;
}

TEST(test_ord_is_running_not_running) {
    _init_svc();
    ASSERT(!ozayn_ord_is_running(&_svc));
    _shutdown_svc();
    return 0;
}

TEST(test_ord_is_running_ready) {
    _init_svc();
    ozayn_ord_transition(&_svc, OZAYN_ORD_MODE_INITIALIZING,
                         OZAYN_ORD_TRIGGER_MANUAL, "test", "test");
    ozayn_ord_transition(&_svc, OZAYN_ORD_MODE_READY,
                         OZAYN_ORD_TRIGGER_MANUAL, "test", "test");
    ASSERT(ozayn_ord_is_running(&_svc));
    _shutdown_svc();
    return 0;
}

TEST(test_ord_is_running_degraded) {
    _init_svc();
    ozayn_ord_transition(&_svc, OZAYN_ORD_MODE_INITIALIZING,
                         OZAYN_ORD_TRIGGER_MANUAL, "test", "test");
    ozayn_ord_transition(&_svc, OZAYN_ORD_MODE_READY_DEGRADED,
                         OZAYN_ORD_TRIGGER_MANUAL, "test", "test");
    ASSERT(ozayn_ord_is_running(&_svc));
    _shutdown_svc();
    return 0;
}

TEST(test_ord_is_running_recovery) {
    _init_svc();
    ozayn_ord_transition(&_svc, OZAYN_ORD_MODE_INITIALIZING,
                         OZAYN_ORD_TRIGGER_MANUAL, "test", "test");
    ozayn_ord_transition(&_svc, OZAYN_ORD_MODE_READY,
                         OZAYN_ORD_TRIGGER_MANUAL, "test", "test");
    ozayn_ord_transition(&_svc, OZAYN_ORD_MODE_RECOVERY,
                         OZAYN_ORD_TRIGGER_MANUAL, "test", "test");
    ASSERT(ozayn_ord_is_running(&_svc));
    _shutdown_svc();
    return 0;
}

TEST(test_ord_is_running_maintenance) {
    _init_svc();
    ozayn_ord_transition(&_svc, OZAYN_ORD_MODE_INITIALIZING,
                         OZAYN_ORD_TRIGGER_MANUAL, "test", "test");
    ozayn_ord_transition(&_svc, OZAYN_ORD_MODE_READY,
                         OZAYN_ORD_TRIGGER_MANUAL, "test", "test");
    ozayn_ord_transition(&_svc, OZAYN_ORD_MODE_MAINTENANCE,
                         OZAYN_ORD_TRIGGER_MANUAL, "test", "test");
    ASSERT(ozayn_ord_is_running(&_svc));
    _shutdown_svc();
    return 0;
}

TEST(test_ord_is_not_running_blocked) {
    _init_svc();
    ozayn_ord_transition(&_svc, OZAYN_ORD_MODE_INITIALIZING,
                         OZAYN_ORD_TRIGGER_MANUAL, "test", "test");
    ozayn_ord_transition(&_svc, OZAYN_ORD_MODE_BLOCKED,
                         OZAYN_ORD_TRIGGER_MANUAL, "test", "test");
    ASSERT(!ozayn_ord_is_running(&_svc));
    _shutdown_svc();
    return 0;
}

TEST(test_ord_is_not_running_safe_hold) {
    _init_svc();
    ozayn_ord_transition(&_svc, OZAYN_ORD_MODE_INITIALIZING,
                         OZAYN_ORD_TRIGGER_MANUAL, "test", "test");
    ozayn_ord_transition(&_svc, OZAYN_ORD_MODE_READY,
                         OZAYN_ORD_TRIGGER_MANUAL, "test", "test");
    ozayn_ord_transition(&_svc, OZAYN_ORD_MODE_SAFE_HOLD,
                         OZAYN_ORD_TRIGGER_MANUAL, "test", "test");
    ASSERT(!ozayn_ord_is_running(&_svc));
    _shutdown_svc();
    return 0;
}

/* ============================================================
 * TRANSITION VALIDITY TESTS
 * ============================================================ */

TEST(test_ord_transition_valid_unknown_to_init) {
    ASSERT(ozayn_ord_is_transition_valid(OZAYN_ORD_MODE_UNKNOWN,
                                         OZAYN_ORD_MODE_INITIALIZING));
    return 0;
}

TEST(test_ord_transition_valid_init_to_ready) {
    ASSERT(ozayn_ord_is_transition_valid(OZAYN_ORD_MODE_INITIALIZING,
                                         OZAYN_ORD_MODE_READY));
    return 0;
}

TEST(test_ord_transition_valid_ready_to_degraded) {
    ASSERT(ozayn_ord_is_transition_valid(OZAYN_ORD_MODE_READY,
                                         OZAYN_ORD_MODE_READY_DEGRADED));
    return 0;
}

TEST(test_ord_transition_valid_ready_to_recovery) {
    ASSERT(ozayn_ord_is_transition_valid(OZAYN_ORD_MODE_READY,
                                         OZAYN_ORD_MODE_RECOVERY));
    return 0;
}

TEST(test_ord_transition_valid_ready_to_maintenance) {
    ASSERT(ozayn_ord_is_transition_valid(OZAYN_ORD_MODE_READY,
                                         OZAYN_ORD_MODE_MAINTENANCE));
    return 0;
}

TEST(test_ord_transition_valid_ready_to_safe_hold) {
    ASSERT(ozayn_ord_is_transition_valid(OZAYN_ORD_MODE_READY,
                                         OZAYN_ORD_MODE_SAFE_HOLD));
    return 0;
}

TEST(test_ord_transition_valid_ready_to_shutting_down) {
    ASSERT(ozayn_ord_is_transition_valid(OZAYN_ORD_MODE_READY,
                                         OZAYN_ORD_MODE_SHUTTING_DOWN));
    return 0;
}

TEST(test_ord_transition_valid_ready_to_failed) {
    ASSERT(ozayn_ord_is_transition_valid(OZAYN_ORD_MODE_READY,
                                         OZAYN_ORD_MODE_FAILED));
    return 0;
}

TEST(test_ord_transition_valid_shutting_down_to_none) {
    ASSERT(!ozayn_ord_is_transition_valid(OZAYN_ORD_MODE_SHUTTING_DOWN,
                                          OZAYN_ORD_MODE_READY));
    return 0;
}

TEST(test_ord_transition_valid_degraded_to_ready) {
    ASSERT(ozayn_ord_is_transition_valid(OZAYN_ORD_MODE_READY_DEGRADED,
                                         OZAYN_ORD_MODE_READY));
    return 0;
}

TEST(test_ord_transition_valid_safe_hold_to_recovery) {
    ASSERT(ozayn_ord_is_transition_valid(OZAYN_ORD_MODE_SAFE_HOLD,
                                         OZAYN_ORD_MODE_RECOVERY));
    return 0;
}

TEST(test_ord_transition_valid_failed_to_recovery) {
    ASSERT(ozayn_ord_is_transition_valid(OZAYN_ORD_MODE_FAILED,
                                         OZAYN_ORD_MODE_RECOVERY));
    return 0;
}

TEST(test_ord_transition_valid_blocked_to_ready) {
    ASSERT(ozayn_ord_is_transition_valid(OZAYN_ORD_MODE_BLOCKED,
                                         OZAYN_ORD_MODE_READY));
    return 0;
}

TEST(test_ord_transition_invalid_unknown_to_ready) {
    ASSERT(!ozayn_ord_is_transition_valid(OZAYN_ORD_MODE_UNKNOWN,
                                          OZAYN_ORD_MODE_READY));
    return 0;
}

TEST(test_ord_transition_invalid_ready_to_unknown) {
    ASSERT(!ozayn_ord_is_transition_valid(OZAYN_ORD_MODE_READY,
                                          OZAYN_ORD_MODE_UNKNOWN));
    return 0;
}

TEST(test_ord_transition_invalid_out_of_range) {
    ASSERT(!ozayn_ord_is_transition_valid(-1, OZAYN_ORD_MODE_READY));
    ASSERT(!ozayn_ord_is_transition_valid(OZAYN_ORD_MODE_READY, 99));
    return 0;
}

/* ============================================================
 * MODE TRANSITION TESTS
 * ============================================================ */

TEST(test_ord_transition_null) {
    ASSERT_EQ(ozayn_ord_transition(NULL, OZAYN_ORD_MODE_READY,
              OZAYN_ORD_TRIGGER_MANUAL, "test", "test"),
              OZAYN_ORD_ERR_NULL);
    return 0;
}

TEST(test_ord_transition_not_init) {
    ozayn_ord_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ASSERT_EQ(ozayn_ord_transition(&svc, OZAYN_ORD_MODE_READY,
              OZAYN_ORD_TRIGGER_MANUAL, "test", "test"),
              OZAYN_ORD_ERR_NOT_INITIALIZED);
    return 0;
}

TEST(test_ord_transition_invalid) {
    _init_svc();
    ASSERT_EQ(ozayn_ord_transition(&_svc, OZAYN_ORD_MODE_READY,
              OZAYN_ORD_TRIGGER_MANUAL, "test", "test"),
              OZAYN_ORD_ERR_MODE_TRANSITION_INVALID);
    _shutdown_svc();
    return 0;
}

TEST(test_ord_transition_unknown_to_init) {
    _init_svc();
    ASSERT_EQ(ozayn_ord_transition(&_svc, OZAYN_ORD_MODE_INITIALIZING,
              OZAYN_ORD_TRIGGER_MANUAL, "Startup", "test"), OZAYN_ORD_OK);
    ASSERT_EQ(ozayn_ord_get_mode(&_svc), OZAYN_ORD_MODE_INITIALIZING);
    ASSERT_EQ(ozayn_ord_get_previous_mode(&_svc), OZAYN_ORD_MODE_UNKNOWN);
    _shutdown_svc();
    return 0;
}

TEST(test_ord_transition_init_to_ready) {
    _init_svc();
    ozayn_ord_transition(&_svc, OZAYN_ORD_MODE_INITIALIZING,
                         OZAYN_ORD_TRIGGER_MANUAL, "test", "test");
    ASSERT_EQ(ozayn_ord_transition(&_svc, OZAYN_ORD_MODE_READY,
              OZAYN_ORD_TRIGGER_MANUAL, "Ready", "test"), OZAYN_ORD_OK);
    ASSERT_EQ(ozayn_ord_get_mode(&_svc), OZAYN_ORD_MODE_READY);
    _shutdown_svc();
    return 0;
}

TEST(test_ord_transition_full_path) {
    _init_svc();
    ASSERT_EQ(ozayn_ord_transition(&_svc, OZAYN_ORD_MODE_INITIALIZING,
              OZAYN_ORD_TRIGGER_STARTUP, "startup", "src"), OZAYN_ORD_OK);
    ASSERT_EQ(ozayn_ord_transition(&_svc, OZAYN_ORD_MODE_READY,
              OZAYN_ORD_TRIGGER_ASSESSMENT, "ready", "ord"), OZAYN_ORD_OK);
    ASSERT_EQ(ozayn_ord_transition_force(&_svc, OZAYN_ORD_MODE_READY_DEGRADED,
              OZAYN_ORD_TRIGGER_EVENT, "degraded", "ord"), OZAYN_ORD_OK);
    ASSERT_EQ(ozayn_ord_transition_force(&_svc, OZAYN_ORD_MODE_READY,
              OZAYN_ORD_TRIGGER_RECOVERY, "recovered", "ord"), OZAYN_ORD_OK);
    ASSERT_EQ(ozayn_ord_transition_force(&_svc, OZAYN_ORD_MODE_MAINTENANCE,
              OZAYN_ORD_TRIGGER_MANUAL, "maintenance", "admin"), OZAYN_ORD_OK);
    ASSERT_EQ(ozayn_ord_transition_force(&_svc, OZAYN_ORD_MODE_READY,
              OZAYN_ORD_TRIGGER_MANUAL, "done", "admin"), OZAYN_ORD_OK);
    ASSERT_EQ(ozayn_ord_transition(&_svc, OZAYN_ORD_MODE_SHUTTING_DOWN,
              OZAYN_ORD_TRIGGER_SHUTDOWN, "shutdown", "sys"), OZAYN_ORD_OK);
    ASSERT_EQ(ozayn_ord_get_mode(&_svc), OZAYN_ORD_MODE_SHUTTING_DOWN);
    _shutdown_svc();
    return 0;
}

TEST(test_ord_transition_to_safe_hold) {
    _init_svc();
    ozayn_ord_transition(&_svc, OZAYN_ORD_MODE_INITIALIZING,
                         OZAYN_ORD_TRIGGER_MANUAL, "test", "test");
    ozayn_ord_transition(&_svc, OZAYN_ORD_MODE_READY,
                         OZAYN_ORD_TRIGGER_MANUAL, "test", "test");
    ASSERT_EQ(ozayn_ord_transition(&_svc, OZAYN_ORD_MODE_SAFE_HOLD,
              OZAYN_ORD_TRIGGER_SAFETY, "safety issue", "safety"), OZAYN_ORD_OK);
    ASSERT_EQ(ozayn_ord_get_mode(&_svc), OZAYN_ORD_MODE_SAFE_HOLD);
    _shutdown_svc();
    return 0;
}

TEST(test_ord_transition_to_blocked) {
    _init_svc();
    ozayn_ord_transition(&_svc, OZAYN_ORD_MODE_INITIALIZING,
                         OZAYN_ORD_TRIGGER_MANUAL, "test", "test");
    ozayn_ord_transition(&_svc, OZAYN_ORD_MODE_READY,
                         OZAYN_ORD_TRIGGER_MANUAL, "test", "test");
    ASSERT_EQ(ozayn_ord_transition(&_svc, OZAYN_ORD_MODE_BLOCKED,
              OZAYN_ORD_TRIGGER_RESOURCE, "resource issue", "rcm"), OZAYN_ORD_OK);
    ASSERT_EQ(ozayn_ord_get_mode(&_svc), OZAYN_ORD_MODE_BLOCKED);
    _shutdown_svc();
    return 0;
}

TEST(test_ord_transition_to_recovery) {
    _init_svc();
    ozayn_ord_transition(&_svc, OZAYN_ORD_MODE_INITIALIZING,
                         OZAYN_ORD_TRIGGER_MANUAL, "test", "test");
    ozayn_ord_transition(&_svc, OZAYN_ORD_MODE_READY,
                         OZAYN_ORD_TRIGGER_MANUAL, "test", "test");
    ASSERT_EQ(ozayn_ord_transition(&_svc, OZAYN_ORD_MODE_RECOVERY,
              OZAYN_ORD_TRIGGER_RECOVERY, "recovery", "wfr"), OZAYN_ORD_OK);
    ASSERT_EQ(ozayn_ord_get_mode(&_svc), OZAYN_ORD_MODE_RECOVERY);
    _shutdown_svc();
    return 0;
}

TEST(test_ord_transition_to_failed) {
    _init_svc();
    ozayn_ord_transition(&_svc, OZAYN_ORD_MODE_INITIALIZING,
                         OZAYN_ORD_TRIGGER_MANUAL, "test", "test");
    ozayn_ord_transition(&_svc, OZAYN_ORD_MODE_READY,
                         OZAYN_ORD_TRIGGER_MANUAL, "test", "test");
    ASSERT_EQ(ozayn_ord_transition(&_svc, OZAYN_ORD_MODE_FAILED,
              OZAYN_ORD_TRIGGER_FAILURE, "critical", "sys"), OZAYN_ORD_OK);
    ASSERT_EQ(ozayn_ord_get_mode(&_svc), OZAYN_ORD_MODE_FAILED);
    _shutdown_svc();
    return 0;
}

TEST(test_ord_transition_reject_shutting_down) {
    _init_svc();
    ozayn_ord_transition(&_svc, OZAYN_ORD_MODE_INITIALIZING,
                         OZAYN_ORD_TRIGGER_MANUAL, "test", "test");
    ozayn_ord_transition(&_svc, OZAYN_ORD_MODE_SHUTTING_DOWN,
                         OZAYN_ORD_TRIGGER_SHUTDOWN, "test", "test");
    ASSERT_EQ(ozayn_ord_transition(&_svc, OZAYN_ORD_MODE_READY,
              OZAYN_ORD_TRIGGER_MANUAL, "test", "test"),
              OZAYN_ORD_ERR_MODE_TRANSITION_INVALID);
    _shutdown_svc();
    return 0;
}

TEST(test_ord_transition_force) {
    _init_svc();
    ozayn_ord_transition(&_svc, OZAYN_ORD_MODE_INITIALIZING,
                         OZAYN_ORD_TRIGGER_MANUAL, "test", "test");
    ozayn_ord_transition(&_svc, OZAYN_ORD_MODE_READY,
                         OZAYN_ORD_TRIGGER_MANUAL, "test", "test");
    ASSERT_EQ(ozayn_ord_transition_force(&_svc, OZAYN_ORD_MODE_SAFE_HOLD,
              OZAYN_ORD_TRIGGER_SAFETY, "force", "safety"), OZAYN_ORD_OK);
    ASSERT_EQ(ozayn_ord_get_mode(&_svc), OZAYN_ORD_MODE_SAFE_HOLD);
    _shutdown_svc();
    return 0;
}

TEST(test_ord_transition_count) {
    _init_svc();
    ASSERT_EQ(ozayn_ord_transition_count(&_svc), 0);
    ozayn_ord_transition(&_svc, OZAYN_ORD_MODE_INITIALIZING,
                         OZAYN_ORD_TRIGGER_MANUAL, "test", "test");
    ASSERT_EQ(ozayn_ord_transition_count(&_svc), 1);
    ozayn_ord_transition(&_svc, OZAYN_ORD_MODE_READY,
                         OZAYN_ORD_TRIGGER_MANUAL, "test", "test");
    ASSERT_EQ(ozayn_ord_transition_count(&_svc), 2);
    _shutdown_svc();
    return 0;
}

TEST(test_ord_get_latest_transition) {
    _init_svc();
    ozayn_ord_transition_t t;
    ASSERT_EQ(ozayn_ord_get_latest_transition(&_svc, &t),
              OZAYN_ORD_ERR_NOT_FOUND);
    ozayn_ord_transition(&_svc, OZAYN_ORD_MODE_INITIALIZING,
                         OZAYN_ORD_TRIGGER_MANUAL, "test", "test");
    ASSERT_EQ(ozayn_ord_get_latest_transition(&_svc, &t), OZAYN_ORD_OK);
    ASSERT_EQ(t.previous_mode, OZAYN_ORD_MODE_UNKNOWN);
    ASSERT_EQ(t.final_mode, OZAYN_ORD_MODE_INITIALIZING);
    _shutdown_svc();
    return 0;
}

TEST(test_ord_get_latest_transition_null) {
    ASSERT_EQ(ozayn_ord_get_latest_transition(NULL, NULL),
              OZAYN_ORD_ERR_NULL);
    return 0;
}

/* ============================================================
 * READINESS ASSESSMENT TESTS
 * ============================================================ */

TEST(test_ord_assess_null) {
    ASSERT_EQ(ozayn_ord_assess(NULL, NULL), OZAYN_ORD_ERR_NULL);
    return 0;
}

TEST(test_ord_assess_not_init) {
    ozayn_ord_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_ord_assessment_t a;
    ASSERT_EQ(ozayn_ord_assess(&svc, &a), OZAYN_ORD_ERR_NOT_INITIALIZED);
    return 0;
}

TEST(test_ord_assess) {
    _init_svc();
    ozayn_ord_assessment_t a;
    ASSERT_EQ(ozayn_ord_assess(&_svc, &a), OZAYN_ORD_OK);
    ASSERT(a.active);
    ASSERT_EQ(a.current_mode, OZAYN_ORD_MODE_UNKNOWN);
    ASSERT(a.condition_count > 0);
    _shutdown_svc();
    return 0;
}

TEST(test_ord_assess_no_subsystems) {
    _init_svc();
    ozayn_ord_assessment_t a;
    ozayn_ord_assess(&_svc, &a);
    /* Without subsystems, should recommend READY (all conditions OK) */
    ASSERT_EQ(a.recommended_mode, OZAYN_ORD_MODE_READY);
    ASSERT_EQ(a.decision, OZAYN_ORD_ASSESS_MAINTAIN_MODE);
    _shutdown_svc();
    return 0;
}

TEST(test_ord_assess_with_subsystems) {
    _init_svc_with_subsystems();
    ozayn_ord_assessment_t a;
    ozayn_ord_assess(&_svc, &a);
    ASSERT_EQ(a.recommended_mode, OZAYN_ORD_MODE_READY);
    ASSERT_EQ(a.decision, OZAYN_ORD_ASSESS_MAINTAIN_MODE);
    _shutdown_svc();
    return 0;
}

TEST(test_ord_assess_with_blocking) {
    _init_svc();
    ozayn_ord_add_blocking(&_svc, "Critical issue");
    ozayn_ord_assessment_t a;
    ozayn_ord_assess(&_svc, &a);
    ASSERT_EQ(a.recommended_mode, OZAYN_ORD_MODE_BLOCKED);
    ASSERT_EQ(a.decision, OZAYN_ORD_ASSESS_TRANSITION_REQUIRED);
    _shutdown_svc();
    return 0;
}

TEST(test_ord_assess_count) {
    _init_svc();
    ASSERT_EQ(ozayn_ord_assessment_count(&_svc), 0);
    ozayn_ord_assessment_t a;
    ozayn_ord_assess(&_svc, &a);
    ASSERT_EQ(ozayn_ord_assessment_count(&_svc), 1);
    _shutdown_svc();
    return 0;
}

TEST(test_ord_get_latest_assessment) {
    _init_svc();
    ozayn_ord_assessment_t a;
    ASSERT_EQ(ozayn_ord_get_latest_assessment(&_svc, &a),
              OZAYN_ORD_ERR_NOT_FOUND);
    ozayn_ord_assess(&_svc, &a);
    ASSERT_EQ(ozayn_ord_get_latest_assessment(&_svc, &a), OZAYN_ORD_OK);
    ASSERT(a.active);
    _shutdown_svc();
    return 0;
}

TEST(test_ord_assess_concurrency) {
    _init_svc();
    _svc.assessment_in_progress = 1;
    ozayn_ord_assessment_t a;
    ASSERT_EQ(ozayn_ord_assess(&_svc, &a), OZAYN_ORD_ERR_CONCURRENCY_ERROR);
    _shutdown_svc();
    return 0;
}

/* ============================================================
 * OPERATION GATING TESTS
 * ============================================================ */

TEST(test_ord_check_operation_null) {
    ASSERT_EQ(ozayn_ord_check_operation(NULL, OZAYN_ORD_OPCLASS_NORMAL),
              OZAYN_ORD_GATE_UNAVAILABLE);
    return 0;
}

TEST(test_ord_check_operation_unknown_mode) {
    _init_svc();
    ASSERT_EQ(ozayn_ord_check_operation(&_svc, OZAYN_ORD_OPCLASS_NORMAL),
              OZAYN_ORD_GATE_UNAVAILABLE);
    _shutdown_svc();
    return 0;
}

TEST(test_ord_check_operation_ready_normal) {
    _init_svc();
    ozayn_ord_transition(&_svc, OZAYN_ORD_MODE_INITIALIZING,
                         OZAYN_ORD_TRIGGER_MANUAL, "test", "test");
    ozayn_ord_transition(&_svc, OZAYN_ORD_MODE_READY,
                         OZAYN_ORD_TRIGGER_MANUAL, "test", "test");
    ASSERT_EQ(ozayn_ord_check_operation(&_svc, OZAYN_ORD_OPCLASS_NORMAL),
              OZAYN_ORD_GATE_ALLOWED);
    _shutdown_svc();
    return 0;
}

TEST(test_ord_check_operation_ready_diagnostic) {
    _init_svc();
    ozayn_ord_transition(&_svc, OZAYN_ORD_MODE_INITIALIZING,
                         OZAYN_ORD_TRIGGER_MANUAL, "test", "test");
    ozayn_ord_transition(&_svc, OZAYN_ORD_MODE_READY,
                         OZAYN_ORD_TRIGGER_MANUAL, "test", "test");
    ASSERT_EQ(ozayn_ord_check_operation(&_svc, OZAYN_ORD_OPCLASS_DIAGNOSTIC),
              OZAYN_ORD_GATE_ALLOWED);
    _shutdown_svc();
    return 0;
}

TEST(test_ord_check_operation_degraded_normal) {
    _init_svc();
    ozayn_ord_transition(&_svc, OZAYN_ORD_MODE_INITIALIZING,
                         OZAYN_ORD_TRIGGER_MANUAL, "test", "test");
    ozayn_ord_transition(&_svc, OZAYN_ORD_MODE_READY_DEGRADED,
                         OZAYN_ORD_TRIGGER_MANUAL, "test", "test");
    ASSERT_EQ(ozayn_ord_check_operation(&_svc, OZAYN_ORD_OPCLASS_NORMAL),
              OZAYN_ORD_GATE_RESTRICTED);
    _shutdown_svc();
    return 0;
}

TEST(test_ord_check_operation_degraded_diagnostic) {
    _init_svc();
    ozayn_ord_transition(&_svc, OZAYN_ORD_MODE_INITIALIZING,
                         OZAYN_ORD_TRIGGER_MANUAL, "test", "test");
    ozayn_ord_transition(&_svc, OZAYN_ORD_MODE_READY_DEGRADED,
                         OZAYN_ORD_TRIGGER_MANUAL, "test", "test");
    ASSERT_EQ(ozayn_ord_check_operation(&_svc, OZAYN_ORD_OPCLASS_DIAGNOSTIC),
              OZAYN_ORD_GATE_ALLOWED);
    _shutdown_svc();
    return 0;
}

TEST(test_ord_check_operation_safe_hold_normal) {
    _init_svc();
    ozayn_ord_transition(&_svc, OZAYN_ORD_MODE_INITIALIZING,
                         OZAYN_ORD_TRIGGER_MANUAL, "test", "test");
    ozayn_ord_transition(&_svc, OZAYN_ORD_MODE_READY,
                         OZAYN_ORD_TRIGGER_MANUAL, "test", "test");
    ozayn_ord_transition(&_svc, OZAYN_ORD_MODE_SAFE_HOLD,
                         OZAYN_ORD_TRIGGER_MANUAL, "test", "test");
    ASSERT_EQ(ozayn_ord_check_operation(&_svc, OZAYN_ORD_OPCLASS_NORMAL),
              OZAYN_ORD_GATE_BLOCKED);
    _shutdown_svc();
    return 0;
}

TEST(test_ord_check_operation_safe_hold_diagnostic) {
    _init_svc();
    ozayn_ord_transition(&_svc, OZAYN_ORD_MODE_INITIALIZING,
                         OZAYN_ORD_TRIGGER_MANUAL, "test", "test");
    ozayn_ord_transition(&_svc, OZAYN_ORD_MODE_READY,
                         OZAYN_ORD_TRIGGER_MANUAL, "test", "test");
    ozayn_ord_transition(&_svc, OZAYN_ORD_MODE_SAFE_HOLD,
                         OZAYN_ORD_TRIGGER_MANUAL, "test", "test");
    ASSERT_EQ(ozayn_ord_check_operation(&_svc, OZAYN_ORD_OPCLASS_DIAGNOSTIC),
              OZAYN_ORD_GATE_ALLOWED);
    _shutdown_svc();
    return 0;
}

TEST(test_ord_check_operation_blocked_normal) {
    _init_svc();
    ozayn_ord_transition(&_svc, OZAYN_ORD_MODE_INITIALIZING,
                         OZAYN_ORD_TRIGGER_MANUAL, "test", "test");
    ozayn_ord_transition(&_svc, OZAYN_ORD_MODE_BLOCKED,
                         OZAYN_ORD_TRIGGER_MANUAL, "test", "test");
    ASSERT_EQ(ozayn_ord_check_operation(&_svc, OZAYN_ORD_OPCLASS_NORMAL),
              OZAYN_ORD_GATE_BLOCKED);
    _shutdown_svc();
    return 0;
}

TEST(test_ord_check_operation_maintenance_maintenance) {
    _init_svc();
    ozayn_ord_transition(&_svc, OZAYN_ORD_MODE_INITIALIZING,
                         OZAYN_ORD_TRIGGER_MANUAL, "test", "test");
    ozayn_ord_transition(&_svc, OZAYN_ORD_MODE_READY,
                         OZAYN_ORD_TRIGGER_MANUAL, "test", "test");
    ozayn_ord_transition(&_svc, OZAYN_ORD_MODE_MAINTENANCE,
                         OZAYN_ORD_TRIGGER_MANUAL, "test", "test");
    ASSERT_EQ(ozayn_ord_check_operation(&_svc, OZAYN_ORD_OPCLASS_MAINTENANCE),
              OZAYN_ORD_GATE_ALLOWED);
    _shutdown_svc();
    return 0;
}

TEST(test_ord_check_operation_maintenance_normal) {
    _init_svc();
    ozayn_ord_transition(&_svc, OZAYN_ORD_MODE_INITIALIZING,
                         OZAYN_ORD_TRIGGER_MANUAL, "test", "test");
    ozayn_ord_transition(&_svc, OZAYN_ORD_MODE_READY,
                         OZAYN_ORD_TRIGGER_MANUAL, "test", "test");
    ozayn_ord_transition(&_svc, OZAYN_ORD_MODE_MAINTENANCE,
                         OZAYN_ORD_TRIGGER_MANUAL, "test", "test");
    ASSERT_EQ(ozayn_ord_check_operation(&_svc, OZAYN_ORD_OPCLASS_NORMAL),
              OZAYN_ORD_GATE_RESTRICTED);
    _shutdown_svc();
    return 0;
}

TEST(test_ord_check_operation_shutting_down_normal) {
    _init_svc();
    ozayn_ord_transition(&_svc, OZAYN_ORD_MODE_INITIALIZING,
                         OZAYN_ORD_TRIGGER_MANUAL, "test", "test");
    ozayn_ord_transition(&_svc, OZAYN_ORD_MODE_SHUTTING_DOWN,
                         OZAYN_ORD_TRIGGER_MANUAL, "test", "test");
    ASSERT_EQ(ozayn_ord_check_operation(&_svc, OZAYN_ORD_OPCLASS_NORMAL),
              OZAYN_ORD_GATE_BLOCKED);
    _shutdown_svc();
    return 0;
}

TEST(test_ord_check_operation_shutting_down_shutdown) {
    _init_svc();
    ozayn_ord_transition(&_svc, OZAYN_ORD_MODE_INITIALIZING,
                         OZAYN_ORD_TRIGGER_MANUAL, "test", "test");
    ozayn_ord_transition(&_svc, OZAYN_ORD_MODE_SHUTTING_DOWN,
                         OZAYN_ORD_TRIGGER_MANUAL, "test", "test");
    ASSERT_EQ(ozayn_ord_check_operation(&_svc, OZAYN_ORD_OPCLASS_SHUTDOWN),
              OZAYN_ORD_GATE_ALLOWED);
    _shutdown_svc();
    return 0;
}

TEST(test_ord_check_operation_failed_recovery) {
    _init_svc();
    ozayn_ord_transition(&_svc, OZAYN_ORD_MODE_INITIALIZING,
                         OZAYN_ORD_TRIGGER_MANUAL, "test", "test");
    ozayn_ord_transition(&_svc, OZAYN_ORD_MODE_FAILED,
                         OZAYN_ORD_TRIGGER_MANUAL, "test", "test");
    ASSERT_EQ(ozayn_ord_check_operation(&_svc, OZAYN_ORD_OPCLASS_RECOVERY),
              OZAYN_ORD_GATE_ALLOWED);
    _shutdown_svc();
    return 0;
}

TEST(test_ord_check_operation_invalid_opclass) {
    _init_svc();
    ozayn_ord_transition(&_svc, OZAYN_ORD_MODE_INITIALIZING,
                         OZAYN_ORD_TRIGGER_MANUAL, "test", "test");
    ozayn_ord_transition(&_svc, OZAYN_ORD_MODE_READY,
                         OZAYN_ORD_TRIGGER_MANUAL, "test", "test");
    ASSERT_EQ(ozayn_ord_check_operation(&_svc, -1),
              OZAYN_ORD_GATE_UNAVAILABLE);
    ASSERT_EQ(ozayn_ord_check_operation(&_svc, OZAYN_ORD_OPCLASS_COUNT),
              OZAYN_ORD_GATE_UNAVAILABLE);
    _shutdown_svc();
    return 0;
}

TEST(test_ord_gate_operation) {
    _init_svc();
    ozayn_ord_transition(&_svc, OZAYN_ORD_MODE_INITIALIZING,
                         OZAYN_ORD_TRIGGER_MANUAL, "test", "test");
    ozayn_ord_transition(&_svc, OZAYN_ORD_MODE_READY,
                         OZAYN_ORD_TRIGGER_MANUAL, "test", "test");
    ASSERT_EQ(ozayn_ord_gate_operation(&_svc, OZAYN_ORD_OPCLASS_NORMAL,
              "op-001"), OZAYN_ORD_OK);
    _shutdown_svc();
    return 0;
}

TEST(test_ord_gate_operation_blocked) {
    _init_svc();
    ozayn_ord_transition(&_svc, OZAYN_ORD_MODE_INITIALIZING,
                         OZAYN_ORD_TRIGGER_MANUAL, "test", "test");
    ozayn_ord_transition(&_svc, OZAYN_ORD_MODE_SAFE_HOLD,
                         OZAYN_ORD_TRIGGER_MANUAL, "test", "test");
    ASSERT_EQ(ozayn_ord_gate_operation(&_svc, OZAYN_ORD_OPCLASS_NORMAL,
              "op-002"), OZAYN_ORD_ERR_OPERATION_GATED);
    _shutdown_svc();
    return 0;
}

TEST(test_ord_gate_operation_null) {
    ASSERT_EQ(ozayn_ord_gate_operation(NULL, OZAYN_ORD_OPCLASS_NORMAL,
              "op"), OZAYN_ORD_ERR_NULL);
    return 0;
}

/* ============================================================
 * BLOCKING AND WARNING TESTS
 * ============================================================ */

TEST(test_ord_add_blocking) {
    _init_svc();
    ASSERT_EQ(ozayn_ord_add_blocking(&_svc, "Critical issue"),
              OZAYN_ORD_OK);
    ASSERT_EQ(_svc.blocking_count, 1);
    _shutdown_svc();
    return 0;
}

TEST(test_ord_add_blocking_null) {
    ASSERT_EQ(ozayn_ord_add_blocking(NULL, "x"), OZAYN_ORD_ERR_NULL);
    return 0;
}

TEST(test_ord_add_blocking_null_desc) {
    _init_svc();
    ASSERT_EQ(ozayn_ord_add_blocking(&_svc, NULL),
              OZAYN_ORD_ERR_INVALID_PARAM);
    _shutdown_svc();
    return 0;
}

TEST(test_ord_add_blocking_limit) {
    _init_svc();
    for (int i = 0; i < OZAYN_ORD_MAX_BLOCKING; i++)
        ozayn_ord_add_blocking(&_svc, "block");
    ASSERT_EQ(ozayn_ord_add_blocking(&_svc, "overflow"),
              OZAYN_ORD_ERR_LIMIT_REACHED);
    _shutdown_svc();
    return 0;
}

TEST(test_ord_blocking_count) {
    _init_svc();
    ASSERT_EQ(ozayn_ord_blocking_count(&_svc), 0);
    ozayn_ord_add_blocking(&_svc, "block1");
    ASSERT_EQ(ozayn_ord_blocking_count(&_svc), 1);
    ozayn_ord_add_blocking(&_svc, "block2");
    ASSERT_EQ(ozayn_ord_blocking_count(&_svc), 2);
    _shutdown_svc();
    return 0;
}

TEST(test_ord_add_warning) {
    _init_svc();
    ASSERT_EQ(ozayn_ord_add_warning(&_svc, "Minor issue"), OZAYN_ORD_OK);
    ASSERT_EQ(_svc.warning_count, 1);
    _shutdown_svc();
    return 0;
}

TEST(test_ord_add_warning_null) {
    ASSERT_EQ(ozayn_ord_add_warning(NULL, "x"), OZAYN_ORD_ERR_NULL);
    return 0;
}

TEST(test_ord_add_warning_null_desc) {
    _init_svc();
    ASSERT_EQ(ozayn_ord_add_warning(&_svc, NULL),
              OZAYN_ORD_ERR_INVALID_PARAM);
    _shutdown_svc();
    return 0;
}

TEST(test_ord_add_warning_limit) {
    _init_svc();
    for (int i = 0; i < OZAYN_ORD_MAX_WARNINGS; i++)
        ozayn_ord_add_warning(&_svc, "warn");
    ASSERT_EQ(ozayn_ord_add_warning(&_svc, "overflow"),
              OZAYN_ORD_ERR_LIMIT_REACHED);
    _shutdown_svc();
    return 0;
}

TEST(test_ord_warning_count) {
    _init_svc();
    ASSERT_EQ(ozayn_ord_warning_count(&_svc), 0);
    ozayn_ord_add_warning(&_svc, "w1");
    ASSERT_EQ(ozayn_ord_warning_count(&_svc), 1);
    _shutdown_svc();
    return 0;
}

/* ============================================================
 * EVENT TESTS
 * ============================================================ */

TEST(test_ord_emit_event) {
    _init_svc();
    int before = _svc.event_count;
    ASSERT_EQ(ozayn_ord_emit_event(&_svc, OZAYN_ORD_EVENT_MODE_CHANGED,
              "test", "test event"), OZAYN_ORD_OK);
    ASSERT_EQ(_svc.event_count, before + 1);
    _shutdown_svc();
    return 0;
}

TEST(test_ord_emit_event_null) {
    ASSERT_EQ(ozayn_ord_emit_event(NULL, OZAYN_ORD_EVENT_MODE_CHANGED,
              "test", "test"), OZAYN_ORD_ERR_NULL);
    return 0;
}

TEST(test_ord_emit_event_null_msg) {
    _init_svc();
    ASSERT_EQ(ozayn_ord_emit_event(&_svc, OZAYN_ORD_EVENT_MODE_CHANGED,
              "test", NULL), OZAYN_ORD_ERR_INVALID_PARAM);
    _shutdown_svc();
    return 0;
}

TEST(test_ord_emit_event_not_init) {
    ozayn_ord_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ASSERT_EQ(ozayn_ord_emit_event(&svc, OZAYN_ORD_EVENT_MODE_CHANGED,
              "test", "test"), OZAYN_ORD_ERR_NOT_INITIALIZED);
    return 0;
}

TEST(test_ord_event_ring_buffer) {
    _init_svc();
    for (int i = 0; i < OZAYN_ORD_MAX_EVENTS + 10; i++)
        ozayn_ord_emit_event(&_svc, OZAYN_ORD_EVENT_MODE_CHANGED,
                             "test", "test");
    ASSERT_EQ(_svc.event_count, OZAYN_ORD_MAX_EVENTS);
    _shutdown_svc();
    return 0;
}

TEST(test_ord_get_event) {
    _init_svc();
    ozayn_ord_event_t ev;
    int before = _svc.event_count;
    ASSERT_EQ(ozayn_ord_get_event(&_svc, 0, &ev), OZAYN_ORD_OK);
    ASSERT(ev.type < OZAYN_ORD_EVENT_COUNT);
    _shutdown_svc();
    return 0;
}

TEST(test_ord_get_event_invalid_index) {
    _init_svc();
    ozayn_ord_event_t ev;
    int total = _svc.event_count;
    ASSERT_EQ(ozayn_ord_get_event(&_svc, -1, &ev), OZAYN_ORD_ERR_NOT_FOUND);
    ASSERT_EQ(ozayn_ord_get_event(&_svc, total, &ev), OZAYN_ORD_ERR_NOT_FOUND);
    _shutdown_svc();
    return 0;
}

TEST(test_ord_event_count) {
    _init_svc();
    int before = _svc.event_count;
    ozayn_ord_emit_event(&_svc, OZAYN_ORD_EVENT_MODE_CHANGED,
                         "test", "test");
    ASSERT_EQ(_svc.event_count, before + 1);
    _shutdown_svc();
    return 0;
}

TEST(test_ord_transition_emits_events) {
    _init_svc();
    int before = _svc.event_count;
    ozayn_ord_transition(&_svc, OZAYN_ORD_MODE_INITIALIZING,
                         OZAYN_ORD_TRIGGER_MANUAL, "test", "test");
    ASSERT(_svc.event_count > before);
    _shutdown_svc();
    return 0;
}

/* ============================================================
 * STATS TESTS
 * ============================================================ */

TEST(test_ord_stats) {
    _init_svc();
    const ozayn_ord_stats_t *stats = ozayn_ord_get_stats(&_svc);
    ASSERT_NOT_NULL(stats);
    ASSERT_EQ(stats->total_assessments, 0);
    ASSERT_EQ(stats->total_transitions, 0);
    _shutdown_svc();
    return 0;
}

TEST(test_ord_stats_null) {
    ASSERT_NULL(ozayn_ord_get_stats(NULL));
    return 0;
}

TEST(test_ord_reset_stats) {
    _init_svc();
    ozayn_ord_assessment_t a;
    ozayn_ord_assess(&_svc, &a);
    ASSERT(_svc.stats.total_assessments > 0);
    ASSERT_EQ(ozayn_ord_reset_stats(&_svc), OZAYN_ORD_OK);
    ASSERT_EQ(_svc.stats.total_assessments, 0);
    _shutdown_svc();
    return 0;
}

TEST(test_ord_stats_transitions) {
    _init_svc();
    ozayn_ord_transition(&_svc, OZAYN_ORD_MODE_INITIALIZING,
                         OZAYN_ORD_TRIGGER_MANUAL, "test", "test");
    ASSERT_EQ(_svc.stats.total_transitions, 1);
    ozayn_ord_transition(&_svc, OZAYN_ORD_MODE_READY,
                         OZAYN_ORD_TRIGGER_MANUAL, "test", "test");
    ASSERT_EQ(_svc.stats.total_transitions, 2);
    _shutdown_svc();
    return 0;
}

TEST(test_ord_stats_gating) {
    _init_svc();
    ozayn_ord_transition(&_svc, OZAYN_ORD_MODE_INITIALIZING,
                         OZAYN_ORD_TRIGGER_MANUAL, "test", "test");
    ozayn_ord_transition(&_svc, OZAYN_ORD_MODE_READY,
                         OZAYN_ORD_TRIGGER_MANUAL, "test", "test");
    ozayn_ord_gate_operation(&_svc, OZAYN_ORD_OPCLASS_NORMAL, "op-1");
    ASSERT_EQ(_svc.stats.total_operations_gated, 1);
    ASSERT_EQ(_svc.stats.total_operations_allowed, 1);
    _shutdown_svc();
    return 0;
}

/* ============================================================
 * FLAPPING PROTECTION TESTS
 * ============================================================ */

TEST(test_ord_flapping_initial) {
    _init_svc();
    ASSERT(!ozayn_ord_is_flapping(&_svc));
    _shutdown_svc();
    return 0;
}

TEST(test_ord_flapping_null) {
    ASSERT(!ozayn_ord_is_flapping(NULL));
    return 0;
}

/* ============================================================
 * SHUTDOWN TESTS
 * ============================================================ */

TEST(test_ord_shutdown_transitions_to_shutting_down) {
    _init_svc();
    ozayn_ord_transition(&_svc, OZAYN_ORD_MODE_INITIALIZING,
                         OZAYN_ORD_TRIGGER_MANUAL, "test", "test");
    ozayn_ord_transition(&_svc, OZAYN_ORD_MODE_READY,
                         OZAYN_ORD_TRIGGER_MANUAL, "test", "test");
    ozayn_ord_service_shutdown(&_svc);
    ASSERT_EQ(_svc.current_mode, OZAYN_ORD_MODE_SHUTTING_DOWN);
    _reset_all();
    return 0;
}

TEST(test_ord_shutdown_preserves_history) {
    _init_svc();
    ozayn_ord_transition(&_svc, OZAYN_ORD_MODE_INITIALIZING,
                         OZAYN_ORD_TRIGGER_MANUAL, "test", "test");
    ozayn_ord_transition(&_svc, OZAYN_ORD_MODE_READY,
                         OZAYN_ORD_TRIGGER_MANUAL, "test", "test");
    int trans_count = _svc.transition_count;
    ozayn_ord_service_shutdown(&_svc);
    ASSERT_GE(_svc.transition_count, trans_count);
    _reset_all();
    return 0;
}

/* ============================================================
 * NAME HELPER TESTS
 * ============================================================ */

TEST(test_ord_err_name) {
    ASSERT_STR_EQ(ozayn_ord_err_name(OZAYN_ORD_OK), "OK");
    ASSERT_STR_EQ(ozayn_ord_err_name(OZAYN_ORD_ERR_NULL), "NULL");
    ASSERT_STR_EQ(ozayn_ord_err_name(OZAYN_ORD_ERR_MODE_TRANSITION_INVALID),
                  "MODE_TRANSITION_INVALID");
    return 0;
}

TEST(test_ord_mode_name) {
    ASSERT_STR_EQ(ozayn_ord_mode_name(OZAYN_ORD_MODE_UNKNOWN), "UNKNOWN");
    ASSERT_STR_EQ(ozayn_ord_mode_name(OZAYN_ORD_MODE_READY), "READY");
    ASSERT_STR_EQ(ozayn_ord_mode_name(OZAYN_ORD_MODE_READY_DEGRADED),
                  "READY_DEGRADED");
    ASSERT_STR_EQ(ozayn_ord_mode_name(OZAYN_ORD_MODE_SAFE_HOLD), "SAFE_HOLD");
    ASSERT_STR_EQ(ozayn_ord_mode_name(OZAYN_ORD_MODE_SHUTTING_DOWN),
                  "SHUTTING_DOWN");
    return 0;
}

TEST(test_ord_opclass_name) {
    ASSERT_STR_EQ(ozayn_ord_opclass_name(OZAYN_ORD_OPCLASS_NORMAL), "NORMAL");
    ASSERT_STR_EQ(ozayn_ord_opclass_name(OZAYN_ORD_OPCLASS_DIAGNOSTIC),
                  "DIAGNOSTIC");
    ASSERT_STR_EQ(ozayn_ord_opclass_name(OZAYN_ORD_OPCLASS_RECOVERY),
                  "RECOVERY");
    ASSERT_STR_EQ(ozayn_ord_opclass_name(OZAYN_ORD_OPCLASS_SHUTDOWN),
                  "SHUTDOWN");
    ASSERT_STR_EQ(ozayn_ord_opclass_name(OZAYN_ORD_OPCLASS_MAINTENANCE),
                  "MAINTENANCE");
    return 0;
}

TEST(test_ord_gate_name) {
    ASSERT_STR_EQ(ozayn_ord_gate_name(OZAYN_ORD_GATE_ALLOWED), "ALLOWED");
    ASSERT_STR_EQ(ozayn_ord_gate_name(OZAYN_ORD_GATE_RESTRICTED), "RESTRICTED");
    ASSERT_STR_EQ(ozayn_ord_gate_name(OZAYN_ORD_GATE_BLOCKED), "BLOCKED");
    ASSERT_STR_EQ(ozayn_ord_gate_name(OZAYN_ORD_GATE_UNAVAILABLE),
                  "UNAVAILABLE");
    return 0;
}

TEST(test_ord_trigger_name) {
    ASSERT_STR_EQ(ozayn_ord_trigger_name(OZAYN_ORD_TRIGGER_MANUAL), "MANUAL");
    ASSERT_STR_EQ(ozayn_ord_trigger_name(OZAYN_ORD_TRIGGER_SAFETY), "SAFETY");
    ASSERT_STR_EQ(ozayn_ord_trigger_name(OZAYN_ORD_TRIGGER_SECURITY),
                  "SECURITY");
    ASSERT_STR_EQ(ozayn_ord_trigger_name(OZAYN_ORD_TRIGGER_STARTUP), "STARTUP");
    return 0;
}

TEST(test_ord_assess_name) {
    ASSERT_STR_EQ(ozayn_ord_assess_name(OZAYN_ORD_ASSESS_MAINTAIN_MODE),
                  "MAINTAIN_MODE");
    ASSERT_STR_EQ(ozayn_ord_assess_name(OZAYN_ORD_ASSESS_TRANSITION_REQUIRED),
                  "TRANSITION_REQUIRED");
    return 0;
}

TEST(test_ord_condition_name) {
    ASSERT_STR_EQ(ozayn_ord_condition_name(OZAYN_ORD_CONDITION_SATISFIED),
                  "SATISFIED");
    ASSERT_STR_EQ(ozayn_ord_condition_name(OZAYN_ORD_CONDITION_FAILED),
                  "FAILED");
    ASSERT_STR_EQ(ozayn_ord_condition_name(OZAYN_ORD_CONDITION_UNKNOWN),
                  "UNKNOWN");
    return 0;
}

TEST(test_ord_subsys_name) {
    ASSERT_STR_EQ(ozayn_ord_subsys_name(OZAYN_ORD_SUBSYS_OK), "OK");
    ASSERT_STR_EQ(ozayn_ord_subsys_name(OZAYN_ORD_SUBSYS_DEGRADED), "DEGRADED");
    ASSERT_STR_EQ(ozayn_ord_subsys_name(OZAYN_ORD_SUBSYS_FAILED), "FAILED");
    ASSERT_STR_EQ(ozayn_ord_subsys_name(OZAYN_ORD_SUBSYS_UNAVAILABLE),
                  "UNAVAILABLE");
    return 0;
}

TEST(test_ord_transition_result_name) {
    ASSERT_STR_EQ(ozayn_ord_transition_result_name(
                  OZAYN_ORD_TRANSITION_ACCEPTED), "ACCEPTED");
    ASSERT_STR_EQ(ozayn_ord_transition_result_name(
                  OZAYN_ORD_TRANSITION_REJECTED), "REJECTED");
    return 0;
}

TEST(test_ord_event_type_name) {
    ASSERT_STR_EQ(ozayn_ord_event_type_name(
                  OZAYN_ORD_EVENT_ASSESSMENT_STARTED), "ASSESSMENT_STARTED");
    ASSERT_STR_EQ(ozayn_ord_event_type_name(
                  OZAYN_ORD_EVENT_MODE_CHANGED), "MODE_CHANGED");
    ASSERT_STR_EQ(ozayn_ord_event_type_name(
                  OZAYN_ORD_EVENT_SYSTEM_READY), "SYSTEM_READY");
    ASSERT_STR_EQ(ozayn_ord_event_type_name(
                  OZAYN_ORD_EVENT_FLAPPING_DETECTED), "FLAPPING_DETECTED");
    return 0;
}

/* ============================================================
 * TEST RUNNER
 * ============================================================ */

int run_cr_operational_readiness_tests(void) {
    SUITE_BEGIN("Control Room — Operational Readiness (Step 20)");

    /* Lifecycle */
    RUN(test_ord_init);
    RUN(test_ord_init_null);
    RUN(test_ord_init_double);
    RUN(test_ord_shutdown);
    RUN(test_ord_shutdown_null);
    RUN(test_ord_shutdown_not_init);
    RUN(test_ord_global);

    /* Subsystem binding */
    RUN(test_ord_set_component_registry);
    RUN(test_ord_set_component_registry_null);
    RUN(test_ord_set_resource_manager);
    RUN(test_ord_set_device_session);
    RUN(test_ord_set_safety);
    RUN(test_ord_set_diagnostics);
    RUN(test_ord_set_startup_recovery);
    RUN(test_ord_set_workflow_recovery);
    RUN(test_ord_set_workflow_checkpoint);

    /* Mode queries */
    RUN(test_ord_get_mode);
    RUN(test_ord_get_mode_null);
    RUN(test_ord_get_mode_not_init);
    RUN(test_ord_get_previous_mode);
    RUN(test_ord_is_running_not_running);
    RUN(test_ord_is_running_ready);
    RUN(test_ord_is_running_degraded);
    RUN(test_ord_is_running_recovery);
    RUN(test_ord_is_running_maintenance);
    RUN(test_ord_is_not_running_blocked);
    RUN(test_ord_is_not_running_safe_hold);

    /* Transition validity */
    RUN(test_ord_transition_valid_unknown_to_init);
    RUN(test_ord_transition_valid_init_to_ready);
    RUN(test_ord_transition_valid_ready_to_degraded);
    RUN(test_ord_transition_valid_ready_to_recovery);
    RUN(test_ord_transition_valid_ready_to_maintenance);
    RUN(test_ord_transition_valid_ready_to_safe_hold);
    RUN(test_ord_transition_valid_ready_to_shutting_down);
    RUN(test_ord_transition_valid_ready_to_failed);
    RUN(test_ord_transition_valid_shutting_down_to_none);
    RUN(test_ord_transition_valid_degraded_to_ready);
    RUN(test_ord_transition_valid_safe_hold_to_recovery);
    RUN(test_ord_transition_valid_failed_to_recovery);
    RUN(test_ord_transition_valid_blocked_to_ready);
    RUN(test_ord_transition_invalid_unknown_to_ready);
    RUN(test_ord_transition_invalid_ready_to_unknown);
    RUN(test_ord_transition_invalid_out_of_range);

    /* Mode transitions */
    RUN(test_ord_transition_null);
    RUN(test_ord_transition_not_init);
    RUN(test_ord_transition_invalid);
    RUN(test_ord_transition_unknown_to_init);
    RUN(test_ord_transition_init_to_ready);
    RUN(test_ord_transition_full_path);
    RUN(test_ord_transition_to_safe_hold);
    RUN(test_ord_transition_to_blocked);
    RUN(test_ord_transition_to_recovery);
    RUN(test_ord_transition_to_failed);
    RUN(test_ord_transition_reject_shutting_down);
    RUN(test_ord_transition_force);
    RUN(test_ord_transition_count);
    RUN(test_ord_get_latest_transition);
    RUN(test_ord_get_latest_transition_null);

    /* Readiness assessment */
    RUN(test_ord_assess_null);
    RUN(test_ord_assess_not_init);
    RUN(test_ord_assess);
    RUN(test_ord_assess_no_subsystems);
    RUN(test_ord_assess_with_subsystems);
    RUN(test_ord_assess_with_blocking);
    RUN(test_ord_assess_count);
    RUN(test_ord_get_latest_assessment);
    RUN(test_ord_assess_concurrency);

    /* Operation gating */
    RUN(test_ord_check_operation_null);
    RUN(test_ord_check_operation_unknown_mode);
    RUN(test_ord_check_operation_ready_normal);
    RUN(test_ord_check_operation_ready_diagnostic);
    RUN(test_ord_check_operation_degraded_normal);
    RUN(test_ord_check_operation_degraded_diagnostic);
    RUN(test_ord_check_operation_safe_hold_normal);
    RUN(test_ord_check_operation_safe_hold_diagnostic);
    RUN(test_ord_check_operation_blocked_normal);
    RUN(test_ord_check_operation_maintenance_maintenance);
    RUN(test_ord_check_operation_maintenance_normal);
    RUN(test_ord_check_operation_shutting_down_normal);
    RUN(test_ord_check_operation_shutting_down_shutdown);
    RUN(test_ord_check_operation_failed_recovery);
    RUN(test_ord_check_operation_invalid_opclass);
    RUN(test_ord_gate_operation);
    RUN(test_ord_gate_operation_blocked);
    RUN(test_ord_gate_operation_null);

    /* Blocking and warnings */
    RUN(test_ord_add_blocking);
    RUN(test_ord_add_blocking_null);
    RUN(test_ord_add_blocking_null_desc);
    RUN(test_ord_add_blocking_limit);
    RUN(test_ord_blocking_count);
    RUN(test_ord_add_warning);
    RUN(test_ord_add_warning_null);
    RUN(test_ord_add_warning_null_desc);
    RUN(test_ord_add_warning_limit);
    RUN(test_ord_warning_count);

    /* Events */
    RUN(test_ord_emit_event);
    RUN(test_ord_emit_event_null);
    RUN(test_ord_emit_event_null_msg);
    RUN(test_ord_emit_event_not_init);
    RUN(test_ord_event_ring_buffer);
    RUN(test_ord_get_event);
    RUN(test_ord_get_event_invalid_index);
    RUN(test_ord_event_count);
    RUN(test_ord_transition_emits_events);

    /* Stats */
    RUN(test_ord_stats);
    RUN(test_ord_stats_null);
    RUN(test_ord_reset_stats);
    RUN(test_ord_stats_transitions);
    RUN(test_ord_stats_gating);

    /* Flapping */
    RUN(test_ord_flapping_initial);
    RUN(test_ord_flapping_null);

    /* Shutdown */
    RUN(test_ord_shutdown_transitions_to_shutting_down);
    RUN(test_ord_shutdown_preserves_history);

    /* Name helpers */
    RUN(test_ord_err_name);
    RUN(test_ord_mode_name);
    RUN(test_ord_opclass_name);
    RUN(test_ord_gate_name);
    RUN(test_ord_trigger_name);
    RUN(test_ord_assess_name);
    RUN(test_ord_condition_name);
    RUN(test_ord_subsys_name);
    RUN(test_ord_transition_result_name);
    RUN(test_ord_event_type_name);

    SUITE_END();
    return FAILED() ? 1 : 0;
}
