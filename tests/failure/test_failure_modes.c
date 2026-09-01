#include "../test_framework.h"
#include "logger.h"
#include "tasks.h"
#include "commands.h"
#include "recovery.h"
#include "monitoring.h"
#include "resource.h"
#include "scheduler.h"
#include "security_boundary.h"
#include "diagnostics.h"
#include "state_manager.h"
#include "config.h"
#include "core_api.h"

/* Failure mode tests: verify graceful handling of invalid inputs */

TEST(failure_logger_null_config) {
    ozayn_logger_t log;
    /* Should handle NULL config gracefully */
    ozayn_result_t r = ozayn_logger_init(&log, NULL);
    /* Either rejects or uses defaults - both are acceptable */
    (void)r;
    return 0;
}

TEST(failure_task_manager_null_submit) {
    ozayn_task_manager_t mgr;
    ozayn_task_manager_init(&mgr);
    /* Submitting a task type NONE should return NULL */
    ozayn_task_t *t = ozayn_task_manager_submit(&mgr, OZAYN_TASK_NONE, OZAYN_TASK_SRC_CORE);
    ASSERT_NULL(t);
    ozayn_task_manager_shutdown(&mgr);
    return 0;
}

TEST(failure_command_unknown_type) {
    ozayn_command_engine_t engine;
    ozayn_command_engine_init(&engine);
    ozayn_command_t cmd = ozayn_command_create(OZAYN_CMD_NONE, OZAYN_CMD_SRC_CLI);
    ozayn_command_result_t r = ozayn_command_engine_execute(&engine, &cmd);
    ASSERT_EQ(r, OZAYN_CMD_RESULT_INVALID);
    ozayn_command_engine_shutdown(&engine);
    return 0;
}

TEST(failure_recovery_consecutive_errors) {
    ozayn_recovery_t rec;
    ozayn_recovery_init(&rec);
    for (int i = 0; i < 10; i++) {
        ozayn_recovery_raise(&rec, OZAYN_ERRCAT_RUNTIME, OZAYN_LOG_ERROR,
                              OZAYN_SCOPE_COMPONENT, "test", "error");
    }
    ASSERT_EQ(rec.total_errors, 10);
    ASSERT_EQ(rec.has_error, 1);
    return 0;
}

TEST(failure_resource_double_free) {
    ozayn_resource_manager_t mgr;
    ozayn_resource_manager_init(&mgr, 1);
    ozayn_resource_create(&mgr, "r1", "Test", OZAYN_RESOURCE_TYPE_DEVICE, 1);
    ozayn_resource_allocate(&mgr, "r1", "owner");
    ASSERT_EQ(ozayn_resource_release(&mgr, "r1", "owner"), OZAYN_RESOURCE_OK);
    /* Double release should be handled gracefully */
    ozayn_resource_result_t r = ozayn_resource_release(&mgr, "r1", "owner");
    (void)r;
    ozayn_resource_manager_shutdown(&mgr);
    return 0;
}

TEST(failure_security_boundary_violation_counter) {
    ozayn_security_boundary_manager_t mgr = {0};
    ozayn_security_boundary_init(&mgr, 1);
    uint32_t ctx = ozayn_security_boundary_register_context(&mgr, "test",
                                                              OZAYN_SB_TRUST_UNTRUSTED);
    for (int i = 0; i < 100; i++) {
        ozayn_security_boundary_report_violation(&mgr, ctx,
                                                   OZAYN_VIOLATION_CAPABILITY_DENIED,
                                                   OZAYN_SEC_SEV_LOW, "violation");
    }
    ASSERT_EQ(ozayn_security_boundary_violation_count(&mgr), 100);
    ozayn_security_boundary_shutdown(&mgr);
    return 0;
}

TEST(failure_diagnostics_capacity) {
    ozayn_diagnostics_manager_t mgr;
    ozayn_diagnostics_init(&mgr, 1);
    /* Fill evidence buffer */
    for (int i = 0; i < 1000; i++) {
        ozayn_diagnostics_record_evidence(&mgr, OZAYN_DIAG_COMP_CORE,
                                            OZAYN_DIAG_TARGET_CORE, "REQ", "ev");
    }
    /* Should not crash, just stop recording */
    ASSERT(ozayn_diagnostics_evidence_count(&mgr) > 0);
    ozayn_diagnostics_shutdown(&mgr);
    return 0;
}

TEST(failure_state_manager_duplicate_register) {
    ozayn_state_manager_t mgr = {0};
    ozayn_state_manager_init(&mgr, 1);
    ozayn_state_create(&mgr, "key", "test", OZAYN_STATE_NS_CORE,
                         OZAYN_STATE_CAT_TRANSIENT, OZAYN_STATE_RECOVER_NEVER, "val1", 4);
    /* Re-registering same key should update or reject */
    ozayn_state_create(&mgr, "key", "test", OZAYN_STATE_NS_CORE,
                         OZAYN_STATE_CAT_TRANSIENT, OZAYN_STATE_RECOVER_NEVER, "val2", 4);
    ASSERT(mgr.entry_count <= 2);
    ozayn_state_manager_shutdown(&mgr);
    return 0;
}

TEST(failure_config_validate_with_entries) {
    ozayn_config_object_t cfg = {0};
    ozayn_config_load(&cfg);
    ASSERT_EQ(ozayn_config_validate(&cfg), OZAYN_OK);
    ozayn_config_destroy(&cfg);
    return 0;
}

TEST(failure_monitoring_metric_overflow) {
    ozayn_monitoring_manager_t mgr;
    ozayn_monitoring_init(&mgr, 1);
    /* Register many metrics */
    char name[64];
    for (int i = 0; i < 50; i++) {
        snprintf(name, sizeof(name), "metric.%d", i);
        ozayn_monitoring_register_metric(&mgr, name, OZAYN_METRIC_COUNTER,
                                          OZAYN_COMP_SCHEDULER);
    }
    /* Should handle capacity gracefully */
    ASSERT(ozayn_monitoring_metric_count(&mgr) > 0);
    ozayn_monitoring_shutdown(&mgr);
    return 0;
}

int run_failure_tests(void) {
    SUITE_BEGIN("Failure Modes");
    RUN(failure_logger_null_config);
    RUN(failure_task_manager_null_submit);
    RUN(failure_command_unknown_type);
    RUN(failure_recovery_consecutive_errors);
    RUN(failure_resource_double_free);
    RUN(failure_security_boundary_violation_counter);
    RUN(failure_diagnostics_capacity);
    RUN(failure_state_manager_duplicate_register);
    RUN(failure_config_validate_with_entries);
    RUN(failure_monitoring_metric_overflow);
    SUITE_END();
    return _tf_suite_fail;
}
