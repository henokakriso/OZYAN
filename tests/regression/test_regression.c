#include "../test_framework.h"
#include "tasks.h"
#include "commands.h"
#include "resource.h"
#include "scheduler.h"
#include "monitoring.h"
#include "recovery.h"
#include "state_manager.h"
#include "security_boundary.h"
#include "diagnostics.h"
#include "registry.h"
#include "processes.h"
#include "platform.h"
#include "logger.h"
#include "ozayn.h"

/* Regression tests: verify existing functionality still works end-to-end */

TEST(regression_task_lifecycle) {
    ozayn_task_manager_t mgr;
    ozayn_task_manager_init(&mgr);
    ozayn_task_t *t1 = ozayn_task_manager_submit(&mgr, OZAYN_TASK_DEMO, OZAYN_TASK_SRC_CORE);
    ozayn_task_t *t2 = ozayn_task_manager_submit(&mgr, OZAYN_TASK_DEMO, OZAYN_TASK_SRC_CORE);
    ASSERT_NOT_NULL(t1);
    ASSERT_NOT_NULL(t2);
    ASSERT_NEQ(t1->id, t2->id);
    ASSERT_NOT_NULL(ozayn_task_manager_get(&mgr, t1->id));
    ASSERT_NOT_NULL(ozayn_task_manager_get(&mgr, t2->id));
    ozayn_task_manager_shutdown(&mgr);
    return 0;
}

TEST(regression_command_execute_status) {
    ozayn_command_engine_t engine;
    ozayn_command_engine_init(&engine);
    ozayn_command_t cmd = ozayn_command_create(OZAYN_CMD_STATUS, OZAYN_CMD_SRC_CLI);
    ASSERT_EQ(ozayn_command_engine_execute(&engine, &cmd), OZAYN_CMD_RESULT_SUCCESS);
    cmd = ozayn_command_create(OZAYN_CMD_HEALTH, OZAYN_CMD_SRC_CLI);
    ASSERT_EQ(ozayn_command_engine_execute(&engine, &cmd), OZAYN_CMD_RESULT_SUCCESS);
    ozayn_command_engine_shutdown(&engine);
    return 0;
}

TEST(regression_resource_full_lifecycle) {
    ozayn_resource_manager_t mgr;
    ozayn_resource_manager_init(&mgr, 1);
    ASSERT_EQ(ozayn_resource_create(&mgr, "dev1", "Device 1",
                                     OZAYN_RESOURCE_TYPE_DEVICE, 1), OZAYN_RESOURCE_OK);
    ASSERT_EQ(ozayn_resource_allocate(&mgr, "dev1", "owner"), OZAYN_RESOURCE_OK);
    ASSERT_EQ(ozayn_resource_activate(&mgr, "dev1", "owner"), OZAYN_RESOURCE_OK);
    ASSERT_EQ(ozayn_resource_release(&mgr, "dev1", "owner"), OZAYN_RESOURCE_OK);
    ASSERT(ozayn_resource_exists(&mgr, "dev1"));
    ozayn_resource_manager_shutdown(&mgr);
    return 0;
}

TEST(regression_scheduler_submit_and_cancel) {
    ozayn_task_manager_t tmgr;
    ozayn_task_manager_init(&tmgr);
    ozayn_scheduler_manager_t smgr;
    ozayn_scheduler_init(&smgr, 1);
    ozayn_scheduler_set_task_mgr(&smgr, &tmgr);
    ozayn_task_t *t = ozayn_task_manager_submit(&tmgr, OZAYN_TASK_DEMO, OZAYN_TASK_SRC_CORE);
    ASSERT_EQ(ozayn_scheduler_submit(&smgr, t->id, OZAYN_SCHED_PRIORITY_HIGH, "test"), OZAYN_OK);
    ASSERT_EQ(smgr.ready_count, 1);
    ASSERT_EQ(ozayn_scheduler_cancel(&smgr, t->id), OZAYN_OK);
    ASSERT_EQ(smgr.ready_count, 0);
    ozayn_scheduler_shutdown(&smgr);
    ozayn_task_manager_shutdown(&tmgr);
    return 0;
}

TEST(regression_monitoring_health_workflow) {
    ozayn_monitoring_manager_t mgr;
    ozayn_monitoring_init(&mgr, 1);
    ASSERT_EQ(ozayn_monitoring_report_health(&mgr, OZAYN_COMP_SCHEDULER,
                                               OZAYN_HEALTH_HEALTHY,
                                               OZAYN_SEVERITY_INFO, "ok"), OZAYN_OK);
    ASSERT_EQ(ozayn_monitoring_get_health(&mgr, OZAYN_COMP_SCHEDULER), OZAYN_HEALTH_HEALTHY);
    ASSERT_EQ(ozayn_monitoring_register_metric(&mgr, "tput", OZAYN_METRIC_COUNTER,
                                                 OZAYN_COMP_SCHEDULER), OZAYN_OK);
    ozayn_monitoring_update_metric(&mgr, "tput", 100);
    const ozayn_metric_record_t *m = ozayn_monitoring_get_metric(&mgr, "tput");
    ASSERT_NOT_NULL(m);
    ASSERT_EQ(m->value, 100);
    ozayn_monitoring_shutdown(&mgr);
    return 0;
}

TEST(regression_recovery_raise_and_evaluate) {
    ozayn_recovery_t rec;
    ozayn_recovery_init(&rec);
    ozayn_recovery_raise(&rec, OZAYN_ERRCAT_CONFIG, OZAYN_LOG_ERROR,
                          OZAYN_SCOPE_COMPONENT, "test", "config error");
    ASSERT_EQ(rec.total_errors, 1);
    ASSERT_EQ(rec.has_error, 1);
    ozayn_recovery_action_t a = ozayn_recovery_evaluate(&rec);
    ASSERT(a >= OZAYN_RECOVERY_IGNORE && a <= OZAYN_RECOVERY_SHUTDOWN);
    ozayn_recovery_clear(&rec);
    ASSERT_EQ(rec.has_error, 0);
    return 0;
}

TEST(regression_state_manager_persist_and_load) {
    ozayn_state_manager_t mgr = {0};
    ozayn_state_manager_init(&mgr, 1);
    ozayn_state_create(&mgr, "key1", "test", OZAYN_STATE_NS_CORE,
                         OZAYN_STATE_CAT_TRANSIENT, OZAYN_STATE_RECOVER_NEVER, "value1", 6);
    ozayn_state_create(&mgr, "key2", "test", OZAYN_STATE_NS_CORE,
                         OZAYN_STATE_CAT_PERSISTENT, OZAYN_STATE_RECOVER_ON_RESTART, "value2", 6);
    ASSERT_NOT_NULL(ozayn_state_get(&mgr, "key1"));
    ASSERT_NOT_NULL(ozayn_state_get(&mgr, "key2"));
    ASSERT_EQ(ozayn_state_update(&mgr, "key1", "updated", 7), 0);
    ASSERT_EQ(mgr.entry_count, 2);
    ozayn_state_manager_shutdown(&mgr);
    return 0;
}

TEST(regression_security_boundary_context) {
    ozayn_security_boundary_manager_t mgr = {0};
    ozayn_security_boundary_init(&mgr, 1);
    uint32_t ctx = ozayn_security_boundary_register_context(&mgr, "svc",
                                                              OZAYN_SB_TRUST_UNTRUSTED);
    ASSERT(ctx > 0);
    ASSERT_EQ(ozayn_security_boundary_context_count(&mgr), 1);
    ozayn_security_check_result_t r = ozayn_security_boundary_check(&mgr, ctx,
                                                                      OZAYN_CAP_IPC_SEND);
    ASSERT(!r.allowed);
    ozayn_security_boundary_shutdown(&mgr);
    return 0;
}

TEST(regression_diagnostics_evidence_and_finding) {
    ozayn_diagnostics_manager_t mgr;
    ozayn_diagnostics_init(&mgr, 1);
    uint32_t eid = ozayn_diagnostics_record_evidence(&mgr, OZAYN_DIAG_COMP_IPC,
                                                       OZAYN_DIAG_TARGET_IPC,
                                                       "REQ-001", "data");
    ASSERT(eid > 0);
    uint32_t fid = ozayn_diagnostics_add_finding(&mgr, OZAYN_DIAG_COMP_SCHEDULER,
                                                    OZAYN_DIAG_SEV_WARNING,
                                                    "REQ-001", "obs", "cause",
                                                    OZAYN_DIAG_CONFIDENCE_HIGH);
    ASSERT(fid > 0);
    ASSERT_EQ(ozayn_diagnostics_evidence_count(&mgr), 1);
    ASSERT_EQ(ozayn_diagnostics_finding_count(&mgr), 1);
    ozayn_diagnostics_shutdown(&mgr);
    return 0;
}

TEST(regression_registry_register_lookup_unregister) {
    ozayn_registry_manager_t mgr;
    ozayn_registry_init(&mgr, 1);
    ozayn_service_registration_t reg = {0};
    strcpy(reg.id, "svc1"); strcpy(reg.name, "SVC"); strcpy(reg.version, "1.0");
    strcpy(reg.endpoint, "/tmp/s.sock"); strcpy(reg.provider, "test");
    reg.protocol_version = 1;
    ozayn_registry_register(&mgr, &reg, -1);
    ASSERT_NOT_NULL(ozayn_registry_lookup(&mgr, "svc1"));
    ASSERT_EQ(ozayn_registry_unregister(&mgr, "svc1"), OZAYN_OK);
    ASSERT_NULL(ozayn_registry_lookup(&mgr, "svc1"));
    ozayn_registry_shutdown(&mgr);
    return 0;
}

TEST(regression_platform_info) {
    ozayn_system_info_t info = {0};
    ASSERT_EQ(ozayn_system_info(&info), OZAYN_OK);
    ASSERT(info.cpu_cores > 0);
    return 0;
}

int run_regression_tests(void) {
    SUITE_BEGIN("Regression");
    RUN(regression_task_lifecycle);
    RUN(regression_command_execute_status);
    RUN(regression_resource_full_lifecycle);
    RUN(regression_scheduler_submit_and_cancel);
    RUN(regression_monitoring_health_workflow);
    RUN(regression_recovery_raise_and_evaluate);
    RUN(regression_state_manager_persist_and_load);
    RUN(regression_security_boundary_context);
    RUN(regression_diagnostics_evidence_and_finding);
    RUN(regression_registry_register_lookup_unregister);
    RUN(regression_platform_info);
    SUITE_END();
    return _tf_suite_fail;
}
