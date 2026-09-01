#include "../test_framework.h"
#include "processes.h"

TEST(process_manager_init) {
    ozayn_process_manager_t mgr;
    ASSERT_EQ(ozayn_process_manager_init(&mgr), OZAYN_OK);
    ASSERT(mgr.initialized);
    ASSERT_EQ(mgr.process_count, 0);
    ozayn_process_manager_shutdown(&mgr);
    return 0;
}

TEST(process_state_names) {
    ASSERT_STR_EQ(ozayn_process_state_name(OZAYN_PROC_CREATED), "CREATED");
    ASSERT_STR_EQ(ozayn_process_state_name(OZAYN_PROC_STARTING), "STARTING");
    ASSERT_STR_EQ(ozayn_process_state_name(OZAYN_PROC_RUNNING), "RUNNING");
    ASSERT_STR_EQ(ozayn_process_state_name(OZAYN_PROC_EXITED), "EXITED");
    ASSERT_STR_EQ(ozayn_process_state_name(OZAYN_PROC_FAILED), "FAILED");
    ASSERT_STR_EQ(ozayn_process_state_name(OZAYN_PROC_TERMINATED), "TERMINATED");
    return 0;
}

TEST(process_active_count) {
    ozayn_process_manager_t mgr;
    ozayn_process_manager_init(&mgr);
    ASSERT_EQ(ozayn_process_manager_active_count(&mgr), 0);
    ozayn_process_manager_shutdown(&mgr);
    return 0;
}

TEST(process_get_nonexistent) {
    ozayn_process_manager_t mgr;
    ozayn_process_manager_init(&mgr);
    ASSERT_NULL(ozayn_process_manager_get(&mgr, 999));
    ozayn_process_manager_shutdown(&mgr);
    return 0;
}

TEST(process_get_by_pid) {
    ozayn_process_manager_t mgr;
    ozayn_process_manager_init(&mgr);
    ASSERT_NULL(ozayn_process_manager_get_by_pid(&mgr, 99999));
    ozayn_process_manager_shutdown(&mgr);
    return 0;
}

TEST(process_reap_no_children) {
    ozayn_process_manager_t mgr;
    ozayn_process_manager_init(&mgr);
    int n = ozayn_process_manager_reap(&mgr);
    ASSERT(n >= 0);
    ozayn_process_manager_shutdown(&mgr);
    return 0;
}

TEST(process_terminate_nonexistent) {
    ozayn_process_manager_t mgr;
    ozayn_process_manager_init(&mgr);
    ASSERT_NEQ(ozayn_process_manager_terminate(&mgr, 999), OZAYN_OK);
    ozayn_process_manager_shutdown(&mgr);
    return 0;
}

int run_processes_tests(void) {
    SUITE_BEGIN("Processes");
    RUN(process_manager_init);
    RUN(process_state_names);
    RUN(process_active_count);
    RUN(process_get_nonexistent);
    RUN(process_get_by_pid);
    RUN(process_reap_no_children);
    RUN(process_terminate_nonexistent);
    SUITE_END();
    return _tf_suite_fail;
}
