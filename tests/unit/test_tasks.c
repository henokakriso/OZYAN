#include "../test_framework.h"
#include "tasks.h"

TEST(task_init_returns_ok) {
    ozayn_task_manager_t mgr;
    ASSERT_EQ(ozayn_task_manager_init(&mgr), OZAYN_OK);
    ASSERT(mgr.initialized);
    ozayn_task_manager_shutdown(&mgr);
    return 0;
}

TEST(task_shutdown_clears_state) {
    ozayn_task_manager_t mgr;
    ozayn_task_manager_init(&mgr);
    ozayn_task_manager_shutdown(&mgr);
    ASSERT(!mgr.initialized);
    return 0;
}

TEST(task_submit_returns_task) {
    ozayn_task_manager_t mgr;
    ozayn_task_manager_init(&mgr);
    ozayn_task_t *t = ozayn_task_manager_submit(&mgr, OZAYN_TASK_DEMO, OZAYN_TASK_SRC_CORE);
    ASSERT_NOT_NULL(t);
    ASSERT_EQ(t->type, OZAYN_TASK_DEMO);
    ASSERT(t->id > 0);
    ozayn_task_manager_shutdown(&mgr);
    return 0;
}

TEST(task_submit_multiple) {
    ozayn_task_manager_t mgr;
    ozayn_task_manager_init(&mgr);
    ozayn_task_t *t1 = ozayn_task_manager_submit(&mgr, OZAYN_TASK_DEMO, OZAYN_TASK_SRC_CORE);
    ozayn_task_t *t2 = ozayn_task_manager_submit(&mgr, OZAYN_TASK_DEMO, OZAYN_TASK_SRC_CORE);
    ASSERT_NOT_NULL(t1);
    ASSERT_NOT_NULL(t2);
    ASSERT_NEQ(t1->id, t2->id);
    ASSERT_EQ(mgr.task_count, 2);
    ozayn_task_manager_shutdown(&mgr);
    return 0;
}

TEST(task_get_returns_correct) {
    ozayn_task_manager_t mgr;
    ozayn_task_manager_init(&mgr);
    ozayn_task_t *t = ozayn_task_manager_submit(&mgr, OZAYN_TASK_DEMO, OZAYN_TASK_SRC_CORE);
    ASSERT_NOT_NULL(t);
    ozayn_task_t *found = ozayn_task_manager_get(&mgr, t->id);
    ASSERT_NOT_NULL(found);
    ASSERT_EQ(found->id, t->id);
    ASSERT_NULL(ozayn_task_manager_get(&mgr, 99999));
    ozayn_task_manager_shutdown(&mgr);
    return 0;
}

TEST(task_cancel_sets_flag) {
    ozayn_task_manager_t mgr;
    ozayn_task_manager_init(&mgr);
    ozayn_task_t *t = ozayn_task_manager_submit(&mgr, OZAYN_TASK_DEMO, OZAYN_TASK_SRC_CORE);
    ASSERT_NOT_NULL(t);
    ozayn_result_t r = ozayn_task_manager_cancel(&mgr, t->id);
    ASSERT(r == OZAYN_OK || t->state == OZAYN_TASK_COMPLETED);
    ozayn_task_manager_shutdown(&mgr);
    return 0;
}

TEST(task_active_count) {
    ozayn_task_manager_t mgr;
    ozayn_task_manager_init(&mgr);
    int before = ozayn_task_manager_active_count(&mgr);
    ozayn_task_manager_submit(&mgr, OZAYN_TASK_DEMO, OZAYN_TASK_SRC_CORE);
    ASSERT(ozayn_task_manager_active_count(&mgr) >= before);
    ozayn_task_manager_shutdown(&mgr);
    return 0;
}

TEST(task_type_names) {
    ASSERT_STR_EQ(ozayn_task_type_name(OZAYN_TASK_NONE), "NONE");
    ASSERT_STR_EQ(ozayn_task_type_name(OZAYN_TASK_DEMO), "DEMO");
    ASSERT_STR_EQ(ozayn_task_type_name(OZAYN_TASK_DEMO_FAIL), "DEMO_FAIL");
    return 0;
}

TEST(task_state_names) {
    ASSERT_STR_EQ(ozayn_task_state_name(OZAYN_TASK_CREATED), "CREATED");
    ASSERT_STR_EQ(ozayn_task_state_name(OZAYN_TASK_QUEUED), "QUEUED");
    ASSERT_STR_EQ(ozayn_task_state_name(OZAYN_TASK_RUNNING), "RUNNING");
    ASSERT_STR_EQ(ozayn_task_state_name(OZAYN_TASK_COMPLETED), "COMPLETED");
    ASSERT_STR_EQ(ozayn_task_state_name(OZAYN_TASK_FAILED), "FAILED");
    ASSERT_STR_EQ(ozayn_task_state_name(OZAYN_TASK_CANCELLED), "CANCELLED");
    return 0;
}

TEST(task_source_names) {
    ASSERT_STR_EQ(ozayn_task_source_name(OZAYN_TASK_SRC_CORE), "CORE");
    ASSERT_STR_EQ(ozayn_task_source_name(OZAYN_TASK_SRC_COMMAND), "COMMAND");
    return 0;
}

TEST(task_cancel_nonexistent) {
    ozayn_task_manager_t mgr;
    ozayn_task_manager_init(&mgr);
    ASSERT_NEQ(ozayn_task_manager_cancel(&mgr, 99999), OZAYN_OK);
    ozayn_task_manager_shutdown(&mgr);
    return 0;
}

int run_tasks_tests(void) {
    SUITE_BEGIN("Tasks");
    RUN(task_init_returns_ok);
    RUN(task_shutdown_clears_state);
    RUN(task_submit_returns_task);
    RUN(task_submit_multiple);
    RUN(task_get_returns_correct);
    RUN(task_cancel_sets_flag);
    RUN(task_active_count);
    RUN(task_type_names);
    RUN(task_state_names);
    RUN(task_source_names);
    RUN(task_cancel_nonexistent);
    SUITE_END();
    return _tf_suite_fail;
}
