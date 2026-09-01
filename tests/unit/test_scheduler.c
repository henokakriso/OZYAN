#include "../test_framework.h"
#include "scheduler.h"
#include "tasks.h"

TEST(scheduler_init) {
    ozayn_scheduler_manager_t mgr;
    ASSERT_EQ(ozayn_scheduler_init(&mgr, 1), OZAYN_OK);
    ASSERT(mgr.initialized);
    ozayn_scheduler_shutdown(&mgr);
    return 0;
}

TEST(scheduler_submit_task) {
    ozayn_task_manager_t tmgr;
    ozayn_task_manager_init(&tmgr);
    ozayn_scheduler_manager_t smgr;
    ozayn_scheduler_init(&smgr, 1);
    ozayn_scheduler_set_task_mgr(&smgr, &tmgr);
    ozayn_task_t *t = ozayn_task_manager_submit(&tmgr, OZAYN_TASK_DEMO, OZAYN_TASK_SRC_CORE);
    ASSERT_NOT_NULL(t);
    ozayn_result_t r = ozayn_scheduler_submit(&smgr, t->id, OZAYN_SCHED_PRIORITY_NORMAL, "test");
    ASSERT_EQ(r, OZAYN_OK);
    ASSERT_EQ(smgr.ready_count, 1);
    ozayn_scheduler_shutdown(&smgr);
    ozayn_task_manager_shutdown(&tmgr);
    return 0;
}

TEST(scheduler_priority_ordering) {
    ozayn_task_manager_t tmgr;
    ozayn_task_manager_init(&tmgr);
    ozayn_scheduler_manager_t smgr;
    ozayn_scheduler_init(&smgr, 1);
    ozayn_scheduler_set_task_mgr(&smgr, &tmgr);

    ozayn_task_t *t1 = ozayn_task_manager_submit(&tmgr, OZAYN_TASK_DEMO, OZAYN_TASK_SRC_CORE);
    ozayn_task_t *t2 = ozayn_task_manager_submit(&tmgr, OZAYN_TASK_DEMO, OZAYN_TASK_SRC_CORE);
    ozayn_scheduler_submit(&smgr, t1->id, OZAYN_SCHED_PRIORITY_LOW, "test");
    ozayn_scheduler_submit(&smgr, t2->id, OZAYN_SCHED_PRIORITY_CRITICAL, "test");

    const ozayn_sched_entry_t *e = ozayn_scheduler_find(&smgr, t2->id);
    ASSERT_NOT_NULL(e);
    ASSERT_EQ(e->base_priority, OZAYN_SCHED_PRIORITY_CRITICAL);
    ozayn_scheduler_shutdown(&smgr);
    ozayn_task_manager_shutdown(&tmgr);
    return 0;
}

TEST(scheduler_cancel) {
    ozayn_task_manager_t tmgr;
    ozayn_task_manager_init(&tmgr);
    ozayn_scheduler_manager_t smgr;
    ozayn_scheduler_init(&smgr, 1);
    ozayn_scheduler_set_task_mgr(&smgr, &tmgr);
    ozayn_task_t *t = ozayn_task_manager_submit(&tmgr, OZAYN_TASK_DEMO, OZAYN_TASK_SRC_CORE);
    ozayn_scheduler_submit(&smgr, t->id, OZAYN_SCHED_PRIORITY_NORMAL, "test");
    ASSERT_EQ(ozayn_scheduler_cancel(&smgr, t->id), OZAYN_OK);
    ASSERT_EQ(smgr.ready_count, 0);
    ozayn_scheduler_shutdown(&smgr);
    ozayn_task_manager_shutdown(&tmgr);
    return 0;
}

TEST(scheduler_stats) {
    ozayn_task_manager_t tmgr;
    ozayn_task_manager_init(&tmgr);
    ozayn_scheduler_manager_t smgr;
    ozayn_scheduler_init(&smgr, 1);
    ozayn_scheduler_set_task_mgr(&smgr, &tmgr);
    ozayn_task_t *t = ozayn_task_manager_submit(&tmgr, OZAYN_TASK_DEMO, OZAYN_TASK_SRC_CORE);
    ozayn_scheduler_submit(&smgr, t->id, OZAYN_SCHED_PRIORITY_NORMAL, "test");
    ozayn_sched_stats_t s = ozayn_scheduler_stats(&smgr);
    ASSERT(s.total_submitted >= 1);
    ozayn_scheduler_shutdown(&smgr);
    ozayn_task_manager_shutdown(&tmgr);
    return 0;
}

TEST(scheduler_priority_names) {
    ASSERT_STR_EQ(ozayn_sched_priority_name(OZAYN_SCHED_PRIORITY_BACKGROUND), "BACKGROUND");
    ASSERT_STR_EQ(ozayn_sched_priority_name(OZAYN_SCHED_PRIORITY_LOW), "LOW");
    ASSERT_STR_EQ(ozayn_sched_priority_name(OZAYN_SCHED_PRIORITY_NORMAL), "NORMAL");
    ASSERT_STR_EQ(ozayn_sched_priority_name(OZAYN_SCHED_PRIORITY_HIGH), "HIGH");
    ASSERT_STR_EQ(ozayn_sched_priority_name(OZAYN_SCHED_PRIORITY_CRITICAL), "CRITICAL");
    return 0;
}

TEST(scheduler_state_names) {
    ASSERT_STR_EQ(ozayn_sched_state_name(OZAYN_SCHED_STATE_READY), "READY");
    ASSERT_STR_EQ(ozayn_sched_state_name(OZAYN_SCHED_STATE_RUNNING), "RUNNING");
    ASSERT_STR_EQ(ozayn_sched_state_name(OZAYN_SCHED_STATE_WAITING), "WAITING");
    ASSERT_STR_EQ(ozayn_sched_state_name(OZAYN_SCHED_STATE_BLOCKED), "BLOCKED");
    return 0;
}

int run_scheduler_tests(void) {
    SUITE_BEGIN("Scheduler");
    RUN(scheduler_init);
    RUN(scheduler_submit_task);
    RUN(scheduler_priority_ordering);
    RUN(scheduler_cancel);
    RUN(scheduler_stats);
    RUN(scheduler_priority_names);
    RUN(scheduler_state_names);
    SUITE_END();
    return _tf_suite_fail;
}
