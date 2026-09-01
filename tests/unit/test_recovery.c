#include "../test_framework.h"
#include "recovery.h"

TEST(recovery_init) {
    ozayn_recovery_t rec;
    ozayn_recovery_init(&rec);
    ASSERT_EQ(rec.total_errors, 0);
    ASSERT_EQ(rec.has_error, 0);
    ASSERT_EQ(rec.consecutive_retries, 0);
    return 0;
}

TEST(recovery_raise_records_error) {
    ozayn_recovery_t rec;
    ozayn_recovery_init(&rec);
    ozayn_recovery_raise(&rec, OZAYN_ERRCAT_CONFIG, OZAYN_LOG_ERROR,
                          OZAYN_SCOPE_COMPONENT, "test", "test error");
    ASSERT_EQ(rec.total_errors, 1);
    ASSERT_EQ(rec.has_error, 1);
    ASSERT_EQ(rec.last_error.category, OZAYN_ERRCAT_CONFIG);
    return 0;
}

TEST(recovery_raise_multiple) {
    ozayn_recovery_t rec;
    ozayn_recovery_init(&rec);
    ozayn_recovery_raise(&rec, OZAYN_ERRCAT_CONFIG, OZAYN_LOG_ERROR,
                          OZAYN_SCOPE_COMPONENT, "test", "err1");
    ozayn_recovery_raise(&rec, OZAYN_ERRCAT_RUNTIME, OZAYN_LOG_ERROR,
                          OZAYN_SCOPE_COMPONENT, "test", "err2");
    ASSERT_EQ(rec.total_errors, 2);
    ASSERT_EQ(rec.last_error.category, OZAYN_ERRCAT_RUNTIME);
    return 0;
}

TEST(recovery_evaluate_returns_action) {
    ozayn_recovery_t rec;
    ozayn_recovery_init(&rec);
    ozayn_recovery_action_t a = ozayn_recovery_evaluate(&rec);
    ASSERT(a == OZAYN_RECOVERY_IGNORE || a == OZAYN_RECOVERY_RETRY);
    return 0;
}

TEST(recovery_clear_resets) {
    ozayn_recovery_t rec;
    ozayn_recovery_init(&rec);
    ozayn_recovery_raise(&rec, OZAYN_ERRCAT_CONFIG, OZAYN_LOG_ERROR,
                          OZAYN_SCOPE_COMPONENT, "test", "err");
    ozayn_recovery_clear(&rec);
    ASSERT_EQ(rec.has_error, 0);
    return 0;
}

TEST(recovery_should_shutdown) {
    ozayn_recovery_t rec;
    ozayn_recovery_init(&rec);
    ASSERT_EQ(ozayn_recovery_should_shutdown(&rec), 0);
    return 0;
}

TEST(recovery_errcat_names) {
    ASSERT_STR_EQ(ozayn_errcat_name(OZAYN_ERRCAT_CONFIG), "CONFIG");
    ASSERT_STR_EQ(ozayn_errcat_name(OZAYN_ERRCAT_RUNTIME), "RUNTIME");
    ASSERT_STR_EQ(ozayn_errcat_name(OZAYN_ERRCAT_SECURITY), "SECURITY");
    ASSERT_STR_EQ(ozayn_errcat_name(OZAYN_ERRCAT_INTERNAL), "INTERNAL");
    return 0;
}

TEST(recovery_scope_names) {
    ASSERT_STR_EQ(ozayn_scope_name(OZAYN_SCOPE_OPERATION), "OPERATION");
    ASSERT_STR_EQ(ozayn_scope_name(OZAYN_SCOPE_COMPONENT), "COMPONENT");
    ASSERT_STR_EQ(ozayn_scope_name(OZAYN_SCOPE_SUBSYSTEM), "SUBSYSTEM");
    ASSERT_STR_EQ(ozayn_scope_name(OZAYN_SCOPE_CORE), "CORE");
    return 0;
}

TEST(recovery_action_names) {
    ASSERT_STR_EQ(ozayn_recovery_action_name(OZAYN_RECOVERY_IGNORE), "IGNORE");
    ASSERT_STR_EQ(ozayn_recovery_action_name(OZAYN_RECOVERY_RETRY), "RETRY");
    ASSERT_STR_EQ(ozayn_recovery_action_name(OZAYN_RECOVERY_SHUTDOWN), "SHUTDOWN");
    return 0;
}

int run_recovery_tests(void) {
    SUITE_BEGIN("Recovery");
    RUN(recovery_init);
    RUN(recovery_raise_records_error);
    RUN(recovery_raise_multiple);
    RUN(recovery_evaluate_returns_action);
    RUN(recovery_clear_resets);
    RUN(recovery_should_shutdown);
    RUN(recovery_errcat_names);
    RUN(recovery_scope_names);
    RUN(recovery_action_names);
    SUITE_END();
    return _tf_suite_fail;
}
