#include "../test_framework.h"
#include "state_manager.h"

TEST(state_manager_init) {
    ozayn_state_manager_t mgr = {0};
    ASSERT_EQ(ozayn_state_manager_init(&mgr, 1), 0);
    ASSERT(mgr.initialized);
    ozayn_state_manager_shutdown(&mgr);
    return 0;
}

TEST(state_create_entry) {
    ozayn_state_manager_t mgr = {0};
    ozayn_state_manager_init(&mgr, 1);
    uint32_t id = ozayn_state_create(&mgr, "test.entry", "test",
                                       OZAYN_STATE_NS_CORE, OZAYN_STATE_CAT_TRANSIENT,
                                       OZAYN_STATE_RECOVER_NEVER, "data", 4);
    ASSERT(id > 0);
    ASSERT_EQ(mgr.entry_count, 1);
    ozayn_state_manager_shutdown(&mgr);
    return 0;
}

TEST(state_get_value) {
    ozayn_state_manager_t mgr = {0};
    ozayn_state_manager_init(&mgr, 1);
    ozayn_state_create(&mgr, "test.key", "test",
                         OZAYN_STATE_NS_CORE, OZAYN_STATE_CAT_TRANSIENT,
                         OZAYN_STATE_RECOVER_NEVER, "hello", 5);
    const ozayn_state_entry_t *e = ozayn_state_get(&mgr, "test.key");
    ASSERT_NOT_NULL(e);
    ASSERT_STR_EQ(e->key, "test.key");
    ozayn_state_manager_shutdown(&mgr);
    return 0;
}

TEST(state_update_value) {
    ozayn_state_manager_t mgr = {0};
    ozayn_state_manager_init(&mgr, 1);
    ozayn_state_create(&mgr, "test.key", "test",
                         OZAYN_STATE_NS_CORE, OZAYN_STATE_CAT_TRANSIENT,
                         OZAYN_STATE_RECOVER_NEVER, "old", 3);
    ASSERT_EQ(ozayn_state_update(&mgr, "test.key", "new", 3), 0);
    const ozayn_state_entry_t *e = ozayn_state_get(&mgr, "test.key");
    ASSERT_NOT_NULL(e);
    ozayn_state_manager_shutdown(&mgr);
    return 0;
}

TEST(state_get_nonexistent) {
    ozayn_state_manager_t mgr = {0};
    ozayn_state_manager_init(&mgr, 1);
    ASSERT_NULL(ozayn_state_get(&mgr, "nonexistent"));
    ozayn_state_manager_shutdown(&mgr);
    return 0;
}

TEST(state_delete) {
    ozayn_state_manager_t mgr = {0};
    ozayn_state_manager_init(&mgr, 1);
    ozayn_state_create(&mgr, "test.key", "test",
                         OZAYN_STATE_NS_CORE, OZAYN_STATE_CAT_TRANSIENT,
                         OZAYN_STATE_RECOVER_NEVER, "data", 4);
    ASSERT_EQ(mgr.entry_count, 1);
    ASSERT_EQ(ozayn_state_delete(&mgr, "test.key"), 0);
    ASSERT_EQ(mgr.entry_count, 0);
    ASSERT_NULL(ozayn_state_get(&mgr, "test.key"));
    ozayn_state_manager_shutdown(&mgr);
    return 0;
}

TEST(state_stats) {
    ozayn_state_manager_t mgr = {0};
    ozayn_state_manager_init(&mgr, 1);
    ozayn_state_create(&mgr, "a", "test", OZAYN_STATE_NS_CORE,
                         OZAYN_STATE_CAT_TRANSIENT, OZAYN_STATE_RECOVER_NEVER, "1", 1);
    ozayn_state_create(&mgr, "b", "test", OZAYN_STATE_NS_CORE,
                         OZAYN_STATE_CAT_PERSISTENT, OZAYN_STATE_RECOVER_ON_RESTART, "2", 1);
    ozayn_state_stats_t s = ozayn_state_manager_stats(&mgr);
    ASSERT_EQ(s.total_entries, 2);
    ASSERT_EQ(s.persistent_entries, 1);
    ozayn_state_manager_shutdown(&mgr);
    return 0;
}

TEST(state_category_names) {
    ASSERT_STR_EQ(ozayn_state_category_name(OZAYN_STATE_CAT_TRANSIENT), "TRANSIENT");
    ASSERT_STR_EQ(ozayn_state_category_name(OZAYN_STATE_CAT_PERSISTENT), "PERSISTENT");
    ASSERT_STR_EQ(ozayn_state_category_name(OZAYN_STATE_CAT_RECOVERABLE), "RECOVERABLE");
    return 0;
}

TEST(state_namespace_names) {
    ASSERT_NOT_NULL(ozayn_state_namespace_name(OZAYN_STATE_NS_CORE));
    ASSERT_NOT_NULL(ozayn_state_namespace_name(OZAYN_STATE_NS_SECURITY));
    ASSERT_NOT_NULL(ozayn_state_namespace_name(OZAYN_STATE_NS_PLUGINS));
    return 0;
}

TEST(state_recovery_names) {
    ASSERT_STR_EQ(ozayn_state_recovery_name(OZAYN_STATE_RECOVER_NEVER), "NEVER");
    ASSERT_STR_EQ(ozayn_state_recovery_name(OZAYN_STATE_RECOVER_ON_FAILURE), "ON_FAILURE");
    ASSERT_STR_EQ(ozayn_state_recovery_name(OZAYN_STATE_RECOVER_ON_RESTART), "ON_RESTART");
    ASSERT_STR_EQ(ozayn_state_recovery_name(OZAYN_STATE_RECOVER_ALWAYS), "ALWAYS");
    return 0;
}

int run_state_manager_tests(void) {
    SUITE_BEGIN("State Manager");
    RUN(state_manager_init);
    RUN(state_create_entry);
    RUN(state_get_value);
    RUN(state_update_value);
    RUN(state_get_nonexistent);
    RUN(state_delete);
    RUN(state_stats);
    RUN(state_category_names);
    RUN(state_namespace_names);
    RUN(state_recovery_names);
    SUITE_END();
    return _tf_suite_fail;
}
