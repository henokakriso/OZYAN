#include "../test_framework.h"
#include "plugins.h"

TEST(plugin_manager_init) {
    ozayn_plugin_manager_t mgr;
    ASSERT_EQ(ozayn_plugin_manager_init(&mgr), OZAYN_OK);
    ASSERT(mgr.initialized);
    ASSERT_EQ(ozayn_plugin_manager_count(&mgr), 0);
    ozayn_plugin_manager_shutdown(&mgr);
    return 0;
}

TEST(plugin_state_names) {
    ASSERT_STR_EQ(ozayn_plugin_state_name(OZAYN_PLUGIN_DISCOVERED), "DISCOVERED");
    ASSERT_STR_EQ(ozayn_plugin_state_name(OZAYN_PLUGIN_VALIDATED), "VALIDATED");
    ASSERT_STR_EQ(ozayn_plugin_state_name(OZAYN_PLUGIN_LOADED), "LOADED");
    ASSERT_STR_EQ(ozayn_plugin_state_name(OZAYN_PLUGIN_INITIALIZED), "INITIALIZED");
    ASSERT_STR_EQ(ozayn_plugin_state_name(OZAYN_PLUGIN_RUNNING), "RUNNING");
    ASSERT_STR_EQ(ozayn_plugin_state_name(OZAYN_PLUGIN_STOPPING), "STOPPING");
    ASSERT_STR_EQ(ozayn_plugin_state_name(OZAYN_PLUGIN_STOPPED), "STOPPED");
    ASSERT_STR_EQ(ozayn_plugin_state_name(OZAYN_PLUGIN_UNLOADED), "UNLOADED");
    ASSERT_STR_EQ(ozayn_plugin_state_name(OZAYN_PLUGIN_INVALID), "INVALID");
    ASSERT_STR_EQ(ozayn_plugin_state_name(OZAYN_PLUGIN_INCOMPATIBLE), "INCOMPATIBLE");
    ASSERT_STR_EQ(ozayn_plugin_state_name(OZAYN_PLUGIN_FAILED), "FAILED");
    return 0;
}

TEST(plugin_manager_find_nonexistent) {
    ozayn_plugin_manager_t mgr;
    ozayn_plugin_manager_init(&mgr);
    ASSERT_NULL(ozayn_plugin_manager_find(&mgr, "nonexistent"));
    ozayn_plugin_manager_shutdown(&mgr);
    return 0;
}

TEST(plugin_manager_discover_empty_dir) {
    ozayn_plugin_manager_t mgr;
    ozayn_plugin_manager_init(&mgr);
    /* Empty or non-existent directory should not crash */
    int n = ozayn_plugin_manager_discover(&mgr, "/tmp/nonexistent_plugins_dir");
    ASSERT(n >= 0);
    ozayn_plugin_manager_shutdown(&mgr);
    return 0;
}

TEST(plugin_manager_active_count) {
    ozayn_plugin_manager_t mgr;
    ozayn_plugin_manager_init(&mgr);
    ASSERT_EQ(ozayn_plugin_manager_active_count(&mgr), 0);
    ozayn_plugin_manager_shutdown(&mgr);
    return 0;
}

TEST(plugin_manager_get_null) {
    ozayn_plugin_manager_t mgr;
    ozayn_plugin_manager_init(&mgr);
    ASSERT_NULL(ozayn_plugin_manager_get(&mgr, 0));
    ozayn_plugin_manager_shutdown(&mgr);
    return 0;
}

int run_plugins_tests(void) {
    SUITE_BEGIN("Plugins");
    RUN(plugin_manager_init);
    RUN(plugin_state_names);
    RUN(plugin_manager_find_nonexistent);
    RUN(plugin_manager_discover_empty_dir);
    RUN(plugin_manager_active_count);
    RUN(plugin_manager_get_null);
    SUITE_END();
    return _tf_suite_fail;
}
