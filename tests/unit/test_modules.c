#include "../test_framework.h"
#include "modules.h"

static ozayn_result_t dummy_init(void *e) { (void)e; return OZAYN_OK; }
static ozayn_result_t dummy_start(void *e) { (void)e; return OZAYN_OK; }
static void dummy_stop(void *e) { (void)e; }
static void dummy_shutdown(void *e) { (void)e; }

TEST(module_manager_init) {
    ozayn_module_manager_t mgr;
    ASSERT_EQ(ozayn_module_manager_init(&mgr), OZAYN_OK);
    ASSERT(mgr.initialized);
    ASSERT_EQ(ozayn_module_manager_count(&mgr), 0);
    ozayn_module_manager_shutdown(&mgr);
    return 0;
}

TEST(module_register) {
    ozayn_module_manager_t mgr;
    ozayn_module_manager_init(&mgr);
    ozayn_module_entry_t entry = {
        .name = "test_mod",
        .version = "1.0",
        .description = "Test module",
        .init = dummy_init,
        .start = dummy_start,
        .stop = dummy_stop,
        .shutdown = dummy_shutdown,
    };
    ASSERT_EQ(ozayn_module_manager_register(&mgr, &entry), OZAYN_OK);
    ASSERT_EQ(ozayn_module_manager_count(&mgr), 1);
    ozayn_module_manager_shutdown(&mgr);
    return 0;
}

TEST(module_find) {
    ozayn_module_manager_t mgr;
    ozayn_module_manager_init(&mgr);
    ozayn_module_entry_t entry = {
        .name = "test_mod", .version = "1.0", .description = "Test",
        .init = dummy_init, .start = dummy_start,
        .stop = dummy_stop, .shutdown = dummy_shutdown,
    };
    ozayn_module_manager_register(&mgr, &entry);
    const ozayn_module_record_t *rec = ozayn_module_manager_find(&mgr, "test_mod");
    ASSERT_NOT_NULL(rec);
    ASSERT_STR_EQ(rec->entry.name, "test_mod");
    ASSERT_NULL(ozayn_module_manager_find(&mgr, "nonexistent"));
    ozayn_module_manager_shutdown(&mgr);
    return 0;
}

TEST(module_unregister) {
    ozayn_module_manager_t mgr;
    ozayn_module_manager_init(&mgr);
    ozayn_module_entry_t entry = {
        .name = "test_mod", .version = "1.0", .description = "Test",
        .init = dummy_init, .start = dummy_start,
        .stop = dummy_stop, .shutdown = dummy_shutdown,
    };
    ozayn_module_manager_register(&mgr, &entry);
    ASSERT_EQ(ozayn_module_manager_count(&mgr), 1);
    ozayn_result_t r = ozayn_module_manager_unregister(&mgr, "test_mod");
    ASSERT_EQ(r, OZAYN_OK);
    ASSERT_EQ(ozayn_module_manager_count(&mgr), 0);
    ozayn_module_manager_shutdown(&mgr);
    return 0;
}

TEST(module_state_names) {
    ASSERT_STR_EQ(ozayn_module_state_name(OZAYN_MOD_REGISTERED), "REGISTERED");
    ASSERT_STR_EQ(ozayn_module_state_name(OZAYN_MOD_INITIALIZED), "INITIALIZED");
    ASSERT_STR_EQ(ozayn_module_state_name(OZAYN_MOD_RUNNING), "RUNNING");
    ASSERT_STR_EQ(ozayn_module_state_name(OZAYN_MOD_STOPPED), "STOPPED");
    ASSERT_STR_EQ(ozayn_module_state_name(OZAYN_MOD_SHUTDOWN), "SHUTDOWN");
    ASSERT_STR_EQ(ozayn_module_state_name(OZAYN_MOD_FAILED), "FAILED");
    return 0;
}

TEST(module_get_by_index) {
    ozayn_module_manager_t mgr;
    ozayn_module_manager_init(&mgr);
    ozayn_module_entry_t entry = {
        .name = "test_mod", .version = "1.0", .description = "Test",
        .init = dummy_init, .start = dummy_start,
        .stop = dummy_stop, .shutdown = dummy_shutdown,
    };
    ozayn_module_manager_register(&mgr, &entry);
    const ozayn_module_record_t *rec = ozayn_module_manager_get(&mgr, 0);
    ASSERT_NOT_NULL(rec);
    ASSERT_STR_EQ(rec->entry.name, "test_mod");
    ASSERT_NULL(ozayn_module_manager_get(&mgr, 99));
    ozayn_module_manager_shutdown(&mgr);
    return 0;
}

int run_modules_tests(void) {
    SUITE_BEGIN("Modules");
    RUN(module_manager_init);
    RUN(module_register);
    RUN(module_find);
    RUN(module_unregister);
    RUN(module_state_names);
    RUN(module_get_by_index);
    SUITE_END();
    return _tf_suite_fail;
}
