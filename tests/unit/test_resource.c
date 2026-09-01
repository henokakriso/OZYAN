#include "../test_framework.h"
#include "resource.h"

TEST(resource_manager_init) {
    ozayn_resource_manager_t mgr;
    ASSERT_EQ(ozayn_resource_manager_init(&mgr, 1), OZAYN_OK);
    ASSERT(mgr.initialized);
    ozayn_resource_manager_shutdown(&mgr);
    return 0;
}

TEST(resource_create) {
    ozayn_resource_manager_t mgr;
    ozayn_resource_manager_init(&mgr, 1);
    ozayn_resource_result_t r = ozayn_resource_create(&mgr, "r1", "Test Resource",
                                                       OZAYN_RESOURCE_TYPE_DEVICE, 1);
    ASSERT_EQ(r, OZAYN_RESOURCE_OK);
    ASSERT(ozayn_resource_exists(&mgr, "r1"));
    ozayn_resource_manager_shutdown(&mgr);
    return 0;
}

TEST(resource_create_duplicate) {
    ozayn_resource_manager_t mgr;
    ozayn_resource_manager_init(&mgr, 1);
    ozayn_resource_create(&mgr, "r1", "Test", OZAYN_RESOURCE_TYPE_DEVICE, 1);
    ozayn_resource_result_t r = ozayn_resource_create(&mgr, "r1", "Test2",
                                                       OZAYN_RESOURCE_TYPE_DEVICE, 1);
    ASSERT_NEQ(r, OZAYN_RESOURCE_OK);
    ozayn_resource_manager_shutdown(&mgr);
    return 0;
}

TEST(resource_allocate) {
    ozayn_resource_manager_t mgr;
    ozayn_resource_manager_init(&mgr, 1);
    ozayn_resource_create(&mgr, "r1", "Test", OZAYN_RESOURCE_TYPE_DEVICE, 1);
    ozayn_resource_result_t r = ozayn_resource_allocate(&mgr, "r1", "owner1");
    ASSERT_EQ(r, OZAYN_RESOURCE_OK);
    ASSERT_STR_EQ(ozayn_resource_owner(&mgr, "r1"), "owner1");
    ozayn_resource_manager_shutdown(&mgr);
    return 0;
}

TEST(resource_activate) {
    ozayn_resource_manager_t mgr;
    ozayn_resource_manager_init(&mgr, 1);
    ozayn_resource_create(&mgr, "r1", "Test", OZAYN_RESOURCE_TYPE_DEVICE, 1);
    ozayn_resource_allocate(&mgr, "r1", "owner1");
    ozayn_resource_result_t r = ozayn_resource_activate(&mgr, "r1", "owner1");
    ASSERT_EQ(r, OZAYN_RESOURCE_OK);
    ozayn_resource_manager_shutdown(&mgr);
    return 0;
}

TEST(resource_release) {
    ozayn_resource_manager_t mgr;
    ozayn_resource_manager_init(&mgr, 1);
    ozayn_resource_create(&mgr, "r1", "Test", OZAYN_RESOURCE_TYPE_DEVICE, 1);
    ozayn_resource_allocate(&mgr, "r1", "owner1");
    ozayn_resource_result_t r = ozayn_resource_release(&mgr, "r1", "owner1");
    ASSERT_EQ(r, OZAYN_RESOURCE_OK);
    ozayn_resource_manager_shutdown(&mgr);
    return 0;
}

TEST(resource_not_found) {
    ozayn_resource_manager_t mgr;
    ozayn_resource_manager_init(&mgr, 1);
    ozayn_resource_result_t r = ozayn_resource_allocate(&mgr, "nonexistent", "owner");
    ASSERT_EQ(r, OZAYN_RESOURCE_NOT_FOUND);
    ozayn_resource_manager_shutdown(&mgr);
    return 0;
}

TEST(resource_stats) {
    ozayn_resource_manager_t mgr;
    ozayn_resource_manager_init(&mgr, 1);
    ozayn_resource_create(&mgr, "r1", "Test1", OZAYN_RESOURCE_TYPE_DEVICE, 1);
    ozayn_resource_create(&mgr, "r2", "Test2", OZAYN_RESOURCE_TYPE_BUFFER, 1);
    ozayn_resource_stats_t s = ozayn_resource_manager_stats(&mgr);
    ASSERT_EQ(s.total, 2);
    ozayn_resource_manager_shutdown(&mgr);
    return 0;
}

TEST(resource_type_names) {
    ASSERT_STR_EQ(ozayn_resource_type_name(OZAYN_RESOURCE_TYPE_DEVICE), "DEVICE");
    ASSERT_STR_EQ(ozayn_resource_type_name(OZAYN_RESOURCE_TYPE_BUFFER), "BUFFER");
    ASSERT_STR_EQ(ozayn_resource_type_name(OZAYN_RESOURCE_TYPE_PROCESS), "PROCESS");
    return 0;
}

TEST(resource_state_names) {
    ASSERT_STR_EQ(ozayn_resource_state_name(OZAYN_RESOURCE_STATE_CREATED), "CREATED");
    ASSERT_STR_EQ(ozayn_resource_state_name(OZAYN_RESOURCE_STATE_AVAILABLE), "AVAILABLE");
    ASSERT_STR_EQ(ozayn_resource_state_name(OZAYN_RESOURCE_STATE_ALLOCATED), "ALLOCATED");
    ASSERT_STR_EQ(ozayn_resource_state_name(OZAYN_RESOURCE_STATE_ACTIVE), "ACTIVE");
    return 0;
}

int run_resource_tests(void) {
    SUITE_BEGIN("Resource Manager");
    RUN(resource_manager_init);
    RUN(resource_create);
    RUN(resource_create_duplicate);
    RUN(resource_allocate);
    RUN(resource_activate);
    RUN(resource_release);
    RUN(resource_not_found);
    RUN(resource_stats);
    RUN(resource_type_names);
    RUN(resource_state_names);
    SUITE_END();
    return _tf_suite_fail;
}
