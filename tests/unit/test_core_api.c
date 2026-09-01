#include "../test_framework.h"
#include "core_api.h"

TEST(api_init) {
    ozayn_api_manager_t mgr;
    ASSERT_EQ(ozayn_api_init(&mgr), 0);
    ASSERT(mgr.next_request_id > 0);
    ozayn_api_shutdown(&mgr);
    return 0;
}

TEST(api_register_interface) {
    ozayn_api_manager_t mgr;
    ozayn_api_init(&mgr);
    ozayn_api_version_t ver = { .major = 1, .minor = 0, .patch = 0 };
    int r = ozayn_api_register(&mgr, "scheduler", "core", &ver,
                                  OZAYN_API_STABLE, "Task scheduler");
    ASSERT_EQ(r, 0);
    ASSERT_NOT_NULL(ozayn_api_find_interface(&mgr, "scheduler"));
    ASSERT_NULL(ozayn_api_find_interface(&mgr, "nonexistent"));
    ozayn_api_shutdown(&mgr);
    return 0;
}

TEST(api_add_method) {
    ozayn_api_manager_t mgr;
    ozayn_api_init(&mgr);
    ozayn_api_version_t ver = { .major = 1, .minor = 0, .patch = 0 };
    ozayn_api_register(&mgr, "sched", "core", &ver, OZAYN_API_STABLE, "Scheduler");
    ASSERT_EQ(ozayn_api_add_method(&mgr, "sched", OZAYN_METHOD_GET), 0);
    ASSERT_EQ(ozayn_api_add_method(&mgr, "sched", OZAYN_METHOD_SET), 0);
    const ozayn_api_interface_t *iface = ozayn_api_find_interface(&mgr, "sched");
    ASSERT_NOT_NULL(iface);
    ASSERT_EQ(iface->method_count, 2);
    ozayn_api_shutdown(&mgr);
    return 0;
}

TEST(api_request_flow) {
    ozayn_api_manager_t mgr;
    ozayn_api_init(&mgr);
    uint32_t req_id = ozayn_api_request_begin(&mgr, "test", "sched", "submit",
                                                OZAYN_METHOD_CALL);
    ASSERT(req_id > 0);
    ASSERT_EQ(ozayn_api_request_complete(&mgr, req_id, OZAYN_API_ERR_OK, ""), 0);
    ozayn_api_shutdown(&mgr);
    return 0;
}

TEST(api_check_compat) {
    ozayn_api_version_t v1 = { .major = 1, .minor = 2, .patch = 3, .revision = 100 };
    ozayn_api_version_t v2 = { .major = 1, .minor = 2, .patch = 3, .revision = 100 };
    ASSERT_EQ(ozayn_api_check_compat(&v1, &v2), OZAYN_API_COMPAT_OK);

    ozayn_api_version_t v3 = { .major = 1, .minor = 2, .patch = 3, .revision = 200 };
    ASSERT_EQ(ozayn_api_check_compat(&v1, &v3), OZAYN_API_COMPAT_REVISION_DIFF);

    ozayn_api_version_t v4 = { .major = 2, .minor = 0, .patch = 0 };
    ASSERT_EQ(ozayn_api_check_compat(&v1, &v4), OZAYN_API_COMPAT_INCOMPATIBLE);
    return 0;
}

TEST(api_unregister) {
    ozayn_api_manager_t mgr;
    ozayn_api_init(&mgr);
    ozayn_api_version_t ver = { .major = 1, .minor = 0, .patch = 0 };
    ozayn_api_register(&mgr, "svc", "test", &ver, OZAYN_API_STABLE, "desc");
    ASSERT_EQ(ozayn_api_unregister(&mgr, "svc"), 0);
    ASSERT_NULL(ozayn_api_find_interface(&mgr, "svc"));
    ozayn_api_shutdown(&mgr);
    return 0;
}

TEST(api_stats) {
    ozayn_api_manager_t mgr;
    ozayn_api_init(&mgr);
    ozayn_api_stats_t s = ozayn_api_stats(&mgr);
    ASSERT_EQ(s.total_interfaces, 0);
    ASSERT_EQ(s.total_requests, 0);
    ozayn_api_shutdown(&mgr);
    return 0;
}

TEST(api_error_names) {
    ASSERT_STR_EQ(ozayn_api_error_name(OZAYN_API_ERR_OK), "OK");
    ASSERT_STR_EQ(ozayn_api_error_name(OZAYN_API_ERR_NULL), "NULL");
    ASSERT_STR_EQ(ozayn_api_error_name(OZAYN_API_ERR_NOT_FOUND), "NOT_FOUND");
    ASSERT_STR_EQ(ozayn_api_error_name(OZAYN_API_ERR_FULL), "FULL");
    return 0;
}

TEST(api_method_names) {
    ASSERT_STR_EQ(ozayn_api_method_name(OZAYN_METHOD_GET), "GET");
    ASSERT_STR_EQ(ozayn_api_method_name(OZAYN_METHOD_SET), "SET");
    ASSERT_STR_EQ(ozayn_api_method_name(OZAYN_METHOD_CALL), "CALL");
    ASSERT_STR_EQ(ozayn_api_method_name(OZAYN_METHOD_START), "START");
    ASSERT_STR_EQ(ozayn_api_method_name(OZAYN_METHOD_STOP), "STOP");
    return 0;
}

TEST(api_stability_names) {
    ASSERT_STR_EQ(ozayn_api_stability_name(OZAYN_API_STABLE), "STABLE");
    ASSERT_STR_EQ(ozayn_api_stability_name(OZAYN_API_EXPERIMENTAL), "EXPERIMENTAL");
    ASSERT_STR_EQ(ozayn_api_stability_name(OZAYN_API_DEPRECATED), "DEPRECATED");
    ASSERT_STR_EQ(ozayn_api_stability_name(OZAYN_API_INTERNAL), "INTERNAL");
    return 0;
}

TEST(api_compat_names) {
    ASSERT_STR_EQ(ozayn_api_compat_name(OZAYN_API_COMPAT_OK), "OK");
    ASSERT_STR_EQ(ozayn_api_compat_name(OZAYN_API_COMPAT_INCOMPATIBLE), "INCOMPATIBLE");
    return 0;
}

TEST(api_request_status_names) {
    ASSERT_STR_EQ(ozayn_api_req_status_name(OZAYN_REQ_PENDING), "PENDING");
    ASSERT_STR_EQ(ozayn_api_req_status_name(OZAYN_REQ_COMPLETED), "COMPLETED");
    ASSERT_STR_EQ(ozayn_api_req_status_name(OZAYN_REQ_FAILED), "FAILED");
    return 0;
}

int run_core_api_tests(void) {
    SUITE_BEGIN("Core API");
    RUN(api_init);
    RUN(api_register_interface);
    RUN(api_add_method);
    RUN(api_request_flow);
    RUN(api_check_compat);
    RUN(api_unregister);
    RUN(api_stats);
    RUN(api_error_names);
    RUN(api_method_names);
    RUN(api_stability_names);
    RUN(api_compat_names);
    RUN(api_request_status_names);
    SUITE_END();
    return _tf_suite_fail;
}
