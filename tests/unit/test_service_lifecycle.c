#include "../test_framework.h"
#include "service_lifecycle.h"

TEST(lc_init) {
    ozayn_svc_lc_manager_t mgr = {0};
    ozayn_svc_lc_config_t cfg = { .max_services = 64, .max_groups = 16 };
    ASSERT_EQ(ozayn_svc_lc_init(&mgr, &cfg), 0);
    ozayn_svc_lc_shutdown(&mgr);
    return 0;
}

TEST(lc_state_names) {
    ASSERT_STR_EQ(ozayn_svc_state_name(OZAYN_SVC_STATE_UNREGISTERED), "UNREGISTERED");
    ASSERT_STR_EQ(ozayn_svc_state_name(OZAYN_SVC_STATE_REGISTERED), "REGISTERED");
    ASSERT_STR_EQ(ozayn_svc_state_name(OZAYN_SVC_STATE_INITIALIZING), "INITIALIZING");
    ASSERT_STR_EQ(ozayn_svc_state_name(OZAYN_SVC_STATE_RUNNING), "RUNNING");
    ASSERT_STR_EQ(ozayn_svc_state_name(OZAYN_SVC_STATE_DRAINING), "DRAINING");
    ASSERT_STR_EQ(ozayn_svc_state_name(OZAYN_SVC_STATE_STOPPING), "STOPPING");
    ASSERT_STR_EQ(ozayn_svc_state_name(OZAYN_SVC_STATE_STOPPED), "STOPPED");
    ASSERT_STR_EQ(ozayn_svc_state_name(OZAYN_SVC_STATE_FAILED), "FAILED");
    ASSERT_STR_EQ(ozayn_svc_state_name(OZAYN_SVC_STATE_RESTARTING), "RESTARTING");
    ASSERT_STR_EQ(ozayn_svc_state_name(OZAYN_SVC_STATE_SUSPENDED), "SUSPENDED");
    return 0;
}

TEST(lc_restart_policy_names) {
    ASSERT_STR_EQ(ozayn_svc_restart_policy_name(OZAYN_SVC_RESTART_NEVER), "NEVER");
    ASSERT_STR_EQ(ozayn_svc_restart_policy_name(OZAYN_SVC_RESTART_ON_FAILURE), "ON_FAILURE");
    ASSERT_STR_EQ(ozayn_svc_restart_policy_name(OZAYN_SVC_RESTART_ALWAYS), "ALWAYS");
    return 0;
}

TEST(lc_health_names) {
    ASSERT_STR_EQ(ozayn_svc_health_name(OZAYN_SVC_HEALTH_UNKNOWN), "UNKNOWN");
    ASSERT_STR_EQ(ozayn_svc_health_name(OZAYN_SVC_HEALTH_HEALTHY), "HEALTHY");
    ASSERT_STR_EQ(ozayn_svc_health_name(OZAYN_SVC_HEALTH_DEGRADED), "DEGRADED");
    ASSERT_STR_EQ(ozayn_svc_health_name(OZAYN_SVC_HEALTH_UNHEALTHY), "UNHEALTHY");
    return 0;
}

TEST(lc_register_service) {
    ozayn_svc_lc_manager_t mgr = {0};
    ozayn_svc_lc_config_t cfg = { .max_services = 64, .max_groups = 16 };
    ozayn_svc_lc_init(&mgr, &cfg);
    ozayn_svc_config_t svc_cfg = {
        .name = "svc1",
        .version = "1.0.0",
        .restart_policy = OZAYN_SVC_RESTART_NEVER,
        .max_restarts = 3,
        .restart_window_ms = 60000,
        .drain_timeout_ms = 5000,
        .health_check_ms = 1000,
        .required = 0,
    };
    ASSERT_EQ(ozayn_svc_lc_register(&mgr, &svc_cfg), 0);
    ASSERT(mgr.services[0].active);
    ozayn_svc_lc_shutdown(&mgr);
    return 0;
}

TEST(lc_find_service) {
    ozayn_svc_lc_manager_t mgr = {0};
    ozayn_svc_lc_config_t cfg = { .max_services = 64, .max_groups = 16 };
    ozayn_svc_lc_init(&mgr, &cfg);
    ozayn_svc_config_t svc_cfg = {
        .name = "svc1", .version = "1.0",
        .restart_policy = OZAYN_SVC_RESTART_NEVER,
        .max_restarts = 0, .restart_window_ms = 0,
        .drain_timeout_ms = 0, .health_check_ms = 0, .required = 0,
    };
    ozayn_svc_lc_register(&mgr, &svc_cfg);
    const ozayn_svc_record_t *rec = ozayn_svc_lc_find(&mgr, "svc1");
    ASSERT_NOT_NULL(rec);
    ASSERT_STR_EQ(rec->name, "svc1");
    ASSERT_NULL(ozayn_svc_lc_find(&mgr, "nonexistent"));
    ozayn_svc_lc_shutdown(&mgr);
    return 0;
}

TEST(lc_stats) {
    ozayn_svc_lc_manager_t mgr = {0};
    ozayn_svc_lc_config_t cfg = { .max_services = 64, .max_groups = 16 };
    ozayn_svc_lc_init(&mgr, &cfg);
    ozayn_svc_lc_stats_t s = ozayn_svc_lc_stats(&mgr);
    ASSERT_EQ(s.total_services, 0);
    ASSERT_EQ(s.total_restarts, 0);
    ozayn_svc_lc_shutdown(&mgr);
    return 0;
}

int run_service_lifecycle_tests(void) {
    SUITE_BEGIN("Service Lifecycle");
    RUN(lc_init);
    RUN(lc_state_names);
    RUN(lc_restart_policy_names);
    RUN(lc_health_names);
    RUN(lc_register_service);
    RUN(lc_find_service);
    RUN(lc_stats);
    SUITE_END();
    return _tf_suite_fail;
}
