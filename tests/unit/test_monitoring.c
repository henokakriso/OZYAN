#include "../test_framework.h"
#include "monitoring.h"

TEST(monitoring_init) {
    ozayn_monitoring_manager_t mgr;
    ASSERT_EQ(ozayn_monitoring_init(&mgr, 1), OZAYN_OK);
    ASSERT(mgr.initialized);
    ASSERT(ozayn_monitoring_is_enabled(&mgr));
    ozayn_monitoring_shutdown(&mgr);
    return 0;
}

TEST(monitoring_report_health) {
    ozayn_monitoring_manager_t mgr;
    ozayn_monitoring_init(&mgr, 1);
    ozayn_result_t r = ozayn_monitoring_report_health(&mgr, OZAYN_COMP_SCHEDULER,
                                                       OZAYN_HEALTH_HEALTHY,
                                                       OZAYN_SEVERITY_INFO, "ok");
    ASSERT_EQ(r, OZAYN_OK);
    ozayn_health_state_t h = ozayn_monitoring_get_health(&mgr, OZAYN_COMP_SCHEDULER);
    ASSERT_EQ(h, OZAYN_HEALTH_HEALTHY);
    ozayn_monitoring_shutdown(&mgr);
    return 0;
}

TEST(monitoring_overall_health) {
    ozayn_monitoring_manager_t mgr;
    ozayn_monitoring_init(&mgr, 1);
    ozayn_monitoring_report_health(&mgr, OZAYN_COMP_SCHEDULER,
                                    OZAYN_HEALTH_HEALTHY, OZAYN_SEVERITY_INFO, "ok");
    ozayn_health_state_t overall = ozayn_monitoring_overall_health(&mgr);
    ASSERT(overall == OZAYN_HEALTH_HEALTHY || overall == OZAYN_HEALTH_UNKNOWN);
    ozayn_monitoring_shutdown(&mgr);
    return 0;
}

TEST(monitoring_register_metric) {
    ozayn_monitoring_manager_t mgr;
    ozayn_monitoring_init(&mgr, 1);
    ozayn_result_t r = ozayn_monitoring_register_metric(&mgr, "test.counter",
                                                         OZAYN_METRIC_COUNTER,
                                                         OZAYN_COMP_SCHEDULER);
    ASSERT_EQ(r, OZAYN_OK);
    ASSERT_EQ(ozayn_monitoring_metric_count(&mgr), 1);
    ozayn_monitoring_shutdown(&mgr);
    return 0;
}

TEST(monitoring_update_metric) {
    ozayn_monitoring_manager_t mgr;
    ozayn_monitoring_init(&mgr, 1);
    ozayn_monitoring_register_metric(&mgr, "test.gauge", OZAYN_METRIC_GAUGE,
                                      OZAYN_COMP_SCHEDULER);
    ozayn_monitoring_update_metric(&mgr, "test.gauge", 42);
    const ozayn_metric_record_t *m = ozayn_monitoring_get_metric(&mgr, "test.gauge");
    ASSERT_NOT_NULL(m);
    ASSERT_EQ(m->value, 42);
    ozayn_monitoring_shutdown(&mgr);
    return 0;
}

TEST(monitoring_increment_metric) {
    ozayn_monitoring_manager_t mgr;
    ozayn_monitoring_init(&mgr, 1);
    ozayn_monitoring_register_metric(&mgr, "test.counter", OZAYN_METRIC_COUNTER,
                                      OZAYN_COMP_SCHEDULER);
    ozayn_monitoring_increment_metric(&mgr, "test.counter", 5);
    ozayn_monitoring_increment_metric(&mgr, "test.counter", 3);
    const ozayn_metric_record_t *m = ozayn_monitoring_get_metric(&mgr, "test.counter");
    ASSERT_NOT_NULL(m);
    ASSERT_EQ(m->value, 8);
    ozayn_monitoring_shutdown(&mgr);
    return 0;
}

TEST(monitoring_create_incident) {
    ozayn_monitoring_manager_t mgr;
    ozayn_monitoring_init(&mgr, 1);
    ozayn_result_t r = ozayn_monitoring_create_incident(&mgr, OZAYN_COMP_SCHEDULER,
                                                         OZAYN_SEVERITY_ERROR, "test failure");
    ASSERT_EQ(r, OZAYN_OK);
    ASSERT_EQ(mgr.incident_count, 1);
    ozayn_monitoring_shutdown(&mgr);
    return 0;
}

TEST(monitoring_stats) {
    ozayn_monitoring_manager_t mgr;
    ozayn_monitoring_init(&mgr, 1);
    ozayn_monitoring_report_health(&mgr, OZAYN_COMP_SCHEDULER,
                                    OZAYN_HEALTH_HEALTHY, OZAYN_SEVERITY_INFO, "ok");
    ozayn_monitor_stats_t s = ozayn_monitoring_stats(&mgr);
    ASSERT(s.total_checks >= 0);
    ozayn_monitoring_shutdown(&mgr);
    return 0;
}

TEST(monitoring_health_names) {
    ASSERT_STR_EQ(ozayn_health_state_name(OZAYN_HEALTH_HEALTHY), "HEALTHY");
    ASSERT_STR_EQ(ozayn_health_state_name(OZAYN_HEALTH_DEGRADED), "DEGRADED");
    ASSERT_STR_EQ(ozayn_health_state_name(OZAYN_HEALTH_UNHEALTHY), "UNHEALTHY");
    ASSERT_STR_EQ(ozayn_health_state_name(OZAYN_HEALTH_FAILED), "FAILED");
    return 0;
}

TEST(monitoring_metric_type_names) {
    ASSERT_STR_EQ(ozayn_metric_type_name(OZAYN_METRIC_COUNTER), "COUNTER");
    ASSERT_STR_EQ(ozayn_metric_type_name(OZAYN_METRIC_GAUGE), "GAUGE");
    return 0;
}

TEST(monitoring_severity_names) {
    ASSERT_STR_EQ(ozayn_severity_name(OZAYN_SEVERITY_INFO), "INFO");
    ASSERT_STR_EQ(ozayn_severity_name(OZAYN_SEVERITY_WARNING), "WARNING");
    ASSERT_STR_EQ(ozayn_severity_name(OZAYN_SEVERITY_ERROR), "ERROR");
    ASSERT_STR_EQ(ozayn_severity_name(OZAYN_SEVERITY_CRITICAL), "CRITICAL");
    return 0;
}

int run_monitoring_tests(void) {
    SUITE_BEGIN("Monitoring");
    RUN(monitoring_init);
    RUN(monitoring_report_health);
    RUN(monitoring_overall_health);
    RUN(monitoring_register_metric);
    RUN(monitoring_update_metric);
    RUN(monitoring_increment_metric);
    RUN(monitoring_create_incident);
    RUN(monitoring_stats);
    RUN(monitoring_health_names);
    RUN(monitoring_metric_type_names);
    RUN(monitoring_severity_names);
    SUITE_END();
    return _tf_suite_fail;
}
