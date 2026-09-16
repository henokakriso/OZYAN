/*
 * test_operational_metrics.c — Section 04, Step 26
 * Operational Metrics & Performance Monitoring Foundation tests
 */

#include "../../tests/test_framework.h"
#include "../operational_metrics.h"
#include <string.h>

/* ============================================================
 * HELPERS
 * ============================================================ */

static ozayn_om_service_t _make_svc(void) {
    ozayn_om_service_t svc;
    memset(&svc, 0, sizeof(svc));
    return svc;
}

/* ============================================================
 * NAME HELPER TESTS
 * ============================================================ */

TEST(test_err_name) {
    ASSERT(strcmp(ozayn_om_err_name(OZAYN_OM_ERR_OK), "OK") == 0);
    ASSERT(strcmp(ozayn_om_err_name(OZAYN_OM_ERR_NULL_PTR), "NULL_PTR") == 0);
    ASSERT(strcmp(ozayn_om_err_name(OZAYN_OM_ERR_NOT_INITIALIZED), "NOT_INITIALIZED") == 0);
    ASSERT(strcmp(ozayn_om_err_name(OZAYN_OM_ERR_ALREADY_INITIALIZED), "ALREADY_INITIALIZED") == 0);
    ASSERT(strcmp(ozayn_om_err_name(OZAYN_OM_ERR_NOT_FOUND), "NOT_FOUND") == 0);
    ASSERT(strcmp(ozayn_om_err_name(OZAYN_OM_ERR_FULL), "FULL") == 0);
    ASSERT(strcmp(ozayn_om_err_name(OZAYN_OM_ERR_DUPLICATE), "DUPLICATE") == 0);
    ASSERT(strcmp(ozayn_om_err_name(OZAYN_OM_ERR_INVALID_TYPE), "INVALID_TYPE") == 0);
    ASSERT(strcmp(ozayn_om_err_name(OZAYN_OM_ERR_INVALID_VALUE), "INVALID_VALUE") == 0);
    ASSERT(strcmp(ozayn_om_err_name(OZAYN_OM_ERR_OVERFLOW), "OVERFLOW") == 0);
    ASSERT(strcmp(ozayn_om_err_name(OZAYN_OM_ERR_STORAGE_ERROR), "STORAGE_ERROR") == 0);
    ASSERT(strcmp(ozayn_om_err_name(OZAYN_OM_ERR_QUERY_INVALID), "QUERY_INVALID") == 0);
    ASSERT(strcmp(ozayn_om_err_name(OZAYN_OM_ERR_QUERY_LIMIT), "QUERY_LIMIT") == 0);
    ASSERT(strcmp(ozayn_om_err_name(OZAYN_OM_ERR_SUBSYSTEM_UNAVAILABLE), "SUBSYSTEM_UNAVAILABLE") == 0);
    ASSERT(strcmp(ozayn_om_err_name(OZAYN_OM_ERR_CONCURRENCY_ERROR), "CONCURRENCY_ERROR") == 0);
    ASSERT(strcmp(ozayn_om_err_name(OZAYN_OM_ERR_INTERNAL), "INTERNAL") == 0);
    return 0;
}

TEST(test_metric_type_name) {
    ASSERT(strcmp(ozayn_om_metric_type_name(OZAYN_OM_TYPE_COUNTER), "COUNTER") == 0);
    ASSERT(strcmp(ozayn_om_metric_type_name(OZAYN_OM_TYPE_GAUGE), "GAUGE") == 0);
    ASSERT(strcmp(ozayn_om_metric_type_name(OZAYN_OM_TYPE_HISTOGRAM), "HISTOGRAM") == 0);
    ASSERT(strcmp(ozayn_om_metric_type_name(OZAYN_OM_TYPE_DURATION), "DURATION") == 0);
    ASSERT(strcmp(ozayn_om_metric_type_name(OZAYN_OM_TYPE_RATE), "RATE") == 0);
    ASSERT(strcmp(ozayn_om_metric_type_name(OZAYN_OM_TYPE_RATIO), "RATIO") == 0);
    return 0;
}

TEST(test_category_name) {
    ASSERT(strcmp(ozayn_om_category_name(OZAYN_OM_CAT_SYSTEM), "SYSTEM") == 0);
    ASSERT(strcmp(ozayn_om_category_name(OZAYN_OM_CAT_CORE), "CORE") == 0);
    ASSERT(strcmp(ozayn_om_category_name(OZAYN_OM_CAT_COMPONENT), "COMPONENT") == 0);
    ASSERT(strcmp(ozayn_om_category_name(OZAYN_OM_CAT_OPERATION), "OPERATION") == 0);
    ASSERT(strcmp(ozayn_om_category_name(OZAYN_OM_CAT_QUEUE), "QUEUE") == 0);
    ASSERT(strcmp(ozayn_om_category_name(OZAYN_OM_CAT_SCHEDULER), "SCHEDULER") == 0);
    ASSERT(strcmp(ozayn_om_category_name(OZAYN_OM_CAT_WORKFLOW), "WORKFLOW") == 0);
    ASSERT(strcmp(ozayn_om_category_name(OZAYN_OM_CAT_PIPELINE), "PIPELINE") == 0);
    ASSERT(strcmp(ozayn_om_category_name(OZAYN_OM_CAT_EXECUTION), "EXECUTION") == 0);
    ASSERT(strcmp(ozayn_om_category_name(OZAYN_OM_CAT_RESOURCE), "RESOURCE") == 0);
    ASSERT(strcmp(ozayn_om_category_name(OZAYN_OM_CAT_DEVICE), "DEVICE") == 0);
    ASSERT(strcmp(ozayn_om_category_name(OZAYN_OM_CAT_IO), "IO") == 0);
    ASSERT(strcmp(ozayn_om_category_name(OZAYN_OM_CAT_SECURITY), "SECURITY") == 0);
    ASSERT(strcmp(ozayn_om_category_name(OZAYN_OM_CAT_DIAGNOSTIC), "DIAGNOSTIC") == 0);
    ASSERT(strcmp(ozayn_om_category_name(OZAYN_OM_CAT_RECOVERY), "RECOVERY") == 0);
    ASSERT(strcmp(ozayn_om_category_name(OZAYN_OM_CAT_EVENT), "EVENT") == 0);
    ASSERT(strcmp(ozayn_om_category_name(OZAYN_OM_CAT_ERROR), "ERROR") == 0);
    ASSERT(strcmp(ozayn_om_category_name(OZAYN_OM_CAT_STARTUP), "STARTUP") == 0);
    ASSERT(strcmp(ozayn_om_category_name(OZAYN_OM_CAT_SHUTDOWN), "SHUTDOWN") == 0);
    return 0;
}

TEST(test_unit_name) {
    ASSERT(strcmp(ozayn_om_unit_name(OZAYN_OM_UNIT_NONE), "NONE") == 0);
    ASSERT(strcmp(ozayn_om_unit_name(OZAYN_OM_UNIT_COUNT), "COUNT") == 0);
    ASSERT(strcmp(ozayn_om_unit_name(OZAYN_OM_UNIT_BYTES), "BYTES") == 0);
    ASSERT(strcmp(ozayn_om_unit_name(OZAYN_OM_UNIT_US), "US") == 0);
    ASSERT(strcmp(ozayn_om_unit_name(OZAYN_OM_UNIT_MS), "MS") == 0);
    ASSERT(strcmp(ozayn_om_unit_name(OZAYN_OM_UNIT_SECONDS), "SECONDS") == 0);
    ASSERT(strcmp(ozayn_om_unit_name(OZAYN_OM_UNIT_PERCENT), "PERCENT") == 0);
    ASSERT(strcmp(ozayn_om_unit_name(OZAYN_OM_UNIT_RATE_PER_SEC), "RATE_PER_SEC") == 0);
    return 0;
}

TEST(test_scope_name) {
    ASSERT(strcmp(ozayn_om_scope_name(OZAYN_OM_SCOPE_GLOBAL), "GLOBAL") == 0);
    ASSERT(strcmp(ozayn_om_scope_name(OZAYN_OM_SCOPE_COMPONENT), "COMPONENT") == 0);
    ASSERT(strcmp(ozayn_om_scope_name(OZAYN_OM_SCOPE_OPERATION), "OPERATION") == 0);
    ASSERT(strcmp(ozayn_om_scope_name(OZAYN_OM_SCOPE_WORKFLOW), "WORKFLOW") == 0);
    ASSERT(strcmp(ozayn_om_scope_name(OZAYN_OM_SCOPE_PIPELINE), "PIPELINE") == 0);
    return 0;
}

TEST(test_collection_status_name) {
    ASSERT(strcmp(ozayn_om_collection_status_name(OZAYN_OM_COLLECTED), "COLLECTED") == 0);
    ASSERT(strcmp(ozayn_om_collection_status_name(OZAYN_OM_UNAVAILABLE), "UNAVAILABLE") == 0);
    ASSERT(strcmp(ozayn_om_collection_status_name(OZAYN_OM_UNSUPPORTED), "UNSUPPORTED") == 0);
    ASSERT(strcmp(ozayn_om_collection_status_name(OZAYN_OM_ERROR), "ERROR") == 0);
    return 0;
}

TEST(test_threshold_state_name) {
    ASSERT(strcmp(ozayn_om_threshold_state_name(OZAYN_OM_THRESH_NORMAL), "NORMAL") == 0);
    ASSERT(strcmp(ozayn_om_threshold_state_name(OZAYN_OM_THRESH_ELEVATED), "ELEVATED") == 0);
    ASSERT(strcmp(ozayn_om_threshold_state_name(OZAYN_OM_THRESH_HIGH), "HIGH") == 0);
    ASSERT(strcmp(ozayn_om_threshold_state_name(OZAYN_OM_THRESH_CRITICAL), "CRITICAL") == 0);
    return 0;
}

TEST(test_threshold_type_name) {
    ASSERT(strcmp(ozayn_om_threshold_type_name(OZAYN_OM_THRESH_CAPACITY_WARNING), "CAPACITY_WARNING") == 0);
    ASSERT(strcmp(ozayn_om_threshold_type_name(OZAYN_OM_THRESH_CAPACITY_CRITICAL), "CAPACITY_CRITICAL") == 0);
    ASSERT(strcmp(ozayn_om_threshold_type_name(OZAYN_OM_THRESH_LATENCY_WARNING), "LATENCY_WARNING") == 0);
    ASSERT(strcmp(ozayn_om_threshold_type_name(OZAYN_OM_THRESH_LATENCY_CRITICAL), "LATENCY_CRITICAL") == 0);
    ASSERT(strcmp(ozayn_om_threshold_type_name(OZAYN_OM_THRESH_EVENT_BACKLOG), "EVENT_BACKLOG") == 0);
    ASSERT(strcmp(ozayn_om_threshold_type_name(OZAYN_OM_THRESH_ERROR_RATE), "ERROR_RATE") == 0);
    return 0;
}

TEST(test_emit_type_name) {
    ASSERT(strcmp(ozayn_om_emit_type_name(OZAYN_OM_EMIT_THRESHOLD_REACHED), "THRESHOLD_REACHED") == 0);
    ASSERT(strcmp(ozayn_om_emit_type_name(OZAYN_OM_EMIT_THRESHOLD_CLEARED), "THRESHOLD_CLEARED") == 0);
    ASSERT(strcmp(ozayn_om_emit_type_name(OZAYN_OM_EMIT_CAPACITY_WARNING), "CAPACITY_WARNING") == 0);
    ASSERT(strcmp(ozayn_om_emit_type_name(OZAYN_OM_EMIT_CAPACITY_CRITICAL), "CAPACITY_CRITICAL") == 0);
    ASSERT(strcmp(ozayn_om_emit_type_name(OZAYN_OM_EMIT_LATENCY_WARNING), "LATENCY_WARNING") == 0);
    ASSERT(strcmp(ozayn_om_emit_type_name(OZAYN_OM_EMIT_EVENT_BACKLOG), "EVENT_BACKLOG") == 0);
    return 0;
}

/* ============================================================
 * LIFECYCLE TESTS
 * ============================================================ */

TEST(test_init_null) {
    ASSERT_EQ(ozayn_om_init(NULL), OZAYN_OM_ERR_NULL_PTR);
    return 0;
}

TEST(test_init_basic) {
    ozayn_om_service_t svc = _make_svc();
    ASSERT_EQ(ozayn_om_init(&svc), OZAYN_OM_ERR_OK);
    ASSERT(svc.initialized);
    ASSERT_EQ(svc.metric_count, (uint64_t)0);
    ASSERT_EQ(svc.counter_count, (uint64_t)0);
    ASSERT_EQ(svc.gauge_count, (uint64_t)0);
    ASSERT_EQ(svc.histogram_count, (uint64_t)0);
    ASSERT_EQ(svc.duration_count, (uint64_t)0);
    ASSERT_EQ(svc.rate_count, (uint64_t)0);
    ASSERT_EQ(svc.ratio_count, (uint64_t)0);
    ASSERT_EQ(svc.threshold_count, (uint64_t)0);
    ASSERT_EQ(svc.alert_count, (uint64_t)0);
    ASSERT_EQ(svc.snapshot_count, (uint64_t)0);
    ozayn_om_shutdown(&svc);
    return 0;
}

TEST(test_init_double) {
    ozayn_om_service_t svc = _make_svc();
    ASSERT_EQ(ozayn_om_init(&svc), OZAYN_OM_ERR_OK);
    ASSERT_EQ(ozayn_om_init(&svc), OZAYN_OM_ERR_ALREADY_INITIALIZED);
    ozayn_om_shutdown(&svc);
    return 0;
}

TEST(test_shutdown_null) {
    ASSERT_EQ(ozayn_om_shutdown(NULL), OZAYN_OM_ERR_NULL_PTR);
    return 0;
}

TEST(test_shutdown_basic) {
    ozayn_om_service_t svc = _make_svc();
    ozayn_om_init(&svc);
    ASSERT_EQ(ozayn_om_shutdown(&svc), OZAYN_OM_ERR_OK);
    ASSERT(!svc.initialized);
    return 0;
}

TEST(test_is_initialized) {
    ozayn_om_service_t svc = _make_svc();
    ASSERT(!ozayn_om_is_initialized(NULL));
    ASSERT(!ozayn_om_is_initialized(&svc));
    ozayn_om_init(&svc);
    ASSERT(ozayn_om_is_initialized(&svc));
    ozayn_om_shutdown(&svc);
    return 0;
}

/* ============================================================
 * METRIC REGISTRATION TESTS
 * ============================================================ */

TEST(test_register_metric_null) {
    uint64_t id = 0;
    ASSERT_EQ(ozayn_om_register_metric(NULL, "test", OZAYN_OM_TYPE_COUNTER,
              OZAYN_OM_CAT_SYSTEM, OZAYN_OM_UNIT_COUNT, OZAYN_OM_SCOPE_GLOBAL,
              "src", &id), OZAYN_OM_ERR_NULL_PTR);
    return 0;
}

TEST(test_register_metric_not_init) {
    ozayn_om_service_t svc = _make_svc();
    uint64_t id = 0;
    ASSERT_EQ(ozayn_om_register_metric(&svc, "test", OZAYN_OM_TYPE_COUNTER,
              OZAYN_OM_CAT_SYSTEM, OZAYN_OM_UNIT_COUNT, OZAYN_OM_SCOPE_GLOBAL,
              "src", &id), OZAYN_OM_ERR_NOT_INITIALIZED);
    return 0;
}

TEST(test_register_counter_metric) {
    ozayn_om_service_t svc = _make_svc();
    ozayn_om_init(&svc);
    uint64_t id = 0;
    ASSERT_EQ(ozayn_om_register_metric(&svc, "my_counter", OZAYN_OM_TYPE_COUNTER,
              OZAYN_OM_CAT_OPERATION, OZAYN_OM_UNIT_COUNT, OZAYN_OM_SCOPE_GLOBAL,
              "ops", &id), OZAYN_OM_ERR_OK);
    ASSERT(id > 0);
    ASSERT_EQ(svc.metric_count, (uint64_t)1);
    ASSERT_EQ(svc.counter_count, (uint64_t)1);
    ozayn_om_shutdown(&svc);
    return 0;
}

TEST(test_register_gauge_metric) {
    ozayn_om_service_t svc = _make_svc();
    ozayn_om_init(&svc);
    uint64_t id = 0;
    ASSERT_EQ(ozayn_om_register_metric(&svc, "my_gauge", OZAYN_OM_TYPE_GAUGE,
              OZAYN_OM_CAT_RESOURCE, OZAYN_OM_UNIT_PERCENT, OZAYN_OM_SCOPE_COMPONENT,
              "res", &id), OZAYN_OM_ERR_OK);
    ASSERT(id > 0);
    ASSERT_EQ(svc.gauge_count, (uint64_t)1);
    ozayn_om_shutdown(&svc);
    return 0;
}

TEST(test_register_duration_metric) {
    ozayn_om_service_t svc = _make_svc();
    ozayn_om_init(&svc);
    uint64_t id = 0;
    ASSERT_EQ(ozayn_om_register_metric(&svc, "my_dur", OZAYN_OM_TYPE_DURATION,
              OZAYN_OM_CAT_SCHEDULER, OZAYN_OM_UNIT_US, OZAYN_OM_SCOPE_OPERATION,
              "sched", &id), OZAYN_OM_ERR_OK);
    ASSERT(id > 0);
    ASSERT_EQ(svc.duration_count, (uint64_t)1);
    ozayn_om_shutdown(&svc);
    return 0;
}

TEST(test_register_rate_metric) {
    ozayn_om_service_t svc = _make_svc();
    ozayn_om_init(&svc);
    uint64_t id = 0;
    ASSERT_EQ(ozayn_om_register_metric(&svc, "my_rate", OZAYN_OM_TYPE_RATE,
              OZAYN_OM_CAT_SYSTEM, OZAYN_OM_UNIT_RATE_PER_SEC, OZAYN_OM_SCOPE_GLOBAL,
              "sys", &id), OZAYN_OM_ERR_OK);
    ASSERT(id > 0);
    ASSERT_EQ(svc.rate_count, (uint64_t)1);
    ozayn_om_shutdown(&svc);
    return 0;
}

TEST(test_register_ratio_metric) {
    ozayn_om_service_t svc = _make_svc();
    ozayn_om_init(&svc);
    uint64_t id = 0;
    ASSERT_EQ(ozayn_om_register_metric(&svc, "my_ratio", OZAYN_OM_TYPE_RATIO,
              OZAYN_OM_CAT_CORE, OZAYN_OM_UNIT_NONE, OZAYN_OM_SCOPE_GLOBAL,
              "core", &id), OZAYN_OM_ERR_OK);
    ASSERT(id > 0);
    ASSERT_EQ(svc.ratio_count, (uint64_t)1);
    ozayn_om_shutdown(&svc);
    return 0;
}

TEST(test_register_duplicate) {
    ozayn_om_service_t svc = _make_svc();
    ozayn_om_init(&svc);
    uint64_t id1 = 0, id2 = 0;
    ASSERT_EQ(ozayn_om_register_metric(&svc, "dup_metric", OZAYN_OM_TYPE_COUNTER,
              OZAYN_OM_CAT_SYSTEM, OZAYN_OM_UNIT_COUNT, OZAYN_OM_SCOPE_GLOBAL,
              "src", &id1), OZAYN_OM_ERR_OK);
    ASSERT_EQ(ozayn_om_register_metric(&svc, "dup_metric", OZAYN_OM_TYPE_COUNTER,
              OZAYN_OM_CAT_SYSTEM, OZAYN_OM_UNIT_COUNT, OZAYN_OM_SCOPE_GLOBAL,
              "src", &id2), OZAYN_OM_ERR_DUPLICATE);
    ozayn_om_shutdown(&svc);
    return 0;
}

TEST(test_unregister_metric) {
    ozayn_om_service_t svc = _make_svc();
    ozayn_om_init(&svc);
    uint64_t id = 0;
    ozayn_om_register_metric(&svc, "to_delete", OZAYN_OM_TYPE_COUNTER,
              OZAYN_OM_CAT_SYSTEM, OZAYN_OM_UNIT_COUNT, OZAYN_OM_SCOPE_GLOBAL,
              "src", &id);
    ASSERT_EQ(ozayn_om_unregister_metric(&svc, id), OZAYN_OM_ERR_OK);
    ASSERT_EQ(ozayn_om_unregister_metric(&svc, id), OZAYN_OM_ERR_NOT_FOUND);
    ozayn_om_shutdown(&svc);
    return 0;
}

TEST(test_unregister_not_found) {
    ozayn_om_service_t svc = _make_svc();
    ozayn_om_init(&svc);
    ASSERT_EQ(ozayn_om_unregister_metric(&svc, 9999), OZAYN_OM_ERR_NOT_FOUND);
    ozayn_om_shutdown(&svc);
    return 0;
}

TEST(test_metric_count) {
    ozayn_om_service_t svc = _make_svc();
    ASSERT_EQ(ozayn_om_metric_count(NULL), -1);
    ASSERT_EQ(ozayn_om_metric_count(&svc), -1);
    ozayn_om_init(&svc);
    ASSERT_EQ(ozayn_om_metric_count(&svc), (int64_t)0);
    uint64_t id = 0;
    ozayn_om_register_metric(&svc, "m1", OZAYN_OM_TYPE_COUNTER,
              OZAYN_OM_CAT_SYSTEM, OZAYN_OM_UNIT_COUNT, OZAYN_OM_SCOPE_GLOBAL,
              "src", &id);
    ASSERT_EQ(ozayn_om_metric_count(&svc), (int64_t)1);
    ozayn_om_shutdown(&svc);
    return 0;
}

/* ============================================================
 * METRIC LOOKUP TESTS
 * ============================================================ */

TEST(test_get_metric_def) {
    ozayn_om_service_t svc = _make_svc();
    ozayn_om_init(&svc);
    uint64_t id = 0;
    ozayn_om_register_metric(&svc, "lookup_test", OZAYN_OM_TYPE_GAUGE,
              OZAYN_OM_CAT_RESOURCE, OZAYN_OM_UNIT_BYTES, OZAYN_OM_SCOPE_COMPONENT,
              "mem", &id);
    const ozayn_om_metric_def_t *def = 0;
    ASSERT_EQ(ozayn_om_get_metric_def(&svc, id, &def), OZAYN_OM_ERR_OK);
    ASSERT(def != 0);
    ASSERT(strcmp(def->name, "lookup_test") == 0);
    ASSERT_EQ(def->type, OZAYN_OM_TYPE_GAUGE);
    ASSERT_EQ(def->category, OZAYN_OM_CAT_RESOURCE);
    ASSERT_EQ(def->unit, OZAYN_OM_UNIT_BYTES);
    ASSERT_EQ(def->scope, OZAYN_OM_SCOPE_COMPONENT);
    ASSERT(def->active);
    ozayn_om_shutdown(&svc);
    return 0;
}

TEST(test_get_metric_def_not_found) {
    ozayn_om_service_t svc = _make_svc();
    ozayn_om_init(&svc);
    const ozayn_om_metric_def_t *def = 0;
    ASSERT_EQ(ozayn_om_get_metric_def(&svc, 9999, &def), OZAYN_OM_ERR_NOT_FOUND);
    ozayn_om_shutdown(&svc);
    return 0;
}

TEST(test_get_metric_by_name) {
    ozayn_om_service_t svc = _make_svc();
    ozayn_om_init(&svc);
    uint64_t id = 0;
    ozayn_om_register_metric(&svc, "name_lookup", OZAYN_OM_TYPE_DURATION,
              OZAYN_OM_CAT_SCHEDULER, OZAYN_OM_UNIT_MS, OZAYN_OM_SCOPE_OPERATION,
              "sched", &id);
    const ozayn_om_metric_def_t *def = 0;
    ASSERT_EQ(ozayn_om_get_metric_by_name(&svc, "name_lookup", &def), OZAYN_OM_ERR_OK);
    ASSERT(def != 0);
    ASSERT_EQ(def->metric_id, id);
    ozayn_om_shutdown(&svc);
    return 0;
}

TEST(test_get_metric_by_name_not_found) {
    ozayn_om_service_t svc = _make_svc();
    ozayn_om_init(&svc);
    const ozayn_om_metric_def_t *def = 0;
    ASSERT_EQ(ozayn_om_get_metric_by_name(&svc, "nonexistent", &def), OZAYN_OM_ERR_NOT_FOUND);
    ozayn_om_shutdown(&svc);
    return 0;
}

/* ============================================================
 * COUNTER TESTS
 * ============================================================ */

TEST(test_counter_increment_basic) {
    ozayn_om_service_t svc = _make_svc();
    ozayn_om_init(&svc);
    uint64_t id = 0;
    ozayn_om_register_metric(&svc, "cnt", OZAYN_OM_TYPE_COUNTER,
              OZAYN_OM_CAT_OPERATION, OZAYN_OM_UNIT_COUNT, OZAYN_OM_SCOPE_GLOBAL,
              "ops", &id);
    ASSERT_EQ(ozayn_om_counter_increment(&svc, id, 10), OZAYN_OM_ERR_OK);
    int64_t val = 0;
    ASSERT_EQ(ozayn_om_counter_get(&svc, id, &val), OZAYN_OM_ERR_OK);
    ASSERT_EQ(val, (int64_t)10);
    ASSERT_EQ(ozayn_om_counter_increment(&svc, id, 5), OZAYN_OM_ERR_OK);
    ASSERT_EQ(ozayn_om_counter_get(&svc, id, &val), OZAYN_OM_ERR_OK);
    ASSERT_EQ(val, (int64_t)15);
    ASSERT_EQ(ozayn_om_counter_increment(&svc, id, -3), OZAYN_OM_ERR_OK);
    ASSERT_EQ(ozayn_om_counter_get(&svc, id, &val), OZAYN_OM_ERR_OK);
    ASSERT_EQ(val, (int64_t)12);
    ASSERT_EQ(svc.stats.total_counter_updates, (uint64_t)3);
    ozayn_om_shutdown(&svc);
    return 0;
}

TEST(test_counter_get_null) {
    int64_t val = 0;
    ASSERT_EQ(ozayn_om_counter_get(NULL, 1, &val), OZAYN_OM_ERR_NULL_PTR);
    return 0;
}

TEST(test_counter_increment_not_found) {
    ozayn_om_service_t svc = _make_svc();
    ozayn_om_init(&svc);
    ASSERT_EQ(ozayn_om_counter_increment(&svc, 9999, 1), OZAYN_OM_ERR_NOT_FOUND);
    ozayn_om_shutdown(&svc);
    return 0;
}

/* ============================================================
 * GAUGE TESTS
 * ============================================================ */

TEST(test_gauge_set_basic) {
    ozayn_om_service_t svc = _make_svc();
    ozayn_om_init(&svc);
    uint64_t id = 0;
    ozayn_om_register_metric(&svc, "gauge1", OZAYN_OM_TYPE_GAUGE,
              OZAYN_OM_CAT_RESOURCE, OZAYN_OM_UNIT_PERCENT, OZAYN_OM_SCOPE_GLOBAL,
              "res", &id);
    ASSERT_EQ(ozayn_om_gauge_set(&svc, id, 42), OZAYN_OM_ERR_OK);
    int64_t val = 0;
    ASSERT_EQ(ozayn_om_gauge_get(&svc, id, &val), OZAYN_OM_ERR_OK);
    ASSERT_EQ(val, (int64_t)42);
    ASSERT_EQ(svc.stats.total_gauge_updates, (uint64_t)1);
    ozayn_om_shutdown(&svc);
    return 0;
}

TEST(test_gauge_update_basic) {
    ozayn_om_service_t svc = _make_svc();
    ozayn_om_init(&svc);
    uint64_t id = 0;
    ozayn_om_register_metric(&svc, "gauge2", OZAYN_OM_TYPE_GAUGE,
              OZAYN_OM_CAT_RESOURCE, OZAYN_OM_UNIT_COUNT, OZAYN_OM_SCOPE_GLOBAL,
              "res", &id);
    ozayn_om_gauge_set(&svc, id, 100);
    ASSERT_EQ(ozayn_om_gauge_update(&svc, id, 25), OZAYN_OM_ERR_OK);
    int64_t val = 0;
    ASSERT_EQ(ozayn_om_gauge_get(&svc, id, &val), OZAYN_OM_ERR_OK);
    ASSERT_EQ(val, (int64_t)125);
    ASSERT_EQ(ozayn_om_gauge_update(&svc, id, -50), OZAYN_OM_ERR_OK);
    ASSERT_EQ(ozayn_om_gauge_get(&svc, id, &val), OZAYN_OM_ERR_OK);
    ASSERT_EQ(val, (int64_t)75);
    ozayn_om_shutdown(&svc);
    return 0;
}

TEST(test_gauge_min_max) {
    ozayn_om_service_t svc = _make_svc();
    ozayn_om_init(&svc);
    uint64_t id = 0;
    ozayn_om_register_metric(&svc, "gauge_mm", OZAYN_OM_TYPE_GAUGE,
              OZAYN_OM_CAT_SYSTEM, OZAYN_OM_UNIT_BYTES, OZAYN_OM_SCOPE_GLOBAL,
              "sys", &id);
    ozayn_om_gauge_set(&svc, id, 50);
    ozayn_om_gauge_set(&svc, id, 10);
    ozayn_om_gauge_set(&svc, id, 80);
    const ozayn_om_metric_def_t *def;
    ozayn_om_get_metric_by_name(&svc, "gauge_mm", &def);
    ASSERT(def != 0);
    int idx = -1;
    for (uint64_t i = 0; i < svc.gauge_count; i++) {
        if (svc.gauges[i].metric_id == def->metric_id) { idx = (int)i; break; }
    }
    ASSERT(idx >= 0);
    ASSERT_EQ(svc.gauges[idx].min_value, (int64_t)10);
    ASSERT_EQ(svc.gauges[idx].max_value, (int64_t)80);
    ozayn_om_shutdown(&svc);
    return 0;
}

/* ============================================================
 * HISTOGRAM TESTS
 * ============================================================ */

TEST(test_histogram_create_and_record) {
    ozayn_om_service_t svc = _make_svc();
    ozayn_om_init(&svc);
    uint64_t id = 0;
    ozayn_om_register_metric(&svc, "hist1", OZAYN_OM_TYPE_HISTOGRAM,
              OZAYN_OM_CAT_EXECUTION, OZAYN_OM_UNIT_US, OZAYN_OM_SCOPE_GLOBAL,
              "exec", &id);
    int64_t boundaries[] = {10, 50, 100, 500};
    ASSERT_EQ(ozayn_om_histogram_create(&svc, id, boundaries, 4), OZAYN_OM_ERR_OK);
    ASSERT_EQ(svc.histogram_count, (uint64_t)1);
    ASSERT_EQ(ozayn_om_histogram_record(&svc, id, 5), OZAYN_OM_ERR_OK);
    ASSERT_EQ(ozayn_om_histogram_record(&svc, id, 25), OZAYN_OM_ERR_OK);
    ASSERT_EQ(ozayn_om_histogram_record(&svc, id, 75), OZAYN_OM_ERR_OK);
    ASSERT_EQ(ozayn_om_histogram_record(&svc, id, 200), OZAYN_OM_ERR_OK);
    ASSERT_EQ(ozayn_om_histogram_record(&svc, id, 1000), OZAYN_OM_ERR_OK);
    const uint64_t *counts = 0;
    int bucket_count = 0;
    uint64_t total_count = 0;
    int64_t total_sum = 0;
    ASSERT_EQ(ozayn_om_histogram_get(&svc, id, &counts, &bucket_count, &total_count, &total_sum), OZAYN_OM_ERR_OK);
    ASSERT_EQ(bucket_count, 4);
    ASSERT_EQ(total_count, (uint64_t)5);
    ASSERT_EQ(total_sum, (int64_t)1305);
    ASSERT_EQ(counts[0], (uint64_t)1);
    ASSERT_EQ(counts[1], (uint64_t)1);
    ASSERT_EQ(counts[2], (uint64_t)1);
    ASSERT_EQ(counts[3], (uint64_t)2);
    ASSERT_EQ(svc.stats.total_histogram_updates, (uint64_t)5);
    ozayn_om_shutdown(&svc);
    return 0;
}

TEST(test_histogram_get_not_found) {
    ozayn_om_service_t svc = _make_svc();
    ozayn_om_init(&svc);
    const uint64_t *counts = 0;
    int bc = 0;
    uint64_t tc = 0;
    int64_t ts = 0;
    ASSERT_EQ(ozayn_om_histogram_get(&svc, 9999, &counts, &bc, &tc, &ts), OZAYN_OM_ERR_NOT_FOUND);
    ozayn_om_shutdown(&svc);
    return 0;
}

/* ============================================================
 * DURATION TESTS
 * ============================================================ */

TEST(test_duration_record) {
    ozayn_om_service_t svc = _make_svc();
    ozayn_om_init(&svc);
    uint64_t id = 0;
    ozayn_om_register_metric(&svc, "dur1", OZAYN_OM_TYPE_DURATION,
              OZAYN_OM_CAT_SCHEDULER, OZAYN_OM_UNIT_US, OZAYN_OM_SCOPE_OPERATION,
              "sched", &id);
    ASSERT_EQ(ozayn_om_duration_record(&svc, id, 100), OZAYN_OM_ERR_OK);
    ASSERT_EQ(ozayn_om_duration_record(&svc, id, 50), OZAYN_OM_ERR_OK);
    ASSERT_EQ(ozayn_om_duration_record(&svc, id, 200), OZAYN_OM_ERR_OK);
    int64_t min_val = 0, max_val = 0;
    uint64_t count = 0;
    ASSERT_EQ(ozayn_om_duration_get(&svc, id, &min_val, &max_val, &count), OZAYN_OM_ERR_OK);
    ASSERT_EQ(min_val, (int64_t)50);
    ASSERT_EQ(max_val, (int64_t)200);
    ASSERT_EQ(count, (uint64_t)3);
    ASSERT_EQ(svc.stats.total_duration_records, (uint64_t)3);
    ozayn_om_shutdown(&svc);
    return 0;
}

/* ============================================================
 * RATE TESTS
 * ============================================================ */

TEST(test_rate_update) {
    ozayn_om_service_t svc = _make_svc();
    ozayn_om_init(&svc);
    uint64_t id = 0;
    ozayn_om_register_metric(&svc, "rate1", OZAYN_OM_TYPE_RATE,
              OZAYN_OM_CAT_SYSTEM, OZAYN_OM_UNIT_RATE_PER_SEC, OZAYN_OM_SCOPE_GLOBAL,
              "sys", &id);
    ASSERT_EQ(ozayn_om_rate_update(&svc, id, 100, 10), OZAYN_OM_ERR_OK);
    double rate = 0.0;
    ASSERT_EQ(ozayn_om_rate_get(&svc, id, &rate), OZAYN_OM_ERR_OK);
    ASSERT(rate > 9.9 && rate < 10.1);
    ozayn_om_shutdown(&svc);
    return 0;
}

/* ============================================================
 * RATIO TESTS
 * ============================================================ */

TEST(test_ratio_update) {
    ozayn_om_service_t svc = _make_svc();
    ozayn_om_init(&svc);
    uint64_t id = 0;
    ozayn_om_register_metric(&svc, "ratio1", OZAYN_OM_TYPE_RATIO,
              OZAYN_OM_CAT_CORE, OZAYN_OM_UNIT_NONE, OZAYN_OM_SCOPE_GLOBAL,
              "core", &id);
    ASSERT_EQ(ozayn_om_ratio_update(&svc, id, 75, 100), OZAYN_OM_ERR_OK);
    double ratio = 0.0;
    ASSERT_EQ(ozayn_om_ratio_get(&svc, id, &ratio), OZAYN_OM_ERR_OK);
    ASSERT(ratio > 0.74 && ratio < 0.76);
    ozayn_om_shutdown(&svc);
    return 0;
}

/* ============================================================
 * THRESHOLD TESTS
 * ============================================================ */

TEST(test_threshold_register_and_evaluate) {
    ozayn_om_service_t svc = _make_svc();
    ozayn_om_init(&svc);
    uint64_t id = 0;
    ozayn_om_register_metric(&svc, "thresh_metric", OZAYN_OM_TYPE_GAUGE,
              OZAYN_OM_CAT_RESOURCE, OZAYN_OM_UNIT_PERCENT, OZAYN_OM_SCOPE_GLOBAL,
              "res", &id);
    ASSERT_EQ(ozayn_om_threshold_register(&svc, "thresh_metric",
              OZAYN_OM_THRESH_CAPACITY_WARNING, OZAYN_OM_CAT_RESOURCE,
              70, 90), OZAYN_OM_ERR_OK);
    ASSERT_EQ(svc.threshold_count, (uint64_t)1);
    ozayn_om_threshold_state_t state = OZAYN_OM_THRESH_NORMAL;
    ASSERT_EQ(ozayn_om_threshold_evaluate(&svc, "thresh_metric", 0, &state), OZAYN_OM_ERR_OK);
    ASSERT_EQ(state, OZAYN_OM_THRESH_NORMAL);
    ASSERT_EQ(ozayn_om_threshold_evaluate(&svc, "thresh_metric", 50, &state), OZAYN_OM_ERR_OK);
    ASSERT_EQ(state, OZAYN_OM_THRESH_ELEVATED);
    ASSERT_EQ(ozayn_om_threshold_evaluate(&svc, "thresh_metric", 75, &state), OZAYN_OM_ERR_OK);
    ASSERT_EQ(state, OZAYN_OM_THRESH_HIGH);
    ASSERT_EQ(ozayn_om_threshold_evaluate(&svc, "thresh_metric", 95, &state), OZAYN_OM_ERR_OK);
    ASSERT_EQ(state, OZAYN_OM_THRESH_CRITICAL);
    ozayn_om_shutdown(&svc);
    return 0;
}

TEST(test_threshold_get_state) {
    ozayn_om_service_t svc = _make_svc();
    ozayn_om_init(&svc);
    uint64_t id = 0;
    ozayn_om_register_metric(&svc, "ts_metric", OZAYN_OM_TYPE_GAUGE,
              OZAYN_OM_CAT_SYSTEM, OZAYN_OM_UNIT_COUNT, OZAYN_OM_SCOPE_GLOBAL,
              "sys", &id);
    ozayn_om_threshold_register(&svc, "ts_metric",
              OZAYN_OM_THRESH_LATENCY_WARNING, OZAYN_OM_CAT_SYSTEM,
              100, 500);
    ozayn_om_threshold_state_t state = OZAYN_OM_THRESH_NORMAL;
    ozayn_om_threshold_evaluate(&svc, "ts_metric", 50, &state);
    ASSERT_EQ(state, OZAYN_OM_THRESH_ELEVATED);
    ozayn_om_shutdown(&svc);
    return 0;
}

TEST(test_threshold_not_found) {
    ozayn_om_service_t svc = _make_svc();
    ozayn_om_init(&svc);
    ozayn_om_threshold_state_t state = OZAYN_OM_THRESH_NORMAL;
    ASSERT_EQ(ozayn_om_threshold_evaluate(&svc, "nonexistent", 50, &state), OZAYN_OM_ERR_NOT_FOUND);
    ASSERT_EQ(ozayn_om_threshold_get_state(&svc, "nonexistent", &state), OZAYN_OM_ERR_NOT_FOUND);
    ozayn_om_shutdown(&svc);
    return 0;
}

/* ============================================================
 * ALERT TESTS
 * ============================================================ */

TEST(test_alert_ring_buffer) {
    ozayn_om_service_t svc = _make_svc();
    ozayn_om_init(&svc);
    uint64_t snap_id = 0;
    ASSERT_EQ(ozayn_om_snapshot_create(&svc, &snap_id), OZAYN_OM_ERR_OK);
    ASSERT(snap_id > 0);
    ASSERT_EQ(svc.alert_count, (uint64_t)0);
    ozayn_om_shutdown(&svc);
    return 0;
}

TEST(test_alert_get_recent_empty) {
    ozayn_om_service_t svc = _make_svc();
    ozayn_om_init(&svc);
    const ozayn_om_alert_t *alerts[10];
    uint64_t count = 0;
    ASSERT_EQ(ozayn_om_alert_get_recent(&svc, 10, alerts, &count), OZAYN_OM_ERR_OK);
    ASSERT_EQ(count, (uint64_t)0);
    ozayn_om_shutdown(&svc);
    return 0;
}

/* ============================================================
 * SNAPSHOT TESTS
 * ============================================================ */

TEST(test_snapshot_create) {
    ozayn_om_service_t svc = _make_svc();
    ozayn_om_init(&svc);
    uint64_t snap_id = 0;
    ASSERT_EQ(ozayn_om_snapshot_create(&svc, &snap_id), OZAYN_OM_ERR_OK);
    ASSERT(snap_id > 0);
    ASSERT_EQ(svc.snapshot_count, (uint64_t)1);
    const ozayn_om_snapshot_t *snap = 0;
    ASSERT_EQ(ozayn_om_snapshot_get(&svc, snap_id, &snap), OZAYN_OM_ERR_OK);
    ASSERT(snap != 0);
    ASSERT(snap->active);
    ASSERT_EQ(snap->snapshot_id, snap_id);
    ozayn_om_shutdown(&svc);
    return 0;
}

TEST(test_snapshot_get_latest) {
    ozayn_om_service_t svc = _make_svc();
    ozayn_om_init(&svc);
    uint64_t id1 = 0, id2 = 0;
    ozayn_om_snapshot_create(&svc, &id1);
    ozayn_om_snapshot_create(&svc, &id2);
    const ozayn_om_snapshot_t *snap = 0;
    ASSERT_EQ(ozayn_om_snapshot_get_latest(&svc, &snap), OZAYN_OM_ERR_OK);
    ASSERT(snap != 0);
    ASSERT_EQ(snap->snapshot_id, id2);
    ozayn_om_shutdown(&svc);
    return 0;
}

TEST(test_snapshot_get_not_found) {
    ozayn_om_service_t svc = _make_svc();
    ozayn_om_init(&svc);
    const ozayn_om_snapshot_t *snap = 0;
    ASSERT_EQ(ozayn_om_snapshot_get(&svc, 9999, &snap), OZAYN_OM_ERR_NOT_FOUND);
    ozayn_om_shutdown(&svc);
    return 0;
}

TEST(test_snapshot_count) {
    ozayn_om_service_t svc = _make_svc();
    ASSERT_EQ(ozayn_om_snapshot_count(NULL), -1);
    ozayn_om_init(&svc);
    ASSERT_EQ(ozayn_om_snapshot_count(&svc), (int64_t)0);
    uint64_t id = 0;
    ozayn_om_snapshot_create(&svc, &id);
    ASSERT_EQ(ozayn_om_snapshot_count(&svc), (int64_t)1);
    ozayn_om_shutdown(&svc);
    return 0;
}

/* ============================================================
 * STATS TESTS
 * ============================================================ */

TEST(test_get_stats_null) {
    ozayn_om_stats_t stats = ozayn_om_get_stats(NULL);
    ASSERT_EQ(stats.total_metrics_registered, (uint64_t)0);
    return 0;
}

TEST(test_get_stats_basic) {
    ozayn_om_service_t svc = _make_svc();
    ozayn_om_init(&svc);
    ozayn_om_stats_t stats = ozayn_om_get_stats(&svc);
    ASSERT_EQ(stats.total_metrics_registered, (uint64_t)0);
    ASSERT_EQ(stats.total_counter_updates, (uint64_t)0);
    ASSERT_EQ(stats.total_gauge_updates, (uint64_t)0);
    ASSERT_EQ(stats.total_histogram_updates, (uint64_t)0);
    ASSERT_EQ(stats.total_duration_records, (uint64_t)0);
    ASSERT_EQ(stats.total_snapshots_created, (uint64_t)0);
    ASSERT_EQ(stats.total_threshold_checks, (uint64_t)0);
    ASSERT_EQ(stats.total_queries, (uint64_t)0);
    ozayn_om_shutdown(&svc);
    return 0;
}

/* ============================================================
 * SHUTDOWN DRAIN TESTS
 * ============================================================ */

TEST(test_shutdown_drain) {
    ozayn_om_service_t svc = _make_svc();
    ozayn_om_init(&svc);
    uint64_t pending_m = 0, pending_s = 0;
    ASSERT_EQ(ozayn_om_shutdown_drain(&svc, &pending_m, &pending_s), OZAYN_OM_ERR_OK);
    ASSERT_EQ(pending_m, (uint64_t)0);
    ASSERT_EQ(pending_s, (uint64_t)0);
    ozayn_om_shutdown(&svc);
    return 0;
}

TEST(test_shutdown_drain_not_init) {
    ozayn_om_service_t svc = _make_svc();
    ASSERT_EQ(ozayn_om_shutdown_drain(&svc, 0, 0), OZAYN_OM_ERR_NOT_INITIALIZED);
    return 0;
}

/* ============================================================
 * COLLECT TESTS (without subsystems - all return SUBSYSTEM_UNAVAILABLE)
 * ============================================================ */

TEST(test_collect_all_null) {
    ASSERT_EQ(ozayn_om_collect_all(NULL), OZAYN_OM_ERR_NULL_PTR);
    return 0;
}

TEST(test_collect_all_not_init) {
    ozayn_om_service_t svc = _make_svc();
    ASSERT_EQ(ozayn_om_collect_all(&svc), OZAYN_OM_ERR_NOT_INITIALIZED);
    return 0;
}

TEST(test_collect_all_no_subsystems) {
    ozayn_om_service_t svc = _make_svc();
    ozayn_om_init(&svc);
    ASSERT_EQ(ozayn_om_collect_all(&svc), OZAYN_OM_ERR_OK);
    ASSERT(svc.stats.total_collection_failures > 0);
    ozayn_om_shutdown(&svc);
    return 0;
}

TEST(test_collect_operation_metrics_null) {
    ASSERT_EQ(ozayn_om_collect_operation_metrics(NULL), OZAYN_OM_ERR_NULL_PTR);
    return 0;
}

TEST(test_collect_queue_metrics_null) {
    ASSERT_EQ(ozayn_om_collect_queue_metrics(NULL), OZAYN_OM_ERR_NULL_PTR);
    return 0;
}

TEST(test_collect_scheduler_metrics_null) {
    ASSERT_EQ(ozayn_om_collect_scheduler_metrics(NULL), OZAYN_OM_ERR_NULL_PTR);
    return 0;
}

TEST(test_collect_workflow_metrics_null) {
    ASSERT_EQ(ozayn_om_collect_workflow_metrics(NULL), OZAYN_OM_ERR_NULL_PTR);
    return 0;
}

TEST(test_collect_pipeline_metrics_null) {
    ASSERT_EQ(ozayn_om_collect_pipeline_metrics(NULL), OZAYN_OM_ERR_NULL_PTR);
    return 0;
}

TEST(test_collect_execution_metrics_null) {
    ASSERT_EQ(ozayn_om_collect_execution_metrics(NULL), OZAYN_OM_ERR_NULL_PTR);
    return 0;
}

TEST(test_collect_failure_metrics_null) {
    ASSERT_EQ(ozayn_om_collect_failure_metrics(NULL), OZAYN_OM_ERR_NULL_PTR);
    return 0;
}

TEST(test_collect_resource_metrics_null) {
    ASSERT_EQ(ozayn_om_collect_resource_metrics(NULL), OZAYN_OM_ERR_NULL_PTR);
    return 0;
}

TEST(test_collect_event_metrics_null) {
    ASSERT_EQ(ozayn_om_collect_event_metrics(NULL), OZAYN_OM_ERR_NULL_PTR);
    return 0;
}

TEST(test_collect_admission_metrics_null) {
    ASSERT_EQ(ozayn_om_collect_admission_metrics(NULL), OZAYN_OM_ERR_NULL_PTR);
    return 0;
}

TEST(test_collect_enforcement_metrics_null) {
    ASSERT_EQ(ozayn_om_collect_enforcement_metrics(NULL), OZAYN_OM_ERR_NULL_PTR);
    return 0;
}

TEST(test_collect_diagnostic_metrics_null) {
    ASSERT_EQ(ozayn_om_collect_diagnostic_metrics(NULL), OZAYN_OM_ERR_NULL_PTR);
    return 0;
}

TEST(test_collect_recovery_metrics_null) {
    ASSERT_EQ(ozayn_om_collect_recovery_metrics(NULL), OZAYN_OM_ERR_NULL_PTR);
    return 0;
}

TEST(test_collect_health_metrics_null) {
    ASSERT_EQ(ozayn_om_collect_health_metrics(NULL), OZAYN_OM_ERR_NULL_PTR);
    return 0;
}

/* ============================================================
 * SUBSYSTEM UNAVAILABLE TESTS
 * ============================================================ */

TEST(test_collect_operation_no_subsystem) {
    ozayn_om_service_t svc = _make_svc();
    ozayn_om_init(&svc);
    ASSERT_EQ(ozayn_om_collect_operation_metrics(&svc), OZAYN_OM_ERR_SUBSYSTEM_UNAVAILABLE);
    ozayn_om_shutdown(&svc);
    return 0;
}

TEST(test_collect_queue_no_subsystem) {
    ozayn_om_service_t svc = _make_svc();
    ozayn_om_init(&svc);
    ASSERT_EQ(ozayn_om_collect_queue_metrics(&svc), OZAYN_OM_ERR_SUBSYSTEM_UNAVAILABLE);
    ozayn_om_shutdown(&svc);
    return 0;
}

TEST(test_collect_scheduler_no_subsystem) {
    ozayn_om_service_t svc = _make_svc();
    ozayn_om_init(&svc);
    ASSERT_EQ(ozayn_om_collect_scheduler_metrics(&svc), OZAYN_OM_ERR_SUBSYSTEM_UNAVAILABLE);
    ozayn_om_shutdown(&svc);
    return 0;
}

TEST(test_collect_workflow_no_subsystem) {
    ozayn_om_service_t svc = _make_svc();
    ozayn_om_init(&svc);
    ASSERT_EQ(ozayn_om_collect_workflow_metrics(&svc), OZAYN_OM_ERR_SUBSYSTEM_UNAVAILABLE);
    ozayn_om_shutdown(&svc);
    return 0;
}

TEST(test_collect_pipeline_no_subsystem) {
    ozayn_om_service_t svc = _make_svc();
    ozayn_om_init(&svc);
    ASSERT_EQ(ozayn_om_collect_pipeline_metrics(&svc), OZAYN_OM_ERR_SUBSYSTEM_UNAVAILABLE);
    ozayn_om_shutdown(&svc);
    return 0;
}

TEST(test_collect_execution_no_subsystem) {
    ozayn_om_service_t svc = _make_svc();
    ozayn_om_init(&svc);
    ASSERT_EQ(ozayn_om_collect_execution_metrics(&svc), OZAYN_OM_ERR_SUBSYSTEM_UNAVAILABLE);
    ozayn_om_shutdown(&svc);
    return 0;
}

TEST(test_collect_failure_no_subsystem) {
    ozayn_om_service_t svc = _make_svc();
    ozayn_om_init(&svc);
    ASSERT_EQ(ozayn_om_collect_failure_metrics(&svc), OZAYN_OM_ERR_SUBSYSTEM_UNAVAILABLE);
    ozayn_om_shutdown(&svc);
    return 0;
}

TEST(test_collect_resource_no_subsystem) {
    ozayn_om_service_t svc = _make_svc();
    ozayn_om_init(&svc);
    ASSERT_EQ(ozayn_om_collect_resource_metrics(&svc), OZAYN_OM_ERR_SUBSYSTEM_UNAVAILABLE);
    ozayn_om_shutdown(&svc);
    return 0;
}

TEST(test_collect_event_no_subsystem) {
    ozayn_om_service_t svc = _make_svc();
    ozayn_om_init(&svc);
    ASSERT_EQ(ozayn_om_collect_event_metrics(&svc), OZAYN_OM_ERR_SUBSYSTEM_UNAVAILABLE);
    ozayn_om_shutdown(&svc);
    return 0;
}

TEST(test_collect_admission_no_subsystem) {
    ozayn_om_service_t svc = _make_svc();
    ozayn_om_init(&svc);
    ASSERT_EQ(ozayn_om_collect_admission_metrics(&svc), OZAYN_OM_ERR_SUBSYSTEM_UNAVAILABLE);
    ozayn_om_shutdown(&svc);
    return 0;
}

TEST(test_collect_enforcement_no_subsystem) {
    ozayn_om_service_t svc = _make_svc();
    ozayn_om_init(&svc);
    ASSERT_EQ(ozayn_om_collect_enforcement_metrics(&svc), OZAYN_OM_ERR_SUBSYSTEM_UNAVAILABLE);
    ozayn_om_shutdown(&svc);
    return 0;
}

TEST(test_collect_diagnostic_no_subsystem) {
    ozayn_om_service_t svc = _make_svc();
    ozayn_om_init(&svc);
    ASSERT_EQ(ozayn_om_collect_diagnostic_metrics(&svc), OZAYN_OM_ERR_SUBSYSTEM_UNAVAILABLE);
    ozayn_om_shutdown(&svc);
    return 0;
}

TEST(test_collect_recovery_no_subsystem) {
    ozayn_om_service_t svc = _make_svc();
    ozayn_om_init(&svc);
    ASSERT_EQ(ozayn_om_collect_recovery_metrics(&svc), OZAYN_OM_ERR_SUBSYSTEM_UNAVAILABLE);
    ozayn_om_shutdown(&svc);
    return 0;
}

TEST(test_collect_health_no_subsystem) {
    ozayn_om_service_t svc = _make_svc();
    ozayn_om_init(&svc);
    ASSERT_EQ(ozayn_om_collect_health_metrics(&svc), OZAYN_OM_ERR_SUBSYSTEM_UNAVAILABLE);
    ozayn_om_shutdown(&svc);
    return 0;
}

/* ============================================================
 * EDGE CASES
 * ============================================================ */

TEST(test_histogram_not_hogram_type) {
    ozayn_om_service_t svc = _make_svc();
    ozayn_om_init(&svc);
    uint64_t id = 0;
    ozayn_om_register_metric(&svc, "not_hist", OZAYN_OM_TYPE_COUNTER,
              OZAYN_OM_CAT_SYSTEM, OZAYN_OM_UNIT_COUNT, OZAYN_OM_SCOPE_GLOBAL,
              "src", &id);
    int64_t b[] = {10};
    ASSERT_EQ(ozayn_om_histogram_create(&svc, id, b, 1), OZAYN_OM_ERR_NOT_FOUND);
    ozayn_om_shutdown(&svc);
    return 0;
}

TEST(test_snapshot_create_overflow) {
    ozayn_om_service_t svc = _make_svc();
    ozayn_om_init(&svc);
    uint64_t last_id = 0;
    for (int i = 0; i < OZAYN_OM_MAX_SNAPSHOTS + 2; i++) {
        ozayn_om_snapshot_create(&svc, &last_id);
    }
    ASSERT_EQ(svc.snapshot_count, (uint64_t)OZAYN_OM_MAX_SNAPSHOTS);
    const ozayn_om_snapshot_t *snap = 0;
    ASSERT_EQ(ozayn_om_snapshot_get(&svc, last_id, &snap), OZAYN_OM_ERR_OK);
    ozayn_om_shutdown(&svc);
    return 0;
}

TEST(test_threshold_state_name_all) {
    ASSERT(strcmp(ozayn_om_threshold_state_name(OZAYN_OM_THRESH_NORMAL), "NORMAL") == 0);
    ASSERT(strcmp(ozayn_om_threshold_state_name(OZAYN_OM_THRESH_ELEVATED), "ELEVATED") == 0);
    ASSERT(strcmp(ozayn_om_threshold_state_name(OZAYN_OM_THRESH_HIGH), "HIGH") == 0);
    ASSERT(strcmp(ozayn_om_threshold_state_name(OZAYN_OM_THRESH_CRITICAL), "CRITICAL") == 0);
    return 0;
}

/* ============================================================
 * SUITE
 * ============================================================ */

int run_cr_operational_metrics_tests(void) {
    int fail = 0;
    SUITE_BEGIN("operational_metrics");
    RUN(test_err_name);
    RUN(test_metric_type_name);
    RUN(test_category_name);
    RUN(test_unit_name);
    RUN(test_scope_name);
    RUN(test_collection_status_name);
    RUN(test_threshold_state_name);
    RUN(test_threshold_type_name);
    RUN(test_emit_type_name);
    RUN(test_init_null);
    RUN(test_init_basic);
    RUN(test_init_double);
    RUN(test_shutdown_null);
    RUN(test_shutdown_basic);
    RUN(test_is_initialized);
    RUN(test_register_metric_null);
    RUN(test_register_metric_not_init);
    RUN(test_register_counter_metric);
    RUN(test_register_gauge_metric);
    RUN(test_register_duration_metric);
    RUN(test_register_rate_metric);
    RUN(test_register_ratio_metric);
    RUN(test_register_duplicate);
    RUN(test_unregister_metric);
    RUN(test_unregister_not_found);
    RUN(test_metric_count);
    RUN(test_get_metric_def);
    RUN(test_get_metric_def_not_found);
    RUN(test_get_metric_by_name);
    RUN(test_get_metric_by_name_not_found);
    RUN(test_counter_increment_basic);
    RUN(test_counter_get_null);
    RUN(test_counter_increment_not_found);
    RUN(test_gauge_set_basic);
    RUN(test_gauge_update_basic);
    RUN(test_gauge_min_max);
    RUN(test_histogram_create_and_record);
    RUN(test_histogram_get_not_found);
    RUN(test_duration_record);
    RUN(test_rate_update);
    RUN(test_ratio_update);
    RUN(test_threshold_register_and_evaluate);
    RUN(test_threshold_get_state);
    RUN(test_threshold_not_found);
    RUN(test_alert_ring_buffer);
    RUN(test_alert_get_recent_empty);
    RUN(test_snapshot_create);
    RUN(test_snapshot_get_latest);
    RUN(test_snapshot_get_not_found);
    RUN(test_snapshot_count);
    RUN(test_get_stats_null);
    RUN(test_get_stats_basic);
    RUN(test_shutdown_drain);
    RUN(test_shutdown_drain_not_init);
    RUN(test_collect_all_null);
    RUN(test_collect_all_not_init);
    RUN(test_collect_all_no_subsystems);
    RUN(test_collect_operation_metrics_null);
    RUN(test_collect_queue_metrics_null);
    RUN(test_collect_scheduler_metrics_null);
    RUN(test_collect_workflow_metrics_null);
    RUN(test_collect_pipeline_metrics_null);
    RUN(test_collect_execution_metrics_null);
    RUN(test_collect_failure_metrics_null);
    RUN(test_collect_resource_metrics_null);
    RUN(test_collect_event_metrics_null);
    RUN(test_collect_admission_metrics_null);
    RUN(test_collect_enforcement_metrics_null);
    RUN(test_collect_diagnostic_metrics_null);
    RUN(test_collect_recovery_metrics_null);
    RUN(test_collect_health_metrics_null);
    RUN(test_collect_operation_no_subsystem);
    RUN(test_collect_queue_no_subsystem);
    RUN(test_collect_scheduler_no_subsystem);
    RUN(test_collect_workflow_no_subsystem);
    RUN(test_collect_pipeline_no_subsystem);
    RUN(test_collect_execution_no_subsystem);
    RUN(test_collect_failure_no_subsystem);
    RUN(test_collect_resource_no_subsystem);
    RUN(test_collect_event_no_subsystem);
    RUN(test_collect_admission_no_subsystem);
    RUN(test_collect_enforcement_no_subsystem);
    RUN(test_collect_diagnostic_no_subsystem);
    RUN(test_collect_recovery_no_subsystem);
    RUN(test_collect_health_no_subsystem);
    RUN(test_histogram_not_hogram_type);
    RUN(test_snapshot_create_overflow);
    RUN(test_threshold_state_name_all);
    SUITE_END();
    return fail;
}
