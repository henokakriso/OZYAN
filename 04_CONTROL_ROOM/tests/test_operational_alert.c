/*
 * test_operational_alert.c — Section 04, Step 27
 * Operational Alert & Notification Management Foundation tests
 */

#include "../../tests/test_framework.h"
#include "../operational_alert.h"
#include <string.h>

/* ============================================================
 * HELPERS
 * ============================================================ */

static ozayn_oan_service_t _make_svc(void) {
    ozayn_oan_service_t svc;
    memset(&svc, 0, sizeof(svc));
    return svc;
}

/* ============================================================
 * NAME HELPER TESTS
 * ============================================================ */

TEST(test_err_name) {
    ASSERT(strcmp(ozayn_oan_err_name(OZAYN_OAN_ERR_OK), "OK") == 0);
    ASSERT(strcmp(ozayn_oan_err_name(OZAYN_OAN_ERR_NULL_PTR), "NULL_PTR") == 0);
    ASSERT(strcmp(ozayn_oan_err_name(OZAYN_OAN_ERR_NOT_INITIALIZED), "NOT_INITIALIZED") == 0);
    ASSERT(strcmp(ozayn_oan_err_name(OZAYN_OAN_ERR_FULL), "FULL") == 0);
    ASSERT(strcmp(ozayn_oan_err_name(OZAYN_OAN_ERR_DUPLICATE), "DUPLICATE") == 0);
    ASSERT(strcmp(ozayn_oan_err_name(OZAYN_OAN_ERR_STATE_TRANSITION), "STATE_TRANSITION") == 0);
    ASSERT(strcmp(ozayn_oan_err_name(OZAYN_OAN_ERR_RATE_LIMITED), "RATE_LIMITED") == 0);
    ASSERT(strcmp(ozayn_oan_err_name(OZAYN_OAN_ERR_NOTIFICATION_FULL), "NOTIFICATION_FULL") == 0);
    ASSERT(strcmp(ozayn_oan_err_name(OZAYN_OAN_ERR_NOTIFICATION_RETRY_LIMIT), "NOTIFICATION_RETRY_LIMIT") == 0);
    return 0;
}

TEST(test_category_name) {
    ASSERT(strcmp(ozayn_oan_category_name(OZAYN_OAN_CAT_SYSTEM), "SYSTEM") == 0);
    ASSERT(strcmp(ozayn_oan_category_name(OZAYN_OAN_CAT_PERFORMANCE), "PERFORMANCE") == 0);
    ASSERT(strcmp(ozayn_oan_category_name(OZAYN_OAN_CAT_RESOURCE), "RESOURCE") == 0);
    ASSERT(strcmp(ozayn_oan_category_name(OZAYN_OAN_CAT_DEVICE), "DEVICE") == 0);
    ASSERT(strcmp(ozayn_oan_category_name(OZAYN_OAN_CAT_OPERATION), "OPERATION") == 0);
    ASSERT(strcmp(ozayn_oan_category_name(OZAYN_OAN_CAT_WORKFLOW), "WORKFLOW") == 0);
    ASSERT(strcmp(ozayn_oan_category_name(OZAYN_OAN_CAT_PIPELINE), "PIPELINE") == 0);
    ASSERT(strcmp(ozayn_oan_category_name(OZAYN_OAN_CAT_EXECUTION), "EXECUTION") == 0);
    ASSERT(strcmp(ozayn_oan_category_name(OZAYN_OAN_CAT_FAILURE), "FAILURE") == 0);
    ASSERT(strcmp(ozayn_oan_category_name(OZAYN_OAN_CAT_SECURITY), "SECURITY") == 0);
    ASSERT(strcmp(ozayn_oan_category_name(OZAYN_OAN_CAT_SAFETY), "SAFETY") == 0);
    ASSERT(strcmp(ozayn_oan_category_name(OZAYN_OAN_CAT_READINESS), "READINESS") == 0);
    ASSERT(strcmp(ozayn_oan_category_name(OZAYN_OAN_CAT_RECOVERY), "RECOVERY") == 0);
    ASSERT(strcmp(ozayn_oan_category_name(OZAYN_OAN_CAT_CONFIGURATION), "CONFIGURATION") == 0);
    ASSERT(strcmp(ozayn_oan_category_name(OZAYN_OAN_CAT_EVENT), "EVENT") == 0);
    ASSERT(strcmp(ozayn_oan_category_name(OZAYN_OAN_CAT_STORAGE), "STORAGE") == 0);
    ASSERT(strcmp(ozayn_oan_category_name(OZAYN_OAN_CAT_CAPACITY), "CAPACITY") == 0);
    return 0;
}

TEST(test_severity_name) {
    ASSERT(strcmp(ozayn_oan_severity_name(OZAYN_OAN_SEV_INFO), "INFO") == 0);
    ASSERT(strcmp(ozayn_oan_severity_name(OZAYN_OAN_SEV_LOW), "LOW") == 0);
    ASSERT(strcmp(ozayn_oan_severity_name(OZAYN_OAN_SEV_MEDIUM), "MEDIUM") == 0);
    ASSERT(strcmp(ozayn_oan_severity_name(OZAYN_OAN_SEV_HIGH), "HIGH") == 0);
    ASSERT(strcmp(ozayn_oan_severity_name(OZAYN_OAN_SEV_CRITICAL), "CRITICAL") == 0);
    return 0;
}

TEST(test_state_name) {
    ASSERT(strcmp(ozayn_oan_state_name(OZAYN_OAN_STATE_CREATED), "CREATED") == 0);
    ASSERT(strcmp(ozayn_oan_state_name(OZAYN_OAN_STATE_ACTIVE), "ACTIVE") == 0);
    ASSERT(strcmp(ozayn_oan_state_name(OZAYN_OAN_STATE_ACKNOWLEDGED), "ACKNOWLEDGED") == 0);
    ASSERT(strcmp(ozayn_oan_state_name(OZAYN_OAN_STATE_SUPPRESSED), "SUPPRESSED") == 0);
    ASSERT(strcmp(ozayn_oan_state_name(OZAYN_OAN_STATE_RESOLVED), "RESOLVED") == 0);
    ASSERT(strcmp(ozayn_oan_state_name(OZAYN_OAN_STATE_EXPIRED), "EXPIRED") == 0);
    ASSERT(strcmp(ozayn_oan_state_name(OZAYN_OAN_STATE_CANCELLED), "CANCELLED") == 0);
    ASSERT(strcmp(ozayn_oan_state_name(OZAYN_OAN_STATE_CLOSED), "CLOSED") == 0);
    return 0;
}

TEST(test_source_name) {
    ASSERT(strcmp(ozayn_oan_source_name(OZAYN_OAN_SRC_EVENT_ENGINE), "EVENT_ENGINE") == 0);
    ASSERT(strcmp(ozayn_oan_source_name(OZAYN_OAN_SRC_TIMELINE), "TIMELINE") == 0);
    ASSERT(strcmp(ozayn_oan_source_name(OZAYN_OAN_SRC_METRICS), "METRICS") == 0);
    ASSERT(strcmp(ozayn_oan_source_name(OZAYN_OAN_SRC_MANUAL), "MANUAL") == 0);
    return 0;
}

TEST(test_trigger_name) {
    ASSERT(strcmp(ozayn_oan_trigger_name(OZAYN_OAN_TRIGGER_EVENT), "EVENT") == 0);
    ASSERT(strcmp(ozayn_oan_trigger_name(OZAYN_OAN_TRIGGER_METRIC_THRESHOLD), "METRIC_THRESHOLD") == 0);
    ASSERT(strcmp(ozayn_oan_trigger_name(OZAYN_OAN_TRIGGER_FAILURE), "FAILURE") == 0);
    ASSERT(strcmp(ozayn_oan_trigger_name(OZAYN_OAN_TRIGGER_HEALTH_CHANGE), "HEALTH_CHANGE") == 0);
    ASSERT(strcmp(ozayn_oan_trigger_name(OZAYN_OAN_TRIGGER_RESOURCE_THRESHOLD), "RESOURCE_THRESHOLD") == 0);
    ASSERT(strcmp(ozayn_oan_trigger_name(OZAYN_OAN_TRIGGER_DEVICE_STATE), "DEVICE_STATE") == 0);
    ASSERT(strcmp(ozayn_oan_trigger_name(OZAYN_OAN_TRIGGER_READINESS_CHANGE), "READINESS_CHANGE") == 0);
    ASSERT(strcmp(ozayn_oan_trigger_name(OZAYN_OAN_TRIGGER_MODE_CHANGE), "MODE_CHANGE") == 0);
    ASSERT(strcmp(ozayn_oan_trigger_name(OZAYN_OAN_TRIGGER_OPERATION_FAILURE), "OPERATION_FAILURE") == 0);
    ASSERT(strcmp(ozayn_oan_trigger_name(OZAYN_OAN_TRIGGER_WORKFLOW_FAILURE), "WORKFLOW_FAILURE") == 0);
    ASSERT(strcmp(ozayn_oan_trigger_name(OZAYN_OAN_TRIGGER_PIPELINE_FAILURE), "PIPELINE_FAILURE") == 0);
    ASSERT(strcmp(ozayn_oan_trigger_name(OZAYN_OAN_TRIGGER_RECOVERY_FAILURE), "RECOVERY_FAILURE") == 0);
    ASSERT(strcmp(ozayn_oan_trigger_name(OZAYN_OAN_TRIGGER_CONFIG_CHANGE), "CONFIG_CHANGE") == 0);
    return 0;
}

TEST(test_channel_name) {
    ASSERT(strcmp(ozayn_oan_channel_name(OZAYN_OAN_CHAN_INTERNAL_EVENT), "INTERNAL_EVENT") == 0);
    ASSERT(strcmp(ozayn_oan_channel_name(OZAYN_OAN_CHAN_LOCAL_LOG), "LOCAL_LOG") == 0);
    ASSERT(strcmp(ozayn_oan_channel_name(OZAYN_OAN_CHAN_SYSTEM_NOTIFICATION), "SYSTEM_NOTIFICATION") == 0);
    ASSERT(strcmp(ozayn_oan_channel_name(OZAYN_OAN_CHAN_EMAIL), "EMAIL") == 0);
    ASSERT(strcmp(ozayn_oan_channel_name(OZAYN_OAN_CHAN_WEBHOOK), "WEBHOOK") == 0);
    ASSERT(strcmp(ozayn_oan_channel_name(OZAYN_OAN_CHAN_FUTURE), "FUTURE") == 0);
    return 0;
}

TEST(test_nstate_name) {
    ASSERT(strcmp(ozayn_oan_nstate_name(OZAYN_OAN_NSTATE_CREATED), "CREATED") == 0);
    ASSERT(strcmp(ozayn_oan_nstate_name(OZAYN_OAN_NSTATE_QUEUED), "QUEUED") == 0);
    ASSERT(strcmp(ozayn_oan_nstate_name(OZAYN_OAN_NSTATE_SENDING), "SENDING") == 0);
    ASSERT(strcmp(ozayn_oan_nstate_name(OZAYN_OAN_NSTATE_SENT), "SENT") == 0);
    ASSERT(strcmp(ozayn_oan_nstate_name(OZAYN_OAN_NSTATE_DELIVERED), "DELIVERED") == 0);
    ASSERT(strcmp(ozayn_oan_nstate_name(OZAYN_OAN_NSTATE_FAILED), "FAILED") == 0);
    ASSERT(strcmp(ozayn_oan_nstate_name(OZAYN_OAN_NSTATE_CANCELLED), "CANCELLED") == 0);
    ASSERT(strcmp(ozayn_oan_nstate_name(OZAYN_OAN_NSTATE_EXPIRED), "EXPIRED") == 0);
    ASSERT(strcmp(ozayn_oan_nstate_name(OZAYN_OAN_NSTATE_RETRYING), "RETRYING") == 0);
    return 0;
}

/* ============================================================
 * LIFECYCLE TESTS
 * ============================================================ */

TEST(test_init_null) {
    ASSERT_EQ(ozayn_oan_init(NULL), OZAYN_OAN_ERR_NULL_PTR);
    return 0;
}

TEST(test_init_basic) {
    ozayn_oan_service_t svc = _make_svc();
    ASSERT_EQ(ozayn_oan_init(&svc), OZAYN_OAN_ERR_OK);
    ASSERT(svc.initialized);
    ASSERT_EQ(svc.alert_count, (uint64_t)0);
    ASSERT_EQ(svc.rule_count, (uint64_t)0);
    ASSERT_EQ(svc.notif_count, (uint64_t)0);
    ASSERT_EQ(svc.policy_count, (uint64_t)0);
    ozayn_oan_shutdown(&svc);
    return 0;
}

TEST(test_init_double) {
    ozayn_oan_service_t svc = _make_svc();
    ozayn_oan_init(&svc);
    ASSERT_EQ(ozayn_oan_init(&svc), OZAYN_OAN_ERR_ALREADY_INITIALIZED);
    ozayn_oan_shutdown(&svc);
    return 0;
}

TEST(test_shutdown_null) {
    ASSERT_EQ(ozayn_oan_shutdown(NULL), OZAYN_OAN_ERR_NULL_PTR);
    return 0;
}

TEST(test_shutdown_basic) {
    ozayn_oan_service_t svc = _make_svc();
    ozayn_oan_init(&svc);
    ASSERT_EQ(ozayn_oan_shutdown(&svc), OZAYN_OAN_ERR_OK);
    ASSERT(!svc.initialized);
    return 0;
}

TEST(test_is_initialized) {
    ASSERT(!ozayn_oan_is_initialized(NULL));
    ozayn_oan_service_t svc = _make_svc();
    ASSERT(!ozayn_oan_is_initialized(&svc));
    ozayn_oan_init(&svc);
    ASSERT(ozayn_oan_is_initialized(&svc));
    ozayn_oan_shutdown(&svc);
    return 0;
}

TEST(test_bind_subsystems) {
    ozayn_oan_service_t svc = _make_svc();
    ozayn_oan_init(&svc);
    ozayn_oan_subsys_bind_t bind;
    memset(&bind, 0, sizeof(bind));
    ASSERT_EQ(ozayn_oan_bind_subsystems(&svc, &bind), OZAYN_OAN_ERR_OK);
    ASSERT_EQ(ozayn_oan_bind_subsystems(0, &bind), OZAYN_OAN_ERR_NULL_PTR);
    ASSERT_EQ(ozayn_oan_bind_subsystems(&svc, 0), OZAYN_OAN_ERR_NULL_PTR);
    ozayn_oan_shutdown(&svc);
    return 0;
}

/* ============================================================
 * STATE TRANSITION TESTS
 * ============================================================ */

TEST(test_state_transitions_valid) {
    ASSERT(ozayn_oan_state_transition_valid(OZAYN_OAN_STATE_CREATED, OZAYN_OAN_STATE_ACTIVE));
    ASSERT(ozayn_oan_state_transition_valid(OZAYN_OAN_STATE_CREATED, OZAYN_OAN_STATE_CANCELLED));
    ASSERT(ozayn_oan_state_transition_valid(OZAYN_OAN_STATE_ACTIVE, OZAYN_OAN_STATE_ACKNOWLEDGED));
    ASSERT(ozayn_oan_state_transition_valid(OZAYN_OAN_STATE_ACTIVE, OZAYN_OAN_STATE_SUPPRESSED));
    ASSERT(ozayn_oan_state_transition_valid(OZAYN_OAN_STATE_ACTIVE, OZAYN_OAN_STATE_RESOLVED));
    ASSERT(ozayn_oan_state_transition_valid(OZAYN_OAN_STATE_ACTIVE, OZAYN_OAN_STATE_EXPIRED));
    ASSERT(ozayn_oan_state_transition_valid(OZAYN_OAN_STATE_ACTIVE, OZAYN_OAN_STATE_CANCELLED));
    ASSERT(ozayn_oan_state_transition_valid(OZAYN_OAN_STATE_ACKNOWLEDGED, OZAYN_OAN_STATE_RESOLVED));
    ASSERT(ozayn_oan_state_transition_valid(OZAYN_OAN_STATE_SUPPRESSED, OZAYN_OAN_STATE_ACTIVE));
    ASSERT(ozayn_oan_state_transition_valid(OZAYN_OAN_STATE_RESOLVED, OZAYN_OAN_STATE_CLOSED));
    ASSERT(ozayn_oan_state_transition_valid(OZAYN_OAN_STATE_EXPIRED, OZAYN_OAN_STATE_CLOSED));
    ASSERT(ozayn_oan_state_transition_valid(OZAYN_OAN_STATE_CANCELLED, OZAYN_OAN_STATE_CLOSED));
    return 0;
}

TEST(test_state_transitions_invalid) {
    ASSERT(!ozayn_oan_state_transition_valid(OZAYN_OAN_STATE_CLOSED, OZAYN_OAN_STATE_ACTIVE));
    ASSERT(!ozayn_oan_state_transition_valid(OZAYN_OAN_STATE_CREATED, OZAYN_OAN_STATE_RESOLVED));
    ASSERT(!ozayn_oan_state_transition_valid(OZAYN_OAN_STATE_RESOLVED, OZAYN_OAN_STATE_ACTIVE));
    ASSERT(!ozayn_oan_state_transition_valid(OZAYN_OAN_STATE_EXPIRED, OZAYN_OAN_STATE_ACTIVE));
    ASSERT(!ozayn_oan_state_transition_valid(OZAYN_OAN_STATE_CANCELLED, OZAYN_OAN_STATE_ACTIVE));
    return 0;
}

TEST(test_nstate_transitions_valid) {
    ASSERT(ozayn_oan_nstate_transition_valid(OZAYN_OAN_NSTATE_CREATED, OZAYN_OAN_NSTATE_QUEUED));
    ASSERT(ozayn_oan_nstate_transition_valid(OZAYN_OAN_NSTATE_QUEUED, OZAYN_OAN_NSTATE_SENDING));
    ASSERT(ozayn_oan_nstate_transition_valid(OZAYN_OAN_NSTATE_SENDING, OZAYN_OAN_NSTATE_SENT));
    ASSERT(ozayn_oan_nstate_transition_valid(OZAYN_OAN_NSTATE_SENT, OZAYN_OAN_NSTATE_DELIVERED));
    ASSERT(ozayn_oan_nstate_transition_valid(OZAYN_OAN_NSTATE_SENDING, OZAYN_OAN_NSTATE_FAILED));
    ASSERT(ozayn_oan_nstate_transition_valid(OZAYN_OAN_NSTATE_FAILED, OZAYN_OAN_NSTATE_RETRYING));
    ASSERT(ozayn_oan_nstate_transition_valid(OZAYN_OAN_NSTATE_RETRYING, OZAYN_OAN_NSTATE_QUEUED));
    return 0;
}

TEST(test_nstate_transitions_invalid) {
    ASSERT(!ozayn_oan_nstate_transition_valid(OZAYN_OAN_NSTATE_DELIVERED, OZAYN_OAN_NSTATE_SENDING));
    ASSERT(!ozayn_oan_nstate_transition_valid(OZAYN_OAN_NSTATE_CANCELLED, OZAYN_OAN_NSTATE_QUEUED));
    ASSERT(!ozayn_oan_nstate_transition_valid(OZAYN_OAN_NSTATE_EXPIRED, OZAYN_OAN_NSTATE_QUEUED));
    return 0;
}

/* ============================================================
 * ALERT RULE TESTS
 * ============================================================ */

TEST(test_rule_create) {
    ozayn_oan_service_t svc = _make_svc();
    ozayn_oan_init(&svc);
    uint64_t rid = 0;
    ASSERT_EQ(ozayn_oan_rule_create(&svc, "queue_high", "Queue utilization high",
              OZAYN_OAN_TRIGGER_METRIC_THRESHOLD, OZAYN_OAN_CAT_PERFORMANCE,
              OZAYN_OAN_SEV_HIGH, "queue_util", 70, 90, 60, 3600, 30, &rid), OZAYN_OAN_ERR_OK);
    ASSERT(rid > 0);
    ASSERT_EQ(svc.rule_count, (uint64_t)1);
    ASSERT_EQ(svc.stats.current_rules, (uint64_t)1);
    ozayn_oan_shutdown(&svc);
    return 0;
}

TEST(test_rule_get) {
    ozayn_oan_service_t svc = _make_svc();
    ozayn_oan_init(&svc);
    uint64_t rid = 0;
    ozayn_oan_rule_create(&svc, "test_rule", "desc",
              OZAYN_OAN_TRIGGER_FAILURE, OZAYN_OAN_CAT_FAILURE,
              OZAYN_OAN_SEV_MEDIUM, "op_fail", 5, 10, 0, 0, 0, &rid);
    const ozayn_oan_rule_t *rule = 0;
    ASSERT_EQ(ozayn_oan_rule_get(&svc, rid, &rule), OZAYN_OAN_ERR_OK);
    ASSERT(rule != 0);
    ASSERT(strcmp(rule->name, "test_rule") == 0);
    ASSERT_EQ(rule->trigger_type, OZAYN_OAN_TRIGGER_FAILURE);
    ASSERT_EQ(rule->category, OZAYN_OAN_CAT_FAILURE);
    ASSERT_EQ(rule->severity, OZAYN_OAN_SEV_MEDIUM);
    ASSERT_EQ(rule->warning_threshold, (int64_t)5);
    ASSERT_EQ(rule->critical_threshold, (int64_t)10);
    ASSERT(rule->enabled);
    ozayn_oan_shutdown(&svc);
    return 0;
}

TEST(test_rule_disable_enable) {
    ozayn_oan_service_t svc = _make_svc();
    ozayn_oan_init(&svc);
    uint64_t rid = 0;
    ozayn_oan_rule_create(&svc, "toggle_rule", 0,
              OZAYN_OAN_TRIGGER_EVENT, OZAYN_OAN_CAT_SYSTEM,
              OZAYN_OAN_SEV_LOW, "", 0, 0, 0, 0, 0, &rid);
    ASSERT_EQ(ozayn_oan_rule_disable(&svc, rid), OZAYN_OAN_ERR_OK);
    const ozayn_oan_rule_t *rule;
    ozayn_oan_rule_get(&svc, rid, &rule);
    ASSERT(!rule->enabled);
    ASSERT_EQ(ozayn_oan_rule_enable(&svc, rid), OZAYN_OAN_ERR_OK);
    ozayn_oan_rule_get(&svc, rid, &rule);
    ASSERT(rule->enabled);
    ozayn_oan_shutdown(&svc);
    return 0;
}

TEST(test_rule_remove) {
    ozayn_oan_service_t svc = _make_svc();
    ozayn_oan_init(&svc);
    uint64_t rid = 0;
    ozayn_oan_rule_create(&svc, "removable", 0,
              OZAYN_OAN_TRIGGER_EVENT, OZAYN_OAN_CAT_SYSTEM,
              OZAYN_OAN_SEV_INFO, "", 0, 0, 0, 0, 0, &rid);
    ASSERT_EQ(ozayn_oan_rule_remove(&svc, rid), OZAYN_OAN_ERR_OK);
    const ozayn_oan_rule_t *dummy = 0;
    ASSERT_EQ(ozayn_oan_rule_get(&svc, rid, &dummy), OZAYN_OAN_ERR_NOT_FOUND);
    ozayn_oan_shutdown(&svc);
    return 0;
}

TEST(test_rule_evaluate) {
    ozayn_oan_service_t svc = _make_svc();
    ozayn_oan_init(&svc);
    uint64_t rid = 0;
    ozayn_oan_rule_create(&svc, "eval_rule", 0,
              OZAYN_OAN_TRIGGER_METRIC_THRESHOLD, OZAYN_OAN_CAT_PERFORMANCE,
              OZAYN_OAN_SEV_HIGH, "", 70, 90, 0, 0, 0, &rid);
    ozayn_oan_severity_t sev = OZAYN_OAN_SEV_INFO;
    ASSERT_EQ(ozayn_oan_rule_evaluate(&svc, rid, 50, &sev), OZAYN_OAN_ERR_OK);
    ASSERT_EQ(sev, OZAYN_OAN_SEV_INFO);
    ASSERT_EQ(ozayn_oan_rule_evaluate(&svc, rid, 75, &sev), OZAYN_OAN_ERR_OK);
    ASSERT_EQ(sev, OZAYN_OAN_SEV_HIGH);
    ASSERT_EQ(ozayn_oan_rule_evaluate(&svc, rid, 95, &sev), OZAYN_OAN_ERR_OK);
    ASSERT_EQ(sev, OZAYN_OAN_SEV_CRITICAL);
    ASSERT_EQ(svc.stats.total_rules_evaluated, (uint64_t)3);
    ozayn_oan_shutdown(&svc);
    return 0;
}

TEST(test_rule_evaluate_disabled) {
    ozayn_oan_service_t svc = _make_svc();
    ozayn_oan_init(&svc);
    uint64_t rid = 0;
    ozayn_oan_rule_create(&svc, "disabled_rule", 0,
              OZAYN_OAN_TRIGGER_EVENT, OZAYN_OAN_CAT_SYSTEM,
              OZAYN_OAN_SEV_LOW, "", 0, 0, 0, 0, 0, &rid);
    ozayn_oan_rule_disable(&svc, rid);
    ozayn_oan_severity_t sev = OZAYN_OAN_SEV_INFO;
    ASSERT_EQ(ozayn_oan_rule_evaluate(&svc, rid, 100, &sev), OZAYN_OAN_ERR_RULE_DISABLED);
    ozayn_oan_shutdown(&svc);
    return 0;
}

/* ============================================================
 * ALERT LIFECYCLE TESTS
 * ============================================================ */

TEST(test_alert_create) {
    ozayn_oan_service_t svc = _make_svc();
    ozayn_oan_init(&svc);
    uint64_t aid = 0;
    ASSERT_EQ(ozayn_oan_alert_create(&svc, OZAYN_OAN_CAT_PERFORMANCE, OZAYN_OAN_SEV_HIGH,
              OZAYN_OAN_SRC_METRICS, OZAYN_OAN_TRIGGER_METRIC_THRESHOLD,
              "Queue High", "Queue utilization above threshold", "queue", "corr-1",
              0, 85, 70, &aid), OZAYN_OAN_ERR_OK);
    ASSERT(aid > 0);
    ASSERT_EQ(svc.alert_count, (uint64_t)1);
    ASSERT_EQ(svc.stats.total_alerts_created, (uint64_t)1);
    ASSERT_EQ(svc.stats.current_active_alerts, (uint64_t)1);
    const ozayn_oan_alert_t *a = 0;
    ozayn_oan_alert_get(&svc, aid, &a);
    ASSERT(strcmp(a->title, "Queue High") == 0);
    ASSERT(strcmp(a->description, "Queue utilization above threshold") == 0);
    ASSERT(strcmp(a->source_component, "queue") == 0);
    ASSERT(strcmp(a->correlation_id, "corr-1") == 0);
    ASSERT_EQ(a->category, OZAYN_OAN_CAT_PERFORMANCE);
    ASSERT_EQ(a->severity, OZAYN_OAN_SEV_HIGH);
    ASSERT_EQ(a->state, OZAYN_OAN_STATE_CREATED);
    ASSERT_EQ(a->source, OZAYN_OAN_SRC_METRICS);
    ASSERT_EQ(a->trigger_type, OZAYN_OAN_TRIGGER_METRIC_THRESHOLD);
    ASSERT_EQ(a->trigger_value, (int64_t)85);
    ASSERT_EQ(a->threshold_value, (int64_t)70);
    ozayn_oan_shutdown(&svc);
    return 0;
}

TEST(test_alert_duplicate_correlation) {
    ozayn_oan_service_t svc = _make_svc();
    ozayn_oan_init(&svc);
    uint64_t aid1 = 0, aid2 = 0;
    ASSERT_EQ(ozayn_oan_alert_create(&svc, OZAYN_OAN_CAT_SYSTEM, OZAYN_OAN_SEV_LOW,
              OZAYN_OAN_SRC_MANUAL, OZAYN_OAN_TRIGGER_EVENT,
              "First", "desc", "", "dup-corr",
              0, 0, 0, &aid1), OZAYN_OAN_ERR_OK);
    ASSERT_EQ(ozayn_oan_alert_create(&svc, OZAYN_OAN_CAT_SYSTEM, OZAYN_OAN_SEV_LOW,
              OZAYN_OAN_SRC_MANUAL, OZAYN_OAN_TRIGGER_EVENT,
              "Second", "desc", "", "dup-corr",
              0, 0, 0, &aid2), OZAYN_OAN_ERR_DUPLICATE);
    ASSERT_EQ(aid1, aid2);
    ozayn_oan_shutdown(&svc);
    return 0;
}

TEST(test_alert_lifecycle_full) {
    ozayn_oan_service_t svc = _make_svc();
    ozayn_oan_init(&svc);
    uint64_t aid = 0;
    ozayn_oan_alert_create(&svc, OZAYN_OAN_CAT_FAILURE, OZAYN_OAN_SEV_CRITICAL,
              OZAYN_OAN_SRC_FAILURE, OZAYN_OAN_TRIGGER_FAILURE,
              "Critical Fail", "Critical failure", "ops", "",
              0, 0, 0, &aid);
    ASSERT_EQ(svc.alerts[0].state, OZAYN_OAN_STATE_CREATED);
    ASSERT_EQ(ozayn_oan_alert_activate(&svc, aid), OZAYN_OAN_ERR_OK);
    ASSERT_EQ(svc.alerts[0].state, OZAYN_OAN_STATE_ACTIVE);
    ASSERT_EQ(svc.stats.total_alerts_activated, (uint64_t)1);
    ASSERT_EQ(ozayn_oan_alert_acknowledge(&svc, aid, "admin", "looking into it"), OZAYN_OAN_ERR_OK);
    ASSERT_EQ(svc.alerts[0].state, OZAYN_OAN_STATE_ACKNOWLEDGED);
    ASSERT_EQ(svc.alerts[0].ack_count, (uint32_t)1);
    ASSERT_EQ(ozayn_oan_alert_resolve(&svc, aid), OZAYN_OAN_ERR_OK);
    ASSERT_EQ(svc.alerts[0].state, OZAYN_OAN_STATE_RESOLVED);
    ASSERT(svc.alerts[0].resolution_time > 0);
    ASSERT_EQ(ozayn_oan_alert_close(&svc, aid), OZAYN_OAN_ERR_OK);
    ASSERT_EQ(svc.alerts[0].state, OZAYN_OAN_STATE_CLOSED);
    ozayn_oan_shutdown(&svc);
    return 0;
}

TEST(test_alert_suppress) {
    ozayn_oan_service_t svc = _make_svc();
    ozayn_oan_init(&svc);
    uint64_t aid = 0;
    ozayn_oan_alert_create(&svc, OZAYN_OAN_CAT_EVENT, OZAYN_OAN_SEV_LOW,
              OZAYN_OAN_SRC_EVENT_ENGINE, OZAYN_OAN_TRIGGER_EVENT,
              "Event Alert", "", "", "", 0, 0, 0, &aid);
    ozayn_oan_alert_activate(&svc, aid);
    ASSERT_EQ(ozayn_oan_alert_suppress(&svc, aid), OZAYN_OAN_ERR_OK);
    ASSERT_EQ(svc.alerts[0].state, OZAYN_OAN_STATE_SUPPRESSED);
    ASSERT_EQ(svc.stats.total_alerts_suppressed, (uint64_t)1);
    ASSERT_EQ(ozayn_oan_alert_activate(&svc, aid), OZAYN_OAN_ERR_OK);
    ASSERT_EQ(svc.alerts[0].state, OZAYN_OAN_STATE_ACTIVE);
    ozayn_oan_shutdown(&svc);
    return 0;
}

TEST(test_alert_cancel) {
    ozayn_oan_service_t svc = _make_svc();
    ozayn_oan_init(&svc);
    uint64_t aid = 0;
    ozayn_oan_alert_create(&svc, OZAYN_OAN_CAT_SYSTEM, OZAYN_OAN_SEV_INFO,
              OZAYN_OAN_SRC_MANUAL, OZAYN_OAN_TRIGGER_EVENT,
              "Cancel me", "", "", "", 0, 0, 0, &aid);
    ASSERT_EQ(ozayn_oan_alert_cancel(&svc, aid), OZAYN_OAN_ERR_OK);
    ASSERT_EQ(svc.alerts[0].state, OZAYN_OAN_STATE_CANCELLED);
    ozayn_oan_shutdown(&svc);
    return 0;
}

TEST(test_alert_expire) {
    ozayn_oan_service_t svc = _make_svc();
    ozayn_oan_init(&svc);
    uint64_t aid = 0;
    ozayn_oan_alert_create(&svc, OZAYN_OAN_CAT_RESOURCE, OZAYN_OAN_SEV_MEDIUM,
              OZAYN_OAN_SRC_RESOURCE, OZAYN_OAN_TRIGGER_RESOURCE_THRESHOLD,
              "Resource High", "", "", "", 0, 80, 90, &aid);
    ozayn_oan_alert_activate(&svc, aid);
    ASSERT_EQ(ozayn_oan_alert_expire(&svc, aid), OZAYN_OAN_ERR_OK);
    ASSERT_EQ(svc.alerts[0].state, OZAYN_OAN_STATE_EXPIRED);
    ASSERT_EQ(svc.stats.total_alerts_expired, (uint64_t)1);
    ozayn_oan_shutdown(&svc);
    return 0;
}

TEST(test_alert_invalid_transition) {
    ozayn_oan_service_t svc = _make_svc();
    ozayn_oan_init(&svc);
    uint64_t aid = 0;
    ozayn_oan_alert_create(&svc, OZAYN_OAN_CAT_SYSTEM, OZAYN_OAN_SEV_INFO,
              OZAYN_OAN_SRC_MANUAL, OZAYN_OAN_TRIGGER_EVENT,
              "No resolve from created", "", "", "", 0, 0, 0, &aid);
    ASSERT_EQ(ozayn_oan_alert_resolve(&svc, aid), OZAYN_OAN_ERR_STATE_TRANSITION);
    ozayn_oan_shutdown(&svc);
    return 0;
}

TEST(test_alert_set_refs) {
    ozayn_oan_service_t svc = _make_svc();
    ozayn_oan_init(&svc);
    uint64_t aid = 0;
    ozayn_oan_alert_create(&svc, OZAYN_OAN_CAT_EXECUTION, OZAYN_OAN_SEV_HIGH,
              OZAYN_OAN_SRC_OPERATION, OZAYN_OAN_TRIGGER_OPERATION_FAILURE,
              "Op Fail", "", "ops", "corr-ops-1",
              0, 0, 0, &aid);
    ASSERT_EQ(ozayn_oan_alert_set_refs(&svc, aid,
              "evt-100", "met-200", "op-300", "wf-400", "pipe-500", "res-600", "dev-700", "fail-800"),
              OZAYN_OAN_ERR_OK);
    const ozayn_oan_alert_t *a;
    ozayn_oan_alert_get(&svc, aid, &a);
    ASSERT(strcmp(a->event_ref, "evt-100") == 0);
    ASSERT(strcmp(a->metric_ref, "met-200") == 0);
    ASSERT(strcmp(a->operation_ref, "op-300") == 0);
    ASSERT(strcmp(a->workflow_ref, "wf-400") == 0);
    ASSERT(strcmp(a->pipeline_ref, "pipe-500") == 0);
    ASSERT(strcmp(a->resource_ref, "res-600") == 0);
    ASSERT(strcmp(a->device_ref, "dev-700") == 0);
    ASSERT(strcmp(a->failure_ref, "fail-800") == 0);
    ozayn_oan_shutdown(&svc);
    return 0;
}

/* ============================================================
 * ALERT QUERIES
 * ============================================================ */

TEST(test_alert_get_by_correlation) {
    ozayn_oan_service_t svc = _make_svc();
    ozayn_oan_init(&svc);
    uint64_t aid = 0;
    ozayn_oan_alert_create(&svc, OZAYN_OAN_CAT_SYSTEM, OZAYN_OAN_SEV_INFO,
              OZAYN_OAN_SRC_MANUAL, OZAYN_OAN_TRIGGER_EVENT,
              "Correlated", "", "", "unique-corr-42", 0, 0, 0, &aid);
    const ozayn_oan_alert_t *a = 0;
    ASSERT_EQ(ozayn_oan_alert_get_by_correlation(&svc, "unique-corr-42", &a), OZAYN_OAN_ERR_OK);
    ASSERT(a != 0);
    ASSERT_EQ(a->alert_id, aid);
    ASSERT_EQ(ozayn_oan_alert_get_by_correlation(&svc, "nonexistent", &a), OZAYN_OAN_ERR_NOT_FOUND);
    ozayn_oan_shutdown(&svc);
    return 0;
}

TEST(test_alert_list_active) {
    ozayn_oan_service_t svc = _make_svc();
    ozayn_oan_init(&svc);
    uint64_t aid1 = 0, aid2 = 0, aid3 = 0;
    ozayn_oan_alert_create(&svc, OZAYN_OAN_CAT_SYSTEM, OZAYN_OAN_SEV_INFO,
              OZAYN_OAN_SRC_MANUAL, OZAYN_OAN_TRIGGER_EVENT, "A", "", "", "", 0, 0, 0, &aid1);
    ozayn_oan_alert_create(&svc, OZAYN_OAN_CAT_SYSTEM, OZAYN_OAN_SEV_LOW,
              OZAYN_OAN_SRC_MANUAL, OZAYN_OAN_TRIGGER_EVENT, "B", "", "", "", 0, 0, 0, &aid2);
    ozayn_oan_alert_create(&svc, OZAYN_OAN_CAT_SYSTEM, OZAYN_OAN_SEV_INFO,
              OZAYN_OAN_SRC_MANUAL, OZAYN_OAN_TRIGGER_EVENT, "C", "", "", "", 0, 0, 0, &aid3);
    ozayn_oan_alert_activate(&svc, aid1);
    ozayn_oan_alert_activate(&svc, aid2);
    ozayn_oan_alert_cancel(&svc, aid3);
    const ozayn_oan_alert_t *results[10];
    uint32_t count = 0;
    ASSERT_EQ(ozayn_oan_alert_list_active(&svc, results, 10, &count), OZAYN_OAN_ERR_OK);
    ASSERT_EQ(count, (uint32_t)2);
    ozayn_oan_shutdown(&svc);
    return 0;
}

TEST(test_alert_list_by_severity) {
    ozayn_oan_service_t svc = _make_svc();
    ozayn_oan_init(&svc);
    uint64_t aid1 = 0, aid2 = 0;
    ozayn_oan_alert_create(&svc, OZAYN_OAN_CAT_SYSTEM, OZAYN_OAN_SEV_CRITICAL,
              OZAYN_OAN_SRC_MANUAL, OZAYN_OAN_TRIGGER_EVENT, "Crit", "", "", "", 0, 0, 0, &aid1);
    ozayn_oan_alert_create(&svc, OZAYN_OAN_CAT_SYSTEM, OZAYN_OAN_SEV_CRITICAL,
              OZAYN_OAN_SRC_MANUAL, OZAYN_OAN_TRIGGER_EVENT, "Crit2", "", "", "", 0, 0, 0, &aid2);
    const ozayn_oan_alert_t *results[10];
    uint32_t count = 0;
    ASSERT_EQ(ozayn_oan_alert_list_by_severity(&svc, OZAYN_OAN_SEV_CRITICAL, results, 10, &count), OZAYN_OAN_ERR_OK);
    ASSERT_EQ(count, (uint32_t)2);
    ASSERT_EQ(ozayn_oan_alert_list_by_severity(&svc, OZAYN_OAN_SEV_LOW, results, 10, &count), OZAYN_OAN_ERR_OK);
    ASSERT_EQ(count, (uint32_t)0);
    ozayn_oan_shutdown(&svc);
    return 0;
}

TEST(test_alert_list_by_category) {
    ozayn_oan_service_t svc = _make_svc();
    ozayn_oan_init(&svc);
    uint64_t aid = 0;
    ozayn_oan_alert_create(&svc, OZAYN_OAN_CAT_RESOURCE, OZAYN_OAN_SEV_MEDIUM,
              OZAYN_OAN_SRC_RESOURCE, OZAYN_OAN_TRIGGER_RESOURCE_THRESHOLD, "Res", "", "", "", 0, 0, 0, &aid);
    const ozayn_oan_alert_t *results[10];
    uint32_t count = 0;
    ASSERT_EQ(ozayn_oan_alert_list_by_category(&svc, OZAYN_OAN_CAT_RESOURCE, results, 10, &count), OZAYN_OAN_ERR_OK);
    ASSERT_EQ(count, (uint32_t)1);
    ASSERT_EQ(ozayn_oan_alert_list_by_category(&svc, OZAYN_OAN_CAT_DEVICE, results, 10, &count), OZAYN_OAN_ERR_OK);
    ASSERT_EQ(count, (uint32_t)0);
    ozayn_oan_shutdown(&svc);
    return 0;
}

TEST(test_alert_list_by_source) {
    ozayn_oan_service_t svc = _make_svc();
    ozayn_oan_init(&svc);
    uint64_t aid = 0;
    ozayn_oan_alert_create(&svc, OZAYN_OAN_CAT_FAILURE, OZAYN_OAN_SEV_HIGH,
              OZAYN_OAN_SRC_FAILURE, OZAYN_OAN_TRIGGER_FAILURE, "Fail", "", "", "", 0, 0, 0, &aid);
    const ozayn_oan_alert_t *results[10];
    uint32_t count = 0;
    ASSERT_EQ(ozayn_oan_alert_list_by_source(&svc, OZAYN_OAN_SRC_FAILURE, results, 10, &count), OZAYN_OAN_ERR_OK);
    ASSERT_EQ(count, (uint32_t)1);
    ozayn_oan_shutdown(&svc);
    return 0;
}

TEST(test_alert_counts) {
    ozayn_oan_service_t svc = _make_svc();
    ASSERT_EQ(ozayn_oan_alert_active_count(&svc), (int64_t)-1);
    ASSERT_EQ(ozayn_oan_alert_total_count(&svc), (int64_t)-1);
    ozayn_oan_init(&svc);
    ASSERT_EQ(ozayn_oan_alert_active_count(&svc), (int64_t)0);
    ASSERT_EQ(ozayn_oan_alert_total_count(&svc), (int64_t)0);
    uint64_t aid = 0;
    ozayn_oan_alert_create(&svc, OZAYN_OAN_CAT_SYSTEM, OZAYN_OAN_SEV_INFO,
              OZAYN_OAN_SRC_MANUAL, OZAYN_OAN_TRIGGER_EVENT, "Count", "", "", "", 0, 0, 0, &aid);
    ASSERT_EQ(ozayn_oan_alert_total_count(&svc), (int64_t)1);
    ASSERT_EQ(ozayn_oan_alert_active_count(&svc), (int64_t)1);
    ozayn_oan_shutdown(&svc);
    return 0;
}

/* ============================================================
 * ALERT SUMMARY TESTS
 * ============================================================ */

TEST(test_summary) {
    ozayn_oan_service_t svc = _make_svc();
    ozayn_oan_init(&svc);
    uint64_t a1 = 0, a2 = 0, a3 = 0, a4 = 0, a5 = 0;
    ozayn_oan_alert_create(&svc, OZAYN_OAN_CAT_SYSTEM, OZAYN_OAN_SEV_CRITICAL,
              OZAYN_OAN_SRC_MANUAL, OZAYN_OAN_TRIGGER_EVENT, "Crit", "", "", "", 0, 0, 0, &a1);
    ozayn_oan_alert_create(&svc, OZAYN_OAN_CAT_SYSTEM, OZAYN_OAN_SEV_HIGH,
              OZAYN_OAN_SRC_MANUAL, OZAYN_OAN_TRIGGER_EVENT, "High", "", "", "", 0, 0, 0, &a2);
    ozayn_oan_alert_create(&svc, OZAYN_OAN_CAT_SYSTEM, OZAYN_OAN_SEV_MEDIUM,
              OZAYN_OAN_SRC_MANUAL, OZAYN_OAN_TRIGGER_EVENT, "Med", "", "", "", 0, 0, 0, &a3);
    ozayn_oan_alert_create(&svc, OZAYN_OAN_CAT_SYSTEM, OZAYN_OAN_SEV_LOW,
              OZAYN_OAN_SRC_MANUAL, OZAYN_OAN_TRIGGER_EVENT, "Low", "", "", "", 0, 0, 0, &a4);
    ozayn_oan_alert_create(&svc, OZAYN_OAN_CAT_SYSTEM, OZAYN_OAN_SEV_INFO,
              OZAYN_OAN_SRC_MANUAL, OZAYN_OAN_TRIGGER_EVENT, "Info", "", "", "", 0, 0, 0, &a5);
    ozayn_oan_alert_activate(&svc, a1);
    ozayn_oan_alert_activate(&svc, a2);
    ozayn_oan_alert_activate(&svc, a3);
    ozayn_oan_alert_activate(&svc, a4);
    ozayn_oan_alert_activate(&svc, a5);
    ozayn_oan_alert_acknowledge(&svc, a3, "admin", "ack");
    ozayn_oan_alert_suppress(&svc, a4);
    ozayn_oan_alert_resolve(&svc, a5);
    ozayn_oan_summary_t sum;
    ASSERT_EQ(ozayn_oan_summary(&svc, &sum), OZAYN_OAN_ERR_OK);
    ASSERT_EQ(sum.total_active, (uint32_t)4);
    ASSERT_EQ(sum.critical_count, (uint32_t)1);
    ASSERT_EQ(sum.high_count, (uint32_t)1);
    ASSERT_EQ(sum.medium_count, (uint32_t)1);
    ASSERT_EQ(sum.low_count, (uint32_t)1);
    ASSERT_EQ(sum.info_count, (uint32_t)0);
    ASSERT_EQ(sum.acknowledged_count, (uint32_t)1);
    ASSERT_EQ(sum.suppressed_count, (uint32_t)1);
    ASSERT_EQ(sum.recently_resolved_count, (uint32_t)1);
    ozayn_oan_shutdown(&svc);
    return 0;
}

/* ============================================================
 * DEDUP TESTS
 * ============================================================ */

TEST(test_dedup_register_and_check) {
    ozayn_oan_service_t svc = _make_svc();
    ozayn_oan_init(&svc);
    ASSERT_EQ(ozayn_oan_dedup_check(&svc, 1, "key1"), 0);
    ASSERT_EQ(ozayn_oan_dedup_register(&svc, 1, "key1", 100), OZAYN_OAN_ERR_OK);
    ASSERT_EQ(ozayn_oan_dedup_check(&svc, 1, "key1"), 1);
    ASSERT_EQ(ozayn_oan_dedup_check(&svc, 1, "key2"), 0);
    ASSERT_EQ(ozayn_oan_dedup_check(&svc, 2, "key1"), 0);
    ASSERT_EQ(ozayn_oan_dedup_register(&svc, 1, "key1", 200), OZAYN_OAN_ERR_OK);
    int idx = -1;
    for (uint64_t i = 0; i < svc.dedup_count; i++) {
        if (svc.dedup[i].active && svc.dedup[i].rule_id == 1 &&
            strcmp(svc.dedup[i].dedup_key, "key1") == 0) { idx = (int)i; break; }
    }
    ASSERT(idx >= 0);
    ASSERT_EQ(svc.dedup[idx].count, (uint32_t)2);
    ASSERT_EQ(svc.stats.total_duplicates_detected, (uint64_t)1);
    ozayn_oan_shutdown(&svc);
    return 0;
}

TEST(test_dedup_cleanup) {
    ozayn_oan_service_t svc = _make_svc();
    ozayn_oan_init(&svc);
    ozayn_oan_dedup_register(&svc, 1, "old_key", 100);
    svc.dedup[0].last_time -= 600;
    ozayn_oan_dedup_register(&svc, 1, "new_key", 200);
    ASSERT_EQ(ozayn_oan_dedup_cleanup(&svc, 300), OZAYN_OAN_ERR_OK);
    ASSERT_EQ(ozayn_oan_dedup_check(&svc, 1, "old_key"), 0);
    ASSERT_EQ(ozayn_oan_dedup_check(&svc, 1, "new_key"), 1);
    ozayn_oan_shutdown(&svc);
    return 0;
}

/* ============================================================
 * NOTIFICATION TESTS
 * ============================================================ */

TEST(test_notif_create) {
    ozayn_oan_service_t svc = _make_svc();
    ozayn_oan_init(&svc);
    uint64_t aid = 0;
    ozayn_oan_alert_create(&svc, OZAYN_OAN_CAT_PERFORMANCE, OZAYN_OAN_SEV_HIGH,
              OZAYN_OAN_SRC_METRICS, OZAYN_OAN_TRIGGER_METRIC_THRESHOLD,
              "Alert for notif", "", "", "", 0, 0, 0, &aid);
    uint64_t nid = 0;
    ASSERT_EQ(ozayn_oan_notif_create(&svc, aid, "admin@ozayn", OZAYN_OAN_CHAN_EMAIL,
              OZAYN_OAN_SEV_HIGH, "Queue Alert", "Queue is high", &nid), OZAYN_OAN_ERR_OK);
    ASSERT(nid > 0);
    ASSERT_EQ(svc.notif_count, (uint64_t)1);
    ASSERT_EQ(svc.stats.total_notifications_created, (uint64_t)1);
    ASSERT_EQ(svc.alerts[0].notification_count, (uint32_t)1);
    const ozayn_oan_notification_t *n = 0;
    ozayn_oan_notif_get(&svc, nid, &n);
    ASSERT(strcmp(n->recipient, "admin@ozayn") == 0);
    ASSERT(strcmp(n->title, "Queue Alert") == 0);
    ASSERT(strcmp(n->body, "Queue is high") == 0);
    ASSERT_EQ(n->channel, OZAYN_OAN_CHAN_EMAIL);
    ASSERT_EQ(n->state, OZAYN_OAN_NSTATE_CREATED);
    ASSERT_EQ(n->max_attempts, (uint32_t)3);
    ozayn_oan_shutdown(&svc);
    return 0;
}

TEST(test_notif_lifecycle) {
    ozayn_oan_service_t svc = _make_svc();
    ozayn_oan_init(&svc);
    uint64_t aid = 0;
    ozayn_oan_alert_create(&svc, OZAYN_OAN_CAT_SECURITY, OZAYN_OAN_SEV_CRITICAL,
              OZAYN_OAN_SRC_EVENT_ENGINE, OZAYN_OAN_TRIGGER_EVENT,
              "Sec Alert", "", "", "", 0, 0, 0, &aid);
    uint64_t nid = 0;
    ozayn_oan_notif_create(&svc, aid, "sec-admin", OZAYN_OAN_CHAN_INTERNAL_EVENT,
              OZAYN_OAN_SEV_CRITICAL, "Sec Notif", "body", &nid);
    ASSERT_EQ(ozayn_oan_notif_advance(&svc, nid, OZAYN_OAN_NSTATE_QUEUED), OZAYN_OAN_ERR_OK);
    ASSERT_EQ(svc.notifications[0].state, OZAYN_OAN_NSTATE_QUEUED);
    ASSERT_EQ(ozayn_oan_notif_advance(&svc, nid, OZAYN_OAN_NSTATE_SENDING), OZAYN_OAN_ERR_OK);
    ASSERT_EQ(svc.notifications[0].state, OZAYN_OAN_NSTATE_SENDING);
    ASSERT_EQ(ozayn_oan_notif_advance(&svc, nid, OZAYN_OAN_NSTATE_SENT), OZAYN_OAN_ERR_OK);
    ASSERT_EQ(svc.notifications[0].state, OZAYN_OAN_NSTATE_SENT);
    ASSERT_EQ(svc.stats.total_notifications_sent, (uint64_t)1);
    ASSERT_EQ(ozayn_oan_notif_advance(&svc, nid, OZAYN_OAN_NSTATE_DELIVERED), OZAYN_OAN_ERR_OK);
    ASSERT_EQ(svc.notifications[0].state, OZAYN_OAN_NSTATE_DELIVERED);
    ASSERT_EQ(svc.stats.total_notifications_delivered, (uint64_t)1);
    ozayn_oan_shutdown(&svc);
    return 0;
}

TEST(test_notif_failure_retry) {
    ozayn_oan_service_t svc = _make_svc();
    ozayn_oan_init(&svc);
    uint64_t aid = 0;
    ozayn_oan_alert_create(&svc, OZAYN_OAN_CAT_SYSTEM, OZAYN_OAN_SEV_MEDIUM,
              OZAYN_OAN_SRC_MANUAL, OZAYN_OAN_TRIGGER_EVENT, "Retry Test", "", "", "", 0, 0, 0, &aid);
    uint64_t nid = 0;
    ozayn_oan_notif_create(&svc, aid, "user", OZAYN_OAN_CHAN_WEBHOOK,
              OZAYN_OAN_SEV_MEDIUM, "title", "body", &nid);
    ozayn_oan_notif_advance(&svc, nid, OZAYN_OAN_NSTATE_QUEUED);
    ozayn_oan_notif_advance(&svc, nid, OZAYN_OAN_NSTATE_SENDING);
    ASSERT_EQ(ozayn_oan_notif_advance(&svc, nid, OZAYN_OAN_NSTATE_FAILED), OZAYN_OAN_ERR_OK);
    ASSERT_EQ(svc.notifications[0].state, OZAYN_OAN_NSTATE_RETRYING);
    ASSERT_EQ(svc.notifications[0].attempt_count, (uint32_t)1);
    ASSERT_EQ(svc.stats.total_notifications_retries, (uint64_t)1);
    ASSERT_EQ(svc.stats.total_notifications_failed, (uint64_t)1);
    ozayn_oan_shutdown(&svc);
    return 0;
}

TEST(test_notif_cancel) {
    ozayn_oan_service_t svc = _make_svc();
    ozayn_oan_init(&svc);
    uint64_t aid = 0;
    ozayn_oan_alert_create(&svc, OZAYN_OAN_CAT_SYSTEM, OZAYN_OAN_SEV_INFO,
              OZAYN_OAN_SRC_MANUAL, OZAYN_OAN_TRIGGER_EVENT, "Cancel", "", "", "", 0, 0, 0, &aid);
    uint64_t nid = 0;
    ozayn_oan_notif_create(&svc, aid, "user", OZAYN_OAN_CHAN_LOCAL_LOG,
              OZAYN_OAN_SEV_INFO, "t", "b", &nid);
    ASSERT_EQ(ozayn_oan_notif_cancel(&svc, nid), OZAYN_OAN_ERR_OK);
    ASSERT_EQ(svc.notifications[0].state, OZAYN_OAN_NSTATE_CANCELLED);
    ozayn_oan_shutdown(&svc);
    return 0;
}

TEST(test_notif_list_by_alert) {
    ozayn_oan_service_t svc = _make_svc();
    ozayn_oan_init(&svc);
    uint64_t aid1 = 0, aid2 = 0;
    ozayn_oan_alert_create(&svc, OZAYN_OAN_CAT_SYSTEM, OZAYN_OAN_SEV_LOW,
              OZAYN_OAN_SRC_MANUAL, OZAYN_OAN_TRIGGER_EVENT, "A1", "", "", "", 0, 0, 0, &aid1);
    ozayn_oan_alert_create(&svc, OZAYN_OAN_CAT_SYSTEM, OZAYN_OAN_SEV_LOW,
              OZAYN_OAN_SRC_MANUAL, OZAYN_OAN_TRIGGER_EVENT, "A2", "", "", "", 0, 0, 0, &aid2);
    uint64_t n1 = 0, n2 = 0, n3 = 0;
    ozayn_oan_notif_create(&svc, aid1, "u1", OZAYN_OAN_CHAN_LOCAL_LOG, OZAYN_OAN_SEV_LOW, "t", "b", &n1);
    ozayn_oan_notif_create(&svc, aid1, "u2", OZAYN_OAN_CHAN_LOCAL_LOG, OZAYN_OAN_SEV_LOW, "t", "b", &n2);
    ozayn_oan_notif_create(&svc, aid2, "u3", OZAYN_OAN_CHAN_LOCAL_LOG, OZAYN_OAN_SEV_LOW, "t", "b", &n3);
    const ozayn_oan_notification_t *results[10];
    uint32_t count = 0;
    ASSERT_EQ(ozayn_oan_notif_list_by_alert(&svc, aid1, results, 10, &count), OZAYN_OAN_ERR_OK);
    ASSERT_EQ(count, (uint32_t)2);
    ASSERT_EQ(ozayn_oan_notif_list_by_alert(&svc, aid2, results, 10, &count), OZAYN_OAN_ERR_OK);
    ASSERT_EQ(count, (uint32_t)1);
    ozayn_oan_shutdown(&svc);
    return 0;
}

TEST(test_notif_pending_count) {
    ozayn_oan_service_t svc = _make_svc();
    ASSERT_EQ(ozayn_oan_notif_pending_count(&svc), (int64_t)-1);
    ozayn_oan_init(&svc);
    ASSERT_EQ(ozayn_oan_notif_pending_count(&svc), (int64_t)0);
    uint64_t aid = 0;
    ozayn_oan_alert_create(&svc, OZAYN_OAN_CAT_SYSTEM, OZAYN_OAN_SEV_INFO,
              OZAYN_OAN_SRC_MANUAL, OZAYN_OAN_TRIGGER_EVENT, "P", "", "", "", 0, 0, 0, &aid);
    uint64_t nid = 0;
    ozayn_oan_notif_create(&svc, aid, "u", OZAYN_OAN_CHAN_LOCAL_LOG, OZAYN_OAN_SEV_INFO, "t", "b", &nid);
    ASSERT_EQ(ozayn_oan_notif_pending_count(&svc), (int64_t)1);
    ozayn_oan_shutdown(&svc);
    return 0;
}

/* ============================================================
 * NOTIFICATION POLICY TESTS
 * ============================================================ */

TEST(test_policy_create) {
    ozayn_oan_service_t svc = _make_svc();
    ozayn_oan_init(&svc);
    uint64_t pid = 0;
    ASSERT_EQ(ozayn_oan_policy_create(&svc, "high_alerts", OZAYN_OAN_SEV_HIGH,
              60, 10, 3, 5, 3600, &pid), OZAYN_OAN_ERR_OK);
    ASSERT(pid > 0);
    ASSERT_EQ(svc.policy_count, (uint64_t)1);
    const ozayn_oan_policy_t *p = 0;
    ozayn_oan_policy_get(&svc, pid, &p);
    ASSERT(strcmp(p->name, "high_alerts") == 0);
    ASSERT_EQ(p->min_severity, OZAYN_OAN_SEV_HIGH);
    ASSERT_EQ(p->cooldown_seconds, (uint64_t)60);
    ASSERT_EQ(p->max_notifications_per_hour, (uint32_t)10);
    ASSERT_EQ(p->retry_limit, (uint32_t)3);
    ASSERT(p->enabled);
    ozayn_oan_shutdown(&svc);
    return 0;
}

TEST(test_policy_enable_disable) {
    ozayn_oan_service_t svc = _make_svc();
    ozayn_oan_init(&svc);
    uint64_t pid = 0;
    ozayn_oan_policy_create(&svc, "toggle", OZAYN_OAN_SEV_LOW, 0, 0, 0, 0, 0, &pid);
    ASSERT_EQ(ozayn_oan_policy_disable(&svc, pid), OZAYN_OAN_ERR_OK);
    const ozayn_oan_policy_t *p;
    ozayn_oan_policy_get(&svc, pid, &p);
    ASSERT(!p->enabled);
    ASSERT_EQ(ozayn_oan_policy_enable(&svc, pid), OZAYN_OAN_ERR_OK);
    ozayn_oan_shutdown(&svc);
    return 0;
}

TEST(test_policy_set_category) {
    ozayn_oan_service_t svc = _make_svc();
    ozayn_oan_init(&svc);
    uint64_t pid = 0;
    ozayn_oan_policy_create(&svc, "cat_policy", OZAYN_OAN_SEV_INFO, 0, 0, 0, 0, 0, &pid);
    ASSERT_EQ(ozayn_oan_policy_set_category(&svc, pid, OZAYN_OAN_CAT_RESOURCE, 0), OZAYN_OAN_ERR_OK);
    const ozayn_oan_policy_t *p;
    ozayn_oan_policy_get(&svc, pid, &p);
    ASSERT(!p->category_mask[OZAYN_OAN_CAT_RESOURCE]);
    ASSERT(p->category_mask[OZAYN_OAN_CAT_SYSTEM]);
    ozayn_oan_shutdown(&svc);
    return 0;
}

TEST(test_policy_set_channel) {
    ozayn_oan_service_t svc = _make_svc();
    ozayn_oan_init(&svc);
    uint64_t pid = 0;
    ozayn_oan_policy_create(&svc, "chan_policy", OZAYN_OAN_SEV_INFO, 0, 0, 0, 0, 0, &pid);
    ASSERT_EQ(ozayn_oan_policy_set_channel(&svc, pid, OZAYN_OAN_CHAN_EMAIL, 0), OZAYN_OAN_ERR_OK);
    const ozayn_oan_policy_t *p;
    ozayn_oan_policy_get(&svc, pid, &p);
    ASSERT(!p->allowed_channels[OZAYN_OAN_CHAN_EMAIL]);
    ASSERT(p->allowed_channels[OZAYN_OAN_CHAN_LOCAL_LOG]);
    ozayn_oan_shutdown(&svc);
    return 0;
}

TEST(test_policy_evaluate) {
    ozayn_oan_service_t svc = _make_svc();
    ozayn_oan_init(&svc);
    uint64_t pid = 0;
    ozayn_oan_policy_create(&svc, "eval_policy", OZAYN_OAN_SEV_HIGH, 0, 0, 0, 0, 0, &pid);
    const ozayn_oan_policy_t *p = 0;
    ASSERT_EQ(ozayn_oan_policy_evaluate(&svc, OZAYN_OAN_CAT_PERFORMANCE, OZAYN_OAN_SEV_CRITICAL, &p), OZAYN_OAN_ERR_OK);
    ASSERT(p != 0);
    ASSERT_EQ(p->policy_id, pid);
    ASSERT_EQ(ozayn_oan_policy_evaluate(&svc, OZAYN_OAN_CAT_PERFORMANCE, OZAYN_OAN_SEV_LOW, &p), OZAYN_OAN_ERR_NOT_FOUND);
    ASSERT(p == 0);
    ozayn_oan_shutdown(&svc);
    return 0;
}

/* ============================================================
 * RATE LIMITING TESTS
 * ============================================================ */

TEST(test_rate_limiting_alerts) {
    ozayn_oan_service_t svc = _make_svc();
    ozayn_oan_init(&svc);
    ASSERT_EQ(ozayn_oan_rate_check_alerts(&svc, 3), OZAYN_OAN_ERR_OK);
    ozayn_oan_rate_record_alert(&svc);
    ozayn_oan_rate_record_alert(&svc);
    ozayn_oan_rate_record_alert(&svc);
    ASSERT_EQ(ozayn_oan_rate_check_alerts(&svc, 3), OZAYN_OAN_ERR_RATE_LIMITED);
    ASSERT_EQ(svc.stats.total_rate_limited, (uint64_t)1);
    ozayn_oan_shutdown(&svc);
    return 0;
}

TEST(test_rate_limiting_notifications) {
    ozayn_oan_service_t svc = _make_svc();
    ozayn_oan_init(&svc);
    ASSERT_EQ(ozayn_oan_rate_check_notifications(&svc, 2), OZAYN_OAN_ERR_OK);
    ozayn_oan_rate_record_notification(&svc);
    ozayn_oan_rate_record_notification(&svc);
    ASSERT_EQ(ozayn_oan_rate_check_notifications(&svc, 2), OZAYN_OAN_ERR_RATE_LIMITED);
    ozayn_oan_shutdown(&svc);
    return 0;
}

/* ============================================================
 * EXPIRATION TESTS
 * ============================================================ */

TEST(test_cleanup_expired) {
    ozayn_oan_service_t svc = _make_svc();
    ozayn_oan_init(&svc);
    uint64_t aid = 0;
    ozayn_oan_alert_create(&svc, OZAYN_OAN_CAT_SYSTEM, OZAYN_OAN_SEV_INFO,
              OZAYN_OAN_SRC_MANUAL, OZAYN_OAN_TRIGGER_EVENT, "Expire", "", "", "", 0, 0, 0, &aid);
    svc.alerts[0].expiration_time = 1;
    ozayn_oan_alert_activate(&svc, aid);
    ASSERT_EQ(ozayn_oan_cleanup_expired(&svc), OZAYN_OAN_ERR_OK);
    ASSERT_EQ(svc.alerts[0].state, OZAYN_OAN_STATE_EXPIRED);
    ozayn_oan_shutdown(&svc);
    return 0;
}

/* ============================================================
 * SHUTDOWN DRAIN TESTS
 * ============================================================ */

TEST(test_shutdown_drain) {
    ozayn_oan_service_t svc = _make_svc();
    ozayn_oan_init(&svc);
    uint64_t a = 0, n = 0;
    uint64_t pending_a = 0, pending_n = 0;
    ozayn_oan_alert_create(&svc, OZAYN_OAN_CAT_SYSTEM, OZAYN_OAN_SEV_LOW,
              OZAYN_OAN_SRC_MANUAL, OZAYN_OAN_TRIGGER_EVENT, "Drain", "", "", "", 0, 0, 0, &a);
    ozayn_oan_notif_create(&svc, a, "u", OZAYN_OAN_CHAN_LOCAL_LOG, OZAYN_OAN_SEV_LOW, "t", "b", &n);
    ASSERT_EQ(ozayn_oan_shutdown_drain(&svc, &pending_a, &pending_n), OZAYN_OAN_ERR_OK);
    ASSERT(pending_a > 0);
    ASSERT(pending_n > 0);
    ozayn_oan_shutdown(&svc);
    return 0;
}

TEST(test_shutdown_drain_not_init) {
    ozayn_oan_service_t svc = _make_svc();
    ASSERT_EQ(ozayn_oan_shutdown_drain(&svc, 0, 0), OZAYN_OAN_ERR_NOT_INITIALIZED);
    return 0;
}

/* ============================================================
 * STATS TESTS
 * ============================================================ */

TEST(test_stats_null) {
    ozayn_oan_stats_t s = ozayn_oan_get_stats(0);
    ASSERT_EQ(s.total_alerts_created, (uint64_t)0);
    return 0;
}

TEST(test_stats_basic) {
    ozayn_oan_service_t svc = _make_svc();
    ozayn_oan_init(&svc);
    ozayn_oan_stats_t s = ozayn_oan_get_stats(&svc);
    ASSERT_EQ(s.total_alerts_created, (uint64_t)0);
    ASSERT_EQ(s.total_rules_evaluated, (uint64_t)0);
    ASSERT_EQ(s.total_notifications_created, (uint64_t)0);
    ASSERT_EQ(s.total_rate_limited, (uint64_t)0);
    ozayn_oan_shutdown(&svc);
    return 0;
}

/* ============================================================
 * NULL / NOT INIT TESTS
 * ============================================================ */

TEST(test_rule_null_not_init) {
    uint64_t rid = 0;
    ASSERT_EQ(ozayn_oan_rule_create(0, "x", 0, OZAYN_OAN_TRIGGER_EVENT, OZAYN_OAN_CAT_SYSTEM,
              OZAYN_OAN_SEV_INFO, "", 0, 0, 0, 0, 0, &rid), OZAYN_OAN_ERR_NULL_PTR);
    ozayn_oan_service_t svc = _make_svc();
    ASSERT_EQ(ozayn_oan_rule_create(&svc, "x", 0, OZAYN_OAN_TRIGGER_EVENT, OZAYN_OAN_CAT_SYSTEM,
              OZAYN_OAN_SEV_INFO, "", 0, 0, 0, 0, 0, &rid), OZAYN_OAN_ERR_NOT_INITIALIZED);
    return 0;
}

TEST(test_alert_null_not_init) {
    uint64_t aid = 0;
    ASSERT_EQ(ozayn_oan_alert_create(0, OZAYN_OAN_CAT_SYSTEM, OZAYN_OAN_SEV_INFO,
              OZAYN_OAN_SRC_MANUAL, OZAYN_OAN_TRIGGER_EVENT, "x", 0, 0, 0, 0, 0, 0, &aid), OZAYN_OAN_ERR_NULL_PTR);
    ozayn_oan_service_t svc = _make_svc();
    ASSERT_EQ(ozayn_oan_alert_create(&svc, OZAYN_OAN_CAT_SYSTEM, OZAYN_OAN_SEV_INFO,
              OZAYN_OAN_SRC_MANUAL, OZAYN_OAN_TRIGGER_EVENT, "x", 0, 0, 0, 0, 0, 0, &aid), OZAYN_OAN_ERR_NOT_INITIALIZED);
    return 0;
}

TEST(test_notif_null_not_init) {
    uint64_t nid = 0;
    ASSERT_EQ(ozayn_oan_notif_create(0, 0, "u", OZAYN_OAN_CHAN_LOCAL_LOG,
              OZAYN_OAN_SEV_INFO, "t", "b", &nid), OZAYN_OAN_ERR_NULL_PTR);
    ozayn_oan_service_t svc = _make_svc();
    ASSERT_EQ(ozayn_oan_notif_create(&svc, 0, "u", OZAYN_OAN_CHAN_LOCAL_LOG,
              OZAYN_OAN_SEV_INFO, "t", "b", &nid), OZAYN_OAN_ERR_NOT_INITIALIZED);
    return 0;
}

TEST(test_policy_null_not_init) {
    uint64_t pid = 0;
    ASSERT_EQ(ozayn_oan_policy_create(0, "x", OZAYN_OAN_SEV_INFO, 0, 0, 0, 0, 0, &pid), OZAYN_OAN_ERR_NULL_PTR);
    ozayn_oan_service_t svc = _make_svc();
    ASSERT_EQ(ozayn_oan_policy_create(&svc, "x", OZAYN_OAN_SEV_INFO, 0, 0, 0, 0, 0, &pid), OZAYN_OAN_ERR_NOT_INITIALIZED);
    return 0;
}

/* ============================================================
 * EDGE CASES
 * ============================================================ */

TEST(test_notif_failure_exhausted) {
    ozayn_oan_service_t svc = _make_svc();
    ozayn_oan_init(&svc);
    uint64_t aid = 0;
    ozayn_oan_alert_create(&svc, OZAYN_OAN_CAT_SYSTEM, OZAYN_OAN_SEV_LOW,
              OZAYN_OAN_SRC_MANUAL, OZAYN_OAN_TRIGGER_EVENT, "Exhaust", "", "", "", 0, 0, 0, &aid);
    uint64_t nid = 0;
    ozayn_oan_notif_create(&svc, aid, "u", OZAYN_OAN_CHAN_WEBHOOK, OZAYN_OAN_SEV_LOW, "t", "b", &nid);
    ozayn_oan_notif_advance(&svc, nid, OZAYN_OAN_NSTATE_QUEUED);
    ozayn_oan_notif_advance(&svc, nid, OZAYN_OAN_NSTATE_SENDING);
    ozayn_oan_notif_advance(&svc, nid, OZAYN_OAN_NSTATE_FAILED);
    ASSERT_EQ(svc.notifications[0].state, OZAYN_OAN_NSTATE_RETRYING);
    ozayn_oan_notif_advance(&svc, nid, OZAYN_OAN_NSTATE_QUEUED);
    ozayn_oan_notif_advance(&svc, nid, OZAYN_OAN_NSTATE_SENDING);
    ozayn_oan_notif_advance(&svc, nid, OZAYN_OAN_NSTATE_FAILED);
    ASSERT_EQ(svc.notifications[0].state, OZAYN_OAN_NSTATE_RETRYING);
    ozayn_oan_notif_advance(&svc, nid, OZAYN_OAN_NSTATE_QUEUED);
    ozayn_oan_notif_advance(&svc, nid, OZAYN_OAN_NSTATE_SENDING);
    ozayn_oan_notif_advance(&svc, nid, OZAYN_OAN_NSTATE_FAILED);
    ASSERT_EQ(svc.notifications[0].state, OZAYN_OAN_NSTATE_RETRYING);
    ozayn_oan_notif_advance(&svc, nid, OZAYN_OAN_NSTATE_QUEUED);
    ozayn_oan_notif_advance(&svc, nid, OZAYN_OAN_NSTATE_SENDING);
    ozayn_oan_notif_advance(&svc, nid, OZAYN_OAN_NSTATE_FAILED);
    ASSERT_EQ(svc.notifications[0].state, OZAYN_OAN_NSTATE_FAILED);
    ASSERT_EQ(svc.notifications[0].attempt_count, (uint32_t)3);
    ozayn_oan_shutdown(&svc);
    return 0;
}

TEST(test_group_key) {
    ozayn_oan_service_t svc = _make_svc();
    ozayn_oan_init(&svc);
    uint64_t aid = 0;
    ozayn_oan_alert_create(&svc, OZAYN_OAN_CAT_RESOURCE, OZAYN_OAN_SEV_HIGH,
              OZAYN_OAN_SRC_RESOURCE, OZAYN_OAN_TRIGGER_RESOURCE_THRESHOLD,
              "Grouped", "", "", "", 0, 80, 90, &aid);
    ASSERT_EQ(ozayn_oan_alert_set_group_key(&svc, aid, "res-cpu-group"), OZAYN_OAN_ERR_OK);
    ASSERT(strcmp(svc.alerts[0].group_key, "res-cpu-group") == 0);
    ozayn_oan_shutdown(&svc);
    return 0;
}

/* ============================================================
 * SUITE
 * ============================================================ */

int run_cr_operational_alert_tests(void) {
    int fail = 0;
    SUITE_BEGIN("operational_alert");
    RUN(test_err_name);
    RUN(test_category_name);
    RUN(test_severity_name);
    RUN(test_state_name);
    RUN(test_source_name);
    RUN(test_trigger_name);
    RUN(test_channel_name);
    RUN(test_nstate_name);
    RUN(test_init_null);
    RUN(test_init_basic);
    RUN(test_init_double);
    RUN(test_shutdown_null);
    RUN(test_shutdown_basic);
    RUN(test_is_initialized);
    RUN(test_bind_subsystems);
    RUN(test_state_transitions_valid);
    RUN(test_state_transitions_invalid);
    RUN(test_nstate_transitions_valid);
    RUN(test_nstate_transitions_invalid);
    RUN(test_rule_create);
    RUN(test_rule_get);
    RUN(test_rule_disable_enable);
    RUN(test_rule_remove);
    RUN(test_rule_evaluate);
    RUN(test_rule_evaluate_disabled);
    RUN(test_alert_create);
    RUN(test_alert_duplicate_correlation);
    RUN(test_alert_lifecycle_full);
    RUN(test_alert_suppress);
    RUN(test_alert_cancel);
    RUN(test_alert_expire);
    RUN(test_alert_invalid_transition);
    RUN(test_alert_set_refs);
    RUN(test_alert_get_by_correlation);
    RUN(test_alert_list_active);
    RUN(test_alert_list_by_severity);
    RUN(test_alert_list_by_category);
    RUN(test_alert_list_by_source);
    RUN(test_alert_counts);
    RUN(test_summary);
    RUN(test_dedup_register_and_check);
    RUN(test_dedup_cleanup);
    RUN(test_notif_create);
    RUN(test_notif_lifecycle);
    RUN(test_notif_failure_retry);
    RUN(test_notif_cancel);
    RUN(test_notif_list_by_alert);
    RUN(test_notif_pending_count);
    RUN(test_policy_create);
    RUN(test_policy_enable_disable);
    RUN(test_policy_set_category);
    RUN(test_policy_set_channel);
    RUN(test_policy_evaluate);
    RUN(test_rate_limiting_alerts);
    RUN(test_rate_limiting_notifications);
    RUN(test_cleanup_expired);
    RUN(test_shutdown_drain);
    RUN(test_shutdown_drain_not_init);
    RUN(test_stats_null);
    RUN(test_stats_basic);
    RUN(test_rule_null_not_init);
    RUN(test_alert_null_not_init);
    RUN(test_notif_null_not_init);
    RUN(test_policy_null_not_init);
    RUN(test_notif_failure_exhausted);
    RUN(test_group_key);
    SUITE_END();
    return fail;
}
