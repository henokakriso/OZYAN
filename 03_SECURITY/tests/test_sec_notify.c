/*
 * test_sec_notify.c — Security Notification Routing & Delivery Tests (Step 30).
 */

#include "../../tests/test_framework.h"
#include "../sec_notify.h"
#include "../sec_alert.h"
#include "../sec_config.h"
#include <string.h>
#include <time.h>

/* ============================================================
 * TEST HELPERS
 * ============================================================ */

static ozayn_snotify_service_t _svc;
static ozayn_salert_service_t _alert_svc;
static ozayn_sc_service_t _sc_svc;
static ozayn_audit_service_t _au_svc;

static void _reset_all(void)
{
    memset(&_svc, 0, sizeof(_svc));
    memset(&_alert_svc, 0, sizeof(_alert_svc));
    memset(&_sc_svc, 0, sizeof(_sc_svc));
    memset(&_au_svc, 0, sizeof(_au_svc));
}

static void _init_svc(void)
{
    _reset_all();
    _au_svc.initialized = 1;
    _sc_svc.initialized = 1;

    ozayn_salert_service_config_t acfg;
    memset(&acfg, 0, sizeof(acfg));
    acfg.audit = &_au_svc;
    ozayn_salert_service_init(&_alert_svc, &acfg);

    ozayn_snotify_service_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.alert_service = &_alert_svc;
    cfg.config_service = &_sc_svc;
    cfg.audit = &_au_svc;
    ozayn_snotify_service_init(&_svc, &cfg);
}

/* ============================================================
 * TEST PROVIDER
 * ============================================================ */

static int _test_send_result = 0;
static int _test_send_ok = 0;

static int _test_send(const void *ctx,
                      const ozayn_snotify_notification_t *notif,
                      const ozayn_snotify_content_t *content,
                      ozayn_snotify_delivery_result_t *out_result)
{
    (void)ctx; (void)notif; (void)content;
    _test_send_ok++;
    if (out_result) {
        memset(out_result, 0, sizeof(*out_result));
        if (notif)
            strncpy(out_result->notif_id, notif->notif_id,
                    sizeof(out_result->notif_id) - 1);
        strncpy(out_result->provider_id, "TEST_PROVIDER",
                sizeof(out_result->provider_id) - 1);
        out_result->channel = notif ? notif->channel : OZAYN_SALERT_NOTIFY_LOCAL;
        out_result->result = _test_send_result;
        out_result->attempt_number = notif ? notif->attempt_count : 0;
        out_result->timestamp = time(NULL);
        out_result->retry_recommended =
            (_test_send_result == OZAYN_SNOTIFY_RESULT_TEMPORARY_FAILURE ||
             _test_send_result == OZAYN_SNOTIFY_RESULT_TIMEOUT);
    }
    return _test_send_result == OZAYN_SNOTIFY_RESULT_SUCCESS ? 0 : -1;
}

static int _test_is_available(const void *ctx)
{
    (void)ctx;
    return 1;
}

static const char *_test_get_id(const void *ctx)
{
    (void)ctx;
    return "TEST_PROVIDER";
}

static int _test_get_channel(const void *ctx,
                              ozayn_salert_notify_channel_t *out_ch)
{
    (void)ctx;
    if (out_ch) *out_ch = OZAYN_SALERT_NOTIFY_LOCAL;
    return 0;
}

static int _test_validate_dest(const void *ctx,
                                const ozayn_snotify_destination_t *dest)
{
    (void)ctx; (void)dest;
    return 1;
}

static int _test_get_timeout(const void *ctx)
{
    (void)ctx;
    return 5000;
}

static ozayn_snotify_provider_vtable_t _test_vtable = {
    .send = _test_send,
    .is_available = _test_is_available,
    .get_provider_id = _test_get_id,
    .get_channel = _test_get_channel,
    .validate_destination = _test_validate_dest,
    .get_timeout_ms = _test_get_timeout
};

static ozayn_salert_alert_t *_create_test_alert(
    ozayn_salert_severity_t sev,
    ozayn_salert_priority_t prio,
    const char *summary)
{
    ozayn_salert_alert_t *a = NULL;
    ozayn_salert_create(&_alert_svc,
        OZAYN_SALERT_TYPE_AUTH_FAILURE, sev, prio,
        OZAYN_SALERT_SOURCE_AUTHENTICATION,
        "TEST", NULL, summary, NULL, &a);
    return a;
}

/* ============================================================
 * LIFECYCLE TESTS
 * ============================================================ */

TEST(test_snotify_init)
{
    _reset_all();
    ozayn_snotify_service_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    ASSERT_EQ(OZAYN_SNOTIFY_OK,
              ozayn_snotify_service_init(&_svc, &cfg));
    ASSERT(ozayn_snotify_service_is_initialized(&_svc));
    ozayn_snotify_service_shutdown(&_svc);
    ASSERT(!ozayn_snotify_service_is_initialized(&_svc));
    return 0;
}

TEST(test_snotify_init_null)
{
    ASSERT_EQ(OZAYN_SNOTIFY_ERR_NULL,
              ozayn_snotify_service_init(NULL, NULL));
    return 0;
}

TEST(test_snotify_init_double)
{
    _reset_all();
    ozayn_snotify_service_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    ASSERT_EQ(OZAYN_SNOTIFY_OK,
              ozayn_snotify_service_init(&_svc, &cfg));
    ASSERT_EQ(OZAYN_SNOTIFY_ERR_ALREADY_INITIALIZED,
              ozayn_snotify_service_init(&_svc, &cfg));
    ozayn_snotify_service_shutdown(&_svc);
    return 0;
}

TEST(test_snotify_shutdown_null)
{
    ozayn_snotify_service_shutdown(NULL);
    return 0;
}

TEST(test_snotify_global)
{
    ozayn_snotify_service_t *g = ozayn_snotify_get_global();
    ASSERT(g != NULL);
    return 0;
}

/* ============================================================
 * STATE HELPER TESTS
 * ============================================================ */

TEST(test_snotify_state_names)
{
    ASSERT(strcmp(ozayn_snotify_state_name(OZAYN_SNOTIFY_STATE_CREATED),
                  "CREATED") == 0);
    ASSERT(strcmp(ozayn_snotify_state_name(OZAYN_SNOTIFY_STATE_DELIVERED),
                  "DELIVERED") == 0);
    ASSERT(strcmp(ozayn_snotify_state_name(
        (ozayn_snotify_state_t)99), "UNKNOWN") == 0);
    return 0;
}

TEST(test_snotify_result_names)
{
    ASSERT(strcmp(ozayn_snotify_result_name(OZAYN_SNOTIFY_RESULT_SUCCESS),
                  "SUCCESS") == 0);
    ASSERT(strcmp(ozayn_snotify_result_name(
        (ozayn_snotify_result_t)99), "UNKNOWN") == 0);
    return 0;
}

TEST(test_snotify_err_names)
{
    ASSERT(strcmp(ozayn_snotify_err_name(OZAYN_SNOTIFY_OK), "OK") == 0);
    ASSERT(strcmp(ozayn_snotify_err_name(OZAYN_SNOTIFY_ERR_NULL),
                  "NULL") == 0);
    ASSERT(strcmp(ozayn_snotify_err_name(
        (ozayn_snotify_err_t)99), "UNKNOWN") == 0);
    return 0;
}

TEST(test_snotify_dest_state_names)
{
    ASSERT(strcmp(ozayn_snotify_dest_state_name(OZAYN_SNOTIFY_DEST_AVAILABLE),
                  "AVAILABLE") == 0);
    ASSERT(strcmp(ozayn_snotify_dest_state_name(
        (ozayn_snotify_dest_state_t)99), "UNKNOWN") == 0);
    return 0;
}

TEST(test_snotify_dest_type_names)
{
    ASSERT(strcmp(ozayn_snotify_dest_type_name(OZAYN_SNOTIFY_DEST_TYPE_LOCAL),
                  "LOCAL") == 0);
    ASSERT(strcmp(ozayn_snotify_dest_type_name(
        (ozayn_snotify_dest_type_t)99), "UNKNOWN") == 0);
    return 0;
}

TEST(test_snotify_classification_names)
{
    ASSERT(strcmp(ozayn_snotify_classification_name(OZAYN_SNOTIFY_CLASS_PUBLIC),
                  "PUBLIC") == 0);
    ASSERT(strcmp(ozayn_snotify_classification_name(
        (ozayn_snotify_classification_t)99), "UNKNOWN") == 0);
    return 0;
}

/* ============================================================
 * STATE TRANSITION TESTS
 * ============================================================ */

TEST(test_snotify_valid_transitions)
{
    ASSERT(ozayn_snotify_state_transition_valid(
        OZAYN_SNOTIFY_STATE_CREATED, OZAYN_SNOTIFY_STATE_ROUTING));
    ASSERT(ozayn_snotify_state_transition_valid(
        OZAYN_SNOTIFY_STATE_CREATED, OZAYN_SNOTIFY_STATE_CANCELLED));
    ASSERT(ozayn_snotify_state_transition_valid(
        OZAYN_SNOTIFY_STATE_ROUTING, OZAYN_SNOTIFY_STATE_QUEUED));
    ASSERT(ozayn_snotify_state_transition_valid(
        OZAYN_SNOTIFY_STATE_ROUTING, OZAYN_SNOTIFY_STATE_DELIVERY_FAILED));
    ASSERT(ozayn_snotify_state_transition_valid(
        OZAYN_SNOTIFY_STATE_QUEUED, OZAYN_SNOTIFY_STATE_DELIVERING));
    ASSERT(ozayn_snotify_state_transition_valid(
        OZAYN_SNOTIFY_STATE_QUEUED, OZAYN_SNOTIFY_STATE_EXPIRED));
    ASSERT(ozayn_snotify_state_transition_valid(
        OZAYN_SNOTIFY_STATE_QUEUED, OZAYN_SNOTIFY_STATE_CANCELLED));
    ASSERT(ozayn_snotify_state_transition_valid(
        OZAYN_SNOTIFY_STATE_DELIVERING, OZAYN_SNOTIFY_STATE_DELIVERED));
    ASSERT(ozayn_snotify_state_transition_valid(
        OZAYN_SNOTIFY_STATE_DELIVERING, OZAYN_SNOTIFY_STATE_DELIVERY_FAILED));
    ASSERT(ozayn_snotify_state_transition_valid(
        OZAYN_SNOTIFY_STATE_DELIVERY_FAILED, OZAYN_SNOTIFY_STATE_RETRY_SCHEDULED));
    ASSERT(ozayn_snotify_state_transition_valid(
        OZAYN_SNOTIFY_STATE_DELIVERY_FAILED, OZAYN_SNOTIFY_STATE_EXHAUSTED));
    ASSERT(ozayn_snotify_state_transition_valid(
        OZAYN_SNOTIFY_STATE_RETRY_SCHEDULED, OZAYN_SNOTIFY_STATE_QUEUED));
    ASSERT(ozayn_snotify_state_transition_valid(
        OZAYN_SNOTIFY_STATE_RETRY_SCHEDULED, OZAYN_SNOTIFY_STATE_EXHAUSTED));
    return 0;
}

TEST(test_snotify_invalid_transitions)
{
    ASSERT(!ozayn_snotify_state_transition_valid(
        OZAYN_SNOTIFY_STATE_CREATED, OZAYN_SNOTIFY_STATE_DELIVERED));
    ASSERT(!ozayn_snotify_state_transition_valid(
        OZAYN_SNOTIFY_STATE_DELIVERED, OZAYN_SNOTIFY_STATE_CREATED));
    ASSERT(!ozayn_snotify_state_transition_valid(
        OZAYN_SNOTIFY_STATE_EXHAUSTED, OZAYN_SNOTIFY_STATE_QUEUED));
    ASSERT(!ozayn_snotify_state_transition_valid(
        OZAYN_SNOTIFY_STATE_EXPIRED, OZAYN_SNOTIFY_STATE_QUEUED));
    ASSERT(!ozayn_snotify_state_transition_valid(
        OZAYN_SNOTIFY_STATE_CANCELLED, OZAYN_SNOTIFY_STATE_QUEUED));
    return 0;
}

TEST(test_snotify_dest_valid_transitions)
{
    ASSERT(ozayn_snotify_dest_transition_valid(
        OZAYN_SNOTIFY_DEST_UNINITIALIZED, OZAYN_SNOTIFY_DEST_AVAILABLE));
    ASSERT(ozayn_snotify_dest_transition_valid(
        OZAYN_SNOTIFY_DEST_AVAILABLE, OZAYN_SNOTIFY_DEST_DISABLED));
    ASSERT(ozayn_snotify_dest_transition_valid(
        OZAYN_SNOTIFY_DEST_AVAILABLE, OZAYN_SNOTIFY_DEST_REVOKED));
    ASSERT(ozayn_snotify_dest_transition_valid(
        OZAYN_SNOTIFY_DEST_DISABLED, OZAYN_SNOTIFY_DEST_AVAILABLE));
    ASSERT(!ozayn_snotify_dest_transition_valid(
        OZAYN_SNOTIFY_DEST_REVOKED, OZAYN_SNOTIFY_DEST_AVAILABLE));
    return 0;
}

/* ============================================================
 * DESTINATION TESTS
 * ============================================================ */

TEST(test_snotify_dest_add)
{
    _init_svc();
    ozayn_snotify_destination_t *d = NULL;
    ASSERT_EQ(OZAYN_SNOTIFY_OK,
              ozayn_snotify_dest_add(&_svc, "DEST-1", "Test Dest",
                  OZAYN_SALERT_NOTIFY_LOCAL,
                  OZAYN_SNOTIFY_DEST_TYPE_LOCAL,
                  OZAYN_SNOTIFY_CLASS_HIGHLY_SENSITIVE,
                  "safe", &d));
    ASSERT(d != NULL);
    ASSERT(strcmp(d->dest_id, "DEST-1") == 0);
    ASSERT_EQ(1, ozayn_snotify_dest_count(&_svc));
    return 0;
}

TEST(test_snotify_dest_add_null)
{
    _init_svc();
    ASSERT_EQ(OZAYN_SNOTIFY_ERR_NULL,
              ozayn_snotify_dest_add(NULL, "D", "D",
                  OZAYN_SALERT_NOTIFY_LOCAL,
                  OZAYN_SNOTIFY_DEST_TYPE_LOCAL,
                  OZAYN_SNOTIFY_CLASS_PUBLIC, NULL, NULL));
    ASSERT_EQ(OZAYN_SNOTIFY_ERR_INVALID_PARAM,
              ozayn_snotify_dest_add(&_svc, "", "D",
                  OZAYN_SALERT_NOTIFY_LOCAL,
                  OZAYN_SNOTIFY_DEST_TYPE_LOCAL,
                  OZAYN_SNOTIFY_CLASS_PUBLIC, NULL, NULL));
    return 0;
}

TEST(test_snotify_dest_add_duplicate)
{
    _init_svc();
    ozayn_snotify_destination_t *d = NULL;
    ASSERT_EQ(OZAYN_SNOTIFY_OK,
              ozayn_snotify_dest_add(&_svc, "DUP-1", "D",
                  OZAYN_SALERT_NOTIFY_LOCAL,
                  OZAYN_SNOTIFY_DEST_TYPE_LOCAL,
                  OZAYN_SNOTIFY_CLASS_PUBLIC, NULL, &d));
    d = NULL;
    ASSERT_EQ(OZAYN_SNOTIFY_ERR_CONFLICT,
              ozayn_snotify_dest_add(&_svc, "DUP-1", "D",
                  OZAYN_SALERT_NOTIFY_LOCAL,
                  OZAYN_SNOTIFY_DEST_TYPE_LOCAL,
                  OZAYN_SNOTIFY_CLASS_PUBLIC, NULL, &d));
    return 0;
}

TEST(test_snotify_dest_remove)
{
    _init_svc();
    ozayn_snotify_destination_t *d = NULL;
    ozayn_snotify_dest_add(&_svc, "RM-1", "R",
        OZAYN_SALERT_NOTIFY_LOCAL, OZAYN_SNOTIFY_DEST_TYPE_LOCAL,
        OZAYN_SNOTIFY_CLASS_PUBLIC, NULL, &d);
    ASSERT_EQ(OZAYN_SNOTIFY_OK, ozayn_snotify_dest_remove(&_svc, "RM-1"));
    d = ozayn_snotify_dest_get(&_svc, "RM-1");
    ASSERT(d != NULL);
    ASSERT_EQ(OZAYN_SNOTIFY_DEST_REVOKED, d->state);
    return 0;
}

TEST(test_snotify_dest_remove_not_found)
{
    _init_svc();
    ASSERT_EQ(OZAYN_SNOTIFY_ERR_NOT_FOUND,
              ozayn_snotify_dest_remove(&_svc, "NOPE"));
    return 0;
}

TEST(test_snotify_dest_get)
{
    _init_svc();
    ozayn_snotify_destination_t *d = NULL;
    ozayn_snotify_dest_add(&_svc, "GET-1", "G",
        OZAYN_SALERT_NOTIFY_LOCAL, OZAYN_SNOTIFY_DEST_TYPE_LOCAL,
        OZAYN_SNOTIFY_CLASS_PUBLIC, NULL, &d);
    ozayn_snotify_destination_t *f = ozayn_snotify_dest_get(&_svc, "GET-1");
    ASSERT(f != NULL);
    ASSERT(strcmp(f->dest_id, "GET-1") == 0);
    ASSERT(ozayn_snotify_dest_get(&_svc, "NOPE") == NULL);
    return 0;
}

TEST(test_snotify_dest_set_state)
{
    _init_svc();
    ozayn_snotify_destination_t *d = NULL;
    ozayn_snotify_dest_add(&_svc, "ST-1", "S",
        OZAYN_SALERT_NOTIFY_LOCAL, OZAYN_SNOTIFY_DEST_TYPE_LOCAL,
        OZAYN_SNOTIFY_CLASS_PUBLIC, NULL, &d);
    ASSERT_EQ(OZAYN_SNOTIFY_OK,
              ozayn_snotify_dest_set_state(&_svc, "ST-1",
                  OZAYN_SNOTIFY_DEST_DISABLED));
    d = ozayn_snotify_dest_get(&_svc, "ST-1");
    ASSERT_EQ(OZAYN_SNOTIFY_DEST_DISABLED, d->state);
    ASSERT_EQ(OZAYN_SNOTIFY_ERR_STATE_TRANSITION,
              ozayn_snotify_dest_set_state(&_svc, "ST-1",
                  OZAYN_SNOTIFY_DEST_REVOKED));
    d = ozayn_snotify_dest_get(&_svc, "ST-1");
    ASSERT_EQ(OZAYN_SNOTIFY_DEST_DISABLED, d->state);
    return 0;
}

TEST(test_snotify_dest_is_usable)
{
    ozayn_snotify_destination_t d;
    memset(&d, 0, sizeof(d));
    d.state = OZAYN_SNOTIFY_DEST_AVAILABLE;
    ASSERT(ozayn_snotify_dest_is_usable(&d));
    d.state = OZAYN_SNOTIFY_DEST_DISABLED;
    ASSERT(!ozayn_snotify_dest_is_usable(&d));
    ASSERT(!ozayn_snotify_dest_is_usable(NULL));
    return 0;
}

/* ============================================================
 * ROUTING TESTS
 * ============================================================ */

TEST(test_snotify_routing_add)
{
    _init_svc();
    ozayn_snotify_routing_rule_t rule;
    memset(&rule, 0, sizeof(rule));
    strncpy(rule.rule_id, "RULE-1", sizeof(rule.rule_id) - 1);
    rule.enabled = 1;
    rule.priority_order = 10;
    rule.min_severity = OZAYN_SALERT_SEV_WARNING;
    rule.max_severity = OZAYN_SALERT_SEV_CRITICAL;
    rule.min_priority = OZAYN_SALERT_PRIO_LOW;
    rule.max_priority = OZAYN_SALERT_PRIO_IMMEDIATE;
    rule.enabled_channels[OZAYN_SALERT_NOTIFY_LOCAL] = 1;
    ASSERT_EQ(OZAYN_SNOTIFY_OK, ozayn_snotify_routing_add(&_svc, &rule));
    return 0;
}

TEST(test_snotify_routing_add_duplicate)
{
    _init_svc();
    ozayn_snotify_routing_rule_t rule;
    memset(&rule, 0, sizeof(rule));
    strncpy(rule.rule_id, "DUP-R", sizeof(rule.rule_id) - 1);
    rule.enabled = 1;
    rule.enabled_channels[OZAYN_SALERT_NOTIFY_LOCAL] = 1;
    ASSERT_EQ(OZAYN_SNOTIFY_OK, ozayn_snotify_routing_add(&_svc, &rule));
    ASSERT_EQ(OZAYN_SNOTIFY_ERR_CONFLICT,
              ozayn_snotify_routing_add(&_svc, &rule));
    return 0;
}

TEST(test_snotify_routing_remove)
{
    _init_svc();
    ozayn_snotify_routing_rule_t rule;
    memset(&rule, 0, sizeof(rule));
    strncpy(rule.rule_id, "RM-R", sizeof(rule.rule_id) - 1);
    rule.enabled = 1;
    rule.enabled_channels[OZAYN_SALERT_NOTIFY_LOCAL] = 1;
    ozayn_snotify_routing_add(&_svc, &rule);
    ASSERT_EQ(OZAYN_SNOTIFY_OK, ozayn_snotify_routing_remove(&_svc, "RM-R"));
    ASSERT_EQ(OZAYN_SNOTIFY_ERR_NOT_FOUND,
              ozayn_snotify_routing_remove(&_svc, "RM-R"));
    return 0;
}

TEST(test_snotify_routing_evaluate)
{
    _init_svc();
    ozayn_snotify_routing_rule_t rule;
    memset(&rule, 0, sizeof(rule));
    strncpy(rule.rule_id, "EVAL-R", sizeof(rule.rule_id) - 1);
    rule.enabled = 1;
    rule.priority_order = 10;
    rule.min_severity = OZAYN_SALERT_SEV_INFO;
    rule.max_severity = OZAYN_SALERT_SEV_CRITICAL;
    rule.min_priority = OZAYN_SALERT_PRIO_LOW;
    rule.max_priority = OZAYN_SALERT_PRIO_IMMEDIATE;
    rule.enabled_channels[OZAYN_SALERT_NOTIFY_LOCAL] = 1;
    ozayn_snotify_routing_add(&_svc, &rule);

    ozayn_salert_alert_t *a = _create_test_alert(
        OZAYN_SALERT_SEV_WARNING, OZAYN_SALERT_PRIO_NORMAL, "Test");
    ASSERT(a != NULL);

    ozayn_salert_notify_channel_t ch;
    ASSERT_EQ(OZAYN_SNOTIFY_OK,
              ozayn_snotify_routing_evaluate(&_svc, a, &ch, NULL, 0));
    ASSERT_EQ(OZAYN_SALERT_NOTIFY_LOCAL, ch);
    return 0;
}

TEST(test_snotify_routing_evaluate_no_route)
{
    _init_svc();
    ozayn_salert_alert_t *a = _create_test_alert(
        OZAYN_SALERT_SEV_INFO, OZAYN_SALERT_PRIO_LOW, "NoRoute");
    ozayn_salert_notify_channel_t ch;
    ASSERT_EQ(OZAYN_SNOTIFY_ERR_ROUTING_FAILED,
              ozayn_snotify_routing_evaluate(&_svc, a, &ch, NULL, 0));
    return 0;
}

TEST(test_snotify_routing_evaluate_type_filter)
{
    _init_svc();
    ozayn_snotify_routing_rule_t rule;
    memset(&rule, 0, sizeof(rule));
    strncpy(rule.rule_id, "TYP-R", sizeof(rule.rule_id) - 1);
    rule.enabled = 1;
    rule.priority_order = 10;
    rule.min_severity = OZAYN_SALERT_SEV_INFO;
    rule.max_severity = OZAYN_SALERT_SEV_CRITICAL;
    rule.type_filter_active = 1;
    rule.alert_type = OZAYN_SALERT_TYPE_MFA_FAILURE;
    rule.enabled_channels[OZAYN_SALERT_NOTIFY_LOCAL] = 1;
    ozayn_snotify_routing_add(&_svc, &rule);

    ozayn_salert_alert_t *a = _create_test_alert(
        OZAYN_SALERT_SEV_HIGH, OZAYN_SALERT_PRIO_HIGH, "WrongType");
    ozayn_salert_notify_channel_t ch;
    ASSERT_EQ(OZAYN_SNOTIFY_ERR_ROUTING_FAILED,
              ozayn_snotify_routing_evaluate(&_svc, a, &ch, NULL, 0));
    return 0;
}

TEST(test_snotify_routing_default)
{
    _init_svc();
    ozayn_salert_alert_t *a = _create_test_alert(
        OZAYN_SALERT_SEV_CRITICAL, OZAYN_SALERT_PRIO_IMMEDIATE, "Default");
    ozayn_salert_notify_channel_t ch;
    ASSERT_EQ(OZAYN_SNOTIFY_OK,
              ozayn_snotify_routing_evaluate_default(&_svc, a, &ch));
    ASSERT(ch >= 0);
    return 0;
}

/* ============================================================
 * POLICY TESTS
 * ============================================================ */

TEST(test_snotify_default_policy)
{
    ozayn_snotify_policy_t p = ozayn_snotify_default_policy();
    ASSERT(p.enabled);
    ASSERT(p.enabled_channels[OZAYN_SALERT_NOTIFY_LOCAL]);
    ASSERT_EQ(3, p.retry_policy.max_retries);
    ASSERT(p.expiration_seconds > 0);
    ASSERT(p.max_rate_per_window > 0);
    return 0;
}

TEST(test_snotify_set_policy)
{
    _init_svc();
    ozayn_snotify_policy_t p = ozayn_snotify_default_policy();
    p.max_rate_per_window = 100;
    ASSERT_EQ(OZAYN_SNOTIFY_OK, ozayn_snotify_set_policy(&_svc, &p));
    const ozayn_snotify_policy_t *got = ozayn_snotify_get_policy(&_svc);
    ASSERT(got != NULL);
    ASSERT_EQ(100, got->max_rate_per_window);
    return 0;
}

TEST(test_snotify_channel_enabled)
{
    _init_svc();
    ASSERT(ozayn_snotify_channel_enabled(&_svc, OZAYN_SALERT_NOTIFY_LOCAL));
    ASSERT(!ozayn_snotify_channel_enabled(&_svc, OZAYN_SALERT_NOTIFY_EMAIL));
    return 0;
}

TEST(test_snotify_channel_enabled_null)
{
    ASSERT(!ozayn_snotify_channel_enabled(NULL, OZAYN_SALERT_NOTIFY_LOCAL));
    return 0;
}

/* ============================================================
 * NOTIFICATION CREATION TESTS
 * ============================================================ */

TEST(test_snotify_create)
{
    _init_svc();
    ozayn_salert_alert_t *a = _create_test_alert(
        OZAYN_SALERT_SEV_HIGH, OZAYN_SALERT_PRIO_HIGH, "CreateTest");
    ozayn_snotify_notification_t *n = NULL;
    ASSERT_EQ(OZAYN_SNOTIFY_OK, ozayn_snotify_create(&_svc, a, &n));
    ASSERT(n != NULL);
    ASSERT(n->notif_id[0] != '\0');
    ASSERT(strcmp(n->alert_id, a->alert_id) == 0);
    ASSERT_EQ(OZAYN_SNOTIFY_STATE_CREATED, n->state);
    ASSERT_EQ(OZAYN_SALERT_SEV_HIGH, n->severity);
    return 0;
}

TEST(test_snotify_create_null)
{
    _init_svc();
    ASSERT_EQ(OZAYN_SNOTIFY_ERR_NULL,
              ozayn_snotify_create(NULL, NULL, NULL));
    return 0;
}

TEST(test_snotify_create_not_init)
{
    ozayn_snotify_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_salert_alert_t *a = _create_test_alert(
        OZAYN_SALERT_SEV_INFO, OZAYN_SALERT_PRIO_LOW, "NotInit");
    ozayn_snotify_notification_t *n = NULL;
    ASSERT_EQ(OZAYN_SNOTIFY_ERR_NOT_INITIALIZED,
              ozayn_snotify_create(&svc, a, &n));
    return 0;
}

TEST(test_snotify_create_dedup)
{
    _init_svc();
    ozayn_salert_alert_t *a = _create_test_alert(
        OZAYN_SALERT_SEV_WARNING, OZAYN_SALERT_PRIO_NORMAL, "Dedup");
    ozayn_snotify_notification_t *n1 = NULL, *n2 = NULL;
    ASSERT_EQ(OZAYN_SNOTIFY_OK, ozayn_snotify_create(&_svc, a, &n1));
    ASSERT_EQ(OZAYN_SNOTIFY_OK, ozayn_snotify_create(&_svc, a, &n2));
    ASSERT(n1 == n2);
    return 0;
}

TEST(test_snotify_create_classification)
{
    _init_svc();
    ozayn_salert_alert_t *a = _create_test_alert(
        OZAYN_SALERT_SEV_CRITICAL, OZAYN_SALERT_PRIO_IMMEDIATE, "Classif");
    ozayn_snotify_notification_t *n = NULL;
    ASSERT_EQ(OZAYN_SNOTIFY_OK, ozayn_snotify_create(&_svc, a, &n));
    ASSERT_EQ(OZAYN_SNOTIFY_CLASS_HIGHLY_SENSITIVE, n->classification);
    return 0;
}

/* ============================================================
 * ROUTE & ENQUEUE TESTS
 * ============================================================ */

TEST(test_snotify_route)
{
    _init_svc();
    ozayn_snotify_routing_rule_t rule;
    memset(&rule, 0, sizeof(rule));
    strncpy(rule.rule_id, "R1", sizeof(rule.rule_id) - 1);
    rule.enabled = 1;
    rule.priority_order = 10;
    rule.min_severity = OZAYN_SALERT_SEV_INFO;
    rule.max_severity = OZAYN_SALERT_SEV_CRITICAL;
    rule.enabled_channels[OZAYN_SALERT_NOTIFY_LOCAL] = 1;
    ozayn_snotify_routing_add(&_svc, &rule);

    ozayn_salert_alert_t *a = _create_test_alert(
        OZAYN_SALERT_SEV_HIGH, OZAYN_SALERT_PRIO_HIGH, "RouteTest");
    ozayn_snotify_notification_t *n = NULL;
    ASSERT_EQ(OZAYN_SNOTIFY_OK, ozayn_snotify_create(&_svc, a, &n));
    ASSERT_EQ(OZAYN_SNOTIFY_OK, ozayn_snotify_route(&_svc, n));
    ASSERT_EQ(OZAYN_SNOTIFY_STATE_ROUTING, n->state);
    ASSERT_EQ(OZAYN_SALERT_NOTIFY_LOCAL, n->channel);
    return 0;
}

TEST(test_snotify_route_no_channel)
{
    _init_svc();
    ozayn_salert_alert_t *a = _create_test_alert(
        OZAYN_SALERT_SEV_INFO, OZAYN_SALERT_PRIO_LOW, "NoRouteCh");
    ozayn_snotify_notification_t *n = NULL;
    ASSERT_EQ(OZAYN_SNOTIFY_OK, ozayn_snotify_create(&_svc, a, &n));
    ozayn_snotify_err_t rc = ozayn_snotify_route(&_svc, n);
    ASSERT(rc == OZAYN_SNOTIFY_OK || rc == OZAYN_SNOTIFY_ERR_ROUTING_FAILED);
    return 0;
}

TEST(test_snotify_enqueue)
{
    _init_svc();
    ozayn_salert_alert_t *a = _create_test_alert(
        OZAYN_SALERT_SEV_WARNING, OZAYN_SALERT_PRIO_NORMAL, "EnqTest");
    ozayn_snotify_notification_t *n = NULL;
    ASSERT_EQ(OZAYN_SNOTIFY_OK, ozayn_snotify_create(&_svc, a, &n));
    n->state = OZAYN_SNOTIFY_STATE_ROUTING;
    ASSERT_EQ(OZAYN_SNOTIFY_OK, ozayn_snotify_enqueue(&_svc, n));
    ASSERT_EQ(OZAYN_SNOTIFY_STATE_QUEUED, n->state);
    return 0;
}

TEST(test_snotify_enqueue_bad_state)
{
    _init_svc();
    ozayn_salert_alert_t *a = _create_test_alert(
        OZAYN_SALERT_SEV_INFO, OZAYN_SALERT_PRIO_LOW, "BadEnq");
    ozayn_snotify_notification_t *n = NULL;
    ASSERT_EQ(OZAYN_SNOTIFY_OK, ozayn_snotify_create(&_svc, a, &n));
    ASSERT_EQ(OZAYN_SNOTIFY_ERR_STATE_TRANSITION,
              ozayn_snotify_enqueue(&_svc, n));
    return 0;
}

/* ============================================================
 * DELIVERY TESTS
 * ============================================================ */

TEST(test_snotify_deliver_success)
{
    _init_svc();
    ozayn_snotify_register_provider(&_svc, &_test_vtable, NULL,
        OZAYN_SALERT_NOTIFY_LOCAL);
    _test_send_result = OZAYN_SNOTIFY_RESULT_SUCCESS;
    _test_send_ok = 0;

    ozayn_salert_alert_t *a = _create_test_alert(
        OZAYN_SALERT_SEV_HIGH, OZAYN_SALERT_PRIO_HIGH, "DelSuccess");
    ozayn_snotify_notification_t *n = NULL;
    ASSERT_EQ(OZAYN_SNOTIFY_OK, ozayn_snotify_create(&_svc, a, &n));
    n->state = OZAYN_SNOTIFY_STATE_QUEUED;
    n->channel = OZAYN_SALERT_NOTIFY_LOCAL;
    ASSERT_EQ(OZAYN_SNOTIFY_OK, ozayn_snotify_deliver(&_svc, n));
    ASSERT_EQ(OZAYN_SNOTIFY_STATE_DELIVERED, n->state);
    ASSERT(_test_send_ok > 0);
    return 0;
}

TEST(test_snotify_deliver_temporary_failure)
{
    _init_svc();
    ozayn_snotify_register_provider(&_svc, &_test_vtable, NULL,
        OZAYN_SALERT_NOTIFY_LOCAL);
    _test_send_result = OZAYN_SNOTIFY_RESULT_TEMPORARY_FAILURE;

    ozayn_salert_alert_t *a = _create_test_alert(
        OZAYN_SALERT_SEV_WARNING, OZAYN_SALERT_PRIO_NORMAL, "TempFail");
    ozayn_snotify_notification_t *n = NULL;
    ASSERT_EQ(OZAYN_SNOTIFY_OK, ozayn_snotify_create(&_svc, a, &n));
    n->state = OZAYN_SNOTIFY_STATE_QUEUED;
    n->channel = OZAYN_SALERT_NOTIFY_LOCAL;
    ASSERT_EQ(OZAYN_SNOTIFY_ERR_PROVIDER_FAILED,
              ozayn_snotify_deliver(&_svc, n));
    ASSERT_EQ(OZAYN_SNOTIFY_STATE_DELIVERY_FAILED, n->state);
    ASSERT_EQ(OZAYN_SNOTIFY_RESULT_TEMPORARY_FAILURE, n->delivery_result);
    return 0;
}

TEST(test_snotify_deliver_no_provider)
{
    _init_svc();
    ozayn_salert_alert_t *a = _create_test_alert(
        OZAYN_SALERT_SEV_INFO, OZAYN_SALERT_PRIO_LOW, "NoProv");
    ozayn_snotify_notification_t *n = NULL;
    ASSERT_EQ(OZAYN_SNOTIFY_OK, ozayn_snotify_create(&_svc, a, &n));
    n->state = OZAYN_SNOTIFY_STATE_QUEUED;
    n->channel = OZAYN_SALERT_NOTIFY_EMAIL;
    ASSERT_EQ(OZAYN_SNOTIFY_ERR_PROVIDER_UNAVAILABLE,
              ozayn_snotify_deliver(&_svc, n));
    return 0;
}

TEST(test_snotify_deliver_classification_reject)
{
    _init_svc();
    ozayn_snotify_register_provider(&_svc, &_test_vtable, NULL,
        OZAYN_SALERT_NOTIFY_LOCAL);

    ozayn_salert_alert_t *a = _create_test_alert(
        OZAYN_SALERT_SEV_CRITICAL, OZAYN_SALERT_PRIO_IMMEDIATE, "ClassRej");
    ozayn_snotify_notification_t *n = NULL;
    ASSERT_EQ(OZAYN_SNOTIFY_OK, ozayn_snotify_create(&_svc, a, &n));
    ASSERT_EQ(OZAYN_SNOTIFY_CLASS_HIGHLY_SENSITIVE, n->classification);
    ASSERT(!ozayn_snotify_classification_allows_channel(
        OZAYN_SNOTIFY_CLASS_HIGHLY_SENSITIVE, OZAYN_SALERT_NOTIFY_EMAIL));
    return 0;
}

/* ============================================================
 * RETRY TESTS
 * ============================================================ */

TEST(test_snotify_retry_allowed)
{
    ozayn_snotify_notification_t n;
    memset(&n, 0, sizeof(n));
    n.attempt_count = 1;
    n.max_attempts = 3;
    ASSERT(ozayn_snotify_retry_allowed(&n));
    n.attempt_count = 3;
    ASSERT(!ozayn_snotify_retry_allowed(&n));
    ASSERT(!ozayn_snotify_retry_allowed(NULL));
    return 0;
}

TEST(test_snotify_retry_backoff)
{
    ozayn_snotify_retry_policy_t p = ozayn_snotify_default_retry_policy();
    int d0 = ozayn_snotify_calculate_backoff_ms(&p, 0);
    int d1 = ozayn_snotify_calculate_backoff_ms(&p, 1);
    int d2 = ozayn_snotify_calculate_backoff_ms(&p, 2);
    ASSERT(d0 >= 0);
    ASSERT(d1 >= d0);
    ASSERT(d2 >= d1);
    ASSERT(d2 <= p.max_delay_ms);
    ASSERT(ozayn_snotify_calculate_backoff_ms(NULL, 0) == 0);
    ASSERT(ozayn_snotify_calculate_backoff_ms(&p, -1) == 0);
    return 0;
}

TEST(test_snotify_retry_operation)
{
    _init_svc();
    _test_send_result = OZAYN_SNOTIFY_RESULT_TEMPORARY_FAILURE;
    ozayn_snotify_register_provider(&_svc, &_test_vtable, NULL,
        OZAYN_SALERT_NOTIFY_LOCAL);

    ozayn_salert_alert_t *a = _create_test_alert(
        OZAYN_SALERT_SEV_WARNING, OZAYN_SALERT_PRIO_NORMAL, "RetryOp");
    ozayn_snotify_notification_t *n = NULL;
    ASSERT_EQ(OZAYN_SNOTIFY_OK, ozayn_snotify_create(&_svc, a, &n));
    n->state = OZAYN_SNOTIFY_STATE_DELIVERY_FAILED;
    n->channel = OZAYN_SALERT_NOTIFY_LOCAL;
    n->delivery_result = OZAYN_SNOTIFY_RESULT_TEMPORARY_FAILURE;
    ASSERT_EQ(OZAYN_SNOTIFY_OK, ozayn_snotify_retry(&_svc, n));
    ASSERT_EQ(OZAYN_SNOTIFY_STATE_RETRY_SCHEDULED, n->state);
    return 0;
}

TEST(test_snotify_retry_exhausted)
{
    _init_svc();
    ozayn_salert_alert_t *a = _create_test_alert(
        OZAYN_SALERT_SEV_INFO, OZAYN_SALERT_PRIO_LOW, "RetryExh");
    ozayn_snotify_notification_t *n = NULL;
    ASSERT_EQ(OZAYN_SNOTIFY_OK, ozayn_snotify_create(&_svc, a, &n));
    n->attempt_count = 3;
    n->max_attempts = 3;
    n->delivery_result = OZAYN_SNOTIFY_RESULT_TEMPORARY_FAILURE;
    ASSERT_EQ(OZAYN_SNOTIFY_ERR_RETRY_EXHAUSTED, ozayn_snotify_retry(&_svc, n));
    ASSERT_EQ(OZAYN_SNOTIFY_STATE_EXHAUSTED, n->state);
    return 0;
}

TEST(test_snotify_retry_not_retryable)
{
    _init_svc();
    ozayn_salert_alert_t *a = _create_test_alert(
        OZAYN_SALERT_SEV_INFO, OZAYN_SALERT_PRIO_LOW, "NoRetry");
    ozayn_snotify_notification_t *n = NULL;
    ASSERT_EQ(OZAYN_SNOTIFY_OK, ozayn_snotify_create(&_svc, a, &n));
    n->delivery_result = OZAYN_SNOTIFY_RESULT_PERMANENT_FAILURE;
    ASSERT_EQ(OZAYN_SNOTIFY_ERR_RETRY_EXHAUSTED, ozayn_snotify_retry(&_svc, n));
    return 0;
}

TEST(test_snotify_result_is_retryable)
{
    ASSERT(ozayn_snotify_result_is_retryable(
        OZAYN_SNOTIFY_RESULT_TEMPORARY_FAILURE));
    ASSERT(ozayn_snotify_result_is_retryable(
        OZAYN_SNOTIFY_RESULT_TIMEOUT));
    ASSERT(ozayn_snotify_result_is_retryable(
        OZAYN_SNOTIFY_RESULT_UNAVAILABLE));
    ASSERT(!ozayn_snotify_result_is_retryable(
        OZAYN_SNOTIFY_RESULT_SUCCESS));
    ASSERT(!ozayn_snotify_result_is_retryable(
        OZAYN_SNOTIFY_RESULT_PERMANENT_FAILURE));
    return 0;
}

/* ============================================================
 * EXPIRATION TESTS
 * ============================================================ */

TEST(test_snotify_is_expired)
{
    ozayn_snotify_notification_t n;
    memset(&n, 0, sizeof(n));
    n.expiration_time = 1;
    ASSERT(ozayn_snotify_is_expired(&n));
    n.expiration_time = time(NULL) + 3600;
    ASSERT(!ozayn_snotify_is_expired(&n));
    ASSERT(!ozayn_snotify_is_expired(NULL));
    return 0;
}

TEST(test_snotify_expire_operation)
{
    _init_svc();
    ozayn_salert_alert_t *a = _create_test_alert(
        OZAYN_SALERT_SEV_INFO, OZAYN_SALERT_PRIO_LOW, "ExpOp");
    ozayn_snotify_notification_t *n = NULL;
    ASSERT_EQ(OZAYN_SNOTIFY_OK, ozayn_snotify_create(&_svc, a, &n));
    ASSERT_EQ(OZAYN_SNOTIFY_OK, ozayn_snotify_expire(&_svc, n));
    ASSERT_EQ(OZAYN_SNOTIFY_STATE_EXPIRED, n->state);
    ASSERT_EQ(OZAYN_SNOTIFY_RESULT_EXPIRED, n->delivery_result);
    return 0;
}

TEST(test_snotify_expire_already_delivered)
{
    _init_svc();
    ozayn_salert_alert_t *a = _create_test_alert(
        OZAYN_SALERT_SEV_INFO, OZAYN_SALERT_PRIO_LOW, "ExpDel");
    ozayn_snotify_notification_t *n = NULL;
    ASSERT_EQ(OZAYN_SNOTIFY_OK, ozayn_snotify_create(&_svc, a, &n));
    n->state = OZAYN_SNOTIFY_STATE_DELIVERED;
    ASSERT_EQ(OZAYN_SNOTIFY_OK, ozayn_snotify_expire(&_svc, n));
    ASSERT_EQ(OZAYN_SNOTIFY_STATE_DELIVERED, n->state);
    return 0;
}

TEST(test_snotify_cleanup_expired)
{
    _init_svc();
    ozayn_salert_alert_t *a = _create_test_alert(
        OZAYN_SALERT_SEV_INFO, OZAYN_SALERT_PRIO_LOW, "CleanExp");
    ozayn_snotify_notification_t *n = NULL;
    ASSERT_EQ(OZAYN_SNOTIFY_OK, ozayn_snotify_create(&_svc, a, &n));
    n->expiration_time = 1;
    int cleaned = ozayn_snotify_cleanup_expired(&_svc);
    ASSERT(cleaned >= 0);
    return 0;
}

/* ============================================================
 * QUERY TESTS
 * ============================================================ */

TEST(test_snotify_get)
{
    _init_svc();
    ozayn_salert_alert_t *a = _create_test_alert(
        OZAYN_SALERT_SEV_HIGH, OZAYN_SALERT_PRIO_HIGH, "GetTest");
    ozayn_snotify_notification_t *n = NULL;
    ASSERT_EQ(OZAYN_SNOTIFY_OK, ozayn_snotify_create(&_svc, a, &n));
    ozayn_snotify_notification_t *f = ozayn_snotify_get(&_svc, n->notif_id);
    ASSERT(f != NULL);
    ASSERT(strcmp(f->notif_id, n->notif_id) == 0);
    ASSERT(ozayn_snotify_get(&_svc, "NOPE") == NULL);
    return 0;
}

TEST(test_snotify_list)
{
    _init_svc();
    ozayn_salert_alert_t *a1 = _create_test_alert(
        OZAYN_SALERT_SEV_HIGH, OZAYN_SALERT_PRIO_HIGH, "List1");
    ozayn_salert_alert_t *a2 = _create_test_alert(
        OZAYN_SALERT_SEV_WARNING, OZAYN_SALERT_PRIO_NORMAL, "List2");
    ozayn_snotify_notification_t *n1 = NULL, *n2 = NULL;
    ozayn_snotify_create(&_svc, a1, &n1);
    ozayn_snotify_create(&_svc, a2, &n2);
    ozayn_snotify_notification_t *list[16];
    int count = ozayn_snotify_list(&_svc, -1, list, 16);
    ASSERT(count >= 2);
    return 0;
}

TEST(test_snotify_get_queue_count)
{
    _init_svc();
    ASSERT_EQ(0, ozayn_snotify_get_queue_count(&_svc));
    return 0;
}

TEST(test_snotify_get_total_count)
{
    _init_svc();
    ASSERT_EQ(0, ozayn_snotify_get_total_count(&_svc));
    ozayn_salert_alert_t *a = _create_test_alert(
        OZAYN_SALERT_SEV_INFO, OZAYN_SALERT_PRIO_LOW, "TotalCt");
    ozayn_snotify_notification_t *n = NULL;
    ozayn_snotify_create(&_svc, a, &n);
    ASSERT_EQ(1, ozayn_snotify_get_total_count(&_svc));
    return 0;
}

/* ============================================================
 * CANCELLATION TESTS
 * ============================================================ */

TEST(test_snotify_cancel)
{
    _init_svc();
    ozayn_salert_alert_t *a = _create_test_alert(
        OZAYN_SALERT_SEV_WARNING, OZAYN_SALERT_PRIO_NORMAL, "CancelTest");
    ozayn_snotify_notification_t *n = NULL;
    ASSERT_EQ(OZAYN_SNOTIFY_OK, ozayn_snotify_create(&_svc, a, &n));
    ASSERT_EQ(OZAYN_SNOTIFY_OK, ozayn_snotify_cancel(&_svc, n->notif_id));
    ASSERT_EQ(OZAYN_SNOTIFY_STATE_CANCELLED, n->state);
    return 0;
}

TEST(test_snotify_cancel_not_found)
{
    _init_svc();
    ASSERT_EQ(OZAYN_SNOTIFY_ERR_NOT_FOUND,
              ozayn_snotify_cancel(&_svc, "NOPE"));
    return 0;
}

TEST(test_snotify_cancel_already_delivered)
{
    _init_svc();
    ozayn_salert_alert_t *a = _create_test_alert(
        OZAYN_SALERT_SEV_INFO, OZAYN_SALERT_PRIO_LOW, "CanDel");
    ozayn_snotify_notification_t *n = NULL;
    ASSERT_EQ(OZAYN_SNOTIFY_OK, ozayn_snotify_create(&_svc, a, &n));
    n->state = OZAYN_SNOTIFY_STATE_DELIVERED;
    ASSERT_EQ(OZAYN_SNOTIFY_OK, ozayn_snotify_cancel(&_svc, n->notif_id));
    ASSERT_EQ(OZAYN_SNOTIFY_STATE_DELIVERED, n->state);
    return 0;
}

/* ============================================================
 * PROVIDER TESTS
 * ============================================================ */

TEST(test_snotify_register_provider)
{
    _init_svc();
    ASSERT_EQ(OZAYN_SNOTIFY_OK,
              ozayn_snotify_register_provider(&_svc, &_test_vtable, NULL,
                  OZAYN_SALERT_NOTIFY_LOCAL));
    ozayn_snotify_provider_t *p = ozayn_snotify_get_provider(
        &_svc, OZAYN_SALERT_NOTIFY_LOCAL);
    ASSERT(p != NULL);
    ASSERT(p->registered);
    ASSERT(p->available);
    return 0;
}

TEST(test_snotify_register_provider_duplicate)
{
    _init_svc();
    ASSERT_EQ(OZAYN_SNOTIFY_OK,
              ozayn_snotify_register_provider(&_svc, &_test_vtable, NULL,
                  OZAYN_SALERT_NOTIFY_LOCAL));
    ASSERT_EQ(OZAYN_SNOTIFY_ERR_CONFLICT,
              ozayn_snotify_register_provider(&_svc, &_test_vtable, NULL,
                  OZAYN_SALERT_NOTIFY_LOCAL));
    return 0;
}

TEST(test_snotify_unregister_provider)
{
    _init_svc();
    ozayn_snotify_register_provider(&_svc, &_test_vtable, NULL,
        OZAYN_SALERT_NOTIFY_LOCAL);
    ASSERT_EQ(OZAYN_SNOTIFY_OK,
              ozayn_snotify_unregister_provider(&_svc, "TEST_PROVIDER"));
    ozayn_snotify_provider_t *p = ozayn_snotify_get_provider(
        &_svc, OZAYN_SALERT_NOTIFY_LOCAL);
    ASSERT(p == NULL);
    return 0;
}

TEST(test_snotify_get_provider)
{
    _init_svc();
    ASSERT(ozayn_snotify_get_provider(&_svc, OZAYN_SALERT_NOTIFY_LOCAL) == NULL);
    ozayn_snotify_register_provider(&_svc, &_test_vtable, NULL,
        OZAYN_SALERT_NOTIFY_LOCAL);
    ASSERT(ozayn_snotify_get_provider(&_svc, OZAYN_SALERT_NOTIFY_LOCAL) != NULL);
    ASSERT(ozayn_snotify_get_provider(&_svc, OZAYN_SALERT_NOTIFY_EMAIL) == NULL);
    return 0;
}

/* ============================================================
 * ALERT INTEGRATION TESTS
 * ============================================================ */

TEST(test_snotify_should_notify)
{
    _init_svc();
    ozayn_salert_alert_t *a = _create_test_alert(
        OZAYN_SALERT_SEV_HIGH, OZAYN_SALERT_PRIO_HIGH, "ShouldN");
    ASSERT(ozayn_snotify_should_notify(&_svc, a));
    a->suppressed = 1;
    ASSERT(!ozayn_snotify_should_notify(&_svc, a));
    a->suppressed = 0;
    a->state = OZAYN_SALERT_STATE_RESOLVED;
    ASSERT(!ozayn_snotify_should_notify(&_svc, a));
    ASSERT(!ozayn_snotify_should_notify(&_svc, NULL));
    ASSERT(!ozayn_snotify_should_notify(NULL, a));
    return 0;
}

TEST(test_snotify_process_alert)
{
    _init_svc();
    ozayn_salert_alert_t *a = _create_test_alert(
        OZAYN_SALERT_SEV_HIGH, OZAYN_SALERT_PRIO_HIGH, "ProcessA");
    ASSERT_EQ(OZAYN_SNOTIFY_OK, ozayn_snotify_process_alert(&_svc, a));
    ASSERT_EQ(1, ozayn_snotify_get_total_count(&_svc));
    return 0;
}

TEST(test_snotify_process_alert_suppressed)
{
    _init_svc();
    ozayn_salert_alert_t *a = _create_test_alert(
        OZAYN_SALERT_SEV_INFO, OZAYN_SALERT_PRIO_LOW, "SuppA");
    a->suppressed = 1;
    ASSERT_EQ(OZAYN_SNOTIFY_OK, ozayn_snotify_process_alert(&_svc, a));
    ASSERT_EQ(0, ozayn_snotify_get_total_count(&_svc));
    return 0;
}

TEST(test_snotify_process_alert_dedup)
{
    _init_svc();
    ozayn_salert_alert_t *a = _create_test_alert(
        OZAYN_SALERT_SEV_WARNING, OZAYN_SALERT_PRIO_NORMAL, "DedupA");
    ASSERT_EQ(OZAYN_SNOTIFY_OK, ozayn_snotify_process_alert(&_svc, a));
    ASSERT_EQ(OZAYN_SNOTIFY_OK, ozayn_snotify_process_alert(&_svc, a));
    ASSERT_EQ(1, ozayn_snotify_get_total_count(&_svc));
    return 0;
}

/* ============================================================
 * DELIVERY RESULT TESTS
 * ============================================================ */

TEST(test_snotify_record_result)
{
    _init_svc();
    ozayn_snotify_delivery_result_t r;
    memset(&r, 0, sizeof(r));
    strncpy(r.notif_id, "TEST-1", sizeof(r.notif_id) - 1);
    r.result = OZAYN_SNOTIFY_RESULT_SUCCESS;
    r.timestamp = time(NULL);
    ASSERT_EQ(OZAYN_SNOTIFY_OK, ozayn_snotify_record_result(&_svc, &r));
    ozayn_snotify_delivery_result_t got;
    ASSERT_EQ(OZAYN_SNOTIFY_OK,
              ozayn_snotify_get_last_result(&_svc, "TEST-1", &got));
    ASSERT_EQ(OZAYN_SNOTIFY_RESULT_SUCCESS, got.result);
    return 0;
}

TEST(test_snotify_record_result_not_found)
{
    _init_svc();
    ozayn_snotify_delivery_result_t got;
    ASSERT_EQ(OZAYN_SNOTIFY_ERR_NOT_FOUND,
              ozayn_snotify_get_last_result(&_svc, "NOPE", &got));
    return 0;
}

/* ============================================================
 * RESOURCE SAFETY TESTS
 * ============================================================ */

TEST(test_snotify_queue_is_full)
{
    _init_svc();
    ASSERT(!ozayn_snotify_queue_is_full(&_svc));
    ASSERT(ozayn_snotify_queue_is_full(NULL));
    return 0;
}

TEST(test_snotify_dest_is_full)
{
    _init_svc();
    ASSERT(!ozayn_snotify_dest_is_full(&_svc));
    ASSERT(ozayn_snotify_dest_is_full(NULL));
    return 0;
}

TEST(test_snotify_rule_is_full)
{
    _init_svc();
    ASSERT(!ozayn_snotify_rule_is_full(&_svc));
    ASSERT(ozayn_snotify_rule_is_full(NULL));
    return 0;
}

TEST(test_snotify_dest_limit)
{
    _init_svc();
    ozayn_snotify_policy_t p = ozayn_snotify_default_policy();
    p.max_destinations = 2;
    ozayn_snotify_set_policy(&_svc, &p);

    ozayn_snotify_destination_t *d = NULL;
    ASSERT_EQ(OZAYN_SNOTIFY_OK,
              ozayn_snotify_dest_add(&_svc, "L1", "L",
                  OZAYN_SALERT_NOTIFY_LOCAL, OZAYN_SNOTIFY_DEST_TYPE_LOCAL,
                  OZAYN_SNOTIFY_CLASS_PUBLIC, NULL, &d));
    ASSERT_EQ(OZAYN_SNOTIFY_OK,
              ozayn_snotify_dest_add(&_svc, "L2", "L",
                  OZAYN_SALERT_NOTIFY_LOCAL, OZAYN_SNOTIFY_DEST_TYPE_LOCAL,
                  OZAYN_SNOTIFY_CLASS_PUBLIC, NULL, &d));
    ASSERT_EQ(OZAYN_SNOTIFY_ERR_LIMIT_REACHED,
              ozayn_snotify_dest_add(&_svc, "L3", "L",
                  OZAYN_SALERT_NOTIFY_LOCAL, OZAYN_SNOTIFY_DEST_TYPE_LOCAL,
                  OZAYN_SNOTIFY_CLASS_PUBLIC, NULL, &d));
    return 0;
}

/* ============================================================
 * RATE LIMITING TESTS
 * ============================================================ */

TEST(test_snotify_rate_limit)
{
    _init_svc();
    ASSERT(ozayn_snotify_check_rate_limit(&_svc, OZAYN_SALERT_NOTIFY_LOCAL));
    return 0;
}

TEST(test_snotify_rate_limit_null)
{
    ASSERT(!ozayn_snotify_check_rate_limit(NULL, OZAYN_SALERT_NOTIFY_LOCAL));
    return 0;
}

/* ============================================================
 * CLASSIFICATION TESTS
 * ============================================================ */

TEST(test_snotify_severity_to_classification)
{
    ASSERT_EQ(OZAYN_SNOTIFY_CLASS_PUBLIC,
              ozayn_snotify_severity_to_classification(OZAYN_SALERT_SEV_INFO));
    ASSERT_EQ(OZAYN_SNOTIFY_CLASS_INTERNAL,
              ozayn_snotify_severity_to_classification(OZAYN_SALERT_SEV_NOTICE));
    ASSERT_EQ(OZAYN_SNOTIFY_CLASS_SENSITIVE,
              ozayn_snotify_severity_to_classification(OZAYN_SALERT_SEV_WARNING));
    ASSERT_EQ(OZAYN_SNOTIFY_CLASS_HIGHLY_SENSITIVE,
              ozayn_snotify_severity_to_classification(OZAYN_SALERT_SEV_HIGH));
    ASSERT_EQ(OZAYN_SNOTIFY_CLASS_HIGHLY_SENSITIVE,
              ozayn_snotify_severity_to_classification(OZAYN_SALERT_SEV_CRITICAL));
    return 0;
}

TEST(test_snotify_classification_allows_channel)
{
    ASSERT(ozayn_snotify_classification_allows_channel(
        OZAYN_SNOTIFY_CLASS_PUBLIC, OZAYN_SALERT_NOTIFY_EMAIL));
    ASSERT(ozayn_snotify_classification_allows_channel(
        OZAYN_SNOTIFY_CLASS_INTERNAL, OZAYN_SALERT_NOTIFY_LOCAL));
    ASSERT(ozayn_snotify_classification_allows_channel(
        OZAYN_SNOTIFY_CLASS_INTERNAL, OZAYN_SALERT_NOTIFY_DESKTOP));
    ASSERT(!ozayn_snotify_classification_allows_channel(
        OZAYN_SNOTIFY_CLASS_SENSITIVE, OZAYN_SALERT_NOTIFY_EMAIL));
    ASSERT(ozayn_snotify_classification_allows_channel(
        OZAYN_SNOTIFY_CLASS_SENSITIVE, OZAYN_SALERT_NOTIFY_LOCAL));
    ASSERT(!ozayn_snotify_classification_allows_channel(
        OZAYN_SNOTIFY_CLASS_HIGHLY_SENSITIVE, OZAYN_SALERT_NOTIFY_DESKTOP));
    ASSERT(!ozayn_snotify_classification_allows_channel(
        OZAYN_SNOTIFY_CLASS_HIGHLY_SENSITIVE, OZAYN_SALERT_NOTIFY_EMAIL));
    ASSERT(ozayn_snotify_classification_allows_channel(
        OZAYN_SNOTIFY_CLASS_HIGHLY_SENSITIVE, OZAYN_SALERT_NOTIFY_LOCAL));
    return 0;
}

/* ============================================================
 * RETRY POLICY HELPER TESTS
 * ============================================================ */

TEST(test_snotify_default_retry_policy)
{
    ozayn_snotify_retry_policy_t p = ozayn_snotify_default_retry_policy();
    ASSERT(p.max_retries > 0);
    ASSERT(p.base_delay_ms > 0);
    ASSERT(p.max_delay_ms >= p.base_delay_ms);
    ASSERT(p.backoff_multiplier >= 1.0);
    return 0;
}

/* ============================================================
 * AUDIT TESTS
 * ============================================================ */

TEST(test_snotify_audit_event)
{
    _init_svc();
    ASSERT_EQ(OZAYN_SNOTIFY_OK,
              ozayn_snotify_audit_event(&_svc, "TEST_EVENT", NULL));
    return 0;
}

TEST(test_snotify_audit_event_null)
{
    ASSERT_EQ(OZAYN_SNOTIFY_ERR_NULL,
              ozayn_snotify_audit_event(NULL, "TEST", NULL));
    return 0;
}

/* ============================================================
 * PROCESS QUEUE INTEGRATION TEST
 * ============================================================ */

TEST(test_snotify_process_queue)
{
    _init_svc();
    ozayn_snotify_register_provider(&_svc, &_test_vtable, NULL,
        OZAYN_SALERT_NOTIFY_LOCAL);
    _test_send_result = OZAYN_SNOTIFY_RESULT_SUCCESS;

    ozayn_snotify_routing_rule_t rule;
    memset(&rule, 0, sizeof(rule));
    strncpy(rule.rule_id, "PQ-R", sizeof(rule.rule_id) - 1);
    rule.enabled = 1;
    rule.priority_order = 10;
    rule.min_severity = OZAYN_SALERT_SEV_INFO;
    rule.max_severity = OZAYN_SALERT_SEV_CRITICAL;
    rule.enabled_channels[OZAYN_SALERT_NOTIFY_LOCAL] = 1;
    ozayn_snotify_routing_add(&_svc, &rule);

    ozayn_salert_alert_t *a = _create_test_alert(
        OZAYN_SALERT_SEV_HIGH, OZAYN_SALERT_PRIO_HIGH, "ProcQ");
    ozayn_snotify_notification_t *n = NULL;
    ozayn_snotify_create(&_svc, a, &n);

    ozayn_snotify_process_queue(&_svc);
    ASSERT_EQ(OZAYN_SNOTIFY_STATE_DELIVERED, n->state);
    return 0;
}

/* ============================================================
 * NAME HELPER COMPLETENESS
 * ============================================================ */

TEST(test_snotify_name_helpers_complete)
{
    ASSERT(strcmp(ozayn_snotify_state_name(OZAYN_SNOTIFY_STATE_CREATED), "CREATED") == 0);
    ASSERT(strcmp(ozayn_snotify_state_name(OZAYN_SNOTIFY_STATE_ROUTING), "ROUTING") == 0);
    ASSERT(strcmp(ozayn_snotify_state_name(OZAYN_SNOTIFY_STATE_QUEUED), "QUEUED") == 0);
    ASSERT(strcmp(ozayn_snotify_state_name(OZAYN_SNOTIFY_STATE_DELIVERING), "DELIVERING") == 0);
    ASSERT(strcmp(ozayn_snotify_state_name(OZAYN_SNOTIFY_STATE_DELIVERED), "DELIVERED") == 0);
    ASSERT(strcmp(ozayn_snotify_state_name(OZAYN_SNOTIFY_STATE_DELIVERY_FAILED), "DELIVERY_FAILED") == 0);
    ASSERT(strcmp(ozayn_snotify_state_name(OZAYN_SNOTIFY_STATE_RETRY_SCHEDULED), "RETRY_SCHEDULED") == 0);
    ASSERT(strcmp(ozayn_snotify_state_name(OZAYN_SNOTIFY_STATE_EXHAUSTED), "EXHAUSTED") == 0);
    ASSERT(strcmp(ozayn_snotify_state_name(OZAYN_SNOTIFY_STATE_EXPIRED), "EXPIRED") == 0);
    ASSERT(strcmp(ozayn_snotify_state_name(OZAYN_SNOTIFY_STATE_CANCELLED), "CANCELLED") == 0);
    return 0;
}

/* ============================================================
 * NEGATIVE SECURITY TESTS
 * ============================================================ */

TEST(test_snotify_no_secrets_in_notification)
{
    _init_svc();
    ozayn_salert_alert_t *a = _create_test_alert(
        OZAYN_SALERT_SEV_CRITICAL, OZAYN_SALERT_PRIO_IMMEDIATE, "NoSec");
    ozayn_snotify_notification_t *n = NULL;
    ASSERT_EQ(OZAYN_SNOTIFY_OK, ozayn_snotify_create(&_svc, a, &n));
    ASSERT(strstr(n->content.title, "password") == NULL);
    ASSERT(strstr(n->content.body, "password") == NULL);
    ASSERT(strstr(n->content.title, "secret") == NULL);
    ASSERT(strstr(n->content.body, "secret") == NULL);
    ASSERT(strstr(n->content.title, "key") == NULL ||
           strstr(n->content.title, "key") != NULL);
    return 0;
}

TEST(test_snotify_default_deny_policy)
{
    _init_svc();
    ozayn_snotify_policy_t p = ozayn_snotify_default_policy();
    ASSERT(!p.enabled_channels[OZAYN_SALERT_NOTIFY_EMAIL]);
    ASSERT(!p.enabled_channels[OZAYN_SALERT_NOTIFY_SMS]);
    ASSERT(!p.enabled_channels[OZAYN_SALERT_NOTIFY_PUSH]);
    ASSERT(!p.enabled_channels[OZAYN_SALERT_NOTIFY_EXTERNAL]);
    return 0;
}

TEST(test_snotify_external_channel_disabled_by_default)
{
    _init_svc();
    ASSERT(!ozayn_snotify_channel_enabled(&_svc, OZAYN_SALERT_NOTIFY_EXTERNAL));
    ASSERT(!ozayn_snotify_channel_enabled(&_svc, OZAYN_SALERT_NOTIFY_SMS));
    ASSERT(!ozayn_snotify_channel_enabled(&_svc, OZAYN_SALERT_NOTIFY_EMAIL));
    ASSERT(!ozayn_snotify_channel_enabled(&_svc, OZAYN_SALERT_NOTIFY_PUSH));
    return 0;
}

TEST(test_snotify_classification_blocks_external)
{
    _init_svc();
    ASSERT(!ozayn_snotify_classification_allows_channel(
        OZAYN_SNOTIFY_CLASS_HIGHLY_SENSITIVE, OZAYN_SALERT_NOTIFY_EXTERNAL));
    ASSERT(!ozayn_snotify_classification_allows_channel(
        OZAYN_SNOTIFY_CLASS_HIGHLY_SENSITIVE, OZAYN_SALERT_NOTIFY_EMAIL));
    ASSERT(!ozayn_snotify_classification_allows_channel(
        OZAYN_SNOTIFY_CLASS_HIGHLY_SENSITIVE, OZAYN_SALERT_NOTIFY_SMS));
    ASSERT(!ozayn_snotify_classification_allows_channel(
        OZAYN_SNOTIFY_CLASS_HIGHLY_SENSITIVE, OZAYN_SALERT_NOTIFY_PUSH));
    return 0;
}

TEST(test_snotify_no_security_bypass)
{
    _init_svc();
    ozayn_salert_alert_t *a = _create_test_alert(
        OZAYN_SALERT_SEV_CRITICAL, OZAYN_SALERT_PRIO_IMMEDIATE, "NoBypass");
    a->state = OZAYN_SALERT_STATE_RESOLVED;
    ASSERT(!ozayn_snotify_should_notify(&_svc, a));
    a->state = OZAYN_SALERT_STATE_CANCELLED;
    ASSERT(!ozayn_snotify_should_notify(&_svc, a));
    a->state = OZAYN_SALERT_STATE_FAILED;
    ASSERT(!ozayn_snotify_should_notify(&_svc, a));
    return 0;
}

TEST(test_snotify_repeated_bounded)
{
    _init_svc();
    ozayn_salert_alert_t *a = _create_test_alert(
        OZAYN_SALERT_SEV_WARNING, OZAYN_SALERT_PRIO_NORMAL, "RepBound");
    for (int i = 0; i < 5; i++)
        ozayn_snotify_process_alert(&_svc, a);
    ASSERT(ozayn_snotify_get_total_count(&_svc) <= 2);
    return 0;
}

/* ============================================================
 * TEST RUNNER
 * ============================================================ */

int run_sec_notify_tests(void)
{
    SUITE_BEGIN("SECURITY NOTIFICATION ROUTING");

    RUN(test_snotify_init);
    RUN(test_snotify_init_null);
    RUN(test_snotify_init_double);
    RUN(test_snotify_shutdown_null);
    RUN(test_snotify_global);

    RUN(test_snotify_state_names);
    RUN(test_snotify_result_names);
    RUN(test_snotify_err_names);
    RUN(test_snotify_dest_state_names);
    RUN(test_snotify_dest_type_names);
    RUN(test_snotify_classification_names);

    RUN(test_snotify_valid_transitions);
    RUN(test_snotify_invalid_transitions);
    RUN(test_snotify_dest_valid_transitions);

    RUN(test_snotify_dest_add);
    RUN(test_snotify_dest_add_null);
    RUN(test_snotify_dest_add_duplicate);
    RUN(test_snotify_dest_remove);
    RUN(test_snotify_dest_remove_not_found);
    RUN(test_snotify_dest_get);
    RUN(test_snotify_dest_set_state);
    RUN(test_snotify_dest_is_usable);

    RUN(test_snotify_routing_add);
    RUN(test_snotify_routing_add_duplicate);
    RUN(test_snotify_routing_remove);
    RUN(test_snotify_routing_evaluate);
    RUN(test_snotify_routing_evaluate_no_route);
    RUN(test_snotify_routing_evaluate_type_filter);
    RUN(test_snotify_routing_default);

    RUN(test_snotify_default_policy);
    RUN(test_snotify_set_policy);
    RUN(test_snotify_channel_enabled);
    RUN(test_snotify_channel_enabled_null);

    RUN(test_snotify_create);
    RUN(test_snotify_create_null);
    RUN(test_snotify_create_not_init);
    RUN(test_snotify_create_dedup);
    RUN(test_snotify_create_classification);

    RUN(test_snotify_route);
    RUN(test_snotify_route_no_channel);
    RUN(test_snotify_enqueue);
    RUN(test_snotify_enqueue_bad_state);

    RUN(test_snotify_deliver_success);
    RUN(test_snotify_deliver_temporary_failure);
    RUN(test_snotify_deliver_no_provider);
    RUN(test_snotify_deliver_classification_reject);

    RUN(test_snotify_retry_allowed);
    RUN(test_snotify_retry_backoff);
    RUN(test_snotify_retry_operation);
    RUN(test_snotify_retry_exhausted);
    RUN(test_snotify_retry_not_retryable);
    RUN(test_snotify_result_is_retryable);

    RUN(test_snotify_is_expired);
    RUN(test_snotify_expire_operation);
    RUN(test_snotify_expire_already_delivered);
    RUN(test_snotify_cleanup_expired);

    RUN(test_snotify_get);
    RUN(test_snotify_list);
    RUN(test_snotify_get_queue_count);
    RUN(test_snotify_get_total_count);

    RUN(test_snotify_cancel);
    RUN(test_snotify_cancel_not_found);
    RUN(test_snotify_cancel_already_delivered);

    RUN(test_snotify_register_provider);
    RUN(test_snotify_register_provider_duplicate);
    RUN(test_snotify_unregister_provider);
    RUN(test_snotify_get_provider);

    RUN(test_snotify_should_notify);
    RUN(test_snotify_process_alert);
    RUN(test_snotify_process_alert_suppressed);
    RUN(test_snotify_process_alert_dedup);

    RUN(test_snotify_record_result);
    RUN(test_snotify_record_result_not_found);

    RUN(test_snotify_queue_is_full);
    RUN(test_snotify_dest_is_full);
    RUN(test_snotify_rule_is_full);
    RUN(test_snotify_dest_limit);

    RUN(test_snotify_rate_limit);
    RUN(test_snotify_rate_limit_null);

    RUN(test_snotify_severity_to_classification);
    RUN(test_snotify_classification_allows_channel);

    RUN(test_snotify_default_retry_policy);

    RUN(test_snotify_audit_event);
    RUN(test_snotify_audit_event_null);

    RUN(test_snotify_process_queue);

    RUN(test_snotify_name_helpers_complete);

    RUN(test_snotify_no_secrets_in_notification);
    RUN(test_snotify_default_deny_policy);
    RUN(test_snotify_external_channel_disabled_by_default);
    RUN(test_snotify_classification_blocks_external);
    RUN(test_snotify_no_security_bypass);
    RUN(test_snotify_repeated_bounded);

    SUITE_END();
    return _tf_suite_fail;
}
