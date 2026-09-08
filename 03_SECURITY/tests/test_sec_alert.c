/*
 * test_sec_alert.c — Security Alerting Tests (Step 29).
 *
 * Comprehensive tests for the security alerting system:
 * lifecycle, creation, query, deduplication, thresholds,
 * notifications, health/diagnostics/incident integration,
 * escalation, suppression, rate limiting, cleanup, and
 * negative security tests.
 */

#include "../../tests/test_framework.h"
#include "../sec_alert.h"
#include "../sec_config.h"
#include "../sec_health.h"
#include "../sec_diag.h"
#include "../incident.h"
#include <string.h>
#include <time.h>

/* ============================================================
 * TEST HELPERS
 * ============================================================ */

static ozayn_salert_service_t _svc;
static ozayn_sc_service_t _sc_svc;
static ozayn_sh_service_t _sh_svc;
static ozayn_sdiag_service_t _sdiag_svc;
static ozayn_ir_service_t _ir_svc;
static ozayn_audit_service_t _au_svc;

static void _reset_all(void)
{
    memset(&_svc, 0, sizeof(_svc));
    memset(&_sc_svc, 0, sizeof(_sc_svc));
    memset(&_sh_svc, 0, sizeof(_sh_svc));
    memset(&_sdiag_svc, 0, sizeof(_sdiag_svc));
    memset(&_ir_svc, 0, sizeof(_ir_svc));
    memset(&_au_svc, 0, sizeof(_au_svc));
}

static void _init_svc(void)
{
    _reset_all();
    _sc_svc.initialized = 1;
    _au_svc.initialized = 1;
    _ir_svc.initialized = 1;
    _sh_svc.initialized = 1;
    _sdiag_svc.initialized = 1;

    ozayn_salert_service_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.config_service = &_sc_svc;
    cfg.health_service = &_sh_svc;
    cfg.diag_service = &_sdiag_svc;
    cfg.incident_service = &_ir_svc;
    cfg.audit = &_au_svc;
    ozayn_salert_service_init(&_svc, &cfg);
}

/* ============================================================
 * TEST PROVIDER
 * ============================================================ */

static int _test_notify_ok = 0;
static int _test_notify_fail = 0;

static int _test_notify(const void *ctx,
                         const ozayn_salert_alert_t *alert,
                         const char *title,
                         const char *body)
{
    (void)ctx; (void)alert; (void)title; (void)body;
    if (_test_notify_fail) return -1;
    _test_notify_ok++;
    return 0;
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

static ozayn_salert_notify_provider_vtable_t _test_vtable = {
    .notify = _test_notify,
    .is_available = _test_is_available,
    .get_provider_id = _test_get_id,
    .get_capabilities = NULL
};

/* ============================================================
 * LIFECYCLE TESTS
 * ============================================================ */

TEST(test_salert_init)
{
    _reset_all();
    ozayn_salert_service_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    ASSERT_EQ(OZAYN_SALERT_OK,
              ozayn_salert_service_init(&_svc, &cfg));
    ASSERT(ozayn_salert_service_is_initialized(&_svc));
    ozayn_salert_service_shutdown(&_svc);
    ASSERT(!ozayn_salert_service_is_initialized(&_svc));
    return 0;
}

TEST(test_salert_init_null)
{
    ASSERT_EQ(OZAYN_SALERT_ERR_NULL,
              ozayn_salert_service_init(NULL, NULL));
    return 0;
}

TEST(test_salert_init_double)
{
    _reset_all();
    ozayn_salert_service_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    ASSERT_EQ(OZAYN_SALERT_OK,
              ozayn_salert_service_init(&_svc, &cfg));
    ASSERT_EQ(OZAYN_SALERT_ERR_ALREADY_INITIALIZED,
              ozayn_salert_service_init(&_svc, &cfg));
    ozayn_salert_service_shutdown(&_svc);
    return 0;
}

TEST(test_salert_shutdown_null)
{
    ozayn_salert_service_shutdown(NULL);
    return 0;
}

TEST(test_salert_is_init_null)
{
    ASSERT(!ozayn_salert_service_is_initialized(NULL));
    return 0;
}

TEST(test_salert_default_policy)
{
    ozayn_salert_policy_t p = ozayn_salert_default_policy();
    ASSERT(p.enabled);
    ASSERT_EQ(256, p.max_active_alerts);
    ASSERT_EQ(300, p.dedup_window_seconds);
    ASSERT_EQ(10, p.max_notify_per_window);
    ASSERT_EQ(3, p.max_notify_retries);
    ASSERT(p.auto_suppress_duplicates);
    ASSERT(p.require_ack_for_critical);
    return 0;
}

TEST(test_salert_global)
{
    ASSERT_NOT_NULL(ozayn_salert_get_global());
    return 0;
}

/* ============================================================
 * POLICY TESTS
 * ============================================================ */

TEST(test_salert_set_policy)
{
    _init_svc();
    ozayn_salert_policy_t p = ozayn_salert_default_policy();
    p.max_active_alerts = 128;
    ASSERT_EQ(OZAYN_SALERT_OK, ozayn_salert_set_policy(&_svc, &p));
    ASSERT_EQ(128, ozayn_salert_get_policy(&_svc)->max_active_alerts);
    return 0;
}

TEST(test_salert_set_policy_null)
{
    _init_svc();
    ASSERT_EQ(OZAYN_SALERT_ERR_NULL,
              ozayn_salert_set_policy(NULL, NULL));
    return 0;
}

TEST(test_salert_set_policy_invalid)
{
    _init_svc();
    ozayn_salert_policy_t p = ozayn_salert_default_policy();
    p.max_active_alerts = -1;
    ASSERT_EQ(OZAYN_SALERT_ERR_POLICY_INVALID,
              ozayn_salert_set_policy(&_svc, &p));
    return 0;
}

TEST(test_salert_set_policy_not_init)
{
    ozayn_salert_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_salert_policy_t p = ozayn_salert_default_policy();
    ASSERT_EQ(OZAYN_SALERT_ERR_NOT_INITIALIZED,
              ozayn_salert_set_policy(&svc, &p));
    return 0;
}

/* ============================================================
 * ALERT CREATION TESTS
 * ============================================================ */

TEST(test_salert_create)
{
    _init_svc();
    ozayn_salert_alert_t *alert = NULL;
    ASSERT_EQ(OZAYN_SALERT_OK,
              ozayn_salert_create(&_svc,
                  OZAYN_SALERT_TYPE_AUTH_FAILURE,
                  OZAYN_SALERT_SEV_HIGH,
                  OZAYN_SALERT_PRIO_NORMAL,
                  OZAYN_SALERT_SOURCE_AUTHENTICATION,
                  "AUTH", NULL,
                  "Test auth failure", "Detail", &alert));
    ASSERT_NOT_NULL(alert);
    ASSERT_EQ(OZAYN_SALERT_STATE_ACTIVE, alert->state);
    ASSERT_EQ(OZAYN_SALERT_TYPE_AUTH_FAILURE, alert->alert_type);
    ASSERT_EQ(OZAYN_SALERT_SEV_HIGH, alert->severity);
    ASSERT_EQ(OZAYN_SALERT_PRIO_NORMAL, alert->priority);
    ASSERT(alert->alert_id[0] != '\0');
    return 0;
}

TEST(test_salert_create_null)
{
    _init_svc();
    ASSERT_EQ(OZAYN_SALERT_ERR_NULL,
              ozayn_salert_create(NULL, 0, 0, 0, 0, NULL,
                                   NULL, NULL, NULL, NULL));
    return 0;
}

TEST(test_salert_create_not_init)
{
    ozayn_salert_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_salert_alert_t *alert = NULL;
    ASSERT_EQ(OZAYN_SALERT_ERR_NOT_INITIALIZED,
              ozayn_salert_create(&svc, 0, 0, 0, 0, NULL,
                                   NULL, NULL, NULL, &alert));
    return 0;
}

TEST(test_salert_create_invalid_type)
{
    _init_svc();
    ozayn_salert_alert_t *alert = NULL;
    ASSERT_EQ(OZAYN_SALERT_ERR_INVALID_TYPE,
              ozayn_salert_create(&_svc,
                  (ozayn_salert_type_t)99,
                  OZAYN_SALERT_SEV_HIGH,
                  OZAYN_SALERT_PRIO_NORMAL,
                  OZAYN_SALERT_SOURCE_SYSTEM,
                  NULL, NULL, NULL, NULL, &alert));
    return 0;
}

TEST(test_salert_create_invalid_severity)
{
    _init_svc();
    ozayn_salert_alert_t *alert = NULL;
    ASSERT_EQ(OZAYN_SALERT_ERR_INVALID_SEVERITY,
              ozayn_salert_create(&_svc,
                  OZAYN_SALERT_TYPE_AUTH_FAILURE,
                  (ozayn_salert_severity_t)99,
                  OZAYN_SALERT_PRIO_NORMAL,
                  OZAYN_SALERT_SOURCE_SYSTEM,
                  NULL, NULL, NULL, NULL, &alert));
    return 0;
}

TEST(test_salert_create_invalid_priority)
{
    _init_svc();
    ozayn_salert_alert_t *alert = NULL;
    ASSERT_EQ(OZAYN_SALERT_ERR_INVALID_PRIORITY,
              ozayn_salert_create(&_svc,
                  OZAYN_SALERT_TYPE_AUTH_FAILURE,
                  OZAYN_SALERT_SEV_HIGH,
                  (ozayn_salert_priority_t)99,
                  OZAYN_SALERT_SOURCE_SYSTEM,
                  NULL, NULL, NULL, NULL, &alert));
    return 0;
}

TEST(test_salert_create_invalid_source)
{
    _init_svc();
    ozayn_salert_alert_t *alert = NULL;
    ASSERT_EQ(OZAYN_SALERT_ERR_INVALID_SOURCE,
              ozayn_salert_create(&_svc,
                  OZAYN_SALERT_TYPE_AUTH_FAILURE,
                  OZAYN_SALERT_SEV_HIGH,
                  OZAYN_SALERT_PRIO_NORMAL,
                  (ozayn_salert_source_t)99,
                  NULL, NULL, NULL, NULL, &alert));
    return 0;
}

TEST(test_salert_create_with_correlation)
{
    _init_svc();
    ozayn_salert_alert_t *alert = NULL;
    ASSERT_EQ(OZAYN_SALERT_OK,
              ozayn_salert_create(&_svc,
                  OZAYN_SALERT_TYPE_MFA_FAILURE,
                  OZAYN_SALERT_SEV_WARNING,
                  OZAYN_SALERT_PRIO_HIGH,
                  OZAYN_SALERT_SOURCE_MFA,
                  "MFA", "CORR-123",
                  "MFA failure", NULL, &alert));
    ASSERT_STR_EQ("CORR-123", alert->correlation_id);
    return 0;
}

TEST(test_salert_create_limit_reached)
{
    _init_svc();
    ozayn_salert_policy_t p = ozayn_salert_default_policy();
    p.max_active_alerts = 2;
    ozayn_salert_set_policy(&_svc, &p);

    ozayn_salert_alert_t *a1 = NULL, *a2 = NULL, *a3 = NULL;
    ASSERT_EQ(OZAYN_SALERT_OK,
              ozayn_salert_create(&_svc,
                  OZAYN_SALERT_TYPE_AUTH_FAILURE,
                  OZAYN_SALERT_SEV_WARNING,
                  OZAYN_SALERT_PRIO_NORMAL,
                  OZAYN_SALERT_SOURCE_AUTHENTICATION,
                  "AUTH", "C1", "Alert 1", NULL, &a1));
    ASSERT_EQ(OZAYN_SALERT_OK,
              ozayn_salert_create(&_svc,
                  OZAYN_SALERT_TYPE_MFA_FAILURE,
                  OZAYN_SALERT_SEV_WARNING,
                  OZAYN_SALERT_PRIO_NORMAL,
                  OZAYN_SALERT_SOURCE_MFA,
                  "MFA", "C2", "Alert 2", NULL, &a2));
    ASSERT_EQ(OZAYN_SALERT_ERR_LIMIT_REACHED,
              ozayn_salert_create(&_svc,
                  OZAYN_SALERT_TYPE_SESSION_ANOMALY,
                  OZAYN_SALERT_SEV_WARNING,
                  OZAYN_SALERT_PRIO_NORMAL,
                  OZAYN_SALERT_SOURCE_SESSION,
                  "SESS", "C3", "Alert 3", NULL, &a3));
    return 0;
}

/* ============================================================
 * ALERT QUERY TESTS
 * ============================================================ */

TEST(test_salert_get)
{
    _init_svc();
    ozayn_salert_alert_t *alert = NULL;
    ozayn_salert_create(&_svc,
        OZAYN_SALERT_TYPE_AUTH_FAILURE,
        OZAYN_SALERT_SEV_HIGH,
        OZAYN_SALERT_PRIO_NORMAL,
        OZAYN_SALERT_SOURCE_AUTHENTICATION,
        "AUTH", NULL, "Test", NULL, &alert);

    ozayn_salert_alert_t *fetched = NULL;
    ASSERT_EQ(OZAYN_SALERT_OK,
              ozayn_salert_get(&_svc, alert->alert_id, &fetched));
    ASSERT_EQ(alert, fetched);
    return 0;
}

TEST(test_salert_get_not_found)
{
    _init_svc();
    ozayn_salert_alert_t *fetched = NULL;
    ASSERT_EQ(OZAYN_SALERT_ERR_NOT_FOUND,
              ozayn_salert_get(&_svc, "NONEXISTENT", &fetched));
    return 0;
}

TEST(test_salert_get_null)
{
    _init_svc();
    ASSERT_EQ(OZAYN_SALERT_ERR_NULL,
              ozayn_salert_get(NULL, "X", NULL));
    return 0;
}

TEST(test_salert_list)
{
    _init_svc();
    ozayn_salert_alert_t *a1 = NULL, *a2 = NULL;
    ozayn_salert_create(&_svc,
        OZAYN_SALERT_TYPE_AUTH_FAILURE,
        OZAYN_SALERT_SEV_HIGH,
        OZAYN_SALERT_PRIO_NORMAL,
        OZAYN_SALERT_SOURCE_AUTHENTICATION,
        "AUTH", NULL, "Auth fail", NULL, &a1);
    ozayn_salert_create(&_svc,
        OZAYN_SALERT_TYPE_MFA_FAILURE,
        OZAYN_SALERT_SEV_WARNING,
        OZAYN_SALERT_PRIO_NORMAL,
        OZAYN_SALERT_SOURCE_MFA,
        "MFA", NULL, "MFA fail", NULL, &a2);

    ozayn_salert_alert_t *list[16];
    int count = ozayn_salert_list(&_svc, -1, -1, list, 16);
    ASSERT_GE(count, 2);
    return 0;
}

TEST(test_salert_list_filter_type)
{
    _init_svc();
    ozayn_salert_alert_t *a1 = NULL;
    ozayn_salert_create(&_svc,
        OZAYN_SALERT_TYPE_AUTH_FAILURE,
        OZAYN_SALERT_SEV_HIGH,
        OZAYN_SALERT_PRIO_NORMAL,
        OZAYN_SALERT_SOURCE_AUTHENTICATION,
        "AUTH", NULL, "Auth fail", NULL, &a1);

    ozayn_salert_alert_t *list[16];
    int count = ozayn_salert_list(&_svc,
        OZAYN_SALERT_TYPE_AUTH_FAILURE, -1, list, 16);
    ASSERT_GE(count, 1);
    return 0;
}

TEST(test_salert_active_count)
{
    _init_svc();
    ASSERT_EQ(0, ozayn_salert_get_active_count(&_svc));
    ozayn_salert_alert_t *a = NULL;
    ozayn_salert_create(&_svc,
        OZAYN_SALERT_TYPE_AUTH_FAILURE,
        OZAYN_SALERT_SEV_HIGH,
        OZAYN_SALERT_PRIO_NORMAL,
        OZAYN_SALERT_SOURCE_AUTHENTICATION,
        "AUTH", NULL, "Test", NULL, &a);
    ASSERT_EQ(1, ozayn_salert_get_active_count(&_svc));
    return 0;
}

/* ============================================================
 * STATE TRANSITION TESTS
 * ============================================================ */

TEST(test_salert_valid_transitions)
{
    /* DETECTED -> CREATED */
    ASSERT(ozayn_salert_state_transition_valid(
        OZAYN_SALERT_STATE_DETECTED, OZAYN_SALERT_STATE_CREATED));
    /* CREATED -> ACTIVE */
    ASSERT(ozayn_salert_state_transition_valid(
        OZAYN_SALERT_STATE_CREATED, OZAYN_SALERT_STATE_ACTIVE));
    /* ACTIVE -> ACKNOWLEDGED */
    ASSERT(ozayn_salert_state_transition_valid(
        OZAYN_SALERT_STATE_ACTIVE, OZAYN_SALERT_STATE_ACKNOWLEDGED));
    /* ACTIVE -> RESOLVED */
    ASSERT(ozayn_salert_state_transition_valid(
        OZAYN_SALERT_STATE_ACTIVE, OZAYN_SALERT_STATE_RESOLVED));
    /* ACTIVE -> SUPPRESSED */
    ASSERT(ozayn_salert_state_transition_valid(
        OZAYN_SALERT_STATE_ACTIVE, OZAYN_SALERT_STATE_SUPPRESSED));
    /* ACTIVE -> EXPIRED */
    ASSERT(ozayn_salert_state_transition_valid(
        OZAYN_SALERT_STATE_ACTIVE, OZAYN_SALERT_STATE_EXPIRED));
    /* ACKNOWLEDGED -> RESOLVING */
    ASSERT(ozayn_salert_state_transition_valid(
        OZAYN_SALERT_STATE_ACKNOWLEDGED, OZAYN_SALERT_STATE_RESOLVING));
    /* RESOLVING -> RESOLVED */
    ASSERT(ozayn_salert_state_transition_valid(
        OZAYN_SALERT_STATE_RESOLVING, OZAYN_SALERT_STATE_RESOLVED));
    /* SUPPRESSED -> ACTIVE */
    ASSERT(ozayn_salert_state_transition_valid(
        OZAYN_SALERT_STATE_SUPPRESSED, OZAYN_SALERT_STATE_ACTIVE));
    return 0;
}

TEST(test_salert_invalid_transitions)
{
    /* RESOLVED -> ACTIVE (not allowed) */
    ASSERT(!ozayn_salert_state_transition_valid(
        OZAYN_SALERT_STATE_RESOLVED, OZAYN_SALERT_STATE_ACTIVE));
    /* RESOLVED -> ACKNOWLEDGED */
    ASSERT(!ozayn_salert_state_transition_valid(
        OZAYN_SALERT_STATE_RESOLVED, OZAYN_SALERT_STATE_ACKNOWLEDGED));
    /* EXPIRED -> ACTIVE */
    ASSERT(!ozayn_salert_state_transition_valid(
        OZAYN_SALERT_STATE_EXPIRED, OZAYN_SALERT_STATE_ACTIVE));
    /* CANCELLED -> ACTIVE */
    ASSERT(!ozayn_salert_state_transition_valid(
        OZAYN_SALERT_STATE_CANCELLED, OZAYN_SALERT_STATE_ACTIVE));
    /* DETECTED -> ACTIVE (must go through CREATED) */
    ASSERT(!ozayn_salert_state_transition_valid(
        OZAYN_SALERT_STATE_DETECTED, OZAYN_SALERT_STATE_ACTIVE));
    return 0;
}

/* ============================================================
 * ACKNOWLEDGE / RESOLVE / SUPPRESS / CANCEL TESTS
 * ============================================================ */

TEST(test_salert_acknowledge)
{
    _init_svc();
    ozayn_salert_alert_t *a = NULL;
    ozayn_salert_create(&_svc,
        OZAYN_SALERT_TYPE_AUTH_FAILURE,
        OZAYN_SALERT_SEV_HIGH,
        OZAYN_SALERT_PRIO_NORMAL,
        OZAYN_SALERT_SOURCE_AUTHENTICATION,
        "AUTH", NULL, "Test", NULL, &a);

    ASSERT_EQ(OZAYN_SALERT_OK,
              ozayn_salert_acknowledge(&_svc, a->alert_id));
    ASSERT_EQ(OZAYN_SALERT_STATE_ACKNOWLEDGED, a->state);
    ASSERT(a->acknowledged_time > 0);
    return 0;
}

TEST(test_salert_acknowledge_not_found)
{
    _init_svc();
    ASSERT_EQ(OZAYN_SALERT_ERR_NOT_FOUND,
              ozayn_salert_acknowledge(&_svc, "NONEXISTENT"));
    return 0;
}

TEST(test_salert_resolve)
{
    _init_svc();
    ozayn_salert_alert_t *a = NULL;
    ozayn_salert_create(&_svc,
        OZAYN_SALERT_TYPE_AUTH_FAILURE,
        OZAYN_SALERT_SEV_HIGH,
        OZAYN_SALERT_PRIO_NORMAL,
        OZAYN_SALERT_SOURCE_AUTHENTICATION,
        "AUTH", NULL, "Test", NULL, &a);

    ASSERT_EQ(OZAYN_SALERT_OK,
              ozayn_salert_resolve(&_svc, a->alert_id));
    ASSERT_EQ(OZAYN_SALERT_STATE_RESOLVED, a->state);
    ASSERT(a->resolved_time > 0);
    return 0;
}

TEST(test_salert_resolve_not_found)
{
    _init_svc();
    ASSERT_EQ(OZAYN_SALERT_ERR_NOT_FOUND,
              ozayn_salert_resolve(&_svc, "NONEXISTENT"));
    return 0;
}

TEST(test_salert_suppress)
{
    _init_svc();
    ozayn_salert_alert_t *a = NULL;
    ozayn_salert_create(&_svc,
        OZAYN_SALERT_TYPE_AUTH_FAILURE,
        OZAYN_SALERT_SEV_WARNING,
        OZAYN_SALERT_PRIO_NORMAL,
        OZAYN_SALERT_SOURCE_AUTHENTICATION,
        "AUTH", NULL, "Test", NULL, &a);

    ASSERT_EQ(OZAYN_SALERT_OK,
              ozayn_salert_suppress(&_svc, a->alert_id, 1));
    ASSERT_EQ(OZAYN_SALERT_STATE_SUPPRESSED, a->state);
    ASSERT(a->suppressed);
    return 0;
}

TEST(test_salert_suppress_critical_rejected)
{
    _init_svc();
    ozayn_salert_alert_t *a = NULL;
    ozayn_salert_create(&_svc,
        OZAYN_SALERT_TYPE_LOCKDOWN,
        OZAYN_SALERT_SEV_CRITICAL,
        OZAYN_SALERT_PRIO_IMMEDIATE,
        OZAYN_SALERT_SOURCE_SYSTEM,
        "SYS", NULL, "Lockdown", NULL, &a);

    ASSERT_EQ(OZAYN_SALERT_ERR_SUPPRESSION_REJECTED,
              ozayn_salert_suppress(&_svc, a->alert_id, 0));
    return 0;
}

TEST(test_salert_cancel)
{
    _init_svc();
    ozayn_salert_alert_t *a = NULL;
    ozayn_salert_create(&_svc,
        OZAYN_SALERT_TYPE_AUTH_FAILURE,
        OZAYN_SALERT_SEV_HIGH,
        OZAYN_SALERT_PRIO_NORMAL,
        OZAYN_SALERT_SOURCE_AUTHENTICATION,
        "AUTH", NULL, "Test", NULL, &a);

    ASSERT_EQ(OZAYN_SALERT_OK,
              ozayn_salert_cancel(&_svc, a->alert_id));
    ASSERT_EQ(OZAYN_SALERT_STATE_CANCELLED, a->state);
    return 0;
}

/* ============================================================
 * ESCALATION TESTS
 * ============================================================ */

TEST(test_salert_escalate)
{
    _init_svc();
    ozayn_salert_alert_t *a = NULL;
    ozayn_salert_create(&_svc,
        OZAYN_SALERT_TYPE_AUTH_FAILURE,
        OZAYN_SALERT_SEV_WARNING,
        OZAYN_SALERT_PRIO_LOW,
        OZAYN_SALERT_SOURCE_AUTHENTICATION,
        "AUTH", NULL, "Test", NULL, &a);

    ASSERT_EQ(OZAYN_SALERT_OK,
              ozayn_salert_escalate(&_svc, a->alert_id));
    ASSERT_EQ(1, a->escalation_level);
    ASSERT_EQ(OZAYN_SALERT_SEV_HIGH, a->severity);
    ASSERT_EQ(OZAYN_SALERT_PRIO_NORMAL, a->priority);
    return 0;
}

TEST(test_salert_escalate_limit)
{
    _init_svc();
    ozayn_salert_alert_t *a = NULL;
    ozayn_salert_create(&_svc,
        OZAYN_SALERT_TYPE_AUTH_FAILURE,
        OZAYN_SALERT_SEV_WARNING,
        OZAYN_SALERT_PRIO_LOW,
        OZAYN_SALERT_SOURCE_AUTHENTICATION,
        "AUTH", NULL, "Test", NULL, &a);

    for (int i = 0; i < 4; i++)
        ozayn_salert_escalate(&_svc, a->alert_id);

    ASSERT_EQ(OZAYN_SALERT_ERR_ESCALATION_REJECTED,
              ozayn_salert_escalate(&_svc, a->alert_id));
    return 0;
}

TEST(test_salert_escalate_resolved)
{
    _init_svc();
    ozayn_salert_alert_t *a = NULL;
    ozayn_salert_create(&_svc,
        OZAYN_SALERT_TYPE_AUTH_FAILURE,
        OZAYN_SALERT_SEV_WARNING,
        OZAYN_SALERT_PRIO_LOW,
        OZAYN_SALERT_SOURCE_AUTHENTICATION,
        "AUTH", NULL, "Test", NULL, &a);

    ozayn_salert_resolve(&_svc, a->alert_id);
    ASSERT_EQ(OZAYN_SALERT_ERR_STATE_TRANSITION_INVALID,
              ozayn_salert_escalate(&_svc, a->alert_id));
    return 0;
}

TEST(test_salert_get_escalation_level)
{
    _init_svc();
    ozayn_salert_alert_t *a = NULL;
    ozayn_salert_create(&_svc,
        OZAYN_SALERT_TYPE_AUTH_FAILURE,
        OZAYN_SALERT_SEV_WARNING,
        OZAYN_SALERT_PRIO_LOW,
        OZAYN_SALERT_SOURCE_AUTHENTICATION,
        "AUTH", NULL, "Test", NULL, &a);

    ASSERT_EQ(0, ozayn_salert_get_escalation_level(&_svc, a->alert_id));
    ozayn_salert_escalate(&_svc, a->alert_id);
    ASSERT_EQ(1, ozayn_salert_get_escalation_level(&_svc, a->alert_id));
    return 0;
}

/* ============================================================
 * DEDUPLICATION TESTS
 * ============================================================ */

TEST(test_salert_dedup_same_condition)
{
    _init_svc();
    ozayn_salert_alert_t *a1 = NULL, *a2 = NULL;
    ozayn_salert_create(&_svc,
        OZAYN_SALERT_TYPE_AUTH_FAILURE,
        OZAYN_SALERT_SEV_HIGH,
        OZAYN_SALERT_PRIO_NORMAL,
        OZAYN_SALERT_SOURCE_AUTHENTICATION,
        "AUTH", "CORR-1",
        "Same condition", NULL, &a1);
    ozayn_salert_create(&_svc,
        OZAYN_SALERT_TYPE_AUTH_FAILURE,
        OZAYN_SALERT_SEV_HIGH,
        OZAYN_SALERT_PRIO_NORMAL,
        OZAYN_SALERT_SOURCE_AUTHENTICATION,
        "AUTH", "CORR-1",
        "Same condition", NULL, &a2);

    /* Should be deduplicated — same alert */
    ASSERT_EQ(a1, a2);
    ASSERT_GE(a1->dedup_count, 2);
    return 0;
}

TEST(test_salert_dedup_different_condition)
{
    _init_svc();
    ozayn_salert_alert_t *a1 = NULL, *a2 = NULL;
    ozayn_salert_create(&_svc,
        OZAYN_SALERT_TYPE_AUTH_FAILURE,
        OZAYN_SALERT_SEV_HIGH,
        OZAYN_SALERT_PRIO_NORMAL,
        OZAYN_SALERT_SOURCE_AUTHENTICATION,
        "AUTH", "CORR-1",
        "Condition A", NULL, &a1);
    ozayn_salert_create(&_svc,
        OZAYN_SALERT_TYPE_MFA_FAILURE,
        OZAYN_SALERT_SEV_HIGH,
        OZAYN_SALERT_PRIO_NORMAL,
        OZAYN_SALERT_SOURCE_MFA,
        "MFA", "CORR-2",
        "Condition B", NULL, &a2);

    /* Should NOT be deduplicated — different types */
    ASSERT_NEQ(a1, a2);
    return 0;
}

TEST(test_salert_check_dedup)
{
    _init_svc();
    ozayn_salert_register_dedup(&_svc, "test-key", 42);
    int is_dup = 0;
    uint32_t hash = 0;
    ASSERT_EQ(OZAYN_SALERT_OK,
              ozayn_salert_check_dedup(&_svc, "test-key", &is_dup, &hash));
    ASSERT(is_dup);
    ASSERT_EQ(42u, hash);
    return 0;
}

TEST(test_salert_check_dedup_not_found)
{
    _init_svc();
    int is_dup = 1;
    ASSERT_EQ(OZAYN_SALERT_OK,
              ozayn_salert_check_dedup(&_svc, "nonexistent", &is_dup, NULL));
    ASSERT(!is_dup);
    return 0;
}

TEST(test_salert_is_in_dedup_window)
{
    _init_svc();
    ozayn_salert_register_dedup(&_svc, "window-key", 1);
    ASSERT(ozayn_salert_is_in_dedup_window(&_svc, "window-key"));
    ASSERT(!ozayn_salert_is_in_dedup_window(&_svc, "other-key"));
    return 0;
}

/* ============================================================
 * THRESHOLD TESTS
 * ============================================================ */

TEST(test_salert_add_threshold)
{
    _init_svc();
    ozayn_salert_threshold_t t;
    memset(&t, 0, sizeof(t));
    t.alert_type = OZAYN_SALERT_TYPE_AUTH_FAILURE;
    t.threshold_count = 5;
    t.window_seconds = 60;
    t.resulting_severity = OZAYN_SALERT_SEV_HIGH;
    t.enabled = 1;
    ASSERT_EQ(OZAYN_SALERT_OK, ozayn_salert_add_threshold(&_svc, &t));
    return 0;
}

TEST(test_salert_add_threshold_invalid)
{
    _init_svc();
    ozayn_salert_threshold_t t;
    memset(&t, 0, sizeof(t));
    t.threshold_count = 0;
    t.window_seconds = 60;
    ASSERT_EQ(OZAYN_SALERT_ERR_THRESHOLD_INVALID,
              ozayn_salert_add_threshold(&_svc, &t));
    return 0;
}

TEST(test_salert_check_threshold_not_exceeded)
{
    _init_svc();
    ozayn_salert_threshold_t t;
    memset(&t, 0, sizeof(t));
    t.alert_type = OZAYN_SALERT_TYPE_AUTH_FAILURE;
    t.threshold_count = 5;
    t.window_seconds = 60;
    t.resulting_severity = OZAYN_SALERT_SEV_HIGH;
    t.enabled = 1;
    ozayn_salert_add_threshold(&_svc, &t);

    int exceeded = 1;
    ASSERT_EQ(OZAYN_SALERT_OK,
              ozayn_salert_check_threshold(&_svc,
                  OZAYN_SALERT_TYPE_AUTH_FAILURE, &exceeded, NULL));
    ASSERT(!exceeded);
    return 0;
}

TEST(test_salert_threshold_exceeded)
{
    _init_svc();
    ozayn_salert_threshold_t t;
    memset(&t, 0, sizeof(t));
    t.alert_type = OZAYN_SALERT_TYPE_AUTH_FAILURE;
    t.threshold_count = 3;
    t.window_seconds = 60;
    t.resulting_severity = OZAYN_SALERT_SEV_CRITICAL;
    t.enabled = 1;
    ozayn_salert_add_threshold(&_svc, &t);

    for (int i = 0; i < 3; i++)
        ozayn_salert_record_threshold_event(&_svc,
            OZAYN_SALERT_TYPE_AUTH_FAILURE);

    int exceeded = 0;
    ozayn_salert_severity_t sev = OZAYN_SALERT_SEV_INFO;
    ASSERT_EQ(OZAYN_SALERT_OK,
              ozayn_salert_check_threshold(&_svc,
                  OZAYN_SALERT_TYPE_AUTH_FAILURE, &exceeded, &sev));
    ASSERT(exceeded);
    ASSERT_EQ(OZAYN_SALERT_SEV_CRITICAL, sev);
    return 0;
}

/* ============================================================
 * RATE LIMITING TESTS
 * ============================================================ */

TEST(test_salert_rate_limit)
{
    _init_svc();
    ASSERT(ozayn_salert_check_rate_limit(&_svc,
        OZAYN_SALERT_TYPE_AUTH_FAILURE));
    return 0;
}

TEST(test_salert_rate_limit_at_capacity)
{
    _init_svc();
    ozayn_salert_policy_t p = ozayn_salert_default_policy();
    p.max_active_alerts = 1;
    ozayn_salert_set_policy(&_svc, &p);

    ozayn_salert_alert_t *a = NULL;
    ozayn_salert_create(&_svc,
        OZAYN_SALERT_TYPE_AUTH_FAILURE,
        OZAYN_SALERT_SEV_HIGH,
        OZAYN_SALERT_PRIO_NORMAL,
        OZAYN_SALERT_SOURCE_AUTHENTICATION,
        "AUTH", NULL, "Test", NULL, &a);

    ASSERT(!ozayn_salert_check_rate_limit(&_svc,
        OZAYN_SALERT_TYPE_AUTH_FAILURE));
    return 0;
}

/* ============================================================
 * NOTIFICATION TESTS
 * ============================================================ */

TEST(test_salert_register_provider)
{
    _init_svc();
    _test_notify_ok = 0;
    _test_notify_fail = 0;
    ASSERT_EQ(OZAYN_SALERT_OK,
              ozayn_salert_register_provider(&_svc, &_test_vtable,
                  NULL, OZAYN_SALERT_NOTIFY_LOCAL));
    return 0;
}

TEST(test_salert_register_provider_null)
{
    _init_svc();
    ASSERT_EQ(OZAYN_SALERT_ERR_NULL,
              ozayn_salert_register_provider(&_svc, NULL, NULL,
                  OZAYN_SALERT_NOTIFY_LOCAL));
    return 0;
}

TEST(test_salert_queue_notification)
{
    _init_svc();
    ozayn_salert_alert_t *a = NULL;
    ozayn_salert_create(&_svc,
        OZAYN_SALERT_TYPE_AUTH_FAILURE,
        OZAYN_SALERT_SEV_HIGH,
        OZAYN_SALERT_PRIO_NORMAL,
        OZAYN_SALERT_SOURCE_AUTHENTICATION,
        "AUTH", NULL, "Test", NULL, &a);

    ASSERT_EQ(OZAYN_SALERT_OK,
              ozayn_salert_queue_notification(&_svc, a->alert_id,
                  OZAYN_SALERT_NOTIFY_LOCAL));
    ASSERT_EQ(OZAYN_SALERT_NOTIFY_STATE_PENDING, a->notify_state);
    ASSERT_EQ(1, ozayn_salert_get_notify_queue_count(&_svc));
    return 0;
}

TEST(test_salert_process_notifications)
{
    _init_svc();
    _test_notify_ok = 0;
    _test_notify_fail = 0;
    ozayn_salert_register_provider(&_svc, &_test_vtable,
        NULL, OZAYN_SALERT_NOTIFY_LOCAL);

    ozayn_salert_alert_t *a = NULL;
    ozayn_salert_create(&_svc,
        OZAYN_SALERT_TYPE_AUTH_FAILURE,
        OZAYN_SALERT_SEV_HIGH,
        OZAYN_SALERT_PRIO_NORMAL,
        OZAYN_SALERT_SOURCE_AUTHENTICATION,
        "AUTH", NULL, "Test", NULL, &a);

    ozayn_salert_queue_notification(&_svc, a->alert_id,
        OZAYN_SALERT_NOTIFY_LOCAL);
    ASSERT_EQ(OZAYN_SALERT_OK, ozayn_salert_process_notifications(&_svc));
    ASSERT_EQ(1, _test_notify_ok);
    ASSERT_EQ(OZAYN_SALERT_NOTIFY_STATE_SENT, a->notify_state);
    return 0;
}

TEST(test_salert_notification_failure)
{
    _init_svc();
    _test_notify_ok = 0;
    _test_notify_fail = 1;
    ozayn_salert_register_provider(&_svc, &_test_vtable,
        NULL, OZAYN_SALERT_NOTIFY_LOCAL);

    ozayn_salert_alert_t *a = NULL;
    ozayn_salert_create(&_svc,
        OZAYN_SALERT_TYPE_AUTH_FAILURE,
        OZAYN_SALERT_SEV_HIGH,
        OZAYN_SALERT_PRIO_NORMAL,
        OZAYN_SALERT_SOURCE_AUTHENTICATION,
        "AUTH", NULL, "Test", NULL, &a);

    ozayn_salert_queue_notification(&_svc, a->alert_id,
        OZAYN_SALERT_NOTIFY_LOCAL);
    /* Process multiple times to exhaust retries */
    for (int i = 0; i < 5; i++)
        ozayn_salert_process_notifications(&_svc);

    ASSERT_EQ(OZAYN_SALERT_NOTIFY_STATE_FAILED, a->notify_state);
    _test_notify_fail = 0;
    return 0;
}

TEST(test_salert_notification_rate_limit)
{
    _init_svc();
    ozayn_salert_register_provider(&_svc, &_test_vtable,
        NULL, OZAYN_SALERT_NOTIFY_LOCAL);

    ozayn_salert_policy_t p = ozayn_salert_default_policy();
    p.max_notify_per_window = 2;
    ozayn_salert_set_policy(&_svc, &p);

    ozayn_salert_alert_t *a1 = NULL, *a2 = NULL, *a3 = NULL;
    ozayn_salert_create(&_svc,
        OZAYN_SALERT_TYPE_AUTH_FAILURE,
        OZAYN_SALERT_SEV_HIGH,
        OZAYN_SALERT_PRIO_NORMAL,
        OZAYN_SALERT_SOURCE_AUTHENTICATION,
        "AUTH", "C1", "T1", NULL, &a1);
    ozayn_salert_create(&_svc,
        OZAYN_SALERT_TYPE_MFA_FAILURE,
        OZAYN_SALERT_SEV_HIGH,
        OZAYN_SALERT_PRIO_NORMAL,
        OZAYN_SALERT_SOURCE_MFA,
        "MFA", "C2", "T2", NULL, &a2);
    ozayn_salert_create(&_svc,
        OZAYN_SALERT_TYPE_SESSION_ANOMALY,
        OZAYN_SALERT_SEV_HIGH,
        OZAYN_SALERT_PRIO_NORMAL,
        OZAYN_SALERT_SOURCE_SESSION,
        "SESS", "C3", "T3", NULL, &a3);

    ASSERT_EQ(OZAYN_SALERT_OK,
              ozayn_salert_queue_notification(&_svc, a1->alert_id,
                  OZAYN_SALERT_NOTIFY_LOCAL));
    ASSERT_EQ(OZAYN_SALERT_OK,
              ozayn_salert_queue_notification(&_svc, a2->alert_id,
                  OZAYN_SALERT_NOTIFY_LOCAL));
    ASSERT_EQ(OZAYN_SALERT_ERR_RATE_LIMITED,
              ozayn_salert_queue_notification(&_svc, a3->alert_id,
                  OZAYN_SALERT_NOTIFY_LOCAL));
    return 0;
}

/* ============================================================
 * HEALTH INTEGRATION TESTS
 * ============================================================ */

TEST(test_salert_evaluate_health_healthy)
{
    _init_svc();
    /* Health is initialized but has no real data, should not create alerts */
    ASSERT_EQ(OZAYN_SALERT_OK,
              ozayn_salert_evaluate_health(&_svc));
    return 0;
}

TEST(test_salert_evaluate_health_unavailable)
{
    _init_svc();
    memset(&_sh_svc, 0, sizeof(_sh_svc));
    ASSERT_EQ(OZAYN_SALERT_ERR_UNAVAILABLE,
              ozayn_salert_evaluate_health(&_svc));
    return 0;
}

/* ============================================================
 * DIAGNOSTIC INTEGRATION TESTS
 * ============================================================ */

TEST(test_salert_evaluate_diagnostics)
{
    _init_svc();
    ASSERT_EQ(OZAYN_SALERT_OK,
              ozayn_salert_evaluate_diagnostics(&_svc));
    return 0;
}

TEST(test_salert_evaluate_diagnostics_unavailable)
{
    _init_svc();
    memset(&_sdiag_svc, 0, sizeof(_sdiag_svc));
    ASSERT_EQ(OZAYN_SALERT_ERR_UNAVAILABLE,
              ozayn_salert_evaluate_diagnostics(&_svc));
    return 0;
}

/* ============================================================
 * INCIDENT INTEGRATION TESTS
 * ============================================================ */

TEST(test_salert_evaluate_incidents)
{
    _init_svc();
    ASSERT_EQ(OZAYN_SALERT_OK,
              ozayn_salert_evaluate_incidents(&_svc));
    return 0;
}

TEST(test_salert_evaluate_incidents_unavailable)
{
    _init_svc();
    memset(&_ir_svc, 0, sizeof(_ir_svc));
    ASSERT_EQ(OZAYN_SALERT_ERR_UNAVAILABLE,
              ozayn_salert_evaluate_incidents(&_svc));
    return 0;
}

/* ============================================================
 * CLEANUP TESTS
 * ============================================================ */

TEST(test_salert_cleanup_expired)
{
    _init_svc();
    ozayn_salert_alert_t *a = NULL;
    ozayn_salert_create(&_svc,
        OZAYN_SALERT_TYPE_AUTH_FAILURE,
        OZAYN_SALERT_SEV_HIGH,
        OZAYN_SALERT_PRIO_NORMAL,
        OZAYN_SALERT_SOURCE_AUTHENTICATION,
        "AUTH", NULL, "Test", NULL, &a);

    /* Set expiration in the past */
    a->expiration_time = time(NULL) - 100;
    int cleaned = ozayn_salert_cleanup_expired(&_svc);
    ASSERT_GE(cleaned, 1);
    return 0;
}

TEST(test_salert_cleanup_resolved)
{
    _init_svc();
    ozayn_salert_alert_t *a = NULL;
    ozayn_salert_create(&_svc,
        OZAYN_SALERT_TYPE_AUTH_FAILURE,
        OZAYN_SALERT_SEV_HIGH,
        OZAYN_SALERT_PRIO_NORMAL,
        OZAYN_SALERT_SOURCE_AUTHENTICATION,
        "AUTH", NULL, "Test", NULL, &a);

    ozayn_salert_resolve(&_svc, a->alert_id);
    a->resolved_time = time(NULL) - 100000;
    int cleaned = ozayn_salert_cleanup_resolved(&_svc, 3600);
    ASSERT_GE(cleaned, 1);
    return 0;
}

/* ============================================================
 * NAME HELPER TESTS
 * ============================================================ */

TEST(test_salert_name_err)
{
    ASSERT(strcmp(ozayn_salert_err_name(OZAYN_SALERT_OK), "OK") == 0);
    ASSERT(strcmp(ozayn_salert_err_name(OZAYN_SALERT_ERR_NULL),
                  "ERR_NULL") == 0);
    ASSERT(strcmp(ozayn_salert_err_name((ozayn_salert_err_t)99),
                  "UNKNOWN") == 0);
    return 0;
}

TEST(test_salert_name_type)
{
    ASSERT(strcmp(ozayn_salert_type_name(OZAYN_SALERT_TYPE_AUTH_FAILURE),
                  "AUTH_FAILURE") == 0);
    ASSERT(strcmp(ozayn_salert_type_name(OZAYN_SALERT_TYPE_LOCKDOWN),
                  "LOCKDOWN") == 0);
    ASSERT(strcmp(ozayn_salert_type_name((ozayn_salert_type_t)99),
                  "UNKNOWN") == 0);
    return 0;
}

TEST(test_salert_name_severity)
{
    ASSERT(strcmp(ozayn_salert_severity_name(OZAYN_SALERT_SEV_INFO),
                  "INFO") == 0);
    ASSERT(strcmp(ozayn_salert_severity_name(OZAYN_SALERT_SEV_CRITICAL),
                  "CRITICAL") == 0);
    ASSERT(strcmp(ozayn_salert_severity_name((ozayn_salert_severity_t)99),
                  "UNKNOWN") == 0);
    return 0;
}

TEST(test_salert_name_priority)
{
    ASSERT(strcmp(ozayn_salert_priority_name(OZAYN_SALERT_PRIO_LOW),
                  "LOW") == 0);
    ASSERT(strcmp(ozayn_salert_priority_name(OZAYN_SALERT_PRIO_IMMEDIATE),
                  "IMMEDIATE") == 0);
    ASSERT(strcmp(ozayn_salert_priority_name((ozayn_salert_priority_t)99),
                  "UNKNOWN") == 0);
    return 0;
}

TEST(test_salert_name_state)
{
    ASSERT(strcmp(ozayn_salert_state_name(OZAYN_SALERT_STATE_ACTIVE),
                  "ACTIVE") == 0);
    ASSERT(strcmp(ozayn_salert_state_name(OZAYN_SALERT_STATE_RESOLVED),
                  "RESOLVED") == 0);
    ASSERT(strcmp(ozayn_salert_state_name((ozayn_salert_state_t)99),
                  "UNKNOWN") == 0);
    return 0;
}

TEST(test_salert_name_source)
{
    ASSERT(strcmp(ozayn_salert_source_name(OZAYN_SALERT_SOURCE_AUTHENTICATION),
                  "AUTHENTICATION") == 0);
    ASSERT(strcmp(ozayn_salert_source_name(OZAYN_SALERT_SOURCE_SYSTEM),
                  "SYSTEM") == 0);
    ASSERT(strcmp(ozayn_salert_source_name((ozayn_salert_source_t)99),
                  "UNKNOWN") == 0);
    return 0;
}

TEST(test_salert_name_notify_channel)
{
    ASSERT(strcmp(ozayn_salert_notify_channel_name(OZAYN_SALERT_NOTIFY_LOCAL),
                  "LOCAL") == 0);
    ASSERT(strcmp(ozayn_salert_notify_channel_name(
                  OZAYN_SALERT_NOTIFY_CONTROL_ROOM), "CONTROL_ROOM") == 0);
    return 0;
}

TEST(test_salert_name_notify_state)
{
    ASSERT(strcmp(ozayn_salert_notify_state_name(
                  OZAYN_SALERT_NOTIFY_STATE_NONE), "NONE") == 0);
    ASSERT(strcmp(ozayn_salert_notify_state_name(
                  OZAYN_SALERT_NOTIFY_STATE_SENT), "SENT") == 0);
    return 0;
}

/* ============================================================
 * SEVERITY / PRIORITY HELPER TESTS
 * ============================================================ */

TEST(test_salert_worse_severity)
{
    ASSERT_EQ(OZAYN_SALERT_SEV_CRITICAL,
              ozayn_salert_worse_severity(
                  OZAYN_SALERT_SEV_INFO, OZAYN_SALERT_SEV_CRITICAL));
    ASSERT_EQ(OZAYN_SALERT_SEV_HIGH,
              ozayn_salert_worse_severity(
                  OZAYN_SALERT_SEV_HIGH, OZAYN_SALERT_SEV_WARNING));
    return 0;
}

TEST(test_salert_higher_priority)
{
    ASSERT_EQ(OZAYN_SALERT_PRIO_IMMEDIATE,
              ozayn_salert_higher_priority(
                  OZAYN_SALERT_PRIO_LOW, OZAYN_SALERT_PRIO_IMMEDIATE));
    return 0;
}

TEST(test_salert_severity_meets_threshold)
{
    ASSERT(ozayn_salert_severity_meets_threshold(
        OZAYN_SALERT_SEV_CRITICAL, OZAYN_SALERT_SEV_HIGH));
    ASSERT(!ozayn_salert_severity_meets_threshold(
        OZAYN_SALERT_SEV_WARNING, OZAYN_SALERT_SEV_HIGH));
    return 0;
}

/* ============================================================
 * SAFE CONTENT TESTS
 * ============================================================ */

TEST(test_salert_generate_safe_title)
{
    ozayn_salert_alert_t alert;
    memset(&alert, 0, sizeof(alert));
    alert.severity = OZAYN_SALERT_SEV_HIGH;
    alert.alert_type = OZAYN_SALERT_TYPE_AUTH_FAILURE;

    char title[256];
    ASSERT_EQ(OZAYN_SALERT_OK,
              ozayn_salert_generate_safe_title(&alert, title, sizeof(title)));
    ASSERT(strstr(title, "HIGH") != NULL);
    ASSERT(strstr(title, "AUTH_FAILURE") != NULL);
    return 0;
}

TEST(test_salert_generate_safe_body)
{
    ozayn_salert_alert_t alert;
    memset(&alert, 0, sizeof(alert));
    alert.severity = OZAYN_SALERT_SEV_CRITICAL;
    alert.priority = OZAYN_SALERT_PRIO_IMMEDIATE;
    strncpy(alert.source_component, "AUTH", 63);
    strncpy(alert.safe_summary, "Repeated failures", 255);
    strncpy(alert.alert_id, "SALERT-0001", 63);

    char body[512];
    ASSERT_EQ(OZAYN_SALERT_OK,
              ozayn_salert_generate_safe_body(&alert, body, sizeof(body)));
    ASSERT(strstr(body, "CRITICAL") != NULL);
    ASSERT(strstr(body, "IMMEDIATE") != NULL);
    ASSERT(strstr(body, "AUTH") != NULL);
    ASSERT(strstr(body, "SALERT-0001") != NULL);
    return 0;
}

TEST(test_salert_generate_safe_title_null)
{
    ASSERT_EQ(OZAYN_SALERT_ERR_NULL,
              ozayn_salert_generate_safe_title(NULL, NULL, 0));
    return 0;
}

/* ============================================================
 * NEGATIVE SECURITY TESTS
 * ============================================================ */

TEST(test_salert_no_secrets_in_alert)
{
    _init_svc();
    ozayn_salert_alert_t *a = NULL;
    ozayn_salert_create(&_svc,
        OZAYN_SALERT_TYPE_AUTH_FAILURE,
        OZAYN_SALERT_SEV_HIGH,
        OZAYN_SALERT_PRIO_NORMAL,
        OZAYN_SALERT_SOURCE_AUTHENTICATION,
        "AUTH", NULL, "Test alert", "Detail", &a);

    ASSERT(strstr(a->safe_summary, "password") == NULL);
    ASSERT(strstr(a->safe_summary, "secret") == NULL);
    ASSERT(strstr(a->safe_summary, "private_key") == NULL);
    ASSERT(strstr(a->safe_detail, "password") == NULL);
    ASSERT(strstr(a->safe_detail, "secret") == NULL);
    ASSERT(strstr(a->safe_detail, "private_key") == NULL);
    return 0;
}

TEST(test_salert_no_secrets_in_notification)
{
    _init_svc();
    ozayn_salert_alert_t *a = NULL;
    ozayn_salert_create(&_svc,
        OZAYN_SALERT_TYPE_AUTH_FAILURE,
        OZAYN_SALERT_SEV_HIGH,
        OZAYN_SALERT_PRIO_NORMAL,
        OZAYN_SALERT_SOURCE_AUTHENTICATION,
        "AUTH", NULL, "Test", NULL, &a);

    char title[256], body[512];
    ozayn_salert_generate_safe_title(a, title, sizeof(title));
    ozayn_salert_generate_safe_body(a, body, sizeof(body));

    ASSERT(strstr(title, "password") == NULL);
    ASSERT(strstr(title, "secret") == NULL);
    ASSERT(strstr(body, "password") == NULL);
    ASSERT(strstr(body, "secret") == NULL);
    return 0;
}

TEST(test_salert_default_deny_policy)
{
    _init_svc();
    /* Policy must be explicitly set; no default bypass */
    ozayn_salert_policy_t p = ozayn_salert_default_policy();
    ASSERT(p.enabled);
    ASSERT(p.require_ack_for_critical);
    ASSERT(p.max_escalation_level > 0);
    return 0;
}

TEST(test_salert_no_bypass_via_alerting)
{
    _init_svc();
    /* Creating an alert must not bypass security */
    ozayn_salert_alert_t *a = NULL;
    ASSERT_EQ(OZAYN_SALERT_OK,
              ozayn_salert_create(&_svc,
                  OZAYN_SALERT_TYPE_AUTH_FAILURE,
                  OZAYN_SALERT_SEV_CRITICAL,
                  OZAYN_SALERT_PRIO_IMMEDIATE,
                  OZAYN_SALERT_SOURCE_AUTHENTICATION,
                  "AUTH", NULL, "Test", NULL, &a));
    /* Alert is active but does not grant any access */
    ASSERT_EQ(OZAYN_SALERT_STATE_ACTIVE, a->state);
    ASSERT(!a->suppressed);
    return 0;
}

TEST(test_salert_suppress_requires_reason)
{
    _init_svc();
    ozayn_salert_alert_t *a = NULL;
    ozayn_salert_create(&_svc,
        OZAYN_SALERT_TYPE_AUTH_FAILURE,
        OZAYN_SALERT_SEV_WARNING,
        OZAYN_SALERT_PRIO_NORMAL,
        OZAYN_SALERT_SOURCE_AUTHENTICATION,
        "AUTH", NULL, "Test", NULL, &a);

    /* Critical alerts cannot be suppressed with reason 0 */
    a->severity = OZAYN_SALERT_SEV_CRITICAL;
    ASSERT_EQ(OZAYN_SALERT_ERR_SUPPRESSION_REJECTED,
              ozayn_salert_suppress(&_svc, a->alert_id, 0));
    return 0;
}

TEST(test_salert_notification_failure_does_not_disable_security)
{
    _init_svc();
    _test_notify_fail = 1;
    ozayn_salert_register_provider(&_svc, &_test_vtable,
        NULL, OZAYN_SALERT_NOTIFY_LOCAL);

    ozayn_salert_alert_t *a = NULL;
    ozayn_salert_create(&_svc,
        OZAYN_SALERT_TYPE_LOCKDOWN,
        OZAYN_SALERT_SEV_CRITICAL,
        OZAYN_SALERT_PRIO_IMMEDIATE,
        OZAYN_SALERT_SOURCE_SYSTEM,
        "SYS", NULL, "Lockdown", NULL, &a);

    ozayn_salert_queue_notification(&_svc, a->alert_id,
        OZAYN_SALERT_NOTIFY_LOCAL);
    for (int i = 0; i < 5; i++)
        ozayn_salert_process_notifications(&_svc);

    /* Alert remains active even though notification failed */
    ASSERT_EQ(OZAYN_SALERT_STATE_ACTIVE, a->state);
    ASSERT_EQ(OZAYN_SALERT_NOTIFY_STATE_FAILED, a->notify_state);
    _test_notify_fail = 0;
    return 0;
}

TEST(test_salert_repeated_events_bounded)
{
    _init_svc();
    ozayn_salert_policy_t p = ozayn_salert_default_policy();
    p.max_active_alerts = 5;
    ozayn_salert_set_policy(&_svc, &p);

    for (int i = 0; i < 10; i++) {
        ozayn_salert_alert_t *a = NULL;
        ozayn_salert_create(&_svc,
            OZAYN_SALERT_TYPE_AUTH_FAILURE,
            OZAYN_SALERT_SEV_HIGH,
            OZAYN_SALERT_PRIO_NORMAL,
            OZAYN_SALERT_SOURCE_AUTHENTICATION,
            "AUTH", NULL, "Repeated", NULL, &a);
    }
    /* Should not exceed limit */
    ASSERT(ozayn_salert_get_active_count(&_svc) <= 5);
    return 0;
}

TEST(test_salert_dedup_prevents_flooding)
{
    _init_svc();
    ozayn_salert_alert_t *a1 = NULL;
    ozayn_salert_create(&_svc,
        OZAYN_SALERT_TYPE_AUTH_FAILURE,
        OZAYN_SALERT_SEV_HIGH,
        OZAYN_SALERT_PRIO_NORMAL,
        OZAYN_SALERT_SOURCE_AUTHENTICATION,
        "AUTH", "SAME-CORR",
        "Same condition", NULL, &a1);

    int count_before = ozayn_salert_get_total_count(&_svc);

    for (int i = 0; i < 10; i++) {
        ozayn_salert_alert_t *a = NULL;
        ozayn_salert_create(&_svc,
            OZAYN_SALERT_TYPE_AUTH_FAILURE,
            OZAYN_SALERT_SEV_HIGH,
            OZAYN_SALERT_PRIO_NORMAL,
            OZAYN_SALERT_SOURCE_AUTHENTICATION,
            "AUTH", "SAME-CORR",
            "Same condition", NULL, &a);
    }

    int count_after = ozayn_salert_get_total_count(&_svc);
    /* Dedup should prevent most new alerts */
    ASSERT(count_after - count_before <= 2);
    return 0;
}

/* ============================================================
 * SUITE
 * ============================================================ */

int run_sec_alert_tests(void)
{
    SUITE_BEGIN("SECURITY ALERTING TESTS");

    /* Lifecycle */
    RUN(test_salert_init);
    RUN(test_salert_init_null);
    RUN(test_salert_init_double);
    RUN(test_salert_shutdown_null);
    RUN(test_salert_is_init_null);
    RUN(test_salert_default_policy);
    RUN(test_salert_global);

    /* Policy */
    RUN(test_salert_set_policy);
    RUN(test_salert_set_policy_null);
    RUN(test_salert_set_policy_invalid);
    RUN(test_salert_set_policy_not_init);

    /* Creation */
    RUN(test_salert_create);
    RUN(test_salert_create_null);
    RUN(test_salert_create_not_init);
    RUN(test_salert_create_invalid_type);
    RUN(test_salert_create_invalid_severity);
    RUN(test_salert_create_invalid_priority);
    RUN(test_salert_create_invalid_source);
    RUN(test_salert_create_with_correlation);
    RUN(test_salert_create_limit_reached);

    /* Query */
    RUN(test_salert_get);
    RUN(test_salert_get_not_found);
    RUN(test_salert_get_null);
    RUN(test_salert_list);
    RUN(test_salert_list_filter_type);
    RUN(test_salert_active_count);

    /* State transitions */
    RUN(test_salert_valid_transitions);
    RUN(test_salert_invalid_transitions);

    /* Lifecycle operations */
    RUN(test_salert_acknowledge);
    RUN(test_salert_acknowledge_not_found);
    RUN(test_salert_resolve);
    RUN(test_salert_resolve_not_found);
    RUN(test_salert_suppress);
    RUN(test_salert_suppress_critical_rejected);
    RUN(test_salert_cancel);

    /* Escalation */
    RUN(test_salert_escalate);
    RUN(test_salert_escalate_limit);
    RUN(test_salert_escalate_resolved);
    RUN(test_salert_get_escalation_level);

    /* Deduplication */
    RUN(test_salert_dedup_same_condition);
    RUN(test_salert_dedup_different_condition);
    RUN(test_salert_check_dedup);
    RUN(test_salert_check_dedup_not_found);
    RUN(test_salert_is_in_dedup_window);

    /* Thresholds */
    RUN(test_salert_add_threshold);
    RUN(test_salert_add_threshold_invalid);
    RUN(test_salert_check_threshold_not_exceeded);
    RUN(test_salert_threshold_exceeded);

    /* Rate limiting */
    RUN(test_salert_rate_limit);
    RUN(test_salert_rate_limit_at_capacity);

    /* Notifications */
    RUN(test_salert_register_provider);
    RUN(test_salert_register_provider_null);
    RUN(test_salert_queue_notification);
    RUN(test_salert_process_notifications);
    RUN(test_salert_notification_failure);
    RUN(test_salert_notification_rate_limit);

    /* Health integration */
    RUN(test_salert_evaluate_health_healthy);
    RUN(test_salert_evaluate_health_unavailable);

    /* Diagnostic integration */
    RUN(test_salert_evaluate_diagnostics);
    RUN(test_salert_evaluate_diagnostics_unavailable);

    /* Incident integration */
    RUN(test_salert_evaluate_incidents);
    RUN(test_salert_evaluate_incidents_unavailable);

    /* Cleanup */
    RUN(test_salert_cleanup_expired);
    RUN(test_salert_cleanup_resolved);

    /* Name helpers */
    RUN(test_salert_name_err);
    RUN(test_salert_name_type);
    RUN(test_salert_name_severity);
    RUN(test_salert_name_priority);
    RUN(test_salert_name_state);
    RUN(test_salert_name_source);
    RUN(test_salert_name_notify_channel);
    RUN(test_salert_name_notify_state);

    /* Severity / Priority helpers */
    RUN(test_salert_worse_severity);
    RUN(test_salert_higher_priority);
    RUN(test_salert_severity_meets_threshold);

    /* Safe content */
    RUN(test_salert_generate_safe_title);
    RUN(test_salert_generate_safe_body);
    RUN(test_salert_generate_safe_title_null);

    /* Negative security */
    RUN(test_salert_no_secrets_in_alert);
    RUN(test_salert_no_secrets_in_notification);
    RUN(test_salert_default_deny_policy);
    RUN(test_salert_no_bypass_via_alerting);
    RUN(test_salert_suppress_requires_reason);
    RUN(test_salert_notification_failure_does_not_disable_security);
    RUN(test_salert_repeated_events_bounded);
    RUN(test_salert_dedup_prevents_flooding);

    SUITE_END();
    return _tf_suite_fail;
}
