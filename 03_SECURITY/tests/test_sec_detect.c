/*
 * test_sec_detect.c — Security Event Correlation & Threat Detection Tests (Step 31).
 */

#include "../../tests/test_framework.h"
#include "../sec_detect.h"
#include "../audit.h"
#include "../sec_alert.h"
#include "../incident.h"
#include <string.h>
#include <time.h>

/* ============================================================
 * TEST HELPERS
 * ============================================================ */

static ozayn_sdet_service_t _svc;
static ozayn_salert_service_t _alert_svc;
static ozayn_ir_service_t _ir_svc;
static ozayn_audit_service_t _au_svc;

static void _reset_all(void)
{
    memset(&_svc, 0, sizeof(_svc));
    memset(&_alert_svc, 0, sizeof(_alert_svc));
    memset(&_ir_svc, 0, sizeof(_ir_svc));
    memset(&_au_svc, 0, sizeof(_au_svc));
}

static void _init_svc(void)
{
    _reset_all();
    _au_svc.initialized = 1;
    _alert_svc.initialized = 1;
    _ir_svc.initialized = 1;

    ozayn_salert_service_config_t acfg;
    memset(&acfg, 0, sizeof(acfg));
    acfg.audit = &_au_svc;
    ozayn_salert_service_init(&_alert_svc, &acfg);

    ozayn_ir_service_config_t icfg;
    memset(&icfg, 0, sizeof(icfg));
    icfg.audit = &_au_svc;
    icfg.identity = NULL;
    ozayn_ir_service_init(&_ir_svc, &icfg);

    ozayn_sdet_service_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.alert_service = &_alert_svc;
    cfg.incident_service = &_ir_svc;
    cfg.audit = &_au_svc;
    ozayn_sdet_service_init(&_svc, &cfg);
}

static ozayn_sdet_event_t _make_event(ozayn_sdet_event_category_t cat,
                                       const char *identity,
                                       const char *resource)
{
    ozayn_sdet_event_t e;
    memset(&e, 0, sizeof(e));
    e.category = cat;
    e.timestamp = time(NULL);
    e.outcome_success = 1;
    e.severity = OZAYN_SDET_SEV_WARNING;
    if (identity) strncpy(e.identity_id, identity, sizeof(e.identity_id) - 1);
    if (resource) strncpy(e.resource_id, resource, sizeof(e.resource_id) - 1);
    return e;
}

static ozayn_sdet_pattern_t _make_pattern(const char *id,
                                           ozayn_sdet_pattern_type_t type,
                                           ozayn_sdet_event_category_t cat,
                                           int threshold,
                                           int window)
{
    ozayn_sdet_pattern_t p;
    memset(&p, 0, sizeof(p));
    strncpy(p.pattern_id, id, sizeof(p.pattern_id) - 1);
    p.enabled = 1;
    p.pattern_type = type;
    p.threshold_count = threshold;
    p.window_seconds = window;
    p.severity = OZAYN_SDET_SEV_WARNING;
    p.confidence = OZAYN_SDET_CONFIDENCE_HIGH;
    if (type == OZAYN_SDET_PATTERN_SINGLE ||
        type == OZAYN_SDET_PATTERN_THRESHOLD) {
        p.events[0] = cat;
        p.event_count = 1;
    }
    return p;
}

/* ============================================================
 * LIFECYCLE TESTS
 * ============================================================ */

TEST(test_sdet_init)
{
    _reset_all();
    ozayn_sdet_service_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    ASSERT_EQ(OZAYN_SDET_OK, ozayn_sdet_service_init(&_svc, &cfg));
    ASSERT(ozayn_sdet_service_is_initialized(&_svc));
    ozayn_sdet_service_shutdown(&_svc);
    ASSERT(!ozayn_sdet_service_is_initialized(&_svc));
    return 0;
}

TEST(test_sdet_init_null)
{
    ASSERT_EQ(OZAYN_SDET_ERR_NULL, ozayn_sdet_service_init(NULL, NULL));
    return 0;
}

TEST(test_sdet_init_double)
{
    _reset_all();
    ozayn_sdet_service_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    ASSERT_EQ(OZAYN_SDET_OK, ozayn_sdet_service_init(&_svc, &cfg));
    ASSERT_EQ(OZAYN_SDET_ERR_ALREADY_INITIALIZED,
              ozayn_sdet_service_init(&_svc, &cfg));
    ozayn_sdet_service_shutdown(&_svc);
    return 0;
}

TEST(test_sdet_shutdown_null)
{
    ozayn_sdet_service_shutdown(NULL);
    return 0;
}

TEST(test_sdet_global)
{
    ozayn_sdet_service_t *g = ozayn_sdet_get_global();
    ASSERT(g != NULL);
    return 0;
}

TEST(test_sdet_not_init)
{
    ozayn_sdet_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_sdet_event_t e = _make_event(OZAYN_SDET_EVT_AUTH_FAILURE, NULL, NULL);
    ASSERT_EQ(OZAYN_SDET_ERR_NOT_INITIALIZED, ozayn_sdet_process_event(&svc, &e));
    return 0;
}

/* ============================================================
 * NAME HELPER TESTS
 * ============================================================ */

TEST(test_sdet_err_names)
{
    ASSERT(strcmp(ozayn_sdet_err_name(OZAYN_SDET_OK), "OK") == 0);
    ASSERT(strcmp(ozayn_sdet_err_name(OZAYN_SDET_ERR_NULL), "NULL") == 0);
    ASSERT(strcmp(ozayn_sdet_err_name(OZAYN_SDET_ERR_NOT_INITIALIZED),
                  "NOT_INITIALIZED") == 0);
    ASSERT(strcmp(ozayn_sdet_err_name(OZAYN_SDET_ERR_INVALID_PARAM),
                  "INVALID_PARAM") == 0);
    ASSERT(strcmp(ozayn_sdet_err_name((ozayn_sdet_err_t)99), "UNKNOWN") == 0);
    return 0;
}

TEST(test_sdet_category_names)
{
    ASSERT(strcmp(ozayn_sdet_event_category_name(OZAYN_SDET_EVT_AUTH_SUCCESS),
                  "AUTH_SUCCESS") == 0);
    ASSERT(strcmp(ozayn_sdet_event_category_name(OZAYN_SDET_EVT_AUTH_FAILURE),
                  "AUTH_FAILURE") == 0);
    ASSERT(strcmp(ozayn_sdet_event_category_name(OZAYN_SDET_EVT_MFA_FAILURE),
                  "MFA_FAILURE") == 0);
    ASSERT(strcmp(ozayn_sdet_event_category_name((ozayn_sdet_event_category_t)99),
                  "UNKNOWN") == 0);
    return 0;
}

TEST(test_sdet_corr_state_names)
{
    ASSERT(strcmp(ozayn_sdet_correlation_state_name(OZAYN_SDET_CORR_NEW),
                  "NEW") == 0);
    ASSERT(strcmp(ozayn_sdet_correlation_state_name(OZAYN_SDET_CORR_MATCHED),
                  "MATCHED") == 0);
    ASSERT(strcmp(ozayn_sdet_correlation_state_name((ozayn_sdet_correlation_state_t)99),
                  "UNKNOWN") == 0);
    return 0;
}

TEST(test_sdet_pattern_type_names)
{
    ASSERT(strcmp(ozayn_sdet_pattern_type_name(OZAYN_SDET_PATTERN_SINGLE),
                  "SINGLE") == 0);
    ASSERT(strcmp(ozayn_sdet_pattern_type_name(OZAYN_SDET_PATTERN_THRESHOLD),
                  "THRESHOLD") == 0);
    ASSERT(strcmp(ozayn_sdet_pattern_type_name((ozayn_sdet_pattern_type_t)99),
                  "UNKNOWN") == 0);
    return 0;
}

TEST(test_sdet_confidence_names)
{
    ASSERT(strcmp(ozayn_sdet_confidence_name(OZAYN_SDET_CONFIDENCE_LOW),
                  "LOW") == 0);
    ASSERT(strcmp(ozayn_sdet_confidence_name(OZAYN_SDET_CONFIDENCE_HIGH),
                  "HIGH") == 0);
    ASSERT(strcmp(ozayn_sdet_confidence_name((ozayn_sdet_confidence_t)99),
                  "UNKNOWN") == 0);
    return 0;
}

TEST(test_sdet_finding_state_names)
{
    ASSERT(strcmp(ozayn_sdet_finding_state_name(OZAYN_SDET_FINDING_DETECTED),
                  "DETECTED") == 0);
    ASSERT(strcmp(ozayn_sdet_finding_state_name(OZAYN_SDET_FINDING_CONFIRMED_THREAT),
                  "CONFIRMED_THREAT") == 0);
    ASSERT(strcmp(ozayn_sdet_finding_state_name((ozayn_sdet_finding_state_t)99),
                  "UNKNOWN") == 0);
    return 0;
}

TEST(test_sdet_severity_names)
{
    ASSERT(strcmp(ozayn_sdet_severity_name(OZAYN_SDET_SEV_INFO), "INFO") == 0);
    ASSERT(strcmp(ozayn_sdet_severity_name(OZAYN_SDET_SEV_CRITICAL),
                  "CRITICAL") == 0);
    ASSERT(strcmp(ozayn_sdet_severity_name((ozayn_sdet_severity_t)99),
                  "UNKNOWN") == 0);
    return 0;
}

TEST(test_sdet_severity_conversions)
{
    ASSERT_EQ(0, ozayn_sdet_severity_to_audit_severity(OZAYN_SDET_SEV_INFO));
    ASSERT_EQ(4, ozayn_sdet_severity_to_audit_severity(OZAYN_SDET_SEV_CRITICAL));
    ASSERT_EQ(0, ozayn_sdet_severity_to_salert_severity(OZAYN_SDET_SEV_INFO));
    ASSERT_EQ(4, ozayn_sdet_severity_to_salert_severity(OZAYN_SDET_SEV_CRITICAL));
    return 0;
}

/* ============================================================
 * EVENT PROCESSING TESTS
 * ============================================================ */

TEST(test_sdet_process_event)
{
    _init_svc();
    ozayn_sdet_event_t e = _make_event(OZAYN_SDET_EVT_AUTH_FAILURE,
                                       "user1", NULL);
    ASSERT_EQ(OZAYN_SDET_OK, ozayn_sdet_process_event(&_svc, &e));
    ASSERT_EQ(1, ozayn_sdet_event_count(&_svc));
    ASSERT(_svc.total_events_received == 1);
    return 0;
}

TEST(test_sdet_process_event_null)
{
    _init_svc();
    ASSERT_EQ(OZAYN_SDET_ERR_NULL, ozayn_sdet_process_event(NULL, NULL));
    ASSERT_EQ(OZAYN_SDET_ERR_NULL,
              ozayn_sdet_process_event(&_svc, NULL));
    return 0;
}

TEST(test_sdet_process_event_not_init)
{
    ozayn_sdet_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_sdet_event_t e = _make_event(OZAYN_SDET_EVT_AUTH_FAILURE, NULL, NULL);
    ASSERT_EQ(OZAYN_SDET_ERR_NOT_INITIALIZED,
              ozayn_sdet_process_event(&svc, &e));
    return 0;
}

TEST(test_sdet_process_event_policy_disabled)
{
    _init_svc();
    _svc.policy.enabled = 0;
    ozayn_sdet_event_t e = _make_event(OZAYN_SDET_EVT_AUTH_FAILURE, NULL, NULL);
    ASSERT_EQ(OZAYN_SDET_ERR_POLICY_REJECTED,
              ozayn_sdet_process_event(&_svc, &e));
    return 0;
}

TEST(test_sdet_process_multiple_events)
{
    _init_svc();
    for (int i = 0; i < 10; i++) {
        ozayn_sdet_event_t e = _make_event(OZAYN_SDET_EVT_AUTH_FAILURE,
                                            "user1", NULL);
        ozayn_sdet_process_event(&_svc, &e);
    }
    ASSERT_EQ(10, ozayn_sdet_event_count(&_svc));
    ASSERT(_svc.total_events_received == 10);
    return 0;
}

TEST(test_sdet_process_event_ring_buffer)
{
    _init_svc();
    for (int i = 0; i < OZAYN_SDET_MAX_EVENTS + 5; i++) {
        ozayn_sdet_event_t e = _make_event(OZAYN_SDET_EVT_AUTH_FAILURE,
                                            "user1", NULL);
        ozayn_sdet_process_event(&_svc, &e);
    }
    ASSERT_EQ(OZAYN_SDET_MAX_EVENTS, ozayn_sdet_event_count(&_svc));
    return 0;
}

TEST(test_sdet_process_event_generates_id)
{
    _init_svc();
    ozayn_sdet_event_t e = _make_event(OZAYN_SDET_EVT_AUTH_FAILURE,
                                       "user1", NULL);
    e.event_id[0] = '\0';
    ASSERT_EQ(OZAYN_SDET_OK, ozayn_sdet_process_event(&_svc, &e));
    ASSERT(_svc.events[0].event_id[0] != '\0');
    return 0;
}

TEST(test_sdet_process_event_sets_timestamp)
{
    _init_svc();
    ozayn_sdet_event_t e = _make_event(OZAYN_SDET_EVT_AUTH_FAILURE,
                                       "user1", NULL);
    e.timestamp = 0;
    ASSERT_EQ(OZAYN_SDET_OK, ozayn_sdet_process_event(&_svc, &e));
    ASSERT(_svc.events[0].timestamp > 0);
    return 0;
}

/* ============================================================
 * NORMALIZE AUDIT EVENT TESTS
 * ============================================================ */

TEST(test_sdet_normalize_audit_event)
{
    ozayn_audit_event_t ae;
    memset(&ae, 0, sizeof(ae));
    strncpy(ae.event_id, "EVT-1", sizeof(ae.event_id) - 1);
    ae.event_type = OZAYN_AUDIT_AUTH_FAILED;
    ae.outcome = OZAYN_AUDIT_OUTCOME_FAILURE;
    ae.severity = OZAYN_AUDIT_SEV_WARNING;
    strncpy(ae.identity_id, "user1", sizeof(ae.identity_id) - 1);
    ae.timestamp = 12345;

    ozayn_sdet_event_t de;
    ASSERT_EQ(OZAYN_SDET_OK,
              ozayn_sdet_normalize_audit_event(&ae, &de));
    ASSERT(strcmp(de.event_id, "EVT-1") == 0);
    ASSERT_EQ(OZAYN_SDET_EVT_AUTH_FAILURE, de.category);
    ASSERT_EQ(12345, de.timestamp);
    ASSERT(!de.outcome_success);
    ASSERT(strcmp(de.identity_id, "user1") == 0);
    return 0;
}

TEST(test_sdet_normalize_audit_event_null)
{
    ASSERT_EQ(OZAYN_SDET_ERR_NULL,
              ozayn_sdet_normalize_audit_event(NULL, NULL));
    ozayn_audit_event_t ae;
    memset(&ae, 0, sizeof(ae));
    ASSERT_EQ(OZAYN_SDET_ERR_NULL,
              ozayn_sdet_normalize_audit_event(&ae, NULL));
    return 0;
}

TEST(test_sdet_normalize_audit_event_types)
{
    struct {
        ozayn_audit_event_type_t audit_type;
        ozayn_sdet_event_category_t expected;
    } cases[] = {
        {OZAYN_AUDIT_AUTH_SUCCEEDED, OZAYN_SDET_EVT_AUTH_SUCCESS},
        {OZAYN_AUDIT_AUTH_FAILED, OZAYN_SDET_EVT_AUTH_FAILURE},
        {OZAYN_AUDIT_RATE_LIMITED, OZAYN_SDET_EVT_AUTH_RATE_LIMIT},
        {OZAYN_AUDIT_TEMPORARILY_BLOCKED, OZAYN_SDET_EVT_AUTH_BLOCKED},
        {OZAYN_AUDIT_MFA_COMPLETED, OZAYN_SDET_EVT_MFA_SUCCESS},
        {OZAYN_AUDIT_MFA_FAILED, OZAYN_SDET_EVT_MFA_FAILURE},
        {OZAYN_AUDIT_MFA_BLOCKED, OZAYN_SDET_EVT_MFA_BLOCKED},
        {OZAYN_AUDIT_SESSION_CREATED, OZAYN_SDET_EVT_SESSION_CREATED},
        {OZAYN_AUDIT_SESSION_EXPIRED, OZAYN_SDET_EVT_SESSION_FAILED},
        {OZAYN_AUDIT_SESSION_TERMINATED, OZAYN_SDET_EVT_SESSION_TERMINATED},
        {OZAYN_AUDIT_AUTHZ_ALLOWED, OZAYN_SDET_EVT_AUTHZ_ALLOWED},
        {OZAYN_AUDIT_AUTHZ_DENIED, OZAYN_SDET_EVT_AUTHZ_DENIED},
    };
    for (int i = 0; i < (int)(sizeof(cases) / sizeof(cases[0])); i++) {
        ozayn_audit_event_t ae;
        memset(&ae, 0, sizeof(ae));
        ae.event_type = cases[i].audit_type;
        ae.outcome = OZAYN_AUDIT_OUTCOME_SUCCESS;
        ozayn_sdet_event_t de;
        ozayn_sdet_normalize_audit_event(&ae, &de);
        ASSERT_EQ(cases[i].expected, de.category);
    }
    return 0;
}

/* ============================================================
 * PATTERN MANAGEMENT TESTS
 * ============================================================ */

TEST(test_sdet_register_pattern)
{
    _init_svc();
    ozayn_sdet_pattern_t p = _make_pattern("PAT-1",
        OZAYN_SDET_PATTERN_SINGLE, OZAYN_SDET_EVT_AUTH_FAILURE, 0, 0);
    ASSERT_EQ(OZAYN_SDET_OK, ozayn_sdet_register_pattern(&_svc, &p));
    ASSERT_EQ(1, ozayn_sdet_pattern_count(&_svc));
    return 0;
}

TEST(test_sdet_register_pattern_null)
{
    _init_svc();
    ASSERT_EQ(OZAYN_SDET_ERR_NULL,
              ozayn_sdet_register_pattern(NULL, NULL));
    return 0;
}

TEST(test_sdet_register_pattern_not_init)
{
    ozayn_sdet_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_sdet_pattern_t p = _make_pattern("PAT-1",
        OZAYN_SDET_PATTERN_SINGLE, OZAYN_SDET_EVT_AUTH_FAILURE, 0, 0);
    ASSERT_EQ(OZAYN_SDET_ERR_NOT_INITIALIZED,
              ozayn_sdet_register_pattern(&svc, &p));
    return 0;
}

TEST(test_sdet_register_pattern_no_id)
{
    _init_svc();
    ozayn_sdet_pattern_t p = _make_pattern("",
        OZAYN_SDET_PATTERN_SINGLE, OZAYN_SDET_EVT_AUTH_FAILURE, 0, 0);
    ASSERT_EQ(OZAYN_SDET_ERR_INVALID_PARAM,
              ozayn_sdet_register_pattern(&_svc, &p));
    return 0;
}

TEST(test_sdet_register_pattern_duplicate)
{
    _init_svc();
    ozayn_sdet_pattern_t p = _make_pattern("DUP-1",
        OZAYN_SDET_PATTERN_SINGLE, OZAYN_SDET_EVT_AUTH_FAILURE, 0, 0);
    ASSERT_EQ(OZAYN_SDET_OK, ozayn_sdet_register_pattern(&_svc, &p));
    ASSERT_EQ(OZAYN_SDET_ERR_PATTERN_INVALID,
              ozayn_sdet_register_pattern(&_svc, &p));
    return 0;
}

TEST(test_sdet_unregister_pattern)
{
    _init_svc();
    ozayn_sdet_pattern_t p = _make_pattern("RM-1",
        OZAYN_SDET_PATTERN_SINGLE, OZAYN_SDET_EVT_AUTH_FAILURE, 0, 0);
    ozayn_sdet_register_pattern(&_svc, &p);
    ASSERT_EQ(OZAYN_SDET_OK, ozayn_sdet_unregister_pattern(&_svc, "RM-1"));
    ASSERT_EQ(0, ozayn_sdet_pattern_count(&_svc));
    return 0;
}

TEST(test_sdet_unregister_pattern_not_found)
{
    _init_svc();
    ASSERT_EQ(OZAYN_SDET_ERR_PATTERN_NOT_FOUND,
              ozayn_sdet_unregister_pattern(&_svc, "NOPE"));
    return 0;
}

TEST(test_sdet_unregister_pattern_null)
{
    _init_svc();
    ASSERT_EQ(OZAYN_SDET_ERR_INVALID_PARAM,
              ozayn_sdet_unregister_pattern(&_svc, NULL));
    return 0;
}

TEST(test_sdet_get_pattern)
{
    _init_svc();
    ozayn_sdet_pattern_t p = _make_pattern("GET-1",
        OZAYN_SDET_PATTERN_SINGLE, OZAYN_SDET_EVT_AUTH_FAILURE, 0, 0);
    ozayn_sdet_register_pattern(&_svc, &p);
    const ozayn_sdet_pattern_t *got = ozayn_sdet_get_pattern(&_svc, "GET-1");
    ASSERT(got != NULL);
    ASSERT(strcmp(got->pattern_id, "GET-1") == 0);
    ASSERT(ozayn_sdet_get_pattern(&_svc, "NOPE") == NULL);
    return 0;
}

TEST(test_sdet_enable_pattern)
{
    _init_svc();
    ozayn_sdet_pattern_t p = _make_pattern("EN-1",
        OZAYN_SDET_PATTERN_SINGLE, OZAYN_SDET_EVT_AUTH_FAILURE, 0, 0);
    ozayn_sdet_register_pattern(&_svc, &p);
    ASSERT_EQ(OZAYN_SDET_OK, ozayn_sdet_enable_pattern(&_svc, "EN-1", 0));
    const ozayn_sdet_pattern_t *got = ozayn_sdet_get_pattern(&_svc, "EN-1");
    ASSERT(!got->enabled);
    ASSERT_EQ(OZAYN_SDET_OK, ozayn_sdet_enable_pattern(&_svc, "EN-1", 1));
    got = ozayn_sdet_get_pattern(&_svc, "EN-1");
    ASSERT(got->enabled);
    return 0;
}

TEST(test_sdet_enable_pattern_not_found)
{
    _init_svc();
    ASSERT_EQ(OZAYN_SDET_ERR_PATTERN_NOT_FOUND,
              ozayn_sdet_enable_pattern(&_svc, "NOPE", 1));
    return 0;
}

/* ============================================================
 * SINGLE PATTERN EVALUATION TESTS
 * ============================================================ */

TEST(test_sdet_evaluate_single_match)
{
    _init_svc();
    ozayn_sdet_pattern_t p = _make_pattern("S-1",
        OZAYN_SDET_PATTERN_SINGLE, OZAYN_SDET_EVT_AUTH_FAILURE, 0, 0);
    ozayn_sdet_register_pattern(&_svc, &p);

    ozayn_sdet_event_t e = _make_event(OZAYN_SDET_EVT_AUTH_FAILURE,
                                       "user1", NULL);
    ASSERT_EQ(OZAYN_SDET_OK, ozayn_sdet_evaluate_single(&_svc, &e));
    ASSERT(_svc.total_patterns_evaluated == 1);
    ASSERT(_svc.total_findings_created >= 1);
    return 0;
}

TEST(test_sdet_evaluate_single_no_match)
{
    _init_svc();
    ozayn_sdet_pattern_t p = _make_pattern("S-2",
        OZAYN_SDET_PATTERN_SINGLE, OZAYN_SDET_EVT_AUTH_FAILURE, 0, 0);
    ozayn_sdet_register_pattern(&_svc, &p);

    ozayn_sdet_event_t e = _make_event(OZAYN_SDET_EVT_AUTH_SUCCESS,
                                       "user1", NULL);
    ASSERT_EQ(OZAYN_SDET_OK, ozayn_sdet_evaluate_single(&_svc, &e));
    ASSERT(_svc.total_patterns_evaluated == 0);
    return 0;
}

TEST(test_sdet_evaluate_single_disabled_pattern)
{
    _init_svc();
    ozayn_sdet_pattern_t p = _make_pattern("S-3",
        OZAYN_SDET_PATTERN_SINGLE, OZAYN_SDET_EVT_AUTH_FAILURE, 0, 0);
    p.enabled = 0;
    ozayn_sdet_register_pattern(&_svc, &p);

    ozayn_sdet_event_t e = _make_event(OZAYN_SDET_EVT_AUTH_FAILURE,
                                       "user1", NULL);
    ASSERT_EQ(OZAYN_SDET_OK, ozayn_sdet_evaluate_single(&_svc, &e));
    ASSERT(_svc.total_patterns_evaluated == 0);
    return 0;
}

TEST(test_sdet_evaluate_single_creates_correlation)
{
    _init_svc();
    ozayn_sdet_pattern_t p = _make_pattern("S-4",
        OZAYN_SDET_PATTERN_SINGLE, OZAYN_SDET_EVT_AUTH_FAILURE, 0, 0);
    ozayn_sdet_register_pattern(&_svc, &p);

    ozayn_sdet_event_t e = _make_event(OZAYN_SDET_EVT_AUTH_FAILURE,
                                       "user1", NULL);
    ozayn_sdet_evaluate_single(&_svc, &e);
    ASSERT(_svc.total_correlations_created >= 1);
    return 0;
}

TEST(test_sdet_evaluate_single_null)
{
    _init_svc();
    ASSERT_EQ(OZAYN_SDET_ERR_NULL,
              ozayn_sdet_evaluate_single(NULL, NULL));
    return 0;
}

/* ============================================================
 * THRESHOLD PATTERN EVALUATION TESTS
 * ============================================================ */

TEST(test_sdet_evaluate_threshold_match)
{
    _init_svc();
    ozayn_sdet_pattern_t p = _make_pattern("T-1",
        OZAYN_SDET_PATTERN_THRESHOLD, OZAYN_SDET_EVT_AUTH_FAILURE, 3, 60);
    ozayn_sdet_register_pattern(&_svc, &p);

    for (int i = 0; i < 3; i++) {
        ozayn_sdet_event_t e = _make_event(OZAYN_SDET_EVT_AUTH_FAILURE,
                                            "user1", NULL);
        ozayn_sdet_process_event(&_svc, &e);
    }
    ASSERT_EQ(OZAYN_SDET_OK, ozayn_sdet_evaluate_threshold(&_svc, &p));
    ASSERT(_svc.total_findings_created >= 1);
    return 0;
}

TEST(test_sdet_evaluate_threshold_not_met)
{
    _init_svc();
    ozayn_sdet_pattern_t p = _make_pattern("T-2",
        OZAYN_SDET_PATTERN_THRESHOLD, OZAYN_SDET_EVT_AUTH_FAILURE, 5, 60);
    ozayn_sdet_register_pattern(&_svc, &p);

    for (int i = 0; i < 3; i++) {
        ozayn_sdet_event_t e = _make_event(OZAYN_SDET_EVT_AUTH_FAILURE,
                                            "user1", NULL);
        ozayn_sdet_process_event(&_svc, &e);
    }
    uint64_t before = _svc.total_findings_created;
    ASSERT_EQ(OZAYN_SDET_OK, ozayn_sdet_evaluate_threshold(&_svc, &p));
    ASSERT(_svc.total_findings_created == before);
    return 0;
}

TEST(test_sdet_evaluate_threshold_null)
{
    _init_svc();
    ASSERT_EQ(OZAYN_SDET_ERR_NULL,
              ozayn_sdet_evaluate_threshold(NULL, NULL));
    return 0;
}

/* ============================================================
 * SEQUENCE PATTERN EVALUATION TESTS
 * ============================================================ */

TEST(test_sdet_evaluate_sequence_match)
{
    _init_svc();
    ozayn_sdet_pattern_t p = _make_pattern("SEQ-1",
        OZAYN_SDET_PATTERN_SEQUENCE, OZAYN_SDET_EVT_AUTH_FAILURE, 0, 60);
    p.sequence[0] = OZAYN_SDET_EVT_AUTH_FAILURE;
    p.sequence[1] = OZAYN_SDET_EVT_AUTH_BLOCKED;
    p.sequence_count = 2;
    ozayn_sdet_register_pattern(&_svc, &p);

    ozayn_sdet_event_t e1 = _make_event(OZAYN_SDET_EVT_AUTH_FAILURE,
                                         "user1", NULL);
    ozayn_sdet_process_event(&_svc, &e1);
    ozayn_sdet_event_t e2 = _make_event(OZAYN_SDET_EVT_AUTH_BLOCKED,
                                         "user1", NULL);
    ozayn_sdet_process_event(&_svc, &e2);

    ASSERT_EQ(OZAYN_SDET_OK, ozayn_sdet_evaluate_sequence(&_svc, &p));
    ASSERT(_svc.total_findings_created >= 1);
    return 0;
}

TEST(test_sdet_evaluate_sequence_not_met)
{
    _init_svc();
    ozayn_sdet_pattern_t p = _make_pattern("SEQ-2",
        OZAYN_SDET_PATTERN_SEQUENCE, OZAYN_SDET_EVT_AUTH_FAILURE, 0, 60);
    p.sequence[0] = OZAYN_SDET_EVT_AUTH_FAILURE;
    p.sequence[1] = OZAYN_SDET_EVT_AUTH_BLOCKED;
    p.sequence_count = 2;
    ozayn_sdet_register_pattern(&_svc, &p);

    ozayn_sdet_event_t e = _make_event(OZAYN_SDET_EVT_AUTH_FAILURE,
                                       "user1", NULL);
    ozayn_sdet_process_event(&_svc, &e);
    uint64_t before = _svc.total_findings_created;
    ASSERT_EQ(OZAYN_SDET_OK, ozayn_sdet_evaluate_sequence(&_svc, &p));
    ASSERT(_svc.total_findings_created == before);
    return 0;
}

TEST(test_sdet_evaluate_sequence_null)
{
    _init_svc();
    ASSERT_EQ(OZAYN_SDET_ERR_NULL,
              ozayn_sdet_evaluate_sequence(NULL, NULL));
    return 0;
}

/* ============================================================
 * EVALUATE PATTERNS TESTS
 * ============================================================ */

TEST(test_sdet_evaluate_patterns)
{
    _init_svc();
    ozayn_sdet_pattern_t p = _make_pattern("EP-1",
        OZAYN_SDET_PATTERN_SINGLE, OZAYN_SDET_EVT_AUTH_FAILURE, 0, 0);
    ozayn_sdet_register_pattern(&_svc, &p);

    ozayn_sdet_event_t e = _make_event(OZAYN_SDET_EVT_AUTH_FAILURE,
                                       "user1", NULL);
    ozayn_sdet_process_event(&_svc, &e);

    ASSERT_EQ(OZAYN_SDET_OK, ozayn_sdet_evaluate_patterns(&_svc));
    return 0;
}

TEST(test_sdet_evaluate_patterns_null)
{
    ASSERT_EQ(OZAYN_SDET_ERR_NULL, ozayn_sdet_evaluate_patterns(NULL));
    return 0;
}

TEST(test_sdet_evaluate_patterns_not_init)
{
    ozayn_sdet_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ASSERT_EQ(OZAYN_SDET_ERR_NOT_INITIALIZED, ozayn_sdet_evaluate_patterns(&svc));
    return 0;
}

/* ============================================================
 * CORRELATION TESTS
 * ============================================================ */

TEST(test_sdet_create_correlation)
{
    _init_svc();
    ozayn_sdet_event_t e = _make_event(OZAYN_SDET_EVT_AUTH_FAILURE,
                                       "user1", "res1");
    ozayn_sdet_correlation_t *c = NULL;
    ASSERT_EQ(OZAYN_SDET_OK,
              ozayn_sdet_create_correlation(&_svc, &e, 0, &c));
    ASSERT(c != NULL);
    ASSERT(c->corr_id[0] != '\0');
    ASSERT_EQ(OZAYN_SDET_CORR_NEW, c->state);
    ASSERT_EQ(1, c->event_count);
    ASSERT(strcmp(c->identity_id, "user1") == 0);
    return 0;
}

TEST(test_sdet_create_correlation_null)
{
    _init_svc();
    ozayn_sdet_event_t e = _make_event(OZAYN_SDET_EVT_AUTH_FAILURE,
                                       NULL, NULL);
    ASSERT_EQ(OZAYN_SDET_ERR_NULL,
              ozayn_sdet_create_correlation(NULL, &e, 0, NULL));
    ASSERT_EQ(OZAYN_SDET_ERR_NULL,
              ozayn_sdet_create_correlation(&_svc, &e, 0, NULL));
    return 0;
}

TEST(test_sdet_correlation_limit)
{
    _init_svc();
    for (int i = 0; i < OZAYN_SDET_MAX_CORRELATIONS; i++) {
        ozayn_sdet_event_t e = _make_event(OZAYN_SDET_EVT_AUTH_FAILURE,
                                            "user1", NULL);
        e.timestamp = time(NULL) + i;
        ozayn_sdet_correlation_t *c = NULL;
        ozayn_sdet_create_correlation(&_svc, &e, 0, &c);
    }
    ozayn_sdet_event_t e = _make_event(OZAYN_SDET_EVT_AUTH_FAILURE,
                                       "user1", NULL);
    ozayn_sdet_correlation_t *c = NULL;
    ASSERT_EQ(OZAYN_SDET_ERR_CORRELATION_LIMIT,
              ozayn_sdet_create_correlation(&_svc, &e, 0, &c));
    return 0;
}

TEST(test_sdet_find_correlation)
{
    _init_svc();
    ozayn_sdet_event_t e = _make_event(OZAYN_SDET_EVT_AUTH_FAILURE,
                                       "user1", NULL);
    ozayn_sdet_correlation_t *c = NULL;
    ozayn_sdet_create_correlation(&_svc, &e, 0, &c);

    ozayn_sdet_correlation_t *found = ozayn_sdet_find_correlation(
        &_svc, "user1", NULL, 0);
    ASSERT(found != NULL);
    ASSERT(ozayn_sdet_find_correlation(&_svc, "nobody", NULL, 0) == NULL);
    return 0;
}

TEST(test_sdet_expire_correlations)
{
    _init_svc();
    ozayn_sdet_pattern_t p = _make_pattern("EC-1",
        OZAYN_SDET_PATTERN_THRESHOLD, OZAYN_SDET_EVT_AUTH_FAILURE, 3, 1);
    ozayn_sdet_register_pattern(&_svc, &p);

    ozayn_sdet_event_t e = _make_event(OZAYN_SDET_EVT_AUTH_FAILURE,
                                       "user1", NULL);
    e.timestamp = time(NULL) - 10;
    ozayn_sdet_correlation_t *c = NULL;
    ozayn_sdet_create_correlation(&_svc, &e, 0, &c);
    c->window_start = time(NULL) - 10;

    ASSERT_EQ(OZAYN_SDET_OK, ozayn_sdet_expire_correlations(&_svc));
    return 0;
}

TEST(test_sdet_correlation_count)
{
    _init_svc();
    ASSERT_EQ(0, ozayn_sdet_correlation_count(&_svc));
    ozayn_sdet_event_t e = _make_event(OZAYN_SDET_EVT_AUTH_FAILURE,
                                       "user1", NULL);
    ozayn_sdet_correlation_t *c = NULL;
    ozayn_sdet_create_correlation(&_svc, &e, 0, &c);
    ASSERT_EQ(1, ozayn_sdet_correlation_count(&_svc));
    return 0;
}

TEST(test_sdet_correlation_count_null)
{
    ASSERT_EQ(0, ozayn_sdet_correlation_count(NULL));
    return 0;
}

/* ============================================================
 * FINDING TESTS
 * ============================================================ */

TEST(test_sdet_create_finding)
{
    _init_svc();
    ozayn_sdet_pattern_t p = _make_pattern("F-1",
        OZAYN_SDET_PATTERN_SINGLE, OZAYN_SDET_EVT_AUTH_FAILURE, 0, 0);
    ozayn_sdet_finding_t *f = NULL;
    ASSERT_EQ(OZAYN_SDET_OK,
              ozayn_sdet_create_finding(&_svc, &p, NULL, &f));
    ASSERT(f != NULL);
    ASSERT(f->finding_id[0] != '\0');
    ASSERT(strcmp(f->pattern_id, "F-1") == 0);
    ASSERT_EQ(OZAYN_SDET_FINDING_DETECTED, f->state);
    ASSERT_EQ(1, _svc.total_findings_created);
    return 0;
}

TEST(test_sdet_create_finding_null)
{
    _init_svc();
    ASSERT_EQ(OZAYN_SDET_ERR_NULL,
              ozayn_sdet_create_finding(NULL, NULL, NULL, NULL));
    ozayn_sdet_pattern_t p = _make_pattern("F-2",
        OZAYN_SDET_PATTERN_SINGLE, OZAYN_SDET_EVT_AUTH_FAILURE, 0, 0);
    ASSERT_EQ(OZAYN_SDET_ERR_NULL,
              ozayn_sdet_create_finding(&_svc, &p, NULL, NULL));
    return 0;
}

TEST(test_sdet_get_finding)
{
    _init_svc();
    ozayn_sdet_pattern_t p = _make_pattern("GF-1",
        OZAYN_SDET_PATTERN_SINGLE, OZAYN_SDET_EVT_AUTH_FAILURE, 0, 0);
    ozayn_sdet_finding_t *f = NULL;
    ozayn_sdet_create_finding(&_svc, &p, NULL, &f);
    ozayn_sdet_finding_t *got = ozayn_sdet_get_finding(&_svc, f->finding_id);
    ASSERT(got != NULL);
    ASSERT(strcmp(got->finding_id, f->finding_id) == 0);
    ASSERT(ozayn_sdet_get_finding(&_svc, "NOPE") == NULL);
    return 0;
}

TEST(test_sdet_finding_count)
{
    _init_svc();
    ASSERT_EQ(0, ozayn_sdet_finding_count(&_svc));
    ozayn_sdet_pattern_t p = _make_pattern("FC-1",
        OZAYN_SDET_PATTERN_SINGLE, OZAYN_SDET_EVT_AUTH_FAILURE, 0, 0);
    ozayn_sdet_finding_t *f = NULL;
    ozayn_sdet_create_finding(&_svc, &p, NULL, &f);
    ASSERT_EQ(1, ozayn_sdet_finding_count(&_svc));
    return 0;
}

TEST(test_sdet_list_findings)
{
    _init_svc();
    ozayn_sdet_pattern_t p = _make_pattern("LF-1",
        OZAYN_SDET_PATTERN_SINGLE, OZAYN_SDET_EVT_AUTH_FAILURE, 0, 0);
    ozayn_sdet_finding_t *f = NULL;
    ozayn_sdet_create_finding(&_svc, &p, NULL, &f);

    ozayn_sdet_finding_t *list[16];
    int count = ozayn_sdet_list_findings(&_svc, -1, list, 16);
    ASSERT(count >= 1);
    return 0;
}

TEST(test_sdet_list_findings_filter)
{
    _init_svc();
    ozayn_sdet_pattern_t p = _make_pattern("LFF-1",
        OZAYN_SDET_PATTERN_SINGLE, OZAYN_SDET_EVT_AUTH_FAILURE, 0, 0);
    ozayn_sdet_finding_t *f = NULL;
    ozayn_sdet_create_finding(&_svc, &p, NULL, &f);

    ozayn_sdet_finding_t *list[16];
    int count = ozayn_sdet_list_findings(&_svc,
        OZAYN_SDET_FINDING_DETECTED, list, 16);
    ASSERT(count >= 1);
    count = ozayn_sdet_list_findings(&_svc,
        OZAYN_SDET_FINDING_CONFIRMED_THREAT, list, 16);
    ASSERT_EQ(0, count);
    return 0;
}

TEST(test_sdet_finding_set_state)
{
    _init_svc();
    ozayn_sdet_pattern_t p = _make_pattern("FS-1",
        OZAYN_SDET_PATTERN_SINGLE, OZAYN_SDET_EVT_AUTH_FAILURE, 0, 0);
    ozayn_sdet_finding_t *f = NULL;
    ozayn_sdet_create_finding(&_svc, &p, NULL, &f);

    ASSERT_EQ(OZAYN_SDET_OK,
              ozayn_sdet_finding_set_state(&_svc, f->finding_id,
                  OZAYN_SDET_FINDING_INVESTIGATING));
    ASSERT_EQ(OZAYN_SDET_FINDING_INVESTIGATING, f->state);
    return 0;
}

TEST(test_sdet_finding_set_state_invalid)
{
    _init_svc();
    ozayn_sdet_pattern_t p = _make_pattern("FSI-1",
        OZAYN_SDET_PATTERN_SINGLE, OZAYN_SDET_EVT_AUTH_FAILURE, 0, 0);
    ozayn_sdet_finding_t *f = NULL;
    ozayn_sdet_create_finding(&_svc, &p, NULL, &f);

    ozayn_sdet_finding_set_state(&_svc, f->finding_id,
        OZAYN_SDET_FINDING_EXPIRED);

    ASSERT_EQ(OZAYN_SDET_ERR_STATE_TRANSITION,
              ozayn_sdet_finding_set_state(&_svc, f->finding_id,
                  OZAYN_SDET_FINDING_INVESTIGATING));
    return 0;
}

TEST(test_sdet_finding_set_state_not_found)
{
    _init_svc();
    ASSERT_EQ(OZAYN_SDET_ERR_NOT_FOUND,
              ozayn_sdet_finding_set_state(&_svc, "NOPE",
                  OZAYN_SDET_FINDING_INVESTIGATING));
    return 0;
}

TEST(test_sdet_finding_set_state_confirmed)
{
    _init_svc();
    ozayn_sdet_pattern_t p = _make_pattern("FSC-1",
        OZAYN_SDET_PATTERN_SINGLE, OZAYN_SDET_EVT_AUTH_FAILURE, 0, 0);
    ozayn_sdet_finding_t *f = NULL;
    ozayn_sdet_create_finding(&_svc, &p, NULL, &f);

    ASSERT_EQ(OZAYN_SDET_OK,
              ozayn_sdet_finding_set_state(&_svc, f->finding_id,
                  OZAYN_SDET_FINDING_INVESTIGATING));
    ASSERT_EQ(OZAYN_SDET_OK,
              ozayn_sdet_finding_set_state(&_svc, f->finding_id,
                  OZAYN_SDET_FINDING_CONFIRMED_THREAT));
    ASSERT_EQ(OZAYN_SDET_FINDING_CONFIRMED_THREAT, f->state);
    return 0;
}

TEST(test_sdet_cleanup_expired_findings)
{
    _init_svc();
    ozayn_sdet_pattern_t p = _make_pattern("CLN-1",
        OZAYN_SDET_PATTERN_SINGLE, OZAYN_SDET_EVT_AUTH_FAILURE, 0, 0);
    ozayn_sdet_finding_t *f = NULL;
    ozayn_sdet_create_finding(&_svc, &p, NULL, &f);
    f->detection_time = 1;

    int cleaned = ozayn_sdet_cleanup_expired_findings(&_svc);
    ASSERT(cleaned >= 1);
    return 0;
}

/* ============================================================
 * DEDUPLICATION TESTS
 * ============================================================ */

TEST(test_sdet_finding_is_duplicate)
{
    _init_svc();
    ozayn_sdet_pattern_t p = _make_pattern("DED-1",
        OZAYN_SDET_PATTERN_SINGLE, OZAYN_SDET_EVT_AUTH_FAILURE, 0, 0);
    ozayn_sdet_finding_t *f = NULL;
    ozayn_sdet_create_finding(&_svc, &p, NULL, &f);
    strncpy(f->identity_id, "user1", sizeof(f->identity_id) - 1);

    ASSERT(ozayn_sdet_finding_is_duplicate(&_svc, "DED-1", "user1", NULL));
    ASSERT(!ozayn_sdet_finding_is_duplicate(&_svc, "DED-1", "user2", NULL));
    ASSERT(!ozayn_sdet_finding_is_duplicate(&_svc, "DED-X", "user1", NULL));
    return 0;
}

TEST(test_sdet_finding_is_duplicate_expired)
{
    _init_svc();
    ozayn_sdet_pattern_t p = _make_pattern("DED-2",
        OZAYN_SDET_PATTERN_SINGLE, OZAYN_SDET_EVT_AUTH_FAILURE, 0, 0);
    ozayn_sdet_finding_t *f = NULL;
    ozayn_sdet_create_finding(&_svc, &p, NULL, &f);
    strncpy(f->identity_id, "user1", sizeof(f->identity_id) - 1);
    f->detection_time = 1;
    f->state = OZAYN_SDET_FINDING_FALSE_POSITIVE;

    ASSERT(!ozayn_sdet_finding_is_duplicate(&_svc, "DED-2", "user1", NULL));
    return 0;
}

TEST(test_sdet_finding_is_duplicate_null)
{
    _init_svc();
    ASSERT(!ozayn_sdet_finding_is_duplicate(&_svc, NULL, NULL, NULL));
    ASSERT(!ozayn_sdet_finding_is_duplicate(NULL, "X", NULL, NULL));
    return 0;
}

/* ============================================================
 * POLICY TESTS
 * ============================================================ */

TEST(test_sdet_default_policy)
{
    ozayn_sdet_policy_t p = ozayn_sdet_default_policy();
    ASSERT(p.enabled);
    ASSERT(p.max_correlation_window_seconds > 0);
    ASSERT(p.finding_retention_seconds > 0);
    ASSERT(p.dedup_window_seconds > 0);
    ASSERT(p.incident_integration_enabled);
    ASSERT(p.alert_integration_enabled);
    return 0;
}

TEST(test_sdet_set_policy)
{
    _init_svc();
    ozayn_sdet_policy_t p = ozayn_sdet_default_policy();
    p.dedup_window_seconds = 600;
    ASSERT_EQ(OZAYN_SDET_OK, ozayn_sdet_set_policy(&_svc, &p));
    const ozayn_sdet_policy_t *got = ozayn_sdet_get_policy(&_svc);
    ASSERT(got != NULL);
    ASSERT_EQ(600, got->dedup_window_seconds);
    return 0;
}

TEST(test_sdet_set_policy_disabled)
{
    _init_svc();
    ozayn_sdet_policy_t p = ozayn_sdet_default_policy();
    p.enabled = 0;
    ASSERT_EQ(OZAYN_SDET_ERR_POLICY_REJECTED,
              ozayn_sdet_set_policy(&_svc, &p));
    return 0;
}

TEST(test_sdet_set_policy_null)
{
    _init_svc();
    ASSERT_EQ(OZAYN_SDET_ERR_NULL, ozayn_sdet_set_policy(NULL, NULL));
    return 0;
}

TEST(test_sdet_get_policy_null)
{
    ASSERT(ozayn_sdet_get_policy(NULL) == NULL);
    return 0;
}

/* ============================================================
 * INCIDENT INTEGRATION TESTS
 * ============================================================ */

TEST(test_sdet_create_incident_from_finding)
{
    _init_svc();
    ozayn_sdet_pattern_t p = _make_pattern("IR-1",
        OZAYN_SDET_PATTERN_SINGLE, OZAYN_SDET_EVT_AUTH_FAILURE, 0, 0);
    ozayn_sdet_finding_t *f = NULL;
    ozayn_sdet_create_finding(&_svc, &p, NULL, &f);
    strncpy(f->identity_id, "user1", sizeof(f->identity_id) - 1);

    ASSERT_EQ(OZAYN_SDET_OK,
              ozayn_sdet_create_incident_from_finding(&_svc, f));
    return 0;
}

TEST(test_sdet_create_incident_disabled)
{
    _init_svc();
    _svc.policy.incident_integration_enabled = 0;
    ozayn_sdet_pattern_t p = _make_pattern("IRD-1",
        OZAYN_SDET_PATTERN_SINGLE, OZAYN_SDET_EVT_AUTH_FAILURE, 0, 0);
    ozayn_sdet_finding_t *f = NULL;
    ozayn_sdet_create_finding(&_svc, &p, NULL, &f);
    ASSERT_EQ(OZAYN_SDET_ERR_POLICY_REJECTED,
              ozayn_sdet_create_incident_from_finding(&_svc, f));
    return 0;
}

TEST(test_sdet_create_incident_wrong_state)
{
    _init_svc();
    ozayn_sdet_pattern_t p = _make_pattern("IRW-1",
        OZAYN_SDET_PATTERN_SINGLE, OZAYN_SDET_EVT_AUTH_FAILURE, 0, 0);
    ozayn_sdet_finding_t *f = NULL;
    ozayn_sdet_create_finding(&_svc, &p, NULL, &f);
    f->state = OZAYN_SDET_FINDING_FALSE_POSITIVE;
    ASSERT_EQ(OZAYN_SDET_ERR_STATE_TRANSITION,
              ozayn_sdet_create_incident_from_finding(&_svc, f));
    return 0;
}

TEST(test_sdet_create_incident_null)
{
    _init_svc();
    ASSERT_EQ(OZAYN_SDET_ERR_NULL,
              ozayn_sdet_create_incident_from_finding(NULL, NULL));
    return 0;
}

/* ============================================================
 * ALERT INTEGRATION TESTS
 * ============================================================ */

TEST(test_sdet_create_alert_from_finding)
{
    _init_svc();
    ozayn_sdet_pattern_t p = _make_pattern("AL-1",
        OZAYN_SDET_PATTERN_SINGLE, OZAYN_SDET_EVT_AUTH_FAILURE, 0, 0);
    p.severity = OZAYN_SDET_SEV_CRITICAL;
    ozayn_sdet_finding_t *f = NULL;
    ozayn_sdet_create_finding(&_svc, &p, NULL, &f);

    ASSERT_EQ(OZAYN_SDET_OK,
              ozayn_sdet_create_alert_from_finding(&_svc, f));
    return 0;
}

TEST(test_sdet_create_alert_disabled)
{
    _init_svc();
    _svc.policy.alert_integration_enabled = 0;
    ozayn_sdet_pattern_t p = _make_pattern("ALD-1",
        OZAYN_SDET_PATTERN_SINGLE, OZAYN_SDET_EVT_AUTH_FAILURE, 0, 0);
    ozayn_sdet_finding_t *f = NULL;
    ozayn_sdet_create_finding(&_svc, &p, NULL, &f);
    ASSERT_EQ(OZAYN_SDET_ERR_POLICY_REJECTED,
              ozayn_sdet_create_alert_from_finding(&_svc, f));
    return 0;
}

TEST(test_sdet_create_alert_null)
{
    _init_svc();
    ASSERT_EQ(OZAYN_SDET_ERR_NULL,
              ozayn_sdet_create_alert_from_finding(NULL, NULL));
    return 0;
}

/* ============================================================
 * AUDIT INTEGRATION TESTS
 * ============================================================ */

TEST(test_sdet_audit_event)
{
    _init_svc();
    ASSERT_EQ(OZAYN_SDET_OK,
              ozayn_sdet_audit_event(&_svc, "TEST_EVENT", NULL));
    return 0;
}

TEST(test_sdet_audit_event_null)
{
    ASSERT_EQ(OZAYN_SDET_ERR_NULL,
              ozayn_sdet_audit_event(NULL, "TEST", NULL));
    return 0;
}

/* ============================================================
 * QUERY TESTS
 * ============================================================ */

TEST(test_sdet_event_count)
{
    _init_svc();
    ASSERT_EQ(0, ozayn_sdet_event_count(&_svc));
    ozayn_sdet_event_t e = _make_event(OZAYN_SDET_EVT_AUTH_FAILURE,
                                       NULL, NULL);
    ozayn_sdet_process_event(&_svc, &e);
    ASSERT_EQ(1, ozayn_sdet_event_count(&_svc));
    return 0;
}

TEST(test_sdet_list_events)
{
    _init_svc();
    ozayn_sdet_event_t e1 = _make_event(OZAYN_SDET_EVT_AUTH_FAILURE,
                                         NULL, NULL);
    ozayn_sdet_event_t e2 = _make_event(OZAYN_SDET_EVT_AUTH_SUCCESS,
                                         NULL, NULL);
    ozayn_sdet_process_event(&_svc, &e1);
    ozayn_sdet_process_event(&_svc, &e2);

    ozayn_sdet_event_t *list[16];
    int count = ozayn_sdet_list_events(&_svc, -1, list, 16);
    ASSERT(count >= 2);
    count = ozayn_sdet_list_events(&_svc, OZAYN_SDET_EVT_AUTH_FAILURE,
                                    list, 16);
    ASSERT(count >= 1);
    return 0;
}

TEST(test_sdet_list_events_null)
{
    _init_svc();
    ozayn_sdet_event_t *list[16];
    ASSERT_EQ(0, ozayn_sdet_list_events(NULL, -1, list, 16));
    ASSERT_EQ(0, ozayn_sdet_list_events(&_svc, -1, NULL, 16));
    ASSERT_EQ(0, ozayn_sdet_list_events(&_svc, -1, list, 0));
    return 0;
}

/* ============================================================
 * RESOURCE SAFETY TESTS
 * ============================================================ */

TEST(test_sdet_events_full)
{
    _init_svc();
    ASSERT(!ozayn_sdet_events_full(&_svc));
    ASSERT(ozayn_sdet_events_full(NULL));
    return 0;
}

TEST(test_sdet_correlations_full)
{
    _init_svc();
    ASSERT(!ozayn_sdet_correlations_full(&_svc));
    ASSERT(ozayn_sdet_correlations_full(NULL));
    return 0;
}

TEST(test_sdet_findings_full)
{
    _init_svc();
    ASSERT(!ozayn_sdet_findings_full(&_svc));
    ASSERT(ozayn_sdet_findings_full(NULL));
    return 0;
}

TEST(test_sdet_patterns_full)
{
    _init_svc();
    ASSERT(!ozayn_sdet_patterns_full(&_svc));
    ASSERT(ozayn_sdet_patterns_full(NULL));
    return 0;
}

/* ============================================================
 * NEGATIVE SECURITY TESTS
 * ============================================================ */

TEST(test_sdet_no_secrets_in_event)
{
    _init_svc();
    ozayn_sdet_event_t e = _make_event(OZAYN_SDET_EVT_AUTH_FAILURE,
                                       "user1", NULL);
    strncpy(e.safe_metadata, "clean safe text only",
            sizeof(e.safe_metadata) - 1);
    ASSERT_EQ(OZAYN_SDET_OK, ozayn_sdet_process_event(&_svc, &e));
    ASSERT(strstr(e.safe_metadata, "password") == NULL);
    return 0;
}

TEST(test_sdet_default_deny_policy)
{
    _init_svc();
    ozayn_sdet_policy_t p = ozayn_sdet_default_policy();
    ASSERT(p.enabled);
    ASSERT(p.incident_integration_enabled);
    ASSERT(p.alert_integration_enabled);
    return 0;
}

TEST(test_sdet_resource_exhaustion_handled)
{
    _init_svc();
    _svc.event_count = OZAYN_SDET_MAX_EVENTS;
    ozayn_sdet_event_t e = _make_event(OZAYN_SDET_EVT_AUTH_FAILURE,
                                       NULL, NULL);
    ASSERT_EQ(OZAYN_SDET_ERR_RESOURCE_EXHAUSTED,
              ozayn_sdet_process_event(&_svc, &e));
    return 0;
}

TEST(test_sdet_finding_dedup_prevents_creation)
{
    _init_svc();
    ozayn_sdet_pattern_t p = _make_pattern("DEDPR-1",
        OZAYN_SDET_PATTERN_SINGLE, OZAYN_SDET_EVT_AUTH_FAILURE, 0, 0);
    ozayn_sdet_finding_t *f1 = NULL;
    ozayn_sdet_create_finding(&_svc, &p, NULL, &f1);
    strncpy(f1->identity_id, "user1", sizeof(f1->identity_id) - 1);

    uint64_t before = _svc.total_findings_created;
    ozayn_sdet_finding_t *f2 = NULL;
    ozayn_sdet_create_finding(&_svc, &p, NULL, &f2);
    ASSERT(f2 == NULL);
    ASSERT(_svc.total_findings_created == before);
    ASSERT(_svc.total_findings_deduplicated == 1);
    return 0;
}

TEST(test_sdet_policy_affects_process)
{
    _init_svc();
    _svc.policy.enabled = 0;
    ozayn_sdet_event_t e = _make_event(OZAYN_SDET_EVT_AUTH_FAILURE,
                                       NULL, NULL);
    ASSERT_EQ(OZAYN_SDET_ERR_POLICY_REJECTED,
              ozayn_sdet_process_event(&_svc, &e));
    return 0;
}

/* ============================================================
 * TEST RUNNER
 * ============================================================ */

int run_sec_detect_tests(void)
{
    SUITE_BEGIN("SECURITY EVENT CORRELATION & THREAT DETECTION");

    RUN(test_sdet_init);
    RUN(test_sdet_init_null);
    RUN(test_sdet_init_double);
    RUN(test_sdet_shutdown_null);
    RUN(test_sdet_global);
    RUN(test_sdet_not_init);

    RUN(test_sdet_err_names);
    RUN(test_sdet_category_names);
    RUN(test_sdet_corr_state_names);
    RUN(test_sdet_pattern_type_names);
    RUN(test_sdet_confidence_names);
    RUN(test_sdet_finding_state_names);
    RUN(test_sdet_severity_names);
    RUN(test_sdet_severity_conversions);

    RUN(test_sdet_process_event);
    RUN(test_sdet_process_event_null);
    RUN(test_sdet_process_event_not_init);
    RUN(test_sdet_process_event_policy_disabled);
    RUN(test_sdet_process_multiple_events);
    RUN(test_sdet_process_event_ring_buffer);
    RUN(test_sdet_process_event_generates_id);
    RUN(test_sdet_process_event_sets_timestamp);

    RUN(test_sdet_normalize_audit_event);
    RUN(test_sdet_normalize_audit_event_null);
    RUN(test_sdet_normalize_audit_event_types);

    RUN(test_sdet_register_pattern);
    RUN(test_sdet_register_pattern_null);
    RUN(test_sdet_register_pattern_not_init);
    RUN(test_sdet_register_pattern_no_id);
    RUN(test_sdet_register_pattern_duplicate);
    RUN(test_sdet_unregister_pattern);
    RUN(test_sdet_unregister_pattern_not_found);
    RUN(test_sdet_unregister_pattern_null);
    RUN(test_sdet_get_pattern);
    RUN(test_sdet_enable_pattern);
    RUN(test_sdet_enable_pattern_not_found);

    RUN(test_sdet_evaluate_single_match);
    RUN(test_sdet_evaluate_single_no_match);
    RUN(test_sdet_evaluate_single_disabled_pattern);
    RUN(test_sdet_evaluate_single_creates_correlation);
    RUN(test_sdet_evaluate_single_null);

    RUN(test_sdet_evaluate_threshold_match);
    RUN(test_sdet_evaluate_threshold_not_met);
    RUN(test_sdet_evaluate_threshold_null);

    RUN(test_sdet_evaluate_sequence_match);
    RUN(test_sdet_evaluate_sequence_not_met);
    RUN(test_sdet_evaluate_sequence_null);

    RUN(test_sdet_evaluate_patterns);
    RUN(test_sdet_evaluate_patterns_null);
    RUN(test_sdet_evaluate_patterns_not_init);

    RUN(test_sdet_create_correlation);
    RUN(test_sdet_create_correlation_null);
    RUN(test_sdet_correlation_limit);
    RUN(test_sdet_find_correlation);
    RUN(test_sdet_expire_correlations);
    RUN(test_sdet_correlation_count);
    RUN(test_sdet_correlation_count_null);

    RUN(test_sdet_create_finding);
    RUN(test_sdet_create_finding_null);
    RUN(test_sdet_get_finding);
    RUN(test_sdet_finding_count);
    RUN(test_sdet_list_findings);
    RUN(test_sdet_list_findings_filter);
    RUN(test_sdet_finding_set_state);
    RUN(test_sdet_finding_set_state_invalid);
    RUN(test_sdet_finding_set_state_not_found);
    RUN(test_sdet_finding_set_state_confirmed);
    RUN(test_sdet_cleanup_expired_findings);

    RUN(test_sdet_finding_is_duplicate);
    RUN(test_sdet_finding_is_duplicate_expired);
    RUN(test_sdet_finding_is_duplicate_null);

    RUN(test_sdet_default_policy);
    RUN(test_sdet_set_policy);
    RUN(test_sdet_set_policy_disabled);
    RUN(test_sdet_set_policy_null);
    RUN(test_sdet_get_policy_null);

    RUN(test_sdet_create_incident_from_finding);
    RUN(test_sdet_create_incident_disabled);
    RUN(test_sdet_create_incident_wrong_state);
    RUN(test_sdet_create_incident_null);

    RUN(test_sdet_create_alert_from_finding);
    RUN(test_sdet_create_alert_disabled);
    RUN(test_sdet_create_alert_null);

    RUN(test_sdet_audit_event);
    RUN(test_sdet_audit_event_null);

    RUN(test_sdet_event_count);
    RUN(test_sdet_list_events);
    RUN(test_sdet_list_events_null);

    RUN(test_sdet_events_full);
    RUN(test_sdet_correlations_full);
    RUN(test_sdet_findings_full);
    RUN(test_sdet_patterns_full);

    RUN(test_sdet_no_secrets_in_event);
    RUN(test_sdet_default_deny_policy);
    RUN(test_sdet_resource_exhaustion_handled);
    RUN(test_sdet_finding_dedup_prevents_creation);
    RUN(test_sdet_policy_affects_process);

    SUITE_END();
    return TOTAL_FAIL();
}
