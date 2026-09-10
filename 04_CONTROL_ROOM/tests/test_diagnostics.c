/*
 * test_diagnostics.c — Diagnostics & Health Assessment Tests (Step 07).
 *
 * Comprehensive tests for: lifecycle, requests, results, findings,
 * health assessments, queries, events, audit, security, concurrency.
 */

#include "../../tests/test_framework.h"
#include "../diagnostics.h"
#include "../../03_SECURITY/audit.h"
#include <string.h>
#include <time.h>

/* ============================================================
 * TEST HELPERS
 * ============================================================ */

static ozayn_dha_service_t _svc;
static ozayn_audit_service_t _au_svc;

static void _reset_all(void)
{
    memset(&_svc, 0, sizeof(_svc));
    memset(&_au_svc, 0, sizeof(_au_svc));
}

static void _init_svc(void)
{
    _reset_all();
    _au_svc.initialized = 1;
    ozayn_dha_service_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.audit = (void *)&_au_svc;
    cfg.max_concurrent = 4;
    cfg.default_timeout_ms = 5000;
    ozayn_dha_service_init(&_svc, &cfg);
}

/* ============================================================
 * LIFECYCLE TESTS
 * ============================================================ */

TEST(test_diag_init)
{
    _reset_all();
    ozayn_dha_service_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    ASSERT_EQ(ozayn_dha_service_init(&_svc, &cfg), OZAYN_DHA_OK);
    ASSERT(_svc.initialized == 1);
    ASSERT_EQ(_svc.max_concurrent, 8);
    ASSERT_EQ(_svc.default_timeout_ms, 30000);
    ozayn_dha_service_shutdown(&_svc);
    return 0;
}

TEST(test_diag_init_null)
{
    ASSERT_EQ(ozayn_dha_service_init(NULL, NULL), OZAYN_DHA_ERR_NULL);
    return 0;
}

TEST(test_diag_init_double)
{
    _init_svc();
    ASSERT_EQ(ozayn_dha_service_init(&_svc, NULL), OZAYN_DHA_ERR_ALREADY_INITIALIZED);
    ozayn_dha_service_shutdown(&_svc);
    return 0;
}

TEST(test_diag_init_custom_config)
{
    _reset_all();
    ozayn_dha_service_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.max_concurrent = 2;
    cfg.default_timeout_ms = 1000;
    ozayn_dha_service_init(&_svc, &cfg);
    ASSERT_EQ(_svc.max_concurrent, 2);
    ASSERT_EQ(_svc.default_timeout_ms, 1000);
    ozayn_dha_service_shutdown(&_svc);
    return 0;
}

TEST(test_diag_shutdown)
{
    _init_svc();
    ozayn_dha_service_shutdown(&_svc);
    ASSERT(_svc.initialized == 0);
    return 0;
}

TEST(test_diag_shutdown_null)
{
    ozayn_dha_service_shutdown(NULL);
    return 0;
}

TEST(test_diag_is_initialized)
{
    _reset_all();
    ASSERT(!ozayn_dha_service_is_initialized(NULL));
    ASSERT(!ozayn_dha_service_is_initialized(&_svc));
    _init_svc();
    ASSERT(ozayn_dha_service_is_initialized(&_svc));
    ozayn_dha_service_shutdown(&_svc);
    ASSERT(!ozayn_dha_service_is_initialized(&_svc));
    return 0;
}

/* ============================================================
 * REQUEST TESTS
 * ============================================================ */

TEST(test_diag_request_create)
{
    _init_svc();
    ozayn_dha_request_t *req = NULL;
    ASSERT_EQ(ozayn_dha_request_create(&_svc, "MOD-VIS", "VIS-CAP",
        OZAYN_DHA_CAT_CONNECTIVITY, "user1", "sess1", "DIAG.READ",
        5000, 1, "ctx", &req), OZAYN_DHA_OK);
    ASSERT_NOT_NULL(req);
    ASSERT(strncmp(req->request_id, "DHAR-", 5) == 0);
    ASSERT_STR_EQ(req->target, "MOD-VIS");
    ASSERT_STR_EQ(req->capability, "VIS-CAP");
    ASSERT_EQ(req->category, OZAYN_DHA_CAT_CONNECTIVITY);
    ASSERT_STR_EQ(req->requester_identity, "user1");
    ASSERT_STR_EQ(req->session_id, "sess1");
    ASSERT_STR_EQ(req->required_permission, "DIAG.READ");
    ASSERT(req->request_time > 0);
    ASSERT_EQ(req->timeout_ms, 5000);
    ASSERT_EQ(req->priority, 1);
    ASSERT_STR_EQ(req->context, "ctx");
    ASSERT_EQ(req->state, OZAYN_DHA_REQ_CREATED);
    ASSERT(req->active == 1);
    ASSERT_EQ(_svc.request_count, 1);
    ASSERT_EQ(_svc.stats.total_requests, 1);
    ASSERT_EQ(_svc.active_diagnostics, 1);
    ozayn_dha_service_shutdown(&_svc);
    return 0;
}

TEST(test_diag_request_create_null)
{
    ASSERT_EQ(ozayn_dha_request_create(NULL, "X", NULL, 0, NULL, NULL, NULL, 0, 0, NULL, NULL),
              OZAYN_DHA_ERR_NULL);
    return 0;
}

TEST(test_diag_request_create_not_init)
{
    memset(&_svc, 0, sizeof(_svc));
    ASSERT_EQ(ozayn_dha_request_create(&_svc, "X", NULL, 0, NULL, NULL, NULL, 0, 0, NULL, NULL),
              OZAYN_DHA_ERR_NOT_INITIALIZED);
    return 0;
}

TEST(test_diag_request_create_empty_target)
{
    _init_svc();
    ASSERT_EQ(ozayn_dha_request_create(&_svc, "", NULL, OZAYN_DHA_CAT_CONNECTIVITY,
        NULL, NULL, NULL, 0, 0, NULL, NULL), OZAYN_DHA_ERR_INVALID_PARAM);
    ozayn_dha_service_shutdown(&_svc);
    return 0;
}

TEST(test_diag_request_create_invalid_category)
{
    _init_svc();
    ASSERT_EQ(ozayn_dha_request_create(&_svc, "MOD", NULL, (ozayn_dha_category_t)99,
        NULL, NULL, NULL, 0, 0, NULL, NULL), OZAYN_DHA_ERR_INVALID_PARAM);
    ozayn_dha_service_shutdown(&_svc);
    return 0;
}

TEST(test_diag_request_create_optional_fields)
{
    _init_svc();
    ozayn_dha_request_t *req = NULL;
    ASSERT_EQ(ozayn_dha_request_create(&_svc, "MOD", NULL, OZAYN_DHA_CAT_LIFECYCLE,
        NULL, NULL, NULL, 0, 0, NULL, &req), OZAYN_DHA_OK);
    ASSERT(req->capability[0] == '\0');
    ASSERT(req->requester_identity[0] == '\0');
    ASSERT(req->session_id[0] == '\0');
    ASSERT(req->context[0] == '\0');
    ozayn_dha_service_shutdown(&_svc);
    return 0;
}

TEST(test_diag_request_advance)
{
    _init_svc();
    ozayn_dha_request_t *req = NULL;
    ozayn_dha_request_create(&_svc, "MOD", NULL, OZAYN_DHA_CAT_LIFECYCLE,
        NULL, NULL, NULL, 0, 0, NULL, &req);
    ASSERT_EQ(ozayn_dha_request_advance(&_svc, req->request_id,
        OZAYN_DHA_REQ_VALIDATING), OZAYN_DHA_OK);
    ASSERT_EQ(req->state, OZAYN_DHA_REQ_VALIDATING);
    ASSERT_EQ(ozayn_dha_request_advance(&_svc, req->request_id,
        OZAYN_DHA_REQ_RESOLVING), OZAYN_DHA_OK);
    ASSERT_EQ(ozayn_dha_request_advance(&_svc, req->request_id,
        OZAYN_DHA_REQ_EXECUTING), OZAYN_DHA_OK);
    ASSERT_EQ(req->state, OZAYN_DHA_REQ_EXECUTING);
    ozayn_dha_service_shutdown(&_svc);
    return 0;
}

TEST(test_diag_request_advance_terminal)
{
    _init_svc();
    ozayn_dha_request_t *req = NULL;
    ozayn_dha_request_create(&_svc, "MOD", NULL, OZAYN_DHA_CAT_LIFECYCLE,
        NULL, NULL, NULL, 0, 0, NULL, &req);
    ozayn_dha_request_complete(&_svc, req->request_id);
    ASSERT_EQ(ozayn_dha_request_advance(&_svc, req->request_id,
        OZAYN_DHA_REQ_VALIDATING), OZAYN_DHA_ERR_STATE_INVALID);
    ozayn_dha_service_shutdown(&_svc);
    return 0;
}

TEST(test_diag_request_advance_not_found)
{
    _init_svc();
    ASSERT_EQ(ozayn_dha_request_advance(&_svc, "NOPE", OZAYN_DHA_REQ_VALIDATING),
              OZAYN_DHA_ERR_NOT_FOUND);
    ozayn_dha_service_shutdown(&_svc);
    return 0;
}

TEST(test_diag_request_complete)
{
    _init_svc();
    ozayn_dha_request_t *req = NULL;
    ozayn_dha_request_create(&_svc, "MOD", NULL, OZAYN_DHA_CAT_LIFECYCLE,
        NULL, NULL, NULL, 0, 0, NULL, &req);
    ASSERT_EQ(ozayn_dha_request_complete(&_svc, req->request_id), OZAYN_DHA_OK);
    ASSERT_EQ(req->state, OZAYN_DHA_REQ_COMPLETED);
    ASSERT_EQ(_svc.stats.total_succeeded, 1);
    ASSERT_EQ(_svc.active_diagnostics, 0);
    ozayn_dha_service_shutdown(&_svc);
    return 0;
}

TEST(test_diag_request_complete_not_found)
{
    _init_svc();
    ASSERT_EQ(ozayn_dha_request_complete(&_svc, "NOPE"), OZAYN_DHA_ERR_NOT_FOUND);
    ozayn_dha_service_shutdown(&_svc);
    return 0;
}

TEST(test_diag_request_fail)
{
    _init_svc();
    ozayn_dha_request_t *req = NULL;
    ozayn_dha_request_create(&_svc, "MOD", NULL, OZAYN_DHA_CAT_LIFECYCLE,
        NULL, NULL, NULL, 0, 0, NULL, &req);
    ASSERT_EQ(ozayn_dha_request_fail(&_svc, req->request_id, -1, "error"),
              OZAYN_DHA_OK);
    ASSERT_EQ(req->state, OZAYN_DHA_REQ_FAILED);
    ASSERT_EQ(_svc.stats.total_failed, 1);
    ASSERT_EQ(_svc.active_diagnostics, 0);
    ozayn_dha_service_shutdown(&_svc);
    return 0;
}

TEST(test_diag_request_cancel)
{
    _init_svc();
    ozayn_dha_request_t *req = NULL;
    ozayn_dha_request_create(&_svc, "MOD", NULL, OZAYN_DHA_CAT_LIFECYCLE,
        NULL, NULL, NULL, 0, 0, NULL, &req);
    ASSERT_EQ(ozayn_dha_request_cancel(&_svc, req->request_id), OZAYN_DHA_OK);
    ASSERT_EQ(req->state, OZAYN_DHA_REQ_CANCELLED);
    ASSERT_EQ(_svc.stats.total_cancelled, 1);
    ASSERT_EQ(_svc.active_diagnostics, 0);
    ozayn_dha_service_shutdown(&_svc);
    return 0;
}

TEST(test_diag_request_cancel_terminal)
{
    _init_svc();
    ozayn_dha_request_t *req = NULL;
    ozayn_dha_request_create(&_svc, "MOD", NULL, OZAYN_DHA_CAT_LIFECYCLE,
        NULL, NULL, NULL, 0, 0, NULL, &req);
    ozayn_dha_request_complete(&_svc, req->request_id);
    ASSERT_EQ(ozayn_dha_request_cancel(&_svc, req->request_id),
              OZAYN_DHA_ERR_STATE_INVALID);
    ozayn_dha_service_shutdown(&_svc);
    return 0;
}

TEST(test_diag_request_concurrency_limit)
{
    _init_svc();
    ozayn_dha_request_t *r1 = NULL, *r2 = NULL, *r3 = NULL, *r4 = NULL;
    ozayn_dha_request_create(&_svc, "M1", NULL, 0, NULL, NULL, NULL, 0, 0, NULL, &r1);
    ozayn_dha_request_create(&_svc, "M2", NULL, 0, NULL, NULL, NULL, 0, 0, NULL, &r2);
    ozayn_dha_request_create(&_svc, "M3", NULL, 0, NULL, NULL, NULL, 0, 0, NULL, &r3);
    ozayn_dha_request_create(&_svc, "M4", NULL, 0, NULL, NULL, NULL, 0, 0, NULL, &r4);
    ASSERT_EQ(_svc.active_diagnostics, 4);
    ozayn_dha_request_t *r5 = NULL;
    ASSERT_EQ(ozayn_dha_request_create(&_svc, "M5", NULL, 0, NULL, NULL, NULL, 0, 0, NULL, &r5),
              OZAYN_DHA_ERR_CONCURRENCY_LIMIT);
    /* Complete one and try again */
    ozayn_dha_request_complete(&_svc, r1->request_id);
    ASSERT_EQ(ozayn_dha_request_create(&_svc, "M5", NULL, 0, NULL, NULL, NULL, 0, 0, NULL, &r5),
              OZAYN_DHA_OK);
    ozayn_dha_service_shutdown(&_svc);
    return 0;
}

/* ============================================================
 * RESULT TESTS
 * ============================================================ */

TEST(test_diag_result_create)
{
    _init_svc();
    ozayn_dha_result_t *res = NULL;
    ASSERT_EQ(ozayn_dha_result_create(&_svc, "REQ-1", "MOD-VIS", "VIS-CAP",
        OZAYN_DHA_CAT_CONNECTIVITY, OZAYN_DHA_RESULT_SUCCEEDED,
        OZAYN_DHA_HEALTH_HEALTHY, 0, NULL, &res), OZAYN_DHA_OK);
    ASSERT_NOT_NULL(res);
    ASSERT(strncmp(res->result_id, "DHAR-", 5) == 0);
    ASSERT_STR_EQ(res->request_id, "REQ-1");
    ASSERT_STR_EQ(res->target, "MOD-VIS");
    ASSERT_STR_EQ(res->capability, "VIS-CAP");
    ASSERT_EQ(res->result_state, OZAYN_DHA_RESULT_SUCCEEDED);
    ASSERT_EQ(res->health_state, OZAYN_DHA_HEALTH_HEALTHY);
    ASSERT(res->start_time > 0);
    ASSERT(res->active == 1);
    ASSERT_EQ(_svc.result_count, 1);
    ozayn_dha_service_shutdown(&_svc);
    return 0;
}

TEST(test_diag_result_create_null)
{
    ASSERT_EQ(ozayn_dha_result_create(NULL, "X", "X", NULL, 0, 0, 0, 0, NULL, NULL),
              OZAYN_DHA_ERR_NULL);
    return 0;
}

TEST(test_diag_result_create_empty_request_id)
{
    _init_svc();
    ASSERT_EQ(ozayn_dha_result_create(&_svc, "", "MOD", NULL, 0, 0, 0, 0, NULL, NULL),
              OZAYN_DHA_ERR_INVALID_PARAM);
    ozayn_dha_service_shutdown(&_svc);
    return 0;
}

TEST(test_diag_result_create_empty_target)
{
    _init_svc();
    ASSERT_EQ(ozayn_dha_result_create(&_svc, "REQ-1", "", NULL, 0, 0, 0, 0, NULL, NULL),
              OZAYN_DHA_ERR_INVALID_PARAM);
    ozayn_dha_service_shutdown(&_svc);
    return 0;
}

TEST(test_diag_result_with_error)
{
    _init_svc();
    ozayn_dha_result_t *res = NULL;
    ASSERT_EQ(ozayn_dha_result_create(&_svc, "REQ-1", "MOD", NULL,
        OZAYN_DHA_CAT_CONNECTIVITY, OZAYN_DHA_RESULT_FAILED,
        OZAYN_DHA_HEALTH_UNHEALTHY, -1, "connection refused", &res), OZAYN_DHA_OK);
    ASSERT_EQ(res->error_code, -1);
    ASSERT_STR_EQ(res->error_detail, "connection refused");
    ozayn_dha_service_shutdown(&_svc);
    return 0;
}

/* ============================================================
 * FINDING TESTS
 * ============================================================ */

TEST(test_diag_finding_create)
{
    _init_svc();
    ozayn_dha_finding_t *f = NULL;
    ASSERT_EQ(ozayn_dha_finding_create(&_svc, OZAYN_DHA_CAT_CONNECTIVITY,
        OZAYN_DHA_SEVERITY_HIGH, "MOD-VIS", "connection timeout", "EVD-1", &f),
        OZAYN_DHA_OK);
    ASSERT_NOT_NULL(f);
    ASSERT(strncmp(f->finding_id, "DHAF-", 5) == 0);
    ASSERT_EQ(f->category, OZAYN_DHA_CAT_CONNECTIVITY);
    ASSERT_EQ(f->severity, OZAYN_DHA_SEVERITY_HIGH);
    ASSERT_STR_EQ(f->component_id, "MOD-VIS");
    ASSERT_STR_EQ(f->description, "connection timeout");
    ASSERT_STR_EQ(f->evidence_ref, "EVD-1");
    ASSERT_EQ(f->status, OZAYN_DHA_FINDING_OPEN);
    ASSERT(f->created_time > 0);
    ASSERT(f->active == 1);
    ASSERT_EQ(_svc.finding_count, 1);
    ozayn_dha_service_shutdown(&_svc);
    return 0;
}

TEST(test_diag_finding_create_null)
{
    ASSERT_EQ(ozayn_dha_finding_create(NULL, 0, 0, "X", "X", NULL, NULL),
              OZAYN_DHA_ERR_NULL);
    return 0;
}

TEST(test_diag_finding_create_empty_component)
{
    _init_svc();
    ASSERT_EQ(ozayn_dha_finding_create(&_svc, 0, 0, "", "desc", NULL, NULL),
              OZAYN_DHA_ERR_INVALID_PARAM);
    ozayn_dha_service_shutdown(&_svc);
    return 0;
}

TEST(test_diag_finding_create_empty_description)
{
    _init_svc();
    ASSERT_EQ(ozayn_dha_finding_create(&_svc, 0, 0, "COMP", "", NULL, NULL),
              OZAYN_DHA_ERR_INVALID_PARAM);
    ozayn_dha_service_shutdown(&_svc);
    return 0;
}

TEST(test_diag_finding_update_status)
{
    _init_svc();
    ozayn_dha_finding_t *f = NULL;
    ozayn_dha_finding_create(&_svc, 0, OZAYN_DHA_SEVERITY_LOW, "COMP", "desc", NULL, &f);
    ASSERT_EQ(f->status, OZAYN_DHA_FINDING_OPEN);
    ASSERT_EQ(ozayn_dha_finding_update_status(&_svc, f->finding_id,
        OZAYN_DHA_FINDING_RESOLVED), OZAYN_DHA_OK);
    ASSERT_EQ(f->status, OZAYN_DHA_FINDING_RESOLVED);
    ASSERT_EQ(ozayn_dha_finding_update_status(&_svc, f->finding_id,
        OZAYN_DHA_FINDING_ACKNOWLEDGED), OZAYN_DHA_OK);
    ASSERT_EQ(f->status, OZAYN_DHA_FINDING_ACKNOWLEDGED);
    ozayn_dha_service_shutdown(&_svc);
    return 0;
}

TEST(test_diag_finding_update_status_not_found)
{
    _init_svc();
    ASSERT_EQ(ozayn_dha_finding_update_status(&_svc, "NOPE", OZAYN_DHA_FINDING_RESOLVED),
              OZAYN_DHA_ERR_NOT_FOUND);
    ozayn_dha_service_shutdown(&_svc);
    return 0;
}

/* ============================================================
 * HEALTH ASSESSMENT TESTS
 * ============================================================ */

TEST(test_diag_assess_health)
{
    _init_svc();
    ozayn_dha_assessment_t *a = NULL;
    ASSERT_EQ(ozayn_dha_assess_health(&_svc, "MOD-VIS", "DIAG-1",
        OZAYN_DHA_HEALTH_HEALTHY, OZAYN_DHA_SEVERITY_INFO, "all good", &a),
        OZAYN_DHA_OK);
    ASSERT_NOT_NULL(a);
    ASSERT(strncmp(a->assessment_id, "DHAA-", 5) == 0);
    ASSERT_STR_EQ(a->component_id, "MOD-VIS");
    ASSERT_EQ(a->health_state, OZAYN_DHA_HEALTH_HEALTHY);
    ASSERT(a->assessment_time > 0);
    ASSERT_STR_EQ(a->diagnostic_source, "DIAG-1");
    ASSERT_EQ(a->severity, OZAYN_DHA_SEVERITY_INFO);
    ASSERT_STR_EQ(a->summary, "all good");
    ASSERT(a->active == 1);
    ASSERT_EQ(_svc.assessment_count, 1);
    ozayn_dha_service_shutdown(&_svc);
    return 0;
}

TEST(test_diag_assess_health_null)
{
    ASSERT_EQ(ozayn_dha_assess_health(NULL, "X", NULL, 0, 0, NULL, NULL),
              OZAYN_DHA_ERR_NULL);
    return 0;
}

TEST(test_diag_assess_health_empty_component)
{
    _init_svc();
    ASSERT_EQ(ozayn_dha_assess_health(&_svc, "", NULL, 0, 0, NULL, NULL),
              OZAYN_DHA_ERR_INVALID_PARAM);
    ozayn_dha_service_shutdown(&_svc);
    return 0;
}

TEST(test_diag_assess_health_change_detection)
{
    _init_svc();
    ozayn_dha_assessment_t *a1 = NULL, *a2 = NULL;
    ozayn_dha_assess_health(&_svc, "MOD-VIS", "DIAG-1",
        OZAYN_DHA_HEALTH_HEALTHY, OZAYN_DHA_SEVERITY_INFO, "good", &a1);
    ASSERT_EQ(_svc.stats.total_health_changed, 0);
    ozayn_dha_assess_health(&_svc, "MOD-VIS", "DIAG-2",
        OZAYN_DHA_HEALTH_DEGRADED, OZAYN_DHA_SEVERITY_MEDIUM, "degraded", &a2);
    ASSERT_EQ(_svc.stats.total_health_changed, 1);
    /* Third assessment with same state — no change */
    ozayn_dha_assessment_t *a3 = NULL;
    ozayn_dha_assess_health(&_svc, "MOD-VIS", "DIAG-3",
        OZAYN_DHA_HEALTH_DEGRADED, OZAYN_DHA_SEVERITY_MEDIUM, "still degraded", &a3);
    ASSERT_EQ(_svc.stats.total_health_changed, 1);
    /* Recovery */
    ozayn_dha_assessment_t *a4 = NULL;
    ozayn_dha_assess_health(&_svc, "MOD-VIS", "DIAG-4",
        OZAYN_DHA_HEALTH_HEALTHY, OZAYN_DHA_SEVERITY_INFO, "recovered", &a4);
    ASSERT_EQ(_svc.stats.total_health_changed, 2);
    ozayn_dha_service_shutdown(&_svc);
    return 0;
}

TEST(test_diag_assess_health_multiple_components)
{
    _init_svc();
    ozayn_dha_assess_health(&_svc, "MOD-A", "D1", OZAYN_DHA_HEALTH_HEALTHY,
        OZAYN_DHA_SEVERITY_INFO, "A good", NULL);
    ozayn_dha_assess_health(&_svc, "MOD-B", "D2", OZAYN_DHA_HEALTH_DEGRADED,
        OZAYN_DHA_SEVERITY_HIGH, "B degraded", NULL);
    ozayn_dha_assess_health(&_svc, "MOD-C", "D3", OZAYN_DHA_HEALTH_UNHEALTHY,
        OZAYN_DHA_SEVERITY_CRITICAL, "C bad", NULL);
    ASSERT_EQ(_svc.assessment_count, 3);
    const ozayn_dha_assessment_t *a = ozayn_dha_assessment_get_by_component(&_svc, "MOD-B");
    ASSERT_NOT_NULL(a);
    ASSERT_EQ(a->health_state, OZAYN_DHA_HEALTH_DEGRADED);
    ozayn_dha_service_shutdown(&_svc);
    return 0;
}

/* ============================================================
 * QUERY TESTS
 * ============================================================ */

TEST(test_diag_request_get)
{
    _init_svc();
    ozayn_dha_request_t *req = NULL;
    ozayn_dha_request_create(&_svc, "MOD", NULL, 0, NULL, NULL, NULL, 0, 0, NULL, &req);
    const ozayn_dha_request_t *found = ozayn_dha_request_get(&_svc, req->request_id);
    ASSERT_NOT_NULL(found);
    ASSERT(strcmp(found->request_id, req->request_id) == 0);
    ASSERT_NULL(ozayn_dha_request_get(&_svc, "NOPE"));
    ASSERT_NULL(ozayn_dha_request_get(NULL, "X"));
    ozayn_dha_service_shutdown(&_svc);
    return 0;
}

TEST(test_diag_result_get)
{
    _init_svc();
    ozayn_dha_result_t *res = NULL;
    ozayn_dha_result_create(&_svc, "REQ-1", "MOD", NULL, 0, 0, 0, 0, NULL, &res);
    const ozayn_dha_result_t *found = ozayn_dha_result_get(&_svc, res->result_id);
    ASSERT_NOT_NULL(found);
    ASSERT(strcmp(found->result_id, res->result_id) == 0);
    ASSERT_NULL(ozayn_dha_result_get(&_svc, "NOPE"));
    ozayn_dha_service_shutdown(&_svc);
    return 0;
}

TEST(test_diag_finding_get)
{
    _init_svc();
    ozayn_dha_finding_t *f = NULL;
    ozayn_dha_finding_create(&_svc, 0, 0, "COMP", "desc", NULL, &f);
    const ozayn_dha_finding_t *found = ozayn_dha_finding_get(&_svc, f->finding_id);
    ASSERT_NOT_NULL(found);
    ASSERT(strcmp(found->finding_id, f->finding_id) == 0);
    ASSERT_NULL(ozayn_dha_finding_get(&_svc, "NOPE"));
    ozayn_dha_service_shutdown(&_svc);
    return 0;
}

TEST(test_diag_assessment_get)
{
    _init_svc();
    ozayn_dha_assessment_t *a = NULL;
    ozayn_dha_assess_health(&_svc, "MOD", "SRC", 0, 0, "sum", &a);
    const ozayn_dha_assessment_t *found = ozayn_dha_assessment_get(&_svc, a->assessment_id);
    ASSERT_NOT_NULL(found);
    ASSERT(strcmp(found->assessment_id, a->assessment_id) == 0);
    ASSERT_NULL(ozayn_dha_assessment_get(&_svc, "NOPE"));
    ozayn_dha_service_shutdown(&_svc);
    return 0;
}

TEST(test_diag_counts)
{
    _init_svc();
    ASSERT_EQ(ozayn_dha_request_count(&_svc), 0);
    ASSERT_EQ(ozayn_dha_result_count(&_svc), 0);
    ASSERT_EQ(ozayn_dha_finding_count(&_svc), 0);
    ASSERT_EQ(ozayn_dha_assessment_count(&_svc), 0);
    ozayn_dha_request_create(&_svc, "M", NULL, 0, NULL, NULL, NULL, 0, 0, NULL, NULL);
    ozayn_dha_result_create(&_svc, "R", "M", NULL, 0, 0, 0, 0, NULL, NULL);
    ozayn_dha_finding_create(&_svc, 0, 0, "M", "d", NULL, NULL);
    ozayn_dha_assess_health(&_svc, "M", "S", 0, 0, "s", NULL);
    ASSERT_EQ(ozayn_dha_request_count(&_svc), 1);
    ASSERT_EQ(ozayn_dha_result_count(&_svc), 1);
    ASSERT_EQ(ozayn_dha_finding_count(&_svc), 1);
    ASSERT_EQ(ozayn_dha_assessment_count(&_svc), 1);
    ASSERT_EQ(ozayn_dha_request_count(NULL), 0);
    ozayn_dha_service_shutdown(&_svc);
    return 0;
}

/* ============================================================
 * STATISTICS TESTS
 * ============================================================ */

TEST(test_diag_get_stats)
{
    _init_svc();
    ozayn_dha_stats_t stats;
    memset(&stats, 0, sizeof(stats));
    ASSERT_EQ(ozayn_dha_get_stats(&_svc, &stats), OZAYN_DHA_OK);
    ASSERT_EQ(stats.total_requests, 0);
    ASSERT_EQ(ozayn_dha_get_stats(NULL, NULL), OZAYN_DHA_ERR_NULL);

    ozayn_dha_request_t *req = NULL;
    ozayn_dha_request_create(&_svc, "M", NULL, 0, NULL, NULL, NULL, 0, 0, NULL, &req);
    ozayn_dha_request_complete(&_svc, req->request_id);
    ozayn_dha_get_stats(&_svc, &stats);
    ASSERT_EQ(stats.total_requests, 1);
    ASSERT_EQ(stats.total_succeeded, 1);
    ASSERT_EQ(stats.current_requests, 0);
    ozayn_dha_service_shutdown(&_svc);
    return 0;
}

TEST(test_diag_stats_all_terminal)
{
    _init_svc();
    ozayn_dha_request_t *r1 = NULL, *r2 = NULL, *r3 = NULL, *r4 = NULL;
    ozayn_dha_request_create(&_svc, "M1", NULL, 0, NULL, NULL, NULL, 0, 0, NULL, &r1);
    ozayn_dha_request_create(&_svc, "M2", NULL, 0, NULL, NULL, NULL, 0, 0, NULL, &r2);
    ozayn_dha_request_create(&_svc, "M3", NULL, 0, NULL, NULL, NULL, 0, 0, NULL, &r3);
    ozayn_dha_request_create(&_svc, "M4", NULL, 0, NULL, NULL, NULL, 0, 0, NULL, &r4);
    ozayn_dha_request_complete(&_svc, r1->request_id);
    ozayn_dha_request_fail(&_svc, r2->request_id, -1, "err");
    ozayn_dha_request_cancel(&_svc, r3->request_id);
    /* r4 stays active */
    ozayn_dha_stats_t stats;
    ozayn_dha_get_stats(&_svc, &stats);
    ASSERT_EQ(stats.total_succeeded, 1);
    ASSERT_EQ(stats.total_failed, 1);
    ASSERT_EQ(stats.total_cancelled, 1);
    ASSERT_EQ(stats.current_requests, 1);
    ozayn_dha_service_shutdown(&_svc);
    return 0;
}

/* ============================================================
 * NAME HELPER TESTS
 * ============================================================ */

TEST(test_diag_err_name)
{
    ASSERT_STR_EQ(ozayn_dha_err_name(OZAYN_DHA_OK), "OK");
    ASSERT_STR_EQ(ozayn_dha_err_name(OZAYN_DHA_ERR_NULL), "NULL");
    ASSERT_STR_EQ(ozayn_dha_err_name(OZAYN_DHA_ERR_TARGET_NOT_FOUND), "TARGET_NOT_FOUND");
    ASSERT_STR_EQ(ozayn_dha_err_name(OZAYN_DHA_ERR_AUTHORIZATION_FAILED), "AUTHORIZATION_FAILED");
    ASSERT_STR_EQ(ozayn_dha_err_name(OZAYN_DHA_ERR_DEPENDENCY_CYCLE), "DEPENDENCY_CYCLE");
    ASSERT_STR_EQ(ozayn_dha_err_name((ozayn_dha_err_t)999), "UNKNOWN");
    return 0;
}

TEST(test_diag_category_name)
{
    ASSERT_STR_EQ(ozayn_dha_category_name(OZAYN_DHA_CAT_CONNECTIVITY), "CONNECTIVITY");
    ASSERT_STR_EQ(ozayn_dha_category_name(OZAYN_DHA_CAT_LIFECYCLE), "LIFECYCLE");
    ASSERT_STR_EQ(ozayn_dha_category_name(OZAYN_DHA_CAT_CAPABILITY), "CAPABILITY");
    ASSERT_STR_EQ(ozayn_dha_category_name(OZAYN_DHA_CAT_DEPENDENCY), "DEPENDENCY");
    ASSERT_STR_EQ(ozayn_dha_category_name(OZAYN_DHA_CAT_SECURITY_INTEGRATION), "SECURITY_INTEGRATION");
    ASSERT_STR_EQ(ozayn_dha_category_name((ozayn_dha_category_t)99), "UNKNOWN");
    return 0;
}

TEST(test_diag_health_name)
{
    ASSERT_STR_EQ(ozayn_dha_health_name(OZAYN_DHA_HEALTH_HEALTHY), "HEALTHY");
    ASSERT_STR_EQ(ozayn_dha_health_name(OZAYN_DHA_HEALTH_DEGRADED), "DEGRADED");
    ASSERT_STR_EQ(ozayn_dha_health_name(OZAYN_DHA_HEALTH_UNHEALTHY), "UNHEALTHY");
    ASSERT_STR_EQ(ozayn_dha_health_name(OZAYN_DHA_HEALTH_UNAVAILABLE), "UNAVAILABLE");
    ASSERT_STR_EQ(ozayn_dha_health_name((ozayn_dha_health_t)99), "UNKNOWN");
    return 0;
}

TEST(test_diag_severity_name)
{
    ASSERT_STR_EQ(ozayn_dha_severity_name(OZAYN_DHA_SEVERITY_INFO), "INFO");
    ASSERT_STR_EQ(ozayn_dha_severity_name(OZAYN_DHA_SEVERITY_LOW), "LOW");
    ASSERT_STR_EQ(ozayn_dha_severity_name(OZAYN_DHA_SEVERITY_MEDIUM), "MEDIUM");
    ASSERT_STR_EQ(ozayn_dha_severity_name(OZAYN_DHA_SEVERITY_HIGH), "HIGH");
    ASSERT_STR_EQ(ozayn_dha_severity_name(OZAYN_DHA_SEVERITY_CRITICAL), "CRITICAL");
    ASSERT_STR_EQ(ozayn_dha_severity_name((ozayn_dha_severity_t)99), "UNKNOWN");
    return 0;
}

TEST(test_diag_result_state_name)
{
    ASSERT_STR_EQ(ozayn_dha_result_state_name(OZAYN_DHA_RESULT_SUCCEEDED), "SUCCEEDED");
    ASSERT_STR_EQ(ozayn_dha_result_state_name(OZAYN_DHA_RESULT_FAILED), "FAILED");
    ASSERT_STR_EQ(ozayn_dha_result_state_name(OZAYN_DHA_RESULT_TIMEOUT), "TIMEOUT");
    ASSERT_STR_EQ(ozayn_dha_result_state_name(OZAYN_DHA_RESULT_REJECTED), "REJECTED");
    ASSERT_STR_EQ(ozayn_dha_result_state_name((ozayn_dha_result_state_t)99), "UNKNOWN");
    return 0;
}

TEST(test_diag_finding_status_name)
{
    ASSERT_STR_EQ(ozayn_dha_finding_status_name(OZAYN_DHA_FINDING_OPEN), "OPEN");
    ASSERT_STR_EQ(ozayn_dha_finding_status_name(OZAYN_DHA_FINDING_RESOLVED), "RESOLVED");
    ASSERT_STR_EQ(ozayn_dha_finding_status_name(OZAYN_DHA_FINDING_ACKNOWLEDGED), "ACKNOWLEDGED");
    ASSERT_STR_EQ(ozayn_dha_finding_status_name(OZAYN_DHA_FINDING_INFORMATIONAL), "INFORMATIONAL");
    ASSERT_STR_EQ(ozayn_dha_finding_status_name((ozayn_dha_finding_status_t)99), "UNKNOWN");
    return 0;
}

TEST(test_diag_event_type_name)
{
    ASSERT_STR_EQ(ozayn_dha_event_type_name(OZAYN_DHA_EVENT_REQUESTED), "REQUESTED");
    ASSERT_STR_EQ(ozayn_dha_event_type_name(OZAYN_DHA_EVENT_SUCCEEDED), "SUCCEEDED");
    ASSERT_STR_EQ(ozayn_dha_event_type_name(OZAYN_DHA_EVENT_HEALTH_CHANGED), "HEALTH_CHANGED");
    ASSERT_STR_EQ(ozayn_dha_event_type_name(OZAYN_DHA_EVENT_HEALTH_RECOVERED), "HEALTH_RECOVERED");
    ASSERT_STR_EQ(ozayn_dha_event_type_name((ozayn_dha_event_type_t)99), "UNKNOWN");
    return 0;
}

TEST(test_diag_req_state_name)
{
    ASSERT_STR_EQ(ozayn_dha_req_state_name(OZAYN_DHA_REQ_CREATED), "CREATED");
    ASSERT_STR_EQ(ozayn_dha_req_state_name(OZAYN_DHA_REQ_EXECUTING), "EXECUTING");
    ASSERT_STR_EQ(ozayn_dha_req_state_name(OZAYN_DHA_REQ_COMPLETED), "COMPLETED");
    ASSERT_STR_EQ(ozayn_dha_req_state_name(OZAYN_DHA_REQ_FAILED), "FAILED");
    ASSERT_STR_EQ(ozayn_dha_req_state_name((ozayn_dha_req_state_t)99), "UNKNOWN");
    return 0;
}

/* ============================================================
 * VALIDATION TESTS
 * ============================================================ */

TEST(test_diag_request_validate)
{
    ozayn_dha_request_t req;
    memset(&req, 0, sizeof(req));
    ASSERT(!ozayn_dha_request_validate(NULL));
    ASSERT(!ozayn_dha_request_validate(&req));
    strncpy(req.request_id, "DHAR-1", OZAYN_DHA_MAX_ID_LEN - 1);
    ASSERT(!ozayn_dha_request_validate(&req));
    strncpy(req.target, "MOD", OZAYN_DHA_MAX_TARGET_LEN - 1);
    ASSERT(!ozayn_dha_request_validate(&req));
    req.category = OZAYN_DHA_CAT_CONNECTIVITY;
    ASSERT(!ozayn_dha_request_validate(&req));
    req.request_time = time(NULL);
    ASSERT(ozayn_dha_request_validate(&req));
    return 0;
}

TEST(test_diag_result_validate)
{
    ozayn_dha_result_t res;
    memset(&res, 0, sizeof(res));
    res.result_state = (ozayn_dha_result_state_t)99;
    ASSERT(!ozayn_dha_result_validate(NULL));
    ASSERT(!ozayn_dha_result_validate(&res));
    strncpy(res.result_id, "DHAR-1", OZAYN_DHA_MAX_ID_LEN - 1);
    ASSERT(!ozayn_dha_result_validate(&res));
    strncpy(res.request_id, "REQ-1", OZAYN_DHA_MAX_ID_LEN - 1);
    ASSERT(!ozayn_dha_result_validate(&res));
    strncpy(res.target, "MOD", OZAYN_DHA_MAX_TARGET_LEN - 1);
    ASSERT(!ozayn_dha_result_validate(&res));
    res.result_state = OZAYN_DHA_RESULT_SUCCEEDED;
    ASSERT(ozayn_dha_result_validate(&res));
    return 0;
}

TEST(test_diag_assessment_validate)
{
    ozayn_dha_assessment_t a;
    memset(&a, 0, sizeof(a));
    ASSERT(!ozayn_dha_assessment_validate(NULL));
    ASSERT(!ozayn_dha_assessment_validate(&a));
    strncpy(a.assessment_id, "DHAA-1", OZAYN_DHA_MAX_ID_LEN - 1);
    ASSERT(!ozayn_dha_assessment_validate(&a));
    strncpy(a.component_id, "MOD", OZAYN_DHA_MAX_ID_LEN - 1);
    ASSERT(!ozayn_dha_assessment_validate(&a));
    a.health_state = OZAYN_DHA_HEALTH_HEALTHY;
    ASSERT(!ozayn_dha_assessment_validate(&a));
    a.assessment_time = time(NULL);
    ASSERT(ozayn_dha_assessment_validate(&a));
    return 0;
}

/* ============================================================
 * EVENT / AUDIT TESTS
 * ============================================================ */

TEST(test_diag_emit_event)
{
    _init_svc();
    ASSERT_EQ(ozayn_dha_emit_event(&_svc, OZAYN_DHA_EVENT_REQUESTED, "X", "X"),
              OZAYN_DHA_OK);
    ASSERT_EQ(ozayn_dha_emit_event(NULL, OZAYN_DHA_EVENT_REQUESTED, "X", "X"),
              OZAYN_DHA_ERR_NULL);
    ozayn_dha_service_shutdown(&_svc);
    return 0;
}

TEST(test_diag_audit)
{
    _init_svc();
    ASSERT_EQ(ozayn_dha_audit(&_svc, "X", "TEST", "detail"), OZAYN_DHA_OK);
    ASSERT_EQ(ozayn_dha_audit(NULL, "X", "X", "X"), OZAYN_DHA_ERR_NULL);
    ASSERT_EQ(ozayn_dha_audit(&_svc, NULL, "X", "X"), OZAYN_DHA_ERR_INVALID_PARAM);
    ozayn_dha_service_shutdown(&_svc);
    return 0;
}

/* ============================================================
 * SECURITY BOUNDARY TESTS
 * ============================================================ */

TEST(test_diag_global_singleton)
{
    ozayn_dha_service_t *g1 = ozayn_dha_get_global();
    ozayn_dha_service_t *g2 = ozayn_dha_get_global();
    ASSERT_NOT_NULL(g1);
    ASSERT(g1 == g2);
    return 0;
}

TEST(test_diag_no_secrets_in_request)
{
    _init_svc();
    ozayn_dha_request_t *req = NULL;
    ozayn_dha_request_create(&_svc, "MOD", "password=secret key=abc",
        OZAYN_DHA_CAT_CONNECTIVITY, "user1", "sess1", "DIAG.READ",
        5000, 1, "token=xyz", &req);
    ASSERT(req->active == 1);
    ASSERT(req->context[0] != '\0'); /* context stored but not logged */
    ozayn_dha_service_shutdown(&_svc);
    return 0;
}

TEST(test_diag_no_secrets_in_assessment)
{
    _init_svc();
    ozayn_dha_assessment_t *a = NULL;
    ozayn_dha_assess_health(&_svc, "MOD", "SRC", OZAYN_DHA_HEALTH_HEALTHY,
        OZAYN_DHA_SEVERITY_INFO, "no secrets here", &a);
    ASSERT(a->safe_metadata[0] == '\0');
    ozayn_dha_service_shutdown(&_svc);
    return 0;
}

/* ============================================================
 * CLEANUP TESTS
 * ============================================================ */

TEST(test_diag_cleanup_results)
{
    _init_svc();
    ozayn_dha_result_create(&_svc, "R1", "M", NULL, 0, 0, 0, 0, NULL, NULL);
    ozayn_dha_result_create(&_svc, "R2", "M", NULL, 0, 0, 0, 0, NULL, NULL);
    int cleaned = ozayn_dha_cleanup_results(&_svc);
    ASSERT_EQ(cleaned, 2);
    ASSERT_EQ(_svc.result_count, 0);
    ASSERT_EQ(ozayn_dha_cleanup_results(NULL), 0);
    ozayn_dha_service_shutdown(&_svc);
    return 0;
}

TEST(test_diag_cleanup_findings)
{
    _init_svc();
    ozayn_dha_finding_create(&_svc, 0, 0, "M", "d1", NULL, NULL);
    ozayn_dha_finding_create(&_svc, 0, 0, "M", "d2", NULL, NULL);
    ozayn_dha_finding_create(&_svc, 0, 0, "M", "d3", NULL, NULL);
    int cleaned = ozayn_dha_cleanup_findings(&_svc);
    ASSERT_EQ(cleaned, 3);
    ASSERT_EQ(_svc.finding_count, 0);
    ASSERT_EQ(ozayn_dha_cleanup_findings(NULL), 0);
    ozayn_dha_service_shutdown(&_svc);
    return 0;
}

TEST(test_diag_cleanup_all)
{
    _init_svc();
    ozayn_dha_request_create(&_svc, "M", NULL, 0, NULL, NULL, NULL, 0, 0, NULL, NULL);
    ozayn_dha_result_create(&_svc, "R", "M", NULL, 0, 0, 0, 0, NULL, NULL);
    ozayn_dha_finding_create(&_svc, 0, 0, "M", "d", NULL, NULL);
    ozayn_dha_assess_health(&_svc, "M", "S", 0, 0, "s", NULL);
    int cleaned = ozayn_dha_cleanup_all(&_svc);
    ASSERT(cleaned >= 4);
    ASSERT_EQ(_svc.request_count, 0);
    ASSERT_EQ(_svc.result_count, 0);
    ASSERT_EQ(_svc.finding_count, 0);
    ASSERT_EQ(_svc.assessment_count, 0);
    ASSERT_EQ(ozayn_dha_cleanup_all(NULL), 0);
    ozayn_dha_service_shutdown(&_svc);
    return 0;
}

/* ============================================================
 * CONCURRENCY TESTS (simulated)
 * ============================================================ */

TEST(test_diag_concurrent_requests)
{
    _init_svc();
    ozayn_dha_request_t *r1 = NULL, *r2 = NULL, *r3 = NULL;
    ozayn_dha_request_create(&_svc, "M1", NULL, OZAYN_DHA_CAT_CONNECTIVITY,
        "alice", NULL, NULL, 0, 0, NULL, &r1);
    ozayn_dha_request_create(&_svc, "M2", NULL, OZAYN_DHA_CAT_LIFECYCLE,
        "bob", NULL, NULL, 0, 0, NULL, &r2);
    ozayn_dha_request_create(&_svc, "M3", NULL, OZAYN_DHA_CAT_CAPABILITY,
        "carol", NULL, NULL, 0, 0, NULL, &r3);
    /* All active simultaneously */
    ASSERT_EQ(_svc.active_diagnostics, 3);
    /* Complete in different order */
    ozayn_dha_request_complete(&_svc, r2->request_id);
    ozayn_dha_request_fail(&_svc, r1->request_id, -1, "err");
    ozayn_dha_request_complete(&_svc, r3->request_id);
    ASSERT_EQ(_svc.active_diagnostics, 0);
    ASSERT_EQ(_svc.stats.total_succeeded, 2);
    ASSERT_EQ(_svc.stats.total_failed, 1);
    ozayn_dha_service_shutdown(&_svc);
    return 0;
}

TEST(test_diag_concurrent_findings)
{
    _init_svc();
    ozayn_dha_finding_t *f1 = NULL, *f2 = NULL, *f3 = NULL;
    ozayn_dha_finding_create(&_svc, OZAYN_DHA_CAT_CONNECTIVITY,
        OZAYN_DHA_SEVERITY_HIGH, "M1", "f1", NULL, &f1);
    ozayn_dha_finding_create(&_svc, OZAYN_DHA_CAT_LIFECYCLE,
        OZAYN_DHA_SEVERITY_CRITICAL, "M2", "f2", NULL, &f2);
    ozayn_dha_finding_create(&_svc, OZAYN_DHA_CAT_RESOURCE,
        OZAYN_DHA_SEVERITY_LOW, "M3", "f3", NULL, &f3);
    ASSERT_EQ(_svc.finding_count, 3);
    ASSERT(f1->severity < f2->severity);
    ASSERT(f3->severity < f1->severity);
    ozayn_dha_service_shutdown(&_svc);
    return 0;
}

TEST(test_diag_concurrent_assessments)
{
    _init_svc();
    ozayn_dha_assess_health(&_svc, "M1", "D1", OZAYN_DHA_HEALTH_HEALTHY,
        OZAYN_DHA_SEVERITY_INFO, "good", NULL);
    ozayn_dha_assess_health(&_svc, "M2", "D2", OZAYN_DHA_HEALTH_DEGRADED,
        OZAYN_DHA_SEVERITY_HIGH, "bad", NULL);
    ozayn_dha_assess_health(&_svc, "M3", "D3", OZAYN_DHA_HEALTH_UNHEALTHY,
        OZAYN_DHA_SEVERITY_CRITICAL, "worse", NULL);
    ASSERT_EQ(_svc.assessment_count, 3);
    const ozayn_dha_assessment_t *a1 = ozayn_dha_assessment_get_by_component(&_svc, "M1");
    const ozayn_dha_assessment_t *a2 = ozayn_dha_assessment_get_by_component(&_svc, "M2");
    const ozayn_dha_assessment_t *a3 = ozayn_dha_assessment_get_by_component(&_svc, "M3");
    ASSERT_NOT_NULL(a1);
    ASSERT_NOT_NULL(a2);
    ASSERT_NOT_NULL(a3);
    ASSERT_EQ(a1->health_state, OZAYN_DHA_HEALTH_HEALTHY);
    ASSERT_EQ(a2->health_state, OZAYN_DHA_HEALTH_DEGRADED);
    ASSERT_EQ(a3->health_state, OZAYN_DHA_HEALTH_UNHEALTHY);
    ozayn_dha_service_shutdown(&_svc);
    return 0;
}

/* ============================================================
 * FULL LIFECYCLE TEST
 * ============================================================ */

TEST(test_diag_full_lifecycle)
{
    _init_svc();

    /* Create request */
    ozayn_dha_request_t *req = NULL;
    ASSERT_EQ(ozayn_dha_request_create(&_svc, "MOD-VISION", "VIS-CAP",
        OZAYN_DHA_CAT_CONNECTIVITY, "user-1", "sess-1", "DIAG.READ",
        5000, 2, "full lifecycle test", &req), OZAYN_DHA_OK);

    /* Advance through states */
    ozayn_dha_request_advance(&_svc, req->request_id, OZAYN_DHA_REQ_VALIDATING);
    ozayn_dha_request_advance(&_svc, req->request_id, OZAYN_DHA_REQ_RESOLVING);
    ozayn_dha_request_advance(&_svc, req->request_id, OZAYN_DHA_REQ_CHECKING);
    ozayn_dha_request_advance(&_svc, req->request_id, OZAYN_DHA_REQ_AUTHORIZING);
    ozayn_dha_request_advance(&_svc, req->request_id, OZAYN_DHA_REQ_EXECUTING);

    /* Create findings */
    ozayn_dha_finding_t *f1 = NULL, *f2 = NULL;
    ozayn_dha_finding_create(&_svc, OZAYN_DHA_CAT_CONNECTIVITY,
        OZAYN_DHA_SEVERITY_LOW, "MOD-VISION", "minor latency", "EVD-1", &f1);
    ozayn_dha_finding_create(&_svc, OZAYN_DHA_CAT_CONNECTIVITY,
        OZAYN_DHA_SEVERITY_MEDIUM, "MOD-VISION", "intermittent timeout", "EVD-2", &f2);
    ozayn_dha_finding_update_status(&_svc, f1->finding_id, OZAYN_DHA_FINDING_INFORMATIONAL);

    /* Create result */
    ozayn_dha_result_t *res = NULL;
    ozayn_dha_result_create(&_svc, req->request_id, "MOD-VISION", "VIS-CAP",
        OZAYN_DHA_CAT_CONNECTIVITY, OZAYN_DHA_RESULT_SUCCEEDED,
        OZAYN_DHA_HEALTH_DEGRADED, 0, NULL, &res);
    res->finding_start = 0;
    res->finding_count = 2;
    res->max_severity = OZAYN_DHA_SEVERITY_MEDIUM;

    /* Create health assessment */
    ozayn_dha_assessment_t *a = NULL;
    ozayn_dha_assess_health(&_svc, "MOD-VISION", req->request_id,
        OZAYN_DHA_HEALTH_DEGRADED, OZAYN_DHA_SEVERITY_MEDIUM,
        "minor connectivity issues detected", &a);

    /* Complete request */
    ASSERT_EQ(ozayn_dha_request_complete(&_svc, req->request_id), OZAYN_DHA_OK);

    /* Verify */
    ASSERT(req->state == OZAYN_DHA_REQ_COMPLETED);
    ASSERT(res->result_state == OZAYN_DHA_RESULT_SUCCEEDED);
    ASSERT(res->health_state == OZAYN_DHA_HEALTH_DEGRADED);
    ASSERT(f1->status == OZAYN_DHA_FINDING_INFORMATIONAL);
    ASSERT(f2->status == OZAYN_DHA_FINDING_OPEN);
    ASSERT(a->health_state == OZAYN_DHA_HEALTH_DEGRADED);

    /* Verify immutability of completed request */
    ASSERT_EQ(ozayn_dha_request_complete(&_svc, req->request_id),
              OZAYN_DHA_ERR_STATE_INVALID);

    /* Verify stats */
    ozayn_dha_stats_t stats;
    ozayn_dha_get_stats(&_svc, &stats);
    ASSERT_EQ(stats.total_requests, 1);
    ASSERT_EQ(stats.total_succeeded, 1);
    ASSERT_EQ(stats.current_requests, 0);
    ASSERT_EQ(stats.current_results, 1);
    ASSERT_EQ(stats.current_findings, 2);
    ASSERT_EQ(stats.current_assessments, 1);

    ozayn_dha_service_shutdown(&_svc);
    return 0;
}

/* ============================================================
 * TEST RUNNER
 * ============================================================ */

int run_cr_diagnostics_tests(void)
{
    SUITE_BEGIN("Diagnostics & Health Assessment");

    /* Lifecycle */
    RUN(test_diag_init);
    RUN(test_diag_init_null);
    RUN(test_diag_init_double);
    RUN(test_diag_init_custom_config);
    RUN(test_diag_shutdown);
    RUN(test_diag_shutdown_null);
    RUN(test_diag_is_initialized);

    /* Requests */
    RUN(test_diag_request_create);
    RUN(test_diag_request_create_null);
    RUN(test_diag_request_create_not_init);
    RUN(test_diag_request_create_empty_target);
    RUN(test_diag_request_create_invalid_category);
    RUN(test_diag_request_create_optional_fields);
    RUN(test_diag_request_advance);
    RUN(test_diag_request_advance_terminal);
    RUN(test_diag_request_advance_not_found);
    RUN(test_diag_request_complete);
    RUN(test_diag_request_complete_not_found);
    RUN(test_diag_request_fail);
    RUN(test_diag_request_cancel);
    RUN(test_diag_request_cancel_terminal);
    RUN(test_diag_request_concurrency_limit);

    /* Results */
    RUN(test_diag_result_create);
    RUN(test_diag_result_create_null);
    RUN(test_diag_result_create_empty_request_id);
    RUN(test_diag_result_create_empty_target);
    RUN(test_diag_result_with_error);

    /* Findings */
    RUN(test_diag_finding_create);
    RUN(test_diag_finding_create_null);
    RUN(test_diag_finding_create_empty_component);
    RUN(test_diag_finding_create_empty_description);
    RUN(test_diag_finding_update_status);
    RUN(test_diag_finding_update_status_not_found);

    /* Health Assessment */
    RUN(test_diag_assess_health);
    RUN(test_diag_assess_health_null);
    RUN(test_diag_assess_health_empty_component);
    RUN(test_diag_assess_health_change_detection);
    RUN(test_diag_assess_health_multiple_components);

    /* Query */
    RUN(test_diag_request_get);
    RUN(test_diag_result_get);
    RUN(test_diag_finding_get);
    RUN(test_diag_assessment_get);
    RUN(test_diag_counts);

    /* Statistics */
    RUN(test_diag_get_stats);
    RUN(test_diag_stats_all_terminal);

    /* Name Helpers */
    RUN(test_diag_err_name);
    RUN(test_diag_category_name);
    RUN(test_diag_health_name);
    RUN(test_diag_severity_name);
    RUN(test_diag_result_state_name);
    RUN(test_diag_finding_status_name);
    RUN(test_diag_event_type_name);
    RUN(test_diag_req_state_name);

    /* Validation */
    RUN(test_diag_request_validate);
    RUN(test_diag_result_validate);
    RUN(test_diag_assessment_validate);

    /* Events / Audit */
    RUN(test_diag_emit_event);
    RUN(test_diag_audit);

    /* Security */
    RUN(test_diag_global_singleton);
    RUN(test_diag_no_secrets_in_request);
    RUN(test_diag_no_secrets_in_assessment);

    /* Cleanup */
    RUN(test_diag_cleanup_results);
    RUN(test_diag_cleanup_findings);
    RUN(test_diag_cleanup_all);

    /* Concurrency */
    RUN(test_diag_concurrent_requests);
    RUN(test_diag_concurrent_findings);
    RUN(test_diag_concurrent_assessments);

    /* Full Lifecycle */
    RUN(test_diag_full_lifecycle);

    SUITE_END();
    return TOTAL_FAIL();
}
