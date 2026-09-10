/*
 * test_operation_history.c — Operation History & Execution Records Tests (Step 06).
 *
 * Comprehensive tests for: record creation, lifecycle, attempts, timing,
 * queries, pagination, retention, concurrency, security, recovery, shutdown.
 */

#include "../../tests/test_framework.h"
#include "../operation_history.h"
#include "../../03_SECURITY/audit.h"
#include <string.h>
#include <time.h>

/* ============================================================
 * TEST HELPERS
 * ============================================================ */

static ozayn_oh_service_t _svc;
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
    ozayn_oh_service_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.audit = (void *)&_au_svc;
    ozayn_oh_service_init(&_svc, &cfg);
}

/* ============================================================
 * LIFECYCLE TESTS
 * ============================================================ */

TEST(test_oh_init)
{
    _reset_all();
    ozayn_oh_service_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    ASSERT_EQ(ozayn_oh_service_init(&_svc, &cfg), OZAYN_OH_OK);
    ASSERT(_svc.initialized == 1);
    ASSERT_EQ(_svc.count, 0);
    ozayn_oh_service_shutdown(&_svc);
    return 0;
}

TEST(test_oh_init_null)
{
    ASSERT_EQ(ozayn_oh_service_init(NULL, NULL), OZAYN_OH_ERR_NULL);
    return 0;
}

TEST(test_oh_init_double)
{
    _init_svc();
    ASSERT_EQ(ozayn_oh_service_init(&_svc, NULL), OZAYN_OH_ERR_ALREADY_INITIALIZED);
    ozayn_oh_service_shutdown(&_svc);
    return 0;
}

TEST(test_oh_init_default_retention)
{
    _reset_all();
    ozayn_oh_service_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    ozayn_oh_service_init(&_svc, &cfg);
    ASSERT(_svc.retention.max_records > 0);
    ASSERT(_svc.retention.max_age_seconds > 0);
    ASSERT(_svc.retention.retain_security_records == 1);
    ozayn_oh_service_shutdown(&_svc);
    return 0;
}

TEST(test_oh_init_custom_retention)
{
    _reset_all();
    ozayn_oh_service_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.retention.max_records = 100;
    cfg.retention.max_age_seconds = 86400;
    cfg.retention.retain_security_records = 0;
    ozayn_oh_service_init(&_svc, &cfg);
    ASSERT_EQ(_svc.retention.max_records, 100);
    ASSERT_EQ(_svc.retention.max_age_seconds, 86400);
    ASSERT(_svc.retention.retain_security_records == 0);
    ozayn_oh_service_shutdown(&_svc);
    return 0;
}

TEST(test_oh_shutdown)
{
    _init_svc();
    ozayn_oh_service_shutdown(&_svc);
    ASSERT(_svc.initialized == 0);
    return 0;
}

TEST(test_oh_shutdown_null)
{
    ozayn_oh_service_shutdown(NULL);
    return 0;
}

TEST(test_oh_is_initialized)
{
    _reset_all();
    ASSERT(!ozayn_oh_service_is_initialized(NULL));
    ASSERT(!ozayn_oh_service_is_initialized(&_svc));
    _init_svc();
    ASSERT(ozayn_oh_service_is_initialized(&_svc));
    ozayn_oh_service_shutdown(&_svc);
    ASSERT(!ozayn_oh_service_is_initialized(&_svc));
    return 0;
}

/* ============================================================
 * RECORD CREATION TESTS
 * ============================================================ */

TEST(test_oh_record_create)
{
    _init_svc();
    ozayn_oh_record_t *rec = NULL;
    ASSERT_EQ(ozayn_oh_record_create(&_svc, "OP-1", "REQ-1",
        "MOD-VIS", "VIS-CAP", OZAYN_OH_ACTION_START, "VIS.READ",
        "user1", "sess1", 3, &rec), OZAYN_OH_OK);
    ASSERT_NOT_NULL(rec);
    ASSERT(rec->record_id[0] != '\0');
    ASSERT_STR_EQ(rec->operation_id, "OP-1");
    ASSERT_STR_EQ(rec->request_id, "REQ-1");
    ASSERT_STR_EQ(rec->target, "MOD-VIS");
    ASSERT_STR_EQ(rec->capability, "VIS-CAP");
    ASSERT_EQ(rec->action, OZAYN_OH_ACTION_START);
    ASSERT_STR_EQ(rec->required_permission, "VIS.READ");
    ASSERT_STR_EQ(rec->requester_identity, "user1");
    ASSERT_STR_EQ(rec->session_id, "sess1");
    ASSERT_EQ(rec->max_retries, 3);
    ASSERT(rec->created_time > 0);
    ASSERT(rec->active == 1);
    ASSERT(rec->finalized == 0);
    ASSERT_EQ(_svc.count, 1);
    ASSERT_EQ(_svc.stats.total_recorded, 1);
    ozayn_oh_service_shutdown(&_svc);
    return 0;
}

TEST(test_oh_record_create_null)
{
    ASSERT_EQ(ozayn_oh_record_create(NULL, "X", "X", "X", NULL, 0, NULL, NULL, NULL, 0, NULL),
              OZAYN_OH_ERR_NULL);
    return 0;
}

TEST(test_oh_record_create_not_init)
{
    memset(&_svc, 0, sizeof(_svc));
    ASSERT_EQ(ozayn_oh_record_create(&_svc, "X", "X", "X", NULL, 0, NULL, NULL, NULL, 0, NULL),
              OZAYN_OH_ERR_NOT_INITIALIZED);
    return 0;
}

TEST(test_oh_record_create_empty_operation_id)
{
    _init_svc();
    ASSERT_EQ(ozayn_oh_record_create(&_svc, "", "REQ-1", "MOD", NULL, 0, NULL, NULL, NULL, 0, NULL),
              OZAYN_OH_ERR_INVALID_PARAM);
    ozayn_oh_service_shutdown(&_svc);
    return 0;
}

TEST(test_oh_record_create_empty_request_id)
{
    _init_svc();
    ASSERT_EQ(ozayn_oh_record_create(&_svc, "OP-1", "", "MOD", NULL, 0, NULL, NULL, NULL, 0, NULL),
              OZAYN_OH_ERR_INVALID_PARAM);
    ozayn_oh_service_shutdown(&_svc);
    return 0;
}

TEST(test_oh_record_create_empty_target)
{
    _init_svc();
    ASSERT_EQ(ozayn_oh_record_create(&_svc, "OP-1", "REQ-1", "", NULL, 0, NULL, NULL, NULL, 0, NULL),
              OZAYN_OH_ERR_INVALID_PARAM);
    ozayn_oh_service_shutdown(&_svc);
    return 0;
}

TEST(test_oh_record_create_invalid_action)
{
    _init_svc();
    ASSERT_EQ(ozayn_oh_record_create(&_svc, "OP-1", "REQ-1", "MOD", NULL,
        (ozayn_oh_action_t)99, NULL, NULL, NULL, 0, NULL),
        OZAYN_OH_ERR_INVALID_PARAM);
    ozayn_oh_service_shutdown(&_svc);
    return 0;
}

TEST(test_oh_record_create_duplicate)
{
    _init_svc();
    ozayn_oh_record_create(&_svc, "OP-1", "REQ-1", "MOD", NULL, 0, NULL, NULL, NULL, 0, NULL);
    ASSERT_EQ(ozayn_oh_record_create(&_svc, "OP-1", "REQ-2", "MOD", NULL, 0, NULL, NULL, NULL, 0, NULL),
              OZAYN_OH_ERR_DUPLICATE_RECORD);
    ozayn_oh_service_shutdown(&_svc);
    return 0;
}

TEST(test_oh_record_create_generates_id)
{
    _init_svc();
    ozayn_oh_record_t *r1 = NULL, *r2 = NULL;
    ozayn_oh_record_create(&_svc, "OP-1", "R1", "M", NULL, 0, NULL, NULL, NULL, 0, &r1);
    ozayn_oh_record_create(&_svc, "OP-2", "R2", "M", NULL, 0, NULL, NULL, NULL, 0, &r2);
    ASSERT(strncmp(r1->record_id, "OHR-", 4) == 0);
    ASSERT(strcmp(r1->record_id, r2->record_id) != 0);
    ozayn_oh_service_shutdown(&_svc);
    return 0;
}

TEST(test_oh_record_create_optional_fields)
{
    _init_svc();
    ozayn_oh_record_t *rec = NULL;
    ASSERT_EQ(ozayn_oh_record_create(&_svc, "OP-1", "REQ-1",
        "MOD", NULL, OZAYN_OH_ACTION_QUERY, NULL,
        NULL, NULL, 0, &rec), OZAYN_OH_OK);
    ASSERT(rec->capability[0] == '\0');
    ASSERT(rec->required_permission[0] == '\0');
    ASSERT(rec->requester_identity[0] == '\0');
    ASSERT(rec->session_id[0] == '\0');
    ozayn_oh_service_shutdown(&_svc);
    return 0;
}

/* ============================================================
 * RECORD FINALIZATION TESTS
 * ============================================================ */

TEST(test_oh_record_finalize)
{
    _init_svc();
    ozayn_oh_record_t *rec = NULL;
    ozayn_oh_record_create(&_svc, "OP-1", "REQ-1", "MOD", NULL, 0, NULL, NULL, NULL, 0, &rec);
    ASSERT_EQ(ozayn_oh_record_finalize(&_svc, rec->record_id,
        OZAYN_OH_STATE_SUCCEEDED, OZAYN_OH_RESULT_SUCCESS, 0, NULL),
        OZAYN_OH_OK);
    ASSERT(rec->finalized == 1);
    ASSERT_EQ(rec->final_state, OZAYN_OH_STATE_SUCCEEDED);
    ASSERT_EQ(rec->result_category, OZAYN_OH_RESULT_SUCCESS);
    ASSERT(rec->completed_time > 0);
    ASSERT(rec->total_duration_ms >= 0);
    ozayn_oh_service_shutdown(&_svc);
    return 0;
}

TEST(test_oh_record_finalize_not_terminal)
{
    _init_svc();
    ozayn_oh_record_t *rec = NULL;
    ozayn_oh_record_create(&_svc, "OP-1", "REQ-1", "MOD", NULL, 0, NULL, NULL, NULL, 0, &rec);
    /* SUCCEEDED(0) through UNSUPPORTED(7) are all terminal, use invalid */
    ASSERT_EQ(ozayn_oh_record_finalize(&_svc, rec->record_id,
        (ozayn_oh_state_t)99, OZAYN_OH_RESULT_SUCCESS, 0, NULL),
        OZAYN_OH_ERR_NOT_TERMINAL);
    ozayn_oh_service_shutdown(&_svc);
    return 0;
}

TEST(test_oh_record_finalize_immutable)
{
    _init_svc();
    ozayn_oh_record_t *rec = NULL;
    ozayn_oh_record_create(&_svc, "OP-1", "REQ-1", "MOD", NULL, 0, NULL, NULL, NULL, 0, &rec);
    ozayn_oh_record_finalize(&_svc, rec->record_id,
        OZAYN_OH_STATE_SUCCEEDED, OZAYN_OH_RESULT_SUCCESS, 0, NULL);
    ASSERT_EQ(ozayn_oh_record_finalize(&_svc, rec->record_id,
        OZAYN_OH_STATE_FAILED, OZAYN_OH_RESULT_INTERNAL_ERROR, -1, NULL),
        OZAYN_OH_ERR_IMMUTABLE);
    ozayn_oh_service_shutdown(&_svc);
    return 0;
}

TEST(test_oh_record_finalize_not_found)
{
    _init_svc();
    ASSERT_EQ(ozayn_oh_record_finalize(&_svc, "NOPE",
        OZAYN_OH_STATE_SUCCEEDED, OZAYN_OH_RESULT_SUCCESS, 0, NULL),
        OZAYN_OH_ERR_NOT_FOUND);
    ozayn_oh_service_shutdown(&_svc);
    return 0;
}

TEST(test_oh_record_finalize_failure_detail)
{
    _init_svc();
    ozayn_oh_record_t *rec = NULL;
    ozayn_oh_record_create(&_svc, "OP-1", "REQ-1", "MOD", NULL, 0, NULL, NULL, NULL, 0, &rec);
    ASSERT_EQ(ozayn_oh_record_finalize(&_svc, rec->record_id,
        OZAYN_OH_STATE_FAILED, OZAYN_OH_RESULT_INTERNAL_ERROR, -1, "component crashed"),
        OZAYN_OH_OK);
    ASSERT_STR_EQ(rec->failure_detail, "component crashed");
    ASSERT_EQ(rec->failure_category, OZAYN_OH_FAILURE_NONE);
    ozayn_oh_service_shutdown(&_svc);
    return 0;
}

TEST(test_oh_record_finalize_all_terminal_states)
{
    _init_svc();
    ozayn_oh_state_t states[] = {
        OZAYN_OH_STATE_SUCCEEDED, OZAYN_OH_STATE_FAILED,
        OZAYN_OH_STATE_CANCELLED, OZAYN_OH_STATE_TIMEOUT,
        OZAYN_OH_STATE_REJECTED, OZAYN_OH_STATE_EXPIRED,
        OZAYN_OH_STATE_UNAVAILABLE, OZAYN_OH_STATE_UNSUPPORTED
    };
    for (int i = 0; i < 8; i++) {
        char opid[32], reqid[32];
        snprintf(opid, sizeof(opid), "OP-%d", i);
        snprintf(reqid, sizeof(reqid), "REQ-%d", i);
        ozayn_oh_record_t *rec = NULL;
        ozayn_oh_record_create(&_svc, opid, reqid, "MOD", NULL, 0, NULL, NULL, NULL, 0, &rec);
        ASSERT_EQ(ozayn_oh_record_finalize(&_svc, rec->record_id,
            states[i], OZAYN_OH_RESULT_SUCCESS, 0, NULL), OZAYN_OH_OK);
        ASSERT(rec->finalized == 1);
    }
    ozayn_oh_service_shutdown(&_svc);
    return 0;
}

/* ============================================================
 * ATTEMPT MANAGEMENT TESTS
 * ============================================================ */

TEST(test_oh_attempt_start)
{
    _init_svc();
    ozayn_oh_record_t *rec = NULL;
    ozayn_oh_record_create(&_svc, "OP-1", "REQ-1", "MOD", NULL, 0, NULL, NULL, NULL, 0, &rec);
    ozayn_oh_attempt_t *att = NULL;
    ASSERT_EQ(ozayn_oh_attempt_start(&_svc, rec->record_id, &att), OZAYN_OH_OK);
    ASSERT_NOT_NULL(att);
    ASSERT(att->attempt_number == 1);
    ASSERT(strncmp(att->attempt_id, "ATM-", 4) == 0);
    ASSERT(att->started_time > 0);
    ASSERT(rec->attempt_count == 1);
    ASSERT(rec->started_time > 0);
    ozayn_oh_service_shutdown(&_svc);
    return 0;
}

TEST(test_oh_attempt_start_not_found)
{
    _init_svc();
    ASSERT_EQ(ozayn_oh_attempt_start(&_svc, "NOPE", NULL), OZAYN_OH_ERR_NOT_FOUND);
    ozayn_oh_service_shutdown(&_svc);
    return 0;
}

TEST(test_oh_attempt_start_after_finalize)
{
    _init_svc();
    ozayn_oh_record_t *rec = NULL;
    ozayn_oh_record_create(&_svc, "OP-1", "REQ-1", "MOD", NULL, 0, NULL, NULL, NULL, 0, &rec);
    ozayn_oh_record_finalize(&_svc, rec->record_id,
        OZAYN_OH_STATE_SUCCEEDED, OZAYN_OH_RESULT_SUCCESS, 0, NULL);
    ASSERT_EQ(ozayn_oh_attempt_start(&_svc, rec->record_id, NULL), OZAYN_OH_ERR_IMMUTABLE);
    ozayn_oh_service_shutdown(&_svc);
    return 0;
}

TEST(test_oh_attempt_multiple)
{
    _init_svc();
    ozayn_oh_record_t *rec = NULL;
    ozayn_oh_record_create(&_svc, "OP-1", "REQ-1", "MOD", NULL, 0, NULL, NULL, NULL, 0, &rec);
    ozayn_oh_attempt_t *a1 = NULL, *a2 = NULL, *a3 = NULL;
    ozayn_oh_attempt_start(&_svc, rec->record_id, &a1);
    ozayn_oh_attempt_start(&_svc, rec->record_id, &a2);
    ozayn_oh_attempt_start(&_svc, rec->record_id, &a3);
    ASSERT(a1->attempt_number == 1);
    ASSERT(a2->attempt_number == 2);
    ASSERT(a3->attempt_number == 3);
    ASSERT(rec->attempt_count == 3);
    ASSERT(strcmp(a1->attempt_id, a2->attempt_id) != 0);
    ASSERT(strcmp(a2->attempt_id, a3->attempt_id) != 0);
    ozayn_oh_service_shutdown(&_svc);
    return 0;
}

TEST(test_oh_attempt_complete)
{
    _init_svc();
    ozayn_oh_record_t *rec = NULL;
    ozayn_oh_record_create(&_svc, "OP-1", "REQ-1", "MOD", NULL, 0, NULL, NULL, NULL, 0, &rec);
    ozayn_oh_attempt_t *att = NULL;
    ozayn_oh_attempt_start(&_svc, rec->record_id, &att);
    ASSERT_EQ(ozayn_oh_attempt_complete(&_svc, rec->record_id, att->attempt_id,
        OZAYN_OH_STATE_SUCCEEDED, OZAYN_OH_RESULT_SUCCESS, 0, NULL), OZAYN_OH_OK);
    ASSERT_EQ(att->attempt_state, OZAYN_OH_STATE_SUCCEEDED);
    ASSERT_EQ(att->attempt_result, OZAYN_OH_RESULT_SUCCESS);
    ASSERT(att->completed_time > 0);
    ASSERT(att->duration_ms >= 0);
    ozayn_oh_service_shutdown(&_svc);
    return 0;
}

TEST(test_oh_attempt_complete_not_found)
{
    _init_svc();
    ASSERT_EQ(ozayn_oh_attempt_complete(&_svc, "NOPE", "ATM-1",
        OZAYN_OH_STATE_SUCCEEDED, OZAYN_OH_RESULT_SUCCESS, 0, NULL),
        OZAYN_OH_ERR_NOT_FOUND);
    ozayn_oh_service_shutdown(&_svc);
    return 0;
}

TEST(test_oh_attempt_complete_wrong_attempt_id)
{
    _init_svc();
    ozayn_oh_record_t *rec = NULL;
    ozayn_oh_record_create(&_svc, "OP-1", "REQ-1", "MOD", NULL, 0, NULL, NULL, NULL, 0, &rec);
    ozayn_oh_attempt_t *att = NULL;
    ozayn_oh_attempt_start(&_svc, rec->record_id, &att);
    ASSERT_EQ(ozayn_oh_attempt_complete(&_svc, rec->record_id, "ATM-WRONG",
        OZAYN_OH_STATE_SUCCEEDED, OZAYN_OH_RESULT_SUCCESS, 0, NULL),
        OZAYN_OH_ERR_NOT_FOUND);
    ozayn_oh_service_shutdown(&_svc);
    return 0;
}

TEST(test_oh_attempt_complete_failed_increments_retry)
{
    _init_svc();
    ozayn_oh_record_t *rec = NULL;
    ozayn_oh_record_create(&_svc, "OP-1", "REQ-1", "MOD", NULL, 0, NULL, NULL, NULL, 0, &rec);
    ozayn_oh_attempt_t *att = NULL;
    ozayn_oh_attempt_start(&_svc, rec->record_id, &att);
    ozayn_oh_attempt_complete(&_svc, rec->record_id, att->attempt_id,
        OZAYN_OH_STATE_FAILED, OZAYN_OH_RESULT_INTERNAL_ERROR, -1, "crash");
    ASSERT_EQ(rec->retry_count, 1);
    ASSERT_STR_EQ(att->error_detail, "crash");
    ozayn_oh_service_shutdown(&_svc);
    return 0;
}

/* ============================================================
 * IMMUTABILITY TESTS
 * ============================================================ */

TEST(test_oh_record_is_finalized)
{
    _init_svc();
    ozayn_oh_record_t *rec = NULL;
    ozayn_oh_record_create(&_svc, "OP-1", "REQ-1", "MOD", NULL, 0, NULL, NULL, NULL, 0, &rec);
    ASSERT(!ozayn_oh_record_is_finalized(&_svc, rec->record_id));
    ozayn_oh_record_finalize(&_svc, rec->record_id,
        OZAYN_OH_STATE_SUCCEEDED, OZAYN_OH_RESULT_SUCCESS, 0, NULL);
    ASSERT(ozayn_oh_record_is_finalized(&_svc, rec->record_id));
    ozayn_oh_service_shutdown(&_svc);
    return 0;
}

TEST(test_oh_record_is_finalized_not_found)
{
    _init_svc();
    ASSERT(!ozayn_oh_record_is_finalized(&_svc, "NOPE"));
    ASSERT(!ozayn_oh_record_is_finalized(NULL, "X"));
    ozayn_oh_service_shutdown(&_svc);
    return 0;
}

/* ============================================================
 * QUERY TESTS
 * ============================================================ */

TEST(test_oh_record_get)
{
    _init_svc();
    ozayn_oh_record_t *rec = NULL;
    ozayn_oh_record_create(&_svc, "OP-1", "REQ-1", "MOD", NULL, 0, NULL, NULL, NULL, 0, &rec);
    const ozayn_oh_record_t *found = ozayn_oh_record_get(&_svc, rec->record_id);
    ASSERT_NOT_NULL(found);
    ASSERT(strcmp(found->record_id, rec->record_id) == 0);
    ASSERT_NULL(ozayn_oh_record_get(&_svc, "NOPE"));
    ASSERT_NULL(ozayn_oh_record_get(NULL, "X"));
    ozayn_oh_service_shutdown(&_svc);
    return 0;
}

TEST(test_oh_record_get_by_request)
{
    _init_svc();
    ozayn_oh_record_t *rec = NULL;
    ozayn_oh_record_create(&_svc, "OP-1", "REQ-1", "MOD", NULL, 0, NULL, NULL, NULL, 0, &rec);
    const ozayn_oh_record_t *found = ozayn_oh_record_get_by_request(&_svc, "REQ-1");
    ASSERT_NOT_NULL(found);
    ASSERT(strcmp(found->request_id, "REQ-1") == 0);
    ASSERT_NULL(ozayn_oh_record_get_by_request(&_svc, "NOPE"));
    ASSERT_NULL(ozayn_oh_record_get_by_request(NULL, "X"));
    ozayn_oh_service_shutdown(&_svc);
    return 0;
}

TEST(test_oh_record_count)
{
    _init_svc();
    ASSERT_EQ(ozayn_oh_record_count(&_svc), 0);
    ozayn_oh_record_create(&_svc, "OP-1", "R1", "M", NULL, 0, NULL, NULL, NULL, 0, NULL);
    ASSERT_EQ(ozayn_oh_record_count(&_svc), 1);
    ozayn_oh_record_create(&_svc, "OP-2", "R2", "M", NULL, 0, NULL, NULL, NULL, 0, NULL);
    ASSERT_EQ(ozayn_oh_record_count(&_svc), 2);
    ASSERT_EQ(ozayn_oh_record_count(NULL), 0);
    ozayn_oh_service_shutdown(&_svc);
    return 0;
}

TEST(test_oh_total_recorded)
{
    _init_svc();
    ASSERT_EQ(ozayn_oh_total_recorded(&_svc), 0);
    ozayn_oh_record_create(&_svc, "OP-1", "R1", "M", NULL, 0, NULL, NULL, NULL, 0, NULL);
    ASSERT_EQ(ozayn_oh_total_recorded(&_svc), 1);
    ASSERT_EQ(ozayn_oh_total_recorded(NULL), 0);
    ozayn_oh_service_shutdown(&_svc);
    return 0;
}

TEST(test_oh_query_no_filter)
{
    _init_svc();
    for (int i = 0; i < 5; i++) {
        char opid[32], reqid[32];
        snprintf(opid, sizeof(opid), "OP-%d", i);
        snprintf(reqid, sizeof(reqid), "REQ-%d", i);
        ozayn_oh_record_create(&_svc, opid, reqid, "MOD", NULL, 0, NULL, NULL, NULL, 0, NULL);
    }
    ozayn_oh_query_results_t results;
    ASSERT_EQ(ozayn_oh_query(&_svc, NULL, &results), OZAYN_OH_OK);
    ASSERT_EQ(results.result_count, 5);
    ASSERT_EQ(results.total_count, 5);
    ASSERT(!results.has_more);
    ozayn_oh_service_shutdown(&_svc);
    return 0;
}

TEST(test_oh_query_by_target)
{
    _init_svc();
    ozayn_oh_record_create(&_svc, "OP-1", "R1", "MOD-A", NULL, 0, NULL, NULL, NULL, 0, NULL);
    ozayn_oh_record_create(&_svc, "OP-2", "R2", "MOD-B", NULL, 0, NULL, NULL, NULL, 0, NULL);
    ozayn_oh_record_create(&_svc, "OP-3", "R3", "MOD-A", NULL, 0, NULL, NULL, NULL, 0, NULL);
    ozayn_oh_query_t filter;
    memset(&filter, 0, sizeof(filter));
    filter.filter_flags = OZAYN_OH_FILTER_TARGET;
    strncpy(filter.target, "MOD-A", OZAYN_OH_MAX_TARGET_LEN - 1);
    ozayn_oh_query_results_t results;
    ozayn_oh_query(&_svc, &filter, &results);
    ASSERT_EQ(results.result_count, 2);
    ASSERT_EQ(results.total_count, 2);
    ozayn_oh_service_shutdown(&_svc);
    return 0;
}

TEST(test_oh_query_by_state)
{
    _init_svc();
    ozayn_oh_record_t *r1 = NULL, *r2 = NULL;
    ozayn_oh_record_create(&_svc, "OP-1", "R1", "M", NULL, 0, NULL, NULL, NULL, 0, &r1);
    ozayn_oh_record_create(&_svc, "OP-2", "R2", "M", NULL, 0, NULL, NULL, NULL, 0, &r2);
    ozayn_oh_record_finalize(&_svc, r1->record_id,
        OZAYN_OH_STATE_SUCCEEDED, OZAYN_OH_RESULT_SUCCESS, 0, NULL);
    ozayn_oh_record_finalize(&_svc, r2->record_id,
        OZAYN_OH_STATE_FAILED, OZAYN_OH_RESULT_INTERNAL_ERROR, -1, NULL);
    ozayn_oh_query_t filter;
    memset(&filter, 0, sizeof(filter));
    filter.filter_flags = OZAYN_OH_FILTER_STATE;
    filter.state = OZAYN_OH_STATE_SUCCEEDED;
    ozayn_oh_query_results_t results;
    ozayn_oh_query(&_svc, &filter, &results);
    ASSERT_EQ(results.result_count, 1);
    ASSERT_STR_EQ(results.results[0]->operation_id, "OP-1");
    ozayn_oh_service_shutdown(&_svc);
    return 0;
}

TEST(test_oh_query_by_requester)
{
    _init_svc();
    ozayn_oh_record_create(&_svc, "OP-1", "R1", "M", NULL, 0, NULL, "alice", NULL, 0, NULL);
    ozayn_oh_record_create(&_svc, "OP-2", "R2", "M", NULL, 0, NULL, "bob", NULL, 0, NULL);
    ozayn_oh_query_t filter;
    memset(&filter, 0, sizeof(filter));
    filter.filter_flags = OZAYN_OH_FILTER_REQUESTER;
    strncpy(filter.requester_identity, "alice", OZAYN_OH_MAX_IDENTITY_LEN - 1);
    ozayn_oh_query_results_t results;
    ozayn_oh_query(&_svc, &filter, &results);
    ASSERT_EQ(results.result_count, 1);
    ASSERT_STR_EQ(results.results[0]->requester_identity, "alice");
    ozayn_oh_service_shutdown(&_svc);
    return 0;
}

TEST(test_oh_query_by_result)
{
    _init_svc();
    ozayn_oh_record_t *r1 = NULL, *r2 = NULL;
    ozayn_oh_record_create(&_svc, "OP-1", "R1", "M", NULL, 0, NULL, NULL, NULL, 0, &r1);
    ozayn_oh_record_create(&_svc, "OP-2", "R2", "M", NULL, 0, NULL, NULL, NULL, 0, &r2);
    ozayn_oh_record_finalize(&_svc, r1->record_id,
        OZAYN_OH_STATE_SUCCEEDED, OZAYN_OH_RESULT_SUCCESS, 0, NULL);
    ozayn_oh_record_finalize(&_svc, r2->record_id,
        OZAYN_OH_STATE_FAILED, OZAYN_OH_RESULT_AUTHORIZATION_FAILED, -1, NULL);
    ozayn_oh_query_t filter;
    memset(&filter, 0, sizeof(filter));
    filter.filter_flags = OZAYN_OH_FILTER_RESULT;
    filter.result = OZAYN_OH_RESULT_AUTHORIZATION_FAILED;
    ozayn_oh_query_results_t results;
    ozayn_oh_query(&_svc, &filter, &results);
    ASSERT_EQ(results.result_count, 1);
    ASSERT_STR_EQ(results.results[0]->operation_id, "OP-2");
    ozayn_oh_service_shutdown(&_svc);
    return 0;
}

TEST(test_oh_query_by_action)
{
    _init_svc();
    ozayn_oh_record_create(&_svc, "OP-1", "R1", "M", NULL, OZAYN_OH_ACTION_START, NULL, NULL, NULL, 0, NULL);
    ozayn_oh_record_create(&_svc, "OP-2", "R2", "M", NULL, OZAYN_OH_ACTION_STOP, NULL, NULL, NULL, 0, NULL);
    ozayn_oh_query_t filter;
    memset(&filter, 0, sizeof(filter));
    filter.filter_flags = OZAYN_OH_FILTER_ACTION;
    filter.action = OZAYN_OH_ACTION_STOP;
    ozayn_oh_query_results_t results;
    ozayn_oh_query(&_svc, &filter, &results);
    ASSERT_EQ(results.result_count, 1);
    ASSERT_STR_EQ(results.results[0]->operation_id, "OP-2");
    ozayn_oh_service_shutdown(&_svc);
    return 0;
}

TEST(test_oh_query_by_request_id)
{
    _init_svc();
    ozayn_oh_record_create(&_svc, "OP-1", "REQ-SPECIAL", "M", NULL, 0, NULL, NULL, NULL, 0, NULL);
    ozayn_oh_record_create(&_svc, "OP-2", "REQ-NORMAL", "M", NULL, 0, NULL, NULL, NULL, 0, NULL);
    ozayn_oh_query_t filter;
    memset(&filter, 0, sizeof(filter));
    filter.filter_flags = OZAYN_OH_FILTER_REQUEST_ID;
    strncpy(filter.request_id, "REQ-SPECIAL", OZAYN_OH_MAX_ID_LEN - 1);
    ozayn_oh_query_results_t results;
    ozayn_oh_query(&_svc, &filter, &results);
    ASSERT_EQ(results.result_count, 1);
    ASSERT_STR_EQ(results.results[0]->request_id, "REQ-SPECIAL");
    ozayn_oh_service_shutdown(&_svc);
    return 0;
}

TEST(test_oh_query_by_time_range)
{
    _init_svc();
    ozayn_oh_record_t *r1 = NULL, *r2 = NULL;
    ozayn_oh_record_create(&_svc, "OP-1", "R1", "M", NULL, 0, NULL, NULL, NULL, 0, &r1);
    ozayn_oh_record_create(&_svc, "OP-2", "R2", "M", NULL, 0, NULL, NULL, NULL, 0, &r2);
    ozayn_oh_record_finalize(&_svc, r1->record_id,
        OZAYN_OH_STATE_SUCCEEDED, OZAYN_OH_RESULT_SUCCESS, 0, NULL);
    /* r2 not finalized — no completed_time, query by time should exclude it */
    time_t now = time(NULL);
    ozayn_oh_query_t filter;
    memset(&filter, 0, sizeof(filter));
    filter.filter_flags = OZAYN_OH_FILTER_TIME_START | OZAYN_OH_FILTER_TIME_END;
    filter.time_start = now - 10;
    filter.time_end = now + 10;
    ozayn_oh_query_results_t results;
    ozayn_oh_query(&_svc, &filter, &results);
    ASSERT(results.result_count >= 1);
    ozayn_oh_service_shutdown(&_svc);
    return 0;
}

/* ============================================================
 * PAGINATION TESTS
 * ============================================================ */

TEST(test_oh_query_pagination)
{
    _init_svc();
    for (int i = 0; i < 10; i++) {
        char opid[32], reqid[32];
        snprintf(opid, sizeof(opid), "OP-%d", i);
        snprintf(reqid, sizeof(reqid), "REQ-%d", i);
        ozayn_oh_record_create(&_svc, opid, reqid, "MOD", NULL, 0, NULL, NULL, NULL, 0, NULL);
    }
    ozayn_oh_query_t filter;
    memset(&filter, 0, sizeof(filter));
    filter.limit = 3;
    filter.offset = 0;
    ozayn_oh_query_results_t page1;
    ozayn_oh_query(&_svc, &filter, &page1);
    ASSERT_EQ(page1.result_count, 3);
    ASSERT(page1.has_more);

    filter.offset = 3;
    ozayn_oh_query_results_t page2;
    ozayn_oh_query(&_svc, &filter, &page2);
    ASSERT_EQ(page2.result_count, 3);
    ASSERT(page2.has_more);

    filter.offset = 9;
    ozayn_oh_query_results_t page_last;
    ozayn_oh_query(&_svc, &filter, &page_last);
    ASSERT_EQ(page_last.result_count, 1);
    ASSERT(!page_last.has_more);
    ozayn_oh_service_shutdown(&_svc);
    return 0;
}

TEST(test_oh_query_empty)
{
    _init_svc();
    ozayn_oh_query_results_t results;
    ASSERT_EQ(ozayn_oh_query(&_svc, NULL, &results), OZAYN_OH_OK);
    ASSERT_EQ(results.result_count, 0);
    ASSERT_EQ(results.total_count, 0);
    ASSERT(!results.has_more);
    ozayn_oh_service_shutdown(&_svc);
    return 0;
}

TEST(test_oh_query_limit)
{
    _init_svc();
    for (int i = 0; i < 5; i++) {
        char opid[32], reqid[32];
        snprintf(opid, sizeof(opid), "OP-%d", i);
        snprintf(reqid, sizeof(reqid), "REQ-%d", i);
        ozayn_oh_record_create(&_svc, opid, reqid, "M", NULL, 0, NULL, NULL, NULL, 0, NULL);
    }
    ozayn_oh_query_t filter;
    memset(&filter, 0, sizeof(filter));
    filter.limit = 2;
    ozayn_oh_query_results_t results;
    ozayn_oh_query(&_svc, &filter, &results);
    ASSERT_EQ(results.result_count, 2);
    ASSERT(results.has_more);
    ozayn_oh_service_shutdown(&_svc);
    return 0;
}

TEST(test_oh_query_null)
{
    ASSERT_EQ(ozayn_oh_query(NULL, NULL, NULL), OZAYN_OH_ERR_NULL);
    return 0;
}

/* ============================================================
 * RETENTION TESTS
 * ============================================================ */

TEST(test_oh_retention_set_get)
{
    _init_svc();
    ozayn_oh_retention_t ret;
    memset(&ret, 0, sizeof(ret));
    ret.max_records = 50;
    ret.max_age_seconds = 86400;
    ret.retain_security_records = 0;
    ASSERT_EQ(ozayn_oh_retention_set(&_svc, &ret), OZAYN_OH_OK);
    const ozayn_oh_retention_t *got = ozayn_oh_retention_get(&_svc);
    ASSERT_NOT_NULL(got);
    ASSERT_EQ(got->max_records, 50);
    ASSERT_EQ(got->max_age_seconds, 86400);
    ASSERT(got->retain_security_records == 0);
    ozayn_oh_service_shutdown(&_svc);
    return 0;
}

TEST(test_oh_retention_check_count)
{
    _init_svc();
    /* Start with high limit, then lower it */
    ozayn_oh_retention_t ret;
    memset(&ret, 0, sizeof(ret));
    ret.max_records = 10;
    ret.retain_security_records = 0;
    ozayn_oh_retention_set(&_svc, &ret);
    for (int i = 0; i < 5; i++) {
        char opid[32], reqid[32];
        snprintf(opid, sizeof(opid), "OP-%d", i);
        snprintf(reqid, sizeof(reqid), "REQ-%d", i);
        ozayn_oh_record_create(&_svc, opid, reqid, "M", NULL, 0, NULL, NULL, NULL, 0, NULL);
    }
    /* Now lower the limit */
    ret.max_records = 3;
    ozayn_oh_retention_set(&_svc, &ret);
    int expired = ozayn_oh_retention_check(&_svc);
    ASSERT(expired > 0);
    ASSERT(_svc.count <= 3);
    ozayn_oh_service_shutdown(&_svc);
    return 0;
}

TEST(test_oh_retention_security_records)
{
    _init_svc();
    ozayn_oh_retention_t ret;
    memset(&ret, 0, sizeof(ret));
    ret.max_records = 2;
    ret.retain_security_records = 1;
    ozayn_oh_retention_set(&_svc, &ret);
    ozayn_oh_record_t *r1 = NULL, *r2 = NULL, *r3 = NULL;
    ozayn_oh_record_create(&_svc, "OP-1", "R1", "M", NULL, 0, NULL, NULL, NULL, 0, &r1);
    ozayn_oh_record_create(&_svc, "OP-2", "R2", "M", NULL, 0, NULL, NULL, NULL, 0, &r2);
    ozayn_oh_record_create(&_svc, "OP-3", "R3", "M", NULL, 0, NULL, NULL, NULL, 0, &r3);
    /* Finalize first two — they should be retained */
    ozayn_oh_record_finalize(&_svc, r1->record_id,
        OZAYN_OH_STATE_SUCCEEDED, OZAYN_OH_RESULT_SUCCESS, 0, NULL);
    ozayn_oh_record_finalize(&_svc, r2->record_id,
        OZAYN_OH_STATE_SUCCEEDED, OZAYN_OH_RESULT_SUCCESS, 0, NULL);
    ozayn_oh_retention_check(&_svc);
    ASSERT(_svc.count >= 2);
    ozayn_oh_service_shutdown(&_svc);
    return 0;
}

TEST(test_oh_cleanup_expired)
{
    _init_svc();
    ASSERT_EQ(ozayn_oh_cleanup_expired(&_svc), 0);
    ASSERT_EQ(ozayn_oh_cleanup_expired(NULL), 0);
    ozayn_oh_service_shutdown(&_svc);
    return 0;
}

TEST(test_oh_cleanup_all)
{
    _init_svc();
    ozayn_oh_record_create(&_svc, "OP-1", "R1", "M", NULL, 0, NULL, NULL, NULL, 0, NULL);
    ozayn_oh_record_create(&_svc, "OP-2", "R2", "M", NULL, 0, NULL, NULL, NULL, 0, NULL);
    int cleaned = ozayn_oh_cleanup_all(&_svc);
    ASSERT_EQ(cleaned, 2);
    ASSERT_EQ(_svc.count, 0);
    ASSERT_EQ(ozayn_oh_cleanup_all(NULL), 0);
    ozayn_oh_service_shutdown(&_svc);
    return 0;
}

/* ============================================================
 * STATISTICS TESTS
 * ============================================================ */

TEST(test_oh_get_stats)
{
    _init_svc();
    ozayn_oh_stats_t stats;
    memset(&stats, 0, sizeof(stats));
    ASSERT_EQ(ozayn_oh_get_stats(&_svc, &stats), OZAYN_OH_OK);
    ASSERT_EQ(stats.total_recorded, 0);
    ASSERT_EQ(stats.storage_capacity, OZAYN_OH_MAX_RECORDS);

    ozayn_oh_record_t *rec = NULL;
    ozayn_oh_record_create(&_svc, "OP-1", "R1", "M", NULL, 0, NULL, NULL, NULL, 0, &rec);
    ozayn_oh_record_finalize(&_svc, rec->record_id,
        OZAYN_OH_STATE_SUCCEEDED, OZAYN_OH_RESULT_SUCCESS, 0, NULL);
    ozayn_oh_get_stats(&_svc, &stats);
    ASSERT_EQ(stats.total_recorded, 1);
    ASSERT_EQ(stats.total_succeeded, 1);
    ASSERT_EQ(stats.current_count, 1);
    ASSERT_EQ(ozayn_oh_get_stats(NULL, NULL), OZAYN_OH_ERR_NULL);
    ozayn_oh_service_shutdown(&_svc);
    return 0;
}

TEST(test_oh_stats_all_terminal)
{
    _init_svc();
    struct { const char *op; const char *req; ozayn_oh_state_t st; ozayn_oh_result_t res; } cases[] = {
        {"OP-S", "R-S", OZAYN_OH_STATE_SUCCEEDED, OZAYN_OH_RESULT_SUCCESS},
        {"OP-F", "R-F", OZAYN_OH_STATE_FAILED, OZAYN_OH_RESULT_INTERNAL_ERROR},
        {"OP-C", "R-C", OZAYN_OH_STATE_CANCELLED, OZAYN_OH_RESULT_CANCELLED},
        {"OP-T", "R-T", OZAYN_OH_STATE_TIMEOUT, OZAYN_OH_RESULT_TIMEOUT},
        {"OP-R", "R-R", OZAYN_OH_STATE_REJECTED, OZAYN_OH_RESULT_REJECTED},
        {"OP-E", "R-E", OZAYN_OH_STATE_EXPIRED, OZAYN_OH_RESULT_EXPIRED},
        {"OP-U", "R-U", OZAYN_OH_STATE_UNAVAILABLE, OZAYN_OH_RESULT_UNAVAILABLE},
        {"OP-X", "R-X", OZAYN_OH_STATE_UNSUPPORTED, OZAYN_OH_RESULT_UNSUPPORTED},
    };
    for (int i = 0; i < 8; i++) {
        ozayn_oh_record_t *rec = NULL;
        ozayn_oh_record_create(&_svc, cases[i].op, cases[i].req, "M", NULL, 0, NULL, NULL, NULL, 0, &rec);
        ozayn_oh_record_finalize(&_svc, rec->record_id, cases[i].st, cases[i].res, 0, NULL);
    }
    ozayn_oh_stats_t stats;
    ozayn_oh_get_stats(&_svc, &stats);
    ASSERT_EQ(stats.total_succeeded, 1);
    ASSERT_EQ(stats.total_failed, 1);
    ASSERT_EQ(stats.total_cancelled, 1);
    ASSERT_EQ(stats.total_timeout, 1);
    ASSERT_EQ(stats.total_rejected, 1);
    ASSERT_EQ(stats.total_expired, 1);
    ASSERT_EQ(stats.total_unavailable, 1);
    ASSERT_EQ(stats.total_unsupported, 1);
    ozayn_oh_service_shutdown(&_svc);
    return 0;
}

/* ============================================================
 * NAME HELPER TESTS
 * ============================================================ */

TEST(test_oh_err_name)
{
    ASSERT_STR_EQ(ozayn_oh_err_name(OZAYN_OH_OK), "OK");
    ASSERT_STR_EQ(ozayn_oh_err_name(OZAYN_OH_ERR_NULL), "NULL");
    ASSERT_STR_EQ(ozayn_oh_err_name(OZAYN_OH_ERR_STORAGE_FULL), "STORAGE_FULL");
    ASSERT_STR_EQ(ozayn_oh_err_name(OZAYN_OH_ERR_IMMUTABLE), "IMMUTABLE");
    ASSERT_STR_EQ(ozayn_oh_err_name((ozayn_oh_err_t)999), "UNKNOWN");
    return 0;
}

TEST(test_oh_state_name)
{
    ASSERT_STR_EQ(ozayn_oh_state_name(OZAYN_OH_STATE_SUCCEEDED), "SUCCEEDED");
    ASSERT_STR_EQ(ozayn_oh_state_name(OZAYN_OH_STATE_FAILED), "FAILED");
    ASSERT_STR_EQ(ozayn_oh_state_name(OZAYN_OH_STATE_CANCELLED), "CANCELLED");
    ASSERT_STR_EQ(ozayn_oh_state_name(OZAYN_OH_STATE_TIMEOUT), "TIMEOUT");
    ASSERT_STR_EQ(ozayn_oh_state_name((ozayn_oh_state_t)99), "UNKNOWN");
    return 0;
}

TEST(test_oh_result_name)
{
    ASSERT_STR_EQ(ozayn_oh_result_name(OZAYN_OH_RESULT_SUCCESS), "SUCCESS");
    ASSERT_STR_EQ(ozayn_oh_result_name(OZAYN_OH_RESULT_TARGET_UNAVAILABLE), "TARGET_UNAVAILABLE");
    ASSERT_STR_EQ(ozayn_oh_result_name(OZAYN_OH_RESULT_AUTHORIZATION_FAILED), "AUTHORIZATION_FAILED");
    ASSERT_STR_EQ(ozayn_oh_result_name((ozayn_oh_result_t)99), "UNKNOWN");
    return 0;
}

TEST(test_oh_failure_name)
{
    ASSERT_STR_EQ(ozayn_oh_failure_name(OZAYN_OH_FAILURE_NONE), "NONE");
    ASSERT_STR_EQ(ozayn_oh_failure_name(OZAYN_OH_FAILURE_COMPONENT_DOWN), "COMPONENT_DOWN");
    ASSERT_STR_EQ(ozayn_oh_failure_name(OZAYN_OH_FAILURE_AUTH_DENIED), "AUTH_DENIED");
    ASSERT_STR_EQ(ozayn_oh_failure_name((ozayn_oh_failure_t)99), "UNKNOWN");
    return 0;
}

TEST(test_oh_action_name)
{
    ASSERT_STR_EQ(ozayn_oh_action_name(OZAYN_OH_ACTION_START), "START");
    ASSERT_STR_EQ(ozayn_oh_action_name(OZAYN_OH_ACTION_STOP), "STOP");
    ASSERT_STR_EQ(ozayn_oh_action_name(OZAYN_OH_ACTION_DIAGNOSTIC), "DIAGNOSTIC");
    ASSERT_STR_EQ(ozayn_oh_action_name((ozayn_oh_action_t)99), "UNKNOWN");
    return 0;
}

TEST(test_oh_event_type_name)
{
    ASSERT_STR_EQ(ozayn_oh_event_type_name(OZAYN_OH_EVENT_CREATED), "CREATED");
    ASSERT_STR_EQ(ozayn_oh_event_type_name(OZAYN_OH_EVENT_RECORD_FINALIZED), "RECORD_FINALIZED");
    ASSERT_STR_EQ(ozayn_oh_event_type_name((ozayn_oh_event_type_t)99), "UNKNOWN");
    return 0;
}

/* ============================================================
 * VALIDATION TESTS
 * ============================================================ */

TEST(test_oh_record_validate)
{
    ozayn_oh_record_t rec;
    memset(&rec, 0, sizeof(rec));
    ASSERT(!ozayn_oh_record_validate(NULL));
    ASSERT(!ozayn_oh_record_validate(&rec));

    strncpy(rec.record_id, "OHR-1", OZAYN_OH_MAX_ID_LEN - 1);
    ASSERT(!ozayn_oh_record_validate(&rec));

    strncpy(rec.operation_id, "OP-1", OZAYN_OH_MAX_ID_LEN - 1);
    ASSERT(!ozayn_oh_record_validate(&rec));

    strncpy(rec.request_id, "REQ-1", OZAYN_OH_MAX_ID_LEN - 1);
    ASSERT(!ozayn_oh_record_validate(&rec));

    strncpy(rec.target, "MOD", OZAYN_OH_MAX_TARGET_LEN - 1);
    ASSERT(!ozayn_oh_record_validate(&rec));

    rec.action = OZAYN_OH_ACTION_START;
    ASSERT(!ozayn_oh_record_validate(&rec));

    rec.created_time = time(NULL);
    ASSERT(ozayn_oh_record_validate(&rec));

    rec.finalized = 1;
    rec.final_state = OZAYN_OH_STATE_SUCCEEDED;
    ASSERT(ozayn_oh_record_validate(&rec));

    rec.final_state = (ozayn_oh_state_t)99;
    ASSERT(!ozayn_oh_record_validate(&rec));
    return 0;
}

TEST(test_oh_record_is_terminal)
{
    ASSERT(ozayn_oh_record_is_terminal(OZAYN_OH_STATE_SUCCEEDED));
    ASSERT(ozayn_oh_record_is_terminal(OZAYN_OH_STATE_FAILED));
    ASSERT(ozayn_oh_record_is_terminal(OZAYN_OH_STATE_CANCELLED));
    ASSERT(ozayn_oh_record_is_terminal(OZAYN_OH_STATE_TIMEOUT));
    ASSERT(ozayn_oh_record_is_terminal(OZAYN_OH_STATE_REJECTED));
    ASSERT(ozayn_oh_record_is_terminal(OZAYN_OH_STATE_EXPIRED));
    ASSERT(ozayn_oh_record_is_terminal(OZAYN_OH_STATE_UNAVAILABLE));
    ASSERT(ozayn_oh_record_is_terminal(OZAYN_OH_STATE_UNSUPPORTED));
    return 0;
}

/* ============================================================
 * EVENT / AUDIT TESTS
 * ============================================================ */

TEST(test_oh_emit_event)
{
    _init_svc();
    ASSERT_EQ(ozayn_oh_emit_event(&_svc, OZAYN_OH_EVENT_CREATED, "X", "X"),
              OZAYN_OH_OK);
    ASSERT_EQ(ozayn_oh_emit_event(NULL, OZAYN_OH_EVENT_CREATED, "X", "X"),
              OZAYN_OH_ERR_NULL);
    ozayn_oh_service_shutdown(&_svc);
    return 0;
}

TEST(test_oh_audit_record)
{
    _init_svc();
    ASSERT_EQ(ozayn_oh_audit_record(&_svc, "X", "TEST", "detail"),
              OZAYN_OH_OK);
    ASSERT_EQ(ozayn_oh_audit_record(NULL, "X", "X", "X"), OZAYN_OH_ERR_NULL);
    ASSERT_EQ(ozayn_oh_audit_record(&_svc, NULL, "X", "X"), OZAYN_OH_ERR_INVALID_PARAM);
    ozayn_oh_service_shutdown(&_svc);
    return 0;
}

/* ============================================================
 * SECURITY BOUNDARY TESTS
 * ============================================================ */

TEST(test_oh_global_singleton)
{
    ozayn_oh_service_t *g1 = ozayn_oh_get_global();
    ozayn_oh_service_t *g2 = ozayn_oh_get_global();
    ASSERT_NOT_NULL(g1);
    ASSERT(g1 == g2);
    return 0;
}

TEST(test_oh_no_secrets_in_record)
{
    _init_svc();
    ozayn_oh_record_t *rec = NULL;
    ozayn_oh_record_create(&_svc, "OP-1", "REQ-1", "MOD",
        "password=secret key=abc token=xyz",
        OZAYN_OH_ACTION_START, "VIS.READ", "user1", "sess1", 3, &rec);
    ASSERT(rec->active == 1);
    /* Safe metadata should not contain secrets */
    ASSERT(rec->safe_metadata[0] == '\0');
    ozayn_oh_service_shutdown(&_svc);
    return 0;
}

TEST(test_oh_record_finalize_not_init)
{
    memset(&_svc, 0, sizeof(_svc));
    ASSERT_EQ(ozayn_oh_record_finalize(&_svc, "X", OZAYN_OH_STATE_SUCCEEDED,
        OZAYN_OH_RESULT_SUCCESS, 0, NULL), OZAYN_OH_ERR_NOT_INITIALIZED);
    return 0;
}

TEST(test_oh_record_finalize_null)
{
    ASSERT_EQ(ozayn_oh_record_finalize(NULL, "X", OZAYN_OH_STATE_SUCCEEDED,
        OZAYN_OH_RESULT_SUCCESS, 0, NULL), OZAYN_OH_ERR_NULL);
    return 0;
}

TEST(test_oh_attempt_start_null)
{
    ASSERT_EQ(ozayn_oh_attempt_start(NULL, "X", NULL), OZAYN_OH_ERR_NULL);
    return 0;
}

TEST(test_oh_attempt_start_not_init)
{
    memset(&_svc, 0, sizeof(_svc));
    ASSERT_EQ(ozayn_oh_attempt_start(&_svc, "X", NULL), OZAYN_OH_ERR_NOT_INITIALIZED);
    return 0;
}

TEST(test_oh_attempt_complete_null)
{
    ASSERT_EQ(ozayn_oh_attempt_complete(NULL, "X", "X", 0, 0, 0, NULL),
              OZAYN_OH_ERR_NULL);
    return 0;
}

TEST(test_oh_attempt_complete_not_init)
{
    memset(&_svc, 0, sizeof(_svc));
    ASSERT_EQ(ozayn_oh_attempt_complete(&_svc, "X", "X", 0, 0, 0, NULL),
              OZAYN_OH_ERR_NOT_INITIALIZED);
    return 0;
}

/* ============================================================
 * CONCURRENCY TESTS (simulated)
 * ============================================================ */

TEST(test_oh_concurrent_writes)
{
    _init_svc();
    ozayn_oh_record_t *r1 = NULL, *r2 = NULL, *r3 = NULL;
    ozayn_oh_record_create(&_svc, "OP-A", "RA", "M", NULL, 0, NULL, "alice", NULL, 0, &r1);
    ozayn_oh_record_create(&_svc, "OP-B", "RB", "M", NULL, 0, NULL, "bob", NULL, 0, &r2);
    ozayn_oh_record_create(&_svc, "OP-C", "RC", "M", NULL, 0, NULL, "carol", NULL, 0, &r3);
    /* Simulate concurrent completions */
    ozayn_oh_record_finalize(&_svc, r1->record_id,
        OZAYN_OH_STATE_SUCCEEDED, OZAYN_OH_RESULT_SUCCESS, 0, NULL);
    ozayn_oh_record_finalize(&_svc, r2->record_id,
        OZAYN_OH_STATE_FAILED, OZAYN_OH_RESULT_INTERNAL_ERROR, -1, NULL);
    ozayn_oh_record_finalize(&_svc, r3->record_id,
        OZAYN_OH_STATE_CANCELLED, OZAYN_OH_RESULT_CANCELLED, 0, NULL);
    ASSERT_EQ(_svc.count, 3);
    ASSERT(r1->finalized && r2->finalized && r3->finalized);
    ozayn_oh_service_shutdown(&_svc);
    return 0;
}

TEST(test_oh_write_and_query)
{
    _init_svc();
    for (int i = 0; i < 20; i++) {
        char opid[32], reqid[32];
        snprintf(opid, sizeof(opid), "OP-%d", i);
        snprintf(reqid, sizeof(reqid), "REQ-%d", i);
        ozayn_oh_record_create(&_svc, opid, reqid, "M", NULL, 0, NULL, NULL, NULL, 0, NULL);
    }
    ozayn_oh_query_results_t results;
    ozayn_oh_query(&_svc, NULL, &results);
    ASSERT_EQ(results.result_count, 20);
    ozayn_oh_service_shutdown(&_svc);
    return 0;
}

TEST(test_oh_write_and_retention)
{
    _init_svc();
    ozayn_oh_retention_t ret;
    memset(&ret, 0, sizeof(ret));
    ret.max_records = 5;
    ret.retain_security_records = 0;
    ozayn_oh_retention_set(&_svc, &ret);
    for (int i = 0; i < 10; i++) {
        char opid[32], reqid[32];
        snprintf(opid, sizeof(opid), "OP-%d", i);
        snprintf(reqid, sizeof(reqid), "REQ-%d", i);
        ozayn_oh_record_create(&_svc, opid, reqid, "M", NULL, 0, NULL, NULL, NULL, 0, NULL);
    }
    ozayn_oh_retention_check(&_svc);
    ASSERT(_svc.count <= 5);
    ozayn_oh_service_shutdown(&_svc);
    return 0;
}

/* ============================================================
 * STORAGE FAILURE TESTS
 * ============================================================ */

TEST(test_oh_storage_full)
{
    _init_svc();
    ozayn_oh_retention_t ret;
    memset(&ret, 0, sizeof(ret));
    ret.max_records = 2;
    ozayn_oh_retention_set(&_svc, &ret);
    ozayn_oh_record_create(&_svc, "OP-1", "R1", "M", NULL, 0, NULL, NULL, NULL, 0, NULL);
    ozayn_oh_record_create(&_svc, "OP-2", "R2", "M", NULL, 0, NULL, NULL, NULL, 0, NULL);
    ASSERT_EQ(ozayn_oh_record_create(&_svc, "OP-3", "R3", "M", NULL, 0, NULL, NULL, NULL, 0, NULL),
              OZAYN_OH_ERR_STORAGE_FULL);
    ozayn_oh_service_shutdown(&_svc);
    return 0;
}

TEST(test_oh_operation_succeeds_but_history_fails)
{
    _init_svc();
    /* Start with high limit */
    ozayn_oh_retention_t ret;
    memset(&ret, 0, sizeof(ret));
    ret.max_records = 10;
    ozayn_oh_retention_set(&_svc, &ret);
    /* First record succeeds */
    ozayn_oh_record_create(&_svc, "OP-1", "R1", "M", NULL, 0, NULL, NULL, NULL, 0, NULL);
    /* Lower limit to 1 — second create should fail */
    ret.max_records = 1;
    ozayn_oh_retention_set(&_svc, &ret);
    ASSERT_EQ(ozayn_oh_record_create(&_svc, "OP-2", "R2", "M", NULL, 0, NULL, NULL, NULL, 0, NULL),
              OZAYN_OH_ERR_STORAGE_FULL);
    /* First record still works */
    ASSERT_NOT_NULL(ozayn_oh_record_get_by_operation(&_svc, "OP-1"));
    ozayn_oh_service_shutdown(&_svc);
    return 0;
}

/* ============================================================
 * CORRELATION TESTS
 * ============================================================ */

TEST(test_oh_correlation_ids)
{
    _init_svc();
    ozayn_oh_record_t *rec = NULL;
    ozayn_oh_record_create(&_svc, "OP-1", "REQ-1", "MOD", NULL, 0, NULL, "user1", "sess1", 0, &rec);
    ozayn_oh_attempt_t *att = NULL;
    ozayn_oh_attempt_start(&_svc, rec->record_id, &att);
    ozayn_oh_attempt_complete(&_svc, rec->record_id, att->attempt_id,
        OZAYN_OH_STATE_SUCCEEDED, OZAYN_OH_RESULT_SUCCESS, 0, NULL);
    ozayn_oh_record_finalize(&_svc, rec->record_id,
        OZAYN_OH_STATE_SUCCEEDED, OZAYN_OH_RESULT_SUCCESS, 0, NULL);
    /* Verify all IDs are present for correlation */
    ASSERT(rec->record_id[0] != '\0');
    ASSERT(rec->operation_id[0] != '\0');
    ASSERT(rec->request_id[0] != '\0');
    ASSERT(att->attempt_id[0] != '\0');
    ASSERT(rec->requester_identity[0] != '\0');
    ASSERT(rec->session_id[0] != '\0');
    ozayn_oh_service_shutdown(&_svc);
    return 0;
}

/* ============================================================
 * TIMING TESTS
 * ============================================================ */

TEST(test_oh_timing)
{
    _init_svc();
    ozayn_oh_record_t *rec = NULL;
    ozayn_oh_record_create(&_svc, "OP-1", "REQ-1", "MOD", NULL, 0, NULL, NULL, NULL, 0, &rec);
    ASSERT(rec->created_time > 0);
    ASSERT_EQ(rec->queued_time, 0);
    ASSERT_EQ(rec->started_time, 0);
    ASSERT_EQ(rec->completed_time, 0);

    /* Simulate timing with past timestamps */
    rec->queued_time = rec->created_time;
    rec->started_time = rec->created_time;
    ozayn_oh_record_finalize(&_svc, rec->record_id,
        OZAYN_OH_STATE_SUCCEEDED, OZAYN_OH_RESULT_SUCCESS, 0, NULL);
    ASSERT(rec->completed_time >= rec->created_time);
    ASSERT(rec->total_duration_ms >= 0);
    ASSERT(rec->queue_duration_ms >= 0);
    ASSERT(rec->execution_duration_ms >= 0);
    ozayn_oh_service_shutdown(&_svc);
    return 0;
}

TEST(test_oh_attempt_timing)
{
    _init_svc();
    ozayn_oh_record_t *rec = NULL;
    ozayn_oh_record_create(&_svc, "OP-1", "REQ-1", "MOD", NULL, 0, NULL, NULL, NULL, 0, &rec);
    ozayn_oh_attempt_t *att = NULL;
    ozayn_oh_attempt_start(&_svc, rec->record_id, &att);
    ASSERT(att->started_time > 0);
    ASSERT_EQ(att->completed_time, 0);
    ozayn_oh_attempt_complete(&_svc, rec->record_id, att->attempt_id,
        OZAYN_OH_STATE_SUCCEEDED, OZAYN_OH_RESULT_SUCCESS, 0, NULL);
    ASSERT(att->completed_time >= att->started_time);
    ASSERT(att->duration_ms >= 0);
    ozayn_oh_service_shutdown(&_svc);
    return 0;
}

/* ============================================================
 * RETRY TRACKING TESTS
 * ============================================================ */

TEST(test_oh_retry_tracking)
{
    _init_svc();
    ozayn_oh_record_t *rec = NULL;
    ozayn_oh_record_create(&_svc, "OP-1", "REQ-1", "MOD", NULL, 0, NULL, NULL, NULL, 5, &rec);
    ASSERT_EQ(rec->retry_count, 0);
    ASSERT_EQ(rec->max_retries, 5);

    for (int i = 0; i < 3; i++) {
        ozayn_oh_attempt_t *att = NULL;
        ozayn_oh_attempt_start(&_svc, rec->record_id, &att);
        ozayn_oh_attempt_complete(&_svc, rec->record_id, att->attempt_id,
            OZAYN_OH_STATE_FAILED, OZAYN_OH_RESULT_INTERNAL_ERROR, -1, "fail");
    }
    ASSERT_EQ(rec->retry_count, 3);
    ASSERT_EQ(rec->attempt_count, 3);
    ozayn_oh_service_shutdown(&_svc);
    return 0;
}

/* ============================================================
 * FULL LIFECYCLE TEST
 * ============================================================ */

TEST(test_oh_full_lifecycle)
{
    _init_svc();

    /* Create record */
    ozayn_oh_record_t *rec = NULL;
    ASSERT_EQ(ozayn_oh_record_create(&_svc, "OP-VISION", "REQ-1",
        "MOD-VISION", "VIS-CAP", OZAYN_OH_ACTION_START, "VIS.READ",
        "user-1", "sess-1", 3, &rec), OZAYN_OH_OK);

    /* First attempt — fails */
    ozayn_oh_attempt_t *a1 = NULL;
    ozayn_oh_attempt_start(&_svc, rec->record_id, &a1);
    ozayn_oh_attempt_complete(&_svc, rec->record_id, a1->attempt_id,
        OZAYN_OH_STATE_FAILED, OZAYN_OH_RESULT_TARGET_UNAVAILABLE, -1, "target down");

    /* Second attempt — fails */
    ozayn_oh_attempt_t *a2 = NULL;
    ozayn_oh_attempt_start(&_svc, rec->record_id, &a2);
    ozayn_oh_attempt_complete(&_svc, rec->record_id, a2->attempt_id,
        OZAYN_OH_STATE_FAILED, OZAYN_OH_RESULT_TARGET_UNAVAILABLE, -1, "target still down");

    /* Third attempt — succeeds */
    ozayn_oh_attempt_t *a3 = NULL;
    ozayn_oh_attempt_start(&_svc, rec->record_id, &a3);
    ozayn_oh_attempt_complete(&_svc, rec->record_id, a3->attempt_id,
        OZAYN_OH_STATE_SUCCEEDED, OZAYN_OH_RESULT_SUCCESS, 0, NULL);

    /* Finalize */
    ASSERT_EQ(ozayn_oh_record_finalize(&_svc, rec->record_id,
        OZAYN_OH_STATE_SUCCEEDED, OZAYN_OH_RESULT_SUCCESS, 0, NULL), OZAYN_OH_OK);

    /* Verify */
    ASSERT(rec->finalized == 1);
    ASSERT_EQ(rec->attempt_count, 3);
    ASSERT_EQ(rec->retry_count, 2);
    ASSERT_STR_EQ(rec->operation_id, "OP-VISION");
    ASSERT_STR_EQ(rec->target, "MOD-VISION");
    ASSERT_STR_EQ(rec->capability, "VIS-CAP");
    ASSERT_EQ(rec->action, OZAYN_OH_ACTION_START);
    ASSERT_STR_EQ(rec->requester_identity, "user-1");
    ASSERT(rec->created_time > 0);
    ASSERT(rec->completed_time > 0);
    ASSERT(rec->total_duration_ms >= 0);

    /* Verify query finds it */
    const ozayn_oh_record_t *found = ozayn_oh_record_get(&_svc, rec->record_id);
    ASSERT_NOT_NULL(found);
    ASSERT(found->finalized == 1);

    /* Verify attempts preserved */
    ASSERT(strcmp(a1->attempt_id, a2->attempt_id) != 0);
    ASSERT(strcmp(a2->attempt_id, a3->attempt_id) != 0);
    ASSERT(a1->attempt_state == OZAYN_OH_STATE_FAILED);
    ASSERT(a3->attempt_state == OZAYN_OH_STATE_SUCCEEDED);

    /* Verify immutability */
    ASSERT_EQ(ozayn_oh_record_finalize(&_svc, rec->record_id,
        OZAYN_OH_STATE_FAILED, OZAYN_OH_RESULT_INTERNAL_ERROR, -1, NULL),
        OZAYN_OH_ERR_IMMUTABLE);

    /* Verify no new attempts after finalization */
    ASSERT_EQ(ozayn_oh_attempt_start(&_svc, rec->record_id, NULL),
              OZAYN_OH_ERR_IMMUTABLE);

    ozayn_oh_service_shutdown(&_svc);
    return 0;
}

/* ============================================================
 * TEST RUNNER
 * ============================================================ */

int run_operation_history_tests(void)
{
    SUITE_BEGIN("Operation History & Execution Records");

    /* Lifecycle */
    RUN(test_oh_init);
    RUN(test_oh_init_null);
    RUN(test_oh_init_double);
    RUN(test_oh_init_default_retention);
    RUN(test_oh_init_custom_retention);
    RUN(test_oh_shutdown);
    RUN(test_oh_shutdown_null);
    RUN(test_oh_is_initialized);

    /* Record Creation */
    RUN(test_oh_record_create);
    RUN(test_oh_record_create_null);
    RUN(test_oh_record_create_not_init);
    RUN(test_oh_record_create_empty_operation_id);
    RUN(test_oh_record_create_empty_request_id);
    RUN(test_oh_record_create_empty_target);
    RUN(test_oh_record_create_invalid_action);
    RUN(test_oh_record_create_duplicate);
    RUN(test_oh_record_create_generates_id);
    RUN(test_oh_record_create_optional_fields);

    /* Record Finalization */
    RUN(test_oh_record_finalize);
    RUN(test_oh_record_finalize_not_terminal);
    RUN(test_oh_record_finalize_immutable);
    RUN(test_oh_record_finalize_not_found);
    RUN(test_oh_record_finalize_failure_detail);
    RUN(test_oh_record_finalize_all_terminal_states);

    /* Attempts */
    RUN(test_oh_attempt_start);
    RUN(test_oh_attempt_start_not_found);
    RUN(test_oh_attempt_start_after_finalize);
    RUN(test_oh_attempt_multiple);
    RUN(test_oh_attempt_complete);
    RUN(test_oh_attempt_complete_not_found);
    RUN(test_oh_attempt_complete_wrong_attempt_id);
    RUN(test_oh_attempt_complete_failed_increments_retry);

    /* Immutability */
    RUN(test_oh_record_is_finalized);
    RUN(test_oh_record_is_finalized_not_found);

    /* Query */
    RUN(test_oh_record_get);
    RUN(test_oh_record_get_by_request);
    RUN(test_oh_record_count);
    RUN(test_oh_total_recorded);
    RUN(test_oh_query_no_filter);
    RUN(test_oh_query_by_target);
    RUN(test_oh_query_by_state);
    RUN(test_oh_query_by_requester);
    RUN(test_oh_query_by_result);
    RUN(test_oh_query_by_action);
    RUN(test_oh_query_by_request_id);
    RUN(test_oh_query_by_time_range);
    RUN(test_oh_query_empty);
    RUN(test_oh_query_limit);
    RUN(test_oh_query_null);

    /* Pagination */
    RUN(test_oh_query_pagination);

    /* Retention */
    RUN(test_oh_retention_set_get);
    RUN(test_oh_retention_check_count);
    RUN(test_oh_retention_security_records);
    RUN(test_oh_cleanup_expired);
    RUN(test_oh_cleanup_all);

    /* Statistics */
    RUN(test_oh_get_stats);
    RUN(test_oh_stats_all_terminal);

    /* Name Helpers */
    RUN(test_oh_err_name);
    RUN(test_oh_state_name);
    RUN(test_oh_result_name);
    RUN(test_oh_failure_name);
    RUN(test_oh_action_name);
    RUN(test_oh_event_type_name);

    /* Validation */
    RUN(test_oh_record_validate);
    RUN(test_oh_record_is_terminal);

    /* Events / Audit */
    RUN(test_oh_emit_event);
    RUN(test_oh_audit_record);

    /* Security */
    RUN(test_oh_global_singleton);
    RUN(test_oh_no_secrets_in_record);
    RUN(test_oh_record_finalize_not_init);
    RUN(test_oh_record_finalize_null);
    RUN(test_oh_attempt_start_null);
    RUN(test_oh_attempt_start_not_init);
    RUN(test_oh_attempt_complete_null);
    RUN(test_oh_attempt_complete_not_init);

    /* Concurrency */
    RUN(test_oh_concurrent_writes);
    RUN(test_oh_write_and_query);
    RUN(test_oh_write_and_retention);

    /* Storage Failure */
    RUN(test_oh_storage_full);
    RUN(test_oh_operation_succeeds_but_history_fails);

    /* Correlation */
    RUN(test_oh_correlation_ids);

    /* Timing */
    RUN(test_oh_timing);
    RUN(test_oh_attempt_timing);

    /* Retry Tracking */
    RUN(test_oh_retry_tracking);

    /* Full Lifecycle */
    RUN(test_oh_full_lifecycle);

    SUITE_END();
    return TOTAL_FAIL();
}
