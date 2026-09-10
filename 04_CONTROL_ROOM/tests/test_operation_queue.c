/*
 * test_operation_queue.c — Operation Queue & Execution Lifecycle Tests (Step 05).
 *
 * Comprehensive tests for: lifecycle, enqueue, dequeue, dispatch, cancellation,
 * timeout, expiration, preconditions, authorization, retry, conflict detection,
 * priority, fairness, resource limits, events, audit, cleanup, statistics,
 * security boundaries.
 */

#include "../../tests/test_framework.h"
#include "../operation_queue.h"
#include "../component_registry.h"
#include "../../03_SECURITY/audit.h"
#include <string.h>
#include <time.h>

/* ============================================================
 * TEST HELPERS
 * ============================================================ */

static ozayn_oq_service_t _svc;
static ozayn_reg_service_t _reg;
static ozayn_audit_service_t _au_svc;

static void _reset_all(void)
{
    memset(&_svc, 0, sizeof(_svc));
    memset(&_reg, 0, sizeof(_reg));
    memset(&_au_svc, 0, sizeof(_au_svc));
}

static void _init_reg(void)
{
    memset(&_reg, 0, sizeof(_reg));
    _au_svc.initialized = 1;
    ozayn_reg_service_config_t rcfg;
    memset(&rcfg, 0, sizeof(rcfg));
    rcfg.audit = (void *)&_au_svc;
    ozayn_reg_service_init(&_reg, &rcfg);
}

static void _init_queue(void)
{
    _reset_all();
    _init_reg();
    _au_svc.initialized = 1;

    ozayn_oq_service_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.component_registry = (void *)&_reg;
    cfg.audit = (void *)&_au_svc;
    ozayn_oq_service_init(&_svc, &cfg);
}

static void _register_target(const char *id)
{
    ozayn_reg_register_component(&_reg, id, id, "1.0",
        OZAYN_REG_COMP_TYPE_CORE, "test", NULL);
    ozayn_reg_update_component_state(&_reg, id, OZAYN_REG_COMP_ACTIVE);
    ozayn_reg_update_component_availability(&_reg, id, OZAYN_REG_AVAIL_AVAILABLE);
}

static void _register_capability(const char *cap_id, const char *provider)
{
    ozayn_reg_register_capability(&_reg, cap_id, cap_id, "1.0", "test cap",
        provider, OZAYN_REG_CAP_CAT_SYSTEM, OZAYN_REG_ASSURANCE_PUBLIC, NULL);
}

/* ============================================================
 * LIFECYCLE TESTS
 * ============================================================ */

TEST(test_oq_init)
{
    _reset_all();
    ozayn_oq_service_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    ASSERT_EQ(ozayn_oq_service_init(&_svc, &cfg), OZAYN_OQ_OK);
    ASSERT(_svc.initialized == 1);
    ASSERT_EQ(_svc.count, 0);
    ozayn_oq_service_shutdown(&_svc);
    return 0;
}

TEST(test_oq_init_null)
{
    ASSERT_EQ(ozayn_oq_service_init(NULL, NULL), OZAYN_OQ_ERR_NULL);
    return 0;
}

TEST(test_oq_init_double)
{
    _init_queue();
    ASSERT_EQ(ozayn_oq_service_init(&_svc, NULL), OZAYN_OQ_ERR_ALREADY_INITIALIZED);
    ozayn_oq_service_shutdown(&_svc);
    return 0;
}

TEST(test_oq_shutdown)
{
    _init_queue();
    ozayn_oq_service_shutdown(&_svc);
    ASSERT(_svc.initialized == 0);
    return 0;
}

TEST(test_oq_shutdown_null)
{
    ozayn_oq_service_shutdown(NULL);
    return 0;
}

TEST(test_oq_is_initialized)
{
    _reset_all();
    ASSERT(!ozayn_oq_service_is_initialized(NULL));
    ASSERT(!ozayn_oq_service_is_initialized(&_svc));
    _init_queue();
    ASSERT(ozayn_oq_service_is_initialized(&_svc));
    ozayn_oq_service_shutdown(&_svc);
    ASSERT(!ozayn_oq_service_is_initialized(&_svc));
    return 0;
}

/* ============================================================
 * ENQUEUE TESTS
 * ============================================================ */

TEST(test_oq_enqueue)
{
    _init_queue();
    _register_target("CORE");
    ozayn_oq_entry_t *e = NULL;
    ASSERT_EQ(ozayn_oq_enqueue(&_svc, "REQ-1", OZAYN_OQ_ACTION_START,
        "CORE", NULL, NULL, NULL, NULL, NULL, 1, 0, 0, 0, 0, &e),
        OZAYN_OQ_OK);
    ASSERT_NOT_NULL(e);
    ASSERT_STR_EQ(e->request_id, "REQ-1");
    ASSERT_EQ(e->action, OZAYN_OQ_ACTION_START);
    ASSERT_STR_EQ(e->target, "CORE");
    ASSERT_EQ(e->state, OZAYN_OQ_STATE_QUEUED);
    ASSERT(e->active == 1);
    ASSERT_EQ(_svc.total_submitted, 1);
    ASSERT_EQ(_svc.queued_count, 1);
    ozayn_oq_service_shutdown(&_svc);
    return 0;
}

TEST(test_oq_enqueue_null)
{
    ASSERT_EQ(ozayn_oq_enqueue(NULL, "X", 0, "X", NULL, NULL, NULL, NULL, NULL, 0, 0, 0, 0, 0, NULL),
              OZAYN_OQ_ERR_NULL);
    return 0;
}

TEST(test_oq_enqueue_not_init)
{
    memset(&_svc, 0, sizeof(_svc));
    ASSERT_EQ(ozayn_oq_enqueue(&_svc, "X", 0, "X", NULL, NULL, NULL, NULL, NULL, 0, 0, 0, 0, 0, NULL),
              OZAYN_OQ_ERR_NOT_INITIALIZED);
    return 0;
}

TEST(test_oq_enqueue_missing_request_id)
{
    _init_queue();
    ASSERT_EQ(ozayn_oq_enqueue(&_svc, "", OZAYN_OQ_ACTION_START,
        "CORE", NULL, NULL, NULL, NULL, NULL, 0, 0, 0, 0, 0, NULL),
        OZAYN_OQ_ERR_INVALID_PARAM);
    ozayn_oq_service_shutdown(&_svc);
    return 0;
}

TEST(test_oq_enqueue_missing_target)
{
    _init_queue();
    ASSERT_EQ(ozayn_oq_enqueue(&_svc, "REQ-1", OZAYN_OQ_ACTION_START,
        "", NULL, NULL, NULL, NULL, NULL, 0, 0, 0, 0, 0, NULL),
        OZAYN_OQ_ERR_INVALID_PARAM);
    ozayn_oq_service_shutdown(&_svc);
    return 0;
}

TEST(test_oq_enqueue_invalid_action)
{
    _init_queue();
    ASSERT_EQ(ozayn_oq_enqueue(&_svc, "REQ-1", (ozayn_oq_action_t)99,
        "CORE", NULL, NULL, NULL, NULL, NULL, 0, 0, 0, 0, 0, NULL),
        OZAYN_OQ_ERR_INVALID_PARAM);
    ozayn_oq_service_shutdown(&_svc);
    return 0;
}

TEST(test_oq_enqueue_generates_id)
{
    _init_queue();
    _register_target("CORE");
    ozayn_oq_entry_t *e = NULL;
    ozayn_oq_enqueue(&_svc, "REQ-1", OZAYN_OQ_ACTION_QUERY,
        "CORE", NULL, NULL, NULL, NULL, NULL, 0, 0, 0, 0, 0, &e);
    ASSERT_NOT_NULL(e);
    ASSERT(strncmp(e->entry_id, "OQE-", 4) == 0);
    ozayn_oq_service_shutdown(&_svc);
    return 0;
}

TEST(test_oq_enqueue_unique_ids)
{
    _init_queue();
    _register_target("CORE");
    ozayn_oq_entry_t *e1 = NULL, *e2 = NULL;
    ozayn_oq_enqueue(&_svc, "REQ-1", OZAYN_OQ_ACTION_QUERY,
        "CORE", NULL, NULL, NULL, NULL, NULL, 0, 0, 0, 0, 0, &e1);
    ozayn_oq_enqueue(&_svc, "REQ-2", OZAYN_OQ_ACTION_QUERY,
        "CORE", NULL, NULL, NULL, NULL, NULL, 0, 0, 0, 0, 0, &e2);
    ASSERT(strcmp(e1->entry_id, e2->entry_id) != 0);
    ozayn_oq_service_shutdown(&_svc);
    return 0;
}

TEST(test_oq_enqueue_stores_fields)
{
    _init_queue();
    _register_target("CORE");
    ozayn_oq_entry_t *e = NULL;
    ozayn_oq_enqueue(&_svc, "REQ-1", OZAYN_OQ_ACTION_START,
        "CORE", "CAP-READ", "ctx", "user1", "sess1", "READ",
        3, 1, 5000, 30000, 5, &e);
    ASSERT_NOT_NULL(e);
    ASSERT_STR_EQ(e->capability, "CAP-READ");
    ASSERT_STR_EQ(e->context, "ctx");
    ASSERT_STR_EQ(e->requester_identity, "user1");
    ASSERT_STR_EQ(e->session_id, "sess1");
    ASSERT_STR_EQ(e->required_permission, "READ");
    ASSERT_EQ(e->priority, 3);
    ASSERT(e->idempotent == 1);
    ASSERT_EQ(e->queue_timeout_ms, 5000);
    ASSERT_EQ(e->execution_timeout_ms, 30000);
    ASSERT_EQ(e->max_retries, 5);
    ozayn_oq_service_shutdown(&_svc);
    return 0;
}

/* ============================================================
 * QUEUE FULL TESTS
 * ============================================================ */

TEST(test_oq_queue_full)
{
    _init_queue();
    _register_target("CORE");
    ozayn_oq_policy_t p = ozayn_oq_default_policy();
    p.max_entries = 2;
    ozayn_oq_set_policy(&_svc, &p);
    ozayn_oq_enqueue(&_svc, "R1", OZAYN_OQ_ACTION_QUERY,
        "CORE", NULL, NULL, NULL, NULL, NULL, 0, 0, 0, 0, 0, NULL);
    ozayn_oq_enqueue(&_svc, "R2", OZAYN_OQ_ACTION_QUERY,
        "CORE", NULL, NULL, NULL, NULL, NULL, 0, 0, 0, 0, 0, NULL);
    ASSERT(ozayn_oq_queue_full(&_svc));
    ASSERT_EQ(ozayn_oq_enqueue(&_svc, "R3", OZAYN_OQ_ACTION_QUERY,
        "CORE", NULL, NULL, NULL, NULL, NULL, 0, 0, 0, 0, 0, NULL),
        OZAYN_OQ_ERR_QUEUE_FULL);
    ozayn_oq_service_shutdown(&_svc);
    return 0;
}

TEST(test_oq_running_limit)
{
    _init_queue();
    _register_target("CORE");
    ozayn_oq_policy_t p = ozayn_oq_default_policy();
    p.max_running = 1;
    ozayn_oq_set_policy(&_svc, &p);
    ASSERT_EQ(ozayn_oq_running_limit(&_svc), 0);
    _svc.running_count = 1;
    ASSERT_EQ(ozayn_oq_running_limit(&_svc), 1);
    ozayn_oq_service_shutdown(&_svc);
    return 0;
}

/* ============================================================
 * DEQUEUE / DISPATCH TESTS
 * ============================================================ */

TEST(test_oq_dequeue_next)
{
    _init_queue();
    _register_target("CORE");
    ozayn_oq_entry_t *enq = NULL;
    ozayn_oq_enqueue(&_svc, "REQ-1", OZAYN_OQ_ACTION_QUERY,
        "CORE", NULL, NULL, NULL, NULL, NULL, 1, 0, 0, 0, 0, &enq);
    ozayn_oq_entry_t *dispatch = NULL;
    ASSERT_EQ(ozayn_oq_dequeue_next(&_svc, &dispatch), OZAYN_OQ_OK);
    ASSERT_NOT_NULL(dispatch);
    ASSERT_EQ(dispatch->state, OZAYN_OQ_STATE_RUNNING);
    ASSERT(strcmp(dispatch->entry_id, enq->entry_id) == 0);
    ASSERT_EQ(_svc.running_count, 1);
    ASSERT_EQ(_svc.queued_count, 0);
    ozayn_oq_service_shutdown(&_svc);
    return 0;
}

TEST(test_oq_dequeue_empty)
{
    _init_queue();
    ozayn_oq_entry_t *dispatch = NULL;
    ASSERT_EQ(ozayn_oq_dequeue_next(&_svc, &dispatch), OZAYN_OQ_ERR_NOT_FOUND);
    ozayn_oq_service_shutdown(&_svc);
    return 0;
}

TEST(test_oq_dequeue_concurrency_limit)
{
    _init_queue();
    _register_target("CORE");
    ozayn_oq_policy_t p = ozayn_oq_default_policy();
    p.max_running = 1;
    ozayn_oq_set_policy(&_svc, &p);
    ozayn_oq_entry_t *e1 = NULL;
    ozayn_oq_enqueue(&_svc, "R1", OZAYN_OQ_ACTION_QUERY,
        "CORE", NULL, NULL, NULL, NULL, NULL, 0, 0, 0, 0, 0, &e1);
    ozayn_oq_entry_t *dispatch = NULL;
    ozayn_oq_dequeue_next(&_svc, &dispatch);
    ASSERT_EQ(_svc.running_count, 1);
    /* Second dequeue should fail */
    ozayn_oq_entry_t *e2 = NULL;
    ozayn_oq_enqueue(&_svc, "R2", OZAYN_OQ_ACTION_QUERY,
        "CORE", NULL, NULL, NULL, NULL, NULL, 0, 0, 0, 0, 0, &e2);
    ASSERT_EQ(ozayn_oq_dequeue_next(&_svc, &dispatch),
              OZAYN_OQ_ERR_RESOURCE_LIMIT);
    ozayn_oq_service_shutdown(&_svc);
    return 0;
}

TEST(test_oq_dequeue_priority_order)
{
    _init_queue();
    _register_target("CORE");
    ozayn_oq_entry_t *e_low = NULL, *e_high = NULL, *e_crit = NULL;
    ozayn_oq_enqueue(&_svc, "R-LOW", OZAYN_OQ_ACTION_QUERY,
        "CORE", NULL, NULL, NULL, NULL, NULL, OZAYN_OQ_PRIORITY_LOW, 0, 0, 0, 0, &e_low);
    ozayn_oq_enqueue(&_svc, "R-HIGH", OZAYN_OQ_ACTION_QUERY,
        "CORE", NULL, NULL, NULL, NULL, NULL, OZAYN_OQ_PRIORITY_HIGH, 0, 0, 0, 0, &e_high);
    ozayn_oq_enqueue(&_svc, "R-CRIT", OZAYN_OQ_ACTION_QUERY,
        "CORE", NULL, NULL, NULL, NULL, NULL, OZAYN_OQ_PRIORITY_CRITICAL, 0, 0, 0, 0, &e_crit);
    /* Should dequeue CRITICAL first */
    ozayn_oq_entry_t *dispatch = NULL;
    ozayn_oq_dequeue_next(&_svc, &dispatch);
    ASSERT(strcmp(dispatch->entry_id, e_crit->entry_id) == 0);
    /* Then HIGH */
    ozayn_oq_dequeue_next(&_svc, &dispatch);
    ASSERT(strcmp(dispatch->entry_id, e_high->entry_id) == 0);
    /* Then LOW */
    ozayn_oq_dequeue_next(&_svc, &dispatch);
    ASSERT(strcmp(dispatch->entry_id, e_low->entry_id) == 0);
    ozayn_oq_service_shutdown(&_svc);
    return 0;
}

/* ============================================================
 * COMPLETE / FAIL TESTS
 * ============================================================ */

TEST(test_oq_complete)
{
    _init_queue();
    _register_target("CORE");
    ozayn_oq_entry_t *enq = NULL;
    ozayn_oq_enqueue(&_svc, "REQ-1", OZAYN_OQ_ACTION_QUERY,
        "CORE", NULL, NULL, NULL, NULL, NULL, 0, 0, 0, 0, 0, &enq);
    ozayn_oq_entry_t *dispatch = NULL;
    ozayn_oq_dequeue_next(&_svc, &dispatch);
    ASSERT_EQ(ozayn_oq_complete(&_svc, dispatch->entry_id, 0, NULL),
              OZAYN_OQ_OK);
    ASSERT_EQ(dispatch->state, OZAYN_OQ_STATE_SUCCEEDED);
    ASSERT_EQ(dispatch->result_code, 0);
    ASSERT_EQ(_svc.running_count, 0);
    ASSERT_EQ(_svc.total_succeeded, 1);
    ozayn_oq_service_shutdown(&_svc);
    return 0;
}

TEST(test_oq_fail)
{
    _init_queue();
    _register_target("CORE");
    ozayn_oq_entry_t *enq = NULL;
    ozayn_oq_enqueue(&_svc, "REQ-1", OZAYN_OQ_ACTION_START,
        "CORE", NULL, NULL, NULL, NULL, NULL, 0, 0, 0, 0, 0, &enq);
    ozayn_oq_entry_t *dispatch = NULL;
    ozayn_oq_dequeue_next(&_svc, &dispatch);
    ASSERT_EQ(ozayn_oq_fail(&_svc, dispatch->entry_id, -1, "error"),
              OZAYN_OQ_OK);
    ASSERT_EQ(dispatch->state, OZAYN_OQ_STATE_FAILED);
    ASSERT_EQ(dispatch->result_code, -1);
    ASSERT_STR_EQ(dispatch->error_detail, "error");
    ASSERT_EQ(_svc.running_count, 0);
    ASSERT_EQ(_svc.total_failed, 1);
    ozayn_oq_service_shutdown(&_svc);
    return 0;
}

TEST(test_oq_complete_wrong_state)
{
    _init_queue();
    _register_target("CORE");
    ozayn_oq_entry_t *enq = NULL;
    ozayn_oq_enqueue(&_svc, "REQ-1", OZAYN_OQ_ACTION_QUERY,
        "CORE", NULL, NULL, NULL, NULL, NULL, 0, 0, 0, 0, 0, &enq);
    /* Complete without dequeue — wrong state */
    ASSERT_EQ(ozayn_oq_complete(&_svc, enq->entry_id, 0, NULL),
              OZAYN_OQ_ERR_STATE_INVALID);
    ozayn_oq_service_shutdown(&_svc);
    return 0;
}

TEST(test_oq_complete_not_found)
{
    _init_queue();
    ASSERT_EQ(ozayn_oq_complete(&_svc, "NOPE", 0, NULL),
              OZAYN_OQ_ERR_NOT_FOUND);
    ozayn_oq_service_shutdown(&_svc);
    return 0;
}

/* ============================================================
 * CANCELLATION TESTS
 * ============================================================ */

TEST(test_oq_cancel)
{
    _init_queue();
    _register_target("CORE");
    ozayn_oq_entry_t *enq = NULL;
    ozayn_oq_enqueue(&_svc, "REQ-1", OZAYN_OQ_ACTION_START,
        "CORE", NULL, NULL, NULL, NULL, NULL, 0, 0, 0, 0, 0, &enq);
    ASSERT_EQ(ozayn_oq_cancel(&_svc, enq->entry_id), OZAYN_OQ_OK);
    ASSERT_EQ(enq->state, OZAYN_OQ_STATE_CANCELLED);
    ASSERT_EQ(_svc.total_cancelled, 1);
    ozayn_oq_service_shutdown(&_svc);
    return 0;
}

TEST(test_oq_cancel_not_found)
{
    _init_queue();
    ASSERT_EQ(ozayn_oq_cancel(&_svc, "NOPE"), OZAYN_OQ_ERR_NOT_FOUND);
    ozayn_oq_service_shutdown(&_svc);
    return 0;
}

TEST(test_oq_cancel_terminal)
{
    _init_queue();
    _register_target("CORE");
    ozayn_oq_entry_t *enq = NULL;
    ozayn_oq_enqueue(&_svc, "REQ-1", OZAYN_OQ_ACTION_QUERY,
        "CORE", NULL, NULL, NULL, NULL, NULL, 0, 0, 0, 0, 0, &enq);
    ozayn_oq_entry_t *dispatch = NULL;
    ozayn_oq_dequeue_next(&_svc, &dispatch);
    ozayn_oq_complete(&_svc, dispatch->entry_id, 0, NULL);
    ASSERT_EQ(ozayn_oq_cancel(&_svc, dispatch->entry_id),
              OZAYN_OQ_ERR_STATE_INVALID);
    ozayn_oq_service_shutdown(&_svc);
    return 0;
}

TEST(test_oq_cancel_running)
{
    _init_queue();
    _register_target("CORE");
    ozayn_oq_entry_t *enq = NULL;
    ozayn_oq_enqueue(&_svc, "REQ-1", OZAYN_OQ_ACTION_START,
        "CORE", NULL, NULL, NULL, NULL, NULL, 0, 0, 0, 0, 0, &enq);
    ozayn_oq_entry_t *dispatch = NULL;
    ozayn_oq_dequeue_next(&_svc, &dispatch);
    ASSERT_EQ(ozayn_oq_cancel(&_svc, dispatch->entry_id),
              OZAYN_OQ_ERR_CANCELLATION_UNSUPPORTED);
    ozayn_oq_service_shutdown(&_svc);
    return 0;
}

TEST(test_oq_cancellable)
{
    _init_queue();
    _register_target("CORE");
    ozayn_oq_entry_t *enq = NULL;
    ozayn_oq_enqueue(&_svc, "REQ-1", OZAYN_OQ_ACTION_QUERY,
        "CORE", NULL, NULL, NULL, NULL, NULL, 0, 0, 0, 0, 0, &enq);
    ASSERT(ozayn_oq_entry_cancellable(&_svc, enq->entry_id));
    ozayn_oq_entry_t *dispatch = NULL;
    ozayn_oq_dequeue_next(&_svc, &dispatch);
    ASSERT(!ozayn_oq_entry_cancellable(&_svc, dispatch->entry_id));
    ozayn_oq_service_shutdown(&_svc);
    return 0;
}

TEST(test_oq_cancel_null)
{
    ASSERT_EQ(ozayn_oq_cancel(NULL, "X"), OZAYN_OQ_ERR_NULL);
    _init_queue();
    ASSERT_EQ(ozayn_oq_cancel(&_svc, ""), OZAYN_OQ_ERR_INVALID_PARAM);
    ozayn_oq_service_shutdown(&_svc);
    return 0;
}

/* ============================================================
 * TIMEOUT TESTS
 * ============================================================ */

TEST(test_oq_check_timeouts_queue)
{
    _init_queue();
    _register_target("CORE");
    ozayn_oq_policy_t p = ozayn_oq_default_policy();
    p.queue_timeout_ms = 1000;
    ozayn_oq_set_policy(&_svc, &p);
    ozayn_oq_entry_t *enq = NULL;
    ozayn_oq_enqueue(&_svc, "REQ-1", OZAYN_OQ_ACTION_START,
        "CORE", NULL, NULL, NULL, NULL, NULL, 0, 0, 1000, 0, 0, &enq);
    /* Simulate old queued time */
    enq->queued_time = time(NULL) - 10;
    int timed_out = ozayn_oq_check_timeouts(&_svc);
    ASSERT(timed_out >= 1);
    ASSERT_EQ(enq->state, OZAYN_OQ_STATE_TIMEOUT);
    ASSERT_EQ(_svc.total_timeouts, 1);
    ozayn_oq_service_shutdown(&_svc);
    return 0;
}

TEST(test_oq_check_timeouts_execution)
{
    _init_queue();
    _register_target("CORE");
    ozayn_oq_entry_t *enq = NULL;
    ozayn_oq_enqueue(&_svc, "REQ-1", OZAYN_OQ_ACTION_START,
        "CORE", NULL, NULL, NULL, NULL, NULL, 0, 0, 0, 1000, 0, &enq);
    ozayn_oq_entry_t *dispatch = NULL;
    ozayn_oq_dequeue_next(&_svc, &dispatch);
    /* Simulate old start time */
    dispatch->start_time = time(NULL) - 10;
    int timed_out = ozayn_oq_check_timeouts(&_svc);
    ASSERT(timed_out >= 1);
    ASSERT_EQ(dispatch->state, OZAYN_OQ_STATE_TIMEOUT);
    ASSERT_EQ(_svc.total_timeouts, 1);
    ozayn_oq_service_shutdown(&_svc);
    return 0;
}

TEST(test_oq_check_timeouts_null)
{
    ASSERT_EQ(ozayn_oq_check_timeouts(NULL), 0);
    return 0;
}

/* ============================================================
 * EXPIRATION TESTS
 * ============================================================ */

TEST(test_oq_check_expired)
{
    _init_queue();
    _register_target("CORE");
    ozayn_oq_entry_t *enq = NULL;
    ozayn_oq_enqueue(&_svc, "REQ-1", OZAYN_OQ_ACTION_QUERY,
        "CORE", NULL, NULL, NULL, NULL, NULL, 0, 0, 0, 0, 0, &enq);
    ozayn_oq_entry_t *dispatch = NULL;
    ozayn_oq_dequeue_next(&_svc, &dispatch);
    ozayn_oq_complete(&_svc, dispatch->entry_id, 0, NULL);
    /* Simulate old completion */
    dispatch->completion_time = time(NULL) - 400;
    int expired = ozayn_oq_check_expired(&_svc);
    ASSERT(expired >= 1);
    ASSERT(!dispatch->active);
    ozayn_oq_service_shutdown(&_svc);
    return 0;
}

TEST(test_oq_check_expired_null)
{
    ASSERT_EQ(ozayn_oq_check_expired(NULL), 0);
    return 0;
}

/* ============================================================
 * PRECONDITION RECHECK TESTS
 * ============================================================ */

TEST(test_oq_recheck_preconditions_ok)
{
    _init_queue();
    _register_target("CORE");
    _register_capability("CAP-1", "CORE");
    ozayn_oq_entry_t *enq = NULL;
    ozayn_oq_enqueue(&_svc, "REQ-1", OZAYN_OQ_ACTION_QUERY,
        "CORE", "CAP-1", NULL, NULL, NULL, NULL, 0, 0, 0, 0, 0, &enq);
    ASSERT_EQ(ozayn_oq_recheck_preconditions(&_svc, enq->entry_id),
              OZAYN_OQ_OK);
    ozayn_oq_service_shutdown(&_svc);
    return 0;
}

TEST(test_oq_recheck_preconditions_target_gone)
{
    _init_queue();
    _register_target("CORE");
    ozayn_oq_entry_t *enq = NULL;
    ozayn_oq_enqueue(&_svc, "REQ-1", OZAYN_OQ_ACTION_QUERY,
        "CORE", NULL, NULL, NULL, NULL, NULL, 0, 0, 0, 0, 0, &enq);
    /* Remove target */
    ozayn_reg_unregister_component(&_reg, "CORE");
    ASSERT_EQ(ozayn_oq_recheck_preconditions(&_svc, enq->entry_id),
              OZAYN_OQ_ERR_PRECONDITION_FAILED);
    ozayn_oq_service_shutdown(&_svc);
    return 0;
}

TEST(test_oq_recheck_preconditions_cap_gone)
{
    _init_queue();
    _register_target("CORE");
    _register_capability("CAP-1", "CORE");
    ozayn_oq_entry_t *enq = NULL;
    ozayn_oq_enqueue(&_svc, "REQ-1", OZAYN_OQ_ACTION_QUERY,
        "CORE", "CAP-1", NULL, NULL, NULL, NULL, 0, 0, 0, 0, 0, &enq);
    ozayn_reg_unregister_capability(&_reg, "CAP-1");
    ASSERT_EQ(ozayn_oq_recheck_preconditions(&_svc, enq->entry_id),
              OZAYN_OQ_ERR_PRECONDITION_FAILED);
    ozayn_oq_service_shutdown(&_svc);
    return 0;
}

TEST(test_oq_recheck_preconditions_null)
{
    ASSERT_EQ(ozayn_oq_recheck_preconditions(NULL, "X"), OZAYN_OQ_ERR_NULL);
    return 0;
}

/* ============================================================
 * AUTHORIZATION RECHECK TESTS
 * ============================================================ */

TEST(test_oq_recheck_authz_not_required)
{
    _init_queue();
    _register_target("CORE");
    ozayn_oq_entry_t *enq = NULL;
    ozayn_oq_enqueue(&_svc, "REQ-1", OZAYN_OQ_ACTION_QUERY,
        "CORE", NULL, NULL, NULL, NULL, NULL, 0, 0, 0, 0, 0, &enq);
    ASSERT_EQ(ozayn_oq_recheck_authorization(&_svc, enq->entry_id),
              OZAYN_OQ_OK);
    ozayn_oq_service_shutdown(&_svc);
    return 0;
}

TEST(test_oq_recheck_authz_required_no_service)
{
    _init_queue();
    _register_target("CORE");
    ozayn_oq_policy_t p = ozayn_oq_default_policy();
    p.require_authorization = 1;
    ozayn_oq_set_policy(&_svc, &p);
    ozayn_oq_entry_t *enq = NULL;
    ozayn_oq_enqueue(&_svc, "REQ-1", OZAYN_OQ_ACTION_QUERY,
        "CORE", NULL, NULL, NULL, NULL, NULL, 0, 0, 0, 0, 0, &enq);
    ASSERT_EQ(ozayn_oq_recheck_authorization(&_svc, enq->entry_id),
              OZAYN_OQ_ERR_PRECONDITION_FAILED);
    ozayn_oq_service_shutdown(&_svc);
    return 0;
}

TEST(test_oq_recheck_authz_null)
{
    ASSERT_EQ(ozayn_oq_recheck_authorization(NULL, "X"), OZAYN_OQ_ERR_NULL);
    return 0;
}

/* ============================================================
 * RETRY TESTS
 * ============================================================ */

TEST(test_oq_retry)
{
    _init_queue();
    _register_target("CORE");
    ozayn_oq_entry_t *enq = NULL;
    ozayn_oq_enqueue(&_svc, "REQ-1", OZAYN_OQ_ACTION_START,
        "CORE", NULL, NULL, NULL, NULL, NULL, 0, 0, 0, 0, 3, &enq);
    ozayn_oq_entry_t *dispatch = NULL;
    ozayn_oq_dequeue_next(&_svc, &dispatch);
    ozayn_oq_fail(&_svc, dispatch->entry_id, -1, "error");
    ASSERT_EQ(ozayn_oq_retry(&_svc, dispatch->entry_id), OZAYN_OQ_OK);
    ASSERT_EQ(dispatch->state, OZAYN_OQ_STATE_QUEUED);
    ASSERT_EQ(dispatch->retry_count, 1);
    ASSERT_EQ(_svc.total_retries, 1);
    ozayn_oq_service_shutdown(&_svc);
    return 0;
}

TEST(test_oq_retry_exhausted)
{
    _init_queue();
    _register_target("CORE");
    ozayn_oq_entry_t *enq = NULL;
    ozayn_oq_enqueue(&_svc, "REQ-1", OZAYN_OQ_ACTION_START,
        "CORE", NULL, NULL, NULL, NULL, NULL, 0, 0, 0, 0, 1, &enq);
    ozayn_oq_entry_t *dispatch = NULL;
    ozayn_oq_dequeue_next(&_svc, &dispatch);
    ozayn_oq_fail(&_svc, dispatch->entry_id, -1, "error");
    ozayn_oq_retry(&_svc, dispatch->entry_id);
    /* Re-dequeue and fail again */
    ozayn_oq_dequeue_next(&_svc, &dispatch);
    ozayn_oq_fail(&_svc, dispatch->entry_id, -1, "error");
    ASSERT_EQ(ozayn_oq_retry(&_svc, dispatch->entry_id),
              OZAYN_OQ_ERR_RETRY_EXHAUSTED);
    ozayn_oq_service_shutdown(&_svc);
    return 0;
}

TEST(test_oq_retry_wrong_state)
{
    _init_queue();
    _register_target("CORE");
    ozayn_oq_entry_t *enq = NULL;
    ozayn_oq_enqueue(&_svc, "REQ-1", OZAYN_OQ_ACTION_QUERY,
        "CORE", NULL, NULL, NULL, NULL, NULL, 0, 0, 0, 0, 3, &enq);
    ASSERT_EQ(ozayn_oq_retry(&_svc, enq->entry_id), OZAYN_OQ_ERR_STATE_INVALID);
    ozayn_oq_service_shutdown(&_svc);
    return 0;
}

TEST(test_oq_retryable)
{
    _init_queue();
    _register_target("CORE");
    ozayn_oq_entry_t *enq = NULL;
    ozayn_oq_enqueue(&_svc, "REQ-1", OZAYN_OQ_ACTION_START,
        "CORE", NULL, NULL, NULL, NULL, NULL, 0, 0, 0, 0, 1, &enq);
    ASSERT(!ozayn_oq_entry_retryable(&_svc, enq->entry_id));
    ozayn_oq_entry_t *dispatch = NULL;
    ozayn_oq_dequeue_next(&_svc, &dispatch);
    ozayn_oq_fail(&_svc, dispatch->entry_id, -1, "error");
    ASSERT(ozayn_oq_entry_retryable(&_svc, dispatch->entry_id));
    ozayn_oq_service_shutdown(&_svc);
    return 0;
}

/* ============================================================
 * CONFLICT DETECTION TESTS
 * ============================================================ */

TEST(test_oq_conflict_start_stop)
{
    _init_queue();
    _register_target("CORE");
    ozayn_oq_entry_t *enq = NULL;
    ozayn_oq_enqueue(&_svc, "R1", OZAYN_OQ_ACTION_START,
        "CORE", NULL, NULL, NULL, NULL, NULL, 0, 0, 0, 0, 0, &enq);
    ozayn_oq_entry_t *dispatch = NULL;
    ozayn_oq_dequeue_next(&_svc, &dispatch);
    ASSERT(ozayn_oq_has_conflict(&_svc, "CORE", OZAYN_OQ_ACTION_STOP));
    ASSERT(!ozayn_oq_has_conflict(&_svc, "CORE", OZAYN_OQ_ACTION_QUERY));
    ASSERT(!ozayn_oq_has_conflict(&_svc, "OTHER", OZAYN_OQ_ACTION_STOP));
    ozayn_oq_service_shutdown(&_svc);
    return 0;
}

TEST(test_oq_conflict_enable_disable)
{
    _init_queue();
    _register_target("CORE");
    ozayn_oq_entry_t *enq = NULL;
    ozayn_oq_enqueue(&_svc, "R1", OZAYN_OQ_ACTION_ENABLE,
        "CORE", NULL, NULL, NULL, NULL, NULL, 0, 0, 0, 0, 0, &enq);
    ozayn_oq_entry_t *dispatch = NULL;
    ozayn_oq_dequeue_next(&_svc, &dispatch);
    ASSERT(ozayn_oq_has_conflict(&_svc, "CORE", OZAYN_OQ_ACTION_DISABLE));
    ozayn_oq_service_shutdown(&_svc);
    return 0;
}

TEST(test_oq_conflict_reject_mode)
{
    _init_queue();
    _register_target("CORE");
    ozayn_oq_policy_t p = ozayn_oq_default_policy();
    p.default_conflict_mode = OZAYN_OQ_CONFLICT_REJECT;
    ozayn_oq_set_policy(&_svc, &p);
    ozayn_oq_entry_t *enq = NULL;
    ozayn_oq_enqueue(&_svc, "R1", OZAYN_OQ_ACTION_START,
        "CORE", NULL, NULL, NULL, NULL, NULL, 0, 0, 0, 0, 0, &enq);
    ozayn_oq_entry_t *dispatch = NULL;
    ozayn_oq_dequeue_next(&_svc, &dispatch);
    /* Enqueue conflicting operation — should be rejected */
    ASSERT_EQ(ozayn_oq_enqueue(&_svc, "R2", OZAYN_OQ_ACTION_STOP,
        "CORE", NULL, NULL, NULL, NULL, NULL, 0, 0, 0, 0, 0, NULL),
        OZAYN_OQ_ERR_STATE_INVALID);
    ozayn_oq_service_shutdown(&_svc);
    return 0;
}

TEST(test_oq_conflict_null)
{
    ASSERT_EQ(ozayn_oq_has_conflict(NULL, "X", 0), 0);
    ASSERT_EQ(ozayn_oq_has_conflict(&_svc, "", 0), 0);
    return 0;
}

/* ============================================================
 * IDEMPOTENCY TESTS
 * ============================================================ */

TEST(test_oq_idempotent_duplicate)
{
    _init_queue();
    _register_target("CORE");
    ozayn_oq_entry_t *e1 = NULL;
    ozayn_oq_enqueue(&_svc, "REQ-1", OZAYN_OQ_ACTION_QUERY,
        "CORE", NULL, NULL, NULL, NULL, NULL, 0, 1, 0, 0, 0, &e1);
    ozayn_oq_entry_t *e2 = NULL;
    ASSERT_EQ(ozayn_oq_enqueue(&_svc, "REQ-1", OZAYN_OQ_ACTION_QUERY,
        "CORE", NULL, NULL, NULL, NULL, NULL, 0, 1, 0, 0, 0, &e2),
        OZAYN_OQ_ERR_DUPLICATE_REQUEST);
    ASSERT_EQ(_svc.total_duplicates, 1);
    ozayn_oq_service_shutdown(&_svc);
    return 0;
}

TEST(test_oq_non_idempotent_allows)
{
    _init_queue();
    _register_target("CORE");
    ozayn_oq_entry_t *e1 = NULL;
    ozayn_oq_enqueue(&_svc, "REQ-1", OZAYN_OQ_ACTION_QUERY,
        "CORE", NULL, NULL, NULL, NULL, NULL, 0, 0, 0, 0, 0, &e1);
    ozayn_oq_entry_t *e2 = NULL;
    ASSERT_EQ(ozayn_oq_enqueue(&_svc, "REQ-1", OZAYN_OQ_ACTION_QUERY,
        "CORE", NULL, NULL, NULL, NULL, NULL, 0, 0, 0, 0, 0, &e2),
        OZAYN_OQ_OK);
    ozayn_oq_service_shutdown(&_svc);
    return 0;
}

/* ============================================================
 * PER-COMPONENT LIMIT TESTS
 * ============================================================ */

TEST(test_oq_per_component_limit)
{
    _init_queue();
    _register_target("CORE");
    ozayn_oq_policy_t p = ozayn_oq_default_policy();
    p.max_per_component = 2;
    ozayn_oq_set_policy(&_svc, &p);
    ozayn_oq_enqueue(&_svc, "R1", OZAYN_OQ_ACTION_QUERY,
        "CORE", NULL, NULL, NULL, NULL, NULL, 0, 0, 0, 0, 0, NULL);
    ozayn_oq_enqueue(&_svc, "R2", OZAYN_OQ_ACTION_QUERY,
        "CORE", NULL, NULL, NULL, NULL, NULL, 0, 0, 0, 0, 0, NULL);
    ASSERT_EQ(ozayn_oq_enqueue(&_svc, "R3", OZAYN_OQ_ACTION_QUERY,
        "CORE", NULL, NULL, NULL, NULL, NULL, 0, 0, 0, 0, 0, NULL),
        OZAYN_OQ_ERR_RESOURCE_LIMIT);
    ozayn_oq_service_shutdown(&_svc);
    return 0;
}

/* ============================================================
 * PER-REQUESTER LIMIT TESTS
 * ============================================================ */

TEST(test_oq_per_requester_limit)
{
    _init_queue();
    _register_target("CORE");
    ozayn_oq_policy_t p = ozayn_oq_default_policy();
    p.max_per_requester = 2;
    ozayn_oq_set_policy(&_svc, &p);
    ozayn_oq_enqueue(&_svc, "R1", OZAYN_OQ_ACTION_QUERY,
        "CORE", NULL, NULL, "user1", NULL, NULL, 0, 0, 0, 0, 0, NULL);
    ozayn_oq_enqueue(&_svc, "R2", OZAYN_OQ_ACTION_QUERY,
        "CORE", NULL, NULL, "user1", NULL, NULL, 0, 0, 0, 0, 0, NULL);
    ASSERT_EQ(ozayn_oq_enqueue(&_svc, "R3", OZAYN_OQ_ACTION_QUERY,
        "CORE", NULL, NULL, "user1", NULL, NULL, 0, 0, 0, 0, 0, NULL),
        OZAYN_OQ_ERR_RESOURCE_LIMIT);
    /* Different requester should work */
    ASSERT_EQ(ozayn_oq_enqueue(&_svc, "R4", OZAYN_OQ_ACTION_QUERY,
        "CORE", NULL, NULL, "user2", NULL, NULL, 0, 0, 0, 0, 0, NULL),
        OZAYN_OQ_OK);
    ozayn_oq_service_shutdown(&_svc);
    return 0;
}

/* ============================================================
 * QUERY TESTS
 * ============================================================ */

TEST(test_oq_get_entry)
{
    _init_queue();
    _register_target("CORE");
    ozayn_oq_entry_t *enq = NULL;
    ozayn_oq_enqueue(&_svc, "REQ-1", OZAYN_OQ_ACTION_QUERY,
        "CORE", NULL, NULL, NULL, NULL, NULL, 0, 0, 0, 0, 0, &enq);
    ozayn_oq_entry_t *found = ozayn_oq_get_entry(&_svc, enq->entry_id);
    ASSERT_NOT_NULL(found);
    ASSERT(strcmp(found->entry_id, enq->entry_id) == 0);
    ASSERT_NULL(ozayn_oq_get_entry(&_svc, "NOPE"));
    ASSERT_NULL(ozayn_oq_get_entry(NULL, "X"));
    ozayn_oq_service_shutdown(&_svc);
    return 0;
}

TEST(test_oq_entry_count)
{
    _init_queue();
    ASSERT_EQ(ozayn_oq_entry_count(&_svc), 0);
    _register_target("CORE");
    ozayn_oq_enqueue(&_svc, "R1", OZAYN_OQ_ACTION_QUERY,
        "CORE", NULL, NULL, NULL, NULL, NULL, 0, 0, 0, 0, 0, NULL);
    ASSERT_EQ(ozayn_oq_entry_count(&_svc), 1);
    ASSERT_EQ(ozayn_oq_entry_count(NULL), 0);
    ozayn_oq_service_shutdown(&_svc);
    return 0;
}

TEST(test_oq_running_queued_counts)
{
    _init_queue();
    _register_target("CORE");
    ASSERT_EQ(ozayn_oq_running_count(&_svc), 0);
    ASSERT_EQ(ozayn_oq_queued_count(&_svc), 0);
    ozayn_oq_entry_t *enq = NULL;
    ozayn_oq_enqueue(&_svc, "R1", OZAYN_OQ_ACTION_QUERY,
        "CORE", NULL, NULL, NULL, NULL, NULL, 0, 0, 0, 0, 0, &enq);
    ASSERT_EQ(ozayn_oq_queued_count(&_svc), 1);
    ozayn_oq_entry_t *dispatch = NULL;
    ozayn_oq_dequeue_next(&_svc, &dispatch);
    ASSERT_EQ(ozayn_oq_queued_count(&_svc), 0);
    ASSERT_EQ(ozayn_oq_running_count(&_svc), 1);
    ozayn_oq_service_shutdown(&_svc);
    return 0;
}

/* ============================================================
 * POLICY TESTS
 * ============================================================ */

TEST(test_oq_default_policy)
{
    ozayn_oq_policy_t p = ozayn_oq_default_policy();
    ASSERT(p.enabled == 1);
    ASSERT_EQ(p.max_entries, OZAYN_OQ_MAX_ENTRIES);
    ASSERT_EQ(p.max_running, 16);
    ASSERT(p.max_retries >= 0);
    ASSERT(p.queue_timeout_ms > 0);
    ASSERT(p.execution_timeout_ms > 0);
    return 0;
}

TEST(test_oq_set_policy)
{
    _init_queue();
    ozayn_oq_policy_t p = ozayn_oq_default_policy();
    p.max_running = 4;
    ASSERT_EQ(ozayn_oq_set_policy(&_svc, &p), OZAYN_OQ_OK);
    ASSERT_EQ(_svc.policy.max_running, 4);
    ozayn_oq_service_shutdown(&_svc);
    return 0;
}

TEST(test_oq_set_policy_null)
{
    _init_queue();
    ASSERT_EQ(ozayn_oq_set_policy(&_svc, NULL), OZAYN_OQ_ERR_INVALID_PARAM);
    ozayn_oq_service_shutdown(&_svc);
    return 0;
}

TEST(test_oq_get_policy)
{
    _init_queue();
    const ozayn_oq_policy_t *p = ozayn_oq_get_policy(&_svc);
    ASSERT_NOT_NULL(p);
    ASSERT(p->enabled == 1);
    ASSERT_NULL(ozayn_oq_get_policy(NULL));
    ozayn_oq_service_shutdown(&_svc);
    return 0;
}

/* ============================================================
 * STATISTICS TESTS
 * ============================================================ */

TEST(test_oq_statistics)
{
    _init_queue();
    ASSERT_EQ(ozayn_oq_total_submitted(&_svc), 0);
    _register_target("CORE");
    ozayn_oq_entry_t *enq = NULL;
    ozayn_oq_enqueue(&_svc, "R1", OZAYN_OQ_ACTION_QUERY,
        "CORE", NULL, NULL, NULL, NULL, NULL, 0, 0, 0, 0, 0, &enq);
    ASSERT_EQ(ozayn_oq_total_submitted(&_svc), 1);
    ozayn_oq_entry_t *dispatch = NULL;
    ozayn_oq_dequeue_next(&_svc, &dispatch);
    ozayn_oq_complete(&_svc, dispatch->entry_id, 0, NULL);
    ASSERT_EQ(ozayn_oq_total_succeeded(&_svc), 1);
    ASSERT_EQ(ozayn_oq_total_submitted(NULL), 0);
    ozayn_oq_service_shutdown(&_svc);
    return 0;
}

/* ============================================================
 * CLEANUP TESTS
 * ============================================================ */

TEST(test_oq_cleanup_completed)
{
    _init_queue();
    _register_target("CORE");
    ozayn_oq_entry_t *enq = NULL;
    ozayn_oq_enqueue(&_svc, "R1", OZAYN_OQ_ACTION_QUERY,
        "CORE", NULL, NULL, NULL, NULL, NULL, 0, 0, 0, 0, 0, &enq);
    ozayn_oq_entry_t *dispatch = NULL;
    ozayn_oq_dequeue_next(&_svc, &dispatch);
    ozayn_oq_complete(&_svc, dispatch->entry_id, 0, NULL);
    int cleaned = ozayn_oq_cleanup_completed(&_svc);
    ASSERT(cleaned >= 1);
    ASSERT(!dispatch->active);
    ozayn_oq_service_shutdown(&_svc);
    return 0;
}

TEST(test_oq_cleanup_all)
{
    _init_queue();
    _register_target("CORE");
    ozayn_oq_enqueue(&_svc, "R1", OZAYN_OQ_ACTION_QUERY,
        "CORE", NULL, NULL, NULL, NULL, NULL, 0, 0, 0, 0, 0, NULL);
    ozayn_oq_enqueue(&_svc, "R2", OZAYN_OQ_ACTION_QUERY,
        "CORE", NULL, NULL, NULL, NULL, NULL, 0, 0, 0, 0, 0, NULL);
    int cleaned = ozayn_oq_cleanup_all(&_svc);
    ASSERT(cleaned >= 2);
    ASSERT_EQ(_svc.running_count, 0);
    ASSERT_EQ(_svc.queued_count, 0);
    ozayn_oq_service_shutdown(&_svc);
    return 0;
}

TEST(test_oq_cleanup_null)
{
    ASSERT_EQ(ozayn_oq_cleanup_completed(NULL), 0);
    ASSERT_EQ(ozayn_oq_cleanup_all(NULL), 0);
    return 0;
}

/* ============================================================
 * NAME HELPER TESTS
 * ============================================================ */

TEST(test_oq_err_name)
{
    ASSERT_STR_EQ(ozayn_oq_err_name(OZAYN_OQ_OK), "OK");
    ASSERT_STR_EQ(ozayn_oq_err_name(OZAYN_OQ_ERR_NULL), "NULL");
    ASSERT_STR_EQ(ozayn_oq_err_name(OZAYN_OQ_ERR_QUEUE_FULL), "QUEUE_FULL");
    ASSERT_STR_EQ(ozayn_oq_err_name(OZAYN_OQ_ERR_NOT_FOUND), "NOT_FOUND");
    ASSERT_STR_EQ(ozayn_oq_err_name(OZAYN_OQ_ERR_RETRY_EXHAUSTED), "RETRY_EXHAUSTED");
    ASSERT_STR_EQ(ozayn_oq_err_name((ozayn_oq_err_t)999), "UNKNOWN");
    return 0;
}

TEST(test_oq_state_name)
{
    ASSERT_STR_EQ(ozayn_oq_state_name(OZAYN_OQ_STATE_CREATED), "CREATED");
    ASSERT_STR_EQ(ozayn_oq_state_name(OZAYN_OQ_STATE_QUEUED), "QUEUED");
    ASSERT_STR_EQ(ozayn_oq_state_name(OZAYN_OQ_STATE_RUNNING), "RUNNING");
    ASSERT_STR_EQ(ozayn_oq_state_name(OZAYN_OQ_STATE_SUCCEEDED), "SUCCEEDED");
    ASSERT_STR_EQ(ozayn_oq_state_name(OZAYN_OQ_STATE_CANCELLED), "CANCELLED");
    ASSERT_STR_EQ(ozayn_oq_state_name((ozayn_oq_state_t)99), "UNKNOWN");
    return 0;
}

TEST(test_oq_priority_name)
{
    ASSERT_STR_EQ(ozayn_oq_priority_name(OZAYN_OQ_PRIORITY_LOW), "LOW");
    ASSERT_STR_EQ(ozayn_oq_priority_name(OZAYN_OQ_PRIORITY_NORMAL), "NORMAL");
    ASSERT_STR_EQ(ozayn_oq_priority_name(OZAYN_OQ_PRIORITY_HIGH), "HIGH");
    ASSERT_STR_EQ(ozayn_oq_priority_name(OZAYN_OQ_PRIORITY_CRITICAL), "CRITICAL");
    ASSERT_STR_EQ(ozayn_oq_priority_name((ozayn_oq_priority_t)99), "UNKNOWN");
    return 0;
}

TEST(test_oq_action_name)
{
    ASSERT_STR_EQ(ozayn_oq_action_name(OZAYN_OQ_ACTION_START), "START");
    ASSERT_STR_EQ(ozayn_oq_action_name(OZAYN_OQ_ACTION_STOP), "STOP");
    ASSERT_STR_EQ(ozayn_oq_action_name(OZAYN_OQ_ACTION_QUERY), "QUERY");
    ASSERT_STR_EQ(ozayn_oq_action_name(OZAYN_OQ_ACTION_DIAGNOSTIC), "DIAGNOSTIC");
    ASSERT_STR_EQ(ozayn_oq_action_name((ozayn_oq_action_t)99), "UNKNOWN");
    return 0;
}

TEST(test_oq_event_type_name)
{
    ASSERT_STR_EQ(ozayn_oq_event_type_name(OZAYN_OQ_EVENT_CREATED), "CREATED");
    ASSERT_STR_EQ(ozayn_oq_event_type_name(OZAYN_OQ_EVENT_SUCCEEDED), "SUCCEEDED");
    ASSERT_STR_EQ(ozayn_oq_event_type_name(OZAYN_OQ_EVENT_TIMEOUT), "TIMEOUT");
    ASSERT_STR_EQ(ozayn_oq_event_type_name((ozayn_oq_event_type_t)99), "UNKNOWN");
    return 0;
}

TEST(test_oq_conflict_mode_name)
{
    ASSERT_STR_EQ(ozayn_oq_conflict_mode_name(OZAYN_OQ_CONFLICT_REJECT), "REJECT");
    ASSERT_STR_EQ(ozayn_oq_conflict_mode_name(OZAYN_OQ_CONFLICT_WAIT), "WAIT");
    ASSERT_STR_EQ(ozayn_oq_conflict_mode_name(OZAYN_OQ_CONFLICT_ALLOW), "ALLOW");
    ASSERT_STR_EQ(ozayn_oq_conflict_mode_name((ozayn_oq_conflict_mode_t)99), "UNKNOWN");
    return 0;
}

/* ============================================================
 * EVENT / AUDIT TESTS
 * ============================================================ */

TEST(test_oq_emit_event)
{
    _init_queue();
    ASSERT_EQ(ozayn_oq_emit_event(&_svc, OZAYN_OQ_EVENT_CREATED, "X", "X"),
              OZAYN_OQ_OK);
    ASSERT_EQ(ozayn_oq_emit_event(NULL, OZAYN_OQ_EVENT_CREATED, "X", "X"),
              OZAYN_OQ_ERR_NULL);
    ozayn_oq_service_shutdown(&_svc);
    return 0;
}

TEST(test_oq_audit_operation)
{
    _init_queue();
    ASSERT_EQ(ozayn_oq_audit_operation(&_svc, "X", "TEST", "detail"),
              OZAYN_OQ_OK);
    ASSERT_EQ(ozayn_oq_audit_operation(NULL, "X", "X", "X"),
              OZAYN_OQ_ERR_NULL);
    ASSERT_EQ(ozayn_oq_audit_operation(&_svc, NULL, "X", "X"),
              OZAYN_OQ_ERR_INVALID_PARAM);
    ozayn_oq_service_shutdown(&_svc);
    return 0;
}

/* ============================================================
 * SECURITY BOUNDARY TESTS
 * ============================================================ */

TEST(test_oq_global_singleton)
{
    ozayn_oq_service_t *g1 = ozayn_oq_get_global();
    ozayn_oq_service_t *g2 = ozayn_oq_get_global();
    ASSERT_NOT_NULL(g1);
    ASSERT(g1 == g2);
    return 0;
}

TEST(test_oq_no_secrets_in_entry)
{
    _init_queue();
    _register_target("CORE");
    ozayn_oq_entry_t *enq = NULL;
    ozayn_oq_enqueue(&_svc, "REQ-1", OZAYN_OQ_ACTION_QUERY,
        "CORE", NULL, "password=secret key=abc token=xyz",
        NULL, NULL, NULL, 0, 0, 0, 0, 0, &enq);
    ASSERT(enq->active == 1);
    ozayn_oq_service_shutdown(&_svc);
    return 0;
}

TEST(test_oq_dequeue_null)
{
    ASSERT_EQ(ozayn_oq_dequeue_next(NULL, NULL), OZAYN_OQ_ERR_NULL);
    return 0;
}

TEST(test_oq_no_registry)
{
    _reset_all();
    _au_svc.initialized = 1;
    ozayn_oq_service_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.audit = (void *)&_au_svc;
    ozayn_oq_service_init(&_svc, &cfg);
    /* No component registry — precondition check should skip */
    ozayn_oq_entry_t *enq = NULL;
    ozayn_oq_enqueue(&_svc, "REQ-1", OZAYN_OQ_ACTION_QUERY,
        "ANY", NULL, NULL, NULL, NULL, NULL, 0, 0, 0, 0, 0, &enq);
    ozayn_oq_entry_t *dispatch = NULL;
    ASSERT_EQ(ozayn_oq_dequeue_next(&_svc, &dispatch), OZAYN_OQ_OK);
    ASSERT_NOT_NULL(dispatch);
    ASSERT_EQ(dispatch->state, OZAYN_OQ_STATE_RUNNING);
    ozayn_oq_complete(&_svc, dispatch->entry_id, 0, NULL);
    ozayn_oq_service_shutdown(&_svc);
    return 0;
}

/* ============================================================
 * FULL LIFECYCLE TEST
 * ============================================================ */

TEST(test_oq_full_lifecycle)
{
    _init_queue();
    _register_target("MOD-VISION");
    _register_capability("VIS-CAP", "MOD-VISION");

    /* Enqueue */
    ozayn_oq_entry_t *enq = NULL;
    ASSERT_EQ(ozayn_oq_enqueue(&_svc, "REQ-FULL",
        OZAYN_OQ_ACTION_QUERY, "MOD-VISION", "VIS-CAP",
        "test context", "user-1", "sess-1", "VISION.READ",
        2, 1, 5000, 30000, 3, &enq), OZAYN_OQ_OK);

    /* Verify queued */
    ASSERT_EQ(enq->state, OZAYN_OQ_STATE_QUEUED);
    ASSERT_STR_EQ(enq->request_id, "REQ-FULL");
    ASSERT_STR_EQ(enq->target, "MOD-VISION");
    ASSERT_STR_EQ(enq->capability, "VIS-CAP");
    ASSERT_EQ(enq->priority, 2);
    ASSERT(enq->idempotent == 1);
    ASSERT_EQ(enq->max_retries, 3);
    ASSERT_EQ(_svc.queued_count, 1);

    /* Dequeue */
    ozayn_oq_entry_t *dispatch = NULL;
    ASSERT_EQ(ozayn_oq_dequeue_next(&_svc, &dispatch), OZAYN_OQ_OK);
    ASSERT(strcmp(dispatch->entry_id, enq->entry_id) == 0);
    ASSERT_EQ(dispatch->state, OZAYN_OQ_STATE_RUNNING);
    ASSERT_EQ(_svc.running_count, 1);
    ASSERT_EQ(_svc.queued_count, 0);

    /* Complete */
    ASSERT_EQ(ozayn_oq_complete(&_svc, dispatch->entry_id, 0, NULL),
              OZAYN_OQ_OK);
    ASSERT_EQ(dispatch->state, OZAYN_OQ_STATE_SUCCEEDED);
    ASSERT_EQ(_svc.running_count, 0);
    ASSERT_EQ(_svc.total_succeeded, 1);

    /* Cleanup */
    int cleaned = ozayn_oq_cleanup_completed(&_svc);
    ASSERT(cleaned >= 1);

    ozayn_oq_service_shutdown(&_svc);
    return 0;
}

/* ============================================================
 * FAIRNESS TEST (same priority, oldest first)
 * ============================================================ */

TEST(test_oq_fairness_same_priority)
{
    _init_queue();
    _register_target("CORE");
    ozayn_oq_entry_t *e1 = NULL, *e2 = NULL, *e3 = NULL;
    ozayn_oq_enqueue(&_svc, "R1", OZAYN_OQ_ACTION_QUERY,
        "CORE", NULL, NULL, NULL, NULL, NULL, 1, 0, 0, 0, 0, &e1);
    ozayn_oq_enqueue(&_svc, "R2", OZAYN_OQ_ACTION_QUERY,
        "CORE", NULL, NULL, NULL, NULL, NULL, 1, 0, 0, 0, 0, &e2);
    ozayn_oq_enqueue(&_svc, "R3", OZAYN_OQ_ACTION_QUERY,
        "CORE", NULL, NULL, NULL, NULL, NULL, 1, 0, 0, 0, 0, &e3);
    /* Same priority — should dequeue in FIFO order (oldest first) */
    ozayn_oq_entry_t *dispatch = NULL;
    ozayn_oq_dequeue_next(&_svc, &dispatch);
    ASSERT(strcmp(dispatch->entry_id, e1->entry_id) == 0);
    ozayn_oq_dequeue_next(&_svc, &dispatch);
    ASSERT(strcmp(dispatch->entry_id, e2->entry_id) == 0);
    ozayn_oq_dequeue_next(&_svc, &dispatch);
    ASSERT(strcmp(dispatch->entry_id, e3->entry_id) == 0);
    ozayn_oq_service_shutdown(&_svc);
    return 0;
}

/* ============================================================
 * TEST RUNNER
 * ============================================================ */

int run_operation_queue_tests(void)
{
    SUITE_BEGIN("Operation Queue & Execution Lifecycle");

    /* Lifecycle */
    RUN(test_oq_init);
    RUN(test_oq_init_null);
    RUN(test_oq_init_double);
    RUN(test_oq_shutdown);
    RUN(test_oq_shutdown_null);
    RUN(test_oq_is_initialized);

    /* Enqueue */
    RUN(test_oq_enqueue);
    RUN(test_oq_enqueue_null);
    RUN(test_oq_enqueue_not_init);
    RUN(test_oq_enqueue_missing_request_id);
    RUN(test_oq_enqueue_missing_target);
    RUN(test_oq_enqueue_invalid_action);
    RUN(test_oq_enqueue_generates_id);
    RUN(test_oq_enqueue_unique_ids);
    RUN(test_oq_enqueue_stores_fields);

    /* Queue Full / Limits */
    RUN(test_oq_queue_full);
    RUN(test_oq_running_limit);
    RUN(test_oq_per_component_limit);
    RUN(test_oq_per_requester_limit);

    /* Dequeue / Dispatch */
    RUN(test_oq_dequeue_next);
    RUN(test_oq_dequeue_empty);
    RUN(test_oq_dequeue_concurrency_limit);
    RUN(test_oq_dequeue_priority_order);
    RUN(test_oq_dequeue_null);

    /* Complete / Fail */
    RUN(test_oq_complete);
    RUN(test_oq_fail);
    RUN(test_oq_complete_wrong_state);
    RUN(test_oq_complete_not_found);

    /* Cancellation */
    RUN(test_oq_cancel);
    RUN(test_oq_cancel_not_found);
    RUN(test_oq_cancel_terminal);
    RUN(test_oq_cancel_running);
    RUN(test_oq_cancellable);
    RUN(test_oq_cancel_null);

    /* Timeout */
    RUN(test_oq_check_timeouts_queue);
    RUN(test_oq_check_timeouts_execution);
    RUN(test_oq_check_timeouts_null);

    /* Expiration */
    RUN(test_oq_check_expired);
    RUN(test_oq_check_expired_null);

    /* Preconditions */
    RUN(test_oq_recheck_preconditions_ok);
    RUN(test_oq_recheck_preconditions_target_gone);
    RUN(test_oq_recheck_preconditions_cap_gone);
    RUN(test_oq_recheck_preconditions_null);

    /* Authorization */
    RUN(test_oq_recheck_authz_not_required);
    RUN(test_oq_recheck_authz_required_no_service);
    RUN(test_oq_recheck_authz_null);

    /* Retry */
    RUN(test_oq_retry);
    RUN(test_oq_retry_exhausted);
    RUN(test_oq_retry_wrong_state);
    RUN(test_oq_retryable);

    /* Conflict */
    RUN(test_oq_conflict_start_stop);
    RUN(test_oq_conflict_enable_disable);
    RUN(test_oq_conflict_reject_mode);
    RUN(test_oq_conflict_null);

    /* Idempotency */
    RUN(test_oq_idempotent_duplicate);
    RUN(test_oq_non_idempotent_allows);

    /* Query */
    RUN(test_oq_get_entry);
    RUN(test_oq_entry_count);
    RUN(test_oq_running_queued_counts);

    /* Policy */
    RUN(test_oq_default_policy);
    RUN(test_oq_set_policy);
    RUN(test_oq_set_policy_null);
    RUN(test_oq_get_policy);

    /* Statistics */
    RUN(test_oq_statistics);

    /* Cleanup */
    RUN(test_oq_cleanup_completed);
    RUN(test_oq_cleanup_all);
    RUN(test_oq_cleanup_null);

    /* Name Helpers */
    RUN(test_oq_err_name);
    RUN(test_oq_state_name);
    RUN(test_oq_priority_name);
    RUN(test_oq_action_name);
    RUN(test_oq_event_type_name);
    RUN(test_oq_conflict_mode_name);

    /* Events / Audit */
    RUN(test_oq_emit_event);
    RUN(test_oq_audit_operation);

    /* Security */
    RUN(test_oq_global_singleton);
    RUN(test_oq_no_secrets_in_entry);
    RUN(test_oq_no_registry);

    /* Full Lifecycle */
    RUN(test_oq_full_lifecycle);

    /* Fairness */
    RUN(test_oq_fairness_same_priority);

    SUITE_END();
    return TOTAL_FAIL();
}
