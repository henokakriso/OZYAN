/*
 * test_workflow_checkpoint.c — Tests for Persistent Workflow Recovery State
 *
 * Step 18/35 — Control Room
 */

#include "../workflow_checkpoint.h"
#include "../../tests/test_framework.h"
#include <string.h>

/* ============================================================
 * STATIC TEST HELPERS
 * ============================================================ */

static ozayn_prs_service_t _svc;
static ozayn_prs_service_config_t _cfg;
static char _cp_id[OZAYN_PRS_MAX_ID_LEN];
static char _cp_id2[OZAYN_PRS_MAX_ID_LEN];

static void _init_svc(void) {
    memset(&_svc, 0, sizeof(_svc));
    memset(&_cfg, 0, sizeof(_cfg));
    ozayn_prs_service_init(&_svc, &_cfg);
}

static void _shutdown_svc(void) {
    ozayn_prs_service_shutdown(&_svc);
}

static int64_t _now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static void _create_simple_checkpoint(void) {
    _init_svc();
    ozayn_prs_checkpoint_create(&_svc, "wf-1", "1.0", "test-workflow",
        "Test workflow", 5, 0, 0, 0, 4, 2, 1, 0, 3, 1, 1,
        "owner-1", "auth-1", "safety-1", "session-1", "op-1",
        NULL, 60000, 0, 0, 0, _cp_id, sizeof(_cp_id));
}

static void _create_committed_checkpoint(void) {
    _create_simple_checkpoint();
    ozayn_prs_checkpoint_validate(&_svc, _cp_id);
    ozayn_prs_checkpoint_commit(&_svc, _cp_id);
}

/* ============================================================
 * LIFECYCLE TESTS
 * ============================================================ */

TEST(test_prs_init) {
    _init_svc();
    ASSERT(ozayn_prs_is_initialized(&_svc));
    _shutdown_svc();
    return 0;
}

TEST(test_prs_init_null) {
    ASSERT_EQ(ozayn_prs_service_init(NULL, &_cfg), OZAYN_PRS_ERR_NULL);
    return 0;
}

TEST(test_prs_init_null_cfg) {
    ozayn_prs_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ASSERT_EQ(ozayn_prs_service_init(&svc, NULL), OZAYN_PRS_ERR_NULL);
    return 0;
}

TEST(test_prs_init_double) {
    _init_svc();
    ASSERT_EQ(ozayn_prs_service_init(&_svc, &_cfg), OZAYN_PRS_ERR_ALREADY_INIT);
    _shutdown_svc();
    return 0;
}

TEST(test_prs_shutdown) {
    _init_svc();
    ASSERT_EQ(ozayn_prs_service_shutdown(&_svc), OZAYN_PRS_OK);
    ASSERT(!ozayn_prs_is_initialized(&_svc));
    return 0;
}

TEST(test_prs_shutdown_null) {
    ASSERT_EQ(ozayn_prs_service_shutdown(NULL), OZAYN_PRS_ERR_NULL);
    return 0;
}

TEST(test_prs_shutdown_not_init) {
    ozayn_prs_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ASSERT_EQ(ozayn_prs_service_shutdown(&svc), OZAYN_PRS_ERR_NOT_INITIALIZED);
    return 0;
}

TEST(test_prs_is_initialized_null) {
    ASSERT(!ozayn_prs_is_initialized(NULL));
    return 0;
}

TEST(test_prs_global) {
    ozayn_prs_service_t *g = ozayn_prs_get_global();
    ASSERT_NOT_NULL(g);
    return 0;
}

/* ============================================================
 * CHECKPOINT CREATION TESTS
 * ============================================================ */

TEST(test_prs_checkpoint_create) {
    _init_svc();
    ASSERT_EQ(ozayn_prs_checkpoint_create(&_svc, "wf-1", "1.0", "test",
        "desc", 5, 0, 0, 0, 4, 2, 1, 0, 3, 1, 1,
        "owner", "auth", "safety", "sess", "op", NULL,
        60000, 0, 0, 0, _cp_id, sizeof(_cp_id)), OZAYN_PRS_OK);
    ASSERT(_cp_id[0] != '\0');
    ASSERT_EQ(ozayn_prs_checkpoint_count(&_svc), 1);
    _shutdown_svc();
    return 0;
}

TEST(test_prs_checkpoint_create_null) {
    _init_svc();
    ASSERT_EQ(ozayn_prs_checkpoint_create(NULL, "wf-1", "1.0", NULL, NULL,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, NULL, NULL, NULL, NULL, NULL,
        NULL, 0, 0, 0, 0, _cp_id, sizeof(_cp_id)), OZAYN_PRS_ERR_NULL);
    _shutdown_svc();
    return 0;
}

TEST(test_prs_checkpoint_create_not_init) {
    ozayn_prs_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ASSERT_EQ(ozayn_prs_checkpoint_create(&svc, "wf-1", "1.0", NULL, NULL,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, NULL, NULL, NULL, NULL, NULL,
        NULL, 0, 0, 0, 0, _cp_id, sizeof(_cp_id)), OZAYN_PRS_ERR_NOT_INITIALIZED);
    return 0;
}

TEST(test_prs_checkpoint_create_bad_id_len) {
    _init_svc();
    char tiny[4];
    ASSERT_EQ(ozayn_prs_checkpoint_create(&_svc, "wf-1", "1.0", NULL, NULL,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, NULL, NULL, NULL, NULL, NULL,
        NULL, 0, 0, 0, 0, tiny, sizeof(tiny)), OZAYN_PRS_ERR_INVALID_PARAM);
    _shutdown_svc();
    return 0;
}

TEST(test_prs_checkpoint_create_bad_stage_count) {
    _init_svc();
    ASSERT_EQ(ozayn_prs_checkpoint_create(&_svc, "wf-1", "1.0", NULL, NULL,
        0, 0, 0, 0, -1, 0, 0, 0, 0, 0, 0, NULL, NULL, NULL, NULL, NULL,
        NULL, 0, 0, 0, 0, _cp_id, sizeof(_cp_id)), OZAYN_PRS_ERR_INVALID_PARAM);
    _shutdown_svc();
    return 0;
}

TEST(test_prs_checkpoint_create_multiple) {
    _init_svc();
    ASSERT_EQ(ozayn_prs_checkpoint_create(&_svc, "wf-1", "1.0", NULL, NULL,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, NULL, NULL, NULL, NULL, NULL,
        NULL, 0, 0, 0, 0, _cp_id, sizeof(_cp_id)), OZAYN_PRS_OK);
    ASSERT_EQ(ozayn_prs_checkpoint_create(&_svc, "wf-1", "1.0", NULL, NULL,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, NULL, NULL, NULL, NULL, NULL,
        NULL, 0, 0, 0, 0, _cp_id2, sizeof(_cp_id2)), OZAYN_PRS_OK);
    ASSERT(strcmp(_cp_id, _cp_id2) != 0);
    ASSERT_EQ(ozayn_prs_checkpoint_count(&_svc), 2);
    _shutdown_svc();
    return 0;
}

/* ============================================================
 * CHECKPOINT STATE TRANSITION TESTS
 * ============================================================ */

TEST(test_prs_checkpoint_validate) {
    _create_simple_checkpoint();
    ASSERT_EQ(ozayn_prs_checkpoint_validate(&_svc, _cp_id), OZAYN_PRS_OK);
    const ozayn_prs_checkpoint_t *cp = ozayn_prs_checkpoint_get(&_svc, _cp_id);
    ASSERT(cp->state == OZAYN_PRS_CP_VALIDATING);
    _shutdown_svc();
    return 0;
}

TEST(test_prs_checkpoint_commit) {
    _create_simple_checkpoint();
    ozayn_prs_checkpoint_validate(&_svc, _cp_id);
    ASSERT_EQ(ozayn_prs_checkpoint_commit(&_svc, _cp_id), OZAYN_PRS_OK);
    const ozayn_prs_checkpoint_t *cp = ozayn_prs_checkpoint_get(&_svc, _cp_id);
    ASSERT(cp->state == OZAYN_PRS_CP_COMMITTED);
    _shutdown_svc();
    return 0;
}

TEST(test_prs_checkpoint_commit_no_validate) {
    _create_simple_checkpoint();
    ASSERT_EQ(ozayn_prs_checkpoint_commit(&_svc, _cp_id),
              OZAYN_PRS_ERR_CHECKPOINT_COMMIT_FAILED);
    _shutdown_svc();
    return 0;
}

TEST(test_prs_checkpoint_supersede) {
    _create_committed_checkpoint();
    ASSERT_EQ(ozayn_prs_checkpoint_supersede(&_svc, _cp_id), OZAYN_PRS_OK);
    const ozayn_prs_checkpoint_t *cp = ozayn_prs_checkpoint_get(&_svc, _cp_id);
    ASSERT(cp->state == OZAYN_PRS_CP_SUPERSEDED);
    _shutdown_svc();
    return 0;
}

TEST(test_prs_checkpoint_invalidate) {
    _create_simple_checkpoint();
    ASSERT_EQ(ozayn_prs_checkpoint_invalidate(&_svc, _cp_id, "test"),
              OZAYN_PRS_OK);
    const ozayn_prs_checkpoint_t *cp = ozayn_prs_checkpoint_get(&_svc, _cp_id);
    ASSERT(cp->state == OZAYN_PRS_CP_INVALID);
    _shutdown_svc();
    return 0;
}

TEST(test_prs_checkpoint_invalidate_terminal) {
    _create_committed_checkpoint();
    ozayn_prs_checkpoint_supersede(&_svc, _cp_id);
    ASSERT_EQ(ozayn_prs_checkpoint_invalidate(&_svc, _cp_id, "test"),
              OZAYN_PRS_ERR_STATE_INVALID);
    _shutdown_svc();
    return 0;
}

TEST(test_prs_checkpoint_mark_recovered) {
    _create_committed_checkpoint();
    /* Mark as recovery-required first */
    _svc.checkpoints[0].state = OZAYN_PRS_CP_RECOVERY_REQUIRED;
    ASSERT_EQ(ozayn_prs_checkpoint_mark_recovered(&_svc, _cp_id), OZAYN_PRS_OK);
    const ozayn_prs_checkpoint_t *cp = ozayn_prs_checkpoint_get(&_svc, _cp_id);
    ASSERT(cp->state == OZAYN_PRS_CP_RECOVERED);
    _shutdown_svc();
    return 0;
}

TEST(test_prs_checkpoint_validate_not_found) {
    _init_svc();
    ASSERT_EQ(ozayn_prs_checkpoint_validate(&_svc, "nonexistent"),
              OZAYN_PRS_ERR_NOT_FOUND);
    _shutdown_svc();
    return 0;
}

TEST(test_prs_checkpoint_commit_not_found) {
    _init_svc();
    ASSERT_EQ(ozayn_prs_checkpoint_commit(&_svc, "nonexistent"),
              OZAYN_PRS_ERR_NOT_FOUND);
    _shutdown_svc();
    return 0;
}

/* ============================================================
 * CHECKPOINT QUERY TESTS
 * ============================================================ */

TEST(test_prs_checkpoint_get) {
    _create_simple_checkpoint();
    const ozayn_prs_checkpoint_t *cp = ozayn_prs_checkpoint_get(&_svc, _cp_id);
    ASSERT_NOT_NULL(cp);
    ASSERT_STR_EQ(cp->workflow_id, "wf-1");
    ASSERT_STR_EQ(cp->workflow_version, "1.0");
    _shutdown_svc();
    return 0;
}

TEST(test_prs_checkpoint_get_not_found) {
    _init_svc();
    ASSERT_NULL(ozayn_prs_checkpoint_get(&_svc, "nonexistent"));
    _shutdown_svc();
    return 0;
}

TEST(test_prs_checkpoint_get_null) {
    ASSERT_NULL(ozayn_prs_checkpoint_get(NULL, "id"));
    ASSERT_NULL(ozayn_prs_checkpoint_get(&_svc, NULL));
    return 0;
}

TEST(test_prs_checkpoint_get_latest_valid) {
    _create_committed_checkpoint();
    const ozayn_prs_checkpoint_t *latest =
        ozayn_prs_checkpoint_get_latest_valid(&_svc, "wf-1");
    ASSERT_NOT_NULL(latest);
    ASSERT_STR_EQ(latest->checkpoint_id, _cp_id);
    _shutdown_svc();
    return 0;
}

TEST(test_prs_checkpoint_get_latest_valid_none) {
    _init_svc();
    ASSERT_NULL(ozayn_prs_checkpoint_get_latest_valid(&_svc, "wf-1"));
    _shutdown_svc();
    return 0;
}

TEST(test_prs_checkpoint_count) {
    _init_svc();
    ASSERT_EQ(ozayn_prs_checkpoint_count(&_svc), 0);
    _create_simple_checkpoint();
    ASSERT_EQ(ozayn_prs_checkpoint_count(&_svc), 1);
    _shutdown_svc();
    return 0;
}

TEST(test_prs_checkpoint_count_by_workflow) {
    _create_simple_checkpoint();
    ASSERT_EQ(ozayn_prs_checkpoint_count_by_workflow(&_svc, "wf-1"), 1);
    ASSERT_EQ(ozayn_prs_checkpoint_count_by_workflow(&_svc, "wf-2"), 0);
    _shutdown_svc();
    return 0;
}

TEST(test_prs_checkpoint_is_valid) {
    _create_committed_checkpoint();
    const ozayn_prs_checkpoint_t *cp = ozayn_prs_checkpoint_get(&_svc, _cp_id);
    ASSERT(ozayn_prs_checkpoint_is_valid(cp));
    _shutdown_svc();
    return 0;
}

TEST(test_prs_checkpoint_is_valid_not_committed) {
    _create_simple_checkpoint();
    const ozayn_prs_checkpoint_t *cp = ozayn_prs_checkpoint_get(&_svc, _cp_id);
    ASSERT(!ozayn_prs_checkpoint_is_valid(cp));
    _shutdown_svc();
    return 0;
}

TEST(test_prs_checkpoint_is_expired) {
    _create_simple_checkpoint();
    const ozayn_prs_checkpoint_t *cp = ozayn_prs_checkpoint_get(&_svc, _cp_id);
    /* Not expired by default (no expiration set) */
    ASSERT(!ozayn_prs_checkpoint_is_expired(cp, _now_ms()));
    _shutdown_svc();
    return 0;
}

TEST(test_prs_checkpoint_is_expired_with_time) {
    _create_simple_checkpoint();
    const ozayn_prs_checkpoint_t *cp = ozayn_prs_checkpoint_get(&_svc, _cp_id);
    /* Set expiration to the past */
    ozayn_prs_checkpoint_t *mutable_cp =
        (ozayn_prs_checkpoint_t *)cp;
    int64_t saved = mutable_cp->expiration_time;
    mutable_cp->expiration_time = 1000;
    ASSERT(ozayn_prs_checkpoint_is_expired(cp, 2000));
    mutable_cp->expiration_time = saved;
    _shutdown_svc();
    return 0;
}

/* ============================================================
 * CHECKPOINT REFERENCE TESTS
 * ============================================================ */

TEST(test_prs_checkpoint_add_failure_ref) {
    _create_simple_checkpoint();
    ASSERT_EQ(ozayn_prs_checkpoint_add_failure_ref(&_svc, _cp_id, "fail-1"),
              OZAYN_PRS_OK);
    const ozayn_prs_checkpoint_t *cp = ozayn_prs_checkpoint_get(&_svc, _cp_id);
    ASSERT_EQ(cp->failure_reference_count, 1);
    ASSERT_STR_EQ(cp->failure_references[0], "fail-1");
    _shutdown_svc();
    return 0;
}

TEST(test_prs_checkpoint_add_resource_ref) {
    _create_simple_checkpoint();
    ASSERT_EQ(ozayn_prs_checkpoint_add_resource_ref(&_svc, _cp_id, "res-1"),
              OZAYN_PRS_OK);
    const ozayn_prs_checkpoint_t *cp = ozayn_prs_checkpoint_get(&_svc, _cp_id);
    ASSERT_EQ(cp->resource_reference_count, 1);
    _shutdown_svc();
    return 0;
}

TEST(test_prs_checkpoint_add_device_ref) {
    _create_simple_checkpoint();
    ASSERT_EQ(ozayn_prs_checkpoint_add_device_ref(&_svc, _cp_id, "dev-1"),
              OZAYN_PRS_OK);
    const ozayn_prs_checkpoint_t *cp = ozayn_prs_checkpoint_get(&_svc, _cp_id);
    ASSERT_EQ(cp->device_reference_count, 1);
    _shutdown_svc();
    return 0;
}

TEST(test_prs_checkpoint_add_ref_limit) {
    _create_simple_checkpoint();
    for (int i = 0; i < OZAYN_PRS_MAX_REFERENCES; i++) {
        char id[32];
        snprintf(id, sizeof(id), "fail-%d", i);
        ozayn_prs_checkpoint_add_failure_ref(&_svc, _cp_id, id);
    }
    ASSERT_EQ(ozayn_prs_checkpoint_add_failure_ref(&_svc, _cp_id, "fail-overflow"),
              OZAYN_PRS_ERR_LIMIT_REACHED);
    _shutdown_svc();
    return 0;
}

/* ============================================================
 * JOURNAL TESTS
 * ============================================================ */

TEST(test_prs_journal_write) {
    _init_svc();
    ASSERT_EQ(ozayn_prs_journal_write(&_svc, OZAYN_PRS_JOURNAL_RESTART_DETECTED,
        NULL, "wf-1", NULL, NULL, NULL, NULL, "Restart detected", NULL),
        OZAYN_PRS_OK);
    ASSERT_EQ(ozayn_prs_journal_count(&_svc), 1);
    _shutdown_svc();
    return 0;
}

TEST(test_prs_journal_write_null) {
    _init_svc();
    ASSERT_EQ(ozayn_prs_journal_write(NULL, OZAYN_PRS_JOURNAL_RESTART_DETECTED,
        NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL), OZAYN_PRS_ERR_NULL);
    _shutdown_svc();
    return 0;
}

TEST(test_prs_journal_write_bad_type) {
    _init_svc();
    ASSERT_EQ(ozayn_prs_journal_write(&_svc, OZAYN_PRS_JOURNAL_COUNT,
        NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL),
        OZAYN_PRS_ERR_INVALID_PARAM);
    _shutdown_svc();
    return 0;
}

TEST(test_prs_journal_get) {
    _init_svc();
    ozayn_prs_journal_write(&_svc, OZAYN_PRS_JOURNAL_RESTART_DETECTED,
        NULL, "wf-1", NULL, NULL, NULL, NULL, "Restart", NULL);
    const ozayn_prs_journal_entry_t *entry = ozayn_prs_journal_get(&_svc, 0);
    ASSERT_NOT_NULL(entry);
    ASSERT(entry->event_type == OZAYN_PRS_JOURNAL_RESTART_DETECTED);
    _shutdown_svc();
    return 0;
}

TEST(test_prs_journal_get_invalid_index) {
    _init_svc();
    ASSERT_NULL(ozayn_prs_journal_get(&_svc, -1));
    ASSERT_NULL(ozayn_prs_journal_get(&_svc, 0));
    _shutdown_svc();
    return 0;
}

TEST(test_prs_journal_get_latest_for_workflow) {
    _init_svc();
    ozayn_prs_journal_write(&_svc, OZAYN_PRS_JOURNAL_CHECKPOINT_CREATED,
        "cp-1", "wf-1", NULL, NULL, NULL, NULL, "created", NULL);
    ozayn_prs_journal_write(&_svc, OZAYN_PRS_JOURNAL_RESTART_DETECTED,
        NULL, "wf-1", NULL, NULL, NULL, NULL, "restart", NULL);
    const ozayn_prs_journal_entry_t *latest =
        ozayn_prs_journal_get_latest_for_workflow(&_svc, "wf-1");
    ASSERT_NOT_NULL(latest);
    ASSERT(latest->event_type == OZAYN_PRS_JOURNAL_RESTART_DETECTED);
    _shutdown_svc();
    return 0;
}

/* ============================================================
 * RESTART DETECTION TESTS
 * ============================================================ */

TEST(test_prs_detect_restart) {
    _create_committed_checkpoint();
    ASSERT_EQ(ozayn_prs_detect_restart(&_svc, _now_ms()), OZAYN_PRS_OK);
    ASSERT(_svc.restart_time > 0);
    ASSERT_EQ(_svc.stats.total_restarts_detected, 1);
    /* Checkpoint should be marked recovery-required */
    const ozayn_prs_checkpoint_t *cp = ozayn_prs_checkpoint_get(&_svc, _cp_id);
    ASSERT(cp->state == OZAYN_PRS_CP_RECOVERY_REQUIRED);
    _shutdown_svc();
    return 0;
}

TEST(test_prs_detect_restart_journal) {
    _init_svc();
    ozayn_prs_detect_restart(&_svc, _now_ms());
    const ozayn_prs_journal_entry_t *entry = ozayn_prs_journal_get(&_svc, 0);
    ASSERT_NOT_NULL(entry);
    ASSERT(entry->event_type == OZAYN_PRS_JOURNAL_RESTART_DETECTED);
    _shutdown_svc();
    return 0;
}

/* ============================================================
 * RECONCILIATION TESTS
 * ============================================================ */

TEST(test_prs_reconcile_workflow) {
    _create_committed_checkpoint();
    ozayn_prs_reconciliation_t *recon = NULL;
    int stages[] = { 1, 2, 3 };
    int ops[] = { 1, 0 };
    ASSERT_EQ(ozayn_prs_reconcile_workflow(&_svc, "wf-1", 0,
        stages, 3, ops, 2, 1, 1, 1, 1, 1, &recon), OZAYN_PRS_OK);
    ASSERT_NOT_NULL(recon);
    ASSERT(recon->recon_state == OZAYN_PRS_RECON_COMPLETED);
    ASSERT(recon->verdict == OZAYN_PRS_VERDICT_INTERRUPTED);
    ASSERT_EQ(recon->stage_count, 3);
    ASSERT_EQ(recon->operation_count, 2);
    _shutdown_svc();
    return 0;
}

TEST(test_prs_reconcile_workflow_not_found) {
    _init_svc();
    ozayn_prs_reconciliation_t *recon = NULL;
    ASSERT_EQ(ozayn_prs_reconcile_workflow(&_svc, "wf-1", 0,
        NULL, 0, NULL, 0, 1, 1, 1, 1, 1, &recon), OZAYN_PRS_ERR_NOT_FOUND);
    _shutdown_svc();
    return 0;
}

TEST(test_prs_reconcile_workflow_null) {
    _init_svc();
    ASSERT_EQ(ozayn_prs_reconcile_workflow(NULL, "wf-1", 0,
        NULL, 0, NULL, 0, 0, 0, 0, 0, 0, NULL), OZAYN_PRS_ERR_NULL);
    _shutdown_svc();
    return 0;
}

TEST(test_prs_reconciliation_get) {
    _create_committed_checkpoint();
    ozayn_prs_reconcile_workflow(&_svc, "wf-1", 0, NULL, 0, NULL, 0,
        1, 1, 1, 1, 1, NULL);
    const ozayn_prs_reconciliation_t *recon =
        ozayn_prs_reconciliation_get(&_svc, "wf-1");
    ASSERT_NOT_NULL(recon);
    _shutdown_svc();
    return 0;
}

TEST(test_prs_reconciliation_get_not_found) {
    _init_svc();
    ASSERT_NULL(ozayn_prs_reconciliation_get(&_svc, "wf-1"));
    _shutdown_svc();
    return 0;
}

TEST(test_prs_reconciliation_count) {
    _init_svc();
    ASSERT_EQ(ozayn_prs_reconciliation_count(&_svc), 0);
    _create_committed_checkpoint();
    ozayn_prs_reconcile_workflow(&_svc, "wf-1", 0, NULL, 0, NULL, 0,
        1, 1, 1, 1, 1, NULL);
    ASSERT_EQ(ozayn_prs_reconciliation_count(&_svc), 1);
    _shutdown_svc();
    return 0;
}

TEST(test_prs_reconciliation_advance) {
    _create_committed_checkpoint();
    ozayn_prs_reconcile_workflow(&_svc, "wf-1", 0, NULL, 0, NULL, 0,
        1, 1, 1, 1, 1, NULL);
    ASSERT_EQ(ozayn_prs_reconciliation_advance(&_svc, "wf-1",
        OZAYN_PRS_RECON_BLOCKED), OZAYN_PRS_ERR_STATE_INVALID);
    _shutdown_svc();
    return 0;
}

TEST(test_prs_reconciliation_advance_terminal) {
    _create_committed_checkpoint();
    ozayn_prs_reconcile_workflow(&_svc, "wf-1", 0, NULL, 0, NULL, 0,
        1, 1, 1, 1, 1, NULL);
    /* Already completed, should fail */
    ASSERT_EQ(ozayn_prs_reconciliation_advance(&_svc, "wf-1",
        OZAYN_PRS_RECON_BLOCKED), OZAYN_PRS_ERR_STATE_INVALID);
    _shutdown_svc();
    return 0;
}

TEST(test_prs_reconciliation_duplicate_risk) {
    _create_committed_checkpoint();
    ozayn_prs_reconciliation_t *recon = NULL;
    ozayn_prs_reconcile_workflow(&_svc, "wf-1", 1, NULL, 0, NULL, 0,
        1, 1, 1, 1, 1, &recon);
    /* Runtime state != 0 means workflow exists — should not be interrupted */
    ASSERT(recon->verdict == OZAYN_PRS_VERDICT_RECOVERY_REQUIRED);
    _shutdown_svc();
    return 0;
}

/* ============================================================
 * RECOVERY ELIGIBILITY TESTS
 * ============================================================ */

TEST(test_prs_eligibility_all_ok) {
    _create_committed_checkpoint();
    ozayn_prs_recovery_eligibility_t elig = OZAYN_PRS_INELIGIBLE;
    ASSERT_EQ(ozayn_prs_assess_eligibility(&_svc, "wf-1", 0,
        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, _now_ms(), &elig), OZAYN_PRS_OK);
    ASSERT(elig == OZAYN_PRS_ELIGIBLE);
    _shutdown_svc();
    return 0;
}

TEST(test_prs_eligibility_no_checkpoint) {
    _init_svc();
    ozayn_prs_recovery_eligibility_t elig = OZAYN_PRS_INELIGIBLE;
    ASSERT_EQ(ozayn_prs_assess_eligibility(&_svc, "wf-1", 0,
        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, _now_ms(), &elig), OZAYN_PRS_OK);
    ASSERT(elig == OZAYN_PRS_RECOVERY_UNAVAILABLE);
    _shutdown_svc();
    return 0;
}

TEST(test_prs_eligibility_schema_incompatible) {
    _create_committed_checkpoint();
    ozayn_prs_recovery_eligibility_t elig = OZAYN_PRS_INELIGIBLE;
    ASSERT_EQ(ozayn_prs_assess_eligibility(&_svc, "wf-1", 0,
        1, 0, 1, 1, 1, 1, 1, 1, 1, 1, _now_ms(), &elig), OZAYN_PRS_OK);
    ASSERT(elig == OZAYN_PRS_RECOVERY_CORRUPTED);
    _shutdown_svc();
    return 0;
}

TEST(test_prs_eligibility_expired) {
    _create_committed_checkpoint();
    /* Set expiration to the past so the checkpoint is expired */
    ozayn_prs_checkpoint_t *cp = (ozayn_prs_checkpoint_t *)
        ozayn_prs_checkpoint_get(&_svc, _cp_id);
    cp->expiration_time = 1000;
    ozayn_prs_recovery_eligibility_t elig = OZAYN_PRS_INELIGIBLE;
    ASSERT_EQ(ozayn_prs_assess_eligibility(&_svc, "wf-1", 0,
        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 2000, &elig),
        OZAYN_PRS_OK);
    ASSERT(elig == OZAYN_PRS_RECOVERY_EXPIRED);
    _shutdown_svc();
    return 0;
}

TEST(test_prs_eligibility_no_auth) {
    _create_committed_checkpoint();
    ozayn_prs_recovery_eligibility_t elig = OZAYN_PRS_INELIGIBLE;
    ASSERT_EQ(ozayn_prs_assess_eligibility(&_svc, "wf-1", 0,
        1, 1, 1, 1, 1, 1, 1, 1, 0, 1, _now_ms(), &elig), OZAYN_PRS_OK);
    ASSERT(elig == OZAYN_PRS_REQUIRES_REAUTHORIZATION);
    _shutdown_svc();
    return 0;
}

TEST(test_prs_eligibility_no_safety) {
    _create_committed_checkpoint();
    ozayn_prs_recovery_eligibility_t elig = OZAYN_PRS_INELIGIBLE;
    ASSERT_EQ(ozayn_prs_assess_eligibility(&_svc, "wf-1", 0,
        1, 1, 1, 1, 1, 1, 1, 1, 1, 0, _now_ms(), &elig), OZAYN_PRS_OK);
    ASSERT(elig == OZAYN_PRS_REQUIRES_SAFETY_RECHECK);
    _shutdown_svc();
    return 0;
}

TEST(test_prs_eligibility_no_resource) {
    _create_committed_checkpoint();
    ozayn_prs_recovery_eligibility_t elig = OZAYN_PRS_INELIGIBLE;
    ASSERT_EQ(ozayn_prs_assess_eligibility(&_svc, "wf-1", 0,
        1, 1, 1, 1, 1, 1, 0, 1, 1, 1, _now_ms(), &elig), OZAYN_PRS_OK);
    ASSERT(elig == OZAYN_PRS_REQUIRES_RESOURCE_RECHECK);
    _shutdown_svc();
    return 0;
}

TEST(test_prs_eligibility_no_device) {
    _create_committed_checkpoint();
    ozayn_prs_recovery_eligibility_t elig = OZAYN_PRS_INELIGIBLE;
    ASSERT_EQ(ozayn_prs_assess_eligibility(&_svc, "wf-1", 0,
        1, 1, 1, 1, 1, 0, 1, 1, 1, 1, _now_ms(), &elig), OZAYN_PRS_OK);
    ASSERT(elig == OZAYN_PRS_REQUIRES_DEVICE_RECHECK);
    _shutdown_svc();
    return 0;
}

TEST(test_prs_eligibility_no_session) {
    _create_committed_checkpoint();
    ozayn_prs_recovery_eligibility_t elig = OZAYN_PRS_INELIGIBLE;
    ASSERT_EQ(ozayn_prs_assess_eligibility(&_svc, "wf-1", 0,
        1, 1, 1, 1, 1, 1, 1, 0, 1, 1, _now_ms(), &elig), OZAYN_PRS_OK);
    ASSERT(elig == OZAYN_PRS_REQUIRES_REAUTHORIZATION);
    _shutdown_svc();
    return 0;
}

TEST(test_prs_eligibility_duplicate_risk) {
    _create_committed_checkpoint();
    ozayn_prs_recovery_eligibility_t elig = OZAYN_PRS_INELIGIBLE;
    /* Runtime state != 0 AND operation_valid == 0 = duplicate risk */
    ASSERT_EQ(ozayn_prs_assess_eligibility(&_svc, "wf-1", 1,
        1, 1, 1, 0, 1, 1, 1, 1, 1, 1, _now_ms(), &elig), OZAYN_PRS_OK);
    ASSERT(elig == OZAYN_PRS_RECOVERY_DUPLICATE_RISK);
    _shutdown_svc();
    return 0;
}

TEST(test_prs_eligibility_reason) {
    ASSERT_STR_EQ(ozayn_prs_eligibility_reason(OZAYN_PRS_ELIGIBLE), "ELIGIBLE");
    ASSERT_STR_EQ(ozayn_prs_eligibility_reason(OZAYN_PRS_INELIGIBLE), "INELIGIBLE");
    ASSERT_STR_EQ(ozayn_prs_eligibility_reason(OZAYN_PRS_RECOVERY_EXPIRED),
                  "RECOVERY_EXPIRED");
    return 0;
}

/* ============================================================
 * DUPLICATE EXECUTION PROTECTION TESTS
 * ============================================================ */

TEST(test_prs_check_duplicate_no_risk) {
    _init_svc();
    ASSERT(!ozayn_prs_check_duplicate_execution(&_svc, "op-1", NULL));
    _shutdown_svc();
    return 0;
}

TEST(test_prs_record_execution_attempt) {
    _init_svc();
    ASSERT_EQ(ozayn_prs_record_execution_attempt(&_svc, "op-1", "rec-1",
        "att-1"), OZAYN_PRS_OK);
    _shutdown_svc();
    return 0;
}

/* ============================================================
 * RETENTION AND CLEANUP TESTS
 * ============================================================ */

TEST(test_prs_retention_enforce) {
    _init_svc();
    ASSERT_EQ(ozayn_prs_retention_enforce(&_svc, _now_ms()), OZAYN_PRS_OK);
    _shutdown_svc();
    return 0;
}

TEST(test_prs_cleanup_expired) {
    _init_svc();
    ASSERT_EQ(ozayn_prs_cleanup_expired_checkpoints(&_svc, _now_ms()),
              OZAYN_PRS_OK);
    _shutdown_svc();
    return 0;
}

TEST(test_prs_cleanup_all) {
    _create_committed_checkpoint();
    ASSERT_EQ(ozayn_prs_cleanup_all(&_svc), OZAYN_PRS_OK);
    ASSERT_EQ(ozayn_prs_checkpoint_count(&_svc), 0);
    ASSERT_EQ(ozayn_prs_journal_count(&_svc), 0);
    _shutdown_svc();
    return 0;
}

TEST(test_prs_journal_cleanup_old) {
    _init_svc();
    ozayn_prs_journal_write(&_svc, OZAYN_PRS_JOURNAL_RESTART_DETECTED,
        NULL, "wf-1", NULL, NULL, NULL, NULL, "Restart", NULL);
    int removed = ozayn_prs_journal_cleanup_old(&_svc, 0, _now_ms());
    ASSERT_GE(removed, 0);
    _shutdown_svc();
    return 0;
}

/* ============================================================
 * TICK TESTS
 * ============================================================ */

TEST(test_prs_tick) {
    _init_svc();
    ASSERT_EQ(ozayn_prs_tick(&_svc, _now_ms()), OZAYN_PRS_OK);
    _shutdown_svc();
    return 0;
}

TEST(test_prs_tick_null) {
    ASSERT_EQ(ozayn_prs_tick(NULL, _now_ms()), OZAYN_PRS_ERR_NULL);
    return 0;
}

/* ============================================================
 * EVENT TESTS
 * ============================================================ */

TEST(test_prs_emit_event) {
    _init_svc();
    ASSERT_EQ(ozayn_prs_emit_event(&_svc, OZAYN_PRS_EVENT_CHECKPOINT_CREATED,
        "cp-1", "wf-1", "test"), OZAYN_PRS_OK);
    ASSERT_EQ(ozayn_prs_event_count(&_svc), 1);
    _shutdown_svc();
    return 0;
}

TEST(test_prs_emit_event_null) {
    _init_svc();
    ASSERT_EQ(ozayn_prs_emit_event(NULL, OZAYN_PRS_EVENT_CHECKPOINT_CREATED,
        NULL, NULL, NULL), OZAYN_PRS_ERR_NULL);
    _shutdown_svc();
    return 0;
}

TEST(test_prs_get_event) {
    _init_svc();
    ozayn_prs_emit_event(&_svc, OZAYN_PRS_EVENT_CHECKPOINT_CREATED,
        "cp-1", "wf-1", "test");
    const ozayn_prs_event_t *ev = ozayn_prs_get_event(&_svc, 0);
    ASSERT_NOT_NULL(ev);
    ASSERT(ev->event_type == OZAYN_PRS_EVENT_CHECKPOINT_CREATED);
    _shutdown_svc();
    return 0;
}

TEST(test_prs_get_event_invalid) {
    _init_svc();
    ASSERT_NULL(ozayn_prs_get_event(&_svc, -1));
    ASSERT_NULL(ozayn_prs_get_event(&_svc, 0));
    _shutdown_svc();
    return 0;
}

/* ============================================================
 * STATISTICS TESTS
 * ============================================================ */

TEST(test_prs_stats) {
    _init_svc();
    const ozayn_prs_stats_t *stats = ozayn_prs_get_stats(&_svc);
    ASSERT_NOT_NULL(stats);
    ASSERT_EQ(stats->total_checkpoints_created, 0);
    _create_simple_checkpoint();
    stats = ozayn_prs_get_stats(&_svc);
    ASSERT_EQ(stats->total_checkpoints_created, 1);
    _shutdown_svc();
    return 0;
}

TEST(test_prs_stats_null) {
    ASSERT_NULL(ozayn_prs_get_stats(NULL));
    return 0;
}

TEST(test_prs_reset_stats) {
    _init_svc();
    _create_simple_checkpoint();
    ASSERT_EQ(ozayn_prs_reset_stats(&_svc), OZAYN_PRS_OK);
    const ozayn_prs_stats_t *stats = ozayn_prs_get_stats(&_svc);
    ASSERT_EQ(stats->total_checkpoints_created, 0);
    _shutdown_svc();
    return 0;
}

/* ============================================================
 * VALIDATION TESTS
 * ============================================================ */

TEST(test_prs_validate_checkpoint) {
    _create_committed_checkpoint();
    const ozayn_prs_checkpoint_t *cp = ozayn_prs_checkpoint_get(&_svc, _cp_id);
    ASSERT(ozayn_prs_validate_checkpoint(cp));
    _shutdown_svc();
    return 0;
}

TEST(test_prs_validate_checkpoint_null) {
    ASSERT(!ozayn_prs_validate_checkpoint(NULL));
    return 0;
}

TEST(test_prs_validate_checkpoint_inactive) {
    ozayn_prs_checkpoint_t bad;
    memset(&bad, 0, sizeof(bad));
    bad.active = 0;
    ASSERT(!ozayn_prs_validate_checkpoint(&bad));
    return 0;
}

TEST(test_prs_validate_config) {
    ozayn_prs_service_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    ASSERT(ozayn_prs_validate_config(&cfg));
    ASSERT(!ozayn_prs_validate_config(NULL));
    return 0;
}

TEST(test_prs_valid_transition) {
    ASSERT(ozayn_prs_is_valid_checkpoint_transition(
        OZAYN_PRS_CP_CREATED, OZAYN_PRS_CP_VALIDATING));
    ASSERT(!ozayn_prs_is_valid_checkpoint_transition(
        OZAYN_PRS_CP_CREATED, OZAYN_PRS_CP_COMMITTED));
    ASSERT(ozayn_prs_is_valid_checkpoint_transition(
        OZAYN_PRS_CP_VALIDATING, OZAYN_PRS_CP_COMMITTED));
    ASSERT(!ozayn_prs_is_valid_checkpoint_transition(
        OZAYN_PRS_CP_COMMITTED, OZAYN_PRS_CP_CREATED));
    return 0;
}

/* ============================================================
 * NAME HELPER TESTS
 * ============================================================ */

TEST(test_prs_err_name) {
    ASSERT_STR_EQ(ozayn_prs_err_name(OZAYN_PRS_OK), "OK");
    ASSERT_STR_EQ(ozayn_prs_err_name(OZAYN_PRS_ERR_NULL), "NULL");
    ASSERT_STR_EQ(ozayn_prs_err_name(OZAYN_PRS_ERR_NOT_FOUND), "NOT_FOUND");
    return 0;
}

TEST(test_prs_checkpoint_state_name) {
    ASSERT_STR_EQ(ozayn_prs_checkpoint_state_name(OZAYN_PRS_CP_CREATED), "CREATED");
    ASSERT_STR_EQ(ozayn_prs_checkpoint_state_name(OZAYN_PRS_CP_COMMITTED), "COMMITTED");
    ASSERT_STR_EQ(ozayn_prs_checkpoint_state_name(OZAYN_PRS_CP_RECOVERED), "RECOVERED");
    return 0;
}

TEST(test_prs_recovery_eligibility_name) {
    ASSERT_STR_EQ(ozayn_prs_recovery_eligibility_name(OZAYN_PRS_ELIGIBLE), "ELIGIBLE");
    ASSERT_STR_EQ(ozayn_prs_recovery_eligibility_name(OZAYN_PRS_INELIGIBLE), "INELIGIBLE");
    return 0;
}

TEST(test_prs_reconciliation_state_name) {
    ASSERT_STR_EQ(ozayn_prs_reconciliation_state_name(OZAYN_PRS_RECON_PENDING), "PENDING");
    ASSERT_STR_EQ(ozayn_prs_reconciliation_state_name(OZAYN_PRS_RECON_COMPLETED), "COMPLETED");
    return 0;
}

TEST(test_prs_reconciliation_verdict_name) {
    ASSERT_STR_EQ(ozayn_prs_reconciliation_verdict_name(OZAYN_PRS_VERDICT_COMPLETED), "COMPLETED");
    ASSERT_STR_EQ(ozayn_prs_reconciliation_verdict_name(OZAYN_PRS_VERDICT_INTERRUPTED), "INTERRUPTED");
    return 0;
}

TEST(test_prs_journal_event_type_name) {
    ASSERT_STR_EQ(ozayn_prs_journal_event_type_name(OZAYN_PRS_JOURNAL_CHECKPOINT_CREATED),
                  "CHECKPOINT_CREATED");
    ASSERT_STR_EQ(ozayn_prs_journal_event_type_name(OZAYN_PRS_JOURNAL_RESTART_DETECTED),
                  "RESTART_DETECTED");
    return 0;
}

TEST(test_prs_event_type_name) {
    ASSERT_STR_EQ(ozayn_prs_event_type_name(OZAYN_PRS_EVENT_CHECKPOINT_CREATED),
                  "CHECKPOINT_CREATED");
    ASSERT_STR_EQ(ozayn_prs_event_type_name(OZAYN_PRS_EVENT_RESTART_DETECTED),
                  "RESTART_DETECTED");
    return 0;
}

TEST(test_prs_stage_recon_result_name) {
    ASSERT_STR_EQ(ozayn_prs_stage_recon_result_name(OZAYN_PRS_STAGE_COMPLETED), "COMPLETED");
    ASSERT_STR_EQ(ozayn_prs_stage_recon_result_name(OZAYN_PRS_STAGE_INTERRUPTED), "INTERRUPTED");
    return 0;
}

TEST(test_prs_operation_recon_result_name) {
    ASSERT_STR_EQ(ozayn_prs_operation_recon_result_name(OZAYN_PRS_OP_COMPLETED), "COMPLETED");
    ASSERT_STR_EQ(ozayn_prs_operation_recon_result_name(OZAYN_PRS_OP_DUPLICATE_RISK), "DUPLICATE_RISK");
    return 0;
}

/* ============================================================
 * FULL LIFECYCLE TEST
 * ============================================================ */

TEST(test_prs_full_lifecycle) {
    _init_svc();

    /* Create checkpoint */
    ASSERT_EQ(ozayn_prs_checkpoint_create(&_svc, "wf-1", "1.0", "lifecycle",
        "Full lifecycle test", 3, 0, 0, 0, 4, 0, 0, 0, 3, 0, 0,
        "owner", NULL, NULL, NULL, "op-1", NULL,
        60000, 0, 0, 0, _cp_id, sizeof(_cp_id)), OZAYN_PRS_OK);

    /* Add references */
    ozayn_prs_checkpoint_add_failure_ref(&_svc, _cp_id, "fail-1");
    ozayn_prs_checkpoint_add_resource_ref(&_svc, _cp_id, "res-1");
    ozayn_prs_checkpoint_add_device_ref(&_svc, _cp_id, "dev-1");

    /* Validate and commit */
    ASSERT_EQ(ozayn_prs_checkpoint_validate(&_svc, _cp_id), OZAYN_PRS_OK);
    ASSERT_EQ(ozayn_prs_checkpoint_commit(&_svc, _cp_id), OZAYN_PRS_OK);

    /* Detect restart */
    ASSERT_EQ(ozayn_prs_detect_restart(&_svc, _now_ms()), OZAYN_PRS_OK);

    /* Reconcile */
    ozayn_prs_reconciliation_t *recon = NULL;
    ASSERT_EQ(ozayn_prs_reconcile_workflow(&_svc, "wf-1", 0,
        NULL, 0, NULL, 0, 1, 1, 1, 1, 1, &recon), OZAYN_PRS_OK);
    ASSERT_NOT_NULL(recon);
    ASSERT(recon->verdict == OZAYN_PRS_VERDICT_INTERRUPTED);

    /* Assess eligibility */
    ozayn_prs_recovery_eligibility_t elig = OZAYN_PRS_INELIGIBLE;
    ASSERT_EQ(ozayn_prs_assess_eligibility(&_svc, "wf-1", 0,
        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, _now_ms(), &elig), OZAYN_PRS_OK);
    ASSERT(elig == OZAYN_PRS_ELIGIBLE);

    /* Verify stats */
    const ozayn_prs_stats_t *stats = ozayn_prs_get_stats(&_svc);
    ASSERT_EQ(stats->total_checkpoints_created, 1);
    ASSERT_EQ(stats->total_checkpoints_committed, 1);
    ASSERT_EQ(stats->total_restarts_detected, 1);
    ASSERT_EQ(stats->total_reconciliations_completed, 1);

    _shutdown_svc();
    return 0;
}

/* ============================================================
 * CRASH CONSISTENCY TESTS
 * ============================================================ */

TEST(test_prs_crash_before_checkpoint) {
    _init_svc();
    /* No checkpoint created — should handle gracefully */
    ASSERT_NULL(ozayn_prs_checkpoint_get_latest_valid(&_svc, "wf-1"));
    _shutdown_svc();
    return 0;
}

TEST(test_prs_crash_after_create_before_commit) {
    _create_simple_checkpoint();
    /* Checkpoint is in CREATED state — not committed */
    const ozayn_prs_checkpoint_t *cp = ozayn_prs_checkpoint_get(&_svc, _cp_id);
    ASSERT(!ozayn_prs_checkpoint_is_valid(cp));
    _shutdown_svc();
    return 0;
}

TEST(test_prs_crash_after_commit) {
    _create_committed_checkpoint();
    /* Simulate restart */
    ozayn_prs_detect_restart(&_svc, _now_ms());
    /* Checkpoint should be recovery-required */
    const ozayn_prs_checkpoint_t *cp = ozayn_prs_checkpoint_get(&_svc, _cp_id);
    ASSERT(cp->state == OZAYN_PRS_CP_RECOVERY_REQUIRED);
    _shutdown_svc();
    return 0;
}

/* ============================================================
 * SECURITY TESTS
 * ============================================================ */

TEST(test_prs_no_bypass_auth) {
    _create_committed_checkpoint();
    ozayn_prs_recovery_eligibility_t elig = OZAYN_PRS_INELIGIBLE;
    /* Without auth, should require reauthorization */
    ASSERT_EQ(ozayn_prs_assess_eligibility(&_svc, "wf-1", 0,
        1, 1, 1, 1, 1, 1, 1, 1, 0, 1, _now_ms(), &elig), OZAYN_PRS_OK);
    ASSERT(elig == OZAYN_PRS_REQUIRES_REAUTHORIZATION);
    _shutdown_svc();
    return 0;
}

TEST(test_prs_no_bypass_safety) {
    _create_committed_checkpoint();
    ozayn_prs_recovery_eligibility_t elig = OZAYN_PRS_INELIGIBLE;
    /* Without safety, should require safety recheck */
    ASSERT_EQ(ozayn_prs_assess_eligibility(&_svc, "wf-1", 0,
        1, 1, 1, 1, 1, 1, 1, 1, 1, 0, _now_ms(), &elig), OZAYN_PRS_OK);
    ASSERT(elig == OZAYN_PRS_REQUIRES_SAFETY_RECHECK);
    _shutdown_svc();
    return 0;
}

TEST(test_prs_no_bypass_resource) {
    _create_committed_checkpoint();
    ozayn_prs_recovery_eligibility_t elig = OZAYN_PRS_INELIGIBLE;
    ASSERT_EQ(ozayn_prs_assess_eligibility(&_svc, "wf-1", 0,
        1, 1, 1, 1, 1, 1, 0, 1, 1, 1, _now_ms(), &elig), OZAYN_PRS_OK);
    ASSERT(elig == OZAYN_PRS_REQUIRES_RESOURCE_RECHECK);
    _shutdown_svc();
    return 0;
}

/* ============================================================
 * MAIN — TEST RUNNER
 * ============================================================ */

int run_cr_workflow_checkpoint_tests(void) {
    SUITE_BEGIN("Control Room — Workflow Checkpoint (Step 18)");

    /* Lifecycle */
    RUN(test_prs_init);
    RUN(test_prs_init_null);
    RUN(test_prs_init_null_cfg);
    RUN(test_prs_init_double);
    RUN(test_prs_shutdown);
    RUN(test_prs_shutdown_null);
    RUN(test_prs_shutdown_not_init);
    RUN(test_prs_is_initialized_null);
    RUN(test_prs_global);

    /* Checkpoint creation */
    RUN(test_prs_checkpoint_create);
    RUN(test_prs_checkpoint_create_null);
    RUN(test_prs_checkpoint_create_not_init);
    RUN(test_prs_checkpoint_create_bad_id_len);
    RUN(test_prs_checkpoint_create_bad_stage_count);
    RUN(test_prs_checkpoint_create_multiple);

    /* State transitions */
    RUN(test_prs_checkpoint_validate);
    RUN(test_prs_checkpoint_commit);
    RUN(test_prs_checkpoint_commit_no_validate);
    RUN(test_prs_checkpoint_supersede);
    RUN(test_prs_checkpoint_invalidate);
    RUN(test_prs_checkpoint_invalidate_terminal);
    RUN(test_prs_checkpoint_mark_recovered);
    RUN(test_prs_checkpoint_validate_not_found);
    RUN(test_prs_checkpoint_commit_not_found);

    /* Query */
    RUN(test_prs_checkpoint_get);
    RUN(test_prs_checkpoint_get_not_found);
    RUN(test_prs_checkpoint_get_null);
    RUN(test_prs_checkpoint_get_latest_valid);
    RUN(test_prs_checkpoint_get_latest_valid_none);
    RUN(test_prs_checkpoint_count);
    RUN(test_prs_checkpoint_count_by_workflow);
    RUN(test_prs_checkpoint_is_valid);
    RUN(test_prs_checkpoint_is_valid_not_committed);
    RUN(test_prs_checkpoint_is_expired);
    RUN(test_prs_checkpoint_is_expired_with_time);

    /* References */
    RUN(test_prs_checkpoint_add_failure_ref);
    RUN(test_prs_checkpoint_add_resource_ref);
    RUN(test_prs_checkpoint_add_device_ref);
    RUN(test_prs_checkpoint_add_ref_limit);

    /* Journal */
    RUN(test_prs_journal_write);
    RUN(test_prs_journal_write_null);
    RUN(test_prs_journal_write_bad_type);
    RUN(test_prs_journal_get);
    RUN(test_prs_journal_get_invalid_index);
    RUN(test_prs_journal_get_latest_for_workflow);

    /* Restart detection */
    RUN(test_prs_detect_restart);
    RUN(test_prs_detect_restart_journal);

    /* Reconciliation */
    RUN(test_prs_reconcile_workflow);
    RUN(test_prs_reconcile_workflow_not_found);
    RUN(test_prs_reconcile_workflow_null);
    RUN(test_prs_reconciliation_get);
    RUN(test_prs_reconciliation_get_not_found);
    RUN(test_prs_reconciliation_count);
    RUN(test_prs_reconciliation_advance);
    RUN(test_prs_reconciliation_advance_terminal);
    RUN(test_prs_reconciliation_duplicate_risk);

    /* Eligibility */
    RUN(test_prs_eligibility_all_ok);
    RUN(test_prs_eligibility_no_checkpoint);
    RUN(test_prs_eligibility_schema_incompatible);
    RUN(test_prs_eligibility_expired);
    RUN(test_prs_eligibility_no_auth);
    RUN(test_prs_eligibility_no_safety);
    RUN(test_prs_eligibility_no_resource);
    RUN(test_prs_eligibility_no_device);
    RUN(test_prs_eligibility_no_session);
    RUN(test_prs_eligibility_duplicate_risk);
    RUN(test_prs_eligibility_reason);

    /* Duplicate execution */
    RUN(test_prs_check_duplicate_no_risk);
    RUN(test_prs_record_execution_attempt);

    /* Retention and cleanup */
    RUN(test_prs_retention_enforce);
    RUN(test_prs_cleanup_expired);
    RUN(test_prs_cleanup_all);
    RUN(test_prs_journal_cleanup_old);

    /* Tick */
    RUN(test_prs_tick);
    RUN(test_prs_tick_null);

    /* Events */
    RUN(test_prs_emit_event);
    RUN(test_prs_emit_event_null);
    RUN(test_prs_get_event);
    RUN(test_prs_get_event_invalid);

    /* Statistics */
    RUN(test_prs_stats);
    RUN(test_prs_stats_null);
    RUN(test_prs_reset_stats);

    /* Validation */
    RUN(test_prs_validate_checkpoint);
    RUN(test_prs_validate_checkpoint_null);
    RUN(test_prs_validate_checkpoint_inactive);
    RUN(test_prs_validate_config);
    RUN(test_prs_valid_transition);

    /* Name helpers */
    RUN(test_prs_err_name);
    RUN(test_prs_checkpoint_state_name);
    RUN(test_prs_recovery_eligibility_name);
    RUN(test_prs_reconciliation_state_name);
    RUN(test_prs_reconciliation_verdict_name);
    RUN(test_prs_journal_event_type_name);
    RUN(test_prs_event_type_name);
    RUN(test_prs_stage_recon_result_name);
    RUN(test_prs_operation_recon_result_name);

    /* Full lifecycle */
    RUN(test_prs_full_lifecycle);

    /* Crash consistency */
    RUN(test_prs_crash_before_checkpoint);
    RUN(test_prs_crash_after_create_before_commit);
    RUN(test_prs_crash_after_commit);

    /* Security */
    RUN(test_prs_no_bypass_auth);
    RUN(test_prs_no_bypass_safety);
    RUN(test_prs_no_bypass_resource);

    SUITE_END();
    return TOTAL_FAIL();
}
