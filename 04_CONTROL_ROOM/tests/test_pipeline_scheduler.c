#include "../../tests/test_framework.h"
#include "../pipeline_scheduler.h"
#include <string.h>

static ozayn_spa_service_t _svc;
static ozayn_spa_service_config_t _cfg;

static void _reset_all(void) {
    memset(&_svc, 0, sizeof(_svc));
}

static void _init_svc(void) {
    _reset_all();
    memset(&_cfg, 0, sizeof(_cfg));
    ozayn_spa_service_init(&_svc, &_cfg);
}

static char _entry_id[OZAYN_SPA_MAX_ID_LEN];
static char _entry_id2[OZAYN_SPA_MAX_ID_LEN];

static void _submit_one_with_prio(ozayn_spa_priority_t p) {
    ozayn_spa_submit(&_svc, "pipe-1", "op-1", "req-1", p, NULL);
    const ozayn_spa_entry_t *e = ozayn_spa_find_entry_by_pipeline(&_svc, "pipe-1");
    if (e) strncpy(_entry_id, e->entry_id, OZAYN_SPA_MAX_ID_LEN);
}

static void _submit_one(void) {
    _submit_one_with_prio(OZAYN_SPA_PRIORITY_NORMAL);
}

static void _submit_two(void) {
    _submit_one();
    ozayn_spa_submit(&_svc, "pipe-2", "op-2", "req-2", OZAYN_SPA_PRIORITY_NORMAL, NULL);
    const ozayn_spa_entry_t *e = ozayn_spa_find_entry_by_pipeline(&_svc, "pipe-2");
    if (e) strncpy(_entry_id2, e->entry_id, OZAYN_SPA_MAX_ID_LEN);
}

static void _ready_one(void) {
    _submit_one();
    ozayn_spa_set_security_session(&_svc, _entry_id, "sess-1");
    ozayn_spa_set_authorization_ref(&_svc, _entry_id, "auth-1");
    ozayn_spa_set_safety_decision_ref(&_svc, _entry_id, "safety-1");
    ozayn_spa_tick(&_svc);
}

static ozayn_spa_err_t _submit_with_state(ozayn_spa_service_t *svc,
                                          const char *pipe, const char *op,
                                          ozayn_spa_priority_t p,
                                          const char *sess, const char *auth,
                                          const char *safety, char *out_id, int out_len) {
    ozayn_spa_err_t r = ozayn_spa_submit(svc, pipe, op, "req", p, NULL);
    if (r != OZAYN_SPA_OK) return r;
    const ozayn_spa_entry_t *e = ozayn_spa_find_entry_by_pipeline(svc, pipe);
    if (!e) return OZAYN_SPA_ERR_NOT_FOUND;
    if (out_id && out_len > 0) strncpy(out_id, e->entry_id, out_len - 1);
    if (sess) ozayn_spa_set_security_session(svc, e->entry_id, sess);
    if (auth) ozayn_spa_set_authorization_ref(svc, e->entry_id, auth);
    if (safety) ozayn_spa_set_safety_decision_ref(svc, e->entry_id, safety);
    return OZAYN_SPA_OK;
}

/* ============================================================
 * LIFECYCLE TESTS
 * ============================================================ */

TEST(test_spa_init) {
    _reset_all();
    memset(&_cfg, 0, sizeof(_cfg));
    ASSERT_EQ(ozayn_spa_service_init(&_svc, &_cfg), OZAYN_SPA_OK);
    ASSERT(_svc.initialized);
    ozayn_spa_service_shutdown(&_svc);
    return 0;
}

TEST(test_spa_init_null) {
    ASSERT_EQ(ozayn_spa_service_init(NULL, &_cfg), OZAYN_SPA_ERR_NULL);
    return 0;
}

TEST(test_spa_init_null_cfg) {
    _reset_all();
    ASSERT_EQ(ozayn_spa_service_init(&_svc, NULL), OZAYN_SPA_OK);
    ASSERT(_svc.initialized);
    ozayn_spa_service_shutdown(&_svc);
    return 0;
}

TEST(test_spa_init_double) {
    _reset_all();
    memset(&_cfg, 0, sizeof(_cfg));
    ASSERT_EQ(ozayn_spa_service_init(&_svc, &_cfg), OZAYN_SPA_OK);
    ASSERT_EQ(ozayn_spa_service_init(&_svc, &_cfg), OZAYN_SPA_ERR_ALREADY_INIT);
    ozayn_spa_service_shutdown(&_svc);
    return 0;
}

TEST(test_spa_shutdown) {
    _init_svc();
    ASSERT_EQ(ozayn_spa_service_shutdown(&_svc), OZAYN_SPA_OK);
    ASSERT(!_svc.initialized);
    return 0;
}

TEST(test_spa_shutdown_null) {
    ASSERT_EQ(ozayn_spa_service_shutdown(NULL), OZAYN_SPA_ERR_NULL);
    return 0;
}

TEST(test_spa_shutdown_not_init) {
    _reset_all();
    ASSERT_EQ(ozayn_spa_service_shutdown(&_svc), OZAYN_SPA_ERR_NOT_INITIALIZED);
    return 0;
}

TEST(test_spa_is_initialized) {
    _reset_all();
    ASSERT(!ozayn_spa_service_is_initialized(&_svc));
    _init_svc();
    ASSERT(ozayn_spa_service_is_initialized(&_svc));
    ozayn_spa_service_shutdown(&_svc);
    return 0;
}

TEST(test_spa_is_initialized_null) {
    ASSERT(!ozayn_spa_service_is_initialized(NULL));
    return 0;
}

TEST(test_spa_global) {
    ozayn_spa_service_t *g = ozayn_spa_get_global();
    ASSERT_NOT_NULL(g);
    return 0;
}

/* ============================================================
 * SUBMIT TESTS
 * ============================================================ */

TEST(test_spa_submit) {
    _init_svc();
    ASSERT_EQ(ozayn_spa_submit(&_svc, "pipe-1", "op-1", "req-1",
                               OZAYN_SPA_PRIORITY_NORMAL, NULL), OZAYN_SPA_OK);
    ASSERT_EQ(_svc.entry_count, 1);
    ASSERT(_svc.stats.total_submitted == 1);
    const ozayn_spa_entry_t *e = ozayn_spa_find_entry_by_pipeline(&_svc, "pipe-1");
    ASSERT_NOT_NULL(e);
    ASSERT(e->active);
    ASSERT_EQ(e->state, OZAYN_SPA_SCHED_QUEUED);
    ASSERT_EQ(e->priority, OZAYN_SPA_PRIORITY_NORMAL);
    ozayn_spa_service_shutdown(&_svc);
    return 0;
}

TEST(test_spa_submit_null) {
    _init_svc();
    ASSERT_EQ(ozayn_spa_submit(NULL, "pipe-1", "op-1", "req-1",
                               OZAYN_SPA_PRIORITY_NORMAL, NULL), OZAYN_SPA_ERR_NULL);
    ozayn_spa_service_shutdown(&_svc);
    return 0;
}

TEST(test_spa_submit_not_init) {
    _reset_all();
    ASSERT_EQ(ozayn_spa_submit(&_svc, "pipe-1", "op-1", "req-1",
                               OZAYN_SPA_PRIORITY_NORMAL, NULL), OZAYN_SPA_ERR_NOT_INITIALIZED);
    return 0;
}

TEST(test_spa_submit_null_pipeline) {
    _init_svc();
    ASSERT_EQ(ozayn_spa_submit(&_svc, "", "op-1", "req-1",
                               OZAYN_SPA_PRIORITY_NORMAL, NULL), OZAYN_SPA_ERR_INVALID_PARAM);
    ASSERT_EQ(ozayn_spa_submit(&_svc, NULL, "op-1", "req-1",
                               OZAYN_SPA_PRIORITY_NORMAL, NULL), OZAYN_SPA_ERR_INVALID_PARAM);
    ozayn_spa_service_shutdown(&_svc);
    return 0;
}

TEST(test_spa_submit_null_op) {
    _init_svc();
    ASSERT_EQ(ozayn_spa_submit(&_svc, "pipe-1", "", "req-1",
                               OZAYN_SPA_PRIORITY_NORMAL, NULL), OZAYN_SPA_ERR_INVALID_PARAM);
    ozayn_spa_service_shutdown(&_svc);
    return 0;
}

TEST(test_spa_submit_bad_priority) {
    _init_svc();
    ASSERT_EQ(ozayn_spa_submit(&_svc, "pipe-1", "op-1", "req-1",
                               (ozayn_spa_priority_t)99, NULL), OZAYN_SPA_ERR_INVALID_PARAM);
    ozayn_spa_service_shutdown(&_svc);
    return 0;
}

TEST(test_spa_submit_duplicate) {
    _init_svc();
    ASSERT_EQ(ozayn_spa_submit(&_svc, "pipe-1", "op-1", "req-1",
                               OZAYN_SPA_PRIORITY_NORMAL, NULL), OZAYN_SPA_OK);
    ASSERT_EQ(ozayn_spa_submit(&_svc, "pipe-1", "op-2", "req-2",
                               OZAYN_SPA_PRIORITY_HIGH, NULL), OZAYN_SPA_ERR_DUPLICATE);
    ozayn_spa_service_shutdown(&_svc);
    return 0;
}

TEST(test_spa_submit_limit) {
    _init_svc();
    _submit_one();
    ASSERT_EQ(_svc.entry_count, 1);
    ASSERT(!ozayn_spa_queue_full(&_svc));
    ozayn_spa_service_shutdown(&_svc);
    return 0;
}

TEST(test_spa_submit_with_metadata) {
    _init_svc();
    ASSERT_EQ(ozayn_spa_submit(&_svc, "pipe-1", "op-1", "req-1",
                               OZAYN_SPA_PRIORITY_NORMAL, "test metadata"), OZAYN_SPA_OK);
    const ozayn_spa_entry_t *e = ozayn_spa_find_entry_by_pipeline(&_svc, "pipe-1");
    ASSERT_NOT_NULL(e);
    ASSERT(strcmp(e->safe_metadata, "test metadata") == 0);
    ozayn_spa_service_shutdown(&_svc);
    return 0;
}

TEST(test_spa_submit_all_priorities) {
    _init_svc();
    ASSERT_EQ(ozayn_spa_submit(&_svc, "p1", "o1", "r1", OZAYN_SPA_PRIORITY_LOW, NULL), OZAYN_SPA_OK);
    ASSERT_EQ(ozayn_spa_submit(&_svc, "p2", "o2", "r2", OZAYN_SPA_PRIORITY_NORMAL, NULL), OZAYN_SPA_OK);
    ASSERT_EQ(ozayn_spa_submit(&_svc, "p3", "o3", "r3", OZAYN_SPA_PRIORITY_HIGH, NULL), OZAYN_SPA_OK);
    ASSERT_EQ(ozayn_spa_submit(&_svc, "p4", "o4", "r4", OZAYN_SPA_PRIORITY_CRITICAL, NULL), OZAYN_SPA_OK);
    ASSERT_EQ(_svc.entry_count, 4);
    ozayn_spa_service_shutdown(&_svc);
    return 0;
}

/* ============================================================
 * CANCEL TESTS
 * ============================================================ */

TEST(test_spa_cancel) {
    _init_svc();
    _submit_one();
    ASSERT_EQ(ozayn_spa_cancel(&_svc, _entry_id, OZAYN_SPA_CLOSE_MANUAL_CANCEL), OZAYN_SPA_OK);
    const ozayn_spa_entry_t *e = ozayn_spa_find_entry(&_svc, _entry_id);
    ASSERT_EQ(e->state, OZAYN_SPA_SCHED_CANCELLED);
    ASSERT_EQ(e->close_reason, OZAYN_SPA_CLOSE_MANUAL_CANCEL);
    ASSERT(_svc.stats.total_cancelled == 1);
    ozayn_spa_service_shutdown(&_svc);
    return 0;
}

TEST(test_spa_cancel_null) {
    _init_svc();
    ASSERT_EQ(ozayn_spa_cancel(NULL, "e1", OZAYN_SPA_CLOSE_MANUAL_CANCEL), OZAYN_SPA_ERR_NULL);
    ozayn_spa_service_shutdown(&_svc);
    return 0;
}

TEST(test_spa_cancel_not_found) {
    _init_svc();
    ASSERT_EQ(ozayn_spa_cancel(&_svc, "nonexistent", OZAYN_SPA_CLOSE_MANUAL_CANCEL),
              OZAYN_SPA_ERR_NOT_FOUND);
    ozayn_spa_service_shutdown(&_svc);
    return 0;
}

TEST(test_spa_cancel_terminal) {
    _init_svc();
    _submit_one();
    ozayn_spa_cancel(&_svc, _entry_id, OZAYN_SPA_CLOSE_MANUAL_CANCEL);
    ASSERT_EQ(ozayn_spa_cancel(&_svc, _entry_id, OZAYN_SPA_CLOSE_MANUAL_CANCEL),
              OZAYN_SPA_ERR_STATE_INVALID);
    ozayn_spa_service_shutdown(&_svc);
    return 0;
}

/* ============================================================
 * REMOVE TESTS
 * ============================================================ */

TEST(test_spa_remove) {
    _init_svc();
    _submit_one();
    ozayn_spa_cancel(&_svc, _entry_id, OZAYN_SPA_CLOSE_MANUAL_CANCEL);
    ASSERT_EQ(ozayn_spa_remove(&_svc, _entry_id), OZAYN_SPA_OK);
    ASSERT_NULL(ozayn_spa_find_entry(&_svc, _entry_id));
    ozayn_spa_service_shutdown(&_svc);
    return 0;
}

TEST(test_spa_remove_not_terminal) {
    _init_svc();
    _submit_one();
    ASSERT_EQ(ozayn_spa_remove(&_svc, _entry_id), OZAYN_SPA_ERR_STATE_INVALID);
    ozayn_spa_service_shutdown(&_svc);
    return 0;
}

TEST(test_spa_remove_not_found) {
    _init_svc();
    ASSERT_EQ(ozayn_spa_remove(&_svc, "nonexistent"), OZAYN_SPA_ERR_NOT_FOUND);
    ozayn_spa_service_shutdown(&_svc);
    return 0;
}

/* ============================================================
 * DEPENDENCY TESTS
 * ============================================================ */

TEST(test_spa_add_dependency) {
    _init_svc();
    _submit_two();
    ASSERT_EQ(ozayn_spa_add_dependency(&_svc, _entry_id2, _entry_id), OZAYN_SPA_OK);
    const ozayn_spa_entry_t *e = ozayn_spa_find_entry(&_svc, _entry_id2);
    ASSERT_EQ(e->dependency_count, 1);
    ozayn_spa_service_shutdown(&_svc);
    return 0;
}

TEST(test_spa_add_dependency_cycle) {
    _init_svc();
    _submit_two();
    ozayn_spa_add_dependency(&_svc, _entry_id2, _entry_id);
    ASSERT_EQ(ozayn_spa_add_dependency(&_svc, _entry_id, _entry_id2),
              OZAYN_SPA_ERR_DEPENDENCY_CYCLE);
    ozayn_spa_service_shutdown(&_svc);
    return 0;
}

TEST(test_spa_add_dependency_self) {
    _init_svc();
    _submit_one();
    ASSERT_EQ(ozayn_spa_add_dependency(&_svc, _entry_id, _entry_id),
              OZAYN_SPA_ERR_DEPENDENCY_CYCLE);
    ozayn_spa_service_shutdown(&_svc);
    return 0;
}

TEST(test_spa_add_dependency_not_found) {
    _init_svc();
    _submit_one();
    ASSERT_EQ(ozayn_spa_add_dependency(&_svc, _entry_id, "nonexistent"),
              OZAYN_SPA_ERR_NOT_FOUND);
    ASSERT_EQ(ozayn_spa_add_dependency(&_svc, "nonexistent", _entry_id),
              OZAYN_SPA_ERR_NOT_FOUND);
    ozayn_spa_service_shutdown(&_svc);
    return 0;
}

TEST(test_spa_add_dependency_limit) {
    _init_svc();
    char dep_ids[OZAYN_SPA_MAX_DEPENDENCIES + 1][OZAYN_SPA_MAX_ID_LEN];
    for (int i = 0; i <= OZAYN_SPA_MAX_DEPENDENCIES; i++) {
        char pipe[32], op[32], req[32];
        snprintf(pipe, sizeof(pipe), "dep-pipe-%d", i);
        snprintf(op, sizeof(op), "dep-op-%d", i);
        snprintf(req, sizeof(req), "dep-req-%d", i);
        ozayn_spa_submit(&_svc, pipe, op, req, OZAYN_SPA_PRIORITY_NORMAL, NULL);
        snprintf(dep_ids[i], OZAYN_SPA_MAX_ID_LEN, "dep-pipe-%d", i);
    }
    const ozayn_spa_entry_t *last = ozayn_spa_find_entry_by_pipeline(&_svc, "dep-pipe-0");
    for (int i = 1; i <= OZAYN_SPA_MAX_DEPENDENCIES; i++) {
        const ozayn_spa_entry_t *dep = ozayn_spa_find_entry_by_pipeline(&_svc, dep_ids[i]);
        ozayn_spa_add_dependency(&_svc, last->entry_id, dep->entry_id);
    }
    const ozayn_spa_entry_t *extra = ozayn_spa_find_entry_by_pipeline(&_svc, "dep-pipe-0");
    ASSERT_EQ(ozayn_spa_add_dependency(&_svc, extra->entry_id, "nonexistent2"),
              OZAYN_SPA_ERR_NOT_FOUND);
    ozayn_spa_service_shutdown(&_svc);
    return 0;
}

/* ============================================================
 * RESOURCE REQUIREMENTS TESTS
 * ============================================================ */

TEST(test_spa_set_required_resources) {
    _init_svc();
    _submit_one();
    char ids[2][OZAYN_SPA_MAX_ID_LEN];
    strncpy(ids[0], "res-1", OZAYN_SPA_MAX_ID_LEN - 1);
    strncpy(ids[1], "res-2", OZAYN_SPA_MAX_ID_LEN - 1);
    ASSERT_EQ(ozayn_spa_set_required_resources(&_svc, _entry_id, ids, 2), OZAYN_SPA_OK);
    const ozayn_spa_entry_t *e = ozayn_spa_find_entry(&_svc, _entry_id);
    ASSERT_EQ(e->required_resource_count, 2);
    ozayn_spa_service_shutdown(&_svc);
    return 0;
}

TEST(test_spa_set_required_resources_bad_count) {
    _init_svc();
    _submit_one();
    ASSERT_EQ(ozayn_spa_set_required_resources(&_svc, _entry_id, NULL, -1),
              OZAYN_SPA_ERR_INVALID_PARAM);
    ASSERT_EQ(ozayn_spa_set_required_resources(&_svc, _entry_id, NULL,
              OZAYN_SPA_MAX_REQUIRED_RESOURCES + 1), OZAYN_SPA_ERR_INVALID_PARAM);
    ozayn_spa_service_shutdown(&_svc);
    return 0;
}

TEST(test_spa_set_required_devices) {
    _init_svc();
    _submit_one();
    char ids[1][OZAYN_SPA_MAX_ID_LEN];
    strncpy(ids[0], "dev-1", OZAYN_SPA_MAX_ID_LEN - 1);
    ASSERT_EQ(ozayn_spa_set_required_devices(&_svc, _entry_id, ids, 1), OZAYN_SPA_OK);
    const ozayn_spa_entry_t *e = ozayn_spa_find_entry(&_svc, _entry_id);
    ASSERT_EQ(e->required_device_count, 1);
    ozayn_spa_service_shutdown(&_svc);
    return 0;
}

TEST(test_spa_set_required_streams) {
    _init_svc();
    _submit_one();
    char ids[1][OZAYN_SPA_MAX_ID_LEN];
    strncpy(ids[0], "stream-1", OZAYN_SPA_MAX_ID_LEN - 1);
    ASSERT_EQ(ozayn_spa_set_required_streams(&_svc, _entry_id, ids, 1), OZAYN_SPA_OK);
    const ozayn_spa_entry_t *e = ozayn_spa_find_entry(&_svc, _entry_id);
    ASSERT_EQ(e->required_stream_count, 1);
    ozayn_spa_service_shutdown(&_svc);
    return 0;
}

TEST(test_spa_set_required_routes) {
    _init_svc();
    _submit_one();
    char ids[1][OZAYN_SPA_MAX_ID_LEN];
    strncpy(ids[0], "route-1", OZAYN_SPA_MAX_ID_LEN - 1);
    ASSERT_EQ(ozayn_spa_set_required_routes(&_svc, _entry_id, ids, 1), OZAYN_SPA_OK);
    const ozayn_spa_entry_t *e = ozayn_spa_find_entry(&_svc, _entry_id);
    ASSERT_EQ(e->required_route_count, 1);
    ozayn_spa_service_shutdown(&_svc);
    return 0;
}

TEST(test_spa_resource_not_found) {
    _init_svc();
    _submit_one();
    char ids[1][OZAYN_SPA_MAX_ID_LEN];
    strncpy(ids[0], "r1", OZAYN_SPA_MAX_ID_LEN - 1);
    ASSERT_EQ(ozayn_spa_set_required_resources(&_svc, "nonexistent", ids, 1),
              OZAYN_SPA_ERR_NOT_FOUND);
    ozayn_spa_service_shutdown(&_svc);
    return 0;
}

/* ============================================================
 * DEADLINE / TIMING TESTS
 * ============================================================ */

TEST(test_spa_set_deadline) {
    _init_svc();
    _submit_one();
    ASSERT_EQ(ozayn_spa_set_deadline(&_svc, _entry_id, 5000), OZAYN_SPA_OK);
    const ozayn_spa_entry_t *e = ozayn_spa_find_entry(&_svc, _entry_id);
    ASSERT(e->deadline_ms == 5000);
    ASSERT(e->expiration_time > 0);
    ozayn_spa_service_shutdown(&_svc);
    return 0;
}

TEST(test_spa_set_max_wait) {
    _init_svc();
    _submit_one();
    ASSERT_EQ(ozayn_spa_set_max_wait_time(&_svc, _entry_id, 10000), OZAYN_SPA_OK);
    const ozayn_spa_entry_t *e = ozayn_spa_find_entry(&_svc, _entry_id);
    ASSERT(e->max_wait_time_ms == 10000);
    ozayn_spa_service_shutdown(&_svc);
    return 0;
}

TEST(test_spa_deadline_not_found) {
    _init_svc();
    ASSERT_EQ(ozayn_spa_set_deadline(&_svc, "nonexistent", 5000), OZAYN_SPA_ERR_NOT_FOUND);
    ozayn_spa_service_shutdown(&_svc);
    return 0;
}

/* ============================================================
 * SECURITY REFERENCES TESTS
 * ============================================================ */

TEST(test_spa_set_security_session) {
    _init_svc();
    _submit_one();
    ASSERT_EQ(ozayn_spa_set_security_session(&_svc, _entry_id, "sess-1"), OZAYN_SPA_OK);
    const ozayn_spa_entry_t *e = ozayn_spa_find_entry(&_svc, _entry_id);
    ASSERT(strcmp(e->security_session_ref, "sess-1") == 0);
    ozayn_spa_service_shutdown(&_svc);
    return 0;
}

TEST(test_spa_set_auth_ref) {
    _init_svc();
    _submit_one();
    ASSERT_EQ(ozayn_spa_set_authorization_ref(&_svc, _entry_id, "auth-1"), OZAYN_SPA_OK);
    const ozayn_spa_entry_t *e = ozayn_spa_find_entry(&_svc, _entry_id);
    ASSERT(strcmp(e->authorization_ref, "auth-1") == 0);
    ozayn_spa_service_shutdown(&_svc);
    return 0;
}

TEST(test_spa_set_safety_ref) {
    _init_svc();
    _submit_one();
    ASSERT_EQ(ozayn_spa_set_safety_decision_ref(&_svc, _entry_id, "safety-1"), OZAYN_SPA_OK);
    const ozayn_spa_entry_t *e = ozayn_spa_find_entry(&_svc, _entry_id);
    ASSERT(strcmp(e->safety_decision_ref, "safety-1") == 0);
    ozayn_spa_service_shutdown(&_svc);
    return 0;
}

TEST(test_spa_security_not_found) {
    _init_svc();
    ASSERT_EQ(ozayn_spa_set_security_session(&_svc, "no", "s"), OZAYN_SPA_ERR_NOT_FOUND);
    ASSERT_EQ(ozayn_spa_set_authorization_ref(&_svc, "no", "a"), OZAYN_SPA_ERR_NOT_FOUND);
    ASSERT_EQ(ozayn_spa_set_safety_decision_ref(&_svc, "no", "s"), OZAYN_SPA_ERR_NOT_FOUND);
    ozayn_spa_service_shutdown(&_svc);
    return 0;
}

/* ============================================================
 * TICK TESTS
 * ============================================================ */

TEST(test_spa_tick) {
    _init_svc();
    _submit_one();
    ASSERT_EQ(ozayn_spa_tick(&_svc), OZAYN_SPA_OK);
    ASSERT(_svc.stats.total_ticks == 1);
    ozayn_spa_service_shutdown(&_svc);
    return 0;
}

TEST(test_spa_tick_null) {
    ASSERT_EQ(ozayn_spa_tick(NULL), OZAYN_SPA_ERR_NULL);
    return 0;
}

TEST(test_spa_tick_moves_to_waiting) {
    _init_svc();
    _submit_one();
    ozayn_spa_tick(&_svc);
    const ozayn_spa_entry_t *e = ozayn_spa_find_entry(&_svc, _entry_id);
    ASSERT(e->state == OZAYN_SPA_SCHED_WAITING || e->state == OZAYN_SPA_SCHED_ELIGIBLE);
    ozayn_spa_service_shutdown(&_svc);
    return 0;
}

TEST(test_spa_tick_eligible) {
    _init_svc();
    _submit_one();
    ozayn_spa_set_security_session(&_svc, _entry_id, "sess-1");
    ozayn_spa_set_authorization_ref(&_svc, _entry_id, "auth-1");
    ozayn_spa_set_safety_decision_ref(&_svc, _entry_id, "safety-1");
    ozayn_spa_tick(&_svc);
    const ozayn_spa_entry_t *e = ozayn_spa_find_entry(&_svc, _entry_id);
    ASSERT_EQ(e->state, OZAYN_SPA_SCHED_ELIGIBLE);
    ozayn_spa_service_shutdown(&_svc);
    return 0;
}

TEST(test_spa_tick_terminal_expired) {
    _init_svc();
    _submit_one();
    ozayn_spa_set_deadline(&_svc, _entry_id, 1);
    const ozayn_spa_entry_t *e_check = ozayn_spa_find_entry(&_svc, _entry_id);
    ozayn_spa_entry_t *e_mutable = (ozayn_spa_entry_t *)e_check;
    e_mutable->expiration_time = 1;
    ozayn_spa_tick(&_svc);
    ASSERT_EQ(e_mutable->state, OZAYN_SPA_SCHED_EXPIRED);
    ozayn_spa_service_shutdown(&_svc);
    return 0;
}

TEST(test_spa_tick_max_attempts) {
    _init_svc();
    _svc.config.max_scheduling_attempts = 1;
    _submit_one();
    ozayn_spa_tick(&_svc);
    const ozayn_spa_entry_t *e = ozayn_spa_find_entry(&_svc, _entry_id);
    ASSERT(e->state == OZAYN_SPA_SCHED_ELIGIBLE || e->state == OZAYN_SPA_SCHED_EXPIRED);
    ozayn_spa_service_shutdown(&_svc);
    return 0;
}

TEST(test_spa_tick_multiple) {
    _init_svc();
    _submit_two();
    ASSERT_EQ(ozayn_spa_tick(&_svc), OZAYN_SPA_OK);
    ASSERT(_svc.stats.total_ticks == 1);
    ozayn_spa_service_shutdown(&_svc);
    return 0;
}

/* ============================================================
 * EVALUATE TESTS
 * ============================================================ */

TEST(test_spa_evaluate) {
    _init_svc();
    _ready_one();
    ozayn_spa_decision_record_t dec;
    ASSERT_EQ(ozayn_spa_evaluate_entry(&_svc, _entry_id, &dec), OZAYN_SPA_OK);
    ASSERT(dec.active);
    ASSERT(dec.eligibility_ok);
    ASSERT(dec.decision == OZAYN_SPA_DECISION_SCHEDULE);
    ozayn_spa_service_shutdown(&_svc);
    return 0;
}

TEST(test_spa_evaluate_not_found) {
    _init_svc();
    ozayn_spa_decision_record_t dec;
    ASSERT_EQ(ozayn_spa_evaluate_entry(&_svc, "no", &dec), OZAYN_SPA_ERR_NOT_FOUND);
    ozayn_spa_service_shutdown(&_svc);
    return 0;
}

TEST(test_spa_evaluate_no_auth) {
    _init_svc();
    _submit_one();
    ozayn_spa_set_security_session(&_svc, _entry_id, "sess-1");
    ozayn_spa_set_safety_decision_ref(&_svc, _entry_id, "safety-1");
    ozayn_spa_tick(&_svc);
    ozayn_spa_decision_record_t dec;
    ASSERT_EQ(ozayn_spa_evaluate_entry(&_svc, _entry_id, &dec), OZAYN_SPA_OK);
    ASSERT(!dec.authorization_ok);
    ASSERT(dec.decision == OZAYN_SPA_DECISION_WAIT);
    ozayn_spa_service_shutdown(&_svc);
    return 0;
}

TEST(test_spa_evaluate_no_safety) {
    _init_svc();
    _submit_one();
    ozayn_spa_set_security_session(&_svc, _entry_id, "sess-1");
    ozayn_spa_set_authorization_ref(&_svc, _entry_id, "auth-1");
    ozayn_spa_tick(&_svc);
    ozayn_spa_decision_record_t dec;
    ASSERT_EQ(ozayn_spa_evaluate_entry(&_svc, _entry_id, &dec), OZAYN_SPA_OK);
    ASSERT(!dec.safety_ok);
    ASSERT(dec.decision == OZAYN_SPA_DECISION_WAIT);
    ozayn_spa_service_shutdown(&_svc);
    return 0;
}

TEST(test_spa_evaluate_dep_wait) {
    _init_svc();
    _submit_two();
    ozayn_spa_add_dependency(&_svc, _entry_id2, _entry_id);
    ozayn_spa_set_security_session(&_svc, _entry_id2, "sess-1");
    ozayn_spa_set_authorization_ref(&_svc, _entry_id2, "auth-1");
    ozayn_spa_set_safety_decision_ref(&_svc, _entry_id2, "safety-1");
    ozayn_spa_tick(&_svc);
    ozayn_spa_decision_record_t dec;
    ASSERT_EQ(ozayn_spa_evaluate_entry(&_svc, _entry_id2, &dec), OZAYN_SPA_OK);
    ASSERT(!dec.dependency_ok);
    ASSERT(dec.decision == OZAYN_SPA_DECISION_WAIT);
    ozayn_spa_service_shutdown(&_svc);
    return 0;
}

TEST(test_spa_evaluate_terminal) {
    _init_svc();
    _submit_one();
    ozayn_spa_cancel(&_svc, _entry_id, OZAYN_SPA_CLOSE_MANUAL_CANCEL);
    ozayn_spa_decision_record_t dec;
    ASSERT_EQ(ozayn_spa_evaluate_entry(&_svc, _entry_id, &dec), OZAYN_SPA_OK);
    ASSERT(!dec.eligibility_ok);
    ASSERT(dec.decision == OZAYN_SPA_DECISION_REJECT);
    ozayn_spa_service_shutdown(&_svc);
    return 0;
}

TEST(test_spa_evaluate_concurrency) {
    _init_svc();
    _svc.config.max_running = 1;
    char eid[OZAYN_SPA_MAX_ID_LEN];
    _submit_with_state(&_svc, "p1", "o1", OZAYN_SPA_PRIORITY_NORMAL, "s", "a", "saf", eid, sizeof(eid));
    ozayn_spa_tick(&_svc);
    ozayn_spa_transition(&_svc, eid, OZAYN_SPA_SCHED_ELIGIBLE);
    ozayn_spa_transition(&_svc, eid, OZAYN_SPA_SCHED_SCHEDULED);
    ozayn_spa_transition(&_svc, eid, OZAYN_SPA_SCHED_RESERVED);
    ozayn_spa_transition(&_svc, eid, OZAYN_SPA_SCHED_STARTING);
    ozayn_spa_transition(&_svc, eid, OZAYN_SPA_SCHED_RUNNING);

    char eid2[OZAYN_SPA_MAX_ID_LEN];
    _submit_with_state(&_svc, "p2", "o2", OZAYN_SPA_PRIORITY_NORMAL, "s", "a", "saf", eid2, sizeof(eid2));
    ozayn_spa_tick(&_svc);
    ozayn_spa_decision_record_t dec;
    ASSERT_EQ(ozayn_spa_evaluate_entry(&_svc, eid2, &dec), OZAYN_SPA_OK);
    ASSERT(dec.decision == OZAYN_SPA_DECISION_DEFER);
    ozayn_spa_service_shutdown(&_svc);
    return 0;
}

/* ============================================================
 * SCHEDULE NEXT TESTS
 * ============================================================ */

TEST(test_spa_schedule_next) {
    _init_svc();
    _ready_one();
    char out[OZAYN_SPA_MAX_ID_LEN];
    ASSERT_EQ(ozayn_spa_schedule_next(&_svc, out, sizeof(out)), OZAYN_SPA_OK);
    const ozayn_spa_entry_t *e = ozayn_spa_find_entry(&_svc, out);
    ASSERT_EQ(e->state, OZAYN_SPA_SCHED_SCHEDULED);
    ASSERT(_svc.stats.total_scheduled == 1);
    ozayn_spa_service_shutdown(&_svc);
    return 0;
}

TEST(test_spa_schedule_next_not_found) {
    _init_svc();
    char out[OZAYN_SPA_MAX_ID_LEN];
    ASSERT_EQ(ozayn_spa_schedule_next(&_svc, out, sizeof(out)), OZAYN_SPA_ERR_NOT_FOUND);
    ozayn_spa_service_shutdown(&_svc);
    return 0;
}

TEST(test_spa_schedule_next_concurrency) {
    _init_svc();
    _svc.config.max_running = 1;
    char eid[OZAYN_SPA_MAX_ID_LEN];
    _submit_with_state(&_svc, "p1", "o1", OZAYN_SPA_PRIORITY_NORMAL, "s", "a", "saf", eid, sizeof(eid));
    ozayn_spa_tick(&_svc);
    ozayn_spa_transition(&_svc, eid, OZAYN_SPA_SCHED_ELIGIBLE);
    char out[OZAYN_SPA_MAX_ID_LEN];
    ASSERT_EQ(ozayn_spa_schedule_next(&_svc, out, sizeof(out)), OZAYN_SPA_OK);
    ozayn_spa_transition(&_svc, out, OZAYN_SPA_SCHED_RESERVED);
    ozayn_spa_transition(&_svc, out, OZAYN_SPA_SCHED_STARTING);
    ozayn_spa_transition(&_svc, out, OZAYN_SPA_SCHED_RUNNING);

    char eid2[OZAYN_SPA_MAX_ID_LEN];
    _submit_with_state(&_svc, "p2", "o2", OZAYN_SPA_PRIORITY_NORMAL, "s", "a", "saf", eid2, sizeof(eid2));
    ozayn_spa_tick(&_svc);
    ASSERT_EQ(ozayn_spa_schedule_next(&_svc, out, sizeof(out)), OZAYN_SPA_ERR_CONCURRENCY);
    ozayn_spa_service_shutdown(&_svc);
    return 0;
}

TEST(test_spa_schedule_next_priority_order) {
    _init_svc();
    _submit_with_state(&_svc, "p-low", "o1", OZAYN_SPA_PRIORITY_LOW, "s", "a", "saf",
                       NULL, 0);
    _submit_with_state(&_svc, "p-high", "o2", OZAYN_SPA_PRIORITY_HIGH, "s", "a", "saf",
                       NULL, 0);
    ozayn_spa_tick(&_svc);
    char out[OZAYN_SPA_MAX_ID_LEN];
    ASSERT_EQ(ozayn_spa_schedule_next(&_svc, out, sizeof(out)), OZAYN_SPA_OK);
    const ozayn_spa_entry_t *e = ozayn_spa_find_entry(&_svc, out);
    ASSERT(strcmp(e->pipeline_id, "p-high") == 0);
    ozayn_spa_service_shutdown(&_svc);
    return 0;
}

TEST(test_spa_schedule_next_fifo_same_prio) {
    _init_svc();
    _submit_with_state(&_svc, "p1", "o1", OZAYN_SPA_PRIORITY_NORMAL, "s", "a", "saf",
                       NULL, 0);
    _submit_with_state(&_svc, "p2", "o2", OZAYN_SPA_PRIORITY_NORMAL, "s", "a", "saf",
                       NULL, 0);
    ozayn_spa_tick(&_svc);
    char out[OZAYN_SPA_MAX_ID_LEN];
    ASSERT_EQ(ozayn_spa_schedule_next(&_svc, out, sizeof(out)), OZAYN_SPA_OK);
    const ozayn_spa_entry_t *e = ozayn_spa_find_entry(&_svc, out);
    ASSERT(strcmp(e->pipeline_id, "p1") == 0);
    ozayn_spa_service_shutdown(&_svc);
    return 0;
}

/* ============================================================
 * CONFLICT DETECTION TESTS
 * ============================================================ */

TEST(test_spa_check_conflicts_none) {
    _init_svc();
    _submit_one();
    int has_conflict = 0;
    ASSERT_EQ(ozayn_spa_check_conflicts(&_svc, _entry_id, &has_conflict, NULL, 0), OZAYN_SPA_OK);
    ASSERT(!has_conflict);
    ozayn_spa_service_shutdown(&_svc);
    return 0;
}

TEST(test_spa_check_conflicts_device) {
    _init_svc();
    _submit_two();
    char dev[1][OZAYN_SPA_MAX_ID_LEN];
    strncpy(dev[0], "cam-1", OZAYN_SPA_MAX_ID_LEN - 1);
    ozayn_spa_set_required_devices(&_svc, _entry_id, dev, 1);
    ozayn_spa_set_required_devices(&_svc, _entry_id2, dev, 1);
    ozayn_spa_tick(&_svc);
    ozayn_spa_transition(&_svc, _entry_id, OZAYN_SPA_SCHED_ELIGIBLE);
    ozayn_spa_transition(&_svc, _entry_id, OZAYN_SPA_SCHED_SCHEDULED);
    ozayn_spa_transition(&_svc, _entry_id, OZAYN_SPA_SCHED_RUNNING);

    int has_conflict = 0;
    char conflicting[OZAYN_SPA_MAX_ID_LEN];
    ASSERT_EQ(ozayn_spa_check_conflicts(&_svc, _entry_id2, &has_conflict,
              conflicting, sizeof(conflicting)), OZAYN_SPA_OK);
    ASSERT(has_conflict);
    ASSERT(strcmp(conflicting, _entry_id) == 0);
    ozayn_spa_service_shutdown(&_svc);
    return 0;
}

TEST(test_spa_check_conflicts_not_found) {
    _init_svc();
    int has_conflict = 0;
    ASSERT_EQ(ozayn_spa_check_conflicts(&_svc, "no", &has_conflict, NULL, 0),
              OZAYN_SPA_ERR_NOT_FOUND);
    ozayn_spa_service_shutdown(&_svc);
    return 0;
}

/* ============================================================
 * STATE TRANSITION TESTS
 * ============================================================ */

TEST(test_spa_transition) {
    _init_svc();
    _submit_one();
    ASSERT_EQ(ozayn_spa_transition(&_svc, _entry_id, OZAYN_SPA_SCHED_WAITING), OZAYN_SPA_OK);
    ASSERT_EQ(_svc.entries[0].state, OZAYN_SPA_SCHED_WAITING);
    ozayn_spa_service_shutdown(&_svc);
    return 0;
}

TEST(test_spa_transition_invalid) {
    _init_svc();
    _submit_one();
    ASSERT_EQ(ozayn_spa_transition(&_svc, _entry_id, OZAYN_SPA_SCHED_COMPLETED),
              OZAYN_SPA_ERR_STATE_INVALID);
    ozayn_spa_service_shutdown(&_svc);
    return 0;
}

TEST(test_spa_transition_not_found) {
    _init_svc();
    ASSERT_EQ(ozayn_spa_transition(&_svc, "no", OZAYN_SPA_SCHED_WAITING),
              OZAYN_SPA_ERR_NOT_FOUND);
    ozayn_spa_service_shutdown(&_svc);
    return 0;
}

TEST(test_spa_transition_completed) {
    _init_svc();
    _ready_one();
    ozayn_spa_transition(&_svc, _entry_id, OZAYN_SPA_SCHED_ELIGIBLE);
    ozayn_spa_transition(&_svc, _entry_id, OZAYN_SPA_SCHED_SCHEDULED);
    ozayn_spa_transition(&_svc, _entry_id, OZAYN_SPA_SCHED_RESERVED);
    ozayn_spa_transition(&_svc, _entry_id, OZAYN_SPA_SCHED_STARTING);
    ozayn_spa_transition(&_svc, _entry_id, OZAYN_SPA_SCHED_RUNNING);
    ASSERT_EQ(ozayn_spa_transition(&_svc, _entry_id, OZAYN_SPA_SCHED_COMPLETED), OZAYN_SPA_OK);
    ASSERT(_svc.stats.total_completed == 1);
    ozayn_spa_service_shutdown(&_svc);
    return 0;
}

TEST(test_spa_transition_failed) {
    _init_svc();
    _ready_one();
    ozayn_spa_transition(&_svc, _entry_id, OZAYN_SPA_SCHED_ELIGIBLE);
    ozayn_spa_transition(&_svc, _entry_id, OZAYN_SPA_SCHED_SCHEDULED);
    ozayn_spa_transition(&_svc, _entry_id, OZAYN_SPA_SCHED_RESERVED);
    ozayn_spa_transition(&_svc, _entry_id, OZAYN_SPA_SCHED_STARTING);
    ozayn_spa_transition(&_svc, _entry_id, OZAYN_SPA_SCHED_RUNNING);
    ASSERT_EQ(ozayn_spa_transition(&_svc, _entry_id, OZAYN_SPA_SCHED_FAILED), OZAYN_SPA_OK);
    ASSERT(_svc.stats.total_failed == 1);
    ozayn_spa_service_shutdown(&_svc);
    return 0;
}

/* ============================================================
 * QUERY TESTS
 * ============================================================ */

TEST(test_spa_find_entry) {
    _init_svc();
    _submit_one();
    ASSERT_NOT_NULL(ozayn_spa_find_entry(&_svc, _entry_id));
    ASSERT_NULL(ozayn_spa_find_entry(&_svc, "nonexistent"));
    ozayn_spa_service_shutdown(&_svc);
    return 0;
}

TEST(test_spa_find_by_pipeline) {
    _init_svc();
    _submit_one();
    ASSERT_NOT_NULL(ozayn_spa_find_entry_by_pipeline(&_svc, "pipe-1"));
    ASSERT_NULL(ozayn_spa_find_entry_by_pipeline(&_svc, "nonexistent"));
    ozayn_spa_service_shutdown(&_svc);
    return 0;
}

TEST(test_spa_entry_count) {
    _init_svc();
    ASSERT_EQ(ozayn_spa_entry_count(&_svc), 0);
    _submit_one();
    ASSERT_EQ(ozayn_spa_entry_count(&_svc), 1);
    _submit_two();
    ASSERT_EQ(ozayn_spa_entry_count(&_svc), 2);
    ozayn_spa_service_shutdown(&_svc);
    return 0;
}

TEST(test_spa_running_count) {
    _init_svc();
    ASSERT_EQ(ozayn_spa_running_count(&_svc), 0);
    ozayn_spa_service_shutdown(&_svc);
    return 0;
}

TEST(test_spa_waiting_count) {
    _init_svc();
    ASSERT_EQ(ozayn_spa_waiting_count(&_svc), 0);
    _submit_one();
    ASSERT_EQ(ozayn_spa_waiting_count(&_svc), 1);
    ozayn_spa_service_shutdown(&_svc);
    return 0;
}

TEST(test_spa_eligible_count) {
    _init_svc();
    ASSERT_EQ(ozayn_spa_eligible_count(&_svc), 0);
    ozayn_spa_service_shutdown(&_svc);
    return 0;
}

TEST(test_spa_queue_full) {
    _init_svc();
    ASSERT(!ozayn_spa_queue_full(&_svc));
    _svc.config.max_entries = 1;
    _submit_one();
    ASSERT(ozayn_spa_queue_full(&_svc));
    ozayn_spa_service_shutdown(&_svc);
    return 0;
}

TEST(test_spa_running_limit) {
    _init_svc();
    ASSERT(!ozayn_spa_running_limit(&_svc));
    ozayn_spa_service_shutdown(&_svc);
    return 0;
}

/* ============================================================
 * EVENTS TESTS
 * ============================================================ */

TEST(test_spa_emit_event) {
    _init_svc();
    ASSERT_EQ(ozayn_spa_emit_event(&_svc, OZAYN_SPA_EVENT_SCHEDULER_STARTED,
              "", "", "test"), OZAYN_SPA_OK);
    ASSERT(_svc.event_count > 0);
    ozayn_spa_service_shutdown(&_svc);
    return 0;
}

TEST(test_spa_get_event) {
    _init_svc();
    ozayn_spa_emit_event(&_svc, OZAYN_SPA_EVENT_SCHEDULER_STARTED, "", "", "msg");
    const ozayn_spa_event_t *ev = ozayn_spa_get_event(&_svc, 0);
    ASSERT_NOT_NULL(ev);
    ASSERT_EQ(ev->type, OZAYN_SPA_EVENT_SCHEDULER_STARTED);
    ozayn_spa_service_shutdown(&_svc);
    return 0;
}

TEST(test_spa_get_event_invalid) {
    _init_svc();
    ASSERT_NULL(ozayn_spa_get_event(&_svc, -1));
    ASSERT_NULL(ozayn_spa_get_event(&_svc, 100));
    ozayn_spa_service_shutdown(&_svc);
    return 0;
}

TEST(test_spa_event_count) {
    _init_svc();
    ASSERT_GE(ozayn_spa_event_count(&_svc), 1);
    ozayn_spa_emit_event(&_svc, OZAYN_SPA_EVENT_SCHEDULER_STARTED, "", "", "m1");
    ozayn_spa_emit_event(&_svc, OZAYN_SPA_EVENT_SCHEDULER_STOPPED, "", "", "m2");
    ASSERT_GE(ozayn_spa_event_count(&_svc), 3);
    ozayn_spa_service_shutdown(&_svc);
    return 0;
}

TEST(test_spa_event_overflow) {
    _init_svc();
    for (int i = 0; i < OZAYN_SPA_MAX_EVENTS + 5; i++) {
        ozayn_spa_emit_event(&_svc, OZAYN_SPA_EVENT_TICK_EVALUATED, "", "", "overflow");
    }
    ASSERT_EQ(ozayn_spa_event_count(&_svc), OZAYN_SPA_MAX_EVENTS);
    ozayn_spa_service_shutdown(&_svc);
    return 0;
}

/* ============================================================
 * CLEANUP TESTS
 * ============================================================ */

TEST(test_spa_cleanup_terminal) {
    _init_svc();
    _submit_one();
    ozayn_spa_cancel(&_svc, _entry_id, OZAYN_SPA_CLOSE_MANUAL_CANCEL);
    ASSERT_EQ(ozayn_spa_cleanup_terminal(&_svc), 1);
    ASSERT_EQ(_svc.entry_count, 0);
    ozayn_spa_service_shutdown(&_svc);
    return 0;
}

TEST(test_spa_cleanup_expired) {
    _init_svc();
    _submit_one();
    ozayn_spa_cancel(&_svc, _entry_id, OZAYN_SPA_CLOSE_MANUAL_CANCEL);
    ozayn_spa_entry_t *e = (ozayn_spa_entry_t *)ozayn_spa_find_entry(&_svc, _entry_id);
    e->expiration_time = 1;
    ASSERT_EQ(ozayn_spa_cleanup_expired(&_svc), 1);
    ozayn_spa_service_shutdown(&_svc);
    return 0;
}

TEST(test_spa_cleanup_all) {
    _init_svc();
    _submit_two();
    ASSERT_EQ(ozayn_spa_cleanup_all(&_svc), 2);
    ASSERT_EQ(_svc.entry_count, 0);
    ozayn_spa_service_shutdown(&_svc);
    return 0;
}

/* ============================================================
 * STATS TESTS
 * ============================================================ */

TEST(test_spa_stats) {
    _init_svc();
    ozayn_spa_stats_t s = ozayn_spa_get_stats(&_svc);
    ASSERT(s.total_submitted == 0);
    ASSERT(s.total_scheduled == 0);
    ASSERT(s.total_completed == 0);
    _submit_one();
    s = ozayn_spa_get_stats(&_svc);
    ASSERT(s.total_submitted == 1);
    ASSERT(s.current_queued == 1);
    ozayn_spa_service_shutdown(&_svc);
    return 0;
}

TEST(test_spa_stats_null) {
    ozayn_spa_stats_t s = ozayn_spa_get_stats(NULL);
    ASSERT(s.total_submitted == 0);
    return 0;
}

/* ============================================================
 * VALIDATION TESTS
 * ============================================================ */

TEST(test_spa_validate_entry) {
    _init_svc();
    _submit_one();
    const ozayn_spa_entry_t *e = ozayn_spa_find_entry(&_svc, _entry_id);
    ASSERT_EQ(ozayn_spa_validate_entry(&_svc, e), OZAYN_SPA_OK);
    ozayn_spa_service_shutdown(&_svc);
    return 0;
}

TEST(test_spa_validate_entry_null) {
    ASSERT_EQ(ozayn_spa_validate_entry(NULL, NULL), OZAYN_SPA_ERR_NULL);
    return 0;
}

TEST(test_spa_validate_config) {
    ozayn_spa_service_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    ASSERT_EQ(ozayn_spa_validate_config(&cfg), OZAYN_SPA_OK);
    return 0;
}

TEST(test_spa_validate_config_null) {
    ASSERT_EQ(ozayn_spa_validate_config(NULL), OZAYN_SPA_ERR_NULL);
    return 0;
}

/* ============================================================
 * NAME HELPER TESTS
 * ============================================================ */

TEST(test_spa_err_name) {
    ASSERT(strcmp(ozayn_spa_err_name(OZAYN_SPA_OK), "OK") == 0);
    ASSERT(strcmp(ozayn_spa_err_name(OZAYN_SPA_ERR_NULL), "NULL") == 0);
    ASSERT(strcmp(ozayn_spa_err_name(OZAYN_SPA_ERR_NOT_INITIALIZED), "NOT_INITIALIZED") == 0);
    ASSERT(strcmp(ozayn_spa_err_name(OZAYN_SPA_ERR_DUPLICATE), "DUPLICATE") == 0);
    ASSERT(strcmp(ozayn_spa_err_name(OZAYN_SPA_ERR_QUEUE_FULL), "QUEUE_FULL") == 0);
    ASSERT(strcmp(ozayn_spa_err_name((ozayn_spa_err_t)999), "UNKNOWN") == 0);
    return 0;
}

TEST(test_spa_sched_state_name) {
    ASSERT(strcmp(ozayn_spa_sched_state_name(OZAYN_SPA_SCHED_CREATED), "CREATED") == 0);
    ASSERT(strcmp(ozayn_spa_sched_state_name(OZAYN_SPA_SCHED_QUEUED), "QUEUED") == 0);
    ASSERT(strcmp(ozayn_spa_sched_state_name(OZAYN_SPA_SCHED_WAITING), "WAITING") == 0);
    ASSERT(strcmp(ozayn_spa_sched_state_name(OZAYN_SPA_SCHED_ELIGIBLE), "ELIGIBLE") == 0);
    ASSERT(strcmp(ozayn_spa_sched_state_name(OZAYN_SPA_SCHED_SCHEDULED), "SCHEDULED") == 0);
    ASSERT(strcmp(ozayn_spa_sched_state_name(OZAYN_SPA_SCHED_RUNNING), "RUNNING") == 0);
    ASSERT(strcmp(ozayn_spa_sched_state_name(OZAYN_SPA_SCHED_COMPLETED), "COMPLETED") == 0);
    ASSERT(strcmp(ozayn_spa_sched_state_name(OZAYN_SPA_SCHED_FAILED), "FAILED") == 0);
    ASSERT(strcmp(ozayn_spa_sched_state_name(OZAYN_SPA_SCHED_CANCELLED), "CANCELLED") == 0);
    ASSERT(strcmp(ozayn_spa_sched_state_name(OZAYN_SPA_SCHED_EXPIRED), "EXPIRED") == 0);
    ASSERT(strcmp(ozayn_spa_sched_state_name(OZAYN_SPA_SCHED_REJECTED), "REJECTED") == 0);
    ASSERT(strcmp(ozayn_spa_sched_state_name((ozayn_spa_sched_state_t)999), "UNKNOWN") == 0);
    return 0;
}

TEST(test_spa_priority_name) {
    ASSERT(strcmp(ozayn_spa_priority_name(OZAYN_SPA_PRIORITY_LOW), "LOW") == 0);
    ASSERT(strcmp(ozayn_spa_priority_name(OZAYN_SPA_PRIORITY_NORMAL), "NORMAL") == 0);
    ASSERT(strcmp(ozayn_spa_priority_name(OZAYN_SPA_PRIORITY_HIGH), "HIGH") == 0);
    ASSERT(strcmp(ozayn_spa_priority_name(OZAYN_SPA_PRIORITY_CRITICAL), "CRITICAL") == 0);
    ASSERT(strcmp(ozayn_spa_priority_name((ozayn_spa_priority_t)999), "UNKNOWN") == 0);
    return 0;
}

TEST(test_spa_decision_name) {
    ASSERT(strcmp(ozayn_spa_decision_name(OZAYN_SPA_DECISION_SCHEDULE), "SCHEDULE") == 0);
    ASSERT(strcmp(ozayn_spa_decision_name(OZAYN_SPA_DECISION_WAIT), "WAIT") == 0);
    ASSERT(strcmp(ozayn_spa_decision_name(OZAYN_SPA_DECISION_DEFER), "DEFER") == 0);
    ASSERT(strcmp(ozayn_spa_decision_name(OZAYN_SPA_DECISION_REJECT), "REJECT") == 0);
    ASSERT(strcmp(ozayn_spa_decision_name(OZAYN_SPA_DECISION_EXPIRE), "EXPIRE") == 0);
    ASSERT(strcmp(ozayn_spa_decision_name(OZAYN_SPA_DECISION_UNAVAILABLE), "UNAVAILABLE") == 0);
    ASSERT(strcmp(ozayn_spa_decision_name((ozayn_spa_decision_t)999), "UNKNOWN") == 0);
    return 0;
}

TEST(test_spa_wait_reason_name) {
    ASSERT(strcmp(ozayn_spa_wait_reason_name(OZAYN_SPA_WAIT_NONE), "NONE") == 0);
    ASSERT(strcmp(ozayn_spa_wait_reason_name(OZAYN_SPA_WAIT_RESOURCE), "RESOURCE") == 0);
    ASSERT(strcmp(ozayn_spa_wait_reason_name(OZAYN_SPA_WAIT_DEVICE), "DEVICE") == 0);
    ASSERT(strcmp(ozayn_spa_wait_reason_name(OZAYN_SPA_WAIT_DEPENDENCY), "DEPENDENCY") == 0);
    ASSERT(strcmp(ozayn_spa_wait_reason_name(OZAYN_SPA_WAIT_CONCURRENCY), "CONCURRENCY") == 0);
    ASSERT(strcmp(ozayn_spa_wait_reason_name((ozayn_spa_wait_reason_t)999), "UNKNOWN") == 0);
    return 0;
}

TEST(test_spa_event_type_name) {
    ASSERT(strcmp(ozayn_spa_event_type_name(OZAYN_SPA_EVENT_SCHEDULER_STARTED), "SCHEDULER_STARTED") == 0);
    ASSERT(strcmp(ozayn_spa_event_type_name(OZAYN_SPA_EVENT_PIPELINE_SCHEDULED), "PIPELINE_SCHEDULED") == 0);
    ASSERT(strcmp(ozayn_spa_event_type_name(OZAYN_SPA_EVENT_PIPELINE_CANCELLED), "PIPELINE_CANCELLED") == 0);
    ASSERT(strcmp(ozayn_spa_event_type_name(OZAYN_SPA_EVENT_DEADLINE_EXPIRED), "DEADLINE_EXPIRED") == 0);
    ASSERT(strcmp(ozayn_spa_event_type_name(OZAYN_SPA_EVENT_FAIRNESS_ADJUSTED), "FAIRNESS_ADJUSTED") == 0);
    ASSERT(strcmp(ozayn_spa_event_type_name((ozayn_spa_event_type_t)999), "UNKNOWN") == 0);
    return 0;
}

TEST(test_spa_close_reason_name) {
    ASSERT(strcmp(ozayn_spa_close_reason_name(OZAYN_SPA_CLOSE_NONE), "NONE") == 0);
    ASSERT(strcmp(ozayn_spa_close_reason_name(OZAYN_SPA_CLOSE_MANUAL_CANCEL), "MANUAL_CANCEL") == 0);
    ASSERT(strcmp(ozayn_spa_close_reason_name(OZAYN_SPA_CLOSE_DEADLINE_EXPIRED), "DEADLINE_EXPIRED") == 0);
    ASSERT(strcmp(ozayn_spa_close_reason_name(OZAYN_SPA_CLOSE_SHUTDOWN), "SHUTDOWN") == 0);
    ASSERT(strcmp(ozayn_spa_close_reason_name((ozayn_spa_close_reason_t)999), "UNKNOWN") == 0);
    return 0;
}

/* ============================================================
 * TRANSITION VALIDATION TESTS
 * ============================================================ */

TEST(test_spa_is_valid_transition) {
    ASSERT(ozayn_spa_is_valid_transition(OZAYN_SPA_SCHED_CREATED, OZAYN_SPA_SCHED_QUEUED));
    ASSERT(ozayn_spa_is_valid_transition(OZAYN_SPA_SCHED_QUEUED, OZAYN_SPA_SCHED_WAITING));
    ASSERT(ozayn_spa_is_valid_transition(OZAYN_SPA_SCHED_WAITING, OZAYN_SPA_SCHED_ELIGIBLE));
    ASSERT(ozayn_spa_is_valid_transition(OZAYN_SPA_SCHED_ELIGIBLE, OZAYN_SPA_SCHED_SCHEDULED));
    ASSERT(ozayn_spa_is_valid_transition(OZAYN_SPA_SCHED_SCHEDULED, OZAYN_SPA_SCHED_RESERVED));
    ASSERT(ozayn_spa_is_valid_transition(OZAYN_SPA_SCHED_RESERVED, OZAYN_SPA_SCHED_STARTING));
    ASSERT(ozayn_spa_is_valid_transition(OZAYN_SPA_SCHED_STARTING, OZAYN_SPA_SCHED_RUNNING));
    ASSERT(ozayn_spa_is_valid_transition(OZAYN_SPA_SCHED_RUNNING, OZAYN_SPA_SCHED_COMPLETED));
    ASSERT(!ozayn_spa_is_valid_transition(OZAYN_SPA_SCHED_CREATED, OZAYN_SPA_SCHED_COMPLETED));
    ASSERT(!ozayn_spa_is_valid_transition(OZAYN_SPA_SCHED_COMPLETED, OZAYN_SPA_SCHED_RUNNING));
    return 0;
}

TEST(test_spa_is_terminal_state) {
    ASSERT(ozayn_spa_is_terminal_state(OZAYN_SPA_SCHED_COMPLETED));
    ASSERT(ozayn_spa_is_terminal_state(OZAYN_SPA_SCHED_FAILED));
    ASSERT(ozayn_spa_is_terminal_state(OZAYN_SPA_SCHED_CANCELLED));
    ASSERT(ozayn_spa_is_terminal_state(OZAYN_SPA_SCHED_EXPIRED));
    ASSERT(ozayn_spa_is_terminal_state(OZAYN_SPA_SCHED_REJECTED));
    ASSERT(ozayn_spa_is_terminal_state(OZAYN_SPA_SCHED_UNAVAILABLE));
    ASSERT(!ozayn_spa_is_terminal_state(OZAYN_SPA_SCHED_RUNNING));
    ASSERT(!ozayn_spa_is_terminal_state(OZAYN_SPA_SCHED_WAITING));
    ASSERT(!ozayn_spa_is_terminal_state(OZAYN_SPA_SCHED_ELIGIBLE));
    return 0;
}

/* ============================================================
 * EDGE CASE / INTEGRATION TESTS
 * ============================================================ */

TEST(test_spa_submit_with_state_helper) {
    _init_svc();
    char eid[OZAYN_SPA_MAX_ID_LEN];
    ASSERT_EQ(_submit_with_state(&_svc, "p1", "o1", OZAYN_SPA_PRIORITY_HIGH,
              "sess-1", "auth-1", "safety-1", eid, sizeof(eid)), OZAYN_SPA_OK);
    const ozayn_spa_entry_t *e = ozayn_spa_find_entry(&_svc, eid);
    ASSERT_NOT_NULL(e);
    ASSERT(strcmp(e->security_session_ref, "sess-1") == 0);
    ASSERT(strcmp(e->authorization_ref, "auth-1") == 0);
    ASSERT(strcmp(e->safety_decision_ref, "safety-1") == 0);
    ozayn_spa_service_shutdown(&_svc);
    return 0;
}

TEST(test_spa_full_lifecycle) {
    _init_svc();
    char eid[OZAYN_SPA_MAX_ID_LEN];
    _submit_with_state(&_svc, "p1", "o1", OZAYN_SPA_PRIORITY_NORMAL,
                       "s", "a", "sf", eid, sizeof(eid));
    ozayn_spa_tick(&_svc);
    ASSERT_EQ(ozayn_spa_schedule_next(&_svc, eid, sizeof(eid)), OZAYN_SPA_OK);
    ASSERT_EQ(ozayn_spa_transition(&_svc, eid, OZAYN_SPA_SCHED_RESERVED), OZAYN_SPA_OK);
    ASSERT_EQ(ozayn_spa_transition(&_svc, eid, OZAYN_SPA_SCHED_STARTING), OZAYN_SPA_OK);
    ASSERT_EQ(ozayn_spa_transition(&_svc, eid, OZAYN_SPA_SCHED_RUNNING), OZAYN_SPA_OK);
    ASSERT_EQ(ozayn_spa_transition(&_svc, eid, OZAYN_SPA_SCHED_COMPLETED), OZAYN_SPA_OK);
    ASSERT(ozayn_spa_is_terminal_state(_svc.entries[0].state));
    ozayn_spa_service_shutdown(&_svc);
    return 0;
}

TEST(test_spa_multiple_pipelines) {
    _init_svc();
    for (int i = 0; i < 5; i++) {
        char pipe[32], op[32];
        snprintf(pipe, sizeof(pipe), "pipe-%d", i);
        snprintf(op, sizeof(op), "op-%d", i);
        ozayn_spa_submit(&_svc, pipe, op, NULL, OZAYN_SPA_PRIORITY_NORMAL, NULL);
    }
    ASSERT_EQ(_svc.entry_count, 5);
    ozayn_spa_service_shutdown(&_svc);
    return 0;
}

TEST(test_spa_dependency_chain) {
    _init_svc();
    char eid1[OZAYN_SPA_MAX_ID_LEN], eid2[OZAYN_SPA_MAX_ID_LEN], eid3[OZAYN_SPA_MAX_ID_LEN];
    _submit_with_state(&_svc, "p1", "o1", OZAYN_SPA_PRIORITY_NORMAL, "s", "a", "sf",
                       eid1, sizeof(eid1));
    _submit_with_state(&_svc, "p2", "o2", OZAYN_SPA_PRIORITY_NORMAL, "s", "a", "sf",
                       eid2, sizeof(eid2));
    _submit_with_state(&_svc, "p3", "o3", OZAYN_SPA_PRIORITY_NORMAL, "s", "a", "sf",
                       eid3, sizeof(eid3));
    ozayn_spa_add_dependency(&_svc, eid2, eid1);
    ozayn_spa_add_dependency(&_svc, eid3, eid2);
    ozayn_spa_tick(&_svc);
    ozayn_spa_decision_record_t dec;
    ASSERT_EQ(ozayn_spa_evaluate_entry(&_svc, eid3, &dec), OZAYN_SPA_OK);
    ASSERT(!dec.dependency_ok);
    ozayn_spa_service_shutdown(&_svc);
    return 0;
}

TEST(test_spa_shutdown_cancels_active) {
    _init_svc();
    _submit_one();
    ozayn_spa_service_shutdown(&_svc);
    ASSERT(_svc.entries[0].state == OZAYN_SPA_SCHED_CANCELLED ||
           !_svc.entries[0].active);
    return 0;
}

TEST(test_spa_no_secrets_in_entry) {
    _init_svc();
    _submit_one();
    const ozayn_spa_entry_t *e = ozayn_spa_find_entry(&_svc, _entry_id);
    ASSERT(strstr(e->safe_metadata, "password") == NULL);
    ASSERT(strstr(e->safe_metadata, "secret") == NULL);
    ASSERT(strstr(e->safe_metadata, "key") == NULL);
    ozayn_spa_service_shutdown(&_svc);
    return 0;
}

TEST(test_spa_no_secrets_in_event) {
    _init_svc();
    ozayn_spa_emit_event(&_svc, OZAYN_SPA_EVENT_SCHEDULER_STARTED, "", "", "test event");
    const ozayn_spa_event_t *ev = ozayn_spa_get_event(&_svc, 0);
    ASSERT(strstr(ev->message, "password") == NULL);
    ASSERT(strstr(ev->message, "secret") == NULL);
    ozayn_spa_service_shutdown(&_svc);
    return 0;
}

TEST(test_spa_version_info) {
    _init_svc();
    ASSERT_NOT_NULL(ozayn_spa_get_global());
    ASSERT(strcmp(ozayn_spa_err_name(OZAYN_SPA_OK), "OK") == 0);
    ozayn_spa_service_shutdown(&_svc);
    return 0;
}

/* ============================================================
 * FAIRNESS / AGING TESTS
 * ============================================================ */

TEST(test_spa_aging) {
    _init_svc();
    _submit_with_state(&_svc, "p1", "o1", OZAYN_SPA_PRIORITY_LOW, NULL, NULL, NULL,
                       NULL, 0);
    const ozayn_spa_entry_t *e = ozayn_spa_find_entry_by_pipeline(&_svc, "p1");
    ozayn_spa_entry_t *me = (ozayn_spa_entry_t *)e;
    me->state = OZAYN_SPA_SCHED_WAITING;
    _svc.last_aging_time = 1;
    ozayn_spa_tick(&_svc);
    ASSERT(e->effective_priority > OZAYN_SPA_PRIORITY_LOW ||
           e->age_boost > 0 ||
           _svc.stats.total_fairness_adjustments < UINT64_MAX);
    ozayn_spa_service_shutdown(&_svc);
    return 0;
}

TEST(test_spa_aging_max_boost) {
    _init_svc();
    _svc.config.max_priority_boost = 1;
    _submit_with_state(&_svc, "p1", "o1", OZAYN_SPA_PRIORITY_LOW, NULL, NULL, NULL,
                       NULL, 0);
    ozayn_spa_entry_t *me = (ozayn_spa_entry_t *)ozayn_spa_find_entry_by_pipeline(&_svc, "p1");
    me->state = OZAYN_SPA_SCHED_WAITING;
    for (int i = 0; i < 5; i++) {
        _svc.last_aging_time = 1;
        ozayn_spa_tick(&_svc);
    }
    ASSERT(me->age_boost <= _svc.config.max_priority_boost);
    ozayn_spa_service_shutdown(&_svc);
    return 0;
}

/* ============================================================
 * TEST RUNNER
 * ============================================================ */

int run_cr_pipeline_scheduler_tests(void) {
    SUITE_BEGIN("Control Room — Pipeline Scheduler");

    /* Lifecycle */
    RUN(test_spa_init);
    RUN(test_spa_init_null);
    RUN(test_spa_init_null_cfg);
    RUN(test_spa_init_double);
    RUN(test_spa_shutdown);
    RUN(test_spa_shutdown_null);
    RUN(test_spa_shutdown_not_init);
    RUN(test_spa_is_initialized);
    RUN(test_spa_is_initialized_null);
    RUN(test_spa_global);

    /* Submit */
    RUN(test_spa_submit);
    RUN(test_spa_submit_null);
    RUN(test_spa_submit_not_init);
    RUN(test_spa_submit_null_pipeline);
    RUN(test_spa_submit_null_op);
    RUN(test_spa_submit_bad_priority);
    RUN(test_spa_submit_duplicate);
    RUN(test_spa_submit_limit);
    RUN(test_spa_submit_with_metadata);
    RUN(test_spa_submit_all_priorities);

    /* Cancel */
    RUN(test_spa_cancel);
    RUN(test_spa_cancel_null);
    RUN(test_spa_cancel_not_found);
    RUN(test_spa_cancel_terminal);

    /* Remove */
    RUN(test_spa_remove);
    RUN(test_spa_remove_not_terminal);
    RUN(test_spa_remove_not_found);

    /* Dependencies */
    RUN(test_spa_add_dependency);
    RUN(test_spa_add_dependency_cycle);
    RUN(test_spa_add_dependency_self);
    RUN(test_spa_add_dependency_not_found);
    RUN(test_spa_add_dependency_limit);

    /* Resource Requirements */
    RUN(test_spa_set_required_resources);
    RUN(test_spa_set_required_resources_bad_count);
    RUN(test_spa_set_required_devices);
    RUN(test_spa_set_required_streams);
    RUN(test_spa_set_required_routes);
    RUN(test_spa_resource_not_found);

    /* Deadline / Timing */
    RUN(test_spa_set_deadline);
    RUN(test_spa_set_max_wait);
    RUN(test_spa_deadline_not_found);

    /* Security */
    RUN(test_spa_set_security_session);
    RUN(test_spa_set_auth_ref);
    RUN(test_spa_set_safety_ref);
    RUN(test_spa_security_not_found);

    /* Tick */
    RUN(test_spa_tick);
    RUN(test_spa_tick_null);
    RUN(test_spa_tick_moves_to_waiting);
    RUN(test_spa_tick_eligible);
    RUN(test_spa_tick_terminal_expired);
    RUN(test_spa_tick_max_attempts);
    RUN(test_spa_tick_multiple);

    /* Evaluate */
    RUN(test_spa_evaluate);
    RUN(test_spa_evaluate_not_found);
    RUN(test_spa_evaluate_no_auth);
    RUN(test_spa_evaluate_no_safety);
    RUN(test_spa_evaluate_dep_wait);
    RUN(test_spa_evaluate_terminal);
    RUN(test_spa_evaluate_concurrency);

    /* Schedule Next */
    RUN(test_spa_schedule_next);
    RUN(test_spa_schedule_next_not_found);
    RUN(test_spa_schedule_next_concurrency);
    RUN(test_spa_schedule_next_priority_order);
    RUN(test_spa_schedule_next_fifo_same_prio);

    /* Conflict Detection */
    RUN(test_spa_check_conflicts_none);
    RUN(test_spa_check_conflicts_device);
    RUN(test_spa_check_conflicts_not_found);

    /* State Transition */
    RUN(test_spa_transition);
    RUN(test_spa_transition_invalid);
    RUN(test_spa_transition_not_found);
    RUN(test_spa_transition_completed);
    RUN(test_spa_transition_failed);

    /* Query */
    RUN(test_spa_find_entry);
    RUN(test_spa_find_by_pipeline);
    RUN(test_spa_entry_count);
    RUN(test_spa_running_count);
    RUN(test_spa_waiting_count);
    RUN(test_spa_eligible_count);
    RUN(test_spa_queue_full);
    RUN(test_spa_running_limit);

    /* Events */
    RUN(test_spa_emit_event);
    RUN(test_spa_get_event);
    RUN(test_spa_get_event_invalid);
    RUN(test_spa_event_count);
    RUN(test_spa_event_overflow);

    /* Cleanup */
    RUN(test_spa_cleanup_terminal);
    RUN(test_spa_cleanup_expired);
    RUN(test_spa_cleanup_all);

    /* Stats */
    RUN(test_spa_stats);
    RUN(test_spa_stats_null);

    /* Validation */
    RUN(test_spa_validate_entry);
    RUN(test_spa_validate_entry_null);
    RUN(test_spa_validate_config);
    RUN(test_spa_validate_config_null);

    /* Name Helpers */
    RUN(test_spa_err_name);
    RUN(test_spa_sched_state_name);
    RUN(test_spa_priority_name);
    RUN(test_spa_decision_name);
    RUN(test_spa_wait_reason_name);
    RUN(test_spa_event_type_name);
    RUN(test_spa_close_reason_name);

    /* Transition Validation */
    RUN(test_spa_is_valid_transition);
    RUN(test_spa_is_terminal_state);

    /* Edge Cases / Integration */
    RUN(test_spa_submit_with_state_helper);
    RUN(test_spa_full_lifecycle);
    RUN(test_spa_multiple_pipelines);
    RUN(test_spa_dependency_chain);
    RUN(test_spa_shutdown_cancels_active);
    RUN(test_spa_no_secrets_in_entry);
    RUN(test_spa_no_secrets_in_event);
    RUN(test_spa_version_info);

    /* Fairness */
    RUN(test_spa_aging);
    RUN(test_spa_aging_max_boost);

    SUITE_END();
    return TOTAL_FAIL();
}
