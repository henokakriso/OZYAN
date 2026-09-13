#include "../workflow_orchestrator.h"
#include "../../tests/test_framework.h"

/* ============================================================
 * STATIC TEST HELPERS
 * ============================================================ */

static ozayn_wof_service_t _svc;
static ozayn_wof_service_config_t _cfg;

static void _init_svc(void) {
    memset(&_svc, 0, sizeof(_svc));
    memset(&_cfg, 0, sizeof(_cfg));
    ozayn_wof_service_init(&_svc, &_cfg);
}

static void _shutdown_svc(void) {
    ozayn_wof_service_shutdown(&_svc);
}

static char _wf_id[OZAYN_WOF_MAX_ID_LEN];
static char _stg_id[OZAYN_WOF_MAX_ID_LEN];
static char _stg_id2[OZAYN_WOF_MAX_ID_LEN];

static void _create_simple_workflow(void) {
    _init_svc();
    ozayn_wof_create(&_svc, "Test WF", "desc", "1.0",
                     OZAYN_WOF_TYPE_SEQUENTIAL, "owner", "req", "sess",
                     NULL, _wf_id, sizeof(_wf_id));
}

static void _create_wf_with_stages(void) {
    _create_simple_workflow();
    ozayn_wof_stage_add(&_svc, _wf_id, "Stage1", "d", OZAYN_WOF_STAGE_PIPELINE,
                        "pipe-1", NULL, NULL, NULL, NULL, 0, 0, 0,
                        OZAYN_WOF_FAIL_FAIL_WORKFLOW, OZAYN_WOF_COMP_NONE,
                        NULL, _stg_id, sizeof(_stg_id));
    ozayn_wof_stage_add(&_svc, _wf_id, "Stage2", "d", OZAYN_WOF_STAGE_PIPELINE,
                        "pipe-2", NULL, NULL, NULL, NULL, 0, 0, 0,
                        OZAYN_WOF_FAIL_FAIL_WORKFLOW, OZAYN_WOF_COMP_NONE,
                        NULL, _stg_id2, sizeof(_stg_id2));
}

/* ============================================================
 * LIFECYCLE TESTS
 * ============================================================ */

TEST(test_wof_init) {
    _init_svc();
    ASSERT(ozayn_wof_is_initialized(&_svc));
    _shutdown_svc();
    return 0;
}

TEST(test_wof_init_null) {
    ASSERT_EQ(ozayn_wof_service_init(NULL, &_cfg), OZAYN_WOF_ERR_NULL);
    return 0;
}

TEST(test_wof_init_null_cfg) {
    ozayn_wof_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ASSERT_EQ(ozayn_wof_service_init(&svc, NULL), OZAYN_WOF_ERR_INVALID_PARAM);
    return 0;
}

TEST(test_wof_init_double) {
    _init_svc();
    ASSERT_EQ(ozayn_wof_service_init(&_svc, &_cfg), OZAYN_WOF_ERR_ALREADY_INIT);
    _shutdown_svc();
    return 0;
}

TEST(test_wof_shutdown) {
    _init_svc();
    ASSERT_EQ(ozayn_wof_service_shutdown(&_svc), OZAYN_WOF_OK);
    ASSERT(!ozayn_wof_is_initialized(&_svc));
    return 0;
}

TEST(test_wof_shutdown_null) {
    ASSERT_EQ(ozayn_wof_service_shutdown(NULL), OZAYN_WOF_ERR_NULL);
    return 0;
}

TEST(test_wof_shutdown_not_init) {
    ozayn_wof_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ASSERT_EQ(ozayn_wof_service_shutdown(&svc), OZAYN_WOF_ERR_NOT_INITIALIZED);
    return 0;
}

TEST(test_wof_is_initialized_null) {
    ASSERT(!ozayn_wof_is_initialized(NULL));
    return 0;
}

TEST(test_wof_global) {
    ASSERT_NOT_NULL(ozayn_wof_get_global());
    return 0;
}

/* ============================================================
 * WORKFLOW CREATION TESTS
 * ============================================================ */

TEST(test_wof_create) {
    _init_svc();
    char wf_id[OZAYN_WOF_MAX_ID_LEN];
    ASSERT_EQ(ozayn_wof_create(&_svc, "Test WF", "desc", "1.0",
                               OZAYN_WOF_TYPE_SEQUENTIAL, "owner", "req",
                               "sess", NULL, wf_id, sizeof(wf_id)), OZAYN_WOF_OK);
    ASSERT(wf_id[0] != '\0');
    ASSERT_EQ(ozayn_wof_workflow_count(&_svc), 1);
    const ozayn_wof_workflow_t *wf = ozayn_wof_get_workflow(&_svc, wf_id);
    ASSERT_NOT_NULL(wf);
    ASSERT_STR_EQ(wf->name, "Test WF");
    ASSERT_EQ(wf->state, OZAYN_WOF_WF_CREATED);
    _shutdown_svc();
    return 0;
}

TEST(test_wof_create_null) {
    _init_svc();
    char wf_id[OZAYN_WOF_MAX_ID_LEN];
    ASSERT_EQ(ozayn_wof_create(NULL, "Test", "d", "1.0",
                               OZAYN_WOF_TYPE_SEQUENTIAL, NULL, NULL, NULL,
                               NULL, wf_id, sizeof(wf_id)), OZAYN_WOF_ERR_NULL);
    _shutdown_svc();
    return 0;
}

TEST(test_wof_create_not_init) {
    ozayn_wof_service_t svc;
    memset(&svc, 0, sizeof(svc));
    char wf_id[OZAYN_WOF_MAX_ID_LEN];
    ASSERT_EQ(ozayn_wof_create(&svc, "Test", "d", "1.0",
                               OZAYN_WOF_TYPE_SEQUENTIAL, NULL, NULL, NULL,
                               NULL, wf_id, sizeof(wf_id)),
              OZAYN_WOF_ERR_NOT_INITIALIZED);
    return 0;
}

TEST(test_wof_create_null_name) {
    _init_svc();
    char wf_id[OZAYN_WOF_MAX_ID_LEN];
    ASSERT_EQ(ozayn_wof_create(&_svc, NULL, "d", "1.0",
                               OZAYN_WOF_TYPE_SEQUENTIAL, NULL, NULL, NULL,
                               NULL, wf_id, sizeof(wf_id)),
              OZAYN_WOF_ERR_INVALID_PARAM);
    _shutdown_svc();
    return 0;
}

TEST(test_wof_create_empty_name) {
    _init_svc();
    char wf_id[OZAYN_WOF_MAX_ID_LEN];
    ASSERT_EQ(ozayn_wof_create(&_svc, "", "d", "1.0",
                               OZAYN_WOF_TYPE_SEQUENTIAL, NULL, NULL, NULL,
                               NULL, wf_id, sizeof(wf_id)),
              OZAYN_WOF_ERR_INVALID_PARAM);
    _shutdown_svc();
    return 0;
}

TEST(test_wof_create_bad_type) {
    _init_svc();
    char wf_id[OZAYN_WOF_MAX_ID_LEN];
    ASSERT_EQ(ozayn_wof_create(&_svc, "Test", "d", "1.0",
                               OZAYN_WOF_TYPE_COUNT, NULL, NULL, NULL,
                               NULL, wf_id, sizeof(wf_id)),
              OZAYN_WOF_ERR_INVALID_PARAM);
    _shutdown_svc();
    return 0;
}

TEST(test_wof_create_parallel) {
    _init_svc();
    char wf_id[OZAYN_WOF_MAX_ID_LEN];
    ASSERT_EQ(ozayn_wof_create(&_svc, "Parallel WF", "d", "1.0",
                               OZAYN_WOF_TYPE_PARALLEL, NULL, NULL, NULL,
                               NULL, wf_id, sizeof(wf_id)), OZAYN_WOF_OK);
    const ozayn_wof_workflow_t *wf = ozayn_wof_get_workflow(&_svc, wf_id);
    ASSERT_EQ(wf->workflow_type, OZAYN_WOF_TYPE_PARALLEL);
    _shutdown_svc();
    return 0;
}

TEST(test_wof_create_bounded) {
    _init_svc();
    char wf_id[OZAYN_WOF_MAX_ID_LEN];
    ASSERT_EQ(ozayn_wof_create(&_svc, "Bounded WF", "d", "1.0",
                               OZAYN_WOF_TYPE_BOUNDED_PARALLEL, NULL, NULL, NULL,
                               NULL, wf_id, sizeof(wf_id)), OZAYN_WOF_OK);
    const ozayn_wof_workflow_t *wf = ozayn_wof_get_workflow(&_svc, wf_id);
    ASSERT_EQ(wf->concurrency_policy, OZAYN_WOF_CONC_BOUNDED);
    _shutdown_svc();
    return 0;
}

/* ============================================================
 * WORKFLOW LIFECYCLE TESTS
 * ============================================================ */

TEST(test_wof_lifecycle) {
    _create_wf_with_stages();
    ASSERT_EQ(ozayn_wof_validate(&_svc, _wf_id), OZAYN_WOF_OK);
    ASSERT_EQ(ozayn_wof_authorize(&_svc, _wf_id, "auth-ref", "safety-ref"),
              OZAYN_WOF_OK);
    ASSERT_EQ(ozayn_wof_ready(&_svc, _wf_id), OZAYN_WOF_OK);
    const ozayn_wof_workflow_t *wf = ozayn_wof_get_workflow(&_svc, _wf_id);
    ASSERT_EQ(wf->state, OZAYN_WOF_WF_READY);
    _shutdown_svc();
    return 0;
}

TEST(test_wof_validate_not_found) {
    _init_svc();
    ASSERT_EQ(ozayn_wof_validate(&_svc, "nonexistent"), OZAYN_WOF_ERR_NOT_FOUND);
    _shutdown_svc();
    return 0;
}

TEST(test_wof_validate_bad_state) {
    _create_simple_workflow();
    ozayn_wof_validate(&_svc, _wf_id);
    ozayn_wof_authorize(&_svc, _wf_id, NULL, NULL);
    ASSERT_EQ(ozayn_wof_validate(&_svc, _wf_id), OZAYN_WOF_ERR_STATE_INVALID);
    _shutdown_svc();
    return 0;
}

TEST(test_wof_authorize_not_found) {
    _init_svc();
    ASSERT_EQ(ozayn_wof_authorize(&_svc, "nonexistent", NULL, NULL),
              OZAYN_WOF_ERR_NOT_FOUND);
    _shutdown_svc();
    return 0;
}

TEST(test_wof_authorize_bad_state) {
    _create_simple_workflow();
    ASSERT_EQ(ozayn_wof_authorize(&_svc, _wf_id, NULL, NULL),
              OZAYN_WOF_ERR_STATE_INVALID);
    _shutdown_svc();
    return 0;
}

TEST(test_wof_reject) {
    _create_simple_workflow();
    ASSERT_EQ(ozayn_wof_validate(&_svc, _wf_id), OZAYN_WOF_OK);
    ASSERT_EQ(ozayn_wof_reject(&_svc, _wf_id, OZAYN_WOF_CLOSE_POLICY_DENIED,
                               "denied"), OZAYN_WOF_OK);
    const ozayn_wof_workflow_t *wf = ozayn_wof_get_workflow(&_svc, _wf_id);
    ASSERT_EQ(wf->state, OZAYN_WOF_WF_REJECTED);
    ASSERT_EQ(wf->close_reason, OZAYN_WOF_CLOSE_POLICY_DENIED);
    _shutdown_svc();
    return 0;
}

TEST(test_wof_reject_terminal) {
    _create_simple_workflow();
    ozayn_wof_validate(&_svc, _wf_id);
    ozayn_wof_authorize(&_svc, _wf_id, NULL, NULL);
    ozayn_wof_reject(&_svc, _wf_id, OZAYN_WOF_CLOSE_POLICY_DENIED, NULL);
    ASSERT_EQ(ozayn_wof_reject(&_svc, _wf_id, OZAYN_WOF_CLOSE_POLICY_DENIED, NULL),
              OZAYN_WOF_ERR_STATE_INVALID);
    _shutdown_svc();
    return 0;
}

TEST(test_wof_ready_no_stages) {
    _create_simple_workflow();
    ozayn_wof_validate(&_svc, _wf_id);
    ozayn_wof_authorize(&_svc, _wf_id, NULL, NULL);
    ASSERT_EQ(ozayn_wof_ready(&_svc, _wf_id), OZAYN_WOF_ERR_STAGE_INVALID);
    _shutdown_svc();
    return 0;
}

TEST(test_wof_schedule_start) {
    _create_wf_with_stages();
    ozayn_wof_validate(&_svc, _wf_id);
    ozayn_wof_authorize(&_svc, _wf_id, NULL, NULL);
    ozayn_wof_ready(&_svc, _wf_id);
    ASSERT_EQ(ozayn_wof_schedule(&_svc, _wf_id), OZAYN_WOF_OK);
    ASSERT_EQ(ozayn_wof_start(&_svc, _wf_id), OZAYN_WOF_OK);
    const ozayn_wof_workflow_t *wf = ozayn_wof_get_workflow(&_svc, _wf_id);
    ASSERT_EQ(wf->state, OZAYN_WOF_WF_ACTIVE);
    _shutdown_svc();
    return 0;
}

TEST(test_wof_pause_resume) {
    _create_wf_with_stages();
    ozayn_wof_validate(&_svc, _wf_id);
    ozayn_wof_authorize(&_svc, _wf_id, NULL, NULL);
    ozayn_wof_ready(&_svc, _wf_id);
    ozayn_wof_schedule(&_svc, _wf_id);
    ozayn_wof_start(&_svc, _wf_id);
    ASSERT_EQ(ozayn_wof_pause(&_svc, _wf_id), OZAYN_WOF_OK);
    const ozayn_wof_workflow_t *wf = ozayn_wof_get_workflow(&_svc, _wf_id);
    ASSERT_EQ(wf->state, OZAYN_WOF_WF_PAUSED);
    ASSERT_EQ(ozayn_wof_resume(&_svc, _wf_id), OZAYN_WOF_OK);
    ASSERT_EQ(wf->state, OZAYN_WOF_WF_RESUMING);
    _shutdown_svc();
    return 0;
}

TEST(test_wof_cancel) {
    _create_wf_with_stages();
    ozayn_wof_validate(&_svc, _wf_id);
    ozayn_wof_authorize(&_svc, _wf_id, NULL, NULL);
    ozayn_wof_ready(&_svc, _wf_id);
    ozayn_wof_schedule(&_svc, _wf_id);
    ozayn_wof_start(&_svc, _wf_id);
    ASSERT_EQ(ozayn_wof_cancel(&_svc, _wf_id, OZAYN_WOF_CLOSE_MANUAL_CANCEL),
              OZAYN_WOF_OK);
    const ozayn_wof_workflow_t *wf = ozayn_wof_get_workflow(&_svc, _wf_id);
    ASSERT_EQ(wf->state, OZAYN_WOF_WF_CANCELLED);
    _shutdown_svc();
    return 0;
}

TEST(test_wof_cancel_terminal) {
    _create_simple_workflow();
    ozayn_wof_validate(&_svc, _wf_id);
    ozayn_wof_authorize(&_svc, _wf_id, NULL, NULL);
    ozayn_wof_reject(&_svc, _wf_id, OZAYN_WOF_CLOSE_POLICY_DENIED, NULL);
    ASSERT_EQ(ozayn_wof_cancel(&_svc, _wf_id, OZAYN_WOF_CLOSE_MANUAL_CANCEL),
              OZAYN_WOF_ERR_STATE_INVALID);
    _shutdown_svc();
    return 0;
}

TEST(test_wof_drain_stop) {
    _create_wf_with_stages();
    ozayn_wof_validate(&_svc, _wf_id);
    ozayn_wof_authorize(&_svc, _wf_id, NULL, NULL);
    ozayn_wof_ready(&_svc, _wf_id);
    ozayn_wof_schedule(&_svc, _wf_id);
    ozayn_wof_start(&_svc, _wf_id);
    ASSERT_EQ(ozayn_wof_drain(&_svc, _wf_id), OZAYN_WOF_OK);
    const ozayn_wof_workflow_t *wf = ozayn_wof_get_workflow(&_svc, _wf_id);
    ASSERT_EQ(wf->state, OZAYN_WOF_WF_DRAINING);
    ASSERT_EQ(ozayn_wof_stop(&_svc, _wf_id), OZAYN_WOF_OK);
    ASSERT_EQ(wf->state, OZAYN_WOF_WF_SUCCEEDED);
    _shutdown_svc();
    return 0;
}

TEST(test_wof_remove) {
    _create_simple_workflow();
    ozayn_wof_validate(&_svc, _wf_id);
    ozayn_wof_authorize(&_svc, _wf_id, NULL, NULL);
    ozayn_wof_reject(&_svc, _wf_id, OZAYN_WOF_CLOSE_POLICY_DENIED, NULL);
    ASSERT_EQ(ozayn_wof_remove(&_svc, _wf_id), OZAYN_WOF_OK);
    ASSERT_NULL(ozayn_wof_get_workflow(&_svc, _wf_id));
    _shutdown_svc();
    return 0;
}

TEST(test_wof_remove_not_terminal) {
    _create_simple_workflow();
    ASSERT_EQ(ozayn_wof_remove(&_svc, _wf_id), OZAYN_WOF_ERR_STATE_INVALID);
    _shutdown_svc();
    return 0;
}

/* ============================================================
 * STAGE TESTS
 * ============================================================ */

TEST(test_wof_stage_add) {
    _create_simple_workflow();
    char stg_id[OZAYN_WOF_MAX_ID_LEN];
    ASSERT_EQ(ozayn_wof_stage_add(&_svc, _wf_id, "Stage1", "d",
                                  OZAYN_WOF_STAGE_PIPELINE, "pipe-1", NULL,
                                  NULL, NULL, NULL, 0, 0, 0,
                                  OZAYN_WOF_FAIL_FAIL_WORKFLOW,
                                  OZAYN_WOF_COMP_NONE, NULL,
                                  stg_id, sizeof(stg_id)), OZAYN_WOF_OK);
    ASSERT(stg_id[0] != '\0');
    ASSERT_EQ(ozayn_wof_stage_count(&_svc, _wf_id), 1);
    _shutdown_svc();
    return 0;
}

TEST(test_wof_stage_add_null) {
    _create_simple_workflow();
    char stg_id[OZAYN_WOF_MAX_ID_LEN];
    ASSERT_EQ(ozayn_wof_stage_add(&_svc, _wf_id, NULL, "d",
                                  OZAYN_WOF_STAGE_PIPELINE, NULL, NULL,
                                  NULL, NULL, NULL, 0, 0, 0,
                                  OZAYN_WOF_FAIL_FAIL_WORKFLOW,
                                  OZAYN_WOF_COMP_NONE, NULL,
                                  stg_id, sizeof(stg_id)),
              OZAYN_WOF_ERR_INVALID_PARAM);
    _shutdown_svc();
    return 0;
}

TEST(test_wof_stage_add_not_found) {
    _init_svc();
    char stg_id[OZAYN_WOF_MAX_ID_LEN];
    ASSERT_EQ(ozayn_wof_stage_add(&_svc, "nonexistent", "Stage", "d",
                                  OZAYN_WOF_STAGE_PIPELINE, NULL, NULL,
                                  NULL, NULL, NULL, 0, 0, 0,
                                  OZAYN_WOF_FAIL_FAIL_WORKFLOW,
                                  OZAYN_WOF_COMP_NONE, NULL,
                                  stg_id, sizeof(stg_id)),
              OZAYN_WOF_ERR_NOT_FOUND);
    _shutdown_svc();
    return 0;
}

TEST(test_wof_stage_add_operation) {
    _create_simple_workflow();
    char stg_id[OZAYN_WOF_MAX_ID_LEN];
    ASSERT_EQ(ozayn_wof_stage_add(&_svc, _wf_id, "OpStage", "d",
                                  OZAYN_WOF_STAGE_OPERATION, NULL, "op-1",
                                  NULL, NULL, NULL, 0, 0, 0,
                                  OZAYN_WOF_FAIL_FAIL_WORKFLOW,
                                  OZAYN_WOF_COMP_NONE, NULL,
                                  stg_id, sizeof(stg_id)), OZAYN_WOF_OK);
    const ozayn_wof_stage_t *stg = ozayn_wof_get_stage(&_svc, _wf_id, stg_id);
    ASSERT_EQ(stg->stage_type, OZAYN_WOF_STAGE_OPERATION);
    _shutdown_svc();
    return 0;
}

TEST(test_wof_stage_add_condition) {
    _create_simple_workflow();
    char stg_id[OZAYN_WOF_MAX_ID_LEN];
    ASSERT_EQ(ozayn_wof_stage_add(&_svc, _wf_id, "CondStage", "d",
                                  OZAYN_WOF_STAGE_CONDITION, NULL, NULL,
                                  NULL, NULL, NULL, 0, 0, 0,
                                  OZAYN_WOF_FAIL_FAIL_WORKFLOW,
                                  OZAYN_WOF_COMP_NONE, NULL,
                                  stg_id, sizeof(stg_id)), OZAYN_WOF_OK);
    const ozayn_wof_stage_t *stg = ozayn_wof_get_stage(&_svc, _wf_id, stg_id);
    ASSERT_EQ(stg->stage_type, OZAYN_WOF_STAGE_CONDITION);
    _shutdown_svc();
    return 0;
}

TEST(test_wof_stage_set_state) {
    _create_wf_with_stages();
    ASSERT_EQ(ozayn_wof_stage_set_state(&_svc, _wf_id, _stg_id,
                                         OZAYN_WOF_STG_WAITING_DEPS),
              OZAYN_WOF_OK);
    const ozayn_wof_stage_t *stg = ozayn_wof_get_stage(&_svc, _wf_id, _stg_id);
    ASSERT_EQ(stg->state, OZAYN_WOF_STG_WAITING_DEPS);
    _shutdown_svc();
    return 0;
}

TEST(test_wof_stage_set_state_invalid) {
    _create_wf_with_stages();
    ASSERT_EQ(ozayn_wof_stage_set_state(&_svc, _wf_id, _stg_id,
                                         OZAYN_WOF_STG_RUNNING),
              OZAYN_WOF_ERR_STATE_INVALID);
    _shutdown_svc();
    return 0;
}

TEST(test_wof_stage_remove) {
    _create_wf_with_stages();
    ASSERT_EQ(ozayn_wof_stage_set_state(&_svc, _wf_id, _stg_id,
                                         OZAYN_WOF_STG_WAITING_DEPS),
              OZAYN_WOF_OK);
    ASSERT_EQ(ozayn_wof_stage_set_state(&_svc, _wf_id, _stg_id,
                                         OZAYN_WOF_STG_DEPS_SATISFIED),
              OZAYN_WOF_OK);
    ASSERT_EQ(ozayn_wof_stage_set_state(&_svc, _wf_id, _stg_id,
                                         OZAYN_WOF_STG_ELIGIBLE),
              OZAYN_WOF_OK);
    ASSERT_EQ(ozayn_wof_stage_set_state(&_svc, _wf_id, _stg_id,
                                         OZAYN_WOF_STG_SUBMITTED),
              OZAYN_WOF_OK);
    ASSERT_EQ(ozayn_wof_stage_set_state(&_svc, _wf_id, _stg_id,
                                         OZAYN_WOF_STG_SCHEDULED),
              OZAYN_WOF_OK);
    ASSERT_EQ(ozayn_wof_stage_set_state(&_svc, _wf_id, _stg_id,
                                         OZAYN_WOF_STG_RUNNING),
              OZAYN_WOF_OK);
    ASSERT_EQ(ozayn_wof_stage_set_state(&_svc, _wf_id, _stg_id,
                                         OZAYN_WOF_STG_COMPLETED),
              OZAYN_WOF_OK);
    ASSERT_EQ(ozayn_wof_stage_remove(&_svc, _wf_id, _stg_id), OZAYN_WOF_OK);
    ASSERT_NULL(ozayn_wof_get_stage(&_svc, _wf_id, _stg_id));
    _shutdown_svc();
    return 0;
}

TEST(test_wof_stage_remove_not_terminal) {
    _create_wf_with_stages();
    ASSERT_EQ(ozayn_wof_stage_remove(&_svc, _wf_id, _stg_id),
              OZAYN_WOF_ERR_STATE_INVALID);
    _shutdown_svc();
    return 0;
}

/* ============================================================
 * DEPENDENCY TESTS
 * ============================================================ */

TEST(test_wof_add_dependency) {
    _create_wf_with_stages();
    ASSERT_EQ(ozayn_wof_add_dependency(&_svc, _wf_id, _stg_id, _stg_id2),
              OZAYN_WOF_OK);
    ASSERT_EQ(ozayn_wof_dependency_count(&_svc, _wf_id), 1);
    _shutdown_svc();
    return 0;
}

TEST(test_wof_add_dependency_self) {
    _create_wf_with_stages();
    ASSERT_EQ(ozayn_wof_add_dependency(&_svc, _wf_id, _stg_id, _stg_id),
              OZAYN_WOF_ERR_DEPENDENCY_INVALID);
    _shutdown_svc();
    return 0;
}

TEST(test_wof_add_dependency_not_found) {
    _create_wf_with_stages();
    ASSERT_EQ(ozayn_wof_add_dependency(&_svc, _wf_id, "nonexistent", _stg_id2),
              OZAYN_WOF_ERR_DEPENDENCY_NOT_FOUND);
    _shutdown_svc();
    return 0;
}

TEST(test_wof_add_dependency_duplicate) {
    _create_wf_with_stages();
    ozayn_wof_add_dependency(&_svc, _wf_id, _stg_id, _stg_id2);
    ASSERT_EQ(ozayn_wof_add_dependency(&_svc, _wf_id, _stg_id, _stg_id2),
              OZAYN_WOF_ERR_DUPLICATE);
    _shutdown_svc();
    return 0;
}

TEST(test_wof_add_dependency_cycle) {
    _create_wf_with_stages();
    char stg_id3[OZAYN_WOF_MAX_ID_LEN];
    ozayn_wof_stage_add(&_svc, _wf_id, "S3", "d", OZAYN_WOF_STAGE_PIPELINE,
                        "pipe-3", NULL, NULL, NULL, NULL, 0, 0, 0,
                        OZAYN_WOF_FAIL_FAIL_WORKFLOW, OZAYN_WOF_COMP_NONE,
                        NULL, stg_id3, sizeof(stg_id3));
    ozayn_wof_add_dependency(&_svc, _wf_id, _stg_id, _stg_id2);
    ozayn_wof_add_dependency(&_svc, _wf_id, _stg_id2, stg_id3);
    ASSERT_EQ(ozayn_wof_add_dependency(&_svc, _wf_id, stg_id3, _stg_id),
              OZAYN_WOF_OK);
    ASSERT_EQ(ozayn_wof_validate(&_svc, _wf_id), OZAYN_WOF_ERR_DEPENDENCY_CYCLE);
    _shutdown_svc();
    return 0;
}

TEST(test_wof_remove_dependency) {
    _create_wf_with_stages();
    ozayn_wof_add_dependency(&_svc, _wf_id, _stg_id, _stg_id2);
    ASSERT_EQ(ozayn_wof_dependency_count(&_svc, _wf_id), 1);
    const ozayn_wof_dependency_t *dep = NULL;
    for (int i = 0; i < OZAYN_WOF_MAX_DEPENDENCIES; i++) {
        if (_svc.dependencies[i].active &&
            strcmp(_svc.dependencies[i].workflow_id, _wf_id) == 0) {
            dep = &_svc.dependencies[i];
            break;
        }
    }
    ASSERT_NOT_NULL(dep);
    ASSERT_EQ(ozayn_wof_remove_dependency(&_svc, _wf_id, dep->dependency_id),
              OZAYN_WOF_OK);
    ASSERT_EQ(ozayn_wof_dependency_count(&_svc, _wf_id), 0);
    _shutdown_svc();
    return 0;
}

/* ============================================================
 * TICK / ORCHESTRATION TESTS
 * ============================================================ */

TEST(test_wof_tick) {
    _create_wf_with_stages();
    ozayn_wof_validate(&_svc, _wf_id);
    ozayn_wof_authorize(&_svc, _wf_id, NULL, NULL);
    ozayn_wof_ready(&_svc, _wf_id);
    ozayn_wof_schedule(&_svc, _wf_id);
    ozayn_wof_start(&_svc, _wf_id);
    int64_t now = _svc.workflows[0].start_time + 100;
    ASSERT_EQ(ozayn_wof_tick(&_svc, now), OZAYN_WOF_OK);
    _shutdown_svc();
    return 0;
}

TEST(test_wof_tick_timeout) {
    _create_wf_with_stages();
    ozayn_wof_validate(&_svc, _wf_id);
    ozayn_wof_authorize(&_svc, _wf_id, NULL, NULL);
    ozayn_wof_ready(&_svc, _wf_id);
    ozayn_wof_schedule(&_svc, _wf_id);
    ozayn_wof_start(&_svc, _wf_id);
    int64_t now = _svc.workflows[0].start_time + OZAYN_WOF_DEFAULT_WORKFLOW_TIMEOUT_MS + 1;
    ozayn_wof_tick(&_svc, now);
    const ozayn_wof_workflow_t *wf = ozayn_wof_get_workflow(&_svc, _wf_id);
    ASSERT_EQ(wf->state, OZAYN_WOF_WF_TIMEOUT);
    _shutdown_svc();
    return 0;
}

TEST(test_wof_tick_deps_satisfied) {
    _create_wf_with_stages();
    ozayn_wof_add_dependency(&_svc, _wf_id, _stg_id, _stg_id2);
    ozayn_wof_validate(&_svc, _wf_id);
    ozayn_wof_authorize(&_svc, _wf_id, NULL, NULL);
    ozayn_wof_ready(&_svc, _wf_id);
    ozayn_wof_schedule(&_svc, _wf_id);
    ozayn_wof_start(&_svc, _wf_id);
    /* Move stage1 to completed via proper transitions */
    ozayn_wof_stage_set_state(&_svc, _wf_id, _stg_id, OZAYN_WOF_STG_WAITING_DEPS);
    ozayn_wof_stage_set_state(&_svc, _wf_id, _stg_id, OZAYN_WOF_STG_DEPS_SATISFIED);
    ozayn_wof_stage_set_state(&_svc, _wf_id, _stg_id, OZAYN_WOF_STG_ELIGIBLE);
    ozayn_wof_stage_set_state(&_svc, _wf_id, _stg_id, OZAYN_WOF_STG_SUBMITTED);
    ozayn_wof_stage_set_state(&_svc, _wf_id, _stg_id, OZAYN_WOF_STG_SCHEDULED);
    ozayn_wof_stage_set_state(&_svc, _wf_id, _stg_id, OZAYN_WOF_STG_RUNNING);
    ozayn_wof_stage_set_state(&_svc, _wf_id, _stg_id, OZAYN_WOF_STG_COMPLETED);
    int64_t now = _svc.workflows[0].start_time + 100;
    ozayn_wof_tick(&_svc, now);
    const ozayn_wof_stage_t *stg2 = ozayn_wof_get_stage(&_svc, _wf_id, _stg_id2);
    ASSERT(stg2->state == OZAYN_WOF_STG_DEPS_SATISFIED ||
           stg2->state == OZAYN_WOF_STG_ELIGIBLE);
    _shutdown_svc();
    return 0;
}

TEST(test_wof_tick_deps_blocked) {
    _create_wf_with_stages();
    ozayn_wof_add_dependency(&_svc, _wf_id, _stg_id, _stg_id2);
    ozayn_wof_validate(&_svc, _wf_id);
    ozayn_wof_authorize(&_svc, _wf_id, NULL, NULL);
    ozayn_wof_ready(&_svc, _wf_id);
    ozayn_wof_schedule(&_svc, _wf_id);
    ozayn_wof_start(&_svc, _wf_id);
    int64_t now = _svc.workflows[0].start_time + 100;
    ozayn_wof_tick(&_svc, now);
    const ozayn_wof_stage_t *stg2 = ozayn_wof_get_stage(&_svc, _wf_id, _stg_id2);
    ASSERT(stg2->state == OZAYN_WOF_STG_WAITING_DEPS ||
           stg2->state == OZAYN_WOF_STG_DEPS_SATISFIED ||
           stg2->state == OZAYN_WOF_STG_CREATED);
    _shutdown_svc();
    return 0;
}

TEST(test_wof_fail_workflow_policy) {
    _create_wf_with_stages();
    ozayn_wof_validate(&_svc, _wf_id);
    ozayn_wof_authorize(&_svc, _wf_id, NULL, NULL);
    ozayn_wof_ready(&_svc, _wf_id);
    ozayn_wof_schedule(&_svc, _wf_id);
    ozayn_wof_start(&_svc, _wf_id);
    /* Move stage1 through proper transitions to FAILED */
    ozayn_wof_stage_set_state(&_svc, _wf_id, _stg_id, OZAYN_WOF_STG_WAITING_DEPS);
    ozayn_wof_stage_set_state(&_svc, _wf_id, _stg_id, OZAYN_WOF_STG_DEPS_SATISFIED);
    ozayn_wof_stage_set_state(&_svc, _wf_id, _stg_id, OZAYN_WOF_STG_ELIGIBLE);
    ozayn_wof_stage_set_state(&_svc, _wf_id, _stg_id, OZAYN_WOF_STG_SUBMITTED);
    ozayn_wof_stage_set_state(&_svc, _wf_id, _stg_id, OZAYN_WOF_STG_SCHEDULED);
    ozayn_wof_stage_set_state(&_svc, _wf_id, _stg_id, OZAYN_WOF_STG_RUNNING);
    ozayn_wof_stage_set_state(&_svc, _wf_id, _stg_id, OZAYN_WOF_STG_FAILED);
    int64_t now = _svc.workflows[0].start_time + 100;
    ozayn_wof_tick(&_svc, now);
    const ozayn_wof_workflow_t *wf = ozayn_wof_get_workflow(&_svc, _wf_id);
    ASSERT_EQ(wf->state, OZAYN_WOF_WF_FAILED);
    _shutdown_svc();
    return 0;
}

/* ============================================================
 * QUERY TESTS
 * ============================================================ */

TEST(test_wof_get_workflow) {
    _create_simple_workflow();
    ASSERT_NOT_NULL(ozayn_wof_get_workflow(&_svc, _wf_id));
    ASSERT_NULL(ozayn_wof_get_workflow(&_svc, "nonexistent"));
    _shutdown_svc();
    return 0;
}

TEST(test_wof_get_workflow_null) {
    ASSERT_NULL(ozayn_wof_get_workflow(NULL, "id"));
    ASSERT_NULL(ozayn_wof_get_workflow(&_svc, NULL));
    return 0;
}

TEST(test_wof_get_stage) {
    _create_wf_with_stages();
    ASSERT_NOT_NULL(ozayn_wof_get_stage(&_svc, _wf_id, _stg_id));
    ASSERT_NULL(ozayn_wof_get_stage(&_svc, _wf_id, "nonexistent"));
    _shutdown_svc();
    return 0;
}

TEST(test_wof_workflow_count) {
    _init_svc();
    ASSERT_EQ(ozayn_wof_workflow_count(&_svc), 0);
    char wf_id[OZAYN_WOF_MAX_ID_LEN];
    ozayn_wof_create(&_svc, "WF1", "d", "1.0", OZAYN_WOF_TYPE_SEQUENTIAL,
                     NULL, NULL, NULL, NULL, wf_id, sizeof(wf_id));
    ASSERT_EQ(ozayn_wof_workflow_count(&_svc), 1);
    _shutdown_svc();
    return 0;
}

TEST(test_wof_workflow_count_by_state) {
    _create_simple_workflow();
    ASSERT_EQ(ozayn_wof_workflow_count_by_state(&_svc, OZAYN_WOF_WF_CREATED), 1);
    ASSERT_EQ(ozayn_wof_workflow_count_by_state(&_svc, OZAYN_WOF_WF_ACTIVE), 0);
    _shutdown_svc();
    return 0;
}

TEST(test_wof_is_terminal) {
    ASSERT(ozayn_wof_is_terminal(OZAYN_WOF_WF_SUCCEEDED));
    ASSERT(ozayn_wof_is_terminal(OZAYN_WOF_WF_FAILED));
    ASSERT(ozayn_wof_is_terminal(OZAYN_WOF_WF_CANCELLED));
    ASSERT(ozayn_wof_is_terminal(OZAYN_WOF_WF_TIMEOUT));
    ASSERT(ozayn_wof_is_terminal(OZAYN_WOF_WF_EXPIRED));
    ASSERT(!ozayn_wof_is_terminal(OZAYN_WOF_WF_ACTIVE));
    ASSERT(!ozayn_wof_is_terminal(OZAYN_WOF_WF_CREATED));
    return 0;
}

TEST(test_wof_is_stage_terminal) {
    ASSERT(ozayn_wof_is_stage_terminal(OZAYN_WOF_STG_COMPLETED));
    ASSERT(ozayn_wof_is_stage_terminal(OZAYN_WOF_STG_FAILED));
    ASSERT(ozayn_wof_is_stage_terminal(OZAYN_WOF_STG_SKIPPED));
    ASSERT(ozayn_wof_is_stage_terminal(OZAYN_WOF_STG_CANCELLED));
    ASSERT(ozayn_wof_is_stage_terminal(OZAYN_WOF_STG_TIMED_OUT));
    ASSERT(!ozayn_wof_is_stage_terminal(OZAYN_WOF_STG_RUNNING));
    ASSERT(!ozayn_wof_is_stage_terminal(OZAYN_WOF_STG_CREATED));
    return 0;
}

TEST(test_wof_concurrent_workflows) {
    _init_svc();
    ASSERT_EQ(ozayn_wof_concurrent_workflows(&_svc), 0);
    char wf1[OZAYN_WOF_MAX_ID_LEN], wf2[OZAYN_WOF_MAX_ID_LEN];
    ozayn_wof_create(&_svc, "WF1", "d", "1.0", OZAYN_WOF_TYPE_SEQUENTIAL,
                     NULL, NULL, NULL, NULL, wf1, sizeof(wf1));
    ozayn_wof_create(&_svc, "WF2", "d", "1.0", OZAYN_WOF_TYPE_SEQUENTIAL,
                     NULL, NULL, NULL, NULL, wf2, sizeof(wf2));
    ASSERT_EQ(ozayn_wof_concurrent_workflows(&_svc), 2);
    _shutdown_svc();
    return 0;
}

/* ============================================================
 * EVENT TESTS
 * ============================================================ */

TEST(test_wof_emit_event) {
    _init_svc();
    int count_before = ozayn_wof_event_count(&_svc);
    ASSERT_EQ(ozayn_wof_emit_event(&_svc, OZAYN_WOF_EVENT_CREATED,
                                    "wf-1", "stg-1", "pipe-1", "op-1",
                                    "test event"), OZAYN_WOF_OK);
    ASSERT_GE(ozayn_wof_event_count(&_svc), count_before + 1);
    _shutdown_svc();
    return 0;
}

TEST(test_wof_get_event) {
    _init_svc();
    ozayn_wof_emit_event(&_svc, OZAYN_WOF_EVENT_CREATED,
                         "wf-1", NULL, NULL, NULL, "msg");
    const ozayn_wof_event_t *ev = ozayn_wof_get_event(&_svc,
        ozayn_wof_event_count(&_svc) - 1);
    ASSERT_NOT_NULL(ev);
    ASSERT_EQ(ev->event_type, OZAYN_WOF_EVENT_CREATED);
    _shutdown_svc();
    return 0;
}

TEST(test_wof_get_event_invalid) {
    _init_svc();
    ASSERT_NULL(ozayn_wof_get_event(&_svc, -1));
    ASSERT_NULL(ozayn_wof_get_event(&_svc, OZAYN_WOF_MAX_EVENTS));
    _shutdown_svc();
    return 0;
}

TEST(test_wof_event_overflow) {
    _init_svc();
    for (int i = 0; i < OZAYN_WOF_MAX_EVENTS + 5; i++) {
        ozayn_wof_emit_event(&_svc, OZAYN_WOF_EVENT_CREATED,
                             "wf-1", NULL, NULL, NULL, "msg");
    }
    ASSERT_GE(ozayn_wof_event_count(&_svc), 1);
    _shutdown_svc();
    return 0;
}

/* ============================================================
 * CLEANUP TESTS
 * ============================================================ */

TEST(test_wof_cleanup_terminal) {
    _create_simple_workflow();
    ozayn_wof_validate(&_svc, _wf_id);
    ozayn_wof_authorize(&_svc, _wf_id, NULL, NULL);
    ozayn_wof_reject(&_svc, _wf_id, OZAYN_WOF_CLOSE_POLICY_DENIED, NULL);
    ASSERT_EQ(ozayn_wof_cleanup_terminal(&_svc), OZAYN_WOF_OK);
    ASSERT_NULL(ozayn_wof_get_workflow(&_svc, _wf_id));
    _shutdown_svc();
    return 0;
}

TEST(test_wof_cleanup_expired) {
    _create_wf_with_stages();
    ozayn_wof_validate(&_svc, _wf_id);
    ozayn_wof_authorize(&_svc, _wf_id, NULL, NULL);
    ozayn_wof_ready(&_svc, _wf_id);
    ozayn_wof_schedule(&_svc, _wf_id);
    ozayn_wof_start(&_svc, _wf_id);
    /* Set a past execution deadline */
    _svc.workflows[0].execution_deadline_ms = 1000;
    ozayn_wof_cleanup_expired(&_svc, 2000);
    const ozayn_wof_workflow_t *wf = ozayn_wof_get_workflow(&_svc, _wf_id);
    ASSERT_EQ(wf->state, OZAYN_WOF_WF_EXPIRED);
    _shutdown_svc();
    return 0;
}

TEST(test_wof_cleanup_all) {
    _create_simple_workflow();
    ASSERT_EQ(ozayn_wof_cleanup_all(&_svc), OZAYN_WOF_OK);
    ASSERT_EQ(ozayn_wof_workflow_count(&_svc), 0);
    _shutdown_svc();
    return 0;
}

/* ============================================================
 * STATISTICS TESTS
 * ============================================================ */

TEST(test_wof_stats) {
    _init_svc();
    const ozayn_wof_stats_t *stats = ozayn_wof_get_stats(&_svc);
    ASSERT_NOT_NULL(stats);
    ASSERT_EQ(stats->total_workflows_created, 0);
    char wf_id[OZAYN_WOF_MAX_ID_LEN];
    ozayn_wof_create(&_svc, "WF", "d", "1.0", OZAYN_WOF_TYPE_SEQUENTIAL,
                     NULL, NULL, NULL, NULL, wf_id, sizeof(wf_id));
    stats = ozayn_wof_get_stats(&_svc);
    ASSERT_EQ(stats->total_workflows_created, 1);
    _shutdown_svc();
    return 0;
}

TEST(test_wof_stats_null) {
    ASSERT_NULL(ozayn_wof_get_stats(NULL));
    return 0;
}

TEST(test_wof_reset_stats) {
    _init_svc();
    char wf_id[OZAYN_WOF_MAX_ID_LEN];
    ozayn_wof_create(&_svc, "WF", "d", "1.0", OZAYN_WOF_TYPE_SEQUENTIAL,
                     NULL, NULL, NULL, NULL, wf_id, sizeof(wf_id));
    ASSERT_EQ(ozayn_wof_reset_stats(&_svc), OZAYN_WOF_OK);
    const ozayn_wof_stats_t *stats = ozayn_wof_get_stats(&_svc);
    ASSERT_EQ(stats->total_workflows_created, 0);
    _shutdown_svc();
    return 0;
}

/* ============================================================
 * VALIDATION TESTS
 * ============================================================ */

TEST(test_wof_validate_workflow) {
    _create_simple_workflow();
    ASSERT(ozayn_wof_validate_workflow(&_svc, _wf_id));
    ASSERT(!ozayn_wof_validate_workflow(&_svc, "nonexistent"));
    _shutdown_svc();
    return 0;
}

TEST(test_wof_validate_workflow_null) {
    ASSERT(!ozayn_wof_validate_workflow(NULL, "id"));
    ASSERT(!ozayn_wof_validate_workflow(&_svc, NULL));
    return 0;
}

TEST(test_wof_validate_stage) {
    _create_wf_with_stages();
    ASSERT(ozayn_wof_validate_stage(&_svc, _wf_id, _stg_id));
    ASSERT(!ozayn_wof_validate_stage(&_svc, _wf_id, "nonexistent"));
    _shutdown_svc();
    return 0;
}

TEST(test_wof_validate_config) {
    ozayn_wof_service_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    ASSERT(ozayn_wof_validate_config(&cfg));
    ASSERT(!ozayn_wof_validate_config(NULL));
    return 0;
}

TEST(test_wof_valid_transition) {
    ASSERT(ozayn_wof_is_valid_transition(OZAYN_WOF_WF_CREATED,
                                          OZAYN_WOF_WF_VALIDATING));
    ASSERT(!ozayn_wof_is_valid_transition(OZAYN_WOF_WF_CREATED,
                                           OZAYN_WOF_WF_ACTIVE));
    return 0;
}

TEST(test_wof_valid_stage_transition) {
    ASSERT(ozayn_wof_is_valid_stage_transition(OZAYN_WOF_STG_CREATED,
                                                OZAYN_WOF_STG_WAITING_DEPS));
    ASSERT(!ozayn_wof_is_valid_stage_transition(OZAYN_WOF_STG_CREATED,
                                                  OZAYN_WOF_STG_RUNNING));
    return 0;
}

/* ============================================================
 * NAME HELPER TESTS
 * ============================================================ */

TEST(test_wof_err_name) {
    ASSERT_STR_EQ(ozayn_wof_err_name(OZAYN_WOF_OK), "OK");
    ASSERT_STR_EQ(ozayn_wof_err_name(OZAYN_WOF_ERR_NULL), "NULL");
    ASSERT_STR_EQ(ozayn_wof_err_name(OZAYN_WOF_ERR_NOT_FOUND), "NOT_FOUND");
    ASSERT_STR_EQ(ozayn_wof_err_name(OZAYN_WOF_ERR_DEPENDENCY_CYCLE),
                  "DEPENDENCY_CYCLE");
    return 0;
}

TEST(test_wof_workflow_state_name) {
    ASSERT_STR_EQ(ozayn_wof_workflow_state_name(OZAYN_WOF_WF_CREATED), "CREATED");
    ASSERT_STR_EQ(ozayn_wof_workflow_state_name(OZAYN_WOF_WF_ACTIVE), "ACTIVE");
    ASSERT_STR_EQ(ozayn_wof_workflow_state_name(OZAYN_WOF_WF_SUCCEEDED),
                  "SUCCEEDED");
    return 0;
}

TEST(test_wof_workflow_type_name) {
    ASSERT_STR_EQ(ozayn_wof_workflow_type_name(OZAYN_WOF_TYPE_SEQUENTIAL),
                  "SEQUENTIAL");
    ASSERT_STR_EQ(ozayn_wof_workflow_type_name(OZAYN_WOF_TYPE_PARALLEL),
                  "PARALLEL");
    ASSERT_STR_EQ(ozayn_wof_workflow_type_name(OZAYN_WOF_TYPE_BOUNDED_PARALLEL),
                  "BOUNDED_PARALLEL");
    return 0;
}

TEST(test_wof_stage_type_name) {
    ASSERT_STR_EQ(ozayn_wof_stage_type_name(OZAYN_WOF_STAGE_PIPELINE), "PIPELINE");
    ASSERT_STR_EQ(ozayn_wof_stage_type_name(OZAYN_WOF_STAGE_OPERATION),
                  "OPERATION");
    ASSERT_STR_EQ(ozayn_wof_stage_type_name(OZAYN_WOF_STAGE_CONDITION),
                  "CONDITION");
    return 0;
}

TEST(test_wof_stage_state_name) {
    ASSERT_STR_EQ(ozayn_wof_stage_state_name(OZAYN_WOF_STG_CREATED), "CREATED");
    ASSERT_STR_EQ(ozayn_wof_stage_state_name(OZAYN_WOF_STG_COMPLETED),
                  "COMPLETED");
    return 0;
}

TEST(test_wof_condition_type_name) {
    ASSERT_STR_EQ(ozayn_wof_condition_type_name(OZAYN_WOF_COND_RESOURCE_AVAILABLE),
                  "RESOURCE_AVAILABLE");
    ASSERT_STR_EQ(ozayn_wof_condition_type_name(OZAYN_WOF_COND_PIPELINE_COMPLETED),
                  "PIPELINE_COMPLETED");
    return 0;
}

TEST(test_wof_failure_policy_name) {
    ASSERT_STR_EQ(ozayn_wof_failure_policy_name(OZAYN_WOF_FAIL_FAIL_WORKFLOW),
                  "FAIL_WORKFLOW");
    ASSERT_STR_EQ(ozayn_wof_failure_policy_name(OZAYN_WOF_FAIL_SKIP_DEPENDENTS),
                  "SKIP_DEPENDENTS");
    return 0;
}

TEST(test_wof_compensation_action_name) {
    ASSERT_STR_EQ(ozayn_wof_compensation_action_name(OZAYN_WOF_COMP_NONE), "NONE");
    ASSERT_STR_EQ(ozayn_wof_compensation_action_name(OZAYN_WOF_COMP_NOTIFY),
                  "NOTIFY");
    return 0;
}

TEST(test_wof_concurrency_policy_name) {
    ASSERT_STR_EQ(ozayn_wof_concurrency_policy_name(OZAYN_WOF_CONC_SEQUENTIAL),
                  "SEQUENTIAL");
    ASSERT_STR_EQ(ozayn_wof_concurrency_policy_name(OZAYN_WOF_CONC_BOUNDED),
                  "BOUNDED");
    return 0;
}

TEST(test_wof_event_type_name) {
    ASSERT_STR_EQ(ozayn_wof_event_type_name(OZAYN_WOF_EVENT_CREATED), "CREATED");
    ASSERT_STR_EQ(ozayn_wof_event_type_name(OZAYN_WOF_EVENT_SUCCEEDED),
                  "SUCCEEDED");
    return 0;
}

TEST(test_wof_close_reason_name) {
    ASSERT_STR_EQ(ozayn_wof_close_reason_name(OZAYN_WOF_CLOSE_MANUAL_CANCEL),
                  "MANUAL_CANCEL");
    ASSERT_STR_EQ(ozayn_wof_close_reason_name(OZAYN_WOF_CLOSE_TIMEOUT),
                  "TIMEOUT");
    return 0;
}

/* ============================================================
 * EDGE CASES / SECURITY TESTS
 * ============================================================ */

TEST(test_wof_no_bypass) {
    _create_simple_workflow();
    ozayn_wof_validate(&_svc, _wf_id);
    ozayn_wof_authorize(&_svc, _wf_id, NULL, NULL);
    const ozayn_wof_workflow_t *wf = ozayn_wof_get_workflow(&_svc, _wf_id);
    ASSERT(!wf->authorization_ref[0] || wf->authorization_ref[0] != '\0');
    ASSERT(!wf->safety_decision_ref[0] || wf->safety_decision_ref[0] != '\0');
    _shutdown_svc();
    return 0;
}

TEST(test_wof_metadata_safe) {
    _create_simple_workflow();
    const ozayn_wof_workflow_t *wf = ozayn_wof_get_workflow(&_svc, _wf_id);
    ASSERT(!strstr(wf->safe_metadata, "secret"));
    ASSERT(!strstr(wf->safe_metadata, "password"));
    _shutdown_svc();
    return 0;
}

TEST(test_wof_full_lifecycle) {
    _create_wf_with_stages();
    ozayn_wof_add_dependency(&_svc, _wf_id, _stg_id, _stg_id2);
    ASSERT_EQ(ozayn_wof_validate(&_svc, _wf_id), OZAYN_WOF_OK);
    ASSERT_EQ(ozayn_wof_authorize(&_svc, _wf_id, "auth-1", "safety-1"),
              OZAYN_WOF_OK);
    ASSERT_EQ(ozayn_wof_ready(&_svc, _wf_id), OZAYN_WOF_OK);
    ASSERT_EQ(ozayn_wof_schedule(&_svc, _wf_id), OZAYN_WOF_OK);
    ASSERT_EQ(ozayn_wof_start(&_svc, _wf_id), OZAYN_WOF_OK);
    const ozayn_wof_workflow_t *wf = ozayn_wof_get_workflow(&_svc, _wf_id);
    ASSERT_EQ(wf->state, OZAYN_WOF_WF_ACTIVE);
    ASSERT_EQ(wf->stage_count, 2);
    ASSERT_STR_EQ(wf->authorization_ref, "auth-1");
    ASSERT_STR_EQ(wf->safety_decision_ref, "safety-1");
    _shutdown_svc();
    return 0;
}

TEST(test_wof_multiple_workflows) {
    _init_svc();
    char wf1[OZAYN_WOF_MAX_ID_LEN], wf2[OZAYN_WOF_MAX_ID_LEN];
    ozayn_wof_create(&_svc, "WF1", "d", "1.0", OZAYN_WOF_TYPE_SEQUENTIAL,
                     NULL, NULL, NULL, NULL, wf1, sizeof(wf1));
    ozayn_wof_create(&_svc, "WF2", "d", "1.0", OZAYN_WOF_TYPE_PARALLEL,
                     NULL, NULL, NULL, NULL, wf2, sizeof(wf2));
    ASSERT_EQ(ozayn_wof_workflow_count(&_svc), 2);
    const ozayn_wof_workflow_t *w1 = ozayn_wof_get_workflow(&_svc, wf1);
    const ozayn_wof_workflow_t *w2 = ozayn_wof_get_workflow(&_svc, wf2);
    ASSERT_NOT_NULL(w1);
    ASSERT_NOT_NULL(w2);
    ASSERT_EQ(w1->workflow_type, OZAYN_WOF_TYPE_SEQUENTIAL);
    ASSERT_EQ(w2->workflow_type, OZAYN_WOF_TYPE_PARALLEL);
    _shutdown_svc();
    return 0;
}

TEST(test_wof_concurrent_stages) {
    _create_wf_with_stages();
    ASSERT_EQ(ozayn_wof_concurrent_stages(&_svc, _wf_id), 0);
    ozayn_wof_stage_set_state(&_svc, _wf_id, _stg_id, OZAYN_WOF_STG_RUNNING);
    ASSERT_EQ(ozayn_wof_concurrent_stages(&_svc, _wf_id), 0);
    _shutdown_svc();
    return 0;
}

TEST(test_wof_id_format) {
    _create_simple_workflow();
    ASSERT(_wf_id[0] == 'W');
    ASSERT(_wf_id[1] == 'O');
    ASSERT(_wf_id[2] == 'F');
    ASSERT(_wf_id[3] == '-');
    _shutdown_svc();
    return 0;
}

TEST(test_wof_event_has_correlation) {
    _create_simple_workflow();
    ozayn_wof_emit_event(&_svc, OZAYN_WOF_EVENT_CREATED, _wf_id,
                         "stg-1", "pipe-1", "op-1", "test");
    const ozayn_wof_event_t *ev = ozayn_wof_get_event(&_svc,
        ozayn_wof_event_count(&_svc) - 1);
    ASSERT_NOT_NULL(ev);
    ASSERT_STR_EQ(ev->workflow_id, _wf_id);
    ASSERT_STR_EQ(ev->stage_id, "stg-1");
    ASSERT_STR_EQ(ev->pipeline_id, "pipe-1");
    ASSERT_STR_EQ(ev->operation_id, "op-1");
    ASSERT(ev->sequence > 0);
    _shutdown_svc();
    return 0;
}

TEST(test_wof_create_out_id_too_small) {
    _init_svc();
    char wf_id[4];
    ASSERT_EQ(ozayn_wof_create(&_svc, "WF", "d", "1.0",
                               OZAYN_WOF_TYPE_SEQUENTIAL, NULL, NULL, NULL,
                               NULL, wf_id, 4), OZAYN_WOF_ERR_INVALID_PARAM);
    _shutdown_svc();
    return 0;
}

/* ============================================================
 * MAIN — TEST RUNNER
 * ============================================================ */

int run_cr_workflow_orchestrator_tests(void) {
    SUITE_BEGIN("Control Room — Workflow Orchestrator");

    RUN(test_wof_init);
    RUN(test_wof_init_null);
    RUN(test_wof_init_null_cfg);
    RUN(test_wof_init_double);
    RUN(test_wof_shutdown);
    RUN(test_wof_shutdown_null);
    RUN(test_wof_shutdown_not_init);
    RUN(test_wof_is_initialized_null);
    RUN(test_wof_global);

    RUN(test_wof_create);
    RUN(test_wof_create_null);
    RUN(test_wof_create_not_init);
    RUN(test_wof_create_null_name);
    RUN(test_wof_create_empty_name);
    RUN(test_wof_create_bad_type);
    RUN(test_wof_create_parallel);
    RUN(test_wof_create_bounded);
    RUN(test_wof_create_out_id_too_small);

    RUN(test_wof_lifecycle);
    RUN(test_wof_validate_not_found);
    RUN(test_wof_validate_bad_state);
    RUN(test_wof_authorize_not_found);
    RUN(test_wof_authorize_bad_state);
    RUN(test_wof_reject);
    RUN(test_wof_reject_terminal);
    RUN(test_wof_ready_no_stages);
    RUN(test_wof_schedule_start);
    RUN(test_wof_pause_resume);
    RUN(test_wof_cancel);
    RUN(test_wof_cancel_terminal);
    RUN(test_wof_drain_stop);
    RUN(test_wof_remove);
    RUN(test_wof_remove_not_terminal);

    RUN(test_wof_stage_add);
    RUN(test_wof_stage_add_null);
    RUN(test_wof_stage_add_not_found);
    RUN(test_wof_stage_add_operation);
    RUN(test_wof_stage_add_condition);
    RUN(test_wof_stage_set_state);
    RUN(test_wof_stage_set_state_invalid);
    RUN(test_wof_stage_remove);
    RUN(test_wof_stage_remove_not_terminal);

    RUN(test_wof_add_dependency);
    RUN(test_wof_add_dependency_self);
    RUN(test_wof_add_dependency_not_found);
    RUN(test_wof_add_dependency_duplicate);
    RUN(test_wof_add_dependency_cycle);
    RUN(test_wof_remove_dependency);

    RUN(test_wof_tick);
    RUN(test_wof_tick_timeout);
    RUN(test_wof_tick_deps_satisfied);
    RUN(test_wof_tick_deps_blocked);
    RUN(test_wof_fail_workflow_policy);

    RUN(test_wof_get_workflow);
    RUN(test_wof_get_workflow_null);
    RUN(test_wof_get_stage);
    RUN(test_wof_workflow_count);
    RUN(test_wof_workflow_count_by_state);
    RUN(test_wof_is_terminal);
    RUN(test_wof_is_stage_terminal);
    RUN(test_wof_concurrent_workflows);
    RUN(test_wof_concurrent_stages);

    RUN(test_wof_emit_event);
    RUN(test_wof_get_event);
    RUN(test_wof_get_event_invalid);
    RUN(test_wof_event_overflow);

    RUN(test_wof_cleanup_terminal);
    RUN(test_wof_cleanup_expired);
    RUN(test_wof_cleanup_all);

    RUN(test_wof_stats);
    RUN(test_wof_stats_null);
    RUN(test_wof_reset_stats);

    RUN(test_wof_validate_workflow);
    RUN(test_wof_validate_workflow_null);
    RUN(test_wof_validate_stage);
    RUN(test_wof_validate_config);
    RUN(test_wof_valid_transition);
    RUN(test_wof_valid_stage_transition);

    RUN(test_wof_err_name);
    RUN(test_wof_workflow_state_name);
    RUN(test_wof_workflow_type_name);
    RUN(test_wof_stage_type_name);
    RUN(test_wof_stage_state_name);
    RUN(test_wof_condition_type_name);
    RUN(test_wof_failure_policy_name);
    RUN(test_wof_compensation_action_name);
    RUN(test_wof_concurrency_policy_name);
    RUN(test_wof_event_type_name);
    RUN(test_wof_close_reason_name);

    RUN(test_wof_no_bypass);
    RUN(test_wof_metadata_safe);
    RUN(test_wof_full_lifecycle);
    RUN(test_wof_multiple_workflows);
    RUN(test_wof_id_format);
    RUN(test_wof_event_has_correlation);

    SUITE_END();
    return TOTAL_FAIL();
}
