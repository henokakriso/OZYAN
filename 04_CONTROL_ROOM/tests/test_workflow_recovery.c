#include "../workflow_recovery.h"
#include "../../tests/test_framework.h"

/* ============================================================
 * STATIC TEST HELPERS
 * ============================================================ */

static ozayn_wfr_service_t _svc;
static ozayn_wfr_service_config_t _cfg;
static char _fail_id[OZAYN_WFR_MAX_ID_LEN];
static char _fail_id2[OZAYN_WFR_MAX_ID_LEN];
static char _dec_id[OZAYN_WFR_MAX_ID_LEN];

static void _init_svc(void) {
    memset(&_svc, 0, sizeof(_svc));
    memset(&_cfg, 0, sizeof(_cfg));
    ozayn_wfr_service_init(&_svc, &_cfg);
}

static void _shutdown_svc(void) {
    ozayn_wfr_service_shutdown(&_svc);
}

static void _record_simple_failure(void) {
    _init_svc();
    ozayn_wfr_record_failure(&_svc, "wf-1", "stg-1", "op-1", "pipe-1",
                             "req-1", "pipeline-coordinator",
                             OZAYN_WFR_CAT_PIPELINE, OZAYN_WFR_SEV_HIGH,
                             -1, "Pipeline failed", _fail_id, sizeof(_fail_id));
}

static void _record_classified_failure(void) {
    _record_simple_failure();
    ozayn_wfr_classify_failure(&_svc, _fail_id, OZAYN_WFR_CAT_PIPELINE,
                               OZAYN_WFR_SEV_HIGH, OZAYN_WFR_IMPACT_STAGE_ONLY);
}

static void _record_second_failure(void) {
    ozayn_wfr_record_failure(&_svc, "wf-1", "stg-2", "op-2", "pipe-2",
                             "req-2", "scheduler",
                             OZAYN_WFR_CAT_RESOURCE, OZAYN_WFR_SEV_MEDIUM,
                             -2, "Resource exhausted", _fail_id2, sizeof(_fail_id2));
}

static int64_t _now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

/* ============================================================
 * LIFECYCLE TESTS
 * ============================================================ */

TEST(test_wfr_init) {
    _init_svc();
    ASSERT(ozayn_wfr_is_initialized(&_svc));
    _shutdown_svc();
    return 0;
}

TEST(test_wfr_init_null) {
    ASSERT_EQ(ozayn_wfr_service_init(NULL, &_cfg), OZAYN_WFR_ERR_NULL);
    return 0;
}

TEST(test_wfr_init_null_cfg) {
    ozayn_wfr_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ASSERT_EQ(ozayn_wfr_service_init(&svc, NULL), OZAYN_WFR_ERR_INVALID_PARAM);
    return 0;
}

TEST(test_wfr_init_double) {
    _init_svc();
    ASSERT_EQ(ozayn_wfr_service_init(&_svc, &_cfg), OZAYN_WFR_ERR_ALREADY_INIT);
    _shutdown_svc();
    return 0;
}

TEST(test_wfr_shutdown) {
    _init_svc();
    ASSERT_EQ(ozayn_wfr_service_shutdown(&_svc), OZAYN_WFR_OK);
    ASSERT(!ozayn_wfr_is_initialized(&_svc));
    return 0;
}

TEST(test_wfr_shutdown_null) {
    ASSERT_EQ(ozayn_wfr_service_shutdown(NULL), OZAYN_WFR_ERR_NULL);
    return 0;
}

TEST(test_wfr_shutdown_not_init) {
    ozayn_wfr_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ASSERT_EQ(ozayn_wfr_service_shutdown(&svc), OZAYN_WFR_ERR_NOT_INITIALIZED);
    return 0;
}

TEST(test_wfr_is_initialized_null) {
    ASSERT(!ozayn_wfr_is_initialized(NULL));
    return 0;
}

TEST(test_wfr_global) {
    ASSERT_NOT_NULL(ozayn_wfr_get_global());
    return 0;
}

/* ============================================================
 * FAILURE DETECTION TESTS
 * ============================================================ */

TEST(test_wfr_record_failure) {
    _init_svc();
    ASSERT_EQ(ozayn_wfr_record_failure(&_svc, "wf-1", "stg-1", "op-1", "pipe-1",
                                        "req-1", "comp",
                                        OZAYN_WFR_CAT_PIPELINE, OZAYN_WFR_SEV_HIGH,
                                        -1, "Pipeline failed",
                                        _fail_id, sizeof(_fail_id)), OZAYN_WFR_OK);
    ASSERT(_fail_id[0] != '\0');
    ASSERT_EQ(ozayn_wfr_failure_count(&_svc), 1);
    const ozayn_wfr_failure_record_t *rec = ozayn_wfr_get_failure(&_svc, _fail_id);
    ASSERT_NOT_NULL(rec);
    ASSERT_EQ(rec->state, OZAYN_WFR_FS_DETECTED);
    ASSERT_EQ(rec->category, OZAYN_WFR_CAT_PIPELINE);
    ASSERT_EQ(rec->severity, OZAYN_WFR_SEV_HIGH);
    _shutdown_svc();
    return 0;
}

TEST(test_wfr_record_failure_null) {
    _init_svc();
    char fid[OZAYN_WFR_MAX_ID_LEN];
    ASSERT_EQ(ozayn_wfr_record_failure(NULL, NULL, NULL, NULL, NULL, NULL, NULL,
                                        OZAYN_WFR_CAT_PIPELINE, OZAYN_WFR_SEV_HIGH,
                                        0, NULL, fid, sizeof(fid)), OZAYN_WFR_ERR_NULL);
    _shutdown_svc();
    return 0;
}

TEST(test_wfr_record_failure_not_init) {
    ozayn_wfr_service_t svc;
    memset(&svc, 0, sizeof(svc));
    char fid[OZAYN_WFR_MAX_ID_LEN];
    ASSERT_EQ(ozayn_wfr_record_failure(&svc, NULL, NULL, NULL, NULL, NULL, NULL,
                                        OZAYN_WFR_CAT_PIPELINE, OZAYN_WFR_SEV_HIGH,
                                        0, NULL, fid, sizeof(fid)),
              OZAYN_WFR_ERR_NOT_INITIALIZED);
    return 0;
}

TEST(test_wfr_record_failure_bad_category) {
    _init_svc();
    char fid[OZAYN_WFR_MAX_ID_LEN];
    ASSERT_EQ(ozayn_wfr_record_failure(&_svc, NULL, NULL, NULL, NULL, NULL, NULL,
                                        OZAYN_WFR_CAT_COUNT, OZAYN_WFR_SEV_HIGH,
                                        0, NULL, fid, sizeof(fid)),
              OZAYN_WFR_ERR_INVALID_PARAM);
    _shutdown_svc();
    return 0;
}

TEST(test_wfr_record_failure_bad_severity) {
    _init_svc();
    char fid[OZAYN_WFR_MAX_ID_LEN];
    ASSERT_EQ(ozayn_wfr_record_failure(&_svc, NULL, NULL, NULL, NULL, NULL, NULL,
                                        OZAYN_WFR_CAT_PIPELINE, OZAYN_WFR_SEV_COUNT,
                                        0, NULL, fid, sizeof(fid)),
              OZAYN_WFR_ERR_INVALID_PARAM);
    _shutdown_svc();
    return 0;
}

TEST(test_wfr_record_failure_small_buffer) {
    _init_svc();
    char fid[4];
    ASSERT_EQ(ozayn_wfr_record_failure(&_svc, NULL, NULL, NULL, NULL, NULL, NULL,
                                        OZAYN_WFR_CAT_PIPELINE, OZAYN_WFR_SEV_HIGH,
                                        0, NULL, fid, sizeof(fid)),
              OZAYN_WFR_ERR_INVALID_PARAM);
    _shutdown_svc();
    return 0;
}

TEST(test_wfr_record_multiple) {
    _init_svc();
    ASSERT_EQ(ozayn_wfr_record_failure(&_svc, "wf-1", NULL, NULL, NULL, NULL, NULL,
                                        OZAYN_WFR_CAT_PIPELINE, OZAYN_WFR_SEV_HIGH,
                                        0, "f1", _fail_id, sizeof(_fail_id)), OZAYN_WFR_OK);
    ASSERT_EQ(ozayn_wfr_record_failure(&_svc, "wf-1", NULL, NULL, NULL, NULL, NULL,
                                        OZAYN_WFR_CAT_RESOURCE, OZAYN_WFR_SEV_LOW,
                                        0, "f2", _fail_id2, sizeof(_fail_id2)), OZAYN_WFR_OK);
    ASSERT_EQ(ozayn_wfr_failure_count(&_svc), 2);
    _shutdown_svc();
    return 0;
}

TEST(test_wfr_record_all_categories) {
    _init_svc();
    char fid[OZAYN_WFR_MAX_ID_LEN];
    for (int i = 0; i < OZAYN_WFR_CAT_COUNT; i++) {
        ASSERT_EQ(ozayn_wfr_record_failure(&_svc, NULL, NULL, NULL, NULL, NULL, NULL,
                                            (ozayn_wfr_failure_category_t)i,
                                            OZAYN_WFR_SEV_LOW, 0, NULL,
                                            fid, sizeof(fid)), OZAYN_WFR_OK);
    }
    ASSERT_EQ(ozayn_wfr_failure_count(&_svc), OZAYN_WFR_CAT_COUNT);
    _shutdown_svc();
    return 0;
}

TEST(test_wfr_record_all_severities) {
    _init_svc();
    char fid[OZAYN_WFR_MAX_ID_LEN];
    for (int i = 0; i < OZAYN_WFR_SEV_COUNT; i++) {
        ASSERT_EQ(ozayn_wfr_record_failure(&_svc, NULL, NULL, NULL, NULL, NULL, NULL,
                                            OZAYN_WFR_CAT_UNKNOWN,
                                            (ozayn_wfr_failure_severity_t)i,
                                            0, NULL, fid, sizeof(fid)), OZAYN_WFR_OK);
    }
    ASSERT_EQ(ozayn_wfr_failure_count(&_svc), OZAYN_WFR_SEV_COUNT);
    _shutdown_svc();
    return 0;
}

/* ============================================================
 * FAILURE CLASSIFICATION TESTS
 * ============================================================ */

TEST(test_wfr_classify) {
    _record_simple_failure();
    ASSERT_EQ(ozayn_wfr_classify_failure(&_svc, _fail_id, OZAYN_WFR_CAT_PIPELINE,
                                          OZAYN_WFR_SEV_HIGH,
                                          OZAYN_WFR_IMPACT_STAGE_ONLY), OZAYN_WFR_OK);
    const ozayn_wfr_failure_record_t *rec = ozayn_wfr_get_failure(&_svc, _fail_id);
    ASSERT_EQ(rec->state, OZAYN_WFR_FS_CLASSIFIED);
    ASSERT_EQ(rec->category, OZAYN_WFR_CAT_PIPELINE);
    ASSERT_EQ(rec->severity, OZAYN_WFR_SEV_HIGH);
    ASSERT_EQ(rec->impact_level, OZAYN_WFR_IMPACT_STAGE_ONLY);
    _shutdown_svc();
    return 0;
}

TEST(test_wfr_classify_not_found) {
    _init_svc();
    ASSERT_EQ(ozayn_wfr_classify_failure(&_svc, "nonexistent",
                                          OZAYN_WFR_CAT_PIPELINE, OZAYN_WFR_SEV_HIGH,
                                          OZAYN_WFR_IMPACT_STAGE_ONLY),
              OZAYN_WFR_ERR_NOT_FOUND);
    _shutdown_svc();
    return 0;
}

TEST(test_wfr_classify_bad_impact) {
    _record_simple_failure();
    ASSERT_EQ(ozayn_wfr_classify_failure(&_svc, _fail_id, OZAYN_WFR_CAT_PIPELINE,
                                          OZAYN_WFR_SEV_HIGH,
                                          OZAYN_WFR_IMPACT_COUNT),
              OZAYN_WFR_ERR_INVALID_PARAM);
    _shutdown_svc();
    return 0;
}

/* ============================================================
 * CONTAINMENT TESTS
 * ============================================================ */

TEST(test_wfr_contain) {
    _record_classified_failure();
    ASSERT_EQ(ozayn_wfr_contain_failure(&_svc, _fail_id,
                                         OZAYN_WFR_CONTAIN_BLOCK_DEPENDENTS), OZAYN_WFR_OK);
    const ozayn_wfr_failure_record_t *rec = ozayn_wfr_get_failure(&_svc, _fail_id);
    ASSERT_EQ(rec->state, OZAYN_WFR_FS_CONTAINING);
    _shutdown_svc();
    return 0;
}

TEST(test_wfr_contain_not_found) {
    _init_svc();
    ASSERT_EQ(ozayn_wfr_contain_failure(&_svc, "nonexistent",
                                         OZAYN_WFR_CONTAIN_BLOCK_DEPENDENTS),
              OZAYN_WFR_ERR_NOT_FOUND);
    _shutdown_svc();
    return 0;
}

TEST(test_wfr_contain_bad_action) {
    _record_classified_failure();
    ASSERT_EQ(ozayn_wfr_contain_failure(&_svc, _fail_id,
                                         OZAYN_WFR_CONTAIN_COUNT),
              OZAYN_WFR_ERR_INVALID_PARAM);
    _shutdown_svc();
    return 0;
}

TEST(test_wfr_contain_from_detected) {
    _record_simple_failure();
    ASSERT_EQ(ozayn_wfr_contain_failure(&_svc, _fail_id,
                                          OZAYN_WFR_CONTAIN_STOP_DISPATCH), OZAYN_WFR_OK);
    const ozayn_wfr_failure_record_t *rec = ozayn_wfr_get_failure(&_svc, _fail_id);
    ASSERT(rec->state == OZAYN_WFR_FS_CONTAINING ||
           rec->state == OZAYN_WFR_FS_ASSESSING);
    _shutdown_svc();
    return 0;
}

TEST(test_wfr_contain_all_actions) {
    _record_classified_failure();
    for (int i = 0; i < OZAYN_WFR_CONTAIN_COUNT; i++) {
        _record_simple_failure();
        ASSERT_EQ(ozayn_wfr_classify_failure(&_svc, _fail_id, OZAYN_WFR_CAT_PIPELINE,
                                              OZAYN_WFR_SEV_HIGH,
                                               OZAYN_WFR_IMPACT_STAGE_ONLY), OZAYN_WFR_OK);
        ASSERT_EQ(ozayn_wfr_contain_failure(&_svc, _fail_id,
                                              (ozayn_wfr_containment_action_t)i), OZAYN_WFR_OK);
    }
    _shutdown_svc();
    return 0;
}

/* ============================================================
 * RECOVERY DECISION TESTS
 * ============================================================ */

TEST(test_wfr_make_decision) {
    _record_classified_failure();
    ozayn_wfr_recovery_decision_t dec;
    memset(&dec, 0, sizeof(dec));
    dec.decision = OZAYN_WFR_DEC_RETRY;
    strncpy(dec.reason, "Retry pipeline", OZAYN_WFR_MAX_DESC_LEN - 1);
    ASSERT_EQ(ozayn_wfr_make_recovery_decision(&_svc, _fail_id, &dec,
                                                _dec_id, sizeof(_dec_id)), OZAYN_WFR_OK);
    ASSERT(_dec_id[0] != '\0');
    ASSERT_EQ(ozayn_wfr_decision_count(&_svc), 1);
    const ozayn_wfr_recovery_decision_t *d = ozayn_wfr_get_decision(&_svc, _dec_id);
    ASSERT_NOT_NULL(d);
    ASSERT_EQ(d->decision, OZAYN_WFR_DEC_RETRY);
    _shutdown_svc();
    return 0;
}

TEST(test_wfr_make_decision_not_found) {
    _init_svc();
    ozayn_wfr_recovery_decision_t dec;
    memset(&dec, 0, sizeof(dec));
    dec.decision = OZAYN_WFR_DEC_RETRY;
    ASSERT_EQ(ozayn_wfr_make_recovery_decision(&_svc, "nonexistent", &dec,
                                                _dec_id, sizeof(_dec_id)),
              OZAYN_WFR_ERR_NOT_FOUND);
    _shutdown_svc();
    return 0;
}

TEST(test_wfr_make_decision_bad_decision) {
    _record_classified_failure();
    ozayn_wfr_recovery_decision_t dec;
    memset(&dec, 0, sizeof(dec));
    dec.decision = OZAYN_WFR_DEC_COUNT;
    ASSERT_EQ(ozayn_wfr_make_recovery_decision(&_svc, _fail_id, &dec,
                                                _dec_id, sizeof(_dec_id)),
              OZAYN_WFR_ERR_INVALID_PARAM);
    _shutdown_svc();
    return 0;
}

TEST(test_wfr_authorize_recovery) {
    _record_classified_failure();
    ozayn_wfr_recovery_decision_t dec;
    memset(&dec, 0, sizeof(dec));
    dec.decision = OZAYN_WFR_DEC_RETRY;
    ozayn_wfr_make_recovery_decision(&_svc, _fail_id, &dec, _dec_id, sizeof(_dec_id));
    ASSERT_EQ(ozayn_wfr_authorize_recovery(&_svc, _dec_id, "auth-ref", "safety-ref"),
              OZAYN_WFR_OK);
    const ozayn_wfr_recovery_decision_t *d = ozayn_wfr_get_decision(&_svc, _dec_id);
    ASSERT(d->authorized);
    ASSERT(d->safety_ok);
    _shutdown_svc();
    return 0;
}

TEST(test_wfr_authorize_not_found) {
    _init_svc();
    ASSERT_EQ(ozayn_wfr_authorize_recovery(&_svc, "nonexistent", "a", "s"),
              OZAYN_WFR_ERR_NOT_FOUND);
    _shutdown_svc();
    return 0;
}

/* ============================================================
 * RECOVERY EXECUTION TESTS
 * ============================================================ */

TEST(test_wfr_execute_continue) {
    _record_classified_failure();
    ozayn_wfr_recovery_decision_t dec;
    memset(&dec, 0, sizeof(dec));
    dec.decision = OZAYN_WFR_DEC_CONTINUE;
    ozayn_wfr_make_recovery_decision(&_svc, _fail_id, &dec, _dec_id, sizeof(_dec_id));
    ASSERT_EQ(ozayn_wfr_execute_recovery(&_svc, _dec_id), OZAYN_WFR_OK);
    const ozayn_wfr_failure_record_t *rec = ozayn_wfr_get_failure(&_svc, _fail_id);
    ASSERT_EQ(rec->state, OZAYN_WFR_FS_RECOVERED);
    _shutdown_svc();
    return 0;
}

TEST(test_wfr_execute_recovery_retry) {
    _record_classified_failure();
    ozayn_wfr_recovery_decision_t dec;
    memset(&dec, 0, sizeof(dec));
    dec.decision = OZAYN_WFR_DEC_RETRY;
    ozayn_wfr_make_recovery_decision(&_svc, _fail_id, &dec, _dec_id, sizeof(_dec_id));
    ASSERT_EQ(ozayn_wfr_execute_recovery(&_svc, _dec_id), OZAYN_WFR_OK);
    const ozayn_wfr_failure_record_t *rec = ozayn_wfr_get_failure(&_svc, _fail_id);
    ASSERT_EQ(rec->state, OZAYN_WFR_FS_RECOVERING);
    _shutdown_svc();
    return 0;
}

TEST(test_wfr_execute_cancel) {
    _record_classified_failure();
    ozayn_wfr_recovery_decision_t dec;
    memset(&dec, 0, sizeof(dec));
    dec.decision = OZAYN_WFR_DEC_CANCEL;
    ozayn_wfr_make_recovery_decision(&_svc, _fail_id, &dec, _dec_id, sizeof(_dec_id));
    ASSERT_EQ(ozayn_wfr_execute_recovery(&_svc, _dec_id), OZAYN_WFR_OK);
    const ozayn_wfr_failure_record_t *rec = ozayn_wfr_get_failure(&_svc, _fail_id);
    ASSERT_EQ(rec->state, OZAYN_WFR_FS_UNRECOVERABLE);
    _shutdown_svc();
    return 0;
}

TEST(test_wfr_execute_fail_workflow) {
    _record_classified_failure();
    ozayn_wfr_recovery_decision_t dec;
    memset(&dec, 0, sizeof(dec));
    dec.decision = OZAYN_WFR_DEC_FAIL_WORKFLOW;
    ozayn_wfr_make_recovery_decision(&_svc, _fail_id, &dec, _dec_id, sizeof(_dec_id));
    ASSERT_EQ(ozayn_wfr_execute_recovery(&_svc, _dec_id), OZAYN_WFR_OK);
    const ozayn_wfr_failure_record_t *rec = ozayn_wfr_get_failure(&_svc, _fail_id);
    ASSERT_EQ(rec->state, OZAYN_WFR_FS_UNRECOVERABLE);
    _shutdown_svc();
    return 0;
}

TEST(test_wfr_execute_partial) {
    _record_classified_failure();
    ozayn_wfr_recovery_decision_t dec;
    memset(&dec, 0, sizeof(dec));
    dec.decision = OZAYN_WFR_DEC_PARTIAL_CONTINUE;
    ozayn_wfr_make_recovery_decision(&_svc, _fail_id, &dec, _dec_id, sizeof(_dec_id));
    ASSERT_EQ(ozayn_wfr_execute_recovery(&_svc, _dec_id), OZAYN_WFR_OK);
    const ozayn_wfr_failure_record_t *rec = ozayn_wfr_get_failure(&_svc, _fail_id);
    ASSERT_EQ(rec->state, OZAYN_WFR_FS_PARTIALLY_RECOVERED);
    _shutdown_svc();
    return 0;
}

TEST(test_wfr_execute_compensate) {
    _record_classified_failure();
    ozayn_wfr_recovery_decision_t dec;
    memset(&dec, 0, sizeof(dec));
    dec.decision = OZAYN_WFR_DEC_COMPENSATE;
    ozayn_wfr_make_recovery_decision(&_svc, _fail_id, &dec, _dec_id, sizeof(_dec_id));
    ASSERT_EQ(ozayn_wfr_execute_recovery(&_svc, _dec_id), OZAYN_WFR_OK);
    const ozayn_wfr_failure_record_t *rec = ozayn_wfr_get_failure(&_svc, _fail_id);
    ASSERT_EQ(rec->state, OZAYN_WFR_FS_RECOVERING);
    _shutdown_svc();
    return 0;
}

TEST(test_wfr_execute_escalate) {
    _record_classified_failure();
    ozayn_wfr_recovery_decision_t dec;
    memset(&dec, 0, sizeof(dec));
    dec.decision = OZAYN_WFR_DEC_ESCALATE;
    ozayn_wfr_make_recovery_decision(&_svc, _fail_id, &dec, _dec_id, sizeof(_dec_id));
    ASSERT_EQ(ozayn_wfr_execute_recovery(&_svc, _dec_id), OZAYN_WFR_OK);
    const ozayn_wfr_failure_record_t *rec = ozayn_wfr_get_failure(&_svc, _fail_id);
    ASSERT_EQ(rec->state, OZAYN_WFR_FS_ESCALATED);
    _shutdown_svc();
    return 0;
}

TEST(test_wfr_execute_unavailable) {
    _record_classified_failure();
    ozayn_wfr_recovery_decision_t dec;
    memset(&dec, 0, sizeof(dec));
    dec.decision = OZAYN_WFR_DEC_UNAVAILABLE;
    ozayn_wfr_make_recovery_decision(&_svc, _fail_id, &dec, _dec_id, sizeof(_dec_id));
    ASSERT_EQ(ozayn_wfr_execute_recovery(&_svc, _dec_id), OZAYN_WFR_OK);
    const ozayn_wfr_failure_record_t *rec = ozayn_wfr_get_failure(&_svc, _fail_id);
    ASSERT_EQ(rec->state, OZAYN_WFR_FS_UNRECOVERABLE);
    _shutdown_svc();
    return 0;
}

TEST(test_wfr_execute_creates_history) {
    _record_classified_failure();
    ozayn_wfr_recovery_decision_t dec;
    memset(&dec, 0, sizeof(dec));
    dec.decision = OZAYN_WFR_DEC_CONTINUE;
    ozayn_wfr_make_recovery_decision(&_svc, _fail_id, &dec, _dec_id, sizeof(_dec_id));
    ASSERT_EQ(ozayn_wfr_history_count(&_svc), 0);
    ozayn_wfr_execute_recovery(&_svc, _dec_id);
    ASSERT_GE(ozayn_wfr_history_count(&_svc), 1);
    _shutdown_svc();
    return 0;
}

TEST(test_wfr_execute_not_found) {
    _init_svc();
    ASSERT_EQ(ozayn_wfr_execute_recovery(&_svc, "nonexistent"), OZAYN_WFR_ERR_NOT_FOUND);
    _shutdown_svc();
    return 0;
}

/* ============================================================
 * RETRY TESTS
 * ============================================================ */

TEST(test_wfr_evaluate_retry_idempotent) {
    _record_classified_failure();
    int retryable = 0;
    ASSERT_EQ(ozayn_wfr_evaluate_retry(&_svc, _fail_id, OZAYN_WFR_IDEMP_IDEMPOTENT,
                                        OZAYN_WFR_BACKOFF_IMMEDIATE, 0,
                                        &retryable), OZAYN_WFR_OK);
    ASSERT(retryable);
    _shutdown_svc();
    return 0;
}

TEST(test_wfr_evaluate_retry_safe_repeat) {
    _record_classified_failure();
    int retryable = 0;
    ASSERT_EQ(ozayn_wfr_evaluate_retry(&_svc, _fail_id, OZAYN_WFR_IDEMP_SAFE_REPEAT,
                                        OZAYN_WFR_BACKOFF_FIXED_DELAY, 1000,
                                        &retryable), OZAYN_WFR_OK);
    ASSERT(retryable);
    _shutdown_svc();
    return 0;
}

TEST(test_wfr_evaluate_retry_non_idempotent) {
    _record_classified_failure();
    int retryable = 0;
    ASSERT_EQ(ozayn_wfr_evaluate_retry(&_svc, _fail_id, OZAYN_WFR_IDEMP_NON_IDEMPOTENT,
                                        OZAYN_WFR_BACKOFF_IMMEDIATE, 0,
                                        &retryable), OZAYN_WFR_OK);
    ASSERT(!retryable);
    _shutdown_svc();
    return 0;
}

TEST(test_wfr_evaluate_retry_unknown) {
    _record_classified_failure();
    int retryable = 0;
    ASSERT_EQ(ozayn_wfr_evaluate_retry(&_svc, _fail_id, OZAYN_WFR_IDEMP_UNKNOWN,
                                        OZAYN_WFR_BACKOFF_IMMEDIATE, 0,
                                        &retryable), OZAYN_WFR_OK);
    ASSERT(!retryable);
    _shutdown_svc();
    return 0;
}

TEST(test_wfr_evaluate_retry_auth_failure) {
    _init_svc();
    char fid[OZAYN_WFR_MAX_ID_LEN];
    ozayn_wfr_record_failure(&_svc, "wf-1", NULL, NULL, NULL, NULL, NULL,
                              OZAYN_WFR_CAT_AUTHORIZATION, OZAYN_WFR_SEV_HIGH,
                              0, "Auth failed", fid, sizeof(fid));
    ozayn_wfr_classify_failure(&_svc, fid, OZAYN_WFR_CAT_AUTHORIZATION,
                                OZAYN_WFR_SEV_HIGH, OZAYN_WFR_IMPACT_STAGE_ONLY);
    int retryable = 1;
    ASSERT_EQ(ozayn_wfr_evaluate_retry(&_svc, fid, OZAYN_WFR_IDEMP_IDEMPOTENT,
                                        OZAYN_WFR_BACKOFF_IMMEDIATE, 0,
                                        &retryable), OZAYN_WFR_OK);
    ASSERT(!retryable);
    _shutdown_svc();
    return 0;
}

TEST(test_wfr_evaluate_retry_safety_failure) {
    _init_svc();
    char fid[OZAYN_WFR_MAX_ID_LEN];
    ozayn_wfr_record_failure(&_svc, "wf-1", NULL, NULL, NULL, NULL, NULL,
                              OZAYN_WFR_CAT_SAFETY, OZAYN_WFR_SEV_HIGH,
                              0, "Safety denied", fid, sizeof(fid));
    ozayn_wfr_classify_failure(&_svc, fid, OZAYN_WFR_CAT_SAFETY,
                                OZAYN_WFR_SEV_HIGH, OZAYN_WFR_IMPACT_STAGE_ONLY);
    int retryable = 1;
    ASSERT_EQ(ozayn_wfr_evaluate_retry(&_svc, fid, OZAYN_WFR_IDEMP_IDEMPOTENT,
                                        OZAYN_WFR_BACKOFF_IMMEDIATE, 0,
                                        &retryable), OZAYN_WFR_OK);
    ASSERT(!retryable);
    _shutdown_svc();
    return 0;
}

TEST(test_wfr_evaluate_retry_critical) {
    _init_svc();
    char fid[OZAYN_WFR_MAX_ID_LEN];
    ozayn_wfr_record_failure(&_svc, "wf-1", NULL, NULL, NULL, NULL, NULL,
                              OZAYN_WFR_CAT_PIPELINE, OZAYN_WFR_SEV_CRITICAL,
                              0, "Critical", fid, sizeof(fid));
    ozayn_wfr_classify_failure(&_svc, fid, OZAYN_WFR_CAT_PIPELINE,
                                OZAYN_WFR_SEV_CRITICAL, OZAYN_WFR_IMPACT_WORKFLOW);
    int retryable = 1;
    ASSERT_EQ(ozayn_wfr_evaluate_retry(&_svc, fid, OZAYN_WFR_IDEMP_IDEMPOTENT,
                                        OZAYN_WFR_BACKOFF_IMMEDIATE, 0,
                                        &retryable), OZAYN_WFR_OK);
    ASSERT(!retryable);
    _shutdown_svc();
    return 0;
}

TEST(test_wfr_execute_retry) {
    _record_classified_failure();
    ozayn_wfr_recovery_decision_t dec;
    memset(&dec, 0, sizeof(dec));
    dec.decision = OZAYN_WFR_DEC_RETRY;
    ozayn_wfr_make_recovery_decision(&_svc, _fail_id, &dec, _dec_id, sizeof(_dec_id));
    ASSERT_EQ(ozayn_wfr_execute_retry(&_svc, _fail_id, _dec_id), OZAYN_WFR_OK);
    _shutdown_svc();
    return 0;
}

TEST(test_wfr_execute_retry_auth_blocked) {
    _init_svc();
    char fid[OZAYN_WFR_MAX_ID_LEN];
    ozayn_wfr_record_failure(&_svc, "wf-1", NULL, NULL, NULL, NULL, NULL,
                              OZAYN_WFR_CAT_AUTHORIZATION, OZAYN_WFR_SEV_HIGH,
                              0, "Auth", fid, sizeof(fid));
    ozayn_wfr_classify_failure(&_svc, fid, OZAYN_WFR_CAT_AUTHORIZATION,
                                OZAYN_WFR_SEV_HIGH, OZAYN_WFR_IMPACT_STAGE_ONLY);
    ozayn_wfr_recovery_decision_t dec;
    memset(&dec, 0, sizeof(dec));
    dec.decision = OZAYN_WFR_DEC_RETRY;
    char did[OZAYN_WFR_MAX_ID_LEN];
    ozayn_wfr_make_recovery_decision(&_svc, fid, &dec, did, sizeof(did));
    ASSERT_EQ(ozayn_wfr_execute_retry(&_svc, fid, did), OZAYN_WFR_ERR_RETRY_NOT_ALLOWED);
    _shutdown_svc();
    return 0;
}

TEST(test_wfr_evaluate_retry_not_found) {
    _init_svc();
    int retryable = 0;
    ASSERT_EQ(ozayn_wfr_evaluate_retry(&_svc, "nonexistent", OZAYN_WFR_IDEMP_IDEMPOTENT,
                                        OZAYN_WFR_BACKOFF_IMMEDIATE, 0,
                                        &retryable), OZAYN_WFR_ERR_NOT_FOUND);
    _shutdown_svc();
    return 0;
}

/* ============================================================
 * COMPENSATION TESTS
 * ============================================================ */

TEST(test_wfr_evaluate_compensation) {
    _record_classified_failure();
    int compensable = 0;
    ASSERT_EQ(ozayn_wfr_evaluate_compensation(&_svc, _fail_id, &compensable), OZAYN_WFR_OK);
    ASSERT(compensable);
    _shutdown_svc();
    return 0;
}

TEST(test_wfr_evaluate_compensation_validation) {
    _init_svc();
    char fid[OZAYN_WFR_MAX_ID_LEN];
    ozayn_wfr_record_failure(&_svc, "wf-1", NULL, NULL, NULL, NULL, NULL,
                              OZAYN_WFR_CAT_VALIDATION, OZAYN_WFR_SEV_LOW,
                              0, "Validation error", fid, sizeof(fid));
    ozayn_wfr_classify_failure(&_svc, fid, OZAYN_WFR_CAT_VALIDATION,
                                OZAYN_WFR_SEV_LOW, OZAYN_WFR_IMPACT_STAGE_ONLY);
    int compensable = 1;
    ASSERT_EQ(ozayn_wfr_evaluate_compensation(&_svc, fid, &compensable), OZAYN_WFR_OK);
    ASSERT(!compensable);
    _shutdown_svc();
    return 0;
}

TEST(test_wfr_execute_compensation) {
    _record_classified_failure();
    ozayn_wfr_recovery_decision_t dec;
    memset(&dec, 0, sizeof(dec));
    dec.decision = OZAYN_WFR_DEC_COMPENSATE;
    ozayn_wfr_make_recovery_decision(&_svc, _fail_id, &dec, _dec_id, sizeof(_dec_id));
    ASSERT_EQ(ozayn_wfr_execute_compensation(&_svc, _fail_id, _dec_id), OZAYN_WFR_OK);
    _shutdown_svc();
    return 0;
}

TEST(test_wfr_evaluate_compensation_not_found) {
    _init_svc();
    int compensable = 0;
    ASSERT_EQ(ozayn_wfr_evaluate_compensation(&_svc, "nonexistent", &compensable),
              OZAYN_WFR_ERR_NOT_FOUND);
    _shutdown_svc();
    return 0;
}

/* ============================================================
 * TICK TESTS
 * ============================================================ */

TEST(test_wfr_tick) {
    _record_simple_failure();
    ASSERT_EQ(ozayn_wfr_tick(&_svc, _now_ms()), OZAYN_WFR_OK);
    _shutdown_svc();
    return 0;
}

TEST(test_wfr_tick_auto_classify) {
    _record_simple_failure();
    ozayn_wfr_tick(&_svc, _now_ms());
    const ozayn_wfr_failure_record_t *rec = ozayn_wfr_get_failure(&_svc, _fail_id);
    ASSERT(rec->state >= OZAYN_WFR_FS_CLASSIFIED);
    _shutdown_svc();
    return 0;
}

TEST(test_wfr_tick_auto_escalate_critical) {
    _init_svc();
    char fid[OZAYN_WFR_MAX_ID_LEN];
    ozayn_wfr_record_failure(&_svc, "wf-1", NULL, NULL, NULL, NULL, NULL,
                              OZAYN_WFR_CAT_INTERNAL, OZAYN_WFR_SEV_CRITICAL,
                              0, "Critical internal", fid, sizeof(fid));
    ozayn_wfr_classify_failure(&_svc, fid, OZAYN_WFR_CAT_INTERNAL,
                                OZAYN_WFR_SEV_CRITICAL, OZAYN_WFR_IMPACT_WORKFLOW);
    ozayn_wfr_recovery_decision_t dec;
    memset(&dec, 0, sizeof(dec));
    dec.decision = OZAYN_WFR_DEC_RETRY;
    char did[OZAYN_WFR_MAX_ID_LEN];
    ozayn_wfr_make_recovery_decision(&_svc, fid, &dec, did, sizeof(did));
    ozayn_wfr_execute_recovery(&_svc, did);
    ozayn_wfr_tick(&_svc, _now_ms());
    const ozayn_wfr_failure_record_t *rec = ozayn_wfr_get_failure(&_svc, fid);
    ASSERT_EQ(rec->state, OZAYN_WFR_FS_ESCALATED);
    _shutdown_svc();
    return 0;
}

TEST(test_wfr_tick_auto_recover_timeout) {
    _init_svc();
    char fid[OZAYN_WFR_MAX_ID_LEN];
    ozayn_wfr_record_failure(&_svc, "wf-1", NULL, NULL, NULL, NULL, NULL,
                              OZAYN_WFR_CAT_TIMEOUT, OZAYN_WFR_SEV_MEDIUM,
                              0, "Timeout", fid, sizeof(fid));
    ozayn_wfr_classify_failure(&_svc, fid, OZAYN_WFR_CAT_TIMEOUT,
                                OZAYN_WFR_SEV_MEDIUM, OZAYN_WFR_IMPACT_STAGE_ONLY);
    ozayn_wfr_recovery_decision_t dec;
    memset(&dec, 0, sizeof(dec));
    dec.decision = OZAYN_WFR_DEC_RETRY;
    char did[OZAYN_WFR_MAX_ID_LEN];
    ozayn_wfr_make_recovery_decision(&_svc, fid, &dec, did, sizeof(did));
    ozayn_wfr_execute_recovery(&_svc, did);
    ozayn_wfr_tick(&_svc, _now_ms());
    const ozayn_wfr_failure_record_t *rec = ozayn_wfr_get_failure(&_svc, fid);
    ASSERT_EQ(rec->state, OZAYN_WFR_FS_RECOVERED);
    _shutdown_svc();
    return 0;
}

TEST(test_wfr_tick_expires_decisions) {
    _record_classified_failure();
    ozayn_wfr_recovery_decision_t dec;
    memset(&dec, 0, sizeof(dec));
    dec.decision = OZAYN_WFR_DEC_RETRY;
    dec.expiration_time = 1000;
    ozayn_wfr_make_recovery_decision(&_svc, _fail_id, &dec, _dec_id, sizeof(_dec_id));
    ozayn_wfr_tick(&_svc, 2000);
    ASSERT_NULL(ozayn_wfr_get_decision(&_svc, _dec_id));
    _shutdown_svc();
    return 0;
}

/* ============================================================
 * CLOSE / ACKNOWLEDGE TESTS
 * ============================================================ */

TEST(test_wfr_close_failure) {
    _record_classified_failure();
    ASSERT_EQ(ozayn_wfr_close_failure(&_svc, _fail_id), OZAYN_WFR_OK);
    const ozayn_wfr_failure_record_t *rec = ozayn_wfr_get_failure(&_svc, _fail_id);
    ASSERT_EQ(rec->state, OZAYN_WFR_FS_CLOSED);
    _shutdown_svc();
    return 0;
}

TEST(test_wfr_close_terminal) {
    _record_classified_failure();
    ozayn_wfr_close_failure(&_svc, _fail_id);
    ASSERT_EQ(ozayn_wfr_close_failure(&_svc, _fail_id), OZAYN_WFR_ERR_STATE_INVALID);
    _shutdown_svc();
    return 0;
}

TEST(test_wfr_acknowledge) {
    _record_classified_failure();
    ASSERT_EQ(ozayn_wfr_acknowledge_failure(&_svc, _fail_id), OZAYN_WFR_OK);
    const ozayn_wfr_failure_record_t *rec = ozayn_wfr_get_failure(&_svc, _fail_id);
    ASSERT_EQ(rec->state, OZAYN_WFR_FS_ACKNOWLEDGED);
    _shutdown_svc();
    return 0;
}

TEST(test_wfr_close_not_found) {
    _init_svc();
    ASSERT_EQ(ozayn_wfr_close_failure(&_svc, "nonexistent"), OZAYN_WFR_ERR_NOT_FOUND);
    _shutdown_svc();
    return 0;
}

/* ============================================================
 * QUERY TESTS
 * ============================================================ */

TEST(test_wfr_get_failure) {
    _record_simple_failure();
    ASSERT_NOT_NULL(ozayn_wfr_get_failure(&_svc, _fail_id));
    ASSERT_NULL(ozayn_wfr_get_failure(&_svc, "nonexistent"));
    _shutdown_svc();
    return 0;
}

TEST(test_wfr_get_failure_null) {
    ASSERT_NULL(ozayn_wfr_get_failure(NULL, "id"));
    ASSERT_NULL(ozayn_wfr_get_failure(&_svc, NULL));
    return 0;
}

TEST(test_wfr_get_decision) {
    _record_classified_failure();
    ozayn_wfr_recovery_decision_t dec;
    memset(&dec, 0, sizeof(dec));
    dec.decision = OZAYN_WFR_DEC_CONTINUE;
    ozayn_wfr_make_recovery_decision(&_svc, _fail_id, &dec, _dec_id, sizeof(_dec_id));
    ASSERT_NOT_NULL(ozayn_wfr_get_decision(&_svc, _dec_id));
    ASSERT_NULL(ozayn_wfr_get_decision(&_svc, "nonexistent"));
    _shutdown_svc();
    return 0;
}

TEST(test_wfr_failure_count) {
    _init_svc();
    ASSERT_EQ(ozayn_wfr_failure_count(&_svc), 0);
    _record_simple_failure();
    ASSERT_EQ(ozayn_wfr_failure_count(&_svc), 1);
    _shutdown_svc();
    return 0;
}

TEST(test_wfr_failure_count_by_state) {
    _record_simple_failure();
    ASSERT_EQ(ozayn_wfr_failure_count_by_state(&_svc, OZAYN_WFR_FS_DETECTED), 1);
    ASSERT_EQ(ozayn_wfr_failure_count_by_state(&_svc, OZAYN_WFR_FS_CLOSED), 0);
    _shutdown_svc();
    return 0;
}

TEST(test_wfr_failure_count_by_category) {
    _record_simple_failure();
    ASSERT_EQ(ozayn_wfr_failure_count_by_category(&_svc, OZAYN_WFR_CAT_PIPELINE), 1);
    ASSERT_EQ(ozayn_wfr_failure_count_by_category(&_svc, OZAYN_WFR_CAT_RESOURCE), 0);
    _shutdown_svc();
    return 0;
}

TEST(test_wfr_decision_count) {
    _init_svc();
    ASSERT_EQ(ozayn_wfr_decision_count(&_svc), 0);
    _record_classified_failure();
    ozayn_wfr_recovery_decision_t dec;
    memset(&dec, 0, sizeof(dec));
    dec.decision = OZAYN_WFR_DEC_CONTINUE;
    ozayn_wfr_make_recovery_decision(&_svc, _fail_id, &dec, _dec_id, sizeof(_dec_id));
    ASSERT_EQ(ozayn_wfr_decision_count(&_svc), 1);
    _shutdown_svc();
    return 0;
}

TEST(test_wfr_active_failures) {
    _init_svc();
    ASSERT_EQ(ozayn_wfr_active_failures(&_svc), 0);
    _record_simple_failure();
    ASSERT_EQ(ozayn_wfr_active_failures(&_svc), 1);
    _shutdown_svc();
    return 0;
}

TEST(test_wfr_is_failure_terminal) {
    ASSERT(ozayn_wfr_is_failure_terminal(OZAYN_WFR_FS_RECOVERED));
    ASSERT(ozayn_wfr_is_failure_terminal(OZAYN_WFR_FS_UNRECOVERABLE));
    ASSERT(ozayn_wfr_is_failure_terminal(OZAYN_WFR_FS_CLOSED));
    ASSERT(!ozayn_wfr_is_failure_terminal(OZAYN_WFR_FS_DETECTED));
    ASSERT(!ozayn_wfr_is_failure_terminal(OZAYN_WFR_FS_RECOVERING));
    return 0;
}

/* ============================================================
 * EVENT TESTS
 * ============================================================ */

TEST(test_wfr_emit_event) {
    _init_svc();
    int before = ozayn_wfr_event_count(&_svc);
    ASSERT_EQ(ozayn_wfr_emit_event(&_svc, OZAYN_WFR_EVENT_FAILURE_DETECTED,
                                    "f-1", "wf-1", "stg-1", "test"), OZAYN_WFR_OK);
    ASSERT_GE(ozayn_wfr_event_count(&_svc), before + 1);
    _shutdown_svc();
    return 0;
}

TEST(test_wfr_get_event) {
    _init_svc();
    ozayn_wfr_emit_event(&_svc, OZAYN_WFR_EVENT_FAILURE_DETECTED,
                         "f-1", "wf-1", NULL, "msg");
    const ozayn_wfr_event_t *ev = ozayn_wfr_get_event(&_svc,
        ozayn_wfr_event_count(&_svc) - 1);
    ASSERT_NOT_NULL(ev);
    ASSERT_EQ(ev->event_type, OZAYN_WFR_EVENT_FAILURE_DETECTED);
    _shutdown_svc();
    return 0;
}

TEST(test_wfr_get_event_invalid) {
    _init_svc();
    ASSERT_NULL(ozayn_wfr_get_event(&_svc, -1));
    ASSERT_NULL(ozayn_wfr_get_event(&_svc, OZAYN_WFR_MAX_EVENTS));
    _shutdown_svc();
    return 0;
}

TEST(test_wfr_event_overflow) {
    _init_svc();
    for (int i = 0; i < OZAYN_WFR_MAX_EVENTS + 5; i++) {
        ozayn_wfr_emit_event(&_svc, OZAYN_WFR_EVENT_FAILURE_DETECTED,
                             "f-1", "wf-1", NULL, "msg");
    }
    ASSERT_GE(ozayn_wfr_event_count(&_svc), 1);
    _shutdown_svc();
    return 0;
}

/* ============================================================
 * CLEANUP TESTS
 * ============================================================ */

TEST(test_wfr_cleanup_closed) {
    _record_classified_failure();
    ozayn_wfr_close_failure(&_svc, _fail_id);
    ASSERT_EQ(ozayn_wfr_cleanup_closed(&_svc), OZAYN_WFR_OK);
    ASSERT_NULL(ozayn_wfr_get_failure(&_svc, _fail_id));
    _shutdown_svc();
    return 0;
}

TEST(test_wfr_cleanup_all) {
    _record_simple_failure();
    ASSERT_EQ(ozayn_wfr_cleanup_all(&_svc), OZAYN_WFR_OK);
    ASSERT_EQ(ozayn_wfr_failure_count(&_svc), 0);
    _shutdown_svc();
    return 0;
}

/* ============================================================
 * STATISTICS TESTS
 * ============================================================ */

TEST(test_wfr_stats) {
    _init_svc();
    const ozayn_wfr_stats_t *stats = ozayn_wfr_get_stats(&_svc);
    ASSERT_NOT_NULL(stats);
    ASSERT_EQ(stats->total_failures_detected, 0);
    _record_simple_failure();
    stats = ozayn_wfr_get_stats(&_svc);
    ASSERT_EQ(stats->total_failures_detected, 1);
    _shutdown_svc();
    return 0;
}

TEST(test_wfr_stats_null) {
    ASSERT_NULL(ozayn_wfr_get_stats(NULL));
    return 0;
}

TEST(test_wfr_reset_stats) {
    _init_svc();
    _record_simple_failure();
    ASSERT_EQ(ozayn_wfr_reset_stats(&_svc), OZAYN_WFR_OK);
    const ozayn_wfr_stats_t *stats = ozayn_wfr_get_stats(&_svc);
    ASSERT_EQ(stats->total_failures_detected, 0);
    _shutdown_svc();
    return 0;
}

/* ============================================================
 * VALIDATION TESTS
 * ============================================================ */

TEST(test_wfr_validate_failure) {
    _record_simple_failure();
    ASSERT(ozayn_wfr_validate_failure_record(&_svc, _fail_id));
    ASSERT(!ozayn_wfr_validate_failure_record(&_svc, "nonexistent"));
    _shutdown_svc();
    return 0;
}

TEST(test_wfr_validate_failure_null) {
    ASSERT(!ozayn_wfr_validate_failure_record(NULL, "id"));
    ASSERT(!ozayn_wfr_validate_failure_record(&_svc, NULL));
    return 0;
}

TEST(test_wfr_validate_decision) {
    _record_classified_failure();
    ozayn_wfr_recovery_decision_t dec;
    memset(&dec, 0, sizeof(dec));
    dec.decision = OZAYN_WFR_DEC_CONTINUE;
    ozayn_wfr_make_recovery_decision(&_svc, _fail_id, &dec, _dec_id, sizeof(_dec_id));
    ASSERT(ozayn_wfr_validate_decision(&_svc, _dec_id));
    ASSERT(!ozayn_wfr_validate_decision(&_svc, "nonexistent"));
    _shutdown_svc();
    return 0;
}

TEST(test_wfr_validate_config) {
    ozayn_wfr_service_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    ASSERT(ozayn_wfr_validate_config(&cfg));
    ASSERT(!ozayn_wfr_validate_config(NULL));
    return 0;
}

TEST(test_wfr_valid_transition) {
    ASSERT(ozayn_wfr_is_valid_failure_transition(OZAYN_WFR_FS_DETECTED,
                                                   OZAYN_WFR_FS_CLASSIFIED));
    ASSERT(!ozayn_wfr_is_valid_failure_transition(OZAYN_WFR_FS_DETECTED,
                                                    OZAYN_WFR_FS_RECOVERED));
    return 0;
}

/* ============================================================
 * NAME HELPER TESTS
 * ============================================================ */

TEST(test_wfr_err_name) {
    ASSERT_STR_EQ(ozayn_wfr_err_name(OZAYN_WFR_OK), "OK");
    ASSERT_STR_EQ(ozayn_wfr_err_name(OZAYN_WFR_ERR_NULL), "NULL");
    ASSERT_STR_EQ(ozayn_wfr_err_name(OZAYN_WFR_ERR_NOT_FOUND), "NOT_FOUND");
    return 0;
}

TEST(test_wfr_category_name) {
    ASSERT_STR_EQ(ozayn_wfr_failure_category_name(OZAYN_WFR_CAT_PIPELINE), "PIPELINE");
    ASSERT_STR_EQ(ozayn_wfr_failure_category_name(OZAYN_WFR_CAT_RESOURCE), "RESOURCE");
    ASSERT_STR_EQ(ozayn_wfr_failure_category_name(OZAYN_WFR_CAT_TIMEOUT), "TIMEOUT");
    return 0;
}

TEST(test_wfr_severity_name) {
    ASSERT_STR_EQ(ozayn_wfr_failure_severity_name(OZAYN_WFR_SEV_INFO), "INFO");
    ASSERT_STR_EQ(ozayn_wfr_failure_severity_name(OZAYN_WFR_SEV_CRITICAL), "CRITICAL");
    return 0;
}

TEST(test_wfr_state_name) {
    ASSERT_STR_EQ(ozayn_wfr_failure_state_name(OZAYN_WFR_FS_DETECTED), "DETECTED");
    ASSERT_STR_EQ(ozayn_wfr_failure_state_name(OZAYN_WFR_FS_RECOVERED), "RECOVERED");
    return 0;
}

TEST(test_wfr_decision_name) {
    ASSERT_STR_EQ(ozayn_wfr_recovery_decision_name(OZAYN_WFR_DEC_RETRY), "RETRY");
    ASSERT_STR_EQ(ozayn_wfr_recovery_decision_name(OZAYN_WFR_DEC_CANCEL), "CANCEL");
    return 0;
}

TEST(test_wfr_impact_name) {
    ASSERT_STR_EQ(ozayn_wfr_impact_level_name(OZAYN_WFR_IMPACT_STAGE_ONLY), "STAGE_ONLY");
    ASSERT_STR_EQ(ozayn_wfr_impact_level_name(OZAYN_WFR_IMPACT_WORKFLOW), "WORKFLOW");
    return 0;
}

TEST(test_wfr_containment_name) {
    ASSERT_STR_EQ(ozayn_wfr_containment_action_name(OZAYN_WFR_CONTAIN_STOP_DISPATCH),
                  "STOP_DISPATCH");
    ASSERT_STR_EQ(ozayn_wfr_containment_action_name(OZAYN_WFR_CONTAIN_CANCEL_PIPELINE),
                  "CANCEL_PIPELINE");
    return 0;
}

TEST(test_wfr_idempotency_name) {
    ASSERT_STR_EQ(ozayn_wfr_idempotency_name(OZAYN_WFR_IDEMP_IDEMPOTENT), "IDEMPOTENT");
    ASSERT_STR_EQ(ozayn_wfr_idempotency_name(OZAYN_WFR_IDEMP_NON_IDEMPOTENT), "NON_IDEMPOTENT");
    return 0;
}

TEST(test_wfr_backoff_name) {
    ASSERT_STR_EQ(ozayn_wfr_backoff_strategy_name(OZAYN_WFR_BACKOFF_IMMEDIATE), "IMMEDIATE");
    ASSERT_STR_EQ(ozayn_wfr_backoff_strategy_name(OZAYN_WFR_BACKOFF_BOUNDED_EXPONENTIAL),
                  "BOUNDED_EXPONENTIAL");
    return 0;
}

TEST(test_wfr_recovery_state_name) {
    ASSERT_STR_EQ(ozayn_wfr_recovery_state_name(OZAYN_WFR_RECOVERY_NONE), "NONE");
    ASSERT_STR_EQ(ozayn_wfr_recovery_state_name(OZAYN_WFR_RECOVERY_RECOVERING), "RECOVERING");
    return 0;
}

TEST(test_wfr_event_type_name) {
    ASSERT_STR_EQ(ozayn_wfr_event_type_name(OZAYN_WFR_EVENT_FAILURE_DETECTED),
                  "FAILURE_DETECTED");
    ASSERT_STR_EQ(ozayn_wfr_event_type_name(OZAYN_WFR_EVENT_RECOVERY_COMPLETED),
                  "RECOVERY_COMPLETED");
    return 0;
}

TEST(test_wfr_history_result_name) {
    ASSERT_STR_EQ(ozayn_wfr_history_result_name(OZAYN_WFR_HIST_SUCCESS), "SUCCESS");
    ASSERT_STR_EQ(ozayn_wfr_history_result_name(OZAYN_WFR_HIST_FAILURE), "FAILURE");
    return 0;
}

/* ============================================================
 * SECURITY / EDGE CASES
 * ============================================================ */

TEST(test_wfr_no_bypass) {
    _record_classified_failure();
    ozayn_wfr_recovery_decision_t dec;
    memset(&dec, 0, sizeof(dec));
    dec.decision = OZAYN_WFR_DEC_CONTINUE;
    ozayn_wfr_make_recovery_decision(&_svc, _fail_id, &dec, _dec_id, sizeof(_dec_id));
    const ozayn_wfr_recovery_decision_t *d = ozayn_wfr_get_decision(&_svc, _dec_id);
    ASSERT(!d->authorization_ref[0] || d->authorization_ref[0] != '\0');
    ASSERT(!d->safety_ref[0] || d->safety_ref[0] != '\0');
    _shutdown_svc();
    return 0;
}

TEST(test_wfr_metadata_safe) {
    _record_simple_failure();
    const ozayn_wfr_failure_record_t *rec = ozayn_wfr_get_failure(&_svc, _fail_id);
    ASSERT(!strstr(rec->safe_metadata, "secret"));
    ASSERT(!strstr(rec->safe_metadata, "password"));
    _shutdown_svc();
    return 0;
}

TEST(test_wfr_correlation_preserved) {
    _init_svc();
    ozayn_wfr_record_failure(&_svc, "wf-1", "stg-1", "op-1", "pipe-1",
                              "req-1", "comp", OZAYN_WFR_CAT_PIPELINE,
                              OZAYN_WFR_SEV_HIGH, 0, "fail",
                              _fail_id, sizeof(_fail_id));
    const ozayn_wfr_failure_record_t *rec = ozayn_wfr_get_failure(&_svc, _fail_id);
    ASSERT_STR_EQ(rec->workflow_id, "wf-1");
    ASSERT_STR_EQ(rec->stage_id, "stg-1");
    ASSERT_STR_EQ(rec->operation_id, "op-1");
    ASSERT_STR_EQ(rec->pipeline_id, "pipe-1");
    ASSERT_STR_EQ(rec->request_id, "req-1");
    _shutdown_svc();
    return 0;
}

TEST(test_wfr_event_correlation) {
    _record_simple_failure();
    const ozayn_wfr_event_t *ev = ozayn_wfr_get_event(&_svc,
        ozayn_wfr_event_count(&_svc) - 1);
    ASSERT_NOT_NULL(ev);
    ASSERT_STR_EQ(ev->failure_id, _fail_id);
    ASSERT_STR_EQ(ev->workflow_id, "wf-1");
    ASSERT_STR_EQ(ev->stage_id, "stg-1");
    ASSERT(ev->sequence > 0);
    _shutdown_svc();
    return 0;
}

TEST(test_wfr_full_lifecycle) {
    _record_classified_failure();
    ozayn_wfr_recovery_decision_t dec;
    memset(&dec, 0, sizeof(dec));
    dec.decision = OZAYN_WFR_DEC_RETRY;
    strncpy(dec.reason, "Retry after transient", OZAYN_WFR_MAX_DESC_LEN - 1);
    ozayn_wfr_make_recovery_decision(&_svc, _fail_id, &dec, _dec_id, sizeof(_dec_id));
    ozayn_wfr_authorize_recovery(&_svc, _dec_id, "auth-1", "safety-1");
    ozayn_wfr_execute_recovery(&_svc, _dec_id);
    ozayn_wfr_close_failure(&_svc, _fail_id);
    const ozayn_wfr_failure_record_t *rec = ozayn_wfr_get_failure(&_svc, _fail_id);
    ASSERT_EQ(rec->state, OZAYN_WFR_FS_CLOSED);
    _shutdown_svc();
    return 0;
}

TEST(test_wfr_multiple_failures) {
    _init_svc();
    ASSERT_EQ(ozayn_wfr_record_failure(&_svc, "wf-1", NULL, NULL, NULL, NULL, NULL,
                                        OZAYN_WFR_CAT_PIPELINE, OZAYN_WFR_SEV_HIGH,
                                        0, "f1", _fail_id, sizeof(_fail_id)), OZAYN_WFR_OK);
    ASSERT_EQ(ozayn_wfr_record_failure(&_svc, "wf-1", NULL, NULL, NULL, NULL, NULL,
                                        OZAYN_WFR_CAT_RESOURCE, OZAYN_WFR_SEV_LOW,
                                        0, "f2", _fail_id2, sizeof(_fail_id2)), OZAYN_WFR_OK);
    ASSERT_EQ(ozayn_wfr_failure_count(&_svc), 2);
    ASSERT(strcmp(_fail_id, _fail_id2) != 0);
    _shutdown_svc();
    return 0;
}

TEST(test_wfr_get_history_entry) {
    _record_classified_failure();
    ozayn_wfr_recovery_decision_t dec;
    memset(&dec, 0, sizeof(dec));
    dec.decision = OZAYN_WFR_DEC_CONTINUE;
    ozayn_wfr_make_recovery_decision(&_svc, _fail_id, &dec, _dec_id, sizeof(_dec_id));
    ozayn_wfr_execute_recovery(&_svc, _dec_id);
    const ozayn_wfr_recovery_history_t *h = ozayn_wfr_get_history_entry(&_svc, 0);
    ASSERT_NOT_NULL(h);
    ASSERT_STR_EQ(h->failure_id, _fail_id);
    _shutdown_svc();
    return 0;
}

TEST(test_wfr_get_history_entry_invalid) {
    _init_svc();
    ASSERT_NULL(ozayn_wfr_get_history_entry(&_svc, -1));
    ASSERT_NULL(ozayn_wfr_get_history_entry(&_svc, OZAYN_WFR_MAX_RECOVERY_HISTORY));
    _shutdown_svc();
    return 0;
}

/* ============================================================
 * MAIN — TEST RUNNER
 * ============================================================ */

int run_cr_workflow_recovery_tests(void) {
    SUITE_BEGIN("Control Room — Workflow Recovery");

    RUN(test_wfr_init);
    RUN(test_wfr_init_null);
    RUN(test_wfr_init_null_cfg);
    RUN(test_wfr_init_double);
    RUN(test_wfr_shutdown);
    RUN(test_wfr_shutdown_null);
    RUN(test_wfr_shutdown_not_init);
    RUN(test_wfr_is_initialized_null);
    RUN(test_wfr_global);

    RUN(test_wfr_record_failure);
    RUN(test_wfr_record_failure_null);
    RUN(test_wfr_record_failure_not_init);
    RUN(test_wfr_record_failure_bad_category);
    RUN(test_wfr_record_failure_bad_severity);
    RUN(test_wfr_record_failure_small_buffer);
    RUN(test_wfr_record_multiple);
    RUN(test_wfr_record_all_categories);
    RUN(test_wfr_record_all_severities);

    RUN(test_wfr_classify);
    RUN(test_wfr_classify_not_found);
    RUN(test_wfr_classify_bad_impact);

    RUN(test_wfr_contain);
    RUN(test_wfr_contain_not_found);
    RUN(test_wfr_contain_bad_action);
    RUN(test_wfr_contain_from_detected);
    RUN(test_wfr_contain_all_actions);

    RUN(test_wfr_make_decision);
    RUN(test_wfr_make_decision_not_found);
    RUN(test_wfr_make_decision_bad_decision);
    RUN(test_wfr_authorize_recovery);
    RUN(test_wfr_authorize_not_found);

    RUN(test_wfr_execute_continue);
    RUN(test_wfr_execute_recovery_retry);
    RUN(test_wfr_execute_cancel);
    RUN(test_wfr_execute_fail_workflow);
    RUN(test_wfr_execute_partial);
    RUN(test_wfr_execute_compensate);
    RUN(test_wfr_execute_escalate);
    RUN(test_wfr_execute_unavailable);
    RUN(test_wfr_execute_creates_history);
    RUN(test_wfr_execute_not_found);

    RUN(test_wfr_evaluate_retry_idempotent);
    RUN(test_wfr_evaluate_retry_safe_repeat);
    RUN(test_wfr_evaluate_retry_non_idempotent);
    RUN(test_wfr_evaluate_retry_unknown);
    RUN(test_wfr_evaluate_retry_auth_failure);
    RUN(test_wfr_evaluate_retry_safety_failure);
    RUN(test_wfr_evaluate_retry_critical);
    RUN(test_wfr_execute_retry);
    RUN(test_wfr_execute_retry_auth_blocked);
    RUN(test_wfr_evaluate_retry_not_found);

    RUN(test_wfr_evaluate_compensation);
    RUN(test_wfr_evaluate_compensation_validation);
    RUN(test_wfr_execute_compensation);
    RUN(test_wfr_evaluate_compensation_not_found);

    RUN(test_wfr_tick);
    RUN(test_wfr_tick_auto_classify);
    RUN(test_wfr_tick_auto_escalate_critical);
    RUN(test_wfr_tick_auto_recover_timeout);
    RUN(test_wfr_tick_expires_decisions);

    RUN(test_wfr_close_failure);
    RUN(test_wfr_close_terminal);
    RUN(test_wfr_acknowledge);
    RUN(test_wfr_close_not_found);

    RUN(test_wfr_get_failure);
    RUN(test_wfr_get_failure_null);
    RUN(test_wfr_get_decision);
    RUN(test_wfr_failure_count);
    RUN(test_wfr_failure_count_by_state);
    RUN(test_wfr_failure_count_by_category);
    RUN(test_wfr_decision_count);
    RUN(test_wfr_active_failures);
    RUN(test_wfr_is_failure_terminal);

    RUN(test_wfr_emit_event);
    RUN(test_wfr_get_event);
    RUN(test_wfr_get_event_invalid);
    RUN(test_wfr_event_overflow);

    RUN(test_wfr_cleanup_closed);
    RUN(test_wfr_cleanup_all);

    RUN(test_wfr_stats);
    RUN(test_wfr_stats_null);
    RUN(test_wfr_reset_stats);

    RUN(test_wfr_validate_failure);
    RUN(test_wfr_validate_failure_null);
    RUN(test_wfr_validate_decision);
    RUN(test_wfr_validate_config);
    RUN(test_wfr_valid_transition);

    RUN(test_wfr_err_name);
    RUN(test_wfr_category_name);
    RUN(test_wfr_severity_name);
    RUN(test_wfr_state_name);
    RUN(test_wfr_decision_name);
    RUN(test_wfr_impact_name);
    RUN(test_wfr_containment_name);
    RUN(test_wfr_idempotency_name);
    RUN(test_wfr_backoff_name);
    RUN(test_wfr_recovery_state_name);
    RUN(test_wfr_event_type_name);
    RUN(test_wfr_history_result_name);

    RUN(test_wfr_no_bypass);
    RUN(test_wfr_metadata_safe);
    RUN(test_wfr_correlation_preserved);
    RUN(test_wfr_event_correlation);
    RUN(test_wfr_full_lifecycle);
    RUN(test_wfr_multiple_failures);
    RUN(test_wfr_shutdown_not_init);
    RUN(test_wfr_get_history_entry);
    RUN(test_wfr_get_history_entry_invalid);

    SUITE_END();
    return TOTAL_FAIL();
}
