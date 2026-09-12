#include "../pipeline.h"
#include "../../tests/test_framework.h"
#include <string.h>
#include <time.h>

/* ============================================================
 * HELPERS
 * ============================================================ */

static ozayn_pco_service_t _svc;
static ozayn_pco_service_config_t _cfg;

static void _reset_all(void) {
    memset(&_svc, 0, sizeof(_svc));
}

static void _init_svc(void) {
    _reset_all();
    memset(&_cfg, 0, sizeof(_cfg));
    ozayn_pco_service_init(&_svc, &_cfg);
}

static void _make_request(ozayn_pco_pipeline_request_t *req) {
    memset(req, 0, sizeof(*req));
    strncpy(req->name, "test-pipeline", OZAYN_PCO_MAX_NAME_LEN);
    strncpy(req->description, "test desc", OZAYN_PCO_MAX_DESCRIPTION_LEN);
    req->type = OZAYN_PCO_PIPELINE_TYPE_LINEAR;
    strncpy(req->requester_ref, "test-user", OZAYN_PCO_MAX_ID_LEN);
    strncpy(req->owner_ref, "test-user", OZAYN_PCO_MAX_ID_LEN);
}

static ozayn_pco_stage_t _make_stage(const char *id,
                                      ozayn_pco_stage_type_t type) {
    ozayn_pco_stage_t s;
    memset(&s, 0, sizeof(s));
    strncpy(s.stage_id, id, OZAYN_PCO_MAX_ID_LEN);
    s.type = type;
    s.state = OZAYN_PCO_STAGE_CREATED;
    s.order = 0;
    s.is_optional = 0;
    return s;
}

static ozayn_pco_edge_t _make_edge(const char *id,
                                    const char *src,
                                    const char *dst) {
    ozayn_pco_edge_t e;
    memset(&e, 0, sizeof(e));
    strncpy(e.edge_id, id, OZAYN_PCO_MAX_ID_LEN);
    strncpy(e.source_stage_id, src, OZAYN_PCO_MAX_ID_LEN);
    strncpy(e.destination_stage_id, dst, OZAYN_PCO_MAX_ID_LEN);
    e.direction = OZAYN_PCO_EDGE_OUTPUT;
    return e;
}

static ozayn_pco_pipeline_t *_create_pipeline(void) {
    ozayn_pco_pipeline_request_t req;
    _make_request(&req);
    ozayn_pco_pipeline_t *p = NULL;
    ozayn_pco_pipeline_create(&_svc, &req, &p);
    return p;
}

static void _add_two_stages_and_edge(ozayn_pco_service_t *svc,
                                      const char *pid) {
    ozayn_pco_stage_t s1 = _make_stage("S1", OZAYN_PCO_STAGE_SOURCE);
    ozayn_pco_stage_t *ps1 = NULL;
    ozayn_pco_stage_add(svc, pid, &s1, &ps1);

    ozayn_pco_stage_t s2 = _make_stage("S2", OZAYN_PCO_STAGE_DESTINATION);
    ozayn_pco_stage_t *ps2 = NULL;
    ozayn_pco_stage_add(svc, pid, &s2, &ps2);

    ozayn_pco_edge_t e = _make_edge("E1", "S1", "S2");
    ozayn_pco_edge_t *pe = NULL;
    ozayn_pco_edge_add(svc, pid, &e, &pe);
}

/* ============================================================
 * LIFECYCLE TESTS
 * ============================================================ */

TEST(test_pco_init) {
    _reset_all();
    memset(&_cfg, 0, sizeof(_cfg));
    ASSERT_EQ(ozayn_pco_service_init(&_svc, &_cfg), OZAYN_PCO_OK);
    ASSERT(ozayn_pco_service_is_initialized(&_svc));
    ozayn_pco_service_shutdown(&_svc);
    return 0;
}

TEST(test_pco_init_null) {
    ASSERT_EQ(ozayn_pco_service_init(NULL, &_cfg), OZAYN_PCO_ERR_NULL);
    return 0;
}

TEST(test_pco_init_null_cfg) {
    _reset_all();
    ASSERT_EQ(ozayn_pco_service_init(&_svc, NULL), OZAYN_PCO_ERR_NULL);
    return 0;
}

TEST(test_pco_init_double) {
    _init_svc();
    ASSERT_EQ(ozayn_pco_service_init(&_svc, &_cfg), OZAYN_PCO_ERR_ALREADY_INIT);
    ozayn_pco_service_shutdown(&_svc);
    return 0;
}

TEST(test_pco_shutdown) {
    _init_svc();
    ozayn_pco_service_shutdown(&_svc);
    ASSERT(!ozayn_pco_service_is_initialized(&_svc));
    return 0;
}

TEST(test_pco_shutdown_null) {
    ozayn_pco_service_shutdown(NULL);
    return 0;
}

TEST(test_pco_is_initialized_null) {
    ASSERT(!ozayn_pco_service_is_initialized(NULL));
    return 0;
}

TEST(test_pco_global) {
    ozayn_pco_service_t *g = ozayn_pco_get_global();
    ASSERT(g != NULL);
    return 0;
}

/* ============================================================
 * PIPELINE CREATION TESTS
 * ============================================================ */

TEST(test_pco_pipeline_create) {
    _init_svc();
    ozayn_pco_pipeline_request_t req;
    _make_request(&req);
    ozayn_pco_pipeline_t *p = NULL;
    ASSERT_EQ(ozayn_pco_pipeline_create(&_svc, &req, &p), OZAYN_PCO_OK);
    ASSERT(p != NULL);
    ASSERT(p->pipeline_id[0] != '\0');
    ASSERT_EQ(p->state, OZAYN_PCO_PIPELINE_CREATED);
    ASSERT_EQ(ozayn_pco_pipeline_count(&_svc), 1);
    ozayn_pco_service_shutdown(&_svc);
    return 0;
}

TEST(test_pco_pipeline_create_null_svc) {
    ASSERT_EQ(ozayn_pco_pipeline_create(NULL, NULL, NULL), OZAYN_PCO_ERR_NULL);
    return 0;
}

TEST(test_pco_pipeline_create_null_req) {
    _init_svc();
    ozayn_pco_pipeline_t *p = NULL;
    ASSERT_EQ(ozayn_pco_pipeline_create(&_svc, NULL, &p), OZAYN_PCO_ERR_NULL);
    ozayn_pco_service_shutdown(&_svc);
    return 0;
}

TEST(test_pco_pipeline_create_null_out) {
    _init_svc();
    ozayn_pco_pipeline_request_t req;
    _make_request(&req);
    ASSERT_EQ(ozayn_pco_pipeline_create(&_svc, &req, NULL), OZAYN_PCO_ERR_NULL);
    ozayn_pco_service_shutdown(&_svc);
    return 0;
}

TEST(test_pco_pipeline_create_no_requester) {
    _init_svc();
    ozayn_pco_pipeline_request_t req;
    _make_request(&req);
    req.requester_ref[0] = '\0';
    ozayn_pco_pipeline_t *p = NULL;
    ASSERT_EQ(ozayn_pco_pipeline_create(&_svc, &req, &p), OZAYN_PCO_ERR_INVALID_PARAM);
    ozayn_pco_service_shutdown(&_svc);
    return 0;
}

TEST(test_pco_pipeline_create_bad_type) {
    _init_svc();
    ozayn_pco_pipeline_request_t req;
    _make_request(&req);
    req.type = OZAYN_PCO_PIPELINE_TYPE_COUNT;
    ozayn_pco_pipeline_t *p = NULL;
    ASSERT_EQ(ozayn_pco_pipeline_create(&_svc, &req, &p), OZAYN_PCO_ERR_INVALID_PARAM);
    ozayn_pco_service_shutdown(&_svc);
    return 0;
}

TEST(test_pco_pipeline_create_duplicate_name) {
    _init_svc();
    ozayn_pco_pipeline_request_t req;
    _make_request(&req);
    ozayn_pco_pipeline_t *p1 = NULL;
    ozayn_pco_pipeline_create(&_svc, &req, &p1);
    ozayn_pco_pipeline_t *p2 = NULL;
    ASSERT_EQ(ozayn_pco_pipeline_create(&_svc, &req, &p2), OZAYN_PCO_ERR_DUPLICATE);
    ozayn_pco_service_shutdown(&_svc);
    return 0;
}

TEST(test_pco_pipeline_create_no_name) {
    _init_svc();
    ozayn_pco_pipeline_request_t req;
    _make_request(&req);
    req.name[0] = '\0';
    ozayn_pco_pipeline_t *p1 = NULL;
    ASSERT_EQ(ozayn_pco_pipeline_create(&_svc, &req, &p1), OZAYN_PCO_OK);
    ozayn_pco_pipeline_t *p2 = NULL;
    ASSERT_EQ(ozayn_pco_pipeline_create(&_svc, &req, &p2), OZAYN_PCO_OK);
    ozayn_pco_service_shutdown(&_svc);
    return 0;
}

TEST(test_pco_pipeline_create_limit) {
    _init_svc();
    for (int i = 0; i < 8; i++) {
        ozayn_pco_pipeline_request_t req;
        _make_request(&req);
        snprintf(req.name, OZAYN_PCO_MAX_NAME_LEN, "PL-%d", i);
        ozayn_pco_pipeline_t *p = NULL;
        ASSERT_EQ(ozayn_pco_pipeline_create(&_svc, &req, &p), OZAYN_PCO_OK);
    }
    ozayn_pco_pipeline_request_t req;
    _make_request(&req);
    ozayn_pco_pipeline_t *p = NULL;
    ASSERT_EQ(ozayn_pco_pipeline_create(&_svc, &req, &p), OZAYN_PCO_ERR_LIMIT_REACHED);
    ozayn_pco_service_shutdown(&_svc);
    return 0;
}

TEST(test_pco_pipeline_metadata) {
    _init_svc();
    ozayn_pco_pipeline_request_t req;
    _make_request(&req);
    strncpy(req.security_session_ref, "SEC-1", OZAYN_PCO_MAX_ID_LEN);
    strncpy(req.authorization_ref, "AUTH-1", OZAYN_PCO_MAX_ID_LEN);
    strncpy(req.safety_decision_ref, "SAFE-1", OZAYN_PCO_MAX_ID_LEN);
    strncpy(req.metadata, "custom-data", OZAYN_PCO_MAX_METADATA_LEN);
    ozayn_pco_pipeline_t *p = NULL;
    ASSERT_EQ(ozayn_pco_pipeline_create(&_svc, &req, &p), OZAYN_PCO_OK);
    ASSERT(strcmp(p->security_session_ref, "SEC-1") == 0);
    ASSERT(strcmp(p->authorization_ref, "AUTH-1") == 0);
    ASSERT(strcmp(p->safety_decision_ref, "SAFE-1") == 0);
    ASSERT(strcmp(p->metadata, "custom-data") == 0);
    ozayn_pco_service_shutdown(&_svc);
    return 0;
}

/* ============================================================
 * STAGE TESTS
 * ============================================================ */

TEST(test_pco_stage_add) {
    _init_svc();
    ozayn_pco_pipeline_t *p = _create_pipeline();
    ozayn_pco_stage_t s = _make_stage("S1", OZAYN_PCO_STAGE_SOURCE);
    ozayn_pco_stage_t *ps = NULL;
    ASSERT_EQ(ozayn_pco_stage_add(&_svc, p->pipeline_id, &s, &ps), OZAYN_PCO_OK);
    ASSERT(ps != NULL);
    ASSERT_EQ(ozayn_pco_stage_count(&_svc, p->pipeline_id), 1);
    ozayn_pco_service_shutdown(&_svc);
    return 0;
}

TEST(test_pco_stage_add_null) {
    _init_svc();
    ASSERT_EQ(ozayn_pco_stage_add(&_svc, NULL, NULL, NULL), OZAYN_PCO_ERR_INVALID_PARAM);
    ozayn_pco_service_shutdown(&_svc);
    return 0;
}

TEST(test_pco_stage_add_no_pipeline) {
    _init_svc();
    ozayn_pco_stage_t s = _make_stage("S1", OZAYN_PCO_STAGE_SOURCE);
    ozayn_pco_stage_t *ps = NULL;
    ASSERT_EQ(ozayn_pco_stage_add(&_svc, "NOPE", &s, &ps), OZAYN_PCO_ERR_NOT_FOUND);
    ozayn_pco_service_shutdown(&_svc);
    return 0;
}

TEST(test_pco_stage_add_bad_type) {
    _init_svc();
    ozayn_pco_pipeline_t *p = _create_pipeline();
    ozayn_pco_stage_t s = _make_stage("S1", OZAYN_PCO_STAGE_COUNT);
    ozayn_pco_stage_t *ps = NULL;
    ASSERT_EQ(ozayn_pco_stage_add(&_svc, p->pipeline_id, &s, &ps), OZAYN_PCO_ERR_INVALID_PARAM);
    ozayn_pco_service_shutdown(&_svc);
    return 0;
}

TEST(test_pco_stage_add_duplicate) {
    _init_svc();
    ozayn_pco_pipeline_t *p = _create_pipeline();
    ozayn_pco_stage_t s = _make_stage("S1", OZAYN_PCO_STAGE_SOURCE);
    ozayn_pco_stage_t *ps1 = NULL;
    ozayn_pco_stage_add(&_svc, p->pipeline_id, &s, &ps1);
    ozayn_pco_stage_t *ps2 = NULL;
    ASSERT_EQ(ozayn_pco_stage_add(&_svc, p->pipeline_id, &s, &ps2), OZAYN_PCO_ERR_DUPLICATE);
    ozayn_pco_service_shutdown(&_svc);
    return 0;
}

TEST(test_pco_stage_get) {
    _init_svc();
    ozayn_pco_pipeline_t *p = _create_pipeline();
    ozayn_pco_stage_t s = _make_stage("S1", OZAYN_PCO_STAGE_SOURCE);
    ozayn_pco_stage_t *ps = NULL;
    ozayn_pco_stage_add(&_svc, p->pipeline_id, &s, &ps);
    const ozayn_pco_stage_t *found = NULL;
    ASSERT_EQ(ozayn_pco_stage_get(&_svc, p->pipeline_id, "S1", &found), OZAYN_PCO_OK);
    ASSERT(found != NULL);
    ASSERT(strcmp(found->stage_id, "S1") == 0);
    ozayn_pco_service_shutdown(&_svc);
    return 0;
}

TEST(test_pco_stage_get_not_found) {
    _init_svc();
    ozayn_pco_pipeline_t *p = _create_pipeline();
    const ozayn_pco_stage_t *found = NULL;
    ASSERT_EQ(ozayn_pco_stage_get(&_svc, p->pipeline_id, "NOPE", &found), OZAYN_PCO_ERR_NOT_FOUND);
    ozayn_pco_service_shutdown(&_svc);
    return 0;
}

TEST(test_pco_stage_remove) {
    _init_svc();
    ozayn_pco_pipeline_t *p = _create_pipeline();
    ozayn_pco_stage_t s = _make_stage("S1", OZAYN_PCO_STAGE_SOURCE);
    ozayn_pco_stage_t *ps = NULL;
    ozayn_pco_stage_add(&_svc, p->pipeline_id, &s, &ps);
    ASSERT_EQ(ozayn_pco_stage_remove(&_svc, p->pipeline_id, "S1"), OZAYN_PCO_OK);
    ASSERT_EQ(ozayn_pco_stage_count(&_svc, p->pipeline_id), 0);
    ozayn_pco_service_shutdown(&_svc);
    return 0;
}

TEST(test_pco_stage_count) {
    _init_svc();
    ozayn_pco_pipeline_t *p = _create_pipeline();
    ASSERT_EQ(ozayn_pco_stage_count(&_svc, p->pipeline_id), 0);
    ozayn_pco_stage_t s = _make_stage("S1", OZAYN_PCO_STAGE_SOURCE);
    ozayn_pco_stage_t *ps = NULL;
    ozayn_pco_stage_add(&_svc, p->pipeline_id, &s, &ps);
    ASSERT_EQ(ozayn_pco_stage_count(&_svc, p->pipeline_id), 1);
    ozayn_pco_service_shutdown(&_svc);
    return 0;
}

TEST(test_pco_stages_for_pipeline) {
    _init_svc();
    ozayn_pco_pipeline_t *p = _create_pipeline();
    ozayn_pco_stage_t s1 = _make_stage("S1", OZAYN_PCO_STAGE_SOURCE);
    ozayn_pco_stage_t *ps1 = NULL;
    ozayn_pco_stage_add(&_svc, p->pipeline_id, &s1, &ps1);
    ozayn_pco_stage_t s2 = _make_stage("S2", OZAYN_PCO_STAGE_DESTINATION);
    ozayn_pco_stage_t *ps2 = NULL;
    ozayn_pco_stage_add(&_svc, p->pipeline_id, &s2, &ps2);
    ozayn_pco_stage_t *buf[8];
    int n = ozayn_pco_stages_for_pipeline(&_svc, p->pipeline_id, buf, 8);
    ASSERT_EQ(n, 2);
    ozayn_pco_service_shutdown(&_svc);
    return 0;
}

/* ============================================================
 * EDGE TESTS
 * ============================================================ */

TEST(test_pco_edge_add) {
    _init_svc();
    ozayn_pco_pipeline_t *p = _create_pipeline();
    _add_two_stages_and_edge(&_svc, p->pipeline_id);
    ASSERT_EQ(ozayn_pco_edge_count(&_svc, p->pipeline_id), 1);
    ozayn_pco_service_shutdown(&_svc);
    return 0;
}

TEST(test_pco_edge_add_null) {
    _init_svc();
    ASSERT_EQ(ozayn_pco_edge_add(&_svc, NULL, NULL, NULL), OZAYN_PCO_ERR_INVALID_PARAM);
    ozayn_pco_service_shutdown(&_svc);
    return 0;
}

TEST(test_pco_edge_add_no_pipeline) {
    _init_svc();
    ozayn_pco_edge_t e = _make_edge("E1", "S1", "S2");
    ozayn_pco_edge_t *pe = NULL;
    ASSERT_EQ(ozayn_pco_edge_add(&_svc, "NOPE", &e, &pe), OZAYN_PCO_ERR_NOT_FOUND);
    ozayn_pco_service_shutdown(&_svc);
    return 0;
}

TEST(test_pco_edge_add_missing_source) {
    _init_svc();
    ozayn_pco_pipeline_t *p = _create_pipeline();
    ozayn_pco_stage_t s2 = _make_stage("S2", OZAYN_PCO_STAGE_DESTINATION);
    ozayn_pco_stage_t *ps2 = NULL;
    ozayn_pco_stage_add(&_svc, p->pipeline_id, &s2, &ps2);
    ozayn_pco_edge_t e = _make_edge("E1", "NOPE", "S2");
    ozayn_pco_edge_t *pe = NULL;
    ASSERT_EQ(ozayn_pco_edge_add(&_svc, p->pipeline_id, &e, &pe), OZAYN_PCO_ERR_STAGE_NOT_FOUND);
    ozayn_pco_service_shutdown(&_svc);
    return 0;
}

TEST(test_pco_edge_add_self_loop) {
    _init_svc();
    ozayn_pco_pipeline_t *p = _create_pipeline();
    ozayn_pco_stage_t s = _make_stage("S1", OZAYN_PCO_STAGE_SOURCE);
    ozayn_pco_stage_t *ps = NULL;
    ozayn_pco_stage_add(&_svc, p->pipeline_id, &s, &ps);
    ozayn_pco_edge_t e = _make_edge("E1", "S1", "S1");
    ozayn_pco_edge_t *pe = NULL;
    ASSERT_EQ(ozayn_pco_edge_add(&_svc, p->pipeline_id, &e, &pe), OZAYN_PCO_ERR_GRAPH_INVALID);
    ozayn_pco_service_shutdown(&_svc);
    return 0;
}

TEST(test_pco_edge_get) {
    _init_svc();
    ozayn_pco_pipeline_t *p = _create_pipeline();
    _add_two_stages_and_edge(&_svc, p->pipeline_id);
    const ozayn_pco_edge_t *found = NULL;
    ASSERT_EQ(ozayn_pco_edge_get(&_svc, p->pipeline_id, "E1", &found), OZAYN_PCO_OK);
    ASSERT(found != NULL);
    ozayn_pco_service_shutdown(&_svc);
    return 0;
}

TEST(test_pco_edge_remove) {
    _init_svc();
    ozayn_pco_pipeline_t *p = _create_pipeline();
    _add_two_stages_and_edge(&_svc, p->pipeline_id);
    ASSERT_EQ(ozayn_pco_edge_remove(&_svc, p->pipeline_id, "E1"), OZAYN_PCO_OK);
    ASSERT_EQ(ozayn_pco_edge_count(&_svc, p->pipeline_id), 0);
    ozayn_pco_service_shutdown(&_svc);
    return 0;
}

TEST(test_pco_edge_count) {
    _init_svc();
    ozayn_pco_pipeline_t *p = _create_pipeline();
    ASSERT_EQ(ozayn_pco_edge_count(&_svc, p->pipeline_id), 0);
    _add_two_stages_and_edge(&_svc, p->pipeline_id);
    ASSERT_EQ(ozayn_pco_edge_count(&_svc, p->pipeline_id), 1);
    ozayn_pco_service_shutdown(&_svc);
    return 0;
}

/* ============================================================
 * GRAPH VALIDATION TESTS
 * ============================================================ */

TEST(test_pco_graph_validate_valid) {
    _init_svc();
    ozayn_pco_pipeline_t *p = _create_pipeline();
    _add_two_stages_and_edge(&_svc, p->pipeline_id);
    ASSERT_EQ(ozayn_pco_graph_validate(&_svc, p->pipeline_id), OZAYN_PCO_OK);
    ozayn_pco_service_shutdown(&_svc);
    return 0;
}

TEST(test_pco_graph_validate_no_stages) {
    _init_svc();
    ozayn_pco_pipeline_t *p = _create_pipeline();
    ASSERT_EQ(ozayn_pco_graph_validate(&_svc, p->pipeline_id), OZAYN_PCO_OK);
    ozayn_pco_service_shutdown(&_svc);
    return 0;
}

TEST(test_pco_graph_check_cycle) {
    _init_svc();
    ozayn_pco_pipeline_t *p = _create_pipeline();
    ASSERT_EQ(ozayn_pco_graph_check_cycle(&_svc, p->pipeline_id), OZAYN_PCO_OK);
    ozayn_pco_service_shutdown(&_svc);
    return 0;
}

TEST(test_pco_graph_validate_null) {
    ASSERT_EQ(ozayn_pco_graph_validate(NULL, NULL), OZAYN_PCO_ERR_NULL);
    return 0;
}

TEST(test_pco_graph_check_cycle_null) {
    ASSERT_EQ(ozayn_pco_graph_check_cycle(NULL, NULL), OZAYN_PCO_ERR_NULL);
    return 0;
}

/* ============================================================
 * PIPELINE VALIDATION TESTS
 * ============================================================ */

TEST(test_pco_pipeline_validate) {
    _init_svc();
    ozayn_pco_pipeline_t *p = _create_pipeline();
    _add_two_stages_and_edge(&_svc, p->pipeline_id);
    ASSERT_EQ(ozayn_pco_pipeline_validate(&_svc, p->pipeline_id), OZAYN_PCO_OK);
    ASSERT_EQ(p->state, OZAYN_PCO_PIPELINE_AUTHORIZED);
    ozayn_pco_service_shutdown(&_svc);
    return 0;
}

TEST(test_pco_pipeline_validate_no_stages) {
    _init_svc();
    ozayn_pco_pipeline_t *p = _create_pipeline();
    ASSERT_EQ(ozayn_pco_pipeline_validate(&_svc, p->pipeline_id), OZAYN_PCO_ERR_GRAPH_INVALID);
    ASSERT_EQ(p->state, OZAYN_PCO_PIPELINE_FAILED);
    ozayn_pco_service_shutdown(&_svc);
    return 0;
}

TEST(test_pco_pipeline_validate_null_id) {
    _init_svc();
    ASSERT_EQ(ozayn_pco_pipeline_validate(&_svc, NULL), OZAYN_PCO_ERR_INVALID_PARAM);
    ASSERT_EQ(ozayn_pco_pipeline_validate(&_svc, ""), OZAYN_PCO_ERR_INVALID_PARAM);
    ozayn_pco_service_shutdown(&_svc);
    return 0;
}

TEST(test_pco_pipeline_validate_not_found) {
    _init_svc();
    ASSERT_EQ(ozayn_pco_pipeline_validate(&_svc, "NOPE"), OZAYN_PCO_ERR_NOT_FOUND);
    ozayn_pco_service_shutdown(&_svc);
    return 0;
}

TEST(test_pco_pipeline_validate_expired) {
    _init_svc();
    ozayn_pco_pipeline_t *p = _create_pipeline();
    p->expiry_time = time(NULL) - 1;
    ASSERT_EQ(ozayn_pco_pipeline_validate(&_svc, p->pipeline_id), OZAYN_PCO_ERR_EXPIRED);
    ASSERT_EQ(p->state, OZAYN_PCO_PIPELINE_EXPIRED);
    ozayn_pco_service_shutdown(&_svc);
    return 0;
}

TEST(test_pco_pipeline_authorize) {
    _init_svc();
    ozayn_pco_pipeline_t *p = _create_pipeline();
    _add_two_stages_and_edge(&_svc, p->pipeline_id);
    ASSERT_EQ(ozayn_pco_pipeline_authorize(&_svc, p->pipeline_id), OZAYN_PCO_OK);
    ASSERT_EQ(p->state, OZAYN_PCO_PIPELINE_AUTHORIZED);
    ozayn_pco_service_shutdown(&_svc);
    return 0;
}

/* ============================================================
 * PIPELINE START TESTS
 * ============================================================ */

TEST(test_pco_pipeline_start) {
    _init_svc();
    ozayn_pco_pipeline_t *p = _create_pipeline();
    _add_two_stages_and_edge(&_svc, p->pipeline_id);
    ozayn_pco_pipeline_validate(&_svc, p->pipeline_id);
    ASSERT_EQ(ozayn_pco_pipeline_start(&_svc, p->pipeline_id), OZAYN_PCO_OK);
    ASSERT_EQ(p->state, OZAYN_PCO_PIPELINE_ACTIVE);
    ASSERT(p->activation_time > 0);
    ozayn_pco_service_shutdown(&_svc);
    return 0;
}

TEST(test_pco_pipeline_start_not_found) {
    _init_svc();
    ASSERT_EQ(ozayn_pco_pipeline_start(&_svc, "NOPE"), OZAYN_PCO_ERR_NOT_FOUND);
    ozayn_pco_service_shutdown(&_svc);
    return 0;
}

TEST(test_pco_pipeline_start_null) {
    ASSERT_EQ(ozayn_pco_pipeline_start(NULL, NULL), OZAYN_PCO_ERR_NULL);
    return 0;
}

TEST(test_pco_pipeline_start_null_id) {
    _init_svc();
    ASSERT_EQ(ozayn_pco_pipeline_start(&_svc, NULL), OZAYN_PCO_ERR_INVALID_PARAM);
    ASSERT_EQ(ozayn_pco_pipeline_start(&_svc, ""), OZAYN_PCO_ERR_INVALID_PARAM);
    ozayn_pco_service_shutdown(&_svc);
    return 0;
}

/* ============================================================
 * PAUSE / RESUME TESTS
 * ============================================================ */

TEST(test_pco_pipeline_pause) {
    _init_svc();
    ozayn_pco_pipeline_t *p = _create_pipeline();
    _add_two_stages_and_edge(&_svc, p->pipeline_id);
    ozayn_pco_pipeline_validate(&_svc, p->pipeline_id);
    ozayn_pco_pipeline_start(&_svc, p->pipeline_id);
    ASSERT_EQ(ozayn_pco_pipeline_pause(&_svc, p->pipeline_id), OZAYN_PCO_OK);
    ASSERT_EQ(p->state, OZAYN_PCO_PIPELINE_PAUSED);
    ozayn_pco_service_shutdown(&_svc);
    return 0;
}

TEST(test_pco_pipeline_pause_not_active) {
    _init_svc();
    ozayn_pco_pipeline_t *p = _create_pipeline();
    ASSERT_EQ(ozayn_pco_pipeline_pause(&_svc, p->pipeline_id), OZAYN_PCO_ERR_PAUSE_FAILED);
    ozayn_pco_service_shutdown(&_svc);
    return 0;
}

TEST(test_pco_pipeline_resume) {
    _init_svc();
    ozayn_pco_pipeline_t *p = _create_pipeline();
    _add_two_stages_and_edge(&_svc, p->pipeline_id);
    ozayn_pco_pipeline_validate(&_svc, p->pipeline_id);
    ozayn_pco_pipeline_start(&_svc, p->pipeline_id);
    ozayn_pco_pipeline_pause(&_svc, p->pipeline_id);
    ASSERT_EQ(ozayn_pco_pipeline_resume(&_svc, p->pipeline_id), OZAYN_PCO_OK);
    ASSERT_EQ(p->state, OZAYN_PCO_PIPELINE_ACTIVE);
    ozayn_pco_service_shutdown(&_svc);
    return 0;
}

TEST(test_pco_pipeline_resume_not_paused) {
    _init_svc();
    ozayn_pco_pipeline_t *p = _create_pipeline();
    ASSERT_EQ(ozayn_pco_pipeline_resume(&_svc, p->pipeline_id), OZAYN_PCO_ERR_RESUME_FAILED);
    ozayn_pco_service_shutdown(&_svc);
    return 0;
}

/* ============================================================
 * DRAIN / STOP TESTS
 * ============================================================ */

TEST(test_pco_pipeline_drain) {
    _init_svc();
    ozayn_pco_pipeline_t *p = _create_pipeline();
    _add_two_stages_and_edge(&_svc, p->pipeline_id);
    ozayn_pco_pipeline_validate(&_svc, p->pipeline_id);
    ozayn_pco_pipeline_start(&_svc, p->pipeline_id);
    ASSERT_EQ(ozayn_pco_pipeline_drain(&_svc, p->pipeline_id), OZAYN_PCO_OK);
    ASSERT_EQ(p->state, OZAYN_PCO_PIPELINE_DRAINING);
    ASSERT_EQ(p->flow_state, OZAYN_PCO_FLOW_DRAINING);
    ozayn_pco_service_shutdown(&_svc);
    return 0;
}

TEST(test_pco_pipeline_drain_not_active) {
    _init_svc();
    ozayn_pco_pipeline_t *p = _create_pipeline();
    ASSERT_EQ(ozayn_pco_pipeline_drain(&_svc, p->pipeline_id), OZAYN_PCO_ERR_DRAIN_FAILED);
    ozayn_pco_service_shutdown(&_svc);
    return 0;
}

TEST(test_pco_pipeline_stop) {
    _init_svc();
    ozayn_pco_pipeline_t *p = _create_pipeline();
    _add_two_stages_and_edge(&_svc, p->pipeline_id);
    ozayn_pco_pipeline_start(&_svc, p->pipeline_id);
    ASSERT_EQ(ozayn_pco_pipeline_stop(&_svc, p->pipeline_id), OZAYN_PCO_OK);
    ASSERT_EQ(p->state, OZAYN_PCO_PIPELINE_STOPPED);
    ASSERT(p->active == 0);
    ozayn_pco_service_shutdown(&_svc);
    return 0;
}

TEST(test_pco_pipeline_stop_terminal) {
    _init_svc();
    ozayn_pco_pipeline_t *p = _create_pipeline();
    p->state = OZAYN_PCO_PIPELINE_STOPPED;
    ASSERT_EQ(ozayn_pco_pipeline_stop(&_svc, p->pipeline_id), OZAYN_PCO_ERR_STATE_INVALID);
    ozayn_pco_service_shutdown(&_svc);
    return 0;
}

TEST(test_pco_pipeline_cancel) {
    _init_svc();
    ozayn_pco_pipeline_t *p = _create_pipeline();
    _add_two_stages_and_edge(&_svc, p->pipeline_id);
    ASSERT_EQ(ozayn_pco_pipeline_cancel(&_svc, p->pipeline_id), OZAYN_PCO_OK);
    ASSERT_EQ(p->state, OZAYN_PCO_PIPELINE_CANCELLED);
    ozayn_pco_service_shutdown(&_svc);
    return 0;
}

TEST(test_pco_pipeline_cancel_terminal) {
    _init_svc();
    ozayn_pco_pipeline_t *p = _create_pipeline();
    p->state = OZAYN_PCO_PIPELINE_FAILED;
    ASSERT_EQ(ozayn_pco_pipeline_cancel(&_svc, p->pipeline_id), OZAYN_PCO_ERR_STATE_INVALID);
    ozayn_pco_service_shutdown(&_svc);
    return 0;
}

TEST(test_pco_pipeline_close) {
    _init_svc();
    ozayn_pco_pipeline_t *p = _create_pipeline();
    _add_two_stages_and_edge(&_svc, p->pipeline_id);
    ozayn_pco_pipeline_start(&_svc, p->pipeline_id);
    ASSERT_EQ(ozayn_pco_pipeline_close(&_svc, p->pipeline_id,
        OZAYN_PCO_CLOSE_MANUAL_STOP), OZAYN_PCO_OK);
    ASSERT_EQ(p->state, OZAYN_PCO_PIPELINE_STOPPED);
    ASSERT_EQ(p->close_reason, OZAYN_PCO_CLOSE_MANUAL_STOP);
    ozayn_pco_service_shutdown(&_svc);
    return 0;
}

TEST(test_pco_pipeline_revoke) {
    _init_svc();
    ozayn_pco_pipeline_t *p = _create_pipeline();
    _add_two_stages_and_edge(&_svc, p->pipeline_id);
    ozayn_pco_pipeline_start(&_svc, p->pipeline_id);
    ASSERT_EQ(ozayn_pco_pipeline_revoke(&_svc, p->pipeline_id,
        OZAYN_PCO_CLOSE_AUTHORIZATION_REVOKED), OZAYN_PCO_OK);
    ASSERT_EQ(p->state, OZAYN_PCO_PIPELINE_REVOKED);
    ASSERT_EQ(p->close_reason, OZAYN_PCO_CLOSE_AUTHORIZATION_REVOKED);
    ozayn_pco_service_shutdown(&_svc);
    return 0;
}

TEST(test_pco_pipeline_remove) {
    _init_svc();
    ozayn_pco_pipeline_t *p = _create_pipeline();
    _add_two_stages_and_edge(&_svc, p->pipeline_id);
    ASSERT_EQ(ozayn_pco_pipeline_remove(&_svc, p->pipeline_id), OZAYN_PCO_OK);
    ASSERT(ozayn_pco_pipeline_get(&_svc, p->pipeline_id) == NULL);
    ozayn_pco_service_shutdown(&_svc);
    return 0;
}

/* ============================================================
 * FULL LIFECYCLE TEST
 * ============================================================ */

TEST(test_pco_pipeline_full_lifecycle) {
    _init_svc();
    ozayn_pco_pipeline_t *p = _create_pipeline();
    _add_two_stages_and_edge(&_svc, p->pipeline_id);
    ASSERT_EQ(p->state, OZAYN_PCO_PIPELINE_CREATED);

    ASSERT_EQ(ozayn_pco_pipeline_validate(&_svc, p->pipeline_id), OZAYN_PCO_OK);
    ASSERT_EQ(p->state, OZAYN_PCO_PIPELINE_AUTHORIZED);

    ASSERT_EQ(ozayn_pco_pipeline_start(&_svc, p->pipeline_id), OZAYN_PCO_OK);
    ASSERT_EQ(p->state, OZAYN_PCO_PIPELINE_ACTIVE);

    ASSERT_EQ(ozayn_pco_pipeline_pause(&_svc, p->pipeline_id), OZAYN_PCO_OK);
    ASSERT_EQ(p->state, OZAYN_PCO_PIPELINE_PAUSED);

    ASSERT_EQ(ozayn_pco_pipeline_resume(&_svc, p->pipeline_id), OZAYN_PCO_OK);
    ASSERT_EQ(p->state, OZAYN_PCO_PIPELINE_ACTIVE);

    ASSERT_EQ(ozayn_pco_pipeline_drain(&_svc, p->pipeline_id), OZAYN_PCO_OK);
    ASSERT_EQ(p->state, OZAYN_PCO_PIPELINE_DRAINING);

    ASSERT_EQ(ozayn_pco_pipeline_stop(&_svc, p->pipeline_id), OZAYN_PCO_OK);
    ASSERT_EQ(p->state, OZAYN_PCO_PIPELINE_STOPPED);

    ozayn_pco_service_shutdown(&_svc);
    return 0;
}

/* ============================================================
 * QUERY TESTS
 * ============================================================ */

TEST(test_pco_pipeline_get) {
    _init_svc();
    ozayn_pco_pipeline_t *p = _create_pipeline();
    ASSERT(ozayn_pco_pipeline_get(&_svc, p->pipeline_id) != NULL);
    ASSERT(ozayn_pco_pipeline_get(&_svc, "NOPE") == NULL);
    ozayn_pco_service_shutdown(&_svc);
    return 0;
}

TEST(test_pco_pipeline_get_by_name) {
    _init_svc();
    ozayn_pco_pipeline_t *p = _create_pipeline();
    ASSERT(ozayn_pco_pipeline_get_by_name(&_svc, "test-pipeline") != NULL);
    ASSERT(ozayn_pco_pipeline_get_by_name(&_svc, "nope") == NULL);
    ozayn_pco_service_shutdown(&_svc);
    return 0;
}

TEST(test_pco_pipeline_count) {
    _init_svc();
    ASSERT_EQ(ozayn_pco_pipeline_count(&_svc), 0);
    _create_pipeline();
    ASSERT_EQ(ozayn_pco_pipeline_count(&_svc), 1);
    ozayn_pco_service_shutdown(&_svc);
    return 0;
}

TEST(test_pco_pipeline_count_by_state) {
    _init_svc();
    _create_pipeline();
    ASSERT_EQ(ozayn_pco_pipeline_count_by_state(&_svc, OZAYN_PCO_PIPELINE_CREATED), 1);
    ASSERT_EQ(ozayn_pco_pipeline_count_by_state(&_svc, OZAYN_PCO_PIPELINE_ACTIVE), 0);
    ozayn_pco_service_shutdown(&_svc);
    return 0;
}

TEST(test_pco_pipeline_is_active) {
    _init_svc();
    ozayn_pco_pipeline_t *p = _create_pipeline();
    ASSERT(!ozayn_pco_pipeline_is_active(&_svc, p->pipeline_id));
    _add_two_stages_and_edge(&_svc, p->pipeline_id);
    ozayn_pco_pipeline_validate(&_svc, p->pipeline_id);
    ozayn_pco_pipeline_start(&_svc, p->pipeline_id);
    ASSERT(ozayn_pco_pipeline_is_active(&_svc, p->pipeline_id));
    ozayn_pco_service_shutdown(&_svc);
    return 0;
}

/* ============================================================
 * HEALTH TESTS
 * ============================================================ */

TEST(test_pco_health_get) {
    _init_svc();
    ozayn_pco_pipeline_t *p = _create_pipeline();
    _add_two_stages_and_edge(&_svc, p->pipeline_id);
    int h = 0, d = 0, f = 0;
    ASSERT_EQ(ozayn_pco_health_get(&_svc, p->pipeline_id, &h, &d, &f), OZAYN_PCO_OK);
    ASSERT(h >= 0);
    ASSERT(d >= 0);
    ASSERT(f >= 0);
    ozayn_pco_service_shutdown(&_svc);
    return 0;
}

TEST(test_pco_health_get_not_found) {
    _init_svc();
    int h = 0, d = 0, f = 0;
    ASSERT_EQ(ozayn_pco_health_get(&_svc, "NOPE", &h, &d, &f), OZAYN_PCO_ERR_NOT_FOUND);
    ozayn_pco_service_shutdown(&_svc);
    return 0;
}

TEST(test_pco_health_get_null) {
    int h = 0, d = 0, f = 0;
    ASSERT_EQ(ozayn_pco_health_get(NULL, NULL, &h, &d, &f), OZAYN_PCO_ERR_NULL);
    return 0;
}

/* ============================================================
 * FLOW CONTROL TESTS
 * ============================================================ */

TEST(test_pco_flow_get_state) {
    _init_svc();
    ozayn_pco_pipeline_t *p = _create_pipeline();
    ozayn_pco_flow_state_t fs;
    ASSERT_EQ(ozayn_pco_flow_get_state(&_svc, p->pipeline_id, &fs), OZAYN_PCO_OK);
    ASSERT_EQ(fs, OZAYN_PCO_FLOW_NORMAL);
    ozayn_pco_service_shutdown(&_svc);
    return 0;
}

TEST(test_pco_flow_set_state) {
    _init_svc();
    ozayn_pco_pipeline_t *p = _create_pipeline();
    ASSERT_EQ(ozayn_pco_flow_set_state(&_svc, p->pipeline_id, OZAYN_PCO_FLOW_THROTTLED), OZAYN_PCO_OK);
    ASSERT_EQ(p->flow_state, OZAYN_PCO_FLOW_THROTTLED);
    ozayn_pco_service_shutdown(&_svc);
    return 0;
}

TEST(test_pco_flow_set_backpressured) {
    _init_svc();
    ozayn_pco_pipeline_t *p = _create_pipeline();
    ASSERT_EQ(ozayn_pco_flow_set_state(&_svc, p->pipeline_id, OZAYN_PCO_FLOW_BACKPRESSURED), OZAYN_PCO_OK);
    ASSERT_EQ(p->flow_state, OZAYN_PCO_FLOW_BACKPRESSURED);
    ozayn_pco_service_shutdown(&_svc);
    return 0;
}

TEST(test_pco_flow_is_blocked) {
    _init_svc();
    ozayn_pco_pipeline_t *p = _create_pipeline();
    ASSERT(!ozayn_pco_flow_is_blocked(&_svc, p->pipeline_id));
    ozayn_pco_flow_set_state(&_svc, p->pipeline_id, OZAYN_PCO_FLOW_BLOCKED);
    ASSERT(ozayn_pco_flow_is_blocked(&_svc, p->pipeline_id));
    ozayn_pco_service_shutdown(&_svc);
    return 0;
}

TEST(test_pco_flow_is_backpressured) {
    _init_svc();
    ozayn_pco_pipeline_t *p = _create_pipeline();
    ASSERT(!ozayn_pco_flow_is_backpressured(&_svc, p->pipeline_id));
    ozayn_pco_flow_set_state(&_svc, p->pipeline_id, OZAYN_PCO_FLOW_BACKPRESSURED);
    ASSERT(ozayn_pco_flow_is_backpressured(&_svc, p->pipeline_id));
    ozayn_pco_service_shutdown(&_svc);
    return 0;
}

TEST(test_pco_flow_set_state_null) {
    ASSERT_EQ(ozayn_pco_flow_set_state(NULL, NULL, 0), OZAYN_PCO_ERR_NULL);
    return 0;
}

TEST(test_pco_flow_get_state_null) {
    ozayn_pco_flow_state_t fs;
    ASSERT_EQ(ozayn_pco_flow_get_state(NULL, NULL, &fs), OZAYN_PCO_ERR_NULL);
    return 0;
}

/* ============================================================
 * SYNCHRONIZATION TESTS
 * ============================================================ */

TEST(test_pco_sync_check_stage) {
    _init_svc();
    ozayn_pco_pipeline_t *p = _create_pipeline();
    ozayn_pco_stage_t s = _make_stage("S1", OZAYN_PCO_STAGE_SOURCE);
    ozayn_pco_stage_t *ps = NULL;
    ozayn_pco_stage_add(&_svc, p->pipeline_id, &s, &ps);
    ASSERT_EQ(ozayn_pco_sync_check_stage(&_svc, p->pipeline_id, "S1"), OZAYN_PCO_OK);
    ozayn_pco_service_shutdown(&_svc);
    return 0;
}

TEST(test_pco_sync_check_stage_not_found) {
    _init_svc();
    ozayn_pco_pipeline_t *p = _create_pipeline();
    ASSERT_EQ(ozayn_pco_sync_check_stage(&_svc, p->pipeline_id, "NOPE"), OZAYN_PCO_ERR_NOT_FOUND);
    ozayn_pco_service_shutdown(&_svc);
    return 0;
}

TEST(test_pco_sync_all_stages_ready) {
    _init_svc();
    ozayn_pco_pipeline_t *p = _create_pipeline();
    _add_two_stages_and_edge(&_svc, p->pipeline_id);
    ASSERT(!ozayn_pco_sync_all_stages_ready(&_svc, p->pipeline_id));
    ozayn_pco_service_shutdown(&_svc);
    return 0;
}

TEST(test_pco_sync_advance_stage) {
    _init_svc();
    ozayn_pco_pipeline_t *p = _create_pipeline();
    ozayn_pco_stage_t s = _make_stage("S1", OZAYN_PCO_STAGE_SOURCE);
    ozayn_pco_stage_t *ps = NULL;
    ozayn_pco_stage_add(&_svc, p->pipeline_id, &s, &ps);
    ASSERT_EQ(ozayn_pco_sync_advance_stage(&_svc, p->pipeline_id, "S1"), OZAYN_PCO_OK);
    ozayn_pco_service_shutdown(&_svc);
    return 0;
}

/* ============================================================
 * EVENTS TESTS
 * ============================================================ */

TEST(test_pco_event_emit) {
    _init_svc();
    ASSERT_EQ(ozayn_pco_emit_event(&_svc, OZAYN_PCO_EVENT_PIPELINE_CREATED,
        "P-1", "S-1", "R-1", "STR-1", "test event"), OZAYN_PCO_OK);
    ASSERT_EQ(ozayn_pco_event_count(&_svc), 1);
    const ozayn_pco_event_t *e = ozayn_pco_event_get(&_svc, 0);
    ASSERT(e != NULL);
    ASSERT_EQ(e->type, OZAYN_PCO_EVENT_PIPELINE_CREATED);
    ASSERT(strcmp(e->pipeline_id, "P-1") == 0);
    ASSERT(strcmp(e->stage_id, "S-1") == 0);
    ASSERT(strcmp(e->route_id, "R-1") == 0);
    ASSERT(strcmp(e->stream_id, "STR-1") == 0);
    ASSERT(strcmp(e->message, "test event") == 0);
    ozayn_pco_service_shutdown(&_svc);
    return 0;
}

TEST(test_pco_event_overflow) {
    _init_svc();
    for (int i = 0; i < 70; i++) {
        ozayn_pco_emit_event(&_svc, OZAYN_PCO_EVENT_PIPELINE_CREATED,
            "P", "S", "R", "STR", "msg");
    }
    ASSERT(ozayn_pco_event_count(&_svc) <= OZAYN_PCO_MAX_EVENTS);
    ozayn_pco_service_shutdown(&_svc);
    return 0;
}

TEST(test_pco_event_get_invalid) {
    _init_svc();
    ASSERT(ozayn_pco_event_get(&_svc, 0) == NULL);
    ASSERT(ozayn_pco_event_get(&_svc, -1) == NULL);
    ozayn_pco_service_shutdown(&_svc);
    return 0;
}

/* ============================================================
 * CLEANUP TESTS
 * ============================================================ */

TEST(test_pco_cleanup_expired) {
    _init_svc();
    ozayn_pco_pipeline_t *p = _create_pipeline();
    p->expiry_time = time(NULL) - 1;
    int cleaned = ozayn_pco_cleanup_expired_pipelines(&_svc);
    ASSERT_GE(cleaned, 1);
    ozayn_pco_service_shutdown(&_svc);
    return 0;
}

TEST(test_pco_cleanup_stopped) {
    _init_svc();
    ozayn_pco_pipeline_t *p = _create_pipeline();
    p->state = OZAYN_PCO_PIPELINE_STOPPED;
    p->active = 0;
    _svc.pipeline_count--;
    int cleaned = ozayn_pco_cleanup_stopped_pipelines(&_svc);
    ASSERT_GE(cleaned, 0);
    ozayn_pco_service_shutdown(&_svc);
    return 0;
}

TEST(test_pco_cleanup_all) {
    _init_svc();
    ozayn_pco_pipeline_t *p = _create_pipeline();
    int cleaned = ozayn_pco_cleanup_all(&_svc);
    ASSERT(cleaned >= 0);
    ozayn_pco_service_shutdown(&_svc);
    return 0;
}

/* ============================================================
 * STATISTICS TESTS
 * ============================================================ */

TEST(test_pco_stats) {
    _init_svc();
    _create_pipeline();
    ozayn_pco_stats_t stats;
    ASSERT_EQ(ozayn_pco_get_stats(&_svc, &stats), OZAYN_PCO_OK);
    ASSERT(stats.total_pipelines_created > 0);
    ozayn_pco_service_shutdown(&_svc);
    return 0;
}

TEST(test_pco_stats_null) {
    ASSERT_EQ(ozayn_pco_get_stats(NULL, NULL), OZAYN_PCO_ERR_NULL);
    return 0;
}

/* ============================================================
 * VALIDATION TESTS
 * ============================================================ */

TEST(test_pco_validate_pipeline) {
    ozayn_pco_pipeline_t p;
    memset(&p, 0, sizeof(p));
    ASSERT(!ozayn_pco_pipeline_validate_fields(&p));
    strncpy(p.pipeline_id, "P-1", OZAYN_PCO_MAX_ID_LEN);
    p.state = OZAYN_PCO_PIPELINE_ACTIVE;
    p.created_time = time(NULL);
    ASSERT(ozayn_pco_pipeline_validate_fields(&p));
    ASSERT(!ozayn_pco_pipeline_validate_fields(NULL));
    return 0;
}

TEST(test_pco_validate_request) {
    ozayn_pco_pipeline_request_t req;
    memset(&req, 0, sizeof(req));
    ASSERT(!ozayn_pco_pipeline_request_validate(&req));
    strncpy(req.requester_ref, "test", OZAYN_PCO_MAX_ID_LEN);
    req.type = OZAYN_PCO_PIPELINE_TYPE_LINEAR;
    ASSERT(ozayn_pco_pipeline_request_validate(&req));
    ASSERT(!ozayn_pco_pipeline_request_validate(NULL));
    return 0;
}

TEST(test_pco_validate_stage) {
    ozayn_pco_stage_t s;
    memset(&s, 0, sizeof(s));
    ASSERT(!ozayn_pco_stage_validate(&s));
    strncpy(s.stage_id, "S1", OZAYN_PCO_MAX_ID_LEN);
    s.type = OZAYN_PCO_STAGE_SOURCE;
    s.state = OZAYN_PCO_STAGE_ACTIVE;
    ASSERT(ozayn_pco_stage_validate(&s));
    ASSERT(!ozayn_pco_stage_validate(NULL));
    return 0;
}

TEST(test_pco_validate_edge) {
    ozayn_pco_edge_t e;
    memset(&e, 0, sizeof(e));
    ASSERT(!ozayn_pco_edge_validate(&e));
    strncpy(e.edge_id, "E1", OZAYN_PCO_MAX_ID_LEN);
    strncpy(e.source_stage_id, "S1", OZAYN_PCO_MAX_ID_LEN);
    strncpy(e.destination_stage_id, "S2", OZAYN_PCO_MAX_ID_LEN);
    ASSERT(ozayn_pco_edge_validate(&e));
    ASSERT(!ozayn_pco_edge_validate(NULL));
    return 0;
}

TEST(test_pco_pipeline_state_transition_valid) {
    ASSERT(ozayn_pco_pipeline_state_transition_valid(
        OZAYN_PCO_PIPELINE_CREATED, OZAYN_PCO_PIPELINE_VALIDATING));
    ASSERT(ozayn_pco_pipeline_state_transition_valid(
        OZAYN_PCO_PIPELINE_ACTIVE, OZAYN_PCO_PIPELINE_PAUSING));
    ASSERT(!ozayn_pco_pipeline_state_transition_valid(
        OZAYN_PCO_PIPELINE_STOPPED, OZAYN_PCO_PIPELINE_ACTIVE));
    ASSERT(!ozayn_pco_pipeline_state_transition_valid(
        OZAYN_PCO_PIPELINE_STATE_COUNT, 0));
    ASSERT(!ozayn_pco_pipeline_state_transition_valid(
        0, OZAYN_PCO_PIPELINE_STATE_COUNT));
    return 0;
}

TEST(test_pco_stage_state_transition_valid) {
    ASSERT(ozayn_pco_stage_state_transition_valid(
        OZAYN_PCO_STAGE_CREATED, OZAYN_PCO_STAGE_VALIDATING));
    ASSERT(ozayn_pco_stage_state_transition_valid(
        OZAYN_PCO_STAGE_ACTIVE, OZAYN_PCO_STAGE_PAUSED));
    ASSERT(!ozayn_pco_stage_state_transition_valid(
        OZAYN_PCO_STAGE_COMPLETED, OZAYN_PCO_STAGE_ACTIVE));
    ASSERT(!ozayn_pco_stage_state_transition_valid(
        OZAYN_PCO_STAGE_STATE_COUNT, 0));
    return 0;
}

/* ============================================================
 * NAME HELPER TESTS
 * ============================================================ */

TEST(test_pco_err_name) {
    ASSERT(strcmp(ozayn_pco_err_name(OZAYN_PCO_OK), "OK") == 0);
    ASSERT(strcmp(ozayn_pco_err_name(OZAYN_PCO_ERR_NULL), "NULL") == 0);
    ASSERT(strcmp(ozayn_pco_err_name(OZAYN_PCO_ERR_NOT_FOUND), "NOT_FOUND") == 0);
    ASSERT(strcmp(ozayn_pco_err_name((ozayn_pco_err_t)9999), "UNKNOWN") == 0);
    return 0;
}

TEST(test_pco_pipeline_state_name) {
    ASSERT(strcmp(ozayn_pco_pipeline_state_name(OZAYN_PCO_PIPELINE_CREATED), "CREATED") == 0);
    ASSERT(strcmp(ozayn_pco_pipeline_state_name(OZAYN_PCO_PIPELINE_ACTIVE), "ACTIVE") == 0);
    ASSERT(strcmp(ozayn_pco_pipeline_state_name(OZAYN_PCO_PIPELINE_STATE_COUNT), "UNKNOWN") == 0);
    return 0;
}

TEST(test_pco_pipeline_type_name) {
    ASSERT(strcmp(ozayn_pco_pipeline_type_name(OZAYN_PCO_PIPELINE_TYPE_LINEAR), "LINEAR") == 0);
    ASSERT(strcmp(ozayn_pco_pipeline_type_name(OZAYN_PCO_PIPELINE_TYPE_COUNT), "UNKNOWN") == 0);
    return 0;
}

TEST(test_pco_stage_type_name) {
    ASSERT(strcmp(ozayn_pco_stage_type_name(OZAYN_PCO_STAGE_SOURCE), "SOURCE") == 0);
    ASSERT(strcmp(ozayn_pco_stage_type_name(OZAYN_PCO_STAGE_COUNT), "UNKNOWN") == 0);
    return 0;
}

TEST(test_pco_stage_state_name) {
    ASSERT(strcmp(ozayn_pco_stage_state_name(OZAYN_PCO_STAGE_ACTIVE), "ACTIVE") == 0);
    ASSERT(strcmp(ozayn_pco_stage_state_name(OZAYN_PCO_STAGE_STATE_COUNT), "UNKNOWN") == 0);
    return 0;
}

TEST(test_pco_flow_state_name) {
    ASSERT(strcmp(ozayn_pco_flow_state_name(OZAYN_PCO_FLOW_NORMAL), "NORMAL") == 0);
    ASSERT(strcmp(ozayn_pco_flow_state_name(OZAYN_PCO_FLOW_COUNT), "UNKNOWN") == 0);
    return 0;
}

TEST(test_pco_event_type_name) {
    ASSERT(strcmp(ozayn_pco_event_type_name(OZAYN_PCO_EVENT_PIPELINE_CREATED), "PIPELINE_CREATED") == 0);
    ASSERT(strcmp(ozayn_pco_event_type_name((ozayn_pco_event_type_t)999), "UNKNOWN") == 0);
    return 0;
}

TEST(test_pco_close_reason_name) {
    ASSERT(strcmp(ozayn_pco_close_reason_name(OZAYN_PCO_CLOSE_NONE), "NONE") == 0);
    ASSERT(strcmp(ozayn_pco_close_reason_name(OZAYN_PCO_CLOSE_MANUAL_STOP), "MANUAL_STOP") == 0);
    ASSERT(strcmp(ozayn_pco_close_reason_name((ozayn_pco_close_reason_t)999), "UNKNOWN") == 0);
    return 0;
}

TEST(test_pco_edge_direction_name) {
    ASSERT(strcmp(ozayn_pco_edge_direction_name(OZAYN_PCO_EDGE_OUTPUT), "OUTPUT") == 0);
    ASSERT(strcmp(ozayn_pco_edge_direction_name((ozayn_pco_edge_direction_t)999), "UNKNOWN") == 0);
    return 0;
}

/* ============================================================
 * EDGE CASE / SECURITY TESTS
 * ============================================================ */

TEST(test_pco_stop_from_paused) {
    _init_svc();
    ozayn_pco_pipeline_t *p = _create_pipeline();
    _add_two_stages_and_edge(&_svc, p->pipeline_id);
    ozayn_pco_pipeline_start(&_svc, p->pipeline_id);
    ozayn_pco_pipeline_pause(&_svc, p->pipeline_id);
    ASSERT_EQ(ozayn_pco_pipeline_stop(&_svc, p->pipeline_id), OZAYN_PCO_OK);
    ASSERT_EQ(p->state, OZAYN_PCO_PIPELINE_STOPPED);
    ozayn_pco_service_shutdown(&_svc);
    return 0;
}

TEST(test_pco_stop_from_created) {
    _init_svc();
    ozayn_pco_pipeline_t *p = _create_pipeline();
    ASSERT_EQ(ozayn_pco_pipeline_stop(&_svc, p->pipeline_id), OZAYN_PCO_OK);
    ASSERT_EQ(p->state, OZAYN_PCO_PIPELINE_STOPPED);
    ozayn_pco_service_shutdown(&_svc);
    return 0;
}

TEST(test_pco_multiple_pipelines) {
    _init_svc();
    for (int i = 0; i < 3; i++) {
        ozayn_pco_pipeline_request_t req;
        _make_request(&req);
        snprintf(req.name, OZAYN_PCO_MAX_NAME_LEN, "MP-%d", i);
        ozayn_pco_pipeline_t *p = NULL;
        ozayn_pco_pipeline_create(&_svc, &req, &p);
        _add_two_stages_and_edge(&_svc, p->pipeline_id);
    }
    ASSERT_EQ(ozayn_pco_pipeline_count(&_svc), 3);
    ozayn_pco_service_shutdown(&_svc);
    return 0;
}

TEST(test_pco_no_secrets_in_pipeline) {
    _init_svc();
    ozayn_pco_pipeline_t *p = _create_pipeline();
    ASSERT(p->security_session_ref[0] == '\0');
    ASSERT(p->authorization_ref[0] == '\0');
    ASSERT(p->safety_decision_ref[0] == '\0');
    ozayn_pco_service_shutdown(&_svc);
    return 0;
}

TEST(test_pco_no_secrets_in_event) {
    _init_svc();
    ozayn_pco_emit_event(&_svc, OZAYN_PCO_EVENT_PIPELINE_CREATED,
        "P-1", NULL, NULL, NULL, "safe message");
    const ozayn_pco_event_t *e = ozayn_pco_event_get(&_svc, 0);
    ASSERT(e != NULL);
    ASSERT(strcmp(e->message, "safe message") == 0);
    ozayn_pco_service_shutdown(&_svc);
    return 0;
}

TEST(test_pco_pipeline_version) {
    _init_svc();
    ozayn_pco_pipeline_t *p = _create_pipeline();
    ASSERT_EQ(p->version, 1u);
    ozayn_pco_service_shutdown(&_svc);
    return 0;
}

TEST(test_pco_pipeline_type_linear) {
    _init_svc();
    ozayn_pco_pipeline_request_t req;
    _make_request(&req);
    req.type = OZAYN_PCO_PIPELINE_TYPE_LINEAR;
    ozayn_pco_pipeline_t *p = NULL;
    ozayn_pco_pipeline_create(&_svc, &req, &p);
    ASSERT_EQ(p->type, OZAYN_PCO_PIPELINE_TYPE_LINEAR);
    ozayn_pco_service_shutdown(&_svc);
    return 0;
}

TEST(test_pco_pipeline_type_fan_out) {
    _init_svc();
    ozayn_pco_pipeline_request_t req;
    _make_request(&req);
    req.type = OZAYN_PCO_PIPELINE_TYPE_FAN_OUT;
    ozayn_pco_pipeline_t *p = NULL;
    ozayn_pco_pipeline_create(&_svc, &req, &p);
    ASSERT_EQ(p->type, OZAYN_PCO_PIPELINE_TYPE_FAN_OUT);
    ozayn_pco_service_shutdown(&_svc);
    return 0;
}

/* ============================================================
 * TEST RUNNER
 * ============================================================ */

int run_cr_pipeline_tests(void)
{
    SUITE_BEGIN("Pipeline Coordinator");

    /* Lifecycle */
    RUN(test_pco_init);
    RUN(test_pco_init_null);
    RUN(test_pco_init_null_cfg);
    RUN(test_pco_init_double);
    RUN(test_pco_shutdown);
    RUN(test_pco_shutdown_null);
    RUN(test_pco_is_initialized_null);
    RUN(test_pco_global);

    /* Pipeline Creation */
    RUN(test_pco_pipeline_create);
    RUN(test_pco_pipeline_create_null_svc);
    RUN(test_pco_pipeline_create_null_req);
    RUN(test_pco_pipeline_create_null_out);
    RUN(test_pco_pipeline_create_no_requester);
    RUN(test_pco_pipeline_create_bad_type);
    RUN(test_pco_pipeline_create_duplicate_name);
    RUN(test_pco_pipeline_create_no_name);
    RUN(test_pco_pipeline_create_limit);
    RUN(test_pco_pipeline_metadata);

    /* Stages */
    RUN(test_pco_stage_add);
    RUN(test_pco_stage_add_null);
    RUN(test_pco_stage_add_no_pipeline);
    RUN(test_pco_stage_add_bad_type);
    RUN(test_pco_stage_add_duplicate);
    RUN(test_pco_stage_get);
    RUN(test_pco_stage_get_not_found);
    RUN(test_pco_stage_remove);
    RUN(test_pco_stage_count);
    RUN(test_pco_stages_for_pipeline);

    /* Edges */
    RUN(test_pco_edge_add);
    RUN(test_pco_edge_add_null);
    RUN(test_pco_edge_add_no_pipeline);
    RUN(test_pco_edge_add_missing_source);
    RUN(test_pco_edge_add_self_loop);
    RUN(test_pco_edge_get);
    RUN(test_pco_edge_remove);
    RUN(test_pco_edge_count);

    /* Graph Validation */
    RUN(test_pco_graph_validate_valid);
    RUN(test_pco_graph_validate_no_stages);
    RUN(test_pco_graph_check_cycle);
    RUN(test_pco_graph_validate_null);
    RUN(test_pco_graph_check_cycle_null);

    /* Pipeline Validation */
    RUN(test_pco_pipeline_validate);
    RUN(test_pco_pipeline_validate_no_stages);
    RUN(test_pco_pipeline_validate_null_id);
    RUN(test_pco_pipeline_validate_not_found);
    RUN(test_pco_pipeline_validate_expired);
    RUN(test_pco_pipeline_authorize);

    /* Pipeline Start */
    RUN(test_pco_pipeline_start);
    RUN(test_pco_pipeline_start_not_found);
    RUN(test_pco_pipeline_start_null);
    RUN(test_pco_pipeline_start_null_id);

    /* Pause / Resume */
    RUN(test_pco_pipeline_pause);
    RUN(test_pco_pipeline_pause_not_active);
    RUN(test_pco_pipeline_resume);
    RUN(test_pco_pipeline_resume_not_paused);

    /* Drain / Stop */
    RUN(test_pco_pipeline_drain);
    RUN(test_pco_pipeline_drain_not_active);
    RUN(test_pco_pipeline_stop);
    RUN(test_pco_pipeline_stop_terminal);
    RUN(test_pco_pipeline_cancel);
    RUN(test_pco_pipeline_cancel_terminal);
    RUN(test_pco_pipeline_close);
    RUN(test_pco_pipeline_revoke);
    RUN(test_pco_pipeline_remove);

    /* Full Lifecycle */
    RUN(test_pco_pipeline_full_lifecycle);

    /* Query */
    RUN(test_pco_pipeline_get);
    RUN(test_pco_pipeline_get_by_name);
    RUN(test_pco_pipeline_count);
    RUN(test_pco_pipeline_count_by_state);
    RUN(test_pco_pipeline_is_active);

    /* Health */
    RUN(test_pco_health_get);
    RUN(test_pco_health_get_not_found);
    RUN(test_pco_health_get_null);

    /* Flow Control */
    RUN(test_pco_flow_get_state);
    RUN(test_pco_flow_set_state);
    RUN(test_pco_flow_set_backpressured);
    RUN(test_pco_flow_is_blocked);
    RUN(test_pco_flow_is_backpressured);
    RUN(test_pco_flow_set_state_null);
    RUN(test_pco_flow_get_state_null);

    /* Synchronization */
    RUN(test_pco_sync_check_stage);
    RUN(test_pco_sync_check_stage_not_found);
    RUN(test_pco_sync_all_stages_ready);
    RUN(test_pco_sync_advance_stage);

    /* Events */
    RUN(test_pco_event_emit);
    RUN(test_pco_event_overflow);
    RUN(test_pco_event_get_invalid);

    /* Cleanup */
    RUN(test_pco_cleanup_expired);
    RUN(test_pco_cleanup_stopped);
    RUN(test_pco_cleanup_all);

    /* Statistics */
    RUN(test_pco_stats);
    RUN(test_pco_stats_null);

    /* Validation */
    RUN(test_pco_validate_pipeline);
    RUN(test_pco_validate_request);
    RUN(test_pco_validate_stage);
    RUN(test_pco_validate_edge);
    RUN(test_pco_pipeline_state_transition_valid);
    RUN(test_pco_stage_state_transition_valid);

    /* Name Helpers */
    RUN(test_pco_err_name);
    RUN(test_pco_pipeline_state_name);
    RUN(test_pco_pipeline_type_name);
    RUN(test_pco_stage_type_name);
    RUN(test_pco_stage_state_name);
    RUN(test_pco_flow_state_name);
    RUN(test_pco_event_type_name);
    RUN(test_pco_close_reason_name);
    RUN(test_pco_edge_direction_name);

    /* Edge Cases / Security */
    RUN(test_pco_stop_from_paused);
    RUN(test_pco_stop_from_created);
    RUN(test_pco_multiple_pipelines);
    RUN(test_pco_no_secrets_in_pipeline);
    RUN(test_pco_no_secrets_in_event);
    RUN(test_pco_pipeline_version);
    RUN(test_pco_pipeline_type_linear);
    RUN(test_pco_pipeline_type_fan_out);

    SUITE_END();
    return TOTAL_FAIL();
}
