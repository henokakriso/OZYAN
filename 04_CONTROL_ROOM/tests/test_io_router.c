#include "../io_router.h"
#include "../../tests/test_framework.h"
#include <string.h>
#include <time.h>

/* ============================================================
 * HELPERS
 * ============================================================ */

static ozayn_ior_service_t _svc;
static ozayn_ior_service_config_t _cfg;

static void _reset_all(void) {
    memset(&_svc, 0, sizeof(_svc));
}

static void _init_svc(void) {
    _reset_all();
    memset(&_cfg, 0, sizeof(_cfg));
    ozayn_ior_service_init(&_svc, &_cfg);
}

static void _register_endpoints(void) {
    ozayn_ior_endpoint_t ep;
    memset(&ep, 0, sizeof(ep));
    strncpy(ep.endpoint_id, "SRC-A", OZAYN_IOR_MAX_ID_LEN);
    ep.type = OZAYN_IOR_ENDPOINT_DEVICE;
    ep.available = 1;
    ep.health = 100;
    ozayn_ior_endpoint_register(&_svc, &ep);

    memset(&ep, 0, sizeof(ep));
    strncpy(ep.endpoint_id, "DST-B", OZAYN_IOR_MAX_ID_LEN);
    ep.type = OZAYN_IOR_ENDPOINT_STREAM;
    ep.available = 1;
    ep.health = 100;
    ozayn_ior_endpoint_register(&_svc, &ep);
}

static void _make_request(ozayn_ior_route_request_t *req) {
    memset(req, 0, sizeof(*req));
    strncpy(req->stream_id, "STRM-1", OZAYN_IOR_MAX_ID_LEN);
    strncpy(req->source_id, "SRC-A", OZAYN_IOR_MAX_ID_LEN);
    req->source_type = OZAYN_IOR_ENDPOINT_DEVICE;
    strncpy(req->destination_id, "DST-B", OZAYN_IOR_MAX_ID_LEN);
    req->destination_type = OZAYN_IOR_ENDPOINT_STREAM;
    req->mode = OZAYN_IOR_MODE_ONE_TO_ONE;
    strncpy(req->requester_ref, "test", OZAYN_IOR_MAX_ID_LEN);
}

static ozayn_ior_route_t *_create_active_route(void) {
    _register_endpoints();
    ozayn_ior_route_request_t req;
    _make_request(&req);
    ozayn_ior_route_t *r = NULL;
    ozayn_ior_route_create(&_svc, &req, &r);
    ozayn_ior_route_authorize(&_svc, r->route_id);
    ozayn_ior_route_connect(&_svc, r->route_id);
    ozayn_ior_route_activate(&_svc, r->route_id);
    return r;
}

/* ============================================================
 * LIFECYCLE TESTS
 * ============================================================ */

TEST(test_ior_init) {
    _reset_all();
    memset(&_cfg, 0, sizeof(_cfg));
    ASSERT_EQ(ozayn_ior_service_init(&_svc, &_cfg), OZAYN_IOR_OK);
    ASSERT(ozayn_ior_service_is_initialized(&_svc));
    ozayn_ior_service_shutdown(&_svc);
    return 0;
}

TEST(test_ior_init_null_svc) {
    ASSERT_EQ(ozayn_ior_service_init(NULL, &_cfg), OZAYN_IOR_ERR_NULL);
    return 0;
}

TEST(test_ior_init_null_cfg) {
    _reset_all();
    ASSERT_EQ(ozayn_ior_service_init(&_svc, NULL), OZAYN_IOR_ERR_NULL);
    return 0;
}

TEST(test_ior_init_double) {
    _init_svc();
    ASSERT_EQ(ozayn_ior_service_init(&_svc, &_cfg), OZAYN_IOR_ERR_ALREADY_INIT);
    ozayn_ior_service_shutdown(&_svc);
    return 0;
}

TEST(test_ior_not_initialized) {
    _reset_all();
    ASSERT_EQ(ozayn_ior_route_count(&_svc), 0);
    return 0;
}

TEST(test_ior_global) {
    ozayn_ior_service_t *g = ozayn_ior_get_global();
    ASSERT(g != NULL);
    return 0;
}

TEST(test_ior_shutdown_idempotent) {
    _init_svc();
    ozayn_ior_service_shutdown(&_svc);
    ozayn_ior_service_shutdown(&_svc);
    ASSERT(!ozayn_ior_service_is_initialized(&_svc));
    return 0;
}

/* ============================================================
 * ENDPOINT TESTS
 * ============================================================ */

TEST(test_ior_endpoint_register) {
    _init_svc();
    ozayn_ior_endpoint_t ep;
    memset(&ep, 0, sizeof(ep));
    strncpy(ep.endpoint_id, "EP-1", OZAYN_IOR_MAX_ID_LEN);
    ep.type = OZAYN_IOR_ENDPOINT_DEVICE;
    ep.available = 1;
    ASSERT_EQ(ozayn_ior_endpoint_register(&_svc, &ep), OZAYN_IOR_OK);
    ASSERT_EQ(ozayn_ior_endpoint_count(&_svc), 1);
    const ozayn_ior_endpoint_t *f = ozayn_ior_endpoint_get(&_svc, "EP-1");
    ASSERT(f != NULL);
    ozayn_ior_service_shutdown(&_svc);
    return 0;
}

TEST(test_ior_endpoint_register_null) {
    _init_svc();
    ASSERT_EQ(ozayn_ior_endpoint_register(&_svc, NULL), OZAYN_IOR_ERR_NULL);
    ozayn_ior_service_shutdown(&_svc);
    return 0;
}

TEST(test_ior_endpoint_register_no_id) {
    _init_svc();
    ozayn_ior_endpoint_t ep;
    memset(&ep, 0, sizeof(ep));
    ep.type = OZAYN_IOR_ENDPOINT_DEVICE;
    ASSERT_EQ(ozayn_ior_endpoint_register(&_svc, &ep), OZAYN_IOR_ERR_INVALID_PARAM);
    ozayn_ior_service_shutdown(&_svc);
    return 0;
}

TEST(test_ior_endpoint_register_bad_type) {
    _init_svc();
    ozayn_ior_endpoint_t ep;
    memset(&ep, 0, sizeof(ep));
    strncpy(ep.endpoint_id, "EP-B", OZAYN_IOR_MAX_ID_LEN);
    ep.type = OZAYN_IOR_ENDPOINT_COUNT;
    ASSERT_EQ(ozayn_ior_endpoint_register(&_svc, &ep), OZAYN_IOR_ERR_INVALID_PARAM);
    ozayn_ior_service_shutdown(&_svc);
    return 0;
}

TEST(test_ior_endpoint_register_duplicate) {
    _init_svc();
    ozayn_ior_endpoint_t ep;
    memset(&ep, 0, sizeof(ep));
    strncpy(ep.endpoint_id, "EP-DUP", OZAYN_IOR_MAX_ID_LEN);
    ep.type = OZAYN_IOR_ENDPOINT_DEVICE;
    ASSERT_EQ(ozayn_ior_endpoint_register(&_svc, &ep), OZAYN_IOR_OK);
    ASSERT_EQ(ozayn_ior_endpoint_register(&_svc, &ep), OZAYN_IOR_ERR_INVALID_PARAM);
    ozayn_ior_service_shutdown(&_svc);
    return 0;
}

TEST(test_ior_endpoint_unregister) {
    _init_svc();
    ozayn_ior_endpoint_t ep;
    memset(&ep, 0, sizeof(ep));
    strncpy(ep.endpoint_id, "EP-UN", OZAYN_IOR_MAX_ID_LEN);
    ep.type = OZAYN_IOR_ENDPOINT_STREAM;
    ozayn_ior_endpoint_register(&_svc, &ep);
    ASSERT_EQ(ozayn_ior_endpoint_unregister(&_svc, "EP-UN"), OZAYN_IOR_OK);
    ASSERT_EQ(ozayn_ior_endpoint_count(&_svc), 0);
    ozayn_ior_service_shutdown(&_svc);
    return 0;
}

TEST(test_ior_endpoint_unregister_not_found) {
    _init_svc();
    ASSERT_EQ(ozayn_ior_endpoint_unregister(&_svc, "NOPE"), OZAYN_IOR_ERR_NOT_FOUND);
    ozayn_ior_service_shutdown(&_svc);
    return 0;
}

TEST(test_ior_endpoint_unregister_null) {
    _init_svc();
    ASSERT_EQ(ozayn_ior_endpoint_unregister(&_svc, NULL), OZAYN_IOR_ERR_INVALID_PARAM);
    ASSERT_EQ(ozayn_ior_endpoint_unregister(&_svc, ""), OZAYN_IOR_ERR_INVALID_PARAM);
    ozayn_ior_service_shutdown(&_svc);
    return 0;
}

TEST(test_ior_endpoint_get_not_found) {
    _init_svc();
    ASSERT(ozayn_ior_endpoint_get(&_svc, "NOPE") == NULL);
    ozayn_ior_service_shutdown(&_svc);
    return 0;
}

TEST(test_ior_endpoint_is_available) {
    _init_svc();
    ozayn_ior_endpoint_t ep;
    memset(&ep, 0, sizeof(ep));
    strncpy(ep.endpoint_id, "EP-AV", OZAYN_IOR_MAX_ID_LEN);
    ep.type = OZAYN_IOR_ENDPOINT_DEVICE;
    ep.available = 1;
    ozayn_ior_endpoint_register(&_svc, &ep);
    ASSERT(ozayn_ior_endpoint_is_available(&_svc, "EP-AV"));
    ozayn_ior_service_shutdown(&_svc);
    return 0;
}

TEST(test_ior_endpoint_not_available) {
    _init_svc();
    ozayn_ior_endpoint_t ep;
    memset(&ep, 0, sizeof(ep));
    strncpy(ep.endpoint_id, "EP-NA", OZAYN_IOR_MAX_ID_LEN);
    ep.type = OZAYN_IOR_ENDPOINT_DEVICE;
    ep.available = 0;
    ozayn_ior_endpoint_register(&_svc, &ep);
    ASSERT(!ozayn_ior_endpoint_is_available(&_svc, "EP-NA"));
    ozayn_ior_service_shutdown(&_svc);
    return 0;
}

TEST(test_ior_endpoint_limit) {
    _init_svc();
    ozayn_ior_endpoint_t ep;
    for (int i = 0; i < 32; i++) {
        memset(&ep, 0, sizeof(ep));
        snprintf(ep.endpoint_id, OZAYN_IOR_MAX_ID_LEN, "EPL-%d", i);
        ep.type = OZAYN_IOR_ENDPOINT_DEVICE;
        ASSERT_EQ(ozayn_ior_endpoint_register(&_svc, &ep), OZAYN_IOR_OK);
    }
    memset(&ep, 0, sizeof(ep));
    strncpy(ep.endpoint_id, "EPL-OVR", OZAYN_IOR_MAX_ID_LEN);
    ep.type = OZAYN_IOR_ENDPOINT_DEVICE;
    ASSERT_EQ(ozayn_ior_endpoint_register(&_svc, &ep), OZAYN_IOR_ERR_LIMIT_REACHED);
    ozayn_ior_service_shutdown(&_svc);
    return 0;
}

/* ============================================================
 * ROUTE CREATION TESTS
 * ============================================================ */

TEST(test_ior_route_create) {
    _init_svc();
    _register_endpoints();
    ozayn_ior_route_request_t req;
    _make_request(&req);
    ozayn_ior_route_t *r = NULL;
    ASSERT_EQ(ozayn_ior_route_create(&_svc, &req, &r), OZAYN_IOR_OK);
    ASSERT(r != NULL);
    ASSERT(r->route_id[0] != '\0');
    ASSERT_EQ(r->state, OZAYN_IOR_ROUTE_REQUESTED);
    ASSERT_EQ(ozayn_ior_route_count(&_svc), 1);
    ozayn_ior_service_shutdown(&_svc);
    return 0;
}

TEST(test_ior_route_create_null_svc) {
    ASSERT_EQ(ozayn_ior_route_create(NULL, NULL, NULL), OZAYN_IOR_ERR_NULL);
    return 0;
}

TEST(test_ior_route_create_null_req) {
    _init_svc();
    ozayn_ior_route_t *r = NULL;
    ASSERT_EQ(ozayn_ior_route_create(&_svc, NULL, &r), OZAYN_IOR_ERR_NULL);
    ozayn_ior_service_shutdown(&_svc);
    return 0;
}

TEST(test_ior_route_create_null_out) {
    _init_svc();
    _register_endpoints();
    ozayn_ior_route_request_t req;
    _make_request(&req);
    ASSERT_EQ(ozayn_ior_route_create(&_svc, &req, NULL), OZAYN_IOR_ERR_NULL);
    ozayn_ior_service_shutdown(&_svc);
    return 0;
}

TEST(test_ior_route_create_no_stream_id) {
    _init_svc();
    _register_endpoints();
    ozayn_ior_route_request_t req;
    _make_request(&req);
    req.stream_id[0] = '\0';
    ozayn_ior_route_t *r = NULL;
    ASSERT_EQ(ozayn_ior_route_create(&_svc, &req, &r), OZAYN_IOR_ERR_INVALID_PARAM);
    ozayn_ior_service_shutdown(&_svc);
    return 0;
}

TEST(test_ior_route_create_no_source_id) {
    _init_svc();
    _register_endpoints();
    ozayn_ior_route_request_t req;
    _make_request(&req);
    req.source_id[0] = '\0';
    ozayn_ior_route_t *r = NULL;
    ASSERT_EQ(ozayn_ior_route_create(&_svc, &req, &r), OZAYN_IOR_ERR_INVALID_PARAM);
    ozayn_ior_service_shutdown(&_svc);
    return 0;
}

TEST(test_ior_route_create_no_dest_id) {
    _init_svc();
    _register_endpoints();
    ozayn_ior_route_request_t req;
    _make_request(&req);
    req.destination_id[0] = '\0';
    ozayn_ior_route_t *r = NULL;
    ASSERT_EQ(ozayn_ior_route_create(&_svc, &req, &r), OZAYN_IOR_ERR_INVALID_PARAM);
    ozayn_ior_service_shutdown(&_svc);
    return 0;
}

TEST(test_ior_route_create_no_requester) {
    _init_svc();
    _register_endpoints();
    ozayn_ior_route_request_t req;
    _make_request(&req);
    req.requester_ref[0] = '\0';
    ozayn_ior_route_t *r = NULL;
    ASSERT_EQ(ozayn_ior_route_create(&_svc, &req, &r), OZAYN_IOR_ERR_INVALID_PARAM);
    ozayn_ior_service_shutdown(&_svc);
    return 0;
}

TEST(test_ior_route_create_bad_source_type) {
    _init_svc();
    _register_endpoints();
    ozayn_ior_route_request_t req;
    _make_request(&req);
    req.source_type = OZAYN_IOR_ENDPOINT_COUNT;
    ozayn_ior_route_t *r = NULL;
    ASSERT_EQ(ozayn_ior_route_create(&_svc, &req, &r), OZAYN_IOR_ERR_INVALID_PARAM);
    ozayn_ior_service_shutdown(&_svc);
    return 0;
}

TEST(test_ior_route_create_bad_dest_type) {
    _init_svc();
    _register_endpoints();
    ozayn_ior_route_request_t req;
    _make_request(&req);
    req.destination_type = OZAYN_IOR_ENDPOINT_COUNT;
    ozayn_ior_route_t *r = NULL;
    ASSERT_EQ(ozayn_ior_route_create(&_svc, &req, &r), OZAYN_IOR_ERR_INVALID_PARAM);
    ozayn_ior_service_shutdown(&_svc);
    return 0;
}

TEST(test_ior_route_create_bad_mode) {
    _init_svc();
    _register_endpoints();
    ozayn_ior_route_request_t req;
    _make_request(&req);
    req.mode = OZAYN_IOR_MODE_COUNT;
    ozayn_ior_route_t *r = NULL;
    ASSERT_EQ(ozayn_ior_route_create(&_svc, &req, &r), OZAYN_IOR_ERR_INVALID_PARAM);
    ozayn_ior_service_shutdown(&_svc);
    return 0;
}

TEST(test_ior_route_create_same_src_dst) {
    _init_svc();
    ozayn_ior_endpoint_t ep;
    memset(&ep, 0, sizeof(ep));
    strncpy(ep.endpoint_id, "SAME-1", OZAYN_IOR_MAX_ID_LEN);
    ep.type = OZAYN_IOR_ENDPOINT_DEVICE;
    ep.available = 1;
    ozayn_ior_endpoint_register(&_svc, &ep);

    ozayn_ior_route_request_t req;
    _make_request(&req);
    strncpy(req.source_id, "SAME-1", OZAYN_IOR_MAX_ID_LEN);
    strncpy(req.destination_id, "SAME-1", OZAYN_IOR_MAX_ID_LEN);
    ozayn_ior_route_t *r = NULL;
    ASSERT_EQ(ozayn_ior_route_create(&_svc, &req, &r), OZAYN_IOR_ERR_LOOP_DETECTED);
    ozayn_ior_service_shutdown(&_svc);
    return 0;
}

TEST(test_ior_route_create_limit) {
    _init_svc();
    _register_endpoints();
    for (int i = 0; i < 32; i++) {
        ozayn_ior_route_request_t req;
        _make_request(&req);
        snprintf(req.stream_id, OZAYN_IOR_MAX_ID_LEN, "STRM-%d", i);
        ozayn_ior_route_t *r = NULL;
        ASSERT_EQ(ozayn_ior_route_create(&_svc, &req, &r), OZAYN_IOR_OK);
    }
    ozayn_ior_route_request_t req;
    _make_request(&req);
    ozayn_ior_route_t *r = NULL;
    ASSERT_EQ(ozayn_ior_route_create(&_svc, &req, &r), OZAYN_IOR_ERR_LIMIT_REACHED);
    ozayn_ior_service_shutdown(&_svc);
    return 0;
}

TEST(test_ior_route_metadata) {
    _init_svc();
    _register_endpoints();
    ozayn_ior_route_request_t req;
    _make_request(&req);
    strncpy(req.metadata, "custom-meta", OZAYN_IOR_MAX_METADATA_LEN);
    strncpy(req.required_permission, "perm-read", OZAYN_IOR_MAX_PERMISSION_LEN);
    strncpy(req.security_session_ref, "SEC-1", OZAYN_IOR_MAX_ID_LEN);
    strncpy(req.device_session_id, "DAS-1", OZAYN_IOR_MAX_ID_LEN);
    ozayn_ior_route_t *r = NULL;
    ASSERT_EQ(ozayn_ior_route_create(&_svc, &req, &r), OZAYN_IOR_OK);
    ASSERT(strcmp(r->metadata, "custom-meta") == 0);
    ASSERT(strcmp(r->required_permission, "perm-read") == 0);
    ASSERT(strcmp(r->security_session_ref, "SEC-1") == 0);
    ASSERT(strcmp(r->device_session_id, "DAS-1") == 0);
    ozayn_ior_service_shutdown(&_svc);
    return 0;
}

/* ============================================================
 * AUTHORIZATION TESTS
 * ============================================================ */

TEST(test_ior_route_authorize) {
    _init_svc();
    _register_endpoints();
    ozayn_ior_route_request_t req;
    _make_request(&req);
    ozayn_ior_route_t *r = NULL;
    ozayn_ior_route_create(&_svc, &req, &r);
    ASSERT_EQ(ozayn_ior_route_authorize(&_svc, r->route_id), OZAYN_IOR_OK);
    ASSERT_EQ(r->state, OZAYN_IOR_ROUTE_AUTHORIZED);
    ozayn_ior_service_shutdown(&_svc);
    return 0;
}

TEST(test_ior_route_authorize_null_id) {
    _init_svc();
    ASSERT_EQ(ozayn_ior_route_authorize(&_svc, NULL), OZAYN_IOR_ERR_INVALID_PARAM);
    ASSERT_EQ(ozayn_ior_route_authorize(&_svc, ""), OZAYN_IOR_ERR_INVALID_PARAM);
    ozayn_ior_service_shutdown(&_svc);
    return 0;
}

TEST(test_ior_route_authorize_not_found) {
    _init_svc();
    ASSERT_EQ(ozayn_ior_route_authorize(&_svc, "NOPE"), OZAYN_IOR_ERR_NOT_FOUND);
    ozayn_ior_service_shutdown(&_svc);
    return 0;
}

TEST(test_ior_route_authorize_no_source) {
    _init_svc();
    ozayn_ior_endpoint_t ep;
    memset(&ep, 0, sizeof(ep));
    strncpy(ep.endpoint_id, "DST-X", OZAYN_IOR_MAX_ID_LEN);
    ep.type = OZAYN_IOR_ENDPOINT_STREAM;
    ozayn_ior_endpoint_register(&_svc, &ep);

    ozayn_ior_route_request_t req;
    _make_request(&req);
    ozayn_ior_route_t *r = NULL;
    ozayn_ior_route_create(&_svc, &req, &r);
    ASSERT_EQ(ozayn_ior_route_authorize(&_svc, r->route_id), OZAYN_IOR_ERR_SOURCE_NOT_FOUND);
    ASSERT_EQ(r->state, OZAYN_IOR_ROUTE_FAILED);
    ozayn_ior_service_shutdown(&_svc);
    return 0;
}

TEST(test_ior_route_authorize_no_dest) {
    _init_svc();
    ozayn_ior_endpoint_t ep;
    memset(&ep, 0, sizeof(ep));
    strncpy(ep.endpoint_id, "SRC-A", OZAYN_IOR_MAX_ID_LEN);
    ep.type = OZAYN_IOR_ENDPOINT_DEVICE;
    ozayn_ior_endpoint_register(&_svc, &ep);

    ozayn_ior_route_request_t req;
    _make_request(&req);
    ozayn_ior_route_t *r = NULL;
    ozayn_ior_route_create(&_svc, &req, &r);
    ASSERT_EQ(ozayn_ior_route_authorize(&_svc, r->route_id), OZAYN_IOR_ERR_DESTINATION_NOT_FOUND);
    ASSERT_EQ(r->state, OZAYN_IOR_ROUTE_FAILED);
    ozayn_ior_service_shutdown(&_svc);
    return 0;
}

TEST(test_ior_route_authorize_bad_state) {
    _init_svc();
    _register_endpoints();
    ozayn_ior_route_request_t req;
    _make_request(&req);
    ozayn_ior_route_t *r = NULL;
    ozayn_ior_route_create(&_svc, &req, &r);
    ozayn_ior_route_authorize(&_svc, r->route_id);
    ASSERT_EQ(ozayn_ior_route_authorize(&_svc, r->route_id), OZAYN_IOR_ERR_STATE_INVALID);
    ozayn_ior_service_shutdown(&_svc);
    return 0;
}

TEST(test_ior_route_authorize_expired) {
    _init_svc();
    _register_endpoints();
    ozayn_ior_route_request_t req;
    _make_request(&req);
    ozayn_ior_route_t *r = NULL;
    ozayn_ior_route_create(&_svc, &req, &r);
    r->expiry_time = time(NULL) - 1;
    ASSERT_EQ(ozayn_ior_route_authorize(&_svc, r->route_id), OZAYN_IOR_ERR_EXPIRED);
    ASSERT_EQ(r->state, OZAYN_IOR_ROUTE_EXPIRED);
    ozayn_ior_service_shutdown(&_svc);
    return 0;
}

/* ============================================================
 * CONNECTION TESTS
 * ============================================================ */

TEST(test_ior_route_connect) {
    _init_svc();
    _register_endpoints();
    ozayn_ior_route_request_t req;
    _make_request(&req);
    ozayn_ior_route_t *r = NULL;
    ozayn_ior_route_create(&_svc, &req, &r);
    ozayn_ior_route_authorize(&_svc, r->route_id);
    ASSERT_EQ(ozayn_ior_route_connect(&_svc, r->route_id), OZAYN_IOR_OK);
    ASSERT_EQ(r->state, OZAYN_IOR_ROUTE_CONNECTING);
    ozayn_ior_service_shutdown(&_svc);
    return 0;
}

TEST(test_ior_route_connect_not_authorized) {
    _init_svc();
    _register_endpoints();
    ozayn_ior_route_request_t req;
    _make_request(&req);
    ozayn_ior_route_t *r = NULL;
    ozayn_ior_route_create(&_svc, &req, &r);
    ASSERT_EQ(ozayn_ior_route_connect(&_svc, r->route_id), OZAYN_IOR_ERR_STATE_INVALID);
    ozayn_ior_service_shutdown(&_svc);
    return 0;
}

TEST(test_ior_route_connect_not_found) {
    _init_svc();
    ASSERT_EQ(ozayn_ior_route_connect(&_svc, "NOPE"), OZAYN_IOR_ERR_NOT_FOUND);
    ozayn_ior_service_shutdown(&_svc);
    return 0;
}

/* ============================================================
 * LIFECYCLE OPERATIONS
 * ============================================================ */

TEST(test_ior_route_activate) {
    _init_svc();
    _register_endpoints();
    ozayn_ior_route_request_t req;
    _make_request(&req);
    ozayn_ior_route_t *r = NULL;
    ozayn_ior_route_create(&_svc, &req, &r);
    ozayn_ior_route_authorize(&_svc, r->route_id);
    ozayn_ior_route_connect(&_svc, r->route_id);
    ASSERT_EQ(ozayn_ior_route_activate(&_svc, r->route_id), OZAYN_IOR_OK);
    ASSERT_EQ(r->state, OZAYN_IOR_ROUTE_ACTIVE);
    ASSERT(r->activated_time > 0);
    ozayn_ior_service_shutdown(&_svc);
    return 0;
}

TEST(test_ior_route_activate_not_connecting) {
    _init_svc();
    _register_endpoints();
    ozayn_ior_route_request_t req;
    _make_request(&req);
    ozayn_ior_route_t *r = NULL;
    ozayn_ior_route_create(&_svc, &req, &r);
    ASSERT_EQ(ozayn_ior_route_activate(&_svc, r->route_id), OZAYN_IOR_ERR_STATE_INVALID);
    ozayn_ior_service_shutdown(&_svc);
    return 0;
}

TEST(test_ior_route_pause) {
    _init_svc();
    _create_active_route();
    const ozayn_ior_route_t *r = ozayn_ior_route_get_by_stream(&_svc, "STRM-1");
    ASSERT(r != NULL);
    ASSERT_EQ(ozayn_ior_route_pause(&_svc, r->route_id), OZAYN_IOR_OK);
    ASSERT_EQ(r->state, OZAYN_IOR_ROUTE_PAUSED);
    ozayn_ior_service_shutdown(&_svc);
    return 0;
}

TEST(test_ior_route_pause_not_active) {
    _init_svc();
    _register_endpoints();
    ozayn_ior_route_request_t req;
    _make_request(&req);
    ozayn_ior_route_t *r = NULL;
    ozayn_ior_route_create(&_svc, &req, &r);
    ASSERT_EQ(ozayn_ior_route_pause(&_svc, r->route_id), OZAYN_IOR_ERR_STATE_INVALID);
    ozayn_ior_service_shutdown(&_svc);
    return 0;
}

TEST(test_ior_route_resume) {
    _init_svc();
    _create_active_route();
    const ozayn_ior_route_t *r = ozayn_ior_route_get_by_stream(&_svc, "STRM-1");
    ozayn_ior_route_pause(&_svc, r->route_id);
    ASSERT_EQ(ozayn_ior_route_resume(&_svc, r->route_id), OZAYN_IOR_OK);
    ASSERT_EQ(r->state, OZAYN_IOR_ROUTE_ACTIVE);
    ozayn_ior_service_shutdown(&_svc);
    return 0;
}

TEST(test_ior_route_resume_not_paused) {
    _init_svc();
    _register_endpoints();
    ozayn_ior_route_request_t req;
    _make_request(&req);
    ozayn_ior_route_t *r = NULL;
    ozayn_ior_route_create(&_svc, &req, &r);
    ASSERT_EQ(ozayn_ior_route_resume(&_svc, r->route_id), OZAYN_IOR_ERR_STATE_INVALID);
    ozayn_ior_service_shutdown(&_svc);
    return 0;
}

TEST(test_ior_route_disconnect) {
    _init_svc();
    _create_active_route();
    const ozayn_ior_route_t *r = ozayn_ior_route_get_by_stream(&_svc, "STRM-1");
    ASSERT_EQ(ozayn_ior_route_disconnect(&_svc, r->route_id), OZAYN_IOR_OK);
    ASSERT_EQ(r->state, OZAYN_IOR_ROUTE_CLOSED);
    ASSERT(r->active == 0);
    ozayn_ior_service_shutdown(&_svc);
    return 0;
}

TEST(test_ior_route_disconnect_terminal) {
    _init_svc();
    _register_endpoints();
    ozayn_ior_route_request_t req;
    _make_request(&req);
    ozayn_ior_route_t *r = NULL;
    ozayn_ior_route_create(&_svc, &req, &r);
    r->state = OZAYN_IOR_ROUTE_CLOSED;
    ASSERT_EQ(ozayn_ior_route_disconnect(&_svc, r->route_id), OZAYN_IOR_ERR_STATE_INVALID);
    ozayn_ior_service_shutdown(&_svc);
    return 0;
}

TEST(test_ior_route_close) {
    _init_svc();
    _create_active_route();
    const ozayn_ior_route_t *r = ozayn_ior_route_get_by_stream(&_svc, "STRM-1");
    ASSERT_EQ(ozayn_ior_route_close(&_svc, r->route_id, OZAYN_IOR_CLOSE_MANUAL_CLOSE), OZAYN_IOR_OK);
    ASSERT_EQ(r->state, OZAYN_IOR_ROUTE_CLOSED);
    ASSERT_EQ(r->close_reason, OZAYN_IOR_CLOSE_MANUAL_CLOSE);
    ozayn_ior_service_shutdown(&_svc);
    return 0;
}

TEST(test_ior_route_revoke) {
    _init_svc();
    _create_active_route();
    const ozayn_ior_route_t *r = ozayn_ior_route_get_by_stream(&_svc, "STRM-1");
    ASSERT_EQ(ozayn_ior_route_revoke(&_svc, r->route_id, OZAYN_IOR_CLOSE_POLICY_CHANGED), OZAYN_IOR_OK);
    ASSERT_EQ(r->state, OZAYN_IOR_ROUTE_REVOKED);
    ASSERT_EQ(r->close_reason, OZAYN_IOR_CLOSE_POLICY_CHANGED);
    ozayn_ior_service_shutdown(&_svc);
    return 0;
}

TEST(test_ior_route_remove_closed) {
    _init_svc();
    _register_endpoints();
    ozayn_ior_route_request_t req;
    _make_request(&req);
    ozayn_ior_route_t *r = NULL;
    ozayn_ior_route_create(&_svc, &req, &r);
    char rid[OZAYN_IOR_MAX_ID_LEN];
    strncpy(rid, r->route_id, OZAYN_IOR_MAX_ID_LEN);
    ozayn_ior_route_authorize(&_svc, rid);
    ozayn_ior_route_connect(&_svc, rid);
    ozayn_ior_route_activate(&_svc, rid);
    ozayn_ior_route_disconnect(&_svc, rid);
    ASSERT_EQ(ozayn_ior_route_remove(&_svc, rid), OZAYN_IOR_OK);
    ASSERT(ozayn_ior_route_get(&_svc, rid) == NULL);
    ozayn_ior_service_shutdown(&_svc);
    return 0;
}

TEST(test_ior_route_remove_active) {
    _init_svc();
    _create_active_route();
    const ozayn_ior_route_t *r = ozayn_ior_route_get_by_stream(&_svc, "STRM-1");
    ASSERT_EQ(ozayn_ior_route_remove(&_svc, r->route_id), OZAYN_IOR_ERR_STATE_INVALID);
    ozayn_ior_service_shutdown(&_svc);
    return 0;
}

TEST(test_ior_route_lifecycle_full) {
    _init_svc();
    _register_endpoints();
    ozayn_ior_route_request_t req;
    _make_request(&req);
    ozayn_ior_route_t *r = NULL;
    ozayn_ior_route_create(&_svc, &req, &r);
    ASSERT_EQ(r->state, OZAYN_IOR_ROUTE_REQUESTED);
    ozayn_ior_route_authorize(&_svc, r->route_id);
    ASSERT_EQ(r->state, OZAYN_IOR_ROUTE_AUTHORIZED);
    ozayn_ior_route_connect(&_svc, r->route_id);
    ASSERT_EQ(r->state, OZAYN_IOR_ROUTE_CONNECTING);
    ozayn_ior_route_activate(&_svc, r->route_id);
    ASSERT_EQ(r->state, OZAYN_IOR_ROUTE_ACTIVE);
    ozayn_ior_route_pause(&_svc, r->route_id);
    ASSERT_EQ(r->state, OZAYN_IOR_ROUTE_PAUSED);
    ozayn_ior_route_resume(&_svc, r->route_id);
    ASSERT_EQ(r->state, OZAYN_IOR_ROUTE_ACTIVE);
    ozayn_ior_route_disconnect(&_svc, r->route_id);
    ASSERT_EQ(r->state, OZAYN_IOR_ROUTE_CLOSED);
    ozayn_ior_service_shutdown(&_svc);
    return 0;
}

/* ============================================================
 * QUERY TESTS
 * ============================================================ */

TEST(test_ior_route_get) {
    _init_svc();
    _create_active_route();
    const ozayn_ior_route_t *r = ozayn_ior_route_get_by_stream(&_svc, "STRM-1");
    ASSERT(r != NULL);
    ASSERT(strcmp(r->stream_id, "STRM-1") == 0);
    ozayn_ior_service_shutdown(&_svc);
    return 0;
}

TEST(test_ior_route_get_by_id) {
    _init_svc();
    _register_endpoints();
    ozayn_ior_route_request_t req;
    _make_request(&req);
    ozayn_ior_route_t *r = NULL;
    ozayn_ior_route_create(&_svc, &req, &r);
    const ozayn_ior_route_t *f = ozayn_ior_route_get(&_svc, r->route_id);
    ASSERT(f != NULL);
    ASSERT(strcmp(f->route_id, r->route_id) == 0);
    ozayn_ior_service_shutdown(&_svc);
    return 0;
}

TEST(test_ior_route_get_by_stream_not_found) {
    _init_svc();
    ASSERT(ozayn_ior_route_get_by_stream(&_svc, "NOPE") == NULL);
    ozayn_ior_service_shutdown(&_svc);
    return 0;
}

TEST(test_ior_route_get_by_source) {
    _init_svc();
    _create_active_route();
    ASSERT(ozayn_ior_route_get_by_source(&_svc, "SRC-A") != NULL);
    ASSERT(ozayn_ior_route_get_by_source(&_svc, "NOPE") == NULL);
    ozayn_ior_service_shutdown(&_svc);
    return 0;
}

TEST(test_ior_route_get_by_destination) {
    _init_svc();
    _create_active_route();
    ASSERT(ozayn_ior_route_get_by_destination(&_svc, "DST-B") != NULL);
    ASSERT(ozayn_ior_route_get_by_destination(&_svc, "NOPE") == NULL);
    ozayn_ior_service_shutdown(&_svc);
    return 0;
}

TEST(test_ior_route_count) {
    _init_svc();
    _create_active_route();
    ASSERT_EQ(ozayn_ior_route_count(&_svc), 1);
    _register_endpoints();
    ozayn_ior_route_request_t req;
    _make_request(&req);
    snprintf(req.stream_id, OZAYN_IOR_MAX_ID_LEN, "STRM-2");
    ozayn_ior_route_t *r2 = NULL;
    ozayn_ior_route_create(&_svc, &req, &r2);
    ASSERT_EQ(ozayn_ior_route_count(&_svc), 2);
    ozayn_ior_service_shutdown(&_svc);
    return 0;
}

TEST(test_ior_route_count_by_stream) {
    _init_svc();
    _create_active_route();
    ASSERT_EQ(ozayn_ior_route_count_by_stream(&_svc, "STRM-1"), 1);
    ASSERT_EQ(ozayn_ior_route_count_by_stream(&_svc, "NOPE"), 0);
    ozayn_ior_service_shutdown(&_svc);
    return 0;
}

TEST(test_ior_route_is_active) {
    _init_svc();
    _create_active_route();
    const ozayn_ior_route_t *r = ozayn_ior_route_get_by_stream(&_svc, "STRM-1");
    ASSERT(ozayn_ior_route_is_active(&_svc, r->route_id));
    ozayn_ior_route_pause(&_svc, r->route_id);
    ASSERT(!ozayn_ior_route_is_active(&_svc, r->route_id));
    ozayn_ior_service_shutdown(&_svc);
    return 0;
}

TEST(test_ior_routes_for_stream) {
    _init_svc();
    _create_active_route();
    _register_endpoints();
    ozayn_ior_route_request_t req;
    _make_request(&req);
    snprintf(req.stream_id, OZAYN_IOR_MAX_ID_LEN, "STRM-1B");
    ozayn_ior_route_t *r2 = NULL;
    ozayn_ior_route_create(&_svc, &req, &r2);
    ozayn_ior_route_t *buf[8];
    int n = ozayn_ior_routes_for_stream(&_svc, "STRM-1", buf, 8);
    ASSERT_EQ(n, 1);
    n = ozayn_ior_routes_for_stream(&_svc, "NOPE", buf, 8);
    ASSERT_EQ(n, 0);
    ozayn_ior_service_shutdown(&_svc);
    return 0;
}

/* ============================================================
 * STREAM / DEVICE CHANGE TESTS
 * ============================================================ */

TEST(test_ior_stream_closed) {
    _init_svc();
    _create_active_route();
    ASSERT_EQ(ozayn_ior_stream_closed(&_svc, "STRM-1"), OZAYN_IOR_OK);
    const ozayn_ior_route_t *r = ozayn_ior_route_get_by_stream(&_svc, "STRM-1");
    ASSERT(r == NULL);
    ASSERT_EQ(ozayn_ior_route_count(&_svc), 0);
    ozayn_ior_service_shutdown(&_svc);
    return 0;
}

TEST(test_ior_stream_closed_not_found) {
    _init_svc();
    ASSERT_EQ(ozayn_ior_stream_closed(&_svc, "NOPE"), OZAYN_IOR_ERR_NOT_FOUND);
    ozayn_ior_service_shutdown(&_svc);
    return 0;
}

TEST(test_ior_stream_closed_null) {
    _init_svc();
    ASSERT_EQ(ozayn_ior_stream_closed(&_svc, NULL), OZAYN_IOR_ERR_INVALID_PARAM);
    ASSERT_EQ(ozayn_ior_stream_closed(&_svc, ""), OZAYN_IOR_ERR_INVALID_PARAM);
    ozayn_ior_service_shutdown(&_svc);
    return 0;
}

TEST(test_ior_device_disconnected) {
    _init_svc();
    _register_endpoints();
    ozayn_ior_route_request_t req;
    _make_request(&req);
    ozayn_ior_route_t *r = NULL;
    ozayn_ior_route_create(&_svc, &req, &r);
    strncpy(r->device_id, "DEV-1", OZAYN_IOR_MAX_ID_LEN);
    ozayn_ior_route_authorize(&_svc, r->route_id);
    ozayn_ior_route_connect(&_svc, r->route_id);
    ozayn_ior_route_activate(&_svc, r->route_id);
    ASSERT_EQ(ozayn_ior_device_disconnected(&_svc, "DEV-1"), OZAYN_IOR_OK);
    ASSERT_EQ(ozayn_ior_route_count(&_svc), 0);
    ozayn_ior_service_shutdown(&_svc);
    return 0;
}

TEST(test_ior_device_disconnected_not_found) {
    _init_svc();
    ASSERT_EQ(ozayn_ior_device_disconnected(&_svc, "NOPE"), OZAYN_IOR_ERR_NOT_FOUND);
    ozayn_ior_service_shutdown(&_svc);
    return 0;
}

TEST(test_ior_device_disconnected_null) {
    _init_svc();
    ASSERT_EQ(ozayn_ior_device_disconnected(&_svc, NULL), OZAYN_IOR_ERR_INVALID_PARAM);
    ASSERT_EQ(ozayn_ior_device_disconnected(&_svc, ""), OZAYN_IOR_ERR_INVALID_PARAM);
    ozayn_ior_service_shutdown(&_svc);
    return 0;
}

/* ============================================================
 * LOOP DETECTION TESTS
 * ============================================================ */

TEST(test_ior_loop_detection_direct) {
    _init_svc();
    ozayn_ior_endpoint_t ep;
    memset(&ep, 0, sizeof(ep));
    strncpy(ep.endpoint_id, "L-A", OZAYN_IOR_MAX_ID_LEN);
    ep.type = OZAYN_IOR_ENDPOINT_DEVICE;
    ozayn_ior_endpoint_register(&_svc, &ep);
    memset(&ep, 0, sizeof(ep));
    strncpy(ep.endpoint_id, "L-B", OZAYN_IOR_MAX_ID_LEN);
    ep.type = OZAYN_IOR_ENDPOINT_STREAM;
    ozayn_ior_endpoint_register(&_svc, &ep);

    ozayn_ior_route_request_t req;
    _make_request(&req);
    strncpy(req.source_id, "L-A", OZAYN_IOR_MAX_ID_LEN);
    strncpy(req.destination_id, "L-B", OZAYN_IOR_MAX_ID_LEN);
    ozayn_ior_route_t *r1 = NULL;
    ozayn_ior_route_create(&_svc, &req, &r1);
    ozayn_ior_route_authorize(&_svc, r1->route_id);

    ozayn_ior_route_request_t req2;
    _make_request(&req2);
    strncpy(req2.source_id, "L-B", OZAYN_IOR_MAX_ID_LEN);
    strncpy(req2.destination_id, "L-A", OZAYN_IOR_MAX_ID_LEN);
    ozayn_ior_route_t *r2 = NULL;
    ozayn_ior_route_create(&_svc, &req2, &r2);
    ASSERT_EQ(ozayn_ior_route_authorize(&_svc, r2->route_id), OZAYN_IOR_ERR_LOOP_DETECTED);
    ozayn_ior_service_shutdown(&_svc);
    return 0;
}

/* ============================================================
 * EVENTS TESTS
 * ============================================================ */

TEST(test_ior_event_emit) {
    _init_svc();
    ASSERT_EQ(ozayn_ior_emit_event(&_svc, OZAYN_IOR_EVENT_ROUTE_REQUESTED,
        "R-1", "S-1", "A", "B", "test event"), OZAYN_IOR_OK);
    ASSERT_EQ(ozayn_ior_event_count(&_svc), 1);
    const ozayn_ior_event_t *e = ozayn_ior_event_get(&_svc, 0);
    ASSERT(e != NULL);
    ASSERT_EQ(e->type, OZAYN_IOR_EVENT_ROUTE_REQUESTED);
    ASSERT(strcmp(e->route_id, "R-1") == 0);
    ASSERT(strcmp(e->stream_id, "S-1") == 0);
    ASSERT(strcmp(e->source_id, "A") == 0);
    ASSERT(strcmp(e->destination_id, "B") == 0);
    ASSERT(strcmp(e->message, "test event") == 0);
    ozayn_ior_service_shutdown(&_svc);
    return 0;
}

TEST(test_ior_event_overflow) {
    _init_svc();
    for (int i = 0; i < 70; i++) {
        ozayn_ior_emit_event(&_svc, OZAYN_IOR_EVENT_ROUTE_REQUESTED,
            "R", "S", "A", "B", "msg");
    }
    ASSERT(ozayn_ior_event_count(&_svc) <= OZAYN_IOR_MAX_EVENTS);
    ozayn_ior_service_shutdown(&_svc);
    return 0;
}

TEST(test_ior_event_get_invalid_index) {
    _init_svc();
    ASSERT(ozayn_ior_event_get(&_svc, 0) == NULL);
    ASSERT(ozayn_ior_event_get(&_svc, -1) == NULL);
    ozayn_ior_service_shutdown(&_svc);
    return 0;
}

/* ============================================================
 * CLEANUP TESTS
 * ============================================================ */

TEST(test_ior_cleanup_expired) {
    _init_svc();
    _register_endpoints();
    ozayn_ior_route_request_t req;
    _make_request(&req);
    ozayn_ior_route_t *r = NULL;
    ozayn_ior_route_create(&_svc, &req, &r);
    r->expiry_time = time(NULL) - 1;
    int cleaned = ozayn_ior_cleanup_expired_routes(&_svc);
    ASSERT_EQ(cleaned, 1);
    ASSERT_EQ(ozayn_ior_route_count(&_svc), 0);
    ozayn_ior_service_shutdown(&_svc);
    return 0;
}

TEST(test_ior_cleanup_idle) {
    _init_svc();
    _create_active_route();
    const ozayn_ior_route_t *r = ozayn_ior_route_get_by_stream(&_svc, "STRM-1");
    ozayn_ior_route_pause(&_svc, r->route_id);
    char rid[OZAYN_IOR_MAX_ID_LEN];
    strncpy(rid, r->route_id, OZAYN_IOR_MAX_ID_LEN);
    const ozayn_ior_route_t *r2 = ozayn_ior_route_get(&_svc, rid);
    ((ozayn_ior_route_t *)r2)->last_activity_time = time(NULL) - 99999;
    ozayn_ior_service_shutdown(&_svc);
    _init_svc();
    _register_endpoints();
    ozayn_ior_route_request_t req;
    _make_request(&req);
    ozayn_ior_route_t *r3 = NULL;
    ozayn_ior_route_create(&_svc, &req, &r3);
    r3->last_activity_time = time(NULL) - 99999;
    ozayn_ior_route_authorize(&_svc, r3->route_id);
    ozayn_ior_route_connect(&_svc, r3->route_id);
    ozayn_ior_route_activate(&_svc, r3->route_id);
    r3->last_activity_time = time(NULL) - 99999;
    int cleaned = ozayn_ior_cleanup_idle_routes(&_svc);
    ASSERT(cleaned >= 0);
    ozayn_ior_service_shutdown(&_svc);
    return 0;
}

TEST(test_ior_cleanup_closed) {
    _init_svc();
    _create_active_route();
    const ozayn_ior_route_t *r = ozayn_ior_route_get_by_stream(&_svc, "STRM-1");
    ozayn_ior_route_disconnect(&_svc, r->route_id);
    int cleaned = ozayn_ior_cleanup_closed_routes(&_svc);
    ASSERT(cleaned >= 0);
    ozayn_ior_service_shutdown(&_svc);
    return 0;
}

TEST(test_ior_cleanup_all) {
    _init_svc();
    _create_active_route();
    ozayn_ior_route_request_t req;
    _make_request(&req);
    snprintf(req.stream_id, OZAYN_IOR_MAX_ID_LEN, "STRM-X");
    ozayn_ior_route_t *r2 = NULL;
    ozayn_ior_route_create(&_svc, &req, &r2);
    int cleaned = ozayn_ior_cleanup_all(&_svc);
    ASSERT(cleaned >= 0);
    ozayn_ior_service_shutdown(&_svc);
    return 0;
}

/* ============================================================
 * STATISTICS TESTS
 * ============================================================ */

TEST(test_ior_stats) {
    _init_svc();
    _create_active_route();
    ozayn_ior_stats_t stats;
    ASSERT_EQ(ozayn_ior_get_stats(&_svc, &stats), OZAYN_IOR_OK);
    ASSERT(stats.total_routes_created > 0);
    ASSERT(stats.endpoints_registered > 0);
    ASSERT(stats.total_state_transitions > 0);
    ozayn_ior_service_shutdown(&_svc);
    return 0;
}

TEST(test_ior_stats_null) {
    ASSERT_EQ(ozayn_ior_get_stats(NULL, NULL), OZAYN_IOR_ERR_NULL);
    return 0;
}

/* ============================================================
 * VALIDATION TESTS
 * ============================================================ */

TEST(test_ior_validate_route) {
    ozayn_ior_route_t r;
    memset(&r, 0, sizeof(r));
    ASSERT(!ozayn_ior_route_validate(&r));
    strncpy(r.route_id, "R-1", OZAYN_IOR_MAX_ID_LEN);
    strncpy(r.stream_id, "S-1", OZAYN_IOR_MAX_ID_LEN);
    strncpy(r.source_id, "A", OZAYN_IOR_MAX_ID_LEN);
    strncpy(r.destination_id, "B", OZAYN_IOR_MAX_ID_LEN);
    r.state = OZAYN_IOR_ROUTE_ACTIVE;
    r.created_time = time(NULL);
    ASSERT(ozayn_ior_route_validate(&r));
    ASSERT(!ozayn_ior_route_validate(NULL));
    return 0;
}

TEST(test_ior_validate_request) {
    ozayn_ior_route_request_t req;
    memset(&req, 0, sizeof(req));
    ASSERT(!ozayn_ior_route_request_validate(&req));
    strncpy(req.stream_id, "S-1", OZAYN_IOR_MAX_ID_LEN);
    strncpy(req.source_id, "A", OZAYN_IOR_MAX_ID_LEN);
    strncpy(req.destination_id, "B", OZAYN_IOR_MAX_ID_LEN);
    req.source_type = OZAYN_IOR_ENDPOINT_DEVICE;
    req.destination_type = OZAYN_IOR_ENDPOINT_STREAM;
    req.mode = OZAYN_IOR_MODE_ONE_TO_ONE;
    strncpy(req.requester_ref, "test", OZAYN_IOR_MAX_ID_LEN);
    ASSERT(ozayn_ior_route_request_validate(&req));
    ASSERT(!ozayn_ior_route_request_validate(NULL));
    return 0;
}

TEST(test_ior_state_transition_valid) {
    ASSERT(ozayn_ior_state_transition_valid(
        OZAYN_IOR_ROUTE_REQUESTED, OZAYN_IOR_ROUTE_VALIDATING));
    ASSERT(ozayn_ior_state_transition_valid(
        OZAYN_IOR_ROUTE_ACTIVE, OZAYN_IOR_ROUTE_PAUSED));
    ASSERT(!ozayn_ior_state_transition_valid(
        OZAYN_IOR_ROUTE_CLOSED, OZAYN_IOR_ROUTE_ACTIVE));
    ASSERT(!ozayn_ior_state_transition_valid(
        OZAYN_IOR_ROUTE_STATE_COUNT, 0));
    ASSERT(!ozayn_ior_state_transition_valid(
        0, OZAYN_IOR_ROUTE_STATE_COUNT));
    return 0;
}

/* ============================================================
 * NAME HELPER TESTS
 * ============================================================ */

TEST(test_ior_err_name) {
    ASSERT(strcmp(ozayn_ior_err_name(OZAYN_IOR_OK), "OK") == 0);
    ASSERT(strcmp(ozayn_ior_err_name(OZAYN_IOR_ERR_NULL), "NULL") == 0);
    ASSERT(strcmp(ozayn_ior_err_name(OZAYN_IOR_ERR_NOT_FOUND), "NOT_FOUND") == 0);
    ASSERT(strcmp(ozayn_ior_err_name((ozayn_ior_err_t)9999), "UNKNOWN") == 0);
    return 0;
}

TEST(test_ior_state_name) {
    ASSERT(strcmp(ozayn_ior_route_state_name(OZAYN_IOR_ROUTE_REQUESTED), "REQUESTED") == 0);
    ASSERT(strcmp(ozayn_ior_route_state_name(OZAYN_IOR_ROUTE_ACTIVE), "ACTIVE") == 0);
    ASSERT(strcmp(ozayn_ior_route_state_name(OZAYN_IOR_ROUTE_STATE_COUNT), "UNKNOWN") == 0);
    return 0;
}

TEST(test_ior_endpoint_type_name) {
    ASSERT(strcmp(ozayn_ior_endpoint_type_name(OZAYN_IOR_ENDPOINT_DEVICE), "DEVICE") == 0);
    ASSERT(strcmp(ozayn_ior_endpoint_type_name(OZAYN_IOR_ENDPOINT_COUNT), "UNKNOWN") == 0);
    return 0;
}

TEST(test_ior_close_reason_name) {
    ASSERT(strcmp(ozayn_ior_close_reason_name(OZAYN_IOR_CLOSE_NONE), "NONE") == 0);
    ASSERT(strcmp(ozayn_ior_close_reason_name(OZAYN_IOR_CLOSE_MANUAL_CLOSE), "MANUAL_CLOSE") == 0);
    ASSERT(strcmp(ozayn_ior_close_reason_name((ozayn_ior_close_reason_t)999), "UNKNOWN") == 0);
    return 0;
}

TEST(test_ior_event_type_name) {
    ASSERT(strcmp(ozayn_ior_event_type_name(OZAYN_IOR_EVENT_ROUTE_REQUESTED), "ROUTE_REQUESTED") == 0);
    ASSERT(strcmp(ozayn_ior_event_type_name((ozayn_ior_event_type_t)999), "UNKNOWN") == 0);
    return 0;
}

TEST(test_ior_mode_name) {
    ASSERT(strcmp(ozayn_ior_route_mode_name(OZAYN_IOR_MODE_ONE_TO_ONE), "ONE_TO_ONE") == 0);
    ASSERT(strcmp(ozayn_ior_route_mode_name(OZAYN_IOR_MODE_ONE_TO_MANY), "ONE_TO_MANY") == 0);
    ASSERT(strcmp(ozayn_ior_route_mode_name((ozayn_ior_route_mode_t)999), "UNKNOWN") == 0);
    return 0;
}

/* ============================================================
 * EDGE CASE TESTS
 * ============================================================ */

TEST(test_ior_connect_disconnect_from_connecting) {
    _init_svc();
    _register_endpoints();
    ozayn_ior_route_request_t req;
    _make_request(&req);
    ozayn_ior_route_t *r = NULL;
    ozayn_ior_route_create(&_svc, &req, &r);
    ozayn_ior_route_authorize(&_svc, r->route_id);
    ozayn_ior_route_connect(&_svc, r->route_id);
    ASSERT_EQ(r->state, OZAYN_IOR_ROUTE_CONNECTING);
    ASSERT_EQ(ozayn_ior_route_disconnect(&_svc, r->route_id), OZAYN_IOR_OK);
    ASSERT_EQ(r->state, OZAYN_IOR_ROUTE_CLOSED);
    ozayn_ior_service_shutdown(&_svc);
    return 0;
}

TEST(test_ior_multiple_routes) {
    _init_svc();
    _register_endpoints();
    for (int i = 0; i < 5; i++) {
        ozayn_ior_route_request_t req;
        _make_request(&req);
        snprintf(req.stream_id, OZAYN_IOR_MAX_ID_LEN, "M-%d", i);
        ozayn_ior_route_t *r = NULL;
        ozayn_ior_route_create(&_svc, &req, &r);
        ozayn_ior_route_authorize(&_svc, r->route_id);
        ozayn_ior_route_connect(&_svc, r->route_id);
        ozayn_ior_route_activate(&_svc, r->route_id);
    }
    ASSERT_EQ(ozayn_ior_route_count(&_svc), 5);
    ozayn_ior_stats_t stats;
    ozayn_ior_get_stats(&_svc, &stats);
    ASSERT_EQ(stats.current_active_routes, 5);
    ozayn_ior_service_shutdown(&_svc);
    return 0;
}

TEST(test_ior_one_to_many_mode) {
    _init_svc();
    _register_endpoints();
    ozayn_ior_route_request_t req;
    _make_request(&req);
    req.mode = OZAYN_IOR_MODE_ONE_TO_MANY;
    ozayn_ior_route_t *r = NULL;
    ASSERT_EQ(ozayn_ior_route_create(&_svc, &req, &r), OZAYN_IOR_OK);
    ASSERT_EQ(r->mode, OZAYN_IOR_MODE_ONE_TO_MANY);
    ozayn_ior_service_shutdown(&_svc);
    return 0;
}

TEST(test_ior_route_version) {
    _init_svc();
    _register_endpoints();
    ozayn_ior_route_request_t req;
    _make_request(&req);
    ozayn_ior_route_t *r = NULL;
    ozayn_ior_route_create(&_svc, &req, &r);
    ASSERT_EQ(r->version, 1u);
    ozayn_ior_service_shutdown(&_svc);
    return 0;
}

/* ============================================================
 * TEST RUNNER
 * ============================================================ */
int run_cr_io_router_tests(void)
{
    SUITE_BEGIN("I/O Router");

    RUN(test_ior_init);
    RUN(test_ior_init_null_svc);
    RUN(test_ior_init_null_cfg);
    RUN(test_ior_init_double);
    RUN(test_ior_not_initialized);
    RUN(test_ior_global);
    RUN(test_ior_shutdown_idempotent);

    RUN(test_ior_endpoint_register);
    RUN(test_ior_endpoint_register_null);
    RUN(test_ior_endpoint_register_no_id);
    RUN(test_ior_endpoint_register_bad_type);
    RUN(test_ior_endpoint_register_duplicate);
    RUN(test_ior_endpoint_unregister);
    RUN(test_ior_endpoint_unregister_not_found);
    RUN(test_ior_endpoint_unregister_null);
    RUN(test_ior_endpoint_get_not_found);
    RUN(test_ior_endpoint_is_available);
    RUN(test_ior_endpoint_not_available);
    RUN(test_ior_endpoint_limit);

    RUN(test_ior_route_create);
    RUN(test_ior_route_create_null_svc);
    RUN(test_ior_route_create_null_req);
    RUN(test_ior_route_create_null_out);
    RUN(test_ior_route_create_no_stream_id);
    RUN(test_ior_route_create_no_source_id);
    RUN(test_ior_route_create_no_dest_id);
    RUN(test_ior_route_create_no_requester);
    RUN(test_ior_route_create_bad_source_type);
    RUN(test_ior_route_create_bad_dest_type);
    RUN(test_ior_route_create_bad_mode);
    RUN(test_ior_route_create_same_src_dst);
    RUN(test_ior_route_create_limit);
    RUN(test_ior_route_metadata);

    RUN(test_ior_route_authorize);
    RUN(test_ior_route_authorize_null_id);
    RUN(test_ior_route_authorize_not_found);
    RUN(test_ior_route_authorize_no_source);
    RUN(test_ior_route_authorize_no_dest);
    RUN(test_ior_route_authorize_bad_state);
    RUN(test_ior_route_authorize_expired);

    RUN(test_ior_route_connect);
    RUN(test_ior_route_connect_not_authorized);
    RUN(test_ior_route_connect_not_found);

    RUN(test_ior_route_activate);
    RUN(test_ior_route_activate_not_connecting);
    RUN(test_ior_route_pause);
    RUN(test_ior_route_pause_not_active);
    RUN(test_ior_route_resume);
    RUN(test_ior_route_resume_not_paused);
    RUN(test_ior_route_disconnect);
    RUN(test_ior_route_disconnect_terminal);
    RUN(test_ior_route_close);
    RUN(test_ior_route_revoke);
    RUN(test_ior_route_remove_closed);
    RUN(test_ior_route_remove_active);
    RUN(test_ior_route_lifecycle_full);

    RUN(test_ior_route_get);
    RUN(test_ior_route_get_by_id);
    RUN(test_ior_route_get_by_stream_not_found);
    RUN(test_ior_route_get_by_source);
    RUN(test_ior_route_get_by_destination);
    RUN(test_ior_route_count);
    RUN(test_ior_route_count_by_stream);
    RUN(test_ior_route_is_active);
    RUN(test_ior_routes_for_stream);

    RUN(test_ior_stream_closed);
    RUN(test_ior_stream_closed_not_found);
    RUN(test_ior_stream_closed_null);
    RUN(test_ior_device_disconnected);
    RUN(test_ior_device_disconnected_not_found);
    RUN(test_ior_device_disconnected_null);

    RUN(test_ior_loop_detection_direct);

    RUN(test_ior_event_emit);
    RUN(test_ior_event_overflow);
    RUN(test_ior_event_get_invalid_index);

    RUN(test_ior_cleanup_expired);
    RUN(test_ior_cleanup_idle);
    RUN(test_ior_cleanup_closed);
    RUN(test_ior_cleanup_all);

    RUN(test_ior_stats);
    RUN(test_ior_stats_null);

    RUN(test_ior_validate_route);
    RUN(test_ior_validate_request);
    RUN(test_ior_state_transition_valid);

    RUN(test_ior_err_name);
    RUN(test_ior_state_name);
    RUN(test_ior_endpoint_type_name);
    RUN(test_ior_close_reason_name);
    RUN(test_ior_event_type_name);
    RUN(test_ior_mode_name);

    RUN(test_ior_connect_disconnect_from_connecting);
    RUN(test_ior_multiple_routes);
    RUN(test_ior_one_to_many_mode);
    RUN(test_ior_route_version);

    SUITE_END();
    return TOTAL_FAIL();
}
