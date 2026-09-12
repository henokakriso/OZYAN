#include "../io_stream.h"
#include "../../tests/test_framework.h"
#include <string.h>
#include <time.h>

/* ============================================================
 * HELPERS
 * ============================================================ */

static ozayn_ios_service_t _svc;
static ozayn_ios_service_config_t _cfg;

static void _reset_all(void)
{
    memset(&_svc, 0, sizeof(_svc));
}

static void _init_svc(void)
{
    _reset_all();
    memset(&_cfg, 0, sizeof(_cfg));
    ozayn_ios_service_init(&_svc, &_cfg);
}

static void _make_request(ozayn_ios_stream_request_t *req)
{
    memset(req, 0, sizeof(*req));
    strncpy(req->device_session_id, "DAS-1", OZAYN_IOS_MAX_ID_LEN - 1);
    strncpy(req->device_id, "CAM-1", OZAYN_IOS_MAX_ID_LEN - 1);
    strncpy(req->capability_id, "CAPTURE", OZAYN_IOS_MAX_ID_LEN - 1);
    req->direction = OZAYN_IOS_DIR_INPUT;
    req->data_type = OZAYN_IOS_DATA_CAMERA_FRAME;
    req->buffer_policy = OZAYN_IOS_POLICY_BLOCK;
    strncpy(req->requester_ref, "proc-1", OZAYN_IOS_MAX_ID_LEN - 1);
}

static ozayn_ios_stream_t *_create_stream(void)
{
    ozayn_ios_stream_request_t req;
    _make_request(&req);
    ozayn_ios_stream_t *s = NULL;
    ozayn_ios_stream_create(&_svc, &req, &s);
    return s;
}

/* ============================================================
 * LIFECYCLE TESTS
 * ============================================================ */

TEST(test_ios_init)
{
    _reset_all();
    memset(&_cfg, 0, sizeof(_cfg));
    ASSERT_EQ(ozayn_ios_service_init(&_svc, &_cfg), OZAYN_IOS_OK);
    ASSERT(ozayn_ios_service_is_initialized(&_svc));
    ozayn_ios_service_shutdown(&_svc);
    return 0;
}

TEST(test_ios_init_null)
{
    ASSERT_EQ(ozayn_ios_service_init(NULL, &_cfg), OZAYN_IOS_ERR_NULL);
    return 0;
}

TEST(test_ios_init_null_config)
{
    _reset_all();
    ASSERT_EQ(ozayn_ios_service_init(&_svc, NULL), OZAYN_IOS_ERR_NULL);
    return 0;
}

TEST(test_ios_init_double)
{
    _init_svc();
    ASSERT_EQ(ozayn_ios_service_init(&_svc, &_cfg), OZAYN_IOS_ERR_ALREADY_INIT);
    ozayn_ios_service_shutdown(&_svc);
    return 0;
}

TEST(test_ios_init_custom_config)
{
    _reset_all();
    memset(&_cfg, 0, sizeof(_cfg));
    _cfg.max_streams = 4;
    _cfg.stream_ttl_ms = 5000;
    ASSERT_EQ(ozayn_ios_service_init(&_svc, &_cfg), OZAYN_IOS_OK);
    ASSERT_EQ(_cfg.max_streams, 4);
    ASSERT_EQ(_svc.config.stream_ttl_ms, 5000);
    ozayn_ios_service_shutdown(&_svc);
    return 0;
}

TEST(test_ios_shutdown)
{
    _init_svc();
    ozayn_ios_service_shutdown(&_svc);
    ASSERT(!ozayn_ios_service_is_initialized(&_svc));
    return 0;
}

TEST(test_ios_shutdown_null)
{
    ozayn_ios_service_shutdown(NULL);
    return 0;
}

TEST(test_ios_is_initialized_null)
{
    ASSERT(!ozayn_ios_service_is_initialized(NULL));
    return 0;
}

TEST(test_ios_global_singleton)
{
    ozayn_ios_service_t *g = ozayn_ios_get_global();
    ASSERT_NOT_NULL(g);
    return 0;
}

/* ============================================================
 * STREAM CREATION TESTS
 * ============================================================ */

TEST(test_ios_stream_create)
{
    _init_svc();
    ozayn_ios_stream_request_t req;
    _make_request(&req);
    ozayn_ios_stream_t *s = NULL;
    ASSERT_EQ(ozayn_ios_stream_create(&_svc, &req, &s), OZAYN_IOS_OK);
    ASSERT_NOT_NULL(s);
    ASSERT_STR_EQ(s->device_id, "CAM-1");
    ASSERT_STR_EQ(s->capability_id, "CAPTURE");
    ASSERT_EQ(s->direction, OZAYN_IOS_DIR_INPUT);
    ASSERT_EQ(s->data_type, OZAYN_IOS_DATA_CAMERA_FRAME);
    ASSERT_EQ(s->state, OZAYN_IOS_STATE_REQUESTED);
    ASSERT(s->active);
    ASSERT_EQ(_svc.stream_count, 1);
    ozayn_ios_service_shutdown(&_svc);
    return 0;
}

TEST(test_ios_stream_create_null)
{
    ASSERT_EQ(ozayn_ios_stream_create(NULL, NULL, NULL), OZAYN_IOS_ERR_NULL);
    return 0;
}

TEST(test_ios_stream_create_not_init)
{
    _reset_all();
    ozayn_ios_stream_request_t req;
    _make_request(&req);
    ozayn_ios_stream_t *s = NULL;
    ASSERT_EQ(ozayn_ios_stream_create(&_svc, &req, &s),
              OZAYN_IOS_ERR_NOT_INITIALIZED);
    return 0;
}

TEST(test_ios_stream_create_null_req)
{
    _init_svc();
    ozayn_ios_stream_t *s = NULL;
    ASSERT_EQ(ozayn_ios_stream_create(&_svc, NULL, &s), OZAYN_IOS_ERR_NULL);
    ozayn_ios_service_shutdown(&_svc);
    return 0;
}

TEST(test_ios_stream_create_null_out)
{
    _init_svc();
    ozayn_ios_stream_request_t req;
    _make_request(&req);
    ASSERT_EQ(ozayn_ios_stream_create(&_svc, &req, NULL), OZAYN_IOS_ERR_NULL);
    ozayn_ios_service_shutdown(&_svc);
    return 0;
}

TEST(test_ios_stream_create_empty_session)
{
    _init_svc();
    ozayn_ios_stream_request_t req;
    _make_request(&req);
    req.device_session_id[0] = '\0';
    ozayn_ios_stream_t *s = NULL;
    ASSERT_EQ(ozayn_ios_stream_create(&_svc, &req, &s),
              OZAYN_IOS_ERR_INVALID_PARAM);
    ozayn_ios_service_shutdown(&_svc);
    return 0;
}

TEST(test_ios_stream_create_empty_device)
{
    _init_svc();
    ozayn_ios_stream_request_t req;
    _make_request(&req);
    req.device_id[0] = '\0';
    ozayn_ios_stream_t *s = NULL;
    ASSERT_EQ(ozayn_ios_stream_create(&_svc, &req, &s),
              OZAYN_IOS_ERR_INVALID_PARAM);
    ozayn_ios_service_shutdown(&_svc);
    return 0;
}

TEST(test_ios_stream_create_empty_capability)
{
    _init_svc();
    ozayn_ios_stream_request_t req;
    _make_request(&req);
    req.capability_id[0] = '\0';
    ozayn_ios_stream_t *s = NULL;
    ASSERT_EQ(ozayn_ios_stream_create(&_svc, &req, &s),
              OZAYN_IOS_ERR_INVALID_PARAM);
    ozayn_ios_service_shutdown(&_svc);
    return 0;
}

TEST(test_ios_stream_create_empty_requester)
{
    _init_svc();
    ozayn_ios_stream_request_t req;
    _make_request(&req);
    req.requester_ref[0] = '\0';
    ozayn_ios_stream_t *s = NULL;
    ASSERT_EQ(ozayn_ios_stream_create(&_svc, &req, &s),
              OZAYN_IOS_ERR_INVALID_PARAM);
    ozayn_ios_service_shutdown(&_svc);
    return 0;
}

TEST(test_ios_stream_create_invalid_direction)
{
    _init_svc();
    ozayn_ios_stream_request_t req;
    _make_request(&req);
    req.direction = (ozayn_ios_direction_t)99;
    ozayn_ios_stream_t *s = NULL;
    ASSERT_EQ(ozayn_ios_stream_create(&_svc, &req, &s),
              OZAYN_IOS_ERR_INVALID_PARAM);
    ozayn_ios_service_shutdown(&_svc);
    return 0;
}

TEST(test_ios_stream_create_invalid_data_type)
{
    _init_svc();
    ozayn_ios_stream_request_t req;
    _make_request(&req);
    req.data_type = (ozayn_ios_data_type_t)99;
    ozayn_ios_stream_t *s = NULL;
    ASSERT_EQ(ozayn_ios_stream_create(&_svc, &req, &s),
              OZAYN_IOS_ERR_INVALID_PARAM);
    ozayn_ios_service_shutdown(&_svc);
    return 0;
}

TEST(test_ios_stream_create_invalid_buffer_policy)
{
    _init_svc();
    ozayn_ios_stream_request_t req;
    _make_request(&req);
    req.buffer_policy = (ozayn_ios_buffer_policy_t)99;
    ozayn_ios_stream_t *s = NULL;
    ASSERT_EQ(ozayn_ios_stream_create(&_svc, &req, &s),
              OZAYN_IOS_ERR_INVALID_PARAM);
    ozayn_ios_service_shutdown(&_svc);
    return 0;
}

TEST(test_ios_stream_create_limit)
{
    _reset_all();
    memset(&_cfg, 0, sizeof(_cfg));
    _cfg.max_streams = 2;
    ozayn_ios_service_init(&_svc, &_cfg);
    ozayn_ios_stream_request_t req;
    _make_request(&req);
    ozayn_ios_stream_t *s1 = NULL, *s2 = NULL, *s3 = NULL;
    ASSERT_EQ(ozayn_ios_stream_create(&_svc, &req, &s1), OZAYN_IOS_OK);
    ASSERT_EQ(ozayn_ios_stream_create(&_svc, &req, &s2), OZAYN_IOS_OK);
    ASSERT_EQ(ozayn_ios_stream_create(&_svc, &req, &s3),
              OZAYN_IOS_ERR_LIMIT_REACHED);
    ozayn_ios_service_shutdown(&_svc);
    return 0;
}

TEST(test_ios_stream_create_emits_event)
{
    _init_svc();
    ozayn_ios_stream_request_t req;
    _make_request(&req);
    ozayn_ios_stream_t *s = NULL;
    ozayn_ios_stream_create(&_svc, &req, &s);
    ASSERT_GE(ozayn_ios_event_count(&_svc), 1);
    const ozayn_ios_event_t *ev = ozayn_ios_event_get(&_svc, 0);
    ASSERT_NOT_NULL(ev);
    ASSERT_EQ(ev->type, OZAYN_IOS_EVENT_STREAM_REQUESTED);
    ozayn_ios_service_shutdown(&_svc);
    return 0;
}

/* ============================================================
 * FULL LIFECYCLE TESTS
 * ============================================================ */

TEST(test_ios_full_lifecycle)
{
    _init_svc();
    ozayn_ios_stream_request_t req;
    _make_request(&req);
    ozayn_ios_stream_t *s = NULL;
    ASSERT_EQ(ozayn_ios_stream_create(&_svc, &req, &s), OZAYN_IOS_OK);
    ASSERT_EQ(s->state, OZAYN_IOS_STATE_REQUESTED);

    ASSERT_EQ(ozayn_ios_stream_authorize(&_svc, s->stream_id), OZAYN_IOS_OK);
    ASSERT_EQ(s->state, OZAYN_IOS_STATE_AUTHORIZED);

    ASSERT_EQ(ozayn_ios_stream_open(&_svc, s->stream_id), OZAYN_IOS_OK);
    ASSERT_EQ(s->state, OZAYN_IOS_STATE_OPENING);

    ASSERT_EQ(ozayn_ios_stream_activate(&_svc, s->stream_id), OZAYN_IOS_OK);
    ASSERT_EQ(s->state, OZAYN_IOS_STATE_ACTIVE);

    ASSERT_EQ(ozayn_ios_stream_close(&_svc, s->stream_id,
              OZAYN_IOS_CLOSE_MANUAL_CLOSE), OZAYN_IOS_OK);
    ASSERT_EQ(s->state, OZAYN_IOS_STATE_CLOSED);
    ASSERT(!s->active);
    ASSERT_EQ(_svc.stream_count, 0);
    ozayn_ios_service_shutdown(&_svc);
    return 0;
}

TEST(test_ios_pause_resume)
{
    _init_svc();
    ozayn_ios_stream_t *s = _create_stream();
    ozayn_ios_stream_authorize(&_svc, s->stream_id);
    ozayn_ios_stream_open(&_svc, s->stream_id);
    ozayn_ios_stream_activate(&_svc, s->stream_id);

    ASSERT_EQ(ozayn_ios_stream_pause(&_svc, s->stream_id), OZAYN_IOS_OK);
    ASSERT_EQ(s->state, OZAYN_IOS_STATE_PAUSED);

    ASSERT_EQ(ozayn_ios_stream_resume(&_svc, s->stream_id), OZAYN_IOS_OK);
    ASSERT_EQ(s->state, OZAYN_IOS_STATE_ACTIVE);
    ozayn_ios_service_shutdown(&_svc);
    return 0;
}

TEST(test_ios_drain)
{
    _init_svc();
    ozayn_ios_stream_t *s = _create_stream();
    ozayn_ios_stream_authorize(&_svc, s->stream_id);
    ozayn_ios_stream_open(&_svc, s->stream_id);
    ozayn_ios_stream_activate(&_svc, s->stream_id);

    ASSERT_EQ(ozayn_ios_stream_drain(&_svc, s->stream_id), OZAYN_IOS_OK);
    ASSERT_EQ(s->state, OZAYN_IOS_STATE_DRAINING);
    ozayn_ios_service_shutdown(&_svc);
    return 0;
}

TEST(test_ios_authorize_from_wrong_state)
{
    _init_svc();
    ozayn_ios_stream_t *s = _create_stream();
    ASSERT_EQ(ozayn_ios_stream_authorize(&_svc, s->stream_id), OZAYN_IOS_OK);
    ASSERT_EQ(ozayn_ios_stream_open(&_svc, s->stream_id), OZAYN_IOS_OK);
    ASSERT_EQ(ozayn_ios_stream_activate(&_svc, s->stream_id), OZAYN_IOS_OK);
    ASSERT_EQ(ozayn_ios_stream_authorize(&_svc, s->stream_id),
              OZAYN_IOS_ERR_STATE_INVALID);
    ozayn_ios_service_shutdown(&_svc);
    return 0;
}

TEST(test_ios_open_from_wrong_state)
{
    _init_svc();
    ozayn_ios_stream_t *s = _create_stream();
    ASSERT_EQ(ozayn_ios_stream_open(&_svc, s->stream_id),
              OZAYN_IOS_ERR_STATE_INVALID);
    ozayn_ios_service_shutdown(&_svc);
    return 0;
}

TEST(test_ios_activate_from_wrong_state)
{
    _init_svc();
    ozayn_ios_stream_t *s = _create_stream();
    ASSERT_EQ(ozayn_ios_stream_activate(&_svc, s->stream_id),
              OZAYN_IOS_ERR_STATE_INVALID);
    ozayn_ios_service_shutdown(&_svc);
    return 0;
}

TEST(test_ios_pause_from_wrong_state)
{
    _init_svc();
    ozayn_ios_stream_t *s = _create_stream();
    ASSERT_EQ(ozayn_ios_stream_pause(&_svc, s->stream_id),
              OZAYN_IOS_ERR_STATE_INVALID);
    ozayn_ios_service_shutdown(&_svc);
    return 0;
}

TEST(test_ios_resume_from_wrong_state)
{
    _init_svc();
    ozayn_ios_stream_t *s = _create_stream();
    ASSERT_EQ(ozayn_ios_stream_resume(&_svc, s->stream_id),
              OZAYN_IOS_ERR_STATE_INVALID);
    ozayn_ios_service_shutdown(&_svc);
    return 0;
}

TEST(test_ios_drain_from_wrong_state)
{
    _init_svc();
    ozayn_ios_stream_t *s = _create_stream();
    ASSERT_EQ(ozayn_ios_stream_drain(&_svc, s->stream_id),
              OZAYN_IOS_ERR_STATE_INVALID);
    ozayn_ios_service_shutdown(&_svc);
    return 0;
}

/* ============================================================
 * CLOSE / REVOKE TESTS
 * ============================================================ */

TEST(test_ios_revoke)
{
    _init_svc();
    ozayn_ios_stream_t *s = _create_stream();
    ozayn_ios_stream_authorize(&_svc, s->stream_id);
    ozayn_ios_stream_open(&_svc, s->stream_id);
    ozayn_ios_stream_activate(&_svc, s->stream_id);

    ASSERT_EQ(ozayn_ios_stream_revoke(&_svc, s->stream_id,
              OZAYN_IOS_CLOSE_SESSION_REVOKED), OZAYN_IOS_OK);
    ASSERT_EQ(s->state, OZAYN_IOS_STATE_REVOKED);
    ASSERT_EQ(s->close_reason, OZAYN_IOS_CLOSE_SESSION_REVOKED);
    ASSERT(!s->active);
    ozayn_ios_service_shutdown(&_svc);
    return 0;
}

TEST(test_ios_close_from_terminal)
{
    _init_svc();
    ozayn_ios_stream_t *s = _create_stream();
    ozayn_ios_stream_close(&_svc, s->stream_id, OZAYN_IOS_CLOSE_MANUAL_CLOSE);
    ASSERT_EQ(ozayn_ios_stream_close(&_svc, s->stream_id,
              OZAYN_IOS_CLOSE_MANUAL_CLOSE), OZAYN_IOS_ERR_NOT_FOUND);
    ASSERT_EQ(ozayn_ios_stream_revoke(&_svc, s->stream_id,
              OZAYN_IOS_CLOSE_TIMEOUT), OZAYN_IOS_ERR_NOT_FOUND);
    ozayn_ios_service_shutdown(&_svc);
    return 0;
}

/* ============================================================
 * DATA FLOW TESTS
 * ============================================================ */

TEST(test_ios_push_pull_data)
{
    _init_svc();
    ozayn_ios_stream_t *s = _create_stream();
    ozayn_ios_stream_authorize(&_svc, s->stream_id);
    ozayn_ios_stream_open(&_svc, s->stream_id);
    ozayn_ios_stream_activate(&_svc, s->stream_id);

    ozayn_ios_data_unit_t unit;
    memset(&unit, 0, sizeof(unit));
    strncpy(unit.stream_id, s->stream_id, OZAYN_IOS_MAX_ID_LEN - 1);
    unit.payload_size = 100;
    unit.data_type = OZAYN_IOS_DATA_CAMERA_FRAME;

    ASSERT_EQ(ozayn_ios_stream_push_data(&_svc, s->stream_id, &unit),
              OZAYN_IOS_OK);
    ASSERT_EQ(s->queue_depth, 1);
    ASSERT_EQ(s->total_units_produced, (uint64_t)1);

    ozayn_ios_data_unit_t out;
    memset(&out, 0, sizeof(out));
    ASSERT_EQ(ozayn_ios_stream_pull_data(&_svc, s->stream_id, &out),
              OZAYN_IOS_OK);
    ASSERT_EQ(s->queue_depth, 0);
    ASSERT_EQ(s->total_units_consumed, (uint64_t)1);
    ozayn_ios_service_shutdown(&_svc);
    return 0;
}

TEST(test_ios_push_data_wrong_state)
{
    _init_svc();
    ozayn_ios_stream_t *s = _create_stream();

    ozayn_ios_data_unit_t unit;
    memset(&unit, 0, sizeof(unit));
    unit.payload_size = 100;

    ASSERT_EQ(ozayn_ios_stream_push_data(&_svc, s->stream_id, &unit),
              OZAYN_IOS_ERR_STATE_INVALID);
    ozayn_ios_service_shutdown(&_svc);
    return 0;
}

TEST(test_ios_pull_data_wrong_state)
{
    _init_svc();
    ozayn_ios_stream_t *s = _create_stream();

    ozayn_ios_data_unit_t out;
    memset(&out, 0, sizeof(out));
    ASSERT_EQ(ozayn_ios_stream_pull_data(&_svc, s->stream_id, &out),
              OZAYN_IOS_ERR_STATE_INVALID);
    ozayn_ios_service_shutdown(&_svc);
    return 0;
}

TEST(test_ios_push_data_buffer_limit)
{
    _reset_all();
    memset(&_cfg, 0, sizeof(_cfg));
    _cfg.default_max_buffer_size = 500;
    ozayn_ios_service_init(&_svc, &_cfg);

    ozayn_ios_stream_t *s = _create_stream();
    ozayn_ios_stream_authorize(&_svc, s->stream_id);
    ozayn_ios_stream_open(&_svc, s->stream_id);
    ozayn_ios_stream_activate(&_svc, s->stream_id);

    ozayn_ios_data_unit_t unit;
    memset(&unit, 0, sizeof(unit));
    unit.payload_size = 400;
    ASSERT_EQ(ozayn_ios_stream_push_data(&_svc, s->stream_id, &unit),
              OZAYN_IOS_OK);

    unit.payload_size = 200;
    ASSERT_EQ(ozayn_ios_stream_push_data(&_svc, s->stream_id, &unit),
              OZAYN_IOS_ERR_BACKPRESSURE);
    ASSERT_EQ(s->state, OZAYN_IOS_STATE_BACKPRESSURED);
    ozayn_ios_service_shutdown(&_svc);
    return 0;
}

TEST(test_ios_push_data_drop_newest)
{
    _reset_all();
    memset(&_cfg, 0, sizeof(_cfg));
    _cfg.default_max_queue_depth = 2;
    ozayn_ios_service_init(&_svc, &_cfg);

    ozayn_ios_stream_request_t req;
    _make_request(&req);
    req.buffer_policy = OZAYN_IOS_POLICY_DROP_NEWEST;
    ozayn_ios_stream_t *s = NULL;
    ozayn_ios_stream_create(&_svc, &req, &s);
    ozayn_ios_stream_authorize(&_svc, s->stream_id);
    ozayn_ios_stream_open(&_svc, s->stream_id);
    ozayn_ios_stream_activate(&_svc, s->stream_id);

    ozayn_ios_data_unit_t unit;
    memset(&unit, 0, sizeof(unit));
    unit.payload_size = 10;
    ASSERT_EQ(ozayn_ios_stream_push_data(&_svc, s->stream_id, &unit),
              OZAYN_IOS_OK);
    ASSERT_EQ(ozayn_ios_stream_push_data(&_svc, s->stream_id, &unit),
              OZAYN_IOS_OK);
    ASSERT_EQ(ozayn_ios_stream_push_data(&_svc, s->stream_id, &unit),
              OZAYN_IOS_ERR_OVERFLOW);
    ASSERT_EQ(s->total_units_dropped, (uint64_t)1);
    ozayn_ios_service_shutdown(&_svc);
    return 0;
}

TEST(test_ios_push_data_fail_stream)
{
    _reset_all();
    memset(&_cfg, 0, sizeof(_cfg));
    _cfg.default_max_queue_depth = 1;
    ozayn_ios_service_init(&_svc, &_cfg);

    ozayn_ios_stream_request_t req;
    _make_request(&req);
    req.buffer_policy = OZAYN_IOS_POLICY_FAIL_STREAM;
    ozayn_ios_stream_t *s = NULL;
    ozayn_ios_stream_create(&_svc, &req, &s);
    ozayn_ios_stream_authorize(&_svc, s->stream_id);
    ozayn_ios_stream_open(&_svc, s->stream_id);
    ozayn_ios_stream_activate(&_svc, s->stream_id);

    ozayn_ios_data_unit_t unit;
    memset(&unit, 0, sizeof(unit));
    unit.payload_size = 10;
    ASSERT_EQ(ozayn_ios_stream_push_data(&_svc, s->stream_id, &unit),
              OZAYN_IOS_OK);
    ASSERT_EQ(ozayn_ios_stream_push_data(&_svc, s->stream_id, &unit),
              OZAYN_IOS_ERR_OVERFLOW);
    ASSERT_EQ(s->state, OZAYN_IOS_STATE_FAILED);
    ASSERT(!s->active);
    ozayn_ios_service_shutdown(&_svc);
    return 0;
}

TEST(test_ios_push_data_size_limit)
{
    _init_svc();
    ozayn_ios_stream_t *s = _create_stream();
    ozayn_ios_stream_authorize(&_svc, s->stream_id);
    ozayn_ios_stream_open(&_svc, s->stream_id);
    ozayn_ios_stream_activate(&_svc, s->stream_id);

    ozayn_ios_data_unit_t unit;
    memset(&unit, 0, sizeof(unit));
    unit.payload_size = s->max_data_size + 1;
    ASSERT_EQ(ozayn_ios_stream_push_data(&_svc, s->stream_id, &unit),
              OZAYN_IOS_ERR_BUFFER_LIMIT);
    ozayn_ios_service_shutdown(&_svc);
    return 0;
}

TEST(test_ios_heartbeat)
{
    _init_svc();
    ozayn_ios_stream_t *s = _create_stream();
    ozayn_ios_stream_authorize(&_svc, s->stream_id);
    ozayn_ios_stream_open(&_svc, s->stream_id);
    ozayn_ios_stream_activate(&_svc, s->stream_id);

    ASSERT_EQ(ozayn_ios_stream_heartbeat(&_svc, s->stream_id), OZAYN_IOS_OK);
    ozayn_ios_service_shutdown(&_svc);
    return 0;
}

TEST(test_ios_heartbeat_wrong_state)
{
    _init_svc();
    ozayn_ios_stream_t *s = _create_stream();
    ASSERT_EQ(ozayn_ios_stream_heartbeat(&_svc, s->stream_id),
              OZAYN_IOS_ERR_STATE_INVALID);
    ozayn_ios_service_shutdown(&_svc);
    return 0;
}

/* ============================================================
 * PRODUCER / CONSUMER TESTS
 * ============================================================ */

TEST(test_ios_attach_detach_producer)
{
    _init_svc();
    ozayn_ios_stream_t *s = _create_stream();
    ASSERT_EQ(ozayn_ios_stream_attach_producer(&_svc, s->stream_id,
              "prod-1"), OZAYN_IOS_OK);
    ASSERT_STR_EQ(s->producer_ref, "prod-1");
    ASSERT_EQ(ozayn_ios_stream_detach_producer(&_svc, s->stream_id),
              OZAYN_IOS_OK);
    ASSERT(s->producer_ref[0] == '\0');
    ozayn_ios_service_shutdown(&_svc);
    return 0;
}

TEST(test_ios_attach_detach_consumer)
{
    _init_svc();
    ozayn_ios_stream_t *s = _create_stream();
    ASSERT_EQ(ozayn_ios_stream_attach_consumer(&_svc, s->stream_id,
              "cons-1"), OZAYN_IOS_OK);
    ASSERT_STR_EQ(s->consumer_ref, "cons-1");
    ASSERT_EQ(ozayn_ios_stream_detach_consumer(&_svc, s->stream_id),
              OZAYN_IOS_OK);
    ASSERT(s->consumer_ref[0] == '\0');
    ozayn_ios_service_shutdown(&_svc);
    return 0;
}

TEST(test_ios_attach_producer_terminal)
{
    _init_svc();
    ozayn_ios_stream_t *s = _create_stream();
    ozayn_ios_stream_close(&_svc, s->stream_id, OZAYN_IOS_CLOSE_MANUAL_CLOSE);
    ASSERT_EQ(ozayn_ios_stream_attach_producer(&_svc, s->stream_id,
              "prod-1"), OZAYN_IOS_ERR_NOT_FOUND);
    ozayn_ios_service_shutdown(&_svc);
    return 0;
}

TEST(test_ios_attach_consumer_terminal)
{
    _init_svc();
    ozayn_ios_stream_t *s = _create_stream();
    ozayn_ios_stream_close(&_svc, s->stream_id, OZAYN_IOS_CLOSE_MANUAL_CLOSE);
    ASSERT_EQ(ozayn_ios_stream_attach_consumer(&_svc, s->stream_id,
              "cons-1"), OZAYN_IOS_ERR_NOT_FOUND);
    ozayn_ios_service_shutdown(&_svc);
    return 0;
}

/* ============================================================
 * DEVICE DISCONNECT TESTS
 * ============================================================ */

TEST(test_ios_device_disconnected)
{
    _init_svc();
    ozayn_ios_stream_t *s = _create_stream();
    ozayn_ios_stream_authorize(&_svc, s->stream_id);
    ozayn_ios_stream_open(&_svc, s->stream_id);
    ozayn_ios_stream_activate(&_svc, s->stream_id);

    ASSERT_EQ(ozayn_ios_stream_device_disconnected(&_svc, s->stream_id),
              OZAYN_IOS_OK);
    ASSERT_EQ(s->state, OZAYN_IOS_STATE_UNAVAILABLE);
    ASSERT_EQ(s->close_reason, OZAYN_IOS_CLOSE_DEVICE_DISCONNECTED);
    ASSERT(s->active);
    ozayn_ios_service_shutdown(&_svc);
    return 0;
}

TEST(test_ios_device_disconnected_terminal)
{
    _init_svc();
    ozayn_ios_stream_t *s = _create_stream();
    ozayn_ios_stream_close(&_svc, s->stream_id, OZAYN_IOS_CLOSE_MANUAL_CLOSE);
    ASSERT_EQ(ozayn_ios_stream_device_disconnected(&_svc, s->stream_id),
              OZAYN_IOS_ERR_NOT_FOUND);
    ozayn_ios_service_shutdown(&_svc);
    return 0;
}

TEST(test_ios_device_reconnected)
{
    _init_svc();
    ozayn_ios_stream_t *s = _create_stream();
    ozayn_ios_stream_authorize(&_svc, s->stream_id);
    ozayn_ios_stream_open(&_svc, s->stream_id);
    ozayn_ios_stream_activate(&_svc, s->stream_id);
    ozayn_ios_stream_device_disconnected(&_svc, s->stream_id);

    ASSERT_EQ(ozayn_ios_stream_device_reconnected(&_svc, s->stream_id),
              OZAYN_IOS_OK);

    ASSERT_EQ(ozayn_ios_stream_device_reconnected(&_svc, "NOPE"),
              OZAYN_IOS_ERR_NOT_FOUND);
    ozayn_ios_service_shutdown(&_svc);
    return 0;
}

TEST(test_ios_device_reconnected_wrong_state)
{
    _init_svc();
    ozayn_ios_stream_t *s = _create_stream();
    ASSERT_EQ(ozayn_ios_stream_device_reconnected(&_svc, s->stream_id),
              OZAYN_IOS_ERR_STATE_INVALID);
    ozayn_ios_service_shutdown(&_svc);
    return 0;
}

/* ============================================================
 * SESSION CHANGE TESTS
 * ============================================================ */

TEST(test_ios_streams_for_session)
{
    _init_svc();
    ozayn_ios_stream_request_t req;
    _make_request(&req);
    ozayn_ios_stream_t *s1 = NULL, *s2 = NULL;
    ozayn_ios_stream_create(&_svc, &req, &s1);
    ozayn_ios_stream_create(&_svc, &req, &s2);

    ozayn_ios_stream_t *out[4];
    int count = ozayn_ios_streams_for_session(&_svc, "DAS-1", out, 4);
    ASSERT_EQ(count, 2);
    ozayn_ios_service_shutdown(&_svc);
    return 0;
}

/* ============================================================
 * QUERY TESTS
 * ============================================================ */

TEST(test_ios_get)
{
    _init_svc();
    ozayn_ios_stream_t *s = _create_stream();
    ASSERT_NOT_NULL(ozayn_ios_stream_get(&_svc, s->stream_id));
    ASSERT_NULL(ozayn_ios_stream_get(&_svc, "NOPE"));
    ozayn_ios_service_shutdown(&_svc);
    return 0;
}

TEST(test_ios_get_by_device)
{
    _init_svc();
    _create_stream();
    ASSERT_NOT_NULL(ozayn_ios_stream_get_by_device(&_svc, "CAM-1"));
    ASSERT_NULL(ozayn_ios_stream_get_by_device(&_svc, "NOPE"));
    ozayn_ios_service_shutdown(&_svc);
    return 0;
}

TEST(test_ios_get_by_session)
{
    _init_svc();
    _create_stream();
    ASSERT_NOT_NULL(ozayn_ios_stream_get_by_session(&_svc, "DAS-1"));
    ASSERT_NULL(ozayn_ios_stream_get_by_session(&_svc, "NOPE"));
    ozayn_ios_service_shutdown(&_svc);
    return 0;
}

TEST(test_ios_count)
{
    _init_svc();
    ASSERT_EQ(ozayn_ios_stream_count(&_svc), 0);
    _create_stream();
    ASSERT_EQ(ozayn_ios_stream_count(&_svc), 1);
    _create_stream();
    ASSERT_EQ(ozayn_ios_stream_count(&_svc), 2);
    ozayn_ios_service_shutdown(&_svc);
    return 0;
}

TEST(test_ios_count_by_device)
{
    _init_svc();
    _create_stream();
    _create_stream();
    ASSERT_EQ(ozayn_ios_stream_count_by_device(&_svc, "CAM-1"), 2);
    ASSERT_EQ(ozayn_ios_stream_count_by_device(&_svc, "NOPE"), 0);
    ozayn_ios_service_shutdown(&_svc);
    return 0;
}

TEST(test_ios_is_active)
{
    _init_svc();
    ozayn_ios_stream_t *s = _create_stream();
    ASSERT(!ozayn_ios_stream_is_active(&_svc, s->stream_id));
    ozayn_ios_stream_authorize(&_svc, s->stream_id);
    ozayn_ios_stream_open(&_svc, s->stream_id);
    ozayn_ios_stream_activate(&_svc, s->stream_id);
    ASSERT(ozayn_ios_stream_is_active(&_svc, s->stream_id));
    ASSERT(!ozayn_ios_stream_is_active(&_svc, "NOPE"));
    ozayn_ios_service_shutdown(&_svc);
    return 0;
}

TEST(test_ios_is_expired)
{
    _init_svc();
    ozayn_ios_stream_t *s = _create_stream();
    ASSERT(!ozayn_ios_stream_is_expired(&_svc, s->stream_id));
    ASSERT(!ozayn_ios_stream_is_expired(&_svc, "NOPE"));
    ozayn_ios_service_shutdown(&_svc);
    return 0;
}

/* ============================================================
 * CLEANUP TESTS
 * ============================================================ */

TEST(test_ios_cleanup_expired)
{
    _reset_all();
    memset(&_cfg, 0, sizeof(_cfg));
    _cfg.stream_ttl_ms = 1000;
    ozayn_ios_service_init(&_svc, &_cfg);

    _create_stream();

    struct timespec ts = {2, 0};
    nanosleep(&ts, NULL);

    int cleaned = ozayn_ios_cleanup_expired_streams(&_svc);
    ASSERT(cleaned >= 1);
    ozayn_ios_service_shutdown(&_svc);
    return 0;
}

TEST(test_ios_cleanup_idle)
{
    _reset_all();
    memset(&_cfg, 0, sizeof(_cfg));
    _cfg.idle_timeout_ms = 1000;
    ozayn_ios_service_init(&_svc, &_cfg);

    ozayn_ios_stream_t *s = _create_stream();
    ozayn_ios_stream_authorize(&_svc, s->stream_id);
    ozayn_ios_stream_open(&_svc, s->stream_id);
    ozayn_ios_stream_activate(&_svc, s->stream_id);

    struct timespec ts = {2, 0};
    nanosleep(&ts, NULL);

    int cleaned = ozayn_ios_cleanup_idle_streams(&_svc);
    ASSERT(cleaned >= 1);
    ozayn_ios_service_shutdown(&_svc);
    return 0;
}

TEST(test_ios_cleanup_closed)
{
    _init_svc();
    ozayn_ios_stream_t *s = _create_stream();
    ozayn_ios_stream_close(&_svc, s->stream_id, OZAYN_IOS_CLOSE_MANUAL_CLOSE);
    int cleaned = ozayn_ios_cleanup_closed_streams(&_svc);
    ASSERT(cleaned >= 1);
    ozayn_ios_service_shutdown(&_svc);
    return 0;
}

TEST(test_ios_cleanup_null)
{
    ASSERT_EQ(ozayn_ios_cleanup_expired_streams(NULL), 0);
    ASSERT_EQ(ozayn_ios_cleanup_idle_streams(NULL), 0);
    ASSERT_EQ(ozayn_ios_cleanup_closed_streams(NULL), 0);
    ASSERT_EQ(ozayn_ios_cleanup_all(NULL), 0);
    return 0;
}

/* ============================================================
 * EVENT TESTS
 * ============================================================ */

TEST(test_ios_emit_event)
{
    _init_svc();
    ASSERT_EQ(ozayn_ios_emit_event(&_svc, OZAYN_IOS_EVENT_STREAM_REQUESTED,
              "S-1", "D-1", "SS-1", "test event"), OZAYN_IOS_OK);
    ASSERT_EQ(ozayn_ios_event_count(&_svc), 1);
    const ozayn_ios_event_t *ev = ozayn_ios_event_get(&_svc, 0);
    ASSERT_NOT_NULL(ev);
    ASSERT_EQ(ev->type, OZAYN_IOS_EVENT_STREAM_REQUESTED);
    ozayn_ios_service_shutdown(&_svc);
    return 0;
}

TEST(test_ios_event_ring_buffer)
{
    _init_svc();
    for (int i = 0; i < 70; i++) {
        ozayn_ios_emit_event(&_svc, OZAYN_IOS_EVENT_STREAM_ACTIVE,
                              "S-1", "D-1", "SS-1", "event");
    }
    ASSERT_EQ(ozayn_ios_event_count(&_svc), OZAYN_IOS_MAX_EVENTS);
    ozayn_ios_service_shutdown(&_svc);
    return 0;
}

TEST(test_ios_event_get_invalid)
{
    _init_svc();
    ASSERT_NULL(ozayn_ios_event_get(&_svc, 0));
    ASSERT_NULL(ozayn_ios_event_get(&_svc, -1));
    ozayn_ios_service_shutdown(&_svc);
    return 0;
}

/* ============================================================
 * STATISTICS TESTS
 * ============================================================ */

TEST(test_ios_stats)
{
    _init_svc();
    ozayn_ios_stats_t stats;
    ASSERT_EQ(ozayn_ios_get_stats(&_svc, &stats), OZAYN_IOS_OK);
    ASSERT_EQ(stats.total_streams_created, 0);

    _create_stream();
    ASSERT_EQ(ozayn_ios_get_stats(&_svc, &stats), OZAYN_IOS_OK);
    ASSERT_EQ(stats.total_streams_created, 1);
    ASSERT_EQ(stats.current_active_streams, 1);
    ozayn_ios_service_shutdown(&_svc);
    return 0;
}

TEST(test_ios_stats_null)
{
    ASSERT_EQ(ozayn_ios_get_stats(NULL, NULL), OZAYN_IOS_ERR_NULL);
    return 0;
}

/* ============================================================
 * VALIDATION TESTS
 * ============================================================ */

TEST(test_ios_stream_validate)
{
    ozayn_ios_stream_t s;
    memset(&s, 0, sizeof(s));
    strncpy(s.stream_id, "IOS-1", OZAYN_IOS_MAX_ID_LEN - 1);
    strncpy(s.device_id, "DEV-1", OZAYN_IOS_MAX_ID_LEN - 1);
    s.state = OZAYN_IOS_STATE_ACTIVE;
    s.direction = OZAYN_IOS_DIR_INPUT;
    s.data_type = OZAYN_IOS_DATA_CAMERA_FRAME;
    s.created_time = time(NULL);
    ASSERT(ozayn_ios_stream_validate(&s));
    ASSERT(!ozayn_ios_stream_validate(NULL));
    s.stream_id[0] = '\0';
    ASSERT(!ozayn_ios_stream_validate(&s));
    return 0;
}

TEST(test_ios_request_validate)
{
    ozayn_ios_stream_request_t req;
    memset(&req, 0, sizeof(req));
    strncpy(req.device_session_id, "DAS-1", OZAYN_IOS_MAX_ID_LEN - 1);
    strncpy(req.device_id, "DEV-1", OZAYN_IOS_MAX_ID_LEN - 1);
    strncpy(req.capability_id, "CAP", OZAYN_IOS_MAX_ID_LEN - 1);
    req.direction = OZAYN_IOS_DIR_INPUT;
    req.data_type = OZAYN_IOS_DATA_CAMERA_FRAME;
    req.buffer_policy = OZAYN_IOS_POLICY_BLOCK;
    strncpy(req.requester_ref, "proc-1", OZAYN_IOS_MAX_ID_LEN - 1);
    ASSERT(ozayn_ios_stream_request_validate(&req));
    ASSERT(!ozayn_ios_stream_request_validate(NULL));
    req.device_session_id[0] = '\0';
    ASSERT(!ozayn_ios_stream_request_validate(&req));
    return 0;
}

TEST(test_ios_state_transition_valid)
{
    ASSERT(ozayn_ios_state_transition_valid(OZAYN_IOS_STATE_REQUESTED,
           OZAYN_IOS_STATE_AUTHORIZING));
    ASSERT(ozayn_ios_state_transition_valid(OZAYN_IOS_STATE_AUTHORIZING,
           OZAYN_IOS_STATE_AUTHORIZED));
    ASSERT(ozayn_ios_state_transition_valid(OZAYN_IOS_STATE_AUTHORIZED,
           OZAYN_IOS_STATE_OPENING));
    ASSERT(ozayn_ios_state_transition_valid(OZAYN_IOS_STATE_OPENING,
           OZAYN_IOS_STATE_ACTIVE));
    ASSERT(ozayn_ios_state_transition_valid(OZAYN_IOS_STATE_ACTIVE,
           OZAYN_IOS_STATE_PAUSED));
    ASSERT(ozayn_ios_state_transition_valid(OZAYN_IOS_STATE_PAUSED,
           OZAYN_IOS_STATE_ACTIVE));
    ASSERT(ozayn_ios_state_transition_valid(OZAYN_IOS_STATE_ACTIVE,
           OZAYN_IOS_STATE_DRAINING));
    ASSERT(ozayn_ios_state_transition_valid(OZAYN_IOS_STATE_ACTIVE,
           OZAYN_IOS_STATE_CLOSING));
    ASSERT(ozayn_ios_state_transition_valid(OZAYN_IOS_STATE_CLOSING,
           OZAYN_IOS_STATE_CLOSED));
    ASSERT(!ozayn_ios_state_transition_valid(OZAYN_IOS_STATE_CLOSED,
            OZAYN_IOS_STATE_ACTIVE));
    ASSERT(!ozayn_ios_state_transition_valid(OZAYN_IOS_STATE_REQUESTED,
            OZAYN_IOS_STATE_ACTIVE));
    return 0;
}

/* ============================================================
 * NAME HELPER TESTS
 * ============================================================ */

TEST(test_ios_err_name)
{
    ASSERT_STR_EQ(ozayn_ios_err_name(OZAYN_IOS_OK), "OK");
    ASSERT_STR_EQ(ozayn_ios_err_name(OZAYN_IOS_ERR_NULL), "NULL");
    ASSERT_STR_EQ(ozayn_ios_err_name(OZAYN_IOS_ERR_NOT_FOUND), "NOT_FOUND");
    ASSERT_STR_EQ(ozayn_ios_err_name(OZAYN_IOS_ERR_STATE_INVALID),
                  "STATE_INVALID");
    ASSERT_STR_EQ(ozayn_ios_err_name(OZAYN_IOS_ERR_BACKPRESSURE),
                  "BACKPRESSURE");
    return 0;
}

TEST(test_ios_direction_name)
{
    ASSERT_STR_EQ(ozayn_ios_direction_name(OZAYN_IOS_DIR_INPUT), "INPUT");
    ASSERT_STR_EQ(ozayn_ios_direction_name(OZAYN_IOS_DIR_OUTPUT), "OUTPUT");
    ASSERT_STR_EQ(ozayn_ios_direction_name(OZAYN_IOS_DIR_BIDIRECTIONAL),
                  "BIDIRECTIONAL");
    return 0;
}

TEST(test_ios_data_type_name)
{
    ASSERT_STR_EQ(ozayn_ios_data_type_name(OZAYN_IOS_DATA_CAMERA_FRAME),
                  "CAMERA_FRAME");
    ASSERT_STR_EQ(ozayn_ios_data_type_name(OZAYN_IOS_DATA_AUDIO_SAMPLE),
                  "AUDIO_SAMPLE");
    ASSERT_STR_EQ(ozayn_ios_data_type_name(OZAYN_IOS_DATA_GENERIC_SAFE),
                  "GENERIC_SAFE");
    return 0;
}

TEST(test_ios_stream_state_name)
{
    ASSERT_STR_EQ(ozayn_ios_stream_state_name(OZAYN_IOS_STATE_REQUESTED),
                  "REQUESTED");
    ASSERT_STR_EQ(ozayn_ios_stream_state_name(OZAYN_IOS_STATE_ACTIVE),
                  "ACTIVE");
    ASSERT_STR_EQ(ozayn_ios_stream_state_name(OZAYN_IOS_STATE_CLOSED),
                  "CLOSED");
    ASSERT_STR_EQ(ozayn_ios_stream_state_name(OZAYN_IOS_STATE_BACKPRESSURED),
                  "BACKPRESSURED");
    return 0;
}

TEST(test_ios_buffer_policy_name)
{
    ASSERT_STR_EQ(ozayn_ios_buffer_policy_name(OZAYN_IOS_POLICY_BLOCK),
                  "BLOCK");
    ASSERT_STR_EQ(ozayn_ios_buffer_policy_name(OZAYN_IOS_POLICY_DROP_OLDEST),
                  "DROP_OLDEST");
    ASSERT_STR_EQ(ozayn_ios_buffer_policy_name(OZAYN_IOS_POLICY_FAIL_STREAM),
                  "FAIL_STREAM");
    return 0;
}

TEST(test_ios_close_reason_name)
{
    ASSERT_STR_EQ(ozayn_ios_close_reason_name(OZAYN_IOS_CLOSE_MANUAL_CLOSE),
                  "MANUAL_CLOSE");
    ASSERT_STR_EQ(ozayn_ios_close_reason_name(OZAYN_IOS_CLOSE_TIMEOUT),
                  "TIMEOUT");
    ASSERT_STR_EQ(ozayn_ios_close_reason_name(OZAYN_IOS_CLOSE_BUFFER_OVERFLOW),
                  "BUFFER_OVERFLOW");
    return 0;
}

TEST(test_ios_event_type_name)
{
    ASSERT_STR_EQ(ozayn_ios_event_type_name(OZAYN_IOS_EVENT_STREAM_REQUESTED),
                  "STREAM_REQUESTED");
    ASSERT_STR_EQ(ozayn_ios_event_type_name(OZAYN_IOS_EVENT_STREAM_ACTIVE),
                  "STREAM_ACTIVE");
    ASSERT_STR_EQ(ozayn_ios_event_type_name(OZAYN_IOS_EVENT_STREAM_CLOSED),
                  "STREAM_CLOSED");
    ASSERT_STR_EQ(
        ozayn_ios_event_type_name(OZAYN_IOS_EVENT_STREAM_DEVICE_DISCONNECTED),
        "STREAM_DEVICE_DISCONNECTED");
    return 0;
}

/* ============================================================
 * PRIVACY & SECURITY TESTS
 * ============================================================ */

TEST(test_ios_no_secrets_in_stream)
{
    _init_svc();
    ozayn_ios_stream_request_t req;
    _make_request(&req);
    strncpy(req.metadata, "normal data", OZAYN_IOS_MAX_METADATA_LEN - 1);
    ozayn_ios_stream_t *s = NULL;
    ozayn_ios_stream_create(&_svc, &req, &s);
    ASSERT(!strstr(s->metadata, "password"));
    ASSERT(!strstr(s->metadata, "secret"));
    ASSERT(!strstr(s->metadata, "key"));
    ozayn_ios_service_shutdown(&_svc);
    return 0;
}

TEST(test_ios_no_secrets_in_event)
{
    _init_svc();
    ozayn_ios_emit_event(&_svc, OZAYN_IOS_EVENT_STREAM_REQUESTED, "S-1",
                          "D-1", "SS-1", "normal message");
    const ozayn_ios_event_t *ev = ozayn_ios_event_get(&_svc, 0);
    ASSERT_NOT_NULL(ev);
    ASSERT(!strstr(ev->message, "password"));
    ASSERT(!strstr(ev->message, "secret"));
    ASSERT(!strstr(ev->message, "key"));
    ozayn_ios_service_shutdown(&_svc);
    return 0;
}

/* ============================================================
 * MULTI-STREAM TESTS
 * ============================================================ */

TEST(test_ios_multiple_streams)
{
    _init_svc();
    ozayn_ios_stream_request_t req;
    _make_request(&req);
    ozayn_ios_stream_t *s1 = NULL, *s2 = NULL, *s3 = NULL;
    ozayn_ios_stream_create(&_svc, &req, &s1);
    strncpy(req.device_id, "MIC-1", OZAYN_IOS_MAX_ID_LEN - 1);
    ozayn_ios_stream_create(&_svc, &req, &s2);
    strncpy(req.device_id, "GPU-1", OZAYN_IOS_MAX_ID_LEN - 1);
    ozayn_ios_stream_create(&_svc, &req, &s3);

    ASSERT_EQ(ozayn_ios_stream_count(&_svc), 3);
    ASSERT_NOT_NULL(ozayn_ios_stream_get_by_device(&_svc, "CAM-1"));
    ASSERT_NOT_NULL(ozayn_ios_stream_get_by_device(&_svc, "MIC-1"));
    ASSERT_NOT_NULL(ozayn_ios_stream_get_by_device(&_svc, "GPU-1"));
    ozayn_ios_service_shutdown(&_svc);
    return 0;
}

TEST(test_ios_output_direction)
{
    _init_svc();
    ozayn_ios_stream_request_t req;
    _make_request(&req);
    req.direction = OZAYN_IOS_DIR_OUTPUT;
    req.data_type = OZAYN_IOS_DATA_DISPLAY_OUTPUT;
    ozayn_ios_stream_t *s = NULL;
    ASSERT_EQ(ozayn_ios_stream_create(&_svc, &req, &s), OZAYN_IOS_OK);
    ASSERT_EQ(s->direction, OZAYN_IOS_DIR_OUTPUT);
    ASSERT_EQ(s->data_type, OZAYN_IOS_DATA_DISPLAY_OUTPUT);
    ozayn_ios_service_shutdown(&_svc);
    return 0;
}

TEST(test_ios_bidirectional)
{
    _init_svc();
    ozayn_ios_stream_request_t req;
    _make_request(&req);
    req.direction = OZAYN_IOS_DIR_BIDIRECTIONAL;
    ozayn_ios_stream_t *s = NULL;
    ASSERT_EQ(ozayn_ios_stream_create(&_svc, &req, &s), OZAYN_IOS_OK);
    ASSERT_EQ(s->direction, OZAYN_IOS_DIR_BIDIRECTIONAL);
    ozayn_ios_service_shutdown(&_svc);
    return 0;
}

TEST(test_ios_null_params)
{
    _init_svc();
    ASSERT_EQ(ozayn_ios_stream_authorize(NULL, "X"), OZAYN_IOS_ERR_NULL);
    ASSERT_EQ(ozayn_ios_stream_open(NULL, "X"), OZAYN_IOS_ERR_NULL);
    ASSERT_EQ(ozayn_ios_stream_activate(NULL, "X"), OZAYN_IOS_ERR_NULL);
    ASSERT_EQ(ozayn_ios_stream_pause(NULL, "X"), OZAYN_IOS_ERR_NULL);
    ASSERT_EQ(ozayn_ios_stream_resume(NULL, "X"), OZAYN_IOS_ERR_NULL);
    ASSERT_EQ(ozayn_ios_stream_drain(NULL, "X"), OZAYN_IOS_ERR_NULL);
    ASSERT_EQ(ozayn_ios_stream_close(NULL, "X", 0), OZAYN_IOS_ERR_NULL);
    ASSERT_EQ(ozayn_ios_stream_revoke(NULL, "X", 0), OZAYN_IOS_ERR_NULL);
    ASSERT_EQ(ozayn_ios_stream_heartbeat(NULL, "X"), OZAYN_IOS_ERR_NULL);
    ozayn_ios_service_shutdown(&_svc);
    return 0;
}

TEST(test_ios_not_found)
{
    _init_svc();
    ASSERT_EQ(ozayn_ios_stream_authorize(&_svc, "NOPE"),
              OZAYN_IOS_ERR_NOT_FOUND);
    ASSERT_EQ(ozayn_ios_stream_open(&_svc, "NOPE"),
              OZAYN_IOS_ERR_NOT_FOUND);
    ASSERT_EQ(ozayn_ios_stream_activate(&_svc, "NOPE"),
              OZAYN_IOS_ERR_NOT_FOUND);
    ASSERT_EQ(ozayn_ios_stream_pause(&_svc, "NOPE"),
              OZAYN_IOS_ERR_NOT_FOUND);
    ASSERT_EQ(ozayn_ios_stream_resume(&_svc, "NOPE"),
              OZAYN_IOS_ERR_NOT_FOUND);
    ASSERT_EQ(ozayn_ios_stream_drain(&_svc, "NOPE"),
              OZAYN_IOS_ERR_NOT_FOUND);
    ASSERT_EQ(ozayn_ios_stream_close(&_svc, "NOPE", 0),
              OZAYN_IOS_ERR_NOT_FOUND);
    ASSERT_EQ(ozayn_ios_stream_revoke(&_svc, "NOPE", 0),
              OZAYN_IOS_ERR_NOT_FOUND);
    ozayn_ios_service_shutdown(&_svc);
    return 0;
}

TEST(test_ios_session_expired)
{
    _reset_all();
    memset(&_cfg, 0, sizeof(_cfg));
    _cfg.stream_ttl_ms = 1000;
    ozayn_ios_service_init(&_svc, &_cfg);

    _create_stream();

    struct timespec ts = {2, 0};
    nanosleep(&ts, NULL);

    ozayn_ios_stream_t *s = &_svc.streams[0];
    ASSERT_EQ(ozayn_ios_stream_authorize(&_svc, s->stream_id),
              OZAYN_IOS_ERR_EXPIRED);
    ASSERT_EQ(s->state, OZAYN_IOS_STATE_EXPIRED);
    ozayn_ios_service_shutdown(&_svc);
    return 0;
}

TEST(test_ios_drop_oldest)
{
    _reset_all();
    memset(&_cfg, 0, sizeof(_cfg));
    _cfg.default_max_queue_depth = 2;
    ozayn_ios_service_init(&_svc, &_cfg);

    ozayn_ios_stream_request_t req;
    _make_request(&req);
    req.buffer_policy = OZAYN_IOS_POLICY_DROP_OLDEST;
    ozayn_ios_stream_t *s = NULL;
    ozayn_ios_stream_create(&_svc, &req, &s);
    ozayn_ios_stream_authorize(&_svc, s->stream_id);
    ozayn_ios_stream_open(&_svc, s->stream_id);
    ozayn_ios_stream_activate(&_svc, s->stream_id);

    ozayn_ios_data_unit_t unit;
    memset(&unit, 0, sizeof(unit));
    unit.payload_size = 10;
    ASSERT_EQ(ozayn_ios_stream_push_data(&_svc, s->stream_id, &unit),
              OZAYN_IOS_OK);
    ASSERT_EQ(ozayn_ios_stream_push_data(&_svc, s->stream_id, &unit),
              OZAYN_IOS_OK);
    ASSERT_EQ(ozayn_ios_stream_push_data(&_svc, s->stream_id, &unit),
              OZAYN_IOS_OK);
    ASSERT_EQ(s->total_units_dropped, (uint64_t)1);
    ASSERT_EQ(s->queue_depth, 2);
    ozayn_ios_service_shutdown(&_svc);
    return 0;
}

/* ============================================================
 * TEST RUNNER
 * ============================================================ */

int run_cr_io_stream_tests(void)
{
    SUITE_BEGIN("I/O Stream Management");

    RUN(test_ios_init);
    RUN(test_ios_init_null);
    RUN(test_ios_init_null_config);
    RUN(test_ios_init_double);
    RUN(test_ios_init_custom_config);
    RUN(test_ios_shutdown);
    RUN(test_ios_shutdown_null);
    RUN(test_ios_is_initialized_null);
    RUN(test_ios_global_singleton);

    RUN(test_ios_stream_create);
    RUN(test_ios_stream_create_null);
    RUN(test_ios_stream_create_not_init);
    RUN(test_ios_stream_create_null_req);
    RUN(test_ios_stream_create_null_out);
    RUN(test_ios_stream_create_empty_session);
    RUN(test_ios_stream_create_empty_device);
    RUN(test_ios_stream_create_empty_capability);
    RUN(test_ios_stream_create_empty_requester);
    RUN(test_ios_stream_create_invalid_direction);
    RUN(test_ios_stream_create_invalid_data_type);
    RUN(test_ios_stream_create_invalid_buffer_policy);
    RUN(test_ios_stream_create_limit);
    RUN(test_ios_stream_create_emits_event);

    RUN(test_ios_full_lifecycle);
    RUN(test_ios_pause_resume);
    RUN(test_ios_drain);
    RUN(test_ios_authorize_from_wrong_state);
    RUN(test_ios_open_from_wrong_state);
    RUN(test_ios_activate_from_wrong_state);
    RUN(test_ios_pause_from_wrong_state);
    RUN(test_ios_resume_from_wrong_state);
    RUN(test_ios_drain_from_wrong_state);

    RUN(test_ios_revoke);
    RUN(test_ios_close_from_terminal);

    RUN(test_ios_push_pull_data);
    RUN(test_ios_push_data_wrong_state);
    RUN(test_ios_pull_data_wrong_state);
    RUN(test_ios_push_data_buffer_limit);
    RUN(test_ios_push_data_drop_newest);
    RUN(test_ios_push_data_fail_stream);
    RUN(test_ios_push_data_size_limit);
    RUN(test_ios_heartbeat);
    RUN(test_ios_heartbeat_wrong_state);

    RUN(test_ios_attach_detach_producer);
    RUN(test_ios_attach_detach_consumer);
    RUN(test_ios_attach_producer_terminal);
    RUN(test_ios_attach_consumer_terminal);

    RUN(test_ios_device_disconnected);
    RUN(test_ios_device_disconnected_terminal);
    RUN(test_ios_device_reconnected);
    RUN(test_ios_device_reconnected_wrong_state);

    RUN(test_ios_streams_for_session);

    RUN(test_ios_get);
    RUN(test_ios_get_by_device);
    RUN(test_ios_get_by_session);
    RUN(test_ios_count);
    RUN(test_ios_count_by_device);
    RUN(test_ios_is_active);
    RUN(test_ios_is_expired);

    RUN(test_ios_cleanup_expired);
    RUN(test_ios_cleanup_idle);
    RUN(test_ios_cleanup_closed);
    RUN(test_ios_cleanup_null);

    RUN(test_ios_emit_event);
    RUN(test_ios_event_ring_buffer);
    RUN(test_ios_event_get_invalid);

    RUN(test_ios_stats);
    RUN(test_ios_stats_null);

    RUN(test_ios_stream_validate);
    RUN(test_ios_request_validate);
    RUN(test_ios_state_transition_valid);

    RUN(test_ios_err_name);
    RUN(test_ios_direction_name);
    RUN(test_ios_data_type_name);
    RUN(test_ios_stream_state_name);
    RUN(test_ios_buffer_policy_name);
    RUN(test_ios_close_reason_name);
    RUN(test_ios_event_type_name);

    RUN(test_ios_no_secrets_in_stream);
    RUN(test_ios_no_secrets_in_event);

    RUN(test_ios_multiple_streams);
    RUN(test_ios_output_direction);
    RUN(test_ios_bidirectional);
    RUN(test_ios_null_params);
    RUN(test_ios_not_found);
    RUN(test_ios_session_expired);
    RUN(test_ios_drop_oldest);

    SUITE_END();
    return TOTAL_FAIL();
}
