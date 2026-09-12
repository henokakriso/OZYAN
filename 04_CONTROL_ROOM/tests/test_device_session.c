#include "../device_session.h"
#include "../../tests/test_framework.h"
#include <string.h>
#include <time.h>

/* ============================================================
 * HELPERS
 * ============================================================ */

static ozayn_das_service_t _svc;
static ozayn_das_service_config_t _cfg;

static void _reset_all(void)
{
    memset(&_svc, 0, sizeof(_svc));
}

static void _init_svc(void)
{
    _reset_all();
    memset(&_cfg, 0, sizeof(_cfg));
    ozayn_das_service_init(&_svc, &_cfg);
}

/* ============================================================
 * LIFECYCLE TESTS
 * ============================================================ */

TEST(test_das_init)
{
    _reset_all();
    memset(&_cfg, 0, sizeof(_cfg));
    ASSERT_EQ(ozayn_das_service_init(&_svc, &_cfg), OZAYN_DAS_OK);
    ASSERT(ozayn_das_service_is_initialized(&_svc));
    ozayn_das_service_shutdown(&_svc);
    return 0;
}

TEST(test_das_init_null)
{
    ASSERT_EQ(ozayn_das_service_init(NULL, &_cfg), OZAYN_DAS_ERR_NULL);
    return 0;
}

TEST(test_das_init_null_config)
{
    _reset_all();
    ASSERT_EQ(ozayn_das_service_init(&_svc, NULL), OZAYN_DAS_ERR_NULL);
    return 0;
}

TEST(test_das_init_double)
{
    _init_svc();
    ASSERT_EQ(ozayn_das_service_init(&_svc, &_cfg), OZAYN_DAS_ERR_ALREADY_INIT);
    ozayn_das_service_shutdown(&_svc);
    return 0;
}

TEST(test_das_init_custom_config)
{
    _reset_all();
    memset(&_cfg, 0, sizeof(_cfg));
    _cfg.max_sessions = 4;
    _cfg.session_ttl_ms = 5000;
    _cfg.idle_timeout_ms = 2000;
    ASSERT_EQ(ozayn_das_service_init(&_svc, &_cfg), OZAYN_DAS_OK);
    ASSERT_EQ(_svc.config.max_sessions, 4);
    ASSERT_EQ(_svc.config.session_ttl_ms, 5000);
    ASSERT_EQ(_svc.config.idle_timeout_ms, 2000);
    ozayn_das_service_shutdown(&_svc);
    return 0;
}

TEST(test_das_shutdown)
{
    _init_svc();
    ozayn_das_service_shutdown(&_svc);
    ASSERT(!ozayn_das_service_is_initialized(&_svc));
    return 0;
}

TEST(test_das_shutdown_null)
{
    ozayn_das_service_shutdown(NULL);
    return 0;
}

TEST(test_das_is_initialized_null)
{
    ASSERT(!ozayn_das_service_is_initialized(NULL));
    return 0;
}

TEST(test_das_global_singleton)
{
    ozayn_das_service_t *g = ozayn_das_get_global();
    ASSERT_NOT_NULL(g);
    return 0;
}

/* ============================================================
 * SESSION CREATION TESTS
 * ============================================================ */

TEST(test_das_session_create)
{
    _init_svc();
    ozayn_das_session_t *s = NULL;
    ASSERT_EQ(ozayn_das_session_create(&_svc, "CAM-1", "CAMERA_CAPTURE",
              OZAYN_DAS_MODE_OBSERVE, "RSV-1", "process-1", "sec-1",
              "OP-1", "perm_cam", &s), OZAYN_DAS_OK);
    ASSERT_NOT_NULL(s);
    ASSERT_STR_EQ(s->device_id, "CAM-1");
    ASSERT_STR_EQ(s->capability, "CAMERA_CAPTURE");
    ASSERT_EQ(s->access_mode, OZAYN_DAS_MODE_OBSERVE);
    ASSERT_EQ(s->state, OZAYN_DAS_STATE_REQUESTED);
    ASSERT(s->active);
    ASSERT_EQ(_svc.session_count, 1);
    ozayn_das_service_shutdown(&_svc);
    return 0;
}

TEST(test_das_session_create_null)
{
    ASSERT_EQ(ozayn_das_session_create(NULL, NULL, NULL, 0, NULL, NULL,
              NULL, NULL, NULL, NULL), OZAYN_DAS_ERR_NULL);
    return 0;
}

TEST(test_das_session_create_not_init)
{
    _reset_all();
    ozayn_das_session_t *s = NULL;
    ASSERT_EQ(ozayn_das_session_create(&_svc, "CAM-1", "CAP", 0, "RSV-1",
              "req", NULL, NULL, NULL, &s), OZAYN_DAS_ERR_NOT_INITIALIZED);
    return 0;
}

TEST(test_das_session_create_empty_device)
{
    _init_svc();
    ozayn_das_session_t *s = NULL;
    ASSERT_EQ(ozayn_das_session_create(&_svc, "", "CAP", 0, NULL, "req",
              NULL, NULL, NULL, &s), OZAYN_DAS_ERR_INVALID_PARAM);
    ozayn_das_service_shutdown(&_svc);
    return 0;
}

TEST(test_das_session_create_empty_capability)
{
    _init_svc();
    ozayn_das_session_t *s = NULL;
    ASSERT_EQ(ozayn_das_session_create(&_svc, "DEV-1", "", 0, NULL, "req",
              NULL, NULL, NULL, &s), OZAYN_DAS_ERR_INVALID_PARAM);
    ozayn_das_service_shutdown(&_svc);
    return 0;
}

TEST(test_das_session_create_empty_requester)
{
    _init_svc();
    ozayn_das_session_t *s = NULL;
    ASSERT_EQ(ozayn_das_session_create(&_svc, "DEV-1", "CAP", 0, NULL, "",
              NULL, NULL, NULL, &s), OZAYN_DAS_ERR_INVALID_PARAM);
    ozayn_das_service_shutdown(&_svc);
    return 0;
}

TEST(test_das_session_create_invalid_mode)
{
    _init_svc();
    ozayn_das_session_t *s = NULL;
    ASSERT_EQ(ozayn_das_session_create(&_svc, "DEV-1", "CAP",
              (ozayn_das_access_mode_t)99, NULL, "req", NULL, NULL, NULL, &s),
              OZAYN_DAS_ERR_INVALID_PARAM);
    ozayn_das_service_shutdown(&_svc);
    return 0;
}

TEST(test_das_session_create_null_out)
{
    _init_svc();
    ASSERT_EQ(ozayn_das_session_create(&_svc, "DEV-1", "CAP", 0, NULL,
              "req", NULL, NULL, NULL, NULL), OZAYN_DAS_ERR_NULL);
    ozayn_das_service_shutdown(&_svc);
    return 0;
}

TEST(test_das_session_create_limit)
{
    _reset_all();
    memset(&_cfg, 0, sizeof(_cfg));
    _cfg.max_sessions = 2;
    ozayn_das_service_init(&_svc, &_cfg);
    ozayn_das_session_t *s1 = NULL, *s2 = NULL, *s3 = NULL;
    ASSERT_EQ(ozayn_das_session_create(&_svc, "D1", "C1", 0, NULL, "r1",
              NULL, NULL, NULL, &s1), OZAYN_DAS_OK);
    ASSERT_EQ(ozayn_das_session_create(&_svc, "D2", "C2", 0, NULL, "r2",
              NULL, NULL, NULL, &s2), OZAYN_DAS_OK);
    ASSERT_EQ(ozayn_das_session_create(&_svc, "D3", "C3", 0, NULL, "r3",
              NULL, NULL, NULL, &s3), OZAYN_DAS_ERR_LIMIT_REACHED);
    ozayn_das_service_shutdown(&_svc);
    return 0;
}

TEST(test_das_session_create_emits_event)
{
    _init_svc();
    ozayn_das_session_t *s = NULL;
    ozayn_das_session_create(&_svc, "CAM-1", "CAP", 0, NULL, "req",
                             NULL, NULL, NULL, &s);
    ASSERT_GE(ozayn_das_event_count(&_svc), 1);
    const ozayn_das_event_t *ev = ozayn_das_event_get(&_svc, 0);
    ASSERT_NOT_NULL(ev);
    ASSERT_EQ(ev->type, OZAYN_DAS_EVENT_SESSION_REQUESTED);
    ozayn_das_service_shutdown(&_svc);
    return 0;
}

/* ============================================================
 * LIFECYCLE TRANSITION TESTS
 * ============================================================ */

TEST(test_das_full_lifecycle)
{
    _init_svc();
    ozayn_das_session_t *s = NULL;
    ASSERT_EQ(ozayn_das_session_create(&_svc, "CAM-1", "CAMERA_CAPTURE",
              OZAYN_DAS_MODE_OBSERVE, "RSV-1", "proc-1", "sec-1",
              "OP-1", "perm", &s), OZAYN_DAS_OK);
    ASSERT_EQ(s->state, OZAYN_DAS_STATE_REQUESTED);

    ASSERT_EQ(ozayn_das_session_authorize(&_svc, s->session_id), OZAYN_DAS_OK);
    ASSERT_EQ(s->state, OZAYN_DAS_STATE_AUTHORIZED);

    ASSERT_EQ(ozayn_das_session_reserve(&_svc, s->session_id), OZAYN_DAS_OK);
    ASSERT_EQ(s->state, OZAYN_DAS_STATE_RESERVED);

    ASSERT_EQ(ozayn_das_session_open(&_svc, s->session_id), OZAYN_DAS_OK);
    ASSERT_EQ(s->state, OZAYN_DAS_STATE_OPENING);

    ASSERT_EQ(ozayn_das_session_activate(&_svc, s->session_id), OZAYN_DAS_OK);
    ASSERT_EQ(s->state, OZAYN_DAS_STATE_ACTIVE);

    ASSERT_EQ(ozayn_das_session_set_idle(&_svc, s->session_id), OZAYN_DAS_OK);
    ASSERT_EQ(s->state, OZAYN_DAS_STATE_IDLE);

    ASSERT_EQ(ozayn_das_session_close(&_svc, s->session_id,
              OZAYN_DAS_CLOSE_MANUAL_CLOSE), OZAYN_DAS_OK);
    ASSERT_EQ(s->state, OZAYN_DAS_STATE_CLOSED);
    ASSERT(!s->active);
    ASSERT_EQ(_svc.session_count, 0);
    ozayn_das_service_shutdown(&_svc);
    return 0;
}

TEST(test_das_authorize_from_wrong_state)
{
    _init_svc();
    ozayn_das_session_t *s = NULL;
    ozayn_das_session_create(&_svc, "CAM-1", "CAP", OZAYN_DAS_MODE_OUTPUT,
                             "RSV-1", "req", NULL, NULL, NULL, &s);

    ASSERT_EQ(ozayn_das_session_authorize(&_svc, s->session_id), OZAYN_DAS_OK);
    ASSERT_EQ(ozayn_das_session_reserve(&_svc, s->session_id), OZAYN_DAS_OK);
    ASSERT_EQ(ozayn_das_session_authorize(&_svc, s->session_id),
              OZAYN_DAS_ERR_STATE_INVALID);
    ozayn_das_service_shutdown(&_svc);
    return 0;
}

TEST(test_das_open_from_wrong_state)
{
    _init_svc();
    ozayn_das_session_t *s = NULL;
    ozayn_das_session_create(&_svc, "CAM-1", "CAP", 0, NULL, "req",
                             NULL, NULL, NULL, &s);

    ASSERT_EQ(ozayn_das_session_open(&_svc, s->session_id),
              OZAYN_DAS_ERR_STATE_INVALID);
    ozayn_das_service_shutdown(&_svc);
    return 0;
}

TEST(test_das_activate_from_wrong_state)
{
    _init_svc();
    ozayn_das_session_t *s = NULL;
    ozayn_das_session_create(&_svc, "CAM-1", "CAP", 0, NULL, "req",
                             NULL, NULL, NULL, &s);

    ASSERT_EQ(ozayn_das_session_activate(&_svc, s->session_id),
              OZAYN_DAS_ERR_STATE_INVALID);
    ozayn_das_service_shutdown(&_svc);
    return 0;
}

TEST(test_das_heartbeat_active)
{
    _init_svc();
    ozayn_das_session_t *s = NULL;
    ozayn_das_session_create(&_svc, "CAM-1", "CAP", 0, "RSV-1", "req",
                             NULL, NULL, NULL, &s);
    ozayn_das_session_authorize(&_svc, s->session_id);
    ozayn_das_session_reserve(&_svc, s->session_id);
    ozayn_das_session_open(&_svc, s->session_id);
    ozayn_das_session_activate(&_svc, s->session_id);

    ASSERT_EQ(ozayn_das_session_heartbeat(&_svc, s->session_id), OZAYN_DAS_OK);
    ASSERT_EQ(_svc.stats.total_heartbeats, 1);
    ozayn_das_service_shutdown(&_svc);
    return 0;
}

TEST(test_das_heartbeat_wrong_state)
{
    _init_svc();
    ozayn_das_session_t *s = NULL;
    ozayn_das_session_create(&_svc, "CAM-1", "CAP", 0, NULL, "req",
                             NULL, NULL, NULL, &s);

    ASSERT_EQ(ozayn_das_session_heartbeat(&_svc, s->session_id),
              OZAYN_DAS_ERR_STATE_INVALID);
    ozayn_das_service_shutdown(&_svc);
    return 0;
}

TEST(test_das_idle_active_resume)
{
    _init_svc();
    ozayn_das_session_t *s = NULL;
    ozayn_das_session_create(&_svc, "CAM-1", "CAP", 0, "RSV-1", "req",
                             NULL, NULL, NULL, &s);
    ozayn_das_session_authorize(&_svc, s->session_id);
    ozayn_das_session_reserve(&_svc, s->session_id);
    ozayn_das_session_open(&_svc, s->session_id);
    ozayn_das_session_activate(&_svc, s->session_id);
    ozayn_das_session_set_idle(&_svc, s->session_id);

    ASSERT_EQ(s->state, OZAYN_DAS_STATE_IDLE);
    ASSERT_EQ(ozayn_das_session_activate(&_svc, s->session_id), OZAYN_DAS_OK);
    ASSERT_EQ(s->state, OZAYN_DAS_STATE_ACTIVE);
    ozayn_das_service_shutdown(&_svc);
    return 0;
}

/* ============================================================
 * CANCEL / REVOKE / CLOSE TESTS
 * ============================================================ */

TEST(test_das_cancel)
{
    _init_svc();
    ozayn_das_session_t *s = NULL;
    ozayn_das_session_create(&_svc, "CAM-1", "CAP", 0, NULL, "req",
                             NULL, NULL, NULL, &s);
    ASSERT_EQ(ozayn_das_session_cancel(&_svc, s->session_id), OZAYN_DAS_OK);
    ASSERT_EQ(s->state, OZAYN_DAS_STATE_CANCELLED);
    ASSERT(!s->active);
    ASSERT_EQ(_svc.session_count, 0);
    ozayn_das_service_shutdown(&_svc);
    return 0;
}

TEST(test_das_cancel_wrong_state)
{
    _init_svc();
    ozayn_das_session_t *s = NULL;
    ozayn_das_session_create(&_svc, "CAM-1", "CAP", 0, NULL, "req",
                             NULL, NULL, NULL, &s);

    ASSERT_EQ(ozayn_das_session_cancel(&_svc, s->session_id), OZAYN_DAS_OK);
    ASSERT_EQ(ozayn_das_session_cancel(&_svc, s->session_id),
              OZAYN_DAS_ERR_NOT_FOUND);
    ozayn_das_service_shutdown(&_svc);
    return 0;
}

TEST(test_das_revoke)
{
    _init_svc();
    ozayn_das_session_t *s = NULL;
    ozayn_das_session_create(&_svc, "CAM-1", "CAP", 0, "RSV-1", "req",
                             NULL, NULL, NULL, &s);
    ozayn_das_session_authorize(&_svc, s->session_id);
    ozayn_das_session_reserve(&_svc, s->session_id);
    ozayn_das_session_open(&_svc, s->session_id);
    ozayn_das_session_activate(&_svc, s->session_id);

    ASSERT_EQ(ozayn_das_session_revoke(&_svc, s->session_id,
              OZAYN_DAS_CLOSE_SECURITY_EXPIRED), OZAYN_DAS_OK);
    ASSERT_EQ(s->state, OZAYN_DAS_STATE_REVOKED);
    ASSERT_EQ(s->close_reason, OZAYN_DAS_CLOSE_SECURITY_EXPIRED);
    ASSERT(!s->active);
    ozayn_das_service_shutdown(&_svc);
    return 0;
}

TEST(test_das_revoke_wrong_state)
{
    _init_svc();
    ozayn_das_session_t *s = NULL;
    ozayn_das_session_create(&_svc, "CAM-1", "CAP", 0, NULL, "req",
                             NULL, NULL, NULL, &s);
    ozayn_das_session_cancel(&_svc, s->session_id);
    ASSERT_EQ(ozayn_das_session_revoke(&_svc, s->session_id,
              OZAYN_DAS_CLOSE_AUTH_REVOKED), OZAYN_DAS_ERR_NOT_FOUND);
    ozayn_das_service_shutdown(&_svc);
    return 0;
}

TEST(test_das_close_device_unavailable)
{
    _init_svc();
    ozayn_das_session_t *s = NULL;
    ozayn_das_session_create(&_svc, "CAM-1", "CAP", 0, "RSV-1", "req",
                             NULL, NULL, NULL, &s);
    ozayn_das_session_authorize(&_svc, s->session_id);
    ozayn_das_session_reserve(&_svc, s->session_id);
    ozayn_das_session_open(&_svc, s->session_id);
    ozayn_das_session_activate(&_svc, s->session_id);

    ASSERT_EQ(ozayn_das_session_close(&_svc, s->session_id,
              OZAYN_DAS_CLOSE_DEVICE_UNAVAILABLE), OZAYN_DAS_OK);
    ASSERT_EQ(s->state, OZAYN_DAS_STATE_CLOSED);
    ASSERT_EQ(s->close_reason, OZAYN_DAS_CLOSE_DEVICE_UNAVAILABLE);
    ozayn_das_service_shutdown(&_svc);
    return 0;
}

TEST(test_das_close_from_closed)
{
    _init_svc();
    ozayn_das_session_t *s = NULL;
    ozayn_das_session_create(&_svc, "CAM-1", "CAP", 0, NULL, "req",
                             NULL, NULL, NULL, &s);
    ozayn_das_session_close(&_svc, s->session_id, OZAYN_DAS_CLOSE_MANUAL_CLOSE);
    ASSERT_EQ(ozayn_das_session_close(&_svc, s->session_id,
              OZAYN_DAS_CLOSE_MANUAL_CLOSE), OZAYN_DAS_ERR_NOT_FOUND);
    ozayn_das_service_shutdown(&_svc);
    return 0;
}

/* ============================================================
 * QUERY TESTS
 * ============================================================ */

TEST(test_das_get)
{
    _init_svc();
    ozayn_das_session_t *s = NULL;
    ozayn_das_session_create(&_svc, "CAM-1", "CAP", 0, NULL, "req",
                             NULL, NULL, NULL, &s);
    const ozayn_das_session_t *found = ozayn_das_session_get(&_svc,
                                                              s->session_id);
    ASSERT_NOT_NULL(found);
    ASSERT_NULL(ozayn_das_session_get(&_svc, "NOPE"));
    ozayn_das_service_shutdown(&_svc);
    return 0;
}

TEST(test_das_get_by_device)
{
    _init_svc();
    ozayn_das_session_t *s = NULL;
    ozayn_das_session_create(&_svc, "CAM-1", "CAP", 0, NULL, "req",
                             NULL, NULL, NULL, &s);
    const ozayn_das_session_t *found = ozayn_das_session_get_by_device(&_svc,
                                                                        "CAM-1");
    ASSERT_NOT_NULL(found);
    ASSERT_NULL(ozayn_das_session_get_by_device(&_svc, "NOPE"));
    ozayn_das_service_shutdown(&_svc);
    return 0;
}

TEST(test_das_get_by_reservation)
{
    _init_svc();
    ozayn_das_session_t *s = NULL;
    ozayn_das_session_create(&_svc, "CAM-1", "CAP", 0, "RSV-1", "req",
                             NULL, NULL, NULL, &s);
    const ozayn_das_session_t *found =
        ozayn_das_session_get_by_reservation(&_svc, "RSV-1");
    ASSERT_NOT_NULL(found);
    ASSERT_NULL(ozayn_das_session_get_by_reservation(&_svc, "NOPE"));
    ozayn_das_service_shutdown(&_svc);
    return 0;
}

TEST(test_das_count)
{
    _init_svc();
    ASSERT_EQ(ozayn_das_session_count(&_svc), 0);
    ozayn_das_session_t *s = NULL;
    ozayn_das_session_create(&_svc, "D1", "C1", 0, NULL, "r1",
                             NULL, NULL, NULL, &s);
    ASSERT_EQ(ozayn_das_session_count(&_svc), 1);
    ozayn_das_session_create(&_svc, "D2", "C2", 0, NULL, "r2",
                             NULL, NULL, NULL, &s);
    ASSERT_EQ(ozayn_das_session_count(&_svc), 2);
    ozayn_das_service_shutdown(&_svc);
    return 0;
}

TEST(test_das_count_by_device)
{
    _init_svc();
    ozayn_das_session_t *s = NULL;
    ozayn_das_session_create(&_svc, "CAM-1", "C1", 0, NULL, "r1",
                             NULL, NULL, NULL, &s);
    ozayn_das_session_create(&_svc, "CAM-1", "C2", 0, NULL, "r2",
                             NULL, NULL, NULL, &s);
    ASSERT_EQ(ozayn_das_session_count_by_device(&_svc, "CAM-1"), 2);
    ASSERT_EQ(ozayn_das_session_count_by_device(&_svc, "NOPE"), 0);
    ozayn_das_service_shutdown(&_svc);
    return 0;
}

TEST(test_das_is_active)
{
    _init_svc();
    ozayn_das_session_t *s = NULL;
    ozayn_das_session_create(&_svc, "CAM-1", "CAP", 0, "RSV-1", "req",
                             NULL, NULL, NULL, &s);
    ASSERT(!ozayn_das_session_is_active(&_svc, s->session_id));

    ozayn_das_session_authorize(&_svc, s->session_id);
    ozayn_das_session_reserve(&_svc, s->session_id);
    ozayn_das_session_open(&_svc, s->session_id);
    ozayn_das_session_activate(&_svc, s->session_id);
    ASSERT(ozayn_das_session_is_active(&_svc, s->session_id));

    ASSERT(!ozayn_das_session_is_active(&_svc, "NOPE"));
    ozayn_das_service_shutdown(&_svc);
    return 0;
}

TEST(test_das_is_expired)
{
    _init_svc();
    ozayn_das_session_t *s = NULL;
    ozayn_das_session_create(&_svc, "CAM-1", "CAP", 0, NULL, "req",
                             NULL, NULL, NULL, &s);
    ASSERT(!ozayn_das_session_is_expired(&_svc, s->session_id));
    ASSERT(!ozayn_das_session_is_expired(&_svc, "NOPE"));
    ozayn_das_service_shutdown(&_svc);
    return 0;
}

/* ============================================================
 * AUTHORIZATION FAILURE TESTS
 * ============================================================ */

TEST(test_das_authorize_expired_session)
{
    _reset_all();
    memset(&_cfg, 0, sizeof(_cfg));
    _cfg.session_ttl_ms = 1000;
    ozayn_das_service_init(&_svc, &_cfg);

    ozayn_das_session_t *s = NULL;
    ozayn_das_session_create(&_svc, "CAM-1", "CAP", 0, NULL, "req",
                             NULL, NULL, NULL, &s);

    struct timespec ts = {2, 0};
    nanosleep(&ts, NULL);

    ASSERT_EQ(ozayn_das_session_authorize(&_svc, s->session_id),
              OZAYN_DAS_ERR_EXPIRED);
    ASSERT_EQ(s->state, OZAYN_DAS_STATE_EXPIRED);
    ozayn_das_service_shutdown(&_svc);
    return 0;
}

TEST(test_das_not_found)
{
    _init_svc();
    ASSERT_EQ(ozayn_das_session_authorize(&_svc, "NOPE"),
              OZAYN_DAS_ERR_NOT_FOUND);
    ASSERT_EQ(ozayn_das_session_reserve(&_svc, "NOPE"),
              OZAYN_DAS_ERR_NOT_FOUND);
    ASSERT_EQ(ozayn_das_session_open(&_svc, "NOPE"),
              OZAYN_DAS_ERR_NOT_FOUND);
    ASSERT_EQ(ozayn_das_session_activate(&_svc, "NOPE"),
              OZAYN_DAS_ERR_NOT_FOUND);
    ASSERT_EQ(ozayn_das_session_close(&_svc, "NOPE",
              OZAYN_DAS_CLOSE_MANUAL_CLOSE), OZAYN_DAS_ERR_NOT_FOUND);
    ASSERT_EQ(ozayn_das_session_revoke(&_svc, "NOPE",
              OZAYN_DAS_CLOSE_TIMEOUT), OZAYN_DAS_ERR_NOT_FOUND);
    ASSERT_EQ(ozayn_das_session_cancel(&_svc, "NOPE"),
              OZAYN_DAS_ERR_NOT_FOUND);
    ozayn_das_service_shutdown(&_svc);
    return 0;
}

TEST(test_das_null_params)
{
    _init_svc();
    ASSERT_EQ(ozayn_das_session_authorize(NULL, "X"), OZAYN_DAS_ERR_NULL);
    ASSERT_EQ(ozayn_das_session_reserve(NULL, "X"), OZAYN_DAS_ERR_NULL);
    ASSERT_EQ(ozayn_das_session_open(NULL, "X"), OZAYN_DAS_ERR_NULL);
    ASSERT_EQ(ozayn_das_session_activate(NULL, "X"), OZAYN_DAS_ERR_NULL);
    ASSERT_EQ(ozayn_das_session_close(NULL, "X", 0), OZAYN_DAS_ERR_NULL);
    ASSERT_EQ(ozayn_das_session_revoke(NULL, "X", 0), OZAYN_DAS_ERR_NULL);
    ASSERT_EQ(ozayn_das_session_cancel(NULL, "X"), OZAYN_DAS_ERR_NULL);
    ASSERT_EQ(ozayn_das_session_heartbeat(NULL, "X"), OZAYN_DAS_ERR_NULL);
    ozayn_das_service_shutdown(&_svc);
    return 0;
}

/* ============================================================
 * CLEANUP TESTS
 * ============================================================ */

TEST(test_das_cleanup_expired)
{
    _reset_all();
    memset(&_cfg, 0, sizeof(_cfg));
    _cfg.session_ttl_ms = 1000;
    ozayn_das_service_init(&_svc, &_cfg);

    ozayn_das_session_t *s = NULL;
    ozayn_das_session_create(&_svc, "CAM-1", "CAP", 0, NULL, "req",
                             NULL, NULL, NULL, &s);

    struct timespec ts = {2, 0};
    nanosleep(&ts, NULL);

    int cleaned = ozayn_das_cleanup_expired_sessions(&_svc);
    ASSERT(cleaned >= 1);
    ozayn_das_service_shutdown(&_svc);
    return 0;
}

TEST(test_das_cleanup_idle)
{
    _reset_all();
    memset(&_cfg, 0, sizeof(_cfg));
    _cfg.idle_timeout_ms = 1000;
    ozayn_das_service_init(&_svc, &_cfg);

    ozayn_das_session_t *s = NULL;
    ozayn_das_session_create(&_svc, "CAM-1", "CAP", 0, "RSV-1", "req",
                             NULL, NULL, NULL, &s);
    ozayn_das_session_authorize(&_svc, s->session_id);
    ozayn_das_session_reserve(&_svc, s->session_id);
    ozayn_das_session_open(&_svc, s->session_id);
    ozayn_das_session_activate(&_svc, s->session_id);
    ozayn_das_session_set_idle(&_svc, s->session_id);

    struct timespec ts = {2, 0};
    nanosleep(&ts, NULL);

    int cleaned = ozayn_das_cleanup_idle_sessions(&_svc);
    ASSERT(cleaned >= 1);
    ozayn_das_service_shutdown(&_svc);
    return 0;
}

TEST(test_das_cleanup_null)
{
    ASSERT_EQ(ozayn_das_cleanup_expired_sessions(NULL), 0);
    ASSERT_EQ(ozayn_das_cleanup_idle_sessions(NULL), 0);
    ASSERT_EQ(ozayn_das_cleanup_all(NULL), 0);
    return 0;
}

/* ============================================================
 * EVENTS TESTS
 * ============================================================ */

TEST(test_das_emit_event)
{
    _init_svc();
    ASSERT_EQ(ozayn_das_emit_event(&_svc, OZAYN_DAS_EVENT_SESSION_REQUESTED,
              "S-1", "D-1", "test event"), OZAYN_DAS_OK);
    ASSERT_EQ(ozayn_das_event_count(&_svc), 1);
    const ozayn_das_event_t *ev = ozayn_das_event_get(&_svc, 0);
    ASSERT_NOT_NULL(ev);
    ASSERT_EQ(ev->type, OZAYN_DAS_EVENT_SESSION_REQUESTED);
    ozayn_das_service_shutdown(&_svc);
    return 0;
}

TEST(test_das_event_ring_buffer)
{
    _init_svc();
    for (int i = 0; i < 70; i++) {
        ozayn_das_emit_event(&_svc, OZAYN_DAS_EVENT_SESSION_HEARTBEAT,
                              "S-1", "D-1", "event");
    }
    ASSERT_EQ(ozayn_das_event_count(&_svc), OZAYN_DAS_MAX_EVENTS);
    ozayn_das_service_shutdown(&_svc);
    return 0;
}

TEST(test_das_event_get_invalid)
{
    _init_svc();
    ASSERT_NULL(ozayn_das_event_get(&_svc, 0));
    ASSERT_NULL(ozayn_das_event_get(&_svc, -1));
    ozayn_das_service_shutdown(&_svc);
    return 0;
}

/* ============================================================
 * STATS TESTS
 * ============================================================ */

TEST(test_das_stats)
{
    _init_svc();
    ozayn_das_stats_t stats;
    ASSERT_EQ(ozayn_das_get_stats(&_svc, &stats), OZAYN_DAS_OK);
    ASSERT_EQ(stats.total_sessions_created, 0);

    ozayn_das_session_t *s = NULL;
    ozayn_das_session_create(&_svc, "CAM-1", "CAP", 0, NULL, "req",
                             NULL, NULL, NULL, &s);
    ASSERT_EQ(ozayn_das_get_stats(&_svc, &stats), OZAYN_DAS_OK);
    ASSERT_EQ(stats.total_sessions_created, 1);
    ASSERT_EQ(stats.current_active_sessions, 1);
    ozayn_das_service_shutdown(&_svc);
    return 0;
}

TEST(test_das_stats_null)
{
    ASSERT_EQ(ozayn_das_get_stats(NULL, NULL), OZAYN_DAS_ERR_NULL);
    return 0;
}

/* ============================================================
 * VALIDATION TESTS
 * ============================================================ */

TEST(test_das_session_validate)
{
    ozayn_das_session_t s;
    memset(&s, 0, sizeof(s));
    strncpy(s.session_id, "DAS-1", OZAYN_DAS_MAX_ID_LEN - 1);
    strncpy(s.device_id, "DEV-1", OZAYN_DAS_MAX_ID_LEN - 1);
    s.state = OZAYN_DAS_STATE_ACTIVE;
    s.access_mode = OZAYN_DAS_MODE_OBSERVE;
    s.created_time = time(NULL);
    ASSERT(ozayn_das_session_validate(&s));
    ASSERT(!ozayn_das_session_validate(NULL));
    s.session_id[0] = '\0';
    ASSERT(!ozayn_das_session_validate(&s));
    return 0;
}

TEST(test_das_state_transition_valid)
{
    ASSERT(ozayn_das_state_transition_valid(OZAYN_DAS_STATE_REQUESTED,
           OZAYN_DAS_STATE_AUTHORIZING));
    ASSERT(ozayn_das_state_transition_valid(OZAYN_DAS_STATE_AUTHORIZING,
           OZAYN_DAS_STATE_AUTHORIZED));
    ASSERT(ozayn_das_state_transition_valid(OZAYN_DAS_STATE_AUTHORIZED,
           OZAYN_DAS_STATE_RESERVED));
    ASSERT(ozayn_das_state_transition_valid(OZAYN_DAS_STATE_RESERVED,
           OZAYN_DAS_STATE_OPENING));
    ASSERT(ozayn_das_state_transition_valid(OZAYN_DAS_STATE_OPENING,
           OZAYN_DAS_STATE_ACTIVE));
    ASSERT(ozayn_das_state_transition_valid(OZAYN_DAS_STATE_ACTIVE,
           OZAYN_DAS_STATE_IDLE));
    ASSERT(ozayn_das_state_transition_valid(OZAYN_DAS_STATE_ACTIVE,
           OZAYN_DAS_STATE_CLOSING));
    ASSERT(!ozayn_das_state_transition_valid(OZAYN_DAS_STATE_CLOSED,
            OZAYN_DAS_STATE_ACTIVE));
    ASSERT(!ozayn_das_state_transition_valid(OZAYN_DAS_STATE_REQUESTED,
            OZAYN_DAS_STATE_ACTIVE));
    ASSERT(!ozayn_das_state_transition_valid(OZAYN_DAS_STATE_REQUESTED,
            OZAYN_DAS_STATE_CLOSED));
    return 0;
}

/* ============================================================
 * NAME HELPER TESTS
 * ============================================================ */

TEST(test_das_access_mode_name)
{
    ASSERT_STR_EQ(ozayn_das_access_mode_name(OZAYN_DAS_MODE_OBSERVE), "OBSERVE");
    ASSERT_STR_EQ(ozayn_das_access_mode_name(OZAYN_DAS_MODE_INPUT), "INPUT");
    ASSERT_STR_EQ(ozayn_das_access_mode_name(OZAYN_DAS_MODE_OUTPUT), "OUTPUT");
    ASSERT_STR_EQ(ozayn_das_access_mode_name(OZAYN_DAS_MODE_CONTROL), "CONTROL");
    ASSERT_STR_EQ(ozayn_das_access_mode_name(OZAYN_DAS_MODE_STREAM), "STREAM");
    ASSERT_STR_EQ(ozayn_das_access_mode_name((ozayn_das_access_mode_t)99),
                  "UNKNOWN");
    return 0;
}

TEST(test_das_session_state_name)
{
    ASSERT_STR_EQ(ozayn_das_session_state_name(OZAYN_DAS_STATE_REQUESTED),
                  "REQUESTED");
    ASSERT_STR_EQ(ozayn_das_session_state_name(OZAYN_DAS_STATE_ACTIVE),
                  "ACTIVE");
    ASSERT_STR_EQ(ozayn_das_session_state_name(OZAYN_DAS_STATE_CLOSED),
                  "CLOSED");
    ASSERT_STR_EQ(ozayn_das_session_state_name(OZAYN_DAS_STATE_REVOKED),
                  "REVOKED");
    ASSERT_STR_EQ(ozayn_das_session_state_name((ozayn_das_session_state_t)99),
                  "UNKNOWN");
    return 0;
}

TEST(test_das_close_reason_name)
{
    ASSERT_STR_EQ(ozayn_das_close_reason_name(OZAYN_DAS_CLOSE_MANUAL_CLOSE),
                  "MANUAL_CLOSE");
    ASSERT_STR_EQ(ozayn_das_close_reason_name(OZAYN_DAS_CLOSE_TIMEOUT),
                  "TIMEOUT");
    ASSERT_STR_EQ(ozayn_das_close_reason_name(OZAYN_DAS_CLOSE_SECURITY_EXPIRED),
                  "SECURITY_EXPIRED");
    ASSERT_STR_EQ(ozayn_das_close_reason_name(OZAYN_DAS_CLOSE_DEVICE_ERROR),
                  "DEVICE_ERROR");
    return 0;
}

TEST(test_das_event_type_name)
{
    ASSERT_STR_EQ(ozayn_das_event_type_name(OZAYN_DAS_EVENT_SESSION_REQUESTED),
                  "SESSION_REQUESTED");
    ASSERT_STR_EQ(ozayn_das_event_type_name(OZAYN_DAS_EVENT_SESSION_ACTIVE),
                  "SESSION_ACTIVE");
    ASSERT_STR_EQ(ozayn_das_event_type_name(OZAYN_DAS_EVENT_SESSION_CLOSED),
                  "SESSION_CLOSED");
    return 0;
}

TEST(test_das_err_name)
{
    ASSERT_STR_EQ(ozayn_das_err_name(OZAYN_DAS_OK), "OK");
    ASSERT_STR_EQ(ozayn_das_err_name(OZAYN_DAS_ERR_NULL), "NULL");
    ASSERT_STR_EQ(ozayn_das_err_name(OZAYN_DAS_ERR_NOT_FOUND), "NOT_FOUND");
    ASSERT_STR_EQ(ozayn_das_err_name(OZAYN_DAS_ERR_STATE_INVALID),
                  "STATE_INVALID");
    return 0;
}

/* ============================================================
 * PRIVACY & SECURITY TESTS
 * ============================================================ */

TEST(test_das_camera_no_auto_activate)
{
    _init_svc();
    ozayn_das_session_t *s = NULL;
    ozayn_das_session_create(&_svc, "CAM-1", "CAMERA_CAPTURE",
                             OZAYN_DAS_MODE_OBSERVE, NULL, "proc-1",
                             NULL, NULL, "perm_cam", &s);
    ASSERT_EQ(s->state, OZAYN_DAS_STATE_REQUESTED);
    ASSERT(s->state != OZAYN_DAS_STATE_ACTIVE);
    ozayn_das_service_shutdown(&_svc);
    return 0;
}

TEST(test_das_mic_no_auto_activate)
{
    _init_svc();
    ozayn_das_session_t *s = NULL;
    ozayn_das_session_create(&_svc, "MIC-1", "MICROPHONE_INPUT",
                             OZAYN_DAS_MODE_INPUT, NULL, "proc-1",
                             NULL, NULL, "perm_mic", &s);
    ASSERT_EQ(s->state, OZAYN_DAS_STATE_REQUESTED);
    ASSERT(s->state != OZAYN_DAS_STATE_ACTIVE);
    ozayn_das_service_shutdown(&_svc);
    return 0;
}

TEST(test_das_no_secrets_in_session)
{
    _init_svc();
    ozayn_das_session_t *s = NULL;
    ozayn_das_session_create(&_svc, "CAM-1", "CAP", 0, NULL, "req",
                             "sec-ref", "OP-1", "perm", &s);
    ASSERT(!strstr(s->metadata, "password"));
    ASSERT(!strstr(s->metadata, "secret"));
    ASSERT(!strstr(s->metadata, "key"));
    ASSERT(!strstr(s->security_session_ref, "password"));
    ozayn_das_service_shutdown(&_svc);
    return 0;
}

TEST(test_das_no_secrets_in_event)
{
    _init_svc();
    ozayn_das_emit_event(&_svc, OZAYN_DAS_EVENT_SESSION_REQUESTED, "S-1",
                          "D-1", "normal message");
    const ozayn_das_event_t *ev = ozayn_das_event_get(&_svc, 0);
    ASSERT_NOT_NULL(ev);
    ASSERT(!strstr(ev->message, "password"));
    ASSERT(!strstr(ev->message, "secret"));
    ASSERT(!strstr(ev->message, "key"));
    ozayn_das_service_shutdown(&_svc);
    return 0;
}

/* ============================================================
 * ACCESS MODE TESTS
 * ============================================================ */

TEST(test_das_access_modes)
{
    _init_svc();
    ozayn_das_session_t *s = NULL;

    ASSERT_EQ(ozayn_das_session_create(&_svc, "D1", "C1",
              OZAYN_DAS_MODE_OBSERVE, NULL, "r", NULL, NULL, NULL, &s),
              OZAYN_DAS_OK);
    ASSERT_EQ(s->access_mode, OZAYN_DAS_MODE_OBSERVE);

    ASSERT_EQ(ozayn_das_session_create(&_svc, "D2", "C2",
              OZAYN_DAS_MODE_INPUT, NULL, "r", NULL, NULL, NULL, &s),
              OZAYN_DAS_OK);
    ASSERT_EQ(s->access_mode, OZAYN_DAS_MODE_INPUT);

    ASSERT_EQ(ozayn_das_session_create(&_svc, "D3", "C3",
              OZAYN_DAS_MODE_OUTPUT, NULL, "r", NULL, NULL, NULL, &s),
              OZAYN_DAS_OK);
    ASSERT_EQ(s->access_mode, OZAYN_DAS_MODE_OUTPUT);

    ASSERT_EQ(ozayn_das_session_create(&_svc, "D4", "C4",
              OZAYN_DAS_MODE_CONTROL, NULL, "r", NULL, NULL, NULL, &s),
              OZAYN_DAS_OK);
    ASSERT_EQ(s->access_mode, OZAYN_DAS_MODE_CONTROL);

    ASSERT_EQ(ozayn_das_session_create(&_svc, "D5", "C5",
              OZAYN_DAS_MODE_STREAM, NULL, "r", NULL, NULL, NULL, &s),
              OZAYN_DAS_OK);
    ASSERT_EQ(s->access_mode, OZAYN_DAS_MODE_STREAM);

    ozayn_das_service_shutdown(&_svc);
    return 0;
}

/* ============================================================
 * MULTI-SESSION TESTS
 * ============================================================ */

TEST(test_das_multiple_sessions)
{
    _init_svc();
    ozayn_das_session_t *s1 = NULL, *s2 = NULL, *s3 = NULL;
    ozayn_das_session_create(&_svc, "CAM-1", "CAP1", 0, NULL, "r1",
                             NULL, NULL, NULL, &s1);
    ozayn_das_session_create(&_svc, "MIC-1", "CAP2", 0, NULL, "r2",
                             NULL, NULL, NULL, &s2);
    ozayn_das_session_create(&_svc, "GPU-1", "CAP3", 0, NULL, "r3",
                             NULL, NULL, NULL, &s3);

    ASSERT_EQ(ozayn_das_session_count(&_svc), 3);
    ASSERT_NOT_NULL(ozayn_das_session_get_by_device(&_svc, "CAM-1"));
    ASSERT_NOT_NULL(ozayn_das_session_get_by_device(&_svc, "MIC-1"));
    ASSERT_NOT_NULL(ozayn_das_session_get_by_device(&_svc, "GPU-1"));

    ozayn_das_session_cancel(&_svc, s1->session_id);
    ASSERT_EQ(ozayn_das_session_count(&_svc), 2);
    ozayn_das_service_shutdown(&_svc);
    return 0;
}

TEST(test_das_rejection_emits_event)
{
    _init_svc();
    ozayn_das_session_t *s = NULL;
    ozayn_das_session_create(&_svc, "CAM-1", "CAP", 0, NULL, "req",
                             NULL, NULL, NULL, &s);
    ozayn_das_session_cancel(&_svc, s->session_id);
    int found = 0;
    for (int i = 0; i < ozayn_das_event_count(&_svc); i++) {
        const ozayn_das_event_t *ev = ozayn_das_event_get(&_svc, i);
        if (ev->type == OZAYN_DAS_EVENT_SESSION_FAILED) {
            found = 1;
            break;
        }
    }
    ASSERT(found);
    ozayn_das_service_shutdown(&_svc);
    return 0;
}

TEST(test_das_reservation_required_for_reserve)
{
    _init_svc();
    ozayn_das_session_t *s = NULL;
    ozayn_das_session_create(&_svc, "CAM-1", "CAP", 0, NULL, "req",
                             NULL, NULL, NULL, &s);
    ozayn_das_session_authorize(&_svc, s->session_id);
    ASSERT_EQ(ozayn_das_session_reserve(&_svc, s->session_id),
              OZAYN_DAS_ERR_RESERVATION_INVALID);
    ozayn_das_service_shutdown(&_svc);
    return 0;
}

TEST(test_das_close_idempotent_terminal)
{
    _init_svc();
    ozayn_das_session_t *s = NULL;
    ozayn_das_session_create(&_svc, "CAM-1", "CAP", 0, NULL, "req",
                             NULL, NULL, NULL, &s);

    ozayn_das_session_close(&_svc, s->session_id, OZAYN_DAS_CLOSE_MANUAL_CLOSE);
    ASSERT_EQ(ozayn_das_session_close(&_svc, s->session_id,
              OZAYN_DAS_CLOSE_MANUAL_CLOSE), OZAYN_DAS_ERR_NOT_FOUND);
    ASSERT_EQ(ozayn_das_session_revoke(&_svc, s->session_id,
              OZAYN_DAS_CLOSE_TIMEOUT), OZAYN_DAS_ERR_NOT_FOUND);
    ASSERT_EQ(ozayn_das_session_cancel(&_svc, s->session_id),
              OZAYN_DAS_ERR_NOT_FOUND);
    ozayn_das_service_shutdown(&_svc);
    return 0;
}

/* ============================================================
 * TEST RUNNER
 * ============================================================ */

int run_cr_device_session_tests(void)
{
    SUITE_BEGIN("Device Access Sessions");

    RUN(test_das_init);
    RUN(test_das_init_null);
    RUN(test_das_init_null_config);
    RUN(test_das_init_double);
    RUN(test_das_init_custom_config);
    RUN(test_das_shutdown);
    RUN(test_das_shutdown_null);
    RUN(test_das_is_initialized_null);
    RUN(test_das_global_singleton);

    RUN(test_das_session_create);
    RUN(test_das_session_create_null);
    RUN(test_das_session_create_not_init);
    RUN(test_das_session_create_empty_device);
    RUN(test_das_session_create_empty_capability);
    RUN(test_das_session_create_empty_requester);
    RUN(test_das_session_create_invalid_mode);
    RUN(test_das_session_create_null_out);
    RUN(test_das_session_create_limit);
    RUN(test_das_session_create_emits_event);

    RUN(test_das_full_lifecycle);
    RUN(test_das_authorize_from_wrong_state);
    RUN(test_das_open_from_wrong_state);
    RUN(test_das_activate_from_wrong_state);
    RUN(test_das_heartbeat_active);
    RUN(test_das_heartbeat_wrong_state);
    RUN(test_das_idle_active_resume);

    RUN(test_das_cancel);
    RUN(test_das_cancel_wrong_state);
    RUN(test_das_revoke);
    RUN(test_das_revoke_wrong_state);
    RUN(test_das_close_device_unavailable);
    RUN(test_das_close_from_closed);

    RUN(test_das_get);
    RUN(test_das_get_by_device);
    RUN(test_das_get_by_reservation);
    RUN(test_das_count);
    RUN(test_das_count_by_device);
    RUN(test_das_is_active);
    RUN(test_das_is_expired);

    RUN(test_das_authorize_expired_session);
    RUN(test_das_not_found);
    RUN(test_das_null_params);

    RUN(test_das_cleanup_expired);
    RUN(test_das_cleanup_idle);
    RUN(test_das_cleanup_null);

    RUN(test_das_emit_event);
    RUN(test_das_event_ring_buffer);
    RUN(test_das_event_get_invalid);

    RUN(test_das_stats);
    RUN(test_das_stats_null);

    RUN(test_das_session_validate);
    RUN(test_das_state_transition_valid);

    RUN(test_das_access_mode_name);
    RUN(test_das_session_state_name);
    RUN(test_das_close_reason_name);
    RUN(test_das_event_type_name);
    RUN(test_das_err_name);

    RUN(test_das_camera_no_auto_activate);
    RUN(test_das_mic_no_auto_activate);
    RUN(test_das_no_secrets_in_session);
    RUN(test_das_no_secrets_in_event);

    RUN(test_das_access_modes);
    RUN(test_das_multiple_sessions);
    RUN(test_das_rejection_emits_event);
    RUN(test_das_reservation_required_for_reserve);
    RUN(test_das_close_idempotent_terminal);

    SUITE_END();
    return TOTAL_FAIL();
}
