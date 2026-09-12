#include "../device_io.h"
#include "../../tests/test_framework.h"
#include <string.h>
#include <time.h>

/* ============================================================
 * HELPERS
 * ============================================================ */

static ozayn_dio_service_t _svc;
static ozayn_dio_service_config_t _cfg;

static void _reset_all(void)
{
    memset(&_svc, 0, sizeof(_svc));
}

static void _init_svc(void)
{
    _reset_all();
    memset(&_cfg, 0, sizeof(_cfg));
    ozayn_dio_service_init(&_svc, &_cfg);
}

static void _make_desc(ozayn_dio_device_desc_t *d, const char *id,
                        ozayn_dio_device_type_t type, const char *name)
{
    memset(d, 0, sizeof(*d));
    strncpy(d->device_id, id, OZAYN_DIO_MAX_ID_LEN - 1);
    d->type = type;
    strncpy(d->name, name, OZAYN_DIO_MAX_NAME_LEN - 1);
    strncpy(d->provider, "test-provider", OZAYN_DIO_MAX_PROVIDER_LEN - 1);
    strncpy(d->platform, "linux", OZAYN_DIO_MAX_PROVIDER_LEN - 1);
    strncpy(d->version, "1.0", OZAYN_DIO_MAX_VERSION_LEN - 1);
    d->state = OZAYN_DIO_STATE_AVAILABLE;
    d->availability = OZAYN_DIO_AVAIL_AVAILABLE;
    d->health = OZAYN_DIO_HEALTH_HEALTHY;
    d->access_mode = OZAYN_DIO_ACCESS_EXCLUSIVE;
}

/* ============================================================
 * LIFECYCLE TESTS
 * ============================================================ */

TEST(test_dio_init)
{
    _reset_all();
    memset(&_cfg, 0, sizeof(_cfg));
    ASSERT_EQ(ozayn_dio_service_init(&_svc, &_cfg), OZAYN_DIO_OK);
    ASSERT(ozayn_dio_service_is_initialized(&_svc));
    ozayn_dio_service_shutdown(&_svc);
    return 0;
}

TEST(test_dio_init_null)
{
    ASSERT_EQ(ozayn_dio_service_init(NULL, &_cfg), OZAYN_DIO_ERR_NULL);
    return 0;
}

TEST(test_dio_init_null_config)
{
    _reset_all();
    ASSERT_EQ(ozayn_dio_service_init(&_svc, NULL), OZAYN_DIO_ERR_NULL);
    return 0;
}

TEST(test_dio_init_double)
{
    _init_svc();
    ASSERT_EQ(ozayn_dio_service_init(&_svc, &_cfg), OZAYN_DIO_ERR_ALREADY_INIT);
    ozayn_dio_service_shutdown(&_svc);
    return 0;
}

TEST(test_dio_init_custom_config)
{
    _reset_all();
    memset(&_cfg, 0, sizeof(_cfg));
    _cfg.max_devices = 4;
    _cfg.max_reservations = 2;
    _cfg.max_events = 8;
    _cfg.reservation_ttl_ms = 3000;
    ASSERT_EQ(ozayn_dio_service_init(&_svc, &_cfg), OZAYN_DIO_OK);
    ASSERT_EQ(_svc.config.max_devices, 4);
    ASSERT_EQ(_svc.config.max_reservations, 2);
    ASSERT_EQ(_svc.config.max_events, 8);
    ASSERT_EQ(_svc.config.reservation_ttl_ms, 3000);
    ozayn_dio_service_shutdown(&_svc);
    return 0;
}

TEST(test_dio_shutdown)
{
    _init_svc();
    ozayn_dio_service_shutdown(&_svc);
    ASSERT(!ozayn_dio_service_is_initialized(&_svc));
    return 0;
}

TEST(test_dio_shutdown_null)
{
    ozayn_dio_service_shutdown(NULL);
    return 0;
}

TEST(test_dio_is_initialized_null)
{
    ASSERT(!ozayn_dio_service_is_initialized(NULL));
    return 0;
}

TEST(test_dio_global_singleton)
{
    ozayn_dio_service_t *g = ozayn_dio_get_global();
    ASSERT_NOT_NULL(g);
    return 0;
}

/* ============================================================
 * REGISTRATION TESTS
 * ============================================================ */

TEST(test_dio_register)
{
    _init_svc();
    ozayn_dio_device_desc_t d, *out = NULL;
    _make_desc(&d, "DEV-1", OZAYN_DIO_DEV_CAMERA, "Test Camera");
    ASSERT_EQ(ozayn_dio_device_register(&_svc, &d, &out), OZAYN_DIO_OK);
    ASSERT_NOT_NULL(out);
    ASSERT_STR_EQ(out->device_id, "DEV-1");
    ASSERT_EQ(_svc.device_count, 1);
    ozayn_dio_service_shutdown(&_svc);
    return 0;
}

TEST(test_dio_register_null)
{
    ASSERT_EQ(ozayn_dio_device_register(NULL, NULL, NULL),
              OZAYN_DIO_ERR_NULL);
    return 0;
}

TEST(test_dio_register_not_init)
{
    _reset_all();
    ozayn_dio_device_desc_t d, *out = NULL;
    _make_desc(&d, "DEV-1", OZAYN_DIO_DEV_CAMERA, "Cam");
    ASSERT_EQ(ozayn_dio_device_register(&_svc, &d, &out),
              OZAYN_DIO_ERR_NOT_INITIALIZED);
    return 0;
}

TEST(test_dio_register_null_desc)
{
    _init_svc();
    ozayn_dio_device_desc_t *out = NULL;
    ASSERT_EQ(ozayn_dio_device_register(&_svc, NULL, &out),
              OZAYN_DIO_ERR_NULL);
    ozayn_dio_service_shutdown(&_svc);
    return 0;
}

TEST(test_dio_register_empty_id)
{
    _init_svc();
    ozayn_dio_device_desc_t d, *out = NULL;
    _make_desc(&d, "", OZAYN_DIO_DEV_CAMERA, "Cam");
    ASSERT_EQ(ozayn_dio_device_register(&_svc, &d, &out),
              OZAYN_DIO_ERR_INVALID_PARAM);
    ozayn_dio_service_shutdown(&_svc);
    return 0;
}

TEST(test_dio_register_invalid_type)
{
    _init_svc();
    ozayn_dio_device_desc_t d, *out = NULL;
    _make_desc(&d, "DEV-X", (ozayn_dio_device_type_t)99, "Cam");
    ASSERT_EQ(ozayn_dio_device_register(&_svc, &d, &out),
              OZAYN_DIO_ERR_INVALID_PARAM);
    ozayn_dio_service_shutdown(&_svc);
    return 0;
}

TEST(test_dio_register_null_out)
{
    _init_svc();
    ozayn_dio_device_desc_t d;
    _make_desc(&d, "DEV-1", OZAYN_DIO_DEV_CAMERA, "Cam");
    ASSERT_EQ(ozayn_dio_device_register(&_svc, &d, NULL),
              OZAYN_DIO_ERR_NULL);
    ozayn_dio_service_shutdown(&_svc);
    return 0;
}

TEST(test_dio_register_duplicate)
{
    _init_svc();
    ozayn_dio_device_desc_t d1, d2, *out1 = NULL, *out2 = NULL;
    _make_desc(&d1, "DEV-1", OZAYN_DIO_DEV_CAMERA, "Cam1");
    _make_desc(&d2, "DEV-1", OZAYN_DIO_DEV_MICROPHONE, "Mic1");
    ASSERT_EQ(ozayn_dio_device_register(&_svc, &d1, &out1), OZAYN_DIO_OK);
    ASSERT_EQ(ozayn_dio_device_register(&_svc, &d2, &out2),
              OZAYN_DIO_ERR_DUPLICATE);
    ozayn_dio_service_shutdown(&_svc);
    return 0;
}

TEST(test_dio_register_limit)
{
    _reset_all();
    memset(&_cfg, 0, sizeof(_cfg));
    _cfg.max_devices = 2;
    ozayn_dio_service_init(&_svc, &_cfg);
    ozayn_dio_device_desc_t d, *out = NULL;
    _make_desc(&d, "D1", OZAYN_DIO_DEV_CAMERA, "C1");
    ASSERT_EQ(ozayn_dio_device_register(&_svc, &d, &out), OZAYN_DIO_OK);
    _make_desc(&d, "D2", OZAYN_DIO_DEV_GPU, "G1");
    ASSERT_EQ(ozayn_dio_device_register(&_svc, &d, &out), OZAYN_DIO_OK);
    _make_desc(&d, "D3", OZAYN_DIO_DEV_DISPLAY, "D3");
    ASSERT_EQ(ozayn_dio_device_register(&_svc, &d, &out),
              OZAYN_DIO_ERR_LIMIT_REACHED);
    ozayn_dio_service_shutdown(&_svc);
    return 0;
}

TEST(test_dio_unregister)
{
    _init_svc();
    ozayn_dio_device_desc_t d, *out = NULL;
    _make_desc(&d, "DEV-1", OZAYN_DIO_DEV_CAMERA, "Cam");
    ASSERT_EQ(ozayn_dio_device_register(&_svc, &d, &out), OZAYN_DIO_OK);
    ASSERT_EQ(ozayn_dio_device_unregister(&_svc, "DEV-1"), OZAYN_DIO_OK);
    ASSERT_EQ(_svc.device_count, 0);
    ozayn_dio_service_shutdown(&_svc);
    return 0;
}

TEST(test_dio_unregister_not_found)
{
    _init_svc();
    ASSERT_EQ(ozayn_dio_device_unregister(&_svc, "NOPE"),
              OZAYN_DIO_ERR_NOT_FOUND);
    ozayn_dio_service_shutdown(&_svc);
    return 0;
}

TEST(test_dio_get)
{
    _init_svc();
    ozayn_dio_device_desc_t d, *out = NULL;
    _make_desc(&d, "DEV-1", OZAYN_DIO_DEV_CAMERA, "Cam");
    ozayn_dio_device_register(&_svc, &d, &out);
    const ozayn_dio_device_desc_t *found = ozayn_dio_device_get(&_svc,
                                                                 "DEV-1");
    ASSERT_NOT_NULL(found);
    ASSERT_STR_EQ(found->device_id, "DEV-1");
    ASSERT_NULL(ozayn_dio_device_get(&_svc, "NOPE"));
    ozayn_dio_service_shutdown(&_svc);
    return 0;
}

TEST(test_dio_get_by_type)
{
    _init_svc();
    ozayn_dio_device_desc_t d, *out = NULL;
    _make_desc(&d, "CAM-1", OZAYN_DIO_DEV_CAMERA, "Cam");
    ozayn_dio_device_register(&_svc, &d, &out);
    const ozayn_dio_device_desc_t *found =
        ozayn_dio_device_get_by_type(&_svc, OZAYN_DIO_DEV_CAMERA);
    ASSERT_NOT_NULL(found);
    ASSERT_STR_EQ(found->device_id, "CAM-1");
    ASSERT_NULL(ozayn_dio_device_get_by_type(&_svc, OZAYN_DIO_DEV_GPU));
    ozayn_dio_service_shutdown(&_svc);
    return 0;
}

TEST(test_dio_exists)
{
    _init_svc();
    ozayn_dio_device_desc_t d, *out = NULL;
    _make_desc(&d, "DEV-1", OZAYN_DIO_DEV_CAMERA, "Cam");
    ozayn_dio_device_register(&_svc, &d, &out);
    ASSERT(ozayn_dio_device_exists(&_svc, "DEV-1"));
    ASSERT(!ozayn_dio_device_exists(&_svc, "NOPE"));
    ozayn_dio_service_shutdown(&_svc);
    return 0;
}

TEST(test_dio_count)
{
    _init_svc();
    ASSERT_EQ(ozayn_dio_device_count(&_svc), 0);
    ozayn_dio_device_desc_t d, *out = NULL;
    _make_desc(&d, "D1", OZAYN_DIO_DEV_CAMERA, "C1");
    ozayn_dio_device_register(&_svc, &d, &out);
    ASSERT_EQ(ozayn_dio_device_count(&_svc), 1);
    _make_desc(&d, "D2", OZAYN_DIO_DEV_GPU, "G1");
    ozayn_dio_device_register(&_svc, &d, &out);
    ASSERT_EQ(ozayn_dio_device_count(&_svc), 2);
    ozayn_dio_service_shutdown(&_svc);
    return 0;
}

TEST(test_dio_full)
{
    _reset_all();
    memset(&_cfg, 0, sizeof(_cfg));
    _cfg.max_devices = 1;
    ozayn_dio_service_init(&_svc, &_cfg);
    ASSERT(!ozayn_dio_device_full(&_svc));
    ozayn_dio_device_desc_t d, *out = NULL;
    _make_desc(&d, "D1", OZAYN_DIO_DEV_CAMERA, "C1");
    ozayn_dio_device_register(&_svc, &d, &out);
    ASSERT(ozayn_dio_device_full(&_svc));
    ozayn_dio_service_shutdown(&_svc);
    return 0;
}

/* ============================================================
 * STATE MANAGEMENT TESTS
 * ============================================================ */

TEST(test_dio_update_state)
{
    _init_svc();
    ozayn_dio_device_desc_t d, *out = NULL;
    _make_desc(&d, "DEV-1", OZAYN_DIO_DEV_CAMERA, "Cam");
    ozayn_dio_device_register(&_svc, &d, &out);
    ASSERT_EQ(ozayn_dio_device_update_state(&_svc, "DEV-1",
              OZAYN_DIO_STATE_ACTIVE), OZAYN_DIO_OK);
    ASSERT_EQ(_svc.devices[0].state, OZAYN_DIO_STATE_ACTIVE);
    ozayn_dio_service_shutdown(&_svc);
    return 0;
}

TEST(test_dio_update_state_not_found)
{
    _init_svc();
    ASSERT_EQ(ozayn_dio_device_update_state(&_svc, "NOPE",
              OZAYN_DIO_STATE_ACTIVE), OZAYN_DIO_ERR_NOT_FOUND);
    ozayn_dio_service_shutdown(&_svc);
    return 0;
}

TEST(test_dio_update_state_invalid)
{
    _init_svc();
    ozayn_dio_device_desc_t d, *out = NULL;
    _make_desc(&d, "DEV-1", OZAYN_DIO_DEV_CAMERA, "Cam");
    ozayn_dio_device_register(&_svc, &d, &out);
    ASSERT_EQ(ozayn_dio_device_update_state(&_svc, "DEV-1",
              (ozayn_dio_device_state_t)99),
              OZAYN_DIO_ERR_INVALID_PARAM);
    ozayn_dio_service_shutdown(&_svc);
    return 0;
}

TEST(test_dio_update_availability)
{
    _init_svc();
    ozayn_dio_device_desc_t d, *out = NULL;
    _make_desc(&d, "DEV-1", OZAYN_DIO_DEV_CAMERA, "Cam");
    ozayn_dio_device_register(&_svc, &d, &out);
    ASSERT_EQ(ozayn_dio_device_update_availability(&_svc, "DEV-1",
              OZAYN_DIO_AVAIL_UNAVAILABLE), OZAYN_DIO_OK);
    ASSERT_EQ(_svc.devices[0].availability, OZAYN_DIO_AVAIL_UNAVAILABLE);
    ozayn_dio_service_shutdown(&_svc);
    return 0;
}

TEST(test_dio_update_health)
{
    _init_svc();
    ozayn_dio_device_desc_t d, *out = NULL;
    _make_desc(&d, "DEV-1", OZAYN_DIO_DEV_CAMERA, "Cam");
    ozayn_dio_device_register(&_svc, &d, &out);
    ASSERT_EQ(ozayn_dio_device_update_health(&_svc, "DEV-1",
              OZAYN_DIO_HEALTH_DEGRADED), OZAYN_DIO_OK);
    ASSERT_EQ(_svc.devices[0].health, OZAYN_DIO_HEALTH_DEGRADED);
    ozayn_dio_service_shutdown(&_svc);
    return 0;
}

/* ============================================================
 * CAPABILITY TESTS
 * ============================================================ */

TEST(test_dio_capability_add)
{
    _init_svc();
    ozayn_dio_device_desc_t d, *out = NULL;
    _make_desc(&d, "DEV-1", OZAYN_DIO_DEV_CAMERA, "Cam");
    ozayn_dio_device_register(&_svc, &d, &out);

    ozayn_dio_capability_t cap;
    memset(&cap, 0, sizeof(cap));
    cap.type = OZAYN_DIO_CAP_CAMERA_CAPTURE;
    cap.state = OZAYN_DIO_CAP_STATE_IMPLEMENTED;
    ASSERT_EQ(ozayn_dio_capability_add(&_svc, "DEV-1", &cap), OZAYN_DIO_OK);
    ASSERT_EQ(ozayn_dio_capability_count(&_svc, "DEV-1"), 1);
    ozayn_dio_service_shutdown(&_svc);
    return 0;
}

TEST(test_dio_capability_add_not_found)
{
    _init_svc();
    ozayn_dio_capability_t cap;
    memset(&cap, 0, sizeof(cap));
    cap.type = OZAYN_DIO_CAP_CAMERA_CAPTURE;
    ASSERT_EQ(ozayn_dio_capability_add(&_svc, "NOPE", &cap),
              OZAYN_DIO_ERR_NOT_FOUND);
    ozayn_dio_service_shutdown(&_svc);
    return 0;
}

TEST(test_dio_capability_add_duplicate)
{
    _init_svc();
    ozayn_dio_device_desc_t d, *out = NULL;
    _make_desc(&d, "DEV-1", OZAYN_DIO_DEV_CAMERA, "Cam");
    ozayn_dio_device_register(&_svc, &d, &out);

    ozayn_dio_capability_t cap;
    memset(&cap, 0, sizeof(cap));
    cap.type = OZAYN_DIO_CAP_CAMERA_CAPTURE;
    cap.state = OZAYN_DIO_CAP_STATE_IMPLEMENTED;
    ASSERT_EQ(ozayn_dio_capability_add(&_svc, "DEV-1", &cap), OZAYN_DIO_OK);
    ASSERT_EQ(ozayn_dio_capability_add(&_svc, "DEV-1", &cap),
              OZAYN_DIO_ERR_DUPLICATE);
    ozayn_dio_service_shutdown(&_svc);
    return 0;
}

TEST(test_dio_capability_add_limit)
{
    _init_svc();
    ozayn_dio_device_desc_t d, *out = NULL;
    _make_desc(&d, "DEV-1", OZAYN_DIO_DEV_CAMERA, "Cam");
    ozayn_dio_device_register(&_svc, &d, &out);

    ozayn_dio_capability_t cap;
    for (int i = 0; i < OZAYN_DIO_MAX_CAPABILITIES; i++) {
        memset(&cap, 0, sizeof(cap));
        cap.type = (ozayn_dio_capability_type_t)i;
        cap.state = OZAYN_DIO_CAP_STATE_IMPLEMENTED;
        ASSERT_EQ(ozayn_dio_capability_add(&_svc, "DEV-1", &cap),
                  OZAYN_DIO_OK);
    }
    memset(&cap, 0, sizeof(cap));
    cap.type = OZAYN_DIO_CAP_CAMERA_CAPTURE;
    ASSERT_EQ(ozayn_dio_capability_add(&_svc, "DEV-1", &cap),
              OZAYN_DIO_ERR_LIMIT_REACHED);
    ozayn_dio_service_shutdown(&_svc);
    return 0;
}

TEST(test_dio_capability_remove)
{
    _init_svc();
    ozayn_dio_device_desc_t d, *out = NULL;
    _make_desc(&d, "DEV-1", OZAYN_DIO_DEV_CAMERA, "Cam");
    ozayn_dio_device_register(&_svc, &d, &out);

    ozayn_dio_capability_t cap;
    memset(&cap, 0, sizeof(cap));
    cap.type = OZAYN_DIO_CAP_CAMERA_CAPTURE;
    cap.state = OZAYN_DIO_CAP_STATE_IMPLEMENTED;
    ozayn_dio_capability_add(&_svc, "DEV-1", &cap);

    ASSERT_EQ(ozayn_dio_capability_remove(&_svc, "DEV-1",
              OZAYN_DIO_CAP_CAMERA_CAPTURE), OZAYN_DIO_OK);
    ASSERT_EQ(ozayn_dio_capability_count(&_svc, "DEV-1"), 0);
    ozayn_dio_service_shutdown(&_svc);
    return 0;
}

TEST(test_dio_capability_remove_not_found)
{
    _init_svc();
    ozayn_dio_device_desc_t d, *out = NULL;
    _make_desc(&d, "DEV-1", OZAYN_DIO_DEV_CAMERA, "Cam");
    ozayn_dio_device_register(&_svc, &d, &out);
    ASSERT_EQ(ozayn_dio_capability_remove(&_svc, "DEV-1",
              OZAYN_DIO_CAP_CAMERA_CAPTURE), OZAYN_DIO_ERR_NOT_FOUND);
    ozayn_dio_service_shutdown(&_svc);
    return 0;
}

TEST(test_dio_capability_get)
{
    _init_svc();
    ozayn_dio_device_desc_t d, *out = NULL;
    _make_desc(&d, "DEV-1", OZAYN_DIO_DEV_CAMERA, "Cam");
    ozayn_dio_device_register(&_svc, &d, &out);

    ozayn_dio_capability_t cap;
    memset(&cap, 0, sizeof(cap));
    cap.type = OZAYN_DIO_CAP_CAMERA_CAPTURE;
    cap.state = OZAYN_DIO_CAP_STATE_IMPLEMENTED;
    ozayn_dio_capability_add(&_svc, "DEV-1", &cap);

    const ozayn_dio_capability_t *found =
        ozayn_dio_capability_get(&_svc, "DEV-1", OZAYN_DIO_CAP_CAMERA_CAPTURE);
    ASSERT_NOT_NULL(found);
    ASSERT(found->active);
    ASSERT_NULL(ozayn_dio_capability_get(&_svc, "DEV-1",
                OZAYN_DIO_CAP_GPU_COMPUTE));
    ozayn_dio_service_shutdown(&_svc);
    return 0;
}

TEST(test_dio_capability_is_available)
{
    _init_svc();
    ozayn_dio_device_desc_t d, *out = NULL;
    _make_desc(&d, "DEV-1", OZAYN_DIO_DEV_CAMERA, "Cam");
    ozayn_dio_device_register(&_svc, &d, &out);

    ozayn_dio_capability_t cap;
    memset(&cap, 0, sizeof(cap));
    cap.type = OZAYN_DIO_CAP_CAMERA_CAPTURE;
    cap.state = OZAYN_DIO_CAP_STATE_IMPLEMENTED;
    ozayn_dio_capability_add(&_svc, "DEV-1", &cap);

    ASSERT(ozayn_dio_capability_is_available(&_svc, "DEV-1",
           OZAYN_DIO_CAP_CAMERA_CAPTURE));

    ASSERT(!ozayn_dio_capability_is_available(&_svc, "DEV-1",
            OZAYN_DIO_CAP_GPU_COMPUTE));

    ASSERT(!ozayn_dio_capability_is_available(&_svc, "NOPE",
            OZAYN_DIO_CAP_CAMERA_CAPTURE));
    ozayn_dio_service_shutdown(&_svc);
    return 0;
}

TEST(test_dio_capability_planned_not_available)
{
    _init_svc();
    ozayn_dio_device_desc_t d, *out = NULL;
    _make_desc(&d, "DEV-1", OZAYN_DIO_DEV_CAMERA, "Cam");
    ozayn_dio_device_register(&_svc, &d, &out);

    ozayn_dio_capability_t cap;
    memset(&cap, 0, sizeof(cap));
    cap.type = OZAYN_DIO_CAP_CAMERA_CAPTURE;
    cap.state = OZAYN_DIO_CAP_STATE_PLANNED;
    ozayn_dio_capability_add(&_svc, "DEV-1", &cap);

    ASSERT(!ozayn_dio_capability_is_available(&_svc, "DEV-1",
            OZAYN_DIO_CAP_CAMERA_CAPTURE));
    ozayn_dio_service_shutdown(&_svc);
    return 0;
}

/* ============================================================
 * RESERVATION TESTS
 * ============================================================ */

TEST(test_dio_reservation_create)
{
    _init_svc();
    ozayn_dio_device_desc_t d, *out = NULL;
    _make_desc(&d, "DEV-1", OZAYN_DIO_DEV_CAMERA, "Cam");
    ozayn_dio_device_register(&_svc, &d, &out);

    ozayn_dio_reservation_t *rsv = NULL;
    ASSERT_EQ(ozayn_dio_reservation_create(&_svc, "DEV-1", "requester-1",
              NULL, OZAYN_DIO_CAP_CAMERA_CAPTURE, &rsv), OZAYN_DIO_OK);
    ASSERT_NOT_NULL(rsv);
    ASSERT_STR_EQ(rsv->device_id, "DEV-1");
    ASSERT_STR_EQ(rsv->requester_ref, "requester-1");
    ASSERT_EQ(rsv->state, OZAYN_DIO_RES_STATE_REQUESTED);
    ASSERT_EQ(_svc.reservation_count, 1);
    ozayn_dio_service_shutdown(&_svc);
    return 0;
}

TEST(test_dio_reservation_create_not_found)
{
    _init_svc();
    ozayn_dio_reservation_t *rsv = NULL;
    ASSERT_EQ(ozayn_dio_reservation_create(&_svc, "NOPE", "req", NULL,
              OZAYN_DIO_CAP_CAMERA_CAPTURE, &rsv),
              OZAYN_DIO_ERR_NOT_FOUND);
    ozayn_dio_service_shutdown(&_svc);
    return 0;
}

TEST(test_dio_reservation_create_invalid_state)
{
    _init_svc();
    ozayn_dio_device_desc_t d, *out = NULL;
    _make_desc(&d, "DEV-1", OZAYN_DIO_DEV_CAMERA, "Cam");
    d.availability = OZAYN_DIO_AVAIL_UNAVAILABLE;
    ozayn_dio_device_register(&_svc, &d, &out);

    ozayn_dio_reservation_t *rsv = NULL;
    ASSERT_EQ(ozayn_dio_reservation_create(&_svc, "DEV-1", "req", NULL,
              OZAYN_DIO_CAP_CAMERA_CAPTURE, &rsv),
              OZAYN_DIO_ERR_UNAVAILABLE);
    ozayn_dio_service_shutdown(&_svc);
    return 0;
}

TEST(test_dio_reservation_exclusive_conflict)
{
    _init_svc();
    ozayn_dio_device_desc_t d, *out = NULL;
    _make_desc(&d, "DEV-1", OZAYN_DIO_DEV_CAMERA, "Cam");
    d.access_mode = OZAYN_DIO_ACCESS_EXCLUSIVE;
    ozayn_dio_device_register(&_svc, &d, &out);

    ozayn_dio_reservation_t *r1 = NULL, *r2 = NULL;
    ASSERT_EQ(ozayn_dio_reservation_create(&_svc, "DEV-1", "req1", NULL,
              OZAYN_DIO_CAP_CAMERA_CAPTURE, &r1), OZAYN_DIO_OK);
    r1->state = OZAYN_DIO_RES_STATE_RESERVED;

    ASSERT_EQ(ozayn_dio_reservation_create(&_svc, "DEV-1", "req2", NULL,
              OZAYN_DIO_CAP_CAMERA_CAPTURE, &r2),
              OZAYN_DIO_ERR_RESERVATION_CONFLICT);
    ozayn_dio_service_shutdown(&_svc);
    return 0;
}

TEST(test_dio_reservation_activate)
{
    _init_svc();
    ozayn_dio_device_desc_t d, *out = NULL;
    _make_desc(&d, "DEV-1", OZAYN_DIO_DEV_CAMERA, "Cam");
    ozayn_dio_device_register(&_svc, &d, &out);

    ozayn_dio_reservation_t *rsv = NULL;
    ozayn_dio_reservation_create(&_svc, "DEV-1", "req", NULL,
                                 OZAYN_DIO_CAP_CAMERA_CAPTURE, &rsv);
    rsv->state = OZAYN_DIO_RES_STATE_RESERVED;

    ASSERT_EQ(ozayn_dio_reservation_activate(&_svc, rsv->reservation_id),
              OZAYN_DIO_OK);
    ASSERT_EQ(rsv->state, OZAYN_DIO_RES_STATE_ACTIVE);
    ozayn_dio_service_shutdown(&_svc);
    return 0;
}

TEST(test_dio_reservation_activate_wrong_state)
{
    _init_svc();
    ozayn_dio_device_desc_t d, *out = NULL;
    _make_desc(&d, "DEV-1", OZAYN_DIO_DEV_CAMERA, "Cam");
    ozayn_dio_device_register(&_svc, &d, &out);

    ozayn_dio_reservation_t *rsv = NULL;
    ozayn_dio_reservation_create(&_svc, "DEV-1", "req", NULL,
                                 OZAYN_DIO_CAP_CAMERA_CAPTURE, &rsv);
    ASSERT_EQ(ozayn_dio_reservation_activate(&_svc, rsv->reservation_id),
              OZAYN_DIO_ERR_STATE_INVALID);
    ozayn_dio_service_shutdown(&_svc);
    return 0;
}

TEST(test_dio_reservation_release)
{
    _init_svc();
    ozayn_dio_device_desc_t d, *out = NULL;
    _make_desc(&d, "DEV-1", OZAYN_DIO_DEV_CAMERA, "Cam");
    ozayn_dio_device_register(&_svc, &d, &out);

    ozayn_dio_reservation_t *rsv = NULL;
    ozayn_dio_reservation_create(&_svc, "DEV-1", "req", NULL,
                                 OZAYN_DIO_CAP_CAMERA_CAPTURE, &rsv);
    rsv->state = OZAYN_DIO_RES_STATE_RESERVED;

    ASSERT_EQ(ozayn_dio_reservation_release(&_svc, rsv->reservation_id),
              OZAYN_DIO_OK);
    ASSERT_EQ(rsv->state, OZAYN_DIO_RES_STATE_RELEASED);
    ASSERT(!rsv->active);
    ozayn_dio_service_shutdown(&_svc);
    return 0;
}

TEST(test_dio_reservation_cancel)
{
    _init_svc();
    ozayn_dio_device_desc_t d, *out = NULL;
    _make_desc(&d, "DEV-1", OZAYN_DIO_DEV_CAMERA, "Cam");
    ozayn_dio_device_register(&_svc, &d, &out);

    ozayn_dio_reservation_t *rsv = NULL;
    ozayn_dio_reservation_create(&_svc, "DEV-1", "req", NULL,
                                 OZAYN_DIO_CAP_CAMERA_CAPTURE, &rsv);

    ASSERT_EQ(ozayn_dio_reservation_cancel(&_svc, rsv->reservation_id),
              OZAYN_DIO_OK);
    ASSERT_EQ(rsv->state, OZAYN_DIO_RES_STATE_CANCELLED);
    ozayn_dio_service_shutdown(&_svc);
    return 0;
}

TEST(test_dio_reservation_get)
{
    _init_svc();
    ozayn_dio_device_desc_t d, *out = NULL;
    _make_desc(&d, "DEV-1", OZAYN_DIO_DEV_CAMERA, "Cam");
    ozayn_dio_device_register(&_svc, &d, &out);

    ozayn_dio_reservation_t *rsv = NULL;
    ozayn_dio_reservation_create(&_svc, "DEV-1", "req", NULL,
                                 OZAYN_DIO_CAP_CAMERA_CAPTURE, &rsv);
    const ozayn_dio_reservation_t *found =
        ozayn_dio_reservation_get(&_svc, rsv->reservation_id);
    ASSERT_NOT_NULL(found);
    ASSERT_NULL(ozayn_dio_reservation_get(&_svc, "NOPE"));
    ozayn_dio_service_shutdown(&_svc);
    return 0;
}

TEST(test_dio_reservation_count)
{
    _init_svc();
    ASSERT_EQ(ozayn_dio_reservation_count(&_svc), 0);
    ozayn_dio_device_desc_t d, *out = NULL;
    _make_desc(&d, "DEV-1", OZAYN_DIO_DEV_CAMERA, "Cam");
    ozayn_dio_device_register(&_svc, &d, &out);

    ozayn_dio_reservation_t *rsv = NULL;
    ozayn_dio_reservation_create(&_svc, "DEV-1", "req", NULL,
                                 OZAYN_DIO_CAP_CAMERA_CAPTURE, &rsv);
    ASSERT_EQ(ozayn_dio_reservation_count(&_svc), 1);
    ozayn_dio_service_shutdown(&_svc);
    return 0;
}

TEST(test_dio_reservation_count_by_device)
{
    _init_svc();
    ozayn_dio_device_desc_t d, *out = NULL;
    _make_desc(&d, "DEV-1", OZAYN_DIO_DEV_CAMERA, "Cam");
    ozayn_dio_device_register(&_svc, &d, &out);

    ozayn_dio_reservation_t *rsv = NULL;
    ozayn_dio_reservation_create(&_svc, "DEV-1", "req", NULL,
                                 OZAYN_DIO_CAP_CAMERA_CAPTURE, &rsv);
    ASSERT_EQ(ozayn_dio_reservation_count_by_device(&_svc, "DEV-1"), 1);
    ASSERT_EQ(ozayn_dio_reservation_count_by_device(&_svc, "NOPE"), 0);
    ozayn_dio_service_shutdown(&_svc);
    return 0;
}

/* ============================================================
 * DISCOVERY TESTS
 * ============================================================ */

TEST(test_dio_discover)
{
    _init_svc();
    ozayn_dio_discovery_result_t result;
    ASSERT_EQ(ozayn_dio_discover(&_svc, NULL, NULL, 5000, &result),
              OZAYN_DIO_OK);
    ASSERT(result.success);
    ASSERT_EQ(_svc.stats.total_discoveries, 1);
    ozayn_dio_service_shutdown(&_svc);
    return 0;
}

TEST(test_dio_discover_null)
{
    ASSERT_EQ(ozayn_dio_discover(NULL, NULL, NULL, 5000, NULL),
              OZAYN_DIO_ERR_NULL);
    return 0;
}

TEST(test_dio_discover_not_init)
{
    _reset_all();
    ozayn_dio_discovery_result_t result;
    ASSERT_EQ(ozayn_dio_discover(&_svc, NULL, NULL, 5000, &result),
              OZAYN_DIO_ERR_NOT_INITIALIZED);
    return 0;
}

/* ============================================================
 * ACCESS LIFECYCLE TESTS
 * ============================================================ */

TEST(test_dio_access_reserve)
{
    _init_svc();
    ozayn_dio_device_desc_t d, *out = NULL;
    _make_desc(&d, "DEV-1", OZAYN_DIO_DEV_CAMERA, "Cam");
    ozayn_dio_device_register(&_svc, &d, &out);

    ozayn_dio_reservation_t *rsv = NULL;
    ASSERT_EQ(ozayn_dio_device_reserve(&_svc, "DEV-1", "req", NULL,
              OZAYN_DIO_CAP_CAMERA_CAPTURE, &rsv), OZAYN_DIO_OK);
    ASSERT_EQ(_svc.devices[0].state, OZAYN_DIO_STATE_RESERVED);
    ASSERT_EQ(rsv->state, OZAYN_DIO_RES_STATE_RESERVED);
    ozayn_dio_service_shutdown(&_svc);
    return 0;
}

TEST(test_dio_access_activate)
{
    _init_svc();
    ozayn_dio_device_desc_t d, *out = NULL;
    _make_desc(&d, "DEV-1", OZAYN_DIO_DEV_CAMERA, "Cam");
    ozayn_dio_device_register(&_svc, &d, &out);

    ozayn_dio_reservation_t *rsv = NULL;
    ozayn_dio_device_reserve(&_svc, "DEV-1", "req", NULL,
                              OZAYN_DIO_CAP_CAMERA_CAPTURE, &rsv);

    ASSERT_EQ(ozayn_dio_device_activate(&_svc, "DEV-1",
              rsv->reservation_id), OZAYN_DIO_OK);
    ASSERT_EQ(_svc.devices[0].state, OZAYN_DIO_STATE_ACTIVE);
    ozayn_dio_service_shutdown(&_svc);
    return 0;
}

TEST(test_dio_access_release)
{
    _init_svc();
    ozayn_dio_device_desc_t d, *out = NULL;
    _make_desc(&d, "DEV-1", OZAYN_DIO_DEV_CAMERA, "Cam");
    ozayn_dio_device_register(&_svc, &d, &out);

    ozayn_dio_reservation_t *rsv = NULL;
    ozayn_dio_device_reserve(&_svc, "DEV-1", "req", NULL,
                              OZAYN_DIO_CAP_CAMERA_CAPTURE, &rsv);
    ozayn_dio_device_activate(&_svc, "DEV-1", rsv->reservation_id);

    ASSERT_EQ(ozayn_dio_device_release(&_svc, "DEV-1",
              rsv->reservation_id), OZAYN_DIO_OK);
    ASSERT_EQ(_svc.devices[0].state, OZAYN_DIO_STATE_AVAILABLE);
    ozayn_dio_service_shutdown(&_svc);
    return 0;
}

/* ============================================================
 * DISCONNECT / RECONNECT TESTS
 * ============================================================ */

TEST(test_dio_disconnect)
{
    _init_svc();
    ozayn_dio_device_desc_t d, *out = NULL;
    _make_desc(&d, "DEV-1", OZAYN_DIO_DEV_CAMERA, "Cam");
    ozayn_dio_device_register(&_svc, &d, &out);

    ASSERT_EQ(ozayn_dio_device_disconnect(&_svc, "DEV-1"), OZAYN_DIO_OK);
    ASSERT_EQ(_svc.devices[0].state, OZAYN_DIO_STATE_UNAVAILABLE);
    ASSERT_EQ(_svc.devices[0].availability, OZAYN_DIO_AVAIL_UNAVAILABLE);
    ozayn_dio_service_shutdown(&_svc);
    return 0;
}

TEST(test_dio_disconnect_invalidates_reservations)
{
    _init_svc();
    ozayn_dio_device_desc_t d, *out = NULL;
    _make_desc(&d, "DEV-1", OZAYN_DIO_DEV_CAMERA, "Cam");
    ozayn_dio_device_register(&_svc, &d, &out);

    ozayn_dio_reservation_t *rsv = NULL;
    ozayn_dio_device_reserve(&_svc, "DEV-1", "req", NULL,
                              OZAYN_DIO_CAP_CAMERA_CAPTURE, &rsv);

    ASSERT_EQ(ozayn_dio_device_disconnect(&_svc, "DEV-1"), OZAYN_DIO_OK);
    ASSERT_EQ(rsv->state, OZAYN_DIO_RES_STATE_FAILED);
    ASSERT(!rsv->active);
    ozayn_dio_service_shutdown(&_svc);
    return 0;
}

TEST(test_dio_reconnect)
{
    _init_svc();
    ozayn_dio_device_desc_t d, *out = NULL;
    _make_desc(&d, "DEV-1", OZAYN_DIO_DEV_CAMERA, "Cam");
    ozayn_dio_device_register(&_svc, &d, &out);

    ozayn_dio_device_disconnect(&_svc, "DEV-1");
    ASSERT_EQ(ozayn_dio_device_reconnect(&_svc, "DEV-1", NULL),
              OZAYN_DIO_OK);
    ASSERT_EQ(_svc.devices[0].state, OZAYN_DIO_STATE_AVAILABLE);
    ASSERT_EQ(_svc.devices[0].availability, OZAYN_DIO_AVAIL_AVAILABLE);
    ozayn_dio_service_shutdown(&_svc);
    return 0;
}

TEST(test_dio_reconnect_new_device)
{
    _init_svc();
    ozayn_dio_device_desc_t d;
    _make_desc(&d, "NEW-1", OZAYN_DIO_DEV_GPU, "New GPU");

    ASSERT_EQ(ozayn_dio_device_reconnect(&_svc, "NEW-1", &d), OZAYN_DIO_OK);
    ASSERT(ozayn_dio_device_exists(&_svc, "NEW-1"));
    ozayn_dio_service_shutdown(&_svc);
    return 0;
}

/* ============================================================
 * EVENTS TESTS
 * ============================================================ */

TEST(test_dio_emit_event)
{
    _init_svc();
    ASSERT_EQ(ozayn_dio_emit_event(&_svc, OZAYN_DIO_EVENT_REGISTERED,
              "DEV-1", "test event"), OZAYN_DIO_OK);
    ASSERT_EQ(ozayn_dio_event_count(&_svc), 1);
    const ozayn_dio_event_t *ev = ozayn_dio_event_get(&_svc, 0);
    ASSERT_NOT_NULL(ev);
    ASSERT_EQ(ev->type, OZAYN_DIO_EVENT_REGISTERED);
    ozayn_dio_service_shutdown(&_svc);
    return 0;
}

TEST(test_dio_event_ring_buffer)
{
    _init_svc();
    _svc.config.max_events = 4;
    for (int i = 0; i < 6; i++) {
        ozayn_dio_emit_event(&_svc, OZAYN_DIO_EVENT_UPDATED, "DEV-1",
                              "event");
    }
    ASSERT_EQ(ozayn_dio_event_count(&_svc), 4);
    ozayn_dio_service_shutdown(&_svc);
    return 0;
}

TEST(test_dio_event_get_invalid)
{
    _init_svc();
    ASSERT_NULL(ozayn_dio_event_get(&_svc, 0));
    ASSERT_NULL(ozayn_dio_event_get(&_svc, -1));
    ozayn_dio_service_shutdown(&_svc);
    return 0;
}

/* ============================================================
 * CLEANUP TESTS
 * ============================================================ */

TEST(test_dio_cleanup_expired)
{
    _reset_all();
    memset(&_cfg, 0, sizeof(_cfg));
    _cfg.reservation_ttl_ms = 1000;
    ozayn_dio_service_init(&_svc, &_cfg);

    ozayn_dio_device_desc_t d, *out = NULL;
    _make_desc(&d, "DEV-1", OZAYN_DIO_DEV_CAMERA, "Cam");
    ozayn_dio_device_register(&_svc, &d, &out);

    ozayn_dio_reservation_t *rsv = NULL;
    ozayn_dio_reservation_create(&_svc, "DEV-1", "req", NULL,
                                 OZAYN_DIO_CAP_CAMERA_CAPTURE, &rsv);

    struct timespec ts = {2, 0};
    nanosleep(&ts, NULL);

    int cleaned = ozayn_dio_cleanup_expired_reservations(&_svc);
    ASSERT(cleaned >= 1);
    ozayn_dio_service_shutdown(&_svc);
    return 0;
}

TEST(test_dio_cleanup_null)
{
    ASSERT_EQ(ozayn_dio_cleanup_expired_reservations(NULL), 0);
    ASSERT_EQ(ozayn_dio_cleanup_all(NULL), 0);
    return 0;
}

/* ============================================================
 * STATS TESTS
 * ============================================================ */

TEST(test_dio_stats)
{
    _init_svc();
    ozayn_dio_stats_t stats;
    ASSERT_EQ(ozayn_dio_get_stats(&_svc, &stats), OZAYN_DIO_OK);
    ASSERT_EQ(stats.total_devices_registered, 0);

    ozayn_dio_device_desc_t d, *out = NULL;
    _make_desc(&d, "DEV-1", OZAYN_DIO_DEV_CAMERA, "Cam");
    ozayn_dio_device_register(&_svc, &d, &out);
    ASSERT_EQ(ozayn_dio_get_stats(&_svc, &stats), OZAYN_DIO_OK);
    ASSERT_EQ(stats.total_devices_registered, 1);
    ASSERT_EQ(stats.current_active_devices, 1);
    ozayn_dio_service_shutdown(&_svc);
    return 0;
}

TEST(test_dio_stats_null)
{
    ASSERT_EQ(ozayn_dio_get_stats(NULL, NULL), OZAYN_DIO_ERR_NULL);
    return 0;
}

/* ============================================================
 * VALIDATION TESTS
 * ============================================================ */

TEST(test_dio_device_validate)
{
    ozayn_dio_device_desc_t d;
    _make_desc(&d, "DEV-1", OZAYN_DIO_DEV_CAMERA, "Cam");
    ASSERT(ozayn_dio_device_validate(&d));
    ASSERT(!ozayn_dio_device_validate(NULL));
    d.device_id[0] = '\0';
    ASSERT(!ozayn_dio_device_validate(&d));
    return 0;
}

TEST(test_dio_capability_validate)
{
    ozayn_dio_capability_t cap;
    memset(&cap, 0, sizeof(cap));
    cap.type = OZAYN_DIO_CAP_CAMERA_CAPTURE;
    cap.state = OZAYN_DIO_CAP_STATE_IMPLEMENTED;
    ASSERT(ozayn_dio_capability_validate(&cap));
    ASSERT(!ozayn_dio_capability_validate(NULL));
    cap.type = (ozayn_dio_capability_type_t)99;
    ASSERT(!ozayn_dio_capability_validate(&cap));
    return 0;
}

TEST(test_dio_reservation_validate)
{
    ozayn_dio_reservation_t r;
    memset(&r, 0, sizeof(r));
    strncpy(r.reservation_id, "RSV-1", OZAYN_DIO_MAX_ID_LEN - 1);
    strncpy(r.device_id, "DEV-1", OZAYN_DIO_MAX_ID_LEN - 1);
    r.state = OZAYN_DIO_RES_STATE_RESERVED;
    ASSERT(ozayn_dio_reservation_validate(&r));
    ASSERT(!ozayn_dio_reservation_validate(NULL));
    r.reservation_id[0] = '\0';
    ASSERT(!ozayn_dio_reservation_validate(&r));
    return 0;
}

/* ============================================================
 * NAME HELPER TESTS
 * ============================================================ */

TEST(test_dio_type_name)
{
    ASSERT_STR_EQ(ozayn_dio_device_type_name(OZAYN_DIO_DEV_CAMERA), "CAMERA");
    ASSERT_STR_EQ(ozayn_dio_device_type_name(OZAYN_DIO_DEV_GPU), "GPU");
    ASSERT_STR_EQ(ozayn_dio_device_type_name(OZAYN_DIO_DEV_OTHER), "OTHER");
    ASSERT_STR_EQ(ozayn_dio_device_type_name((ozayn_dio_device_type_t)99),
                  "UNKNOWN");
    return 0;
}

TEST(test_dio_state_name)
{
    ASSERT_STR_EQ(ozayn_dio_device_state_name(OZAYN_DIO_STATE_AVAILABLE),
                  "AVAILABLE");
    ASSERT_STR_EQ(ozayn_dio_device_state_name(OZAYN_DIO_STATE_ACTIVE),
                  "ACTIVE");
    ASSERT_STR_EQ(ozayn_dio_device_state_name(OZAYN_DIO_STATE_ERROR),
                  "ERROR");
    ASSERT_STR_EQ(ozayn_dio_device_state_name((ozayn_dio_device_state_t)99),
                  "UNKNOWN");
    return 0;
}

TEST(test_dio_availability_name)
{
    ASSERT_STR_EQ(ozayn_dio_availability_name(OZAYN_DIO_AVAIL_AVAILABLE),
                  "AVAILABLE");
    ASSERT_STR_EQ(ozayn_dio_availability_name(OZAYN_DIO_AVAIL_UNAVAILABLE),
                  "UNAVAILABLE");
    return 0;
}

TEST(test_dio_health_name)
{
    ASSERT_STR_EQ(ozayn_dio_health_name(OZAYN_DIO_HEALTH_HEALTHY), "HEALTHY");
    ASSERT_STR_EQ(ozayn_dio_health_name(OZAYN_DIO_HEALTH_DEGRADED),
                  "DEGRADED");
    return 0;
}

TEST(test_dio_cap_type_name)
{
    ASSERT_STR_EQ(ozayn_dio_capability_type_name(OZAYN_DIO_CAP_CAMERA_CAPTURE),
                  "CAMERA_CAPTURE");
    ASSERT_STR_EQ(ozayn_dio_capability_type_name(OZAYN_DIO_CAP_GPU_COMPUTE),
                  "GPU_COMPUTE");
    return 0;
}

TEST(test_dio_cap_state_name)
{
    ASSERT_STR_EQ(ozayn_dio_cap_state_name(OZAYN_DIO_CAP_STATE_IMPLEMENTED),
                  "IMPLEMENTED");
    ASSERT_STR_EQ(ozayn_dio_cap_state_name(OZAYN_DIO_CAP_STATE_PLANNED),
                  "PLANNED");
    return 0;
}

TEST(test_dio_access_mode_name)
{
    ASSERT_STR_EQ(ozayn_dio_access_mode_name(OZAYN_DIO_ACCESS_SHARED),
                  "SHARED");
    ASSERT_STR_EQ(ozayn_dio_access_mode_name(OZAYN_DIO_ACCESS_EXCLUSIVE),
                  "EXCLUSIVE");
    return 0;
}

TEST(test_dio_reservation_state_name)
{
    ASSERT_STR_EQ(ozayn_dio_reservation_state_name(
                  OZAYN_DIO_RES_STATE_RESERVED), "RESERVED");
    ASSERT_STR_EQ(ozayn_dio_reservation_state_name(
                  OZAYN_DIO_RES_STATE_ACTIVE), "ACTIVE");
    return 0;
}

TEST(test_dio_event_type_name)
{
    ASSERT_STR_EQ(ozayn_dio_event_type_name(OZAYN_DIO_EVENT_DISCOVERED),
                  "DISCOVERED");
    ASSERT_STR_EQ(ozayn_dio_event_type_name(OZAYN_DIO_EVENT_ACTIVATED),
                  "ACTIVATED");
    return 0;
}

TEST(test_dio_err_name)
{
    ASSERT_STR_EQ(ozayn_dio_err_name(OZAYN_DIO_OK), "OK");
    ASSERT_STR_EQ(ozayn_dio_err_name(OZAYN_DIO_ERR_NULL), "NULL");
    ASSERT_STR_EQ(ozayn_dio_err_name(OZAYN_DIO_ERR_NOT_FOUND), "NOT_FOUND");
    return 0;
}

/* ============================================================
 * PRIVACY & SECURITY TESTS
 * ============================================================ */

TEST(test_dio_camera_not_auto_activated)
{
    _init_svc();
    ozayn_dio_device_desc_t d, *out = NULL;
    _make_desc(&d, "CAM-1", OZAYN_DIO_DEV_CAMERA, "Camera");
    ozayn_dio_device_register(&_svc, &d, &out);

    const ozayn_dio_device_desc_t *cam = ozayn_dio_device_get(&_svc,
                                                                "CAM-1");
    ASSERT_NOT_NULL(cam);
    ASSERT(cam->state != OZAYN_DIO_STATE_ACTIVE);
    ASSERT(cam->state != OZAYN_DIO_STATE_RESERVED);
    ozayn_dio_service_shutdown(&_svc);
    return 0;
}

TEST(test_dio_mic_not_auto_activated)
{
    _init_svc();
    ozayn_dio_device_desc_t d, *out = NULL;
    _make_desc(&d, "MIC-1", OZAYN_DIO_DEV_MICROPHONE, "Microphone");
    ozayn_dio_device_register(&_svc, &d, &out);

    const ozayn_dio_device_desc_t *mic = ozayn_dio_device_get(&_svc,
                                                                 "MIC-1");
    ASSERT_NOT_NULL(mic);
    ASSERT(mic->state != OZAYN_DIO_STATE_ACTIVE);
    ozayn_dio_service_shutdown(&_svc);
    return 0;
}

TEST(test_dio_no_secrets_in_event)
{
    _init_svc();
    ozayn_dio_emit_event(&_svc, OZAYN_DIO_EVENT_REGISTERED, "DEV-1",
                          "normal message");
    const ozayn_dio_event_t *ev = ozayn_dio_event_get(&_svc, 0);
    ASSERT_NOT_NULL(ev);
    ASSERT(!strstr(ev->message, "password"));
    ASSERT(!strstr(ev->message, "secret"));
    ASSERT(!strstr(ev->message, "key"));
    ozayn_dio_service_shutdown(&_svc);
    return 0;
}

/* ============================================================
 * INTEGRATION-STYLE TESTS
 * ============================================================ */

TEST(test_dio_multi_device)
{
    _init_svc();
    ozayn_dio_device_desc_t d, *out = NULL;

    _make_desc(&d, "CAM", OZAYN_DIO_DEV_CAMERA, "Cam");
    ozayn_dio_device_register(&_svc, &d, &out);
    _make_desc(&d, "MIC", OZAYN_DIO_DEV_MICROPHONE, "Mic");
    ozayn_dio_device_register(&_svc, &d, &out);
    _make_desc(&d, "GPU", OZAYN_DIO_DEV_GPU, "GPU");
    ozayn_dio_device_register(&_svc, &d, &out);

    ASSERT_EQ(ozayn_dio_device_count(&_svc), 3);
    ASSERT_NOT_NULL(ozayn_dio_device_get(&_svc, "CAM"));
    ASSERT_NOT_NULL(ozayn_dio_device_get(&_svc, "MIC"));
    ASSERT_NOT_NULL(ozayn_dio_device_get(&_svc, "GPU"));
    ozayn_dio_service_shutdown(&_svc);
    return 0;
}

TEST(test_dio_full_access_lifecycle)
{
    _init_svc();
    ozayn_dio_device_desc_t d, *out = NULL;
    _make_desc(&d, "CAM-1", OZAYN_DIO_DEV_CAMERA, "Camera");
    ozayn_dio_device_register(&_svc, &d, &out);

    ozayn_dio_capability_t cap;
    memset(&cap, 0, sizeof(cap));
    cap.type = OZAYN_DIO_CAP_CAMERA_CAPTURE;
    cap.state = OZAYN_DIO_CAP_STATE_IMPLEMENTED;
    ozayn_dio_capability_add(&_svc, "CAM-1", &cap);

    ozayn_dio_reservation_t *rsv = NULL;
    ASSERT_EQ(ozayn_dio_device_reserve(&_svc, "CAM-1", "process-1",
              "session-1", OZAYN_DIO_CAP_CAMERA_CAPTURE, &rsv), OZAYN_DIO_OK);
    ASSERT_EQ(_svc.devices[0].state, OZAYN_DIO_STATE_RESERVED);

    ASSERT_EQ(ozayn_dio_device_activate(&_svc, "CAM-1",
              rsv->reservation_id), OZAYN_DIO_OK);
    ASSERT_EQ(_svc.devices[0].state, OZAYN_DIO_STATE_ACTIVE);

    ASSERT_EQ(ozayn_dio_device_release(&_svc, "CAM-1",
              rsv->reservation_id), OZAYN_DIO_OK);
    ASSERT_EQ(_svc.devices[0].state, OZAYN_DIO_STATE_AVAILABLE);

    ozayn_dio_service_shutdown(&_svc);
    return 0;
}

TEST(test_dio_device_types)
{
    _init_svc();
    ozayn_dio_device_desc_t d, *out = NULL;
    const char *names[] = {
        "CAM", "MIC", "AIN", "AOUT", "DISP", "KEY", "MOUSE",
        "PTR", "INP", "GPU", "NET", "STOR", "OTHER"
    };
    for (int i = 0; i < OZAYN_DIO_DEV_TYPE_COUNT - 1; i++) {
        _make_desc(&d, names[i], (ozayn_dio_device_type_t)i, names[i]);
        ASSERT_EQ(ozayn_dio_device_register(&_svc, &d, &out), OZAYN_DIO_OK);
    }
    ASSERT_EQ(ozayn_dio_device_count(&_svc), OZAYN_DIO_DEV_TYPE_COUNT - 1);
    ozayn_dio_service_shutdown(&_svc);
    return 0;
}

TEST(test_dio_shared_access_multiple)
{
    _init_svc();
    ozayn_dio_device_desc_t d, *out = NULL;
    _make_desc(&d, "DISP-1", OZAYN_DIO_DEV_DISPLAY, "Display");
    d.access_mode = OZAYN_DIO_ACCESS_SHARED;
    ozayn_dio_device_register(&_svc, &d, &out);

    ozayn_dio_reservation_t *r1 = NULL, *r2 = NULL;
    ASSERT_EQ(ozayn_dio_reservation_create(&_svc, "DISP-1", "req1", NULL,
              OZAYN_DIO_CAP_DISPLAY_OUTPUT, &r1), OZAYN_DIO_OK);
    ASSERT_EQ(ozayn_dio_reservation_create(&_svc, "DISP-1", "req2", NULL,
              OZAYN_DIO_CAP_DISPLAY_OUTPUT, &r2), OZAYN_DIO_OK);
    ASSERT_EQ(_svc.reservation_count, 2);
    ozayn_dio_service_shutdown(&_svc);
    return 0;
}

TEST(test_dio_event_emitted_on_register)
{
    _init_svc();
    ozayn_dio_device_desc_t d, *out = NULL;
    _make_desc(&d, "DEV-1", OZAYN_DIO_DEV_CAMERA, "Cam");
    ozayn_dio_device_register(&_svc, &d, &out);
    ASSERT_GE(ozayn_dio_event_count(&_svc), 1);
    const ozayn_dio_event_t *ev = ozayn_dio_event_get(&_svc, 0);
    ASSERT_EQ(ev->type, OZAYN_DIO_EVENT_REGISTERED);
    ozayn_dio_service_shutdown(&_svc);
    return 0;
}

TEST(test_dio_multiple_reservations_release)
{
    _init_svc();
    ozayn_dio_device_desc_t d, *out = NULL;
    _make_desc(&d, "DISP-1", OZAYN_DIO_DEV_DISPLAY, "Display");
    d.access_mode = OZAYN_DIO_ACCESS_SHARED;
    ozayn_dio_device_register(&_svc, &d, &out);

    ozayn_dio_reservation_t *r1 = NULL, *r2 = NULL;
    ozayn_dio_reservation_create(&_svc, "DISP-1", "req1", NULL,
                                 OZAYN_DIO_CAP_DISPLAY_OUTPUT, &r1);
    ozayn_dio_reservation_create(&_svc, "DISP-1", "req2", NULL,
                                 OZAYN_DIO_CAP_DISPLAY_OUTPUT, &r2);

    r1->state = OZAYN_DIO_RES_STATE_RESERVED;
    r2->state = OZAYN_DIO_RES_STATE_RESERVED;

    ASSERT_EQ(ozayn_dio_reservation_release(&_svc, r1->reservation_id),
              OZAYN_DIO_OK);
    ASSERT_EQ(ozayn_dio_reservation_count(&_svc), 1);
    ASSERT_EQ(ozayn_dio_reservation_release(&_svc, r2->reservation_id),
              OZAYN_DIO_OK);
    ASSERT_EQ(ozayn_dio_reservation_count(&_svc), 0);
    ozayn_dio_service_shutdown(&_svc);
    return 0;
}

/* ============================================================
 * TEST RUNNER
 * ============================================================ */

int run_cr_device_io_tests(void)
{
    SUITE_BEGIN("Device & I/O Management");

    RUN(test_dio_init);
    RUN(test_dio_init_null);
    RUN(test_dio_init_null_config);
    RUN(test_dio_init_double);
    RUN(test_dio_init_custom_config);
    RUN(test_dio_shutdown);
    RUN(test_dio_shutdown_null);
    RUN(test_dio_is_initialized_null);
    RUN(test_dio_global_singleton);

    RUN(test_dio_register);
    RUN(test_dio_register_null);
    RUN(test_dio_register_not_init);
    RUN(test_dio_register_null_desc);
    RUN(test_dio_register_empty_id);
    RUN(test_dio_register_invalid_type);
    RUN(test_dio_register_null_out);
    RUN(test_dio_register_duplicate);
    RUN(test_dio_register_limit);
    RUN(test_dio_unregister);
    RUN(test_dio_unregister_not_found);
    RUN(test_dio_get);
    RUN(test_dio_get_by_type);
    RUN(test_dio_exists);
    RUN(test_dio_count);
    RUN(test_dio_full);

    RUN(test_dio_update_state);
    RUN(test_dio_update_state_not_found);
    RUN(test_dio_update_state_invalid);
    RUN(test_dio_update_availability);
    RUN(test_dio_update_health);

    RUN(test_dio_capability_add);
    RUN(test_dio_capability_add_not_found);
    RUN(test_dio_capability_add_duplicate);
    RUN(test_dio_capability_add_limit);
    RUN(test_dio_capability_remove);
    RUN(test_dio_capability_remove_not_found);
    RUN(test_dio_capability_get);
    RUN(test_dio_capability_is_available);
    RUN(test_dio_capability_planned_not_available);

    RUN(test_dio_reservation_create);
    RUN(test_dio_reservation_create_not_found);
    RUN(test_dio_reservation_create_invalid_state);
    RUN(test_dio_reservation_exclusive_conflict);
    RUN(test_dio_reservation_activate);
    RUN(test_dio_reservation_activate_wrong_state);
    RUN(test_dio_reservation_release);
    RUN(test_dio_reservation_cancel);
    RUN(test_dio_reservation_get);
    RUN(test_dio_reservation_count);
    RUN(test_dio_reservation_count_by_device);

    RUN(test_dio_discover);
    RUN(test_dio_discover_null);
    RUN(test_dio_discover_not_init);

    RUN(test_dio_access_reserve);
    RUN(test_dio_access_activate);
    RUN(test_dio_access_release);

    RUN(test_dio_disconnect);
    RUN(test_dio_disconnect_invalidates_reservations);
    RUN(test_dio_reconnect);
    RUN(test_dio_reconnect_new_device);

    RUN(test_dio_emit_event);
    RUN(test_dio_event_ring_buffer);
    RUN(test_dio_event_get_invalid);

    RUN(test_dio_cleanup_expired);
    RUN(test_dio_cleanup_null);

    RUN(test_dio_stats);
    RUN(test_dio_stats_null);

    RUN(test_dio_device_validate);
    RUN(test_dio_capability_validate);
    RUN(test_dio_reservation_validate);

    RUN(test_dio_type_name);
    RUN(test_dio_state_name);
    RUN(test_dio_availability_name);
    RUN(test_dio_health_name);
    RUN(test_dio_cap_type_name);
    RUN(test_dio_cap_state_name);
    RUN(test_dio_access_mode_name);
    RUN(test_dio_reservation_state_name);
    RUN(test_dio_event_type_name);
    RUN(test_dio_err_name);

    RUN(test_dio_camera_not_auto_activated);
    RUN(test_dio_mic_not_auto_activated);
    RUN(test_dio_no_secrets_in_event);

    RUN(test_dio_multi_device);
    RUN(test_dio_full_access_lifecycle);
    RUN(test_dio_device_types);
    RUN(test_dio_shared_access_multiple);
    RUN(test_dio_event_emitted_on_register);
    RUN(test_dio_multiple_reservations_release);

    SUITE_END();
    return TOTAL_FAIL();
}
