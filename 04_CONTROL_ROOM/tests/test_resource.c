#include "../resource.h"
#include "../../tests/test_framework.h"
#include <string.h>
#include <time.h>

/* ============================================================
 * HELPERS
 * ============================================================ */

static ozayn_rcm_service_t _svc;
static ozayn_rcm_service_config_t _cfg;

static void _reset_all(void)
{
    memset(&_svc, 0, sizeof(_svc));
}

static void _init_svc(void)
{
    _reset_all();
    memset(&_cfg, 0, sizeof(_cfg));
    ozayn_rcm_service_init(&_svc, &_cfg);
}

/* ============================================================
 * LIFECYCLE TESTS
 * ============================================================ */

TEST(test_rcm_init)
{
    _reset_all();
    memset(&_cfg, 0, sizeof(_cfg));
    ASSERT_EQ(ozayn_rcm_service_init(&_svc, &_cfg), OZAYN_RCM_OK);
    ASSERT(ozayn_rcm_service_is_initialized(&_svc));
    ozayn_rcm_service_shutdown(&_svc);
    return 0;
}

TEST(test_rcm_init_null)
{
    ASSERT_EQ(ozayn_rcm_service_init(NULL, NULL), OZAYN_RCM_ERR_NULL);
    return 0;
}

TEST(test_rcm_init_double)
{
    _init_svc();
    ASSERT_EQ(ozayn_rcm_service_init(&_svc, &_cfg), OZAYN_RCM_ERR_ALREADY_INITIALIZED);
    ozayn_rcm_service_shutdown(&_svc);
    return 0;
}

TEST(test_rcm_init_custom_config)
{
    _reset_all();
    memset(&_cfg, 0, sizeof(_cfg));
    _cfg.max_resources = 8;
    _cfg.max_decisions = 16;
    _cfg.max_reservations = 4;
    _cfg.reservation_ttl_ms = 5000;
    _cfg.max_concurrent_operations = 4;
    _cfg.max_workers = 2;
    _cfg.max_queue_size = 8;
    ASSERT_EQ(ozayn_rcm_service_init(&_svc, &_cfg), OZAYN_RCM_OK);
    ASSERT_EQ(_svc.max_resources, 8);
    ASSERT_EQ(_svc.max_decisions, 16);
    ASSERT_EQ(_svc.max_reservations, 4);
    ASSERT_EQ(_svc.reservation_ttl_ms, 5000);
    ASSERT_EQ(_svc.max_concurrent_operations, 4);
    ASSERT_EQ(_svc.max_workers, 2);
    ASSERT_EQ(_svc.max_queue_size, 8);
    ozayn_rcm_service_shutdown(&_svc);
    return 0;
}

TEST(test_rcm_shutdown)
{
    _init_svc();
    ozayn_rcm_service_shutdown(&_svc);
    ASSERT(!ozayn_rcm_service_is_initialized(&_svc));
    return 0;
}

TEST(test_rcm_shutdown_null)
{
    ozayn_rcm_service_shutdown(NULL);
    return 0;
}

TEST(test_rcm_is_initialized)
{
    ASSERT(!ozayn_rcm_service_is_initialized(NULL));
    _init_svc();
    ASSERT(ozayn_rcm_service_is_initialized(&_svc));
    ozayn_rcm_service_shutdown(&_svc);
    return 0;
}

TEST(test_rcm_global_singleton)
{
    ozayn_rcm_service_t *g = ozayn_rcm_get_global();
    ASSERT_NOT_NULL(g);
    return 0;
}

/* ============================================================
 * RESOURCE REGISTRATION TESTS
 * ============================================================ */

TEST(test_rcm_resource_register)
{
    _init_svc();
    ozayn_rcm_resource_desc_t *res = NULL;
    ASSERT_EQ(ozayn_rcm_resource_register(&_svc, OZAYN_RCM_RES_CPU,
        "Main CPU", "platform", "cores", 8, &res), OZAYN_RCM_OK);
    ASSERT_NOT_NULL(res);
    ASSERT(res->resource_id[0] != '\0');
    ASSERT(strcmp(res->name, "Main CPU") == 0);
    ASSERT_EQ(res->type, OZAYN_RCM_RES_CPU);
    ASSERT_EQ(res->capacity.total, 8);
    ASSERT_EQ(res->state, OZAYN_RCM_STATE_AVAILABLE);
    ASSERT_EQ(res->health, OZAYN_RCM_HEALTH_HEALTHY);
    ASSERT_EQ(_svc.resource_count, 1);
    ozayn_rcm_service_shutdown(&_svc);
    return 0;
}

TEST(test_rcm_resource_register_null)
{
    ASSERT_EQ(ozayn_rcm_resource_register(NULL, 0, "X", NULL, NULL, 0, NULL),
              OZAYN_RCM_ERR_NULL);
    return 0;
}

TEST(test_rcm_resource_register_not_init)
{
    _reset_all();
    memset(&_cfg, 0, sizeof(_cfg));
    ozayn_rcm_resource_desc_t *res = NULL;
    ASSERT_EQ(ozayn_rcm_resource_register(&_svc, OZAYN_RCM_RES_CPU,
        "X", NULL, NULL, 0, &res), OZAYN_RCM_ERR_NOT_INITIALIZED);
    return 0;
}

TEST(test_rcm_resource_register_invalid_type)
{
    _init_svc();
    ozayn_rcm_resource_desc_t *res = NULL;
    ASSERT_EQ(ozayn_rcm_resource_register(&_svc, (ozayn_rcm_resource_type_t)99,
        "X", NULL, NULL, 0, &res), OZAYN_RCM_ERR_INVALID_PARAM);
    ozayn_rcm_service_shutdown(&_svc);
    return 0;
}

TEST(test_rcm_resource_register_empty_name)
{
    _init_svc();
    ozayn_rcm_resource_desc_t *res = NULL;
    ASSERT_EQ(ozayn_rcm_resource_register(&_svc, OZAYN_RCM_RES_CPU,
        "", NULL, NULL, 0, &res), OZAYN_RCM_ERR_INVALID_PARAM);
    ozayn_rcm_service_shutdown(&_svc);
    return 0;
}

TEST(test_rcm_resource_register_null_out)
{
    _init_svc();
    ASSERT_EQ(ozayn_rcm_resource_register(&_svc, OZAYN_RCM_RES_CPU,
        "X", NULL, NULL, 0, NULL), OZAYN_RCM_ERR_NULL);
    ozayn_rcm_service_shutdown(&_svc);
    return 0;
}

TEST(test_rcm_resource_register_duplicate)
{
    _init_svc();
    ozayn_rcm_resource_desc_t *r1 = NULL, *r2 = NULL;
    ozayn_rcm_resource_register(&_svc, OZAYN_RCM_RES_CPU,
        "CPU1", NULL, NULL, 8, &r1);
    ASSERT_EQ(ozayn_rcm_resource_register(&_svc, OZAYN_RCM_RES_CPU,
        "CPU1", NULL, NULL, 8, &r2), OZAYN_RCM_ERR_DUPLICATE);
    ozayn_rcm_service_shutdown(&_svc);
    return 0;
}

TEST(test_rcm_resource_register_limit)
{
    _reset_all();
    memset(&_cfg, 0, sizeof(_cfg));
    _cfg.max_resources = 2;
    ozayn_rcm_service_init(&_svc, &_cfg);
    ozayn_rcm_resource_desc_t *r1 = NULL, *r2 = NULL, *r3 = NULL;
    ozayn_rcm_resource_register(&_svc, OZAYN_RCM_RES_CPU, "C1", NULL, NULL, 8, &r1);
    ozayn_rcm_resource_register(&_svc, OZAYN_RCM_RES_MEMORY, "M1", NULL, NULL, 16, &r2);
    ASSERT_EQ(ozayn_rcm_resource_register(&_svc, OZAYN_RCM_RES_GPU, "G1", NULL, NULL, 4, &r3),
              OZAYN_RCM_ERR_LIMIT_REACHED);
    ozayn_rcm_service_shutdown(&_svc);
    return 0;
}

TEST(test_rcm_resource_unregister)
{
    _init_svc();
    ozayn_rcm_resource_desc_t *res = NULL;
    ozayn_rcm_resource_register(&_svc, OZAYN_RCM_RES_CPU, "CPU1", NULL, NULL, 8, &res);
    ASSERT_EQ(ozayn_rcm_resource_unregister(&_svc, res->resource_id), OZAYN_RCM_OK);
    ASSERT_EQ(_svc.resource_count, 0);
    ozayn_rcm_service_shutdown(&_svc);
    return 0;
}

TEST(test_rcm_resource_unregister_not_found)
{
    _init_svc();
    ASSERT_EQ(ozayn_rcm_resource_unregister(&_svc, "NOPE"), OZAYN_RCM_ERR_NOT_FOUND);
    ozayn_rcm_service_shutdown(&_svc);
    return 0;
}

TEST(test_rcm_resource_get)
{
    _init_svc();
    ozayn_rcm_resource_desc_t *res = NULL;
    ozayn_rcm_resource_register(&_svc, OZAYN_RCM_RES_CPU, "CPU1", NULL, NULL, 8, &res);
    const ozayn_rcm_resource_desc_t *found = ozayn_rcm_resource_get(&_svc, res->resource_id);
    ASSERT_NOT_NULL(found);
    ASSERT(strcmp(found->resource_id, res->resource_id) == 0);
    ASSERT_NULL(ozayn_rcm_resource_get(&_svc, "NOPE"));
    ASSERT_NULL(ozayn_rcm_resource_get(NULL, "X"));
    ozayn_rcm_service_shutdown(&_svc);
    return 0;
}

TEST(test_rcm_resource_get_by_type)
{
    _init_svc();
    ozayn_rcm_resource_desc_t *res = NULL;
    ozayn_rcm_resource_register(&_svc, OZAYN_RCM_RES_MEMORY, "RAM", NULL, NULL, 16, &res);
    const ozayn_rcm_resource_desc_t *found = ozayn_rcm_resource_get_by_type(&_svc,
        OZAYN_RCM_RES_MEMORY);
    ASSERT_NOT_NULL(found);
    ASSERT_NULL(ozayn_rcm_resource_get_by_type(&_svc, OZAYN_RCM_RES_GPU));
    ozayn_rcm_service_shutdown(&_svc);
    return 0;
}

TEST(test_rcm_resource_count)
{
    _init_svc();
    ASSERT_EQ(ozayn_rcm_resource_count(&_svc), 0);
    ASSERT_EQ(ozayn_rcm_resource_count(NULL), 0);
    ozayn_rcm_resource_desc_t *res = NULL;
    ozayn_rcm_resource_register(&_svc, OZAYN_RCM_RES_CPU, "CPU", NULL, NULL, 8, &res);
    ASSERT_EQ(ozayn_rcm_resource_count(&_svc), 1);
    ozayn_rcm_service_shutdown(&_svc);
    return 0;
}

TEST(test_rcm_resource_full)
{
    _reset_all();
    memset(&_cfg, 0, sizeof(_cfg));
    _cfg.max_resources = 1;
    ozayn_rcm_service_init(&_svc, &_cfg);
    ASSERT(!ozayn_rcm_resource_full(&_svc));
    ozayn_rcm_resource_desc_t *res = NULL;
    ozayn_rcm_resource_register(&_svc, OZAYN_RCM_RES_CPU, "CPU", NULL, NULL, 8, &res);
    ASSERT(ozayn_rcm_resource_full(&_svc));
    ozayn_rcm_service_shutdown(&_svc);
    return 0;
}

/* ============================================================
 * RESOURCE STATE UPDATE TESTS
 * ============================================================ */

TEST(test_rcm_resource_update_usage)
{
    _init_svc();
    ozayn_rcm_resource_desc_t *res = NULL;
    ozayn_rcm_resource_register(&_svc, OZAYN_RCM_RES_MEMORY, "RAM", NULL, NULL, 16, &res);
    ASSERT_EQ(ozayn_rcm_resource_update_usage(&_svc, res->resource_id, 8), OZAYN_RCM_OK);
    ASSERT_EQ(res->capacity.used, 8);
    ASSERT_EQ(res->capacity.available, 8);
    ozayn_rcm_service_shutdown(&_svc);
    return 0;
}

TEST(test_rcm_resource_update_usage_overflow)
{
    _init_svc();
    ozayn_rcm_resource_desc_t *res = NULL;
    ozayn_rcm_resource_register(&_svc, OZAYN_RCM_RES_MEMORY, "RAM", NULL, NULL, 16, &res);
    ASSERT_EQ(ozayn_rcm_resource_update_usage(&_svc, res->resource_id, 32),
              OZAYN_RCM_ERR_CAPACITY_INVALID);
    ozayn_rcm_service_shutdown(&_svc);
    return 0;
}

TEST(test_rcm_resource_update_state)
{
    _init_svc();
    ozayn_rcm_resource_desc_t *res = NULL;
    ozayn_rcm_resource_register(&_svc, OZAYN_RCM_RES_CPU, "CPU", NULL, NULL, 8, &res);
    ASSERT_EQ(ozayn_rcm_resource_update_state(&_svc, res->resource_id,
        OZAYN_RCM_STATE_BUSY), OZAYN_RCM_OK);
    ASSERT_EQ(res->state, OZAYN_RCM_STATE_BUSY);
    ozayn_rcm_service_shutdown(&_svc);
    return 0;
}

TEST(test_rcm_resource_update_health)
{
    _init_svc();
    ozayn_rcm_resource_desc_t *res = NULL;
    ozayn_rcm_resource_register(&_svc, OZAYN_RCM_RES_GPU, "GPU", NULL, NULL, 4, &res);
    ASSERT_EQ(ozayn_rcm_resource_update_health(&_svc, res->resource_id,
        OZAYN_RCM_HEALTH_DEGRADED), OZAYN_RCM_OK);
    ASSERT_EQ(res->health, OZAYN_RCM_HEALTH_DEGRADED);
    ozayn_rcm_service_shutdown(&_svc);
    return 0;
}

TEST(test_rcm_resource_update_availability)
{
    _init_svc();
    ozayn_rcm_resource_desc_t *res = NULL;
    ozayn_rcm_resource_register(&_svc, OZAYN_RCM_RES_NETWORK, "NET", NULL, NULL, 1, &res);
    ASSERT_EQ(ozayn_rcm_resource_update_availability(&_svc, res->resource_id,
        OZAYN_RCM_AVAIL_UNAVAILABLE), OZAYN_RCM_OK);
    ASSERT_EQ(res->availability, OZAYN_RCM_AVAIL_UNAVAILABLE);
    ozayn_rcm_service_shutdown(&_svc);
    return 0;
}

TEST(test_rcm_resource_update_not_found)
{
    _init_svc();
    ASSERT_EQ(ozayn_rcm_resource_update_usage(&_svc, "NOPE", 1),
              OZAYN_RCM_ERR_NOT_FOUND);
    ASSERT_EQ(ozayn_rcm_resource_update_state(&_svc, "NOPE",
        OZAYN_RCM_STATE_BUSY), OZAYN_RCM_ERR_NOT_FOUND);
    ASSERT_EQ(ozayn_rcm_resource_update_health(&_svc, "NOPE",
        OZAYN_RCM_HEALTH_HEALTHY), OZAYN_RCM_ERR_NOT_FOUND);
    ozayn_rcm_service_shutdown(&_svc);
    return 0;
}

/* ============================================================
 * CAPACITY TESTS
 * ============================================================ */

TEST(test_rcm_capacity_get)
{
    _init_svc();
    ozayn_rcm_resource_desc_t *res = NULL;
    ozayn_rcm_resource_register(&_svc, OZAYN_RCM_RES_MEMORY, "RAM", NULL, NULL, 16, &res);
    ozayn_rcm_capacity_t cap;
    ASSERT_EQ(ozayn_rcm_capacity_get(&_svc, res->resource_id, &cap), OZAYN_RCM_OK);
    ASSERT_EQ(cap.total, 16);
    ASSERT_EQ(cap.available, 16);
    ozayn_rcm_service_shutdown(&_svc);
    return 0;
}

TEST(test_rcm_capacity_check_sufficient)
{
    _init_svc();
    ozayn_rcm_resource_desc_t *res = NULL;
    ozayn_rcm_resource_register(&_svc, OZAYN_RCM_RES_MEMORY, "RAM", NULL, NULL, 16, &res);
    int sufficient = 0;
    ASSERT_EQ(ozayn_rcm_capacity_check(&_svc, res->resource_id, 8, &sufficient), OZAYN_RCM_OK);
    ASSERT(sufficient);
    ozayn_rcm_service_shutdown(&_svc);
    return 0;
}

TEST(test_rcm_capacity_check_insufficient)
{
    _init_svc();
    ozayn_rcm_resource_desc_t *res = NULL;
    ozayn_rcm_resource_register(&_svc, OZAYN_RCM_RES_MEMORY, "RAM", NULL, NULL, 16, &res);
    ozayn_rcm_resource_update_usage(&_svc, res->resource_id, 14);
    int sufficient = 0;
    ASSERT_EQ(ozayn_rcm_capacity_check(&_svc, res->resource_id, 4, &sufficient), OZAYN_RCM_OK);
    ASSERT(!sufficient);
    ozayn_rcm_service_shutdown(&_svc);
    return 0;
}

TEST(test_rcm_capacity_check_unavailable)
{
    _init_svc();
    ozayn_rcm_resource_desc_t *res = NULL;
    ozayn_rcm_resource_register(&_svc, OZAYN_RCM_RES_GPU, "GPU", NULL, NULL, 4, &res);
    ozayn_rcm_resource_update_state(&_svc, res->resource_id, OZAYN_RCM_STATE_UNAVAILABLE);
    int sufficient = 0;
    ASSERT_EQ(ozayn_rcm_capacity_check(&_svc, res->resource_id, 1, &sufficient), OZAYN_RCM_OK);
    ASSERT(!sufficient);
    ozayn_rcm_service_shutdown(&_svc);
    return 0;
}

TEST(test_rcm_capacity_check_zero)
{
    _init_svc();
    ozayn_rcm_resource_desc_t *res = NULL;
    ozayn_rcm_resource_register(&_svc, OZAYN_RCM_RES_STORAGE, "Disk", NULL, NULL, 0, &res);
    int sufficient = 0;
    ASSERT_EQ(ozayn_rcm_capacity_check(&_svc, res->resource_id, 1, &sufficient), OZAYN_RCM_OK);
    ASSERT(!sufficient);
    ozayn_rcm_service_shutdown(&_svc);
    return 0;
}

TEST(test_rcm_capacity_check_all)
{
    _init_svc();
    ozayn_rcm_resource_desc_t *r1 = NULL, *r2 = NULL;
    ozayn_rcm_resource_register(&_svc, OZAYN_RCM_RES_CPU, "CPU", NULL, NULL, 8, &r1);
    ozayn_rcm_resource_register(&_svc, OZAYN_RCM_RES_MEMORY, "RAM", NULL, NULL, 16, &r2);

    ozayn_rcm_resource_requirement_t reqs[2];
    memset(reqs, 0, sizeof(reqs));
    strncpy(reqs[0].resource_id, r1->resource_id, OZAYN_RCM_MAX_ID_LEN - 1);
    reqs[0].min_capacity = 4;
    strncpy(reqs[1].resource_id, r2->resource_id, OZAYN_RCM_MAX_ID_LEN - 1);
    reqs[1].min_capacity = 8;

    int all_met = 0;
    ASSERT_EQ(ozayn_rcm_capacity_check_all(&_svc, reqs, 2, &all_met), OZAYN_RCM_OK);
    ASSERT(all_met);
    ozayn_rcm_service_shutdown(&_svc);
    return 0;
}

/* ============================================================
 * REQUIREMENT TESTS
 * ============================================================ */

TEST(test_rcm_requirement_create)
{
    _init_svc();
    ozayn_rcm_resource_requirement_t *req = NULL;
    ASSERT_EQ(ozayn_rcm_requirement_create(&_svc, OZAYN_RCM_RES_MEMORY,
        NULL, 4096, 0, OZAYN_RCM_AVAIL_AVAILABLE, 0,
        OZAYN_RCM_PRIORITY_NORMAL, 30000, &req), OZAYN_RCM_OK);
    ASSERT_NOT_NULL(req);
    ASSERT(req->requirement_id[0] != '\0');
    ASSERT_EQ(req->resource_type, OZAYN_RCM_RES_MEMORY);
    ASSERT_EQ(req->min_capacity, 4096);
    ozayn_rcm_service_shutdown(&_svc);
    return 0;
}

TEST(test_rcm_requirement_create_null)
{
    ASSERT_EQ(ozayn_rcm_requirement_create(NULL, 0, NULL, 0, 0, 0, 0, 0, 0, NULL),
              OZAYN_RCM_ERR_NULL);
    return 0;
}

TEST(test_rcm_requirement_create_invalid_type)
{
    _init_svc();
    ozayn_rcm_resource_requirement_t *req = NULL;
    ASSERT_EQ(ozayn_rcm_requirement_create(&_svc, (ozayn_rcm_resource_type_t)99,
        NULL, 0, 0, 0, 0, 0, 0, &req), OZAYN_RCM_ERR_INVALID_PARAM);
    ozayn_rcm_service_shutdown(&_svc);
    return 0;
}

TEST(test_rcm_requirement_create_null_out)
{
    _init_svc();
    ASSERT_EQ(ozayn_rcm_requirement_create(&_svc, OZAYN_RCM_RES_CPU,
        NULL, 0, 0, 0, 0, 0, 0, NULL), OZAYN_RCM_ERR_NULL);
    ozayn_rcm_service_shutdown(&_svc);
    return 0;
}

/* ============================================================
 * DECISION TESTS
 * ============================================================ */

TEST(test_rcm_evaluate_available)
{
    _init_svc();
    ozayn_rcm_resource_desc_t *res = NULL;
    ozayn_rcm_resource_register(&_svc, OZAYN_RCM_RES_MEMORY, "RAM", NULL, NULL, 16, &res);

    ozayn_rcm_resource_requirement_t *req = NULL;
    ozayn_rcm_requirement_create(&_svc, OZAYN_RCM_RES_MEMORY,
        res->resource_id, 4, 0, OZAYN_RCM_AVAIL_AVAILABLE, 0,
        OZAYN_RCM_PRIORITY_NORMAL, 30000, &req);

    ozayn_rcm_resource_decision_t *dec = NULL;
    ASSERT_EQ(ozayn_rcm_evaluate(&_svc, "OP-1", req, 1, &dec), OZAYN_RCM_OK);
    ASSERT_NOT_NULL(dec);
    ASSERT_EQ(dec->decision, OZAYN_RCM_DECISION_AVAILABLE);
    ASSERT(dec->decision_id[0] != '\0');
    ASSERT(strcmp(dec->operation_id, "OP-1") == 0);
    ozayn_rcm_service_shutdown(&_svc);
    return 0;
}

TEST(test_rcm_evaluate_insufficient)
{
    _init_svc();
    ozayn_rcm_resource_desc_t *res = NULL;
    ozayn_rcm_resource_register(&_svc, OZAYN_RCM_RES_MEMORY, "RAM", NULL, NULL, 16, &res);
    ozayn_rcm_resource_update_usage(&_svc, res->resource_id, 14);

    ozayn_rcm_resource_requirement_t *req = NULL;
    ozayn_rcm_requirement_create(&_svc, OZAYN_RCM_RES_MEMORY,
        res->resource_id, 4, 0, OZAYN_RCM_AVAIL_AVAILABLE, 0,
        OZAYN_RCM_PRIORITY_NORMAL, 30000, &req);

    ozayn_rcm_resource_decision_t *dec = NULL;
    ASSERT_EQ(ozayn_rcm_evaluate(&_svc, "OP-1", req, 1, &dec), OZAYN_RCM_OK);
    ASSERT_EQ(dec->decision, OZAYN_RCM_DECISION_INSUFFICIENT);
    ASSERT(dec->failed_requirement_count > 0);
    ozayn_rcm_service_shutdown(&_svc);
    return 0;
}

TEST(test_rcm_evaluate_unknown_resource)
{
    _init_svc();
    ozayn_rcm_resource_requirement_t *req = NULL;
    ozayn_rcm_requirement_create(&_svc, OZAYN_RCM_RES_GPU,
        "NONEXISTENT", 1, 0, OZAYN_RCM_AVAIL_UNKNOWN, 0,
        OZAYN_RCM_PRIORITY_NORMAL, 30000, &req);

    ozayn_rcm_resource_decision_t *dec = NULL;
    ASSERT_EQ(ozayn_rcm_evaluate(&_svc, "OP-1", req, 1, &dec), OZAYN_RCM_OK);
    ASSERT_EQ(dec->decision, OZAYN_RCM_DECISION_UNKNOWN);
    ozayn_rcm_service_shutdown(&_svc);
    return 0;
}

TEST(test_rcm_evaluate_unavailable)
{
    _init_svc();
    ozayn_rcm_resource_desc_t *res = NULL;
    ozayn_rcm_resource_register(&_svc, OZAYN_RCM_RES_NETWORK, "NET", NULL, NULL, 1, &res);
    ozayn_rcm_resource_update_state(&_svc, res->resource_id, OZAYN_RCM_STATE_UNAVAILABLE);

    ozayn_rcm_resource_requirement_t *req = NULL;
    ozayn_rcm_requirement_create(&_svc, OZAYN_RCM_RES_NETWORK,
        res->resource_id, 1, 0, OZAYN_RCM_AVAIL_UNKNOWN, 0,
        OZAYN_RCM_PRIORITY_NORMAL, 30000, &req);

    ozayn_rcm_resource_decision_t *dec = NULL;
    ASSERT_EQ(ozayn_rcm_evaluate(&_svc, "OP-1", req, 1, &dec), OZAYN_RCM_OK);
    ASSERT_EQ(dec->decision, OZAYN_RCM_DECISION_UNAVAILABLE);
    ozayn_rcm_service_shutdown(&_svc);
    return 0;
}

TEST(test_rcm_evaluate_null)
{
    ASSERT_EQ(ozayn_rcm_evaluate(NULL, "X", NULL, 0, NULL), OZAYN_RCM_ERR_NULL);
    return 0;
}

TEST(test_rcm_evaluate_not_init)
{
    _reset_all();
    memset(&_cfg, 0, sizeof(_cfg));
    ozayn_rcm_resource_requirement_t req;
    memset(&req, 0, sizeof(req));
    ozayn_rcm_resource_decision_t *dec = NULL;
    ASSERT_EQ(ozayn_rcm_evaluate(&_svc, "X", &req, 1, &dec), OZAYN_RCM_ERR_NOT_INITIALIZED);
    return 0;
}

TEST(test_rcm_decision_get)
{
    _init_svc();
    ozayn_rcm_resource_desc_t *res = NULL;
    ozayn_rcm_resource_register(&_svc, OZAYN_RCM_RES_CPU, "CPU", NULL, NULL, 8, &res);

    ozayn_rcm_resource_requirement_t *req = NULL;
    ozayn_rcm_requirement_create(&_svc, OZAYN_RCM_RES_CPU,
        res->resource_id, 2, 0, OZAYN_RCM_AVAIL_UNKNOWN, 0,
        OZAYN_RCM_PRIORITY_NORMAL, 30000, &req);

    ozayn_rcm_resource_decision_t *dec = NULL;
    ozayn_rcm_evaluate(&_svc, "OP-1", req, 1, &dec);

    const ozayn_rcm_resource_decision_t *found = ozayn_rcm_decision_get(&_svc,
        dec->decision_id);
    ASSERT_NOT_NULL(found);
    ASSERT(strcmp(found->decision_id, dec->decision_id) == 0);
    ASSERT_NULL(ozayn_rcm_decision_get(&_svc, "NOPE"));
    ASSERT_NULL(ozayn_rcm_decision_get(NULL, "X"));
    ozayn_rcm_service_shutdown(&_svc);
    return 0;
}

TEST(test_rcm_decision_get_by_operation)
{
    _init_svc();
    ozayn_rcm_resource_desc_t *res = NULL;
    ozayn_rcm_resource_register(&_svc, OZAYN_RCM_RES_CPU, "CPU", NULL, NULL, 8, &res);

    ozayn_rcm_resource_requirement_t *req = NULL;
    ozayn_rcm_requirement_create(&_svc, OZAYN_RCM_RES_CPU,
        res->resource_id, 2, 0, OZAYN_RCM_AVAIL_UNKNOWN, 0,
        OZAYN_RCM_PRIORITY_NORMAL, 30000, &req);

    ozayn_rcm_resource_decision_t *dec = NULL;
    ozayn_rcm_evaluate(&_svc, "OP-UNIQUE", req, 1, &dec);

    const ozayn_rcm_resource_decision_t *found = ozayn_rcm_decision_get_by_operation(
        &_svc, "OP-UNIQUE");
    ASSERT_NOT_NULL(found);
    ASSERT_NULL(ozayn_rcm_decision_get_by_operation(&_svc, "NOPE"));
    ozayn_rcm_service_shutdown(&_svc);
    return 0;
}

TEST(test_rcm_decision_count)
{
    _init_svc();
    ASSERT_EQ(ozayn_rcm_decision_count(&_svc), 0);
    ASSERT_EQ(ozayn_rcm_decision_count(NULL), 0);
    ozayn_rcm_resource_desc_t *res = NULL;
    ozayn_rcm_resource_register(&_svc, OZAYN_RCM_RES_CPU, "CPU", NULL, NULL, 8, &res);

    ozayn_rcm_resource_requirement_t *req = NULL;
    ozayn_rcm_requirement_create(&_svc, OZAYN_RCM_RES_CPU,
        res->resource_id, 2, 0, OZAYN_RCM_AVAIL_UNKNOWN, 0,
        OZAYN_RCM_PRIORITY_NORMAL, 30000, &req);

    ozayn_rcm_resource_decision_t *d1 = NULL, *d2 = NULL;
    ozayn_rcm_evaluate(&_svc, "OP-1", req, 1, &d1);
    ozayn_rcm_evaluate(&_svc, "OP-2", req, 1, &d2);
    ASSERT_EQ(ozayn_rcm_decision_count(&_svc), 2);
    ozayn_rcm_service_shutdown(&_svc);
    return 0;
}

TEST(test_rcm_decision_is_valid)
{
    _init_svc();
    ozayn_rcm_resource_desc_t *res = NULL;
    ozayn_rcm_resource_register(&_svc, OZAYN_RCM_RES_CPU, "CPU", NULL, NULL, 8, &res);

    ozayn_rcm_resource_requirement_t *req = NULL;
    ozayn_rcm_requirement_create(&_svc, OZAYN_RCM_RES_CPU,
        res->resource_id, 2, 0, OZAYN_RCM_AVAIL_UNKNOWN, 0,
        OZAYN_RCM_PRIORITY_NORMAL, 30000, &req);

    ozayn_rcm_resource_decision_t *dec = NULL;
    ozayn_rcm_evaluate(&_svc, "OP-1", req, 1, &dec);
    ASSERT(ozayn_rcm_decision_is_valid(&_svc, dec->decision_id));
    ASSERT(!ozayn_rcm_decision_is_valid(&_svc, "NOPE"));
    ASSERT(!ozayn_rcm_decision_is_valid(NULL, "X"));
    ozayn_rcm_service_shutdown(&_svc);
    return 0;
}

/* ============================================================
 * RESOURCE RECHECK TESTS
 * ============================================================ */

TEST(test_rcm_recheck)
{
    _init_svc();
    ozayn_rcm_resource_desc_t *res = NULL;
    ozayn_rcm_resource_register(&_svc, OZAYN_RCM_RES_MEMORY, "RAM", NULL, NULL, 16, &res);

    ozayn_rcm_resource_requirement_t *req = NULL;
    ozayn_rcm_requirement_create(&_svc, OZAYN_RCM_RES_MEMORY,
        res->resource_id, 4, 0, OZAYN_RCM_AVAIL_UNKNOWN, 0,
        OZAYN_RCM_PRIORITY_NORMAL, 30000, &req);

    ozayn_rcm_resource_decision_t *dec = NULL;
    ozayn_rcm_evaluate(&_svc, "OP-1", req, 1, &dec);
    ASSERT_EQ(ozayn_rcm_recheck(&_svc, dec->decision_id), OZAYN_RCM_OK);
    ozayn_rcm_service_shutdown(&_svc);
    return 0;
}

TEST(test_rcm_recheck_not_found)
{
    _init_svc();
    ASSERT_EQ(ozayn_rcm_recheck(&_svc, "NOPE"), OZAYN_RCM_ERR_RESERVATION_NOT_FOUND);
    ozayn_rcm_service_shutdown(&_svc);
    return 0;
}

TEST(test_rcm_recheck_capacity_reduced)
{
    _init_svc();
    ozayn_rcm_resource_desc_t *res = NULL;
    ozayn_rcm_resource_register(&_svc, OZAYN_RCM_RES_MEMORY, "RAM", NULL, NULL, 16, &res);

    ozayn_rcm_resource_requirement_t *req = NULL;
    ozayn_rcm_requirement_create(&_svc, OZAYN_RCM_RES_MEMORY,
        res->resource_id, 8, 0, OZAYN_RCM_AVAIL_UNKNOWN, 0,
        OZAYN_RCM_PRIORITY_NORMAL, 30000, &req);

    ozayn_rcm_resource_decision_t *dec = NULL;
    ozayn_rcm_evaluate(&_svc, "OP-1", req, 1, &dec);
    ASSERT_EQ(dec->decision, OZAYN_RCM_DECISION_AVAILABLE);

    ozayn_rcm_resource_update_usage(&_svc, res->resource_id, 12);
    ASSERT_EQ(ozayn_rcm_recheck(&_svc, dec->decision_id), OZAYN_RCM_OK);
    ASSERT_EQ(dec->decision, OZAYN_RCM_DECISION_INSUFFICIENT);
    ozayn_rcm_service_shutdown(&_svc);
    return 0;
}

TEST(test_rcm_recheck_null)
{
    ASSERT_EQ(ozayn_rcm_recheck(NULL, "X"), OZAYN_RCM_ERR_NULL);
    return 0;
}

TEST(test_rcm_recheck_not_init)
{
    _reset_all();
    memset(&_cfg, 0, sizeof(_cfg));
    ozayn_rcm_service_init(&_svc, &_cfg);
    ASSERT_EQ(ozayn_rcm_recheck(&_svc, "NOPE"), OZAYN_RCM_ERR_RESERVATION_NOT_FOUND);
    ozayn_rcm_service_shutdown(&_svc);
    return 0;
}

/* ============================================================
 * RESERVATION TESTS
 * ============================================================ */

TEST(test_rcm_reservation_create)
{
    _init_svc();
    ozayn_rcm_resource_desc_t *res = NULL;
    ozayn_rcm_resource_register(&_svc, OZAYN_RCM_RES_MEMORY, "RAM", NULL, NULL, 16, &res);

    ozayn_rcm_reservation_t *resv = NULL;
    ASSERT_EQ(ozayn_rcm_reservation_create(&_svc, "OP-1", res->resource_id,
        OZAYN_RCM_RES_MEMORY, 4, &resv), OZAYN_RCM_OK);
    ASSERT_NOT_NULL(resv);
    ASSERT(resv->reservation_id[0] != '\0');
    ASSERT(strcmp(resv->operation_id, "OP-1") == 0);
    ASSERT_EQ(resv->reserved_capacity, 4);
    ASSERT_EQ(resv->state, OZAYN_RCM_RESERV_RESERVED);
    ASSERT_EQ(res->capacity.reserved, 4);
    ASSERT_EQ(res->capacity.available, 12);
    ozayn_rcm_service_shutdown(&_svc);
    return 0;
}

TEST(test_rcm_reservation_create_insufficient)
{
    _init_svc();
    ozayn_rcm_resource_desc_t *res = NULL;
    ozayn_rcm_resource_register(&_svc, OZAYN_RCM_RES_MEMORY, "RAM", NULL, NULL, 8, &res);

    ozayn_rcm_reservation_t *resv = NULL;
    ASSERT_EQ(ozayn_rcm_reservation_create(&_svc, "OP-1", res->resource_id,
        OZAYN_RCM_RES_MEMORY, 16, &resv), OZAYN_RCM_ERR_RESERVATION_FAILED);
    ozayn_rcm_service_shutdown(&_svc);
    return 0;
}

TEST(test_rcm_reservation_create_duplicate)
{
    _init_svc();
    ozayn_rcm_resource_desc_t *res = NULL;
    ozayn_rcm_resource_register(&_svc, OZAYN_RCM_RES_MEMORY, "RAM", NULL, NULL, 16, &res);

    ozayn_rcm_reservation_t *r1 = NULL, *r2 = NULL;
    ozayn_rcm_reservation_create(&_svc, "OP-1", res->resource_id,
        OZAYN_RCM_RES_MEMORY, 4, &r1);
    ASSERT_EQ(ozayn_rcm_reservation_create(&_svc, "OP-1", res->resource_id,
        OZAYN_RCM_RES_MEMORY, 4, &r2), OZAYN_RCM_ERR_DUPLICATE);
    ozayn_rcm_service_shutdown(&_svc);
    return 0;
}

TEST(test_rcm_reservation_activate)
{
    _init_svc();
    ozayn_rcm_resource_desc_t *res = NULL;
    ozayn_rcm_resource_register(&_svc, OZAYN_RCM_RES_MEMORY, "RAM", NULL, NULL, 16, &res);

    ozayn_rcm_reservation_t *resv = NULL;
    ozayn_rcm_reservation_create(&_svc, "OP-1", res->resource_id,
        OZAYN_RCM_RES_MEMORY, 4, &resv);
    ASSERT_EQ(ozayn_rcm_reservation_activate(&_svc, resv->reservation_id), OZAYN_RCM_OK);
    ASSERT_EQ(resv->state, OZAYN_RCM_RESERV_ACTIVE);
    ozayn_rcm_service_shutdown(&_svc);
    return 0;
}

TEST(test_rcm_reservation_release)
{
    _init_svc();
    ozayn_rcm_resource_desc_t *res = NULL;
    ozayn_rcm_resource_register(&_svc, OZAYN_RCM_RES_MEMORY, "RAM", NULL, NULL, 16, &res);

    ozayn_rcm_reservation_t *resv = NULL;
    ozayn_rcm_reservation_create(&_svc, "OP-1", res->resource_id,
        OZAYN_RCM_RES_MEMORY, 4, &resv);
    ASSERT_EQ(ozayn_rcm_reservation_release(&_svc, resv->reservation_id), OZAYN_RCM_OK);
    ASSERT_EQ(resv->state, OZAYN_RCM_RESERV_RELEASED);
    ASSERT_EQ(res->capacity.reserved, 0);
    ASSERT_EQ(res->capacity.available, 16);
    ozayn_rcm_service_shutdown(&_svc);
    return 0;
}

TEST(test_rcm_reservation_cancel)
{
    _init_svc();
    ozayn_rcm_resource_desc_t *res = NULL;
    ozayn_rcm_resource_register(&_svc, OZAYN_RCM_RES_MEMORY, "RAM", NULL, NULL, 16, &res);

    ozayn_rcm_reservation_t *resv = NULL;
    ozayn_rcm_reservation_create(&_svc, "OP-1", res->resource_id,
        OZAYN_RCM_RES_MEMORY, 4, &resv);
    ASSERT_EQ(ozayn_rcm_reservation_cancel(&_svc, resv->reservation_id), OZAYN_RCM_OK);
    ASSERT_EQ(resv->state, OZAYN_RCM_RESERV_CANCELLED);
    ASSERT_EQ(res->capacity.reserved, 0);
    ozayn_rcm_service_shutdown(&_svc);
    return 0;
}

TEST(test_rcm_reservation_get)
{
    _init_svc();
    ozayn_rcm_resource_desc_t *res = NULL;
    ozayn_rcm_resource_register(&_svc, OZAYN_RCM_RES_MEMORY, "RAM", NULL, NULL, 16, &res);

    ozayn_rcm_reservation_t *resv = NULL;
    ozayn_rcm_reservation_create(&_svc, "OP-1", res->resource_id,
        OZAYN_RCM_RES_MEMORY, 4, &resv);
    const ozayn_rcm_reservation_t *found = ozayn_rcm_reservation_get(&_svc,
        resv->reservation_id);
    ASSERT_NOT_NULL(found);
    ASSERT(strcmp(found->reservation_id, resv->reservation_id) == 0);
    ASSERT_NULL(ozayn_rcm_reservation_get(&_svc, "NOPE"));
    ozayn_rcm_service_shutdown(&_svc);
    return 0;
}

TEST(test_rcm_reservation_count)
{
    _init_svc();
    ASSERT_EQ(ozayn_rcm_reservation_count(&_svc), 0);
    ASSERT_EQ(ozayn_rcm_reservation_count(NULL), 0);
    ozayn_rcm_resource_desc_t *res = NULL;
    ozayn_rcm_resource_register(&_svc, OZAYN_RCM_RES_MEMORY, "RAM", NULL, NULL, 16, &res);
    ozayn_rcm_reservation_t *r1 = NULL;
    ozayn_rcm_reservation_create(&_svc, "OP-1", res->resource_id,
        OZAYN_RCM_RES_MEMORY, 4, &r1);
    ASSERT_EQ(ozayn_rcm_reservation_count(&_svc), 1);
    ozayn_rcm_service_shutdown(&_svc);
    return 0;
}

TEST(test_rcm_reservation_count_by_resource)
{
    _init_svc();
    ozayn_rcm_resource_desc_t *res = NULL;
    ozayn_rcm_resource_register(&_svc, OZAYN_RCM_RES_MEMORY, "RAM", NULL, NULL, 16, &res);
    ozayn_rcm_reservation_t *r1 = NULL, *r2 = NULL;
    ozayn_rcm_reservation_create(&_svc, "OP-1", res->resource_id,
        OZAYN_RCM_RES_MEMORY, 4, &r1);
    ozayn_rcm_reservation_create(&_svc, "OP-2", res->resource_id,
        OZAYN_RCM_RES_MEMORY, 4, &r2);
    ASSERT_EQ(ozayn_rcm_reservation_count_by_resource(&_svc, res->resource_id), 2);
    ASSERT_EQ(ozayn_rcm_reservation_count_by_resource(&_svc, "NOPE"), 0);
    ozayn_rcm_service_shutdown(&_svc);
    return 0;
}

TEST(test_rcm_reservation_release_not_found)
{
    _init_svc();
    ASSERT_EQ(ozayn_rcm_reservation_release(&_svc, "NOPE"),
              OZAYN_RCM_ERR_RESERVATION_NOT_FOUND);
    ozayn_rcm_service_shutdown(&_svc);
    return 0;
}

TEST(test_rcm_reservation_cancel_not_found)
{
    _init_svc();
    ASSERT_EQ(ozayn_rcm_reservation_cancel(&_svc, "NOPE"),
              OZAYN_RCM_ERR_RESERVATION_NOT_FOUND);
    ozayn_rcm_service_shutdown(&_svc);
    return 0;
}

/* ============================================================
 * SNAPSHOT TESTS
 * ============================================================ */

TEST(test_rcm_snapshot_create)
{
    _init_svc();
    ozayn_rcm_resource_desc_t *r1 = NULL, *r2 = NULL;
    ozayn_rcm_resource_register(&_svc, OZAYN_RCM_RES_CPU, "CPU", NULL, NULL, 8, &r1);
    ozayn_rcm_resource_register(&_svc, OZAYN_RCM_RES_MEMORY, "RAM", NULL, NULL, 16, &r2);

    ozayn_rcm_snapshot_t *snap = NULL;
    ASSERT_EQ(ozayn_rcm_snapshot_create(&_svc, &snap), OZAYN_RCM_OK);
    ASSERT_NOT_NULL(snap);
    ASSERT(snap->snapshot_id[0] != '\0');
    ASSERT_EQ(snap->resource_count, 2);
    ASSERT_EQ(snap->summary.total, 24);
    ASSERT_EQ(snap->overall_state, OZAYN_RCM_STATE_AVAILABLE);
    ozayn_rcm_service_shutdown(&_svc);
    return 0;
}

TEST(test_rcm_snapshot_get)
{
    _init_svc();
    ozayn_rcm_snapshot_t *snap = NULL;
    ozayn_rcm_snapshot_create(&_svc, &snap);
    const ozayn_rcm_snapshot_t *found = ozayn_rcm_snapshot_get(&_svc, snap->snapshot_id);
    ASSERT_NOT_NULL(found);
    ASSERT(strcmp(found->snapshot_id, snap->snapshot_id) == 0);
    ASSERT_NULL(ozayn_rcm_snapshot_get(&_svc, "NOPE"));
    ozayn_rcm_service_shutdown(&_svc);
    return 0;
}

TEST(test_rcm_snapshot_count)
{
    _init_svc();
    ASSERT_EQ(ozayn_rcm_snapshot_count(&_svc), 0);
    ASSERT_EQ(ozayn_rcm_snapshot_count(NULL), 0);
    ozayn_rcm_snapshot_t *snap = NULL;
    ozayn_rcm_snapshot_create(&_svc, &snap);
    ASSERT_EQ(ozayn_rcm_snapshot_count(&_svc), 1);
    ozayn_rcm_service_shutdown(&_svc);
    return 0;
}

TEST(test_rcm_snapshot_overall_degraded)
{
    _init_svc();
    ozayn_rcm_resource_desc_t *r1 = NULL, *r2 = NULL;
    ozayn_rcm_resource_register(&_svc, OZAYN_RCM_RES_CPU, "CPU", NULL, NULL, 8, &r1);
    ozayn_rcm_resource_register(&_svc, OZAYN_RCM_RES_MEMORY, "RAM", NULL, NULL, 16, &r2);
    ozayn_rcm_resource_update_state(&_svc, r2->resource_id, OZAYN_RCM_STATE_UNAVAILABLE);

    ozayn_rcm_snapshot_t *snap = NULL;
    ozayn_rcm_snapshot_create(&_svc, &snap);
    ASSERT_EQ(snap->overall_state, OZAYN_RCM_STATE_DEGRADED);
    ozayn_rcm_service_shutdown(&_svc);
    return 0;
}

/* ============================================================
 * CLEANUP TESTS
 * ============================================================ */

TEST(test_rcm_cleanup_expired_reservations)
{
    _reset_all();
    memset(&_cfg, 0, sizeof(_cfg));
    _cfg.reservation_ttl_ms = 1000;
    ozayn_rcm_service_init(&_svc, &_cfg);
    ozayn_rcm_resource_desc_t *res = NULL;
    ozayn_rcm_resource_register(&_svc, OZAYN_RCM_RES_MEMORY, "RAM", NULL, NULL, 16, &res);

    ozayn_rcm_reservation_t *resv = NULL;
    ozayn_rcm_reservation_create(&_svc, "OP-1", res->resource_id,
        OZAYN_RCM_RES_MEMORY, 4, &resv);

    struct timespec ts = {2, 0};
    nanosleep(&ts, NULL);

    int cleaned = ozayn_rcm_cleanup_expired_reservations(&_svc);
    ASSERT(cleaned >= 1);
    ASSERT_EQ(res->capacity.reserved, 0);
    ASSERT_EQ(res->capacity.available, 16);
    ozayn_rcm_service_shutdown(&_svc);
    return 0;
}

TEST(test_rcm_cleanup_expired_decisions)
{
    _reset_all();
    memset(&_cfg, 0, sizeof(_cfg));
    _cfg.reservation_ttl_ms = 1000;
    ozayn_rcm_service_init(&_svc, &_cfg);
    ozayn_rcm_resource_desc_t *res = NULL;
    ozayn_rcm_resource_register(&_svc, OZAYN_RCM_RES_CPU, "CPU", NULL, NULL, 8, &res);

    ozayn_rcm_resource_requirement_t *req = NULL;
    ozayn_rcm_requirement_create(&_svc, OZAYN_RCM_RES_CPU,
        res->resource_id, 2, 0, OZAYN_RCM_AVAIL_UNKNOWN, 0,
        OZAYN_RCM_PRIORITY_NORMAL, 1000, &req);

    ozayn_rcm_resource_decision_t *dec = NULL;
    ozayn_rcm_evaluate(&_svc, "OP-1", req, 1, &dec);

    struct timespec ts = {2, 0};
    nanosleep(&ts, NULL);

    int cleaned = ozayn_rcm_cleanup_expired_decisions(&_svc);
    ASSERT(cleaned >= 1);
    ozayn_rcm_service_shutdown(&_svc);
    return 0;
}

TEST(test_rcm_cleanup_all)
{
    _init_svc();
    ozayn_rcm_resource_desc_t *res = NULL;
    ozayn_rcm_resource_register(&_svc, OZAYN_RCM_RES_MEMORY, "RAM", NULL, NULL, 16, &res);
    ozayn_rcm_snapshot_t *snap = NULL;
    ozayn_rcm_snapshot_create(&_svc, &snap);

    int cleaned = ozayn_rcm_cleanup_all(&_svc);
    ASSERT(cleaned >= 1);
    ASSERT_EQ(_svc.snapshot_count, 0);
    ozayn_rcm_service_shutdown(&_svc);
    return 0;
}

TEST(test_rcm_cleanup_null)
{
    ASSERT_EQ(ozayn_rcm_cleanup_all(NULL), 0);
    return 0;
}

/* ============================================================
 * HEALTH INTEGRATION TESTS
 * ============================================================ */

TEST(test_rcm_health_healthy)
{
    _init_svc();
    ozayn_rcm_resource_desc_t *res = NULL;
    ozayn_rcm_resource_register(&_svc, OZAYN_RCM_RES_CPU, "CPU", NULL, NULL, 8, &res);
    ASSERT_EQ(res->health, OZAYN_RCM_HEALTH_HEALTHY);
    ozayn_rcm_service_shutdown(&_svc);
    return 0;
}

TEST(test_rcm_health_degraded)
{
    _init_svc();
    ozayn_rcm_resource_desc_t *res = NULL;
    ozayn_rcm_resource_register(&_svc, OZAYN_RCM_RES_CPU, "CPU", NULL, NULL, 8, &res);
    ozayn_rcm_resource_update_health(&_svc, res->resource_id, OZAYN_RCM_HEALTH_DEGRADED);
    ASSERT_EQ(res->health, OZAYN_RCM_HEALTH_DEGRADED);
    ASSERT_EQ(res->availability, OZAYN_RCM_AVAIL_AVAILABLE);
    ozayn_rcm_service_shutdown(&_svc);
    return 0;
}

TEST(test_rcm_health_unknown)
{
    _init_svc();
    ozayn_rcm_resource_desc_t *res = NULL;
    ozayn_rcm_resource_register(&_svc, OZAYN_RCM_RES_CPU, "CPU", NULL, NULL, 8, &res);
    ozayn_rcm_resource_update_health(&_svc, res->resource_id, OZAYN_RCM_HEALTH_UNKNOWN);
    ASSERT_EQ(res->health, OZAYN_RCM_HEALTH_UNKNOWN);
    ozayn_rcm_service_shutdown(&_svc);
    return 0;
}

/* ============================================================
 * STATISTICS TESTS
 * ============================================================ */

TEST(test_rcm_get_stats)
{
    _init_svc();
    ozayn_rcm_stats_t stats;
    memset(&stats, 0, sizeof(stats));
    ASSERT_EQ(ozayn_rcm_get_stats(&_svc, &stats), OZAYN_RCM_OK);
    ASSERT_EQ(stats.total_resources_registered, 0);
    ASSERT_EQ(ozayn_rcm_get_stats(NULL, NULL), OZAYN_RCM_ERR_NULL);

    ozayn_rcm_resource_desc_t *res = NULL;
    ozayn_rcm_resource_register(&_svc, OZAYN_RCM_RES_CPU, "CPU", NULL, NULL, 8, &res);
    ozayn_rcm_get_stats(&_svc, &stats);
    ASSERT_EQ(stats.total_resources_registered, 1);
    ozayn_rcm_service_shutdown(&_svc);
    return 0;
}

TEST(test_rcm_stats_evaluations)
{
    _init_svc();
    ozayn_rcm_resource_desc_t *res = NULL;
    ozayn_rcm_resource_register(&_svc, OZAYN_RCM_RES_MEMORY, "RAM", NULL, NULL, 16, &res);

    ozayn_rcm_resource_requirement_t *req = NULL;
    ozayn_rcm_requirement_create(&_svc, OZAYN_RCM_RES_MEMORY,
        res->resource_id, 4, 0, OZAYN_RCM_AVAIL_UNKNOWN, 0,
        OZAYN_RCM_PRIORITY_NORMAL, 30000, &req);

    ozayn_rcm_resource_decision_t *d = NULL;
    ozayn_rcm_evaluate(&_svc, "OP-1", req, 1, &d);

    ozayn_rcm_stats_t stats;
    ozayn_rcm_get_stats(&_svc, &stats);
    ASSERT_EQ(stats.total_decisions, 1);
    ASSERT_EQ(stats.total_available, 1);
    ozayn_rcm_service_shutdown(&_svc);
    return 0;
}

/* ============================================================
 * VALIDATION TESTS
 * ============================================================ */

TEST(test_rcm_resource_validate)
{
    ozayn_rcm_resource_desc_t res;
    memset(&res, 0, sizeof(res));
    ASSERT(!ozayn_rcm_resource_validate(NULL));
    ASSERT(!ozayn_rcm_resource_validate(&res));
    strncpy(res.resource_id, "RCR-1", OZAYN_RCM_MAX_ID_LEN - 1);
    res.type = OZAYN_RCM_RES_CPU;
    res.state = OZAYN_RCM_STATE_AVAILABLE;
    res.health = OZAYN_RCM_HEALTH_HEALTHY;
    res.availability = OZAYN_RCM_AVAIL_AVAILABLE;
    ASSERT(ozayn_rcm_resource_validate(&res));
    return 0;
}

TEST(test_rcm_capacity_validate)
{
    ozayn_rcm_capacity_t cap;
    memset(&cap, 0, sizeof(cap));
    ASSERT(!ozayn_rcm_capacity_validate(NULL));
    cap.total = 16;
    cap.used = 8;
    ASSERT(ozayn_rcm_capacity_validate(&cap));
    cap.used = 20;
    ASSERT(!ozayn_rcm_capacity_validate(&cap));
    return 0;
}

TEST(test_rcm_decision_validate)
{
    ozayn_rcm_resource_decision_t dec;
    memset(&dec, 0, sizeof(dec));
    ASSERT(!ozayn_rcm_decision_validate(NULL));
    ASSERT(!ozayn_rcm_decision_validate(&dec));
    strncpy(dec.decision_id, "RCD-1", OZAYN_RCM_MAX_ID_LEN - 1);
    dec.decision = OZAYN_RCM_DECISION_AVAILABLE;
    ASSERT(ozayn_rcm_decision_validate(&dec));
    return 0;
}

TEST(test_rcm_reservation_validate)
{
    ozayn_rcm_reservation_t res;
    memset(&res, 0, sizeof(res));
    ASSERT(!ozayn_rcm_reservation_validate(NULL));
    ASSERT(!ozayn_rcm_reservation_validate(&res));
    strncpy(res.reservation_id, "RCV-1", OZAYN_RCM_MAX_ID_LEN - 1);
    res.state = OZAYN_RCM_RESERV_RESERVED;
    ASSERT(ozayn_rcm_reservation_validate(&res));
    return 0;
}

TEST(test_rcm_requirement_validate)
{
    ozayn_rcm_resource_requirement_t req;
    memset(&req, 0, sizeof(req));
    ASSERT(!ozayn_rcm_requirement_validate(NULL));
    ASSERT(!ozayn_rcm_requirement_validate(&req));
    strncpy(req.requirement_id, "RCQ-1", OZAYN_RCM_MAX_ID_LEN - 1);
    req.resource_type = OZAYN_RCM_RES_CPU;
    ASSERT(ozayn_rcm_requirement_validate(&req));
    return 0;
}

/* ============================================================
 * NAME HELPER TESTS
 * ============================================================ */

TEST(test_rcm_resource_type_name)
{
    ASSERT(strcmp(ozayn_rcm_resource_type_name(OZAYN_RCM_RES_CPU), "CPU") == 0);
    ASSERT(strcmp(ozayn_rcm_resource_type_name(OZAYN_RCM_RES_MEMORY), "Memory") == 0);
    ASSERT(strcmp(ozayn_rcm_resource_type_name(OZAYN_RCM_RES_STORAGE), "Storage") == 0);
    ASSERT(strcmp(ozayn_rcm_resource_type_name(OZAYN_RCM_RES_WORKER_CAPACITY), "WorkerCapacity") == 0);
    ASSERT(strcmp(ozayn_rcm_resource_type_name(OZAYN_RCM_RES_QUEUE_CAPACITY), "QueueCapacity") == 0);
    ASSERT(strcmp(ozayn_rcm_resource_type_name(OZAYN_RCM_RES_GPU), "GPU") == 0);
    ASSERT(strcmp(ozayn_rcm_resource_type_name(OZAYN_RCM_RES_AUDIO), "Audio") == 0);
    ASSERT(strcmp(ozayn_rcm_resource_type_name(OZAYN_RCM_RES_CAMERA), "Camera") == 0);
    ASSERT(strcmp(ozayn_rcm_resource_type_name(OZAYN_RCM_RES_MICROPHONE), "Microphone") == 0);
    ASSERT(strcmp(ozayn_rcm_resource_type_name(OZAYN_RCM_RES_NETWORK), "Network") == 0);
    ASSERT(strcmp(ozayn_rcm_resource_type_name((ozayn_rcm_resource_type_t)99), "Invalid") == 0);
    return 0;
}

TEST(test_rcm_resource_state_name)
{
    ASSERT(strcmp(ozayn_rcm_resource_state_name(OZAYN_RCM_STATE_AVAILABLE), "Available") == 0);
    ASSERT(strcmp(ozayn_rcm_resource_state_name(OZAYN_RCM_STATE_BUSY), "Busy") == 0);
    ASSERT(strcmp(ozayn_rcm_resource_state_name((ozayn_rcm_resource_state_t)99), "Invalid") == 0);
    return 0;
}

TEST(test_rcm_resource_health_name)
{
    ASSERT(strcmp(ozayn_rcm_resource_health_name(OZAYN_RCM_HEALTH_HEALTHY), "Healthy") == 0);
    ASSERT(strcmp(ozayn_rcm_resource_health_name(OZAYN_RCM_HEALTH_DEGRADED), "Degraded") == 0);
    ASSERT(strcmp(ozayn_rcm_resource_health_name((ozayn_rcm_resource_health_t)99), "Invalid") == 0);
    return 0;
}

TEST(test_rcm_availability_name)
{
    ASSERT(strcmp(ozayn_rcm_availability_name(OZAYN_RCM_AVAIL_AVAILABLE), "Available") == 0);
    ASSERT(strcmp(ozayn_rcm_availability_name((ozayn_rcm_availability_t)99), "Invalid") == 0);
    return 0;
}

TEST(test_rcm_decision_name)
{
    ASSERT(strcmp(ozayn_rcm_resource_decision_name(OZAYN_RCM_DECISION_AVAILABLE), "Available") == 0);
    ASSERT(strcmp(ozayn_rcm_resource_decision_name(OZAYN_RCM_DECISION_INSUFFICIENT), "Insufficient") == 0);
    ASSERT(strcmp(ozayn_rcm_resource_decision_name((ozayn_rcm_decision_result_t)99), "Invalid") == 0);
    return 0;
}

TEST(test_rcm_reservation_state_name)
{
    ASSERT(strcmp(ozayn_rcm_reservation_state_name(OZAYN_RCM_RESERV_RESERVED), "Reserved") == 0);
    ASSERT(strcmp(ozayn_rcm_reservation_state_name(OZAYN_RCM_RESERV_ACTIVE), "Active") == 0);
    ASSERT(strcmp(ozayn_rcm_reservation_state_name((ozayn_rcm_reservation_state_t)99), "Invalid") == 0);
    return 0;
}

TEST(test_rcm_priority_name)
{
    ASSERT(strcmp(ozayn_rcm_priority_name(OZAYN_RCM_PRIORITY_LOW), "Low") == 0);
    ASSERT(strcmp(ozayn_rcm_priority_name(OZAYN_RCM_PRIORITY_CRITICAL), "Critical") == 0);
    ASSERT(strcmp(ozayn_rcm_priority_name((ozayn_rcm_priority_t)99), "Invalid") == 0);
    return 0;
}

TEST(test_rcm_event_type_name)
{
    ASSERT(strcmp(ozayn_rcm_event_type_name(OZAYN_RCM_EVENT_RESOURCE_REGISTERED), "ResourceRegistered") == 0);
    ASSERT(strcmp(ozayn_rcm_event_type_name(OZAYN_RCM_EVENT_CAPACITY_CHANGED), "CapacityChanged") == 0);
    ASSERT(strcmp(ozayn_rcm_event_type_name((ozayn_rcm_event_type_t)99), "Invalid") == 0);
    return 0;
}

TEST(test_rcm_err_name)
{
    ASSERT(strcmp(ozayn_rcm_err_name(OZAYN_RCM_OK), "OK") == 0);
    ASSERT(strcmp(ozayn_rcm_err_name(OZAYN_RCM_ERR_NULL), "Null") == 0);
    ASSERT(strcmp(ozayn_rcm_err_name(OZAYN_RCM_ERR_NOT_INITIALIZED), "NotInitialized") == 0);
    ASSERT(strcmp(ozayn_rcm_err_name(OZAYN_RCM_ERR_INVALID_PARAM), "InvalidParam") == 0);
    ASSERT(strcmp(ozayn_rcm_err_name(OZAYN_RCM_ERR_LIMIT_REACHED), "LimitReached") == 0);
    ASSERT(strcmp(ozayn_rcm_err_name(OZAYN_RCM_ERR_NOT_FOUND), "NotFound") == 0);
    ASSERT(strcmp(ozayn_rcm_err_name(OZAYN_RCM_ERR_DUPLICATE), "Duplicate") == 0);
    return 0;
}

/* ============================================================
 * DEVICE RESOURCE TESTS
 * ============================================================ */

TEST(test_rcm_device_resources)
{
    _init_svc();
    ozayn_rcm_resource_desc_t *cam = NULL, *mic = NULL, *audio = NULL;
    ozayn_rcm_resource_register(&_svc, OZAYN_RCM_RES_CAMERA, "Camera", NULL, NULL, 0, &cam);
    ozayn_rcm_resource_register(&_svc, OZAYN_RCM_RES_MICROPHONE, "Mic", NULL, NULL, 0, &mic);
    ozayn_rcm_resource_register(&_svc, OZAYN_RCM_RES_AUDIO, "Speaker", NULL, NULL, 0, &audio);
    ASSERT(cam);
    ASSERT(mic);
    ASSERT(audio);
    ASSERT_EQ(cam->state, OZAYN_RCM_STATE_AVAILABLE);
    ASSERT_EQ(mic->state, OZAYN_RCM_STATE_AVAILABLE);
    ASSERT_EQ(audio->state, OZAYN_RCM_STATE_AVAILABLE);
    ozayn_rcm_service_shutdown(&_svc);
    return 0;
}

TEST(test_rcm_device_unsupported)
{
    _init_svc();
    ozayn_rcm_resource_desc_t *cam = NULL;
    ozayn_rcm_resource_register(&_svc, OZAYN_RCM_RES_CAMERA, "Camera", NULL, NULL, 0, &cam);
    ozayn_rcm_resource_update_state(&_svc, cam->resource_id, OZAYN_RCM_STATE_UNSUPPORTED);
    ASSERT_EQ(cam->state, OZAYN_RCM_STATE_UNSUPPORTED);
    int sufficient = 0;
    ozayn_rcm_capacity_check(&_svc, cam->resource_id, 1, &sufficient);
    ASSERT(!sufficient);
    ozayn_rcm_service_shutdown(&_svc);
    return 0;
}

/* ============================================================
 * NETWORK RESOURCE TESTS
 * ============================================================ */

TEST(test_rcm_network_resource)
{
    _init_svc();
    ozayn_rcm_resource_desc_t *net = NULL;
    ozayn_rcm_resource_register(&_svc, OZAYN_RCM_RES_NETWORK, "WiFi", NULL, NULL, 1, &net);
    ASSERT_NOT_NULL(net);
    ASSERT_EQ(net->state, OZAYN_RCM_STATE_AVAILABLE);
    ozayn_rcm_resource_update_state(&_svc, net->resource_id, OZAYN_RCM_STATE_UNAVAILABLE);
    int sufficient = 0;
    ozayn_rcm_capacity_check(&_svc, net->resource_id, 1, &sufficient);
    ASSERT(!sufficient);
    ozayn_rcm_service_shutdown(&_svc);
    return 0;
}

/* ============================================================
 * GPU RESOURCE TESTS
 * ============================================================ */

TEST(test_rcm_gpu_resource)
{
    _init_svc();
    ozayn_rcm_resource_desc_t *gpu = NULL;
    ozayn_rcm_resource_register(&_svc, OZAYN_RCM_RES_GPU, "NVIDIA", "nvidia", "cores", 5120, &gpu);
    ASSERT_NOT_NULL(gpu);
    ASSERT_EQ(gpu->capacity.total, 5120);
    ASSERT_EQ(gpu->state, OZAYN_RCM_STATE_AVAILABLE);
    ozayn_rcm_service_shutdown(&_svc);
    return 0;
}

/* ============================================================
 * CONFLICT DETECTION TESTS
 * ============================================================ */

TEST(test_rcm_reservation_conflict)
{
    _init_svc();
    ozayn_rcm_resource_desc_t *res = NULL;
    ozayn_rcm_resource_register(&_svc, OZAYN_RCM_RES_MEMORY, "RAM", NULL, NULL, 16, &res);

    ozayn_rcm_resource_requirement_t *req = NULL;
    ozayn_rcm_requirement_create(&_svc, OZAYN_RCM_RES_MEMORY,
        res->resource_id, 12, 0, OZAYN_RCM_AVAIL_UNKNOWN, 1,
        OZAYN_RCM_PRIORITY_NORMAL, 30000, &req);

    ozayn_rcm_reservation_t *r1 = NULL;
    ozayn_rcm_reservation_create(&_svc, "OP-1", res->resource_id,
        OZAYN_RCM_RES_MEMORY, 8, &r1);

    ozayn_rcm_resource_decision_t *dec = NULL;
    ozayn_rcm_evaluate(&_svc, "OP-2", req, 1, &dec);
    ASSERT_EQ(dec->decision, OZAYN_RCM_DECISION_CONFLICT);
    ozayn_rcm_service_shutdown(&_svc);
    return 0;
}

/* ============================================================
 * CAPACITY COMPUTATION TESTS
 * ============================================================ */

TEST(test_rcm_capacity_computation)
{
    _init_svc();
    ozayn_rcm_resource_desc_t *res = NULL;
    ozayn_rcm_resource_register(&_svc, OZAYN_RCM_RES_MEMORY, "RAM", NULL, NULL, 16, &res);

    ozayn_rcm_capacity_t cap;
    ozayn_rcm_capacity_get(&_svc, res->resource_id, &cap);
    ASSERT_EQ(cap.total, 16);
    ASSERT_EQ(cap.available, 16);

    ozayn_rcm_resource_update_usage(&_svc, res->resource_id, 6);
    ozayn_rcm_capacity_get(&_svc, res->resource_id, &cap);
    ASSERT_EQ(cap.available, 10);

    ozayn_rcm_reservation_t *resv = NULL;
    ozayn_rcm_reservation_create(&_svc, "OP-1", res->resource_id,
        OZAYN_RCM_RES_MEMORY, 4, &resv);
    ozayn_rcm_capacity_get(&_svc, res->resource_id, &cap);
    ASSERT_EQ(cap.available, 6);
    ozayn_rcm_service_shutdown(&_svc);
    return 0;
}

/* ============================================================
 * SECURITY TESTS
 * ============================================================ */

TEST(test_rcm_no_secrets_in_resource)
{
    _init_svc();
    ozayn_rcm_resource_desc_t *res = NULL;
    ozayn_rcm_resource_register(&_svc, OZAYN_RCM_RES_CPU, "CPU", NULL, NULL, 8, &res);
    ASSERT(res->metadata[0] == '\0');
    ozayn_rcm_service_shutdown(&_svc);
    return 0;
}

TEST(test_rcm_no_secrets_in_decision)
{
    _init_svc();
    ozayn_rcm_resource_desc_t *res = NULL;
    ozayn_rcm_resource_register(&_svc, OZAYN_RCM_RES_MEMORY, "RAM", NULL, NULL, 16, &res);

    ozayn_rcm_resource_requirement_t *req = NULL;
    ozayn_rcm_requirement_create(&_svc, OZAYN_RCM_RES_MEMORY,
        res->resource_id, 4, 0, OZAYN_RCM_AVAIL_UNKNOWN, 0,
        OZAYN_RCM_PRIORITY_NORMAL, 30000, &req);

    ozayn_rcm_resource_decision_t *dec = NULL;
    ozayn_rcm_evaluate(&_svc, "OP-1", req, 1, &dec);
    ASSERT(dec->metadata[0] == '\0');
    ozayn_rcm_service_shutdown(&_svc);
    return 0;
}

/* ============================================================
 * QUEUE INTEGRATION TESTS (simulated)
 * ============================================================ */

TEST(test_rcm_queue_capacity_resource)
{
    _init_svc();
    ozayn_rcm_resource_desc_t *res = NULL;
    ozayn_rcm_resource_register(&_svc, OZAYN_RCM_RES_QUEUE_CAPACITY, "OpQueue",
        "control-room", "slots", 64, &res);
    ASSERT_NOT_NULL(res);
    ASSERT_EQ(res->capacity.total, 64);
    ASSERT_EQ(res->capacity.available, 64);
    ozayn_rcm_resource_update_usage(&_svc, res->resource_id, 32);
    ASSERT_EQ(res->capacity.available, 32);
    ozayn_rcm_service_shutdown(&_svc);
    return 0;
}

TEST(test_rcm_worker_capacity_resource)
{
    _init_svc();
    ozayn_rcm_resource_desc_t *res = NULL;
    ozayn_rcm_resource_register(&_svc, OZAYN_RCM_RES_WORKER_CAPACITY, "Workers",
        "control-room", "slots", 8, &res);
    ASSERT_NOT_NULL(res);
    ASSERT_EQ(res->capacity.total, 8);
    ozayn_rcm_service_shutdown(&_svc);
    return 0;
}

/* ============================================================
 * FULL LIFECYCLE TEST
 * ============================================================ */

TEST(test_rcm_full_lifecycle)
{
    _init_svc();

    ozayn_rcm_resource_desc_t *cpu = NULL, *mem = NULL;
    ozayn_rcm_resource_register(&_svc, OZAYN_RCM_RES_CPU, "CPU", "platform", "cores", 8, &cpu);
    ozayn_rcm_resource_register(&_svc, OZAYN_RCM_RES_MEMORY, "RAM", "platform", "GB", 16, &mem);

    ozayn_rcm_resource_requirement_t *req1 = NULL, *req2 = NULL;
    ozayn_rcm_requirement_create(&_svc, OZAYN_RCM_RES_CPU,
        cpu->resource_id, 2, 0, OZAYN_RCM_AVAIL_AVAILABLE, 0,
        OZAYN_RCM_PRIORITY_NORMAL, 30000, &req1);
    ozayn_rcm_requirement_create(&_svc, OZAYN_RCM_RES_MEMORY,
        mem->resource_id, 4, 0, OZAYN_RCM_AVAIL_AVAILABLE, 0,
        OZAYN_RCM_PRIORITY_NORMAL, 30000, &req2);

    ozayn_rcm_resource_decision_t *dec = NULL;
    ozayn_rcm_resource_requirement_t reqs[2];
    reqs[0] = *req1;
    reqs[1] = *req2;
    ASSERT_EQ(ozayn_rcm_evaluate(&_svc, "OP-LIFECYCLE", reqs, 2, &dec), OZAYN_RCM_OK);
    ASSERT_EQ(dec->decision, OZAYN_RCM_DECISION_AVAILABLE);
    ASSERT(ozayn_rcm_decision_is_valid(&_svc, dec->decision_id));

    ozayn_rcm_reservation_t *resv = NULL;
    ASSERT_EQ(ozayn_rcm_reservation_create(&_svc, "OP-LIFECYCLE", mem->resource_id,
        OZAYN_RCM_RES_MEMORY, 4, &resv), OZAYN_RCM_OK);
    ASSERT_EQ(ozayn_rcm_reservation_activate(&_svc, resv->reservation_id), OZAYN_RCM_OK);

    ASSERT_EQ(ozayn_rcm_recheck(&_svc, dec->decision_id), OZAYN_RCM_OK);
    ASSERT_EQ(dec->decision, OZAYN_RCM_DECISION_AVAILABLE);

    ASSERT_EQ(ozayn_rcm_reservation_release(&_svc, resv->reservation_id), OZAYN_RCM_OK);

    ozayn_rcm_snapshot_t *snap = NULL;
    ASSERT_EQ(ozayn_rcm_snapshot_create(&_svc, &snap), OZAYN_RCM_OK);
    ASSERT_EQ(snap->resource_count, 2);

    ozayn_rcm_stats_t stats;
    ozayn_rcm_get_stats(&_svc, &stats);
    ASSERT_EQ(stats.total_resources_registered, 2);
    ASSERT_EQ(stats.total_decisions, 1);

    ozayn_rcm_service_shutdown(&_svc);
    return 0;
}

/* ============================================================
 * TEST RUNNER
 * ============================================================ */

int run_cr_resource_tests(void)
{
    SUITE_BEGIN("Resource & Capacity Management");

    RUN(test_rcm_init);
    RUN(test_rcm_init_null);
    RUN(test_rcm_init_double);
    RUN(test_rcm_init_custom_config);
    RUN(test_rcm_shutdown);
    RUN(test_rcm_shutdown_null);
    RUN(test_rcm_is_initialized);
    RUN(test_rcm_global_singleton);

    RUN(test_rcm_resource_register);
    RUN(test_rcm_resource_register_null);
    RUN(test_rcm_resource_register_not_init);
    RUN(test_rcm_resource_register_invalid_type);
    RUN(test_rcm_resource_register_empty_name);
    RUN(test_rcm_resource_register_null_out);
    RUN(test_rcm_resource_register_duplicate);
    RUN(test_rcm_resource_register_limit);
    RUN(test_rcm_resource_unregister);
    RUN(test_rcm_resource_unregister_not_found);
    RUN(test_rcm_resource_get);
    RUN(test_rcm_resource_get_by_type);
    RUN(test_rcm_resource_count);
    RUN(test_rcm_resource_full);

    RUN(test_rcm_resource_update_usage);
    RUN(test_rcm_resource_update_usage_overflow);
    RUN(test_rcm_resource_update_state);
    RUN(test_rcm_resource_update_health);
    RUN(test_rcm_resource_update_availability);
    RUN(test_rcm_resource_update_not_found);

    RUN(test_rcm_capacity_get);
    RUN(test_rcm_capacity_check_sufficient);
    RUN(test_rcm_capacity_check_insufficient);
    RUN(test_rcm_capacity_check_unavailable);
    RUN(test_rcm_capacity_check_zero);
    RUN(test_rcm_capacity_check_all);

    RUN(test_rcm_requirement_create);
    RUN(test_rcm_requirement_create_null);
    RUN(test_rcm_requirement_create_invalid_type);
    RUN(test_rcm_requirement_create_null_out);

    RUN(test_rcm_evaluate_available);
    RUN(test_rcm_evaluate_insufficient);
    RUN(test_rcm_evaluate_unknown_resource);
    RUN(test_rcm_evaluate_unavailable);
    RUN(test_rcm_evaluate_null);
    RUN(test_rcm_evaluate_not_init);
    RUN(test_rcm_decision_get);
    RUN(test_rcm_decision_get_by_operation);
    RUN(test_rcm_decision_count);
    RUN(test_rcm_decision_is_valid);

    RUN(test_rcm_recheck);
    RUN(test_rcm_recheck_not_found);
    RUN(test_rcm_recheck_capacity_reduced);
    RUN(test_rcm_recheck_null);
    RUN(test_rcm_recheck_not_init);

    RUN(test_rcm_reservation_create);
    RUN(test_rcm_reservation_create_insufficient);
    RUN(test_rcm_reservation_create_duplicate);
    RUN(test_rcm_reservation_activate);
    RUN(test_rcm_reservation_release);
    RUN(test_rcm_reservation_cancel);
    RUN(test_rcm_reservation_get);
    RUN(test_rcm_reservation_count);
    RUN(test_rcm_reservation_count_by_resource);
    RUN(test_rcm_reservation_release_not_found);
    RUN(test_rcm_reservation_cancel_not_found);

    RUN(test_rcm_snapshot_create);
    RUN(test_rcm_snapshot_get);
    RUN(test_rcm_snapshot_count);
    RUN(test_rcm_snapshot_overall_degraded);

    RUN(test_rcm_cleanup_expired_reservations);
    RUN(test_rcm_cleanup_expired_decisions);
    RUN(test_rcm_cleanup_all);
    RUN(test_rcm_cleanup_null);

    RUN(test_rcm_health_healthy);
    RUN(test_rcm_health_degraded);
    RUN(test_rcm_health_unknown);

    RUN(test_rcm_get_stats);
    RUN(test_rcm_stats_evaluations);

    RUN(test_rcm_resource_validate);
    RUN(test_rcm_capacity_validate);
    RUN(test_rcm_decision_validate);
    RUN(test_rcm_reservation_validate);
    RUN(test_rcm_requirement_validate);

    RUN(test_rcm_resource_type_name);
    RUN(test_rcm_resource_state_name);
    RUN(test_rcm_resource_health_name);
    RUN(test_rcm_availability_name);
    RUN(test_rcm_decision_name);
    RUN(test_rcm_reservation_state_name);
    RUN(test_rcm_priority_name);
    RUN(test_rcm_event_type_name);
    RUN(test_rcm_err_name);

    RUN(test_rcm_device_resources);
    RUN(test_rcm_device_unsupported);
    RUN(test_rcm_network_resource);
    RUN(test_rcm_gpu_resource);
    RUN(test_rcm_reservation_conflict);
    RUN(test_rcm_capacity_computation);
    RUN(test_rcm_no_secrets_in_resource);
    RUN(test_rcm_no_secrets_in_decision);
    RUN(test_rcm_queue_capacity_resource);
    RUN(test_rcm_worker_capacity_resource);
    RUN(test_rcm_full_lifecycle);

    SUITE_END();
    return TOTAL_FAIL();
}
