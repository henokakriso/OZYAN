/*
 * test_operational_status.c — Section 04, Step 29
 * Control Room Integration & Operational Status Consolidation
 */

#include "../../tests/test_framework.h"
#include "../operational_status.h"
#include "../control_room.h"
#include "../operational_readiness.h"
#include "../diagnostics.h"
#include "../operational_metrics.h"
#include "../operational_alert.h"
#include "../../include/runtime.h"
#include "../../include/modules.h"
#include "../../include/tasks.h"
#include "../../include/processes.h"

#include <string.h>

/* ============================================================
 * TEST FIXTURE
 * ============================================================ */

static ozayn_ost_service_t _ost;
static ozayn_cr_service_t _cr;
static ozayn_ord_service_t _ord;
static ozayn_dha_service_t _dha;
static ozayn_om_service_t _om;
static ozayn_oan_service_t _oan;
static ozayn_runtime_t _rt;
static ozayn_module_manager_t _modules;
static ozayn_task_manager_t _tasks;
static ozayn_process_manager_t _processes;

typedef struct {
    int fail;
    int calls;
    ozayn_ost_state_t state;
} _test_provider_ctx_t;

static void _reset_all(void) {
    memset(&_ost, 0, sizeof(_ost));
    memset(&_cr, 0, sizeof(_cr));
    memset(&_ord, 0, sizeof(_ord));
    memset(&_dha, 0, sizeof(_dha));
    memset(&_om, 0, sizeof(_om));
    memset(&_oan, 0, sizeof(_oan));
    memset(&_rt, 0, sizeof(_rt));
    memset(&_modules, 0, sizeof(_modules));
    memset(&_tasks, 0, sizeof(_tasks));
    memset(&_processes, 0, sizeof(_processes));
}

static void _init_runtime(void) {
    _rt.state = OZAYN_STATE_RUNNING;
}

static void _init_control_room(void) {
    ozayn_cr_service_init(&_cr, NULL);
    _cr.lifecycle = OZAYN_CR_LC_READY;
    _cr.core_state = OZAYN_CR_CORE_STATE_ONLINE;
}

static void _init_core_managers(void) {
    ozayn_module_manager_init(&_modules);
    ozayn_task_manager_init(&_tasks);
    ozayn_process_manager_init(&_processes);
}

static void _init_optional_services(void) {
    ozayn_ord_service_init(&_ord, NULL);
    _ord.current_mode = OZAYN_ORD_MODE_READY;
    ozayn_dha_service_init(&_dha, NULL);
    ozayn_om_init(&_om);
    ozayn_oan_init(&_oan);
    memset(&_ost, 0, sizeof(_ost));
}

static void _config_full(ozayn_ost_config_t *cfg) {
    memset(cfg, 0, sizeof(*cfg));
    cfg->runtime = &_rt;
    cfg->module_manager = &_modules;
    cfg->task_manager = &_tasks;
    cfg->process_manager = &_processes;
    cfg->control_room = &_cr;
    cfg->operational_readiness = &_ord;
    cfg->diagnostics = &_dha;
    cfg->operational_metrics = &_om;
    cfg->operational_alert = &_oan;
}

static void _init_full(void) {
    _reset_all();
    _init_runtime();
    _init_control_room();
    _init_core_managers();
    _init_optional_services();

    ozayn_ost_config_t cfg;
    _config_full(&cfg);
    ozayn_ost_init(&_ost, &cfg);
}

static void _init_required_only(void) {
    _reset_all();
    _init_runtime();
    _init_control_room();

    ozayn_ost_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.runtime = &_rt;
    cfg.control_room = &_cr;
    ozayn_ost_init(&_ost, &cfg);
}

static void _shutdown_full(void) {
    ozayn_ost_shutdown(&_ost);
    ozayn_cr_service_shutdown(&_cr);
    ozayn_ord_service_shutdown(&_ord);
    ozayn_dha_service_shutdown(&_dha);
    ozayn_om_shutdown(&_om);
    ozayn_oan_shutdown(&_oan);
    ozayn_module_manager_shutdown(&_modules);
    ozayn_task_manager_shutdown(&_tasks);
    ozayn_process_manager_shutdown(&_processes);
    _reset_all();
}

static ozayn_ost_state_t _component_state(const char *id) {
    ozayn_ost_component_status_t status;
    if (ozayn_ost_get_component(&_ost, id, &status) != OZAYN_OST_OK) {
        return OZAYN_OST_STATE_UNKNOWN;
    }
    return status.state;
}

static int _provider_ok(void *ctx, ozayn_ost_reading_t *r) {
    _test_provider_ctx_t *p = (_test_provider_ctx_t *)ctx;
    p->calls++;
    if (p->fail) return 1;
    r->state = p->state;
    snprintf(r->detail, sizeof(r->detail), "custom provider ok");
    return 0;
}

typedef struct {
    ozayn_ost_service_t *svc;
    int nested_rc;
} _reentrant_ctx_t;

static int _provider_reentrant(void *ctx, ozayn_ost_reading_t *r) {
    _reentrant_ctx_t *p = (_reentrant_ctx_t *)ctx;
    p->nested_rc = ozayn_ost_refresh(p->svc);
    r->state = OZAYN_OST_STATE_OPERATIONAL;
    snprintf(r->detail, sizeof(r->detail), "reentrant provider ok");
    return 0;
}

/* ============================================================
 * NAME HELPERS
 * ============================================================ */

TEST(test_ost_err_name) {
    ASSERT_STR_EQ(ozayn_ost_err_name(OZAYN_OST_OK), "OK");
    ASSERT_STR_EQ(ozayn_ost_err_name(OZAYN_OST_ERR_NULL), "NULL");
    ASSERT_STR_EQ(ozayn_ost_err_name(OZAYN_OST_ERR_CONCURRENCY), "CONCURRENCY");
    ASSERT_STR_EQ(ozayn_ost_err_name(OZAYN_OST_ERR_REFRESH_PARTIAL), "REFRESH_PARTIAL");
    return 0;
}

TEST(test_ost_state_name) {
    ASSERT_STR_EQ(ozayn_ost_state_name(OZAYN_OST_STATE_UNKNOWN), "UNKNOWN");
    ASSERT_STR_EQ(ozayn_ost_state_name(OZAYN_OST_STATE_INITIALIZING), "INITIALIZING");
    ASSERT_STR_EQ(ozayn_ost_state_name(OZAYN_OST_STATE_OPERATIONAL), "OPERATIONAL");
    ASSERT_STR_EQ(ozayn_ost_state_name(OZAYN_OST_STATE_DEGRADED), "DEGRADED");
    ASSERT_STR_EQ(ozayn_ost_state_name(OZAYN_OST_STATE_UNAVAILABLE), "UNAVAILABLE");
    ASSERT_STR_EQ(ozayn_ost_state_name(OZAYN_OST_STATE_ERROR), "ERROR");
    return 0;
}

TEST(test_ost_refresh_result_name) {
    ASSERT_STR_EQ(ozayn_ost_refresh_result_name(OZAYN_OST_REFRESH_NONE), "NONE");
    ASSERT_STR_EQ(ozayn_ost_refresh_result_name(OZAYN_OST_REFRESH_OK), "OK");
    ASSERT_STR_EQ(ozayn_ost_refresh_result_name(OZAYN_OST_REFRESH_PARTIAL), "PARTIAL");
    ASSERT_STR_EQ(ozayn_ost_refresh_result_name(OZAYN_OST_REFRESH_FAILED), "FAILED");
    return 0;
}

/* ============================================================
 * LIFECYCLE
 * ============================================================ */

TEST(test_ost_init_null) {
    ASSERT_EQ(ozayn_ost_init(NULL, NULL), OZAYN_OST_ERR_NULL);
    return 0;
}

TEST(test_ost_init_requires_config) {
    ozayn_ost_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ASSERT_EQ(ozayn_ost_init(&svc, NULL), OZAYN_OST_ERR_INVALID_PARAM);
    ASSERT_EQ(ozayn_ost_is_initialized(&svc), 0);
    return 0;
}

TEST(test_ost_init_and_shutdown) {
    _init_full();
    ASSERT(ozayn_ost_is_initialized(&_ost));
    ASSERT_EQ(ozayn_ost_component_count(&_ost), 10);
    ASSERT_EQ(ozayn_ost_shutdown(&_ost), OZAYN_OST_OK);
    ASSERT_EQ(ozayn_ost_is_initialized(&_ost), 0);
    _shutdown_full();
    return 0;
}

TEST(test_ost_init_double) {
    _init_full();
    ozayn_ost_config_t cfg;
    _config_full(&cfg);
    ASSERT_EQ(ozayn_ost_init(&_ost, &cfg), OZAYN_OST_ERR_ALREADY_INITIALIZED);
    _shutdown_full();
    return 0;
}

TEST(test_ost_refresh_not_initialized) {
    _reset_all();
    ASSERT_EQ(ozayn_ost_refresh(&_ost), OZAYN_OST_ERR_NOT_INITIALIZED);
    return 0;
}

/* ============================================================
 * INITIAL STATE
 * ============================================================ */

TEST(test_ost_initial_state_unknown) {
    _init_full();

    ASSERT_EQ(ozayn_ost_overall_state(&_ost), OZAYN_OST_STATE_UNKNOWN);
    ASSERT_EQ(_ost.refresh_count, 0);
    ASSERT_EQ(_ost.generation, 0);
    ASSERT_EQ(_component_state(OZAYN_OST_ID_RUNTIME), OZAYN_OST_STATE_UNAVAILABLE);
    ASSERT_EQ(_component_state(OZAYN_OST_ID_METRICS), OZAYN_OST_STATE_UNKNOWN);

    _shutdown_full();
    return 0;
}

/* ============================================================
 * SUCCESSFUL REFRESH
 * ============================================================ */

TEST(test_ost_refresh_success_all_operational) {
    _init_full();

    ASSERT_EQ(ozayn_ost_refresh(&_ost), OZAYN_OST_OK);
    ASSERT_EQ(ozayn_ost_overall_state(&_ost), OZAYN_OST_STATE_OPERATIONAL);

    ASSERT_EQ(_component_state(OZAYN_OST_ID_RUNTIME), OZAYN_OST_STATE_OPERATIONAL);
    ASSERT_EQ(_component_state(OZAYN_OST_ID_MODULES), OZAYN_OST_STATE_OPERATIONAL);
    ASSERT_EQ(_component_state(OZAYN_OST_ID_TASKS), OZAYN_OST_STATE_OPERATIONAL);
    ASSERT_EQ(_component_state(OZAYN_OST_ID_PROCESSES), OZAYN_OST_STATE_OPERATIONAL);
    ASSERT_EQ(_component_state(OZAYN_OST_ID_CONTROL_ROOM), OZAYN_OST_STATE_OPERATIONAL);
    ASSERT_EQ(_component_state(OZAYN_OST_ID_READINESS), OZAYN_OST_STATE_OPERATIONAL);
    ASSERT_EQ(_component_state(OZAYN_OST_ID_DIAGNOSTICS), OZAYN_OST_STATE_OPERATIONAL);
    ASSERT_EQ(_component_state(OZAYN_OST_ID_METRICS), OZAYN_OST_STATE_OPERATIONAL);
    ASSERT_EQ(_component_state(OZAYN_OST_ID_ALERTS), OZAYN_OST_STATE_OPERATIONAL);

    ASSERT_EQ(_ost.refresh_count, 1);
    ASSERT_EQ(_ost.generation, 1);
    ASSERT(_ost.last_refresh_ms > 0);
    ASSERT(_ost.last_successful_refresh_ms > 0);
    ASSERT_EQ(_ost.refresh_result, OZAYN_OST_REFRESH_OK);
    ASSERT_EQ(_ost.warning_count, 0);

    _shutdown_full();
    return 0;
}

TEST(test_ost_refresh_missing_optional_stays_operational) {
    _init_required_only();

    ASSERT_EQ(ozayn_ost_refresh(&_ost), OZAYN_OST_OK);
    ASSERT_EQ(ozayn_ost_overall_state(&_ost), OZAYN_OST_STATE_OPERATIONAL);
    ASSERT_EQ(_component_state(OZAYN_OST_ID_METRICS), OZAYN_OST_STATE_UNKNOWN);
    ASSERT_EQ(_component_state(OZAYN_OST_ID_ALERTS), OZAYN_OST_STATE_UNKNOWN);

    _shutdown_full();
    return 0;
}

TEST(test_ost_refresh_missing_required_unavailable) {
    _reset_all();
    _init_control_room();

    ozayn_ost_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.control_room = &_cr;
    ozayn_ost_init(&_ost, &cfg);

    ASSERT_EQ(ozayn_ost_refresh(&_ost), OZAYN_OST_OK);
    ASSERT_EQ(_component_state(OZAYN_OST_ID_RUNTIME), OZAYN_OST_STATE_UNAVAILABLE);
    ASSERT_EQ(ozayn_ost_overall_state(&_ost), OZAYN_OST_STATE_UNAVAILABLE);

    _shutdown_full();
    return 0;
}

/* ============================================================
 * DEGRADED / ERROR / INITIALIZING
 * ============================================================ */

TEST(test_ost_refresh_degraded_readiness) {
    _init_full();
    _ord.current_mode = OZAYN_ORD_MODE_READY_DEGRADED;

    ASSERT_EQ(ozayn_ost_refresh(&_ost), OZAYN_OST_OK);
    ASSERT_EQ(_component_state(OZAYN_OST_ID_READINESS), OZAYN_OST_STATE_DEGRADED);
    ASSERT_EQ(ozayn_ost_overall_state(&_ost), OZAYN_OST_STATE_DEGRADED);

    _shutdown_full();
    return 0;
}

TEST(test_ost_refresh_control_room_error) {
    _init_full();
    ozayn_cr_set_error(&_cr);

    ASSERT_EQ(ozayn_ost_refresh(&_ost), OZAYN_OST_OK);
    ASSERT_EQ(_component_state(OZAYN_OST_ID_CONTROL_ROOM), OZAYN_OST_STATE_ERROR);
    ASSERT_EQ(ozayn_ost_overall_state(&_ost), OZAYN_OST_STATE_ERROR);

    _shutdown_full();
    return 0;
}

TEST(test_ost_refresh_runtime_initializing) {
    _init_full();
    _rt.state = OZAYN_STATE_INITIALIZING;

    ASSERT_EQ(ozayn_ost_refresh(&_ost), OZAYN_OST_OK);
    ASSERT_EQ(_component_state(OZAYN_OST_ID_RUNTIME), OZAYN_OST_STATE_INITIALIZING);
    ASSERT_EQ(ozayn_ost_overall_state(&_ost), OZAYN_OST_STATE_INITIALIZING);

    _shutdown_full();
    return 0;
}

TEST(test_ost_optional_error_degrades) {
    _init_required_only();
    _test_provider_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.state = OZAYN_OST_STATE_ERROR;

    ASSERT_EQ(ozayn_ost_register_component(&_ost, "custom.optional", "Optional",
                                           0, _provider_ok, &ctx),
              OZAYN_OST_OK);
    ASSERT_EQ(ozayn_ost_refresh(&_ost), OZAYN_OST_OK);
    ASSERT_EQ(ozayn_ost_overall_state(&_ost), OZAYN_OST_STATE_DEGRADED);

    _shutdown_full();
    return 0;
}

/* ============================================================
 * REFRESH FAILURE PRESERVES LAST VALID STATUS
 * ============================================================ */

TEST(test_ost_failed_refresh_preserves_last_valid_state) {
    _init_required_only();
    _test_provider_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.state = OZAYN_OST_STATE_OPERATIONAL;

    ASSERT_EQ(ozayn_ost_register_component(&_ost, "custom.required", "Required",
                                           1, _provider_ok, &ctx),
              OZAYN_OST_OK);

    ASSERT_EQ(ozayn_ost_refresh(&_ost), OZAYN_OST_OK);
    ASSERT_EQ(ozayn_ost_overall_state(&_ost), OZAYN_OST_STATE_OPERATIONAL);

    int64_t last_success = _ost.last_successful_refresh_ms;
    uint64_t generation = _ost.generation;

    ctx.fail = 1;
    ASSERT_EQ(ozayn_ost_refresh(&_ost), OZAYN_OST_ERR_REFRESH_PARTIAL);

    ozayn_ost_component_status_t status;
    ASSERT_EQ(ozayn_ost_get_component(&_ost, "custom.required", &status),
              OZAYN_OST_OK);
    ASSERT_EQ(status.state, OZAYN_OST_STATE_OPERATIONAL);
    ASSERT_EQ(status.refresh_failures, 1);
    ASSERT_EQ(status.last_refresh_ok, 0);
    ASSERT(status.last_success_ms > 0);

    ASSERT_EQ(ozayn_ost_overall_state(&_ost), OZAYN_OST_STATE_OPERATIONAL);
    ASSERT(_ost.last_successful_refresh_ms == last_success);
    ASSERT_EQ(_ost.partial_refresh_count, 1);
    ASSERT(_ost.generation > generation);

    _shutdown_full();
    return 0;
}

TEST(test_ost_failed_refresh_returns_failed_when_all_fail) {
    _reset_all();
    _test_provider_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.fail = 1;

    ozayn_ost_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    ozayn_ost_init(&_ost, &cfg);
    ASSERT_EQ(ozayn_ost_register_component(&_ost, "custom.fail", "Fail",
                                           1, _provider_ok, &ctx),
              OZAYN_OST_OK);

    ASSERT_EQ(ozayn_ost_refresh(&_ost), OZAYN_OST_ERR_REFRESH_FAILED);
    ASSERT_EQ(_ost.failed_refresh_count, 1);
    ASSERT_EQ(_ost.refresh_result, OZAYN_OST_REFRESH_FAILED);
    ASSERT_EQ(_component_state("custom.fail"), OZAYN_OST_STATE_UNKNOWN);

    _shutdown_full();
    return 0;
}

TEST(test_ost_repeated_refresh_is_bounded) {
    _init_full();

    for (int i = 0; i < 5; i++) {
        ASSERT_EQ(ozayn_ost_refresh(&_ost), OZAYN_OST_OK);
    }

    ASSERT_EQ(ozayn_ost_component_count(&_ost), 10);
    ASSERT_EQ(_ost.refresh_count, 5);
    ASSERT_EQ(_ost.generation, 5);
    ASSERT_EQ(ozayn_ost_overall_state(&_ost), OZAYN_OST_STATE_OPERATIONAL);

    _shutdown_full();
    return 0;
}

/* ============================================================
 * CONCURRENCY GUARD
 * ============================================================ */

TEST(test_ost_reentrant_refresh_rejected) {
    _init_required_only();
    _reentrant_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.svc = &_ost;

    ASSERT_EQ(ozayn_ost_register_component(&_ost, "custom.reentrant", "Reentrant",
                                           1, _provider_reentrant, &ctx),
              OZAYN_OST_OK);

    ASSERT_EQ(ozayn_ost_refresh(&_ost), OZAYN_OST_OK);
    ASSERT_EQ(ctx.nested_rc, OZAYN_OST_ERR_CONCURRENCY);
    ASSERT_EQ(_ost.rejected_refresh_count, 1);
    ASSERT_EQ(ozayn_ost_overall_state(&_ost), OZAYN_OST_STATE_OPERATIONAL);

    _shutdown_full();
    return 0;
}

/* ============================================================
 * IDENTIFIERS / REGISTRATION
 * ============================================================ */

TEST(test_ost_invalid_component_identifiers) {
    _init_full();

    ozayn_ost_component_status_t status;
    ASSERT_EQ(ozayn_ost_get_component(&_ost, "", &status), OZAYN_OST_ERR_NOT_FOUND);
    ASSERT_EQ(ozayn_ost_get_component(&_ost, "missing.component", &status),
              OZAYN_OST_ERR_NOT_FOUND);
    ASSERT_EQ(ozayn_ost_get_component(NULL, OZAYN_OST_ID_RUNTIME, &status),
              OZAYN_OST_ERR_NULL);
    ASSERT_EQ(ozayn_ost_get_component(&_ost, NULL, &status), OZAYN_OST_ERR_NULL);
    ASSERT_EQ(ozayn_ost_get_component(&_ost, OZAYN_OST_ID_RUNTIME, NULL),
              OZAYN_OST_ERR_NULL);

    _shutdown_full();
    return 0;
}

TEST(test_ost_register_validation) {
    _init_full();

    _test_provider_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));

    ASSERT_EQ(ozayn_ost_register_component(&_ost, "", "Empty", 0,
                                           _provider_ok, &ctx),
              OZAYN_OST_ERR_INVALID_PARAM);
    ASSERT_EQ(ozayn_ost_register_component(&_ost,
                                           "1234567890123456789012345678901234567890123456789012345678901234",
                                           "TooLong", 0, _provider_ok, &ctx),
              OZAYN_OST_ERR_INVALID_PARAM);
    ASSERT_EQ(ozayn_ost_register_component(&_ost, "custom.test", "Custom", 0,
                                           NULL, &ctx),
              OZAYN_OST_ERR_NULL);
    ASSERT_EQ(ozayn_ost_register_component(&_ost, OZAYN_OST_ID_RUNTIME,
                                           "Duplicate", 0, _provider_ok, &ctx),
              OZAYN_OST_ERR_DUPLICATE);
    ASSERT_EQ(ozayn_ost_register_component(&_ost, "custom.test", "Custom", 0,
                                           _provider_ok, &ctx),
              OZAYN_OST_OK);
    ASSERT_EQ(ozayn_ost_component_count(&_ost), 11);

    _shutdown_full();
    return 0;
}

TEST(test_ost_component_capacity) {
    _init_required_only();

    _test_provider_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.state = OZAYN_OST_STATE_OPERATIONAL;

    char id[32];
    for (int i = 0; i < 6; i++) {
        snprintf(id, sizeof(id), "custom.%d", i);
        ASSERT_EQ(ozayn_ost_register_component(&_ost, id, "Custom", 0,
                                               _provider_ok, &ctx),
                  OZAYN_OST_OK);
    }

    ASSERT_EQ(ozayn_ost_register_component(&_ost, "custom.overflow", "Overflow",
                                           0, _provider_ok, &ctx),
              OZAYN_OST_ERR_FULL);

    _shutdown_full();
    return 0;
}

/* ============================================================
 * BINDING / SNAPSHOT
 * ============================================================ */

TEST(test_ost_bind_invalidates_stale_status) {
    _init_full();
    ASSERT_EQ(ozayn_ost_refresh(&_ost), OZAYN_OST_OK);
    ASSERT_EQ(ozayn_ost_overall_state(&_ost), OZAYN_OST_STATE_OPERATIONAL);

    ozayn_ost_config_t empty;
    memset(&empty, 0, sizeof(empty));
    ASSERT_EQ(ozayn_ost_bind(&_ost, &empty), OZAYN_OST_OK);
    ASSERT_EQ(ozayn_ost_overall_state(&_ost), OZAYN_OST_STATE_UNKNOWN);
    ASSERT_EQ(_component_state(OZAYN_OST_ID_RUNTIME), OZAYN_OST_STATE_UNAVAILABLE);

    ASSERT_EQ(ozayn_ost_refresh(&_ost), OZAYN_OST_OK);
    ASSERT_EQ(ozayn_ost_overall_state(&_ost), OZAYN_OST_STATE_UNAVAILABLE);

    _shutdown_full();
    return 0;
}

TEST(test_ost_snapshot) {
    _init_full();
    ASSERT_EQ(ozayn_ost_refresh(&_ost), OZAYN_OST_OK);

    ozayn_ost_snapshot_t snapshot;
    ASSERT_EQ(ozayn_ost_get_snapshot(&_ost, &snapshot), OZAYN_OST_OK);
    ASSERT_EQ(snapshot.overall_state, OZAYN_OST_STATE_OPERATIONAL);
    ASSERT_EQ(snapshot.component_count, 10);
    ASSERT_EQ(snapshot.generation, 1);
    ASSERT_EQ(snapshot.refresh_count, 1);
    ASSERT_EQ(snapshot.refresh_result, OZAYN_OST_REFRESH_OK);
    ASSERT(snapshot.refreshed_at_ms > 0);
    ASSERT(snapshot.overall_detail[0] != '\0');
    ASSERT(strcmp(snapshot.components[0].id, OZAYN_OST_ID_RUNTIME) == 0);

    _shutdown_full();
    return 0;
}

TEST(test_ost_warnings_for_unavailable_required) {
    _reset_all();
    _init_control_room();

    ozayn_ost_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.control_room = &_cr;
    ozayn_ost_init(&_ost, &cfg);
    ASSERT_EQ(ozayn_ost_refresh(&_ost), OZAYN_OST_OK);

    ozayn_ost_snapshot_t snapshot;
    ASSERT_EQ(ozayn_ost_get_snapshot(&_ost, &snapshot), OZAYN_OST_OK);
    ASSERT(snapshot.warning_count > 0);
    ASSERT(strstr(snapshot.warnings[0], OZAYN_OST_ID_RUNTIME) != NULL);

    _shutdown_full();
    return 0;
}

TEST(test_ost_query_null_guards) {
    _init_full();

    ozayn_ost_snapshot_t snapshot;
    ASSERT_EQ(ozayn_ost_get_snapshot(NULL, &snapshot), OZAYN_OST_ERR_NULL);
    ASSERT_EQ(ozayn_ost_get_snapshot(&_ost, NULL), OZAYN_OST_ERR_NULL);
    ASSERT_EQ(ozayn_ost_bind(&_ost, NULL), OZAYN_OST_ERR_NULL);
    ASSERT_EQ(ozayn_ost_overall_state(NULL), OZAYN_OST_STATE_UNKNOWN);
    ASSERT_EQ(ozayn_ost_component_count(NULL), 0);

    _shutdown_full();
    return 0;
}

/* ============================================================
 * SUITE
 * ============================================================ */

int run_cr_operational_status_tests(void) {
    int fail = 0;
    SUITE_BEGIN("Section 04 — Step 29: Operational Status Consolidation");

    RUN(test_ost_err_name);
    RUN(test_ost_state_name);
    RUN(test_ost_refresh_result_name);

    RUN(test_ost_init_null);
    RUN(test_ost_init_requires_config);
    RUN(test_ost_init_and_shutdown);
    RUN(test_ost_init_double);
    RUN(test_ost_refresh_not_initialized);

    RUN(test_ost_initial_state_unknown);
    RUN(test_ost_refresh_success_all_operational);
    RUN(test_ost_refresh_missing_optional_stays_operational);
    RUN(test_ost_refresh_missing_required_unavailable);
    RUN(test_ost_refresh_degraded_readiness);
    RUN(test_ost_refresh_control_room_error);
    RUN(test_ost_refresh_runtime_initializing);
    RUN(test_ost_optional_error_degrades);

    RUN(test_ost_failed_refresh_preserves_last_valid_state);
    RUN(test_ost_failed_refresh_returns_failed_when_all_fail);
    RUN(test_ost_repeated_refresh_is_bounded);
    RUN(test_ost_reentrant_refresh_rejected);

    RUN(test_ost_invalid_component_identifiers);
    RUN(test_ost_register_validation);
    RUN(test_ost_component_capacity);

    RUN(test_ost_bind_invalidates_stale_status);
    RUN(test_ost_snapshot);
    RUN(test_ost_warnings_for_unavailable_required);
    RUN(test_ost_query_null_guards);

    SUITE_END();
    return fail;
}
