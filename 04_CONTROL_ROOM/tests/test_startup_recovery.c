/*
 * test_startup_recovery.c — Tests for Startup Recovery Orchestration
 *
 * Step 19/35 — Control Room
 */

#include "../startup_recovery.h"
#include "../../tests/test_framework.h"
#include <string.h>

/* ============================================================
 * STATIC TEST HELPERS
 * ============================================================ */

static ozayn_src_service_t _svc;

static void _init_svc(void) {
    memset(&_svc, 0, sizeof(_svc));
    ozayn_src_service_init(&_svc);
}

static void _shutdown_svc(void) {
    ozayn_src_service_shutdown(&_svc);
}

static int64_t _now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

/* ============================================================
 * LIFECYCLE TESTS
 * ============================================================ */

TEST(test_src_init) {
    _init_svc();
    ASSERT(ozayn_src_is_initialized(&_svc));
    _shutdown_svc();
    return 0;
}

TEST(test_src_init_null) {
    ASSERT_EQ(ozayn_src_service_init(NULL), OZAYN_SRC_ERR_NULL);
    return 0;
}

TEST(test_src_init_double) {
    _init_svc();
    ASSERT_EQ(ozayn_src_service_init(&_svc), OZAYN_SRC_ERR_ALREADY_INITIALIZED);
    _shutdown_svc();
    return 0;
}

TEST(test_src_shutdown) {
    _init_svc();
    ASSERT_EQ(ozayn_src_service_shutdown(&_svc), OZAYN_SRC_OK);
    ASSERT(!ozayn_src_is_initialized(&_svc));
    return 0;
}

TEST(test_src_shutdown_null) {
    ASSERT_EQ(ozayn_src_service_shutdown(NULL), OZAYN_SRC_ERR_NULL);
    return 0;
}

TEST(test_src_shutdown_not_init) {
    ozayn_src_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ASSERT_EQ(ozayn_src_service_shutdown(&svc), OZAYN_SRC_ERR_NOT_INITIALIZED);
    return 0;
}

TEST(test_src_is_initialized_null) {
    ASSERT(!ozayn_src_is_initialized(NULL));
    return 0;
}

TEST(test_src_global) {
    ozayn_src_service_t *g = ozayn_src_get_global();
    ASSERT_NOT_NULL(g);
    return 0;
}

/* ============================================================
 * EXTERNAL DEPENDENCY BINDING TESTS
 * ============================================================ */

TEST(test_src_set_lifecycle) {
    _init_svc();
    int dummy;
    ASSERT_EQ(ozayn_src_set_lifecycle(&_svc, &dummy), OZAYN_SRC_OK);
    _shutdown_svc();
    return 0;
}

TEST(test_src_set_lifecycle_null) {
    ASSERT_EQ(ozayn_src_set_lifecycle(NULL, NULL), OZAYN_SRC_ERR_NULL);
    return 0;
}

TEST(test_src_set_dependency) {
    _init_svc();
    int dummy;
    ASSERT_EQ(ozayn_src_set_dependency(&_svc, &dummy), OZAYN_SRC_OK);
    _shutdown_svc();
    return 0;
}

TEST(test_src_set_component_registry) {
    _init_svc();
    int dummy;
    ASSERT_EQ(ozayn_src_set_component_registry(&_svc, &dummy), OZAYN_SRC_OK);
    _shutdown_svc();
    return 0;
}

TEST(test_src_set_resource_manager) {
    _init_svc();
    int dummy;
    ASSERT_EQ(ozayn_src_set_resource_manager(&_svc, &dummy), OZAYN_SRC_OK);
    _shutdown_svc();
    return 0;
}

TEST(test_src_set_device_session) {
    _init_svc();
    int dummy;
    ASSERT_EQ(ozayn_src_set_device_session(&_svc, &dummy), OZAYN_SRC_OK);
    _shutdown_svc();
    return 0;
}

TEST(test_src_set_safety) {
    _init_svc();
    int dummy;
    ASSERT_EQ(ozayn_src_set_safety(&_svc, &dummy), OZAYN_SRC_OK);
    _shutdown_svc();
    return 0;
}

TEST(test_src_set_diagnostics) {
    _init_svc();
    int dummy;
    ASSERT_EQ(ozayn_src_set_diagnostics(&_svc, &dummy), OZAYN_SRC_OK);
    _shutdown_svc();
    return 0;
}

TEST(test_src_set_workflow_recovery) {
    _init_svc();
    int dummy;
    ASSERT_EQ(ozayn_src_set_workflow_recovery(&_svc, &dummy), OZAYN_SRC_OK);
    _shutdown_svc();
    return 0;
}

TEST(test_src_set_workflow_checkpoint) {
    _init_svc();
    int dummy;
    ASSERT_EQ(ozayn_src_set_workflow_checkpoint(&_svc, &dummy), OZAYN_SRC_OK);
    _shutdown_svc();
    return 0;
}

TEST(test_src_set_state_manager) {
    _init_svc();
    int dummy;
    ASSERT_EQ(ozayn_src_set_state_manager(&_svc, &dummy), OZAYN_SRC_OK);
    _shutdown_svc();
    return 0;
}

TEST(test_src_set_events_engine) {
    _init_svc();
    int dummy;
    ASSERT_EQ(ozayn_src_set_events_engine(&_svc, &dummy), OZAYN_SRC_OK);
    _shutdown_svc();
    return 0;
}

/* ============================================================
 * STARTUP CAUSE DETECTION TESTS
 * ============================================================ */

TEST(test_src_detect_cause) {
    _init_svc();
    ozayn_src_startup_cause_t cause;
    ozayn_src_previous_shutdown_t shutdown;
    ASSERT_EQ(ozayn_src_detect_startup_cause(&_svc, &cause, &shutdown),
              OZAYN_SRC_OK);
    /* Without bound state manager, should be UNKNOWN */
    ASSERT(cause == OZAYN_SRC_CAUSE_UNKNOWN);
    ASSERT(shutdown == OZAYN_SRC_SHUTDOWN_UNKNOWN);
    _shutdown_svc();
    return 0;
}

TEST(test_src_detect_cause_null) {
    ASSERT_EQ(ozayn_src_detect_startup_cause(NULL, NULL, NULL),
              OZAYN_SRC_ERR_NULL);
    return 0;
}

TEST(test_src_detect_cause_not_init) {
    ozayn_src_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ASSERT_EQ(ozayn_src_detect_startup_cause(&svc, NULL, NULL),
              OZAYN_SRC_ERR_NOT_INITIALIZED);
    return 0;
}

/* ============================================================
 * MANIFEST TESTS
 * ============================================================ */

TEST(test_src_manifest_reset) {
    _init_svc();
    ASSERT_EQ(ozayn_src_manifest_reset(&_svc), OZAYN_SRC_OK);
    const ozayn_src_startup_manifest_t *m = ozayn_src_manifest_get(&_svc);
    ASSERT_NOT_NULL(m);
    ASSERT_EQ(m->component_count, 0);
    ASSERT_EQ(m->dependency_count, 0);
    ASSERT_EQ(m->capability_count, 0);
    _shutdown_svc();
    return 0;
}

TEST(test_src_manifest_reset_null) {
    ASSERT_EQ(ozayn_src_manifest_reset(NULL), OZAYN_SRC_ERR_NULL);
    return 0;
}

TEST(test_src_manifest_add_component) {
    _init_svc();
    ASSERT_EQ(ozayn_src_manifest_add_component(&_svc, "core", 1),
              OZAYN_SRC_OK);
    ASSERT_EQ(ozayn_src_manifest_add_component(&_svc, "plugin", 0),
              OZAYN_SRC_OK);
    const ozayn_src_startup_manifest_t *m = ozayn_src_manifest_get(&_svc);
    ASSERT_EQ(m->component_count, 2);
    ASSERT_STR_EQ(m->component_names[0], "core");
    ASSERT(m->component_required[0] == 1);
    ASSERT_STR_EQ(m->component_names[1], "plugin");
    ASSERT(m->component_required[1] == 0);
    _shutdown_svc();
    return 0;
}

TEST(test_src_manifest_add_component_null) {
    _init_svc();
    ASSERT_EQ(ozayn_src_manifest_add_component(NULL, "x", 0),
              OZAYN_SRC_ERR_NULL);
    ASSERT_EQ(ozayn_src_manifest_add_component(&_svc, NULL, 0),
              OZAYN_SRC_ERR_NULL);
    _shutdown_svc();
    return 0;
}

TEST(test_src_manifest_add_component_limit) {
    _init_svc();
    for (int i = 0; i < OZAYN_SRC_MAX_COMPONENTS; i++) {
        char name[32];
        snprintf(name, sizeof(name), "comp-%d", i);
        ozayn_src_manifest_add_component(&_svc, name, 0);
    }
    ASSERT_EQ(ozayn_src_manifest_add_component(&_svc, "overflow", 0),
              OZAYN_SRC_ERR_LIMIT_REACHED);
    _shutdown_svc();
    return 0;
}

TEST(test_src_manifest_add_dependency) {
    _init_svc();
    ASSERT_EQ(ozayn_src_manifest_add_dependency(&_svc, "dep-a", 1),
              OZAYN_SRC_OK);
    const ozayn_src_startup_manifest_t *m = ozayn_src_manifest_get(&_svc);
    ASSERT_EQ(m->dependency_count, 1);
    ASSERT_STR_EQ(m->dependency_names[0], "dep-a");
    _shutdown_svc();
    return 0;
}

TEST(test_src_manifest_add_capability) {
    _init_svc();
    ASSERT_EQ(ozayn_src_manifest_add_capability(&_svc, "cap-a", 1),
              OZAYN_SRC_OK);
    const ozayn_src_startup_manifest_t *m = ozayn_src_manifest_get(&_svc);
    ASSERT_EQ(m->capability_count, 1);
    ASSERT_STR_EQ(m->capability_names[0], "cap-a");
    _shutdown_svc();
    return 0;
}

TEST(test_src_manifest_set_phase_timeout) {
    _init_svc();
    ASSERT_EQ(ozayn_src_manifest_set_phase_timeout(&_svc,
        OZAYN_SRC_PHASE_BOOTSTRAP, 5000), OZAYN_SRC_OK);
    const ozayn_src_startup_manifest_t *m = ozayn_src_manifest_get(&_svc);
    ASSERT(m->phase_timeout_ms[OZAYN_SRC_PHASE_BOOTSTRAP] == 5000);
    _shutdown_svc();
    return 0;
}

TEST(test_src_manifest_set_phase_timeout_invalid) {
    _init_svc();
    ASSERT_EQ(ozayn_src_manifest_set_phase_timeout(&_svc,
        OZAYN_SRC_PHASE_COUNT, 5000), OZAYN_SRC_ERR_INVALID_PARAM);
    ASSERT_EQ(ozayn_src_manifest_set_phase_timeout(&_svc,
        OZAYN_SRC_PHASE_BOOTSTRAP, 0), OZAYN_SRC_ERR_INVALID_PARAM);
    _shutdown_svc();
    return 0;
}

TEST(test_src_manifest_set_total_timeout) {
    _init_svc();
    ASSERT_EQ(ozayn_src_manifest_set_total_timeout(&_svc, 60000),
              OZAYN_SRC_OK);
    const ozayn_src_startup_manifest_t *m = ozayn_src_manifest_get(&_svc);
    ASSERT(m->total_timeout_ms == 60000);
    _shutdown_svc();
    return 0;
}

TEST(test_src_manifest_get) {
    _init_svc();
    ASSERT_NOT_NULL(ozayn_src_manifest_get(&_svc));
    ASSERT_NULL(ozayn_src_manifest_get(NULL));
    _shutdown_svc();
    return 0;
}

/* ============================================================
 * EVENT TESTS
 * ============================================================ */

TEST(test_src_emit_event) {
    _init_svc();
    ASSERT_EQ(ozayn_src_emit_event(&_svc, OZAYN_SRC_EVENT_STARTUP_STARTED,
        "test", "Test event", NULL), OZAYN_SRC_OK);
    ASSERT_EQ(ozayn_src_event_count(&_svc), 1);
    _shutdown_svc();
    return 0;
}

TEST(test_src_emit_event_null) {
    ASSERT_EQ(ozayn_src_emit_event(NULL, OZAYN_SRC_EVENT_STARTUP_STARTED,
        NULL, NULL, NULL), OZAYN_SRC_ERR_NULL);
    return 0;
}

TEST(test_src_emit_event_bad_type) {
    _init_svc();
    ASSERT_EQ(ozayn_src_emit_event(&_svc, OZAYN_SRC_EVENT_COUNT,
        NULL, NULL, NULL), OZAYN_SRC_ERR_INVALID_PARAM);
    _shutdown_svc();
    return 0;
}

TEST(test_src_get_event) {
    _init_svc();
    ozayn_src_emit_event(&_svc, OZAYN_SRC_EVENT_READY, "test", "Ready", NULL);
    const ozayn_src_event_t *ev = ozayn_src_get_event(&_svc, 0);
    ASSERT_NOT_NULL(ev);
    ASSERT(ev->event_type == OZAYN_SRC_EVENT_READY);
    _shutdown_svc();
    return 0;
}

TEST(test_src_get_event_invalid) {
    _init_svc();
    ASSERT_NULL(ozayn_src_get_event(&_svc, -1));
    ASSERT_NULL(ozayn_src_get_event(&_svc, 0));
    _shutdown_svc();
    return 0;
}

TEST(test_src_event_ring_buffer) {
    _init_svc();
    for (int i = 0; i < OZAYN_SRC_MAX_EVENTS + 5; i++) {
        ozayn_src_emit_event(&_svc, OZAYN_SRC_EVENT_PHASE_STARTED,
            "test", "Event", NULL);
    }
    ASSERT_EQ(ozayn_src_event_count(&_svc), OZAYN_SRC_MAX_EVENTS);
    _shutdown_svc();
    return 0;
}

/* ============================================================
 * WARNING & BLOCKING TESTS
 * ============================================================ */

TEST(test_src_add_warning) {
    _init_svc();
    ASSERT_EQ(ozayn_src_add_warning(&_svc, "Test warning"), OZAYN_SRC_OK);
    ASSERT_EQ(ozayn_src_warning_count(&_svc), 1);
    ASSERT_STR_EQ(ozayn_src_warning_get(&_svc, 0), "Test warning");
    _shutdown_svc();
    return 0;
}

TEST(test_src_add_warning_null) {
    ASSERT_EQ(ozayn_src_add_warning(NULL, "x"), OZAYN_SRC_ERR_NULL);
    ASSERT_EQ(ozayn_src_add_warning(&_svc, NULL), OZAYN_SRC_ERR_NULL);
    return 0;
}

TEST(test_src_add_warning_limit) {
    _init_svc();
    for (int i = 0; i < OZAYN_SRC_MAX_WARNINGS; i++) {
        ozayn_src_add_warning(&_svc, "w");
    }
    ASSERT_EQ(ozayn_src_add_warning(&_svc, "overflow"),
              OZAYN_SRC_ERR_LIMIT_REACHED);
    _shutdown_svc();
    return 0;
}

TEST(test_src_add_blocking) {
    _init_svc();
    ASSERT_EQ(ozayn_src_add_blocking(&_svc, "Block reason"), OZAYN_SRC_OK);
    ASSERT_EQ(ozayn_src_blocking_count(&_svc), 1);
    ASSERT_STR_EQ(ozayn_src_blocking_get(&_svc, 0), "Block reason");
    _shutdown_svc();
    return 0;
}

TEST(test_src_blocking_limit) {
    _init_svc();
    for (int i = 0; i < OZAYN_SRC_MAX_BLOCKING; i++) {
        ozayn_src_add_blocking(&_svc, "b");
    }
    ASSERT_EQ(ozayn_src_add_blocking(&_svc, "overflow"),
              OZAYN_SRC_ERR_LIMIT_REACHED);
    _shutdown_svc();
    return 0;
}

/* ============================================================
 * PHASE RESULT TESTS
 * ============================================================ */

TEST(test_src_phase_result_count) {
    _init_svc();
    ASSERT_EQ(ozayn_src_phase_result_count(&_svc), 0);
    _shutdown_svc();
    return 0;
}

TEST(test_src_phase_result_get) {
    _init_svc();
    ASSERT_NULL(ozayn_src_phase_result_get(&_svc, 0));
    ASSERT_NULL(ozayn_src_phase_result_get_by_phase(&_svc,
        OZAYN_SRC_PHASE_BOOTSTRAP));
    _shutdown_svc();
    return 0;
}

/* ============================================================
 * STARTUP EXECUTION TESTS
 * ============================================================ */

TEST(test_src_startup_basic) {
    _init_svc();
    ASSERT_EQ(ozayn_src_startup(&_svc), OZAYN_SRC_OK);
    ASSERT(ozayn_src_is_running(&_svc));
    ASSERT(ozayn_src_get_decision(&_svc) == OZAYN_SRC_DECISION_READY);
    _shutdown_svc();
    return 0;
}

TEST(test_src_startup_null) {
    ASSERT_EQ(ozayn_src_startup(NULL), OZAYN_SRC_ERR_NULL);
    return 0;
}

TEST(test_src_startup_not_init) {
    ozayn_src_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ASSERT_EQ(ozayn_src_startup(&svc), OZAYN_SRC_ERR_NOT_INITIALIZED);
    return 0;
}

TEST(test_src_startup_double) {
    _init_svc();
    ASSERT_EQ(ozayn_src_startup(&_svc), OZAYN_SRC_OK);
    ASSERT_EQ(ozayn_src_startup(&_svc), OZAYN_SRC_ERR_STATE_INVALID);
    _shutdown_svc();
    return 0;
}

TEST(test_src_startup_context) {
    _init_svc();
    ozayn_src_startup(&_svc);
    const ozayn_src_startup_context_t *ctx = ozayn_src_get_context(&_svc);
    ASSERT_NOT_NULL(ctx);
    ASSERT(ctx->current_phase == OZAYN_SRC_PHASE_READY);
    ASSERT(ctx->runtime_state == OZAYN_SRC_STATE_RUNNING);
    ASSERT(ctx->startup_cause == OZAYN_SRC_CAUSE_UNKNOWN);
    ASSERT(ctx->previous_shutdown == OZAYN_SRC_SHUTDOWN_UNKNOWN);
    ASSERT(ctx->start_time_ms > 0);
    ASSERT(ctx->completion_time_ms > 0);
    _shutdown_svc();
    return 0;
}

TEST(test_src_startup_phases_executed) {
    _init_svc();
    ozayn_src_startup(&_svc);
    ASSERT_GE(ozayn_src_phase_result_count(&_svc), 10);
    _shutdown_svc();
    return 0;
}

TEST(test_src_startup_with_manifest) {
    _init_svc();
    ozayn_src_manifest_add_component(&_svc, "core", 1);
    ozayn_src_manifest_add_component(&_svc, "plugin", 0);
    ozayn_src_manifest_add_capability(&_svc, "cap-a", 1);
    ASSERT_EQ(ozayn_src_startup(&_svc), OZAYN_SRC_OK);
    ASSERT(ozayn_src_get_decision(&_svc) == OZAYN_SRC_DECISION_READY);
    _shutdown_svc();
    return 0;
}

TEST(test_src_startup_degraded) {
    _init_svc();
    /* Add a warning to trigger degraded mode */
    ozayn_src_manifest_add_component(&_svc, "core", 1);
    ozayn_src_startup(&_svc);
    /* Should be READY (no warnings yet from phases) */
    /* Manually add a warning and re-determine */
    ozayn_src_add_warning(&_svc, "test warning");
    ozayn_src_determine_decision(&_svc);
    ASSERT(ozayn_src_get_decision(&_svc) == OZAYN_SRC_DECISION_READY_DEGRADED);
    _shutdown_svc();
    return 0;
}

TEST(test_src_startup_blocked) {
    _init_svc();
    ozayn_src_add_blocking(&_svc, "Required condition not met");
    ozayn_src_determine_decision(&_svc);
    ASSERT(ozayn_src_get_decision(&_svc) == OZAYN_SRC_DECISION_BLOCKED);
    _shutdown_svc();
    return 0;
}

/* ============================================================
 * SHUTDOWN TESTS
 * ============================================================ */

TEST(test_src_shutdown_basic) {
    _init_svc();
    ozayn_src_startup(&_svc);
    ASSERT_EQ(ozayn_src_shutdown(&_svc), OZAYN_SRC_OK);
    ASSERT(!ozayn_src_is_running(&_svc));
    ASSERT(ozayn_src_get_state(&_svc) == OZAYN_SRC_STATE_STOPPED);
    _shutdown_svc();
    return 0;
}

/* ============================================================
 * PHASE QUERY TESTS
 * ============================================================ */

TEST(test_src_get_phase) {
    _init_svc();
    ASSERT(ozayn_src_get_phase(&_svc) == OZAYN_SRC_PHASE_NOT_STARTED);
    _shutdown_svc();
    return 0;
}

TEST(test_src_get_phase_null) {
    ASSERT(ozayn_src_get_phase(NULL) == OZAYN_SRC_PHASE_NOT_STARTED);
    return 0;
}

TEST(test_src_get_state) {
    _init_svc();
    ASSERT(ozayn_src_get_state(&_svc) == OZAYN_SRC_STATE_IDLE);
    ozayn_src_startup(&_svc);
    ASSERT(ozayn_src_get_state(&_svc) == OZAYN_SRC_STATE_RUNNING);
    _shutdown_svc();
    return 0;
}

TEST(test_src_get_decision) {
    _init_svc();
    ASSERT(ozayn_src_get_decision(&_svc) == OZAYN_SRC_DECISION_UNKNOWN);
    ozayn_src_startup(&_svc);
    ASSERT(ozayn_src_get_decision(&_svc) == OZAYN_SRC_DECISION_READY);
    _shutdown_svc();
    return 0;
}

TEST(test_src_is_running) {
    _init_svc();
    ASSERT(!ozayn_src_is_running(&_svc));
    ozayn_src_startup(&_svc);
    ASSERT(ozayn_src_is_running(&_svc));
    ozayn_src_shutdown(&_svc);
    ASSERT(!ozayn_src_is_running(&_svc));
    _shutdown_svc();
    return 0;
}

/* ============================================================
 * CONTEXT TESTS
 * ============================================================ */

TEST(test_src_context_set_cause) {
    _init_svc();
    ASSERT_EQ(ozayn_src_context_set_startup_cause(&_svc,
        OZAYN_SRC_CAUSE_CRASH_RECOVERY), OZAYN_SRC_OK);
    const ozayn_src_startup_context_t *ctx = ozayn_src_get_context(&_svc);
    ASSERT(ctx->startup_cause == OZAYN_SRC_CAUSE_CRASH_RECOVERY);
    _shutdown_svc();
    return 0;
}

TEST(test_src_context_set_shutdown) {
    _init_svc();
    ASSERT_EQ(ozayn_src_context_set_previous_shutdown(&_svc,
        OZAYN_SRC_SHUTDOWN_UNCLEAN), OZAYN_SRC_OK);
    const ozayn_src_startup_context_t *ctx = ozayn_src_get_context(&_svc);
    ASSERT(ctx->previous_shutdown == OZAYN_SRC_SHUTDOWN_UNCLEAN);
    _shutdown_svc();
    return 0;
}

TEST(test_src_get_context_null) {
    ASSERT_NULL(ozayn_src_get_context(NULL));
    return 0;
}

/* ============================================================
 * COMPONENT RECONCILIATION TESTS
 * ============================================================ */

TEST(test_src_reconcile_components) {
    _init_svc();
    ozayn_src_manifest_add_component(&_svc, "core", 1);
    ozayn_src_manifest_add_component(&_svc, "plugin", 0);
    ASSERT_EQ(ozayn_src_reconcile_components(&_svc), OZAYN_SRC_OK);
    ASSERT_EQ(ozayn_src_component_recon_count(&_svc), 2);
    _shutdown_svc();
    return 0;
}

TEST(test_src_reconcile_components_null) {
    ASSERT_EQ(ozayn_src_reconcile_components(NULL), OZAYN_SRC_ERR_NULL);
    return 0;
}

TEST(test_src_reconcile_components_concurrency) {
    _init_svc();
    _svc.reconciliation_in_progress = 1;
    ASSERT_EQ(ozayn_src_reconcile_components(&_svc),
              OZAYN_SRC_ERR_CONCURRENCY_ERROR);
    _shutdown_svc();
    return 0;
}

TEST(test_src_component_recon_get) {
    _init_svc();
    ASSERT_NULL(ozayn_src_component_recon_get(&_svc, 0));
    ozayn_src_manifest_add_component(&_svc, "core", 1);
    ozayn_src_reconcile_components(&_svc);
    const ozayn_src_component_recon_entry_t *entry =
        ozayn_src_component_recon_get(&_svc, 0);
    ASSERT_NOT_NULL(entry);
    ASSERT_STR_EQ(entry->component_name, "core");
    ASSERT(entry->is_required == 1);
    _shutdown_svc();
    return 0;
}

TEST(test_src_component_recon_inconsistencies) {
    _init_svc();
    ASSERT_EQ(ozayn_src_component_recon_inconsistencies(&_svc), 0);
    ozayn_src_manifest_add_component(&_svc, "core", 1);
    ozayn_src_reconcile_components(&_svc);
    /* With no registry bound, should be CONSISTENT */
    ASSERT_EQ(ozayn_src_component_recon_inconsistencies(&_svc), 0);
    _shutdown_svc();
    return 0;
}

/* ============================================================
 * CAPABILITY RECONCILIATION TESTS
 * ============================================================ */

TEST(test_src_reconcile_capabilities) {
    _init_svc();
    ozayn_src_manifest_add_capability(&_svc, "cap-a", 1);
    ASSERT_EQ(ozayn_src_reconcile_capabilities(&_svc), OZAYN_SRC_OK);
    ASSERT_EQ(ozayn_src_capability_recon_count(&_svc), 1);
    _shutdown_svc();
    return 0;
}

TEST(test_src_capability_recon_get) {
    _init_svc();
    ASSERT_NULL(ozayn_src_capability_recon_get(&_svc, 0));
    ozayn_src_manifest_add_capability(&_svc, "cap-a", 1);
    ozayn_src_reconcile_capabilities(&_svc);
    const ozayn_src_capability_recon_entry_t *entry =
        ozayn_src_capability_recon_get(&_svc, 0);
    ASSERT_NOT_NULL(entry);
    ASSERT_STR_EQ(entry->capability_name, "cap-a");
    _shutdown_svc();
    return 0;
}

TEST(test_src_capability_recon_unavailable) {
    _init_svc();
    ASSERT_EQ(ozayn_src_capability_recon_unavailable(&_svc), 0);
    _shutdown_svc();
    return 0;
}

/* ============================================================
 * RESOURCE RECONCILIATION TESTS
 * ============================================================ */

TEST(test_src_reconcile_resources) {
    _init_svc();
    ASSERT_EQ(ozayn_src_reconcile_resources(&_svc), OZAYN_SRC_OK);
    ASSERT_GE(ozayn_src_resource_recon_count(&_svc), 7);
    _shutdown_svc();
    return 0;
}

TEST(test_src_resource_recon_get) {
    _init_svc();
    ozayn_src_reconcile_resources(&_svc);
    const ozayn_src_resource_recon_entry_t *entry =
        ozayn_src_resource_recon_get(&_svc, 0);
    ASSERT_NOT_NULL(entry);
    ASSERT_STR_EQ(entry->resource_name, "CPU");
    _shutdown_svc();
    return 0;
}

TEST(test_src_resource_recon_unavailable) {
    _init_svc();
    ASSERT_EQ(ozayn_src_resource_recon_unavailable(&_svc), 0);
    _shutdown_svc();
    return 0;
}

/* ============================================================
 * DEVICE RECONCILIATION TESTS
 * ============================================================ */

TEST(test_src_reconcile_devices) {
    _init_svc();
    ASSERT_EQ(ozayn_src_reconcile_devices(&_svc), OZAYN_SRC_OK);
    _shutdown_svc();
    return 0;
}

TEST(test_src_device_recon_count) {
    _init_svc();
    ASSERT_EQ(ozayn_src_device_recon_count(&_svc), 0);
    _shutdown_svc();
    return 0;
}

TEST(test_src_device_recon_stale) {
    _init_svc();
    ASSERT_EQ(ozayn_src_device_recon_stale_sessions(&_svc), 0);
    _shutdown_svc();
    return 0;
}

/* ============================================================
 * SECURITY REVALIDATION TESTS
 * ============================================================ */

TEST(test_src_revalidate_security) {
    _init_svc();
    ASSERT_EQ(ozayn_src_revalidate_security(&_svc), OZAYN_SRC_OK);
    /* Without safety bound, should be UNAVAILABLE */
    ASSERT(ozayn_src_security_status(&_svc) == OZAYN_SRC_SEC_RECON_UNAVAILABLE);
    _shutdown_svc();
    return 0;
}

TEST(test_src_revalidate_security_with_safety) {
    _init_svc();
    int dummy;
    ozayn_src_set_safety(&_svc, &dummy);
    ASSERT_EQ(ozayn_src_revalidate_security(&_svc), OZAYN_SRC_OK);
    ASSERT(ozayn_src_security_status(&_svc) == OZAYN_SRC_SEC_RECON_VALID);
    _shutdown_svc();
    return 0;
}

TEST(test_src_security_status_null) {
    ASSERT(ozayn_src_security_status(NULL) == OZAYN_SRC_SEC_RECON_UNKNOWN);
    return 0;
}

/* ============================================================
 * RECOVERY ASSESSMENT TESTS
 * ============================================================ */

TEST(test_src_assess_recovery) {
    _init_svc();
    ASSERT_EQ(ozayn_src_assess_recovery(&_svc), OZAYN_SRC_OK);
    ASSERT_EQ(ozayn_src_recovery_item_count(&_svc), 0);
    ASSERT(ozayn_src_recovery_overall_assessment(&_svc) ==
           OZAYN_SRC_RECOVERY_NONE);
    _shutdown_svc();
    return 0;
}

TEST(test_src_assess_recovery_null) {
    ASSERT_EQ(ozayn_src_assess_recovery(NULL), OZAYN_SRC_ERR_NULL);
    return 0;
}

TEST(test_src_recovery_item_get) {
    _init_svc();
    ASSERT_NULL(ozayn_src_recovery_item_get(&_svc, 0));
    _shutdown_svc();
    return 0;
}

/* ============================================================
 * STARTUP DECISION TESTS
 * ============================================================ */

TEST(test_src_determine_decision_ready) {
    _init_svc();
    ASSERT_EQ(ozayn_src_determine_decision(&_svc), OZAYN_SRC_OK);
    ASSERT(ozayn_src_get_decision(&_svc) == OZAYN_SRC_DECISION_READY);
    _shutdown_svc();
    return 0;
}

TEST(test_src_determine_decision_degraded) {
    _init_svc();
    ozayn_src_add_warning(&_svc, "Something suboptimal");
    ASSERT_EQ(ozayn_src_determine_decision(&_svc), OZAYN_SRC_OK);
    ASSERT(ozayn_src_get_decision(&_svc) == OZAYN_SRC_DECISION_READY_DEGRADED);
    _shutdown_svc();
    return 0;
}

TEST(test_src_determine_decision_blocked) {
    _init_svc();
    ozayn_src_add_blocking(&_svc, "Required condition");
    ASSERT_EQ(ozayn_src_determine_decision(&_svc), OZAYN_SRC_OK);
    ASSERT(ozayn_src_get_decision(&_svc) == OZAYN_SRC_DECISION_BLOCKED);
    _shutdown_svc();
    return 0;
}

TEST(test_src_decision_description) {
    _init_svc();
    const char *desc = ozayn_src_decision_description(&_svc);
    ASSERT_NOT_NULL(desc);
    _shutdown_svc();
    return 0;
}

/* ============================================================
 * FULL STARTUP FLOW TESTS
 * ============================================================ */

TEST(test_src_full_startup_flow) {
    _init_svc();

    /* Setup manifest */
    ozayn_src_manifest_add_component(&_svc, "lifecycle", 1);
    ozayn_src_manifest_add_component(&_svc, "dependency", 1);
    ozayn_src_manifest_add_component(&_svc, "registry", 0);
    ozayn_src_manifest_add_capability(&_svc, "core-services", 1);

    /* Bind external deps */
    int dummy_lifecycle = 1;
    int dummy_dep = 1;
    int dummy_safety = 1;
    ozayn_src_set_lifecycle(&_svc, &dummy_lifecycle);
    ozayn_src_set_dependency(&_svc, &dummy_dep);
    ozayn_src_set_safety(&_svc, &dummy_safety);

    /* Startup */
    ASSERT_EQ(ozayn_src_startup(&_svc), OZAYN_SRC_OK);
    ASSERT(ozayn_src_is_running(&_svc));
    ASSERT(ozayn_src_get_decision(&_svc) == OZAYN_SRC_DECISION_READY);

    /* Verify phases executed */
    ASSERT_GE(ozayn_src_phase_result_count(&_svc), 10);

    /* Verify component reconciliation */
    ASSERT_GE(ozayn_src_component_recon_count(&_svc), 2);

    /* Verify capability reconciliation */
    ASSERT_GE(ozayn_src_capability_recon_count(&_svc), 1);

    /* Verify resource reconciliation */
    ASSERT_GE(ozayn_src_resource_recon_count(&_svc), 7);

    /* Verify security revalidation */
    ASSERT(ozayn_src_security_status(&_svc) == OZAYN_SRC_SEC_RECON_VALID);

    /* Verify recovery assessment */
    ASSERT(ozayn_src_recovery_overall_assessment(&_svc) ==
           OZAYN_SRC_RECOVERY_NONE);

    /* Verify events */
    ASSERT_GE(ozayn_src_event_count(&_svc), 5);

    /* Verify stats */
    const ozayn_src_stats_t *stats = ozayn_src_get_stats(&_svc);
    ASSERT_NOT_NULL(stats);
    ASSERT_EQ(stats->total_startups, 1);
    ASSERT_GE(stats->total_phases_completed, 8);
    ASSERT_GE(stats->total_components_reconciled, 2);
    ASSERT_GE(stats->total_capabilities_checked, 1);
    ASSERT_GE(stats->total_resources_reconciled, 7);
    ASSERT_GE(stats->total_security_revalidated, 1);

    /* Shutdown */
    ASSERT_EQ(ozayn_src_shutdown(&_svc), OZAYN_SRC_OK);
    ASSERT(!ozayn_src_is_running(&_svc));

    _shutdown_svc();
    return 0;
}

TEST(test_src_startup_shutdown_restart) {
    _init_svc();
    ASSERT_EQ(ozayn_src_startup(&_svc), OZAYN_SRC_OK);
    ASSERT(ozayn_src_is_running(&_svc));
    ASSERT_EQ(ozayn_src_shutdown(&_svc), OZAYN_SRC_OK);
    ASSERT(!ozayn_src_is_running(&_svc));
    /* Can start again */
    ASSERT_EQ(ozayn_src_startup(&_svc), OZAYN_SRC_OK);
    ASSERT(ozayn_src_is_running(&_svc));
    _shutdown_svc();
    return 0;
}

TEST(test_src_startup_cause_detection_flow) {
    _init_svc();
    /* Set startup cause before starting */
    ozayn_src_context_set_startup_cause(&_svc,
        OZAYN_SRC_CAUSE_CRASH_RECOVERY);
    ozayn_src_context_set_previous_shutdown(&_svc,
        OZAYN_SRC_SHUTDOWN_UNCLEAN);
    ozayn_src_startup(&_svc);
    const ozayn_src_startup_context_t *ctx = ozayn_src_get_context(&_svc);
    ASSERT(ctx->startup_cause == OZAYN_SRC_CAUSE_CRASH_RECOVERY);
    ASSERT(ctx->previous_shutdown == OZAYN_SRC_SHUTDOWN_UNCLEAN);
    _shutdown_svc();
    return 0;
}

/* ============================================================
 * NAME HELPER TESTS
 * ============================================================ */

TEST(test_src_err_name) {
    ASSERT_STR_EQ(ozayn_src_err_name(OZAYN_SRC_OK), "OK");
    ASSERT_STR_EQ(ozayn_src_err_name(OZAYN_SRC_ERR_NULL), "NULL");
    ASSERT_STR_EQ(ozayn_src_err_name(OZAYN_SRC_ERR_BLOCKED), "BLOCKED");
    return 0;
}

TEST(test_src_phase_name) {
    ASSERT_NOT_NULL(ozayn_src_phase_name(OZAYN_SRC_PHASE_NOT_STARTED));
    ASSERT_NOT_NULL(ozayn_src_phase_name(OZAYN_SRC_PHASE_BOOTSTRAP));
    ASSERT_NOT_NULL(ozayn_src_phase_name(OZAYN_SRC_PHASE_READY));
    ASSERT_NOT_NULL(ozayn_src_phase_name(OZAYN_SRC_PHASE_FAILED));
    return 0;
}

TEST(test_src_state_name) {
    ASSERT_STR_EQ(ozayn_src_state_name(OZAYN_SRC_STATE_IDLE), "IDLE");
    ASSERT_STR_EQ(ozayn_src_state_name(OZAYN_SRC_STATE_STARTING), "STARTING");
    ASSERT_STR_EQ(ozayn_src_state_name(OZAYN_SRC_STATE_RUNNING), "RUNNING");
    ASSERT_STR_EQ(ozayn_src_state_name(OZAYN_SRC_STATE_STOPPING), "STOPPING");
    ASSERT_STR_EQ(ozayn_src_state_name(OZAYN_SRC_STATE_STOPPED), "STOPPED");
    ASSERT_STR_EQ(ozayn_src_state_name(OZAYN_SRC_STATE_FAILED), "FAILED");
    return 0;
}

TEST(test_src_cause_name) {
    ASSERT_STR_EQ(ozayn_src_cause_name(OZAYN_SRC_CAUSE_UNKNOWN), "UNKNOWN");
    ASSERT_STR_EQ(ozayn_src_cause_name(OZAYN_SRC_CAUSE_NORMAL_START),
                  "NORMAL_START");
    ASSERT_STR_EQ(ozayn_src_cause_name(OZAYN_SRC_CAUSE_CRASH_RECOVERY),
                  "CRASH_RECOVERY");
    return 0;
}

TEST(test_src_shutdown_name) {
    ASSERT_STR_EQ(ozayn_src_shutdown_name(OZAYN_SRC_SHUTDOWN_UNKNOWN),
                  "UNKNOWN");
    ASSERT_STR_EQ(ozayn_src_shutdown_name(OZAYN_SRC_SHUTDOWN_CLEAN), "CLEAN");
    ASSERT_STR_EQ(ozayn_src_shutdown_name(OZAYN_SRC_SHUTDOWN_CRASH), "CRASH");
    return 0;
}

TEST(test_src_component_recon_name) {
    ASSERT_STR_EQ(ozayn_src_component_recon_name(OZAYN_SRC_RECON_CONSISTENT),
                  "CONSISTENT");
    ASSERT_STR_EQ(ozayn_src_component_recon_name(OZAYN_SRC_RECON_MISSING),
                  "MISSING");
    return 0;
}

TEST(test_src_capability_recon_name) {
    ASSERT_STR_EQ(ozayn_src_capability_recon_name(OZAYN_SRC_CAP_RECON_AVAILABLE),
                  "AVAILABLE");
    ASSERT_STR_EQ(ozayn_src_capability_recon_name(OZAYN_SRC_CAP_RECON_UNAVAILABLE),
                  "UNAVAILABLE");
    return 0;
}

TEST(test_src_resource_recon_name) {
    ASSERT_STR_EQ(ozayn_src_resource_recon_name(OZAYN_SRC_RES_RECON_AVAILABLE),
                  "AVAILABLE");
    ASSERT_STR_EQ(ozayn_src_resource_recon_name(OZAYN_SRC_RES_RECON_CHANGED),
                  "CHANGED");
    return 0;
}

TEST(test_src_device_recon_name) {
    ASSERT_STR_EQ(ozayn_src_device_recon_name(OZAYN_SRC_DEV_RECON_PRESENT),
                  "PRESENT");
    ASSERT_STR_EQ(ozayn_src_device_recon_name(OZAYN_SRC_DEV_RECON_ABSENT),
                  "ABSENT");
    return 0;
}

TEST(test_src_security_recon_name) {
    ASSERT_STR_EQ(ozayn_src_security_recon_name(OZAYN_SRC_SEC_RECON_VALID),
                  "VALID");
    ASSERT_STR_EQ(ozayn_src_security_recon_name(OZAYN_SRC_SEC_RECON_EXPIRED),
                  "EXPIRED");
    return 0;
}

TEST(test_src_recovery_assessment_name) {
    ASSERT_STR_EQ(ozayn_src_recovery_assessment_name(OZAYN_SRC_RECOVERY_NONE),
                  "NONE");
    ASSERT_STR_EQ(ozayn_src_recovery_assessment_name(OZAYN_SRC_RECOVERY_REQUIRED),
                  "REQUIRED");
    return 0;
}

TEST(test_src_decision_name) {
    ASSERT_NOT_NULL(ozayn_src_decision_name(OZAYN_SRC_DECISION_READY));
    ASSERT_NOT_NULL(ozayn_src_decision_name(OZAYN_SRC_DECISION_BLOCKED));
    return 0;
}

TEST(test_src_failure_class_name) {
    ASSERT_STR_EQ(ozayn_src_failure_class_name(OZAYN_SRC_FAIL_NON_CRITICAL),
                  "NON_CRITICAL");
    ASSERT_STR_EQ(ozayn_src_failure_class_name(OZAYN_SRC_FAIL_BLOCKING),
                  "BLOCKING");
    return 0;
}

TEST(test_src_priority_name) {
    ASSERT_STR_EQ(ozayn_src_priority_name(OZAYN_SRC_PRIORITY_LOW), "LOW");
    ASSERT_STR_EQ(ozayn_src_priority_name(OZAYN_SRC_PRIORITY_CRITICAL),
                  "CRITICAL");
    return 0;
}

TEST(test_src_event_type_name) {
    ASSERT_STR_EQ(ozayn_src_event_type_name(OZAYN_SRC_EVENT_STARTUP_STARTED),
                  "STARTUP_STARTED");
    ASSERT_STR_EQ(ozayn_src_event_type_name(OZAYN_SRC_EVENT_READY), "READY");
    ASSERT_STR_EQ(ozayn_src_event_type_name(OZAYN_SRC_EVENT_FAILED), "FAILED");
    return 0;
}

TEST(test_src_phase_result_status_name) {
    ASSERT_STR_EQ(ozayn_src_phase_result_status_name(
        OZAYN_SRC_PHASE_RESULT_SUCCESS), "SUCCESS");
    ASSERT_STR_EQ(ozayn_src_phase_result_status_name(
        OZAYN_SRC_PHASE_RESULT_FAILED), "FAILED");
    return 0;
}

/* ============================================================
 * VALIDATION TESTS
 * ============================================================ */

TEST(test_src_validate_context) {
    ozayn_src_startup_context_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.current_phase = OZAYN_SRC_PHASE_READY;
    ctx.runtime_state = OZAYN_SRC_STATE_RUNNING;
    ctx.startup_cause = OZAYN_SRC_CAUSE_UNKNOWN;
    ASSERT(ozayn_src_validate_context(&ctx));
    ASSERT(!ozayn_src_validate_context(NULL));
    return 0;
}

TEST(test_src_validate_manifest) {
    ozayn_src_startup_manifest_t m;
    memset(&m, 0, sizeof(m));
    m.total_timeout_ms = 60000;
    ASSERT(ozayn_src_validate_manifest(&m));
    ASSERT(!ozayn_src_validate_manifest(NULL));
    return 0;
}

TEST(test_src_validate_phase) {
    ASSERT(ozayn_src_validate_phase(OZAYN_SRC_PHASE_BOOTSTRAP));
    ASSERT(!ozayn_src_validate_phase(OZAYN_SRC_PHASE_COUNT));
    return 0;
}

TEST(test_src_is_phase_terminal) {
    ASSERT(ozayn_src_is_phase_terminal(OZAYN_SRC_PHASE_READY));
    ASSERT(ozayn_src_is_phase_terminal(OZAYN_SRC_PHASE_FAILED));
    ASSERT(!ozayn_src_is_phase_terminal(OZAYN_SRC_PHASE_BOOTSTRAP));
    return 0;
}

TEST(test_src_is_decision_terminal) {
    ASSERT(ozayn_src_is_decision_terminal(OZAYN_SRC_DECISION_READY));
    ASSERT(ozayn_src_is_decision_terminal(OZAYN_SRC_DECISION_BLOCKED));
    ASSERT(!ozayn_src_is_decision_terminal(OZAYN_SRC_DECISION_UNKNOWN));
    return 0;
}

/* ============================================================
 * STATISTICS TESTS
 * ============================================================ */

TEST(test_src_stats) {
    _init_svc();
    const ozayn_src_stats_t *stats = ozayn_src_get_stats(&_svc);
    ASSERT_NOT_NULL(stats);
    ASSERT_EQ(stats->total_startups, 0);
    ozayn_src_startup(&_svc);
    stats = ozayn_src_get_stats(&_svc);
    ASSERT_EQ(stats->total_startups, 1);
    _shutdown_svc();
    return 0;
}

TEST(test_src_stats_null) {
    ASSERT_NULL(ozayn_src_get_stats(NULL));
    return 0;
}

TEST(test_src_reset_stats) {
    _init_svc();
    ozayn_src_startup(&_svc);
    ASSERT_EQ(ozayn_src_reset_stats(&_svc), OZAYN_SRC_OK);
    const ozayn_src_stats_t *stats = ozayn_src_get_stats(&_svc);
    ASSERT_EQ(stats->total_startups, 0);
    _shutdown_svc();
    return 0;
}

/* ============================================================
 * CRASH RECOVERY SCENARIO TEST
 * ============================================================ */

TEST(test_src_crash_recovery_scenario) {
    _init_svc();

    /* Simulate crash recovery */
    ozayn_src_context_set_startup_cause(&_svc,
        OZAYN_SRC_CAUSE_CRASH_RECOVERY);
    ozayn_src_context_set_previous_shutdown(&_svc,
        OZAYN_SRC_SHUTDOWN_CRASH);

    /* Setup */
    int dummy = 1;
    ozayn_src_set_lifecycle(&_svc, &dummy);
    ozayn_src_set_dependency(&_svc, &dummy);
    ozayn_src_manifest_add_component(&_svc, "core", 1);

    /* Startup */
    ASSERT_EQ(ozayn_src_startup(&_svc), OZAYN_SRC_OK);
    ASSERT(ozayn_src_is_running(&_svc));

    /* Verify crash recovery is tracked */
    const ozayn_src_stats_t *stats = ozayn_src_get_stats(&_svc);
    ASSERT_EQ(stats->total_startups, 1);

    /* Verify cause is preserved */
    const ozayn_src_startup_context_t *ctx = ozayn_src_get_context(&_svc);
    ASSERT(ctx->startup_cause == OZAYN_SRC_CAUSE_CRASH_RECOVERY);
    ASSERT(ctx->previous_shutdown == OZAYN_SRC_SHUTDOWN_CRASH);

    _shutdown_svc();
    return 0;
}

/* ============================================================
 * CONCURRENCY PROTECTION TEST
 * ============================================================ */

TEST(test_src_concurrent_startup_prevented) {
    _init_svc();
    _svc.startup_in_progress = 1;
    ASSERT_EQ(ozayn_src_startup(&_svc), OZAYN_SRC_ERR_CONCURRENCY_ERROR);
    _shutdown_svc();
    return 0;
}

TEST(test_src_running_prevents_startup) {
    _init_svc();
    _svc.running = 1;
    ASSERT_EQ(ozayn_src_startup(&_svc), OZAYN_SRC_ERR_STATE_INVALID);
    _shutdown_svc();
    return 0;
}

/* ============================================================
 * MAIN — TEST RUNNER
 * ============================================================ */

int run_cr_startup_recovery_tests(void) {
    SUITE_BEGIN("Control Room — Startup Recovery (Step 19)");

    /* Lifecycle */
    RUN(test_src_init);
    RUN(test_src_init_null);
    RUN(test_src_init_double);
    RUN(test_src_shutdown);
    RUN(test_src_shutdown_null);
    RUN(test_src_shutdown_not_init);
    RUN(test_src_is_initialized_null);
    RUN(test_src_global);

    /* External dependency binding */
    RUN(test_src_set_lifecycle);
    RUN(test_src_set_lifecycle_null);
    RUN(test_src_set_dependency);
    RUN(test_src_set_component_registry);
    RUN(test_src_set_resource_manager);
    RUN(test_src_set_device_session);
    RUN(test_src_set_safety);
    RUN(test_src_set_diagnostics);
    RUN(test_src_set_workflow_recovery);
    RUN(test_src_set_workflow_checkpoint);
    RUN(test_src_set_state_manager);
    RUN(test_src_set_events_engine);

    /* Startup cause detection */
    RUN(test_src_detect_cause);
    RUN(test_src_detect_cause_null);
    RUN(test_src_detect_cause_not_init);

    /* Manifest */
    RUN(test_src_manifest_reset);
    RUN(test_src_manifest_reset_null);
    RUN(test_src_manifest_add_component);
    RUN(test_src_manifest_add_component_null);
    RUN(test_src_manifest_add_component_limit);
    RUN(test_src_manifest_add_dependency);
    RUN(test_src_manifest_add_capability);
    RUN(test_src_manifest_set_phase_timeout);
    RUN(test_src_manifest_set_phase_timeout_invalid);
    RUN(test_src_manifest_set_total_timeout);
    RUN(test_src_manifest_get);

    /* Events */
    RUN(test_src_emit_event);
    RUN(test_src_emit_event_null);
    RUN(test_src_emit_event_bad_type);
    RUN(test_src_get_event);
    RUN(test_src_get_event_invalid);
    RUN(test_src_event_ring_buffer);

    /* Warnings & blocking */
    RUN(test_src_add_warning);
    RUN(test_src_add_warning_null);
    RUN(test_src_add_warning_limit);
    RUN(test_src_add_blocking);
    RUN(test_src_blocking_limit);

    /* Phase results */
    RUN(test_src_phase_result_count);
    RUN(test_src_phase_result_get);

    /* Startup execution */
    RUN(test_src_startup_basic);
    RUN(test_src_startup_null);
    RUN(test_src_startup_not_init);
    RUN(test_src_startup_double);
    RUN(test_src_startup_context);
    RUN(test_src_startup_phases_executed);
    RUN(test_src_startup_with_manifest);
    RUN(test_src_startup_degraded);
    RUN(test_src_startup_blocked);

    /* Shutdown */
    RUN(test_src_shutdown_basic);

    /* Phase query */
    RUN(test_src_get_phase);
    RUN(test_src_get_phase_null);
    RUN(test_src_get_state);
    RUN(test_src_get_decision);
    RUN(test_src_is_running);

    /* Context */
    RUN(test_src_context_set_cause);
    RUN(test_src_context_set_shutdown);
    RUN(test_src_get_context_null);

    /* Component reconciliation */
    RUN(test_src_reconcile_components);
    RUN(test_src_reconcile_components_null);
    RUN(test_src_reconcile_components_concurrency);
    RUN(test_src_component_recon_get);
    RUN(test_src_component_recon_inconsistencies);

    /* Capability reconciliation */
    RUN(test_src_reconcile_capabilities);
    RUN(test_src_capability_recon_get);
    RUN(test_src_capability_recon_unavailable);

    /* Resource reconciliation */
    RUN(test_src_reconcile_resources);
    RUN(test_src_resource_recon_get);
    RUN(test_src_resource_recon_unavailable);

    /* Device reconciliation */
    RUN(test_src_reconcile_devices);
    RUN(test_src_device_recon_count);
    RUN(test_src_device_recon_stale);

    /* Security revalidation */
    RUN(test_src_revalidate_security);
    RUN(test_src_revalidate_security_with_safety);
    RUN(test_src_security_status_null);

    /* Recovery assessment */
    RUN(test_src_assess_recovery);
    RUN(test_src_assess_recovery_null);
    RUN(test_src_recovery_item_get);

    /* Startup decision */
    RUN(test_src_determine_decision_ready);
    RUN(test_src_determine_decision_degraded);
    RUN(test_src_determine_decision_blocked);
    RUN(test_src_decision_description);

    /* Full flow */
    RUN(test_src_full_startup_flow);
    RUN(test_src_startup_shutdown_restart);
    RUN(test_src_startup_cause_detection_flow);

    /* Name helpers */
    RUN(test_src_err_name);
    RUN(test_src_phase_name);
    RUN(test_src_state_name);
    RUN(test_src_cause_name);
    RUN(test_src_shutdown_name);
    RUN(test_src_component_recon_name);
    RUN(test_src_capability_recon_name);
    RUN(test_src_resource_recon_name);
    RUN(test_src_device_recon_name);
    RUN(test_src_security_recon_name);
    RUN(test_src_recovery_assessment_name);
    RUN(test_src_decision_name);
    RUN(test_src_failure_class_name);
    RUN(test_src_priority_name);
    RUN(test_src_event_type_name);
    RUN(test_src_phase_result_status_name);

    /* Validation */
    RUN(test_src_validate_context);
    RUN(test_src_validate_manifest);
    RUN(test_src_validate_phase);
    RUN(test_src_is_phase_terminal);
    RUN(test_src_is_decision_terminal);

    /* Statistics */
    RUN(test_src_stats);
    RUN(test_src_stats_null);
    RUN(test_src_reset_stats);

    /* Scenario tests */
    RUN(test_src_crash_recovery_scenario);
    RUN(test_src_concurrent_startup_prevented);
    RUN(test_src_running_prevents_startup);

    SUITE_END();
    return TOTAL_FAIL();
}
