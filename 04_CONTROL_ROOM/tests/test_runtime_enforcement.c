/*
 * test_runtime_enforcement.c — Section 04, Step 23
 * Runtime Operation Enforcement & Execution Boundary tests
 */

#include "../../tests/test_framework.h"
#include "../runtime_enforcement.h"
#include <string.h>

/* ============================================================
 * HELPERS
 * ============================================================ */

static ozayn_roe_request_t _make_request(const char *id, const char *op_id) {
    ozayn_roe_request_t r;
    memset(&r, 0, sizeof(r));
    strncpy(r.id, id, OZAYN_ROE_MAX_ID_LEN - 1);
    strncpy(r.operation_id, op_id, OZAYN_ROE_MAX_ID_LEN - 1);
    r.priority = 5;
    r.request_time_ms = 1000;
    r.expiration_ms = 2000000000;
    return r;
}

static ozayn_roe_context_t _make_ready_ctx(void) {
    ozayn_roe_context_t c;
    memset(&c, 0, sizeof(c));
    c.runtime_mode = OZAYN_ORD_MODE_READY;
    c.readiness_satisfied = 1;
    c.component_available = 1;
    c.capability_available = 1;
    c.security_session_valid = 1;
    c.authorization_valid = 1;
    c.safety_policy_valid = 1;
    c.resources_available = 1;
    c.devices_available = 1;
    c.workflow_valid = 1;
    c.pipeline_valid = 1;
    c.dependencies_satisfied = 1;
    c.operation_active = 1;
    return c;
}

/* ============================================================
 * LIFECYCLE TESTS
 * ============================================================ */

TEST(test_roe_init_null) {
    ASSERT_EQ(ozayn_roe_service_init(NULL, NULL), OZAYN_ROE_ERR_NULL);
    return 0;
}

TEST(test_roe_init_ok) {
    ozayn_roe_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ASSERT_EQ(ozayn_roe_service_init(&svc, NULL), OZAYN_ROE_OK);
    ASSERT(svc.initialized);
    ASSERT_EQ(svc.request_count, 0);
    ASSERT_EQ(svc.decision_count, 0);
    ASSERT_EQ(svc.event_count, 0);
    ozayn_roe_service_shutdown(&svc);
    return 0;
}

TEST(test_roe_double_init) {
    ozayn_roe_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ASSERT_EQ(ozayn_roe_service_init(&svc, NULL), OZAYN_ROE_OK);
    ASSERT_EQ(ozayn_roe_service_init(&svc, NULL), OZAYN_ROE_ERR_ALREADY_INITIALIZED);
    ozayn_roe_service_shutdown(&svc);
    return 0;
}

TEST(test_roe_shutdown_null) {
    ASSERT_EQ(ozayn_roe_service_shutdown(NULL), OZAYN_ROE_ERR_NULL);
    return 0;
}

TEST(test_roe_shutdown_not_init) {
    ozayn_roe_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ASSERT_EQ(ozayn_roe_service_shutdown(&svc), OZAYN_ROE_ERR_NOT_INITIALIZED);
    return 0;
}

TEST(test_roe_shutdown_ok) {
    ozayn_roe_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ASSERT_EQ(ozayn_roe_service_init(&svc, NULL), OZAYN_ROE_OK);
    ASSERT_EQ(ozayn_roe_service_shutdown(&svc), OZAYN_ROE_OK);
    ASSERT(!svc.initialized);
    return 0;
}

TEST(test_roe_init_with_config) {
    ozayn_roe_service_t svc;
    memset(&svc, 0, sizeof(svc));
    int dummy = 1;
    ozayn_roe_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.readiness = &dummy;
    cfg.audit = &dummy;
    cfg.safety = &dummy;
    ASSERT_EQ(ozayn_roe_service_init(&svc, &cfg), OZAYN_ROE_OK);
    ASSERT_EQ(svc.readiness, &dummy);
    ASSERT_EQ(svc.audit, &dummy);
    ASSERT_EQ(svc.safety, &dummy);
    ozayn_roe_service_shutdown(&svc);
    return 0;
}

/* ============================================================
 * SUBSYSTEM BINDING TESTS
 * ============================================================ */

TEST(test_roe_set_subsystems_null) {
    ASSERT_EQ(ozayn_roe_set_readiness(NULL, NULL), OZAYN_ROE_ERR_NULL);
    ASSERT_EQ(ozayn_roe_set_audit(NULL, NULL), OZAYN_ROE_ERR_NULL);
    ASSERT_EQ(ozayn_roe_set_safety(NULL, NULL), OZAYN_ROE_ERR_NULL);
    ASSERT_EQ(ozayn_roe_set_resource_manager(NULL, NULL), OZAYN_ROE_ERR_NULL);
    ASSERT_EQ(ozayn_roe_set_component_registry(NULL, NULL), OZAYN_ROE_ERR_NULL);
    ASSERT_EQ(ozayn_roe_set_device_session(NULL, NULL), OZAYN_ROE_ERR_NULL);
    ASSERT_EQ(ozayn_roe_set_operation_queue(NULL, NULL), OZAYN_ROE_ERR_NULL);
    ASSERT_EQ(ozayn_roe_set_operation_history(NULL, NULL), OZAYN_ROE_ERR_NULL);
    ASSERT_EQ(ozayn_roe_set_pipeline_scheduler(NULL, NULL), OZAYN_ROE_ERR_NULL);
    ASSERT_EQ(ozayn_roe_set_workflow_orchestrator(NULL, NULL), OZAYN_ROE_ERR_NULL);
    ASSERT_EQ(ozayn_roe_set_pipeline_coordinator(NULL, NULL), OZAYN_ROE_ERR_NULL);
    ASSERT_EQ(ozayn_roe_set_events_engine(NULL, NULL), OZAYN_ROE_ERR_NULL);
    ASSERT_EQ(ozayn_roe_set_diagnostics(NULL, NULL), OZAYN_ROE_ERR_NULL);
    ASSERT_EQ(ozayn_roe_set_command_router(NULL, NULL), OZAYN_ROE_ERR_NULL);
    ASSERT_EQ(ozayn_roe_set_mode_transition_policy(NULL, NULL), OZAYN_ROE_ERR_NULL);
    return 0;
}

TEST(test_roe_set_all_subsystems) {
    ozayn_roe_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_roe_service_init(&svc, NULL);
    int a=1,b=2,c=3,d=4,e=5,f=6,g=7,h=8,i=9,j=10,k=11,l=12,m=13,n=14,o=15;
    ASSERT_EQ(ozayn_roe_set_readiness(&svc, &a), OZAYN_ROE_OK);
    ASSERT_EQ(ozayn_roe_set_audit(&svc, &b), OZAYN_ROE_OK);
    ASSERT_EQ(ozayn_roe_set_safety(&svc, &c), OZAYN_ROE_OK);
    ASSERT_EQ(ozayn_roe_set_resource_manager(&svc, &d), OZAYN_ROE_OK);
    ASSERT_EQ(ozayn_roe_set_component_registry(&svc, &e), OZAYN_ROE_OK);
    ASSERT_EQ(ozayn_roe_set_device_session(&svc, &f), OZAYN_ROE_OK);
    ASSERT_EQ(ozayn_roe_set_operation_queue(&svc, &g), OZAYN_ROE_OK);
    ASSERT_EQ(ozayn_roe_set_operation_history(&svc, &h), OZAYN_ROE_OK);
    ASSERT_EQ(ozayn_roe_set_pipeline_scheduler(&svc, &i), OZAYN_ROE_OK);
    ASSERT_EQ(ozayn_roe_set_workflow_orchestrator(&svc, &j), OZAYN_ROE_OK);
    ASSERT_EQ(ozayn_roe_set_pipeline_coordinator(&svc, &k), OZAYN_ROE_OK);
    ASSERT_EQ(ozayn_roe_set_events_engine(&svc, &l), OZAYN_ROE_OK);
    ASSERT_EQ(ozayn_roe_set_diagnostics(&svc, &m), OZAYN_ROE_OK);
    ASSERT_EQ(ozayn_roe_set_command_router(&svc, &n), OZAYN_ROE_OK);
    ASSERT_EQ(ozayn_roe_set_mode_transition_policy(&svc, &o), OZAYN_ROE_OK);
    ozayn_roe_service_shutdown(&svc);
    return 0;
}

/* ============================================================
 * ENFORCEMENT — BASIC TESTS
 * ============================================================ */

TEST(test_roe_enforce_null) {
    ozayn_roe_enforcement_t out;
    ASSERT_EQ(ozayn_roe_enforce(NULL, NULL, NULL, &out), OZAYN_ROE_ERR_NULL);
    return 0;
}

TEST(test_roe_enforce_not_init) {
    ozayn_roe_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_roe_request_t req = _make_request("R1", "OP1");
    ozayn_roe_context_t ctx = _make_ready_ctx();
    ozayn_roe_enforcement_t out;
    ASSERT_EQ(ozayn_roe_enforce(&svc, &req, &ctx, &out), OZAYN_ROE_ERR_NOT_INITIALIZED);
    return 0;
}

TEST(test_roe_enforce_empty_request_id) {
    ozayn_roe_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_roe_service_init(&svc, NULL);
    ozayn_roe_request_t req;
    memset(&req, 0, sizeof(req));
    ozayn_roe_context_t ctx = _make_ready_ctx();
    ozayn_roe_enforcement_t out;
    ASSERT_EQ(ozayn_roe_enforce(&svc, &req, &ctx, &out), OZAYN_ROE_OK);
    ASSERT_EQ(out.decision, OZAYN_ROE_DECISION_BLOCK_DISPATCH);
    ASSERT_EQ(out.phase, OZAYN_ROE_PHASE_REJECTED);
    ozayn_roe_service_shutdown(&svc);
    return 0;
}

TEST(test_roe_enforce_valid_ready) {
    ozayn_roe_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_roe_service_init(&svc, NULL);
    ozayn_roe_request_t req = _make_request("R1", "OP1");
    ozayn_roe_context_t ctx = _make_ready_ctx();
    ozayn_roe_enforcement_t out;
    ASSERT_EQ(ozayn_roe_enforce(&svc, &req, &ctx, &out), OZAYN_ROE_OK);
    ASSERT_EQ(out.decision, OZAYN_ROE_DECISION_ALLOW_DISPATCH);
    ASSERT_EQ(out.phase, OZAYN_ROE_PHASE_APPROVED);
    ASSERT(out.active);
    ozayn_roe_service_shutdown(&svc);
    return 0;
}

TEST(test_roe_enforce_records_request) {
    ozayn_roe_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_roe_service_init(&svc, NULL);
    ozayn_roe_request_t req = _make_request("R1", "OP1");
    ozayn_roe_context_t ctx = _make_ready_ctx();
    ozayn_roe_enforcement_t out;
    ozayn_roe_enforce(&svc, &req, &ctx, &out);
    ASSERT_EQ(ozayn_roe_request_count(&svc), 1);
    ozayn_roe_request_t stored;
    ASSERT_EQ(ozayn_roe_get_request(&svc, "R1", &stored), OZAYN_ROE_OK);
    ASSERT(strcmp(stored.operation_id, "OP1") == 0);
    ozayn_roe_service_shutdown(&svc);
    return 0;
}

TEST(test_roe_enforce_records_decision) {
    ozayn_roe_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_roe_service_init(&svc, NULL);
    ozayn_roe_request_t req = _make_request("R1", "OP1");
    ozayn_roe_context_t ctx = _make_ready_ctx();
    ozayn_roe_enforcement_t out;
    ozayn_roe_enforce(&svc, &req, &ctx, &out);
    ASSERT_EQ(ozayn_roe_decision_count(&svc), 1);
    ozayn_roe_enforcement_t stored;
    ASSERT_EQ(ozayn_roe_get_decision(&svc, out.id, &stored), OZAYN_ROE_OK);
    ASSERT_EQ(stored.decision, OZAYN_ROE_DECISION_ALLOW_DISPATCH);
    ozayn_roe_service_shutdown(&svc);
    return 0;
}

TEST(test_roe_enforce_generates_ids) {
    ozayn_roe_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_roe_service_init(&svc, NULL);
    ozayn_roe_request_t r1 = _make_request("R1", "OP1");
    ozayn_roe_request_t r2 = _make_request("R2", "OP2");
    ozayn_roe_context_t ctx = _make_ready_ctx();
    ozayn_roe_enforcement_t d1, d2;
    ozayn_roe_enforce(&svc, &r1, &ctx, &d1);
    ozayn_roe_enforce(&svc, &r2, &ctx, &d2);
    ASSERT(strcmp(d1.id, d2.id) != 0);
    ozayn_roe_service_shutdown(&svc);
    return 0;
}

/* ============================================================
 * MODE ENFORCEMENT TESTS
 * ============================================================ */

TEST(test_roe_mode_ready_degraded) {
    ozayn_roe_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_roe_service_init(&svc, NULL);
    ozayn_roe_request_t req = _make_request("R1", "OP1");
    ozayn_roe_context_t ctx = _make_ready_ctx();
    ctx.runtime_mode = OZAYN_ORD_MODE_READY_DEGRADED;
    ozayn_roe_enforcement_t out;
    ASSERT_EQ(ozayn_roe_enforce(&svc, &req, &ctx, &out), OZAYN_ROE_OK);
    ASSERT_EQ(out.decision, OZAYN_ROE_DECISION_ALLOW_DISPATCH);
    ASSERT(out.warning_count > 0);
    ozayn_roe_service_shutdown(&svc);
    return 0;
}

TEST(test_roe_mode_recovery) {
    ozayn_roe_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_roe_service_init(&svc, NULL);
    ozayn_roe_request_t req = _make_request("R1", "OP1");
    ozayn_roe_context_t ctx = _make_ready_ctx();
    ctx.runtime_mode = OZAYN_ORD_MODE_RECOVERY;
    ozayn_roe_enforcement_t out;
    ASSERT_EQ(ozayn_roe_enforce(&svc, &req, &ctx, &out), OZAYN_ROE_OK);
    ASSERT_EQ(out.decision, OZAYN_ROE_DECISION_REQUIRE_MODE_RECHECK);
    ASSERT_EQ(out.phase, OZAYN_ROE_PHASE_MODE_CHECK);
    ozayn_roe_service_shutdown(&svc);
    return 0;
}

TEST(test_roe_mode_maintenance) {
    ozayn_roe_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_roe_service_init(&svc, NULL);
    ozayn_roe_request_t req = _make_request("R1", "OP1");
    ozayn_roe_context_t ctx = _make_ready_ctx();
    ctx.runtime_mode = OZAYN_ORD_MODE_MAINTENANCE;
    ozayn_roe_enforcement_t out;
    ASSERT_EQ(ozayn_roe_enforce(&svc, &req, &ctx, &out), OZAYN_ROE_OK);
    ASSERT_EQ(out.decision, OZAYN_ROE_DECISION_REQUIRE_MODE_RECHECK);
    ozayn_roe_service_shutdown(&svc);
    return 0;
}

TEST(test_roe_mode_safe_hold) {
    ozayn_roe_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_roe_service_init(&svc, NULL);
    ozayn_roe_request_t req = _make_request("R1", "OP1");
    ozayn_roe_context_t ctx = _make_ready_ctx();
    ctx.runtime_mode = OZAYN_ORD_MODE_SAFE_HOLD;
    ozayn_roe_enforcement_t out;
    ASSERT_EQ(ozayn_roe_enforce(&svc, &req, &ctx, &out), OZAYN_ROE_OK);
    ASSERT_EQ(out.decision, OZAYN_ROE_DECISION_BLOCK_DISPATCH);
    ASSERT_EQ(out.phase, OZAYN_ROE_PHASE_BLOCKED);
    ozayn_roe_service_shutdown(&svc);
    return 0;
}

TEST(test_roe_mode_blocked) {
    ozayn_roe_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_roe_service_init(&svc, NULL);
    ozayn_roe_request_t req = _make_request("R1", "OP1");
    ozayn_roe_context_t ctx = _make_ready_ctx();
    ctx.runtime_mode = OZAYN_ORD_MODE_BLOCKED;
    ozayn_roe_enforcement_t out;
    ASSERT_EQ(ozayn_roe_enforce(&svc, &req, &ctx, &out), OZAYN_ROE_OK);
    ASSERT_EQ(out.decision, OZAYN_ROE_DECISION_BLOCK_DISPATCH);
    ozayn_roe_service_shutdown(&svc);
    return 0;
}

TEST(test_roe_mode_shutting_down) {
    ozayn_roe_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_roe_service_init(&svc, NULL);
    ozayn_roe_request_t req = _make_request("R1", "OP1");
    ozayn_roe_context_t ctx = _make_ready_ctx();
    ctx.runtime_mode = OZAYN_ORD_MODE_SHUTTING_DOWN;
    ozayn_roe_enforcement_t out;
    ASSERT_EQ(ozayn_roe_enforce(&svc, &req, &ctx, &out), OZAYN_ROE_OK);
    ASSERT_EQ(out.decision, OZAYN_ROE_DECISION_BLOCK_DISPATCH);
    ozayn_roe_service_shutdown(&svc);
    return 0;
}

TEST(test_roe_mode_failed) {
    ozayn_roe_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_roe_service_init(&svc, NULL);
    ozayn_roe_request_t req = _make_request("R1", "OP1");
    ozayn_roe_context_t ctx = _make_ready_ctx();
    ctx.runtime_mode = OZAYN_ORD_MODE_FAILED;
    ozayn_roe_enforcement_t out;
    ASSERT_EQ(ozayn_roe_enforce(&svc, &req, &ctx, &out), OZAYN_ROE_OK);
    ASSERT_EQ(out.decision, OZAYN_ROE_DECISION_BLOCK_DISPATCH);
    ozayn_roe_service_shutdown(&svc);
    return 0;
}

TEST(test_roe_mode_unknown) {
    ozayn_roe_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_roe_service_init(&svc, NULL);
    ozayn_roe_request_t req = _make_request("R1", "OP1");
    ozayn_roe_context_t ctx = _make_ready_ctx();
    ctx.runtime_mode = OZAYN_ORD_MODE_UNKNOWN;
    ozayn_roe_enforcement_t out;
    ASSERT_EQ(ozayn_roe_enforce(&svc, &req, &ctx, &out), OZAYN_ROE_OK);
    ASSERT_EQ(out.decision, OZAYN_ROE_DECISION_REQUIRE_MODE_RECHECK);
    ozayn_roe_service_shutdown(&svc);
    return 0;
}

TEST(test_roe_mode_initializing) {
    ozayn_roe_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_roe_service_init(&svc, NULL);
    ozayn_roe_request_t req = _make_request("R1", "OP1");
    ozayn_roe_context_t ctx = _make_ready_ctx();
    ctx.runtime_mode = OZAYN_ORD_MODE_INITIALIZING;
    ozayn_roe_enforcement_t out;
    ASSERT_EQ(ozayn_roe_enforce(&svc, &req, &ctx, &out), OZAYN_ROE_OK);
    ASSERT_EQ(out.decision, OZAYN_ROE_DECISION_REQUIRE_MODE_RECHECK);
    ozayn_roe_service_shutdown(&svc);
    return 0;
}

/* ============================================================
 * OPERATION STATE ENFORCEMENT TESTS
 * ============================================================ */

TEST(test_roe_operation_cancelled) {
    ozayn_roe_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_roe_service_init(&svc, NULL);
    ozayn_roe_request_t req = _make_request("R1", "OP1");
    ozayn_roe_context_t ctx = _make_ready_ctx();
    ctx.operation_cancelled = 1;
    ozayn_roe_enforcement_t out;
    ASSERT_EQ(ozayn_roe_enforce(&svc, &req, &ctx, &out), OZAYN_ROE_OK);
    ASSERT_EQ(out.decision, OZAYN_ROE_DECISION_BLOCK_DISPATCH);
    ASSERT(!out.operation_valid);
    ozayn_roe_service_shutdown(&svc);
    return 0;
}

TEST(test_roe_operation_expired) {
    ozayn_roe_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_roe_service_init(&svc, NULL);
    ozayn_roe_request_t req = _make_request("R1", "OP1");
    ozayn_roe_context_t ctx = _make_ready_ctx();
    ctx.operation_expired = 1;
    ozayn_roe_enforcement_t out;
    ASSERT_EQ(ozayn_roe_enforce(&svc, &req, &ctx, &out), OZAYN_ROE_OK);
    ASSERT_EQ(out.decision, OZAYN_ROE_DECISION_BLOCK_DISPATCH);
    ASSERT(!out.operation_valid);
    ozayn_roe_service_shutdown(&svc);
    return 0;
}

TEST(test_roe_operation_inactive) {
    ozayn_roe_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_roe_service_init(&svc, NULL);
    ozayn_roe_request_t req = _make_request("R1", "OP1");
    ozayn_roe_context_t ctx = _make_ready_ctx();
    ctx.operation_active = 0;
    ozayn_roe_enforcement_t out;
    ASSERT_EQ(ozayn_roe_enforce(&svc, &req, &ctx, &out), OZAYN_ROE_OK);
    ASSERT_EQ(out.decision, OZAYN_ROE_DECISION_BLOCK_DISPATCH);
    ASSERT(!out.operation_valid);
    ozayn_roe_service_shutdown(&svc);
    return 0;
}

TEST(test_roe_duplicate_detected) {
    ozayn_roe_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_roe_service_init(&svc, NULL);
    ozayn_roe_request_t req = _make_request("R1", "OP1");
    ozayn_roe_context_t ctx = _make_ready_ctx();
    ctx.duplicate_detected = 1;
    ozayn_roe_enforcement_t out;
    ASSERT_EQ(ozayn_roe_enforce(&svc, &req, &ctx, &out), OZAYN_ROE_OK);
    ASSERT_EQ(out.decision, OZAYN_ROE_DECISION_BLOCK_DISPATCH);
    ASSERT(!out.operation_valid);
    const ozayn_roe_stats_t *s = ozayn_roe_get_stats(&svc);
    ASSERT_EQ(s->total_duplicates_blocked, 1);
    ozayn_roe_service_shutdown(&svc);
    return 0;
}

/* ============================================================
 * SECURITY / SAFETY / RESOURCE / DEVICE TESTS
 * ============================================================ */

TEST(test_roe_readiness_not_satisfied) {
    ozayn_roe_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_roe_service_init(&svc, NULL);
    ozayn_roe_request_t req = _make_request("R1", "OP1");
    ozayn_roe_context_t ctx = _make_ready_ctx();
    ctx.readiness_satisfied = 0;
    ozayn_roe_enforcement_t out;
    ASSERT_EQ(ozayn_roe_enforce(&svc, &req, &ctx, &out), OZAYN_ROE_OK);
    ASSERT_EQ(out.decision, OZAYN_ROE_DECISION_REQUIRE_REASSESSMENT);
    ozayn_roe_service_shutdown(&svc);
    return 0;
}

TEST(test_roe_target_unavailable) {
    ozayn_roe_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_roe_service_init(&svc, NULL);
    ozayn_roe_request_t req = _make_request("R1", "OP1");
    strncpy(req.target_component_id, "comp1", OZAYN_ROE_MAX_NAME_LEN - 1);
    ozayn_roe_context_t ctx = _make_ready_ctx();
    ctx.component_available = 0;
    ozayn_roe_enforcement_t out;
    ASSERT_EQ(ozayn_roe_enforce(&svc, &req, &ctx, &out), OZAYN_ROE_OK);
    ASSERT_EQ(out.decision, OZAYN_ROE_DECISION_BLOCK_DISPATCH);
    ASSERT(!out.target_valid);
    ozayn_roe_service_shutdown(&svc);
    return 0;
}

TEST(test_roe_no_target_always_ok) {
    ozayn_roe_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_roe_service_init(&svc, NULL);
    ozayn_roe_request_t req = _make_request("R1", "OP1");
    ozayn_roe_context_t ctx = _make_ready_ctx();
    ctx.component_available = 0;
    ozayn_roe_enforcement_t out;
    ASSERT_EQ(ozayn_roe_enforce(&svc, &req, &ctx, &out), OZAYN_ROE_OK);
    ASSERT_EQ(out.decision, OZAYN_ROE_DECISION_ALLOW_DISPATCH);
    ozayn_roe_service_shutdown(&svc);
    return 0;
}

TEST(test_roe_capability_unavailable) {
    ozayn_roe_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_roe_service_init(&svc, NULL);
    ozayn_roe_request_t req = _make_request("R1", "OP1");
    strncpy(req.capability_id, "cap1", OZAYN_ROE_MAX_NAME_LEN - 1);
    ozayn_roe_context_t ctx = _make_ready_ctx();
    ctx.capability_available = 0;
    ozayn_roe_enforcement_t out;
    ASSERT_EQ(ozayn_roe_enforce(&svc, &req, &ctx, &out), OZAYN_ROE_OK);
    ASSERT_EQ(out.decision, OZAYN_ROE_DECISION_BLOCK_DISPATCH);
    ASSERT(!out.capability_valid);
    ozayn_roe_service_shutdown(&svc);
    return 0;
}

TEST(test_roe_security_session_invalid) {
    ozayn_roe_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_roe_service_init(&svc, NULL);
    ozayn_roe_request_t req = _make_request("R1", "OP1");
    strncpy(req.security_session_ref, "sess1", OZAYN_ROE_MAX_CORRELATION_LEN - 1);
    ozayn_roe_context_t ctx = _make_ready_ctx();
    ctx.security_session_valid = 0;
    ozayn_roe_enforcement_t out;
    ASSERT_EQ(ozayn_roe_enforce(&svc, &req, &ctx, &out), OZAYN_ROE_OK);
    ASSERT_EQ(out.decision, OZAYN_ROE_DECISION_REQUIRE_AUTHORIZATION);
    ASSERT(!out.security_valid);
    ozayn_roe_service_shutdown(&svc);
    return 0;
}

TEST(test_roe_authorization_failed) {
    ozayn_roe_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_roe_service_init(&svc, NULL);
    ozayn_roe_request_t req = _make_request("R1", "OP1");
    strncpy(req.security_session_ref, "sess1", OZAYN_ROE_MAX_CORRELATION_LEN - 1);
    ozayn_roe_context_t ctx = _make_ready_ctx();
    ctx.authorization_valid = 0;
    ozayn_roe_enforcement_t out;
    ASSERT_EQ(ozayn_roe_enforce(&svc, &req, &ctx, &out), OZAYN_ROE_OK);
    ASSERT_EQ(out.decision, OZAYN_ROE_DECISION_REQUIRE_AUTHORIZATION);
    ASSERT(!out.authorization_valid);
    ozayn_roe_service_shutdown(&svc);
    return 0;
}

TEST(test_roe_safety_failed) {
    ozayn_roe_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_roe_service_init(&svc, NULL);
    ozayn_roe_request_t req = _make_request("R1", "OP1");
    ozayn_roe_context_t ctx = _make_ready_ctx();
    ctx.safety_policy_valid = 0;
    ozayn_roe_enforcement_t out;
    ASSERT_EQ(ozayn_roe_enforce(&svc, &req, &ctx, &out), OZAYN_ROE_OK);
    ASSERT_EQ(out.decision, OZAYN_ROE_DECISION_REQUIRE_SAFETY_RECHECK);
    ASSERT(!out.safety_valid);
    ozayn_roe_service_shutdown(&svc);
    return 0;
}

TEST(test_roe_resource_unavailable) {
    ozayn_roe_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_roe_service_init(&svc, NULL);
    ozayn_roe_request_t req = _make_request("R1", "OP1");
    ozayn_roe_context_t ctx = _make_ready_ctx();
    ctx.resources_available = 0;
    ozayn_roe_enforcement_t out;
    ASSERT_EQ(ozayn_roe_enforce(&svc, &req, &ctx, &out), OZAYN_ROE_OK);
    ASSERT_EQ(out.decision, OZAYN_ROE_DECISION_REQUIRE_RESOURCE_RECHECK);
    ASSERT(!out.resource_valid);
    ozayn_roe_service_shutdown(&svc);
    return 0;
}

TEST(test_roe_device_unavailable) {
    ozayn_roe_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_roe_service_init(&svc, NULL);
    ozayn_roe_request_t req = _make_request("R1", "OP1");
    ozayn_roe_context_t ctx = _make_ready_ctx();
    ctx.devices_available = 0;
    ozayn_roe_enforcement_t out;
    ASSERT_EQ(ozayn_roe_enforce(&svc, &req, &ctx, &out), OZAYN_ROE_OK);
    ASSERT_EQ(out.decision, OZAYN_ROE_DECISION_REQUIRE_DEVICE_RECHECK);
    ASSERT(!out.device_valid);
    ozayn_roe_service_shutdown(&svc);
    return 0;
}

TEST(test_roe_workflow_blocked) {
    ozayn_roe_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_roe_service_init(&svc, NULL);
    ozayn_roe_request_t req = _make_request("R1", "OP1");
    strncpy(req.workflow_id, "wf1", OZAYN_ROE_MAX_ID_LEN - 1);
    ozayn_roe_context_t ctx = _make_ready_ctx();
    ctx.workflow_valid = 0;
    ozayn_roe_enforcement_t out;
    ASSERT_EQ(ozayn_roe_enforce(&svc, &req, &ctx, &out), OZAYN_ROE_OK);
    ASSERT_EQ(out.decision, OZAYN_ROE_DECISION_BLOCK_DISPATCH);
    ASSERT(!out.workflow_valid);
    ozayn_roe_service_shutdown(&svc);
    return 0;
}

TEST(test_roe_pipeline_blocked) {
    ozayn_roe_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_roe_service_init(&svc, NULL);
    ozayn_roe_request_t req = _make_request("R1", "OP1");
    strncpy(req.pipeline_id, "pl1", OZAYN_ROE_MAX_ID_LEN - 1);
    ozayn_roe_context_t ctx = _make_ready_ctx();
    ctx.pipeline_valid = 0;
    ozayn_roe_enforcement_t out;
    ASSERT_EQ(ozayn_roe_enforce(&svc, &req, &ctx, &out), OZAYN_ROE_OK);
    ASSERT_EQ(out.decision, OZAYN_ROE_DECISION_BLOCK_DISPATCH);
    ASSERT(!out.pipeline_valid);
    ozayn_roe_service_shutdown(&svc);
    return 0;
}

TEST(test_roe_dependency_failed) {
    ozayn_roe_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_roe_service_init(&svc, NULL);
    ozayn_roe_request_t req = _make_request("R1", "OP1");
    ozayn_roe_context_t ctx = _make_ready_ctx();
    ctx.dependencies_satisfied = 0;
    ozayn_roe_enforcement_t out;
    ASSERT_EQ(ozayn_roe_enforce(&svc, &req, &ctx, &out), OZAYN_ROE_OK);
    ASSERT_EQ(out.decision, OZAYN_ROE_DECISION_REQUIRE_REASSESSMENT);
    ASSERT(!out.dependency_valid);
    ozayn_roe_service_shutdown(&svc);
    return 0;
}

/* ============================================================
 * QUICK CHECK TESTS
 * ============================================================ */

TEST(test_roe_can_dispatch_null) {
    ASSERT(!ozayn_roe_can_dispatch(NULL, NULL, NULL));
    return 0;
}

TEST(test_roe_can_dispatch_not_init) {
    ozayn_roe_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_roe_request_t req = _make_request("R1", "OP1");
    ozayn_roe_context_t ctx = _make_ready_ctx();
    ASSERT(!ozayn_roe_can_dispatch(&svc, &req, &ctx));
    return 0;
}

TEST(test_roe_can_dispatch_ready) {
    ozayn_roe_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_roe_service_init(&svc, NULL);
    ozayn_roe_request_t req = _make_request("R1", "OP1");
    ozayn_roe_context_t ctx = _make_ready_ctx();
    ASSERT(ozayn_roe_can_dispatch(&svc, &req, &ctx));
    ozayn_roe_service_shutdown(&svc);
    return 0;
}

TEST(test_roe_can_dispatch_blocked_mode) {
    ozayn_roe_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_roe_service_init(&svc, NULL);
    ozayn_roe_request_t req = _make_request("R1", "OP1");
    ozayn_roe_context_t ctx = _make_ready_ctx();
    ctx.runtime_mode = OZAYN_ORD_MODE_BLOCKED;
    ASSERT(!ozayn_roe_can_dispatch(&svc, &req, &ctx));
    ozayn_roe_service_shutdown(&svc);
    return 0;
}

TEST(test_roe_can_dispatch_empty_id) {
    ozayn_roe_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_roe_service_init(&svc, NULL);
    ozayn_roe_request_t req;
    memset(&req, 0, sizeof(req));
    ozayn_roe_context_t ctx = _make_ready_ctx();
    ASSERT(!ozayn_roe_can_dispatch(&svc, &req, &ctx));
    ozayn_roe_service_shutdown(&svc);
    return 0;
}

TEST(test_roe_can_dispatch_operation_cancelled) {
    ozayn_roe_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_roe_service_init(&svc, NULL);
    ozayn_roe_request_t req = _make_request("R1", "OP1");
    ozayn_roe_context_t ctx = _make_ready_ctx();
    ctx.operation_cancelled = 1;
    ASSERT(!ozayn_roe_can_dispatch(&svc, &req, &ctx));
    ozayn_roe_service_shutdown(&svc);
    return 0;
}

TEST(test_roe_can_dispatch_no_safety) {
    ozayn_roe_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_roe_service_init(&svc, NULL);
    ozayn_roe_request_t req = _make_request("R1", "OP1");
    ozayn_roe_context_t ctx = _make_ready_ctx();
    ctx.safety_policy_valid = 0;
    ASSERT(!ozayn_roe_can_dispatch(&svc, &req, &ctx));
    ozayn_roe_service_shutdown(&svc);
    return 0;
}

TEST(test_roe_can_dispatch_duplicate) {
    ozayn_roe_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_roe_service_init(&svc, NULL);
    ozayn_roe_request_t req = _make_request("R1", "OP1");
    ozayn_roe_context_t ctx = _make_ready_ctx();
    ctx.duplicate_detected = 1;
    ASSERT(!ozayn_roe_can_dispatch(&svc, &req, &ctx));
    ozayn_roe_service_shutdown(&svc);
    return 0;
}

/* ============================================================
 * EXPIRATION TEST
 * ============================================================ */

TEST(test_roe_enforce_expired_request) {
    ozayn_roe_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_roe_service_init(&svc, NULL);
    ozayn_roe_request_t req = _make_request("R1", "OP1");
    req.expiration_ms = 1;
    ozayn_roe_context_t ctx = _make_ready_ctx();
    ozayn_roe_enforcement_t out;
    ASSERT_EQ(ozayn_roe_enforce(&svc, &req, &ctx, &out), OZAYN_ROE_OK);
    ASSERT_EQ(out.decision, OZAYN_ROE_DECISION_EXPIRED);
    ASSERT_EQ(out.phase, OZAYN_ROE_PHASE_EXPIRED);
    ozayn_roe_service_shutdown(&svc);
    return 0;
}

/* ============================================================
 * REASSESSMENT TESTS
 * ============================================================ */

TEST(test_roe_reassess_null) {
    ozayn_roe_context_t ctx = _make_ready_ctx();
    ozayn_roe_enforcement_t out;
    ASSERT_EQ(ozayn_roe_reassess(NULL, NULL, &ctx, &out), OZAYN_ROE_ERR_NULL);
    return 0;
}

TEST(test_roe_reassess_not_found) {
    ozayn_roe_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_roe_service_init(&svc, NULL);
    ozayn_roe_context_t ctx = _make_ready_ctx();
    ozayn_roe_enforcement_t out;
    ASSERT_EQ(ozayn_roe_reassess(&svc, "NONEXISTENT", &ctx, &out),
              OZAYN_ROE_ERR_NOT_FOUND);
    ozayn_roe_service_shutdown(&svc);
    return 0;
}

TEST(test_roe_reassess_ok) {
    ozayn_roe_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_roe_service_init(&svc, NULL);
    ozayn_roe_request_t req = _make_request("R1", "OP1");
    ozayn_roe_context_t ctx = _make_ready_ctx();
    ctx.resources_available = 0;
    ozayn_roe_enforcement_t d1;
    ASSERT_EQ(ozayn_roe_enforce(&svc, &req, &ctx, &d1), OZAYN_ROE_OK);
    ASSERT_EQ(d1.decision, OZAYN_ROE_DECISION_REQUIRE_RESOURCE_RECHECK);

    ctx.resources_available = 1;
    ozayn_roe_enforcement_t d2;
    ASSERT_EQ(ozayn_roe_reassess(&svc, d1.id, &ctx, &d2), OZAYN_ROE_OK);
    ASSERT_EQ(d2.decision, OZAYN_ROE_DECISION_ALLOW_DISPATCH);
    ASSERT_EQ(d2.reassessment_count, 1);

    /* Old decision should be invalidated */
    ozayn_roe_enforcement_t check;
    ASSERT_EQ(ozayn_roe_get_decision(&svc, d1.id, &check), OZAYN_ROE_ERR_NOT_FOUND);
    ozayn_roe_service_shutdown(&svc);
    return 0;
}

TEST(test_roe_reassess_limit) {
    ozayn_roe_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_roe_service_init(&svc, NULL);
    ozayn_roe_request_t req = _make_request("R1", "OP1");
    ozayn_roe_context_t ctx = _make_ready_ctx();
    ctx.resources_available = 0;
    ozayn_roe_enforcement_t d;
    ozayn_roe_enforce(&svc, &req, &ctx, &d);

    /* Reassess up to limit */
    ctx.resources_available = 1;
    ozayn_roe_enforcement_t d2;
    ozayn_roe_reassess(&svc, d.id, &ctx, &d2);

    ozayn_roe_enforcement_t d3;
    ctx.resources_available = 0;
    ozayn_roe_reassess(&svc, d2.id, &ctx, &d3);

    ozayn_roe_enforcement_t d4;
    ctx.resources_available = 1;
    ozayn_roe_reassess(&svc, d3.id, &ctx, &d4);

    /* One more should hit limit */
    ozayn_roe_enforcement_t d5;
    ctx.resources_available = 0;
    ozayn_roe_err_t rc = ozayn_roe_reassess(&svc, d4.id, &ctx, &d5);
    ASSERT_EQ(rc, OZAYN_ROE_OK);
    ASSERT_EQ(d5.decision, OZAYN_ROE_DECISION_BLOCK_DISPATCH);
    ozayn_roe_service_shutdown(&svc);
    return 0;
}

/* ============================================================
 * INVALIDATION TESTS
 * ============================================================ */

TEST(test_roe_invalidate_null) {
    ASSERT_EQ(ozayn_roe_invalidate(NULL, NULL), OZAYN_ROE_ERR_NULL);
    return 0;
}

TEST(test_roe_invalidate_not_found) {
    ozayn_roe_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_roe_service_init(&svc, NULL);
    ASSERT_EQ(ozayn_roe_invalidate(&svc, "NONEXISTENT"), OZAYN_ROE_ERR_NOT_FOUND);
    ozayn_roe_service_shutdown(&svc);
    return 0;
}

TEST(test_roe_invalidate_ok) {
    ozayn_roe_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_roe_service_init(&svc, NULL);
    ozayn_roe_request_t req = _make_request("R1", "OP1");
    ozayn_roe_context_t ctx = _make_ready_ctx();
    ozayn_roe_enforcement_t d;
    ozayn_roe_enforce(&svc, &req, &ctx, &d);
    ASSERT_EQ(ozayn_roe_invalidate(&svc, d.id), OZAYN_ROE_OK);
    ASSERT_EQ(svc.stats.total_invalidated, 1);
    ozayn_roe_enforcement_t check;
    ASSERT_EQ(ozayn_roe_get_decision(&svc, d.id, &check), OZAYN_ROE_ERR_NOT_FOUND);
    ozayn_roe_service_shutdown(&svc);
    return 0;
}

TEST(test_roe_invalidate_already_invalidated) {
    ozayn_roe_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_roe_service_init(&svc, NULL);
    ozayn_roe_request_t req = _make_request("R1", "OP1");
    ozayn_roe_context_t ctx = _make_ready_ctx();
    ozayn_roe_enforcement_t d;
    ozayn_roe_enforce(&svc, &req, &ctx, &d);
    ASSERT_EQ(ozayn_roe_invalidate(&svc, d.id), OZAYN_ROE_OK);
    ASSERT_EQ(ozayn_roe_invalidate(&svc, d.id), OZAYN_ROE_ERR_INVALIDATED);
    ozayn_roe_service_shutdown(&svc);
    return 0;
}

/* ============================================================
 * DECISION QUERY TESTS
 * ============================================================ */

TEST(test_roe_get_decision_null) {
    ozayn_roe_enforcement_t out;
    ASSERT_EQ(ozayn_roe_get_decision(NULL, "x", &out), OZAYN_ROE_ERR_NULL);
    return 0;
}

TEST(test_roe_get_decision_not_found) {
    ozayn_roe_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_roe_service_init(&svc, NULL);
    ozayn_roe_enforcement_t out;
    ASSERT_EQ(ozayn_roe_get_decision(&svc, "NONEXISTENT", &out),
              OZAYN_ROE_ERR_NOT_FOUND);
    ozayn_roe_service_shutdown(&svc);
    return 0;
}

TEST(test_roe_get_latest_decision_empty) {
    ozayn_roe_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_roe_service_init(&svc, NULL);
    ozayn_roe_enforcement_t out;
    ASSERT_EQ(ozayn_roe_get_latest_decision(&svc, &out), OZAYN_ROE_ERR_NOT_FOUND);
    ozayn_roe_service_shutdown(&svc);
    return 0;
}

TEST(test_roe_get_latest_decision_ok) {
    ozayn_roe_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_roe_service_init(&svc, NULL);
    ozayn_roe_request_t req = _make_request("R1", "OP1");
    ozayn_roe_context_t ctx = _make_ready_ctx();
    ozayn_roe_enforcement_t d;
    ozayn_roe_enforce(&svc, &req, &ctx, &d);
    ozayn_roe_enforcement_t latest;
    ASSERT_EQ(ozayn_roe_get_latest_decision(&svc, &latest), OZAYN_ROE_OK);
    ASSERT(strcmp(latest.id, d.id) == 0);
    ozayn_roe_service_shutdown(&svc);
    return 0;
}

TEST(test_roe_decision_count_null) {
    ASSERT_EQ(ozayn_roe_decision_count(NULL), 0);
    return 0;
}

TEST(test_roe_decision_count_after_enforce) {
    ozayn_roe_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_roe_service_init(&svc, NULL);
    ASSERT_EQ(ozayn_roe_decision_count(&svc), 0);
    ozayn_roe_request_t req = _make_request("R1", "OP1");
    ozayn_roe_context_t ctx = _make_ready_ctx();
    ozayn_roe_enforcement_t d;
    ozayn_roe_enforce(&svc, &req, &ctx, &d);
    ASSERT_EQ(ozayn_roe_decision_count(&svc), 1);
    ozayn_roe_service_shutdown(&svc);
    return 0;
}

/* ============================================================
 * REQUEST QUERY TESTS
 * ============================================================ */

TEST(test_roe_get_request_null) {
    ozayn_roe_request_t out;
    ASSERT_EQ(ozayn_roe_get_request(NULL, "x", &out), OZAYN_ROE_ERR_NULL);
    return 0;
}

TEST(test_roe_get_request_not_found) {
    ozayn_roe_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_roe_service_init(&svc, NULL);
    ozayn_roe_request_t out;
    ASSERT_EQ(ozayn_roe_get_request(&svc, "NONEXISTENT", &out),
              OZAYN_ROE_ERR_NOT_FOUND);
    ozayn_roe_service_shutdown(&svc);
    return 0;
}

TEST(test_roe_request_count_null) {
    ASSERT_EQ(ozayn_roe_request_count(NULL), 0);
    return 0;
}

TEST(test_roe_request_count_after_enforce) {
    ozayn_roe_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_roe_service_init(&svc, NULL);
    ASSERT_EQ(ozayn_roe_request_count(&svc), 0);
    ozayn_roe_request_t req = _make_request("R1", "OP1");
    ozayn_roe_context_t ctx = _make_ready_ctx();
    ozayn_roe_enforcement_t d;
    ozayn_roe_enforce(&svc, &req, &ctx, &d);
    ASSERT_EQ(ozayn_roe_request_count(&svc), 1);
    ozayn_roe_service_shutdown(&svc);
    return 0;
}

/* ============================================================
 * EVENT TESTS
 * ============================================================ */

TEST(test_roe_event_count_null) {
    ASSERT_EQ(ozayn_roe_event_count(NULL), 0);
    return 0;
}

TEST(test_roe_event_count_after_enforce) {
    ozayn_roe_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_roe_service_init(&svc, NULL);
    int before = ozayn_roe_event_count(&svc);
    ozayn_roe_request_t req = _make_request("R1", "OP1");
    ozayn_roe_context_t ctx = _make_ready_ctx();
    ozayn_roe_enforcement_t d;
    ozayn_roe_enforce(&svc, &req, &ctx, &d);
    ASSERT(ozayn_roe_event_count(&svc) > before);
    ozayn_roe_service_shutdown(&svc);
    return 0;
}

TEST(test_roe_get_event_null) {
    ozayn_roe_event_t e;
    ASSERT_EQ(ozayn_roe_get_event(NULL, 0, &e), OZAYN_ROE_ERR_NULL);
    return 0;
}

TEST(test_roe_get_event_out_of_range) {
    ozayn_roe_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_roe_service_init(&svc, NULL);
    ozayn_roe_event_t e;
    ASSERT_EQ(ozayn_roe_get_event(&svc, 9999, &e), OZAYN_ROE_ERR_NOT_FOUND);
    ozayn_roe_service_shutdown(&svc);
    return 0;
}

TEST(test_roe_event_sequence_increments) {
    ozayn_roe_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_roe_service_init(&svc, NULL);

    ozayn_roe_request_t req1 = _make_request("R1", "OP1");
    ozayn_roe_context_t ctx = _make_ready_ctx();
    ozayn_roe_enforcement_t d1;
    ozayn_roe_enforce(&svc, &req1, &ctx, &d1);
    int count1 = ozayn_roe_event_count(&svc);
    ASSERT(count1 >= 2);

    ozayn_roe_event_t e1, e2;
    ASSERT_EQ(ozayn_roe_get_event(&svc, count1 - 2, &e1), OZAYN_ROE_OK);
    ASSERT_EQ(ozayn_roe_get_event(&svc, count1 - 1, &e2), OZAYN_ROE_OK);
    ASSERT(e2.sequence > e1.sequence);
    ozayn_roe_service_shutdown(&svc);
    return 0;
}

/* ============================================================
 * STATS TESTS
 * ============================================================ */

TEST(test_roe_stats_null) {
    ASSERT(ozayn_roe_get_stats(NULL) == NULL);
    return 0;
}

TEST(test_roe_stats_initial_zero) {
    ozayn_roe_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_roe_service_init(&svc, NULL);
    const ozayn_roe_stats_t *s = ozayn_roe_get_stats(&svc);
    ASSERT(s != NULL);
    ASSERT_EQ(s->total_requests, 0);
    ASSERT_EQ(s->total_approved, 0);
    ASSERT_EQ(s->total_blocked, 0);
    ASSERT_EQ(s->total_duplicates_blocked, 0);
    ozayn_roe_service_shutdown(&svc);
    return 0;
}

TEST(test_roe_stats_after_allow) {
    ozayn_roe_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_roe_service_init(&svc, NULL);
    ozayn_roe_request_t req = _make_request("R1", "OP1");
    ozayn_roe_context_t ctx = _make_ready_ctx();
    ozayn_roe_enforcement_t d;
    ozayn_roe_enforce(&svc, &req, &ctx, &d);
    const ozayn_roe_stats_t *s = ozayn_roe_get_stats(&svc);
    ASSERT_EQ(s->total_requests, 1);
    ASSERT_EQ(s->total_approved, 1);
    ozayn_roe_service_shutdown(&svc);
    return 0;
}

TEST(test_roe_stats_after_mode_block) {
    ozayn_roe_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_roe_service_init(&svc, NULL);
    ozayn_roe_request_t req = _make_request("R1", "OP1");
    ozayn_roe_context_t ctx = _make_ready_ctx();
    ctx.runtime_mode = OZAYN_ORD_MODE_BLOCKED;
    ozayn_roe_enforcement_t d;
    ozayn_roe_enforce(&svc, &req, &ctx, &d);
    const ozayn_roe_stats_t *s = ozayn_roe_get_stats(&svc);
    ASSERT_EQ(s->mode_blocks, 1);
    ozayn_roe_service_shutdown(&svc);
    return 0;
}

TEST(test_roe_stats_after_security_block) {
    ozayn_roe_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_roe_service_init(&svc, NULL);
    ozayn_roe_request_t req = _make_request("R1", "OP1");
    strncpy(req.security_session_ref, "sess1", OZAYN_ROE_MAX_CORRELATION_LEN - 1);
    ozayn_roe_context_t ctx = _make_ready_ctx();
    ctx.security_session_valid = 0;
    ozayn_roe_enforcement_t d;
    ozayn_roe_enforce(&svc, &req, &ctx, &d);
    const ozayn_roe_stats_t *s = ozayn_roe_get_stats(&svc);
    ASSERT_EQ(s->security_blocks, 1);
    ozayn_roe_service_shutdown(&svc);
    return 0;
}

TEST(test_roe_stats_after_expire) {
    ozayn_roe_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_roe_service_init(&svc, NULL);
    ozayn_roe_request_t req = _make_request("R1", "OP1");
    req.expiration_ms = 1;
    ozayn_roe_context_t ctx = _make_ready_ctx();
    ozayn_roe_enforcement_t d;
    ozayn_roe_enforce(&svc, &req, &ctx, &d);
    const ozayn_roe_stats_t *s = ozayn_roe_get_stats(&svc);
    ASSERT_EQ(s->total_expired, 1);
    ozayn_roe_service_shutdown(&svc);
    return 0;
}

TEST(test_roe_reset_stats) {
    ozayn_roe_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_roe_service_init(&svc, NULL);
    ozayn_roe_request_t req = _make_request("R1", "OP1");
    ozayn_roe_context_t ctx = _make_ready_ctx();
    ozayn_roe_enforcement_t d;
    ozayn_roe_enforce(&svc, &req, &ctx, &d);
    ASSERT_EQ(ozayn_roe_reset_stats(&svc), OZAYN_ROE_OK);
    const ozayn_roe_stats_t *s = ozayn_roe_get_stats(&svc);
    ASSERT_EQ(s->total_requests, 0);
    ASSERT_EQ(s->total_approved, 0);
    ozayn_roe_service_shutdown(&svc);
    return 0;
}

TEST(test_roe_reset_stats_null) {
    ASSERT_EQ(ozayn_roe_reset_stats(NULL), OZAYN_ROE_ERR_NULL);
    return 0;
}

/* ============================================================
 * NAME HELPERS TESTS
 * ============================================================ */

TEST(test_roe_err_name_all) {
    ASSERT(strcmp(ozayn_roe_err_name(OZAYN_ROE_OK), "OK") == 0);
    ASSERT(strcmp(ozayn_roe_err_name(OZAYN_ROE_ERR_NULL), "NULL") == 0);
    ASSERT(strcmp(ozayn_roe_err_name(OZAYN_ROE_ERR_NOT_INITIALIZED),
                  "NOT_INITIALIZED") == 0);
    ASSERT(strcmp(ozayn_roe_err_name(OZAYN_ROE_ERR_MODE_BLOCKED),
                  "MODE_BLOCKED") == 0);
    ASSERT(strcmp(ozayn_roe_err_name(OZAYN_ROE_ERR_SAFETY_UNAVAILABLE),
                  "SAFETY_UNAVAILABLE") == 0);
    ASSERT(strcmp(ozayn_roe_err_name(OZAYN_ROE_ERR_CONCURRENCY_ERROR),
                  "CONCURRENCY_ERROR") == 0);
    ASSERT(strcmp(ozayn_roe_err_name(OZAYN_ROE_ERR_LIMIT_REACHED),
                  "LIMIT_REACHED") == 0);
    return 0;
}

TEST(test_roe_decision_name_all) {
    ASSERT(strcmp(ozayn_roe_decision_name(OZAYN_ROE_DECISION_ALLOW_DISPATCH),
                  "ALLOW_DISPATCH") == 0);
    ASSERT(strcmp(ozayn_roe_decision_name(OZAYN_ROE_DECISION_BLOCK_DISPATCH),
                  "BLOCK_DISPATCH") == 0);
    ASSERT(strcmp(ozayn_roe_decision_name(OZAYN_ROE_DECISION_REQUIRE_REASSESSMENT),
                  "REQUIRE_REASSESSMENT") == 0);
    ASSERT(strcmp(ozayn_roe_decision_name(OZAYN_ROE_DECISION_REQUIRE_AUTHORIZATION),
                  "REQUIRE_AUTHORIZATION") == 0);
    ASSERT(strcmp(ozayn_roe_decision_name(OZAYN_ROE_DECISION_REQUIRE_SAFETY_RECHECK),
                  "REQUIRE_SAFETY_RECHECK") == 0);
    ASSERT(strcmp(ozayn_roe_decision_name(OZAYN_ROE_DECISION_REQUIRE_RESOURCE_RECHECK),
                  "REQUIRE_RESOURCE_RECHECK") == 0);
    ASSERT(strcmp(ozayn_roe_decision_name(OZAYN_ROE_DECISION_REQUIRE_DEVICE_RECHECK),
                  "REQUIRE_DEVICE_RECHECK") == 0);
    ASSERT(strcmp(ozayn_roe_decision_name(OZAYN_ROE_DECISION_REQUIRE_MODE_RECHECK),
                  "REQUIRE_MODE_RECHECK") == 0);
    ASSERT(strcmp(ozayn_roe_decision_name(OZAYN_ROE_DECISION_EXPIRED),
                  "EXPIRED") == 0);
    ASSERT(strcmp(ozayn_roe_decision_name(OZAYN_ROE_DECISION_UNAVAILABLE),
                  "UNAVAILABLE") == 0);
    return 0;
}

TEST(test_roe_phase_name_all) {
    ASSERT(strcmp(ozayn_roe_phase_name(OZAYN_ROE_PHASE_NONE), "NONE") == 0);
    ASSERT(strcmp(ozayn_roe_phase_name(OZAYN_ROE_PHASE_REQUESTED), "REQUESTED") == 0);
    ASSERT(strcmp(ozayn_roe_phase_name(OZAYN_ROE_PHASE_VALIDATING), "VALIDATING") == 0);
    ASSERT(strcmp(ozayn_roe_phase_name(OZAYN_ROE_PHASE_REVALIDATING), "REVALIDATING") == 0);
    ASSERT(strcmp(ozayn_roe_phase_name(OZAYN_ROE_PHASE_SECURITY_CHECK), "SECURITY_CHECK") == 0);
    ASSERT(strcmp(ozayn_roe_phase_name(OZAYN_ROE_PHASE_SAFETY_CHECK), "SAFETY_CHECK") == 0);
    ASSERT(strcmp(ozayn_roe_phase_name(OZAYN_ROE_PHASE_RESOURCE_CHECK), "RESOURCE_CHECK") == 0);
    ASSERT(strcmp(ozayn_roe_phase_name(OZAYN_ROE_PHASE_DEVICE_CHECK), "DEVICE_CHECK") == 0);
    ASSERT(strcmp(ozayn_roe_phase_name(OZAYN_ROE_PHASE_MODE_CHECK), "MODE_CHECK") == 0);
    ASSERT(strcmp(ozayn_roe_phase_name(OZAYN_ROE_PHASE_TARGET_CHECK), "TARGET_CHECK") == 0);
    ASSERT(strcmp(ozayn_roe_phase_name(OZAYN_ROE_PHASE_APPROVED), "APPROVED") == 0);
    ASSERT(strcmp(ozayn_roe_phase_name(OZAYN_ROE_PHASE_DISPATCHING), "DISPATCHING") == 0);
    ASSERT(strcmp(ozayn_roe_phase_name(OZAYN_ROE_PHASE_DISPATCHED), "DISPATCHED") == 0);
    ASSERT(strcmp(ozayn_roe_phase_name(OZAYN_ROE_PHASE_REJECTED), "REJECTED") == 0);
    ASSERT(strcmp(ozayn_roe_phase_name(OZAYN_ROE_PHASE_BLOCKED), "BLOCKED") == 0);
    ASSERT(strcmp(ozayn_roe_phase_name(OZAYN_ROE_PHASE_EXPIRED), "EXPIRED") == 0);
    ASSERT(strcmp(ozayn_roe_phase_name(OZAYN_ROE_PHASE_FAILED), "FAILED") == 0);
    ASSERT(strcmp(ozayn_roe_phase_name(OZAYN_ROE_PHASE_CANCELLED), "CANCELLED") == 0);
    ASSERT(strcmp(ozayn_roe_phase_name(OZAYN_ROE_PHASE_UNAVAILABLE), "UNAVAILABLE") == 0);
    return 0;
}

TEST(test_roe_event_type_name_all) {
    ASSERT(strcmp(ozayn_roe_event_type_name(OZAYN_ROE_EVENT_REQUESTED), "REQUESTED") == 0);
    ASSERT(strcmp(ozayn_roe_event_type_name(OZAYN_ROE_EVENT_VALIDATING), "VALIDATING") == 0);
    ASSERT(strcmp(ozayn_roe_event_type_name(OZAYN_ROE_EVENT_REVALIDATING), "REVALIDATING") == 0);
    ASSERT(strcmp(ozayn_roe_event_type_name(OZAYN_ROE_EVENT_APPROVED), "APPROVED") == 0);
    ASSERT(strcmp(ozayn_roe_event_type_name(OZAYN_ROE_EVENT_BLOCKED), "BLOCKED") == 0);
    ASSERT(strcmp(ozayn_roe_event_type_name(OZAYN_ROE_EVENT_REASSESSMENT_REQUIRED),
                  "REASSESSMENT_REQUIRED") == 0);
    ASSERT(strcmp(ozayn_roe_event_type_name(OZAYN_ROE_EVENT_AUTHORIZATION_REQUIRED),
                  "AUTHORIZATION_REQUIRED") == 0);
    ASSERT(strcmp(ozayn_roe_event_type_name(OZAYN_ROE_EVENT_SAFETY_CHECK_REQUIRED),
                  "SAFETY_CHECK_REQUIRED") == 0);
    ASSERT(strcmp(ozayn_roe_event_type_name(OZAYN_ROE_EVENT_RESOURCE_CHECK_REQUIRED),
                  "RESOURCE_CHECK_REQUIRED") == 0);
    ASSERT(strcmp(ozayn_roe_event_type_name(OZAYN_ROE_EVENT_DEVICE_CHECK_REQUIRED),
                  "DEVICE_CHECK_REQUIRED") == 0);
    ASSERT(strcmp(ozayn_roe_event_type_name(OZAYN_ROE_EVENT_MODE_CHECK_REQUIRED),
                  "MODE_CHECK_REQUIRED") == 0);
    ASSERT(strcmp(ozayn_roe_event_type_name(OZAYN_ROE_EVENT_DISPATCHING), "DISPATCHING") == 0);
    ASSERT(strcmp(ozayn_roe_event_type_name(OZAYN_ROE_EVENT_DISPATCHED), "DISPATCHED") == 0);
    ASSERT(strcmp(ozayn_roe_event_type_name(OZAYN_ROE_EVENT_EXPIRED), "EXPIRED") == 0);
    ASSERT(strcmp(ozayn_roe_event_type_name(OZAYN_ROE_EVENT_CANCELLED), "CANCELLED") == 0);
    ASSERT(strcmp(ozayn_roe_event_type_name(OZAYN_ROE_EVENT_FAILED), "FAILED") == 0);
    ASSERT(strcmp(ozayn_roe_event_type_name(OZAYN_ROE_EVENT_DUPLICATE_BLOCKED),
                  "DUPLICATE_BLOCKED") == 0);
    return 0;
}

/* ============================================================
 * TOCTOU PROTECTION TESTS
 * ============================================================ */

TEST(test_roe_toctou_mode_change) {
    ozayn_roe_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_roe_service_init(&svc, NULL);

    ozayn_roe_request_t req = _make_request("R1", "OP1");
    ozayn_roe_context_t ctx = _make_ready_ctx();
    ozayn_roe_enforcement_t d;
    ozayn_roe_enforce(&svc, &req, &ctx, &d);
    ASSERT_EQ(d.decision, OZAYN_ROE_DECISION_ALLOW_DISPATCH);

    /* Mode changes to SAFE_HOLD after admission */
    ctx.runtime_mode = OZAYN_ORD_MODE_SAFE_HOLD;
    ASSERT(!ozayn_roe_can_dispatch(&svc, &req, &ctx));

    /* Reassessment should detect the mode change */
    ozayn_roe_enforcement_t d2;
    ozayn_roe_reassess(&svc, d.id, &ctx, &d2);
    ASSERT_EQ(d2.decision, OZAYN_ROE_DECISION_BLOCK_DISPATCH);
    ozayn_roe_service_shutdown(&svc);
    return 0;
}

TEST(test_roe_toctou_resource_exhausted) {
    ozayn_roe_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_roe_service_init(&svc, NULL);

    ozayn_roe_request_t req = _make_request("R1", "OP1");
    ozayn_roe_context_t ctx = _make_ready_ctx();
    ozayn_roe_enforcement_t d;
    ozayn_roe_enforce(&svc, &req, &ctx, &d);
    ASSERT_EQ(d.decision, OZAYN_ROE_DECISION_ALLOW_DISPATCH);

    /* Resources become exhausted */
    ctx.resources_available = 0;
    ASSERT(!ozayn_roe_can_dispatch(&svc, &req, &ctx));

    ozayn_roe_enforcement_t d2;
    ozayn_roe_reassess(&svc, d.id, &ctx, &d2);
    ASSERT_EQ(d2.decision, OZAYN_ROE_DECISION_REQUIRE_RESOURCE_RECHECK);
    ozayn_roe_service_shutdown(&svc);
    return 0;
}

TEST(test_roe_toctou_session_expired) {
    ozayn_roe_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_roe_service_init(&svc, NULL);

    ozayn_roe_request_t req = _make_request("R1", "OP1");
    strncpy(req.security_session_ref, "sess1", OZAYN_ROE_MAX_CORRELATION_LEN - 1);
    ozayn_roe_context_t ctx = _make_ready_ctx();
    ozayn_roe_enforcement_t d;
    ozayn_roe_enforce(&svc, &req, &ctx, &d);
    ASSERT_EQ(d.decision, OZAYN_ROE_DECISION_ALLOW_DISPATCH);

    /* Security session expires */
    ctx.security_session_valid = 0;
    ASSERT(!ozayn_roe_can_dispatch(&svc, &req, &ctx));

    ozayn_roe_enforcement_t d2;
    ozayn_roe_reassess(&svc, d.id, &ctx, &d2);
    ASSERT_EQ(d2.decision, OZAYN_ROE_DECISION_REQUIRE_AUTHORIZATION);
    ozayn_roe_service_shutdown(&svc);
    return 0;
}

TEST(test_roe_toctou_device_disconnect) {
    ozayn_roe_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_roe_service_init(&svc, NULL);

    ozayn_roe_request_t req = _make_request("R1", "OP1");
    ozayn_roe_context_t ctx = _make_ready_ctx();
    ozayn_roe_enforcement_t d;
    ozayn_roe_enforce(&svc, &req, &ctx, &d);
    ASSERT_EQ(d.decision, OZAYN_ROE_DECISION_ALLOW_DISPATCH);

    /* Device disconnects */
    ctx.devices_available = 0;
    ASSERT(!ozayn_roe_can_dispatch(&svc, &req, &ctx));

    ozayn_roe_enforcement_t d2;
    ozayn_roe_reassess(&svc, d.id, &ctx, &d2);
    ASSERT_EQ(d2.decision, OZAYN_ROE_DECISION_REQUIRE_DEVICE_RECHECK);
    ozayn_roe_service_shutdown(&svc);
    return 0;
}

/* ============================================================
 * SHUTDOWN TESTS
 * ============================================================ */

TEST(test_roe_ops_after_shutdown) {
    ozayn_roe_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_roe_service_init(&svc, NULL);
    ozayn_roe_service_shutdown(&svc);
    ozayn_roe_request_t req = _make_request("R1", "OP1");
    ozayn_roe_context_t ctx = _make_ready_ctx();
    ozayn_roe_enforcement_t d;
    ASSERT_EQ(ozayn_roe_enforce(&svc, &req, &ctx, &d), OZAYN_ROE_ERR_NOT_INITIALIZED);
    ASSERT_EQ(ozayn_roe_decision_count(&svc), 0);
    ASSERT_EQ(ozayn_roe_request_count(&svc), 0);
    ASSERT_EQ(ozayn_roe_event_count(&svc), 0);
    ASSERT(!ozayn_roe_can_dispatch(&svc, &req, &ctx));
    return 0;
}

TEST(test_roe_multiple_enforcements) {
    ozayn_roe_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_roe_service_init(&svc, NULL);
    ozayn_roe_context_t ctx = _make_ready_ctx();

    ozayn_roe_request_t r1 = _make_request("R1", "OP1");
    ozayn_roe_request_t r2 = _make_request("R2", "OP2");
    ozayn_roe_request_t r3 = _make_request("R3", "OP3");
    r3.expiration_ms = 1;

    ozayn_roe_enforcement_t d1, d2, d3;
    ozayn_roe_enforce(&svc, &r1, &ctx, &d1);
    ozayn_roe_enforce(&svc, &r2, &ctx, &d2);
    ozayn_roe_enforce(&svc, &r3, &ctx, &d3);

    ASSERT_EQ(ozayn_roe_decision_count(&svc), 3);
    ASSERT_EQ(ozayn_roe_request_count(&svc), 3);
    ASSERT_EQ(d1.decision, OZAYN_ROE_DECISION_ALLOW_DISPATCH);
    ASSERT_EQ(d2.decision, OZAYN_ROE_DECISION_ALLOW_DISPATCH);
    ASSERT_EQ(d3.decision, OZAYN_ROE_DECISION_EXPIRED);
    ozayn_roe_service_shutdown(&svc);
    return 0;
}

/* ============================================================
 * RUNNER
 * ============================================================ */

int run_cr_runtime_enforcement_tests(void) {
    int fail = 0;
    printf("\n  --- CR RUNTIME ENFORCEMENT ---");
    SUITE_BEGIN("Runtime Enforcement");

    /* Lifecycle */
    RUN(test_roe_init_null);
    RUN(test_roe_init_ok);
    RUN(test_roe_double_init);
    RUN(test_roe_shutdown_null);
    RUN(test_roe_shutdown_not_init);
    RUN(test_roe_shutdown_ok);
    RUN(test_roe_init_with_config);

    /* Subsystems */
    RUN(test_roe_set_subsystems_null);
    RUN(test_roe_set_all_subsystems);

    /* Basic enforcement */
    RUN(test_roe_enforce_null);
    RUN(test_roe_enforce_not_init);
    RUN(test_roe_enforce_empty_request_id);
    RUN(test_roe_enforce_valid_ready);
    RUN(test_roe_enforce_records_request);
    RUN(test_roe_enforce_records_decision);
    RUN(test_roe_enforce_generates_ids);

    /* Mode enforcement */
    RUN(test_roe_mode_ready_degraded);
    RUN(test_roe_mode_recovery);
    RUN(test_roe_mode_maintenance);
    RUN(test_roe_mode_safe_hold);
    RUN(test_roe_mode_blocked);
    RUN(test_roe_mode_shutting_down);
    RUN(test_roe_mode_failed);
    RUN(test_roe_mode_unknown);
    RUN(test_roe_mode_initializing);

    /* Operation state */
    RUN(test_roe_operation_cancelled);
    RUN(test_roe_operation_expired);
    RUN(test_roe_operation_inactive);
    RUN(test_roe_duplicate_detected);

    /* Security / Safety / Resource / Device */
    RUN(test_roe_readiness_not_satisfied);
    RUN(test_roe_target_unavailable);
    RUN(test_roe_no_target_always_ok);
    RUN(test_roe_capability_unavailable);
    RUN(test_roe_security_session_invalid);
    RUN(test_roe_authorization_failed);
    RUN(test_roe_safety_failed);
    RUN(test_roe_resource_unavailable);
    RUN(test_roe_device_unavailable);
    RUN(test_roe_workflow_blocked);
    RUN(test_roe_pipeline_blocked);
    RUN(test_roe_dependency_failed);

    /* Quick check */
    RUN(test_roe_can_dispatch_null);
    RUN(test_roe_can_dispatch_not_init);
    RUN(test_roe_can_dispatch_ready);
    RUN(test_roe_can_dispatch_blocked_mode);
    RUN(test_roe_can_dispatch_empty_id);
    RUN(test_roe_can_dispatch_operation_cancelled);
    RUN(test_roe_can_dispatch_no_safety);
    RUN(test_roe_can_dispatch_duplicate);

    /* Expiration */
    RUN(test_roe_enforce_expired_request);

    /* Reassessment */
    RUN(test_roe_reassess_null);
    RUN(test_roe_reassess_not_found);
    RUN(test_roe_reassess_ok);
    RUN(test_roe_reassess_limit);

    /* Invalidation */
    RUN(test_roe_invalidate_null);
    RUN(test_roe_invalidate_not_found);
    RUN(test_roe_invalidate_ok);
    RUN(test_roe_invalidate_already_invalidated);

    /* Decision queries */
    RUN(test_roe_get_decision_null);
    RUN(test_roe_get_decision_not_found);
    RUN(test_roe_get_latest_decision_empty);
    RUN(test_roe_get_latest_decision_ok);
    RUN(test_roe_decision_count_null);
    RUN(test_roe_decision_count_after_enforce);

    /* Request queries */
    RUN(test_roe_get_request_null);
    RUN(test_roe_get_request_not_found);
    RUN(test_roe_request_count_null);
    RUN(test_roe_request_count_after_enforce);

    /* Events */
    RUN(test_roe_event_count_null);
    RUN(test_roe_event_count_after_enforce);
    RUN(test_roe_get_event_null);
    RUN(test_roe_get_event_out_of_range);
    RUN(test_roe_event_sequence_increments);

    /* Stats */
    RUN(test_roe_stats_null);
    RUN(test_roe_stats_initial_zero);
    RUN(test_roe_stats_after_allow);
    RUN(test_roe_stats_after_mode_block);
    RUN(test_roe_stats_after_security_block);
    RUN(test_roe_stats_after_expire);
    RUN(test_roe_reset_stats);
    RUN(test_roe_reset_stats_null);

    /* Name helpers */
    RUN(test_roe_err_name_all);
    RUN(test_roe_decision_name_all);
    RUN(test_roe_phase_name_all);
    RUN(test_roe_event_type_name_all);

    /* TOCTOU */
    RUN(test_roe_toctou_mode_change);
    RUN(test_roe_toctou_resource_exhausted);
    RUN(test_roe_toctou_session_expired);
    RUN(test_roe_toctou_device_disconnect);

    /* Shutdown */
    RUN(test_roe_ops_after_shutdown);
    RUN(test_roe_multiple_enforcements);

    SUITE_END();
    fail = TOTAL_FAIL();
    return fail;
}
