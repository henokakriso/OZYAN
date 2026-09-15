/*
 * test_runtime_admission_gate.c — Section 04, Step 22
 * Runtime Operation Admission & Control Gate tests
 */

#include "../../tests/test_framework.h"
#include "../runtime_admission_gate.h"
#include <string.h>

/* ============================================================
 * HELPERS
 * ============================================================ */

static ozayn_rag_request_t _make_request(const char *id, const char *op_id) {
    ozayn_rag_request_t r;
    memset(&r, 0, sizeof(r));
    strncpy(r.id, id, OZAYN_RAG_MAX_ID_LEN - 1);
    strncpy(r.operation_id, op_id, OZAYN_RAG_MAX_ID_LEN - 1);
    r.priority = 5;
    r.timestamp_ms = 1000;
    r.expiration_ms = 2000000000;
    return r;
}

static ozayn_rag_context_t _make_ready_ctx(void) {
    ozayn_rag_context_t c;
    memset(&c, 0, sizeof(c));
    c.runtime_mode = OZAYN_ORD_MODE_READY;
    c.readiness_satisfied = 1;
    c.component_available = 1;
    c.capability_available = 1;
    c.security_session_valid = 1;
    c.authorization_valid = 1;
    c.safety_policy_valid = 1;
    c.health_ok = 1;
    c.resources_available = 1;
    c.devices_available = 1;
    c.workflow_valid = 1;
    c.pipeline_valid = 1;
    c.scheduler_eligible = 1;
    c.dependencies_satisfied = 1;
    return c;
}

/* ============================================================
 * LIFECYCLE TESTS
 * ============================================================ */

TEST(test_rag_init_null) {
    ASSERT_EQ(ozayn_rag_service_init(NULL, NULL), OZAYN_RAG_ERR_NULL);
    return 0;
}

TEST(test_rag_init_ok) {
    ozayn_rag_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ASSERT_EQ(ozayn_rag_service_init(&svc, NULL), OZAYN_RAG_OK);
    ASSERT(svc.initialized);
    ASSERT_EQ(svc.request_count, 0);
    ASSERT_EQ(svc.decision_count, 0);
    ASSERT_EQ(svc.event_count, 0);
    ozayn_rag_service_shutdown(&svc);
    return 0;
}

TEST(test_rag_double_init) {
    ozayn_rag_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ASSERT_EQ(ozayn_rag_service_init(&svc, NULL), OZAYN_RAG_OK);
    ASSERT_EQ(ozayn_rag_service_init(&svc, NULL), OZAYN_RAG_ERR_ALREADY_INITIALIZED);
    ozayn_rag_service_shutdown(&svc);
    return 0;
}

TEST(test_rag_shutdown_null) {
    ASSERT_EQ(ozayn_rag_service_shutdown(NULL), OZAYN_RAG_ERR_NULL);
    return 0;
}

TEST(test_rag_shutdown_not_init) {
    ozayn_rag_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ASSERT_EQ(ozayn_rag_service_shutdown(&svc), OZAYN_RAG_ERR_NOT_INITIALIZED);
    return 0;
}

TEST(test_rag_shutdown_ok) {
    ozayn_rag_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ASSERT_EQ(ozayn_rag_service_init(&svc, NULL), OZAYN_RAG_OK);
    ASSERT_EQ(ozayn_rag_service_shutdown(&svc), OZAYN_RAG_OK);
    ASSERT(!svc.initialized);
    return 0;
}

TEST(test_rag_init_with_config) {
    ozayn_rag_service_t svc;
    memset(&svc, 0, sizeof(svc));
    int dummy = 1;
    ozayn_rag_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.readiness = &dummy;
    cfg.audit = &dummy;
    cfg.safety = &dummy;
    ASSERT_EQ(ozayn_rag_service_init(&svc, &cfg), OZAYN_RAG_OK);
    ASSERT_EQ(svc.readiness, &dummy);
    ASSERT_EQ(svc.audit, &dummy);
    ASSERT_EQ(svc.safety, &dummy);
    ozayn_rag_service_shutdown(&svc);
    return 0;
}

/* ============================================================
 * SUBSYSTEM BINDING TESTS
 * ============================================================ */

TEST(test_rag_set_subsystems_null) {
    ASSERT_EQ(ozayn_rag_set_readiness(NULL, NULL), OZAYN_RAG_ERR_NULL);
    ASSERT_EQ(ozayn_rag_set_audit(NULL, NULL), OZAYN_RAG_ERR_NULL);
    ASSERT_EQ(ozayn_rag_set_safety(NULL, NULL), OZAYN_RAG_ERR_NULL);
    ASSERT_EQ(ozayn_rag_set_resource_manager(NULL, NULL), OZAYN_RAG_ERR_NULL);
    ASSERT_EQ(ozayn_rag_set_component_registry(NULL, NULL), OZAYN_RAG_ERR_NULL);
    ASSERT_EQ(ozayn_rag_set_device_session(NULL, NULL), OZAYN_RAG_ERR_NULL);
    ASSERT_EQ(ozayn_rag_set_operation_queue(NULL, NULL), OZAYN_RAG_ERR_NULL);
    ASSERT_EQ(ozayn_rag_set_operation_history(NULL, NULL), OZAYN_RAG_ERR_NULL);
    ASSERT_EQ(ozayn_rag_set_pipeline_scheduler(NULL, NULL), OZAYN_RAG_ERR_NULL);
    ASSERT_EQ(ozayn_rag_set_workflow_orchestrator(NULL, NULL), OZAYN_RAG_ERR_NULL);
    ASSERT_EQ(ozayn_rag_set_events_engine(NULL, NULL), OZAYN_RAG_ERR_NULL);
    ASSERT_EQ(ozayn_rag_set_diagnostics(NULL, NULL), OZAYN_RAG_ERR_NULL);
    return 0;
}

TEST(test_rag_set_all_subsystems) {
    ozayn_rag_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_rag_service_init(&svc, NULL);
    int a = 1, b = 2, c = 3, d = 4, e = 5, f = 6, g = 7, h = 8, i = 9, j = 10, k = 11, l = 12;
    ASSERT_EQ(ozayn_rag_set_readiness(&svc, &a), OZAYN_RAG_OK);
    ASSERT_EQ(ozayn_rag_set_audit(&svc, &b), OZAYN_RAG_OK);
    ASSERT_EQ(ozayn_rag_set_safety(&svc, &c), OZAYN_RAG_OK);
    ASSERT_EQ(ozayn_rag_set_resource_manager(&svc, &d), OZAYN_RAG_OK);
    ASSERT_EQ(ozayn_rag_set_component_registry(&svc, &e), OZAYN_RAG_OK);
    ASSERT_EQ(ozayn_rag_set_device_session(&svc, &f), OZAYN_RAG_OK);
    ASSERT_EQ(ozayn_rag_set_operation_queue(&svc, &g), OZAYN_RAG_OK);
    ASSERT_EQ(ozayn_rag_set_operation_history(&svc, &h), OZAYN_RAG_OK);
    ASSERT_EQ(ozayn_rag_set_pipeline_scheduler(&svc, &i), OZAYN_RAG_OK);
    ASSERT_EQ(ozayn_rag_set_workflow_orchestrator(&svc, &j), OZAYN_RAG_OK);
    ASSERT_EQ(ozayn_rag_set_events_engine(&svc, &k), OZAYN_RAG_OK);
    ASSERT_EQ(ozayn_rag_set_diagnostics(&svc, &l), OZAYN_RAG_OK);
    ozayn_rag_service_shutdown(&svc);
    return 0;
}

/* ============================================================
 * ADMISSION — BASIC TESTS
 * ============================================================ */

TEST(test_rag_admit_null) {
    ozayn_rag_admission_t out;
    ASSERT_EQ(ozayn_rag_admit(NULL, NULL, NULL, &out), OZAYN_RAG_ERR_NULL);
    return 0;
}

TEST(test_rag_admit_not_init) {
    ozayn_rag_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_rag_request_t req = _make_request("R1", "OP1");
    ozayn_rag_context_t ctx = _make_ready_ctx();
    ozayn_rag_admission_t out;
    ASSERT_EQ(ozayn_rag_admit(&svc, &req, &ctx, &out), OZAYN_RAG_ERR_NOT_INITIALIZED);
    return 0;
}

TEST(test_rag_admit_empty_request_id) {
    ozayn_rag_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_rag_service_init(&svc, NULL);
    ozayn_rag_request_t req;
    memset(&req, 0, sizeof(req));
    ozayn_rag_context_t ctx = _make_ready_ctx();
    ozayn_rag_admission_t out;
    ASSERT_EQ(ozayn_rag_admit(&svc, &req, &ctx, &out), OZAYN_RAG_OK);
    ASSERT_EQ(out.decision, OZAYN_RAG_DECISION_DENY);
    ASSERT_EQ(out.phase, OZAYN_RAG_PHASE_DENIED);
    ozayn_rag_service_shutdown(&svc);
    return 0;
}

TEST(test_rag_admit_valid_ready) {
    ozayn_rag_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_rag_service_init(&svc, NULL);
    ozayn_rag_request_t req = _make_request("R1", "OP1");
    ozayn_rag_context_t ctx = _make_ready_ctx();
    ozayn_rag_admission_t out;
    ASSERT_EQ(ozayn_rag_admit(&svc, &req, &ctx, &out), OZAYN_RAG_OK);
    ASSERT_EQ(out.decision, OZAYN_RAG_DECISION_ACCEPT);
    ASSERT_EQ(out.phase, OZAYN_RAG_PHASE_ACCEPTED);
    ASSERT(out.active);
    ozayn_rag_service_shutdown(&svc);
    return 0;
}

TEST(test_rag_admit_records_request) {
    ozayn_rag_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_rag_service_init(&svc, NULL);
    ozayn_rag_request_t req = _make_request("R1", "OP1");
    ozayn_rag_context_t ctx = _make_ready_ctx();
    ozayn_rag_admission_t out;
    ozayn_rag_admit(&svc, &req, &ctx, &out);
    ASSERT_EQ(ozayn_rag_request_count(&svc), 1);
    ozayn_rag_request_t stored;
    ASSERT_EQ(ozayn_rag_get_request(&svc, "R1", &stored), OZAYN_RAG_OK);
    ASSERT(strcmp(stored.operation_id, "OP1") == 0);
    ozayn_rag_service_shutdown(&svc);
    return 0;
}

TEST(test_rag_admit_records_decision) {
    ozayn_rag_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_rag_service_init(&svc, NULL);
    ozayn_rag_request_t req = _make_request("R1", "OP1");
    ozayn_rag_context_t ctx = _make_ready_ctx();
    ozayn_rag_admission_t out;
    ozayn_rag_admit(&svc, &req, &ctx, &out);
    ASSERT_EQ(ozayn_rag_decision_count(&svc), 1);
    ozayn_rag_admission_t stored;
    ASSERT_EQ(ozayn_rag_get_decision(&svc, out.id, &stored), OZAYN_RAG_OK);
    ASSERT_EQ(stored.decision, OZAYN_RAG_DECISION_ACCEPT);
    ozayn_rag_service_shutdown(&svc);
    return 0;
}

TEST(test_rag_admit_generates_ids) {
    ozayn_rag_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_rag_service_init(&svc, NULL);
    ozayn_rag_request_t r1 = _make_request("R1", "OP1");
    ozayn_rag_request_t r2 = _make_request("R2", "OP2");
    ozayn_rag_context_t ctx = _make_ready_ctx();
    ozayn_rag_admission_t d1, d2;
    ozayn_rag_admit(&svc, &r1, &ctx, &d1);
    ozayn_rag_admit(&svc, &r2, &ctx, &d2);
    ASSERT(strcmp(d1.id, d2.id) != 0);
    ozayn_rag_service_shutdown(&svc);
    return 0;
}

/* ============================================================
 * MODE ENFORCEMENT TESTS
 * ============================================================ */

TEST(test_rag_mode_ready_degraded) {
    ozayn_rag_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_rag_service_init(&svc, NULL);
    ozayn_rag_request_t req = _make_request("R1", "OP1");
    ozayn_rag_context_t ctx = _make_ready_ctx();
    ctx.runtime_mode = OZAYN_ORD_MODE_READY_DEGRADED;
    ozayn_rag_admission_t out;
    ASSERT_EQ(ozayn_rag_admit(&svc, &req, &ctx, &out), OZAYN_RAG_OK);
    ASSERT_EQ(out.decision, OZAYN_RAG_DECISION_ACCEPT);
    ASSERT(out.warning_count > 0);
    ozayn_rag_service_shutdown(&svc);
    return 0;
}

TEST(test_rag_mode_recovery) {
    ozayn_rag_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_rag_service_init(&svc, NULL);
    ozayn_rag_request_t req = _make_request("R1", "OP1");
    ozayn_rag_context_t ctx = _make_ready_ctx();
    ctx.runtime_mode = OZAYN_ORD_MODE_RECOVERY;
    ozayn_rag_admission_t out;
    ASSERT_EQ(ozayn_rag_admit(&svc, &req, &ctx, &out), OZAYN_RAG_OK);
    ASSERT_EQ(out.decision, OZAYN_RAG_DECISION_DEFER);
    ASSERT_EQ(out.phase, OZAYN_RAG_PHASE_DEFERRED);
    ozayn_rag_service_shutdown(&svc);
    return 0;
}

TEST(test_rag_mode_maintenance) {
    ozayn_rag_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_rag_service_init(&svc, NULL);
    ozayn_rag_request_t req = _make_request("R1", "OP1");
    ozayn_rag_context_t ctx = _make_ready_ctx();
    ctx.runtime_mode = OZAYN_ORD_MODE_MAINTENANCE;
    ozayn_rag_admission_t out;
    ASSERT_EQ(ozayn_rag_admit(&svc, &req, &ctx, &out), OZAYN_RAG_OK);
    ASSERT_EQ(out.decision, OZAYN_RAG_DECISION_DEFER);
    ozayn_rag_service_shutdown(&svc);
    return 0;
}

TEST(test_rag_mode_safe_hold) {
    ozayn_rag_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_rag_service_init(&svc, NULL);
    ozayn_rag_request_t req = _make_request("R1", "OP1");
    ozayn_rag_context_t ctx = _make_ready_ctx();
    ctx.runtime_mode = OZAYN_ORD_MODE_SAFE_HOLD;
    ozayn_rag_admission_t out;
    ASSERT_EQ(ozayn_rag_admit(&svc, &req, &ctx, &out), OZAYN_RAG_OK);
    ASSERT_EQ(out.decision, OZAYN_RAG_DECISION_BLOCKED);
    ASSERT_EQ(out.phase, OZAYN_RAG_PHASE_BLOCKED);
    ozayn_rag_service_shutdown(&svc);
    return 0;
}

TEST(test_rag_mode_blocked) {
    ozayn_rag_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_rag_service_init(&svc, NULL);
    ozayn_rag_request_t req = _make_request("R1", "OP1");
    ozayn_rag_context_t ctx = _make_ready_ctx();
    ctx.runtime_mode = OZAYN_ORD_MODE_BLOCKED;
    ozayn_rag_admission_t out;
    ASSERT_EQ(ozayn_rag_admit(&svc, &req, &ctx, &out), OZAYN_RAG_OK);
    ASSERT_EQ(out.decision, OZAYN_RAG_DECISION_BLOCKED);
    ozayn_rag_service_shutdown(&svc);
    return 0;
}

TEST(test_rag_mode_shutting_down) {
    ozayn_rag_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_rag_service_init(&svc, NULL);
    ozayn_rag_request_t req = _make_request("R1", "OP1");
    ozayn_rag_context_t ctx = _make_ready_ctx();
    ctx.runtime_mode = OZAYN_ORD_MODE_SHUTTING_DOWN;
    ozayn_rag_admission_t out;
    ASSERT_EQ(ozayn_rag_admit(&svc, &req, &ctx, &out), OZAYN_RAG_OK);
    ASSERT_EQ(out.decision, OZAYN_RAG_DECISION_DENY);
    ozayn_rag_service_shutdown(&svc);
    return 0;
}

TEST(test_rag_mode_failed) {
    ozayn_rag_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_rag_service_init(&svc, NULL);
    ozayn_rag_request_t req = _make_request("R1", "OP1");
    ozayn_rag_context_t ctx = _make_ready_ctx();
    ctx.runtime_mode = OZAYN_ORD_MODE_FAILED;
    ozayn_rag_admission_t out;
    ASSERT_EQ(ozayn_rag_admit(&svc, &req, &ctx, &out), OZAYN_RAG_OK);
    ASSERT_EQ(out.decision, OZAYN_RAG_DECISION_BLOCKED);
    ozayn_rag_service_shutdown(&svc);
    return 0;
}

TEST(test_rag_mode_unknown) {
    ozayn_rag_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_rag_service_init(&svc, NULL);
    ozayn_rag_request_t req = _make_request("R1", "OP1");
    ozayn_rag_context_t ctx = _make_ready_ctx();
    ctx.runtime_mode = OZAYN_ORD_MODE_UNKNOWN;
    ozayn_rag_admission_t out;
    ASSERT_EQ(ozayn_rag_admit(&svc, &req, &ctx, &out), OZAYN_RAG_OK);
    ASSERT_EQ(out.decision, OZAYN_RAG_DECISION_DEFER);
    ozayn_rag_service_shutdown(&svc);
    return 0;
}

TEST(test_rag_mode_initializing) {
    ozayn_rag_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_rag_service_init(&svc, NULL);
    ozayn_rag_request_t req = _make_request("R1", "OP1");
    ozayn_rag_context_t ctx = _make_ready_ctx();
    ctx.runtime_mode = OZAYN_ORD_MODE_INITIALIZING;
    ozayn_rag_admission_t out;
    ASSERT_EQ(ozayn_rag_admit(&svc, &req, &ctx, &out), OZAYN_RAG_OK);
    ASSERT_EQ(out.decision, OZAYN_RAG_DECISION_DEFER);
    ozayn_rag_service_shutdown(&svc);
    return 0;
}

/* ============================================================
 * SECURITY / SAFETY / RESOURCE / DEVICE TESTS
 * ============================================================ */

TEST(test_rag_readiness_not_satisfied) {
    ozayn_rag_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_rag_service_init(&svc, NULL);
    ozayn_rag_request_t req = _make_request("R1", "OP1");
    ozayn_rag_context_t ctx = _make_ready_ctx();
    ctx.readiness_satisfied = 0;
    ozayn_rag_admission_t out;
    ASSERT_EQ(ozayn_rag_admit(&svc, &req, &ctx, &out), OZAYN_RAG_OK);
    ASSERT_EQ(out.decision, OZAYN_RAG_DECISION_DEFER);
    ozayn_rag_service_shutdown(&svc);
    return 0;
}

TEST(test_rag_component_unavailable) {
    ozayn_rag_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_rag_service_init(&svc, NULL);
    ozayn_rag_request_t req = _make_request("R1", "OP1");
    strncpy(req.target_component_id, "comp1", OZAYN_RAG_MAX_NAME_LEN - 1);
    ozayn_rag_context_t ctx = _make_ready_ctx();
    ctx.component_available = 0;
    ozayn_rag_admission_t out;
    ASSERT_EQ(ozayn_rag_admit(&svc, &req, &ctx, &out), OZAYN_RAG_OK);
    ASSERT_EQ(out.decision, OZAYN_RAG_DECISION_DENY);
    ozayn_rag_service_shutdown(&svc);
    return 0;
}

TEST(test_rag_no_target_always_ok) {
    ozayn_rag_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_rag_service_init(&svc, NULL);
    ozayn_rag_request_t req = _make_request("R1", "OP1");
    ozayn_rag_context_t ctx = _make_ready_ctx();
    ctx.component_available = 0;
    ozayn_rag_admission_t out;
    ASSERT_EQ(ozayn_rag_admit(&svc, &req, &ctx, &out), OZAYN_RAG_OK);
    ASSERT_EQ(out.decision, OZAYN_RAG_DECISION_ACCEPT);
    ozayn_rag_service_shutdown(&svc);
    return 0;
}

TEST(test_rag_capability_unavailable) {
    ozayn_rag_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_rag_service_init(&svc, NULL);
    ozayn_rag_request_t req = _make_request("R1", "OP1");
    strncpy(req.capability_id, "cap1", OZAYN_RAG_MAX_NAME_LEN - 1);
    ozayn_rag_context_t ctx = _make_ready_ctx();
    ctx.capability_available = 0;
    ozayn_rag_admission_t out;
    ASSERT_EQ(ozayn_rag_admit(&svc, &req, &ctx, &out), OZAYN_RAG_OK);
    ASSERT_EQ(out.decision, OZAYN_RAG_DECISION_DENY);
    ozayn_rag_service_shutdown(&svc);
    return 0;
}

TEST(test_rag_security_session_invalid) {
    ozayn_rag_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_rag_service_init(&svc, NULL);
    ozayn_rag_request_t req = _make_request("R1", "OP1");
    strncpy(req.security_session_ref, "sess1", OZAYN_RAG_MAX_CORRELATION_LEN - 1);
    ozayn_rag_context_t ctx = _make_ready_ctx();
    ctx.security_session_valid = 0;
    ozayn_rag_admission_t out;
    ASSERT_EQ(ozayn_rag_admit(&svc, &req, &ctx, &out), OZAYN_RAG_OK);
    ASSERT_EQ(out.decision, OZAYN_RAG_DECISION_REQUIRES_AUTHORIZATION);
    ASSERT(!ctx.security_session_valid);
    ozayn_rag_service_shutdown(&svc);
    return 0;
}

TEST(test_rag_authorization_failed) {
    ozayn_rag_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_rag_service_init(&svc, NULL);
    ozayn_rag_request_t req = _make_request("R1", "OP1");
    strncpy(req.security_session_ref, "sess1", OZAYN_RAG_MAX_CORRELATION_LEN - 1);
    ozayn_rag_context_t ctx = _make_ready_ctx();
    ctx.authorization_valid = 0;
    ozayn_rag_admission_t out;
    ASSERT_EQ(ozayn_rag_admit(&svc, &req, &ctx, &out), OZAYN_RAG_OK);
    ASSERT_EQ(out.decision, OZAYN_RAG_DECISION_REQUIRES_AUTHORIZATION);
    ozayn_rag_service_shutdown(&svc);
    return 0;
}

TEST(test_rag_safety_failed) {
    ozayn_rag_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_rag_service_init(&svc, NULL);
    ozayn_rag_request_t req = _make_request("R1", "OP1");
    ozayn_rag_context_t ctx = _make_ready_ctx();
    ctx.safety_policy_valid = 0;
    ozayn_rag_admission_t out;
    ASSERT_EQ(ozayn_rag_admit(&svc, &req, &ctx, &out), OZAYN_RAG_OK);
    ASSERT_EQ(out.decision, OZAYN_RAG_DECISION_REQUIRES_SAFETY_CHECK);
    ozayn_rag_service_shutdown(&svc);
    return 0;
}

TEST(test_rag_resource_unavailable) {
    ozayn_rag_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_rag_service_init(&svc, NULL);
    ozayn_rag_request_t req = _make_request("R1", "OP1");
    ozayn_rag_context_t ctx = _make_ready_ctx();
    ctx.resources_available = 0;
    ozayn_rag_admission_t out;
    ASSERT_EQ(ozayn_rag_admit(&svc, &req, &ctx, &out), OZAYN_RAG_OK);
    ASSERT_EQ(out.decision, OZAYN_RAG_DECISION_REQUIRES_RESOURCE_CHECK);
    ozayn_rag_service_shutdown(&svc);
    return 0;
}

TEST(test_rag_device_unavailable) {
    ozayn_rag_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_rag_service_init(&svc, NULL);
    ozayn_rag_request_t req = _make_request("R1", "OP1");
    ozayn_rag_context_t ctx = _make_ready_ctx();
    ctx.devices_available = 0;
    ozayn_rag_admission_t out;
    ASSERT_EQ(ozayn_rag_admit(&svc, &req, &ctx, &out), OZAYN_RAG_OK);
    ASSERT_EQ(out.decision, OZAYN_RAG_DECISION_REQUIRES_DEVICE_CHECK);
    ozayn_rag_service_shutdown(&svc);
    return 0;
}

TEST(test_rag_workflow_blocked) {
    ozayn_rag_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_rag_service_init(&svc, NULL);
    ozayn_rag_request_t req = _make_request("R1", "OP1");
    strncpy(req.workflow_id, "wf1", OZAYN_RAG_MAX_ID_LEN - 1);
    ozayn_rag_context_t ctx = _make_ready_ctx();
    ctx.workflow_valid = 0;
    ozayn_rag_admission_t out;
    ASSERT_EQ(ozayn_rag_admit(&svc, &req, &ctx, &out), OZAYN_RAG_OK);
    ASSERT_EQ(out.decision, OZAYN_RAG_DECISION_DENY);
    ozayn_rag_service_shutdown(&svc);
    return 0;
}

TEST(test_rag_pipeline_blocked) {
    ozayn_rag_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_rag_service_init(&svc, NULL);
    ozayn_rag_request_t req = _make_request("R1", "OP1");
    strncpy(req.pipeline_id, "pl1", OZAYN_RAG_MAX_ID_LEN - 1);
    ozayn_rag_context_t ctx = _make_ready_ctx();
    ctx.pipeline_valid = 0;
    ozayn_rag_admission_t out;
    ASSERT_EQ(ozayn_rag_admit(&svc, &req, &ctx, &out), OZAYN_RAG_OK);
    ASSERT_EQ(out.decision, OZAYN_RAG_DECISION_DENY);
    ozayn_rag_service_shutdown(&svc);
    return 0;
}

TEST(test_rag_dependency_failed) {
    ozayn_rag_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_rag_service_init(&svc, NULL);
    ozayn_rag_request_t req = _make_request("R1", "OP1");
    ozayn_rag_context_t ctx = _make_ready_ctx();
    ctx.dependencies_satisfied = 0;
    ozayn_rag_admission_t out;
    ASSERT_EQ(ozayn_rag_admit(&svc, &req, &ctx, &out), OZAYN_RAG_OK);
    ASSERT_EQ(out.decision, OZAYN_RAG_DECISION_DEFER);
    ozayn_rag_service_shutdown(&svc);
    return 0;
}

TEST(test_rag_scheduler_not_eligible) {
    ozayn_rag_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_rag_service_init(&svc, NULL);
    ozayn_rag_request_t req = _make_request("R1", "OP1");
    ozayn_rag_context_t ctx = _make_ready_ctx();
    ctx.scheduler_eligible = 0;
    ozayn_rag_admission_t out;
    ASSERT_EQ(ozayn_rag_admit(&svc, &req, &ctx, &out), OZAYN_RAG_OK);
    ASSERT_EQ(out.decision, OZAYN_RAG_DECISION_QUEUE);
    ozayn_rag_service_shutdown(&svc);
    return 0;
}

/* ============================================================
 * QUICK CHECK TESTS
 * ============================================================ */

TEST(test_rag_can_admit_null) {
    ASSERT(!ozayn_rag_can_admit(NULL, NULL, NULL));
    return 0;
}

TEST(test_rag_can_admit_not_init) {
    ozayn_rag_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_rag_request_t req = _make_request("R1", "OP1");
    ozayn_rag_context_t ctx = _make_ready_ctx();
    ASSERT(!ozayn_rag_can_admit(&svc, &req, &ctx));
    return 0;
}

TEST(test_rag_can_admit_ready) {
    ozayn_rag_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_rag_service_init(&svc, NULL);
    ozayn_rag_request_t req = _make_request("R1", "OP1");
    ozayn_rag_context_t ctx = _make_ready_ctx();
    ASSERT(ozayn_rag_can_admit(&svc, &req, &ctx));
    ozayn_rag_service_shutdown(&svc);
    return 0;
}

TEST(test_rag_can_admit_blocked_mode) {
    ozayn_rag_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_rag_service_init(&svc, NULL);
    ozayn_rag_request_t req = _make_request("R1", "OP1");
    ozayn_rag_context_t ctx = _make_ready_ctx();
    ctx.runtime_mode = OZAYN_ORD_MODE_BLOCKED;
    ASSERT(!ozayn_rag_can_admit(&svc, &req, &ctx));
    ozayn_rag_service_shutdown(&svc);
    return 0;
}

TEST(test_rag_can_admit_empty_id) {
    ozayn_rag_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_rag_service_init(&svc, NULL);
    ozayn_rag_request_t req;
    memset(&req, 0, sizeof(req));
    ozayn_rag_context_t ctx = _make_ready_ctx();
    ASSERT(!ozayn_rag_can_admit(&svc, &req, &ctx));
    ozayn_rag_service_shutdown(&svc);
    return 0;
}

TEST(test_rag_can_admit_no_safety) {
    ozayn_rag_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_rag_service_init(&svc, NULL);
    ozayn_rag_request_t req = _make_request("R1", "OP1");
    ozayn_rag_context_t ctx = _make_ready_ctx();
    ctx.safety_policy_valid = 0;
    ASSERT(!ozayn_rag_can_admit(&svc, &req, &ctx));
    ozayn_rag_service_shutdown(&svc);
    return 0;
}

/* ============================================================
 * EXPIRATION TEST
 * ============================================================ */

TEST(test_rag_admit_expired_request) {
    ozayn_rag_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_rag_service_init(&svc, NULL);
    ozayn_rag_request_t req = _make_request("R1", "OP1");
    req.expiration_ms = 1;
    ozayn_rag_context_t ctx = _make_ready_ctx();
    ozayn_rag_admission_t out;
    ASSERT_EQ(ozayn_rag_admit(&svc, &req, &ctx, &out), OZAYN_RAG_OK);
    ASSERT_EQ(out.decision, OZAYN_RAG_DECISION_EXPIRED);
    ASSERT_EQ(out.phase, OZAYN_RAG_PHASE_EXPIRED);
    ozayn_rag_service_shutdown(&svc);
    return 0;
}

/* ============================================================
 * REASSESSMENT TESTS
 * ============================================================ */

TEST(test_rag_reassess_null) {
    ozayn_rag_context_t ctx = _make_ready_ctx();
    ozayn_rag_admission_t out;
    ASSERT_EQ(ozayn_rag_reassess(NULL, NULL, &ctx, &out), OZAYN_RAG_ERR_NULL);
    return 0;
}

TEST(test_rag_reassess_not_found) {
    ozayn_rag_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_rag_service_init(&svc, NULL);
    ozayn_rag_context_t ctx = _make_ready_ctx();
    ozayn_rag_admission_t out;
    ASSERT_EQ(ozayn_rag_reassess(&svc, "NONEXISTENT", &ctx, &out),
              OZAYN_RAG_ERR_NOT_FOUND);
    ozayn_rag_service_shutdown(&svc);
    return 0;
}

TEST(test_rag_reassess_ok) {
    ozayn_rag_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_rag_service_init(&svc, NULL);
    ozayn_rag_request_t req = _make_request("R1", "OP1");
    ozayn_rag_context_t ctx = _make_ready_ctx();
    ctx.resources_available = 0;
    ozayn_rag_admission_t d1;
    ASSERT_EQ(ozayn_rag_admit(&svc, &req, &ctx, &d1), OZAYN_RAG_OK);
    ASSERT_EQ(d1.decision, OZAYN_RAG_DECISION_REQUIRES_RESOURCE_CHECK);

    ctx.resources_available = 1;
    ozayn_rag_admission_t d2;
    ASSERT_EQ(ozayn_rag_reassess(&svc, d1.id, &ctx, &d2), OZAYN_RAG_OK);
    ASSERT_EQ(d2.decision, OZAYN_RAG_DECISION_ACCEPT);
    ASSERT_EQ(d2.reassessment_count, 1);

    /* Old decision should be invalidated */
    ozayn_rag_admission_t check;
    ASSERT_EQ(ozayn_rag_get_decision(&svc, d1.id, &check), OZAYN_RAG_ERR_NOT_FOUND);
    ozayn_rag_service_shutdown(&svc);
    return 0;
}

TEST(test_rag_reassess_limit) {
    ozayn_rag_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_rag_service_init(&svc, NULL);
    ozayn_rag_request_t req = _make_request("R1", "OP1");
    ozayn_rag_context_t ctx = _make_ready_ctx();
    ctx.resources_available = 0;
    ozayn_rag_admission_t d;
    ozayn_rag_admit(&svc, &req, &ctx, &d);

    /* Reassess up to limit */
    ctx.resources_available = 1;
    ozayn_rag_admission_t d2;
    ozayn_rag_reassess(&svc, d.id, &ctx, &d2);
    /* d2 was stored, need its id */
    ozayn_rag_admission_t d3;
    ctx.resources_available = 0;
    ozayn_rag_reassess(&svc, d2.id, &ctx, &d3);
    ozayn_rag_admission_t d4;
    ctx.resources_available = 1;
    ozayn_rag_reassess(&svc, d3.id, &ctx, &d4);
    /* Now one more should fail */
    ozayn_rag_admission_t d5;
    ctx.resources_available = 0;
    ozayn_rag_err_t rc = ozayn_rag_reassess(&svc, d4.id, &ctx, &d5);
    ASSERT_EQ(rc, OZAYN_RAG_OK);
    ASSERT_EQ(d5.decision, OZAYN_RAG_DECISION_DENY);
    ozayn_rag_service_shutdown(&svc);
    return 0;
}

/* ============================================================
 * INVALIDATION TESTS
 * ============================================================ */

TEST(test_rag_invalidate_null) {
    ASSERT_EQ(ozayn_rag_invalidate(NULL, NULL), OZAYN_RAG_ERR_NULL);
    return 0;
}

TEST(test_rag_invalidate_not_found) {
    ozayn_rag_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_rag_service_init(&svc, NULL);
    ASSERT_EQ(ozayn_rag_invalidate(&svc, "NONEXISTENT"), OZAYN_RAG_ERR_NOT_FOUND);
    ozayn_rag_service_shutdown(&svc);
    return 0;
}

TEST(test_rag_invalidate_ok) {
    ozayn_rag_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_rag_service_init(&svc, NULL);
    ozayn_rag_request_t req = _make_request("R1", "OP1");
    ozayn_rag_context_t ctx = _make_ready_ctx();
    ozayn_rag_admission_t d;
    ozayn_rag_admit(&svc, &req, &ctx, &d);
    ASSERT_EQ(ozayn_rag_invalidate(&svc, d.id), OZAYN_RAG_OK);
    ASSERT_EQ(svc.stats.total_invalidated, 1);
    ozayn_rag_admission_t check;
    ASSERT_EQ(ozayn_rag_get_decision(&svc, d.id, &check), OZAYN_RAG_ERR_NOT_FOUND);
    ozayn_rag_service_shutdown(&svc);
    return 0;
}

TEST(test_rag_invalidate_already_invalidated) {
    ozayn_rag_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_rag_service_init(&svc, NULL);
    ozayn_rag_request_t req = _make_request("R1", "OP1");
    ozayn_rag_context_t ctx = _make_ready_ctx();
    ozayn_rag_admission_t d;
    ozayn_rag_admit(&svc, &req, &ctx, &d);
    ASSERT_EQ(ozayn_rag_invalidate(&svc, d.id), OZAYN_RAG_OK);
    ASSERT_EQ(ozayn_rag_invalidate(&svc, d.id), OZAYN_RAG_ERR_INVALIDATED);
    ozayn_rag_service_shutdown(&svc);
    return 0;
}

/* ============================================================
 * DECISION QUERY TESTS
 * ============================================================ */

TEST(test_rag_get_decision_null) {
    ozayn_rag_admission_t out;
    ASSERT_EQ(ozayn_rag_get_decision(NULL, "x", &out), OZAYN_RAG_ERR_NULL);
    return 0;
}

TEST(test_rag_get_decision_not_found) {
    ozayn_rag_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_rag_service_init(&svc, NULL);
    ozayn_rag_admission_t out;
    ASSERT_EQ(ozayn_rag_get_decision(&svc, "NONEXISTENT", &out),
              OZAYN_RAG_ERR_NOT_FOUND);
    ozayn_rag_service_shutdown(&svc);
    return 0;
}

TEST(test_rag_get_latest_decision_empty) {
    ozayn_rag_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_rag_service_init(&svc, NULL);
    ozayn_rag_admission_t out;
    ASSERT_EQ(ozayn_rag_get_latest_decision(&svc, &out), OZAYN_RAG_ERR_NOT_FOUND);
    ozayn_rag_service_shutdown(&svc);
    return 0;
}

TEST(test_rag_get_latest_decision_ok) {
    ozayn_rag_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_rag_service_init(&svc, NULL);
    ozayn_rag_request_t req = _make_request("R1", "OP1");
    ozayn_rag_context_t ctx = _make_ready_ctx();
    ozayn_rag_admission_t d;
    ozayn_rag_admit(&svc, &req, &ctx, &d);
    ozayn_rag_admission_t latest;
    ASSERT_EQ(ozayn_rag_get_latest_decision(&svc, &latest), OZAYN_RAG_OK);
    ASSERT(strcmp(latest.id, d.id) == 0);
    ozayn_rag_service_shutdown(&svc);
    return 0;
}

TEST(test_rag_decision_count_null) {
    ASSERT_EQ(ozayn_rag_decision_count(NULL), 0);
    return 0;
}

TEST(test_rag_decision_count_after_admit) {
    ozayn_rag_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_rag_service_init(&svc, NULL);
    ASSERT_EQ(ozayn_rag_decision_count(&svc), 0);
    ozayn_rag_request_t req = _make_request("R1", "OP1");
    ozayn_rag_context_t ctx = _make_ready_ctx();
    ozayn_rag_admission_t d;
    ozayn_rag_admit(&svc, &req, &ctx, &d);
    ASSERT_EQ(ozayn_rag_decision_count(&svc), 1);
    ozayn_rag_service_shutdown(&svc);
    return 0;
}

/* ============================================================
 * REQUEST QUERY TESTS
 * ============================================================ */

TEST(test_rag_get_request_null) {
    ozayn_rag_request_t out;
    ASSERT_EQ(ozayn_rag_get_request(NULL, "x", &out), OZAYN_RAG_ERR_NULL);
    return 0;
}

TEST(test_rag_get_request_not_found) {
    ozayn_rag_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_rag_service_init(&svc, NULL);
    ozayn_rag_request_t out;
    ASSERT_EQ(ozayn_rag_get_request(&svc, "NONEXISTENT", &out),
              OZAYN_RAG_ERR_NOT_FOUND);
    ozayn_rag_service_shutdown(&svc);
    return 0;
}

TEST(test_rag_request_count_null) {
    ASSERT_EQ(ozayn_rag_request_count(NULL), 0);
    return 0;
}

TEST(test_rag_request_count_after_admit) {
    ozayn_rag_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_rag_service_init(&svc, NULL);
    ASSERT_EQ(ozayn_rag_request_count(&svc), 0);
    ozayn_rag_request_t req = _make_request("R1", "OP1");
    ozayn_rag_context_t ctx = _make_ready_ctx();
    ozayn_rag_admission_t d;
    ozayn_rag_admit(&svc, &req, &ctx, &d);
    ASSERT_EQ(ozayn_rag_request_count(&svc), 1);
    ozayn_rag_service_shutdown(&svc);
    return 0;
}

/* ============================================================
 * EVENT TESTS
 * ============================================================ */

TEST(test_rag_event_count_null) {
    ASSERT_EQ(ozayn_rag_event_count(NULL), 0);
    return 0;
}

TEST(test_rag_event_count_after_admit) {
    ozayn_rag_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_rag_service_init(&svc, NULL);
    int before = ozayn_rag_event_count(&svc);
    ozayn_rag_request_t req = _make_request("R1", "OP1");
    ozayn_rag_context_t ctx = _make_ready_ctx();
    ozayn_rag_admission_t d;
    ozayn_rag_admit(&svc, &req, &ctx, &d);
    ASSERT(ozayn_rag_event_count(&svc) > before);
    ozayn_rag_service_shutdown(&svc);
    return 0;
}

TEST(test_rag_get_event_null) {
    ozayn_rag_event_t e;
    ASSERT_EQ(ozayn_rag_get_event(NULL, 0, &e), OZAYN_RAG_ERR_NULL);
    return 0;
}

TEST(test_rag_get_event_out_of_range) {
    ozayn_rag_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_rag_service_init(&svc, NULL);
    ozayn_rag_event_t e;
    ASSERT_EQ(ozayn_rag_get_event(&svc, 9999, &e), OZAYN_RAG_ERR_NOT_FOUND);
    ozayn_rag_service_shutdown(&svc);
    return 0;
}

TEST(test_rag_event_sequence_increments) {
    ozayn_rag_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_rag_service_init(&svc, NULL);

    ozayn_rag_request_t req1 = _make_request("R1", "OP1");
    ozayn_rag_context_t ctx = _make_ready_ctx();
    ozayn_rag_admission_t d1;
    ozayn_rag_admit(&svc, &req1, &ctx, &d1);
    int count1 = ozayn_rag_event_count(&svc);
    ASSERT(count1 >= 2);

    ozayn_rag_event_t e1, e2;
    ASSERT_EQ(ozayn_rag_get_event(&svc, count1 - 2, &e1), OZAYN_RAG_OK);
    ASSERT_EQ(ozayn_rag_get_event(&svc, count1 - 1, &e2), OZAYN_RAG_OK);
    ASSERT(e2.sequence > e1.sequence);
    ozayn_rag_service_shutdown(&svc);
    return 0;
}

/* ============================================================
 * STATS TESTS
 * ============================================================ */

TEST(test_rag_stats_null) {
    ASSERT(ozayn_rag_get_stats(NULL) == NULL);
    return 0;
}

TEST(test_rag_stats_initial_zero) {
    ozayn_rag_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_rag_service_init(&svc, NULL);
    const ozayn_rag_stats_t *s = ozayn_rag_get_stats(&svc);
    ASSERT(s != NULL);
    ASSERT_EQ(s->total_requests, 0);
    ASSERT_EQ(s->total_accepted, 0);
    ASSERT_EQ(s->total_denied, 0);
    ASSERT_EQ(s->total_blocked, 0);
    ozayn_rag_service_shutdown(&svc);
    return 0;
}

TEST(test_rag_stats_after_accept) {
    ozayn_rag_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_rag_service_init(&svc, NULL);
    ozayn_rag_request_t req = _make_request("R1", "OP1");
    ozayn_rag_context_t ctx = _make_ready_ctx();
    ozayn_rag_admission_t d;
    ozayn_rag_admit(&svc, &req, &ctx, &d);
    const ozayn_rag_stats_t *s = ozayn_rag_get_stats(&svc);
    ASSERT_EQ(s->total_requests, 1);
    ASSERT_EQ(s->total_accepted, 1);
    ozayn_rag_service_shutdown(&svc);
    return 0;
}

TEST(test_rag_stats_after_deny) {
    ozayn_rag_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_rag_service_init(&svc, NULL);
    ozayn_rag_request_t req = _make_request("R1", "OP1");
    ozayn_rag_context_t ctx = _make_ready_ctx();
    ctx.runtime_mode = OZAYN_ORD_MODE_SHUTTING_DOWN;
    ozayn_rag_admission_t d;
    ozayn_rag_admit(&svc, &req, &ctx, &d);
    const ozayn_rag_stats_t *s = ozayn_rag_get_stats(&svc);
    ASSERT_EQ(s->total_denied, 1);
    ASSERT_EQ(s->mode_denials, 1);
    ozayn_rag_service_shutdown(&svc);
    return 0;
}

TEST(test_rag_stats_after_block) {
    ozayn_rag_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_rag_service_init(&svc, NULL);
    ozayn_rag_request_t req = _make_request("R1", "OP1");
    ozayn_rag_context_t ctx = _make_ready_ctx();
    ctx.runtime_mode = OZAYN_ORD_MODE_SAFE_HOLD;
    ozayn_rag_admission_t d;
    ozayn_rag_admit(&svc, &req, &ctx, &d);
    const ozayn_rag_stats_t *s = ozayn_rag_get_stats(&svc);
    ASSERT_EQ(s->total_blocked, 1);
    ozayn_rag_service_shutdown(&svc);
    return 0;
}

TEST(test_rag_stats_after_queue) {
    ozayn_rag_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_rag_service_init(&svc, NULL);
    ozayn_rag_request_t req = _make_request("R1", "OP1");
    ozayn_rag_context_t ctx = _make_ready_ctx();
    ctx.scheduler_eligible = 0;
    ozayn_rag_admission_t d;
    ozayn_rag_admit(&svc, &req, &ctx, &d);
    const ozayn_rag_stats_t *s = ozayn_rag_get_stats(&svc);
    ASSERT_EQ(s->total_queued, 1);
    ozayn_rag_service_shutdown(&svc);
    return 0;
}

TEST(test_rag_stats_after_expire) {
    ozayn_rag_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_rag_service_init(&svc, NULL);
    ozayn_rag_request_t req = _make_request("R1", "OP1");
    req.expiration_ms = 1;
    ozayn_rag_context_t ctx = _make_ready_ctx();
    ozayn_rag_admission_t d;
    ozayn_rag_admit(&svc, &req, &ctx, &d);
    const ozayn_rag_stats_t *s = ozayn_rag_get_stats(&svc);
    ASSERT_EQ(s->total_expired, 1);
    ozayn_rag_service_shutdown(&svc);
    return 0;
}

TEST(test_rag_reset_stats) {
    ozayn_rag_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_rag_service_init(&svc, NULL);
    ozayn_rag_request_t req = _make_request("R1", "OP1");
    ozayn_rag_context_t ctx = _make_ready_ctx();
    ozayn_rag_admission_t d;
    ozayn_rag_admit(&svc, &req, &ctx, &d);
    ASSERT_EQ(ozayn_rag_reset_stats(&svc), OZAYN_RAG_OK);
    const ozayn_rag_stats_t *s = ozayn_rag_get_stats(&svc);
    ASSERT_EQ(s->total_requests, 0);
    ASSERT_EQ(s->total_accepted, 0);
    ozayn_rag_service_shutdown(&svc);
    return 0;
}

TEST(test_rag_reset_stats_null) {
    ASSERT_EQ(ozayn_rag_reset_stats(NULL), OZAYN_RAG_ERR_NULL);
    return 0;
}

/* ============================================================
 * NAME HELPERS TESTS
 * ============================================================ */

TEST(test_rag_err_name_all) {
    ASSERT(strcmp(ozayn_rag_err_name(OZAYN_RAG_OK), "OK") == 0);
    ASSERT(strcmp(ozayn_rag_err_name(OZAYN_RAG_ERR_NULL), "NULL") == 0);
    ASSERT(strcmp(ozayn_rag_err_name(OZAYN_RAG_ERR_NOT_INITIALIZED),
                  "NOT_INITIALIZED") == 0);
    ASSERT(strcmp(ozayn_rag_err_name(OZAYN_RAG_ERR_MODE_BLOCKED),
                  "MODE_BLOCKED") == 0);
    ASSERT(strcmp(ozayn_rag_err_name(OZAYN_RAG_ERR_SAFETY_UNAVAILABLE),
                  "SAFETY_UNAVAILABLE") == 0);
    ASSERT(strcmp(ozayn_rag_err_name(OZAYN_RAG_ERR_CONCURRENCY_ERROR),
                  "CONCURRENCY_ERROR") == 0);
    ASSERT(strcmp(ozayn_rag_err_name(OZAYN_RAG_ERR_LIMIT_REACHED),
                  "LIMIT_REACHED") == 0);
    return 0;
}

TEST(test_rag_decision_name_all) {
    ASSERT(strcmp(ozayn_rag_decision_name(OZAYN_RAG_DECISION_ACCEPT), "ACCEPT") == 0);
    ASSERT(strcmp(ozayn_rag_decision_name(OZAYN_RAG_DECISION_QUEUE), "QUEUE") == 0);
    ASSERT(strcmp(ozayn_rag_decision_name(OZAYN_RAG_DECISION_DEFER), "DEFER") == 0);
    ASSERT(strcmp(ozayn_rag_decision_name(OZAYN_RAG_DECISION_DENY), "DENY") == 0);
    ASSERT(strcmp(ozayn_rag_decision_name(OZAYN_RAG_DECISION_BLOCKED), "BLOCKED") == 0);
    ASSERT(strcmp(ozayn_rag_decision_name(OZAYN_RAG_DECISION_EXPIRED), "EXPIRED") == 0);
    ASSERT(strcmp(ozayn_rag_decision_name(OZAYN_RAG_DECISION_UNAVAILABLE),
                  "UNAVAILABLE") == 0);
    ASSERT(strcmp(ozayn_rag_decision_name(OZAYN_RAG_DECISION_REQUIRES_AUTHORIZATION),
                  "REQUIRES_AUTHORIZATION") == 0);
    ASSERT(strcmp(ozayn_rag_decision_name(OZAYN_RAG_DECISION_REQUIRES_SAFETY_CHECK),
                  "REQUIRES_SAFETY_CHECK") == 0);
    ASSERT(strcmp(ozayn_rag_decision_name(OZAYN_RAG_DECISION_REQUIRES_RESOURCE_CHECK),
                  "REQUIRES_RESOURCE_CHECK") == 0);
    ASSERT(strcmp(ozayn_rag_decision_name(OZAYN_RAG_DECISION_REQUIRES_DEVICE_CHECK),
                  "REQUIRES_DEVICE_CHECK") == 0);
    ASSERT(strcmp(ozayn_rag_decision_name(OZAYN_RAG_DECISION_REQUIRES_RECOVERY),
                  "REQUIRES_RECOVERY") == 0);
    ASSERT(strcmp(ozayn_rag_decision_name(OZAYN_RAG_DECISION_REQUIRES_REASSESSMENT),
                  "REQUIRES_REASSESSMENT") == 0);
    return 0;
}

TEST(test_rag_phase_name_all) {
    ASSERT(strcmp(ozayn_rag_phase_name(OZAYN_RAG_PHASE_NONE), "NONE") == 0);
    ASSERT(strcmp(ozayn_rag_phase_name(OZAYN_RAG_PHASE_REQUESTED), "REQUESTED") == 0);
    ASSERT(strcmp(ozayn_rag_phase_name(OZAYN_RAG_PHASE_VALIDATING), "VALIDATING") == 0);
    ASSERT(strcmp(ozayn_rag_phase_name(OZAYN_RAG_PHASE_EVALUATING), "EVALUATING") == 0);
    ASSERT(strcmp(ozayn_rag_phase_name(OZAYN_RAG_PHASE_ACCEPTED), "ACCEPTED") == 0);
    ASSERT(strcmp(ozayn_rag_phase_name(OZAYN_RAG_PHASE_DENIED), "DENIED") == 0);
    ASSERT(strcmp(ozayn_rag_phase_name(OZAYN_RAG_PHASE_DEFERRED), "DEFERRED") == 0);
    ASSERT(strcmp(ozayn_rag_phase_name(OZAYN_RAG_PHASE_BLOCKED), "BLOCKED") == 0);
    ASSERT(strcmp(ozayn_rag_phase_name(OZAYN_RAG_PHASE_EXPIRED), "EXPIRED") == 0);
    ASSERT(strcmp(ozayn_rag_phase_name(OZAYN_RAG_PHASE_INVALIDATED), "INVALIDATED") == 0);
    ASSERT(strcmp(ozayn_rag_phase_name(OZAYN_RAG_PHASE_CANCELLED), "CANCELLED") == 0);
    return 0;
}

TEST(test_rag_event_type_name_all) {
    ASSERT(strcmp(ozayn_rag_event_type_name(OZAYN_RAG_EVENT_REQUESTED), "REQUESTED") == 0);
    ASSERT(strcmp(ozayn_rag_event_type_name(OZAYN_RAG_EVENT_ACCEPTED), "ACCEPTED") == 0);
    ASSERT(strcmp(ozayn_rag_event_type_name(OZAYN_RAG_EVENT_QUEUED), "QUEUED") == 0);
    ASSERT(strcmp(ozayn_rag_event_type_name(OZAYN_RAG_EVENT_DEFERRED), "DEFERRED") == 0);
    ASSERT(strcmp(ozayn_rag_event_type_name(OZAYN_RAG_EVENT_DENIED), "DENIED") == 0);
    ASSERT(strcmp(ozayn_rag_event_type_name(OZAYN_RAG_EVENT_BLOCKED), "BLOCKED") == 0);
    ASSERT(strcmp(ozayn_rag_event_type_name(OZAYN_RAG_EVENT_EXPIRED), "EXPIRED") == 0);
    ASSERT(strcmp(ozayn_rag_event_type_name(OZAYN_RAG_EVENT_INVALIDATED),
                  "INVALIDATED") == 0);
    ASSERT(strcmp(ozayn_rag_event_type_name(OZAYN_RAG_EVENT_REVOKED), "REVOKED") == 0);
    ASSERT(strcmp(ozayn_rag_event_type_name(OZAYN_RAG_EVENT_REASSESSMENT_STARTED),
                  "REASSESSMENT_STARTED") == 0);
    ASSERT(strcmp(ozayn_rag_event_type_name(OZAYN_RAG_EVENT_REASSESSMENT_COMPLETED),
                  "REASSESSMENT_COMPLETED") == 0);
    ASSERT(strcmp(ozayn_rag_event_type_name(OZAYN_RAG_EVENT_AUTHORIZATION_REQUIRED),
                  "AUTHORIZATION_REQUIRED") == 0);
    ASSERT(strcmp(ozayn_rag_event_type_name(OZAYN_RAG_EVENT_SAFETY_CHECK_REQUIRED),
                  "SAFETY_CHECK_REQUIRED") == 0);
    ASSERT(strcmp(ozayn_rag_event_type_name(OZAYN_RAG_EVENT_RESOURCE_CHECK_REQUIRED),
                  "RESOURCE_CHECK_REQUIRED") == 0);
    ASSERT(strcmp(ozayn_rag_event_type_name(OZAYN_RAG_EVENT_DEVICE_CHECK_REQUIRED),
                  "DEVICE_CHECK_REQUIRED") == 0);
    ASSERT(strcmp(ozayn_rag_event_type_name(OZAYN_RAG_EVENT_REASSESSMENT_REQUIRED),
                  "REASSESSMENT_REQUIRED") == 0);
    return 0;
}

/* ============================================================
 * SHUTDOWN STATE TESTS
 * ============================================================ */

TEST(test_rag_ops_after_shutdown) {
    ozayn_rag_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_rag_service_init(&svc, NULL);
    ozayn_rag_service_shutdown(&svc);
    ozayn_rag_request_t req = _make_request("R1", "OP1");
    ozayn_rag_context_t ctx = _make_ready_ctx();
    ozayn_rag_admission_t d;
    ASSERT_EQ(ozayn_rag_admit(&svc, &req, &ctx, &d), OZAYN_RAG_ERR_NOT_INITIALIZED);
    ASSERT_EQ(ozayn_rag_decision_count(&svc), 0);
    ASSERT_EQ(ozayn_rag_request_count(&svc), 0);
    ASSERT_EQ(ozayn_rag_event_count(&svc), 0);
    ASSERT(!ozayn_rag_can_admit(&svc, &req, &ctx));
    return 0;
}

TEST(test_rag_multiple_admissions) {
    ozayn_rag_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_rag_service_init(&svc, NULL);
    ozayn_rag_context_t ctx = _make_ready_ctx();

    ozayn_rag_request_t r1 = _make_request("R1", "OP1");
    ozayn_rag_request_t r2 = _make_request("R2", "OP2");
    ozayn_rag_request_t r3 = _make_request("R3", "OP3");
    r3.expiration_ms = 1;

    ozayn_rag_admission_t d1, d2, d3;
    ozayn_rag_admit(&svc, &r1, &ctx, &d1);
    ozayn_rag_admit(&svc, &r2, &ctx, &d2);
    ozayn_rag_admit(&svc, &r3, &ctx, &d3);

    ASSERT_EQ(ozayn_rag_decision_count(&svc), 3);
    ASSERT_EQ(ozayn_rag_request_count(&svc), 3);
    ASSERT_EQ(d1.decision, OZAYN_RAG_DECISION_ACCEPT);
    ASSERT_EQ(d2.decision, OZAYN_RAG_DECISION_ACCEPT);
    ASSERT_EQ(d3.decision, OZAYN_RAG_DECISION_EXPIRED);
    ozayn_rag_service_shutdown(&svc);
    return 0;
}

/* ============================================================
 * CONCURRENCY TEST
 * ============================================================ */

TEST(test_rag_concurrent_mode_change_during_admit) {
    ozayn_rag_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_rag_service_init(&svc, NULL);

    ozayn_rag_request_t req = _make_request("R1", "OP1");
    ozayn_rag_context_t ctx = _make_ready_ctx();
    ozayn_rag_admission_t d;
    ozayn_rag_admit(&svc, &req, &ctx, &d);
    ASSERT_EQ(d.decision, OZAYN_RAG_DECISION_ACCEPT);

    /* Mode changes after admission */
    ctx.runtime_mode = OZAYN_ORD_MODE_SAFE_HOLD;
    ASSERT(!ozayn_rag_can_admit(&svc, &req, &ctx));

    /* Reassessment should detect the mode change */
    ozayn_rag_admission_t d2;
    ozayn_rag_reassess(&svc, d.id, &ctx, &d2);
    ASSERT_EQ(d2.decision, OZAYN_RAG_DECISION_BLOCKED);
    ozayn_rag_service_shutdown(&svc);
    return 0;
}

/* ============================================================
 * RUNNER
 * ============================================================ */

int run_cr_runtime_admission_gate_tests(void) {
    int fail = 0;
    printf("\n  --- CR RUNTIME ADMISSION GATE ---");
    SUITE_BEGIN("Runtime Admission Gate");

    /* Lifecycle */
    RUN(test_rag_init_null);
    RUN(test_rag_init_ok);
    RUN(test_rag_double_init);
    RUN(test_rag_shutdown_null);
    RUN(test_rag_shutdown_not_init);
    RUN(test_rag_shutdown_ok);
    RUN(test_rag_init_with_config);

    /* Subsystems */
    RUN(test_rag_set_subsystems_null);
    RUN(test_rag_set_all_subsystems);

    /* Basic admission */
    RUN(test_rag_admit_null);
    RUN(test_rag_admit_not_init);
    RUN(test_rag_admit_empty_request_id);
    RUN(test_rag_admit_valid_ready);
    RUN(test_rag_admit_records_request);
    RUN(test_rag_admit_records_decision);
    RUN(test_rag_admit_generates_ids);

    /* Mode enforcement */
    RUN(test_rag_mode_ready_degraded);
    RUN(test_rag_mode_recovery);
    RUN(test_rag_mode_maintenance);
    RUN(test_rag_mode_safe_hold);
    RUN(test_rag_mode_blocked);
    RUN(test_rag_mode_shutting_down);
    RUN(test_rag_mode_failed);
    RUN(test_rag_mode_unknown);
    RUN(test_rag_mode_initializing);

    /* Security / Safety / Resource / Device */
    RUN(test_rag_readiness_not_satisfied);
    RUN(test_rag_component_unavailable);
    RUN(test_rag_no_target_always_ok);
    RUN(test_rag_capability_unavailable);
    RUN(test_rag_security_session_invalid);
    RUN(test_rag_authorization_failed);
    RUN(test_rag_safety_failed);
    RUN(test_rag_resource_unavailable);
    RUN(test_rag_device_unavailable);
    RUN(test_rag_workflow_blocked);
    RUN(test_rag_pipeline_blocked);
    RUN(test_rag_dependency_failed);
    RUN(test_rag_scheduler_not_eligible);

    /* Quick check */
    RUN(test_rag_can_admit_null);
    RUN(test_rag_can_admit_not_init);
    RUN(test_rag_can_admit_ready);
    RUN(test_rag_can_admit_blocked_mode);
    RUN(test_rag_can_admit_empty_id);
    RUN(test_rag_can_admit_no_safety);

    /* Expiration */
    RUN(test_rag_admit_expired_request);

    /* Reassessment */
    RUN(test_rag_reassess_null);
    RUN(test_rag_reassess_not_found);
    RUN(test_rag_reassess_ok);
    RUN(test_rag_reassess_limit);

    /* Invalidation */
    RUN(test_rag_invalidate_null);
    RUN(test_rag_invalidate_not_found);
    RUN(test_rag_invalidate_ok);
    RUN(test_rag_invalidate_already_invalidated);

    /* Decision queries */
    RUN(test_rag_get_decision_null);
    RUN(test_rag_get_decision_not_found);
    RUN(test_rag_get_latest_decision_empty);
    RUN(test_rag_get_latest_decision_ok);
    RUN(test_rag_decision_count_null);
    RUN(test_rag_decision_count_after_admit);

    /* Request queries */
    RUN(test_rag_get_request_null);
    RUN(test_rag_get_request_not_found);
    RUN(test_rag_request_count_null);
    RUN(test_rag_request_count_after_admit);

    /* Events */
    RUN(test_rag_event_count_null);
    RUN(test_rag_event_count_after_admit);
    RUN(test_rag_get_event_null);
    RUN(test_rag_get_event_out_of_range);
    RUN(test_rag_event_sequence_increments);

    /* Stats */
    RUN(test_rag_stats_null);
    RUN(test_rag_stats_initial_zero);
    RUN(test_rag_stats_after_accept);
    RUN(test_rag_stats_after_deny);
    RUN(test_rag_stats_after_block);
    RUN(test_rag_stats_after_queue);
    RUN(test_rag_stats_after_expire);
    RUN(test_rag_reset_stats);
    RUN(test_rag_reset_stats_null);

    /* Name helpers */
    RUN(test_rag_err_name_all);
    RUN(test_rag_decision_name_all);
    RUN(test_rag_phase_name_all);
    RUN(test_rag_event_type_name_all);

    /* Shutdown */
    RUN(test_rag_ops_after_shutdown);
    RUN(test_rag_multiple_admissions);

    /* Concurrency */
    RUN(test_rag_concurrent_mode_change_during_admit);

    SUITE_END();
    fail = TOTAL_FAIL();
    return fail;
}
