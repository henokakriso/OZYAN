/*
 * test_execution_result.c — Section 04, Step 24
 * Execution Result & Post-Execution State Reconciliation tests
 */

#include "../../tests/test_framework.h"
#include "../execution_result.h"
#include <string.h>

/* ============================================================
 * HELPERS
 * ============================================================ */

static ozayn_xr_service_t _make_svc(void) {
    ozayn_xr_service_t svc;
    memset(&svc, 0, sizeof(svc));
    svc.initialized = 1;
    return svc;
}

static ozayn_xr_service_t _make_svc_bound(void) {
    ozayn_xr_service_t svc;
    memset(&svc, 0, sizeof(svc));
    svc.initialized = 1;
    ozayn_xr_subsystem_bind_t bind;
    memset(&bind, 0, sizeof(bind));
    int dummy = 1;
    bind.component_registry = &dummy;
    bind.resource_manager = &dummy;
    bind.device_session = &dummy;
    bind.workflow_orchestrator = &dummy;
    bind.pipeline_coordinator = &dummy;
    bind.pipeline_scheduler = &dummy;
    ozayn_xr_bind_subsystems(&svc, &bind);
    return svc;
}

/* ============================================================
 * LIFECYCLE TESTS
 * ============================================================ */

TEST(test_xr_init_null) {
    ASSERT_EQ(ozayn_xr_init(NULL), OZAYN_XR_ERR_NULL_PTR);
    return 0;
}

TEST(test_xr_init_ok) {
    ozayn_xr_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ASSERT_EQ(ozayn_xr_init(&svc), OZAYN_XR_ERR_OK);
    ASSERT(svc.initialized);
    ASSERT_EQ(svc.result_count, 0);
    ASSERT_EQ(svc.recon_count, 0);
    ASSERT_EQ(svc.event_count, 0);
    ASSERT_EQ(svc.sequence, 0);
    return 0;
}

TEST(test_xr_double_init) {
    ozayn_xr_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ASSERT_EQ(ozayn_xr_init(&svc), OZAYN_XR_ERR_OK);
    ASSERT_EQ(ozayn_xr_init(&svc), OZAYN_XR_ERR_ALREADY_INITIALIZED);
    return 0;
}

TEST(test_xr_shutdown_null) {
    ASSERT_EQ(ozayn_xr_shutdown(NULL), OZAYN_XR_ERR_NULL_PTR);
    return 0;
}

TEST(test_xr_shutdown_not_init) {
    ozayn_xr_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ASSERT_EQ(ozayn_xr_shutdown(&svc), OZAYN_XR_ERR_NOT_INITIALIZED);
    return 0;
}

TEST(test_xr_shutdown_ok) {
    ozayn_xr_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ASSERT_EQ(ozayn_xr_init(&svc), OZAYN_XR_ERR_OK);
    ASSERT_EQ(ozayn_xr_shutdown(&svc), OZAYN_XR_ERR_OK);
    ASSERT(!svc.initialized);
    return 0;
}

TEST(test_xr_is_initialized) {
    ozayn_xr_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ASSERT(!ozayn_xr_is_initialized(&svc));
    svc.initialized = 1;
    ASSERT(ozayn_xr_is_initialized(&svc));
    ASSERT(!ozayn_xr_is_initialized(NULL));
    return 0;
}

/* ============================================================
 * SUBSYSTEM BINDING TESTS
 * ============================================================ */

TEST(test_xr_bind_null) {
    ASSERT_EQ(ozayn_xr_bind_subsystems(NULL, NULL), OZAYN_XR_ERR_NULL_PTR);
    return 0;
}

TEST(test_xr_bind_not_init) {
    ozayn_xr_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_xr_subsystem_bind_t bind;
    memset(&bind, 0, sizeof(bind));
    ASSERT_EQ(ozayn_xr_bind_subsystems(&svc, &bind), OZAYN_XR_ERR_NOT_INITIALIZED);
    return 0;
}

TEST(test_xr_bind_ok) {
    ozayn_xr_service_t svc = _make_svc();
    ozayn_xr_subsystem_bind_t bind;
    memset(&bind, 0, sizeof(bind));
    int dummy = 42;
    bind.component_registry = &dummy;
    bind.resource_manager = &dummy;
    bind.device_session = &dummy;
    ASSERT_EQ(ozayn_xr_bind_subsystems(&svc, &bind), OZAYN_XR_ERR_OK);
    ASSERT(svc.bind.component_registry == &dummy);
    ASSERT(svc.bind.resource_manager == &dummy);
    ASSERT(svc.bind.device_session == &dummy);
    return 0;
}

/* ============================================================
 * NAME HELPERS
 * ============================================================ */

TEST(test_xr_exec_state_name_all) {
    ASSERT_STR_EQ(ozayn_xr_exec_state_name(OZAYN_XR_EXEC_STARTED), "STARTED");
    ASSERT_STR_EQ(ozayn_xr_exec_state_name(OZAYN_XR_EXEC_SUCCEEDED), "SUCCEEDED");
    ASSERT_STR_EQ(ozayn_xr_exec_state_name(OZAYN_XR_EXEC_FAILED), "FAILED");
    ASSERT_STR_EQ(ozayn_xr_exec_state_name(OZAYN_XR_EXEC_PARTIAL), "PARTIAL");
    ASSERT_STR_EQ(ozayn_xr_exec_state_name(OZAYN_XR_EXEC_CANCELLED), "CANCELLED");
    ASSERT_STR_EQ(ozayn_xr_exec_state_name(OZAYN_XR_EXEC_TIMEOUT), "TIMEOUT");
    ASSERT_STR_EQ(ozayn_xr_exec_state_name(OZAYN_XR_EXEC_INTERRUPTED), "INTERRUPTED");
    ASSERT_STR_EQ(ozayn_xr_exec_state_name(OZAYN_XR_EXEC_UNKNOWN), "UNKNOWN");
    ASSERT_STR_EQ(ozayn_xr_exec_state_name(OZAYN_XR_EXEC_UNAVAILABLE), "UNAVAILABLE");
    return 0;
}

TEST(test_xr_result_outcome_name_all) {
    ASSERT_STR_EQ(ozayn_xr_result_outcome_name(OZAYN_XR_RESULT_SUCCESS), "SUCCESS");
    ASSERT_STR_EQ(ozayn_xr_result_outcome_name(OZAYN_XR_RESULT_FAILED), "FAILED");
    ASSERT_STR_EQ(ozayn_xr_result_outcome_name(OZAYN_XR_RESULT_PARTIAL), "PARTIAL");
    ASSERT_STR_EQ(ozayn_xr_result_outcome_name(OZAYN_XR_RESULT_CANCELLED), "CANCELLED");
    ASSERT_STR_EQ(ozayn_xr_result_outcome_name(OZAYN_XR_RESULT_TIMEOUT), "TIMEOUT");
    ASSERT_STR_EQ(ozayn_xr_result_outcome_name(OZAYN_XR_RESULT_INTERRUPTED), "INTERRUPTED");
    ASSERT_STR_EQ(ozayn_xr_result_outcome_name(OZAYN_XR_RESULT_UNKNOWN), "UNKNOWN");
    ASSERT_STR_EQ(ozayn_xr_result_outcome_name(OZAYN_XR_RESULT_UNAVAILABLE), "UNAVAILABLE");
    ASSERT_STR_EQ(ozayn_xr_result_outcome_name(OZAYN_XR_RESULT_DUPLICATE), "DUPLICATE");
    return 0;
}

TEST(test_xr_recon_state_name_all) {
    ASSERT_STR_EQ(ozayn_xr_recon_state_name(OZAYN_XR_RECON_PENDING), "PENDING");
    ASSERT_STR_EQ(ozayn_xr_recon_state_name(OZAYN_XR_RECON_IN_PROGRESS), "IN_PROGRESS");
    ASSERT_STR_EQ(ozayn_xr_recon_state_name(OZAYN_XR_RECON_CONSISTENT), "CONSISTENT");
    ASSERT_STR_EQ(ozayn_xr_recon_state_name(OZAYN_XR_RECON_STATE_CHANGED_AS_EXPECTED), "STATE_CHANGED_AS_EXPECTED");
    ASSERT_STR_EQ(ozayn_xr_recon_state_name(OZAYN_XR_RECON_STATE_CHANGED_UNEXPECTEDLY), "STATE_CHANGED_UNEXPECTEDLY");
    ASSERT_STR_EQ(ozayn_xr_recon_state_name(OZAYN_XR_RECON_PARTIAL), "PARTIAL");
    ASSERT_STR_EQ(ozayn_xr_recon_state_name(OZAYN_XR_RECON_INCONSISTENT), "INCONSISTENT");
    ASSERT_STR_EQ(ozayn_xr_recon_state_name(OZAYN_XR_RECON_UNKNOWN), "UNKNOWN");
    ASSERT_STR_EQ(ozayn_xr_recon_state_name(OZAYN_XR_RECON_UNAVAILABLE), "UNAVAILABLE");
    ASSERT_STR_EQ(ozayn_xr_recon_state_name(OZAYN_XR_RECON_REQUIRES_DIAGNOSTICS), "REQUIRES_DIAGNOSTICS");
    return 0;
}

TEST(test_xr_event_type_name_all) {
    ASSERT_STR_EQ(ozayn_xr_event_type_name(OZAYN_XR_EVENT_EXEC_STARTED), "EXEC_STARTED");
    ASSERT_STR_EQ(ozayn_xr_event_type_name(OZAYN_XR_EVENT_EXEC_COMPLETED), "EXEC_COMPLETED");
    ASSERT_STR_EQ(ozayn_xr_event_type_name(OZAYN_XR_EVENT_EXEC_SUCCEEDED), "EXEC_SUCCEEDED");
    ASSERT_STR_EQ(ozayn_xr_event_type_name(OZAYN_XR_EVENT_EXEC_FAILED), "EXEC_FAILED");
    ASSERT_STR_EQ(ozayn_xr_event_type_name(OZAYN_XR_EVENT_EXEC_PARTIAL), "EXEC_PARTIAL");
    ASSERT_STR_EQ(ozayn_xr_event_type_name(OZAYN_XR_EVENT_EXEC_CANCELLED), "EXEC_CANCELLED");
    ASSERT_STR_EQ(ozayn_xr_event_type_name(OZAYN_XR_EVENT_EXEC_TIMEOUT), "EXEC_TIMEOUT");
    ASSERT_STR_EQ(ozayn_xr_event_type_name(OZAYN_XR_EVENT_EXEC_INTERRUPTED), "EXEC_INTERRUPTED");
    ASSERT_STR_EQ(ozayn_xr_event_type_name(OZAYN_XR_EVENT_EXEC_UNKNOWN), "EXEC_UNKNOWN");
    ASSERT_STR_EQ(ozayn_xr_event_type_name(OZAYN_XR_EVENT_RECON_STARTED), "RECON_STARTED");
    ASSERT_STR_EQ(ozayn_xr_event_type_name(OZAYN_XR_EVENT_RECON_COMPLETED), "RECON_COMPLETED");
    ASSERT_STR_EQ(ozayn_xr_event_type_name(OZAYN_XR_EVENT_RECON_CONSISTENT), "RECON_CONSISTENT");
    ASSERT_STR_EQ(ozayn_xr_event_type_name(OZAYN_XR_EVENT_RECON_INCONSISTENT), "RECON_INCONSISTENT");
    ASSERT_STR_EQ(ozayn_xr_event_type_name(OZAYN_XR_EVENT_RECON_PARTIAL), "RECON_PARTIAL");
    ASSERT_STR_EQ(ozayn_xr_event_type_name(OZAYN_XR_EVENT_RECON_UNKNOWN), "RECON_UNKNOWN");
    ASSERT_STR_EQ(ozayn_xr_event_type_name(OZAYN_XR_EVENT_RECON_REQUIRED), "RECON_REQUIRED");
    ASSERT_STR_EQ(ozayn_xr_event_type_name(OZAYN_XR_EVENT_RESULT_RECORDED), "RESULT_RECORDED");
    ASSERT_STR_EQ(ozayn_xr_event_type_name(OZAYN_XR_EVENT_STATE_RECON_REQUIRED), "STATE_RECON_REQUIRED");
    return 0;
}

TEST(test_xr_target_state_name_all) {
    ASSERT_STR_EQ(ozayn_xr_target_state_name(OZAYN_XR_TARGET_AVAILABLE), "AVAILABLE");
    ASSERT_STR_EQ(ozayn_xr_target_state_name(OZAYN_XR_TARGET_UNAVAILABLE), "UNAVAILABLE");
    ASSERT_STR_EQ(ozayn_xr_target_state_name(OZAYN_XR_TARGET_UNKNOWN), "UNKNOWN");
    return 0;
}

TEST(test_xr_resource_state_name_all) {
    ASSERT_STR_EQ(ozayn_xr_resource_state_name(OZAYN_XR_RESOURCE_OK), "OK");
    ASSERT_STR_EQ(ozayn_xr_resource_state_name(OZAYN_XR_RESOURCE_LEAK_DETECTED), "LEAK_DETECTED");
    ASSERT_STR_EQ(ozayn_xr_resource_state_name(OZAYN_XR_RESOURCE_EXHAUSTED), "EXHAUSTED");
    ASSERT_STR_EQ(ozayn_xr_resource_state_name(OZAYN_XR_RESOURCE_MISMATCH), "MISMATCH");
    ASSERT_STR_EQ(ozayn_xr_resource_state_name(OZAYN_XR_RESOURCE_UNKNOWN), "UNKNOWN");
    ASSERT_STR_EQ(ozayn_xr_resource_state_name(OZAYN_XR_RESOURCE_UNAVAILABLE), "UNAVAILABLE");
    return 0;
}

TEST(test_xr_device_state_name_all) {
    ASSERT_STR_EQ(ozayn_xr_device_state_name(OZAYN_XR_DEVICE_OK), "OK");
    ASSERT_STR_EQ(ozayn_xr_device_state_name(OZAYN_XR_DEVICE_DISCONNECTED), "DISCONNECTED");
    ASSERT_STR_EQ(ozayn_xr_device_state_name(OZAYN_XR_DEVICE_SESSION_CLOSED), "SESSION_CLOSED");
    ASSERT_STR_EQ(ozayn_xr_device_state_name(OZAYN_XR_DEVICE_RESERVATION_LOST), "RESERVATION_LOST");
    ASSERT_STR_EQ(ozayn_xr_device_state_name(OZAYN_XR_DEVICE_UNKNOWN), "UNKNOWN");
    ASSERT_STR_EQ(ozayn_xr_device_state_name(OZAYN_XR_DEVICE_UNAVAILABLE), "UNAVAILABLE");
    return 0;
}

TEST(test_xr_workflow_state_name_all) {
    ASSERT_STR_EQ(ozayn_xr_workflow_state_name(OZAYN_XR_WORKFLOW_OK), "OK");
    ASSERT_STR_EQ(ozayn_xr_workflow_state_name(OZAYN_XR_WORKFLOW_STAGE_FAILED), "STAGE_FAILED");
    ASSERT_STR_EQ(ozayn_xr_workflow_state_name(OZAYN_XR_WORKFLOW_CANCELLED), "CANCELLED");
    ASSERT_STR_EQ(ozayn_xr_workflow_state_name(OZAYN_XR_WORKFLOW_UNKNOWN), "UNKNOWN");
    ASSERT_STR_EQ(ozayn_xr_workflow_state_name(OZAYN_XR_WORKFLOW_UNAVAILABLE), "UNAVAILABLE");
    return 0;
}

TEST(test_xr_pipeline_state_name_all) {
    ASSERT_STR_EQ(ozayn_xr_pipeline_state_name(OZAYN_XR_PIPELINE_OK), "OK");
    ASSERT_STR_EQ(ozayn_xr_pipeline_state_name(OZAYN_XR_PIPELINE_STAGE_FAILED), "STAGE_FAILED");
    ASSERT_STR_EQ(ozayn_xr_pipeline_state_name(OZAYN_XR_PIPELINE_FAILED), "FAILED");
    ASSERT_STR_EQ(ozayn_xr_pipeline_state_name(OZAYN_XR_PIPELINE_UNKNOWN), "UNKNOWN");
    ASSERT_STR_EQ(ozayn_xr_pipeline_state_name(OZAYN_XR_PIPELINE_UNAVAILABLE), "UNAVAILABLE");
    return 0;
}

TEST(test_xr_scheduler_state_name_all) {
    ASSERT_STR_EQ(ozayn_xr_scheduler_state_name(OZAYN_XR_SCHEDULER_RELEASED), "RELEASED");
    ASSERT_STR_EQ(ozayn_xr_scheduler_state_name(OZAYN_XR_SCHEDULER_STILL_RUNNING), "STILL_RUNNING");
    ASSERT_STR_EQ(ozayn_xr_scheduler_state_name(OZAYN_XR_SCHEDULER_UNKNOWN), "UNKNOWN");
    ASSERT_STR_EQ(ozayn_xr_scheduler_state_name(OZAYN_XR_SCHEDULER_UNAVAILABLE), "UNAVAILABLE");
    return 0;
}

TEST(test_xr_diagnostic_state_name_all) {
    ASSERT_STR_EQ(ozayn_xr_diagnostic_state_name(OZAYN_XR_DIAG_NONE), "NONE");
    ASSERT_STR_EQ(ozayn_xr_diagnostic_state_name(OZAYN_XR_DIAG_REQUESTED), "REQUESTED");
    ASSERT_STR_EQ(ozayn_xr_diagnostic_state_name(OZAYN_XR_DIAG_COMPLETED), "COMPLETED");
    ASSERT_STR_EQ(ozayn_xr_diagnostic_state_name(OZAYN_XR_DIAG_UNAVAILABLE), "UNAVAILABLE");
    return 0;
}

TEST(test_xr_is_exec_terminal) {
    ASSERT(ozayn_xr_is_exec_terminal(OZAYN_XR_EXEC_SUCCEEDED));
    ASSERT(ozayn_xr_is_exec_terminal(OZAYN_XR_EXEC_FAILED));
    ASSERT(ozayn_xr_is_exec_terminal(OZAYN_XR_EXEC_PARTIAL));
    ASSERT(ozayn_xr_is_exec_terminal(OZAYN_XR_EXEC_CANCELLED));
    ASSERT(ozayn_xr_is_exec_terminal(OZAYN_XR_EXEC_TIMEOUT));
    ASSERT(ozayn_xr_is_exec_terminal(OZAYN_XR_EXEC_INTERRUPTED));
    ASSERT(ozayn_xr_is_exec_terminal(OZAYN_XR_EXEC_UNKNOWN));
    ASSERT(ozayn_xr_is_exec_terminal(OZAYN_XR_EXEC_UNAVAILABLE));
    ASSERT(!ozayn_xr_is_exec_terminal(OZAYN_XR_EXEC_STARTED));
    return 0;
}

TEST(test_xr_is_recon_terminal) {
    ASSERT(ozayn_xr_is_recon_terminal(OZAYN_XR_RECON_CONSISTENT));
    ASSERT(ozayn_xr_is_recon_terminal(OZAYN_XR_RECON_STATE_CHANGED_AS_EXPECTED));
    ASSERT(ozayn_xr_is_recon_terminal(OZAYN_XR_RECON_STATE_CHANGED_UNEXPECTEDLY));
    ASSERT(ozayn_xr_is_recon_terminal(OZAYN_XR_RECON_PARTIAL));
    ASSERT(ozayn_xr_is_recon_terminal(OZAYN_XR_RECON_INCONSISTENT));
    ASSERT(ozayn_xr_is_recon_terminal(OZAYN_XR_RECON_UNKNOWN));
    ASSERT(ozayn_xr_is_recon_terminal(OZAYN_XR_RECON_UNAVAILABLE));
    ASSERT(ozayn_xr_is_recon_terminal(OZAYN_XR_RECON_REQUIRES_DIAGNOSTICS));
    ASSERT(!ozayn_xr_is_recon_terminal(OZAYN_XR_RECON_PENDING));
    ASSERT(!ozayn_xr_is_recon_terminal(OZAYN_XR_RECON_IN_PROGRESS));
    return 0;
}

/* ============================================================
 * RESULT RECORDING TESTS
 * ============================================================ */

TEST(test_xr_record_null) {
    ASSERT_EQ(ozayn_xr_result_record(NULL, "r1", "er1", "op1", 0, 0, 0, 0, 0, 0,
        OZAYN_XR_EXEC_STARTED, OZAYN_XR_RESULT_SUCCESS, 0, 0, 0, 0, 0, 0, 0, 0),
        OZAYN_XR_ERR_NULL_PTR);
    return 0;
}

TEST(test_xr_record_not_init) {
    ozayn_xr_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ASSERT_EQ(ozayn_xr_result_record(&svc, "r1", "er1", "op1", 0, 0, 0, 0, 0, 0,
        OZAYN_XR_EXEC_STARTED, OZAYN_XR_RESULT_SUCCESS, 0, 0, 0, 0, 0, 0, 0, 0),
        OZAYN_XR_ERR_NOT_INITIALIZED);
    return 0;
}

TEST(test_xr_record_null_ids) {
    ozayn_xr_service_t svc = _make_svc();
    ASSERT_EQ(ozayn_xr_result_record(&svc, NULL, "er1", "op1", 0, 0, 0, 0, 0, 0,
        OZAYN_XR_EXEC_STARTED, OZAYN_XR_RESULT_SUCCESS, 0, 0, 0, 0, 0, 0, 0, 0),
        OZAYN_XR_ERR_NULL_PTR);
    ASSERT_EQ(ozayn_xr_result_record(&svc, "r1", "er1", NULL, 0, 0, 0, 0, 0, 0,
        OZAYN_XR_EXEC_STARTED, OZAYN_XR_RESULT_SUCCESS, 0, 0, 0, 0, 0, 0, 0, 0),
        OZAYN_XR_ERR_NULL_PTR);
    return 0;
}

TEST(test_xr_record_terminal_state_rejected) {
    ozayn_xr_service_t svc = _make_svc();
    ASSERT_EQ(ozayn_xr_result_record(&svc, "r1", "er1", "op1", 0, 0, 0, 0, 0, 0,
        OZAYN_XR_EXEC_SUCCEEDED, OZAYN_XR_RESULT_SUCCESS, 0, 0, 0, 0, 0, 0, 0, 0),
        OZAYN_XR_ERR_INVALID_STATE);
    ASSERT_EQ(ozayn_xr_result_record(&svc, "r1", "er1", "op1", 0, 0, 0, 0, 0, 0,
        OZAYN_XR_EXEC_FAILED, OZAYN_XR_RESULT_FAILED, 0, 0, 0, 0, 0, 0, 0, 0),
        OZAYN_XR_ERR_INVALID_STATE);
    return 0;
}

TEST(test_xr_record_ok) {
    ozayn_xr_service_t svc = _make_svc();
    ozayn_xr_result_record_t *out = 0;
    int rc = ozayn_xr_result_record(&svc, "result-001", "exec-rec-001", "op-001", "req-001",
        "target-001", "cap-001", "START", "user1", "session-001",
        OZAYN_XR_EXEC_STARTED, OZAYN_XR_RESULT_SUCCESS, 0, 0,
        1000, 2000, 1000, 10, 20, &out);
    ASSERT_EQ(rc, OZAYN_XR_ERR_OK);
    ASSERT_NOT_NULL(out);
    ASSERT(out->record_id > 0);
    ASSERT_STR_EQ(out->result_id, "result-001");
    ASSERT_STR_EQ(out->execution_record_id, "exec-rec-001");
    ASSERT_STR_EQ(out->operation_id, "op-001");
    ASSERT_STR_EQ(out->request_id, "req-001");
    ASSERT_STR_EQ(out->target_component_id, "target-001");
    ASSERT_STR_EQ(out->capability_id, "cap-001");
    ASSERT_STR_EQ(out->action, "START");
    ASSERT_STR_EQ(out->requester_identity, "user1");
    ASSERT_STR_EQ(out->session_id, "session-001");
    ASSERT_EQ(out->result.exec_state, OZAYN_XR_EXEC_STARTED);
    ASSERT_EQ(out->result.outcome, OZAYN_XR_RESULT_SUCCESS);
    ASSERT_EQ(out->result.duration_ms, 1000);
    ASSERT_EQ(out->admission_ref, 10);
    ASSERT_EQ(out->enforcement_ref, 20);
    ASSERT_EQ(out->reconciliation.recon_state, OZAYN_XR_RECON_PENDING);
    ASSERT(!out->finalized);
    ASSERT(svc.result_count == 1);
    return 0;
}

TEST(test_xr_record_generates_ids) {
    ozayn_xr_service_t svc = _make_svc();
    ozayn_xr_result_record_t *r1 = 0;
    ozayn_xr_result_record_t *r2 = 0;
    ASSERT_EQ(ozayn_xr_result_record(&svc, "r1", "er1", "op1", 0, 0, 0, 0, 0, 0,
        OZAYN_XR_EXEC_STARTED, OZAYN_XR_RESULT_SUCCESS, 0, 0, 0, 0, 0, 0, 0, &r1), OZAYN_XR_ERR_OK);
    ASSERT_EQ(ozayn_xr_result_record(&svc, "r2", "er2", "op2", 0, 0, 0, 0, 0, 0,
        OZAYN_XR_EXEC_STARTED, OZAYN_XR_RESULT_SUCCESS, 0, 0, 0, 0, 0, 0, 0, &r2), OZAYN_XR_ERR_OK);
    ASSERT(r1->record_id != r2->record_id);
    return 0;
}

TEST(test_xr_record_events_emitted) {
    ozayn_xr_service_t svc = _make_svc();
    ASSERT_EQ(ozayn_xr_result_record(&svc, "r1", "er1", "op1", 0, 0, 0, 0, 0, 0,
        OZAYN_XR_EXEC_STARTED, OZAYN_XR_RESULT_SUCCESS, 0, 0, 0, 0, 0, 0, 0, 0), OZAYN_XR_ERR_OK);
    ASSERT(svc.event_count >= 2);
    return 0;
}

TEST(test_xr_record_duplicate_rejected) {
    ozayn_xr_service_t svc = _make_svc();
    ASSERT_EQ(ozayn_xr_result_record(&svc, "r1", "er1", "op1", 0, 0, 0, 0, 0, 0,
        OZAYN_XR_EXEC_STARTED, OZAYN_XR_RESULT_SUCCESS, 0, 0, 0, 0, 0, 0, 0, 0), OZAYN_XR_ERR_OK);
    ASSERT_EQ(ozayn_xr_result_finalize(&svc, svc.results[0].record_id), OZAYN_XR_ERR_OK);
    ASSERT_EQ(ozayn_xr_result_record(&svc, "r1", "er1", "op1", 0, 0, 0, 0, 0, 0,
        OZAYN_XR_EXEC_STARTED, OZAYN_XR_RESULT_SUCCESS, 0, 0, 0, 0, 0, 0, 0, 0), OZAYN_XR_ERR_DUPLICATE);
    return 0;
}

/* ============================================================
 * UPDATE TESTS
 * ============================================================ */

TEST(test_xr_update_null) {
    ASSERT_EQ(ozayn_xr_result_update(NULL, 1, OZAYN_XR_EXEC_SUCCEEDED, OZAYN_XR_RESULT_SUCCESS, 0, 0, 0, 0), OZAYN_XR_ERR_NULL_PTR);
    return 0;
}

TEST(test_xr_update_not_init) {
    ozayn_xr_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ASSERT_EQ(ozayn_xr_result_update(&svc, 1, OZAYN_XR_EXEC_SUCCEEDED, OZAYN_XR_RESULT_SUCCESS, 0, 0, 0, 0), OZAYN_XR_ERR_NOT_INITIALIZED);
    return 0;
}

TEST(test_xr_update_not_found) {
    ozayn_xr_service_t svc = _make_svc();
    ASSERT_EQ(ozayn_xr_result_update(&svc, 999, OZAYN_XR_EXEC_SUCCEEDED, OZAYN_XR_RESULT_SUCCESS, 0, 0, 0, 0), OZAYN_XR_ERR_NOT_FOUND);
    return 0;
}

TEST(test_xr_update_already_finalized) {
    ozayn_xr_service_t svc = _make_svc();
    ASSERT_EQ(ozayn_xr_result_record(&svc, "r1", "er1", "op1", 0, 0, 0, 0, 0, 0,
        OZAYN_XR_EXEC_STARTED, OZAYN_XR_RESULT_SUCCESS, 0, 0, 0, 0, 0, 0, 0, 0), OZAYN_XR_ERR_OK);
    ASSERT_EQ(ozayn_xr_result_finalize(&svc, svc.results[0].record_id), OZAYN_XR_ERR_OK);
    ASSERT_EQ(ozayn_xr_result_update(&svc, svc.results[0].record_id,
        OZAYN_XR_EXEC_SUCCEEDED, OZAYN_XR_RESULT_SUCCESS, 0, 0, 0, 0), OZAYN_XR_ERR_INVALID_STATE);
    return 0;
}

TEST(test_xr_update_terminal_rejected) {
    ozayn_xr_service_t svc = _make_svc();
    ASSERT_EQ(ozayn_xr_result_record(&svc, "r1", "er1", "op1", 0, 0, 0, 0, 0, 0,
        OZAYN_XR_EXEC_STARTED, OZAYN_XR_RESULT_SUCCESS, 0, 0, 0, 0, 0, 0, 0, 0), OZAYN_XR_ERR_OK);
    ASSERT_EQ(ozayn_xr_result_update(&svc, svc.results[0].record_id,
        OZAYN_XR_EXEC_STARTED, OZAYN_XR_RESULT_SUCCESS, 0, 0, 0, 0), OZAYN_XR_ERR_INVALID_STATE);
    return 0;
}

TEST(test_xr_update_ok) {
    ozayn_xr_service_t svc = _make_svc();
    ASSERT_EQ(ozayn_xr_result_record(&svc, "r1", "er1", "op1", 0, 0, 0, 0, 0, 0,
        OZAYN_XR_EXEC_STARTED, OZAYN_XR_RESULT_SUCCESS, 0, 0, 0, 0, 0, 0, 0, 0), OZAYN_XR_ERR_OK);
    ASSERT_EQ(ozayn_xr_result_update(&svc, svc.results[0].record_id,
        OZAYN_XR_EXEC_SUCCEEDED, OZAYN_XR_RESULT_SUCCESS, 0, 0, 2000, 1000), OZAYN_XR_ERR_OK);
    ASSERT_EQ(svc.results[0].result.exec_state, OZAYN_XR_EXEC_SUCCEEDED);
    ASSERT_EQ(svc.results[0].result.outcome, OZAYN_XR_RESULT_SUCCESS);
    ASSERT_EQ(svc.results[0].result.completed_time, 2000);
    ASSERT_EQ(svc.results[0].result.duration_ms, 1000);
    return 0;
}

TEST(test_xr_update_applies_changes) {
    ozayn_xr_service_t svc = _make_svc();
    ASSERT_EQ(ozayn_xr_result_record(&svc, "r1", "er1", "op1", 0, 0, 0, 0, 0, 0,
        OZAYN_XR_EXEC_STARTED, OZAYN_XR_RESULT_SUCCESS, 0, 0, 0, 0, 0, 0, 0, 0), OZAYN_XR_ERR_OK);
    ASSERT_EQ(ozayn_xr_result_update(&svc, svc.results[0].record_id,
        OZAYN_XR_EXEC_FAILED, OZAYN_XR_RESULT_FAILED, 500, "error msg", 3000, 2000), OZAYN_XR_ERR_OK);
    ASSERT_STR_EQ(svc.results[0].result.error_detail, "error msg");
    ASSERT_EQ(svc.results[0].result.result_code, 500);
    return 0;
}

/* ============================================================
 * DUPLICATE RESULT CHECK
 * ============================================================ */

TEST(test_xr_dup_check_null) {
    ASSERT_EQ(ozayn_xr_result_record_duplicate_check(NULL, "r1", "op1", "er1"), OZAYN_XR_ERR_NULL_PTR);
    return 0;
}

TEST(test_xr_dup_check_not_init) {
    ozayn_xr_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ASSERT_EQ(ozayn_xr_result_record_duplicate_check(&svc, "r1", "op1", "er1"), OZAYN_XR_ERR_NOT_INITIALIZED);
    return 0;
}

TEST(test_xr_dup_check_not_found) {
    ozayn_xr_service_t svc = _make_svc();
    ASSERT_EQ(ozayn_xr_result_record_duplicate_check(&svc, "r1", "op1", "er1"), 0);
    return 0;
}

TEST(test_xr_dup_check_found) {
    ozayn_xr_service_t svc = _make_svc();
    ASSERT_EQ(ozayn_xr_result_record(&svc, "r1", "er1", "op1", 0, 0, 0, 0, 0, 0,
        OZAYN_XR_EXEC_STARTED, OZAYN_XR_RESULT_SUCCESS, 0, 0, 0, 0, 0, 0, 0, 0), OZAYN_XR_ERR_OK);
    ASSERT_EQ(ozayn_xr_result_finalize(&svc, svc.results[0].record_id), OZAYN_XR_ERR_OK);
    ASSERT(ozayn_xr_result_record_duplicate_check(&svc, "r1", "op1", "er1") == 1);
    return 0;
}

/* ============================================================
 * RESULT FINALIZATION TESTS
 * ============================================================ */

TEST(test_xr_finalize_null) {
    ASSERT_EQ(ozayn_xr_result_finalize(NULL, 0), OZAYN_XR_ERR_NULL_PTR);
    return 0;
}

TEST(test_xr_finalize_not_init) {
    ozayn_xr_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ASSERT_EQ(ozayn_xr_result_finalize(&svc, 1), OZAYN_XR_ERR_NOT_INITIALIZED);
    return 0;
}

TEST(test_xr_finalize_not_found) {
    ozayn_xr_service_t svc = _make_svc();
    ASSERT_EQ(ozayn_xr_result_finalize(&svc, 999), OZAYN_XR_ERR_NOT_FOUND);
    return 0;
}

TEST(test_xr_finalize_ok) {
    ozayn_xr_service_t svc = _make_svc();
    ASSERT_EQ(ozayn_xr_result_record(&svc, "r1", "er1", "op1", 0, 0, 0, 0, 0, 0,
        OZAYN_XR_EXEC_STARTED, OZAYN_XR_RESULT_SUCCESS, 0, 0, 0, 0, 0, 0, 0, 0), OZAYN_XR_ERR_OK);
    uint64_t rec_id = svc.results[0].record_id;
    ASSERT_EQ(ozayn_xr_result_finalize(&svc, rec_id), OZAYN_XR_ERR_OK);
    ASSERT(svc.results[0].finalized);
    ASSERT_EQ(svc.stats.current_pending, 0);
    ASSERT_EQ(svc.stats.current_finalized, 1);
    return 0;
}

TEST(test_xr_finalize_already_finalized) {
    ozayn_xr_service_t svc = _make_svc();
    ASSERT_EQ(ozayn_xr_result_record(&svc, "r1", "er1", "op1", 0, 0, 0, 0, 0, 0,
        OZAYN_XR_EXEC_STARTED, OZAYN_XR_RESULT_SUCCESS, 0, 0, 0, 0, 0, 0, 0, 0), OZAYN_XR_ERR_OK);
    uint64_t rec_id = svc.results[0].record_id;
    ASSERT_EQ(ozayn_xr_result_finalize(&svc, rec_id), OZAYN_XR_ERR_OK);
    ASSERT_EQ(ozayn_xr_result_finalize(&svc, rec_id), OZAYN_XR_ERR_INVALID_STATE);
    return 0;
}

TEST(test_xr_finalize_stats_success) {
    ozayn_xr_service_t svc = _make_svc();
    ASSERT_EQ(ozayn_xr_result_record(&svc, "r1", "er1", "op1", 0, 0, 0, 0, 0, 0,
        OZAYN_XR_EXEC_STARTED, OZAYN_XR_RESULT_SUCCESS, 0, 0, 0, 0, 0, 0, 0, 0), OZAYN_XR_ERR_OK);
    ASSERT_EQ(ozayn_xr_result_update(&svc, svc.results[0].record_id,
        OZAYN_XR_EXEC_SUCCEEDED, OZAYN_XR_RESULT_SUCCESS, 0, 0, 2000, 1000), OZAYN_XR_ERR_OK);
    ASSERT_EQ(ozayn_xr_result_finalize(&svc, svc.results[0].record_id), OZAYN_XR_ERR_OK);
    ASSERT_EQ(svc.stats.total_succeeded, 1);
    return 0;
}

TEST(test_xr_finalize_stats_failed) {
    ozayn_xr_service_t svc = _make_svc();
    ASSERT_EQ(ozayn_xr_result_record(&svc, "r1", "er1", "op1", 0, 0, 0, 0, 0, 0,
        OZAYN_XR_EXEC_STARTED, OZAYN_XR_RESULT_FAILED, 0, 0, 0, 0, 0, 0, 0, 0), OZAYN_XR_ERR_OK);
    ASSERT_EQ(ozayn_xr_result_update(&svc, svc.results[0].record_id,
        OZAYN_XR_EXEC_FAILED, OZAYN_XR_RESULT_FAILED, 500, "error", 2000, 1000), OZAYN_XR_ERR_OK);
    ASSERT_EQ(ozayn_xr_result_finalize(&svc, svc.results[0].record_id), OZAYN_XR_ERR_OK);
    ASSERT_EQ(svc.stats.total_failed, 1);
    return 0;
}

TEST(test_xr_finalize_stats_partial) {
    ozayn_xr_service_t svc = _make_svc();
    ASSERT_EQ(ozayn_xr_result_record(&svc, "r1", "er1", "op1", 0, 0, 0, 0, 0, 0,
        OZAYN_XR_EXEC_STARTED, OZAYN_XR_RESULT_PARTIAL, 0, 0, 0, 0, 0, 0, 0, 0), OZAYN_XR_ERR_OK);
    ASSERT_EQ(ozayn_xr_result_update(&svc, svc.results[0].record_id,
        OZAYN_XR_EXEC_PARTIAL, OZAYN_XR_RESULT_PARTIAL, 0, 0, 2000, 1000), OZAYN_XR_ERR_OK);
    ASSERT_EQ(ozayn_xr_result_finalize(&svc, svc.results[0].record_id), OZAYN_XR_ERR_OK);
    ASSERT_EQ(svc.stats.total_partial, 1);
    return 0;
}

TEST(test_xr_finalize_stats_cancelled) {
    ozayn_xr_service_t svc = _make_svc();
    ASSERT_EQ(ozayn_xr_result_record(&svc, "r1", "er1", "op1", 0, 0, 0, 0, 0, 0,
        OZAYN_XR_EXEC_STARTED, OZAYN_XR_RESULT_CANCELLED, 0, 0, 0, 0, 0, 0, 0, 0), OZAYN_XR_ERR_OK);
    ASSERT_EQ(ozayn_xr_result_update(&svc, svc.results[0].record_id,
        OZAYN_XR_EXEC_CANCELLED, OZAYN_XR_RESULT_CANCELLED, 0, 0, 2000, 1000), OZAYN_XR_ERR_OK);
    ASSERT_EQ(ozayn_xr_result_finalize(&svc, svc.results[0].record_id), OZAYN_XR_ERR_OK);
    ASSERT_EQ(svc.stats.total_cancelled, 1);
    return 0;
}

TEST(test_xr_finalize_stats_timeout) {
    ozayn_xr_service_t svc = _make_svc();
    ASSERT_EQ(ozayn_xr_result_record(&svc, "r1", "er1", "op1", 0, 0, 0, 0, 0, 0,
        OZAYN_XR_EXEC_STARTED, OZAYN_XR_RESULT_TIMEOUT, 0, 0, 0, 0, 0, 0, 0, 0), OZAYN_XR_ERR_OK);
    ASSERT_EQ(ozayn_xr_result_update(&svc, svc.results[0].record_id,
        OZAYN_XR_EXEC_TIMEOUT, OZAYN_XR_RESULT_TIMEOUT, 0, 0, 2000, 1000), OZAYN_XR_ERR_OK);
    ASSERT_EQ(ozayn_xr_result_finalize(&svc, svc.results[0].record_id), OZAYN_XR_ERR_OK);
    ASSERT_EQ(svc.stats.total_timeout, 1);
    return 0;
}

TEST(test_xr_finalize_stats_interrupted) {
    ozayn_xr_service_t svc = _make_svc();
    ASSERT_EQ(ozayn_xr_result_record(&svc, "r1", "er1", "op1", 0, 0, 0, 0, 0, 0,
        OZAYN_XR_EXEC_STARTED, OZAYN_XR_RESULT_INTERRUPTED, 0, 0, 0, 0, 0, 0, 0, 0), OZAYN_XR_ERR_OK);
    ASSERT_EQ(ozayn_xr_result_update(&svc, svc.results[0].record_id,
        OZAYN_XR_EXEC_INTERRUPTED, OZAYN_XR_RESULT_INTERRUPTED, 0, 0, 2000, 1000), OZAYN_XR_ERR_OK);
    ASSERT_EQ(ozayn_xr_result_finalize(&svc, svc.results[0].record_id), OZAYN_XR_ERR_OK);
    ASSERT_EQ(svc.stats.total_interrupted, 1);
    return 0;
}

TEST(test_xr_finalize_stats_unknown) {
    ozayn_xr_service_t svc = _make_svc();
    ASSERT_EQ(ozayn_xr_result_record(&svc, "r1", "er1", "op1", 0, 0, 0, 0, 0, 0,
        OZAYN_XR_EXEC_STARTED, OZAYN_XR_RESULT_UNKNOWN, 0, 0, 0, 0, 0, 0, 0, 0), OZAYN_XR_ERR_OK);
    ASSERT_EQ(ozayn_xr_result_update(&svc, svc.results[0].record_id,
        OZAYN_XR_EXEC_UNKNOWN, OZAYN_XR_RESULT_UNKNOWN, 0, 0, 2000, 1000), OZAYN_XR_ERR_OK);
    ASSERT_EQ(ozayn_xr_result_finalize(&svc, svc.results[0].record_id), OZAYN_XR_ERR_OK);
    ASSERT_EQ(svc.stats.total_unknown, 1);
    return 0;
}

TEST(test_xr_finalize_events_emitted) {
    ozayn_xr_service_t svc = _make_svc();
    ASSERT_EQ(ozayn_xr_result_record(&svc, "r1", "er1", "op1", 0, 0, 0, 0, 0, 0,
        OZAYN_XR_EXEC_STARTED, OZAYN_XR_RESULT_SUCCESS, 0, 0, 0, 0, 0, 0, 0, 0), OZAYN_XR_ERR_OK);
    uint64_t events_before = svc.event_count;
    ASSERT_EQ(ozayn_xr_result_finalize(&svc, svc.results[0].record_id), OZAYN_XR_ERR_OK);
    ASSERT(svc.event_count > events_before);
    return 0;
}

/* ============================================================
 * RESULT QUERY TESTS
 * ============================================================ */

TEST(test_xr_get_null) {
    ASSERT_EQ(ozayn_xr_result_get(NULL, 1, 0), OZAYN_XR_ERR_NULL_PTR);
    return 0;
}

TEST(test_xr_get_not_found) {
    ozayn_xr_service_t svc = _make_svc();
    const ozayn_xr_result_record_t *rec = 0;
    ASSERT_EQ(ozayn_xr_result_get(&svc, 999, &rec), OZAYN_XR_ERR_NOT_FOUND);
    return 0;
}

TEST(test_xr_get_ok) {
    ozayn_xr_service_t svc = _make_svc();
    ASSERT_EQ(ozayn_xr_result_record(&svc, "r1", "er1", "op1", 0, 0, 0, 0, 0, 0,
        OZAYN_XR_EXEC_STARTED, OZAYN_XR_RESULT_SUCCESS, 0, 0, 0, 0, 0, 0, 0, 0), OZAYN_XR_ERR_OK);
    uint64_t rec_id = svc.results[0].record_id;
    const ozayn_xr_result_record_t *rec = 0;
    ASSERT_EQ(ozayn_xr_result_get(&svc, rec_id, &rec), OZAYN_XR_ERR_OK);
    ASSERT_NOT_NULL(rec);
    ASSERT(rec->record_id == rec_id);
    return 0;
}

TEST(test_xr_get_by_op_not_found) {
    ozayn_xr_service_t svc = _make_svc();
    const ozayn_xr_result_record_t *rec = 0;
    ASSERT_EQ(ozayn_xr_result_get_by_operation(&svc, "nonexistent", &rec), OZAYN_XR_ERR_NOT_FOUND);
    return 0;
}

TEST(test_xr_get_by_op_ok) {
    ozayn_xr_service_t svc = _make_svc();
    ASSERT_EQ(ozayn_xr_result_record(&svc, "r1", "er1", "op-target", 0, 0, 0, 0, 0, 0,
        OZAYN_XR_EXEC_STARTED, OZAYN_XR_RESULT_SUCCESS, 0, 0, 0, 0, 0, 0, 0, 0), OZAYN_XR_ERR_OK);
    const ozayn_xr_result_record_t *rec = 0;
    ASSERT_EQ(ozayn_xr_result_get_by_operation(&svc, "op-target", &rec), OZAYN_XR_ERR_OK);
    ASSERT_NOT_NULL(rec);
    ASSERT_STR_EQ(rec->operation_id, "op-target");
    return 0;
}

TEST(test_xr_get_pending) {
    ozayn_xr_service_t svc = _make_svc();
    ASSERT_EQ(ozayn_xr_result_record(&svc, "r1", "er1", "op1", 0, 0, 0, 0, 0, 0,
        OZAYN_XR_EXEC_STARTED, OZAYN_XR_RESULT_SUCCESS, 0, 0, 0, 0, 0, 0, 0, 0), OZAYN_XR_ERR_OK);
    ASSERT_EQ(ozayn_xr_result_record(&svc, "r2", "er2", "op2", 0, 0, 0, 0, 0, 0,
        OZAYN_XR_EXEC_STARTED, OZAYN_XR_RESULT_SUCCESS, 0, 0, 0, 0, 0, 0, 0, 0), OZAYN_XR_ERR_OK);
    const ozayn_xr_result_record_t *records[8];
    uint64_t cnt = 0;
    ASSERT_EQ(ozayn_xr_result_get_pending(&svc, records, 8, &cnt), OZAYN_XR_ERR_OK);
    ASSERT_EQ(cnt, 2);
    return 0;
}

TEST(test_xr_get_finalized) {
    ozayn_xr_service_t svc = _make_svc();
    ASSERT_EQ(ozayn_xr_result_record(&svc, "r1", "er1", "op1", 0, 0, 0, 0, 0, 0,
        OZAYN_XR_EXEC_STARTED, OZAYN_XR_RESULT_SUCCESS, 0, 0, 0, 0, 0, 0, 0, 0), OZAYN_XR_ERR_OK);
    ASSERT_EQ(ozayn_xr_result_finalize(&svc, svc.results[0].record_id), OZAYN_XR_ERR_OK);
    const ozayn_xr_result_record_t *records[8];
    uint64_t cnt = 0;
    ASSERT_EQ(ozayn_xr_result_get_finalized(&svc, records, 8, &cnt), OZAYN_XR_ERR_OK);
    ASSERT_EQ(cnt, 1);
    return 0;
}

/* ============================================================
 * RECONCILIATION TESTS
 * ============================================================ */

TEST(test_xr_reconcile_null) {
    ozayn_xr_recon_state_t rs;
    ASSERT_EQ(ozayn_xr_reconcile(NULL, 1, &rs), OZAYN_XR_ERR_NULL_PTR);
    return 0;
}

TEST(test_xr_reconcile_not_init) {
    ozayn_xr_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_xr_recon_state_t rs;
    ASSERT_EQ(ozayn_xr_reconcile(&svc, 1, &rs), OZAYN_XR_ERR_NOT_INITIALIZED);
    return 0;
}

TEST(test_xr_reconcile_not_found) {
    ozayn_xr_service_t svc = _make_svc();
    ozayn_xr_recon_state_t rs;
    ASSERT_EQ(ozayn_xr_reconcile(&svc, 999, &rs), OZAYN_XR_ERR_NOT_FOUND);
    return 0;
}

TEST(test_xr_reconcile_success_consistent) {
    ozayn_xr_service_t svc = _make_svc_bound();
    ASSERT_EQ(ozayn_xr_result_record(&svc, "r1", "er1", "op1", "req1",
        "target1", "cap1", "START", "user1", "sess1",
        OZAYN_XR_EXEC_STARTED, OZAYN_XR_RESULT_SUCCESS, 0, 0,
        1000, 2000, 1000, 0, 0, 0), OZAYN_XR_ERR_OK);
    ASSERT_EQ(ozayn_xr_result_update(&svc, svc.results[0].record_id,
        OZAYN_XR_EXEC_SUCCEEDED, OZAYN_XR_RESULT_SUCCESS, 0, 0, 2000, 1000), OZAYN_XR_ERR_OK);
    uint64_t rec_id = svc.results[0].record_id;
    ozayn_xr_recon_state_t rs;
    ASSERT_EQ(ozayn_xr_reconcile(&svc, rec_id, &rs), OZAYN_XR_ERR_OK);
    ASSERT_EQ(rs, OZAYN_XR_RECON_CONSISTENT);
    return 0;
}

TEST(test_xr_reconcile_full) {
    ozayn_xr_service_t svc = _make_svc_bound();
    ASSERT_EQ(ozayn_xr_result_record(&svc, "r1", "er1", "op1", "req1",
        "target1", "cap1", "START", "user1", "sess1",
        OZAYN_XR_EXEC_STARTED, OZAYN_XR_RESULT_SUCCESS, 0, 0,
        1000, 2000, 1000, 0, 0, 0), OZAYN_XR_ERR_OK);
    ASSERT_EQ(ozayn_xr_result_update(&svc, svc.results[0].record_id,
        OZAYN_XR_EXEC_SUCCEEDED, OZAYN_XR_RESULT_SUCCESS, 0, 0, 2000, 1000), OZAYN_XR_ERR_OK);
    uint64_t rec_id = svc.results[0].record_id;
    ozayn_xr_reconciliation_t recon;
    ASSERT_EQ(ozayn_xr_reconcile_full(&svc, rec_id, &recon), OZAYN_XR_ERR_OK);
    ASSERT_EQ(recon.recon_state, OZAYN_XR_RECON_CONSISTENT);
    ASSERT_EQ(recon.target_state, OZAYN_XR_TARGET_AVAILABLE);
    ASSERT_EQ(recon.resource_state, OZAYN_XR_RESOURCE_OK);
    ASSERT_EQ(recon.device_state, OZAYN_XR_DEVICE_OK);
    ASSERT_EQ(recon.workflow_state, OZAYN_XR_WORKFLOW_OK);
    ASSERT_EQ(recon.pipeline_state, OZAYN_XR_PIPELINE_OK);
    ASSERT_EQ(recon.scheduler_state, OZAYN_XR_SCHEDULER_RELEASED);
    return 0;
}

TEST(test_xr_reconcile_no_subsystems) {
    ozayn_xr_service_t svc = _make_svc();
    ASSERT_EQ(ozayn_xr_result_record(&svc, "r1", "er1", "op1", "req1",
        "target1", "cap1", "START", "user1", "sess1",
        OZAYN_XR_EXEC_STARTED, OZAYN_XR_RESULT_SUCCESS, 0, 0,
        1000, 2000, 1000, 0, 0, 0), OZAYN_XR_ERR_OK);
    uint64_t rec_id = svc.results[0].record_id;
    ozayn_xr_recon_state_t rs;
    ASSERT_EQ(ozayn_xr_reconcile(&svc, rec_id, &rs), OZAYN_XR_ERR_OK);
    ASSERT_EQ(rs, OZAYN_XR_RECON_UNKNOWN);
    return 0;
}

TEST(test_xr_reconcile_target_match) {
    ozayn_xr_service_t svc = _make_svc();
    ASSERT_EQ(ozayn_xr_result_record(&svc, "r1", "er1", "op1", 0, 0, 0, 0, 0, 0,
        OZAYN_XR_EXEC_STARTED, OZAYN_XR_RESULT_SUCCESS, 0, 0, 0, 0, 0, 0, 0, 0), OZAYN_XR_ERR_OK);
    uint64_t rec_id = svc.results[0].record_id;
    ozayn_xr_recon_state_t rs;
    ASSERT_EQ(ozayn_xr_reconcile_target(&svc, rec_id, "ACTIVE", "ACTIVE", &rs), OZAYN_XR_ERR_OK);
    ASSERT_EQ(rs, OZAYN_XR_RECON_CONSISTENT);
    return 0;
}

TEST(test_xr_reconcile_target_mismatch) {
    ozayn_xr_service_t svc = _make_svc();
    ASSERT_EQ(ozayn_xr_result_record(&svc, "r1", "er1", "op1", 0, 0, 0, 0, 0, 0,
        OZAYN_XR_EXEC_STARTED, OZAYN_XR_RESULT_SUCCESS, 0, 0, 0, 0, 0, 0, 0, 0), OZAYN_XR_ERR_OK);
    uint64_t rec_id = svc.results[0].record_id;
    ozayn_xr_recon_state_t rs;
    ASSERT_EQ(ozayn_xr_reconcile_target(&svc, rec_id, "ACTIVE", "ERROR", &rs), OZAYN_XR_ERR_OK);
    ASSERT_EQ(rs, OZAYN_XR_RECON_INCONSISTENT);
    return 0;
}

TEST(test_xr_reconcile_target_not_found) {
    ozayn_xr_service_t svc = _make_svc();
    ozayn_xr_recon_state_t rs;
    ASSERT_EQ(ozayn_xr_reconcile_target(&svc, 999, "A", "B", &rs), OZAYN_XR_ERR_NOT_FOUND);
    return 0;
}

/* ============================================================
 * EVENT TESTS
 * ============================================================ */

TEST(test_xr_event_emit_null) {
    ASSERT_EQ(ozayn_xr_event_emit(NULL, OZAYN_XR_EVENT_EXEC_STARTED, 0, 0, 0), OZAYN_XR_ERR_NULL_PTR);
    return 0;
}

TEST(test_xr_event_emit_not_init) {
    ozayn_xr_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ASSERT_EQ(ozayn_xr_event_emit(&svc, OZAYN_XR_EVENT_EXEC_STARTED, 0, 0, 0), OZAYN_XR_ERR_NOT_INITIALIZED);
    return 0;
}

TEST(test_xr_event_emit_ok) {
    ozayn_xr_service_t svc = _make_svc();
    ASSERT_EQ(ozayn_xr_event_emit(&svc, OZAYN_XR_EVENT_EXEC_COMPLETED, "op1", "r1", "t1"), OZAYN_XR_ERR_OK);
    ASSERT(svc.event_count >= 1);
    return 0;
}

TEST(test_xr_event_get_null) {
    ASSERT_EQ(ozayn_xr_event_get(NULL, 1, 0), OZAYN_XR_ERR_NULL_PTR);
    return 0;
}

TEST(test_xr_event_get_not_found) {
    ozayn_xr_service_t svc = _make_svc();
    const ozayn_xr_event_t *ev = 0;
    ASSERT_EQ(ozayn_xr_event_get(&svc, 999, &ev), OZAYN_XR_ERR_NOT_FOUND);
    return 0;
}

TEST(test_xr_event_get_ok) {
    ozayn_xr_service_t svc = _make_svc();
    ASSERT_EQ(ozayn_xr_event_emit(&svc, OZAYN_XR_EVENT_EXEC_STARTED, "op1", "r1", "t1"), OZAYN_XR_ERR_OK);
    uint64_t ev_id = svc.events[0].event_id;
    const ozayn_xr_event_t *ev = 0;
    ASSERT_EQ(ozayn_xr_event_get(&svc, ev_id, &ev), OZAYN_XR_ERR_OK);
    ASSERT_NOT_NULL(ev);
    ASSERT(ev->event_id == ev_id);
    ASSERT_EQ(ev->event_type, OZAYN_XR_EVENT_EXEC_STARTED);
    ASSERT_STR_EQ(ev->operation_id, "op1");
    ASSERT_STR_EQ(ev->result_id, "r1");
    ASSERT_STR_EQ(ev->target_component_id, "t1");
    return 0;
}

TEST(test_xr_event_get_by_op) {
    ozayn_xr_service_t svc = _make_svc();
    ASSERT_EQ(ozayn_xr_event_emit(&svc, OZAYN_XR_EVENT_EXEC_STARTED, "op-target", "r1", "t1"), OZAYN_XR_ERR_OK);
    ASSERT_EQ(ozayn_xr_event_emit(&svc, OZAYN_XR_EVENT_EXEC_COMPLETED, "op-other", "r2", "t2"), OZAYN_XR_ERR_OK);
    const ozayn_xr_event_t *evs[8];
    uint64_t cnt = 0;
    ASSERT_EQ(ozayn_xr_event_get_by_operation(&svc, "op-target", evs, 8, &cnt), OZAYN_XR_ERR_OK);
    ASSERT_EQ(cnt, 1);
    return 0;
}

/* ============================================================
 * SHUTDOWN DRAIN TESTS
 * ============================================================ */

TEST(test_xr_drain_null) {
    ASSERT_EQ(ozayn_xr_shutdown_drain(NULL, 0, 0, 0), OZAYN_XR_ERR_NULL_PTR);
    return 0;
}

TEST(test_xr_drain_not_init) {
    ozayn_xr_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_xr_result_record_t *records[8];
    uint64_t cnt = 0;
    ASSERT_EQ(ozayn_xr_shutdown_drain(&svc, records, 8, &cnt), OZAYN_XR_ERR_NOT_INITIALIZED);
    return 0;
}

TEST(test_xr_drain_all_finalized) {
    ozayn_xr_service_t svc = _make_svc();
    ASSERT_EQ(ozayn_xr_result_record(&svc, "r1", "er1", "op1", 0, 0, 0, 0, 0, 0,
        OZAYN_XR_EXEC_STARTED, OZAYN_XR_RESULT_SUCCESS, 0, 0, 0, 0, 0, 0, 0, 0), OZAYN_XR_ERR_OK);
    ASSERT_EQ(ozayn_xr_result_finalize(&svc, svc.results[0].record_id), OZAYN_XR_ERR_OK);
    ozayn_xr_result_record_t *unresolved[8];
    uint64_t cnt = 0;
    ASSERT_EQ(ozayn_xr_shutdown_drain(&svc, unresolved, 8, &cnt), OZAYN_XR_ERR_OK);
    ASSERT_EQ(cnt, 0);
    return 0;
}

TEST(test_xr_drain_has_unresolved) {
    ozayn_xr_service_t svc = _make_svc();
    ASSERT_EQ(ozayn_xr_result_record(&svc, "r1", "er1", "op1", 0, 0, 0, 0, 0, 0,
        OZAYN_XR_EXEC_STARTED, OZAYN_XR_RESULT_SUCCESS, 0, 0, 0, 0, 0, 0, 0, 0), OZAYN_XR_ERR_OK);
    ASSERT_EQ(ozayn_xr_result_record(&svc, "r2", "er2", "op2", 0, 0, 0, 0, 0, 0,
        OZAYN_XR_EXEC_STARTED, OZAYN_XR_RESULT_SUCCESS, 0, 0, 0, 0, 0, 0, 0, 0), OZAYN_XR_ERR_OK);
    ASSERT_EQ(ozayn_xr_result_finalize(&svc, svc.results[0].record_id), OZAYN_XR_ERR_OK);
    ozayn_xr_result_record_t *unresolved[8];
    uint64_t cnt = 0;
    ASSERT_EQ(ozayn_xr_shutdown_drain(&svc, unresolved, 8, &cnt), OZAYN_XR_ERR_OK);
    ASSERT_EQ(cnt, 1);
    return 0;
}

/* ============================================================
 * COUNTS TESTS
 * ============================================================ */

TEST(test_xr_pending_count) {
    ozayn_xr_service_t svc = _make_svc();
    ASSERT_EQ(ozayn_xr_pending_count(&svc), 0);
    ASSERT_EQ(ozayn_xr_pending_count(NULL), -1);
    ASSERT_EQ(ozayn_xr_result_record(&svc, "r1", "er1", "op1", 0, 0, 0, 0, 0, 0,
        OZAYN_XR_EXEC_STARTED, OZAYN_XR_RESULT_SUCCESS, 0, 0, 0, 0, 0, 0, 0, 0), OZAYN_XR_ERR_OK);
    ASSERT_EQ(ozayn_xr_pending_count(&svc), 1);
    return 0;
}

TEST(test_xr_finalized_count) {
    ozayn_xr_service_t svc = _make_svc();
    ASSERT_EQ(ozayn_xr_finalized_count(&svc), 0);
    ASSERT_EQ(ozayn_xr_finalized_count(NULL), -1);
    ASSERT_EQ(ozayn_xr_result_record(&svc, "r1", "er1", "op1", 0, 0, 0, 0, 0, 0,
        OZAYN_XR_EXEC_STARTED, OZAYN_XR_RESULT_SUCCESS, 0, 0, 0, 0, 0, 0, 0, 0), OZAYN_XR_ERR_OK);
    ASSERT_EQ(ozayn_xr_result_finalize(&svc, svc.results[0].record_id), OZAYN_XR_ERR_OK);
    ASSERT_EQ(ozayn_xr_finalized_count(&svc), 1);
    return 0;
}

/* ============================================================
 * STATS TESTS
 * ============================================================ */

TEST(test_xr_stats_null) {
    ASSERT_EQ(ozayn_xr_stats_get(NULL, 0), OZAYN_XR_ERR_NULL_PTR);
    return 0;
}

TEST(test_xr_stats_initial) {
    ozayn_xr_service_t svc = _make_svc();
    ozayn_xr_stats_t stats;
    ASSERT_EQ(ozayn_xr_stats_get(&svc, &stats), OZAYN_XR_ERR_OK);
    ASSERT_EQ(stats.total_results_received, 0);
    ASSERT_EQ(stats.total_succeeded, 0);
    ASSERT_EQ(stats.total_failed, 0);
    ASSERT_EQ(stats.total_reconciliations, 0);
    ASSERT_EQ(stats.current_pending, 0);
    ASSERT_EQ(stats.current_finalized, 0);
    return 0;
}

TEST(test_xr_stats_after_records) {
    ozayn_xr_service_t svc = _make_svc();
    ASSERT_EQ(ozayn_xr_result_record(&svc, "r1", "er1", "op1", 0, 0, 0, 0, 0, 0,
        OZAYN_XR_EXEC_STARTED, OZAYN_XR_RESULT_SUCCESS, 0, 0, 0, 0, 0, 0, 0, 0), OZAYN_XR_ERR_OK);
    ASSERT_EQ(ozayn_xr_result_record(&svc, "r2", "er2", "op2", 0, 0, 0, 0, 0, 0,
        OZAYN_XR_EXEC_STARTED, OZAYN_XR_RESULT_SUCCESS, 0, 0, 0, 0, 0, 0, 0, 0), OZAYN_XR_ERR_OK);
    ozayn_xr_stats_t stats;
    ASSERT_EQ(ozayn_xr_stats_get(&svc, &stats), OZAYN_XR_ERR_OK);
    ASSERT_EQ(stats.total_results_received, 2);
    ASSERT_EQ(stats.current_pending, 2);
    return 0;
}

/* ============================================================
 * CONCURRENCY / EDGE CASE TESTS
 * ============================================================ */

TEST(test_xr_multiple_records_finalized) {
    ozayn_xr_service_t svc = _make_svc();
    for (int i = 0; i < 5; i++) {
        char rid[32], eid[32], oid[32];
        snprintf(rid, sizeof(rid), "r%d", i);
        snprintf(eid, sizeof(eid), "er%d", i);
        snprintf(oid, sizeof(oid), "op%d", i);
        ASSERT_EQ(ozayn_xr_result_record(&svc, rid, eid, oid, 0, 0, 0, 0, 0, 0,
            OZAYN_XR_EXEC_STARTED, OZAYN_XR_RESULT_SUCCESS, 0, 0, 0, 0, 0, 0, 0, 0), OZAYN_XR_ERR_OK);
        ASSERT_EQ(ozayn_xr_result_update(&svc, svc.results[svc.result_count - 1].record_id,
            OZAYN_XR_EXEC_SUCCEEDED, OZAYN_XR_RESULT_SUCCESS, 0, 0, 0, 0), OZAYN_XR_ERR_OK);
        ASSERT_EQ(ozayn_xr_result_finalize(&svc, svc.results[svc.result_count - 1].record_id), OZAYN_XR_ERR_OK);
    }
    ASSERT_EQ(svc.stats.total_succeeded, 5);
    ASSERT_EQ(svc.stats.current_finalized, 5);
    ASSERT_EQ(svc.stats.current_pending, 0);
    return 0;
}

TEST(test_xr_recon_full_not_found) {
    ozayn_xr_service_t svc = _make_svc();
    ozayn_xr_reconciliation_t recon;
    ASSERT_EQ(ozayn_xr_reconcile_full(&svc, 999, &recon), OZAYN_XR_ERR_NOT_FOUND);
    return 0;
}

TEST(test_xr_recon_target_null) {
    ozayn_xr_service_t svc = _make_svc();
    ozayn_xr_recon_state_t rs;
    ASSERT_EQ(ozayn_xr_reconcile_target(&svc, 1, NULL, "A", &rs), OZAYN_XR_ERR_NULL_PTR);
    ASSERT_EQ(ozayn_xr_reconcile_target(&svc, 1, "A", NULL, &rs), OZAYN_XR_ERR_NULL_PTR);
    return 0;
}

TEST(test_xr_get_pending_empty) {
    ozayn_xr_service_t svc = _make_svc();
    const ozayn_xr_result_record_t *records[8];
    uint64_t cnt = 0;
    ASSERT_EQ(ozayn_xr_result_get_pending(&svc, records, 8, &cnt), OZAYN_XR_ERR_OK);
    ASSERT_EQ(cnt, 0);
    return 0;
}

TEST(test_xr_get_finalized_empty) {
    ozayn_xr_service_t svc = _make_svc();
    const ozayn_xr_result_record_t *records[8];
    uint64_t cnt = 0;
    ASSERT_EQ(ozayn_xr_result_get_finalized(&svc, records, 8, &cnt), OZAYN_XR_ERR_OK);
    ASSERT_EQ(cnt, 0);
    return 0;
}

TEST(test_xr_recon_get_not_found) {
    ozayn_xr_service_t svc = _make_svc();
    const ozayn_xr_result_record_t *rec = 0;
    ASSERT_EQ(ozayn_xr_recon_get(&svc, 999, &rec), OZAYN_XR_ERR_NOT_FOUND);
    return 0;
}

TEST(test_xr_recon_get_by_op_not_found) {
    ozayn_xr_service_t svc = _make_svc();
    const ozayn_xr_result_record_t *rec = 0;
    ASSERT_EQ(ozayn_xr_recon_get_by_operation(&svc, "nonexistent", &rec), OZAYN_XR_ERR_NOT_FOUND);
    return 0;
}

TEST(test_xr_event_get_by_op_empty) {
    ozayn_xr_service_t svc = _make_svc();
    const ozayn_xr_event_t *evs[8];
    uint64_t cnt = 0;
    ASSERT_EQ(ozayn_xr_event_get_by_operation(&svc, "op1", evs, 8, &cnt), OZAYN_XR_ERR_OK);
    ASSERT_EQ(cnt, 0);
    return 0;
}

TEST(test_xr_record_error_detail) {
    ozayn_xr_service_t svc = _make_svc();
    ASSERT_EQ(ozayn_xr_result_record(&svc, "r1", "er1", "op1", 0, 0, 0, 0, 0, 0,
        OZAYN_XR_EXEC_STARTED, OZAYN_XR_RESULT_FAILED, 404, "not found",
        1000, 2000, 1000, 0, 0, 0), OZAYN_XR_ERR_OK);
    ASSERT_STR_EQ(svc.results[0].result.error_detail, "not found");
    ASSERT_EQ(svc.results[0].result.result_code, 404);
    return 0;
}

TEST(test_xr_recon_full_null) {
    ASSERT_EQ(ozayn_xr_reconcile_full(NULL, 1, 0), OZAYN_XR_ERR_NULL_PTR);
    return 0;
}

TEST(test_xr_reconcile_null_out) {
    ozayn_xr_service_t svc = _make_svc();
    ASSERT_EQ(ozayn_xr_result_record(&svc, "r1", "er1", "op1", 0, 0, 0, 0, 0, 0,
        OZAYN_XR_EXEC_STARTED, OZAYN_XR_RESULT_SUCCESS, 0, 0, 0, 0, 0, 0, 0, 0), OZAYN_XR_ERR_OK);
    ASSERT_EQ(ozayn_xr_reconcile(&svc, svc.results[0].record_id, 0), OZAYN_XR_ERR_OK);
    return 0;
}

TEST(test_xr_event_sequence) {
    ozayn_xr_service_t svc = _make_svc();
    ASSERT_EQ(ozayn_xr_event_emit(&svc, OZAYN_XR_EVENT_EXEC_STARTED, "op1", 0, 0), OZAYN_XR_ERR_OK);
    uint64_t e1 = svc.events[0].event_id;
    ASSERT_EQ(ozayn_xr_event_emit(&svc, OZAYN_XR_EVENT_EXEC_COMPLETED, "op1", 0, 0), OZAYN_XR_ERR_OK);
    uint64_t e2 = svc.events[1].event_id;
    ASSERT(e2 > e1);
    return 0;
}

/* ============================================================
 * RECONCILIATION SCENARIOS
 * ============================================================ */

TEST(test_xr_reconcile_success_target_unavailable) {
    ozayn_xr_service_t svc = _make_svc();
    ASSERT_EQ(ozayn_xr_result_record(&svc, "r1", "er1", "op1", "req1",
        "target1", "cap1", "START", "user1", "sess1",
        OZAYN_XR_EXEC_STARTED, OZAYN_XR_RESULT_SUCCESS, 0, 0,
        1000, 2000, 1000, 0, 0, 0), OZAYN_XR_ERR_OK);
    svc.bind.component_registry = 0;
    uint64_t rec_id = svc.results[0].record_id;
    ozayn_xr_recon_state_t rs;
    ASSERT_EQ(ozayn_xr_reconcile(&svc, rec_id, &rs), OZAYN_XR_ERR_OK);
    ASSERT_EQ(rs, OZAYN_XR_RECON_UNKNOWN);
    return 0;
}

TEST(test_xr_reconcile_failed_target_unavailable) {
    ozayn_xr_service_t svc = _make_svc();
    ASSERT_EQ(ozayn_xr_result_record(&svc, "r1", "er1", "op1", 0,
        "target1", 0, 0, 0, 0,
        OZAYN_XR_EXEC_STARTED, OZAYN_XR_RESULT_FAILED, 0, 0,
        0, 0, 0, 0, 0, 0), OZAYN_XR_ERR_OK);
    svc.bind.component_registry = 0;
    uint64_t rec_id = svc.results[0].record_id;
    ozayn_xr_recon_state_t rs;
    ASSERT_EQ(ozayn_xr_reconcile(&svc, rec_id, &rs), OZAYN_XR_ERR_OK);
    ASSERT_EQ(rs, OZAYN_XR_RECON_UNKNOWN);
    return 0;
}

TEST(test_xr_reconcile_timeout_with_success) {
    ozayn_xr_service_t svc = _make_svc_bound();
    ASSERT_EQ(ozayn_xr_result_record(&svc, "r1", "er1", "op1", 0,
        "target1", 0, 0, 0, 0,
        OZAYN_XR_EXEC_STARTED, OZAYN_XR_RESULT_TIMEOUT, 0, 0,
        0, 0, 0, 0, 0, 0), OZAYN_XR_ERR_OK);
    ASSERT_EQ(ozayn_xr_result_update(&svc, svc.results[0].record_id,
        OZAYN_XR_EXEC_TIMEOUT, OZAYN_XR_RESULT_TIMEOUT, 0, 0, 0, 0), OZAYN_XR_ERR_OK);
    uint64_t rec_id = svc.results[0].record_id;
    ozayn_xr_recon_state_t rs;
    ASSERT_EQ(ozayn_xr_reconcile(&svc, rec_id, &rs), OZAYN_XR_ERR_OK);
    ASSERT_EQ(rs, OZAYN_XR_RECON_STATE_CHANGED_UNEXPECTEDLY);
    return 0;
}

TEST(test_xr_reconcile_cancelled) {
    ozayn_xr_service_t svc = _make_svc();
    ASSERT_EQ(ozayn_xr_result_record(&svc, "r1", "er1", "op1", 0,
        "target1", 0, 0, 0, 0,
        OZAYN_XR_EXEC_STARTED, OZAYN_XR_RESULT_CANCELLED, 0, 0,
        0, 0, 0, 0, 0, 0), OZAYN_XR_ERR_OK);
    ASSERT_EQ(ozayn_xr_result_update(&svc, svc.results[0].record_id,
        OZAYN_XR_EXEC_CANCELLED, OZAYN_XR_RESULT_CANCELLED, 0, 0, 0, 0), OZAYN_XR_ERR_OK);
    uint64_t rec_id = svc.results[0].record_id;
    ozayn_xr_recon_state_t rs;
    ASSERT_EQ(ozayn_xr_reconcile(&svc, rec_id, &rs), OZAYN_XR_ERR_OK);
    ASSERT_EQ(rs, OZAYN_XR_RECON_UNKNOWN);
    return 0;
}

TEST(test_xr_reconcile_unknown_exec) {
    ozayn_xr_service_t svc = _make_svc_bound();
    ASSERT_EQ(ozayn_xr_result_record(&svc, "r1", "er1", "op1", 0,
        "target1", 0, 0, 0, 0,
        OZAYN_XR_EXEC_STARTED, OZAYN_XR_RESULT_UNKNOWN, 0, 0,
        0, 0, 0, 0, 0, 0), OZAYN_XR_ERR_OK);
    ASSERT_EQ(ozayn_xr_result_update(&svc, svc.results[0].record_id,
        OZAYN_XR_EXEC_UNKNOWN, OZAYN_XR_RESULT_UNKNOWN, 0, 0, 0, 0), OZAYN_XR_ERR_OK);
    uint64_t rec_id = svc.results[0].record_id;
    ozayn_xr_recon_state_t rs;
    ASSERT_EQ(ozayn_xr_reconcile(&svc, rec_id, &rs), OZAYN_XR_ERR_OK);
    ASSERT_EQ(rs, OZAYN_XR_RECON_UNKNOWN);
    const ozayn_xr_result_record_t *rec = 0;
    ASSERT_EQ(ozayn_xr_result_get(&svc, rec_id, &rec), OZAYN_XR_ERR_OK);
    ASSERT(rec->reconciliation.requires_diagnostics);
    return 0;
}

TEST(test_xr_reconcile_interrupted) {
    ozayn_xr_service_t svc = _make_svc_bound();
    ASSERT_EQ(ozayn_xr_result_record(&svc, "r1", "er1", "op1", 0,
        "target1", 0, 0, 0, 0,
        OZAYN_XR_EXEC_STARTED, OZAYN_XR_RESULT_INTERRUPTED, 0, 0,
        0, 0, 0, 0, 0, 0), OZAYN_XR_ERR_OK);
    ASSERT_EQ(ozayn_xr_result_update(&svc, svc.results[0].record_id,
        OZAYN_XR_EXEC_INTERRUPTED, OZAYN_XR_RESULT_INTERRUPTED, 0, 0, 0, 0), OZAYN_XR_ERR_OK);
    uint64_t rec_id = svc.results[0].record_id;
    ozayn_xr_recon_state_t rs;
    ASSERT_EQ(ozayn_xr_reconcile(&svc, rec_id, &rs), OZAYN_XR_ERR_OK);
    ASSERT_EQ(rs, OZAYN_XR_RECON_UNKNOWN);
    return 0;
}

/* ============================================================
 * TEST RUNNER
 * ============================================================ */

int run_cr_execution_result_tests(void) {
    int fail = 0;
    printf("\n  --- CR EXECUTION RESULT ---");
    SUITE_BEGIN("Execution Result");

    /* Lifecycle */
    RUN(test_xr_init_null);
    RUN(test_xr_init_ok);
    RUN(test_xr_double_init);
    RUN(test_xr_shutdown_null);
    RUN(test_xr_shutdown_not_init);
    RUN(test_xr_shutdown_ok);
    RUN(test_xr_is_initialized);

    /* Subsystems */
    RUN(test_xr_bind_null);
    RUN(test_xr_bind_not_init);
    RUN(test_xr_bind_ok);

    /* Name helpers */
    RUN(test_xr_exec_state_name_all);
    RUN(test_xr_result_outcome_name_all);
    RUN(test_xr_recon_state_name_all);
    RUN(test_xr_event_type_name_all);
    RUN(test_xr_target_state_name_all);
    RUN(test_xr_resource_state_name_all);
    RUN(test_xr_device_state_name_all);
    RUN(test_xr_workflow_state_name_all);
    RUN(test_xr_pipeline_state_name_all);
    RUN(test_xr_scheduler_state_name_all);
    RUN(test_xr_diagnostic_state_name_all);
    RUN(test_xr_is_exec_terminal);
    RUN(test_xr_is_recon_terminal);

    /* Result recording */
    RUN(test_xr_record_null);
    RUN(test_xr_record_not_init);
    RUN(test_xr_record_null_ids);
    RUN(test_xr_record_terminal_state_rejected);
    RUN(test_xr_record_ok);
    RUN(test_xr_record_generates_ids);
    RUN(test_xr_record_events_emitted);
    RUN(test_xr_record_duplicate_rejected);

    /* Update */
    RUN(test_xr_update_null);
    RUN(test_xr_update_not_init);
    RUN(test_xr_update_not_found);
    RUN(test_xr_update_already_finalized);
    RUN(test_xr_update_terminal_rejected);
    RUN(test_xr_update_ok);
    RUN(test_xr_update_applies_changes);

    /* Duplicate check */
    RUN(test_xr_dup_check_null);
    RUN(test_xr_dup_check_not_init);
    RUN(test_xr_dup_check_not_found);
    RUN(test_xr_dup_check_found);

    /* Finalization */
    RUN(test_xr_finalize_null);
    RUN(test_xr_finalize_not_init);
    RUN(test_xr_finalize_not_found);
    RUN(test_xr_finalize_ok);
    RUN(test_xr_finalize_already_finalized);
    RUN(test_xr_finalize_stats_success);
    RUN(test_xr_finalize_stats_failed);
    RUN(test_xr_finalize_stats_partial);
    RUN(test_xr_finalize_stats_cancelled);
    RUN(test_xr_finalize_stats_timeout);
    RUN(test_xr_finalize_stats_interrupted);
    RUN(test_xr_finalize_stats_unknown);
    RUN(test_xr_finalize_events_emitted);

    /* Queries */
    RUN(test_xr_get_null);
    RUN(test_xr_get_not_found);
    RUN(test_xr_get_ok);
    RUN(test_xr_get_by_op_not_found);
    RUN(test_xr_get_by_op_ok);
    RUN(test_xr_get_pending);
    RUN(test_xr_get_finalized);
    RUN(test_xr_get_pending_empty);
    RUN(test_xr_get_finalized_empty);

    /* Reconciliation */
    RUN(test_xr_reconcile_null);
    RUN(test_xr_reconcile_not_init);
    RUN(test_xr_reconcile_not_found);
    RUN(test_xr_reconcile_success_consistent);
    RUN(test_xr_reconcile_full);
    RUN(test_xr_reconcile_no_subsystems);
    RUN(test_xr_reconcile_target_match);
    RUN(test_xr_reconcile_target_mismatch);
    RUN(test_xr_reconcile_target_not_found);
    RUN(test_xr_recon_target_null);
    RUN(test_xr_recon_full_not_found);
    RUN(test_xr_recon_full_null);
    RUN(test_xr_reconcile_null_out);

    /* Reconciliation scenarios */
    RUN(test_xr_reconcile_success_target_unavailable);
    RUN(test_xr_reconcile_failed_target_unavailable);
    RUN(test_xr_reconcile_timeout_with_success);
    RUN(test_xr_reconcile_cancelled);
    RUN(test_xr_reconcile_unknown_exec);
    RUN(test_xr_reconcile_interrupted);

    /* Events */
    RUN(test_xr_event_emit_null);
    RUN(test_xr_event_emit_not_init);
    RUN(test_xr_event_emit_ok);
    RUN(test_xr_event_get_null);
    RUN(test_xr_event_get_not_found);
    RUN(test_xr_event_get_ok);
    RUN(test_xr_event_get_by_op);
    RUN(test_xr_event_get_by_op_empty);
    RUN(test_xr_event_sequence);

    /* Reconciliation queries */
    RUN(test_xr_recon_get_not_found);
    RUN(test_xr_recon_get_by_op_not_found);

    /* Stats */
    RUN(test_xr_stats_null);
    RUN(test_xr_stats_initial);
    RUN(test_xr_stats_after_records);

    /* Counts */
    RUN(test_xr_pending_count);
    RUN(test_xr_finalized_count);

    /* Shutdown drain */
    RUN(test_xr_drain_null);
    RUN(test_xr_drain_not_init);
    RUN(test_xr_drain_all_finalized);
    RUN(test_xr_drain_has_unresolved);

    /* Edge cases */
    RUN(test_xr_multiple_records_finalized);
    RUN(test_xr_record_error_detail);

    SUITE_END();
    fail = TOTAL_FAIL();
    return fail;
}
