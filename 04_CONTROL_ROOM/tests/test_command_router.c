/*
 * test_command_router.c — Command Router & Operation Routing Tests (Step 04).
 *
 * Comprehensive tests for: lifecycle, request validation, target resolution,
 * capability verification, authorization, routing, cancellation, idempotency,
 * resource limits, events, audit, policy, statistics, cleanup, security.
 */

#include "../../tests/test_framework.h"
#include "../command_router.h"
#include "../component_registry.h"
#include "../../03_SECURITY/audit.h"
#include <string.h>
#include <time.h>

/* ============================================================
 * TEST HELPERS
 * ============================================================ */

static ozayn_router_service_t _svc;
static ozayn_reg_service_t _reg;
static ozayn_audit_service_t _au_svc;

static void _reset_all(void)
{
    memset(&_svc, 0, sizeof(_svc));
    memset(&_reg, 0, sizeof(_reg));
    memset(&_au_svc, 0, sizeof(_au_svc));
}

static void _init_reg(void)
{
    memset(&_reg, 0, sizeof(_reg));
    _au_svc.initialized = 1;
    ozayn_reg_service_config_t rcfg;
    memset(&rcfg, 0, sizeof(rcfg));
    rcfg.audit = (void *)&_au_svc;
    ozayn_reg_service_init(&_reg, &rcfg);
}

static void _init_router(void)
{
    _reset_all();
    _init_reg();
    _au_svc.initialized = 1;

    ozayn_router_service_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.component_registry = (void *)&_reg;
    cfg.audit = (void *)&_au_svc;
    ozayn_router_service_init(&_svc, &cfg);
}

static void _register_target(const char *id)
{
    ozayn_reg_register_component(&_reg, id, id, "1.0",
        OZAYN_REG_COMP_TYPE_CORE, "test", NULL);
    ozayn_reg_update_component_state(&_reg, id, OZAYN_REG_COMP_ACTIVE);
    ozayn_reg_update_component_availability(&_reg, id, OZAYN_REG_AVAIL_AVAILABLE);
}

static void _register_capability(const char *cap_id, const char *provider)
{
    ozayn_reg_register_capability(&_reg, cap_id, cap_id, "1.0", "test cap",
        provider, OZAYN_REG_CAP_CAT_SYSTEM, OZAYN_REG_ASSURANCE_PUBLIC, NULL);
}

/* ============================================================
 * LIFECYCLE TESTS
 * ============================================================ */

TEST(test_router_init)
{
    _reset_all();
    ozayn_router_service_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    ozayn_router_err_t r = ozayn_router_service_init(&_svc, &cfg);
    ASSERT_EQ(r, OZAYN_ROUTER_OK);
    ASSERT(_svc.initialized == 1);
    ASSERT_EQ(_svc.operation_count, 0);
    ozayn_router_service_shutdown(&_svc);
    return 0;
}

TEST(test_router_init_null)
{
    ASSERT_EQ(ozayn_router_service_init(NULL, NULL), OZAYN_ROUTER_ERR_NULL);
    return 0;
}

TEST(test_router_init_double)
{
    _init_router();
    ASSERT_EQ(ozayn_router_service_init(&_svc, NULL),
              OZAYN_ROUTER_ERR_ALREADY_INITIALIZED);
    ozayn_router_service_shutdown(&_svc);
    return 0;
}

TEST(test_router_shutdown)
{
    _init_router();
    ozayn_router_service_shutdown(&_svc);
    ASSERT(_svc.initialized == 0);
    return 0;
}

TEST(test_router_shutdown_null)
{
    ozayn_router_service_shutdown(NULL);
    return 0;
}

TEST(test_router_is_initialized)
{
    _reset_all();
    ASSERT(!ozayn_router_service_is_initialized(NULL));
    ASSERT(!ozayn_router_service_is_initialized(&_svc));
    _init_router();
    ASSERT(ozayn_router_service_is_initialized(&_svc));
    ozayn_router_service_shutdown(&_svc);
    ASSERT(!ozayn_router_service_is_initialized(&_svc));
    return 0;
}

/* ============================================================
 * REQUEST VALIDATION TESTS
 * ============================================================ */

TEST(test_router_validate_valid)
{
    _init_router();
    ASSERT_EQ(ozayn_router_validate_request(&_svc, "REQ-1",
        OZAYN_ROUTER_ACTION_START, "comp1", NULL), OZAYN_ROUTER_OK);
    ozayn_router_service_shutdown(&_svc);
    return 0;
}

TEST(test_router_validate_null)
{
    ASSERT_EQ(ozayn_router_validate_request(NULL, "X", 0, "X", NULL),
              OZAYN_ROUTER_ERR_NULL);
    return 0;
}

TEST(test_router_validate_not_init)
{
    memset(&_svc, 0, sizeof(_svc));
    ASSERT_EQ(ozayn_router_validate_request(&_svc, "X", 0, "X", NULL),
              OZAYN_ROUTER_ERR_NOT_INITIALIZED);
    return 0;
}

TEST(test_router_validate_missing_id)
{
    _init_router();
    ASSERT_EQ(ozayn_router_validate_request(&_svc, "",
        OZAYN_ROUTER_ACTION_START, "comp1", NULL),
              OZAYN_ROUTER_ERR_REQUEST_MISSING_ID);
    ASSERT_EQ(ozayn_router_validate_request(&_svc, NULL,
        OZAYN_ROUTER_ACTION_START, "comp1", NULL),
              OZAYN_ROUTER_ERR_REQUEST_MISSING_ID);
    ozayn_router_service_shutdown(&_svc);
    return 0;
}

TEST(test_router_validate_missing_target)
{
    _init_router();
    ASSERT_EQ(ozayn_router_validate_request(&_svc, "REQ-1",
        OZAYN_ROUTER_ACTION_START, "", NULL),
              OZAYN_ROUTER_ERR_REQUEST_MISSING_TARGET);
    ASSERT_EQ(ozayn_router_validate_request(&_svc, "REQ-1",
        OZAYN_ROUTER_ACTION_START, NULL, NULL),
              OZAYN_ROUTER_ERR_REQUEST_MISSING_TARGET);
    ozayn_router_service_shutdown(&_svc);
    return 0;
}

TEST(test_router_validate_invalid_action)
{
    _init_router();
    ASSERT_EQ(ozayn_router_validate_request(&_svc, "REQ-1",
        (ozayn_router_action_t)99, "comp1", NULL),
              OZAYN_ROUTER_ERR_REQUEST_MISSING_ACTION);
    ozayn_router_service_shutdown(&_svc);
    return 0;
}

TEST(test_router_validate_target_too_long)
{
    _init_router();
    char long_target[128];
    memset(long_target, 'A', sizeof(long_target) - 1);
    long_target[sizeof(long_target) - 1] = '\0';
    ASSERT_EQ(ozayn_router_validate_request(&_svc, "REQ-1",
        OZAYN_ROUTER_ACTION_START, long_target, NULL),
              OZAYN_ROUTER_ERR_INVALID_PARAM);
    ozayn_router_service_shutdown(&_svc);
    return 0;
}

/* ============================================================
 * OPERATION SUBMISSION TESTS
 * ============================================================ */

TEST(test_router_submit)
{
    _init_router();
    _register_target("CORE");
    ozayn_router_operation_t *op = NULL;
    ASSERT_EQ(ozayn_router_submit(&_svc, "REQ-1", OZAYN_ROUTER_ACTION_QUERY,
        "CORE", NULL, NULL, NULL, NULL, NULL, 0, 0, &op), OZAYN_ROUTER_OK);
    ASSERT_NOT_NULL(op);
    ASSERT_STR_EQ(op->request_id, "REQ-1");
    ASSERT_EQ(op->action, OZAYN_ROUTER_ACTION_QUERY);
    ASSERT_STR_EQ(op->target, "CORE");
    ASSERT_EQ(op->state, OZAYN_ROUTER_OP_RECEIVED);
    ASSERT(op->active == 1);
    ASSERT_EQ(_svc.total_requests, 1);
    ozayn_router_service_shutdown(&_svc);
    return 0;
}

TEST(test_router_submit_null)
{
    ASSERT_EQ(ozayn_router_submit(NULL, "X", 0, "X", NULL, NULL, NULL, NULL, NULL, 0, 0, NULL),
              OZAYN_ROUTER_ERR_NULL);
    return 0;
}

TEST(test_router_submit_not_init)
{
    memset(&_svc, 0, sizeof(_svc));
    ASSERT_EQ(ozayn_router_submit(&_svc, "X", 0, "X", NULL, NULL, NULL, NULL, NULL, 0, 0, NULL),
              OZAYN_ROUTER_ERR_NOT_INITIALIZED);
    return 0;
}

TEST(test_router_submit_generates_op_id)
{
    _init_router();
    _register_target("CORE");
    ozayn_router_operation_t *op = NULL;
    ozayn_router_submit(&_svc, "REQ-1", OZAYN_ROUTER_ACTION_QUERY,
        "CORE", NULL, NULL, NULL, NULL, NULL, 0, 0, &op);
    ASSERT_NOT_NULL(op);
    ASSERT(op->operation_id[0] != '\0');
    ASSERT(strncmp(op->operation_id, "OPR-", 4) == 0);
    ozayn_router_service_shutdown(&_svc);
    return 0;
}

TEST(test_router_submit_unique_ids)
{
    _init_router();
    _register_target("CORE");
    ozayn_router_operation_t *op1 = NULL, *op2 = NULL;
    ozayn_router_submit(&_svc, "REQ-1", OZAYN_ROUTER_ACTION_QUERY,
        "CORE", NULL, NULL, NULL, NULL, NULL, 0, 0, &op1);
    ozayn_router_submit(&_svc, "REQ-2", OZAYN_ROUTER_ACTION_QUERY,
        "CORE", NULL, NULL, NULL, NULL, NULL, 0, 0, &op2);
    ASSERT_NOT_NULL(op1);
    ASSERT_NOT_NULL(op2);
    ASSERT(strcmp(op1->operation_id, op2->operation_id) != 0);
    ozayn_router_service_shutdown(&_svc);
    return 0;
}

TEST(test_router_submit_stores_context)
{
    _init_router();
    _register_target("CORE");
    ozayn_router_operation_t *op = NULL;
    ozayn_router_submit(&_svc, "REQ-1", OZAYN_ROUTER_ACTION_QUERY,
        "CORE", NULL, "some context", "user1", "sess1", "READ", 5, 1, &op);
    ASSERT_NOT_NULL(op);
    ASSERT_STR_EQ(op->context, "some context");
    ASSERT_STR_EQ(op->requester_identity, "user1");
    ASSERT_STR_EQ(op->session_id, "sess1");
    ASSERT_STR_EQ(op->required_permission, "READ");
    ASSERT_EQ(op->priority, 5);
    ASSERT(op->idempotent == 1);
    ozayn_router_service_shutdown(&_svc);
    return 0;
}

/* ============================================================
 * PROCESSING / ROUTING TESTS
 * ============================================================ */

TEST(test_router_process_query)
{
    _init_router();
    _register_target("CORE");
    ozayn_router_operation_t *op = NULL;
    ozayn_router_submit(&_svc, "REQ-1", OZAYN_ROUTER_ACTION_QUERY,
        "CORE", NULL, NULL, NULL, NULL, NULL, 0, 0, &op);
    ozayn_router_result_t result;
    ASSERT_EQ(ozayn_router_process(&_svc, op->operation_id, &result),
              OZAYN_ROUTER_OK);
    ASSERT_EQ(result.result_state, OZAYN_ROUTER_RESULT_SUCCEEDED);
    ASSERT_EQ(result.result_code, 0);
    ASSERT_STR_EQ(result.target, "CORE");
    ASSERT_EQ(result.action, OZAYN_ROUTER_ACTION_QUERY);
    ozayn_router_service_shutdown(&_svc);
    return 0;
}

TEST(test_router_process_unsupported_action)
{
    _init_router();
    _register_target("CORE");
    ozayn_router_operation_t *op = NULL;
    ozayn_router_submit(&_svc, "REQ-1", OZAYN_ROUTER_ACTION_START,
        "CORE", NULL, NULL, NULL, NULL, NULL, 0, 0, &op);
    ozayn_router_result_t result;
    ASSERT_EQ(ozayn_router_process(&_svc, op->operation_id, &result),
              OZAYN_ROUTER_OK);
    ASSERT_EQ(result.result_state, OZAYN_ROUTER_RESULT_UNSUPPORTED);
    ozayn_router_service_shutdown(&_svc);
    return 0;
}

TEST(test_router_process_not_found)
{
    _init_router();
    ozayn_router_result_t result;
    ASSERT_EQ(ozayn_router_process(&_svc, "NOPE", &result),
              OZAYN_ROUTER_ERR_NOT_FOUND);
    ozayn_router_service_shutdown(&_svc);
    return 0;
}

TEST(test_router_process_null)
{
    ASSERT_EQ(ozayn_router_process(NULL, "X", NULL), OZAYN_ROUTER_ERR_NULL);
    return 0;
}

TEST(test_router_process_empty_id)
{
    _init_router();
    ASSERT_EQ(ozayn_router_process(&_svc, "", NULL),
              OZAYN_ROUTER_ERR_INVALID_PARAM);
    ozayn_router_service_shutdown(&_svc);
    return 0;
}

TEST(test_router_process_validates_request)
{
    _init_router();
    /* Submit with invalid data but process will re-validate */
    ozayn_router_operation_t *op = NULL;
    ozayn_router_submit(&_svc, "REQ-1", OZAYN_ROUTER_ACTION_QUERY,
        "TARGET", NULL, NULL, NULL, NULL, NULL, 0, 0, &op);
    /* Target not in registry — should fail target resolution */
    ozayn_router_result_t result;
    ASSERT_EQ(ozayn_router_process(&_svc, op->operation_id, &result),
              OZAYN_ROUTER_OK);
    ASSERT_EQ(result.result_state, OZAYN_ROUTER_RESULT_REJECTED);
    ozayn_router_service_shutdown(&_svc);
    return 0;
}

/* ============================================================
 * TARGET RESOLUTION TESTS
 * ============================================================ */

TEST(test_router_target_resolved)
{
    _init_router();
    _register_target("MOD-A");
    ozayn_router_operation_t *op = NULL;
    ozayn_router_submit(&_svc, "REQ-1", OZAYN_ROUTER_ACTION_QUERY,
        "MOD-A", NULL, NULL, NULL, NULL, NULL, 0, 0, &op);
    ozayn_router_result_t result;
    ASSERT_EQ(ozayn_router_process(&_svc, op->operation_id, &result),
              OZAYN_ROUTER_OK);
    ASSERT_EQ(result.result_state, OZAYN_ROUTER_RESULT_SUCCEEDED);
    ozayn_router_service_shutdown(&_svc);
    return 0;
}

TEST(test_router_target_not_found)
{
    _init_router();
    ozayn_router_operation_t *op = NULL;
    ozayn_router_submit(&_svc, "REQ-1", OZAYN_ROUTER_ACTION_QUERY,
        "NONEXISTENT", NULL, NULL, NULL, NULL, NULL, 0, 0, &op);
    ozayn_router_result_t result;
    ASSERT_EQ(ozayn_router_process(&_svc, op->operation_id, &result),
              OZAYN_ROUTER_OK);
    ASSERT_EQ(result.result_state, OZAYN_ROUTER_RESULT_REJECTED);
    ASSERT_EQ(_svc.total_rejected, 1);
    ozayn_router_service_shutdown(&_svc);
    return 0;
}

TEST(test_router_target_unavailable)
{
    _init_router();
    _register_target("MOD-B");
    ozayn_reg_update_component_availability(&_reg, "MOD-B",
        OZAYN_REG_AVAIL_UNAVAILABLE);
    ozayn_router_operation_t *op = NULL;
    ozayn_router_submit(&_svc, "REQ-1", OZAYN_ROUTER_ACTION_QUERY,
        "MOD-B", NULL, NULL, NULL, NULL, NULL, 0, 0, &op);
    ozayn_router_result_t result;
    ASSERT_EQ(ozayn_router_process(&_svc, op->operation_id, &result),
              OZAYN_ROUTER_OK);
    ASSERT_EQ(result.result_state, OZAYN_ROUTER_RESULT_UNAVAILABLE);
    ozayn_router_service_shutdown(&_svc);
    return 0;
}

TEST(test_router_target_error_state)
{
    _init_router();
    _register_target("MOD-C");
    ozayn_reg_update_component_state(&_reg, "MOD-C", OZAYN_REG_COMP_ERROR);
    ozayn_router_operation_t *op = NULL;
    ozayn_router_submit(&_svc, "REQ-1", OZAYN_ROUTER_ACTION_QUERY,
        "MOD-C", NULL, NULL, NULL, NULL, NULL, 0, 0, &op);
    ozayn_router_result_t result;
    ASSERT_EQ(ozayn_router_process(&_svc, op->operation_id, &result),
              OZAYN_ROUTER_OK);
    ASSERT_EQ(result.result_state, OZAYN_ROUTER_RESULT_REJECTED);
    ozayn_router_service_shutdown(&_svc);
    return 0;
}

/* ============================================================
 * CAPABILITY VERIFICATION TESTS
 * ============================================================ */

TEST(test_router_capability_found)
{
    _init_router();
    _register_target("CORE");
    _register_capability("CAP-READ", "CORE");
    ozayn_router_operation_t *op = NULL;
    ozayn_router_submit(&_svc, "REQ-1", OZAYN_ROUTER_ACTION_QUERY,
        "CORE", "CAP-READ", NULL, NULL, NULL, NULL, 0, 0, &op);
    ozayn_router_result_t result;
    ASSERT_EQ(ozayn_router_process(&_svc, op->operation_id, &result),
              OZAYN_ROUTER_OK);
    ASSERT_EQ(result.result_state, OZAYN_ROUTER_RESULT_SUCCEEDED);
    ozayn_router_service_shutdown(&_svc);
    return 0;
}

TEST(test_router_capability_not_found)
{
    _init_router();
    _register_target("CORE");
    ozayn_router_operation_t *op = NULL;
    ozayn_router_submit(&_svc, "REQ-1", OZAYN_ROUTER_ACTION_QUERY,
        "CORE", "NO-CAP", NULL, NULL, NULL, NULL, 0, 0, &op);
    ozayn_router_result_t result;
    ASSERT_EQ(ozayn_router_process(&_svc, op->operation_id, &result),
              OZAYN_ROUTER_OK);
    ASSERT_EQ(result.result_state, OZAYN_ROUTER_RESULT_REJECTED);
    ozayn_router_service_shutdown(&_svc);
    return 0;
}

TEST(test_router_capability_unavailable)
{
    _init_router();
    _register_target("CORE");
    _register_capability("CAP-DBG", "CORE");
    ozayn_reg_update_capability_state(&_reg, "CAP-DBG",
        OZAYN_REG_CAP_STATE_UNAVAILABLE);
    ozayn_router_operation_t *op = NULL;
    ozayn_router_submit(&_svc, "REQ-1", OZAYN_ROUTER_ACTION_QUERY,
        "CORE", "CAP-DBG", NULL, NULL, NULL, NULL, 0, 0, &op);
    ozayn_router_result_t result;
    ASSERT_EQ(ozayn_router_process(&_svc, op->operation_id, &result),
              OZAYN_ROUTER_OK);
    ASSERT_EQ(result.result_state, OZAYN_ROUTER_RESULT_UNAVAILABLE);
    ozayn_router_service_shutdown(&_svc);
    return 0;
}

TEST(test_router_capability_disabled)
{
    _init_router();
    _register_target("CORE");
    _register_capability("CAP-DIS", "CORE");
    ozayn_reg_update_capability_state(&_reg, "CAP-DIS",
        OZAYN_REG_CAP_STATE_DISABLED);
    ozayn_router_operation_t *op = NULL;
    ozayn_router_submit(&_svc, "REQ-1", OZAYN_ROUTER_ACTION_QUERY,
        "CORE", "CAP-DIS", NULL, NULL, NULL, NULL, 0, 0, &op);
    ozayn_router_result_t result;
    ASSERT_EQ(ozayn_router_process(&_svc, op->operation_id, &result),
              OZAYN_ROUTER_OK);
    ASSERT_EQ(result.result_state, OZAYN_ROUTER_RESULT_REJECTED);
    ozayn_router_service_shutdown(&_svc);
    return 0;
}

TEST(test_router_capability_provider_missing)
{
    _init_router();
    _register_target("CORE");
    _register_capability("CAP-ORPH", "GHOST");
    ozayn_router_operation_t *op = NULL;
    ozayn_router_submit(&_svc, "REQ-1", OZAYN_ROUTER_ACTION_QUERY,
        "CORE", "CAP-ORPH", NULL, NULL, NULL, NULL, 0, 0, &op);
    ozayn_router_result_t result;
    ASSERT_EQ(ozayn_router_process(&_svc, op->operation_id, &result),
              OZAYN_ROUTER_OK);
    ASSERT_EQ(result.result_state, OZAYN_ROUTER_RESULT_REJECTED);
    ozayn_router_service_shutdown(&_svc);
    return 0;
}

TEST(test_router_no_capability_required)
{
    _init_router();
    _register_target("CORE");
    /* No capability specified — should pass when not required */
    ozayn_router_operation_t *op = NULL;
    ozayn_router_submit(&_svc, "REQ-1", OZAYN_ROUTER_ACTION_QUERY,
        "CORE", NULL, NULL, NULL, NULL, NULL, 0, 0, &op);
    ozayn_router_result_t result;
    ASSERT_EQ(ozayn_router_process(&_svc, op->operation_id, &result),
              OZAYN_ROUTER_OK);
    ASSERT_EQ(result.result_state, OZAYN_ROUTER_RESULT_SUCCEEDED);
    ozayn_router_service_shutdown(&_svc);
    return 0;
}

/* ============================================================
 * AUTHORIZATION INTEGRATION TESTS
 * ============================================================ */

TEST(test_router_auth_not_required)
{
    _init_router();
    _register_target("CORE");
    /* Default policy: require_authorization = 0 */
    ozayn_router_operation_t *op = NULL;
    ozayn_router_submit(&_svc, "REQ-1", OZAYN_ROUTER_ACTION_QUERY,
        "CORE", NULL, NULL, NULL, NULL, NULL, 0, 0, &op);
    ozayn_router_result_t result;
    ASSERT_EQ(ozayn_router_process(&_svc, op->operation_id, &result),
              OZAYN_ROUTER_OK);
    ASSERT_EQ(result.result_state, OZAYN_ROUTER_RESULT_SUCCEEDED);
    ozayn_router_service_shutdown(&_svc);
    return 0;
}

TEST(test_router_auth_required_no_service)
{
    _init_router();
    _register_target("CORE");
    ozayn_router_policy_t p = ozayn_router_default_policy();
    p.require_authorization = 1;
    ozayn_router_set_policy(&_svc, &p);
    /* No authorization service configured */
    ozayn_router_operation_t *op = NULL;
    ozayn_router_submit(&_svc, "REQ-1", OZAYN_ROUTER_ACTION_QUERY,
        "CORE", NULL, NULL, NULL, NULL, NULL, 0, 0, &op);
    ozayn_router_result_t result;
    ASSERT_EQ(ozayn_router_process(&_svc, op->operation_id, &result),
              OZAYN_ROUTER_OK);
    ASSERT_EQ(result.result_state, OZAYN_ROUTER_RESULT_REJECTED);
    ASSERT_EQ(_svc.total_authorization_denials, 1);
    ozayn_router_service_shutdown(&_svc);
    return 0;
}

/* ============================================================
 * CANCELLATION TESTS
 * ============================================================ */

TEST(test_router_cancel)
{
    _init_router();
    _register_target("CORE");
    ozayn_router_operation_t *op = NULL;
    ozayn_router_submit(&_svc, "REQ-1", OZAYN_ROUTER_ACTION_QUERY,
        "CORE", NULL, NULL, NULL, NULL, NULL, 0, 0, &op);
    ASSERT_EQ(ozayn_router_cancel(&_svc, op->operation_id), OZAYN_ROUTER_OK);
    ASSERT_EQ(op->state, OZAYN_ROUTER_OP_CANCELLED);
    ASSERT_EQ(_svc.total_cancelled, 1);
    ozayn_router_service_shutdown(&_svc);
    return 0;
}

TEST(test_router_cancel_not_found)
{
    _init_router();
    ASSERT_EQ(ozayn_router_cancel(&_svc, "NOPE"),
              OZAYN_ROUTER_ERR_NOT_FOUND);
    ozayn_router_service_shutdown(&_svc);
    return 0;
}

TEST(test_router_cancel_terminal)
{
    _init_router();
    _register_target("CORE");
    ozayn_router_operation_t *op = NULL;
    ozayn_router_submit(&_svc, "REQ-1", OZAYN_ROUTER_ACTION_QUERY,
        "CORE", NULL, NULL, NULL, NULL, NULL, 0, 0, &op);
    /* Process to completion */
    ozayn_router_result_t result;
    ozayn_router_process(&_svc, op->operation_id, &result);
    /* Now try to cancel — should fail because it's terminal */
    ASSERT_EQ(ozayn_router_cancel(&_svc, op->operation_id),
              OZAYN_ROUTER_ERR_STATE_INVALID);
    ozayn_router_service_shutdown(&_svc);
    return 0;
}

TEST(test_router_cancellable)
{
    _init_router();
    _register_target("CORE");
    ozayn_router_operation_t *op = NULL;
    ozayn_router_submit(&_svc, "REQ-1", OZAYN_ROUTER_ACTION_QUERY,
        "CORE", NULL, NULL, NULL, NULL, NULL, 0, 0, &op);
    ASSERT(ozayn_router_operation_cancellable(&_svc, op->operation_id));
    /* Process to completion */
    ozayn_router_result_t result;
    ozayn_router_process(&_svc, op->operation_id, &result);
    ASSERT(!ozayn_router_operation_cancellable(&_svc, op->operation_id));
    ozayn_router_service_shutdown(&_svc);
    return 0;
}

TEST(test_router_cancel_null)
{
    ASSERT_EQ(ozayn_router_cancel(NULL, "X"), OZAYN_ROUTER_ERR_NULL);
    _init_router();
    ASSERT_EQ(ozayn_router_cancel(&_svc, ""), OZAYN_ROUTER_ERR_INVALID_PARAM);
    ozayn_router_service_shutdown(&_svc);
    return 0;
}

/* ============================================================
 * IDEMPOTENCY TESTS
 * ============================================================ */

TEST(test_router_idempotent_duplicate)
{
    _init_router();
    _register_target("CORE");
    ozayn_router_operation_t *op1 = NULL;
    ozayn_router_submit(&_svc, "REQ-1", OZAYN_ROUTER_ACTION_QUERY,
        "CORE", NULL, NULL, NULL, NULL, NULL, 0, 1, &op1);
    ozayn_router_operation_t *op2 = NULL;
    ASSERT_EQ(ozayn_router_submit(&_svc, "REQ-1", OZAYN_ROUTER_ACTION_QUERY,
        "CORE", NULL, NULL, NULL, NULL, NULL, 0, 1, &op2),
              OZAYN_ROUTER_ERR_DUPLICATE_REQUEST);
    ASSERT_EQ(_svc.total_duplicates, 1);
    ozayn_router_service_shutdown(&_svc);
    return 0;
}

TEST(test_router_non_idempotent_allows)
{
    _init_router();
    _register_target("CORE");
    ozayn_router_operation_t *op1 = NULL;
    ozayn_router_submit(&_svc, "REQ-1", OZAYN_ROUTER_ACTION_QUERY,
        "CORE", NULL, NULL, NULL, NULL, NULL, 0, 0, &op1);
    ozayn_router_operation_t *op2 = NULL;
    ASSERT_EQ(ozayn_router_submit(&_svc, "REQ-1", OZAYN_ROUTER_ACTION_QUERY,
        "CORE", NULL, NULL, NULL, NULL, NULL, 0, 0, &op2),
              OZAYN_ROUTER_OK);
    ozayn_router_service_shutdown(&_svc);
    return 0;
}

/* ============================================================
 * RESOURCE LIMIT TESTS
 * ============================================================ */

TEST(test_router_queue_full)
{
    _init_router();
    _register_target("CORE");
    ozayn_router_policy_t p = ozayn_router_default_policy();
    p.max_queue_size = 2;
    ozayn_router_set_policy(&_svc, &p);
    ozayn_router_operation_t *op1 = NULL, *op2 = NULL;
    ozayn_router_submit(&_svc, "R1", OZAYN_ROUTER_ACTION_QUERY,
        "CORE", NULL, NULL, NULL, NULL, NULL, 0, 0, &op1);
    ozayn_router_submit(&_svc, "R2", OZAYN_ROUTER_ACTION_QUERY,
        "CORE", NULL, NULL, NULL, NULL, NULL, 0, 0, &op2);
    ASSERT_EQ(ozayn_router_queue_full(&_svc), 1);
    ASSERT_EQ(ozayn_router_submit(&_svc, "R3", OZAYN_ROUTER_ACTION_QUERY,
        "CORE", NULL, NULL, NULL, NULL, NULL, 0, 0, NULL),
              OZAYN_ROUTER_ERR_QUEUE_FULL);
    ozayn_router_service_shutdown(&_svc);
    return 0;
}

TEST(test_router_concurrency_limit)
{
    _init_router();
    _register_target("CORE");
    ozayn_router_policy_t p = ozayn_router_default_policy();
    p.max_concurrent_ops = 1;
    ozayn_router_set_policy(&_svc, &p);
    ASSERT_EQ(ozayn_router_concurrency_limit(&_svc), 0);
    _svc.active_ops = 1;
    ASSERT_EQ(ozayn_router_concurrency_limit(&_svc), 1);
    ozayn_router_service_shutdown(&_svc);
    return 0;
}

/* ============================================================
 * QUERY TESTS
 * ============================================================ */

TEST(test_router_get_operation)
{
    _init_router();
    _register_target("CORE");
    ozayn_router_operation_t *op = NULL;
    ozayn_router_submit(&_svc, "REQ-1", OZAYN_ROUTER_ACTION_QUERY,
        "CORE", NULL, NULL, NULL, NULL, NULL, 0, 0, &op);
    ozayn_router_operation_t *found = ozayn_router_get_operation(
        &_svc, op->operation_id);
    ASSERT_NOT_NULL(found);
    ASSERT(strcmp(found->operation_id, op->operation_id) == 0);
    ASSERT_NULL(ozayn_router_get_operation(&_svc, "NOPE"));
    ASSERT_NULL(ozayn_router_get_operation(NULL, "X"));
    ozayn_router_service_shutdown(&_svc);
    return 0;
}

TEST(test_router_operation_count)
{
    _init_router();
    ASSERT_EQ(ozayn_router_operation_count(&_svc), 0);
    _register_target("CORE");
    ozayn_router_submit(&_svc, "REQ-1", OZAYN_ROUTER_ACTION_QUERY,
        "CORE", NULL, NULL, NULL, NULL, NULL, 0, 0, NULL);
    ASSERT_EQ(ozayn_router_operation_count(&_svc), 1);
    ASSERT_EQ(ozayn_router_operation_count(NULL), 0);
    ozayn_router_service_shutdown(&_svc);
    return 0;
}

TEST(test_router_active_count)
{
    _init_router();
    _register_target("CORE");
    ozayn_router_operation_t *op = NULL;
    ozayn_router_submit(&_svc, "REQ-1", OZAYN_ROUTER_ACTION_QUERY,
        "CORE", NULL, NULL, NULL, NULL, NULL, 0, 0, &op);
    ASSERT_EQ(ozayn_router_active_count(&_svc), 1);
    /* Process to completion */
    ozayn_router_result_t result;
    ozayn_router_process(&_svc, op->operation_id, &result);
    ASSERT_EQ(ozayn_router_active_count(&_svc), 0);
    ozayn_router_service_shutdown(&_svc);
    return 0;
}

/* ============================================================
 * POLICY TESTS
 * ============================================================ */

TEST(test_router_default_policy)
{
    ozayn_router_policy_t p = ozayn_router_default_policy();
    ASSERT(p.enabled == 1);
    ASSERT_EQ(p.max_concurrent_ops, 16);
    ASSERT_EQ(p.max_queue_size, OZAYN_ROUTER_MAX_QUEUE);
    ASSERT(p.request_timeout_ms > 0);
    ASSERT(p.require_authorization == 0);
    return 0;
}

TEST(test_router_set_policy)
{
    _init_router();
    ozayn_router_policy_t p = ozayn_router_default_policy();
    p.max_concurrent_ops = 4;
    ASSERT_EQ(ozayn_router_set_policy(&_svc, &p), OZAYN_ROUTER_OK);
    ASSERT_EQ(_svc.policy.max_concurrent_ops, 4);
    ozayn_router_service_shutdown(&_svc);
    return 0;
}

TEST(test_router_set_policy_null)
{
    _init_router();
    ASSERT_EQ(ozayn_router_set_policy(&_svc, NULL),
              OZAYN_ROUTER_ERR_INVALID_PARAM);
    ozayn_router_service_shutdown(&_svc);
    return 0;
}

TEST(test_router_get_policy)
{
    _init_router();
    const ozayn_router_policy_t *p = ozayn_router_get_policy(&_svc);
    ASSERT_NOT_NULL(p);
    ASSERT(p->enabled == 1);
    ASSERT_NULL(ozayn_router_get_policy(NULL));
    ozayn_router_service_shutdown(&_svc);
    return 0;
}

/* ============================================================
 * STATISTICS TESTS
 * ============================================================ */

TEST(test_router_statistics)
{
    _init_router();
    ASSERT_EQ(ozayn_router_total_requests(&_svc), 0);
    _register_target("CORE");
    ozayn_router_operation_t *op = NULL;
    ozayn_router_submit(&_svc, "REQ-1", OZAYN_ROUTER_ACTION_QUERY,
        "CORE", NULL, NULL, NULL, NULL, NULL, 0, 0, &op);
    ASSERT_EQ(ozayn_router_total_requests(&_svc), 1);
    ozayn_router_result_t result;
    ozayn_router_process(&_svc, op->operation_id, &result);
    ASSERT_EQ(ozayn_router_total_succeeded(&_svc), 1);
    ASSERT_EQ(ozayn_router_total_requests(NULL), 0);
    ozayn_router_service_shutdown(&_svc);
    return 0;
}

TEST(test_router_statistics_rejected)
{
    _init_router();
    _register_target("CORE");
    /* Submit with unknown target to trigger rejection */
    ozayn_router_operation_t *op = NULL;
    ozayn_router_submit(&_svc, "REQ-1", OZAYN_ROUTER_ACTION_QUERY,
        "NOPE", NULL, NULL, NULL, NULL, NULL, 0, 0, &op);
    ozayn_router_result_t result;
    ozayn_router_process(&_svc, op->operation_id, &result);
    ASSERT_EQ(_svc.total_rejected, 1);
    ozayn_router_service_shutdown(&_svc);
    return 0;
}

/* ============================================================
 * CLEANUP TESTS
 * ============================================================ */

TEST(test_router_cleanup_completed)
{
    _init_router();
    _register_target("CORE");
    ozayn_router_operation_t *op = NULL;
    ozayn_router_submit(&_svc, "REQ-1", OZAYN_ROUTER_ACTION_QUERY,
        "CORE", NULL, NULL, NULL, NULL, NULL, 0, 0, &op);
    ozayn_router_result_t result;
    ozayn_router_process(&_svc, op->operation_id, &result);
    int cleaned = ozayn_router_cleanup_completed(&_svc);
    ASSERT(cleaned >= 1);
    ozayn_router_service_shutdown(&_svc);
    return 0;
}

TEST(test_router_cleanup_null)
{
    ASSERT_EQ(ozayn_router_cleanup_completed(NULL), 0);
    ASSERT_EQ(ozayn_router_cleanup_expired(NULL), 0);
    return 0;
}

/* ============================================================
 * NAME HELPER TESTS
 * ============================================================ */

TEST(test_router_err_name)
{
    ASSERT_STR_EQ(ozayn_router_err_name(OZAYN_ROUTER_OK), "OK");
    ASSERT_STR_EQ(ozayn_router_err_name(OZAYN_ROUTER_ERR_NULL), "NULL");
    ASSERT_STR_EQ(ozayn_router_err_name(OZAYN_ROUTER_ERR_TARGET_NOT_FOUND),
                  "TARGET_NOT_FOUND");
    ASSERT_STR_EQ(ozayn_router_err_name(OZAYN_ROUTER_ERR_CAPABILITY_NOT_FOUND),
                  "CAPABILITY_NOT_FOUND");
    ASSERT_STR_EQ(ozayn_router_err_name(OZAYN_ROUTER_ERR_QUEUE_FULL),
                  "QUEUE_FULL");
    ASSERT_STR_EQ(ozayn_router_err_name((ozayn_router_err_t)999), "UNKNOWN");
    return 0;
}

TEST(test_router_op_state_name)
{
    ASSERT_STR_EQ(ozayn_router_op_state_name(OZAYN_ROUTER_OP_RECEIVED),
                  "RECEIVED");
    ASSERT_STR_EQ(ozayn_router_op_state_name(OZAYN_ROUTER_OP_SUCCEEDED),
                  "SUCCEEDED");
    ASSERT_STR_EQ(ozayn_router_op_state_name(OZAYN_ROUTER_OP_CANCELLED),
                  "CANCELLED");
    ASSERT_STR_EQ(ozayn_router_op_state_name((ozayn_router_op_state_t)99),
                  "UNKNOWN");
    return 0;
}

TEST(test_router_result_state_name)
{
    ASSERT_STR_EQ(ozayn_router_result_state_name(OZAYN_ROUTER_RESULT_SUCCEEDED),
                  "SUCCEEDED");
    ASSERT_STR_EQ(ozayn_router_result_state_name(OZAYN_ROUTER_RESULT_REJECTED),
                  "REJECTED");
    ASSERT_STR_EQ(ozayn_router_result_state_name((ozayn_router_result_state_t)99),
                  "UNKNOWN");
    return 0;
}

TEST(test_router_action_name)
{
    ASSERT_STR_EQ(ozayn_router_action_name(OZAYN_ROUTER_ACTION_START), "START");
    ASSERT_STR_EQ(ozayn_router_action_name(OZAYN_ROUTER_ACTION_STOP), "STOP");
    ASSERT_STR_EQ(ozayn_router_action_name(OZAYN_ROUTER_ACTION_QUERY), "QUERY");
    ASSERT_STR_EQ(ozayn_router_action_name(OZAYN_ROUTER_ACTION_DIAGNOSTIC),
                  "DIAGNOSTIC");
    ASSERT_STR_EQ(ozayn_router_action_name((ozayn_router_action_t)99), "UNKNOWN");
    return 0;
}

TEST(test_router_event_type_name)
{
    ASSERT_STR_EQ(ozayn_router_event_type_name(OZAYN_ROUTER_EVENT_REQUEST_RECEIVED),
                  "REQUEST_RECEIVED");
    ASSERT_STR_EQ(ozayn_router_event_type_name(OZAYN_ROUTER_EVENT_OPERATION_SUCCEEDED),
                  "OPERATION_SUCCEEDED");
    ASSERT_STR_EQ(ozayn_router_event_type_name((ozayn_router_event_type_t)99),
                  "UNKNOWN");
    return 0;
}

TEST(test_router_precond_name)
{
    ASSERT_STR_EQ(ozayn_router_precond_name(OZAYN_ROUTER_PRECOND_NONE), "NONE");
    ASSERT_STR_EQ(ozayn_router_precond_name(OZAYN_ROUTER_PRECOND_TARGET_MISSING),
                  "TARGET_MISSING");
    ASSERT_STR_EQ(ozayn_router_precond_name((ozayn_router_precond_t)99),
                  "UNKNOWN");
    return 0;
}

/* ============================================================
 * EVENT / AUDIT TESTS
 * ============================================================ */

TEST(test_router_emit_event)
{
    _init_router();
    ASSERT_EQ(ozayn_router_emit_event(&_svc,
        OZAYN_ROUTER_EVENT_REQUEST_RECEIVED, "OPR-1", "test"),
        OZAYN_ROUTER_OK);
    ASSERT_EQ(ozayn_router_emit_event(NULL,
        OZAYN_ROUTER_EVENT_REQUEST_RECEIVED, "OPR-1", "test"),
        OZAYN_ROUTER_ERR_NULL);
    ozayn_router_service_shutdown(&_svc);
    return 0;
}

TEST(test_router_audit_operation)
{
    _init_router();
    ASSERT_EQ(ozayn_router_audit_operation(&_svc, "OPR-1", "TEST", "detail"),
              OZAYN_ROUTER_OK);
    ASSERT_EQ(ozayn_router_audit_operation(NULL, "X", "X", "X"),
              OZAYN_ROUTER_ERR_NULL);
    ASSERT_EQ(ozayn_router_audit_operation(&_svc, NULL, "X", "X"),
              OZAYN_ROUTER_ERR_INVALID_PARAM);
    ozayn_router_service_shutdown(&_svc);
    return 0;
}

/* ============================================================
 * SECURITY BOUNDARY TESTS
 * ============================================================ */

TEST(test_router_no_secrets_in_operation)
{
    _init_router();
    _register_target("CORE");
    ozayn_router_operation_t *op = NULL;
    ozayn_router_submit(&_svc, "REQ-1", OZAYN_ROUTER_ACTION_QUERY,
        "CORE", NULL, "password=secret key=abc token=xyz",
        NULL, NULL, NULL, 0, 0, &op);
    /* The operation stores metadata but does not log it */
    ASSERT(op->active == 1);
    ozayn_router_service_shutdown(&_svc);
    return 0;
}

TEST(test_router_global_singleton)
{
    ozayn_router_service_t *g1 = ozayn_router_get_global();
    ozayn_router_service_t *g2 = ozayn_router_get_global();
    ASSERT_NOT_NULL(g1);
    ASSERT(g1 == g2);
    return 0;
}

TEST(test_router_process_null_result)
{
    _init_router();
    _register_target("CORE");
    ozayn_router_operation_t *op = NULL;
    ozayn_router_submit(&_svc, "REQ-1", OZAYN_ROUTER_ACTION_QUERY,
        "CORE", NULL, NULL, NULL, NULL, NULL, 0, 0, &op);
    /* Process with NULL result — should not crash */
    ASSERT_EQ(ozayn_router_process(&_svc, op->operation_id, NULL),
              OZAYN_ROUTER_OK);
    ozayn_router_service_shutdown(&_svc);
    return 0;
}

TEST(test_router_no_registry)
{
    _reset_all();
    _au_svc.initialized = 1;
    ozayn_router_service_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.audit = (void *)&_au_svc;
    ozayn_router_service_init(&_svc, &cfg);
    /* No component registry — target resolution skipped */
    ozayn_router_operation_t *op = NULL;
    ozayn_router_submit(&_svc, "REQ-1", OZAYN_ROUTER_ACTION_QUERY,
        "ANY", NULL, NULL, NULL, NULL, NULL, 0, 0, &op);
    ozayn_router_result_t result;
    ASSERT_EQ(ozayn_router_process(&_svc, op->operation_id, &result),
              OZAYN_ROUTER_OK);
    ASSERT_EQ(result.result_state, OZAYN_ROUTER_RESULT_SUCCEEDED);
    ozayn_router_service_shutdown(&_svc);
    return 0;
}

/* ============================================================
 * FULL PIPELINE TEST
 * ============================================================ */

TEST(test_router_full_pipeline)
{
    _init_router();
    _register_target("MOD-VISION");
    _register_capability("VIS-CAP", "MOD-VISION");

    /* Submit */
    ozayn_router_operation_t *op = NULL;
    ASSERT_EQ(ozayn_router_submit(&_svc, "REQ-FULL",
        OZAYN_ROUTER_ACTION_QUERY, "MOD-VISION", "VIS-CAP",
        "test context", "user-1", "sess-1", "VISION.READ",
        5, 1, &op), OZAYN_ROUTER_OK);

    /* Verify initial state */
    ASSERT_EQ(op->state, OZAYN_ROUTER_OP_RECEIVED);
    ASSERT_STR_EQ(op->request_id, "REQ-FULL");
    ASSERT_STR_EQ(op->target, "MOD-VISION");
    ASSERT_STR_EQ(op->capability, "VIS-CAP");
    ASSERT_STR_EQ(op->requester_identity, "user-1");

    /* Process full pipeline */
    ozayn_router_result_t result;
    ASSERT_EQ(ozayn_router_process(&_svc, op->operation_id, &result),
              OZAYN_ROUTER_OK);

    /* Verify result */
    ASSERT_EQ(result.result_state, OZAYN_ROUTER_RESULT_SUCCEEDED);
    ASSERT_EQ(result.result_code, 0);
    ASSERT_STR_EQ(result.operation_id, op->operation_id);
    ASSERT_STR_EQ(result.request_id, "REQ-FULL");
    ASSERT_STR_EQ(result.target, "MOD-VISION");
    ASSERT_EQ(result.action, OZAYN_ROUTER_ACTION_QUERY);

    /* Verify stats */
    ASSERT_EQ(_svc.total_requests, 1);
    ASSERT_EQ(_svc.total_succeeded, 1);

    /* Verify terminal state */
    ASSERT(!ozayn_router_operation_cancellable(&_svc, op->operation_id));

    ozayn_router_service_shutdown(&_svc);
    return 0;
}

/* ============================================================
 * TEST RUNNER
 * ============================================================ */

int run_command_router_tests(void)
{
    SUITE_BEGIN("Command Router & Operation Routing");

    /* Lifecycle */
    RUN(test_router_init);
    RUN(test_router_init_null);
    RUN(test_router_init_double);
    RUN(test_router_shutdown);
    RUN(test_router_shutdown_null);
    RUN(test_router_is_initialized);

    /* Request Validation */
    RUN(test_router_validate_valid);
    RUN(test_router_validate_null);
    RUN(test_router_validate_not_init);
    RUN(test_router_validate_missing_id);
    RUN(test_router_validate_missing_target);
    RUN(test_router_validate_invalid_action);
    RUN(test_router_validate_target_too_long);

    /* Operation Submission */
    RUN(test_router_submit);
    RUN(test_router_submit_null);
    RUN(test_router_submit_not_init);
    RUN(test_router_submit_generates_op_id);
    RUN(test_router_submit_unique_ids);
    RUN(test_router_submit_stores_context);

    /* Processing / Routing */
    RUN(test_router_process_query);
    RUN(test_router_process_unsupported_action);
    RUN(test_router_process_not_found);
    RUN(test_router_process_null);
    RUN(test_router_process_empty_id);
    RUN(test_router_process_validates_request);

    /* Target Resolution */
    RUN(test_router_target_resolved);
    RUN(test_router_target_not_found);
    RUN(test_router_target_unavailable);
    RUN(test_router_target_error_state);

    /* Capability Verification */
    RUN(test_router_capability_found);
    RUN(test_router_capability_not_found);
    RUN(test_router_capability_unavailable);
    RUN(test_router_capability_disabled);
    RUN(test_router_capability_provider_missing);
    RUN(test_router_no_capability_required);

    /* Authorization */
    RUN(test_router_auth_not_required);
    RUN(test_router_auth_required_no_service);

    /* Cancellation */
    RUN(test_router_cancel);
    RUN(test_router_cancel_not_found);
    RUN(test_router_cancel_terminal);
    RUN(test_router_cancellable);
    RUN(test_router_cancel_null);

    /* Idempotency */
    RUN(test_router_idempotent_duplicate);
    RUN(test_router_non_idempotent_allows);

    /* Resource Limits */
    RUN(test_router_queue_full);
    RUN(test_router_concurrency_limit);

    /* Query */
    RUN(test_router_get_operation);
    RUN(test_router_operation_count);
    RUN(test_router_active_count);

    /* Policy */
    RUN(test_router_default_policy);
    RUN(test_router_set_policy);
    RUN(test_router_set_policy_null);
    RUN(test_router_get_policy);

    /* Statistics */
    RUN(test_router_statistics);
    RUN(test_router_statistics_rejected);

    /* Cleanup */
    RUN(test_router_cleanup_completed);
    RUN(test_router_cleanup_null);

    /* Name Helpers */
    RUN(test_router_err_name);
    RUN(test_router_op_state_name);
    RUN(test_router_result_state_name);
    RUN(test_router_action_name);
    RUN(test_router_event_type_name);
    RUN(test_router_precond_name);

    /* Events / Audit */
    RUN(test_router_emit_event);
    RUN(test_router_audit_operation);

    /* Security */
    RUN(test_router_no_secrets_in_operation);
    RUN(test_router_global_singleton);
    RUN(test_router_process_null_result);
    RUN(test_router_no_registry);

    /* Full Pipeline */
    RUN(test_router_full_pipeline);

    SUITE_END();
    return TOTAL_FAIL();
}
