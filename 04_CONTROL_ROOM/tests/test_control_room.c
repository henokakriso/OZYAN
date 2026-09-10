/*
 * test_control_room.c — Control Room Foundation Tests (Step 01).
 *
 * Comprehensive tests for: lifecycle, state, components, capabilities,
 * control requests, event observation, monitors, policy, audit,
 * resource safety, name helpers, and security boundary verification.
 */

#include "../../tests/test_framework.h"
#include "../control_room.h"
#include "../../03_SECURITY/audit.h"
#include <string.h>
#include <time.h>

/* Event type constants (matching include/events.h values) */
#define TEST_EVENT_NONE              0
#define TEST_EVENT_MODULE_STARTED   17
#define TEST_EVENT_MODULE_STOPPED   18
#define TEST_EVENT_TASK_COMPLETED    9

/* ============================================================
 * TEST HELPERS
 * ============================================================ */

static ozayn_cr_service_t _svc;
static ozayn_audit_service_t _au_svc;

static void _reset_all(void)
{
    memset(&_svc, 0, sizeof(_svc));
    memset(&_au_svc, 0, sizeof(_au_svc));
}

static void _init_svc(void)
{
    _reset_all();
    _au_svc.initialized = 1;

    ozayn_cr_service_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.audit = (void *)&_au_svc;
    ozayn_cr_service_init(&_svc, &cfg);
}

static void _init_svc_no_audit(void)
{
    _reset_all();
    ozayn_cr_service_init(&_svc, NULL);
}

static void _activate_svc(void)
{
    _init_svc();
    /* Init sets lifecycle=INITIALIZING; transition to READY then ACTIVE */
    _svc.lifecycle = OZAYN_CR_LC_READY;
    ozayn_cr_activate(&_svc);
}

/* ============================================================
 * LIFECYCLE TESTS
 * ============================================================ */

TEST(test_cr_init)
{
    _reset_all();
    ozayn_cr_service_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    ozayn_cr_err_t r = ozayn_cr_service_init(&_svc, &cfg);
    ASSERT_EQ(r, OZAYN_CR_OK);
    ASSERT(_svc.initialized == 1);
    ASSERT_EQ(_svc.lifecycle, OZAYN_CR_LC_INITIALIZING);
    ASSERT_EQ(_svc.core_state, OZAYN_CR_CORE_STATE_STARTING);
    ASSERT(_svc.version == 1);
    ASSERT(_svc.start_time > 0);
    ozayn_cr_service_shutdown(&_svc);
    return 0;
}

TEST(test_cr_init_null)
{
    ozayn_cr_err_t r = ozayn_cr_service_init(NULL, NULL);
    ASSERT_EQ(r, OZAYN_CR_ERR_NULL);
    return 0;
}

TEST(test_cr_init_double)
{
    _init_svc();
    ozayn_cr_err_t r = ozayn_cr_service_init(&_svc, NULL);
    ASSERT_EQ(r, OZAYN_CR_ERR_ALREADY_INITIALIZED);
    ozayn_cr_service_shutdown(&_svc);
    return 0;
}

TEST(test_cr_init_with_audit)
{
    _init_svc();
    ASSERT(_svc.audit == &_au_svc);
    ozayn_cr_service_shutdown(&_svc);
    return 0;
}

TEST(test_cr_init_no_audit)
{
    _init_svc_no_audit();
    ASSERT(_svc.audit == NULL);
    ASSERT(_svc.initialized == 1);
    return 0;
}

TEST(test_cr_shutdown)
{
    _init_svc();
    ozayn_cr_service_shutdown(&_svc);
    ASSERT(_svc.initialized == 0);
    ASSERT_EQ(_svc.lifecycle, OZAYN_CR_LC_STOPPED);
    ASSERT_EQ(_svc.core_state, OZAYN_CR_CORE_STATE_OFFLINE);
    return 0;
}

TEST(test_cr_shutdown_null)
{
    ozayn_cr_service_shutdown(NULL);
    return 0;
}

TEST(test_cr_shutdown_before_init)
{
    memset(&_svc, 0, sizeof(_svc));
    ozayn_cr_service_shutdown(&_svc);
    return 0;
}

TEST(test_cr_is_initialized)
{
    _reset_all();
    ASSERT(!ozayn_cr_service_is_initialized(NULL));
    ASSERT(!ozayn_cr_service_is_initialized(&_svc));
    _init_svc();
    ASSERT(ozayn_cr_service_is_initialized(&_svc));
    ozayn_cr_service_shutdown(&_svc);
    ASSERT(!ozayn_cr_service_is_initialized(&_svc));
    return 0;
}

/* ============================================================
 * LIFECYCLE TRANSITION TESTS
 * ============================================================ */

TEST(test_cr_activate)
{
    _init_svc();
    _svc.lifecycle = OZAYN_CR_LC_READY;
    ozayn_cr_err_t r = ozayn_cr_activate(&_svc);
    ASSERT_EQ(r, OZAYN_CR_OK);
    ASSERT_EQ(_svc.lifecycle, OZAYN_CR_LC_ACTIVE);
    ASSERT_EQ(_svc.core_state, OZAYN_CR_CORE_STATE_ONLINE);
    ozayn_cr_service_shutdown(&_svc);
    return 0;
}

TEST(test_cr_activate_null)
{
    ASSERT_EQ(ozayn_cr_activate(NULL), OZAYN_CR_ERR_NULL);
    return 0;
}

TEST(test_cr_activate_not_ready)
{
    _init_svc();
    /* lifecycle is INITIALIZING after init */
    ozayn_cr_err_t r = ozayn_cr_activate(&_svc);
    ASSERT_EQ(r, OZAYN_CR_ERR_STATE_TRANSITION);
    ozayn_cr_service_shutdown(&_svc);
    return 0;
}

TEST(test_cr_deactivate)
{
    _activate_svc();
    ozayn_cr_err_t r = ozayn_cr_deactivate(&_svc);
    ASSERT_EQ(r, OZAYN_CR_OK);
    ASSERT_EQ(_svc.lifecycle, OZAYN_CR_LC_READY);
    ozayn_cr_service_shutdown(&_svc);
    return 0;
}

TEST(test_cr_deactivate_null)
{
    ASSERT_EQ(ozayn_cr_deactivate(NULL), OZAYN_CR_ERR_NULL);
    return 0;
}

TEST(test_cr_deactivate_not_active)
{
    _init_svc();
    ozayn_cr_err_t r = ozayn_cr_deactivate(&_svc);
    ASSERT_EQ(r, OZAYN_CR_ERR_STATE_TRANSITION);
    ozayn_cr_service_shutdown(&_svc);
    return 0;
}

TEST(test_cr_set_error)
{
    _init_svc();
    ozayn_cr_err_t r = ozayn_cr_set_error(&_svc);
    ASSERT_EQ(r, OZAYN_CR_OK);
    ASSERT_EQ(_svc.lifecycle, OZAYN_CR_LC_ERROR);
    ASSERT_EQ(_svc.core_state, OZAYN_CR_CORE_STATE_ERROR);
    ozayn_cr_service_shutdown(&_svc);
    return 0;
}

TEST(test_cr_set_error_null)
{
    ASSERT_EQ(ozayn_cr_set_error(NULL), OZAYN_CR_ERR_NULL);
    return 0;
}

/* ============================================================
 * STATE QUERY TESTS
 * ============================================================ */

TEST(test_cr_get_state)
{
    _init_svc();
    ozayn_cr_state_t state;
    ozayn_cr_err_t r = ozayn_cr_get_state(&_svc, &state);
    ASSERT_EQ(r, OZAYN_CR_OK);
    ASSERT_EQ(state.lifecycle, OZAYN_CR_LC_INITIALIZING);
    ASSERT_EQ(state.core_state, OZAYN_CR_CORE_STATE_STARTING);
    ASSERT(state.version == 1);
    ASSERT(state.start_time > 0);
    ASSERT(state.component_count == 0);
    ASSERT(state.active_requests == 0);
    ASSERT(state.event_count == 0);
    ASSERT(state.capability_count == 0);
    ASSERT(state.safe_status[0] != '\0');
    ozayn_cr_service_shutdown(&_svc);
    return 0;
}

TEST(test_cr_get_state_null)
{
    ASSERT_EQ(ozayn_cr_get_state(NULL, NULL), OZAYN_CR_ERR_NULL);
    return 0;
}

TEST(test_cr_get_state_not_init)
{
    memset(&_svc, 0, sizeof(_svc));
    ozayn_cr_state_t state;
    ASSERT_EQ(ozayn_cr_get_state(&_svc, &state), OZAYN_CR_ERR_NOT_INITIALIZED);
    return 0;
}

TEST(test_cr_get_state_invalid_out)
{
    _init_svc();
    ASSERT_EQ(ozayn_cr_get_state(&_svc, NULL), OZAYN_CR_ERR_INVALID_PARAM);
    ozayn_cr_service_shutdown(&_svc);
    return 0;
}

TEST(test_cr_get_state_reflects_components)
{
    _init_svc();
    ozayn_cr_register_component(&_svc, "CORE-1", OZAYN_CR_COMP_TYPE_CORE,
                                OZAYN_CR_COMP_ACTIVE);
    ozayn_cr_state_t state;
    ozayn_cr_get_state(&_svc, &state);
    ASSERT(state.component_count == 1);
    ozayn_cr_service_shutdown(&_svc);
    return 0;
}

/* ============================================================
 * COMPONENT REGISTRATION TESTS
 * ============================================================ */

TEST(test_cr_register_component)
{
    _init_svc();
    ozayn_cr_err_t r = ozayn_cr_register_component(
        &_svc, "MOD-1", OZAYN_CR_COMP_TYPE_MODULE, OZAYN_CR_COMP_READY);
    ASSERT_EQ(r, OZAYN_CR_OK);
    ASSERT(_svc.component_count == 1);
    ASSERT_STR_EQ(_svc.components[0].component_id, "MOD-1");
    ASSERT_EQ(_svc.components[0].component_type, OZAYN_CR_COMP_TYPE_MODULE);
    ASSERT_EQ(_svc.components[0].state, OZAYN_CR_COMP_READY);
    ASSERT(_svc.components[0].availability == 1);
    ASSERT(_svc.components[0].health == 100);
    ozayn_cr_service_shutdown(&_svc);
    return 0;
}

TEST(test_cr_register_component_null)
{
    ASSERT_EQ(ozayn_cr_register_component(NULL, "X", 0, 0), OZAYN_CR_ERR_NULL);
    return 0;
}

TEST(test_cr_register_component_not_init)
{
    memset(&_svc, 0, sizeof(_svc));
    ASSERT_EQ(ozayn_cr_register_component(&_svc, "X", 0, 0),
              OZAYN_CR_ERR_NOT_INITIALIZED);
    return 0;
}

TEST(test_cr_register_component_empty_id)
{
    _init_svc();
    ozayn_cr_err_t r = ozayn_cr_register_component(
        &_svc, "", OZAYN_CR_COMP_TYPE_MODULE, OZAYN_CR_COMP_READY);
    ASSERT_EQ(r, OZAYN_CR_ERR_INVALID_PARAM);
    ozayn_cr_service_shutdown(&_svc);
    return 0;
}

TEST(test_cr_register_component_duplicate)
{
    _init_svc();
    ozayn_cr_register_component(&_svc, "MOD-1", OZAYN_CR_COMP_TYPE_MODULE,
                                OZAYN_CR_COMP_READY);
    ozayn_cr_err_t r = ozayn_cr_register_component(
        &_svc, "MOD-1", OZAYN_CR_COMP_TYPE_MODULE, OZAYN_CR_COMP_READY);
    ASSERT_EQ(r, OZAYN_CR_ERR_ALREADY_INITIALIZED);
    ozayn_cr_service_shutdown(&_svc);
    return 0;
}

TEST(test_cr_register_component_limit)
{
    _init_svc();
    _svc.policy.max_components = 2;
    ozayn_cr_register_component(&_svc, "C1", OZAYN_CR_COMP_TYPE_CORE,
                                OZAYN_CR_COMP_READY);
    ozayn_cr_register_component(&_svc, "C2", OZAYN_CR_COMP_TYPE_CORE,
                                OZAYN_CR_COMP_READY);
    ozayn_cr_err_t r = ozayn_cr_register_component(
        &_svc, "C3", OZAYN_CR_COMP_TYPE_CORE, OZAYN_CR_COMP_READY);
    ASSERT_EQ(r, OZAYN_CR_ERR_LIMIT_REACHED);
    ozayn_cr_service_shutdown(&_svc);
    return 0;
}

TEST(test_cr_get_component)
{
    _init_svc();
    ozayn_cr_register_component(&_svc, "MOD-1", OZAYN_CR_COMP_TYPE_MODULE,
                                OZAYN_CR_COMP_READY);
    ozayn_cr_monitor_t *m = ozayn_cr_get_component(&_svc, "MOD-1");
    ASSERT_NOT_NULL(m);
    ASSERT_STR_EQ(m->component_id, "MOD-1");
    ASSERT_NULL(ozayn_cr_get_component(&_svc, "NOPE"));
    ozayn_cr_service_shutdown(&_svc);
    return 0;
}

TEST(test_cr_get_component_null)
{
    ASSERT_NULL(ozayn_cr_get_component(NULL, "X"));
    return 0;
}

TEST(test_cr_component_count)
{
    _init_svc();
    ASSERT_EQ(ozayn_cr_component_count(&_svc), 0);
    ozayn_cr_register_component(&_svc, "C1", OZAYN_CR_COMP_TYPE_CORE,
                                OZAYN_CR_COMP_READY);
    ASSERT_EQ(ozayn_cr_component_count(&_svc), 1);
    ozayn_cr_register_component(&_svc, "C2", OZAYN_CR_COMP_TYPE_MODULE,
                                OZAYN_CR_COMP_ACTIVE);
    ASSERT_EQ(ozayn_cr_component_count(&_svc), 2);
    ASSERT_EQ(ozayn_cr_component_count(NULL), 0);
    ozayn_cr_service_shutdown(&_svc);
    return 0;
}

TEST(test_cr_update_component_state)
{
    _init_svc();
    ozayn_cr_register_component(&_svc, "MOD-1", OZAYN_CR_COMP_TYPE_MODULE,
                                OZAYN_CR_COMP_READY);
    ozayn_cr_err_t r = ozayn_cr_update_component_state(
        &_svc, "MOD-1", OZAYN_CR_COMP_ACTIVE);
    ASSERT_EQ(r, OZAYN_CR_OK);
    ozayn_cr_monitor_t *m = ozayn_cr_get_component(&_svc, "MOD-1");
    ASSERT_EQ(m->state, OZAYN_CR_COMP_ACTIVE);
    ozayn_cr_service_shutdown(&_svc);
    return 0;
}

TEST(test_cr_update_component_not_found)
{
    _init_svc();
    ozayn_cr_err_t r = ozayn_cr_update_component_state(
        &_svc, "NOPE", OZAYN_CR_COMP_ACTIVE);
    ASSERT_EQ(r, OZAYN_CR_ERR_NOT_FOUND);
    ozayn_cr_service_shutdown(&_svc);
    return 0;
}

/* ============================================================
 * CAPABILITY REGISTRATION TESTS
 * ============================================================ */

TEST(test_cr_register_capability)
{
    _init_svc();
    ozayn_cr_err_t r = ozayn_cr_register_capability(
        &_svc, OZAYN_CR_CAP_CORE_MONITORING, 1, "Core monitoring active");
    ASSERT_EQ(r, OZAYN_CR_OK);
    ASSERT(_svc.capability_count == 1);
    ASSERT_EQ(_svc.capabilities[0].type, OZAYN_CR_CAP_CORE_MONITORING);
    ASSERT(_svc.capabilities[0].enabled == 1);
    ASSERT(_svc.capabilities[0].available == 1);
    ozayn_cr_service_shutdown(&_svc);
    return 0;
}

TEST(test_cr_register_capability_null)
{
    ASSERT_EQ(ozayn_cr_register_capability(NULL, 0, 0, NULL), OZAYN_CR_ERR_NULL);
    return 0;
}

TEST(test_cr_register_capability_not_init)
{
    memset(&_svc, 0, sizeof(_svc));
    ASSERT_EQ(ozayn_cr_register_capability(&_svc, 0, 0, NULL),
              OZAYN_CR_ERR_NOT_INITIALIZED);
    return 0;
}

TEST(test_cr_register_capability_invalid_type)
{
    _init_svc();
    ozayn_cr_err_t r = ozayn_cr_register_capability(
        &_svc, (ozayn_cr_cap_type_t)999, 1, NULL);
    ASSERT_EQ(r, OZAYN_CR_ERR_CAPABILITY_INVALID);
    ozayn_cr_service_shutdown(&_svc);
    return 0;
}

TEST(test_cr_register_capability_duplicate)
{
    _init_svc();
    ozayn_cr_register_capability(&_svc, OZAYN_CR_CAP_CORE_MONITORING, 1, NULL);
    ozayn_cr_err_t r = ozayn_cr_register_capability(
        &_svc, OZAYN_CR_CAP_CORE_MONITORING, 1, NULL);
    ASSERT_EQ(r, OZAYN_CR_ERR_ALREADY_INITIALIZED);
    ozayn_cr_service_shutdown(&_svc);
    return 0;
}

TEST(test_cr_register_capability_limit)
{
    _init_svc();
    _svc.policy.max_capabilities = 2;
    ozayn_cr_register_capability(&_svc, OZAYN_CR_CAP_CORE_MONITORING, 1, NULL);
    ozayn_cr_register_capability(&_svc, OZAYN_CR_CAP_MODULE_MONITORING, 1, NULL);
    ozayn_cr_err_t r = ozayn_cr_register_capability(
        &_svc, OZAYN_CR_CAP_TASK_MONITORING, 1, NULL);
    ASSERT_EQ(r, OZAYN_CR_ERR_LIMIT_REACHED);
    ozayn_cr_service_shutdown(&_svc);
    return 0;
}

TEST(test_cr_get_capability)
{
    _init_svc();
    ozayn_cr_register_capability(&_svc, OZAYN_CR_CAP_VOICE_INPUT, 1, "Voice");
    ozayn_cr_capability_t *cap = ozayn_cr_get_capability(&_svc,
                                                          OZAYN_CR_CAP_VOICE_INPUT);
    ASSERT_NOT_NULL(cap);
    ASSERT_EQ(cap->type, OZAYN_CR_CAP_VOICE_INPUT);
    ASSERT_NULL(ozayn_cr_get_capability(&_svc, OZAYN_CR_CAP_GESTURE_INPUT));
    ozayn_cr_service_shutdown(&_svc);
    return 0;
}

TEST(test_cr_capability_count)
{
    _init_svc();
    ASSERT_EQ(ozayn_cr_capability_count(&_svc), 0);
    ozayn_cr_register_capability(&_svc, OZAYN_CR_CAP_CORE_MONITORING, 1, NULL);
    ASSERT_EQ(ozayn_cr_capability_count(&_svc), 1);
    ASSERT_EQ(ozayn_cr_capability_count(NULL), 0);
    ozayn_cr_service_shutdown(&_svc);
    return 0;
}

TEST(test_cr_capability_available)
{
    _init_svc();
    ozayn_cr_register_capability(&_svc, OZAYN_CR_CAP_CAMERA_INPUT, 1, NULL);
    ASSERT(ozayn_cr_capability_available(&_svc, OZAYN_CR_CAP_CAMERA_INPUT));
    ASSERT(!ozayn_cr_capability_available(&_svc, OZAYN_CR_CAP_VOICE_INPUT));
    ASSERT(!ozayn_cr_capability_available(NULL, OZAYN_CR_CAP_CAMERA_INPUT));
    ozayn_cr_service_shutdown(&_svc);
    return 0;
}

TEST(test_cr_capability_disabled)
{
    _init_svc();
    ozayn_cr_register_capability(&_svc, OZAYN_CR_CAP_AI_PROCESSING, 0, NULL);
    ASSERT(!ozayn_cr_capability_available(&_svc, OZAYN_CR_CAP_AI_PROCESSING));
    ozayn_cr_service_shutdown(&_svc);
    return 0;
}

/* ============================================================
 * CONTROL REQUEST TESTS
 * ============================================================ */

TEST(test_cr_create_request)
{
    _activate_svc();
    ozayn_cr_register_component(&_svc, "MOD-1", OZAYN_CR_COMP_TYPE_MODULE,
                                OZAYN_CR_COMP_ACTIVE);
    ozayn_cr_request_t *req = NULL;
    ozayn_cr_err_t r = ozayn_cr_create_request(
        &_svc, OZAYN_CR_ACTION_QUERY, "MOD-1", "test context", &req);
    ASSERT_EQ(r, OZAYN_CR_OK);
    ASSERT_NOT_NULL(req);
    ASSERT(req->request_id[0] != '\0');
    ASSERT(req->request_version == 1);
    ASSERT_EQ(req->action, OZAYN_CR_ACTION_QUERY);
    ASSERT_STR_EQ(req->target, "MOD-1");
    ASSERT_STR_EQ(req->context, "test context");
    ASSERT_EQ(req->state, OZAYN_CR_REQ_STATE_CREATED);
    ASSERT_EQ(req->result_state, OZAYN_CR_RESULT_PENDING);
    ASSERT(req->request_time > 0);
    ozayn_cr_service_shutdown(&_svc);
    return 0;
}

TEST(test_cr_create_request_null)
{
    ASSERT_EQ(ozayn_cr_create_request(NULL, 0, "X", NULL, NULL),
              OZAYN_CR_ERR_NULL);
    return 0;
}

TEST(test_cr_create_request_not_init)
{
    memset(&_svc, 0, sizeof(_svc));
    ASSERT_EQ(ozayn_cr_create_request(&_svc, 0, "X", NULL, NULL),
              OZAYN_CR_ERR_NOT_INITIALIZED);
    return 0;
}

TEST(test_cr_create_request_invalid_action)
{
    _init_svc();
    ozayn_cr_err_t r = ozayn_cr_create_request(
        &_svc, (ozayn_cr_action_t)999, "X", NULL, NULL);
    ASSERT_EQ(r, OZAYN_CR_ERR_ACTION_INVALID);
    ozayn_cr_service_shutdown(&_svc);
    return 0;
}

TEST(test_cr_create_request_empty_target)
{
    _init_svc();
    ozayn_cr_err_t r = ozayn_cr_create_request(
        &_svc, OZAYN_CR_ACTION_START, "", NULL, NULL);
    ASSERT_EQ(r, OZAYN_CR_ERR_TARGET_INVALID);
    ozayn_cr_service_shutdown(&_svc);
    return 0;
}

TEST(test_cr_create_request_null_target)
{
    _init_svc();
    ozayn_cr_err_t r = ozayn_cr_create_request(
        &_svc, OZAYN_CR_ACTION_START, NULL, NULL, NULL);
    ASSERT_EQ(r, OZAYN_CR_ERR_TARGET_INVALID);
    ozayn_cr_service_shutdown(&_svc);
    return 0;
}

TEST(test_cr_create_request_policy_rejected)
{
    _init_svc();
    _svc.policy.enabled = 0;
    ozayn_cr_err_t r = ozayn_cr_create_request(
        &_svc, OZAYN_CR_ACTION_START, "MOD-1", NULL, NULL);
    ASSERT_EQ(r, OZAYN_CR_ERR_POLICY_REJECTED);
    ASSERT(_svc.total_requests_rejected == 1);
    ozayn_cr_service_shutdown(&_svc);
    return 0;
}

TEST(test_cr_create_request_no_out)
{
    _activate_svc();
    ozayn_cr_register_component(&_svc, "MOD-1", OZAYN_CR_COMP_TYPE_MODULE,
                                OZAYN_CR_COMP_ACTIVE);
    ozayn_cr_err_t r = ozayn_cr_create_request(
        &_svc, OZAYN_CR_ACTION_QUERY, "MOD-1", NULL, NULL);
    ASSERT_EQ(r, OZAYN_CR_OK);
    ASSERT(_svc.request_count == 1);
    ozayn_cr_service_shutdown(&_svc);
    return 0;
}

TEST(test_cr_get_request)
{
    _activate_svc();
    ozayn_cr_register_component(&_svc, "MOD-1", OZAYN_CR_COMP_TYPE_MODULE,
                                OZAYN_CR_COMP_ACTIVE);
    ozayn_cr_request_t *req = NULL;
    ozayn_cr_create_request(&_svc, OZAYN_CR_ACTION_QUERY, "MOD-1", NULL, &req);
    ozayn_cr_request_t *found = ozayn_cr_get_request(&_svc, req->request_id);
    ASSERT_NOT_NULL(found);
    ASSERT_STR_EQ(found->request_id, req->request_id);
    ASSERT_NULL(ozayn_cr_get_request(&_svc, "NOPE"));
    ASSERT_NULL(ozayn_cr_get_request(NULL, "X"));
    ozayn_cr_service_shutdown(&_svc);
    return 0;
}

TEST(test_cr_request_count)
{
    _activate_svc();
    ozayn_cr_register_component(&_svc, "MOD-1", OZAYN_CR_COMP_TYPE_MODULE,
                                OZAYN_CR_COMP_ACTIVE);
    ASSERT_EQ(ozayn_cr_request_count(&_svc), 0);
    ozayn_cr_create_request(&_svc, OZAYN_CR_ACTION_QUERY, "MOD-1", NULL, NULL);
    ASSERT_EQ(ozayn_cr_request_count(&_svc), 1);
    ASSERT_EQ(ozayn_cr_request_count(NULL), 0);
    ozayn_cr_service_shutdown(&_svc);
    return 0;
}

/* ============================================================
 * CONTROL EXECUTION TESTS
 * ============================================================ */

TEST(test_cr_execute_query)
{
    _activate_svc();
    ozayn_cr_register_component(&_svc, "MOD-1", OZAYN_CR_COMP_TYPE_MODULE,
                                OZAYN_CR_COMP_ACTIVE);
    ozayn_cr_request_t *req = NULL;
    ozayn_cr_create_request(&_svc, OZAYN_CR_ACTION_QUERY, "MOD-1", NULL, &req);
    ozayn_cr_result_t result;
    ozayn_cr_err_t r = ozayn_cr_execute_request(&_svc, req, &result);
    ASSERT_EQ(r, OZAYN_CR_OK);
    ASSERT_EQ(result.result_state, OZAYN_CR_RESULT_SUCCEEDED);
    ASSERT(result.result_code == 0);
    ASSERT(result.completion_time > 0);
    ASSERT_STR_EQ(result.target, "MOD-1");
    ASSERT_EQ(result.action, OZAYN_CR_ACTION_QUERY);
    ASSERT(_svc.total_requests_succeeded == 1);
    ozayn_cr_service_shutdown(&_svc);
    return 0;
}

TEST(test_cr_execute_unsupported_action)
{
    _activate_svc();
    ozayn_cr_register_component(&_svc, "MOD-1", OZAYN_CR_COMP_TYPE_MODULE,
                                OZAYN_CR_COMP_ACTIVE);
    ozayn_cr_request_t *req = NULL;
    ozayn_cr_create_request(&_svc, OZAYN_CR_ACTION_START, "MOD-1", NULL, &req);
    ozayn_cr_result_t result;
    ozayn_cr_err_t r = ozayn_cr_execute_request(&_svc, req, &result);
    ASSERT_EQ(r, OZAYN_CR_OK);
    ASSERT_EQ(result.result_state, OZAYN_CR_RESULT_UNSUPPORTED);
    ASSERT(_svc.total_requests_failed == 1);
    ozayn_cr_service_shutdown(&_svc);
    return 0;
}

TEST(test_cr_execute_null)
{
    _init_svc();
    ozayn_cr_result_t result;
    ASSERT_EQ(ozayn_cr_execute_request(NULL, NULL, &result), OZAYN_CR_ERR_NULL);
    ASSERT_EQ(ozayn_cr_execute_request(&_svc, NULL, &result),
              OZAYN_CR_ERR_REQUEST_INVALID);
    ozayn_cr_service_shutdown(&_svc);
    return 0;
}

TEST(test_cr_execute_null_result)
{
    _activate_svc();
    ozayn_cr_register_component(&_svc, "MOD-1", OZAYN_CR_COMP_TYPE_MODULE,
                                OZAYN_CR_COMP_ACTIVE);
    ozayn_cr_request_t *req = NULL;
    ozayn_cr_create_request(&_svc, OZAYN_CR_ACTION_QUERY, "MOD-1", NULL, &req);
    ASSERT_EQ(ozayn_cr_execute_request(&_svc, req, NULL),
              OZAYN_CR_ERR_INVALID_PARAM);
    ozayn_cr_service_shutdown(&_svc);
    return 0;
}

TEST(test_cr_validate_request)
{
    _activate_svc();
    ozayn_cr_register_component(&_svc, "MOD-1", OZAYN_CR_COMP_TYPE_MODULE,
                                OZAYN_CR_COMP_ACTIVE);
    ozayn_cr_request_t *req = NULL;
    ozayn_cr_create_request(&_svc, OZAYN_CR_ACTION_QUERY, "MOD-1", NULL, &req);
    ozayn_cr_err_t r = ozayn_cr_validate_request(&_svc, req);
    ASSERT_EQ(r, OZAYN_CR_OK);
    ozayn_cr_service_shutdown(&_svc);
    return 0;
}

TEST(test_cr_validate_request_target_not_found)
{
    _activate_svc();
    ozayn_cr_request_t *req = NULL;
    ozayn_cr_create_request(&_svc, OZAYN_CR_ACTION_QUERY, "NOPE", NULL, &req);
    ozayn_cr_err_t r = ozayn_cr_validate_request(&_svc, req);
    ASSERT_EQ(r, OZAYN_CR_ERR_TARGET_NOT_FOUND);
    ozayn_cr_service_shutdown(&_svc);
    return 0;
}

TEST(test_cr_validate_request_null)
{
    _init_svc();
    ASSERT_EQ(ozayn_cr_validate_request(&_svc, NULL), OZAYN_CR_ERR_REQUEST_INVALID);
    ozayn_cr_service_shutdown(&_svc);
    return 0;
}

/* ============================================================
 * EVENT OBSERVATION TESTS
 * ============================================================ */

TEST(test_cr_observe_event)
{
    _init_svc();
    ozayn_cr_err_t r = ozayn_cr_observe_event(
        &_svc, TEST_EVENT_MODULE_STARTED, "MOD-1", "Module started");
    ASSERT_EQ(r, OZAYN_CR_OK);
    ASSERT(_svc.event_count == 1);
    ASSERT(_svc.total_events_observed == 1);
    ASSERT(_svc.events[0].event_type == TEST_EVENT_MODULE_STARTED);
    ASSERT(_svc.events[0].timestamp > 0);
    ozayn_cr_service_shutdown(&_svc);
    return 0;
}

TEST(test_cr_observe_event_null)
{
    ASSERT_EQ(ozayn_cr_observe_event(NULL, 0, NULL, NULL), OZAYN_CR_ERR_NULL);
    return 0;
}

TEST(test_cr_observe_event_not_init)
{
    memset(&_svc, 0, sizeof(_svc));
    ASSERT_EQ(ozayn_cr_observe_event(&_svc, TEST_EVENT_MODULE_STARTED, NULL, NULL),
              OZAYN_CR_ERR_NOT_INITIALIZED);
    return 0;
}

TEST(test_cr_observe_event_invalid)
{
    _init_svc();
    ozayn_cr_err_t r = ozayn_cr_observe_event(
        &_svc, TEST_EVENT_NONE, "SRC", NULL);
    ASSERT_EQ(r, OZAYN_CR_ERR_EVENT_INVALID);
    ozayn_cr_service_shutdown(&_svc);
    return 0;
}

TEST(test_cr_observe_event_policy_rejected)
{
    _init_svc();
    _svc.policy.enabled = 0;
    ozayn_cr_err_t r = ozayn_cr_observe_event(
        &_svc, TEST_EVENT_MODULE_STARTED, NULL, NULL);
    ASSERT_EQ(r, OZAYN_CR_ERR_POLICY_REJECTED);
    ozayn_cr_service_shutdown(&_svc);
    return 0;
}

TEST(test_cr_event_count)
{
    _init_svc();
    ASSERT_EQ(ozayn_cr_event_count(&_svc), 0);
    ozayn_cr_observe_event(&_svc, TEST_EVENT_MODULE_STARTED, NULL, NULL);
    ASSERT_EQ(ozayn_cr_event_count(&_svc), 1);
    ASSERT_EQ(ozayn_cr_event_count(NULL), 0);
    ozayn_cr_service_shutdown(&_svc);
    return 0;
}

TEST(test_cr_observe_multiple_events)
{
    _init_svc();
    ozayn_cr_observe_event(&_svc, TEST_EVENT_MODULE_STARTED, "M1", NULL);
    ozayn_cr_observe_event(&_svc, TEST_EVENT_MODULE_STOPPED, "M2", NULL);
    ozayn_cr_observe_event(&_svc, TEST_EVENT_TASK_COMPLETED, "T1", NULL);
    ASSERT_EQ(_svc.event_count, 3);
    ASSERT(_svc.total_events_observed == 3);
    ozayn_cr_service_shutdown(&_svc);
    return 0;
}

TEST(test_cr_event_ring_buffer_overflow)
{
    _init_svc();
    for (int i = 0; i < OZAYN_CR_MAX_EVENTS + 5; i++) {
        ozayn_cr_observe_event(&_svc, TEST_EVENT_MODULE_STARTED, NULL, NULL);
    }
    ASSERT(_svc.event_count == OZAYN_CR_MAX_EVENTS);
    ozayn_cr_service_shutdown(&_svc);
    return 0;
}

/* ============================================================
 * MONITOR TESTS
 * ============================================================ */

TEST(test_cr_create_monitor)
{
    _init_svc();
    ozayn_cr_monitor_t *mon = NULL;
    ozayn_cr_err_t r = ozayn_cr_create_monitor(
        &_svc, "MOD-1", OZAYN_CR_COMP_TYPE_MODULE, &mon);
    ASSERT_EQ(r, OZAYN_CR_OK);
    ASSERT_NOT_NULL(mon);
    ASSERT_STR_EQ(mon->component_id, "MOD-1");
    ASSERT_EQ(mon->component_type, OZAYN_CR_COMP_TYPE_MODULE);
    ASSERT_EQ(mon->state, OZAYN_CR_COMP_INITIALIZING);
    ASSERT(_svc.monitor_count == 1);
    ozayn_cr_service_shutdown(&_svc);
    return 0;
}

TEST(test_cr_create_monitor_null)
{
    ASSERT_EQ(ozayn_cr_create_monitor(NULL, "X", 0, NULL), OZAYN_CR_ERR_NULL);
    return 0;
}

TEST(test_cr_create_monitor_empty_id)
{
    _init_svc();
    ASSERT_EQ(ozayn_cr_create_monitor(&_svc, "", OZAYN_CR_COMP_TYPE_MODULE, NULL),
              OZAYN_CR_ERR_INVALID_PARAM);
    ozayn_cr_service_shutdown(&_svc);
    return 0;
}

TEST(test_cr_create_monitor_duplicate)
{
    _init_svc();
    ozayn_cr_create_monitor(&_svc, "MOD-1", OZAYN_CR_COMP_TYPE_MODULE, NULL);
    ozayn_cr_err_t r = ozayn_cr_create_monitor(
        &_svc, "MOD-1", OZAYN_CR_COMP_TYPE_MODULE, NULL);
    ASSERT_EQ(r, OZAYN_CR_ERR_ALREADY_INITIALIZED);
    ozayn_cr_service_shutdown(&_svc);
    return 0;
}

TEST(test_cr_create_monitor_limit)
{
    _init_svc();
    _svc.policy.max_monitors = 2;
    ozayn_cr_create_monitor(&_svc, "M1", OZAYN_CR_COMP_TYPE_MODULE, NULL);
    ozayn_cr_create_monitor(&_svc, "M2", OZAYN_CR_COMP_TYPE_MODULE, NULL);
    ozayn_cr_err_t r = ozayn_cr_create_monitor(
        &_svc, "M3", OZAYN_CR_COMP_TYPE_MODULE, NULL);
    ASSERT_EQ(r, OZAYN_CR_ERR_LIMIT_REACHED);
    ozayn_cr_service_shutdown(&_svc);
    return 0;
}

TEST(test_cr_get_monitor)
{
    _init_svc();
    ozayn_cr_create_monitor(&_svc, "MOD-1", OZAYN_CR_COMP_TYPE_MODULE, NULL);
    ozayn_cr_monitor_t *m = ozayn_cr_get_monitor(&_svc, "MOD-1");
    ASSERT_NOT_NULL(m);
    ASSERT_NULL(ozayn_cr_get_monitor(&_svc, "NOPE"));
    ASSERT_NULL(ozayn_cr_get_monitor(NULL, "X"));
    ozayn_cr_service_shutdown(&_svc);
    return 0;
}

TEST(test_cr_monitor_count)
{
    _init_svc();
    ASSERT_EQ(ozayn_cr_monitor_count(&_svc), 0);
    ozayn_cr_create_monitor(&_svc, "M1", OZAYN_CR_COMP_TYPE_MODULE, NULL);
    ASSERT_EQ(ozayn_cr_monitor_count(&_svc), 1);
    ASSERT_EQ(ozayn_cr_monitor_count(NULL), 0);
    ozayn_cr_service_shutdown(&_svc);
    return 0;
}

TEST(test_cr_update_monitor)
{
    _init_svc();
    ozayn_cr_create_monitor(&_svc, "MOD-1", OZAYN_CR_COMP_TYPE_MODULE, NULL);
    ozayn_cr_err_t r = ozayn_cr_update_monitor(
        &_svc, "MOD-1", OZAYN_CR_COMP_ACTIVE, 1, 95);
    ASSERT_EQ(r, OZAYN_CR_OK);
    ozayn_cr_monitor_t *m = ozayn_cr_get_monitor(&_svc, "MOD-1");
    ASSERT_EQ(m->state, OZAYN_CR_COMP_ACTIVE);
    ASSERT(m->availability == 1);
    ASSERT(m->health == 95);
    ozayn_cr_service_shutdown(&_svc);
    return 0;
}

TEST(test_cr_update_monitor_not_found)
{
    _init_svc();
    ozayn_cr_err_t r = ozayn_cr_update_monitor(
        &_svc, "NOPE", OZAYN_CR_COMP_ACTIVE, 1, 100);
    ASSERT_EQ(r, OZAYN_CR_ERR_NOT_FOUND);
    ozayn_cr_service_shutdown(&_svc);
    return 0;
}

/* ============================================================
 * POLICY TESTS
 * ============================================================ */

TEST(test_cr_default_policy)
{
    ozayn_cr_policy_t p = ozayn_cr_default_policy();
    ASSERT(p.enabled == 1);
    ASSERT(p.max_components == OZAYN_CR_MAX_COMPONENTS);
    ASSERT(p.max_capabilities == OZAYN_CR_MAX_CAPABILITIES);
    ASSERT(p.max_requests == OZAYN_CR_MAX_REQUESTS);
    ASSERT(p.max_events == OZAYN_CR_MAX_EVENTS);
    ASSERT(p.max_monitors == OZAYN_CR_MAX_MONITORS);
    ASSERT(p.require_authorization == 0);
    ASSERT(p.require_approval == 0);
    return 0;
}

TEST(test_cr_set_policy)
{
    _init_svc();
    ozayn_cr_policy_t p = ozayn_cr_default_policy();
    p.max_components = 4;
    p.require_authorization = 1;
    ozayn_cr_err_t r = ozayn_cr_set_policy(&_svc, &p);
    ASSERT_EQ(r, OZAYN_CR_OK);
    ASSERT(_svc.policy.max_components == 4);
    ASSERT(_svc.policy.require_authorization == 1);
    ozayn_cr_service_shutdown(&_svc);
    return 0;
}

TEST(test_cr_set_policy_null)
{
    _init_svc();
    ASSERT_EQ(ozayn_cr_set_policy(&_svc, NULL), OZAYN_CR_ERR_INVALID_PARAM);
    ozayn_cr_service_shutdown(&_svc);
    return 0;
}

TEST(test_cr_get_policy)
{
    _init_svc();
    const ozayn_cr_policy_t *p = ozayn_cr_get_policy(&_svc);
    ASSERT_NOT_NULL(p);
    ASSERT(p->enabled == 1);
    ASSERT_NULL(ozayn_cr_get_policy(NULL));
    ozayn_cr_service_shutdown(&_svc);
    return 0;
}

/* ============================================================
 * AUDIT INTEGRATION TESTS
 * ============================================================ */

TEST(test_cr_audit_event)
{
    _init_svc();
    ozayn_cr_err_t r = ozayn_cr_audit_event(&_svc, "TEST", "detail");
    ASSERT_EQ(r, OZAYN_CR_OK);
    ozayn_cr_service_shutdown(&_svc);
    return 0;
}

TEST(test_cr_audit_event_null)
{
    ASSERT_EQ(ozayn_cr_audit_event(NULL, NULL, NULL), OZAYN_CR_ERR_NULL);
    return 0;
}

/* ============================================================
 * RESOURCE SAFETY TESTS
 * ============================================================ */

TEST(test_cr_components_full)
{
    _init_svc();
    ASSERT(!ozayn_cr_components_full(&_svc));
    _svc.policy.max_components = 1;
    ozayn_cr_register_component(&_svc, "C1", OZAYN_CR_COMP_TYPE_CORE,
                                OZAYN_CR_COMP_READY);
    ASSERT(ozayn_cr_components_full(&_svc));
    ASSERT(ozayn_cr_components_full(NULL));
    ozayn_cr_service_shutdown(&_svc);
    return 0;
}

TEST(test_cr_capabilities_full)
{
    _init_svc();
    ASSERT(!ozayn_cr_capabilities_full(&_svc));
    _svc.policy.max_capabilities = 1;
    ozayn_cr_register_capability(&_svc, OZAYN_CR_CAP_CORE_MONITORING, 1, NULL);
    ASSERT(ozayn_cr_capabilities_full(&_svc));
    ozayn_cr_service_shutdown(&_svc);
    return 0;
}

TEST(test_cr_requests_full)
{
    _activate_svc();
    ozayn_cr_register_component(&_svc, "MOD-1", OZAYN_CR_COMP_TYPE_MODULE,
                                OZAYN_CR_COMP_ACTIVE);
    ASSERT(!ozayn_cr_requests_full(&_svc));
    _svc.policy.max_requests = 1;
    ozayn_cr_create_request(&_svc, OZAYN_CR_ACTION_QUERY, "MOD-1", NULL, NULL);
    ASSERT(ozayn_cr_requests_full(&_svc));
    ozayn_cr_service_shutdown(&_svc);
    return 0;
}

TEST(test_cr_events_full)
{
    _init_svc();
    ASSERT(!ozayn_cr_events_full(&_svc));
    _svc.policy.max_events = 1;
    ozayn_cr_observe_event(&_svc, TEST_EVENT_MODULE_STARTED, NULL, NULL);
    ASSERT(ozayn_cr_events_full(&_svc));
    ozayn_cr_service_shutdown(&_svc);
    return 0;
}

/* ============================================================
 * STATISTICS TESTS
 * ============================================================ */

TEST(test_cr_statistics)
{
    _activate_svc();
    ozayn_cr_register_component(&_svc, "MOD-1", OZAYN_CR_COMP_TYPE_MODULE,
                                OZAYN_CR_COMP_ACTIVE);
    ASSERT_EQ(ozayn_cr_total_requests(&_svc), 0);
    ASSERT_EQ(ozayn_cr_total_events(&_svc), 0);
    ozayn_cr_create_request(&_svc, OZAYN_CR_ACTION_QUERY, "MOD-1", NULL, NULL);
    ASSERT_EQ(ozayn_cr_total_requests(&_svc), 1);
    ozayn_cr_observe_event(&_svc, TEST_EVENT_MODULE_STARTED, NULL, NULL);
    ASSERT_EQ(ozayn_cr_total_events(&_svc), 1);
    ASSERT_EQ(ozayn_cr_total_requests(NULL), 0);
    ASSERT_EQ(ozayn_cr_total_events(NULL), 0);
    ozayn_cr_service_shutdown(&_svc);
    return 0;
}

/* ============================================================
 * CLEANUP TESTS
 * ============================================================ */

TEST(test_cr_cleanup_expired_requests)
{
    _activate_svc();
    ozayn_cr_register_component(&_svc, "MOD-1", OZAYN_CR_COMP_TYPE_MODULE,
                                OZAYN_CR_COMP_ACTIVE);
    ozayn_cr_request_t *req = NULL;
    ozayn_cr_create_request(&_svc, OZAYN_CR_ACTION_QUERY, "MOD-1", NULL, &req);
    ozayn_cr_result_t res;
    ozayn_cr_execute_request(&_svc, req, &res);
    /* Simulate old timestamp */
    req->completion_time = time(NULL) - 7200;
    int removed = ozayn_cr_cleanup_expired_requests(&_svc);
    ASSERT(removed >= 1);
    ozayn_cr_service_shutdown(&_svc);
    return 0;
}

TEST(test_cr_cleanup_expired_events)
{
    _init_svc();
    ozayn_cr_observe_event(&_svc, TEST_EVENT_MODULE_STARTED, NULL, NULL);
    /* Simulate old timestamp */
    _svc.events[0].timestamp = time(NULL) - 7200;
    int removed = ozayn_cr_cleanup_expired_events(&_svc);
    ASSERT(removed == 1);
    ASSERT(_svc.event_count == 0);
    ozayn_cr_service_shutdown(&_svc);
    return 0;
}

/* ============================================================
 * NAME HELPER TESTS
 * ============================================================ */

TEST(test_cr_err_name)
{
    ASSERT_STR_EQ(ozayn_cr_err_name(OZAYN_CR_OK), "OK");
    ASSERT_STR_EQ(ozayn_cr_err_name(OZAYN_CR_ERR_NULL), "NULL");
    ASSERT_STR_EQ(ozayn_cr_err_name(OZAYN_CR_ERR_NOT_INITIALIZED), "NOT_INITIALIZED");
    ASSERT_STR_EQ(ozayn_cr_err_name(OZAYN_CR_ERR_ALREADY_INITIALIZED), "ALREADY_INITIALIZED");
    ASSERT_STR_EQ(ozayn_cr_err_name(OZAYN_CR_ERR_INVALID_PARAM), "INVALID_PARAM");
    ASSERT_STR_EQ(ozayn_cr_err_name(OZAYN_CR_ERR_LIMIT_REACHED), "LIMIT_REACHED");
    ASSERT_STR_EQ(ozayn_cr_err_name(OZAYN_CR_ERR_NOT_FOUND), "NOT_FOUND");
    ASSERT_STR_EQ(ozayn_cr_err_name(OZAYN_CR_ERR_STATE_INVALID), "STATE_INVALID");
    ASSERT_STR_EQ(ozayn_cr_err_name(OZAYN_CR_ERR_STATE_TRANSITION), "STATE_TRANSITION");
    ASSERT_STR_EQ(ozayn_cr_err_name(OZAYN_CR_ERR_POLICY_REJECTED), "POLICY_REJECTED");
    ASSERT_STR_EQ(ozayn_cr_err_name((ozayn_cr_err_t)999), "UNKNOWN");
    return 0;
}

TEST(test_cr_lifecycle_name)
{
    ASSERT_STR_EQ(ozayn_cr_lifecycle_name(OZAYN_CR_LC_UNINITIALIZED), "UNINITIALIZED");
    ASSERT_STR_EQ(ozayn_cr_lifecycle_name(OZAYN_CR_LC_INITIALIZING), "INITIALIZING");
    ASSERT_STR_EQ(ozayn_cr_lifecycle_name(OZAYN_CR_LC_READY), "READY");
    ASSERT_STR_EQ(ozayn_cr_lifecycle_name(OZAYN_CR_LC_ACTIVE), "ACTIVE");
    ASSERT_STR_EQ(ozayn_cr_lifecycle_name(OZAYN_CR_LC_STOPPING), "STOPPING");
    ASSERT_STR_EQ(ozayn_cr_lifecycle_name(OZAYN_CR_LC_STOPPED), "STOPPED");
    ASSERT_STR_EQ(ozayn_cr_lifecycle_name(OZAYN_CR_LC_ERROR), "ERROR");
    ASSERT_STR_EQ(ozayn_cr_lifecycle_name((ozayn_cr_lifecycle_t)999), "UNKNOWN");
    return 0;
}

TEST(test_cr_comp_state_name)
{
    ASSERT_STR_EQ(ozayn_cr_comp_state_name(OZAYN_CR_COMP_UNKNOWN), "UNKNOWN");
    ASSERT_STR_EQ(ozayn_cr_comp_state_name(OZAYN_CR_COMP_READY), "READY");
    ASSERT_STR_EQ(ozayn_cr_comp_state_name(OZAYN_CR_COMP_ACTIVE), "ACTIVE");
    ASSERT_STR_EQ(ozayn_cr_comp_state_name(OZAYN_CR_COMP_PAUSED), "PAUSED");
    ASSERT_STR_EQ(ozayn_cr_comp_state_name(OZAYN_CR_COMP_ERROR), "ERROR");
    ASSERT_STR_EQ(ozayn_cr_comp_state_name((ozayn_cr_comp_state_t)999), "UNKNOWN");
    return 0;
}

TEST(test_cr_comp_type_name)
{
    ASSERT_STR_EQ(ozayn_cr_comp_type_name(OZAYN_CR_COMP_TYPE_CORE), "CORE");
    ASSERT_STR_EQ(ozayn_cr_comp_type_name(OZAYN_CR_COMP_TYPE_MODULE), "MODULE");
    ASSERT_STR_EQ(ozayn_cr_comp_type_name(OZAYN_CR_COMP_TYPE_TASK), "TASK");
    ASSERT_STR_EQ(ozayn_cr_comp_type_name(OZAYN_CR_COMP_TYPE_SECURITY), "SECURITY");
    ASSERT_STR_EQ(ozayn_cr_comp_type_name(OZAYN_CR_COMP_TYPE_AI), "AI");
    ASSERT_STR_EQ(ozayn_cr_comp_type_name(OZAYN_CR_COMP_TYPE_ARWE), "ARWE");
    ASSERT_STR_EQ(ozayn_cr_comp_type_name((ozayn_cr_comp_type_t)999), "UNKNOWN");
    return 0;
}

TEST(test_cr_cap_type_name)
{
    ASSERT_STR_EQ(ozayn_cr_cap_type_name(OZAYN_CR_CAP_CORE_MONITORING), "CORE_MONITORING");
    ASSERT_STR_EQ(ozayn_cr_cap_type_name(OZAYN_CR_CAP_VOICE_INPUT), "VOICE_INPUT");
    ASSERT_STR_EQ(ozayn_cr_cap_type_name(OZAYN_CR_CAP_AI_PROCESSING), "AI_PROCESSING");
    ASSERT_STR_EQ(ozayn_cr_cap_type_name(OZAYN_CR_CAP_SECURITY_CONTROL), "SECURITY_CONTROL");
    ASSERT_STR_EQ(ozayn_cr_cap_type_name((ozayn_cr_cap_type_t)999), "UNKNOWN");
    return 0;
}

TEST(test_cr_action_name)
{
    ASSERT_STR_EQ(ozayn_cr_action_name(OZAYN_CR_ACTION_START), "START");
    ASSERT_STR_EQ(ozayn_cr_action_name(OZAYN_CR_ACTION_STOP), "STOP");
    ASSERT_STR_EQ(ozayn_cr_action_name(OZAYN_CR_ACTION_PAUSE), "PAUSE");
    ASSERT_STR_EQ(ozayn_cr_action_name(OZAYN_CR_ACTION_RESUME), "RESUME");
    ASSERT_STR_EQ(ozayn_cr_action_name(OZAYN_CR_ACTION_QUERY), "QUERY");
    ASSERT_STR_EQ(ozayn_cr_action_name(OZAYN_CR_ACTION_RESTART), "RESTART");
    ASSERT_STR_EQ(ozayn_cr_action_name(OZAYN_CR_ACTION_ENABLE), "ENABLE");
    ASSERT_STR_EQ(ozayn_cr_action_name(OZAYN_CR_ACTION_DISABLE), "DISABLE");
    ASSERT_STR_EQ(ozayn_cr_action_name(OZAYN_CR_ACTION_DIAGNOSTIC), "DIAGNOSTIC");
    ASSERT_STR_EQ(ozayn_cr_action_name((ozayn_cr_action_t)999), "UNKNOWN");
    return 0;
}

TEST(test_cr_req_state_name)
{
    ASSERT_STR_EQ(ozayn_cr_req_state_name(OZAYN_CR_REQ_STATE_CREATED), "CREATED");
    ASSERT_STR_EQ(ozayn_cr_req_state_name(OZAYN_CR_REQ_STATE_VALIDATED), "VALIDATED");
    ASSERT_STR_EQ(ozayn_cr_req_state_name(OZAYN_CR_REQ_STATE_SUCCEEDED), "SUCCEEDED");
    ASSERT_STR_EQ(ozayn_cr_req_state_name(OZAYN_CR_REQ_STATE_FAILED), "FAILED");
    ASSERT_STR_EQ(ozayn_cr_req_state_name((ozayn_cr_req_state_t)999), "UNKNOWN");
    return 0;
}

TEST(test_cr_result_state_name)
{
    ASSERT_STR_EQ(ozayn_cr_result_state_name(OZAYN_CR_RESULT_ACCEPTED), "ACCEPTED");
    ASSERT_STR_EQ(ozayn_cr_result_state_name(OZAYN_CR_RESULT_REJECTED), "REJECTED");
    ASSERT_STR_EQ(ozayn_cr_result_state_name(OZAYN_CR_RESULT_SUCCEEDED), "SUCCEEDED");
    ASSERT_STR_EQ(ozayn_cr_result_state_name(OZAYN_CR_RESULT_FAILED), "FAILED");
    ASSERT_STR_EQ(ozayn_cr_result_state_name(OZAYN_CR_RESULT_UNSUPPORTED), "UNSUPPORTED");
    ASSERT_STR_EQ(ozayn_cr_result_state_name((ozayn_cr_result_state_t)999), "UNKNOWN");
    return 0;
}

TEST(test_cr_core_state_name)
{
    ASSERT_STR_EQ(ozayn_cr_core_state_name(OZAYN_CR_CORE_STATE_UNKNOWN), "UNKNOWN");
    ASSERT_STR_EQ(ozayn_cr_core_state_name(OZAYN_CR_CORE_STATE_ONLINE), "ONLINE");
    ASSERT_STR_EQ(ozayn_cr_core_state_name(OZAYN_CR_CORE_STATE_DEGRADED), "DEGRADED");
    ASSERT_STR_EQ(ozayn_cr_core_state_name(OZAYN_CR_CORE_STATE_ERROR), "ERROR");
    ASSERT_STR_EQ(ozayn_cr_core_state_name((ozayn_cr_core_state_t)999), "UNKNOWN");
    return 0;
}

/* ============================================================
 * SECURITY BOUNDARY TESTS
 * ============================================================ */

TEST(test_cr_no_arbitrary_execution)
{
    _init_svc();
    /* Verify no EXECUTE_SHELL, RUN_COMMAND, or bypass exists */
    ASSERT(OZAYN_CR_ACTION_COUNT == 9);
    /* All actions are controlled, bounded operations */
    for (int i = 0; i < OZAYN_CR_ACTION_COUNT; i++) {
        const char *name = ozayn_cr_action_name((ozayn_cr_action_t)i);
        ASSERT(name != NULL);
        ASSERT(strcmp(name, "UNKNOWN") != 0);
        ASSERT(strstr(name, "EXECUTE") == NULL);
        ASSERT(strstr(name, "SHELL") == NULL);
        ASSERT(strstr(name, "BYPASS") == NULL);
        ASSERT(strstr(name, "MASTER") == NULL);
        ASSERT(strstr(name, "UNSAFE") == NULL);
    }
    ozayn_cr_service_shutdown(&_svc);
    return 0;
}

TEST(test_cr_no_secrets_in_state)
{
    _init_svc();
    ozayn_cr_state_t state;
    ozayn_cr_get_state(&_svc, &state);
    /* Verify safe_status contains no sensitive data */
    ASSERT(strstr(state.safe_status, "key") == NULL);
    ASSERT(strstr(state.safe_status, "password") == NULL);
    ASSERT(strstr(state.safe_status, "secret") == NULL);
    ASSERT(strstr(state.safe_status, "credential") == NULL);
    ASSERT(strstr(state.safe_status, "token") == NULL);
    ASSERT(strstr(state.safe_status, "private") == NULL);
    ozayn_cr_service_shutdown(&_svc);
    return 0;
}

TEST(test_cr_no_secrets_in_request)
{
    _activate_svc();
    ozayn_cr_register_component(&_svc, "MOD-1", OZAYN_CR_COMP_TYPE_MODULE,
                                OZAYN_CR_COMP_ACTIVE);
    ozayn_cr_request_t *req = NULL;
    ozayn_cr_create_request(&_svc, OZAYN_CR_ACTION_QUERY, "MOD-1", "context", &req);
    /* Verify no secrets in request fields */
    ASSERT(strstr(req->request_id, "key") == NULL);
    ASSERT(strstr(req->target, "password") == NULL);
    ASSERT(strstr(req->context, "secret") == NULL);
    ASSERT(strstr(req->metadata, "token") == NULL);
    ozayn_cr_service_shutdown(&_svc);
    return 0;
}

TEST(test_cr_no_secrets_in_result)
{
    _activate_svc();
    ozayn_cr_register_component(&_svc, "MOD-1", OZAYN_CR_COMP_TYPE_MODULE,
                                OZAYN_CR_COMP_ACTIVE);
    ozayn_cr_request_t *req = NULL;
    ozayn_cr_create_request(&_svc, OZAYN_CR_ACTION_QUERY, "MOD-1", NULL, &req);
    ozayn_cr_result_t result;
    ozayn_cr_execute_request(&_svc, req, &result);
    /* Verify no secrets in result */
    ASSERT(strstr(result.request_id, "key") == NULL);
    ASSERT(strstr(result.target, "password") == NULL);
    ASSERT(strstr(result.safe_metadata, "secret") == NULL);
    ozayn_cr_service_shutdown(&_svc);
    return 0;
}

TEST(test_cr_global_singleton)
{
    ozayn_cr_service_t *g1 = ozayn_cr_get_global();
    ozayn_cr_service_t *g2 = ozayn_cr_get_global();
    ASSERT_NOT_NULL(g1);
    ASSERT(g1 == g2);
    return 0;
}

/* ============================================================
 * TEST RUNNER
 * ============================================================ */

int run_control_room_tests(void)
{
    SUITE_BEGIN("Control Room Foundation");

    /* Lifecycle */
    RUN(test_cr_init);
    RUN(test_cr_init_null);
    RUN(test_cr_init_double);
    RUN(test_cr_init_with_audit);
    RUN(test_cr_init_no_audit);
    RUN(test_cr_shutdown);
    RUN(test_cr_shutdown_null);
    RUN(test_cr_shutdown_before_init);
    RUN(test_cr_is_initialized);

    /* Lifecycle transitions */
    RUN(test_cr_activate);
    RUN(test_cr_activate_null);
    RUN(test_cr_activate_not_ready);
    RUN(test_cr_deactivate);
    RUN(test_cr_deactivate_null);
    RUN(test_cr_deactivate_not_active);
    RUN(test_cr_set_error);
    RUN(test_cr_set_error_null);

    /* State query */
    RUN(test_cr_get_state);
    RUN(test_cr_get_state_null);
    RUN(test_cr_get_state_not_init);
    RUN(test_cr_get_state_invalid_out);
    RUN(test_cr_get_state_reflects_components);

    /* Component registration */
    RUN(test_cr_register_component);
    RUN(test_cr_register_component_null);
    RUN(test_cr_register_component_not_init);
    RUN(test_cr_register_component_empty_id);
    RUN(test_cr_register_component_duplicate);
    RUN(test_cr_register_component_limit);
    RUN(test_cr_get_component);
    RUN(test_cr_get_component_null);
    RUN(test_cr_component_count);
    RUN(test_cr_update_component_state);
    RUN(test_cr_update_component_not_found);

    /* Capability registration */
    RUN(test_cr_register_capability);
    RUN(test_cr_register_capability_null);
    RUN(test_cr_register_capability_not_init);
    RUN(test_cr_register_capability_invalid_type);
    RUN(test_cr_register_capability_duplicate);
    RUN(test_cr_register_capability_limit);
    RUN(test_cr_get_capability);
    RUN(test_cr_capability_count);
    RUN(test_cr_capability_available);
    RUN(test_cr_capability_disabled);

    /* Control requests */
    RUN(test_cr_create_request);
    RUN(test_cr_create_request_null);
    RUN(test_cr_create_request_not_init);
    RUN(test_cr_create_request_invalid_action);
    RUN(test_cr_create_request_empty_target);
    RUN(test_cr_create_request_null_target);
    RUN(test_cr_create_request_policy_rejected);
    RUN(test_cr_create_request_no_out);
    RUN(test_cr_get_request);
    RUN(test_cr_request_count);

    /* Control execution */
    RUN(test_cr_execute_query);
    RUN(test_cr_execute_unsupported_action);
    RUN(test_cr_execute_null);
    RUN(test_cr_execute_null_result);
    RUN(test_cr_validate_request);
    RUN(test_cr_validate_request_target_not_found);
    RUN(test_cr_validate_request_null);

    /* Event observation */
    RUN(test_cr_observe_event);
    RUN(test_cr_observe_event_null);
    RUN(test_cr_observe_event_not_init);
    RUN(test_cr_observe_event_invalid);
    RUN(test_cr_observe_event_policy_rejected);
    RUN(test_cr_event_count);
    RUN(test_cr_observe_multiple_events);
    RUN(test_cr_event_ring_buffer_overflow);

    /* Monitors */
    RUN(test_cr_create_monitor);
    RUN(test_cr_create_monitor_null);
    RUN(test_cr_create_monitor_empty_id);
    RUN(test_cr_create_monitor_duplicate);
    RUN(test_cr_create_monitor_limit);
    RUN(test_cr_get_monitor);
    RUN(test_cr_monitor_count);
    RUN(test_cr_update_monitor);
    RUN(test_cr_update_monitor_not_found);

    /* Policy */
    RUN(test_cr_default_policy);
    RUN(test_cr_set_policy);
    RUN(test_cr_set_policy_null);
    RUN(test_cr_get_policy);

    /* Audit */
    RUN(test_cr_audit_event);
    RUN(test_cr_audit_event_null);

    /* Resource safety */
    RUN(test_cr_components_full);
    RUN(test_cr_capabilities_full);
    RUN(test_cr_requests_full);
    RUN(test_cr_events_full);

    /* Statistics */
    RUN(test_cr_statistics);

    /* Cleanup */
    RUN(test_cr_cleanup_expired_requests);
    RUN(test_cr_cleanup_expired_events);

    /* Name helpers */
    RUN(test_cr_err_name);
    RUN(test_cr_lifecycle_name);
    RUN(test_cr_comp_state_name);
    RUN(test_cr_comp_type_name);
    RUN(test_cr_cap_type_name);
    RUN(test_cr_action_name);
    RUN(test_cr_req_state_name);
    RUN(test_cr_result_state_name);
    RUN(test_cr_core_state_name);

    /* Security boundary */
    RUN(test_cr_no_arbitrary_execution);
    RUN(test_cr_no_secrets_in_state);
    RUN(test_cr_no_secrets_in_request);
    RUN(test_cr_no_secrets_in_result);
    RUN(test_cr_global_singleton);

    SUITE_END();
    return TOTAL_FAIL();
}
