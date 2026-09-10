/*
 * test_component_registry.c — Component Registry & Capability Discovery Tests (Step 03).
 *
 * Comprehensive tests for: lifecycle, component registration/unregistration,
 * component state management, capability registration/unregistration,
 * capability state management, dependencies, permissions, queries,
 * discovery, stale data, snapshots, events, policy, security boundaries.
 */

#include "../../tests/test_framework.h"
#include "../component_registry.h"
#include "../../03_SECURITY/audit.h"
#include <string.h>
#include <time.h>

/* ============================================================
 * TEST HELPERS
 * ============================================================ */

static ozayn_reg_service_t _svc;
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

    ozayn_reg_service_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.audit = (void *)&_au_svc;
    ozayn_reg_service_init(&_svc, &cfg);
}

/* ============================================================
 * LIFECYCLE TESTS
 * ============================================================ */

TEST(test_reg_init)
{
    _reset_all();
    ozayn_reg_service_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    ozayn_reg_err_t r = ozayn_reg_service_init(&_svc, &cfg);
    ASSERT_EQ(r, OZAYN_REG_OK);
    ASSERT(_svc.initialized == 1);
    ASSERT(_svc.component_count == 0);
    ASSERT(_svc.capability_count == 0);
    ozayn_reg_service_shutdown(&_svc);
    return 0;
}

TEST(test_reg_init_null)
{
    ASSERT_EQ(ozayn_reg_service_init(NULL, NULL), OZAYN_REG_ERR_NULL);
    return 0;
}

TEST(test_reg_init_double)
{
    _init_svc();
    ASSERT_EQ(ozayn_reg_service_init(&_svc, NULL), OZAYN_REG_ERR_ALREADY_INITIALIZED);
    ozayn_reg_service_shutdown(&_svc);
    return 0;
}

TEST(test_reg_shutdown)
{
    _init_svc();
    ozayn_reg_service_shutdown(&_svc);
    ASSERT(_svc.initialized == 0);
    return 0;
}

TEST(test_reg_shutdown_null)
{
    ozayn_reg_service_shutdown(NULL);
    return 0;
}

TEST(test_reg_is_initialized)
{
    _reset_all();
    ASSERT(!ozayn_reg_service_is_initialized(NULL));
    ASSERT(!ozayn_reg_service_is_initialized(&_svc));
    _init_svc();
    ASSERT(ozayn_reg_service_is_initialized(&_svc));
    ozayn_reg_service_shutdown(&_svc);
    ASSERT(!ozayn_reg_service_is_initialized(&_svc));
    return 0;
}

/* ============================================================
 * COMPONENT REGISTRATION TESTS
 * ============================================================ */

TEST(test_reg_register_component)
{
    _init_svc();
    ozayn_reg_err_t r = ozayn_reg_register_component(
        &_svc, "CORE-1", "Core System", "1.0.0",
        OZAYN_REG_COMP_TYPE_CORE, "OZAYN", NULL);
    ASSERT_EQ(r, OZAYN_REG_OK);
    ASSERT_EQ(_svc.component_count, 1);
    ASSERT_STR_EQ(_svc.components[0].component_id, "CORE-1");
    ASSERT_STR_EQ(_svc.components[0].name, "Core System");
    ASSERT_STR_EQ(_svc.components[0].version, "1.0.0");
    ASSERT_EQ(_svc.components[0].type, OZAYN_REG_COMP_TYPE_CORE);
    ASSERT_STR_EQ(_svc.components[0].provider, "OZAYN");
    ASSERT_EQ(_svc.components[0].state, OZAYN_REG_COMP_INITIALIZING);
    ASSERT_EQ(_svc.components[0].availability, OZAYN_REG_AVAIL_UNKNOWN);
    ASSERT_EQ(_svc.components[0].health, OZAYN_REG_HEALTH_UNKNOWN);
    ASSERT(_svc.components[0].active == 1);
    ASSERT(_svc.total_registrations == 1);
    ozayn_reg_service_shutdown(&_svc);
    return 0;
}

TEST(test_reg_register_component_null)
{
    ASSERT_EQ(ozayn_reg_register_component(NULL, "X", "X", "1", 0, "P", NULL),
              OZAYN_REG_ERR_NULL);
    return 0;
}

TEST(test_reg_register_component_not_init)
{
    memset(&_svc, 0, sizeof(_svc));
    ASSERT_EQ(ozayn_reg_register_component(&_svc, "X", "X", "1", 0, "P", NULL),
              OZAYN_REG_ERR_NOT_INITIALIZED);
    return 0;
}

TEST(test_reg_register_component_empty_id)
{
    _init_svc();
    ASSERT_EQ(ozayn_reg_register_component(&_svc, "", "X", "1", 0, "P", NULL),
              OZAYN_REG_ERR_INVALID_PARAM);
    ozayn_reg_service_shutdown(&_svc);
    return 0;
}

TEST(test_reg_register_component_empty_name)
{
    _init_svc();
    ASSERT_EQ(ozayn_reg_register_component(&_svc, "X", "", "1", 0, "P", NULL),
              OZAYN_REG_ERR_INVALID_PARAM);
    ozayn_reg_service_shutdown(&_svc);
    return 0;
}

TEST(test_reg_register_component_duplicate)
{
    _init_svc();
    ozayn_reg_register_component(&_svc, "C1", "Comp1", "1.0", 0, "P", NULL);
    ASSERT_EQ(ozayn_reg_register_component(&_svc, "C1", "Comp1", "1.0", 0, "P", NULL),
              OZAYN_REG_ERR_COMPONENT_EXISTS);
    ozayn_reg_service_shutdown(&_svc);
    return 0;
}

TEST(test_reg_register_component_limit)
{
    _init_svc();
    _svc.policy.max_components = 2;
    ozayn_reg_register_component(&_svc, "C1", "C1", "1", 0, "P", NULL);
    ozayn_reg_register_component(&_svc, "C2", "C2", "1", 0, "P", NULL);
    ASSERT_EQ(ozayn_reg_register_component(&_svc, "C3", "C3", "1", 0, "P", NULL),
              OZAYN_REG_ERR_LIMIT_REACHED);
    ozayn_reg_service_shutdown(&_svc);
    return 0;
}

TEST(test_reg_register_component_no_provider)
{
    _init_svc();
    _svc.policy.require_provider = 1;
    ASSERT_EQ(ozayn_reg_register_component(&_svc, "C1", "C1", "1", 0, NULL, NULL),
              OZAYN_REG_ERR_CAPABILITY_PROVIDER_MISSING);
    ASSERT_EQ(ozayn_reg_register_component(&_svc, "C1", "C1", "1", 0, "", NULL),
              OZAYN_REG_ERR_CAPABILITY_PROVIDER_MISSING);
    ozayn_reg_service_shutdown(&_svc);
    return 0;
}

TEST(test_reg_unregister_component)
{
    _init_svc();
    ozayn_reg_register_component(&_svc, "C1", "C1", "1", 0, "P", NULL);
    ASSERT_EQ(_svc.component_count, 1);
    ASSERT_EQ(ozayn_reg_unregister_component(&_svc, "C1"), OZAYN_REG_OK);
    ASSERT_EQ(_svc.component_count, 0);
    ASSERT(_svc.total_unregistrations == 1);
    ozayn_reg_service_shutdown(&_svc);
    return 0;
}

TEST(test_reg_unregister_component_not_found)
{
    _init_svc();
    ASSERT_EQ(ozayn_reg_unregister_component(&_svc, "NOPE"),
              OZAYN_REG_ERR_COMPONENT_NOT_FOUND);
    ozayn_reg_service_shutdown(&_svc);
    return 0;
}

TEST(test_reg_unregister_component_null)
{
    ASSERT_EQ(ozayn_reg_unregister_component(NULL, "X"), OZAYN_REG_ERR_NULL);
    return 0;
}

TEST(test_reg_unregister_component_removes_capabilities)
{
    _init_svc();
    ozayn_reg_register_component(&_svc, "PROV", "Provider", "1", 0, "P", NULL);
    ozayn_reg_register_capability(&_svc, "CAP1", "Cap1", "1", "desc", "PROV", 0, 0, NULL);
    ozayn_reg_register_capability(&_svc, "CAP2", "Cap2", "1", "desc", "PROV", 0, 0, NULL);
    ASSERT_EQ(_svc.capability_count, 2);
    ASSERT_EQ(ozayn_reg_unregister_component(&_svc, "PROV"), OZAYN_REG_OK);
    ASSERT_EQ(_svc.component_count, 0);
    ASSERT_EQ(_svc.capability_count, 0);
    ozayn_reg_service_shutdown(&_svc);
    return 0;
}

TEST(test_reg_get_component)
{
    _init_svc();
    ozayn_reg_register_component(&_svc, "C1", "Comp1", "1.0", 0, "P", NULL);
    ozayn_reg_component_t *comp = ozayn_reg_get_component(&_svc, "C1");
    ASSERT_NOT_NULL(comp);
    ASSERT_STR_EQ(comp->component_id, "C1");
    ASSERT_NULL(ozayn_reg_get_component(&_svc, "NOPE"));
    ASSERT_NULL(ozayn_reg_get_component(NULL, "X"));
    ozayn_reg_service_shutdown(&_svc);
    return 0;
}

TEST(test_reg_component_count)
{
    _init_svc();
    ASSERT_EQ(ozayn_reg_component_count(&_svc), 0);
    ozayn_reg_register_component(&_svc, "C1", "C1", "1", 0, "P", NULL);
    ASSERT_EQ(ozayn_reg_component_count(&_svc), 1);
    ASSERT_EQ(ozayn_reg_component_count(NULL), 0);
    ozayn_reg_service_shutdown(&_svc);
    return 0;
}

TEST(test_reg_component_exists)
{
    _init_svc();
    ASSERT(!ozayn_reg_component_exists(&_svc, "C1"));
    ozayn_reg_register_component(&_svc, "C1", "C1", "1", 0, "P", NULL);
    ASSERT(ozayn_reg_component_exists(&_svc, "C1"));
    ASSERT(!ozayn_reg_component_exists(&_svc, "C2"));
    ASSERT(!ozayn_reg_component_exists(NULL, "X"));
    ozayn_reg_service_shutdown(&_svc);
    return 0;
}

/* ============================================================
 * COMPONENT STATE MANAGEMENT TESTS
 * ============================================================ */

TEST(test_reg_update_component_state)
{
    _init_svc();
    ozayn_reg_register_component(&_svc, "C1", "C1", "1", 0, "P", NULL);
    ASSERT_EQ(ozayn_reg_update_component_state(&_svc, "C1", OZAYN_REG_COMP_ACTIVE),
              OZAYN_REG_OK);
    ASSERT_EQ(_svc.components[0].state, OZAYN_REG_COMP_ACTIVE);
    ozayn_reg_service_shutdown(&_svc);
    return 0;
}

TEST(test_reg_update_component_state_not_found)
{
    _init_svc();
    ASSERT_EQ(ozayn_reg_update_component_state(&_svc, "NOPE", OZAYN_REG_COMP_ACTIVE),
              OZAYN_REG_ERR_COMPONENT_NOT_FOUND);
    ozayn_reg_service_shutdown(&_svc);
    return 0;
}

TEST(test_reg_update_component_availability)
{
    _init_svc();
    ozayn_reg_register_component(&_svc, "C1", "C1", "1", 0, "P", NULL);
    ASSERT_EQ(ozayn_reg_update_component_availability(&_svc, "C1", OZAYN_REG_AVAIL_AVAILABLE),
              OZAYN_REG_OK);
    ASSERT_EQ(_svc.components[0].availability, OZAYN_REG_AVAIL_AVAILABLE);
    ozayn_reg_service_shutdown(&_svc);
    return 0;
}

TEST(test_reg_update_component_health)
{
    _init_svc();
    ozayn_reg_register_component(&_svc, "C1", "C1", "1", 0, "P", NULL);
    ASSERT_EQ(ozayn_reg_update_component_health(&_svc, "C1", OZAYN_REG_HEALTH_HEALTHY),
              OZAYN_REG_OK);
    ASSERT_EQ(_svc.components[0].health, OZAYN_REG_HEALTH_HEALTHY);
    ozayn_reg_service_shutdown(&_svc);
    return 0;
}

/* ============================================================
 * COMPONENT QUERIES TESTS
 * ============================================================ */

TEST(test_reg_list_components)
{
    _init_svc();
    ozayn_reg_register_component(&_svc, "C1", "C1", "1", OZAYN_REG_COMP_TYPE_CORE, "P", NULL);
    ozayn_reg_register_component(&_svc, "C2", "C2", "1", OZAYN_REG_COMP_TYPE_MODULE, "P", NULL);
    ozayn_reg_component_t *list[8];
    int n = ozayn_reg_list_components(&_svc, list, 8);
    ASSERT_EQ(n, 2);
    ozayn_reg_service_shutdown(&_svc);
    return 0;
}

TEST(test_reg_list_components_by_type)
{
    _init_svc();
    ozayn_reg_register_component(&_svc, "C1", "C1", "1", OZAYN_REG_COMP_TYPE_CORE, "P", NULL);
    ozayn_reg_register_component(&_svc, "C2", "C2", "1", OZAYN_REG_COMP_TYPE_CORE, "P", NULL);
    ozayn_reg_register_component(&_svc, "C3", "C3", "1", OZAYN_REG_COMP_TYPE_MODULE, "P", NULL);
    ozayn_reg_component_t *list[8];
    int n = ozayn_reg_list_components_by_type(&_svc, OZAYN_REG_COMP_TYPE_CORE, list, 8);
    ASSERT_EQ(n, 2);
    n = ozayn_reg_list_components_by_type(&_svc, OZAYN_REG_COMP_TYPE_MODULE, list, 8);
    ASSERT_EQ(n, 1);
    ozayn_reg_service_shutdown(&_svc);
    return 0;
}

TEST(test_reg_list_active_components)
{
    _init_svc();
    ozayn_reg_register_component(&_svc, "C1", "C1", "1", 0, "P", NULL);
    ozayn_reg_register_component(&_svc, "C2", "C2", "1", 0, "P", NULL);
    ozayn_reg_update_component_state(&_svc, "C1", OZAYN_REG_COMP_ACTIVE);
    ozayn_reg_component_t *list[8];
    int n = ozayn_reg_list_active_components(&_svc, list, 8);
    ASSERT_EQ(n, 1);
    ozayn_reg_service_shutdown(&_svc);
    return 0;
}

TEST(test_reg_list_available_components)
{
    _init_svc();
    ozayn_reg_register_component(&_svc, "C1", "C1", "1", 0, "P", NULL);
    ozayn_reg_register_component(&_svc, "C2", "C2", "1", 0, "P", NULL);
    ozayn_reg_update_component_availability(&_svc, "C1", OZAYN_REG_AVAIL_AVAILABLE);
    ozayn_reg_component_t *list[8];
    int n = ozayn_reg_list_available_components(&_svc, list, 8);
    ASSERT_EQ(n, 1);
    ozayn_reg_service_shutdown(&_svc);
    return 0;
}

TEST(test_reg_list_unavailable_components)
{
    _init_svc();
    ozayn_reg_register_component(&_svc, "C1", "C1", "1", 0, "P", NULL);
    ozayn_reg_update_component_availability(&_svc, "C1", OZAYN_REG_AVAIL_UNAVAILABLE);
    ozayn_reg_component_t *list[8];
    int n = ozayn_reg_list_unavailable_components(&_svc, list, 8);
    ASSERT_EQ(n, 1);
    ozayn_reg_service_shutdown(&_svc);
    return 0;
}

/* ============================================================
 * CAPABILITY REGISTRATION TESTS
 * ============================================================ */

TEST(test_reg_register_capability)
{
    _init_svc();
    ozayn_reg_register_component(&_svc, "PROV", "Provider", "1", 0, "P", NULL);
    ozayn_reg_err_t r = ozayn_reg_register_capability(
        &_svc, "CAP1", "Camera", "1.0", "Camera input", "PROV",
        OZAYN_REG_CAP_CAT_DEVICE, OZAYN_REG_ASSURANCE_PUBLIC, NULL);
    ASSERT_EQ(r, OZAYN_REG_OK);
    ASSERT_EQ(_svc.capability_count, 1);
    ASSERT_STR_EQ(_svc.capabilities[0].cap_id, "CAP1");
    ASSERT_STR_EQ(_svc.capabilities[0].name, "Camera");
    ASSERT_STR_EQ(_svc.capabilities[0].provider_component, "PROV");
    ASSERT_EQ(_svc.capabilities[0].state, OZAYN_REG_CAP_STATE_AVAILABLE);
    ASSERT(_svc.total_cap_registrations == 1);
    ozayn_reg_service_shutdown(&_svc);
    return 0;
}

TEST(test_reg_register_capability_null)
{
    ASSERT_EQ(ozayn_reg_register_capability(NULL, "X", "X", "1", "d", "P", 0, 0, NULL),
              OZAYN_REG_ERR_NULL);
    return 0;
}

TEST(test_reg_register_capability_empty_id)
{
    _init_svc();
    ASSERT_EQ(ozayn_reg_register_capability(&_svc, "", "X", "1", "d", "P", 0, 0, NULL),
              OZAYN_REG_ERR_INVALID_PARAM);
    ozayn_reg_service_shutdown(&_svc);
    return 0;
}

TEST(test_reg_register_capability_no_provider)
{
    _init_svc();
    ASSERT_EQ(ozayn_reg_register_capability(&_svc, "C1", "C1", "1", "d", "", 0, 0, NULL),
              OZAYN_REG_ERR_CAPABILITY_PROVIDER_MISSING);
    ASSERT_EQ(ozayn_reg_register_capability(&_svc, "C1", "C1", "1", "d", NULL, 0, 0, NULL),
              OZAYN_REG_ERR_CAPABILITY_PROVIDER_MISSING);
    ozayn_reg_service_shutdown(&_svc);
    return 0;
}

TEST(test_reg_register_capability_provider_not_registered)
{
    _init_svc();
    ASSERT_EQ(ozayn_reg_register_capability(&_svc, "C1", "C1", "1", "d", "NOPE", 0, 0, NULL),
              OZAYN_REG_ERR_CAPABILITY_PROVIDER_MISSING);
    ozayn_reg_service_shutdown(&_svc);
    return 0;
}

TEST(test_reg_register_capability_duplicate)
{
    _init_svc();
    ozayn_reg_register_component(&_svc, "P", "P", "1", 0, "P", NULL);
    ozayn_reg_register_capability(&_svc, "C1", "C1", "1", "d", "P", 0, 0, NULL);
    ASSERT_EQ(ozayn_reg_register_capability(&_svc, "C1", "C1", "1", "d", "P", 0, 0, NULL),
              OZAYN_REG_ERR_CAPABILITY_EXISTS);
    ozayn_reg_service_shutdown(&_svc);
    return 0;
}

TEST(test_reg_register_capability_limit)
{
    _init_svc();
    ozayn_reg_register_component(&_svc, "P", "P", "1", 0, "P", NULL);
    _svc.policy.max_capabilities = 2;
    ozayn_reg_register_capability(&_svc, "C1", "C1", "1", "d", "P", 0, 0, NULL);
    ozayn_reg_register_capability(&_svc, "C2", "C2", "1", "d", "P", 0, 0, NULL);
    ASSERT_EQ(ozayn_reg_register_capability(&_svc, "C3", "C3", "1", "d", "P", 0, 0, NULL),
              OZAYN_REG_ERR_LIMIT_REACHED);
    ozayn_reg_service_shutdown(&_svc);
    return 0;
}

TEST(test_reg_unregister_capability)
{
    _init_svc();
    ozayn_reg_register_component(&_svc, "P", "P", "1", 0, "P", NULL);
    ozayn_reg_register_capability(&_svc, "C1", "C1", "1", "d", "P", 0, 0, NULL);
    ASSERT_EQ(_svc.capability_count, 1);
    ASSERT_EQ(ozayn_reg_unregister_capability(&_svc, "C1"), OZAYN_REG_OK);
    ASSERT_EQ(_svc.capability_count, 0);
    ozayn_reg_service_shutdown(&_svc);
    return 0;
}

TEST(test_reg_unregister_capability_not_found)
{
    _init_svc();
    ASSERT_EQ(ozayn_reg_unregister_capability(&_svc, "NOPE"),
              OZAYN_REG_ERR_CAPABILITY_NOT_FOUND);
    ozayn_reg_service_shutdown(&_svc);
    return 0;
}

TEST(test_reg_get_capability)
{
    _init_svc();
    ozayn_reg_register_component(&_svc, "P", "P", "1", 0, "P", NULL);
    ozayn_reg_register_capability(&_svc, "C1", "C1", "1", "d", "P", 0, 0, NULL);
    ozayn_reg_capability_desc_t *cap = ozayn_reg_get_capability(&_svc, "C1");
    ASSERT_NOT_NULL(cap);
    ASSERT_STR_EQ(cap->cap_id, "C1");
    ASSERT_NULL(ozayn_reg_get_capability(&_svc, "NOPE"));
    ASSERT_NULL(ozayn_reg_get_capability(NULL, "X"));
    ozayn_reg_service_shutdown(&_svc);
    return 0;
}

TEST(test_reg_capability_count)
{
    _init_svc();
    ASSERT_EQ(ozayn_reg_capability_count(&_svc), 0);
    ozayn_reg_register_component(&_svc, "P", "P", "1", 0, "P", NULL);
    ozayn_reg_register_capability(&_svc, "C1", "C1", "1", "d", "P", 0, 0, NULL);
    ASSERT_EQ(ozayn_reg_capability_count(&_svc), 1);
    ASSERT_EQ(ozayn_reg_capability_count(NULL), 0);
    ozayn_reg_service_shutdown(&_svc);
    return 0;
}

TEST(test_reg_capability_exists)
{
    _init_svc();
    ASSERT(!ozayn_reg_capability_exists(&_svc, "C1"));
    ozayn_reg_register_component(&_svc, "P", "P", "1", 0, "P", NULL);
    ozayn_reg_register_capability(&_svc, "C1", "C1", "1", "d", "P", 0, 0, NULL);
    ASSERT(ozayn_reg_capability_exists(&_svc, "C1"));
    ASSERT(!ozayn_reg_capability_exists(&_svc, "C2"));
    ozayn_reg_service_shutdown(&_svc);
    return 0;
}

/* ============================================================
 * CAPABILITY STATE MANAGEMENT TESTS
 * ============================================================ */

TEST(test_reg_update_capability_state)
{
    _init_svc();
    ozayn_reg_register_component(&_svc, "P", "P", "1", 0, "P", NULL);
    ozayn_reg_register_capability(&_svc, "C1", "C1", "1", "d", "P", 0, 0, NULL);
    ASSERT_EQ(ozayn_reg_update_capability_state(&_svc, "C1", OZAYN_REG_CAP_STATE_ACTIVE),
              OZAYN_REG_OK);
    ASSERT_EQ(_svc.capabilities[0].state, OZAYN_REG_CAP_STATE_ACTIVE);
    ozayn_reg_service_shutdown(&_svc);
    return 0;
}

TEST(test_reg_update_capability_state_not_found)
{
    _init_svc();
    ASSERT_EQ(ozayn_reg_update_capability_state(&_svc, "NOPE", OZAYN_REG_CAP_STATE_ACTIVE),
              OZAYN_REG_ERR_CAPABILITY_NOT_FOUND);
    ozayn_reg_service_shutdown(&_svc);
    return 0;
}

TEST(test_reg_update_capability_availability)
{
    _init_svc();
    ozayn_reg_register_component(&_svc, "P", "P", "1", 0, "P", NULL);
    ozayn_reg_register_capability(&_svc, "C1", "C1", "1", "d", "P", 0, 0, NULL);
    ASSERT_EQ(ozayn_reg_update_capability_availability(&_svc, "C1", OZAYN_REG_AVAIL_UNAVAILABLE),
              OZAYN_REG_OK);
    ASSERT_EQ(_svc.capabilities[0].availability, OZAYN_REG_AVAIL_UNAVAILABLE);
    ozayn_reg_service_shutdown(&_svc);
    return 0;
}

/* ============================================================
 * CAPABILITY DEPENDENCIES & PERMISSIONS TESTS
 * ============================================================ */

TEST(test_reg_add_capability_dependency)
{
    _init_svc();
    ozayn_reg_register_component(&_svc, "P", "P", "1", 0, "P", NULL);
    ozayn_reg_register_capability(&_svc, "CAM", "Camera", "1", "d", "P", 0, 0, NULL);
    ozayn_reg_register_capability(&_svc, "VIS", "Vision", "1", "d", "P", 0, 0, NULL);
    ASSERT_EQ(ozayn_reg_add_capability_dependency(&_svc, "VIS", "CAM"), OZAYN_REG_OK);
    ASSERT_EQ(_svc.capabilities[1].dependency_count, 1);
    ASSERT_STR_EQ(_svc.capabilities[1].dependencies[0], "CAM");
    ozayn_reg_service_shutdown(&_svc);
    return 0;
}

TEST(test_reg_add_capability_dependency_invalid)
{
    _init_svc();
    ozayn_reg_register_component(&_svc, "P", "P", "1", 0, "P", NULL);
    ozayn_reg_register_capability(&_svc, "C1", "C1", "1", "d", "P", 0, 0, NULL);
    ASSERT_EQ(ozayn_reg_add_capability_dependency(&_svc, "C1", "NOPE"),
              OZAYN_REG_ERR_CAPABILITY_DEPENDENCY_INVALID);
    ozayn_reg_service_shutdown(&_svc);
    return 0;
}

TEST(test_reg_add_capability_dependency_not_found)
{
    _init_svc();
    ASSERT_EQ(ozayn_reg_add_capability_dependency(&_svc, "NOPE", "X"),
              OZAYN_REG_ERR_CAPABILITY_NOT_FOUND);
    ozayn_reg_service_shutdown(&_svc);
    return 0;
}

TEST(test_reg_add_capability_permission)
{
    _init_svc();
    ozayn_reg_register_component(&_svc, "P", "P", "1", 0, "P", NULL);
    ozayn_reg_register_capability(&_svc, "C1", "C1", "1", "d", "P", 0, 0, NULL);
    ASSERT_EQ(ozayn_reg_add_capability_permission(&_svc, "C1", "CAMERA.ACCESS"), OZAYN_REG_OK);
    ASSERT_EQ(_svc.capabilities[0].permission_count, 1);
    ASSERT_STR_EQ(_svc.capabilities[0].required_permissions[0], "CAMERA.ACCESS");
    ozayn_reg_service_shutdown(&_svc);
    return 0;
}

TEST(test_reg_add_capability_permission_not_found)
{
    _init_svc();
    ASSERT_EQ(ozayn_reg_add_capability_permission(&_svc, "NOPE", "X"),
              OZAYN_REG_ERR_CAPABILITY_NOT_FOUND);
    ozayn_reg_service_shutdown(&_svc);
    return 0;
}

TEST(test_reg_add_capability_permission_duplicate)
{
    _init_svc();
    ozayn_reg_register_component(&_svc, "P", "P", "1", 0, "P", NULL);
    ozayn_reg_register_capability(&_svc, "C1", "C1", "1", "d", "P", 0, 0, NULL);
    ozayn_reg_add_capability_permission(&_svc, "C1", "CAMERA.ACCESS");
    ASSERT_EQ(ozayn_reg_add_capability_permission(&_svc, "C1", "CAMERA.ACCESS"), OZAYN_REG_OK);
    ASSERT_EQ(_svc.capabilities[0].permission_count, 1);
    ozayn_reg_service_shutdown(&_svc);
    return 0;
}

/* ============================================================
 * CAPABILITY QUERIES TESTS
 * ============================================================ */

TEST(test_reg_list_capabilities)
{
    _init_svc();
    ozayn_reg_register_component(&_svc, "P", "P", "1", 0, "P", NULL);
    ozayn_reg_register_capability(&_svc, "C1", "C1", "1", "d", "P", 0, 0, NULL);
    ozayn_reg_register_capability(&_svc, "C2", "C2", "1", "d", "P", 0, 0, NULL);
    ozayn_reg_capability_desc_t *list[8];
    int n = ozayn_reg_list_capabilities(&_svc, list, 8);
    ASSERT_EQ(n, 2);
    ozayn_reg_service_shutdown(&_svc);
    return 0;
}

TEST(test_reg_list_capabilities_by_component)
{
    _init_svc();
    ozayn_reg_register_component(&_svc, "P1", "P1", "1", 0, "P", NULL);
    ozayn_reg_register_component(&_svc, "P2", "P2", "1", 0, "P", NULL);
    ozayn_reg_register_capability(&_svc, "C1", "C1", "1", "d", "P1", 0, 0, NULL);
    ozayn_reg_register_capability(&_svc, "C2", "C2", "1", "d", "P2", 0, 0, NULL);
    ozayn_reg_capability_desc_t *list[8];
    int n = ozayn_reg_list_capabilities_by_component(&_svc, "P1", list, 8);
    ASSERT_EQ(n, 1);
    ozayn_reg_service_shutdown(&_svc);
    return 0;
}

TEST(test_reg_list_capabilities_by_category)
{
    _init_svc();
    ozayn_reg_register_component(&_svc, "P", "P", "1", 0, "P", NULL);
    ozayn_reg_register_capability(&_svc, "C1", "C1", "1", "d", "P", OZAYN_REG_CAP_CAT_DEVICE, 0, NULL);
    ozayn_reg_register_capability(&_svc, "C2", "C2", "1", "d", "P", OZAYN_REG_CAP_CAT_SYSTEM, 0, NULL);
    ozayn_reg_capability_desc_t *list[8];
    int n = ozayn_reg_list_capabilities_by_category(&_svc, OZAYN_REG_CAP_CAT_DEVICE, list, 8);
    ASSERT_EQ(n, 1);
    ozayn_reg_service_shutdown(&_svc);
    return 0;
}

TEST(test_reg_list_available_capabilities)
{
    _init_svc();
    ozayn_reg_register_component(&_svc, "P", "P", "1", 0, "P", NULL);
    ozayn_reg_register_capability(&_svc, "C1", "C1", "1", "d", "P", 0, 0, NULL);
    ozayn_reg_register_capability(&_svc, "C2", "C2", "1", "d", "P", 0, 0, NULL);
    ozayn_reg_update_capability_availability(&_svc, "C1", OZAYN_REG_AVAIL_UNAVAILABLE);
    ozayn_reg_capability_desc_t *list[8];
    int n = ozayn_reg_list_available_capabilities(&_svc, list, 8);
    ASSERT_EQ(n, 1);
    ozayn_reg_service_shutdown(&_svc);
    return 0;
}

TEST(test_reg_list_active_capabilities)
{
    _init_svc();
    ozayn_reg_register_component(&_svc, "P", "P", "1", 0, "P", NULL);
    ozayn_reg_register_capability(&_svc, "C1", "C1", "1", "d", "P", 0, 0, NULL);
    ozayn_reg_update_capability_state(&_svc, "C1", OZAYN_REG_CAP_STATE_ACTIVE);
    ozayn_reg_capability_desc_t *list[8];
    int n = ozayn_reg_list_active_capabilities(&_svc, list, 8);
    ASSERT_EQ(n, 1);
    ozayn_reg_service_shutdown(&_svc);
    return 0;
}

TEST(test_reg_is_capability_available)
{
    _init_svc();
    ozayn_reg_register_component(&_svc, "P", "P", "1", 0, "P", NULL);
    ozayn_reg_register_capability(&_svc, "C1", "C1", "1", "d", "P", 0, 0, NULL);
    ASSERT(ozayn_reg_is_capability_available(&_svc, "C1"));
    ozayn_reg_update_capability_availability(&_svc, "C1", OZAYN_REG_AVAIL_UNAVAILABLE);
    ASSERT(!ozayn_reg_is_capability_available(&_svc, "C1"));
    ASSERT(!ozayn_reg_is_capability_available(NULL, "X"));
    ozayn_reg_service_shutdown(&_svc);
    return 0;
}

/* ============================================================
 * CAPABILITY DISCOVERY TESTS
 * ============================================================ */

TEST(test_reg_discover_all)
{
    _init_svc();
    ozayn_reg_snapshot_t snap;
    ASSERT_EQ(ozayn_reg_discover_all(&_svc, &snap), OZAYN_REG_OK);
    ASSERT_EQ(snap.total_components, 0);
    ASSERT(_svc.total_discoveries == 1);
    ozayn_reg_service_shutdown(&_svc);
    return 0;
}

TEST(test_reg_discover_component)
{
    _init_svc();
    ozayn_reg_register_component(&_svc, "C1", "C1", "1", 0, "P", NULL);
    ASSERT_EQ(ozayn_reg_discover_component(&_svc, "C1"), OZAYN_REG_OK);
    ASSERT(_svc.total_discoveries == 1);
    ozayn_reg_service_shutdown(&_svc);
    return 0;
}

TEST(test_reg_discover_component_not_found)
{
    _init_svc();
    ASSERT_EQ(ozayn_reg_discover_component(&_svc, "NOPE"),
              OZAYN_REG_ERR_COMPONENT_NOT_FOUND);
    ozayn_reg_service_shutdown(&_svc);
    return 0;
}

TEST(test_reg_discover_capability)
{
    _init_svc();
    ozayn_reg_register_component(&_svc, "P", "P", "1", 0, "P", NULL);
    ozayn_reg_register_capability(&_svc, "C1", "C1", "1", "d", "P", 0, 0, NULL);
    ASSERT_EQ(ozayn_reg_discover_capability(&_svc, "C1"), OZAYN_REG_OK);
    ASSERT(_svc.total_discoveries == 1);
    ozayn_reg_service_shutdown(&_svc);
    return 0;
}

TEST(test_reg_discover_capability_provider_missing)
{
    _init_svc();
    ozayn_reg_register_component(&_svc, "P", "P", "1", 0, "P", NULL);
    ozayn_reg_register_capability(&_svc, "C1", "C1", "1", "d", "P", 0, 0, NULL);
    /* Manually set provider to non-existent to simulate missing provider */
    strncpy(_svc.capabilities[0].provider_component, "GONE", OZAYN_REG_MAX_ID_LEN - 1);
    _svc.capabilities[0].provider_component[OZAYN_REG_MAX_ID_LEN - 1] = '\0';
    ASSERT_EQ(ozayn_reg_discover_capability(&_svc, "C1"), OZAYN_REG_OK);
    ASSERT_EQ(_svc.capabilities[0].state, OZAYN_REG_CAP_STATE_UNAVAILABLE);
    ASSERT_EQ(_svc.capabilities[0].availability, OZAYN_REG_AVAIL_UNAVAILABLE);
    ozayn_reg_service_shutdown(&_svc);
    return 0;
}

TEST(test_reg_refresh)
{
    _init_svc();
    ozayn_reg_register_component(&_svc, "P", "P", "1", 0, "P", NULL);
    ozayn_reg_register_capability(&_svc, "C1", "C1", "1", "d", "P", 0, 0, NULL);
    ASSERT_EQ(ozayn_reg_refresh(&_svc), OZAYN_REG_OK);
    ozayn_reg_service_shutdown(&_svc);
    return 0;
}

/* ============================================================
 * STALE DATA TESTS
 * ============================================================ */

TEST(test_reg_detect_stale_components)
{
    _init_svc();
    ozayn_reg_register_component(&_svc, "C1", "C1", "1", 0, "P", NULL);
    /* Simulate stale data */
    _svc.components[0].last_update = time(NULL) - 7200;
    int stale = ozayn_reg_detect_stale_components(&_svc);
    ASSERT(stale >= 1);
    ASSERT_EQ(_svc.components[0].state, OZAYN_REG_COMP_UNKNOWN);
    ASSERT_EQ(_svc.components[0].availability, OZAYN_REG_AVAIL_UNAVAILABLE);
    ozayn_reg_service_shutdown(&_svc);
    return 0;
}

TEST(test_reg_cleanup_stale)
{
    _init_svc();
    _svc.policy.stale_threshold_seconds = 1;
    ozayn_reg_register_component(&_svc, "C1", "C1", "1", 0, "P", NULL);
    _svc.components[0].last_update = time(NULL) - 10;
    int cleaned = ozayn_reg_cleanup_stale(&_svc);
    ASSERT(cleaned >= 1);
    ozayn_reg_service_shutdown(&_svc);
    return 0;
}

/* ============================================================
 * SNAPSHOT TESTS
 * ============================================================ */

TEST(test_reg_get_snapshot)
{
    _init_svc();
    ozayn_reg_register_component(&_svc, "C1", "C1", "1", 0, "P", NULL);
    ozayn_reg_register_component(&_svc, "C2", "C2", "1", 0, "P", NULL);
    ozayn_reg_update_component_state(&_svc, "C1", OZAYN_REG_COMP_ACTIVE);
    ozayn_reg_register_capability(&_svc, "CAP1", "CAP1", "1", "d", "C1", 0, 0, NULL);
    ozayn_reg_snapshot_t snap;
    ASSERT_EQ(ozayn_reg_get_snapshot(&_svc, &snap), OZAYN_REG_OK);
    ASSERT_EQ(snap.total_components, 2);
    ASSERT_EQ(snap.active_components, 1);
    ASSERT_EQ(snap.total_capabilities, 1);
    ozayn_reg_service_shutdown(&_svc);
    return 0;
}

TEST(test_reg_get_snapshot_null)
{
    ASSERT_EQ(ozayn_reg_get_snapshot(NULL, NULL), OZAYN_REG_ERR_NULL);
    return 0;
}

/* ============================================================
 * EVENT TESTS
 * ============================================================ */

TEST(test_reg_event_count)
{
    _init_svc();
    ASSERT_EQ(ozayn_reg_event_count(&_svc), 0);
    ozayn_reg_register_component(&_svc, "C1", "C1", "1", 0, "P", NULL);
    ASSERT(_svc.event_count >= 1);
    ozayn_reg_service_shutdown(&_svc);
    return 0;
}

TEST(test_reg_get_last_event)
{
    _init_svc();
    ozayn_reg_register_component(&_svc, "C1", "C1", "1", 0, "P", NULL);
    ozayn_reg_event_t ev;
    ASSERT_EQ(ozayn_reg_get_last_event(&_svc, &ev), OZAYN_REG_OK);
    ASSERT_EQ(ev.event_type, OZAYN_REG_EVENT_COMPONENT_REGISTERED);
    ASSERT_STR_EQ(ev.component_id, "C1");
    ozayn_reg_service_shutdown(&_svc);
    return 0;
}

TEST(test_reg_get_last_event_empty)
{
    _init_svc();
    ozayn_reg_event_t ev;
    ASSERT_EQ(ozayn_reg_get_last_event(&_svc, &ev), OZAYN_REG_ERR_NOT_FOUND);
    ozayn_reg_service_shutdown(&_svc);
    return 0;
}

/* ============================================================
 * POLICY TESTS
 * ============================================================ */

TEST(test_reg_default_policy)
{
    ozayn_reg_policy_t p = ozayn_reg_default_policy();
    ASSERT(p.enabled == 1);
    ASSERT(p.max_components == OZAYN_REG_MAX_COMPONENTS);
    ASSERT(p.max_capabilities == OZAYN_REG_MAX_CAPABILITIES);
    ASSERT(p.require_provider == 1);
    ASSERT(p.validate_dependencies == 1);
    return 0;
}

TEST(test_reg_set_policy)
{
    _init_svc();
    ozayn_reg_policy_t p = ozayn_reg_default_policy();
    p.max_components = 4;
    ASSERT_EQ(ozayn_reg_set_policy(&_svc, &p), OZAYN_REG_OK);
    ASSERT(_svc.policy.max_components == 4);
    ozayn_reg_service_shutdown(&_svc);
    return 0;
}

TEST(test_reg_set_policy_null)
{
    _init_svc();
    ASSERT_EQ(ozayn_reg_set_policy(&_svc, NULL), OZAYN_REG_ERR_INVALID_PARAM);
    ozayn_reg_service_shutdown(&_svc);
    return 0;
}

TEST(test_reg_get_policy)
{
    _init_svc();
    const ozayn_reg_policy_t *p = ozayn_reg_get_policy(&_svc);
    ASSERT_NOT_NULL(p);
    ASSERT(p->enabled == 1);
    ASSERT_NULL(ozayn_reg_get_policy(NULL));
    ozayn_reg_service_shutdown(&_svc);
    return 0;
}

/* ============================================================
 * RESOURCE SAFETY TESTS
 * ============================================================ */

TEST(test_reg_components_full)
{
    _init_svc();
    ASSERT(!ozayn_reg_components_full(&_svc));
    _svc.policy.max_components = 1;
    ozayn_reg_register_component(&_svc, "C1", "C1", "1", 0, "P", NULL);
    ASSERT(ozayn_reg_components_full(&_svc));
    ASSERT(ozayn_reg_components_full(NULL));
    ozayn_reg_service_shutdown(&_svc);
    return 0;
}

TEST(test_reg_capabilities_full)
{
    _init_svc();
    ASSERT(!ozayn_reg_capabilities_full(&_svc));
    _svc.policy.max_capabilities = 1;
    ozayn_reg_register_component(&_svc, "P", "P", "1", 0, "P", NULL);
    ozayn_reg_register_capability(&_svc, "C1", "C1", "1", "d", "P", 0, 0, NULL);
    ASSERT(ozayn_reg_capabilities_full(&_svc));
    ozayn_reg_service_shutdown(&_svc);
    return 0;
}

/* ============================================================
 * STATISTICS TESTS
 * ============================================================ */

TEST(test_reg_statistics)
{
    _init_svc();
    ASSERT_EQ(ozayn_reg_total_registrations(&_svc), 0);
    ASSERT_EQ(ozayn_reg_total_unregistrations(&_svc), 0);
    ASSERT_EQ(ozayn_reg_total_discoveries(&_svc), 0);
    ozayn_reg_register_component(&_svc, "C1", "C1", "1", 0, "P", NULL);
    ASSERT_EQ(ozayn_reg_total_registrations(&_svc), 1);
    ozayn_reg_unregister_component(&_svc, "C1");
    ASSERT_EQ(ozayn_reg_total_unregistrations(&_svc), 1);
    ozayn_reg_discover_all(&_svc, NULL);
    ASSERT_EQ(ozayn_reg_total_discoveries(&_svc), 1);
    ASSERT_EQ(ozayn_reg_total_registrations(NULL), 0);
    ozayn_reg_service_shutdown(&_svc);
    return 0;
}

/* ============================================================
 * NAME HELPER TESTS
 * ============================================================ */

TEST(test_reg_err_name)
{
    ASSERT_STR_EQ(ozayn_reg_err_name(OZAYN_REG_OK), "OK");
    ASSERT_STR_EQ(ozayn_reg_err_name(OZAYN_REG_ERR_NULL), "NULL");
    ASSERT_STR_EQ(ozayn_reg_err_name(OZAYN_REG_ERR_COMPONENT_EXISTS), "COMPONENT_EXISTS");
    ASSERT_STR_EQ(ozayn_reg_err_name(OZAYN_REG_ERR_CAPABILITY_NOT_FOUND), "CAPABILITY_NOT_FOUND");
    ASSERT_STR_EQ(ozayn_reg_err_name((ozayn_reg_err_t)999), "UNKNOWN");
    return 0;
}

TEST(test_reg_comp_state_name)
{
    ASSERT_STR_EQ(ozayn_reg_comp_state_name(OZAYN_REG_COMP_ACTIVE), "ACTIVE");
    ASSERT_STR_EQ(ozayn_reg_comp_state_name(OZAYN_REG_COMP_ERROR), "ERROR");
    ASSERT_STR_EQ(ozayn_reg_comp_state_name((ozayn_reg_comp_state_t)999), "UNKNOWN");
    return 0;
}

TEST(test_reg_comp_type_name)
{
    ASSERT_STR_EQ(ozayn_reg_comp_type_name(OZAYN_REG_COMP_TYPE_CORE), "CORE");
    ASSERT_STR_EQ(ozayn_reg_comp_type_name(OZAYN_REG_COMP_TYPE_MODULE), "MODULE");
    ASSERT_STR_EQ(ozayn_reg_comp_type_name(OZAYN_REG_COMP_TYPE_AI), "AI");
    ASSERT_STR_EQ(ozayn_reg_comp_type_name((ozayn_reg_comp_type_t)999), "UNKNOWN");
    return 0;
}

TEST(test_reg_availability_name)
{
    ASSERT_STR_EQ(ozayn_reg_availability_name(OZAYN_REG_AVAIL_AVAILABLE), "AVAILABLE");
    ASSERT_STR_EQ(ozayn_reg_availability_name(OZAYN_REG_AVAIL_UNAVAILABLE), "UNAVAILABLE");
    ASSERT_STR_EQ(ozayn_reg_availability_name((ozayn_reg_availability_t)999), "UNKNOWN");
    return 0;
}

TEST(test_reg_health_name)
{
    ASSERT_STR_EQ(ozayn_reg_health_name(OZAYN_REG_HEALTH_HEALTHY), "HEALTHY");
    ASSERT_STR_EQ(ozayn_reg_health_name(OZAYN_REG_HEALTH_FAILED), "FAILED");
    ASSERT_STR_EQ(ozayn_reg_health_name((ozayn_reg_health_t)999), "UNKNOWN");
    return 0;
}

TEST(test_reg_cap_state_name)
{
    ASSERT_STR_EQ(ozayn_reg_cap_state_name(OZAYN_REG_CAP_STATE_AVAILABLE), "AVAILABLE");
    ASSERT_STR_EQ(ozayn_reg_cap_state_name(OZAYN_REG_CAP_STATE_UNSUPPORTED), "UNSUPPORTED");
    ASSERT_STR_EQ(ozayn_reg_cap_state_name((ozayn_reg_cap_state_t)999), "UNKNOWN");
    return 0;
}

TEST(test_reg_cap_category_name)
{
    ASSERT_STR_EQ(ozayn_reg_cap_category_name(OZAYN_REG_CAP_CAT_DEVICE), "DEVICE");
    ASSERT_STR_EQ(ozayn_reg_cap_category_name(OZAYN_REG_CAP_CAT_INTELLIGENCE), "INTELLIGENCE");
    ASSERT_STR_EQ(ozayn_reg_cap_category_name((ozayn_reg_cap_category_t)999), "UNKNOWN");
    return 0;
}

TEST(test_reg_assurance_name)
{
    ASSERT_STR_EQ(ozayn_reg_assurance_name(OZAYN_REG_ASSURANCE_PUBLIC), "PUBLIC");
    ASSERT_STR_EQ(ozayn_reg_assurance_name(OZAYN_REG_ASSURANCE_MFA_REQUIRED), "MFA_REQUIRED");
    ASSERT_STR_EQ(ozayn_reg_assurance_name((ozayn_reg_assurance_t)999), "UNKNOWN");
    return 0;
}

TEST(test_reg_event_type_name)
{
    ASSERT_STR_EQ(ozayn_reg_event_type_name(OZAYN_REG_EVENT_COMPONENT_REGISTERED), "COMPONENT_REGISTERED");
    ASSERT_STR_EQ(ozayn_reg_event_type_name(OZAYN_REG_EVENT_CAPABILITY_REMOVED), "CAPABILITY_REMOVED");
    ASSERT_STR_EQ(ozayn_reg_event_type_name((ozayn_reg_event_type_t)999), "UNKNOWN");
    return 0;
}

/* ============================================================
 * SECURITY BOUNDARY TESTS
 * ============================================================ */

TEST(test_reg_no_secrets_in_component)
{
    _init_svc();
    ozayn_reg_register_component(&_svc, "C1", "C1", "1", 0, "P", "metadata");
    ozayn_reg_component_t *comp = ozayn_reg_get_component(&_svc, "C1");
    ASSERT(strstr(comp->metadata, "password") == NULL);
    ASSERT(strstr(comp->metadata, "key") == NULL);
    ASSERT(strstr(comp->metadata, "secret") == NULL);
    ASSERT(strstr(comp->metadata, "token") == NULL);
    ASSERT(strstr(comp->metadata, "credential") == NULL);
    ozayn_reg_service_shutdown(&_svc);
    return 0;
}

TEST(test_reg_no_secrets_in_capability)
{
    _init_svc();
    ozayn_reg_register_component(&_svc, "P", "P", "1", 0, "P", NULL);
    ozayn_reg_register_capability(&_svc, "C1", "C1", "1", "d", "P", 0, 0, "metadata");
    ozayn_reg_capability_desc_t *cap = ozayn_reg_get_capability(&_svc, "C1");
    ASSERT(strstr(cap->metadata, "password") == NULL);
    ASSERT(strstr(cap->metadata, "key") == NULL);
    ASSERT(strstr(cap->metadata, "secret") == NULL);
    ASSERT(strstr(cap->metadata, "token") == NULL);
    ASSERT(strstr(cap->description, "password") == NULL);
    ozayn_reg_service_shutdown(&_svc);
    return 0;
}

TEST(test_reg_global_singleton)
{
    ozayn_reg_service_t *g1 = ozayn_reg_get_global();
    ozayn_reg_service_t *g2 = ozayn_reg_get_global();
    ASSERT_NOT_NULL(g1);
    ASSERT(g1 == g2);
    return 0;
}

/* ============================================================
 * TEST RUNNER
 * ============================================================ */

int run_component_registry_tests(void)
{
    SUITE_BEGIN("Component Registry & Capability Discovery");

    /* Lifecycle */
    RUN(test_reg_init);
    RUN(test_reg_init_null);
    RUN(test_reg_init_double);
    RUN(test_reg_shutdown);
    RUN(test_reg_shutdown_null);
    RUN(test_reg_is_initialized);

    /* Component Registration */
    RUN(test_reg_register_component);
    RUN(test_reg_register_component_null);
    RUN(test_reg_register_component_not_init);
    RUN(test_reg_register_component_empty_id);
    RUN(test_reg_register_component_empty_name);
    RUN(test_reg_register_component_duplicate);
    RUN(test_reg_register_component_limit);
    RUN(test_reg_register_component_no_provider);
    RUN(test_reg_unregister_component);
    RUN(test_reg_unregister_component_not_found);
    RUN(test_reg_unregister_component_null);
    RUN(test_reg_unregister_component_removes_capabilities);
    RUN(test_reg_get_component);
    RUN(test_reg_component_count);
    RUN(test_reg_component_exists);

    /* Component State Management */
    RUN(test_reg_update_component_state);
    RUN(test_reg_update_component_state_not_found);
    RUN(test_reg_update_component_availability);
    RUN(test_reg_update_component_health);

    /* Component Queries */
    RUN(test_reg_list_components);
    RUN(test_reg_list_components_by_type);
    RUN(test_reg_list_active_components);
    RUN(test_reg_list_available_components);
    RUN(test_reg_list_unavailable_components);

    /* Capability Registration */
    RUN(test_reg_register_capability);
    RUN(test_reg_register_capability_null);
    RUN(test_reg_register_capability_empty_id);
    RUN(test_reg_register_capability_no_provider);
    RUN(test_reg_register_capability_provider_not_registered);
    RUN(test_reg_register_capability_duplicate);
    RUN(test_reg_register_capability_limit);
    RUN(test_reg_unregister_capability);
    RUN(test_reg_unregister_capability_not_found);
    RUN(test_reg_get_capability);
    RUN(test_reg_capability_count);
    RUN(test_reg_capability_exists);

    /* Capability State Management */
    RUN(test_reg_update_capability_state);
    RUN(test_reg_update_capability_state_not_found);
    RUN(test_reg_update_capability_availability);

    /* Capability Dependencies & Permissions */
    RUN(test_reg_add_capability_dependency);
    RUN(test_reg_add_capability_dependency_invalid);
    RUN(test_reg_add_capability_dependency_not_found);
    RUN(test_reg_add_capability_permission);
    RUN(test_reg_add_capability_permission_not_found);
    RUN(test_reg_add_capability_permission_duplicate);

    /* Capability Queries */
    RUN(test_reg_list_capabilities);
    RUN(test_reg_list_capabilities_by_component);
    RUN(test_reg_list_capabilities_by_category);
    RUN(test_reg_list_available_capabilities);
    RUN(test_reg_list_active_capabilities);
    RUN(test_reg_is_capability_available);

    /* Capability Discovery */
    RUN(test_reg_discover_all);
    RUN(test_reg_discover_component);
    RUN(test_reg_discover_component_not_found);
    RUN(test_reg_discover_capability);
    RUN(test_reg_discover_capability_provider_missing);
    RUN(test_reg_refresh);

    /* Stale Data */
    RUN(test_reg_detect_stale_components);
    RUN(test_reg_cleanup_stale);

    /* Snapshot */
    RUN(test_reg_get_snapshot);
    RUN(test_reg_get_snapshot_null);

    /* Events */
    RUN(test_reg_event_count);
    RUN(test_reg_get_last_event);
    RUN(test_reg_get_last_event_empty);

    /* Policy */
    RUN(test_reg_default_policy);
    RUN(test_reg_set_policy);
    RUN(test_reg_set_policy_null);
    RUN(test_reg_get_policy);

    /* Resource Safety */
    RUN(test_reg_components_full);
    RUN(test_reg_capabilities_full);

    /* Statistics */
    RUN(test_reg_statistics);

    /* Name Helpers */
    RUN(test_reg_err_name);
    RUN(test_reg_comp_state_name);
    RUN(test_reg_comp_type_name);
    RUN(test_reg_availability_name);
    RUN(test_reg_health_name);
    RUN(test_reg_cap_state_name);
    RUN(test_reg_cap_category_name);
    RUN(test_reg_assurance_name);
    RUN(test_reg_event_type_name);

    /* Security Boundary */
    RUN(test_reg_no_secrets_in_component);
    RUN(test_reg_no_secrets_in_capability);
    RUN(test_reg_global_singleton);

    SUITE_END();
    return TOTAL_FAIL();
}
