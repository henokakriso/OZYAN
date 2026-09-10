/*
 * component_registry.h — Component Registry & Capability Discovery (Step 03).
 *
 * Provides a controlled registry for OZAYN components and their capabilities.
 * The registry is an inventory — it does NOT implement the registered components.
 *
 *   COMPONENT REGISTRY
 *          |
 *   CAPABILITY DISCOVERY
 *          |
 *   CONTROL ROOM STATE
 *
 * No AI/ML, no arbitrary command execution, no security bypass,
 * no autonomous control, no GUI, no voice, no gesture, no face
 * recognition, no ARWE integration.
 */

#ifndef OZAYN_COMPONENT_REGISTRY_H
#define OZAYN_COMPONENT_REGISTRY_H

#include "control_room.h"
#include <stdint.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================
 * SECTION 1 — REGISTRY ERROR CODES
 * ============================================================ */

typedef enum {
    OZAYN_REG_OK                              =   0,
    OZAYN_REG_ERR_NULL                        =  -1,
    OZAYN_REG_ERR_NOT_INITIALIZED             =  -2,
    OZAYN_REG_ERR_ALREADY_INITIALIZED         =  -3,
    OZAYN_REG_ERR_INVALID_PARAM               =  -4,
    OZAYN_REG_ERR_LIMIT_REACHED               =  -5,
    OZAYN_REG_ERR_NOT_FOUND                   =  -6,
    OZAYN_REG_ERR_COMPONENT_INVALID           =  -7,
    OZAYN_REG_ERR_COMPONENT_EXISTS            =  -8,
    OZAYN_REG_ERR_COMPONENT_NOT_FOUND         =  -9,
    OZAYN_REG_ERR_COMPONENT_STATE_INVALID     = -10,
    OZAYN_REG_ERR_CAPABILITY_INVALID          = -11,
    OZAYN_REG_ERR_CAPABILITY_EXISTS           = -12,
    OZAYN_REG_ERR_CAPABILITY_NOT_FOUND        = -13,
    OZAYN_REG_ERR_CAPABILITY_UNAVAILABLE      = -14,
    OZAYN_REG_ERR_CAPABILITY_PROVIDER_MISSING = -15,
    OZAYN_REG_ERR_CAPABILITY_DEPENDENCY_INVALID = -16,
    OZAYN_REG_ERR_DISCOVERY_FAILED            = -17,
    OZAYN_REG_ERR_UNAVAILABLE                 = -18,
    OZAYN_REG_ERR_UNREGISTRATION_FAILED       = -19,
    OZAYN_REG_ERR_STATE_TRANSITION            = -20,
    OZAYN_REG_ERR_STALE_DATA                  = -21
} ozayn_reg_err_t;

/* ============================================================
 * SECTION 2 — COMPONENT STATES
 * ============================================================ */

typedef enum {
    OZAYN_REG_COMP_UNINITIALIZED              = 0,
    OZAYN_REG_COMP_INITIALIZING               = 1,
    OZAYN_REG_COMP_READY                      = 2,
    OZAYN_REG_COMP_ACTIVE                     = 3,
    OZAYN_REG_COMP_PAUSED                     = 4,
    OZAYN_REG_COMP_STOPPING                   = 5,
    OZAYN_REG_COMP_STOPPED                    = 6,
    OZAYN_REG_COMP_DEGRADED                   = 7,
    OZAYN_REG_COMP_ERROR                      = 8,
    OZAYN_REG_COMP_UNAVAILABLE                = 9,
    OZAYN_REG_COMP_UNKNOWN                    = 10
} ozayn_reg_comp_state_t;

/* ============================================================
 * SECTION 3 — COMPONENT TYPES
 * ============================================================ */

typedef enum {
    OZAYN_REG_COMP_TYPE_CORE                  = 0,
    OZAYN_REG_COMP_TYPE_RUNTIME               = 1,
    OZAYN_REG_COMP_TYPE_MODULE                = 2,
    OZAYN_REG_COMP_TYPE_PLUGIN                = 3,
    OZAYN_REG_COMP_TYPE_TASK_SYSTEM           = 4,
    OZAYN_REG_COMP_TYPE_PROCESS_SYSTEM        = 5,
    OZAYN_REG_COMP_TYPE_EVENT_SYSTEM          = 6,
    OZAYN_REG_COMP_TYPE_SECURITY              = 7,
    OZAYN_REG_COMP_TYPE_STORAGE               = 8,
    OZAYN_REG_COMP_TYPE_DEVICE                = 9,
    OZAYN_REG_COMP_TYPE_VISION                = 10,
    OZAYN_REG_COMP_TYPE_VOICE                 = 11,
    OZAYN_REG_COMP_TYPE_GESTURE               = 12,
    OZAYN_REG_COMP_TYPE_AI                    = 13,
    OZAYN_REG_COMP_TYPE_MEMORY                = 14,
    OZAYN_REG_COMP_TYPE_ARWE                  = 15,
    OZAYN_REG_COMP_TYPE_WEB_INTELLIGENCE      = 16,
    OZAYN_REG_COMP_TYPE_GUI                   = 17,
    OZAYN_REG_COMP_TYPE_CUSTOM                = 18
} ozayn_reg_comp_type_t;

/* ============================================================
 * SECTION 4 — COMPONENT AVAILABILITY
 * ============================================================ */

typedef enum {
    OZAYN_REG_AVAIL_UNKNOWN                   = 0,
    OZAYN_REG_AVAIL_AVAILABLE                 = 1,
    OZAYN_REG_AVAIL_UNAVAILABLE               = 2,
    OZAYN_REG_AVAIL_DEGRADED                  = 3
} ozayn_reg_availability_t;

/* ============================================================
 * SECTION 5 — HEALTH STATES
 * ============================================================ */

typedef enum {
    OZAYN_REG_HEALTH_UNKNOWN                  = 0,
    OZAYN_REG_HEALTH_HEALTHY                  = 1,
    OZAYN_REG_HEALTH_DEGRADED                 = 2,
    OZAYN_REG_HEALTH_UNHEALTHY                = 3,
    OZAYN_REG_HEALTH_FAILED                   = 4
} ozayn_reg_health_t;

/* ============================================================
 * SECTION 6 — CAPABILITY STATES
 * ============================================================ */

typedef enum {
    OZAYN_REG_CAP_STATE_UNKNOWN               = 0,
    OZAYN_REG_CAP_STATE_AVAILABLE             = 1,
    OZAYN_REG_CAP_STATE_ACTIVE                = 2,
    OZAYN_REG_CAP_STATE_DISABLED              = 3,
    OZAYN_REG_CAP_STATE_UNAVAILABLE           = 4,
    OZAYN_REG_CAP_STATE_UNSUPPORTED           = 5,
    OZAYN_REG_CAP_STATE_ERROR                 = 6
} ozayn_reg_cap_state_t;

/* ============================================================
 * SECTION 7 — CAPABILITY CATEGORIES
 * ============================================================ */

typedef enum {
    OZAYN_REG_CAP_CAT_SYSTEM                  = 0,
    OZAYN_REG_CAP_CAT_CORE                    = 1,
    OZAYN_REG_CAP_CAT_SECURITY                = 2,
    OZAYN_REG_CAP_CAT_DEVICE                  = 3,
    OZAYN_REG_CAP_CAT_INTELLIGENCE            = 4,
    OZAYN_REG_CAP_CAT_ARWE                    = 5,
    OZAYN_REG_CAP_CAT_CUSTOM                  = 6
} ozayn_reg_cap_category_t;

/* ============================================================
 * SECTION 8 — ASSURANCE LEVELS
 * ============================================================ */

typedef enum {
    OZAYN_REG_ASSURANCE_PUBLIC                = 0,
    OZAYN_REG_ASSURANCE_AUTHENTICATED         = 1,
    OZAYN_REG_ASSURANCE_MFA_REQUIRED          = 2,
    OZAYN_REG_ASSURANCE_HIGH_ASSURANCE        = 3
} ozayn_reg_assurance_t;

/* ============================================================
 * SECTION 9 — REGISTRY EVENTS
 * ============================================================ */

typedef enum {
    OZAYN_REG_EVENT_COMPONENT_REGISTERED      = 0,
    OZAYN_REG_EVENT_COMPONENT_UNREGISTERED    = 1,
    OZAYN_REG_EVENT_COMPONENT_STATE_CHANGED   = 2,
    OZAYN_REG_EVENT_COMPONENT_AVAIL_CHANGED   = 3,
    OZAYN_REG_EVENT_COMPONENT_HEALTH_CHANGED  = 4,
    OZAYN_REG_EVENT_CAPABILITY_REGISTERED     = 5,
    OZAYN_REG_EVENT_CAPABILITY_REMOVED        = 6,
    OZAYN_REG_EVENT_CAPABILITY_STATE_CHANGED  = 7,
    OZAYN_REG_EVENT_CAPABILITY_AVAIL_CHANGED  = 8,
    OZAYN_REG_EVENT_DISCOVERY_COMPLETED       = 9,
    OZAYN_REG_EVENT_STALE_DATA_DETECTED       = 10
} ozayn_reg_event_type_t;

/* ============================================================
 * SECTION 10 — LIMITS
 * ============================================================ */

#define OZAYN_REG_MAX_COMPONENTS              64
#define OZAYN_REG_MAX_CAPABILITIES           128
#define OZAYN_REG_MAX_DEPENDENCIES            16
#define OZAYN_REG_MAX_PERMISSIONS             16
#define OZAYN_REG_MAX_EVENTS                 256
#define OZAYN_REG_MAX_ID_LEN                  64
#define OZAYN_REG_MAX_NAME_LEN               128
#define OZAYN_REG_MAX_VERSION_LEN             32
#define OZAYN_REG_MAX_DESC_LEN               256
#define OZAYN_REG_MAX_META_LEN               256
#define OZAYN_REG_STALE_THRESHOLD_SECONDS  3600

/* ============================================================
 * SECTION 11 — COMPONENT DESCRIPTOR
 * ============================================================ */

typedef struct {
    char                    component_id[OZAYN_REG_MAX_ID_LEN];
    char                    name[OZAYN_REG_MAX_NAME_LEN];
    char                    version[OZAYN_REG_MAX_VERSION_LEN];
    ozayn_reg_comp_type_t   type;
    ozayn_reg_comp_state_t  state;
    ozayn_reg_availability_t availability;
    ozayn_reg_health_t      health;
    char                    provider[OZAYN_REG_MAX_NAME_LEN];
    time_t                  registration_time;
    time_t                  last_update;
    char                    metadata[OZAYN_REG_MAX_META_LEN];
    int                     active;
} ozayn_reg_component_t;

/* ============================================================
 * SECTION 12 — CAPABILITY DESCRIPTOR
 * ============================================================ */

typedef struct {
    char                    cap_id[OZAYN_REG_MAX_ID_LEN];
    char                    name[OZAYN_REG_MAX_NAME_LEN];
    char                    version[OZAYN_REG_MAX_VERSION_LEN];
    char                    description[OZAYN_REG_MAX_DESC_LEN];
    char                    provider_component[OZAYN_REG_MAX_ID_LEN];
    ozayn_reg_cap_state_t   state;
    ozayn_reg_availability_t availability;
    ozayn_reg_cap_category_t category;
    ozayn_reg_assurance_t   required_assurance;
    char                    required_permissions[OZAYN_REG_MAX_PERMISSIONS][OZAYN_REG_MAX_ID_LEN];
    int                     permission_count;
    char                    dependencies[OZAYN_REG_MAX_DEPENDENCIES][OZAYN_REG_MAX_ID_LEN];
    int                     dependency_count;
    time_t                  registration_time;
    time_t                  last_update;
    char                    metadata[OZAYN_REG_MAX_META_LEN];
    int                     active;
} ozayn_reg_capability_desc_t;

/* ============================================================
 * SECTION 13 — REGISTRY EVENT
 * ============================================================ */

typedef struct {
    ozayn_reg_event_type_t  event_type;
    char                    component_id[OZAYN_REG_MAX_ID_LEN];
    char                    cap_id[OZAYN_REG_MAX_ID_LEN];
    time_t                  timestamp;
    char                    detail[OZAYN_REG_MAX_META_LEN];
} ozayn_reg_event_t;

/* ============================================================
 * SECTION 14 — REGISTRY SNAPSHOT
 * ============================================================ */

typedef struct {
    int                     total_components;
    int                     active_components;
    int                     available_components;
    int                     unavailable_components;
    int                     failed_components;
    int                     total_capabilities;
    int                     active_capabilities;
    int                     available_capabilities;
    int                     disabled_capabilities;
    int                     unsupported_capabilities;
    int                     stale_components;
    time_t                  snapshot_time;
} ozayn_reg_snapshot_t;

/* ============================================================
 * SECTION 15 — REGISTRY POLICY
 * ============================================================ */

typedef struct {
    int                     enabled;
    int                     max_components;
    int                     max_capabilities;
    int                     max_dependencies;
    int                     max_permissions;
    int                     max_events;
    int                     stale_threshold_seconds;
    int                     require_provider;
    int                     validate_dependencies;
} ozayn_reg_policy_t;

/* ============================================================
 * SECTION 16 — REGISTRY SERVICE CONFIGURATION
 * ============================================================ */

typedef struct {
    void                   *audit;
    void                   *control_room;
} ozayn_reg_service_config_t;

/* ============================================================
 * SECTION 17 — REGISTRY SERVICE STATE
 * ============================================================ */

typedef struct {
    int                     initialized;

    /* Components */
    ozayn_reg_component_t   components[OZAYN_REG_MAX_COMPONENTS];
    int                     component_count;

    /* Capabilities */
    ozayn_reg_capability_desc_t capabilities[OZAYN_REG_MAX_CAPABILITIES];
    int                     capability_count;

    /* Events */
    ozayn_reg_event_t       events[OZAYN_REG_MAX_EVENTS];
    int                     event_head;
    int                     event_count;
    uint32_t                event_sequence;

    /* Policy */
    ozayn_reg_policy_t      policy;

    /* Dependencies (not owned) */
    void                   *audit;
    void                   *control_room;

    /* Statistics */
    uint64_t                total_registrations;
    uint64_t                total_unregistrations;
    uint64_t                total_cap_registrations;
    uint64_t                total_cap_removals;
    uint64_t                total_discoveries;
    uint64_t                total_stale_detections;
    uint64_t                total_state_queries;
} ozayn_reg_service_t;

/* ============================================================
 * SECTION 18 — NAME HELPERS — REGISTRY ERRORS
 * ============================================================ */

const char *ozayn_reg_err_name(ozayn_reg_err_t err);

/* ============================================================
 * SECTION 19 — NAME HELPERS — COMPONENT STATES
 * ============================================================ */

const char *ozayn_reg_comp_state_name(ozayn_reg_comp_state_t s);

/* ============================================================
 * SECTION 20 — NAME HELPERS — COMPONENT TYPES
 * ============================================================ */

const char *ozayn_reg_comp_type_name(ozayn_reg_comp_type_t t);

/* ============================================================
 * SECTION 21 — NAME HELPERS — AVAILABILITY
 * ============================================================ */

const char *ozayn_reg_availability_name(ozayn_reg_availability_t a);

/* ============================================================
 * SECTION 22 — NAME HELPERS — HEALTH
 * ============================================================ */

const char *ozayn_reg_health_name(ozayn_reg_health_t h);

/* ============================================================
 * SECTION 23 — NAME HELPERS — CAPABILITY STATES
 * ============================================================ */

const char *ozayn_reg_cap_state_name(ozayn_reg_cap_state_t s);

/* ============================================================
 * SECTION 24 — NAME HELPERS — CAPABILITY CATEGORIES
 * ============================================================ */

const char *ozayn_reg_cap_category_name(ozayn_reg_cap_category_t c);

/* ============================================================
 * SECTION 25 — NAME HELPERS — ASSURANCE
 * ============================================================ */

const char *ozayn_reg_assurance_name(ozayn_reg_assurance_t a);

/* ============================================================
 * SECTION 26 — NAME HELPERS — REGISTRY EVENTS
 * ============================================================ */

const char *ozayn_reg_event_type_name(ozayn_reg_event_type_t e);

/* ============================================================
 * SECTION 27 — LIFECYCLE
 * ============================================================ */

ozayn_reg_err_t ozayn_reg_service_init(
    ozayn_reg_service_t *svc,
    const ozayn_reg_service_config_t *cfg);

void ozayn_reg_service_shutdown(ozayn_reg_service_t *svc);

int ozayn_reg_service_is_initialized(const ozayn_reg_service_t *svc);

/* ============================================================
 * SECTION 28 — COMPONENT REGISTRATION
 * ============================================================ */

ozayn_reg_err_t ozayn_reg_register_component(
    ozayn_reg_service_t *svc,
    const char *component_id,
    const char *name,
    const char *version,
    ozayn_reg_comp_type_t type,
    const char *provider,
    const char *metadata);

ozayn_reg_err_t ozayn_reg_unregister_component(
    ozayn_reg_service_t *svc,
    const char *component_id);

ozayn_reg_component_t *ozayn_reg_get_component(
    ozayn_reg_service_t *svc,
    const char *component_id);

int ozayn_reg_component_count(const ozayn_reg_service_t *svc);

int ozayn_reg_component_exists(
    const ozayn_reg_service_t *svc,
    const char *component_id);

/* ============================================================
 * SECTION 29 — COMPONENT STATE MANAGEMENT
 * ============================================================ */

ozayn_reg_err_t ozayn_reg_update_component_state(
    ozayn_reg_service_t *svc,
    const char *component_id,
    ozayn_reg_comp_state_t new_state);

ozayn_reg_err_t ozayn_reg_update_component_availability(
    ozayn_reg_service_t *svc,
    const char *component_id,
    ozayn_reg_availability_t availability);

ozayn_reg_err_t ozayn_reg_update_component_health(
    ozayn_reg_service_t *svc,
    const char *component_id,
    ozayn_reg_health_t health);

/* ============================================================
 * SECTION 30 — COMPONENT QUERIES
 * ============================================================ */

int ozayn_reg_list_components(
    const ozayn_reg_service_t *svc,
    ozayn_reg_component_t **out_components,
    int max_count);

int ozayn_reg_list_components_by_type(
    const ozayn_reg_service_t *svc,
    ozayn_reg_comp_type_t type,
    ozayn_reg_component_t **out_components,
    int max_count);

int ozayn_reg_list_active_components(
    const ozayn_reg_service_t *svc,
    ozayn_reg_component_t **out_components,
    int max_count);

int ozayn_reg_list_available_components(
    const ozayn_reg_service_t *svc,
    ozayn_reg_component_t **out_components,
    int max_count);

int ozayn_reg_list_unavailable_components(
    const ozayn_reg_service_t *svc,
    ozayn_reg_component_t **out_components,
    int max_count);

/* ============================================================
 * SECTION 31 — CAPABILITY REGISTRATION
 * ============================================================ */

ozayn_reg_err_t ozayn_reg_register_capability(
    ozayn_reg_service_t *svc,
    const char *cap_id,
    const char *name,
    const char *version,
    const char *description,
    const char *provider_component,
    ozayn_reg_cap_category_t category,
    ozayn_reg_assurance_t required_assurance,
    const char *metadata);

ozayn_reg_err_t ozayn_reg_unregister_capability(
    ozayn_reg_service_t *svc,
    const char *cap_id);

ozayn_reg_capability_desc_t *ozayn_reg_get_capability(
    ozayn_reg_service_t *svc,
    const char *cap_id);

int ozayn_reg_capability_count(const ozayn_reg_service_t *svc);

int ozayn_reg_capability_exists(
    const ozayn_reg_service_t *svc,
    const char *cap_id);

/* ============================================================
 * SECTION 32 — CAPABILITY STATE MANAGEMENT
 * ============================================================ */

ozayn_reg_err_t ozayn_reg_update_capability_state(
    ozayn_reg_service_t *svc,
    const char *cap_id,
    ozayn_reg_cap_state_t new_state);

ozayn_reg_err_t ozayn_reg_update_capability_availability(
    ozayn_reg_service_t *svc,
    const char *cap_id,
    ozayn_reg_availability_t availability);

/* ============================================================
 * SECTION 33 — CAPABILITY DEPENDENCIES & PERMISSIONS
 * ============================================================ */

ozayn_reg_err_t ozayn_reg_add_capability_dependency(
    ozayn_reg_service_t *svc,
    const char *cap_id,
    const char *dependency_cap_id);

ozayn_reg_err_t ozayn_reg_add_capability_permission(
    ozayn_reg_service_t *svc,
    const char *cap_id,
    const char *permission_ref);

/* ============================================================
 * SECTION 34 — CAPABILITY QUERIES
 * ============================================================ */

int ozayn_reg_list_capabilities(
    const ozayn_reg_service_t *svc,
    ozayn_reg_capability_desc_t **out_caps,
    int max_count);

int ozayn_reg_list_capabilities_by_component(
    const ozayn_reg_service_t *svc,
    const char *component_id,
    ozayn_reg_capability_desc_t **out_caps,
    int max_count);

int ozayn_reg_list_capabilities_by_category(
    const ozayn_reg_service_t *svc,
    ozayn_reg_cap_category_t category,
    ozayn_reg_capability_desc_t **out_caps,
    int max_count);

int ozayn_reg_list_available_capabilities(
    const ozayn_reg_service_t *svc,
    ozayn_reg_capability_desc_t **out_caps,
    int max_count);

int ozayn_reg_list_active_capabilities(
    const ozayn_reg_service_t *svc,
    ozayn_reg_capability_desc_t **out_caps,
    int max_count);

int ozayn_reg_is_capability_available(
    const ozayn_reg_service_t *svc,
    const char *cap_id);

/* ============================================================
 * SECTION 35 — CAPABILITY DISCOVERY
 * ============================================================ */

ozayn_reg_err_t ozayn_reg_discover_all(
    ozayn_reg_service_t *svc,
    ozayn_reg_snapshot_t *out_snapshot);

ozayn_reg_err_t ozayn_reg_discover_component(
    ozayn_reg_service_t *svc,
    const char *component_id);

ozayn_reg_err_t ozayn_reg_discover_capability(
    ozayn_reg_service_t *svc,
    const char *cap_id);

ozayn_reg_err_t ozayn_reg_refresh(
    ozayn_reg_service_t *svc);

/* ============================================================
 * SECTION 36 — STALE DATA HANDLING
 * ============================================================ */

int ozayn_reg_detect_stale_components(ozayn_reg_service_t *svc);

int ozayn_reg_cleanup_stale(ozayn_reg_service_t *svc);

/* ============================================================
 * SECTION 37 — SNAPSHOT
 * ============================================================ */

ozayn_reg_err_t ozayn_reg_get_snapshot(
    const ozayn_reg_service_t *svc,
    ozayn_reg_snapshot_t *out_snapshot);

/* ============================================================
 * SECTION 38 — EVENT OBSERVATION
 * ============================================================ */

int ozayn_reg_event_count(const ozayn_reg_service_t *svc);

ozayn_reg_err_t ozayn_reg_get_last_event(
    const ozayn_reg_service_t *svc,
    ozayn_reg_event_t *out_event);

/* ============================================================
 * SECTION 39 — POLICY
 * ============================================================ */

ozayn_reg_policy_t ozayn_reg_default_policy(void);

ozayn_reg_err_t ozayn_reg_set_policy(
    ozayn_reg_service_t *svc,
    const ozayn_reg_policy_t *policy);

const ozayn_reg_policy_t *ozayn_reg_get_policy(const ozayn_reg_service_t *svc);

/* ============================================================
 * SECTION 40 — AUDIT INTEGRATION
 * ============================================================ */

ozayn_reg_err_t ozayn_reg_audit_event(
    ozayn_reg_service_t *svc,
    const char *event_type,
    const char *detail);

/* ============================================================
 * SECTION 41 — RESOURCE SAFETY
 * ============================================================ */

int ozayn_reg_components_full(const ozayn_reg_service_t *svc);
int ozayn_reg_capabilities_full(const ozayn_reg_service_t *svc);

/* ============================================================
 * SECTION 42 — STATISTICS
 * ============================================================ */

uint64_t ozayn_reg_total_registrations(const ozayn_reg_service_t *svc);
uint64_t ozayn_reg_total_unregistrations(const ozayn_reg_service_t *svc);
uint64_t ozayn_reg_total_discoveries(const ozayn_reg_service_t *svc);

/* ============================================================
 * SECTION 43 — GLOBAL ACCESSOR
 * ============================================================ */

ozayn_reg_service_t *ozayn_reg_get_global(void);

#ifdef __cplusplus
}
#endif

#endif /* OZAYN_COMPONENT_REGISTRY_H */
