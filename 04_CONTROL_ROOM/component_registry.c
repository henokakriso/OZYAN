/*
 * component_registry.c — Component Registry & Capability Discovery (Step 03).
 *
 * Implements a controlled registry for OZAYN components and their capabilities.
 * The registry is an inventory — it does NOT implement the registered components.
 *
 * No AI/ML, no arbitrary command execution, no security bypass,
 * no autonomous control, no GUI, no voice, no gesture, no face
 * recognition, no ARWE integration.
 */

#include "component_registry.h"
#include "audit.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

/* ============================================================
 * GLOBAL SINGLETON
 * ============================================================ */

static ozayn_reg_service_t _reg_global = {0};

ozayn_reg_service_t *ozayn_reg_get_global(void)
{
    return &_reg_global;
}

/* ============================================================
 * INTERNAL — AUDIT EVENT
 * ============================================================ */

static void _audit_event(ozayn_reg_service_t *svc,
                          const char *event_type,
                          const char *detail)
{
    if (!svc->audit) return;
    ozayn_audit_service_t *au = (ozayn_audit_service_t *)svc->audit;
    if (!au->initialized) return;
    ozayn_audit_event_t ev;
    ozayn_audit_event_init(&ev);
    ozayn_audit_event_set_type(&ev, OZAYN_AUDIT_CONFIG_CHANGED);
    ozayn_audit_event_set_outcome(&ev, OZAYN_AUDIT_OUTCOME_SUCCESS);
    ozayn_audit_event_set_severity(&ev, OZAYN_AUDIT_SEV_NOTICE);
    ozayn_audit_event_set_source(&ev, "REG");
    char buf[512];
    snprintf(buf, sizeof(buf), "%s: %s", event_type, detail ? detail : "N/A");
    ozayn_audit_event_set_detail(&ev, buf);
    ozayn_audit_record(au, &ev);
}

/* ============================================================
 * INTERNAL — EVENT RECORDING
 * ============================================================ */

static void _record_event(ozayn_reg_service_t *svc,
                           ozayn_reg_event_type_t event_type,
                           const char *component_id,
                           const char *cap_id,
                           const char *detail)
{
    if (svc->event_count >= OZAYN_REG_MAX_EVENTS) {
        svc->event_head = (svc->event_head + 1) % OZAYN_REG_MAX_EVENTS;
        svc->event_count--;
    }
    int slot = (svc->event_head + svc->event_count) % OZAYN_REG_MAX_EVENTS;
    memset(&svc->events[slot], 0, sizeof(ozayn_reg_event_t));
    svc->events[slot].event_type = event_type;
    svc->events[slot].timestamp = time(NULL);
    if (component_id)
        strncpy(svc->events[slot].component_id, component_id, OZAYN_REG_MAX_ID_LEN - 1);
    if (cap_id)
        strncpy(svc->events[slot].cap_id, cap_id, OZAYN_REG_MAX_ID_LEN - 1);
    if (detail)
        strncpy(svc->events[slot].detail, detail, OZAYN_REG_MAX_META_LEN - 1);
    svc->event_count++;
    svc->event_sequence++;
}

/* ============================================================
 * SECTION 18 — NAME HELPERS — REGISTRY ERRORS
 * ============================================================ */

const char *ozayn_reg_err_name(ozayn_reg_err_t err)
{
    switch (err) {
    case OZAYN_REG_OK:                              return "OK";
    case OZAYN_REG_ERR_NULL:                        return "NULL";
    case OZAYN_REG_ERR_NOT_INITIALIZED:             return "NOT_INITIALIZED";
    case OZAYN_REG_ERR_ALREADY_INITIALIZED:         return "ALREADY_INITIALIZED";
    case OZAYN_REG_ERR_INVALID_PARAM:               return "INVALID_PARAM";
    case OZAYN_REG_ERR_LIMIT_REACHED:               return "LIMIT_REACHED";
    case OZAYN_REG_ERR_NOT_FOUND:                   return "NOT_FOUND";
    case OZAYN_REG_ERR_COMPONENT_INVALID:           return "COMPONENT_INVALID";
    case OZAYN_REG_ERR_COMPONENT_EXISTS:            return "COMPONENT_EXISTS";
    case OZAYN_REG_ERR_COMPONENT_NOT_FOUND:         return "COMPONENT_NOT_FOUND";
    case OZAYN_REG_ERR_COMPONENT_STATE_INVALID:     return "COMPONENT_STATE_INVALID";
    case OZAYN_REG_ERR_CAPABILITY_INVALID:          return "CAPABILITY_INVALID";
    case OZAYN_REG_ERR_CAPABILITY_EXISTS:           return "CAPABILITY_EXISTS";
    case OZAYN_REG_ERR_CAPABILITY_NOT_FOUND:        return "CAPABILITY_NOT_FOUND";
    case OZAYN_REG_ERR_CAPABILITY_UNAVAILABLE:      return "CAPABILITY_UNAVAILABLE";
    case OZAYN_REG_ERR_CAPABILITY_PROVIDER_MISSING: return "CAPABILITY_PROVIDER_MISSING";
    case OZAYN_REG_ERR_CAPABILITY_DEPENDENCY_INVALID: return "CAPABILITY_DEPENDENCY_INVALID";
    case OZAYN_REG_ERR_DISCOVERY_FAILED:            return "DISCOVERY_FAILED";
    case OZAYN_REG_ERR_UNAVAILABLE:                 return "UNAVAILABLE";
    case OZAYN_REG_ERR_UNREGISTRATION_FAILED:       return "UNREGISTRATION_FAILED";
    case OZAYN_REG_ERR_STATE_TRANSITION:            return "STATE_TRANSITION";
    case OZAYN_REG_ERR_STALE_DATA:                  return "STALE_DATA";
    }
    return "UNKNOWN";
}

/* ============================================================
 * SECTION 19 — NAME HELPERS — COMPONENT STATES
 * ============================================================ */

const char *ozayn_reg_comp_state_name(ozayn_reg_comp_state_t s)
{
    switch (s) {
    case OZAYN_REG_COMP_UNINITIALIZED:  return "UNINITIALIZED";
    case OZAYN_REG_COMP_INITIALIZING:   return "INITIALIZING";
    case OZAYN_REG_COMP_READY:          return "READY";
    case OZAYN_REG_COMP_ACTIVE:         return "ACTIVE";
    case OZAYN_REG_COMP_PAUSED:         return "PAUSED";
    case OZAYN_REG_COMP_STOPPING:       return "STOPPING";
    case OZAYN_REG_COMP_STOPPED:        return "STOPPED";
    case OZAYN_REG_COMP_DEGRADED:       return "DEGRADED";
    case OZAYN_REG_COMP_ERROR:          return "ERROR";
    case OZAYN_REG_COMP_UNAVAILABLE:    return "UNAVAILABLE";
    case OZAYN_REG_COMP_UNKNOWN:        return "UNKNOWN";
    }
    return "UNKNOWN";
}

/* ============================================================
 * SECTION 20 — NAME HELPERS — COMPONENT TYPES
 * ============================================================ */

const char *ozayn_reg_comp_type_name(ozayn_reg_comp_type_t t)
{
    switch (t) {
    case OZAYN_REG_COMP_TYPE_CORE:           return "CORE";
    case OZAYN_REG_COMP_TYPE_RUNTIME:        return "RUNTIME";
    case OZAYN_REG_COMP_TYPE_MODULE:         return "MODULE";
    case OZAYN_REG_COMP_TYPE_PLUGIN:         return "PLUGIN";
    case OZAYN_REG_COMP_TYPE_TASK_SYSTEM:    return "TASK_SYSTEM";
    case OZAYN_REG_COMP_TYPE_PROCESS_SYSTEM: return "PROCESS_SYSTEM";
    case OZAYN_REG_COMP_TYPE_EVENT_SYSTEM:   return "EVENT_SYSTEM";
    case OZAYN_REG_COMP_TYPE_SECURITY:       return "SECURITY";
    case OZAYN_REG_COMP_TYPE_STORAGE:        return "STORAGE";
    case OZAYN_REG_COMP_TYPE_DEVICE:         return "DEVICE";
    case OZAYN_REG_COMP_TYPE_VISION:         return "VISION";
    case OZAYN_REG_COMP_TYPE_VOICE:          return "VOICE";
    case OZAYN_REG_COMP_TYPE_GESTURE:        return "GESTURE";
    case OZAYN_REG_COMP_TYPE_AI:             return "AI";
    case OZAYN_REG_COMP_TYPE_MEMORY:         return "MEMORY";
    case OZAYN_REG_COMP_TYPE_ARWE:           return "ARWE";
    case OZAYN_REG_COMP_TYPE_WEB_INTELLIGENCE: return "WEB_INTELLIGENCE";
    case OZAYN_REG_COMP_TYPE_GUI:            return "GUI";
    case OZAYN_REG_COMP_TYPE_CUSTOM:         return "CUSTOM";
    }
    return "UNKNOWN";
}

/* ============================================================
 * SECTION 21 — NAME HELPERS — AVAILABILITY
 * ============================================================ */

const char *ozayn_reg_availability_name(ozayn_reg_availability_t a)
{
    switch (a) {
    case OZAYN_REG_AVAIL_UNKNOWN:     return "UNKNOWN";
    case OZAYN_REG_AVAIL_AVAILABLE:   return "AVAILABLE";
    case OZAYN_REG_AVAIL_UNAVAILABLE: return "UNAVAILABLE";
    case OZAYN_REG_AVAIL_DEGRADED:    return "DEGRADED";
    }
    return "UNKNOWN";
}

/* ============================================================
 * SECTION 22 — NAME HELPERS — HEALTH
 * ============================================================ */

const char *ozayn_reg_health_name(ozayn_reg_health_t h)
{
    switch (h) {
    case OZAYN_REG_HEALTH_UNKNOWN:    return "UNKNOWN";
    case OZAYN_REG_HEALTH_HEALTHY:    return "HEALTHY";
    case OZAYN_REG_HEALTH_DEGRADED:   return "DEGRADED";
    case OZAYN_REG_HEALTH_UNHEALTHY:  return "UNHEALTHY";
    case OZAYN_REG_HEALTH_FAILED:     return "FAILED";
    }
    return "UNKNOWN";
}

/* ============================================================
 * SECTION 23 — NAME HELPERS — CAPABILITY STATES
 * ============================================================ */

const char *ozayn_reg_cap_state_name(ozayn_reg_cap_state_t s)
{
    switch (s) {
    case OZAYN_REG_CAP_STATE_UNKNOWN:     return "UNKNOWN";
    case OZAYN_REG_CAP_STATE_AVAILABLE:   return "AVAILABLE";
    case OZAYN_REG_CAP_STATE_ACTIVE:      return "ACTIVE";
    case OZAYN_REG_CAP_STATE_DISABLED:    return "DISABLED";
    case OZAYN_REG_CAP_STATE_UNAVAILABLE: return "UNAVAILABLE";
    case OZAYN_REG_CAP_STATE_UNSUPPORTED: return "UNSUPPORTED";
    case OZAYN_REG_CAP_STATE_ERROR:       return "ERROR";
    }
    return "UNKNOWN";
}

/* ============================================================
 * SECTION 24 — NAME HELPERS — CAPABILITY CATEGORIES
 * ============================================================ */

const char *ozayn_reg_cap_category_name(ozayn_reg_cap_category_t c)
{
    switch (c) {
    case OZAYN_REG_CAP_CAT_SYSTEM:        return "SYSTEM";
    case OZAYN_REG_CAP_CAT_CORE:          return "CORE";
    case OZAYN_REG_CAP_CAT_SECURITY:      return "SECURITY";
    case OZAYN_REG_CAP_CAT_DEVICE:        return "DEVICE";
    case OZAYN_REG_CAP_CAT_INTELLIGENCE:  return "INTELLIGENCE";
    case OZAYN_REG_CAP_CAT_ARWE:          return "ARWE";
    case OZAYN_REG_CAP_CAT_CUSTOM:        return "CUSTOM";
    }
    return "UNKNOWN";
}

/* ============================================================
 * SECTION 25 — NAME HELPERS — ASSURANCE
 * ============================================================ */

const char *ozayn_reg_assurance_name(ozayn_reg_assurance_t a)
{
    switch (a) {
    case OZAYN_REG_ASSURANCE_PUBLIC:          return "PUBLIC";
    case OZAYN_REG_ASSURANCE_AUTHENTICATED:   return "AUTHENTICATED";
    case OZAYN_REG_ASSURANCE_MFA_REQUIRED:    return "MFA_REQUIRED";
    case OZAYN_REG_ASSURANCE_HIGH_ASSURANCE:  return "HIGH_ASSURANCE";
    }
    return "UNKNOWN";
}

/* ============================================================
 * SECTION 26 — NAME HELPERS — REGISTRY EVENTS
 * ============================================================ */

const char *ozayn_reg_event_type_name(ozayn_reg_event_type_t e)
{
    switch (e) {
    case OZAYN_REG_EVENT_COMPONENT_REGISTERED:     return "COMPONENT_REGISTERED";
    case OZAYN_REG_EVENT_COMPONENT_UNREGISTERED:   return "COMPONENT_UNREGISTERED";
    case OZAYN_REG_EVENT_COMPONENT_STATE_CHANGED:  return "COMPONENT_STATE_CHANGED";
    case OZAYN_REG_EVENT_COMPONENT_AVAIL_CHANGED:  return "COMPONENT_AVAIL_CHANGED";
    case OZAYN_REG_EVENT_COMPONENT_HEALTH_CHANGED: return "COMPONENT_HEALTH_CHANGED";
    case OZAYN_REG_EVENT_CAPABILITY_REGISTERED:    return "CAPABILITY_REGISTERED";
    case OZAYN_REG_EVENT_CAPABILITY_REMOVED:       return "CAPABILITY_REMOVED";
    case OZAYN_REG_EVENT_CAPABILITY_STATE_CHANGED: return "CAPABILITY_STATE_CHANGED";
    case OZAYN_REG_EVENT_CAPABILITY_AVAIL_CHANGED: return "CAPABILITY_AVAIL_CHANGED";
    case OZAYN_REG_EVENT_DISCOVERY_COMPLETED:      return "DISCOVERY_COMPLETED";
    case OZAYN_REG_EVENT_STALE_DATA_DETECTED:      return "STALE_DATA_DETECTED";
    }
    return "UNKNOWN";
}

/* ============================================================
 * SECTION 27 — LIFECYCLE
 * ============================================================ */

ozayn_reg_err_t ozayn_reg_service_init(
    ozayn_reg_service_t *svc,
    const ozayn_reg_service_config_t *cfg)
{
    if (!svc) return OZAYN_REG_ERR_NULL;
    if (svc->initialized) return OZAYN_REG_ERR_ALREADY_INITIALIZED;

    memset(svc, 0, sizeof(*svc));

    if (cfg) {
        svc->audit = cfg->audit;
        svc->control_room = cfg->control_room;
    }

    svc->policy = ozayn_reg_default_policy();
    svc->initialized = 1;

    _audit_event(svc, "INIT", "Component Registry initialized");
    return OZAYN_REG_OK;
}

void ozayn_reg_service_shutdown(ozayn_reg_service_t *svc)
{
    if (!svc) return;
    _audit_event(svc, "SHUTDOWN", "Component Registry shutting down");
    svc->initialized = 0;
}

int ozayn_reg_service_is_initialized(const ozayn_reg_service_t *svc)
{
    return svc ? svc->initialized : 0;
}

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
    const char *metadata)
{
    if (!svc) return OZAYN_REG_ERR_NULL;
    if (!svc->initialized) return OZAYN_REG_ERR_NOT_INITIALIZED;
    if (!component_id || !component_id[0]) return OZAYN_REG_ERR_INVALID_PARAM;
    if (!name || !name[0]) return OZAYN_REG_ERR_INVALID_PARAM;
    if (svc->component_count >= svc->policy.max_components)
        return OZAYN_REG_ERR_LIMIT_REACHED;
    if (svc->policy.require_provider && (!provider || !provider[0]))
        return OZAYN_REG_ERR_CAPABILITY_PROVIDER_MISSING;

    /* Check duplicate */
    for (int i = 0; i < svc->component_count; i++) {
        if (strcmp(svc->components[i].component_id, component_id) == 0)
            return OZAYN_REG_ERR_COMPONENT_EXISTS;
    }

    ozayn_reg_component_t *comp = &svc->components[svc->component_count];
    memset(comp, 0, sizeof(*comp));
    strncpy(comp->component_id, component_id, OZAYN_REG_MAX_ID_LEN - 1);
    strncpy(comp->name, name, OZAYN_REG_MAX_NAME_LEN - 1);
    if (version) strncpy(comp->version, version, OZAYN_REG_MAX_VERSION_LEN - 1);
    comp->type = type;
    comp->state = OZAYN_REG_COMP_INITIALIZING;
    comp->availability = OZAYN_REG_AVAIL_UNKNOWN;
    comp->health = OZAYN_REG_HEALTH_UNKNOWN;
    if (provider) strncpy(comp->provider, provider, OZAYN_REG_MAX_NAME_LEN - 1);
    comp->registration_time = time(NULL);
    comp->last_update = comp->registration_time;
    if (metadata) strncpy(comp->metadata, metadata, OZAYN_REG_MAX_META_LEN - 1);
    comp->active = 1;
    svc->component_count++;
    svc->total_registrations++;


    _record_event(svc, OZAYN_REG_EVENT_COMPONENT_REGISTERED,
                  component_id, NULL, name);
    char detail[256];
    snprintf(detail, sizeof(detail), "COMP:%s NAME:%s TYPE:%s",
             component_id, name, ozayn_reg_comp_type_name(type));
    _audit_event(svc, "COMP_REGISTER", detail);

    return OZAYN_REG_OK;
}

ozayn_reg_err_t ozayn_reg_unregister_component(
    ozayn_reg_service_t *svc,
    const char *component_id)
{
    if (!svc) return OZAYN_REG_ERR_NULL;
    if (!svc->initialized) return OZAYN_REG_ERR_NOT_INITIALIZED;
    if (!component_id || !component_id[0]) return OZAYN_REG_ERR_INVALID_PARAM;

    int idx = -1;
    for (int i = 0; i < svc->component_count; i++) {
        if (strcmp(svc->components[i].component_id, component_id) == 0) {
            idx = i;
            break;
        }
    }
    if (idx < 0) return OZAYN_REG_ERR_COMPONENT_NOT_FOUND;

    /* Remove associated capabilities */
    for (int i = svc->capability_count - 1; i >= 0; i--) {
        if (strcmp(svc->capabilities[i].provider_component, component_id) == 0) {
            _record_event(svc, OZAYN_REG_EVENT_CAPABILITY_REMOVED,
                          component_id, svc->capabilities[i].cap_id,
                          "Provider unregistered");
            /* Shift remaining capabilities */
            for (int j = i; j < svc->capability_count - 1; j++) {
                svc->capabilities[j] = svc->capabilities[j + 1];
            }
            svc->capability_count--;
            svc->total_cap_removals++;
        }
    }

    /* Shift remaining components */
    for (int i = idx; i < svc->component_count - 1; i++) {
        svc->components[i] = svc->components[i + 1];
    }
    svc->component_count--;
    svc->total_unregistrations++;


    _record_event(svc, OZAYN_REG_EVENT_COMPONENT_UNREGISTERED,
                  component_id, NULL, NULL);
    char detail[256];
    snprintf(detail, sizeof(detail), "COMP:%s", component_id);
    _audit_event(svc, "COMP_UNREGISTER", detail);

    return OZAYN_REG_OK;
}

ozayn_reg_component_t *ozayn_reg_get_component(
    ozayn_reg_service_t *svc,
    const char *component_id)
{
    if (!svc || !svc->initialized || !component_id) return NULL;
    for (int i = 0; i < svc->component_count; i++) {
        if (strcmp(svc->components[i].component_id, component_id) == 0)
            return &svc->components[i];
    }
    return NULL;
}

int ozayn_reg_component_count(const ozayn_reg_service_t *svc)
{
    return svc ? svc->component_count : 0;
}

int ozayn_reg_component_exists(
    const ozayn_reg_service_t *svc,
    const char *component_id)
{
    if (!svc || !svc->initialized || !component_id) return 0;
    for (int i = 0; i < svc->component_count; i++) {
        if (strcmp(svc->components[i].component_id, component_id) == 0)
            return 1;
    }
    return 0;
}

/* ============================================================
 * SECTION 29 — COMPONENT STATE MANAGEMENT
 * ============================================================ */

ozayn_reg_err_t ozayn_reg_update_component_state(
    ozayn_reg_service_t *svc,
    const char *component_id,
    ozayn_reg_comp_state_t new_state)
{
    if (!svc) return OZAYN_REG_ERR_NULL;
    if (!svc->initialized) return OZAYN_REG_ERR_NOT_INITIALIZED;

    ozayn_reg_component_t *comp = ozayn_reg_get_component(svc, component_id);
    if (!comp) return OZAYN_REG_ERR_COMPONENT_NOT_FOUND;

    ozayn_reg_comp_state_t old_state = comp->state;
    comp->state = new_state;
    comp->last_update = time(NULL);


    if (old_state != new_state) {
        _record_event(svc, OZAYN_REG_EVENT_COMPONENT_STATE_CHANGED,
                      component_id, NULL,
                      ozayn_reg_comp_state_name(new_state));
    }
    return OZAYN_REG_OK;
}

ozayn_reg_err_t ozayn_reg_update_component_availability(
    ozayn_reg_service_t *svc,
    const char *component_id,
    ozayn_reg_availability_t availability)
{
    if (!svc) return OZAYN_REG_ERR_NULL;
    if (!svc->initialized) return OZAYN_REG_ERR_NOT_INITIALIZED;

    ozayn_reg_component_t *comp = ozayn_reg_get_component(svc, component_id);
    if (!comp) return OZAYN_REG_ERR_COMPONENT_NOT_FOUND;

    ozayn_reg_availability_t old = comp->availability;
    comp->availability = availability;
    comp->last_update = time(NULL);


    if (old != availability) {
        _record_event(svc, OZAYN_REG_EVENT_COMPONENT_AVAIL_CHANGED,
                      component_id, NULL,
                      ozayn_reg_availability_name(availability));
    }
    return OZAYN_REG_OK;
}

ozayn_reg_err_t ozayn_reg_update_component_health(
    ozayn_reg_service_t *svc,
    const char *component_id,
    ozayn_reg_health_t health)
{
    if (!svc) return OZAYN_REG_ERR_NULL;
    if (!svc->initialized) return OZAYN_REG_ERR_NOT_INITIALIZED;

    ozayn_reg_component_t *comp = ozayn_reg_get_component(svc, component_id);
    if (!comp) return OZAYN_REG_ERR_COMPONENT_NOT_FOUND;

    ozayn_reg_health_t old = comp->health;
    comp->health = health;
    comp->last_update = time(NULL);


    if (old != health) {
        _record_event(svc, OZAYN_REG_EVENT_COMPONENT_HEALTH_CHANGED,
                      component_id, NULL,
                      ozayn_reg_health_name(health));
    }
    return OZAYN_REG_OK;
}

/* ============================================================
 * SECTION 30 — COMPONENT QUERIES
 * ============================================================ */

int ozayn_reg_list_components(
    const ozayn_reg_service_t *svc,
    ozayn_reg_component_t **out_components,
    int max_count)
{
    if (!svc || !svc->initialized || !out_components || max_count <= 0) return 0;
    int count = svc->component_count < max_count ? svc->component_count : max_count;
    for (int i = 0; i < count; i++) {
        out_components[i] = (ozayn_reg_component_t *)&svc->components[i];
    }
    return count;
}

int ozayn_reg_list_components_by_type(
    const ozayn_reg_service_t *svc,
    ozayn_reg_comp_type_t type,
    ozayn_reg_component_t **out_components,
    int max_count)
{
    if (!svc || !svc->initialized || !out_components || max_count <= 0) return 0;
    int count = 0;
    for (int i = 0; i < svc->component_count && count < max_count; i++) {
        if (svc->components[i].type == type) {
            out_components[count++] = (ozayn_reg_component_t *)&svc->components[i];
        }
    }
    return count;
}

int ozayn_reg_list_active_components(
    const ozayn_reg_service_t *svc,
    ozayn_reg_component_t **out_components,
    int max_count)
{
    if (!svc || !svc->initialized || !out_components || max_count <= 0) return 0;
    int count = 0;
    for (int i = 0; i < svc->component_count && count < max_count; i++) {
        if (svc->components[i].state == OZAYN_REG_COMP_ACTIVE) {
            out_components[count++] = (ozayn_reg_component_t *)&svc->components[i];
        }
    }
    return count;
}

int ozayn_reg_list_available_components(
    const ozayn_reg_service_t *svc,
    ozayn_reg_component_t **out_components,
    int max_count)
{
    if (!svc || !svc->initialized || !out_components || max_count <= 0) return 0;
    int count = 0;
    for (int i = 0; i < svc->component_count && count < max_count; i++) {
        if (svc->components[i].availability == OZAYN_REG_AVAIL_AVAILABLE) {
            out_components[count++] = (ozayn_reg_component_t *)&svc->components[i];
        }
    }
    return count;
}

int ozayn_reg_list_unavailable_components(
    const ozayn_reg_service_t *svc,
    ozayn_reg_component_t **out_components,
    int max_count)
{
    if (!svc || !svc->initialized || !out_components || max_count <= 0) return 0;
    int count = 0;
    for (int i = 0; i < svc->component_count && count < max_count; i++) {
        if (svc->components[i].availability == OZAYN_REG_AVAIL_UNAVAILABLE) {
            out_components[count++] = (ozayn_reg_component_t *)&svc->components[i];
        }
    }
    return count;
}

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
    const char *metadata)
{
    if (!svc) return OZAYN_REG_ERR_NULL;
    if (!svc->initialized) return OZAYN_REG_ERR_NOT_INITIALIZED;
    if (!cap_id || !cap_id[0]) return OZAYN_REG_ERR_INVALID_PARAM;
    if (!name || !name[0]) return OZAYN_REG_ERR_INVALID_PARAM;
    if (!provider_component || !provider_component[0])
        return OZAYN_REG_ERR_CAPABILITY_PROVIDER_MISSING;
    if (svc->capability_count >= svc->policy.max_capabilities)
        return OZAYN_REG_ERR_LIMIT_REACHED;

    /* Validate provider exists */
    if (!ozayn_reg_component_exists(svc, provider_component))
        return OZAYN_REG_ERR_CAPABILITY_PROVIDER_MISSING;

    /* Check duplicate */
    for (int i = 0; i < svc->capability_count; i++) {
        if (strcmp(svc->capabilities[i].cap_id, cap_id) == 0)
            return OZAYN_REG_ERR_CAPABILITY_EXISTS;
    }

    ozayn_reg_capability_desc_t *cap = &svc->capabilities[svc->capability_count];
    memset(cap, 0, sizeof(*cap));
    strncpy(cap->cap_id, cap_id, OZAYN_REG_MAX_ID_LEN - 1);
    strncpy(cap->name, name, OZAYN_REG_MAX_NAME_LEN - 1);
    if (version) strncpy(cap->version, version, OZAYN_REG_MAX_VERSION_LEN - 1);
    if (description) strncpy(cap->description, description, OZAYN_REG_MAX_DESC_LEN - 1);
    strncpy(cap->provider_component, provider_component, OZAYN_REG_MAX_ID_LEN - 1);
    cap->state = OZAYN_REG_CAP_STATE_AVAILABLE;
    cap->availability = OZAYN_REG_AVAIL_AVAILABLE;
    cap->category = category;
    cap->required_assurance = required_assurance;
    cap->registration_time = time(NULL);
    cap->last_update = cap->registration_time;
    if (metadata) strncpy(cap->metadata, metadata, OZAYN_REG_MAX_META_LEN - 1);
    cap->active = 1;
    svc->capability_count++;
    svc->total_cap_registrations++;


    _record_event(svc, OZAYN_REG_EVENT_CAPABILITY_REGISTERED,
                  provider_component, cap_id, name);
    char detail[256];
    snprintf(detail, sizeof(detail), "CAP:%s NAME:%s PROV:%s",
             cap_id, name, provider_component);
    _audit_event(svc, "CAP_REGISTER", detail);

    return OZAYN_REG_OK;
}

ozayn_reg_err_t ozayn_reg_unregister_capability(
    ozayn_reg_service_t *svc,
    const char *cap_id)
{
    if (!svc) return OZAYN_REG_ERR_NULL;
    if (!svc->initialized) return OZAYN_REG_ERR_NOT_INITIALIZED;
    if (!cap_id || !cap_id[0]) return OZAYN_REG_ERR_INVALID_PARAM;

    int idx = -1;
    for (int i = 0; i < svc->capability_count; i++) {
        if (strcmp(svc->capabilities[i].cap_id, cap_id) == 0) {
            idx = i;
            break;
        }
    }
    if (idx < 0) return OZAYN_REG_ERR_CAPABILITY_NOT_FOUND;

    char prov[OZAYN_REG_MAX_ID_LEN];
    strncpy(prov, svc->capabilities[idx].provider_component, OZAYN_REG_MAX_ID_LEN - 1);

    for (int i = idx; i < svc->capability_count - 1; i++) {
        svc->capabilities[i] = svc->capabilities[i + 1];
    }
    svc->capability_count--;
    svc->total_cap_removals++;


    _record_event(svc, OZAYN_REG_EVENT_CAPABILITY_REMOVED, prov, cap_id, NULL);
    char detail[256];
    snprintf(detail, sizeof(detail), "CAP:%s", cap_id);
    _audit_event(svc, "CAP_UNREGISTER", detail);

    return OZAYN_REG_OK;
}

ozayn_reg_capability_desc_t *ozayn_reg_get_capability(
    ozayn_reg_service_t *svc,
    const char *cap_id)
{
    if (!svc || !svc->initialized || !cap_id) return NULL;
    for (int i = 0; i < svc->capability_count; i++) {
        if (strcmp(svc->capabilities[i].cap_id, cap_id) == 0)
            return &svc->capabilities[i];
    }
    return NULL;
}

int ozayn_reg_capability_count(const ozayn_reg_service_t *svc)
{
    return svc ? svc->capability_count : 0;
}

int ozayn_reg_capability_exists(
    const ozayn_reg_service_t *svc,
    const char *cap_id)
{
    if (!svc || !svc->initialized || !cap_id) return 0;
    for (int i = 0; i < svc->capability_count; i++) {
        if (strcmp(svc->capabilities[i].cap_id, cap_id) == 0)
            return 1;
    }
    return 0;
}

/* ============================================================
 * SECTION 32 — CAPABILITY STATE MANAGEMENT
 * ============================================================ */

ozayn_reg_err_t ozayn_reg_update_capability_state(
    ozayn_reg_service_t *svc,
    const char *cap_id,
    ozayn_reg_cap_state_t new_state)
{
    if (!svc) return OZAYN_REG_ERR_NULL;
    if (!svc->initialized) return OZAYN_REG_ERR_NOT_INITIALIZED;

    ozayn_reg_capability_desc_t *cap = ozayn_reg_get_capability(svc, cap_id);
    if (!cap) return OZAYN_REG_ERR_CAPABILITY_NOT_FOUND;

    ozayn_reg_cap_state_t old = cap->state;
    cap->state = new_state;
    cap->last_update = time(NULL);


    if (old != new_state) {
        _record_event(svc, OZAYN_REG_EVENT_CAPABILITY_STATE_CHANGED,
                      cap->provider_component, cap_id,
                      ozayn_reg_cap_state_name(new_state));
    }
    return OZAYN_REG_OK;
}

ozayn_reg_err_t ozayn_reg_update_capability_availability(
    ozayn_reg_service_t *svc,
    const char *cap_id,
    ozayn_reg_availability_t availability)
{
    if (!svc) return OZAYN_REG_ERR_NULL;
    if (!svc->initialized) return OZAYN_REG_ERR_NOT_INITIALIZED;

    ozayn_reg_capability_desc_t *cap = ozayn_reg_get_capability(svc, cap_id);
    if (!cap) return OZAYN_REG_ERR_CAPABILITY_NOT_FOUND;

    ozayn_reg_availability_t old = cap->availability;
    cap->availability = availability;
    cap->last_update = time(NULL);


    if (old != availability) {
        _record_event(svc, OZAYN_REG_EVENT_CAPABILITY_AVAIL_CHANGED,
                      cap->provider_component, cap_id,
                      ozayn_reg_availability_name(availability));
    }
    return OZAYN_REG_OK;
}

/* ============================================================
 * SECTION 33 — CAPABILITY DEPENDENCIES & PERMISSIONS
 * ============================================================ */

ozayn_reg_err_t ozayn_reg_add_capability_dependency(
    ozayn_reg_service_t *svc,
    const char *cap_id,
    const char *dependency_cap_id)
{
    if (!svc) return OZAYN_REG_ERR_NULL;
    if (!svc->initialized) return OZAYN_REG_ERR_NOT_INITIALIZED;
    if (!cap_id || !dependency_cap_id) return OZAYN_REG_ERR_INVALID_PARAM;

    ozayn_reg_capability_desc_t *cap = ozayn_reg_get_capability(svc, cap_id);
    if (!cap) return OZAYN_REG_ERR_CAPABILITY_NOT_FOUND;

    if (!ozayn_reg_capability_exists(svc, dependency_cap_id))
        return OZAYN_REG_ERR_CAPABILITY_DEPENDENCY_INVALID;

    if (cap->dependency_count >= OZAYN_REG_MAX_DEPENDENCIES)
        return OZAYN_REG_ERR_LIMIT_REACHED;

    /* Check not already present */
    for (int i = 0; i < cap->dependency_count; i++) {
        if (strcmp(cap->dependencies[i], dependency_cap_id) == 0)
            return OZAYN_REG_OK; /* Already registered */
    }

    strncpy(cap->dependencies[cap->dependency_count], dependency_cap_id,
            OZAYN_REG_MAX_ID_LEN - 1);
    cap->dependency_count++;
    cap->last_update = time(NULL);
    return OZAYN_REG_OK;
}

ozayn_reg_err_t ozayn_reg_add_capability_permission(
    ozayn_reg_service_t *svc,
    const char *cap_id,
    const char *permission_ref)
{
    if (!svc) return OZAYN_REG_ERR_NULL;
    if (!svc->initialized) return OZAYN_REG_ERR_NOT_INITIALIZED;
    if (!cap_id || !permission_ref) return OZAYN_REG_ERR_INVALID_PARAM;

    ozayn_reg_capability_desc_t *cap = ozayn_reg_get_capability(svc, cap_id);
    if (!cap) return OZAYN_REG_ERR_CAPABILITY_NOT_FOUND;

    if (cap->permission_count >= OZAYN_REG_MAX_PERMISSIONS)
        return OZAYN_REG_ERR_LIMIT_REACHED;

    /* Check not already present */
    for (int i = 0; i < cap->permission_count; i++) {
        if (strcmp(cap->required_permissions[i], permission_ref) == 0)
            return OZAYN_REG_OK; /* Already registered */
    }

    strncpy(cap->required_permissions[cap->permission_count], permission_ref,
            OZAYN_REG_MAX_ID_LEN - 1);
    cap->permission_count++;
    cap->last_update = time(NULL);
    return OZAYN_REG_OK;
}

/* ============================================================
 * SECTION 34 — CAPABILITY QUERIES
 * ============================================================ */

int ozayn_reg_list_capabilities(
    const ozayn_reg_service_t *svc,
    ozayn_reg_capability_desc_t **out_caps,
    int max_count)
{
    if (!svc || !svc->initialized || !out_caps || max_count <= 0) return 0;
    int count = svc->capability_count < max_count ? svc->capability_count : max_count;
    for (int i = 0; i < count; i++) {
        out_caps[i] = (ozayn_reg_capability_desc_t *)&svc->capabilities[i];
    }
    return count;
}

int ozayn_reg_list_capabilities_by_component(
    const ozayn_reg_service_t *svc,
    const char *component_id,
    ozayn_reg_capability_desc_t **out_caps,
    int max_count)
{
    if (!svc || !svc->initialized || !component_id || !out_caps || max_count <= 0) return 0;
    int count = 0;
    for (int i = 0; i < svc->capability_count && count < max_count; i++) {
        if (strcmp(svc->capabilities[i].provider_component, component_id) == 0) {
            out_caps[count++] = (ozayn_reg_capability_desc_t *)&svc->capabilities[i];
        }
    }
    return count;
}

int ozayn_reg_list_capabilities_by_category(
    const ozayn_reg_service_t *svc,
    ozayn_reg_cap_category_t category,
    ozayn_reg_capability_desc_t **out_caps,
    int max_count)
{
    if (!svc || !svc->initialized || !out_caps || max_count <= 0) return 0;
    int count = 0;
    for (int i = 0; i < svc->capability_count && count < max_count; i++) {
        if (svc->capabilities[i].category == category) {
            out_caps[count++] = (ozayn_reg_capability_desc_t *)&svc->capabilities[i];
        }
    }
    return count;
}

int ozayn_reg_list_available_capabilities(
    const ozayn_reg_service_t *svc,
    ozayn_reg_capability_desc_t **out_caps,
    int max_count)
{
    if (!svc || !svc->initialized || !out_caps || max_count <= 0) return 0;
    int count = 0;
    for (int i = 0; i < svc->capability_count && count < max_count; i++) {
        if (svc->capabilities[i].availability == OZAYN_REG_AVAIL_AVAILABLE) {
            out_caps[count++] = (ozayn_reg_capability_desc_t *)&svc->capabilities[i];
        }
    }
    return count;
}

int ozayn_reg_list_active_capabilities(
    const ozayn_reg_service_t *svc,
    ozayn_reg_capability_desc_t **out_caps,
    int max_count)
{
    if (!svc || !svc->initialized || !out_caps || max_count <= 0) return 0;
    int count = 0;
    for (int i = 0; i < svc->capability_count && count < max_count; i++) {
        if (svc->capabilities[i].state == OZAYN_REG_CAP_STATE_ACTIVE) {
            out_caps[count++] = (ozayn_reg_capability_desc_t *)&svc->capabilities[i];
        }
    }
    return count;
}

int ozayn_reg_is_capability_available(
    const ozayn_reg_service_t *svc,
    const char *cap_id)
{
    if (!svc || !svc->initialized || !cap_id) return 0;
    for (int i = 0; i < svc->capability_count; i++) {
        if (strcmp(svc->capabilities[i].cap_id, cap_id) == 0)
            return svc->capabilities[i].availability == OZAYN_REG_AVAIL_AVAILABLE &&
                   svc->capabilities[i].state != OZAYN_REG_CAP_STATE_DISABLED;
    }
    return 0;
}

/* ============================================================
 * SECTION 35 — CAPABILITY DISCOVERY
 * ============================================================ */

ozayn_reg_err_t ozayn_reg_discover_all(
    ozayn_reg_service_t *svc,
    ozayn_reg_snapshot_t *out_snapshot)
{
    if (!svc) return OZAYN_REG_ERR_NULL;
    if (!svc->initialized) return OZAYN_REG_ERR_NOT_INITIALIZED;

    /* Detect stale data */
    ozayn_reg_detect_stale_components(svc);

    /* Take snapshot */
    if (out_snapshot) {
        ozayn_reg_get_snapshot(svc, out_snapshot);
    }

    svc->total_discoveries++;


    _record_event(svc, OZAYN_REG_EVENT_DISCOVERY_COMPLETED, NULL, NULL, "ALL");
    _audit_event(svc, "DISCOVER_ALL", "Full discovery completed");

    return OZAYN_REG_OK;
}

ozayn_reg_err_t ozayn_reg_discover_component(
    ozayn_reg_service_t *svc,
    const char *component_id)
{
    if (!svc) return OZAYN_REG_ERR_NULL;
    if (!svc->initialized) return OZAYN_REG_ERR_NOT_INITIALIZED;
    if (!component_id) return OZAYN_REG_ERR_INVALID_PARAM;

    ozayn_reg_component_t *comp = ozayn_reg_get_component(svc, component_id);
    if (!comp) return OZAYN_REG_ERR_COMPONENT_NOT_FOUND;

    /* Check staleness */
    time_t now = time(NULL);
    if ((now - comp->last_update) > svc->policy.stale_threshold_seconds) {
        comp->state = OZAYN_REG_COMP_UNKNOWN;
        comp->availability = OZAYN_REG_AVAIL_UNAVAILABLE;
        _record_event(svc, OZAYN_REG_EVENT_STALE_DATA_DETECTED,
                      component_id, NULL, "Stale component detected");
        svc->total_stale_detections++;
    }

    svc->total_discoveries++;

    return OZAYN_REG_OK;
}

ozayn_reg_err_t ozayn_reg_discover_capability(
    ozayn_reg_service_t *svc,
    const char *cap_id)
{
    if (!svc) return OZAYN_REG_ERR_NULL;
    if (!svc->initialized) return OZAYN_REG_ERR_NOT_INITIALIZED;
    if (!cap_id) return OZAYN_REG_ERR_INVALID_PARAM;

    ozayn_reg_capability_desc_t *cap = ozayn_reg_get_capability(svc, cap_id);
    if (!cap) return OZAYN_REG_ERR_CAPABILITY_NOT_FOUND;

    /* Check provider still exists */
    if (!ozayn_reg_component_exists(svc, cap->provider_component)) {
        cap->state = OZAYN_REG_CAP_STATE_UNAVAILABLE;
        cap->availability = OZAYN_REG_AVAIL_UNAVAILABLE;
    }

    svc->total_discoveries++;

    return OZAYN_REG_OK;
}

ozayn_reg_err_t ozayn_reg_refresh(ozayn_reg_service_t *svc)
{
    if (!svc) return OZAYN_REG_ERR_NULL;
    if (!svc->initialized) return OZAYN_REG_ERR_NOT_INITIALIZED;

    /* Refresh all capabilities based on provider state */
    for (int i = 0; i < svc->capability_count; i++) {
        ozayn_reg_component_t *prov = ozayn_reg_get_component(
            svc, svc->capabilities[i].provider_component);
        if (!prov) {
            svc->capabilities[i].state = OZAYN_REG_CAP_STATE_UNAVAILABLE;
            svc->capabilities[i].availability = OZAYN_REG_AVAIL_UNAVAILABLE;
        } else if (prov->state == OZAYN_REG_COMP_ACTIVE) {
            if (svc->capabilities[i].state == OZAYN_REG_CAP_STATE_AVAILABLE)
                svc->capabilities[i].state = OZAYN_REG_CAP_STATE_AVAILABLE;
        } else if (prov->state == OZAYN_REG_COMP_ERROR) {
            svc->capabilities[i].state = OZAYN_REG_CAP_STATE_ERROR;
        }
    }


    return OZAYN_REG_OK;
}

/* ============================================================
 * SECTION 36 — STALE DATA HANDLING
 * ============================================================ */

int ozayn_reg_detect_stale_components(ozayn_reg_service_t *svc)
{
    if (!svc || !svc->initialized) return 0;
    int stale = 0;
    time_t now = time(NULL);
    for (int i = 0; i < svc->component_count; i++) {
        if (svc->components[i].active &&
            (now - svc->components[i].last_update) > svc->policy.stale_threshold_seconds) {
            svc->components[i].state = OZAYN_REG_COMP_UNKNOWN;
            svc->components[i].availability = OZAYN_REG_AVAIL_UNAVAILABLE;
            stale++;
        }
    }
    if (stale > 0) {
        _record_event(svc, OZAYN_REG_EVENT_STALE_DATA_DETECTED, NULL, NULL, NULL);
        svc->total_stale_detections += stale;
    }
    return stale;
}

int ozayn_reg_cleanup_stale(ozayn_reg_service_t *svc)
{
    if (!svc || !svc->initialized) return 0;
    int cleaned = 0;
    time_t now = time(NULL);
    for (int i = svc->component_count - 1; i >= 0; i--) {
        if (svc->components[i].active &&
            (now - svc->components[i].last_update) > (svc->policy.stale_threshold_seconds * 2)) {
            /* Remove stale component and its capabilities */
            ozayn_reg_unregister_component(svc, svc->components[i].component_id);
            cleaned++;
        }
    }
    return cleaned;
}

/* ============================================================
 * SECTION 37 — SNAPSHOT
 * ============================================================ */

ozayn_reg_err_t ozayn_reg_get_snapshot(
    const ozayn_reg_service_t *svc,
    ozayn_reg_snapshot_t *out_snapshot)
{
    if (!svc) return OZAYN_REG_ERR_NULL;
    if (!svc->initialized) return OZAYN_REG_ERR_NOT_INITIALIZED;
    if (!out_snapshot) return OZAYN_REG_ERR_INVALID_PARAM;

    memset(out_snapshot, 0, sizeof(*out_snapshot));
    out_snapshot->snapshot_time = time(NULL);
    out_snapshot->total_components = svc->component_count;
    out_snapshot->total_capabilities = svc->capability_count;

    for (int i = 0; i < svc->component_count; i++) {
        if (svc->components[i].state == OZAYN_REG_COMP_ACTIVE)
            out_snapshot->active_components++;
        if (svc->components[i].availability == OZAYN_REG_AVAIL_AVAILABLE)
            out_snapshot->available_components++;
        if (svc->components[i].availability == OZAYN_REG_AVAIL_UNAVAILABLE)
            out_snapshot->unavailable_components++;
        if (svc->components[i].state == OZAYN_REG_COMP_ERROR)
            out_snapshot->failed_components++;
        if (!svc->components[i].active ||
            (time(NULL) - svc->components[i].last_update) > svc->policy.stale_threshold_seconds)
            out_snapshot->stale_components++;
    }

    for (int i = 0; i < svc->capability_count; i++) {
        if (svc->capabilities[i].state == OZAYN_REG_CAP_STATE_ACTIVE)
            out_snapshot->active_capabilities++;
        if (svc->capabilities[i].availability == OZAYN_REG_AVAIL_AVAILABLE)
            out_snapshot->available_capabilities++;
        if (svc->capabilities[i].state == OZAYN_REG_CAP_STATE_DISABLED)
            out_snapshot->disabled_capabilities++;
        if (svc->capabilities[i].state == OZAYN_REG_CAP_STATE_UNSUPPORTED)
            out_snapshot->unsupported_capabilities++;
    }

    ((ozayn_reg_service_t *)svc)->total_state_queries++;
    return OZAYN_REG_OK;
}

/* ============================================================
 * SECTION 38 — EVENT OBSERVATION
 * ============================================================ */

int ozayn_reg_event_count(const ozayn_reg_service_t *svc)
{
    return svc ? svc->event_count : 0;
}

ozayn_reg_err_t ozayn_reg_get_last_event(
    const ozayn_reg_service_t *svc,
    ozayn_reg_event_t *out_event)
{
    if (!svc) return OZAYN_REG_ERR_NULL;
    if (!svc->initialized) return OZAYN_REG_ERR_NOT_INITIALIZED;
    if (!out_event) return OZAYN_REG_ERR_INVALID_PARAM;
    if (svc->event_count == 0) return OZAYN_REG_ERR_NOT_FOUND;

    int idx = (svc->event_head + svc->event_count - 1) % OZAYN_REG_MAX_EVENTS;
    *out_event = svc->events[idx];
    return OZAYN_REG_OK;
}

/* ============================================================
 * SECTION 39 — POLICY
 * ============================================================ */

ozayn_reg_policy_t ozayn_reg_default_policy(void)
{
    ozayn_reg_policy_t p;
    memset(&p, 0, sizeof(p));
    p.enabled = 1;
    p.max_components = OZAYN_REG_MAX_COMPONENTS;
    p.max_capabilities = OZAYN_REG_MAX_CAPABILITIES;
    p.max_dependencies = OZAYN_REG_MAX_DEPENDENCIES;
    p.max_permissions = OZAYN_REG_MAX_PERMISSIONS;
    p.max_events = OZAYN_REG_MAX_EVENTS;
    p.stale_threshold_seconds = OZAYN_REG_STALE_THRESHOLD_SECONDS;
    p.require_provider = 1;
    p.validate_dependencies = 1;
    return p;
}

ozayn_reg_err_t ozayn_reg_set_policy(
    ozayn_reg_service_t *svc,
    const ozayn_reg_policy_t *policy)
{
    if (!svc) return OZAYN_REG_ERR_NULL;
    if (!svc->initialized) return OZAYN_REG_ERR_NOT_INITIALIZED;
    if (!policy) return OZAYN_REG_ERR_INVALID_PARAM;
    svc->policy = *policy;

    return OZAYN_REG_OK;
}

const ozayn_reg_policy_t *ozayn_reg_get_policy(const ozayn_reg_service_t *svc)
{
    if (!svc || !svc->initialized) return NULL;
    return &svc->policy;
}

/* ============================================================
 * SECTION 40 — AUDIT INTEGRATION
 * ============================================================ */

ozayn_reg_err_t ozayn_reg_audit_event(
    ozayn_reg_service_t *svc,
    const char *event_type,
    const char *detail)
{
    if (!svc) return OZAYN_REG_ERR_NULL;
    if (!svc->initialized) return OZAYN_REG_ERR_NOT_INITIALIZED;
    _audit_event(svc, event_type, detail);
    return OZAYN_REG_OK;
}

/* ============================================================
 * SECTION 41 — RESOURCE SAFETY
 * ============================================================ */

int ozayn_reg_components_full(const ozayn_reg_service_t *svc)
{
    if (!svc) return 1;
    return svc->component_count >= svc->policy.max_components;
}

int ozayn_reg_capabilities_full(const ozayn_reg_service_t *svc)
{
    if (!svc) return 1;
    return svc->capability_count >= svc->policy.max_capabilities;
}

/* ============================================================
 * SECTION 42 — STATISTICS
 * ============================================================ */

uint64_t ozayn_reg_total_registrations(const ozayn_reg_service_t *svc)
{
    return svc ? svc->total_registrations : 0;
}

uint64_t ozayn_reg_total_unregistrations(const ozayn_reg_service_t *svc)
{
    return svc ? svc->total_unregistrations : 0;
}

uint64_t ozayn_reg_total_discoveries(const ozayn_reg_service_t *svc)
{
    return svc ? svc->total_discoveries : 0;
}
