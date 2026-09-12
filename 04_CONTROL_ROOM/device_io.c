#include "device_io.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

/* ============================================================
 * SECTION 1 — INTERNAL HELPERS
 * ============================================================ */

static ozayn_dio_service_t _svc;

static int _find_device(const ozayn_dio_service_t *svc, const char *device_id)
{
    if (!svc || !device_id) return -1;
    for (int i = 0; i < svc->config.max_devices; i++) {
        if (svc->devices[i].active &&
            strncmp(svc->devices[i].device_id, device_id,
                    OZAYN_DIO_MAX_ID_LEN) == 0)
            return i;
    }
    return -1;
}

static int _find_reservation(const ozayn_dio_service_t *svc,
                             const char *reservation_id)
{
    if (!svc || !reservation_id) return -1;
    for (int i = 0; i < svc->config.max_reservations; i++) {
        if (svc->reservations[i].active &&
            strncmp(svc->reservations[i].reservation_id, reservation_id,
                    OZAYN_DIO_MAX_ID_LEN) == 0)
            return i;
    }
    return -1;
}

static int _find_device_slot(const ozayn_dio_service_t *svc)
{
    for (int i = 0; i < svc->config.max_devices; i++) {
        if (!svc->devices[i].active) return i;
    }
    return -1;
}

static int _find_reservation_slot(const ozayn_dio_service_t *svc)
{
    for (int i = 0; i < svc->config.max_reservations; i++) {
        if (!svc->reservations[i].active) return i;
    }
    return -1;
}

static void _emit_event(ozayn_dio_service_t *svc,
                         ozayn_dio_event_type_t type,
                         const char *device_id,
                         const char *message)
{
    if (!svc) return;
    int idx = (svc->event_head + svc->event_count) %
              svc->config.max_events;
    if (svc->event_count >= svc->config.max_events) {
        svc->event_head = (svc->event_head + 1) % svc->config.max_events;
    } else {
        svc->event_count++;
    }
    svc->events[idx].type = type;
    strncpy(svc->events[idx].device_id, device_id ? device_id : "",
            OZAYN_DIO_MAX_ID_LEN - 1);
    svc->events[idx].device_id[OZAYN_DIO_MAX_ID_LEN - 1] = '\0';
    strncpy(svc->events[idx].message, message ? message : "",
            OZAYN_DIO_MAX_DESCRIPTION_LEN - 1);
    svc->events[idx].message[OZAYN_DIO_MAX_DESCRIPTION_LEN - 1] = '\0';
    svc->events[idx].timestamp = time(NULL);
    svc->event_sequence++;
    svc->stats.total_events_emitted++;
}

/* ============================================================
 * SECTION 2 — LIFECYCLE
 * ============================================================ */

ozayn_dio_err_t ozayn_dio_service_init(ozayn_dio_service_t *svc,
                                        const ozayn_dio_service_config_t *cfg)
{
    if (!svc) return OZAYN_DIO_ERR_NULL;
    if (!cfg) return OZAYN_DIO_ERR_NULL;
    if (svc->initialized) return OZAYN_DIO_ERR_ALREADY_INIT;

    memset(svc, 0, sizeof(*svc));
    svc->config = *cfg;

    if (svc->config.max_devices <= 0)
        svc->config.max_devices = OZAYN_DIO_MAX_DEVICES;
    if (svc->config.max_reservations <= 0)
        svc->config.max_reservations = OZAYN_DIO_MAX_RESERVATIONS;
    if (svc->config.max_events <= 0)
        svc->config.max_events = OZAYN_DIO_MAX_EVENTS;
    if (svc->config.reservation_ttl_ms <= 0)
        svc->config.reservation_ttl_ms = OZAYN_DIO_DEFAULT_RESERVATION_TTL_MS;

    svc->initialized = 1;
    return OZAYN_DIO_OK;
}

void ozayn_dio_service_shutdown(ozayn_dio_service_t *svc)
{
    if (!svc) return;
    svc->initialized = 0;
}

int ozayn_dio_service_is_initialized(const ozayn_dio_service_t *svc)
{
    if (!svc) return 0;
    return svc->initialized;
}

ozayn_dio_service_t *ozayn_dio_get_global(void)
{
    return &_svc;
}

/* ============================================================
 * SECTION 3 — DEVICE REGISTRY
 * ============================================================ */

ozayn_dio_err_t ozayn_dio_device_register(ozayn_dio_service_t *svc,
                                           const ozayn_dio_device_desc_t *desc,
                                           ozayn_dio_device_desc_t **out_device)
{
    if (!svc) return OZAYN_DIO_ERR_NULL;
    if (!svc->initialized) return OZAYN_DIO_ERR_NOT_INITIALIZED;
    if (!desc) return OZAYN_DIO_ERR_NULL;
    if (!out_device) return OZAYN_DIO_ERR_NULL;
    if (desc->device_id[0] == '\0') return OZAYN_DIO_ERR_INVALID_PARAM;
    if (desc->type < 0 || desc->type >= OZAYN_DIO_DEV_TYPE_COUNT)
        return OZAYN_DIO_ERR_INVALID_PARAM;

    if (_find_device(svc, desc->device_id) >= 0)
        return OZAYN_DIO_ERR_DUPLICATE;

    int slot = _find_device_slot(svc);
    if (slot < 0) return OZAYN_DIO_ERR_LIMIT_REACHED;

    svc->devices[slot] = *desc;
    svc->devices[slot].active = 1;
    svc->devices[slot].registration_time = time(NULL);
    svc->devices[slot].last_update_time = time(NULL);

    svc->device_count++;
    svc->device_sequence++;
    svc->stats.total_devices_registered++;
    svc->stats.current_active_devices++;

    _emit_event(svc, OZAYN_DIO_EVENT_REGISTERED, desc->device_id,
                "Device registered");

    *out_device = &svc->devices[slot];
    return OZAYN_DIO_OK;
}

ozayn_dio_err_t ozayn_dio_device_unregister(ozayn_dio_service_t *svc,
                                             const char *device_id)
{
    if (!svc) return OZAYN_DIO_ERR_NULL;
    if (!svc->initialized) return OZAYN_DIO_ERR_NOT_INITIALIZED;
    if (!device_id || device_id[0] == '\0')
        return OZAYN_DIO_ERR_INVALID_PARAM;

    int idx = _find_device(svc, device_id);
    if (idx < 0) return OZAYN_DIO_ERR_NOT_FOUND;

    svc->devices[idx].active = 0;
    svc->device_count--;
    svc->stats.total_devices_unregistered++;
    svc->stats.current_active_devices--;

    _emit_event(svc, OZAYN_DIO_EVENT_UNAVAILABLE, device_id,
                "Device unregistered");

    return OZAYN_DIO_OK;
}

const ozayn_dio_device_desc_t *ozayn_dio_device_get(
    const ozayn_dio_service_t *svc,
    const char *device_id)
{
    if (!svc || !svc->initialized || !device_id) return NULL;
    int idx = _find_device(svc, device_id);
    if (idx < 0) return NULL;
    return &svc->devices[idx];
}

const ozayn_dio_device_desc_t *ozayn_dio_device_get_by_type(
    const ozayn_dio_service_t *svc,
    ozayn_dio_device_type_t type)
{
    if (!svc || !svc->initialized) return NULL;
    if (type < 0 || type >= OZAYN_DIO_DEV_TYPE_COUNT) return NULL;
    for (int i = 0; i < svc->config.max_devices; i++) {
        if (svc->devices[i].active && svc->devices[i].type == type)
            return &svc->devices[i];
    }
    return NULL;
}

int ozayn_dio_device_exists(const ozayn_dio_service_t *svc,
                            const char *device_id)
{
    if (!svc || !svc->initialized || !device_id) return 0;
    return _find_device(svc, device_id) >= 0;
}

int ozayn_dio_device_count(const ozayn_dio_service_t *svc)
{
    if (!svc || !svc->initialized) return 0;
    return svc->device_count;
}

int ozayn_dio_device_full(const ozayn_dio_service_t *svc)
{
    if (!svc || !svc->initialized) return 1;
    return svc->device_count >= svc->config.max_devices;
}

/* ============================================================
 * SECTION 4 — DEVICE STATE MANAGEMENT
 * ============================================================ */

ozayn_dio_err_t ozayn_dio_device_update_state(ozayn_dio_service_t *svc,
                                               const char *device_id,
                                               ozayn_dio_device_state_t state)
{
    if (!svc) return OZAYN_DIO_ERR_NULL;
    if (!svc->initialized) return OZAYN_DIO_ERR_NOT_INITIALIZED;
    if (!device_id || device_id[0] == '\0')
        return OZAYN_DIO_ERR_INVALID_PARAM;
    if (state < 0 || state >= OZAYN_DIO_STATE_COUNT)
        return OZAYN_DIO_ERR_INVALID_PARAM;

    int idx = _find_device(svc, device_id);
    if (idx < 0) return OZAYN_DIO_ERR_NOT_FOUND;

    svc->devices[idx].state = state;
    svc->devices[idx].last_update_time = time(NULL);
    svc->stats.total_state_changes++;
    svc->stats.total_devices_updated++;

    _emit_event(svc, OZAYN_DIO_EVENT_UPDATED, device_id,
                "Device state updated");
    return OZAYN_DIO_OK;
}

ozayn_dio_err_t ozayn_dio_device_update_availability(
    ozayn_dio_service_t *svc,
    const char *device_id,
    ozayn_dio_availability_t availability)
{
    if (!svc) return OZAYN_DIO_ERR_NULL;
    if (!svc->initialized) return OZAYN_DIO_ERR_NOT_INITIALIZED;
    if (!device_id || device_id[0] == '\0')
        return OZAYN_DIO_ERR_INVALID_PARAM;
    if (availability < 0 || availability >= OZAYN_DIO_AVAIL_COUNT)
        return OZAYN_DIO_ERR_INVALID_PARAM;

    int idx = _find_device(svc, device_id);
    if (idx < 0) return OZAYN_DIO_ERR_NOT_FOUND;

    svc->devices[idx].availability = availability;
    svc->devices[idx].last_update_time = time(NULL);
    svc->stats.total_state_changes++;
    svc->stats.total_devices_updated++;

    if (availability == OZAYN_DIO_AVAIL_AVAILABLE)
        _emit_event(svc, OZAYN_DIO_EVENT_AVAILABLE, device_id,
                    "Device available");
    else if (availability == OZAYN_DIO_AVAIL_UNAVAILABLE)
        _emit_event(svc, OZAYN_DIO_EVENT_UNAVAILABLE, device_id,
                    "Device unavailable");

    return OZAYN_DIO_OK;
}

ozayn_dio_err_t ozayn_dio_device_update_health(ozayn_dio_service_t *svc,
                                                const char *device_id,
                                                ozayn_dio_health_t health)
{
    if (!svc) return OZAYN_DIO_ERR_NULL;
    if (!svc->initialized) return OZAYN_DIO_ERR_NOT_INITIALIZED;
    if (!device_id || device_id[0] == '\0')
        return OZAYN_DIO_ERR_INVALID_PARAM;
    if (health < 0 || health >= OZAYN_DIO_HEALTH_COUNT)
        return OZAYN_DIO_ERR_INVALID_PARAM;

    int idx = _find_device(svc, device_id);
    if (idx < 0) return OZAYN_DIO_ERR_NOT_FOUND;

    svc->devices[idx].health = health;
    svc->devices[idx].last_update_time = time(NULL);
    svc->stats.total_state_changes++;
    svc->stats.total_devices_updated++;

    if (health == OZAYN_DIO_HEALTH_DEGRADED)
        _emit_event(svc, OZAYN_DIO_EVENT_DEGRADED, device_id,
                    "Device degraded");
    else if (health == OZAYN_DIO_HEALTH_FAILED)
        _emit_event(svc, OZAYN_DIO_EVENT_ERROR, device_id,
                    "Device health failed");

    return OZAYN_DIO_OK;
}

/* ============================================================
 * SECTION 5 — DEVICE CAPABILITIES
 * ============================================================ */

ozayn_dio_err_t ozayn_dio_capability_add(ozayn_dio_service_t *svc,
                                          const char *device_id,
                                          const ozayn_dio_capability_t *cap)
{
    if (!svc) return OZAYN_DIO_ERR_NULL;
    if (!svc->initialized) return OZAYN_DIO_ERR_NOT_INITIALIZED;
    if (!device_id || device_id[0] == '\0')
        return OZAYN_DIO_ERR_INVALID_PARAM;
    if (!cap) return OZAYN_DIO_ERR_NULL;
    if (cap->type < 0 || cap->type >= OZAYN_DIO_CAP_COUNT)
        return OZAYN_DIO_ERR_INVALID_PARAM;

    int idx = _find_device(svc, device_id);
    if (idx < 0) return OZAYN_DIO_ERR_NOT_FOUND;

    ozayn_dio_device_desc_t *dev = &svc->devices[idx];
    if (dev->capability_count >= OZAYN_DIO_MAX_CAPABILITIES)
        return OZAYN_DIO_ERR_LIMIT_REACHED;

    for (int i = 0; i < dev->capability_count; i++) {
        if (dev->capabilities[i].type == cap->type)
            return OZAYN_DIO_ERR_DUPLICATE;
    }

    dev->capabilities[dev->capability_count] = *cap;
    dev->capabilities[dev->capability_count].active = 1;
    dev->capability_count++;
    dev->last_update_time = time(NULL);
    svc->stats.total_capabilities_added++;

    _emit_event(svc, OZAYN_DIO_EVENT_CAPABILITY_CHANGED, device_id,
                "Capability added");
    return OZAYN_DIO_OK;
}

ozayn_dio_err_t ozayn_dio_capability_remove(ozayn_dio_service_t *svc,
                                             const char *device_id,
                                             ozayn_dio_capability_type_t type)
{
    if (!svc) return OZAYN_DIO_ERR_NULL;
    if (!svc->initialized) return OZAYN_DIO_ERR_NOT_INITIALIZED;
    if (!device_id || device_id[0] == '\0')
        return OZAYN_DIO_ERR_INVALID_PARAM;

    int idx = _find_device(svc, device_id);
    if (idx < 0) return OZAYN_DIO_ERR_NOT_FOUND;

    ozayn_dio_device_desc_t *dev = &svc->devices[idx];
    for (int i = 0; i < dev->capability_count; i++) {
        if (dev->capabilities[i].type == type) {
            dev->capabilities[i].active = 0;
            for (int j = i; j < dev->capability_count - 1; j++) {
                dev->capabilities[j] = dev->capabilities[j + 1];
            }
            dev->capability_count--;
            dev->last_update_time = time(NULL);
            svc->stats.total_capabilities_removed++;
            _emit_event(svc, OZAYN_DIO_EVENT_CAPABILITY_CHANGED, device_id,
                        "Capability removed");
            return OZAYN_DIO_OK;
        }
    }
    return OZAYN_DIO_ERR_NOT_FOUND;
}

const ozayn_dio_capability_t *ozayn_dio_capability_get(
    const ozayn_dio_service_t *svc,
    const char *device_id,
    ozayn_dio_capability_type_t type)
{
    if (!svc || !svc->initialized || !device_id) return NULL;
    int idx = _find_device(svc, device_id);
    if (idx < 0) return NULL;

    const ozayn_dio_device_desc_t *dev = &svc->devices[idx];
    for (int i = 0; i < dev->capability_count; i++) {
        if (dev->capabilities[i].active && dev->capabilities[i].type == type)
            return &dev->capabilities[i];
    }
    return NULL;
}

int ozayn_dio_capability_count(const ozayn_dio_service_t *svc,
                               const char *device_id)
{
    if (!svc || !svc->initialized || !device_id) return 0;
    int idx = _find_device(svc, device_id);
    if (idx < 0) return 0;
    return svc->devices[idx].capability_count;
}

int ozayn_dio_capability_is_available(const ozayn_dio_service_t *svc,
                                      const char *device_id,
                                      ozayn_dio_capability_type_t type)
{
    if (!svc || !svc->initialized || !device_id) return 0;
    const ozayn_dio_capability_t *cap = ozayn_dio_capability_get(svc, device_id,
                                                                  type);
    if (!cap) return 0;
    return cap->active &&
           cap->state == OZAYN_DIO_CAP_STATE_IMPLEMENTED;
}

/* ============================================================
 * SECTION 6 — DEVICE RESERVATIONS
 * ============================================================ */

ozayn_dio_err_t ozayn_dio_reservation_create(ozayn_dio_service_t *svc,
                                              const char *device_id,
                                              const char *requester_ref,
                                              const char *session_ref,
                                              ozayn_dio_capability_type_t capability,
                                              ozayn_dio_reservation_t **out_reservation)
{
    if (!svc) return OZAYN_DIO_ERR_NULL;
    if (!svc->initialized) return OZAYN_DIO_ERR_NOT_INITIALIZED;
    if (!device_id || device_id[0] == '\0')
        return OZAYN_DIO_ERR_INVALID_PARAM;
    if (!requester_ref || requester_ref[0] == '\0')
        return OZAYN_DIO_ERR_INVALID_PARAM;
    if (!out_reservation) return OZAYN_DIO_ERR_NULL;

    int dev_idx = _find_device(svc, device_id);
    if (dev_idx < 0) return OZAYN_DIO_ERR_NOT_FOUND;

    ozayn_dio_device_desc_t *dev = &svc->devices[dev_idx];
    if (dev->state != OZAYN_DIO_STATE_AVAILABLE &&
        dev->state != OZAYN_DIO_STATE_UNKNOWN)
        return OZAYN_DIO_ERR_STATE_INVALID;

    if (dev->availability != OZAYN_DIO_AVAIL_AVAILABLE &&
        dev->availability != OZAYN_DIO_AVAIL_UNKNOWN)
        return OZAYN_DIO_ERR_UNAVAILABLE;

    if (dev->access_mode == OZAYN_DIO_ACCESS_EXCLUSIVE) {
        for (int i = 0; i < svc->reservation_count; i++) {
            if (svc->reservations[i].active &&
                strncmp(svc->reservations[i].device_id, device_id,
                        OZAYN_DIO_MAX_ID_LEN) == 0 &&
                (svc->reservations[i].state == OZAYN_DIO_RES_STATE_RESERVED ||
                 svc->reservations[i].state == OZAYN_DIO_RES_STATE_ACTIVE))
                return OZAYN_DIO_ERR_RESERVATION_CONFLICT;
        }
    }

    int slot = _find_reservation_slot(svc);
    if (slot < 0) return OZAYN_DIO_ERR_LIMIT_REACHED;

    svc->reservation_sequence++;
    ozayn_dio_reservation_t *res = &svc->reservations[slot];
    memset(res, 0, sizeof(*res));
    snprintf(res->reservation_id, OZAYN_DIO_MAX_ID_LEN, "DIO-RSV-%u",
             svc->reservation_sequence);
    strncpy(res->device_id, device_id, OZAYN_DIO_MAX_ID_LEN - 1);
    strncpy(res->requester_ref, requester_ref, OZAYN_DIO_MAX_ID_LEN - 1);
    if (session_ref)
        strncpy(res->session_ref, session_ref, OZAYN_DIO_MAX_ID_LEN - 1);
    res->requested_capability = capability;
    res->created_time = time(NULL);
    res->expiry_time = res->created_time +
                       (svc->config.reservation_ttl_ms / 1000);
    res->state = OZAYN_DIO_RES_STATE_REQUESTED;
    res->active = 1;

    svc->reservation_count++;
    svc->stats.total_reservations_created++;
    svc->stats.current_active_reservations++;

    _emit_event(svc, OZAYN_DIO_EVENT_RESERVATION_CREATED, device_id,
                "Reservation created");

    *out_reservation = res;
    return OZAYN_DIO_OK;
}

ozayn_dio_err_t ozayn_dio_reservation_activate(ozayn_dio_service_t *svc,
                                                const char *reservation_id)
{
    if (!svc) return OZAYN_DIO_ERR_NULL;
    if (!svc->initialized) return OZAYN_DIO_ERR_NOT_INITIALIZED;
    if (!reservation_id || reservation_id[0] == '\0')
        return OZAYN_DIO_ERR_INVALID_PARAM;

    int idx = _find_reservation(svc, reservation_id);
    if (idx < 0) return OZAYN_DIO_ERR_RESERVATION_NOT_FOUND;

    ozayn_dio_reservation_t *res = &svc->reservations[idx];

    time_t now = time(NULL);
    if (res->expiry_time > 0 && now > res->expiry_time) {
        res->state = OZAYN_DIO_RES_STATE_EXPIRED;
        res->active = 0;
        svc->reservation_count--;
        svc->stats.total_reservations_expired++;
        svc->stats.current_active_reservations--;
        _emit_event(svc, OZAYN_DIO_EVENT_RESERVATION_EXPIRED, res->device_id,
                    "Reservation expired");
        return OZAYN_DIO_ERR_RESERVATION_EXPIRED;
    }

    if (res->state != OZAYN_DIO_RES_STATE_RESERVED)
        return OZAYN_DIO_ERR_STATE_INVALID;

    res->state = OZAYN_DIO_RES_STATE_ACTIVE;
    svc->stats.total_reservations_activated++;

    int dev_idx = _find_device(svc, res->device_id);
    if (dev_idx >= 0) {
        svc->devices[dev_idx].state = OZAYN_DIO_STATE_ACTIVE;
        svc->devices[dev_idx].last_update_time = now;
    }

    _emit_event(svc, OZAYN_DIO_EVENT_ACTIVATED, res->device_id,
                "Device activated via reservation");
    return OZAYN_DIO_OK;
}

ozayn_dio_err_t ozayn_dio_reservation_release(ozayn_dio_service_t *svc,
                                               const char *reservation_id)
{
    if (!svc) return OZAYN_DIO_ERR_NULL;
    if (!svc->initialized) return OZAYN_DIO_ERR_NOT_INITIALIZED;
    if (!reservation_id || reservation_id[0] == '\0')
        return OZAYN_DIO_ERR_INVALID_PARAM;

    int idx = _find_reservation(svc, reservation_id);
    if (idx < 0) return OZAYN_DIO_ERR_RESERVATION_NOT_FOUND;

    ozayn_dio_reservation_t *res = &svc->reservations[idx];
    if (res->state != OZAYN_DIO_RES_STATE_ACTIVE &&
        res->state != OZAYN_DIO_RES_STATE_RESERVED)
        return OZAYN_DIO_ERR_STATE_INVALID;

    res->state = OZAYN_DIO_RES_STATE_RELEASED;
    res->active = 0;
    svc->reservation_count--;
    svc->stats.total_reservations_released++;
    svc->stats.current_active_reservations--;
    svc->stats.total_releases++;

    int dev_idx = _find_device(svc, res->device_id);
    if (dev_idx >= 0) {
        svc->devices[dev_idx].state = OZAYN_DIO_STATE_AVAILABLE;
        svc->devices[dev_idx].last_update_time = time(NULL);
    }

    _emit_event(svc, OZAYN_DIO_EVENT_RELEASED, res->device_id,
                "Reservation released");
    return OZAYN_DIO_OK;
}

ozayn_dio_err_t ozayn_dio_reservation_cancel(ozayn_dio_service_t *svc,
                                              const char *reservation_id)
{
    if (!svc) return OZAYN_DIO_ERR_NULL;
    if (!svc->initialized) return OZAYN_DIO_ERR_NOT_INITIALIZED;
    if (!reservation_id || reservation_id[0] == '\0')
        return OZAYN_DIO_ERR_INVALID_PARAM;

    int idx = _find_reservation(svc, reservation_id);
    if (idx < 0) return OZAYN_DIO_ERR_RESERVATION_NOT_FOUND;

    ozayn_dio_reservation_t *res = &svc->reservations[idx];
    if (res->state == OZAYN_DIO_RES_STATE_RELEASED ||
        res->state == OZAYN_DIO_RES_STATE_EXPIRED ||
        res->state == OZAYN_DIO_RES_STATE_CANCELLED)
        return OZAYN_DIO_ERR_STATE_INVALID;

    res->state = OZAYN_DIO_RES_STATE_CANCELLED;
    res->active = 0;
    svc->reservation_count--;
    svc->stats.total_reservations_cancelled++;
    svc->stats.current_active_reservations--;

    _emit_event(svc, OZAYN_DIO_EVENT_RESERVATION_FAILED, res->device_id,
                "Reservation cancelled");
    return OZAYN_DIO_OK;
}

const ozayn_dio_reservation_t *ozayn_dio_reservation_get(
    const ozayn_dio_service_t *svc,
    const char *reservation_id)
{
    if (!svc || !svc->initialized || !reservation_id) return NULL;
    int idx = _find_reservation(svc, reservation_id);
    if (idx < 0) return NULL;
    return &svc->reservations[idx];
}

int ozayn_dio_reservation_count(const ozayn_dio_service_t *svc)
{
    if (!svc || !svc->initialized) return 0;
    return svc->reservation_count;
}

int ozayn_dio_reservation_count_by_device(const ozayn_dio_service_t *svc,
                                          const char *device_id)
{
    if (!svc || !svc->initialized || !device_id) return 0;
    int count = 0;
    for (int i = 0; i < svc->config.max_reservations; i++) {
        if (svc->reservations[i].active &&
            strncmp(svc->reservations[i].device_id, device_id,
                    OZAYN_DIO_MAX_ID_LEN) == 0)
            count++;
    }
    return count;
}

/* ============================================================
 * SECTION 7 — DEVICE DISCOVERY
 * ============================================================ */

ozayn_dio_err_t ozayn_dio_discover(ozayn_dio_service_t *svc,
                                    ozayn_dio_discover_cb_t callback,
                                    void *context,
                                    int timeout_ms,
                                    ozayn_dio_discovery_result_t *out_result)
{
    if (!svc) return OZAYN_DIO_ERR_NULL;
    if (!svc->initialized) return OZAYN_DIO_ERR_NOT_INITIALIZED;
    if (!out_result) return OZAYN_DIO_ERR_NULL;

    svc->discovery_in_progress = 1;
    svc->stats.total_discoveries++;
    svc->stats.current_discoveries_in_progress++;

    memset(out_result, 0, sizeof(*out_result));
    out_result->discovery_time = time(NULL);
    strncpy(out_result->provider, "system", OZAYN_DIO_MAX_PROVIDER_LEN - 1);

    svc->last_discovery = *out_result;
    svc->discovery_in_progress = 0;
    svc->stats.current_discoveries_in_progress--;
    out_result->success = 1;

    return OZAYN_DIO_OK;
}

/* ============================================================
 * SECTION 8 — DEVICE ACCESS LIFECYCLE
 * ============================================================ */

ozayn_dio_err_t ozayn_dio_device_reserve(ozayn_dio_service_t *svc,
                                          const char *device_id,
                                          const char *requester_ref,
                                          const char *session_ref,
                                          ozayn_dio_capability_type_t capability,
                                          ozayn_dio_reservation_t **out_reservation)
{
    if (!svc) return OZAYN_DIO_ERR_NULL;
    if (!svc->initialized) return OZAYN_DIO_ERR_NOT_INITIALIZED;
    if (!device_id || device_id[0] == '\0')
        return OZAYN_DIO_ERR_INVALID_PARAM;

    ozayn_dio_err_t err = ozayn_dio_reservation_create(svc, device_id,
                                                        requester_ref,
                                                        session_ref,
                                                        capability,
                                                        out_reservation);
    if (err != OZAYN_DIO_OK) return err;

    int dev_idx = _find_device(svc, device_id);
    if (dev_idx >= 0) {
        svc->devices[dev_idx].state = OZAYN_DIO_STATE_RESERVED;
        svc->devices[dev_idx].last_update_time = time(NULL);
    }

    (*out_reservation)->state = OZAYN_DIO_RES_STATE_RESERVED;

    _emit_event(svc, OZAYN_DIO_EVENT_RESERVED, device_id,
                "Device reserved");
    return OZAYN_DIO_OK;
}

ozayn_dio_err_t ozayn_dio_device_activate(ozayn_dio_service_t *svc,
                                           const char *device_id,
                                           const char *reservation_id)
{
    if (!svc) return OZAYN_DIO_ERR_NULL;
    if (!svc->initialized) return OZAYN_DIO_ERR_NOT_INITIALIZED;
    if (!device_id || device_id[0] == '\0')
        return OZAYN_DIO_ERR_INVALID_PARAM;
    if (!reservation_id || reservation_id[0] == '\0')
        return OZAYN_DIO_ERR_INVALID_PARAM;

    int dev_idx = _find_device(svc, device_id);
    if (dev_idx < 0) return OZAYN_DIO_ERR_NOT_FOUND;

    ozayn_dio_device_desc_t *dev = &svc->devices[dev_idx];
    if (dev->state != OZAYN_DIO_STATE_RESERVED &&
        dev->state != OZAYN_DIO_STATE_OPENING)
        return OZAYN_DIO_ERR_STATE_INVALID;

    dev->state = OZAYN_DIO_STATE_OPENING;
    dev->last_update_time = time(NULL);

    ozayn_dio_err_t err = ozayn_dio_reservation_activate(svc, reservation_id);
    if (err != OZAYN_DIO_OK) {
        dev->state = OZAYN_DIO_STATE_ERROR;
        svc->stats.total_errors++;
        _emit_event(svc, OZAYN_DIO_EVENT_RESERVATION_FAILED, device_id,
                    "Activation failed");
        return err;
    }

    svc->stats.total_activations++;
    _emit_event(svc, OZAYN_DIO_EVENT_ACTIVATED, device_id,
                "Device activated");
    return OZAYN_DIO_OK;
}

ozayn_dio_err_t ozayn_dio_device_release(ozayn_dio_service_t *svc,
                                          const char *device_id,
                                          const char *reservation_id)
{
    if (!svc) return OZAYN_DIO_ERR_NULL;
    if (!svc->initialized) return OZAYN_DIO_ERR_NOT_INITIALIZED;
    if (!device_id || device_id[0] == '\0')
        return OZAYN_DIO_ERR_INVALID_PARAM;
    if (!reservation_id || reservation_id[0] == '\0')
        return OZAYN_DIO_ERR_INVALID_PARAM;

    int dev_idx = _find_device(svc, device_id);
    if (dev_idx < 0) return OZAYN_DIO_ERR_NOT_FOUND;

    ozayn_dio_err_t err = ozayn_dio_reservation_release(svc, reservation_id);
    if (err != OZAYN_DIO_OK) return err;

    svc->devices[dev_idx].state = OZAYN_DIO_STATE_RELEASING;
    svc->devices[dev_idx].last_update_time = time(NULL);
    svc->devices[dev_idx].state = OZAYN_DIO_STATE_AVAILABLE;

    return OZAYN_DIO_OK;
}

/* ============================================================
 * SECTION 9 — DEVICE DISCONNECT / RECONNECT
 * ============================================================ */

ozayn_dio_err_t ozayn_dio_device_disconnect(ozayn_dio_service_t *svc,
                                             const char *device_id)
{
    if (!svc) return OZAYN_DIO_ERR_NULL;
    if (!svc->initialized) return OZAYN_DIO_ERR_NOT_INITIALIZED;
    if (!device_id || device_id[0] == '\0')
        return OZAYN_DIO_ERR_INVALID_PARAM;

    int idx = _find_device(svc, device_id);
    if (idx < 0) return OZAYN_DIO_ERR_NOT_FOUND;

    svc->devices[idx].state = OZAYN_DIO_STATE_UNAVAILABLE;
    svc->devices[idx].availability = OZAYN_DIO_AVAIL_UNAVAILABLE;
    svc->devices[idx].last_update_time = time(NULL);

    for (int i = 0; i < svc->config.max_reservations; i++) {
        if (svc->reservations[i].active &&
            strncmp(svc->reservations[i].device_id, device_id,
                    OZAYN_DIO_MAX_ID_LEN) == 0 &&
            (svc->reservations[i].state == OZAYN_DIO_RES_STATE_RESERVED ||
             svc->reservations[i].state == OZAYN_DIO_RES_STATE_ACTIVE)) {
            svc->reservations[i].state = OZAYN_DIO_RES_STATE_FAILED;
            svc->reservations[i].active = 0;
            svc->reservation_count--;
            svc->stats.total_reservations_failed++;
            svc->stats.current_active_reservations--;
        }
    }

    svc->stats.total_errors++;
    _emit_event(svc, OZAYN_DIO_EVENT_DISCONNECTED, device_id,
                "Device disconnected");
    return OZAYN_DIO_OK;
}

ozayn_dio_err_t ozayn_dio_device_reconnect(ozayn_dio_service_t *svc,
                                            const char *device_id,
                                            const ozayn_dio_device_desc_t *desc)
{
    if (!svc) return OZAYN_DIO_ERR_NULL;
    if (!svc->initialized) return OZAYN_DIO_ERR_NOT_INITIALIZED;
    if (!device_id || device_id[0] == '\0')
        return OZAYN_DIO_ERR_INVALID_PARAM;

    int idx = _find_device(svc, device_id);
    if (idx < 0) {
        if (!desc) return OZAYN_DIO_ERR_NOT_FOUND;
        ozayn_dio_device_desc_t *out = NULL;
        ozayn_dio_err_t err = ozayn_dio_device_register(svc, desc, &out);
        if (err != OZAYN_DIO_OK) return err;
        idx = _find_device(svc, device_id);
        if (idx < 0) return OZAYN_DIO_ERR_NOT_FOUND;
    }

    svc->devices[idx].state = OZAYN_DIO_STATE_AVAILABLE;
    svc->devices[idx].availability = OZAYN_DIO_AVAIL_AVAILABLE;
    svc->devices[idx].last_update_time = time(NULL);

    if (desc) {
        svc->devices[idx].health = desc->health;
        svc->devices[idx].type = desc->type;
        strncpy(svc->devices[idx].version, desc->version,
                OZAYN_DIO_MAX_VERSION_LEN - 1);
    }

    _emit_event(svc, OZAYN_DIO_EVENT_RECONNECTED, device_id,
                "Device reconnected");
    return OZAYN_DIO_OK;
}

/* ============================================================
 * SECTION 10 — EVENTS
 * ============================================================ */

ozayn_dio_err_t ozayn_dio_emit_event(ozayn_dio_service_t *svc,
                                      ozayn_dio_event_type_t type,
                                      const char *device_id,
                                      const char *message)
{
    if (!svc) return OZAYN_DIO_ERR_NULL;
    if (!svc->initialized) return OZAYN_DIO_ERR_NOT_INITIALIZED;

    _emit_event(svc, type, device_id, message);
    return OZAYN_DIO_OK;
}

const ozayn_dio_event_t *ozayn_dio_event_get(const ozayn_dio_service_t *svc,
                                              int index)
{
    if (!svc || !svc->initialized) return NULL;
    if (index < 0 || index >= svc->event_count) return NULL;
    int idx = (svc->event_head + index) % svc->config.max_events;
    return &svc->events[idx];
}

int ozayn_dio_event_count(const ozayn_dio_service_t *svc)
{
    if (!svc || !svc->initialized) return 0;
    return svc->event_count;
}

/* ============================================================
 * SECTION 11 — CLEANUP
 * ============================================================ */

int ozayn_dio_cleanup_expired_reservations(ozayn_dio_service_t *svc)
{
    if (!svc) return 0;
    int cleaned = 0;
    time_t now = time(NULL);
    for (int i = 0; i < svc->config.max_reservations; i++) {
        if (svc->reservations[i].active) {
            if (svc->reservations[i].expiry_time > 0 &&
                now > svc->reservations[i].expiry_time) {
                svc->reservations[i].state = OZAYN_DIO_RES_STATE_EXPIRED;
                svc->reservations[i].active = 0;
                svc->stats.total_reservations_expired++;
                svc->stats.current_active_reservations--;
                cleaned++;
            }
        }
    }
    svc->reservation_count -= cleaned;
    return cleaned;
}

int ozayn_dio_cleanup_all(ozayn_dio_service_t *svc)
{
    if (!svc) return 0;
    int cleaned = 0;
    cleaned += ozayn_dio_cleanup_expired_reservations(svc);
    return cleaned;
}

/* ============================================================
 * SECTION 12 — STATISTICS
 * ============================================================ */

ozayn_dio_err_t ozayn_dio_get_stats(const ozayn_dio_service_t *svc,
                                     ozayn_dio_stats_t *out_stats)
{
    if (!svc) return OZAYN_DIO_ERR_NULL;
    if (!out_stats) return OZAYN_DIO_ERR_NULL;
    *out_stats = svc->stats;
    return OZAYN_DIO_OK;
}

/* ============================================================
 * SECTION 13 — VALIDATION
 * ============================================================ */

int ozayn_dio_device_validate(const ozayn_dio_device_desc_t *desc)
{
    if (!desc) return 0;
    if (desc->device_id[0] == '\0') return 0;
    if (desc->type < 0 || desc->type >= OZAYN_DIO_DEV_TYPE_COUNT) return 0;
    if (desc->state < 0 || desc->state >= OZAYN_DIO_STATE_COUNT) return 0;
    if (desc->availability < 0 || desc->availability >= OZAYN_DIO_AVAIL_COUNT)
        return 0;
    if (desc->health < 0 || desc->health >= OZAYN_DIO_HEALTH_COUNT) return 0;
    return 1;
}

int ozayn_dio_capability_validate(const ozayn_dio_capability_t *cap)
{
    if (!cap) return 0;
    if (cap->type < 0 || cap->type >= OZAYN_DIO_CAP_COUNT) return 0;
    if (cap->state < 0 || cap->state >= OZAYN_DIO_CAP_STATE_COUNT) return 0;
    return 1;
}

int ozayn_dio_reservation_validate(const ozayn_dio_reservation_t *res)
{
    if (!res) return 0;
    if (res->reservation_id[0] == '\0') return 0;
    if (res->device_id[0] == '\0') return 0;
    if (res->state < 0 || res->state >= OZAYN_DIO_RES_STATE_COUNT) return 0;
    return 1;
}

/* ============================================================
 * SECTION 14 — NAME HELPERS
 * ============================================================ */

const char *ozayn_dio_device_type_name(ozayn_dio_device_type_t type)
{
    switch (type) {
    case OZAYN_DIO_DEV_CAMERA:          return "CAMERA";
    case OZAYN_DIO_DEV_MICROPHONE:      return "MICROPHONE";
    case OZAYN_DIO_DEV_AUDIO_INPUT:     return "AUDIO_INPUT";
    case OZAYN_DIO_DEV_AUDIO_OUTPUT:    return "AUDIO_OUTPUT";
    case OZAYN_DIO_DEV_DISPLAY:         return "DISPLAY";
    case OZAYN_DIO_DEV_KEYBOARD:        return "KEYBOARD";
    case OZAYN_DIO_DEV_MOUSE:           return "MOUSE";
    case OZAYN_DIO_DEV_POINTER:         return "POINTER";
    case OZAYN_DIO_DEV_INPUT_DEVICE:    return "INPUT_DEVICE";
    case OZAYN_DIO_DEV_GPU:             return "GPU";
    case OZAYN_DIO_DEV_NETWORK_DEVICE:  return "NETWORK_DEVICE";
    case OZAYN_DIO_DEV_STORAGE_DEVICE:  return "STORAGE_DEVICE";
    case OZAYN_DIO_DEV_OTHER:           return "OTHER";
    default:                            return "UNKNOWN";
    }
}

const char *ozayn_dio_device_state_name(ozayn_dio_device_state_t state)
{
    switch (state) {
    case OZAYN_DIO_STATE_UNKNOWN:       return "UNKNOWN";
    case OZAYN_DIO_STATE_DISCOVERING:   return "DISCOVERING";
    case OZAYN_DIO_STATE_AVAILABLE:     return "AVAILABLE";
    case OZAYN_DIO_STATE_RESERVED:      return "RESERVED";
    case OZAYN_DIO_STATE_OPENING:       return "OPENING";
    case OZAYN_DIO_STATE_ACTIVE:        return "ACTIVE";
    case OZAYN_DIO_STATE_BUSY:          return "BUSY";
    case OZAYN_DIO_STATE_DISABLED:      return "DISABLED";
    case OZAYN_DIO_STATE_UNAVAILABLE:   return "UNAVAILABLE";
    case OZAYN_DIO_STATE_ERROR:         return "ERROR";
    case OZAYN_DIO_STATE_UNSUPPORTED:   return "UNSUPPORTED";
    case OZAYN_DIO_STATE_RELEASING:     return "RELEASING";
    default:                            return "UNKNOWN";
    }
}

const char *ozayn_dio_availability_name(ozayn_dio_availability_t avail)
{
    switch (avail) {
    case OZAYN_DIO_AVAIL_UNKNOWN:       return "UNKNOWN";
    case OZAYN_DIO_AVAIL_AVAILABLE:     return "AVAILABLE";
    case OZAYN_DIO_AVAIL_UNAVAILABLE:   return "UNAVAILABLE";
    case OZAYN_DIO_AVAIL_LIMITED:       return "LIMITED";
    default:                            return "UNKNOWN";
    }
}

const char *ozayn_dio_health_name(ozayn_dio_health_t health)
{
    switch (health) {
    case OZAYN_DIO_HEALTH_UNKNOWN:      return "UNKNOWN";
    case OZAYN_DIO_HEALTH_HEALTHY:      return "HEALTHY";
    case OZAYN_DIO_HEALTH_DEGRADED:     return "DEGRADED";
    case OZAYN_DIO_HEALTH_UNHEALTHY:    return "UNHEALTHY";
    case OZAYN_DIO_HEALTH_FAILED:       return "FAILED";
    default:                            return "UNKNOWN";
    }
}

const char *ozayn_dio_capability_type_name(ozayn_dio_capability_type_t cap)
{
    switch (cap) {
    case OZAYN_DIO_CAP_CAMERA_CAPTURE:  return "CAMERA_CAPTURE";
    case OZAYN_DIO_CAP_MICROPHONE_INPUT:return "MICROPHONE_INPUT";
    case OZAYN_DIO_CAP_AUDIO_PLAYBACK:  return "AUDIO_PLAYBACK";
    case OZAYN_DIO_CAP_DISPLAY_OUTPUT:  return "DISPLAY_OUTPUT";
    case OZAYN_DIO_CAP_KEYBOARD_INPUT:  return "KEYBOARD_INPUT";
    case OZAYN_DIO_CAP_MOUSE_INPUT:     return "MOUSE_INPUT";
    case OZAYN_DIO_CAP_POINTER_CONTROL: return "POINTER_CONTROL";
    case OZAYN_DIO_CAP_GPU_COMPUTE:     return "GPU_COMPUTE";
    case OZAYN_DIO_CAP_GPU_RENDERING:   return "GPU_RENDERING";
    case OZAYN_DIO_CAP_NETWORK_ACCESS:  return "NETWORK_ACCESS";
    case OZAYN_DIO_CAP_STORAGE_ACCESS:  return "STORAGE_ACCESS";
    default:                            return "UNKNOWN";
    }
}

const char *ozayn_dio_cap_state_name(ozayn_dio_cap_state_t state)
{
    switch (state) {
    case OZAYN_DIO_CAP_STATE_IMPLEMENTED:  return "IMPLEMENTED";
    case OZAYN_DIO_CAP_STATE_PLANNED:      return "PLANNED";
    case OZAYN_DIO_CAP_STATE_UNAVAILABLE:  return "UNAVAILABLE";
    case OZAYN_DIO_CAP_STATE_UNSUPPORTED:  return "UNSUPPORTED";
    case OZAYN_DIO_CAP_STATE_DISABLED:     return "DISABLED";
    case OZAYN_DIO_CAP_STATE_ERROR:        return "ERROR";
    default:                               return "UNKNOWN";
    }
}

const char *ozayn_dio_access_mode_name(ozayn_dio_access_mode_t mode)
{
    switch (mode) {
    case OZAYN_DIO_ACCESS_SHARED:      return "SHARED";
    case OZAYN_DIO_ACCESS_EXCLUSIVE:   return "EXCLUSIVE";
    default:                           return "UNKNOWN";
    }
}

const char *ozayn_dio_reservation_state_name(ozayn_dio_reservation_state_t state)
{
    switch (state) {
    case OZAYN_DIO_RES_STATE_REQUESTED:  return "REQUESTED";
    case OZAYN_DIO_RES_STATE_RESERVED:   return "RESERVED";
    case OZAYN_DIO_RES_STATE_ACTIVE:     return "ACTIVE";
    case OZAYN_DIO_RES_STATE_RELEASED:   return "RELEASED";
    case OZAYN_DIO_RES_STATE_EXPIRED:    return "EXPIRED";
    case OZAYN_DIO_RES_STATE_CANCELLED:  return "CANCELLED";
    case OZAYN_DIO_RES_STATE_FAILED:     return "FAILED";
    default:                             return "UNKNOWN";
    }
}

const char *ozayn_dio_event_type_name(ozayn_dio_event_type_t type)
{
    switch (type) {
    case OZAYN_DIO_EVENT_DISCOVERED:            return "DISCOVERED";
    case OZAYN_DIO_EVENT_REGISTERED:            return "REGISTERED";
    case OZAYN_DIO_EVENT_UPDATED:               return "UPDATED";
    case OZAYN_DIO_EVENT_AVAILABLE:             return "AVAILABLE";
    case OZAYN_DIO_EVENT_UNAVAILABLE:           return "UNAVAILABLE";
    case OZAYN_DIO_EVENT_DEGRADED:              return "DEGRADED";
    case OZAYN_DIO_EVENT_RESERVED:              return "RESERVED";
    case OZAYN_DIO_EVENT_RESERVATION_CREATED:   return "RESERVATION_CREATED";
    case OZAYN_DIO_EVENT_RESERVATION_FAILED:    return "RESERVATION_FAILED";
    case OZAYN_DIO_EVENT_RESERVATION_EXPIRED:   return "RESERVATION_EXPIRED";
    case OZAYN_DIO_EVENT_ACTIVATED:             return "ACTIVATED";
    case OZAYN_DIO_EVENT_RELEASED:              return "RELEASED";
    case OZAYN_DIO_EVENT_DISABLED:              return "DISABLED";
    case OZAYN_DIO_EVENT_ERROR:                 return "ERROR";
    case OZAYN_DIO_EVENT_CAPABILITY_CHANGED:    return "CAPABILITY_CHANGED";
    case OZAYN_DIO_EVENT_DISCONNECTED:          return "DISCONNECTED";
    case OZAYN_DIO_EVENT_RECONNECTED:           return "RECONNECTED";
    default:                                    return "UNKNOWN";
    }
}

const char *ozayn_dio_err_name(ozayn_dio_err_t err)
{
    switch (err) {
    case OZAYN_DIO_OK:                          return "OK";
    case OZAYN_DIO_ERR_NULL:                    return "NULL";
    case OZAYN_DIO_ERR_NOT_INITIALIZED:         return "NOT_INITIALIZED";
    case OZAYN_DIO_ERR_ALREADY_INIT:            return "ALREADY_INIT";
    case OZAYN_DIO_ERR_INVALID_PARAM:           return "INVALID_PARAM";
    case OZAYN_DIO_ERR_LIMIT_REACHED:           return "LIMIT_REACHED";
    case OZAYN_DIO_ERR_NOT_FOUND:               return "NOT_FOUND";
    case OZAYN_DIO_ERR_DUPLICATE:               return "DUPLICATE";
    case OZAYN_DIO_ERR_UNAVAILABLE:             return "UNAVAILABLE";
    case OZAYN_DIO_ERR_UNSUPPORTED:             return "UNSUPPORTED";
    case OZAYN_DIO_ERR_STATE_INVALID:           return "STATE_INVALID";
    case OZAYN_DIO_ERR_RESERVATION_FAILED:      return "RESERVATION_FAILED";
    case OZAYN_DIO_ERR_RESERVATION_CONFLICT:    return "RESERVATION_CONFLICT";
    case OZAYN_DIO_ERR_RESERVATION_EXPIRED:     return "RESERVATION_EXPIRED";
    case OZAYN_DIO_ERR_RESERVATION_NOT_FOUND:   return "RESERVATION_NOT_FOUND";
    case OZAYN_DIO_ERR_ACTIVATION_FAILED:       return "ACTIVATION_FAILED";
    case OZAYN_DIO_ERR_RELEASE_FAILED:          return "RELEASE_FAILED";
    case OZAYN_DIO_ERR_DISCOVERY_FAILED:        return "DISCOVERY_FAILED";
    case OZAYN_DIO_ERR_DISCOVERY_TIMEOUT:       return "DISCOVERY_TIMEOUT";
    case OZAYN_DIO_ERR_PROVIDER_ERROR:          return "PROVIDER_ERROR";
    case OZAYN_DIO_ERR_PERMISSION_DENIED:       return "PERMISSION_DENIED";
    case OZAYN_DIO_ERR_AUTH_FAILED:             return "AUTH_FAILED";
    case OZAYN_DIO_ERR_SAFETY_FAILED:           return "SAFETY_FAILED";
    case OZAYN_DIO_ERR_RESOURCE_FAILED:         return "RESOURCE_FAILED";
    case OZAYN_DIO_ERR_TIMEOUT:                 return "TIMEOUT";
    case OZAYN_DIO_ERR_CONCURRENCY:             return "CONCURRENCY";
    case OZAYN_DIO_ERR_DEVICE_DISCONNECTED:     return "DEVICE_DISCONNECTED";
    default:                                    return "UNKNOWN";
    }
}
