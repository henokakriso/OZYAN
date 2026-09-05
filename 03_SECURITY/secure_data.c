#include "secure_data.h"
#include <string.h>
#include <stdio.h>

/*
 * secure_data.c — Secure Data Layer Boundary Implementation (Section 03, Step 02).
 *
 * Implements the storage abstraction layer that sits between OZAYN application
 * components and sensitive persistent data. All data access passes through this
 * boundary.
 *
 * This is a structural foundation. Encryption, authorization checks, and audit
 * logging are deferred to later steps.
 */

/* ---- Operation name lookup ---- */
const char *ozayn_sd_operation_name(ozayn_sd_operation_t op)
{
    switch (op) {
        case OZAYN_SD_OP_CREATE: return "Create";
        case OZAYN_SD_OP_READ:   return "Read";
        case OZAYN_SD_OP_UPDATE: return "Update";
        case OZAYN_SD_OP_DELETE: return "Delete";
        case OZAYN_SD_OP_EXISTS: return "Exists";
        case OZAYN_SD_OP_LIST:   return "List";
        default:                 return "Unknown";
    }
}

/* ---- Lifecycle ---- */
ozayn_secure_data_result_t ozayn_secure_data_init(ozayn_secure_data_manager_t *mgr)
{
    if (!mgr)
        return OZAYN_SD_ERR_NULL;

    memset(mgr, 0, sizeof(*mgr));
    mgr->initialized = 1;
    return OZAYN_SD_OK;
}

void ozayn_secure_data_shutdown(ozayn_secure_data_manager_t *mgr)
{
    if (!mgr)
        return;
    memset(mgr, 0, sizeof(*mgr));
}

int ozayn_secure_data_is_initialized(const ozayn_secure_data_manager_t *mgr)
{
    if (!mgr)
        return 0;
    return mgr->initialized;
}

/* ---- Find internal index ---- */
static int _find_index(const ozayn_secure_data_manager_t *mgr, const char *id)
{
    if (!mgr || !id || !mgr->initialized)
        return -1;
    for (int i = 0; i < mgr->object_count; i++) {
        if (strcmp(mgr->objects[i].id, id) == 0)
            return i;
    }
    return -1;
}

/* ---- Create ---- */
ozayn_secure_data_result_t ozayn_secure_data_create(ozayn_secure_data_manager_t *mgr,
                                                     const ozayn_data_metadata_t *meta)
{
    if (!mgr || !meta)
        return OZAYN_SD_ERR_NULL;
    if (!mgr->initialized)
        return OZAYN_SD_ERR_NOT_INITIALIZED;
    if (ozayn_data_metadata_validate(meta) != 0)
        return OZAYN_SD_ERR_INVALID_REQUEST;
    if (_find_index(mgr, meta->id) >= 0)
        return OZAYN_SD_ERR_STATE;
    if (mgr->object_count >= OZAYN_SD_MAX_OBJECTS)
        return OZAYN_SD_ERR_STORAGE_FAILURE;

    mgr->objects[mgr->object_count] = *meta;
    mgr->objects[mgr->object_count].storage_state = OZAYN_DATA_STORAGE_ACTIVE;
    mgr->object_count++;
    mgr->total_creates++;
    return OZAYN_SD_OK;
}

/* ---- Read ---- */
ozayn_secure_data_result_t ozayn_secure_data_read(const ozayn_secure_data_manager_t *mgr,
                                                   const char *id,
                                                   ozayn_data_metadata_t *out_meta)
{
    if (!mgr || !id || !out_meta)
        return OZAYN_SD_ERR_NULL;
    if (!mgr->initialized)
        return OZAYN_SD_ERR_NOT_INITIALIZED;

    int idx = _find_index(mgr, id);
    if (idx < 0)
        return OZAYN_SD_ERR_NOT_FOUND;

    *out_meta = mgr->objects[idx];
    /* Cast away const for stats — acceptable for non-atomic counter */
    ((ozayn_secure_data_manager_t *)mgr)->total_reads++;
    return OZAYN_SD_OK;
}

/* ---- Update ---- */
ozayn_secure_data_result_t ozayn_secure_data_update(ozayn_secure_data_manager_t *mgr,
                                                     const char *id,
                                                     const ozayn_data_metadata_t *new_meta)
{
    if (!mgr || !id || !new_meta)
        return OZAYN_SD_ERR_NULL;
    if (!mgr->initialized)
        return OZAYN_SD_ERR_NOT_INITIALIZED;
    if (ozayn_data_metadata_validate(new_meta) != 0)
        return OZAYN_SD_ERR_INVALID_REQUEST;

    int idx = _find_index(mgr, id);
    if (idx < 0)
        return OZAYN_SD_ERR_NOT_FOUND;

    /* Preserve creation timestamp, update everything else */
    time_t created = mgr->objects[idx].created_at;
    mgr->objects[idx] = *new_meta;
    mgr->objects[idx].created_at = created;
    mgr->total_updates++;
    return OZAYN_SD_OK;
}

/* ---- Delete ---- */
ozayn_secure_data_result_t ozayn_secure_data_delete(ozayn_secure_data_manager_t *mgr,
                                                     const char *id)
{
    if (!mgr || !id)
        return OZAYN_SD_ERR_NULL;
    if (!mgr->initialized)
        return OZAYN_SD_ERR_NOT_INITIALIZED;

    int idx = _find_index(mgr, id);
    if (idx < 0)
        return OZAYN_SD_ERR_NOT_FOUND;

    /* Mark as deleted */
    mgr->objects[idx].storage_state = OZAYN_DATA_STORAGE_DELETED;
    mgr->total_deletes++;
    return OZAYN_SD_OK;
}

/* ---- Exists ---- */
int ozayn_secure_data_exists(const ozayn_secure_data_manager_t *mgr, const char *id)
{
    if (!mgr || !id || !mgr->initialized)
        return 0;
    return _find_index(mgr, id) >= 0;
}

/* ---- List by category ---- */
int ozayn_secure_data_list(const ozayn_secure_data_manager_t *mgr,
                           ozayn_data_category_t category,
                           ozayn_data_metadata_t *out_array,
                           int max_count)
{
    if (!mgr || !out_array || max_count <= 0)
        return 0;
    if (!mgr->initialized)
        return 0;
    if (category < 0 || category >= OZAYN_DATA_CATEGORY_COUNT)
        return 0;

    int count = 0;
    for (int i = 0; i < mgr->object_count && count < max_count; i++) {
        if (mgr->objects[i].category == category &&
            mgr->objects[i].storage_state != OZAYN_DATA_STORAGE_DELETED) {
            out_array[count] = mgr->objects[i];
            count++;
        }
    }
    return count;
}

/* ---- Object count ---- */
int ozayn_secure_data_object_count(const ozayn_secure_data_manager_t *mgr)
{
    if (!mgr || !mgr->initialized)
        return 0;
    return mgr->object_count;
}

/* ---- Category count ---- */
int ozayn_secure_data_category_count(const ozayn_secure_data_manager_t *mgr,
                                      ozayn_data_category_t category)
{
    if (!mgr || !mgr->initialized)
        return 0;
    if (category < 0 || category >= OZAYN_DATA_CATEGORY_COUNT)
        return 0;

    int count = 0;
    for (int i = 0; i < mgr->object_count; i++) {
        if (mgr->objects[i].category == category &&
            mgr->objects[i].storage_state != OZAYN_DATA_STORAGE_DELETED) {
            count++;
        }
    }
    return count;
}

/* ---- Statistics ---- */
ozayn_secure_data_stats_t ozayn_secure_data_stats(const ozayn_secure_data_manager_t *mgr)
{
    ozayn_secure_data_stats_t stats;
    memset(&stats, 0, sizeof(stats));
    if (!mgr || !mgr->initialized)
        return stats;

    stats.total_objects = mgr->object_count;
    stats.total_creates = mgr->total_creates;
    stats.total_reads   = mgr->total_reads;
    stats.total_updates = mgr->total_updates;
    stats.total_deletes = mgr->total_deletes;
    stats.total_denied  = mgr->total_denied;
    return stats;
}
