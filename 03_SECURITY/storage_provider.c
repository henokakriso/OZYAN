#include "storage_provider.h"
#include <string.h>

/*
 * storage_provider.c — Storage Abstraction Dispatch (Section 03, Step 04).
 *
 * Implements the dispatch layer that routes storage operations through the
 * provider vtable. Validates preconditions before dispatching.
 */

/* ---- State name lookup ---- */
const char *ozayn_sp_state_name(ozayn_sp_state_t state)
{
    switch (state) {
        case OZAYN_SP_STATE_UNINITIALIZED: return "Uninitialized";
        case OZAYN_SP_STATE_INITIALIZED:   return "Initialized";
        case OZAYN_SP_STATE_READY:         return "Ready";
        case OZAYN_SP_STATE_SHUTTING_DOWN: return "Shutting Down";
        case OZAYN_SP_STATE_STOPPED:       return "Stopped";
        default:                           return "Unknown State";
    }
}

/* ---- Lifecycle ---- */
ozayn_secure_data_result_t ozayn_sp_init(ozayn_storage_provider_t *provider)
{
    if (!provider)
        return OZAYN_SD_ERR_NULL;
    if (!provider->ops)
        return OZAYN_SD_ERR_INVALID_REQUEST;
    if (!provider->ops->init)
        return OZAYN_SD_ERR_INVALID_REQUEST;

    provider->state = OZAYN_SP_STATE_INITIALIZED;
    memset(&provider->stats, 0, sizeof(provider->stats));

    ozayn_secure_data_result_t rc = provider->ops->init(provider);
    if (rc == OZAYN_SD_OK)
        provider->state = OZAYN_SP_STATE_READY;
    return rc;
}

void ozayn_sp_shutdown(ozayn_storage_provider_t *provider)
{
    if (!provider)
        return;
    if (provider->state == OZAYN_SP_STATE_UNINITIALIZED ||
        provider->state == OZAYN_SP_STATE_STOPPED)
        return;

    provider->state = OZAYN_SP_STATE_SHUTTING_DOWN;
    if (provider->ops && provider->ops->shutdown)
        provider->ops->shutdown(provider);
    provider->state = OZAYN_SP_STATE_STOPPED;
}

int ozayn_sp_is_ready(const ozayn_storage_provider_t *provider)
{
    if (!provider)
        return 0;
    return provider->state == OZAYN_SP_STATE_READY;
}

/* ---- Dispatch: CREATE ---- */
ozayn_secure_data_result_t ozayn_sp_create(ozayn_storage_provider_t *provider,
                                            const ozayn_secure_data_object_t *obj)
{
    if (!provider || !obj)
        return OZAYN_SD_ERR_NULL;
    if (provider->state != OZAYN_SP_STATE_READY)
        return OZAYN_SD_ERR_NOT_INITIALIZED;
    if (!provider->ops || !provider->ops->create)
        return OZAYN_SD_ERR_INVALID_REQUEST;

    /* Validate object before passing to provider */
    if (ozayn_sdo_validate(obj) != 0) {
        provider->stats.total_errors++;
        return OZAYN_SD_ERR_INVALID_DATA;
    }

    ozayn_secure_data_result_t rc = provider->ops->create(provider, obj);
    if (rc == OZAYN_SD_OK)
        provider->stats.total_creates++;
    else
        provider->stats.total_errors++;
    return rc;
}

/* ---- Dispatch: READ ---- */
ozayn_secure_data_result_t ozayn_sp_read(ozayn_storage_provider_t *provider,
                                           const char *id,
                                           ozayn_secure_data_object_t *out_obj)
{
    if (!provider || !id || !out_obj)
        return OZAYN_SD_ERR_NULL;
    if (provider->state != OZAYN_SP_STATE_READY)
        return OZAYN_SD_ERR_NOT_INITIALIZED;
    if (!provider->ops || !provider->ops->read)
        return OZAYN_SD_ERR_INVALID_REQUEST;
    if (id[0] == '\0')
        return OZAYN_SD_ERR_INVALID_REQUEST;

    ozayn_secure_data_result_t rc = provider->ops->read(provider, id, out_obj);
    if (rc == OZAYN_SD_OK)
        provider->stats.total_reads++;
    else
        provider->stats.total_errors++;
    return rc;
}

/* ---- Dispatch: UPDATE ---- */
ozayn_secure_data_result_t ozayn_sp_update(ozayn_storage_provider_t *provider,
                                             const ozayn_secure_data_object_t *obj)
{
    if (!provider || !obj)
        return OZAYN_SD_ERR_NULL;
    if (provider->state != OZAYN_SP_STATE_READY)
        return OZAYN_SD_ERR_NOT_INITIALIZED;
    if (!provider->ops || !provider->ops->update)
        return OZAYN_SD_ERR_INVALID_REQUEST;

    /* Validate object before passing to provider */
    if (ozayn_sdo_validate(obj) != 0) {
        provider->stats.total_errors++;
        return OZAYN_SD_ERR_INVALID_DATA;
    }

    ozayn_secure_data_result_t rc = provider->ops->update(provider, obj);
    if (rc == OZAYN_SD_OK)
        provider->stats.total_updates++;
    else
        provider->stats.total_errors++;
    return rc;
}

/* ---- Dispatch: DELETE ---- */
ozayn_secure_data_result_t ozayn_sp_delete(ozayn_storage_provider_t *provider,
                                             const char *id)
{
    if (!provider || !id)
        return OZAYN_SD_ERR_NULL;
    if (provider->state != OZAYN_SP_STATE_READY)
        return OZAYN_SD_ERR_NOT_INITIALIZED;
    if (!provider->ops || !provider->ops->delete_obj)
        return OZAYN_SD_ERR_INVALID_REQUEST;
    if (id[0] == '\0')
        return OZAYN_SD_ERR_INVALID_REQUEST;

    ozayn_secure_data_result_t rc = provider->ops->delete_obj(provider, id);
    if (rc == OZAYN_SD_OK)
        provider->stats.total_deletes++;
    else
        provider->stats.total_errors++;
    return rc;
}

/* ---- Dispatch: EXISTS ---- */
int ozayn_sp_exists(ozayn_storage_provider_t *provider, const char *id)
{
    if (!provider || !id)
        return 0;
    if (provider->state != OZAYN_SP_STATE_READY)
        return 0;
    if (!provider->ops || !provider->ops->exists)
        return 0;
    if (id[0] == '\0')
        return 0;

    int result = provider->ops->exists(provider, id);
    provider->stats.total_exists++;
    return result;
}

/* ---- Dispatch: LIST ---- */
int ozayn_sp_list(ozayn_storage_provider_t *provider,
                  ozayn_data_category_t category,
                  ozayn_secure_data_object_t *out_array,
                  int max_count)
{
    if (!provider || !out_array || max_count <= 0)
        return 0;
    if (provider->state != OZAYN_SP_STATE_READY)
        return 0;
    if (!provider->ops || !provider->ops->list)
        return 0;

    int result = provider->ops->list(provider, category, out_array, max_count);
    provider->stats.total_lists++;
    return result;
}

/* ---- Dispatch: COUNT ---- */
int ozayn_sp_count(ozayn_storage_provider_t *provider)
{
    if (!provider)
        return 0;
    if (provider->state != OZAYN_SP_STATE_READY)
        return 0;
    if (!provider->ops || !provider->ops->count)
        return 0;
    return provider->ops->count(provider);
}

/* ---- Stats ---- */
ozayn_sp_stats_t ozayn_sp_stats(const ozayn_storage_provider_t *provider)
{
    ozayn_sp_stats_t stats;
    memset(&stats, 0, sizeof(stats));
    if (provider)
        stats = provider->stats;
    return stats;
}
