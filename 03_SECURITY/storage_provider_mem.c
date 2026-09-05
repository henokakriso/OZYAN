#include "storage_provider_mem.h"
#include <string.h>

/*
 * storage_provider_mem.c — In-Memory Storage Provider (Section 03, Step 04).
 *
 * TEST-ONLY implementation. Not for production use.
 * Provides no encryption, persistence, access control, or secure deletion.
 */

/* ---- Internal helpers ---- */
static int _mem_find_index(ozayn_sp_mem_data_t *data, const char *id)
{
    if (!data || !id || !data->initialized)
        return -1;
    for (int i = 0; i < data->count; i++) {
        if (strcmp(data->objects[i].id, id) == 0)
            return i;
    }
    return -1;
}

/* ---- Provider operations ---- */
static ozayn_secure_data_result_t _mem_init(ozayn_storage_provider_t *provider)
{
    if (!provider)
        return OZAYN_SD_ERR_NULL;

    ozayn_sp_mem_data_t *data = (ozayn_sp_mem_data_t *)provider->impl_data;
    if (!data)
        return OZAYN_SD_ERR_NULL;

    memset(data, 0, sizeof(*data));
    data->initialized = 1;
    return OZAYN_SD_OK;
}

static void _mem_shutdown(ozayn_storage_provider_t *provider)
{
    if (!provider)
        return;
    ozayn_sp_mem_data_t *data = (ozayn_sp_mem_data_t *)provider->impl_data;
    if (data)
        memset(data, 0, sizeof(*data));
}

static ozayn_secure_data_result_t _mem_create(ozayn_storage_provider_t *provider,
                                               const ozayn_secure_data_object_t *obj)
{
    if (!provider || !obj)
        return OZAYN_SD_ERR_NULL;

    ozayn_sp_mem_data_t *data = (ozayn_sp_mem_data_t *)provider->impl_data;
    if (!data || !data->initialized)
        return OZAYN_SD_ERR_NOT_INITIALIZED;

    if (_mem_find_index(data, obj->id) >= 0)
        return OZAYN_SD_ERR_STATE;  /* DATA_ALREADY_EXISTS */

    if (data->count >= OZAYN_SP_MEM_MAX_OBJECTS)
        return OZAYN_SD_ERR_STORAGE_FAILURE;

    data->objects[data->count] = *obj;
    data->objects[data->count].storage_state = OZAYN_DATA_STORAGE_ACTIVE;
    data->count++;
    return OZAYN_SD_OK;
}

static ozayn_secure_data_result_t _mem_read(ozayn_storage_provider_t *provider,
                                             const char *id,
                                             ozayn_secure_data_object_t *out_obj)
{
    if (!provider || !id || !out_obj)
        return OZAYN_SD_ERR_NULL;

    ozayn_sp_mem_data_t *data = (ozayn_sp_mem_data_t *)provider->impl_data;
    if (!data || !data->initialized)
        return OZAYN_SD_ERR_NOT_INITIALIZED;

    int idx = _mem_find_index(data, id);
    if (idx < 0)
        return OZAYN_SD_ERR_NOT_FOUND;

    *out_obj = data->objects[idx];
    return OZAYN_SD_OK;
}

static ozayn_secure_data_result_t _mem_update(ozayn_storage_provider_t *provider,
                                               const ozayn_secure_data_object_t *obj)
{
    if (!provider || !obj)
        return OZAYN_SD_ERR_NULL;

    ozayn_sp_mem_data_t *data = (ozayn_sp_mem_data_t *)provider->impl_data;
    if (!data || !data->initialized)
        return OZAYN_SD_ERR_NOT_INITIALIZED;

    int idx = _mem_find_index(data, obj->id);
    if (idx < 0)
        return OZAYN_SD_ERR_NOT_FOUND;

    /* Preserve creation timestamp */
    time_t created = data->objects[idx].created_at;
    data->objects[idx] = *obj;
    data->objects[idx].created_at = created;
    data->objects[idx].storage_state = OZAYN_DATA_STORAGE_ACTIVE;
    return OZAYN_SD_OK;
}

static ozayn_secure_data_result_t _mem_delete(ozayn_storage_provider_t *provider,
                                               const char *id)
{
    if (!provider || !id)
        return OZAYN_SD_ERR_NULL;

    ozayn_sp_mem_data_t *data = (ozayn_sp_mem_data_t *)provider->impl_data;
    if (!data || !data->initialized)
        return OZAYN_SD_ERR_NOT_INITIALIZED;

    int idx = _mem_find_index(data, id);
    if (idx < 0)
        return OZAYN_SD_ERR_NOT_FOUND;

    /* Compact: shift remaining objects */
    for (int i = idx; i < data->count - 1; i++) {
        data->objects[i] = data->objects[i + 1];
    }
    data->count--;
    return OZAYN_SD_OK;
}

static int _mem_exists(ozayn_storage_provider_t *provider, const char *id)
{
    if (!provider || !id)
        return 0;

    ozayn_sp_mem_data_t *data = (ozayn_sp_mem_data_t *)provider->impl_data;
    if (!data || !data->initialized)
        return 0;

    return _mem_find_index(data, id) >= 0;
}

static int _mem_list(ozayn_storage_provider_t *provider,
                      ozayn_data_category_t category,
                      ozayn_secure_data_object_t *out_array,
                      int max_count)
{
    if (!provider || !out_array || max_count <= 0)
        return 0;

    ozayn_sp_mem_data_t *data = (ozayn_sp_mem_data_t *)provider->impl_data;
    if (!data || !data->initialized)
        return 0;

    int count = 0;
    for (int i = 0; i < data->count && count < max_count; i++) {
        if (data->objects[i].category == category) {
            out_array[count] = data->objects[i];
            count++;
        }
    }
    return count;
}

static int _mem_count(ozayn_storage_provider_t *provider)
{
    if (!provider)
        return 0;

    ozayn_sp_mem_data_t *data = (ozayn_sp_mem_data_t *)provider->impl_data;
    if (!data || !data->initialized)
        return 0;

    return data->count;
}

/* ---- Operations table ---- */
static const ozayn_sp_ops_t _mem_ops = {
    .init      = _mem_init,
    .shutdown  = _mem_shutdown,
    .create    = _mem_create,
    .read      = _mem_read,
    .update    = _mem_update,
    .delete_obj = _mem_delete,
    .exists    = _mem_exists,
    .list      = _mem_list,
    .count     = _mem_count,
};

/* ---- Factory ---- */
int ozayn_sp_mem_create_provider(ozayn_storage_provider_t *provider)
{
    if (!provider)
        return -1;

    static ozayn_sp_mem_data_t _mem_data;

    memset(provider, 0, sizeof(*provider));
    provider->name      = "InMemory";
    provider->state     = OZAYN_SP_STATE_UNINITIALIZED;
    provider->ops       = &_mem_ops;
    provider->impl_data = &_mem_data;

    return 0;
}
