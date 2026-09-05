#include "storage_provider_local.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <errno.h>
#include <dirent.h>
#include <platform.h>

/*
 * storage_provider_local.c — Local Persistent Storage Provider (Section 03, Step 05).
 *
 * Stores SecureDataObjects as individual files on the local filesystem.
 * Each object is serialized to a simple key-value text format.
 *
 * IMPORTANT: This provider is NOT encrypted. Cryptographic protection
 * is implemented in later security-layer steps.
 *
 * Serialization format (one key=value per line):
 *   id=...
 *   version=...
 *   category=...
 *   classification=...
 *   state=...
 *   integrity=...
 *   storage_state=...
 *   owner=...
 *   scope=...
 *   created_at=...
 *   modified_at=...
 *   content_size=...
 *   checksum=...
 *   ---
 */

/* ---- ID Validation ---- */
int ozayn_sp_local_validate_id(const char *id)
{
    if (!id || id[0] == '\0')
        return -1;
    if (strlen(id) >= OZAYN_SP_LOCAL_MAX_ID)
        return -1;

    /* Reject path traversal and dangerous characters */
    for (const char *p = id; *p; p++) {
        char c = *p;
        if (c == '/' || c == '\\')
            return -1;
        if (c == '.' && (p[1] == '.' || p[1] == '\0'))
            return -1;  /* reject ".." and "." components */
        if (c == '\0')
            break;
    }

    /* Reject leading dot (hidden files) */
    if (id[0] == '.')
        return -1;

    return 0;
}

/* ---- Path Helpers ---- */
static void _build_obj_path(const ozayn_sp_local_data_t *data,
                             const char *id,
                             char *path,
                             size_t path_size)
{
    snprintf(path, path_size, "%s/%s.sdo", data->data_dir, id);
}

static void _build_tmp_path(const ozayn_sp_local_data_t *data,
                             const char *id,
                             char *path,
                             size_t path_size)
{
    snprintf(path, path_size, "%s/%s.sdo.tmp", data->data_dir, id);
}

/* ---- Ensure Directory (recursive) ---- */
static int _ensure_dir(const char *path)
{
    struct stat st;
    if (stat(path, &st) == 0) {
        if (S_ISDIR(st.st_mode))
            return 0;
        return -1;  /* exists but not a directory */
    }

    /* Try to create parent first */
    char parent[OZAYN_SP_LOCAL_MAX_PATH];
    strncpy(parent, path, sizeof(parent) - 1);
    parent[sizeof(parent) - 1] = '\0';
    char *slash = strrchr(parent, '/');
    if (slash && slash != parent) {
        *slash = '\0';
        _ensure_dir(parent);  /* recurse to create parents */
    }

    if (mkdir(path, 0700) != 0 && errno != EEXIST)
        return -1;
    return 0;
}

/* ---- Serialization ---- */
static int _serialize_obj(const ozayn_secure_data_object_t *obj, const char *path)
{
    FILE *f = fopen(path, "w");
    if (!f)
        return -1;

    fprintf(f, "id=%s\n", obj->id);
    fprintf(f, "version=%s\n", obj->version);
    fprintf(f, "category=%d\n", (int)obj->category);
    fprintf(f, "classification=%d\n", (int)obj->classification);
    fprintf(f, "state=%d\n", (int)obj->state);
    fprintf(f, "integrity=%d\n", (int)obj->integrity);
    fprintf(f, "storage_state=%d\n", (int)obj->storage_state);
    fprintf(f, "owner=%s\n", obj->owner);
    fprintf(f, "scope=%d\n", (int)obj->scope);
    fprintf(f, "created_at=%ld\n", (long)obj->created_at);
    fprintf(f, "modified_at=%ld\n", (long)obj->modified_at);
    fprintf(f, "content_size=%lu\n", (unsigned long)obj->content_size);
    fprintf(f, "checksum=%u\n", obj->checksum);
    fprintf(f, "---\n");

    int err = ferror(f);
    fclose(f);
    return err ? -1 : 0;
}

static int _deserialize_obj(const char *path, ozayn_secure_data_object_t *out)
{
    FILE *f = fopen(path, "r");
    if (!f)
        return -1;

    memset(out, 0, sizeof(*out));
    char line[512];
    int found_end = 0;

    while (fgets(line, sizeof(line), f)) {
        /* Remove trailing newline */
        size_t len = strlen(line);
        if (len > 0 && line[len - 1] == '\n')
            line[--len] = '\0';
        if (len > 0 && line[len - 1] == '\r')
            line[--len] = '\0';

        if (strcmp(line, "---") == 0) {
            found_end = 1;
            break;
        }

        char *eq = strchr(line, '=');
        if (!eq)
            continue;
        *eq = '\0';
        const char *key = line;
        const char *val = eq + 1;

        if (strcmp(key, "id") == 0)
            strncpy(out->id, val, OZAYN_SDO_MAX_ID_LEN - 1);
        else if (strcmp(key, "version") == 0)
            strncpy(out->version, val, OZAYN_SDO_MAX_VERSION_LEN - 1);
        else if (strcmp(key, "category") == 0)
            out->category = (ozayn_data_category_t)atoi(val);
        else if (strcmp(key, "classification") == 0)
            out->classification = (ozayn_security_level_t)atoi(val);
        else if (strcmp(key, "state") == 0)
            out->state = (ozayn_data_state_t)atoi(val);
        else if (strcmp(key, "integrity") == 0)
            out->integrity = (ozayn_data_integrity_t)atoi(val);
        else if (strcmp(key, "storage_state") == 0)
            out->storage_state = (ozayn_data_storage_state_t)atoi(val);
        else if (strcmp(key, "owner") == 0)
            strncpy(out->owner, val, OZAYN_SDO_MAX_OWNER_LEN - 1);
        else if (strcmp(key, "scope") == 0)
            out->scope = (ozayn_data_scope_t)atoi(val);
        else if (strcmp(key, "created_at") == 0)
            out->created_at = (time_t)atol(val);
        else if (strcmp(key, "modified_at") == 0)
            out->modified_at = (time_t)atol(val);
        else if (strcmp(key, "content_size") == 0)
            out->content_size = (uint64_t)strtoul(val, NULL, 10);
        else if (strcmp(key, "checksum") == 0)
            out->checksum = (uint32_t)strtoul(val, NULL, 10);
    }

    fclose(f);
    return found_end ? 0 : -1;
}

/* ---- Atomic Write ---- */
static int _atomic_write(const ozayn_sp_local_data_t *data,
                          const char *id,
                          const ozayn_secure_data_object_t *obj)
{
    char tmp_path[OZAYN_SP_LOCAL_MAX_PATH];
    char obj_path[OZAYN_SP_LOCAL_MAX_PATH];
    _build_tmp_path(data, id, tmp_path, sizeof(tmp_path));
    _build_obj_path(data, id, obj_path, sizeof(obj_path));

    if (_serialize_obj(obj, tmp_path) != 0)
        return -1;

    if (rename(tmp_path, obj_path) != 0) {
        /* Cleanup temp file on failure */
        remove(tmp_path);
        return -1;
    }
    return 0;
}

/* ---- Provider Operations ---- */
static ozayn_secure_data_result_t _local_init(ozayn_storage_provider_t *provider)
{
    if (!provider)
        return OZAYN_SD_ERR_NULL;

    ozayn_sp_local_data_t *data = (ozayn_sp_local_data_t *)provider->impl_data;
    if (!data)
        return OZAYN_SD_ERR_NULL;

    if (data->data_dir[0] == '\0') {
        /* Use default: $HOME/.ozayn/data/secure_data/ */
        const char *home = ozayn_fs_home();
        if (!home || home[0] == '\0')
            return OZAYN_SD_ERR_STORAGE_FAILURE;
        snprintf(data->data_dir, OZAYN_SP_LOCAL_MAX_PATH,
                 "%s/.ozayn/data/secure_data", home);
    }

    if (_ensure_dir(data->data_dir) != 0)
        return OZAYN_SD_ERR_STORAGE_FAILURE;

    data->initialized = 1;
    return OZAYN_SD_OK;
}

static void _local_shutdown(ozayn_storage_provider_t *provider)
{
    if (!provider)
        return;
    ozayn_sp_local_data_t *data = (ozayn_sp_local_data_t *)provider->impl_data;
    if (data) {
        data->initialized = 0;
        data->data_dir[0] = '\0';
    }
}

static ozayn_secure_data_result_t _local_create(ozayn_storage_provider_t *provider,
                                                  const ozayn_secure_data_object_t *obj)
{
    if (!provider || !obj)
        return OZAYN_SD_ERR_NULL;

    ozayn_sp_local_data_t *data = (ozayn_sp_local_data_t *)provider->impl_data;
    if (!data || !data->initialized)
        return OZAYN_SD_ERR_NOT_INITIALIZED;

    if (ozayn_sp_local_validate_id(obj->id) != 0)
        return OZAYN_SD_ERR_INVALID_DATA;

    /* Check duplicate */
    char obj_path[OZAYN_SP_LOCAL_MAX_PATH];
    _build_obj_path(data, obj->id, obj_path, sizeof(obj_path));
    struct stat st;
    if (stat(obj_path, &st) == 0)
        return OZAYN_SD_ERR_STATE;  /* DATA_ALREADY_EXISTS */

    if (_atomic_write(data, obj->id, obj) != 0)
        return OZAYN_SD_ERR_STORAGE_FAILURE;

    return OZAYN_SD_OK;
}

static ozayn_secure_data_result_t _local_read(ozayn_storage_provider_t *provider,
                                                const char *id,
                                                ozayn_secure_data_object_t *out_obj)
{
    if (!provider || !id || !out_obj)
        return OZAYN_SD_ERR_NULL;

    ozayn_sp_local_data_t *data = (ozayn_sp_local_data_t *)provider->impl_data;
    if (!data || !data->initialized)
        return OZAYN_SD_ERR_NOT_INITIALIZED;

    if (ozayn_sp_local_validate_id(id) != 0)
        return OZAYN_SD_ERR_INVALID_DATA;

    char obj_path[OZAYN_SP_LOCAL_MAX_PATH];
    _build_obj_path(data, id, obj_path, sizeof(obj_path));

    if (_deserialize_obj(obj_path, out_obj) != 0)
        return OZAYN_SD_ERR_NOT_FOUND;

    /* Validate reconstructed object */
    if (ozayn_sdo_validate(out_obj) != 0)
        return OZAYN_SD_ERR_INTEGRITY;

    return OZAYN_SD_OK;
}

static ozayn_secure_data_result_t _local_update(ozayn_storage_provider_t *provider,
                                                  const ozayn_secure_data_object_t *obj)
{
    if (!provider || !obj)
        return OZAYN_SD_ERR_NULL;

    ozayn_sp_local_data_t *data = (ozayn_sp_local_data_t *)provider->impl_data;
    if (!data || !data->initialized)
        return OZAYN_SD_ERR_NOT_INITIALIZED;

    if (ozayn_sp_local_validate_id(obj->id) != 0)
        return OZAYN_SD_ERR_INVALID_DATA;

    /* Must exist */
    char obj_path[OZAYN_SP_LOCAL_MAX_PATH];
    _build_obj_path(data, obj->id, obj_path, sizeof(obj_path));
    struct stat st;
    if (stat(obj_path, &st) != 0)
        return OZAYN_SD_ERR_NOT_FOUND;

    if (_atomic_write(data, obj->id, obj) != 0)
        return OZAYN_SD_ERR_STORAGE_FAILURE;

    return OZAYN_SD_OK;
}

static ozayn_secure_data_result_t _local_delete(ozayn_storage_provider_t *provider,
                                                  const char *id)
{
    if (!provider || !id)
        return OZAYN_SD_ERR_NULL;

    ozayn_sp_local_data_t *data = (ozayn_sp_local_data_t *)provider->impl_data;
    if (!data || !data->initialized)
        return OZAYN_SD_ERR_NOT_INITIALIZED;

    if (ozayn_sp_local_validate_id(id) != 0)
        return OZAYN_SD_ERR_INVALID_DATA;

    char obj_path[OZAYN_SP_LOCAL_MAX_PATH];
    _build_obj_path(data, id, obj_path, sizeof(obj_path));

    if (remove(obj_path) != 0)
        return OZAYN_SD_ERR_NOT_FOUND;

    return OZAYN_SD_OK;
}

static int _local_exists(ozayn_storage_provider_t *provider, const char *id)
{
    if (!provider || !id)
        return 0;

    ozayn_sp_local_data_t *data = (ozayn_sp_local_data_t *)provider->impl_data;
    if (!data || !data->initialized)
        return 0;

    if (ozayn_sp_local_validate_id(id) != 0)
        return 0;

    char obj_path[OZAYN_SP_LOCAL_MAX_PATH];
    _build_obj_path(data, id, obj_path, sizeof(obj_path));

    struct stat st;
    return stat(obj_path, &st) == 0;
}

static int _local_list(ozayn_storage_provider_t *provider,
                        ozayn_data_category_t category,
                        ozayn_secure_data_object_t *out_array,
                        int max_count)
{
    if (!provider || !out_array || max_count <= 0)
        return 0;

    ozayn_sp_local_data_t *data = (ozayn_sp_local_data_t *)provider->impl_data;
    if (!data || !data->initialized)
        return 0;

    DIR *dir = opendir(data->data_dir);
    if (!dir)
        return 0;

    int count = 0;
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL && count < max_count) {
        const char *name = entry->d_name;
        size_t nlen = strlen(name);
        if (nlen < 5 || strcmp(name + nlen - 4, ".sdo") != 0)
            continue;

        /* Extract ID from filename */
        char id_buf[OZAYN_SP_LOCAL_MAX_ID];
        size_t id_len = nlen - 4;
        if (id_len >= sizeof(id_buf))
            continue;
        strncpy(id_buf, name, id_len);
        id_buf[id_len] = '\0';

        /* Read and filter by category */
        ozayn_secure_data_object_t tmp;
        if (_local_read(provider, id_buf, &tmp) == OZAYN_SD_OK) {
            if (tmp.category == category) {
                out_array[count] = tmp;
                count++;
            }
        }
    }

    closedir(dir);
    return count;
}

static int _local_count(ozayn_storage_provider_t *provider)
{
    if (!provider)
        return 0;

    ozayn_sp_local_data_t *data = (ozayn_sp_local_data_t *)provider->impl_data;
    if (!data || !data->initialized)
        return 0;

    DIR *dir = opendir(data->data_dir);
    if (!dir)
        return 0;

    int count = 0;
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        const char *name = entry->d_name;
        size_t nlen = strlen(name);
        if (nlen >= 5 && strcmp(name + nlen - 4, ".sdo") == 0)
            count++;
    }

    closedir(dir);
    return count;
}

/* ---- Operations Table ---- */
static const ozayn_sp_ops_t _local_ops = {
    .init      = _local_init,
    .shutdown  = _local_shutdown,
    .create    = _local_create,
    .read      = _local_read,
    .update    = _local_update,
    .delete_obj = _local_delete,
    .exists    = _local_exists,
    .list      = _local_list,
    .count     = _local_count,
};

/* ---- Factory ---- */
int ozayn_sp_local_create_provider(ozayn_storage_provider_t *provider,
                                    const char *storage_dir)
{
    if (!provider)
        return -1;

    static ozayn_sp_local_data_t _local_data;
    memset(&_local_data, 0, sizeof(_local_data));

    if (storage_dir && storage_dir[0] != '\0') {
        strncpy(_local_data.data_dir, storage_dir, OZAYN_SP_LOCAL_MAX_PATH - 1);
    }

    memset(provider, 0, sizeof(*provider));
    provider->name      = "LocalPersistent";
    provider->state     = OZAYN_SP_STATE_UNINITIALIZED;
    provider->ops       = &_local_ops;
    provider->impl_data = &_local_data;

    return 0;
}
