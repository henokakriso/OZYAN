#ifndef OZAYN_STORAGE_PROVIDER_H
#define OZAYN_STORAGE_PROVIDER_H

#include "secure_data_object.h"

/*
 * storage_provider.h — Storage Abstraction & Provider Contract (Section 03, Step 04).
 *
 * Defines the storage abstraction layer that separates OZAYN's secure data
 * logic from the actual persistent storage implementation. Application modules
 * interact with this interface; they never touch storage directly.
 *
 * Architecture:
 *
 *   OZAYN MODULE
 *          |
 *          v
 *   SECURE DATA OBJECT
 *          |
 *          v
 *   VALIDATION
 *          |
 *          v
 *   STORAGE PROVIDER  <-- this layer
 *          |
 *          v
 *   [File / DB / OS / Encrypted / etc.]
 *
 * The in-memory provider (storage_provider_mem.h) exists only for testing.
 * It is NOT production secure storage.
 */

/* ---- Storage Provider State ---- */
typedef enum {
    OZAYN_SP_STATE_UNINITIALIZED = 0,
    OZAYN_SP_STATE_INITIALIZED   = 1,
    OZAYN_SP_STATE_READY         = 2,
    OZAYN_SP_STATE_SHUTTING_DOWN = 3,
    OZAYN_SP_STATE_STOPPED       = 4
} ozayn_sp_state_t;

/* ---- Storage Provider Stats ---- */
typedef struct {
    int total_creates;
    int total_reads;
    int total_updates;
    int total_deletes;
    int total_exists;
    int total_lists;
    int total_errors;
} ozayn_sp_stats_t;

/* ---- Storage Provider Interface (vtable) ---- */
typedef struct ozayn_storage_provider ozayn_storage_provider_t;

typedef struct {
    /* Lifecycle */
    ozayn_secure_data_result_t (*init)(ozayn_storage_provider_t *provider);
    void                       (*shutdown)(ozayn_storage_provider_t *provider);

    /* Operations */
    ozayn_secure_data_result_t (*create)(ozayn_storage_provider_t *provider,
                                         const ozayn_secure_data_object_t *obj);

    ozayn_secure_data_result_t (*read)(ozayn_storage_provider_t *provider,
                                        const char *id,
                                        ozayn_secure_data_object_t *out_obj);

    ozayn_secure_data_result_t (*update)(ozayn_storage_provider_t *provider,
                                          const ozayn_secure_data_object_t *obj);

    ozayn_secure_data_result_t (*delete_obj)(ozayn_storage_provider_t *provider,
                                              const char *id);

    int (*exists)(ozayn_storage_provider_t *provider, const char *id);

    int (*list)(ozayn_storage_provider_t *provider,
                ozayn_data_category_t category,
                ozayn_secure_data_object_t *out_array,
                int max_count);

    /* Query */
    int (*count)(ozayn_storage_provider_t *provider);

} ozayn_sp_ops_t;

/* ---- Storage Provider ---- */
struct ozayn_storage_provider {
    const char              *name;
    ozayn_sp_state_t         state;
    const ozayn_sp_ops_t    *ops;
    void                    *impl_data;    /* Provider-specific private data */
    ozayn_sp_stats_t         stats;
};

/* ---- Provider Lifecycle ---- */
ozayn_secure_data_result_t ozayn_sp_init(ozayn_storage_provider_t *provider);
void ozayn_sp_shutdown(ozayn_storage_provider_t *provider);
int  ozayn_sp_is_ready(const ozayn_storage_provider_t *provider);

/* ---- Provider Operations (dispatch through vtable) ---- */
ozayn_secure_data_result_t ozayn_sp_create(ozayn_storage_provider_t *provider,
                                            const ozayn_secure_data_object_t *obj);

ozayn_secure_data_result_t ozayn_sp_read(ozayn_storage_provider_t *provider,
                                           const char *id,
                                           ozayn_secure_data_object_t *out_obj);

ozayn_secure_data_result_t ozayn_sp_update(ozayn_storage_provider_t *provider,
                                             const ozayn_secure_data_object_t *obj);

ozayn_secure_data_result_t ozayn_sp_delete(ozayn_storage_provider_t *provider,
                                             const char *id);

int ozayn_sp_exists(ozayn_storage_provider_t *provider, const char *id);

int ozayn_sp_list(ozayn_storage_provider_t *provider,
                  ozayn_data_category_t category,
                  ozayn_secure_data_object_t *out_array,
                  int max_count);

int ozayn_sp_count(ozayn_storage_provider_t *provider);

/* ---- Provider Stats ---- */
ozayn_sp_stats_t ozayn_sp_stats(const ozayn_storage_provider_t *provider);

/* ---- Name Helpers ---- */
const char *ozayn_sp_state_name(ozayn_sp_state_t state);

#endif
