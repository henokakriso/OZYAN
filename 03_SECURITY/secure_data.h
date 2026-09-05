#ifndef OZAYN_SECURE_DATA_H
#define OZAYN_SECURE_DATA_H

#include "data_classification.h"

/*
 * secure_data.h — Secure Data Layer Boundary (Section 03, Step 02).
 *
 * Establishes the storage abstraction layer and access boundary between
 * OZAYN application components and sensitive persistent data.
 *
 * Architecture:
 *
 *   OZAYN COMPONENT
 *          |
 *          v
 *   SECURE DATA INTERFACE  <-- this boundary
 *          |
 *          v
 *   DATA CLASSIFICATION
 *          |
 *          v
 *   STORAGE ABSTRACTION
 *          |
 *          v
 *   FUTURE PROTECTION LAYER
 *          |
 *          v
 *   PERSISTENT STORAGE
 *
 * Application modules must NOT directly access sensitive persistent storage.
 * All access goes through the Secure Data Layer.
 */

/* ---- Storage Operations ---- */
typedef enum {
    OZAYN_SD_OP_CREATE = 0,
    OZAYN_SD_OP_READ   = 1,
    OZAYN_SD_OP_UPDATE = 2,
    OZAYN_SD_OP_DELETE = 3,
    OZAYN_SD_OP_EXISTS = 4,
    OZAYN_SD_OP_LIST   = 5
} ozayn_sd_operation_t;

const char *ozayn_sd_operation_name(ozayn_sd_operation_t op);

/* ---- Secure Data Manager ---- */
#define OZAYN_SD_MAX_OBJECTS 256

typedef struct {
    int                         initialized;
    int                         object_count;
    ozayn_data_metadata_t       objects[OZAYN_SD_MAX_OBJECTS];
    int                         total_creates;
    int                         total_reads;
    int                         total_updates;
    int                         total_deletes;
    int                         total_denied;
} ozayn_secure_data_manager_t;

/* ---- Lifecycle ---- */
ozayn_secure_data_result_t ozayn_secure_data_init(ozayn_secure_data_manager_t *mgr);
void ozayn_secure_data_shutdown(ozayn_secure_data_manager_t *mgr);
int  ozayn_secure_data_is_initialized(const ozayn_secure_data_manager_t *mgr);

/* ---- Data Operations ---- */
ozayn_secure_data_result_t ozayn_secure_data_create(ozayn_secure_data_manager_t *mgr,
                                                     const ozayn_data_metadata_t *meta);

ozayn_secure_data_result_t ozayn_secure_data_read(const ozayn_secure_data_manager_t *mgr,
                                                   const char *id,
                                                   ozayn_data_metadata_t *out_meta);

ozayn_secure_data_result_t ozayn_secure_data_update(ozayn_secure_data_manager_t *mgr,
                                                     const char *id,
                                                     const ozayn_data_metadata_t *new_meta);

ozayn_secure_data_result_t ozayn_secure_data_delete(ozayn_secure_data_manager_t *mgr,
                                                     const char *id);

int ozayn_secure_data_exists(const ozayn_secure_data_manager_t *mgr, const char *id);

int ozayn_secure_data_list(const ozayn_secure_data_manager_t *mgr,
                           ozayn_data_category_t category,
                           ozayn_data_metadata_t *out_array,
                           int max_count);

/* ---- Query ---- */
int ozayn_secure_data_object_count(const ozayn_secure_data_manager_t *mgr);
int ozayn_secure_data_category_count(const ozayn_secure_data_manager_t *mgr,
                                      ozayn_data_category_t category);

/* ---- Statistics ---- */
typedef struct {
    int total_objects;
    int total_creates;
    int total_reads;
    int total_updates;
    int total_deletes;
    int total_denied;
} ozayn_secure_data_stats_t;

ozayn_secure_data_stats_t ozayn_secure_data_stats(const ozayn_secure_data_manager_t *mgr);

#endif
