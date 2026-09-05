#ifndef OZAYN_STORAGE_PROVIDER_MEM_H
#define OZAYN_STORAGE_PROVIDER_MEM_H

#include "storage_provider.h"

/*
 * storage_provider_mem.h — In-Memory Storage Provider (Section 03, Step 04).
 *
 * A minimal in-memory storage provider for testing the storage abstraction.
 *
 * WARNING: This is a TEST-ONLY implementation. It provides:
 *   - No encryption
 *   - No persistence
 *   - No access control
 *   - No secure deletion
 *
 * It exists solely to validate that the storage abstraction works correctly.
 * Do NOT use this as production storage.
 */

#define OZAYN_SP_MEM_MAX_OBJECTS 256

/* ---- In-Memory Provider Private Data ---- */
typedef struct {
    ozayn_secure_data_object_t objects[OZAYN_SP_MEM_MAX_OBJECTS];
    int                        count;
    int                        initialized;
} ozayn_sp_mem_data_t;

/* ---- Factory ---- */
/* Initializes a storage_provider_t with in-memory operations.
 * The provider must be allocated by the caller. */
int ozayn_sp_mem_create_provider(ozayn_storage_provider_t *provider);

#endif
