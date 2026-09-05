#ifndef OZAYN_STORAGE_PROVIDER_LOCAL_H
#define OZAYN_STORAGE_PROVIDER_LOCAL_H

#include "storage_provider.h"

/*
 * storage_provider_local.h — Local Persistent Storage Provider (Section 03, Step 05).
 *
 * First real persistent storage provider. Stores SecureDataObjects as individual
 * files on the local filesystem.
 *
 * IMPORTANT LIMITATIONS:
 *   - This provider is NOT encrypted
 *   - This provider does NOT provide secure deletion
 *   - This provider does NOT provide access control
 *   - Cryptographic protection is implemented in later steps
 *
 * Storage location: $HOME/.ozayn/data/secure_data/
 * Each object is stored as: {id}.sdo
 *
 * SECURITY:
 *   - Object identifiers are validated (no path traversal)
 *   - Files are created with restrictive permissions (0600)
 *   - Directories created with 0700
 *   - Atomic writes via temp file + rename
 */

#define OZAYN_SP_LOCAL_MAX_PATH 1024
#define OZAYN_SP_LOCAL_MAX_ID   128

/* ---- Local Provider Private Data ---- */
typedef struct {
    char data_dir[OZAYN_SP_LOCAL_MAX_PATH];  /* Resolved storage directory */
    int  initialized;
} ozayn_sp_local_data_t;

/* ---- Factory ---- */
/* Initializes a storage_provider_t with local filesystem operations.
 * The provider must be allocated by the caller.
 * storage_dir: custom data directory, or NULL for default ($HOME/.ozayn/data/secure_data/) */
int ozayn_sp_local_create_provider(ozayn_storage_provider_t *provider,
                                    const char *storage_dir);

/* ---- Path Helpers ---- */
/* Validate that an identifier is safe for use as a filename.
 * Returns 0 if safe, -1 if the identifier contains path traversal or invalid chars. */
int ozayn_sp_local_validate_id(const char *id);

#endif
