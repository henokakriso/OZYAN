#ifndef OZAYN_KEY_LIFECYCLE_H
#define OZAYN_KEY_LIFECYCLE_H

#include "key_provider.h"
#include "secure_key_storage.h"
#include <stdint.h>
#include <stddef.h>
#include <time.h>

/*
 * key_lifecycle.h — Key Lifecycle & Rotation (Section 03, Step 10).
 *
 * Manages key versions, lifecycle transitions, active-key selection,
 * controlled rotation, and historical-key lookup.
 *
 * Architecture:
 *   KeyLifecycleManager
 *       -> KeyProvider (for key material access)
 *       -> SecureKeyStorage (for key persistence)
 *
 * Lifecycle States:
 *   UNINITIALIZED -> AVAILABLE -> ACTIVE -> RETIRED -> REVOKED
 *
 * Rotation Flow:
 *   1. Generate new key material
 *   2. Store new key in secure storage
 *   3. Register new version
 *   4. Validate new key
 *   5. Activate new key
 *   6. Retire previous key
 */

#define OZAYN_KL_MAX_KEY_VERSIONS  16
#define OZAYN_KL_MAX_KEY_NAMES      8

/* ============================================================
 * KEY LIFECYCLE ERROR CODES
 * ============================================================ */

typedef enum {
    OZAYN_KL_OK                         =  0,
    OZAYN_KL_ERR_NULL                   = -1,
    OZAYN_KL_ERR_NOT_INITIALIZED        = -2,
    OZAYN_KL_ERR_UNAVAILABLE            = -3,
    OZAYN_KL_ERR_NOT_FOUND              = -4,
    OZAYN_KL_ERR_INVALID_TRANSITION     = -5,
    OZAYN_KL_ERR_ALREADY_ACTIVE         = -6,
    OZAYN_KL_ERR_ALREADY_RETIRED        = -7,
    OZAYN_KL_ERR_ALREADY_REVOKED        = -8,
    OZAYN_KL_ERR_VERSION_CONFLICT       = -9,
    OZAYN_KL_ERR_NO_ACTIVE_KEY          = -10,
    OZAYN_KL_ERR_ROTATION_FAILED        = -11,
    OZAYN_KL_ERR_ROTATION_IN_PROGRESS   = -12,
    OZAYN_KL_ERR_KEY_UNAVAILABLE        = -13,
    OZAYN_KL_ERR_KEY_INVALID            = -14,
    OZAYN_KL_ERR_STORAGE_FAILED         = -15,
    OZAYN_KL_ERR_ACTIVATION_FAILED      = -16,
    OZAYN_KL_ERR_RETIREMENT_FAILED      = -17
} ozayn_kl_result_t;

/* ============================================================
 * KEY VERSION ENTRY
 * ============================================================ */

typedef struct {
    ozayn_key_id_t        id;
    ozayn_key_lifecycle_t  lifecycle;
    ozayn_key_purpose_t   purpose;
    uint32_t              key_length;
    time_t                created_at;
    time_t                activated_at;
    time_t                retired_at;
    time_t                revoked_at;
    int                   in_use;
} ozayn_kl_version_t;

/* ============================================================
 * KEY NAME TRACKER
 * ============================================================ */

typedef struct {
    char                    name[OZAYN_KEY_MAX_NAME_LEN];
    ozayn_key_purpose_t     purpose;
    ozayn_kl_version_t      versions[OZAYN_KL_MAX_KEY_VERSIONS];
    int                     version_count;
    int                     active_version_index;  /* -1 if none */
    int                     in_use;
} ozayn_kl_key_entry_t;

/* ============================================================
 * ROTATION CONTEXT
 * ============================================================ */

typedef struct {
    char                    key_name[OZAYN_KEY_MAX_NAME_LEN];
    ozayn_key_purpose_t     purpose;
    uint32_t                old_version;
    uint32_t                new_version;
    int                     in_progress;
    time_t                  started_at;
} ozayn_kl_rotation_t;

/* ============================================================
 * KEY LIFECYCLE MANAGER
 * ============================================================ */

typedef struct {
    ozayn_kl_key_entry_t   keys[OZAYN_KL_MAX_KEY_NAMES];
    int                    key_count;
    ozayn_kl_rotation_t    current_rotation;
    int                    initialized;
} ozayn_kl_manager_t;

/* ============================================================
 * LIFECYCLE
 * ============================================================ */

ozayn_kl_result_t ozayn_kl_init(ozayn_kl_manager_t *mgr);
void ozayn_kl_shutdown(ozayn_kl_manager_t *mgr);

/* ============================================================
 * KEY REGISTRATION
 * ============================================================ */

/* Register a new key name (purpose context) */
ozayn_kl_result_t ozayn_kl_register_key(ozayn_kl_manager_t *mgr,
                                          const char *name,
                                          ozayn_key_purpose_t purpose);

/* Add a version to a registered key name */
ozayn_kl_result_t ozayn_kl_add_version(ozayn_kl_manager_t *mgr,
                                         const char *name,
                                         const ozayn_key_id_t *id,
                                         uint32_t key_length);

/* ============================================================
 * LIFECYCLE TRANSITIONS
 * ============================================================ */

/* Transition a key version to a new lifecycle state */
ozayn_kl_result_t ozayn_kl_transition(ozayn_kl_manager_t *mgr,
                                        const char *name,
                                        uint32_t version,
                                        ozayn_key_lifecycle_t target);

/* Activate a key version (becomes the active key for new operations) */
ozayn_kl_result_t ozayn_kl_activate(ozayn_kl_manager_t *mgr,
                                      const char *name,
                                      uint32_t version);

/* Retire a key version (no longer used for new encryption) */
ozayn_kl_result_t ozayn_kl_retire(ozayn_kl_manager_t *mgr,
                                    const char *name,
                                    uint32_t version);

/* Revoke a key version (untrusted, must not be used) */
ozayn_kl_result_t ozayn_kl_revoke(ozayn_kl_manager_t *mgr,
                                    const char *name,
                                    uint32_t version);

/* ============================================================
 * KEY ROTATION
 * ============================================================ */

/* Start a rotation: create new version, store, activate, retire old */
ozayn_kl_result_t ozayn_kl_rotate(ozayn_kl_manager_t *mgr,
                                    const char *name,
                                    const uint8_t *new_key_material,
                                    size_t key_length);

/* ============================================================
 * KEY LOOKUP
 * ============================================================ */

/* Get the active key version for a given key name and purpose */
ozayn_kl_result_t ozayn_kl_get_active(ozayn_kl_manager_t *mgr,
                                        const char *name,
                                        ozayn_kl_version_t **out_version);

/* Get a specific key version */
ozayn_kl_result_t ozayn_kl_get_version(ozayn_kl_manager_t *mgr,
                                         const char *name,
                                         uint32_t version,
                                         ozayn_kl_version_t **out_version);

/* Get the latest version number for a key name */
ozayn_kl_result_t ozayn_kl_get_latest_version(ozayn_kl_manager_t *mgr,
                                                const char *name,
                                                uint32_t *out_version);

/* Check if a key version is usable (ACTIVE) */
int ozayn_kl_is_active(ozayn_kl_manager_t *mgr,
                        const char *name,
                        uint32_t version);

/* Check if a key version exists and is not revoked */
int ozayn_kl_is_usable(ozayn_kl_manager_t *mgr,
                        const char *name,
                        uint32_t version);

/* ============================================================
 * QUERY
 * ============================================================ */

int ozayn_kl_key_count(const ozayn_kl_manager_t *mgr);
int ozayn_kl_version_count(const ozayn_kl_manager_t *mgr, const char *name);
int ozayn_kl_is_rotation_in_progress(const ozayn_kl_manager_t *mgr);

/* ============================================================
 * NAME HELPERS
 * ============================================================ */

const char *ozayn_kl_result_name(ozayn_kl_result_t result);

#endif
