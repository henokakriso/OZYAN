#ifndef OZAYN_KEY_PROVIDER_H
#define OZAYN_KEY_PROVIDER_H

#include <stdint.h>
#include <stddef.h>

/*
 * key_provider.h — Key Provider Abstraction (Section 03, Step 07).
 *
 * Abstracts the source of encryption keys from the protection provider.
 * The protection implementation must not know where the key comes from.
 *
 * For testing, a controlled test key source may be used.
 * Production key storage belongs to the later key-management steps.
 */

#define OZAYN_KEY_MAX_SIZE  64

/* ---- Key Provider Error Codes ---- */
typedef enum {
    OZAYN_KEY_OK                  =  0,
    OZAYN_KEY_ERR_NULL            = -1,
    OZAYN_KEY_ERR_UNAVAILABLE     = -2,
    OZAYN_KEY_ERR_INVALID_SIZE    = -3,
    OZAYN_KEY_ERR_NOT_INITIALIZED = -4
} ozayn_key_result_t;

/* ---- Key Provider State ---- */
typedef enum {
    OZAYN_KEY_STATE_UNINITIALIZED = 0,
    OZAYN_KEY_STATE_INITIALIZED   = 1,
    OZAYN_KEY_STATE_READY         = 2,
    OZAYN_KEY_STATE_STOPPED       = 3
} ozayn_key_state_t;

/* ---- Key Provider Interface (vtable) ---- */
typedef struct ozayn_key_provider ozayn_key_provider_t;

typedef struct {
    ozayn_key_result_t (*init)(ozayn_key_provider_t *provider);
    void               (*shutdown)(ozayn_key_provider_t *provider);
    ozayn_key_result_t (*get_key)(ozayn_key_provider_t *provider,
                                   uint8_t *key_out, size_t key_size);
    int                (*is_available)(const ozayn_key_provider_t *provider);
    size_t             (*key_length)(const ozayn_key_provider_t *provider);
} ozayn_key_ops_t;

/* ---- Key Provider ---- */
struct ozayn_key_provider {
    const char              *name;
    ozayn_key_state_t        state;
    const ozayn_key_ops_t   *ops;
    void                    *impl_data;
};

/* ---- Lifecycle ---- */
ozayn_key_result_t ozayn_key_init(ozayn_key_provider_t *provider);
void ozayn_key_shutdown(ozayn_key_provider_t *provider);
int  ozayn_key_is_ready(const ozayn_key_provider_t *provider);

/* ---- Operations ---- */
ozayn_key_result_t ozayn_key_get(ozayn_key_provider_t *provider,
                                   uint8_t *key_out, size_t key_size);
int  ozayn_key_is_available(const ozayn_key_provider_t *provider);
size_t ozayn_key_length(const ozayn_key_provider_t *provider);

/* ---- Name Helper ---- */
const char *ozayn_key_result_name(ozayn_key_result_t result);

#endif
