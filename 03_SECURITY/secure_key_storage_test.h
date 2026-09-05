#ifndef OZAYN_SECURE_KEY_STORAGE_TEST_H
#define OZAYN_SECURE_KEY_STORAGE_TEST_H

#include "secure_key_storage.h"

/*
 * secure_key_storage_test.h — Test-Only Key Storage Backend (Section 03, Step 09).
 *
 * In-memory key storage backend for testing.
 * Supports: store, load, exists, remove, metadata.
 * Simulates platform failure when configured.
 * DO NOT use in production.
 */

#define OZAYN_KS_TEST_MAX_ENTRIES  16

/* Configuration flags */
typedef struct {
    int  fail_store;       /* Force store operations to fail */
    int  fail_load;        /* Force load operations to fail */
    int  fail_remove;      /* Force remove operations to fail */
    int  unavailable;      /* Simulate storage unavailability */
    int  access_denied;    /* Simulate access denied */
} ozayn_ks_test_config_t;

/* Create a test key storage backend */
void ozayn_ks_test_create(ozayn_key_storage_t *storage,
                           ozayn_ks_test_config_t *config);

#endif
