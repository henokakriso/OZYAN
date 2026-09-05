#ifndef OZAYN_KEY_PROVIDER_TEST_H
#define OZAYN_KEY_PROVIDER_TEST_H

#include "key_provider.h"

/*
 * key_provider_test.h — Test-Only Key Provider (Section 03, Step 07).
 *
 * A controlled key provider for testing the protection architecture.
 * Provides a fixed key for deterministic testing.
 * DO NOT use in production.
 */

/* Create a test key provider with a fixed key */
void ozayn_key_test_create(ozayn_key_provider_t *provider,
                            const uint8_t *key, size_t key_len);

#endif
