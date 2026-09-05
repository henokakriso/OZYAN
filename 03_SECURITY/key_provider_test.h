#ifndef OZAYN_KEY_PROVIDER_TEST_H
#define OZAYN_KEY_PROVIDER_TEST_H

#include "key_provider.h"

/*
 * key_provider_test.h — Test-Only Key Provider (Section 03, Step 08).
 *
 * Provides fixed test keys with full key management support.
 * DO NOT use in production.
 */

#define OZAYN_KEY_TEST_MAX_KEYS  8

/* Create a test key provider with a single fixed key */
void ozayn_key_test_create(ozayn_key_provider_t *provider,
                            const uint8_t *key, size_t key_len);

/* Create a test key provider with multiple managed keys */
void ozayn_key_test_create_managed(ozayn_key_provider_t *provider);

#endif
