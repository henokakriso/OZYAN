#ifndef OZAYN_PROTECTION_PROVIDER_MOCK_H
#define OZAYN_PROTECTION_PROVIDER_MOCK_H

#include "protection_provider.h"

/*
 * protection_provider_mock.h — Test-Only Protection Provider (Section 03, Step 06).
 *
 * A deterministic mock protection provider for testing the protection architecture.
 * DO NOT use this in production. This mock:
 *   - Uses XOR-based "encryption" (NOT cryptographically secure)
 *   - Always uses a fixed key (DO NOT use in production)
 *   - Provides authenticated-encryption simulation via a simple checksum tag
 *   - Simulates protection/unprotection failures when configured
 *
 * Production encryption must use a vetted cryptographic library.
 */

#define OZAYN_PROT_MOCK_MAX_PROTECTED_OBJECTS  64
#define OZAYN_PROT_MOCK_KEY_SIZE               32
#define OZAYN_PROT_MOCK_TAG_SIZE               8

/* Mock configuration flags */
typedef struct {
    int  fail_protect;       /* Force protect to fail */
    int  fail_unprotect;     /* Force unprotect to fail */
    int  inject_tag_error;   /* Corrupt tag on protect (tamper simulation) */
    int  require_auth_check; /* If set, unprotect verifies tag integrity */
} ozayn_prot_mock_config_t;

/* Create a mock protection provider for testing */
void ozayn_prot_mock_create(ozayn_protection_provider_t *provider,
                             ozayn_prot_mock_config_t *config);

/* Get the mock provider's ops table (for direct access if needed) */
const ozayn_prot_ops_t *ozayn_prot_mock_get_ops(void);

/* Verify mock protected data has consistent tag */
int ozayn_prot_mock_verify_tag(const ozayn_protected_data_t *pd);

#endif
