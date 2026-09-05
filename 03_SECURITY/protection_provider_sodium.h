#ifndef OZAYN_PROTECTION_PROVIDER_SODIUM_H
#define OZAYN_PROTECTION_PROVIDER_SODIUM_H

#include "protection_provider.h"
#include "key_provider.h"

/*
 * protection_provider_sodium.h — Production Protection Provider (Section 03, Step 07).
 *
 * Production protection provider using libsodium's AES-256-GCM authenticated
 * encryption (via crypto_aead_aes256gcm) or XSalsa20-Poly1305 (via
 * crypto_aead_xchacha20poly1305_ietf) depending on hardware support.
 *
 * Uses libsodium 1.0.20 (stable, maintained, BSD license).
 *
 * Requirements:
 *   - libsodium must be installed and linked
 *   - Key provided through ozayn_key_provider_t abstraction
 *   - Fresh nonce generated per encryption via randombytes_buf()
 *
 * This is NOT a key management system. Keys are supplied externally.
 */

#define OZAYN_PROT_SODIUM_KEY_SIZE  32  /* AES-256 */
#define OZAYN_PROT_SODIUM_NONCE_SIZE 12 /* AES-256-GCM nonce */
#define OZAYN_PROT_SODIUM_TAG_SIZE  16  /* AES-256-GCM auth tag */

/* Create a production protection provider backed by libsodium */
void ozayn_prot_sodium_create(ozayn_protection_provider_t *provider,
                               ozayn_key_provider_t *key_provider);

#endif
