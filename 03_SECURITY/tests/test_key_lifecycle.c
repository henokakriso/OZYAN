#include "../../tests/test_framework.h"
#include "../key_lifecycle.h"
#include "../key_provider.h"
#include <string.h>

/*
 * test_key_lifecycle.c — Key Lifecycle & Rotation tests (Section 03, Step 10).
 */

/* ---- Lifecycle State Tests ---- */

int test_lifecycle_valid_transitions(void)
{
    ozayn_kl_manager_t mgr;
    ASSERT_EQ(OZAYN_KL_OK, ozayn_kl_init(&mgr));

    /* Register and add version */
    ASSERT_EQ(OZAYN_KL_OK, ozayn_kl_register_key(&mgr, "DATA", OZAYN_KEY_PURPOSE_DATA_ENCRYPTION));
    ozayn_key_id_t id;
    ozayn_key_id_set(&id, "DATA", 1, "test");
    ASSERT_EQ(OZAYN_KL_OK, ozayn_kl_add_version(&mgr, "DATA", &id, 32));

    /* Check initial state */
    ozayn_kl_version_t *ver;
    ASSERT_EQ(OZAYN_KL_OK, ozayn_kl_get_version(&mgr, "DATA", 1, &ver));
    ASSERT_EQ(OZAYN_KEY_LIFECYCLE_AVAILABLE, ver->lifecycle);

    /* AVAILABLE -> ACTIVE */
    ASSERT_EQ(OZAYN_KL_OK, ozayn_kl_transition(&mgr, "DATA", 1, OZAYN_KEY_LIFECYCLE_ACTIVE));
    ASSERT_EQ(OZAYN_KEY_LIFECYCLE_ACTIVE, ver->lifecycle);

    /* ACTIVE -> RETIRED */
    ASSERT_EQ(OZAYN_KL_OK, ozayn_kl_transition(&mgr, "DATA", 1, OZAYN_KEY_LIFECYCLE_RETIRED));
    ASSERT_EQ(OZAYN_KEY_LIFECYCLE_RETIRED, ver->lifecycle);

    /* Test a fresh key for ACTIVE -> REVOKED */
    ozayn_key_id_set(&id, "DATA", 2, "test");
    ASSERT_EQ(OZAYN_KL_OK, ozayn_kl_add_version(&mgr, "DATA", &id, 32));
    ASSERT_EQ(OZAYN_KL_OK, ozayn_kl_transition(&mgr, "DATA", 2, OZAYN_KEY_LIFECYCLE_ACTIVE));
    ASSERT_EQ(OZAYN_KL_OK, ozayn_kl_transition(&mgr, "DATA", 2, OZAYN_KEY_LIFECYCLE_REVOKED));
    ozayn_kl_version_t *ver2;
    ASSERT_EQ(OZAYN_KL_OK, ozayn_kl_get_version(&mgr, "DATA", 2, &ver2));
    ASSERT_EQ(OZAYN_KEY_LIFECYCLE_REVOKED, ver2->lifecycle);

    /* RETIRED -> REVOKED */
    ASSERT_EQ(OZAYN_KL_OK, ozayn_kl_transition(&mgr, "DATA", 1, OZAYN_KEY_LIFECYCLE_REVOKED));

    ozayn_kl_shutdown(&mgr);
    return 0;
}

int test_lifecycle_invalid_transitions(void)
{
    ozayn_kl_manager_t mgr;
    ASSERT_EQ(OZAYN_KL_OK, ozayn_kl_init(&mgr));

    ASSERT_EQ(OZAYN_KL_OK, ozayn_kl_register_key(&mgr, "DATA", OZAYN_KEY_PURPOSE_DATA_ENCRYPTION));
    ozayn_key_id_t id;
    ozayn_key_id_set(&id, "DATA", 1, "test");
    ASSERT_EQ(OZAYN_KL_OK, ozayn_kl_add_version(&mgr, "DATA", &id, 32));

    /* Revoked -> Active (INVALID) */
    ASSERT_EQ(OZAYN_KL_OK, ozayn_kl_transition(&mgr, "DATA", 1, OZAYN_KEY_LIFECYCLE_ACTIVE));
    ASSERT_EQ(OZAYN_KL_OK, ozayn_kl_transition(&mgr, "DATA", 1, OZAYN_KEY_LIFECYCLE_REVOKED));
    ASSERT_EQ(OZAYN_KL_ERR_INVALID_TRANSITION,
              ozayn_kl_transition(&mgr, "DATA", 1, OZAYN_KEY_LIFECYCLE_ACTIVE));

    /* Retired -> Active (INVALID) */
    ozayn_key_id_set(&id, "DATA", 2, "test");
    ASSERT_EQ(OZAYN_KL_OK, ozayn_kl_add_version(&mgr, "DATA", &id, 32));
    ASSERT_EQ(OZAYN_KL_OK, ozayn_kl_transition(&mgr, "DATA", 2, OZAYN_KEY_LIFECYCLE_ACTIVE));
    ASSERT_EQ(OZAYN_KL_OK, ozayn_kl_transition(&mgr, "DATA", 2, OZAYN_KEY_LIFECYCLE_RETIRED));
    ASSERT_EQ(OZAYN_KL_ERR_INVALID_TRANSITION,
              ozayn_kl_transition(&mgr, "DATA", 2, OZAYN_KEY_LIFECYCLE_ACTIVE));

    /* Revoked -> Available (INVALID) */
    ozayn_key_id_set(&id, "DATA", 3, "test");
    ASSERT_EQ(OZAYN_KL_OK, ozayn_kl_add_version(&mgr, "DATA", &id, 32));
    ASSERT_EQ(OZAYN_KL_OK, ozayn_kl_transition(&mgr, "DATA", 3, OZAYN_KEY_LIFECYCLE_ACTIVE));
    ASSERT_EQ(OZAYN_KL_OK, ozayn_kl_transition(&mgr, "DATA", 3, OZAYN_KEY_LIFECYCLE_REVOKED));
    ASSERT_EQ(OZAYN_KL_ERR_INVALID_TRANSITION,
              ozayn_kl_transition(&mgr, "DATA", 3, OZAYN_KEY_LIFECYCLE_AVAILABLE));

    ozayn_kl_shutdown(&mgr);
    return 0;
}

int test_lifecycle_already_active(void)
{
    ozayn_kl_manager_t mgr;
    ASSERT_EQ(OZAYN_KL_OK, ozayn_kl_init(&mgr));

    ASSERT_EQ(OZAYN_KL_OK, ozayn_kl_register_key(&mgr, "DATA", OZAYN_KEY_PURPOSE_DATA_ENCRYPTION));
    ozayn_key_id_t id;
    ozayn_key_id_set(&id, "DATA", 1, "test");
    ASSERT_EQ(OZAYN_KL_OK, ozayn_kl_add_version(&mgr, "DATA", &id, 32));

    ASSERT_EQ(OZAYN_KL_OK, ozayn_kl_activate(&mgr, "DATA", 1));
    ASSERT_EQ(OZAYN_KL_ERR_ALREADY_ACTIVE, ozayn_kl_activate(&mgr, "DATA", 1));

    ozayn_kl_shutdown(&mgr);
    return 0;
}

int test_lifecycle_already_revoked(void)
{
    ozayn_kl_manager_t mgr;
    ASSERT_EQ(OZAYN_KL_OK, ozayn_kl_init(&mgr));

    ASSERT_EQ(OZAYN_KL_OK, ozayn_kl_register_key(&mgr, "DATA", OZAYN_KEY_PURPOSE_DATA_ENCRYPTION));
    ozayn_key_id_t id;
    ozayn_key_id_set(&id, "DATA", 1, "test");
    ASSERT_EQ(OZAYN_KL_OK, ozayn_kl_add_version(&mgr, "DATA", &id, 32));

    ASSERT_EQ(OZAYN_KL_OK, ozayn_kl_revoke(&mgr, "DATA", 1));
    ASSERT_EQ(OZAYN_KL_ERR_ALREADY_REVOKED, ozayn_kl_revoke(&mgr, "DATA", 1));

    ozayn_kl_shutdown(&mgr);
    return 0;
}

int test_lifecycle_already_retired(void)
{
    ozayn_kl_manager_t mgr;
    ASSERT_EQ(OZAYN_KL_OK, ozayn_kl_init(&mgr));

    ASSERT_EQ(OZAYN_KL_OK, ozayn_kl_register_key(&mgr, "DATA", OZAYN_KEY_PURPOSE_DATA_ENCRYPTION));
    ozayn_key_id_t id;
    ozayn_key_id_set(&id, "DATA", 1, "test");
    ASSERT_EQ(OZAYN_KL_OK, ozayn_kl_add_version(&mgr, "DATA", &id, 32));

    ASSERT_EQ(OZAYN_KL_OK, ozayn_kl_transition(&mgr, "DATA", 1, OZAYN_KEY_LIFECYCLE_ACTIVE));
    ASSERT_EQ(OZAYN_KL_OK, ozayn_kl_transition(&mgr, "DATA", 1, OZAYN_KEY_LIFECYCLE_RETIRED));
    ASSERT_EQ(OZAYN_KL_ERR_ALREADY_RETIRED, ozayn_kl_retire(&mgr, "DATA", 1));

    ozayn_kl_shutdown(&mgr);
    return 0;
}

/* ---- Key Registration Tests ---- */

int test_register_key(void)
{
    ozayn_kl_manager_t mgr;
    ASSERT_EQ(OZAYN_KL_OK, ozayn_kl_init(&mgr));

    ASSERT_EQ(OZAYN_KL_OK, ozayn_kl_register_key(&mgr, "DATA", OZAYN_KEY_PURPOSE_DATA_ENCRYPTION));
    ASSERT_EQ(1, ozayn_kl_key_count(&mgr));

    /* Duplicate name rejected */
    ASSERT_EQ(OZAYN_KL_ERR_VERSION_CONFLICT,
              ozayn_kl_register_key(&mgr, "DATA", OZAYN_KEY_PURPOSE_DATA_ENCRYPTION));

    ozayn_kl_shutdown(&mgr);
    return 0;
}

int test_add_version(void)
{
    ozayn_kl_manager_t mgr;
    ASSERT_EQ(OZAYN_KL_OK, ozayn_kl_init(&mgr));

    ASSERT_EQ(OZAYN_KL_OK, ozayn_kl_register_key(&mgr, "DATA", OZAYN_KEY_PURPOSE_DATA_ENCRYPTION));

    ozayn_key_id_t id;
    ozayn_key_id_set(&id, "DATA", 1, "test");
    ASSERT_EQ(OZAYN_KL_OK, ozayn_kl_add_version(&mgr, "DATA", &id, 32));
    ASSERT_EQ(1, ozayn_kl_version_count(&mgr, "DATA"));

    /* Duplicate version rejected */
    ASSERT_EQ(OZAYN_KL_ERR_VERSION_CONFLICT, ozayn_kl_add_version(&mgr, "DATA", &id, 32));

    /* Version 2 allowed */
    ozayn_key_id_set(&id, "DATA", 2, "test");
    ASSERT_EQ(OZAYN_KL_OK, ozayn_kl_add_version(&mgr, "DATA", &id, 32));
    ASSERT_EQ(2, ozayn_kl_version_count(&mgr, "DATA"));

    ozayn_kl_shutdown(&mgr);
    return 0;
}

int test_activate_replaces_active(void)
{
    ozayn_kl_manager_t mgr;
    ASSERT_EQ(OZAYN_KL_OK, ozayn_kl_init(&mgr));

    ASSERT_EQ(OZAYN_KL_OK, ozayn_kl_register_key(&mgr, "DATA", OZAYN_KEY_PURPOSE_DATA_ENCRYPTION));

    ozayn_key_id_t id;
    ozayn_key_id_set(&id, "DATA", 1, "test");
    ASSERT_EQ(OZAYN_KL_OK, ozayn_kl_add_version(&mgr, "DATA", &id, 32));

    ozayn_key_id_set(&id, "DATA", 2, "test");
    ASSERT_EQ(OZAYN_KL_OK, ozayn_kl_add_version(&mgr, "DATA", &id, 32));

    ASSERT_EQ(OZAYN_KL_OK, ozayn_kl_activate(&mgr, "DATA", 1));
    ASSERT_EQ(1, ozayn_kl_is_active(&mgr, "DATA", 1));

    /* Activating V2 retires V1 */
    ASSERT_EQ(OZAYN_KL_OK, ozayn_kl_activate(&mgr, "DATA", 2));
    ASSERT_EQ(0, ozayn_kl_is_active(&mgr, "DATA", 1));
    ASSERT_EQ(1, ozayn_kl_is_active(&mgr, "DATA", 2));

    /* V1 is retired, not revoked */
    ozayn_kl_version_t *v1;
    ASSERT_EQ(OZAYN_KL_OK, ozayn_kl_get_version(&mgr, "DATA", 1, &v1));
    ASSERT_EQ(OZAYN_KEY_LIFECYCLE_RETIRED, v1->lifecycle);

    ozayn_kl_shutdown(&mgr);
    return 0;
}

int test_revoked_key_unusable(void)
{
    ozayn_kl_manager_t mgr;
    ASSERT_EQ(OZAYN_KL_OK, ozayn_kl_init(&mgr));

    ASSERT_EQ(OZAYN_KL_OK, ozayn_kl_register_key(&mgr, "DATA", OZAYN_KEY_PURPOSE_DATA_ENCRYPTION));

    ozayn_key_id_t id;
    ozayn_key_id_set(&id, "DATA", 1, "test");
    ASSERT_EQ(OZAYN_KL_OK, ozayn_kl_add_version(&mgr, "DATA", &id, 32));

    ASSERT_EQ(OZAYN_KL_OK, ozayn_kl_revoke(&mgr, "DATA", 1));

    /* Revoked key is not active */
    ASSERT_EQ(0, ozayn_kl_is_active(&mgr, "DATA", 1));

    /* Revoked key is not usable */
    ASSERT_EQ(0, ozayn_kl_is_usable(&mgr, "DATA", 1));

    ozayn_kl_shutdown(&mgr);
    return 0;
}

/* ---- Rotation Tests ---- */

int test_rotation_basic(void)
{
    ozayn_kl_manager_t mgr;
    ASSERT_EQ(OZAYN_KL_OK, ozayn_kl_init(&mgr));

    ASSERT_EQ(OZAYN_KL_OK, ozayn_kl_register_key(&mgr, "DATA", OZAYN_KEY_PURPOSE_DATA_ENCRYPTION));

    /* Initial key V1 */
    ozayn_key_id_t id;
    ozayn_key_id_set(&id, "DATA", 1, "test");
    ASSERT_EQ(OZAYN_KL_OK, ozayn_kl_add_version(&mgr, "DATA", &id, 32));
    ASSERT_EQ(OZAYN_KL_OK, ozayn_kl_activate(&mgr, "DATA", 1));

    /* Rotate V1 -> V2 */
    uint8_t new_key[32];
    memset(new_key, 0x42, sizeof(new_key));
    ASSERT_EQ(OZAYN_KL_OK, ozayn_kl_rotate(&mgr, "DATA", new_key, sizeof(new_key)));

    /* V2 is now active */
    ASSERT_EQ(1, ozayn_kl_is_active(&mgr, "DATA", 2));
    ASSERT_EQ(0, ozayn_kl_is_active(&mgr, "DATA", 1));

    /* V1 is retired but still usable */
    ASSERT_EQ(1, ozayn_kl_is_usable(&mgr, "DATA", 1));

    /* Latest version is 2 */
    uint32_t latest;
    ASSERT_EQ(OZAYN_KL_OK, ozayn_kl_get_latest_version(&mgr, "DATA", &latest));
    ASSERT_EQ(2, (int)latest);

    ozayn_kl_shutdown(&mgr);
    return 0;
}

int test_rotation_failure_safety(void)
{
    ozayn_kl_manager_t mgr;
    ASSERT_EQ(OZAYN_KL_OK, ozayn_kl_init(&mgr));

    /* Register with invalid purpose to cause failure */
    ASSERT_EQ(OZAYN_KL_OK, ozayn_kl_register_key(&mgr, "DATA", OZAYN_KEY_PURPOSE_DATA_ENCRYPTION));

    /* Initial key V1 active */
    ozayn_key_id_t id;
    ozayn_key_id_set(&id, "DATA", 1, "test");
    ASSERT_EQ(OZAYN_KL_OK, ozayn_kl_add_version(&mgr, "DATA", &id, 32));
    ASSERT_EQ(OZAYN_KL_OK, ozayn_kl_activate(&mgr, "DATA", 1));

    /* Rotate succeeds */
    uint8_t new_key[32];
    memset(new_key, 0x43, sizeof(new_key));
    ASSERT_EQ(OZAYN_KL_OK, ozayn_kl_rotate(&mgr, "DATA", new_key, sizeof(new_key)));

    /* V2 active, V1 retired - old key still usable */
    ASSERT_EQ(1, ozayn_kl_is_active(&mgr, "DATA", 2));
    ASSERT_EQ(1, ozayn_kl_is_usable(&mgr, "DATA", 1));

    ozayn_kl_shutdown(&mgr);
    return 0;
}

int test_rotation_no_double(void)
{
    ozayn_kl_manager_t mgr;
    ASSERT_EQ(OZAYN_KL_OK, ozayn_kl_init(&mgr));

    ASSERT_EQ(OZAYN_KL_OK, ozayn_kl_register_key(&mgr, "DATA", OZAYN_KEY_PURPOSE_DATA_ENCRYPTION));

    ozayn_key_id_t id;
    ozayn_key_id_set(&id, "DATA", 1, "test");
    ASSERT_EQ(OZAYN_KL_OK, ozayn_kl_add_version(&mgr, "DATA", &id, 32));
    ASSERT_EQ(OZAYN_KL_OK, ozayn_kl_activate(&mgr, "DATA", 1));

    uint8_t new_key[32];
    memset(new_key, 0x44, sizeof(new_key));
    ASSERT_EQ(OZAYN_KL_OK, ozayn_kl_rotate(&mgr, "DATA", new_key, sizeof(new_key)));

    /* No concurrent rotation - complete first */
    ASSERT_EQ(0, ozayn_kl_is_rotation_in_progress(&mgr));

    /* Second rotation succeeds (V2 -> V3) */
    memset(new_key, 0x45, sizeof(new_key));
    ASSERT_EQ(OZAYN_KL_OK, ozayn_kl_rotate(&mgr, "DATA", new_key, sizeof(new_key)));

    uint32_t latest;
    ASSERT_EQ(OZAYN_KL_OK, ozayn_kl_get_latest_version(&mgr, "DATA", &latest));
    ASSERT_EQ(3, (int)latest);

    ozayn_kl_shutdown(&mgr);
    return 0;
}

int test_rotation_historical_key_preserved(void)
{
    ozayn_kl_manager_t mgr;
    ASSERT_EQ(OZAYN_KL_OK, ozayn_kl_init(&mgr));

    ASSERT_EQ(OZAYN_KL_OK, ozayn_kl_register_key(&mgr, "DATA", OZAYN_KEY_PURPOSE_DATA_ENCRYPTION));

    ozayn_key_id_t id;
    ozayn_key_id_set(&id, "DATA", 1, "test");
    ASSERT_EQ(OZAYN_KL_OK, ozayn_kl_add_version(&mgr, "DATA", &id, 32));
    ASSERT_EQ(OZAYN_KL_OK, ozayn_kl_activate(&mgr, "DATA", 1));

    /* Rotate twice */
    uint8_t new_key[32];
    memset(new_key, 0x46, sizeof(new_key));
    ASSERT_EQ(OZAYN_KL_OK, ozayn_kl_rotate(&mgr, "DATA", new_key, sizeof(new_key)));
    memset(new_key, 0x47, sizeof(new_key));
    ASSERT_EQ(OZAYN_KL_OK, ozayn_kl_rotate(&mgr, "DATA", new_key, sizeof(new_key)));

    /* V1 retired, V2 retired, V3 active */
    ASSERT_EQ(0, ozayn_kl_is_active(&mgr, "DATA", 1));
    ASSERT_EQ(0, ozayn_kl_is_active(&mgr, "DATA", 2));
    ASSERT_EQ(1, ozayn_kl_is_active(&mgr, "DATA", 3));

    /* All historical keys still usable */
    ASSERT_EQ(1, ozayn_kl_is_usable(&mgr, "DATA", 1));
    ASSERT_EQ(1, ozayn_kl_is_usable(&mgr, "DATA", 2));
    ASSERT_EQ(1, ozayn_kl_is_usable(&mgr, "DATA", 3));

    ozayn_kl_shutdown(&mgr);
    return 0;
}

int test_rotation_new_key_not_usable(void)
{
    ozayn_kl_manager_t mgr;
    ASSERT_EQ(OZAYN_KL_OK, ozayn_kl_init(&mgr));

    ASSERT_EQ(OZAYN_KL_OK, ozayn_kl_register_key(&mgr, "DATA", OZAYN_KEY_PURPOSE_DATA_ENCRYPTION));

    ozayn_key_id_t id;
    ozayn_key_id_set(&id, "DATA", 1, "test");
    ASSERT_EQ(OZAYN_KL_OK, ozayn_kl_add_version(&mgr, "DATA", &id, 32));
    ASSERT_EQ(OZAYN_KL_OK, ozayn_kl_activate(&mgr, "DATA", 1));

    /* New data after rotation uses new key */
    uint8_t new_key[32];
    memset(new_key, 0x48, sizeof(new_key));
    ASSERT_EQ(OZAYN_KL_OK, ozayn_kl_rotate(&mgr, "DATA", new_key, sizeof(new_key)));

    /* V2 active for new data */
    ASSERT_EQ(1, ozayn_kl_is_active(&mgr, "DATA", 2));

    ozayn_kl_shutdown(&mgr);
    return 0;
}

int test_rotation_revoked_key_no_rotate(void)
{
    ozayn_kl_manager_t mgr;
    ASSERT_EQ(OZAYN_KL_OK, ozayn_kl_init(&mgr));

    ASSERT_EQ(OZAYN_KL_OK, ozayn_kl_register_key(&mgr, "DATA", OZAYN_KEY_PURPOSE_DATA_ENCRYPTION));

    ozayn_key_id_t id;
    ozayn_key_id_set(&id, "DATA", 1, "test");
    ASSERT_EQ(OZAYN_KL_OK, ozayn_kl_add_version(&mgr, "DATA", &id, 32));
    ASSERT_EQ(OZAYN_KL_OK, ozayn_kl_activate(&mgr, "DATA", 1));
    ASSERT_EQ(OZAYN_KL_OK, ozayn_kl_revoke(&mgr, "DATA", 1));

    /* Revoked key cannot rotate - no active key */
    ASSERT_EQ(0, ozayn_kl_is_active(&mgr, "DATA", 1));

    ozayn_kl_shutdown(&mgr);
    return 0;
}

int test_rotation_invalid_key_material(void)
{
    ozayn_kl_manager_t mgr;
    ASSERT_EQ(OZAYN_KL_OK, ozayn_kl_init(&mgr));

    ASSERT_EQ(OZAYN_KL_OK, ozayn_kl_register_key(&mgr, "DATA", OZAYN_KEY_PURPOSE_DATA_ENCRYPTION));

    ozayn_key_id_t id;
    ozayn_key_id_set(&id, "DATA", 1, "test");
    ASSERT_EQ(OZAYN_KL_OK, ozayn_kl_add_version(&mgr, "DATA", &id, 32));
    ASSERT_EQ(OZAYN_KL_OK, ozayn_kl_activate(&mgr, "DATA", 1));

    /* Zero-length key rejected */
    uint8_t new_key[32];
    ASSERT_EQ(OZAYN_KL_ERR_KEY_INVALID, ozayn_kl_rotate(&mgr, "DATA", new_key, 0));

    /* Old key still active */
    ASSERT_EQ(1, ozayn_kl_is_active(&mgr, "DATA", 1));

    ozayn_kl_shutdown(&mgr);
    return 0;
}

int test_rotation_not_found(void)
{
    ozayn_kl_manager_t mgr;
    ASSERT_EQ(OZAYN_KL_OK, ozayn_kl_init(&mgr));

    uint8_t new_key[32];
    ASSERT_EQ(OZAYN_KL_ERR_NOT_FOUND, ozayn_kl_rotate(&mgr, "NONEXIST", new_key, 32));

    ozayn_kl_shutdown(&mgr);
    return 0;
}

/* ---- Crash Safety Test ---- */

int test_rotation_crash_safety(void)
{
    ozayn_kl_manager_t mgr;
    ASSERT_EQ(OZAYN_KL_OK, ozayn_kl_init(&mgr));

    ASSERT_EQ(OZAYN_KL_OK, ozayn_kl_register_key(&mgr, "DATA", OZAYN_KEY_PURPOSE_DATA_ENCRYPTION));

    ozayn_key_id_t id;
    ozayn_key_id_set(&id, "DATA", 1, "test");
    ASSERT_EQ(OZAYN_KL_OK, ozayn_kl_add_version(&mgr, "DATA", &id, 32));
    ASSERT_EQ(OZAYN_KL_OK, ozayn_kl_activate(&mgr, "DATA", 1));

    /* Successful rotation */
    uint8_t new_key[32];
    memset(new_key, 0x50, sizeof(new_key));
    ASSERT_EQ(OZAYN_KL_OK, ozayn_kl_rotate(&mgr, "DATA", new_key, sizeof(new_key)));

    /* After rotation: V2 active, V1 retired, no crash state */
    ASSERT_EQ(0, ozayn_kl_is_rotation_in_progress(&mgr));
    ASSERT_EQ(1, ozayn_kl_is_active(&mgr, "DATA", 2));
    ASSERT_EQ(1, ozayn_kl_is_usable(&mgr, "DATA", 1));

    /* Old key V1 is retired but still usable for historical decryption */
    ozayn_kl_version_t *v1;
    ASSERT_EQ(OZAYN_KL_OK, ozayn_kl_get_version(&mgr, "DATA", 1, &v1));
    ASSERT_EQ(OZAYN_KEY_LIFECYCLE_RETIRED, v1->lifecycle);

    /* Can still look up V1 for decryption */
    ozayn_kl_version_t *lookup;
    ASSERT_EQ(OZAYN_KL_OK, ozayn_kl_get_version(&mgr, "DATA", 1, &lookup));
    ASSERT_EQ(OZAYN_KEY_LIFECYCLE_RETIRED, lookup->lifecycle);

    ozayn_kl_shutdown(&mgr);
    return 0;
}

/* ---- Query Tests ---- */

int test_query_key_count(void)
{
    ozayn_kl_manager_t mgr;
    ASSERT_EQ(OZAYN_KL_OK, ozayn_kl_init(&mgr));

    ASSERT_EQ(0, ozayn_kl_key_count(&mgr));

    ASSERT_EQ(OZAYN_KL_OK, ozayn_kl_register_key(&mgr, "DATA", OZAYN_KEY_PURPOSE_DATA_ENCRYPTION));
    ASSERT_EQ(1, ozayn_kl_key_count(&mgr));

    ASSERT_EQ(OZAYN_KL_OK, ozayn_kl_register_key(&mgr, "AUTH", OZAYN_KEY_PURPOSE_AUTH_ENCRYPTION));
    ASSERT_EQ(2, ozayn_kl_key_count(&mgr));

    ozayn_kl_shutdown(&mgr);
    return 0;
}

int test_query_version_count(void)
{
    ozayn_kl_manager_t mgr;
    ASSERT_EQ(OZAYN_KL_OK, ozayn_kl_init(&mgr));

    ASSERT_EQ(OZAYN_KL_OK, ozayn_kl_register_key(&mgr, "DATA", OZAYN_KEY_PURPOSE_DATA_ENCRYPTION));
    ASSERT_EQ(0, ozayn_kl_version_count(&mgr, "DATA"));

    ozayn_key_id_t id;
    ozayn_key_id_set(&id, "DATA", 1, "test");
    ASSERT_EQ(OZAYN_KL_OK, ozayn_kl_add_version(&mgr, "DATA", &id, 32));
    ASSERT_EQ(1, ozayn_kl_version_count(&mgr, "DATA"));

    ozayn_kl_shutdown(&mgr);
    return 0;
}

int test_query_null_safety(void)
{
    ASSERT_EQ(OZAYN_KL_ERR_NULL, ozayn_kl_init(NULL));
    ASSERT_EQ(0, ozayn_kl_key_count(NULL));
    ASSERT_EQ(0, ozayn_kl_version_count(NULL, "DATA"));
    ASSERT_EQ(0, ozayn_kl_is_active(NULL, "DATA", 1));
    ASSERT_EQ(0, ozayn_kl_is_usable(NULL, "DATA", 1));
    ASSERT_EQ(0, ozayn_kl_is_rotation_in_progress(NULL));

    ozayn_kl_manager_t mgr;
    ASSERT_EQ(OZAYN_KL_OK, ozayn_kl_init(&mgr));
    ASSERT_EQ(0, ozayn_kl_version_count(&mgr, "NONEXIST"));
    ASSERT_EQ(0, ozayn_kl_is_active(&mgr, "NONEXIST", 1));
    ASSERT_EQ(0, ozayn_kl_is_usable(&mgr, "NONEXIST", 1));

    ozayn_kl_shutdown(&mgr);
    return 0;
}

int test_shutdown_safe(void)
{
    ozayn_kl_manager_t mgr;
    ASSERT_EQ(OZAYN_KL_OK, ozayn_kl_init(&mgr));
    ozayn_kl_shutdown(NULL);  /* No crash */
    ozayn_kl_shutdown(&mgr);
    return 0;
}

/* ============================================================
 * TEST RUNNER
 * ============================================================ */

int run_key_lifecycle_tests(void)
{
    int failed = 0;
    int total = 0;

    printf("\n  --- KEY LIFECYCLE TESTS ---\n");

    #define RUN_KL(name) do { total++; printf("    [%d] %s ... ", total, #name); if (name() == 0) { printf("PASS\n"); } else { printf("FAIL\n"); failed++; } } while(0)

    RUN_KL(test_lifecycle_valid_transitions);
    RUN_KL(test_lifecycle_invalid_transitions);
    RUN_KL(test_lifecycle_already_active);
    RUN_KL(test_lifecycle_already_revoked);
    RUN_KL(test_lifecycle_already_retired);
    RUN_KL(test_register_key);
    RUN_KL(test_add_version);
    RUN_KL(test_activate_replaces_active);
    RUN_KL(test_revoked_key_unusable);
    RUN_KL(test_rotation_basic);
    RUN_KL(test_rotation_failure_safety);
    RUN_KL(test_rotation_no_double);
    RUN_KL(test_rotation_historical_key_preserved);
    RUN_KL(test_rotation_new_key_not_usable);
    RUN_KL(test_rotation_revoked_key_no_rotate);
    RUN_KL(test_rotation_invalid_key_material);
    RUN_KL(test_rotation_not_found);
    RUN_KL(test_rotation_crash_safety);
    RUN_KL(test_query_key_count);
    RUN_KL(test_query_version_count);
    RUN_KL(test_query_null_safety);
    RUN_KL(test_shutdown_safe);

    #undef RUN_KL

    printf("  KEY LIFECYCLE: %d/%d passed\n", total - failed, total);
    return failed;
}
