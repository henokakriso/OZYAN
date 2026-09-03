#include "../../tests/test_framework.h"
#include "platform.h"
#include <stdio.h>
#include <string.h>

/*
 * test_storage.c — Section 02 Step 26: System Storage & Disk Information Abstraction Tests.
 *
 * Tests storage initialization, shutdown, enumeration, system volume,
 * and error handling. Read-only — no formatting or partitioning.
 */

/* --- Initialization --- */

TEST(storage_init_basic) {
    ozayn_result_t r = ozayn_storage_init();
    ASSERT_EQ(r, OZAYN_OK);
    ozayn_storage_shutdown();
    return 0;
}

TEST(storage_init_idempotent) {
    ozayn_storage_init();
    ozayn_result_t r = ozayn_storage_init();
    ASSERT_EQ(r, OZAYN_OK);
    ozayn_storage_shutdown();
    return 0;
}

/* --- Availability --- */

TEST(storage_is_available_before_init) {
    int avail = ozayn_storage_is_available();
    ASSERT_EQ(avail, 0);
    return 0;
}

TEST(storage_is_available_after_init) {
    ozayn_storage_init();
    int avail = ozayn_storage_is_available();
    ASSERT(avail == 0 || avail == 1);
    ozayn_storage_shutdown();
    return 0;
}

/* --- Count --- */

TEST(storage_count_before_init) {
    int count = ozayn_storage_get_count();
    ASSERT_EQ(count, 0);
    return 0;
}

TEST(storage_count_after_init) {
    ozayn_storage_init();
    int count = ozayn_storage_get_count();
    ASSERT(count >= 0);
    ozayn_storage_shutdown();
    return 0;
}

/* --- Enumeration --- */

TEST(storage_get_info_null) {
    ozayn_storage_init();
    OzaynStorageInfo info;
    ozayn_result_t r = ozayn_storage_get_info(0, NULL);
    ASSERT_EQ(r, OZAYN_ERR_NULL);
    ozayn_storage_shutdown();
    return 0;
}

TEST(storage_get_info_before_init) {
    OzaynStorageInfo info;
    ozayn_result_t r = ozayn_storage_get_info(0, &info);
    ASSERT(r != OZAYN_OK);
    return 0;
}

TEST(storage_get_info_negative_index) {
    ozayn_storage_init();
    OzaynStorageInfo info;
    ozayn_result_t r = ozayn_storage_get_info(-1, &info);
    ASSERT(r != OZAYN_OK);
    ozayn_storage_shutdown();
    return 0;
}

TEST(storage_get_info_index_out_of_range) {
    ozayn_storage_init();
    int count = ozayn_storage_get_count();
    OzaynStorageInfo info;
    ozayn_result_t r = ozayn_storage_get_info(count, &info);
    ASSERT(r != OZAYN_OK);
    r = ozayn_storage_get_info(count + 100, &info);
    ASSERT(r != OZAYN_OK);
    ozayn_storage_shutdown();
    return 0;
}

TEST(storage_get_info_valid) {
    ozayn_storage_init();
    if (ozayn_storage_get_count() <= 0) {
        ozayn_storage_shutdown();
        return 0;
    }

    OzaynStorageInfo info;
    ozayn_result_t r = ozayn_storage_get_info(0, &info);
    if (r == OZAYN_OK) {
        ASSERT_EQ(info.index, 0);
        ASSERT(info.available == 0 || info.available == 1);
        if (info.available) {
            /* Mount point should be non-empty */
            ASSERT(strlen(info.mount_point) > 0);
            /* Capacity validation: available <= total */
            ASSERT(info.available_bytes <= info.total_bytes);
            ASSERT(info.free_bytes <= info.total_bytes);
        }
    }
    ozayn_storage_shutdown();
    return 0;
}

TEST(storage_get_info_multiple) {
    ozayn_storage_init();
    int count = ozayn_storage_get_count();
    if (count <= 1) {
        ozayn_storage_shutdown();
        return 0;
    }

    OzaynStorageInfo info_first, info_last;
    ozayn_storage_get_info(0, &info_first);
    ozayn_storage_get_info(count - 1, &info_last);

    ASSERT_EQ(info_first.index, 0);
    ASSERT_EQ(info_last.index, count - 1);

    ozayn_storage_shutdown();
    return 0;
}

/* --- System Volume --- */

TEST(storage_get_system_volume_null) {
    ozayn_storage_init();
    ozayn_result_t r = ozayn_storage_get_system_volume(NULL);
    ASSERT_EQ(r, OZAYN_ERR_NULL);
    ozayn_storage_shutdown();
    return 0;
}

TEST(storage_get_system_volume_before_init) {
    OzaynStorageInfo info;
    ozayn_result_t r = ozayn_storage_get_system_volume(&info);
    ASSERT(r != OZAYN_OK);
    return 0;
}

TEST(storage_get_system_volume_valid) {
    ozayn_storage_init();
    OzaynStorageInfo info;
    ozayn_result_t r = ozayn_storage_get_system_volume(&info);
    /* May succeed or fail depending on platform — both acceptable */
    ASSERT(r == OZAYN_OK || r == OZAYN_ERR);
    if (r == OZAYN_OK) {
        ASSERT(info.available == 0 || info.available == 1);
        ASSERT(info.total_bytes > 0);
    }
    ozayn_storage_shutdown();
    return 0;
}

/* --- Shutdown --- */

TEST(storage_shutdown_basic) {
    ozayn_storage_init();
    ozayn_storage_shutdown();
    return 0;
}

TEST(storage_shutdown_idempotent) {
    ozayn_storage_init();
    ozayn_storage_shutdown();
    ozayn_storage_shutdown();
    return 0;
}

TEST(storage_shutdown_before_init) {
    ozayn_storage_shutdown();
    return 0;
}

/* --- Test Suite --- */

int run_storage_tests(void) {
    SUITE_BEGIN("System Storage & Disk Information Abstraction (Step 26)");

    /* Lifecycle */
    RUN(storage_init_basic);
    RUN(storage_init_idempotent);

    /* Availability */
    RUN(storage_is_available_before_init);
    RUN(storage_is_available_after_init);

    /* Count */
    RUN(storage_count_before_init);
    RUN(storage_count_after_init);

    /* Enumeration */
    RUN(storage_get_info_null);
    RUN(storage_get_info_before_init);
    RUN(storage_get_info_negative_index);
    RUN(storage_get_info_index_out_of_range);
    RUN(storage_get_info_valid);
    RUN(storage_get_info_multiple);

    /* System Volume */
    RUN(storage_get_system_volume_null);
    RUN(storage_get_system_volume_before_init);
    RUN(storage_get_system_volume_valid);

    /* Shutdown */
    RUN(storage_shutdown_basic);
    RUN(storage_shutdown_idempotent);
    RUN(storage_shutdown_before_init);

    SUITE_END();
    return FAILED();
}
