#include "../../tests/test_framework.h"
#include "platform.h"
#include <stdio.h>
#include <string.h>

/*
 * test_display.c — Section 02 Step 05: Display Abstraction Tests.
 *
 * Tests display initialization, shutdown, availability, count, and info retrieval.
 * Works in both graphical and headless environments.
 */

/* --- Display Initialization --- */

TEST(display_init_basic) {
    ozayn_result_t r = ozayn_display_init();
    ASSERT_EQ(r, OZAYN_OK);
    ozayn_display_shutdown();
    return 0;
}

TEST(display_init_idempotent) {
    ozayn_display_init();
    ozayn_result_t r = ozayn_display_init();
    ASSERT_EQ(r, OZAYN_OK);
    ozayn_display_shutdown();
    return 0;
}

/* --- Display Availability --- */

TEST(display_is_available_after_init) {
    ozayn_display_init();
    int avail = ozayn_display_is_available();
    ASSERT(avail == 0 || avail == 1);
    ozayn_display_shutdown();
    return 0;
}

TEST(display_is_available_before_init) {
    ozayn_display_shutdown();
    int avail = ozayn_display_is_available();
    ASSERT_EQ(avail, 0);
    return 0;
}

/* --- Display Count --- */

TEST(display_count_after_init) {
    ozayn_display_init();
    uint32_t count = ozayn_display_count();
    ASSERT(count <= OZAYN_MAX_DISPLAYS);
    ozayn_display_shutdown();
    return 0;
}

TEST(display_count_before_init) {
    ozayn_display_shutdown();
    uint32_t count = ozayn_display_count();
    ASSERT_EQ(count, 0);
    return 0;
}

TEST(display_count_matches_availability) {
    ozayn_display_init();
    uint32_t count = ozayn_display_count();
    int avail = ozayn_display_is_available();
    if (avail) {
        ASSERT(count > 0);
    } else {
        ASSERT_EQ(count, 0);
    }
    ozayn_display_shutdown();
    return 0;
}

/* --- Display Get --- */

TEST(display_get_by_index) {
    ozayn_display_init();
    uint32_t count = ozayn_display_count();
    if (count > 0) {
        OzaynDisplayInfo info;
        ozayn_result_t r = ozayn_display_get(0, &info);
        ASSERT_EQ(r, OZAYN_OK);
        ASSERT(info.width > 0);
        ASSERT(info.height > 0);
    }
    ozayn_display_shutdown();
    return 0;
}

TEST(display_get_null_info) {
    ozayn_display_init();
    ozayn_result_t r = ozayn_display_get(0, NULL);
    ASSERT_EQ(r, OZAYN_ERR_NULL);
    ozayn_display_shutdown();
    return 0;
}

TEST(display_get_invalid_index) {
    ozayn_display_init();
    OzaynDisplayInfo info;
    ozayn_result_t r = ozayn_display_get(999, &info);
    ASSERT_EQ(r, OZAYN_ERR);
    ozayn_display_shutdown();
    return 0;
}

TEST(display_get_before_init) {
    OzaynDisplayInfo info;
    ozayn_result_t r = ozayn_display_get(0, &info);
    ASSERT_EQ(r, OZAYN_ERR);
    return 0;
}

/* --- Primary Display --- */

TEST(display_get_primary) {
    ozayn_display_init();
    uint32_t count = ozayn_display_count();
    if (count > 0) {
        OzaynDisplayInfo info;
        ozayn_result_t r = ozayn_display_get_primary(&info);
        ASSERT_EQ(r, OZAYN_OK);
        ASSERT_EQ(info.is_primary, 1);
        ASSERT(info.width > 0);
        ASSERT(info.height > 0);
    }
    ozayn_display_shutdown();
    return 0;
}

TEST(display_get_primary_null) {
    ozayn_display_init();
    ozayn_result_t r = ozayn_display_get_primary(NULL);
    ASSERT_EQ(r, OZAYN_ERR_NULL);
    ozayn_display_shutdown();
    return 0;
}

TEST(display_get_primary_before_init) {
    OzaynDisplayInfo info;
    ozayn_result_t r = ozayn_display_get_primary(&info);
    ASSERT_EQ(r, OZAYN_ERR);
    return 0;
}

/* --- Display Info Fields --- */

TEST(display_info_has_valid_name) {
    ozayn_display_init();
    uint32_t count = ozayn_display_count();
    if (count > 0) {
        OzaynDisplayInfo info;
        ozayn_display_get(0, &info);
        /* Name should be non-empty */
        ASSERT(strlen(info.name) > 0);
    }
    ozayn_display_shutdown();
    return 0;
}

TEST(display_info_has_valid_dimensions) {
    ozayn_display_init();
    uint32_t count = ozayn_display_count();
    if (count > 0) {
        OzaynDisplayInfo info;
        ozayn_display_get(0, &info);
        ASSERT(info.width > 0);
        ASSERT(info.height > 0);
        ASSERT(info.width <= 32768);
        ASSERT(info.height <= 32768);
    }
    ozayn_display_shutdown();
    return 0;
}

TEST(display_info_has_valid_index) {
    ozayn_display_init();
    uint32_t count = ozayn_display_count();
    for (uint32_t i = 0; i < count; i++) {
        OzaynDisplayInfo info;
        ozayn_display_get(i, &info);
        ASSERT_EQ(info.index, i);
    }
    ozayn_display_shutdown();
    return 0;
}

TEST(display_info_primary_flag) {
    ozayn_display_init();
    uint32_t count = ozayn_display_count();
    int found_primary = 0;
    for (uint32_t i = 0; i < count; i++) {
        OzaynDisplayInfo info;
        ozayn_display_get(i, &info);
        if (info.is_primary) found_primary = 1;
    }
    /* Should have at least one primary display if any displays exist */
    if (count > 0) {
        ASSERT_EQ(found_primary, 1);
    }
    ozayn_display_shutdown();
    return 0;
}

/* --- Display Refresh --- */

TEST(display_refresh_basic) {
    ozayn_display_init();
    ozayn_result_t r = ozayn_display_refresh();
    ASSERT_EQ(r, OZAYN_OK);
    ozayn_display_shutdown();
    return 0;
}

TEST(display_refresh_before_init) {
    ozayn_result_t r = ozayn_display_refresh();
    ASSERT_EQ(r, OZAYN_ERR);
    return 0;
}

/* --- Display Shutdown --- */

TEST(display_shutdown_basic) {
    ozayn_display_init();
    ozayn_display_shutdown();
    ASSERT_EQ(ozayn_display_is_available(), 0);
    ASSERT_EQ(ozayn_display_count(), 0);
    return 0;
}

TEST(display_shutdown_idempotent) {
    ozayn_display_init();
    ozayn_display_shutdown();
    ozayn_display_shutdown();
    ASSERT_EQ(ozayn_display_is_available(), 0);
    return 0;
}

TEST(display_shutdown_before_init) {
    ozayn_display_shutdown();
    ASSERT_EQ(ozayn_display_is_available(), 0);
    return 0;
}

/* --- Multiple Displays --- */

TEST(display_multiple_query_all) {
    ozayn_display_init();
    uint32_t count = ozayn_display_count();
    for (uint32_t i = 0; i < count; i++) {
        OzaynDisplayInfo info;
        ozayn_result_t r = ozayn_display_get(i, &info);
        ASSERT_EQ(r, OZAYN_OK);
        ASSERT_EQ(info.index, i);
    }
    ozayn_display_shutdown();
    return 0;
}

/* --- Legacy Display API --- */

TEST(display_legacy_api_works) {
    ozayn_display_info_t info;
    ozayn_result_t r = ozayn_display_info(&info);
    ASSERT_EQ(r, OZAYN_OK);
    ASSERT(info.count > 0);
    return 0;
}

TEST(display_legacy_api_null) {
    ozayn_result_t r = ozayn_display_info(NULL);
    ASSERT_EQ(r, OZAYN_ERR_NULL);
    return 0;
}

int run_display_tests(void) {
    SUITE_BEGIN("Display Abstraction (Section 02)");
    RUN(display_init_basic);
    RUN(display_init_idempotent);
    RUN(display_is_available_after_init);
    RUN(display_is_available_before_init);
    RUN(display_count_after_init);
    RUN(display_count_before_init);
    RUN(display_count_matches_availability);
    RUN(display_get_by_index);
    RUN(display_get_null_info);
    RUN(display_get_invalid_index);
    RUN(display_get_before_init);
    RUN(display_get_primary);
    RUN(display_get_primary_null);
    RUN(display_get_primary_before_init);
    RUN(display_info_has_valid_name);
    RUN(display_info_has_valid_dimensions);
    RUN(display_info_has_valid_index);
    RUN(display_info_primary_flag);
    RUN(display_refresh_basic);
    RUN(display_refresh_before_init);
    RUN(display_shutdown_basic);
    RUN(display_shutdown_idempotent);
    RUN(display_shutdown_before_init);
    RUN(display_multiple_query_all);
    RUN(display_legacy_api_works);
    RUN(display_legacy_api_null);
    SUITE_END();
    return _tf_suite_fail;
}
