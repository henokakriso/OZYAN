#include "../../tests/test_framework.h"
#include "platform.h"
#include <stdio.h>
#include <string.h>

/*
 * test_window.c — Section 02 Step 06: Window Abstraction Tests.
 *
 * Tests window initialization, shutdown, availability, enumeration,
 * active window, and error handling. Works in headless environments.
 */

/* --- Window Initialization --- */

TEST(window_init_basic) {
    ozayn_result_t r = ozayn_window_init();
    ASSERT_EQ(r, OZAYN_OK);
    ozayn_window_shutdown();
    return 0;
}

TEST(window_init_idempotent) {
    ozayn_window_init();
    ozayn_result_t r = ozayn_window_init();
    ASSERT_EQ(r, OZAYN_OK);
    ozayn_window_shutdown();
    return 0;
}

/* --- Window Availability --- */

TEST(window_is_available_after_init) {
    ozayn_window_init();
    int avail = ozayn_window_is_available();
    ASSERT(avail == 0 || avail == 1);
    ozayn_window_shutdown();
    return 0;
}

TEST(window_is_available_before_init) {
    ozayn_window_shutdown();
    int avail = ozayn_window_is_available();
    ASSERT_EQ(avail, 0);
    return 0;
}

/* --- Window Count --- */

TEST(window_get_count_after_init) {
    ozayn_window_init();
    uint32_t count = ozayn_window_get_count();
    ASSERT(count <= OZAYN_MAX_WINDOWS);
    ozayn_window_shutdown();
    return 0;
}

TEST(window_get_count_before_init) {
    ozayn_window_shutdown();
    uint32_t count = ozayn_window_get_count();
    ASSERT_EQ(count, 0);
    return 0;
}

/* --- Window Info --- */

TEST(window_get_info_by_index) {
    ozayn_window_init();
    uint32_t count = ozayn_window_get_count();
    if (count > 0) {
        OzaynWindowInfo info;
        ozayn_result_t r = ozayn_window_get_info(0, &info);
        ASSERT_EQ(r, OZAYN_OK);
        ASSERT(info.id != 0);
    }
    ozayn_window_shutdown();
    return 0;
}

TEST(window_get_info_null) {
    ozayn_window_init();
    ozayn_result_t r = ozayn_window_get_info(0, NULL);
    ASSERT_EQ(r, OZAYN_ERR_NULL);
    ozayn_window_shutdown();
    return 0;
}

TEST(window_get_info_invalid_index) {
    ozayn_window_init();
    OzaynWindowInfo info;
    ozayn_result_t r = ozayn_window_get_info(999999, &info);
    ASSERT_EQ(r, OZAYN_ERR);
    ozayn_window_shutdown();
    return 0;
}

TEST(window_get_info_before_init) {
    OzaynWindowInfo info;
    ozayn_result_t r = ozayn_window_get_info(0, &info);
    ASSERT_EQ(r, OZAYN_ERR);
    return 0;
}

/* --- Active Window --- */

TEST(window_get_active_returns_result) {
    ozayn_window_init();
    OzaynWindowInfo info;
    ozayn_result_t r = ozayn_window_get_active(&info);
    /* May succeed or fail depending on environment — both are valid */
    ASSERT(r == OZAYN_OK || r == OZAYN_ERR);
    ozayn_window_shutdown();
    return 0;
}

TEST(window_get_active_null) {
    ozayn_window_init();
    ozayn_result_t r = ozayn_window_get_active(NULL);
    ASSERT_EQ(r, OZAYN_ERR_NULL);
    ozayn_window_shutdown();
    return 0;
}

TEST(window_get_active_before_init) {
    OzaynWindowInfo info;
    ozayn_result_t r = ozayn_window_get_active(&info);
    ASSERT_EQ(r, OZAYN_ERR);
    return 0;
}

/* --- Window Manipulation Safety --- */

TEST(window_move_invalid_id) {
    ozayn_window_init();
    ozayn_result_t r = ozayn_window_move(0, 100, 100);
    ASSERT_EQ(r, OZAYN_ERR);
    r = ozayn_window_move(999999, 100, 100);
    ASSERT(r == OZAYN_ERR || r == OZAYN_OK);
    ozayn_window_shutdown();
    return 0;
}

TEST(window_resize_invalid_id) {
    ozayn_window_init();
    ozayn_result_t r = ozayn_window_resize(0, 800, 600);
    ASSERT_EQ(r, OZAYN_ERR);
    r = ozayn_window_resize(999999, 800, 600);
    ASSERT(r == OZAYN_ERR || r == OZAYN_OK);
    ozayn_window_shutdown();
    return 0;
}

TEST(window_resize_zero_dimensions) {
    ozayn_window_init();
    ozayn_result_t r = ozayn_window_resize(12345, 0, 600);
    ASSERT_EQ(r, OZAYN_ERR);
    r = ozayn_window_resize(12345, 800, 0);
    ASSERT_EQ(r, OZAYN_ERR);
    ozayn_window_shutdown();
    return 0;
}

TEST(window_minimize_invalid_id) {
    ozayn_window_init();
    ozayn_result_t r = ozayn_window_minimize(0);
    ASSERT_EQ(r, OZAYN_ERR);
    ozayn_window_shutdown();
    return 0;
}

TEST(window_maximize_invalid_id) {
    ozayn_window_init();
    ozayn_result_t r = ozayn_window_maximize(0);
    ASSERT_EQ(r, OZAYN_ERR);
    ozayn_window_shutdown();
    return 0;
}

TEST(window_restore_invalid_id) {
    ozayn_window_init();
    ozayn_result_t r = ozayn_window_restore(0);
    ASSERT_EQ(r, OZAYN_ERR);
    ozayn_window_shutdown();
    return 0;
}

TEST(window_close_invalid_id) {
    ozayn_window_init();
    ozayn_result_t r = ozayn_window_close(0);
    ASSERT_EQ(r, OZAYN_ERR);
    ozayn_window_shutdown();
    return 0;
}

/* --- Window Refresh --- */

TEST(window_refresh_basic) {
    ozayn_window_init();
    ozayn_result_t r = ozayn_window_refresh();
    ASSERT_EQ(r, OZAYN_OK);
    ozayn_window_shutdown();
    return 0;
}

TEST(window_refresh_before_init) {
    ozayn_result_t r = ozayn_window_refresh();
    ASSERT_EQ(r, OZAYN_ERR);
    return 0;
}

/* --- Window Shutdown --- */

TEST(window_shutdown_basic) {
    ozayn_window_init();
    ozayn_window_shutdown();
    ASSERT_EQ(ozayn_window_is_available(), 0);
    ASSERT_EQ(ozayn_window_get_count(), 0);
    return 0;
}

TEST(window_shutdown_idempotent) {
    ozayn_window_init();
    ozayn_window_shutdown();
    ozayn_window_shutdown();
    ASSERT_EQ(ozayn_window_is_available(), 0);
    return 0;
}

TEST(window_shutdown_before_init) {
    ozayn_window_shutdown();
    ASSERT_EQ(ozayn_window_is_available(), 0);
    return 0;
}

/* --- Multiple Windows --- */

TEST(window_enumerate_all) {
    ozayn_window_init();
    uint32_t count = ozayn_window_get_count();
    for (uint32_t i = 0; i < count; i++) {
        OzaynWindowInfo info;
        ozayn_result_t r = ozayn_window_get_info(i, &info);
        ASSERT_EQ(r, OZAYN_OK);
        ASSERT(info.id != 0);
    }
    ozayn_window_shutdown();
    return 0;
}

int run_window_tests(void) {
    SUITE_BEGIN("Window Abstraction (Section 02)");
    RUN(window_init_basic);
    RUN(window_init_idempotent);
    RUN(window_is_available_after_init);
    RUN(window_is_available_before_init);
    RUN(window_get_count_after_init);
    RUN(window_get_count_before_init);
    RUN(window_get_info_by_index);
    RUN(window_get_info_null);
    RUN(window_get_info_invalid_index);
    RUN(window_get_info_before_init);
    RUN(window_get_active_returns_result);
    RUN(window_get_active_null);
    RUN(window_get_active_before_init);
    RUN(window_move_invalid_id);
    RUN(window_resize_invalid_id);
    RUN(window_resize_zero_dimensions);
    RUN(window_minimize_invalid_id);
    RUN(window_maximize_invalid_id);
    RUN(window_restore_invalid_id);
    RUN(window_close_invalid_id);
    RUN(window_refresh_basic);
    RUN(window_refresh_before_init);
    RUN(window_shutdown_basic);
    RUN(window_shutdown_idempotent);
    RUN(window_shutdown_before_init);
    RUN(window_enumerate_all);
    SUITE_END();
    return _tf_suite_fail;
}
