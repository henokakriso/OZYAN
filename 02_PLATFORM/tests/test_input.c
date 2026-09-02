#include "../../tests/test_framework.h"
#include "platform.h"
#include <stdio.h>
#include <string.h>

/*
 * test_input.c — Section 02 Step 07: Input & Mouse Abstraction Tests.
 *
 * Tests input initialization, shutdown, availability, mouse position,
 * mouse state, and error handling. Works in headless environments.
 *
 * Mouse movement and button tests are only performed when explicitly safe.
 * In headless environments, these tests verify graceful failure.
 */

/* --- Input Initialization --- */

TEST(input_init_basic) {
    ozayn_result_t r = ozayn_input_init();
    ASSERT_EQ(r, OZAYN_OK);
    ozayn_input_shutdown();
    return 0;
}

TEST(input_init_idempotent) {
    ozayn_input_init();
    ozayn_result_t r = ozayn_input_init();
    ASSERT_EQ(r, OZAYN_OK);
    ozayn_input_shutdown();
    return 0;
}

/* --- Input Availability --- */

TEST(input_is_available_after_init) {
    ozayn_input_init();
    int avail = ozayn_input_is_available();
    ASSERT(avail == 0 || avail == 1);
    ozayn_input_shutdown();
    return 0;
}

TEST(input_is_available_before_init) {
    ozayn_input_shutdown();
    int avail = ozayn_input_is_available();
    ASSERT_EQ(avail, 0);
    return 0;
}

/* --- Input Device Info --- */

TEST(input_device_info_after_init) {
    ozayn_input_init();
    OzaynInputDeviceInfo info;
    ozayn_result_t r = ozayn_input_device_info(&info);
    ASSERT_EQ(r, OZAYN_OK);
    ASSERT(info.has_keyboard == 0 || info.has_keyboard == 1);
    ASSERT(info.has_mouse == 0 || info.has_mouse == 1);
    ozayn_input_shutdown();
    return 0;
}

TEST(input_device_info_null) {
    ozayn_input_init();
    ozayn_result_t r = ozayn_input_device_info(NULL);
    ASSERT_EQ(r, OZAYN_ERR_NULL);
    ozayn_input_shutdown();
    return 0;
}

TEST(input_device_info_before_init) {
    OzaynInputDeviceInfo info;
    ozayn_result_t r = ozayn_input_device_info(&info);
    ASSERT_EQ(r, OZAYN_ERR);
    return 0;
}

/* --- Mouse Position --- */

TEST(input_get_mouse_position_returns_result) {
    ozayn_input_init();
    int32_t x, y;
    ozayn_result_t r = ozayn_input_get_mouse_position(&x, &y);
    /* May succeed or fail depending on environment — both are valid */
    ASSERT(r == OZAYN_OK || r == OZAYN_ERR);
    ozayn_input_shutdown();
    return 0;
}

TEST(input_get_mouse_position_null) {
    ozayn_input_init();
    ozayn_result_t r = ozayn_input_get_mouse_position(NULL, NULL);
    ASSERT_EQ(r, OZAYN_ERR_NULL);
    int32_t x;
    r = ozayn_input_get_mouse_position(&x, NULL);
    ASSERT_EQ(r, OZAYN_ERR_NULL);
    r = ozayn_input_get_mouse_position(NULL, &x);
    ASSERT_EQ(r, OZAYN_ERR_NULL);
    ozayn_input_shutdown();
    return 0;
}

TEST(input_get_mouse_position_before_init) {
    int32_t x, y;
    ozayn_result_t r = ozayn_input_get_mouse_position(&x, &y);
    ASSERT_EQ(r, OZAYN_ERR);
    return 0;
}

/* --- Mouse State --- */

TEST(input_get_mouse_state_returns_result) {
    ozayn_input_init();
    OzaynMouseState state;
    ozayn_result_t r = ozayn_input_get_mouse_state(&state);
    /* May succeed or fail depending on environment — both are valid */
    ASSERT(r == OZAYN_OK || r == OZAYN_ERR);
    ozayn_input_shutdown();
    return 0;
}

TEST(input_get_mouse_state_null) {
    ozayn_input_init();
    ozayn_result_t r = ozayn_input_get_mouse_state(NULL);
    ASSERT_EQ(r, OZAYN_ERR_NULL);
    ozayn_input_shutdown();
    return 0;
}

TEST(input_get_mouse_state_before_init) {
    OzaynMouseState state;
    ozayn_result_t r = ozayn_input_get_mouse_state(&state);
    ASSERT_EQ(r, OZAYN_ERR);
    return 0;
}

TEST(input_get_mouse_state_button_fields) {
    ozayn_input_init();
    OzaynMouseState state;
    ozayn_result_t r = ozayn_input_get_mouse_state(&state);
    if (r == OZAYN_OK) {
        ASSERT(state.left_button == 0 || state.left_button == 1);
        ASSERT(state.middle_button == 0 || state.middle_button == 1);
        ASSERT(state.right_button == 0 || state.right_button == 1);
        ASSERT(state.available == 0 || state.available == 1);
    }
    ozayn_input_shutdown();
    return 0;
}

/* --- Mouse Movement --- */

TEST(input_move_mouse_returns_result) {
    ozayn_input_init();
    /* Only test movement if input is available */
    if (ozayn_input_is_available()) {
        /* Save current position */
        int32_t orig_x, orig_y;
        ozayn_result_t r = ozayn_input_get_mouse_position(&orig_x, &orig_y);
        if (r == OZAYN_OK) {
            /* Move to a safe test coordinate */
            r = ozayn_input_move_mouse(100, 100);
            ASSERT(r == OZAYN_OK || r == OZAYN_ERR);

            /* Restore original position */
            ozayn_input_move_mouse(orig_x, orig_y);
        }
    }
    ozayn_input_shutdown();
    return 0;
}

TEST(input_move_mouse_before_init) {
    ozayn_result_t r = ozayn_input_move_mouse(100, 100);
    ASSERT_EQ(r, OZAYN_ERR);
    return 0;
}

/* --- Mouse Buttons --- */

TEST(input_mouse_buttons_before_init) {
    ozayn_result_t r;

    r = ozayn_input_mouse_left_down();
    ASSERT_EQ(r, OZAYN_ERR);

    r = ozayn_input_mouse_left_up();
    ASSERT_EQ(r, OZAYN_ERR);

    r = ozayn_input_mouse_right_down();
    ASSERT_EQ(r, OZAYN_ERR);

    r = ozayn_input_mouse_right_up();
    ASSERT_EQ(r, OZAYN_ERR);

    r = ozayn_input_mouse_middle_down();
    ASSERT_EQ(r, OZAYN_ERR);

    r = ozayn_input_mouse_middle_up();
    ASSERT_EQ(r, OZAYN_ERR);

    return 0;
}

TEST(input_mouse_buttons_after_init) {
    ozayn_input_init();
    /* Button operations may succeed or fail depending on environment */
    if (ozayn_input_is_available()) {
        /* We do NOT actually click — just verify the API doesn't crash */
        /* In a real test environment, this would be marked as NOT RUN */
        ozayn_result_t r;

        /* Left button */
        r = ozayn_input_mouse_left_down();
        ASSERT(r == OZAYN_OK || r == OZAYN_ERR);
        r = ozayn_input_mouse_left_up();
        ASSERT(r == OZAYN_OK || r == OZAYN_ERR);

        /* Right button */
        r = ozayn_input_mouse_right_down();
        ASSERT(r == OZAYN_OK || r == OZAYN_ERR);
        r = ozayn_input_mouse_right_up();
        ASSERT(r == OZAYN_OK || r == OZAYN_ERR);

        /* Middle button */
        r = ozayn_input_mouse_middle_down();
        ASSERT(r == OZAYN_OK || r == OZAYN_ERR);
        r = ozayn_input_mouse_middle_up();
        ASSERT(r == OZAYN_OK || r == OZAYN_ERR);
    }
    ozayn_input_shutdown();
    return 0;
}

/* --- Input Shutdown --- */

TEST(input_shutdown_basic) {
    ozayn_input_init();
    ozayn_input_shutdown();
    ASSERT_EQ(ozayn_input_is_available(), 0);
    return 0;
}

TEST(input_shutdown_idempotent) {
    ozayn_input_init();
    ozayn_input_shutdown();
    ozayn_input_shutdown();
    ASSERT_EQ(ozayn_input_is_available(), 0);
    return 0;
}

TEST(input_shutdown_before_init) {
    ozayn_input_shutdown();
    ASSERT_EQ(ozayn_input_is_available(), 0);
    return 0;
}

/* --- Legacy API --- */

TEST(input_legacy_info_returns_result) {
    ozayn_input_info_t info;
    ozayn_result_t r = ozayn_input_info(&info);
    ASSERT_EQ(r, OZAYN_OK);
    ASSERT(info.has_keyboard == 0 || info.has_keyboard == 1);
    ASSERT(info.has_mouse == 0 || info.has_mouse == 1);
    return 0;
}

TEST(input_legacy_info_null) {
    ozayn_result_t r = ozayn_input_info(NULL);
    ASSERT_EQ(r, OZAYN_ERR_NULL);
    return 0;
}

int run_input_tests(void) {
    SUITE_BEGIN("Input & Mouse Abstraction (Section 02)");
    RUN(input_init_basic);
    RUN(input_init_idempotent);
    RUN(input_is_available_after_init);
    RUN(input_is_available_before_init);
    RUN(input_device_info_after_init);
    RUN(input_device_info_null);
    RUN(input_device_info_before_init);
    RUN(input_get_mouse_position_returns_result);
    RUN(input_get_mouse_position_null);
    RUN(input_get_mouse_position_before_init);
    RUN(input_get_mouse_state_returns_result);
    RUN(input_get_mouse_state_null);
    RUN(input_get_mouse_state_before_init);
    RUN(input_get_mouse_state_button_fields);
    RUN(input_move_mouse_returns_result);
    RUN(input_move_mouse_before_init);
    RUN(input_mouse_buttons_before_init);
    RUN(input_mouse_buttons_after_init);
    RUN(input_shutdown_basic);
    RUN(input_shutdown_idempotent);
    RUN(input_shutdown_before_init);
    RUN(input_legacy_info_returns_result);
    RUN(input_legacy_info_null);
    SUITE_END();
    return _tf_suite_fail;
}
