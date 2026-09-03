#include "../../tests/test_framework.h"
#include "platform.h"
#include <stdio.h>
#include <string.h>

/*
 * test_brightness.c — Section 02 Step 22: System Brightness & Display Power Abstraction Tests.
 *
 * Tests brightness initialization, shutdown, queries, control, and error handling.
 * Restores original brightness after testing.
 * Safe for systems without controllable brightness — reports unavailable.
 */

/* --- Initialization --- */

TEST(brightness_init_basic) {
    ozayn_result_t r = ozayn_brightness_init();
    ASSERT_EQ(r, OZAYN_OK);
    ozayn_brightness_shutdown();
    return 0;
}

TEST(brightness_init_idempotent) {
    ozayn_brightness_init();
    ozayn_result_t r = ozayn_brightness_init();
    ASSERT_EQ(r, OZAYN_OK);
    ozayn_brightness_shutdown();
    return 0;
}

/* --- Availability --- */

TEST(brightness_is_available_after_init) {
    ozayn_brightness_init();
    int avail = ozayn_brightness_is_available();
    ASSERT(avail == 0 || avail == 1);
    ozayn_brightness_shutdown();
    return 0;
}

TEST(brightness_is_available_before_init) {
    int avail = ozayn_brightness_is_available();
    ASSERT_EQ(avail, 0);
    return 0;
}

/* --- Supported --- */

TEST(brightness_get_supported_null) {
    ozayn_brightness_init();
    ozayn_result_t r = ozayn_brightness_get_supported(NULL);
    ASSERT_EQ(r, OZAYN_ERR_NULL);
    ozayn_brightness_shutdown();
    return 0;
}

TEST(brightness_get_supported_before_init) {
    int supported;
    ozayn_result_t r = ozayn_brightness_get_supported(&supported);
    ASSERT(r != OZAYN_OK);
    return 0;
}

TEST(brightness_get_supported_value) {
    ozayn_brightness_init();
    int supported;
    ozayn_result_t r = ozayn_brightness_get_supported(&supported);
    if (r == OZAYN_OK) {
        ASSERT(supported == 0 || supported == 1);
    }
    ozayn_brightness_shutdown();
    return 0;
}

/* --- Brightness Query --- */

TEST(brightness_get_null) {
    ozayn_brightness_init();
    ozayn_result_t r = ozayn_brightness_get(NULL);
    ASSERT_EQ(r, OZAYN_ERR_NULL);
    ozayn_brightness_shutdown();
    return 0;
}

TEST(brightness_get_before_init) {
    int br;
    ozayn_result_t r = ozayn_brightness_get(&br);
    ASSERT(r != OZAYN_OK);
    return 0;
}

TEST(brightness_get_valid_range) {
    ozayn_brightness_init();
    if (!ozayn_brightness_is_available()) {
        ozayn_brightness_shutdown();
        return 0;
    }
    int br;
    ozayn_result_t r = ozayn_brightness_get(&br);
    if (r == OZAYN_OK) {
        ASSERT(br >= 0 && br <= 100);
    }
    ozayn_brightness_shutdown();
    return 0;
}

/* --- Brightness Set --- */

TEST(brightness_set_invalid_negative) {
    ozayn_brightness_init();
    ozayn_result_t r = ozayn_brightness_set(-1);
    ASSERT(r != OZAYN_OK);
    ozayn_brightness_shutdown();
    return 0;
}

TEST(brightness_set_invalid_over) {
    ozayn_brightness_init();
    ozayn_result_t r = ozayn_brightness_set(101);
    ASSERT(r != OZAYN_OK);
    ozayn_brightness_shutdown();
    return 0;
}

TEST(brightness_set_before_init) {
    ozayn_result_t r = ozayn_brightness_set(50);
    ASSERT(r != OZAYN_OK);
    return 0;
}

TEST(brightness_set_restore) {
    ozayn_brightness_init();
    if (!ozayn_brightness_is_available()) {
        ozayn_brightness_shutdown();
        return 0;
    }

    /* Save original brightness */
    int orig_br;
    ozayn_result_t r = ozayn_brightness_get(&orig_br);
    if (r != OZAYN_OK) {
        ozayn_brightness_shutdown();
        return 0;
    }

    /* Set to 50% and verify */
    r = ozayn_brightness_set(50);
    if (r == OZAYN_OK) {
        int check_br;
        ozayn_brightness_get(&check_br);
        /* Allow ±1 for rounding */
        ASSERT(check_br >= 49 && check_br <= 51);
    }

    /* Restore original */
    ozayn_brightness_set(orig_br);
    ozayn_brightness_shutdown();
    return 0;
}

/* --- Shutdown --- */

TEST(brightness_shutdown_basic) {
    ozayn_brightness_init();
    ozayn_brightness_shutdown();
    return 0;
}

TEST(brightness_shutdown_idempotent) {
    ozayn_brightness_init();
    ozayn_brightness_shutdown();
    ozayn_brightness_shutdown();
    return 0;
}

TEST(brightness_shutdown_before_init) {
    ozayn_brightness_shutdown();
    return 0;
}

/* --- Test Suite --- */

int run_brightness_tests(void) {
    int failed = 0;
    SUITE_BEGIN("System Brightness & Display Power (Section 02)");

    /* Initialization */
    RUN(brightness_init_basic);
    RUN(brightness_init_idempotent);

    /* Availability */
    RUN(brightness_is_available_after_init);
    RUN(brightness_is_available_before_init);

    /* Supported */
    RUN(brightness_get_supported_null);
    RUN(brightness_get_supported_before_init);
    RUN(brightness_get_supported_value);

    /* Brightness Query */
    RUN(brightness_get_null);
    RUN(brightness_get_before_init);
    RUN(brightness_get_valid_range);

    /* Brightness Set */
    RUN(brightness_set_invalid_negative);
    RUN(brightness_set_invalid_over);
    RUN(brightness_set_before_init);
    RUN(brightness_set_restore);

    /* Shutdown */
    RUN(brightness_shutdown_basic);
    RUN(brightness_shutdown_idempotent);
    RUN(brightness_shutdown_before_init);

    SUITE_END();
    return FAILED();
}
