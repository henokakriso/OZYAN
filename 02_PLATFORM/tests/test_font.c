#include "../../tests/test_framework.h"
#include "platform.h"
#include <stdio.h>
#include <string.h>

/*
 * test_font.c — Section 02 Step 24: System Font & Text Rendering Information Abstraction Tests.
 *
 * Tests font initialization, shutdown, enumeration, default font,
 * and error handling. Read-only — no font modification.
 */

/* --- Initialization --- */

TEST(font_init_basic) {
    ozayn_result_t r = ozayn_font_init();
    ASSERT_EQ(r, OZAYN_OK);
    ozayn_font_shutdown();
    return 0;
}

TEST(font_init_idempotent) {
    ozayn_font_init();
    ozayn_result_t r = ozayn_font_init();
    ASSERT_EQ(r, OZAYN_OK);
    ozayn_font_shutdown();
    return 0;
}

/* --- Availability --- */

TEST(font_is_available_after_init) {
    ozayn_font_init();
    int avail = ozayn_font_is_available();
    ASSERT(avail == 0 || avail == 1);
    ozayn_font_shutdown();
    return 0;
}

TEST(font_is_available_before_init) {
    int avail = ozayn_font_is_available();
    ASSERT_EQ(avail, 0);
    return 0;
}

/* --- Count --- */

TEST(font_get_count_before_init) {
    int count = ozayn_font_get_count();
    ASSERT(count == 0);
    return 0;
}

TEST(font_get_count_after_init) {
    ozayn_font_init();
    int count = ozayn_font_get_count();
    ASSERT(count >= 0);
    ozayn_font_shutdown();
    return 0;
}

/* --- Enumeration --- */

TEST(font_get_info_null) {
    ozayn_font_init();
    OzaynFontInfo info;
    ozayn_result_t r = ozayn_font_get_info(0, NULL);
    ASSERT_EQ(r, OZAYN_ERR_NULL);
    ozayn_font_shutdown();
    return 0;
}

TEST(font_get_info_before_init) {
    OzaynFontInfo info;
    ozayn_result_t r = ozayn_font_get_info(0, &info);
    ASSERT(r != OZAYN_OK);
    return 0;
}

TEST(font_get_info_negative_index) {
    ozayn_font_init();
    if (!ozayn_font_is_available()) {
        ozayn_font_shutdown();
        return 0;
    }
    OzaynFontInfo info;
    ozayn_result_t r = ozayn_font_get_info(-1, &info);
    ASSERT(r != OZAYN_OK);
    ozayn_font_shutdown();
    return 0;
}

TEST(font_get_info_index_out_of_range) {
    ozayn_font_init();
    if (!ozayn_font_is_available()) {
        ozayn_font_shutdown();
        return 0;
    }
    int count = ozayn_font_get_count();
    OzaynFontInfo info;
    ozayn_result_t r = ozayn_font_get_info(count, &info);
    ASSERT(r != OZAYN_OK);
    r = ozayn_font_get_info(count + 100, &info);
    ASSERT(r != OZAYN_OK);
    ozayn_font_shutdown();
    return 0;
}

TEST(font_get_info_valid) {
    ozayn_font_init();
    if (!ozayn_font_is_available()) {
        ozayn_font_shutdown();
        return 0;
    }
    int count = ozayn_font_get_count();
    if (count <= 0) {
        ozayn_font_shutdown();
        return 0;
    }

    OzaynFontInfo info;
    ozayn_result_t r = ozayn_font_get_info(0, &info);
    if (r == OZAYN_OK) {
        ASSERT_EQ(info.index, 0);
        ASSERT(info.available == 0 || info.available == 1);
        /* Family should be non-empty if font is available */
        if (info.available) {
            ASSERT(strlen(info.family) > 0);
        }
    }
    ozayn_font_shutdown();
    return 0;
}

TEST(font_get_info_multiple) {
    ozayn_font_init();
    if (!ozayn_font_is_available()) {
        ozayn_font_shutdown();
        return 0;
    }
    int count = ozayn_font_get_count();
    if (count <= 1) {
        ozayn_font_shutdown();
        return 0;
    }

    /* Check first and last fonts */
    OzaynFontInfo info_first, info_last;
    ozayn_font_get_info(0, &info_first);
    ozayn_font_get_info(count - 1, &info_last);

    /* Both should have valid indices */
    ASSERT_EQ(info_first.index, 0);
    ASSERT_EQ(info_last.index, count - 1);

    ozayn_font_shutdown();
    return 0;
}

/* --- Default Font --- */

TEST(font_get_default_null) {
    ozayn_font_init();
    ozayn_result_t r = ozayn_font_get_default(NULL, 0);
    ASSERT_EQ(r, OZAYN_ERR_NULL);
    ozayn_font_shutdown();
    return 0;
}

TEST(font_get_default_zero_size) {
    ozayn_font_init();
    char buf[256];
    ozayn_result_t r = ozayn_font_get_default(buf, 0);
    ASSERT(r != OZAYN_OK);
    ozayn_font_shutdown();
    return 0;
}

TEST(font_get_default_before_init) {
    char buf[256];
    ozayn_result_t r = ozayn_font_get_default(buf, sizeof(buf));
    ASSERT(r != OZAYN_OK);
    return 0;
}

TEST(font_get_default_valid) {
    ozayn_font_init();
    char buf[256] = {0};
    ozayn_result_t r = ozayn_font_get_default(buf, sizeof(buf));
    /* May succeed or fail depending on platform — both acceptable */
    ASSERT(r == OZAYN_OK || r == OZAYN_ERR);
    if (r == OZAYN_OK) {
        ASSERT(strlen(buf) > 0);
    }
    ozayn_font_shutdown();
    return 0;
}

/* --- Shutdown --- */

TEST(font_shutdown_basic) {
    ozayn_font_init();
    ozayn_font_shutdown();
    return 0;
}

TEST(font_shutdown_idempotent) {
    ozayn_font_init();
    ozayn_font_shutdown();
    ozayn_font_shutdown();
    return 0;
}

TEST(font_shutdown_before_init) {
    ozayn_font_shutdown();
    return 0;
}

/* --- Test Suite --- */

int run_font_tests(void) {
    int failed = 0;
    SUITE_BEGIN("System Font & Text Rendering Information (Section 02)");

    /* Initialization */
    RUN(font_init_basic);
    RUN(font_init_idempotent);

    /* Availability */
    RUN(font_is_available_after_init);
    RUN(font_is_available_before_init);

    /* Count */
    RUN(font_get_count_before_init);
    RUN(font_get_count_after_init);

    /* Enumeration */
    RUN(font_get_info_null);
    RUN(font_get_info_before_init);
    RUN(font_get_info_negative_index);
    RUN(font_get_info_index_out_of_range);
    RUN(font_get_info_valid);
    RUN(font_get_info_multiple);

    /* Default Font */
    RUN(font_get_default_null);
    RUN(font_get_default_zero_size);
    RUN(font_get_default_before_init);
    RUN(font_get_default_valid);

    /* Shutdown */
    RUN(font_shutdown_basic);
    RUN(font_shutdown_idempotent);
    RUN(font_shutdown_before_init);

    SUITE_END();
    return FAILED();
}
