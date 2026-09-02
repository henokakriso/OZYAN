#include "../../tests/test_framework.h"
#include "platform.h"
#include <stdio.h>
#include <string.h>

/*
 * test_clipboard.c — Section 02 Step 15: Clipboard Abstraction Tests.
 *
 * Tests clipboard initialization, shutdown, availability, text operations,
 * buffer handling, and error handling. Works on headless systems.
 *
 * If no clipboard is available, tests verify graceful handling.
 * Tests restore previous clipboard content when possible.
 * Plain text only — no images, files, or rich text.
 */

/* --- Clipboard Initialization --- */

TEST(clip_init_basic) {
    ozayn_result_t r = ozayn_clipboard_init();
    ASSERT_EQ(r, OZAYN_OK);
    ozayn_clipboard_shutdown();
    return 0;
}

TEST(clip_init_idempotent) {
    ozayn_clipboard_init();
    ozayn_result_t r = ozayn_clipboard_init();
    ASSERT_EQ(r, OZAYN_OK);
    ozayn_clipboard_shutdown();
    return 0;
}

/* --- Clipboard Availability --- */

TEST(clip_is_available_after_init) {
    ozayn_clipboard_init();
    int avail = ozayn_clipboard_is_available();
    ASSERT(avail == 0 || avail == 1);
    ozayn_clipboard_shutdown();
    return 0;
}

TEST(clip_is_available_before_init) {
    int avail = ozayn_clipboard_is_available();
    ASSERT(avail == 0);
    return 0;
}

/* --- Clipboard Has Text --- */

TEST(clip_has_text_before_init) {
    int has = ozayn_clipboard_has_text();
    ASSERT(has == 0);
    return 0;
}

TEST(clip_has_text_after_init) {
    ozayn_clipboard_init();
    int has = ozayn_clipboard_has_text();
    ASSERT(has == 0 || has == 1);
    ozayn_clipboard_shutdown();
    return 0;
}

/* --- Clipboard Set/Get --- */

TEST(clip_set_get_basic) {
    ozayn_clipboard_init();
    if (!ozayn_clipboard_is_available()) {
        ozayn_clipboard_shutdown();
        return 0;
    }

    /* Save current clipboard */
    char saved[1024] = {0};
    ozayn_clipboard_get_text(saved, sizeof(saved), NULL);

    /* Set and get */
    const char *test_text = "Hello OZAYN";
    ozayn_result_t r = ozayn_clipboard_set_text(test_text);
    ASSERT_EQ(r, OZAYN_OK);

    char buffer[256] = {0};
    r = ozayn_clipboard_get_text(buffer, sizeof(buffer), NULL);
    ASSERT_EQ(r, OZAYN_OK);
    ASSERT_STR_EQ(buffer, test_text);

    /* Restore */
    ozayn_clipboard_set_text(saved);
    ozayn_clipboard_shutdown();
    return 0;
}

TEST(clip_set_get_unicode) {
    ozayn_clipboard_init();
    if (!ozayn_clipboard_is_available()) {
        ozayn_clipboard_shutdown();
        return 0;
    }

    /* Save current clipboard */
    char saved[1024] = {0};
    ozayn_clipboard_get_text(saved, sizeof(saved), NULL);

    /* Set unicode text */
    const char *unicode_text = "OZAYN \xe2\x80\x94 Cross-Platform AI";
    ozayn_result_t r = ozayn_clipboard_set_text(unicode_text);
    ASSERT_EQ(r, OZAYN_OK);

    char buffer[256] = {0};
    r = ozayn_clipboard_get_text(buffer, sizeof(buffer), NULL);
    ASSERT_EQ(r, OZAYN_OK);
    ASSERT_STR_EQ(buffer, unicode_text);

    /* Restore */
    ozayn_clipboard_set_text(saved);
    ozayn_clipboard_shutdown();
    return 0;
}

TEST(clip_set_get_empty) {
    ozayn_clipboard_init();
    if (!ozayn_clipboard_is_available()) {
        ozayn_clipboard_shutdown();
        return 0;
    }

    /* Save current clipboard */
    char saved[1024] = {0};
    ozayn_clipboard_get_text(saved, sizeof(saved), NULL);

    /* Set empty string */
    ozayn_result_t r = ozayn_clipboard_set_text("");
    ASSERT_EQ(r, OZAYN_OK);

    char buffer[256] = {0};
    r = ozayn_clipboard_get_text(buffer, sizeof(buffer), NULL);
    ASSERT_EQ(r, OZAYN_OK);
    ASSERT_STR_EQ(buffer, "");

    /* Restore */
    ozayn_clipboard_set_text(saved);
    ozayn_clipboard_shutdown();
    return 0;
}

/* --- Buffer Handling --- */

TEST(clip_get_text_null_buffer) {
    ozayn_clipboard_init();
    if (!ozayn_clipboard_is_available()) {
        ozayn_clipboard_shutdown();
        return 0;
    }

    size_t required = 0;
    ozayn_result_t r = ozayn_clipboard_get_text(NULL, 0, &required);
    ASSERT(r == OZAYN_OK || r == OZAYN_ERR);
    ozayn_clipboard_shutdown();
    return 0;
}

TEST(clip_get_text_zero_buffer) {
    ozayn_clipboard_init();
    if (!ozayn_clipboard_is_available()) {
        ozayn_clipboard_shutdown();
        return 0;
    }

    size_t required = 0;
    char buf[1] = {0};
    ozayn_result_t r = ozayn_clipboard_get_text(buf, 0, &required);
    ASSERT(r == OZAYN_OK || r == OZAYN_ERR);
    ozayn_clipboard_shutdown();
    return 0;
}

TEST(clip_get_text_small_buffer) {
    ozayn_clipboard_init();
    if (!ozayn_clipboard_is_available()) {
        ozayn_clipboard_shutdown();
        return 0;
    }

    /* Save current clipboard */
    char saved[1024] = {0};
    ozayn_clipboard_get_text(saved, sizeof(saved), NULL);

    /* Set text */
    ozayn_clipboard_set_text("Hello OZAYN Test");

    /* Try to get with small buffer */
    char buffer[5] = {0};
    size_t required = 0;
    ozayn_result_t r = ozayn_clipboard_get_text(buffer, sizeof(buffer), &required);
    ASSERT(r == OZAYN_OK);
    ASSERT(strlen(buffer) < sizeof(buffer));

    /* Restore */
    ozayn_clipboard_set_text(saved);
    ozayn_clipboard_shutdown();
    return 0;
}

TEST(clip_get_text_required_size) {
    ozayn_clipboard_init();
    if (!ozayn_clipboard_is_available()) {
        ozayn_clipboard_shutdown();
        return 0;
    }

    /* Save current clipboard */
    char saved[1024] = {0};
    ozayn_clipboard_get_text(saved, sizeof(saved), NULL);

    /* Set text */
    const char *test_text = "Hello OZAYN Size";
    ozayn_clipboard_set_text(test_text);

    /* Query required size */
    size_t required = 0;
    ozayn_result_t r = ozayn_clipboard_get_text(NULL, 0, &required);
    ASSERT_EQ(r, OZAYN_OK);
    ASSERT(required > 0);
    ASSERT(required == strlen(test_text) + 1);

    /* Restore */
    ozayn_clipboard_set_text(saved);
    ozayn_clipboard_shutdown();
    return 0;
}

/* --- Clipboard Clear --- */

TEST(clip_clear_basic) {
    ozayn_clipboard_init();
    if (!ozayn_clipboard_is_available()) {
        ozayn_clipboard_shutdown();
        return 0;
    }

    /* Save current clipboard */
    char saved[1024] = {0};
    ozayn_clipboard_get_text(saved, sizeof(saved), NULL);

    /* Set and clear */
    ozayn_clipboard_set_text("To be cleared");
    ozayn_result_t r = ozayn_clipboard_clear();
    ASSERT(r == OZAYN_OK || r == OZAYN_ERR);

    /* Restore */
    ozayn_clipboard_set_text(saved);
    ozayn_clipboard_shutdown();
    return 0;
}

/* --- Clipboard After Shutdown --- */

TEST(clip_operations_after_shutdown) {
    ozayn_clipboard_init();
    ozayn_clipboard_shutdown();

    ozayn_result_t r = ozayn_clipboard_set_text("test");
    ASSERT(r != OZAYN_OK);

    r = ozayn_clipboard_get_text(NULL, 0, NULL);
    ASSERT(r != OZAYN_OK);

    return 0;
}

/* --- Clipboard NULL Handling --- */

TEST(clip_set_text_null) {
    ozayn_clipboard_init();
    ozayn_result_t r = ozayn_clipboard_set_text(NULL);
    ASSERT_EQ(r, OZAYN_ERR_NULL);
    ozayn_clipboard_shutdown();
    return 0;
}

/* --- Clipboard Shutdown --- */

TEST(clip_shutdown_basic) {
    ozayn_clipboard_init();
    ozayn_clipboard_shutdown();
    return 0;
}

TEST(clip_shutdown_idempotent) {
    ozayn_clipboard_init();
    ozayn_clipboard_shutdown();
    ozayn_clipboard_shutdown();
    return 0;
}

TEST(clip_shutdown_before_init) {
    ozayn_clipboard_shutdown();
    return 0;
}

/* --- Test Suite --- */

int run_clipboard_tests(void) {
    int failed = 0;
    SUITE_BEGIN("Clipboard Abstraction (Section 02)");

    RUN(clip_init_basic);
    RUN(clip_init_idempotent);
    RUN(clip_is_available_after_init);
    RUN(clip_is_available_before_init);
    RUN(clip_has_text_before_init);
    RUN(clip_has_text_after_init);
    RUN(clip_set_get_basic);
    RUN(clip_set_get_unicode);
    RUN(clip_set_get_empty);
    RUN(clip_get_text_null_buffer);
    RUN(clip_get_text_zero_buffer);
    RUN(clip_get_text_small_buffer);
    RUN(clip_get_text_required_size);
    RUN(clip_clear_basic);
    RUN(clip_operations_after_shutdown);
    RUN(clip_set_text_null);
    RUN(clip_shutdown_basic);
    RUN(clip_shutdown_idempotent);
    RUN(clip_shutdown_before_init);

    SUITE_END();
    return FAILED();
}
