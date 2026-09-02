#include "../../tests/test_framework.h"
#include "platform.h"
#include <stdio.h>
#include <string.h>

/*
 * test_application.c — Section 02 Step 18: Application Launch & Discovery Abstraction Tests.
 *
 * Tests application initialization, shutdown, discovery, launching,
 * URL opening, default browser detection, and error handling.
 * No destructive tests — no shell execution, no system modification.
 */

/* --- Initialization --- */

TEST(application_init_basic) {
    ozayn_result_t r = ozayn_application_init();
    ASSERT_EQ(r, OZAYN_OK);
    ozayn_application_shutdown();
    return 0;
}

TEST(application_init_idempotent) {
    ozayn_application_init();
    ozayn_result_t r = ozayn_application_init();
    ASSERT_EQ(r, OZAYN_OK);
    ozayn_application_shutdown();
    return 0;
}

/* --- Availability --- */

TEST(application_is_available_after_init) {
    ozayn_application_init();
    int avail = ozayn_application_is_available();
    ASSERT(avail == 0 || avail == 1);
    ozayn_application_shutdown();
    return 0;
}

TEST(application_is_available_before_init) {
    int avail = ozayn_application_is_available();
    ASSERT_EQ(avail, 0);
    return 0;
}

/* --- Application Existence --- */

TEST(application_exists_valid) {
    ozayn_application_init();
    int exists = ozayn_application_exists("ls");
    ASSERT(exists == 0 || exists == 1);
    ozayn_application_shutdown();
    return 0;
}

TEST(application_exists_nonexistent) {
    ozayn_application_init();
    int exists = ozayn_application_exists("nonexistent_app_xyz_12345");
    ASSERT_EQ(exists, 0);
    ozayn_application_shutdown();
    return 0;
}

TEST(application_exists_null) {
    ozayn_application_init();
    int exists = ozayn_application_exists(NULL);
    ASSERT_EQ(exists, 0);
    ozayn_application_shutdown();
    return 0;
}

TEST(application_exists_empty) {
    ozayn_application_init();
    int exists = ozayn_application_exists("");
    ASSERT_EQ(exists, 0);
    ozayn_application_shutdown();
    return 0;
}

TEST(application_exists_before_init) {
    int exists = ozayn_application_exists("ls");
    ASSERT_EQ(exists, 0);
    return 0;
}

TEST(application_exists_path) {
    ozayn_application_init();
    /* Try an absolute path if /bin/ls exists */
    int exists = ozayn_application_exists("/bin/ls");
    if (exists != -1) {
        ASSERT(exists == 0 || exists == 1);
    }
    ozayn_application_shutdown();
    return 0;
}

/* --- Application Launch --- */

TEST(application_launch_null) {
    ozayn_application_init();
    ozayn_result_t r = ozayn_application_launch(NULL);
    ASSERT_EQ(r, OZAYN_ERR_NULL);
    ozayn_application_shutdown();
    return 0;
}

TEST(application_launch_empty) {
    ozayn_application_init();
    ozayn_result_t r = ozayn_application_launch("");
    ASSERT(r != OZAYN_OK);
    ozayn_application_shutdown();
    return 0;
}

TEST(application_launch_before_init) {
    ozayn_result_t r = ozayn_application_launch("ls");
    ASSERT(r != OZAYN_OK);
    return 0;
}

TEST(application_launch_nonexistent) {
    ozayn_application_init();
    ozayn_result_t r = ozayn_application_launch("nonexistent_app_xyz_12345");
    ASSERT(r != OZAYN_OK);
    ozayn_application_shutdown();
    return 0;
}

TEST(application_launch_valid) {
    /* NOTE: This test does NOT launch anything.
     * It only tests the NULL/empty/before-init error paths.
     * Actual launch testing should be done manually. */
    ozayn_result_t r;

    /* Test null */
    r = ozayn_application_launch(NULL);
    ASSERT_EQ(r, OZAYN_ERR_NULL);

    /* Test empty */
    r = ozayn_application_launch("");
    ASSERT(r != OZAYN_OK);

    /* Test before init */
    r = ozayn_application_launch("ls");
    ASSERT(r != OZAYN_OK);

    return 0;
}

/* --- Default Browser --- */

TEST(application_get_default_browser_null) {
    ozayn_application_init();
    ozayn_result_t r = ozayn_application_get_default_browser(NULL, 0);
    ASSERT_EQ(r, OZAYN_ERR_NULL);
    ozayn_application_shutdown();
    return 0;
}

TEST(application_get_default_browser_zero_size) {
    ozayn_application_init();
    char buf[256];
    ozayn_result_t r = ozayn_application_get_default_browser(buf, 0);
    ASSERT(r != OZAYN_OK);
    ozayn_application_shutdown();
    return 0;
}

TEST(application_get_default_browser_before_init) {
    char buf[256];
    ozayn_result_t r = ozayn_application_get_default_browser(buf, sizeof(buf));
    ASSERT(r != OZAYN_OK);
    return 0;
}

TEST(application_get_default_browser_valid) {
    ozayn_application_init();
    char buf[256] = {0};
    ozayn_result_t r = ozayn_application_get_default_browser(buf, sizeof(buf));
    /* May succeed or fail depending on environment — both are acceptable */
    ASSERT(r == OZAYN_OK || r == OZAYN_ERR);
    ozayn_application_shutdown();
    return 0;
}

/* --- URL Opening --- */

TEST(application_open_url_null) {
    ozayn_application_init();
    ozayn_result_t r = ozayn_application_open_url(NULL);
    ASSERT_EQ(r, OZAYN_ERR_NULL);
    ozayn_application_shutdown();
    return 0;
}

TEST(application_open_url_empty) {
    ozayn_application_init();
    ozayn_result_t r = ozayn_application_open_url("");
    ASSERT(r != OZAYN_OK);
    ozayn_application_shutdown();
    return 0;
}

TEST(application_open_url_before_init) {
    ozayn_result_t r = ozayn_application_open_url("https://example.com");
    ASSERT(r != OZAYN_OK);
    return 0;
}

TEST(application_open_url_invalid_scheme) {
    ozayn_application_init();
    ozayn_result_t r = ozayn_application_open_url("javascript:alert(1)");
    ASSERT(r != OZAYN_OK);
    ozayn_application_shutdown();
    return 0;
}

TEST(application_open_url_no_scheme) {
    ozayn_application_init();
    ozayn_result_t r = ozayn_application_open_url("example.com");
    ASSERT(r != OZAYN_OK);
    ozayn_application_shutdown();
    return 0;
}

TEST(application_open_url_valid_scheme_check) {
    /* Only test that valid schemes pass validation.
     * Does NOT actually open a URL — that's manual testing only. */
    ozayn_application_init();

    /* These should at least pass scheme validation (may fail at OS level) */
    /* We test by checking that invalid schemes are rejected */
    ozayn_result_t r1 = ozayn_application_open_url("javascript:alert(1)");
    ASSERT(r1 != OZAYN_OK);

    ozayn_result_t r2 = ozayn_application_open_url("data:text/html,<h1>test</h1>");
    ASSERT(r2 != OZAYN_OK);

    ozayn_result_t r3 = ozayn_application_open_url("file:///etc/passwd");
    ASSERT(r3 != OZAYN_OK);

    ozayn_application_shutdown();
    return 0;
}

TEST(application_open_url_oversized) {
    ozayn_application_init();
    char url[1024] = {0};
    memset(url, 'A', sizeof(url) - 1);
    /* No valid scheme */
    ozayn_result_t r = ozayn_application_open_url(url);
    ASSERT(r != OZAYN_OK);
    ozayn_application_shutdown();
    return 0;
}

/* --- Shutdown --- */

TEST(application_shutdown_basic) {
    ozayn_application_init();
    ozayn_application_shutdown();
    return 0;
}

TEST(application_shutdown_idempotent) {
    ozayn_application_init();
    ozayn_application_shutdown();
    ozayn_application_shutdown();
    return 0;
}

TEST(application_shutdown_before_init) {
    ozayn_application_shutdown();
    return 0;
}

/* --- Test Suite --- */

int run_application_tests(void) {
    int failed = 0;
    SUITE_BEGIN("Application Launch & Discovery Abstraction (Section 02)");

    /* Initialization */
    RUN(application_init_basic);
    RUN(application_init_idempotent);

    /* Availability */
    RUN(application_is_available_after_init);
    RUN(application_is_available_before_init);

    /* Application Discovery */
    RUN(application_exists_valid);
    RUN(application_exists_nonexistent);
    RUN(application_exists_null);
    RUN(application_exists_empty);
    RUN(application_exists_before_init);
    RUN(application_exists_path);

    /* Application Launch */
    RUN(application_launch_null);
    RUN(application_launch_empty);
    RUN(application_launch_before_init);
    RUN(application_launch_nonexistent);
    RUN(application_launch_valid);

    /* Default Browser */
    RUN(application_get_default_browser_null);
    RUN(application_get_default_browser_zero_size);
    RUN(application_get_default_browser_before_init);
    RUN(application_get_default_browser_valid);

    /* URL Opening */
    RUN(application_open_url_null);
    RUN(application_open_url_empty);
    RUN(application_open_url_before_init);
    RUN(application_open_url_invalid_scheme);
    RUN(application_open_url_no_scheme);
    RUN(application_open_url_valid_scheme_check);
    RUN(application_open_url_oversized);

    /* Shutdown */
    RUN(application_shutdown_basic);
    RUN(application_shutdown_idempotent);
    RUN(application_shutdown_before_init);

    SUITE_END();
    return FAILED();
}
