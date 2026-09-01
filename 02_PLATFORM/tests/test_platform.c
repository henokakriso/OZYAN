#include "../../tests/test_framework.h"
#include "platform.h"
#include <stdio.h>
#include <string.h>

/*
 * test_platform.c — Section 02 Step 01: Platform Detection & Initialization Tests.
 *
 * Tests:
 *   1. Platform detection init succeeds on supported OS
 *   2. Platform is not UNKNOWN after init
 *   3. Platform name is not "Unknown" after init
 *   4. Platform name matches detected platform
 *   5. Platform state resets to UNKNOWN after shutdown
 *   6. Platform name returns "Unknown" after shutdown
 *   7. Init/shutdown cycle is idempotent
 *   8. Double init does not crash
 */

TEST(platform_detect_init_succeeds) {
    ozayn_result_t r = ozayn_platform_detect_init();
    ASSERT_EQ(r, OZAYN_OK);
    ozayn_platform_detect_shutdown();
    return 0;
}

TEST(platform_is_not_unknown_after_init) {
    ozayn_platform_detect_init();
    OzaynPlatform p = ozayn_platform_get();
    ASSERT_NEQ(p, OZAYN_PLATFORM_UNKNOWN);
    ozayn_platform_detect_shutdown();
    return 0;
}

TEST(platform_name_not_unknown_after_init) {
    ozayn_platform_detect_init();
    const char *name = ozayn_platform_name();
    ASSERT_NOT_NULL(name);
    ASSERT(strcmp(name, "Unknown") != 0);
    ozayn_platform_detect_shutdown();
    return 0;
}

TEST(platform_name_matches_detected) {
    ozayn_platform_detect_init();
    OzaynPlatform p = ozayn_platform_get();
    const char *name = ozayn_platform_name();

    switch (p) {
        case OZAYN_PLATFORM_LINUX:   ASSERT_STR_EQ(name, "Linux"); break;
        case OZAYN_PLATFORM_WINDOWS: ASSERT_STR_EQ(name, "Windows"); break;
        case OZAYN_PLATFORM_MACOS:   ASSERT_STR_EQ(name, "macOS"); break;
        default: ASSERT_MSG(0, "unexpected platform"); break;
    }

    ozayn_platform_detect_shutdown();
    return 0;
}

TEST(platform_resets_to_unknown_after_shutdown) {
    ozayn_platform_detect_init();
    ozayn_platform_detect_shutdown();
    ASSERT_EQ(ozayn_platform_get(), OZAYN_PLATFORM_UNKNOWN);
    return 0;
}

TEST(platform_name_unknown_after_shutdown) {
    ozayn_platform_detect_init();
    ozayn_platform_detect_shutdown();
    ASSERT_STR_EQ(ozayn_platform_name(), "Unknown");
    return 0;
}

TEST(platform_init_shutdown_idempotent) {
    for (int i = 0; i < 3; i++) {
        ASSERT_EQ(ozayn_platform_detect_init(), OZAYN_OK);
        ASSERT_NEQ(ozayn_platform_get(), OZAYN_PLATFORM_UNKNOWN);
        ozayn_platform_detect_shutdown();
        ASSERT_EQ(ozayn_platform_get(), OZAYN_PLATFORM_UNKNOWN);
    }
    return 0;
}

TEST(platform_double_init_no_crash) {
    ASSERT_EQ(ozayn_platform_detect_init(), OZAYN_OK);
    ASSERT_EQ(ozayn_platform_detect_init(), OZAYN_OK);
    ozayn_platform_detect_shutdown();
    return 0;
}

int run_platform_detect_tests(void) {
    SUITE_BEGIN("Platform Detection (Section 02)");
    RUN(platform_detect_init_succeeds);
    RUN(platform_is_not_unknown_after_init);
    RUN(platform_name_not_unknown_after_init);
    RUN(platform_name_matches_detected);
    RUN(platform_resets_to_unknown_after_shutdown);
    RUN(platform_name_unknown_after_shutdown);
    RUN(platform_init_shutdown_idempotent);
    RUN(platform_double_init_no_crash);
    SUITE_END();
    return _tf_suite_fail;
}
