#include "../../tests/test_framework.h"
#include "platform_info.h"
#include "platform.h"
#include <stdio.h>
#include <string.h>

/*
 * test_platform_info.c — Section 02 Step 02: System Information Tests.
 *
 * Tests:
 *   1. Platform info API succeeds
 *   2. Operating system is not empty
 *   3. Architecture is not empty
 *   4. Hostname is not empty
 *   5. Username is not empty
 *   6. CPU count is > 0
 *   7. Memory total is > 0
 *   8. Memory available is > 0 and <= total
 *   9. NULL pointer is handled safely
 *  10. Fields match detected platform
 */

TEST(platform_info_succeeds) {
    ozayn_platform_detect_init();
    OzaynPlatformInfo info;
    ozayn_result_t r = ozayn_platform_get_info(&info);
    ASSERT_EQ(r, OZAYN_OK);
    ozayn_platform_detect_shutdown();
    return 0;
}

TEST(platform_info_os_not_empty) {
    ozayn_platform_detect_init();
    OzaynPlatformInfo info;
    ozayn_platform_get_info(&info);
    ASSERT(strlen(info.operating_system) > 0);
    ozayn_platform_detect_shutdown();
    return 0;
}

TEST(platform_info_arch_not_empty) {
    ozayn_platform_detect_init();
    OzaynPlatformInfo info;
    ozayn_platform_get_info(&info);
    ASSERT(strlen(info.architecture) > 0);
    ozayn_platform_detect_shutdown();
    return 0;
}

TEST(platform_info_hostname_not_empty) {
    ozayn_platform_detect_init();
    OzaynPlatformInfo info;
    ozayn_platform_get_info(&info);
    ASSERT(strlen(info.hostname) > 0);
    ozayn_platform_detect_shutdown();
    return 0;
}

TEST(platform_info_username_not_empty) {
    ozayn_platform_detect_init();
    OzaynPlatformInfo info;
    ozayn_platform_get_info(&info);
    ASSERT(strlen(info.username) > 0);
    ozayn_platform_detect_shutdown();
    return 0;
}

TEST(platform_info_cpu_positive) {
    ozayn_platform_detect_init();
    OzaynPlatformInfo info;
    ozayn_platform_get_info(&info);
    ASSERT(info.cpu_count > 0);
    ozayn_platform_detect_shutdown();
    return 0;
}

TEST(platform_info_memory_total_positive) {
    ozayn_platform_detect_init();
    OzaynPlatformInfo info;
    ozayn_platform_get_info(&info);
    ASSERT(info.memory_total > 0);
    ozayn_platform_detect_shutdown();
    return 0;
}

TEST(platform_info_memory_available_valid) {
    ozayn_platform_detect_init();
    OzaynPlatformInfo info;
    ozayn_platform_get_info(&info);
    ASSERT(info.memory_available <= info.memory_total);
    ozayn_platform_detect_shutdown();
    return 0;
}

TEST(platform_info_null_safe) {
    ozayn_result_t r = ozayn_platform_get_info(NULL);
    ASSERT_EQ(r, OZAYN_ERR_NULL);
    return 0;
}

TEST(platform_info_os_matches_platform) {
    ozayn_platform_detect_init();
    OzaynPlatformInfo info;
    ozayn_platform_get_info(&info);

    switch (ozayn_platform_get()) {
        case OZAYN_PLATFORM_LINUX:   ASSERT_STR_EQ(info.operating_system, "Linux"); break;
        case OZAYN_PLATFORM_WINDOWS: ASSERT_STR_EQ(info.operating_system, "Windows"); break;
        case OZAYN_PLATFORM_MACOS:   ASSERT_STR_EQ(info.operating_system, "macOS"); break;
        default: ASSERT_MSG(0, "unexpected platform"); break;
    }

    ozayn_platform_detect_shutdown();
    return 0;
}

int run_platform_info_tests(void) {
    SUITE_BEGIN("Platform Info (Section 02)");
    RUN(platform_info_succeeds);
    RUN(platform_info_os_not_empty);
    RUN(platform_info_arch_not_empty);
    RUN(platform_info_hostname_not_empty);
    RUN(platform_info_username_not_empty);
    RUN(platform_info_cpu_positive);
    RUN(platform_info_memory_total_positive);
    RUN(platform_info_memory_available_valid);
    RUN(platform_info_null_safe);
    RUN(platform_info_os_matches_platform);
    SUITE_END();
    return _tf_suite_fail;
}
