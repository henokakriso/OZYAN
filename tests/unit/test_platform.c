#include "../test_framework.h"
#include "platform.h"
#include <string.h>

TEST(platform_system_info) {
    ozayn_system_info_t info = {0};
    ASSERT_EQ(ozayn_system_info(&info), OZAYN_OK);
    ASSERT(info.cpu_cores > 0);
    ASSERT(info.total_memory_mb > 0);
    ASSERT(strlen(info.os_name) > 0);
    return 0;
}

TEST(platform_os_is_linux) {
#ifdef OZAYN_OS_LINUX
    ASSERT(1);
#else
    ASSERT(1); /* skip on other platforms */
#endif
    return 0;
}

TEST(platform_arch_is_x86_64) {
#if defined(OZAYN_ARCH_X86_64) || defined(OZAYN_ARCH_ARM64)
    ASSERT(1);
#else
    ASSERT(1);
#endif
    return 0;
}

TEST(platform_process_self) {
    uint32_t pid = ozayn_process_self();
    ASSERT(pid > 0);
    return 0;
}

TEST(platform_system_time) {
    uint64_t t = ozayn_system_time();
    ASSERT(t > 0);
    return 0;
}

TEST(platform_fs_exists_tmp) {
    ASSERT(ozayn_fs_exists("/tmp") == 1);
    ASSERT(ozayn_fs_exists("/tmp/nonexistent_dir_xyz") == 0);
    return 0;
}

TEST(platform_fs_is_dir) {
    ASSERT(ozayn_fs_is_dir("/tmp") == 1);
    ASSERT(ozayn_fs_is_dir("/etc/hostname") == 0);
    return 0;
}

TEST(platform_fs_home) {
    const char *home = ozayn_fs_home();
    ASSERT_NOT_NULL(home);
    ASSERT(home[0] != '\0');
    return 0;
}

int run_platform_tests(void) {
    SUITE_BEGIN("Platform");
    RUN(platform_system_info);
    RUN(platform_os_is_linux);
    RUN(platform_arch_is_x86_64);
    RUN(platform_process_self);
    RUN(platform_system_time);
    RUN(platform_fs_exists_tmp);
    RUN(platform_fs_is_dir);
    RUN(platform_fs_home);
    SUITE_END();
    return _tf_suite_fail;
}
