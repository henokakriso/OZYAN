#include "../../tests/test_framework.h"
#include "platform.h"
#include <stdio.h>
#include <string.h>

/*
 * test_environment.c — Section 02 Step 16: Environment & User Session Abstraction Tests.
 *
 * Tests environment initialization, shutdown, variable access, directory queries,
 * user/host information, and error handling.
 *
 * No environment variables are logged or dumped.
 * No sensitive data is exposed in test output.
 */

/* --- Environment Initialization --- */

TEST(env_init_basic) {
    ozayn_result_t r = ozayn_environment_init();
    ASSERT_EQ(r, OZAYN_OK);
    ozayn_environment_shutdown();
    return 0;
}

TEST(env_init_idempotent) {
    ozayn_environment_init();
    ozayn_result_t r = ozayn_environment_init();
    ASSERT_EQ(r, OZAYN_OK);
    ozayn_environment_shutdown();
    return 0;
}

/* --- Environment Availability --- */

TEST(env_is_available_after_init) {
    ozayn_environment_init();
    int avail = ozayn_environment_is_available();
    ASSERT(avail == 0 || avail == 1);
    ozayn_environment_shutdown();
    return 0;
}

TEST(env_is_available_before_init) {
    int avail = ozayn_environment_is_available();
    ASSERT(avail == 0);
    return 0;
}

/* --- Environment Variable Access --- */

TEST(env_get_variable_existing) {
    ozayn_environment_init();
    char buffer[256] = {0};
    ozayn_result_t r = ozayn_environment_get_variable("PATH", buffer, sizeof(buffer), NULL);
    ASSERT_EQ(r, OZAYN_OK);
    ASSERT(strlen(buffer) > 0);
    ozayn_environment_shutdown();
    return 0;
}

TEST(env_get_variable_missing) {
    ozayn_environment_init();
    char buffer[256] = {0};
    ozayn_result_t r = ozayn_environment_get_variable("OZAYN_NONEXISTENT_VAR_12345", buffer, sizeof(buffer), NULL);
    ASSERT_EQ(r, OZAYN_OK);
    ASSERT_EQ(buffer[0], '\0');
    ozayn_environment_shutdown();
    return 0;
}

TEST(env_get_variable_empty_name) {
    ozayn_environment_init();
    char buffer[256] = {0};
    ozayn_result_t r = ozayn_environment_get_variable("", buffer, sizeof(buffer), NULL);
    ASSERT(r != OZAYN_OK);
    ozayn_environment_shutdown();
    return 0;
}

TEST(env_get_variable_null_name) {
    ozayn_environment_init();
    char buffer[256] = {0};
    ozayn_result_t r = ozayn_environment_get_variable(NULL, buffer, sizeof(buffer), NULL);
    ASSERT(r != OZAYN_OK);
    ozayn_environment_shutdown();
    return 0;
}

TEST(env_get_variable_required_size) {
    ozayn_environment_init();
    size_t required = 0;
    ozayn_result_t r = ozayn_environment_get_variable("PATH", NULL, 0, &required);
    ASSERT_EQ(r, OZAYN_OK);
    ASSERT(required > 0);
    ozayn_environment_shutdown();
    return 0;
}

TEST(env_get_variable_small_buffer) {
    ozayn_environment_init();
    char buffer[5] = {0};
    size_t required = 0;
    ozayn_result_t r = ozayn_environment_get_variable("PATH", buffer, sizeof(buffer), &required);
    ASSERT_EQ(r, OZAYN_OK);
    ASSERT(strlen(buffer) < sizeof(buffer));
    ASSERT(required > 0);
    ozayn_environment_shutdown();
    return 0;
}

TEST(env_get_variable_before_init) {
    char buffer[256] = {0};
    ozayn_result_t r = ozayn_environment_get_variable("PATH", buffer, sizeof(buffer), NULL);
    ASSERT(r != OZAYN_OK);
    return 0;
}

/* --- Directory Queries --- */

TEST(env_get_home_directory) {
    ozayn_environment_init();
    char buffer[1024] = {0};
    ozayn_result_t r = ozayn_environment_get_home_directory(buffer, sizeof(buffer));
    ASSERT_EQ(r, OZAYN_OK);
    ASSERT(strlen(buffer) > 0);
    ASSERT(buffer[0] == '/');
    ozayn_environment_shutdown();
    return 0;
}

TEST(env_get_temp_directory) {
    ozayn_environment_init();
    char buffer[1024] = {0};
    ozayn_result_t r = ozayn_environment_get_temp_directory(buffer, sizeof(buffer));
    ASSERT_EQ(r, OZAYN_OK);
    ASSERT(strlen(buffer) > 0);
    ozayn_environment_shutdown();
    return 0;
}

TEST(env_get_current_directory) {
    ozayn_environment_init();
    char buffer[1024] = {0};
    ozayn_result_t r = ozayn_environment_get_current_directory(buffer, sizeof(buffer));
    ASSERT_EQ(r, OZAYN_OK);
    ASSERT(strlen(buffer) > 0);
    ASSERT(buffer[0] == '/');
    ozayn_environment_shutdown();
    return 0;
}

TEST(env_get_home_directory_null) {
    ozayn_environment_init();
    ozayn_result_t r = ozayn_environment_get_home_directory(NULL, 0);
    ASSERT(r != OZAYN_OK);
    ozayn_environment_shutdown();
    return 0;
}

/* --- User/Host Information --- */

TEST(env_get_username) {
    ozayn_environment_init();
    char buffer[256] = {0};
    ozayn_result_t r = ozayn_environment_get_username(buffer, sizeof(buffer));
    ASSERT_EQ(r, OZAYN_OK);
    ASSERT(strlen(buffer) > 0);
    ozayn_environment_shutdown();
    return 0;
}

TEST(env_get_hostname) {
    ozayn_environment_init();
    char buffer[256] = {0};
    ozayn_result_t r = ozayn_environment_get_hostname(buffer, sizeof(buffer));
    ASSERT_EQ(r, OZAYN_OK);
    ASSERT(strlen(buffer) > 0);
    ozayn_environment_shutdown();
    return 0;
}

TEST(env_get_username_null) {
    ozayn_environment_init();
    ozayn_result_t r = ozayn_environment_get_username(NULL, 0);
    ASSERT(r != OZAYN_OK);
    ozayn_environment_shutdown();
    return 0;
}

TEST(env_get_hostname_null) {
    ozayn_environment_init();
    ozayn_result_t r = ozayn_environment_get_hostname(NULL, 0);
    ASSERT(r != OZAYN_OK);
    ozayn_environment_shutdown();
    return 0;
}

/* --- Buffer Handling --- */

TEST(env_get_home_small_buffer) {
    ozayn_environment_init();
    char buffer[5] = {0};
    ozayn_result_t r = ozayn_environment_get_home_directory(buffer, sizeof(buffer));
    ASSERT_EQ(r, OZAYN_OK);
    ASSERT(strlen(buffer) < sizeof(buffer));
    ozayn_environment_shutdown();
    return 0;
}

TEST(env_get_temp_small_buffer) {
    ozayn_environment_init();
    char buffer[5] = {0};
    ozayn_result_t r = ozayn_environment_get_temp_directory(buffer, sizeof(buffer));
    ASSERT_EQ(r, OZAYN_OK);
    ASSERT(strlen(buffer) < sizeof(buffer));
    ozayn_environment_shutdown();
    return 0;
}

/* --- Environment Shutdown --- */

TEST(env_shutdown_basic) {
    ozayn_environment_init();
    ozayn_environment_shutdown();
    return 0;
}

TEST(env_shutdown_idempotent) {
    ozayn_environment_init();
    ozayn_environment_shutdown();
    ozayn_environment_shutdown();
    return 0;
}

TEST(env_shutdown_before_init) {
    ozayn_environment_shutdown();
    return 0;
}

/* --- Test Suite --- */

int run_environment_tests(void) {
    int failed = 0;
    SUITE_BEGIN("Environment & User Session Abstraction (Section 02)");

    RUN(env_init_basic);
    RUN(env_init_idempotent);
    RUN(env_is_available_after_init);
    RUN(env_is_available_before_init);
    RUN(env_get_variable_existing);
    RUN(env_get_variable_missing);
    RUN(env_get_variable_empty_name);
    RUN(env_get_variable_null_name);
    RUN(env_get_variable_required_size);
    RUN(env_get_variable_small_buffer);
    RUN(env_get_variable_before_init);
    RUN(env_get_home_directory);
    RUN(env_get_temp_directory);
    RUN(env_get_current_directory);
    RUN(env_get_home_directory_null);
    RUN(env_get_username);
    RUN(env_get_hostname);
    RUN(env_get_username_null);
    RUN(env_get_hostname_null);
    RUN(env_get_home_small_buffer);
    RUN(env_get_temp_small_buffer);
    RUN(env_shutdown_basic);
    RUN(env_shutdown_idempotent);
    RUN(env_shutdown_before_init);

    SUITE_END();
    return FAILED();
}
