#include "../test_framework.h"
#include "logger.h"
#include <string.h>

TEST(logger_init_creates_logger) {
    ozayn_logger_t log;
    ozayn_log_config_t cfg = {
        .console_enabled = 0,
        .file_enabled = 0,
        .min_level = OZAYN_LOG_DEBUG,
    };
    strcpy(cfg.directory, "/tmp");
    ASSERT_EQ(ozayn_logger_init(&log, &cfg), OZAYN_OK);
    ASSERT_EQ(log.state, OZAYN_LOG_ACTIVE);
    ozayn_logger_shutdown(&log);
    return 0;
}

TEST(logger_shutdown_clears_state) {
    ozayn_logger_t log;
    ozayn_log_config_t cfg = {
        .console_enabled = 0,
        .file_enabled = 0,
        .min_level = OZAYN_LOG_DEBUG,
    };
    strcpy(cfg.directory, "/tmp");
    ozayn_logger_init(&log, &cfg);
    ozayn_logger_shutdown(&log);
    ASSERT_EQ(log.state, OZAYN_LOG_STOPPED);
    return 0;
}

TEST(logger_level_str_returns_strings) {
    ASSERT(ozayn_log_level_str(OZAYN_LOG_DEBUG) != NULL);
    ASSERT(ozayn_log_level_str(OZAYN_LOG_INFO) != NULL);
    ASSERT(ozayn_log_level_str(OZAYN_LOG_WARNING) != NULL);
    ASSERT(ozayn_log_level_str(OZAYN_LOG_ERROR) != NULL);
    ASSERT(ozayn_log_level_str(OZAYN_LOG_CRITICAL) != NULL);
    return 0;
}

TEST(logger_level_str_unknown) {
    const char *s = ozayn_log_level_str(999);
    ASSERT_NOT_NULL(s);
    ASSERT(s[0] != '\0');
    return 0;
}

TEST(logger_log_does_not_crash) {
    ozayn_logger_t log;
    ozayn_log_config_t cfg = {
        .console_enabled = 0,
        .file_enabled = 0,
        .min_level = OZAYN_LOG_DEBUG,
    };
    strcpy(cfg.directory, "/tmp");
    ozayn_logger_init(&log, &cfg);
    ozayn_log(&log, OZAYN_LOG_INFO, "TEST", "test message %d", 42);
    ozayn_log(&log, OZAYN_LOG_ERROR, "TEST", "error message");
    ozayn_log(&log, OZAYN_LOG_CRITICAL, "TEST", "critical message");
    ozayn_logger_shutdown(&log);
    return 0;
}

TEST(logger_file_output) {
    ozayn_logger_t log;
    ozayn_log_config_t cfg = {
        .console_enabled = 0,
        .file_enabled = 1,
        .min_level = OZAYN_LOG_DEBUG,
    };
    strcpy(cfg.directory, "/tmp");
    ozayn_result_t r = ozayn_logger_init(&log, &cfg);
    if (r == OZAYN_OK && log.file) {
        ozayn_log(&log, OZAYN_LOG_INFO, "TEST", "file test");
        ASSERT(log.file != NULL);
    }
    ozayn_logger_shutdown(&log);
    return 0;
}

TEST(logger_level_filtering) {
    ozayn_logger_t log;
    ozayn_log_config_t cfg = {
        .console_enabled = 0,
        .file_enabled = 0,
        .min_level = OZAYN_LOG_WARNING,
    };
    strcpy(cfg.directory, "/tmp");
    ozayn_logger_init(&log, &cfg);
    /* These should be filtered out (below WARNING level) */
    ozayn_log(&log, OZAYN_LOG_DEBUG, "TEST", "should be filtered");
    ozayn_log(&log, OZAYN_LOG_INFO, "TEST", "should be filtered");
    /* These should pass through */
    ozayn_log(&log, OZAYN_LOG_WARNING, "TEST", "should pass");
    ozayn_log(&log, OZAYN_LOG_ERROR, "TEST", "should pass");
    ozayn_logger_shutdown(&log);
    return 0;
}

int run_logger_tests(void) {
    SUITE_BEGIN("Logger");
    RUN(logger_init_creates_logger);
    RUN(logger_shutdown_clears_state);
    RUN(logger_level_str_returns_strings);
    RUN(logger_level_str_unknown);
    RUN(logger_log_does_not_crash);
    RUN(logger_file_output);
    RUN(logger_level_filtering);
    SUITE_END();
    return _tf_suite_fail;
}
