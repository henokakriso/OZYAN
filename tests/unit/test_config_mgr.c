#include "../test_framework.h"
#include "config.h"
#include <string.h>

TEST(config_load_defaults) {
    ozayn_config_object_t cfg = {0};
    ASSERT_EQ(ozayn_config_load(&cfg), OZAYN_OK);
    ASSERT(cfg.state == OZAYN_CFG_LOADED || cfg.state == OZAYN_CFG_VALIDATED);
    ozayn_config_destroy(&cfg);
    return 0;
}

TEST(config_validate) {
    ozayn_config_object_t cfg = {0};
    ozayn_config_load(&cfg);
    ASSERT_EQ(ozayn_config_validate(&cfg), OZAYN_OK);
    ozayn_config_destroy(&cfg);
    return 0;
}

TEST(config_state_names) {
    ASSERT_STR_EQ(ozayn_config_state_name(OZAYN_CFG_NOT_LOADED), "NOT_LOADED");
    ASSERT_STR_EQ(ozayn_config_state_name(OZAYN_CFG_LOADED), "LOADED");
    ASSERT_STR_EQ(ozayn_config_state_name(OZAYN_CFG_VALIDATED), "VALIDATED");
    ASSERT_STR_EQ(ozayn_config_state_name(OZAYN_CFG_ACTIVE), "ACTIVE");
    ASSERT_STR_EQ(ozayn_config_state_name(OZAYN_CFG_LOAD_FAILED), "LOAD_FAILED");
    return 0;
}

TEST(config_log_level_names) {
    ASSERT_NOT_NULL(ozayn_log_level_name(0));
    ASSERT_NOT_NULL(ozayn_log_level_name(1));
    ASSERT_NOT_NULL(ozayn_log_level_name(2));
    ASSERT_NOT_NULL(ozayn_log_level_name(3));
    ASSERT_NOT_NULL(ozayn_log_level_name(4));
    return 0;
}

TEST(config_log_level_from_name) {
    ASSERT_EQ(ozayn_log_level_from_name("debug"), 0);
    ASSERT_EQ(ozayn_log_level_from_name("info"), 1);
    ASSERT_EQ(ozayn_log_level_from_name("error"), 3);
    ASSERT_EQ(ozayn_log_level_from_name("critical"), 4);
    return 0;
}

TEST(config_defaults_populated) {
    ozayn_config_object_t cfg = {0};
    ozayn_config_load(&cfg);
    ASSERT(cfg.values.runtime_interval > 0);
    ASSERT(cfg.values.log_level >= 0 && cfg.values.log_level <= 4);
    ozayn_config_destroy(&cfg);
    return 0;
}

int run_config_mgr_tests(void) {
    SUITE_BEGIN("Config Manager");
    RUN(config_load_defaults);
    RUN(config_validate);
    RUN(config_state_names);
    RUN(config_log_level_names);
    RUN(config_log_level_from_name);
    RUN(config_defaults_populated);
    SUITE_END();
    return _tf_suite_fail;
}
