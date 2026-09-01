#include "../test_framework.h"
#include "commands.h"

TEST(command_engine_init_returns_ok) {
    ozayn_command_engine_t engine;
    ASSERT_EQ(ozayn_command_engine_init(&engine), OZAYN_OK);
    ASSERT(engine.initialized);
    ozayn_command_engine_shutdown(&engine);
    return 0;
}

TEST(command_engine_shutdown_clears_state) {
    ozayn_command_engine_t engine;
    ozayn_command_engine_init(&engine);
    ozayn_command_engine_shutdown(&engine);
    ASSERT(!engine.initialized);
    return 0;
}

TEST(command_create_sets_fields) {
    ozayn_command_t cmd = ozayn_command_create(OZAYN_CMD_STATUS, OZAYN_CMD_SRC_CLI);
    ASSERT_EQ(cmd.type, OZAYN_CMD_STATUS);
    ASSERT_EQ(cmd.source, OZAYN_CMD_SRC_CLI);
    return 0;
}

TEST(command_engine_execute_status) {
    ozayn_command_engine_t engine;
    ozayn_command_engine_init(&engine);
    ozayn_command_t cmd = ozayn_command_create(OZAYN_CMD_STATUS, OZAYN_CMD_SRC_CLI);
    ozayn_command_result_t r = ozayn_command_engine_execute(&engine, &cmd);
    ASSERT_EQ(r, OZAYN_CMD_RESULT_SUCCESS);
    ozayn_command_engine_shutdown(&engine);
    return 0;
}

TEST(command_engine_execute_unknown) {
    ozayn_command_engine_t engine;
    ozayn_command_engine_init(&engine);
    ozayn_command_t cmd = ozayn_command_create(OZAYN_CMD_NONE, OZAYN_CMD_SRC_CLI);
    ozayn_command_result_t r = ozayn_command_engine_execute(&engine, &cmd);
    ASSERT_EQ(r, OZAYN_CMD_RESULT_INVALID);
    ozayn_command_engine_shutdown(&engine);
    return 0;
}

TEST(command_type_names) {
    ASSERT_STR_EQ(ozayn_command_type_name(OZAYN_CMD_NONE), "NONE");
    ASSERT_STR_EQ(ozayn_command_type_name(OZAYN_CMD_STATUS), "STATUS");
    ASSERT_STR_EQ(ozayn_command_type_name(OZAYN_CMD_STOP), "STOP");
    ASSERT_STR_EQ(ozayn_command_type_name(OZAYN_CMD_HEALTH), "HEALTH");
    ASSERT_STR_EQ(ozayn_command_type_name(OZAYN_CMD_LC_STATUS), "LC_STATUS");
    return 0;
}

TEST(command_result_names) {
    ASSERT_STR_EQ(ozayn_command_result_name(OZAYN_CMD_RESULT_SUCCESS), "SUCCESS");
    ASSERT_STR_EQ(ozayn_command_result_name(OZAYN_CMD_RESULT_FAILURE), "FAILURE");
    ASSERT_STR_EQ(ozayn_command_result_name(OZAYN_CMD_RESULT_REJECTED), "REJECTED");
    ASSERT_STR_EQ(ozayn_command_result_name(OZAYN_CMD_RESULT_INVALID), "INVALID");
    ASSERT_STR_EQ(ozayn_command_result_name(OZAYN_CMD_RESULT_NOT_FOUND), "NOT_FOUND");
    return 0;
}

TEST(command_source_names) {
    ASSERT_STR_EQ(ozayn_command_source_name(OZAYN_CMD_SRC_CORE), "CORE");
    ASSERT_STR_EQ(ozayn_command_source_name(OZAYN_CMD_SRC_CLI), "CLI");
    return 0;
}

TEST(command_engine_execute_health) {
    ozayn_command_engine_t engine;
    ozayn_command_engine_init(&engine);
    ozayn_command_t cmd = ozayn_command_create(OZAYN_CMD_HEALTH, OZAYN_CMD_SRC_CLI);
    ozayn_command_result_t r = ozayn_command_engine_execute(&engine, &cmd);
    ASSERT_EQ(r, OZAYN_CMD_RESULT_SUCCESS);
    ozayn_command_engine_shutdown(&engine);
    return 0;
}

TEST(command_engine_execute_lc_status) {
    ozayn_command_engine_t engine;
    ozayn_command_engine_init(&engine);
    ozayn_command_t cmd = ozayn_command_create(OZAYN_CMD_LC_STATUS, OZAYN_CMD_SRC_CLI);
    ozayn_command_result_t r = ozayn_command_engine_execute(&engine, &cmd);
    ASSERT_EQ(r, OZAYN_CMD_RESULT_SUCCESS);
    ozayn_command_engine_shutdown(&engine);
    return 0;
}

int run_commands_tests(void) {
    SUITE_BEGIN("Commands");
    RUN(command_engine_init_returns_ok);
    RUN(command_engine_shutdown_clears_state);
    RUN(command_create_sets_fields);
    RUN(command_engine_execute_status);
    RUN(command_engine_execute_unknown);
    RUN(command_type_names);
    RUN(command_result_names);
    RUN(command_source_names);
    RUN(command_engine_execute_health);
    RUN(command_engine_execute_lc_status);
    SUITE_END();
    return _tf_suite_fail;
}
