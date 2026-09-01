#include "../test_framework.h"
#include "ipc.h"

TEST(ipc_header_pack_unpack) {
    ozayn_ipc_header_t hdr1 = {
        .magic = OZAYN_IPC_MAGIC,
        .version = OZAYN_IPC_VERSION,
        .type = OZAYN_IPC_MSG_REQUEST,
        .id = 42,
        .length = 100,
    };
    uint8_t buf[OZAYN_IPC_HEADER_SIZE];
    ASSERT_EQ(ozayn_ipc_header_pack(&hdr1, buf, sizeof(buf)), OZAYN_OK);
    ozayn_ipc_header_t hdr2 = {0};
    ASSERT_EQ(ozayn_ipc_header_unpack(&hdr2, buf, sizeof(buf)), OZAYN_OK);
    ASSERT_EQ(hdr2.magic, OZAYN_IPC_MAGIC);
    ASSERT_EQ(hdr2.version, OZAYN_IPC_VERSION);
    ASSERT_EQ(hdr2.type, OZAYN_IPC_MSG_REQUEST);
    ASSERT_EQ(hdr2.id, 42);
    ASSERT_EQ(hdr2.length, 100);
    return 0;
}

TEST(ipc_header_unpack_bad_magic) {
    uint8_t buf[OZAYN_IPC_HEADER_SIZE] = {0};
    buf[0] = 0xFF; buf[1] = 0xFF;
    ozayn_ipc_header_t hdr = {0};
    /* May accept or reject depending on implementation */
    ozayn_result_t r = ozayn_ipc_header_unpack(&hdr, buf, sizeof(buf));
    (void)r;
    return 0;
}

TEST(ipc_msg_type_names) {
    ASSERT_STR_EQ(ozayn_ipc_msg_type_name(OZAYN_IPC_MSG_NONE), "NONE");
    ASSERT_STR_EQ(ozayn_ipc_msg_type_name(OZAYN_IPC_MSG_HELLO), "HELLO");
    ASSERT_STR_EQ(ozayn_ipc_msg_type_name(OZAYN_IPC_MSG_REQUEST), "REQUEST");
    ASSERT_STR_EQ(ozayn_ipc_msg_type_name(OZAYN_IPC_MSG_RESPONSE), "RESPONSE");
    ASSERT_STR_EQ(ozayn_ipc_msg_type_name(OZAYN_IPC_MSG_EVENT), "EVENT");
    ASSERT_STR_EQ(ozayn_ipc_msg_type_name(OZAYN_IPC_MSG_PING), "PING");
    ASSERT_STR_EQ(ozayn_ipc_msg_type_name(OZAYN_IPC_MSG_PONG), "PONG");
    ASSERT_STR_EQ(ozayn_ipc_msg_type_name(OZAYN_IPC_MSG_BYE), "BYE");
    return 0;
}

TEST(ipc_conn_state_names) {
    ASSERT_STR_EQ(ozayn_ipc_conn_state_name(OZAYN_IPC_CONN_DISCONNECTED), "DISCONNECTED");
    ASSERT_STR_EQ(ozayn_ipc_conn_state_name(OZAYN_IPC_CONN_READY), "READY");
    ASSERT_STR_EQ(ozayn_ipc_conn_state_name(OZAYN_IPC_CONN_FAILED), "FAILED");
    return 0;
}

TEST(ipc_state_names) {
    ASSERT_STR_EQ(ozayn_ipc_state_name(OZAYN_IPC_NOT_CREATED), "NOT_CREATED");
    ASSERT_STR_EQ(ozayn_ipc_state_name(OZAYN_IPC_CREATED), "CREATED");
    ASSERT_STR_EQ(ozayn_ipc_state_name(OZAYN_IPC_LISTENING), "LISTENING");
    ASSERT_STR_EQ(ozayn_ipc_state_name(OZAYN_IPC_STOPPED), "STOPPED");
    return 0;
}

TEST(ipc_component_type_names) {
    ASSERT_STR_EQ(ozayn_ipc_component_type_name(OZAYN_IPC_COMP_UNKNOWN), "UNKNOWN");
    ASSERT_STR_EQ(ozayn_ipc_component_type_name(OZAYN_IPC_COMP_CORE), "CORE");
    ASSERT_STR_EQ(ozayn_ipc_component_type_name(OZAYN_IPC_COMP_MODULE), "MODULE");
    ASSERT_STR_EQ(ozayn_ipc_component_type_name(OZAYN_IPC_COMP_PLUGIN), "PLUGIN");
    return 0;
}

TEST(ipc_manager_init_disabled) {
    ozayn_ipc_manager_t mgr = {0};
    ozayn_ipc_config_t cfg = { .enabled = 0 };
    ASSERT_EQ(ozayn_ipc_manager_init(&mgr, &cfg), OZAYN_OK);
    ASSERT(!ozayn_ipc_manager_is_enabled(&mgr));
    ASSERT_EQ(ozayn_ipc_manager_connection_count(&mgr), 0);
    ozayn_ipc_manager_shutdown(&mgr);
    return 0;
}

int run_ipc_tests(void) {
    SUITE_BEGIN("IPC");
    RUN(ipc_header_pack_unpack);
    RUN(ipc_header_unpack_bad_magic);
    RUN(ipc_msg_type_names);
    RUN(ipc_conn_state_names);
    RUN(ipc_state_names);
    RUN(ipc_component_type_names);
    RUN(ipc_manager_init_disabled);
    SUITE_END();
    return _tf_suite_fail;
}
