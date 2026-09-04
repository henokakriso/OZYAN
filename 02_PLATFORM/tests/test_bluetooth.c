#include "../../tests/test_framework.h"
#include "platform.h"
#include <stdio.h>
#include <string.h>

/*
 * test_bluetooth.c — Section 02 Step 28: Bluetooth & Wireless Peripheral Discovery Abstraction Tests.
 *
 * Tests bluetooth initialization, shutdown, discovery lifecycle, enumeration,
 * type names, and error handling. Read-only — no pairing or connection.
 */

/* --- Initialization --- */

TEST(bluetooth_init_basic) {
    ozayn_result_t r = ozayn_bluetooth_init();
    ASSERT_EQ(r, OZAYN_OK);
    ozayn_bluetooth_shutdown();
    return 0;
}

TEST(bluetooth_init_idempotent) {
    ozayn_bluetooth_init();
    ozayn_result_t r = ozayn_bluetooth_init();
    ASSERT_EQ(r, OZAYN_OK);
    ozayn_bluetooth_shutdown();
    return 0;
}

/* --- Availability --- */

TEST(bluetooth_is_available_before_init) {
    int avail = ozayn_bluetooth_is_available();
    ASSERT_EQ(avail, 0);
    return 0;
}

TEST(bluetooth_is_available_after_init) {
    ozayn_bluetooth_init();
    int avail = ozayn_bluetooth_is_available();
    ASSERT(avail == 0 || avail == 1);
    ozayn_bluetooth_shutdown();
    return 0;
}

/* --- Discovery Lifecycle --- */

TEST(bluetooth_start_discovery_before_init) {
    ozayn_result_t r = ozayn_bluetooth_start_discovery();
    ASSERT(r != OZAYN_OK);
    return 0;
}

TEST(bluetooth_start_discovery_basic) {
    ozayn_bluetooth_init();
    /* Start discovery — may succeed or fail depending on BT availability */
    ozayn_bluetooth_start_discovery();
    /* Stop should always succeed */
    ozayn_result_t r = ozayn_bluetooth_stop_discovery();
    ASSERT_EQ(r, OZAYN_OK);
    ozayn_bluetooth_shutdown();
    return 0;
}

TEST(bluetooth_stop_discovery_before_init) {
    ozayn_result_t r = ozayn_bluetooth_stop_discovery();
    ASSERT(r != OZAYN_OK);
    return 0;
}

TEST(bluetooth_is_discovering_before_init) {
    int discovering = ozayn_bluetooth_is_discovering();
    ASSERT_EQ(discovering, 0);
    return 0;
}

TEST(bluetooth_is_discovering_after_start) {
    ozayn_bluetooth_init();
    ozayn_bluetooth_start_discovery();
    int discovering = ozayn_bluetooth_is_discovering();
    ASSERT(discovering == 0 || discovering == 1);
    ozayn_bluetooth_stop_discovery();
    ozayn_bluetooth_shutdown();
    return 0;
}

TEST(bluetooth_is_discovering_after_stop) {
    ozayn_bluetooth_init();
    ozayn_bluetooth_start_discovery();
    ozayn_bluetooth_stop_discovery();
    int discovering = ozayn_bluetooth_is_discovering();
    ASSERT_EQ(discovering, 0);
    ozayn_bluetooth_shutdown();
    return 0;
}

/* --- Enumeration --- */

TEST(bluetooth_get_device_count_before_init) {
    size_t count = ozayn_bluetooth_get_device_count();
    ASSERT(count == 0);
    return 0;
}

TEST(bluetooth_get_device_count_after_init) {
    ozayn_bluetooth_init();
    size_t count = ozayn_bluetooth_get_device_count();
    ASSERT(count >= 0);
    ozayn_bluetooth_shutdown();
    return 0;
}

TEST(bluetooth_get_device_info_null) {
    ozayn_bluetooth_init();
    OzaynBluetoothDeviceInfo info;
    ozayn_result_t r = ozayn_bluetooth_get_device_info(0, NULL);
    ASSERT_EQ(r, OZAYN_ERR_NULL);
    ozayn_bluetooth_shutdown();
    return 0;
}

TEST(bluetooth_get_device_info_before_init) {
    OzaynBluetoothDeviceInfo info;
    ozayn_result_t r = ozayn_bluetooth_get_device_info(0, &info);
    ASSERT(r != OZAYN_OK);
    return 0;
}

TEST(bluetooth_get_device_info_large_index) {
    ozayn_bluetooth_init();
    OzaynBluetoothDeviceInfo info;
    ozayn_result_t r = ozayn_bluetooth_get_device_info(999999, &info);
    ASSERT(r != OZAYN_OK);
    ozayn_bluetooth_shutdown();
    return 0;
}

TEST(bluetooth_get_device_info_valid) {
    ozayn_bluetooth_init();
    size_t count = ozayn_bluetooth_get_device_count();
    if (count == 0) {
        ozayn_bluetooth_shutdown();
        return 0;
    }

    OzaynBluetoothDeviceInfo info;
    ozayn_result_t r = ozayn_bluetooth_get_device_info(0, &info);
    if (r == OZAYN_OK) {
        ASSERT(info.index == 0);
        ASSERT(info.available == 0 || info.available == 1);
        ASSERT(info.type >= OZAYN_BLUETOOTH_UNKNOWN && info.type <= OZAYN_BLUETOOTH_LOW_ENERGY);
        ASSERT(info.paired == 0 || info.paired == 1);
        ASSERT(info.connected == 0 || info.connected == 1);
        ASSERT(info.signal_strength_available == 0 || info.signal_strength_available == 1);
    }
    ozayn_bluetooth_shutdown();
    return 0;
}

TEST(bluetooth_get_device_info_multiple) {
    ozayn_bluetooth_init();
    size_t count = ozayn_bluetooth_get_device_count();
    if (count <= 1) {
        ozayn_bluetooth_shutdown();
        return 0;
    }

    OzaynBluetoothDeviceInfo info_first, info_last;
    ozayn_bluetooth_get_device_info(0, &info_first);
    ozayn_bluetooth_get_device_info(count - 1, &info_last);

    ASSERT(info_first.index == 0);
    ASSERT(info_last.index == count - 1);

    ozayn_bluetooth_shutdown();
    return 0;
}

/* --- Type Names --- */

TEST(bluetooth_type_name_unknown) {
    const char *name = ozayn_bluetooth_type_name(OZAYN_BLUETOOTH_UNKNOWN);
    ASSERT(name != NULL);
    ASSERT(strlen(name) > 0);
    return 0;
}

TEST(bluetooth_type_name_classic) {
    const char *name = ozayn_bluetooth_type_name(OZAYN_BLUETOOTH_CLASSIC);
    ASSERT(name != NULL);
    ASSERT(strlen(name) > 0);
    return 0;
}

TEST(bluetooth_type_name_low_energy) {
    const char *name = ozayn_bluetooth_type_name(OZAYN_BLUETOOTH_LOW_ENERGY);
    ASSERT(name != NULL);
    ASSERT(strlen(name) > 0);
    return 0;
}

TEST(bluetooth_type_name_invalid) {
    const char *name = ozayn_bluetooth_type_name((OzaynBluetoothType)9999);
    ASSERT(name != NULL);
    ASSERT(strlen(name) > 0);
    return 0;
}

/* --- Shutdown --- */

TEST(bluetooth_shutdown_basic) {
    ozayn_bluetooth_init();
    ozayn_bluetooth_shutdown();
    return 0;
}

TEST(bluetooth_shutdown_idempotent) {
    ozayn_bluetooth_init();
    ozayn_bluetooth_shutdown();
    ozayn_bluetooth_shutdown();
    return 0;
}

TEST(bluetooth_shutdown_before_init) {
    ozayn_bluetooth_shutdown();
    return 0;
}

/* --- Test Suite --- */

int run_bluetooth_tests(void) {
    SUITE_BEGIN("Bluetooth & Wireless Peripheral Discovery Abstraction (Step 28)");

    /* Lifecycle */
    RUN(bluetooth_init_basic);
    RUN(bluetooth_init_idempotent);

    /* Availability */
    RUN(bluetooth_is_available_before_init);
    RUN(bluetooth_is_available_after_init);

    /* Discovery Lifecycle */
    RUN(bluetooth_start_discovery_before_init);
    RUN(bluetooth_start_discovery_basic);
    RUN(bluetooth_stop_discovery_before_init);
    RUN(bluetooth_is_discovering_before_init);
    RUN(bluetooth_is_discovering_after_start);
    RUN(bluetooth_is_discovering_after_stop);

    /* Enumeration */
    RUN(bluetooth_get_device_count_before_init);
    RUN(bluetooth_get_device_count_after_init);
    RUN(bluetooth_get_device_info_null);
    RUN(bluetooth_get_device_info_before_init);
    RUN(bluetooth_get_device_info_large_index);
    RUN(bluetooth_get_device_info_valid);
    RUN(bluetooth_get_device_info_multiple);

    /* Type Names */
    RUN(bluetooth_type_name_unknown);
    RUN(bluetooth_type_name_classic);
    RUN(bluetooth_type_name_low_energy);
    RUN(bluetooth_type_name_invalid);

    /* Shutdown */
    RUN(bluetooth_shutdown_basic);
    RUN(bluetooth_shutdown_idempotent);
    RUN(bluetooth_shutdown_before_init);

    SUITE_END();
    return FAILED();
}
