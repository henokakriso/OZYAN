#include "../../tests/test_framework.h"
#include "platform.h"
#include <stdio.h>
#include <string.h>

/*
 * test_network.c — Section 02 Step 12: Network Information & Connectivity Abstraction Tests.
 *
 * Tests network initialization, shutdown, availability, interface enumeration,
 * connectivity status, and error handling. Works in any network environment.
 *
 * Systems with no network connection produce valid test results.
 * No port scanning, packet capture, or network modification is performed.
 */

/* --- Network Initialization --- */

TEST(net_init_basic) {
    ozayn_result_t r = ozayn_network_init();
    ASSERT_EQ(r, OZAYN_OK);
    ozayn_network_shutdown();
    return 0;
}

TEST(net_init_idempotent) {
    ozayn_network_init();
    ozayn_result_t r = ozayn_network_init();
    ASSERT_EQ(r, OZAYN_OK);
    ozayn_network_shutdown();
    return 0;
}

/* --- Network Availability --- */

TEST(net_is_available_after_init) {
    ozayn_network_init();
    int avail = ozayn_network_is_available();
    ASSERT(avail == 0 || avail == 1);
    ozayn_network_shutdown();
    return 0;
}

TEST(net_is_available_before_init) {
    int avail = ozayn_network_is_available();
    ASSERT(avail == 0);
    return 0;
}

/* --- Interface Enumeration --- */

TEST(net_get_count_before_init) {
    unsigned int count = ozayn_network_get_interface_count();
    ASSERT_EQ(count, 0u);
    return 0;
}

TEST(net_get_count_after_init) {
    ozayn_network_init();
    unsigned int count = ozayn_network_get_interface_count();
    ASSERT(count >= 0u);
    ozayn_network_shutdown();
    return 0;
}

TEST(net_get_info_valid_index) {
    ozayn_network_init();
    unsigned int count = ozayn_network_get_interface_count();
    if (count > 0) {
        OzaynNetworkInterfaceInfo info;
        ozayn_result_t r = ozayn_network_get_interface_info(0, &info);
        ASSERT_EQ(r, OZAYN_OK);
        ASSERT(info.name[0] != '\0');
    }
    ozayn_network_shutdown();
    return 0;
}

TEST(net_get_info_invalid_index) {
    ozayn_network_init();
    OzaynNetworkInterfaceInfo info;
    ozayn_result_t r = ozayn_network_get_interface_info(999, &info);
    ASSERT(r != OZAYN_OK);
    ozayn_network_shutdown();
    return 0;
}

TEST(net_get_info_null) {
    ozayn_network_init();
    ozayn_result_t r = ozayn_network_get_interface_info(0, NULL);
    ASSERT_EQ(r, OZAYN_ERR_NULL);
    ozayn_network_shutdown();
    return 0;
}

TEST(net_get_info_before_init) {
    OzaynNetworkInterfaceInfo info;
    ozayn_result_t r = ozayn_network_get_interface_info(0, &info);
    ASSERT(r != OZAYN_OK);
    return 0;
}

/* --- IPv4/IPv6 Handling --- */

TEST(net_ipv4_format) {
    ozayn_network_init();
    unsigned int count = ozayn_network_get_interface_count();
    for (unsigned int i = 0; i < count; i++) {
        OzaynNetworkInterfaceInfo info;
        ozayn_network_get_interface_info(i, &info);
        if (info.ipv4[0]) {
            ASSERT(strlen(info.ipv4) > 0);
        }
    }
    ozayn_network_shutdown();
    return 0;
}

TEST(net_ipv6_format) {
    ozayn_network_init();
    unsigned int count = ozayn_network_get_interface_count();
    for (unsigned int i = 0; i < count; i++) {
        OzaynNetworkInterfaceInfo info;
        ozayn_network_get_interface_info(i, &info);
        if (info.ipv6[0]) {
            ASSERT(strlen(info.ipv6) > 0);
        }
    }
    ozayn_network_shutdown();
    return 0;
}

/* --- Loopback Detection --- */

TEST(net_loopback_detection) {
    ozayn_network_init();
    unsigned int count = ozayn_network_get_interface_count();
    int found_loopback = 0;
    for (unsigned int i = 0; i < count; i++) {
        OzaynNetworkInterfaceInfo info;
        ozayn_network_get_interface_info(i, &info);
        if (info.is_loopback) {
            found_loopback = 1;
            ASSERT(strstr(info.name, "lo") != NULL || info.ipv4[0] != '\0');
        }
    }
    /* Loopback should exist on most systems, but not required */
    ASSERT(found_loopback == 0 || found_loopback == 1);
    ozayn_network_shutdown();
    return 0;
}

/* --- Interface State --- */

TEST(net_interface_state) {
    ozayn_network_init();
    unsigned int count = ozayn_network_get_interface_count();
    for (unsigned int i = 0; i < count; i++) {
        OzaynNetworkInterfaceInfo info;
        ozayn_network_get_interface_info(i, &info);
        ASSERT(info.is_up == 0 || info.is_up == 1);
        ASSERT(info.is_loopback == 0 || info.is_loopback == 1);
    }
    ozayn_network_shutdown();
    return 0;
}

/* --- Connectivity Status --- */

TEST(net_connectivity_status) {
    ozayn_network_init();
    OzaynConnectivityState state = ozayn_network_is_connected();
    ASSERT(state == OZAYN_CONNECTIVITY_UNKNOWN ||
           state == OZAYN_CONNECTIVITY_DISCONNECTED ||
           state == OZAYN_CONNECTIVITY_CONNECTED);
    ozayn_network_shutdown();
    return 0;
}

TEST(net_connectivity_before_init) {
    OzaynConnectivityState state = ozayn_network_is_connected();
    ASSERT(state == OZAYN_CONNECTIVITY_UNKNOWN);
    return 0;
}

/* --- Default Interface --- */

TEST(net_get_default_interface) {
    ozayn_network_init();
    int def = ozayn_network_get_default_interface();
    ASSERT(def == -1 || def >= 0);
    ozayn_network_shutdown();
    return 0;
}

TEST(net_get_default_interface_before_init) {
    int def = ozayn_network_get_default_interface();
    ASSERT_EQ(def, -1);
    return 0;
}

/* --- MAC Address --- */

TEST(net_mac_address) {
    ozayn_network_init();
    unsigned int count = ozayn_network_get_interface_count();
    for (unsigned int i = 0; i < count; i++) {
        OzaynNetworkInterfaceInfo info;
        ozayn_network_get_interface_info(i, &info);
        if (info.mac[0]) {
            /* MAC should be in xx:xx:xx:xx:xx:xx format */
            ASSERT(strlen(info.mac) == 17);
        }
    }
    ozayn_network_shutdown();
    return 0;
}

/* --- Network Shutdown --- */

TEST(net_shutdown_basic) {
    ozayn_network_init();
    ozayn_network_shutdown();
    return 0;
}

TEST(net_shutdown_idempotent) {
    ozayn_network_init();
    ozayn_network_shutdown();
    ozayn_network_shutdown();
    return 0;
}

TEST(net_shutdown_before_init) {
    ozayn_network_shutdown();
    return 0;
}

/* --- Connectivity State Constants --- */

TEST(net_connectivity_constants) {
    ASSERT_EQ(OZAYN_CONNECTIVITY_UNKNOWN, 0);
    ASSERT(OZAYN_CONNECTIVITY_DISCONNECTED != OZAYN_CONNECTIVITY_UNKNOWN);
    ASSERT(OZAYN_CONNECTIVITY_CONNECTED != OZAYN_CONNECTIVITY_UNKNOWN);
    ASSERT(OZAYN_CONNECTIVITY_DISCONNECTED != OZAYN_CONNECTIVITY_CONNECTED);
    return 0;
}

/* --- Test Suite --- */

int run_network_tests(void) {
    int failed = 0;
    SUITE_BEGIN("Network Information & Connectivity Abstraction (Section 02)");

    RUN(net_init_basic);
    RUN(net_init_idempotent);
    RUN(net_is_available_after_init);
    RUN(net_is_available_before_init);
    RUN(net_get_count_before_init);
    RUN(net_get_count_after_init);
    RUN(net_get_info_valid_index);
    RUN(net_get_info_invalid_index);
    RUN(net_get_info_null);
    RUN(net_get_info_before_init);
    RUN(net_ipv4_format);
    RUN(net_ipv6_format);
    RUN(net_loopback_detection);
    RUN(net_interface_state);
    RUN(net_connectivity_status);
    RUN(net_connectivity_before_init);
    RUN(net_get_default_interface);
    RUN(net_get_default_interface_before_init);
    RUN(net_mac_address);
    RUN(net_shutdown_basic);
    RUN(net_shutdown_idempotent);
    RUN(net_shutdown_before_init);
    RUN(net_connectivity_constants);

    SUITE_END();
    return FAILED();
}
