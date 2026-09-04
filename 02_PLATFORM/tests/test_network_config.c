#include "../../tests/test_framework.h"
#include "platform.h"
#include <stdio.h>
#include <string.h>

/*
 * test_network_config.c — Section 02 Step 31: Network Configuration & Routing Information Abstraction Tests.
 *
 * Tests network config initialization, shutdown, enumeration, information validation,
 * default configuration, and error handling. Read-only — no network modification.
 */

/* --- Initialization --- */

TEST(netcfg_init_basic) {
    ozayn_result_t r = ozayn_network_config_init();
    ASSERT_EQ(r, OZAYN_OK);
    ozayn_network_config_shutdown();
    return 0;
}

TEST(netcfg_init_idempotent) {
    ozayn_network_config_init();
    ozayn_result_t r = ozayn_network_config_init();
    ASSERT_EQ(r, OZAYN_OK);
    ozayn_network_config_shutdown();
    return 0;
}

/* --- Availability --- */

TEST(netcfg_is_available_before_init) {
    int avail = ozayn_network_config_is_available();
    ASSERT_EQ(avail, 0);
    return 0;
}

TEST(netcfg_is_available_after_init) {
    ozayn_network_config_init();
    int avail = ozayn_network_config_is_available();
    ASSERT(avail == 0 || avail == 1);
    ozayn_network_config_shutdown();
    return 0;
}

/* --- Count --- */

TEST(netcfg_count_before_init) {
    int count = ozayn_network_config_get_count();
    ASSERT_EQ(count, 0);
    return 0;
}

TEST(netcfg_count_after_init) {
    ozayn_network_config_init();
    int count = ozayn_network_config_get_count();
    ASSERT(count >= 0);
    ozayn_network_config_shutdown();
    return 0;
}

/* --- Get by Index --- */

TEST(netcfg_get_null) {
    ozayn_network_config_init();
    ozayn_result_t r = ozayn_network_config_get(0, NULL);
    ASSERT_EQ(r, OZAYN_ERR_NULL);
    ozayn_network_config_shutdown();
    return 0;
}

TEST(netcfg_get_before_init) {
    OzaynNetworkConfig cfg;
    ozayn_result_t r = ozayn_network_config_get(0, &cfg);
    ASSERT(r != OZAYN_OK);
    return 0;
}

TEST(netcfg_get_negative_index) {
    ozayn_network_config_init();
    OzaynNetworkConfig cfg;
    ozayn_result_t r = ozayn_network_config_get(-1, &cfg);
    ASSERT(r != OZAYN_OK);
    ozayn_network_config_shutdown();
    return 0;
}

TEST(netcfg_get_index_out_of_range) {
    ozayn_network_config_init();
    int count = ozayn_network_config_get_count();
    OzaynNetworkConfig cfg;
    ozayn_result_t r = ozayn_network_config_get(count + 100, &cfg);
    ASSERT(r != OZAYN_OK);
    ozayn_network_config_shutdown();
    return 0;
}

TEST(netcfg_get_valid) {
    ozayn_network_config_init();
    int count = ozayn_network_config_get_count();
    if (count <= 0) {
        ozayn_network_config_shutdown();
        return 0;
    }
    OzaynNetworkConfig cfg;
    memset(&cfg, 0, sizeof(cfg));
    ozayn_result_t r = ozayn_network_config_get(0, &cfg);
    ASSERT_EQ(r, OZAYN_OK);
    ASSERT_EQ(cfg.available, 1);
    ASSERT(cfg.interface_name[0] != '\0');
    ozayn_network_config_shutdown();
    return 0;
}

TEST(netcfg_get_all_interfaces) {
    ozayn_network_config_init();
    int count = ozayn_network_config_get_count();
    for (int i = 0; i < count; i++) {
        OzaynNetworkConfig cfg;
        memset(&cfg, 0, sizeof(cfg));
        ozayn_result_t r = ozayn_network_config_get(i, &cfg);
        ASSERT_EQ(r, OZAYN_OK);
        ASSERT_EQ(cfg.available, 1);
        ASSERT(cfg.interface_name[0] != '\0');
    }
    ozayn_network_config_shutdown();
    return 0;
}

/* --- Information Validation --- */

TEST(netcfg_ipv4_valid_format) {
    ozayn_network_config_init();
    int count = ozayn_network_config_get_count();
    for (int i = 0; i < count; i++) {
        OzaynNetworkConfig cfg;
        ozayn_network_config_get(i, &cfg);
        if (cfg.has_ipv4) {
            /* Must contain at least 3 dots */
            int dots = 0;
            for (const char *p = cfg.ipv4_address; *p; p++) {
                if (*p == '.') dots++;
            }
            ASSERT(dots == 3);
            ASSERT(strlen(cfg.ipv4_address) > 0);
            ASSERT(strlen(cfg.ipv4_address) < OZAYN_MAX_NETCFG_ADDR);
        }
    }
    ozayn_network_config_shutdown();
    return 0;
}

TEST(netcfg_ipv6_valid_format) {
    ozayn_network_config_init();
    int count = ozayn_network_config_get_count();
    for (int i = 0; i < count; i++) {
        OzaynNetworkConfig cfg;
        ozayn_network_config_get(i, &cfg);
        if (cfg.has_ipv6) {
            /* Must contain at least one colon */
            int colons = 0;
            for (const char *p = cfg.ipv6_address; *p; p++) {
                if (*p == ':') colons++;
            }
            ASSERT(colons >= 2);
            ASSERT(strlen(cfg.ipv6_address) > 0);
            ASSERT(strlen(cfg.ipv6_address) < OZAYN_MAX_NETCFG_V6);
        }
    }
    ozayn_network_config_shutdown();
    return 0;
}

TEST(netcfg_strings_null_terminated) {
    ozayn_network_config_init();
    int count = ozayn_network_config_get_count();
    for (int i = 0; i < count; i++) {
        OzaynNetworkConfig cfg;
        ozayn_network_config_get(i, &cfg);
        /* All string buffers should be null-terminated */
        ASSERT(cfg.interface_name[OZAYN_MAX_NETCFG_IFACE - 1] == '\0');
        ASSERT(cfg.ipv4_address[OZAYN_MAX_NETCFG_ADDR - 1] == '\0');
        ASSERT(cfg.ipv6_address[OZAYN_MAX_NETCFG_V6 - 1] == '\0');
        ASSERT(cfg.subnet_mask[OZAYN_MAX_NETCFG_ADDR - 1] == '\0');
        ASSERT(cfg.gateway_ipv4[OZAYN_MAX_NETCFG_ADDR - 1] == '\0');
        ASSERT(cfg.gateway_ipv6[OZAYN_MAX_NETCFG_V6 - 1] == '\0');
        ASSERT(cfg.dns_primary[OZAYN_MAX_NETCFG_DNS - 1] == '\0');
        ASSERT(cfg.dns_secondary[OZAYN_MAX_NETCFG_DNS - 1] == '\0');
    }
    ozayn_network_config_shutdown();
    return 0;
}

/* --- Default Configuration --- */

TEST(netcfg_default_null) {
    ozayn_network_config_init();
    ozayn_result_t r = ozayn_network_config_get_default(NULL);
    ASSERT_EQ(r, OZAYN_ERR_NULL);
    ozayn_network_config_shutdown();
    return 0;
}

TEST(netcfg_default_before_init) {
    OzaynNetworkConfig cfg;
    ozayn_result_t r = ozayn_network_config_get_default(&cfg);
    ASSERT(r != OZAYN_OK);
    return 0;
}

TEST(netcfg_default_valid) {
    ozayn_network_config_init();
    OzaynNetworkConfig cfg;
    memset(&cfg, 0, sizeof(cfg));
    ozayn_result_t r = ozayn_network_config_get_default(&cfg);
    if (r == OZAYN_OK) {
        ASSERT_EQ(cfg.available, 1);
        ASSERT(cfg.interface_name[0] != '\0');
    }
    /* No default route is a valid environment condition */
    ozayn_network_config_shutdown();
    return 0;
}

/* --- Shutdown --- */

TEST(netcfg_shutdown_basic) {
    ozayn_network_config_init();
    ozayn_network_config_shutdown();
    return 0;
}

TEST(netcfg_shutdown_idempotent) {
    ozayn_network_config_init();
    ozayn_network_config_shutdown();
    ozayn_network_config_shutdown();
    return 0;
}

TEST(netcfg_shutdown_before_init) {
    ozayn_network_config_shutdown();
    return 0;
}

/* --- After Shutdown --- */

TEST(netcfg_query_after_shutdown) {
    ozayn_network_config_init();
    ozayn_network_config_shutdown();

    int avail = ozayn_network_config_is_available();
    ASSERT_EQ(avail, 0);

    int count = ozayn_network_config_get_count();
    ASSERT_EQ(count, 0);

    OzaynNetworkConfig cfg;
    ozayn_result_t r = ozayn_network_config_get(0, &cfg);
    ASSERT(r != OZAYN_OK);

    r = ozayn_network_config_get_default(&cfg);
    ASSERT(r != OZAYN_OK);

    return 0;
}

/* --- Test Suite --- */

int run_network_config_tests(void) {
    SUITE_BEGIN("Network Configuration & Routing Information Abstraction (Step 31)");

    /* Lifecycle */
    RUN(netcfg_init_basic);
    RUN(netcfg_init_idempotent);

    /* Availability */
    RUN(netcfg_is_available_before_init);
    RUN(netcfg_is_available_after_init);

    /* Count */
    RUN(netcfg_count_before_init);
    RUN(netcfg_count_after_init);

    /* Get by Index */
    RUN(netcfg_get_null);
    RUN(netcfg_get_before_init);
    RUN(netcfg_get_negative_index);
    RUN(netcfg_get_index_out_of_range);
    RUN(netcfg_get_valid);
    RUN(netcfg_get_all_interfaces);

    /* Information Validation */
    RUN(netcfg_ipv4_valid_format);
    RUN(netcfg_ipv6_valid_format);
    RUN(netcfg_strings_null_terminated);

    /* Default Configuration */
    RUN(netcfg_default_null);
    RUN(netcfg_default_before_init);
    RUN(netcfg_default_valid);

    /* Shutdown */
    RUN(netcfg_shutdown_basic);
    RUN(netcfg_shutdown_idempotent);
    RUN(netcfg_shutdown_before_init);
    RUN(netcfg_query_after_shutdown);

    SUITE_END();
    return FAILED();
}
