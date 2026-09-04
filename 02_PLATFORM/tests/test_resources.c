#include "../../tests/test_framework.h"
#include "platform.h"
#include <stdio.h>
#include <string.h>
#include <math.h>

/*
 * test_resources.c — Section 02 Step 30: System Resource Monitoring Abstraction Tests.
 *
 * Tests resource monitoring initialization, shutdown, availability,
 * CPU usage, memory usage, process count, load average,
 * and error handling. Read-only — no system modification.
 */

/* --- Initialization --- */

TEST(resources_init_basic) {
    ozayn_result_t r = ozayn_resources_init();
    ASSERT_EQ(r, OZAYN_OK);
    ozayn_resources_shutdown();
    return 0;
}

TEST(resources_init_idempotent) {
    ozayn_resources_init();
    ozayn_result_t r = ozayn_resources_init();
    ASSERT_EQ(r, OZAYN_OK);
    ozayn_resources_shutdown();
    return 0;
}

/* --- Availability --- */

TEST(resources_is_available_before_init) {
    int avail = ozayn_resources_is_available();
    ASSERT_EQ(avail, 0);
    return 0;
}

TEST(resources_is_available_after_init) {
    ozayn_resources_init();
    int avail = ozayn_resources_is_available();
    ASSERT_EQ(avail, 1);
    ozayn_resources_shutdown();
    return 0;
}

/* --- CPU Usage --- */

TEST(resources_cpu_usage_null) {
    ozayn_resources_init();
    ozayn_result_t r = ozayn_resources_get_cpu_usage(NULL);
    ASSERT_EQ(r, OZAYN_ERR_NULL);
    ozayn_resources_shutdown();
    return 0;
}

TEST(resources_cpu_usage_before_init) {
    double usage = 999.0;
    ozayn_result_t r = ozayn_resources_get_cpu_usage(&usage);
    ASSERT(r != OZAYN_OK);
    ASSERT_EQ(usage, 0.0);
    return 0;
}

TEST(resources_cpu_usage_range) {
    ozayn_resources_init();
    /* Need two samples for CPU measurement */
    ozayn_system_sleep_ms(50);
    double usage = -1.0;
    ozayn_result_t r = ozayn_resources_get_cpu_usage(&usage);
    if (r == OZAYN_OK) {
        ASSERT(usage >= 0.0);
        ASSERT(usage <= 100.0);
        ASSERT(usage == usage); /* not NaN */
    }
    ozayn_resources_shutdown();
    return 0;
}

/* --- Memory Usage --- */

TEST(resources_memory_usage_before_init) {
    uint64_t total = 999, used = 999, avail = 999;
    ozayn_result_t r = ozayn_resources_get_memory_usage(&total, &used, &avail);
    ASSERT(r != OZAYN_OK);
    ASSERT_EQ(total, 0);
    ASSERT_EQ(used, 0);
    ASSERT_EQ(avail, 0);
    return 0;
}

TEST(resources_memory_usage_values) {
    ozayn_resources_init();
    uint64_t total = 0, used = 0, avail = 0;
    ozayn_result_t r = ozayn_resources_get_memory_usage(&total, &used, &avail);
    if (r == OZAYN_OK) {
        ASSERT(total > 0);
        ASSERT(avail <= total);
        ASSERT(used <= total);
        ASSERT(used + avail <= total + 1024 * 1024); /* allow 1MB rounding */
    }
    ozayn_resources_shutdown();
    return 0;
}

TEST(resources_memory_usage_partial_null) {
    ozayn_resources_init();
    /* Only total */
    uint64_t total = 0;
    ozayn_result_t r = ozayn_resources_get_memory_usage(&total, NULL, NULL);
    if (r == OZAYN_OK) {
        ASSERT(total > 0);
    }
    ozayn_resources_shutdown();
    return 0;
}

/* --- Process Count --- */

TEST(resources_process_count_before_init) {
    size_t count = 999;
    ozayn_result_t r = ozayn_resources_get_process_count(&count);
    ASSERT(r != OZAYN_OK);
    ASSERT_EQ(count, 0);
    return 0;
}

TEST(resources_process_count_values) {
    ozayn_resources_init();
    size_t count = 0;
    ozayn_result_t r = ozayn_resources_get_process_count(&count);
    if (r == OZAYN_OK) {
        ASSERT(count > 0);
    }
    ozayn_resources_shutdown();
    return 0;
}

TEST(resources_process_count_null) {
    ozayn_resources_init();
    ozayn_result_t r = ozayn_resources_get_process_count(NULL);
    ASSERT_EQ(r, OZAYN_ERR_NULL);
    ozayn_resources_shutdown();
    return 0;
}

/* --- Load Average --- */

TEST(resources_load_average_before_init) {
    double l1 = 999, l5 = 999, l15 = 999;
    ozayn_result_t r = ozayn_resources_get_load_average(&l1, &l5, &l15);
    ASSERT(r != OZAYN_OK);
    ASSERT_EQ(l1, 0.0);
    ASSERT_EQ(l5, 0.0);
    ASSERT_EQ(l15, 0.0);
    return 0;
}

TEST(resources_load_average_values) {
    ozayn_resources_init();
    double l1 = -1, l5 = -1, l15 = -1;
    ozayn_result_t r = ozayn_resources_get_load_average(&l1, &l5, &l15);
    if (r == OZAYN_OK) {
        ASSERT(l1 >= 0.0);
        ASSERT(l5 >= 0.0);
        ASSERT(l15 >= 0.0);
        ASSERT(l1 == l1); /* not NaN */
    }
    ozayn_resources_shutdown();
    return 0;
}

TEST(resources_load_average_partial_null) {
    ozayn_resources_init();
    double l1 = -1;
    ozayn_result_t r = ozayn_resources_get_load_average(&l1, NULL, NULL);
    if (r == OZAYN_OK) {
        ASSERT(l1 >= 0.0);
    }
    ozayn_resources_shutdown();
    return 0;
}

/* --- Full Info Query --- */

TEST(resources_get_info_null) {
    ozayn_resources_init();
    ozayn_result_t r = ozayn_resources_get_info(NULL);
    ASSERT_EQ(r, OZAYN_ERR_NULL);
    ozayn_resources_shutdown();
    return 0;
}

TEST(resources_get_info_before_init) {
    OzaynResourceInfo info;
    memset(&info, 0xFF, sizeof(info));
    ozayn_result_t r = ozayn_resources_get_info(&info);
    ASSERT(r != OZAYN_OK);
    ASSERT_EQ(info.available, 0);
    return 0;
}

TEST(resources_get_info_values) {
    ozayn_resources_init();
    OzaynResourceInfo info;
    memset(&info, 0, sizeof(info));
    ozayn_result_t r = ozayn_resources_get_info(&info);
    if (r == OZAYN_OK) {
        ASSERT_EQ(info.available, 1);
        /* At least memory should be available on any system */
        if (info.memory_usage_available) {
            ASSERT(info.memory_total_bytes > 0);
            ASSERT(info.memory_available_bytes <= info.memory_total_bytes);
            ASSERT(info.memory_used_bytes <= info.memory_total_bytes);
        }
        if (info.cpu_usage_available) {
            ASSERT(info.cpu_usage_percent >= 0.0);
            ASSERT(info.cpu_usage_percent <= 100.0);
        }
        if (info.process_count_available) {
            ASSERT(info.process_count > 0);
        }
    }
    ozayn_resources_shutdown();
    return 0;
}

/* --- Stability Test (multiple queries) --- */

TEST(resources_stability_multiple_queries) {
    ozayn_resources_init();
    for (int i = 0; i < 5; i++) {
        OzaynResourceInfo info;
        memset(&info, 0, sizeof(info));
        ozayn_result_t r = ozayn_resources_get_info(&info);
        ASSERT(r == OZAYN_OK || r == OZAYN_ERR);

        double cpu = -1;
        r = ozayn_resources_get_cpu_usage(&cpu);
        if (r == OZAYN_OK) {
            ASSERT(cpu >= 0.0 && cpu <= 100.0);
        }

        uint64_t total = 0, used = 0, avail = 0;
        r = ozayn_resources_get_memory_usage(&total, &used, &avail);
        if (r == OZAYN_OK) {
            ASSERT(total > 0);
        }

        size_t pcount = 0;
        r = ozayn_resources_get_process_count(&pcount);
        if (r == OZAYN_OK) {
            ASSERT(pcount > 0);
        }

        ozayn_system_sleep_ms(20);
    }
    ozayn_resources_shutdown();
    return 0;
}

/* --- Shutdown --- */

TEST(resources_shutdown_basic) {
    ozayn_resources_init();
    ozayn_resources_shutdown();
    return 0;
}

TEST(resources_shutdown_idempotent) {
    ozayn_resources_init();
    ozayn_resources_shutdown();
    ozayn_resources_shutdown();
    return 0;
}

TEST(resources_shutdown_before_init) {
    ozayn_resources_shutdown();
    return 0;
}

/* --- After Shutdown --- */

TEST(resources_query_after_shutdown) {
    ozayn_resources_init();
    ozayn_resources_shutdown();

    int avail = ozayn_resources_is_available();
    ASSERT_EQ(avail, 0);

    double cpu = -1;
    ozayn_result_t r = ozayn_resources_get_cpu_usage(&cpu);
    ASSERT(r != OZAYN_OK);
    ASSERT_EQ(cpu, 0.0);

    uint64_t total = 999;
    r = ozayn_resources_get_memory_usage(&total, NULL, NULL);
    ASSERT(r != OZAYN_OK);
    ASSERT_EQ(total, 0);

    return 0;
}

/* --- Test Suite --- */

int run_resource_monitoring_tests(void) {
    SUITE_BEGIN("System Resource Monitoring Abstraction (Step 30)");

    /* Lifecycle */
    RUN(resources_init_basic);
    RUN(resources_init_idempotent);

    /* Availability */
    RUN(resources_is_available_before_init);
    RUN(resources_is_available_after_init);

    /* CPU Usage */
    RUN(resources_cpu_usage_null);
    RUN(resources_cpu_usage_before_init);
    RUN(resources_cpu_usage_range);

    /* Memory Usage */
    RUN(resources_memory_usage_before_init);
    RUN(resources_memory_usage_values);
    RUN(resources_memory_usage_partial_null);

    /* Process Count */
    RUN(resources_process_count_before_init);
    RUN(resources_process_count_values);
    RUN(resources_process_count_null);

    /* Load Average */
    RUN(resources_load_average_before_init);
    RUN(resources_load_average_values);
    RUN(resources_load_average_partial_null);

    /* Full Info Query */
    RUN(resources_get_info_null);
    RUN(resources_get_info_before_init);
    RUN(resources_get_info_values);

    /* Stability */
    RUN(resources_stability_multiple_queries);

    /* Shutdown */
    RUN(resources_shutdown_basic);
    RUN(resources_shutdown_idempotent);
    RUN(resources_shutdown_before_init);
    RUN(resources_query_after_shutdown);

    SUITE_END();
    return FAILED();
}
