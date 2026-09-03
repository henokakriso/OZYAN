#include "../../tests/test_framework.h"
#include "platform.h"
#include <stdio.h>
#include <string.h>
#include <math.h>

/*
 * test_sensors.c — Section 02 Step 25: System Hardware Sensors Abstraction Tests.
 *
 * Tests sensor initialization, shutdown, enumeration, type names,
 * and error handling. Read-only — no hardware control.
 */

/* --- Initialization --- */

TEST(sensors_init_basic) {
    ozayn_result_t r = ozayn_sensors_init();
    ASSERT_EQ(r, OZAYN_OK);
    ozayn_sensors_shutdown();
    return 0;
}

TEST(sensors_init_idempotent) {
    ozayn_sensors_init();
    ozayn_result_t r = ozayn_sensors_init();
    ASSERT_EQ(r, OZAYN_OK);
    ozayn_sensors_shutdown();
    return 0;
}

/* --- Availability --- */

TEST(sensors_is_available_before_init) {
    int avail = ozayn_sensors_is_available();
    ASSERT_EQ(avail, 0);
    return 0;
}

TEST(sensors_is_available_after_init) {
    ozayn_sensors_init();
    int avail = ozayn_sensors_is_available();
    ASSERT(avail == 0 || avail == 1);
    ozayn_sensors_shutdown();
    return 0;
}

/* --- Count --- */

TEST(sensors_count_before_init) {
    int count = ozayn_sensors_get_count();
    ASSERT_EQ(count, 0);
    return 0;
}

TEST(sensors_count_after_init) {
    ozayn_sensors_init();
    int count = ozayn_sensors_get_count();
    ASSERT(count >= 0);
    ozayn_sensors_shutdown();
    return 0;
}

/* --- Enumeration --- */

TEST(sensors_get_info_null) {
    ozayn_sensors_init();
    OzaynSensorInfo info;
    ozayn_result_t r = ozayn_sensors_get_info(0, NULL);
    ASSERT_EQ(r, OZAYN_ERR_NULL);
    ozayn_sensors_shutdown();
    return 0;
}

TEST(sensors_get_info_before_init) {
    OzaynSensorInfo info;
    ozayn_result_t r = ozayn_sensors_get_info(0, &info);
    ASSERT(r != OZAYN_OK);
    return 0;
}

TEST(sensors_get_info_negative_index) {
    ozayn_sensors_init();
    if (ozayn_sensors_get_count() <= 0) {
        ozayn_sensors_shutdown();
        return 0;
    }
    OzaynSensorInfo info;
    ozayn_result_t r = ozayn_sensors_get_info(-1, &info);
    ASSERT(r != OZAYN_OK);
    ozayn_sensors_shutdown();
    return 0;
}

TEST(sensors_get_info_index_out_of_range) {
    ozayn_sensors_init();
    if (ozayn_sensors_get_count() <= 0) {
        ozayn_sensors_shutdown();
        return 0;
    }
    int count = ozayn_sensors_get_count();
    OzaynSensorInfo info;
    ozayn_result_t r = ozayn_sensors_get_info(count, &info);
    ASSERT(r != OZAYN_OK);
    r = ozayn_sensors_get_info(count + 100, &info);
    ASSERT(r != OZAYN_OK);
    ozayn_sensors_shutdown();
    return 0;
}

TEST(sensors_get_info_valid) {
    ozayn_sensors_init();
    if (ozayn_sensors_get_count() <= 0) {
        ozayn_sensors_shutdown();
        return 0;
    }

    OzaynSensorInfo info;
    ozayn_result_t r = ozayn_sensors_get_info(0, &info);
    if (r == OZAYN_OK) {
        ASSERT_EQ(info.index, 0);
        ASSERT(info.available == 0 || info.available == 1);
        /* Type must be valid */
        ASSERT(info.type >= OZAYN_SENSOR_UNKNOWN && info.type <= OZAYN_SENSOR_POWER);
        /* If available, value must be finite */
        if (info.available) {
            ASSERT(!isnan(info.value));
            ASSERT(!isinf(info.value));
        }
    }
    ozayn_sensors_shutdown();
    return 0;
}

TEST(sensors_get_info_multiple) {
    ozayn_sensors_init();
    int count = ozayn_sensors_get_count();
    if (count <= 1) {
        ozayn_sensors_shutdown();
        return 0;
    }

    OzaynSensorInfo info_first, info_last;
    ozayn_sensors_get_info(0, &info_first);
    ozayn_sensors_get_info(count - 1, &info_last);

    ASSERT_EQ(info_first.index, 0);
    ASSERT_EQ(info_last.index, count - 1);

    ozayn_sensors_shutdown();
    return 0;
}

/* --- Sensor Type Names --- */

TEST(sensor_type_name_temperature) {
    const char *name = ozayn_sensor_type_name(OZAYN_SENSOR_TEMPERATURE);
    ASSERT(name != NULL);
    ASSERT(strlen(name) > 0);
    return 0;
}

TEST(sensor_type_name_fan) {
    const char *name = ozayn_sensor_type_name(OZAYN_SENSOR_FAN);
    ASSERT(name != NULL);
    ASSERT(strlen(name) > 0);
    return 0;
}

TEST(sensor_type_name_voltage) {
    const char *name = ozayn_sensor_type_name(OZAYN_SENSOR_VOLTAGE);
    ASSERT(name != NULL);
    ASSERT(strlen(name) > 0);
    return 0;
}

TEST(sensor_type_name_current) {
    const char *name = ozayn_sensor_type_name(OZAYN_SENSOR_CURRENT);
    ASSERT(name != NULL);
    ASSERT(strlen(name) > 0);
    return 0;
}

TEST(sensor_type_name_power) {
    const char *name = ozayn_sensor_type_name(OZAYN_SENSOR_POWER);
    ASSERT(name != NULL);
    ASSERT(strlen(name) > 0);
    return 0;
}

TEST(sensor_type_name_unknown) {
    const char *name = ozayn_sensor_type_name(OZAYN_SENSOR_UNKNOWN);
    ASSERT(name != NULL);
    ASSERT(strlen(name) > 0);
    return 0;
}

TEST(sensor_type_name_invalid) {
    const char *name = ozayn_sensor_type_name((OzaynSensorType)9999);
    ASSERT(name != NULL);
    ASSERT(strlen(name) > 0);
    return 0;
}

/* --- Shutdown --- */

TEST(sensors_shutdown_basic) {
    ozayn_sensors_init();
    ozayn_sensors_shutdown();
    return 0;
}

TEST(sensors_shutdown_idempotent) {
    ozayn_sensors_init();
    ozayn_sensors_shutdown();
    ozayn_sensors_shutdown();
    return 0;
}

TEST(sensors_shutdown_before_init) {
    ozayn_sensors_shutdown();
    return 0;
}

/* --- Test Suite --- */

int run_sensors_tests(void) {
    SUITE_BEGIN("System Hardware Sensors Abstraction (Step 25)");

    /* Lifecycle */
    RUN(sensors_init_basic);
    RUN(sensors_init_idempotent);

    /* Availability */
    RUN(sensors_is_available_before_init);
    RUN(sensors_is_available_after_init);

    /* Count */
    RUN(sensors_count_before_init);
    RUN(sensors_count_after_init);

    /* Enumeration */
    RUN(sensors_get_info_null);
    RUN(sensors_get_info_before_init);
    RUN(sensors_get_info_negative_index);
    RUN(sensors_get_info_index_out_of_range);
    RUN(sensors_get_info_valid);
    RUN(sensors_get_info_multiple);

    /* Type Names */
    RUN(sensor_type_name_temperature);
    RUN(sensor_type_name_fan);
    RUN(sensor_type_name_voltage);
    RUN(sensor_type_name_current);
    RUN(sensor_type_name_power);
    RUN(sensor_type_name_unknown);
    RUN(sensor_type_name_invalid);

    /* Shutdown */
    RUN(sensors_shutdown_basic);
    RUN(sensors_shutdown_idempotent);
    RUN(sensors_shutdown_before_init);

    SUITE_END();
    return FAILED();
}
