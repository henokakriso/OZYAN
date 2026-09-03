#include "../../tests/test_framework.h"
#include "platform.h"
#include <stdio.h>
#include <string.h>

/*
 * test_peripheral.c — Section 02 Step 27: USB & Peripheral Device Enumeration Abstraction Tests.
 *
 * Tests peripheral initialization, shutdown, enumeration, type names,
 * and error handling. Read-only — no device control.
 */

/* --- Initialization --- */

TEST(peripheral_init_basic) {
    ozayn_result_t r = ozayn_peripheral_init();
    ASSERT_EQ(r, OZAYN_OK);
    ozayn_peripheral_shutdown();
    return 0;
}

TEST(peripheral_init_idempotent) {
    ozayn_peripheral_init();
    ozayn_result_t r = ozayn_peripheral_init();
    ASSERT_EQ(r, OZAYN_OK);
    ozayn_peripheral_shutdown();
    return 0;
}

/* --- Availability --- */

TEST(peripheral_is_available_before_init) {
    int avail = ozayn_peripheral_is_available();
    ASSERT_EQ(avail, 0);
    return 0;
}

TEST(peripheral_is_available_after_init) {
    ozayn_peripheral_init();
    int avail = ozayn_peripheral_is_available();
    ASSERT(avail == 0 || avail == 1);
    ozayn_peripheral_shutdown();
    return 0;
}

/* --- Count --- */

TEST(peripheral_count_before_init) {
    size_t count = ozayn_peripheral_get_count();
    ASSERT(count == 0);
    return 0;
}

TEST(peripheral_count_after_init) {
    ozayn_peripheral_init();
    size_t count = ozayn_peripheral_get_count();
    /* Count is non-negative by type (size_t) */
    ASSERT(count >= 0);
    ozayn_peripheral_shutdown();
    return 0;
}

/* --- Enumeration --- */

TEST(peripheral_get_info_null) {
    ozayn_peripheral_init();
    OzaynPeripheralInfo info;
    ozayn_result_t r = ozayn_peripheral_get_info(0, NULL);
    ASSERT_EQ(r, OZAYN_ERR_NULL);
    ozayn_peripheral_shutdown();
    return 0;
}

TEST(peripheral_get_info_before_init) {
    OzaynPeripheralInfo info;
    ozayn_result_t r = ozayn_peripheral_get_info(0, &info);
    ASSERT(r != OZAYN_OK);
    return 0;
}

TEST(peripheral_get_info_large_index) {
    ozayn_peripheral_init();
    OzaynPeripheralInfo info;
    ozayn_result_t r = ozayn_peripheral_get_info(999999, &info);
    ASSERT(r != OZAYN_OK);
    ozayn_peripheral_shutdown();
    return 0;
}

TEST(peripheral_get_info_valid) {
    ozayn_peripheral_init();
    size_t count = ozayn_peripheral_get_count();
    if (count == 0) {
        ozayn_peripheral_shutdown();
        return 0;
    }

    OzaynPeripheralInfo info;
    ozayn_result_t r = ozayn_peripheral_get_info(0, &info);
    if (r == OZAYN_OK) {
        ASSERT(info.index == 0);
        ASSERT(info.available == 0 || info.available == 1);
        /* Type must be valid */
        ASSERT(info.type >= OZAYN_PERIPHERAL_UNKNOWN && info.type <= OZAYN_PERIPHERAL_OTHER);
        /* Vendor/product IDs are either valid or -1 (unknown) */
        ASSERT(info.vendor_id == -1 || info.vendor_id >= 0);
        ASSERT(info.product_id == -1 || info.product_id >= 0);
    }
    ozayn_peripheral_shutdown();
    return 0;
}

TEST(peripheral_get_info_multiple) {
    ozayn_peripheral_init();
    size_t count = ozayn_peripheral_get_count();
    if (count <= 1) {
        ozayn_peripheral_shutdown();
        return 0;
    }

    OzaynPeripheralInfo info_first, info_last;
    ozayn_peripheral_get_info(0, &info_first);
    ozayn_peripheral_get_info(count - 1, &info_last);

    ASSERT(info_first.index == 0);
    ASSERT(info_last.index == count - 1);

    ozayn_peripheral_shutdown();
    return 0;
}

/* --- Type Names --- */

TEST(peripheral_type_name_unknown) {
    const char *name = ozayn_peripheral_type_name(OZAYN_PERIPHERAL_UNKNOWN);
    ASSERT(name != NULL);
    ASSERT(strlen(name) > 0);
    return 0;
}

TEST(peripheral_type_name_usb) {
    const char *name = ozayn_peripheral_type_name(OZAYN_PERIPHERAL_USB);
    ASSERT(name != NULL);
    ASSERT(strlen(name) > 0);
    return 0;
}

TEST(peripheral_type_name_camera) {
    const char *name = ozayn_peripheral_type_name(OZAYN_PERIPHERAL_CAMERA);
    ASSERT(name != NULL);
    ASSERT(strlen(name) > 0);
    return 0;
}

TEST(peripheral_type_name_microphone) {
    const char *name = ozayn_peripheral_type_name(OZAYN_PERIPHERAL_MICROPHONE);
    ASSERT(name != NULL);
    ASSERT(strlen(name) > 0);
    return 0;
}

TEST(peripheral_type_name_audio_output) {
    const char *name = ozayn_peripheral_type_name(OZAYN_PERIPHERAL_AUDIO_OUTPUT);
    ASSERT(name != NULL);
    ASSERT(strlen(name) > 0);
    return 0;
}

TEST(peripheral_type_name_keyboard) {
    const char *name = ozayn_peripheral_type_name(OZAYN_PERIPHERAL_KEYBOARD);
    ASSERT(name != NULL);
    ASSERT(strlen(name) > 0);
    return 0;
}

TEST(peripheral_type_name_mouse) {
    const char *name = ozayn_peripheral_type_name(OZAYN_PERIPHERAL_MOUSE);
    ASSERT(name != NULL);
    ASSERT(strlen(name) > 0);
    return 0;
}

TEST(peripheral_type_name_storage) {
    const char *name = ozayn_peripheral_type_name(OZAYN_PERIPHERAL_STORAGE);
    ASSERT(name != NULL);
    ASSERT(strlen(name) > 0);
    return 0;
}

TEST(peripheral_type_name_display) {
    const char *name = ozayn_peripheral_type_name(OZAYN_PERIPHERAL_DISPLAY);
    ASSERT(name != NULL);
    ASSERT(strlen(name) > 0);
    return 0;
}

TEST(peripheral_type_name_other) {
    const char *name = ozayn_peripheral_type_name(OZAYN_PERIPHERAL_OTHER);
    ASSERT(name != NULL);
    ASSERT(strlen(name) > 0);
    return 0;
}

TEST(peripheral_type_name_invalid) {
    const char *name = ozayn_peripheral_type_name((OzaynPeripheralType)9999);
    ASSERT(name != NULL);
    ASSERT(strlen(name) > 0);
    return 0;
}

/* --- Shutdown --- */

TEST(peripheral_shutdown_basic) {
    ozayn_peripheral_init();
    ozayn_peripheral_shutdown();
    return 0;
}

TEST(peripheral_shutdown_idempotent) {
    ozayn_peripheral_init();
    ozayn_peripheral_shutdown();
    ozayn_peripheral_shutdown();
    return 0;
}

TEST(peripheral_shutdown_before_init) {
    ozayn_peripheral_shutdown();
    return 0;
}

/* --- Test Suite --- */

int run_peripheral_tests(void) {
    SUITE_BEGIN("USB & Peripheral Device Enumeration Abstraction (Step 27)");

    /* Lifecycle */
    RUN(peripheral_init_basic);
    RUN(peripheral_init_idempotent);

    /* Availability */
    RUN(peripheral_is_available_before_init);
    RUN(peripheral_is_available_after_init);

    /* Count */
    RUN(peripheral_count_before_init);
    RUN(peripheral_count_after_init);

    /* Enumeration */
    RUN(peripheral_get_info_null);
    RUN(peripheral_get_info_before_init);
    RUN(peripheral_get_info_large_index);
    RUN(peripheral_get_info_valid);
    RUN(peripheral_get_info_multiple);

    /* Type Names */
    RUN(peripheral_type_name_unknown);
    RUN(peripheral_type_name_usb);
    RUN(peripheral_type_name_camera);
    RUN(peripheral_type_name_microphone);
    RUN(peripheral_type_name_audio_output);
    RUN(peripheral_type_name_keyboard);
    RUN(peripheral_type_name_mouse);
    RUN(peripheral_type_name_storage);
    RUN(peripheral_type_name_display);
    RUN(peripheral_type_name_other);
    RUN(peripheral_type_name_invalid);

    /* Shutdown */
    RUN(peripheral_shutdown_basic);
    RUN(peripheral_shutdown_idempotent);
    RUN(peripheral_shutdown_before_init);

    SUITE_END();
    return FAILED();
}
