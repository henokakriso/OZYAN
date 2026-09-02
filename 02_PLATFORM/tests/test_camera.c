#include "../../tests/test_framework.h"
#include "platform.h"
#include <stdio.h>
#include <string.h>

/*
 * test_camera.c — Section 02 Step 09: Camera Device Abstraction Tests.
 *
 * Tests camera initialization, shutdown, availability, enumeration,
 * lifecycle transitions, and error handling. Works in headless environments.
 *
 * If no camera hardware is present, tests verify graceful handling.
 * No physical camera interaction is required for automated tests.
 */

/* --- Camera Initialization --- */

TEST(camera_init_basic) {
    ozayn_result_t r = ozayn_camera_init();
    ASSERT_EQ(r, OZAYN_OK);
    ozayn_camera_shutdown();
    return 0;
}

TEST(camera_init_idempotent) {
    ozayn_camera_init();
    ozayn_result_t r = ozayn_camera_init();
    ASSERT_EQ(r, OZAYN_OK);
    ozayn_camera_shutdown();
    return 0;
}

/* --- Camera Availability --- */

TEST(camera_is_available_after_init) {
    ozayn_camera_init();
    int avail = ozayn_camera_is_available();
    ASSERT(avail == 0 || avail == 1);
    ozayn_camera_shutdown();
    return 0;
}

TEST(camera_is_available_before_init) {
    ozayn_camera_shutdown();
    int avail = ozayn_camera_is_available();
    ASSERT_EQ(avail, 0);
    return 0;
}

/* --- Device Enumeration --- */

TEST(camera_get_count_before_init) {
    unsigned int count = ozayn_camera_get_count();
    ASSERT_EQ(count, 0);
    return 0;
}

TEST(camera_get_count_after_init) {
    ozayn_camera_init();
    unsigned int count = ozayn_camera_get_count();
    /* Count may be 0 (no camera) or >0 — both valid */
    ASSERT(count >= 0);
    ozayn_camera_shutdown();
    return 0;
}

TEST(camera_get_info_valid_index) {
    ozayn_camera_init();
    unsigned int count = ozayn_camera_get_count();
    if (count > 0) {
        OzaynCameraInfo info;
        ozayn_result_t r = ozayn_camera_get_info(0, &info);
        ASSERT_EQ(r, OZAYN_OK);
        ASSERT(info.index == 0);
        ASSERT(info.available == 0 || info.available == 1);
    }
    ozayn_camera_shutdown();
    return 0;
}

TEST(camera_get_info_invalid_index) {
    ozayn_camera_init();
    OzaynCameraInfo info;
    ozayn_result_t r = ozayn_camera_get_info(999, &info);
    ASSERT_EQ(r, OZAYN_ERR);
    ozayn_camera_shutdown();
    return 0;
}

TEST(camera_get_info_null) {
    ozayn_camera_init();
    ozayn_result_t r = ozayn_camera_get_info(0, NULL);
    ASSERT_EQ(r, OZAYN_ERR_NULL);
    ozayn_camera_shutdown();
    return 0;
}

TEST(camera_get_info_before_init) {
    OzaynCameraInfo info;
    ozayn_result_t r = ozayn_camera_get_info(0, &info);
    ASSERT_EQ(r, OZAYN_ERR);
    return 0;
}

/* --- Lifecycle Transitions --- */

TEST(camera_open_invalid_index) {
    ozayn_camera_init();
    ozayn_result_t r = ozayn_camera_open(999);
    ASSERT_EQ(r, OZAYN_ERR);
    ozayn_camera_shutdown();
    return 0;
}

TEST(camera_open_before_init) {
    ozayn_result_t r = ozayn_camera_open(0);
    ASSERT_EQ(r, OZAYN_ERR);
    return 0;
}

TEST(camera_start_before_open) {
    ozayn_camera_init();
    ozayn_result_t r = ozayn_camera_start();
    ASSERT_EQ(r, OZAYN_ERR_STATE);
    ozayn_camera_shutdown();
    return 0;
}

TEST(camera_stop_before_start) {
    ozayn_camera_init();
    ozayn_result_t r = ozayn_camera_stop();
    ASSERT_EQ(r, OZAYN_ERR_STATE);
    ozayn_camera_shutdown();
    return 0;
}

TEST(camera_capture_before_open) {
    ozayn_camera_init();
    OzaynCameraFrame frame;
    ozayn_result_t r = ozayn_camera_capture(&frame);
    ASSERT_EQ(r, OZAYN_ERR_STATE);
    ozayn_camera_shutdown();
    return 0;
}

TEST(camera_capture_null) {
    ozayn_camera_init();
    ozayn_result_t r = ozayn_camera_capture(NULL);
    ASSERT_EQ(r, OZAYN_ERR_NULL);
    ozayn_camera_shutdown();
    return 0;
}

TEST(camera_capture_before_init) {
    OzaynCameraFrame frame;
    ozayn_result_t r = ozayn_camera_capture(&frame);
    ASSERT_EQ(r, OZAYN_ERR);
    return 0;
}

TEST(camera_close_before_open) {
    ozayn_camera_init();
    ozayn_result_t r = ozayn_camera_close();
    ASSERT_EQ(r, OZAYN_ERR_STATE);
    ozayn_camera_shutdown();
    return 0;
}

TEST(camera_close_before_init) {
    ozayn_result_t r = ozayn_camera_close();
    ASSERT_EQ(r, OZAYN_ERR);
    return 0;
}

/* --- Configuration --- */

TEST(camera_set_resolution_before_init) {
    ozayn_result_t r = ozayn_camera_set_resolution(640, 480);
    ASSERT_EQ(r, OZAYN_ERR);
    return 0;
}

TEST(camera_set_fps_before_init) {
    ozayn_result_t r = ozayn_camera_set_fps(30);
    ASSERT_EQ(r, OZAYN_ERR);
    return 0;
}

TEST(camera_set_resolution_zero) {
    ozayn_camera_init();
    ozayn_result_t r = ozayn_camera_set_resolution(0, 0);
    ASSERT(r == OZAYN_ERR || r == OZAYN_ERR_STATE);
    ozayn_camera_shutdown();
    return 0;
}

TEST(camera_set_fps_zero) {
    ozayn_camera_init();
    ozayn_result_t r = ozayn_camera_set_fps(0);
    ASSERT(r == OZAYN_ERR || r == OZAYN_ERR_STATE);
    ozayn_camera_shutdown();
    return 0;
}

/* --- Frame Release --- */

TEST(camera_frame_release_null) {
    ozayn_camera_frame_release(NULL);
    return 0;
}

TEST(camera_frame_release_clears) {
    OzaynCameraFrame frame;
    memset(&frame, 0xFF, sizeof(frame));
    ozayn_camera_frame_release(&frame);
    ASSERT_NULL(frame.data);
    ASSERT_EQ(frame.data_size, 0);
    ASSERT_EQ(frame.width, 0u);
    ASSERT_EQ(frame.height, 0u);
    ASSERT_EQ(frame.stride, 0u);
    ASSERT_EQ(frame.format, OZAYN_PIXEL_FORMAT_UNKNOWN);
    return 0;
}

/* --- Camera Shutdown --- */

TEST(camera_shutdown_basic) {
    ozayn_camera_init();
    ozayn_camera_shutdown();
    ASSERT_EQ(ozayn_camera_is_available(), 0);
    return 0;
}

TEST(camera_shutdown_idempotent) {
    ozayn_camera_init();
    ozayn_camera_shutdown();
    ozayn_camera_shutdown();
    ASSERT_EQ(ozayn_camera_is_available(), 0);
    return 0;
}

TEST(camera_shutdown_before_init) {
    ozayn_camera_shutdown();
    ASSERT_EQ(ozayn_camera_is_available(), 0);
    return 0;
}

/* --- Pixel Format Constants --- */

TEST(camera_pixel_format_constants) {
    ASSERT_EQ(OZAYN_PIXEL_FORMAT_UNKNOWN, 0);
    ASSERT(OZAYN_PIXEL_FORMAT_RGB24 > 0);
    ASSERT(OZAYN_PIXEL_FORMAT_BGR24 > 0);
    ASSERT(OZAYN_PIXEL_FORMAT_GRAY8 > 0);
    ASSERT(OZAYN_PIXEL_FORMAT_YUYV > 0);
    ASSERT(OZAYN_PIXEL_FORMAT_MJPEG > 0);
    return 0;
}

int run_camera_tests(void) {
    SUITE_BEGIN("Camera Device Abstraction (Section 02)");
    RUN(camera_init_basic);
    RUN(camera_init_idempotent);
    RUN(camera_is_available_after_init);
    RUN(camera_is_available_before_init);
    RUN(camera_get_count_before_init);
    RUN(camera_get_count_after_init);
    RUN(camera_get_info_valid_index);
    RUN(camera_get_info_invalid_index);
    RUN(camera_get_info_null);
    RUN(camera_get_info_before_init);
    RUN(camera_open_invalid_index);
    RUN(camera_open_before_init);
    RUN(camera_start_before_open);
    RUN(camera_stop_before_start);
    RUN(camera_capture_before_open);
    RUN(camera_capture_null);
    RUN(camera_capture_before_init);
    RUN(camera_close_before_open);
    RUN(camera_close_before_init);
    RUN(camera_set_resolution_before_init);
    RUN(camera_set_fps_before_init);
    RUN(camera_set_resolution_zero);
    RUN(camera_set_fps_zero);
    RUN(camera_frame_release_null);
    RUN(camera_frame_release_clears);
    RUN(camera_shutdown_basic);
    RUN(camera_shutdown_idempotent);
    RUN(camera_shutdown_before_init);
    RUN(camera_pixel_format_constants);
    SUITE_END();
    return _tf_suite_fail;
}
