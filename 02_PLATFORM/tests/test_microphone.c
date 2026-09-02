#include "../../tests/test_framework.h"
#include "platform.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * test_microphone.c — Section 02 Step 10: Microphone Device Abstraction Tests.
 *
 * Tests microphone initialization, shutdown, availability, enumeration,
 * lifecycle transitions, and error handling. Works in headless environments.
 *
 * If no microphone hardware is present, tests verify graceful handling.
 * No physical microphone interaction is required for automated tests.
 */

/* --- Microphone Initialization --- */

TEST(mic_init_basic) {
    ozayn_result_t r = ozayn_microphone_init();
    ASSERT_EQ(r, OZAYN_OK);
    ozayn_microphone_shutdown();
    return 0;
}

TEST(mic_init_idempotent) {
    ozayn_microphone_init();
    ozayn_result_t r = ozayn_microphone_init();
    ASSERT_EQ(r, OZAYN_OK);
    ozayn_microphone_shutdown();
    return 0;
}

/* --- Microphone Availability --- */

TEST(mic_is_available_after_init) {
    ozayn_microphone_init();
    int avail = ozayn_microphone_is_available();
    ASSERT(avail == 0 || avail == 1);
    ozayn_microphone_shutdown();
    return 0;
}

TEST(mic_is_available_before_init) {
    ozayn_microphone_shutdown();
    int avail = ozayn_microphone_is_available();
    ASSERT_EQ(avail, 0);
    return 0;
}

/* --- Device Enumeration --- */

TEST(mic_get_count_before_init) {
    unsigned int count = ozayn_microphone_get_count();
    ASSERT_EQ(count, 0);
    return 0;
}

TEST(mic_get_count_after_init) {
    ozayn_microphone_init();
    unsigned int count = ozayn_microphone_get_count();
    ASSERT(count >= 0u);
    ozayn_microphone_shutdown();
    return 0;
}

TEST(mic_get_info_valid_index) {
    ozayn_microphone_init();
    unsigned int count = ozayn_microphone_get_count();
    if (count > 0) {
        OzaynMicrophoneInfo info;
        ozayn_result_t r = ozayn_microphone_get_info(0, &info);
        ASSERT_EQ(r, OZAYN_OK);
        ASSERT(info.index == 0);
        ASSERT(info.available == 0 || info.available == 1);
        ASSERT(info.channels >= 0);
        ASSERT(info.sample_rate >= 0);
    }
    ozayn_microphone_shutdown();
    return 0;
}

TEST(mic_get_info_invalid_index) {
    ozayn_microphone_init();
    OzaynMicrophoneInfo info;
    ozayn_result_t r = ozayn_microphone_get_info(999, &info);
    ASSERT_EQ(r, OZAYN_ERR);
    ozayn_microphone_shutdown();
    return 0;
}

TEST(mic_get_info_null) {
    ozayn_microphone_init();
    ozayn_result_t r = ozayn_microphone_get_info(0, NULL);
    ASSERT_EQ(r, OZAYN_ERR_NULL);
    ozayn_microphone_shutdown();
    return 0;
}

TEST(mic_get_info_before_init) {
    OzaynMicrophoneInfo info;
    ozayn_result_t r = ozayn_microphone_get_info(0, &info);
    ASSERT_EQ(r, OZAYN_ERR);
    return 0;
}

/* --- Lifecycle Transitions --- */

TEST(mic_open_invalid_index) {
    ozayn_microphone_init();
    ozayn_result_t r = ozayn_microphone_open(999);
    ASSERT_EQ(r, OZAYN_ERR);
    ozayn_microphone_shutdown();
    return 0;
}

TEST(mic_open_before_init) {
    ozayn_result_t r = ozayn_microphone_open(0);
    ASSERT_EQ(r, OZAYN_ERR);
    return 0;
}

TEST(mic_start_before_open) {
    ozayn_microphone_init();
    ozayn_result_t r = ozayn_microphone_start();
    ASSERT_EQ(r, OZAYN_ERR_STATE);
    ozayn_microphone_shutdown();
    return 0;
}

TEST(mic_stop_before_start) {
    ozayn_microphone_init();
    ozayn_result_t r = ozayn_microphone_stop();
    ASSERT_EQ(r, OZAYN_ERR_STATE);
    ozayn_microphone_shutdown();
    return 0;
}

TEST(mic_capture_before_open) {
    ozayn_microphone_init();
    OzaynAudioBuffer buffer;
    ozayn_result_t r = ozayn_microphone_capture(&buffer);
    ASSERT_EQ(r, OZAYN_ERR_STATE);
    ozayn_microphone_shutdown();
    return 0;
}

TEST(mic_capture_null) {
    ozayn_microphone_init();
    ozayn_result_t r = ozayn_microphone_capture(NULL);
    ASSERT_EQ(r, OZAYN_ERR_NULL);
    ozayn_microphone_shutdown();
    return 0;
}

TEST(mic_capture_before_init) {
    OzaynAudioBuffer buffer;
    ozayn_result_t r = ozayn_microphone_capture(&buffer);
    ASSERT_EQ(r, OZAYN_ERR);
    return 0;
}

TEST(mic_close_before_open) {
    ozayn_microphone_init();
    ozayn_result_t r = ozayn_microphone_close();
    ASSERT_EQ(r, OZAYN_ERR_STATE);
    ozayn_microphone_shutdown();
    return 0;
}

TEST(mic_close_before_init) {
    ozayn_result_t r = ozayn_microphone_close();
    ASSERT_EQ(r, OZAYN_ERR);
    return 0;
}

/* --- Buffer Management --- */

TEST(mic_buffer_release_null) {
    ozayn_microphone_buffer_release(NULL);
    return 0;
}

TEST(mic_buffer_release_clears) {
    OzaynAudioBuffer buffer;
    memset(&buffer, 0xFF, sizeof(buffer));
    buffer.data = (unsigned char *)malloc(64);
    ASSERT_NOT_NULL(buffer.data);
    ozayn_microphone_buffer_release(&buffer);
    ASSERT_NULL(buffer.data);
    ASSERT_EQ(buffer.data_size, 0);
    ASSERT_EQ(buffer.frame_count, 0);
    ASSERT_EQ(buffer.sample_rate, 0u);
    ASSERT_EQ(buffer.channels, 0u);
    ASSERT_EQ(buffer.format, OZAYN_AUDIO_FORMAT_UNKNOWN);
    return 0;
}

TEST(mic_buffer_release_empty) {
    OzaynAudioBuffer buffer;
    memset(&buffer, 0, sizeof(buffer));
    ozayn_microphone_buffer_release(&buffer);
    ASSERT_NULL(buffer.data);
    return 0;
}

/* --- Microphone Shutdown --- */

TEST(mic_shutdown_basic) {
    ozayn_microphone_init();
    ozayn_microphone_shutdown();
    ASSERT_EQ(ozayn_microphone_is_available(), 0);
    return 0;
}

TEST(mic_shutdown_idempotent) {
    ozayn_microphone_init();
    ozayn_microphone_shutdown();
    ozayn_microphone_shutdown();
    ASSERT_EQ(ozayn_microphone_is_available(), 0);
    return 0;
}

TEST(mic_shutdown_before_init) {
    ozayn_microphone_shutdown();
    ASSERT_EQ(ozayn_microphone_is_available(), 0);
    return 0;
}

/* --- Audio Format Constants --- */

TEST(mic_audio_format_constants) {
    ASSERT_EQ(OZAYN_AUDIO_FORMAT_UNKNOWN, 0);
    ASSERT(OZAYN_AUDIO_FORMAT_S16 > 0);
    ASSERT(OZAYN_AUDIO_FORMAT_F32 > 0);
    return 0;
}

int run_microphone_tests(void) {
    SUITE_BEGIN("Microphone Device Abstraction (Section 02)");
    RUN(mic_init_basic);
    RUN(mic_init_idempotent);
    RUN(mic_is_available_after_init);
    RUN(mic_is_available_before_init);
    RUN(mic_get_count_before_init);
    RUN(mic_get_count_after_init);
    RUN(mic_get_info_valid_index);
    RUN(mic_get_info_invalid_index);
    RUN(mic_get_info_null);
    RUN(mic_get_info_before_init);
    RUN(mic_open_invalid_index);
    RUN(mic_open_before_init);
    RUN(mic_start_before_open);
    RUN(mic_stop_before_start);
    RUN(mic_capture_before_open);
    RUN(mic_capture_null);
    RUN(mic_capture_before_init);
    RUN(mic_close_before_open);
    RUN(mic_close_before_init);
    RUN(mic_buffer_release_null);
    RUN(mic_buffer_release_clears);
    RUN(mic_buffer_release_empty);
    RUN(mic_shutdown_basic);
    RUN(mic_shutdown_idempotent);
    RUN(mic_shutdown_before_init);
    RUN(mic_audio_format_constants);
    SUITE_END();
    return _tf_suite_fail;
}
