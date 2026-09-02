#include "../../tests/test_framework.h"
#include "platform.h"
#include <stdio.h>
#include <string.h>

/*
 * test_audio_output.c — Section 02 Step 11: Audio Output / Speaker Abstraction Tests.
 *
 * Tests audio output initialization, shutdown, availability, enumeration,
 * lifecycle transitions, and error handling. Works in headless environments.
 *
 * If no audio output device is present, tests verify graceful handling.
 * No physical audio playback is required for automated tests.
 */

/* --- Audio Output Initialization --- */

TEST(speaker_init_basic) {
    ozayn_result_t r = ozayn_audio_output_init();
    ASSERT_EQ(r, OZAYN_OK);
    ozayn_audio_output_shutdown();
    return 0;
}

TEST(speaker_init_idempotent) {
    ozayn_audio_output_init();
    ozayn_result_t r = ozayn_audio_output_init();
    ASSERT_EQ(r, OZAYN_OK);
    ozayn_audio_output_shutdown();
    return 0;
}

/* --- Audio Output Availability --- */

TEST(speaker_is_available_after_init) {
    ozayn_audio_output_init();
    int avail = ozayn_audio_output_is_available();
    ASSERT(avail == 0 || avail == 1);
    ozayn_audio_output_shutdown();
    return 0;
}

TEST(speaker_is_available_before_init) {
    int avail = ozayn_audio_output_is_available();
    ASSERT(avail == 0);
    return 0;
}

/* --- Audio Output Enumeration --- */

TEST(speaker_get_count_before_init) {
    unsigned int count = ozayn_audio_output_get_count();
    ASSERT_EQ(count, 0u);
    return 0;
}

TEST(speaker_get_count_after_init) {
    ozayn_audio_output_init();
    unsigned int count = ozayn_audio_output_get_count();
    ASSERT(count >= 0u);
    ozayn_audio_output_shutdown();
    return 0;
}

TEST(speaker_get_info_valid_index) {
    ozayn_audio_output_init();
    unsigned int count = ozayn_audio_output_get_count();
    if (count > 0) {
        OzaynAudioOutputInfo info;
        ozayn_result_t r = ozayn_audio_output_get_info(0, &info);
        ASSERT_EQ(r, OZAYN_OK);
    }
    ozayn_audio_output_shutdown();
    return 0;
}

TEST(speaker_get_info_invalid_index) {
    ozayn_audio_output_init();
    OzaynAudioOutputInfo info;
    ozayn_result_t r = ozayn_audio_output_get_info(999, &info);
    ASSERT(r != OZAYN_OK);
    ozayn_audio_output_shutdown();
    return 0;
}

TEST(speaker_get_info_null) {
    ozayn_audio_output_init();
    ozayn_result_t r = ozayn_audio_output_get_info(0, NULL);
    ASSERT_EQ(r, OZAYN_ERR_NULL);
    ozayn_audio_output_shutdown();
    return 0;
}

TEST(speaker_get_info_before_init) {
    OzaynAudioOutputInfo info;
    ozayn_result_t r = ozayn_audio_output_get_info(0, &info);
    ASSERT(r != OZAYN_OK);
    return 0;
}

/* --- Lifecycle Transitions --- */

TEST(speaker_open_invalid_index) {
    ozayn_audio_output_init();
    ozayn_result_t r = ozayn_audio_output_open(999);
    ASSERT(r != OZAYN_OK);
    ozayn_audio_output_shutdown();
    return 0;
}

TEST(speaker_open_before_init) {
    ozayn_result_t r = ozayn_audio_output_open(0);
    ASSERT(r != OZAYN_OK);
    return 0;
}

TEST(speaker_start_before_open) {
    ozayn_audio_output_init();
    ozayn_result_t r = ozayn_audio_output_start();
    ASSERT(r != OZAYN_OK);
    ozayn_audio_output_shutdown();
    return 0;
}

TEST(speaker_stop_before_start) {
    ozayn_audio_output_init();
    ozayn_result_t r = ozayn_audio_output_stop();
    ASSERT(r != OZAYN_OK);
    ozayn_audio_output_shutdown();
    return 0;
}

TEST(speaker_write_before_open) {
    ozayn_audio_output_init();
    OzaynAudioOutputBuffer buf = {0};
    buf.sample_rate = 44100;
    buf.channels = 2;
    buf.format = OZAYN_AUDIO_FORMAT_S16;
    buf.frame_count = 4;
    buf.data_size = 4 * 2 * 2;
    ozayn_result_t r = ozayn_audio_output_write(&buf);
    ASSERT(r != OZAYN_OK);
    ozayn_audio_output_shutdown();
    return 0;
}

TEST(speaker_write_null) {
    ozayn_audio_output_init();
    ozayn_result_t r = ozayn_audio_output_write(NULL);
    ASSERT_EQ(r, OZAYN_ERR_NULL);
    ozayn_audio_output_shutdown();
    return 0;
}

TEST(speaker_write_before_init) {
    OzaynAudioOutputBuffer buf = {0};
    ozayn_result_t r = ozayn_audio_output_write(&buf);
    ASSERT(r != OZAYN_OK);
    return 0;
}

TEST(speaker_close_before_open) {
    ozayn_audio_output_init();
    ozayn_result_t r = ozayn_audio_output_close();
    ASSERT(r != OZAYN_OK);
    ozayn_audio_output_shutdown();
    return 0;
}

TEST(speaker_close_before_init) {
    ozayn_result_t r = ozayn_audio_output_close();
    ASSERT(r != OZAYN_OK);
    return 0;
}

/* --- Audio Output Shutdown --- */

TEST(speaker_shutdown_basic) {
    ozayn_audio_output_init();
    ozayn_audio_output_shutdown();
    return 0;
}

TEST(speaker_shutdown_idempotent) {
    ozayn_audio_output_init();
    ozayn_audio_output_shutdown();
    ozayn_audio_output_shutdown();
    return 0;
}

TEST(speaker_shutdown_before_init) {
    ozayn_audio_output_shutdown();
    return 0;
}

/* --- Audio Format Constants --- */

TEST(speaker_audio_format_constants) {
    ASSERT_EQ(OZAYN_AUDIO_FORMAT_UNKNOWN, 0);
    ASSERT(OZAYN_AUDIO_FORMAT_S16 != OZAYN_AUDIO_FORMAT_UNKNOWN);
    ASSERT(OZAYN_AUDIO_FORMAT_F32 != OZAYN_AUDIO_FORMAT_UNKNOWN);
    ASSERT(OZAYN_AUDIO_FORMAT_S16 != OZAYN_AUDIO_FORMAT_F32);
    return 0;
}

/* --- Audio Output Buffer Validation --- */

TEST(speaker_write_empty_buffer) {
    ozayn_audio_output_init();
    OzaynAudioOutputBuffer buf = {0};
    buf.sample_rate = 44100;
    buf.channels = 2;
    buf.format = OZAYN_AUDIO_FORMAT_S16;
    buf.frame_count = 0;
    buf.data = NULL;
    buf.data_size = 0;
    ozayn_result_t r = ozayn_audio_output_write(&buf);
    ASSERT(r != OZAYN_OK);
    ozayn_audio_output_shutdown();
    return 0;
}

TEST(speaker_write_no_data) {
    ozayn_audio_output_init();
    OzaynAudioOutputBuffer buf = {0};
    buf.sample_rate = 44100;
    buf.channels = 2;
    buf.format = OZAYN_AUDIO_FORMAT_S16;
    buf.frame_count = 4;
    buf.data = NULL;
    buf.data_size = 0;
    ozayn_result_t r = ozayn_audio_output_write(&buf);
    ASSERT(r != OZAYN_OK);
    ozayn_audio_output_shutdown();
    return 0;
}

TEST(speaker_write_unknown_format) {
    ozayn_audio_output_init();
    unsigned char data[16] = {0};
    OzaynAudioOutputBuffer buf = {0};
    buf.sample_rate = 44100;
    buf.channels = 2;
    buf.format = OZAYN_AUDIO_FORMAT_UNKNOWN;
    buf.frame_count = 4;
    buf.data = data;
    buf.data_size = 16;
    ozayn_result_t r = ozayn_audio_output_write(&buf);
    ASSERT(r != OZAYN_OK);
    ozayn_audio_output_shutdown();
    return 0;
}

TEST(speaker_write_insufficient_data) {
    ozayn_audio_output_init();
    unsigned char data[8] = {0};
    OzaynAudioOutputBuffer buf = {0};
    buf.sample_rate = 44100;
    buf.channels = 2;
    buf.format = OZAYN_AUDIO_FORMAT_S16;
    buf.frame_count = 4;
    buf.data = data;
    buf.data_size = 8;
    ozayn_result_t r = ozayn_audio_output_write(&buf);
    ASSERT(r != OZAYN_OK);
    ozayn_audio_output_shutdown();
    return 0;
}

/* --- Test Suite --- */

int run_audio_output_tests(void) {
    int failed = 0;
    SUITE_BEGIN("Audio Output Device Abstraction (Section 02)");

    RUN(speaker_init_basic);
    RUN(speaker_init_idempotent);
    RUN(speaker_is_available_after_init);
    RUN(speaker_is_available_before_init);
    RUN(speaker_get_count_before_init);
    RUN(speaker_get_count_after_init);
    RUN(speaker_get_info_valid_index);
    RUN(speaker_get_info_invalid_index);
    RUN(speaker_get_info_null);
    RUN(speaker_get_info_before_init);
    RUN(speaker_open_invalid_index);
    RUN(speaker_open_before_init);
    RUN(speaker_start_before_open);
    RUN(speaker_stop_before_start);
    RUN(speaker_write_before_open);
    RUN(speaker_write_null);
    RUN(speaker_write_before_init);
    RUN(speaker_close_before_open);
    RUN(speaker_close_before_init);
    RUN(speaker_shutdown_basic);
    RUN(speaker_shutdown_idempotent);
    RUN(speaker_shutdown_before_init);
    RUN(speaker_audio_format_constants);
    RUN(speaker_write_empty_buffer);
    RUN(speaker_write_no_data);
    RUN(speaker_write_unknown_format);
    RUN(speaker_write_insufficient_data);

    SUITE_END();
    return FAILED();
}
