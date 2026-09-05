#include "../../tests/test_framework.h"
#include "../common/platform_capabilities.h"
#include <stdio.h>
#include <string.h>

/*
 * test_platform_capabilities.c — Section 02 Step 35: Platform Capability Registry Tests.
 *
 * Tests initialization, shutdown, enumeration, name mapping, state mapping,
 * query, availability, and error handling. Read-only — no system modification.
 */

/* ---- Initialization ---- */

TEST(cap_init_basic) {
    int r = ozayn_platform_capabilities_init();
    ASSERT_EQ(r, 1);
    ozayn_platform_capabilities_shutdown();
    return 0;
}

TEST(cap_init_idempotent) {
    ozayn_platform_capabilities_init();
    int r = ozayn_platform_capabilities_init();
    ASSERT_EQ(r, 1);
    ozayn_platform_capabilities_shutdown();
    return 0;
}

/* ---- Availability (registry state) ---- */

TEST(cap_is_available_before_init) {
    int avail = ozayn_platform_capabilities_is_available();
    ASSERT_EQ(avail, 0);
    return 0;
}

TEST(cap_is_available_after_init) {
    ozayn_platform_capabilities_init();
    int avail = ozayn_platform_capabilities_is_available();
    ASSERT_EQ(avail, 1);
    ozayn_platform_capabilities_shutdown();
    return 0;
}

/* ---- Count ---- */

TEST(cap_count_before_init) {
    int count = ozayn_platform_capabilities_get_count();
    ASSERT_EQ(count, 0);
    return 0;
}

TEST(cap_count_matches_expected) {
    ozayn_platform_capabilities_init();
    int count = ozayn_platform_capabilities_get_count();
    ASSERT_EQ(count, OZAYN_CAPABILITY_COUNT);
    ASSERT_EQ(count, 33);
    ozayn_platform_capabilities_shutdown();
    return 0;
}

/* ---- Shutdown ---- */

TEST(cap_shutdown_basic) {
    ozayn_platform_capabilities_init();
    ozayn_platform_capabilities_shutdown();
    return 0;
}

TEST(cap_shutdown_idempotent) {
    ozayn_platform_capabilities_init();
    ozayn_platform_capabilities_shutdown();
    ozayn_platform_capabilities_shutdown();
    return 0;
}

TEST(cap_shutdown_before_init) {
    ozayn_platform_capabilities_shutdown();
    return 0;
}

/* ---- Re-init after shutdown ---- */

TEST(cap_reinit_after_shutdown) {
    ozayn_platform_capabilities_init();
    ozayn_platform_capabilities_shutdown();
    int r = ozayn_platform_capabilities_init();
    ASSERT_EQ(r, 1);
    ASSERT_EQ(ozayn_platform_capabilities_get_count(), OZAYN_CAPABILITY_COUNT);
    ozayn_platform_capabilities_shutdown();
    return 0;
}

/* ---- Capability Names ---- */

TEST(cap_name_platform) {
    const char *name = ozayn_platform_capability_name(OZAYN_CAPABILITY_PLATFORM);
    ASSERT(name != NULL);
    ASSERT(strcmp(name, "platform") == 0);
    return 0;
}

TEST(cap_name_diagnostics) {
    const char *name = ozayn_platform_capability_name(OZAYN_CAPABILITY_DIAGNOSTICS);
    ASSERT(name != NULL);
    ASSERT(strcmp(name, "diagnostics") == 0);
    return 0;
}

TEST(cap_name_all_valid) {
    for (int i = 0; i < OZAYN_CAPABILITY_COUNT; i++) {
        const char *name = ozayn_platform_capability_name((OzaynPlatformCapability)i);
        ASSERT(name != NULL);
        ASSERT(strlen(name) > 0);
    }
    return 0;
}

TEST(cap_name_invalid_negative) {
    const char *name = ozayn_platform_capability_name((OzaynPlatformCapability)-1);
    ASSERT(name != NULL);
    ASSERT(strcmp(name, "unknown") == 0);
    return 0;
}

TEST(cap_name_invalid_large) {
    const char *name = ozayn_platform_capability_name((OzaynPlatformCapability)9999);
    ASSERT(name != NULL);
    ASSERT(strcmp(name, "unknown") == 0);
    return 0;
}

/* ---- State Names ---- */

TEST(cap_state_name_unknown) {
    const char *name = ozayn_platform_capability_state_name(OZAYN_CAPABILITY_UNKNOWN);
    ASSERT(name != NULL);
    ASSERT(strcmp(name, "unknown") == 0);
    return 0;
}

TEST(cap_state_name_available) {
    const char *name = ozayn_platform_capability_state_name(OZAYN_CAPABILITY_AVAILABLE);
    ASSERT(name != NULL);
    ASSERT(strcmp(name, "available") == 0);
    return 0;
}

TEST(cap_state_name_unavailable) {
    const char *name = ozayn_platform_capability_state_name(OZAYN_CAPABILITY_UNAVAILABLE);
    ASSERT(name != NULL);
    ASSERT(strcmp(name, "unavailable") == 0);
    return 0;
}

TEST(cap_state_name_invalid) {
    const char *name = ozayn_platform_capability_state_name((OzaynCapabilityState)9999);
    ASSERT(name != NULL);
    ASSERT(strcmp(name, "unknown") == 0);
    return 0;
}

/* ---- Get ---- */

TEST(cap_get_null) {
    ozayn_platform_capabilities_init();
    int r = ozayn_platform_capabilities_get(OZAYN_CAPABILITY_PLATFORM, NULL);
    ASSERT_EQ(r, 0);
    ozayn_platform_capabilities_shutdown();
    return 0;
}

TEST(cap_get_before_init) {
    OzaynPlatformCapabilityInfo info;
    int r = ozayn_platform_capabilities_get(OZAYN_CAPABILITY_PLATFORM, &info);
    ASSERT_EQ(r, 0);
    return 0;
}

TEST(cap_get_invalid_capability) {
    ozayn_platform_capabilities_init();
    OzaynPlatformCapabilityInfo info;
    int r = ozayn_platform_capabilities_get((OzaynPlatformCapability)9999, &info);
    ASSERT_EQ(r, 0);
    ozayn_platform_capabilities_shutdown();
    return 0;
}

TEST(cap_get_negative_capability) {
    ozayn_platform_capabilities_init();
    OzaynPlatformCapabilityInfo info;
    int r = ozayn_platform_capabilities_get((OzaynPlatformCapability)-1, &info);
    ASSERT_EQ(r, 0);
    ozayn_platform_capabilities_shutdown();
    return 0;
}

TEST(cap_get_valid_platform) {
    ozayn_platform_capabilities_init();
    OzaynPlatformCapabilityInfo info;
    memset(&info, 0, sizeof(info));
    int r = ozayn_platform_capabilities_get(OZAYN_CAPABILITY_PLATFORM, &info);
    ASSERT_EQ(r, 1);
    ASSERT_EQ(info.capability, OZAYN_CAPABILITY_PLATFORM);
    ASSERT(info.state >= OZAYN_CAPABILITY_UNKNOWN &&
           info.state <= OZAYN_CAPABILITY_UNAVAILABLE);
    ASSERT(info.name[0] != '\0');
    ASSERT(info.description[0] != '\0');
    ozayn_platform_capabilities_shutdown();
    return 0;
}

TEST(cap_get_all_valid) {
    ozayn_platform_capabilities_init();
    for (int i = 0; i < OZAYN_CAPABILITY_COUNT; i++) {
        OzaynPlatformCapabilityInfo info;
        memset(&info, 0, sizeof(info));
        int r = ozayn_platform_capabilities_get((OzaynPlatformCapability)i, &info);
        ASSERT_EQ(r, 1);
        ASSERT_EQ(info.capability, (OzaynPlatformCapability)i);
        ASSERT(info.state >= OZAYN_CAPABILITY_UNKNOWN &&
               info.state <= OZAYN_CAPABILITY_UNAVAILABLE);
        ASSERT(info.name[0] != '\0');
        ASSERT(info.description[0] != '\0');
    }
    ozayn_platform_capabilities_shutdown();
    return 0;
}

/* ---- is_capability_available ---- */

TEST(cap_is_avail_before_init) {
    int r = ozayn_platform_capabilities_is_capability_available(OZAYN_CAPABILITY_PLATFORM);
    ASSERT_EQ(r, 0);
    return 0;
}

TEST(cap_is_avail_invalid) {
    ozayn_platform_capabilities_init();
    int r = ozayn_platform_capabilities_is_capability_available((OzaynPlatformCapability)9999);
    ASSERT_EQ(r, 0);
    ozayn_platform_capabilities_shutdown();
    return 0;
}

TEST(cap_is_avail_all) {
    ozayn_platform_capabilities_init();
    for (int i = 0; i < OZAYN_CAPABILITY_COUNT; i++) {
        /* Must not crash regardless of environment */
        int r = ozayn_platform_capabilities_is_capability_available((OzaynPlatformCapability)i);
        ASSERT(r == 0 || r == 1);
    }
    ozayn_platform_capabilities_shutdown();
    return 0;
}

/* ---- String Validation ---- */

TEST(cap_info_strings_null_terminated) {
    ozayn_platform_capabilities_init();
    for (int i = 0; i < OZAYN_CAPABILITY_COUNT; i++) {
        OzaynPlatformCapabilityInfo info;
        ozayn_platform_capabilities_get((OzaynPlatformCapability)i, &info);
        ASSERT(info.name[127] == '\0');
        ASSERT(info.description[255] == '\0');
    }
    ozayn_platform_capabilities_shutdown();
    return 0;
}

/* ---- After Shutdown ---- */

TEST(cap_query_after_shutdown) {
    ozayn_platform_capabilities_init();
    ozayn_platform_capabilities_shutdown();

    ASSERT_EQ(ozayn_platform_capabilities_is_available(), 0);
    ASSERT_EQ(ozayn_platform_capabilities_get_count(), 0);

    OzaynPlatformCapabilityInfo info;
    ASSERT_EQ(ozayn_platform_capabilities_get(OZAYN_CAPABILITY_PLATFORM, &info), 0);
    ASSERT_EQ(ozayn_platform_capabilities_is_capability_available(OZAYN_CAPABILITY_PLATFORM), 0);

    return 0;
}

/* ---- Platform is available on any working system ---- */

TEST(cap_platform_available) {
    ozayn_platform_capabilities_init();
    int r = ozayn_platform_capabilities_is_capability_available(OZAYN_CAPABILITY_PLATFORM);
    ASSERT_EQ(r, 1);
    ozayn_platform_capabilities_shutdown();
    return 0;
}

/* ---- Filesystem is available on any working system ---- */

TEST(cap_filesystem_available) {
    ozayn_platform_capabilities_init();
    int r = ozayn_platform_capabilities_is_capability_available(OZAYN_CAPABILITY_FILESYSTEM);
    ASSERT_EQ(r, 1);
    ozayn_platform_capabilities_shutdown();
    return 0;
}

/* ---- Process is available on any working system ---- */

TEST(cap_process_available) {
    ozayn_platform_capabilities_init();
    int r = ozayn_platform_capabilities_is_capability_available(OZAYN_CAPABILITY_PROCESS);
    ASSERT_EQ(r, 1);
    ozayn_platform_capabilities_shutdown();
    return 0;
}

/* ---- Time is available on any working system ---- */

TEST(cap_time_available) {
    ozayn_platform_capabilities_init();
    int r = ozayn_platform_capabilities_is_capability_available(OZAYN_CAPABILITY_TIME);
    ASSERT_EQ(r, 1);
    ozayn_platform_capabilities_shutdown();
    return 0;
}

/* ---- Test Suite ---- */

int run_platform_capabilities_tests(void) {
    SUITE_BEGIN("Platform Capability Registry (Step 35)");

    /* Initialization */
    RUN(cap_init_basic);
    RUN(cap_init_idempotent);

    /* Availability */
    RUN(cap_is_available_before_init);
    RUN(cap_is_available_after_init);

    /* Count */
    RUN(cap_count_before_init);
    RUN(cap_count_matches_expected);

    /* Shutdown */
    RUN(cap_shutdown_basic);
    RUN(cap_shutdown_idempotent);
    RUN(cap_shutdown_before_init);

    /* Re-init */
    RUN(cap_reinit_after_shutdown);

    /* Names */
    RUN(cap_name_platform);
    RUN(cap_name_diagnostics);
    RUN(cap_name_all_valid);
    RUN(cap_name_invalid_negative);
    RUN(cap_name_invalid_large);

    /* State Names */
    RUN(cap_state_name_unknown);
    RUN(cap_state_name_available);
    RUN(cap_state_name_unavailable);
    RUN(cap_state_name_invalid);

    /* Get */
    RUN(cap_get_null);
    RUN(cap_get_before_init);
    RUN(cap_get_invalid_capability);
    RUN(cap_get_negative_capability);
    RUN(cap_get_valid_platform);
    RUN(cap_get_all_valid);

    /* is_capability_available */
    RUN(cap_is_avail_before_init);
    RUN(cap_is_avail_invalid);
    RUN(cap_is_avail_all);

    /* String Validation */
    RUN(cap_info_strings_null_terminated);

    /* After Shutdown */
    RUN(cap_query_after_shutdown);

    /* Environment Compatibility */
    RUN(cap_platform_available);
    RUN(cap_filesystem_available);
    RUN(cap_process_available);
    RUN(cap_time_available);

    SUITE_END();
    return FAILED();
}
