#include "../../tests/test_framework.h"
#include "platform.h"
#include <stdio.h>
#include <string.h>

/*
 * test_permissions.c — Section 02 Step 19: System Permissions & Capability Access Abstraction Tests.
 *
 * Tests permissions initialization, shutdown, capability queries, name helpers,
 * and error handling. Read-only — no permission modification, no bypass.
 */

/* --- Initialization --- */

TEST(permissions_init_basic) {
    ozayn_result_t r = ozayn_permissions_init();
    ASSERT_EQ(r, OZAYN_OK);
    ozayn_permissions_shutdown();
    return 0;
}

TEST(permissions_init_idempotent) {
    ozayn_permissions_init();
    ozayn_result_t r = ozayn_permissions_init();
    ASSERT_EQ(r, OZAYN_OK);
    ozayn_permissions_shutdown();
    return 0;
}

/* --- Availability --- */

TEST(permissions_is_available_after_init) {
    ozayn_permissions_init();
    int avail = ozayn_permissions_is_available();
    ASSERT(avail == 0 || avail == 1);
    ozayn_permissions_shutdown();
    return 0;
}

TEST(permissions_is_available_before_init) {
    int avail = ozayn_permissions_is_available();
    ASSERT_EQ(avail, 0);
    return 0;
}

/* --- Capability Name --- */

TEST(capability_name_unknown) {
    const char *name = ozayn_capability_get_name(OZAYN_CAP_UNKNOWN);
    ASSERT(name != NULL);
    ASSERT(strlen(name) > 0);
    return 0;
}

TEST(capability_name_camera) {
    const char *name = ozayn_capability_get_name(OZAYN_CAP_CAMERA);
    ASSERT(name != NULL);
    ASSERT(strcmp(name, "Camera") == 0);
    return 0;
}

TEST(capability_name_microphone) {
    const char *name = ozayn_capability_get_name(OZAYN_CAP_MICROPHONE);
    ASSERT(name != NULL);
    ASSERT(strcmp(name, "Microphone") == 0);
    return 0;
}

TEST(capability_name_notifications) {
    const char *name = ozayn_capability_get_name(OZAYN_CAP_NOTIFICATIONS);
    ASSERT(name != NULL);
    ASSERT(strcmp(name, "Notifications") == 0);
    return 0;
}

TEST(capability_name_accessibility) {
    const char *name = ozayn_capability_get_name(OZAYN_CAP_ACCESSIBILITY);
    ASSERT(name != NULL);
    ASSERT(strcmp(name, "Accessibility") == 0);
    return 0;
}

TEST(capability_name_filesystem) {
    const char *name = ozayn_capability_get_name(OZAYN_CAP_FILESYSTEM);
    ASSERT(name != NULL);
    ASSERT(strcmp(name, "Filesystem") == 0);
    return 0;
}

TEST(capability_name_network) {
    const char *name = ozayn_capability_get_name(OZAYN_CAP_NETWORK);
    ASSERT(name != NULL);
    ASSERT(strcmp(name, "Network") == 0);
    return 0;
}

TEST(capability_name_invalid) {
    const char *name = ozayn_capability_get_name((OzaynCapability)999);
    ASSERT(name != NULL);
    ASSERT(strcmp(name, "Invalid") == 0);
    return 0;
}

/* --- Permission State Name --- */

TEST(permission_state_name_unknown) {
    const char *name = ozayn_permission_state_name(OZAYN_PERMISSION_UNKNOWN);
    ASSERT(name != NULL);
    ASSERT(strcmp(name, "Unknown") == 0);
    return 0;
}

TEST(permission_state_name_available) {
    const char *name = ozayn_permission_state_name(OZAYN_PERMISSION_AVAILABLE);
    ASSERT(name != NULL);
    ASSERT(strcmp(name, "Available") == 0);
    return 0;
}

TEST(permission_state_name_granted) {
    const char *name = ozayn_permission_state_name(OZAYN_PERMISSION_GRANTED);
    ASSERT(name != NULL);
    ASSERT(strcmp(name, "Granted") == 0);
    return 0;
}

TEST(permission_state_name_denied) {
    const char *name = ozayn_permission_state_name(OZAYN_PERMISSION_DENIED);
    ASSERT(name != NULL);
    ASSERT(strcmp(name, "Denied") == 0);
    return 0;
}

TEST(permission_state_name_restricted) {
    const char *name = ozayn_permission_state_name(OZAYN_PERMISSION_RESTRICTED);
    ASSERT(name != NULL);
    ASSERT(strcmp(name, "Restricted") == 0);
    return 0;
}

TEST(permission_state_name_unavailable) {
    const char *name = ozayn_permission_state_name(OZAYN_PERMISSION_UNAVAILABLE);
    ASSERT(name != NULL);
    ASSERT(strcmp(name, "Unavailable") == 0);
    return 0;
}

TEST(permission_state_name_invalid) {
    const char *name = ozayn_permission_state_name((OzaynPermissionState)999);
    ASSERT(name != NULL);
    ASSERT(strcmp(name, "Invalid") == 0);
    return 0;
}

/* --- Capability Queries --- */

TEST(permissions_get_state_before_init) {
    OzaynPermissionState state = ozayn_permissions_get_state(OZAYN_CAP_CAMERA);
    ASSERT_EQ(state, OZAYN_PERMISSION_UNKNOWN);
    return 0;
}

TEST(permissions_get_state_camera) {
    ozayn_permissions_init();
    OzaynPermissionState state = ozayn_permissions_get_state(OZAYN_CAP_CAMERA);
    ASSERT(state == OZAYN_PERMISSION_AVAILABLE || state == OZAYN_PERMISSION_UNAVAILABLE ||
           state == OZAYN_PERMISSION_UNKNOWN || state == OZAYN_PERMISSION_DENIED);
    ozayn_permissions_shutdown();
    return 0;
}

TEST(permissions_get_state_microphone) {
    ozayn_permissions_init();
    OzaynPermissionState state = ozayn_permissions_get_state(OZAYN_CAP_MICROPHONE);
    ASSERT(state == OZAYN_PERMISSION_AVAILABLE || state == OZAYN_PERMISSION_UNAVAILABLE ||
           state == OZAYN_PERMISSION_UNKNOWN || state == OZAYN_PERMISSION_DENIED);
    ozayn_permissions_shutdown();
    return 0;
}

TEST(permissions_get_state_notifications) {
    ozayn_permissions_init();
    OzaynPermissionState state = ozayn_permissions_get_state(OZAYN_CAP_NOTIFICATIONS);
    ASSERT(state == OZAYN_PERMISSION_AVAILABLE || state == OZAYN_PERMISSION_UNAVAILABLE ||
           state == OZAYN_PERMISSION_UNKNOWN || state == OZAYN_PERMISSION_DENIED);
    ozayn_permissions_shutdown();
    return 0;
}

TEST(permissions_get_state_accessibility) {
    ozayn_permissions_init();
    OzaynPermissionState state = ozayn_permissions_get_state(OZAYN_CAP_ACCESSIBILITY);
    ASSERT(state == OZAYN_PERMISSION_AVAILABLE || state == OZAYN_PERMISSION_UNAVAILABLE ||
           state == OZAYN_PERMISSION_UNKNOWN || state == OZAYN_PERMISSION_DENIED);
    ozayn_permissions_shutdown();
    return 0;
}

TEST(permissions_get_state_filesystem) {
    ozayn_permissions_init();
    OzaynPermissionState state = ozayn_permissions_get_state(OZAYN_CAP_FILESYSTEM);
    ASSERT(state == OZAYN_PERMISSION_AVAILABLE || state == OZAYN_PERMISSION_UNAVAILABLE ||
           state == OZAYN_PERMISSION_UNKNOWN || state == OZAYN_PERMISSION_DENIED);
    ozayn_permissions_shutdown();
    return 0;
}

TEST(permissions_get_state_network) {
    ozayn_permissions_init();
    OzaynPermissionState state = ozayn_permissions_get_state(OZAYN_CAP_NETWORK);
    ASSERT(state == OZAYN_PERMISSION_AVAILABLE || state == OZAYN_PERMISSION_UNAVAILABLE ||
           state == OZAYN_PERMISSION_UNKNOWN || state == OZAYN_PERMISSION_DENIED);
    ozayn_permissions_shutdown();
    return 0;
}

TEST(permissions_get_state_invalid) {
    ozayn_permissions_init();
    OzaynPermissionState state = ozayn_permissions_get_state((OzaynCapability)999);
    ASSERT_EQ(state, OZAYN_PERMISSION_UNKNOWN);
    ozayn_permissions_shutdown();
    return 0;
}

/* --- Shutdown --- */

TEST(permissions_shutdown_basic) {
    ozayn_permissions_init();
    ozayn_permissions_shutdown();
    return 0;
}

TEST(permissions_shutdown_idempotent) {
    ozayn_permissions_init();
    ozayn_permissions_shutdown();
    ozayn_permissions_shutdown();
    return 0;
}

TEST(permissions_shutdown_before_init) {
    ozayn_permissions_shutdown();
    return 0;
}

/* --- Test Suite --- */

int run_permissions_tests(void) {
    int failed = 0;
    SUITE_BEGIN("System Permissions & Capability Access (Section 02)");

    /* Initialization */
    RUN(permissions_init_basic);
    RUN(permissions_init_idempotent);

    /* Availability */
    RUN(permissions_is_available_after_init);
    RUN(permissions_is_available_before_init);

    /* Capability Names */
    RUN(capability_name_unknown);
    RUN(capability_name_camera);
    RUN(capability_name_microphone);
    RUN(capability_name_notifications);
    RUN(capability_name_accessibility);
    RUN(capability_name_filesystem);
    RUN(capability_name_network);
    RUN(capability_name_invalid);

    /* Permission State Names */
    RUN(permission_state_name_unknown);
    RUN(permission_state_name_available);
    RUN(permission_state_name_granted);
    RUN(permission_state_name_denied);
    RUN(permission_state_name_restricted);
    RUN(permission_state_name_unavailable);
    RUN(permission_state_name_invalid);

    /* Capability Queries */
    RUN(permissions_get_state_before_init);
    RUN(permissions_get_state_camera);
    RUN(permissions_get_state_microphone);
    RUN(permissions_get_state_notifications);
    RUN(permissions_get_state_accessibility);
    RUN(permissions_get_state_filesystem);
    RUN(permissions_get_state_network);
    RUN(permissions_get_state_invalid);

    /* Shutdown */
    RUN(permissions_shutdown_basic);
    RUN(permissions_shutdown_idempotent);
    RUN(permissions_shutdown_before_init);

    SUITE_END();
    return FAILED();
}
