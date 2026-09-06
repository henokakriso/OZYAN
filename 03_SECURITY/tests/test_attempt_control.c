#include "../../tests/test_framework.h"
#include "../attempt_control.h"
#include <string.h>
#include <unistd.h>

/* ============================================================
 * 1. DEFAULT POLICY
 * ============================================================ */

TEST(test_default_policy_valid)
{
    ozayn_ac_policy_t p = ozayn_ac_default_policy();
    ASSERT(p.enabled);
    ASSERT_EQ(p.max_failures, 5);
    ASSERT_EQ(p.window_seconds, 300);
    ASSERT_EQ(p.initial_delay_ms, 1000);
    ASSERT_EQ(p.max_delay_ms, 30000);
    ASSERT(p.backoff_multiplier == 2.0);
    ASSERT_EQ(p.block_seconds, 900);
    ASSERT_EQ(p.counter_reset_seconds, 0);
    return 0;
}

TEST(test_default_policy_validates)
{
    ozayn_ac_policy_t p = ozayn_ac_default_policy();
    ASSERT_EQ(ozayn_ac_validate_policy(&p), 0);
    return 0;
}

/* ============================================================
 * 2. TEST POLICY
 * ============================================================ */

TEST(test_test_policy_valid)
{
    ozayn_ac_policy_t p = ozayn_ac_test_policy();
    ASSERT(p.enabled);
    ASSERT_EQ(p.max_failures, 3);
    ASSERT_EQ(p.window_seconds, 5);
    ASSERT_EQ(p.initial_delay_ms, 100);
    ASSERT_EQ(p.max_delay_ms, 2000);
    ASSERT(p.backoff_multiplier == 2.0);
    ASSERT_EQ(p.block_seconds, 10);
    return 0;
}

TEST(test_test_policy_validates)
{
    ozayn_ac_policy_t p = ozayn_ac_test_policy();
    ASSERT_EQ(ozayn_ac_validate_policy(&p), 0);
    return 0;
}

/* ============================================================
 * 3. SERVICE INIT
 * ============================================================ */

TEST(test_service_init_null)
{
    ASSERT_EQ(ozayn_ac_service_init(NULL, NULL), OZAYN_AC_ERR_NULL);
    ozayn_ac_service_t svc;
    ASSERT_EQ(ozayn_ac_service_init(&svc, NULL), OZAYN_AC_ERR_NULL);
    ozayn_ac_service_config_t cfg;
    ASSERT_EQ(ozayn_ac_service_init(NULL, &cfg), OZAYN_AC_ERR_NULL);
    return 0;
}

TEST(test_service_init_defaults)
{
    ozayn_ac_service_t svc;
    ozayn_ac_service_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.policy = ozayn_ac_default_policy();
    ASSERT_EQ(ozayn_ac_service_init(&svc, &cfg), OZAYN_AC_OK);
    ASSERT(ozayn_ac_service_is_initialized(&svc));
    ASSERT_EQ(ozayn_ac_service_entry_count(&svc), 0);
    ozayn_ac_service_shutdown(&svc);
    return 0;
}

TEST(test_service_init_invalid_policy)
{
    ozayn_ac_service_t svc;
    ozayn_ac_service_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));

    cfg.policy.enabled      = 1;
    cfg.policy.max_failures = 0;
    ASSERT_EQ(ozayn_ac_service_init(&svc, &cfg), OZAYN_AC_ERR_POLICY_INVALID);

    cfg.policy.max_failures = 5;
    cfg.policy.window_seconds = 0;
    ASSERT_EQ(ozayn_ac_service_init(&svc, &cfg), OZAYN_AC_ERR_POLICY_INVALID);

    cfg.policy.window_seconds = 300;
    cfg.policy.block_seconds = 0;
    ASSERT_EQ(ozayn_ac_service_init(&svc, &cfg), OZAYN_AC_ERR_POLICY_INVALID);

    cfg.policy.block_seconds = 900;
    cfg.policy.backoff_multiplier = 0.5;
    ASSERT_EQ(ozayn_ac_service_init(&svc, &cfg), OZAYN_AC_ERR_POLICY_INVALID);

    return 0;
}

/* ============================================================
 * 4. SERVICE SHUTDOWN
 * ============================================================ */

TEST(test_service_shutdown)
{
    ozayn_ac_service_t svc;
    ozayn_ac_service_config_t cfg;
    cfg.policy = ozayn_ac_default_policy();
    ASSERT_EQ(ozayn_ac_service_init(&svc, &cfg), OZAYN_AC_OK);

    ozayn_ac_record_failure(&svc, "user1");
    ASSERT_GT(ozayn_ac_service_entry_count(&svc), 0);

    ozayn_ac_service_shutdown(&svc);
    ASSERT(!ozayn_ac_service_is_initialized(&svc));
    ASSERT_EQ(ozayn_ac_service_entry_count(&svc), 0);
    return 0;
}

TEST(test_service_shutdown_null)
{
    ozayn_ac_service_shutdown(NULL);
    return 0;
}

/* ============================================================
 * 5. CHECK ALLOWED — NO FAILURES
 * ============================================================ */

TEST(test_check_allowed_no_failures)
{
    ozayn_ac_service_t svc;
    ozayn_ac_service_config_t cfg;
    cfg.policy = ozayn_ac_test_policy();
    ASSERT_EQ(ozayn_ac_service_init(&svc, &cfg), OZAYN_AC_OK);

    int allowed = 0, retry_ms = 0;
    ASSERT_EQ(ozayn_ac_check_allowed(&svc, "alice", &allowed, &retry_ms),
              OZAYN_AC_OK);
    ASSERT_EQ(allowed, 1);
    ASSERT_EQ(retry_ms, 0);
    ozayn_ac_service_shutdown(&svc);
    return 0;
}

TEST(test_check_allowed_unknown_identity)
{
    ozayn_ac_service_t svc;
    ozayn_ac_service_config_t cfg;
    cfg.policy = ozayn_ac_test_policy();
    ASSERT_EQ(ozayn_ac_service_init(&svc, &cfg), OZAYN_AC_OK);

    int allowed = 0, retry_ms = 0;
    ASSERT_EQ(ozayn_ac_check_allowed(&svc, "unknown_user", &allowed, &retry_ms),
              OZAYN_AC_OK);
    ASSERT_EQ(allowed, 1);
    ASSERT_EQ(retry_ms, 0);
    ozayn_ac_service_shutdown(&svc);
    return 0;
}

TEST(test_check_allowed_disabled_policy)
{
    ozayn_ac_service_t svc;
    ozayn_ac_service_config_t cfg;
    cfg.policy = ozayn_ac_default_policy();
    cfg.policy.enabled = 0;
    ASSERT_EQ(ozayn_ac_service_init(&svc, &cfg), OZAYN_AC_OK);

    int allowed = 0, retry_ms = 0;
    ASSERT_EQ(ozayn_ac_check_allowed(&svc, "alice", &allowed, &retry_ms),
              OZAYN_AC_OK);
    ASSERT_EQ(allowed, 1);
    ASSERT_EQ(retry_ms, 0);

    ozayn_ac_record_failure(&svc, "alice");
    ASSERT_EQ(ozayn_ac_check_allowed(&svc, "alice", &allowed, &retry_ms),
              OZAYN_AC_OK);
    ASSERT_EQ(allowed, 1);
    ozayn_ac_service_shutdown(&svc);
    return 0;
}

/* ============================================================
 * 6. RECORD FAILURE — BASIC
 * ============================================================ */

TEST(test_record_failure_basic)
{
    ozayn_ac_service_t svc;
    ozayn_ac_service_config_t cfg;
    cfg.policy = ozayn_ac_test_policy();
    ASSERT_EQ(ozayn_ac_service_init(&svc, &cfg), OZAYN_AC_OK);

    ASSERT_EQ(ozayn_ac_record_failure(&svc, "bob"), OZAYN_AC_OK);
    ASSERT_EQ(ozayn_ac_get_failure_count(&svc, "bob"), 1);
    ASSERT_EQ(ozayn_ac_get_state(&svc, "bob"), OZAYN_AC_STATE_THROTTLED);
    ASSERT(ozayn_ac_service_entry_count(&svc) >= 1);
    ozayn_ac_service_shutdown(&svc);
    return 0;
}

TEST(test_record_failure_multiple)
{
    ozayn_ac_service_t svc;
    ozayn_ac_service_config_t cfg;
    cfg.policy = ozayn_ac_test_policy();
    ASSERT_EQ(ozayn_ac_service_init(&svc, &cfg), OZAYN_AC_OK);

    for (int i = 1; i <= 3; i++) {
        ASSERT_EQ(ozayn_ac_record_failure(&svc, "bob"), OZAYN_AC_OK);
        ASSERT_EQ(ozayn_ac_get_failure_count(&svc, "bob"), i);
    }
    ASSERT_EQ(ozayn_ac_get_state(&svc, "bob"), OZAYN_AC_STATE_BLOCKED);
    ozayn_ac_service_shutdown(&svc);
    return 0;
}

/* ============================================================
 * 7. RECORD FAILURE — NULL / INVALID
 * ============================================================ */

TEST(test_record_failure_null)
{
    ASSERT_EQ(ozayn_ac_record_failure(NULL, "alice"), OZAYN_AC_ERR_NULL);
    ozayn_ac_service_t svc;
    ASSERT_EQ(ozayn_ac_record_failure(&svc, NULL), OZAYN_AC_ERR_NULL);
    return 0;
}

TEST(test_record_failure_empty_id)
{
    ozayn_ac_service_t svc;
    ozayn_ac_service_config_t cfg;
    cfg.policy = ozayn_ac_test_policy();
    ASSERT_EQ(ozayn_ac_service_init(&svc, &cfg), OZAYN_AC_OK);
    ASSERT_EQ(ozayn_ac_record_failure(&svc, ""), OZAYN_AC_ERR_INVALID);
    ozayn_ac_service_shutdown(&svc);
    return 0;
}

TEST(test_record_failure_not_initialized)
{
    ozayn_ac_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ASSERT_EQ(ozayn_ac_record_failure(&svc, "alice"), OZAYN_AC_ERR_NOT_INITIALIZED);
    return 0;
}

/* ============================================================
 * 8. CHECK ALLOWED — AFTER FAILURES (RATE LIMITED)
 * ============================================================ */

TEST(test_check_allowed_rate_limited)
{
    ozayn_ac_service_t svc;
    ozayn_ac_service_config_t cfg;
    cfg.policy = ozayn_ac_test_policy();
    cfg.policy.initial_delay_ms = 500;
    cfg.policy.backoff_multiplier = 2.0;
    ASSERT_EQ(ozayn_ac_service_init(&svc, &cfg), OZAYN_AC_OK);

    ASSERT_EQ(ozayn_ac_record_failure(&svc, "alice"), OZAYN_AC_OK);

    int allowed = 0, retry_ms = 0;
    ozayn_ac_error_t r = ozayn_ac_check_allowed(&svc, "alice", &allowed, &retry_ms);
    ASSERT_EQ(r, OZAYN_AC_ERR_RATE_LIMITED);
    ASSERT_EQ(allowed, 0);
    ASSERT_GT(retry_ms, 0);
    ozayn_ac_service_shutdown(&svc);
    return 0;
}

TEST(test_check_allowed_blocked)
{
    ozayn_ac_service_t svc;
    ozayn_ac_service_config_t cfg;
    cfg.policy = ozayn_ac_test_policy();
    ASSERT_EQ(ozayn_ac_service_init(&svc, &cfg), OZAYN_AC_OK);

    for (int i = 0; i < 3; i++)
        ASSERT_EQ(ozayn_ac_record_failure(&svc, "alice"), OZAYN_AC_OK);

    int allowed = 0, retry_ms = 0;
    ozayn_ac_error_t r = ozayn_ac_check_allowed(&svc, "alice", &allowed, &retry_ms);
    ASSERT_EQ(r, OZAYN_AC_ERR_TEMPORARILY_BLOCKED);
    ASSERT_EQ(allowed, 0);
    ASSERT_GT(retry_ms, 0);
    ozayn_ac_service_shutdown(&svc);
    return 0;
}

/* ============================================================
 * 9. RECORD SUCCESS — RESETS
 * ============================================================ */

TEST(test_record_success_resets_failures)
{
    ozayn_ac_service_t svc;
    ozayn_ac_service_config_t cfg;
    cfg.policy = ozayn_ac_test_policy();
    ASSERT_EQ(ozayn_ac_service_init(&svc, &cfg), OZAYN_AC_OK);

    for (int i = 0; i < 2; i++)
        ASSERT_EQ(ozayn_ac_record_failure(&svc, "alice"), OZAYN_AC_OK);
    ASSERT_EQ(ozayn_ac_get_failure_count(&svc, "alice"), 2);
    ASSERT_EQ(ozayn_ac_get_state(&svc, "alice"), OZAYN_AC_STATE_THROTTLED);

    ASSERT_EQ(ozayn_ac_record_success(&svc, "alice"), OZAYN_AC_OK);
    ASSERT_EQ(ozayn_ac_get_failure_count(&svc, "alice"), 0);
    ASSERT_EQ(ozayn_ac_get_state(&svc, "alice"), OZAYN_AC_STATE_READY);

    int allowed = 0, retry_ms = 0;
    ASSERT_EQ(ozayn_ac_check_allowed(&svc, "alice", &allowed, &retry_ms),
              OZAYN_AC_OK);
    ASSERT_EQ(allowed, 1);
    ASSERT_EQ(retry_ms, 0);
    ozayn_ac_service_shutdown(&svc);
    return 0;
}

TEST(test_record_success_unknown_identity)
{
    ozayn_ac_service_t svc;
    ozayn_ac_service_config_t cfg;
    cfg.policy = ozayn_ac_test_policy();
    ASSERT_EQ(ozayn_ac_service_init(&svc, &cfg), OZAYN_AC_OK);

    ASSERT_EQ(ozayn_ac_record_success(&svc, "unknown"), OZAYN_AC_OK);
    ASSERT_EQ(ozayn_ac_get_failure_count(&svc, "unknown"), 0);
    ozayn_ac_service_shutdown(&svc);
    return 0;
}

/* ============================================================
 * 10. RESET
 * ============================================================ */

TEST(test_reset)
{
    ozayn_ac_service_t svc;
    ozayn_ac_service_config_t cfg;
    cfg.policy = ozayn_ac_test_policy();
    ASSERT_EQ(ozayn_ac_service_init(&svc, &cfg), OZAYN_AC_OK);

    for (int i = 0; i < 3; i++)
        ASSERT_EQ(ozayn_ac_record_failure(&svc, "alice"), OZAYN_AC_OK);
    ASSERT_EQ(ozayn_ac_get_state(&svc, "alice"), OZAYN_AC_STATE_BLOCKED);

    ASSERT_EQ(ozayn_ac_reset(&svc, "alice"), OZAYN_AC_OK);
    ASSERT_EQ(ozayn_ac_get_failure_count(&svc, "alice"), 0);
    ASSERT_EQ(ozayn_ac_get_state(&svc, "alice"), OZAYN_AC_STATE_READY);

    int allowed = 0, retry_ms = 0;
    ASSERT_EQ(ozayn_ac_check_allowed(&svc, "alice", &allowed, &retry_ms),
              OZAYN_AC_OK);
    ASSERT_EQ(allowed, 1);
    ozayn_ac_service_shutdown(&svc);
    return 0;
}

TEST(test_reset_unknown_identity)
{
    ozayn_ac_service_t svc;
    ozayn_ac_service_config_t cfg;
    cfg.policy = ozayn_ac_test_policy();
    ASSERT_EQ(ozayn_ac_service_init(&svc, &cfg), OZAYN_AC_OK);
    ASSERT_EQ(ozayn_ac_reset(&svc, "unknown"), OZAYN_AC_OK);
    ozayn_ac_service_shutdown(&svc);
    return 0;
}

/* ============================================================
 * 11. PROGRESSIVE BACKOFF
 * ============================================================ */

TEST(test_progressive_backoff)
{
    ozayn_ac_service_t svc;
    ozayn_ac_service_config_t cfg;
    cfg.policy = ozayn_ac_test_policy();
    cfg.policy.initial_delay_ms = 100;
    cfg.policy.backoff_multiplier = 2.0;
    cfg.policy.max_delay_ms = 10000;
    ASSERT_EQ(ozayn_ac_service_init(&svc, &cfg), OZAYN_AC_OK);

    ASSERT_EQ(ozayn_ac_record_failure(&svc, "alice"), OZAYN_AC_OK);
    int allowed = 0, retry_ms = 0;
    ASSERT_EQ(ozayn_ac_check_allowed(&svc, "alice", &allowed, &retry_ms),
              OZAYN_AC_ERR_RATE_LIMITED);
    ASSERT_GE(retry_ms, 50);

    usleep(150000);

    ASSERT_EQ(ozayn_ac_record_failure(&svc, "alice"), OZAYN_AC_OK);
    ASSERT_EQ(ozayn_ac_check_allowed(&svc, "alice", &allowed, &retry_ms),
              OZAYN_AC_ERR_RATE_LIMITED);
    ASSERT_GE(retry_ms, 50);

    ozayn_ac_service_shutdown(&svc);
    return 0;
}

TEST(test_backoff_max_cap)
{
    ozayn_ac_service_t svc;
    ozayn_ac_service_config_t cfg;
    cfg.policy = ozayn_ac_test_policy();
    cfg.policy.initial_delay_ms = 100;
    cfg.policy.backoff_multiplier = 10.0;
    cfg.policy.max_delay_ms = 500;
    ASSERT_EQ(ozayn_ac_service_init(&svc, &cfg), OZAYN_AC_OK);

    ASSERT_EQ(ozayn_ac_record_failure(&svc, "alice"), OZAYN_AC_OK);
    ASSERT_EQ(ozayn_ac_record_failure(&svc, "alice"), OZAYN_AC_OK);

    int allowed = 0, retry_ms = 0;
    ASSERT_EQ(ozayn_ac_check_allowed(&svc, "alice", &allowed, &retry_ms),
              OZAYN_AC_ERR_RATE_LIMITED);
    ASSERT_GE(retry_ms, 100);
    ozayn_ac_service_shutdown(&svc);
    return 0;
}

/* ============================================================
 * 12. MULTIPLE IDENTITIES — ISOLATION
 * ============================================================ */

TEST(test_multiple_identities_isolated)
{
    ozayn_ac_service_t svc;
    ozayn_ac_service_config_t cfg;
    cfg.policy = ozayn_ac_test_policy();
    ASSERT_EQ(ozayn_ac_service_init(&svc, &cfg), OZAYN_AC_OK);

    ASSERT_EQ(ozayn_ac_record_failure(&svc, "alice"), OZAYN_AC_OK);
    ASSERT_EQ(ozayn_ac_record_failure(&svc, "alice"), OZAYN_AC_OK);

    ASSERT_EQ(ozayn_ac_get_failure_count(&svc, "bob"), 0);
    ASSERT_EQ(ozayn_ac_get_state(&svc, "bob"), OZAYN_AC_STATE_READY);

    int allowed = 0, retry_ms = 0;
    ASSERT_EQ(ozayn_ac_check_allowed(&svc, "bob", &allowed, &retry_ms),
              OZAYN_AC_OK);
    ASSERT_EQ(allowed, 1);
    ozayn_ac_service_shutdown(&svc);
    return 0;
}

/* ============================================================
 * 13. ENTRY COUNT
 * ============================================================ */

TEST(test_entry_count_tracking)
{
    ozayn_ac_service_t svc;
    ozayn_ac_service_config_t cfg;
    cfg.policy = ozayn_ac_test_policy();
    ASSERT_EQ(ozayn_ac_service_init(&svc, &cfg), OZAYN_AC_OK);
    ASSERT_EQ(ozayn_ac_service_entry_count(&svc), 0);

    ozayn_ac_record_failure(&svc, "alice");
    ASSERT_GE(ozayn_ac_service_entry_count(&svc), 1);

    ozayn_ac_record_failure(&svc, "bob");
    ASSERT_GE(ozayn_ac_service_entry_count(&svc), 2);

    ozayn_ac_record_success(&svc, "alice");
    ASSERT_GE(ozayn_ac_service_entry_count(&svc), 2);
    ozayn_ac_service_shutdown(&svc);
    return 0;
}

/* ============================================================
 * 14. NAME HELPERS
 * ============================================================ */

TEST(test_state_name)
{
    ASSERT_STR_EQ(ozayn_ac_state_name(OZAYN_AC_STATE_READY), "READY");
    ASSERT_STR_EQ(ozayn_ac_state_name(OZAYN_AC_STATE_THROTTLED), "THROTTLED");
    ASSERT_STR_EQ(ozayn_ac_state_name(OZAYN_AC_STATE_BLOCKED), "BLOCKED");
    ASSERT_STR_EQ(ozayn_ac_state_name((ozayn_ac_state_t)99), "UNKNOWN");
    return 0;
}

TEST(test_error_name)
{
    ASSERT_STR_EQ(ozayn_ac_error_name(OZAYN_AC_OK), "OK");
    ASSERT_STR_EQ(ozayn_ac_error_name(OZAYN_AC_ERR_NULL), "NULL");
    ASSERT_STR_EQ(ozayn_ac_error_name(OZAYN_AC_ERR_NOT_INITIALIZED),
                  "NOT_INITIALIZED");
    ASSERT_STR_EQ(ozayn_ac_error_name(OZAYN_AC_ERR_RATE_LIMITED),
                  "RATE_LIMITED");
    ASSERT_STR_EQ(ozayn_ac_error_name(OZAYN_AC_ERR_TEMPORARILY_BLOCKED),
                  "TEMPORARILY_BLOCKED");
    ASSERT_STR_EQ(ozayn_ac_error_name((ozayn_ac_error_t)999), "UNKNOWN");
    return 0;
}

/* ============================================================
 * 15. VALIDATION
 * ============================================================ */

TEST(test_validate_state_valid)
{
    ASSERT_EQ(ozayn_ac_validate_state(OZAYN_AC_STATE_READY), 0);
    ASSERT_EQ(ozayn_ac_validate_state(OZAYN_AC_STATE_THROTTLED), 0);
    ASSERT_EQ(ozayn_ac_validate_state(OZAYN_AC_STATE_BLOCKED), 0);
    return 0;
}

TEST(test_validate_state_invalid)
{
    ASSERT_EQ(ozayn_ac_validate_state((ozayn_ac_state_t)-1), -1);
    ASSERT_EQ(ozayn_ac_validate_state((ozayn_ac_state_t)3), -1);
    ASSERT_EQ(ozayn_ac_validate_state((ozayn_ac_state_t)99), -1);
    return 0;
}

TEST(test_validate_policy_null)
{
    ASSERT_EQ(ozayn_ac_validate_policy(NULL), -1);
    return 0;
}

TEST(test_validate_policy_disabled)
{
    ozayn_ac_policy_t p;
    memset(&p, 0, sizeof(p));
    p.enabled = 0;
    ASSERT_EQ(ozayn_ac_validate_policy(&p), 0);
    return 0;
}

/* ============================================================
 * 16. INIT NULL CHECKS
 * ============================================================ */

TEST(test_init_null_service)
{
    ozayn_ac_service_config_t cfg;
    cfg.policy = ozayn_ac_default_policy();
    ASSERT_EQ(ozayn_ac_service_init(NULL, &cfg), OZAYN_AC_ERR_NULL);
    return 0;
}

TEST(test_init_null_config)
{
    ozayn_ac_service_t svc;
    ASSERT_EQ(ozayn_ac_service_init(&svc, NULL), OZAYN_AC_ERR_NULL);
    return 0;
}

/* ============================================================
 * 17. CHECK ALLOWED NULL CHECKS
 * ============================================================ */

TEST(test_check_allowed_null)
{
    ozayn_ac_service_t svc;
    svc.initialized = 1;
    int a = 0, r = 0;
    ASSERT_EQ(ozayn_ac_check_allowed(NULL, "alice", &a, &r), OZAYN_AC_ERR_NULL);
    ASSERT_EQ(ozayn_ac_check_allowed(&svc, NULL, &a, &r), OZAYN_AC_ERR_NULL);
    ASSERT_EQ(ozayn_ac_check_allowed(&svc, "alice", NULL, &r), OZAYN_AC_ERR_NULL);
    ASSERT_EQ(ozayn_ac_check_allowed(&svc, "alice", &a, NULL), OZAYN_AC_ERR_NULL);
    return 0;
}

TEST(test_check_allowed_empty_id)
{
    ozayn_ac_service_t svc;
    ozayn_ac_service_config_t cfg;
    cfg.policy = ozayn_ac_test_policy();
    ASSERT_EQ(ozayn_ac_service_init(&svc, &cfg), OZAYN_AC_OK);
    int a = 0, r = 0;
    ASSERT_EQ(ozayn_ac_check_allowed(&svc, "", &a, &r), OZAYN_AC_ERR_INVALID);
    ozayn_ac_service_shutdown(&svc);
    return 0;
}

TEST(test_check_allowed_not_initialized)
{
    ozayn_ac_service_t svc;
    memset(&svc, 0, sizeof(svc));
    int a = 0, r = 0;
    ASSERT_EQ(ozayn_ac_check_allowed(&svc, "alice", &a, &r),
              OZAYN_AC_ERR_NOT_INITIALIZED);
    return 0;
}

/* ============================================================
 * 18. RECORD SUCCESS NULL CHECKS
 * ============================================================ */

TEST(test_record_success_null)
{
    ASSERT_EQ(ozayn_ac_record_success(NULL, "alice"), OZAYN_AC_ERR_NULL);
    ozayn_ac_service_t svc;
    ASSERT_EQ(ozayn_ac_record_success(&svc, NULL), OZAYN_AC_ERR_NULL);
    return 0;
}

TEST(test_record_success_empty_id)
{
    ozayn_ac_service_t svc;
    ozayn_ac_service_config_t cfg;
    cfg.policy = ozayn_ac_test_policy();
    ASSERT_EQ(ozayn_ac_service_init(&svc, &cfg), OZAYN_AC_OK);
    ASSERT_EQ(ozayn_ac_record_success(&svc, ""), OZAYN_AC_ERR_INVALID);
    ozayn_ac_service_shutdown(&svc);
    return 0;
}

/* ============================================================
 * 19. RESET NULL CHECKS
 * ============================================================ */

TEST(test_reset_null)
{
    ASSERT_EQ(ozayn_ac_reset(NULL, "alice"), OZAYN_AC_ERR_NULL);
    ozayn_ac_service_t svc;
    ASSERT_EQ(ozayn_ac_reset(&svc, NULL), OZAYN_AC_ERR_NULL);
    return 0;
}

TEST(test_reset_empty_id)
{
    ozayn_ac_service_t svc;
    ozayn_ac_service_config_t cfg;
    cfg.policy = ozayn_ac_test_policy();
    ASSERT_EQ(ozayn_ac_service_init(&svc, &cfg), OZAYN_AC_OK);
    ASSERT_EQ(ozayn_ac_reset(&svc, ""), OZAYN_AC_ERR_INVALID);
    ozayn_ac_service_shutdown(&svc);
    return 0;
}

TEST(test_reset_not_initialized)
{
    ozayn_ac_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ASSERT_EQ(ozayn_ac_reset(&svc, "alice"), OZAYN_AC_ERR_NOT_INITIALIZED);
    return 0;
}

/* ============================================================
 * 20. QUERY NULL CHECKS
 * ============================================================ */

TEST(test_query_null)
{
    ASSERT(!ozayn_ac_service_is_initialized(NULL));
    ASSERT_EQ(ozayn_ac_service_entry_count(NULL), 0);
    ASSERT_EQ(ozayn_ac_get_failure_count(NULL, "alice"), -1);
    ASSERT_EQ(ozayn_ac_get_failure_count(&(ozayn_ac_service_t){0}, NULL), -1);
    ASSERT_EQ(ozayn_ac_get_state(NULL, "alice"), OZAYN_AC_STATE_READY);
    return 0;
}

/* ============================================================
 * 21. ANTI-ENUMERATION
 * ============================================================ */

TEST(test_anti_enumeration_same_response)
{
    ozayn_ac_service_t svc;
    ozayn_ac_service_config_t cfg;
    cfg.policy = ozayn_ac_test_policy();
    ASSERT_EQ(ozayn_ac_service_init(&svc, &cfg), OZAYN_AC_OK);

    ozayn_ac_record_failure(&svc, "alice");
    ozayn_ac_record_failure(&svc, "alice");

    int a1 = 0, r1 = 0;
    ozayn_ac_error_t r = ozayn_ac_check_allowed(&svc, "alice", &a1, &r1);
    ASSERT_EQ(r, OZAYN_AC_ERR_RATE_LIMITED);
    ASSERT_EQ(a1, 0);
    ASSERT_GT(r1, 0);

    int a2 = 0, r2 = 0;
    ozayn_ac_error_t r2_check = ozayn_ac_check_allowed(&svc, "nonexistent", &a2, &r2);
    ASSERT_EQ(r2_check, OZAYN_AC_OK);
    ASSERT_EQ(a2, 1);
    ASSERT_EQ(r2, 0);

    ozayn_ac_service_shutdown(&svc);
    return 0;
}

/* ============================================================
 * 22. DISABLED POLICY — NO RESTRICTIONS
 * ============================================================ */

TEST(test_disabled_policy_no_restriction)
{
    ozayn_ac_service_t svc;
    ozayn_ac_service_config_t cfg;
    cfg.policy = ozayn_ac_default_policy();
    cfg.policy.enabled = 0;
    ASSERT_EQ(ozayn_ac_service_init(&svc, &cfg), OZAYN_AC_OK);

    for (int i = 0; i < 100; i++)
        ASSERT_EQ(ozayn_ac_record_failure(&svc, "alice"), OZAYN_AC_OK);

    int allowed = 0, retry_ms = 0;
    ASSERT_EQ(ozayn_ac_check_allowed(&svc, "alice", &allowed, &retry_ms),
              OZAYN_AC_OK);
    ASSERT_EQ(allowed, 1);
    ASSERT_EQ(retry_ms, 0);
    ozayn_ac_service_shutdown(&svc);
    return 0;
}

/* ============================================================
 * 23. COUNTER OVERFLOW
 * ============================================================ */

TEST(test_counter_overflow)
{
    ozayn_ac_service_t svc;
    ozayn_ac_service_config_t cfg;
    cfg.policy = ozayn_ac_test_policy();
    ASSERT_EQ(ozayn_ac_service_init(&svc, &cfg), OZAYN_AC_OK);

    char id[OZAYN_AC_MAX_ID_LEN];
    for (int i = 0; i < OZAYN_AC_MAX_TRACKED_IDENTITIES; i++) {
        snprintf(id, sizeof(id), "user%d", i);
        ASSERT_EQ(ozayn_ac_record_failure(&svc, id), OZAYN_AC_OK);
    }
    ASSERT_EQ(ozayn_ac_service_entry_count(&svc), OZAYN_AC_MAX_TRACKED_IDENTITIES);

    ASSERT_EQ(ozayn_ac_record_failure(&svc, "overflow"),
              OZAYN_AC_ERR_COUNTER_OVERFLOW);
    ozayn_ac_service_shutdown(&svc);
    return 0;
}

/* ============================================================
 * 24. VERSION INCREMENT
 * ============================================================ */

TEST(test_version_increments)
{
    ozayn_ac_service_t svc;
    ozayn_ac_service_config_t cfg;
    cfg.policy = ozayn_ac_test_policy();
    ASSERT_EQ(ozayn_ac_service_init(&svc, &cfg), OZAYN_AC_OK);

    ozayn_ac_record_failure(&svc, "alice");
    uint32_t v1 = svc.entries[0].version;

    ozayn_ac_record_failure(&svc, "alice");
    uint32_t v2 = svc.entries[0].version;
    ASSERT_GT(v2, v1);

    ozayn_ac_record_success(&svc, "alice");
    uint32_t v3 = svc.entries[0].version;
    ASSERT_GT(v3, v2);
    ozayn_ac_service_shutdown(&svc);
    return 0;
}

/* ============================================================
 * 25. ENTRY REUSE AFTER CLEANUP
 * ============================================================ */

TEST(test_entry_in_use_flag)
{
    ozayn_ac_service_t svc;
    ozayn_ac_service_config_t cfg;
    cfg.policy = ozayn_ac_test_policy();
    ASSERT_EQ(ozayn_ac_service_init(&svc, &cfg), OZAYN_AC_OK);

    ozayn_ac_record_failure(&svc, "alice");
    ASSERT(svc.entries[0].in_use);

    ozayn_ac_reset(&svc, "alice");
    ASSERT(svc.entries[0].in_use);
    ASSERT_EQ(svc.entries[0].failure_count, 0);

    ozayn_ac_service_shutdown(&svc);
    return 0;
}

/* ============================================================
 * 26. SCENARIO — FULL PROTECTION FLOW
 * ============================================================ */

TEST(test_scenario_full_protection_flow)
{
    ozayn_ac_service_t svc;
    ozayn_ac_service_config_t cfg;
    cfg.policy = ozayn_ac_test_policy();
    ASSERT_EQ(ozayn_ac_service_init(&svc, &cfg), OZAYN_AC_OK);

    int allowed = 0, retry_ms = 0;

    ASSERT_EQ(ozayn_ac_check_allowed(&svc, "alice", &allowed, &retry_ms),
              OZAYN_AC_OK);
    ASSERT_EQ(allowed, 1);

    ASSERT_EQ(ozayn_ac_record_failure(&svc, "alice"), OZAYN_AC_OK);
    ASSERT_EQ(ozayn_ac_get_failure_count(&svc, "alice"), 1);

    ASSERT_EQ(ozayn_ac_check_allowed(&svc, "alice", &allowed, &retry_ms),
              OZAYN_AC_ERR_RATE_LIMITED);
    ASSERT_EQ(allowed, 0);

    ASSERT_EQ(ozayn_ac_record_failure(&svc, "alice"), OZAYN_AC_OK);
    ASSERT_EQ(ozayn_ac_record_failure(&svc, "alice"), OZAYN_AC_OK);
    ASSERT_EQ(ozayn_ac_get_state(&svc, "alice"), OZAYN_AC_STATE_BLOCKED);

    ASSERT_EQ(ozayn_ac_check_allowed(&svc, "alice", &allowed, &retry_ms),
              OZAYN_AC_ERR_TEMPORARILY_BLOCKED);
    ASSERT_EQ(allowed, 0);

    ASSERT_EQ(ozayn_ac_reset(&svc, "alice"), OZAYN_AC_OK);
    ASSERT_EQ(ozayn_ac_get_failure_count(&svc, "alice"), 0);

    ASSERT_EQ(ozayn_ac_check_allowed(&svc, "alice", &allowed, &retry_ms),
              OZAYN_AC_OK);
    ASSERT_EQ(allowed, 1);
    ozayn_ac_service_shutdown(&svc);
    return 0;
}

/* ============================================================
 * 27. SCENARIO — SUCCESS RESETS
 * ============================================================ */

TEST(test_scenario_success_resets)
{
    ozayn_ac_service_t svc;
    ozayn_ac_service_config_t cfg;
    cfg.policy = ozayn_ac_test_policy();
    ASSERT_EQ(ozayn_ac_service_init(&svc, &cfg), OZAYN_AC_OK);

    ozayn_ac_record_failure(&svc, "alice");
    ozayn_ac_record_failure(&svc, "alice");
    ASSERT_EQ(ozayn_ac_get_state(&svc, "alice"), OZAYN_AC_STATE_THROTTLED);

    ASSERT_EQ(ozayn_ac_record_success(&svc, "alice"), OZAYN_AC_OK);
    ASSERT_EQ(ozayn_ac_get_failure_count(&svc, "alice"), 0);
    ASSERT_EQ(ozayn_ac_get_state(&svc, "alice"), OZAYN_AC_STATE_READY);

    int allowed = 0, retry_ms = 0;
    ASSERT_EQ(ozayn_ac_check_allowed(&svc, "alice", &allowed, &retry_ms),
              OZAYN_AC_OK);
    ASSERT_EQ(allowed, 1);
    ozayn_ac_service_shutdown(&svc);
    return 0;
}

/* ============================================================
 * 28. SCENARIO — SUCCESSFUL AUTH COMPLETES FLOW
 * ============================================================ */

TEST(test_scenario_successful_auth_completes)
{
    ozayn_ac_service_t svc;
    ozayn_ac_service_config_t cfg;
    cfg.policy = ozayn_ac_test_policy();
    ASSERT_EQ(ozayn_ac_service_init(&svc, &cfg), OZAYN_AC_OK);

    int allowed = 0, retry_ms = 0;

    ASSERT_EQ(ozayn_ac_check_allowed(&svc, "alice", &allowed, &retry_ms),
              OZAYN_AC_OK);
    ASSERT_EQ(allowed, 1);

    ASSERT_EQ(ozayn_ac_record_failure(&svc, "alice"), OZAYN_AC_OK);
    ASSERT_EQ(ozayn_ac_get_state(&svc, "alice"), OZAYN_AC_STATE_THROTTLED);

    ASSERT_EQ(ozayn_ac_check_allowed(&svc, "alice", &allowed, &retry_ms),
              OZAYN_AC_ERR_RATE_LIMITED);
    ASSERT_EQ(allowed, 0);

    ASSERT_EQ(ozayn_ac_record_success(&svc, "alice"), OZAYN_AC_OK);
    ASSERT_EQ(ozayn_ac_get_failure_count(&svc, "alice"), 0);

    ASSERT_EQ(ozayn_ac_check_allowed(&svc, "alice", &allowed, &retry_ms),
              OZAYN_AC_OK);
    ASSERT_EQ(allowed, 1);
    ASSERT_EQ(retry_ms, 0);
    ozayn_ac_service_shutdown(&svc);
    return 0;
}

/* ============================================================
 * 29. WINDOW EXPIRATION
 * ============================================================ */

TEST(test_window_expiration_short)
{
    ozayn_ac_service_t svc;
    ozayn_ac_service_config_t cfg;
    cfg.policy = ozayn_ac_test_policy();
    cfg.policy.window_seconds = 1;
    cfg.policy.initial_delay_ms = 50;
    ASSERT_EQ(ozayn_ac_service_init(&svc, &cfg), OZAYN_AC_OK);

    ASSERT_EQ(ozayn_ac_record_failure(&svc, "alice"), OZAYN_AC_OK);
    ASSERT_EQ(ozayn_ac_record_failure(&svc, "alice"), OZAYN_AC_OK);
    ASSERT_EQ(ozayn_ac_get_failure_count(&svc, "alice"), 2);

    usleep(1500000);
    ASSERT_EQ(ozayn_ac_get_failure_count(&svc, "alice"), 2);

    int allowed = 0, retry_ms = 0;
    ASSERT_EQ(ozayn_ac_check_allowed(&svc, "alice", &allowed, &retry_ms),
              OZAYN_AC_OK);
    ASSERT_EQ(allowed, 1);
    ozayn_ac_service_shutdown(&svc);
    return 0;
}

/* ============================================================
 * 30. STRESS TEST — MANY IDENTITIES
 * ============================================================ */

TEST(test_stress_many_identities)
{
    ozayn_ac_service_t svc;
    ozayn_ac_service_config_t cfg;
    cfg.policy = ozayn_ac_test_policy();
    ASSERT_EQ(ozayn_ac_service_init(&svc, &cfg), OZAYN_AC_OK);

    char id[32];
    for (int i = 0; i < 50; i++) {
        snprintf(id, sizeof(id), "stress_user_%d", i);
        ASSERT_EQ(ozayn_ac_record_failure(&svc, id), OZAYN_AC_OK);
    }
    ASSERT_GE(ozayn_ac_service_entry_count(&svc), 50);

    snprintf(id, sizeof(id), "stress_user_%d", 25);
    ASSERT_EQ(ozayn_ac_get_failure_count(&svc, id), 1);
    ASSERT_EQ(ozayn_ac_get_state(&svc, id), OZAYN_AC_STATE_THROTTLED);

    snprintf(id, sizeof(id), "stress_user_%d", 0);
    int allowed = 0, retry_ms = 0;
    ASSERT_EQ(ozayn_ac_check_allowed(&svc, id, &allowed, &retry_ms),
              OZAYN_AC_ERR_RATE_LIMITED);
    ASSERT_EQ(allowed, 0);
    ozayn_ac_service_shutdown(&svc);
    return 0;
}

/* ============================================================
 * 31. BLOCK TRANSITION
 * ============================================================ */

TEST(test_transition_to_blocked)
{
    ozayn_ac_service_t svc;
    ozayn_ac_service_config_t cfg;
    cfg.policy = ozayn_ac_test_policy();
    ASSERT_EQ(ozayn_ac_service_init(&svc, &cfg), OZAYN_AC_OK);

    ASSERT_EQ(ozayn_ac_record_failure(&svc, "alice"), OZAYN_AC_OK);
    ASSERT_EQ(ozayn_ac_get_state(&svc, "alice"), OZAYN_AC_STATE_THROTTLED);

    ASSERT_EQ(ozayn_ac_record_failure(&svc, "alice"), OZAYN_AC_OK);
    ASSERT_EQ(ozayn_ac_get_state(&svc, "alice"), OZAYN_AC_STATE_THROTTLED);

    ASSERT_EQ(ozayn_ac_record_failure(&svc, "alice"), OZAYN_AC_OK);
    ASSERT_EQ(ozayn_ac_get_state(&svc, "alice"), OZAYN_AC_STATE_BLOCKED);
    ozayn_ac_service_shutdown(&svc);
    return 0;
}

/* ============================================================
 * RUN SUITE
 * ============================================================ */

int run_attempt_control_tests(void)
{
    SUITE_BEGIN("Attempt Control");

    RUN(test_default_policy_valid);
    RUN(test_default_policy_validates);
    RUN(test_test_policy_valid);
    RUN(test_test_policy_validates);
    RUN(test_service_init_null);
    RUN(test_service_init_defaults);
    RUN(test_service_init_invalid_policy);
    RUN(test_service_shutdown);
    RUN(test_service_shutdown_null);
    RUN(test_check_allowed_no_failures);
    RUN(test_check_allowed_unknown_identity);
    RUN(test_check_allowed_disabled_policy);
    RUN(test_record_failure_basic);
    RUN(test_record_failure_multiple);
    RUN(test_record_failure_null);
    RUN(test_record_failure_empty_id);
    RUN(test_record_failure_not_initialized);
    RUN(test_check_allowed_rate_limited);
    RUN(test_check_allowed_blocked);
    RUN(test_record_success_resets_failures);
    RUN(test_record_success_unknown_identity);
    RUN(test_reset);
    RUN(test_reset_unknown_identity);
    RUN(test_progressive_backoff);
    RUN(test_backoff_max_cap);
    RUN(test_multiple_identities_isolated);
    RUN(test_entry_count_tracking);
    RUN(test_state_name);
    RUN(test_error_name);
    RUN(test_validate_state_valid);
    RUN(test_validate_state_invalid);
    RUN(test_validate_policy_null);
    RUN(test_validate_policy_disabled);
    RUN(test_init_null_service);
    RUN(test_init_null_config);
    RUN(test_check_allowed_null);
    RUN(test_check_allowed_empty_id);
    RUN(test_check_allowed_not_initialized);
    RUN(test_record_success_null);
    RUN(test_record_success_empty_id);
    RUN(test_reset_null);
    RUN(test_reset_empty_id);
    RUN(test_reset_not_initialized);
    RUN(test_query_null);
    RUN(test_anti_enumeration_same_response);
    RUN(test_disabled_policy_no_restriction);
    RUN(test_counter_overflow);
    RUN(test_version_increments);
    RUN(test_entry_in_use_flag);
    RUN(test_scenario_full_protection_flow);
    RUN(test_scenario_success_resets);
    RUN(test_scenario_successful_auth_completes);
    RUN(test_window_expiration_short);
    RUN(test_stress_many_identities);
    RUN(test_transition_to_blocked);

    SUITE_END();
    return _tf_suite_fail;
}
