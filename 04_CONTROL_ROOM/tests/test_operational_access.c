/*
 * test_operational_access.c — Section 04, Step 28
 * Operational Access, Session & Command Authority Management tests
 */

#include "../../tests/test_framework.h"
#include "../operational_access.h"
#include <string.h>

TEST(test_err_name) {
    ASSERT(strcmp(ozayn_oac_err_name(OZAYN_OAC_OK), "OK") == 0);
    ASSERT(strcmp(ozayn_oac_err_name(OZAYN_OAC_ERR_NULL), "NULL") == 0);
    ASSERT(strcmp(ozayn_oac_err_name(OZAYN_OAC_ERR_NOT_INITIALIZED), "NOT_INITIALIZED") == 0);
    ASSERT(strcmp(ozayn_oac_err_name(OZAYN_OAC_ERR_ACCESS_DENIED), "ACCESS_DENIED") == 0);
    ASSERT(strcmp(ozayn_oac_err_name(OZAYN_OAC_ERR_SESSION_EXPIRED), "SESSION_EXPIRED") == 0);
    ASSERT(strcmp(ozayn_oac_err_name(OZAYN_OAC_ERR_AUTHORITY_CONSUMED), "AUTHORITY_CONSUMED") == 0);
    ASSERT(strcmp(ozayn_oac_err_name(OZAYN_OAC_ERR_IDENTITY_MISMATCH), "IDENTITY_MISMATCH") == 0);
    ASSERT(strcmp(ozayn_oac_err_name(OZAYN_OAC_ERR_PERMISSION_DENIED), "PERMISSION_DENIED") == 0);
    return 0;
}

TEST(test_level_name) {
    ASSERT(strcmp(ozayn_oac_access_level_name(OZAYN_OAC_LEVEL_NONE), "NONE") == 0);
    ASSERT(strcmp(ozayn_oac_access_level_name(OZAYN_OAC_LEVEL_OBSERVE), "OBSERVE") == 0);
    ASSERT(strcmp(ozayn_oac_access_level_name(OZAYN_OAC_LEVEL_DIAGNOSTIC), "DIAGNOSTIC") == 0);
    ASSERT(strcmp(ozayn_oac_access_level_name(OZAYN_OAC_LEVEL_OPERATE), "OPERATE") == 0);
    ASSERT(strcmp(ozayn_oac_access_level_name(OZAYN_OAC_LEVEL_ADMIN), "ADMIN") == 0);
    return 0;
}

TEST(test_ctx_state_name) {
    ASSERT(strcmp(ozayn_oac_ctx_state_name(OZAYN_OAC_CTX_CREATED), "CREATED") == 0);
    ASSERT(strcmp(ozayn_oac_ctx_state_name(OZAYN_OAC_CTX_ACTIVE), "ACTIVE") == 0);
    ASSERT(strcmp(ozayn_oac_ctx_state_name(OZAYN_OAC_CTX_VALIDATED), "VALIDATED") == 0);
    ASSERT(strcmp(ozayn_oac_ctx_state_name(OZAYN_OAC_CTX_EXPIRED), "EXPIRED") == 0);
    ASSERT(strcmp(ozayn_oac_ctx_state_name(OZAYN_OAC_CTX_REVOKED), "REVOKED") == 0);
    ASSERT(strcmp(ozayn_oac_ctx_state_name(OZAYN_OAC_CTX_TERMINATED), "TERMINATED") == 0);
    return 0;
}

TEST(test_auth_state_name) {
    ASSERT(strcmp(ozayn_oac_auth_state_name(OZAYN_OAC_AUTH_REQUESTED), "REQUESTED") == 0);
    ASSERT(strcmp(ozayn_oac_auth_state_name(OZAYN_OAC_AUTH_VALIDATING), "VALIDATING") == 0);
    ASSERT(strcmp(ozayn_oac_auth_state_name(OZAYN_OAC_AUTH_AUTHORIZED), "AUTHORIZED") == 0);
    ASSERT(strcmp(ozayn_oac_auth_state_name(OZAYN_OAC_AUTH_DENIED), "DENIED") == 0);
    ASSERT(strcmp(ozayn_oac_auth_state_name(OZAYN_OAC_AUTH_EXPIRED), "EXPIRED") == 0);
    ASSERT(strcmp(ozayn_oac_auth_state_name(OZAYN_OAC_AUTH_REVOKED), "REVOKED") == 0);
    ASSERT(strcmp(ozayn_oac_auth_state_name(OZAYN_OAC_AUTH_CONSUMED), "CONSUMED") == 0);
    ASSERT(strcmp(ozayn_oac_auth_state_name(OZAYN_OAC_AUTH_CANCELLED), "CANCELLED") == 0);
    return 0;
}

TEST(test_scope_type_name) {
    ASSERT(strcmp(ozayn_oac_scope_type_name(OZAYN_OAC_SCOPE_SYSTEM_WIDE), "SYSTEM_WIDE") == 0);
    ASSERT(strcmp(ozayn_oac_scope_type_name(OZAYN_OAC_SCOPE_COMPONENT_SPECIFIC), "COMPONENT_SPECIFIC") == 0);
    ASSERT(strcmp(ozayn_oac_scope_type_name(OZAYN_OAC_SCOPE_OPERATION_SPECIFIC), "OPERATION_SPECIFIC") == 0);
    return 0;
}

TEST(test_event_type_name) {
    ASSERT(strcmp(ozayn_oac_event_type_name(OZAYN_OAC_EVT_ACCESS_CREATED), "ACCESS_CREATED") == 0);
    ASSERT(strcmp(ozayn_oac_event_type_name(OZAYN_OAC_EVT_AUTHORITY_GRANTED), "AUTHORITY_GRANTED") == 0);
    ASSERT(strcmp(ozayn_oac_event_type_name(OZAYN_OAC_EVT_DUPLICATE_ATTEMPT), "DUPLICATE_ATTEMPT") == 0);
    ASSERT(strcmp(ozayn_oac_event_type_name(OZAYN_OAC_EVT_SESSION_INVALIDATED), "SESSION_INVALIDATED") == 0);
    ASSERT(strcmp(ozayn_oac_event_type_name(OZAYN_OAC_EVT_MODE_CHANGE_INVALIDATED), "MODE_CHANGE_INVALIDATED") == 0);
    return 0;
}

TEST(test_ctx_transitions_valid) {
    ASSERT(ozayn_oac_ctx_state_transition_valid(OZAYN_OAC_CTX_CREATED, OZAYN_OAC_CTX_ACTIVE));
    ASSERT(ozayn_oac_ctx_state_transition_valid(OZAYN_OAC_CTX_CREATED, OZAYN_OAC_CTX_TERMINATED));
    ASSERT(ozayn_oac_ctx_state_transition_valid(OZAYN_OAC_CTX_ACTIVE, OZAYN_OAC_CTX_VALIDATED));
    ASSERT(ozayn_oac_ctx_state_transition_valid(OZAYN_OAC_CTX_ACTIVE, OZAYN_OAC_CTX_EXPIRED));
    ASSERT(ozayn_oac_ctx_state_transition_valid(OZAYN_OAC_CTX_ACTIVE, OZAYN_OAC_CTX_REVOKED));
    ASSERT(ozayn_oac_ctx_state_transition_valid(OZAYN_OAC_CTX_VALIDATED, OZAYN_OAC_CTX_ACTIVE));
    ASSERT(ozayn_oac_ctx_state_transition_valid(OZAYN_OAC_CTX_VALIDATED, OZAYN_OAC_CTX_EXPIRED));
    ASSERT(ozayn_oac_ctx_state_transition_valid(OZAYN_OAC_CTX_VALIDATED, OZAYN_OAC_CTX_REVOKED));
    return 0;
}

TEST(test_ctx_transitions_invalid) {
    ASSERT(!ozayn_oac_ctx_state_transition_valid(OZAYN_OAC_CTX_EXPIRED, OZAYN_OAC_CTX_ACTIVE));
    ASSERT(!ozayn_oac_ctx_state_transition_valid(OZAYN_OAC_CTX_REVOKED, OZAYN_OAC_CTX_ACTIVE));
    ASSERT(!ozayn_oac_ctx_state_transition_valid(OZAYN_OAC_CTX_TERMINATED, OZAYN_OAC_CTX_ACTIVE));
    ASSERT(!ozayn_oac_ctx_state_transition_valid(OZAYN_OAC_CTX_CREATED, OZAYN_OAC_CTX_VALIDATED));
    return 0;
}

TEST(test_auth_transitions_valid) {
    ASSERT(ozayn_oac_auth_state_transition_valid(OZAYN_OAC_AUTH_REQUESTED, OZAYN_OAC_AUTH_VALIDATING));
    ASSERT(ozayn_oac_auth_state_transition_valid(OZAYN_OAC_AUTH_REQUESTED, OZAYN_OAC_AUTH_DENIED));
    ASSERT(ozayn_oac_auth_state_transition_valid(OZAYN_OAC_AUTH_REQUESTED, OZAYN_OAC_AUTH_CANCELLED));
    ASSERT(ozayn_oac_auth_state_transition_valid(OZAYN_OAC_AUTH_VALIDATING, OZAYN_OAC_AUTH_AUTHORIZED));
    ASSERT(ozayn_oac_auth_state_transition_valid(OZAYN_OAC_AUTH_AUTHORIZED, OZAYN_OAC_AUTH_CONSUMED));
    ASSERT(ozayn_oac_auth_state_transition_valid(OZAYN_OAC_AUTH_AUTHORIZED, OZAYN_OAC_AUTH_EXPIRED));
    ASSERT(ozayn_oac_auth_state_transition_valid(OZAYN_OAC_AUTH_AUTHORIZED, OZAYN_OAC_AUTH_REVOKED));
    return 0;
}

TEST(test_auth_transitions_invalid) {
    ASSERT(!ozayn_oac_auth_state_transition_valid(OZAYN_OAC_AUTH_DENIED, OZAYN_OAC_AUTH_AUTHORIZED));
    ASSERT(!ozayn_oac_auth_state_transition_valid(OZAYN_OAC_AUTH_EXPIRED, OZAYN_OAC_AUTH_AUTHORIZED));
    ASSERT(!ozayn_oac_auth_state_transition_valid(OZAYN_OAC_AUTH_REVOKED, OZAYN_OAC_AUTH_AUTHORIZED));
    ASSERT(!ozayn_oac_auth_state_transition_valid(OZAYN_OAC_AUTH_CONSUMED, OZAYN_OAC_AUTH_AUTHORIZED));
    ASSERT(!ozayn_oac_auth_state_transition_valid(OZAYN_OAC_AUTH_CANCELLED, OZAYN_OAC_AUTH_AUTHORIZED));
    return 0;
}

TEST(test_init_null) {
    ASSERT_EQ(ozayn_oac_init(NULL), OZAYN_OAC_ERR_NULL);
    return 0;
}

TEST(test_init_basic) {
    ozayn_oac_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ASSERT_EQ(ozayn_oac_init(&svc), OZAYN_OAC_OK);
    ASSERT(svc.initialized);
    ASSERT_EQ(svc.context_count, 0);
    ASSERT_EQ(svc.authority_count, 0);
    ozayn_oac_shutdown(&svc);
    return 0;
}

TEST(test_init_double) {
    ozayn_oac_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_oac_init(&svc);
    ASSERT_EQ(ozayn_oac_init(&svc), OZAYN_OAC_ERR_ALREADY_INITIALIZED);
    ozayn_oac_shutdown(&svc);
    return 0;
}

TEST(test_shutdown_null) {
    ASSERT_EQ(ozayn_oac_shutdown(NULL), OZAYN_OAC_ERR_NULL);
    return 0;
}

TEST(test_shutdown_basic) {
    ozayn_oac_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_oac_init(&svc);
    ASSERT_EQ(ozayn_oac_shutdown(&svc), OZAYN_OAC_OK);
    ASSERT(!svc.initialized);
    return 0;
}

TEST(test_is_initialized) {
    ASSERT(!ozayn_oac_is_initialized(NULL));
    ozayn_oac_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ASSERT(!ozayn_oac_is_initialized(&svc));
    ozayn_oac_init(&svc);
    ASSERT(ozayn_oac_is_initialized(&svc));
    ozayn_oac_shutdown(&svc);
    return 0;
}

TEST(test_bind_subsystems) {
    ozayn_oac_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_oac_init(&svc);
    ozayn_oac_subsys_bind_t bind;
    memset(&bind, 0, sizeof(bind));
    ASSERT_EQ(ozayn_oac_bind_subsystems(&svc, &bind), OZAYN_OAC_OK);
    ASSERT_EQ(ozayn_oac_bind_subsystems(0, &bind), OZAYN_OAC_ERR_NULL);
    ASSERT_EQ(ozayn_oac_bind_subsystems(&svc, 0), OZAYN_OAC_ERR_NULL);
    ozayn_oac_shutdown(&svc);
    return 0;
}

TEST(test_context_create) {
    ozayn_oac_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_oac_init(&svc);
    uint64_t ctx_id = 0;
    ASSERT_EQ(ozayn_oac_context_create(&svc, "user-1", "sess-1", "authz-1",
              OZAYN_OAC_LEVEL_OPERATE, OZAYN_OAC_SCOPE_SYSTEM_WIDE, "",
              3600, &ctx_id), OZAYN_OAC_OK);
    ASSERT(ctx_id > 0);
    ASSERT_EQ(svc.context_count, 1);
    ASSERT_EQ(svc.stats.total_access_contexts_created, (uint64_t)1);
    ASSERT_EQ(svc.stats.current_active_contexts, (uint32_t)1);
    const ozayn_oac_access_ctx_t *ctx = 0;
    ASSERT_EQ(ozayn_oac_context_get(&svc, ctx_id, &ctx), OZAYN_OAC_OK);
    ASSERT(strcmp(ctx->identity_id, "user-1") == 0);
    ASSERT(strcmp(ctx->session_id, "sess-1") == 0);
    ASSERT(strcmp(ctx->authorization_ref, "authz-1") == 0);
    ASSERT_EQ(ctx->access_level, OZAYN_OAC_LEVEL_OPERATE);
    ASSERT_EQ(ctx->scope_type, OZAYN_OAC_SCOPE_SYSTEM_WIDE);
    ASSERT_EQ(ctx->state, OZAYN_OAC_CTX_ACTIVE);
    ozayn_oac_shutdown(&svc);
    return 0;
}

TEST(test_context_create_null) {
    ASSERT_EQ(ozayn_oac_context_create(0, "u", "s", 0, OZAYN_OAC_LEVEL_NONE,
              OZAYN_OAC_SCOPE_SYSTEM_WIDE, 0, 0, 0), OZAYN_OAC_ERR_NULL);
    ozayn_oac_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ASSERT_EQ(ozayn_oac_context_create(&svc, 0, "s", 0, OZAYN_OAC_LEVEL_NONE,
              OZAYN_OAC_SCOPE_SYSTEM_WIDE, 0, 0, 0), OZAYN_OAC_ERR_NOT_INITIALIZED);
    ozayn_oac_init(&svc);
    ASSERT_EQ(ozayn_oac_context_create(&svc, 0, "s", 0, OZAYN_OAC_LEVEL_NONE,
              OZAYN_OAC_SCOPE_SYSTEM_WIDE, 0, 0, 0), OZAYN_OAC_ERR_INVALID_PARAM);
    ozayn_oac_shutdown(&svc);
    return 0;
}

TEST(test_context_validate) {
    ozayn_oac_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_oac_init(&svc);
    uint64_t ctx_id = 0;
    ozayn_oac_context_create(&svc, "user-1", "sess-1", 0,
              OZAYN_OAC_LEVEL_DIAGNOSTIC, OZAYN_OAC_SCOPE_COMPONENT_SPECIFIC, "comp-1",
              3600, &ctx_id);
    ASSERT_EQ(ozayn_oac_context_validate(&svc, ctx_id), OZAYN_OAC_OK);
    const ozayn_oac_access_ctx_t *ctx;
    ozayn_oac_context_get(&svc, ctx_id, &ctx);
    ASSERT_EQ(ctx->state, OZAYN_OAC_CTX_VALIDATED);
    ASSERT_EQ(ctx->validation_count, 1);
    ASSERT_EQ(svc.stats.total_validations, (uint64_t)1);
    ozayn_oac_shutdown(&svc);
    return 0;
}

TEST(test_context_validate_expired) {
    ozayn_oac_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_oac_init(&svc);
    uint64_t ctx_id = 0;
    ozayn_oac_context_create(&svc, "user-1", "sess-1", 0,
              OZAYN_OAC_LEVEL_NONE, OZAYN_OAC_SCOPE_SYSTEM_WIDE, 0, 1, &ctx_id);
    svc.contexts[0].expiration_time = 1;
    ASSERT_EQ(ozayn_oac_context_validate(&svc, ctx_id), OZAYN_OAC_ERR_ACCESS_EXPIRED);
    ASSERT_EQ(svc.stats.total_access_expired, (uint64_t)1);
    ozayn_oac_shutdown(&svc);
    return 0;
}

TEST(test_context_expire) {
    ozayn_oac_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_oac_init(&svc);
    uint64_t ctx_id = 0;
    ozayn_oac_context_create(&svc, "user-1", "sess-1", 0,
              OZAYN_OAC_LEVEL_NONE, OZAYN_OAC_SCOPE_SYSTEM_WIDE, 0, 3600, &ctx_id);
    ASSERT_EQ(ozayn_oac_context_expire(&svc, ctx_id), OZAYN_OAC_OK);
    const ozayn_oac_access_ctx_t *ctx;
    ozayn_oac_context_get(&svc, ctx_id, &ctx);
    ASSERT_EQ(ctx->state, OZAYN_OAC_CTX_EXPIRED);
    ASSERT_EQ(svc.stats.current_active_contexts, (uint32_t)0);
    ozayn_oac_shutdown(&svc);
    return 0;
}

TEST(test_context_revoke) {
    ozayn_oac_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_oac_init(&svc);
    uint64_t ctx_id = 0;
    ozayn_oac_context_create(&svc, "user-1", "sess-1", 0,
              OZAYN_OAC_LEVEL_NONE, OZAYN_OAC_SCOPE_SYSTEM_WIDE, 0, 3600, &ctx_id);
    ASSERT_EQ(ozayn_oac_context_revoke(&svc, ctx_id), OZAYN_OAC_OK);
    const ozayn_oac_access_ctx_t *ctx;
    ozayn_oac_context_get(&svc, ctx_id, &ctx);
    ASSERT_EQ(ctx->state, OZAYN_OAC_CTX_REVOKED);
    ASSERT_EQ(svc.stats.total_access_revoked, (uint64_t)1);
    ozayn_oac_shutdown(&svc);
    return 0;
}

TEST(test_context_terminate) {
    ozayn_oac_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_oac_init(&svc);
    uint64_t ctx_id = 0;
    ozayn_oac_context_create(&svc, "user-1", "sess-1", 0,
              OZAYN_OAC_LEVEL_NONE, OZAYN_OAC_SCOPE_SYSTEM_WIDE, 0, 3600, &ctx_id);
    ASSERT_EQ(ozayn_oac_context_terminate(&svc, ctx_id), OZAYN_OAC_OK);
    const ozayn_oac_access_ctx_t *ctx;
    ozayn_oac_context_get(&svc, ctx_id, &ctx);
    ASSERT_EQ(ctx->state, OZAYN_OAC_CTX_TERMINATED);
    ozayn_oac_shutdown(&svc);
    return 0;
}

TEST(test_context_invalid_transition) {
    ozayn_oac_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_oac_init(&svc);
    uint64_t ctx_id = 0;
    ozayn_oac_context_create(&svc, "user-1", "sess-1", 0,
              OZAYN_OAC_LEVEL_NONE, OZAYN_OAC_SCOPE_SYSTEM_WIDE, 0, 3600, &ctx_id);
    ASSERT_EQ(ozayn_oac_context_expire(&svc, ctx_id), OZAYN_OAC_OK);
    ASSERT_EQ(ozayn_oac_context_validate(&svc, ctx_id), OZAYN_OAC_ERR_ACCESS_DENIED);
    ASSERT_EQ(ozayn_oac_context_revoke(&svc, ctx_id), OZAYN_OAC_ERR_STATE_TRANSITION);
    ozayn_oac_shutdown(&svc);
    return 0;
}

TEST(test_context_counts) {
    ozayn_oac_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ASSERT_EQ(ozayn_oac_context_active_count(&svc), -1);
    ASSERT_EQ(ozayn_oac_context_total_count(&svc), -1);
    ozayn_oac_init(&svc);
    ASSERT_EQ(ozayn_oac_context_active_count(&svc), 0);
    uint64_t c1 = 0, c2 = 0;
    ozayn_oac_context_create(&svc, "u", "s", 0, OZAYN_OAC_LEVEL_NONE,
              OZAYN_OAC_SCOPE_SYSTEM_WIDE, 0, 3600, &c1);
    ozayn_oac_context_create(&svc, "u", "s2", 0, OZAYN_OAC_LEVEL_NONE,
              OZAYN_OAC_SCOPE_SYSTEM_WIDE, 0, 3600, &c2);
    ASSERT_EQ(svc.context_count, 2);
    ASSERT_EQ(ozayn_oac_context_active_count(&svc), 2);
    ozayn_oac_context_expire(&svc, c1);
    ASSERT_EQ(ozayn_oac_context_active_count(&svc), 1);
    ozayn_oac_shutdown(&svc);
    return 0;
}

TEST(test_context_list_by_identity) {
    ozayn_oac_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_oac_init(&svc);
    uint64_t c1 = 0, c2 = 0, c3 = 0;
    ozayn_oac_context_create(&svc, "alice", "s1", 0, OZAYN_OAC_LEVEL_NONE,
              OZAYN_OAC_SCOPE_SYSTEM_WIDE, 0, 3600, &c1);
    ozayn_oac_context_create(&svc, "bob", "s2", 0, OZAYN_OAC_LEVEL_NONE,
              OZAYN_OAC_SCOPE_SYSTEM_WIDE, 0, 3600, &c2);
    ozayn_oac_context_create(&svc, "alice", "s3", 0, OZAYN_OAC_LEVEL_NONE,
              OZAYN_OAC_SCOPE_SYSTEM_WIDE, 0, 3600, &c3);
    const ozayn_oac_access_ctx_t *results[10];
    uint32_t count = 0;
    ASSERT_EQ(ozayn_oac_context_list_by_identity(&svc, "alice", results, 10, &count), OZAYN_OAC_OK);
    ASSERT_EQ(count, (uint32_t)2);
    ASSERT_EQ(ozayn_oac_context_list_by_identity(&svc, "bob", results, 10, &count), OZAYN_OAC_OK);
    ASSERT_EQ(count, (uint32_t)1);
    ozayn_oac_shutdown(&svc);
    return 0;
}

TEST(test_authority_create) {
    ozayn_oac_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_oac_init(&svc);
    uint64_t ctx_id = 0;
    ozayn_oac_context_create(&svc, "user-1", "sess-1", "authz-1",
              OZAYN_OAC_LEVEL_OPERATE, OZAYN_OAC_SCOPE_SYSTEM_WIDE, 0, 3600, &ctx_id);
    ozayn_oac_context_validate(&svc, ctx_id);
    uint64_t auth_id = 0;
    ASSERT_EQ(ozayn_oac_authority_create(&svc, ctx_id, "req-1", "op-1",
              "comp-x", "cap-y", "start", "perm-1", 600, &auth_id), OZAYN_OAC_OK);
    ASSERT(auth_id > 0);
    ASSERT_EQ(svc.authority_count, 1);
    ASSERT_EQ(svc.stats.total_authorities_created, (uint64_t)1);
    const ozayn_oac_authority_t *auth = 0;
    ASSERT_EQ(ozayn_oac_authority_get(&svc, auth_id, &auth), OZAYN_OAC_OK);
    ASSERT(strcmp(auth->identity_id, "user-1") == 0);
    ASSERT(strcmp(auth->session_id, "sess-1") == 0);
    ASSERT(strcmp(auth->request_id, "req-1") == 0);
    ASSERT(strcmp(auth->operation_id, "op-1") == 0);
    ASSERT(strcmp(auth->target, "comp-x") == 0);
    ASSERT(strcmp(auth->capability, "cap-y") == 0);
    ASSERT(strcmp(auth->action, "start") == 0);
    ASSERT(strcmp(auth->required_permission, "perm-1") == 0);
    ASSERT_EQ(auth->state, OZAYN_OAC_AUTH_REQUESTED);
    ASSERT(!auth->consumed);
    ozayn_oac_shutdown(&svc);
    return 0;
}

TEST(test_authority_create_invalid_context) {
    ozayn_oac_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_oac_init(&svc);
    uint64_t auth_id = 0;
    ASSERT_EQ(ozayn_oac_authority_create(&svc, 999, "req-1", "op-1",
              0, 0, 0, 0, 600, &auth_id), OZAYN_OAC_ERR_ACCESS_INVALID);
    ozayn_oac_shutdown(&svc);
    return 0;
}

TEST(test_authority_create_expired_context) {
    ozayn_oac_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_oac_init(&svc);
    uint64_t ctx_id = 0;
    ozayn_oac_context_create(&svc, "user-1", "sess-1", 0,
              OZAYN_OAC_LEVEL_NONE, OZAYN_OAC_SCOPE_SYSTEM_WIDE, 0, 1, &ctx_id);
    svc.contexts[0].expiration_time = 1;
    uint64_t auth_id = 0;
    ASSERT_EQ(ozayn_oac_authority_create(&svc, ctx_id, "req-1", "op-1",
              0, 0, 0, 0, 600, &auth_id), OZAYN_OAC_ERR_ACCESS_EXPIRED);
    ozayn_oac_shutdown(&svc);
    return 0;
}

TEST(test_authority_validate) {
    ozayn_oac_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_oac_init(&svc);
    uint64_t ctx_id = 0;
    ozayn_oac_context_create(&svc, "user-1", "sess-1", "authz-1",
              OZAYN_OAC_LEVEL_OPERATE, OZAYN_OAC_SCOPE_SYSTEM_WIDE, 0, 3600, &ctx_id);
    uint64_t auth_id = 0;
    ozayn_oac_authority_create(&svc, ctx_id, "req-1", "op-1",
              "comp-x", "cap-y", "start", "perm-1", 600, &auth_id);
    ASSERT_EQ(ozayn_oac_authority_validate(&svc, auth_id, "req-1", "op-1", "sess-1", "user-1"), OZAYN_OAC_OK);
    const ozayn_oac_authority_t *auth;
    ozayn_oac_authority_get(&svc, auth_id, &auth);
    ASSERT_EQ(auth->state, OZAYN_OAC_AUTH_AUTHORIZED);
    ASSERT_EQ(svc.stats.total_authorities_granted, (uint64_t)1);
    ozayn_oac_shutdown(&svc);
    return 0;
}

TEST(test_authority_validate_session_mismatch) {
    ozayn_oac_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_oac_init(&svc);
    uint64_t ctx_id = 0;
    ozayn_oac_context_create(&svc, "user-1", "sess-1", 0,
              OZAYN_OAC_LEVEL_NONE, OZAYN_OAC_SCOPE_SYSTEM_WIDE, 0, 3600, &ctx_id);
    uint64_t auth_id = 0;
    ozayn_oac_authority_create(&svc, ctx_id, "req-1", "op-1",
              0, 0, 0, 0, 600, &auth_id);
    ASSERT_EQ(ozayn_oac_authority_validate(&svc, auth_id, "req-1", "op-1", "wrong-sess", "user-1"),
              OZAYN_OAC_ERR_SESSION_MISMATCH);
    ozayn_oac_shutdown(&svc);
    return 0;
}

TEST(test_authority_validate_identity_mismatch) {
    ozayn_oac_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_oac_init(&svc);
    uint64_t ctx_id = 0;
    ozayn_oac_context_create(&svc, "user-1", "sess-1", 0,
              OZAYN_OAC_LEVEL_NONE, OZAYN_OAC_SCOPE_SYSTEM_WIDE, 0, 3600, &ctx_id);
    uint64_t auth_id = 0;
    ozayn_oac_authority_create(&svc, ctx_id, "req-1", "op-1",
              0, 0, 0, 0, 600, &auth_id);
    ASSERT_EQ(ozayn_oac_authority_validate(&svc, auth_id, "req-1", "op-1", "sess-1", "wrong-user"),
              OZAYN_OAC_ERR_IDENTITY_MISMATCH);
    ozayn_oac_shutdown(&svc);
    return 0;
}

TEST(test_authority_validate_operation_mismatch) {
    ozayn_oac_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_oac_init(&svc);
    uint64_t ctx_id = 0;
    ozayn_oac_context_create(&svc, "user-1", "sess-1", 0,
              OZAYN_OAC_LEVEL_NONE, OZAYN_OAC_SCOPE_SYSTEM_WIDE, 0, 3600, &ctx_id);
    uint64_t auth_id = 0;
    ozayn_oac_authority_create(&svc, ctx_id, "req-1", "op-1",
              0, 0, 0, 0, 600, &auth_id);
    ASSERT_EQ(ozayn_oac_authority_validate(&svc, auth_id, "req-1", "wrong-op", "sess-1", "user-1"),
              OZAYN_OAC_ERR_AUTHORITY_MISMATCH);
    ozayn_oac_shutdown(&svc);
    return 0;
}

TEST(test_authority_validate_expired) {
    ozayn_oac_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_oac_init(&svc);
    uint64_t ctx_id = 0;
    ozayn_oac_context_create(&svc, "user-1", "sess-1", 0,
              OZAYN_OAC_LEVEL_NONE, OZAYN_OAC_SCOPE_SYSTEM_WIDE, 0, 3600, &ctx_id);
    uint64_t auth_id = 0;
    ozayn_oac_authority_create(&svc, ctx_id, "req-1", "op-1",
              0, 0, 0, 0, 1, &auth_id);
    svc.authorities[0].expiration_time = 1;
    ASSERT_EQ(ozayn_oac_authority_validate(&svc, auth_id, "req-1", "op-1", "sess-1", "user-1"),
              OZAYN_OAC_ERR_AUTHORITY_EXPIRED);
    ozayn_oac_shutdown(&svc);
    return 0;
}

TEST(test_authority_consume) {
    ozayn_oac_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_oac_init(&svc);
    uint64_t ctx_id = 0;
    ozayn_oac_context_create(&svc, "user-1", "sess-1", 0,
              OZAYN_OAC_LEVEL_NONE, OZAYN_OAC_SCOPE_SYSTEM_WIDE, 0, 3600, &ctx_id);
    uint64_t auth_id = 0;
    ozayn_oac_authority_create(&svc, ctx_id, "req-1", "op-1",
              0, 0, 0, 0, 600, &auth_id);
    ozayn_oac_authority_validate(&svc, auth_id, "req-1", "op-1", "sess-1", "user-1");
    ASSERT_EQ(ozayn_oac_authority_consume(&svc, auth_id), OZAYN_OAC_OK);
    const ozayn_oac_authority_t *auth;
    ozayn_oac_authority_get(&svc, auth_id, &auth);
    ASSERT_EQ(auth->state, OZAYN_OAC_AUTH_CONSUMED);
    ASSERT(auth->consumed);
    ASSERT_EQ(svc.stats.total_authorities_consumed, (uint64_t)1);
    ozayn_oac_shutdown(&svc);
    return 0;
}

TEST(test_authority_consume_duplicate) {
    ozayn_oac_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_oac_init(&svc);
    uint64_t ctx_id = 0;
    ozayn_oac_context_create(&svc, "user-1", "sess-1", 0,
              OZAYN_OAC_LEVEL_NONE, OZAYN_OAC_SCOPE_SYSTEM_WIDE, 0, 3600, &ctx_id);
    uint64_t auth_id = 0;
    ozayn_oac_authority_create(&svc, ctx_id, "req-1", "op-1",
              0, 0, 0, 0, 600, &auth_id);
    ozayn_oac_authority_validate(&svc, auth_id, "req-1", "op-1", "sess-1", "user-1");
    ASSERT_EQ(ozayn_oac_authority_consume(&svc, auth_id), OZAYN_OAC_OK);
    ASSERT_EQ(ozayn_oac_authority_consume(&svc, auth_id), OZAYN_OAC_ERR_AUTHORITY_CONSUMED);
    ASSERT_EQ(svc.stats.total_duplicate_authority_attempts, (uint64_t)1);
    ozayn_oac_shutdown(&svc);
    return 0;
}

TEST(test_authority_consume_not_authorized) {
    ozayn_oac_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_oac_init(&svc);
    uint64_t ctx_id = 0;
    ozayn_oac_context_create(&svc, "user-1", "sess-1", 0,
              OZAYN_OAC_LEVEL_NONE, OZAYN_OAC_SCOPE_SYSTEM_WIDE, 0, 3600, &ctx_id);
    uint64_t auth_id = 0;
    ozayn_oac_authority_create(&svc, ctx_id, "req-1", "op-1",
              0, 0, 0, 0, 600, &auth_id);
    ASSERT_EQ(ozayn_oac_authority_consume(&svc, auth_id), OZAYN_OAC_ERR_AUTHORITY_INVALID);
    ozayn_oac_shutdown(&svc);
    return 0;
}

TEST(test_authority_expire) {
    ozayn_oac_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_oac_init(&svc);
    uint64_t ctx_id = 0;
    ozayn_oac_context_create(&svc, "user-1", "sess-1", 0,
              OZAYN_OAC_LEVEL_NONE, OZAYN_OAC_SCOPE_SYSTEM_WIDE, 0, 3600, &ctx_id);
    uint64_t auth_id = 0;
    ozayn_oac_authority_create(&svc, ctx_id, "req-1", "op-1",
              0, 0, 0, 0, 600, &auth_id);
    ASSERT_EQ(ozayn_oac_authority_expire(&svc, auth_id), OZAYN_OAC_OK);
    const ozayn_oac_authority_t *auth;
    ozayn_oac_authority_get(&svc, auth_id, &auth);
    ASSERT_EQ(auth->state, OZAYN_OAC_AUTH_EXPIRED);
    ASSERT_EQ(svc.stats.total_authorities_expired, (uint64_t)1);
    ozayn_oac_shutdown(&svc);
    return 0;
}

TEST(test_authority_revoke) {
    ozayn_oac_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_oac_init(&svc);
    uint64_t ctx_id = 0;
    ozayn_oac_context_create(&svc, "user-1", "sess-1", 0,
              OZAYN_OAC_LEVEL_NONE, OZAYN_OAC_SCOPE_SYSTEM_WIDE, 0, 3600, &ctx_id);
    uint64_t auth_id = 0;
    ozayn_oac_authority_create(&svc, ctx_id, "req-1", "op-1",
              0, 0, 0, 0, 600, &auth_id);
    ASSERT_EQ(ozayn_oac_authority_revoke(&svc, auth_id), OZAYN_OAC_OK);
    const ozayn_oac_authority_t *auth;
    ozayn_oac_authority_get(&svc, auth_id, &auth);
    ASSERT_EQ(auth->state, OZAYN_OAC_AUTH_REVOKED);
    ASSERT_EQ(svc.stats.total_authorities_revoked, (uint64_t)1);
    ozayn_oac_shutdown(&svc);
    return 0;
}

TEST(test_authority_cancel) {
    ozayn_oac_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_oac_init(&svc);
    uint64_t ctx_id = 0;
    ozayn_oac_context_create(&svc, "user-1", "sess-1", 0,
              OZAYN_OAC_LEVEL_NONE, OZAYN_OAC_SCOPE_SYSTEM_WIDE, 0, 3600, &ctx_id);
    uint64_t auth_id = 0;
    ozayn_oac_authority_create(&svc, ctx_id, "req-1", "op-1",
              0, 0, 0, 0, 600, &auth_id);
    ASSERT_EQ(ozayn_oac_authority_cancel(&svc, auth_id), OZAYN_OAC_OK);
    const ozayn_oac_authority_t *auth;
    ozayn_oac_authority_get(&svc, auth_id, &auth);
    ASSERT_EQ(auth->state, OZAYN_OAC_AUTH_CANCELLED);
    ozayn_oac_shutdown(&svc);
    return 0;
}

TEST(test_authority_invalidate_by_session) {
    ozayn_oac_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_oac_init(&svc);
    uint64_t ctx_id = 0;
    ozayn_oac_context_create(&svc, "user-1", "sess-1", 0,
              OZAYN_OAC_LEVEL_NONE, OZAYN_OAC_SCOPE_SYSTEM_WIDE, 0, 3600, &ctx_id);
    uint64_t a1 = 0, a2 = 0;
    ozayn_oac_authority_create(&svc, ctx_id, "req-1", "op-1",
              0, 0, 0, 0, 600, &a1);
    ozayn_oac_authority_create(&svc, ctx_id, "req-2", "op-2",
              0, 0, 0, 0, 600, &a2);
    ASSERT_EQ(ozayn_oac_authority_invalidate_by_session(&svc, "sess-1"), OZAYN_OAC_OK);
    ASSERT_EQ(svc.stats.total_authorities_invalidated, (uint64_t)2);
    const ozayn_oac_authority_t *auth;
    ozayn_oac_authority_get(&svc, a1, &auth);
    ASSERT_EQ(auth->state, OZAYN_OAC_AUTH_INVALID);
    ozayn_oac_shutdown(&svc);
    return 0;
}

TEST(test_revoke_all_for_session) {
    ozayn_oac_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_oac_init(&svc);
    uint64_t ctx_id = 0;
    ozayn_oac_context_create(&svc, "user-1", "sess-1", 0,
              OZAYN_OAC_LEVEL_NONE, OZAYN_OAC_SCOPE_SYSTEM_WIDE, 0, 3600, &ctx_id);
    uint64_t a1 = 0, a2 = 0;
    ozayn_oac_authority_create(&svc, ctx_id, "r1", "o1", 0, 0, 0, 0, 600, &a1);
    ozayn_oac_authority_create(&svc, ctx_id, "r2", "o2", 0, 0, 0, 0, 600, &a2);
    uint32_t count = 0;
    ASSERT_EQ(ozayn_oac_revoke_all_for_session(&svc, "sess-1", &count), OZAYN_OAC_OK);
    ASSERT(count > 0);
    ozayn_oac_shutdown(&svc);
    return 0;
}

TEST(test_expire_all_for_context) {
    ozayn_oac_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_oac_init(&svc);
    uint64_t ctx_id = 0;
    ozayn_oac_context_create(&svc, "user-1", "sess-1", 0,
              OZAYN_OAC_LEVEL_NONE, OZAYN_OAC_SCOPE_SYSTEM_WIDE, 0, 3600, &ctx_id);
    uint64_t a1 = 0, a2 = 0;
    ozayn_oac_authority_create(&svc, ctx_id, "r1", "o1", 0, 0, 0, 0, 600, &a1);
    ozayn_oac_authority_create(&svc, ctx_id, "r2", "o2", 0, 0, 0, 0, 600, &a2);
    uint32_t count = 0;
    ASSERT_EQ(ozayn_oac_expire_all_for_context(&svc, ctx_id, &count), OZAYN_OAC_OK);
    ASSERT(count > 0);
    ozayn_oac_shutdown(&svc);
    return 0;
}

TEST(test_authority_counts) {
    ozayn_oac_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ASSERT_EQ(ozayn_oac_authority_active_count(&svc), -1);
    ASSERT_EQ(ozayn_oac_authority_total_count(&svc), -1);
    ozayn_oac_init(&svc);
    ASSERT_EQ(ozayn_oac_authority_active_count(&svc), 0);
    uint64_t ctx_id = 0;
    ozayn_oac_context_create(&svc, "u", "s", 0, OZAYN_OAC_LEVEL_NONE,
              OZAYN_OAC_SCOPE_SYSTEM_WIDE, 0, 3600, &ctx_id);
    ozayn_oac_authority_create(&svc, ctx_id, "r1", "o1", 0, 0, 0, 0, 600, &(uint64_t){0});
    ozayn_oac_authority_create(&svc, ctx_id, "r2", "o2", 0, 0, 0, 0, 600, &(uint64_t){0});
    ASSERT_EQ(svc.authority_count, 2);
    ASSERT_EQ(ozayn_oac_authority_active_count(&svc), 2);
    ozayn_oac_shutdown(&svc);
    return 0;
}

TEST(test_authority_list_by_session) {
    ozayn_oac_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_oac_init(&svc);
    uint64_t ctx1 = 0, ctx2 = 0;
    ozayn_oac_context_create(&svc, "alice", "sess-a", 0, OZAYN_OAC_LEVEL_NONE,
              OZAYN_OAC_SCOPE_SYSTEM_WIDE, 0, 3600, &ctx1);
    ozayn_oac_context_create(&svc, "bob", "sess-b", 0, OZAYN_OAC_LEVEL_NONE,
              OZAYN_OAC_SCOPE_SYSTEM_WIDE, 0, 3600, &ctx2);
    ozayn_oac_authority_create(&svc, ctx1, "r1", "o1", 0, 0, 0, 0, 600, &(uint64_t){0});
    ozayn_oac_authority_create(&svc, ctx1, "r2", "o2", 0, 0, 0, 0, 600, &(uint64_t){0});
    ozayn_oac_authority_create(&svc, ctx2, "r3", "o3", 0, 0, 0, 0, 600, &(uint64_t){0});
    const ozayn_oac_authority_t *results[10];
    uint32_t count = 0;
    ASSERT_EQ(ozayn_oac_authority_list_by_session(&svc, "sess-a", results, 10, &count), OZAYN_OAC_OK);
    ASSERT_EQ(count, (uint32_t)2);
    ASSERT_EQ(ozayn_oac_authority_list_by_session(&svc, "sess-b", results, 10, &count), OZAYN_OAC_OK);
    ASSERT_EQ(count, (uint32_t)1);
    ozayn_oac_shutdown(&svc);
    return 0;
}

TEST(test_history_find) {
    ozayn_oac_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_oac_init(&svc);
    uint64_t ctx_id = 0;
    ozayn_oac_context_create(&svc, "user-1", "sess-1", 0,
              OZAYN_OAC_LEVEL_NONE, OZAYN_OAC_SCOPE_SYSTEM_WIDE, 0, 3600, &ctx_id);
    uint64_t auth_id = 0;
    ozayn_oac_authority_create(&svc, ctx_id, "req-1", "op-1",
              0, 0, 0, 0, 600, &auth_id);
    ozayn_oac_authority_validate(&svc, auth_id, "req-1", "op-1", "sess-1", "user-1");
    ozayn_oac_authority_consume(&svc, auth_id);
    ASSERT(ozayn_oac_history_find(&svc, "req-1", "op-1"));
    ASSERT(!ozayn_oac_history_find(&svc, "req-99", "op-99"));
    ozayn_oac_shutdown(&svc);
    return 0;
}

TEST(test_cleanup_expired) {
    ozayn_oac_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_oac_init(&svc);
    uint64_t ctx_id = 0;
    ozayn_oac_context_create(&svc, "user-1", "sess-1", 0,
              OZAYN_OAC_LEVEL_NONE, OZAYN_OAC_SCOPE_SYSTEM_WIDE, 0, 3600, &ctx_id);
    uint64_t auth_id = 0;
    ozayn_oac_authority_create(&svc, ctx_id, "req-1", "op-1",
              0, 0, 0, 0, 600, &auth_id);
    svc.contexts[0].expiration_time = 1;
    svc.authorities[0].expiration_time = 1;
    ASSERT_EQ(ozayn_oac_cleanup_expired(&svc), OZAYN_OAC_OK);
    ASSERT_EQ(svc.contexts[0].state, OZAYN_OAC_CTX_EXPIRED);
    ASSERT_EQ(svc.authorities[0].state, OZAYN_OAC_AUTH_EXPIRED);
    ozayn_oac_shutdown(&svc);
    return 0;
}

TEST(test_stats) {
    ozayn_oac_stats_t s = ozayn_oac_get_stats(0);
    ASSERT_EQ(s.total_access_contexts_created, (uint64_t)0);
    ozayn_oac_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_oac_init(&svc);
    s = ozayn_oac_get_stats(&svc);
    ASSERT_EQ(s.total_authorities_created, (uint64_t)0);
    ozayn_oac_shutdown(&svc);
    return 0;
}

TEST(test_validation_log) {
    ozayn_oac_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_oac_init(&svc);
    ASSERT_EQ(ozayn_oac_validation_log_count(&svc), 0);
    uint64_t ctx_id = 0;
    ozayn_oac_context_create(&svc, "user-1", "sess-1", 0,
              OZAYN_OAC_LEVEL_NONE, OZAYN_OAC_SCOPE_SYSTEM_WIDE, 0, 3600, &ctx_id);
    ASSERT(ozayn_oac_validation_log_count(&svc) > 0);
    ozayn_oac_shutdown(&svc);
    return 0;
}

TEST(test_scenarios_expired_session) {
    ozayn_oac_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_oac_init(&svc);
    uint64_t ctx_id = 0;
    ozayn_oac_context_create(&svc, "user-1", "sess-1", 0,
              OZAYN_OAC_LEVEL_NONE, OZAYN_OAC_SCOPE_SYSTEM_WIDE, 0, 3600, &ctx_id);
    ozayn_oac_context_revoke(&svc, ctx_id);
    uint64_t auth_id = 0;
    ASSERT_EQ(ozayn_oac_authority_create(&svc, ctx_id, "req-1", "op-1",
              0, 0, 0, 0, 600, &auth_id), OZAYN_OAC_ERR_ACCESS_DENIED);
    ozayn_oac_shutdown(&svc);
    return 0;
}

TEST(test_scenarios_operation_mismatch) {
    ozayn_oac_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_oac_init(&svc);
    uint64_t ctx_id = 0;
    ozayn_oac_context_create(&svc, "user-1", "sess-1", 0,
              OZAYN_OAC_LEVEL_NONE, OZAYN_OAC_SCOPE_SYSTEM_WIDE, 0, 3600, &ctx_id);
    uint64_t auth_id = 0;
    ozayn_oac_authority_create(&svc, ctx_id, "req-A", "op-A",
              0, 0, 0, 0, 600, &auth_id);
    ASSERT_EQ(ozayn_oac_authority_validate(&svc, auth_id, "req-B", "op-B", "sess-1", "user-1"),
              OZAYN_OAC_ERR_AUTHORITY_MISMATCH);
    ozayn_oac_shutdown(&svc);
    return 0;
}

TEST(test_scenarios_duplicate_authority) {
    ozayn_oac_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_oac_init(&svc);
    uint64_t ctx_id = 0;
    ozayn_oac_context_create(&svc, "user-1", "sess-1", 0,
              OZAYN_OAC_LEVEL_NONE, OZAYN_OAC_SCOPE_SYSTEM_WIDE, 0, 3600, &ctx_id);
    uint64_t a1 = 0, a2 = 0;
    ozayn_oac_authority_create(&svc, ctx_id, "req-1", "op-1",
              0, 0, 0, 0, 600, &a1);
    ASSERT_EQ(ozayn_oac_authority_create(&svc, ctx_id, "req-1", "op-1",
              0, 0, 0, 0, 600, &a2), OZAYN_OAC_ERR_AUTHORITY_DUPLICATE);
    ASSERT_EQ(svc.stats.total_duplicate_authority_attempts, (uint64_t)1);
    ozayn_oac_shutdown(&svc);
    return 0;
}

TEST(test_scenarios_full_chain) {
    ozayn_oac_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_oac_init(&svc);
    uint64_t ctx_id = 0;
    ASSERT_EQ(ozayn_oac_context_create(&svc, "user-1", "sess-1", "authz-1",
              OZAYN_OAC_LEVEL_OPERATE, OZAYN_OAC_SCOPE_SYSTEM_WIDE, 0, 3600, &ctx_id), OZAYN_OAC_OK);
    ASSERT_EQ(ozayn_oac_context_validate(&svc, ctx_id), OZAYN_OAC_OK);
    uint64_t auth_id = 0;
    ASSERT_EQ(ozayn_oac_authority_create(&svc, ctx_id, "req-1", "op-1",
              "comp", "cap", "start", "perm", 600, &auth_id), OZAYN_OAC_OK);
    ASSERT_EQ(ozayn_oac_authority_validate(&svc, auth_id, "req-1", "op-1", "sess-1", "user-1"), OZAYN_OAC_OK);
    ASSERT_EQ(ozayn_oac_authority_consume(&svc, auth_id), OZAYN_OAC_OK);
    ASSERT(ozayn_oac_history_find(&svc, "req-1", "op-1"));
    ASSERT_EQ(svc.stats.total_authorities_consumed, (uint64_t)1);
    ozayn_oac_shutdown(&svc);
    return 0;
}

TEST(test_scenarios_session_revoked_blocks_queued) {
    ozayn_oac_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_oac_init(&svc);
    uint64_t ctx_id = 0;
    ozayn_oac_context_create(&svc, "user-1", "sess-1", 0,
              OZAYN_OAC_LEVEL_NONE, OZAYN_OAC_SCOPE_SYSTEM_WIDE, 0, 3600, &ctx_id);
    uint64_t auth_id = 0;
    ozayn_oac_authority_create(&svc, ctx_id, "req-1", "op-1",
              0, 0, 0, 0, 600, &auth_id);
    ozayn_oac_authority_invalidate_by_session(&svc, "sess-1");
    ASSERT_EQ(ozayn_oac_authority_validate(&svc, auth_id, "req-1", "op-1", "sess-1", "user-1"),
              OZAYN_OAC_ERR_AUTHORITY_INVALID);
    ozayn_oac_shutdown(&svc);
    return 0;
}

TEST(test_scenarios_mode_change_invalidates) {
    ozayn_oac_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_oac_init(&svc);
    uint64_t ctx_id = 0;
    ozayn_oac_context_create(&svc, "user-1", "sess-1", 0,
              OZAYN_OAC_LEVEL_NONE, OZAYN_OAC_SCOPE_SYSTEM_WIDE, 0, 3600, &ctx_id);
    uint64_t auth_id = 0;
    ozayn_oac_authority_create(&svc, ctx_id, "req-1", "op-1",
              0, 0, 0, 0, 600, &auth_id);
    ozayn_oac_authority_invalidate_by_context(&svc, ctx_id);
    ASSERT_EQ(ozayn_oac_authority_validate(&svc, auth_id, "req-1", "op-1", "sess-1", "user-1"),
              OZAYN_OAC_ERR_AUTHORITY_INVALID);
    ozayn_oac_shutdown(&svc);
    return 0;
}

int run_cr_operational_access_tests(void) {
    int fail = 0;
    SUITE_BEGIN("operational_access");
    RUN(test_err_name);
    RUN(test_level_name);
    RUN(test_ctx_state_name);
    RUN(test_auth_state_name);
    RUN(test_scope_type_name);
    RUN(test_event_type_name);
    RUN(test_ctx_transitions_valid);
    RUN(test_ctx_transitions_invalid);
    RUN(test_auth_transitions_valid);
    RUN(test_auth_transitions_invalid);
    RUN(test_init_null);
    RUN(test_init_basic);
    RUN(test_init_double);
    RUN(test_shutdown_null);
    RUN(test_shutdown_basic);
    RUN(test_is_initialized);
    RUN(test_bind_subsystems);
    RUN(test_context_create);
    RUN(test_context_create_null);
    RUN(test_context_validate);
    RUN(test_context_validate_expired);
    RUN(test_context_expire);
    RUN(test_context_revoke);
    RUN(test_context_terminate);
    RUN(test_context_invalid_transition);
    RUN(test_context_counts);
    RUN(test_context_list_by_identity);
    RUN(test_authority_create);
    RUN(test_authority_create_invalid_context);
    RUN(test_authority_create_expired_context);
    RUN(test_authority_validate);
    RUN(test_authority_validate_session_mismatch);
    RUN(test_authority_validate_identity_mismatch);
    RUN(test_authority_validate_operation_mismatch);
    RUN(test_authority_validate_expired);
    RUN(test_authority_consume);
    RUN(test_authority_consume_duplicate);
    RUN(test_authority_consume_not_authorized);
    RUN(test_authority_expire);
    RUN(test_authority_revoke);
    RUN(test_authority_cancel);
    RUN(test_authority_invalidate_by_session);
    RUN(test_revoke_all_for_session);
    RUN(test_expire_all_for_context);
    RUN(test_authority_counts);
    RUN(test_authority_list_by_session);
    RUN(test_history_find);
    RUN(test_cleanup_expired);
    RUN(test_stats);
    RUN(test_validation_log);
    RUN(test_scenarios_expired_session);
    RUN(test_scenarios_operation_mismatch);
    RUN(test_scenarios_duplicate_authority);
    RUN(test_scenarios_full_chain);
    RUN(test_scenarios_session_revoked_blocks_queued);
    RUN(test_scenarios_mode_change_invalidates);
    SUITE_END();
    return fail;
}
