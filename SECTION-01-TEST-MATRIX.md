# SECTION-01-TEST-MATRIX.md — OZAYN Core Test Matrix

**Date:** 2026-08-31  
**Version:** 0.1 (Genesis)  
**Total Tests:** 368 / 368 PASS  

---

## Summary

| Category | Suites | Tests | Pass | Fail |
|---|---|---|---|---|
| Unit Tests (Existing) | 14 | 160 | 160 | 0 |
| Unit Tests (New) | 20 | 167 | 167 | 0 |
| Failure Mode Tests | 1 | 10 | 10 | 0 |
| Regression Tests | 1 | 11 | 11 | 0 |
| Integration Tests | 2 | 12 | 12 | 0 |
| System Tests | 1 | 5 | 5 | 0 |
| **Total** | **39** | **368** | **368** | **0** |

---

## Unit Tests — Existing (Stages 27-30)

| # | Suite | File | Tests | Description |
|---|---|---|---|---|
| 1 | Events | `unit/test_events.c` | 11 | Event engine pub/sub/correlate |
| 2 | Dependency | `unit/test_dependency.c` | 11 | Dependency graph resolution |
| 3 | Lifecycle | `unit/test_lifecycle.c` | 9 | Component lifecycle states |
| 4 | Security | `unit/test_security.c` | 16 | Identity, auth, permissions |
| 5 | Reload | `unit/test_reload.c` | 10 | Hot reload, audit, rollback |
| 6 | Perf | `unit/test_perf.c` | 13 | Performance manager |
| 7 | Defense | `unit/test_defense.c` | 8 | Defensive assertions |
| 8 | Circuit Breaker | `unit/test_cb.c` | 10 | Circuit breaker state machine |
| 9 | Resource Limits | `unit/test_rl.c` | 8 | Resource limit tracking |
| 10 | Health Tracker | `unit/test_ht.c` | 9 | Health tracking engine |
| 11 | Config Lookup | `unit/test_cl.c` | 10 | Config value lookup |
| 12 | Config Validate | `unit/test_cv.c` | 16 | Config validation |
| 13 | Version | `unit/test_version.c` | 16 | SemVer parse/compare/format |
| 14 | Release | `unit/test_release.c` | 13 | Release manager |

## Unit Tests — New (Section 01)

| # | Suite | File | Tests | Description |
|---|---|---|---|---|
| 15 | Logger | `unit/test_logger.c` | 7 | Logger init/shutdown/levels/file output |
| 16 | Tasks | `unit/test_tasks.c` | 11 | Task submit/cancel/query/names |
| 17 | Commands | `unit/test_commands.c` | 10 | Command engine execute/names |
| 18 | Recovery | `unit/test_recovery.c` | 9 | Error recovery raise/evaluate/clear |
| 19 | Resource | `unit/test_resource.c` | 10 | Resource create/allocate/activate/release |
| 20 | Scheduler | `unit/test_scheduler.c` | 7 | Scheduler submit/cancel/priority |
| 21 | Monitoring | `unit/test_monitoring.c` | 11 | Health/metrics/incidents |
| 22 | Diagnostics | `unit/test_diagnostics.c` | 10 | Evidence/findings/timeline/sessions |
| 23 | Security Boundary | `unit/test_security_boundary.c` | 8 | Context/capabilities/enforcement |
| 24 | State Manager | `unit/test_state_manager.c` | 10 | Persistence create/get/update/delete |
| 25 | Service Lifecycle | `unit/test_service_lifecycle.c` | 7 | Service register/start/find/stats |
| 26 | Platform | `unit/test_platform.c` | 8 | System info/process/fs |
| 27 | IPC | `unit/test_ipc.c` | 7 | Header pack/unpack/names |
| 28 | Registry | `unit/test_registry.c` | 8 | Service register/lookup/capabilities |
| 29 | Modules | `unit/test_modules.c` | 6 | Module register/find/unregister |
| 30 | Plugins | `unit/test_plugins.c` | 6 | Plugin discover/find/names |
| 31 | Processes | `unit/test_processes.c` | 7 | Process create/reap/terminate |
| 32 | Perf Manager | `unit/test_perf_mgr.c` | 11 | Startup timing/benchmarks/thresholds |
| 33 | Core API | `unit/test_core_api.c` | 12 | Interface register/request/compat |
| 34 | Config Manager | `unit/test_config_mgr.c` | 6 | Config load/validate/level names |

## Failure Mode Tests

| # | Suite | File | Tests | Description |
|---|---|---|---|---|
| 35 | Failure Modes | `failure/test_failure_modes.c` | 10 | Null configs, bad inputs, capacity overflow |

## Regression Tests

| # | Suite | File | Tests | Description |
|---|---|---|---|---|
| 36 | Regression | `regression/test_regression.c` | 11 | End-to-end workflows for all subsystems |

## Integration Tests (Existing)

| # | Suite | File | Tests | Description |
|---|---|---|---|---|
| 37 | Startup/Shutdown | `integration/test_startup_shutdown.c` | 6 | Component init/shutdown ordering |
| 38 | Service Integration | `integration/test_service_integration.c` | 6 | Cross-component workflows |

## System Tests (Existing)

| # | Suite | File | Tests | Description |
|---|---|---|---|---|
| 39 | Full Lifecycle | `system/test_full_lifecycle.c` | 5 | Complete system lifecycle |

---

## Modules Tested

| Module | Header | Unit | Failure | Regression | Integration | System |
|---|---|---|---|---|---|---|
| Logger | `logger.h` | ✅ | ✅ | — | — | — |
| Tasks | `tasks.h` | ✅ | ✅ | ✅ | — | — |
| Commands | `commands.h` | ✅ | ✅ | ✅ | — | — |
| Recovery | `recovery.h` | ✅ | ✅ | ✅ | — | — |
| Resource | `resource.h` | ✅ | ✅ | ✅ | — | — |
| Scheduler | `scheduler.h` | ✅ | — | ✅ | — | — |
| Monitoring | `monitoring.h` | ✅ | ✅ | ✅ | — | — |
| Diagnostics | `diagnostics.h` | ✅ | ✅ | ✅ | — | — |
| Security Boundary | `security_boundary.h` | ✅ | ✅ | ✅ | — | ✅ |
| State Manager | `state_manager.h` | ✅ | ✅ | ✅ | — | — |
| Service Lifecycle | `service_lifecycle.h` | ✅ | — | — | — | ✅ |
| Platform | `platform.h` | ✅ | — | ✅ | — | — |
| IPC | `ipc.h` | ✅ | — | — | — | — |
| Registry | `registry.h` | ✅ | — | ✅ | — | — |
| Modules | `modules.h` | ✅ | — | — | — | — |
| Plugins | `plugins.h` | ✅ | — | — | — | — |
| Processes | `processes.h` | ✅ | — | — | — | — |
| Perf Manager | `perf_mgr.h` | ✅ | — | — | — | — |
| Core API | `core_api.h` | ✅ | — | — | — | — |
| Config | `config.h` | ✅ | ✅ | — | — | — |
| Events | `events.h` | ✅ | — | — | — | — |
| Dependency | `dependency.h` | ✅ | — | — | ✅ | — |
| Lifecycle | `lifecycle.h` | ✅ | — | — | ✅ | — |
| Security | `security.h` | ✅ | — | — | ✅ | — |
| Reload | `reload_mgr.h` | ✅ | — | — | — | ✅ |
| Perf | `perf.h` | ✅ | — | — | — | — |
| Defense | `defense.h` | ✅ | — | — | — | — |
| Circuit Breaker | `circuit_breaker.h` | ✅ | — | — | — | — |
| Resource Limits | `resource_limits.h` | ✅ | — | — | — | — |
| Health Tracker | `health_tracker.h` | ✅ | — | — | — | — |
| Version | `version.h` | ✅ | — | — | — | — |
| Release | `release_mgr.h` | ✅ | — | — | — | — |

---

## Build & Run

```bash
make clean && make test
```

**Expected output:** `TOTAL: 368/368 passed -- ALL PASS`
