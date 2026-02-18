# Release Notes

## v0.0.2

### Major
- Introduced Go node agent runtime foundation and systemd-managed agent execution path, including heartbeat/failover runtime loops and unix-socket agent status endpoints.
- Added cluster bootstrap + join flow with first-node and join-node install paths, including generated node identity artifacts and one-time join token enrollment semantics.
- Implemented monitoring orchestration (V1 M7):
  - Prometheus config reconciliation from live node registry
  - validate/reload/rollback-safe apply pipeline
  - monitoring status persisted into cluster settings
  - monitoring API/UI/CLI visibility (`/monitoring/*`, `/ui/monitoring`, CLI monitoring commands)
- Implemented snapshot and support execution tooling (V1 M8):
  - etcd snapshot run lifecycle with explicit state transitions and restore flow
  - snapshot artifact integrity sidecars and restore guardrails
  - downloadable snapshot and support artifacts
  - support bundles containing sanitized cluster diagnostics and incident artifacts
- Added runtime scheduled snapshot loop with configurable cadence and request attribution.

### Minor
- Added managed monitoring templates and provisioning wiring for Prometheus, Alertmanager, and Grafana assets.
- Expanded installer defaults and environment keys for runtime monitoring + snapshot scheduler controls.
- Improved support UI with actionable controls (snapshot restore/download, bundle download) and clearer error surfacing.
- Added CLI commands for monitoring visibility and artifact download paths.
- Improved structured logging coverage around runtime reconciliation and operational actions.
- Updated documentation and operational command examples for install, monitoring, snapshots, and support workflows.

## Included Changes Since v0.0.1
- This release includes all commits after `v0.0.1`, including bootstrap/install updates, Go agent integration, monitoring reconciliation APIs/UI/CLI, snapshot/restore hardening, support bundle generation improvements, and associated runtime/config/doc updates.
