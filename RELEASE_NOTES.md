# Release Notes

## v0.0.3

### Major
- Added a full network visibility surface in the Web UI:
  - New `Network` page with node topology map, SWIM connectivity links, load-based node coloring, and etcd quorum snapshot.
  - New `Roles` tab and per-role detail pages to expose deterministic placement outcomes and active holders.
  - Expanded node detail page with SWIM membership/peers, role placement mapping, and load breakdown.
- Extended Go agent runtime with SWIM + load telemetry integration:
  - SWIM heartbeats/reports now include CPU, RAM, disk, network, and total load flags.
  - Added cached load sampling aligned to heartbeat interval to reduce per-tick recomputation overhead.
  - Added load-aware SWIM local state behavior (degrade when total load is high or critical runtime/heartbeat errors are present).
- Hardened first-node install flow for production-like bootstrap reliability:
  - Introduced installer command logging to `data/install.log`.
  - Added quieter step-oriented install output with retained deep command logs.
  - Enforced self-signed HTTPS UI proxy provisioning with nginx/caddy fallback and explicit fail path when unavailable.
  - Added safer service enable/start behavior for optional units to avoid noisy false alarms.

### Minor
- Installer UX and safety improvements:
  - Bare `./install.sh` path remains non-wizard/non-interactive while preserving first-node auto-bootstrap behavior.
  - Added clearer install-phase step narration and end-of-run summary fields (including install log path).
  - Improved package installation resilience with retry support on required apt operations.
  - Added proxy conflict safeguards (disables alternate proxy service before applying active proxy config).
  - Reduced startup-time watchdog noise by handling initial transient failures gracefully.
- Login/auth and dashboard UI polish:
  - Reworked sign-in page styling for a consistent dark glass aesthetic with stronger typography and spacing.
  - Improved login input readability/autofill behavior and added password visibility toggle.
  - Reworked primary top navigation tabs with clearer active-state treatment and better small-screen behavior (scrollable tab row).
  - Updated settings/login UX consistency around default `admin` username flow.
- API/runtime/model updates:
  - Added role-related routes/schemas/services and UI plumbing for placement introspection.
  - Added migration updates for cluster setting value storage compatibility (`0005_cluster_settings_value_text`).
  - Expanded overview/node metrics exposure to include SWIM and load-centric diagnostics.

## Included Changes Since v0.0.2
- This release includes all commits after `v0.0.2`, including:
  - installer non-interactive path fixes,
  - watchdog/self-heal runtime additions,
  - install restart handling for API/agent updates,
  - auth/UI defaults and dark-mode improvements,
  - network map + roles UI + SWIM/load instrumentation,
  - and subsequent install hardening + navigation/login polish updates.

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
