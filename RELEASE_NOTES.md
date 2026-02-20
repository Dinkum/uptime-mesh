# Release Notes

## v0.0.5

### Major
- Fixed public install path reliability regressions:
  - Resolved `curl ... | bash` crash caused by strict `BASH_SOURCE[0]` use under `set -u`.
  - Hardened script source-path resolution so install runs correctly in both piped and file-based modes.
- Fixed release/version drift risk in updater/install flow:
  - Installer and updater now enforce manifest/release lockstep (`channels.<channel>.version` must match `releases/latest` tag).
  - Removed stale-manifest `source.url` precedence in updater; source tarball now always comes from release metadata.
  - Prevents scenarios where nodes could mark themselves updated to a new version while applying old source content.

### Minor
- Improved source tarball checksum behavior and operator feedback:
  - `source.sha256` is now optional in manifest contract.
  - For GitHub-generated tarballs, checksum mismatch now logs a clear warning with expected/actual hashes and continues.
  - For non-GitHub tarballs, checksum mismatch remains hard-fail with actionable error context.
- Updated lifecycle docs (`ops/README.md`) to reflect dynamic release tarball resolution and optional source checksum.
- Updated version manifest script checksums for `install.sh` and `ops/update.sh`.

## Included Changes Since v0.0.4
- This release includes all commits after `v0.0.4`, focused on:
  - unblocking public install (`curl | bash` and `./install.sh`) failures,
  - eliminating stale release source selection paths,
  - and making update/install manifest semantics safer and easier to operate.

## v0.0.4

### Major
- Reworked install/bootstrap/update lifecycle for safer production operation:
  - Hardened `install.sh` into a first-node and join-node entrypoint with clearer defaults, generated credentials, and service bootstrap wiring.
  - Added manifest-driven `ops/bootstrap.sh` dispatcher + hourly systemd timer flow for unattended update checks.
  - Added full `ops/update.sh` update pipeline with lock control, staged apply, health gating, rollback path, and persistent `update-state.json`.
  - Added dedicated `ops/agent-update.sh` path for Go-agent-only rollouts.
  - Standardized operational logs into `data/logs` (`install.log`, `update.log`, `bootstrap.log`, `app.log`, `agent.log`).
- Strengthened cluster security and trust boundaries:
  - Removed cluster-wide signing secrets from node join responses and installer join handling.
  - Added explicit throttling for public join and heartbeat endpoints.
  - Redacted sensitive cluster settings/secrets from support bundle output.
  - Hardened heartbeat signature validation and sequencing paths with richer rejection telemetry.
- Upgraded Go agent SWIM behavior and role actuation stability:
  - Added SWIM indirect probing (`ping-req` / `indirect-ack`) to reduce false dead detection on transient/asymmetric links.
  - Added SWIM gossip piggybacking with bounded fanout and merge rules to propagate membership state peer-to-peer faster.
  - Added load-aware SWIM flags and state handling with CPU/RAM/DISK/NETWORK/TOTAL load reporting.
  - Added hash-gated backend/proxy runtime reconciliation to avoid unnecessary nginx/caddy reload churn.
- Expanded operator UI information architecture and visibility:
  - Added consolidated `Infrastructure` and `Workloads` pages and deeper node-level diagnostics.
  - Added richer network/node visualizations, role placement visibility, rollout progress surfaces, and endpoint state visibility.
  - Updated login and dashboard experience toward consistent dark-mode-first styling and clearer controls.

### Minor
- Added migration `0006_events_index_and_node_cleanup` to improve event query performance and clean obsolete node schema surface.
- Improved settings/config reconciliation and reduced redundant DB reads/queries in key settings and UI flows.
- Added shared utility helpers and route/service refactors to move heavy business logic out of route handlers.
- Improved event query correctness for filtered timelines and broadened structured logging coverage for config, runtime, and failure paths.
- Updated `.env.example`, CLI workflows, and ops docs to match the new install/update/bootstrap model.

## Included Changes Since v0.0.3
- This release includes all work since `v0.0.3`, including:
  - install/bootstrap/update pipeline hardening with rollback + logging,
  - Go agent SWIM reliability upgrades (indirect probes + gossip),
  - cluster security boundary fixes for join/heartbeat/support artifacts,
  - large UI/UX restructuring for node/workload/infrastructure visibility,
  - and DB/settings/runtime performance and maintainability improvements.

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
  - Introduced installer command logging to `data/logs/install.log`.
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
