# Node Lifecycle Scripts

This directory contains the node-side lifecycle scripts used in production.

## Scripts

- `bootstrap.sh`: tiny dispatcher used by systemd timer and manual recovery.
  - Acquires lock.
  - Fetches `version.json`.
  - Verifies script checksum.
  - Runs repo-root `install.sh` (if node not installed) or `ops/update.sh` (if installed).

- `update.sh`: full in-place application update.
  - Compares installed `VERSION` vs latest release.
  - Uses `update-state.json` failed-version gate.
  - Backs up app dir + sqlite DB + agent binary.
  - Downloads latest release source tarball from GitHub release metadata.
  - Optionally verifies source checksum when `channels.<name>.source.sha256` is provided.
  - Applies source update, rebuilds Go agent, runs migrations.
  - Restarts services and enforces health gate.
  - Rolls back on failure.
  - Health probes use bounded curl/wget timeouts.

- `agent-update.sh`: agent-only rebuild/swap/restart flow.
  - Pre/post health gates use short per-request curl/wget timeouts so a hung local probe does not stall the update.

- `node-update.sh`: compatibility wrapper to `agent-update.sh`.

- `install.sh`: compatibility wrapper that dispatches to repo-root `install.sh`.

## Manifest contract (`version.json`)

`channels.<name>` should include:

- `version`
- `bootstrap.path`, `bootstrap.sha256`
- `install.path`, `install.sha256`
- `update.path`, `update.sha256`
- Optional: `source.sha256`

Notes:
- Source tarball URL is resolved dynamically from GitHub Releases API (`releases/latest`), not pinned via manifest URL.
- Channel `version` must match `releases/latest` tag version, otherwise install/update aborts to prevent version drift.

## Systemd

Installed by `install.sh`:

- `uptime-mesh-update.service`
- `uptime-mesh-update.timer` (hourly)

Manual recovery:

```bash
sudo /opt/uptime-mesh/ops/bootstrap.sh
```
