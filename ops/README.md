# Node Lifecycle Scripts

This directory contains the node-side lifecycle scripts used in production.

## Scripts

- `bootstrap.sh`: tiny dispatcher used by systemd timer and manual recovery.
  - Acquires lock.
  - Fetches `version.json`.
  - Verifies script checksum.
  - Runs `install.sh` (if node not installed) or `update.sh` (if installed).

- `update.sh`: full in-place application update.
  - Compares installed `VERSION` vs latest release.
  - Uses `update-state.json` failed-version gate.
  - Backs up app dir + sqlite DB + agent binary.
  - Downloads and verifies source tarball checksum.
  - Applies source update, rebuilds Go agent, runs migrations.
  - Restarts services and enforces health gate.
  - Rolls back on failure.

- `agent-update.sh`: agent-only rebuild/swap/restart flow.

- `node-update.sh`: compatibility wrapper to `agent-update.sh`.

## Manifest contract (`version.json`)

`channels.<name>` should include:

- `version`
- `bootstrap.path`, `bootstrap.sha256`
- `install.path`, `install.sha256`
- `update.path`, `update.sha256`
- `source.url`, `source.sha256`

## Systemd

Installed by `install.sh`:

- `uptime-mesh-update.service`
- `uptime-mesh-update.timer` (hourly)

Manual recovery:

```bash
sudo /opt/uptime-mesh/ops/bootstrap.sh
```
