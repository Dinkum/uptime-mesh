# Node Bootstrap + Update

This directory contains node-side operational scripts:

- `bootstrap.sh`: tiny shim that fetches/verifies updater and hands off.
- `node-update.sh`: robust updater with locking, retries, checksum verification, atomic install, and rollback.

## Safety model

- Bootstrap is intentionally minimal and only does:
  1. fetch manifest,
  2. fetch updater,
  3. execute updater (or fallback to local updater).
- Updater is the only component that applies binary changes.
- Updater validates SHA-256 from `version.json` before installing anything.
- Updater installs atomically and rolls back if post-update health checks fail.

## Manifest

`version.json` at repo root is the source of truth.

The updater reads:

- `channels.<name>.updater`
- `channels.<name>.bootstrap`
- `channels.<name>.agent.artifacts.<os-arch>`

Example target keys:

- `linux-amd64`
- `linux-arm64`

## Release checklist

1. Build and upload node agent artifacts (GitHub Releases recommended).
2. Update `version.json`:
   - bump `channels.stable.version`,
   - set `agent.version`,
   - set artifact URLs and SHA-256 values.
3. Recompute script checksums when scripts change:
   - `shasum -a 256 ops/bootstrap.sh ops/node-update.sh`
   - update `bootstrap.sha256` and `updater.sha256` in `version.json`.
4. Validate in a test node:
   - `VERSION_URL=<raw-version-json-url> sh ops/bootstrap.sh`
