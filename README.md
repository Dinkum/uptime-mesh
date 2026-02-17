# UptimeMesh

UptimeMesh is a small-control-plane cluster manager and private network fabric. This repo contains the FastAPI control UI and API service for V1.

## Requirements

- Python 3.11+
- SQLite for dev (WAL mode enabled automatically)

## Setup

1. Create a virtualenv and install dependencies.
2. Create a `.env` file (see `.env.example`).
3. Run migrations.

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .
alembic upgrade head
```

## Run

```bash
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

## UI

The Web UI is available under `/ui`.

## Authentication

- Login page: `/auth/login`
- API login: `POST /auth/token`
- Default credentials after migration/seed: `admin` / `uptime`
- Change password in UI: `/ui/settings`
- Set `AUTH_SECRET_KEY` in `.env` for production-like environments.

## Production Hardening

- Set `APP_ENV=prod` (or `production`) to enable strict startup validation.
- In production, startup now fails unless all are true:
  - `AUTH_SECRET_KEY` is non-default and at least 32 chars.
  - `CLUSTER_SIGNING_KEY` is non-default and at least 32 chars.
  - `AUTH_COOKIE_SECURE=true`.
- Rotate the default `admin/uptime` credential immediately after first bootstrap (`/ui/settings`).

## Bootstrap and Enrollment

- `POST /cluster/bootstrap` creates initial core/worker join tokens.
- `POST /cluster/join-tokens` creates on-demand one-time join tokens.
- `POST /cluster/join` enrolls a node using a one-time token + CSR, returns signed node cert + signed lease token.
- `POST /cluster/heartbeat` requires signed heartbeat payload (node private key proof).
- `GET /cluster/leases` lists node lease health (`alive`, `stale`, `dead`).

## CLI

ASCII-first CLI is available as `uptimemesh`:

```bash
uptimemesh bootstrap --api-url http://127.0.0.1:8000
uptimemesh join --api-url http://127.0.0.1:8000 --token <join-token> --node-id node-a --name node-a --role worker
uptimemesh heartbeat --api-url http://127.0.0.1:8000 --node-id node-a
uptimemesh nodes-status --api-url http://127.0.0.1:8000
```

`uptimemesh join` stores identity artifacts under `data/identities/<node-id>/`:

- `node.key` (private key)
- `node.crt` (cluster-signed cert)
- `ca.crt` (cluster CA)
- `lease.token` (signed lease token)

## Node Update Mechanism

Node-side update tooling is included for GitHub-based distribution:

- manifest: `version.json`
- bootstrap shim: `ops/bootstrap.sh` (tiny handoff script)
- robust updater: `ops/node-update.sh`

Typical node invocation:

```bash
VERSION_URL=https://raw.githubusercontent.com/<org>/<repo>/main/version.json sh ops/bootstrap.sh
```

See `ops/README.md` for release/checksum workflow.

## API Endpoints (Initial)

- `GET /health`
- `GET /version`
- `GET /nodes` / `POST /nodes` / `PATCH /nodes/{id}`
- `POST /nodes/{id}/cordon` / `POST /nodes/{id}/uncordon` / `POST /nodes/{id}/drain`
- `POST /nodes/{id}/reboot-marker` / `POST /nodes/{id}/rotate-wg-keys`
- `GET /services` / `POST /services` / `PATCH /services/{id}`
- `POST /services/{id}/rollout` / `POST /services/{id}/rollback`
- `GET /replicas` / `POST /replicas` / `PATCH /replicas/{id}` / `POST /replicas/{id}/move`
- `POST /replicas/{id}/restart` / `POST /replicas/{id}/snapshot` / `POST /replicas/{id}/restore`
- `DELETE /replicas/{id}`
- `GET /endpoints` / `POST /endpoints` / `PATCH /endpoints/{id}`
- `GET /router-assignments` / `POST /router-assignments`
- `GET /scheduler/plan/services/{id}` / `POST /scheduler/reconcile/services/{id}`
- `GET /scheduler/plan/all` / `POST /scheduler/reconcile/all`
- `GET /events` / `POST /events` / `GET /events/stream`
- `GET /wireguard/status`
- `GET /etcd/snapshots` / `POST /etcd/snapshots`
- `GET /support-bundles` / `POST /support-bundles`
- `GET /cluster-settings` / `GET /cluster-settings/{key}` / `PUT /cluster-settings/{key}`
- `POST /cluster/bootstrap` / `POST /cluster/join-tokens`
- `POST /cluster/join` / `POST /cluster/heartbeat` / `GET /cluster/leases`

Snapshot and support bundle requests are recorded in the API and are expected to be executed by agents.
Write operations are rejected with `503` when `cluster_settings.etcd_status` is `down`, `unavailable`, or `stale`.

## V2 Scheduler

V2 scheduler logic reads scheduling policy from `service.spec`:

- `scheduling.desired_replicas` (or `replicas_desired`)
- `scheduling.node_selector` (supports `role`, `node_id`, and label keys)
- `scheduling.anti_affinity` (boolean)
- `scheduling.reschedule_unhealthy` (boolean)
- `rolling_update.max_surge` and `rolling_update.max_unavailable`

The scheduler can dry-run or apply reconcile actions (move unhealthy replicas, scale up/down, queue rolling updates).

## Migrations and Seeds

- Schema migrations use Alembic.
- Repeatable seed steps run after every `alembic upgrade` and are safe to re-run.

## Logging

Logging is structured and ASCII-only. Each log line includes:

- timestamp
- level (8-char width)
- category
- event name and message
- context fields
