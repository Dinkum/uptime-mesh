# UptimeMesh

## Intro
UptimeMesh is a self-healing private mesh control plane for small to mid-sized clusters.

It combines:
- WireGuard for encrypted node-to-node transport
- etcd for replicated cluster truth and coordination
- a standalone Go node agent for continuous reconciliation and signed heartbeats
- LXD-based workload sandboxes with snapshot/restore actions
- a built-in Web UI plus ASCII-first CLI
- Prometheus/Grafana-ready observability

This repository is the V1 control plane, UI, and operational tooling.

## Features
- Source-first deployment: no binary packaging required for V1.
- One-command install path: local `./install.sh` or remote `curl ... | bash`.
- Secure auth baseline: login page, session cookies, password change in UI.
- Signed node identity flow: CSR-based cert issuance + signed heartbeat payloads.
- Dedicated Go agent process (`uptimemesh-agent`) per node.
- etcd operations:
  - health and member management
  - snapshot run and restore flow
- Runtime failover foundations:
  - dual WireGuard interface status model
  - route metric preference switching
- CoreDNS discovery projection:
  - healthy endpoint registry -> zone rendering (`mesh.local`)
- LXD operations wired to replica and service actions:
  - create/move/restart/snapshot/restore/delete
  - service rollout and rollback with snapshot-based safety behavior
- High-signal structured logging to `app.log`.
- Prometheus/Grafana-ready metrics and monitoring config scaffolding in `ops/monitoring`.

## Setup
### 1. Local Development Setup
```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .
alembic upgrade head
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

Build the Go agent locally (optional in dev, required for node installs):
```bash
go build -o bin/uptimemesh-agent ./agent/cmd/uptimemesh-agent
```

UI: `http://127.0.0.1:8000/ui`

Default login after seed/migrations:
- username: `admin`
- password: `uptime`

### 2. Node Install (Source-First)
Run from a checkout:
```bash
sudo ./install.sh --wizard
```

Direct from GitHub:
```bash
curl -fsSL https://raw.githubusercontent.com/Dinkum/uptime-mesh/main/install.sh | bash -s -- --wizard
```

### 3. First Core Node (Bootstrap)
```bash
sudo ./install.sh \
  --install-deps \
  --install-monitoring \
  --bootstrap \
  --node-id node1 \
  --name node1 \
  --role core \
  --api-endpoint http://<node1-ip>:8010 \
  --etcd-peer-url http://<node1-ip>:2380
```

### 4. Additional Nodes (Join)
```bash
sudo ./install.sh \
  --install-deps \
  --node-id node2 \
  --name node2 \
  --role worker \
  --api-url http://<node1-ip>:8010 \
  --api-endpoint http://<node2-ip>:8010 \
  --token <join-token>
```

## Architecture
```text
                  +---------------------------+
                  |        Web UI / CLI       |
                  +------------+--------------+
                               |
                               v
                  +---------------------------+
                  |   FastAPI Control Plane   |
                  | auth, APIs, events, UI    |
                  +------------+--------------+
                               |
                +--------------+--------------+
                |                             |
                v                             v
        +---------------+             +---------------+
        |     etcd      |             |   Go Agent    |
        | cluster truth |             | reconcile loop|
        +-------+-------+             +-------+-------+
                |                             |
                v                             v
        +---------------+             +---------------+
        |  Discovery    |             |   WireGuard   |
        | CoreDNS zone  |             | + LXD actions |
        +---------------+             +---------------+
```

### Role Model
- Core node:
  - API/UI
  - etcd member (when configured)
  - discovery/monitoring components
- Worker node:
  - Go agent loop
  - LXD workload actions
- Gateway node:
  - reserved for ingress-focused behavior in V1/V2 roadmap

### Control Behavior
- Writes are guarded when etcd status is `down`, `unavailable`, or `stale`.
- Existing workloads and local runtime logic continue even during partial control-plane degradation.

## Configuration
Configuration is split across:
- `.env` for runtime environment settings (see `.env.example`)
- `config.yaml` for managed cluster-level values (auto-generated and auto-healed on startup)

`config.yaml` behavior:
- created automatically if missing
- rebuilt with defaults when keys are missing
- written in stable key order with ASCII section comments
- synchronized immediately when managed values are updated from UI/API flows

### Core App
- `APP_ENV`, `DATABASE_URL`
- `LOG_LEVEL`, `LOG_FILE`
- `METRICS_ENABLED`

### Auth and Security
- `AUTH_SECRET_KEY`
- `AUTH_COOKIE_SECURE`
- `CLUSTER_SIGNING_KEY`
- `CLUSTER_PKI_DIR`
- `NODE_CERT_VALIDITY_DAYS`
- `CLUSTER_LEASE_TOKEN_TTL_SECONDS`
- `HEARTBEAT_SIGNATURE_MAX_SKEW_SECONDS`

### etcd and Backups
- `ETCD_ENABLED`
- `ETCD_ENDPOINTS`
- `ETCDCTL_COMMAND`
- `ETCD_PREFIX`
- `ETCD_SNAPSHOT_DIR`
- `ETCD_SNAPSHOT_RETENTION`

### Runtime Loop
- `RUNTIME_ENABLE` (set `false` for Go-agent mode)
- `RUNTIME_NODE_ID`, `RUNTIME_NODE_NAME`, `RUNTIME_NODE_ROLE`
- `RUNTIME_API_BASE_URL`
- `RUNTIME_HEARTBEAT_INTERVAL_SECONDS`, `RUNTIME_HEARTBEAT_TTL_SECONDS`

### WireGuard Runtime
- `RUNTIME_WG_PRIMARY_IFACE`, `RUNTIME_WG_SECONDARY_IFACE`
- `RUNTIME_WG_PRIMARY_ROUTER_IP`, `RUNTIME_WG_SECONDARY_ROUTER_IP`
- `RUNTIME_ROUTE_PRIMARY_METRIC`, `RUNTIME_ROUTE_SECONDARY_METRIC`
- `RUNTIME_FAILOVER_THRESHOLD`, `RUNTIME_FAILBACK_STABLE_COUNT`

### Discovery
- `RUNTIME_DISCOVERY_ENABLE`
- `RUNTIME_DISCOVERY_DOMAIN`
- `RUNTIME_DISCOVERY_ZONE_PATH`
- `RUNTIME_DISCOVERY_RELOAD_COMMAND`

### LXD
- `LXD_ENABLED`
- `LXD_COMMAND`
- `LXD_PROJECT`
- `LXD_DEFAULT_IMAGE`, `LXD_DEFAULT_PROFILE`
- `LXD_HEALTH_TIMEOUT_SECONDS`, `LXD_HEALTH_POLL_SECONDS`

### Support Artifacts
- `SUPPORT_BUNDLE_DIR`

## CLI Commands
The CLI entrypoint is `uptimemesh`.

### Cluster Bootstrap and Join
```bash
uptimemesh bootstrap --api-url http://127.0.0.1:8010
uptimemesh create-token --api-url http://127.0.0.1:8010 --role worker

uptimemesh join \
  --api-url http://127.0.0.1:8010 \
  --token <join-token> \
  --node-id node-a \
  --name node-a \
  --role worker \
  --api-endpoint http://<node-a-ip>:8010

uptimemesh heartbeat --api-url http://127.0.0.1:8010 --node-id node-a
uptimemesh nodes-status --api-url http://127.0.0.1:8010
```

### etcd Operations
```bash
uptimemesh etcd-status --api-url http://127.0.0.1:8010
uptimemesh etcd-members --api-url http://127.0.0.1:8010
```

### Snapshot and Support Ops
```bash
uptimemesh snapshot-run --api-url http://127.0.0.1:8010
uptimemesh snapshot-list --api-url http://127.0.0.1:8010
uptimemesh snapshot-restore --api-url http://127.0.0.1:8010 <snapshot-id>

uptimemesh support-bundle-run --api-url http://127.0.0.1:8010
uptimemesh support-bundle-list --api-url http://127.0.0.1:8010
```

Node identity artifacts are stored under:
- `data/identities/<node-id>/node.key`
- `data/identities/<node-id>/node.crt`
- `data/identities/<node-id>/ca.crt`
- `data/identities/<node-id>/lease.token`

## Versioning
- `version.json` is the version source of truth.
- Runtime version data is loaded from `version.json` (app/manifest/channel/agent).

## Production Notes
- Set `APP_ENV=prod` for strict startup validation.
- Use strong, non-default values for:
  - `AUTH_SECRET_KEY`
  - `CLUSTER_SIGNING_KEY`
- Set `AUTH_COOKIE_SECURE=true` behind HTTPS.
