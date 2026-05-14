# UptimeMesh

Private mesh control for small clusters that need encrypted node traffic, visible health, and practical failover without a large platform team.

UptimeMesh ships a FastAPI control plane, Web UI, CLI, Go node agent, WireGuard runtime, etcd coordination, LXD workload hooks, gateway routing, discovery, monitoring, snapshots, and support bundle tooling.

## What It Does

* Builds a private WireGuard mesh for node traffic.
* Tracks cluster state with etcd when quorum support is enabled.
* Runs a Go agent on each node for heartbeats, role runtime, WireGuard reconcile, and local status.
* Provides a Web UI and `uptimemesh` CLI for common operator tasks.
* Manages LXD workload placement, snapshots, restore requests, and replica moves.
* Renders CoreDNS, NGINX, and Prometheus config from current cluster state.
* Supports domain routing and provider settings for OpenAI, Cloudflare, Hetzner, Scaleway, and Online.net.
* Creates support bundles with sanitized cluster state and useful diagnostics.

## Quickstart

### 1. Install The First Node

Run this on the first node in a new mesh:

```bash
sudo ./install.sh
```

The first node install will:

* create a short node ID
* create a readable node name
* use the `auto` role unless you set one
* bootstrap the cluster
* seed monitoring config
* install required system packages

The installer prints generated admin credentials once at the end of bootstrap.

Install directly from GitHub:

```bash
curl -fsSL https://raw.githubusercontent.com/Dinkum/uptime-mesh/main/install.sh | bash
```

### 2. Open The UI Or CLI

Web UI:

```text
http://<node-ip>:8010/ui
```

Basic CLI health check:

```bash
uptime-mesh --api-url http://127.0.0.1:8010 nodes-status --username <admin-user> --password <admin-pass>
```

### 3. Join More Nodes

Create a join token in the UI or CLI, then run:

```bash
sudo ./install.sh --join <node-ip> --token <join-token>
```

Use a custom peer port when the first node is not listening on `8010`:

```bash
sudo ./install.sh --join <node-ip> --join-port 9010 --token <join-token>
```

For guided setup:

```bash
sudo ./install.sh --wizard
```

### Install Flags

* `--wizard`: run the interactive setup flow.
* `--join <peer-ip|url>`: join an existing mesh through a peer API.
* `--join-port <port>`: peer API port for join mode. Default: `8010`.
* `--name <name>`: set the node display name.
* `--role <auto|backend_server|reverse_proxy>`: set the runtime role. Default: `auto`.
* `--api-endpoint <url>`: advertise this node API endpoint.
* `--api-url <url>`: set the cluster API URL for join and bootstrap paths.
* `--token <join-token>`: required in join mode.
* `--install-deps`: force dependency installation.
* `--port <port>`: set the local API port. Default: `8010`.

## Architecture

UptimeMesh keeps the operator surface small:

* The Web UI and CLI call the FastAPI control plane.
* The control plane stores durable cluster state in SQLite and can coordinate through etcd.
* Nodes communicate across WireGuard.
* The Go agent runs local reconcile loops and reports signed heartbeats.
* LXD, CoreDNS, NGINX, and Prometheus are updated from declared cluster state.

### Node Behavior

Every installed node can run the API, Web UI, Go agent, and local runtime loops. Runtime role placement decides which nodes serve backend content, reverse proxy traffic, DNS, or other managed roles.

Writes are blocked when etcd is `down`, `unavailable`, or `stale`. Local workloads and node runtime loops continue during partial control plane degradation.

## Common Configuration Options

Most installs only need a few settings. Use `.env.example` as the full reference. The installer also manages `config.yaml`, which is created when missing, repaired when keys are absent, and updated when managed values change through the UI or API.

```dotenv
# Supported runtime mode for deployed nodes.
APP_ENV=prod

# Control plane database. The local default stores SQLite data under ./data.
DATABASE_URL=sqlite+aiosqlite:///./data/app.db

# Log level and app log path.
LOG_LEVEL=INFO
LOG_FILE=data/logs/app.log

# Enable Prometheus style metrics from the app.
METRICS_ENABLED=true

# Browser session secret. Installer and bootstrap flows generate this for real installs.
AUTH_SECRET_KEY=change-me-uptimemesh-auth-secret

# Set this to true when the UI is served through HTTPS.
AUTH_COOKIE_SECURE=false

# Cluster signing secret used for node trust flows. Generated during bootstrap.
CLUSTER_SIGNING_KEY=change-me-uptimemesh-cluster-signing-key

# Node certificate storage and validity period.
CLUSTER_PKI_DIR=data/pki
NODE_CERT_VALIDITY_DAYS=30

# Enable etcd coordination and set endpoints when running a quorum.
ETCD_ENABLED=false
ETCD_ENDPOINTS=

# Snapshot storage, retention, and schedule interval.
ETCD_SNAPSHOT_DIR=data/etcd-snapshots
ETCD_SNAPSHOT_RETENTION=30
ETCD_SNAPSHOT_INTERVAL_SECONDS=86400

# Enable the local runtime controller on nodes that should run reconcile loops.
RUNTIME_ENABLE=false
RUNTIME_NODE_ID=
RUNTIME_NODE_NAME=
RUNTIME_NODE_ROLE=auto
RUNTIME_API_BASE_URL=http://127.0.0.1:8000

# Heartbeat cadence and expiry window for node liveness.
RUNTIME_HEARTBEAT_INTERVAL_SECONDS=15
RUNTIME_HEARTBEAT_TTL_SECONDS=45

# WireGuard interfaces and route metrics used by failover.
RUNTIME_WG_PRIMARY_IFACE=wg-mesh0
RUNTIME_WG_SECONDARY_IFACE=wg-mesh1
RUNTIME_ROUTE_PRIMARY_METRIC=100
RUNTIME_ROUTE_SECONDARY_METRIC=200

# CoreDNS discovery output. Enable this when nodes should render DNS records.
RUNTIME_DISCOVERY_ENABLE=false
RUNTIME_DISCOVERY_DOMAIN=mesh.local
RUNTIME_DISCOVERY_ZONE_PATH=data/coredns/db.mesh.local
RUNTIME_DISCOVERY_COREFILE_PATH=data/coredns/Corefile

# NGINX gateway output. Enable this when nodes should render ingress config.
RUNTIME_GATEWAY_ENABLE=false
RUNTIME_GATEWAY_CONFIG_PATH=data/nginx/nginx.conf
RUNTIME_GATEWAY_LISTEN=0.0.0.0:80
RUNTIME_GATEWAY_SERVER_NAME=_

# LXD execution settings for workload actions.
LXD_ENABLED=true
LXD_COMMAND=lxc
LXD_PROJECT=default
LXD_DEFAULT_IMAGE=images:ubuntu/22.04

# Support bundle output directory.
SUPPORT_BUNDLE_DIR=data/support-bundles
```

## CLI

CLI entrypoint: `uptimemesh`.

### Cluster Bootstrap And Join

```bash
uptimemesh bootstrap --api-url http://127.0.0.1:8010 --username <admin-user> --password <admin-pass>
uptimemesh create-token --api-url http://127.0.0.1:8010 --username <admin-user> --password <admin-pass> --role auto

uptimemesh join \
  --api-url http://127.0.0.1:8010 \
  --token <join-token> \
  --node-id node-a \
  --name node-a \
  --api-endpoint http://<node-ip>:8010

uptimemesh heartbeat --api-url http://127.0.0.1:8010 --node-id node-a
uptimemesh nodes-status --api-url http://127.0.0.1:8010 --username <admin-user> --password <admin-pass>
```

### etcd Operations

```bash
uptimemesh etcd-members --api-url http://127.0.0.1:8010 --username <admin-user> --password <admin-pass>
uptimemesh etcd-quorum --api-url http://127.0.0.1:8010 --username <admin-user> --password <admin-pass>
uptimemesh etcd-reconcile --api-url http://127.0.0.1:8010 --username <admin-user> --password <admin-pass> --dry-run
```

### Replica And Placement Operations

```bash
uptimemesh replica-move \
  --api-url http://127.0.0.1:8010 \
  --username <admin-user> \
  --password <admin-pass> \
  --replica-id <replica-id> \
  --target-node-id <node-id>

uptimemesh service-apply-pinned \
  --api-url http://127.0.0.1:8010 \
  --username <admin-user> \
  --password <admin-pass> \
  --service-id <service-id>
```

Pinned placement in `service.spec` supports either `pinned_replicas` or `placement.pinned_replicas`:

```yaml
pinned_replicas:
  - replica_id: web-a
    node_id: node-a
    desired_state: running
  - replica_id: web-b
    node_id: node-b
    desired_state: running
```

Gateway routing in `service.spec` enables ingress for a service:

```yaml
gateway:
  enabled: true
  host: mesh.local
  path: /web/
```

### Snapshots And Support

```bash
uptimemesh snapshot-run --api-url http://127.0.0.1:8010 --username <admin-user> --password <admin-pass>
uptimemesh snapshot-list --api-url http://127.0.0.1:8010 --username <admin-user> --password <admin-pass>
uptimemesh snapshot-restore --api-url http://127.0.0.1:8010 <snapshot-id> --username <admin-user> --password <admin-pass>
uptimemesh snapshot-download --api-url http://127.0.0.1:8010 <snapshot-id> --output ./snapshot.db --username <admin-user> --password <admin-pass>

uptimemesh support-bundle-run --api-url http://127.0.0.1:8010 --username <admin-user> --password <admin-pass>
uptimemesh support-bundle-list --api-url http://127.0.0.1:8010 --username <admin-user> --password <admin-pass>
uptimemesh support-bundle-download --api-url http://127.0.0.1:8010 <bundle-id> --output ./bundle.tar.gz --username <admin-user> --password <admin-pass>
```

Scheduled etcd snapshots are enabled by default and controlled with:

* `ETCD_SNAPSHOT_SCHEDULE_ENABLED`
* `ETCD_SNAPSHOT_INTERVAL_SECONDS`
* `ETCD_SNAPSHOT_SCHEDULE_REQUESTED_BY`

Node identity artifacts live under:

* `data/identities/<node-id>/node.key`
* `data/identities/<node-id>/node.crt`
* `data/identities/<node-id>/ca.crt`
* `data/identities/<node-id>/lease.token`

## Versioning

`version.json` is the version source for the app, manifest, release channel, and agent metadata.

## Operational Notes

* Keep `APP_ENV=prod` for deployed nodes.
* Installer and bootstrap flows generate `AUTH_SECRET_KEY` and `CLUSTER_SIGNING_KEY`.
* Joining nodes receive cluster signing material during enrollment.
* Only edit internal keys for planned rotation or recovery.
* Set `AUTH_COOKIE_SECURE=true` behind HTTPS.
* Local agent status is available with `curl --unix-socket data/agent.sock http://localhost/status`.
