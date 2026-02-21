# UptimeMesh

> Self-healing private mesh control plane for small to mid-sized clusters.

UptimeMesh gives you a WireGuard-backed, etcd-powered mesh with a Go agent, LXD sandboxes, and a Web UI / CLI for day-2 ops. It’s designed to be source-first, observable, and safe to fail over.

This repo contains the V1 control plane, UI, Go agent, and operational tooling.

---

## Highlights

- 🔐 **Encrypted mesh**: WireGuard for node-to-node transport.
- 🧠 **Cluster truth**: etcd for replicated state and coordination.
- 🤖 **Node agent**: standalone Go agent (`uptimemesh-agent`) for reconcile loops and signed heartbeats.
- 🔌 **Local agent control**: unix socket admin API (`data/agent.sock`) with `/healthz`, `/version`, `/status`.
- 🧱 **Workload sandboxes**: LXD containers with snapshot/restore and rollout/rollback primitives.
- 🖥️ **UI + CLI**: built-in Web UI and ASCII-first `uptimemesh` CLI.
- 📊 **Observability-ready**: Prometheus config reconciliation, Grafana dashboard provisioning, Alertmanager rules, and structured logs (`app.log`, `agent.log`).
- 🔁 **Failover foundations**: dual WireGuard interfaces and route metric switching for runtime failover.
- 🧭 **Router assignment automation**: node joins auto-reconcile primary/secondary router assignments.
- 🔎 **Discovery**: CoreDNS zone generation (`mesh.local`) from the health registry.
- 🌐 **Gateway**: NGINX route rendering with validate -> reload -> health-check -> rollback safety.
- 🌍 **Domain routing**: map custom domains/subdomains to applications and service backends.
- 🔑 **Provider settings**: OpenAI, Cloudflare, Hetzner, Scaleway, and Online.net API integration fields in UI settings.

---

## Quickstart

### 1. First Node Install (auto-bootstrap)

Run this on the first node in a new mesh:

```bash
sudo ./install.sh
```

This command is first-node mode by default:
- generated short UUID node ID
- generated 3-word node name
- role defaults to `auto` (runtime role chosen automatically)
- auto-bootstraps the cluster
- seeds monitoring config
- required dependencies installed automatically

At the end of a first-node bootstrap, the installer prints generated admin credentials once
(`username` + password).

Direct from GitHub:

```bash
curl -fsSL https://raw.githubusercontent.com/Dinkum/uptime-mesh/main/install.sh | bash
```

---

### 2. Verify in UI or CLI

Web UI:
- `http://<first-node-ip>:8010/ui`

Basic CLI checks (run on the first node):
```bash
uptime-mesh --api-url http://127.0.0.1:8010 nodes-status --username <admin-username> --password <admin-pass>
```

---

### 3. Join More Nodes

Join flow (peer + one-time token; defaults to port `8010`):

```bash
sudo ./install.sh --join <cluster-node-ip> --token <join-token>
```

Non-default peer port:

```bash
sudo ./install.sh --join <cluster-node-ip> --join-port 9010 --token <join-token>
```

Optional: use wizard or explicit flags:

```bash
sudo ./install.sh --wizard
```

### Optional Install Command Flags

- `--wizard`: interactive setup flow.
- `--join <peer-ip|url>`: join an existing mesh via peer API.
- `--join-port <port>`: peer API port for `--join` (default `8010`).
- `--name <name>`: override node display name.
- `--role <auto|backend_server|reverse_proxy>`: optional role override (default `auto`).
- `--api-endpoint <url>`: advertised API endpoint for this node.
- `--api-url <url>`: cluster API URL (used for join/bootstrap paths).
- `--token <join-token>`: required in join mode.
- `--install-deps`: force apt dependency installation.
- `--port <port>`: local API port (default `8010`).

---

## Architecture

```text
                  +---------------------------+
                  |        Web UI / CLI       |
                  +-------------+-------------+
                                |
                                v
                  +---------------------------+
                  |   FastAPI Control Plane   |
                  |    auth / APIs / events   |
                  +-------------+-------------+
                                |
                                v
                  +---------------------------+
                  |        etcd Quorum        |
                  |     cluster truth/audit   |
                  +-------------+-------------+
                                |
                                v
        =============================================================
        =               WireGuard Mesh (private fabric)             =
        =============================================================
          +----------------+    +----------------+    +----------------+
          |     NODE A     |    |     NODE B     |    |     NODE C     |
          |----------------|    |----------------|    |----------------|
          |  Go agent      |    |  Go agent      |    |  Go agent      |
          |  LXD sandboxes |    |  LXD sandboxes |    |  LXD sandboxes |
          |  WG peer       |    |  WG peer       |    |  WG peer       |
          +----------------+    +----------------+    +----------------+
```

### Node Roles

* **Node (role-agnostic install)**

  * Runs API/UI and the Go agent loop.
  * etcd member (when configured).
  * Executes LXD workload actions.
  * Receives runtime role placement automatically (or explicit override).

### Control Behavior

* Writes are guarded when etcd is `down`, `unavailable`, or `stale`.
* Existing workloads and local runtime logic continue during partial control-plane degradation.

---

## Configuration

Config is split between:

* `.env` – runtime environment settings (see `.env.example`).
* `config.yaml` – managed cluster-level config (auto-generated and auto-healed).

`config.yaml`:

* Created automatically if missing.
* Rebuilt with defaults when keys are missing.
* Written in stable key order with section comments.
* Updated immediately when managed values change via UI/API.

High-level areas (non-exhaustive):

### Core App

* `APP_ENV` (set to `prod`)
* `DATABASE_URL`
* `LOG_LEVEL`, `LOG_FILE`
* `METRICS_ENABLED`

### Routing & Provider Integrations

* `applications_json`, `domain_routes_json`, `domain_ingress_target`
* `provider_openai_api_key`
* `provider_cloudflare_api_token`, `provider_cloudflare_zone_id`
* `provider_hetzner_api_token`, `provider_scaleway_api_token`, `provider_online_api_token`

### Auth & Security

* `AUTH_SECRET_KEY`, `AUTH_COOKIE_SECURE`
* `CLUSTER_SIGNING_KEY`, `CLUSTER_PKI_DIR`
* `NODE_CERT_VALIDITY_DAYS`
* `CLUSTER_LEASE_TOKEN_TTL_SECONDS`
* `HEARTBEAT_SIGNATURE_MAX_SKEW_SECONDS`

### etcd & Backups

* `ETCD_ENABLED`, `ETCD_ENDPOINTS`, `ETCD_PREFIX`
* `ETCD_SNAPSHOT_DIR`, `ETCD_SNAPSHOT_RETENTION`

### Runtime / Agent Loop

* `RUNTIME_ENABLE`
* `RUNTIME_NODE_ID`, `RUNTIME_NODE_NAME`, `RUNTIME_NODE_ROLE`
* `RUNTIME_API_BASE_URL`
* `RUNTIME_HEARTBEAT_INTERVAL_SECONDS`, `RUNTIME_HEARTBEAT_TTL_SECONDS`

### WireGuard Failover

* `RUNTIME_WG_PRIMARY_IFACE`, `RUNTIME_WG_SECONDARY_IFACE`
* `RUNTIME_WG_PRIMARY_ROUTER_IP`, `RUNTIME_WG_SECONDARY_ROUTER_IP`
* `RUNTIME_ROUTE_PRIMARY_METRIC`, `RUNTIME_ROUTE_SECONDARY_METRIC`
* `RUNTIME_FAILOVER_THRESHOLD`, `RUNTIME_FAILBACK_STABLE_COUNT`

### Discovery

* `RUNTIME_DISCOVERY_ENABLE`
* `RUNTIME_DISCOVERY_DOMAIN`
* `RUNTIME_DISCOVERY_ZONE_PATH`
* `RUNTIME_DISCOVERY_COREFILE_PATH`
* `RUNTIME_DISCOVERY_LISTEN`
* `RUNTIME_DISCOVERY_FORWARDERS`
* `RUNTIME_DISCOVERY_RELOAD_COMMAND`

### Gateway

* `RUNTIME_GATEWAY_ENABLE`
* `RUNTIME_GATEWAY_CONFIG_PATH`
* `RUNTIME_GATEWAY_CANDIDATE_PATH`
* `RUNTIME_GATEWAY_BACKUP_PATH`
* `RUNTIME_GATEWAY_LISTEN`
* `RUNTIME_GATEWAY_SERVER_NAME`
* `RUNTIME_GATEWAY_VALIDATE_COMMAND`
* `RUNTIME_GATEWAY_RELOAD_COMMAND`
* `RUNTIME_GATEWAY_HEALTHCHECK_URLS`

### LXD

* `LXD_ENABLED`, `LXD_COMMAND`, `LXD_PROJECT`
* `LXD_DEFAULT_IMAGE`, `LXD_DEFAULT_PROFILE`
* `LXD_HEALTH_TIMEOUT_SECONDS`, `LXD_HEALTH_POLL_SECONDS`

### Support Artifacts

* `SUPPORT_BUNDLE_DIR`

For the full list, use `.env.example` as the source of truth.

---

## CLI

CLI entrypoint: `uptimemesh`.

### Cluster Bootstrap / Join

```bash
uptimemesh bootstrap --api-url http://127.0.0.1:8010 --username <admin-username> --password <admin-pass>
uptimemesh create-token --api-url http://127.0.0.1:8010 --username <admin-username> --password <admin-pass> --role auto

uptimemesh join \
  --api-url http://127.0.0.1:8010 \
  --token <join-token> \
  --node-id node-a \
  --name node-a \
  --api-endpoint http://<node-a-ip>:8010

uptimemesh heartbeat --api-url http://127.0.0.1:8010 --node-id node-a
uptimemesh nodes-status --api-url http://127.0.0.1:8010 --username <admin-username> --password <admin-pass>
```

### etcd Operations

```bash
uptimemesh etcd-members --api-url http://127.0.0.1:8010 --username <admin-username> --password <admin-pass>
uptimemesh etcd-quorum --api-url http://127.0.0.1:8010 --username <admin-username> --password <admin-pass>
uptimemesh etcd-reconcile --api-url http://127.0.0.1:8010 --username <admin-username> --password <admin-pass> --dry-run
```

### Replica & Placement Operations

```bash
uptimemesh replica-move \
  --api-url http://127.0.0.1:8010 \
  --username <admin-username> \
  --password <admin-pass> \
  --replica-id <replica-id> \
  --target-node-id <node-id>

uptimemesh service-apply-pinned \
  --api-url http://127.0.0.1:8010 \
  --username <admin-username> \
  --password <admin-pass> \
  --service-id <service-id>
```

Pinned placement spec (in `service.spec`) supports either `pinned_replicas` or `placement.pinned_replicas`:

```yaml
pinned_replicas:
  - replica_id: web-a
    node_id: node-a
    desired_state: running
  - replica_id: web-b
    node_id: node-b
    desired_state: running
```

Gateway route spec (in `service.spec`) enables ingress for a service:

```yaml
gateway:
  enabled: true
  host: mesh.local
  path: /web/
```

### Snapshots & Support

```bash
uptimemesh snapshot-run --api-url http://127.0.0.1:8010 --username <admin-username> --password <admin-pass>
uptimemesh snapshot-list --api-url http://127.0.0.1:8010 --username <admin-username> --password <admin-pass>
uptimemesh snapshot-restore --api-url http://127.0.0.1:8010 <snapshot-id> --username <admin-username> --password <admin-pass>
uptimemesh snapshot-download --api-url http://127.0.0.1:8010 <snapshot-id> --output ./snapshot.db --username <admin-username> --password <admin-pass>

uptimemesh support-bundle-run --api-url http://127.0.0.1:8010 --username <admin-username> --password <admin-pass>
uptimemesh support-bundle-list --api-url http://127.0.0.1:8010 --username <admin-username> --password <admin-pass>
uptimemesh support-bundle-download --api-url http://127.0.0.1:8010 <bundle-id> --output ./bundle.tar.gz --username <admin-username> --password <admin-pass>
```

Scheduled etcd snapshots are enabled by default and controlled via:
- `ETCD_SNAPSHOT_SCHEDULE_ENABLED`
- `ETCD_SNAPSHOT_INTERVAL_SECONDS`
- `ETCD_SNAPSHOT_SCHEDULE_REQUESTED_BY`

Node identity artifacts live under:

* `data/identities/<node-id>/node.key`
* `data/identities/<node-id>/node.crt`
* `data/identities/<node-id>/ca.crt`
* `data/identities/<node-id>/lease.token`

---

## Versioning

* `version.json` is the single version source of truth.
* Runtime version data (app/manifest/channel/agent) is loaded from `version.json`.

---

## Operational Notes

* `APP_ENV` should be set to `prod` (supported mode).
* `AUTH_SECRET_KEY` and `CLUSTER_SIGNING_KEY` are internal secrets and are auto-generated by installer/bootstrap flows.
* Joining nodes receive cluster-consistent internal signing secrets during enrollment; manual key editing is not required.
* Operators should only touch those keys for explicit rotation/recovery procedures.
* Behind HTTPS, set `AUTH_COOKIE_SECURE=true`.
* Local agent admin API (unix socket): `curl --unix-socket data/agent.sock http://localhost/status`
