#!/usr/bin/env bash
set -euo pipefail

DEFAULT_REPO_URL="https://github.com/Dinkum/uptime-mesh"
REPO_URL="${UPTIMEMESH_REPO_URL:-${DEFAULT_REPO_URL}}"
REPO_REF="${UPTIMEMESH_REPO_REF:-main}"
INSTALL_DIR="${UPTIMEMESH_INSTALL_DIR:-/opt/uptime-mesh}"
CONFIG_PATH="${UPTIMEMESH_CONFIG_PATH:-${INSTALL_DIR}/config.yaml}"

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing required command: $1" >&2
    exit 1
  fi
}

as_root() {
  if [[ "${EUID:-$(id -u)}" -eq 0 ]]; then
    "$@"
  else
    if ! command -v sudo >/dev/null 2>&1; then
      echo "sudo is required to run installer as non-root" >&2
      exit 1
    fi
    sudo "$@"
  fi
}

repo_url_from_config() {
  local path="$1"
  if [[ ! -f "$path" ]]; then
    return 1
  fi
  local value=""
  value="$(sed -n -E 's/^[[:space:]]*github_repo_url:[[:space:]]*"?([^"#]+)"?.*$/\1/p' "$path" | head -n 1 | tr -d '[:space:]')"
  if [[ -n "$value" ]]; then
    printf '%s' "$value"
    return 0
  fi
  return 1
}

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_DIR="${SCRIPT_DIR}"

# Remote mode (e.g. curl | bash): clone/update repo, then run root install script there.
if [[ ! -d "${APP_DIR}/app" || ! -f "${APP_DIR}/pyproject.toml" ]]; then
  require_cmd git
  as_root mkdir -p "$(dirname "${INSTALL_DIR}")"
  if config_repo_url="$(repo_url_from_config "${CONFIG_PATH}")"; then
    REPO_URL="${config_repo_url}"
  fi
  if as_root test -d "${INSTALL_DIR}/.git"; then
    as_root git -C "${INSTALL_DIR}" fetch --tags origin
    as_root git -C "${INSTALL_DIR}" checkout "${REPO_REF}"
    as_root git -C "${INSTALL_DIR}" pull --ff-only origin "${REPO_REF}"
  else
    as_root git clone --branch "${REPO_REF}" --depth 1 "${REPO_URL}" "${INSTALL_DIR}"
  fi

  if [[ "${EUID:-$(id -u)}" -eq 0 ]]; then
    exec "${INSTALL_DIR}/install.sh" "$@"
  fi
  exec sudo "${INSTALL_DIR}/install.sh" "$@"
fi

usage() {
  cat <<'USAGE'
Usage:
  sudo ./install.sh --node-id <id> --role <core|worker|gateway> [options]
  sudo ./install.sh --wizard

Options:
  --node-id <id>             Node ID (required)
  --name <name>              Node display name (default: node-id)
  --role <role>              core | worker | gateway (required)
  --api-url <url>            Cluster API URL (default: http://127.0.0.1:8010)
  --api-endpoint <url>       This node endpoint advertised to cluster
  --etcd-peer-url <url>      etcd peer URL for core membership (default: derived from node endpoint host:2380)
  --token <join-token>       Join token for enrollment
  --bootstrap                Bootstrap cluster on this node (first node only)
  --port <port>              Local API port (default: 8010)
  --install-deps             Install apt dependencies (python3, venv, pip, curl, ca-certificates, git, go)
  --install-monitoring       Seed Prometheus/Alertmanager/Grafana config (core nodes)
  --wizard                   Interactive setup wizard
  -h, --help                 Show help

Examples:
  # Interactive wizard
  sudo ./install.sh --wizard

  # First node (core)
  sudo ./install.sh --install-deps --bootstrap --node-id node1 --name node1 --role core --api-endpoint http://51.15.211.158:8010 --etcd-peer-url http://51.15.211.158:2380 --install-monitoring

  # Additional worker node
  sudo ./install.sh --install-deps --node-id node2 --name node2 --role worker --api-url http://51.15.211.158:8010 --api-endpoint http://163.172.133.213:8010 --token <worker-token>
USAGE
}

NODE_ID=""
NODE_NAME=""
NODE_ROLE=""
API_URL="http://127.0.0.1:8010"
API_ENDPOINT=""
ETCD_PEER_URL=""
JOIN_TOKEN=""
BOOTSTRAP=0
PORT="8010"
INSTALL_DEPS=0
INSTALL_MONITORING=0
WIZARD=0

prompt_default() {
  local prompt="$1"
  local default_value="$2"
  local reply=""
  read -r -p "${prompt} [${default_value}]: " reply
  if [[ -n "$reply" ]]; then
    printf '%s' "$reply"
  else
    printf '%s' "$default_value"
  fi
}

prompt_required() {
  local prompt="$1"
  local reply=""
  while true; do
    read -r -p "${prompt}: " reply
    if [[ -n "$reply" ]]; then
      printf '%s' "$reply"
      return 0
    fi
    echo "value is required"
  done
}

prompt_yes_no() {
  local prompt="$1"
  local default_value="$2"
  local reply=""
  local normalized=""
  while true; do
    read -r -p "${prompt} [${default_value}]: " reply
    if [[ -z "$reply" ]]; then
      reply="$default_value"
    fi
    normalized="$(printf '%s' "$reply" | tr '[:upper:]' '[:lower:]')"
    case "$normalized" in
      y|yes) printf 'y'; return 0 ;;
      n|no) printf 'n'; return 0 ;;
      *) echo "enter y or n" ;;
    esac
  done
}

detect_public_ip() {
  if command -v curl >/dev/null 2>&1; then
    curl -fsS --max-time 4 https://api.ipify.org || true
  fi
}

derive_etcd_peer_url() {
  local endpoint="$1"
  local parsed=""
  parsed="$(printf '%s\n' "$endpoint" | sed -E 's#^[a-zA-Z]+://##; s#/.*$##; s#:[0-9]+$##')"
  if [[ -n "$parsed" ]]; then
    printf 'http://%s:2380' "$parsed"
  fi
}

run_wizard() {
  local reply=""
  local role=""
  local public_ip=""
  local endpoint_default=""
  local token_prefix=""

  echo "UptimeMesh setup wizard"
  echo "-----------------------"
  reply="$(prompt_yes_no "Install apt dependencies?" "y")"
  if [[ "$reply" == "y" ]]; then
    INSTALL_DEPS=1
  fi

  NODE_ID="$(prompt_required "Node ID")"
  NODE_NAME="$(prompt_default "Node name" "$NODE_ID")"

  while true; do
    role="$(prompt_default "Node role (core|worker|gateway)" "worker")"
    case "$role" in
      core|worker|gateway)
        NODE_ROLE="$role"
        break
        ;;
      *)
        echo "invalid role: $role"
        ;;
    esac
  done

  PORT="$(prompt_default "Local API port" "$PORT")"
  public_ip="$(detect_public_ip)"
  if [[ -n "$public_ip" ]]; then
    endpoint_default="http://${public_ip}:${PORT}"
  else
    endpoint_default="http://127.0.0.1:${PORT}"
  fi
  API_ENDPOINT="$(prompt_default "Advertised API endpoint for this node" "$endpoint_default")"

  if [[ "$NODE_ROLE" == "core" ]]; then
    ETCD_PEER_URL="$(prompt_default "etcd peer URL for this core node" "$(derive_etcd_peer_url "$API_ENDPOINT")")"
    reply="$(prompt_yes_no "Is this the first cluster node (bootstrap)?" "n")"
    if [[ "$reply" == "y" ]]; then
      BOOTSTRAP=1
      API_URL="$(prompt_default "API URL used for bootstrap" "http://127.0.0.1:${PORT}")"
    fi
    reply="$(prompt_yes_no "Seed monitoring configs (Prometheus/Grafana/Alertmanager)?" "y")"
    if [[ "$reply" == "y" ]]; then
      INSTALL_MONITORING=1
    fi
  fi

  if [[ "$BOOTSTRAP" -ne 1 ]]; then
    API_URL="$(prompt_default "Cluster API URL (core node)" "$API_URL")"
    JOIN_TOKEN="$(prompt_default "Join token (leave blank for install-only)" "")"
  fi

  echo
  echo "Summary:"
  echo "  node_id:      $NODE_ID"
  echo "  node_name:    $NODE_NAME"
  echo "  role:         $NODE_ROLE"
  echo "  api_url:      $API_URL"
  echo "  api_endpoint: $API_ENDPOINT"
  echo "  port:         $PORT"
  echo "  bootstrap:    $BOOTSTRAP"
  echo "  etcd_peer:    ${ETCD_PEER_URL:-"(auto/none)"}"
  echo "  monitoring:   $INSTALL_MONITORING"
  if [[ -n "$JOIN_TOKEN" ]]; then
    token_prefix="${JOIN_TOKEN:0:8}"
    echo "  join_token:   ${token_prefix}..."
  else
    echo "  join_token:   (none)"
  fi
  echo "  install_deps: $INSTALL_DEPS"
  echo

  reply="$(prompt_yes_no "Proceed with install?" "y")"
  if [[ "$reply" != "y" ]]; then
    echo "aborted"
    exit 0
  fi
}

if [[ $# -eq 0 ]]; then
  WIZARD=1
fi

while [[ $# -gt 0 ]]; do
  case "$1" in
    --node-id)
      NODE_ID="$2"; shift 2 ;;
    --name)
      NODE_NAME="$2"; shift 2 ;;
    --role)
      NODE_ROLE="$2"; shift 2 ;;
    --api-url)
      API_URL="$2"; shift 2 ;;
    --api-endpoint)
      API_ENDPOINT="$2"; shift 2 ;;
    --etcd-peer-url)
      ETCD_PEER_URL="$2"; shift 2 ;;
    --token)
      JOIN_TOKEN="$2"; shift 2 ;;
    --bootstrap)
      BOOTSTRAP=1; shift ;;
    --port)
      PORT="$2"; shift 2 ;;
    --install-deps)
      INSTALL_DEPS=1; shift ;;
    --install-monitoring)
      INSTALL_MONITORING=1; shift ;;
    --wizard)
      WIZARD=1; shift ;;
    -h|--help)
      usage; exit 0 ;;
    *)
      echo "unknown argument: $1" >&2
      usage
      exit 1 ;;
  esac
done

if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
  echo "run as root (use sudo)" >&2
  exit 1
fi

if [[ "$WIZARD" -eq 1 ]]; then
  run_wizard
fi

if [[ -z "$NODE_ID" ]]; then
  echo "--node-id is required" >&2
  exit 1
fi
if [[ -z "$NODE_ROLE" ]]; then
  echo "--role is required" >&2
  exit 1
fi
case "$NODE_ROLE" in
  core|worker|gateway) ;;
  *)
    echo "--role must be one of: core, worker, gateway" >&2
    exit 1 ;;
esac

if [[ -z "$NODE_NAME" ]]; then
  NODE_NAME="$NODE_ID"
fi
if [[ -z "$API_ENDPOINT" ]]; then
  API_ENDPOINT="http://127.0.0.1:${PORT}"
fi
if [[ -z "$ETCD_PEER_URL" && "$NODE_ROLE" == "core" ]]; then
  ETCD_PEER_URL="$(derive_etcd_peer_url "$API_ENDPOINT")"
fi

if [[ "$BOOTSTRAP" -eq 1 && "$NODE_ROLE" != "core" ]]; then
  echo "--bootstrap requires --role core" >&2
  exit 1
fi
if [[ "$BOOTSTRAP" -eq 1 && -n "$JOIN_TOKEN" ]]; then
  echo "do not pass --token with --bootstrap" >&2
  exit 1
fi

if [[ "$INSTALL_DEPS" -eq 1 ]]; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y
  apt-get install -y python3 python3-venv python3-pip curl ca-certificates git golang-go iproute2 iputils-ping
  if [[ "$NODE_ROLE" == "worker" ]]; then
    apt-get install -y lxd || true
  fi
  if [[ "$NODE_ROLE" == "core" ]]; then
    apt-get install -y etcd || true
  fi
  if [[ "$INSTALL_MONITORING" -eq 1 ]]; then
    apt-get install -y prometheus prometheus-node-exporter prometheus-alertmanager || true
  fi
fi

require_cmd python3
require_cmd curl
require_cmd systemctl

cd "$APP_DIR"

if [[ ! -d .venv ]]; then
  python3 -m venv .venv
fi

.venv/bin/pip install --upgrade pip
.venv/bin/pip install -e .
mkdir -p data

require_cmd go
mkdir -p bin
go build -trimpath -ldflags="-s -w" -o "${APP_DIR}/bin/uptimemesh-agent" "./agent/cmd/uptimemesh-agent"

if [[ ! -f .env ]]; then
  if [[ -f .env.example ]]; then
    cp .env.example .env
  else
    : > .env
  fi
fi

python3 - <<PY
import pathlib
import secrets

env_path = pathlib.Path(".env")
lines = env_path.read_text(encoding="utf-8").splitlines()
kv = {}
for line in lines:
    if "=" in line and not line.lstrip().startswith("#"):
        k, v = line.split("=", 1)
        kv[k.strip()] = v.strip()

def setv(key: str, value: str) -> None:
    kv[key] = value

setv("DATABASE_URL", "sqlite+aiosqlite:///./data/app.db")
setv("LOG_LEVEL", kv.get("LOG_LEVEL", "INFO") or "INFO")
setv("LOG_FILE", "./data/app.log")
setv("AGENT_LOG_FILE", kv.get("AGENT_LOG_FILE", "./data/agent.log") or "./data/agent.log")
setv("MANAGED_CONFIG_PATH", kv.get("MANAGED_CONFIG_PATH", "config.yaml") or "config.yaml")
setv("METRICS_ENABLED", kv.get("METRICS_ENABLED", "true") or "true")
default_etcd_enabled = "true" if "${NODE_ROLE}" == "core" else "false"
setv("ETCD_ENABLED", kv.get("ETCD_ENABLED", default_etcd_enabled) or default_etcd_enabled)
default_etcd_endpoints = "http://127.0.0.1:2379" if "${NODE_ROLE}" == "core" else ""
setv("ETCD_ENDPOINTS", kv.get("ETCD_ENDPOINTS", default_etcd_endpoints) or default_etcd_endpoints)
setv("ETCDCTL_COMMAND", kv.get("ETCDCTL_COMMAND", "etcdctl") or "etcdctl")
setv("ETCD_PREFIX", kv.get("ETCD_PREFIX", "/uptimemesh") or "/uptimemesh")
setv("ETCD_DIAL_TIMEOUT_SECONDS", kv.get("ETCD_DIAL_TIMEOUT_SECONDS", "5") or "5")
setv("ETCD_COMMAND_TIMEOUT_SECONDS", kv.get("ETCD_COMMAND_TIMEOUT_SECONDS", "10") or "10")
setv("ETCD_SNAPSHOT_DIR", kv.get("ETCD_SNAPSHOT_DIR", "data/etcd-snapshots") or "data/etcd-snapshots")
setv("ETCD_SNAPSHOT_RETENTION", kv.get("ETCD_SNAPSHOT_RETENTION", "30") or "30")
setv("SUPPORT_BUNDLE_DIR", kv.get("SUPPORT_BUNDLE_DIR", "data/support-bundles") or "data/support-bundles")
setv("LXD_ENABLED", kv.get("LXD_ENABLED", "true") or "true")
setv("LXD_COMMAND", kv.get("LXD_COMMAND", "lxc") or "lxc")
setv("LXD_PROJECT", kv.get("LXD_PROJECT", "default") or "default")
setv("LXD_DEFAULT_IMAGE", kv.get("LXD_DEFAULT_IMAGE", "images:ubuntu/22.04") or "images:ubuntu/22.04")
setv("LXD_DEFAULT_PROFILE", kv.get("LXD_DEFAULT_PROFILE", "default") or "default")
setv("LXD_HEALTH_TIMEOUT_SECONDS", kv.get("LXD_HEALTH_TIMEOUT_SECONDS", "60") or "60")
setv("LXD_HEALTH_POLL_SECONDS", kv.get("LXD_HEALTH_POLL_SECONDS", "2") or "2")
setv("RUNTIME_ENABLE", "false")
setv("RUNTIME_NODE_ID", "${NODE_ID}")
setv("RUNTIME_NODE_NAME", "${NODE_NAME}")
setv("RUNTIME_NODE_ROLE", "${NODE_ROLE}")
setv("RUNTIME_API_BASE_URL", "http://127.0.0.1:${PORT}")
setv("RUNTIME_IDENTITY_DIR", "./data/identities")
setv("RUNTIME_HEARTBEAT_INTERVAL_SECONDS", kv.get("RUNTIME_HEARTBEAT_INTERVAL_SECONDS", "10") or "10")
setv("RUNTIME_HEARTBEAT_TTL_SECONDS", kv.get("RUNTIME_HEARTBEAT_TTL_SECONDS", "45") or "45")
setv("RUNTIME_MESH_CIDR", kv.get("RUNTIME_MESH_CIDR", "10.42.0.0/16") or "10.42.0.0/16")
setv("RUNTIME_WG_PRIMARY_IFACE", kv.get("RUNTIME_WG_PRIMARY_IFACE", "wg-mesh0") or "wg-mesh0")
setv("RUNTIME_WG_SECONDARY_IFACE", kv.get("RUNTIME_WG_SECONDARY_IFACE", "wg-mesh1") or "wg-mesh1")
setv("RUNTIME_WG_CONFIGURE", kv.get("RUNTIME_WG_CONFIGURE", "true") or "true")
setv("RUNTIME_WG_KEY_DIR", kv.get("RUNTIME_WG_KEY_DIR", "data/wireguard") or "data/wireguard")
setv("RUNTIME_WG_LOCAL_ADDRESS", kv.get("RUNTIME_WG_LOCAL_ADDRESS", ""))
setv("RUNTIME_WG_PRIMARY_LISTEN_PORT", kv.get("RUNTIME_WG_PRIMARY_LISTEN_PORT", "51820") or "51820")
setv("RUNTIME_WG_SECONDARY_LISTEN_PORT", kv.get("RUNTIME_WG_SECONDARY_LISTEN_PORT", "51821") or "51821")
setv("RUNTIME_WG_PEER_PORT", kv.get("RUNTIME_WG_PEER_PORT", "51820") or "51820")
setv("RUNTIME_WG_PEER_ALLOWED_IPS", kv.get("RUNTIME_WG_PEER_ALLOWED_IPS", ""))
setv(
    "RUNTIME_WG_PERSISTENT_KEEPALIVE_SECONDS",
    kv.get("RUNTIME_WG_PERSISTENT_KEEPALIVE_SECONDS", "25") or "25",
)
setv("RUNTIME_WG_PRIMARY_PEER_PUBLIC_KEY", kv.get("RUNTIME_WG_PRIMARY_PEER_PUBLIC_KEY", ""))
setv("RUNTIME_WG_SECONDARY_PEER_PUBLIC_KEY", kv.get("RUNTIME_WG_SECONDARY_PEER_PUBLIC_KEY", ""))
setv("RUNTIME_WG_PRIMARY_PEER_ENDPOINT", kv.get("RUNTIME_WG_PRIMARY_PEER_ENDPOINT", ""))
setv("RUNTIME_WG_SECONDARY_PEER_ENDPOINT", kv.get("RUNTIME_WG_SECONDARY_PEER_ENDPOINT", ""))
setv("RUNTIME_WG_PRIMARY_ROUTER_IP", kv.get("RUNTIME_WG_PRIMARY_ROUTER_IP", "10.42.0.1") or "10.42.0.1")
setv("RUNTIME_WG_SECONDARY_ROUTER_IP", kv.get("RUNTIME_WG_SECONDARY_ROUTER_IP", "10.42.0.2") or "10.42.0.2")
setv("RUNTIME_FAILOVER_THRESHOLD", kv.get("RUNTIME_FAILOVER_THRESHOLD", "3") or "3")
setv("RUNTIME_FAILBACK_STABLE_COUNT", kv.get("RUNTIME_FAILBACK_STABLE_COUNT", "6") or "6")
setv("RUNTIME_FAILBACK_ENABLED", kv.get("RUNTIME_FAILBACK_ENABLED", "false") or "false")
setv("RUNTIME_ROUTE_PRIMARY_METRIC", kv.get("RUNTIME_ROUTE_PRIMARY_METRIC", "100") or "100")
setv("RUNTIME_ROUTE_SECONDARY_METRIC", kv.get("RUNTIME_ROUTE_SECONDARY_METRIC", "200") or "200")
setv("RUNTIME_ETCD_ENDPOINTS", kv.get("RUNTIME_ETCD_ENDPOINTS", default_etcd_endpoints) or default_etcd_endpoints)
setv("RUNTIME_ETCD_PROBE_INTERVAL_SECONDS", kv.get("RUNTIME_ETCD_PROBE_INTERVAL_SECONDS", "10") or "10")
default_discovery = "true" if "${NODE_ROLE}" == "core" else "false"
setv("RUNTIME_DISCOVERY_ENABLE", kv.get("RUNTIME_DISCOVERY_ENABLE", default_discovery) or default_discovery)
setv("RUNTIME_DISCOVERY_DOMAIN", kv.get("RUNTIME_DISCOVERY_DOMAIN", "mesh.local") or "mesh.local")
setv("RUNTIME_DISCOVERY_TTL_SECONDS", kv.get("RUNTIME_DISCOVERY_TTL_SECONDS", "30") or "30")
setv(
    "RUNTIME_DISCOVERY_ZONE_PATH",
    kv.get("RUNTIME_DISCOVERY_ZONE_PATH", "data/coredns/db.mesh.local") or "data/coredns/db.mesh.local",
)
setv("RUNTIME_DISCOVERY_INTERVAL_SECONDS", kv.get("RUNTIME_DISCOVERY_INTERVAL_SECONDS", "10") or "10")
setv("RUNTIME_DISCOVERY_RELOAD_COMMAND", kv.get("RUNTIME_DISCOVERY_RELOAD_COMMAND", ""))

if (not kv.get("AUTH_SECRET_KEY")) or kv["AUTH_SECRET_KEY"].startswith("change-me"):
    setv("AUTH_SECRET_KEY", secrets.token_hex(32))
if (not kv.get("CLUSTER_SIGNING_KEY")) or kv["CLUSTER_SIGNING_KEY"].startswith("change-me"):
    setv("CLUSTER_SIGNING_KEY", secrets.token_hex(32))

ordered = sorted(kv.items(), key=lambda x: x[0])
env_path.write_text("".join(f"{k}={v}\n" for k, v in ordered), encoding="utf-8")
PY

.venv/bin/alembic upgrade head

if [[ "$INSTALL_MONITORING" -eq 1 ]]; then
  install -d /etc/uptime-mesh/monitoring/grafana/provisioning/dashboards
  install -d /etc/uptime-mesh/monitoring/grafana/provisioning/datasources
  install -d /etc/uptime-mesh/monitoring/grafana/dashboards
  cp "${APP_DIR}/ops/monitoring/prometheus.yml" /etc/uptime-mesh/monitoring/prometheus.yml
  cp "${APP_DIR}/ops/monitoring/alert_rules.yml" /etc/uptime-mesh/monitoring/alert_rules.yml
  cp "${APP_DIR}/ops/monitoring/alertmanager.yml" /etc/uptime-mesh/monitoring/alertmanager.yml
  cp "${APP_DIR}/ops/monitoring/grafana/provisioning/dashboards/uptimemesh.yml" /etc/uptime-mesh/monitoring/grafana/provisioning/dashboards/uptimemesh.yml
  cp "${APP_DIR}/ops/monitoring/grafana/provisioning/datasources/uptimemesh.yml" /etc/uptime-mesh/monitoring/grafana/provisioning/datasources/uptimemesh.yml
  cp "${APP_DIR}/ops/monitoring/grafana/dashboards/uptimemesh-overview.json" /etc/uptime-mesh/monitoring/grafana/dashboards/uptimemesh-overview.json
fi

cat > /etc/systemd/system/uptime-mesh.service <<SYSTEMD
[Unit]
Description=UptimeMesh API
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=${APP_DIR}
ExecStart=${APP_DIR}/.venv/bin/uvicorn app.main:app --host 0.0.0.0 --port ${PORT}
Restart=always
RestartSec=2
Environment=PYTHONUNBUFFERED=1
Environment=LOG_FILE=./data/app.log

[Install]
WantedBy=multi-user.target
SYSTEMD

cat > /etc/systemd/system/uptime-mesh-agent.service <<SYSTEMD
[Unit]
Description=UptimeMesh Go Agent
After=network-online.target uptime-mesh.service
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=${APP_DIR}
ExecStart=${APP_DIR}/bin/uptimemesh-agent --env-file ${APP_DIR}/.env
Restart=always
RestartSec=2
Environment=PYTHONUNBUFFERED=1
Environment=LOG_FILE=./data/agent.log
Environment=AGENT_LOG_FILE=./data/agent.log

[Install]
WantedBy=multi-user.target
SYSTEMD

systemctl daemon-reload
systemctl enable --now uptime-mesh.service

for _ in 1 2 3 4 5 6 7 8 9 10; do
  if curl -fsS "http://127.0.0.1:${PORT}/health" >/dev/null 2>&1; then
    break
  fi
  sleep 1
done
curl -fsS "http://127.0.0.1:${PORT}/health" >/dev/null

if [[ "$BOOTSTRAP" -eq 1 ]]; then
  bootstrap_json="$(${APP_DIR}/.venv/bin/uptimemesh --api-url "${API_URL}" bootstrap --username admin --password uptime)"
  core_token="$(printf '%s' "$bootstrap_json" | python3 -c 'import json,sys; print(json.load(sys.stdin)["core_token"]["token"])')"
  worker_token="$(printf '%s' "$bootstrap_json" | python3 -c 'import json,sys; print(json.load(sys.stdin)["worker_token"]["token"])')"
  join_cmd=(
    "${APP_DIR}/.venv/bin/uptimemesh" --api-url "${API_URL}" join
    --token "${core_token}"
    --node-id "${NODE_ID}"
    --name "${NODE_NAME}"
    --role "${NODE_ROLE}"
    --api-endpoint "${API_ENDPOINT}"
    --identity-dir ./data/identities
  )
  if [[ -n "$ETCD_PEER_URL" ]]; then
    join_cmd+=(--etcd-peer-url "${ETCD_PEER_URL}")
  fi
  "${join_cmd[@]}"

  echo "Bootstrap complete."
  echo "Worker token (save this): ${worker_token}"
elif [[ -n "$JOIN_TOKEN" ]]; then
  join_cmd=(
    "${APP_DIR}/.venv/bin/uptimemesh" --api-url "${API_URL}" join
    --token "${JOIN_TOKEN}"
    --node-id "${NODE_ID}"
    --name "${NODE_NAME}"
    --role "${NODE_ROLE}"
    --api-endpoint "${API_ENDPOINT}"
    --identity-dir ./data/identities
  )
  if [[ -n "$ETCD_PEER_URL" ]]; then
    join_cmd+=(--etcd-peer-url "${ETCD_PEER_URL}")
  fi
  "${join_cmd[@]}"
  echo "Join complete."
else
  echo "Install complete (service running)."
  echo "Next: run join with --token, or run this script with --bootstrap on the first core node."
fi

if [[ -f "${APP_DIR}/data/identities/${NODE_ID}/node.key" && -f "${APP_DIR}/data/identities/${NODE_ID}/lease.token" ]]; then
  systemctl enable --now uptime-mesh-agent.service
  echo "Go agent service started."
else
  systemctl disable --now uptime-mesh-agent.service >/dev/null 2>&1 || true
  echo "Go agent not started yet (missing identity artifacts)."
fi

echo "Status:"
${APP_DIR}/.venv/bin/uptimemesh --api-url "${API_URL}" nodes-status || true
