#!/usr/bin/env bash
set -euo pipefail

DEFAULT_REPO_URL="https://github.com/Dinkum/uptime-mesh"
REPO_URL="${UPTIMEMESH_REPO_URL:-${DEFAULT_REPO_URL}}"
REPO_REF="${UPTIMEMESH_REPO_REF:-main}"
INSTALL_DIR="${UPTIMEMESH_INSTALL_DIR:-/opt/uptime-mesh}"
CONFIG_PATH="${UPTIMEMESH_CONFIG_PATH:-${INSTALL_DIR}/config.yaml}"
INSTALL_LOG=""
LOG_READY=0

say() {
  echo "(*) $*"
}

warn() {
  echo "(!) $*" >&2
}

fail() {
  echo "(x) $*" >&2
  exit 1
}

init_install_log() {
  if [[ "$LOG_READY" -eq 1 ]]; then
    return 0
  fi
  mkdir -p "${APP_DIR}/data"
  INSTALL_LOG="${UPTIMEMESH_INSTALL_LOG:-${APP_DIR}/data/install.log}"
  touch "${INSTALL_LOG}"
  chmod 600 "${INSTALL_LOG}" || true
  exec > >(tee -a "${INSTALL_LOG}") 2>&1
  LOG_READY=1
  echo "----- $(date -u +%Y-%m-%dT%H:%M:%SZ) | install.sh -----"
  say "install.log | path: ${INSTALL_LOG}"
}

run_quiet_command() {
  local label="$1"
  shift
  local tmp_file
  tmp_file="$(mktemp)"
  say "${label}"
  if "$@" >"${tmp_file}" 2>&1; then
    cat "${tmp_file}" >> "${INSTALL_LOG}"
    rm -f "${tmp_file}"
    return 0
  fi
  local rc=$?
  cat "${tmp_file}" >> "${INSTALL_LOG}"
  warn "${label} failed (exit ${rc})"
  warn "last output:"
  tail -n 30 "${tmp_file}" >&2 || true
  rm -f "${tmp_file}"
  return "${rc}"
}

apt_quiet_retry() {
  local label="$1"
  shift
  local attempt=1
  local max_attempts=3
  while (( attempt <= max_attempts )); do
    if run_quiet_command "${label} (attempt ${attempt}/${max_attempts})" "$@"; then
      return 0
    fi
    sleep $((attempt * 2))
    attempt=$((attempt + 1))
  done
  return 1
}

apt_install_optional() {
  local package_name="$1"
  if ! apt_quiet_retry "Install optional package: ${package_name}" apt-get install -y "${package_name}"; then
    warn "optional package not installed: ${package_name}"
  fi
}

unit_exists() {
  local unit="$1"
  systemctl list-unit-files --type=service --no-legend 2>/dev/null | awk '{print $1}' | grep -qx "${unit}"
}

enable_service_if_exists() {
  local unit="$1"
  if unit_exists "${unit}"; then
    systemctl enable --now "${unit}" >/dev/null 2>&1 || warn "failed to enable/start ${unit}"
  else
    warn "service unit not found: ${unit}"
  fi
}

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

init_install_log

usage() {
  cat <<'USAGE'
Usage:
  sudo ./install.sh
  sudo ./install.sh [options]
  sudo ./install.sh --wizard

Options:
  --name <name>              Node display name (default: generated 3-word name)
  --username <username>      Initial admin username for first-node bootstrap (default: admin)
  --role <role>              Optional advanced override: general | backend_server | reverse_proxy | gateway (default: general)
  --join <peer-ip|url>       Join an existing mesh via peer API
  --join-port <port>         Peer API port for --join when omitted in target (default: 8010)
  --api-url <url>            Cluster API URL (default: http://127.0.0.1:8010)
  --api-endpoint <url>       This node endpoint advertised to cluster
  --etcd-peer-url <url>      etcd peer URL for node membership (default: derived from node endpoint host:2380)
  --token <join-token>       Join token for enrollment (required for join mode)
  --port <port>              Local API port (default: 8010)
  --install-deps             Force apt dependency install (auto-enabled by default)
  --wizard                   Interactive setup wizard
  -h, --help                 Show help

Examples:
  # First node (auto-bootstrap + monitoring, generated short UUID node ID)
  sudo ./install.sh

  # Interactive wizard
  sudo ./install.sh --wizard

  # Join an existing mesh (token required)
  sudo ./install.sh --join 51.15.211.158 --token <join-token>
USAGE
}

NODE_ID=""
NODE_NAME=""
INSTALL_ADMIN_USERNAME="admin"
NODE_ROLE=""
API_URL="http://127.0.0.1:8010"
API_ENDPOINT=""
ETCD_PEER_URL=""
JOIN_TOKEN=""
JOIN_TARGET=""
JOIN_PORT="8010"
BOOTSTRAP=0
PORT="8010"
INSTALL_DEPS=0
INSTALL_MONITORING=1
WIZARD=0
INITIAL_ADMIN_USERNAME=""
INITIAL_ADMIN_PASSWORD=""
INITIAL_ADMIN_GENERATED=0
WEB_UI_URL=""

generate_three_word_phrase() {
  local words_a=(amber silent crimson silver golden rapid steady bright cedar iron polar brisk cobalt ember)
  local words_b=(mesa pine river canyon harbor summit valley meadow forest glacier ridge dune orchard basalt)
  local words_c=(falcon otter badger heron wolf kestrel sparrow badger raven hawk fox osprey lynx condor)
  local idx_a=$((RANDOM % ${#words_a[@]}))
  local idx_b=$((RANDOM % ${#words_b[@]}))
  local idx_c=$((RANDOM % ${#words_c[@]}))
  printf '%s-%s-%s' "${words_a[$idx_a]}" "${words_b[$idx_b]}" "${words_c[$idx_c]}"
}

generate_short_uuid() {
  local raw=""
  if [[ -r /proc/sys/kernel/random/uuid ]]; then
    raw="$(cat /proc/sys/kernel/random/uuid | tr -d '-' | cut -c1-8)"
  elif command -v uuidgen >/dev/null 2>&1; then
    raw="$(uuidgen | tr -d '-' | cut -c1-8)"
  elif command -v openssl >/dev/null 2>&1; then
    raw="$(openssl rand -hex 4)"
  else
    raw="$(date +%s | sha256sum | cut -c1-8 2>/dev/null || true)"
  fi
  if [[ -z "$raw" ]]; then
    raw="node$(printf '%04d' "$RANDOM")"
  fi
  printf '%s' "$raw"
}

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

default_api_endpoint() {
  local public_ip=""
  public_ip="$(detect_public_ip)"
  if [[ -n "$public_ip" ]]; then
    printf 'http://%s:%s' "$public_ip" "$PORT"
  else
    printf 'http://127.0.0.1:%s' "$PORT"
  fi
}

existing_node_id_from_env() {
  local env_file="${APP_DIR}/.env"
  if [[ ! -f "$env_file" ]]; then
    return 0
  fi
  sed -n -E 's/^RUNTIME_NODE_ID=([A-Za-z0-9_-]{8,64})$/\1/p' "$env_file" | head -n 1
}

existing_node_name_from_env() {
  local env_file="${APP_DIR}/.env"
  if [[ ! -f "$env_file" ]]; then
    return 0
  fi
  sed -n -E 's/^RUNTIME_NODE_NAME=(.+)$/\1/p' "$env_file" | head -n 1
}

normalize_join_api_url() {
  local target="$1"
  local default_port="$2"
  local scheme="http"
  local hostport="$target"
  local host=""
  local port=""

  if [[ "$target" == *"://"* ]]; then
    scheme="${target%%://*}"
    hostport="${target#*://}"
  fi
  hostport="${hostport%%/*}"
  host="${hostport%%:*}"
  if [[ "$hostport" == *:* ]]; then
    port="${hostport##*:}"
  fi
  if [[ -z "$port" ]]; then
    port="$default_port"
  fi
  printf '%s://%s:%s' "$scheme" "$host" "$port"
}

derive_etcd_peer_url() {
  local endpoint="$1"
  local parsed=""
  parsed="$(printf '%s\n' "$endpoint" | sed -E 's#^[a-zA-Z]+://##; s#/.*$##; s#:[0-9]+$##')"
  if [[ -n "$parsed" ]]; then
    printf 'http://%s:2380' "$parsed"
  fi
}

extract_endpoint_host() {
  local endpoint="$1"
  local host="$endpoint"
  host="${host#*://}"
  host="${host%%/*}"
  if [[ "$host" == \[*\]* ]]; then
    host="${host#\[}"
    host="${host%%\]*}"
  else
    host="${host%%:*}"
  fi
  printf '%s' "$host"
}

generate_self_signed_cert() {
  local host=""
  local cert_dir="${APP_DIR}/data/tls"
  local cert_path="${cert_dir}/ui-selfsigned.crt"
  local key_path="${cert_dir}/ui-selfsigned.key"
  local san="DNS:localhost,IP:127.0.0.1"
  local openssl_cfg=""

  host="$(extract_endpoint_host "${API_ENDPOINT}")"
  if [[ -z "$host" ]]; then
    host="localhost"
  fi
  if [[ "$host" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    san="${san},IP:${host}"
  else
    san="${san},DNS:${host}"
  fi

  mkdir -p "${cert_dir}"
  if [[ ! -s "${cert_path}" || ! -s "${key_path}" ]]; then
    say "Generating self-signed TLS certificate"
    openssl_cfg="$(mktemp)"
    cat > "${openssl_cfg}" <<EOF
[req]
distinguished_name=req_distinguished_name
x509_extensions=v3_req
prompt=no
[req_distinguished_name]
CN=${host}
[v3_req]
subjectAltName=${san}
EOF
    openssl req -x509 -nodes -newkey rsa:2048 -sha256 -days 825 \
      -keyout "${key_path}" \
      -out "${cert_path}" \
      -config "${openssl_cfg}" \
      -extensions v3_req
    rm -f "${openssl_cfg}"
    chmod 600 "${key_path}"
    chmod 644 "${cert_path}"
  fi
}

configure_self_signed_tls_proxy_nginx() {
  local host=""
  local cert_path="${APP_DIR}/data/tls/ui-selfsigned.crt"
  local key_path="${APP_DIR}/data/tls/ui-selfsigned.key"
  local nginx_conf="/etc/nginx/conf.d/uptimemesh-selfsigned.conf"

  host="$(extract_endpoint_host "${API_ENDPOINT}")"
  if [[ -z "${host}" ]]; then
    host="localhost"
  fi

  generate_self_signed_cert
  say "Configuring HTTPS reverse proxy (nginx)"

  cat > "${nginx_conf}" <<EOF
server {
    listen 443 ssl;
    listen [::]:443 ssl;
    server_name _;

    ssl_certificate ${cert_path};
    ssl_certificate_key ${key_path};
    ssl_session_timeout 1d;
    ssl_session_cache shared:MESHSSL:10m;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers off;

    add_header Strict-Transport-Security "max-age=31536000" always;
    add_header X-Content-Type-Options nosniff always;
    add_header X-Frame-Options SAMEORIGIN always;
    add_header Referrer-Policy no-referrer-when-downgrade always;

    location / {
        proxy_pass http://127.0.0.1:${PORT};
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
    }
}

server {
    listen 80;
    listen [::]:80;
    server_name _;
    return 301 https://\$host\$request_uri;
}
EOF

  nginx -t
  systemctl enable --now nginx
  systemctl reload nginx || systemctl restart nginx
  WEB_UI_URL="https://${host}/ui"
}

configure_self_signed_tls_proxy_caddy() {
  local host=""
  local cert_path="${APP_DIR}/data/tls/ui-selfsigned.crt"
  local key_path="${APP_DIR}/data/tls/ui-selfsigned.key"
  local caddyfile="/etc/caddy/Caddyfile"

  host="$(extract_endpoint_host "${API_ENDPOINT}")"
  if [[ -z "${host}" ]]; then
    host="localhost"
  fi

  generate_self_signed_cert
  say "Configuring HTTPS reverse proxy (caddy)"

  install -d /etc/caddy
  cat > "${caddyfile}" <<EOF
http://${host}, http://localhost {
    redir https://{host}{uri} permanent
}

https://${host}, https://localhost {
    tls ${cert_path} ${key_path}
    reverse_proxy 127.0.0.1:${PORT}
    header {
        Strict-Transport-Security "max-age=31536000"
        X-Content-Type-Options "nosniff"
        X-Frame-Options "SAMEORIGIN"
        Referrer-Policy "no-referrer-when-downgrade"
    }
}
EOF

  caddy validate --config "${caddyfile}" >/dev/null 2>&1 || fail "caddy config validation failed"
  systemctl enable --now caddy
  systemctl reload caddy || systemctl restart caddy
  WEB_UI_URL="https://${host}/ui"
}

ensure_self_signed_tls_proxy() {
  if ! command -v openssl >/dev/null 2>&1; then
    fail "openssl is required to generate the self-signed certificate"
  fi

  if command -v nginx >/dev/null 2>&1; then
    configure_self_signed_tls_proxy_nginx
    return 0
  fi
  if command -v caddy >/dev/null 2>&1; then
    configure_self_signed_tls_proxy_caddy
    return 0
  fi

  warn "No proxy binary found; attempting to install nginx/caddy now"
  export DEBIAN_FRONTEND=noninteractive
  apt_quiet_retry "Refresh package index for HTTPS proxy" apt-get update -y || true

  if apt_quiet_retry "Install nginx for HTTPS proxy" apt-get install -y nginx; then
    configure_self_signed_tls_proxy_nginx
    return 0
  fi
  if apt_quiet_retry "Install caddy for HTTPS proxy" apt-get install -y caddy; then
    configure_self_signed_tls_proxy_caddy
    return 0
  fi

  fail "Unable to configure HTTPS proxy with self-signed certificate (nginx/caddy unavailable)"
}

apply_cluster_secrets_from_join_json() {
  local join_json="$1"
  local extracted=""
  local auth_secret_key=""
  local cluster_signing_key=""
  local updated="0"

  extracted="$(printf '%s' "$join_json" | python3 -c 'import json,sys; data=json.load(sys.stdin); print(data.get("auth_secret_key","")); print(data.get("cluster_signing_key",""))' 2>/dev/null || true)"
  auth_secret_key="$(printf '%s\n' "$extracted" | sed -n '1p')"
  cluster_signing_key="$(printf '%s\n' "$extracted" | sed -n '2p')"

  if [[ -z "$auth_secret_key" || -z "$cluster_signing_key" ]]; then
    echo "warning: cluster secrets missing from join response; keeping local values."
    return 0
  fi

  updated="$(python3 - <<PY
import pathlib

env_path = pathlib.Path(".env")
if env_path.exists():
    lines = env_path.read_text(encoding="utf-8").splitlines()
else:
    lines = []

kv = {}
for line in lines:
    if "=" in line and not line.lstrip().startswith("#"):
        key, value = line.split("=", 1)
        kv[key.strip()] = value.strip()

changed = False
if kv.get("AUTH_SECRET_KEY", "") != "${auth_secret_key}":
    kv["AUTH_SECRET_KEY"] = "${auth_secret_key}"
    changed = True
if kv.get("CLUSTER_SIGNING_KEY", "") != "${cluster_signing_key}":
    kv["CLUSTER_SIGNING_KEY"] = "${cluster_signing_key}"
    changed = True

if changed:
    ordered = sorted(kv.items(), key=lambda item: item[0])
    env_path.write_text("".join(f"{k}={v}\n" for k, v in ordered), encoding="utf-8")
print("1" if changed else "0")
PY
)"

  if [[ "$updated" == "1" ]]; then
    echo "Applied cluster-internal signing secrets from enrollment response."
    systemctl restart uptime-mesh.service
    for _ in 1 2 3 4 5 6 7 8 9 10; do
      if curl -fsS "http://127.0.0.1:${PORT}/health" >/dev/null 2>&1; then
        break
      fi
      sleep 1
    done
    curl -fsS "http://127.0.0.1:${PORT}/health" >/dev/null
  fi
}

run_wizard() {
  local reply=""
  local endpoint_default=""
  local token_prefix=""
  local default_name=""
  local mode="first"
  local peer_target=""
  local peer_port=""
  local dep_default="y"

  echo "UptimeMesh setup wizard"
  echo "-----------------------"
  if [[ "$INSTALL_DEPS" -eq 0 ]]; then
    dep_default="n"
  fi
  reply="$(prompt_yes_no "Install apt dependencies?" "$dep_default")"
  if [[ "$reply" == "y" ]]; then
    INSTALL_DEPS=1
  else
    INSTALL_DEPS=0
  fi

  default_name="${NODE_NAME:-$(generate_three_word_phrase)}"
  NODE_NAME="$(prompt_default "Node name" "$default_name")"

  if [[ -n "$JOIN_TARGET" ]]; then
    mode="join"
  fi
  mode="$(prompt_default "Is this the first node or joining another? (first|join)" "$mode")"
  case "$mode" in
    first|join) ;;
    *) mode="first" ;;
  esac

  if [[ -z "$NODE_ROLE" ]]; then
    NODE_ROLE="general"
  fi

  if [[ "$mode" == "first" ]]; then
    BOOTSTRAP=1
    INSTALL_MONITORING=1
    INSTALL_ADMIN_USERNAME="$(prompt_default "Initial admin username" "${INSTALL_ADMIN_USERNAME}")"
  else
    BOOTSTRAP=0
    INSTALL_MONITORING=1
    peer_target="$(prompt_required "Peer node API host/IP")"
    peer_port="$(prompt_default "Peer node API port" "$JOIN_PORT")"
    JOIN_TARGET="$peer_target"
    JOIN_PORT="$peer_port"
    API_URL="$(normalize_join_api_url "$JOIN_TARGET" "$JOIN_PORT")"
    JOIN_TOKEN="$(prompt_required "Join token")"
  fi

  PORT="$(prompt_default "Local API port" "$PORT")"
  endpoint_default="$(default_api_endpoint)"
  API_ENDPOINT="$(prompt_default "Advertised API endpoint for this node" "$endpoint_default")"

  if [[ "$NODE_ROLE" != "gateway" ]]; then
    ETCD_PEER_URL="$(prompt_default "etcd peer URL for this node" "$(derive_etcd_peer_url "$API_ENDPOINT")")"
    if [[ "$mode" == "first" ]]; then
      API_URL="$(prompt_default "API URL used for bootstrap" "http://127.0.0.1:${PORT}")"
    fi
  fi

  echo
  echo "Summary:"
  echo "  mode:         $mode"
  echo "  node_id:      ${NODE_ID:-"(short-uuid auto)"}"
  echo "  node_name:    $NODE_NAME"
  echo "  role:         $NODE_ROLE"
  echo "  api_url:      $API_URL"
  echo "  api_endpoint: $API_ENDPOINT"
  echo "  port:         $PORT"
  echo "  bootstrap:    $BOOTSTRAP"
  echo "  join_target:  ${JOIN_TARGET:-"(none)"}"
  echo "  etcd_peer:    ${ETCD_PEER_URL:-"(auto/none)"}"
  echo "  monitoring:   mandatory"
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

print_install_summary() {
  local mode_label="first"
  local api_status="unknown"
  local agent_status="unknown"
  if [[ -n "$JOIN_TARGET" ]]; then
    mode_label="join"
  fi
  if [[ "$BOOTSTRAP" -eq 1 ]]; then
    mode_label="bootstrap"
  fi
  if systemctl is-active --quiet uptime-mesh.service; then
    api_status="active"
  else
    api_status="inactive"
  fi
  if systemctl is-active --quiet uptime-mesh-agent.service; then
    agent_status="active"
  else
    agent_status="inactive"
  fi

  cat <<EOF
+--------------------------------------------------------------+
|                    UPTIMEMESH INSTALL DONE                   |
+--------------------------------------------------------------+
| mode              : ${mode_label}
| node_id           : ${NODE_ID}
| node_name         : ${NODE_NAME}
| role              : ${NODE_ROLE}
| local_api         : http://127.0.0.1:${PORT}
| advertised_api    : ${API_ENDPOINT}
| cluster_api       : ${API_URL}
| web_ui            : ${WEB_UI_URL:-"(https proxy unavailable)"}
| bootstrap         : ${BOOTSTRAP}
| join_target       : ${JOIN_TARGET:-"(none)"}
| etcd_peer_url     : ${ETCD_PEER_URL:-"(none)"}
| monitoring_seed   : ${INSTALL_MONITORING}
| api_service       : ${api_status}
| agent_service     : ${agent_status}
| app_log           : ${APP_DIR}/data/app.log
| agent_log         : ${APP_DIR}/data/agent.log
| agent_socket      : ${APP_DIR}/data/agent.sock
+--------------------------------------------------------------+
EOF
}

ORIGINAL_ARGC="$#"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --name)
      NODE_NAME="$2"; shift 2 ;;
    --username)
      INSTALL_ADMIN_USERNAME="$2"; shift 2 ;;
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
    --join)
      JOIN_TARGET="$2"; shift 2 ;;
    --join-port)
      JOIN_PORT="$2"; shift 2 ;;
    --port)
      PORT="$2"; shift 2 ;;
    --install-deps)
      INSTALL_DEPS=1; shift ;;
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

if [[ "$WIZARD" -eq 0 ]]; then
  if [[ "$ORIGINAL_ARGC" -eq 0 || -n "$JOIN_TARGET" ]]; then
    INSTALL_DEPS=1
  fi
fi

if [[ "$WIZARD" -eq 1 ]]; then
  run_wizard
fi

if [[ -z "$NODE_ID" ]]; then
  NODE_ID="$(existing_node_id_from_env)"
fi
if [[ -z "$NODE_ID" ]]; then
  NODE_ID="$(generate_short_uuid)"
fi
if [[ -z "$NODE_ROLE" ]]; then
  NODE_ROLE="general"
fi
case "$NODE_ROLE" in
  general|backend_server|reverse_proxy|gateway|worker) ;;
  *)
    echo "--role must be one of: general, backend_server, reverse_proxy, gateway, worker" >&2
    exit 1 ;;
esac

if [[ -z "$NODE_NAME" ]]; then
  NODE_NAME="$(existing_node_name_from_env)"
fi
if [[ -z "$NODE_NAME" ]]; then
  NODE_NAME="$(generate_three_word_phrase)"
fi
if [[ -z "$API_ENDPOINT" ]]; then
  API_ENDPOINT="$(default_api_endpoint)"
fi
if [[ -z "$ETCD_PEER_URL" && "$NODE_ROLE" != "gateway" ]]; then
  ETCD_PEER_URL="$(derive_etcd_peer_url "$API_ENDPOINT")"
fi
if [[ -n "$JOIN_TARGET" ]]; then
  API_URL="$(normalize_join_api_url "$JOIN_TARGET" "$JOIN_PORT")"
fi

if [[ -n "$JOIN_TARGET" ]]; then
  BOOTSTRAP=0
else
  BOOTSTRAP=1
fi
if [[ "$BOOTSTRAP" -eq 1 && -z "${INSTALL_ADMIN_USERNAME// }" ]]; then
  echo "--username cannot be empty for first-node install" >&2
  exit 1
fi

if [[ -z "$JOIN_TARGET" && -n "$JOIN_TOKEN" ]]; then
  echo "--token requires --join" >&2
  exit 1
fi
if [[ -n "$JOIN_TARGET" && -z "$JOIN_TOKEN" ]]; then
  echo "--join requires --token" >&2
  exit 1
fi

if [[ "$INSTALL_DEPS" -eq 1 ]]; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y
  apt-get install -y python3 python3-venv python3-pip curl ca-certificates git golang-go iproute2 iputils-ping openssl
  apt-get install -y lxd || true
  apt-get install -y etcd || apt-get install -y etcd-server etcd-client || true
  apt-get install -y nginx || true
  apt-get install -y caddy || true
  apt-get install -y prometheus prometheus-node-exporter prometheus-alertmanager grafana || true
fi

ETCD_AVAILABLE=0
if command -v etcdctl >/dev/null 2>&1 || command -v etcd >/dev/null 2>&1; then
  ETCD_AVAILABLE=1
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
setv("AGENT_ENABLE_UNIX_SOCKET", kv.get("AGENT_ENABLE_UNIX_SOCKET", "true") or "true")
setv("AGENT_UNIX_SOCKET", kv.get("AGENT_UNIX_SOCKET", "./data/agent.sock") or "./data/agent.sock")
setv("MANAGED_CONFIG_PATH", kv.get("MANAGED_CONFIG_PATH", "config.yaml") or "config.yaml")
setv("METRICS_ENABLED", kv.get("METRICS_ENABLED", "true") or "true")
default_etcd_enabled = "true" if "${ETCD_AVAILABLE}" == "1" else "false"
setv("ETCD_ENABLED", kv.get("ETCD_ENABLED", default_etcd_enabled) or default_etcd_enabled)
default_etcd_endpoints = "http://127.0.0.1:2379" if "${ETCD_AVAILABLE}" == "1" else ""
setv("ETCD_ENDPOINTS", kv.get("ETCD_ENDPOINTS", default_etcd_endpoints) or default_etcd_endpoints)
setv("ETCDCTL_COMMAND", kv.get("ETCDCTL_COMMAND", "etcdctl") or "etcdctl")
setv("ETCD_PREFIX", kv.get("ETCD_PREFIX", "/uptimemesh") or "/uptimemesh")
setv("ETCD_DIAL_TIMEOUT_SECONDS", kv.get("ETCD_DIAL_TIMEOUT_SECONDS", "5") or "5")
setv("ETCD_COMMAND_TIMEOUT_SECONDS", kv.get("ETCD_COMMAND_TIMEOUT_SECONDS", "10") or "10")
setv("ETCD_SNAPSHOT_DIR", kv.get("ETCD_SNAPSHOT_DIR", "data/etcd-snapshots") or "data/etcd-snapshots")
setv("ETCD_SNAPSHOT_RETENTION", kv.get("ETCD_SNAPSHOT_RETENTION", "30") or "30")
setv("ETCD_SNAPSHOT_SCHEDULE_ENABLED", kv.get("ETCD_SNAPSHOT_SCHEDULE_ENABLED", "true") or "true")
setv("ETCD_SNAPSHOT_INTERVAL_SECONDS", kv.get("ETCD_SNAPSHOT_INTERVAL_SECONDS", "86400") or "86400")
setv(
    "ETCD_SNAPSHOT_SCHEDULE_REQUESTED_BY",
    kv.get("ETCD_SNAPSHOT_SCHEDULE_REQUESTED_BY", "runtime.snapshot_scheduler") or "runtime.snapshot_scheduler",
)
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
setv("RUNTIME_HEARTBEAT_INTERVAL_SECONDS", kv.get("RUNTIME_HEARTBEAT_INTERVAL_SECONDS", "15") or "15")
setv("RUNTIME_HEARTBEAT_TTL_SECONDS", kv.get("RUNTIME_HEARTBEAT_TTL_SECONDS", "45") or "45")
setv("RUNTIME_MESH_CIDR", kv.get("RUNTIME_MESH_CIDR", "10.42.0.0/16") or "10.42.0.0/16")
setv("RUNTIME_WG_PRIMARY_IFACE", kv.get("RUNTIME_WG_PRIMARY_IFACE", "wg-mesh0") or "wg-mesh0")
setv("RUNTIME_WG_SECONDARY_IFACE", kv.get("RUNTIME_WG_SECONDARY_IFACE", "wg-mesh1") or "wg-mesh1")
setv("RUNTIME_WG_CONFIGURE", kv.get("RUNTIME_WG_CONFIGURE", "false") or "false")
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
setv("RUNTIME_SWIM_ENABLE", kv.get("RUNTIME_SWIM_ENABLE", "true") or "true")
setv("RUNTIME_SWIM_PORT", kv.get("RUNTIME_SWIM_PORT", "7946") or "7946")
setv("RUNTIME_SWIM_PROBE_TIMEOUT_MS", kv.get("RUNTIME_SWIM_PROBE_TIMEOUT_MS", "500") or "500")
setv("RUNTIME_SWIM_SUSPECT_THRESHOLD", kv.get("RUNTIME_SWIM_SUSPECT_THRESHOLD", "2") or "2")
setv("RUNTIME_SWIM_DEAD_THRESHOLD", kv.get("RUNTIME_SWIM_DEAD_THRESHOLD", "4") or "4")
setv("RUNTIME_SWIM_COOLDOWN_SECONDS", kv.get("RUNTIME_SWIM_COOLDOWN_SECONDS", "30") or "30")
setv("RUNTIME_INTERNAL_CDN_DIR", kv.get("RUNTIME_INTERNAL_CDN_DIR", "data/internal-cdn") or "data/internal-cdn")
setv("RUNTIME_BACKEND_LISTEN_PORT", kv.get("RUNTIME_BACKEND_LISTEN_PORT", "8081") or "8081")
setv("RUNTIME_PROXY_LISTEN_PORT", kv.get("RUNTIME_PROXY_LISTEN_PORT", "8080") or "8080")
default_discovery = "true"
setv("RUNTIME_DISCOVERY_ENABLE", kv.get("RUNTIME_DISCOVERY_ENABLE", default_discovery) or default_discovery)
setv("RUNTIME_DISCOVERY_DOMAIN", kv.get("RUNTIME_DISCOVERY_DOMAIN", "mesh.local") or "mesh.local")
setv("RUNTIME_DISCOVERY_TTL_SECONDS", kv.get("RUNTIME_DISCOVERY_TTL_SECONDS", "30") or "30")
setv(
    "RUNTIME_DISCOVERY_ZONE_PATH",
    kv.get("RUNTIME_DISCOVERY_ZONE_PATH", "data/coredns/db.mesh.local") or "data/coredns/db.mesh.local",
)
setv(
    "RUNTIME_DISCOVERY_COREFILE_PATH",
    kv.get("RUNTIME_DISCOVERY_COREFILE_PATH", "data/coredns/Corefile") or "data/coredns/Corefile",
)
setv("RUNTIME_DISCOVERY_LISTEN", kv.get("RUNTIME_DISCOVERY_LISTEN", ".:53") or ".:53")
setv(
    "RUNTIME_DISCOVERY_FORWARDERS",
    kv.get("RUNTIME_DISCOVERY_FORWARDERS", "/etc/resolv.conf") or "/etc/resolv.conf",
)
setv("RUNTIME_DISCOVERY_INTERVAL_SECONDS", kv.get("RUNTIME_DISCOVERY_INTERVAL_SECONDS", "10") or "10")
setv("RUNTIME_DISCOVERY_RELOAD_COMMAND", kv.get("RUNTIME_DISCOVERY_RELOAD_COMMAND", ""))
default_gateway = "false"
setv("RUNTIME_GATEWAY_ENABLE", kv.get("RUNTIME_GATEWAY_ENABLE", default_gateway) or default_gateway)
setv("RUNTIME_GATEWAY_CONFIG_PATH", kv.get("RUNTIME_GATEWAY_CONFIG_PATH", "data/nginx/nginx.conf") or "data/nginx/nginx.conf")
setv(
    "RUNTIME_GATEWAY_CANDIDATE_PATH",
    kv.get("RUNTIME_GATEWAY_CANDIDATE_PATH", "data/nginx/nginx.candidate.conf") or "data/nginx/nginx.candidate.conf",
)
setv(
    "RUNTIME_GATEWAY_BACKUP_PATH",
    kv.get("RUNTIME_GATEWAY_BACKUP_PATH", "data/nginx/nginx.prev.conf") or "data/nginx/nginx.prev.conf",
)
setv("RUNTIME_GATEWAY_LISTEN", kv.get("RUNTIME_GATEWAY_LISTEN", "0.0.0.0:80") or "0.0.0.0:80")
setv("RUNTIME_GATEWAY_SERVER_NAME", kv.get("RUNTIME_GATEWAY_SERVER_NAME", "_") or "_")
setv("RUNTIME_GATEWAY_INTERVAL_SECONDS", kv.get("RUNTIME_GATEWAY_INTERVAL_SECONDS", "10") or "10")
setv(
    "RUNTIME_GATEWAY_VALIDATE_COMMAND",
    kv.get("RUNTIME_GATEWAY_VALIDATE_COMMAND", "nginx -t -c {config_path}") or "nginx -t -c {config_path}",
)
setv(
    "RUNTIME_GATEWAY_RELOAD_COMMAND",
    kv.get("RUNTIME_GATEWAY_RELOAD_COMMAND", "systemctl reload nginx") or "systemctl reload nginx",
)
setv("RUNTIME_GATEWAY_HEALTHCHECK_URLS", kv.get("RUNTIME_GATEWAY_HEALTHCHECK_URLS", ""))
setv(
    "RUNTIME_GATEWAY_HEALTHCHECK_TIMEOUT_SECONDS",
    kv.get("RUNTIME_GATEWAY_HEALTHCHECK_TIMEOUT_SECONDS", "3") or "3",
)
setv(
    "RUNTIME_GATEWAY_HEALTHCHECK_EXPECTED_STATUS",
    kv.get("RUNTIME_GATEWAY_HEALTHCHECK_EXPECTED_STATUS", "200") or "200",
)
default_monitoring = "true"
setv("RUNTIME_MONITORING_ENABLE", kv.get("RUNTIME_MONITORING_ENABLE", default_monitoring) or default_monitoring)
setv("RUNTIME_MONITORING_INTERVAL_SECONDS", kv.get("RUNTIME_MONITORING_INTERVAL_SECONDS", "15") or "15")
setv(
    "RUNTIME_MONITORING_PROMETHEUS_CONFIG_PATH",
    kv.get("RUNTIME_MONITORING_PROMETHEUS_CONFIG_PATH", "/etc/prometheus/prometheus.yml") or "/etc/prometheus/prometheus.yml",
)
setv(
    "RUNTIME_MONITORING_PROMETHEUS_CANDIDATE_PATH",
    kv.get("RUNTIME_MONITORING_PROMETHEUS_CANDIDATE_PATH", "/etc/prometheus/prometheus.candidate.yml") or "/etc/prometheus/prometheus.candidate.yml",
)
setv(
    "RUNTIME_MONITORING_PROMETHEUS_BACKUP_PATH",
    kv.get("RUNTIME_MONITORING_PROMETHEUS_BACKUP_PATH", "/etc/prometheus/prometheus.prev.yml") or "/etc/prometheus/prometheus.prev.yml",
)
setv(
    "RUNTIME_MONITORING_RULES_PATH",
    kv.get("RUNTIME_MONITORING_RULES_PATH", "/etc/uptime-mesh/monitoring/alert_rules.yml") or "/etc/uptime-mesh/monitoring/alert_rules.yml",
)
setv(
    "RUNTIME_MONITORING_ALERTMANAGER_TARGETS",
    kv.get("RUNTIME_MONITORING_ALERTMANAGER_TARGETS", "127.0.0.1:9093") or "127.0.0.1:9093",
)
setv(
    "RUNTIME_MONITORING_SCRAPE_INTERVAL_SECONDS",
    kv.get("RUNTIME_MONITORING_SCRAPE_INTERVAL_SECONDS", "15") or "15",
)
setv(
    "RUNTIME_MONITORING_EVALUATION_INTERVAL_SECONDS",
    kv.get("RUNTIME_MONITORING_EVALUATION_INTERVAL_SECONDS", "15") or "15",
)
setv(
    "RUNTIME_MONITORING_NODE_EXPORTER_PORT",
    kv.get("RUNTIME_MONITORING_NODE_EXPORTER_PORT", "9100") or "9100",
)
setv(
    "RUNTIME_MONITORING_INCLUDE_LOCALHOST_TARGETS",
    kv.get("RUNTIME_MONITORING_INCLUDE_LOCALHOST_TARGETS", "true") or "true",
)
setv(
    "RUNTIME_MONITORING_VALIDATE_COMMAND",
    kv.get("RUNTIME_MONITORING_VALIDATE_COMMAND", "promtool check config {candidate_path}") or "promtool check config {candidate_path}",
)
setv(
    "RUNTIME_MONITORING_RELOAD_COMMAND",
    kv.get("RUNTIME_MONITORING_RELOAD_COMMAND", "systemctl reload prometheus || systemctl restart prometheus")
    or "systemctl reload prometheus || systemctl restart prometheus",
)

if (not kv.get("AUTH_SECRET_KEY")) or kv["AUTH_SECRET_KEY"].startswith("change-me"):
    setv("AUTH_SECRET_KEY", secrets.token_hex(32))
if (not kv.get("CLUSTER_SIGNING_KEY")) or kv["CLUSTER_SIGNING_KEY"].startswith("change-me"):
    setv("CLUSTER_SIGNING_KEY", secrets.token_hex(32))

ordered = sorted(kv.items(), key=lambda x: x[0])
env_path.write_text("".join(f"{k}={v}\n" for k, v in ordered), encoding="utf-8")
PY

.venv/bin/alembic upgrade head

install -d /etc/uptime-mesh/monitoring/grafana/provisioning/dashboards
install -d /etc/uptime-mesh/monitoring/grafana/provisioning/datasources
install -d /etc/uptime-mesh/monitoring/grafana/dashboards
install -d /etc/prometheus
install -d /etc/alertmanager
cp "${APP_DIR}/ops/monitoring/prometheus.yml" /etc/uptime-mesh/monitoring/prometheus.yml
cp "${APP_DIR}/ops/monitoring/alert_rules.yml" /etc/uptime-mesh/monitoring/alert_rules.yml
cp "${APP_DIR}/ops/monitoring/alertmanager.yml" /etc/uptime-mesh/monitoring/alertmanager.yml
cp "${APP_DIR}/ops/monitoring/grafana/provisioning/dashboards/uptimemesh.yml" /etc/uptime-mesh/monitoring/grafana/provisioning/dashboards/uptimemesh.yml
cp "${APP_DIR}/ops/monitoring/grafana/provisioning/datasources/uptimemesh.yml" /etc/uptime-mesh/monitoring/grafana/provisioning/datasources/uptimemesh.yml
cp "${APP_DIR}/ops/monitoring/grafana/dashboards/uptimemesh-overview.json" /etc/uptime-mesh/monitoring/grafana/dashboards/uptimemesh-overview.json
cp "${APP_DIR}/ops/monitoring/prometheus.yml" /etc/prometheus/prometheus.yml || true
cp "${APP_DIR}/ops/monitoring/alertmanager.yml" /etc/alertmanager/alertmanager.yml || true
if [[ -d /etc/grafana/provisioning ]]; then
  install -d /etc/grafana/provisioning/dashboards
  install -d /etc/grafana/provisioning/datasources
  install -d /var/lib/grafana/dashboards
  cp "${APP_DIR}/ops/monitoring/grafana/provisioning/dashboards/uptimemesh.yml" /etc/grafana/provisioning/dashboards/uptimemesh.yml || true
  cp "${APP_DIR}/ops/monitoring/grafana/provisioning/datasources/uptimemesh.yml" /etc/grafana/provisioning/datasources/uptimemesh.yml || true
  cp "${APP_DIR}/ops/monitoring/grafana/dashboards/uptimemesh-overview.json" /var/lib/grafana/dashboards/uptimemesh-overview.json || true
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
Environment=AGENT_ENABLE_UNIX_SOCKET=true
Environment=AGENT_UNIX_SOCKET=./data/agent.sock

[Install]
WantedBy=multi-user.target
SYSTEMD

cat > /etc/systemd/system/uptime-mesh-watchdog.service <<SYSTEMD
[Unit]
Description=UptimeMesh local self-heal watchdog
After=network-online.target uptime-mesh.service
Wants=network-online.target

[Service]
Type=oneshot
WorkingDirectory=${APP_DIR}
ExecStart=${APP_DIR}/.venv/bin/python ${APP_DIR}/ops/watchdog.py --api-url http://127.0.0.1:${PORT}/health --api-service uptime-mesh.service --agent-service uptime-mesh-agent.service
Environment=PYTHONUNBUFFERED=1
Environment=LOG_FILE=./data/app.log
Environment=AGENT_LOG_FILE=./data/agent.log
SYSTEMD

cat > /etc/systemd/system/uptime-mesh-watchdog.timer <<SYSTEMD
[Unit]
Description=Run UptimeMesh self-heal watchdog every minute

[Timer]
OnBootSec=2min
OnUnitActiveSec=60s
Unit=uptime-mesh-watchdog.service
AccuracySec=10s
Persistent=true

[Install]
WantedBy=timers.target
SYSTEMD

systemctl daemon-reload

if systemctl list-unit-files | awk '{print $1}' | grep -qx 'etcd.service'; then
  systemctl enable --now etcd || true
fi
if systemctl list-unit-files | awk '{print $1}' | grep -qx 'etcd-server.service'; then
  systemctl enable --now etcd-server || true
fi

systemctl enable uptime-mesh.service
systemctl restart uptime-mesh.service || systemctl start uptime-mesh.service
if command -v nginx >/dev/null 2>&1 && command -v openssl >/dev/null 2>&1; then
  configure_self_signed_tls_proxy
else
  echo "warning: HTTPS proxy not configured (nginx and openssl are required)."
fi
systemctl enable --now uptime-mesh-watchdog.timer
systemctl start uptime-mesh-watchdog.service || true
systemctl enable --now prometheus prometheus-node-exporter prometheus-alertmanager || true
systemctl enable --now grafana-server || true

for _ in 1 2 3 4 5 6 7 8 9 10; do
  if curl -fsS "http://127.0.0.1:${PORT}/health" >/dev/null 2>&1; then
    break
  fi
  sleep 1
done
curl -fsS "http://127.0.0.1:${PORT}/health" >/dev/null

if [[ "$BOOTSTRAP" -eq 1 ]]; then
  bootstrap_prep_json="$(INSTALL_ADMIN_USERNAME="${INSTALL_ADMIN_USERNAME}" ${APP_DIR}/.venv/bin/python - <<'PY'
import datetime as dt
import json
import os
import secrets
import sqlite3
import string

from app.security import hash_password

conn = sqlite3.connect("data/app.db")
cur = conn.cursor()

def get_value(key: str) -> str:
    row = cur.execute("SELECT value FROM cluster_settings WHERE key = ?", (key,)).fetchone()
    return row[0] if row else ""

bootstrapped = get_value("cluster_bootstrapped").strip().lower() == "true"

if bootstrapped:
    print(json.dumps({"action": "already_bootstrapped"}))
    raise SystemExit(0)

alphabet = string.ascii_letters + string.digits + "-_"
username = os.environ.get("INSTALL_ADMIN_USERNAME", "").strip() or "admin"
password = "".join(secrets.choice(alphabet) for _ in range(28))
password_hash = hash_password(password)
updated_at = dt.datetime.now(dt.timezone.utc).isoformat()

for key, value in (
    ("auth_username", username),
    ("auth_password_hash", password_hash),
    ("auth_password_updated_at", updated_at),
):
    cur.execute(
        """
        INSERT INTO cluster_settings (key, value)
        VALUES (?, ?)
        ON CONFLICT(key) DO UPDATE SET value = excluded.value
        """,
        (key, value),
    )

conn.commit()
print(json.dumps({"action": "generated", "username": username, "password": password}))
PY
)"
  bootstrap_action="$(printf '%s' "$bootstrap_prep_json" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("action",""))')"
  if [[ "$bootstrap_action" == "generated" ]]; then
    INITIAL_ADMIN_USERNAME="$(printf '%s' "$bootstrap_prep_json" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("username",""))')"
    INITIAL_ADMIN_PASSWORD="$(printf '%s' "$bootstrap_prep_json" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("password",""))')"
    bootstrap_json="$(${APP_DIR}/.venv/bin/uptimemesh --api-url "${API_URL}" bootstrap --username "${INITIAL_ADMIN_USERNAME}" --password "${INITIAL_ADMIN_PASSWORD}")"
    worker_token="$(printf '%s' "$bootstrap_json" | python3 -c 'import json,sys; print(json.load(sys.stdin)["worker_token"]["token"])')"
    join_cmd=(
      "${APP_DIR}/.venv/bin/uptimemesh" --api-url "${API_URL}" join
      --token "${worker_token}"
      --node-id "${NODE_ID}"
      --name "${NODE_NAME}"
      --role "${NODE_ROLE}"
      --api-endpoint "${API_ENDPOINT}"
      --identity-dir ./data/identities
    )
    if [[ -n "$ETCD_PEER_URL" ]]; then
      join_cmd+=(--etcd-peer-url "${ETCD_PEER_URL}")
    fi
    join_json="$("${join_cmd[@]}")"
    apply_cluster_secrets_from_join_json "$join_json"
    INITIAL_ADMIN_GENERATED=1
    echo "Bootstrap complete."
  else
    echo "Cluster already bootstrapped; skipping bootstrap on this node."
  fi
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
  join_json="$("${join_cmd[@]}")"
  apply_cluster_secrets_from_join_json "$join_json"
  echo "Join complete."
else
  echo "Install complete (service running)."
  echo "Next: run join with --token on additional nodes."
fi

if [[ -f "${APP_DIR}/data/identities/${NODE_ID}/node.key" && -f "${APP_DIR}/data/identities/${NODE_ID}/lease.token" ]]; then
  systemctl enable uptime-mesh-agent.service
  systemctl restart uptime-mesh-agent.service || systemctl start uptime-mesh-agent.service
  echo "Go agent service started."
else
  systemctl disable --now uptime-mesh-agent.service >/dev/null 2>&1 || true
  echo "Go agent not started yet (missing identity artifacts)."
fi

echo "Status:"
if [[ "$INITIAL_ADMIN_GENERATED" -eq 1 ]]; then
  ${APP_DIR}/.venv/bin/uptimemesh --api-url "${API_URL}" nodes-status \
    --username "${INITIAL_ADMIN_USERNAME}" \
    --password "${INITIAL_ADMIN_PASSWORD}" || true
else
  echo "nodes-status requires admin credentials; run it manually once credentials are available."
fi
print_install_summary
if [[ "$INITIAL_ADMIN_GENERATED" -eq 1 ]]; then
  cat <<EOF
Initial admin credentials (shown once):
  username: ${INITIAL_ADMIN_USERNAME}
  password: ${INITIAL_ADMIN_PASSWORD}
EOF
fi
