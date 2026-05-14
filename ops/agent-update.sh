#!/usr/bin/env sh
# UptimeMesh agent-only updater

set -eu

INSTALL_DIR="${INSTALL_DIR:-/opt/uptime-mesh}"
BIN_PATH="${BIN_PATH:-$INSTALL_DIR/bin/uptimemesh-agent}"
UPDATE_LOG="${UPDATE_LOG:-$INSTALL_DIR/data/logs/update.log}"
HEALTH_URL="${HEALTH_URL:-}"
AGENT_SOCKET="${AGENT_SOCKET:-$INSTALL_DIR/data/agent.sock}"
FORCE=0

usage() {
  cat <<'USAGE'
Usage:
  sudo ops/agent-update.sh [options]

Options:
  --install-dir <path>      Install directory (default: /opt/uptime-mesh)
  --bin-path <path>         Agent binary path
  --health-url <url>        Health check URL
  --agent-socket <path>     Agent control socket path
  --force                   Skip pre-update health check
  -h, --help                Show help
USAGE
}

require_arg_value() {
  flag="$1"
  value="${2:-}"
  if [ -z "$value" ] || [ "${value#--}" != "$value" ]; then
    echo "missing value for ${flag}" >&2
    usage
    exit 1
  fi
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --install-dir)
      require_arg_value "$1" "${2:-}"
      INSTALL_DIR="$2"
      shift 2
      ;;
    --bin-path)
      require_arg_value "$1" "${2:-}"
      BIN_PATH="$2"
      shift 2
      ;;
    --health-url)
      require_arg_value "$1" "${2:-}"
      HEALTH_URL="$2"
      shift 2
      ;;
    --agent-socket)
      require_arg_value "$1" "${2:-}"
      AGENT_SOCKET="$2"
      shift 2
      ;;
    --force)
      FORCE=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown argument: $1" >&2
      exit 1
      ;;
  esac
done

resolve_health_url() {
  if [ -n "${HEALTH_URL:-}" ]; then
    printf '%s' "$HEALTH_URL"
    return 0
  fi
  env_file="$INSTALL_DIR/.env"
  if [ ! -f "$env_file" ]; then
    printf 'http://127.0.0.1:8010/health'
    return 0
  fi
  port="$(sed -n -E 's/^SERVER_PORT=(.*)$/\1/p' "$env_file" | tail -n 1)"
  if [ -n "$port" ]; then
    printf 'http://127.0.0.1:%s/health' "$port"
  else
    printf 'http://127.0.0.1:8010/health'
  fi
}

HEALTH_URL="$(resolve_health_url)"

mkdir -p "$(dirname "$UPDATE_LOG")" >/dev/null 2>&1 || true
: "${GOFLAGS:=-mod=mod}"
: "${GOPROXY:=https://proxy.golang.org,direct}"
export GOFLAGS GOPROXY

ts() { date -u +"%Y-%m-%dT%H:%M:%SZ"; }
log() {
  line="$(ts) [agent-update] $*"
  printf '%s\n' "$line"
  printf '%s\n' "$line" >>"$UPDATE_LOG" 2>/dev/null || true
}
fail() {
  line="$(ts) [agent-update][error] $*"
  printf '%s\n' "$line" >&2
  printf '%s\n' "$line" >>"$UPDATE_LOG" 2>/dev/null || true
  exit 1
}

[ "$(id -u)" -eq 0 ] || fail "agent update must run as root"
command -v go >/dev/null 2>&1 || fail "go is required"
[ -d "$INSTALL_DIR/agent/cmd/uptimemesh-agent" ] || fail "agent source missing under $INSTALL_DIR"

if [ "$FORCE" -ne 1 ]; then
  if command -v curl >/dev/null 2>&1; then
    curl -fsS --connect-timeout 3 --max-time 8 "$HEALTH_URL" >/dev/null 2>&1 || fail "pre-update health check failed: $HEALTH_URL"
  elif command -v wget >/dev/null 2>&1; then
    wget -qO - --timeout=8 --tries=1 "$HEALTH_URL" >/dev/null 2>&1 || fail "pre-update health check failed: $HEALTH_URL"
  else
    fail "curl or wget is required for health checks"
  fi
fi

tmp_bin="$(mktemp "${TMPDIR:-/tmp}/uptimemesh-agent.XXXXXX")"
backup_bin="$INSTALL_DIR/data/uptimemesh-agent.pre-agent-update"
mkdir -p "$(dirname "$BIN_PATH")" "$INSTALL_DIR/data" >/dev/null 2>&1 || true

(
  cd "$INSTALL_DIR"
  go build -trimpath -ldflags "-s -w" -o "$tmp_bin" ./agent/cmd/uptimemesh-agent
) || fail "go build failed"
chmod 0755 "$tmp_bin"

if [ -f "$BIN_PATH" ]; then
  cp "$BIN_PATH" "$backup_bin"
fi

install -m 0755 "$tmp_bin" "${BIN_PATH}.new"
mv "${BIN_PATH}.new" "$BIN_PATH"
rm -f "$tmp_bin"

restore_agent_backup() {
  if [ -f "$backup_bin" ]; then
    install -m 0755 "$backup_bin" "$BIN_PATH" || true
    if command -v systemctl >/dev/null 2>&1; then
      systemctl restart uptime-mesh-agent.service || true
    fi
  fi
}

if command -v systemctl >/dev/null 2>&1; then
  systemctl restart uptime-mesh-agent.service || {
    restore_agent_backup
    fail "failed restarting uptime-mesh-agent.service"
  }
fi

if command -v systemctl >/dev/null 2>&1; then
  systemctl is-active --quiet uptime-mesh-agent.service || {
    restore_agent_backup
    fail "post-update agent service is not active"
  }
fi

if [ -S "$AGENT_SOCKET" ] && command -v curl >/dev/null 2>&1; then
  curl -fsS --unix-socket "$AGENT_SOCKET" --connect-timeout 2 --max-time 5 http://localhost/healthz >/dev/null 2>&1 || {
    restore_agent_backup
    fail "post-update agent socket health gate failed"
  }
fi

if command -v curl >/dev/null 2>&1; then
  curl -fsS --connect-timeout 3 --max-time 8 "$HEALTH_URL" >/dev/null 2>&1 || {
    restore_agent_backup
    fail "post-update health gate failed"
  }
else
  wget -qO - --timeout=8 --tries=1 "$HEALTH_URL" >/dev/null 2>&1 || {
    restore_agent_backup
    fail "post-update health gate failed"
  }
fi

log "agent update complete"
exit 0
