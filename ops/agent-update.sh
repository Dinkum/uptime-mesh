#!/usr/bin/env sh
# UptimeMesh agent-only updater

set -eu

INSTALL_DIR="${INSTALL_DIR:-/opt/uptime-mesh}"
BIN_PATH="${BIN_PATH:-/usr/local/bin/uptimemesh-agent}"
UPDATE_LOG="${UPDATE_LOG:-$INSTALL_DIR/data/logs/update.log}"
HEALTH_URL="${HEALTH_URL:-http://127.0.0.1:8010/health}"
FORCE=0

while [ "$#" -gt 0 ]; do
  case "$1" in
    --install-dir)
      INSTALL_DIR="$2"
      shift 2
      ;;
    --bin-path)
      BIN_PATH="$2"
      shift 2
      ;;
    --health-url)
      HEALTH_URL="$2"
      shift 2
      ;;
    --force)
      FORCE=1
      shift
      ;;
    *)
      echo "unknown argument: $1" >&2
      exit 1
      ;;
  esac
done

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
    curl -fsS "$HEALTH_URL" >/dev/null 2>&1 || fail "pre-update health check failed: $HEALTH_URL"
  elif command -v wget >/dev/null 2>&1; then
    wget -qO - "$HEALTH_URL" >/dev/null 2>&1 || fail "pre-update health check failed: $HEALTH_URL"
  else
    fail "curl or wget is required for health checks"
  fi
fi

tmp_bin="$(mktemp "${TMPDIR:-/tmp}/uptimemesh-agent.XXXXXX")"
backup_bin="$INSTALL_DIR/data/uptimemesh-agent.pre-agent-update"

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

if command -v systemctl >/dev/null 2>&1; then
  systemctl restart uptime-mesh-agent.service || fail "failed restarting uptime-mesh-agent.service"
fi

if command -v curl >/dev/null 2>&1; then
  curl -fsS "$HEALTH_URL" >/dev/null 2>&1 || {
    if [ -f "$backup_bin" ]; then
      install -m 0755 "$backup_bin" "$BIN_PATH" || true
      systemctl restart uptime-mesh-agent.service || true
    fi
    fail "post-update health gate failed"
  }
else
  wget -qO - "$HEALTH_URL" >/dev/null 2>&1 || {
    if [ -f "$backup_bin" ]; then
      install -m 0755 "$backup_bin" "$BIN_PATH" || true
      systemctl restart uptime-mesh-agent.service || true
    fi
    fail "post-update health gate failed"
  }
fi

log "agent update complete"
exit 0
