#!/usr/bin/env sh
# UptimeMesh Node Updater
# - Atomic installs
# - Checksum verification
# - Rollback on failed health check
# - Locking to avoid concurrent runs

set -eu

UPDATER_VERSION="1.0.1"
DEFAULT_VERSION_URL="https://raw.githubusercontent.com/Dinkum/uptime-mesh/main/version.json"

VERSION_URL="${VERSION_URL:-$DEFAULT_VERSION_URL}"
CHANNEL="${CHANNEL:-stable}"
INSTALL_DIR="${INSTALL_DIR:-/opt/uptime-mesh}"
BIN_DIR="${BIN_DIR:-/usr/local/bin}"
STATE_DIR="${STATE_DIR:-/var/lib/uptimemesh}"
LOCK_DIR="${LOCK_DIR:-/tmp/uptimemesh-update.lock}"
NODE_BIN_NAME="${NODE_BIN_NAME:-uptimemesh-agent}"
HEALTHCHECK_CMD="${HEALTHCHECK_CMD:-}"
FORCE_UPDATE=0
SKIP_SELF_UPDATE=0

log() {
  printf '%s %s\n' "[updater]" "$*"
}

warn() {
  printf '%s %s\n' "[updater][warn]" "$*" >&2
}

die() {
  printf '%s %s\n' "[updater][error]" "$*" >&2
  exit 1
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --version-url)
      VERSION_URL="$2"
      shift 2
      ;;
    --channel)
      CHANNEL="$2"
      shift 2
      ;;
    --install-dir)
      INSTALL_DIR="$2"
      shift 2
      ;;
    --bin-dir)
      BIN_DIR="$2"
      shift 2
      ;;
    --state-dir)
      STATE_DIR="$2"
      shift 2
      ;;
    --node-bin-name)
      NODE_BIN_NAME="$2"
      shift 2
      ;;
    --healthcheck-cmd)
      HEALTHCHECK_CMD="$2"
      shift 2
      ;;
    --skip-self-update)
      SKIP_SELF_UPDATE=1
      shift
      ;;
    --force)
      FORCE_UPDATE=1
      shift
      ;;
    *)
      die "unknown argument: $1"
      ;;
  esac
done

mkdir -p "$INSTALL_DIR" "$BIN_DIR" "$STATE_DIR"

TMP_DIR=""
cleanup() {
  [ -n "$TMP_DIR" ] && rm -rf "$TMP_DIR" || true
  rm -rf "$LOCK_DIR" || true
}
trap cleanup EXIT INT TERM

if ! mkdir "$LOCK_DIR" 2>/dev/null; then
  die "another updater process is already running (lock: $LOCK_DIR)"
fi

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/uptimemesh-update.XXXXXX")"

download_file() {
  src="$1"
  dst="$2"
  i=1
  while [ "$i" -le 5 ]; do
    if command -v curl >/dev/null 2>&1; then
      if curl -fsSL --connect-timeout 10 --max-time 120 "$src" -o "$dst"; then
        return 0
      fi
    elif command -v wget >/dev/null 2>&1; then
      if wget -qO "$dst" "$src"; then
        return 0
      fi
    else
      die "curl or wget is required"
    fi
    sleep "$i"
    i=$((i + 1))
  done
  return 1
}

sha256_file() {
  f="$1"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$f" | awk '{print $1}'
    return 0
  fi
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$f" | awk '{print $1}'
    return 0
  fi
  if command -v openssl >/dev/null 2>&1; then
    openssl dgst -sha256 "$f" | awk '{print $NF}'
    return 0
  fi
  die "no sha256 tool available (sha256sum/shasum/openssl)"
}

verify_sha256() {
  file="$1"
  expected="$2"
  if [ -z "$expected" ]; then
    return 0
  fi
  actual="$(sha256_file "$file")"
  if [ "$actual" != "$expected" ]; then
    die "checksum mismatch for $file (expected=$expected actual=$actual)"
  fi
}

manifest="$TMP_DIR/version.json"
download_file "$VERSION_URL" "$manifest" || die "failed to fetch version manifest: $VERSION_URL"

target_arch="$(uname -m)"
case "$target_arch" in
  x86_64) target_arch="amd64" ;;
  aarch64|arm64) target_arch="arm64" ;;
esac
target_os="$(uname -s | tr '[:upper:]' '[:lower:]')"
target_key="${target_os}-${target_arch}"

eval "$(
python3 - "$manifest" "$VERSION_URL" "$CHANNEL" "$target_key" <<'PY'
import json
import shlex
import sys
from urllib.parse import urljoin

manifest_path, version_url, channel, target_key = sys.argv[1:5]
doc = json.load(open(manifest_path, "r", encoding="utf-8"))
if isinstance(doc.get("channels"), dict):
    cfg = doc["channels"].get(channel)
    if cfg is None:
        raise SystemExit(f"channel not found in version manifest: {channel}")
else:
    cfg = doc

def resolve_url(block):
    if not isinstance(block, dict):
        return ""
    if block.get("url"):
        return str(block["url"])
    if block.get("path"):
        return urljoin(version_url, str(block["path"]))
    return ""

updater = cfg.get("updater", {})
bootstrap = cfg.get("bootstrap", {})
agent = cfg.get("agent", {})
artifacts = agent.get("artifacts", {}) if isinstance(agent, dict) else {}
artifact = artifacts.get(target_key, {}) if isinstance(artifacts, dict) else {}

values = {
    "MANIFEST_VERSION": str(cfg.get("version", "")),
    "UPDATER_LATEST_VERSION": str(updater.get("version", "")),
    "UPDATER_URL": resolve_url(updater),
    "UPDATER_SHA256": str(updater.get("sha256", "")),
    "BOOTSTRAP_URL": resolve_url(bootstrap),
    "BOOTSTRAP_SHA256": str(bootstrap.get("sha256", "")),
    "AGENT_VERSION": str(agent.get("version", "")),
    "AGENT_URL": str(artifact.get("url", "")),
    "AGENT_SHA256": str(artifact.get("sha256", "")),
}

for key, value in values.items():
    print(f"{key}={shlex.quote(value)}")
PY
)"

if [ "$SKIP_SELF_UPDATE" -eq 0 ] && [ -n "$UPDATER_URL" ]; then
  if [ "$UPDATER_LATEST_VERSION" != "$UPDATER_VERSION" ] || [ "$FORCE_UPDATE" -eq 1 ]; then
    log "self-updating updater script $UPDATER_VERSION -> $UPDATER_LATEST_VERSION"
    updater_tmp="$TMP_DIR/node-update.sh"
    download_file "$UPDATER_URL" "$updater_tmp" || die "failed to download updater script"
    verify_sha256 "$updater_tmp" "$UPDATER_SHA256"
    install -m 0755 "$updater_tmp" "$INSTALL_DIR/node-update.sh.new"
    mv "$INSTALL_DIR/node-update.sh.new" "$INSTALL_DIR/node-update.sh"
    force_arg=""
    if [ "$FORCE_UPDATE" -eq 1 ]; then
      force_arg="--force"
    fi
    exec "$INSTALL_DIR/node-update.sh" \
      --skip-self-update \
      --version-url "$VERSION_URL" \
      --channel "$CHANNEL" \
      --install-dir "$INSTALL_DIR" \
      --bin-dir "$BIN_DIR" \
      --state-dir "$STATE_DIR" \
      --node-bin-name "$NODE_BIN_NAME" \
      --healthcheck-cmd "$HEALTHCHECK_CMD" \
      $force_arg
  fi
fi

if [ -n "$BOOTSTRAP_URL" ]; then
  bootstrap_tmp="$TMP_DIR/bootstrap.sh"
  if download_file "$BOOTSTRAP_URL" "$bootstrap_tmp"; then
    if [ -n "$BOOTSTRAP_SHA256" ]; then
      got="$(sha256_file "$bootstrap_tmp")"
      if [ "$got" != "$BOOTSTRAP_SHA256" ]; then
        warn "skipping bootstrap refresh due to checksum mismatch"
      else
        install -m 0755 "$bootstrap_tmp" "$INSTALL_DIR/bootstrap.sh.new"
        mv "$INSTALL_DIR/bootstrap.sh.new" "$INSTALL_DIR/bootstrap.sh"
      fi
    else
      install -m 0755 "$bootstrap_tmp" "$INSTALL_DIR/bootstrap.sh.new"
      mv "$INSTALL_DIR/bootstrap.sh.new" "$INSTALL_DIR/bootstrap.sh"
    fi
  else
    warn "failed to refresh bootstrap script from $BOOTSTRAP_URL"
  fi
fi

if [ -z "$AGENT_URL" ]; then
  log "no agent artifact configured for target=$target_key in manifest, skipping binary update"
  exit 0
fi

log "updating $NODE_BIN_NAME to version=$AGENT_VERSION target=$target_key"
artifact_tmp="$TMP_DIR/agent.asset"
download_file "$AGENT_URL" "$artifact_tmp" || die "failed to download agent artifact"
verify_sha256 "$artifact_tmp" "$AGENT_SHA256"

agent_new="$TMP_DIR/$NODE_BIN_NAME.new"
case "$AGENT_URL" in
  *.tar.gz|*.tgz)
    tar -xzf "$artifact_tmp" -C "$TMP_DIR"
    found="$(find "$TMP_DIR" -type f -name "$NODE_BIN_NAME" | head -n 1 || true)"
    [ -n "$found" ] || die "agent artifact archive does not contain $NODE_BIN_NAME"
    cp "$found" "$agent_new"
    ;;
  *)
    cp "$artifact_tmp" "$agent_new"
    ;;
esac
chmod 0755 "$agent_new"

target_bin="$BIN_DIR/$NODE_BIN_NAME"
backup_bin="$STATE_DIR/${NODE_BIN_NAME}.bak"
if [ -f "$target_bin" ]; then
  cp "$target_bin" "$backup_bin"
fi

install -m 0755 "$agent_new" "${target_bin}.new"
mv "${target_bin}.new" "$target_bin"

health_ok=1
if [ -n "$HEALTHCHECK_CMD" ]; then
  if ! sh -c "$HEALTHCHECK_CMD"; then
    health_ok=0
  fi
elif command -v systemctl >/dev/null 2>&1 && systemctl list-unit-files >/dev/null 2>&1; then
  unit="${NODE_BIN_NAME}.service"
  if systemctl list-unit-files --type=service | grep -q "^${unit}"; then
    if ! systemctl restart "$unit"; then
      health_ok=0
    elif ! systemctl is-active --quiet "$unit"; then
      health_ok=0
    fi
  fi
fi

if [ "$health_ok" -ne 1 ]; then
  warn "health check failed after update, attempting rollback"
  if [ -f "$backup_bin" ]; then
    cp "$backup_bin" "$target_bin"
    chmod 0755 "$target_bin"
  fi
  die "update failed and rollback applied"
fi

cat > "$STATE_DIR/update-state.json" <<EOF
{
  "updated_at": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
  "channel": "$CHANNEL",
  "manifest_version": "$MANIFEST_VERSION",
  "agent_version": "$AGENT_VERSION",
  "updater_version": "$UPDATER_LATEST_VERSION"
}
EOF

log "update completed successfully"
