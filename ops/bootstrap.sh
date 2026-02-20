#!/usr/bin/env sh
# UptimeMesh bootstrap dispatcher
# - Safe lock
# - Fetches and verifies manifest-driven scripts
# - Installs or updates based on node state

set -eu

DEFAULT_VERSION_URL="https://raw.githubusercontent.com/Dinkum/uptime-mesh/main/version.json"
VERSION_URL="${VERSION_URL:-$DEFAULT_VERSION_URL}"
CHANNEL="${CHANNEL:-stable}"
INSTALL_DIR="${INSTALL_DIR:-/opt/uptime-mesh}"
LOCK_DIR="${LOCK_DIR:-/tmp/uptimemesh-bootstrap.lock}"
BOOTSTRAP_LOG="${BOOTSTRAP_LOG:-${INSTALL_DIR}/data/logs/bootstrap.log}"
UPDATE_LOG="${UPDATE_LOG:-${INSTALL_DIR}/data/logs/update.log}"
MIN_FREE_MB="${MIN_FREE_MB:-256}"
TIMEOUT_SECONDS="${TIMEOUT_SECONDS:-900}"
FORCE=0

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
    --timeout-seconds)
      TIMEOUT_SECONDS="$2"
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

mkdir -p "$(dirname "$BOOTSTRAP_LOG")" >/dev/null 2>&1 || true
mkdir -p "$(dirname "$UPDATE_LOG")" >/dev/null 2>&1 || true

ts() { date -u +"%Y-%m-%dT%H:%M:%SZ"; }

log() {
  msg="$*"
  line="$(ts) [bootstrap] ${msg}"
  printf '%s\n' "$line"
  printf '%s\n' "$line" >>"$BOOTSTRAP_LOG" 2>/dev/null || true
  printf '%s\n' "$line" >>"$UPDATE_LOG" 2>/dev/null || true
}

warn() {
  msg="$*"
  line="$(ts) [bootstrap][warn] ${msg}"
  printf '%s\n' "$line" >&2
  printf '%s\n' "$line" >>"$BOOTSTRAP_LOG" 2>/dev/null || true
  printf '%s\n' "$line" >>"$UPDATE_LOG" 2>/dev/null || true
}

fail() {
  msg="$*"
  line="$(ts) [bootstrap][error] ${msg}"
  printf '%s\n' "$line" >&2
  printf '%s\n' "$line" >>"$BOOTSTRAP_LOG" 2>/dev/null || true
  printf '%s\n' "$line" >>"$UPDATE_LOG" 2>/dev/null || true
  exit 1
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
  return 1
}

download_file() {
  src="$1"
  dst="$2"
  tries=1
  while [ "$tries" -le 3 ]; do
    if command -v curl >/dev/null 2>&1; then
      if curl -fsSL --connect-timeout 10 --max-time 120 "$src" -o "$dst"; then
        return 0
      fi
    elif command -v wget >/dev/null 2>&1; then
      if wget -qO "$dst" "$src"; then
        return 0
      fi
    else
      return 1
    fi
    sleep "$tries"
    tries=$((tries + 1))
  done
  return 1
}

run_with_timeout() {
  if command -v timeout >/dev/null 2>&1; then
    timeout "$TIMEOUT_SECONDS" "$@"
    return $?
  fi
  "$@"
}

preflight() {
  if ! command -v python3 >/dev/null 2>&1; then
    fail "python3 is required"
  fi
  if ! command -v curl >/dev/null 2>&1 && ! command -v wget >/dev/null 2>&1; then
    fail "curl or wget is required"
  fi
  if ! command -v df >/dev/null 2>&1; then
    warn "df not available; disk preflight skipped"
    return 0
  fi
  target_dir="$INSTALL_DIR"
  if [ ! -d "$target_dir" ]; then
    target_dir="$(dirname "$target_dir")"
  fi
  free_kb="$(df -Pk "$target_dir" | awk 'NR==2 {print $4}')"
  if [ -n "$free_kb" ]; then
    required_kb=$((MIN_FREE_MB * 1024))
    if [ "$free_kb" -lt "$required_kb" ]; then
      fail "insufficient free disk space (${MIN_FREE_MB}MB required)"
    fi
  fi
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL --connect-timeout 6 --max-time 12 https://api.github.com >/dev/null 2>&1 \
      || fail "github unreachable from this node (https://api.github.com)"
  elif command -v wget >/dev/null 2>&1; then
    wget -qO - --timeout=12 https://api.github.com >/dev/null 2>&1 \
      || fail "github unreachable from this node (https://api.github.com)"
  fi
}

verify_sha() {
  file="$1"
  expected="$2"
  [ -n "$expected" ] || fail "missing required checksum for $(basename "$file")"
  actual="$(sha256_file "$file" || true)"
  [ -n "$actual" ] || fail "unable to compute sha256 for $(basename "$file")"
  [ "$actual" = "$expected" ] || fail "checksum mismatch for $(basename "$file")"
}

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/uptimemesh-bootstrap.XXXXXX")"
cleanup() {
  rm -rf "$TMP_DIR" >/dev/null 2>&1 || true
  rm -rf "$LOCK_DIR" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

if ! mkdir "$LOCK_DIR" 2>/dev/null; then
  log "another bootstrap run is active; skipping"
  exit 0
fi

log "run started | version_url: $VERSION_URL | channel: $CHANNEL"
preflight

manifest="$TMP_DIR/version.json"
download_file "$VERSION_URL" "$manifest" || fail "failed to fetch version manifest"

if [ -n "${VERSION_SHA256:-}" ]; then
  verify_sha "$manifest" "$VERSION_SHA256"
fi

MODE="install"
if [ -f "$INSTALL_DIR/VERSION" ] && [ -f "$INSTALL_DIR/.env" ] && [ -x "$INSTALL_DIR/install.sh" ]; then
  MODE="update"
fi

# Parse script URL + checksum from manifest.
eval "$(
python3 - "$manifest" "$VERSION_URL" "$CHANNEL" "$MODE" <<'PY'
import json
import shlex
import sys
from urllib.parse import urljoin

manifest_path, version_url, channel, mode = sys.argv[1:5]
doc = json.load(open(manifest_path, "r", encoding="utf-8"))
channels = doc.get("channels", {}) if isinstance(doc, dict) else {}
cfg = channels.get(channel, {}) if isinstance(channels, dict) else {}

entry_key = "install" if mode == "install" else "update"
entry = cfg.get(entry_key, {}) if isinstance(cfg, dict) else {}

path = str(entry.get("path", "")).strip()
sha = str(entry.get("sha256", "")).strip()
url = str(entry.get("url", "")).strip()
if not url and path:
    url = urljoin(version_url, path)

print(f"SCRIPT_URL={shlex.quote(url)}")
print(f"SCRIPT_SHA={shlex.quote(sha)}")
print(f"TARGET_MODE={shlex.quote(mode)}")
PY
)"

[ -n "${SCRIPT_URL:-}" ] || fail "manifest missing script URL for mode=$MODE"
script_file="$TMP_DIR/entry.sh"
download_file "$SCRIPT_URL" "$script_file" || fail "failed to download $MODE script"
verify_sha "$script_file" "$SCRIPT_SHA"
chmod +x "$script_file"

if [ "$MODE" = "install" ]; then
  log "dispatching install script"
  if [ "$FORCE" -eq 1 ]; then
    UPTIMEMESH_INSTALL_DIR="$INSTALL_DIR" run_with_timeout "$script_file" --force || fail "install script failed"
  else
    UPTIMEMESH_INSTALL_DIR="$INSTALL_DIR" run_with_timeout "$script_file" || fail "install script failed"
  fi
else
  log "dispatching update script"
  if [ "$FORCE" -eq 1 ]; then
    run_with_timeout "$script_file" --install-dir "$INSTALL_DIR" --version-url "$VERSION_URL" --channel "$CHANNEL" --force || fail "update script failed"
  else
    run_with_timeout "$script_file" --install-dir "$INSTALL_DIR" --version-url "$VERSION_URL" --channel "$CHANNEL" || fail "update script failed"
  fi
fi

log "run complete | mode: $MODE | status: success"
exit 0
