#!/usr/bin/env bash
# UptimeMesh full app updater.
# - Release-driven source update
# - Snapshot + rollback
# - Health-gated apply

set -euo pipefail

DEFAULT_VERSION_URL="https://raw.githubusercontent.com/Dinkum/uptime-mesh/main/version.json"
DEFAULT_GITHUB_REPO="Dinkum/uptime-mesh"

VERSION_URL="${VERSION_URL:-$DEFAULT_VERSION_URL}"
CHANNEL="${CHANNEL:-stable}"
GITHUB_REPO="${GITHUB_REPO:-$DEFAULT_GITHUB_REPO}"
INSTALL_DIR="${INSTALL_DIR:-/opt/uptime-mesh}"
BIN_PATH="${BIN_PATH:-/usr/local/bin/uptimemesh-agent}"
HEALTH_TIMEOUT_SECONDS="${HEALTH_TIMEOUT_SECONDS:-90}"
HEALTH_INTERVAL_SECONDS="${HEALTH_INTERVAL_SECONDS:-3}"
STATE_FILE=""
FORCE=0

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --version-url)
      VERSION_URL="$2"
      shift 2
      ;;
    --channel)
      CHANNEL="$2"
      shift 2
      ;;
    --github-repo)
      GITHUB_REPO="$2"
      shift 2
      ;;
    --install-dir)
      INSTALL_DIR="$2"
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

STATE_FILE="${STATE_FILE:-$INSTALL_DIR/data/update-state.json}"
LOCK_DIR="${LOCK_DIR:-/tmp/uptimemesh-update.lock}"
UPDATE_LOG="${UPDATE_LOG:-$INSTALL_DIR/data/logs/update.log}"

mkdir -p "$(dirname "$UPDATE_LOG")" >/dev/null 2>&1 || true
mkdir -p "$INSTALL_DIR/data" >/dev/null 2>&1 || true

: "${GOFLAGS:=-mod=mod}"
: "${GOPROXY:=https://proxy.golang.org,direct}"
export GOFLAGS GOPROXY

ts() { date -u +"%Y-%m-%dT%H:%M:%SZ"; }

log() {
  local line
  line="$(ts) [update] $*"
  printf '%s\n' "$line"
  printf '%s\n' "$line" >>"$UPDATE_LOG" 2>/dev/null || true
}

warn() {
  local line
  line="$(ts) [update][warn] $*"
  printf '%s\n' "$line" >&2
  printf '%s\n' "$line" >>"$UPDATE_LOG" 2>/dev/null || true
}

fail() {
  local line
  line="$(ts) [update][error] $*"
  printf '%s\n' "$line" >&2
  printf '%s\n' "$line" >>"$UPDATE_LOG" 2>/dev/null || true
  exit 1
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || fail "missing required command: $1"
}

sha256_file() {
  local f="$1"
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
  local src="$1"
  local dst="$2"
  local tries=1
  while (( tries <= 4 )); do
    if command -v curl >/dev/null 2>&1; then
      if curl -fsSL --connect-timeout 10 --max-time 180 "$src" -o "$dst"; then
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

verify_sha() {
  local file="$1"
  local expected="$2"
  [[ -n "$expected" ]] || return 1
  local actual
  actual="$(sha256_file "$file" || true)"
  [[ -n "$actual" ]] || return 1
  [[ "$actual" == "$expected" ]] || return 1
  return 0
}

is_github_generated_tarball_url() {
  local url="$1"
  [[ "$url" =~ ^https://api\.github\.com/repos/.+/tarball/ ]] || [[ "$url" =~ ^https://codeload\.github\.com/.+/tar\.gz/ ]]
}

http_get() {
  local url="$1"
  if command -v curl >/dev/null 2>&1; then
    curl -fsS "$url" >/dev/null 2>&1
    return $?
  fi
  if command -v wget >/dev/null 2>&1; then
    wget -qO - "$url" >/dev/null 2>&1
    return $?
  fi
  return 1
}

run_logged() {
  local name="$1"
  shift
  local tmp_file
  local rc=0
  tmp_file="$(mktemp)"
  log "$name.start"
  set +e
  "$@" >"$tmp_file" 2>&1
  rc=$?
  set -e
  cat "$tmp_file" >>"$UPDATE_LOG" 2>/dev/null || true
  rm -f "$tmp_file"
  if [[ "$rc" -ne 0 ]]; then
    warn "$name.failed | exit_code: $rc"
    return "$rc"
  fi
  log "$name.ok"
  return 0
}

write_state() {
  local status="$1"
  local attempted="$2"
  local previous="$3"
  python3 - "$STATE_FILE" "$status" "$attempted" "$previous" <<'PY'
import json
import os
import sys
from datetime import datetime, timezone

path, status, attempted, previous = sys.argv[1:5]
os.makedirs(os.path.dirname(path), exist_ok=True)
payload = {
    "status": status,
    "attempted": attempted,
    "previous": previous,
    "updated_at": datetime.now(timezone.utc).isoformat(),
}
with open(path, "w", encoding="utf-8") as fh:
    json.dump(payload, fh, sort_keys=True, indent=2)
PY
}

extract_state_field() {
  local file="$1"
  local key="$2"
  if [[ ! -f "$file" ]]; then
    printf ''
    return 0
  fi
  python3 - "$file" "$key" <<'PY'
import json
import sys

p, k = sys.argv[1:3]
try:
    doc = json.load(open(p, "r", encoding="utf-8"))
except Exception:
    print("")
    raise SystemExit(0)
value = doc.get(k, "") if isinstance(doc, dict) else ""
print(str(value) if value is not None else "")
PY
}

resolve_health_url() {
  local env_file="$INSTALL_DIR/.env"
  if [[ ! -f "$env_file" ]]; then
    printf 'http://127.0.0.1:8010/health'
    return 0
  fi
  local base
  base="$(sed -n -E 's/^RUNTIME_API_BASE_URL=(.*)$/\1/p' "$env_file" | tail -n 1)"
  if [[ -n "$base" ]]; then
    printf '%s/health' "${base%/}"
  else
    printf 'http://127.0.0.1:8010/health'
  fi
}

wait_for_health() {
  local url="$1"
  local elapsed=0
  while (( elapsed < HEALTH_TIMEOUT_SECONDS )); do
    if http_get "$url"; then
      return 0
    fi
    sleep "$HEALTH_INTERVAL_SECONDS"
    elapsed=$((elapsed + HEALTH_INTERVAL_SECONDS))
  done
  return 1
}

resolve_db_path() {
  local env_file="$INSTALL_DIR/.env"
  [[ -f "$env_file" ]] || return 1
  local db_url rel
  db_url="$(sed -n -E 's/^DATABASE_URL=(.*)$/\1/p' "$env_file" | tail -n 1)"
  case "$db_url" in
    sqlite+aiosqlite:///*)
      rel="${db_url#sqlite+aiosqlite:///}"
      ;;
    sqlite:///*)
      rel="${db_url#sqlite:///}"
      ;;
    *)
      return 1
      ;;
  esac
  if [[ "${rel#/}" != "$rel" ]]; then
    printf '%s' "$rel"
  else
    printf '%s/%s' "$INSTALL_DIR" "${rel#./}"
  fi
}

service_exists() {
  local unit="$1"
  systemctl list-unit-files --type=service --no-legend 2>/dev/null | awk '{print $1}' | grep -qx "$unit"
}

normalize_log_paths() {
  mkdir -p "$INSTALL_DIR/data/logs" >/dev/null 2>&1 || true
  local env_file="$INSTALL_DIR/.env"
  if [[ -f "$env_file" ]]; then
    python3 - "$env_file" <<'PY'
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
lines = path.read_text(encoding="utf-8").splitlines()
kv = {}
for line in lines:
    if "=" in line and not line.lstrip().startswith("#"):
        k, v = line.split("=", 1)
        kv[k.strip()] = v.strip()
kv["LOG_FILE"] = "./data/logs/app.log"
kv["AGENT_LOG_FILE"] = "./data/logs/agent.log"
ordered = sorted(kv.items(), key=lambda x: x[0])
tmp = path.with_name(path.name + ".tmp")
tmp.write_text("".join(f"{k}={v}\n" for k, v in ordered), encoding="utf-8")
tmp.replace(path)
PY
  fi
  local unit
  for unit in /etc/systemd/system/uptime-mesh.service /etc/systemd/system/uptime-mesh-agent.service /etc/systemd/system/uptime-mesh-watchdog.service /etc/systemd/system/uptime-mesh-update.service; do
    if [[ -f "$unit" ]]; then
      sed -i \
        -e 's#\./data/app\.log#./data/logs/app.log#g' \
        -e 's#\./data/agent\.log#./data/logs/agent.log#g' \
        -e 's#/data/update\.log#/data/logs/update.log#g' \
        "$unit"
    fi
  done
}

prune_glob_keep() {
  local pattern="$1"
  local keep="$2"
  local count=0
  local f
  while IFS= read -r f; do
    count=$((count + 1))
    if (( count > keep )); then
      rm -rf "$f" || true
    fi
  done < <(ls -1dt $pattern 2>/dev/null || true)
}

prune_old_backups() {
  prune_glob_keep "${INSTALL_DIR}.prev.*.tar.gz" 3
  prune_glob_keep "${INSTALL_DIR}.prev.*.sqlite" 3
  prune_glob_keep "${INSTALL_DIR}/data/uptimemesh-agent.pre-update-*" 3
  prune_glob_keep "${INSTALL_DIR}.failed.*" 2
}

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/uptimemesh-update.XXXXXX")"
APP_ARCHIVE_BACKUP=""
DB_BACKUP=""
AGENT_BACKUP=""
HEALTH_URL=""
LATEST_VERSION=""
PREVIOUS_VERSION=""
ROLLBACK_READY=0
FAILED_DIR=""
db_path=""

cleanup() {
  rm -rf "$TMP_DIR" >/dev/null 2>&1 || true
  rm -rf "$LOCK_DIR" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

rollback_and_fail() {
  local reason="$1"
  if [[ "$ROLLBACK_READY" -eq 1 ]]; then
    warn "starting rollback | reason: $reason"
    local restore_base restore_dir restored_tree
    restore_base="$TMP_DIR/restore"
    restore_dir="$restore_base/root"
    mkdir -p "$restore_dir"

    if [[ -n "$APP_ARCHIVE_BACKUP" && -f "$APP_ARCHIVE_BACKUP" ]]; then
      run_logged "rollback.app_extract" tar -xzf "$APP_ARCHIVE_BACKUP" -C "$restore_dir" || true
      restored_tree="$restore_dir/$(basename "$INSTALL_DIR")"
      if [[ -d "$restored_tree" ]]; then
        if [[ -d "$INSTALL_DIR/data" ]]; then
          cp -a "$INSTALL_DIR/data" "$restored_tree/" || warn "rollback failed to preserve data dir"
        fi
        if [[ -d "$INSTALL_DIR/.venv" ]]; then
          cp -a "$INSTALL_DIR/.venv" "$restored_tree/" || warn "rollback failed to preserve venv"
        fi
        if [[ -d "$INSTALL_DIR" ]]; then
          FAILED_DIR="${INSTALL_DIR}.failed.$(date -u +%Y%m%dT%H%M%SZ)"
          mv "$INSTALL_DIR" "$FAILED_DIR" || true
        fi
        mv "$restored_tree" "$INSTALL_DIR" || warn "rollback failed to put app tree back"
      else
        warn "rollback archive did not contain expected app tree"
      fi
    fi

    if [[ -n "$db_path" && -f "$DB_BACKUP" ]]; then
      mkdir -p "$(dirname "$db_path")" || true
      cp "$DB_BACKUP" "$db_path" || warn "rollback could not restore DB backup"
    fi
    if [[ -f "$AGENT_BACKUP" ]]; then
      install -m 0755 "$AGENT_BACKUP" "$BIN_PATH" || warn "rollback could not restore agent binary"
    fi

    normalize_log_paths
    if command -v systemctl >/dev/null 2>&1; then
      systemctl daemon-reload || true
      systemctl restart uptime-mesh.service || true
      if service_exists uptime-mesh-agent.service; then
        systemctl restart uptime-mesh-agent.service || true
      fi
    fi
    write_state "failed" "$LATEST_VERSION" "$PREVIOUS_VERSION"
  fi
  fail "$reason"
}

run_or_rollback() {
  local reason="$1"
  shift
  "$@" || rollback_and_fail "$reason"
}

if ! mkdir "$LOCK_DIR" 2>/dev/null; then
  log "update already running; skipping"
  exit 0
fi

[[ "$(id -u)" -eq 0 ]] || fail "update must run as root"
require_cmd python3
require_cmd tar
require_cmd go
if ! command -v curl >/dev/null 2>&1 && ! command -v wget >/dev/null 2>&1; then
  fail "curl or wget is required"
fi

HEALTH_URL="$(resolve_health_url)"
if [[ "$FORCE" -ne 1 ]]; then
  http_get "$HEALTH_URL" || fail "service health check failed before update: $HEALTH_URL"
fi

log "run started | channel: $CHANNEL | version_url: $VERSION_URL"

manifest="$TMP_DIR/version.json"
run_logged "manifest.download" download_file "$VERSION_URL" "$manifest" || fail "failed to fetch version manifest"

release_json="$TMP_DIR/release.json"
release_api="https://api.github.com/repos/${GITHUB_REPO}/releases/latest"
run_logged "release.download" download_file "$release_api" "$release_json" || fail "failed to fetch latest release metadata"

# Collect manifest and release data.
eval "$(
python3 - "$manifest" "$release_json" "$CHANNEL" <<'PY'
import json
import shlex
import sys

manifest_path, release_path, channel = sys.argv[1:4]
manifest = json.load(open(manifest_path, "r", encoding="utf-8"))
release = json.load(open(release_path, "r", encoding="utf-8"))
channels = manifest.get("channels", {}) if isinstance(manifest, dict) else {}
cfg = channels.get(channel, {}) if isinstance(channels, dict) else {}
source = cfg.get("source", {}) if isinstance(cfg, dict) else {}
latest_tag = str(release.get("tag_name", "")).strip()
tarball_url = str(release.get("tarball_url", "")).strip()
source_sha = str(source.get("sha256", "")).strip()
channel_version = str(cfg.get("version", "")).strip() if isinstance(cfg, dict) else ""
print(f"LATEST_TAG={shlex.quote(latest_tag)}")
print(f"TARBALL_URL={shlex.quote(tarball_url)}")
print(f"SOURCE_SHA256={shlex.quote(source_sha)}")
print(f"CHANNEL_VERSION={shlex.quote(channel_version)}")
PY
)"

[[ -n "${LATEST_TAG:-}" ]] || fail "release metadata missing tag_name"
LATEST_VERSION="${LATEST_TAG#v}"
CHANNEL_VERSION="${CHANNEL_VERSION:-}"
if [[ -n "$CHANNEL_VERSION" && "$CHANNEL_VERSION" != "$LATEST_VERSION" ]]; then
  fail "manifest channel version (${CHANNEL_VERSION}) does not match latest release (${LATEST_VERSION})"
fi
SOURCE_TARBALL_URL="${TARBALL_URL:-}"
[[ -n "$SOURCE_TARBALL_URL" ]] || fail "missing source tarball URL"

CURRENT_VERSION=""
if [[ -f "$INSTALL_DIR/VERSION" ]]; then
  CURRENT_VERSION="$(tr -d ' \n\r' < "$INSTALL_DIR/VERSION")"
fi
PREVIOUS_VERSION="$CURRENT_VERSION"

if [[ "$FORCE" -ne 1 && -n "$CURRENT_VERSION" && "$CURRENT_VERSION" == "$LATEST_VERSION" ]]; then
  log "already current | version: $CURRENT_VERSION"
  exit 0
fi

if [[ "$FORCE" -ne 1 ]]; then
  last_status="$(extract_state_field "$STATE_FILE" status)"
  last_attempted="$(extract_state_field "$STATE_FILE" attempted)"
  if [[ "$last_status" == "failed" && "$last_attempted" == "$LATEST_VERSION" ]]; then
    log "skipping failed version retry | attempted: $LATEST_VERSION"
    exit 0
  fi
fi

write_state "in_progress" "$LATEST_VERSION" "$CURRENT_VERSION"

# Backups before changes.
backup_stamp="$(date -u +%Y%m%dT%H%M%SZ)"
APP_ARCHIVE_BACKUP="${INSTALL_DIR}.prev.${backup_stamp}.tar.gz"
DB_BACKUP="${INSTALL_DIR}.prev.${backup_stamp}.sqlite"
AGENT_BACKUP="$INSTALL_DIR/data/uptimemesh-agent.pre-update-${backup_stamp}"

if [[ -d "$INSTALL_DIR" ]]; then
  run_logged "backup.app" tar --exclude='./data' --exclude='./.venv' -czf "$APP_ARCHIVE_BACKUP" -C "$(dirname "$INSTALL_DIR")" "$(basename "$INSTALL_DIR")" || fail "failed app directory backup"
fi

db_path="$(resolve_db_path || true)"
if [[ -n "$db_path" && -f "$db_path" ]]; then
  if command -v sqlite3 >/dev/null 2>&1; then
    run_logged "backup.db" sqlite3 "$db_path" ".backup '$DB_BACKUP'" || run_logged "backup.db_copy" cp "$db_path" "$DB_BACKUP" || fail "failed db backup"
  else
    run_logged "backup.db_copy" cp "$db_path" "$DB_BACKUP" || fail "failed db backup"
  fi
fi

if [[ -f "$BIN_PATH" ]]; then
  run_logged "backup.agent" cp "$BIN_PATH" "$AGENT_BACKUP" || fail "failed agent backup"
fi

ROLLBACK_READY=1

# Download + verify source tarball.
source_tgz="$TMP_DIR/source.tar.gz"
run_or_rollback "failed to download release tarball" run_logged "source.download" download_file "$SOURCE_TARBALL_URL" "$source_tgz"

if [[ -n "${SOURCE_SHA256:-}" ]]; then
  if ! verify_sha "$source_tgz" "$SOURCE_SHA256"; then
    actual_sha="$(sha256_file "$source_tgz" || true)"
    if is_github_generated_tarball_url "$SOURCE_TARBALL_URL"; then
      warn "source checksum mismatch on GitHub-generated tarball; continuing | expected: ${SOURCE_SHA256} actual: ${actual_sha:-unknown}"
    else
      rollback_and_fail "source tarball checksum verification failed | expected: ${SOURCE_SHA256} actual: ${actual_sha:-unknown}"
    fi
  fi
else
  warn "manifest missing channels.${CHANNEL}.source.sha256; proceeding with release API tarball URL"
fi

src_unpack="$TMP_DIR/src"
mkdir -p "$src_unpack"
run_or_rollback "failed to extract source tarball" run_logged "source.extract" tar -xzf "$source_tgz" -C "$src_unpack"
source_root="$(find "$src_unpack" -mindepth 1 -maxdepth 1 -type d | head -n 1)"
[[ -n "$source_root" ]] || rollback_and_fail "release tarball extraction produced no source root"

preserve_env="$TMP_DIR/preserve.env"
preserve_cfg="$TMP_DIR/preserve.config.yaml"
[[ -f "$INSTALL_DIR/.env" ]] && cp "$INSTALL_DIR/.env" "$preserve_env"
[[ -f "$INSTALL_DIR/config.yaml" ]] && cp "$INSTALL_DIR/config.yaml" "$preserve_cfg"

sync_tar="$TMP_DIR/source-sync.tar"
run_or_rollback "failed packing source sync archive" run_logged "sync.pack" tar --exclude='./data' --exclude='./.venv' --exclude='./.env' --exclude='./config.yaml' -cf "$sync_tar" -C "$source_root" .
run_or_rollback "failed applying source sync archive" run_logged "sync.apply" tar -xf "$sync_tar" -C "$INSTALL_DIR"

[[ -f "$preserve_env" ]] && cp "$preserve_env" "$INSTALL_DIR/.env"
[[ -f "$preserve_cfg" ]] && cp "$preserve_cfg" "$INSTALL_DIR/config.yaml"

agent_new="$TMP_DIR/uptimemesh-agent.new"
run_or_rollback "go agent build failed" run_logged "go.build" bash -lc "cd '$INSTALL_DIR' && go build -trimpath -ldflags '-s -w' -o '$agent_new' ./agent/cmd/uptimemesh-agent"
run_or_rollback "failed staging new agent binary" run_logged "agent.stage" install -m 0755 "$agent_new" "${BIN_PATH}.new"
run_or_rollback "failed swapping new agent binary" run_logged "agent.swap" mv "${BIN_PATH}.new" "$BIN_PATH"

if [[ ! -x "$INSTALL_DIR/.venv/bin/pip" ]]; then
  run_or_rollback "failed creating python venv" run_logged "venv.create" python3 -m venv "$INSTALL_DIR/.venv"
fi
run_or_rollback "pip upgrade failed" run_logged "pip.upgrade" "$INSTALL_DIR/.venv/bin/pip" install --upgrade pip
run_or_rollback "pip install failed" run_logged "pip.install" "$INSTALL_DIR/.venv/bin/pip" install -e "$INSTALL_DIR"
run_or_rollback "database migration failed" run_logged "db.migrate" bash -lc "cd '$INSTALL_DIR' && ./.venv/bin/alembic upgrade head"

normalize_log_paths

printf '%s\n' "$LATEST_VERSION" >"$INSTALL_DIR/VERSION"

if command -v systemctl >/dev/null 2>&1; then
  systemctl daemon-reload || true
  run_or_rollback "failed restarting uptime-mesh.service" run_logged "service.restart.api" systemctl restart uptime-mesh.service
  if service_exists uptime-mesh-agent.service; then
    run_or_rollback "failed restarting uptime-mesh-agent.service" run_logged "service.restart.agent" systemctl restart uptime-mesh-agent.service
  else
    warn "skipping agent restart (unit not present)"
  fi
fi

if wait_for_health "$HEALTH_URL"; then
  write_state "success" "$LATEST_VERSION" "$PREVIOUS_VERSION"
  prune_old_backups
  log "update complete | from: ${PREVIOUS_VERSION:-unknown} | to: $LATEST_VERSION"
  exit 0
fi

rollback_and_fail "health gate timed out (${HEALTH_TIMEOUT_SECONDS}s)"
