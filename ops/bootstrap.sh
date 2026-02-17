#!/usr/bin/env sh
# UptimeMesh Bootstrap Shim
# Intentionally tiny: fetch/update updater and hand off.

set -u

DEFAULT_VERSION_URL="https://raw.githubusercontent.com/your-org/uptime-mesh/main/version.json"
VERSION_URL="${VERSION_URL:-$DEFAULT_VERSION_URL}"
CHANNEL="${CHANNEL:-stable}"
INSTALL_DIR="${INSTALL_DIR:-/opt/uptimemesh}"
UPDATER_PATH="${UPDATER_PATH:-$INSTALL_DIR/node-update.sh}"

log() {
  printf '%s %s\n' "[bootstrap]" "$*"
}

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/uptimemesh-bootstrap.XXXXXX")" || exit 1
cleanup() { rm -rf "$TMP_DIR"; }
trap cleanup EXIT INT TERM

download() {
  src="$1"
  dst="$2"
  i=1
  while [ "$i" -le 3 ]; do
    if command -v curl >/dev/null 2>&1; then
      curl -fsSL --connect-timeout 10 --max-time 60 "$src" -o "$dst" && return 0
    elif command -v wget >/dev/null 2>&1; then
      wget -qO "$dst" "$src" && return 0
    fi
    sleep "$i"
    i=$((i + 1))
  done
  return 1
}

sha256() {
  f="$1"
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$f" | awk '{print $1}'; return 0; fi
  if command -v shasum >/dev/null 2>&1; then shasum -a 256 "$f" | awk '{print $1}'; return 0; fi
  if command -v openssl >/dev/null 2>&1; then openssl dgst -sha256 "$f" | awk '{print $NF}'; return 0; fi
  return 1
}

manifest="$TMP_DIR/version.json"
if download "$VERSION_URL" "$manifest"; then
  eval "$(
  python3 - "$manifest" "$VERSION_URL" "$CHANNEL" <<'PY'
import json
import shlex
import sys
from urllib.parse import urljoin

manifest_path, version_url, channel = sys.argv[1:4]
doc = json.load(open(manifest_path, "r", encoding="utf-8"))
cfg = doc.get("channels", {}).get(channel, doc) if isinstance(doc.get("channels"), dict) else doc
updater = cfg.get("updater", {})
url = str(updater.get("url", "")) or urljoin(version_url, str(updater.get("path", "")))
sha = str(updater.get("sha256", ""))
print(f"UPDATER_URL={shlex.quote(url)}")
print(f"UPDATER_SHA={shlex.quote(sha)}")
PY
  )"
  if [ -n "${UPDATER_URL:-}" ]; then
    mkdir -p "$INSTALL_DIR"
    updater_tmp="$TMP_DIR/node-update.sh"
    if download "$UPDATER_URL" "$updater_tmp"; then
      checksum_ok=1
      if [ -n "${UPDATER_SHA:-}" ]; then
        got="$(sha256 "$updater_tmp" || true)"
        if [ -z "$got" ] || [ "$got" != "$UPDATER_SHA" ]; then
          checksum_ok=0
          log "checksum mismatch for downloaded updater; using local fallback"
        fi
      fi
      if [ "$checksum_ok" -eq 1 ]; then
        install -m 0755 "$updater_tmp" "${UPDATER_PATH}.new" && mv "${UPDATER_PATH}.new" "$UPDATER_PATH"
      fi
    fi
  fi
fi

if [ -x "$UPDATER_PATH" ]; then
  log "handing off to updater: $UPDATER_PATH"
  exec "$UPDATER_PATH" --version-url "$VERSION_URL" --channel "$CHANNEL" "$@"
fi

log "no updater available; bootstrap cannot continue safely"
exit 1
