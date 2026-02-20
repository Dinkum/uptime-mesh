#!/usr/bin/env sh
# Backward-compatible wrapper.
exec "$(cd "$(dirname "$0")" && pwd)/agent-update.sh" "$@"
