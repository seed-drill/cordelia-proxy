#!/bin/bash
# Cordelia SessionEnd Hook - Update ephemeral memory via REST API

HOOK_DIR="$(cd "$(dirname "$0")" && pwd)"

# session-end.mjs reads user_id and memory_root from ~/.cordelia/config.toml
node "$HOOK_DIR/session-end.mjs"

exit 0
