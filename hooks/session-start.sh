#!/bin/bash
# Cordelia SessionStart Hook - Load L1 hot context via REST API
# stdout from SessionStart hooks is added to context

HOOK_DIR="$(cd "$(dirname "$0")" && pwd)"

# session-start.mjs reads user_id and memory_root from ~/.cordelia/config.toml
node "$HOOK_DIR/session-start.mjs"

exit 0
