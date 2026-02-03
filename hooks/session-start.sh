#!/bin/bash
# Cordelia SessionStart Hook - Load L1 hot context via MCP
# stdout from SessionStart hooks is added to context

HOOK_DIR="$(cd "$(dirname "$0")" && pwd)"

# Source encryption key from seed-drill .mcp.json
MCP_JSON="$HOME/seed-drill/.mcp.json"
if [[ -f "$MCP_JSON" ]]; then
  export CORDELIA_ENCRYPTION_KEY=$(jq -r '.mcpServers.cordelia.env.CORDELIA_ENCRYPTION_KEY // empty' "$MCP_JSON" 2>/dev/null)
  export CORDELIA_STORAGE=$(jq -r '.mcpServers.cordelia.env.CORDELIA_STORAGE // "sqlite"' "$MCP_JSON" 2>/dev/null)
fi

if [[ -z "$CORDELIA_ENCRYPTION_KEY" ]]; then
  echo "Warning: CORDELIA_ENCRYPTION_KEY not found"
  exit 0
fi

# session-start.mjs reads user_id and memory_root from ~/.cordelia/config.toml
node "$HOOK_DIR/session-start.mjs"

exit 0
