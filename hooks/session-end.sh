#!/bin/bash
# Cordelia SessionEnd Hook - Update ephemeral memory via MCP

HOOK_DIR="$(cd "$(dirname "$0")" && pwd)"

# Source encryption key from seed-drill .mcp.json
MCP_JSON="$HOME/seed-drill/.mcp.json"
if [ -f "$MCP_JSON" ]; then
  export CORDELIA_ENCRYPTION_KEY=$(jq -r '.mcpServers.cordelia.env.CORDELIA_ENCRYPTION_KEY // empty' "$MCP_JSON" 2>/dev/null)
fi

if [ -z "$CORDELIA_ENCRYPTION_KEY" ]; then
  exit 0
fi

# session-end.mjs reads user_id and memory_root from ~/.cordelia/config.toml
node "$HOOK_DIR/session-end.mjs"

exit 0
