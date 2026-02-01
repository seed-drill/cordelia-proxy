#!/bin/bash
# Cordelia PreCompact Hook - Flush insights before context compaction (R2-011)
# Reads transcript_path from stdin, passes to pre-compact.mjs

HOOK_DIR="$(cd "$(dirname "$0")" && pwd)"

# Source encryption key
MCP_JSON="$HOME/seed-drill/.mcp.json"
if [ -f "$MCP_JSON" ]; then
  export CORDELIA_ENCRYPTION_KEY=$(jq -r '.mcpServers.cordelia.env.CORDELIA_ENCRYPTION_KEY // empty' "$MCP_JSON" 2>/dev/null)
fi

if [ -z "$CORDELIA_ENCRYPTION_KEY" ]; then
  exit 0
fi

# Pass stdin through to node script
# pre-compact.mjs reads user_id and memory_root from ~/.cordelia/config.toml
node "$HOOK_DIR/pre-compact.mjs"

exit 0
