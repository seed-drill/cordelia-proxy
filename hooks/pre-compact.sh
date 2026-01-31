#!/bin/bash
# Cordelia PreCompact Hook - Flush insights before context compaction (R2-011)
# Reads transcript_path from stdin, passes to pre-compact.mjs

USER_ID="russell"
CORDELIA_DIR="$HOME/cordelia"

# Source encryption key
MCP_JSON="$HOME/seed-drill/.mcp.json"
if [ -f "$MCP_JSON" ]; then
  export CORDELIA_ENCRYPTION_KEY=$(jq -r '.mcpServers.cordelia.env.CORDELIA_ENCRYPTION_KEY // empty' "$MCP_JSON" 2>/dev/null)
fi

if [ -z "$CORDELIA_ENCRYPTION_KEY" ]; then
  exit 0
fi

# Pass stdin through to node script
node "$CORDELIA_DIR/hooks/pre-compact.mjs" "$USER_ID"

exit 0
