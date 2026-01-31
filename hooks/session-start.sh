#!/bin/bash
# Cordelia SessionStart Hook - Load L1 hot context automatically
# stdout from SessionStart hooks is added to context

USER_ID="russell"
CORDELIA_DIR="$HOME/cordelia"

# Source encryption key from seed-drill .mcp.json
# This keeps the key in one place
MCP_JSON="$HOME/seed-drill/.mcp.json"
if [ -f "$MCP_JSON" ]; then
  export CORDELIA_ENCRYPTION_KEY=$(jq -r '.mcpServers.cordelia.env.CORDELIA_ENCRYPTION_KEY // empty' "$MCP_JSON" 2>/dev/null)
fi

if [ -z "$CORDELIA_ENCRYPTION_KEY" ]; then
  echo "Warning: CORDELIA_ENCRYPTION_KEY not found"
  exit 0
fi

echo "=== CORDELIA L1 HOT CONTEXT ==="
node "$CORDELIA_DIR/decrypt-l1.mjs" "$USER_ID" 2>/dev/null || echo '{"error": "decryption failed"}'
echo "=== END CORDELIA CONTEXT ==="

exit 0
