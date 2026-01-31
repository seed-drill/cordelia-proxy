#!/bin/bash
# Cordelia SessionEnd Hook - Update timestamp and auto-commit memory

USER_ID="russell"
MEMORY_FILE="$HOME/cordelia/memory/L1-hot/${USER_ID}.json"
CORDELIA_DIR="$HOME/cordelia"

if [ -f "$MEMORY_FILE" ]; then
  # Update the updated_at timestamp using jq
  TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
  jq --arg ts "$TIMESTAMP" '.updated_at = $ts' "$MEMORY_FILE" > "${MEMORY_FILE}.tmp"
  mv "${MEMORY_FILE}.tmp" "$MEMORY_FILE"
fi

# Auto-commit memory changes (sleep/wake model - memory persists automatically)
cd "$CORDELIA_DIR"
if git diff --quiet memory/ && git diff --cached --quiet memory/; then
  # No memory changes to commit
  exit 0
fi

git add memory/
git commit -m "chore: Auto-commit memory state

Co-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>" --no-verify 2>/dev/null || true

exit 0
