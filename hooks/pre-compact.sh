#!/bin/bash
# Cordelia PreCompact Hook - Flush insights before context compaction (R2-011)
# Reads transcript_path from stdin, passes to pre-compact.mjs

HOOK_DIR="$(cd "$(dirname "$0")" && pwd)"

# Pass stdin through to node script
# pre-compact.mjs reads user_id and memory_root from ~/.cordelia/config.toml
node "$HOOK_DIR/pre-compact.mjs"

exit 0
