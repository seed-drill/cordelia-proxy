#!/usr/bin/env bash
# ===============================================================
# Cordelia Backup Cron Wrapper
# ===============================================================
#
# Cron runs with a minimal environment -- no shell profile, no
# env vars. This wrapper sources the encryption key before
# invoking the backup script.
#
# Key source: ~/.cordelia-env (mode 0600, not in git)
#
# File format of ~/.cordelia-env:
#   export CORDELIA_ENCRYPTION_KEY="<64-char-hex>"
#
# CRONTAB ENTRY:
#   0 * * * * /Users/russellwing/cordelia/scripts/backup-cron-wrapper.sh
#
# ===============================================================

set -euo pipefail

ENV_FILE="$HOME/.cordelia-env"

if [[ ! -f "$ENV_FILE" ]]; then
    echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) ERROR: $ENV_FILE not found" >> /Users/russellwing/cordelia/logs/backup-memory.log
    exit 1
fi

# shellcheck source=/dev/null
source "$ENV_FILE"

exec /Users/russellwing/cordelia/scripts/backup-memory-db.sh
