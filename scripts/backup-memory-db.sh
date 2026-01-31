#!/usr/bin/env bash
# ===============================================================
# Cordelia Memory DB Backup + Key Escrow
# ===============================================================
#
# PURPOSE:
#   Backs up all Cordelia memory state (SQLite DB + JSON files)
#   to 3 geographically distributed servers, and escrows the
#   encryption key to each so memories can be decrypted from
#   any backup site after total local loss.
#
# SCHEDULE: Hourly cron job
#
# WHAT GETS BACKED UP:
#   1. cordelia.db        - SQLite database (via atomic .backup)
#   2. memory/            - JSON memory files (L1 hot, L2 warm)
#   3. .encryption-key    - CORDELIA_ENCRYPTION_KEY (mode 0600)
#
# BACKUP SERVERS (all on WireGuard mesh, no public exposure):
#   - dooku.skynet   (direct)  - Primary site 1
#   - rey.skynet     (direct)  - Primary site 2
#   - ren.skynet     (via dooku jump host) - Secondary site
#
# REMOTE LAYOUT (each server):
#   ~/cordelia/
#     cordelia.db            - SQLite database
#     .encryption-key        - Encryption key (0600, rezi owner)
#     memory/                - JSON memory files
#
# RECOVERY:
#   From any backup server:
#     1. Copy ~/cordelia/ to local machine
#     2. Export CORDELIA_ENCRYPTION_KEY=$(cat .encryption-key)
#     3. Start Cordelia MCP server
#   All 3 servers hold identical complete recovery state.
#
# SECURITY:
#   - Key transmitted over SSH (encrypted in transit)
#   - Key stored mode 0600 on each server (rezi owner only)
#   - All servers on WireGuard mesh (no public internet)
#   - Integrity > Confidentiality rationale: recovering
#     encrypted memories without the key = total loss.
#     Key distribution is the lesser risk. (2026-01-29)
#
# FUTURE HARDENING (R2+):
#   - Shamir secret sharing (n-of-m across servers)
#   - Hardware key storage / TPM
#   - Key rotation and re-encryption schedule
#
# REQUIRES: sqlite3, rsync, ssh, CORDELIA_ENCRYPTION_KEY env var
#
# The memories are the critical path -
# code can be regenerated from them, not vice versa.
# ===============================================================

set -euo pipefail

DB_PATH="/Users/russellwing/cordelia/memory/cordelia.db"
BACKUP_PATH="/Users/russellwing/cordelia/memory/cordelia-backup.db"
# Direct hosts (reachable from WireGuard)
DIRECT_HOSTS=("rezi@dooku.skynet" "rezi@rey.skynet")
# Jump hosts (routed via dooku - secondary site not directly reachable from WG range)
# TODO: Allow direct WG->ren routing, remove jump host workaround
JUMP_HOSTS=("rezi@ren.skynet")
JUMP_VIA="rezi@dooku.skynet"
REMOTE_DIR="~/cordelia"
KEY_FILE="$REMOTE_DIR/.encryption-key"
LOG="/Users/russellwing/cordelia/logs/backup-memory.log"

mkdir -p "$(dirname "$LOG")"

log() {
    echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) $1" >> "$LOG"
}

# Pre-flight: check DB exists
if [ ! -f "$DB_PATH" ]; then
    log "ERROR: Database not found at $DB_PATH"
    exit 1
fi

# Pre-flight: check encryption key is available
if [ -z "${CORDELIA_ENCRYPTION_KEY:-}" ]; then
    log "WARN: CORDELIA_ENCRYPTION_KEY not set - key escrow skipped"
fi

# Safe SQLite backup (handles WAL correctly - atomic consistent snapshot)
if sqlite3 "$DB_PATH" ".backup '$BACKUP_PATH'"; then
    SIZE=$(wc -c < "$BACKUP_PATH" | tr -d ' ')
    log "OK: SQLite backup created (${SIZE} bytes)"
else
    log "ERROR: SQLite backup failed"
    exit 1
fi

# ---------------------------------------------------------------
# KEY ESCROW
# ---------------------------------------------------------------
# Distributes CORDELIA_ENCRYPTION_KEY to each backup server so
# memories can be decrypted from any site after total local loss.
#
# Method: writes key to a local temp file (mode 0600), rsyncs to
# remote, then shreds the temp file. rsync is used rather than
# stdin piping because SSH consumes stdin during connection setup,
# which causes pipe-based approaches to deliver empty files.
#
# Integrity > Confidentiality rationale (2026-01-29):
#   Right now the priority is ensuring we can always recover and
#   decrypt backed-up memories. The key is transmitted over SSH
#   (encrypted in transit) and stored in a restricted file on each
#   server. All servers are on the WireGuard mesh -- no public
#   exposure. This is still subject to normal opsec regime.
#
# File layout on remote:
#   ~/cordelia/.encryption-key   (mode 0600, owner rezi)
#
# Future hardening (R2+):
#   - Shamir secret sharing across the 3 servers (n-of-m)
#   - Hardware key storage / TPM
#   - Rotate key and re-encrypt on schedule
# ---------------------------------------------------------------
escrow_key_to_host() {
    local HOST="$1"
    local JUMP="${2:-}"
    local RSYNC_SSH=""
    local SSH_CMD="ssh"
    if [ -n "$JUMP" ]; then
        RSYNC_SSH="-e ssh -J $JUMP"
        SSH_CMD="ssh -J $JUMP"
    fi

    if [ -z "${CORDELIA_ENCRYPTION_KEY:-}" ]; then
        return 0  # nothing to escrow
    fi

    # Write key to temp file with strict perms
    local TMP_KEY
    TMP_KEY=$(mktemp)
    chmod 600 "$TMP_KEY"
    printf '%s' "$CORDELIA_ENCRYPTION_KEY" > "$TMP_KEY"

    # Ensure remote dir exists
    if ! $SSH_CMD "$HOST" "mkdir -p ${REMOTE_DIR}" 2>>"$LOG"; then
        log "ERROR: Key escrow failed (mkdir) to ${HOST}"
        rm -f "$TMP_KEY"
        FAILED=$((FAILED + 1))
        return 1
    fi

    # Rsync key file to remote, then set perms
    local RSYNC_ARGS=("-az")
    if [ -n "$JUMP" ]; then
        RSYNC_ARGS+=("-e" "ssh -J $JUMP")
    fi
    if rsync "${RSYNC_ARGS[@]}" "$TMP_KEY" "${HOST}:${KEY_FILE}" 2>>"$LOG" && \
       $SSH_CMD "$HOST" "chmod 600 ${KEY_FILE}" 2>>"$LOG"; then
        log "OK: Encryption key escrowed to ${HOST}"
    else
        log "ERROR: Key escrow failed to ${HOST}"
        FAILED=$((FAILED + 1))
    fi

    # Clean up temp file
    rm -f "$TMP_KEY"
}

# Sync function: DB + JSON memories to a host, with optional jump
sync_to_host() {
    local HOST="$1"
    local RSYNC_OPTS="-az"
    local SSH_OPTS=""
    if [ -n "${2:-}" ]; then
        SSH_OPTS="-e 'ssh -J $2'"
    fi

    # Escrow encryption key first
    escrow_key_to_host "$HOST" "${2:-}"

    # Sync SQLite DB
    if eval rsync $RSYNC_OPTS $SSH_OPTS "$BACKUP_PATH" "${HOST}:${REMOTE_DIR}/cordelia.db" 2>>"$LOG"; then
        log "OK: Synced DB to ${HOST}"
    else
        log "ERROR: Failed to sync DB to ${HOST}"
        FAILED=$((FAILED + 1))
    fi

    # Sync JSON memory files
    if eval rsync $RSYNC_OPTS $SSH_OPTS /Users/russellwing/cordelia/memory/ "${HOST}:${REMOTE_DIR}/memory/" \
        --exclude="'cordelia.db'" \
        --exclude="'cordelia.db-wal'" \
        --exclude="'cordelia.db-shm'" \
        --exclude="'cordelia-backup.db'" 2>>"$LOG"; then
        log "OK: JSON memory synced to ${HOST}"
    else
        log "ERROR: JSON memory sync failed to ${HOST}"
        FAILED=$((FAILED + 1))
    fi
}

FAILED=0

# Direct hosts
for HOST in "${DIRECT_HOSTS[@]}"; do
    sync_to_host "$HOST"
done

# Jump hosts (via dooku)
for HOST in "${JUMP_HOSTS[@]}"; do
    sync_to_host "$HOST" "$JUMP_VIA"
done

if [ "$FAILED" -gt 0 ]; then
    log "WARN: ${FAILED} sync operations failed"
    exit 1
else
    log "OK: All backups complete (3 sites)"
fi
