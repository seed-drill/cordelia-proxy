#!/bin/bash
#
# Cordelia Setup Script (Manual Version)
# Usage: ./setup.sh <user_id> [--no-embeddings] [encryption_key]
#
# For fully automated installation, use: ./install.sh
#
# This script:
# 1. Builds Cordelia
# 2. Generates encryption key
# 3. Creates user L1 context
# 4. Configures global MCP (~/.claude.json)
# 5. Outputs manual steps for hooks and shell config
#

set -e

CORDELIA_DIR="$(cd "$(dirname "$0")" && pwd)"
USER_ID=""
ENCRYPTION_KEY=""
NO_EMBEDDINGS=false

# OS detection
detect_os() {
    case "$(uname -s)" in
        Darwin) echo "macos" ;;
        Linux)  echo "linux" ;;
        *)      echo "unknown" ;;
    esac
    return 0
}

OS="$(detect_os)"

# Parse arguments
for arg in "$@"; do
    case $arg in
        --no-embeddings)
            NO_EMBEDDINGS=true
            ;;
        *)
            if [[ -z "$USER_ID" ]]; then
                USER_ID="$arg"
            elif [[ -z "$ENCRYPTION_KEY" ]]; then
                ENCRYPTION_KEY="$arg"
            fi
            ;;
    esac
done

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

info() { local msg="$1"; echo -e "${GREEN}[OK]${NC} $msg"; return 0; }
warn() { local msg="$1"; echo -e "${YELLOW}[WARN]${NC} $msg"; return 0; }
error() { local msg="$1"; echo -e "${RED}[ERROR]${NC} $msg" >&2; exit 1; }
step() { local msg="$1"; echo -e "${BLUE}[STEP]${NC} $msg"; return 0; }

# Check arguments
if [[ -z "$USER_ID" ]]; then
    echo "Cordelia Setup (Manual Version)"
    echo ""
    echo "Usage: ./setup.sh <user_id> [--no-embeddings] [encryption_key]"
    echo ""
    echo "For fully automated installation, use: ./install.sh <user_id>"
    echo ""
    echo "Options:"
    echo "  --no-embeddings    Disable semantic search (for Intel Macs)"
    echo ""
    echo "Examples:"
    echo "  ./setup.sh bill                       # Generate new key"
    echo "  ./setup.sh bill --no-embeddings       # Intel Mac, no Ollama"
    echo "  ./setup.sh bill 'existing-key'        # Use provided key"
    echo ""
    exit 1
fi

echo ""
echo "========================================"
echo "   Cordelia Setup for: $USER_ID"
echo "========================================"
echo ""

# Step 1: Check Node.js
step "Checking prerequisites..."
if ! command -v node &> /dev/null; then
    if [[ "$OS" = "linux" ]]; then
        error "Node.js is required but not installed. Install via: curl -fsSL https://deb.nodesource.com/setup_22.x | sudo -E bash - && sudo apt-get install -y nodejs"
    else
        error "Node.js is required but not installed. Install via: brew install node"
    fi
fi
info "Node.js: $(node --version)"

# Step 2: Install dependencies if needed
step "Installing dependencies..."
if [[ ! -d "$CORDELIA_DIR/node_modules" ]]; then
    cd "$CORDELIA_DIR" && npm install --silent
fi
info "Dependencies ready"

# Step 3: Build if needed
step "Building Cordelia..."
if [[ ! -d "$CORDELIA_DIR/dist" ]]; then
    cd "$CORDELIA_DIR" && npm run build --silent 2>/dev/null || npm run build
fi
info "Build ready"

# Step 4: Generate or use encryption key
step "Setting up encryption..."
if [[ -z "$ENCRYPTION_KEY" ]]; then
    ENCRYPTION_KEY=$(openssl rand -hex 32)
    info "Generated new 64-character hex key"
else
    # Validate provided key length
    KEY_LEN=${#ENCRYPTION_KEY}
    if [[ "$KEY_LEN" -ne 64 ]]; then
        warn "Provided key is $KEY_LEN chars, should be 64"
    fi
    info "Using provided encryption key"
fi

# Step 5: Configure global MCP (~/.claude.json)
step "Configuring global MCP server..."

GLOBAL_MCP="$HOME/.claude.json"

# Build the env object based on embeddings setting
if [[ "$NO_EMBEDDINGS" = true ]]; then
    ENV_JSON="{\"CORDELIA_ENCRYPTION_KEY\": \"$ENCRYPTION_KEY\", \"CORDELIA_EMBEDDING_PROVIDER\": \"none\"}"
else
    ENV_JSON="{\"CORDELIA_ENCRYPTION_KEY\": \"$ENCRYPTION_KEY\"}"
fi

# Use node to safely merge with existing config
node -e "
const fs = require('fs');
const globalMcp = '$GLOBAL_MCP';
const cordeliaDir = '$CORDELIA_DIR';
const envJson = $ENV_JSON;

let config = {};

// Load existing config if present
try {
    const content = fs.readFileSync(globalMcp, 'utf-8');
    config = JSON.parse(content);
} catch (e) {
    // File doesn't exist or invalid JSON, start fresh
}

// Ensure mcpServers structure exists
if (!config.mcpServers) config.mcpServers = {};

// Add/update cordelia server
config.mcpServers.cordelia = {
    command: 'node',
    args: [cordeliaDir + '/dist/server.js'],
    env: envJson
};

// Write config
fs.writeFileSync(globalMcp, JSON.stringify(config, null, 2));
"
info "Global MCP configured: ~/.claude.json"

# Step 6: Create L1 hot context for user
step "Creating L1 memory context..."
L1_DIR="$CORDELIA_DIR/memory/L1-hot"
L1_FILE="$L1_DIR/$USER_ID.json"

if [[ ! -f "$L1_FILE" ]] || [[ ! -s "$L1_FILE" ]]; then
    mkdir -p "$L1_DIR"

    # Capitalize first letter of user_id for name (portable method)
    USER_NAME="$(echo "${USER_ID:0:1}" | tr '[:lower:]' '[:upper:]')${USER_ID:1}"

    cat > "$L1_FILE" << EOF
{
  "version": 1,
  "updated_at": "$(date -u +"%Y-%m-%dT%H:%M:%S.000Z")",
  "identity": {
    "id": "${USER_ID}",
    "name": "${USER_NAME}",
    "roles": [],
    "orgs": [],
    "key_refs": [],
    "style": [],
    "tz": "Europe/London"
  },
  "active": {
    "project": null,
    "sprint": null,
    "focus": "Getting started with Cordelia",
    "blockers": [],
    "next": ["Explore Cordelia memory system", "Configure personal preferences"],
    "context_refs": [],
    "sprint_plan": {},
    "notes": ["Welcome to Cordelia - your AI memory system"]
  },
  "prefs": {
    "planning_mode": "important",
    "feedback_style": "continuous",
    "verbosity": "concise",
    "emoji": false,
    "proactive_suggestions": true,
    "auto_commit": false
  },
  "delegation": {
    "allowed": true,
    "max_parallel": 3,
    "require_approval": ["git_push", "destructive_operations", "external_api_calls", "file_delete"],
    "autonomous": ["file_read", "file_write", "git_commit", "code_execution_sandbox"]
  },
  "ephemeral": {
    "session_count": 0,
    "current_session_start": null,
    "last_session_end": null,
    "last_summary": null,
    "open_threads": [],
    "vessel": null,
    "integrity": null
  }
}
EOF
    info "Created L1 context: $USER_ID.json"
else
    warn "L1 context already exists for $USER_ID - not overwriting"
fi

# Step 7: Ensure salt directory exists
mkdir -p "$CORDELIA_DIR/memory/L2-warm/.salt"

# Step 8: Output manual steps
echo ""
echo "========================================"
echo "   Setup Complete - Manual Steps Below"
echo "========================================"
echo ""
if [[ "$OS" = "linux" ]]; then
    SUGGESTED_PROFILE="~/.bashrc"
else
    SUGGESTED_PROFILE="~/.zshrc"
fi
echo "1. Add encryption key to your shell profile ($SUGGESTED_PROFILE):"
echo ""
echo "   export CORDELIA_ENCRYPTION_KEY=\"$ENCRYPTION_KEY\""
echo ""
echo "2. Add hooks to Claude Code settings (~/.claude/settings.json):"
echo ""
echo "   {
     \"hooks\": {
       \"SessionStart\": [{
         \"matcher\": \"\",
         \"hooks\": [{
           \"type\": \"command\",
           \"command\": \"$CORDELIA_DIR/hooks/session-start.mjs $USER_ID\",
           \"timeout\": 10
         }]
       }],
       \"SessionEnd\": [{
         \"matcher\": \"\",
         \"hooks\": [{
           \"type\": \"command\",
           \"command\": \"$CORDELIA_DIR/hooks/session-end.mjs $USER_ID\",
           \"timeout\": 10
         }]
       }]
     }
   }"
echo ""
echo "3. Open a NEW terminal and run 'claude' from any directory"
echo ""
echo "IMPORTANT: Save this encryption key somewhere safe!"
echo ""
echo "  $ENCRYPTION_KEY"
echo ""
echo "If you lose it, your memory cannot be recovered."
echo ""
echo "Tip: For fully automated setup, use ./install.sh instead"
echo "========================================"
echo ""
