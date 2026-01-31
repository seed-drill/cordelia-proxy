#!/bin/bash
#
# Cordelia One-Click Installer
# Usage: ./install.sh <user_id> [--no-embeddings]
#
# Does EVERYTHING:
# 1. Checks/installs prerequisites
# 2. Builds Cordelia
# 3. Generates encryption key
# 4. Creates user L1 context
# 5. Configures Claude Code MCP (global ~/.claude.json)
# 6. Configures Claude Code hooks (global ~/.claude/settings.json)
# 7. Installs Cordelia skills (/persist, /sprint, /remember)
# 8. Sets up shell environment
# 9. Validates installation
#

set -e

CORDELIA_DIR="$(cd "$(dirname "$0")" && pwd)"
USER_ID=""
NO_EMBEDDINGS=false

# OS detection
detect_os() {
    case "$(uname -s)" in
        Darwin) echo "macos" ;;
        Linux)  echo "linux" ;;
        *)      echo "unknown" ;;
    esac
}

OS="$(detect_os)"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

info() { echo -e "${GREEN}[OK]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }
step() { echo -e "${BLUE}[STEP]${NC} $1"; }

# Parse arguments
for arg in "$@"; do
    case $arg in
        --no-embeddings)
            NO_EMBEDDINGS=true
            ;;
        --help|-h)
            echo "Cordelia One-Click Installer"
            echo ""
            echo "Usage: ./install.sh <user_id> [--no-embeddings]"
            echo ""
            echo "Options:"
            echo "  --no-embeddings    Skip Ollama (Intel Macs, simpler setup)"
            echo ""
            echo "Examples:"
            echo "  ./install.sh bill"
            echo "  ./install.sh bill --no-embeddings"
            exit 0
            ;;
        *)
            if [ -z "$USER_ID" ]; then
                USER_ID="$arg"
            fi
            ;;
    esac
done

if [ -z "$USER_ID" ]; then
    echo "Cordelia One-Click Installer"
    echo ""
    echo "Usage: ./install.sh <user_id> [--no-embeddings]"
    echo ""
    echo "Example: ./install.sh bill"
    exit 1
fi

echo ""
echo "========================================"
echo "   Cordelia Memory System Installer"
echo "========================================"
echo ""
echo "Installing for user: $USER_ID"
[ "$NO_EMBEDDINGS" = true ] && echo "Mode: No embeddings (Intel Mac compatible)"
echo ""

# ============================================
# Step 1: Check prerequisites
# ============================================
step "Checking prerequisites..."

# Check for Node.js (platform-aware install)
if ! command -v node &> /dev/null; then
    warn "Node.js not found. Installing..."
    if [ "$OS" = "macos" ]; then
        if ! command -v brew &> /dev/null; then
            warn "Homebrew not found. Required for installing Node.js on macOS."
            echo ""
            read -p "Install Homebrew now? [y/N] " -n 1 -r
            echo ""
            if [[ $REPLY =~ ^[Yy]$ ]]; then
                /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
                info "Homebrew installed"
            else
                error "Homebrew is required. Install manually from https://brew.sh or install Node.js another way."
            fi
        fi
        brew install node
    elif [ "$OS" = "linux" ]; then
        curl -fsSL https://deb.nodesource.com/setup_22.x | sudo -E bash -
        sudo apt-get install -y nodejs
    else
        error "Unsupported OS: $(uname -s). Supported: macOS, Linux."
    fi
    info "Node.js installed"
else
    info "Node.js $(node --version)"
fi

# Check for Claude Code (with Linux npm fallback)
if ! command -v claude &> /dev/null; then
    if [ "$OS" = "linux" ]; then
        warn "Claude Code not found. Installing via npm..."
        npm install -g @anthropic-ai/claude-code
        if command -v claude &> /dev/null; then
            info "Claude Code installed via npm"
        else
            error "Claude Code installation failed. Install manually: npm install -g @anthropic-ai/claude-code"
        fi
    else
        error "Claude Code not found. Please install from: https://claude.ai/download"
    fi
else
    info "Claude Code found"
fi

# ============================================
# Step 2: Build Cordelia
# ============================================
step "Building Cordelia..."

cd "$CORDELIA_DIR"

if [ ! -d "node_modules" ]; then
    npm install --silent
fi
info "Dependencies installed"

npm run build --silent 2>/dev/null || npm run build
info "TypeScript compiled"

# ============================================
# Step 3: Generate encryption key
# ============================================
step "Setting up encryption..."

ENCRYPTION_KEY=$(openssl rand -hex 32)
info "Generated 64-character hex encryption key"

# ============================================
# Step 4: Configure global MCP (~/.claude.json)
# ============================================
step "Configuring global MCP server..."

GLOBAL_MCP="$HOME/.claude.json"

# Build the env object based on embeddings setting
if [ "$NO_EMBEDDINGS" = true ]; then
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
console.log('Global MCP configured: ' + globalMcp);
"
info "Cordelia MCP server configured globally"

# ============================================
# Step 5: Create L1 context for user
# ============================================
step "Creating memory for $USER_ID..."

L1_DIR="$CORDELIA_DIR/memory/L1-hot"
L1_FILE="$L1_DIR/$USER_ID.json"
mkdir -p "$L1_DIR"

if [ ! -f "$L1_FILE" ] || [ ! -s "$L1_FILE" ]; then
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
  }
}
EOF
    info "Created L1 context: $USER_ID.json"
else
    info "L1 context already exists for $USER_ID"
fi

# Generate default node config with bootnodes (if cordelia-node is installed)
NODE_CONFIG_DIR="$HOME/.cordelia"
NODE_CONFIG="$NODE_CONFIG_DIR/config.toml"
mkdir -p "$NODE_CONFIG_DIR"
if [ ! -f "$NODE_CONFIG" ]; then
    cat > "$NODE_CONFIG" << NODEEOF
[node]
identity_key = "~/.cordelia/node.key"
api_transport = "http"
api_addr = "127.0.0.1:9473"
database = "~/.cordelia/cordelia.db"
entity_id = "${USER_ID}"

[network]
listen_addr = "0.0.0.0:9474"

[[network.bootnodes]]
addr = "boot1.cordelia.seeddrill.io:9474"

[[network.bootnodes]]
addr = "boot2.cordelia.seeddrill.io:9474"

[governor]
hot_min = 2
hot_max = 20
warm_min = 10
warm_max = 50

[replication]
sync_interval_moderate_secs = 300
tombstone_retention_days = 7
max_batch_size = 100
NODEEOF
    info "Generated node config with bootnodes: $NODE_CONFIG"
else
    info "Node config already exists: $NODE_CONFIG"
fi

# Ensure salt directory and file exist
SALT_DIR="$CORDELIA_DIR/memory/L2-warm/.salt"
SALT_FILE="$SALT_DIR/global.salt"
mkdir -p "$SALT_DIR"
if [ ! -f "$SALT_FILE" ]; then
    openssl rand -out "$SALT_FILE" 32
    info "Generated encryption salt"
fi

# ============================================
# Step 6: Configure Claude Code hooks
# ============================================
step "Configuring Claude Code session hooks..."

CLAUDE_DIR="$HOME/.claude"
SETTINGS_FILE="$CLAUDE_DIR/settings.json"

mkdir -p "$CLAUDE_DIR"

# Use node to safely merge hooks with existing settings
node -e "
const fs = require('fs');
const settingsFile = '$SETTINGS_FILE';
const cordeliaDir = '$CORDELIA_DIR';
const userId = '$USER_ID';

let settings = {};

// Load existing settings if present
try {
    const content = fs.readFileSync(settingsFile, 'utf-8');
    settings = JSON.parse(content);
} catch (e) {
    // File doesn't exist or invalid JSON, start fresh
}

// Ensure hooks structure exists
if (!settings.hooks) settings.hooks = {};
if (!settings.hooks.SessionStart) settings.hooks.SessionStart = [];
if (!settings.hooks.SessionEnd) settings.hooks.SessionEnd = [];

// Define Cordelia hooks
const startHook = {
    matcher: '',
    hooks: [{
        type: 'command',
        command: cordeliaDir + '/hooks/session-start.mjs ' + userId,
        timeout: 10
    }]
};

const endHook = {
    matcher: '',
    hooks: [{
        type: 'command',
        command: cordeliaDir + '/hooks/session-end.mjs ' + userId,
        timeout: 10
    }]
};

// Check if Cordelia hooks already exist (avoid duplicates)
const hasStartHook = settings.hooks.SessionStart.some(h =>
    h.hooks && h.hooks.some(hh => hh.command && hh.command.includes('cordelia'))
);
const hasEndHook = settings.hooks.SessionEnd.some(h =>
    h.hooks && h.hooks.some(hh => hh.command && hh.command.includes('cordelia'))
);

// Add hooks if not present
if (!hasStartHook) settings.hooks.SessionStart.push(startHook);
if (!hasEndHook) settings.hooks.SessionEnd.push(endHook);

// Write settings
fs.writeFileSync(settingsFile, JSON.stringify(settings, null, 2));
console.log('Hooks configured: ' + settingsFile);
"
info "Session hooks configured"

# ============================================
# Step 7: Install Cordelia skills
# ============================================
step "Installing Cordelia skills..."

SKILLS_SRC="$CORDELIA_DIR/skills"
SKILLS_DEST="$HOME/.claude/skills"

mkdir -p "$SKILLS_DEST"

# Copy skills and replace __USER_ID__ placeholder
for skill_dir in "$SKILLS_SRC"/*; do
    if [ -d "$skill_dir" ]; then
        skill_name=$(basename "$skill_dir")
        dest_dir="$SKILLS_DEST/$skill_name"
        mkdir -p "$dest_dir"

        for file in "$skill_dir"/*; do
            if [ -f "$file" ]; then
                # Replace __USER_ID__ with actual user_id
                sed "s/__USER_ID__/$USER_ID/g" "$file" > "$dest_dir/$(basename "$file")"
            fi
        done
    fi
done

info "Skills installed: persist, sprint, remember"

# ============================================
# Step 8: Set up shell environment
# ============================================
step "Setting up shell environment..."

# Detect shell profile (platform-aware defaults)
if [ "$OS" = "linux" ]; then
    # Linux: prefer .bashrc (most common default shell)
    if [ -f "$HOME/.bashrc" ]; then
        SHELL_PROFILE="$HOME/.bashrc"
    elif [ -f "$HOME/.zshrc" ]; then
        SHELL_PROFILE="$HOME/.zshrc"
    elif [ -f "$HOME/.bash_profile" ]; then
        SHELL_PROFILE="$HOME/.bash_profile"
    else
        SHELL_PROFILE="$HOME/.bashrc"
        touch "$SHELL_PROFILE"
    fi
else
    # macOS: prefer .zshrc (default since Catalina)
    if [ -f "$HOME/.zshrc" ]; then
        SHELL_PROFILE="$HOME/.zshrc"
    elif [ -f "$HOME/.bashrc" ]; then
        SHELL_PROFILE="$HOME/.bashrc"
    elif [ -f "$HOME/.bash_profile" ]; then
        SHELL_PROFILE="$HOME/.bash_profile"
    else
        SHELL_PROFILE="$HOME/.zshrc"
        touch "$SHELL_PROFILE"
    fi
fi

# Check if key already in profile
if ! grep -q "CORDELIA_ENCRYPTION_KEY" "$SHELL_PROFILE" 2>/dev/null; then
    echo "" >> "$SHELL_PROFILE"
    echo "# Cordelia Memory System" >> "$SHELL_PROFILE"
    echo "export CORDELIA_ENCRYPTION_KEY=\"$ENCRYPTION_KEY\"" >> "$SHELL_PROFILE"
    info "Added encryption key to $SHELL_PROFILE"
else
    warn "CORDELIA_ENCRYPTION_KEY already in $SHELL_PROFILE - not overwriting"
    warn "If you need to update the key, edit $SHELL_PROFILE manually"
fi

# Export for current session
export CORDELIA_ENCRYPTION_KEY="$ENCRYPTION_KEY"

# ============================================
# Step 9: Validate installation
# ============================================
step "Validating installation..."

ERRORS=0

[ -f "$CORDELIA_DIR/dist/server.js" ] && info "MCP server built" || { warn "MCP server missing"; ERRORS=$((ERRORS+1)); }
[ -f "$GLOBAL_MCP" ] && info "Global MCP config exists (~/.claude.json)" || { warn "Global MCP config missing"; ERRORS=$((ERRORS+1)); }
[ -f "$L1_FILE" ] && [ -s "$L1_FILE" ] && info "L1 context exists and non-empty" || { warn "L1 context missing or empty"; ERRORS=$((ERRORS+1)); }
[ -f "$SETTINGS_FILE" ] && info "Claude settings exist" || { warn "Claude settings missing"; ERRORS=$((ERRORS+1)); }
[ -d "$SKILLS_DEST/persist" ] && info "Skills installed" || { warn "Skills missing"; ERRORS=$((ERRORS+1)); }

# Verify key length
KEY_LEN=${#ENCRYPTION_KEY}
[ "$KEY_LEN" -eq 64 ] && info "Encryption key is correct length (64 chars)" || { warn "Encryption key wrong length: $KEY_LEN"; ERRORS=$((ERRORS+1)); }

if [ $ERRORS -gt 0 ]; then
    warn "Installation completed with $ERRORS warnings"
else
    info "All validations passed"
fi

# ============================================
# Done!
# ============================================
echo ""
echo "========================================"
echo "      Installation Complete!"
echo "========================================"
echo ""
echo "Cordelia is ready for: $USER_ID"
echo ""
echo "Configuration:"
echo "  MCP Server:  ~/.claude.json (global - works from any directory)"
echo "  Hooks:       ~/.claude/settings.json"
echo "  Skills:      ~/.claude/skills/ (persist, sprint, remember)"
echo "  Memory:      $CORDELIA_DIR/memory/L1-hot/$USER_ID.json"
echo ""
echo "Next steps:"
echo "  1. Open a NEW terminal window (to load the encryption key)"
echo "  2. Run 'claude' from any directory"
echo "  3. You should see: [CORDELIA] Session 1 | Genesis..."
echo ""
echo "IMPORTANT: Save this encryption key somewhere safe!"
echo ""
echo "  $ENCRYPTION_KEY"
echo ""
echo "If you lose it, your memory cannot be recovered."
echo ""
