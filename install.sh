#!/bin/bash
#
# Cordelia Universal Installer
# Usage: curl -fsSL https://seeddrill.ai/install.sh | sh -s -- <user_id>
#    or: ./install.sh <user_id> [--no-embeddings]
#
# Phases:
#   1. Platform detection
#   2. Prerequisites (Node.js, Claude Code)
#   3. Download cordelia-node binary
#   4. Clone + build proxy
#   5. Generate credentials (encryption key, node identity)
#   6. Write config + seed L1
#   7. Configure Claude Code (MCP, hooks, skills)
#   8. Shell environment (~/.cordelia/bin to PATH)
#   9. Start node service (launchd / systemd)
#

set -e

# --- Constants ---

CORDELIA_HOME="$HOME/.cordelia"
CORDELIA_BIN="$CORDELIA_HOME/bin"
CORDELIA_LOGS="$CORDELIA_HOME/logs"
MEMORY_ROOT="$CORDELIA_HOME/memory"
GITHUB_REPO="seed-drill/cordelia-core"
PROXY_REPO="https://github.com/seed-drill/cordelia-proxy.git"

USER_ID=""
NO_EMBEDDINGS=false

# --- Colors ---

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

info()  { local msg="$1"; echo -e "${GREEN}[OK]${NC} $msg"; return 0; }
warn()  { local msg="$1"; echo -e "${YELLOW}[WARN]${NC} $msg"; return 0; }
error() { local msg="$1"; echo -e "${RED}[ERROR]${NC} $msg" >&2; exit 1; }
phase() {
    local num="$1"
    local label="$2"
    echo ""
    echo -e "${BLUE}--- Phase ${num}: ${label} ---${NC}"
    return 0
}

# --- Parse arguments ---

for arg in "$@"; do
    case $arg in
        --no-embeddings) NO_EMBEDDINGS=true ;;
        --help|-h)
            echo "Cordelia Universal Installer"
            echo ""
            echo "Usage: ./install.sh <user_id> [--no-embeddings]"
            echo "   or: curl -fsSL https://seeddrill.ai/install.sh | sh -s -- <user_id>"
            echo ""
            echo "Options:"
            echo "  --no-embeddings    Skip Ollama (Intel Macs, simpler setup)"
            exit 0
            ;;
        *)
            if [[ -z "$USER_ID" ]]; then
                USER_ID="$arg"
            fi
            ;;
    esac
done

if [[ -z "$USER_ID" ]]; then
    echo "Cordelia Universal Installer"
    echo ""
    echo "Usage: ./install.sh <user_id>"
    echo "   or: curl -fsSL https://seeddrill.ai/install.sh | sh -s -- <user_id>"
    exit 1
fi

echo ""
echo "========================================"
echo "   Cordelia Universal Installer"
echo "========================================"
echo ""
echo "Installing for user: $USER_ID"
[[ "$NO_EMBEDDINGS" = true ]] && echo "Mode: No embeddings (Intel Mac compatible)"
echo ""

# ============================================
# Phase 1: Platform detection
# ============================================
phase 1 "Platform detection"

OS="$(uname -s)"
ARCH="$(uname -m)"

case "$OS" in
    Darwin) OS_NAME="macos" ;;
    Linux)  OS_NAME="linux" ;;
    *)      error "Unsupported OS: $OS. Supported: macOS, Linux." ;;
esac

# Normalise arch
case "$ARCH" in
    x86_64|amd64)   ARCH_NAME="x86_64" ;;
    aarch64|arm64)   ARCH_NAME="aarch64" ;;
    *)               error "Unsupported architecture: $ARCH. Supported: x86_64, aarch64/arm64." ;;
esac

# Build target triple
case "${OS_NAME}-${ARCH_NAME}" in
    macos-x86_64)   TARGET="x86_64-apple-darwin" ;;
    macos-aarch64)  TARGET="aarch64-apple-darwin" ;;
    linux-x86_64)   TARGET="x86_64-unknown-linux-gnu" ;;
    linux-aarch64)  TARGET="aarch64-unknown-linux-gnu" ;;
    *)              error "Unsupported platform: ${OS_NAME}-${ARCH_NAME}" ;;
esac

info "Platform: $OS_NAME $ARCH_NAME -> $TARGET"

# ============================================
# Phase 2: Prerequisites
# ============================================
phase 2 "Prerequisites"

# Node.js
if ! command -v node &> /dev/null; then
    warn "Node.js not found. Installing..."
    if [[ "$OS_NAME" = "macos" ]]; then
        if ! command -v brew &> /dev/null; then
            warn "Homebrew not found. Required for Node.js on macOS."
            echo ""
            read -p "Install Homebrew now? [y/N] " -n 1 -r
            echo ""
            if [[ $REPLY =~ ^[Yy]$ ]]; then
                /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
                info "Homebrew installed"
            else
                error "Homebrew required. Install from https://brew.sh or install Node.js manually."
            fi
        fi
        brew install node
    elif [[ "$OS_NAME" = "linux" ]]; then
        curl -fsSL https://deb.nodesource.com/setup_22.x | sudo -E bash -
        sudo apt-get install -y nodejs
    fi
    info "Node.js installed"
else
    info "Node.js $(node --version)"
fi

# Claude Code
if ! command -v claude &> /dev/null; then
    if [[ "$OS_NAME" = "linux" ]]; then
        warn "Claude Code not found. Installing via npm..."
        sudo npm install -g @anthropic-ai/claude-code
        command -v claude &> /dev/null || error "Claude Code install failed. Install manually: npm install -g @anthropic-ai/claude-code"
        info "Claude Code installed via npm"
    else
        error "Claude Code not found. Install from: https://claude.ai/download"
    fi
else
    info "Claude Code found"
fi

# Git (needed for proxy clone)
command -v git &> /dev/null || error "git not found. Install git first."
info "git found"

# ============================================
# Phase 3: Download cordelia-node binary
# ============================================
phase 3 "Download cordelia-node binary"

mkdir -p "$CORDELIA_BIN" "$CORDELIA_LOGS"

BINARY_NAME="cordelia-node-${TARGET}"
BINARY_URL="https://github.com/${GITHUB_REPO}/releases/latest/download/${BINARY_NAME}"
CHECKSUM_URL="${BINARY_URL}.sha256"
BINARY_PATH="${CORDELIA_BIN}/cordelia-node"

if [[ -f "$BINARY_PATH" ]]; then
    info "cordelia-node already installed at $BINARY_PATH"
    info "Re-downloading to check for updates..."
fi

echo "Downloading cordelia-node for $TARGET..."
curl -fsSL -o "${CORDELIA_BIN}/${BINARY_NAME}" "$BINARY_URL" || error "Failed to download binary. Check https://github.com/${GITHUB_REPO}/releases"
curl -fsSL -o "${CORDELIA_BIN}/${BINARY_NAME}.sha256" "$CHECKSUM_URL" || error "Failed to download checksum."

# Verify SHA256
echo "Verifying checksum..."
cd "$CORDELIA_BIN"
if [[ "$OS_NAME" = "macos" ]]; then
    shasum -a 256 -c "${BINARY_NAME}.sha256" || error "Checksum verification failed. Binary may be corrupt."
else
    sha256sum -c "${BINARY_NAME}.sha256" || error "Checksum verification failed. Binary may be corrupt."
fi
cd - > /dev/null

cp "${CORDELIA_BIN}/${BINARY_NAME}" "$BINARY_PATH"
chmod +x "$BINARY_PATH"
rm -f "${CORDELIA_BIN}/${BINARY_NAME}" "${CORDELIA_BIN}/${BINARY_NAME}.sha256"

info "cordelia-node installed: $BINARY_PATH"

# ============================================
# Phase 4: Clone + build proxy
# ============================================
phase 4 "Clone + build proxy"

PROXY_DIR="$CORDELIA_HOME/proxy"

if [[ -d "$PROXY_DIR/.git" ]]; then
    info "Proxy already cloned at $PROXY_DIR"
    cd "$PROXY_DIR"
    git pull --ff-only 2>/dev/null || warn "Could not fast-forward proxy. Continuing with existing version."
else
    # Check if we're running from inside the proxy repo
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
    if [[ -f "$SCRIPT_DIR/package.json" ]] && grep -q '"cordelia-proxy"' "$SCRIPT_DIR/package.json" 2>/dev/null; then
        info "Running from proxy repo at $SCRIPT_DIR"
        PROXY_DIR="$SCRIPT_DIR"
    else
        echo "Cloning cordelia-proxy..."
        git clone "$PROXY_REPO" "$PROXY_DIR" || error "Failed to clone cordelia-proxy."
    fi
fi

cd "$PROXY_DIR"

if [[ ! -d "node_modules" ]]; then
    npm install --silent
fi
info "Dependencies installed"

npm run build --silent 2>/dev/null || npm run build
info "Proxy built"

# ============================================
# Phase 5: Generate credentials
# ============================================
phase 5 "Generate credentials"

# --- Encryption key ---
ENCRYPTION_KEY=$(openssl rand -hex 32)
info "Generated 64-character hex encryption key"

# Store in platform keychain (no plaintext in shell profile)
KEY_STORED=false

if [[ "$OS_NAME" = "macos" ]]; then
    # macOS Keychain
    if security add-generic-password -a cordelia -s cordelia-encryption-key -w "$ENCRYPTION_KEY" -U 2>/dev/null; then
        KEY_STORED=true
        info "Encryption key stored in macOS Keychain"
    else
        warn "Could not store key in Keychain"
    fi
elif [[ "$OS_NAME" = "linux" ]]; then
    # Linux: GNOME Keyring via secret-tool
    if command -v secret-tool &> /dev/null; then
        echo -n "$ENCRYPTION_KEY" | secret-tool store --label='Cordelia Encryption Key' service cordelia type encryption-key 2>/dev/null
        if [[ $? -eq 0 ]]; then
            KEY_STORED=true
            info "Encryption key stored in GNOME Keyring"
        else
            warn "Could not store key in GNOME Keyring"
        fi
    else
        warn "secret-tool not found (install libsecret-tools for keyring support)"
    fi
fi

# Fallback: file with restrictive permissions
if [[ "$KEY_STORED" = false ]]; then
    KEY_FILE="$CORDELIA_HOME/key"
    echo -n "$ENCRYPTION_KEY" > "$KEY_FILE"
    chmod 0600 "$KEY_FILE"
    info "Encryption key stored in $KEY_FILE (chmod 0600)"
fi

# --- Node identity key ---
if [[ -f "$CORDELIA_HOME/node.key" ]]; then
    info "Node identity key already exists"
else
    if "$BINARY_PATH" identity generate --output "$CORDELIA_HOME/node.key" 2>/dev/null; then
        info "Node identity key generated via cordelia-node"
    else
        # Fallback: generate ed25519 key with openssl
        openssl genpkey -algorithm ed25519 -out "$CORDELIA_HOME/node.key" 2>/dev/null
        chmod 0600 "$CORDELIA_HOME/node.key"
        info "Node identity key generated (openssl ed25519 fallback)"
    fi
fi

# ============================================
# Phase 6: Write config + seed L1
# ============================================
phase 6 "Write config + seed L1"

CORDELIA_CONFIG="$CORDELIA_HOME/config.toml"

if [[ ! -f "$CORDELIA_CONFIG" ]]; then
    cat > "$CORDELIA_CONFIG" << NODEEOF
# Cordelia configuration
# Generated by install.sh for user: ${USER_ID}

[identity]
user_id = "${USER_ID}"

[paths]
memory_root = "${MEMORY_ROOT}"

[node]
identity_key = "${CORDELIA_HOME}/node.key"
api_transport = "http"
api_addr = "127.0.0.1:9473"
database = "${CORDELIA_HOME}/cordelia.db"
entity_id = "${USER_ID}"

[network]
listen_addr = "0.0.0.0:9474"

[[network.bootnodes]]
addr = "boot1.cordelia.seeddrill.ai:9474"

[[network.bootnodes]]
addr = "boot2.cordelia.seeddrill.ai:9474"

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
    info "Generated config: $CORDELIA_CONFIG"
else
    info "Config already exists: $CORDELIA_CONFIG"
    # Fix stale bootnode addresses if present
    if grep -q 'seeddrill\.io' "$CORDELIA_CONFIG" 2>/dev/null; then
        sed -i.bak 's/seeddrill\.io/seeddrill.ai/g' "$CORDELIA_CONFIG"
        rm -f "${CORDELIA_CONFIG}.bak"
        info "Fixed bootnode addresses (.io -> .ai)"
    fi
    if grep -q 'moltbot' "$CORDELIA_CONFIG" 2>/dev/null; then
        sed -i.bak '/moltbot/d' "$CORDELIA_CONFIG"
        rm -f "${CORDELIA_CONFIG}.bak"
        info "Removed stale moltbot bootnode"
    fi
fi

# Ensure salt directory and file
SALT_DIR="$MEMORY_ROOT/L2-warm/.salt"
SALT_FILE="$SALT_DIR/global.salt"
mkdir -p "$SALT_DIR"
if [[ ! -f "$SALT_FILE" ]]; then
    openssl rand -out "$SALT_FILE" 32
    info "Generated encryption salt"
fi

# Seed L1 context
echo "Seeding L1 memory for $USER_ID..."
export CORDELIA_ENCRYPTION_KEY="$ENCRYPTION_KEY"
export CORDELIA_MEMORY_ROOT="$MEMORY_ROOT"
export CORDELIA_STORAGE=sqlite
[[ "$NO_EMBEDDINGS" = true ]] && export CORDELIA_EMBEDDING_PROVIDER=none
node "$PROXY_DIR/scripts/seed-l1.mjs" "$USER_ID"
info "L1 context seeded"

# ============================================
# Phase 7: Configure Claude Code
# ============================================
phase 7 "Configure Claude Code"

GLOBAL_MCP="$HOME/.claude.json"
CLAUDE_DIR="$HOME/.claude"
SETTINGS_FILE="$CLAUDE_DIR/settings.json"

mkdir -p "$CLAUDE_DIR"

# --- MCP server config (NO encryption key in env -- retrieved at runtime) ---
ENV_STORAGE="{\"CORDELIA_STORAGE\": \"sqlite\", \"CORDELIA_MEMORY_ROOT\": \"$MEMORY_ROOT\"}"
if [[ "$NO_EMBEDDINGS" = true ]]; then
    ENV_STORAGE="{\"CORDELIA_EMBEDDING_PROVIDER\": \"none\", \"CORDELIA_STORAGE\": \"sqlite\", \"CORDELIA_MEMORY_ROOT\": \"$MEMORY_ROOT\"}"
fi

node -e "
const fs = require('fs');
const globalMcp = '$GLOBAL_MCP';
const proxyDir = '$PROXY_DIR';
const envJson = $ENV_STORAGE;

let config = {};
try { config = JSON.parse(fs.readFileSync(globalMcp, 'utf-8')); } catch {}

if (!config.mcpServers) config.mcpServers = {};
config.mcpServers.cordelia = {
    command: 'node',
    args: [proxyDir + '/dist/server.js'],
    env: envJson
};

fs.writeFileSync(globalMcp, JSON.stringify(config, null, 2));
"
info "MCP server configured: $GLOBAL_MCP"

# --- Session hooks ---
node -e "
const fs = require('fs');
const settingsFile = '$SETTINGS_FILE';
const proxyDir = '$PROXY_DIR';

let settings = {};
try { settings = JSON.parse(fs.readFileSync(settingsFile, 'utf-8')); } catch {}

if (!settings.hooks) settings.hooks = {};
if (!settings.hooks.SessionStart) settings.hooks.SessionStart = [];
if (!settings.hooks.SessionEnd) settings.hooks.SessionEnd = [];

const startHook = {
    matcher: '',
    hooks: [{ type: 'command', command: proxyDir + '/hooks/session-start.mjs', timeout: 10 }]
};
const endHook = {
    matcher: '',
    hooks: [{ type: 'command', command: proxyDir + '/hooks/session-end.mjs', timeout: 10 }]
};

const hasStart = settings.hooks.SessionStart.some(h =>
    h.hooks && h.hooks.some(hh => hh.command && hh.command.includes('cordelia'))
);
const hasEnd = settings.hooks.SessionEnd.some(h =>
    h.hooks && h.hooks.some(hh => hh.command && hh.command.includes('cordelia'))
);

if (!hasStart) settings.hooks.SessionStart.push(startHook);
if (!hasEnd) settings.hooks.SessionEnd.push(endHook);

fs.writeFileSync(settingsFile, JSON.stringify(settings, null, 2));
"
info "Session hooks configured"

# --- Skills ---
SKILLS_SRC="$PROXY_DIR/skills"
SKILLS_DEST="$CLAUDE_DIR/skills"
mkdir -p "$SKILLS_DEST"

for skill_dir in "$SKILLS_SRC"/*; do
    if [[ -d "$skill_dir" ]]; then
        skill_name=$(basename "$skill_dir")
        dest_dir="$SKILLS_DEST/$skill_name"
        mkdir -p "$dest_dir"
        for file in "$skill_dir"/*; do
            if [[ -f "$file" ]]; then
                sed "s/__USER_ID__/$USER_ID/g" "$file" > "$dest_dir/$(basename "$file")"
            fi
        done
    fi
done
info "Skills installed: persist, sprint, remember"

# ============================================
# Phase 8: Shell environment
# ============================================
phase 8 "Shell environment"

# Add ~/.cordelia/bin to PATH (but NOT the encryption key)
if [[ "$OS_NAME" = "linux" ]]; then
    if [[ -f "$HOME/.bashrc" ]]; then
        SHELL_PROFILE="$HOME/.bashrc"
    elif [[ -f "$HOME/.zshrc" ]]; then
        SHELL_PROFILE="$HOME/.zshrc"
    else
        SHELL_PROFILE="$HOME/.bashrc"
        touch "$SHELL_PROFILE"
    fi
else
    if [[ -f "$HOME/.zshrc" ]]; then
        SHELL_PROFILE="$HOME/.zshrc"
    elif [[ -f "$HOME/.bashrc" ]]; then
        SHELL_PROFILE="$HOME/.bashrc"
    else
        SHELL_PROFILE="$HOME/.zshrc"
        touch "$SHELL_PROFILE"
    fi
fi

# Remove any existing CORDELIA_ENCRYPTION_KEY export (cleanup from old installs)
if grep -q "CORDELIA_ENCRYPTION_KEY" "$SHELL_PROFILE" 2>/dev/null; then
    # Remove the key line (no longer storing in shell profile)
    sed -i.bak '/CORDELIA_ENCRYPTION_KEY/d' "$SHELL_PROFILE"
    rm -f "${SHELL_PROFILE}.bak"
    warn "Removed plaintext encryption key from $SHELL_PROFILE (now stored in keychain)"
fi

# Add PATH entry for cordelia binaries
if ! grep -q 'cordelia/bin' "$SHELL_PROFILE" 2>/dev/null; then
    echo "" >> "$SHELL_PROFILE"
    echo "# Cordelia" >> "$SHELL_PROFILE"
    echo 'export PATH="$HOME/.cordelia/bin:$PATH"' >> "$SHELL_PROFILE"
    info "Added ~/.cordelia/bin to PATH in $SHELL_PROFILE"
else
    info "~/.cordelia/bin already in PATH"
fi

# Export for current session
export PATH="$CORDELIA_BIN:$PATH"

# ============================================
# Phase 9: Start node service
# ============================================
phase 9 "Start node service"

if [[ "$OS_NAME" = "macos" ]]; then
    # launchd
    PLIST_LABEL="ai.seeddrill.cordelia"
    PLIST_SRC="$PROXY_DIR/setup/ai.seeddrill.cordelia.plist"
    PLIST_DEST="$HOME/Library/LaunchAgents/${PLIST_LABEL}.plist"

    if [[ -f "$PLIST_SRC" ]]; then
        mkdir -p "$HOME/Library/LaunchAgents"
        # Substitute home directory in plist
        sed "s|__HOME__|$HOME|g" "$PLIST_SRC" > "$PLIST_DEST"

        # Unload if already loaded (ignore errors)
        launchctl bootout "gui/$(id -u)/${PLIST_LABEL}" 2>/dev/null || true

        launchctl bootstrap "gui/$(id -u)" "$PLIST_DEST" 2>/dev/null || launchctl load "$PLIST_DEST" 2>/dev/null
        info "cordelia-node registered with launchd ($PLIST_LABEL)"
        info "Logs: $CORDELIA_LOGS/"
    else
        warn "launchd plist not found at $PLIST_SRC -- skipping service install"
        echo "Start manually: cordelia-node --config $CORDELIA_HOME/config.toml"
    fi

elif [[ "$OS_NAME" = "linux" ]]; then
    # systemd user unit
    UNIT_SRC="$PROXY_DIR/setup/cordelia-node.service"
    UNIT_DIR="$HOME/.config/systemd/user"
    UNIT_DEST="$UNIT_DIR/cordelia-node.service"

    if [[ -f "$UNIT_SRC" ]]; then
        mkdir -p "$UNIT_DIR"
        sed "s|__HOME__|$HOME|g" "$UNIT_SRC" > "$UNIT_DEST"

        systemctl --user daemon-reload
        systemctl --user enable cordelia-node.service
        systemctl --user start cordelia-node.service
        info "cordelia-node enabled and started (systemd user unit)"
        info "Check status: systemctl --user status cordelia-node"
        info "Logs: journalctl --user -u cordelia-node -f"
    else
        warn "systemd unit not found at $UNIT_SRC -- skipping service install"
        echo "Start manually: cordelia-node --config $CORDELIA_HOME/config.toml"
    fi
fi

# ============================================
# Validate
# ============================================
echo ""
echo "--- Validation ---"
ERRORS=0

[[ -x "$BINARY_PATH" ]] && info "cordelia-node binary" || { warn "cordelia-node binary missing"; ERRORS=$((ERRORS+1)); }
[[ -f "$PROXY_DIR/dist/server.js" ]] && info "MCP proxy built" || { warn "MCP proxy missing"; ERRORS=$((ERRORS+1)); }
[[ -f "$GLOBAL_MCP" ]] && info "MCP config (~/.claude.json)" || { warn "MCP config missing"; ERRORS=$((ERRORS+1)); }
[[ -f "$SETTINGS_FILE" ]] && info "Claude hooks" || { warn "Claude hooks missing"; ERRORS=$((ERRORS+1)); }
[[ -d "$SKILLS_DEST/persist" ]] && info "Skills installed" || { warn "Skills missing"; ERRORS=$((ERRORS+1)); }
[[ -f "$CORDELIA_CONFIG" ]] && info "Node config" || { warn "Node config missing"; ERRORS=$((ERRORS+1)); }

CORDELIA_DB="$MEMORY_ROOT/cordelia.db"
[[ -f "$CORDELIA_DB" ]] && [[ -s "$CORDELIA_DB" ]] && info "L1 memory seeded" || { warn "L1 memory missing"; ERRORS=$((ERRORS+1)); }

KEY_LEN=${#ENCRYPTION_KEY}
[[ "$KEY_LEN" -eq 64 ]] && info "Encryption key valid (64 chars)" || { warn "Encryption key wrong length: $KEY_LEN"; ERRORS=$((ERRORS+1)); }

# Verify key NOT in shell profile
if grep -q "CORDELIA_ENCRYPTION_KEY" "$SHELL_PROFILE" 2>/dev/null; then
    warn "Encryption key still in shell profile -- remove manually"
    ERRORS=$((ERRORS+1))
else
    info "No plaintext key in shell profile"
fi

if [[ $ERRORS -gt 0 ]]; then
    warn "Completed with $ERRORS warnings"
else
    info "All validations passed"
fi

# ============================================
# Done
# ============================================
echo ""
echo "========================================"
echo "      Installation Complete!"
echo "========================================"
echo ""
echo "Cordelia is ready for: $USER_ID"
echo ""
echo "Layout:"
echo "  Binary:    ~/.cordelia/bin/cordelia-node"
echo "  Proxy:     $PROXY_DIR"
echo "  Config:    ~/.cordelia/config.toml"
echo "  Memory:    ~/.cordelia/memory/cordelia.db"
echo "  MCP:       ~/.claude.json"
echo "  Hooks:     ~/.claude/settings.json"
echo "  Skills:    ~/.claude/skills/ (persist, sprint, remember)"
echo ""
echo "Next steps:"
echo "  1. Open a NEW terminal (to pick up PATH changes)"
echo "  2. Run 'claude' from any directory"
echo "  3. You should see: [CORDELIA] Session 1 | Genesis..."
echo ""

if [[ "$KEY_STORED" = true ]]; then
    echo "Your encryption key is stored securely in the platform keychain."
else
    echo "IMPORTANT: Your encryption key is stored in ~/.cordelia/key"
    echo "Back it up somewhere safe. If you lose it, your memory cannot be recovered."
fi

echo ""
echo "Encryption key (save this):"
echo ""
echo "  $ENCRYPTION_KEY"
echo ""
