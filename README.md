<p><img src="docs/logo.svg" alt="Cordelia" width="48" height="42"></p>

# Cordelia Proxy

[![CI](https://github.com/seed-drill/cordelia-proxy/actions/workflows/ci.yml/badge.svg)](https://github.com/seed-drill/cordelia-proxy/actions/workflows/ci.yml)

TypeScript MCP server, dashboard, and REST API for Cordelia.

> **Looking to install Cordelia?** Go to **[cordelia-agent-sdk](https://github.com/seed-drill/cordelia-agent-sdk)** -- that's the front door.

## What This Is

This repo contains the MCP proxy server that Claude Code talks to. It handles memory storage (SQLite), encryption (AES-256-GCM), search, groups, and the web dashboard.

## What This Is NOT

This is not where you install Cordelia from. Install, hooks, skills, and setup have moved to **[cordelia-agent-sdk](https://github.com/seed-drill/cordelia-agent-sdk)**.

## Architecture

```
Claude Code --> cordelia-agent-sdk (hooks) --> cordelia-proxy (MCP/HTTP) --> cordelia-node (Rust, QUIC)
```

```
Memory Layers:
  L0: Session Buffer    (ephemeral, current conversation)
  L1: Hot Context       (loaded at session start, ~50KB)
  L2: Warm Index        (searchable, pulled on demand, ~5MB)
  L3: Cold Archive      (compressed, rarely accessed)
```

L2 items can be private (entity-only), group-scoped (membership-gated), or public. Sharing uses copy-on-write -- originals are never modified, preserving entity sovereignty.

### Security

L2 items are encrypted at rest using AES-256-GCM with scrypt key derivation. Embeddings are stripped from the persisted index and regenerated on-demand to prevent semantic fingerprint leakage.

## Installation

**For end users:** Use the SDK installer:

```bash
curl -fsSL https://seeddrill.ai/install.sh | sh -s -- <your-username>
```

See **[cordelia-agent-sdk](https://github.com/seed-drill/cordelia-agent-sdk)** for full instructions.

## Configuration

### Claude Code MCP Settings

The installer automatically configures `~/.claude.json` (global MCP config):

```json
{
  "mcpServers": {
    "cordelia": {
      "command": "node",
      "args": ["/path/to/cordelia-proxy/dist/server.js"],
      "env": {
        "CORDELIA_STORAGE": "node",
        "CORDELIA_MEMORY_ROOT": "~/.cordelia/memory"
      }
    }
  }
}
```

The encryption key is **not** stored in MCP config or shell profiles. It is retrieved at runtime from the platform keychain (macOS Keychain / Linux GNOME Keyring) or `~/.cordelia/key`. See [docs/KEY-MANAGEMENT.md](docs/KEY-MANAGEMENT.md) for details.

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `CORDELIA_ENCRYPTION_KEY` | Passphrase for L2 encryption | (none - encryption disabled) |
| `CORDELIA_ENCRYPTION_ENABLED` | Explicit enable/disable | `true` if key provided |
| `CORDELIA_EMBEDDING_PROVIDER` | Embedding provider: `ollama`, `openai`, `none` | `ollama` |
| `CORDELIA_EMBEDDING_URL` | Embedding API URL | `http://localhost:11434` |
| `CORDELIA_EMBEDDING_MODEL` | Embedding model name | `nomic-embed-text` |
| `CORDELIA_STORAGE` | Storage backend: `sqlite`, `json` (legacy) | `sqlite` |
| `CORDELIA_TTL_SWEEP_INTERVAL_MS` | Interval for TTL expiry sweep (ms) | `3600000` |

## Available MCP Tools

### L1 Hot Context

| Tool | Description |
|------|-------------|
| `memory_read_hot` | Read L1 hot context for a user |
| `memory_write_hot` | Write/patch L1 hot context with optimistic concurrency |
| `memory_status` | Get memory system status and encryption state |

### L2 Warm Index

| Tool | Description |
|------|-------------|
| `memory_search` | Search L2 by keyword, type, tags |
| `memory_read_warm` | Read a specific L2 item by ID |
| `memory_write_warm` | Create/update entities, sessions, or learnings |
| `memory_delete_warm` | Delete a specific L2 item by ID |

### Groups

| Tool | Description |
|------|-------------|
| `memory_share` | Share a private memory to a group (COW copy) |
| `memory_group_create` | Create a new group (creator becomes owner) |
| `memory_group_list` | List groups |
| `memory_group_read` | Read group details |
| `memory_group_add_member` | Add entity to group |
| `memory_group_remove_member` | Remove entity from group |

### Analysis + Operations

| Tool | Description |
|------|-------------|
| `memory_analyze_novelty` | Detect novelty signals for persistence decisions |
| `memory_backup` | Export memory to backup directory |
| `memory_restore` | Restore from backup with integrity verification |

## Session Hooks

Session hooks have moved to **[cordelia-agent-sdk](https://github.com/seed-drill/cordelia-agent-sdk)**. The SDK hooks resolve this proxy via `getProxyDir()` in `hooks/lib.mjs`.

## Development

```bash
npm run dev      # Run with ts-node
npm run build    # Compile TypeScript
npm start        # Run compiled server
npm test         # Run all tests
npm run lint     # ESLint
npm run typecheck # tsc --noEmit
npm run ci       # Full pipeline: lint + typecheck + test + audit + build
```

## Related Repos

- [cordelia-agent-sdk](https://github.com/seed-drill/cordelia-agent-sdk) -- **Start here.** Install, hooks, skills, agent spec
- [cordelia-core](https://github.com/seed-drill/cordelia-core) -- Rust P2P node, protocol, replication, governor
- [cordelia](https://github.com/seed-drill/cordelia) -- Archived monorepo (full git history)

## License

AGPL-3.0 -- Copyright (c) 2026 Seed Drill

See [LICENSE](LICENSE) for full text.

## Community

- **Slack:** https://join.slack.com/t/seeddrill/shared_invite/zt-3op96zqna-Y3OqZfUHsjQpHz~F8a~DPA
