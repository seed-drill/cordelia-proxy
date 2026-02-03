# Cordelia Proxy -- Claude Instructions

You have access to the Cordelia memory system via MCP tools. This gives you persistent memory across sessions.

## Available Tools

### Reading Memory
- `memory_read_hot` - Read L1 hot context (identity, preferences, current focus)
- `memory_search` - Search L2 warm index for entities, sessions, learnings
- `memory_read_warm` - Read specific L2 items by ID

### Writing Memory
- `memory_write_hot` - Update L1 context (use `operation: "patch"` for partial updates)
- `memory_write_warm` - Store entities, sessions, or learnings to L2
- `memory_analyze_novelty` - Analyze text for persistence-worthy content

## When to Use Memory

### Storing Information
When the user shares personal information (family, preferences, important context):
```
Use memory_write_hot with operation "patch" to update their identity or active context.
```

### Retrieving Information
The L1 hot context is loaded automatically at session start via hooks. Check the session startup message for current context.

For historical information, use `memory_search` to find relevant entities or learnings.

## Key Principles

1. **Patch, don't replace** - Use `operation: "patch"` to merge new data without overwriting existing context
2. **Be selective** - Only store information that's genuinely useful across sessions
3. **Respect privacy** - Memory is encrypted, but be thoughtful about what you store
4. **Session continuity** - Cordelia exists to make sessions feel continuous, not isolated

## Deprecated Files (moved to cordelia-agent-sdk)

The following files in this repo are **deprecated** and will be removed in a future release.
They remain temporarily so existing installs with proxy-based hook paths continue to work
until users re-run the installer (which migrates hooks to SDK paths).

- `install.sh` -- moved to cordelia-agent-sdk
- `setup.sh` -- moved to cordelia-agent-sdk
- `hooks/*` (11 files) -- moved to cordelia-agent-sdk/hooks/
- `skills/*` (3 dirs) -- moved to cordelia-agent-sdk/skills/
- `setup/*` (plist, service) -- moved to cordelia-agent-sdk/setup/
- `scripts/seed-l1.mjs` -- moved to cordelia-agent-sdk/scripts/
- `scripts/check-memory-health.mjs` -- moved to cordelia-agent-sdk/scripts/
- `scripts/backup-memory-db.sh` -- moved to cordelia-agent-sdk/scripts/
- `scripts/backup-cron-wrapper.sh` -- moved to cordelia-agent-sdk/scripts/

**Do not modify these files.** All changes should go to cordelia-agent-sdk instead.
Removal tracked in seed-drill BACKLOG under "Proxy deprecated file cleanup".

## Project Structure

TypeScript MCP server. Key source files in `src/`:

- `server.ts` -- MCP server entry point (stdio transport)
- `http-server.ts` -- Dashboard HTTP server
- `storage.ts` / `storage-sqlite.ts` / `storage-json.ts` -- Storage abstraction + backends
- `l2.ts` -- L2 warm index logic
- `crypto.ts` -- AES-256-GCM encryption
- `integrity.ts` -- Hash chain verification
- `novelty.ts` -- Novelty analysis heuristics
- `policy.ts` -- 5-rule policy engine
- `schema.ts` -- TypeScript schemas/types

## Build Commands

```bash
npm install          # Install dependencies
npm run build        # Compile TypeScript
npm test             # Run all tests
npm run lint         # ESLint
npm run typecheck    # tsc --noEmit
npm run ci           # Full pipeline
```

## Related Repo

The Rust P2P node lives in [cordelia-core](https://github.com/seed-drill/cordelia-core). See that repo for architecture docs, requirements, threat model, and protocol spec.

## MANDATORY: Memory Safety Principles

Memory is Cordelia's reason for existing. Treat it with the same criticality as a database engine treats user data.

### Cardinal Rules

1. **Truly paranoid about memory changes** - Any change to storage, schema, encryption, or indexing is treated as a high-risk operation. No exceptions.
2. **Every upgrade must have a recovery path** - Before any migration or schema change, verify you can roll back. If you can't roll back, don't proceed.
3. **Fail safe, not fail open** - If a memory operation fails, the system must preserve existing data. Never overwrite good data with potentially bad data. When in doubt, refuse the write.
4. **The index is derived data** - Items are the source of truth. The index can always be rebuilt from items via `npm run rebuild-index`. Never treat the index as authoritative.
5. **Test isolation is sacred** - Tests MUST NEVER touch production memory. This is not a guideline, it is an invariant. Violation caused INCIDENT-001.

### Recovery Tools

- `npm run rebuild-index` - Rebuild L2 search index from item files (requires `CORDELIA_ENCRYPTION_KEY`)
- `npm run migrate` - Migrate JSON files to SQLite (JSON files preserved as backup)
- JSON backup files in `memory/L2-warm/` are never deleted by migration

## MANDATORY: Memory Migration & Upgrade Testing

Any change to storage, schema, encryption, or indexing MUST follow the protocol below.
Failure to follow this caused a production incident on 2026-01-29 (index corruption, see INCIDENT-001.md).

### Pre-Migration Checklist

1. **Test isolation is absolute** - Tests MUST use temp directories. NEVER `initStorageProvider(memoryRoot)` with the real memory path. Audit every test file for real-path usage before merge.
2. **Snapshot before** - Record counts: L1 users, L2 entities, L2 learnings, L2 sessions, L2 index entries. Store as baseline.
3. **Verify encryption context** - Confirm which encryption key and storage backend (`CORDELIA_STORAGE`) the server is actually running. Check MCP config, not assumptions.
4. **Cross-key items** - Identify items encrypted with other users' keys (they will fail `auth tag mismatch`). These are expected failures, not data loss. Count them.

### Migration Execution

5. **Migrate index FROM items, not from index file** - The index is derived data. If it can be rebuilt from items, rebuild it. Never trust the existing index as source of truth during migration.
6. **Match storage backend** - Rebuild/migrate must target the SAME backend the server uses. Check `CORDELIA_STORAGE` env var in the MCP config (not shell env).
7. **Encrypt/decrypt round-trip** - After writing, immediately read back and verify decryption succeeds for every item.

### Post-Migration Verification

8. **Count comparison** - Compare post-migration counts against pre-migration baseline. Account for expected cross-key failures.
9. **Search verification** - Run searches for known real entities (not test data). Verify results include real items with correct names and types.
10. **Read verification** - Read at least 3 items by ID (one entity, one learning, one session) and verify full content is intact.
11. **Session persist test** - Write a test session summary and verify it survives a server restart.
12. **MCP tool verification** - Test via the actual MCP tools (`memory_search`, `memory_read_warm`), not just direct function calls. The MCP server may have different config.

### Test Suite Safeguards

13. **No production paths in tests** - Grep all test files for the real memory path before every release. Fail CI if found.
14. **Test cleanup** - Every test that creates items must delete them or use an isolated temp directory with cleanup.
15. **Index integrity check** - After test suite runs, verify the production index was not modified (compare hash before/after).
