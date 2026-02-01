/**
 * Project Cordelia - MCP Tool Handler Registry
 *
 * Extracted from CordeliaServer class so both stdio (server.ts) and HTTP
 * (http-server.ts) transports register identical tools from one source.
 */

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  ListResourcesRequestSchema,
  ReadResourceRequestSchema,
} from '@modelcontextprotocol/sdk/types.js';
import * as path from 'path';
import { L1HotContextSchema, GroupCultureSchema, type L1HotContext } from './schema.js';
import { analyzeNovelty, analyzeSession, filterForPersistence, type NoveltyResult } from './novelty.js';
import * as l2 from './l2.js';
import {
  getDefaultCryptoProvider,
  isEncryptedPayload,
  type EncryptedPayload,
} from './crypto.js';
import { getStorageProvider } from './storage.js';

// --- Module-level state (effectively singletons, previously on CordeliaServer) ---

const hotContextCache: Map<string, L1HotContext> = new Map();
let encryptionEnabled = false;

interface AuditEntry {
  ts: string;
  user: string;
  op: 'patch' | 'replace';
  path: string;
  old: unknown;
  new: unknown;
}

// --- Helpers ---

/**
 * Deep merge two objects. Arrays are replaced, not concatenated.
 */
function deepMerge(target: Record<string, unknown>, source: Record<string, unknown>): Record<string, unknown> {
  const result = { ...target };

  for (const key of Object.keys(source)) {
    const sourceVal = source[key];
    const targetVal = target[key];

    if (
      sourceVal !== null &&
      typeof sourceVal === 'object' &&
      !Array.isArray(sourceVal) &&
      targetVal !== null &&
      typeof targetVal === 'object' &&
      !Array.isArray(targetVal)
    ) {
      result[key] = deepMerge(targetVal as Record<string, unknown>, sourceVal as Record<string, unknown>);
    } else {
      result[key] = sourceVal;
    }
  }

  return result;
}

/**
 * Compute changed paths between two objects for audit logging.
 */
function computeChanges(
  oldObj: Record<string, unknown>,
  newObj: Record<string, unknown>,
  prefix = ''
): Array<{ path: string; old: unknown; new: unknown }> {
  const changes: Array<{ path: string; old: unknown; new: unknown }> = [];

  const allKeys = new Set([...Object.keys(oldObj), ...Object.keys(newObj)]);

  for (const key of allKeys) {
    const fullPath = prefix ? `${prefix}.${key}` : key;
    const oldVal = oldObj[key];
    const newVal = newObj[key];

    if (JSON.stringify(oldVal) !== JSON.stringify(newVal)) {
      if (
        oldVal !== null &&
        typeof oldVal === 'object' &&
        !Array.isArray(oldVal) &&
        newVal !== null &&
        typeof newVal === 'object' &&
        !Array.isArray(newVal)
      ) {
        changes.push(
          ...computeChanges(oldVal as Record<string, unknown>, newVal as Record<string, unknown>, fullPath)
        );
      } else {
        changes.push({ path: fullPath, old: oldVal, new: newVal });
      }
    }
  }

  return changes;
}

// --- L1 Context Operations ---

async function loadHotContext(
  userId: string,
  bypassCache = false,
  skipValidation = false
): Promise<L1HotContext | null> {
  if (!bypassCache && hotContextCache.has(userId)) {
    return hotContextCache.get(userId)!;
  }

  try {
    const storage = getStorageProvider();
    const buffer = await storage.readL1(userId);

    if (!buffer) {
      return null;
    }

    let parsed = JSON.parse(buffer.toString('utf-8'));

    if (isEncryptedPayload(parsed)) {
      const cryptoProvider = getDefaultCryptoProvider();
      if (!cryptoProvider.isUnlocked()) {
        throw new Error('Cannot read encrypted L1 context: encryption not configured');
      }
      const decrypted = await cryptoProvider.decrypt(parsed as EncryptedPayload);
      parsed = JSON.parse(decrypted.toString('utf-8'));
    }

    if (skipValidation) {
      return parsed as L1HotContext;
    }

    const validated = L1HotContextSchema.parse(parsed);
    hotContextCache.set(userId, validated);
    return validated;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') {
      return null;
    }
    throw error;
  }
}

async function appendAudit(entries: AuditEntry[]): Promise<void> {
  if (entries.length === 0) return;

  const storage = getStorageProvider();
  for (const entry of entries) {
    await storage.appendAudit(JSON.stringify(entry));
  }
}

async function writeHotContext(
  userId: string,
  operation: 'patch' | 'replace',
  data: Record<string, unknown>,
  expectedUpdatedAt?: string
): Promise<{ success: true; updated_at: string } | { error: string; current_updated_at?: string; detail?: string; known_users?: string[] }> {
  const current = await loadHotContext(userId, true, true);

  if (!current) {
    let knownUsers: string[] = [];
    try {
      const storage = getStorageProvider();
      knownUsers = await storage.listL1Users();
    } catch {
      // Storage not ready
    }
    return {
      error: 'user_not_found',
      detail: `No L1 context for "${userId}". Known users: [${knownUsers.join(', ')}]`,
      known_users: knownUsers,
    };
  }

  if (expectedUpdatedAt && current.updated_at !== expectedUpdatedAt) {
    return { error: 'conflict', current_updated_at: current.updated_at };
  }

  const newUpdatedAt = new Date().toISOString();
  let newContext: L1HotContext;

  if (operation === 'replace') {
    const merged = { ...data, version: 1, updated_at: newUpdatedAt };
    try {
      newContext = L1HotContextSchema.parse(merged);
    } catch (e) {
      return { error: `validation_failed: ${(e as Error).message}` };
    }
  } else {
    const merged = deepMerge(current as unknown as Record<string, unknown>, data);
    merged.updated_at = newUpdatedAt;
    try {
      newContext = L1HotContextSchema.parse(merged);
    } catch (e) {
      return { error: `validation_failed: ${(e as Error).message}` };
    }
  }

  const changes = computeChanges(
    current as unknown as Record<string, unknown>,
    newContext as unknown as Record<string, unknown>
  );

  const cryptoProvider = getDefaultCryptoProvider();
  let fileContent: string;

  if (cryptoProvider.isUnlocked() && cryptoProvider.name !== 'none') {
    const plaintext = Buffer.from(JSON.stringify(newContext, null, 2), 'utf-8');
    const encrypted = await cryptoProvider.encrypt(plaintext);
    fileContent = JSON.stringify(encrypted, null, 2);
  } else {
    fileContent = JSON.stringify(newContext, null, 2);
  }

  const storage = getStorageProvider();
  await storage.writeL1(userId, Buffer.from(fileContent, 'utf-8'));

  hotContextCache.delete(userId);

  const auditEntries: AuditEntry[] = changes
    .filter((c) => c.path !== 'updated_at')
    .map((c) => ({
      ts: newUpdatedAt,
      user: userId,
      op: operation,
      path: c.path,
      old: c.old,
      new: c.new,
    }));

  await appendAudit(auditEntries);

  return { success: true, updated_at: newUpdatedAt };
}

// --- Public API ---

/**
 * Mark encryption as enabled (called by server init after crypto setup).
 */
export function setEncryptionEnabled(enabled: boolean): void {
  encryptionEnabled = enabled;
}

/**
 * Get cached user IDs (for status reporting).
 */
export function getCachedUserIds(): string[] {
  return Array.from(hotContextCache.keys());
}

/**
 * Register all Cordelia MCP tools and resource handlers on the given Server.
 * Called by both stdio (server.ts) and HTTP (http-server.ts) transports.
 */
export function registerCordeliaTools(server: Server): void {
  // List available tools
  server.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: [
      {
        name: 'memory_read_hot',
        description:
          'Read L1 hot context for a user. Returns dense structured memory including identity, active state, preferences, and delegation rules. Load this at session start.',
        inputSchema: {
          type: 'object' as const,
          properties: {
            user_id: {
              type: 'string',
              description: 'User identifier (e.g., "russell")',
            },
          },
          required: ['user_id'],
        },
      },
      {
        name: 'memory_write_hot',
        description:
          'Write to L1 hot context for a user. Use patch for partial updates, replace for full replacement. Supports optimistic concurrency via expected_updated_at.',
        inputSchema: {
          type: 'object' as const,
          properties: {
            user_id: {
              type: 'string',
              description: 'User identifier (e.g., "russell")',
            },
            operation: {
              type: 'string',
              enum: ['patch', 'replace'],
              description: 'patch = deep merge data into existing context, replace = full replacement',
            },
            data: {
              type: 'object',
              description: 'The data to write/merge into context',
            },
            expected_updated_at: {
              type: 'string',
              description: 'Optional optimistic lock - if provided, write fails if current updated_at differs',
            },
          },
          required: ['user_id', 'operation', 'data'],
        },
      },
      {
        name: 'memory_status',
        description: 'Get memory system status and available users.',
        inputSchema: {
          type: 'object' as const,
          properties: {},
        },
      },
      {
        name: 'memory_analyze_novelty',
        description:
          'Analyze text for novelty signals. Returns detected signals, confidence scores, and suggested persistence targets. Use this to determine what from a conversation should be persisted to memory.',
        inputSchema: {
          type: 'object' as const,
          properties: {
            text: {
              type: 'string',
              description: 'Single message or text to analyze',
            },
            messages: {
              type: 'array',
              items: { type: 'string' },
              description: 'Multiple messages to analyze as a session (alternative to text)',
            },
            threshold: {
              type: 'number',
              description: 'Confidence threshold for persistence suggestions (default: 0.7)',
            },
          },
        },
      },
      {
        name: 'memory_search',
        description:
          'Search L2 warm index by keyword, type, and/or tags. Returns matching entries with relevance scores. Use this to find entities, sessions, or learnings from memory.',
        inputSchema: {
          type: 'object' as const,
          properties: {
            query: {
              type: 'string',
              description: 'Search query (matches against names, content, and keywords)',
            },
            type: {
              type: 'string',
              enum: ['entity', 'session', 'learning'],
              description: 'Filter by item type',
            },
            tags: {
              type: 'array',
              items: { type: 'string' },
              description: 'Filter by tags (any match)',
            },
            limit: {
              type: 'number',
              description: 'Maximum results to return (default: 20)',
            },
            group_id: {
              type: 'string',
              description: 'Filter results to a specific group',
            },
          },
        },
      },
      {
        name: 'memory_read_warm',
        description:
          'Read a specific L2 warm item by ID. Returns the full item content (entity, session, or learning).',
        inputSchema: {
          type: 'object' as const,
          properties: {
            id: {
              type: 'string',
              description: 'Item ID to retrieve',
            },
            entity_id: {
              type: 'string',
              description: 'Optional: entity requesting access (enables group visibility checks)',
            },
          },
          required: ['id'],
        },
      },
      {
        name: 'memory_write_warm',
        description:
          'Create or update an L2 warm item. Use for storing entities (people, orgs, projects, concepts), session summaries, or learnings (patterns, insights, principles).',
        inputSchema: {
          type: 'object' as const,
          properties: {
            type: {
              type: 'string',
              enum: ['entity', 'session', 'learning'],
              description: 'Item type to create/update',
            },
            data: {
              type: 'object',
              description:
                'Item data (schema varies by type). For entity: data.type must be "person"|"org"|"project"|"concept". For learning: data.type must be "pattern"|"insight"|"principle". Sessions have no subtype.',
            },
            entity_id: {
              type: 'string',
              description: 'Optional: entity performing the write (enables group policy checks)',
            },
            group_id: {
              type: 'string',
              description: 'Optional: target group for group-scoped writes',
            },
          },
          required: ['type', 'data'],
        },
      },
      {
        name: 'memory_delete_warm',
        description:
          'Delete a specific L2 warm item by ID. Removes the item from storage and the index.',
        inputSchema: {
          type: 'object' as const,
          properties: {
            id: {
              type: 'string',
              description: 'Item ID to delete',
            },
            entity_id: {
              type: 'string',
              description: 'Optional: entity requesting deletion (enables policy checks)',
            },
          },
          required: ['id'],
        },
      },
      {
        name: 'memory_backup',
        description:
          'Create a backup of the memory database. Returns backup manifest with SHA-256 verification. SQLite provider only.',
        inputSchema: {
          type: 'object' as const,
          properties: {
            destination: {
              type: 'string',
              description: 'Destination directory for backup files (default: memory/backups)',
            },
          },
        },
      },
      {
        name: 'memory_restore',
        description:
          'Restore memory database from a backup. Verifies SHA-256, runs integrity checks, migrates schema if needed. SQLite provider only.',
        inputSchema: {
          type: 'object' as const,
          properties: {
            source: {
              type: 'string',
              description: 'Source directory containing backup files (.db + .manifest.json)',
            },
            dry_run: {
              type: 'boolean',
              description: 'If true, validate backup without applying (default: false)',
            },
          },
          required: ['source'],
        },
      },
      {
        name: 'memory_share',
        description:
          'Share a private memory to a group. Creates an immutable copy; the original is never modified.',
        inputSchema: {
          type: 'object' as const,
          properties: {
            item_id: { type: 'string', description: 'ID of the memory to share' },
            target_group: { type: 'string', description: 'Group ID to share to' },
            entity_id: { type: 'string', description: 'Entity performing the share' },
          },
          required: ['item_id', 'target_group', 'entity_id'],
        },
      },
      {
        name: 'memory_group_create',
        description: 'Create a new group. The calling entity becomes owner.',
        inputSchema: {
          type: 'object' as const,
          properties: {
            id: { type: 'string', description: 'Group ID (unique identifier)' },
            name: { type: 'string', description: 'Human-readable group name' },
            entity_id: { type: 'string', description: 'Entity creating the group (becomes owner)' },
            culture: { type: 'object', description: 'Group culture object (optional)' },
          },
          required: ['id', 'name', 'entity_id'],
        },
      },
      {
        name: 'memory_group_list',
        description: 'List groups, optionally filtered by entity membership.',
        inputSchema: {
          type: 'object' as const,
          properties: {
            entity_id: { type: 'string', description: 'Filter to groups this entity belongs to' },
          },
        },
      },
      {
        name: 'memory_group_read',
        description: 'Read group details including members.',
        inputSchema: {
          type: 'object' as const,
          properties: {
            group_id: { type: 'string', description: 'Group ID to read' },
          },
          required: ['group_id'],
        },
      },
      {
        name: 'memory_group_add_member',
        description: 'Add a member to a group. Requires admin/owner role.',
        inputSchema: {
          type: 'object' as const,
          properties: {
            group_id: { type: 'string', description: 'Group to add member to' },
            entity_id: { type: 'string', description: 'Entity requesting the add (must be admin/owner)' },
            target_entity_id: { type: 'string', description: 'Entity to add as member' },
            role: { type: 'string', enum: ['admin', 'member', 'viewer'], description: 'Role for the new member (default: member)' },
          },
          required: ['group_id', 'entity_id', 'target_entity_id'],
        },
      },
      {
        name: 'memory_group_remove_member',
        description: 'Remove a member from a group. Requires admin/owner role.',
        inputSchema: {
          type: 'object' as const,
          properties: {
            group_id: { type: 'string', description: 'Group to remove member from' },
            entity_id: { type: 'string', description: 'Entity requesting the removal (must be admin/owner)' },
            target_entity_id: { type: 'string', description: 'Entity to remove' },
          },
          required: ['group_id', 'entity_id', 'target_entity_id'],
        },
      },
      {
        name: 'memory_bind_context',
        description: 'Bind a working directory to a group. Writes from that directory will be scoped to the group, and searches will prioritize group memories. Stored in L1 active.context_bindings.',
        inputSchema: {
          type: 'object' as const,
          properties: {
            user_id: { type: 'string', description: 'User whose bindings to update' },
            directory: { type: 'string', description: 'Absolute directory path to bind' },
            group_id: { type: 'string', description: 'Group ID to bind to this directory' },
          },
          required: ['user_id', 'directory', 'group_id'],
        },
      },
      {
        name: 'memory_unbind_context',
        description: 'Remove a context binding for a working directory. Restores default behavior (private memory).',
        inputSchema: {
          type: 'object' as const,
          properties: {
            user_id: { type: 'string', description: 'User whose bindings to update' },
            directory: { type: 'string', description: 'Absolute directory path to unbind' },
          },
          required: ['user_id', 'directory'],
        },
      },
      {
        name: 'memory_prefetch_l2',
        description: 'Prefetch top L2 items for faster session start. Returns most recently accessed items from user groups and private memory. Context-aware: prioritizes bound group if context binding exists.',
        inputSchema: {
          type: 'object' as const,
          properties: {
            user_id: { type: 'string', description: 'User to prefetch for' },
            cwd: { type: 'string', description: 'Optional working directory for context-aware prefetch' },
            limit: { type: 'number', description: 'Max items to prefetch (default: 10)' },
          },
          required: ['user_id'],
        },
      },
    ],
  }));

  // List available resources
  server.setRequestHandler(ListResourcesRequestSchema, async () => {
    try {
      const storage = getStorageProvider();
      const users = await storage.listL1Users();

      return {
        resources: users.map((userId) => ({
          uri: `cordelia://hot/${userId}`,
          name: `Hot context: ${userId}`,
          mimeType: 'application/json',
        })),
      };
    } catch {
      return { resources: [] };
    }
  });

  // Read resource
  server.setRequestHandler(ReadResourceRequestSchema, async (request) => {
    const uri = request.params.uri;
    const match = uri.match(/^cordelia:\/\/hot\/(.+)$/);

    if (!match) {
      throw new Error(`Unknown resource URI: ${uri}`);
    }

    const userId = match[1];
    const context = await loadHotContext(userId);

    if (!context) {
      throw new Error(`No hot context found for user: ${userId}`);
    }

    return {
      contents: [
        {
          uri,
          mimeType: 'application/json',
          text: JSON.stringify(context, null, 2),
        },
      ],
    };
  });

  // Handle tool calls
  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name, arguments: args } = request.params;

    switch (name) {
      case 'memory_read_hot': {
        const userId = (args as { user_id: string }).user_id;
        const context = await loadHotContext(userId);

        if (!context) {
          let knownUsers: string[] = [];
          try {
            const storage = getStorageProvider();
            knownUsers = await storage.listL1Users();
          } catch {
            // Storage not ready
          }

          const detail = knownUsers.length > 0
            ? `No L1 context found for "${userId}". Known users: [${knownUsers.join(', ')}]. ` +
              `Check that you're using the L1 storage key (filename), not the identity.id field.`
            : `No L1 context found for "${userId}". No users found in storage.`;

          return {
            content: [
              {
                type: 'text',
                text: JSON.stringify({ error: 'user_not_found', user_id: userId, detail, known_users: knownUsers }),
              },
            ],
          };
        }

        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(context),
            },
          ],
        };
      }

      case 'memory_write_hot': {
        const { user_id, operation, data, expected_updated_at } = args as {
          user_id: string;
          operation: 'patch' | 'replace';
          data: Record<string, unknown>;
          expected_updated_at?: string;
        };

        const result = await writeHotContext(user_id, operation, data, expected_updated_at);

        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(result),
            },
          ],
        };
      }

      case 'memory_status': {
        let users: string[] = [];

        try {
          const storage = getStorageProvider();
          users = await storage.listL1Users();
        } catch {
          // Storage not ready yet
        }

        const l2Index = await l2.loadIndex();
        const l2Stats = {
          status: 'active',
          entries: l2Index.entries.length,
          entities: l2Index.entries.filter((e) => e.type === 'entity').length,
          sessions: l2Index.entries.filter((e) => e.type === 'session').length,
          learnings: l2Index.entries.filter((e) => e.type === 'learning').length,
          embedding_cache_size: l2.getEmbeddingCacheSize(),
        };

        const cryptoProvider = getDefaultCryptoProvider();
        const encryptionStatus = {
          enabled: encryptionEnabled,
          provider: cryptoProvider.name,
          unlocked: cryptoProvider.isUnlocked(),
        };

        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify({
                status: 'ok',
                version: '0.3.0',
                layers: {
                  L1_hot: { users, cached: getCachedUserIds() },
                  L2_warm: l2Stats,
                  L3_cold: { status: 'not_implemented' },
                },
                encryption: encryptionStatus,
              }),
            },
          ],
        };
      }

      case 'memory_analyze_novelty': {
        const { text, messages, threshold = 0.7 } = args as {
          text?: string;
          messages?: string[];
          threshold?: number;
        };

        let result: NoveltyResult;

        if (messages && messages.length > 0) {
          result = analyzeSession(messages);
        } else if (text) {
          result = analyzeNovelty(text);
        } else {
          return {
            content: [
              {
                type: 'text',
                text: JSON.stringify({ error: 'must_provide_text_or_messages' }),
              },
            ],
          };
        }

        const forPersistence = filterForPersistence(result, threshold);

        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify({
                signals: result.signals,
                score: result.score,
                extracts: result.extracts,
                for_persistence: forPersistence,
              }),
            },
          ],
        };
      }

      case 'memory_search': {
        const { query, type, tags, limit } = args as {
          query?: string;
          type?: 'entity' | 'session' | 'learning';
          tags?: string[];
          limit?: number;
        };

        const results = await l2.search({ query, type, tags, limit });

        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify({ results, count: results.length }),
            },
          ],
        };
      }

      case 'memory_read_warm': {
        const { id, entity_id } = args as { id: string; entity_id?: string };

        if (entity_id) {
          const storage = getStorageProvider();
          const meta = await storage.readL2ItemMeta(id);
          if (meta && meta.visibility === 'group' && meta.group_id) {
            const membership = await storage.getMembership(meta.group_id, entity_id);
            if (!membership) {
              return { content: [{ type: 'text', text: JSON.stringify({ error: 'unauthorized', detail: 'not a member of group' }) }] };
            }
          } else if (meta && meta.visibility === 'private' && meta.owner_id && meta.owner_id !== entity_id) {
            return { content: [{ type: 'text', text: JSON.stringify({ error: 'unauthorized', detail: 'not owner of private item' }) }] };
          }
        }

        const item = await l2.readItem(id);

        if (!item) {
          return {
            content: [
              {
                type: 'text',
                text: JSON.stringify({ error: 'not_found', id }),
              },
            ],
          };
        }

        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(item),
            },
          ],
        };
      }

      case 'memory_write_warm': {
        const { type, data, entity_id, group_id: writeGroupId } = args as {
          type: 'entity' | 'session' | 'learning';
          data: Record<string, unknown>;
          entity_id?: string;
          group_id?: string;
        };

        if (entity_id && writeGroupId) {
          const storage = getStorageProvider();
          const membership = await storage.getMembership(writeGroupId, entity_id);
          if (!membership) {
            return { content: [{ type: 'text', text: JSON.stringify({ error: 'unauthorized', detail: 'not a member of group' }) }] };
          }
          if (membership.role === 'viewer') {
            return { content: [{ type: 'text', text: JSON.stringify({ error: 'unauthorized', detail: 'viewer cannot write' }) }] };
          }
          if (membership.posture === 'emcon') {
            return { content: [{ type: 'text', text: JSON.stringify({ error: 'unauthorized', detail: 'EMCON posture blocks writes' }) }] };
          }
        }

        const result = await l2.writeItem(type, data, { group_id: writeGroupId, entity_id });

        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(result),
            },
          ],
        };
      }

      case 'memory_delete_warm': {
        const { id, entity_id } = args as { id: string; entity_id?: string };

        if (entity_id) {
          const storage = getStorageProvider();
          const meta = await storage.readL2ItemMeta(id);
          if (meta && meta.visibility === 'group' && meta.group_id) {
            const membership = await storage.getMembership(meta.group_id, entity_id);
            if (!membership) {
              return { content: [{ type: 'text', text: JSON.stringify({ error: 'unauthorized', detail: 'not a member of group' }) }] };
            }
            if (membership.role !== 'owner' && membership.role !== 'admin' && meta.author_id !== entity_id) {
              return { content: [{ type: 'text', text: JSON.stringify({ error: 'unauthorized', detail: 'only owner/admin or author can delete group items' }) }] };
            }
          } else if (meta && meta.visibility === 'private' && meta.owner_id && meta.owner_id !== entity_id) {
            return { content: [{ type: 'text', text: JSON.stringify({ error: 'unauthorized', detail: 'not owner of private item' }) }] };
          }
        }

        const result = await l2.deleteItem(id);

        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(result),
            },
          ],
        };
      }

      case 'memory_backup': {
        const { destination } = args as { destination?: string };
        const MEMORY_ROOT = process.env.CORDELIA_MEMORY_ROOT || path.join(path.dirname(new URL(import.meta.url).pathname), '..', 'memory');
        const destDir = destination || path.join(MEMORY_ROOT, 'backups');

        try {
          const { createBackup } = await import('./backup.js');
          const result = await createBackup(destDir);
          return {
            content: [
              {
                type: 'text',
                text: JSON.stringify({
                  success: true,
                  manifest: result.manifest,
                  size: result.size,
                  duration_ms: result.duration_ms,
                  dbPath: result.dbPath,
                }),
              },
            ],
          };
        } catch (e) {
          return {
            content: [
              {
                type: 'text',
                text: JSON.stringify({ error: (e as Error).message }),
              },
            ],
          };
        }
      }

      case 'memory_restore': {
        const { source, dry_run } = args as { source: string; dry_run?: boolean };

        try {
          const { restoreBackup } = await import('./backup.js');
          const result = await restoreBackup(source, { dryRun: dry_run });
          return {
            content: [
              {
                type: 'text',
                text: JSON.stringify({
                  success: true,
                  items: result.items,
                  schemaVersion: result.schemaVersion,
                  integrity: result.integrityReport.ok ? 'passed' : 'failed',
                  integrityReport: result.integrityReport,
                }),
              },
            ],
          };
        } catch (e) {
          return {
            content: [
              {
                type: 'text',
                text: JSON.stringify({ error: (e as Error).message }),
              },
            ],
          };
        }
      }

      case 'memory_share': {
        const { item_id, target_group, entity_id } = args as {
          item_id: string;
          target_group: string;
          entity_id: string;
        };
        const result = await l2.shareItem(item_id, target_group, entity_id);
        return { content: [{ type: 'text', text: JSON.stringify(result) }] };
      }

      case 'memory_group_create': {
        const { id, name: groupName, entity_id, culture } = args as {
          id: string;
          name: string;
          entity_id: string;
          culture?: Record<string, unknown>;
        };
        const storage = getStorageProvider();
        if (culture && Object.keys(culture).length > 0) {
          const parsed = GroupCultureSchema.safeParse(culture);
          if (!parsed.success) {
            return { content: [{ type: 'text', text: JSON.stringify({ error: `invalid culture: ${parsed.error.message}` }) }] };
          }
        }
        const cultureStr = culture ? JSON.stringify(culture) : '{}';
        try {
          await storage.createGroup(id, groupName, cultureStr, '{}');
          await storage.addMember(id, entity_id, 'owner');
          await storage.logAccess({ entity_id, action: 'create', resource_type: 'group', resource_id: id });
          return { content: [{ type: 'text', text: JSON.stringify({ success: true, id }) }] };
        } catch (e) {
          return { content: [{ type: 'text', text: JSON.stringify({ error: (e as Error).message }) }] };
        }
      }

      case 'memory_group_list': {
        const { entity_id } = args as { entity_id?: string };
        const storage = getStorageProvider();
        let groups = await storage.listGroups();
        if (entity_id) {
          const filtered = [];
          for (const g of groups) {
            const m = await storage.getMembership(g.id, entity_id);
            if (m) filtered.push(g);
          }
          groups = filtered;
        }
        return { content: [{ type: 'text', text: JSON.stringify({ groups, count: groups.length }) }] };
      }

      case 'memory_group_read': {
        const { group_id } = args as { group_id: string };
        const storage = getStorageProvider();
        const group = await storage.readGroup(group_id);
        if (!group) {
          return { content: [{ type: 'text', text: JSON.stringify({ error: 'not_found', group_id }) }] };
        }
        const members = await storage.listMembers(group_id);
        return { content: [{ type: 'text', text: JSON.stringify({ ...group, members }) }] };
      }

      case 'memory_group_add_member': {
        const { group_id, entity_id, target_entity_id, role = 'member' } = args as {
          group_id: string;
          entity_id: string;
          target_entity_id: string;
          role?: string;
        };
        const storage = getStorageProvider();
        const requester = await storage.getMembership(group_id, entity_id);
        if (!requester || (requester.role !== 'owner' && requester.role !== 'admin')) {
          return { content: [{ type: 'text', text: JSON.stringify({ error: 'unauthorized', detail: 'requires admin or owner role' }) }] };
        }
        try {
          await storage.addMember(group_id, target_entity_id, role);
          await storage.logAccess({ entity_id, action: 'add_member', resource_type: 'group', resource_id: group_id, detail: `added ${target_entity_id} as ${role}` });
          return { content: [{ type: 'text', text: JSON.stringify({ success: true }) }] };
        } catch (e) {
          return { content: [{ type: 'text', text: JSON.stringify({ error: (e as Error).message }) }] };
        }
      }

      case 'memory_group_remove_member': {
        const { group_id, entity_id, target_entity_id } = args as {
          group_id: string;
          entity_id: string;
          target_entity_id: string;
        };
        const storage = getStorageProvider();
        const requester = await storage.getMembership(group_id, entity_id);
        if (!requester || (requester.role !== 'owner' && requester.role !== 'admin')) {
          return { content: [{ type: 'text', text: JSON.stringify({ error: 'unauthorized', detail: 'requires admin or owner role' }) }] };
        }
        const removed = await storage.removeMember(group_id, target_entity_id);
        if (removed) {
          await storage.logAccess({ entity_id, action: 'remove_member', resource_type: 'group', resource_id: group_id, detail: `removed ${target_entity_id}` });
        }
        return { content: [{ type: 'text', text: JSON.stringify({ success: removed }) }] };
      }

      case 'memory_bind_context': {
        const { user_id, directory, group_id } = args as {
          user_id: string;
          directory: string;
          group_id: string;
        };

        const storage = getStorageProvider();
        const group = await storage.readGroup(group_id);
        if (!group) {
          return { content: [{ type: 'text', text: JSON.stringify({ error: 'group_not_found', group_id }) }] };
        }

        const ctx = await loadHotContext(user_id);
        if (!ctx) {
          return { content: [{ type: 'text', text: JSON.stringify({ error: 'user_not_found', user_id }) }] };
        }

        const bindings = { ...(ctx.active.context_bindings || {}), [directory]: group_id };
        const result = await writeHotContext(user_id, 'patch', {
          active: { context_bindings: bindings },
        });

        return { content: [{ type: 'text', text: JSON.stringify(result) }] };
      }

      case 'memory_unbind_context': {
        const { user_id, directory } = args as {
          user_id: string;
          directory: string;
        };

        const ctx = await loadHotContext(user_id);
        if (!ctx) {
          return { content: [{ type: 'text', text: JSON.stringify({ error: 'user_not_found', user_id }) }] };
        }

        const bindings = { ...(ctx.active.context_bindings || {}) };
        delete bindings[directory];
        const result = await writeHotContext(user_id, 'patch', {
          active: { context_bindings: Object.keys(bindings).length > 0 ? bindings : undefined },
        });

        return { content: [{ type: 'text', text: JSON.stringify(result) }] };
      }

      case 'memory_prefetch_l2': {
        const { user_id, cwd, limit: prefetchLimit = 10 } = args as {
          user_id: string;
          cwd?: string;
          limit?: number;
        };

        const ctx = await loadHotContext(user_id);
        if (!ctx) {
          return { content: [{ type: 'text', text: JSON.stringify({ error: 'user_not_found', user_id }) }] };
        }

        const items = await l2.prefetchItems(user_id, {
          cwd,
          bindings: ctx.active.context_bindings,
          limit: prefetchLimit,
        });

        return {
          content: [{
            type: 'text',
            text: JSON.stringify({ prefetched: items.length, items }),
          }],
        };
      }

      default:
        throw new Error(`Unknown tool: ${name}`);
    }
  });
}
