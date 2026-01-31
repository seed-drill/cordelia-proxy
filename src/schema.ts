/**
 * Project Cordelia - L1 Hot Context Schema
 *
 * Dense, machine-optimized format for Claude's persistent memory.
 * Not intended for human reading - optimized for fast parsing and
 * maximum information density.
 */

import { z } from 'zod';

// Key reference format: namespace:identifier
const KeyRefSchema = z.string().regex(/^[a-z_]+:[a-z0-9_]+$/);

// Identity core - who is this human
export const IdentitySchema = z.object({
  id: z.string(),
  name: z.string(),
  roles: z.array(z.string()),
  orgs: z.array(z.object({
    id: z.string(),
    name: z.string(),
    role: z.string(),
  })),
  key_refs: z.array(KeyRefSchema).describe('Foundational references: author:work format'),
  style: z.array(z.string()).describe('Communication and working style markers'),
  tz: z.string().optional().describe('Timezone'),
  github_id: z.string().optional().describe('GitHub username for OAuth login'),
  email: z.string().optional().describe('Email address'),
  api_key: z.string().optional().describe('Per-user API key for CLI uploads'),
  interests: z.array(z.string()).optional().describe('User interests and hobbies'),
  heroes: z.array(z.string()).optional().describe('Inspirational figures'),
});

// Active state - current work context
export const ActiveStateSchema = z.object({
  project: z.string().nullable(),
  sprint: z.number().nullable(),
  focus: z.string().nullable().describe('Current primary focus'),
  blockers: z.array(z.string()),
  next: z.array(z.string()).describe('Immediate next actions'),
  context_refs: z.array(z.string()).describe('Relevant file paths or URLs'),
  sprint_plan: z.record(z.string(), z.string()).optional().describe('Sprint overview: s1, s2, etc.'),
  notes: z.array(z.string()).optional().describe('Ad-hoc notes and learnings'),
  context_bindings: z.record(z.string(), z.string()).optional().describe('Map of directory path -> group_id. Scopes group memory visibility by working directory.'),
});

// Preferences - how we work together
export const PreferencesSchema = z.object({
  planning_mode: z.enum(['critical', 'important', 'optional']),
  feedback_style: z.enum(['continuous', 'batched', 'end_of_task']),
  verbosity: z.enum(['minimal', 'concise', 'detailed']),
  emoji: z.boolean(),
  proactive_suggestions: z.boolean(),
  auto_commit: z.boolean().describe('Auto-commit on session end'),
});

// Delegation rules - how sub-agents should behave
export const DelegationSchema = z.object({
  allowed: z.boolean(),
  max_parallel: z.number(),
  require_approval: z.array(z.string()).describe('Actions requiring human approval'),
  autonomous: z.array(z.string()).describe('Actions that can proceed without approval'),
});

// Integrity block - cryptographic identity continuity
export const IntegritySchema = z.object({
  chain_hash: z.string().describe('SHA256(previous_hash + session_count + content_hash)'),
  previous_hash: z.string().describe('Chain hash from previous session'),
  genesis: z.string().datetime().describe('Identity birth timestamp'),
});

// Culture ship vessel names for session character
export const VesselSchema = z.enum([
  'GSV Sleeper Service',
  'GSV Just Read The Instructions',
  'GCU Grey Area',
  'GSV So Much For Subtlety',
  'ROU Frank Exchange Of Views',
  'GSV Quietly Confident',
]);

// Ephemeral memory - autobiographical/session continuity
export const EphemeralSchema = z.object({
  session_count: z.number().int().min(1).describe('Total sessions since genesis'),
  current_session_start: z.string().datetime().describe('When this session began'),
  last_session_end: z.string().datetime().nullable().describe('When previous session ended'),
  last_summary: z.string().nullable().describe('Brief summary of last session'),
  open_threads: z.array(z.string()).describe('Unfinished work from last session'),
  vessel: VesselSchema.nullable().describe('Culture ship name matching session character'),
  integrity: IntegritySchema,
});

// L1 Hot Context - loaded every session
export const L1HotContextSchema = z.object({
  version: z.literal(1),
  updated_at: z.string().datetime(),
  identity: IdentitySchema,
  active: ActiveStateSchema,
  prefs: PreferencesSchema,
  delegation: DelegationSchema,
  ephemeral: EphemeralSchema.optional().describe('Autobiographical memory - added S7'),
});

export type L1HotContext = z.infer<typeof L1HotContextSchema>;
export type Identity = z.infer<typeof IdentitySchema>;
export type ActiveState = z.infer<typeof ActiveStateSchema>;
export type Preferences = z.infer<typeof PreferencesSchema>;
export type Delegation = z.infer<typeof DelegationSchema>;
export type Ephemeral = z.infer<typeof EphemeralSchema>;
export type Integrity = z.infer<typeof IntegritySchema>;
export type Vessel = z.infer<typeof VesselSchema>;

// =============================================================================
// Group Culture Schema
// =============================================================================

/**
 * Group culture governs broadcast behavior, TTL, notifications, and departure.
 * Maps to cache coherence protocols:
 *   chatty = write-update, moderate = write-invalidate, taciturn = TTL expiry
 */
export const GroupCultureSchema = z.object({
  broadcast_eagerness: z.enum(['chatty', 'moderate', 'taciturn']).default('moderate')
    .describe('Replication strategy: chatty=eager push, moderate=notify-and-fetch, taciturn=passive'),
  ttl_default: z.number().int().positive().nullable().default(null)
    .describe('Default TTL in seconds for group-cached memories. Null = no expiry'),
  notification_policy: z.enum(['push', 'notify', 'silent']).default('notify')
    .describe('How members are notified of new content'),
  departure_policy: z.enum(['permissive', 'standard', 'restrictive']).default('standard')
    .describe('What happens to shared memories when a member leaves'),
});

export type GroupCulture = z.infer<typeof GroupCultureSchema>;

// =============================================================================
// Encryption Schema
// =============================================================================

/**
 * Encrypted item wrapper - detected by _encrypted field.
 * Items are encrypted with AES-256-GCM.
 */
export const EncryptedItemSchema = z.object({
  _encrypted: z.literal(true),
  version: z.literal(1),
  iv: z.string().describe('Base64-encoded IV, 12 bytes'),
  authTag: z.string().describe('Base64-encoded auth tag, 16 bytes'),
  ciphertext: z.string().describe('Base64-encoded encrypted content'),
});

export type EncryptedItem = z.infer<typeof EncryptedItemSchema>;

// =============================================================================
// L2 Warm Index Schema
// =============================================================================

/**
 * Entity - person, org, project, or concept
 * Stored in /memory/L2-warm/entities/{id}.json
 */
export const L2EntitySchema = z.object({
  id: z.string(),
  type: z.enum(['person', 'org', 'project', 'concept']),
  name: z.string(),
  aliases: z.array(z.string()).default([]),
  tags: z.array(z.string()).default([]),
  summary: z.string(),
  details: z.record(z.string(), z.unknown()).default({}),
  refs: z.array(z.string()).default([]).describe('Related entity IDs'),
  created_at: z.string().datetime(),
  updated_at: z.string().datetime(),
});

/**
 * Session Summary - compressed session record
 * Stored in /memory/L2-warm/sessions/{date}-{hash}.json
 */
export const L2SessionSchema = z.object({
  id: z.string(),
  date: z.string(),
  duration_minutes: z.number().optional(),
  focus: z.string(),
  highlights: z.array(z.string()).default([]),
  decisions: z.array(z.string()).default([]),
  entities_mentioned: z.array(z.string()).default([]),
  novelty_score: z.number().min(0).max(1).optional(),
});

/**
 * Learning - validated pattern or insight
 * Stored in /memory/L2-warm/learnings/{id}.json
 */
export const L2LearningSchema = z.object({
  id: z.string(),
  type: z.enum(['pattern', 'insight', 'principle']),
  content: z.string(),
  context: z.string().optional(),
  confidence: z.number().min(0).max(1).default(0.5),
  source_session: z.string().optional(),
  validated: z.boolean().default(false),
  tags: z.array(z.string()).default([]),
  created_at: z.string().datetime(),
});

/**
 * Index Entry - lightweight metadata for search
 */
export const L2IndexEntrySchema = z.object({
  id: z.string(),
  type: z.enum(['entity', 'session', 'learning']),
  subtype: z.string().optional(),
  name: z.string(),
  tags: z.array(z.string()).default([]),
  keywords: z.array(z.string()).default([]),
  path: z.string().describe('Relative file path from L2-warm/'),
  embedding: z.array(z.number()).optional().describe('Semantic embedding vector'),
  visibility: z.enum(['private', 'group', 'public', 'shared']).default('private').describe('Access visibility for multi-user support'),
});

/**
 * L2 Index - searchable metadata index
 * Stored in /memory/L2-warm/index.json
 */
export const L2IndexSchema = z.object({
  version: z.literal(1),
  updated_at: z.string().datetime(),
  entries: z.array(L2IndexEntrySchema).default([]),
});

export type L2Entity = z.infer<typeof L2EntitySchema>;
export type L2Session = z.infer<typeof L2SessionSchema>;
export type L2Learning = z.infer<typeof L2LearningSchema>;
export type L2IndexEntry = z.infer<typeof L2IndexEntrySchema>;
export type L2Index = z.infer<typeof L2IndexSchema>;
