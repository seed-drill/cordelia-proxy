/**
 * Project Cordelia - L2 Warm Index Module
 *
 * Searchable memory layer for content that isn't always loaded
 * but can be retrieved on demand.
 *
 * Search: FTS5 BM25 + optional sqlite-vec cosine, dominant-signal hybrid.
 *   Hybrid scoring: 0.7 * max(semantic, keyword) + 0.3 * min(semantic, keyword)
 *   Dominant signal leads, weaker signal boosts. Prevents keyword-precise queries
 *   (e.g. "386") being drowned by weak semantic scores.
 *
 * JSON provider returns empty FTS/vec results — search degrades to blob index
 * listing (no-query path). This is acceptable for non-search test stubs.
 */

import * as crypto from 'crypto';
import * as fs from 'fs/promises';
import * as path from 'path';
import {
  L2IndexSchema,
  L2EntitySchema,
  L2SessionSchema,
  L2LearningSchema,
  type L2Index,
  type L2IndexEntry,
  type L2Entity,
  type L2Session,
  type L2Learning,
} from './schema.js';
import {
  inferDomainFromType,
  computeInterruptTtl,
  PROCEDURAL_CAP,
  type MemoryDomain,
} from './domain.js';
import {
  getDefaultProvider,
  getEmbeddableText,
  extractStringValues,
  type EmbeddingProvider,
} from './embeddings.js';
import {
  getDefaultCryptoProvider,
  isEncryptedPayload,
  type EncryptedPayload,
} from './crypto.js';
import { getStorageProvider } from './storage.js';
import type { SqliteStorageProvider } from './storage-sqlite.js';

export const L2_ROOT = path.join(path.dirname(new URL(import.meta.url).pathname), '..', 'memory', 'L2-warm');

// In-memory embedding cache - fallback for JSON provider
// For SQLite, embeddings are persisted in embedding_cache table
const embeddingCache = new Map<string, number[]>();

/**
 * Clear the embedding cache (for testing).
 */
export function clearEmbeddingCache(): void {
  embeddingCache.clear();
}

/**
 * Get embedding cache size (for status reporting).
 */
export function getEmbeddingCacheSize(): number {
  return embeddingCache.size;
}

type L2Item = L2Entity | L2Session | L2Learning;
type L2ItemType = 'entity' | 'session' | 'learning';

/**
 * Group culture fields consumed at runtime (R3-011).
 */
export interface GroupCulture {
  ttl_default?: number | null;          // seconds before group items expire
  broadcast_eagerness?: 'chatty' | 'moderate' | 'taciturn';  // notification frequency
  notification_policy?: 'push' | 'notify' | 'silent';        // how peers are notified
}

/**
 * Read and parse a group's culture from storage.
 * Returns null if group not found or culture unparseable.
 */
export async function getGroupCulture(groupId: string): Promise<GroupCulture | null> {
  const storage = getStorageProvider();
  const group = await storage.readGroup(groupId);
  if (!group) return null;
  try {
    return JSON.parse(group.culture) as GroupCulture;
  } catch {
    return null;
  }
}

export interface SearchResult {
  id: string;
  type: L2ItemType;
  subtype?: string;
  name: string;
  tags: string[];
  path: string;
  score: number;
  domain?: MemoryDomain;
}

export interface SearchDiagnostics {
  search_path: 'sql';
  vec_available: boolean;
  vec_used: boolean;
  query_embedding_generated: boolean;
  fts_candidates: number;
  vec_candidates: number;
  blob_index_entries: number;
  results: Array<{
    id: string;
    fts_score: number;
    vec_score: number;
    combined_score: number;
  }>;
}

export interface SearchOptions {
  query?: string;
  type?: L2ItemType;
  tags?: string[];
  limit?: number;
  semantic?: boolean; // Enable semantic search (default: true if embeddings available)
  debug?: boolean;    // Return diagnostic metadata alongside results
  domain?: MemoryDomain; // Filter by memory domain
}

/**
 * Compute SHA-256 hash of text for embedding cache key.
 */
function contentHash(text: string): string {
  return crypto.createHash('sha256').update(text, 'utf-8').digest('hex');
}

/**
 * Convert number[] embedding to Float32Array.
 */
function toFloat32Array(embedding: number[]): Float32Array {
  return new Float32Array(embedding);
}

/**
 * Convert Buffer (from embedding_cache) to number[].
 */
function bufferToEmbedding(buf: Buffer): number[] {
  const f32 = new Float32Array(buf.buffer, buf.byteOffset, buf.byteLength / 4);
  return Array.from(f32);
}

/**
 * Convert number[] to Buffer for storage.
 */
function embeddingToBuffer(embedding: number[]): Buffer {
  const f32 = new Float32Array(embedding);
  return Buffer.from(f32.buffer, f32.byteOffset, f32.byteLength);
}

/**
 * Get or generate embedding, using storage-backed cache for SQLite.
 */
async function getCachedEmbedding(
  embeddableText: string,
  provider: EmbeddingProvider,
): Promise<number[] | null> {
  if (provider.dimensions() <= 0) return null;

  const storage = getStorageProvider();
  const hash = contentHash(embeddableText);
  const providerName = provider.name;
  const model = provider.modelName();

  // Check storage-backed cache (SQLite)
  if (storage.name === 'sqlite') {
    const cached = await storage.getEmbedding(hash, providerName, model);
    if (cached) {
      return bufferToEmbedding(cached);
    }
  }

  // Check in-memory cache
  const memKey = `${hash}:${providerName}:${model}`;
  if (embeddingCache.has(memKey)) {
    return embeddingCache.get(memKey)!;
  }

  // Generate new embedding
  try {
    const embedding = await provider.embed(embeddableText);

    // Store in both caches
    if (storage.name === 'sqlite') {
      await storage.putEmbedding(hash, providerName, model, embedding.length, embeddingToBuffer(embedding));
    }
    embeddingCache.set(memKey, embedding);

    return embedding;
  } catch (e) {
    console.error(`Cordelia: embedding generation failed — falling back to FTS-only: ${(e as Error).message}`);
    return null;
  }
}

/**
 * Build embeddable text from item fields.
 */
function buildEmbeddableText(validated: L2Item, name: string, tags: string[]): string {
  return getEmbeddableText({
    name,
    summary: (validated as { summary?: string }).summary,
    content: (validated as { content?: string }).content,
    context: (validated as { context?: string }).context,
    focus: (validated as { focus?: string }).focus,
    highlights: (validated as { highlights?: string[] }).highlights,
    aliases: (validated as { aliases?: string[] }).aliases,
    details: (validated as { details?: Record<string, unknown> }).details,
    tags,
  });
}

/**
 * Load the L2 index from disk.
 * Handles both encrypted and unencrypted formats for automatic migration.
 */
export async function loadIndex(): Promise<L2Index> {
  try {
    const storage = getStorageProvider();
    const buffer = await storage.readL2Index();

    if (!buffer) {
      return { version: 1, updated_at: new Date().toISOString(), entries: [] };
    }

    let parsed = JSON.parse(buffer.toString('utf-8'));

    // Handle encrypted index
    if (isEncryptedPayload(parsed)) {
      const cryptoProvider = getDefaultCryptoProvider();
      if (!cryptoProvider.isUnlocked()) {
        throw new Error('Cannot read encrypted L2 index: encryption not configured');
      }
      const decrypted = await cryptoProvider.decrypt(parsed as EncryptedPayload);
      parsed = JSON.parse(decrypted.toString('utf-8'));
    }

    return L2IndexSchema.parse(parsed);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') {
      // Return empty index if file doesn't exist
      return { version: 1, updated_at: new Date().toISOString(), entries: [] };
    }
    throw error;
  }
}

/**
 * Save the L2 index to disk.
 * Embeddings are stripped before persistence and cached in memory.
 * This prevents semantic fingerprint leakage in stored index.
 */
export async function saveIndex(index: L2Index): Promise<void> {
  // Cache embeddings before stripping
  for (const entry of index.entries) {
    if (entry.embedding?.length) {
      embeddingCache.set(entry.id, entry.embedding);
    }
  }

  // Strip embeddings for persistence
  const entriesWithoutEmbeddings = index.entries.map(({ embedding: _embedding, ...rest }) => rest);

  const validated = L2IndexSchema.parse({
    ...index,
    entries: entriesWithoutEmbeddings,
    updated_at: new Date().toISOString(),
  });

  // Encrypt index if crypto provider is unlocked
  const cryptoProvider = getDefaultCryptoProvider();
  let fileContent: string;

  if (cryptoProvider.isUnlocked() && cryptoProvider.name !== 'none') {
    const plaintext = Buffer.from(JSON.stringify(validated, null, 2), 'utf-8');
    const encrypted = await cryptoProvider.encrypt(plaintext);
    fileContent = JSON.stringify(encrypted, null, 2);
  } else {
    fileContent = JSON.stringify(validated, null, 2);
  }

  const storage = getStorageProvider();
  await storage.writeL2Index(Buffer.from(fileContent, 'utf-8'));
}

/**
 * Extract keywords from text for indexing.
 * Simple tokenization - splits on whitespace and punctuation, lowercases, dedupes.
 */
function extractKeywords(text: string): string[] {
  const words = text
    .toLowerCase()
    .replace(/[^\w\s]/g, ' ')
    .split(/\s+/)
    .filter((w) => w.length > 2);
  return [...new Set(words)];
}

// --- Search Helper Functions ---

interface SearchContext {
  storage: ReturnType<typeof getStorageProvider>;
  entryMap: Map<string, L2IndexEntry>;
  indexEntryCount: number;
}

/**
 * Build lookup map from blob index, enriching with domain from DB.
 */
async function buildEntryMap(index: L2Index): Promise<SearchContext> {
  const storage = getStorageProvider();
  const entryMap = new Map<string, L2IndexEntry>();

  for (const entry of index.entries) {
    if (!entry.domain && storage.name === 'sqlite') {
      const meta = await storage.readL2ItemMeta(entry.id);
      if (meta?.domain) {
        entry.domain = meta.domain as MemoryDomain;
      }
    }
    entryMap.set(entry.id, entry);
  }

  return { storage, entryMap, indexEntryCount: index.entries.length };
}

/**
 * Filter entries matching type, tags, and domain without a search query.
 */
function filterEntryByOptions(
  entry: { type: L2ItemType; tags: string[]; domain?: MemoryDomain },
  type: L2ItemType | undefined,
  tags: string[] | undefined,
  domainFilter: MemoryDomain | undefined,
): boolean {
  if (type && entry.type !== type) return false;
  if (domainFilter && entry.domain !== domainFilter) return false;
  if (tags && tags.length > 0) {
    const hasMatchingTag = tags.some((t) => entry.tags.includes(t.toLowerCase()));
    if (!hasMatchingTag) return false;
  }
  return true;
}

/**
 * Search without query - return all matching type/tags/domain.
 */
async function searchWithoutQuery(
  ctx: SearchContext,
  options: SearchOptions,
  index: L2Index,
): Promise<SearchResult[]> {
  const { type, tags, limit = 20, domain: domainFilter } = options;
  const results: SearchResult[] = [];

  if (domainFilter && ctx.storage.name === 'sqlite') {
    const sqliteStorage = ctx.storage as SqliteStorageProvider;
    const dbItems = await sqliteStorage.getDomainItems(domainFilter, limit);
    for (const item of dbItems) {
      const entry = ctx.entryMap.get(item.id);
      const itemTags = entry?.tags || [];
      if (!filterEntryByOptions({ type: item.type as L2ItemType, tags: itemTags, domain: item.domain as MemoryDomain }, type, tags, domainFilter)) {
        continue;
      }
      results.push({
        id: item.id,
        type: item.type as L2ItemType,
        subtype: entry?.subtype,
        name: entry?.name || item.id,
        tags: itemTags,
        path: entry?.path || `${item.type}s/${item.id}.json`,
        score: 1,
        domain: item.domain as MemoryDomain | undefined,
      });
    }
  } else {
    for (const entry of index.entries) {
      if (!filterEntryByOptions(entry, type, tags, domainFilter)) continue;
      results.push({
        id: entry.id,
        type: entry.type,
        subtype: entry.subtype,
        name: entry.name,
        tags: entry.tags,
        path: entry.path,
        score: 1,
        domain: entry.domain,
      });
    }
  }

  return results.slice(0, limit);
}

/**
 * Perform FTS5 BM25 keyword search, returning normalized scores.
 */
async function performFtsSearch(
  storage: ReturnType<typeof getStorageProvider>,
  query: string,
  limit: number,
): Promise<Map<string, number>> {
  const ftsResults = await storage.ftsSearch(query, limit * 3);
  const ftsScores = new Map<string, number>();
  const maxAbsRank = ftsResults.length > 0
    ? Math.max(...ftsResults.map((r) => Math.abs(r.rank)), 1)
    : 1;
  for (const r of ftsResults) {
    ftsScores.set(r.item_id, Math.abs(r.rank) / maxAbsRank);
  }
  return ftsScores;
}

/**
 * Perform semantic vector search, returning similarity scores.
 */
async function performVecSearch(
  storage: ReturnType<typeof getStorageProvider>,
  query: string,
  limit: number,
  semantic: boolean,
): Promise<{ vecScores: Map<string, number>; queryEmbeddingGenerated: boolean; useVec: boolean }> {
  const provider = getDefaultProvider();
  const vecAvailable = storage.vecAvailable();
  const useVec = semantic && vecAvailable && provider.dimensions() > 0;

  const vecScores = new Map<string, number>();
  let queryEmbeddingGenerated = false;

  if (useVec) {
    const queryEmbedding = await getCachedEmbedding(query, provider);
    queryEmbeddingGenerated = queryEmbedding !== null;
    if (queryEmbedding) {
      const vecResults = await storage.vecSearch(toFloat32Array(queryEmbedding), limit * 3);
      for (const r of vecResults) {
        vecScores.set(r.item_id, Math.max(0, 1 - r.distance));
      }
    }
  }

  return { vecScores, queryEmbeddingGenerated, useVec };
}

/**
 * Compute hybrid score from FTS and vector scores.
 */
function computeHybridScore(
  ftsScore: number,
  vecScore: number,
  hasSemanticScores: boolean,
  domain?: MemoryDomain,
): number {
  let score = hasSemanticScores
    ? 0.7 * Math.max(vecScore, ftsScore) + 0.3 * Math.min(vecScore, ftsScore)
    : ftsScore;

  if (domain === 'value') score += 0.05;
  else if (domain === 'procedural') score += 0.02;

  return score;
}

/**
 * Resolve entry from storage if not in blob index.
 */
async function resolveEntry(
  id: string,
  storage: ReturnType<typeof getStorageProvider>,
): Promise<L2IndexEntry | null> {
  const stored = await storage.readL2Item(id);
  if (!stored) return null;
  const item = await readItem(id);
  if (!item) return null;
  const resolvedType = stored.type as L2ItemType;
  const resolvedName = (item as { name?: string }).name || (item as { focus?: string }).focus || id;
  const resolvedTags = ((item as { tags?: string[] }).tags || []).map((t) => t.toLowerCase());
  return {
    id,
    type: resolvedType,
    name: resolvedName,
    tags: resolvedTags,
    keywords: [],
    path: `${resolvedType}s/${id}.json`,
    visibility: 'private' as const,
  };
}

/**
 * Build diagnostics object for debug mode.
 */
interface BuildDiagnosticsOptions {
  finalResults: SearchResult[];
  debugScores: Array<{ id: string; fts_score: number; vec_score: number; combined_score: number }>;
  vecAvailable: boolean;
  useVec: boolean;
  queryEmbeddingGenerated: boolean;
  ftsCount: number;
  vecCount: number;
  indexEntryCount: number;
}

function buildDiagnostics(opts: BuildDiagnosticsOptions): SearchDiagnostics {
  const { finalResults, debugScores, vecAvailable, useVec, queryEmbeddingGenerated, ftsCount, vecCount, indexEntryCount } = opts;
  const resultIds = new Set(finalResults.map((r) => r.id));
  const filteredDebugScores = debugScores
    .filter((d) => resultIds.has(d.id))
    .sort((a, b) => b.combined_score - a.combined_score);

  return {
    search_path: 'sql',
    vec_available: vecAvailable,
    vec_used: useVec && queryEmbeddingGenerated,
    query_embedding_generated: queryEmbeddingGenerated,
    fts_candidates: ftsCount,
    vec_candidates: vecCount,
    blob_index_entries: indexEntryCount,
    results: filteredDebugScores,
  };
}

/**
 * Return results with optional diagnostics wrapper.
 */
function wrapSearchResults(
  results: SearchResult[],
  debug: boolean,
  diagnostics: Partial<SearchDiagnostics>,
): SearchResult[] | { results: SearchResult[]; diagnostics: SearchDiagnostics } {
  if (debug) {
    return {
      results,
      diagnostics: {
        search_path: 'sql',
        vec_available: diagnostics.vec_available ?? false,
        vec_used: diagnostics.vec_used ?? false,
        query_embedding_generated: diagnostics.query_embedding_generated ?? false,
        fts_candidates: diagnostics.fts_candidates ?? 0,
        vec_candidates: diagnostics.vec_candidates ?? 0,
        blob_index_entries: diagnostics.blob_index_entries ?? 0,
        results: diagnostics.results ?? [],
      },
    };
  }
  return results;
}

interface ScoreCandidateOpts {
  id: string;
  ctx: SearchContext;
  ftsScores: Map<string, number>;
  vecScores: Map<string, number>;
  hasSemanticScores: boolean;
  type?: L2ItemType;
  tags?: string[];
  domainFilter?: MemoryDomain;
}

async function scoreCandidate(
  opts: ScoreCandidateOpts,
): Promise<{ result: SearchResult; debug: { id: string; fts_score: number; vec_score: number; combined_score: number } } | null> {
  const { id, ctx, ftsScores, vecScores, hasSemanticScores, type, tags, domainFilter } = opts;
  const entry = ctx.entryMap.get(id) ?? await resolveEntry(id, ctx.storage);
  if (!entry || !filterEntryByOptions(entry, type, tags, domainFilter)) return null;

  const kw = ftsScores.get(id) || 0;
  const sem = vecScores.get(id) || 0;
  const score = computeHybridScore(kw, sem, hasSemanticScores, entry.domain);
  if (score === 0) return null;

  return {
    result: {
      id: entry.id, type: entry.type, subtype: entry.subtype,
      name: entry.name, tags: entry.tags, path: entry.path, score, domain: entry.domain,
    },
    debug: { id: entry.id, fts_score: kw, vec_score: sem, combined_score: score },
  };
}

/**
 * Search implementation: FTS5 BM25 + optional sqlite-vec cosine similarity.
 * 70/30 dominant-signal hybrid weighting when both are available.
 * For JSON/non-SQLite providers, FTS/vec return empty — degrades to blob index listing.
 */
async function searchImpl(options: SearchOptions): Promise<SearchResult[] | { results: SearchResult[]; diagnostics: SearchDiagnostics }> {
  const { query, type, tags, limit = 20, semantic = true, debug = false, domain: domainFilter } = options;
  const index = await loadIndex();
  const ctx = await buildEntryMap(index);

  // No query: return all matching type/tags/domain
  if (!query) {
    const results = await searchWithoutQuery(ctx, options, index);
    for (const r of results) await ctx.storage.recordAccess(r.id);

    return wrapSearchResults(results, debug, {
      vec_available: ctx.storage.vecAvailable(),
      vec_used: false,
      query_embedding_generated: false,
      fts_candidates: 0,
      vec_candidates: 0,
      blob_index_entries: ctx.indexEntryCount,
      results: results.map((r) => ({ id: r.id, fts_score: 0, vec_score: 0, combined_score: 1 })),
    });
  }

  // Perform FTS and vector searches
  const ftsScores = await performFtsSearch(ctx.storage, query, limit);
  const { vecScores, queryEmbeddingGenerated, useVec } = await performVecSearch(ctx.storage, query, limit, semantic);
  const hasSemanticScores = vecScores.size > 0;

  // Merge candidates and compute scores
  const candidateIds = new Set<string>([...ftsScores.keys(), ...vecScores.keys()]);
  const results: SearchResult[] = [];
  const debugScores: Array<{ id: string; fts_score: number; vec_score: number; combined_score: number }> = [];

  for (const id of candidateIds) {
    const scored = await scoreCandidate({ id, ctx, ftsScores, vecScores, hasSemanticScores, type, tags, domainFilter });
    if (!scored) continue;

    results.push(scored.result);
    if (debug) {
      debugScores.push(scored.debug);
    }
  }

  results.sort((a, b) => b.score - a.score);
  const finalResults = results.slice(0, limit);

  for (const r of finalResults) await ctx.storage.recordAccess(r.id);

  return wrapSearchResults(finalResults, debug, {
    ...buildDiagnostics({
      finalResults,
      debugScores,
      vecAvailable: ctx.storage.vecAvailable(),
      useVec,
      queryEmbeddingGenerated,
      ftsCount: ftsScores.size,
      vecCount: vecScores.size,
      indexEntryCount: ctx.indexEntryCount,
    }),
  });
}

export interface SearchOptionsWithDebug extends SearchOptions {
  debug: true;
}

/**
 * Search the L2 index by keyword, type, and/or tags.
 * Uses FTS5 BM25 + optional sqlite-vec cosine similarity.
 * For JSON provider, FTS/vec return empty and search degrades to blob index listing.
 *
 * When options.debug is true, returns { results, diagnostics } instead of bare results.
 */
export function search(options: SearchOptionsWithDebug): Promise<{ results: SearchResult[]; diagnostics: SearchDiagnostics }>;
export function search(options: SearchOptions): Promise<SearchResult[]>;
export function search(options: SearchOptions): Promise<SearchResult[] | { results: SearchResult[]; diagnostics: SearchDiagnostics }> {
  return searchImpl(options);
}

/**
 * Get the file path for an item.
 */
function _getItemPath(type: L2ItemType, id: string): string {
  let subdir: string;
  if (type === 'entity') subdir = 'entities';
  else if (type === 'session') subdir = 'sessions';
  else subdir = 'learnings';
  return path.join(L2_ROOT, subdir, `${id}.json`);
}

/**
 * Decrypt an encrypted payload using group or personal key.
 */
async function decryptPayload(
  parsed: unknown,
  storage: ReturnType<typeof getStorageProvider>,
  id: string,
): Promise<unknown> {
  const itemMeta = await storage.readL2ItemMeta(id);
  if (itemMeta?.key_version === 2 && itemMeta.group_id) {
    const { getGroupKey, groupDecrypt } = await import('./group-keys.js');
    const groupKey = await getGroupKey(itemMeta.group_id);
    if (groupKey) {
      const decrypted = await groupDecrypt(parsed as EncryptedPayload, groupKey);
      return JSON.parse(decrypted.toString('utf-8'));
    }
    throw new Error(`Cannot read group item: no PSK for group ${itemMeta.group_id}`);
  }

  const cryptoProvider = getDefaultCryptoProvider();
  if (!cryptoProvider.isUnlocked()) {
    throw new Error('Cannot read encrypted item: encryption not configured');
  }
  const decrypted = await cryptoProvider.decrypt(parsed as EncryptedPayload);
  return JSON.parse(decrypted.toString('utf-8'));
}

/**
 * Refresh TTL on item access based on domain or group policy.
 */
async function refreshTtlOnAccess(
  storage: ReturnType<typeof getStorageProvider>,
  id: string,
): Promise<void> {
  if (storage.name !== 'sqlite') return;

  const accessMeta = await storage.readL2ItemMeta(id);
  if (!accessMeta?.ttl_expires_at) return;

  if (accessMeta.visibility === 'group' && accessMeta.group_id) {
    const culture = await getGroupCulture(accessMeta.group_id);
    if (culture?.ttl_default && culture.ttl_default > 0) {
      await storage.updateTtl(id, new Date(Date.now() + culture.ttl_default * 1000).toISOString());
    }
  } else if (accessMeta.domain === 'interrupt') {
    await storage.updateTtl(id, computeInterruptTtl());
  }
}

/**
 * Validate and parse item based on type.
 */
function validateItem(itemType: string, parsed: unknown): L2Item | null {
  switch (itemType) {
    case 'entity':
      return L2EntitySchema.parse(parsed);
    case 'session':
      return L2SessionSchema.parse(parsed);
    case 'learning':
      return L2LearningSchema.parse(parsed);
    default:
      return null;
  }
}

/**
 * Read a specific L2 item by ID.
 * Handles decryption if the item is encrypted.
 */
export async function readItem(id: string): Promise<L2Item | null> {
  const storage = getStorageProvider();

  try {
    const stored = await storage.readL2Item(id);
    if (!stored) return null;

    // Determine type: SQLite storage returns type directly, JSON needs index lookup
    let itemType: string = stored.type;
    if (!itemType) {
      const index = await loadIndex();
      const entry = index.entries.find((e) => e.id === id);
      if (!entry) return null;
      itemType = entry.type;
    }

    let parsed = JSON.parse(stored.data.toString('utf-8'));

    // Handle encrypted items
    if (isEncryptedPayload(parsed)) {
      parsed = await decryptPayload(parsed, storage, id);
    }

    // Record access and refresh TTL
    await storage.recordAccess(id);
    await refreshTtlOnAccess(storage, id);

    return validateItem(itemType, parsed);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') {
      return null;
    }
    throw error;
  }
}

/**
 * Generate a unique ID.
 */
function generateId(): string {
  return `${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`;
}

/**
 * Extract item name from validated data.
 */
function extractName(type: L2ItemType, validated: L2Item): string {
  return (validated as { name?: string }).name
    || (validated as L2Session).focus
    || (validated as L2Learning).content.slice(0, 50);
}

/**
 * Build keyword source text from validated item.
 */
function buildKeywordSources(validated: L2Item, name: string): string {
  const details = (validated as { details?: Record<string, unknown> }).details;
  return [
    name,
    (validated as { summary?: string }).summary || '',
    (validated as { content?: string }).content || '',
    (validated as { context?: string }).context || '',
    ...(validated as { highlights?: string[] }).highlights || [],
    ...(validated as { aliases?: string[] }).aliases || [],
    ...(details ? extractStringValues(details) : []),
  ].join(' ');
}

/**
 * Write an L2 item (create or update).
 * Updates blob index, FTS5, embedding cache, and vec table.
 */
export interface WriteItemOptions {
  group_id?: string;
  entity_id?: string;
  domain?: MemoryDomain;
}

/**
 * Encrypt item content using group PSK, personal key, or plaintext.
 */
async function encryptItemContent(validated: L2Item, groupId?: string): Promise<string> {
  if (groupId) {
    const { getGroupKey, groupEncrypt } = await import('./group-keys.js');
    const groupKey = await getGroupKey(groupId);
    if (groupKey) {
      const plaintext = Buffer.from(JSON.stringify(validated, null, 2), 'utf-8');
      const encrypted = await groupEncrypt(plaintext, groupKey);
      return JSON.stringify(encrypted, null, 2);
    }
    console.error(`Cordelia: no PSK for group ${groupId}, storing unencrypted`);
    return JSON.stringify(validated, null, 2);
  }

  const cryptoProvider = getDefaultCryptoProvider();
  if (cryptoProvider.isUnlocked() && cryptoProvider.name !== 'none') {
    const plaintext = Buffer.from(JSON.stringify(validated, null, 2), 'utf-8');
    const encrypted = await cryptoProvider.encrypt(plaintext);
    return JSON.stringify(encrypted, null, 2);
  }

  return JSON.stringify(validated, null, 2);
}

/**
 * Update blob index, FTS5, and vec tables for an item.
 */
async function updateItemIndex(
  id: string,
  type: L2ItemType,
  validated: L2Item,
  relativePath: string,
  options: WriteItemOptions,
  domain: MemoryDomain,
  subtype?: string,
): Promise<void> {
  const storage = getStorageProvider();
  const index = await loadIndex();
  const existingIdx = index.entries.findIndex((e) => e.id === id);

  const name = extractName(type, validated);
  const tags = (validated as { tags?: string[] }).tags || [];
  const keywordSources = buildKeywordSources(validated, name);
  const lowerTags = tags.map((t) => t.toLowerCase());

  // Generate embedding
  let embedding: number[] | undefined;
  const provider = getDefaultProvider();
  if (provider.dimensions() > 0) {
    const embeddableText = buildEmbeddableText(validated, name, tags);
    const cached = await getCachedEmbedding(embeddableText, provider);
    if (cached) embedding = cached;
  }

  const indexEntry: L2IndexEntry = {
    id,
    type,
    subtype,
    name,
    tags: lowerTags,
    keywords: extractKeywords(keywordSources),
    path: relativePath,
    embedding,
    visibility: options.group_id ? 'group' : 'private',
    domain,
  };

  if (existingIdx >= 0) {
    index.entries[existingIdx] = indexEntry;
  } else {
    index.entries.push(indexEntry);
  }

  await saveIndex(index);

  // Update FTS5 and vec tables (no-op for JSON provider)
  await storage.ftsUpsert(id, name, keywordSources, lowerTags.join(' '));

  if (embedding && storage.vecAvailable()) {
    await storage.vecUpsert(id, toFloat32Array(embedding));
  }
}

export async function writeItem(
  type: L2ItemType,
  data: Partial<L2Item>,
  options: WriteItemOptions = {},
): Promise<{ success: true; id: string; ttl_expires?: string } | { error: string }> {
  const now = new Date().toISOString();
  const id = (data as { id?: string }).id || generateId();

  let validated: L2Item;
  let subtype: string | undefined;

  try {
    switch (type) {
      case 'entity': {
        validated = L2EntitySchema.parse({
          ...data,
          id,
          created_at: (data as L2Entity).created_at || now,
          updated_at: now,
        });
        subtype = (validated as L2Entity).type;
        break;
      }
      case 'session': {
        validated = L2SessionSchema.parse({
          ...data,
          id,
        });
        break;
      }
      case 'learning': {
        validated = L2LearningSchema.parse({
          ...data,
          id,
          created_at: (data as L2Learning).created_at || now,
        });
        subtype = (validated as L2Learning).type;
        break;
      }
      default:
        return { error: `unknown_type: ${type}` };
    }
  } catch (e) {
    return { error: `validation_failed: ${(e as Error).message}` };
  }

  // Determine file path (still used for index entry)
  let subdir: string;
  if (type === 'entity') subdir = 'entities';
  else if (type === 'session') subdir = 'sessions';
  else subdir = 'learnings';
  const relativePath = `${subdir}/${id}.json`;

  // Encrypt: group items use group PSK, private items use proxy personal key
  const fileContent = await encryptItemContent(validated, options.group_id);

  // Determine domain (metadata -- always set regardless of visibility)
  const domain: MemoryDomain = options.domain || inferDomainFromType(type, subtype);

  // Lifecycle policy: group culture governs group items, domain governs private items.
  // Groups are sovereign over their own information handling policies.
  let ttlExpires: string | undefined;
  if (options.group_id) {
    // Group item: culture policy is the sole TTL source
    const culture = await getGroupCulture(options.group_id);
    if (culture?.ttl_default && culture.ttl_default > 0) {
      ttlExpires = new Date(Date.now() + culture.ttl_default * 1000).toISOString();
    }
  } else if (domain === 'interrupt') {
    // Private item: domain governs lifecycle
    ttlExpires = computeInterruptTtl();
  }

  // Write via storage provider
  const storage = getStorageProvider();
  const meta: import('./storage.js').L2ItemMeta = {
    type: type as 'entity' | 'session' | 'learning',
    owner_id: options.entity_id,
    visibility: options.group_id ? 'group' : 'private',
    group_id: options.group_id,
    author_id: options.entity_id,
    key_version: options.group_id ? 2 : 1,
    domain,
    ttl_expires_at: ttlExpires,
  };
  await storage.writeL2Item(id, type, Buffer.from(fileContent, 'utf-8'), meta);

  // Update blob index, FTS5, and vec tables
  await updateItemIndex(id, type, validated, relativePath, options, domain, subtype);

  // Push group items to Rust node for P2P replication
  if (options.group_id) {
    const { getNodeBridge } = await import('./node-bridge.js');
    const bridge = getNodeBridge();
    const encryptedData = JSON.parse(fileContent);
    bridge.pushGroupItem(id, type, encryptedData, meta).catch((e) => {
      console.error(`Cordelia: node push failed: ${(e as Error).message}`);
    });
  }

  const result: { success: true; id: string; ttl_expires?: string } = { success: true, id };
  if (ttlExpires) result.ttl_expires = ttlExpires;
  return result;
}

/**
 * Delete an L2 item by ID.
 * Removes from storage, blob index, FTS, vec, and embedding cache.
 */
export async function deleteItem(id: string): Promise<{ success: true; id: string } | { error: string }> {
  const index = await loadIndex();
  const entryIdx = index.entries.findIndex((e) => e.id === id);

  if (entryIdx === -1) {
    return { error: 'not_found' };
  }

  const storage = getStorageProvider();
  await storage.deleteL2Item(id);

  // Remove from blob index
  index.entries.splice(entryIdx, 1);
  embeddingCache.delete(id);

  await saveIndex(index);

  // Remove from FTS and vec (no-op for JSON provider)
  await storage.ftsDelete(id);
  await storage.vecDelete(id);

  return { success: true, id };
}

/**
 * Check share policy: ownership, membership, role, and posture.
 * Returns an error object if sharing is not allowed, or null if allowed.
 */
async function checkSharePolicy(
  itemId: string,
  entityId: string,
  targetGroup: string,
  storage: ReturnType<typeof getStorageProvider>,
): Promise<{ error: string } | null> {
  const meta = await storage.readL2ItemMeta(itemId);
  if (!meta) {
    return { error: 'not_found' };
  }

  if (meta.owner_id !== entityId) {
    return { error: 'not_owner' };
  }

  const membership = await storage.getMembership(targetGroup, entityId);
  if (!membership) {
    return { error: 'not_member' };
  }
  if (membership.role === 'viewer') {
    return { error: 'viewer_cannot_share' };
  }
  if (membership.posture === 'emcon') {
    return { error: 'emcon_blocks_share' };
  }

  return null;
}

/**
 * Decrypt original data then re-encrypt with group PSK.
 */
async function reencryptForGroup(
  originalData: Buffer,
  targetGroup: string,
): Promise<{ data: Buffer; keyVersion: number } | { error: string }> {
  let plainData: Buffer;
  const parsed = JSON.parse(originalData.toString('utf-8'));
  if (isEncryptedPayload(parsed)) {
    const cryptoProvider = getDefaultCryptoProvider();
    if (!cryptoProvider.isUnlocked()) {
      return { error: 'encryption_locked' };
    }
    plainData = await cryptoProvider.decrypt(parsed as EncryptedPayload);
  } else {
    plainData = originalData;
  }

  const { getGroupKey, groupEncrypt } = await import('./group-keys.js');
  const groupKey = await getGroupKey(targetGroup);
  if (groupKey) {
    const encrypted = await groupEncrypt(plainData, groupKey);
    return { data: Buffer.from(JSON.stringify(encrypted, null, 2), 'utf-8'), keyVersion: 2 };
  }
  return { data: plainData, keyVersion: 1 };
}

/**
 * Share a private memory to a group (COW copy).
 * The original is never modified. A new row is created with parent_id pointing to the original.
 */
export async function shareItem(
  itemId: string,
  targetGroup: string,
  entityId: string,
): Promise<{ success: true; copy_id: string } | { error: string }> {
  const storage = getStorageProvider();

  // Policy checks
  const policyError = await checkSharePolicy(itemId, entityId, targetGroup, storage);
  if (policyError) {
    return policyError;
  }

  const meta = await storage.readL2ItemMeta(itemId);
  if (!meta) {
    return { error: 'not_found' };
  }

  // Read original data
  const original = await storage.readL2Item(itemId);
  if (!original) {
    return { error: 'not_found' };
  }

  // Decrypt and re-encrypt for group
  const reencrypted = await reencryptForGroup(original.data, targetGroup);
  if ('error' in reencrypted) {
    return reencrypted;
  }
  const cowFileContent = reencrypted.data;
  const cowKeyVersion = reencrypted.keyVersion;

  // Generate new ID for COW copy
  const copyId = generateId();
  let subdir: string;
  if (original.type === 'entity') subdir = 'entities';
  else if (original.type === 'session') subdir = 'sessions';
  else subdir = 'learnings';
  const relativePath = `${subdir}/${copyId}.json`;

  // Write COW copy
  const cowMeta = {
    type: original.type as 'entity' | 'session' | 'learning',
    owner_id: meta.owner_id || undefined,
    author_id: entityId,
    visibility: 'group' as const,
    group_id: targetGroup,
    parent_id: itemId,
    is_copy: true,
    key_version: cowKeyVersion,
  };
  await storage.writeL2Item(copyId, original.type, cowFileContent, cowMeta);

  // Update L2 index with copy entry
  const index = await loadIndex();
  const originalEntry = index.entries.find((e) => e.id === itemId);
  if (originalEntry) {
    index.entries.push({
      ...originalEntry,
      id: copyId,
      path: relativePath,
      visibility: 'group',
    });
    await saveIndex(index);
  }

  // Upsert FTS for copy
  if (originalEntry) {
    const name = originalEntry.name;
    const tags = originalEntry.tags.join(' ');
    const keywords = originalEntry.keywords.join(' ');
    await storage.ftsUpsert(copyId, name, keywords, tags);
  }

  // Push COW copy to Rust node for P2P replication
  if (cowKeyVersion === 2) {
    const { getNodeBridge } = await import('./node-bridge.js');
    const bridge = getNodeBridge();
    const encryptedData = JSON.parse(cowFileContent.toString('utf-8'));
    bridge.pushGroupItem(copyId, original.type, encryptedData, cowMeta).catch((e) => {
      console.error(`Cordelia: node push (share) failed: ${(e as Error).message}`);
    });
  }

  // Log to access_log
  await storage.logAccess({
    entity_id: entityId,
    action: 'share',
    resource_type: original.type,
    resource_id: itemId,
    group_id: targetGroup,
    detail: `shared as ${copyId} (COW copy)`,
  });

  return { success: true, copy_id: copyId };
}

/**
 * Prefetch top L2 items for faster session start (R3-012).
 * Domain-aware ordering: values first, procedural next, interrupt last.
 * Context-aware: if a binding exists for cwd, prioritize bound group's items.
 */
export async function prefetchItems(
  entityId: string,
  options: {
    cwd?: string;
    bindings?: Record<string, string>;
    limit?: number;
  } = {},
): Promise<Array<{ id: string; type: string; group_id: string | null; last_accessed_at: string | null; domain: string | null }>> {
  const storage = getStorageProvider();
  if (storage.name !== 'sqlite') return [];

  const limit = options.limit || 10;

  // Get all groups this entity belongs to
  const allGroups = await storage.listGroups();
  const memberGroups: string[] = [];
  for (const g of allGroups) {
    const m = await storage.getMembership(g.id, entityId);
    if (m) memberGroups.push(g.id);
  }

  // If context binding exists, prioritize bound group
  let boundGroupId: string | undefined;
  if (options.cwd && options.bindings) {
    const { resolveContextBinding } = await import('./policy.js');
    boundGroupId = resolveContextBinding(options.cwd, options.bindings);
  }

  const groupIds = boundGroupId
    ? [boundGroupId, ...memberGroups.filter(g => g !== boundGroupId)]
    : memberGroups;

  // Domain-aware prefetch: values first, procedural next, interrupt last
  const valueItems = await storage.getItemsByDomain(entityId, groupIds, 'value', 50);
  let remaining = limit - valueItems.length;

  let proceduralItems: Array<{ id: string; type: string; domain: string | null; group_id: string | null; last_accessed_at: string | null }> = [];
  if (remaining > 0) {
    proceduralItems = await storage.getItemsByDomain(entityId, groupIds, 'procedural', remaining);
    remaining -= proceduralItems.length;
  }

  let interruptItems: Array<{ id: string; type: string; domain: string | null; group_id: string | null; last_accessed_at: string | null }> = [];
  if (remaining > 0) {
    interruptItems = await storage.getItemsByDomain(entityId, groupIds, 'interrupt', remaining);
  }

  return [...valueItems, ...proceduralItems, ...interruptItems];
}

/**
 * Sweep legacy group culture TTL items.
 * Returns count of swept items.
 */
function parseGroupTtl(culture: string): number | null {
  try {
    const parsed = JSON.parse(culture) as { ttl_default?: number | null };
    return parsed.ttl_default && parsed.ttl_default > 0 ? parsed.ttl_default : null;
  } catch {
    return null;
  }
}

async function isItemExpiredByTtl(
  storage: ReturnType<typeof getStorageProvider>,
  itemId: string,
  ttlSeconds: number,
): Promise<boolean> {
  const stats = await storage.getAccessStats(itemId);
  if (!stats) return false;

  const refTime = stats.last_accessed_at;
  if (!refTime) return false;

  const lastAccess = new Date(refTime + 'Z').getTime();
  const ageSec = (Date.now() - lastAccess) / 1000;
  return ageSec > ttlSeconds;
}

async function sweepLegacyGroupTtl(storage: ReturnType<typeof getStorageProvider>): Promise<number> {
  let swept = 0;
  const groups = await storage.listGroups();

  for (const group of groups) {
    const ttlSeconds = parseGroupTtl(group.culture);
    if (ttlSeconds === null) continue;

    const items = await storage.listGroupItems(group.id, 10000);
    for (const item of items) {
      if (await isItemExpiredByTtl(storage, item.id, ttlSeconds)) {
        await deleteItem(item.id);
        swept++;
      }
    }
  }
  return swept;
}

/**
 * Sweep expired items using three eviction strategies:
 * 1. Interrupt TTL sweep: delete items with expired ttl_expires_at
 * 2. Procedural cap-based eviction: evict least-used items exceeding PROCEDURAL_CAP
 * 3. Legacy group culture TTL: preserved for backwards compatibility
 */
export async function sweepExpiredItems(): Promise<{ swept: number }> {
  const storage = getStorageProvider();
  if (storage.name !== 'sqlite') return { swept: 0 };

  let swept = 0;
  const now = new Date().toISOString();

  // 1. Interrupt TTL sweep
  const expired = await storage.getExpiredItems(now);
  for (const item of expired) {
    await deleteItem(item.id);
    swept++;
  }

  // 2. Procedural cap-based eviction
  const evictable = await storage.getEvictableProceduralItems(PROCEDURAL_CAP);
  for (const id of evictable) {
    await deleteItem(id);
    swept++;
  }

  // 3. Legacy group culture TTL (for items without domain-based TTL)
  swept += await sweepLegacyGroupTtl(storage);

  return { swept };
}

/**
 * Process a single item for domain reclassification.
 * Returns a change record if reclassified, or 'skipped' if no action needed.
 */
async function reclassifyItem(
  entry: { id: string; type: string },
  storage: ReturnType<typeof getStorageProvider>,
  sqliteStorage: SqliteStorageProvider,
): Promise<{ change: { id: string; from: string; to: string; reason: string } } | 'skipped'> {
  const meta = await storage.readL2ItemMeta(entry.id);
  if (!meta) {
    return 'skipped';
  }

  const currentDomain = meta.domain || 'unclassified';

  const item = await readItem(entry.id);
  if (!item) {
    return 'skipped';
  }

  let subtype: string | undefined;
  if (entry.type === 'learning') {
    subtype = (item as L2Learning).type;
  } else if (entry.type === 'entity') {
    subtype = (item as L2Entity).type;
  }

  const correctDomain = inferDomainFromType(
    entry.type as 'entity' | 'session' | 'learning',
    subtype,
  );

  if (correctDomain === currentDomain) {
    return 'skipped';
  }

  const ttl = correctDomain === 'interrupt' && !meta.ttl_expires_at
    ? computeInterruptTtl()
    : meta.ttl_expires_at;

  const db = sqliteStorage.getDatabase();
  db.prepare('UPDATE l2_items SET domain = ?, ttl_expires_at = ? WHERE id = ?')
    .run(correctDomain, ttl || null, entry.id);

  return {
    change: {
      id: entry.id,
      from: currentDomain,
      to: correctDomain,
      reason: `${entry.type}/${subtype || 'none'}`,
    },
  };
}

/**
 * Backfill domain classification by reading items through the decryption layer.
 * The V6 migration conservatively assigns all learnings to procedural, but
 * learnings with subtype "principle" should be value. This function reads each
 * item, checks the actual subtype, and reclassifies where needed.
 */
export async function backfillDomains(): Promise<{
  total: number;
  reclassified: number;
  skipped: number;
  errors: number;
  changes: Array<{ id: string; from: string; to: string; reason: string }>;
}> {
  const storage = getStorageProvider();
  if (storage.name !== 'sqlite') {
    return { total: 0, reclassified: 0, skipped: 0, errors: 0, changes: [] };
  }

  const sqliteStorage = storage as SqliteStorageProvider;
  const allItems = sqliteStorage.listL2ItemIds();
  let reclassified = 0;
  let skipped = 0;
  let errors = 0;
  const changes: Array<{ id: string; from: string; to: string; reason: string }> = [];

  for (const entry of allItems) {
    try {
      const result = await reclassifyItem(entry, storage, sqliteStorage);
      if (result === 'skipped') {
        skipped++;
      } else {
        changes.push(result.change);
        reclassified++;
      }
    } catch (e) {
      console.error(`Cordelia: domain backfill error for ${entry.id}: ${(e as Error).message}`);
      errors++;
    }
  }

  return { total: allItems.length, reclassified, skipped, errors, changes };
}

/**
 * Process a single item for vec backfill: rebuild FTS and optionally generate embedding.
 */
async function processVecBackfillItem(
  entry: { id: string; type: string },
  sqliteStorage: SqliteStorageProvider,
  provider: EmbeddingProvider,
  canEmbed: boolean,
): Promise<'cached' | 'generated' | 'skipped' | 'fts_only' | 'error'> {
  const item = await readItem(entry.id);
  if (!item) {
    return 'skipped';
  }

  const name = extractName(entry.type as L2ItemType, item);
  const tags = (item as { tags?: string[] }).tags || [];

  // Rebuild FTS entry with current field extraction (includes details)
  const keywordSources = buildKeywordSources(item, name);
  const lowerTags = tags.map((t) => t.toLowerCase());
  await sqliteStorage.ftsUpsert(entry.id, name, keywordSources, lowerTags.join(' '));

  if (!canEmbed) {
    return 'fts_only';
  }

  // Rebuild vec entry
  const embeddableText = buildEmbeddableText(item, name, tags);
  const hash = contentHash(embeddableText);
  const existingCached = await sqliteStorage.getEmbedding(hash, provider.name, provider.modelName());

  let embedding: number[];
  let result: 'cached' | 'generated';
  if (existingCached) {
    embedding = bufferToEmbedding(existingCached);
    result = 'cached';
  } else {
    const gen = await getCachedEmbedding(embeddableText, provider);
    if (!gen) {
      return 'skipped';
    }
    embedding = gen;
    result = 'generated';
  }

  await sqliteStorage.vecUpsert(entry.id, toFloat32Array(embedding));
  return result;
}

/**
 * Backfill l2_vec from existing L2 index entries.
 * Uses cached embeddings where available, generates new ones via provider.
 * Returns counts of items processed, cached hits, generated, and errors.
 */
export async function backfillVec(): Promise<{
  total: number;
  cached: number;
  generated: number;
  skipped: number;
  errors: number;
  fts_updated: number;
}> {
  const storage = getStorageProvider();
  if (storage.name !== 'sqlite') {
    return { total: 0, cached: 0, generated: 0, skipped: 0, errors: 0, fts_updated: 0 };
  }

  const sqliteStorage = storage as SqliteStorageProvider;
  const provider = getDefaultProvider();
  const canEmbed = sqliteStorage.vecAvailable() && provider.dimensions() > 0;

  // Iterate l2_items directly (not the legacy l2_index blob)
  const allItems = sqliteStorage.listL2ItemIds();
  let cached = 0;
  let generated = 0;
  let skipped = 0;
  let errors = 0;
  let ftsUpdated = 0;

  for (const entry of allItems) {
    try {
      const result = await processVecBackfillItem(entry, sqliteStorage, provider, canEmbed);
      switch (result) {
        case 'cached': cached++; ftsUpdated++; break;
        case 'generated': generated++; ftsUpdated++; break;
        case 'fts_only': ftsUpdated++; break;
        case 'skipped': skipped++; break;
        case 'error': errors++; break;
      }
    } catch (e) {
      console.error(`Cordelia: backfill error for ${entry.id}: ${(e as Error).message}`);
      errors++;
    }
  }

  return { total: allItems.length, cached, generated, skipped, errors, fts_updated: ftsUpdated };
}

/**
 * Process a single file for index rebuild: read, parse, decrypt, validate,
 * optionally re-encrypt, extract metadata, and generate embedding.
 * Returns null on error (file is skipped).
 */
async function processFileForIndex(
  filePath: string,
  file: string,
  type: L2ItemType,
  dir: string,
  cryptoProvider: ReturnType<typeof getDefaultCryptoProvider>,
  shouldEncrypt: boolean,
  storage: ReturnType<typeof getStorageProvider>,
): Promise<{ entry: L2IndexEntry; encrypted: boolean } | null> {
  const content = await fs.readFile(filePath, 'utf-8');
  let parsed = JSON.parse(content);
  let wasEncrypted = false;

  // Handle encrypted items
  if (isEncryptedPayload(parsed)) {
    if (!cryptoProvider.isUnlocked()) {
      return null;
    }
    const decrypted = await cryptoProvider.decrypt(parsed as EncryptedPayload);
    parsed = JSON.parse(decrypted.toString('utf-8'));
    wasEncrypted = true;
  }

  // Validate and extract metadata
  const validated = validateItem(type, parsed);
  if (!validated) return null;

  let subtype: string | undefined;
  if (type === 'entity') {
    subtype = (validated as L2Entity).type;
  } else if (type === 'learning') {
    subtype = (validated as L2Learning).type;
  }

  // Re-encrypt unencrypted items if requested
  let didEncrypt = false;
  if (shouldEncrypt && !wasEncrypted) {
    const plaintext = Buffer.from(JSON.stringify(validated, null, 2), 'utf-8');
    const encrypted = await cryptoProvider.encrypt(plaintext);
    await fs.writeFile(filePath, JSON.stringify(encrypted, null, 2), 'utf-8');
    didEncrypt = true;
  }

  const name = extractName(type, validated);
  const tags = (validated as { tags?: string[] }).tags || [];
  const lowerTags = tags.map((t) => t.toLowerCase());
  const keywordSources = buildKeywordSources(validated, name);

  // Generate/cache embedding
  let embedding: number[] | undefined;
  const provider = getDefaultProvider();
  if (provider.dimensions() > 0) {
    const embeddableText = buildEmbeddableText(validated, name, tags);
    const cached = await getCachedEmbedding(embeddableText, provider);
    if (cached) embedding = cached;
  }

  const itemId = (validated as { id: string }).id;

  // Populate FTS5 and vec tables
  await storage.ftsUpsert(itemId, name, keywordSources, lowerTags.join(' '));
  if (embedding && storage.vecAvailable()) {
    await storage.vecUpsert(itemId, toFloat32Array(embedding));
  }

  return {
    entry: {
      id: itemId,
      type,
      subtype,
      name,
      tags: lowerTags,
      keywords: extractKeywords(keywordSources),
      path: `${dir}/${file}`,
      embedding,
      visibility: 'private',
    },
    encrypted: didEncrypt,
  };
}

async function scanDirectoryForIndex(
  dir: string,
  type: L2ItemType,
  cryptoProvider: ReturnType<typeof getDefaultCryptoProvider>,
  shouldEncrypt: boolean,
  storage: ReturnType<typeof getStorageProvider>,
): Promise<Array<{ entry: L2IndexEntry; encrypted: boolean }>> {
  const dirPath = path.join(L2_ROOT, dir);
  const results: Array<{ entry: L2IndexEntry; encrypted: boolean }> = [];

  try {
    const files = await fs.readdir(dirPath);
    for (const file of files) {
      if (!file.endsWith('.json')) continue;
      try {
        const result = await processFileForIndex(path.join(dirPath, file), file, type, dir, cryptoProvider, shouldEncrypt, storage);
        if (result) results.push(result);
      } catch {
        // Skip invalid files
      }
    }
  } catch {
    // Directory doesn't exist, skip
  }

  return results;
}

/**
 * Rebuild the index by scanning all files.
 * Populates blob index, FTS5, and vec tables.
 * Optionally re-encrypts unencrypted items if crypto is enabled.
 */
export async function rebuildIndex(options?: { reencrypt?: boolean }): Promise<{ success: true; count: number; encrypted?: number } | { error: string }> {
  const entries: L2IndexEntry[] = [];
  const subdirs: Array<{ dir: string; type: L2ItemType }> = [
    { dir: 'entities', type: 'entity' },
    { dir: 'sessions', type: 'session' },
    { dir: 'learnings', type: 'learning' },
  ];
  const cryptoProvider = getDefaultCryptoProvider();
  const shouldEncrypt = options?.reencrypt && cryptoProvider.isUnlocked() && cryptoProvider.name !== 'none';
  let encryptedCount = 0;
  const storage = getStorageProvider();

  for (const { dir, type } of subdirs) {
    const dirEntries = await scanDirectoryForIndex(dir, type, cryptoProvider, shouldEncrypt ?? false, storage);
    for (const e of dirEntries) {
      entries.push(e.entry);
      if (e.encrypted) encryptedCount++;
    }
  }

  const index: L2Index = {
    version: 1,
    updated_at: new Date().toISOString(),
    entries,
  };

  await saveIndex(index);

  const result: { success: true; count: number; encrypted?: number } = { success: true, count: entries.length };
  if (shouldEncrypt) {
    result.encrypted = encryptedCount;
  }
  return result;
}
