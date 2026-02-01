# Cordelia Search Architecture

Design notes for the hybrid search system in `src/l2.ts`.

## Overview

L2 warm search combines two signals:

- **Keyword (FTS5 BM25)**: exact token matching via SQLite FTS5. Strong for specific terms, names, numbers, identifiers.
- **Semantic (sqlite-vec cosine)**: embedding similarity via Ollama nomic-embed-text. Strong for conceptual/natural-language queries.

A legacy in-memory path exists for the JSON storage provider but follows the same scoring logic.

## Hybrid Scoring Formula

```
score = 0.7 * max(semantic, keyword) + 0.3 * min(semantic, keyword)
```

**Dominant-signal hybrid**: the stronger signal for each result leads at 70%, the weaker boosts at 30%. This replaced a static `0.7 * semantic + 0.3 * keyword` weighting that always favoured semantic scores.

### Why not static 70/30?

The original static formula assumed semantic would always be the better discriminator. In practice:

- **Keyword-precise queries** (e.g. "386", a person's name, an error code) produce weak semantic scores because the embedding doesn't capture the specific association. FTS matches the literal token. Static 70/30 drowns the strong FTS signal.
- **Conceptual queries** (e.g. "how does trust calibration work") produce strong semantic scores and weak/zero FTS scores. Static 70/30 works fine here.

The dominant-signal formula adapts per-result: whichever signal is stronger leads. Items matching on both signals get the full combined score.

### Worked example

Query: `"386"` against a memory containing `"386DX33"` in its content.

| Signal | Score | Static 70/30 | Dominant-signal |
|--------|-------|-------------|-----------------|
| semantic | 0.25 | 0.175 | 0.075 (minor) |
| keyword | 0.80 | 0.240 | 0.560 (leads) |
| **combined** | | **0.415** | **0.635** |

With static weighting, 0.415 sits in the noise floor. With dominant-signal, 0.635 clearly separates from irrelevant results (~0.17).

## Distance Metric

sqlite-vec tables use **cosine distance** (`distance_metric=cosine`), not the default L2/Euclidean. This is critical: normalised embeddings from models like nomic-embed-text produce L2 distances of 16-17, which breaks the `1 - distance` similarity conversion (clamps to 0).

Migration is handled automatically by `loadSqliteVec()` in `storage-sqlite.ts`. A sentinel row in `l2_vec_meta` (`distance_metric=cosine`) prevents re-migration.

## FTS5 Indexing

Indexed fields per item:
- `name` (title/identifier)
- `content` (concatenation of summary, content, context, highlights, aliases, details values)
- `tags` (space-separated lowercase)

The `details` field (arbitrary key-value metadata on entities/learnings) is recursively extracted via `extractStringValues()` and included in FTS content. This was added in session 70 to ensure metadata like `"386DX33"` or `"russell_connection"` is searchable.

## Embedding Pipeline

1. **Text assembly**: `getEmbeddableText()` concatenates name, summary, content, context, highlights, aliases, details, and tags.
2. **Content hashing**: SHA-256 of the assembled text, used as cache key.
3. **Cache check**: `embedding_cache` table in SQLite (keyed by hash + provider + model).
4. **Generation**: Ollama `nomic-embed-text` (768 dimensions) if no cache hit.
5. **Storage**: Written to both `embedding_cache` (for future backfills) and `l2_vec` (for search).

### Backfill

After schema changes affecting what feeds into embeddings or FTS, run `memory_backfill_embeddings` after server restart. The backfill:
- Iterates all `l2_items`
- Rebuilds FTS entries with current field extraction
- Rebuilds vec entries using cached embeddings where possible
- Generates new embeddings only when content hash has changed

## Search Paths

### SQL path (default for SQLite provider)

1. FTS5 BM25 query (over-fetches 3x limit for merging)
2. sqlite-vec cosine similarity query (over-fetches 3x limit)
3. Merge candidate sets, apply type/tag filters
4. Score each candidate with dominant-signal formula
5. Sort by score, truncate to limit

### Legacy path (JSON provider fallback)

1. In-memory keyword scoring (name match, keyword overlap, tag overlap)
2. Optional in-memory cosine similarity against cached embeddings
3. Same dominant-signal formula for combining scores

## Future Considerations

- **Reciprocal Rank Fusion (RRF)**: rank-based merging as an alternative to score-based. Scale-invariant, no weight tuning needed. Worth evaluating if score distributions shift with different embedding models.
- **Query-type detection**: classify queries as keyword-like vs conceptual to further tune behaviour. The dominant-signal formula reduces the need for this but doesn't eliminate it.
- **Working set model (R4)**: Denning's model for adaptive L1 sizing could also inform search result ranking by recency/frequency of access.

---

*Last updated: 2026-02-01*
