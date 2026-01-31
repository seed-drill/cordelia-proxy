/**
 * Project Cordelia - Novelty Detection
 *
 * Heuristic-based filtering to identify high-information-density content
 * that should be persisted to memory. Library of Babel principle:
 * meaning is rare, ruthlessly curate.
 */

/**
 * Novelty signal types - what kind of novel information was detected
 */
export type NoveltySignal =
  | 'correction'           // User corrected Claude's understanding
  | 'preference'           // User expressed a preference
  | 'entity_new'           // New person, project, concept introduced
  | 'entity_update'        // Update to known entity
  | 'decision'             // Decision was made
  | 'insight'              // Pattern recognition, realization
  | 'blocker'              // Blocker identified or resolved
  | 'reference'            // New key reference (book, person, concept)
  | 'working_pattern'      // How we work together
  | 'meta_learning';       // Learning about the collaboration itself

/**
 * Result of novelty analysis on a piece of text
 */
export interface NoveltyResult {
  signals: NoveltySignal[];
  score: number;           // 0-1, higher = more novel
  extracts: NoveltyExtract[];
}

/**
 * Extracted content that should potentially be persisted
 */
export interface NoveltyExtract {
  signal: NoveltySignal;
  content: string;
  confidence: number;      // 0-1
  target?: string;         // Where in L1 this might go (e.g., "identity.key_refs", "active.notes")
}

/**
 * Patterns for detecting novelty signals
 * Format: [pattern, signal, confidence, target?]
 */
const NOVELTY_PATTERNS: Array<[RegExp, NoveltySignal, number, string?]> = [
  // Corrections - high signal
  [/actually[,\s]+(?:i|my|we|it['']?s)/i, 'correction', 0.9],
  [/that['']?s (?:not quite|wrong|incorrect)/i, 'correction', 0.9],
  [/let me correct/i, 'correction', 0.9],
  [/to clarify[,:]?\s/i, 'correction', 0.8],
  [/i (?:meant|mean)\s/i, 'correction', 0.7],

  // Preferences
  [/i (?:prefer|like|want|need)\s/i, 'preference', 0.8, 'prefs'],
  [/(?:always|never|usually)\s+(?:do|use|want)/i, 'preference', 0.7, 'prefs'],
  [/my (?:preference|style|approach) is/i, 'preference', 0.9, 'prefs'],
  [/don['']?t (?:like|want|need)/i, 'preference', 0.7, 'prefs'],

  // New entities - people, projects, concepts
  [/(?:this is|meet|introducing)\s+([A-Z][a-z]+)/i, 'entity_new', 0.8],
  [/new (?:project|initiative|venture)(?:\s+called)?\s+/i, 'entity_new', 0.9, 'active'],
  [/working with\s+([A-Z][a-z]+(?:\s+[A-Z][a-z]+)?)/i, 'entity_new', 0.6],

  // Decisions
  [/(?:let['']?s|we['']?ll|i['']?ll|decided to)\s+(?:go with|use|do)/i, 'decision', 0.8],
  [/the decision is/i, 'decision', 0.9],
  [/we['']?re going (?:to|with)/i, 'decision', 0.7],

  // Insights and realizations
  [/i['']?ve (?:noticed|realized|learned)/i, 'insight', 0.9, 'active.notes'],
  [/(?:key|important) (?:insight|learning|takeaway)/i, 'insight', 0.9, 'active.notes'],
  [/pattern (?:i['']?ve|we['']?ve) (?:seen|noticed)/i, 'insight', 0.8, 'active.notes'],
  [/this (?:reminds me|connects to|relates to)/i, 'insight', 0.6],

  // Blockers
  [/(?:blocked|stuck|waiting) (?:on|by|for)/i, 'blocker', 0.9, 'active.blockers'],
  [/(?:blocker|impediment|obstacle):/i, 'blocker', 0.9, 'active.blockers'],
  [/can['']?t (?:proceed|continue|move forward)/i, 'blocker', 0.8, 'active.blockers'],
  [/unblocked|resolved the/i, 'blocker', 0.8, 'active.blockers'],

  // Key references
  [/(?:read|reading|influenced by)\s+["']?([A-Z][^"']+)["']?\s+by\s+/i, 'reference', 0.9, 'identity.key_refs'],
  [/(?:dennett|hofstadter|banks|ries|shannon|pkd)/i, 'reference', 0.7, 'identity.key_refs'],
  [/(?:hero|influence|inspiration)(?:\s+(?:is|of mine))?/i, 'reference', 0.7, 'identity.key_refs'],

  // Working patterns
  [/(?:when we|how we|the way we)\s+work/i, 'working_pattern', 0.8, 'active.notes'],
  [/our (?:process|workflow|approach)/i, 'working_pattern', 0.7, 'active.notes'],
  [/minute manager/i, 'working_pattern', 0.9, 'active.notes'],

  // Meta-learning about collaboration
  [/(?:your|my|our)\s+superpower/i, 'meta_learning', 0.9, 'active.notes'],
  [/complement(?:ary|ing)\s+(?:skills|abilities|strengths|superpowers?)/i, 'meta_learning', 0.9, 'active.notes'],
  [/working together we/i, 'meta_learning', 0.8, 'active.notes'],
];

/**
 * Anti-patterns - content that is low novelty (skip)
 */
const NOISE_PATTERNS: RegExp[] = [
  /^(?:ok|okay|got it|thanks|sure|yes|no|right)\.?$/i,
  /^(?:sounds good|makes sense|understood)\.?$/i,
  /read (?:this|the) file/i,
  /run (?:this|the) (?:command|script|test)/i,
  /let me (?:check|look|see)/i,
  /^done\.?$/i,
];

/**
 * Analyze text for novelty signals
 */
export function analyzeNovelty(text: string): NoveltyResult {
  const signals: NoveltySignal[] = [];
  const extracts: NoveltyExtract[] = [];
  let totalScore = 0;
  let matchCount = 0;

  // Check if this is noise first
  for (const pattern of NOISE_PATTERNS) {
    if (pattern.test(text.trim())) {
      return { signals: [], score: 0, extracts: [] };
    }
  }

  // Check each novelty pattern
  for (const [pattern, signal, confidence, target] of NOVELTY_PATTERNS) {
    const match = text.match(pattern);
    if (match) {
      if (!signals.includes(signal)) {
        signals.push(signal);
      }

      // Extract the sentence containing the match
      const sentenceMatch = extractSentence(text, match.index || 0);

      extracts.push({
        signal,
        content: sentenceMatch,
        confidence,
        target,
      });

      totalScore += confidence;
      matchCount++;
    }
  }

  // Normalize score to 0-1 range, cap at 1
  const score = matchCount > 0 ? Math.min(totalScore / matchCount, 1) : 0;

  // Deduplicate extracts by content
  const uniqueExtracts = dedupeExtracts(extracts);

  return { signals, score, extracts: uniqueExtracts };
}

/**
 * Extract the sentence containing a match
 */
function extractSentence(text: string, matchIndex: number): string {
  // Find sentence boundaries (., !, ?, or newlines)
  const sentenceEnd = /[.!?\n]/g;
  const sentences: Array<{ start: number; end: number; text: string }> = [];

  let lastEnd = 0;
  let match;

  while ((match = sentenceEnd.exec(text)) !== null) {
    sentences.push({
      start: lastEnd,
      end: match.index + 1,
      text: text.slice(lastEnd, match.index + 1).trim(),
    });
    lastEnd = match.index + 1;
  }

  // Add any remaining text
  if (lastEnd < text.length) {
    sentences.push({
      start: lastEnd,
      end: text.length,
      text: text.slice(lastEnd).trim(),
    });
  }

  // Find which sentence contains the match
  for (const sentence of sentences) {
    if (matchIndex >= sentence.start && matchIndex < sentence.end) {
      return sentence.text;
    }
  }

  // Fallback: return first 200 chars around the match
  const start = Math.max(0, matchIndex - 100);
  const end = Math.min(text.length, matchIndex + 100);
  return text.slice(start, end).trim();
}

/**
 * Deduplicate extracts by content similarity
 */
function dedupeExtracts(extracts: NoveltyExtract[]): NoveltyExtract[] {
  const seen = new Set<string>();
  return extracts.filter((e) => {
    const normalized = e.content.toLowerCase().trim();
    if (seen.has(normalized)) {
      return false;
    }
    seen.add(normalized);
    return true;
  });
}

/**
 * Batch analyze multiple messages and return aggregated results
 */
export function analyzeSession(messages: string[]): NoveltyResult {
  const allSignals: NoveltySignal[] = [];
  const allExtracts: NoveltyExtract[] = [];
  let totalScore = 0;
  let nonZeroCount = 0;

  for (const msg of messages) {
    const result = analyzeNovelty(msg);
    if (result.score > 0) {
      allSignals.push(...result.signals);
      allExtracts.push(...result.extracts);
      totalScore += result.score;
      nonZeroCount++;
    }
  }

  // Unique signals
  const uniqueSignals = [...new Set(allSignals)];

  // Average score across non-noise messages
  const avgScore = nonZeroCount > 0 ? totalScore / nonZeroCount : 0;

  return {
    signals: uniqueSignals,
    score: avgScore,
    extracts: dedupeExtracts(allExtracts),
  };
}

/**
 * Filter extracts to only high-confidence items for persistence
 */
export function filterForPersistence(
  result: NoveltyResult,
  threshold = 0.7
): NoveltyExtract[] {
  return result.extracts.filter((e) => e.confidence >= threshold);
}
