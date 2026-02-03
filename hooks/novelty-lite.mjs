/**
 * Cordelia - Lightweight Novelty Detection for Hooks
 *
 * Pure JS port of core patterns from src/novelty.ts.
 * No dependencies, fast startup. Used by pre-compact hook.
 */

/**
 * Novelty patterns: [regex, signal, confidence, target?]
 */
const NOVELTY_PATTERNS = [
  // Corrections - high signal
  [/actually[,\s]+(?:i|my|we|it'?s)/i, 'correction', 0.9],
  [/that'?s (?:not quite|wrong|incorrect)/i, 'correction', 0.9],
  [/let me correct/i, 'correction', 0.9],
  [/to clarify[,:]?\s/i, 'correction', 0.8],
  [/i (?:meant|mean)\s/i, 'correction', 0.7],

  // Preferences
  [/i (?:prefer|like|want|need)\s/i, 'preference', 0.8, 'prefs'],
  [/(?:always|never|usually)\s+(?:do|use|want)/i, 'preference', 0.7, 'prefs'],
  [/my (?:preference|style|approach) is/i, 'preference', 0.9, 'prefs'],
  [/don'?t (?:like|want|need)/i, 'preference', 0.7, 'prefs'],

  // New entities
  [/(?:this is|meet|introducing)\s+([A-Z][a-z]+)/i, 'entity_new', 0.8],
  [/new (?:project|initiative|venture)(?:\s+called)?\s+/i, 'entity_new', 0.9, 'active'],
  [/working with\s+([A-Z][a-z]+(?:\s+[A-Z][a-z]+)?)/i, 'entity_new', 0.6],

  // Decisions
  [/(?:let'?s|we'?ll|i'?ll|decided to)\s+(?:go with|use|do)/i, 'decision', 0.8, 'active.notes'],
  [/the decision is/i, 'decision', 0.9, 'active.notes'],
  [/we'?re going (?:to|with)/i, 'decision', 0.7, 'active.notes'],

  // Insights
  [/i'?ve (?:noticed|realized|learned)/i, 'insight', 0.9, 'active.notes'],
  [/(?:key|important) (?:insight|learning|takeaway)/i, 'insight', 0.9, 'active.notes'],
  [/pattern (?:i'?ve|we'?ve) (?:seen|noticed)/i, 'insight', 0.8, 'active.notes'],
  [/this (?:reminds me|connects to|relates to)/i, 'insight', 0.6],

  // Blockers
  [/(?:blocked|stuck|waiting) (?:on|by|for)/i, 'blocker', 0.9, 'active.blockers'],
  [/(?:blocker|impediment|obstacle):/i, 'blocker', 0.9, 'active.blockers'],
  [/can'?t (?:proceed|continue|move forward)/i, 'blocker', 0.8, 'active.blockers'],
  [/unblocked|resolved the/i, 'blocker', 0.8, 'active.blockers'],

  // References
  [/(?:read|reading|influenced by)\s+["']?([A-Z][^"']+)["']?\s+by\s+/i, 'reference', 0.9, 'identity.key_refs'],
  [/(?:dennett|hofstadter|banks|ries|shannon|pkd|minsky)/i, 'reference', 0.7, 'identity.key_refs'],

  // Working patterns
  [/(?:when we|how we|the way we)\s+work/i, 'working_pattern', 0.8, 'active.notes'],
  [/our (?:process|workflow|approach)/i, 'working_pattern', 0.7, 'active.notes'],

  // Meta-learning
  [/(?:your|my|our)\s+superpower/i, 'meta_learning', 0.9, 'active.notes'],
  [/complement(?:ary|ing)\s+(?:skills|abilities|strengths)/i, 'meta_learning', 0.9, 'active.notes'],
];

/**
 * Noise patterns - skip these entirely
 */
const NOISE_PATTERNS = [
  /^(?:ok|okay|got it|thanks|sure|yes|no|right)\.?$/i,
  /^(?:sounds good|makes sense|understood)\.?$/i,
  /read (?:this|the) file/i,
  /run (?:this|the) (?:command|script|test)/i,
  /let me (?:check|look|see)/i,
  /^done\.?$/i,
];

/**
 * Extract the sentence containing a match.
 */
function extractSentence(text, matchIndex) {
  const sentenceEnd = /[.!?\n]/g;
  let lastEnd = 0;
  let match;

  while ((match = sentenceEnd.exec(text)) !== null) {
    if (matchIndex >= lastEnd && matchIndex < match.index + 1) {
      return text.slice(lastEnd, match.index + 1).trim();
    }
    lastEnd = match.index + 1;
  }

  // Remaining text
  if (matchIndex >= lastEnd) {
    return text.slice(lastEnd).trim();
  }

  // Fallback
  const start = Math.max(0, matchIndex - 100);
  const end = Math.min(text.length, matchIndex + 100);
  return text.slice(start, end).trim();
}

/**
 * Analyze a single message for novelty signals.
 * Returns { signals: string[], extracts: [{signal, content, confidence, target}] }
 */
export function analyzeText(text) {
  const trimmed = text.trim();

  // Check noise first
  for (const pattern of NOISE_PATTERNS) {
    if (pattern.test(trimmed)) {
      return { signals: [], extracts: [] };
    }
  }

  const signals = [];
  const extracts = [];
  const seenContent = new Set();

  for (const [pattern, signal, confidence, target] of NOVELTY_PATTERNS) {
    const match = trimmed.match(pattern);
    if (match) {
      if (!signals.includes(signal)) {
        signals.push(signal);
      }

      const sentence = extractSentence(trimmed, match.index || 0);
      const normalized = sentence.toLowerCase();

      if (!seenContent.has(normalized)) {
        seenContent.add(normalized);
        extracts.push({ signal, content: sentence, confidence, target });
      }
    }
  }

  return { signals, extracts };
}

/**
 * Analyze multiple messages and return aggregated high-confidence extracts.
 * @param {string[]} messages - Array of message texts
 * @param {number} threshold - Minimum confidence for inclusion (default 0.7)
 * @returns {{ signals: string[], suggestions: Array<{signal, content, confidence, target}> }}
 */
export function analyzeMessages(messages, threshold = 0.7) {
  const allSignals = new Set();
  const suggestions = [];
  const seenContent = new Set();

  for (const msg of messages) {
    const result = analyzeText(msg);
    for (const s of result.signals) allSignals.add(s);

    for (const extract of result.extracts) {
      if (extract.confidence >= threshold) {
        const normalized = extract.content.toLowerCase();
        if (!seenContent.has(normalized)) {
          seenContent.add(normalized);
          suggestions.push(extract);
        }
      }
    }
  }

  return { signals: [...allSignals], suggestions };
}
