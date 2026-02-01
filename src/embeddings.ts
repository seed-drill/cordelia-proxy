/**
 * Project Cordelia - Embedding Provider Module
 *
 * Pluggable embedding generation for semantic search.
 * Default: Ollama (local, private, M-series optimized)
 *
 * Configuration via environment:
 *   CORDELIA_EMBEDDING_PROVIDER: 'ollama' | 'openai' | 'none' (default: 'ollama')
 *   CORDELIA_EMBEDDING_URL: provider URL (default: 'http://localhost:11434')
 *   CORDELIA_EMBEDDING_MODEL: model name (default: 'nomic-embed-text')
 */

export interface EmbeddingProvider {
  name: string;
  embed(text: string): Promise<number[]>;
  embedBatch(texts: string[]): Promise<number[][]>;
  dimensions(): number;
  isAvailable(): Promise<boolean>;
  modelName(): string;
}

export interface EmbeddingConfig {
  provider: 'ollama' | 'openai' | 'none';
  url: string;
  model: string;
}

/**
 * Get configuration from environment.
 */
export function getConfig(): EmbeddingConfig {
  return {
    provider: (process.env.CORDELIA_EMBEDDING_PROVIDER as EmbeddingConfig['provider']) || 'ollama',
    url: process.env.CORDELIA_EMBEDDING_URL || 'http://localhost:11434',
    model: process.env.CORDELIA_EMBEDDING_MODEL || 'nomic-embed-text',
  };
}

/**
 * Ollama embedding provider.
 * Local, private, Metal-accelerated on Apple Silicon.
 */
export class OllamaProvider implements EmbeddingProvider {
  name = 'ollama';
  private url: string;
  private model: string;
  private dims: number | null = null;

  constructor(url: string, model: string) {
    this.url = url;
    this.model = model;
  }

  async embed(text: string): Promise<number[]> {
    const response = await fetch(`${this.url}/api/embeddings`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ model: this.model, prompt: text }),
    });

    if (!response.ok) {
      throw new Error(`Ollama embedding failed: ${response.status} ${response.statusText}`);
    }

    const data = await response.json();
    const embedding = data.embedding as number[];

    // Cache dimensions on first call
    if (this.dims === null) {
      this.dims = embedding.length;
    }

    return embedding;
  }

  async embedBatch(texts: string[]): Promise<number[][]> {
    // Ollama doesn't have native batch - parallelize individual calls
    return Promise.all(texts.map((t) => this.embed(t)));
  }

  dimensions(): number {
    // nomic-embed-text is 768 dims, but verify on first embed
    return this.dims ?? 768;
  }

  async isAvailable(): Promise<boolean> {
    try {
      const response = await fetch(`${this.url}/api/tags`, { method: 'GET' });
      if (!response.ok) return false;

      const data = await response.json();
      const models = (data.models || []) as Array<{ name: string }>;
      return models.some((m) => m.name.startsWith(this.model));
    } catch {
      return false;
    }
  }

  modelName(): string {
    return this.model;
  }
}

/**
 * Null provider - embeddings disabled.
 */
export class NullProvider implements EmbeddingProvider {
  name = 'none';

  async embed(_text: string): Promise<number[]> {
    return [];
  }

  async embedBatch(texts: string[]): Promise<number[][]> {
    return texts.map(() => []);
  }

  dimensions(): number {
    return 0;
  }

  async isAvailable(): Promise<boolean> {
    return true;
  }

  modelName(): string {
    return 'none';
  }
}

/**
 * Get the configured embedding provider.
 */
export function getProvider(config?: EmbeddingConfig): EmbeddingProvider {
  const cfg = config ?? getConfig();

  switch (cfg.provider) {
    case 'ollama':
      return new OllamaProvider(cfg.url, cfg.model);
    case 'none':
      return new NullProvider();
    default:
      // Future: add openai, voyage, etc.
      return new NullProvider();
  }
}

// Singleton instance for convenience
let defaultProvider: EmbeddingProvider | null = null;

export function getDefaultProvider(): EmbeddingProvider {
  if (!defaultProvider) {
    defaultProvider = getProvider();
  }
  return defaultProvider;
}

/**
 * Cosine similarity between two vectors.
 */
export function cosineSimilarity(a: number[], b: number[]): number {
  if (a.length !== b.length || a.length === 0) {
    return 0;
  }

  let dot = 0;
  let magA = 0;
  let magB = 0;

  for (let i = 0; i < a.length; i++) {
    dot += a[i] * b[i];
    magA += a[i] * a[i];
    magB += b[i] * b[i];
  }

  const magnitude = Math.sqrt(magA) * Math.sqrt(magB);
  return magnitude === 0 ? 0 : dot / magnitude;
}

/**
 * Generate searchable text from an item's fields.
 * Combines relevant fields for embedding.
 */
/**
 * Recursively extract string values from an object/array.
 * Flattens nested structures into a single array of strings.
 */
export function extractStringValues(obj: unknown): string[] {
  if (typeof obj === 'string') return [obj];
  if (Array.isArray(obj)) return obj.flatMap(extractStringValues);
  if (obj && typeof obj === 'object') {
    return Object.values(obj).flatMap(extractStringValues);
  }
  return [];
}

export function getEmbeddableText(fields: {
  name?: string;
  summary?: string;
  content?: string;
  context?: string;
  focus?: string;
  highlights?: string[];
  aliases?: string[];
  tags?: string[];
  details?: Record<string, unknown>;
}): string {
  const parts: string[] = [];

  if (fields.name) parts.push(fields.name);
  if (fields.summary) parts.push(fields.summary);
  if (fields.content) parts.push(fields.content);
  if (fields.context) parts.push(fields.context);
  if (fields.focus) parts.push(fields.focus);
  if (fields.highlights?.length) parts.push(fields.highlights.join('. '));
  if (fields.aliases?.length) parts.push(fields.aliases.join(', '));
  if (fields.details && Object.keys(fields.details).length > 0) {
    parts.push(extractStringValues(fields.details).join('. '));
  }
  if (fields.tags?.length) parts.push(fields.tags.join(', '));

  return parts.join('. ');
}
