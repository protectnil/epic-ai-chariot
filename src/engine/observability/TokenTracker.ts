/**
 * @epicai/chariot — Token & Cost Tracker
 * Tracks token usage and estimated costs across orchestrator and generator calls.
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 *
 * CHARIOT::§8.12::5 — "TokenTracker.ts — token counting by adapter, by tool,
 * by tenant. Backs the per-tenant cost-attribution surface." `record()`
 * previously carried no adapter/tool/tenant dimension at all (provider,
 * model, role only), so `summary()` could not answer "how many tokens did
 * tenant X spend on adapter Y's tool Z" — the exact question §8.12::5 and
 * §16.3::1's "token usage by adapter" group both require. Redesigned to an
 * options-object `record()` call that requires all three dimensions; there
 * were zero production call sites at the time of this change (grepped
 * `tokenTracker\.record\|new TokenTracker` repo-wide — the class was
 * exported from `engine/index.ts` but never instantiated), so this is a
 * clean redesign, not a breaking change to any live caller.
 */

export interface TokenUsage {
  inputTokens: number;
  outputTokens: number;
  totalTokens: number;
}

export interface CostEntry {
  provider: string;
  model: string;
  role: 'orchestrator' | 'generator';
  usage: TokenUsage;
  estimatedCostUsd: number;
  timestamp: Date;
  /** CHARIOT::§8.12::5 dimension — which adapter this call attributes to. */
  adapterId: string;
  /** CHARIOT::§8.12::5 dimension — which tool this call attributes to. */
  toolName: string;
  /** CHARIOT::§8.12::5 dimension — per-tenant cost-attribution key. */
  tenantId: string;
}

/** Parameters for {@link TokenTracker.record}. All three dimension fields
 * (adapterId, toolName, tenantId) are required — CHARIOT::§8.12::5 pins all
 * three, not an optional subset. */
export interface TokenRecordParams {
  provider: string;
  model: string;
  role: 'orchestrator' | 'generator';
  usage: TokenUsage;
  adapterId: string;
  toolName: string;
  tenantId: string;
}

interface DimensionTotal {
  tokens: number;
  costUsd: number;
}

export interface CostSummary {
  totalInputTokens: number;
  totalOutputTokens: number;
  totalTokens: number;
  totalEstimatedCostUsd: number;
  byRole: {
    orchestrator: DimensionTotal;
    generator: DimensionTotal;
  };
  /** CHARIOT::§8.12::5 — token/cost totals grouped by adapterId. */
  byAdapter: Record<string, DimensionTotal>;
  /** CHARIOT::§8.12::5 — token/cost totals grouped by toolName. */
  byTool: Record<string, DimensionTotal>;
  /** CHARIOT::§8.12::5 — token/cost totals grouped by tenantId; backs the
   * per-tenant cost-attribution surface the clause names explicitly. */
  byTenant: Record<string, DimensionTotal>;
  entries: CostEntry[];
}

// Default pricing per 1M tokens (USD) — consumer can override
const DEFAULT_PRICING: Record<string, { input: number; output: number }> = {
  'gpt-4.1': { input: 2.00, output: 8.00 },
  'gpt-4o': { input: 2.50, output: 10.00 },
  'claude-sonnet-4-6': { input: 3.00, output: 15.00 },
  'claude-opus-4-6': { input: 15.00, output: 75.00 },
  'qwen2.5:7b': { input: 0, output: 0 }, // local model — free
  'llama3.1:8b': { input: 0, output: 0 }, // local model — free
  'mistral:7b': { input: 0, output: 0 }, // local model — free
  'ollama': { input: 0, output: 0 }, // local — free
};

function addToDimension(map: Record<string, DimensionTotal>, key: string, tokens: number, costUsd: number): void {
  const existing = map[key];
  if (existing) {
    existing.tokens += tokens;
    existing.costUsd += costUsd;
  } else {
    map[key] = { tokens, costUsd };
  }
}

export class TokenTracker {
  private readonly entries: CostEntry[] = [];
  private readonly pricing: Record<string, { input: number; output: number }>;

  constructor(customPricing?: Record<string, { input: number; output: number }>) {
    this.pricing = { ...DEFAULT_PRICING, ...customPricing };
  }

  /**
   * Record token usage from an LLM call, attributed to an adapter, a tool,
   * and a tenant (CHARIOT::§8.12::5).
   */
  record(params: TokenRecordParams): CostEntry {
    const { provider, model, role, usage, adapterId, toolName, tenantId } = params;
    const pricing = this.pricing[model] ?? this.pricing[provider] ?? { input: 0, output: 0 };
    const estimatedCostUsd =
      (usage.inputTokens / 1_000_000) * pricing.input +
      (usage.outputTokens / 1_000_000) * pricing.output;

    const entry: CostEntry = {
      provider,
      model,
      role,
      usage,
      estimatedCostUsd,
      timestamp: new Date(),
      adapterId,
      toolName,
      tenantId,
    };

    this.entries.push(entry);
    return entry;
  }

  /**
   * Estimate token count from text (rough: ~4 chars per token).
   */
  static estimateTokens(text: string): number {
    return Math.ceil(text.length / 4);
  }

  /**
   * Get cost summary across all recorded entries, including the
   * CHARIOT::§8.12::5 by-adapter / by-tool / by-tenant breakdowns.
   */
  summary(): CostSummary {
    let totalInput = 0;
    let totalOutput = 0;
    let totalCost = 0;
    let orchTokens = 0;
    let orchCost = 0;
    let genTokens = 0;
    let genCost = 0;

    const byAdapter: Record<string, DimensionTotal> = {};
    const byTool: Record<string, DimensionTotal> = {};
    const byTenant: Record<string, DimensionTotal> = {};

    for (const entry of this.entries) {
      totalInput += entry.usage.inputTokens;
      totalOutput += entry.usage.outputTokens;
      totalCost += entry.estimatedCostUsd;

      if (entry.role === 'orchestrator') {
        orchTokens += entry.usage.totalTokens;
        orchCost += entry.estimatedCostUsd;
      } else {
        genTokens += entry.usage.totalTokens;
        genCost += entry.estimatedCostUsd;
      }

      addToDimension(byAdapter, entry.adapterId, entry.usage.totalTokens, entry.estimatedCostUsd);
      addToDimension(byTool, entry.toolName, entry.usage.totalTokens, entry.estimatedCostUsd);
      addToDimension(byTenant, entry.tenantId, entry.usage.totalTokens, entry.estimatedCostUsd);
    }

    return {
      totalInputTokens: totalInput,
      totalOutputTokens: totalOutput,
      totalTokens: totalInput + totalOutput,
      totalEstimatedCostUsd: totalCost,
      byRole: {
        orchestrator: { tokens: orchTokens, costUsd: orchCost },
        generator: { tokens: genTokens, costUsd: genCost },
      },
      byAdapter,
      byTool,
      byTenant,
      entries: [...this.entries],
    };
  }

  /**
   * Reset all tracked entries.
   */
  reset(): void {
    this.entries.length = 0;
  }
}
