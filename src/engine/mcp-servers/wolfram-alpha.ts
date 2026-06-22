/**
 * Wolfram Alpha MCP Adapter
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

// Upstream: https://products.wolframalpha.com/api/documentation
// Base URL (short answer): https://api.wolframalpha.com/v1/result
// Base URL (full query):   https://api.wolframalpha.com/v2/query
// Auth: AppID query parameter (free tier: ~2,000 queries/month)
//   Register at https://developer.wolframalpha.com
// Category: science
// Rate limits: ~2,000 queries/month on free tier; higher on paid plans

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

const SHORT_URL = 'https://api.wolframalpha.com/v1/result';
const FULL_URL  = 'https://api.wolframalpha.com/v2/query';

interface WolframAlphaConfig {
  appId: string;
  baseUrl?: string;
}

interface WolframPod {
  title?: string;
  id?: string;
  primary?: boolean;
  position?: number;
  subpods?: { plaintext?: string; img?: { src?: string; alt?: string } }[];
}

interface WolframQueryResult {
  success?: boolean;
  error?: boolean | { msg?: string };
  numpods?: number;
  pods?: WolframPod[];
  didyoumeans?: { val?: string } | { val?: string }[];
  tips?: { text?: string };
}

export class WolframAlphaMCPServer extends MCPAdapterBase {
  private readonly appId: string;

  constructor(config: WolframAlphaConfig) {
    super();
    if (!config || typeof config !== 'object') {
      throw new Error('Wolfram Alpha: configuration object is required');
    }
    for (const __k of (['appId'] as Array<keyof typeof config>)) {
      if (config[__k] === undefined || config[__k] === null || (config[__k] as unknown) === '') {
        throw new Error('Wolfram Alpha: ' + __k + ' is required');
      }
    }
    this.appId = config.appId;
  }

  static catalog() {
    return {
      name: 'wolfram-alpha',
      displayName: 'Wolfram Alpha',
      version: '1.0.0',
      category: 'science' as const,
      keywords: [
        'wolfram', 'wolfram alpha', 'math', 'mathematics', 'computation',
        'unit conversion', 'calculator', 'science', 'physics', 'chemistry',
        'astronomy', 'demographics', 'geography', 'calendar', 'dates',
        'factual', 'quantitative', 'equation', 'formula', 'element',
        'periodic table', 'exchange rate', 'statistics', 'plot', 'integral',
        'derivative', 'symbolic math', 'answer engine',
      ],
      toolNames: ['short_answer', 'full_query'],
      description: 'Wolfram Alpha: get terse plain-text answers or full structured pod results for math, unit conversions, science formulas, factual lookups, and quantitative queries — requires a free AppID.',
      type: 'rest' as const,
      auth: {
        inferredModel: 'api-key' as const,
        probeState: 'never-probed' as const,
      },
      author: 'protectnil',
    };
  }

  get tools(): ToolDefinition[] {
    return [
      {
        name: 'short_answer',
        description:
          'Get a single terse plain-text answer from Wolfram Alpha. Best for: arithmetic, unit conversion, "what is X", "how many Y in Z", factual lookups (planet diameter, country GDP, element atomic weight, current time in Tokyo). Returns one string.',
        inputSchema: {
          type: 'object',
          properties: {
            query: {
              type: 'string',
              description: 'Natural-language query',
            },
            units: {
              type: 'string',
              description: 'metric | imperial (default metric)',
              enum: ['metric', 'imperial'],
            },
          },
          required: ['query'],
        },
      },
      {
        name: 'full_query',
        description:
          'Get the full structured result from Wolfram Alpha. Returns named "pods" (Input, Result, Solution, Plot, Properties, etc.) — useful when short_answer is too terse or you need multiple facets (e.g., element properties, equation solution + plot + alternate forms).',
        inputSchema: {
          type: 'object',
          properties: {
            query: {
              type: 'string',
              description: 'Natural-language query',
            },
            units: {
              type: 'string',
              description: 'metric | imperial (default metric)',
              enum: ['metric', 'imperial'],
            },
            include_pods: {
              type: 'string',
              description: 'Comma-separated pod IDs to restrict (e.g., "Result,Solution"). Default: return all.',
            },
            format: {
              type: 'string',
              description: 'plaintext (default) | plaintext,image — plaintext is most agent-friendly.',
            },
          },
          required: ['query'],
        },
      },
    ];
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<ToolResult> {
    try {
      switch (name) {
        case 'short_answer': return this.shortAnswer(args);
        case 'full_query':   return this.fullQuery(args);
        default:
          return { content: [{ type: 'text', text: `Unknown tool: ${name}` }], isError: true };
      }
    } catch (error) {
      return {
        content: [{ type: 'text', text: `Tool execution failed: ${error instanceof Error ? error.message : String(error)}` }],
        isError: true,
      };
    }
  }

  // ── Private helpers ────────────────────────────────────────────────────────

  private async shortAnswer(args: Record<string, unknown>): Promise<ToolResult> {
    const params = new URLSearchParams({
      appid: this.appId,
      i: String(args.query),
    });
    if (args.units) params.set('units', String(args.units));

    const response = await this.fetchWithRetry(`${SHORT_URL}?${params}`, {
      method: 'GET',
      headers: { Accept: 'text/plain' },
    });

    if (response.status === 401) {
      return {
        content: [{ type: 'text', text: 'Wolfram Alpha: invalid AppID (HTTP 401)' }],
        isError: true,
      };
    }
    if (response.status === 501) {
      const result = {
        query: args.query,
        answer: null,
        message: 'Wolfram Alpha did not understand the query (HTTP 501). Try rephrasing or use full_query for more context.',
      };
      return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
    }
    if (!response.ok) {
      const body = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `Wolfram Alpha error: ${response.status} ${body.slice(0, 200)}` }],
        isError: true,
      };
    }

    const text = await response.text();
    return {
      content: [{ type: 'text', text: this.truncate({ query: args.query, answer: text }) }],
      isError: false,
    };
  }

  private async fullQuery(args: Record<string, unknown>): Promise<ToolResult> {
    const params = new URLSearchParams({
      appid: this.appId,
      input: String(args.query),
      output: 'JSON',
      format: (args.format as string) ?? 'plaintext',
    });
    if (args.units) params.set('units', String(args.units));
    if (args.include_pods) params.set('includepodid', String(args.include_pods));

    const response = await this.fetchWithRetry(`${FULL_URL}?${params}`, {
      method: 'GET',
      headers: { Accept: 'application/json' },
    });

    if (response.status === 401) {
      return {
        content: [{ type: 'text', text: 'Wolfram Alpha: invalid AppID (HTTP 401)' }],
        isError: true,
      };
    }
    if (!response.ok) {
      const body = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `Wolfram Alpha error: ${response.status} ${body.slice(0, 200)}` }],
        isError: true,
      };
    }

    const data = (await response.json()) as { queryresult?: WolframQueryResult };
    const qr = data.queryresult;

    if (!qr || qr.success === false) {
      const err = typeof qr?.error === 'object' ? qr?.error?.msg : null;
      const result = {
        query: args.query,
        success: false,
        message: err ?? 'No interpretation found.',
        did_you_mean: this.extractDYM(qr?.didyoumeans),
        tips: qr?.tips?.text ?? null,
      };
      return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
    }

    const result = {
      query: args.query,
      success: true,
      pod_count: qr.numpods ?? 0,
      pods: (qr.pods ?? []).map(this.normalizePod),
    };
    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }

  private extractDYM(dym?: { val?: string } | { val?: string }[]): string[] {
    if (!dym) return [];
    if (Array.isArray(dym)) return dym.map((d) => d.val ?? '').filter(Boolean);
    return dym.val ? [dym.val] : [];
  }

  private normalizePod(p: WolframPod) {
    return {
      title: p.title ?? null,
      id: p.id ?? null,
      primary: p.primary ?? false,
      position: p.position ?? null,
      contents: (p.subpods ?? [])
        .map((s) => s.plaintext)
        .filter((t): t is string => !!t)
        .join('\n'),
      images: (p.subpods ?? []).map((s) => s.img?.src).filter((u): u is string => !!u),
    };
  }
}
