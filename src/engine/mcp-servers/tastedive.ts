/**
 * TasteDive MCP Adapter
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

// Base URL: https://tastedive.com/api/similar
// Auth: API key query parameter (?k=)
// Docs: https://tastedive.com/read/api
// Category: entertainment
// Rate limits: Free plan available; register at tastedive.com/profile/api

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

const TASTEDIVE_TYPES = ['music', 'movie', 'show', 'book', 'game', 'podcast', 'person', 'place', 'brand'] as const;
type TasteDiveType = typeof TASTEDIVE_TYPES[number];

interface TasteDiveConfig {
  apiKey: string;
  baseUrl?: string;
}

interface TasteDiveResp {
  similar?: {
    info?: { name?: string; type?: string; wTeaser?: string; wUrl?: string; yUrl?: string }[];
    results?: { name?: string; type?: string; wTeaser?: string; wUrl?: string; yUrl?: string }[];
  };
}

export class TasteDiveMCPServer extends MCPAdapterBase {
  private readonly apiKey: string;
  private readonly baseUrl: string;

  constructor(config: TasteDiveConfig) {
    super();
    if (!config || typeof config !== 'object') {
      throw new Error('TasteDive: configuration object is required');
    }
    for (const __k of (['apiKey'] as Array<keyof typeof config>)) {
      if (config[__k] === undefined || config[__k] === null || (config[__k] as unknown) === '') {
        throw new Error('TasteDive: ' + __k + ' is required');
      }
    }
    this.apiKey = config.apiKey;
    this.baseUrl = config.baseUrl || 'https://tastedive.com/api/similar';
  }

  static catalog() {
    return {
      name: 'tastedive',
      displayName: 'TasteDive',
      version: '1.0.0',
      category: 'entertainment',
      keywords: [
        'tastedive', 'recommendations', 'similar', 'movies', 'music', 'books',
        'shows', 'games', 'podcasts', 'taste', 'cross-media', 'discovery',
        'like x', 'similar to', 'entertainment', 'suggestion',
      ],
      toolNames: ['get_recommendations'],
      description: 'TasteDive: get "similar to X" cross-media recommendations across music, movies, shows, books, games, and podcasts.',
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
        name: 'get_recommendations',
        description:
          'Get "similar to X" recommendations from TasteDive. type narrows the category (music | movie | show | book | game | podcast | person | place | brand). include_info=true also returns short descriptions and Wikipedia URLs.',
        inputSchema: {
          type: 'object',
          properties: {
            query: {
              type: 'string',
              description: 'Seed — one or more titles, comma-separated. Prefix with `<type>:` to disambiguate (e.g., "movie:Inception").',
            },
            type: {
              type: 'string',
              description: 'Restrict to one category. Note: types are singular (movie, show, book), not plural.',
              enum: [...TASTEDIVE_TYPES],
            },
            limit: {
              type: 'number',
              description: '1-50 (default 20)',
            },
            include_info: {
              type: 'boolean',
              description: 'Add description + Wikipedia URL to each result (default false)',
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
        case 'get_recommendations': return this.getRecommendations(args);
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

  private async getRecommendations(args: Record<string, unknown>): Promise<ToolResult> {
    const query = args.query as string;
    const params = new URLSearchParams({
      q: query,
      k: this.apiKey,
      limit: String(Math.min(50, Math.max(1, typeof args.limit === 'number' ? args.limit : 20))),
    });

    if (args.type !== undefined) {
      const t = String(args.type);
      if (!(TASTEDIVE_TYPES as readonly string[]).includes(t)) {
        return {
          content: [{ type: 'text', text: `Unknown type "${t}". Expected one of: ${TASTEDIVE_TYPES.join(', ')}.` }],
          isError: true,
        };
      }
      params.set('type', t as TasteDiveType);
    }

    if (args.include_info) {
      params.set('info', '1');
      params.set('description', '1');
    }

    const url = `${this.baseUrl}?${params.toString()}`;
    const response = await this.fetchWithRetry(url, {
      method: 'GET',
      headers: { Accept: 'application/json' },
    });

    if (response.status === 401 || response.status === 403) {
      return {
        content: [{ type: 'text', text: 'TasteDive: unauthorized — check the API key' }],
        isError: true,
      };
    }
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `TasteDive API error: ${response.status} ${errText.slice(0, 200)}` }],
        isError: true,
      };
    }

    const data = (await response.json()) as TasteDiveResp;
    const results = data.similar?.results ?? [];
    const info = data.similar?.info ?? [];

    const payload = {
      query,
      type: args.type ?? 'mixed',
      seed_resolved: info.map((i) => ({ name: i.name ?? null, type: i.type ?? null })),
      count: results.length,
      recommendations: results.map((r) => ({
        name: r.name ?? null,
        type: r.type ?? null,
        teaser: r.wTeaser ?? null,
        wikipedia: r.wUrl ?? null,
        youtube: r.yUrl ?? null,
      })),
    };

    return { content: [{ type: 'text', text: this.truncate(payload) }], isError: false };
  }
}
