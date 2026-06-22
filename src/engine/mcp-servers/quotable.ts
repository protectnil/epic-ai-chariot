/**
 * Quotable MCP Adapter
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

// Base URL: https://api.quotable.kurokeita.dev/api
//   (maintained community mirror of the Quotable dataset; the original
//   api.quotable.io went dark — verified HTTP 000/unreachable 2026-06-09,
//   mirror verified live 2026-06-10: /quotes/random, /quotes?query=,
//   /authors, /tags all HTTP 200 with real data)
// Auth: none (free, public API)
// Category: entertainment
// Rate limits: none documented; `limit` must be one of 10, 25, 50, 100

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

const BASE_URL = 'https://api.quotable.kurokeita.dev/api';

/** The mirror validates `limit` strictly: only 10, 25, 50, 100 are accepted. */
function clampMirrorLimit(requested: unknown, fallback: 10 | 25 | 50 | 100): number {
  const n = typeof requested === 'number' && Number.isFinite(requested) ? requested : fallback;
  for (const allowed of [10, 25, 50, 100]) if (n <= allowed) return allowed;
  return 100;
}

export class QuotableMCPServer extends MCPAdapterBase {
  constructor() {
    super();
  }

  static catalog() {
    return {
      name: 'quotable',
      displayName: 'Quotable',
      version: '1.0.0',
      category: 'entertainment',
      keywords: [
        'quotes', 'quotable', 'random quote', 'inspirational', 'authors',
        'wisdom', 'tags', 'search quotes', 'motivational', 'sayings',
      ],
      toolNames: ['random_quote', 'search_quotes', 'get_authors', 'list_tags'],
      description: 'Quotable: get random quotes, search quotes by keyword, browse authors, and list available tags — free and unauthenticated.',
      type: 'rest' as const,
      auth: {
        inferredModel: 'none' as const,
        probeState: 'no-auth-verified' as const,
      },
      author: 'protectnil',
    };
  }

  get tools(): ToolDefinition[] {
    return [
      {
        name: 'random_quote',
        description: 'Get a random quote from the Quotable dataset, with content, author, and tags.',
        inputSchema: {
          type: 'object',
          properties: {},
        },
      },
      {
        name: 'search_quotes',
        description: 'Search quotes by keyword. Returns matching quotes with author and tags.',
        inputSchema: {
          type: 'object',
          properties: {
            query: {
              type: 'string',
              description: 'Keyword or phrase to search for in quote content',
            },
            limit: {
              type: 'number',
              description: 'Number of results (rounded up to 10, 25, 50, or 100 — the values the API accepts; default 10)',
            },
          },
          required: ['query'],
        },
      },
      {
        name: 'get_authors',
        description: 'List authors from the Quotable dataset with bio, description, and slug.',
        inputSchema: {
          type: 'object',
          properties: {
            limit: {
              type: 'number',
              description: 'Number of authors (rounded up to 10, 25, 50, or 100 — the values the API accepts; default 10)',
            },
          },
        },
      },
      {
        name: 'list_tags',
        description: 'List all quote tags available in Quotable, sorted by quote count. Use these tag names with random_quote.',
        inputSchema: {
          type: 'object',
          properties: {},
        },
      },
    ];
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<ToolResult> {
    try {
      switch (name) {
        case 'random_quote':  return this.randomQuote(args);
        case 'search_quotes': return this.searchQuotes(args);
        case 'get_authors':   return this.getAuthors(args);
        case 'list_tags':     return this.listTags();
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

  private async request(path: string): Promise<ToolResult> {
    const url = `${BASE_URL}${path}`;
    const response = await this.fetchWithRetry(url, {
      method: 'GET',
      headers: { Accept: 'application/json' },
    });
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `API error: ${response.status} ${errText}` }],
        isError: true,
      };
    }
    const data = await response.json();
    return { content: [{ type: 'text', text: this.truncate(data) }], isError: false };
  }

  private async randomQuote(_args: Record<string, unknown>): Promise<ToolResult> {
    // Mirror shape: { quote: { id, content, tags: [{name}], author: {name, slug} } }
    return this.request('/quotes/random');
  }

  private async searchQuotes(args: Record<string, unknown>): Promise<ToolResult> {
    const query = args.query as string;
    const limit = clampMirrorLimit(args.limit, 10);
    const params = new URLSearchParams({ query, limit: String(limit) });
    return this.request(`/quotes?${params}`);
  }

  private async getAuthors(args: Record<string, unknown>): Promise<ToolResult> {
    const limit = clampMirrorLimit(args.limit, 10);
    const params = new URLSearchParams({ limit: String(limit) });
    return this.request(`/authors?${params}`);
  }

  private async listTags(): Promise<ToolResult> {
    return this.request('/tags');
  }
}
