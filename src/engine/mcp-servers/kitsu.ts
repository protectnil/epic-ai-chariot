/**
 * Kitsu MCP Adapter — anime + manga catalogue (JSON:API)
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 *
 * Base URL: https://kitsu.io/api/edge
 * Auth: none (public API)
 * Docs: https://kitsu.docs.apiary.io/
 * Category: entertainment
 */

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

const BASE_URL = 'https://kitsu.io/api/edge';
const ACCEPT_HEADER = 'application/vnd.api+json';

export class KitsuMCPServer extends MCPAdapterBase {
  private readonly baseUrl: string;

  constructor(config?: { baseUrl?: string }) {
    super();
    if (config === null) { throw new Error('KitsuMCPServer: configuration object is required when provided'); }
    this.baseUrl = config?.baseUrl ?? BASE_URL;
  }

  static catalog() {
    return {
      name: 'kitsu',
      displayName: 'Kitsu',
      version: '1.0.0',
      category: 'entertainment',
      keywords: [
        'kitsu', 'anime', 'manga', 'japanese animation', 'cartoon',
        'otaku', 'categories', 'genres', 'themes', 'top anime',
        'top manga', 'search anime', 'search manga', 'ratings',
        'popularity', 'catalogue', 'media database',
      ],
      toolNames: [
        'search_anime',
        'search_manga',
        'anime',
        'manga',
        'top_anime',
        'top_manga',
        'categories',
      ],
      description: 'Kitsu API: search and browse the anime and manga catalogue, retrieve titles by ID, list top-ranked or most popular series, and explore categories/genres.',
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
        name: 'search_anime',
        description: 'Search anime by name.',
        inputSchema: {
          type: 'object',
          properties: {
            query: { type: 'string', description: 'Anime title to search for.' },
            limit: { type: 'number', description: 'Number of results to return, 1-20 (default 10).' },
          },
          required: ['query'],
        },
      },
      {
        name: 'search_manga',
        description: 'Search manga by name.',
        inputSchema: {
          type: 'object',
          properties: {
            query: { type: 'string', description: 'Manga title to search for.' },
            limit: { type: 'number', description: 'Number of results to return, 1-20 (default 10).' },
          },
          required: ['query'],
        },
      },
      {
        name: 'anime',
        description: 'Fetch a single anime entry by its Kitsu ID.',
        inputSchema: {
          type: 'object',
          properties: {
            id: { type: 'string', description: 'Kitsu anime ID (numeric string).' },
          },
          required: ['id'],
        },
      },
      {
        name: 'manga',
        description: 'Fetch a single manga entry by its Kitsu ID.',
        inputSchema: {
          type: 'object',
          properties: {
            id: { type: 'string', description: 'Kitsu manga ID (numeric string).' },
          },
          required: ['id'],
        },
      },
      {
        name: 'top_anime',
        description: 'List top anime sorted by popularity rank or rating rank.',
        inputSchema: {
          type: 'object',
          properties: {
            by: {
              type: 'string',
              description: 'Sort order: "popularityRank" (default) or "ratingRank".',
            },
            limit: { type: 'number', description: 'Number of results to return, 1-20 (default 10).' },
          },
        },
      },
      {
        name: 'top_manga',
        description: 'List top manga sorted by popularity rank or rating rank.',
        inputSchema: {
          type: 'object',
          properties: {
            by: {
              type: 'string',
              description: 'Sort order: "popularityRank" (default) or "ratingRank".',
            },
            limit: { type: 'number', description: 'Number of results to return, 1-20 (default 10).' },
          },
        },
      },
      {
        name: 'categories',
        description: 'List Kitsu categories (genres and themes).',
        inputSchema: {
          type: 'object',
          properties: {
            limit: { type: 'number', description: 'Number of categories to return, 1-20 (default 10).' },
          },
        },
      },
    ];
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<ToolResult> {
    try {
      switch (name) {
        case 'search_anime':  return this.searchAnime(args);
        case 'search_manga':  return this.searchManga(args);
        case 'anime':         return this.getAnime(args);
        case 'manga':         return this.getManga(args);
        case 'top_anime':     return this.topAnime(args);
        case 'top_manga':     return this.topManga(args);
        case 'categories':    return this.getCategories(args);
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

  // ── Private helpers ──────────────────────────────────────────────────────────

  private async kitsuGet(path: string): Promise<ToolResult> {
    const url = `${this.baseUrl}${path}`;
    const response = await this.fetchWithRetry(url, {
      method: 'GET',
      headers: { Accept: ACCEPT_HEADER },
    });
    if (response.status === 404) {
      return { content: [{ type: 'text', text: 'Kitsu: not found' }], isError: true };
    }
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `Kitsu API error: ${response.status} ${errText.slice(0, 200)}` }],
        isError: true,
      };
    }
    const data = await response.json();
    return { content: [{ type: 'text', text: this.truncate(data) }], isError: false };
  }

  private pageLimit(args: Record<string, unknown>): number {
    const raw = args.limit;
    if (raw === undefined || raw === null) return 10;
    const n = Number(raw);
    return Number.isFinite(n) ? Math.min(20, Math.max(1, Math.trunc(n))) : 10;
  }

  private sortKey(args: Record<string, unknown>): string {
    const by = String(args.by ?? 'popularityRank').toLowerCase();
    if (by === 'ratingrank' || by === 'rating') return 'ratingRank';
    return 'popularityRank';
  }

  private requireString(args: Record<string, unknown>, key: string, example: string): string {
    const v = args[key];
    if (typeof v !== 'string' || !v.trim()) {
      throw new Error(`Required argument "${key}" is missing. Pass a string like ${example}.`);
    }
    return v;
  }

  private async searchAnime(args: Record<string, unknown>): Promise<ToolResult> {
    const query = this.requireString(args, 'query', '"naruto"');
    return this.kitsuGet(`/anime?filter[text]=${encodeURIComponent(query)}&page[limit]=${this.pageLimit(args)}`);
  }

  private async searchManga(args: Record<string, unknown>): Promise<ToolResult> {
    const query = this.requireString(args, 'query', '"berserk"');
    return this.kitsuGet(`/manga?filter[text]=${encodeURIComponent(query)}&page[limit]=${this.pageLimit(args)}`);
  }

  private async getAnime(args: Record<string, unknown>): Promise<ToolResult> {
    const id = this.requireString(args, 'id', '"1"');
    return this.kitsuGet(`/anime/${encodeURIComponent(id)}`);
  }

  private async getManga(args: Record<string, unknown>): Promise<ToolResult> {
    const id = this.requireString(args, 'id', '"1"');
    return this.kitsuGet(`/manga/${encodeURIComponent(id)}`);
  }

  private async topAnime(args: Record<string, unknown>): Promise<ToolResult> {
    return this.kitsuGet(`/anime?sort=${this.sortKey(args)}&page[limit]=${this.pageLimit(args)}`);
  }

  private async topManga(args: Record<string, unknown>): Promise<ToolResult> {
    return this.kitsuGet(`/manga?sort=${this.sortKey(args)}&page[limit]=${this.pageLimit(args)}`);
  }

  private async getCategories(args: Record<string, unknown>): Promise<ToolResult> {
    return this.kitsuGet(`/categories?page[limit]=${this.pageLimit(args)}`);
  }
}
