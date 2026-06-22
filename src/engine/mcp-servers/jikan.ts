/**
 * Jikan MCP Adapter — MyAnimeList anime/manga data (free, no auth)
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 *
 * Base URL: https://api.jikan.moe/v4
 * Auth: None required — Jikan is a free, public, rate-limited API (no key needed)
 * Docs: https://docs.api.jikan.moe/
 * Category: entertainment
 * Rate limits: ~3 req/sec, 60 req/min — Jikan enforces upstream throttling
 */

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

interface JikanConfig {
  /** Optional base URL override (default: https://api.jikan.moe/v4) */
  baseUrl?: string;
}

export class JikanMCPServer extends MCPAdapterBase {
  private readonly baseUrl: string;

  constructor(config?: JikanConfig) {
    super();
    if (config === null) { throw new Error('JikanMCPServer: configuration object is required when provided'); }
    this.baseUrl = config?.baseUrl ?? 'https://api.jikan.moe/v4';
  }

  static catalog() {
    return {
      name: 'jikan',
      displayName: 'Jikan — MyAnimeList API',
      version: '1.0.0',
      category: 'entertainment',
      keywords: [
        'jikan', 'anime', 'manga', 'myanimelist', 'mal', 'characters',
        'top anime', 'anime search', 'anime details', 'otaku', 'animation',
        'japanese animation', 'season', 'studios', 'genres', 'score',
      ],
      toolNames: ['search_anime', 'get_anime', 'top_anime', 'search_characters'],
      description: 'Jikan v4 API: search anime by title, retrieve full anime details by MyAnimeList ID, browse top-ranked anime, and search anime/manga characters — free and unauthenticated.',
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
        description:
          'Search anime by title using MyAnimeList data. Returns title, score, type, episode count, status, synopsis, and genres.',
        inputSchema: {
          type: 'object',
          properties: {
            query: {
              type: 'string',
              description: 'Anime title to search for (e.g., "Fullmetal Alchemist")',
            },
          },
          required: ['query'],
        },
      },
      {
        name: 'get_anime',
        description:
          'Get full details for a specific anime by its MyAnimeList ID. Includes score, synopsis, genres, studios, episodes, and more.',
        inputSchema: {
          type: 'object',
          properties: {
            id: {
              type: 'number',
              description: 'MyAnimeList anime ID (e.g., 5114 for Fullmetal Alchemist: Brotherhood)',
            },
          },
          required: ['id'],
        },
      },
      {
        name: 'top_anime',
        description:
          'Get the top-ranked anime from MyAnimeList, optionally filtered by type (tv, movie, ova, special, ona, music).',
        inputSchema: {
          type: 'object',
          properties: {
            type: {
              type: 'string',
              description:
                'Filter by anime type: tv, movie, ova, special, ona, music. Omit for all types.',
            },
          },
        },
      },
      {
        name: 'search_characters',
        description:
          'Search anime and manga characters by name. Returns name, nicknames, favorites count, and a brief biography.',
        inputSchema: {
          type: 'object',
          properties: {
            query: {
              type: 'string',
              description: 'Character name to search for (e.g., "Naruto")',
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
        case 'search_anime':    return this.searchAnime(args);
        case 'get_anime':       return this.getAnime(args);
        case 'top_anime':       return this.topAnime(args);
        case 'search_characters': return this.searchCharacters(args);
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
    const url = `${this.baseUrl}${path}`;
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

  private async searchAnime(args: Record<string, unknown>): Promise<ToolResult> {
    const query = args.query as string;
    const params = new URLSearchParams({ q: query, limit: '10' });
    return this.request(`/anime?${params.toString()}`);
  }

  private async getAnime(args: Record<string, unknown>): Promise<ToolResult> {
    const id = args.id as number;
    return this.request(`/anime/${encodeURIComponent(String(id))}/full`);
  }

  private async topAnime(args: Record<string, unknown>): Promise<ToolResult> {
    const params = new URLSearchParams({ limit: '10' });
    if (args.type) params.set('type', args.type as string);
    return this.request(`/top/anime?${params.toString()}`);
  }

  private async searchCharacters(args: Record<string, unknown>): Promise<ToolResult> {
    const query = args.query as string;
    const params = new URLSearchParams({ q: query, limit: '10' });
    return this.request(`/characters?${params.toString()}`);
  }
}
