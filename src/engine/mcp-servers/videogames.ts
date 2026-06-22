/**
 * FreeToGame API MCP Adapter
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

// Upstream confirmed from open-source MCP wrapper (MIT) for FreeToGame API.
// This file calls the real upstream directly. No proxy or gateway is involved.
//
// Base URL: https://www.freetogame.com/api
// Auth: None — free public API, no key required
// Docs: https://www.freetogame.com/api-doc
// Category: entertainment
// Rate limits: Not published — free, public

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

const BASE_URL = 'https://www.freetogame.com/api';

export class VideoGamesMCPServer extends MCPAdapterBase {
  constructor() {
    super();
  }

  static catalog() {
    return {
      name: 'videogames',
      displayName: 'FreeToGame API',
      version: '1.0.0',
      category: 'entertainment' as const,
      keywords: [
        'videogames', 'free to play', 'freetogame', 'games', 'gaming',
        'mmorpg', 'shooter', 'strategy', 'moba', 'browser games', 'pc games',
        'free games', 'game catalog', 'game details', 'genre', 'platform',
      ],
      toolNames: ['list_games', 'get_game', 'filter_games'],
      description: 'FreeToGame API: list, search, and filter free-to-play games with details on genre, platform, publisher, screenshots, and system requirements.',
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
        name: 'list_games',
        description:
          'List free-to-play games from FreeToGame. Optionally filter by platform and category, and sort results. Returns title, short description, game URL, genre, platform, publisher, release date, and thumbnail.',
        inputSchema: {
          type: 'object',
          properties: {
            platform: {
              type: 'string',
              description: 'Platform filter: "pc", "browser", or "all" (default "all")',
            },
            category: {
              type: 'string',
              description:
                'Genre/category filter, e.g. "mmorpg", "shooter", "strategy", "moba", "racing", "sports", "social", "sandbox", "open-world", "survival", "pvp", "pve", "pixel", "voxel", "zombie", "turn-based", "first-person", "third-person", "top-down", "tower-defense", "horror", "mmofps"',
            },
            sort_by: {
              type: 'string',
              description:
                'Sort order: "release-date", "popularity", "alphabetical", or "relevance"',
            },
          },
        },
      },
      {
        name: 'get_game',
        description:
          'Get full details for a free-to-play game by its FreeToGame ID. Returns title, description, genre, platform, publisher, developer, release date, screenshots, and minimum system requirements.',
        inputSchema: {
          type: 'object',
          properties: {
            id: {
              type: 'number',
              description: 'FreeToGame game ID (e.g. 452 for "Valorant")',
            },
          },
          required: ['id'],
        },
      },
      {
        name: 'filter_games',
        description:
          'Filter free-to-play games by tag (dot-separated combination of attributes). Returns matching games with title, short description, genre, platform, publisher, release date, and thumbnail.',
        inputSchema: {
          type: 'object',
          properties: {
            tag: {
              type: 'string',
              description:
                'Dot-separated tag filter, e.g. "3d.mmorpg.fantasy", "shooter.pvp", "browser.strategy"',
            },
            platform: {
              type: 'string',
              description: 'Optional platform filter: "pc" or "browser"',
            },
          },
          required: ['tag'],
        },
      },
    ];
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<ToolResult> {
    try {
      switch (name) {
        case 'list_games':  return this.listGames(args);
        case 'get_game':    return this.getGame(args);
        case 'filter_games': return this.filterGames(args);
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

  private async listGames(args: Record<string, unknown>): Promise<ToolResult> {
    const params = new URLSearchParams();
    const platform = args.platform as string | undefined;
    const category = args.category as string | undefined;
    const sort_by = args.sort_by as string | undefined;

    if (platform && platform !== 'all') params.set('platform', platform);
    if (category) params.set('category', category);
    if (sort_by) params.set('sort-by', sort_by);

    const qs = params.toString();
    return this.request(`/games${qs ? `?${qs}` : ''}`);
  }

  private async getGame(args: Record<string, unknown>): Promise<ToolResult> {
    const id = args.id;
    if (id === undefined || id === null) {
      return { content: [{ type: 'text', text: 'get_game: id is required' }], isError: true };
    }
    return this.request(`/game?id=${encodeURIComponent(String(id))}`);
  }

  private async filterGames(args: Record<string, unknown>): Promise<ToolResult> {
    const tag = args.tag as string | undefined;
    if (!tag) {
      return { content: [{ type: 'text', text: 'filter_games: tag is required' }], isError: true };
    }
    const params = new URLSearchParams({ tag });
    const platform = args.platform as string | undefined;
    if (platform) params.set('platform', platform);
    return this.request(`/filter?${params}`);
  }
}
