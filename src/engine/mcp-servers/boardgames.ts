/**
 * Board Game Atlas MCP Adapter
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

// Base URL: https://api.boardgameatlas.com/api
// Auth: public demo client_id appended as query param (no user key needed)
// Docs: https://www.boardgameatlas.com/api/docs
// Category: entertainment
// Rate limits: free demo client_id — reasonable for low-volume queries

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

const BASE_URL = 'https://api.boardgameatlas.com/api';
// Public demo client_id issued by Board Game Atlas for open API use.
const CLIENT_ID = 'JLBr5npPhV';

export class BoardGamesMCPServer extends MCPAdapterBase {
  private readonly baseUrl: string;

  constructor(config?: { baseUrl?: string }) {
    super();
    if (config === null) { throw new Error('BoardGamesMCPServer: configuration object is required when provided'); }
    this.baseUrl = config?.baseUrl ?? BASE_URL;
  }

  static catalog() {
    return {
      name: 'boardgames',
      displayName: 'Board Game Atlas',
      version: '1.0.0',
      category: 'entertainment',
      keywords: [
        'board games', 'boardgames', 'tabletop', 'tabletop games',
        'card games', 'catan', 'board game atlas', 'bga',
        'popular games', 'game ratings', 'game search', 'game details',
        'hot games', 'trending games', 'game publisher', 'game designer',
      ],
      toolNames: ['search_games', 'get_game', 'hot_games'],
      description: 'Board Game Atlas APIs: search board games by name, retrieve full game details by ID, and list the most popular games right now — public, no user auth required.',
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
        name: 'search_games',
        description:
          'Search for board games by name using Board Game Atlas. Returns name, year, player count, playtime, rating, price, and a short description.',
        inputSchema: {
          type: 'object',
          properties: {
            name: {
              type: 'string',
              description: 'Board game name or partial name to search for, e.g. "Catan" or "Ticket to Ride"',
            },
            limit: {
              type: 'number',
              description: 'Number of results to return (1–100, default 10)',
            },
          },
          required: ['name'],
        },
      },
      {
        name: 'get_game',
        description:
          'Get full details for a specific board game by its Board Game Atlas ID. Returns name, year, player count, playtime, description, rating, publisher, designer, and price.',
        inputSchema: {
          type: 'object',
          properties: {
            id: {
              type: 'string',
              description: 'Board Game Atlas game ID (e.g. "OIXt3DmJU0" for Catan)',
            },
          },
          required: ['id'],
        },
      },
      {
        name: 'hot_games',
        description:
          'Get the most popular board games right now, ordered by popularity rank. Returns name, year, player count, playtime, rating, and rank.',
        inputSchema: {
          type: 'object',
          properties: {
            limit: {
              type: 'number',
              description: 'Number of results to return (1–100, default 10)',
            },
          },
          required: [],
        },
      },
    ];
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<ToolResult> {
    try {
      switch (name) {
        case 'search_games': return this.searchGames(args);
        case 'get_game':     return this.getGame(args);
        case 'hot_games':    return this.hotGames(args);
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

  // ── Private helpers ─────────────────────────────────────────────────────────

  private buildParams(extra: Record<string, string>): URLSearchParams {
    return new URLSearchParams({ client_id: CLIENT_ID, ...extra });
  }

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

  private async searchGames(args: Record<string, unknown>): Promise<ToolResult> {
    const name = args.name as string;
    const limit = typeof args.limit === 'number' ? Math.min(Math.max(args.limit, 1), 100) : 10;
    const params = this.buildParams({
      name,
      limit: String(limit),
      order_by: 'rank',
      ascending: 'false',
    });
    return this.request(`/search?${params}`);
  }

  private async getGame(args: Record<string, unknown>): Promise<ToolResult> {
    const id = args.id as string;
    const params = this.buildParams({ ids: id });
    return this.request(`/search?${params}`);
  }

  private async hotGames(args: Record<string, unknown>): Promise<ToolResult> {
    const limit = typeof args.limit === 'number' ? Math.min(Math.max(args.limit, 1), 100) : 10;
    const params = this.buildParams({
      limit: String(limit),
      order_by: 'popularity',
      ascending: 'false',
    });
    return this.request(`/search?${params}`);
  }
}
