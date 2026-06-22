/**
 * Chess.com Public API MCP Adapter
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

// Base URL: https://api.chess.com/pub
// Auth: none (Chess.com public API is free, no authentication required)
// Docs: https://www.chess.com/news/view/published-data-api
// Category: entertainment
// Rate limits: No published limit — Chess.com enforces fair-use throttling

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

export class ChessMCPServer extends MCPAdapterBase {
  private readonly baseUrl: string;

  constructor(config?: { baseUrl?: string }) {
    super();
    if (config === null) { throw new Error('ChessMCPServer: configuration object is required when provided'); }
    this.baseUrl = config?.baseUrl ?? 'https://api.chess.com/pub';
  }

  static catalog() {
    return {
      name: 'chess',
      displayName: 'Chess.com Public API',
      version: '1.0.0',
      category: 'entertainment',
      keywords: [
        'chess', 'chess.com', 'player', 'games', 'leaderboard',
        'rating', 'blitz', 'bullet', 'rapid', 'daily', 'pgn',
        'elo', 'fide', 'stats', 'profile',
      ],
      toolNames: ['get_player', 'get_stats', 'get_games', 'get_leaderboards'],
      description: 'Chess.com public data: fetch player profiles, game statistics, monthly game archives, and leaderboards across all time controls.',
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
        name: 'get_player',
        description:
          "Get a Chess.com player's public profile including name, title, followers, country, join date, and last online time.",
        inputSchema: {
          type: 'object',
          properties: {
            username: {
              type: 'string',
              description: 'Chess.com username (case-insensitive, e.g. "hikaru", "magnuscarlsen")',
            },
          },
          required: ['username'],
        },
      },
      {
        name: 'get_stats',
        description:
          "Get a player's game statistics including current rating, best rating, and win/loss/draw record for daily, rapid, blitz, and bullet formats.",
        inputSchema: {
          type: 'object',
          properties: {
            username: {
              type: 'string',
              description: 'Chess.com username',
            },
          },
          required: ['username'],
        },
      },
      {
        name: 'get_games',
        description:
          "Get a player's completed games for a specific month. Returns game URLs, time controls, results, and player ratings.",
        inputSchema: {
          type: 'object',
          properties: {
            username: {
              type: 'string',
              description: 'Chess.com username',
            },
            year: {
              type: 'number',
              description: 'Year (e.g. 2024)',
            },
            month: {
              type: 'number',
              description: 'Month as a number (1–12)',
            },
          },
          required: ['username', 'year', 'month'],
        },
      },
      {
        name: 'get_leaderboards',
        description:
          'Get the top-ranked Chess.com players across game formats including daily, rapid, blitz, and bullet.',
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
        case 'get_player':      return this.getPlayer(args);
        case 'get_stats':       return this.getStats(args);
        case 'get_games':       return this.getGames(args);
        case 'get_leaderboards': return this.getLeaderboards();
        default:
          return { content: [{ type: 'text', text: `Unknown tool: ${name}` }], isError: true };
      }
    } catch (error) {
      return {
        content: [{
          type: 'text',
          text: `Tool execution failed: ${error instanceof Error ? error.message : String(error)}`,
        }],
        isError: true,
      };
    }
  }

  // ── Private helpers ──────────────────────────────────────────────────────────

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

  private async getPlayer(args: Record<string, unknown>): Promise<ToolResult> {
    const username = String(args.username ?? '').toLowerCase();
    if (!username) {
      return { content: [{ type: 'text', text: 'get_player: username is required' }], isError: true };
    }
    return this.request(`/player/${encodeURIComponent(username)}`);
  }

  private async getStats(args: Record<string, unknown>): Promise<ToolResult> {
    const username = String(args.username ?? '').toLowerCase();
    if (!username) {
      return { content: [{ type: 'text', text: 'get_stats: username is required' }], isError: true };
    }
    return this.request(`/player/${encodeURIComponent(username)}/stats`);
  }

  private async getGames(args: Record<string, unknown>): Promise<ToolResult> {
    const username = String(args.username ?? '').toLowerCase();
    const year = Number(args.year);
    const month = Number(args.month);
    if (!username) {
      return { content: [{ type: 'text', text: 'get_games: username is required' }], isError: true };
    }
    if (!Number.isInteger(year) || year < 1 || !Number.isInteger(month) || month < 1 || month > 12) {
      return { content: [{ type: 'text', text: 'get_games: year and month (1–12) are required integers' }], isError: true };
    }
    const mm = String(month).padStart(2, '0');
    return this.request(`/player/${encodeURIComponent(username)}/games/${year}/${mm}`);
  }

  private async getLeaderboards(): Promise<ToolResult> {
    return this.request('/leaderboards');
  }
}
