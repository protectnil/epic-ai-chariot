/**
 * NBA MCP Adapter — player, team, and game data via the BallDontLie API
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 *
 * Base URL: https://api.balldontlie.io/v1
 * Auth: API key via Authorization header (BALLDONTLIE_API_KEY)
 * Docs: https://www.balldontlie.io/
 * Category: sports
 */

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

interface NBAConfig {
  apiKey: string;
  baseUrl?: string;
}

export class NBAMCPServer extends MCPAdapterBase {
  private readonly apiKey: string;
  private readonly baseUrl: string;

  constructor(config: NBAConfig) {
    super();
    if (!config || typeof config !== 'object') {
      throw new Error('NBA (BallDontLie): configuration object is required');
    }
    for (const __k of (['apiKey'] as Array<keyof typeof config>)) {
      if (config[__k] === undefined || config[__k] === null || (config[__k] as unknown) === '') {
        throw new Error('NBA (BallDontLie): ' + __k + ' is required');
      }
    }
    this.apiKey = config.apiKey;
    this.baseUrl = config.baseUrl || 'https://api.balldontlie.io/v1';
  }

  static catalog() {
    return {
      name: 'nba',
      displayName: 'NBA — BallDontLie Player, Team & Game Data',
      version: '1.0.0',
      category: 'sports',
      keywords: [
        'nba', 'basketball', 'balldontlie', 'player', 'players', 'team', 'teams',
        'game', 'games', 'season', 'scores', 'stats', 'sports data',
        'search players', 'nba teams', 'nba games', 'nba stats',
      ],
      toolNames: ['search_players', 'get_player', 'get_teams', 'get_games'],
      description: 'NBA data via BallDontLie: search players by name, retrieve player profiles, list all 30 NBA teams, and fetch game results and scores by season.',
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
        name: 'search_players',
        description:
          'Search NBA players by name. Returns player profile including position, height, weight, college, and current team.',
        inputSchema: {
          type: 'object',
          properties: {
            query: {
              type: 'string',
              description: 'Player name or partial name to search for',
            },
            limit: {
              type: 'number',
              description: 'Number of results to return (default: 10, max: 100)',
            },
          },
          required: ['query'],
        },
      },
      {
        name: 'get_player',
        description:
          'Get detailed profile for a single NBA player by their BallDontLie player ID.',
        inputSchema: {
          type: 'object',
          properties: {
            id: {
              type: 'number',
              description: 'BallDontLie player ID',
            },
          },
          required: ['id'],
        },
      },
      {
        name: 'get_teams',
        description:
          'List all 30 NBA teams with their full names, abbreviations, conference, and division.',
        inputSchema: {
          type: 'object',
          properties: {},
        },
      },
      {
        name: 'get_games',
        description:
          'Get NBA games for a given season. Returns game date, status, teams, and scores.',
        inputSchema: {
          type: 'object',
          properties: {
            season: {
              type: 'number',
              description: 'Season start year (e.g., 2024 for the 2024-25 season)',
            },
            limit: {
              type: 'number',
              description: 'Number of results to return (default: 25, max: 100)',
            },
          },
          required: ['season'],
        },
      },
    ];
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<ToolResult> {
    try {
      switch (name) {
        case 'search_players': return this.searchPlayers(args);
        case 'get_player':     return this.getPlayer(args);
        case 'get_teams':      return this.getTeams();
        case 'get_games':      return this.getGames(args);
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

  private authHeaders(): Record<string, string> {
    return {
      Authorization: this.apiKey,
      Accept: 'application/json',
    };
  }

  private async request(path: string): Promise<ToolResult> {
    const url = `${this.baseUrl}${path}`;
    const response = await this.fetchWithRetry(url, {
      method: 'GET',
      headers: this.authHeaders(),
    });
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `BallDontLie API error: ${response.status} ${errText}` }],
        isError: true,
      };
    }
    const data = await response.json();
    return { content: [{ type: 'text', text: this.truncate(data) }], isError: false };
  }

  private async searchPlayers(args: Record<string, unknown>): Promise<ToolResult> {
    const query = args.query as string;
    const perPage = Math.min(Math.max(1, (args.limit as number) ?? 10), 100);
    const params = new URLSearchParams({
      search: query,
      per_page: String(perPage),
    });
    return this.request(`/players?${params}`);
  }

  private async getPlayer(args: Record<string, unknown>): Promise<ToolResult> {
    const id = args.id as number;
    return this.request(`/players/${id}`);
  }

  private async getTeams(): Promise<ToolResult> {
    return this.request('/teams');
  }

  private async getGames(args: Record<string, unknown>): Promise<ToolResult> {
    const season = args.season as number;
    const perPage = Math.min(Math.max(1, (args.limit as number) ?? 25), 100);
    const params = new URLSearchParams({
      'seasons[]': String(season),
      per_page: String(perPage),
    });
    return this.request(`/games?${params}`);
  }
}
