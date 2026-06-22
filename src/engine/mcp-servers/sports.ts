/**
 * TheSportsDB MCP Adapter
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 *
 * Upstream: https://www.thesportsdb.com/api.php
 * Base URL: https://www.thesportsdb.com/api/v1/json/3
 * Auth: none — free-tier test key "3" is baked into the path; no header required
 * Docs: https://www.thesportsdb.com/api.php
 * Category: sports
 * Rate limits: free tier; avoid hammering — no published hard cap
 */

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

const BASE_URL = 'https://www.thesportsdb.com/api/v1/json/3';

export class SportsMCPServer extends MCPAdapterBase {
  private readonly baseUrl: string;

  constructor(config?: { baseUrl?: string }) {
    super();
    if (config === null) { throw new Error('SportsMCPServer: configuration object is required when provided'); }
    this.baseUrl = config?.baseUrl ?? BASE_URL;
  }

  static catalog() {
    return {
      name: 'sports',
      displayName: 'TheSportsDB',
      version: '1.0.0',
      category: 'sports',
      keywords: [
        'sports', 'thesportsdb', 'football', 'soccer', 'basketball', 'baseball',
        'nfl', 'nba', 'nhl', 'mlb', 'premier league', 'teams', 'players',
        'league standings', 'fixtures', 'results', 'matches', 'events',
        'scores', 'schedule', 'sports data',
      ],
      toolNames: [
        'search_teams',
        'search_players',
        'get_league_table',
        'get_last_events',
        'get_next_events',
      ],
      description: 'TheSportsDB: search sports teams and players, retrieve league standings, and fetch past or upcoming match events — free public API, no authentication required.',
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
        name: 'search_teams',
        description:
          'Search for sports teams by name. Returns team name, sport, league, country, stadium, description, and badge URL.',
        inputSchema: {
          type: 'object',
          properties: {
            query: {
              type: 'string',
              description: 'Team name or partial name to search for',
            },
          },
          required: ['query'],
        },
      },
      {
        name: 'search_players',
        description:
          'Search for players by name. Returns player name, team, nationality, position, description, and thumbnail URL.',
        inputSchema: {
          type: 'object',
          properties: {
            query: {
              type: 'string',
              description: 'Player name or partial name to search for',
            },
          },
          required: ['query'],
        },
      },
      {
        name: 'get_league_table',
        description:
          'Get current standings/table for a league and season. Returns team, played, wins, draws, losses, goals for, goals against, and points.',
        inputSchema: {
          type: 'object',
          properties: {
            league_id: {
              type: 'string',
              description: 'TheSportsDB league ID (e.g., "4328" for English Premier League)',
            },
            season: {
              type: 'string',
              description: 'Season string (e.g., "2024-2025")',
            },
          },
          required: ['league_id', 'season'],
        },
      },
      {
        name: 'get_last_events',
        description:
          'Get the last 15 events/matches played by a team. Returns event name, date, home team, away team, scores, and league.',
        inputSchema: {
          type: 'object',
          properties: {
            team_id: {
              type: 'string',
              description: 'TheSportsDB team ID (e.g., "133604" for Arsenal)',
            },
          },
          required: ['team_id'],
        },
      },
      {
        name: 'get_next_events',
        description:
          'Get the next 15 upcoming events/matches for a team. Returns event name, date, home team, away team, and league.',
        inputSchema: {
          type: 'object',
          properties: {
            team_id: {
              type: 'string',
              description: 'TheSportsDB team ID (e.g., "133604" for Arsenal)',
            },
          },
          required: ['team_id'],
        },
      },
    ];
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<ToolResult> {
    try {
      switch (name) {
        case 'search_teams':   return this.searchTeams(args.query as string);
        case 'search_players': return this.searchPlayers(args.query as string);
        case 'get_league_table':
          return this.getLeagueTable(args.league_id as string, args.season as string);
        case 'get_last_events': return this.getLastEvents(args.team_id as string);
        case 'get_next_events': return this.getNextEvents(args.team_id as string);
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

  private async get(path: string): Promise<ToolResult> {
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

  private async searchTeams(query: string): Promise<ToolResult> {
    return this.get(`/searchteams.php?t=${encodeURIComponent(query)}`);
  }

  private async searchPlayers(query: string): Promise<ToolResult> {
    return this.get(`/searchplayers.php?p=${encodeURIComponent(query)}`);
  }

  private async getLeagueTable(leagueId: string, season: string): Promise<ToolResult> {
    return this.get(
      `/lookuptable.php?l=${encodeURIComponent(leagueId)}&s=${encodeURIComponent(season)}`,
    );
  }

  private async getLastEvents(teamId: string): Promise<ToolResult> {
    return this.get(`/eventslast.php?id=${encodeURIComponent(teamId)}`);
  }

  private async getNextEvents(teamId: string): Promise<ToolResult> {
    return this.get(`/eventsnext.php?id=${encodeURIComponent(teamId)}`);
  }
}
