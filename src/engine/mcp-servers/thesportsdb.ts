/**
 * TheSportsDB MCP Adapter
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 *
 * Base URL: https://www.thesportsdb.com/api/v1/json/{apiKey}
 * Auth: Optional API key path parameter; public free-tier key "3" used by default.
 *       Patreon/paid supporters may supply their own key via config.
 * Docs: https://www.thesportsdb.com/free_sports_api
 * Category: sports
 * Rate limits: Varies by tier; free tier has limited endpoints.
 */

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

const DEFAULT_API_KEY = '3';

interface TheSportsDBConfig {
  apiKey?: string;
  baseUrl?: string;
}

export class TheSportsDBMCPServer extends MCPAdapterBase {
  private readonly apiKey: string;
  private readonly baseUrl: string;

  constructor(config?: TheSportsDBConfig) {
    super();
    if (config === null) { throw new Error('TheSportsDBMCPServer: configuration object is required when provided'); }
    this.apiKey = config?.apiKey?.trim() || DEFAULT_API_KEY;
    this.baseUrl = config?.baseUrl || 'https://www.thesportsdb.com/api/v1/json';
  }

  static catalog() {
    return {
      name: 'thesportsdb',
      displayName: 'TheSportsDB',
      version: '1.0.0',
      category: 'sports' as const,
      keywords: [
        'thesportsdb', 'sports', 'football', 'soccer', 'basketball', 'baseball',
        'hockey', 'ice hockey', 'tennis', 'rugby', 'cricket', 'teams', 'players',
        'leagues', 'events', 'standings', 'scores', 'fixtures', 'results',
        'sports data', 'sports catalog', 'schedules',
      ],
      toolNames: [
        'list_sports',
        'list_leagues',
        'search_teams',
        'get_team',
        'league_teams',
        'search_players',
        'get_player',
        'team_events_last',
        'team_events_next',
        'events_by_day',
        'league_table',
      ],
      description: 'TheSportsDB: search sports, leagues, teams, and players; retrieve schedules, results, and standings across dozens of sports worldwide. Free public tier requires no sign-up.',
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
        name: 'list_sports',
        description: 'List all sports tracked by TheSportsDB.',
        inputSchema: {
          type: 'object',
          properties: {},
        },
      },
      {
        name: 'list_leagues',
        description: 'List leagues, optionally filtered by sport name and/or country.',
        inputSchema: {
          type: 'object',
          properties: {
            sport: {
              type: 'string',
              description: 'Sport name (e.g. "Soccer", "Ice Hockey"). Optional.',
            },
            country: {
              type: 'string',
              description: 'Country name. Optional.',
            },
          },
        },
      },
      {
        name: 'search_teams',
        description: 'Search teams by name (full or partial).',
        inputSchema: {
          type: 'object',
          properties: {
            query: {
              type: 'string',
              description: 'Team name to search for (e.g. "Arsenal").',
            },
          },
          required: ['query'],
        },
      },
      {
        name: 'get_team',
        description: 'Retrieve a full team profile by TheSportsDB team ID.',
        inputSchema: {
          type: 'object',
          properties: {
            team_id: {
              type: 'string',
              description: 'TheSportsDB team ID (e.g. "133604").',
            },
          },
          required: ['team_id'],
        },
      },
      {
        name: 'league_teams',
        description: 'List all teams in a league by league ID.',
        inputSchema: {
          type: 'object',
          properties: {
            league_id: {
              type: 'string',
              description: 'TheSportsDB league ID (e.g. "4328" for English Premier League).',
            },
          },
          required: ['league_id'],
        },
      },
      {
        name: 'search_players',
        description: 'Search players by name (full or partial).',
        inputSchema: {
          type: 'object',
          properties: {
            query: {
              type: 'string',
              description: 'Player name to search for (e.g. "Messi").',
            },
          },
          required: ['query'],
        },
      },
      {
        name: 'get_player',
        description: 'Retrieve a full player profile by TheSportsDB player ID.',
        inputSchema: {
          type: 'object',
          properties: {
            player_id: {
              type: 'string',
              description: 'TheSportsDB player ID (e.g. "34145937").',
            },
          },
          required: ['player_id'],
        },
      },
      {
        name: 'team_events_last',
        description: 'Retrieve the last 5 events (matches/games) for a team.',
        inputSchema: {
          type: 'object',
          properties: {
            team_id: {
              type: 'string',
              description: 'TheSportsDB team ID.',
            },
          },
          required: ['team_id'],
        },
      },
      {
        name: 'team_events_next',
        description: 'Retrieve the next 5 upcoming events (matches/games) for a team.',
        inputSchema: {
          type: 'object',
          properties: {
            team_id: {
              type: 'string',
              description: 'TheSportsDB team ID.',
            },
          },
          required: ['team_id'],
        },
      },
      {
        name: 'events_by_day',
        description: 'List all events on a given date, optionally filtered by sport or league.',
        inputSchema: {
          type: 'object',
          properties: {
            date: {
              type: 'string',
              description: 'Date in YYYY-MM-DD format.',
            },
            sport: {
              type: 'string',
              description: 'Sport name filter (optional, e.g. "Soccer").',
            },
            league: {
              type: 'string',
              description: 'League name filter (optional, e.g. "English Premier League").',
            },
          },
          required: ['date'],
        },
      },
      {
        name: 'league_table',
        description: 'Retrieve the standings table for a league, optionally for a specific season.',
        inputSchema: {
          type: 'object',
          properties: {
            league_id: {
              type: 'string',
              description: 'TheSportsDB league ID.',
            },
            season: {
              type: 'string',
              description: 'Season string (e.g. "2024-2025"). Defaults to current season if omitted.',
            },
          },
          required: ['league_id'],
        },
      },
    ];
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<ToolResult> {
    try {
      switch (name) {
        case 'list_sports':       return this.listSports();
        case 'list_leagues':      return this.listLeagues(args);
        case 'search_teams':      return this.searchTeams(args);
        case 'get_team':          return this.getTeam(args);
        case 'league_teams':      return this.leagueTeams(args);
        case 'search_players':    return this.searchPlayers(args);
        case 'get_player':        return this.getPlayer(args);
        case 'team_events_last':  return this.teamEventsLast(args);
        case 'team_events_next':  return this.teamEventsNext(args);
        case 'events_by_day':     return this.eventsByDay(args);
        case 'league_table':      return this.leagueTable(args);
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

  private get apiBase(): string {
    return `${this.baseUrl}/${encodeURIComponent(this.apiKey)}`;
  }

  private async request(path: string): Promise<ToolResult> {
    const url = `${this.apiBase}${path}`;
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

  private reqStr(args: Record<string, unknown>, key: string, example: string): string {
    const v = args[key];
    if (typeof v !== 'string' || !v.trim()) {
      throw new Error(`Required argument "${key}" is missing. Pass a string like ${example}.`);
    }
    return v;
  }

  private async listSports(): Promise<ToolResult> {
    return this.request('/all_sports.php');
  }

  private async listLeagues(args: Record<string, unknown>): Promise<ToolResult> {
    if (args.sport || args.country) {
      const params = new URLSearchParams();
      if (args.sport) params.set('s', String(args.sport));
      if (args.country) params.set('c', String(args.country));
      return this.request(`/search_all_leagues.php?${params}`);
    }
    return this.request('/all_leagues.php');
  }

  private async searchTeams(args: Record<string, unknown>): Promise<ToolResult> {
    const params = new URLSearchParams({ t: this.reqStr(args, 'query', '"Arsenal"') });
    return this.request(`/searchteams.php?${params}`);
  }

  private async getTeam(args: Record<string, unknown>): Promise<ToolResult> {
    const params = new URLSearchParams({ id: this.reqStr(args, 'team_id', '"133604"') });
    return this.request(`/lookupteam.php?${params}`);
  }

  private async leagueTeams(args: Record<string, unknown>): Promise<ToolResult> {
    const params = new URLSearchParams({ id: this.reqStr(args, 'league_id', '"4328"') });
    return this.request(`/lookup_all_teams.php?${params}`);
  }

  private async searchPlayers(args: Record<string, unknown>): Promise<ToolResult> {
    const params = new URLSearchParams({ p: this.reqStr(args, 'query', '"Messi"') });
    return this.request(`/searchplayers.php?${params}`);
  }

  private async getPlayer(args: Record<string, unknown>): Promise<ToolResult> {
    const params = new URLSearchParams({ id: this.reqStr(args, 'player_id', '"34145937"') });
    return this.request(`/lookupplayer.php?${params}`);
  }

  private async teamEventsLast(args: Record<string, unknown>): Promise<ToolResult> {
    const params = new URLSearchParams({ id: this.reqStr(args, 'team_id', '"133604"') });
    return this.request(`/eventslast.php?${params}`);
  }

  private async teamEventsNext(args: Record<string, unknown>): Promise<ToolResult> {
    const params = new URLSearchParams({ id: this.reqStr(args, 'team_id', '"133604"') });
    return this.request(`/eventsnext.php?${params}`);
  }

  private async eventsByDay(args: Record<string, unknown>): Promise<ToolResult> {
    const params = new URLSearchParams({ d: this.reqStr(args, 'date', '"2024-09-15"') });
    if (args.sport) params.set('s', String(args.sport));
    if (args.league) params.set('l', String(args.league));
    return this.request(`/eventsday.php?${params}`);
  }

  private async leagueTable(args: Record<string, unknown>): Promise<ToolResult> {
    const params = new URLSearchParams({ l: this.reqStr(args, 'league_id', '"4328"') });
    if (args.season) params.set('s', String(args.season));
    return this.request(`/lookuptable.php?${params}`);
  }
}
