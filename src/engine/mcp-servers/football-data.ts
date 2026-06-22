/**
 * Football-Data.org MCP Adapter
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

// Base URL: https://api.football-data.org/v4
// Auth: header X-Auth-Token. Free tier: 10 req/min, 12 major competitions.
//       Register at https://www.football-data.org/client/register
// Docs: https://www.football-data.org/documentation/quickstart
// Category: sports
// Rate limits: Free tier 10 req/min

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

interface FootballDataConfig {
  /** football-data.org API key (X-Auth-Token header) */
  apiKey: string;
  /** Optional base URL override (default: https://api.football-data.org/v4) */
  baseUrl?: string;
}

export class FootballDataMCPServer extends MCPAdapterBase {
  private readonly apiKey: string;
  private readonly baseUrl: string;

  constructor(config: FootballDataConfig) {
    super();
    if (!config || typeof config !== 'object') {
      throw new Error('Football-Data.org: configuration object is required');
    }
    for (const k of (['apiKey'] as Array<keyof FootballDataConfig>)) {
      if (!config[k] || (config[k] as string).trim() === '') {
        throw new Error(`Football-Data.org: ${k} is required`);
      }
    }
    this.apiKey = config.apiKey;
    this.baseUrl = config.baseUrl ?? 'https://api.football-data.org/v4';
  }

  static catalog() {
    return {
      name: 'football-data',
      displayName: 'Football-Data.org',
      version: '1.0.0',
      category: 'sports' as const,
      keywords: [
        'football', 'soccer', 'football-data', 'premier league', 'la liga',
        'serie a', 'bundesliga', 'ligue 1', 'champions league', 'world cup',
        'eredivisie', 'brasileirao', 'mls', 'competitions', 'matches',
        'standings', 'league table', 'team', 'squad', 'fixtures', 'results',
      ],
      toolNames: [
        'list_competitions',
        'get_competition_matches',
        'get_competition_standings',
        'get_team',
        'get_team_matches',
      ],
      description: 'Football-Data.org API v4: soccer competitions, live/scheduled/finished matches, league standings, team details with squad, and team match history across 12 major competitions on the free tier (Premier League, La Liga, Serie A, Bundesliga, Ligue 1, Champions League, World Cup, and more).',
      type: 'rest' as const,
      auth: {
        inferredModel: 'api-key' as const,
        probeState: 'never-probed' as const,
      },
      author: 'protectnil' as const,
    };
  }

  get tools(): ToolDefinition[] {
    return [
      {
        name: 'list_competitions',
        description:
          'List competitions accessible on your plan. Free tier: 12 majors (Premier League, La Liga, Serie A, Bundesliga, Ligue 1, Eredivisie, Primeira Liga, Brasileirão, MLS, Champions League, European Championship, World Cup). Use the returned `code` (e.g. "PL", "PD", "CL") for downstream calls.',
        inputSchema: {
          type: 'object',
          properties: {},
          required: [],
        },
      },
      {
        name: 'get_competition_matches',
        description:
          'List matches in a competition. Filter by status (SCHEDULED, LIVE, IN_PLAY, PAUSED, FINISHED, POSTPONED, SUSPENDED, CANCELLED), date range, matchday, stage, or season year.',
        inputSchema: {
          type: 'object',
          properties: {
            competition: {
              type: 'string',
              description: 'Competition code (e.g. "PL" = Premier League, "PD" = La Liga, "CL" = Champions League)',
            },
            status: {
              type: 'string',
              description:
                'Match status filter (SCHEDULED | LIVE | IN_PLAY | PAUSED | FINISHED | POSTPONED | SUSPENDED | CANCELLED)',
            },
            date_from: { type: 'string', description: 'Start date filter YYYY-MM-DD' },
            date_to: { type: 'string', description: 'End date filter YYYY-MM-DD' },
            matchday: { type: 'number', description: 'Round number' },
            stage: { type: 'string', description: 'Stage (e.g. "GROUP_STAGE", "QUARTER_FINALS")' },
            season: { type: 'number', description: 'Season start year (e.g. 2025)' },
          },
          required: ['competition'],
        },
      },
      {
        name: 'get_competition_standings',
        description: 'League table for a competition season. Returns total / home / away tables.',
        inputSchema: {
          type: 'object',
          properties: {
            competition: { type: 'string', description: 'Competition code' },
            season: { type: 'number', description: 'Season start year (optional, defaults current)' },
            matchday: { type: 'number', description: 'Standings as of a specific matchday (optional)' },
          },
          required: ['competition'],
        },
      },
      {
        name: 'get_team',
        description: 'Team detail by ID — current squad, coach, running competitions, venue.',
        inputSchema: {
          type: 'object',
          properties: {
            team_id: { type: 'number', description: 'football-data.org numeric team ID (e.g. 64 = Liverpool)' },
          },
          required: ['team_id'],
        },
      },
      {
        name: 'get_team_matches',
        description: "A team's matches across competitions. Filter by status, date range, venue (HOME|AWAY), season, or limit.",
        inputSchema: {
          type: 'object',
          properties: {
            team_id: { type: 'number', description: 'Numeric team ID' },
            status: { type: 'string', description: 'Match status filter' },
            date_from: { type: 'string', description: 'Start date YYYY-MM-DD' },
            date_to: { type: 'string', description: 'End date YYYY-MM-DD' },
            venue: { type: 'string', description: 'HOME | AWAY' },
            season: { type: 'number', description: 'Season start year' },
            limit: { type: 'number', description: 'Cap matches returned (default 50)' },
          },
          required: ['team_id'],
        },
      },
    ];
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<ToolResult> {
    try {
      switch (name) {
        case 'list_competitions':
          return this.listCompetitions();
        case 'get_competition_matches':
          return this.getCompetitionMatches(args);
        case 'get_competition_standings':
          return this.getCompetitionStandings(args);
        case 'get_team':
          return this.getTeam(args);
        case 'get_team_matches':
          return this.getTeamMatches(args);
        default:
          return {
            content: [{ type: 'text', text: `Unknown tool: ${name}` }],
            isError: true,
          };
      }
    } catch (error) {
      return {
        content: [
          {
            type: 'text',
            text: `Tool execution failed: ${error instanceof Error ? error.message : String(error)}`,
          },
        ],
        isError: true,
      };
    }
  }

  // ── Private helpers ──────────────────────────────────────────────────────────

  private async fdFetch(path: string, params?: URLSearchParams): Promise<ToolResult> {
    const qs = params?.toString() ? `?${params.toString()}` : '';
    const url = `${this.baseUrl}${path}${qs}`;
    const response = await this.fetchWithRetry(url, {
      method: 'GET',
      headers: {
        'X-Auth-Token': this.apiKey,
        Accept: 'application/json',
      },
    });
    if (response.status === 400) {
      const body = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `Football-Data: bad request — ${body.slice(0, 200)}` }],
        isError: true,
      };
    }
    if (response.status === 403) {
      return {
        content: [{ type: 'text', text: 'Football-Data: competition/resource not available on your tier (HTTP 403)' }],
        isError: true,
      };
    }
    if (!response.ok) {
      const body = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `Football-Data error: ${response.status} ${body.slice(0, 200)}` }],
        isError: true,
      };
    }
    const data = await response.json();
    return { content: [{ type: 'text', text: this.truncate(data) }], isError: false };
  }

  private buildMatchFilters(args: Record<string, unknown>): URLSearchParams {
    const params = new URLSearchParams();
    if (args.status) params.set('status', String(args.status));
    if (args.date_from) params.set('dateFrom', String(args.date_from));
    if (args.date_to) params.set('dateTo', String(args.date_to));
    if (args.matchday) params.set('matchday', String(args.matchday));
    if (args.stage) params.set('stage', String(args.stage));
    if (args.season) params.set('season', String(args.season));
    if (args.venue) params.set('venue', String(args.venue));
    if (args.limit) params.set('limit', String(args.limit));
    return params;
  }

  private requireTeamId(args: Record<string, unknown>): number {
    const v = args.team_id;
    if (typeof v !== 'number' || !Number.isFinite(v)) {
      throw new Error('Required argument "team_id" must be a number. Example: 64 (Liverpool).');
    }
    return v;
  }

  private async listCompetitions(): Promise<ToolResult> {
    return this.fdFetch('/competitions');
  }

  private async getCompetitionMatches(args: Record<string, unknown>): Promise<ToolResult> {
    if (!args.competition || String(args.competition).trim() === '') {
      return {
        content: [{ type: 'text', text: 'get_competition_matches: "competition" is required (e.g. "PL")' }],
        isError: true,
      };
    }
    const code = encodeURIComponent(String(args.competition).toUpperCase());
    const params = this.buildMatchFilters(args);
    return this.fdFetch(`/competitions/${code}/matches`, params);
  }

  private async getCompetitionStandings(args: Record<string, unknown>): Promise<ToolResult> {
    if (!args.competition || String(args.competition).trim() === '') {
      return {
        content: [{ type: 'text', text: 'get_competition_standings: "competition" is required (e.g. "PL")' }],
        isError: true,
      };
    }
    const code = encodeURIComponent(String(args.competition).toUpperCase());
    const params = new URLSearchParams();
    if (args.season) params.set('season', String(args.season));
    if (args.matchday) params.set('matchday', String(args.matchday));
    return this.fdFetch(`/competitions/${code}/standings`, params);
  }

  private async getTeam(args: Record<string, unknown>): Promise<ToolResult> {
    const teamId = this.requireTeamId(args);
    return this.fdFetch(`/teams/${teamId}`);
  }

  private async getTeamMatches(args: Record<string, unknown>): Promise<ToolResult> {
    const teamId = this.requireTeamId(args);
    const params = this.buildMatchFilters(args);
    return this.fdFetch(`/teams/${teamId}/matches`, params);
  }
}
