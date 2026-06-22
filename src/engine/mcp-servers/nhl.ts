/**
 * NHL MCP Adapter
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

// Base URL: https://api-web.nhle.com/v1
// Auth: None (official NHL public API, no key required)
// Docs: https://github.com/Zmalski/NHL-API-Reference
// Category: sports
// Rate limits: Not documented — public, fair-use

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

const BASE_URL = 'https://api-web.nhle.com/v1';

// --- Raw API types ---

type RawTeamRecord = {
  teamName?: { default?: string } | null;
  teamAbbrev?: { default?: string } | null;
  divisionName?: string | null;
  conferenceName?: string | null;
  wins?: number | null;
  losses?: number | null;
  otLosses?: number | null;
  points?: number | null;
  gamesPlayed?: number | null;
  goalFor?: number | null;
  goalAgainst?: number | null;
  streakCode?: string | null;
  streakCount?: number | null;
};

type RawStandingsResponse = {
  standings: RawTeamRecord[];
};

type RawGame = {
  id?: number | null;
  gameState?: string | null;
  awayTeam?: {
    abbrev?: string | null;
    name?: { default?: string } | null;
    score?: number | null;
    sog?: number | null;
  } | null;
  homeTeam?: {
    abbrev?: string | null;
    name?: { default?: string } | null;
    score?: number | null;
    sog?: number | null;
  } | null;
  startTimeUTC?: string | null;
  period?: number | null;
};

type RawScoreResponse = {
  currentDate?: string | null;
  games: RawGame[];
};

type RawScheduleGame = {
  id?: number | null;
  gameDate?: string | null;
  startTimeUTC?: string | null;
  gameState?: string | null;
  awayTeam?: { abbrev?: string | null; name?: { default?: string } | null } | null;
  homeTeam?: { abbrev?: string | null; name?: { default?: string } | null } | null;
  venue?: { default?: string } | null;
};

type RawScheduleResponse = {
  currentDate?: string | null;
  gameWeek?: Array<{
    date?: string;
    games?: RawScheduleGame[];
  }> | null;
};

type RawPlayerLanding = {
  playerId?: number | null;
  firstName?: { default?: string } | null;
  lastName?: { default?: string } | null;
  sweaterNumber?: number | null;
  position?: string | null;
  headshot?: string | null;
  birthDate?: string | null;
  birthCity?: { default?: string } | null;
  birthCountry?: string | null;
  heightInInches?: number | null;
  weightInPounds?: number | null;
  currentTeamAbbrev?: string | null;
  currentTeamName?: { default?: string } | null;
  featuredStats?: {
    season?: number | null;
    regularSeason?: {
      subSeason?: {
        gamesPlayed?: number | null;
        goals?: number | null;
        assists?: number | null;
        points?: number | null;
        plusMinus?: number | null;
        pim?: number | null;
      };
    } | null;
  } | null;
};

export class NhlMCPServer extends MCPAdapterBase {
  constructor() {
    super();
  }

  static catalog() {
    return {
      name: 'nhl',
      displayName: 'NHL',
      version: '1.0.0',
      category: 'sports' as const,
      keywords: [
        'nhl', 'hockey', 'ice hockey', 'standings', 'scores', 'schedule',
        'player', 'stats', 'league', 'teams', 'goals', 'assists', 'points',
        'playoffs', 'season', 'live scores', 'sports data',
      ],
      toolNames: ['get_standings', 'get_scores', 'get_schedule', 'get_player'],
      description: 'NHL: retrieve live NHL standings, game scores, weekly schedule, and detailed player profiles with current-season stats — via the official NHL public API, no authentication required.',
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
        name: 'get_standings',
        description:
          'Get current NHL standings for all teams. Returns wins, losses, OT losses, points, goals for/against, and streak.',
        inputSchema: {
          type: 'object',
          properties: {},
        },
      },
      {
        name: 'get_scores',
        description:
          "Get today's NHL game scores and states (live, final, scheduled). Returns teams, scores, shots on goal, and period.",
        inputSchema: {
          type: 'object',
          properties: {},
        },
      },
      {
        name: 'get_schedule',
        description:
          'Get the current NHL weekly schedule. Returns upcoming and recent games with teams, dates, and venues.',
        inputSchema: {
          type: 'object',
          properties: {},
        },
      },
      {
        name: 'get_player',
        description:
          'Get detailed profile and current season stats for an NHL player by their numeric player ID.',
        inputSchema: {
          type: 'object',
          properties: {
            playerId: {
              type: 'number',
              description: 'NHL player ID (e.g., 8478402 for Connor McDavid)',
            },
          },
          required: ['playerId'],
        },
      },
    ];
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<ToolResult> {
    try {
      switch (name) {
        case 'get_standings': return this.getStandings();
        case 'get_scores':    return this.getScores();
        case 'get_schedule':  return this.getSchedule();
        case 'get_player':    return this.getPlayer(args);
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

  private async request(path: string): Promise<ToolResult> {
    const url = `${BASE_URL}${path}`;
    const response = await this.fetchWithRetry(url, {
      method: 'GET',
      headers: { Accept: 'application/json' },
    });
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `NHL API error: ${response.status} ${errText}` }],
        isError: true,
      };
    }
    const data = await response.json();
    return { content: [{ type: 'text', text: this.truncate(data) }], isError: false };
  }

  private formatTeamRecord(team: RawTeamRecord) {
    return {
      name: team.teamName?.default ?? null,
      abbrev: team.teamAbbrev?.default ?? null,
      division: team.divisionName ?? null,
      conference: team.conferenceName ?? null,
      games_played: team.gamesPlayed ?? null,
      wins: team.wins ?? null,
      losses: team.losses ?? null,
      ot_losses: team.otLosses ?? null,
      points: team.points ?? null,
      goals_for: team.goalFor ?? null,
      goals_against: team.goalAgainst ?? null,
      streak:
        team.streakCode && team.streakCount != null
          ? `${team.streakCode}${team.streakCount}`
          : null,
    };
  }

  private formatGame(game: RawGame) {
    return {
      id: game.id ?? null,
      state: game.gameState ?? null,
      start_time_utc: game.startTimeUTC ?? null,
      period: game.period ?? null,
      away_team: game.awayTeam?.name?.default ?? game.awayTeam?.abbrev ?? null,
      away_score: game.awayTeam?.score ?? null,
      away_sog: game.awayTeam?.sog ?? null,
      home_team: game.homeTeam?.name?.default ?? game.homeTeam?.abbrev ?? null,
      home_score: game.homeTeam?.score ?? null,
      home_sog: game.homeTeam?.sog ?? null,
    };
  }

  private formatScheduleGame(game: RawScheduleGame) {
    return {
      id: game.id ?? null,
      date: game.gameDate ?? null,
      start_time_utc: game.startTimeUTC ?? null,
      state: game.gameState ?? null,
      away_team: game.awayTeam?.name?.default ?? game.awayTeam?.abbrev ?? null,
      home_team: game.homeTeam?.name?.default ?? game.homeTeam?.abbrev ?? null,
      venue: game.venue?.default ?? null,
    };
  }

  private formatPlayer(p: RawPlayerLanding) {
    const stats = p.featuredStats?.regularSeason?.subSeason;
    return {
      player_id: p.playerId ?? null,
      name:
        [p.firstName?.default, p.lastName?.default].filter(Boolean).join(' ') || null,
      number: p.sweaterNumber ?? null,
      position: p.position ?? null,
      team: p.currentTeamName?.default ?? null,
      team_abbrev: p.currentTeamAbbrev ?? null,
      birth_date: p.birthDate ?? null,
      birth_city: p.birthCity?.default ?? null,
      birth_country: p.birthCountry ?? null,
      height_in: p.heightInInches ?? null,
      weight_lbs: p.weightInPounds ?? null,
      headshot: p.headshot ?? null,
      current_season_stats: stats
        ? {
            season: p.featuredStats?.season ?? null,
            games_played: stats.gamesPlayed ?? null,
            goals: stats.goals ?? null,
            assists: stats.assists ?? null,
            points: stats.points ?? null,
            plus_minus: stats.plusMinus ?? null,
            pim: stats.pim ?? null,
          }
        : null,
    };
  }

  private async getStandings(): Promise<ToolResult> {
    const response = await this.fetchWithRetry(`${BASE_URL}/standings/now`, {
      method: 'GET',
      headers: { Accept: 'application/json' },
    });
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `NHL API error: ${response.status} ${errText}` }],
        isError: true,
      };
    }
    const data = (await response.json()) as RawStandingsResponse;
    const result = {
      total: data.standings.length,
      standings: data.standings.map((t) => this.formatTeamRecord(t)),
    };
    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }

  private async getScores(): Promise<ToolResult> {
    const response = await this.fetchWithRetry(`${BASE_URL}/score/now`, {
      method: 'GET',
      headers: { Accept: 'application/json' },
    });
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `NHL API error: ${response.status} ${errText}` }],
        isError: true,
      };
    }
    const data = (await response.json()) as RawScoreResponse;
    const result = {
      date: data.currentDate ?? null,
      total_games: data.games.length,
      games: data.games.map((g) => this.formatGame(g)),
    };
    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }

  private async getSchedule(): Promise<ToolResult> {
    const response = await this.fetchWithRetry(`${BASE_URL}/schedule/now`, {
      method: 'GET',
      headers: { Accept: 'application/json' },
    });
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `NHL API error: ${response.status} ${errText}` }],
        isError: true,
      };
    }
    const data = (await response.json()) as RawScheduleResponse;
    const allGames: ReturnType<NhlMCPServer['formatScheduleGame']>[] = [];
    for (const week of data.gameWeek ?? []) {
      for (const game of week.games ?? []) {
        allGames.push(this.formatScheduleGame(game));
      }
    }
    const result = {
      current_date: data.currentDate ?? null,
      total_games: allGames.length,
      games: allGames,
    };
    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }

  private async getPlayer(args: Record<string, unknown>): Promise<ToolResult> {
    const playerId = args.playerId;
    if (typeof playerId !== 'number' || !Number.isFinite(playerId)) {
      return {
        content: [{ type: 'text', text: 'get_player: playerId must be a finite number' }],
        isError: true,
      };
    }
    const response = await this.fetchWithRetry(
      `${BASE_URL}/player/${encodeURIComponent(String(playerId))}/landing`,
      { method: 'GET', headers: { Accept: 'application/json' } },
    );
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `NHL API error: ${response.status} ${errText}` }],
        isError: true,
      };
    }
    const data = (await response.json()) as RawPlayerLanding;
    return { content: [{ type: 'text', text: this.truncate(this.formatPlayer(data)) }], isError: false };
  }
}
