/**
 * MLB Stats MCP Adapter
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

// Official REST API: https://statsapi.mlb.com/api/v1
// Auth: none required (public, keyless)
// Docs: https://github.com/MiLB-ThreeOh/mlb-stats-api (community docs)
// Category: sports
// Rate limits: not published; no auth required

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

const BASE_URL = 'https://statsapi.mlb.com/api/v1';

export class MlbStatsMCPServer extends MCPAdapterBase {
  private readonly baseUrl: string;

  constructor(config?: { baseUrl?: string }) {
    super();
    if (config === null) { throw new Error('MlbStatsMCPServer: configuration object is required when provided'); }
    this.baseUrl = config?.baseUrl ?? BASE_URL;
  }

  static catalog() {
    return {
      name: 'mlb-stats',
      displayName: 'MLB Stats',
      version: '1.0.0',
      category: 'sports',
      keywords: [
        'mlb', 'baseball', 'stats', 'teams', 'standings', 'schedule',
        'roster', 'player', 'scores', 'sports', 'american league',
        'national league', 'divisions', 'season',
      ],
      toolNames: [
        'get_teams',
        'get_standings',
        'get_schedule',
        'get_roster',
        'get_player',
        'player_stats',
        'get_boxscore',
        'get_game_feed',
      ],
      description: 'MLB Stats: official MLB statistics — teams, division standings, daily schedule/scores, active rosters, player bios, season stat lines, game box scores, and live game feeds via the public MLB Stats API.',
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
        name: 'get_teams',
        description:
          'List all MLB teams from the official MLB Stats API. Returns each team with id, name, abbreviation, location, league, division, and home venue.',
        inputSchema: {
          type: 'object',
          properties: {},
        },
      },
      {
        name: 'get_standings',
        description:
          'MLB division standings (regular season) from the official MLB Stats API. Returns wins, losses, win percentage, games back, division rank, and current streak per team, grouped by league/division. Pass the desired season year (e.g. "2024"); defaults to "2024" if omitted.',
        inputSchema: {
          type: 'object',
          properties: {
            season: {
              type: 'string',
              description: 'Season year, e.g. "2024". Defaults to "2024" if omitted — pass the year you want.',
            },
            league_id: {
              type: 'string',
              description: 'Comma-separated league IDs (103=AL, 104=NL). Default "103,104" (both).',
            },
          },
        },
      },
      {
        name: 'get_schedule',
        description:
          "MLB daily schedule and scores from the official MLB Stats API. Returns each game's teams, scores, status, and venue. Pass a date (YYYY-MM-DD) or omit for today's games.",
        inputSchema: {
          type: 'object',
          properties: {
            date: {
              type: 'string',
              description: "Date in YYYY-MM-DD. Omit to get today's schedule.",
            },
          },
        },
      },
      {
        name: 'get_roster',
        description:
          'Active roster for an MLB team from the official MLB Stats API. Returns each player with id, name, jersey number, and position abbreviation.',
        inputSchema: {
          type: 'object',
          properties: {
            team_id: {
              type: ['number', 'string'],
              description: 'MLB team id (e.g. 147 for the Yankees).',
            },
          },
          required: ['team_id'],
        },
      },
      {
        name: 'get_player',
        description:
          'Player biographical profile from the official MLB Stats API. Returns name, number, birth date, age, height, weight, position, bats/throws, and MLB debut date.',
        inputSchema: {
          type: 'object',
          properties: {
            person_id: {
              type: ['number', 'string'],
              description: 'MLB person/player id (e.g. 660271).',
            },
          },
          required: ['person_id'],
        },
      },
      {
        name: 'player_stats',
        description:
          'Season statistics line for an MLB player from the official MLB Stats API. Returns the aggregate stat object for the requested season and group (hitting: AVG/OBP/SLG, HR, RBI, games; pitching: ERA, WHIP, strikeouts, etc.).',
        inputSchema: {
          type: 'object',
          properties: {
            person_id: { type: ['number', 'string'], description: 'MLB person/player id (e.g. 660271).' },
            season: { type: 'string', description: 'Season year, e.g. "2024". Defaults to "2024".' },
            group: { type: 'string', description: "Stat group: 'hitting', 'pitching', or 'fielding'. Default 'hitting'." },
          },
          required: ['person_id'],
        },
      },
      {
        name: 'get_boxscore',
        description:
          "Box score for an MLB game from the official MLB Stats API. Returns each team's batting and pitching summary. Pass the gamePk (from get_schedule).",
        inputSchema: {
          type: 'object',
          properties: {
            game_pk: { type: ['number', 'string'], description: 'MLB gamePk (from get_schedule).' },
          },
          required: ['game_pk'],
        },
      },
      {
        name: 'get_game_feed',
        description:
          'Live game feed summary for an MLB game from the official MLB Stats API (v1.1). Returns game status, the linescore (runs/hits/errors by inning), and decisions (winning/losing/save pitchers). Pass the gamePk (from get_schedule).',
        inputSchema: {
          type: 'object',
          properties: {
            game_pk: { type: ['number', 'string'], description: 'MLB gamePk (from get_schedule).' },
          },
          required: ['game_pk'],
        },
      },
    ];
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<ToolResult> {
    try {
      switch (name) {
        case 'get_teams':     return this.getTeams();
        case 'get_standings': return this.getStandings(args);
        case 'get_schedule':  return this.getSchedule(args);
        case 'get_roster':    return this.getRoster(args);
        case 'get_player':    return this.getPlayer(args);
        case 'player_stats':  return this.getPlayerStats(args);
        case 'get_boxscore':  return this.getBoxscore(args);
        case 'get_game_feed': return this.getGameFeed(args);
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

  private async mlbGet(path: string): Promise<ToolResult> {
    const url = `${this.baseUrl}${path}`;
    const response = await this.fetchWithRetry(url, {
      method: 'GET',
      headers: { Accept: 'application/json', 'User-Agent': 'epic-ai-chariot/1.0' },
    });
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `MLB Stats API error: ${response.status} ${errText}` }],
        isError: true,
      };
    }
    const data = await response.json();
    return { content: [{ type: 'text', text: JSON.stringify(data) }], isError: false };
  }

  private async getTeams(): Promise<ToolResult> {
    const result = await this.mlbGet('/teams?sportId=1');
    if (result.isError) return result;
    const raw = JSON.parse(result.content[0].text) as { teams?: Record<string, unknown>[] };
    const teams = (raw.teams ?? []).map((t) => ({
      id: t['id'],
      name: t['name'],
      abbreviation: t['abbreviation'],
      location: t['locationName'],
      league: (t['league'] as Record<string, unknown> | undefined)?.['name'],
      division: (t['division'] as Record<string, unknown> | undefined)?.['name'],
      venue: (t['venue'] as Record<string, unknown> | undefined)?.['name'],
    }));
    return { content: [{ type: 'text', text: this.truncate({ count: teams.length, teams }) }], isError: false };
  }

  private async getStandings(args: Record<string, unknown>): Promise<ToolResult> {
    const season = this.strArg(args['season']) ?? '2024';
    const leagueId = this.strArg(args['league_id']) ?? '103,104';
    const params = new URLSearchParams({
      leagueId,
      season,
      standingsTypes: 'regularSeason',
    });
    const result = await this.mlbGet(`/standings?${params.toString()}`);
    if (result.isError) return result;
    const raw = JSON.parse(result.content[0].text) as { records?: Record<string, unknown>[] };
    const divisions = (raw.records ?? []).map((r) => ({
      league_id: (r['league'] as Record<string, unknown> | undefined)?.['id'],
      division_id: (r['division'] as Record<string, unknown> | undefined)?.['id'],
      teams: ((r['teamRecords'] as Record<string, unknown>[]) ?? []).map((tr) => ({
        team: (tr['team'] as Record<string, unknown> | undefined)?.['name'],
        wins: tr['wins'],
        losses: tr['losses'],
        pct: tr['winningPercentage'],
        gamesBack: tr['gamesBack'],
        divisionRank: tr['divisionRank'],
        streak: (tr['streak'] as Record<string, unknown> | undefined)?.['streakCode'],
      })),
    }));
    return { content: [{ type: 'text', text: this.truncate({ season, divisions }) }], isError: false };
  }

  private async getSchedule(args: Record<string, unknown>): Promise<ToolResult> {
    const params = new URLSearchParams({ sportId: '1' });
    const date = this.strArg(args['date']);
    if (date) params.set('date', date);
    const result = await this.mlbGet(`/schedule?${params.toString()}`);
    if (result.isError) return result;
    const raw = JSON.parse(result.content[0].text) as { dates?: Record<string, unknown>[] };
    const games: unknown[] = [];
    for (const d of raw.dates ?? []) {
      for (const g of ((d['games'] as Record<string, unknown>[]) ?? [])) {
        const teams = g['teams'] as Record<string, Record<string, unknown>> | undefined;
        games.push({
          gamePk: g['gamePk'],
          date: g['gameDate'],
          status: (g['status'] as Record<string, unknown> | undefined)?.['detailedState'],
          away: {
            team: teams?.['away']?.['team'] && (teams['away']['team'] as Record<string, unknown>)['name'],
            score: teams?.['away']?.['score'],
          },
          home: {
            team: teams?.['home']?.['team'] && (teams['home']['team'] as Record<string, unknown>)['name'],
            score: teams?.['home']?.['score'],
          },
          venue: (g['venue'] as Record<string, unknown> | undefined)?.['name'],
        });
      }
    }
    return { content: [{ type: 'text', text: this.truncate({ count: games.length, games }) }], isError: false };
  }

  private async getRoster(args: Record<string, unknown>): Promise<ToolResult> {
    const teamId = this.reqIdArg(args, 'team_id', '147');
    const result = await this.mlbGet(`/teams/${encodeURIComponent(teamId)}/roster?rosterType=active`);
    if (result.isError) return result;
    const raw = JSON.parse(result.content[0].text) as { roster?: Record<string, unknown>[] };
    const roster = (raw.roster ?? []).map((r) => ({
      id: (r['person'] as Record<string, unknown> | undefined)?.['id'],
      name: (r['person'] as Record<string, unknown> | undefined)?.['fullName'],
      number: r['jerseyNumber'],
      position: (r['position'] as Record<string, unknown> | undefined)?.['abbreviation'],
    }));
    return { content: [{ type: 'text', text: this.truncate({ count: roster.length, roster }) }], isError: false };
  }

  private async getPlayer(args: Record<string, unknown>): Promise<ToolResult> {
    const personId = this.reqIdArg(args, 'person_id', '660271');
    const result = await this.mlbGet(`/people/${encodeURIComponent(personId)}`);
    if (result.isError) return result;
    const raw = JSON.parse(result.content[0].text) as { people?: Record<string, unknown>[] };
    const p = (raw.people ?? [])[0];
    if (!p) {
      return { content: [{ type: 'text', text: JSON.stringify({ error: 'player not found', person_id: personId }) }], isError: true };
    }
    const player = {
      id: p['id'],
      name: p['fullName'],
      number: p['primaryNumber'],
      birthDate: p['birthDate'],
      age: p['currentAge'],
      height: p['height'],
      weight: p['weight'],
      position: (p['primaryPosition'] as Record<string, unknown> | undefined)?.['name'],
      bats: (p['batSide'] as Record<string, unknown> | undefined)?.['description'],
      throws: (p['pitchHand'] as Record<string, unknown> | undefined)?.['description'],
      debut: p['mlbDebutDate'],
    };
    return { content: [{ type: 'text', text: this.truncate(player) }], isError: false };
  }

  private async getPlayerStats(args: Record<string, unknown>): Promise<ToolResult> {
    const personId = this.reqIdArg(args, 'person_id', '660271');
    const season = this.strArg(args['season']) ?? '2024';
    const group = this.strArg(args['group']) ?? 'hitting';
    const params = new URLSearchParams({ stats: 'season', group, season });
    const result = await this.mlbGet(`/people/${encodeURIComponent(personId)}/stats?${params.toString()}`);
    if (result.isError) return result;
    const raw = JSON.parse(result.content[0].text) as { stats?: Record<string, unknown>[] };
    const split = ((raw.stats ?? [])[0]?.['splits'] as Record<string, unknown>[] | undefined)?.[0];
    if (!split) {
      return { content: [{ type: 'text', text: JSON.stringify({ note: 'no stats for this player/season/group', person_id: personId, season, group }) }], isError: false };
    }
    return {
      content: [{ type: 'text', text: this.truncate({ person_id: personId, season, group, team: (split['team'] as Record<string, unknown> | undefined)?.['name'], stat: split['stat'] }) }],
      isError: false,
    };
  }

  private async getBoxscore(args: Record<string, unknown>): Promise<ToolResult> {
    const gamePk = this.reqIdArg(args, 'game_pk', '744914');
    const result = await this.mlbGet(`/game/${encodeURIComponent(gamePk)}/boxscore`);
    if (result.isError) return result;
    const raw = JSON.parse(result.content[0].text) as { teams?: Record<string, Record<string, unknown>> };
    const side = (s: Record<string, unknown> | undefined) => s && {
      team: (s['team'] as Record<string, unknown> | undefined)?.['name'],
      batting: (s['teamStats'] as Record<string, Record<string, unknown>> | undefined)?.['batting'],
      pitching: (s['teamStats'] as Record<string, Record<string, unknown>> | undefined)?.['pitching'],
    };
    return {
      content: [{ type: 'text', text: this.truncate({ game_pk: gamePk, home: side(raw.teams?.['home']), away: side(raw.teams?.['away']) }) }],
      isError: false,
    };
  }

  private async getGameFeed(args: Record<string, unknown>): Promise<ToolResult> {
    const gamePk = this.reqIdArg(args, 'game_pk', '744914');
    // The live feed lives on the v1.1 surface, not v1.
    const feedBase = this.baseUrl.replace(/\/api\/v1$/, '/api/v1.1');
    const url = `${feedBase}/game/${encodeURIComponent(gamePk)}/feed/live`;
    const response = await this.fetchWithRetry(url, {
      method: 'GET',
      headers: { Accept: 'application/json', 'User-Agent': 'epic-ai-chariot/1.0' },
    });
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return { content: [{ type: 'text', text: `MLB Stats API error: ${response.status} ${errText}` }], isError: true };
    }
    const data = (await response.json()) as { gameData?: Record<string, unknown>; liveData?: Record<string, unknown> };
    const status = (data.gameData?.['status'] as Record<string, unknown> | undefined)?.['detailedState'];
    return {
      content: [{ type: 'text', text: this.truncate({ game_pk: gamePk, status, linescore: data.liveData?.['linescore'], decisions: data.liveData?.['decisions'] }) }],
      isError: false,
    };
  }

  // ── Arg helpers ─────────────────────────────────────────────────────────────

  private strArg(v: unknown): string | undefined {
    if (typeof v === 'string') {
      const t = v.trim();
      return t ? t : undefined;
    }
    if (typeof v === 'number' && Number.isFinite(v)) return String(v);
    return undefined;
  }

  private reqIdArg(args: Record<string, unknown>, key: string, example: string): string {
    const v = args[key];
    if (typeof v === 'number' && Number.isFinite(v)) return String(v);
    if (typeof v === 'string' && v.trim()) return v.trim();
    throw new Error(`Required argument "${key}" is missing. Pass a number or string id like ${example}.`);
  }
}
