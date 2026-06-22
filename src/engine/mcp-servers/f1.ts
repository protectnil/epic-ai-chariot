/**
 * Formula 1 (Ergast) MCP Adapter
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

// Upstream API: Jolpica F1 (Ergast-compatible mirror — ergast.com was deprecated Dec 2024)
// Base URL: https://api.jolpi.ca/ergast/f1
// Auth: none (public, no key required)
// Docs: https://jolpi.ca/ | original: https://ergast.com/mrd/
// Category: sports
// Rate limits: none documented; please be courteous

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

const BASE_URL = 'https://api.jolpi.ca/ergast/f1';

// --- Raw API types ---

type RawDriverStanding = {
  position: string;
  positionText: string;
  points: string;
  wins: string;
  Driver: {
    driverId: string;
    permanentNumber?: string;
    code?: string;
    givenName: string;
    familyName: string;
    dateOfBirth?: string;
    nationality?: string;
  };
  Constructors: Array<{
    constructorId: string;
    name: string;
    nationality?: string;
  }>;
};

type RawStandingsTable = {
  season: string;
  round: string;
  StandingsLists: Array<{
    season: string;
    round: string;
    DriverStandings: RawDriverStanding[];
  }>;
};

type RawRaceResult = {
  number: string;
  position: string;
  positionText: string;
  points: string;
  Driver: {
    driverId: string;
    code?: string;
    givenName: string;
    familyName: string;
    nationality?: string;
  };
  Constructor: {
    constructorId: string;
    name: string;
  };
  grid: string;
  laps: string;
  status: string;
  Time?: { millis?: string; time?: string };
  FastestLap?: { rank: string; lap: string; Time?: { time?: string } };
};

type RawRace = {
  season: string;
  round: string;
  raceName: string;
  Circuit: {
    circuitId: string;
    circuitName: string;
    Location?: { locality?: string; country?: string };
  };
  date: string;
  time?: string;
  Results?: RawRaceResult[];
};

type RawDriver = {
  driverId: string;
  permanentNumber?: string;
  code?: string;
  url?: string;
  givenName: string;
  familyName: string;
  dateOfBirth?: string;
  nationality?: string;
};

type ErgastResponse<T> = {
  MRData: {
    xmlns: string;
    series: string;
    url: string;
    limit: string;
    offset: string;
    total: string;
  } & T;
};

// --- Formatters ---

function formatDriverStanding(s: RawDriverStanding) {
  return {
    position: Number(s.position),
    points: Number(s.points),
    wins: Number(s.wins),
    driver_id: s.Driver.driverId,
    number: s.Driver.permanentNumber ?? null,
    code: s.Driver.code ?? null,
    name: `${s.Driver.givenName} ${s.Driver.familyName}`,
    nationality: s.Driver.nationality ?? null,
    constructor: s.Constructors[0]?.name ?? null,
  };
}

function formatRaceResult(r: RawRaceResult) {
  return {
    position: Number(r.position),
    number: r.number,
    driver_id: r.Driver.driverId,
    code: r.Driver.code ?? null,
    name: `${r.Driver.givenName} ${r.Driver.familyName}`,
    constructor: r.Constructor.name,
    grid: Number(r.grid),
    laps: Number(r.laps),
    status: r.status,
    points: Number(r.points),
    time: r.Time?.time ?? null,
    fastest_lap_time: r.FastestLap?.Time?.time ?? null,
  };
}

function formatRace(race: RawRace) {
  return {
    season: race.season,
    round: Number(race.round),
    name: race.raceName,
    circuit_id: race.Circuit.circuitId,
    circuit_name: race.Circuit.circuitName,
    locality: race.Circuit.Location?.locality ?? null,
    country: race.Circuit.Location?.country ?? null,
    date: race.date,
    time: race.time ?? null,
  };
}

function formatDriver(d: RawDriver) {
  return {
    driver_id: d.driverId,
    number: d.permanentNumber ?? null,
    code: d.code ?? null,
    name: `${d.givenName} ${d.familyName}`,
    date_of_birth: d.dateOfBirth ?? null,
    nationality: d.nationality ?? null,
    url: d.url ?? null,
  };
}

export class F1MCPServer extends MCPAdapterBase {
  private readonly baseUrl: string;

  constructor(config?: { baseUrl?: string }) {
    super();
    if (config === null) { throw new Error('F1MCPServer: configuration object is required when provided'); }
    this.baseUrl = config?.baseUrl ?? BASE_URL;
  }

  static catalog() {
    return {
      name: 'f1',
      displayName: 'Formula 1 (Jolpica/Ergast)',
      version: '1.0.0',
      category: 'sports',
      keywords: [
        'formula 1', 'f1', 'formula one', 'ergast', 'motorsport', 'racing',
        'grand prix', 'driver standings', 'race results', 'race schedule',
        'championship', 'constructor', 'driver', 'circuit',
      ],
      toolNames: ['get_current_standings', 'get_race_results', 'get_schedule', 'get_driver'],
      description: 'Formula 1 data via the Jolpica F1 API (Ergast-compatible mirror): driver standings, race results, season schedules, and driver profiles — free and unauthenticated.',
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
        name: 'get_current_standings',
        description:
          'Get the current Formula 1 season driver championship standings. Returns position, points, wins, driver name, and constructor.',
        inputSchema: {
          type: 'object',
          properties: {},
        },
      },
      {
        name: 'get_race_results',
        description:
          'Get finishing results for a specific F1 race by season year and round number. Returns position, driver, constructor, status, and points.',
        inputSchema: {
          type: 'object',
          properties: {
            season: { type: 'string', description: 'Season year (e.g., "2025")' },
            round: { type: 'string', description: 'Round number within the season (e.g., "1")' },
          },
          required: ['season', 'round'],
        },
      },
      {
        name: 'get_schedule',
        description:
          'Get the full race calendar/schedule for an F1 season. Returns round number, race name, circuit, location, and date for each round.',
        inputSchema: {
          type: 'object',
          properties: {
            season: { type: 'string', description: 'Season year (e.g., "2025")' },
          },
          required: ['season'],
        },
      },
      {
        name: 'get_driver',
        description:
          'Get profile information for an F1 driver by their Ergast driver ID. Returns name, number, nationality, and date of birth.',
        inputSchema: {
          type: 'object',
          properties: {
            driverId: {
              type: 'string',
              description: 'Ergast driver ID (e.g., "hamilton", "verstappen", "leclerc")',
            },
          },
          required: ['driverId'],
        },
      },
    ];
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<ToolResult> {
    try {
      switch (name) {
        case 'get_current_standings': return this.getCurrentStandings();
        case 'get_race_results':      return this.getRaceResults(args.season as string, args.round as string);
        case 'get_schedule':          return this.getSchedule(args.season as string);
        case 'get_driver':            return this.getDriverProfile(args.driverId as string);
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

  private async ergastGet(path: string): Promise<Response> {
    return this.fetchWithRetry(`${this.baseUrl}${path}`, {
      method: 'GET',
      headers: { Accept: 'application/json' },
    });
  }

  private async getCurrentStandings(): Promise<ToolResult> {
    const response = await this.ergastGet('/current/driverStandings.json');
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return { content: [{ type: 'text', text: `API error: ${response.status} ${errText}` }], isError: true };
    }
    const data = (await response.json()) as ErgastResponse<{ StandingsTable: RawStandingsTable }>;
    const list = data.MRData.StandingsTable.StandingsLists[0];
    const result = list
      ? { season: list.season, round: Number(list.round), standings: list.DriverStandings.map(formatDriverStanding) }
      : { season: null, round: null, standings: [] };
    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }

  private async getRaceResults(season: string, round: string): Promise<ToolResult> {
    const response = await this.ergastGet(`/${encodeURIComponent(season)}/${encodeURIComponent(round)}/results.json`);
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return { content: [{ type: 'text', text: `API error: ${response.status} ${errText}` }], isError: true };
    }
    const data = (await response.json()) as ErgastResponse<{ RaceTable: { Races: RawRace[] } }>;
    const race = data.MRData.RaceTable.Races[0];
    if (!race) {
      return { content: [{ type: 'text', text: `No race found for season ${season} round ${round}` }], isError: true };
    }
    const result = {
      season: race.season,
      round: Number(race.round),
      name: race.raceName,
      circuit: race.Circuit.circuitName,
      date: race.date,
      results: (race.Results ?? []).map(formatRaceResult),
    };
    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }

  private async getSchedule(season: string): Promise<ToolResult> {
    const response = await this.ergastGet(`/${encodeURIComponent(season)}.json`);
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return { content: [{ type: 'text', text: `API error: ${response.status} ${errText}` }], isError: true };
    }
    const data = (await response.json()) as ErgastResponse<{ RaceTable: { Races: RawRace[] } }>;
    const races = data.MRData.RaceTable.Races;
    const result = { season, total: races.length, schedule: races.map(formatRace) };
    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }

  private async getDriverProfile(driverId: string): Promise<ToolResult> {
    const response = await this.ergastGet(`/drivers/${encodeURIComponent(driverId)}.json`);
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return { content: [{ type: 'text', text: `API error: ${response.status} ${errText}` }], isError: true };
    }
    const data = (await response.json()) as ErgastResponse<{ DriverTable: { Drivers: RawDriver[] } }>;
    const driver = data.MRData.DriverTable.Drivers[0];
    if (!driver) {
      return { content: [{ type: 'text', text: `Driver not found: ${driverId}` }], isError: true };
    }
    return { content: [{ type: 'text', text: this.truncate(formatDriver(driver)) }], isError: false };
  }
}
