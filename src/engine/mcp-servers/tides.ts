/**
 * NOAA Tides and Currents MCP Adapter
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

// Base URL: https://api.tidesandcurrents.noaa.gov/api/prod/datagetter
// Stations URL: https://api.tidesandcurrents.noaa.gov/mdapi/prod/webapi/stations.json
// Auth: None — public NOAA API
// Docs: https://api.tidesandcurrents.noaa.gov/api/prod/
// Category: weather
// Rate limits: No documented limit; public government data service

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

const BASE_URL = 'https://api.tidesandcurrents.noaa.gov/api/prod/datagetter';
const STATIONS_URL = 'https://api.tidesandcurrents.noaa.gov/mdapi/prod/webapi/stations.json';

export class TidesMCPServer extends MCPAdapterBase {
  constructor() {
    super();
  }

  static catalog() {
    return {
      name: 'tides',
      displayName: 'NOAA Tides and Currents',
      version: '1.0.0',
      category: 'weather',
      keywords: [
        'tides', 'noaa', 'water level', 'tide predictions', 'currents',
        'coastal', 'ocean', 'mllw', 'hi lo', 'tide stations', 'nautical',
        'marine', 'sea level', 'tidal',
      ],
      toolNames: ['get_predictions', 'get_water_levels', 'list_stations'],
      description: 'NOAA Tides and Currents: get hi/lo tide predictions for a date range, retrieve the latest observed water level, and list all NOAA tide prediction stations — free public API, no authentication required.',
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
        name: 'get_predictions',
        description:
          'Get hi/lo tide predictions for a NOAA station over a date range. Dates must be formatted YYYYMMDD.',
        inputSchema: {
          type: 'object',
          properties: {
            station_id: {
              type: 'string',
              description: 'NOAA station ID (e.g. "9414290" for San Francisco)',
            },
            begin_date: {
              type: 'string',
              description: 'Start date in YYYYMMDD format (e.g. "20240101")',
            },
            end_date: {
              type: 'string',
              description: 'End date in YYYYMMDD format (e.g. "20240107")',
            },
          },
          required: ['station_id', 'begin_date', 'end_date'],
        },
      },
      {
        name: 'get_water_levels',
        description: 'Get the latest observed water level for a NOAA station.',
        inputSchema: {
          type: 'object',
          properties: {
            station_id: {
              type: 'string',
              description: 'NOAA station ID (e.g. "9414290" for San Francisco)',
            },
          },
          required: ['station_id'],
        },
      },
      {
        name: 'list_stations',
        description: 'List all NOAA tide prediction stations with their IDs and names.',
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
        case 'get_predictions':  return this.getPredictions(args);
        case 'get_water_levels': return this.getWaterLevels(args);
        case 'list_stations':    return this.listStations();
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

  private async getPredictions(args: Record<string, unknown>): Promise<ToolResult> {
    const stationId = args.station_id as string;
    const beginDate = args.begin_date as string;
    const endDate = args.end_date as string;

    const params = new URLSearchParams({
      station: stationId,
      product: 'predictions',
      datum: 'MLLW',
      units: 'english',
      time_zone: 'lst_ldt',
      interval: 'hilo',
      format: 'json',
      begin_date: beginDate,
      end_date: endDate,
    });

    const response = await this.fetchWithRetry(`${BASE_URL}?${params}`, {
      method: 'GET',
      headers: { Accept: 'application/json' },
    });

    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `NOAA tides API error: ${response.status} ${errText}` }],
        isError: true,
      };
    }

    const data = await response.json() as { predictions?: Array<{ t: string; v: string; type: string }>; error?: { message: string } };

    if (data.error) {
      return {
        content: [{ type: 'text', text: `NOAA tides error: ${data.error.message}` }],
        isError: true,
      };
    }

    const result = {
      station_id: stationId,
      begin_date: beginDate,
      end_date: endDate,
      datum: 'MLLW',
      units: 'feet',
      count: data.predictions?.length ?? 0,
      predictions: data.predictions ?? [],
    };

    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }

  private async getWaterLevels(args: Record<string, unknown>): Promise<ToolResult> {
    const stationId = args.station_id as string;

    const params = new URLSearchParams({
      station: stationId,
      product: 'water_level',
      datum: 'MLLW',
      units: 'english',
      time_zone: 'lst_ldt',
      format: 'json',
      date: 'latest',
    });

    const response = await this.fetchWithRetry(`${BASE_URL}?${params}`, {
      method: 'GET',
      headers: { Accept: 'application/json' },
    });

    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `NOAA water level API error: ${response.status} ${errText}` }],
        isError: true,
      };
    }

    const data = await response.json() as {
      data?: Array<{ t: string; v: string; s: string; f: string; q: string }>;
      error?: { message: string };
    };

    if (data.error) {
      return {
        content: [{ type: 'text', text: `NOAA water level error: ${data.error.message}` }],
        isError: true,
      };
    }

    const latest = data.data?.[0] ?? null;

    const result = {
      station_id: stationId,
      datum: 'MLLW',
      units: 'feet',
      latest: latest
        ? {
            time: latest.t,
            value_ft: parseFloat(latest.v),
            sigma: latest.s,
            quality: latest.q,
          }
        : null,
    };

    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }

  private async listStations(): Promise<ToolResult> {
    const response = await this.fetchWithRetry(
      `${STATIONS_URL}?type=tidepredictions`,
      {
        method: 'GET',
        headers: { Accept: 'application/json' },
      },
    );

    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `NOAA stations API error: ${response.status} ${errText}` }],
        isError: true,
      };
    }

    const data = await response.json() as {
      stations: Array<{ id: string; name: string; state?: string; lat?: number; lng?: number }>;
    };

    const result = {
      count: data.stations.length,
      stations: data.stations.map((s) => ({
        id: s.id,
        name: s.name,
        state: s.state ?? null,
        lat: s.lat ?? null,
        lng: s.lng ?? null,
      })),
    };

    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }
}
