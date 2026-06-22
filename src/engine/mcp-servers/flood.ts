/**
 * Open-Meteo Flood API MCP Adapter
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

// Base URL: https://flood-api.open-meteo.com/v1
// Auth: None (free, no API key required)
// Docs: https://open-meteo.com/en/docs/flood-api
// Category: weather
// Rate limits: Free, fair-use — no stated hard cap

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

const BASE_URL = 'https://flood-api.open-meteo.com/v1';

interface FloodApiResponse {
  latitude: number;
  longitude: number;
  elevation: number;
  generationtime_ms: number;
  utc_offset_seconds: number;
  timezone: string;
  timezone_abbreviation: string;
  daily_units: Record<string, string>;
  daily: Record<string, (number | null)[]>;
}

export class FloodMCPServer extends MCPAdapterBase {
  constructor() {
    super();
  }

  static catalog() {
    return {
      name: 'flood',
      displayName: 'Open-Meteo Flood API',
      version: '1.0.0',
      category: 'weather' as const,
      keywords: [
        'flood', 'river', 'discharge', 'hydrology', 'water level',
        'river discharge', 'flood forecast', 'open-meteo', 'weather',
        'natural disaster', 'hydrological forecast', 'streamflow',
        'flood risk', 'precipitation', 'catchment',
      ],
      toolNames: ['get_river_discharge', 'get_flood_forecast'],
      description: 'Open-Meteo Flood API: retrieve daily river discharge forecasts and comprehensive flood forecasts (discharge, mean, and max) for any geographic location — free, no authentication required.',
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
        name: 'get_river_discharge',
        description: 'Get daily river discharge forecast (m³/s) for a geographic location using the Open-Meteo Flood API.',
        inputSchema: {
          type: 'object',
          properties: {
            latitude: {
              type: 'number',
              description: 'Latitude of the location in decimal degrees.',
            },
            longitude: {
              type: 'number',
              description: 'Longitude of the location in decimal degrees.',
            },
            forecast_days: {
              type: 'number',
              description: 'Number of forecast days to retrieve (1–92). Defaults to 7.',
            },
          },
          required: ['latitude', 'longitude'],
        },
      },
      {
        name: 'get_flood_forecast',
        description: 'Get a comprehensive flood forecast including river discharge, mean discharge, and max discharge for a location.',
        inputSchema: {
          type: 'object',
          properties: {
            latitude: {
              type: 'number',
              description: 'Latitude of the location in decimal degrees.',
            },
            longitude: {
              type: 'number',
              description: 'Longitude of the location in decimal degrees.',
            },
            forecast_days: {
              type: 'number',
              description: 'Number of forecast days to retrieve (1–92). Defaults to 16.',
            },
          },
          required: ['latitude', 'longitude'],
        },
      },
    ];
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<ToolResult> {
    try {
      switch (name) {
        case 'get_river_discharge':
          return this.getRiverDischarge(args);
        case 'get_flood_forecast':
          return this.getFloodForecast(args);
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

  private async floodRequest(params: URLSearchParams): Promise<ToolResult> {
    const url = `${BASE_URL}/flood?${params.toString()}`;
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
    const data = (await response.json()) as FloodApiResponse;
    return { content: [{ type: 'text', text: this.truncate(this.formatResponse(data)) }], isError: false };
  }

  private formatResponse(data: FloodApiResponse): object {
    const dates = (data.daily['time'] ?? []) as unknown as string[];
    const variables = Object.keys(data.daily).filter((k) => k !== 'time');

    const days = dates.map((date, i) => {
      const entry: Record<string, unknown> = { date };
      for (const variable of variables) {
        entry[variable] = data.daily[variable]?.[i] ?? null;
      }
      return entry;
    });

    return {
      latitude: data.latitude,
      longitude: data.longitude,
      timezone: data.timezone,
      units: data.daily_units,
      days,
    };
  }

  private async getRiverDischarge(args: Record<string, unknown>): Promise<ToolResult> {
    const latitude = args.latitude as number;
    const longitude = args.longitude as number;
    const forecastDays = (args.forecast_days as number | undefined) ?? 7;

    const params = new URLSearchParams({
      latitude: String(latitude),
      longitude: String(longitude),
      daily: 'river_discharge',
      forecast_days: String(forecastDays),
    });
    return this.floodRequest(params);
  }

  private async getFloodForecast(args: Record<string, unknown>): Promise<ToolResult> {
    const latitude = args.latitude as number;
    const longitude = args.longitude as number;
    const forecastDays = (args.forecast_days as number | undefined) ?? 16;

    const params = new URLSearchParams({
      latitude: String(latitude),
      longitude: String(longitude),
      daily: 'river_discharge,river_discharge_mean,river_discharge_max',
      forecast_days: String(forecastDays),
    });
    return this.floodRequest(params);
  }
}
