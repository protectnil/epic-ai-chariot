/**
 * Marine Weather MCP Adapter
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

// Upstream: https://marine-api.open-meteo.com (free, no auth)
// Docs: https://open-meteo.com/en/docs/marine-weather-api
// Category: weather
// Auth: none (public API, no key required)

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

const BASE_URL = 'https://marine-api.open-meteo.com/v1';

export class MarineMCPServer extends MCPAdapterBase {
  static catalog() {
    return {
      name: 'marine',
      displayName: 'Marine Weather',
      version: '1.0.0',
      category: 'weather',
      keywords: [
        'marine', 'wave', 'ocean', 'sea', 'forecast', 'wave height',
        'wave period', 'wave direction', 'coastal', 'open-meteo',
        'weather', 'surf', 'nautical', 'maritime',
      ],
      toolNames: ['get_wave_forecast', 'get_current_waves'],
      description: 'Marine Weather API: retrieve multi-day daily wave forecasts and current wave conditions (height, period, direction) for any coastal location — free, no authentication required.',
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
        name: 'get_wave_forecast',
        description:
          'Get a multi-day daily wave forecast for a coastal location. Returns maximum wave height, wave period, and dominant wave direction per day.',
        inputSchema: {
          type: 'object',
          properties: {
            latitude: {
              type: 'number',
              description: 'Latitude of the location.',
            },
            longitude: {
              type: 'number',
              description: 'Longitude of the location.',
            },
            days: {
              type: 'number',
              description: 'Number of forecast days (1–7, default 7).',
            },
          },
          required: ['latitude', 'longitude'],
        },
      },
      {
        name: 'get_current_waves',
        description:
          'Get current wave conditions for a coastal location. Returns wave height, period, and direction right now.',
        inputSchema: {
          type: 'object',
          properties: {
            latitude: {
              type: 'number',
              description: 'Latitude of the location.',
            },
            longitude: {
              type: 'number',
              description: 'Longitude of the location.',
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
        case 'get_wave_forecast':  return this.getWaveForecast(args);
        case 'get_current_waves':  return this.getCurrentWaves(args);
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

  private async getWaveForecast(args: Record<string, unknown>): Promise<ToolResult> {
    const lat = args.latitude as number;
    const lon = args.longitude as number;
    const rawDays = args.days !== undefined ? (args.days as number) : 7;
    const safeDays = Math.min(7, Math.max(1, rawDays));

    const params = new URLSearchParams({
      latitude: String(lat),
      longitude: String(lon),
      daily: 'wave_height_max,wave_period_max,wave_direction_dominant',
      forecast_days: String(safeDays),
    });

    const response = await this.fetchWithRetry(`${BASE_URL}/marine?${params}`, {
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

    const data = await response.json() as {
      latitude: number;
      longitude: number;
      daily: {
        time: string[];
        wave_height_max: number[];
        wave_period_max: number[];
        wave_direction_dominant: number[];
      };
    };

    const d = data.daily;
    const result = {
      latitude: data.latitude,
      longitude: data.longitude,
      days: d.time.map((date, i) => ({
        date,
        wave_height_max_m: d.wave_height_max[i],
        wave_period_max_s: d.wave_period_max[i],
        wave_direction_dominant_deg: d.wave_direction_dominant[i],
      })),
    };

    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }

  private async getCurrentWaves(args: Record<string, unknown>): Promise<ToolResult> {
    const lat = args.latitude as number;
    const lon = args.longitude as number;

    const params = new URLSearchParams({
      latitude: String(lat),
      longitude: String(lon),
      current: 'wave_height,wave_period,wave_direction',
    });

    const response = await this.fetchWithRetry(`${BASE_URL}/marine?${params}`, {
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

    const data = await response.json() as {
      latitude: number;
      longitude: number;
      current: {
        wave_height: number;
        wave_period: number;
        wave_direction: number;
      };
    };

    const c = data.current;
    const result = {
      latitude: data.latitude,
      longitude: data.longitude,
      wave_height_m: c.wave_height,
      wave_period_s: c.wave_period,
      wave_direction_deg: c.wave_direction,
    };

    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }
}
