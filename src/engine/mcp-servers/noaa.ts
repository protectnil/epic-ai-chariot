/**
 * NOAA Weather MCP Adapter — National Weather Service forecasts and alerts
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 *
 * Upstream API: https://api.weather.gov (National Weather Service, public, no auth)
 * Docs: https://www.weather.gov/documentation/services-web-api
 * Category: weather
 * Rate limits: None published; NWS requests a descriptive User-Agent
 */

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

const BASE_URL = 'https://api.weather.gov';
const NWS_USER_AGENT = 'epic-ai-chariot/1.0 (https://epicai.com)';

export class NOAAMCPServer extends MCPAdapterBase {
  private readonly baseUrl: string;

  constructor(config?: { baseUrl?: string }) {
    super();
    if (config === null) { throw new Error('NOAAMCPServer: configuration object is required when provided'); }
    this.baseUrl = config?.baseUrl ?? BASE_URL;
  }

  static catalog() {
    return {
      name: 'noaa',
      displayName: 'NOAA National Weather Service',
      version: '1.0.0',
      category: 'weather',
      keywords: [
        'noaa', 'nws', 'weather', 'forecast', 'alerts', 'stations',
        'national weather service', 'temperature', 'wind', 'severe weather',
        'meteorology', 'us weather', 'weather api',
      ],
      toolNames: ['get_forecast', 'get_alerts', 'get_stations'],
      description: 'NOAA National Weather Service: multi-day forecasts, active weather alerts, and observation station listings for US locations — no API key required.',
      author: 'protectnil',
      type: 'rest' as const,
      auth: {
        inferredModel: 'none' as const,
        probeState: 'no-auth-verified' as const,
      },
    };
  }

  get tools(): ToolDefinition[] {
    return [
      {
        name: 'get_forecast',
        description:
          'Get a multi-day weather forecast for a latitude/longitude location using the National Weather Service.',
        inputSchema: {
          type: 'object',
          properties: {
            lat: {
              type: 'number',
              description: 'Latitude of the location (e.g. 37.7749)',
            },
            lon: {
              type: 'number',
              description: 'Longitude of the location (e.g. -122.4194)',
            },
          },
          required: ['lat', 'lon'],
        },
      },
      {
        name: 'get_alerts',
        description:
          'Get currently active weather alerts for a US state (e.g. CA, NY, TX).',
        inputSchema: {
          type: 'object',
          properties: {
            state: {
              type: 'string',
              description: 'Two-letter US state code (e.g. "CA", "NY")',
            },
          },
          required: ['state'],
        },
      },
      {
        name: 'get_stations',
        description: 'List weather observation stations for a US state.',
        inputSchema: {
          type: 'object',
          properties: {
            state: {
              type: 'string',
              description: 'Two-letter US state code (e.g. "CA", "NY")',
            },
            limit: {
              type: 'number',
              description: 'Maximum number of stations to return (default: 20)',
            },
          },
          required: ['state'],
        },
      },
    ];
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<ToolResult> {
    try {
      switch (name) {
        case 'get_forecast': return this.getForecast(args);
        case 'get_alerts':   return this.getAlerts(args);
        case 'get_stations': return this.getStations(args);
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

  // ── Private helpers ─────────────────────────────────────────────────────────

  private get nwsHeaders(): Record<string, string> {
    return {
      'User-Agent': NWS_USER_AGENT,
      Accept: 'application/geo+json',
    };
  }

  private async getForecast(args: Record<string, unknown>): Promise<ToolResult> {
    const lat = args.lat as number;
    const lon = args.lon as number;

    // Step 1: resolve NWS grid point from lat/lon
    const pointRes = await this.fetchWithRetry(
      `${this.baseUrl}/points/${lat},${lon}`,
      { method: 'GET', headers: this.nwsHeaders },
    );
    if (!pointRes.ok) {
      const errText = await pointRes.text().catch(() => pointRes.statusText);
      return {
        content: [{ type: 'text', text: `NWS points lookup failed: ${pointRes.status} — coordinates may be outside the US. ${errText}` }],
        isError: true,
      };
    }
    const pointData = await pointRes.json() as {
      properties: {
        forecast: string;
        relativeLocation?: { properties?: { city?: string; state?: string } };
      };
    };
    const forecastUrl = pointData.properties.forecast;
    const location = pointData.properties.relativeLocation?.properties;

    // Step 2: fetch the forecast
    const forecastRes = await this.fetchWithRetry(
      forecastUrl,
      { method: 'GET', headers: this.nwsHeaders },
    );
    if (!forecastRes.ok) {
      const errText = await forecastRes.text().catch(() => forecastRes.statusText);
      return {
        content: [{ type: 'text', text: `NWS forecast fetch failed: ${forecastRes.status} ${errText}` }],
        isError: true,
      };
    }
    const forecastData = await forecastRes.json() as {
      properties: {
        periods: Array<{
          name: string;
          startTime: string;
          endTime: string;
          isDaytime: boolean;
          temperature: number;
          temperatureUnit: string;
          windSpeed: string;
          windDirection: string;
          shortForecast: string;
          detailedForecast: string;
        }>;
      };
    };

    const result = {
      location: {
        lat,
        lon,
        city: location?.city ?? null,
        state: location?.state ?? null,
      },
      periods: forecastData.properties.periods.map((p) => ({
        name: p.name,
        start_time: p.startTime,
        end_time: p.endTime,
        is_daytime: p.isDaytime,
        temperature: p.temperature,
        temperature_unit: p.temperatureUnit,
        wind_speed: p.windSpeed,
        wind_direction: p.windDirection,
        short_forecast: p.shortForecast,
        detailed_forecast: p.detailedForecast,
      })),
    };

    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }

  private async getAlerts(args: Record<string, unknown>): Promise<ToolResult> {
    const state = (args.state as string).toUpperCase();

    const params = new URLSearchParams({ area: state });
    const res = await this.fetchWithRetry(
      `${this.baseUrl}/alerts/active?${params}`,
      { method: 'GET', headers: this.nwsHeaders },
    );
    if (!res.ok) {
      const errText = await res.text().catch(() => res.statusText);
      return {
        content: [{ type: 'text', text: `NWS alerts error: ${res.status} ${errText}` }],
        isError: true,
      };
    }

    const data = await res.json() as {
      features: Array<{
        properties: {
          id: string;
          event: string;
          headline?: string;
          description?: string;
          severity: string;
          urgency: string;
          certainty: string;
          effective: string;
          expires: string;
          areaDesc?: string;
        };
      }>;
    };

    const result = {
      state,
      count: data.features.length,
      alerts: data.features.map((f) => ({
        id: f.properties.id,
        event: f.properties.event,
        headline: f.properties.headline ?? null,
        severity: f.properties.severity,
        urgency: f.properties.urgency,
        certainty: f.properties.certainty,
        effective: f.properties.effective,
        expires: f.properties.expires,
        area: f.properties.areaDesc ?? null,
        description: f.properties.description ?? null,
      })),
    };

    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }

  private async getStations(args: Record<string, unknown>): Promise<ToolResult> {
    const state = (args.state as string).toUpperCase();
    const limit = Math.max(1, Math.min(500, ((args.limit as number) ?? 20)));

    const params = new URLSearchParams({ state, limit: String(limit) });
    const res = await this.fetchWithRetry(
      `${this.baseUrl}/stations?${params}`,
      { method: 'GET', headers: this.nwsHeaders },
    );
    if (!res.ok) {
      const errText = await res.text().catch(() => res.statusText);
      return {
        content: [{ type: 'text', text: `NWS stations error: ${res.status} ${errText}` }],
        isError: true,
      };
    }

    const data = await res.json() as {
      features: Array<{
        properties: {
          stationIdentifier: string;
          name: string;
          timeZone?: string;
        };
        geometry?: { coordinates?: [number, number] };
      }>;
    };

    const result = {
      state,
      count: data.features.length,
      stations: data.features.map((f) => ({
        id: f.properties.stationIdentifier,
        name: f.properties.name,
        time_zone: f.properties.timeZone ?? null,
        coordinates: f.geometry?.coordinates
          ? { lon: f.geometry.coordinates[0], lat: f.geometry.coordinates[1] }
          : null,
      })),
    };

    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }
}
