/**
 * Open-Meteo Weather MCP Adapter
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

// Upstream: Open-Meteo (https://open-meteo.com) — free, no auth required
// Base URL: https://api.open-meteo.com/v1
// Docs: https://open-meteo.com/en/docs
// License: CC BY 4.0 (data) / MIT (client libs)
// Category: weather
// Rate limits: None enforced (fair-use; no API key needed)

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

const WMO_CODES: Record<number, string> = {
  0: 'Clear sky',
  1: 'Mainly clear',
  2: 'Partly cloudy',
  3: 'Overcast',
  45: 'Foggy',
  48: 'Depositing rime fog',
  51: 'Light drizzle',
  53: 'Moderate drizzle',
  55: 'Dense drizzle',
  61: 'Slight rain',
  63: 'Moderate rain',
  65: 'Heavy rain',
  71: 'Slight snow',
  73: 'Moderate snow',
  75: 'Heavy snow',
  77: 'Snow grains',
  80: 'Slight rain showers',
  81: 'Moderate rain showers',
  82: 'Violent rain showers',
  85: 'Slight snow showers',
  86: 'Heavy snow showers',
  95: 'Thunderstorm',
  96: 'Thunderstorm with slight hail',
  99: 'Thunderstorm with heavy hail',
};

export class WeatherMCPServer extends MCPAdapterBase {
  private readonly baseUrl: string;

  constructor(config?: { baseUrl?: string }) {
    super();
    if (config === null) { throw new Error('WeatherMCPServer: configuration object is required when provided'); }
    this.baseUrl = config?.baseUrl ?? 'https://api.open-meteo.com/v1';
  }

  static catalog() {
    return {
      name: 'weather',
      displayName: 'Open-Meteo Weather',
      version: '1.0.0',
      category: 'weather',
      keywords: [
        'weather', 'forecast', 'temperature', 'humidity', 'wind',
        'precipitation', 'conditions', 'open-meteo', 'meteorology',
        'current weather', 'daily forecast', 'WMO', 'latitude', 'longitude',
      ],
      toolNames: ['get_weather', 'get_forecast', 'get_historical'],
      description: 'Open-Meteo Weather: fetch current conditions, multi-day forecasts, and historical daily weather for any latitude/longitude — free and unauthenticated.',
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
        name: 'get_weather',
        description: 'Get current weather conditions for a location. Returns temperature, humidity, wind speed, and conditions.',
        inputSchema: {
          type: 'object',
          properties: {
            latitude: { type: 'number', description: 'Latitude of the location' },
            longitude: { type: 'number', description: 'Longitude of the location' },
          },
          required: ['latitude', 'longitude'],
        },
      },
      {
        name: 'get_forecast',
        description: 'Get a multi-day weather forecast for a location. Returns daily high/low temperatures, precipitation, and conditions.',
        inputSchema: {
          type: 'object',
          properties: {
            latitude: { type: 'number', description: 'Latitude of the location' },
            longitude: { type: 'number', description: 'Longitude of the location' },
            days: {
              type: 'number',
              description: 'Number of forecast days (1-16, default 7)',
            },
          },
          required: ['latitude', 'longitude'],
        },
      },
      {
        name: 'get_historical',
        description: 'Get historical daily weather for a location from the Open-Meteo archive. Returns daily high/low temperature, precipitation, and conditions for the given date range. Dates are YYYY-MM-DD.',
        inputSchema: {
          type: 'object',
          properties: {
            latitude: { type: 'number', description: 'Latitude of the location' },
            longitude: { type: 'number', description: 'Longitude of the location' },
            start_date: { type: 'string', description: 'Start date, YYYY-MM-DD' },
            end_date: { type: 'string', description: 'End date, YYYY-MM-DD' },
          },
          required: ['latitude', 'longitude', 'start_date', 'end_date'],
        },
      },
    ];
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<ToolResult> {
    try {
      switch (name) {
        case 'get_weather':   return this.getWeather(args);
        case 'get_forecast':  return this.getForecast(args);
        case 'get_historical': return this.getHistorical(args);
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

  private async getWeather(args: Record<string, unknown>): Promise<ToolResult> {
    const lat = args.latitude as number;
    const lon = args.longitude as number;

    const params = new URLSearchParams({
      latitude: String(lat),
      longitude: String(lon),
      current: 'temperature_2m,relative_humidity_2m,apparent_temperature,weather_code,wind_speed_10m,wind_direction_10m',
      temperature_unit: 'fahrenheit',
      wind_speed_unit: 'mph',
    });

    const url = `${this.baseUrl}/forecast?${params.toString()}`;
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

    const data = await response.json() as {
      current: {
        temperature_2m: number;
        relative_humidity_2m: number;
        apparent_temperature: number;
        weather_code: number;
        wind_speed_10m: number;
        wind_direction_10m: number;
      };
    };

    const c = data.current;
    const result = {
      temperature_f: c.temperature_2m,
      feels_like_f: c.apparent_temperature,
      humidity_pct: c.relative_humidity_2m,
      conditions: WMO_CODES[c.weather_code] ?? `Code ${c.weather_code}`,
      wind_mph: c.wind_speed_10m,
      wind_direction_deg: c.wind_direction_10m,
    };

    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }

  private async getForecast(args: Record<string, unknown>): Promise<ToolResult> {
    const lat = args.latitude as number;
    const lon = args.longitude as number;
    const forecastDays = Math.min(16, Math.max(1, (args.days as number) ?? 7));

    const params = new URLSearchParams({
      latitude: String(lat),
      longitude: String(lon),
      daily: 'temperature_2m_max,temperature_2m_min,precipitation_sum,weather_code',
      temperature_unit: 'fahrenheit',
      forecast_days: String(forecastDays),
    });

    const url = `${this.baseUrl}/forecast?${params.toString()}`;
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

    const data = await response.json() as {
      daily: {
        time: string[];
        temperature_2m_max: number[];
        temperature_2m_min: number[];
        precipitation_sum: number[];
        weather_code: number[];
      };
    };

    const d = data.daily;
    const result = {
      days: d.time.map((date, i) => ({
        date,
        high_f: d.temperature_2m_max[i],
        low_f: d.temperature_2m_min[i],
        precipitation_mm: d.precipitation_sum[i],
        conditions: WMO_CODES[d.weather_code[i]] ?? `Code ${d.weather_code[i]}`,
      })),
    };

    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }

  private async getHistorical(args: Record<string, unknown>): Promise<ToolResult> {
    const lat = args.latitude as number;
    const lon = args.longitude as number;
    const startDate = String(args.start_date ?? '');
    const endDate = String(args.end_date ?? '');

    const params = new URLSearchParams({
      latitude: String(lat),
      longitude: String(lon),
      start_date: startDate,
      end_date: endDate,
      daily: 'temperature_2m_max,temperature_2m_min,precipitation_sum,weather_code',
      temperature_unit: 'fahrenheit',
    });

    // Historical data is served from the Open-Meteo archive host, not the forecast host.
    const archiveBase = this.baseUrl.replace('//api.open-meteo.com', '//archive-api.open-meteo.com');
    const url = `${archiveBase}/archive?${params.toString()}`;
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

    const data = await response.json() as {
      daily: {
        time: string[];
        temperature_2m_max: number[];
        temperature_2m_min: number[];
        precipitation_sum: number[];
        weather_code: number[];
      };
    };

    const d = data.daily;
    const result = {
      start_date: startDate,
      end_date: endDate,
      days: (d?.time ?? []).map((date, i) => ({
        date,
        high_f: d.temperature_2m_max[i],
        low_f: d.temperature_2m_min[i],
        precipitation_mm: d.precipitation_sum[i],
        conditions: WMO_CODES[d.weather_code[i]] ?? `Code ${d.weather_code[i]}`,
      })),
    };

    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }
}
