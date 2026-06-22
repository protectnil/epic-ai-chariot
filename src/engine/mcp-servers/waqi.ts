/**
 * WAQI — World Air Quality Index MCP Adapter
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

// Base URL: https://api.waqi.info
// Auth: API token required — query param `token`. Register at https://aqicn.org/data-platform/token/
// Docs: https://aqicn.org/api/
// Category: environment
// Rate limits: Depends on plan; free tier available with registration.

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

interface WaqiConfig {
  apiKey: string;
  baseUrl?: string;
}

export class WaqiMCPServer extends MCPAdapterBase {
  private readonly apiKey: string;
  private readonly baseUrl: string;

  constructor(config: WaqiConfig) {
    super();
    if (!config || typeof config !== 'object') {
      throw new Error('WAQI: configuration object is required');
    }
    for (const __k of (['apiKey'] as Array<keyof typeof config>)) {
      if (config[__k] === undefined || config[__k] === null || (config[__k] as unknown) === '') {
        throw new Error('WAQI: ' + __k + ' is required');
      }
    }
    this.apiKey = config.apiKey;
    this.baseUrl = config.baseUrl ?? 'https://api.waqi.info';
  }

  static catalog() {
    return {
      name: 'waqi',
      displayName: 'WAQI — World Air Quality Index',
      version: '1.0.0',
      category: 'environment',
      keywords: [
        'waqi', 'air quality', 'aqi', 'pollution', 'pm2.5', 'pm10',
        'ozone', 'no2', 'so2', 'co', 'air pollution', 'monitoring station',
        'environment', 'weather', 'atmosphere', 'smog', 'hazardous',
      ],
      toolNames: [
        'get_aqi_by_city',
        'get_aqi_by_location',
        'get_aqi_by_station',
        'search_stations',
      ],
      description: 'World Air Quality Index API: real-time AQI readings from 12,000+ monitoring stations worldwide. Look up air quality by city name, GPS coordinates, or station UID; search stations by keyword. Returns AQI value, category, dominant pollutant, and individual readings (PM2.5, PM10, O3, NO2, SO2, CO, temperature, humidity, pressure).',
      type: 'rest' as const,
      auth: {
        inferredModel: 'api-key' as const,
        probeState: 'never-probed' as const,
      },
      author: 'protectnil',
    };
  }

  get tools(): ToolDefinition[] {
    return [
      {
        name: 'get_aqi_by_city',
        description:
          'Real-time AQI for a city. Returns AQI value, dominant pollutant, individual pollutant readings (PM2.5, PM10, O3, NO2, SO2, CO), temperature/humidity/pressure, and station info.',
        inputSchema: {
          type: 'object',
          properties: {
            city: {
              type: 'string',
              description: 'City name (e.g., "beijing", "los-angeles", "new-delhi")',
            },
          },
          required: ['city'],
        },
      },
      {
        name: 'get_aqi_by_location',
        description: 'Real-time AQI for the WAQI station nearest a lat/lon.',
        inputSchema: {
          type: 'object',
          properties: {
            latitude: {
              type: 'number',
              description: 'Latitude',
            },
            longitude: {
              type: 'number',
              description: 'Longitude',
            },
          },
          required: ['latitude', 'longitude'],
        },
      },
      {
        name: 'get_aqi_by_station',
        description: 'Real-time AQI for a specific WAQI station by UID (numeric).',
        inputSchema: {
          type: 'object',
          properties: {
            station_id: {
              type: 'number',
              description: 'WAQI station UID (returned by search_stations)',
            },
          },
          required: ['station_id'],
        },
      },
      {
        name: 'search_stations',
        description:
          'Search stations by keyword (city/region name). Returns station UID, name, current AQI, and location.',
        inputSchema: {
          type: 'object',
          properties: {
            keyword: {
              type: 'string',
              description: 'Search keyword',
            },
          },
          required: ['keyword'],
        },
      },
    ];
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<ToolResult> {
    try {
      switch (name) {
        case 'get_aqi_by_city':
          return this.getAqiByCity(args);
        case 'get_aqi_by_location':
          return this.getAqiByLocation(args);
        case 'get_aqi_by_station':
          return this.getAqiByStation(args);
        case 'search_stations':
          return this.searchStations(args);
        default:
          return {
            content: [{ type: 'text', text: `Unknown tool: ${name}` }],
            isError: true,
          };
      }
    } catch (error) {
      return {
        content: [{ type: 'text', text: `Tool execution failed: ${error instanceof Error ? error.message : String(error)}` }],
        isError: true,
      };
    }
  }

  // ── Private helpers ────────────────────────────────────────────────────────

  private async waqiFetch(path: string): Promise<ToolResult> {
    const separator = path.includes('?') ? '&' : '?';
    const url = `${this.baseUrl}${path}${separator}token=${encodeURIComponent(this.apiKey)}`;
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
    const json = await response.json() as { status?: string; data?: unknown; msg?: string };
    if (json.status !== 'ok') {
      return {
        content: [{ type: 'text', text: `WAQI error: ${json.msg ?? 'unknown error'}` }],
        isError: true,
      };
    }
    return { content: [{ type: 'text', text: this.truncate(json.data) }], isError: false };
  }

  private aqiCategory(aqi: number | null | undefined): string | null {
    if (aqi == null) return null;
    if (aqi <= 50) return 'Good';
    if (aqi <= 100) return 'Moderate';
    if (aqi <= 150) return 'Unhealthy for sensitive groups';
    if (aqi <= 200) return 'Unhealthy';
    if (aqi <= 300) return 'Very Unhealthy';
    return 'Hazardous';
  }

  private async getAqiFeed(path: string): Promise<ToolResult> {
    const separator = path.includes('?') ? '&' : '?';
    const url = `${this.baseUrl}${path}${separator}token=${encodeURIComponent(this.apiKey)}`;
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
    const json = await response.json() as {
      status?: string;
      msg?: string;
      data?: {
        aqi?: number;
        idx?: number;
        dominentpol?: string;
        time?: { s?: string; tz?: string; v?: number; iso?: string };
        city?: { name?: string; geo?: number[]; url?: string };
        iaqi?: Record<string, { v?: number }>;
        attributions?: { name?: string; url?: string }[];
      };
    };
    if (json.status !== 'ok' || !json.data) {
      return {
        content: [{ type: 'text', text: `WAQI error: ${json.msg ?? 'unknown error'}` }],
        isError: true,
      };
    }
    const d = json.data;
    const iaqi = d.iaqi ?? {};
    const valueOf = (k: string): number | null => iaqi[k]?.v ?? null;
    const result = {
      aqi: d.aqi ?? null,
      category: this.aqiCategory(d.aqi),
      dominant_pollutant: d.dominentpol ?? null,
      station: {
        id: d.idx ?? null,
        name: d.city?.name ?? null,
        latitude: d.city?.geo?.[0] ?? null,
        longitude: d.city?.geo?.[1] ?? null,
        url: d.city?.url ?? null,
      },
      measurements: {
        pm25: valueOf('pm25'),
        pm10: valueOf('pm10'),
        o3: valueOf('o3'),
        no2: valueOf('no2'),
        so2: valueOf('so2'),
        co: valueOf('co'),
        temperature_c: valueOf('t'),
        humidity_pct: valueOf('h'),
        pressure_hpa: valueOf('p'),
        wind_speed: valueOf('w'),
      },
      measured_at: d.time?.iso ?? d.time?.s ?? null,
      timezone: d.time?.tz ?? null,
      attributions: (d.attributions ?? []).map((a) => ({
        name: a.name ?? null,
        url: a.url ?? null,
      })),
    };
    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }

  private async getAqiByCity(args: Record<string, unknown>): Promise<ToolResult> {
    const city = args.city;
    if (typeof city !== 'string' || !city.trim()) {
      return {
        content: [{ type: 'text', text: 'get_aqi_by_city: "city" is required (e.g., "beijing")' }],
        isError: true,
      };
    }
    return this.getAqiFeed(`/feed/${encodeURIComponent(city.trim())}/`);
  }

  private async getAqiByLocation(args: Record<string, unknown>): Promise<ToolResult> {
    const lat = args.latitude;
    const lon = args.longitude;
    if (typeof lat !== 'number' || typeof lon !== 'number') {
      return {
        content: [{ type: 'text', text: 'get_aqi_by_location: "latitude" and "longitude" are required numbers' }],
        isError: true,
      };
    }
    return this.getAqiFeed(`/feed/geo:${lat};${lon}/`);
  }

  private async getAqiByStation(args: Record<string, unknown>): Promise<ToolResult> {
    const id = args.station_id;
    if (typeof id !== 'number') {
      return {
        content: [{ type: 'text', text: 'get_aqi_by_station: "station_id" is required (numeric WAQI station UID)' }],
        isError: true,
      };
    }
    return this.getAqiFeed(`/feed/@${id}/`);
  }

  private async searchStations(args: Record<string, unknown>): Promise<ToolResult> {
    const keyword = args.keyword;
    if (typeof keyword !== 'string' || !keyword.trim()) {
      return {
        content: [{ type: 'text', text: 'search_stations: "keyword" is required' }],
        isError: true,
      };
    }
    const url = `${this.baseUrl}/search/?keyword=${encodeURIComponent(keyword.trim())}&token=${encodeURIComponent(this.apiKey)}`;
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
    const json = await response.json() as {
      status?: string;
      msg?: string;
      data?: Array<{
        uid?: number;
        aqi?: string;
        station?: { name?: string; geo?: number[]; url?: string; country?: string };
        time?: { stime?: string; tz?: string };
      }>;
    };
    if (json.status !== 'ok') {
      return {
        content: [{ type: 'text', text: `WAQI error: ${json.msg ?? 'unknown error'}` }],
        isError: true,
      };
    }
    const result = {
      keyword: keyword.trim(),
      count: json.data?.length ?? 0,
      stations: (json.data ?? []).map((s) => ({
        station_id: s.uid ?? null,
        name: s.station?.name ?? null,
        aqi: s.aqi != null && s.aqi !== '-' ? Number(s.aqi) : null,
        country: s.station?.country ?? null,
        latitude: s.station?.geo?.[0] ?? null,
        longitude: s.station?.geo?.[1] ?? null,
        last_seen: s.time?.stime ?? null,
        timezone: s.time?.tz ?? null,
        url: s.station?.url ?? null,
      })),
    };
    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }
}
