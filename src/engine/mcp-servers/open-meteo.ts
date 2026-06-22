/**
 * Open-Meteo MCP Adapter
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 *
 * Upstream: Open-Meteo REST APIs (https://open-meteo.com)
 * Auth: none (non-commercial fair-use only)
 * Docs: https://open-meteo.com/en/docs
 */

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

const FORECAST_URL  = 'https://api.open-meteo.com/v1/forecast';
const HISTORICAL_URL = 'https://archive-api.open-meteo.com/v1/archive';
const GEO_URL       = 'https://geocoding-api.open-meteo.com/v1/search';
const AIR_URL       = 'https://air-quality-api.open-meteo.com/v1/air-quality';
const MARINE_URL    = 'https://marine-api.open-meteo.com/v1/marine';
const FLOOD_URL     = 'https://flood-api.open-meteo.com/v1/flood';

const DEFAULT_HOURLY = 'temperature_2m,relative_humidity_2m,precipitation,wind_speed_10m,cloud_cover,weather_code';
const DEFAULT_DAILY  = 'temperature_2m_max,temperature_2m_min,precipitation_sum,wind_speed_10m_max,weather_code';

export class OpenMeteoMCPServer extends MCPAdapterBase {
  constructor() {
    super();
  }

  static catalog() {
    return {
      name: 'open-meteo',
      displayName: 'Open-Meteo Weather',
      version: '1.0.0',
      category: 'weather',
      keywords: [
        'weather', 'forecast', 'temperature', 'precipitation', 'wind',
        'humidity', 'climate', 'historical', 'geocoding', 'air quality',
        'marine', 'waves', 'flood', 'river discharge', 'ERA5', 'open-meteo',
      ],
      toolNames: ['forecast', 'historical', 'geocode', 'air_quality', 'marine', 'flood'],
      description: 'Open-Meteo Weather APIs: free weather forecast, ERA5 historical reanalysis, geocoding, air quality, marine conditions, and flood (river discharge) data — no API key required.',
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
        name: 'forecast',
        description: 'Weather forecast up to 16 days, hourly or daily.',
        inputSchema: {
          type: 'object',
          properties: {
            latitude:         { type: 'number', description: 'Latitude in decimal degrees' },
            longitude:        { type: 'number', description: 'Longitude in decimal degrees' },
            hourly:           { type: 'string', description: 'Comma-separated hourly variables. Default sensible set.' },
            daily:            { type: 'string', description: 'Comma-separated daily variables. Default sensible set.' },
            forecast_days:    { type: 'number', description: '1-16 (default 7)' },
            past_days:        { type: 'number', description: '0-92 (default 0)' },
            timezone:         { type: 'string', description: 'IANA timezone or "auto"' },
            temperature_unit: { type: 'string', description: 'celsius (default) | fahrenheit' },
            wind_speed_unit:  { type: 'string', description: 'kmh | ms | mph | kn' },
          },
          required: ['latitude', 'longitude'],
        },
      },
      {
        name: 'historical',
        description: 'ERA5 reanalysis 1940-present. Date range required.',
        inputSchema: {
          type: 'object',
          properties: {
            latitude:   { type: 'number', description: 'Latitude in decimal degrees' },
            longitude:  { type: 'number', description: 'Longitude in decimal degrees' },
            start_date: { type: 'string', description: 'Start date YYYY-MM-DD' },
            end_date:   { type: 'string', description: 'End date YYYY-MM-DD' },
            hourly:     { type: 'string', description: 'Comma-separated hourly variables' },
            daily:      { type: 'string', description: 'Comma-separated daily variables' },
            timezone:   { type: 'string', description: 'IANA timezone or "auto"' },
          },
          required: ['latitude', 'longitude', 'start_date', 'end_date'],
        },
      },
      {
        name: 'geocode',
        description: 'Resolve a place name to coordinates.',
        inputSchema: {
          type: 'object',
          properties: {
            name:     { type: 'string', description: 'Place name (any language)' },
            count:    { type: 'number', description: 'Max results, 1-100 (default 10)' },
            language: { type: 'string', description: 'ISO-639 language code for returned names (default en)' },
          },
          required: ['name'],
        },
      },
      {
        name: 'air_quality',
        description: 'PM2.5, PM10, O3, NO2, SO2, CO, dust, pollen — hourly forecast.',
        inputSchema: {
          type: 'object',
          properties: {
            latitude:      { type: 'number', description: 'Latitude in decimal degrees' },
            longitude:     { type: 'number', description: 'Longitude in decimal degrees' },
            hourly:        { type: 'string', description: 'Comma-separated variables. Default pm2_5,pm10,ozone,nitrogen_dioxide,european_aqi' },
            forecast_days: { type: 'number', description: '1-5 (default 5)' },
          },
          required: ['latitude', 'longitude'],
        },
      },
      {
        name: 'marine',
        description: 'Wave height, period, and direction forecast.',
        inputSchema: {
          type: 'object',
          properties: {
            latitude:      { type: 'number', description: 'Latitude in decimal degrees' },
            longitude:     { type: 'number', description: 'Longitude in decimal degrees' },
            hourly:        { type: 'string', description: 'Comma-separated variables. Default wave_height,wave_period,wind_wave_height,wind_wave_period' },
            forecast_days: { type: 'number', description: 'Forecast days' },
          },
          required: ['latitude', 'longitude'],
        },
      },
      {
        name: 'flood',
        description: 'Daily river discharge forecast (GloFAS model).',
        inputSchema: {
          type: 'object',
          properties: {
            latitude:      { type: 'number', description: 'Latitude in decimal degrees' },
            longitude:     { type: 'number', description: 'Longitude in decimal degrees' },
            daily:         { type: 'string', description: 'Comma-separated variables. Default river_discharge' },
            forecast_days: { type: 'number', description: 'Forecast days' },
          },
          required: ['latitude', 'longitude'],
        },
      },
    ];
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<ToolResult> {
    try {
      switch (name) {
        case 'forecast':    return this.forecast(args);
        case 'historical':  return this.historical(args);
        case 'geocode':     return this.geocode(args);
        case 'air_quality': return this.airQuality(args);
        case 'marine':      return this.marine(args);
        case 'flood':       return this.flood(args);
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

  private async meteoGet(baseUrl: string, params: URLSearchParams): Promise<ToolResult> {
    const url = `${baseUrl}?${params.toString()}`;
    const response = await this.fetchWithRetry(url, {
      method: 'GET',
      headers: { Accept: 'application/json' },
    });
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `Open-Meteo error: ${response.status} ${errText.slice(0, 300)}` }],
        isError: true,
      };
    }
    const data = await response.json();
    return { content: [{ type: 'text', text: this.truncate(data) }], isError: false };
  }

  private baseLatLon(args: Record<string, unknown>): URLSearchParams {
    const lat = args.latitude;
    const lon = args.longitude;
    if (typeof lat !== 'number' || !Number.isFinite(lat)) {
      throw new Error('forecast: "latitude" must be a finite number');
    }
    if (typeof lon !== 'number' || !Number.isFinite(lon)) {
      throw new Error('forecast: "longitude" must be a finite number');
    }
    return new URLSearchParams({
      latitude:  String(lat),
      longitude: String(lon),
    });
  }

  private async forecast(args: Record<string, unknown>): Promise<ToolResult> {
    const params = this.baseLatLon(args);
    params.set('hourly', typeof args.hourly === 'string' ? args.hourly : DEFAULT_HOURLY);
    params.set('daily',  typeof args.daily  === 'string' ? args.daily  : DEFAULT_DAILY);
    if (args.forecast_days !== undefined) params.set('forecast_days', String(args.forecast_days));
    if (args.past_days     !== undefined) params.set('past_days',     String(args.past_days));
    if (args.timezone)         params.set('timezone',          String(args.timezone));
    if (args.temperature_unit) params.set('temperature_unit',  String(args.temperature_unit));
    if (args.wind_speed_unit)  params.set('wind_speed_unit',   String(args.wind_speed_unit));
    return this.meteoGet(FORECAST_URL, params);
  }

  private async historical(args: Record<string, unknown>): Promise<ToolResult> {
    const startDate = args.start_date;
    const endDate   = args.end_date;
    if (typeof startDate !== 'string' || !startDate.trim()) {
      throw new Error('historical: "start_date" is required (YYYY-MM-DD)');
    }
    if (typeof endDate !== 'string' || !endDate.trim()) {
      throw new Error('historical: "end_date" is required (YYYY-MM-DD)');
    }
    const params = this.baseLatLon(args);
    params.set('start_date', startDate);
    params.set('end_date',   endDate);
    params.set('hourly', typeof args.hourly === 'string' ? args.hourly : DEFAULT_HOURLY);
    params.set('daily',  typeof args.daily  === 'string' ? args.daily  : DEFAULT_DAILY);
    if (args.timezone) params.set('timezone', String(args.timezone));
    return this.meteoGet(HISTORICAL_URL, params);
  }

  private async geocode(args: Record<string, unknown>): Promise<ToolResult> {
    const name = args.name;
    if (typeof name !== 'string' || !name.trim()) {
      throw new Error('geocode: "name" is required');
    }
    const count = typeof args.count === 'number' ? Math.min(100, Math.max(1, args.count)) : 10;
    const params = new URLSearchParams({
      name:     name,
      count:    String(count),
      language: typeof args.language === 'string' ? args.language : 'en',
      format:   'json',
    });
    return this.meteoGet(GEO_URL, params);
  }

  private async airQuality(args: Record<string, unknown>): Promise<ToolResult> {
    const params = this.baseLatLon(args);
    params.set('hourly', typeof args.hourly === 'string' ? args.hourly : 'pm2_5,pm10,ozone,nitrogen_dioxide,european_aqi');
    if (args.forecast_days !== undefined) params.set('forecast_days', String(args.forecast_days));
    return this.meteoGet(AIR_URL, params);
  }

  private async marine(args: Record<string, unknown>): Promise<ToolResult> {
    const params = this.baseLatLon(args);
    params.set('hourly', typeof args.hourly === 'string' ? args.hourly : 'wave_height,wave_period,wind_wave_height,wind_wave_period');
    if (args.forecast_days !== undefined) params.set('forecast_days', String(args.forecast_days));
    return this.meteoGet(MARINE_URL, params);
  }

  private async flood(args: Record<string, unknown>): Promise<ToolResult> {
    const params = this.baseLatLon(args);
    params.set('daily', typeof args.daily === 'string' ? args.daily : 'river_discharge');
    if (args.forecast_days !== undefined) params.set('forecast_days', String(args.forecast_days));
    return this.meteoGet(FLOOD_URL, params);
  }
}
