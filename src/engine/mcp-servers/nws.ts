/**
 * NWS (US National Weather Service) MCP Adapter
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

// Upstream: US National Weather Service public REST API
// Base URL: https://api.weather.gov
// Auth: None — public API. NWS asks clients to identify via User-Agent.
// Docs: https://www.weather.gov/documentation/services-web-api
// Category: weather
//
// Tools:
// - get_forecast:        7-day forecast for a US lat/lon (two-step gridpoint resolve)
// - get_hourly_forecast: hourly forecast for a US lat/lon
// - get_alerts:          active watches/warnings/advisories by area or point
// - get_observation:     latest observation from a weather station

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

const BASE_URL = 'https://api.weather.gov';
const NWS_USER_AGENT = 'EpicAI-Chariot-NWS/1.0 (support@epicai.com)';

export class NWSMCPServer extends MCPAdapterBase {
  private readonly baseUrl: string;

  constructor(config?: { baseUrl?: string }) {
    super();
    if (config === null) { throw new Error('NWSMCPServer: configuration object is required when provided'); }
    this.baseUrl = config?.baseUrl ?? BASE_URL;
  }

  static catalog() {
    return {
      name: 'nws',
      displayName: 'NWS — US National Weather Service',
      version: '1.0.0',
      category: 'weather' as const,
      keywords: [
        'nws', 'national weather service', 'weather', 'forecast', 'alerts',
        'warnings', 'watches', 'advisories', 'severe weather', 'tornado',
        'hurricane', 'observation', 'us weather', 'noaa', 'gridpoint',
        'hourly forecast', 'weather station', 'temperature', 'wind',
        'precipitation', 'meteorology',
      ],
      toolNames: ['get_forecast', 'get_hourly_forecast', 'get_alerts', 'get_observation'],
      description: 'NWS (US National Weather Service): get 7-day or hourly forecasts, active watches/warnings/advisories, and latest station observations for US locations — authoritative official source, no authentication required.',
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
        name: 'get_forecast',
        description:
          'Get the 7-day NWS forecast for a US lat/lon. Returns named periods (e.g., "Tonight", "Wednesday") with high/low temperature, wind, and a short text forecast. US locations only.',
        inputSchema: {
          type: 'object',
          properties: {
            latitude:  { type: 'number', description: 'US latitude' },
            longitude: { type: 'number', description: 'US longitude' },
          },
          required: ['latitude', 'longitude'],
        },
      },
      {
        name: 'get_hourly_forecast',
        description:
          'Get the hourly NWS forecast for a US lat/lon (~168 hours). Useful for short-term planning, severe-weather windows, or precipitation timing.',
        inputSchema: {
          type: 'object',
          properties: {
            latitude:  { type: 'number', description: 'US latitude' },
            longitude: { type: 'number', description: 'US longitude' },
            max_hours: { type: 'number', description: 'Cap hours returned (default 24)' },
          },
          required: ['latitude', 'longitude'],
        },
      },
      {
        name: 'get_alerts',
        description:
          'Active NWS watches / warnings / advisories. Filter by US state (2-letter code), point (lat,lon), severity, or status. Returns event name, severity, urgency, headline, description, affected areas, and effective/expires times.',
        inputSchema: {
          type: 'object',
          properties: {
            area: {
              type: 'string',
              description: '2-letter US state/territory code (e.g., "CA", "TX")',
            },
            latitude:  { type: 'number', description: 'Latitude (use with longitude for point query)' },
            longitude: { type: 'number', description: 'Longitude (use with latitude for point query)' },
            severity: {
              type: 'string',
              description: 'Extreme | Severe | Moderate | Minor | Unknown',
            },
            urgency: {
              type: 'string',
              description: 'Immediate | Expected | Future | Past | Unknown',
            },
            event: {
              type: 'string',
              description: 'Restrict to a specific event type (e.g., "Tornado Warning")',
            },
            limit: {
              type: 'number',
              description: 'Cap alerts returned (default 50, max 500)',
            },
          },
          required: [],
        },
      },
      {
        name: 'get_observation',
        description:
          'Latest observation from a specific NWS weather station. Returns temperature, humidity, wind, visibility, pressure, and present-weather codes.',
        inputSchema: {
          type: 'object',
          properties: {
            station_id: {
              type: 'string',
              description: '4-character NWS / ICAO station ID (e.g., "KSFO", "KJFK", "KDEN")',
            },
          },
          required: ['station_id'],
        },
      },
    ];
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<ToolResult> {
    try {
      switch (name) {
        case 'get_forecast':
          return this.getForecast(args.latitude as number, args.longitude as number, false, undefined);
        case 'get_hourly_forecast':
          return this.getForecast(
            args.latitude as number,
            args.longitude as number,
            true,
            (args.max_hours as number) ?? 24,
          );
        case 'get_alerts':
          return this.getAlerts(args);
        case 'get_observation':
          return this.getObservation(this.requireString(args, 'station_id', '"KSFO"'));
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

  private requireString(args: Record<string, unknown>, key: string, example: string): string {
    const v = args[key];
    if (typeof v !== 'string' || !v.trim()) {
      throw new Error(`Required argument "${key}" is missing or empty. Pass a string like ${example}.`);
    }
    return v;
  }

  private nwsHeaders(): Record<string, string> {
    return {
      'User-Agent': NWS_USER_AGENT,
      Accept: 'application/geo+json,application/json',
    };
  }

  private async nwsFetch<T>(path: string, params?: URLSearchParams): Promise<T> {
    const url = `${this.baseUrl}${path}${params && params.toString() ? `?${params}` : ''}`;
    const response = await this.fetchWithRetry(url, {
      method: 'GET',
      headers: this.nwsHeaders(),
    });
    if (response.status === 404) {
      throw new Error('NWS: not found (HTTP 404). NWS only covers US locations.');
    }
    if (response.status === 429) {
      throw new Error('NWS: rate-limit hit (HTTP 429)');
    }
    if (!response.ok) {
      const body = await response.text().catch(() => response.statusText);
      throw new Error(`NWS error: ${response.status} ${body.slice(0, 200)}`);
    }
    return response.json() as Promise<T>;
  }

  private async getForecast(
    lat: number,
    lon: number,
    hourly: boolean,
    maxHours?: number,
  ): Promise<ToolResult> {
    if (typeof lat !== 'number' || typeof lon !== 'number') {
      throw new Error('latitude and longitude (numbers) are required');
    }

    // Step 1: resolve lat/lon to NWS gridpoint
    interface PointResponse {
      properties?: {
        forecast?: string;
        forecastHourly?: string;
        gridId?: string;
        gridX?: number;
        gridY?: number;
        timeZone?: string;
        radarStation?: string;
        relativeLocation?: { properties?: { city?: string; state?: string } };
      };
    }
    const point = await this.nwsFetch<PointResponse>(
      `/points/${lat.toFixed(4)},${lon.toFixed(4)}`,
    );
    const props = point.properties;
    if (!props) throw new Error('NWS: empty point response');

    const forecastUrl = hourly ? props.forecastHourly : props.forecast;
    if (!forecastUrl) throw new Error('NWS: no forecast URL on gridpoint response');

    // Step 2: fetch the forecast — URL is absolute (from NWS gridpoint response)
    const fcResponse = await this.fetchWithRetry(forecastUrl, {
      method: 'GET',
      headers: this.nwsHeaders(),
    });
    if (!fcResponse.ok) {
      throw new Error(`NWS forecast fetch failed: ${fcResponse.status}`);
    }

    interface ForecastPeriod {
      name?: string;
      startTime?: string;
      endTime?: string;
      isDaytime?: boolean;
      temperature?: number;
      temperatureUnit?: string;
      windSpeed?: string;
      windDirection?: string;
      shortForecast?: string;
      detailedForecast?: string;
      probabilityOfPrecipitation?: { value?: number | null };
    }
    interface ForecastResponse {
      properties?: {
        updated?: string;
        periods?: ForecastPeriod[];
      };
    }

    const fc = (await fcResponse.json()) as ForecastResponse;
    const allPeriods = fc.properties?.periods ?? [];
    const periods = hourly && maxHours ? allPeriods.slice(0, maxHours) : allPeriods;

    const result = {
      location: {
        latitude: lat,
        longitude: lon,
        city: props.relativeLocation?.properties?.city ?? null,
        state: props.relativeLocation?.properties?.state ?? null,
        timezone: props.timeZone ?? null,
        grid: props.gridId ? `${props.gridId} ${props.gridX},${props.gridY}` : null,
        radar_station: props.radarStation ?? null,
      },
      updated: fc.properties?.updated ?? null,
      period_count: periods.length,
      periods: periods.map((p) => ({
        name: p.name ?? null,
        start: p.startTime ?? null,
        end: p.endTime ?? null,
        is_daytime: p.isDaytime ?? null,
        temperature: p.temperature ?? null,
        temperature_unit: p.temperatureUnit ?? null,
        wind:
          p.windSpeed && p.windDirection
            ? `${p.windSpeed} ${p.windDirection}`
            : (p.windSpeed ?? null),
        precip_chance_pct: p.probabilityOfPrecipitation?.value ?? null,
        short: p.shortForecast ?? null,
        detailed: p.detailedForecast ?? null,
      })),
    };

    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }

  private async getAlerts(args: Record<string, unknown>): Promise<ToolResult> {
    const params = new URLSearchParams();
    if (args.area) params.set('area', String(args.area).toUpperCase());
    if (typeof args.latitude === 'number' && typeof args.longitude === 'number') {
      params.set(
        'point',
        `${(args.latitude as number).toFixed(4)},${(args.longitude as number).toFixed(4)}`,
      );
    }
    if (args.severity) params.set('severity', String(args.severity));
    if (args.urgency)   params.set('urgency',  String(args.urgency));
    if (args.event)     params.set('event',    String(args.event));
    // NOTE: NWS /alerts/active does NOT accept a "limit" query param (returns 400).
    // Apply the cap in-process after the response is received.
    const limit = Math.min(500, Math.max(1, (args.limit as number) ?? 50));

    interface AlertResponse {
      features?: {
        properties?: {
          id?: string;
          event?: string;
          severity?: string;
          urgency?: string;
          certainty?: string;
          status?: string;
          category?: string;
          headline?: string;
          description?: string;
          instruction?: string | null;
          areaDesc?: string;
          senderName?: string;
          response?: string;
          sent?: string;
          effective?: string;
          onset?: string;
          expires?: string;
          ends?: string;
        };
      }[];
    }

    const data = await this.nwsFetch<AlertResponse>('/alerts/active', params);
    const alerts = (data.features ?? []).slice(0, limit).map((f) => f.properties ?? {});

    const result = {
      count: alerts.length,
      alerts: alerts.map((a) => ({
        id: a.id ?? null,
        event: a.event ?? null,
        severity: a.severity ?? null,
        urgency: a.urgency ?? null,
        certainty: a.certainty ?? null,
        status: a.status ?? null,
        category: a.category ?? null,
        headline: a.headline ?? null,
        description: a.description ?? null,
        instruction: a.instruction ?? null,
        area: a.areaDesc ?? null,
        sender: a.senderName ?? null,
        response: a.response ?? null,
        sent: a.sent ?? null,
        effective: a.effective ?? null,
        onset: a.onset ?? null,
        expires: a.expires ?? null,
        ends: a.ends ?? null,
      })),
    };

    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }

  private async getObservation(stationId: string): Promise<ToolResult> {
    interface ObservationResponse {
      properties?: {
        timestamp?: string;
        textDescription?: string;
        temperature?: { value?: number | null };
        dewpoint?: { value?: number | null };
        windDirection?: { value?: number | null };
        windSpeed?: { value?: number | null };
        windGust?: { value?: number | null };
        barometricPressure?: { value?: number | null };
        seaLevelPressure?: { value?: number | null };
        visibility?: { value?: number | null };
        relativeHumidity?: { value?: number | null };
        heatIndex?: { value?: number | null };
        windChill?: { value?: number | null };
      };
    }

    const data = await this.nwsFetch<ObservationResponse>(
      `/stations/${encodeURIComponent(stationId)}/observations/latest`,
    );
    const p = data.properties ?? {};

    const celsiusToF = (c: number | null | undefined): number | null =>
      typeof c === 'number' ? Math.round(((c * 9) / 5 + 32) * 10) / 10 : null;

    const mpsToMph = (v: number | null | undefined): number | null =>
      typeof v === 'number' ? Math.round(v * 2.23694 * 10) / 10 : null;

    const result = {
      station_id: stationId,
      timestamp: p.timestamp ?? null,
      conditions: p.textDescription ?? null,
      temperature_c: p.temperature?.value ?? null,
      temperature_f: celsiusToF(p.temperature?.value),
      dewpoint_c: p.dewpoint?.value ?? null,
      humidity_pct: p.relativeHumidity?.value ?? null,
      wind_speed_mph: mpsToMph(p.windSpeed?.value),
      wind_gust_mph: mpsToMph(p.windGust?.value),
      wind_direction_deg: p.windDirection?.value ?? null,
      pressure_pa: p.barometricPressure?.value ?? null,
      sea_level_pressure_pa: p.seaLevelPressure?.value ?? null,
      visibility_m: p.visibility?.value ?? null,
      heat_index_c: p.heatIndex?.value ?? null,
      wind_chill_c: p.windChill?.value ?? null,
    };

    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }
}
