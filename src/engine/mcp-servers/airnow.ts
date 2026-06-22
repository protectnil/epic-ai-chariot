/**
 * EPA AirNow MCP Adapter
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

// Official upstream: EPA AirNow API (https://docs.airnowapi.org)
// This adapter calls the real upstream API directly via fetchWithRetry.
//
// Base URL: https://www.airnowapi.org/aq
// Auth: API key query param (API_KEY). Free account: 500 req/hour.
//   Register at: https://docs.airnowapi.org/account/request/
// Docs: https://docs.airnowapi.org
// Rate limits: 500 requests/hour on the free tier.
//
// Tools:
//   current_by_zip         — latest AQI for a US ZIP code
//   current_by_location    — latest AQI nearest a lat/lon
//   forecast_by_zip        — AQI forecast for a US ZIP code on a given date
//   observations_in_bbox   — historical AQI observations inside a bounding box

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

interface AirNowConfig {
  /** EPA AirNow API key (free 500 req/hour — register at https://docs.airnowapi.org/account/request/) */
  apiKey: string;
  /** Optional base URL override (default: https://www.airnowapi.org/aq) */
  baseUrl?: string;
}

export class AirNowMCPServer extends MCPAdapterBase {
  private readonly apiKey: string;
  private readonly baseUrl: string;

  constructor(config: AirNowConfig) {
    super();
    if (!config || typeof config !== 'object') {
      throw new Error('AirNow: configuration object is required');
    }
    for (const __k of (['apiKey'] as Array<keyof typeof config>)) {
      if (config[__k] === undefined || config[__k] === null || (config[__k] as unknown) === '') {
        throw new Error('AirNow: ' + __k + ' is required');
      }
    }
    this.apiKey = config.apiKey;
    this.baseUrl = config.baseUrl ?? 'https://www.airnowapi.org/aq';
  }

  static catalog() {
    return {
      name: 'airnow',
      displayName: 'EPA AirNow — US Air Quality Index',
      version: '1.0.0',
      category: 'weather',
      keywords: [
        'airnow', 'aqi', 'air quality', 'epa', 'pollution', 'ozone',
        'pm2.5', 'pm10', 'particulate matter', 'smog', 'forecast',
        'us air quality', 'environmental', 'health', 'outdoor',
        'monitoring', 'co', 'no2', 'so2', 'zip code', 'bounding box',
      ],
      toolNames: [
        'current_by_zip',
        'current_by_location',
        'forecast_by_zip',
        'observations_in_bbox',
      ],
      description: 'EPA AirNow API: real-time and forecasted US air quality index (AQI) for ozone, PM2.5, PM10, CO, NO2, and SO2 — the official EPA data source covering 2,000+ monitoring sites.',
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
        name: 'current_by_zip',
        description:
          'Latest observed AQI for a US ZIP code. Returns one record per pollutant reported at the nearest site (typically O3 + PM2.5). Includes AQI value, category (Good / Moderate / etc.), reporting area, and timestamp.',
        inputSchema: {
          type: 'object',
          properties: {
            zip_code: {
              type: 'string',
              description: 'US 5-digit ZIP code',
            },
            distance_miles: {
              type: 'number',
              description: 'Search radius in miles (default 25, max 250)',
            },
          },
          required: ['zip_code'],
        },
      },
      {
        name: 'current_by_location',
        description: 'Latest observed AQI for the AirNow station nearest a lat/lon.',
        inputSchema: {
          type: 'object',
          properties: {
            latitude: {
              type: 'number',
              description: 'US latitude',
            },
            longitude: {
              type: 'number',
              description: 'US longitude',
            },
            distance_miles: {
              type: 'number',
              description: 'Search radius in miles (default 25, max 250)',
            },
          },
          required: ['latitude', 'longitude'],
        },
      },
      {
        name: 'forecast_by_zip',
        description:
          'AQI forecast for a US ZIP code on a given date (defaults to today). Useful for "is tomorrow ok for outdoor activity" decisions.',
        inputSchema: {
          type: 'object',
          properties: {
            zip_code: {
              type: 'string',
              description: 'US 5-digit ZIP code',
            },
            date: {
              type: 'string',
              description: 'Forecast date in YYYY-MM-DD format (default: today)',
            },
            distance_miles: {
              type: 'number',
              description: 'Search radius in miles (default 25, max 250)',
            },
          },
          required: ['zip_code'],
        },
      },
      {
        name: 'observations_in_bbox',
        description:
          'Historical AQI observations inside a bounding box for a date/time range. Specify pollutants as comma-separated parameter codes (e.g., "OZONE,PM25,PM10,CO,NO2,SO2"). bbox format: "minLon,minLat,maxLon,maxLat".',
        inputSchema: {
          type: 'object',
          properties: {
            bbox: {
              type: 'string',
              description: 'Bounding box as "minLon,minLat,maxLon,maxLat" (e.g., "-123.0,37.0,-121.0,38.5")',
            },
            start_date: {
              type: 'string',
              description: 'Start datetime in YYYY-MM-DDT00 format (hour-granular, e.g., "2026-05-01T00")',
            },
            end_date: {
              type: 'string',
              description: 'End datetime in YYYY-MM-DDT23 format (e.g., "2026-05-01T23")',
            },
            parameters: {
              type: 'string',
              description: 'Comma-separated pollutant codes (default: "OZONE,PM25,PM10"; valid values: OZONE, PM25, PM10, CO, NO2, SO2)',
            },
            data_type: {
              type: 'string',
              description: 'A (AQI only) | C (concentration only) | B (both — default)',
            },
            verbose: {
              type: 'boolean',
              description: 'When true, include site name, agency, county, and full AQS code fields',
            },
          },
          required: ['bbox', 'start_date', 'end_date'],
        },
      },
    ];
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<ToolResult> {
    try {
      switch (name) {
        case 'current_by_zip':       return this.currentByZip(args);
        case 'current_by_location':  return this.currentByLocation(args);
        case 'forecast_by_zip':      return this.forecastByZip(args);
        case 'observations_in_bbox': return this.observationsInBbox(args);
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

  private async airnowGet(path: string, params: URLSearchParams): Promise<ToolResult> {
    params.set('format', 'application/json');
    params.set('API_KEY', this.apiKey);
    const url = `${this.baseUrl}${path}?${params.toString()}`;
    const response = await this.fetchWithRetry(url, {
      method: 'GET',
      headers: { Accept: 'application/json' },
    });
    if (response.status === 401 || response.status === 403) {
      return {
        content: [{ type: 'text', text: 'AirNow: unauthorized — check the API key' }],
        isError: true,
      };
    }
    if (response.status === 429) {
      return {
        content: [{ type: 'text', text: 'AirNow: rate-limit (HTTP 429) — free tier is 500 req/hour' }],
        isError: true,
      };
    }
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `AirNow API error: ${response.status} ${errText.slice(0, 200)}` }],
        isError: true,
      };
    }
    const data = await response.json();
    return { content: [{ type: 'text', text: this.truncate(data) }], isError: false };
  }

  private reqStr(args: Record<string, unknown>, key: string, example: string): string {
    const v = args[key];
    if (typeof v !== 'string' || !v.trim()) {
      throw new Error(`Required argument "${key}" is missing or empty. Pass a string like ${example}.`);
    }
    return v;
  }

  private clampDistance(args: Record<string, unknown>, defaultVal = 25): number {
    return Math.min(250, Math.max(0, Number(args.distance_miles ?? defaultVal)));
  }

  private async currentByZip(args: Record<string, unknown>): Promise<ToolResult> {
    const zip = this.reqStr(args, 'zip_code', '"94103"');
    const params = new URLSearchParams({
      zipCode: zip,
      distance: String(this.clampDistance(args)),
    });
    return this.airnowGet('/observation/zipCode/current/', params);
  }

  private async currentByLocation(args: Record<string, unknown>): Promise<ToolResult> {
    if (args.latitude === undefined || args.latitude === null) {
      throw new Error('Required argument "latitude" is missing.');
    }
    if (args.longitude === undefined || args.longitude === null) {
      throw new Error('Required argument "longitude" is missing.');
    }
    const params = new URLSearchParams({
      latitude: String(args.latitude),
      longitude: String(args.longitude),
      distance: String(this.clampDistance(args)),
    });
    return this.airnowGet('/observation/latLong/current/', params);
  }

  private async forecastByZip(args: Record<string, unknown>): Promise<ToolResult> {
    const zip = this.reqStr(args, 'zip_code', '"94103"');
    const params = new URLSearchParams({
      zipCode: zip,
      distance: String(this.clampDistance(args)),
    });
    if (args.date) {
      params.set('date', String(args.date));
    }
    return this.airnowGet('/forecast/zipCode/', params);
  }

  private async observationsInBbox(args: Record<string, unknown>): Promise<ToolResult> {
    const params = new URLSearchParams({
      BBOX: this.reqStr(args, 'bbox', '"-123.0,37.0,-121.0,38.5"'),
      startDate: this.reqStr(args, 'start_date', '"2026-05-01T00"'),
      endDate: this.reqStr(args, 'end_date', '"2026-05-01T23"'),
      parameters: (args.parameters as string) ?? 'OZONE,PM25,PM10',
      dataType: (args.data_type as string) ?? 'B',
      verbose: args.verbose ? '1' : '0',
    });
    return this.airnowGet('/data/', params);
  }
}
