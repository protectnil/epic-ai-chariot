/**
 * NASA POWER MCP Adapter
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

// Upstream: https://power.larc.nasa.gov (public REST API, no auth required)
// API docs: https://power.larc.nasa.gov/docs/services/api/
// Base URL: https://power.larc.nasa.gov/api
// Auth: none (public, no-auth-verified)
// Category: weather
// Rate limits: None documented; NASA POWER is a free public service

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

const BASE_URL = 'https://power.larc.nasa.gov/api';
const DEFAULT_PARAMS = 'T2M,T2M_MAX,T2M_MIN,PRECTOTCORR,ALLSKY_SFC_SW_DWN,RH2M,WS10M';

export class NasaPowerMCPServer extends MCPAdapterBase {
  private readonly baseUrl: string;

  constructor(config?: { baseUrl?: string }) {
    super();
    if (config === null) { throw new Error('NasaPowerMCPServer: configuration object is required when provided'); }
    this.baseUrl = config?.baseUrl ?? BASE_URL;
  }

  static catalog() {
    return {
      name: 'nasa-power',
      displayName: 'NASA POWER',
      version: '1.0.0',
      category: 'weather',
      keywords: [
        'nasa', 'power', 'solar', 'meteorology', 'climate', 'weather',
        'agriculture', 'renewable energy', 'sustainable buildings',
        'temperature', 'precipitation', 'humidity', 'wind speed',
        'irradiance', 'time series', 'climatology', 'geospatial',
      ],
      toolNames: ['point_data', 'climatology', 'regional_data'],
      description: 'NASA POWER: query solar and meteorological time-series data for any coordinate or bounding-box region — covers agriculture, renewable energy, and sustainable building communities. Free public API, no authentication required.',
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
        name: 'point_data',
        description:
          'Time-series observations for a single coordinate. Temporal granularity controlled by the dates supplied — both must be YYYYMMDD; use daily by default.',
        inputSchema: {
          type: 'object',
          properties: {
            latitude: { type: 'number', description: 'Latitude in degrees (-90 to 90)' },
            longitude: { type: 'number', description: 'Longitude in degrees (-180 to 180)' },
            start: { type: 'string', description: 'Start date YYYYMMDD' },
            end: { type: 'string', description: 'End date YYYYMMDD' },
            parameters: {
              type: 'string',
              description:
                'Comma-separated POWER parameter codes (default T2M,T2M_MAX,T2M_MIN,PRECTOTCORR,ALLSKY_SFC_SW_DWN,RH2M,WS10M)',
            },
            community: {
              type: 'string',
              description: 'AG (agriculture, default) | RE (renewable energy) | SB (sustainable buildings)',
            },
            temporal: {
              type: 'string',
              description: 'hourly | daily (default) | monthly',
            },
          },
          required: ['latitude', 'longitude', 'start', 'end'],
        },
      },
      {
        name: 'climatology',
        description: 'Long-term monthly climatology averages for a coordinate.',
        inputSchema: {
          type: 'object',
          properties: {
            latitude: { type: 'number', description: 'Latitude in degrees (-90 to 90)' },
            longitude: { type: 'number', description: 'Longitude in degrees (-180 to 180)' },
            parameters: {
              type: 'string',
              description:
                'Comma-separated POWER parameter codes (default T2M,T2M_MAX,T2M_MIN,PRECTOTCORR,ALLSKY_SFC_SW_DWN,RH2M,WS10M)',
            },
            community: {
              type: 'string',
              description: 'AG (agriculture, default) | RE (renewable energy) | SB (sustainable buildings)',
            },
          },
          required: ['latitude', 'longitude'],
        },
      },
      {
        name: 'regional_data',
        description:
          'Bounding-box query — daily or monthly data over a rectangular region. Bbox area max ~10° × 10°.',
        inputSchema: {
          type: 'object',
          properties: {
            latitude_min: { type: 'number', description: 'Minimum latitude of bounding box' },
            latitude_max: { type: 'number', description: 'Maximum latitude of bounding box' },
            longitude_min: { type: 'number', description: 'Minimum longitude of bounding box' },
            longitude_max: { type: 'number', description: 'Maximum longitude of bounding box' },
            start: { type: 'string', description: 'Start date YYYYMMDD' },
            end: { type: 'string', description: 'End date YYYYMMDD' },
            parameters: {
              type: 'string',
              description:
                'Comma-separated POWER parameter codes (default T2M,T2M_MAX,T2M_MIN,PRECTOTCORR,ALLSKY_SFC_SW_DWN,RH2M,WS10M)',
            },
            community: {
              type: 'string',
              description: 'AG (agriculture, default) | RE (renewable energy) | SB (sustainable buildings)',
            },
            temporal: {
              type: 'string',
              description: 'daily (default) | monthly',
            },
          },
          required: ['latitude_min', 'latitude_max', 'longitude_min', 'longitude_max', 'start', 'end'],
        },
      },
    ];
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<ToolResult> {
    try {
      switch (name) {
        case 'point_data':    return this.pointData(args);
        case 'climatology':   return this.climatologyData(args);
        case 'regional_data': return this.regionalData(args);
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

  private async powerGet(path: string): Promise<ToolResult> {
    const url = `${this.baseUrl}${path}`;
    const response = await this.fetchWithRetry(url, {
      method: 'GET',
      headers: { Accept: 'application/json' },
    });
    if (response.status === 422) {
      const text = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `NASA POWER bad request (422): ${text.slice(0, 300)}` }],
        isError: true,
      };
    }
    if (!response.ok) {
      const text = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `NASA POWER error: ${response.status} ${text.slice(0, 200)}` }],
        isError: true,
      };
    }
    const data = await response.json();
    return { content: [{ type: 'text', text: this.truncate(data) }], isError: false };
  }

  private requireStr(args: Record<string, unknown>, key: string): string {
    const v = args[key];
    if (typeof v !== 'string' || !v.trim()) {
      throw new Error(`Required argument "${key}" is missing or empty.`);
    }
    return v;
  }

  private requireNum(args: Record<string, unknown>, key: string): number {
    const v = args[key];
    if (typeof v !== 'number' || !Number.isFinite(v)) {
      throw new Error(`Required argument "${key}" must be a finite number.`);
    }
    return v;
  }

  private async pointData(args: Record<string, unknown>): Promise<ToolResult> {
    const latitude  = this.requireNum(args, 'latitude');
    const longitude = this.requireNum(args, 'longitude');
    const start     = this.requireStr(args, 'start');
    const end       = this.requireStr(args, 'end');
    const community  = ((args.community as string) ?? 'AG').toUpperCase();
    const parameters = (args.parameters as string) ?? DEFAULT_PARAMS;
    const temporal   = ((args.temporal as string) ?? 'daily').toLowerCase();

    const qs = new URLSearchParams({
      parameters,
      community,
      longitude: String(longitude),
      latitude: String(latitude),
      start,
      end,
      format: 'JSON',
    });
    return this.powerGet(`/temporal/${temporal}/point?${qs}`);
  }

  private async climatologyData(args: Record<string, unknown>): Promise<ToolResult> {
    const latitude  = this.requireNum(args, 'latitude');
    const longitude = this.requireNum(args, 'longitude');
    const community  = ((args.community as string) ?? 'AG').toUpperCase();
    const parameters = (args.parameters as string) ?? DEFAULT_PARAMS;

    const qs = new URLSearchParams({
      parameters,
      community,
      longitude: String(longitude),
      latitude: String(latitude),
      format: 'JSON',
    });
    return this.powerGet(`/temporal/climatology/point?${qs}`);
  }

  private async regionalData(args: Record<string, unknown>): Promise<ToolResult> {
    const latMin  = this.requireNum(args, 'latitude_min');
    const latMax  = this.requireNum(args, 'latitude_max');
    const lonMin  = this.requireNum(args, 'longitude_min');
    const lonMax  = this.requireNum(args, 'longitude_max');
    const start   = this.requireStr(args, 'start');
    const end     = this.requireStr(args, 'end');
    const community  = ((args.community as string) ?? 'AG').toUpperCase();
    const parameters = (args.parameters as string) ?? DEFAULT_PARAMS;
    const temporal   = ((args.temporal as string) ?? 'daily').toLowerCase();

    const qs = new URLSearchParams({
      parameters,
      community,
      'latitude-min': String(latMin),
      'latitude-max': String(latMax),
      'longitude-min': String(lonMin),
      'longitude-max': String(lonMax),
      start,
      end,
      format: 'JSON',
    });
    return this.powerGet(`/temporal/${temporal}/regional?${qs}`);
  }
}
