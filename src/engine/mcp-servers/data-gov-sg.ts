/**
 * data.gov.sg MCP Adapter
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

// Upstream confirmed from open-source MCP wrapper (MIT) for the Singapore government open-data API.
// This file calls the real upstream directly. No proxy or gateway is involved.
//
// Base URL (catalog / tabular): https://api-open.data.gov.sg/v2
// Base URL (real-time feeds):   https://api.data.gov.sg/v1
// Auth: None required — data.gov.sg APIs are public and free with no auth.
// Docs: https://data.gov.sg/developer
// Rate limits: Not officially documented; polite use expected.

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

interface DataGovSgConfig {
  /** Optional base URL override for the v2 catalog API (default: https://api-open.data.gov.sg/v2) */
  baseV2Url?: string;
  /** Optional base URL override for the v1 real-time API (default: https://api.data.gov.sg/v1) */
  baseV1Url?: string;
}

export class DataGovSgMCPServer extends MCPAdapterBase {
  private readonly baseV2Url: string;
  private readonly baseV1Url: string;

  constructor(config: DataGovSgConfig = {}) {
    super();
    if (!config || typeof config !== 'object') {
      throw new Error('data.gov.sg: configuration object is required');
    }
    this.baseV2Url = config.baseV2Url ?? 'https://api-open.data.gov.sg/v2';
    this.baseV1Url = config.baseV1Url ?? 'https://api.data.gov.sg/v1';
  }

  static catalog() {
    return {
      name: 'data-gov-sg',
      displayName: 'data.gov.sg — Singapore Open Data',
      version: '1.0.0',
      category: 'data',
      keywords: [
        'singapore', 'data.gov.sg', 'open data', 'government', 'sg',
        'weather', 'air quality', 'psi', 'pm25', 'uv index',
        'taxi', 'transport', 'traffic', 'real-time', 'environment',
        'dataset', 'catalog', 'tabular data', 'public api',
      ],
      toolNames: [
        'search_datasets',
        'get_dataset',
        'query_dataset',
        'weather_now',
        'air_quality_psi',
        'air_quality_pm25',
        'uv_index',
        'taxi_availability',
        'traffic_incidents',
      ],
      description: 'data.gov.sg: browse and query Singapore\'s open-data catalog (datasets, metadata, rows) and access real-time environment and transport feeds (weather, PSI, PM2.5, UV, taxis, traffic incidents).',
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
      // ── Tabular catalog ──────────────────────────────────────────────────────
      {
        name: 'search_datasets',
        description: 'Browse / search the data.gov.sg dataset catalog. Returns dataset IDs, titles, and descriptions.',
        inputSchema: {
          type: 'object',
          properties: {
            query: {
              type: 'string',
              description: 'Free-text filter applied to dataset titles and descriptions.',
            },
            page: {
              type: 'number',
              description: '1-based page number (default 1).',
            },
            page_size: {
              type: 'number',
              description: 'Results per page, 1–100 (default 20).',
            },
          },
        },
      },
      {
        name: 'get_dataset',
        description: 'Retrieve metadata and column schema for a specific dataset by its ID.',
        inputSchema: {
          type: 'object',
          properties: {
            dataset_id: {
              type: 'string',
              description: 'Dataset ID, e.g. "d_8b84c4ee58e3cfc0ece0d773c8ca6abc".',
            },
          },
          required: ['dataset_id'],
        },
      },
      {
        name: 'query_dataset',
        description: 'Fetch rows from a dataset. Supports limit, offset, and an optional column-value filter map.',
        inputSchema: {
          type: 'object',
          properties: {
            dataset_id: {
              type: 'string',
              description: 'Dataset ID.',
            },
            limit: {
              type: 'number',
              description: 'Number of rows to return, 1–10000 (default 100).',
            },
            offset: {
              type: 'number',
              description: '0-based row offset for pagination (default 0).',
            },
            filters: {
              type: 'object',
              description: 'Column-value filter map. Keys are column names; values are the strings to match.',
              additionalProperties: { type: 'string' },
            },
          },
          required: ['dataset_id'],
        },
      },
      // ── Real-time environment ────────────────────────────────────────────────
      {
        name: 'weather_now',
        description: 'Current temperature, humidity, wind speed, and rainfall readings across Singapore weather stations.',
        inputSchema: {
          type: 'object',
          properties: {},
        },
      },
      {
        name: 'air_quality_psi',
        description: 'Current Pollutant Standards Index (PSI) by region: north, south, east, west, and central Singapore.',
        inputSchema: {
          type: 'object',
          properties: {},
        },
      },
      {
        name: 'air_quality_pm25',
        description: 'Current PM2.5 concentration (µg/m³) readings by region across Singapore.',
        inputSchema: {
          type: 'object',
          properties: {},
        },
      },
      {
        name: 'uv_index',
        description: 'Current UV index for Singapore.',
        inputSchema: {
          type: 'object',
          properties: {},
        },
      },
      // ── Real-time transport ──────────────────────────────────────────────────
      {
        name: 'taxi_availability',
        description: 'Live positions of available taxis across Singapore.',
        inputSchema: {
          type: 'object',
          properties: {},
        },
      },
      {
        name: 'traffic_incidents',
        description: 'Current traffic incidents on Singapore expressways and major roads.',
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
        case 'search_datasets':    return this.searchDatasets(args);
        case 'get_dataset':        return this.getDataset(args);
        case 'query_dataset':      return this.queryDataset(args);
        case 'weather_now':        return this.weatherNow();
        case 'air_quality_psi':    return this.v1Realtime('/environment/psi');
        case 'air_quality_pm25':   return this.v1Realtime('/environment/pm25');
        case 'uv_index':           return this.v1Realtime('/environment/uv-index');
        case 'taxi_availability':  return this.v1Realtime('/transport/taxi-availability');
        case 'traffic_incidents':  return this.v1Realtime('/transport/traffic-incidents');
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

  private async sgGet(url: string): Promise<ToolResult> {
    const response = await this.fetchWithRetry(url, {
      method: 'GET',
      headers: { Accept: 'application/json' },
    });
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `data.gov.sg API error: ${response.status} ${errText.slice(0, 200)}` }],
        isError: true,
      };
    }
    const data = await response.json();
    return { content: [{ type: 'text', text: this.truncate(data) }], isError: false };
  }

  private async searchDatasets(args: Record<string, unknown>): Promise<ToolResult> {
    const page = Math.max(1, (args.page as number) ?? 1);
    const params = new URLSearchParams({ page: String(page) });
    if (args.query) params.set('search', String(args.query));
    if (args.page_size) {
      params.set('pageSize', String(Math.min(100, Math.max(1, args.page_size as number))));
    }
    return this.sgGet(`${this.baseV2Url}/public/api/datasets?${params}`);
  }

  private async getDataset(args: Record<string, unknown>): Promise<ToolResult> {
    const datasetId = this.requireString(args, 'dataset_id', '"d_8b84c4ee58e3cfc0ece0d773c8ca6abc"');
    return this.sgGet(`${this.baseV2Url}/public/api/datasets/${encodeURIComponent(datasetId)}/metadata`);
  }

  private async queryDataset(args: Record<string, unknown>): Promise<ToolResult> {
    const datasetId = this.requireString(args, 'dataset_id', '"d_8b84c4ee58e3cfc0ece0d773c8ca6abc"');
    const limit = Math.min(10000, Math.max(1, (args.limit as number) ?? 100));
    const offset = Math.max(0, (args.offset as number) ?? 0);
    const params = new URLSearchParams({
      limit: String(limit),
      offset: String(offset),
    });
    if (args.filters && typeof args.filters === 'object') {
      params.set('filters', JSON.stringify(args.filters));
    }
    return this.sgGet(`${this.baseV2Url}/public/api/datasets/${encodeURIComponent(datasetId)}/poll-download?${params}`);
  }

  private async weatherNow(): Promise<ToolResult> {
    const tempResp = await this.fetchWithRetry(
      `${this.baseV1Url}/environment/air-temperature`,
      { method: 'GET', headers: { Accept: 'application/json' } },
    );
    if (!tempResp.ok) {
      return {
        content: [{ type: 'text', text: `data.gov.sg weather error: ${tempResp.status}` }],
        isError: true,
      };
    }
    const temperature = await tempResp.json();

    const [humidityResult, windResult, rainfallResult] = await Promise.allSettled([
      this.fetchWithRetry(`${this.baseV1Url}/environment/relative-humidity`, { method: 'GET', headers: { Accept: 'application/json' } }).then(r => r.ok ? r.json() : null),
      this.fetchWithRetry(`${this.baseV1Url}/environment/wind-speed`, { method: 'GET', headers: { Accept: 'application/json' } }).then(r => r.ok ? r.json() : null),
      this.fetchWithRetry(`${this.baseV1Url}/environment/rainfall`, { method: 'GET', headers: { Accept: 'application/json' } }).then(r => r.ok ? r.json() : null),
    ]);

    const combined = {
      temperature,
      humidity: humidityResult.status === 'fulfilled' ? humidityResult.value : null,
      wind: windResult.status === 'fulfilled' ? windResult.value : null,
      rainfall: rainfallResult.status === 'fulfilled' ? rainfallResult.value : null,
    };
    return { content: [{ type: 'text', text: this.truncate(combined) }], isError: false };
  }

  private async v1Realtime(path: string): Promise<ToolResult> {
    return this.sgGet(`${this.baseV1Url}${path}`);
  }

  private requireString(args: Record<string, unknown>, key: string, example: string): string {
    const v = args[key];
    if (typeof v !== 'string' || !v.trim()) {
      throw new Error(`Required argument "${key}" is missing. Pass a string like ${example}.`);
    }
    return v;
  }
}
