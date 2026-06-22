/**
 * e-Stat Japan Government Statistics MCP Adapter
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

// API: https://www.e-stat.go.jp/api/api-info/e-stat-manual3-0
// Base URL: https://api.e-stat.go.jp/rest/3.0/app/json
// Auth: appId query parameter — register at https://www.e-stat.go.jp/api/
// Endpoints: /getStatsList, /getMetaInfo, /getStatsData, /getDataCatalog
// Category: government
// Rate limits: varies by plan

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

interface EStatJapanConfig {
  apiKey: string;
  baseUrl?: string;
}

export class EStatJapanMCPServer extends MCPAdapterBase {
  private readonly apiKey: string;
  private readonly baseUrl: string;

  constructor(config: EStatJapanConfig) {
    super();
    if (!config || typeof config !== 'object') {
      throw new Error('e-Stat Japan: configuration object is required');
    }
    for (const __k of (['apiKey'] as Array<keyof typeof config>)) {
      if (config[__k] === undefined || config[__k] === null || (config[__k] as unknown) === '') {
        throw new Error('e-Stat Japan: ' + __k + ' is required');
      }
    }
    this.apiKey = config.apiKey;
    this.baseUrl = config.baseUrl || 'https://api.e-stat.go.jp/rest/3.0/app/json';
  }

  static catalog() {
    return {
      name: 'estat-japan',
      displayName: 'e-Stat Japan Government Statistics',
      version: '1.0.0',
      category: 'government',
      keywords: [
        'e-stat', 'estat', 'japan', 'government', 'statistics', 'census',
        'population', 'demographics', 'economic data', 'public data',
        'japanese statistics', 'open data', 'national statistics',
      ],
      toolNames: ['search_stats', 'get_metadata', 'get_data', 'list_data_catalog'],
      description: 'e-Stat Japan: search and retrieve statistical tables from the Japanese government statistics portal, including census data, economic indicators, and demographic information.',
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
        name: 'search_stats',
        description: 'Search e-Stat statistical tables. Returns IDs and names for tables matching the query. Use the IDs with get_data / get_metadata.',
        inputSchema: {
          type: 'object',
          properties: {
            query: { type: 'string', description: 'Free-text search (Japanese or English)' },
            limit: { type: 'number', description: '1-100000 (default 20)' },
            start_position: { type: 'number', description: '1-based row offset (default 1)' },
            lang: { type: 'string', description: 'J (Japanese, default) | E (English)' },
          },
          required: ['query'],
        },
      },
      {
        name: 'get_metadata',
        description: 'Fetch dimensions and code lists for a stats table.',
        inputSchema: {
          type: 'object',
          properties: {
            stats_data_id: { type: 'string', description: 'Table ID (statsDataId)' },
            lang: { type: 'string', description: 'J | E' },
          },
          required: ['stats_data_id'],
        },
      },
      {
        name: 'get_data',
        description: 'Fetch observations from a stats table. Optionally filter by dimension codes.',
        inputSchema: {
          type: 'object',
          properties: {
            stats_data_id: { type: 'string', description: 'Table ID (statsDataId)' },
            limit: { type: 'number', description: '1-100000 (default 100)' },
            start_position: { type: 'number', description: '1-based row offset' },
            lang: { type: 'string', description: 'J | E' },
            filters: {
              type: 'object',
              description: 'Dimension code filters as { "cdCat01": "A03503", "cdTime": "2023" }',
              additionalProperties: { type: 'string' },
            },
          },
          required: ['stats_data_id'],
        },
      },
      {
        name: 'list_data_catalog',
        description: 'Browse the high-level data catalog (table groupings).',
        inputSchema: {
          type: 'object',
          properties: {
            query: { type: 'string', description: 'Optional free-text filter' },
            limit: { type: 'number', description: '1-100 (default 20)' },
            start_position: { type: 'number', description: '1-based offset' },
            lang: { type: 'string', description: 'J | E' },
          },
        },
      },
    ];
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<ToolResult> {
    try {
      switch (name) {
        case 'search_stats':     return this.searchStats(args);
        case 'get_metadata':     return this.getMetadata(args);
        case 'get_data':         return this.getData(args);
        case 'list_data_catalog': return this.listDataCatalog(args);
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

  private async request(path: string, params: URLSearchParams): Promise<ToolResult> {
    params.set('appId', this.apiKey);
    const url = `${this.baseUrl}${path}?${params.toString()}`;
    const response = await this.fetchWithRetry(url, {
      method: 'GET',
      headers: { Accept: 'application/json' },
    });
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `API error: ${response.status} ${errText.slice(0, 200)}` }],
        isError: true,
      };
    }
    const data = await response.json() as Record<string, unknown>;
    // e-Stat embeds status codes inside the payload — propagate as errors
    const env = (
      (data['GET_STATS_LIST'] as Record<string, unknown> | undefined) ??
      (data['GET_STATS_DATA'] as Record<string, unknown> | undefined) ??
      (data['GET_META_INFO'] as Record<string, unknown> | undefined) ??
      (data['GET_DATA_CATALOG'] as Record<string, unknown> | undefined)
    ) as { RESULT?: { STATUS?: number; ERROR_MSG?: string } } | undefined;
    if (env?.RESULT?.STATUS !== undefined && env.RESULT.STATUS !== 0) {
      return {
        content: [{ type: 'text', text: `e-Stat status ${env.RESULT.STATUS}: ${env.RESULT.ERROR_MSG ?? 'unknown'}` }],
        isError: true,
      };
    }
    return { content: [{ type: 'text', text: this.truncate(data) }], isError: false };
  }

  private reqStr(args: Record<string, unknown>, key: string, example: string): string {
    const v = args[key];
    if (typeof v !== 'string' || !v.trim()) {
      throw new Error(`Required argument "${key}" is missing. Pass a string like ${example}.`);
    }
    return v;
  }

  private async searchStats(args: Record<string, unknown>): Promise<ToolResult> {
    const params = new URLSearchParams({
      searchWord: this.reqStr(args, 'query', '"population"'),
      limit: String(Math.min(100000, Math.max(1, (args.limit as number) ?? 20))),
      startPosition: String(Math.max(1, (args.start_position as number) ?? 1)),
    });
    const lang = (args.lang as string | undefined)?.toUpperCase();
    if (lang) params.set('lang', lang);
    return this.request('/getStatsList', params);
  }

  private async getMetadata(args: Record<string, unknown>): Promise<ToolResult> {
    const params = new URLSearchParams({
      statsDataId: this.reqStr(args, 'stats_data_id', '"0003411634"'),
    });
    const lang = (args.lang as string | undefined)?.toUpperCase();
    if (lang) params.set('lang', lang);
    return this.request('/getMetaInfo', params);
  }

  private async getData(args: Record<string, unknown>): Promise<ToolResult> {
    const params = new URLSearchParams({
      statsDataId: this.reqStr(args, 'stats_data_id', '"0003411634"'),
      limit: String(Math.min(100000, Math.max(1, (args.limit as number) ?? 100))),
      startPosition: String(Math.max(1, (args.start_position as number) ?? 1)),
    });
    const lang = (args.lang as string | undefined)?.toUpperCase();
    if (lang) params.set('lang', lang);
    if (args.filters && typeof args.filters === 'object' && !Array.isArray(args.filters)) {
      for (const [k, v] of Object.entries(args.filters as Record<string, unknown>)) {
        params.set(k, String(v));
      }
    }
    return this.request('/getStatsData', params);
  }

  private async listDataCatalog(args: Record<string, unknown>): Promise<ToolResult> {
    const params = new URLSearchParams({
      limit: String(Math.min(100, Math.max(1, (args.limit as number) ?? 20))),
      startPosition: String(Math.max(1, (args.start_position as number) ?? 1)),
    });
    if (args.query) params.set('searchWord', String(args.query));
    const lang = (args.lang as string | undefined)?.toUpperCase();
    if (lang) params.set('lang', lang);
    return this.request('/getDataCatalog', params);
  }
}
