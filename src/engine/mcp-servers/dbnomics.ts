/**
 * DBnomics MCP Adapter
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

// Base URL: https://api.db.nomics.world/v22
// Auth: none — public API, no key required
// Docs: https://api.db.nomics.world/v22/apidocs
// Category: economics
// Covers ~1 billion time series across 80+ stats providers (ECB, BLS, Eurostat, FRED, IMF, OECD, WB, etc.)

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

const BASE_URL = 'https://api.db.nomics.world/v22';

export class DBnomicsMCPServer extends MCPAdapterBase {
  private readonly baseUrl: string;

  constructor(config?: { baseUrl?: string }) {
    super();
    if (config === null) { throw new Error('DBnomicsMCPServer: configuration object is required when provided'); }
    this.baseUrl = config?.baseUrl ?? BASE_URL;
  }

  static catalog() {
    return {
      name: 'dbnomics',
      displayName: 'DBnomics — Global Economic & Statistical Data',
      version: '1.0.0',
      category: 'economics',
      keywords: [
        'dbnomics', 'economics', 'statistics', 'macroeconomics', 'time series',
        'ECB', 'BLS', 'Eurostat', 'FRED', 'IMF', 'OECD', 'World Bank',
        'GDP', 'inflation', 'exchange rate', 'national accounts',
        'financial data', 'open data', 'public data', 'global data',
      ],
      toolNames: ['search', 'list_providers', 'list_datasets', 'get_series', 'find_series'],
      description: 'DBnomics API v22: full-text search and retrieval of ~1 billion economic and statistical time series from 80+ providers including ECB, BLS, Eurostat, FRED, IMF, OECD, and the World Bank.',
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
        name: 'search',
        description:
          'Full-text search across all DBnomics providers. Returns matching series with provider/dataset/series codes and human-readable labels.',
        inputSchema: {
          type: 'object',
          properties: {
            query: { type: 'string', description: 'Free-text search query' },
            limit: { type: 'number', description: 'Number of results to return, 1–1000 (default 20)' },
            offset: { type: 'number', description: '0-based offset for pagination' },
          },
          required: ['query'],
        },
      },
      {
        name: 'list_providers',
        description: 'List all statistics providers available in DBnomics (ECB, BLS, Eurostat, FRED, IMF, OECD, World Bank, and 80+ more).',
        inputSchema: {
          type: 'object',
          properties: {},
        },
      },
      {
        name: 'list_datasets',
        description: 'List all datasets available from a given statistics provider.',
        inputSchema: {
          type: 'object',
          properties: {
            provider: { type: 'string', description: 'Provider code, e.g. "ECB", "BLS", "EUROSTAT"' },
            limit: { type: 'number', description: 'Number of results to return, 1–1000 (default 100)' },
            offset: { type: 'number', description: '0-based offset for pagination' },
          },
          required: ['provider'],
        },
      },
      {
        name: 'get_series',
        description:
          'Fetch a specific time series identified by provider, dataset, and series code. Set observations to true to include the actual data points.',
        inputSchema: {
          type: 'object',
          properties: {
            provider: { type: 'string', description: 'Provider code, e.g. "ECB"' },
            dataset: { type: 'string', description: 'Dataset code, e.g. "EXR"' },
            series_code: { type: 'string', description: 'Series code (dot-separated dimensions or named code), e.g. "A.USD.EUR.SP00.A"' },
            observations: { type: 'boolean', description: 'Include data points (default true)' },
          },
          required: ['provider', 'dataset', 'series_code'],
        },
      },
      {
        name: 'find_series',
        description:
          'Browse series within a provider/dataset with optional dimension filters. Useful when you know the provider+dataset and want to enumerate or filter series by dimension values.',
        inputSchema: {
          type: 'object',
          properties: {
            provider: { type: 'string', description: 'Provider code, e.g. "ECB"' },
            dataset: { type: 'string', description: 'Dataset code, e.g. "EXR"' },
            dimensions: {
              type: 'object',
              description: 'Optional dimension filter map, e.g. {"FREQ":"A","COUNTRY":"DE"}',
              additionalProperties: { type: 'string' },
            },
            limit: { type: 'number', description: 'Number of results to return, 1–1000 (default 100)' },
            offset: { type: 'number', description: '0-based offset for pagination' },
            observations: { type: 'boolean', description: 'Include observations in response (default false to save bandwidth)' },
          },
          required: ['provider', 'dataset'],
        },
      },
    ];
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<ToolResult> {
    try {
      switch (name) {
        case 'search':         return this.search(args);
        case 'list_providers': return this.listProviders();
        case 'list_datasets':  return this.listDatasets(args);
        case 'get_series':     return this.getSeries(args);
        case 'find_series':    return this.findSeries(args);
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

  private async get(path: string, params: URLSearchParams): Promise<ToolResult> {
    const qs = params.toString();
    const url = `${this.baseUrl}${path}${qs ? `?${qs}` : ''}`;
    const response = await this.fetchWithRetry(url, {
      method: 'GET',
      headers: { Accept: 'application/json' },
    });
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `DBnomics API error: ${response.status} ${errText.slice(0, 200)}` }],
        isError: true,
      };
    }
    const data = await response.json();
    return { content: [{ type: 'text', text: this.truncate(data) }], isError: false };
  }

  private requireString(args: Record<string, unknown>, key: string, example: string): string {
    const v = args[key];
    if (typeof v !== 'string' || !v.trim()) {
      throw new Error(`Required argument "${key}" is missing. Pass a string like ${example}.`);
    }
    return v;
  }

  private async search(args: Record<string, unknown>): Promise<ToolResult> {
    const query = this.requireString(args, 'query', '"GDP growth"');
    const params = new URLSearchParams({
      q: query,
      limit: String(Math.min(1000, Math.max(1, (args.limit as number) ?? 20))),
      offset: String(Math.max(0, (args.offset as number) ?? 0)),
    });
    return this.get('/search', params);
  }

  private async listProviders(): Promise<ToolResult> {
    return this.get('/providers', new URLSearchParams());
  }

  private async listDatasets(args: Record<string, unknown>): Promise<ToolResult> {
    const provider = this.requireString(args, 'provider', '"ECB"').toUpperCase();
    const params = new URLSearchParams({
      limit: String(Math.min(1000, Math.max(1, (args.limit as number) ?? 100))),
      offset: String(Math.max(0, (args.offset as number) ?? 0)),
    });
    return this.get(`/providers/${encodeURIComponent(provider)}`, params);
  }

  private async getSeries(args: Record<string, unknown>): Promise<ToolResult> {
    const provider = this.requireString(args, 'provider', '"ECB"').toUpperCase();
    const dataset = this.requireString(args, 'dataset', '"EXR"');
    const seriesCode = this.requireString(args, 'series_code', '"A.USD.EUR.SP00.A"');
    const params = new URLSearchParams({
      observations: String(args.observations !== false),
    });
    return this.get(
      `/series/${encodeURIComponent(provider)}/${encodeURIComponent(dataset)}/${encodeURIComponent(seriesCode)}`,
      params,
    );
  }

  private async findSeries(args: Record<string, unknown>): Promise<ToolResult> {
    const provider = this.requireString(args, 'provider', '"ECB"').toUpperCase();
    const dataset = this.requireString(args, 'dataset', '"EXR"');
    const params = new URLSearchParams({
      limit: String(Math.min(1000, Math.max(1, (args.limit as number) ?? 100))),
      offset: String(Math.max(0, (args.offset as number) ?? 0)),
      observations: String(args.observations === true),
    });
    if (args.dimensions && typeof args.dimensions === 'object' && !Array.isArray(args.dimensions)) {
      params.set('dimensions', JSON.stringify(args.dimensions));
    }
    return this.get(
      `/series/${encodeURIComponent(provider)}/${encodeURIComponent(dataset)}`,
      params,
    );
  }
}
