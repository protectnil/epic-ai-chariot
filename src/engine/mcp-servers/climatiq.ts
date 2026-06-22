/**
 * Climatiq Carbon Footprint MCP Adapter
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

// Base URL: https://api.climatiq.io/data/v1
// Auth: Bearer token (Authorization: Bearer <key>) — register at https://www.climatiq.io
// Docs: https://www.climatiq.io/docs
// Free tier: 200 requests/month
// Category: environment

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

interface ClimatiqConfig {
  apiKey: string;
  baseUrl?: string;
}

export class ClimatiqMCPServer extends MCPAdapterBase {
  private readonly apiKey: string;
  private readonly baseUrl: string;

  constructor(config: ClimatiqConfig) {
    super();
    if (!config || typeof config !== 'object') {
      throw new Error('Climatiq: configuration object is required');
    }
    for (const __k of (['apiKey'] as Array<keyof typeof config>)) {
      if (config[__k] === undefined || config[__k] === null || (config[__k] as unknown) === '') {
        throw new Error('Climatiq: ' + __k + ' is required');
      }
    }
    this.apiKey = config.apiKey;
    this.baseUrl = config.baseUrl || 'https://api.climatiq.io/data/v1';
  }

  static catalog() {
    return {
      name: 'climatiq',
      displayName: 'Climatiq Carbon Footprint',
      version: '1.0.0',
      type: 'rest' as const,
      category: 'environment',
      keywords: [
        'climatiq', 'carbon', 'carbon footprint', 'emissions', 'co2', 'co2e',
        'greenhouse gas', 'ghg', 'climate', 'sustainability', 'emission factors',
        'epa', 'defra', 'beis', 'ecoinvent', 'kgco2e', 'energy', 'freight',
        'computing', 'fuel', 'carbon calculator', 'net zero', 'scope 1', 'scope 2', 'scope 3',
      ],
      toolNames: ['search_factors', 'estimate_emissions', 'list_unit_types'],
      description: 'Calculate carbon footprints using Climatiq\'s database of 60,000+ peer-reviewed emission factors. Search factors by source/region/year, estimate kgCO₂e for any activity, and list supported unit types.',
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
        name: 'search_factors',
        description:
          'Search Climatiq\'s emission-factor database. Use to discover factor IDs and required parameters before calling estimate_emissions. Filter by query, category, source (e.g., "EPA", "DEFRA"), region (ISO code), or year.',
        inputSchema: {
          type: 'object',
          properties: {
            query: { type: 'string', description: 'Free-text search (e.g., "electricity grid", "concrete production")' },
            category: { type: 'string', description: 'Climatiq category (e.g., "electricity", "fuel", "freight", "computing")' },
            source: { type: 'string', description: 'Source dataset (e.g., "EPA", "DEFRA", "BEIS", "ecoinvent")' },
            region: { type: 'string', description: 'ISO-3166 region code (e.g., "US", "GB", "DE")' },
            year: { type: 'number', description: 'Publication year' },
            unit_type: { type: 'string', description: 'Activity unit type (Energy, Volume, Distance, Mass, etc.)' },
            results_per_page: { type: 'number', description: '1-100 (default 25)' },
            page: { type: 'number', description: '1-based page (default 1)' },
          },
        },
      },
      {
        name: 'estimate_emissions',
        description:
          'Calculate kgCO₂e for an activity. Pass an emission_factor with at minimum `activity_id` (from search_factors) or `id`, plus the required `parameters` (e.g., `{ energy: 200, energy_unit: "kWh" }`). Returns CO₂e + breakdown.',
        inputSchema: {
          type: 'object',
          properties: {
            emission_factor: {
              type: 'object',
              description:
                'Selector object — at minimum {activity_id: "..."} or {id: "..."}. May add region, year, source for disambiguation.',
            },
            parameters: {
              type: 'object',
              description: 'Activity quantities matching the factor\'s required unit type (e.g., {energy:200, energy_unit:"kWh"}).',
            },
          },
          required: ['emission_factor', 'parameters'],
        },
      },
      {
        name: 'list_unit_types',
        description: 'List supported unit-type families (Energy / Volume / Distance / Mass / etc.) and their valid units.',
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
        case 'search_factors':    return this.searchFactors(args);
        case 'estimate_emissions': return this.estimateEmissions(args);
        case 'list_unit_types':   return this.listUnitTypes();
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

  private async climatiqRequest(path: string, init: RequestInit = {}): Promise<ToolResult> {
    const url = `${this.baseUrl}${path}`;
    const response = await this.fetchWithRetry(url, {
      ...init,
      headers: {
        ...(init.headers ?? {}),
        Authorization: `Bearer ${this.apiKey}`,
        Accept: 'application/json',
      },
    });
    if (response.status === 401 || response.status === 403) {
      return {
        content: [{ type: 'text', text: 'Climatiq: unauthorized — check the API key' }],
        isError: true,
      };
    }
    if (response.status === 429) {
      return {
        content: [{ type: 'text', text: 'Climatiq: rate-limit (HTTP 429) — free tier is 200 requests/month' }],
        isError: true,
      };
    }
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `Climatiq API error: ${response.status} ${errText.slice(0, 200)}` }],
        isError: true,
      };
    }
    const data = await response.json();
    return { content: [{ type: 'text', text: this.truncate(data) }], isError: false };
  }

  private async searchFactors(args: Record<string, unknown>): Promise<ToolResult> {
    const params = new URLSearchParams({
      results_per_page: String(Math.min(100, Math.max(1, (args.results_per_page as number) ?? 25))),
      page: String(Math.max(1, (args.page as number) ?? 1)),
    });
    if (args.query)     params.set('query',     String(args.query));
    if (args.category)  params.set('category',  String(args.category));
    if (args.source)    params.set('source',    String(args.source));
    if (args.region)    params.set('region',    String(args.region));
    if (args.year)      params.set('year',      String(args.year));
    if (args.unit_type) params.set('unit_type', String(args.unit_type));

    return this.climatiqRequest(`/search?${params}`);
  }

  private async estimateEmissions(args: Record<string, unknown>): Promise<ToolResult> {
    const body = JSON.stringify({
      emission_factor: args.emission_factor,
      parameters: args.parameters,
    });
    return this.climatiqRequest('/estimate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body,
    });
  }

  private async listUnitTypes(): Promise<ToolResult> {
    return this.climatiqRequest('/unit-types');
  }
}
