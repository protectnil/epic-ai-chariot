/**
 * Trefle Plant Database MCP Adapter
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

// Base URL: https://trefle.io/api/v1
// Auth: API token as query param (?token=<api_key>). Free — register at https://trefle.io
// Docs: https://docs.trefle.io
// Category: nature
// Tools: search_plants, get_plant, search_species, get_species, list_distributions

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

interface TrefleConfig {
  apiKey: string;
  baseUrl?: string;
}

interface TreflePlantSummary {
  id?: number;
  common_name?: string | null;
  scientific_name?: string;
  family?: string;
  family_common_name?: string | null;
  genus?: string;
  image_url?: string | null;
  slug?: string;
  year?: number | null;
  bibliography?: string;
  author?: string;
  status?: string;
  rank?: string;
}

export class TrefleMCPServer extends MCPAdapterBase {
  private readonly apiKey: string;
  private readonly baseUrl: string;

  constructor(config: TrefleConfig) {
    super();
    if (!config || typeof config !== 'object') {
      throw new Error('Trefle: configuration object is required');
    }
    for (const __k of (['apiKey'] as Array<keyof typeof config>)) {
      if (config[__k] === undefined || config[__k] === null || (config[__k] as unknown) === '') {
        throw new Error('Trefle: ' + __k + ' is required');
      }
    }
    this.apiKey = config.apiKey;
    this.baseUrl = config.baseUrl || 'https://trefle.io/api/v1';
  }

  static catalog() {
    return {
      name: 'trefle',
      displayName: 'Trefle Plant Database',
      version: '1.0.0',
      category: 'nature' as const,
      keywords: [
        'trefle', 'plants', 'botany', 'flora', 'species', 'scientific name',
        'common name', 'edible plants', 'medicinal plants', 'plant family',
        'plant distribution', 'TDWG', 'native range', 'plant images',
        'plant database', 'vegetation', 'herbs', 'trees', 'shrubs',
        'growth habit', 'plant taxonomy',
      ],
      toolNames: [
        'search_plants',
        'get_plant',
        'search_species',
        'get_species',
        'list_distributions',
      ],
      description: 'Trefle plant database (1M+ species): search plants and species by name, retrieve full botanical records with growth/distribution/image data, and list native ranges by TDWG zone.',
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
        name: 'search_plants',
        description:
          'Search plants by common or scientific name. Returns Trefle plant ID, scientific name, common name, family, and image URL. Optionally filter by edible or vegetable flags.',
        inputSchema: {
          type: 'object',
          properties: {
            query: { type: 'string', description: 'Free-text search query (common or scientific name)' },
            edible: { type: 'boolean', description: 'Only return edible plants' },
            vegetable: { type: 'boolean', description: 'Only return vegetables' },
            page: { type: 'number', description: '1-based page number' },
            page_size: { type: 'number', description: 'Results per page, 1–100 (default 20)' },
          },
          required: ['query'],
        },
      },
      {
        name: 'get_plant',
        description:
          'Retrieve a full plant record by Trefle plant ID. Returns scientific name, common name, family, status, image URL, publication year, and main species data.',
        inputSchema: {
          type: 'object',
          properties: {
            plant_id: { type: 'number', description: 'Trefle numeric plant ID (e.g. 189734)' },
          },
          required: ['plant_id'],
        },
      },
      {
        name: 'search_species',
        description:
          'Search the species rank (below plant — some plants have multiple species). Returns Trefle species ID and scientific name.',
        inputSchema: {
          type: 'object',
          properties: {
            query: { type: 'string', description: 'Free-text search query' },
            page: { type: 'number', description: '1-based page number' },
            page_size: { type: 'number', description: 'Results per page, 1–100' },
          },
          required: ['query'],
        },
      },
      {
        name: 'get_species',
        description:
          'Retrieve a full species record by Trefle species ID. Includes growth habit, light and soil requirements, edible/medicinal flags, native distribution zones, images, and sources.',
        inputSchema: {
          type: 'object',
          properties: {
            species_id: { type: 'number', description: 'Trefle numeric species ID (e.g. 189734)' },
          },
          required: ['species_id'],
        },
      },
      {
        name: 'list_distributions',
        description:
          'List plants native or introduced to a TDWG WGSRPD distribution zone (e.g. "CAL" = California, "FRA" = France, "JAP" = Japan). Returns a paged list of plant summaries for that zone.',
        inputSchema: {
          type: 'object',
          properties: {
            zone: { type: 'string', description: 'TDWG zone code, e.g. "CAL", "FRA", "NWY", "JAP"' },
            page: { type: 'number', description: '1-based page number' },
            page_size: { type: 'number', description: 'Results per page, 1–100' },
          },
          required: ['zone'],
        },
      },
    ];
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<ToolResult> {
    try {
      switch (name) {
        case 'search_plants':   return this.searchPlants(args);
        case 'get_plant':       return this.getPlant(args);
        case 'search_species':  return this.searchSpecies(args);
        case 'get_species':     return this.getSpecies(args);
        case 'list_distributions': return this.listDistributions(args);
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

  private buildUrl(path: string, params: URLSearchParams): string {
    params.set('token', this.apiKey);
    return `${this.baseUrl}${path}?${params.toString()}`;
  }

  private async trefleRequest(path: string, params: URLSearchParams): Promise<ToolResult> {
    const url = this.buildUrl(path, params);
    const response = await this.fetchWithRetry(url, {
      method: 'GET',
      headers: { Accept: 'application/json' },
    });
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `Trefle API error: ${response.status} ${errText.slice(0, 200)}` }],
        isError: true,
      };
    }
    const data = await response.json();
    return { content: [{ type: 'text', text: this.truncate(data) }], isError: false };
  }

  private normalizePlant(p: TreflePlantSummary): Record<string, unknown> {
    return {
      id: p.id ?? null,
      scientific_name: p.scientific_name ?? null,
      common_name: p.common_name ?? null,
      family: p.family ?? null,
      family_common_name: p.family_common_name ?? null,
      genus: p.genus ?? null,
      year: p.year ?? null,
      author: p.author ?? null,
      status: p.status ?? null,
      rank: p.rank ?? null,
      image: p.image_url ?? null,
      slug: p.slug ?? null,
    };
  }

  private requireNumber(args: Record<string, unknown>, key: string, example: string): number {
    const v = args[key];
    if (typeof v !== 'number' || !Number.isFinite(v)) {
      throw new Error(`Required argument "${key}" must be a finite number. Example: ${example}.`);
    }
    return v;
  }

  private async searchPlants(args: Record<string, unknown>): Promise<ToolResult> {
    const params = new URLSearchParams({
      q: String(args.query),
      page: String(Math.max(1, typeof args.page === 'number' ? args.page : 1)),
      per_page: String(Math.min(100, Math.max(1, typeof args.page_size === 'number' ? args.page_size : 20))),
    });
    if (args.edible) params.set('filter[edible]', 'true');
    if (args.vegetable) params.set('filter[vegetable]', 'true');

    const response = await this.fetchWithRetry(this.buildUrl('/plants/search', params), {
      method: 'GET',
      headers: { Accept: 'application/json' },
    });
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return { content: [{ type: 'text', text: `Trefle API error: ${response.status} ${errText.slice(0, 200)}` }], isError: true };
    }
    const data = await response.json() as { data?: TreflePlantSummary[]; meta?: { total?: number } };
    const result = {
      total: data.meta?.total ?? 0,
      returned: data.data?.length ?? 0,
      plants: (data.data ?? []).map(p => this.normalizePlant(p)),
    };
    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }

  private async getPlant(args: Record<string, unknown>): Promise<ToolResult> {
    const plantId = this.requireNumber(args, 'plant_id', '189734');
    return this.trefleRequest(`/plants/${plantId}`, new URLSearchParams());
  }

  private async searchSpecies(args: Record<string, unknown>): Promise<ToolResult> {
    const params = new URLSearchParams({
      q: String(args.query),
      page: String(Math.max(1, typeof args.page === 'number' ? args.page : 1)),
      per_page: String(Math.min(100, Math.max(1, typeof args.page_size === 'number' ? args.page_size : 20))),
    });

    const response = await this.fetchWithRetry(this.buildUrl('/species/search', params), {
      method: 'GET',
      headers: { Accept: 'application/json' },
    });
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return { content: [{ type: 'text', text: `Trefle API error: ${response.status} ${errText.slice(0, 200)}` }], isError: true };
    }
    const data = await response.json() as { data?: TreflePlantSummary[]; meta?: { total?: number } };
    const result = {
      total: data.meta?.total ?? 0,
      returned: data.data?.length ?? 0,
      species: (data.data ?? []).map(p => this.normalizePlant(p)),
    };
    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }

  private async getSpecies(args: Record<string, unknown>): Promise<ToolResult> {
    const speciesId = this.requireNumber(args, 'species_id', '189734');
    return this.trefleRequest(`/species/${speciesId}`, new URLSearchParams());
  }

  private async listDistributions(args: Record<string, unknown>): Promise<ToolResult> {
    const zone = String(args.zone).toUpperCase();
    const params = new URLSearchParams({
      page: String(Math.max(1, typeof args.page === 'number' ? args.page : 1)),
      per_page: String(Math.min(100, Math.max(1, typeof args.page_size === 'number' ? args.page_size : 20))),
    });

    const response = await this.fetchWithRetry(
      this.buildUrl(`/distributions/${encodeURIComponent(zone)}/plants`, params),
      { method: 'GET', headers: { Accept: 'application/json' } },
    );
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return { content: [{ type: 'text', text: `Trefle API error: ${response.status} ${errText.slice(0, 200)}` }], isError: true };
    }
    const data = await response.json() as { data?: TreflePlantSummary[]; meta?: { total?: number } };
    const result = {
      zone,
      total: data.meta?.total ?? 0,
      returned: data.data?.length ?? 0,
      plants: (data.data ?? []).map(p => this.normalizePlant(p)),
    };
    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }
}
