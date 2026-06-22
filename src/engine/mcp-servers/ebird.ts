/**
 * eBird MCP Adapter — Cornell Lab of Ornithology citizen-science bird observations
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 *
 * Upstream API: https://api.ebird.org/v2
 * Auth: header X-eBirdApiToken. Free — register at https://ebird.org/api/keygen.
 * Docs: https://documenter.getpostman.com/view/664302/S1ENwy59
 * Category: science
 */

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

interface EbirdConfig {
  apiKey: string;
  baseUrl?: string;
}

interface EbirdObservation {
  speciesCode?: string;
  comName?: string;
  sciName?: string;
  locId?: string;
  locName?: string;
  obsDt?: string;
  howMany?: number;
  lat?: number;
  lng?: number;
  obsValid?: boolean;
  obsReviewed?: boolean;
  locationPrivate?: boolean;
  subId?: string;
  exoticCategory?: string;
}

export class EbirdMCPServer extends MCPAdapterBase {
  private readonly apiKey: string;
  private readonly baseUrl: string;

  constructor(config: EbirdConfig) {
    super();
    if (!config || typeof config !== 'object') {
      throw new Error('eBird: configuration object is required');
    }
    for (const __k of (['apiKey'] as Array<keyof typeof config>)) {
      if (config[__k] === undefined || config[__k] === null || (config[__k] as unknown) === '') {
        throw new Error('eBird: ' + __k + ' is required');
      }
    }
    this.apiKey = config.apiKey;
    this.baseUrl = config.baseUrl || 'https://api.ebird.org/v2';
  }

  static catalog() {
    return {
      name: 'ebird',
      displayName: 'eBird — Cornell Lab Bird Observations',
      version: '1.0.0',
      category: 'science',
      keywords: [
        'ebird', 'birds', 'birding', 'ornithology', 'bird sightings',
        'citizen science', 'species', 'observations', 'cornell', 'wildlife',
        'rare birds', 'notable sightings', 'bird watching', 'taxonomy',
        'region', 'hotspot', 'checklist',
      ],
      toolNames: [
        'recent_observations',
        'recent_notable',
        'nearby_observations',
        'find_species',
        'list_subregions',
      ],
      description: 'eBird API v2: 1B+ bird sightings worldwide — recent observations by region, notable/rare sightings, nearby geo-search, species taxonomy lookup, and region hierarchy browsing from the Cornell Lab of Ornithology.',
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
        name: 'recent_observations',
        description:
          'Recent bird sightings in a region. region_code is the eBird identifier — countries are 2-letter ("US", "GB"), states "US-CA", counties "US-CA-075", and birding hotspots use the "L<id>" code from eBird (e.g., "L99381"). Optionally filter to one species.',
        inputSchema: {
          type: 'object',
          properties: {
            region_code: { type: 'string', description: 'eBird region code' },
            species_code: {
              type: 'string',
              description: 'Optional eBird species code (use find_species to look up)',
            },
            back: { type: 'number', description: 'Days back (1-30, default 14)' },
            max_results: { type: 'number', description: '1-10000 (default 100)' },
            include_provisional: {
              type: 'boolean',
              description: 'Include unconfirmed observations (default false)',
            },
          },
          required: ['region_code'],
        },
      },
      {
        name: 'recent_notable',
        description:
          'Only notable (rare / out-of-range / first-of-season) sightings in a region. Sometimes the most interesting subset.',
        inputSchema: {
          type: 'object',
          properties: {
            region_code: { type: 'string', description: 'eBird region code' },
            back: { type: 'number', description: 'Days back (1-30, default 14)' },
            max_results: { type: 'number', description: '1-10000 (default 100)' },
            detail: { type: 'string', description: 'simple | full (default simple)' },
          },
          required: ['region_code'],
        },
      },
      {
        name: 'nearby_observations',
        description:
          'Recent observations within a radius of a lat/lon. Useful for "what birds are around here right now."',
        inputSchema: {
          type: 'object',
          properties: {
            latitude: { type: 'number', description: 'Latitude' },
            longitude: { type: 'number', description: 'Longitude' },
            dist_km: { type: 'number', description: 'Radius in km (1-50, default 25)' },
            back: { type: 'number', description: 'Days back (1-30, default 14)' },
            max_results: { type: 'number', description: '1-10000 (default 100)' },
            species_code: { type: 'string', description: 'Optional species filter' },
          },
          required: ['latitude', 'longitude'],
        },
      },
      {
        name: 'find_species',
        description:
          'Search the eBird taxonomy by common or scientific name. Returns the eBird species code needed by the observation tools.',
        inputSchema: {
          type: 'object',
          properties: {
            query: { type: 'string', description: 'Common or scientific name' },
          },
          required: ['query'],
        },
      },
      {
        name: 'list_subregions',
        description:
          'Child regions of a parent. region_type is "country", "subnational1" (states/provinces), or "subnational2" (counties). parent_region_code uses eBird codes ("world", "US", "US-CA").',
        inputSchema: {
          type: 'object',
          properties: {
            region_type: {
              type: 'string',
              description: 'country | subnational1 | subnational2',
              enum: ['country', 'subnational1', 'subnational2'],
            },
            parent_region_code: {
              type: 'string',
              description: 'Parent region (default "world")',
            },
          },
          required: ['region_type'],
        },
      },
    ];
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<ToolResult> {
    try {
      switch (name) {
        case 'recent_observations':  return this.recentObservations(args);
        case 'recent_notable':       return this.recentNotable(args);
        case 'nearby_observations':  return this.nearbyObservations(args);
        case 'find_species':         return this.findSpecies(args);
        case 'list_subregions':      return this.listSubregions(args);
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

  private async ebirdRequest(path: string, params: URLSearchParams): Promise<ToolResult> {
    const qs = params.toString();
    const url = `${this.baseUrl}${path}${qs ? `?${qs}` : ''}`;
    const response = await this.fetchWithRetry(url, {
      method: 'GET',
      headers: {
        'X-eBirdApiToken': this.apiKey,
        Accept: 'application/json',
      },
    });
    if (response.status === 401 || response.status === 403) {
      return {
        content: [{ type: 'text', text: 'eBird: unauthorized — check the API token' }],
        isError: true,
      };
    }
    if (response.status === 404) {
      return {
        content: [{ type: 'text', text: 'eBird: not found (HTTP 404) — check region/species codes' }],
        isError: true,
      };
    }
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `eBird API error: ${response.status} ${errText.slice(0, 200)}` }],
        isError: true,
      };
    }
    const data = await response.json();
    return { content: [{ type: 'text', text: this.truncate(data) }], isError: false };
  }

  private requireStr(args: Record<string, unknown>, key: string, example: string): string {
    const v = args[key];
    if (typeof v !== 'string' || !v.trim()) {
      throw new Error(`Required argument "${key}" is missing or empty. Pass a string like ${example}.`);
    }
    return v;
  }

  private normalizeObservation(o: EbirdObservation) {
    return {
      species_code:      o.speciesCode      ?? null,
      common_name:       o.comName          ?? null,
      scientific_name:   o.sciName          ?? null,
      location_id:       o.locId            ?? null,
      location:          o.locName          ?? null,
      latitude:          o.lat              ?? null,
      longitude:         o.lng              ?? null,
      observed_at:       o.obsDt            ?? null,
      count:             o.howMany          ?? null,
      valid:             o.obsValid         ?? null,
      reviewed:          o.obsReviewed      ?? null,
      private_location:  o.locationPrivate  ?? null,
      checklist_id:      o.subId            ?? null,
      exotic_category:   o.exoticCategory   ?? null,
    };
  }

  private async recentObservations(args: Record<string, unknown>): Promise<ToolResult> {
    const region = this.requireStr(args, 'region_code', '"US-CA" or "L99381"');
    const params = new URLSearchParams({
      back:       String(Math.min(30, Math.max(1, (args.back as number) ?? 14))),
      maxResults: String(Math.min(10000, Math.max(1, (args.max_results as number) ?? 100))),
    });
    if (args.include_provisional) params.set('includeProvisional', 'true');
    const path = args.species_code
      ? `/data/obs/${encodeURIComponent(region)}/recent/${encodeURIComponent(String(args.species_code))}`
      : `/data/obs/${encodeURIComponent(region)}/recent`;
    const result = await this.ebirdRequest(path, params);
    if (result.isError) return result;
    try {
      const raw = JSON.parse(result.content[0].text) as EbirdObservation[];
      const normalized = { region_code: region, count: raw.length, observations: raw.map(o => this.normalizeObservation(o)) };
      return { content: [{ type: 'text', text: this.truncate(normalized) }], isError: false };
    } catch {
      return result;
    }
  }

  private async recentNotable(args: Record<string, unknown>): Promise<ToolResult> {
    const region = this.requireStr(args, 'region_code', '"US-MA"');
    const params = new URLSearchParams({
      back:       String(Math.min(30, Math.max(1, (args.back as number) ?? 14))),
      maxResults: String(Math.min(10000, Math.max(1, (args.max_results as number) ?? 100))),
      detail:     (args.detail as string) ?? 'simple',
    });
    const result = await this.ebirdRequest(
      `/data/obs/${encodeURIComponent(region)}/recent/notable`,
      params,
    );
    if (result.isError) return result;
    try {
      const raw = JSON.parse(result.content[0].text) as EbirdObservation[];
      const normalized = { region_code: region, count: raw.length, observations: raw.map(o => this.normalizeObservation(o)) };
      return { content: [{ type: 'text', text: this.truncate(normalized) }], isError: false };
    } catch {
      return result;
    }
  }

  private async nearbyObservations(args: Record<string, unknown>): Promise<ToolResult> {
    const params = new URLSearchParams({
      lat:        String(args.latitude),
      lng:        String(args.longitude),
      dist:       String(Math.min(50, Math.max(1, (args.dist_km as number) ?? 25))),
      back:       String(Math.min(30, Math.max(1, (args.back as number) ?? 14))),
      maxResults: String(Math.min(10000, Math.max(1, (args.max_results as number) ?? 100))),
    });
    const path = args.species_code
      ? `/data/obs/geo/recent/${encodeURIComponent(String(args.species_code))}`
      : '/data/obs/geo/recent';
    const result = await this.ebirdRequest(path, params);
    if (result.isError) return result;
    try {
      const raw = JSON.parse(result.content[0].text) as EbirdObservation[];
      const normalized = {
        center: { latitude: args.latitude, longitude: args.longitude },
        count: raw.length,
        observations: raw.map(o => this.normalizeObservation(o)),
      };
      return { content: [{ type: 'text', text: this.truncate(normalized) }], isError: false };
    } catch {
      return result;
    }
  }

  private async findSpecies(args: Record<string, unknown>): Promise<ToolResult> {
    const query = this.requireStr(args, 'query', '"snowy owl"');
    const result = await this.ebirdRequest(
      '/ref/taxa/search',
      new URLSearchParams({ q: query }),
    );
    if (result.isError) return result;
    try {
      const raw = JSON.parse(result.content[0].text) as { code?: string; name?: string }[];
      const normalized = {
        query,
        count: raw.length,
        species: raw.map(s => ({ species_code: s.code ?? null, name: s.name ?? null })),
      };
      return { content: [{ type: 'text', text: this.truncate(normalized) }], isError: false };
    } catch {
      return result;
    }
  }

  private async listSubregions(args: Record<string, unknown>): Promise<ToolResult> {
    const regionType = this.requireStr(args, 'region_type', '"subnational1" (e.g., for US states)');
    const parent = (args.parent_region_code as string) ?? 'world';
    const result = await this.ebirdRequest(
      `/ref/region/list/${encodeURIComponent(regionType)}/${encodeURIComponent(parent)}`,
      new URLSearchParams(),
    );
    if (result.isError) return result;
    try {
      const raw = JSON.parse(result.content[0].text) as { code?: string; name?: string }[];
      const normalized = {
        region_type: regionType,
        parent_region: parent,
        count: raw.length,
        regions: raw.map(r => ({ code: r.code ?? null, name: r.name ?? null })),
      };
      return { content: [{ type: 'text', text: this.truncate(normalized) }], isError: false };
    } catch {
      return result;
    }
  }
}
