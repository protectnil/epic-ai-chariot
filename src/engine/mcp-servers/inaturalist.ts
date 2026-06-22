/**
 * iNaturalist MCP Adapter
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

// Official REST API: https://api.inaturalist.org/v1
// Auth: none (public read-only endpoints require no key)
// Docs: https://api.inaturalist.org/v1/docs
// Category: science
// Rate limits: none documented for read-only endpoints

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

const BASE_URL = 'https://api.inaturalist.org/v1';

export class INaturalistMCPServer extends MCPAdapterBase {
  private readonly baseUrl: string;

  constructor(config?: { baseUrl?: string }) {
    super();
    if (config === null) { throw new Error('INaturalistMCPServer: configuration object is required when provided'); }
    this.baseUrl = config?.baseUrl ?? BASE_URL;
  }

  static catalog() {
    return {
      name: 'inaturalist',
      displayName: 'iNaturalist',
      version: '1.0.0',
      category: 'science',
      keywords: [
        'inaturalist', 'citizen science', 'species', 'observations', 'biodiversity',
        'wildlife', 'taxa', 'birds', 'mammals', 'plants', 'nature', 'ecology',
        'IUCN', 'threatened', 'conservation', 'sightings', 'naturalist',
      ],
      toolNames: ['search_observations', 'search_taxa', 'top_species'],
      description: 'iNaturalist: search citizen-science species observations, look up taxa by name, and find the most-observed wildlife in any place — free, no auth required.',
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
        name: 'search_observations',
        description:
          'Search citizen-science observations on iNaturalist. Filter by taxon name (e.g., "Pandion haliaetus" or "osprey"), place name ("California"), year, threatened status, or quality grade. Returns photographed sightings with coordinates, dates, and observer info. Pairs well with GBIF for cross-validation.',
        inputSchema: {
          type: 'object',
          properties: {
            taxon_name: { type: 'string', description: 'Scientific or common species/taxon name' },
            place: { type: 'string', description: 'Place name (country, state, park). Auto-resolved to place_id.' },
            year: { type: 'number', description: 'Filter to a specific year' },
            threatened: {
              type: 'boolean',
              description: 'Restrict to IUCN-threatened taxa',
            },
            quality_grade: {
              type: 'string',
              description: 'casual | needs_id | research (default: research)',
              enum: ['casual', 'needs_id', 'research'],
            },
            per_page: { type: 'number', description: 'Results per page (1-200, default 20)' },
          },
        },
      },
      {
        name: 'search_taxa',
        description:
          'Search iNaturalist taxa by name (common or scientific). Returns taxon ID, rank, ancestry, conservation status, and photo URL. Use the taxon ID for downstream filters or to disambiguate look-alike species.',
        inputSchema: {
          type: 'object',
          properties: {
            query: { type: 'string', description: 'Common or scientific name' },
            rank: {
              type: 'string',
              description: 'Restrict to a rank (kingdom, phylum, class, order, family, genus, species)',
            },
            per_page: { type: 'number', description: 'Results per page (1-30, default 10)' },
          },
          required: ['query'],
        },
      },
      {
        name: 'top_species',
        description:
          'Most-frequently-observed species in a place over a date range. Auto-resolves place name to place_id. Returns ranked species with observation counts and taxonomic info. Great for "what wildlife lives here?" questions.',
        inputSchema: {
          type: 'object',
          properties: {
            place: { type: 'string', description: 'Place name (country, state, park, etc.)' },
            year: { type: 'number', description: 'Restrict to a specific year (optional)' },
            per_page: { type: 'number', description: 'Top-N species (1-50, default 20)' },
          },
          required: ['place'],
        },
      },
    ];
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<ToolResult> {
    try {
      switch (name) {
        case 'search_observations': return this.searchObservations(args);
        case 'search_taxa':         return this.searchTaxa(args);
        case 'top_species':         return this.topSpecies(args);
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

  private async resolvePlaceId(place: string): Promise<{ id: number; name: string } | null> {
    const params = new URLSearchParams({ q: place, per_page: '1' });
    const response = await this.fetchWithRetry(
      `${this.baseUrl}/places/autocomplete?${params}`,
      { method: 'GET', headers: { Accept: 'application/json' } },
    );
    if (!response.ok) return null;
    const data = (await response.json()) as {
      results?: { id: number; display_name?: string; name?: string }[];
    };
    const first = data.results?.[0];
    if (!first) return null;
    return { id: first.id, name: first.display_name ?? first.name ?? place };
  }

  private async resolveTaxonId(name: string): Promise<{ id: number; name: string } | null> {
    const params = new URLSearchParams({ q: name, per_page: '1' });
    const response = await this.fetchWithRetry(
      `${this.baseUrl}/taxa/autocomplete?${params}`,
      { method: 'GET', headers: { Accept: 'application/json' } },
    );
    if (!response.ok) return null;
    const data = (await response.json()) as {
      results?: { id: number; name?: string; preferred_common_name?: string }[];
    };
    const first = data.results?.[0];
    if (!first) return null;
    return { id: first.id, name: first.preferred_common_name ?? first.name ?? name };
  }

  private async searchObservations(args: Record<string, unknown>): Promise<ToolResult> {
    const params = new URLSearchParams({
      per_page: String(Math.min(200, Math.max(1, (args.per_page as number | undefined) ?? 20))),
      order_by: 'observed_on',
      quality_grade: (args.quality_grade as string | undefined) ?? 'research',
    });

    const resolved: {
      taxon?: { id: number; name: string };
      place?: { id: number; name: string };
    } = {};

    if (args.taxon_name) {
      const t = await this.resolveTaxonId(args.taxon_name as string);
      if (t) {
        params.set('taxon_id', String(t.id));
        resolved.taxon = t;
      }
    }
    if (args.place) {
      const p = await this.resolvePlaceId(args.place as string);
      if (p) {
        params.set('place_id', String(p.id));
        resolved.place = p;
      }
    }
    if (args.year) params.set('year', String(args.year));
    if (args.threatened) params.set('threatened', 'true');

    const response = await this.fetchWithRetry(
      `${this.baseUrl}/observations?${params}`,
      { method: 'GET', headers: { Accept: 'application/json' } },
    );
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `API error: ${response.status} ${errText}` }],
        isError: true,
      };
    }

    const data = (await response.json()) as {
      total_results?: number;
      results?: {
        id: number;
        uri?: string;
        observed_on?: string;
        place_guess?: string;
        latitude?: string | number;
        longitude?: string | number;
        geojson?: { coordinates?: [number, number] };
        taxon?: {
          id: number;
          name?: string;
          preferred_common_name?: string;
          rank?: string;
        };
        user?: { login?: string };
        photos?: { url?: string }[];
        quality_grade?: string;
      }[];
    };

    const result = {
      resolved,
      total_results: data.total_results ?? 0,
      observations: (data.results ?? []).map((o) => ({
        id: o.id,
        url: o.uri ?? `https://www.inaturalist.org/observations/${o.id}`,
        observed_on: o.observed_on ?? null,
        place: o.place_guess ?? null,
        latitude: o.geojson?.coordinates?.[1] ?? (o.latitude != null ? Number(o.latitude) : null),
        longitude: o.geojson?.coordinates?.[0] ?? (o.longitude != null ? Number(o.longitude) : null),
        taxon: o.taxon
          ? {
              id: o.taxon.id,
              scientific_name: o.taxon.name ?? null,
              common_name: o.taxon.preferred_common_name ?? null,
              rank: o.taxon.rank ?? null,
            }
          : null,
        observer: o.user?.login ?? null,
        photo: o.photos?.[0]?.url ?? null,
        quality_grade: o.quality_grade ?? null,
      })),
    };

    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }

  private async searchTaxa(args: Record<string, unknown>): Promise<ToolResult> {
    const query = args.query as string;
    const perPage = Math.min(30, Math.max(1, (args.per_page as number | undefined) ?? 10));
    const params = new URLSearchParams({ q: query, per_page: String(perPage) });
    if (args.rank) params.set('rank', args.rank as string);

    const response = await this.fetchWithRetry(
      `${this.baseUrl}/taxa?${params}`,
      { method: 'GET', headers: { Accept: 'application/json' } },
    );
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `API error: ${response.status} ${errText}` }],
        isError: true,
      };
    }

    const data = (await response.json()) as {
      total_results?: number;
      results?: {
        id: number;
        name?: string;
        rank?: string;
        preferred_common_name?: string;
        observations_count?: number;
        conservation_status?: { status_name?: string };
        ancestors?: { name?: string; rank?: string }[];
        default_photo?: { medium_url?: string };
      }[];
    };

    const result = {
      total_results: data.total_results ?? 0,
      results: (data.results ?? []).map((t) => ({
        id: t.id,
        scientific_name: t.name ?? null,
        common_name: t.preferred_common_name ?? null,
        rank: t.rank ?? null,
        observations_count: t.observations_count ?? null,
        conservation_status: t.conservation_status?.status_name ?? null,
        ancestry: (t.ancestors ?? [])
          .map((a) => `${a.rank ?? ''}:${a.name ?? ''}`)
          .filter(Boolean),
        photo: t.default_photo?.medium_url ?? null,
      })),
    };

    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }

  private async topSpecies(args: Record<string, unknown>): Promise<ToolResult> {
    const place = args.place as string;
    const perPage = Math.min(50, Math.max(1, (args.per_page as number | undefined) ?? 20));

    const resolved = await this.resolvePlaceId(place);
    if (!resolved) {
      return {
        content: [{ type: 'text', text: this.truncate({ resolved: null, top_species: [], note: `No iNaturalist place matched "${place}"` }) }],
        isError: false,
      };
    }

    const params = new URLSearchParams({
      place_id: String(resolved.id),
      per_page: String(perPage),
    });
    if (args.year) params.set('year', String(args.year));

    const response = await this.fetchWithRetry(
      `${this.baseUrl}/observations/species_counts?${params}`,
      { method: 'GET', headers: { Accept: 'application/json' } },
    );
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `API error: ${response.status} ${errText}` }],
        isError: true,
      };
    }

    const data = (await response.json()) as {
      total_results?: number;
      results?: {
        count: number;
        taxon: {
          id: number;
          name?: string;
          rank?: string;
          preferred_common_name?: string;
          default_photo?: { medium_url?: string };
        };
      }[];
    };

    const result = {
      resolved: { place: resolved },
      total_unique_species: data.total_results ?? 0,
      top_species: (data.results ?? []).map((r) => ({
        observation_count: r.count,
        taxon_id: r.taxon.id,
        scientific_name: r.taxon.name ?? null,
        common_name: r.taxon.preferred_common_name ?? null,
        rank: r.taxon.rank ?? null,
        photo: r.taxon.default_photo?.medium_url ?? null,
      })),
    };

    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }
}
