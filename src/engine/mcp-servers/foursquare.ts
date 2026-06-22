/**
 * Foursquare Places MCP Adapter
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 *
 * API:  https://api.foursquare.com/v3/places
 * Auth: Authorization header — raw API key (no Bearer prefix)
 * Docs: https://docs.foursquare.com/developer/reference/place-search
 * Category: travel
 */

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

interface FoursquareConfig {
  apiKey: string;
  baseUrl?: string;
}

// ── Upstream response shapes ──────────────────────────────────────────────────

interface FsqCategory {
  id?: number;
  name?: string;
  short_name?: string;
  plural_name?: string;
}

interface FsqPlace {
  fsq_id?: string;
  name?: string;
  categories?: FsqCategory[];
  chains?: { id?: string; name?: string }[];
  closed_bucket?: string;
  distance?: number;
  geocodes?: { main?: { latitude?: number; longitude?: number } };
  location?: {
    address?: string;
    locality?: string;
    region?: string;
    country?: string;
    postcode?: string;
    formatted_address?: string;
    neighborhood?: string[];
  };
  link?: string;
  related_places?: unknown;
  timezone?: string;
  popularity?: number;
  rating?: number;
  price?: number;
  hours?: { display?: string; open_now?: boolean };
  website?: string;
  tel?: string;
  email?: string;
  social_media?: Record<string, string>;
  tips?: { count?: number };
  description?: string;
}

// ── Adapter ───────────────────────────────────────────────────────────────────

export class FoursquareMCPServer extends MCPAdapterBase {
  private readonly apiKey: string;
  private readonly baseUrl: string;

  constructor(config: FoursquareConfig) {
    super();
    if (!config || typeof config !== 'object') {
      throw new Error('Foursquare: configuration object is required');
    }
    for (const __k of (['apiKey'] as Array<keyof typeof config>)) {
      if (config[__k] === undefined || config[__k] === null || (config[__k] as unknown) === '') {
        throw new Error('Foursquare: ' + __k + ' is required');
      }
    }
    this.apiKey = config.apiKey;
    this.baseUrl = config.baseUrl || 'https://api.foursquare.com/v3/places';
  }

  static catalog() {
    return {
      name: 'foursquare',
      displayName: 'Foursquare Places',
      version: '1.0.0',
      category: 'travel',
      keywords: [
        'foursquare', 'places', 'poi', 'points of interest', 'venue', 'venues',
        'restaurant', 'coffee', 'location', 'nearby', 'geocoding', 'address',
        'business search', 'place search', 'fsq', 'local search', 'maps',
        'latitude', 'longitude', 'categories', 'popularity', 'rating',
      ],
      toolNames: ['search_places', 'get_place', 'nearby_places'],
      description: 'Foursquare Places v3: search POIs by text or category, retrieve full place details by fsq_id, and discover nearby venues around a lat/lon — directly via the Foursquare REST API.',
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
        name: 'search_places',
        description:
          'Search Foursquare places. Combine `query` (free text like "coffee", "italian food", "hardware store") with a location anchor — either `near` (e.g., "Brooklyn, NY"), or `latitude`+`longitude`, or `bbox`. Returns place name, fsq_id, categories, address, distance, lat/lon, and popularity.',
        inputSchema: {
          type: 'object',
          properties: {
            query: { type: 'string', description: 'Free-text query (e.g., "coffee shop", "hardware store")' },
            near: { type: 'string', description: 'Place name to anchor the search ("Brooklyn, NY", "Tokyo")' },
            latitude: { type: 'number', description: 'Center latitude (pair with longitude)' },
            longitude: { type: 'number', description: 'Center longitude' },
            radius_m: { type: 'number', description: '1-100000 metres (only with lat/lon)' },
            categories: { type: 'string', description: 'Comma-separated Foursquare category IDs' },
            sort: {
              type: 'string',
              description: 'RELEVANCE (default) | DISTANCE | POPULARITY | RATING',
              enum: ['RELEVANCE', 'DISTANCE', 'POPULARITY', 'RATING'],
            },
            limit: { type: 'number', description: 'Results (1-50, default 10)' },
          },
        },
      },
      {
        name: 'get_place',
        description:
          'Get full details for a Foursquare place by fsq_id. Returns name, categories, address, geocodes, social media, website, hours, rating, price, popularity, tips counts.',
        inputSchema: {
          type: 'object',
          properties: {
            fsq_id: { type: 'string', description: 'Foursquare place ID (returned by search_places or nearby_places)' },
          },
          required: ['fsq_id'],
        },
      },
      {
        name: 'nearby_places',
        description:
          "POIs near a lat/lon without a search term — useful for \"what's around me?\" agents. Optionally filter by Foursquare category.",
        inputSchema: {
          type: 'object',
          properties: {
            latitude: { type: 'number', description: 'Latitude' },
            longitude: { type: 'number', description: 'Longitude' },
            radius_m: { type: 'number', description: '1-100000 metres (default 500)' },
            categories: { type: 'string', description: 'Comma-separated Foursquare category IDs' },
            limit: { type: 'number', description: 'Results (1-50, default 20)' },
          },
          required: ['latitude', 'longitude'],
        },
      },
    ];
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<ToolResult> {
    try {
      switch (name) {
        case 'search_places':  return this.searchPlaces(args);
        case 'get_place':      return this.getPlace(args);
        case 'nearby_places':  return this.nearbyPlaces(args);
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

  private async fsqRequest(path: string, params?: URLSearchParams): Promise<ToolResult> {
    const url = `${this.baseUrl}${path}${params ? `?${params}` : ''}`;
    const response = await this.fetchWithRetry(url, {
      method: 'GET',
      headers: {
        Authorization: this.apiKey,
        Accept: 'application/json',
      },
    });
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `Foursquare API error: ${response.status} ${errText.slice(0, 200)}` }],
        isError: true,
      };
    }
    const data = await response.json();
    return { content: [{ type: 'text', text: this.truncate(data) }], isError: false };
  }

  private normalizePlace(p: FsqPlace): Record<string, unknown> {
    return {
      fsq_id: p.fsq_id ?? null,
      name: p.name ?? null,
      categories: (p.categories ?? []).map((c) => c.name).filter(Boolean),
      category_ids: (p.categories ?? []).map((c) => c.id).filter((x): x is number => x != null),
      address: p.location?.formatted_address ?? p.location?.address ?? null,
      locality: p.location?.locality ?? null,
      region: p.location?.region ?? null,
      country: p.location?.country ?? null,
      postcode: p.location?.postcode ?? null,
      latitude: p.geocodes?.main?.latitude ?? null,
      longitude: p.geocodes?.main?.longitude ?? null,
      distance_m: p.distance ?? null,
      popularity: p.popularity ?? null,
      rating: p.rating ?? null,
      price: p.price ?? null,
      website: p.website ?? null,
      tel: p.tel ?? null,
      hours: p.hours?.display ?? null,
      open_now: p.hours?.open_now ?? null,
      chain: p.chains?.[0]?.name ?? null,
      timezone: p.timezone ?? null,
      description: p.description ?? null,
      foursquare_url: p.link ? `https://foursquare.com${p.link}` : null,
    };
  }

  private async searchPlaces(args: Record<string, unknown>): Promise<ToolResult> {
    const params = new URLSearchParams();
    if (args.query)    params.set('query', String(args.query));
    if (args.near)     params.set('near', String(args.near));
    if (typeof args.latitude === 'number' && typeof args.longitude === 'number') {
      params.set('ll', `${args.latitude},${args.longitude}`);
    }
    if (args.radius_m) params.set('radius', String(Math.min(100000, Math.max(1, args.radius_m as number))));
    if (args.categories) params.set('categories', String(args.categories));
    if (args.sort)     params.set('sort', String(args.sort));
    params.set('limit', String(Math.min(50, Math.max(1, (args.limit as number) ?? 10))));

    const response = await this.fetchWithRetry(
      `${this.baseUrl}/search?${params}`,
      { method: 'GET', headers: { Authorization: this.apiKey, Accept: 'application/json' } },
    );
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `Foursquare API error: ${response.status} ${errText.slice(0, 200)}` }],
        isError: true,
      };
    }
    const data = await response.json() as { results?: FsqPlace[] };
    const normalized = {
      count: data.results?.length ?? 0,
      results: (data.results ?? []).map((p) => this.normalizePlace(p)),
    };
    return { content: [{ type: 'text', text: this.truncate(normalized) }], isError: false };
  }

  private async getPlace(args: Record<string, unknown>): Promise<ToolResult> {
    const fsqId = args.fsq_id;
    if (typeof fsqId !== 'string' || !fsqId.trim()) {
      return {
        content: [{ type: 'text', text: 'Required argument "fsq_id" is missing or empty.' }],
        isError: true,
      };
    }
    const params = new URLSearchParams({
      fields: 'fsq_id,name,categories,chains,distance,geocodes,location,link,timezone,popularity,rating,price,hours,website,tel,email,social_media,tips,description',
    });
    const response = await this.fetchWithRetry(
      `${this.baseUrl}/${encodeURIComponent(fsqId.trim())}?${params}`,
      { method: 'GET', headers: { Authorization: this.apiKey, Accept: 'application/json' } },
    );
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `Foursquare API error: ${response.status} ${errText.slice(0, 200)}` }],
        isError: true,
      };
    }
    const data = await response.json() as FsqPlace;
    return { content: [{ type: 'text', text: this.truncate(this.normalizePlace(data)) }], isError: false };
  }

  private async nearbyPlaces(args: Record<string, unknown>): Promise<ToolResult> {
    if (typeof args.latitude !== 'number' || typeof args.longitude !== 'number') {
      return {
        content: [{ type: 'text', text: 'Required arguments "latitude" and "longitude" must be numbers.' }],
        isError: true,
      };
    }
    const params = new URLSearchParams({
      ll: `${args.latitude},${args.longitude}`,
      radius: String(Math.min(100000, Math.max(1, (args.radius_m as number) ?? 500))),
      limit: String(Math.min(50, Math.max(1, (args.limit as number) ?? 20))),
    });
    if (args.categories) params.set('categories', String(args.categories));

    const response = await this.fetchWithRetry(
      `${this.baseUrl}/nearby?${params}`,
      { method: 'GET', headers: { Authorization: this.apiKey, Accept: 'application/json' } },
    );
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `Foursquare API error: ${response.status} ${errText.slice(0, 200)}` }],
        isError: true,
      };
    }
    const data = await response.json() as { results?: FsqPlace[] };
    const normalized = {
      center: { latitude: args.latitude, longitude: args.longitude },
      count: data.results?.length ?? 0,
      results: (data.results ?? []).map((p) => this.normalizePlace(p)),
    };
    return { content: [{ type: 'text', text: this.truncate(normalized) }], isError: false };
  }
}
