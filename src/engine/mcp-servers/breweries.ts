/**
 * Open Brewery DB MCP Adapter
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

// Base URL: https://api.openbrewerydb.org/v1/breweries
// Auth: none (public, free, no key required)
// Docs: https://www.openbrewerydb.org/documentation
// Category: food
// Rate limits: none published

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

const BASE_URL = 'https://api.openbrewerydb.org/v1/breweries';

interface RawBrewery {
  id: string;
  name: string;
  brewery_type: string | null;
  address_1: string | null;
  address_2: string | null;
  address_3: string | null;
  city: string | null;
  state_province: string | null;
  postal_code: string | null;
  country: string | null;
  longitude: string | null;
  latitude: string | null;
  phone: string | null;
  website_url: string | null;
}

function formatBrewery(raw: RawBrewery): Record<string, unknown> {
  const addressParts = [raw.address_1, raw.address_2, raw.address_3].filter(Boolean);
  return {
    id: raw.id,
    name: raw.name,
    type: raw.brewery_type ?? '',
    address: addressParts.join(', '),
    city: raw.city ?? '',
    state: raw.state_province ?? '',
    postal_code: raw.postal_code ?? '',
    country: raw.country ?? '',
    coordinates:
      raw.latitude && raw.longitude
        ? { latitude: parseFloat(raw.latitude), longitude: parseFloat(raw.longitude) }
        : null,
    phone: raw.phone ?? '',
    website: raw.website_url ?? '',
  };
}

export class BreweriesMCPServer extends MCPAdapterBase {
  constructor() {
    super();
  }

  static catalog() {
    return {
      name: 'breweries',
      displayName: 'Open Brewery DB',
      version: '1.0.0',
      category: 'food',
      keywords: [
        'brewery', 'breweries', 'beer', 'craft beer', 'microbrewery',
        'taproom', 'brewpub', 'nano brewery', 'regional brewery',
        'open brewery db', 'alcohol', 'drink', 'local brewery',
        'city brewery', 'brewery search', 'brewery lookup',
      ],
      toolNames: ['search_breweries', 'get_brewery', 'breweries_by_city'],
      description: 'Open Brewery DB API v1: search breweries by name, look up a specific brewery by ID, and list breweries in a given city — public, free, no authentication required.',
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
        name: 'search_breweries',
        description:
          'Search for breweries by name. Returns a list of matching breweries with location and contact details.',
        inputSchema: {
          type: 'object',
          properties: {
            query: {
              type: 'string',
              description: 'Brewery name or partial name to search for',
            },
            limit: {
              type: 'number',
              description: 'Maximum number of results to return (default 10, max 50)',
            },
          },
          required: ['query'],
        },
      },
      {
        name: 'get_brewery',
        description:
          'Get full details for a specific brewery by its Open Brewery DB ID.',
        inputSchema: {
          type: 'object',
          properties: {
            id: {
              type: 'string',
              description:
                'Open Brewery DB brewery ID (e.g., "b54b16e1-ac3b-4bff-a11f-f7ae4ddc27e1")',
            },
          },
          required: ['id'],
        },
      },
      {
        name: 'breweries_by_city',
        description: 'Find breweries located in a specific city.',
        inputSchema: {
          type: 'object',
          properties: {
            city: {
              type: 'string',
              description:
                'City name to search breweries in (e.g., "Portland", "Denver")',
            },
            limit: {
              type: 'number',
              description: 'Maximum number of results to return (default 10, max 50)',
            },
          },
          required: ['city'],
        },
      },
    ];
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<ToolResult> {
    try {
      switch (name) {
        case 'search_breweries': return this.searchBreweries(args);
        case 'get_brewery':      return this.getBrewery(args);
        case 'breweries_by_city': return this.breweriesByCity(args);
        default:
          return {
            content: [{ type: 'text', text: `Unknown tool: ${name}` }],
            isError: true,
          };
      }
    } catch (error) {
      return {
        content: [
          {
            type: 'text',
            text: `Tool execution failed: ${error instanceof Error ? error.message : String(error)}`,
          },
        ],
        isError: true,
      };
    }
  }

  // ── Private helpers ──────────────────────────────────────────────────────────

  private async searchBreweries(args: Record<string, unknown>): Promise<ToolResult> {
    const query = args.query as string;
    const limit = Math.min(50, Math.max(1, ((args.limit as number) ?? 10)));
    const params = new URLSearchParams({
      by_name: query,
      per_page: String(limit),
    });
    const url = `${BASE_URL}?${params}`;
    const response = await this.fetchWithRetry(url, {
      method: 'GET',
      headers: { Accept: 'application/json' },
    });
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `Open Brewery DB error: ${response.status} ${errText}` }],
        isError: true,
      };
    }
    const data = (await response.json()) as RawBrewery[];
    const result = { count: data.length, breweries: data.map(formatBrewery) };
    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }

  private async getBrewery(args: Record<string, unknown>): Promise<ToolResult> {
    const id = args.id as string;
    const url = `${BASE_URL}/${encodeURIComponent(id)}`;
    const response = await this.fetchWithRetry(url, {
      method: 'GET',
      headers: { Accept: 'application/json' },
    });
    if (!response.ok) {
      const errText = response.status === 404
        ? `Brewery not found: ${id}`
        : await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `Open Brewery DB error: ${response.status} ${errText}` }],
        isError: true,
      };
    }
    const data = (await response.json()) as RawBrewery;
    return { content: [{ type: 'text', text: this.truncate(formatBrewery(data)) }], isError: false };
  }

  private async breweriesByCity(args: Record<string, unknown>): Promise<ToolResult> {
    const city = args.city as string;
    const limit = Math.min(50, Math.max(1, ((args.limit as number) ?? 10)));
    const params = new URLSearchParams({
      by_city: city,
      per_page: String(limit),
    });
    const url = `${BASE_URL}?${params}`;
    const response = await this.fetchWithRetry(url, {
      method: 'GET',
      headers: { Accept: 'application/json' },
    });
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `Open Brewery DB error: ${response.status} ${errText}` }],
        isError: true,
      };
    }
    const data = (await response.json()) as RawBrewery[];
    const result = { city, count: data.length, breweries: data.map(formatBrewery) };
    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }
}
