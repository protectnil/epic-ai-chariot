/**
 * CityBik.es MCP Adapter
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

// Base URL: https://api.citybik.es/v2
// Auth: None — free public API, no key required
// Docs: https://api.citybik.es/v2/
// Category: transportation
// Rate limits: None published; reasonable use expected

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

const BASE_URL = 'https://api.citybik.es/v2';

export class CitybikesServer extends MCPAdapterBase {
  constructor() {
    super();
  }

  static catalog() {
    return {
      name: 'citybikes',
      displayName: 'CityBik.es Bike Sharing',
      version: '1.0.0',
      category: 'transportation',
      keywords: [
        'citybikes', 'bike sharing', 'bikeshare', 'bicycle', 'cycling',
        'stations', 'docked bikes', 'free bikes', 'bike rental',
        'urban mobility', 'transit', 'networks',
      ],
      toolNames: ['list_networks', 'get_network', 'search_networks'],
      description: 'CityBik.es API: list all bike-sharing networks worldwide, get live station availability for a specific network, and search networks by city or country.',
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
        name: 'list_networks',
        description:
          'List all bike-sharing networks worldwide. Returns name, id, and location (city, country, lat/lng) for each network.',
        inputSchema: {
          type: 'object',
          properties: {},
        },
      },
      {
        name: 'get_network',
        description:
          'Get live station data for a bike-sharing network by its id (e.g. "citi-bike-nyc"). Returns network name and all stations with bike availability, empty slots, and coordinates.',
        inputSchema: {
          type: 'object',
          properties: {
            id: {
              type: 'string',
              description: 'Network id (e.g. "citi-bike-nyc", "velib" for Paris, "nextbike-berlin")',
            },
          },
          required: ['id'],
        },
      },
      {
        name: 'search_networks',
        description:
          'Search bike-sharing networks by city or country name. Returns matching networks with location info.',
        inputSchema: {
          type: 'object',
          properties: {
            query: {
              type: 'string',
              description: 'City or country name to search for (e.g. "New York", "France", "Berlin")',
            },
          },
          required: ['query'],
        },
      },
    ];
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<ToolResult> {
    try {
      switch (name) {
        case 'list_networks':   return this.listNetworks();
        case 'get_network':     return this.getNetwork(args.id as string);
        case 'search_networks': return this.searchNetworks(args.query as string);
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

  private async get(path: string): Promise<ToolResult> {
    const url = `${BASE_URL}${path}`;
    const response = await this.fetchWithRetry(url, {
      method: 'GET',
      headers: { Accept: 'application/json' },
    });
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `API error: ${response.status} ${errText}` }],
        isError: true,
      };
    }
    const data = await response.json();
    return { content: [{ type: 'text', text: this.truncate(data) }], isError: false };
  }

  private async listNetworks(): Promise<ToolResult> {
    const url = `${BASE_URL}/networks`;
    const response = await this.fetchWithRetry(url, {
      method: 'GET',
      headers: { Accept: 'application/json' },
    });
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `API error: ${response.status} ${errText}` }],
        isError: true,
      };
    }
    const data = await response.json() as { networks: Array<{
      id: string; name: string;
      location: { city: string; country: string; latitude: number; longitude: number };
    }> };
    const networks = data.networks.map((n) => ({
      id: n.id,
      name: n.name,
      city: n.location.city,
      country: n.location.country,
      latitude: n.location.latitude,
      longitude: n.location.longitude,
    }));
    return {
      content: [{ type: 'text', text: this.truncate({ count: networks.length, networks }) }],
      isError: false,
    };
  }

  private async getNetwork(id: string): Promise<ToolResult> {
    if (!id) {
      return { content: [{ type: 'text', text: 'get_network: id is required' }], isError: true };
    }
    const url = `${BASE_URL}/networks/${encodeURIComponent(id)}`;
    const response = await this.fetchWithRetry(url, {
      method: 'GET',
      headers: { Accept: 'application/json' },
    });
    if (response.status === 404) {
      return { content: [{ type: 'text', text: `Network not found: ${id}` }], isError: true };
    }
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `API error: ${response.status} ${errText}` }],
        isError: true,
      };
    }
    const data = await response.json() as { network: {
      id: string; name: string;
      location: { city: string; country: string; latitude: number; longitude: number };
      stations: Array<{
        id: string; name: string; free_bikes: number; empty_slots: number;
        latitude: number; longitude: number; timestamp: string;
      }>;
    } };
    const net = data.network;
    const result = {
      id: net.id,
      name: net.name,
      city: net.location.city,
      country: net.location.country,
      station_count: net.stations.length,
      stations: net.stations.map((s) => ({
        id: s.id,
        name: s.name,
        free_bikes: s.free_bikes,
        empty_slots: s.empty_slots,
        latitude: s.latitude,
        longitude: s.longitude,
        timestamp: s.timestamp,
      })),
    };
    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }

  private async searchNetworks(query: string): Promise<ToolResult> {
    if (!query) {
      return { content: [{ type: 'text', text: 'search_networks: query is required' }], isError: true };
    }
    const url = `${BASE_URL}/networks`;
    const response = await this.fetchWithRetry(url, {
      method: 'GET',
      headers: { Accept: 'application/json' },
    });
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `API error: ${response.status} ${errText}` }],
        isError: true,
      };
    }
    const data = await response.json() as { networks: Array<{
      id: string; name: string;
      location: { city: string; country: string; latitude: number; longitude: number };
    }> };
    const q = query.toLowerCase();
    const matches = data.networks
      .filter(
        (n) =>
          n.location.city.toLowerCase().includes(q) ||
          n.location.country.toLowerCase().includes(q) ||
          n.name.toLowerCase().includes(q),
      )
      .map((n) => ({
        id: n.id,
        name: n.name,
        city: n.location.city,
        country: n.location.country,
        latitude: n.location.latitude,
        longitude: n.location.longitude,
      }));
    return {
      content: [{ type: 'text', text: this.truncate({ count: matches.length, networks: matches }) }],
      isError: false,
    };
  }
}
