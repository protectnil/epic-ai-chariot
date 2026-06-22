/**
 * Swiss Transport Open Data MCP Adapter
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

// Upstream: Transport Open Data API — https://transport.opendata.ch/v1
// Auth: none (public, free, no key required)
// Docs: https://transport.opendata.ch/docs.html
// Category: travel
// Tools: search_stations, get_connections, get_stationboard

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

const BASE_URL = 'https://transport.opendata.ch/v1';

export class SwissTransportMCPServer extends MCPAdapterBase {
  constructor() {
    super();
  }

  static catalog() {
    return {
      name: 'swisstransport',
      displayName: 'Swiss Transport Open Data',
      version: '1.0.0',
      category: 'travel',
      keywords: [
        'swiss transport', 'switzerland', 'sbb', 'train', 'bus', 'tram',
        'public transport', 'connections', 'stationboard', 'departure',
        'arrival', 'transit', 'opendata', 'zurich', 'bern', 'geneva',
        'lausanne', 'stations', 'schedule',
      ],
      toolNames: ['search_stations', 'get_connections', 'get_stationboard'],
      description: 'Swiss public transport: search stations, look up connections between locations, and get live departure boards — all via the free Transport Open Data API.',
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
        name: 'search_stations',
        description: 'Search for Swiss public transport stations (train, bus, tram) by name query.',
        inputSchema: {
          type: 'object',
          properties: {
            query: {
              type: 'string',
              description: 'Station name to search for (e.g., "Zurich HB", "Bern", "Geneva").',
            },
          },
          required: ['query'],
        },
      },
      {
        name: 'get_connections',
        description: 'Get public transport connections between two Swiss locations. Returns up to the requested number of next departures.',
        inputSchema: {
          type: 'object',
          properties: {
            from: {
              type: 'string',
              description: 'Departure station name or ID.',
            },
            to: {
              type: 'string',
              description: 'Arrival station name or ID.',
            },
            limit: {
              type: 'number',
              description: 'Maximum number of connections to return. Defaults to 4.',
            },
          },
          required: ['from', 'to'],
        },
      },
      {
        name: 'get_stationboard',
        description: 'Get the live departure board for a Swiss public transport station.',
        inputSchema: {
          type: 'object',
          properties: {
            station: {
              type: 'string',
              description: 'Station name or ID to get the departure board for.',
            },
            limit: {
              type: 'number',
              description: 'Maximum number of departures to return. Defaults to 10.',
            },
          },
          required: ['station'],
        },
      },
    ];
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<ToolResult> {
    try {
      switch (name) {
        case 'search_stations':  return this.searchStations(args);
        case 'get_connections':  return this.getConnections(args);
        case 'get_stationboard': return this.getStationboard(args);
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

  private async request(path: string): Promise<ToolResult> {
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

  private async searchStations(args: Record<string, unknown>): Promise<ToolResult> {
    const query = args.query as string;
    const params = new URLSearchParams({ query });
    return this.request(`/locations?${params.toString()}`);
  }

  private async getConnections(args: Record<string, unknown>): Promise<ToolResult> {
    const from = args.from as string;
    const to = args.to as string;
    const limit = String((args.limit as number | undefined) ?? 4);
    const params = new URLSearchParams({ from, to, limit });
    return this.request(`/connections?${params.toString()}`);
  }

  private async getStationboard(args: Record<string, unknown>): Promise<ToolResult> {
    const station = args.station as string;
    const limit = String((args.limit as number | undefined) ?? 10);
    const params = new URLSearchParams({ station, limit });
    return this.request(`/stationboard?${params.toString()}`);
  }
}
