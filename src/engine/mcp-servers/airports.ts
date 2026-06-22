/**
 * Airports MCP Adapter
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

// Source analysis used to confirm upstream endpoint shapes; this file calls the
// real upstream directly.
//
// Base URL: https://airportgap.com/api/airports
// Auth: None required — AirportGap API is public and free with no auth.
// Docs: https://airportgap.com/docs
// Rate limits: Fair-use; no published hard limit.

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

interface AirportsConfig {
  /** Optional base URL override (default: https://airportgap.com/api/airports) */
  baseUrl?: string;
}

export class AirportsMCPServer extends MCPAdapterBase {
  private readonly baseUrl: string;

  constructor(config: AirportsConfig = {}) {
    super();
    if (!config || typeof config !== 'object') {
      throw new Error('Airports: configuration object is required');
    }
    this.baseUrl = config.baseUrl ?? 'https://airportgap.com/api/airports';
  }

  static catalog() {
    return {
      name: 'airports',
      displayName: 'Airports — AirportGap',
      version: '1.0.0',
      category: 'travel',
      keywords: [
        'airport', 'airports', 'iata', 'icao', 'aviation', 'flight',
        'travel', 'airline', 'distance', 'great-circle', 'runway',
        'timezone', 'coordinates', 'latitude', 'longitude', 'city',
      ],
      toolNames: ['search_airports', 'get_airport', 'calculate_distance'],
      description: 'AirportGap API: search airports by name, city, or country; look up a single airport by IATA code; and calculate the great-circle distance between two airports — free and unauthenticated.',
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
        name: 'search_airports',
        description: 'Search for airports by name, city, or country. Returns up to 30 results per page.',
        inputSchema: {
          type: 'object',
          properties: {
            query: {
              type: 'string',
              description: 'Airport name, city, or country to search for',
            },
            page: {
              type: 'number',
              description: 'Page number for pagination (default: 1)',
            },
          },
          required: ['query'],
        },
      },
      {
        name: 'get_airport',
        description: 'Get detailed information about an airport by its IATA code (e.g. "JFK", "LHR", "NRT"). Returns name, city, country, coordinates, altitude, and timezone.',
        inputSchema: {
          type: 'object',
          properties: {
            iata_code: {
              type: 'string',
              description: 'Three-letter IATA airport code (e.g. "JFK")',
            },
          },
          required: ['iata_code'],
        },
      },
      {
        name: 'calculate_distance',
        description: 'Calculate the great-circle distance between two airports by their IATA codes. Returns distance in both kilometers and miles.',
        inputSchema: {
          type: 'object',
          properties: {
            from: {
              type: 'string',
              description: 'IATA code of the origin airport (e.g. "JFK")',
            },
            to: {
              type: 'string',
              description: 'IATA code of the destination airport (e.g. "LHR")',
            },
          },
          required: ['from', 'to'],
        },
      },
    ];
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<ToolResult> {
    try {
      switch (name) {
        case 'search_airports':    return this.searchAirports(args);
        case 'get_airport':        return this.getAirport(args);
        case 'calculate_distance': return this.calculateDistance(args);
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

  private async searchAirports(args: Record<string, unknown>): Promise<ToolResult> {
    const query = args.query as string;
    const page = Math.max(1, Number(args.page ?? 1));
    const params = new URLSearchParams({
      q: query,
      'page[number]': String(page),
      'page[size]': '30',
    });
    const url = `${this.baseUrl}?${params.toString()}`;
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
    const data = await response.json() as { data: Array<{ id: string; type: string; attributes: Record<string, unknown> }> };
    const results = data.data.map((r) => this.shapeAirport(r.attributes));
    return {
      content: [{ type: 'text', text: this.truncate({ results, count: results.length, page }) }],
      isError: false,
    };
  }

  private async getAirport(args: Record<string, unknown>): Promise<ToolResult> {
    const code = (args.iata_code as string).trim().toUpperCase();
    const url = `${this.baseUrl}/${encodeURIComponent(code)}`;
    const response = await this.fetchWithRetry(url, {
      method: 'GET',
      headers: { Accept: 'application/json' },
    });
    if (response.status === 404) {
      return {
        content: [{ type: 'text', text: `Airport not found: ${code}` }],
        isError: true,
      };
    }
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `API error: ${response.status} ${errText}` }],
        isError: true,
      };
    }
    const data = await response.json() as { data: { attributes: Record<string, unknown> } };
    return {
      content: [{ type: 'text', text: this.truncate(this.shapeAirport(data.data.attributes)) }],
      isError: false,
    };
  }

  private async calculateDistance(args: Record<string, unknown>): Promise<ToolResult> {
    const fromCode = (args.from as string).trim().toUpperCase();
    const toCode = (args.to as string).trim().toUpperCase();
    const body = new URLSearchParams({ from: fromCode, to: toCode });
    const url = `${this.baseUrl}/distance`;
    const response = await this.fetchWithRetry(url, {
      method: 'POST',
      headers: {
        Accept: 'application/json',
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: body.toString(),
    });
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `API error: ${response.status} ${errText}` }],
        isError: true,
      };
    }
    const data = await response.json() as {
      data: {
        attributes: {
          from_airport: Record<string, unknown>;
          to_airport: Record<string, unknown>;
          kilometers: number;
          miles: number;
        };
      };
    };
    const attrs = data.data.attributes;
    return {
      content: [{
        type: 'text',
        text: this.truncate({
          from: this.shapeAirport(attrs.from_airport),
          to: this.shapeAirport(attrs.to_airport),
          distance_km: attrs.kilometers,
          distance_miles: attrs.miles,
        }),
      }],
      isError: false,
    };
  }

  private shapeAirport(attrs: Record<string, unknown>): Record<string, unknown> {
    return {
      name: attrs['name'],
      city: attrs['city'],
      country: attrs['country'],
      iata: attrs['iata'],
      icao: attrs['icao'],
      latitude: typeof attrs['latitude'] === 'string' ? parseFloat(attrs['latitude']) : attrs['latitude'],
      longitude: typeof attrs['longitude'] === 'string' ? parseFloat(attrs['longitude']) : attrs['longitude'],
      altitude_ft: attrs['altitude'],
      timezone: attrs['timezone'],
    };
  }
}
