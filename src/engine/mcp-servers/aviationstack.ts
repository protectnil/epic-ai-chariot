/**
 * Aviationstack MCP Adapter
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

// Base URL: http://api.aviationstack.com/v1
// Auth: ?access_key= query param (free plan: HTTP only; paid plans support HTTPS)
// Docs: https://aviationstack.com/documentation
// Category: travel
// Rate limits: Free plan — 100 req/mo; paid plans vary

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

interface AviationstackConfig {
  apiKey: string;
  baseUrl?: string;
}

export class AviationstackMCPServer extends MCPAdapterBase {
  private readonly apiKey: string;
  private readonly baseUrl: string;

  constructor(config: AviationstackConfig) {
    super();
    if (!config || typeof config !== 'object') {
      throw new Error('Aviationstack: configuration object is required');
    }
    for (const __k of (['apiKey'] as Array<keyof typeof config>)) {
      if (config[__k] === undefined || config[__k] === null || (config[__k] as unknown) === '') {
        throw new Error('Aviationstack: ' + __k + ' is required');
      }
    }
    this.apiKey = config.apiKey;
    this.baseUrl = config.baseUrl || 'http://api.aviationstack.com/v1';
  }

  static catalog() {
    return {
      name: 'aviationstack',
      displayName: 'Aviationstack — Global Flight & Airport Data',
      version: '1.0.0',
      category: 'travel',
      keywords: [
        'aviationstack', 'aviation', 'flight', 'flights', 'airline', 'airlines',
        'airport', 'airports', 'iata', 'icao', 'real-time', 'live flight',
        'flight status', 'departure', 'arrival', 'routes', 'cities', 'countries',
        'flight tracker', 'aviation data', 'scheduled flights',
      ],
      toolNames: ['flights', 'airports', 'airlines', 'cities', 'countries', 'routes'],
      description: 'Aviationstack: real-time and scheduled flight data, airport and airline directories, city and country reference data, and scheduled route lookups — directly via the Aviationstack REST API.',
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
        name: 'flights',
        description:
          'Real-time and scheduled flights with departure/arrival airport, time, gate, and status. Combine filters to narrow results.',
        inputSchema: {
          type: 'object',
          properties: {
            flight_iata: { type: 'string', description: 'IATA flight number (e.g. "AA100")' },
            flight_icao: { type: 'string', description: 'ICAO flight number' },
            dep_iata: { type: 'string', description: 'Departure airport IATA code (e.g. "JFK")' },
            arr_iata: { type: 'string', description: 'Arrival airport IATA code' },
            airline_iata: { type: 'string', description: 'Airline IATA code' },
            flight_status: {
              type: 'string',
              description: 'Filter by status: scheduled | active | landed | cancelled | incident | diverted',
            },
            limit: { type: 'number', description: 'Results per page, 1–100 (default 25)' },
            offset: { type: 'number', description: '0-based pagination offset' },
          },
        },
      },
      {
        name: 'airports',
        description: 'Airport directory — name, IATA/ICAO codes, country, GPS coordinates, timezone.',
        inputSchema: {
          type: 'object',
          properties: {
            search: { type: 'string', description: 'Free-text search by name or city' },
            iata_code: { type: 'string', description: '3-letter IATA airport code' },
            icao_code: { type: 'string', description: '4-letter ICAO airport code' },
            country_iso2: { type: 'string', description: 'ISO 3166-1 alpha-2 country code' },
            limit: { type: 'number', description: 'Results per page (default 25)' },
            offset: { type: 'number', description: '0-based pagination offset' },
          },
        },
      },
      {
        name: 'airlines',
        description: 'Airline directory — name, IATA/ICAO codes, country, fleet info.',
        inputSchema: {
          type: 'object',
          properties: {
            search: { type: 'string', description: 'Free-text search by airline name' },
            iata_code: { type: 'string', description: '2-letter IATA airline code' },
            icao_code: { type: 'string', description: '3-letter ICAO airline code' },
            limit: { type: 'number', description: 'Results per page (default 25)' },
            offset: { type: 'number', description: '0-based pagination offset' },
          },
        },
      },
      {
        name: 'cities',
        description: 'City and primary-airport database with country and timezone details.',
        inputSchema: {
          type: 'object',
          properties: {
            search: { type: 'string', description: 'Free-text search by city name' },
            iata_code: {
              type: 'string',
              description: 'City IATA code (e.g. "NYC" covers all New York City airports)',
            },
            country_iso2: { type: 'string', description: 'ISO 3166-1 alpha-2 country code' },
            limit: { type: 'number', description: 'Results per page (default 25)' },
          },
        },
      },
      {
        name: 'countries',
        description: 'Country reference data including capital city, currency, and dialling code.',
        inputSchema: {
          type: 'object',
          properties: {
            search: { type: 'string', description: 'Free-text search by country name' },
            country_iso2: { type: 'string', description: 'ISO 3166-1 alpha-2 country code' },
            limit: { type: 'number', description: 'Results per page (default 25)' },
          },
        },
      },
      {
        name: 'routes',
        description: 'Scheduled routes between airports, optionally filtered by airline or flight number.',
        inputSchema: {
          type: 'object',
          properties: {
            dep_iata: { type: 'string', description: 'Departure airport IATA code' },
            arr_iata: { type: 'string', description: 'Arrival airport IATA code' },
            airline_iata: { type: 'string', description: '2-letter IATA airline code' },
            flight_number: { type: 'string', description: 'Flight number (numeric part only, e.g. "100")' },
            limit: { type: 'number', description: 'Results per page (default 25)' },
          },
        },
      },
    ];
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<ToolResult> {
    try {
      switch (name) {
        case 'flights':   return this.request('/flights', args);
        case 'airports':  return this.request('/airports', args);
        case 'airlines':  return this.request('/airlines', args);
        case 'cities':    return this.request('/cities', args);
        case 'countries': return this.request('/countries', args);
        case 'routes':    return this.request('/routes', args);
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

  // ── Private helpers ─────────────────────────────────────────────────────────

  private async request(
    path: string,
    args: Record<string, unknown> = {},
  ): Promise<ToolResult> {
    const params = new URLSearchParams({ access_key: this.apiKey });
    for (const [k, v] of Object.entries(args)) {
      if (v === undefined || v === null) continue;
      params.set(k, String(v));
    }
    const url = `${this.baseUrl}${path}?${params.toString()}`;
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
    const data = await response.json() as { error?: { code?: string; message?: string } };
    if (data.error) {
      return {
        content: [{ type: 'text', text: `Aviationstack error: ${data.error.code ?? 'error'} — ${data.error.message ?? 'unknown'}` }],
        isError: true,
      };
    }
    return { content: [{ type: 'text', text: this.truncate(data) }], isError: false };
  }
}
