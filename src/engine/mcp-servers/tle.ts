/**
 * TLE (Two-Line Element) Satellite Tracking MCP Adapter
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

//
// Base URL: https://tle.ivanstanojevic.me/api/tle
// Auth: None required — free public API, no authentication needed.
// Docs: https://tle.ivanstanojevic.me
// Rate limits: None published; fair-use.

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

interface TLEConfig {
  /** Optional base URL override (default: https://tle.ivanstanojevic.me/api/tle) */
  baseUrl?: string;
}

export class TLEMCPServer extends MCPAdapterBase {
  private readonly baseUrl: string;

  constructor(config: TLEConfig = {}) {
    super();
    if (!config || typeof config !== 'object') {
      throw new Error('TLE: configuration object is required');
    }
    this.baseUrl = config.baseUrl ?? 'https://tle.ivanstanojevic.me/api/tle';
  }

  static catalog() {
    return {
      name: 'tle',
      displayName: 'TLE — Satellite Two-Line Element Tracker',
      version: '1.0.0',
      category: 'science',
      keywords: [
        'tle', 'satellite', 'two-line element', 'norad', 'orbital',
        'space', 'tracking', 'ISS', 'Hubble', 'Starlink', 'GPS',
        'epoch', 'orbital mechanics', 'space surveillance', 'catalog',
      ],
      toolNames: ['get_tle', 'search_satellites', 'list_recent'],
      description: 'TLE API: fetch Two-Line Element sets for satellites by NORAD catalog ID, search satellites by name or keyword, and list the most recently launched or updated satellites — free, unauthenticated.',
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
        name: 'get_tle',
        description:
          'Fetch the Two-Line Element (TLE) set for a specific satellite by its NORAD catalog ID. Returns the satellite name, epoch date, and both TLE lines.',
        inputSchema: {
          type: 'object',
          properties: {
            norad_id: {
              type: 'number',
              description:
                'NORAD catalog number for the satellite (e.g. 25544 for the ISS, 20580 for Hubble Space Telescope).',
            },
          },
          required: ['norad_id'],
        },
      },
      {
        name: 'search_satellites',
        description:
          'Search for satellites by name or keyword. Returns matching satellites with their NORAD IDs and TLE data.',
        inputSchema: {
          type: 'object',
          properties: {
            query: {
              type: 'string',
              description: 'Name or keyword to search for (e.g. "ISS", "Starlink", "GPS").',
            },
            limit: {
              type: 'number',
              description: 'Maximum number of results to return. Defaults to 10.',
            },
          },
          required: ['query'],
        },
      },
      {
        name: 'list_recent',
        description:
          'List the most recently launched or updated satellites, sorted by epoch date descending.',
        inputSchema: {
          type: 'object',
          properties: {
            limit: {
              type: 'number',
              description: 'Number of satellites to return. Defaults to 10.',
            },
          },
        },
      },
    ];
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<ToolResult> {
    try {
      switch (name) {
        case 'get_tle':        return this.getTle(args);
        case 'search_satellites': return this.searchSatellites(args);
        case 'list_recent':    return this.listRecent(args);
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

  private async getTle(args: Record<string, unknown>): Promise<ToolResult> {
    const noradId = args.norad_id as number;
    if (typeof noradId !== 'number' || !Number.isFinite(noradId)) {
      return { content: [{ type: 'text', text: 'get_tle: norad_id must be a finite number' }], isError: true };
    }
    const url = `${this.baseUrl}/${encodeURIComponent(String(Math.trunc(noradId)))}`;
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
    const data = await response.json() as Record<string, unknown>;
    return { content: [{ type: 'text', text: this.truncate(this.formatRecord(data)) }], isError: false };
  }

  private async searchSatellites(args: Record<string, unknown>): Promise<ToolResult> {
    const query = args.query as string;
    if (typeof query !== 'string' || query.trim().length === 0) {
      return { content: [{ type: 'text', text: 'search_satellites: query must be a non-empty string' }], isError: true };
    }
    const limit = typeof args.limit === 'number' && Number.isFinite(args.limit) ? Math.trunc(args.limit) : 10;
    const params = new URLSearchParams({
      search: query,
      'page-size': String(limit),
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
    const data = await response.json() as { totalItems?: number; member?: Record<string, unknown>[] };
    const result = {
      total: data.totalItems ?? 0,
      query,
      satellites: (data.member ?? []).map((r) => this.formatRecord(r)),
    };
    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }

  private async listRecent(args: Record<string, unknown>): Promise<ToolResult> {
    const limit = typeof args.limit === 'number' && Number.isFinite(args.limit) ? Math.trunc(args.limit) : 10;
    // The API does not accept 'date' as a sort value; omitting sort returns results
    // ordered by epoch date descending (most-recently-updated first) by default.
    const params = new URLSearchParams({
      'page-size': String(limit),
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
    const data = await response.json() as { totalItems?: number; member?: Record<string, unknown>[] };
    const result = {
      total: data.totalItems ?? 0,
      satellites: (data.member ?? []).map((r) => this.formatRecord(r)),
    };
    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }

  private formatRecord(record: Record<string, unknown>): Record<string, unknown> {
    return {
      norad_id: record['satelliteId'],
      name: record['name'],
      epoch: record['date'],
      line1: record['line1'],
      line2: record['line2'],
    };
  }
}
