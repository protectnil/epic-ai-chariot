/**
 * Radio Browser MCP Adapter
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

// Upstream: Radio Browser API (https://de1.api.radio-browser.info/json)
// Auth: none — free public API, no key required
// Docs: https://api.radio-browser.info/
// Category: media
// Rate limits: none documented; community-operated, fair-use expected

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

const BASE_URL = 'https://de1.api.radio-browser.info/json';

export class RadioMCPServer extends MCPAdapterBase {
  private readonly baseUrl: string;

  constructor(config?: { baseUrl?: string }) {
    super();
    if (config === null) { throw new Error('RadioMCPServer: configuration object is required when provided'); }
    this.baseUrl = config?.baseUrl ?? BASE_URL;
  }

  static catalog() {
    return {
      name: 'radio',
      displayName: 'Radio Browser',
      version: '1.0.0',
      category: 'media',
      keywords: [
        'radio', 'radio browser', 'radio stations', 'streaming', 'internet radio',
        'music', 'genres', 'countries', 'broadcast', 'audio', 'live radio',
        'stations search', 'top stations', 'tags', 'fm', 'am',
      ],
      toolNames: ['search_stations', 'get_top_stations', 'list_countries', 'list_tags'],
      description: 'Radio Browser: search internet radio stations by name, browse top stations globally or by country, list countries with station counts, and explore genres/tags — free public API, no authentication required.',
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
        description: 'Search for radio stations by name. Results are ordered by votes (popularity).',
        inputSchema: {
          type: 'object',
          properties: {
            query: {
              type: 'string',
              description: 'Station name to search for.',
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
        name: 'get_top_stations',
        description: 'Get the most popular radio stations by vote count, optionally filtered by country.',
        inputSchema: {
          type: 'object',
          properties: {
            count: {
              type: 'number',
              description: 'Number of stations to return. Defaults to 10.',
            },
            country: {
              type: 'string',
              description: 'Filter by country name (e.g. "Germany", "United States"). Omit for global results.',
            },
          },
        },
      },
      {
        name: 'list_countries',
        description: 'List countries that have radio stations, sorted by station count descending.',
        inputSchema: {
          type: 'object',
          properties: {},
        },
      },
      {
        name: 'list_tags',
        description: 'List the most common radio station genres and tags by station count.',
        inputSchema: {
          type: 'object',
          properties: {
            limit: {
              type: 'number',
              description: 'Maximum number of tags to return. Defaults to 20.',
            },
          },
        },
      },
    ];
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<ToolResult> {
    try {
      switch (name) {
        case 'search_stations':  return this.searchStations(args);
        case 'get_top_stations': return this.getTopStations(args);
        case 'list_countries':   return this.listCountries();
        case 'list_tags':        return this.listTags(args);
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
    const url = `${this.baseUrl}${path}`;
    const response = await this.fetchWithRetry(url, {
      method: 'GET',
      headers: { Accept: 'application/json', 'User-Agent': 'EpicAI-Chariot/1.0' },
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
    const limit = (args.limit as number | undefined) ?? 10;
    const params = new URLSearchParams({
      limit: String(limit),
      order: 'votes',
      reverse: 'true',
    });
    return this.request(`/stations/byname/${encodeURIComponent(query)}?${params.toString()}`);
  }

  private async getTopStations(args: Record<string, unknown>): Promise<ToolResult> {
    const count = (args.count as number | undefined) ?? 10;
    const country = args.country as string | undefined;

    if (country) {
      const params = new URLSearchParams({
        limit: String(count),
        order: 'votes',
        reverse: 'true',
      });
      return this.request(`/stations/bycountry/${encodeURIComponent(country)}?${params.toString()}`);
    }

    return this.request(`/stations/topvote/${count}`);
  }

  private async listCountries(): Promise<ToolResult> {
    return this.request('/countries');
  }

  private async listTags(args: Record<string, unknown>): Promise<ToolResult> {
    const limit = (args.limit as number | undefined) ?? 20;
    const params = new URLSearchParams({
      order: 'stationcount',
      reverse: 'true',
      limit: String(limit),
    });
    return this.request(`/tags?${params.toString()}`);
  }
}
