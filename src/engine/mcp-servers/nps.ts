/**
 * US National Park Service (NPS) MCP Adapter
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

// Base URL: https://developer.nps.gov/api/v1
// Auth: X-Api-Key header (free registration at https://www.nps.gov/subjects/developer/get-started.htm)
// Docs: https://www.nps.gov/subjects/developer/api-documentation.htm
// Category: travel
// Rate limits: free tier — generous daily quota per key

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

const BASE_URL = 'https://developer.nps.gov/api/v1';

interface NpsConfig {
  apiKey: string;
  baseUrl?: string;
}

export class NpsMCPServer extends MCPAdapterBase {
  private readonly apiKey: string;
  private readonly baseUrl: string;

  constructor(config: NpsConfig) {
    super();
    if (!config || typeof config !== 'object') {
      throw new Error('NPS: configuration object is required');
    }
    for (const __k of (['apiKey'] as Array<keyof typeof config>)) {
      if (config[__k] === undefined || config[__k] === null || (config[__k] as unknown) === '') {
        throw new Error('NPS: ' + __k + ' is required');
      }
    }
    this.apiKey = config.apiKey;
    this.baseUrl = config.baseUrl ?? BASE_URL;
  }

  static catalog() {
    return {
      name: 'nps',
      displayName: 'US National Park Service',
      version: '1.0.0',
      category: 'travel' as const,
      keywords: [
        'nps', 'national park', 'park', 'campground', 'camping', 'hiking',
        'park alert', 'closure', 'things to do', 'ranger', 'trail',
        'yosemite', 'grand canyon', 'yellowstone', 'national monument',
        'recreation', 'outdoors', 'nature', 'state', 'visitor center',
      ],
      toolNames: [
        'list_parks',
        'get_park',
        'list_alerts',
        'list_campgrounds',
        'list_things_to_do',
      ],
      description: 'US National Park Service: search parks, fetch full park records, retrieve current alerts and closures, list campgrounds, and discover activities — free API key required.',
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
        name: 'list_parks',
        description:
          'List or search NPS parks. Filter by free-text query, state code (2-letter, comma-separated), or parkCode list. Returns full name, description, designation, states, GPS coordinates, and official URL.',
        inputSchema: {
          type: 'object',
          properties: {
            query: { type: 'string', description: 'Free-text search term' },
            state: { type: 'string', description: '2-letter state code(s), comma-separated (e.g., "CA,NV")' },
            park_code: { type: 'string', description: 'Specific parkCode(s), comma-separated (e.g., "yose,grca")' },
            limit: { type: 'number', description: 'Number of results to return (1–500, default 25)' },
            start: { type: 'number', description: '0-based result offset for pagination (default 0)' },
          },
        },
      },
      {
        name: 'get_park',
        description:
          'Fetch a single park by its 4-letter parkCode. Returns full description, designation, activities, topics, address, contacts, operating hours, entrance fees, and image gallery.',
        inputSchema: {
          type: 'object',
          properties: {
            park_code: { type: 'string', description: '4-letter NPS parkCode (e.g., "yose" for Yosemite, "grca" for Grand Canyon, "yell" for Yellowstone)' },
          },
          required: ['park_code'],
        },
      },
      {
        name: 'list_alerts',
        description:
          'Retrieve current park alerts — closures, road conditions, weather warnings, and danger advisories. Filter by parkCode or state.',
        inputSchema: {
          type: 'object',
          properties: {
            park_code: { type: 'string', description: 'parkCode(s), comma-separated (optional)' },
            state: { type: 'string', description: '2-letter state code (optional)' },
            query: { type: 'string', description: 'Free-text search within alerts (optional)' },
            limit: { type: 'number', description: 'Number of results (1–500, default 50)' },
          },
        },
      },
      {
        name: 'list_campgrounds',
        description:
          'List campgrounds inside a park or state. Returns name, description, RV/tent capacity, amenities, reservation info, wheelchair access, and GPS coordinates.',
        inputSchema: {
          type: 'object',
          properties: {
            park_code: { type: 'string', description: 'parkCode (optional)' },
            state: { type: 'string', description: '2-letter state code (optional)' },
            query: { type: 'string', description: 'Free-text search (optional)' },
            limit: { type: 'number', description: 'Number of results (1–500, default 25)' },
          },
        },
      },
      {
        name: 'list_things_to_do',
        description:
          'Activities recommended by the park service — hikes, ranger programs, scenic drives, and ranger-led activities. Filter by parkCode or state.',
        inputSchema: {
          type: 'object',
          properties: {
            park_code: { type: 'string', description: 'parkCode (optional)' },
            state: { type: 'string', description: '2-letter state code (optional)' },
            query: { type: 'string', description: 'Free-text search (optional)' },
            limit: { type: 'number', description: 'Number of results (1–500, default 25)' },
          },
        },
      },
    ];
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<ToolResult> {
    try {
      switch (name) {
        case 'list_parks':       return this.listParks(args);
        case 'get_park':         return this.getPark(args);
        case 'list_alerts':      return this.listAlerts(args);
        case 'list_campgrounds': return this.listCampgrounds(args);
        case 'list_things_to_do': return this.listThingsToDo(args);
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

  private async npsRequest(path: string, params: URLSearchParams): Promise<ToolResult> {
    const url = `${this.baseUrl}${path}?${params.toString()}`;
    const response = await this.fetchWithRetry(url, {
      method: 'GET',
      headers: {
        'X-Api-Key': this.apiKey,
        'Accept': 'application/json',
      },
    });
    if (response.status === 401 || response.status === 403) {
      return {
        content: [{ type: 'text', text: 'NPS: unauthorized — check the API key' }],
        isError: true,
      };
    }
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `NPS API error: ${response.status} ${errText.slice(0, 200)}` }],
        isError: true,
      };
    }
    const data = await response.json();
    return { content: [{ type: 'text', text: this.truncate(data) }], isError: false };
  }

  private clamp(val: unknown, min: number, max: number, defaultVal: number): number {
    const n = typeof val === 'number' ? val : defaultVal;
    return Math.min(max, Math.max(min, n));
  }

  private async listParks(args: Record<string, unknown>): Promise<ToolResult> {
    const params = new URLSearchParams({
      limit: String(this.clamp(args.limit, 1, 500, 25)),
      start: String(typeof args.start === 'number' ? args.start : 0),
    });
    if (args.query)     params.set('q',         String(args.query));
    if (args.state)     params.set('stateCode',  String(args.state).toUpperCase());
    if (args.park_code) params.set('parkCode',   String(args.park_code).toLowerCase());
    return this.npsRequest('/parks', params);
  }

  private async getPark(args: Record<string, unknown>): Promise<ToolResult> {
    const parkCode = args.park_code;
    if (typeof parkCode !== 'string' || !parkCode.trim()) {
      return {
        content: [{ type: 'text', text: 'get_park: required argument "park_code" is missing or empty (e.g., "yose", "grca")' }],
        isError: true,
      };
    }
    const params = new URLSearchParams({ parkCode: parkCode.toLowerCase(), limit: '1' });
    return this.npsRequest('/parks', params);
  }

  private async listAlerts(args: Record<string, unknown>): Promise<ToolResult> {
    const params = new URLSearchParams({ limit: String(this.clamp(args.limit, 1, 500, 50)) });
    if (args.park_code) params.set('parkCode',  String(args.park_code).toLowerCase());
    if (args.state)     params.set('stateCode', String(args.state).toUpperCase());
    if (args.query)     params.set('q',          String(args.query));
    return this.npsRequest('/alerts', params);
  }

  private async listCampgrounds(args: Record<string, unknown>): Promise<ToolResult> {
    const params = new URLSearchParams({ limit: String(this.clamp(args.limit, 1, 500, 25)) });
    if (args.park_code) params.set('parkCode',  String(args.park_code).toLowerCase());
    if (args.state)     params.set('stateCode', String(args.state).toUpperCase());
    if (args.query)     params.set('q',          String(args.query));
    return this.npsRequest('/campgrounds', params);
  }

  private async listThingsToDo(args: Record<string, unknown>): Promise<ToolResult> {
    const params = new URLSearchParams({ limit: String(this.clamp(args.limit, 1, 500, 25)) });
    if (args.park_code) params.set('parkCode',  String(args.park_code).toLowerCase());
    if (args.state)     params.set('stateCode', String(args.state).toUpperCase());
    if (args.query)     params.set('q',          String(args.query));
    return this.npsRequest('/thingstodo', params);
  }
}
