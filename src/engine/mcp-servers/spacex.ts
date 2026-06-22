/**
 * SpaceX MCP Adapter
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

// Base URL: https://api.spacexdata.com/v4
// Auth: None — public, no authentication required
// Docs: https://github.com/r-spacex/SpaceX-API/tree/master/docs
// Category: data
// Rate limits: No documented rate limits; public API

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

const BASE_URL = 'https://api.spacexdata.com/v4';

export class SpaceXMCPServer extends MCPAdapterBase {
  constructor() {
    super();
  }

  static catalog() {
    return {
      name: 'spacex',
      displayName: 'SpaceX API',
      version: '1.0.0',
      category: 'data' as const,
      keywords: [
        'spacex', 'space', 'launch', 'rocket', 'crew', 'starlink',
        'satellite', 'astronaut', 'falcon', 'dragon', 'aerospace',
        'spacecraft', 'orbit', 'nasa', 'launch schedule', 'space travel',
      ],
      toolNames: [
        'get_latest_launch',
        'get_next_launch',
        'get_past_launches',
        'get_rockets',
        'get_crew',
        'get_starlink',
      ],
      description: 'SpaceX API: retrieve real-time SpaceX launch data, rocket information, crew members, and Starlink satellite info directly from the official SpaceX data API.',
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
        name: 'get_latest_launch',
        description: 'Get the most recent SpaceX launch. Returns launch name, date, success status, details, rocket id, and media links (webcast, article, wikipedia).',
        inputSchema: {
          type: 'object',
          properties: {},
          required: [],
        },
      },
      {
        name: 'get_next_launch',
        description: 'Get the next upcoming SpaceX launch. Returns launch name, date, details, and rocket id.',
        inputSchema: {
          type: 'object',
          properties: {},
          required: [],
        },
      },
      {
        name: 'get_past_launches',
        description: 'Get recent past SpaceX launches sorted by date descending. Returns name, date, success status, and details for each launch.',
        inputSchema: {
          type: 'object',
          properties: {
            limit: {
              type: 'number',
              description: 'Number of launches to return (default 10)',
            },
          },
          required: [],
        },
      },
      {
        name: 'get_rockets',
        description: 'List all SpaceX rockets. Returns name, type, active status, stages, boosters, cost per launch, success rate, first flight date, and description.',
        inputSchema: {
          type: 'object',
          properties: {},
          required: [],
        },
      },
      {
        name: 'get_crew',
        description: 'List SpaceX crew members. Returns name, agency, status, wikipedia link, and image URL for each crew member.',
        inputSchema: {
          type: 'object',
          properties: {},
          required: [],
        },
      },
      {
        name: 'get_starlink',
        description: 'Get Starlink satellite info sorted by most recently launched. Returns spaceTrack data including object name, launch date, and decay date.',
        inputSchema: {
          type: 'object',
          properties: {
            limit: {
              type: 'number',
              description: 'Number of satellites to return (default 20)',
            },
          },
          required: [],
        },
      },
    ];
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<ToolResult> {
    try {
      switch (name) {
        case 'get_latest_launch': return this.getLatestLaunch();
        case 'get_next_launch':   return this.getNextLaunch();
        case 'get_past_launches': return this.getPastLaunches((args.limit as number) ?? 10);
        case 'get_rockets':       return this.getRockets();
        case 'get_crew':          return this.getCrew();
        case 'get_starlink':      return this.getStarlink((args.limit as number) ?? 20);
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
    const response = await this.fetchWithRetry(`${BASE_URL}${path}`, {
      method: 'GET',
      headers: { Accept: 'application/json' },
    });
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `SpaceX API error: ${response.status} ${errText}` }],
        isError: true,
      };
    }
    const data = await response.json();
    return { content: [{ type: 'text', text: this.truncate(data) }], isError: false };
  }

  private async post(path: string, body: unknown): Promise<ToolResult> {
    const response = await this.fetchWithRetry(`${BASE_URL}${path}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
      body: JSON.stringify(body),
    });
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `SpaceX API error: ${response.status} ${errText}` }],
        isError: true,
      };
    }
    const data = await response.json();
    return { content: [{ type: 'text', text: this.truncate(data) }], isError: false };
  }

  private async getLatestLaunch(): Promise<ToolResult> {
    return this.get('/launches/latest');
  }

  private async getNextLaunch(): Promise<ToolResult> {
    return this.get('/launches/next');
  }

  private async getPastLaunches(limit: number): Promise<ToolResult> {
    return this.post('/launches/query', {
      query: {},
      options: {
        sort: { date_utc: 'desc' },
        limit,
      },
    });
  }

  private async getRockets(): Promise<ToolResult> {
    return this.get('/rockets');
  }

  private async getCrew(): Promise<ToolResult> {
    return this.get('/crew');
  }

  private async getStarlink(limit: number): Promise<ToolResult> {
    return this.post('/starlink/query', {
      query: {},
      options: {
        limit,
        sort: { launch: 'desc' },
      },
    });
  }
}
