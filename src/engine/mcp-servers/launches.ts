/**
 * Launch Library 2 MCP Adapter
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

// Official MCP: None. Native REST adapter for the Launch Library 2 API.
//
// Base URL: https://ll.thespacedevs.com/2.2.0
// Auth: None (public, anonymous access)
// Docs: https://ll.thespacedevs.com/2.2.0/swagger/
// Category: science
// Rate limits: 15 requests/hour for anonymous callers; User-Agent required.

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

const BASE_URL = 'https://ll.thespacedevs.com/2.2.0';
const USER_AGENT = 'epic-ai-chariot/1.0 (https://epic-ai.io)';

export class LaunchesMCPServer extends MCPAdapterBase {
  constructor() {
    super();
  }

  static catalog() {
    return {
      name: 'launches',
      displayName: 'Launch Library 2 — Rocket Launches',
      version: '1.0.0',
      category: 'science',
      keywords: [
        'launches', 'rockets', 'space', 'nasa', 'spacex', 'ula', 'launch library',
        'upcoming launches', 'past launches', 'mission', 'launch pad', 'orbit',
        'falcon 9', 'artemis', 'iss', 'thespacedevs',
      ],
      toolNames: [
        'get_upcoming_launches',
        'get_past_launches',
        'get_launch',
        'search_launches',
      ],
      description: 'Real-time rocket launch data from Launch Library 2 (ll.thespacedevs.com). Retrieve upcoming and past launches, full launch details by ID, and keyword search across all launches.',
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
        name: 'get_upcoming_launches',
        description:
          'Get upcoming rocket launches from Launch Library 2. Returns name, net launch time, status, launch pad name and location, rocket name, and mission description.',
        inputSchema: {
          type: 'object',
          properties: {
            limit: {
              type: 'number',
              description: 'Number of launches to return (default 10)',
            },
          },
        },
      },
      {
        name: 'get_past_launches',
        description:
          'Get past rocket launches from Launch Library 2. Returns name, net launch time, status, launch pad name and location, rocket name, and mission description.',
        inputSchema: {
          type: 'object',
          properties: {
            limit: {
              type: 'number',
              description: 'Number of launches to return (default 10)',
            },
          },
        },
      },
      {
        name: 'get_launch',
        description:
          'Get full details for a specific launch by its Launch Library 2 ID. Returns name, net time, status, pad, rocket, mission, orbit info, video URLs, and mission patches.',
        inputSchema: {
          type: 'object',
          properties: {
            id: {
              type: 'string',
              description: 'Launch Library 2 launch UUID (e.g. "a6ce038e-4d89-4265-b47f-1c6ee5863f84")',
            },
          },
          required: ['id'],
        },
      },
      {
        name: 'search_launches',
        description:
          'Search launches by keyword (rocket name, mission name, agency, etc). Returns matching launches with name, net launch time, status, pad, rocket, and mission description.',
        inputSchema: {
          type: 'object',
          properties: {
            query: {
              type: 'string',
              description: 'Search keyword (e.g. "Falcon 9", "Artemis", "ISS")',
            },
            limit: {
              type: 'number',
              description: 'Number of results to return (default 10)',
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
        case 'get_upcoming_launches':
          return this.getUpcomingLaunches((args.limit as number) ?? 10);
        case 'get_past_launches':
          return this.getPastLaunches((args.limit as number) ?? 10);
        case 'get_launch':
          return this.getLaunch(args.id as string);
        case 'search_launches':
          return this.searchLaunches(args.query as string, (args.limit as number) ?? 10);
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

  private commonHeaders(): Record<string, string> {
    return {
      'Accept': 'application/json',
      'User-Agent': USER_AGENT,
    };
  }

  private async request(path: string): Promise<ToolResult> {
    const url = `${BASE_URL}${path}`;
    const response = await this.fetchWithRetry(url, {
      method: 'GET',
      headers: this.commonHeaders(),
    });
    if (!response.ok) {
      if (response.status === 404) {
        return { content: [{ type: 'text', text: `Not found: ${path}` }], isError: true };
      }
      const errText = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `Launch Library 2 API error: ${response.status} ${errText}` }],
        isError: true,
      };
    }
    const data = await response.json();
    return { content: [{ type: 'text', text: this.truncate(data) }], isError: false };
  }

  private async getUpcomingLaunches(limit: number): Promise<ToolResult> {
    const params = new URLSearchParams({ limit: String(limit), mode: 'list' });
    return this.request(`/launch/upcoming/?${params}`);
  }

  private async getPastLaunches(limit: number): Promise<ToolResult> {
    const params = new URLSearchParams({ limit: String(limit), mode: 'list' });
    return this.request(`/launch/previous/?${params}`);
  }

  private async getLaunch(id: string): Promise<ToolResult> {
    if (!id || typeof id !== 'string') {
      return { content: [{ type: 'text', text: 'get_launch: id is required' }], isError: true };
    }
    return this.request(`/launch/${encodeURIComponent(id)}/`);
  }

  private async searchLaunches(query: string, limit: number): Promise<ToolResult> {
    if (!query || typeof query !== 'string') {
      return { content: [{ type: 'text', text: 'search_launches: query is required' }], isError: true };
    }
    const params = new URLSearchParams({
      search: query,
      limit: String(limit),
      mode: 'list',
    });
    return this.request(`/launch/?${params}`);
  }
}
