/**
 * Squiggle AFL MCP Adapter
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

// Upstream REST API: https://api.squiggle.com.au
// Auth: none (public API; ToS requests a descriptive User-Agent)
// Docs: https://api.squiggle.com.au
// Category: sports
// Rate limits: Reasonable use per upstream ToS

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

const BASE_URL = 'https://api.squiggle.com.au';
const USER_AGENT = 'epic-ai-chariot/1.0 (contact: ops@protectnil.com; +https://epicai.com)';

export class SquiggleMCPServer extends MCPAdapterBase {
  private readonly baseUrl: string;

  constructor(config?: { baseUrl?: string }) {
    super();
    if (config === null) { throw new Error('SquiggleMCPServer: configuration object is required when provided'); }
    this.baseUrl = config?.baseUrl || BASE_URL;
  }

  static catalog() {
    return {
      name: 'squiggle',
      displayName: 'Squiggle — AFL Fixture, Results & Tips',
      version: '1.0.0',
      category: 'sports' as const,
      keywords: [
        'squiggle', 'afl', 'australian football', 'afl fixture', 'afl results',
        'afl tips', 'afl ladder', 'afl standings', 'afl teams', 'football',
        'sports', 'tipping', 'footy', 'aussie rules',
      ],
      toolNames: ['teams', 'games', 'standings', 'sources', 'tips', 'ladder'],
      description: 'Squiggle AFL API: retrieve AFL teams, fixtures, results, ladder standings, registered tipping sources, per-game tips, and projected ladders. No authentication required.',
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
        name: 'teams',
        description: 'Get the list of AFL teams, optionally filtered by year.',
        inputSchema: {
          type: 'object',
          properties: {
            year: {
              type: 'number',
              description: 'Season year to filter teams (e.g. 2024). Omit for current season.',
            },
          },
        },
      },
      {
        name: 'games',
        description: 'Get AFL fixture and results. Returns scheduled and completed games for the specified season and/or round.',
        inputSchema: {
          type: 'object',
          properties: {
            year: {
              type: 'number',
              description: 'Season year (e.g. 2024).',
            },
            round: {
              type: 'number',
              description: 'Round number within the season.',
            },
            complete: {
              type: 'boolean',
              description: 'When true, filter to only completed (played) games.',
            },
          },
        },
      },
      {
        name: 'standings',
        description: 'Get the AFL ladder (standings) at a given point in the season.',
        inputSchema: {
          type: 'object',
          properties: {
            year: {
              type: 'number',
              description: 'Season year (e.g. 2024).',
            },
            round: {
              type: 'number',
              description: 'Round number to retrieve standings after.',
            },
          },
        },
      },
      {
        name: 'sources',
        description: 'Get all registered AFL tipping sources. Returns source IDs and names used as input to the tips and ladder tools.',
        inputSchema: {
          type: 'object',
          properties: {},
        },
      },
      {
        name: 'tips',
        description: 'Get AFL tips (predictions) per game per tipping source for a given round.',
        inputSchema: {
          type: 'object',
          properties: {
            year: {
              type: 'number',
              description: 'Season year (e.g. 2024).',
            },
            round: {
              type: 'number',
              description: 'Round number.',
            },
            source: {
              type: 'number',
              description: 'Tipping source ID (from the sources tool).',
            },
          },
        },
      },
      {
        name: 'ladder',
        description: 'Get the projected AFL ladder according to a specific tipping source for a given round.',
        inputSchema: {
          type: 'object',
          properties: {
            year: {
              type: 'number',
              description: 'Season year (e.g. 2024).',
            },
            round: {
              type: 'number',
              description: 'Round number.',
            },
            source: {
              type: 'number',
              description: 'Tipping source ID (from the sources tool).',
            },
          },
        },
      },
    ];
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<ToolResult> {
    try {
      switch (name) {
        case 'teams':     return this.query('teams', args);
        case 'games':     return this.query('games', args);
        case 'standings': return this.query('standings', args);
        case 'sources':   return this.query('sources', {});
        case 'tips':      return this.query('tips', args);
        case 'ladder':    return this.query('ladder', args);
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

  private async query(q: string, args: Record<string, unknown>): Promise<ToolResult> {
    const params = new URLSearchParams({ q });
    for (const [k, v] of Object.entries(args)) {
      if (v == null) continue;
      if (typeof v === 'boolean') {
        params.set(k, v ? '1' : '0');
      } else {
        params.set(k, String(v));
      }
    }

    const url = `${this.baseUrl}?${params.toString()}`;
    const response = await this.fetchWithRetry(url, {
      method: 'GET',
      headers: {
        Accept: 'application/json',
        'User-Agent': USER_AGENT,
      },
    });

    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `API error: ${response.status} ${errText.slice(0, 200)}` }],
        isError: true,
      };
    }

    const data = await response.json();
    return { content: [{ type: 'text', text: this.truncate(data) }], isError: false };
  }
}
