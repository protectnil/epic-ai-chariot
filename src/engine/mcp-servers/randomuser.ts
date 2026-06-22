/**
 * Random User API MCP Adapter
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

// Upstream confirmed from open-source MCP wrapper (MIT) for the Random User API.
// This file calls the real upstream directly. No proxy or gateway is involved.
//
// Base URL: https://randomuser.me/api
// Auth: None required — randomuser.me is public and free with no auth.
// Docs: https://randomuser.me/documentation
// Rate limits: None documented; reasonable use expected.

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

interface RandomUserConfig {
  /** Optional base URL override (default: https://randomuser.me/api) */
  baseUrl?: string;
}

export class RandomUserMCPServer extends MCPAdapterBase {
  private readonly baseUrl: string;

  constructor(config: RandomUserConfig = {}) {
    super();
    if (!config || typeof config !== 'object') {
      throw new Error('Random User API: configuration object is required');
    }
    this.baseUrl = config.baseUrl ?? 'https://randomuser.me/api';
  }

  static catalog() {
    return {
      name: 'randomuser',
      displayName: 'Random User API',
      version: '1.0.0',
      category: 'data',
      keywords: [
        'randomuser', 'random user', 'fake user', 'test data', 'mock data',
        'user profile', 'persona', 'name generator', 'address generator',
        'avatar', 'nationality', 'gender', 'seed', 'lorem ipsum people',
      ],
      toolNames: ['generate_users', 'generate_by_gender'],
      description: 'Random User API: generate realistic random user profiles with names, addresses, emails, photos, and more — free and unauthenticated.',
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
        name: 'generate_users',
        description: 'Generate one or more random user profiles with realistic names, addresses, emails, and photos. Optionally filter by nationality.',
        inputSchema: {
          type: 'object',
          properties: {
            count: {
              type: 'number',
              description: 'Number of users to generate (default 1, max 100).',
            },
            nationality: {
              type: 'string',
              description: 'Comma-separated nationality codes to filter by (e.g. "us,gb,au"). Supported: AU, BR, CA, CH, DE, DK, ES, FI, FR, GB, IE, IN, IR, MX, NL, NO, NZ, RS, TR, UA, US.',
            },
          },
        },
      },
      {
        name: 'generate_by_gender',
        description: 'Generate random user profiles filtered to a specific gender.',
        inputSchema: {
          type: 'object',
          properties: {
            gender: {
              type: 'string',
              description: 'Gender to filter by. One of: male, female.',
            },
            count: {
              type: 'number',
              description: 'Number of users to generate (default 1, max 100).',
            },
          },
          required: ['gender'],
        },
      },
    ];
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<ToolResult> {
    try {
      switch (name) {
        case 'generate_users':    return this.generateUsers(args);
        case 'generate_by_gender': return this.generateByGender(args);
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

  private async request(params: URLSearchParams): Promise<ToolResult> {
    const url = `${this.baseUrl}/?${params.toString()}`;
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

  private async generateUsers(args: Record<string, unknown>): Promise<ToolResult> {
    const count = typeof args.count === 'number' ? Math.min(100, Math.max(1, args.count)) : 1;
    const params = new URLSearchParams({ results: String(count) });
    if (args.nationality && typeof args.nationality === 'string') {
      params.set('nat', args.nationality);
    }
    return this.request(params);
  }

  private async generateByGender(args: Record<string, unknown>): Promise<ToolResult> {
    const gender = args.gender as string;
    const count = typeof args.count === 'number' ? Math.min(100, Math.max(1, args.count)) : 1;
    const params = new URLSearchParams({ results: String(count), gender });
    return this.request(params);
  }
}
