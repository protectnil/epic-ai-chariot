/**
 * Ship on Friday MCP Adapter
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

// Official MCP: open/MIT reference used only to confirm upstream endpoint shapes.
// This file calls the real upstream directly. No proxy or gateway is involved.
//
// Base URL: https://api.stupidapis.com/ship-on-friday
// Auth: X-API-Key header (StupidAPIs key required)
// Docs: https://stupidapis.com
// Category: entertainment
// Rate limits: Depends on StupidAPIs plan

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

interface ShipOnFridayConfig {
  apiKey: string;
  /** Optional base URL override (default: https://api.stupidapis.com/ship-on-friday) */
  baseUrl?: string;
}

export class ShipOnFridayMCPServer extends MCPAdapterBase {
  private readonly apiKey: string;
  private readonly baseUrl: string;

  constructor(config: ShipOnFridayConfig) {
    super();
    if (!config || typeof config !== 'object') {
      throw new Error('Ship on Friday: configuration object is required');
    }
    for (const __k of (['apiKey'] as Array<keyof typeof config>)) {
      if (config[__k] === undefined || config[__k] === null || (config[__k] as unknown) === '') {
        throw new Error('Ship on Friday: ' + __k + ' is required');
      }
    }
    this.apiKey = config.apiKey;
    this.baseUrl = config.baseUrl || 'https://api.stupidapis.com/ship-on-friday';
  }

  static catalog() {
    return {
      name: 'ship-on-friday',
      displayName: 'Ship on Friday',
      version: '1.0.0',
      category: 'entertainment',
      keywords: [
        'ship on friday', 'deploy', 'friday deploy', 'devops humor', 'release',
        'risk level', 'on-call', 'stupidapis', 'engineering culture', 'novelty',
      ],
      toolNames: ['ship_on_friday_check'],
      description: 'Ship on Friday API: check whether you should ship on Friday. The answer is always no. Returns a rotating reason, risk level (always catastrophic), suggested day, and on-call sympathy score.',
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
        name: 'ship_on_friday_check',
        description: 'Check whether you should ship on Friday. The answer is always no. Returns a rotating reason, risk level (always catastrophic), suggested day, and on-call sympathy score.',
        inputSchema: {
          type: 'object',
          properties: {
            deploy_type: {
              type: 'string',
              description: 'Type of deploy: hotfix, feature, or refactor',
              enum: ['hotfix', 'feature', 'refactor'],
            },
            team_size: {
              type: 'number',
              description: 'Size of your team',
            },
            is_friday: {
              type: 'boolean',
              description: 'Override Friday detection (auto-detected by default)',
            },
          },
        },
      },
    ];
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<ToolResult> {
    try {
      switch (name) {
        case 'ship_on_friday_check': return this.check(args);
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

  private async check(args: Record<string, unknown>): Promise<ToolResult> {
    const params = new URLSearchParams();
    if (args.deploy_type !== undefined && args.deploy_type !== null && args.deploy_type !== '') {
      params.set('deploy_type', String(args.deploy_type));
    }
    if (args.team_size !== undefined && args.team_size !== null && args.team_size !== '') {
      params.set('team_size', String(args.team_size));
    }
    if (args.is_friday !== undefined && args.is_friday !== null && args.is_friday !== '') {
      params.set('is_friday', String(args.is_friday));
    }
    const qs = params.toString();
    const url = qs ? `${this.baseUrl}/check?${qs}` : `${this.baseUrl}/check`;
    const response = await this.fetchWithRetry(url, {
      method: 'GET',
      headers: {
        Accept: 'application/json',
        'X-API-Key': this.apiKey,
      },
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
}
