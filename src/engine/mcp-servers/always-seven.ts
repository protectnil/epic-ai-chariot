/**
 * Always Seven MCP Adapter
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

// Official MCP: open/MIT reference used only to confirm upstream endpoint shapes.
// This file calls the real upstream directly. No proxy or gateway is involved.
//
// Base URL: https://api.stupidapis.com/always-seven
// Auth: X-API-Key header (StupidAPIs key required)
// Docs: https://stupidapis.com
// Category: entertainment
// Rate limits: Depends on StupidAPIs plan

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

interface AlwaysSevenConfig {
  apiKey: string;
  /** Optional base URL override (default: https://api.stupidapis.com/always-seven) */
  baseUrl?: string;
}

export class AlwaysSevenMCPServer extends MCPAdapterBase {
  private readonly apiKey: string;
  private readonly baseUrl: string;

  constructor(config: AlwaysSevenConfig) {
    super();
    if (!config || typeof config !== 'object') {
      throw new Error('Always Seven: configuration object is required');
    }
    for (const __k of (['apiKey'] as Array<keyof typeof config>)) {
      if (config[__k] === undefined || config[__k] === null || (config[__k] as unknown) === '') {
        throw new Error('Always Seven: ' + __k + ' is required');
      }
    }
    this.apiKey = config.apiKey;
    this.baseUrl = config.baseUrl || 'https://api.stupidapis.com/always-seven';
  }

  static catalog() {
    return {
      name: 'always-seven',
      displayName: 'Always Seven',
      version: '1.0.0',
      category: 'entertainment',
      keywords: [
        'always seven', 'random number', 'seven', '7', 'humor', 'joke',
        'stupidapis', 'random', 'number generator', 'novelty',
      ],
      toolNames: ['always_seven_generate'],
      description: 'Always Seven API: returns a random number between 1 and 10. The number is 7. It is always 7.',
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
        name: 'always_seven_generate',
        description: 'Returns a random number between 1 and 10. The number is 7. It is always 7.',
        inputSchema: {
          type: 'object',
          properties: {
            question: {
              type: 'string',
              description: 'Your question. It will not affect the number.',
            },
            force: {
              type: 'number',
              description: 'Attempt to force a different number (1-10). It will not work.',
            },
          },
        },
      },
    ];
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<ToolResult> {
    try {
      switch (name) {
        case 'always_seven_generate': return this.generate(args);
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

  private async generate(args: Record<string, unknown>): Promise<ToolResult> {
    const params = new URLSearchParams();
    if (args.question !== undefined && args.question !== null && args.question !== '') {
      params.set('question', String(args.question));
    }
    if (args.force !== undefined && args.force !== null && args.force !== '') {
      params.set('force', String(args.force));
    }
    const qs = params.toString();
    const url = qs ? `${this.baseUrl}/generate?${qs}` : `${this.baseUrl}/generate`;
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
