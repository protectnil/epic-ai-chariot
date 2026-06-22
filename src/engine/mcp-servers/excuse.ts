/**
 * Excuse Generator MCP Adapter
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

// Upstream: StupidAPIs — https://api.stupidapis.com/excuse/generate
// Auth: X-API-Key header (required)
// Category: entertainment
// Docs: https://stupidapis.com

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

interface ExcuseConfig {
  apiKey: string;
  baseUrl?: string;
}

export class ExcuseMCPServer extends MCPAdapterBase {
  private readonly apiKey: string;
  private readonly baseUrl: string;

  constructor(config: ExcuseConfig) {
    super();
    if (!config || typeof config !== 'object') {
      throw new Error('Excuse Generator: configuration object is required');
    }
    for (const __k of (['apiKey'] as Array<keyof typeof config>)) {
      if (config[__k] === undefined || config[__k] === null || (config[__k] as unknown) === '') {
        throw new Error('Excuse Generator: ' + __k + ' is required');
      }
    }
    this.apiKey = config.apiKey;
    this.baseUrl = config.baseUrl || 'https://api.stupidapis.com';
  }

  static catalog() {
    return {
      name: 'excuse',
      displayName: 'Excuse Generator',
      version: '1.0.0',
      category: 'entertainment',
      keywords: [
        'excuse', 'excuses', 'late', 'missed deadline', 'ghosted',
        'funny', 'humor', 'creative writing', 'generator', 'plausible deniability',
        'boss', 'friend', 'date', 'recruiter', 'professor', 'client',
      ],
      toolNames: ['excuse_generate'],
      description: 'Excuse Generator: generate a tailored excuse for being late, missing a deadline, or ghosting someone — with configurable audience, quality level, and usage history.',
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
        name: 'excuse_generate',
        description: 'Generate an excuse for being late, missing a deadline, or ghosting someone.',
        inputSchema: {
          type: 'object',
          properties: {
            situation: {
              type: 'string',
              enum: ['late', 'missed_deadline', 'ghosted'],
              description: 'The situation that requires an excuse.',
            },
            audience: {
              type: 'string',
              enum: ['boss', 'friend', 'date', 'recruiter', 'professor', 'client'],
              description: 'The person the excuse is directed at.',
            },
            excuse_quality: {
              type: 'string',
              enum: ['implausible', 'plausible', 'airtight', 'medical'],
              description: 'The believability tier of the excuse.',
            },
            times_used_before: {
              type: 'number',
              description: 'How many times you have used this excuse before.',
            },
          },
          required: ['situation'],
        },
      },
    ];
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<ToolResult> {
    try {
      switch (name) {
        case 'excuse_generate':
          return this.generateExcuse(args);
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

  private async generateExcuse(args: Record<string, unknown>): Promise<ToolResult> {
    const params = new URLSearchParams();
    for (const [k, v] of Object.entries(args)) {
      if (v !== undefined && v !== null && v !== '') {
        params.set(k, String(v));
      }
    }
    const path = '/excuse/generate';
    const qs = params.toString();
    const url = `${this.baseUrl}${path}${qs ? '?' + qs : ''}`;

    const response = await this.fetchWithRetry(url, {
      method: 'GET',
      headers: {
        'X-API-Key': this.apiKey,
        Accept: 'application/json',
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
