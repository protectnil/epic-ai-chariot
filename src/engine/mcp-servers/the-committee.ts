/**
 * The Committee MCP Adapter
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

// Base URL: https://api.stupidapis.com/the-committee
// Auth: X-API-Key header (api-key)
// Docs: https://stupidapis.com
// Category: entertainment
// Rate limits: Depends on plan

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

interface TheCommitteeConfig {
  apiKey: string;
  baseUrl?: string;
}

export class TheCommitteeMCPServer extends MCPAdapterBase {
  private readonly apiKey: string;
  private readonly baseUrl: string;

  constructor(config: TheCommitteeConfig) {
    super();
    if (!config || typeof config !== 'object') {
      throw new Error('The Committee: configuration object is required');
    }
    for (const __k of (['apiKey'] as Array<keyof typeof config>)) {
      if (config[__k] === undefined || config[__k] === null || (config[__k] as unknown) === '') {
        throw new Error('The Committee: ' + __k + ' is required');
      }
    }
    this.apiKey = config.apiKey;
    this.baseUrl = config.baseUrl || 'https://api.stupidapis.com/the-committee';
  }

  static catalog() {
    return {
      name: 'the-committee',
      displayName: 'The Committee',
      version: '1.0.0',
      category: 'entertainment',
      keywords: [
        'committee', 'random', 'random number', 'democracy', 'vote',
        'decision', 'funny', 'humor', 'stupid', 'generator', 'dissent',
      ],
      toolNames: ['the_committee_convene'],
      description: 'The Committee: convene five random number generators that argue for their number and use democracy to determine the result — one member always dissents.',
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
        name: 'the_committee_convene',
        description: 'Convenes five random number generators. Each argues for their number. Democracy determines the result. One member always dissents.',
        inputSchema: {
          type: 'object',
          properties: {
            question: {
              type: 'string',
              description: 'The question before the committee. Optional.',
            },
            urgency: {
              type: 'string',
              enum: ['routine', 'urgent', 'emergency'],
              description: 'Meeting urgency.',
            },
          },
        },
      },
    ];
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<ToolResult> {
    try {
      switch (name) {
        case 'the_committee_convene': return this.convene(args);
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

  private async convene(args: Record<string, unknown>): Promise<ToolResult> {
    const params = new URLSearchParams();
    if (args.question !== undefined && args.question !== null && args.question !== '') {
      params.set('question', String(args.question));
    }
    if (args.urgency !== undefined && args.urgency !== null && args.urgency !== '') {
      params.set('urgency', String(args.urgency));
    }
    const query = params.toString();
    const url = `${this.baseUrl}/convene${query ? '?' + query : ''}`;
    const response = await this.fetchWithRetry(url, {
      method: 'GET',
      headers: {
        'Accept': 'application/json',
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
