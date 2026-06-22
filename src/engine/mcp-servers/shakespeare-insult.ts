/**
 * Shakespeare Insult MCP Adapter
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

// Upstream: StupidAPIs shakespeare-insult endpoint
// Base URL: https://api.stupidapis.com/shakespeare-insult
// Auth: X-API-Key header (required)
// Category: entertainment

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

interface ShakespeareInsultConfig {
  apiKey: string;
  baseUrl?: string;
}

export class ShakespeareInsultMCPServer extends MCPAdapterBase {
  private readonly apiKey: string;
  private readonly baseUrl: string;

  constructor(config: ShakespeareInsultConfig) {
    super();
    if (!config || typeof config !== 'object') {
      throw new Error('Shakespeare Insult: configuration object is required');
    }
    for (const __k of (['apiKey'] as Array<keyof typeof config>)) {
      if (config[__k] === undefined || config[__k] === null || (config[__k] as unknown) === '') {
        throw new Error('Shakespeare Insult: ' + __k + ' is required');
      }
    }
    this.apiKey = config.apiKey;
    this.baseUrl = config.baseUrl || 'https://api.stupidapis.com/shakespeare-insult';
  }

  static catalog() {
    return {
      name: 'shakespeare-insult',
      displayName: 'Shakespeare Insult Generator',
      version: '1.0.0',
      category: 'entertainment',
      keywords: [
        'shakespeare', 'insult', 'classical', 'elizabethan', 'humor',
        'comedy', 'roast', 'vintage', 'insult generator', 'bard',
        'wordplay', 'fun', 'creative writing',
      ],
      toolNames: ['shakespeare_insult_generate'],
      description: 'Shakespeare Insult Generator: produce Shakespearean insults in classical or targeted mode, with optional severity, recipient category, and modern English translation.',
      type: 'rest' as const,
      auth: {
        inferredModel: 'header' as const,
        probeState: 'never-probed' as const,
      },
      author: 'protectnil',
    };
  }

  get tools(): ToolDefinition[] {
    return [
      {
        name: 'shakespeare_insult_generate',
        description: 'Generate a Shakespearean insult. Classical mode (no target) uses authentic vocabulary. Targeted mode uses Haiku for bespoke devastation.',
        inputSchema: {
          type: 'object',
          properties: {
            target: {
              type: 'string',
              description: 'Target for a bespoke insult. Omit for classical random.',
            },
            severity: {
              type: 'string',
              enum: ['mild', 'medium', 'devastating', 'nuclear'],
              description: 'Intensity of the insult.',
            },
            recipient: {
              type: 'string',
              enum: ['colleague', 'ex', 'traffic', 'software', 'abstract_concept', 'the_universe'],
              description: 'Category of recipient for the insult.',
            },
            translate: {
              type: 'boolean',
              description: 'Include modern English translation alongside the Shakespearean text.',
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
        case 'shakespeare_insult_generate':
          return this.generateInsult(args);
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

  private async generateInsult(args: Record<string, unknown>): Promise<ToolResult> {
    const params = new URLSearchParams();
    for (const [k, v] of Object.entries(args)) {
      if (v !== undefined && v !== null && v !== '') {
        params.set(k, String(v));
      }
    }
    const qs = params.toString();
    const url = `${this.baseUrl}/generate${qs ? '?' + qs : ''}`;
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
