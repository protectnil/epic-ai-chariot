/**
 * Conspiracy Theory MCP Adapter
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

// Base URL: https://api.stupidapis.com/conspiracy-theory/generate
// Auth: X-API-Key header (StupidAPIs key)
// Docs: https://stupidapis.com
// Category: entertainment
// Rate limits: Depends on plan

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

interface ConspiracyTheoryConfig {
  apiKey: string;
  baseUrl?: string;
}

export class ConspiracyTheoryMCPServer extends MCPAdapterBase {
  private readonly apiKey: string;
  private readonly baseUrl: string;

  constructor(config: ConspiracyTheoryConfig) {
    super();
    if (!config || typeof config !== 'object') {
      throw new Error('Conspiracy Theory: configuration object is required');
    }
    for (const __k of (['apiKey'] as Array<keyof typeof config>)) {
      if (config[__k] === undefined || config[__k] === null || (config[__k] as unknown) === '') {
        throw new Error('Conspiracy Theory: ' + __k + ' is required');
      }
    }
    this.apiKey = config.apiKey;
    this.baseUrl = config.baseUrl || 'https://api.stupidapis.com/conspiracy-theory';
  }

  static catalog() {
    return {
      name: 'conspiracy-theory',
      displayName: 'Conspiracy Theory Generator',
      version: '1.0.0',
      category: 'entertainment',
      keywords: [
        'conspiracy', 'conspiracy theory', 'theory', 'humor', 'satire',
        'entertainment', 'generate', 'connect', 'investigate', 'tinfoil',
        'fun', 'creative writing',
      ],
      toolNames: ['conspiracy_theory_generate'],
      description: 'Conspiracy Theory Generator: generate satirical conspiracy theories by connecting two things, investigating an event, or escalating an observation — directly via the StupidAPIs REST API.',
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
        name: 'conspiracy_theory_generate',
        description: 'Generate conspiracy theories. Three modes: connect (link two things), investigate (three theories about one event), complete (escalate an observation).',
        inputSchema: {
          type: 'object',
          properties: {
            mode: {
              type: 'string',
              enum: ['connect', 'investigate', 'complete'],
              description: 'Generation mode: connect (link thing_one and thing_two), investigate (three theories about an event), complete (escalate an observation starting with "I have noticed that...").',
            },
            thing_one: {
              type: 'string',
              description: 'First thing to connect (connect mode only).',
            },
            thing_two: {
              type: 'string',
              description: 'Second thing to connect (connect mode only).',
            },
            event: {
              type: 'string',
              description: 'Event to investigate (investigate mode only).',
            },
            prompt: {
              type: 'string',
              description: '"I have noticed that..." — observation to escalate (complete mode only).',
            },
            depth: {
              type: 'string',
              enum: ['surface', 'deep', 'full_tinfoil'],
              description: 'Depth of the conspiracy theory.',
            },
            confidence: {
              type: 'string',
              enum: ['low', 'medium', 'high', 'suspiciously_high'],
              description: 'Stated confidence level of the theory.',
            },
          },
          required: ['mode'],
        },
      },
    ];
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<ToolResult> {
    try {
      switch (name) {
        case 'conspiracy_theory_generate': return this.generate(args);
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
    for (const [k, v] of Object.entries(args)) {
      if (v !== undefined && v !== null && v !== '') {
        params.set(k, String(v));
      }
    }
    const query = params.toString();
    const url = `${this.baseUrl}/generate${query ? '?' + query : ''}`;
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
