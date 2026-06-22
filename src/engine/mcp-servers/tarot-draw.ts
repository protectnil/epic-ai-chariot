/**
 * Tarot Draw MCP Adapter
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

// Base URL: https://api.stupidapis.com/tarot-draw
// Auth: X-API-Key header (required)
// Docs: https://stupidapis.com
// Category: entertainment
// Rate limits: Depends on plan

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

interface TarotDrawConfig {
  apiKey: string;
  baseUrl?: string;
}

export class TarotDrawMCPServer extends MCPAdapterBase {
  private readonly apiKey: string;
  private readonly baseUrl: string;

  constructor(config: TarotDrawConfig) {
    super();
    if (!config || typeof config !== 'object') {
      throw new Error('Tarot Draw: configuration object is required');
    }
    for (const __k of (['apiKey'] as Array<keyof typeof config>)) {
      if (config[__k] === undefined || config[__k] === null || (config[__k] as unknown) === '') {
        throw new Error('Tarot Draw: ' + __k + ' is required');
      }
    }
    this.apiKey = config.apiKey;
    this.baseUrl = config.baseUrl || 'https://api.stupidapis.com/tarot-draw';
  }

  static catalog() {
    return {
      name: 'tarot-draw',
      displayName: 'Tarot Draw',
      version: '1.0.0',
      category: 'entertainment',
      keywords: [
        'tarot', 'tarot card', 'card draw', 'divination', 'fortune',
        'spread', 'past present future', 'single card', 'mystical',
        'reading', 'oracle',
      ],
      toolNames: ['tarot_draw_pull'],
      description: 'Tarot Draw: draw one or more tarot cards from the 78-card deck with optional question context and spread type.',
      type: 'rest' as const,
      auth: {
        inferredModel: 'header-apikey' as const,
        probeState: 'never-probed' as const,
      },
      author: 'protectnil',
    };
  }

  get tools(): ToolDefinition[] {
    return [
      {
        name: 'tarot_draw_pull',
        description: 'Draw a tarot card from the 78-card deck. Interprets it for your situation. Accuracy not guaranteed. Refunds not available.',
        inputSchema: {
          type: 'object',
          properties: {
            question: {
              type: 'string',
              description: 'Your question for the cards. Optional. The cards do not care.',
            },
            spread: {
              type: 'string',
              enum: ['single', 'past_present_future'],
              description: 'Card spread type',
            },
          },
        },
      },
    ];
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<ToolResult> {
    try {
      switch (name) {
        case 'tarot_draw_pull': return this.pull(args);
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

  private async pull(args: Record<string, unknown>): Promise<ToolResult> {
    const params = new URLSearchParams();
    if (args.question !== undefined && args.question !== null && args.question !== '') {
      params.set('question', String(args.question));
    }
    if (args.spread !== undefined && args.spread !== null && args.spread !== '') {
      params.set('spread', String(args.spread));
    }
    const qs = params.toString();
    const url = `${this.baseUrl}/pull${qs ? '?' + qs : ''}`;
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
