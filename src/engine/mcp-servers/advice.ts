/**
 * Advice Slip API MCP Adapter
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

// Upstream confirmed from open-source MCP wrapper (MIT) for the Advice Slip API.
// This file calls the real upstream directly. No proxy or gateway is involved.
//
// Base URL: https://api.adviceslip.com
// Auth: None required — Advice Slip API is public and free with no auth.
// Docs: https://api.adviceslip.com/
// Rate limits: None documented; reasonable use expected.

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

interface AdviceConfig {
  /** Optional base URL override (default: https://api.adviceslip.com) */
  baseUrl?: string;
}

export class AdviceMCPServer extends MCPAdapterBase {
  private readonly baseUrl: string;

  constructor(config: AdviceConfig = {}) {
    super();
    if (!config || typeof config !== 'object') {
      throw new Error('Advice Slip API: configuration object is required');
    }
    this.baseUrl = config.baseUrl ?? 'https://api.adviceslip.com';
  }

  static catalog() {
    return {
      name: 'advice',
      displayName: 'Advice Slip API',
      version: '1.0.0',
      category: 'entertainment',
      keywords: [
        'advice', 'advice slip', 'random advice', 'tips', 'wisdom',
        'life advice', 'motivational', 'search advice', 'advice by id',
        'self-improvement', 'free', 'public api',
      ],
      toolNames: ['random_advice', 'search_advice', 'get_advice'],
      description: 'Advice Slip API: get random advice slips, search for advice by keyword, or retrieve a specific advice slip by numeric ID — all free and unauthenticated.',
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
        name: 'random_advice',
        description: 'Get a random piece of advice from the Advice Slip API.',
        inputSchema: {
          type: 'object',
          properties: {},
        },
      },
      {
        name: 'search_advice',
        description: 'Search for advice slips containing a specific keyword or phrase.',
        inputSchema: {
          type: 'object',
          properties: {
            query: {
              type: 'string',
              description: 'Keyword or phrase to search for within advice text.',
            },
          },
          required: ['query'],
        },
      },
      {
        name: 'get_advice',
        description: 'Get a specific advice slip by its numeric ID.',
        inputSchema: {
          type: 'object',
          properties: {
            id: {
              type: 'number',
              description: 'The numeric ID of the advice slip to retrieve.',
            },
          },
          required: ['id'],
        },
      },
    ];
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<ToolResult> {
    try {
      switch (name) {
        case 'random_advice': return this.randomAdvice();
        case 'search_advice': return this.searchAdvice(args);
        case 'get_advice':    return this.getAdvice(args);
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

  private async request(path: string): Promise<ToolResult> {
    const url = `${this.baseUrl}${path}`;
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

  private async randomAdvice(): Promise<ToolResult> {
    return this.request('/advice');
  }

  private async searchAdvice(args: Record<string, unknown>): Promise<ToolResult> {
    const query = encodeURIComponent(args.query as string);
    return this.request(`/advice/search/${query}`);
  }

  private async getAdvice(args: Record<string, unknown>): Promise<ToolResult> {
    const id = Number(args.id);
    return this.request(`/advice/${id}`);
  }
}
