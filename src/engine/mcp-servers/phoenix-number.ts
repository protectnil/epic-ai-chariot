/**
 * Phoenix Number API MCP Adapter
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

// Base URL: https://api.stupidapis.com/phoenix-number
// Auth: API key via X-API-Key header
// Docs: https://stupidapis.com
// Category: entertainment
// Rate limits: Depends on plan

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

interface PhoenixNumberConfig {
  apiKey: string;
  baseUrl?: string;
}

export class PhoenixNumberMCPServer extends MCPAdapterBase {
  private readonly apiKey: string;
  private readonly baseUrl: string;

  constructor(config: PhoenixNumberConfig) {
    super();
    if (!config || typeof config !== 'object') {
      throw new Error('Phoenix Number API: configuration object is required');
    }
    for (const __k of (['apiKey'] as Array<keyof typeof config>)) {
      if (config[__k] === undefined || config[__k] === null || (config[__k] as unknown) === '') {
        throw new Error('Phoenix Number API: ' + __k + ' is required');
      }
    }
    this.apiKey = config.apiKey;
    this.baseUrl = config.baseUrl || 'https://api.stupidapis.com/phoenix-number';
  }

  static catalog() {
    return {
      name: 'phoenix-number',
      displayName: 'Phoenix Number API',
      version: '1.0.0',
      category: 'entertainment',
      keywords: [
        'phoenix', 'phoenix number', 'random number', 'temperature', 'arizona',
        'stupidapis', 'random', 'novelty',
      ],
      toolNames: ['phoenix_number_generate'],
      description: 'Phoenix Number API: returns the current temperature in Phoenix, Arizona as a random number. This is not a weather API.',
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
        name: 'phoenix_number_generate',
        description: 'Returns the current temperature in Phoenix, Arizona. As a random number. This is not a weather API.',
        inputSchema: {
          type: 'object',
          properties: {},
        },
      },
    ];
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<ToolResult> {
    try {
      switch (name) {
        case 'phoenix_number_generate': return this.generate(args);
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

  private async request(path: string, args: Record<string, unknown>): Promise<ToolResult> {
    const params = new URLSearchParams();
    for (const [k, v] of Object.entries(args)) {
      if (v !== undefined && v !== null && v !== '') {
        params.set(k, String(v));
      }
    }
    const url = params.toString()
      ? `${this.baseUrl}${path}?${params.toString()}`
      : `${this.baseUrl}${path}`;

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

  private async generate(args: Record<string, unknown>): Promise<ToolResult> {
    return this.request('/generate', args);
  }
}
