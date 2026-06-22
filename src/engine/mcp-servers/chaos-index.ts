/**
 * Chaos Index API MCP Adapter
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

// Upstream confirmed from open-source MCP wrapper (MIT) for the Chaos Index API.
// This file calls the real upstream directly. No proxy or gateway is involved.
//
// Base URL: https://api.stupidapis.com
// Auth: X-API-Key header required
// Docs: https://stupidapis.com/
// Rate limits: None documented; reasonable use expected.

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

interface ChaosIndexConfig {
  apiKey: string;
  /** Optional base URL override (default: https://api.stupidapis.com) */
  baseUrl?: string;
}

export class ChaosIndexMCPServer extends MCPAdapterBase {
  private readonly apiKey: string;
  private readonly baseUrl: string;

  constructor(config: ChaosIndexConfig) {
    super();
    if (!config || typeof config !== 'object') {
      throw new Error('Chaos Index API: configuration object is required');
    }
    for (const __k of (['apiKey'] as Array<keyof typeof config>)) {
      if (config[__k] === undefined || config[__k] === null || (config[__k] as unknown) === '') {
        throw new Error('Chaos Index API: ' + __k + ' is required');
      }
    }
    this.apiKey = config.apiKey;
    this.baseUrl = config.baseUrl ?? 'https://api.stupidapis.com';
  }

  static catalog() {
    return {
      name: 'chaos-index',
      displayName: 'Chaos Index API',
      version: '1.0.0',
      category: 'entertainment',
      keywords: [
        'chaos', 'chaos index', 'bitcoin', 'iss', 'earthquake', 'lunar phase',
        'temperature', 'score', 'combined metrics', 'stupidapis',
      ],
      toolNames: ['chaos_index_calculate'],
      description: 'Chaos Index API: combines Bitcoin price, ISS coordinates, city temperatures, earthquake magnitude, and lunar phase into a single chaos score.',
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
        name: 'chaos_index_calculate',
        description: 'Combines Bitcoin price, ISS coordinates, city temperatures, earthquake magnitude, and lunar phase into a single chaos score.',
        inputSchema: {
          type: 'object',
          properties: {},
          required: [],
        },
      },
    ];
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<ToolResult> {
    try {
      switch (name) {
        case 'chaos_index_calculate': return this.calculateChaosIndex();
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

  private async calculateChaosIndex(): Promise<ToolResult> {
    return this.request('/chaos-index/calculate');
  }
}
