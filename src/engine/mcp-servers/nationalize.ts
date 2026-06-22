/**
 * Nationalize.io MCP Adapter
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

// Base URL: https://api.nationalize.io
// Auth: None — free public API, no key required
// Docs: https://nationalize.io/
// Category: data
// Rate limits: Free tier; batch up to 10 names per request

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

interface NationalizeConfig {
  baseUrl?: string;
}

interface NationalityEntry {
  country_id: string;
  probability: number;
}

interface NationalizeResult {
  count: number;
  name: string;
  country: NationalityEntry[];
}

export class NationalizeMCPServer extends MCPAdapterBase {
  private readonly baseUrl: string;

  constructor(config?: NationalizeConfig) {
    super();
    if (config === null) { throw new Error('NationalizeMCPServer: configuration object is required when provided'); }
    this.baseUrl = config?.baseUrl ?? 'https://api.nationalize.io';
  }

  static catalog() {
    return {
      name: 'nationalize',
      displayName: 'Nationalize.io — Nationality Prediction',
      version: '1.0.0',
      category: 'data',
      keywords: [
        'nationality', 'nationalize', 'name', 'country', 'prediction',
        'demographics', 'first name', 'origin', 'country code', 'probability',
        'batch', 'identity',
      ],
      toolNames: ['predict_nationality', 'batch_predict'],
      description: 'Nationalize.io API: predict the most likely nationalities for a given first name or a batch of up to 10 names, ranked by probability — free and unauthenticated.',
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
        name: 'predict_nationality',
        description:
          'Predict the most likely nationalities for a given first name, ranked by probability. Returns up to 5 country codes with probability scores.',
        inputSchema: {
          type: 'object',
          properties: {
            name: {
              type: 'string',
              description: 'First name to predict nationality for.',
            },
          },
          required: ['name'],
        },
      },
      {
        name: 'batch_predict',
        description:
          'Predict nationalities for multiple first names in a single request (up to 10 names). Returns ranked nationality probabilities for each name.',
        inputSchema: {
          type: 'object',
          properties: {
            names: {
              type: 'array',
              items: { type: 'string' },
              description: 'Array of first names to predict nationality for (maximum 10).',
              maxItems: 10,
            },
          },
          required: ['names'],
        },
      },
    ];
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<ToolResult> {
    try {
      switch (name) {
        case 'predict_nationality': return this.predictNationality(args);
        case 'batch_predict':       return this.batchPredict(args);
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

  private formatResult(result: NationalizeResult): Record<string, unknown> {
    return {
      name: result.name,
      sample_size: result.count,
      nationalities: result.country.map((c) => ({
        country_code: c.country_id,
        probability: c.probability,
      })),
    };
  }

  private async predictNationality(args: Record<string, unknown>): Promise<ToolResult> {
    const name = args.name as string;
    if (!name || typeof name !== 'string' || name.trim().length === 0) {
      return { content: [{ type: 'text', text: 'predict_nationality: name is required and must be a non-empty string' }], isError: true };
    }
    const url = `${this.baseUrl}?name=${encodeURIComponent(name.trim())}`;
    const response = await this.fetchWithRetry(url, {
      method: 'GET',
      headers: { Accept: 'application/json' },
    });
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return { content: [{ type: 'text', text: `API error: ${response.status} ${errText}` }], isError: true };
    }
    const data = (await response.json()) as NationalizeResult;
    return { content: [{ type: 'text', text: this.truncate(this.formatResult(data)) }], isError: false };
  }

  private async batchPredict(args: Record<string, unknown>): Promise<ToolResult> {
    const names = args.names as string[];
    if (!Array.isArray(names) || names.length === 0) {
      return { content: [{ type: 'text', text: 'batch_predict: names must be a non-empty array' }], isError: true };
    }
    if (names.length > 10) {
      return { content: [{ type: 'text', text: 'batch_predict: maximum 10 names per batch request' }], isError: true };
    }
    const params = names.map((n) => `name[]=${encodeURIComponent(String(n).trim())}`).join('&');
    const url = `${this.baseUrl}?${params}`;
    const response = await this.fetchWithRetry(url, {
      method: 'GET',
      headers: { Accept: 'application/json' },
    });
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return { content: [{ type: 'text', text: `API error: ${response.status} ${errText}` }], isError: true };
    }
    const data = (await response.json()) as NationalizeResult | NationalizeResult[];
    const results = Array.isArray(data) ? data : [data];
    return { content: [{ type: 'text', text: this.truncate({ results: results.map((r) => this.formatResult(r)) }) }], isError: false };
  }
}
