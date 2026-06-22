/**
 * Agify REST Adapter — age prediction from first name (agify.io)
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 *
 * Base URL: https://api.agify.io
 * Auth: None required — agify.io public API is free with no auth.
 * Docs: https://agify.io/documentation
 * Rate limits: Free tier — 1,000 requests/day per IP. No API key required.
 */

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

interface AgifyConfig {
  /** Optional base URL override (default: https://api.agify.io) */
  baseUrl?: string;
}

interface AgifyResponse {
  count: number;
  age: number | null;
  name: string;
  country_id?: string;
}

export class AgifyMCPServer extends MCPAdapterBase {
  private readonly baseUrl: string;

  constructor(config?: AgifyConfig) {
    super();
    if (config === null) { throw new Error('AgifyMCPServer: configuration object is required when provided'); }
    this.baseUrl = config?.baseUrl ?? 'https://api.agify.io';
  }

  static catalog() {
    return {
      name: 'agify',
      displayName: 'Agify — Age Prediction by Name',
      version: '1.0.0',
      category: 'data',
      keywords: [
        'agify', 'age', 'name', 'age prediction', 'demographics',
        'first name', 'nationality', 'country', 'statistics', 'people',
      ],
      toolNames: ['predict_age', 'predict_age_country'],
      description: 'Agify.io API: predict the most likely age of a person from their first name, globally or calibrated to a specific country.',
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
        name: 'predict_age',
        description:
          'Predict the most likely age of a person based on their first name, using global data from agify.io.',
        inputSchema: {
          type: 'object',
          properties: {
            name: {
              type: 'string',
              description: 'First name to predict age for.',
            },
          },
          required: ['name'],
        },
      },
      {
        name: 'predict_age_country',
        description:
          'Predict the most likely age of a person based on their first name, calibrated to a specific country.',
        inputSchema: {
          type: 'object',
          properties: {
            name: {
              type: 'string',
              description: 'First name to predict age for.',
            },
            country_code: {
              type: 'string',
              description:
                'ISO 3166-1 alpha-2 country code (e.g. "US", "GB", "DE") to localize the prediction.',
            },
          },
          required: ['name', 'country_code'],
        },
      },
    ];
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<ToolResult> {
    try {
      switch (name) {
        case 'predict_age':
          return this.predictAge(args.name as string);
        case 'predict_age_country':
          return this.predictAge(args.name as string, args.country_code as string);
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

  private async predictAge(name: string, countryCode?: string): Promise<ToolResult> {
    const params = new URLSearchParams({ name });
    if (countryCode) params.set('country_id', countryCode);

    const url = `${this.baseUrl}?${params.toString()}`;
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

    const data = (await response.json()) as AgifyResponse;
    const result: Record<string, unknown> = {
      name: data.name,
      predicted_age: data.age,
      sample_size: data.count,
    };
    if (data.country_id) result.country = data.country_id;

    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }
}
