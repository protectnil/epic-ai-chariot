/**
 * Genderize MCP Adapter
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

// Upstream: https://api.genderize.io (genderize.io, free, no auth required)
// Docs: https://genderize.io/#docs
// Category: data
// Auth: none — public API, no key required

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

const BASE_URL = 'https://api.genderize.io';

export class GenderizeMCPServer extends MCPAdapterBase {
  constructor() {
    super();
  }

  static catalog() {
    return {
      name: 'genderize',
      displayName: 'Genderize',
      version: '1.0.0',
      category: 'data',
      keywords: [
        'genderize', 'gender', 'gender prediction', 'first name', 'name',
        'demographics', 'probability', 'male', 'female', 'localization',
        'country', 'ISO 3166',
      ],
      toolNames: ['predict_gender', 'predict_gender_country'],
      description: 'Genderize API: predict the most likely gender of a person based on their first name, globally or calibrated to a specific country.',
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
        name: 'predict_gender',
        description:
          'Predict the most likely gender of a person based on their first name, using global data from genderize.io. Returns gender ("male" or "female"), probability (0–1), and sample size.',
        inputSchema: {
          type: 'object',
          properties: {
            name: {
              type: 'string',
              description: 'First name to predict gender for.',
            },
          },
          required: ['name'],
        },
      },
      {
        name: 'predict_gender_country',
        description:
          'Predict the most likely gender of a person based on their first name, calibrated to a specific country.',
        inputSchema: {
          type: 'object',
          properties: {
            name: {
              type: 'string',
              description: 'First name to predict gender for.',
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
        case 'predict_gender':
          return this.predictGender(args.name as string);
        case 'predict_gender_country':
          return this.predictGenderCountry(args.name as string, args.country_code as string);
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

  // ── Private helpers ──────────────────────────────────────────────────────────

  private async predictGender(name: string): Promise<ToolResult> {
    const params = new URLSearchParams({ name });
    return this.request(`?${params}`);
  }

  private async predictGenderCountry(name: string, countryCode: string): Promise<ToolResult> {
    const params = new URLSearchParams({ name, country_id: countryCode });
    return this.request(`?${params}`);
  }

  private async request(query: string): Promise<ToolResult> {
    const url = `${BASE_URL}/${query}`;
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
}
