/**
 * Mercury Number MCP Adapter
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

// Upstream: StupidAPIs Mercury Number
// Base URL: https://api.stupidapis.com/mercury-number
// Auth: X-API-Key header (api-key)
// Docs: https://stupidapis.com
// Category: entertainment
// Description: Returns a random number justified by Mercury's current astrological position.

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

interface MercuryNumberConfig {
  apiKey: string;
  baseUrl?: string;
}

export class MercuryNumberMCPServer extends MCPAdapterBase {
  private readonly apiKey: string;
  private readonly baseUrl: string;

  constructor(config: MercuryNumberConfig) {
    super();
    if (!config || typeof config !== 'object') {
      throw new Error('Mercury Number: configuration object is required');
    }
    for (const __k of (['apiKey'] as Array<keyof typeof config>)) {
      if (config[__k] === undefined || config[__k] === null || (config[__k] as unknown) === '') {
        throw new Error('Mercury Number: ' + __k + ' is required');
      }
    }
    this.apiKey = config.apiKey;
    this.baseUrl = config.baseUrl || 'https://api.stupidapis.com/mercury-number';
  }

  static catalog() {
    return {
      name: 'mercury-number',
      displayName: 'Mercury Number',
      version: '1.0.0',
      category: 'entertainment',
      keywords: [
        'mercury', 'astrology', 'random', 'number', 'zodiac', 'horoscope',
        'sign', 'aries', 'taurus', 'gemini', 'cancer', 'leo', 'virgo',
        'libra', 'scorpio', 'sagittarius', 'capricorn', 'aquarius', 'pisces',
        'retrograde', 'humor', 'fun',
      ],
      toolNames: ['mercury_number_generate'],
      description: 'Mercury Number: generates a random number cosmically justified by Mercury\'s current astrological position and optionally your sun sign.',
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
        name: 'mercury_number_generate',
        description: 'Your random number, justified by Mercury\'s current position. Mercury is in something. It\'s always in something.',
        inputSchema: {
          type: 'object',
          properties: {
            sign: {
              type: 'string',
              description: 'Your sun sign. Optional. Mercury does not know your sign either.',
              enum: [
                'aries', 'taurus', 'gemini', 'cancer', 'leo', 'virgo',
                'libra', 'scorpio', 'sagittarius', 'capricorn', 'aquarius', 'pisces',
              ],
            },
          },
        },
      },
    ];
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<ToolResult> {
    try {
      switch (name) {
        case 'mercury_number_generate': return this.generateNumber(args);
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

  private async generateNumber(args: Record<string, unknown>): Promise<ToolResult> {
    const params = new URLSearchParams();
    if (args.sign && typeof args.sign === 'string' && args.sign.trim() !== '') {
      params.set('sign', args.sign.trim());
    }
    const query = params.toString();
    const url = query
      ? `${this.baseUrl}/generate?${query}`
      : `${this.baseUrl}/generate`;

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
