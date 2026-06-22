/**
 * ExchangeRate API MCP Adapter
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

// Official REST API: https://open.er-api.com/v6
// Auth: none (free tier, no key required)
// Docs: https://www.exchangerate-api.com/docs/free
// Category: finance
// Rate limits: 1,500 requests/month on the free open tier

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

const BASE_URL = 'https://open.er-api.com/v6';

interface ErApiResponse {
  result: string;
  time_last_update_utc: string;
  time_next_update_utc: string;
  base_code: string;
  rates: Record<string, number>;
  'error-type'?: string;
}

export class ExchangeRateMCPServer extends MCPAdapterBase {
  private readonly baseUrl: string;

  constructor(config?: { baseUrl?: string }) {
    super();
    if (config === null) { throw new Error('ExchangeRateMCPServer: configuration object is required when provided'); }
    this.baseUrl = config?.baseUrl ?? BASE_URL;
  }

  static catalog() {
    return {
      name: 'exchangerate',
      displayName: 'ExchangeRate API',
      version: '1.0.0',
      category: 'finance',
      keywords: [
        'exchange rate', 'currency', 'forex', 'fx', 'conversion',
        'currency pair', 'rates', 'ISO 4217', 'foreign exchange',
        'open.er-api.com', 'free exchange rate',
      ],
      toolNames: ['get_rates', 'get_pair'],
      description: 'ExchangeRate API: fetch live exchange rates for any ISO 4217 base currency and convert between currency pairs — free, no authentication required.',
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
        name: 'get_rates',
        description: 'Get all exchange rates for a given base currency. Returns a map of currency codes to rates relative to the base.',
        inputSchema: {
          type: 'object',
          properties: {
            base_currency: {
              type: 'string',
              description: 'ISO 4217 currency code to use as the base (e.g., "USD", "EUR", "GBP")',
            },
          },
          required: ['base_currency'],
        },
      },
      {
        name: 'get_pair',
        description: 'Get the exchange rate from one currency to another.',
        inputSchema: {
          type: 'object',
          properties: {
            from: {
              type: 'string',
              description: 'Source currency code (e.g., "USD")',
            },
            to: {
              type: 'string',
              description: 'Target currency code (e.g., "JPY")',
            },
          },
          required: ['from', 'to'],
        },
      },
    ];
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<ToolResult> {
    try {
      switch (name) {
        case 'get_rates': return this.getRates(args.base_currency as string);
        case 'get_pair':  return this.getPair(args.from as string, args.to as string);
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

  private async fetchLatest(base: string): Promise<ErApiResponse> {
    const url = `${this.baseUrl}/latest/${encodeURIComponent(base.toUpperCase())}`;
    const response = await this.fetchWithRetry(url, {
      method: 'GET',
      headers: { Accept: 'application/json' },
    });
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      throw new Error(`open.er-api.com error: ${response.status} ${errText}`);
    }
    const data = (await response.json()) as ErApiResponse;
    if (data.result !== 'success') {
      throw new Error(`open.er-api.com error: ${data['error-type'] ?? 'unknown error'}`);
    }
    return data;
  }

  private async getRates(baseCurrency: string): Promise<ToolResult> {
    const data = await this.fetchLatest(baseCurrency);
    const result = {
      base: data.base_code,
      last_updated: data.time_last_update_utc,
      next_update: data.time_next_update_utc,
      rate_count: Object.keys(data.rates).length,
      rates: data.rates,
    };
    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }

  private async getPair(from: string, to: string): Promise<ToolResult> {
    const data = await this.fetchLatest(from);
    const toCode = to.toUpperCase();
    const rate = data.rates[toCode];
    if (rate === undefined) {
      return {
        content: [{ type: 'text', text: `Currency not found: ${toCode}` }],
        isError: true,
      };
    }
    const result = {
      from: data.base_code,
      to: toCode,
      rate,
      last_updated: data.time_last_update_utc,
    };
    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }
}
