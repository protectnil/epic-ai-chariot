/**
 * Exchange Rate MCP Adapter (Frankfurter API)
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

// Base URL: https://api.frankfurter.app
// Auth: None (free public API, no key required)
// Docs: https://www.frankfurter.app/docs/
// Category: finance
// Rate limits: None documented; fair-use expected

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

const BASE_URL = 'https://api.frankfurter.app';

export class ExchangeMCPServer extends MCPAdapterBase {
  constructor() {
    super();
  }

  static catalog() {
    return {
      name: 'exchange',
      displayName: 'Exchange Rates (Frankfurter)',
      version: '1.0.0',
      category: 'finance',
      keywords: [
        'exchange rate', 'currency', 'forex', 'fx', 'foreign exchange',
        'convert', 'conversion', 'historical rate', 'EUR', 'USD', 'GBP',
        'Frankfurter', 'ECB', 'European Central Bank',
      ],
      toolNames: ['get_rate', 'convert', 'get_historical_rate', 'get_currencies'],
      description: 'Frankfurter Exchange Rate API: fetch current and historical currency exchange rates, convert amounts between currencies, and list all supported currency codes — free and unauthenticated.',
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
        name: 'get_rate',
        description: 'Get the current exchange rate between two currencies (e.g., USD to EUR).',
        inputSchema: {
          type: 'object',
          properties: {
            from: {
              type: 'string',
              description: 'Source currency code (e.g., USD, EUR, GBP)',
            },
            to: {
              type: 'string',
              description: 'Target currency code (e.g., EUR, JPY, CHF)',
            },
          },
          required: ['from', 'to'],
        },
      },
      {
        name: 'convert',
        description: 'Convert an amount from one currency to another at the current exchange rate.',
        inputSchema: {
          type: 'object',
          properties: {
            from: {
              type: 'string',
              description: 'Source currency code (e.g., USD)',
            },
            to: {
              type: 'string',
              description: 'Target currency code (e.g., JPY)',
            },
            amount: {
              type: 'number',
              description: 'Amount to convert',
            },
          },
          required: ['from', 'to', 'amount'],
        },
      },
      {
        name: 'get_historical_rate',
        description: 'Get the exchange rate between two currencies on a specific historical date (YYYY-MM-DD).',
        inputSchema: {
          type: 'object',
          properties: {
            from: {
              type: 'string',
              description: 'Source currency code (e.g., USD)',
            },
            to: {
              type: 'string',
              description: 'Target currency code (e.g., EUR)',
            },
            date: {
              type: 'string',
              description: 'Date in YYYY-MM-DD format (earliest available: 1999-01-04)',
            },
          },
          required: ['from', 'to', 'date'],
        },
      },
      {
        name: 'get_currencies',
        description: 'List all currencies supported by the Frankfurter API with their full names.',
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
        case 'get_rate':
          return this.getRate(args);
        case 'convert':
          return this.convertAmount(args);
        case 'get_historical_rate':
          return this.getHistoricalRate(args);
        case 'get_currencies':
          return this.getCurrencies();
        default:
          return {
            content: [{ type: 'text', text: `Unknown tool: ${name}` }],
            isError: true,
          };
      }
    } catch (error) {
      return {
        content: [
          {
            type: 'text',
            text: `Tool execution failed: ${error instanceof Error ? error.message : String(error)}`,
          },
        ],
        isError: true,
      };
    }
  }

  // ── Private helpers ──────────────────────────────────────────────────────────

  private async fetchRate(
    endpoint: string,
    from: string,
    to: string,
  ): Promise<{ data: { amount: number; base: string; date: string; rates: Record<string, number> }; rate: number }> {
    const params = new URLSearchParams({
      base: from.toUpperCase(),
      symbols: to.toUpperCase(),
    });
    const url = `${BASE_URL}/${endpoint}?${params}`;
    const response = await this.fetchWithRetry(url, {
      method: 'GET',
      headers: { Accept: 'application/json' },
    });
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      throw new Error(`Frankfurter API error: ${response.status} ${errText}`);
    }
    const data = (await response.json()) as {
      amount: number;
      base: string;
      date: string;
      rates: Record<string, number>;
    };
    const rate = data.rates[to.toUpperCase()];
    if (rate === undefined) {
      throw new Error(`Currency not found: ${to.toUpperCase()}`);
    }
    return { data, rate };
  }

  private async getRate(args: Record<string, unknown>): Promise<ToolResult> {
    const from = args.from as string;
    const to = args.to as string;
    if (!from || !to) {
      return {
        content: [{ type: 'text', text: 'get_rate: "from" and "to" are required' }],
        isError: true,
      };
    }
    const { data, rate } = await this.fetchRate('latest', from, to);
    const result = {
      from: data.base,
      to: to.toUpperCase(),
      rate,
      date: data.date,
    };
    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }

  private async convertAmount(args: Record<string, unknown>): Promise<ToolResult> {
    const from = args.from as string;
    const to = args.to as string;
    const amount = args.amount as number;
    if (!from || !to || amount === undefined || amount === null) {
      return {
        content: [{ type: 'text', text: 'convert: "from", "to", and "amount" are required' }],
        isError: true,
      };
    }
    const { data, rate } = await this.fetchRate('latest', from, to);
    const result = {
      from: data.base,
      to: to.toUpperCase(),
      rate,
      amount,
      converted: Math.round(amount * rate * 10000) / 10000,
      date: data.date,
    };
    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }

  private async getHistoricalRate(args: Record<string, unknown>): Promise<ToolResult> {
    const from = args.from as string;
    const to = args.to as string;
    const date = args.date as string;
    if (!from || !to || !date) {
      return {
        content: [{ type: 'text', text: 'get_historical_rate: "from", "to", and "date" are required' }],
        isError: true,
      };
    }
    if (!/^\d{4}-\d{2}-\d{2}$/.test(date)) {
      return {
        content: [
          {
            type: 'text',
            text: `get_historical_rate: invalid date format "${date}". Expected YYYY-MM-DD.`,
          },
        ],
        isError: true,
      };
    }
    const { data, rate } = await this.fetchRate(date, from, to);
    const result = {
      from: data.base,
      to: to.toUpperCase(),
      rate,
      date: data.date,
    };
    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }

  private async getCurrencies(): Promise<ToolResult> {
    const url = `${BASE_URL}/currencies`;
    const response = await this.fetchWithRetry(url, {
      method: 'GET',
      headers: { Accept: 'application/json' },
    });
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `Frankfurter API error: ${response.status} ${errText}` }],
        isError: true,
      };
    }
    const data = (await response.json()) as Record<string, string>;
    const result = {
      count: Object.keys(data).length,
      currencies: Object.entries(data)
        .sort(([a], [b]) => a.localeCompare(b))
        .map(([code, name]) => ({ code, name })),
    };
    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }
}
