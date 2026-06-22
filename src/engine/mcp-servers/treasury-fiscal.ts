/**
 * US Treasury Fiscal Data MCP Adapter
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

// Base URL: https://api.fiscaldata.treasury.gov/services/api/fiscal_service
// Auth: none (public API — no key required)
// Docs: https://fiscaldata.treasury.gov/api-documentation/
// Category: finance
// Rate limits: None published — standard fair-use applies

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

const BASE_URL = 'https://api.fiscaldata.treasury.gov/services/api/fiscal_service';

export class TreasuryFiscalMCPServer extends MCPAdapterBase {
  private readonly baseUrl: string;

  constructor(config?: { baseUrl?: string }) {
    super();
    if (config === null) { throw new Error('TreasuryFiscalMCPServer: configuration object is required when provided'); }
    this.baseUrl = config?.baseUrl ?? BASE_URL;
  }

  static catalog() {
    return {
      name: 'treasury-fiscal',
      displayName: 'US Treasury Fiscal Data',
      version: '1.0.0',
      category: 'finance',
      keywords: [
        'treasury', 'fiscal', 'us government', 'national debt', 'debt to the penny',
        'customs duty', 'tariff revenue', 'government receipts', 'exchange rates',
        'fiscal data', 'federal budget', 'tax revenue', 'public debt',
      ],
      toolNames: [
        'treasury_customs_revenue',
        'treasury_receipts',
        'treasury_debt',
        'treasury_exchange_rates',
      ],
      description: 'Access US Treasury Fiscal Data: monthly customs duty collections, total government receipts by source, national debt (debt to the penny), and official Treasury exchange rates by country.',
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
        name: 'treasury_customs_revenue',
        description:
          'Get monthly US customs duty revenue collections from the Treasury. Useful for tracking tariff revenue impact over time.',
        inputSchema: {
          type: 'object',
          properties: {
            limit: {
              type: 'number',
              description: 'Number of monthly records to return (default 12 for 1 year)',
            },
          },
        },
      },
      {
        name: 'treasury_receipts',
        description:
          'Get total US government receipts broken down by source (individual income tax, corporate tax, excise taxes, customs duties, etc.).',
        inputSchema: {
          type: 'object',
          properties: {
            limit: {
              type: 'number',
              description: 'Number of records to return (default 12)',
            },
          },
        },
      },
      {
        name: 'treasury_debt',
        description:
          'Get the current US national debt (debt to the penny). Returns total public debt outstanding with historical data points.',
        inputSchema: {
          type: 'object',
          properties: {
            limit: {
              type: 'number',
              description: 'Number of records to return (default 10)',
            },
          },
        },
      },
      {
        name: 'treasury_exchange_rates',
        description:
          'Get Treasury exchange rates for a specific country. Shows the official rates used by the US government for currency conversion.',
        inputSchema: {
          type: 'object',
          properties: {
            country: {
              type: 'string',
              description: 'Country name (e.g., "China", "Mexico", "Japan", "Canada")',
            },
            limit: {
              type: 'number',
              description: 'Number of records to return (default 12)',
            },
          },
          required: ['country'],
        },
      },
    ];
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<ToolResult> {
    try {
      switch (name) {
        case 'treasury_customs_revenue':
          return this.getCustomsRevenue((args.limit as number | undefined) ?? 12);
        case 'treasury_receipts':
          return this.getReceipts((args.limit as number | undefined) ?? 12);
        case 'treasury_debt':
          return this.getDebt((args.limit as number | undefined) ?? 10);
        case 'treasury_exchange_rates':
          return this.getExchangeRates(
            args.country as string,
            (args.limit as number | undefined) ?? 12,
          );
        default:
          return {
            content: [{ type: 'text', text: `Unknown tool: ${name}` }],
            isError: true,
          };
      }
    } catch (error) {
      return {
        content: [{ type: 'text', text: `Tool execution failed: ${error instanceof Error ? error.message : String(error)}` }],
        isError: true,
      };
    }
  }

  // ── Private helpers ────────────────────────────────────────────────────────

  private async fetchFiscalRaw(
    endpoint: string,
    params: Record<string, string> = {},
  ): Promise<{ error: true; result: ToolResult } | { error: false; data: unknown }> {
    const url = new URL(`${this.baseUrl}/${endpoint}`);
    for (const [key, value] of Object.entries(params)) {
      url.searchParams.set(key, value);
    }

    const response = await this.fetchWithRetry(url.toString(), {
      method: 'GET',
      headers: { Accept: 'application/json', 'User-Agent': 'EpicAI-Chariot/1.0' },
    });

    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return {
        error: true,
        result: {
          content: [{ type: 'text', text: `Treasury Fiscal API error: ${response.status} ${response.statusText} — ${errText}` }],
          isError: true,
        },
      };
    }

    const data = await response.json();
    return { error: false, data };
  }

  private async getCustomsRevenue(limit: number): Promise<ToolResult> {
    const raw = await this.fetchFiscalRaw('v1/accounting/mts/mts_table_9', {
      filter: 'line_code_nbr:eq:830',
      sort: '-record_date',
      'page[size]': String(limit),
    });
    if (raw.error) return raw.result;

    const parsed = raw.data as {
      data: Record<string, unknown>[];
      meta: { 'total-count': number };
    };

    const result = {
      description: 'Monthly US customs duty revenue',
      count: parsed.data.length,
      total_available: parsed.meta['total-count'],
      records: parsed.data.map((r) => ({
        record_date: r.record_date,
        classification: r.classification_desc ?? r.classification,
        current_month_gross: r.current_month_gross_rcpt_amt,
        current_month_refund: r.current_month_refund_amt,
        current_month_net: r.current_month_net_rcpt_amt,
        fiscal_year_gross: r.fiscal_year_gross_rcpt_amt,
        fiscal_year_refund: r.fiscal_year_refund_amt,
        fiscal_year_net: r.fiscal_year_net_rcpt_amt,
      })),
    };
    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }

  private async getReceipts(limit: number): Promise<ToolResult> {
    const raw = await this.fetchFiscalRaw('v1/accounting/mts/mts_table_4', {
      sort: '-record_date',
      'page[size]': String(limit),
    });
    if (raw.error) return raw.result;

    const parsed = raw.data as {
      data: Record<string, unknown>[];
      meta: { 'total-count': number };
    };

    const result = {
      description: 'US government receipts by source category',
      count: parsed.data.length,
      total_available: parsed.meta['total-count'],
      records: parsed.data.map((r) => ({
        record_date: r.record_date,
        classification: r.classification_desc,
        current_month_net: r.current_month_net_rcpt_amt,
        current_month_gross: r.current_month_gross_rcpt_amt,
        current_month_refund: r.current_month_refund_amt,
        fiscal_year_net: r.current_fytd_net_rcpt_amt,
        fiscal_year_gross: r.current_fytd_gross_rcpt_amt,
        fiscal_year_refund: r.current_fytd_refund_amt,
        line_code: r.line_code_nbr,
        table_nbr: r.table_nbr,
      })),
    };
    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }

  private async getDebt(limit: number): Promise<ToolResult> {
    const raw = await this.fetchFiscalRaw('v2/accounting/od/debt_to_penny', {
      sort: '-record_date',
      'page[size]': String(limit),
    });
    if (raw.error) return raw.result;

    const parsed = raw.data as {
      data: Record<string, unknown>[];
    };

    const result = {
      description: 'US national debt (Debt to the Penny)',
      count: parsed.data.length,
      records: parsed.data.map((r) => ({
        record_date: r.record_date,
        total_public_debt_outstanding: r.tot_pub_debt_out_amt,
        debt_held_by_public: r.debt_held_public_amt,
        intragovernmental_holdings: r.intragov_hold_amt,
      })),
    };
    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }

  private async getExchangeRates(country: string, limit: number): Promise<ToolResult> {
    if (!country || typeof country !== 'string' || country.trim().length === 0) {
      return {
        content: [{ type: 'text', text: 'treasury_exchange_rates: country parameter is required' }],
        isError: true,
      };
    }

    const raw = await this.fetchFiscalRaw('v1/accounting/od/rates_of_exchange', {
      filter: `country:eq:${country.trim()}`,
      sort: '-record_date',
      'page[size]': String(limit),
    });
    if (raw.error) return raw.result;

    const parsed = raw.data as {
      data: Record<string, unknown>[];
    };

    if (parsed.data.length === 0) {
      return {
        content: [{
          type: 'text',
          text: `No exchange rate data found for country: "${country}". Try the full country name (e.g., "China", "Mexico", "Japan").`,
        }],
        isError: true,
      };
    }

    const result = {
      description: `Treasury exchange rates for ${country}`,
      country,
      count: parsed.data.length,
      records: parsed.data.map((r) => ({
        record_date: r.record_date,
        country: r.country,
        currency: r.currency,
        exchange_rate: r.exchange_rate,
        effective_date: r.effective_date,
      })),
    };
    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }
}
