/**
 * US Treasury Fiscal Data MCP Adapter
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

// Base URL: https://api.fiscaldata.treasury.gov/services/api/fiscal_service
// Auth: None (public US Treasury API, no key required)
// Docs: https://fiscaldata.treasury.gov/api-documentation/
// Category: finance
// Rate limits: Free, no stated hard cap

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

const BASE_URL = 'https://api.fiscaldata.treasury.gov/services/api/fiscal_service';

export class TreasuryMCPServer extends MCPAdapterBase {
  constructor() {
    super();
  }

  static catalog() {
    return {
      name: 'treasury',
      displayName: 'US Treasury Fiscal Data',
      version: '1.0.0',
      category: 'finance' as const,
      keywords: [
        'treasury', 'us treasury', 'fiscal data', 'national debt', 'debt to the penny',
        'federal spending', 'interest rates', 'treasury rates', 'government finance',
        'fiscal year', 'public debt', 'net cost', 'statement of net cost',
        'average interest rate', 'debt outstanding', 'intragovernmental',
      ],
      toolNames: [
        'get_national_debt',
        'get_treasury_rates',
        'get_federal_spending',
      ],
      description: 'US Treasury Fiscal Data: retrieve current national debt (debt to the penny), Treasury average interest rates, and federal net cost / spending data. Public API, no authentication required.',
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
        name: 'get_national_debt',
        description:
          'Get the current US national debt (debt to the penny). Returns the most recent total public debt outstanding figure from the US Treasury.',
        inputSchema: {
          type: 'object',
          properties: {},
        },
      },
      {
        name: 'get_treasury_rates',
        description:
          'Get US Treasury average interest rates. Returns the 10 most recent rate records, optionally filtered by a specific date (YYYY-MM-DD).',
        inputSchema: {
          type: 'object',
          properties: {
            date: {
              type: 'string',
              description: 'Filter by record date in YYYY-MM-DD format (optional)',
            },
          },
        },
      },
      {
        name: 'get_federal_spending',
        description:
          'Get federal net cost / spending data. Returns the 20 most recent records, optionally filtered by a specific fiscal year (e.g., "2023").',
        inputSchema: {
          type: 'object',
          properties: {
            fiscal_year: {
              type: 'string',
              description: 'Four-digit fiscal year to filter by (e.g., "2023"). Omit for all recent records.',
            },
          },
        },
      },
    ];
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<ToolResult> {
    try {
      switch (name) {
        case 'get_national_debt':   return this.getNationalDebt();
        case 'get_treasury_rates':  return this.getTreasuryRates(args.date as string | undefined);
        case 'get_federal_spending': return this.getFederalSpending(args.fiscal_year as string | undefined);
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

  private async getNationalDebt(): Promise<ToolResult> {
    const url = `${BASE_URL}/v2/accounting/od/debt_to_penny?sort=-record_date&page[size]=1`;
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
    const data = await response.json() as {
      data: {
        record_date: string;
        tot_pub_debt_out_amt: string;
        debt_held_public_amt: string;
        intragov_hold_amt: string;
      }[];
      meta: { total_count: number };
    };
    const record = data.data[0];
    if (!record) {
      return { content: [{ type: 'text', text: 'No debt data returned' }], isError: true };
    }
    const result = {
      record_date: record.record_date,
      total_public_debt: record.tot_pub_debt_out_amt,
      debt_held_by_public: record.debt_held_public_amt,
      intragovernmental_holdings: record.intragov_hold_amt,
    };
    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }

  private async getTreasuryRates(date?: string): Promise<ToolResult> {
    let url = `${BASE_URL}/v2/accounting/od/avg_interest_rates?sort=-record_date&page[size]=10`;
    if (date) {
      url += `&filter=record_date:eq:${encodeURIComponent(date)}`;
    }
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
    const data = await response.json() as {
      data: {
        record_date: string;
        security_type_desc: string;
        security_desc: string;
        avg_interest_rate_amt: string;
      }[];
      meta: { total_count: number };
    };
    const result = {
      filter_date: date ?? null,
      total_records: data.meta?.total_count ?? data.data.length,
      rates: data.data.map((r) => ({
        record_date: r.record_date,
        security_type: r.security_type_desc,
        security_description: r.security_desc,
        avg_interest_rate: r.avg_interest_rate_amt,
      })),
    };
    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }

  private async getFederalSpending(fiscalYear?: string): Promise<ToolResult> {
    let url = `${BASE_URL}/v2/accounting/od/statement_net_cost?sort=-record_date&page[size]=20`;
    if (fiscalYear) {
      url += `&filter=fiscal_year:eq:${encodeURIComponent(fiscalYear)}`;
    }
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
    const data = await response.json() as {
      data: {
        record_date: string;
        fiscal_year: string;
        fiscal_quarter_number: string;
        agency_nm: string;
        gross_cost_amt: string;
        earned_revenue_amt: string;
        net_cost_amt: string;
      }[];
      meta: { total_count: number };
    };
    const result = {
      filter_fiscal_year: fiscalYear ?? null,
      total_records: data.meta?.total_count ?? data.data.length,
      spending: data.data.map((r) => ({
        record_date: r.record_date,
        fiscal_year: r.fiscal_year,
        fiscal_quarter: r.fiscal_quarter_number,
        agency: r.agency_nm,
        gross_cost: r.gross_cost_amt,
        earned_revenue: r.earned_revenue_amt,
        net_cost: r.net_cost_amt,
      })),
    };
    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }
}
