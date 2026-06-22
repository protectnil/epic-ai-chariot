/**
 * FDIC BankFind Suite API MCP Adapter
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

// Base URL: https://banks.data.fdic.gov/api
// Auth: None — free public API, no key required
// Docs: https://banks.data.fdic.gov/docs/
// Category: finance
// Rate limits: None documented

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

const BASE_URL = 'https://banks.data.fdic.gov/api';

export class FDICMCPServer extends MCPAdapterBase {
  private readonly baseUrl: string;

  constructor(config?: { baseUrl?: string }) {
    super();
    if (config === null) { throw new Error('FDICMCPServer: configuration object is required when provided'); }
    this.baseUrl = config?.baseUrl ?? BASE_URL;
  }

  static catalog() {
    return {
      name: 'fdic',
      displayName: 'FDIC BankFind Suite API',
      version: '1.0.0',
      category: 'finance',
      keywords: [
        'fdic', 'bank', 'banking', 'institutions', 'insured banks',
        'bank failures', 'financials', 'call report', 'deposits', 'assets',
        'net income', 'roa', 'roe', 'cert', 'certificate number',
        'industry summary', 'bank data', 'financial data', 'public', 'free',
      ],
      toolNames: [
        'fdic_search_institutions',
        'fdic_get_institution',
        'fdic_financials',
        'fdic_failures',
        'fdic_summary',
      ],
      description:
        'FDIC BankFind Suite API: search FDIC-insured banks, retrieve institution profiles, financial call-report data, bank failure history, and aggregate industry summaries — all free and unauthenticated.',
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
        name: 'fdic_search_institutions',
        description:
          'Search for FDIC-insured banks and institutions by name. Returns institution name, CERT number, city, state, total assets, deposits, net income, ROA, ROE, and report date.',
        inputSchema: {
          type: 'object',
          properties: {
            search: {
              type: 'string',
              description: 'Bank or institution name to search for (e.g., "Chase", "Wells Fargo")',
            },
            limit: {
              type: 'number',
              description: 'Number of results to return (default 10)',
            },
          },
          required: ['search'],
        },
      },
      {
        name: 'fdic_get_institution',
        description:
          'Get detailed information for a specific FDIC-insured bank by its CERT (certificate) number. Returns full institution profile including name, location, assets, and regulatory details.',
        inputSchema: {
          type: 'object',
          properties: {
            cert: {
              type: 'string',
              description: 'FDIC certificate number (e.g., "628" for Chase)',
            },
          },
          required: ['cert'],
        },
      },
      {
        name: 'fdic_financials',
        description:
          'Get financial call report data for a bank by CERT number. Returns quarterly financial metrics including total assets, deposits, net income, interest income, loan losses, ROA, ROE, and efficiency ratio.',
        inputSchema: {
          type: 'object',
          properties: {
            cert: {
              type: 'string',
              description: 'FDIC certificate number',
            },
            limit: {
              type: 'number',
              description: 'Number of quarterly reports to return (default 8, which is 2 years)',
            },
          },
          required: ['cert'],
        },
      },
      {
        name: 'fdic_failures',
        description:
          'List FDIC bank failures, sorted by most recent. Optionally filter by date range. Returns bank name, city, state, CERT, failure date, acquiring institution, and fund used.',
        inputSchema: {
          type: 'object',
          properties: {
            limit: {
              type: 'number',
              description: 'Number of failure records to return (default 20)',
            },
            start_date: {
              type: 'string',
              description: 'Start date filter in MM/DD/YYYY format (e.g., "01/01/2023")',
            },
            end_date: {
              type: 'string',
              description: 'End date filter in MM/DD/YYYY format (e.g., "12/31/2023")',
            },
          },
        },
      },
      {
        name: 'fdic_summary',
        description:
          'Get aggregate industry summary data for all FDIC-insured institutions for a given reporting date. Returns total assets, deposits, net income, interest income, number of loans, and institution count.',
        inputSchema: {
          type: 'object',
          properties: {
            date: {
              type: 'string',
              description: 'Report date in YYYYMMDD format (e.g., "20240331" for Q1 2024)',
            },
          },
          required: ['date'],
        },
      },
    ];
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<ToolResult> {
    try {
      switch (name) {
        case 'fdic_search_institutions':
          return this.searchInstitutions(
            args.search as string,
            (args.limit as number) ?? 10,
          );
        case 'fdic_get_institution':
          return this.getInstitution(args.cert as string);
        case 'fdic_financials':
          return this.getFinancials(
            args.cert as string,
            (args.limit as number) ?? 8,
          );
        case 'fdic_failures':
          return this.getFailures(
            (args.limit as number) ?? 20,
            args.start_date as string | undefined,
            args.end_date as string | undefined,
          );
        case 'fdic_summary':
          return this.getSummary(args.date as string);
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

  // ── Private helpers ────────────────────────────────────────────────────────

  private async fdicGet(path: string): Promise<ToolResult> {
    const url = `${this.baseUrl}${path}`;
    const response = await this.fetchWithRetry(url, {
      method: 'GET',
      headers: { Accept: 'application/json' },
    });
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `FDIC API error (${response.status}): ${errText}` }],
        isError: true,
      };
    }
    const data = await response.json();
    return { content: [{ type: 'text', text: this.truncate(data) }], isError: false };
  }

  private async searchInstitutions(search: string, limit: number): Promise<ToolResult> {
    const fields = 'INSTNAME,CERT,CITY,STNAME,ASSET,DEP,NETINC,ROA,ROE,RISDATE';
    const path = `/institutions?search=${encodeURIComponent(search)}&limit=${limit}&fields=${fields}`;
    const result = await this.fdicGet(path);
    if (result.isError) return result;

    try {
      const raw = JSON.parse(result.content[0].text) as {
        data: { data: Record<string, unknown> }[];
        totals: { count: number };
      };
      const out = {
        query: search,
        total_results: raw.totals?.count ?? raw.data?.length ?? 0,
        institutions: (raw.data ?? []).map((row) => ({
          name: row.data.INSTNAME ?? null,
          cert: row.data.CERT ?? null,
          city: row.data.CITY ?? null,
          state: row.data.STNAME ?? null,
          total_assets: row.data.ASSET ?? null,
          total_deposits: row.data.DEP ?? null,
          net_income: row.data.NETINC ?? null,
          roa: row.data.ROA ?? null,
          roe: row.data.ROE ?? null,
          report_date: row.data.RISDATE ?? null,
        })),
      };
      return { content: [{ type: 'text', text: this.truncate(out) }], isError: false };
    } catch {
      return result;
    }
  }

  private async getInstitution(cert: string): Promise<ToolResult> {
    const result = await this.fdicGet(`/institutions/${encodeURIComponent(cert)}`);
    if (result.isError) return result;

    try {
      const raw = JSON.parse(result.content[0].text) as {
        data: { data: Record<string, unknown> }[];
      };
      const row = raw.data?.[0]?.data;
      if (!row) {
        return {
          content: [{ type: 'text', text: `No institution found for CERT: ${cert}` }],
          isError: true,
        };
      }
      return { content: [{ type: 'text', text: this.truncate(row) }], isError: false };
    } catch {
      return result;
    }
  }

  private async getFinancials(cert: string, limit: number): Promise<ToolResult> {
    const fields = 'REPDTE,ASSET,DEP,NETINC,INTINC,ELNATR,NITEFULL,ROA,ROE,EEFFR';
    const path =
      `/financials?filters=CERT%3A${encodeURIComponent(cert)}&sort_by=REPDTE&sort_order=DESC&limit=${limit}&fields=${fields}`;
    const result = await this.fdicGet(path);
    if (result.isError) return result;

    try {
      const raw = JSON.parse(result.content[0].text) as {
        data: { data: Record<string, unknown> }[];
        totals: { count: number };
      };
      const out = {
        cert,
        total_reports: raw.totals?.count ?? raw.data?.length ?? 0,
        financials: (raw.data ?? []).map((row) => ({
          report_date: row.data.REPDTE ?? null,
          total_assets: row.data.ASSET ?? null,
          total_deposits: row.data.DEP ?? null,
          net_income: row.data.NETINC ?? null,
          interest_income: row.data.INTINC ?? null,
          loan_losses: row.data.ELNATR ?? null,
          net_interest_margin: row.data.NITEFULL ?? null,
          roa: row.data.ROA ?? null,
          roe: row.data.ROE ?? null,
          efficiency_ratio: row.data.EEFFR ?? null,
        })),
      };
      return { content: [{ type: 'text', text: this.truncate(out) }], isError: false };
    } catch {
      return result;
    }
  }

  private async getFailures(
    limit: number,
    startDate?: string,
    endDate?: string,
  ): Promise<ToolResult> {
    let path = `/failures?sort_by=FAILDATE&sort_order=DESC&limit=${limit}`;
    const filters: string[] = [];
    if (startDate) filters.push(`FAILDATE_MIN:${encodeURIComponent(startDate)}`);
    if (endDate) filters.push(`FAILDATE_MAX:${encodeURIComponent(endDate)}`);
    if (filters.length > 0) path += `&filters=${filters.join(',')}`;

    const result = await this.fdicGet(path);
    if (result.isError) return result;

    try {
      const raw = JSON.parse(result.content[0].text) as {
        data: { data: Record<string, unknown> }[];
        totals: { count: number };
      };
      const out = {
        total_failures: raw.totals?.count ?? raw.data?.length ?? 0,
        filters: {
          start_date: startDate ?? null,
          end_date: endDate ?? null,
        },
        failures: (raw.data ?? []).map((row) => ({
          name: row.data.NAME ?? null,
          cert: row.data.CERT ?? null,
          city: row.data.CITYST ?? row.data.CITY ?? null,
          state: row.data.STALP ?? null,
          failure_date: row.data.FAILDATE ?? null,
          acquiring_institution: row.data.ACQUIRER ?? null,
          fund: row.data.FUND ?? null,
          total_deposits: row.data.TOTALDEPOSITS ?? null,
          total_assets: row.data.COST ?? null,
        })),
      };
      return { content: [{ type: 'text', text: this.truncate(out) }], isError: false };
    } catch {
      return result;
    }
  }

  private async getSummary(date: string): Promise<ToolResult> {
    const fields = 'ASSET,DEP,NETINC,INTINC,NUML,INSTCNT';
    const path = `/summary?filters=REPDTE%3A${encodeURIComponent(date)}&fields=${fields}`;
    const result = await this.fdicGet(path);
    if (result.isError) return result;

    try {
      const raw = JSON.parse(result.content[0].text) as {
        data: { data: Record<string, unknown> }[];
        totals: { count: number };
      };
      if (!raw.data?.length) {
        return {
          content: [{ type: 'text', text: `No summary data found for date: ${date}` }],
          isError: true,
        };
      }
      const out = {
        report_date: date,
        total_records: raw.totals?.count ?? raw.data.length,
        summary: (raw.data ?? []).map((row) => ({
          total_assets: row.data.ASSET ?? null,
          total_deposits: row.data.DEP ?? null,
          net_income: row.data.NETINC ?? null,
          interest_income: row.data.INTINC ?? null,
          number_of_loans: row.data.NUML ?? null,
          institution_count: row.data.INSTCNT ?? null,
        })),
      };
      return { content: [{ type: 'text', text: this.truncate(out) }], isError: false };
    } catch {
      return result;
    }
  }
}
