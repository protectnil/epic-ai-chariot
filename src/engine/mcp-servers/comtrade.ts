/**
 * UN Comtrade MCP Adapter
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

// Base URL: https://comtradeapi.un.org/public/v1/preview
// Auth: none — UN Comtrade public preview API requires no credentials
// Docs: https://comtradeapi.un.org/
// Category: finance
// Rate limits: UN Comtrade public preview — usage quotas apply per IP

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

interface ComtradeConfig {
  baseUrl?: string;
}

// Reverse lookup: numeric code → country name (preview API returns null for desc fields)
const CODE_TO_COUNTRY: Record<number, string> = {
  0: 'World', 36: 'Australia', 76: 'Brazil', 124: 'Canada', 156: 'China',
  250: 'France', 276: 'Germany', 344: 'Hong Kong', 356: 'India', 360: 'Indonesia',
  372: 'Ireland', 381: 'Italy', 392: 'Japan', 410: 'South Korea', 458: 'Malaysia',
  484: 'Mexico', 528: 'Netherlands', 682: 'Saudi Arabia', 702: 'Singapore',
  710: 'South Africa', 724: 'Spain', 757: 'Switzerland', 764: 'Thailand',
  490: 'Taiwan', 699: 'India', 704: 'Vietnam', 826: 'United Kingdom',
  842: 'United States',
};

const FLOW_NAMES: Record<string, string> = {
  M: 'Imports', X: 'Exports', 'RE-X': 'Re-exports', 'RE-M': 'Re-imports',
};

interface ComtradeRecord {
  reporterCode: number;
  reporterDesc: string;
  partnerCode: number;
  partnerDesc: string;
  flowCode: string;
  flowDesc: string;
  cmdCode: string;
  cmdDesc: string;
  primaryValue: number;
  netWgt: number;
  qty: number;
  qtyUnitAbbr: string;
  period: number;
}

interface ComtradeResponse {
  data: ComtradeRecord[];
  count: number;
  error?: string;
  elapsedTime?: string;
}

export class ComtradeMCPServer extends MCPAdapterBase {
  private readonly baseUrl: string;

  constructor(config?: ComtradeConfig) {
    super();
    if (config === null) { throw new Error('ComtradeMCPServer: configuration object is required when provided'); }
    this.baseUrl = config?.baseUrl ?? 'https://comtradeapi.un.org/public/v1/preview';
  }

  static catalog() {
    return {
      name: 'comtrade',
      displayName: 'UN Comtrade',
      version: '1.0.0',
      category: 'finance',
      keywords: [
        'comtrade', 'trade', 'international trade', 'bilateral trade', 'imports',
        'exports', 'commodities', 'HS code', 'countries', 'trade partners',
        'trade data', 'UN', 'global trade', 'tariff', 'commerce',
      ],
      toolNames: [
        'comtrade_trade_data',
        'comtrade_top_partners',
        'comtrade_top_commodities',
        'comtrade_country_codes',
      ],
      description: 'UN Comtrade: query bilateral trade data between countries, top trading partners, top traded commodities, and country code references from the UN Comtrade public API.',
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
        name: 'comtrade_trade_data',
        description:
          'Get bilateral trade data between two countries from the UN Comtrade database. Returns trade value, quantity, partner, and commodity description for imports and/or exports.',
        inputSchema: {
          type: 'object',
          properties: {
            reporter_code: {
              type: 'string',
              description: 'ISO numeric country code for the reporting country (e.g., "842" for US, "156" for China)',
            },
            partner_code: {
              type: 'string',
              description: 'ISO numeric country code for the partner country (e.g., "156" for China, "0" for World)',
            },
            year: {
              type: 'string',
              description: 'Trade year (e.g., "2024")',
            },
            hs_code: {
              type: 'string',
              description: 'HS commodity code at 2/4/6 digit level (e.g., "8471" for computers). Optional — omit for all commodities.',
            },
            flow: {
              type: 'string',
              description: 'Trade flow: "M" for imports, "X" for exports. Optional — defaults to both "M,X".',
            },
          },
          required: ['reporter_code', 'partner_code', 'year'],
        },
      },
      {
        name: 'comtrade_top_partners',
        description:
          "Get top trading partners for a country by trade value. Useful for understanding a country's main trade relationships.",
        inputSchema: {
          type: 'object',
          properties: {
            reporter_code: {
              type: 'string',
              description: 'ISO numeric country code (e.g., "842" for US)',
            },
            year: {
              type: 'string',
              description: 'Trade year (e.g., "2024")',
            },
            flow: {
              type: 'string',
              description: 'Trade flow: "M" for imports, "X" for exports',
            },
            hs_code: {
              type: 'string',
              description: 'Optional HS commodity code to filter by specific product',
            },
            limit: {
              type: 'number',
              description: 'Number of top partners to return (default 20)',
            },
          },
          required: ['reporter_code', 'year', 'flow'],
        },
      },
      {
        name: 'comtrade_top_commodities',
        description:
          'Get top traded commodities between two countries by trade value. Shows which product categories dominate bilateral trade.',
        inputSchema: {
          type: 'object',
          properties: {
            reporter_code: {
              type: 'string',
              description: 'ISO numeric country code for the reporting country',
            },
            partner_code: {
              type: 'string',
              description: 'ISO numeric country code for the partner country',
            },
            year: {
              type: 'string',
              description: 'Trade year (e.g., "2024")',
            },
            flow: {
              type: 'string',
              description: 'Trade flow: "M" for imports, "X" for exports',
            },
            limit: {
              type: 'number',
              description: 'Number of top commodities to return (default 20)',
            },
          },
          required: ['reporter_code', 'partner_code', 'year', 'flow'],
        },
      },
      {
        name: 'comtrade_country_codes',
        description:
          'Get a reference list of common country ISO numeric codes used in UN Comtrade queries. No API call needed.',
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
        case 'comtrade_trade_data':
          return this.getTradeData(
            args.reporter_code as string,
            args.partner_code as string,
            args.year as string,
            args.hs_code as string | undefined,
            args.flow as string | undefined,
          );
        case 'comtrade_top_partners':
          return this.getTopPartners(
            args.reporter_code as string,
            args.year as string,
            args.flow as string,
            args.hs_code as string | undefined,
            typeof args.limit === 'number' ? args.limit : 20,
          );
        case 'comtrade_top_commodities':
          return this.getTopCommodities(
            args.reporter_code as string,
            args.partner_code as string,
            args.year as string,
            args.flow as string,
            typeof args.limit === 'number' ? args.limit : 20,
          );
        case 'comtrade_country_codes':
          return { content: [{ type: 'text', text: this.truncate(this.getCountryCodes()) }], isError: false };
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

  private buildUrl(params: Record<string, string>): string {
    const url = new URL(`${this.baseUrl}/C/A/HS`);
    url.searchParams.set('customsCode', 'C00');
    url.searchParams.set('motCode', '0');
    for (const [key, value] of Object.entries(params)) {
      url.searchParams.set(key, value);
    }
    return url.toString();
  }

  private async fetchComtrade(params: Record<string, string>): Promise<ComtradeResponse> {
    const url = this.buildUrl(params);
    const response = await this.fetchWithRetry(url, {
      method: 'GET',
      headers: { Accept: 'application/json' },
    });
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      throw new Error(`UN Comtrade API error: ${response.status} ${errText}`);
    }
    const data = (await response.json()) as ComtradeResponse;
    if (data.error) {
      throw new Error(`UN Comtrade API error: ${data.error}`);
    }
    return data;
  }

  private resolveRecord(r: ComtradeRecord) {
    return {
      reporter: r.reporterDesc || CODE_TO_COUNTRY[r.reporterCode] || `Code ${r.reporterCode}`,
      partner: r.partnerDesc || CODE_TO_COUNTRY[r.partnerCode] || `Code ${r.partnerCode}`,
      flow: r.flowDesc || FLOW_NAMES[r.flowCode] || r.flowCode,
      commodity_code: r.cmdCode,
      commodity: r.cmdDesc || r.cmdCode,
      trade_value_usd: r.primaryValue,
      net_weight_kg: r.netWgt,
      quantity: r.qty,
      quantity_unit: r.qtyUnitAbbr,
    };
  }

  private async getTradeData(
    reporterCode: string,
    partnerCode: string,
    year: string,
    hsCode?: string,
    flow?: string,
  ): Promise<ToolResult> {
    const params: Record<string, string> = {
      reporterCode,
      partnerCode,
      period: year,
      flowCode: flow || 'M,X',
    };
    if (hsCode) {
      params.cmdCode = hsCode;
    }
    const response = await this.fetchComtrade(params);
    const result = {
      count: response.count,
      year,
      records: response.data.map((r) => this.resolveRecord(r)),
    };
    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }

  private async getTopPartners(
    reporterCode: string,
    year: string,
    flow: string,
    hsCode?: string,
    limit: number = 20,
  ): Promise<ToolResult> {
    const params: Record<string, string> = {
      reporterCode,
      period: year,
      flowCode: flow,
      cmdCode: hsCode || 'TOTAL',
    };
    const response = await this.fetchComtrade(params);
    const sorted = response.data
      .filter((r) => r.partnerCode !== 0 && r.primaryValue > 0)
      .sort((a, b) => b.primaryValue - a.primaryValue)
      .slice(0, limit);
    const result = {
      reporter: CODE_TO_COUNTRY[Number(reporterCode)] || `Code ${reporterCode}`,
      year,
      flow: flow === 'M' ? 'Imports' : 'Exports',
      total_partners: sorted.length,
      top_partners: sorted.map((r, i) => ({
        rank: i + 1,
        partner: r.partnerDesc || CODE_TO_COUNTRY[r.partnerCode] || `Code ${r.partnerCode}`,
        partner_code: r.partnerCode,
        trade_value_usd: r.primaryValue,
        commodity: r.cmdDesc || r.cmdCode,
      })),
    };
    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }

  private async getTopCommodities(
    reporterCode: string,
    partnerCode: string,
    year: string,
    flow: string,
    limit: number = 20,
  ): Promise<ToolResult> {
    const params: Record<string, string> = {
      reporterCode,
      partnerCode,
      period: year,
      flowCode: flow,
      cmdCode: 'TOTAL',
    };
    const response = await this.fetchComtrade(params);
    const sorted = response.data
      .sort((a, b) => b.primaryValue - a.primaryValue)
      .slice(0, limit);
    const result = {
      reporter: CODE_TO_COUNTRY[Number(reporterCode)] || `Code ${reporterCode}`,
      partner: CODE_TO_COUNTRY[Number(partnerCode)] || `Code ${partnerCode}`,
      year,
      flow: flow === 'M' ? 'Imports' : 'Exports',
      total_commodities: sorted.length,
      top_commodities: sorted.map((r, i) => ({
        rank: i + 1,
        hs_code: r.cmdCode,
        commodity: r.cmdDesc || r.cmdCode,
        trade_value_usd: r.primaryValue,
        net_weight_kg: r.netWgt,
      })),
    };
    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }

  private getCountryCodes() {
    return {
      note: 'Use these numeric codes in reporter_code and partner_code parameters. Use 0 for World aggregate.',
      countries: [
        { label: 'US', numeric_code: 842, full_name: 'United States' },
        { label: 'China', numeric_code: 156, full_name: 'China' },
        { label: 'Japan', numeric_code: 392, full_name: 'Japan' },
        { label: 'Germany', numeric_code: 276, full_name: 'Germany' },
        { label: 'UK', numeric_code: 826, full_name: 'United Kingdom' },
        { label: 'Mexico', numeric_code: 484, full_name: 'Mexico' },
        { label: 'Canada', numeric_code: 124, full_name: 'Canada' },
        { label: 'India', numeric_code: 699, full_name: 'India' },
        { label: 'Brazil', numeric_code: 76, full_name: 'Brazil' },
        { label: 'Vietnam', numeric_code: 704, full_name: 'Vietnam' },
        { label: 'South Korea', numeric_code: 410, full_name: 'South Korea' },
        { label: 'Taiwan', numeric_code: 490, full_name: 'Taiwan' },
        { label: 'France', numeric_code: 251, full_name: 'France' },
        { label: 'Italy', numeric_code: 381, full_name: 'Italy' },
        { label: 'Netherlands', numeric_code: 528, full_name: 'Netherlands' },
        { label: 'Australia', numeric_code: 36, full_name: 'Australia' },
        { label: 'Singapore', numeric_code: 702, full_name: 'Singapore' },
        { label: 'Thailand', numeric_code: 764, full_name: 'Thailand' },
        { label: 'Indonesia', numeric_code: 360, full_name: 'Indonesia' },
        { label: 'Malaysia', numeric_code: 458, full_name: 'Malaysia' },
        { label: 'Saudi Arabia', numeric_code: 682, full_name: 'Saudi Arabia' },
        { label: 'Switzerland', numeric_code: 757, full_name: 'Switzerland' },
        { label: 'Ireland', numeric_code: 372, full_name: 'Ireland' },
        { label: 'Spain', numeric_code: 724, full_name: 'Spain' },
        { label: 'World', numeric_code: 0, full_name: 'World (aggregate)' },
      ],
    };
  }
}
