/**
 * US Census Bureau International Trade API Adapter
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 *
 * Base URL: https://api.census.gov/data/timeseries/intltrade
 * Auth: none (public API — no key required)
 * Docs: https://www.census.gov/foreign-trade/reference/guides/index.html
 * Category: finance
 */

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

const BASE_URL = 'https://api.census.gov/data/timeseries/intltrade';

type CensusRow = string[];
type CensusResponse = CensusRow[];

export class CensusTradeMCPServer extends MCPAdapterBase {
  private readonly baseUrl: string;

  constructor(config?: { baseUrl?: string }) {
    super();
    if (config === null) { throw new Error('CensusTradeMCPServer: configuration object is required when provided'); }
    this.baseUrl = config?.baseUrl ?? BASE_URL;
  }

  static catalog() {
    return {
      name: 'census-trade',
      displayName: 'US Census Bureau International Trade',
      version: '1.0.0',
      category: 'finance' as const,
      keywords: [
        'census', 'trade', 'international trade', 'imports', 'exports',
        'hs code', 'commodity', 'trade balance', 'trade deficit', 'trade surplus',
        'us trade', 'foreign trade', 'tariff', 'country trade', 'monthly trade',
        'trade trends', 'end-use', 'hs2', 'hs4', 'hs6',
      ],
      toolNames: [
        'census_imports',
        'census_exports',
        'census_trade_balance',
        'census_trade_trends',
      ],
      description: 'US Census Bureau International Trade API: query US import and export data by HS commodity code and country, compute trade balances, and retrieve monthly trade trends.',
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
        name: 'census_imports',
        description:
          'Get US import data by HS commodity code and/or country. Returns import values, quantities, commodity details, and country names from the US Census Bureau.',
        inputSchema: {
          type: 'object',
          properties: {
            hs_code: {
              type: 'string',
              description:
                'HS commodity code at 2, 4, or 6 digit level (e.g., "8471" for computers, "87" for vehicles)',
            },
            country_code: {
              type: 'string',
              description:
                'Census country code (e.g., "5700" for China, "2010" for Mexico). Optional — omit for all countries.',
            },
            year: {
              type: 'string',
              description: 'Trade year (e.g., "2024")',
            },
            month: {
              type: 'string',
              description:
                'Trade month 01-12 (e.g., "06" for June). Optional — omit for annual data.',
            },
            limit: {
              type: 'number',
              description: 'Maximum number of records to return (default 20)',
            },
          },
          required: ['hs_code', 'year'],
        },
      },
      {
        name: 'census_exports',
        description:
          'Get US export data by HS commodity code and/or country. Returns export values, quantities, commodity details, and country names from the US Census Bureau.',
        inputSchema: {
          type: 'object',
          properties: {
            hs_code: {
              type: 'string',
              description:
                'HS commodity code at 2, 4, or 6 digit level (e.g., "8471" for computers)',
            },
            country_code: {
              type: 'string',
              description:
                'Census country code (e.g., "5700" for China). Optional — omit for all countries.',
            },
            year: {
              type: 'string',
              description: 'Trade year (e.g., "2024")',
            },
            month: {
              type: 'string',
              description: 'Trade month 01-12. Optional — omit for annual data.',
            },
            limit: {
              type: 'number',
              description: 'Maximum number of records to return (default 20)',
            },
          },
          required: ['hs_code', 'year'],
        },
      },
      {
        name: 'census_trade_balance',
        description:
          'Get the US trade balance (exports minus imports) with a specific country for a given year. Uses end-use commodity categories for aggregate values.',
        inputSchema: {
          type: 'object',
          properties: {
            country_code: {
              type: 'string',
              description:
                'Census country code (e.g., "5700" for China, "2010" for Mexico)',
            },
            year: {
              type: 'string',
              description: 'Trade year (e.g., "2024")',
            },
          },
          required: ['country_code', 'year'],
        },
      },
      {
        name: 'census_trade_trends',
        description:
          'Get monthly US trade trends over a period. Shows how trade values change month by month for a commodity and/or country.',
        inputSchema: {
          type: 'object',
          properties: {
            hs_code: {
              type: 'string',
              description: 'HS commodity code. Optional — omit for aggregate trade.',
            },
            country_code: {
              type: 'string',
              description: 'Census country code. Optional — omit for all countries.',
            },
            start_year: {
              type: 'string',
              description: 'Start year (e.g., "2022")',
            },
            end_year: {
              type: 'string',
              description: 'End year (e.g., "2024")',
            },
          },
          required: ['start_year', 'end_year'],
        },
      },
    ];
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<ToolResult> {
    try {
      switch (name) {
        case 'census_imports':
          return await this.getImports(
            args.hs_code as string,
            args.year as string,
            args.country_code as string | undefined,
            args.month as string | undefined,
            (args.limit as number) ?? 20,
          );
        case 'census_exports':
          return await this.getExports(
            args.hs_code as string,
            args.year as string,
            args.country_code as string | undefined,
            args.month as string | undefined,
            (args.limit as number) ?? 20,
          );
        case 'census_trade_balance':
          return await this.getTradeBalance(
            args.country_code as string,
            args.year as string,
          );
        case 'census_trade_trends':
          return await this.getTradeTrends(
            args.start_year as string,
            args.end_year as string,
            args.hs_code as string | undefined,
            args.country_code as string | undefined,
          );
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

  private commLvl(hsCode: string): string {
    if (hsCode.length <= 2) return 'HS2';
    if (hsCode.length <= 4) return 'HS4';
    return 'HS6';
  }

  private async fetchCensus(
    path: string,
    params: Record<string, string>,
  ): Promise<CensusResponse> {
    const url = new URL(`${this.baseUrl}/${path}`);
    for (const [key, value] of Object.entries(params)) {
      url.searchParams.set(key, value);
    }

    const response = await this.fetchWithRetry(url.toString(), {
      method: 'GET',
      headers: { Accept: 'application/json' },
    });

    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      throw new Error(`Census API error: ${response.status} ${response.statusText} — ${errText}`);
    }

    const data = (await response.json()) as CensusResponse;
    if (!Array.isArray(data) || data.length < 2) {
      throw new Error('Census API returned no data for this query');
    }
    return data;
  }

  private parseRows(
    data: CensusResponse,
    limit = 20,
  ): Record<string, string>[] {
    const headers = data[0];
    const rows = data.slice(1, limit + 1);
    return rows.map((row) => {
      const obj: Record<string, string> = {};
      headers.forEach((h, i) => {
        obj[h] = row[i];
      });
      return obj;
    });
  }

  private async getImports(
    hsCode: string,
    year: string,
    countryCode?: string,
    month?: string,
    limit = 20,
  ): Promise<ToolResult> {
    const params: Record<string, string> = {
      get: 'GEN_VAL_MO,GEN_QY1_MO,I_COMMODITY,CTY_CODE,CTY_NAME',
      COMM_LVL: this.commLvl(hsCode),
      I_COMMODITY: hsCode,
      time: month ? `${year}-${month}` : year,
    };
    if (countryCode) params.CTY_CODE = countryCode;

    const data = await this.fetchCensus('imports/hs', params);
    const records = this.parseRows(data, limit);

    const result = {
      type: 'US Imports',
      hs_code: hsCode,
      period: month ? `${year}-${month}` : year,
      count: records.length,
      records: records.map((r) => ({
        commodity_code: r.I_COMMODITY,
        country_code: r.CTY_CODE,
        country_name: r.CTY_NAME,
        import_value_usd: Number(r.GEN_VAL_MO) || 0,
        quantity: Number(r.GEN_QY1_MO) || 0,
        period: r.time,
      })),
    };

    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }

  private async getExports(
    hsCode: string,
    year: string,
    countryCode?: string,
    month?: string,
    limit = 20,
  ): Promise<ToolResult> {
    const params: Record<string, string> = {
      get: 'ALL_VAL_MO,QTY_1_MO,E_COMMODITY,CTY_CODE,CTY_NAME',
      COMM_LVL: this.commLvl(hsCode),
      E_COMMODITY: hsCode,
      time: month ? `${year}-${month}` : year,
    };
    if (countryCode) params.CTY_CODE = countryCode;

    const data = await this.fetchCensus('exports/hs', params);
    const records = this.parseRows(data, limit);

    const result = {
      type: 'US Exports',
      hs_code: hsCode,
      period: month ? `${year}-${month}` : year,
      count: records.length,
      records: records.map((r) => ({
        commodity_code: r.E_COMMODITY,
        country_code: r.CTY_CODE,
        country_name: r.CTY_NAME,
        export_value_usd: Number(r.ALL_VAL_MO) || 0,
        quantity: Number(r.QTY_1_MO) || 0,
        period: r.time,
      })),
    };

    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }

  private async getTradeBalance(
    countryCode: string,
    year: string,
  ): Promise<ToolResult> {
    const [importsData, exportsData] = await Promise.all([
      this.fetchCensus('imports/enduse', {
        get: 'GEN_VAL_YR,CTY_CODE,CTY_NAME',
        CTY_CODE: countryCode,
        time: year,
      }),
      this.fetchCensus('exports/enduse', {
        get: 'ALL_VAL_YR,CTY_CODE,CTY_NAME',
        CTY_CODE: countryCode,
        time: year,
      }),
    ]);

    const importRows = this.parseRows(importsData);
    const exportRows = this.parseRows(exportsData);

    const totalImports = importRows.reduce(
      (sum, r) => sum + (Number(r.GEN_VAL_YR) || 0),
      0,
    );
    const totalExports = exportRows.reduce(
      (sum, r) => sum + (Number(r.ALL_VAL_YR) || 0),
      0,
    );
    const balance = totalExports - totalImports;
    const countryName =
      importRows[0]?.CTY_NAME ?? exportRows[0]?.CTY_NAME ?? countryCode;

    const result = {
      country: countryName,
      country_code: countryCode,
      year,
      total_imports_usd: totalImports,
      total_exports_usd: totalExports,
      trade_balance_usd: balance,
      deficit_or_surplus: balance >= 0 ? 'surplus' : 'deficit',
    };

    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }

  private async getTradeTrends(
    startYear: string,
    endYear: string,
    hsCode?: string,
    countryCode?: string,
  ): Promise<ToolResult> {
    const startYr = parseInt(startYear, 10);
    const endYr = parseInt(endYear, 10);
    if (endYr - startYr > 5) {
      throw new Error('Date range too large. Maximum 5 year span supported.');
    }

    const timeRange = `from ${startYear} to ${endYear}`;

    const importParams: Record<string, string> = {
      get: 'GEN_VAL_MO,CTY_CODE,CTY_NAME,time',
      time: timeRange,
    };
    const exportParams: Record<string, string> = {
      get: 'ALL_VAL_MO,CTY_CODE,CTY_NAME,time',
      time: timeRange,
    };

    if (hsCode) {
      const commLvl = this.commLvl(hsCode);
      importParams.COMM_LVL = commLvl;
      importParams.I_COMMODITY = hsCode;
      exportParams.COMM_LVL = commLvl;
      exportParams.E_COMMODITY = hsCode;
    }
    if (countryCode) {
      importParams.CTY_CODE = countryCode;
      exportParams.CTY_CODE = countryCode;
    }

    const [importsData, exportsData] = await Promise.all([
      this.fetchCensus('imports/hs', importParams).catch(() => null),
      this.fetchCensus('exports/hs', exportParams).catch(() => null),
    ]);

    const importRecords = importsData ? this.parseRows(importsData, 200) : [];
    const exportRecords = exportsData ? this.parseRows(exportsData, 200) : [];

    const monthlyData: Record<string, { imports: number; exports: number }> = {};

    for (const r of importRecords) {
      const period = r.time;
      if (!monthlyData[period]) monthlyData[period] = { imports: 0, exports: 0 };
      monthlyData[period].imports += Number(r.GEN_VAL_MO) || 0;
    }

    for (const r of exportRecords) {
      const period = r.time;
      if (!monthlyData[period]) monthlyData[period] = { imports: 0, exports: 0 };
      monthlyData[period].exports += Number(r.ALL_VAL_MO) || 0;
    }

    const trends = Object.entries(monthlyData)
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([period, values]) => ({
        period,
        imports_usd: values.imports,
        exports_usd: values.exports,
        balance_usd: values.exports - values.imports,
      }));

    const result = {
      start_year: startYear,
      end_year: endYear,
      hs_code: hsCode ?? 'all',
      country_code: countryCode ?? 'all',
      months: trends.length,
      trends,
    };

    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }
}
