/**
 * Econdata MCP Adapter — BLS (Bureau of Labor Statistics) Public API v2
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 *
 * Base URL: https://api.bls.gov/publicAPI/v2
 * Auth: None (public API)
 * Docs: https://www.bls.gov/developers/api_signature_v2.htm
 * Category: finance
 * Rate limits: 25 queries/day (unauthenticated); 500/day with API key
 */

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

const BASE_URL = 'https://api.bls.gov/publicAPI/v2';

const INDUSTRY_SERIES: Record<string, string> = {
  total_nonfarm: 'CES0000000001',
  manufacturing: 'CES3000000001',
  construction:  'CES2000000001',
  retail:        'CES4200000001',
  financial:     'CES5500000001',
  government:    'CES9000000001',
};

// eslint-disable-next-line @typescript-eslint/no-empty-object-type
interface EcondataConfig {}

export class EcondataMCPServer extends MCPAdapterBase {
  private readonly baseUrl: string;

  constructor(_config?: EcondataConfig) {
    super();
    this.baseUrl = BASE_URL;
  }

  static catalog() {
    return {
      name: 'econdata',
      displayName: 'Econdata — BLS Economic Data',
      version: '1.0.0',
      category: 'finance',
      keywords: [
        'bls', 'bureau of labor statistics', 'economics', 'economic data',
        'unemployment', 'cpi', 'consumer price index', 'inflation',
        'employment', 'payroll', 'labor', 'time series', 'macroeconomics',
        'us economy', 'jobs', 'nonfarm payroll', 'industry employment',
      ],
      toolNames: [
        'get_series',
        'get_unemployment',
        'get_cpi',
        'get_employment_by_industry',
      ],
      description:
        'Econdata: fetch US economic time series from the Bureau of Labor Statistics public API v2. ' +
        'Retrieve unemployment rates, CPI, non-farm payroll employment by industry, or any arbitrary BLS series by ID.',
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
        name: 'get_series',
        description:
          'Fetch a BLS time series by series ID. Returns data points with year, period, and value. ' +
          'Example series IDs: "CUUR0000SA0" (CPI), "LNS14000000" (unemployment rate), "CES0000000001" (total nonfarm employment).',
        inputSchema: {
          type: 'object',
          properties: {
            series_id: {
              type: 'string',
              description: 'BLS series ID (e.g. "CUUR0000SA0" for CPI)',
            },
            start_year: {
              type: 'string',
              description: 'Start year as 4-digit string (e.g. "2020"). Optional.',
            },
            end_year: {
              type: 'string',
              description: 'End year as 4-digit string (e.g. "2024"). Optional.',
            },
          },
          required: ['series_id'],
        },
      },
      {
        name: 'get_unemployment',
        description:
          'Get the US civilian unemployment rate over time (BLS series LNS14000000). ' +
          'Returns year, month, and rate for each period.',
        inputSchema: {
          type: 'object',
          properties: {
            start_year: {
              type: 'string',
              description: 'Start year as 4-digit string (e.g. "2020"). Optional.',
            },
            end_year: {
              type: 'string',
              description: 'End year as 4-digit string (e.g. "2024"). Optional.',
            },
          },
          required: [],
        },
      },
      {
        name: 'get_cpi',
        description:
          'Get the US Consumer Price Index for All Urban Consumers (BLS series CUUR0000SA0). ' +
          'Returns year, month, and index value for each period.',
        inputSchema: {
          type: 'object',
          properties: {
            start_year: {
              type: 'string',
              description: 'Start year as 4-digit string (e.g. "2020"). Optional.',
            },
            end_year: {
              type: 'string',
              description: 'End year as 4-digit string (e.g. "2024"). Optional.',
            },
          },
          required: [],
        },
      },
      {
        name: 'get_employment_by_industry',
        description:
          'Get US non-farm payroll employment figures by industry. ' +
          'Industry options: "total_nonfarm" (default), "manufacturing", "construction", "retail", "financial", "government". ' +
          'Returns employment in thousands.',
        inputSchema: {
          type: 'object',
          properties: {
            industry: {
              type: 'string',
              description:
                'Industry to retrieve. One of: "total_nonfarm", "manufacturing", "construction", ' +
                '"retail", "financial", "government". Defaults to "total_nonfarm".',
            },
            start_year: {
              type: 'string',
              description: 'Start year as 4-digit string (e.g. "2020"). Optional.',
            },
            end_year: {
              type: 'string',
              description: 'End year as 4-digit string (e.g. "2024"). Optional.',
            },
          },
          required: [],
        },
      },
    ];
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<ToolResult> {
    try {
      switch (name) {
        case 'get_series':
          return this.getSeries(
            args.series_id as string,
            args.start_year as string | undefined,
            args.end_year as string | undefined,
          );
        case 'get_unemployment':
          return this.getUnemployment(
            args.start_year as string | undefined,
            args.end_year as string | undefined,
          );
        case 'get_cpi':
          return this.getCpi(
            args.start_year as string | undefined,
            args.end_year as string | undefined,
          );
        case 'get_employment_by_industry':
          return this.getEmploymentByIndustry(
            (args.industry as string | undefined) ?? 'total_nonfarm',
            args.start_year as string | undefined,
            args.end_year as string | undefined,
          );
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

  private async fetchSeries(
    seriesId: string,
    startYear?: string,
    endYear?: string,
  ): Promise<BlsDataPoint[]> {
    const body: Record<string, unknown> = { seriesid: [seriesId] };
    if (startYear) body.startyear = startYear;
    if (endYear)   body.endyear   = endYear;

    const response = await this.fetchWithRetry(
      `${this.baseUrl}/timeseries/data/`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
        body: JSON.stringify(body),
      },
    );

    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      throw new Error(`BLS API error: ${response.status} ${errText}`);
    }

    const data = (await response.json()) as BlsResponse;
    if (data.status !== 'REQUEST_SUCCEEDED') {
      throw new Error(`BLS API error: ${data.message?.join(', ') ?? data.status}`);
    }

    return data.Results?.series[0]?.data ?? [];
  }

  private formatPoint(point: BlsDataPoint) {
    return {
      year:        point.year,
      period:      point.period,
      period_name: point.periodName,
      value:       Number(point.value),
    };
  }

  private async getSeries(
    seriesId: string,
    startYear?: string,
    endYear?: string,
  ): Promise<ToolResult> {
    if (!seriesId) {
      return { content: [{ type: 'text', text: 'series_id is required' }], isError: true };
    }
    const data = await this.fetchSeries(seriesId, startYear, endYear);
    const result = {
      series_id:  seriesId,
      start_year: startYear ?? null,
      end_year:   endYear ?? null,
      total:      data.length,
      data:       data.map(this.formatPoint),
    };
    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }

  private async getUnemployment(startYear?: string, endYear?: string): Promise<ToolResult> {
    const seriesId = 'LNS14000000';
    const data = await this.fetchSeries(seriesId, startYear, endYear);
    const result = {
      series_id:   seriesId,
      description: 'Civilian Unemployment Rate (seasonally adjusted)',
      unit:        'percent',
      start_year:  startYear ?? null,
      end_year:    endYear ?? null,
      total:       data.length,
      data:        data.map((point) => ({
        year:   point.year,
        month:  point.periodName,
        period: point.period,
        rate:   Number(point.value),
      })),
    };
    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }

  private async getCpi(startYear?: string, endYear?: string): Promise<ToolResult> {
    const seriesId = 'CUUR0000SA0';
    const data = await this.fetchSeries(seriesId, startYear, endYear);
    const result = {
      series_id:   seriesId,
      description: 'CPI for All Urban Consumers (not seasonally adjusted)',
      unit:        'index (1982-84=100)',
      start_year:  startYear ?? null,
      end_year:    endYear ?? null,
      total:       data.length,
      data:        data.map((point) => ({
        year:   point.year,
        month:  point.periodName,
        period: point.period,
        value:  Number(point.value),
      })),
    };
    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }

  private async getEmploymentByIndustry(
    industry: string,
    startYear?: string,
    endYear?: string,
  ): Promise<ToolResult> {
    const seriesId = INDUSTRY_SERIES[industry] ?? INDUSTRY_SERIES['total_nonfarm'];
    const data = await this.fetchSeries(seriesId, startYear, endYear);
    const result = {
      series_id:   seriesId,
      industry,
      description: 'All Employees (seasonally adjusted)',
      unit:        'thousands of persons',
      start_year:  startYear ?? null,
      end_year:    endYear ?? null,
      total:       data.length,
      data:        data.map((point) => ({
        year:                 point.year,
        month:                point.periodName,
        period:               point.period,
        employment_thousands: Number(point.value),
      })),
    };
    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }
}

// ── Internal BLS response types ────────────────────────────────────────────

interface BlsDataPoint {
  year:        string;
  period:      string;
  periodName:  string;
  value:       string;
  footnotes:   unknown[];
}

interface BlsSeries {
  seriesID: string;
  data:     BlsDataPoint[];
}

interface BlsResponse {
  status:       string;
  responseTime: number;
  message:      string[];
  Results?: {
    series: BlsSeries[];
  };
}
