/**
 * BLS (Bureau of Labor Statistics) MCP Adapter
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

// No vendor-published official MCP found. Native REST adapter built directly
// against the public BLS API v2. No gateway or proxy is involved.
//
// Base URL: https://api.bls.gov/publicAPI/v2/timeseries/data/
// Auth: None required for basic access. Optional BLS registration key for higher rate limits.
// Docs: https://www.bls.gov/developers/api_signature_v2.htm
// Rate limits: Unauthenticated: 25 queries/day, 10 series per query, 20-year range.
//              Registered key: 500 queries/day, 50 series per query, 20-year range.

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

interface BLSConfig {
  /** Optional BLS registration key (increases daily rate limits) */
  apiKey?: string;
  /** Optional base URL override */
  baseUrl?: string;
}

interface SeriesEntry {
  id: string;
  title: string;
  category: string;
  description: string;
}

// ── Curated series catalog ──────────────────────────────────────────────────

const CURATED_SERIES: SeriesEntry[] = [
  // Employment
  { id: 'CES0000000001', title: 'Total Nonfarm Employment', category: 'employment', description: 'Total nonfarm payroll employment (seasonally adjusted), the headline jobs number from the monthly Employment Situation report.' },
  { id: 'LNS14000000', title: 'Unemployment Rate', category: 'employment', description: 'Civilian unemployment rate (seasonally adjusted), percentage of labor force that is unemployed.' },
  { id: 'LNS11300000', title: 'Labor Force Participation Rate', category: 'employment', description: 'Civilian labor force participation rate (seasonally adjusted).' },
  { id: 'CES2000000001', title: 'Construction Employment', category: 'employment', description: 'Total construction sector employment (seasonally adjusted). Key indicator for housing construction activity.' },
  { id: 'CES2023610001', title: 'Residential Building Construction Employment', category: 'housing', description: 'Employment in residential building construction (NAICS 2361).' },
  { id: 'CES2023800001', title: 'Specialty Trade Contractors Employment', category: 'housing', description: 'Employment in specialty trade contractors (NAICS 238), includes plumbing, electrical, HVAC for housing.' },
  { id: 'JTS000000000000000HIR', title: 'JOLTS Total Hires', category: 'employment', description: 'Total hires from the Job Openings and Labor Turnover Survey (JOLTS).' },
  { id: 'JTS000000000000000JOL', title: 'JOLTS Job Openings', category: 'employment', description: 'Total job openings from JOLTS.' },
  { id: 'JTS000000000000000QUR', title: 'JOLTS Quits Rate', category: 'employment', description: 'Total quits rate from JOLTS, a measure of worker confidence.' },
  { id: 'CES0500000003', title: 'Average Hourly Earnings (Private)', category: 'wages', description: 'Average hourly earnings of all employees on private nonfarm payrolls (seasonally adjusted).' },
  // Prices / CPI
  { id: 'CUUR0000SA0', title: 'CPI-U All Items', category: 'prices', description: 'Consumer Price Index for All Urban Consumers, all items (not seasonally adjusted). The headline inflation measure.' },
  { id: 'CUUR0000SA0L1E', title: 'CPI-U All Items Less Food & Energy', category: 'prices', description: 'Core CPI excluding food and energy (not seasonally adjusted).' },
  { id: 'CUUR0000SEHA', title: 'CPI-U Rent of Primary Residence', category: 'housing', description: 'CPI for rent of primary residence (not seasonally adjusted). Key housing cost component.' },
  { id: 'CUUR0000SEHC', title: 'CPI-U Owners Equivalent Rent', category: 'housing', description: "CPI for owners' equivalent rent of residences (not seasonally adjusted). Largest single component of CPI." },
  { id: 'CUUR0000SAH1', title: 'CPI-U Shelter', category: 'housing', description: "CPI for shelter (not seasonally adjusted). Covers rent, owners' equivalent rent, lodging." },
  { id: 'CUUR0000SEHF01', title: 'CPI-U Electricity', category: 'housing', description: 'CPI for electricity (not seasonally adjusted). Housing utility cost.' },
  { id: 'CUUR0000SEHF02', title: 'CPI-U Piped Gas', category: 'housing', description: 'CPI for utility (piped) gas service (not seasonally adjusted).' },
  // Producer Prices
  { id: 'PCU236211236211', title: 'PPI Residential Construction', category: 'housing', description: 'Producer Price Index for new single-family residential construction (general contractors).' },
  { id: 'WPU081', title: 'PPI Lumber & Wood Products', category: 'housing', description: 'Producer Price Index for lumber and wood products. Key input cost for housing construction.' },
  // Productivity
  { id: 'PRS85006092', title: 'Nonfarm Business Labor Productivity', category: 'productivity', description: 'Output per hour of all persons in the nonfarm business sector (seasonally adjusted).' },
  { id: 'PRS85006112', title: 'Nonfarm Business Unit Labor Costs', category: 'productivity', description: 'Unit labor costs in the nonfarm business sector (seasonally adjusted).' },
];

export class BLSMCPServer extends MCPAdapterBase {
  private readonly apiKey: string | undefined;
  private readonly baseUrl: string;

  constructor(config: BLSConfig = {}) {
    super();
    if (config && typeof config !== 'object') {
      throw new Error('BLS: configuration must be an object');
    }
    this.apiKey = config.apiKey ?? undefined;
    this.baseUrl = config.baseUrl ?? 'https://api.bls.gov/publicAPI/v2/timeseries/data/';
  }

  static catalog() {
    return {
      name: 'bls',
      displayName: 'Bureau of Labor Statistics (BLS)',
      version: '1.0.0',
      category: 'government',
      keywords: [
        'bls', 'bureau of labor statistics', 'employment', 'unemployment',
        'jobs', 'payroll', 'labor', 'cpi', 'inflation', 'consumer price index',
        'wages', 'productivity', 'ppi', 'producer price', 'jolts',
        'housing', 'rent', 'shelter', 'construction', 'economic data',
        'time series', 'federal statistics',
      ],
      toolNames: ['bls_get_series', 'bls_search', 'bls_latest', 'bls_popular_series'],
      description: 'Bureau of Labor Statistics public data API v2: fetch employment, CPI/inflation, wages, productivity, and housing-related time series; search a curated catalog of popular series; and retrieve the most recent data point for any BLS series.',
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
        name: 'bls_get_series',
        description: 'Get time series data from the Bureau of Labor Statistics for one or more series. Supports employment, CPI/inflation, wages, productivity, and housing-related series.',
        inputSchema: {
          type: 'object',
          properties: {
            series_id: {
              type: 'string',
              description: 'BLS series ID (e.g., "LNS14000000" for unemployment rate). For multiple series, comma-separate them (e.g., "LNS14000000,CES0000000001").',
            },
            start_year: {
              type: 'string',
              description: 'Start year (e.g., "2023"). Default: current year minus 2.',
            },
            end_year: {
              type: 'string',
              description: 'End year (e.g., "2024"). Default: current year.',
            },
          },
          required: ['series_id'],
        },
      },
      {
        name: 'bls_search',
        description: 'Search for BLS series IDs by keyword from a curated catalog of popular housing, employment, wages, prices, and productivity series. Returns matching series IDs with descriptions.',
        inputSchema: {
          type: 'object',
          properties: {
            keyword: {
              type: 'string',
              description: 'Keyword to search for (e.g., "rent", "construction", "unemployment", "CPI", "housing")',
            },
          },
          required: ['keyword'],
        },
      },
      {
        name: 'bls_latest',
        description: 'Get just the most recent data point for a BLS series. Useful for quick current-value lookups.',
        inputSchema: {
          type: 'object',
          properties: {
            series_id: {
              type: 'string',
              description: 'BLS series ID (e.g., "LNS14000000")',
            },
          },
          required: ['series_id'],
        },
      },
      {
        name: 'bls_popular_series',
        description: 'List all curated popular BLS series with IDs and descriptions, organized by category (housing, employment, prices, wages, productivity). Use this to discover available series.',
        inputSchema: {
          type: 'object',
          properties: {
            category: {
              type: 'string',
              description: 'Filter by category: housing, employment, prices, wages, productivity (optional, returns all if omitted)',
            },
          },
        },
      },
    ];
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<ToolResult> {
    try {
      switch (name) {
        case 'bls_get_series':    return this.getSeriesData(args);
        case 'bls_search':        return this.searchSeries(args);
        case 'bls_latest':        return this.getLatest(args);
        case 'bls_popular_series': return this.listPopularSeries(args);
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

  private async blsFetch(
    seriesIds: string[],
    opts: { startYear?: string; endYear?: string; latest?: boolean },
  ): Promise<unknown> {
    const currentYear = new Date().getFullYear();
    const body: Record<string, unknown> = {
      seriesid: seriesIds,
      startyear: opts.startYear ?? String(currentYear - 2),
      endyear: opts.endYear ?? String(currentYear),
    };
    if (opts.latest) body.latest = true;
    if (this.apiKey) body.registrationkey = this.apiKey;

    const response = await this.fetchWithRetry(this.baseUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });

    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      throw new Error(`BLS API error (${response.status}): ${errText}`);
    }

    const data = await response.json() as {
      status: string;
      message?: string[];
      Results: {
        series: Array<{
          seriesID: string;
          data: Array<{
            year: string;
            period: string;
            periodName: string;
            value: string;
            latest?: string;
          }>;
        }>;
      };
    };

    if (data.status === 'REQUEST_NOT_PROCESSED') {
      throw new Error(`BLS API request not processed: ${data.message?.join('; ') ?? 'Unknown error'}`);
    }

    return data;
  }

  private async getSeriesData(args: Record<string, unknown>): Promise<ToolResult> {
    const rawIds = args.series_id as string;
    if (!rawIds) {
      return { content: [{ type: 'text', text: 'series_id is required' }], isError: true };
    }
    const seriesIds = rawIds.split(',').map((s) => s.trim()).filter(Boolean);
    if (seriesIds.length === 0) {
      return { content: [{ type: 'text', text: 'At least one series_id is required' }], isError: true };
    }
    if (seriesIds.length > 50) {
      return { content: [{ type: 'text', text: 'Maximum 50 series per request' }], isError: true };
    }

    const raw = await this.blsFetch(seriesIds, {
      startYear: args.start_year as string | undefined,
      endYear: args.end_year as string | undefined,
    }) as {
      status: string;
      Results: { series: Array<{ seriesID: string; data: Array<{ year: string; period: string; periodName: string; value: string; latest?: string }> }> };
    };

    const result = {
      status: raw.status,
      series: raw.Results.series.map((s) => ({
        series_id: s.seriesID,
        data: s.data.map((d) => ({
          year: d.year,
          period: d.period,
          period_name: d.periodName,
          value: d.value,
          latest: d.latest === 'true',
        })),
      })),
    };

    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }

  private searchSeries(args: Record<string, unknown>): ToolResult {
    const keyword = args.keyword as string;
    if (!keyword) {
      return { content: [{ type: 'text', text: 'keyword is required' }], isError: true };
    }
    const lower = keyword.toLowerCase();
    const matches = CURATED_SERIES.filter(
      (s) =>
        s.title.toLowerCase().includes(lower) ||
        s.description.toLowerCase().includes(lower) ||
        s.category.toLowerCase().includes(lower) ||
        s.id.toLowerCase().includes(lower),
    );

    const result = {
      keyword,
      total_matches: matches.length,
      series: matches.map((s) => ({
        series_id: s.id,
        title: s.title,
        category: s.category,
        description: s.description,
      })),
      note: matches.length === 0
        ? 'No matches in curated catalog. Try broader keywords or use bls_popular_series to browse all available series. You can also use any valid BLS series ID directly with bls_get_series.'
        : undefined,
    };

    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }

  private async getLatest(args: Record<string, unknown>): Promise<ToolResult> {
    const seriesId = args.series_id as string;
    if (!seriesId) {
      return { content: [{ type: 'text', text: 'series_id is required' }], isError: true };
    }

    const raw = await this.blsFetch([seriesId], { latest: true }) as {
      Results: { series: Array<{ seriesID: string; data: Array<{ year: string; period: string; periodName: string; value: string }> }> };
    };

    const series = raw.Results.series[0];
    if (!series || series.data.length === 0) {
      return { content: [{ type: 'text', text: `No data returned for series: ${seriesId}` }], isError: true };
    }

    const latest = series.data[0];
    const catalogEntry = CURATED_SERIES.find((s) => s.id === seriesId);

    const result = {
      series_id: series.seriesID,
      title: catalogEntry?.title ?? null,
      latest: {
        year: latest.year,
        period: latest.period,
        period_name: latest.periodName,
        value: latest.value,
      },
    };

    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }

  private listPopularSeries(args: Record<string, unknown>): ToolResult {
    const category = args.category as string | undefined;
    const filtered = category
      ? CURATED_SERIES.filter((s) => s.category.toLowerCase() === category.toLowerCase())
      : CURATED_SERIES;

    const grouped: Record<string, Array<{ series_id: string; title: string; description: string }>> = {};
    for (const s of filtered) {
      if (!grouped[s.category]) grouped[s.category] = [];
      grouped[s.category].push({
        series_id: s.id,
        title: s.title,
        description: s.description,
      });
    }

    const result = {
      filter_category: category ?? null,
      total_series: filtered.length,
      categories: grouped,
    };

    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }
}
