/**
 * Statistics Canada (StatCan) WDS REST Adapter
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

// Upstream: Statistics Canada Web Data Service (WDS)
// Base URL: https://www150.statcan.gc.ca/t1/wds/rest
// Auth: none — public open-data API
// Docs: https://www.statcan.gc.ca/en/developers/wds/user-guide
// Category: government
//
// Tools:
//   list_cubes           — lean list of all available cubes (~3,000)
//   get_cube_metadata    — full metadata: dimensions, members, frequency, geography
//   get_latest_data      — recent N observations for a coordinate
//   get_changed_series   — series changed on a given date (default today)
//   get_csv_download_url — pre-built download URL for a full cube CSV

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

const BASE_URL = 'https://www150.statcan.gc.ca/t1/wds/rest';

export class StatCanMCPServer extends MCPAdapterBase {
  private readonly baseUrl: string;

  constructor(config?: { baseUrl?: string }) {
    super();
    if (config === null) { throw new Error('StatCanMCPServer: configuration object is required when provided'); }
    this.baseUrl = config?.baseUrl ?? BASE_URL;
  }

  static catalog() {
    return {
      name: 'statscan',
      displayName: 'Statistics Canada (StatCan) WDS',
      version: '1.0.0',
      category: 'government' as const,
      keywords: [
        'statscan', 'statistics canada', 'statcan', 'canada', 'canadian',
        'cpi', 'gdp', 'labour force', 'trade', 'demographics', 'healthcare',
        'environment', 'socioeconomic', 'cansim', 'wds', 'open data',
        'official statistics', 'cubes', 'time series', 'national accounts',
      ],
      toolNames: [
        'list_cubes',
        'get_cube_metadata',
        'get_latest_data',
        'get_changed_series',
        'get_csv_download_url',
      ],
      description:
        'Statistics Canada Web Data Service: list and query official Canadian statistical cubes covering CPI, GDP, labour, trade, demographics, healthcare, and more. No authentication required.',
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
        name: 'list_cubes',
        description:
          'List all available cubes (lean: productId + title + cansim + dimension count + release date). Use the productId with the other tools. Response is large (~3,000 cubes) — agents should filter client-side or cache.',
        inputSchema: {
          type: 'object',
          properties: {},
          required: [],
        },
      },
      {
        name: 'get_cube_metadata',
        description:
          'Fetch full metadata for a cube: dimensions, member trees (e.g., "Goods-producing industries", "Services-producing industries"), frequency, geography, last release. Use to figure out a coordinate string for get_latest_data.',
        inputSchema: {
          type: 'object',
          properties: {
            product_id: {
              type: 'number',
              description: 'Cube product ID (8-digit, e.g., 36100434 = quarterly GDP)',
            },
          },
          required: ['product_id'],
        },
      },
      {
        name: 'get_latest_data',
        description:
          'Get the latest N observations for a specific series within a cube. coordinate is a 10-position dot-separated string where each position indexes into a dimension (use get_cube_metadata to map members → positions). Trailing zeros for unused dimensions.',
        inputSchema: {
          type: 'object',
          properties: {
            product_id: {
              type: 'number',
              description: 'Cube product ID',
            },
            coordinate: {
              type: 'string',
              description: '10-position coordinate (e.g., "1.2.0.0.0.0.0.0.0.0")',
            },
            n_periods: {
              type: 'number',
              description: 'Latest N periods (default 12)',
            },
          },
          required: ['product_id', 'coordinate'],
        },
      },
      {
        name: 'get_changed_series',
        description:
          'List of series that changed (new release) on a given date. Default: today. Useful to detect updated cubes for scheduled refreshes.',
        inputSchema: {
          type: 'object',
          properties: {
            date: {
              type: 'string',
              description: 'YYYY-MM-DD (default today)',
            },
          },
          required: [],
        },
      },
      {
        name: 'get_csv_download_url',
        description:
          "Return the StatCan-hosted URL for the full cube as a CSV download. Doesn't fetch the file — gives a direct URL agents can hand to a downloader.",
        inputSchema: {
          type: 'object',
          properties: {
            product_id: {
              type: 'number',
              description: 'Cube product ID',
            },
            language: {
              type: 'string',
              description: 'en | fr (default en)',
            },
          },
          required: ['product_id'],
        },
      },
    ];
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<ToolResult> {
    try {
      switch (name) {
        case 'list_cubes':
          return this.listCubes();
        case 'get_cube_metadata':
          return this.getCubeMetadata(this.requireNum(args, 'product_id', '36100434'));
        case 'get_latest_data':
          return this.getLatestData(
            this.requireNum(args, 'product_id', '36100434'),
            this.requireStr(args, 'coordinate', '"1.1.1.0.0.0.0.0.0.0"'),
            typeof args.n_periods === 'number' ? args.n_periods : 12,
          );
        case 'get_changed_series':
          return this.getChangedSeries(
            typeof args.date === 'string' ? args.date : undefined,
          );
        case 'get_csv_download_url':
          return this.getCsvDownloadUrl(
            this.requireNum(args, 'product_id', '36100434'),
            typeof args.language === 'string' ? args.language : 'en',
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

  private requireStr(args: Record<string, unknown>, key: string, example: string): string {
    const v = args[key];
    if (typeof v !== 'string' || !v.trim()) {
      throw new Error(`Required argument "${key}" is missing or empty. Pass a string like ${example}.`);
    }
    return v;
  }

  private requireNum(args: Record<string, unknown>, key: string, example: string): number {
    const v = args[key];
    if (typeof v !== 'number' || !Number.isFinite(v)) {
      throw new Error(`Required argument "${key}" must be a number. Example: ${example}.`);
    }
    return v;
  }

  private async wdsGet<T>(path: string): Promise<T> {
    const url = `${this.baseUrl}${path}`;
    const response = await this.fetchWithRetry(url, {
      method: 'GET',
      headers: { Accept: 'application/json' },
    });
    if (!response.ok) {
      const body = await response.text().catch(() => response.statusText);
      throw new Error(`StatCan error: ${response.status} ${body.slice(0, 200)}`);
    }
    return response.json() as Promise<T>;
  }

  private async wdsPost<T>(path: string, body: unknown): Promise<T> {
    const url = `${this.baseUrl}${path}`;
    const response = await this.fetchWithRetry(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Accept: 'application/json',
      },
      body: JSON.stringify(body),
    });
    if (!response.ok) {
      const text = await response.text().catch(() => response.statusText);
      throw new Error(`StatCan error: ${response.status} ${text.slice(0, 200)}`);
    }
    return response.json() as Promise<T>;
  }

  // ── Tool implementations ─────────────────────────────────────────────────────

  private async listCubes(): Promise<ToolResult> {
    interface WdsLiteCube {
      productId?: number;
      cansimId?: string | null;
      cubeTitleEn?: string;
      cubeTitleFr?: string;
      cubeStartDate?: string;
      cubeEndDate?: string;
      releaseTime?: string;
      archived?: string;
      subjectCode?: string[];
      dimensions?: { dimensionPositionId?: number; dimensionNameEn?: string }[];
    }
    const data = await this.wdsGet<WdsLiteCube[]>('/getAllCubesListLite');
    const result = {
      count: data.length,
      cubes: data.map((c) => ({
        product_id: c.productId ?? null,
        cansim_id: c.cansimId ?? null,
        title_en: c.cubeTitleEn ?? null,
        title_fr: c.cubeTitleFr ?? null,
        start_date: c.cubeStartDate ?? null,
        end_date: c.cubeEndDate ?? null,
        release_time: c.releaseTime ?? null,
        archived: c.archived ?? null,
        subject_codes: c.subjectCode ?? [],
        dimension_count: c.dimensions?.length ?? null,
      })),
    };
    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }

  private async getCubeMetadata(productId: number): Promise<ToolResult> {
    interface CubeMetadataResp {
      status?: string;
      object?: {
        productId?: number;
        cansimId?: string;
        cubeTitleEn?: string;
        cubeTitleFr?: string;
        cubeStartDate?: string;
        cubeEndDate?: string;
        nbSeriesCube?: number;
        nbDatapointsCube?: number;
        archiveStatusEn?: string;
        frequencyCode?: number;
        dimension?: {
          dimensionPositionId?: number;
          dimensionNameEn?: string;
          hasUom?: boolean;
          member?: { memberId?: number; memberNameEn?: string }[];
        }[];
      };
    }
    const data = await this.wdsPost<CubeMetadataResp[]>('/getCubeMetadata', [{ productId }]);
    const first = data?.[0];
    if (first?.status !== 'SUCCESS' || !first.object) {
      throw new Error(`StatCan: cube ${productId} not found or restricted`);
    }
    const o = first.object;
    const result = {
      product_id: o.productId ?? productId,
      cansim_id: o.cansimId ?? null,
      title_en: o.cubeTitleEn ?? null,
      title_fr: o.cubeTitleFr ?? null,
      start_date: o.cubeStartDate ?? null,
      end_date: o.cubeEndDate ?? null,
      series_count: o.nbSeriesCube ?? null,
      datapoint_count: o.nbDatapointsCube ?? null,
      frequency_code: o.frequencyCode ?? null,
      archive_status: o.archiveStatusEn ?? null,
      dimensions: (o.dimension ?? []).map((d) => ({
        position: d.dimensionPositionId ?? null,
        name_en: d.dimensionNameEn ?? null,
        has_unit_of_measure: d.hasUom ?? null,
        member_count: d.member?.length ?? null,
        member_sample: (d.member ?? []).slice(0, 10).map((m) => ({
          id: m.memberId ?? null,
          name: m.memberNameEn ?? null,
        })),
      })),
    };
    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }

  private async getLatestData(
    productId: number,
    coordinate: string,
    nPeriods: number,
  ): Promise<ToolResult> {
    interface LatestDataResp {
      status?: string;
      object?: {
        productId?: number;
        coordinate?: string;
        vectorDataPoint?: {
          refPer?: string;
          value?: number | string;
          releaseTime?: string;
          decimals?: number;
        }[];
        vectorId?: number;
        SeriesTitleEn?: string;
        frequencyCode?: number;
      };
    }
    const data = await this.wdsPost<LatestDataResp[]>(
      '/getDataFromCubePidCoordAndLatestNPeriods',
      [{ productId, coordinate, latestN: nPeriods }],
    );
    const first = data?.[0];
    if (first?.status !== 'SUCCESS' || !first.object) {
      throw new Error(`StatCan: no data for productId=${productId} coord=${coordinate}`);
    }
    const o = first.object;
    const result = {
      product_id: o.productId ?? productId,
      coordinate: o.coordinate ?? coordinate,
      series_title: o.SeriesTitleEn ?? null,
      vector_id: o.vectorId ?? null,
      frequency_code: o.frequencyCode ?? null,
      observations: (o.vectorDataPoint ?? []).map((d) => ({
        period: d.refPer ?? null,
        value: d.value != null ? Number(d.value) : null,
        released_at: d.releaseTime ?? null,
      })),
    };
    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }

  private async getChangedSeries(date?: string): Promise<ToolResult> {
    interface ChangedSeriesResp {
      status?: string;
      object?: {
        vectorId?: number;
        productId?: number;
        coordinate?: string;
        releaseTime?: string;
      }[];
    }
    const path = date
      ? `/getChangedSeriesList/${encodeURIComponent(date)}`
      : '/getChangedSeriesList';
    const data = await this.wdsGet<ChangedSeriesResp>(path);
    const result = {
      date: date ?? 'today',
      count: data.object?.length ?? 0,
      series: (data.object ?? []).map((s) => ({
        product_id: s.productId ?? null,
        coordinate: s.coordinate ?? null,
        vector_id: s.vectorId ?? null,
        released_at: s.releaseTime ?? null,
      })),
    };
    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }

  private async getCsvDownloadUrl(productId: number, language: string): Promise<ToolResult> {
    const lang = language === 'fr' ? 'fr' : 'en';
    interface CsvUrlResp {
      status?: string;
      object?: string;
    }
    const data = await this.wdsGet<CsvUrlResp>(
      `/getFullTableDownloadCSV/${productId}/${lang}`,
    );
    const result = {
      product_id: productId,
      language: lang,
      download_url: data.object ?? null,
      status: data.status ?? null,
    };
    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }
}
