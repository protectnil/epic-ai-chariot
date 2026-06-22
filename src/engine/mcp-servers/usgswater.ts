/**
 * USGS Water MCP Adapter
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 *
 * Wraps the USGS National Water Information System (NWIS) REST services directly.
 * Free, no authentication required.
 *
 * Base URL: https://waterservices.usgs.gov/nwis
 * Auth: None (public API)
 * Docs: https://waterservices.usgs.gov/
 * Category: environment
 */

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

const BASE_URL = 'https://waterservices.usgs.gov/nwis';

interface NwisTimeSeries {
  name?: string;
  variable?: { variableName?: { value?: string }; unit?: { unitCode?: string } };
  values?: { value?: { value?: string; dateTime?: string; qualifiers?: string[] }[] }[];
  sourceInfo?: { siteName?: string; siteCode?: { value?: string }[] };
}

interface NwisResponse {
  value?: { timeSeries?: NwisTimeSeries[] };
}

export class USGSWaterMCPServer extends MCPAdapterBase {
  private readonly baseUrl: string;

  constructor(config?: { baseUrl?: string }) {
    super();
    if (config === null) { throw new Error('USGSWaterMCPServer: configuration object is required when provided'); }
    this.baseUrl = config?.baseUrl ?? BASE_URL;
  }

  static catalog() {
    return {
      name: 'usgswater',
      displayName: 'USGS Water (NWIS)',
      version: '1.0.0',
      category: 'environment' as const,
      keywords: [
        'usgs', 'water', 'streamflow', 'discharge', 'gage height',
        'river', 'stream', 'hydrology', 'nwis', 'national water',
        'water level', 'cfs', 'daily mean', 'instantaneous', 'monitoring',
        'flood', 'streamgage', 'hydrological',
      ],
      toolNames: ['get_current', 'search_sites', 'get_daily'],
      description: 'USGS National Water Information System (NWIS): retrieve real-time instantaneous streamflow and gage height, find active stream-gage sites by state, and fetch daily mean streamflow values for any date range — free, no authentication required.',
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
        name: 'get_current',
        description:
          'Get current instantaneous streamflow (discharge, cfs) and gage height (ft) for a USGS monitoring site.',
        inputSchema: {
          type: 'object',
          properties: {
            site_id: {
              type: 'string',
              description: 'USGS site number (e.g., "01646500" for Potomac River at Little Falls, MD)',
            },
          },
          required: ['site_id'],
        },
      },
      {
        name: 'search_sites',
        description:
          'Find active USGS stream-gage sites in a US state that have real-time instantaneous data.',
        inputSchema: {
          type: 'object',
          properties: {
            state: {
              type: 'string',
              description: 'Two-letter US state abbreviation (e.g., "VA", "CA", "TX")',
            },
          },
          required: ['state'],
        },
      },
      {
        name: 'get_daily',
        description:
          'Get daily mean streamflow values for a USGS site over a date range. Dates must be in YYYY-MM-DD format.',
        inputSchema: {
          type: 'object',
          properties: {
            site_id: { type: 'string', description: 'USGS site number' },
            start: { type: 'string', description: 'Start date in YYYY-MM-DD format' },
            end: { type: 'string', description: 'End date in YYYY-MM-DD format' },
          },
          required: ['site_id', 'start', 'end'],
        },
      },
    ];
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<ToolResult> {
    try {
      switch (name) {
        case 'get_current':
          return this.getCurrent(args.site_id as string);
        case 'search_sites':
          return this.searchSites(args.state as string);
        case 'get_daily':
          return this.getDaily(
            args.site_id as string,
            args.start as string,
            args.end as string,
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

  // ── Private helpers ────────────────────────────────────────────────────────

  private async getCurrent(siteId: string): Promise<ToolResult> {
    const params = new URLSearchParams({
      format: 'json',
      sites: siteId,
      parameterCd: '00060,00065',
    });

    const response = await this.fetchWithRetry(
      `${this.baseUrl}/iv/?${params.toString()}`,
      { method: 'GET', headers: { Accept: 'application/json' } },
    );

    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `USGS NWIS error: ${response.status} ${errText}` }],
        isError: true,
      };
    }

    const data = (await response.json()) as NwisResponse;
    const series = data.value?.timeSeries ?? [];

    if (series.length === 0) {
      const result = { site_id: siteId, site_name: null, readings: [] };
      return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
    }

    const siteName = series[0]?.sourceInfo?.siteName ?? null;
    const readings = series.map((ts) => {
      const latestValue = ts.values?.[0]?.value?.[0];
      return {
        parameter: ts.variable?.variableName?.value ?? ts.name ?? null,
        unit: ts.variable?.unit?.unitCode ?? null,
        value: latestValue?.value != null ? parseFloat(latestValue.value) : null,
        date_time: latestValue?.dateTime ?? null,
        qualifiers: latestValue?.qualifiers ?? [],
      };
    });

    const result = { site_id: siteId, site_name: siteName, readings };
    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }

  private async searchSites(state: string): Promise<ToolResult> {
    const params = new URLSearchParams({
      format: 'json',
      stateCD: state.toUpperCase(),
      siteType: 'ST',
      hasDataTypeCd: 'iv',
    });

    const response = await this.fetchWithRetry(
      `${this.baseUrl}/site/?${params.toString()}`,
      { method: 'GET', headers: { Accept: 'application/json' } },
    );

    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `USGS NWIS error: ${response.status} ${errText}` }],
        isError: true,
      };
    }

    const data = (await response.json()) as {
      value?: {
        sites?: {
          siteName?: string;
          siteCode?: { value?: string; network?: string }[];
          geoLocation?: {
            geogLocation?: { latitude?: number; longitude?: number };
            srs?: string;
          };
          hucCd?: string;
          drainageAreaCd?: string;
        }[];
      };
    };

    const sites = data.value?.sites ?? [];
    const result = {
      state: state.toUpperCase(),
      count: sites.length,
      sites: sites.map((s) => ({
        site_id: s.siteCode?.[0]?.value ?? null,
        site_name: s.siteName ?? null,
        latitude: s.geoLocation?.geogLocation?.latitude ?? null,
        longitude: s.geoLocation?.geogLocation?.longitude ?? null,
        huc: s.hucCd ?? null,
        drainage_area_sqmi: s.drainageAreaCd ? parseFloat(s.drainageAreaCd) : null,
      })),
    };

    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }

  private async getDaily(siteId: string, start: string, end: string): Promise<ToolResult> {
    const params = new URLSearchParams({
      format: 'json',
      sites: siteId,
      startDT: start,
      endDT: end,
    });

    const response = await this.fetchWithRetry(
      `${this.baseUrl}/dv/?${params.toString()}`,
      { method: 'GET', headers: { Accept: 'application/json' } },
    );

    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `USGS NWIS error: ${response.status} ${errText}` }],
        isError: true,
      };
    }

    const data = (await response.json()) as NwisResponse;
    const series = data.value?.timeSeries ?? [];

    if (series.length === 0) {
      const result = { site_id: siteId, start, end, series: [] };
      return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
    }

    const siteName = series[0]?.sourceInfo?.siteName ?? null;
    const seriesData = series.map((ts) => ({
      parameter: ts.variable?.variableName?.value ?? null,
      unit: ts.variable?.unit?.unitCode ?? null,
      values: (ts.values?.[0]?.value ?? []).map((v) => ({
        date: v.dateTime ?? null,
        value: v.value != null ? parseFloat(v.value) : null,
        qualifiers: v.qualifiers ?? [],
      })),
    }));

    const result = { site_id: siteId, site_name: siteName, start, end, series: seriesData };
    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }
}
