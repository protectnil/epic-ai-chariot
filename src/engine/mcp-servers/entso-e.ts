/**
 * ENTSO-E Transparency Platform MCP Adapter
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 *
 * Pan-European electricity TSO data: load, generation, day-ahead prices, cross-border flows.
 * API returns XML; parsed into typed JSON.
 *
 * Base URL: https://web-api.tp.entsoe.eu/api
 * Auth: securityToken query parameter (register at https://transparency.entsoe.eu/ +
 *       email transparency@entsoe.eu to request API access)
 * Docs: https://transparency.entsoe.eu/content/static_content/Static%20content/web%20api/Guide.html
 * Category: energy
 */

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

interface EntsoeConfig {
  securityToken: string;
  baseUrl?: string;
}

export class EntsoeMCPServer extends MCPAdapterBase {
  private readonly securityToken: string;
  private readonly baseUrl: string;

  constructor(config: EntsoeConfig) {
    super();
    if (!config || typeof config !== 'object') {
      throw new Error('ENTSO-E Transparency Platform: configuration object is required');
    }
    for (const __k of (['securityToken'] as Array<keyof typeof config>)) {
      if (config[__k] === undefined || config[__k] === null || (config[__k] as unknown) === '') {
        throw new Error('ENTSO-E Transparency Platform: ' + __k + ' is required');
      }
    }
    this.securityToken = config.securityToken;
    this.baseUrl = config.baseUrl || 'https://web-api.tp.entsoe.eu/api';
  }

  static catalog() {
    return {
      name: 'entso-e',
      displayName: 'ENTSO-E Transparency Platform',
      version: '1.0.0',
      category: 'energy',
      keywords: [
        'entso-e', 'entsoe', 'electricity', 'energy', 'power grid', 'TSO',
        'day-ahead prices', 'electricity prices', 'generation', 'solar', 'wind',
        'nuclear', 'load', 'consumption', 'cross-border flow', 'interconnector',
        'installed capacity', 'bidding zone', 'EIC', 'europe', 'pan-european',
        'transparency platform', 'MWh', 'MW',
      ],
      toolNames: [
        'day_ahead_prices',
        'actual_load',
        'actual_generation_per_type',
        'cross_border_flow',
        'installed_capacity',
      ],
      description:
        'ENTSO-E Transparency Platform: fetch pan-European electricity TSO data including day-ahead auction prices, actual load, generation by production type, cross-border physical flows, and installed generation capacity.',
      type: 'rest' as const,
      auth: {
        inferredModel: 'api-key' as const,
        probeState: 'never-probed' as const,
      },
      author: 'protectnil',
    };
  }

  get tools(): ToolDefinition[] {
    return [
      {
        name: 'day_ahead_prices',
        description:
          'Day-ahead auction prices (€/MWh) per hour for a bidding zone. Period is YYYYMMDDHHmm format (UTC).',
        inputSchema: {
          type: 'object',
          properties: {
            area: {
              type: 'string',
              description: 'Bidding-zone EIC code (e.g. "10YDE-VE-------2" for Germany)',
            },
            period_start: {
              type: 'string',
              description: 'Period start in YYYYMMDDHHmm format (UTC)',
            },
            period_end: {
              type: 'string',
              description: 'Period end in YYYYMMDDHHmm format (UTC)',
            },
          },
          required: ['area', 'period_start', 'period_end'],
        },
      },
      {
        name: 'actual_load',
        description: 'Measured electricity consumption per hour for a bidding zone (MW).',
        inputSchema: {
          type: 'object',
          properties: {
            area: {
              type: 'string',
              description: 'Bidding-zone EIC code',
            },
            period_start: {
              type: 'string',
              description: 'Period start in YYYYMMDDHHmm format (UTC)',
            },
            period_end: {
              type: 'string',
              description: 'Period end in YYYYMMDDHHmm format (UTC)',
            },
          },
          required: ['area', 'period_start', 'period_end'],
        },
      },
      {
        name: 'actual_generation_per_type',
        description:
          'Actual generation per production type (solar, wind, nuclear, gas, etc.) per hour for a bidding zone.',
        inputSchema: {
          type: 'object',
          properties: {
            area: {
              type: 'string',
              description: 'Bidding-zone EIC code',
            },
            period_start: {
              type: 'string',
              description: 'Period start in YYYYMMDDHHmm format (UTC)',
            },
            period_end: {
              type: 'string',
              description: 'Period end in YYYYMMDDHHmm format (UTC)',
            },
          },
          required: ['area', 'period_start', 'period_end'],
        },
      },
      {
        name: 'cross_border_flow',
        description: 'Physical electricity flow across an interconnector from one area to another.',
        inputSchema: {
          type: 'object',
          properties: {
            area_from: {
              type: 'string',
              description: 'Source area EIC code (e.g. "10YDE-VE-------2")',
            },
            area_to: {
              type: 'string',
              description: 'Destination area EIC code (e.g. "10YFR-RTE------C")',
            },
            period_start: {
              type: 'string',
              description: 'Period start in YYYYMMDDHHmm format (UTC)',
            },
            period_end: {
              type: 'string',
              description: 'Period end in YYYYMMDDHHmm format (UTC)',
            },
          },
          required: ['area_from', 'area_to', 'period_start', 'period_end'],
        },
      },
      {
        name: 'installed_capacity',
        description:
          'Year-end installed generation capacity by production type (MW) for a bidding zone.',
        inputSchema: {
          type: 'object',
          properties: {
            area: {
              type: 'string',
              description: 'Bidding-zone EIC code',
            },
            year: {
              type: 'number',
              description: 'Year (e.g. 2024)',
            },
          },
          required: ['area', 'year'],
        },
      },
    ];
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<ToolResult> {
    try {
      switch (name) {
        case 'day_ahead_prices':         return this.dayAheadPrices(args);
        case 'actual_load':              return this.actualLoad(args);
        case 'actual_generation_per_type': return this.actualGenerationPerType(args);
        case 'cross_border_flow':        return this.crossBorderFlow(args);
        case 'installed_capacity':       return this.installedCapacity(args);
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

  // ── Private tool implementations ──────────────────────────────────────────

  private async dayAheadPrices(args: Record<string, unknown>): Promise<ToolResult> {
    return this.entsoeRequest({
      documentType: 'A44',
      in_Domain: this.reqStr(args, 'area'),
      out_Domain: this.reqStr(args, 'area'),
      periodStart: this.reqStr(args, 'period_start'),
      periodEnd: this.reqStr(args, 'period_end'),
    });
  }

  private async actualLoad(args: Record<string, unknown>): Promise<ToolResult> {
    return this.entsoeRequest({
      documentType: 'A65',
      processType: 'A16',
      outBiddingZone_Domain: this.reqStr(args, 'area'),
      periodStart: this.reqStr(args, 'period_start'),
      periodEnd: this.reqStr(args, 'period_end'),
    });
  }

  private async actualGenerationPerType(args: Record<string, unknown>): Promise<ToolResult> {
    return this.entsoeRequest({
      documentType: 'A75',
      processType: 'A16',
      in_Domain: this.reqStr(args, 'area'),
      periodStart: this.reqStr(args, 'period_start'),
      periodEnd: this.reqStr(args, 'period_end'),
    });
  }

  private async crossBorderFlow(args: Record<string, unknown>): Promise<ToolResult> {
    return this.entsoeRequest({
      documentType: 'A11',
      in_Domain: this.reqStr(args, 'area_to'),
      out_Domain: this.reqStr(args, 'area_from'),
      periodStart: this.reqStr(args, 'period_start'),
      periodEnd: this.reqStr(args, 'period_end'),
    });
  }

  private async installedCapacity(args: Record<string, unknown>): Promise<ToolResult> {
    const yr = typeof args.year === 'number' ? args.year : new Date().getUTCFullYear();
    return this.entsoeRequest({
      documentType: 'A68',
      processType: 'A33',
      in_Domain: this.reqStr(args, 'area'),
      periodStart: `${yr}01010000`,
      periodEnd: `${yr}01020000`,
    });
  }

  // ── HTTP helpers ──────────────────────────────────────────────────────────

  private async entsoeRequest(query: Record<string, string>): Promise<ToolResult> {
    const params = new URLSearchParams({ securityToken: this.securityToken, ...query });
    const url = `${this.baseUrl}?${params.toString()}`;

    const response = await this.fetchWithRetry(url, {
      method: 'GET',
      headers: { Accept: 'application/xml' },
    });

    if (response.status === 401) {
      return {
        content: [{ type: 'text', text: 'ENTSO-E: unauthorized — check securityToken' }],
        isError: true,
      };
    }
    if (response.status === 400) {
      const body = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `ENTSO-E bad request: ${body.slice(0, 300)}` }],
        isError: true,
      };
    }
    if (!response.ok) {
      const body = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `ENTSO-E error: ${response.status} ${body.slice(0, 200)}` }],
        isError: true,
      };
    }

    const xml = await response.text();
    const parsed = this.parseEntsoeXml(xml, query);
    return { content: [{ type: 'text', text: this.truncate(parsed) }], isError: false };
  }

  // ── XML parser ────────────────────────────────────────────────────────────

  /**
   * Minimal XML extractor — pulls TimeSeries blocks and their Points
   * without a full XML parser. Returns a structured JSON result with
   * { query, time_series_count, time_series: [...] }.
   */
  private parseEntsoeXml(
    xml: string,
    query: Record<string, string>,
  ): {
    query: Record<string, string>;
    time_series_count: number;
    time_series: Array<{
      mrid: string | null;
      business_type: string | null;
      psr_type: string | null;
      in_domain: string | null;
      out_domain: string | null;
      periods: Array<{
        period_start: string | null;
        period_end: string | null;
        resolution: string | null;
        points: Array<{ position: number; value: number }>;
      }>;
    }>;
  } {
    const tsBlocks = [...xml.matchAll(/<TimeSeries>([\s\S]*?)<\/TimeSeries>/g)].map((m) => m[1]);
    const timeSeries = tsBlocks.map((block) => {
      const mrid = this.firstMatch(block, /<mRID>([^<]+)<\/mRID>/);
      const business = this.firstMatch(block, /<businessType>([^<]+)<\/businessType>/);
      const psrType = this.firstMatch(block, /<psrType>([^<]+)<\/psrType>|<MktPSRType>\s*<psrType>([^<]+)<\/psrType>/);
      const inDomain = this.firstMatch(block, /<in_Domain\.mRID[^>]*>([^<]+)</);
      const outDomain = this.firstMatch(block, /<out_Domain\.mRID[^>]*>([^<]+)</);
      const periodBlocks = [...block.matchAll(/<Period>([\s\S]*?)<\/Period>/g)].map((m) => m[1]);
      const periods = periodBlocks.map((p) => {
        const start = this.firstMatch(p, /<timeInterval>\s*<start>([^<]+)<\/start>/);
        const end = this.firstMatch(p, /<timeInterval>[\s\S]*?<end>([^<]+)<\/end>/);
        const resolution = this.firstMatch(p, /<resolution>([^<]+)<\/resolution>/);
        const points = [
          ...p.matchAll(
            /<Point>\s*<position>(\d+)<\/position>\s*(?:<quantity>([^<]+)<\/quantity>|<price\.amount>([^<]+)<\/price\.amount>)\s*<\/Point>/g,
          ),
        ].map((m) => ({
          position: Number(m[1]),
          value: Number(m[2] ?? m[3]),
        }));
        return { period_start: start, period_end: end, resolution, points };
      });
      return {
        mrid,
        business_type: business,
        psr_type: psrType,
        in_domain: inDomain,
        out_domain: outDomain,
        periods,
      };
    });
    return { query, time_series_count: timeSeries.length, time_series: timeSeries };
  }

  private firstMatch(text: string, re: RegExp): string | null {
    const m = re.exec(text);
    return m ? (m[1] ?? m[2] ?? null) : null;
  }

  // ── Argument helpers ──────────────────────────────────────────────────────

  private reqStr(args: Record<string, unknown>, key: string): string {
    const v = args[key];
    if (typeof v !== 'string' || !v.trim()) {
      throw new Error(`Required argument "${key}" is missing or empty.`);
    }
    return v;
  }
}
