/**
 * Meteostat MCP Adapter — historical weather from 11k+ stations (no auth)
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

// Upstream bulk API: https://bulk.meteostat.net/v2
// No authentication required — public free-tier bulk CSV endpoint.
// Docs: https://dev.meteostat.net/bulk
// Station IDs: visit https://meteostat.net, search a place, the URL ends in the numeric station ID.
// Category: weather
// Rate limits: none documented; files are served via Cloudflare CDN

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

const BULK_BASE = 'https://bulk.meteostat.net/v2';
const DATE_RE = /^\d{4}-\d{2}-\d{2}$/;

export class MeteostatMCPServer extends MCPAdapterBase {
  constructor() {
    super();
  }

  static catalog() {
    return {
      name: 'meteostat',
      displayName: 'Meteostat Historical Weather',
      version: '1.0.0',
      category: 'weather',
      keywords: [
        'meteostat', 'weather', 'historical weather', 'climate', 'temperature',
        'precipitation', 'wind', 'pressure', 'weather station', 'daily weather',
        'monthly normals', 'climate normals', 'weather history', 'meteorology',
      ],
      toolNames: ['get_daily_history', 'get_monthly_normals'],
      description: 'Meteostat: fetch historical daily weather observations and long-run monthly climate normals from 11k+ physical weather stations worldwide — free and unauthenticated.',
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
        name: 'get_daily_history',
        description:
          'Daily historical weather for a Meteostat station between two dates. Returns date-keyed temperature (avg/min/max), precipitation, snow, wind direction/speed/peak, pressure, and sunshine minutes. Station IDs are numeric — find them at meteostat.net (URL suffix, e.g. 72494 = San Francisco Intl).',
        inputSchema: {
          type: 'object',
          properties: {
            station_id: {
              type: 'string',
              description: 'Meteostat numeric station ID (e.g., "72494")',
            },
            start_date: {
              type: 'string',
              description: 'Start date in YYYY-MM-DD format (inclusive)',
            },
            end_date: {
              type: 'string',
              description: 'End date in YYYY-MM-DD format (inclusive)',
            },
          },
          required: ['station_id', 'start_date', 'end_date'],
        },
      },
      {
        name: 'get_monthly_normals',
        description:
          "Monthly climate normals for a station — long-run averages (typically 30-year reference period) of temperature, precipitation, wind speed, and pressure by calendar month. Useful for baselines like \"what's normal in May here\".",
        inputSchema: {
          type: 'object',
          properties: {
            station_id: {
              type: 'string',
              description: 'Meteostat numeric station ID (e.g., "72494")',
            },
          },
          required: ['station_id'],
        },
      },
    ];
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<ToolResult> {
    try {
      switch (name) {
        case 'get_daily_history':
          return this.getDailyHistory(args);
        case 'get_monthly_normals':
          return this.getMonthlyNormals(args);
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

  private reqStr(args: Record<string, unknown>, key: string, example: string): string {
    const v = args[key];
    if (typeof v !== 'string' || !v.trim()) {
      throw new Error(`Required argument "${key}" is missing or empty. Pass a string like ${example}.`);
    }
    return v;
  }

  private num(v: string): number | null {
    if (v === '' || v == null) return null;
    const n = Number(v);
    return Number.isFinite(n) ? n : null;
  }

  private parseCsv(text: string): string[][] {
    return text
      .split('\n')
      .map((line) => line.trim())
      .filter((line) => line.length > 0)
      .map((line) => line.split(','));
  }

  /**
   * Fetch a gzip-compressed CSV file from bulk.meteostat.net.
   * The files are served as application/octet-stream with gzip encoding,
   * so we decompress via DecompressionStream rather than relying on
   * automatic Content-Encoding decompression.
   */
  private async fetchGzipText(url: string): Promise<string> {
    const response = await this.fetchWithRetry(url, {
      method: 'GET',
      headers: { Accept: '*/*' },
    });

    if (response.status === 404) {
      throw new Error(`Meteostat: no data file at ${url} — check the station ID`);
    }
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      throw new Error(`Meteostat error: ${response.status} ${errText}`);
    }
    if (!response.body) {
      throw new Error('Meteostat: empty response body');
    }

    const ds = new DecompressionStream('gzip');
    const stream = response.body.pipeThrough(ds);
    return new Response(stream).text();
  }

  // ── Daily history ────────────────────────────────────────────────────────
  // Bulk daily CSV columns (no header):
  //   date, tavg, tmin, tmax, prcp, snow, wdir, wspd, wpgt, pres, tsun

  private async getDailyHistory(args: Record<string, unknown>): Promise<ToolResult> {
    const stationId = this.reqStr(args, 'station_id', '"72494" (KSFO)');
    const start = this.reqStr(args, 'start_date', '"2020-01-01"');
    const end = this.reqStr(args, 'end_date', '"2020-12-31"');

    if (!DATE_RE.test(start) || !DATE_RE.test(end)) {
      return {
        content: [{ type: 'text', text: 'start_date and end_date must be YYYY-MM-DD' }],
        isError: true,
      };
    }
    if (start > end) {
      return {
        content: [{ type: 'text', text: 'start_date must be <= end_date' }],
        isError: true,
      };
    }
    const id = stationId.trim();
    if (!/^\d+$/.test(id)) {
      return {
        content: [{ type: 'text', text: 'station_id must be a numeric Meteostat ID' }],
        isError: true,
      };
    }

    const text = await this.fetchGzipText(`${BULK_BASE}/daily/${id}.csv.gz`);
    const rows = this.parseCsv(text);

    interface DailyRow {
      date: string;
      tavg_c: number | null;
      tmin_c: number | null;
      tmax_c: number | null;
      precip_mm: number | null;
      snow_mm: number | null;
      wind_dir_deg: number | null;
      wind_speed_kmh: number | null;
      wind_peak_kmh: number | null;
      pressure_hpa: number | null;
      sunshine_min: number | null;
    }

    const out: DailyRow[] = [];
    for (const r of rows) {
      if (r.length < 11) continue;
      const date = r[0];
      if (date < start || date > end) continue;
      out.push({
        date,
        tavg_c: this.num(r[1]),
        tmin_c: this.num(r[2]),
        tmax_c: this.num(r[3]),
        precip_mm: this.num(r[4]),
        snow_mm: this.num(r[5]),
        wind_dir_deg: this.num(r[6]),
        wind_speed_kmh: this.num(r[7]),
        wind_peak_kmh: this.num(r[8]),
        pressure_hpa: this.num(r[9]),
        sunshine_min: this.num(r[10]),
      });
    }

    const result = {
      station_id: id,
      start_date: start,
      end_date: end,
      count: out.length,
      days: out,
    };

    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }

  // ── Monthly normals ──────────────────────────────────────────────────────
  // Bulk normals CSV columns (no header):
  //   start, end, month, tavg, tmin, tmax, prcp, wspd, pres, tsun

  private async getMonthlyNormals(args: Record<string, unknown>): Promise<ToolResult> {
    const stationId = this.reqStr(args, 'station_id', '"72494"');
    const id = stationId.trim();
    if (!/^\d+$/.test(id)) {
      return {
        content: [{ type: 'text', text: 'station_id must be a numeric Meteostat ID' }],
        isError: true,
      };
    }

    const text = await this.fetchGzipText(`${BULK_BASE}/normals/${id}.csv.gz`);
    const rows = this.parseCsv(text);

    const normals = rows
      .filter((r) => r.length >= 10)
      .map((r) => ({
        reference_start_year: Number(r[0]),
        reference_end_year: Number(r[1]),
        month: Number(r[2]),
        tavg_c: this.num(r[3]),
        tmin_c: this.num(r[4]),
        tmax_c: this.num(r[5]),
        precip_mm: this.num(r[6]),
        wind_speed_kmh: this.num(r[7]),
        pressure_hpa: this.num(r[8]),
        sunshine_min: this.num(r[9]),
      }));

    const result = {
      station_id: id,
      count: normals.length,
      normals,
    };

    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }
}
