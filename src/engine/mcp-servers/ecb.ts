/**
 * ECB Data Portal MCP Adapter
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

// Base URL: https://data-api.ecb.europa.eu/service
// Auth: none (public SDMX 2.1 REST API)
// Docs: https://data.ecb.europa.eu/help/api/
// Category: finance

import { parseStringPromise } from 'xml2js';
import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

const BASE_URL = 'https://data-api.ecb.europa.eu/service';

export class EcbMCPServer extends MCPAdapterBase {
  private readonly baseUrl: string;

  constructor(config?: { baseUrl?: string }) {
    super();
    if (config === null) { throw new Error('EcbMCPServer: configuration object is required when provided'); }
    this.baseUrl = config?.baseUrl ?? BASE_URL;
  }

  static catalog() {
    return {
      name: 'ecb',
      displayName: 'ECB Data Portal',
      version: '1.0.0',
      category: 'finance',
      keywords: [
        'ecb', 'european central bank', 'sdmx', 'exchange rate', 'eur',
        'forex', 'hicp', 'inflation', 'cpi', 'euro area', 'macroeconomics',
        'monetary policy', 'interest rates', 'financial statistics', 'dataflow',
      ],
      toolNames: ['exchange_rate', 'hicp_inflation', 'get_data', 'list_dataflows'],
      description: 'ECB Data Portal: fetch EUR exchange rates, HICP inflation, and generic SDMX statistical data from the European Central Bank.',
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
        name: 'exchange_rate',
        description:
          'Daily EUR exchange rate against a currency. Returns time series of observations. Currency is the ISO 4217 code (e.g. "USD", "GBP", "JPY", "CHF").',
        inputSchema: {
          type: 'object',
          properties: {
            currency: { type: 'string', description: 'ISO 4217 currency code (USD, GBP, JPY, ...)' },
            start_period: { type: 'string', description: 'Start date (YYYY-MM-DD)' },
            end_period: { type: 'string', description: 'End date (YYYY-MM-DD)' },
            frequency: {
              type: 'string',
              description: 'Observation frequency — D (daily), M (monthly), Q (quarterly), A (annual). Default D.',
            },
          },
          required: ['currency'],
        },
      },
      {
        name: 'hicp_inflation',
        description:
          'Harmonised Index of Consumer Prices (HICP) annual rate of change for a country / euro area. Monthly frequency. country defaults to U2 (euro area).',
        inputSchema: {
          type: 'object',
          properties: {
            country: {
              type: 'string',
              description: 'Reference area — U2 (euro area, default), DE, FR, IT, ES, NL, BE, etc.',
            },
            start_period: { type: 'string', description: 'Start date (YYYY or YYYY-MM)' },
            end_period: { type: 'string', description: 'End date (YYYY or YYYY-MM)' },
          },
        },
      },
      {
        name: 'get_data',
        description:
          'Generic SDMX data fetch from any ECB flow. Key is dot-separated dimension values; empty positions are wildcards. Example: flow_ref="EXR", key="D.USD.EUR.SP00.A" (daily USD/EUR spot).',
        inputSchema: {
          type: 'object',
          properties: {
            flow_ref: {
              type: 'string',
              description: 'Flow reference — EXR (exchange rates), ICP (HICP), BSI, IRS, STS, BLS, MIR, ...',
            },
            key: {
              type: 'string',
              description: 'Series key, dot-separated dimension values',
            },
            start_period: { type: 'string', description: 'Start date / period' },
            end_period: { type: 'string', description: 'End date / period' },
            last_n: { type: 'number', description: 'Return only the last N observations' },
          },
          required: ['flow_ref', 'key'],
        },
      },
      {
        name: 'list_dataflows',
        description: 'List ECB SDMX data flows. Optional substring filter on flow ref or name.',
        inputSchema: {
          type: 'object',
          properties: {
            filter: { type: 'string', description: 'Case-insensitive substring filter' },
          },
        },
      },
    ];
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<ToolResult> {
    try {
      switch (name) {
        case 'exchange_rate':   return this.exchangeRate(args);
        case 'hicp_inflation':  return this.hicpInflation(args);
        case 'get_data':        return this.getData(args);
        case 'list_dataflows':  return this.listDataflows(args);
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

  private async exchangeRate(args: Record<string, unknown>): Promise<ToolResult> {
    const currency = this.reqStr(args, 'currency', '"USD"').toUpperCase();
    const freq = ((args.frequency as string) ?? 'D').toUpperCase();
    // EXR flow key: FREQ.CURRENCY.CURRENCY_DENOM.EXR_TYPE.EXR_SUFFIX
    const key = `${freq}.${currency}.EUR.SP00.A`;
    return this.fetchSdmxData('EXR', key, {
      start_period: args.start_period as string | undefined,
      end_period: args.end_period as string | undefined,
    });
  }

  private async hicpInflation(args: Record<string, unknown>): Promise<ToolResult> {
    const country = ((args.country as string) ?? 'U2').toUpperCase();
    // ICP flow key: FREQ.REF_AREA.ADJUSTMENT.ICP_ITEM.STS_INSTITUTION.ICP_SUFFIX
    // M.U2.N.000000.4.ANR = monthly euro area annual rate of change, all items
    const key = `M.${country}.N.000000.4.ANR`;
    return this.fetchSdmxData('ICP', key, {
      start_period: args.start_period as string | undefined,
      end_period: args.end_period as string | undefined,
    });
  }

  private async getData(args: Record<string, unknown>): Promise<ToolResult> {
    return this.fetchSdmxData(
      this.reqStr(args, 'flow_ref', '"EXR"'),
      this.reqStr(args, 'key', '"D.USD.EUR.SP00.A"'),
      {
        start_period: args.start_period as string | undefined,
        end_period: args.end_period as string | undefined,
        last_n: args.last_n as number | undefined,
      },
    );
  }

  private async fetchSdmxData(
    flow: string,
    key: string,
    opts: { start_period?: string; end_period?: string; last_n?: number },
  ): Promise<ToolResult> {
    const params = new URLSearchParams({ format: 'jsondata' });
    if (opts.start_period) params.set('startPeriod', opts.start_period);
    if (opts.end_period) params.set('endPeriod', opts.end_period);
    if (opts.last_n) params.set('lastNObservations', String(opts.last_n));
    const url = `${this.baseUrl}/data/${encodeURIComponent(flow)}/${encodeURIComponent(key)}?${params}`;

    const response = await this.fetchWithRetry(url, {
      method: 'GET',
      headers: { Accept: 'application/json' },
    });

    if (response.status === 404) {
      return {
        content: [{ type: 'text', text: `ECB: no data found for flow=${flow} key=${key}` }],
        isError: true,
      };
    }
    if (!response.ok) {
      const body = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `ECB error: ${response.status} ${body.slice(0, 200)}` }],
        isError: true,
      };
    }

    const data = (await response.json()) as SdmxData;
    const result = this.normalizeSdmx(flow, key, data);
    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }

  private async listDataflows(args: Record<string, unknown>): Promise<ToolResult> {
    // The ECB SDMX /dataflow endpoint only serves XML (application/xml or
    // application/vnd.sdmx.structure+xml;version=2.1).  Sending Accept:
    // application/json results in HTTP 406 Not Acceptable.
    const url = `${this.baseUrl}/dataflow/ECB`;
    const response = await this.fetchWithRetry(url, {
      method: 'GET',
      headers: { Accept: 'application/vnd.sdmx.structure+xml;version=2.1' },
    });

    if (!response.ok) {
      const body = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `ECB error: ${response.status} ${body.slice(0, 200)}` }],
        isError: true,
      };
    }

    const xml = await response.text();
    const parsed = await parseStringPromise(xml, { explicitArray: true });
    const rawFlows: { $: { id: string }; 'com:Name'?: ({ _?: string } | string)[] }[] =
      parsed?.['mes:Structure']?.['mes:Structures']?.[0]?.['str:Dataflows']?.[0]?.['str:Dataflow'] ?? [];

    const filter = ((args.filter as string) ?? '').toLowerCase();
    const items = rawFlows
      .map((f) => {
        const id = f.$.id;
        const nameEntry = f['com:Name']?.[0];
        const name = typeof nameEntry === 'string'
          ? nameEntry
          : (nameEntry as { _?: string })?._
            ?? id;
        return { flow_ref: id, name };
      })
      .filter((f) => !filter || f.flow_ref.toLowerCase().includes(filter) || f.name.toLowerCase().includes(filter));

    return { content: [{ type: 'text', text: this.truncate({ count: items.length, dataflows: items }) }], isError: false };
  }

  // ── SDMX normalizer ────────────────────────────────────────────────────────

  private normalizeSdmx(flow: string, key: string, data: SdmxData): unknown {
    const seriesDims = data.structure?.dimensions?.series ?? [];
    const obsDims = data.structure?.dimensions?.observation ?? [];
    const series = data.dataSets?.[0]?.series ?? {};
    const out: {
      series_key: string;
      dimensions: Record<string, string>;
      observations: { period: string; value: number | null }[];
    }[] = [];

    for (const [skey, sval] of Object.entries(series)) {
      const idx = skey.split(':').map(Number);
      const dims: Record<string, string> = {};
      seriesDims.forEach((d, i) => {
        const v = d.values?.[idx[i]];
        if (v) dims[d.id] = v.name ?? v.id;
      });
      const obs: { period: string; value: number | null }[] = [];
      for (const [oidx, ovals] of Object.entries(sval.observations ?? {})) {
        const period = obsDims[0]?.values?.[Number(oidx)]?.id ?? oidx;
        obs.push({ period, value: ovals[0] ?? null });
      }
      obs.sort((a, b) => (a.period < b.period ? -1 : 1));
      out.push({ series_key: skey, dimensions: dims, observations: obs });
    }

    return { flow, key, series_count: out.length, series: out };
  }

  // ── Helpers ────────────────────────────────────────────────────────────────

  private reqStr(args: Record<string, unknown>, key: string, example: string): string {
    const v = args[key];
    if (typeof v !== 'string' || !v.trim()) {
      throw new Error(`Required argument "${key}" is missing. Pass a string like ${example}.`);
    }
    return v;
  }
}

// ── SDMX type definitions ──────────────────────────────────────────────────

interface SdmxData {
  dataSets?: {
    series?: Record<string, { observations?: Record<string, [number | null, ...unknown[]]> }>;
  }[];
  structure?: {
    dimensions?: {
      series?: { id: string; name?: string; values?: { id: string; name?: string }[] }[];
      observation?: { id: string; name?: string; values?: { id: string; name?: string }[] }[];
    };
    attributes?: {
      series?: { id: string; values?: { id: string; name?: string }[] }[];
    };
  };
}
