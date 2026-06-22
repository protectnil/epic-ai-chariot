/**
 * Altos Research MCP Adapter
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

// No official vendor MCP found. This is a native REST adapter calling the upstream directly.
//
// Base URL: https://intel.altosresearch.com/api
// Auth: API key via HTTP Basic auth (key as username, empty password) — BYO key from https://altosresearch.com
// Docs: https://altosresearch.com
// Category: real-estate
// Rate limits: Dependent on subscription plan.

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

interface AltosConfig {
  apiKey: string;
  baseUrl?: string;
}

export class AltosMCPServer extends MCPAdapterBase {
  private readonly apiKey: string;
  private readonly baseUrl: string;

  constructor(config: AltosConfig) {
    super();
    if (!config || typeof config !== 'object') {
      throw new Error('Altos Research: configuration object is required');
    }
    for (const __k of (['apiKey'] as Array<keyof typeof config>)) {
      if (config[__k] === undefined || config[__k] === null || (config[__k] as unknown) === '') {
        throw new Error('Altos Research: ' + __k + ' is required');
      }
    }
    this.apiKey = config.apiKey;
    this.baseUrl = config.baseUrl || 'https://intel.altosresearch.com/api';
  }

  static catalog() {
    return {
      name: 'altos',
      displayName: 'Altos Research — Real Estate Market Intelligence',
      version: '1.0.0',
      category: 'real-estate',
      keywords: [
        'altos', 'real estate', 'housing market', 'market stats', 'inventory',
        'home listings', 'pending sales', 'new listings', 'days on market',
        'median price', 'market action index', 'real estate data', 'housing data',
        'property listings', 'real estate trends', 'housing inventory',
      ],
      toolNames: [
        'altos_market_stats',
        'altos_inventory_trend',
        'altos_active_listings',
        'altos_pending_sales',
        'altos_new_listings',
        'altos_list_files',
      ],
      description: 'Altos Research real estate market intelligence: aggregated market statistics, inventory trends, active listings, pending sales, and new listings by region — requires an Altos Research API key.',
      type: 'rest' as const,
      auth: {
        inferredModel: 'apikey' as const,
        probeState: 'never-probed' as const,
      },
      author: 'protectnil',
    };
  }

  get tools(): ToolDefinition[] {
    return [
      {
        name: 'altos_market_stats',
        description: 'Get aggregated market statistics for a region — inventory, new listings, median price, days on market, and market action index.',
        inputSchema: {
          type: 'object',
          properties: {
            region: {
              type: 'string',
              description: 'Region code (e.g., "us_national", "ca_los-angeles", "ca_94105").',
            },
            date: {
              type: 'string',
              description: 'Date (must be a Friday, YYYY-MM-DD). Defaults to the most recent Friday.',
            },
            res_type: {
              type: 'string',
              description: 'Residential type filter: "single_family" or "multi_family". Default: single_family.',
            },
            quartile: {
              type: 'string',
              description: 'Price quartile: "ALL", "FIRST", "SECOND", "THIRD", "FOURTH". Default: ALL.',
            },
          },
          required: ['region'],
        },
      },
      {
        name: 'altos_inventory_trend',
        description: 'Get inventory trend over multiple weeks — tracks inventory, new listings, days on market, median price, and percent price decreased over time.',
        inputSchema: {
          type: 'object',
          properties: {
            region: {
              type: 'string',
              description: 'Region code (e.g., "us_national", "ca_los-angeles").',
            },
            weeks: {
              type: 'number',
              description: 'Number of weeks to look back (default 12, max 52).',
            },
          },
          required: ['region'],
        },
      },
      {
        name: 'altos_active_listings',
        description: 'Get active listing-level data for a region — individual property details including address, price, beds, baths, and square footage.',
        inputSchema: {
          type: 'object',
          properties: {
            region: {
              type: 'string',
              description: 'Region code (e.g., "ca_los-angeles", "ca_94105").',
            },
            date: {
              type: 'string',
              description: 'Date (must be a Friday, YYYY-MM-DD). Defaults to the most recent Friday.',
            },
            limit: {
              type: 'number',
              description: 'Max rows to return (default 100, max 500).',
            },
          },
          required: ['region'],
        },
      },
      {
        name: 'altos_pending_sales',
        description: 'Get pending sales (under contract) for a region — properties that have accepted offers but have not yet closed.',
        inputSchema: {
          type: 'object',
          properties: {
            region: {
              type: 'string',
              description: 'Region code (e.g., "ca_los-angeles", "ca_94105").',
            },
            date: {
              type: 'string',
              description: 'Date (must be a Friday, YYYY-MM-DD). Defaults to the most recent Friday.',
            },
            limit: {
              type: 'number',
              description: 'Max rows to return (default 100, max 500).',
            },
          },
          required: ['region'],
        },
      },
      {
        name: 'altos_new_listings',
        description: 'Get new listings (on market less than a week) for a region — freshly listed properties.',
        inputSchema: {
          type: 'object',
          properties: {
            region: {
              type: 'string',
              description: 'Region code (e.g., "ca_los-angeles", "ca_94105").',
            },
            date: {
              type: 'string',
              description: 'Date (must be a Friday, YYYY-MM-DD). Defaults to the most recent Friday.',
            },
            limit: {
              type: 'number',
              description: 'Max rows to return (default 100, max 500).',
            },
          },
          required: ['region'],
        },
      },
      {
        name: 'altos_list_files',
        description: 'List available data files for a region — returns the catalog of downloadable data files from Altos Research.',
        inputSchema: {
          type: 'object',
          properties: {
            region: {
              type: 'string',
              description: 'Region code (default: "us_national").',
            },
            type: {
              type: 'string',
              description: 'Data type: "stats", "listings", "listings-new", "pendings" (default: "stats").',
            },
          },
        },
      },
    ];
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<ToolResult> {
    try {
      switch (name) {
        case 'altos_market_stats':    return this.marketStats(args);
        case 'altos_inventory_trend': return this.inventoryTrend(args);
        case 'altos_active_listings': return this.activeListings(args);
        case 'altos_pending_sales':   return this.pendingSales(args);
        case 'altos_new_listings':    return this.newListings(args);
        case 'altos_list_files':      return this.listFiles(args);
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

  /** HTTP Basic auth header: apiKey as username, empty password. */
  private authHeader(): string {
    return `Basic ${btoa(this.apiKey + ':')}`;
  }

  /** Most recent Friday as YYYY-MM-DD. */
  private lastFriday(): string {
    const d = new Date();
    const day = d.getDay();
    const diff = (day + 2) % 7;
    d.setDate(d.getDate() - (diff === 0 ? 7 : diff));
    return d.toISOString().slice(0, 10);
  }

  /** Friday N weeks before the most recent Friday. */
  private fridayNWeeksAgo(n: number): string {
    const d = new Date();
    const day = d.getDay();
    const diff = (day + 2) % 7;
    d.setDate(d.getDate() - (diff === 0 ? 7 : diff));
    d.setDate(d.getDate() - n * 7);
    return d.toISOString().slice(0, 10);
  }

  /** Fetch a CSV endpoint and return raw response text. */
  private async fetchCSVText(params: Record<string, string>): Promise<string> {
    const url = new URL(`${this.baseUrl}/data`);
    for (const [k, v] of Object.entries(params)) {
      url.searchParams.set(k, v);
    }
    const response = await this.fetchWithRetry(url.toString(), {
      method: 'GET',
      headers: { Authorization: this.authHeader() },
    });
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      throw new Error(`Altos API error (${response.status}): ${errText}`);
    }
    // Decompress gzip if needed
    const contentEncoding = response.headers.get('content-encoding') ?? '';
    if (contentEncoding.includes('gzip')) {
      const ds = new DecompressionStream('gzip');
      const decompressed = response.body!.pipeThrough(ds);
      const reader = decompressed.getReader();
      const chunks: Uint8Array[] = [];
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        chunks.push(value);
      }
      const total = chunks.reduce((a, c) => a + c.length, 0);
      const merged = new Uint8Array(total);
      let offset = 0;
      for (const chunk of chunks) { merged.set(chunk, offset); offset += chunk.length; }
      return new TextDecoder().decode(merged);
    }
    return response.text();
  }

  /** Parse CSV text into an array of row objects. */
  private parseCSV(text: string): Record<string, string>[] {
    const lines = text.trim().split('\n');
    if (lines.length < 2) return [];
    const headers = lines[0].split(',').map(h => h.trim().replace(/^"|"$/g, ''));
    return lines.slice(1).map(line => {
      const values = line.split(',').map(v => v.trim().replace(/^"|"$/g, ''));
      const row: Record<string, string> = {};
      headers.forEach((h, i) => { row[h] = values[i] ?? ''; });
      return row;
    });
  }

  /** Fetch CSV endpoint and parse into rows. */
  private async fetchCSV(params: Record<string, string>): Promise<Record<string, string>[]> {
    const text = await this.fetchCSVText(params);
    return this.parseCSV(text);
  }

  /** Fetch a JSON endpoint (e.g. /list). */
  private async fetchJSON(path: string, params: Record<string, string>): Promise<ToolResult> {
    const url = new URL(`${this.baseUrl}${path}`);
    for (const [k, v] of Object.entries(params)) {
      url.searchParams.set(k, v);
    }
    const response = await this.fetchWithRetry(url.toString(), {
      method: 'GET',
      headers: { Authorization: this.authHeader(), Accept: 'application/json' },
    });
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `API error: ${response.status} ${errText}` }],
        isError: true,
      };
    }
    const data = await response.json();
    return { content: [{ type: 'text', text: this.truncate(data) }], isError: false };
  }

  private async marketStats(args: Record<string, unknown>): Promise<ToolResult> {
    const region = args.region as string;
    const date = (args.date as string | undefined) ?? this.lastFriday();
    const resType = (args.res_type as string | undefined) ?? 'single_family';
    const quartile = (args.quartile as string | undefined) ?? 'ALL';

    const rows = await this.fetchCSV({ region, date, type: 'stats', columnset: 'classic' });
    const filtered = rows.filter(r =>
      (!r.res_type || r.res_type === resType) &&
      (!r.quartile || r.quartile === quartile) &&
      (!r.rolling_average || r.rolling_average === '7-day'),
    );
    const result = (filtered.length > 0 ? filtered : rows.slice(0, 5)).map(r => ({
      date: r.date ?? date,
      inventory_total: r.inventory_total ?? '',
      new_listings_total: r.new_listings_total ?? '',
      listings_absorbed_total: r.listings_absorbed_total ?? '',
      days_on_market_median: r.days_on_market_median ?? '',
      price_median: r.price_median ?? '',
      percent_price_decreased_median: r.percent_price_decreased_median ?? '',
      market_action_median: r.market_action_median ?? '',
      months_of_inventory_median: r.months_of_inventory_median ?? '',
      estimated_sales_total: r.estimated_sales_total ?? '',
    }));
    return {
      content: [{ type: 'text', text: this.truncate({ region, date, res_type: resType, quartile, stats: result }) }],
      isError: false,
    };
  }

  private async inventoryTrend(args: Record<string, unknown>): Promise<ToolResult> {
    const region = args.region as string;
    const weeksRaw = Math.min(Math.max((args.weeks as number | undefined) ?? 12, 1), 52);
    const maxCalls = 6;
    const datesToFetch: string[] = [];

    if (weeksRaw <= maxCalls) {
      for (let i = 0; i < weeksRaw; i++) datesToFetch.push(this.fridayNWeeksAgo(i));
    } else {
      const step = Math.floor(weeksRaw / maxCalls);
      for (let i = 0; i < maxCalls; i++) datesToFetch.push(this.fridayNWeeksAgo(i * step));
    }

    const snapshots = await Promise.all(
      datesToFetch.map(async (date) => {
        try {
          const rows = await this.fetchCSV({ region, date, type: 'stats', columnset: 'classic' });
          const match = rows.find(r =>
            (!r.res_type || r.res_type === 'single_family') &&
            (!r.quartile || r.quartile === 'ALL') &&
            (!r.rolling_average || r.rolling_average === '7-day'),
          ) ?? rows[0];
          if (!match) return null;
          return {
            date,
            inventory: match.inventory_total ?? '',
            new_listings: match.new_listings_total ?? '',
            days_on_market: match.days_on_market_median ?? '',
            price_median: match.price_median ?? '',
            pct_price_decreased: match.percent_price_decreased_median ?? '',
          };
        } catch {
          return null;
        }
      }),
    );

    return {
      content: [{
        type: 'text',
        text: this.truncate({
          region,
          weeks_requested: weeksRaw,
          snapshots_fetched: datesToFetch.length,
          trend: snapshots.filter(Boolean),
        }),
      }],
      isError: false,
    };
  }

  private async activeListings(args: Record<string, unknown>): Promise<ToolResult> {
    const region = args.region as string;
    const date = (args.date as string | undefined) ?? this.lastFriday();
    const limit = Math.min((args.limit as number | undefined) ?? 100, 500);

    const rows = await this.fetchCSV({ region, date, type: 'listings', columnset: 'classic' });
    const listings = rows.slice(0, limit).map(r => ({
      property_id: r.property_id ?? '',
      street_address: r.street_address ?? '',
      city: r.city ?? '',
      state: r.state ?? '',
      zip: r.zip ?? '',
      price: r.price ?? '',
      type: r.type ?? '',
      beds: r.beds ?? '',
      baths: r.baths ?? '',
      floor_size: r.floor_size ?? '',
      lot_size: r.lot_size ?? '',
      built_in: r.built_in ?? '',
      days_on_market: r.days_on_market ?? '',
    }));
    return {
      content: [{ type: 'text', text: this.truncate({ region, date, total_available: rows.length, returned: listings.length, listings }) }],
      isError: false,
    };
  }

  private async pendingSales(args: Record<string, unknown>): Promise<ToolResult> {
    const region = args.region as string;
    const date = (args.date as string | undefined) ?? this.lastFriday();
    const limit = Math.min((args.limit as number | undefined) ?? 100, 500);

    const rows = await this.fetchCSV({ region, date, type: 'pendings', columnset: 'classic' });
    return {
      content: [{
        type: 'text',
        text: this.truncate({ region, date, total_available: rows.length, returned: Math.min(rows.length, limit), pendings: rows.slice(0, limit) }),
      }],
      isError: false,
    };
  }

  private async newListings(args: Record<string, unknown>): Promise<ToolResult> {
    const region = args.region as string;
    const date = (args.date as string | undefined) ?? this.lastFriday();
    const limit = Math.min((args.limit as number | undefined) ?? 100, 500);

    const rows = await this.fetchCSV({ region, date, type: 'listings-new', columnset: 'classic' });
    return {
      content: [{
        type: 'text',
        text: this.truncate({ region, date, total_available: rows.length, returned: Math.min(rows.length, limit), new_listings: rows.slice(0, limit) }),
      }],
      isError: false,
    };
  }

  private async listFiles(args: Record<string, unknown>): Promise<ToolResult> {
    const region = (args.region as string | undefined) ?? 'us_national';
    const type = (args.type as string | undefined) ?? 'stats';
    return this.fetchJSON('/list', { region, type });
  }
}
