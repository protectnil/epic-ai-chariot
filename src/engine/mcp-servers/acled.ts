/**
 * ACLED — Armed Conflict Location & Event Data Project MCP Adapter
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 *
 * Base URL: https://acleddata.com/api/acled/read
 * OAuth token URL: https://acleddata.com/oauth/token
 *
 * Auth: ACLED OAuth (Resource Owner Password Credentials).
 * Exchange a myACLED email + password for a short-lived Bearer token via
 * /oauth/token (grant_type=password, client_id=acled). Token cached
 * per-instance with a 23-hour safety margin under ACLED's 24-hour TTL;
 * refreshed automatically on 401.
 *
 * Docs: https://acleddata.com/resources/general-guides/
 * Register: https://acleddata.com/register/
 *
 * Category: geopolitical
 * Tools: search_events, event_counts_by_country
 */

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

interface AcledConfig {
  email: string;
  password: string;
  baseUrl?: string;
}

interface CachedToken {
  access_token: string;
  expires_at: number; // epoch ms
}

interface EventRow {
  data_id?: string;
  event_id_cnty?: string;
  event_date?: string;
  year?: string;
  event_type?: string;
  sub_event_type?: string;
  actor1?: string;
  actor2?: string;
  inter1?: string;
  inter2?: string;
  country?: string;
  iso?: string;
  region?: string;
  admin1?: string;
  admin2?: string;
  location?: string;
  latitude?: string;
  longitude?: string;
  fatalities?: string;
  notes?: string;
  source?: string;
  source_scale?: string;
}

const TOKEN_TTL_MS = 23 * 60 * 60 * 1000; // 23h safety margin under ACLED's 24h

export class AcledMCPServer extends MCPAdapterBase {
  private readonly email: string;
  private readonly password: string;
  private readonly readUrl: string;
  private readonly tokenUrl: string;

  /** per-instance OAuth token cache */
  private tokenCache: CachedToken | null = null;

  constructor(config: AcledConfig) {
    super();
    if (!config || typeof config !== 'object') {
      throw new Error('ACLED: configuration object is required');
    }
    if (!config.email || typeof config.email !== 'string') {
      throw new Error('ACLED: email is required — register at https://acleddata.com/register/');
    }
    if (!config.password || typeof config.password !== 'string') {
      throw new Error('ACLED: password is required — register at https://acleddata.com/register/');
    }
    this.email = config.email.trim();
    this.password = config.password;
    const base = (config.baseUrl ?? 'https://acleddata.com').replace(/\/$/, '');
    this.readUrl = `${base}/api/acled/read`;
    this.tokenUrl = `${base}/oauth/token`;
  }

  static catalog() {
    return {
      name: 'acled',
      displayName: 'ACLED — Armed Conflict Location & Event Data',
      version: '1.0.0',
      category: 'geopolitical',
      keywords: [
        'acled', 'conflict', 'political violence', 'protest', 'riot',
        'battle', 'fatalities', 'armed conflict', 'security', 'geopolitical',
        'event data', 'country risk', 'actor', 'sub-event', 'demonstration',
        'explosion', 'remote violence', 'strategic development',
      ],
      toolNames: ['search_events', 'event_counts_by_country'],
      description:
        'ACLED API: search political-violence and protest events worldwide with filters for country, region, event type, actor, date range, and fatalities; aggregate event and fatality counts by country for cross-country risk comparison.',
      type: 'rest' as const,
      auth: {
        inferredModel: 'oauth-password' as const,
        probeState: 'never-probed' as const,
      },
      author: 'protectnil',
    };
  }

  get tools(): ToolDefinition[] {
    return [
      {
        name: 'search_events',
        description:
          'Search ACLED political-violence and protest events. Filter by country (use "|" to OR, e.g., "Ukraine|Russia"), region, event_type, actor, ISO country code, or date range. Returns date, lat/lon, actors, event type, fatalities, and source notes.',
        inputSchema: {
          type: 'object',
          properties: {
            country: {
              type: 'string',
              description: 'Country name(s), pipe-separated for OR (e.g., "Ukraine|Russia")',
            },
            region: {
              type: 'string',
              description: 'ACLED region (e.g., "Western Africa")',
            },
            event_type: {
              type: 'string',
              description:
                'Battles | Protests | Riots | Explosions/Remote violence | Violence against civilians | Strategic developments',
            },
            sub_event_type: {
              type: 'string',
              description: 'Optional ACLED sub-event type',
            },
            actor: {
              type: 'string',
              description: 'Match actor1 or actor2 (partial substring match)',
            },
            iso: {
              type: 'number',
              description: 'ISO 3166-1 numeric country code (alternative to country)',
            },
            event_date_from: {
              type: 'string',
              description: 'Start of date range, inclusive (YYYY-MM-DD)',
            },
            event_date_to: {
              type: 'string',
              description: 'End of date range, inclusive (YYYY-MM-DD)',
            },
            year: {
              type: 'number',
              description: 'Restrict results to a single calendar year',
            },
            fatalities_min: {
              type: 'number',
              description: 'Minimum fatalities filter (inclusive)',
            },
            limit: {
              type: 'number',
              description: 'Records to return (1–5000, default 100; ACLED max-per-call is 5000)',
            },
          },
          required: [],
        },
      },
      {
        name: 'event_counts_by_country',
        description:
          'Aggregate event and fatality counts by country over a date range. Useful for cross-country comparison and time-bounded risk snapshots.',
        inputSchema: {
          type: 'object',
          properties: {
            event_date_from: {
              type: 'string',
              description: 'Start of date range, inclusive (YYYY-MM-DD)',
            },
            event_date_to: {
              type: 'string',
              description: 'End of date range, inclusive (YYYY-MM-DD)',
            },
            region: {
              type: 'string',
              description: 'Optional ACLED region restriction',
            },
            event_type: {
              type: 'string',
              description: 'Optional event-type restriction',
            },
            limit: {
              type: 'number',
              description: 'Underlying-event cap for aggregation (1–5000, default 5000)',
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
        case 'search_events':
          return this.searchEvents(args);
        case 'event_counts_by_country':
          return this.countsByCountry(args);
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

  // ── OAuth token management ────────────────────────────────────────────────

  private async getAccessToken(): Promise<string> {
    if (this.tokenCache && this.tokenCache.expires_at > Date.now()) {
      return this.tokenCache.access_token;
    }

    const body = new URLSearchParams({
      username: this.email,
      password: this.password,
      grant_type: 'password',
      client_id: 'acled',
    });

    const res = await this.fetchWithRetry(this.tokenUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        Accept: 'application/json',
      },
      body: body.toString(),
    });

    if (res.status === 401 || res.status === 400) {
      const txt = await res.text().catch(() => res.statusText);
      throw new Error(
        `ACLED OAuth: invalid credentials (HTTP ${res.status}). ${txt.slice(0, 200)} — register at https://acleddata.com/register/`,
      );
    }
    if (!res.ok) {
      const txt = await res.text().catch(() => res.statusText);
      throw new Error(`ACLED OAuth error: ${res.status} ${txt.slice(0, 200)}`);
    }

    const data = (await res.json()) as { access_token?: string; expires_in?: number };
    if (!data.access_token) {
      throw new Error('ACLED OAuth: response missing access_token');
    }

    const ttlMs = (data.expires_in ?? 86400) * 1000;
    this.tokenCache = {
      access_token: data.access_token,
      expires_at: Date.now() + Math.min(ttlMs, TOKEN_TTL_MS),
    };
    return this.tokenCache.access_token;
  }

  // ── Query helpers ─────────────────────────────────────────────────────────

  private buildFilters(params: URLSearchParams, args: Record<string, unknown>): void {
    if (args.country) params.set('country', String(args.country));
    if (args.region) params.set('region', String(args.region));
    if (args.event_type) params.set('event_type', String(args.event_type));
    if (args.sub_event_type) params.set('sub_event_type', String(args.sub_event_type));
    if (args.actor) {
      params.set('actor1', String(args.actor));
      params.set('actor1_where', 'LIKE');
    }
    if (args.iso) params.set('iso', String(args.iso));
    if (args.event_date_from && args.event_date_to) {
      params.set('event_date', `${args.event_date_from}|${args.event_date_to}`);
      params.set('event_date_where', 'BETWEEN');
    } else if (args.event_date_from) {
      params.set('event_date', String(args.event_date_from));
      params.set('event_date_where', '>=');
    } else if (args.event_date_to) {
      params.set('event_date', String(args.event_date_to));
      params.set('event_date_where', '<=');
    }
    if (args.year) params.set('year', String(args.year));
    if (args.fatalities_min) {
      params.set('fatalities', String(args.fatalities_min));
      params.set('fatalities_where', '>=');
    }
  }

  private async acledFetch(args: Record<string, unknown>, defaultLimit = 100): Promise<EventRow[]> {
    const params = new URLSearchParams({ _format: 'json' });
    this.buildFilters(params, args);
    const cap = Math.min(5000, Math.max(1, (args.limit as number | undefined) ?? defaultLimit));
    params.set('limit', String(cap));

    // Try with cached token; on 401 invalidate cache and retry once.
    let token = await this.getAccessToken();
    let res = await this.fetchWithRetry(`${this.readUrl}?${params}`, {
      headers: { Authorization: `Bearer ${token}`, Accept: 'application/json' },
    });

    if (res.status === 401) {
      this.tokenCache = null;
      token = await this.getAccessToken();
      res = await this.fetchWithRetry(`${this.readUrl}?${params}`, {
        headers: { Authorization: `Bearer ${token}`, Accept: 'application/json' },
      });
    }

    if (!res.ok) {
      const body = await res.text().catch(() => res.statusText);
      throw new Error(`ACLED error: ${res.status} ${body.slice(0, 200)}`);
    }

    const data = (await res.json()) as {
      success?: boolean;
      error?: Array<{ message?: string }>;
      data?: EventRow[];
    };
    if (data.success === false) {
      const msg = data.error?.[0]?.message ?? 'unknown error';
      throw new Error(`ACLED: ${msg}`);
    }
    return data.data ?? [];
  }

  // ── Tool implementations ──────────────────────────────────────────────────

  private async searchEvents(args: Record<string, unknown>): Promise<ToolResult> {
    const rows = await this.acledFetch(args, 100);
    const result = {
      count: rows.length,
      events: rows.map((r) => ({
        data_id: r.data_id ?? null,
        event_id_cnty: r.event_id_cnty ?? null,
        event_date: r.event_date ?? null,
        year: r.year ? Number(r.year) : null,
        event_type: r.event_type ?? null,
        sub_event_type: r.sub_event_type ?? null,
        actor1: r.actor1 ?? null,
        actor2: r.actor2 ?? null,
        country: r.country ?? null,
        iso: r.iso ? Number(r.iso) : null,
        region: r.region ?? null,
        admin1: r.admin1 ?? null,
        admin2: r.admin2 ?? null,
        location: r.location ?? null,
        latitude: r.latitude ? Number(r.latitude) : null,
        longitude: r.longitude ? Number(r.longitude) : null,
        fatalities: r.fatalities ? Number(r.fatalities) : 0,
        notes: r.notes ?? null,
        source: r.source ?? null,
        source_scale: r.source_scale ?? null,
      })),
    };
    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }

  private async countsByCountry(args: Record<string, unknown>): Promise<ToolResult> {
    const rows = await this.acledFetch(args, 5000);
    const agg = new Map<string, { events: number; fatalities: number; by_type: Record<string, number> }>();

    for (const r of rows) {
      const c = r.country ?? 'Unknown';
      const slot = agg.get(c) ?? { events: 0, fatalities: 0, by_type: {} };
      slot.events += 1;
      slot.fatalities += r.fatalities ? Number(r.fatalities) : 0;
      const t = r.event_type ?? 'Unknown';
      slot.by_type[t] = (slot.by_type[t] ?? 0) + 1;
      agg.set(c, slot);
    }

    const breakdown = Array.from(agg.entries())
      .map(([country, v]) => ({ country, ...v }))
      .sort((a, b) => b.events - a.events);

    const result = {
      total_events: rows.length,
      countries: breakdown.length,
      truncated: rows.length >= 5000,
      breakdown,
    };
    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }
}
