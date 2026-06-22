/**
 * GDELT 2.0 DOC API MCP Adapter
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

// Base URL: https://api.gdeltproject.org/api/v2/doc/doc
// Auth: None — public, free, no API key required
// Docs: https://blog.gdeltproject.org/gdelt-doc-2-0-api-debuts/
// Category: news
// Rate limits: No official rate limit documented; be polite.

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

const BASE_URL = 'https://api.gdeltproject.org/api/v2/doc/doc';

export class GdeltMCPServer extends MCPAdapterBase {
  constructor() {
    super();
  }

  static catalog() {
    return {
      name: 'gdelt',
      displayName: 'GDELT 2.0 News Intelligence',
      version: '1.0.0',
      category: 'news',
      keywords: [
        'gdelt', 'news', 'global news', 'media', 'events', 'language', 'tone',
        'sentiment', 'geopolitics', 'articles', 'news search', 'news volume',
        'timeline', 'media monitoring', 'broadcast', 'web news',
      ],
      toolNames: ['search_articles', 'timeline_tone', 'timeline_volume'],
      description: 'GDELT 2.0 DOC API: search global news articles, track sentiment over time, and measure news volume for any query across 100+ languages indexed every 15 minutes.',
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
        name: 'search_articles',
        description:
          'Search global news articles indexed by GDELT 2.0. Returns recent matches with URL, title, domain, source country, language, tone (-100..+100), and image. Use the query language: plain words AND together, "quotes" for phrases, parens for OR groups, "-word" to exclude, "sourcecountry:US" / "sourcelang:eng" / "theme:TERROR" / "near:Paris~50" for advanced filters.',
        inputSchema: {
          type: 'object',
          properties: {
            query: { type: 'string', description: 'GDELT query string' },
            timespan: {
              type: 'string',
              description: 'Lookback window: e.g., "24h", "7d", "1m", "custom" (paired with startdatetime/enddatetime). Default 7d.',
            },
            startdatetime: { type: 'string', description: 'YYYYMMDDHHMMSS (UTC) — only with timespan=custom' },
            enddatetime: { type: 'string', description: 'YYYYMMDDHHMMSS (UTC) — only with timespan=custom' },
            sort: {
              type: 'string',
              description: 'HybridRel (default) | DateDesc | DateAsc | ToneDesc | ToneAsc',
              enum: ['HybridRel', 'DateDesc', 'DateAsc', 'ToneDesc', 'ToneAsc'],
            },
            max_records: { type: 'number', description: 'Results to return (1-250, default 25)' },
          },
          required: ['query'],
        },
      },
      {
        name: 'timeline_tone',
        description:
          'Day-by-day average tone (-100 very negative .. +100 very positive) for a GDELT query over time. Returns datapoints with timestamp and tone value. Useful for tracking sentiment shifts around a topic, person, or place.',
        inputSchema: {
          type: 'object',
          properties: {
            query: { type: 'string', description: 'GDELT query string' },
            timespan: { type: 'string', description: 'Lookback window (default "1m" — month)' },
            startdatetime: { type: 'string', description: 'YYYYMMDDHHMMSS — only with timespan=custom' },
            enddatetime: { type: 'string', description: 'YYYYMMDDHHMMSS — only with timespan=custom' },
          },
          required: ['query'],
        },
      },
      {
        name: 'timeline_volume',
        description:
          'Day-by-day article volume as % of total news for a GDELT query. Returns datapoints with timestamp and intensity. Useful for spotting topic spikes and comparing news attention across periods.',
        inputSchema: {
          type: 'object',
          properties: {
            query: { type: 'string', description: 'GDELT query string' },
            timespan: { type: 'string', description: 'Lookback window (default "1m")' },
            startdatetime: { type: 'string', description: 'YYYYMMDDHHMMSS — only with timespan=custom' },
            enddatetime: { type: 'string', description: 'YYYYMMDDHHMMSS — only with timespan=custom' },
          },
          required: ['query'],
        },
      },
    ];
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<ToolResult> {
    try {
      switch (name) {
        case 'search_articles': return this.searchArticles(args);
        case 'timeline_tone':   return this.timeline(args, 'timelinetone');
        case 'timeline_volume': return this.timeline(args, 'timelinevol');
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

  private buildParams(args: Record<string, unknown>, mode: string, format: string): URLSearchParams {
    const params = new URLSearchParams({
      query: String(args.query),
      mode,
      format,
    });
    const timespan = args.timespan as string | undefined;
    if (timespan && timespan !== 'custom') params.set('timespan', timespan);
    if (timespan === 'custom') {
      if (args.startdatetime) params.set('startdatetime', String(args.startdatetime));
      if (args.enddatetime)   params.set('enddatetime',   String(args.enddatetime));
    }
    return params;
  }

  private async gdeltFetch<T>(params: URLSearchParams): Promise<T> {
    const url = `${BASE_URL}?${params.toString()}`;
    const response = await this.fetchWithRetry(url, {
      method: 'GET',
      headers: { Accept: 'application/json' },
    });
    if (!response.ok) {
      const text = await response.text().catch(() => response.statusText);
      throw new Error(`GDELT error: ${response.status} ${text.slice(0, 200)}`);
    }
    const body = await response.text();
    // GDELT sometimes returns HTML error pages with a 200 status — guard the parse.
    try {
      return JSON.parse(body) as T;
    } catch {
      throw new Error(`GDELT returned non-JSON (likely a query syntax error): ${body.slice(0, 200)}`);
    }
  }

  private async searchArticles(args: Record<string, unknown>): Promise<ToolResult> {
    const params = this.buildParams(args, 'ArtList', 'json');
    if (!args.timespan) params.set('timespan', '7d');
    if (args.sort) params.set('sort', String(args.sort));
    const maxRecords = typeof args.max_records === 'number'
      ? Math.min(250, Math.max(1, args.max_records))
      : 25;
    params.set('maxrecords', String(maxRecords));

    const data = await this.gdeltFetch<{
      articles?: {
        url?: string;
        url_mobile?: string;
        title?: string;
        seendate?: string;
        socialimage?: string;
        domain?: string;
        language?: string;
        sourcecountry?: string;
        tone?: number;
      }[];
    }>(params);

    const result = {
      query: args.query,
      timespan: args.timespan ?? '7d',
      returned: data.articles?.length ?? 0,
      articles: (data.articles ?? []).map((a) => ({
        url:            a.url            ?? null,
        title:          a.title          ?? null,
        seen_at:        a.seendate       ?? null,
        domain:         a.domain         ?? null,
        language:       a.language       ?? null,
        source_country: a.sourcecountry  ?? null,
        tone:           typeof a.tone === 'number' ? a.tone : null,
        image:          a.socialimage    ?? null,
      })),
    };

    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }

  private async timeline(
    args: Record<string, unknown>,
    mode: 'timelinetone' | 'timelinevol',
  ): Promise<ToolResult> {
    const params = this.buildParams(args, mode, 'json');
    if (!args.timespan) params.set('timespan', '1m');

    const data = await this.gdeltFetch<{
      timeline?: {
        series?: string;
        data?: { date: string; value: number }[];
      }[];
    }>(params);

    const series = data.timeline?.[0]?.data ?? [];
    const result = {
      query:   args.query,
      timespan: args.timespan ?? '1m',
      metric:  mode === 'timelinetone' ? 'avg_tone (-100..+100)' : 'volume_pct (% of news)',
      points:  series.length,
      series:  series.map((d) => ({ date: d.date, value: d.value })),
    };

    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }
}
