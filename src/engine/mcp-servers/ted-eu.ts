/**
 * TED (Tenders Electronic Daily) EU Procurement MCP Adapter
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 *
 * Upstream: https://api.ted.europa.eu/v3
 * Base URL: https://api.ted.europa.eu/v3
 * Auth: none (public, no-auth-verified)
 * Docs: https://docs.ted.europa.eu/api/
 * Category: government
 * Rate limits: none documented — public EU open data
 */

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

const BASE_URL = 'https://api.ted.europa.eu/v3';

export class TedEuMCPServer extends MCPAdapterBase {
  private readonly baseUrl: string;

  constructor(config?: { baseUrl?: string }) {
    super();
    if (config === null) { throw new Error('TedEuMCPServer: configuration object is required when provided'); }
    this.baseUrl = config?.baseUrl ?? BASE_URL;
  }

  static catalog() {
    return {
      name: 'ted-eu',
      displayName: 'TED — EU Tenders Electronic Daily',
      version: '1.0.0',
      category: 'government',
      keywords: [
        'ted', 'tenders', 'procurement', 'eu', 'european union', 'public tender',
        'contract notice', 'award notice', 'cpv', 'buyer', 'rfp', 'rfq',
        'official journal', 'open data', 'government contracts', 'europe',
      ],
      toolNames: ['search_notices', 'get_notice'],
      description: 'TED (Tenders Electronic Daily): search EU public procurement notices and fetch individual notices by publication number — free public API, no authentication required.',
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
        name: 'search_notices',
        description:
          'Search EU procurement notices on TED (Tenders Electronic Daily). Combine free-text query with structured filters. Returns notice metadata: publication number, title, buyer, country, CPV code, value, deadlines, type.',
        inputSchema: {
          type: 'object',
          properties: {
            query: {
              type: 'string',
              description: 'Free-text — matches title and description',
            },
            country: {
              type: 'string',
              description: 'Country of buyer (ISO 3166-1 alpha-3 — e.g. FRA, DEU, ITA, ESP)',
            },
            cpv: {
              type: 'string',
              description: 'CPV code (Common Procurement Vocabulary, 8-digit)',
            },
            date_from: {
              type: 'string',
              description: 'Publication date from (YYYY-MM-DD)',
            },
            date_to: {
              type: 'string',
              description: 'Publication date to (YYYY-MM-DD)',
            },
            value_min: {
              type: 'number',
              description: 'Estimated value floor (EUR)',
            },
            value_max: {
              type: 'number',
              description: 'Estimated value ceiling (EUR)',
            },
            notice_type: {
              type: 'string',
              description: 'Notice subtype — "cn-standard" (contract notice), "can-standard" (award), "pin" (prior info), ...',
            },
            limit: {
              type: 'number',
              description: 'Page size, 1-250 (default 25)',
            },
            page: {
              type: 'number',
              description: '1-based page (default 1)',
            },
          },
        },
      },
      {
        name: 'get_notice',
        description: 'Fetch a single TED notice by publication number (e.g. "123456-2025").',
        inputSchema: {
          type: 'object',
          properties: {
            publication_number: {
              type: 'string',
              description: 'TED publication number, format "<num>-<year>"',
            },
          },
          required: ['publication_number'],
        },
      },
    ];
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<ToolResult> {
    try {
      switch (name) {
        case 'search_notices': return this.searchNotices(args);
        case 'get_notice':     return this.getNotice(args);
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

  private async searchNotices(args: Record<string, unknown>): Promise<ToolResult> {
    const parts: string[] = [];
    if (args.query)       parts.push(`(notice-title~"${this.escapeQ(String(args.query))}")`);
    if (args.country)     parts.push(`buyer-country=${String(args.country).toUpperCase()}`);
    if (args.cpv)         parts.push(`classification-cpv=${args.cpv}`);
    if (args.notice_type) parts.push(`notice-type=${args.notice_type}`);
    if (args.date_from)   parts.push(`publication-date>=${this.tedDate(String(args.date_from))}`);
    if (args.date_to)     parts.push(`publication-date<=${this.tedDate(String(args.date_to))}`);
    if (args.value_min !== undefined) parts.push(`total-value>=${args.value_min}`);
    if (args.value_max !== undefined) parts.push(`total-value<=${args.value_max}`);

    const expertQuery = parts.length ? parts.join(' AND ') : `publication-date>=${this.tedDateBack(7)}`;

    const limit = typeof args.limit === 'number' ? Math.min(250, Math.max(1, args.limit)) : 25;
    const page  = typeof args.page  === 'number' ? Math.max(1, args.page)                 : 1;

    const body = {
      query: expertQuery,
      fields: [
        'publication-number',
        'notice-title',
        'buyer-name',
        'buyer-country',
        'classification-cpv',
        'total-value',
        'publication-date',
        'deadline-receipt-tender-date-lot',
        'notice-type',
        'links',
      ],
      limit,
      page,
      scope: 'ALL',
    };

    const response = await this.fetchWithRetry(`${this.baseUrl}/notices/search`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
      body: JSON.stringify(body),
    });

    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `TED API error: ${response.status} ${errText.slice(0, 200)}` }],
        isError: true,
      };
    }

    const data = await response.json() as {
      totalNoticeCount?: number;
      notices?: unknown[];
      iterationNextToken?: string;
    };

    const result = {
      query: expertQuery,
      total: data.totalNoticeCount ?? null,
      count: data.notices?.length ?? 0,
      notices: data.notices ?? [],
      next_page_token: data.iterationNextToken ?? null,
    };

    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }

  private async getNotice(args: Record<string, unknown>): Promise<ToolResult> {
    const pubNum = args.publication_number;
    if (typeof pubNum !== 'string' || !pubNum.trim()) {
      return {
        content: [{ type: 'text', text: 'Required argument "publication_number" is missing. Pass a string like "123456-2025".' }],
        isError: true,
      };
    }

    const response = await this.fetchWithRetry(
      `${this.baseUrl}/notices/${encodeURIComponent(pubNum.trim())}`,
      { method: 'GET', headers: { Accept: 'application/json' } },
    );

    if (response.status === 404) {
      return {
        content: [{ type: 'text', text: `TED: notice ${pubNum} not found` }],
        isError: true,
      };
    }
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `TED API error: ${response.status} ${errText.slice(0, 200)}` }],
        isError: true,
      };
    }

    const data = await response.json();
    return { content: [{ type: 'text', text: this.truncate(data) }], isError: false };
  }

  // TED expert search requires compact YYYYMMDD dates.
  private tedDate(input: string): string {
    return input.replace(/-/g, '').slice(0, 8);
  }

  private tedDateBack(days: number): string {
    const d = new Date(Date.now() - days * 86_400_000);
    return d.toISOString().slice(0, 10).replace(/-/g, '');
  }

  private escapeQ(s: string): string {
    return s.replace(/"/g, '\\"');
  }
}
